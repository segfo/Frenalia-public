//! **パス2**（Tier2aでのドメイン記録）のオーケストレーション。
//!
//! ```text
//!   排他を取る ── 記録セッションのdirを作る ── policy.jsonの穴を FsPassthrough へ
//!        │                                                  │
//!        │                              WFPパイプを用意 → select_tier（＝preflightがACE付与）
//!        │                                                  │
//!        │                        付与できた穴を台帳へ／付与できなかった穴を表示
//!        │                                                  │
//!        │                     Proxy（record_all）＋Fake DNS（record_all）を起こす
//!        │                                                  │
//!        │                            netfilterd（WFP default-deny＋loopback許可）
//!        │                                                  │
//!        │                       Tier2aでコマンドを起動 → 出力とnet監査を同時に吸う
//!        │                                                  │
//!        │        撤収: netfilterd → Fake DNS/Proxy → end_session（プロファイルとACE）
//!        └── マニフェストを finished/canceled/failed で書き直す ──────────────────┘
//! ```
//!
//! # なぜパス1と分けるのか（2パス記録）
//!
//! FSのpermissiveさ（Tier1の低IL）とネットワーク強制（Tier2aのpackage SID）は同一トークンでは
//! 両立しない。順番に使う——パス1で「触ったファイル」を全部記録し、ユーザーが承認して穴を開け、
//! そのうえでパス2をTier2aで走らせて「接続したドメイン」を記録する
//! （`plans/POLICY-EDITOR-TOMOYO-DIG.md` 第3セッション節）。
//!
//! # 2箇所でfail-closedにする（降格して「記録できた」と言わない）
//!
//! | 条件 | 扱い |
//! |---|---|
//! | 着地したTierがTier2aでない | **中止**。Tier1にWFPは効かず素通しなので、記録しても「何も拒否されなかった」以上のことは言えない |
//! | netfilterdが立たない | **中止**。`should_grant_tier2a_network_capability`はこの状態で`Deny`を返すので、走らせても子はソケットを1つも作れない |
//!
//! パス1が観測（fail-open、D-43）なのに対し、パス2は**強制の上に成り立つ観測**である。
//! 強制が無い状態の観測を同じ顔で出すと、ユーザーは「このドメインだけ使う」と読んでしまう。
//!
//! # tokioランタイムは背景ドライバとしてだけ使う（B-31）
//!
//! ProxyとFake DNSはasyncだが、この関数自体は同期でありパス1と同じ形をしている。ランタイムは
//! **起こしたまま持っておくだけ**で、`block_on`は短い起動呼び出しにしか使わない
//! ——オーケストレーション本体（`std::thread::sleep`で回るポーリング）を`block_on`の中で
//! 走らせると、ランタイムのワーカースレッドを待ち時間ぶん専有してProxyが応答しなくなる。

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use harness_core::{DomainPolicy, NetProxyConfig, RequireSandbox, ShellTier};
use harness_sandbox::tier2a::win_appcontainer::{NetworkCapability, WorkspaceSpawn};
use harness_sandbox::{FsPassthrough, WorkspaceWriteMode};

use crate::child_run::{pump_child, ChildRunSink};

pub use crate::child_run::AbortReason;
use crate::net_aggregate::NetAggregate;

use crate::policy_file::PolicyDomain;
use crate::session_dir::{now_unix_ms, RecordManifest, RecordSessionDir, RecordStatus};
use crate::session_lock::{LockOutcome, RecordingLock};
use crate::shell_output::ShellLine;

/// 対象コマンド終了後、Proxy/Fake DNSの監査ログが書き切られるのを待つ猶予。
/// ETWのような配送遅延は無い（監査は同じプロセス内で同期的に書かれる）ので、パス1の
/// [`crate::record::DRAIN`]（4秒）より短くてよい。
pub const NET_DRAIN: Duration = Duration::from_millis(500);
/// 撤収待ちの間、監査ログを読み続ける間隔。
const POLL_INTERVAL: Duration = Duration::from_millis(100);

pub struct RecordNetRequest<'a> {
    /// 承認済みのドメイン（`policy.json`から読んだもの）。
    pub domain: &'a PolicyDomain,
    /// Tier2aで走らせるコマンド。
    pub command: &'a str,
    pub cwd: &'a Path,
    pub workspace_root: &'a Path,
    pub timeout: Option<Duration>,
    /// 真を返したら打ち切る（TUIの停止操作用、B-23(b)）。
    pub cancel: &'a dyn Fn() -> bool,
}

/// パス2の進行。呼び出し側（CLI・TUI）が表示に使う。
#[derive(Debug, Clone)]
pub enum NetRecordEvent {
    /// これから何回UACが出そうかの見込み。
    ElevationExpected { max_prompts: u8 },
    /// `preflight`がworkspace外の穴へACEを付けようとしている。
    GrantingPassthrough { outside_count: usize },
    /// ACEを付けられた穴（台帳へも記録済み）。**マシンに残る変更**。
    PassthroughGranted { path: PathBuf, writable: bool },
    /// ACEを付けられなかった穴。パス2が途中で落ちる原因になる。
    PassthroughDenied {
        path: PathBuf,
        access: String,
        reason: String,
    },
    /// Tier2aへ着地した。
    Tier2aReady,
    ProxyStarted(std::net::SocketAddr),
    FakeDnsStarted(std::net::SocketAddr),
    /// WFPのdefault-denyが立った（loopbackの穴はProxy/Fake DNSのポートだけ）。
    WfpEnforced,
    ChildStarted,
    /// シェルがコマンドを走らせる**前に**吐いた出力（BUG-086）。
    StartupNoise(String),
    Stdout(String),
    Stderr(String),
    /// 監査イベントを1件観測した（`net-audit.jsonl`の1行）。
    NetAccess(Box<serde_json::Value>),
    Exited(i32),
    Aborted(AbortReason),
    Draining(Duration),
    /// 撤収の各段（表示のため。**失敗しても記録は続ける**が事実は必ず出す）。
    TearingDown(&'static str),
    Warning(String),
}

impl NetRecordEvent {
    fn from_line(line: ShellLine) -> Self {
        match line {
            ShellLine::StartupNoise(l) => NetRecordEvent::StartupNoise(l),
            ShellLine::Stdout(l) => NetRecordEvent::Stdout(l),
            ShellLine::Stderr(l) => NetRecordEvent::Stderr(l),
        }
    }
}

#[derive(Debug)]
pub struct RecordNetOutcome {
    pub session_id: String,
    pub session_dir: PathBuf,
    pub net_audit_log_path: PathBuf,
    pub exit_code: Option<i32>,
    pub aborted: Option<AbortReason>,
    pub granted_passthrough: Vec<(PathBuf, bool)>,
    pub denied_passthrough: Vec<(PathBuf, String, String)>,
    pub warnings: Vec<String>,
    pub aggregate: NetAggregate,
}

#[derive(Debug, thiserror::Error)]
pub enum RecordNetError {
    #[error("{0}")]
    AlreadyRecording(String),
    #[error("記録セッションの排他を確認できませんでした: {0}")]
    Lock(String),
    #[error("記録セッションのディレクトリを作れませんでした（{path}）: {source}")]
    SessionDir {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(
        "Tier2aへ着地しませんでした（着地: {tier}）。パス2はWFPによる出口強制の上に成り立つので、\
         降格した状態で「接続したドメインを記録した」とは言えません。理由: {reason}"
    )]
    NotTier2a { tier: String, reason: String },
    #[error(
        "WFPの出口強制（harness-netfilterd）を起動できませんでした: {0}。\
         この状態でTier2aの子へnetwork capabilityを与えることはしません\
         （fail-closed——強制されていないのではなく、ソケットを1つも作れません）"
    )]
    NoWfp(String),
    #[error("Local Proxyを起動できませんでした: {0}")]
    NoProxy(String),
    #[error("tokioランタイムを起こせませんでした: {0}")]
    Runtime(String),
    #[error("Tier2aでコマンドを起動できませんでした: {0}")]
    Spawn(String),
}

/// パス2を実行する。
///
/// **排他ロックはこの関数が保持する**（記録の全期間、パス1と同じグローバルmutex）。
pub fn record_net(
    request: &RecordNetRequest<'_>,
    on_event: &mut dyn FnMut(NetRecordEvent),
) -> Result<RecordNetOutcome, RecordNetError> {
    let (lock, lock_outcome) = RecordingLock::try_acquire().map_err(RecordNetError::Lock)?;
    if !lock_outcome.can_proceed() {
        return Err(RecordNetError::AlreadyRecording(
            lock_outcome.message().to_string(),
        ));
    }
    if lock_outcome == LockOutcome::AcquiredAfterAbandon {
        on_event(NetRecordEvent::Warning(
            lock_outcome.message().to_string(),
        ));
    }
    let _lock = lock;

    let session_id = harness_sandbox::tier2a::session_profile::session_token().to_string();
    let dir = RecordSessionDir::create(request.workspace_root, &session_id).map_err(|e| {
        RecordNetError::SessionDir {
            path: crate::session_dir::sandbox_root(request.workspace_root),
            source: e,
        }
    })?;

    let mut manifest = RecordManifest::new(
        &session_id,
        request.command,
        request.cwd,
        request.workspace_root,
        now_unix_ms(),
    );
    manifest.pass = 2;
    manifest.domain = Some(request.domain.name.clone());
    if let Err(e) = dir.write_manifest(&manifest) {
        on_event(NetRecordEvent::Warning(format!(
            "記録セッションのマニフェストを書けませんでした（{}）: {e}",
            dir.manifest_path().display()
        )));
    }

    let mut warnings: Vec<String> = Vec::new();
    // 撤収は**どの経路を通っても必ず行う**。ここから先で早期returnするたびに
    // `finish_failed`を通すのはそのため（`?`で素通しにしない）。
    let mut state = TeardownState::default();

    let result = run_pass2(request, &dir, &mut warnings, &mut state, on_event);
    teardown(&mut state, on_event);

    match result {
        Ok(inner) => {
            manifest.status = match inner.aborted {
                Some(_) => RecordStatus::Canceled,
                None => RecordStatus::Finished,
            };
            manifest.finished_unix_ms = Some(now_unix_ms());
            manifest.exit_code = inner.exit_code;
            manifest.warnings = warnings.clone();
            if let Err(e) = dir.write_manifest(&manifest) {
                on_event(NetRecordEvent::Warning(format!(
                    "マニフェストを更新できませんでした: {e}"
                )));
            }
            Ok(RecordNetOutcome {
                session_id,
                session_dir: dir.path().to_path_buf(),
                net_audit_log_path: dir.net_audit_log_path(),
                exit_code: inner.exit_code,
                aborted: inner.aborted,
                granted_passthrough: inner.granted_passthrough,
                denied_passthrough: inner.denied_passthrough,
                warnings,
                aggregate: inner.aggregate,
            })
        }
        Err(e) => {
            manifest.status = RecordStatus::Failed;
            manifest.finished_unix_ms = Some(now_unix_ms());
            manifest.warnings = warnings;
            let _ = dir.write_manifest(&manifest);
            Err(e)
        }
    }
}

/// 撤収が要る資源。**取得した順の逆で畳む。**
#[derive(Default)]
struct TeardownState {
    /// `preflight`が`begin_session`でセッションプロファイルを作ったか
    /// （作った以上、`end_session`を通さないとプロファイルとACEが残る）。
    session_started: bool,
    wfp: Option<harness_sandbox::tier2a::netfilterd::NetfilterHandle>,
    /// ProxyとFake DNSはDropでaccept loopを止める。ランタイムより先に落とす。
    proxy: Option<harness_tools::net_proxy::LocalProxy>,
    fake_dns: Option<harness_tools::fake_dns::FakeDnsAgent>,
    runtime: Option<tokio::runtime::Runtime>,
}

fn teardown(state: &mut TeardownState, on_event: &mut dyn FnMut(NetRecordEvent)) {
    if let Some(wfp) = state.wfp.take() {
        on_event(NetRecordEvent::TearingDown("WFPの出口強制"));
        if let Err(e) = wfp.stop() {
            on_event(NetRecordEvent::Warning(format!(
                "netfilterdが正常に撤収しませんでした: {e}"
            )));
        }
    }
    if state.fake_dns.take().is_some() {
        on_event(NetRecordEvent::TearingDown("Fake DNS"));
    }
    if state.proxy.take().is_some() {
        on_event(NetRecordEvent::TearingDown("Local Proxy"));
    }
    // ランタイムはタスクの持ち主より後に落とす（accept loopを先に止めてから畳む）。
    if let Some(runtime) = state.runtime.take() {
        runtime.shutdown_background();
    }
    if state.session_started {
        // D-37: このセッションのAppContainerプロファイルと、それ宛に付けたACEを撤収する。
        // 撤収順序（ACE→最後にプロファイル）は`session_profile`側が保証する。ここへ到達せずに
        // 落ちた場合（クラッシュ・Ctrl+C）は、次回起動時の`preflight`のGCが同じ経路で回収する
        // ——だからこの呼び出しは「速く片付けるための最適化」であって、正しさの要件ではない。
        on_event(NetRecordEvent::TearingDown("AppContainerプロファイルとACE"));
        harness_sandbox::tier2a::session_profile::end_session(
            &harness_sandbox::tier2a::win_appcontainer::revoke_session_grant,
        );
        state.session_started = false;
    }
}

struct Pass2Inner {
    exit_code: Option<i32>,
    aborted: Option<AbortReason>,
    granted_passthrough: Vec<(PathBuf, bool)>,
    denied_passthrough: Vec<(PathBuf, String, String)>,
    aggregate: NetAggregate,
}

fn run_pass2(
    request: &RecordNetRequest<'_>,
    dir: &RecordSessionDir,
    warnings: &mut Vec<String>,
    state: &mut TeardownState,
    on_event: &mut dyn FnMut(NetRecordEvent),
) -> Result<Pass2Inner, RecordNetError> {
    let passthrough = passthrough_for_domain(request.domain, request.workspace_root);
    on_event(NetRecordEvent::ElevationExpected {
        // privhelper（workspace外のACE付与がある場合）と netfilterd（連鎖起動できない場合）。
        max_prompts: if passthrough.is_empty() { 1 } else { 2 },
    });
    on_event(NetRecordEvent::GrantingPassthrough {
        outside_count: passthrough.len(),
    });

    // WFPパイプは`select_tier`（＝preflight）**より前**に用意する。preflightがprivhelperへ
    // 委譲したとき、「処理完了後にこの名前でnetfilterdを連鎖起動してほしい」と添えられる
    // （シナリオA＝UACを1回に抑えられる経路）。
    let wfp_prelude = match harness_sandbox::tier2a::netfilterd::prepare_pipe() {
        Ok(prepared) => Some(prepared),
        Err(e) => {
            // ここで失敗しても`NetfilterHandle::start`（シナリオB、UACがもう1回）で立て直せる。
            warn(
                format!("WFPの連鎖起動用パイプを用意できませんでした（{e}）。UACがもう1回出ます。"),
                warnings,
                on_event,
            );
            None
        }
    };
    let wfp_chain_pipe = wfp_prelude.as_ref().map(|p| p.name().to_string());

    // preflightはここで`begin_session`を呼ぶ——**この行より後の全経路が`end_session`を
    // 通らなければならない**（`teardown`が担当）。
    state.session_started = true;
    let selection = harness_sandbox::select_tier(
        RequireSandbox::None,
        request.workspace_root,
        /* opt_in_tier3 */ false,
        /* opt_in_tier1 */ false,
        &passthrough,
        wfp_chain_pipe,
        &WorkspaceWriteMode::DirectRw,
        // 準備の進捗コールバック。ここへ繋ぐのは記録画面を足すコミット。
        None,
    )
    .map_err(|e| RecordNetError::NotTier2a {
        tier: "(選択できず)".to_string(),
        reason: e.to_string(),
    })?;

    if selection.tier != ShellTier::Tier2a {
        return Err(RecordNetError::NotTier2a {
            tier: selection.tier.label().to_string(),
            reason: selection
                .reason
                .clone()
                .unwrap_or_else(|| "理由は報告されていません".to_string()),
        });
    }
    on_event(NetRecordEvent::Tier2aReady);
    for warning in &selection.passthrough_warnings {
        warn(warning.clone(), warnings, on_event);
    }

    // **実際にACEが付いた穴だけ**を台帳へ記録する（幻の台帳エントリを作らない、BUG-017）。
    // 記録しないと撤収経路の無い孤立ACEになるので、ここは飛ばせない。
    for (path, writable) in &selection.granted_passthrough {
        let forced = passthrough
            .iter()
            .find(|fp| &fp.path == path)
            .map(|fp| fp.forced)
            .unwrap_or(false);
        harness_sandbox::tier2a::fs_passthrough_ledger::record_fs_passthrough_grant(
            path, *writable, forced, // policy.json由来はsettings.jsonの参照カウントに載せない
            None,
            // [BUG-101] 付与先のSID。パス2側で渡すのは後続のコミット。
            None,
        );
        on_event(NetRecordEvent::PassthroughGranted {
            path: path.clone(),
            writable: *writable,
        });
    }
    // **付けられなかった穴は必ず見せる。** パス2が途中で落ちる原因はほぼこれである。
    for (path, access, reason) in &selection.denied_passthrough {
        harness_sandbox::tier2a::fs_passthrough_ledger::record_fs_passthrough_denied(
            path, access, reason,
        );
        on_event(NetRecordEvent::PassthroughDenied {
            path: path.clone(),
            access: access.clone(),
            reason: reason.clone(),
        });
    }

    // --- Proxy / Fake DNS（どちらもrecord_all）-----------------------------------
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .map_err(|e| RecordNetError::Runtime(e.to_string()))?;

    let net_audit_path = dir.net_audit_log_path();
    let proxy_config = NetProxyConfig {
        allow_domains: Vec::new(),
        domain_policy_enabled: true,
        // 下でnetfilterdを立てるまでは未確定。この値はProxy自身の判定には使われない。
        enforced_by_wfp: false,
        audit_log_path: Some(net_audit_path.clone()),
        proxy_addr: None,
        fake_dns_addr: None,
        tls_inspection: harness_core::TlsInspection::Sni,
    };
    let proxy = runtime
        .block_on(harness_tools::net_proxy::spawn_local_proxy_with_policy(
            &proxy_config,
            DomainPolicy::record_all(),
        ))
        .map_err(|e| RecordNetError::NoProxy(e.to_string()))?
        .ok_or_else(|| {
            RecordNetError::NoProxy("domain_policy_enabled=false（内部エラー）".to_string())
        })?;
    let proxy_addr = proxy.addr;
    state.proxy = Some(proxy);
    on_event(NetRecordEvent::ProxyStarted(proxy_addr));

    // **Proxyと同じポリシー**を渡す（食い違うと、名前は引けたのに繋がらない／その逆になる）。
    let fake_dns = runtime.block_on(harness_tools::fake_dns::spawn_fake_dns_with_policy(
        &harness_tools::fake_dns::FakeDnsConfig {
            allow_domains: Vec::new(),
            policy_required: true,
            audit_log_path: Some(net_audit_path.clone()),
            preferred_port: Some(53),
        },
        DomainPolicy::record_all(),
    ));
    let fake_dns_addr = match fake_dns {
        Ok(agent) => {
            let addr = agent.addr;
            state.fake_dns = Some(agent);
            on_event(NetRecordEvent::FakeDnsStarted(addr));
            Some(addr)
        }
        Err(e) => {
            // Fake DNSはSOCKS5のremote DNS経路が主なので、無くても記録は成立する。
            warn(
                format!(
                    "Fake DNSを起動できませんでした（{e}）。SOCKS5のremote DNS経路は使えますが、\
                     OSリゾルバ経由の名前解決は記録されません。"
                ),
                warnings,
                on_event,
            );
            None
        }
    };
    state.runtime = Some(runtime);

    // --- WFPの出口強制 -----------------------------------------------------------
    let loopback = harness_tools::net_proxy::net_loopback_ports_for_agents(
        Some(proxy_addr),
        fake_dns_addr,
    );
    let policy = harness_sandbox::tier2a::netfilterd::NetfilterPolicy {
        // D-37: WFPフィルタはこのセッションのpackage SIDだけを条件にする。
        session_profile: harness_sandbox::tier2a::session_profile::current_profile_name(),
        allow_loopback_tcp_ports: loopback.tcp.clone(),
        allow_loopback_udp_ports: loopback.udp.clone(),
        audit_log_path: Some(net_audit_path.clone()),
        mcp_profiles: Vec::new(),
        // M15.7/D-44: 昇格側が`audit_log_path`を検証するための基準。渡さないと監査ログが
        // 無効化される（fail-safe側）。
        workspace_root: Some(request.workspace_root.to_path_buf()),
        chain_launch_policy_learnd: None,
    };
    let wfp = match (selection.netfilterd_chain_attempted, wfp_prelude) {
        // シナリオA: privhelperが既に連鎖起動を試みている。同じパイプでハンドシェイクする。
        (true, Some(prepared)) => {
            harness_sandbox::tier2a::netfilterd::NetfilterHandle::connect_after_chain_launch(
                prepared.into_handle(),
                policy,
            )
        }
        // シナリオB: 連鎖起動は発生しなかった。投機的パイプは使わない
        // （`start`が自前で新規パイプを作るため）、dropして自動的に閉じる。
        (_, prelude) => {
            drop(prelude);
            harness_sandbox::tier2a::netfilterd::NetfilterHandle::start(policy)
        }
    };
    // `start`/`start_with_prelude`はD-60で「ハンドル＋連鎖起動の結末」を返すようになった。
    // 結末を表示へ載せるのは後続のコミット（パス2の出力）なので、ここでは捨てる。
    state.wfp = Some(
        wfp.map(|(handle, _chain)| handle)
            .map_err(|e| RecordNetError::NoWfp(e.to_string()))?,
    );
    on_event(NetRecordEvent::WfpEnforced);

    // --- Tier2aで対象コマンドを起動 ----------------------------------------------
    // `should_grant_tier2a_network_capability`は`run_shell`と**同じ関数**を通す
    // （判定を書き直すと片方だけ緩む）。ここまで来ていればWFPは立っているので
    // `InternetClient`になるが、規則そのものは共有側が持つ。
    let net_capability = if harness_tools::should_grant_tier2a_network_capability(
        harness_tools::NetDecision::Deny,
        /* net_proxy_enforced */ true,
        /* net_domain_policy_requested */ true,
    ) {
        NetworkCapability::InternetClient
    } else {
        NetworkCapability::Deny
    };

    let mut env = harness_sandbox::secret_env::build_child_env();
    // Proxy/Fake DNSのアドレスは`run_shell`と**同じ純粋関数**で組み立てる（規則5）。
    env.extend(harness_tools::net_proxy::proxy_env_vars(
        Some(proxy_addr),
        fake_dns_addr,
    ));
    // BUG-050: コマンド本体はstdinスクリプトへ埋め込まず、env経由で渡す。
    env.push((
        harness_tools::RUN_SHELL_COMMAND_ENV_VAR.to_string(),
        request.command.to_string(),
    ));

    let (child, _shell_label) = harness_sandbox::tier2a::win_appcontainer::spawn_shell_in_workspace(
        WorkspaceSpawn {
            cwd: request.cwd.to_path_buf(),
            env,
            workspace_root: request.workspace_root.to_path_buf(),
            cow_upper_dir: None,
            granted_passthrough: selection.granted_passthrough.clone(),
            net_capability,
        },
    )
    .map_err(|e| RecordNetError::Spawn(e.to_string()))?;
    let kill_token = child.kill_token();
    let mut rx = child.spawn_streaming(Some(&harness_tools::run_shell_bootstrap_stdin()));
    on_event(NetRecordEvent::ChildStarted);

    // --- 出力と監査を同時に吸う ---------------------------------------------------
    let mut aggregate = NetAggregate::new();
    let mut tail = crate::audit_tail::AuditTail::new(net_audit_path.clone());
    let outcome = {
        let mut sink = Pass2Sink {
            on_event,
            tail: &mut tail,
            aggregate: &mut aggregate,
        };
        pump_child(
            &mut rx,
            &|| kill_token.kill(),
            request.timeout,
            request.cancel,
            &mut sink,
        )
    };

    if let Some(code) = outcome.exit_code {
        on_event(NetRecordEvent::Exited(code));
    }

    // 監査は同期的に書かれるが、最後のリクエストが書き切られる直前で抜けないよう少し待つ。
    on_event(NetRecordEvent::Draining(NET_DRAIN));
    let until = Instant::now() + NET_DRAIN;
    while Instant::now() < until {
        drain_net_audit(&mut tail, &mut aggregate, on_event);
        std::thread::sleep(POLL_INTERVAL);
    }
    drain_net_audit(&mut tail, &mut aggregate, on_event);

    Ok(Pass2Inner {
        exit_code: outcome.exit_code,
        aborted: outcome.aborted,
        granted_passthrough: selection.granted_passthrough.clone(),
        denied_passthrough: selection.denied_passthrough.clone(),
        aggregate,
    })
}

/// パス2が[`pump_child`]へ渡す出力先。パス1との違いは`on_tick`（何の監査ログを読むか）だけ。
struct Pass2Sink<'a> {
    on_event: &'a mut dyn FnMut(NetRecordEvent),
    tail: &'a mut crate::audit_tail::AuditTail,
    aggregate: &'a mut NetAggregate,
}

impl ChildRunSink for Pass2Sink<'_> {
    fn on_line(&mut self, line: ShellLine) {
        (self.on_event)(NetRecordEvent::from_line(line));
    }

    fn on_tick(&mut self) {
        drain_net_audit(self.tail, self.aggregate, self.on_event);
    }

    fn on_abort(&mut self, reason: AbortReason) {
        (self.on_event)(NetRecordEvent::Aborted(reason));
    }
}

fn drain_net_audit(
    tail: &mut crate::audit_tail::AuditTail,
    aggregate: &mut NetAggregate,
    on_event: &mut dyn FnMut(NetRecordEvent),
) {
    let (events, skipped) = tail.poll_json_values();
    for event in events {
        aggregate.add_event(&event);
        on_event(NetRecordEvent::NetAccess(Box::new(event)));
    }
    aggregate.add_unparsable(skipped);
}

/// ドメインのFSルールから`FsPassthrough`を作る。
///
/// **workspace配下のパスは含めない**——Tier2aのworkspace grantが既に覆っているので、
/// 同じツリーへ別主体のACEを重ねる意味が無い（`preflight`の走査対象を無駄に増やすだけ）。
/// 分類の規則は[`crate::approve`]の表示とそろえる（B-19: 綴りを揃える規則を2つ持たない）。
fn passthrough_for_domain(domain: &PolicyDomain, workspace_root: &Path) -> Vec<FsPassthrough> {
    let mut out: Vec<FsPassthrough> = Vec::new();
    for (value, access) in domain.fs.entries() {
        let Some(root) = crate::approve::grant_root(value, workspace_root) else {
            continue;
        };
        if let Some(existing) = out.iter_mut().find(|fp| fp.path == root) {
            // 同じルートに複数のaccessが宣言されていたら、**広い方**を採る
            // （読み取り穴と書込穴を2本張れないので、片方だけ張ると宣言と食い違う）。
            if access == harness_config::FsAccess::ReadWrite {
                existing.access = harness_sandbox::FsAccess::ReadWrite;
            }
            continue;
        }
        out.push(FsPassthrough {
            path: root,
            access: match access {
                harness_config::FsAccess::Read => harness_sandbox::FsAccess::Read,
                harness_config::FsAccess::ReadWrite => harness_sandbox::FsAccess::ReadWrite,
                harness_config::FsAccess::ReadExec => harness_sandbox::FsAccess::ReadExec,
            },
            // `--force-system-acl`（D-19）はポリシーエディタからは使わせない。
            // システム保護パスへ`SeRestorePrivilege`で強制付与するのは、記録のついでに
            // やってよい操作ではない（`harness fs`から明示的に行う）。
            forced: false,
        });
    }
    out
}

/// 伝える価値のある事実を、**その場で見せる**と同時に**マニフェストへも残す**。
fn warn(message: String, warnings: &mut Vec<String>, on_event: &mut dyn FnMut(NetRecordEvent)) {
    on_event(NetRecordEvent::Warning(message.clone()));
    warnings.push(message);
}
