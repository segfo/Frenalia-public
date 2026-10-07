//! **パス2**（Tier2aでのドメイン記録）のオーケストレーション。
//!
//! ```text
//!   排他を取る ── 記録セッションのdirを作る ── policy.jsonの穴を FsPassthrough へ
//!        │                                                  │
//!        │                              WFPパイプを用意 → select_tier（＝preflightがACE付与）
//!        │                                                  │
//!        │                        付与できた穴を台帳へ／付与できなかった穴を表示
//!        │                                                  │
//!        │    Proxy＋Fake DNSを起こす（記録: record_all／強制: 宣言したallow_domainsだけ）
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
//! FSのpermissiveさ（隔離しないこと）とネットワーク強制（Tier2aのpackage SID）は同一トークンでは
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
//! # 通信の扱いは2通り（決定64、[`NetMode`]）
//!
//! | モード | 中継プロキシと名前解決が許す宛先 | 候補にする行 |
//! |---|---|---|
//! | 記録（既定） | IPリテラル以外の全部（`DomainPolicy::record_all`） | 触った宛先の全部 |
//! | 強制 | `policy.json`の`net.allow_domains`に一致する宛先だけ | 断られた宛先だけ |
//!
//! どちらのモードでもWFPのdefault-denyは同じで、子が直接外へ出る経路は無い。違うのは
//! **中継プロキシと名前解決がどの宛先を通すか**だけである。記録は宣言をまだ持たない段階で
//! 使う宛先を1回で集めるため、強制は宣言を書き終えた後で宣言の外が無いかを確かめるためにある。
//!
//! # tokioランタイムは背景ドライバとしてだけ使う（B-31）
//!
//! ProxyとFake DNSはasyncだが、この関数自体は同期でありパス1と同じ形をしている。ランタイムは
//! **起こしたまま持っておくだけ**で、`block_on`は短い起動呼び出しにしか使わない
//! ——オーケストレーション本体（`std::thread::sleep`で回るポーリング）を`block_on`の中で
//! 走らせると、ランタイムのワーカースレッドを待ち時間ぶん専有してProxyが応答しなくなる。

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use harness_core::{DomainPolicy, NetProxyConfig, RequireSandbox, SandboxChoice, ShellTier};
use harness_sandbox::tier2a::win_appcontainer::{
    NetworkCapability, WorkspaceImage, WorkspaceSpawn,
};
use harness_sandbox::{FsPassthrough, WorkspaceWriteMode};

use crate::child_run::{pump_child, ChildRunSink};

pub use crate::child_run::AbortReason;
use crate::net_aggregate::NetAggregate;

use crate::policy_file::PolicyDomain;
pub use crate::session_dir::NetMode;
use crate::session_dir::{now_unix_ms, RecordManifest, RecordSessionDir, RecordStatus};
use crate::session_lock::{LockOutcome, RecordingLock};
use crate::shell_output::ShellLine;

/// パス2の本体（`run_pass2`）。
mod run;
/// プロセスの寿命で持つ常駐のもの（WFP・Spawn Daemon）。
mod hosts;
/// 穴とプロファイルの寿命のガードと、宣言が縮んだ分の取り消し。
mod session_grants;
/// 人へ見せる文言（CLIと画面が共有する）。
mod lines;

pub use hosts::{SharedNetfilter, SharedSpawnDaemon};
pub use session_grants::SessionGrants;
pub use lines::{
    elevation_notice, net_mode_note, proxy_started_line, render_fs_denials, wfp_enforced_line,
};
use run::{run_pass2, Pass2Facts};

/// パス2の中継プロキシと名前解決（Fake DNS）へ渡す、通信の扱い（決定64）。
///
/// 2つへは**同じ値**を渡す——食い違うと、名前は引けたのに繋がらない（またはその逆の）状態に
/// なる（`harness_tools::fake_dns::spawn_fake_dns_with_policy`のdoc）。だから1回だけ作る。
#[derive(Debug, Clone)]
pub struct NetPolicyPlan {
    /// 設定型（`NetProxyConfig`・`FakeDnsConfig`）の`allow_domains`へ入れる値。
    /// 記録では空のまま（判定は[`DomainPolicy::record_all`]が持つ）。
    pub allow_domains: Vec<String>,
    pub policy: DomainPolicy,
}

/// モードと、そのドメインの`net.allow_domains`から[`NetPolicyPlan`]を作る。
///
/// 強制では、宣言の値を`harness.exe`本体が`settings.json`の`net.allow_domains`に掛けているのと
/// 同じ正規化（[`harness_core::normalize_domain_pattern`]、`validate_and_merge_net_allow_domains`）
/// へ通す。**正規化できない値が1つでもあれば走らせない。** [`DomainPolicy::new`]はそういう値を
/// 黙って捨てるので、そのまま渡すと宣言の一部が無言で消えたまま「宣言どおりに走った」と
/// 表示される（B-10）。
pub fn net_policy_plan(mode: NetMode, declared: &[String]) -> Result<NetPolicyPlan, String> {
    match mode {
        NetMode::RecordAll => Ok(NetPolicyPlan {
            allow_domains: Vec::new(),
            policy: DomainPolicy::record_all(),
        }),
        NetMode::Declared => {
            let mut allow_domains: Vec<String> = Vec::new();
            for value in declared {
                let normalized = harness_core::normalize_domain_pattern(value)
                    .map_err(|e| format!("net.allow_domains の `{value}`: {e}"))?;
                if !allow_domains.contains(&normalized) {
                    allow_domains.push(normalized);
                }
            }
            Ok(NetPolicyPlan {
                policy: DomainPolicy::new(allow_domains.clone()),
                allow_domains,
            })
        }
    }
}

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
    /// WFPの出口強制daemon。**このプロセスの寿命で持つ**（D-56、[`SharedNetfilter`]）。
    ///
    /// 実行ごとに起こし直すとそのたびUACが出るので、2回目以降は同じdaemonへ`ApplyRules`を
    /// 再送する（許可ポートは実行ごとに変わる——Proxy/Fake DNSを起こし直すため）。
    pub wfp: &'a SharedNetfilter,
    /// ETW収集器（**deny-only**）。パス2で実際に起きたFS拒否を観測する。
    ///
    /// パス1（record-all）と**同じdaemon**を使い回す（D-56 段階2）。スコープ判定は
    /// Tier2aなのでpackage SIDが効く——`record_all=true`のときにprobeを使えなかった制約
    /// （`LearnPolicy.record_all`のdoc）はここでは当てはまらない。
    pub collector: &'a crate::record::SharedCollector,
    /// このpolicy editor processが共有するSpawn Daemon。最初のパス2でだけ遅延起動する。
    pub spawn_daemon: &'a SharedSpawnDaemon,
    /// [決定64] 通信をどう扱うか（記録＝全部許して記録／強制＝宣言どおり）。
    pub net_mode: NetMode,
}

/// パス2の進行。呼び出し側（CLI・TUI）が表示に使う。
#[derive(Debug, Clone)]
pub enum NetRecordEvent {
    /// これから何回UACが出そうかの見込み。
    ElevationExpected {
        max_prompts: u8,
    },
    /// `preflight`がworkspace外の穴へACEを付けようとしている。
    GrantingPassthrough {
        outside_count: usize,
    },
    /// ACEを付けられた穴（台帳へも記録済み）。**マシンに残る変更**。
    PassthroughGranted {
        path: PathBuf,
        writable: bool,
    },
    /// もう宣言されていないルートのACEをこれから剥がす（[`reconcile_undeclared_roots`]）。
    /// **件数を先に出す**——1件ごとの進捗だけだと、全体でどれくらい待つのかが分からない。
    RevokingUndeclared {
        total: usize,
    },
    /// 宣言が取り消されたルートのACEを剥がした。**マシンに残る変更の巻き戻し**なので、
    /// 付与（`PassthroughGranted`）と同じ粒度で見せる（B-01: 対の片方だけを可視にしない）。
    UndeclaredRevoked {
        path: PathBuf,
        done: usize,
        total: usize,
    },
    /// ACEを付けられなかった穴。パス2が途中で落ちる原因になる。
    PassthroughDenied {
        path: PathBuf,
        access: String,
        reason: String,
    },
    /// Tier2aへ着地した。
    Tier2aReady,
    /// **子を起こす前に測った**「コマンドの実行ファイルへ届くか」（[`crate::exec_reach`]）。
    ///
    /// 届かないと分かっていても**止めない**（判定は`which`の解決に依存し外れ得る）。
    /// 警告は`warnings`にも積まれるので、実行後のマニフェストからも辿れる。
    ExecReachability(Box<crate::exec_reach::ExecReach>),
    /// 中継プロキシが起きた。`allowed`は強制で許す通信先の件数（記録では0）。
    /// 表示の文言は[`proxy_started_line`]が持つ。
    ProxyStarted {
        addr: std::net::SocketAddr,
        mode: NetMode,
        allowed: usize,
    },
    FakeDnsStarted(std::net::SocketAddr),
    /// WFPのdefault-denyが立った（loopbackの穴はProxy/Fake DNSのポートだけ）。
    ///
    /// `reused`が真なら**daemonを起こしていない＝UACが出ていない**（D-56）。
    /// これを表示に出すのは、「UACが出なかった」を「強制が掛かっていない」と読み違えるのを
    /// 防ぐため（B-32）。UACの有無は、ユーザーがこのパスの結果をどう読むかを決める入力である。
    WfpEnforced {
        reused: bool,
    },
    /// deny-only収集器が起きた。`reused`が真ならUACは出ていない（D-56 段階2）。
    CollectorStarted {
        etw_available: bool,
        reused: bool,
    },
    /// ETWの配送が始まるのを待っている（実測1500ms。**再利用してもこの待ちは消えない**）。
    WarmingUp(Duration),
    /// 収集器が観測したFSイベントを1件取り込んだ（`fs-audit.jsonl`の1行）。
    FsAccess(Box<harness_policy::FsAuditEvent>),
    /// 収集器が現世代を畳んだ。`written`は収集器の自己申告による書込件数。
    CollectorStopped {
        written: u64,
    },
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
    pub granted_passthrough: Vec<harness_core::GrantedPassthrough>,
    pub denied_passthrough: Vec<(PathBuf, String, String)>,
    pub warnings: Vec<String>,
    pub aggregate: NetAggregate,
    /// FS監査ログの置き場（deny-only収集器が書く）。
    pub audit_log_path: PathBuf,
    /// **強制が効いている状態で観測されたFS拒否**の集計。ネットワーク側とは別枠
    /// （あちらは記録のため全許可、こちらは宣言どおりに強制した結果）。
    pub fs_aggregate: crate::aggregate::Aggregate,
    /// 収集器が起動できたか。**偽なら「拒否が0件だった」ではなく「観測していない」**（D-43）。
    pub collector_started: bool,
    /// ETWセッションが実際に張れたか。同上。
    pub etw_available: bool,
    /// [決定64] 通信をどう扱って走らせたか（結果の注記と候補の作り方がこれで決まる）。
    pub net_mode: NetMode,
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
    #[error("Spawn Daemonを起動または利用できませんでした: {0}")]
    SpawnDaemon(String),
    #[error("Local Proxyを起動できませんでした: {0}")]
    NoProxy(String),
    #[error("tokioランタイムを起こせませんでした: {0}")]
    Runtime(String),
    #[error("Tier2aでコマンドを起動できませんでした: {0}")]
    Spawn(String),
    #[error(
        "強制モードで走らせられません——宣言した通信先を解釈できませんでした（{0}）。\
         policy.jsonの値を直すか、記録モードで走らせてください"
    )]
    InvalidNetDeclaration(String),
}

impl RecordNetError {
    /// マニフェストへ残す**機械可読のタグ**（[`crate::session_dir::RecordManifest::error_kind`]）。
    ///
    /// 文面（`Display`）はパスや下位のエラーを含むうえ、読みやすさのために書き換わる。
    /// 「どの段で落ちたか」で後から突き合わせたいので、変わらないタグを別に持つ。
    ///
    /// **ワイルドカードを使わない**——variantを足した人のビルドがここで落ちる
    /// （タグの付け忘れを実行時ではなくコンパイル時に捕まえる）。
    pub fn kind(&self) -> &'static str {
        match self {
            RecordNetError::AlreadyRecording(_) => "already_recording",
            RecordNetError::Lock(_) => "lock",
            RecordNetError::SessionDir { .. } => "session_dir",
            RecordNetError::NotTier2a { .. } => "not_tier2a",
            RecordNetError::NoWfp(_) => "no_wfp",
            RecordNetError::SpawnDaemon(_) => "spawn_daemon",
            RecordNetError::NoProxy(_) => "no_proxy",
            RecordNetError::Runtime(_) => "runtime",
            RecordNetError::Spawn(_) => "spawn",
            RecordNetError::InvalidNetDeclaration(_) => "invalid_net_declaration",
        }
    }
}

/// パス2を実行する。
///
/// **排他ロックはこの関数が保持する**（記録の全期間、パス1と同じグローバルmutex）。
pub fn record_net(
    request: &RecordNetRequest<'_>,
    on_event: &mut dyn FnMut(NetRecordEvent),
) -> Result<RecordNetOutcome, RecordNetError> {
    // **排他も記録の置き場も取る前に**組み立てる。宣言を解釈できなければ、マシンに何も残さずに断る。
    let net_plan = net_policy_plan(request.net_mode, &request.domain.net.allow_domains)
        .map_err(RecordNetError::InvalidNetDeclaration)?;
    let (lock, lock_outcome) = RecordingLock::try_acquire().map_err(RecordNetError::Lock)?;
    if !lock_outcome.can_proceed() {
        return Err(RecordNetError::AlreadyRecording(
            lock_outcome.message().to_string(),
        ));
    }
    if lock_outcome == LockOutcome::AcquiredAfterAbandon {
        on_event(NetRecordEvent::Warning(lock_outcome.message().to_string()));
    }
    let _lock = lock;

    // **記録1回ごとに別のディレクトリ**（`next_record_id`のdoc）。同じプロセスで2回目のパス2を
    // 走らせたときに、1回目の`net-audit.jsonl`へ追記して観測が混ざるのを防ぐ。
    // **`session_profile`（package SID）はプロセス単位のまま**——分けているのは記録の置き場だけ。
    let session_id = crate::session_dir::next_record_id();
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
    manifest.net_mode = Some(request.net_mode);
    // **この記録を走らせた時点の宣言**を残す（`RecordManifest::declared_fs`のdoc）。
    // 後から`policy.json`を読み直す形にすると、承認して1周した後に古い記録を開いたときに
    // 当時は成立していなかった診断が出る。
    manifest.declared_fs = request
        .domain
        .fs
        .entries()
        .into_iter()
        .map(|(value, access)| crate::session_dir::DeclaredFsRule {
            value: value.to_string(),
            access,
        })
        .collect();
    if let Err(e) = dir.write_manifest(&manifest) {
        on_event(NetRecordEvent::Warning(format!(
            "記録セッションのマニフェストを書けませんでした（{}）: {e}",
            dir.manifest_path().display()
        )));
    }

    let mut warnings: Vec<String> = Vec::new();
    // 強制で通信先を1件も宣言していなければ、名前解決も接続も全部断られる。止めはしない
    // （「このコマンドは通信しない」を確かめる使い方は正当）が、黙って走らせない（B-10）。
    if request.net_mode == NetMode::Declared && net_plan.allow_domains.is_empty() {
        warn(
            format!(
                "強制モードですが、ドメイン `{}` は通信先を1件も宣言していません。\
                 この実行では名前解決と接続がすべて断られます（断られた宛先は候補に出ます）。",
                request.domain.name
            ),
            &mut warnings,
            on_event,
        );
    }
    // **失敗しても残さなければならない事実**は`warnings`と同じ形で外へ出す（下記doc）。
    let mut facts = Pass2Facts::default();
    // 撤収は**どの経路を通っても必ず行う**。ここから先で早期returnするたびに
    // `finish_failed`を通すのはそのため（`?`で素通しにしない）。
    let mut state = TeardownState::default();

    let result = run_pass2(
        request,
        &net_plan,
        &dir,
        &mut warnings,
        &mut facts,
        &mut state,
        on_event,
    );
    teardown(&mut state, on_event);

    // 収集器の状態は**成功・失敗のどちらでも**そのまま残す。ここを`Ok`側だけで代入して
    // いた頃、失敗した記録は常に`collector_started: false`になり、「収集器が起きなかった」と
    // 「収集器の状態を記録しそこねた」が区別できなかった（D-43）。
    manifest.collector_started = facts.collector_started;
    manifest.etw_available = facts.etw_available;
    manifest.unreachable_exec = facts.unreachable_exec.clone();
    manifest.shell_tier = facts.shell_tier.clone();

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
                audit_log_path: dir.audit_log_path(),
                collector_started: facts.collector_started,
                etw_available: facts.etw_available,
                net_mode: request.net_mode,
                // **撤収まで済ませてから読み直す。** `teardown`の`StopCollect`で収集器が
                // 最後の1バッチを書くので、実行中に積んだ集計だけでは取りこぼす。
                // 観測の正本はJSONLだけ、という既存の方針（`aggregate::from_session`）に合わせる。
                //
                // 収集器が起きなかったときは実行中の集計（ほぼ空）を使うが、**そちらにも
                // 同じ合流を掛ける**——実行前診断は収集器の生死と無関係に得られている事実で、
                // 起動できなかった理由を出す責任はむしろこちら側にある（B-06: 同じ状態を
                // 作り得る経路が2つあるなら両方通す）。
                fs_aggregate: if facts.collector_started {
                    crate::aggregate::from_session(&dir, &manifest)
                } else {
                    let mut fs_aggregate = inner.fs_aggregate;
                    crate::aggregate::apply_session_context(&mut fs_aggregate, &manifest);
                    fs_aggregate
                },
            })
        }
        Err(e) => {
            manifest.warnings = warnings;
            // **なぜ失敗したかを残す。** これが無いと、次に同じ記録を走らせる人も、
            // この失敗が残した副作用（払ったUACぶんの昇格daemon）をどう扱うべきかを
            // 決められない（B-09）。
            manifest.fail(now_unix_ms(), e.kind(), &e);
            let _ = dir.write_manifest(&manifest);
            Err(e)
        }
    }
}

/// 撤収が要る資源。**取得した順の逆で畳む。**
#[derive(Default)]
struct TeardownState<'a> {
    /// この実行でWFPフィルタを張ったか。真なら撤収で`ClearRules`を送る。
    /// **daemon自体は畳まない**（次の実行で再利用する、D-56）。
    wfp_applied: Option<&'a SharedNetfilter>,
    /// この実行で収集を始めたか。真なら撤収で`StopCollect`を送る。
    /// **daemon自体は畳まない**（次の記録で再利用する、D-56 段階2）。
    collector: Option<&'a crate::record::SharedCollector>,
    /// ProxyとFake DNSはDropでaccept loopを止める。ランタイムより先に落とす。
    proxy: Option<harness_tools::net_proxy::LocalProxy>,
    fake_dns: Option<harness_tools::fake_dns::FakeDnsAgent>,
    runtime: Option<tokio::runtime::Runtime>,
}

fn teardown(state: &mut TeardownState<'_>, on_event: &mut dyn FnMut(NetRecordEvent)) {
    // **収集器を先に畳む。** 後にすると、WFP・Proxyの撤収そのものが観測に混ざる。
    // daemonは残す（次の記録で再利用する、D-56 段階2）。
    if let Some(collector) = state.collector.take() {
        on_event(NetRecordEvent::TearingDown("収集器（ETWセッション）"));
        match collector.stop() {
            Ok(Some(written)) => on_event(NetRecordEvent::CollectorStopped { written }),
            Ok(None) => {}
            Err(e) => on_event(NetRecordEvent::Warning(format!(
                "収集器が正常に畳めませんでした（{e}）。次の記録は収集器を起こし直すので、                 UACが1回出ます。"
            ))),
        }
    }
    if let Some(wfp) = state.wfp_applied.take() {
        // **daemonは残す。フィルタだけ畳む。**（D-56の不変条件1「待機中はフィルタを持たない」）
        // 畳んでよいのは、Tier2aの子がkill-on-closeのJob Objectに入っていて、`pump_child`が
        // 抜けた時点で子孫ごと終了しているため——待機中に対象SIDを持つプロセスは残らない。
        on_event(NetRecordEvent::TearingDown("WFPのフィルタ"));
        if let Err(e) = wfp.clear() {
            on_event(NetRecordEvent::Warning(format!(
                "WFPのフィルタを畳めませんでした（{e}）。次の実行はdaemonを起こし直すので、\
                 UACが1回出ます。"
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
    // **AppContainerプロファイルとACEはここでは撤収しない。**
    //
    // D-37の「セッション」は**プロセスの寿命**である（`session_token`はプロセス内で一度だけ
    // 確定する`OnceLock`）。実行1回ごとに`end_session`を呼ぶと、同じプロセスで2回目を走らせた
    // ときに、直前に剥がしたばかりの穴を付け直すことになる——`.cargo`のような大きなツリーでは
    // その付与と撤収がそのまま待ち時間になる（workspace本体がD-54で解いたのと同じコスト構造）。
    // 撤収は[`SessionGrants`]がプロセス終了時に1度だけ行う。
    //
    // **例外が1つある**（宣言を取り消したとき）: [`reconcile_undeclared_roots`]が次のパス2の
    // 開始時に「もう宣言されていないルート」だけを剥がす。ここで警戒しているコスト
    // （同一プロセスの2回目で付け直す無駄）は起きない——剥がすのは次の実行で要求されない
    // ものだけなので、付け直す対象にならない。
}

/// 伝える価値のある事実を、**その場で見せる**と同時に**マニフェストへも残す**。
fn warn(message: String, warnings: &mut Vec<String>, on_event: &mut dyn FnMut(NetRecordEvent)) {
    on_event(NetRecordEvent::Warning(message.clone()));
    warnings.push(message);
}

#[cfg(test)]
mod error_kind_tests {
    use super::*;

    /// **タグが互いに区別できること。** マニフェストへ残す`error_kind`は「どの段で落ちたか」を
    /// 後から突き合わせるためのもので、2つのvariantが同じタグを持つと区別が消える。
    ///
    /// variantの追加は`kind()`のワイルドカード無し`match`がコンパイル時に止めるので、
    /// ここで固定するのは**綴りの重複が無いこと**だけでよい。
    #[test]
    fn every_failure_gets_its_own_label() {
        let all = [
            RecordNetError::AlreadyRecording("x".into()),
            RecordNetError::Lock("x".into()),
            RecordNetError::SessionDir {
                path: PathBuf::from("C:/w"),
                source: std::io::Error::other("x"),
            },
            RecordNetError::NotTier2a {
                tier: "Tier1".into(),
                reason: "x".into(),
            },
            RecordNetError::NoWfp("x".into()),
            RecordNetError::NoProxy("x".into()),
            RecordNetError::Runtime("x".into()),
            RecordNetError::Spawn("x".into()),
        ];

        let mut seen: Vec<&str> = all.iter().map(|e| e.kind()).collect();
        let total = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), total, "duplicate error_kind labels: {seen:?}");
        assert!(seen.iter().all(|k| !k.is_empty()));
    }

    /// タグは**文面と一緒に**マニフェストへ残る。ここが繋がっていないと、
    /// `error_kind`だけがあって理由が読めない／その逆になる。
    #[test]
    fn the_label_and_the_message_travel_together() {
        let error = RecordNetError::NoWfp("engine busy".into());
        let mut manifest = crate::session_dir::RecordManifest::new(
            "k-1",
            "cargo test",
            Path::new("C:/w"),
            Path::new("C:/w"),
            1,
        );

        manifest.fail(2, error.kind(), &error);

        assert_eq!(manifest.error_kind.as_deref(), Some("no_wfp"));
        assert!(manifest
            .error
            .as_deref()
            .is_some_and(|e| e.contains("engine busy")));
    }
}

#[cfg(test)]
mod fs_denial_panel_tests {
    use super::*;

    /// **「観測していない」と「拒否が0件だった」を混ぜない。**
    ///
    /// これを混ぜると、fail-open（収集器が起きなかった）が「サンドボックスは何も拒否
    /// しなかった」という正反対の意味で読まれる（D-43が「黙って空にしない」と言っているのは
    /// この形のこと）。**両方の文面を対で固定する**（B-35）。
    #[test]
    fn not_observing_is_worded_differently_from_observing_nothing() {
        let empty =
            crate::aggregate::Aggregate::new(crate::exclusion::ExclusionRules::with_temp_root(
                std::path::Path::new("C:/no-such-workspace"),
                Some(std::path::Path::new("C:/no-such-temp")),
            ));

        let not_started = render_fs_denials(&empty, false, false, NetMode::RecordAll);
        let no_etw = render_fs_denials(&empty, true, false, NetMode::RecordAll);
        let observed_nothing = render_fs_denials(&empty, true, true, NetMode::RecordAll);

        assert!(not_started.contains("観測していません"), "{not_started}");
        assert!(
            not_started.contains("ではありません"),
            "it must say explicitly that this is not 'zero denials': {not_started}"
        );
        assert!(no_etw.contains("観測していません"), "{no_etw}");
        assert!(
            observed_nothing.contains("1件も観測されませんでした"),
            "{observed_nothing}"
        );
        assert!(
            !observed_nothing.contains("観測していません"),
            "observing zero denials must not be phrased as 'not observed': {observed_nothing}"
        );
    }

    /// **通信をどう扱ったかを必ず併記する（決定64）。2つのモードを対で固定する（B-35）。**
    ///
    /// 記録で走らせた実行はFSだけを宣言どおりに強制した中間状態で、書かないと「宣言どおりに
    /// 確かめた」と読まれる。強制で走らせた実行は、それが**この試験実行の中だけ**であること
    /// （`harness.exe`本体はまだ`policy.json`の通信の宣言を使わない）を書かないと、
    /// 「本体でもこの宣言で動く」と読まれる。
    #[test]
    fn the_panel_says_how_the_network_was_handled_in_each_mode() {
        let empty =
            crate::aggregate::Aggregate::new(crate::exclusion::ExclusionRules::with_temp_root(
                std::path::Path::new("C:/no-such-workspace"),
                Some(std::path::Path::new("C:/no-such-temp")),
            ));

        let record_all = render_fs_denials(&empty, true, true, NetMode::RecordAll);
        let declared = render_fs_denials(&empty, true, true, NetMode::Declared);

        assert!(record_all.contains("通信は全許可"), "{record_all}");
        assert!(record_all.contains("FSの拒否だけ"), "{record_all}");
        assert!(declared.contains("宣言どおりに強制"), "{declared}");
        assert!(
            declared.contains("harness.exe本体はまだ"),
            "強制が試験実行の中だけであることを書く: {declared}"
        );
        assert!(
            !declared.contains("全許可"),
            "強制した実行を全許可と書かない: {declared}"
        );
    }

    /// **FSを観測できなかった回にも、通信の扱いは出す。**
    ///
    /// 決定64より前は、収集器が起きなかった分岐が早く抜けていたので、この一文ごと消えていた。
    /// 通信の扱いは収集器の成否と無関係に効いている事実である。
    #[test]
    fn the_network_note_survives_when_fs_was_not_observed() {
        let empty =
            crate::aggregate::Aggregate::new(crate::exclusion::ExclusionRules::with_temp_root(
                std::path::Path::new("C:/no-such-workspace"),
                Some(std::path::Path::new("C:/no-such-temp")),
            ));

        for (collector_started, etw_available) in [(false, false), (true, false)] {
            for mode in [NetMode::RecordAll, NetMode::Declared] {
                let text = render_fs_denials(&empty, collector_started, etw_available, mode);
                assert!(text.contains("観測していません"), "{text}");
                assert!(text.contains(net_mode_note(mode)), "{mode:?}: {text}");
            }
        }
    }

    /// 観測できたときは件数を出す（数を出さない報告は行動を決められない、B-32）。
    #[test]
    fn observed_denials_are_reported_with_their_count() {
        let mut aggregate =
            crate::aggregate::Aggregate::new(crate::exclusion::ExclusionRules::with_temp_root(
                std::path::Path::new("C:/no-such-workspace"),
                Some(std::path::Path::new("C:/no-such-temp")),
            ));
        aggregate.add_event(&harness_policy::FsAuditEvent::denied(
            harness_policy::FsAuditKind::Etw,
            "C:/Users/me/.cargo/bin/cargo.exe",
            harness_config::FsAccess::Read,
            "STATUS_ACCESS_DENIED",
            1,
        ));

        let text = render_fs_denials(&aggregate, true, true, NetMode::RecordAll);

        assert!(text.contains("1件の拒否を観測"), "{text}");
    }
}

#[cfg(test)]
#[path = "record_net_mode_tests.rs"]
mod record_net_mode_tests;
