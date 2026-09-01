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
//! # tokioランタイムは背景ドライバとしてだけ使う（B-31）
//!
//! ProxyとFake DNSはasyncだが、この関数自体は同期でありパス1と同じ形をしている。ランタイムは
//! **起こしたまま持っておくだけ**で、`block_on`は短い起動呼び出しにしか使わない
//! ——オーケストレーション本体（`std::thread::sleep`で回るポーリング）を`block_on`の中で
//! 走らせると、ランタイムのワーカースレッドを待ち時間ぶん専有してProxyが応答しなくなる。

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use harness_core::{DomainPolicy, NetProxyConfig, RequireSandbox, SandboxChoice, ShellTier};
use harness_sandbox::tier2a::win_appcontainer::{NetworkCapability, WorkspaceSpawn};
use harness_sandbox::{FsPassthrough, WorkspaceWriteMode};

use crate::child_run::{pump_child, ChildRunSink};

pub use crate::child_run::AbortReason;
use crate::net_aggregate::NetAggregate;

use crate::policy_file::PolicyDomain;
use crate::session_dir::{now_unix_ms, RecordManifest, RecordSessionDir, RecordStatus};
use crate::session_lock::{LockOutcome, RecordingLock};
use crate::shell_output::ShellLine;

/// 記録を始める前・始めた直後にユーザーへ見せる前置き（CLIとTUIで共有）。
///
/// `max_prompts`は実際に出そうなUACの回数。実行前のUI（回数がまだ確定しない）は上限の2を
/// 渡す。**ACEが付くのはこのパスだけ**という事実をここに書いておくのは、それが
/// 「実行してよいか」の判断材料そのものだからである。
pub fn elevation_notice(max_prompts: u8) -> String {
    format!(
        "隔離: Tier2a（AppContainer＋WFP＋Local Proxy）。UACが最大{max_prompts}回出ます\n\
         （ACEの付与と、WFPの出口強制daemonの起動が管理者権限を要するためです）。\n\
         **ACEが実際に付くのはこのパスだけです**——付けた穴は台帳に記録され、終了時に撤収します。"
    )
}

/// WFPが立ったことをユーザーへ伝える1行（CLIとTUIで共有する）。
///
/// **`reused`をここで文言に出すのが要点。** 2回目以降はdaemonを再利用するのでUACが出ないが、
/// それを「強制が掛かっていない」と読み違えられると、この記録の意味が正反対になる（B-32）。
/// 表示側ごとに書くと片方だけが再利用に触れる文面になるので、実行側が1つだけ持つ
/// （`ELEVATION_NOTICE`・[`elevation_notice`]と同じ方針、`docs/CODE-STRUCTURE-RULES.md`規則5）。
pub fn wfp_enforced_line(reused: bool) -> String {
    let base = "WFPのdefault-denyを張りました（loopbackの穴は上の2つのポートだけ）";
    if reused {
        format!("{base}。既存の昇格daemonを再利用したのでUACは出ていません")
    } else {
        base.to_string()
    }
}

/// パス2で**実際に拒否されたFSアクセス**の欄（CLIとTUIで共有する）。
///
/// # ネットワークとの非対称を必ず書く
///
/// パス2は`DomainPolicy::record_all()`（ネットワーク全許可）で走る。つまりこの実行は
/// **FSは宣言どおりに強制されているが、ネットワークは全許可**という中間状態にある。
/// これを書かないと「テスト画面ができた」と誤読される——実際にはまだ、宣言由来の
/// ネットワークポリシー注入は無い（`plans/POLICY-EDITOR-TOMOYO-DIG.md`の決定27）。
///
/// `collector_started`が偽なら**観測していない**。「拒否が0件だった」と区別できないと、
/// fail-openは単なる隠蔽になる（D-43）。
pub fn render_fs_denials(
    aggregate: &crate::aggregate::Aggregate,
    collector_started: bool,
    etw_available: bool,
) -> String {
    let mut out = String::from("\n観測されたFS拒否（このドメインの宣言で強制した結果）:\n");
    if !collector_started {
        out.push_str(
            "  （観測していません——収集器を起動できませんでした。\n\
             「拒否が0件だった」ではありません）\n",
        );
        return out;
    }
    if !etw_available {
        out.push_str(
            "  （観測していません——ETWセッションを張れませんでした。\n\
             理由はfs-audit.jsonlの制御レコードに残っています）\n",
        );
        return out;
    }
    if aggregate.denied == 0 {
        out.push_str("  （拒否は1件も観測されませんでした）\n");
    } else {
        out.push_str(&format!(
            "  {}件の拒否を観測しました。候補は下の一覧と同じ形で確認できます:\n\
             harness-policy-editor show <session> --generalize <none|dir|auto>\n",
            aggregate.denied
        ));
    }
    out.push_str(
        "\n注意: **この実行でネットワークは全許可です**（接続先を記録するため）。\n\
         ここに出ているのはFSの拒否だけで、ネットワークの強制はまだ試していません。\n",
    );
    out
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
    ProxyStarted(std::net::SocketAddr),
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
            RecordNetError::NoProxy(_) => "no_proxy",
            RecordNetError::Runtime(_) => "runtime",
            RecordNetError::Spawn(_) => "spawn",
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
    // **失敗しても残さなければならない事実**は`warnings`と同じ形で外へ出す（下記doc）。
    let mut facts = Pass2Facts::default();
    // 撤収は**どの経路を通っても必ず行う**。ここから先で早期returnするたびに
    // `finish_failed`を通すのはそのため（`?`で素通しにしない）。
    let mut state = TeardownState::default();

    let result = run_pass2(
        request,
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
    /// `preflight`が`begin_session`でセッションプロファイルを作ったか
    /// （作った以上、`end_session`を通さないとプロファイルとACEが残る）。
    session_started: bool,
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
    state.session_started = false;
}

/// このプロセスがパス2で開けた穴（workspace外へのACE）とAppContainerプロファイルの寿命を、
/// **プロセスの寿命**に合わせるガード。
///
/// # なぜ実行1回ごとに撤収しないのか
///
/// D-37の「セッション」＝プロセスであり、`session_token`はプロセス内で一度だけ確定する。
/// 同じプロセスで2回目のパス2を走らせるとSIDは同じなので、穴を残しておけば`preflight`の
/// `already_sufficient`が効いて**付与も昇格（UAC）も丸ごとスキップされる**。実行のたびに
/// 撤収すると、そのたびに巨大ツリーへの再帰付与をやり直すことになる。
///
/// # 落ちたときにどうなるか
///
/// `Drop`は`std::process::exit`やクラッシュでは走らない。その場合でも**次回起動時の
/// `preflight`が`gc_dead_sessions`で回収する**——生存マーカー（名前付きmutex）が消えている
/// セッションを、台帳とプロファイル名の列挙の**両方**から拾って剥がす（台帳が失われていても
/// 効く二重化）。つまりこのガードは「速く片付けるための最適化」であって、正しさの要件は
/// GC側が持つ。この構造は`session_profile::end_session`のdocが元々宣言しているものである。
pub struct SessionGrants;

impl SessionGrants {
    /// プロセスの入口で1つだけ作る（CLIの`record-net`とTUIの`run`）。
    pub fn hold() -> Self {
        Self
    }

    /// 撤収を**いま**行い、1件ごとに進捗を返す。
    ///
    /// # なぜ`Drop`任せにしないのか（画面を出せる場所で撤収する）
    ///
    /// `Drop`が走るのはイベントループを抜けた後で、そこではもうフレームを描けない。
    /// 結果として撤収は「素のstderrへ686行流れる」しかなくなり、**付与にはゲージがあるのに
    /// 撤収は画面が滝になる**という非対称になった（`docs/CODE-STRUCTURE-RULES.md`§5.1違反）。
    /// TUIはループの中でこれを呼び、付与と同じゲージ（`PhaseWork`）で見せる。
    ///
    /// **`Drop`は保険として残る。** `end_session`は台帳のエントリを消してから戻るので、
    /// ここで撤収済みなら`Drop`側は対象0件で何もしない（冪等）。クラッシュや
    /// `std::process::exit`で`Drop`ごと飛んだ場合も、正しさは次回起動時の
    /// `gc_dead_sessions`が担保する（型のdocを参照）。
    pub fn release(&self, on_progress: &mut dyn FnMut(usize, usize, &Path)) -> usize {
        // [§22.3.2] **capability SID宛の付与も数える。** `granted_paths`だけを見ると、
        // 差分層しか付けていないセッションで撤収が丸ごと飛ぶ（`end_session`を呼ばずに戻る）。
        // 足し算は`session_profile`側の唯一の場所が持つ（`B-05`: 2箇所で別々に足さない）。
        let total = harness_sandbox::tier2a::session_profile::pending_revocation_count();
        if total == 0 {
            return 0;
        }
        // `end_session`が受けるのは`&dyn Fn`（＝不変借用）なので、進捗コールバックは
        // `RefCell`越しに借りる。**単一スレッドで、同時に2回借りる経路は無い**
        // （`end_session`はこのクロージャを直列に呼ぶだけ）。
        let done = std::cell::Cell::new(0usize);
        let sink = std::cell::RefCell::new(on_progress);
        let outcome = harness_sandbox::tier2a::session_profile::end_session(&|path, profile| {
            let leftovers =
                harness_sandbox::tier2a::win_appcontainer::revoke_session_grant(path, profile);
            done.set(done.get() + 1);
            (sink.borrow_mut())(done.get(), total, path);
            leftovers
        });
        // [BUG-103] **剥がせなかったノードは黙って捨てない。** ここはパス2の撤収の正面で、
        // 残ったACEは実マシンに残り続ける（プロファイル削除後はSIDを導出できず、
        // どのコマンドでも剥がせなくなる）。件数ではなく名前を出す（B-09）。
        if let Some(summary) = outcome.summary() {
            eprintln!("note: {summary}");
        }
        done.get()
    }
}

impl Drop for SessionGrants {
    fn drop(&mut self) {
        // **撤収したことは必ず見せる。** これは実マシンのACLとAppContainerプロファイルを
        // 実際に変える操作なので、「付けた」だけが見えて「剥がした」が見えない状態にしない
        // （B-01: 対の片方だけを可視にしない）。実行1回ごとの`teardown`から
        // プロセス終了時のここへ移した際に、この1行が一緒に消えていた——
        // `record_net_e2e`の「撤収まで通っている」というassertはその文言を見ており、
        // 移動と同時に赤くなっていた（`safe-refactoring`段階1-1の実例）。
        //
        // # ここでは1件ごとの行を出さない（TUIのゲージが正面）
        //
        // 撤収は速くない（`.cargo`規模のツリーは付与に実測142.6s掛かり、剥がす側も同じ
        // 再帰walkをする）ので進捗は要るが、**それを出す場所はここではない**——`Drop`が走るのは
        // イベントループを抜けた後で、1件ごとに`eprintln!`すると端末へ686行流れる（実際に
        // そうなった）。進捗は[`SessionGrants::release`]をループの中から呼び、**付与と同じ
        // ゲージ**で見せる（`docs/CODE-STRUCTURE-RULES.md`§5.1）。
        //
        // ここは**保険**として、まだ残っていたぶんだけを黙って畳み、結果を1行で報告する。
        // 撤収済み（`release`を通った）なら対象は0件なので、何も出さない——
        // 「撤収しました」が2回出ると、2回撤収したように読める。
        // [§22.3.2] **capability SID宛の付与も数える。** `granted_paths`だけを見ると、
        // 差分層しか付けていないセッションで撤収が丸ごと飛ぶ（`end_session`を呼ばずに戻る）。
        // 足し算は`session_profile`側の唯一の場所が持つ（`B-05`: 2箇所で別々に足さない）。
        let total = harness_sandbox::tier2a::session_profile::pending_revocation_count();
        if total == 0 {
            return;
        }
        let done = std::cell::Cell::new(0usize);
        let outcome = harness_sandbox::tier2a::session_profile::end_session(&|path, profile| {
            let leftovers =
                harness_sandbox::tier2a::win_appcontainer::revoke_session_grant(path, profile);
            done.set(done.get() + 1);
            leftovers
        });
        // [BUG-103] 保険経路でも残件は出す（`release`と同じ理由・同じ文言、規則5）。
        if let Some(summary) = outcome.summary() {
            eprintln!("note: {summary}");
        }
        // **撤収したことは1行で必ず言う**（B-01: 付けたのが見えて剥がしたのが見えない状態にしない）。
        eprintln!(
            "撤収: AppContainerプロファイルとACE（{}/{total}件）",
            done.get()
        );
        // 台帳に無いパス（＝`record_granted_path`の記録漏れ）があると件数がずれる。
        // **ずれたら黙らない**（B-09。BUG-057・BUG-059はどちらも「付与したのに記録しなかった」
        // 欠陥で、記録漏れは撤収漏れに直結する）。
        if done.get() != total {
            eprintln!(
                "警告: 撤収した件数 {} が台帳の {total} 件と一致しません\
                 （台帳に記録されていない付与があった可能性があります）",
                done.get()
            );
        }
    }
}

/// 「このworkspaceが宛先SIDを発行済みのルート」のうち、**今回の宣言がもう要求していない**ものを返す。
///
/// 剥がす対象を決める判定そのもの。OSに触らない純粋関数にしてあるのは、**取りすぎ・取り足りず
/// のどちらも実害が出る**判定であり、実機や管理者権限なしで全数を固定したいためである
/// （条件を反転させたら「まだ要る穴を剥がす」になり、コマンドが動かなくなる）。
///
/// # 突き合わせは畳み込み鍵で行う（`eq_ignore_ascii_case`では足りない）
///
/// `held`の出どころは**capability台帳**で、綴りは`declaration_key`が畳んだ形
/// （小文字・区切りは`\`）である。一方`wanted`は`policy.json`由来なので区切りが`/`のことが多い。
/// 大文字小文字だけを無視する比較では**同じルートが別物に見え、まだ要る穴を全部剥がす**。
/// FS軸の畳み込みは1つでなければならない（`B-20`）ので、ここでも同じ関数を通す。
fn stale_roots(held: &[PathBuf], wanted: &[FsPassthrough]) -> Vec<PathBuf> {
    use harness_sandbox::tier2a::workspace_capability::declaration_key;
    let wanted_keys: Vec<String> = wanted.iter().map(|fp| declaration_key(&fp.path)).collect();
    held.iter()
        .filter(|granted| {
            let key = declaration_key(granted);
            !wanted_keys.iter().any(|w| w == &key)
        })
        .cloned()
        .collect()
}

/// 宣言が縮んだぶんのACEを剥がす（パス2開始時のreconcile、D-27と同型）。
///
/// # なぜここでやるのか（付与と同じライフサイクル点）
///
/// ACEが付くのは**パス2の開始時**（`preflight`）である。したがって「もう宣言されていない」に
/// なったACEを落とすのも同じ点でやるのが対になる。宣言を取り消した瞬間に剥がす設計にすると、
/// 付与は遅延するのに撤収は即時という非対称になり、しかもUACを要求しうる操作が
/// 「宣言を1行消すだけ」のつもりの操作へ紛れ込む。
///
/// # 縮んでいなければ何もしない
///
/// 差分が空なら追加コストは0である。`teardown`が実行1回ごとの撤収を**しない**理由
/// （同一プロセスの2回目で付け直す無駄を避ける）はここでも守られる——剥がすのは
/// 「今回の宣言に含まれないもの」だけなので、次の実行で付け直す対象にはならない。
fn reconcile_undeclared_roots(
    wanted: &[FsPassthrough],
    workspace_root: &Path,
    warnings: &mut Vec<String>,
    on_event: &mut dyn FnMut(NetRecordEvent),
) {
    // [§22.2.1] 宣言capabilityの索引は**canonicalize済みのworkspace**で引く。付与側
    // （`preflight`）が台帳へ書くときに使うのがその形なので、生のパスで絞ると
    // **1件も一致せず、黙って何も剥がさない**（この経路の失敗は無症状になる）。
    let canonical_ws = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    // [BUG-142] 索引は**台帳**から引く。かつてはプロセス内の`static`に「この実行が開けた穴」を
    // 覚えていたが、CLIの流れ（付与→`unapprove`→再実行）は3つとも別プロセスなので
    // **常に空集合との差分**になり、撤収が無言で0件になっていた。
    let held: Vec<PathBuf> =
        harness_sandbox::tier2a::workspace_capability::declared_paths_for_workspace(&canonical_ws)
            .into_iter()
            .map(PathBuf::from)
            .collect();
    let stale = stale_roots(&held, wanted);
    if stale.is_empty() {
        return;
    }

    // **黙って数十秒使わない**（B-23a）。剥がす側も付与と同じ再帰walkをするので、
    // 大きなツリーでは時間がかかる（`.cargo`への付与は実測142.6s）。
    on_event(NetRecordEvent::RevokingUndeclared { total: stale.len() });
    let profile = harness_sandbox::tier2a::session_profile::current_profile_name();
    // [残課題#37] **撤収の索引は1回だけ読む。** 単発版はパス1件ごとに台帳を全文読んで
    // 構文解析するので、宣言を数百件まとめて取り消すこの経路では、その読取が件数ぶん走る
    // （付与側と同じ形の費用。「配る側だけ速くして剥がす側を取り残さない」）。
    // 写しの限界は`workspace_capability::DeclarationIndex`のdocが持つ。
    let declaration_index = harness_sandbox::tier2a::workspace_capability::DeclarationIndex::load();
    for (index, path) in stale.iter().enumerate() {
        // [§22.2.1] **`--fs-allow`の宛先SIDは宣言ごとのcapability SIDへ移った。**
        // package SIDの撤収（下）だけでは、宣言を取り消しても穴が閉じない。
        // 絞り込みは自分のworkspaceに限る——このプロセスが開けた穴だけが対象で、
        // 同じパスを宣言している他のworkspaceの宛先SIDには触らない（BUG-046と同型）。
        match harness_sandbox::tier2a::win_appcontainer::revoke_declaration_capabilities_indexed(
            &declaration_index,
            path,
            Some(&canonical_ws),
            &|_, _| {},
        ) {
            Ok(report) if report.is_clean() => {}
            // **黙って飛ばさない**（B-10）。剥がせなかった穴は開いたままなので、
            // 「宣言を取り消したのにまだ通る」が起きる。昇格が要る場合もここへ来る。
            Ok(report) => warnings.push(format!(
                "fs-allow {} : the declaration capability ACE is still on the path after the \
                 revoke ({}); run `harness fs revoke {}` to close it",
                path.display(),
                report.still_on_root.join(", "),
                path.display()
            )),
            Err(e) => warnings.push(format!(
                "fs-allow {} : could not revoke the declaration capability ACE ({e}); run \
                 `harness fs revoke {}` to close it",
                path.display(),
                path.display()
            )),
        }
        // D-37時代の残骸（package SID宛）も同じ機会に剥がす。撤収は`end_session`が使うのと
        // **同じ関数**を通す（撤収経路を2つ持たない、B-05）。
        harness_sandbox::tier2a::win_appcontainer::revoke_session_grant(path, &profile);
        on_event(NetRecordEvent::UndeclaredRevoked {
            path: path.clone(),
            done: index + 1,
            total: stale.len(),
        });
    }
    // **セッション台帳（`granted_paths`）からは消さない。** 消すと「撤収の責任を負っている
    // パス」の記録が減り、剥がし残しがあったときに`end_session`/`gc_dead_sessions`が
    // 拾えなくなる。責任を多めに持つのは安全側で、少なく持つのがBUG-057・BUG-059の形である。
    //
    // [BUG-142] **capability台帳のほうは落とす。** ここが索引そのものなので、落とさないと
    // 次の実行でも同じパスをstaleとして拾い、剥がすものが無いまま再walkを繰り返す。
    // ただし判定は「撤収を呼んだ」ではなく**実DACLからもう消えている**で行う——
    // 生きているworkspaceの宛先SIDは意図的に残るので、呼んだだけを根拠に記録を捨てると
    // 宛先SIDを導出できない孤児ACEになる（`B-01`/`B-14`）。判定の実体は`harness-sandbox`側にある
    // （`harness fs revoke`系と共有。同じ判定を2箇所に書かない、`B-05`）。
    //
    // **ここで別の行は出さない。** 剥がしたことは`UndeclaredRevoked`が1件ずつ見せており
    // （付与と同じ粒度、`B-01`）、これはその後始末である。剥がせなかった場合は上の`warnings`が
    // 既に名指ししている——「無言で飛ばした」にはならない。
    let _forgotten = harness_sandbox::tier2a::win_appcontainer::forget_revoked_declarations(&stale);
}

/// WFPの出口強制daemonを**プロセスの寿命で**持つ（D-56）。
///
/// [`SessionGrants`]と同じ理由でここに置く——実行1回ごとに起こし直すとそのたびUACが出る。
/// 記録は同時に1本しか走らない（`session_lock`）が、TUIは記録を専用スレッドで回すので、
/// 所有権をUIスレッドに置いたままworkerへ貸せるよう`Arc<Mutex<..>>`で包む。
///
/// # 宣言順（重要）
///
/// **[`SessionGrants`]より後に宣言すること。** Rustは宣言の逆順にdropするので、これで
/// netfilterdの`Teardown`がAppContainerプロファイルの削除（`end_session`）より**先**に走る。
/// 逆にすると、フィルタが条件にしているpackage SIDのプロファイルを先に消すことになる
/// （現行`record_net`の撤収順「WFP → Proxy/Fake DNS → プロファイル」と同じ関係）。
///
/// # 落ちたときにどうなるか
///
/// `Drop`が走らない終わり方でも、プロセス消滅でパイプが閉じ、daemonは`ERROR_BROKEN_PIPE`を
/// 見て自発的に撤収する。残ったフィルタはDYNAMICセッションなのでBFEが消す
/// （`NetfilterSession`のdoc）。
#[derive(Clone, Default)]
pub struct SharedNetfilter {
    inner: std::sync::Arc<std::sync::Mutex<harness_sandbox::tier2a::netfilterd::NetfilterSession>>,
}

impl SharedNetfilter {
    pub fn hold() -> Self {
        Self::default()
    }

    /// 生きているdaemonを持っているか。**呼び出し側はこれを見て、投機的パイプの用意と
    /// privhelperへの連鎖起動依頼を省く**（B-23(c) 二重起動ガード）。
    pub fn is_live(&self) -> bool {
        self.lock().is_live()
    }

    /// **生きているdaemonから`privhelper`を起こす**（D-60、UACは出ない）。
    ///
    /// ポリシーエディタは「記録→承認→パス2」の対話ループなので、承認で増えたルートの
    /// 祖先traverse付与が**後から**必要になる。そのときnetfilterdは既に生きているので、
    /// `privhelper`はここから起こせる——起こさないと`runas`になり、**確定のたびにUACが
    /// 1回増える**（D-60の経緯そのもの）。
    ///
    /// 起こせなかった理由は`Err`で返す。呼び出し側（`preflight`）は`runas`へ落ちる。
    pub fn chain_launch_privhelper(&self, pipe_name: &str) -> Result<(), String> {
        self.chain_launch(
            harness_sandbox::tier2a::netfilterd::SiblingHelper::Privhelper,
            pipe_name,
        )
    }

    /// **生きているdaemonから収集器を起こす**（D-60の適用範囲を収集器へ広げたもの）。
    ///
    /// `ApplyRules`相乗りの経路（`chain_launch_policy_learnd`）は「netfilterdをこれから
    /// 起こす」ときにしか使えない——昇格側は1接続につき1回しか相乗りを受け付けないためで、
    /// **起動時前倒しでdaemonが常駐すると毎回そちらの条件になる**。塞がないと、
    /// netfilterdから消したUACが収集器で復活する（昇格するプロセスが入れ替わるだけになる）。
    pub fn chain_launch_collector(&self, pipe_name: &str) -> Result<(), String> {
        self.chain_launch(
            harness_sandbox::tier2a::netfilterd::SiblingHelper::PolicyLearnd,
            pipe_name,
        )
    }

    fn chain_launch(
        &self,
        helper: harness_sandbox::tier2a::netfilterd::SiblingHelper,
        pipe_name: &str,
    ) -> Result<(), String> {
        use harness_sandbox::tier2a::netfilterd::ChainLaunchReport;
        match self.lock().chain_launch_helper(helper, pipe_name) {
            None => Err("no resident WFP daemon to chain-launch from".to_string()),
            Some(Err(e)) => Err(e.to_string()),
            Some(Ok(ChainLaunchReport::Launched { .. })) => Ok(()),
            Some(Ok(ChainLaunchReport::Failed { reason })) => Err(reason),
        }
    }

    /// **daemonを先に起こしておく**（起動時前倒し）。`Ok(true)`は「この呼び出しで起こした
    /// ＝UACが1回出た」、`Ok(false)`は「既に居た」。
    ///
    /// 失敗しても記録は使える（必要になった時点で`apply`が起こす）ので、呼び出し側は
    /// 続行してよい——ただし**理由は必ず見せる**（黙って諦めると、後で出るUACの説明が付かない）。
    pub fn standby(&self) -> Result<bool, String> {
        self.lock().standby().map_err(|e| e.to_string())
    }

    fn lock(
        &self,
    ) -> std::sync::MutexGuard<'_, harness_sandbox::tier2a::netfilterd::NetfilterSession> {
        // 毒されたロックでも中身は使える——daemonのハンドルは`NetfilterSession`が持っており、
        // 最後の砦（プロセス終了でパイプが閉じる）はpanicの有無に依存しない。
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn apply(
        &self,
        prelude: Option<harness_sandbox::tier2a::netfilterd::PreparedPipe>,
        chain_attempted: bool,
        policy: harness_sandbox::tier2a::netfilterd::NetfilterPolicy,
    ) -> Result<
        harness_sandbox::tier2a::netfilterd::Applied,
        harness_sandbox::tier2a::netfilterd::NetfilterError,
    > {
        self.lock().apply(prelude, chain_attempted, policy)
    }

    fn clear(&self) -> Result<(), harness_sandbox::tier2a::netfilterd::NetfilterError> {
        self.lock().clear()
    }
}

struct Pass2Inner {
    exit_code: Option<i32>,
    aborted: Option<AbortReason>,
    granted_passthrough: Vec<harness_core::GrantedPassthrough>,
    denied_passthrough: Vec<(PathBuf, String, String)>,
    aggregate: NetAggregate,
    /// **強制が効いている状態で実際に拒否されたFSアクセス。** ネットワークの候補とは
    /// 別枠にする——スキーマも意味も違う（あちらは全許可の記録、こちらは強制下の拒否）。
    fs_aggregate: crate::aggregate::Aggregate,
}

/// **途中で失敗しても残さなければならない事実。**
///
/// [`Pass2Inner`]は成功したときにしか返らないので、そこへ置いた事実は失敗経路から消える。
/// 収集器が起きたかどうかは「拒否を1件も観測しなかった」と「観測していない」の区別
/// （D-43）そのものなので、**失敗した記録でも正しくなければならない**。
/// `warnings: &mut Vec<String>`と同じ形で外から渡し、**出所を1つにする**（B-13）。
#[derive(Default)]
struct Pass2Facts {
    collector_started: bool,
    etw_available: bool,
    /// 実行前診断が「このままでは起動できない」と名指しした実行ファイル
    /// （[`crate::exec_reach::ExecReach::unreachable_exec_value`]）。
    ///
    /// **失敗した記録にも残さなければならない。** 起動できないと分かっているコマンドは
    /// その先で落ちやすく、そのときこそ「何を許可すれば動くのか」が要る。
    unreachable_exec: Option<String>,
    /// 記録対象が実際に着地したTier（[`crate::session_dir::RecordManifest::shell_tier`]）。
    /// **Tierが確定した後にだけ入れる**——「Tier2aを狙った」と「Tier2aへ着地した」は
    /// 別の事実で、混ぜると失敗した記録が成功した記録と同じタグを持ってしまう（B-15）。
    shell_tier: Option<String>,
}

fn run_pass2<'a>(
    request: &RecordNetRequest<'a>,
    dir: &RecordSessionDir,
    warnings: &mut Vec<String>,
    facts: &mut Pass2Facts,
    state: &mut TeardownState<'a>,
    on_event: &mut dyn FnMut(NetRecordEvent),
) -> Result<Pass2Inner, RecordNetError> {
    let passthrough = passthrough_for_domain(request.domain, request.workspace_root);
    // **付与より先に、もう宣言されていない穴を閉じる。** 宣言を取り消しただけでは
    // このプロセスが既に開けたACEは残っており、同じプロセスで次のパス2を走らせると
    // 「取り消したのにまだ通る」ことになる（付与は`preflight`が宣言から毎回計算するので
    // 付け直しはされないが、剥がす側の経路が無かった）。
    reconcile_undeclared_roots(&passthrough, request.workspace_root, warnings, on_event);
    on_event(NetRecordEvent::ElevationExpected {
        // **出ない見込みのUACを予告しない**——出なかったことが「何か起きなかった」に見える。
        max_prompts: if request.wfp.is_live() {
            // 常駐daemonが居るなら全部まかなえる: netfilterdは`ApplyRules`の再送（D-56）、
            // privhelperと収集器は`ChainLaunchHelper`（D-60）。どれも昇格を起こさない。
            // 連鎖起動が失敗したときは、その時点で理由とUACが増える旨を警告に出す。
            0
        } else {
            // netfilterdをこれから起こす（1回）。workspace外の穴があるとprivhelperが先に
            // `runas`され、netfilterdはそこから連鎖起動されるので**実際は1回で収まる**
            // 見込みだが、連鎖が失敗すると2回になるので上限として数える。
            1 + u8::from(!passthrough.is_empty())
        },
    });
    on_event(NetRecordEvent::GrantingPassthrough {
        outside_count: passthrough.len(),
    });

    // WFPパイプは`select_tier`（＝preflight）**より前**に用意する。preflightがprivhelperへ
    // 委譲したとき、「処理完了後にこの名前でnetfilterdを連鎖起動してほしい」と添えられる
    // （シナリオA＝UACを1回に抑えられる経路）。
    //
    // **daemonが既に立っているなら、パイプも連鎖起動の依頼も作らない**（B-23(c) 二重起動ガード）。
    // 依頼を残すと、2回目の実行でworkspace外の新しい穴が要る場合——つまりprivhelperが起動する
    // 場合——に**2つ目のnetfilterdが連鎖起動される**。「2回目は`already_sufficient`が効くから
    // privhelperは起動しないはず」という当てには乗らない（ドメインを変えれば起動しうる）。
    let wfp_prelude = if request.wfp.is_live() {
        None
    } else {
        match harness_sandbox::tier2a::netfilterd::prepare_pipe() {
            Ok(prepared) => Some(prepared),
            Err(e) => {
                // ここで失敗しても`NetfilterHandle::start`（シナリオB、UACがもう1回）で立て直せる。
                warn(
                    format!(
                        "WFPの連鎖起動用パイプを用意できませんでした（{e}）。UACがもう1回出ます。"
                    ),
                    warnings,
                    on_event,
                );
                None
            }
        }
    };
    let wfp_chain_pipe = wfp_prelude.as_ref().map(|p| p.name().to_string());

    // 収集器の連鎖起動用パイプ。**収集器が既に生きているときだけ**用意しない（B-23(c)）。
    //
    // 起こし方は3通りあり、**どれもUACは0回**である。
    //
    // | netfilterdの状態 | 収集器の起こし方 |
    // |---|---|
    // | これから起こす | `ApplyRules`へ相乗り（`chain_launch_policy_learnd`） |
    // | 既に生きている | `ChainLaunchHelper`（D-60、`chain_launch_collector`） |
    // | 起こせなかった | `runas`（**ここだけUACが1回**） |
    //
    // 相乗りが「これから起こす場合だけ」なのは、昇格側が1接続につき1回しか受け付けない
    // ためである（2回目以降は拒否を印字して無視するので、依頼を残すと待ち時間だけが増える）。
    // **起動時前倒しでdaemonが常駐すると毎回「既に生きている」側になる**ので、
    // 2列目が無いと消したはずのUACが収集器で復活する。
    let learn_prelude = if request.collector.is_live() {
        None
    } else {
        match harness_sandbox::tier2a::policy_learnd::client::prepare_pipe() {
            Ok(prepared) => Some(prepared),
            Err(e) => {
                warn(
                    format!(
                        "収集器の連鎖起動用パイプを用意できませんでした（{e}）。UACがもう1回出ます。"
                    ),
                    warnings,
                    on_event,
                );
                None
            }
        }
    };
    let learn_chain_pipe = learn_prelude.as_ref().map(|p| p.name().to_string());
    // 相乗りを依頼するのは「netfilterdをこれから起こす」場合だけ（上の表）。
    let ride_learn_on_apply = !request.wfp.is_live();

    // preflightはここで`begin_session`を呼ぶ——**この行より後の全経路が`end_session`を
    // 通らなければならない**（`teardown`が担当）。
    state.session_started = true;
    // D-60: **2回目以降の記録では、privhelperを常駐netfilterdから起こす**（UACは出ない）。
    // 1回目はdaemonがまだ居ないので`chain_launch_privhelper`が`Err`を返し、`preflight`が
    // `runas`へ落ちる（UAC 1回）——これが「セッション全体でUAC 1回」の内訳である。
    let privhelper_launcher = |pipe_name: &str| request.wfp.chain_launch_privhelper(pipe_name);
    // **`Auto`ではなく`Tier2a`を渡す。** この経路はモジュールdocの表のとおり
    // 「着地したTierがTier2aでなければ中止」であり、Tier2aは選好ではなく**要件**である
    // ——Tier1にWFPは効かず素通しなので、そこで記録しても「何も拒否されなかった」以上のことは
    // 言えない。`Auto`のままだと、昇格できないアカウントでTier0へ降格し、
    // すぐ下の`selection.tier != ShellTier::Tier2a`で結局中止する（同じ結末を2段階で出す）。
    // 要求を引数で言えば、拒否の理由が`select_tier`の側で「tier2aを要求したが届かなかった」
    // として1つに定まる。下の分岐は残す——`Tier2a`指定なら`Ok`はTier2aだけのはずだという
    // 不変条件の検算として安い（B-06: 前提が変わったときに黙って通らない）。
    let selection = harness_sandbox::select_tier(
        RequireSandbox::None,
        request.workspace_root,
        SandboxChoice::Tier2a,
        &passthrough,
        wfp_chain_pipe,
        &WorkspaceWriteMode::DirectRw,
        Some(&privhelper_launcher),
    )
    .map_err(|e| RecordNetError::NotTier2a {
        tier: "(選択できず)".to_string(),
        reason: e.to_string(),
    })?;

    if selection.tier != ShellTier::Tier2a {
        // **到達しないはずの分岐**（`Tier2a`を要求しているので`Ok`ならTier2aである）。
        // 残してあるのは不変条件の検算のためで、D-75後は「降格した理由」という概念が無い
        // ので、理由の欄には**何が起きたか**をそのまま書く。
        return Err(RecordNetError::NotTier2a {
            tier: selection.tier.label().to_string(),
            reason: "select_tier(Tier2a)がTier2a以外を返しました（要求したTierに着地しない\
                     経路は存在しないはずです）"
                .to_string(),
        });
    }
    // ここへ来た＝**実際にTier2aへ着地した**（直前の分岐が他のTierを弾いている）。
    facts.shell_tier = Some(selection.tier.label().to_string());
    on_event(NetRecordEvent::Tier2aReady);
    for warning in &selection.passthrough_warnings {
        warn(warning.clone(), warnings, on_event);
    }

    // **実際にACEが付いた穴だけ**を台帳へ記録する（幻の台帳エントリを作らない、BUG-017）。
    // 記録しないと撤収経路の無い孤立ACEになるので、ここは飛ばせない。
    //
    // **台帳の更新は1回にまとめる。** `record_fs_passthrough_grant`を1件ずつ呼ぶと、
    // 1回ごとに全文読取＋`.bak`への全文コピー＋全文書込が走る。この台帳は実測185KBあるので
    // 1件あたり約550KB、668件では**約370MB**のI/Oになり数秒かかる
    // （`record_fs_passthrough_grants`のdoc）。**イベントの発火は1件ずつのまま**——
    // 見せ方と台帳の書き方は別の話である。
    // [BUG-101/§22.3] `granted_sid`には**何も入れない**（2026-09-01）。この欄が意味するのは
    // 「このパスへ**どのpackage SID宛に**ACEを付けたか」で、撤収側（`revoke_subjects`）は
    // `S-1-15-2-`で始まるSIDしか列挙しないため、そこに載る資格があるのはpackage SIDだけである。
    // 主体移行が済んだいま、`--fs-allow`の穴にpackage SID宛のACEは**1本も無い**ので、
    // `None`＝「package SID宛には付与していない」が事実そのものになる。
    //
    // capability SIDをここへ書かないのは、書いても撤収側が一度も見ないうえに、
    // package SID専用の欄へ別種を混ぜる形になるからである（`revoke_subjects`は
    // capability SIDを混ぜないことが意図——BUG-046の再発防止）。宣言capabilityの撤収は
    // `workspace-capability-ledger.json`の`declaration`欄を索引にした名前の付いた扉が担う。
    //
    // **移行前の記録は消えない**——この欄は上書きではなく積み増しである。
    let grants: Vec<_> = selection
        .granted_passthrough
        .iter()
        .map(|granted| {
            let path = &granted.path;
            harness_sandbox::tier2a::fs_passthrough_ledger::FsPassthroughGrantRecord {
                path: path.clone(),
                writable: granted.writable,
                forced: passthrough
                    .iter()
                    .find(|fp| &fp.path == path)
                    .map(|fp| fp.forced)
                    .unwrap_or(false),
                // [D-63] 宣言された範囲を記録する（`forced`と同じ引き方）。
                scope: passthrough
                    .iter()
                    .find(|fp| &fp.path == path)
                    .map(|fp| fp.scope)
                    .unwrap_or(harness_policy::GrantScope::Recursive),
                // policy.json由来はsettings.jsonの参照カウントに載せない。
                settings_workspace: None,
                granted_sid: None,
            }
        })
        .collect();
    harness_sandbox::tier2a::fs_passthrough_ledger::record_fs_passthrough_grants(&grants);
    // [BUG-142] **ここでプロセス内へ覚え直さない。** 「どのパスへ宛先SIDを発行したか」は
    // `preflight`が既にcapability台帳へ書いており（`declaration`欄）、撤収側は
    // `declared_paths_for_workspace`でそこから引く。2つ目の索引を作ると、
    // 片方だけ更新される形（＝この欠陥そのもの）へ戻る。
    for granted in &selection.granted_passthrough {
        on_event(NetRecordEvent::PassthroughGranted {
            path: granted.path.clone(),
            writable: granted.writable,
        });
    }
    // **付けられなかった穴は必ず見せる。** パス2が途中で落ちる原因はほぼこれである。
    harness_sandbox::tier2a::fs_passthrough_ledger::record_fs_passthrough_denials(
        &selection.denied_passthrough,
    );
    for (path, access, reason) in &selection.denied_passthrough {
        on_event(NetRecordEvent::PassthroughDenied {
            path: path.clone(),
            access: access.clone(),
            reason: reason.clone(),
        });
    }

    // --- 実行ファイルへ届くかを、**子を起こす前に**測る ---------------------------
    // 起こしてから`Access is denied`という文言を解釈する形にはしない（ロケール依存の
    // 文字列判定はBUG-086が「やってはいけない」と結論した形そのもの）。
    // **警告だけで止めない**（`exec_reach`のモジュールdoc参照）。
    //
    // envはここで組み立てて下の起動でも使い回す——`PATH`を測るときと渡すときで別々に
    // 読むと、片方だけ変わったときに判定が静かにずれる（B-05）。
    let mut env = harness_sandbox::secret_env::build_child_env();
    let reach = diagnose_command_exe(request, &selection.denied_passthrough, &env);
    // **表示はイベント側だけが行う。** ここで`warn`も呼ぶと、同じ文言が2回出る
    // （`Warning`と`ExecReachability`の両方を表示側が描くため。実機E2Eで実際に二重に出た）。
    // マニフェストへは残したいので、`warnings`へは直接積む。
    if let Some(message) = reach.message() {
        warnings.push(message);
    }
    // **名指しできた実行ファイルは候補の材料になる**（D-57の追記）。起動を拒否されたexeは
    // `ProcessStart`を出さないので、収集器の観測からは永久に候補が作れない——ここで拾わないと
    // 「詰まった当のexeだけが候補一覧に無い」状態が続く。文言ではなく**値**を残すこと
    // （表示のために積んだ`warnings`から後で文字列を切り出す形にはしない、B-05）。
    facts.unreachable_exec = reach.unreachable_exec_value();
    on_event(NetRecordEvent::ExecReachability(Box::new(reach)));

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
    let loopback =
        harness_tools::net_proxy::net_loopback_ports_for_agents(Some(proxy_addr), fake_dns_addr);
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
        chain_launch_policy_learnd: if ride_learn_on_apply {
            learn_chain_pipe.clone()
        } else {
            None
        },
    };
    // D-56: 生きているdaemonがあれば`ApplyRules`を再送するだけ（UACは出ない）。無ければ
    // シナリオA/Bで起こす。**この行より後の全経路が`teardown`（＝`ClearRules`）を通る。**
    let applied = request
        .wfp
        .apply(wfp_prelude, selection.netfilterd_chain_attempted, policy)
        .map_err(|e| RecordNetError::NoWfp(e.to_string()))?;
    state.wfp_applied = Some(request.wfp);
    on_event(NetRecordEvent::WfpEnforced {
        reused: applied.reused,
    });

    // --- deny-only収集器（パス2で実際に起きたFS拒否を観測する）---------------------
    // **WFPを張ってから起こす**（順序に依存は無いが、出口強制の確立を遅らせない）。
    // fail-open（D-43）: 起こせなくてもパス2は続ける。ただし観測できていない事実は必ず出す。
    let learn_policy = harness_sandbox::tier2a::policy_learnd::LearnPolicy {
        session_profile: harness_sandbox::tier2a::session_profile::current_profile_name(),
        workspace_root: request.workspace_root.to_path_buf(),
        fs_audit_log_path: dir.audit_log_path(),
        harness_pid: Some(std::process::id()),
        // **パス2はdeny-only。** 全アクセスを採ると、強制が効いている状態の「触れた記録」に
        // なってしまい、パス1（隔離しないTier0での記録）と意味が混ざる。
        record_all: false,
    };
    // **依頼したことと起きたことは別**（BUG-093）。昇格側は結末を`Applied`の応答で返すので、
    // 起きていないと分かっているものは待たない——待つと`ConnectNamedPipe`が60秒
    // タイムアウトしてから同じフォールバックへ着くだけで、その60秒が丸ごと無駄になる。
    if let Some(harness_sandbox::tier2a::netfilterd::ChainLaunchReport::Failed { reason }) =
        applied.chain_launch.as_ref()
    {
        // **黙ってフォールバックしない。** UACが1回増える理由をここで言い切る（B-32）。
        warn(
            format!(
                "収集器をnetfilterdから連鎖起動できませんでした（{reason}）。\
                 代わりに直接起動します——UACがもう1回出ます。"
            ),
            warnings,
            on_event,
        );
    }
    let learn_chain_attempted = if ride_learn_on_apply {
        learn_chain_pipe.is_some() && applied.collector_chain_launched()
    } else if let Some(pipe) = learn_chain_pipe.as_deref() {
        // daemonは既に生きている＝相乗りは使えない。D-60の`ChainLaunchHelper`で起こす
        // （これが無いと、ここが`runas`＝UAC1回になる）。
        match request.wfp.chain_launch_collector(pipe) {
            Ok(()) => true,
            Err(reason) => {
                warn(
                    format!(
                        "収集器を常駐daemonから連鎖起動できませんでした（{reason}）。\
                         代わりに直接起動します——UACがもう1回出ます。"
                    ),
                    warnings,
                    on_event,
                );
                false
            }
        }
    } else {
        // 収集器が既に生きている（`StartCollect`の再送だけで済む）。
        false
    };
    let collecting = match request.collector.start(
        learn_prelude,
        learn_chain_attempted,
        learn_policy,
    ) {
        Ok(collecting) => {
            // **起きた事実はここで確定させる**（この後に失敗しても消えない、`Pass2Facts`のdoc）。
            facts.collector_started = true;
            facts.etw_available = collecting.etw_available;
            on_event(NetRecordEvent::CollectorStarted {
                etw_available: collecting.etw_available,
                reused: collecting.reused,
            });
            if !collecting.etw_available {
                warn(
                    "収集器は起動しましたがETWセッションを張れませんでした。この実行では\
                     FSの拒否を1件も観測できません（理由はfs-audit.jsonlの制御レコードに残ります）。"
                        .to_string(),
                    warnings,
                    on_event,
                );
            }
            state.collector = Some(request.collector);
            Some(collecting)
        }
        Err(e) => {
            // **どちらの経路で試したかを必ず残す**（BUG-093）。「60秒待って接続が来なかった」
            // だけでは、netfilterdからの連鎖起動（UACなし）が黙って失敗したのか、`runas`の
            // UACが放置されたのかを後から区別できない。パイプ名は昇格側の制御レコードにも
            // 入るので、親とdaemonが同じ要求について話していることの突き合わせに使う。
            let route = if learn_chain_attempted {
                format!(
                    "netfilterdからの連鎖起動（追加UACなし）。依頼したパイプ: {}",
                    learn_chain_pipe.as_deref().unwrap_or("(不明)")
                )
            } else {
                "runasでの直接起動（UACが1回出るはずの経路）".to_string()
            };
            warn(
                format!(
                    "収集器を起動できませんでした（{e}）。試した経路: {route}／\
                     WFPのdaemonは{}。コマンドは実行しますが、FSの拒否は1件も記録されません。",
                    if applied.reused {
                        "既存を再利用した"
                    } else {
                        "この実行で起こした"
                    }
                ),
                warnings,
                on_event,
            );
            None
        }
    };
    // ETWの配送が始まるまで待つ。**対象コマンドの起動前**でなければ意味が無い。
    // **daemonを再利用してもこの待ちは消えない**（消えるのはUACだけ、B-32）。
    if collecting.is_some() {
        on_event(NetRecordEvent::WarmingUp(crate::record::WARMUP));
        std::thread::sleep(crate::record::WARMUP);
    }

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

    // `env`は上の到達性診断で組み立てたものをそのまま使う（同じ`PATH`で測って渡す）。
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

    let (child, _shell_label) =
        harness_sandbox::tier2a::win_appcontainer::spawn_shell_in_workspace(WorkspaceSpawn {
            cwd: request.cwd.to_path_buf(),
            env,
            workspace_root: request.workspace_root.to_path_buf(),
            cow_diff_layer_dir: None,
            granted_passthrough: selection.granted_passthrough.clone(),
            net_capability,
        })
        .map_err(|e| RecordNetError::Spawn(e.to_string()))?;
    let kill_token = child.kill_token();
    let mut rx = child.spawn_streaming(Some(&harness_tools::run_shell_bootstrap_stdin()));
    on_event(NetRecordEvent::ChildStarted);

    // --- 出力と監査を同時に吸う ---------------------------------------------------
    let mut aggregate = NetAggregate::new();
    let mut tail = crate::audit_tail::AuditTail::new(net_audit_path.clone());
    // 候補にしないパスの規則は**このセッションのworkspace**から作る（BUG-103）。
    // `from_session`（撤収後に読み直す方）と同じ規則になる——マニフェストの
    // `workspace_root`は`request.workspace_root`そのものなので、綴りも一致する。
    let mut fs_aggregate = crate::aggregate::Aggregate::new(
        crate::exclusion::ExclusionRules::for_session(request.workspace_root),
    );
    let mut fs_tail = crate::audit_tail::AuditTail::new(dir.audit_log_path());
    let outcome = {
        let mut sink = Pass2Sink {
            on_event,
            tail: &mut tail,
            aggregate: &mut aggregate,
            fs_tail: &mut fs_tail,
            fs_aggregate: &mut fs_aggregate,
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
    //
    // **収集器が居るときは長い方（ETWの配送遅延ぶん）で待つ。** net側だけの500msで抜けると、
    // 最後に起きたFS拒否——つまり「なぜ落ちたか」の答えそのもの——を取りこぼす。
    let drain = if collecting.is_some() {
        crate::record::DRAIN
    } else {
        NET_DRAIN
    };
    on_event(NetRecordEvent::Draining(drain));
    let until = Instant::now() + drain;
    while Instant::now() < until {
        drain_net_audit(&mut tail, &mut aggregate, on_event);
        drain_fs_audit(&mut fs_tail, &mut fs_aggregate, on_event);
        std::thread::sleep(POLL_INTERVAL);
    }
    drain_net_audit(&mut tail, &mut aggregate, on_event);
    drain_fs_audit(&mut fs_tail, &mut fs_aggregate, on_event);

    // 昇格側の制御レコードを**マニフェストにも残す**（画面は`drain_net_audit`が既に出している。
    // ここで`warn()`を使うと同じ文言が2回描かれる）。進行ログは末尾しか見せない窓なので、
    // 残さないと実行が終わった時点で理由が消える——それがBUG-093の見え方そのものだった。
    for reason in aggregate.control_reasons() {
        warnings.push(format!("昇格側（harness-netfilterd）からの報告: {reason}"));
    }

    Ok(Pass2Inner {
        exit_code: outcome.exit_code,
        aborted: outcome.aborted,
        granted_passthrough: selection.granted_passthrough.clone(),
        denied_passthrough: selection.denied_passthrough.clone(),
        aggregate,
        fs_aggregate,
    })
}

/// パス2が[`pump_child`]へ渡す出力先。パス1との違いは`on_tick`（何の監査ログを読むか）だけ。
struct Pass2Sink<'a> {
    on_event: &'a mut dyn FnMut(NetRecordEvent),
    tail: &'a mut crate::audit_tail::AuditTail,
    aggregate: &'a mut NetAggregate,
    /// FS監査（deny-only収集器が書く）。net側とは別のファイル・別の集計。
    fs_tail: &'a mut crate::audit_tail::AuditTail,
    fs_aggregate: &'a mut crate::aggregate::Aggregate,
}

impl ChildRunSink for Pass2Sink<'_> {
    fn on_line(&mut self, line: ShellLine) {
        (self.on_event)(NetRecordEvent::from_line(line));
    }

    fn on_tick(&mut self) {
        drain_net_audit(self.tail, self.aggregate, self.on_event);
        drain_fs_audit(self.fs_tail, self.fs_aggregate, self.on_event);
    }

    fn on_abort(&mut self, reason: AbortReason) {
        (self.on_event)(NetRecordEvent::Aborted(reason));
    }
}

/// FS監査ログ（収集器が書く`fs-audit.jsonl`）を読み進める。
///
/// net側と**別の関数**にしているのはスキーマが違うため（あちらは生のJSON値、こちらは
/// 型付きの[`harness_policy::FsAuditEvent`]）。集計も別で、`.harness`除外や実行像の
/// 候補化といった判断は`Aggregate`が既に持っているものをそのまま通す。
fn drain_fs_audit(
    tail: &mut crate::audit_tail::AuditTail,
    aggregate: &mut crate::aggregate::Aggregate,
    on_event: &mut dyn FnMut(NetRecordEvent),
) {
    let (events, skipped) = tail.poll_fs_events();
    for event in events {
        aggregate.add_event(&event);
        on_event(NetRecordEvent::FsAccess(Box::new(event)));
    }
    aggregate.add_unparsable(skipped);
}

fn drain_net_audit(
    tail: &mut crate::audit_tail::AuditTail,
    aggregate: &mut NetAggregate,
    on_event: &mut dyn FnMut(NetRecordEvent),
) {
    let (events, skipped) = tail.poll_json_values();
    for event in events {
        // **昇格側の制御レコードは通信の記録ではない**（BUG-093）。件数へ足して黙って
        // 流すと、`net-audit.jsonl`を手で開いた人にしか届かない——昇格側の`eprintln!`は
        // `SW_HIDE`のコンソールへ消えるので、これが「なぜ収集器が居ないのか」を伝える
        // 唯一の経路である。**その場で警告として出す。**
        if harness_policy::is_net_control_record(&event) {
            aggregate.add_event(&event);
            if let Some(reason) = event.get("reason").and_then(|v| v.as_str()) {
                // ここでは`warn()`を使わない——`warn()`はイベント発火と`warnings`への
                // 蓄積を両方やるが、`warnings`はこの関数から触れない。マニフェストへは
                // 呼び出し側が`aggregate.control_reasons()`から1回だけ積む
                // （**出す側1回・残す側1回**。両方でやると同じ文言が2回出る）。
                on_event(NetRecordEvent::Warning(format!(
                    "昇格側（harness-netfilterd）からの報告: {reason}"
                )));
            }
            continue;
        }
        aggregate.add_event(&event);
        on_event(NetRecordEvent::NetAccess(Box::new(event)));
    }
    aggregate.add_unparsable(skipped);
}

/// ドメインのFSルールから`FsPassthrough`を作る。
///
/// **workspace配下のパスは含めない**——Tier2aのworkspace grantが既に覆っているので、
/// 同じツリーへ別の宛先SIDのACEを重ねる意味が無い（`preflight`の走査対象を無駄に増やすだけ）。
/// 分類の規則は[`crate::approve`]の表示とそろえる（B-19: 綴りを揃える規則を2つ持たない）。
fn passthrough_for_domain(domain: &PolicyDomain, workspace_root: &Path) -> Vec<FsPassthrough> {
    // ルートの畳み込み（どれをworkspace外と見るか・重複したときどちらのaccessを採るか）は
    // [`crate::approve::grant_roots`]が唯一の定義を持つ。承認時に「N件になります」と警告する
    // のと同じ集合でなければ、警告した数と実際に待たされる数が食い違う（B-05）。
    crate::approve::grant_roots(domain, workspace_root)
        .into_iter()
        .map(|(path, access, scope)| FsPassthrough {
            path,
            access,
            // [D-63] 宣言値の書き方がそのまま付与範囲になる（`R`で付けた`/**`だけが再帰）。
            scope,
            // `--force-system-acl`（D-19）はポリシーエディタからは使わせない。
            // システム保護パスへ`SeRestorePrivilege`で強制付与するのは、記録のついでに
            // やってよい操作ではない（`harness fs`から明示的に行う）。
            forced: false,
        })
        .collect()
}

/// このドメインの宣言と付与結果から、コマンドの実行ファイルへ届くかを測る。
///
/// 判定そのものは[`crate::exec_reach`]の純粋関数が持つ（実機なしで全数テストできる）。
/// ここがやるのは**入力の組み立てだけ**——`PATH`は子へ渡す`env`から取る（プロセスのenvを
/// 別途読むと、渡す値と測る値が将来ずれる）。
fn diagnose_command_exe(
    request: &RecordNetRequest<'_>,
    denied_passthrough: &[(PathBuf, String, String)],
    env: &[(String, String)],
) -> crate::exec_reach::ExecReach {
    let path_env = env
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("PATH"))
        .map(|(_, value)| value.as_str())
        .unwrap_or("");
    let Some(exe) = crate::exec_reach::resolve_command_exe(request.command, path_env, request.cwd)
    else {
        return crate::exec_reach::ExecReach::Unresolved {
            token: request
                .command
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string(),
        };
    };
    let entries = request.domain.fs.entries();
    crate::exec_reach::diagnose(&exe, &entries, request.workspace_root, denied_passthrough)
}

/// 伝える価値のある事実を、**その場で見せる**と同時に**マニフェストへも残す**。
fn warn(message: String, warnings: &mut Vec<String>, on_event: &mut dyn FnMut(NetRecordEvent)) {
    on_event(NetRecordEvent::Warning(message.clone()));
    warnings.push(message);
}

#[cfg(test)]
mod stale_roots_tests {
    use super::*;
    use harness_sandbox::FsAccess;

    fn wanted(paths: &[&str]) -> Vec<FsPassthrough> {
        paths
            .iter()
            .map(|p| FsPassthrough {
                path: PathBuf::from(p),
                access: FsAccess::Read,
                forced: false,
                scope: harness_policy::GrantScope::Recursive,
            })
            .collect()
    }

    fn held(paths: &[&str]) -> Vec<PathBuf> {
        paths.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn a_root_that_is_no_longer_declared_is_stale() {
        let stale = stale_roots(
            &held(&["C:/Users/segfo/.cargo", "C:/Users/segfo/.rustup"]),
            &wanted(&["C:/Users/segfo/.cargo"]),
        );
        assert_eq!(stale, held(&["C:/Users/segfo/.rustup"]));
    }

    /// B-35の対。上のテストだけなら「常に全部staleと言う」実装でも緑になる——それは
    /// **まだ要る穴を毎回剥がす**（付け直しの待ち時間が毎回乗る）という別の壊れ方である。
    #[test]
    fn a_root_that_is_still_declared_is_never_stale() {
        let stale = stale_roots(
            &held(&["C:/Users/segfo/.cargo"]),
            &wanted(&["C:/Users/segfo/.cargo", "C:/Users/segfo/.rustup"]),
        );
        assert!(stale.is_empty(), "宣言が増えた側は剥がす対象にならない");
    }

    #[test]
    fn nothing_is_stale_when_the_declaration_did_not_change() {
        let same = ["C:/Users/segfo/.cargo", "C:/Users/segfo/.rustup"];
        assert!(stale_roots(&held(&same), &wanted(&same)).is_empty());
    }

    /// Windowsのパスは大文字小文字を区別しないので、綴りの違いで「別物」と見ると
    /// **まだ要る穴を剥がす**ことになる。
    #[test]
    fn the_comparison_ignores_case_because_windows_paths_do() {
        let stale = stale_roots(
            &held(&["C:/Users/segfo/.cargo"]),
            &wanted(&["c:/users/segfo/.CARGO"]),
        );
        assert!(stale.is_empty());
    }

    /// 前綴りを共有する別ルートを同一視すると、要る穴を剥がすか剥がし残す。
    /// ここは**完全一致だけ**を見る（`covers`のような包含判定ではない）——`grant_roots`が
    /// 返すのは畳み込み済みのルートそのものなので、比較すべきはルート同士の同一性である。
    #[test]
    fn a_sibling_root_sharing_a_prefix_is_a_different_root() {
        let stale = stale_roots(
            &held(&["C:/Users/segfo/.cargo"]),
            &wanted(&["C:/Users/segfo/.cargo-alt"]),
        );
        assert_eq!(
            stale,
            held(&["C:/Users/segfo/.cargo"]),
            "別ルートなのでstale（宣言されているのは .cargo-alt だけ）"
        );
    }

    /// [BUG-142] **`held`の出どころが台帳になったので、区切りの違いが日常的に混ざる。**
    ///
    /// 台帳の綴りは`declaration_key`が畳んだ形（区切りは`\`）、`wanted`は`policy.json`由来で
    /// `/`のことが多い。大文字小文字だけを無視する比較のままだと、この対が「別ルート」に見えて
    /// **まだ宣言されている穴を剥がす**。剥がすのは再帰walkなので、気づいたときには
    /// 付け直しの待ち時間が毎回乗っている。
    #[test]
    fn the_comparison_folds_separators_because_the_ledger_and_the_policy_file_spell_them_differently(
    ) {
        let stale = stale_roots(
            &held(&[r"c:\users\segfo\.cargo"]),
            &wanted(&["C:/Users/segfo/.cargo"]),
        );
        assert!(
            stale.is_empty(),
            "同じルートなので剥がしてはならない（区切りだけが違う）: {stale:?}"
        );
    }

    #[test]
    fn every_held_root_is_stale_when_all_declarations_were_unapproved() {
        // 再現性の確認（宣言を全部取り消してからパス2を走らせる）でまさにこの形になる。
        let stale = stale_roots(
            &held(&["C:/Users/segfo/.cargo", "C:/Users/segfo/.rustup"]),
            &wanted(&[]),
        );
        assert_eq!(stale.len(), 2);
    }
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

        let not_started = render_fs_denials(&empty, false, false);
        let no_etw = render_fs_denials(&empty, true, false);
        let observed_nothing = render_fs_denials(&empty, true, true);

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

    /// **ネットワークが全許可であることを必ず併記する。**
    ///
    /// 書かないと「テスト画面ができた」と読まれる——この実行はFSだけを宣言どおりに強制した
    /// 中間状態であり、ネットワークの強制はまだ試していない（決定27の範囲）。
    #[test]
    fn the_network_is_all_allowed_and_the_panel_says_so() {
        let empty =
            crate::aggregate::Aggregate::new(crate::exclusion::ExclusionRules::with_temp_root(
                std::path::Path::new("C:/no-such-workspace"),
                Some(std::path::Path::new("C:/no-such-temp")),
            ));

        let text = render_fs_denials(&empty, true, true);

        assert!(text.contains("ネットワークは全許可"), "{text}");
        assert!(text.contains("FSの拒否だけ"), "{text}");
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

        let text = render_fs_denials(&aggregate, true, true);

        assert!(text.contains("1件の拒否を観測"), "{text}");
    }
}
