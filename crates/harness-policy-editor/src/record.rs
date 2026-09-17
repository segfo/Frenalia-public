//! **パス1**（隔離なし＝Tier0でのrecord-all記録）のオーケストレーション。
//!
//! ```text
//!   排他を取る ── 記録セッションのディレクトリを作る ── 収集器を昇格起動（UAC 1回）
//!        │                                                      │
//!        │                                           ウォームアップ 1500ms
//!        │                                                      │
//!        │                              Tier0（隔離なし）でコマンドを起動
//!        │                                                      │
//!        │            ┌─────────── 出力を行単位で流す ───────────┤
//!        │            └─────────── 監査JSONLを追従読み ──────────┤
//!        │                                                      │
//!        │                                     終了 → 4秒待って収集器を撤収
//!        └── マニフェストを finished/canceled/failed で書き直す ─┘
//! ```
//!
//! # UIから独立させている理由
//!
//! ここは「記録する」という行為だけを持ち、表示は[`RecordEvent`]のコールバックへ渡す。
//! 今はCLIが受け取って標準出力へ書くが、TUIの記録画面も**同じ関数**を呼んで同じイベントを
//! 受け取る（画面ごとに記録の手順を書き直すと、片方だけ直る事故になる）。
//!
//! # なぜ同期なのか
//!
//! `tokio`は`RestrictedChild::spawn_streaming`が返すreceiverのために依存しているだけで、
//! ランタイムは起こさない。**この関数は呼び出しスレッドをブロックする**ので、
//! TUIから呼ぶときは`spawn_blocking`相当のスレッドで回すこと（B-31）。
//!
//! # 実測に基づく2つの待ち時間
//!
//! | 定数 | 値 | 根拠 |
//! |---|---|---|
//! | [`WARMUP`] | 1500ms | ETWのリアルタイムセッションは即座に配送を始めない。**対象コマンドの起動前に**待たないと`ProcessStart`ごと取りこぼし、観測が0件になる（`tier1_record_all_spike_tests.rs`で実測） |
//! | [`DRAIN`] | 4s | 対象コマンド終了後、バッファ内のイベントが配送され切るまでの待ち（同上） |

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// パス1はTier0（隔離なし）で記録するので、Tier1（`win_restricted`）へは依存しない。
// `OutputEvent`はTier0/Tier1/Tier2aが共有する`win_common`のものを直接使う。
use harness_sandbox::tier2a::policy_learnd::{self, LearnPolicy};
use harness_sandbox::win_common::OutputEvent;

use crate::aggregate::Aggregate;
use crate::audit_tail::AuditTail;
use crate::child_run::pump_child;
use crate::session_dir::{now_unix_ms, RecordManifest, RecordSessionDir, RecordStatus};
use crate::session_lock::{LockOutcome, RecordingLock};
use crate::shell_output::ShellLine;

pub use crate::child_run::AbortReason;

/// 記録を始める**前**にユーザーへ見せる前置き（CLIとTUIで共有）。
///
/// 何回UACが出るかは「このパスが何をするか」の一部なので、表示する側ではなく実行する側が持つ
/// ——UIを増やすたびに書き写すと、経路ごとに違うことを言い始める（B-05）。
pub const ELEVATION_NOTICE: &str =
    "隔離: なし（Tier0）。これはdry-runではありません。対象コマンドは、あなたのシェルと\n\
     同じ権限・同じ環境変数で本当に実行され、ファイル変更・秘密情報の読み取り・外部通信などの\n\
     副作用もそのまま起こります。push・deploy・publish・deleteなど、1回の実行自体が\n\
     害になり得るコマンドは、このパスでは記録しないでください。\n\
     記録の目的は「正常に動くときに何へ触るか」を観測することなので、観測の器が対象の動きを\n\
     変えないようにしています。\n\
     ETW収集器の起動でUACが1回出ます（収集器が張るETWセッションが管理者権限を要するため）。\n\
     観測機構はACEを付けませんが、対象コマンドが起こした変更はマシンに残ります。";

/// ETWセッションを張ってから対象コマンドを起動するまでの待ち（モジュールdocの表を参照）。
pub const WARMUP: Duration = Duration::from_millis(1500);
/// 対象コマンド終了後、収集器を撤収するまでの待ち（同上）。
pub const DRAIN: Duration = Duration::from_secs(4);
/// 収集器を撤収するまでの間、監査ログを読み続ける間隔。
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// 記録の要求。
pub struct RecordRequest<'a> {
    /// 記録対象のコマンド（PowerShellのスクリプトとして解釈される）。
    pub command: &'a str,
    /// 作業ディレクトリ。記録対象はここをcwdとして走る（隔離しないのでラベル等は付けない）。
    pub cwd: &'a Path,
    /// workspaceルート。監査ログの置き場（`.harness/sandbox/`配下）の基準。
    /// 昇格側が同じ基準で再検証する。
    pub workspace_root: &'a Path,
    /// 経過したら対象コマンドを打ち切る。`None`なら待ち続ける。
    pub timeout: Option<Duration>,
    /// 真を返したら打ち切る（TUIの停止操作用、B-23(b)）。
    pub cancel: &'a dyn Fn() -> bool,
    /// ETW収集器。**このプロセスの寿命で持つ**（D-56 段階2、[`SharedCollector`]）。
    ///
    /// 実行ごとに起こし直すとそのたびUACが出るので、2回目以降は同じdaemonへ
    /// `StartCollect`を再送する（記録の置き場は実行ごとに変わる）。
    pub collector: &'a SharedCollector,
    /// 常駐netfilterd（あれば）。パス1はWFPを張らないので`ApplyRules`への相乗りは使えないが、
    /// **netfilterdが既に生きているなら、そこから収集器を連鎖起動できる**（D-60の適用範囲。
    /// `record_net::start_collector`と同じ`ChainLaunchHelper`経路）。渡さない/生きていない
    /// なら`runas`にフォールバックする——`None`は「使えない」ことを表すだけで、記録自体は
    /// 従来どおり成立する。
    pub wfp: Option<&'a crate::record_net::SharedNetfilter>,
}

/// 収集器daemonを**プロセスの寿命で**持つ（D-56 段階2）。
///
/// [`crate::record_net::SharedNetfilter`]と同じ理由でここに置く——実行1回ごとに起こし直すと
/// そのたびUACが出る。記録は同時に1本しか走らない（`session_lock`）が、TUIは記録を専用
/// スレッドで回すので、所有権をUIスレッドに置いたままworkerへ貸せるよう`Arc<Mutex<..>>`で包む。
///
/// # 宣言順（重要）
///
/// **[`crate::record_net::SessionGrants`]より後に宣言すること。** Rustは宣言の逆順にdropするので、
/// これで収集器の`Teardown`がAppContainerプロファイルの削除より**先**に走る。
#[derive(Clone, Default)]
pub struct SharedCollector {
    inner: std::sync::Arc<
        std::sync::Mutex<harness_sandbox::tier2a::policy_learnd::client::CollectorSession>,
    >,
}

impl SharedCollector {
    pub fn hold() -> Self {
        Self::default()
    }

    /// 生きているdaemonを持っているか（B-23(c) 二重起動ガード）。
    pub fn is_live(&self) -> bool {
        self.lock().is_live()
    }

    fn lock(
        &self,
    ) -> std::sync::MutexGuard<'_, harness_sandbox::tier2a::policy_learnd::client::CollectorSession>
    {
        // 毒されたロックでも中身は使える——最後の砦（プロセス終了でパイプが閉じる）は
        // panicの有無に依存しない。
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn start(
        &self,
        prelude: Option<harness_sandbox::tier2a::policy_learnd::client::PreparedLearnPipe>,
        chain_attempted: bool,
        policy: LearnPolicy,
    ) -> Result<harness_sandbox::tier2a::policy_learnd::client::Collecting, policy_learnd::LearnError>
    {
        self.lock().start(prelude, chain_attempted, policy)
    }

    pub(crate) fn stop(&self) -> Result<Option<u64>, policy_learnd::LearnError> {
        self.lock().stop()
    }
}

/// 収集器が起きたことをユーザーへ伝える1行（CLIとTUIで共有する）。
///
/// **`reused`をここで文言に出すのが要点。** 2回目以降はdaemonを再利用するのでUACが出ないが、
/// それを「収集器が動いていない」と読み違えられると、この記録の意味が正反対になる（B-32）。
/// 文言は実行側が1つだけ持つ（`record_net::wfp_enforced_line`と同じ方針、規則5）。
pub fn collector_started_line(etw_available: bool, reused: bool) -> String {
    let base = if reused {
        "収集器を再利用しました（既に起動しているのでUACは出ていません）"
    } else {
        "収集器を起動しました"
    };
    if etw_available {
        format!("{base}。ETWセッションを張っています")
    } else {
        format!("{base}が、ETWセッションを張れていません（今回は何も観測できません）")
    }
}

/// 記録中に起きたこと。呼び出し側（CLI・TUI）が表示に使う。
#[derive(Debug, Clone)]
pub enum RecordEvent {
    /// 収集器が起動した。`etw_available=false`なら**何も観測できない**。
    ///
    /// `reused`が真なら**daemonを起こしていない＝UACが出ていない**（D-56 段階2）。
    CollectorStarted {
        etw_available: bool,
        reused: bool,
    },
    /// 収集器を起動できなかった（fail-open: 記録自体は続ける）。
    CollectorUnavailable(String),
    /// ETWの配送が始まるのを待っている。
    WarmingUp(Duration),
    /// 対象コマンドを起動した。
    ChildStarted,
    /// シェルがコマンドを走らせる**前に**吐いた出力（境界印より前）。
    /// コマンドの出力と混ぜない（BUG-086）。
    StartupNoise(String),
    Stdout(String),
    Stderr(String),
    /// 監査イベントを1件観測した。
    Access(Box<harness_policy::FsAuditEvent>),
    /// 対象コマンドが終了した。
    Exited(i32),
    /// キャンセルまたはタイムアウトで打ち切った。
    Aborted(AbortReason),
    /// 収集器の撤収を待っている。
    Draining(Duration),
    /// 収集器が撤収した。`written`は収集器の自己申告による書込件数。
    CollectorStopped {
        written: u64,
    },
    /// 記録中に起きた、伝える価値のある事実（致命的ではない）。
    Warning(String),
}

impl RecordEvent {
    fn from_line(line: ShellLine) -> Self {
        match line {
            ShellLine::StartupNoise(l) => RecordEvent::StartupNoise(l),
            ShellLine::Stdout(l) => RecordEvent::Stdout(l),
            ShellLine::Stderr(l) => RecordEvent::Stderr(l),
        }
    }
}

/// 記録の結果。
#[derive(Debug)]
pub struct RecordOutcome {
    pub session_id: String,
    pub session_dir: PathBuf,
    pub audit_log_path: PathBuf,
    pub exit_code: Option<i32>,
    pub aborted: Option<AbortReason>,
    pub collector_started: bool,
    pub etw_available: bool,
    pub collector_written: Option<u64>,
    pub warnings: Vec<String>,
    pub aggregate: Aggregate,
}

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("{0}")]
    AlreadyRecording(String),
    #[error("記録セッションのディレクトリを作れませんでした（{path}）: {source}")]
    SessionDir {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("記録セッションの排他を確認できませんでした: {0}")]
    Lock(String),
    #[error("記録対象のコマンドを起動できませんでした: {0}")]
    Spawn(String),
    #[error("PowerShellが見つかりません（pwsh も powershell も PATH にありません）")]
    NoShell,
    /// **argv観測を張れなかったので、記録を始めなかった**（段階6d、§10.3 fail-closed）。
    ///
    /// # この1つだけ扱いが違う
    ///
    /// 収集器が起動できない・ETWセッションが張れないは**fail-open**で、観測できないまま
    /// コマンドを走らせる（D-43）。argv観測だけは違う——黙って続けると
    /// 「argvが観測されなかった辺」と「argvを観測できなかった辺」が区別できなくなり、
    /// **候補が1件も出ない記録が「候補ゼロの記録」として残る**。
    #[error("{0}")]
    ArgvCaptureUnavailable(String),
}

impl RecordError {
    /// マニフェストへ残す**機械可読のタグ**（パス2の`RecordNetError::kind`と対。同じ理由で
    /// ワイルドカードを使わない）。
    pub fn kind(&self) -> &'static str {
        match self {
            RecordError::AlreadyRecording(_) => "already_recording",
            RecordError::SessionDir { .. } => "session_dir",
            RecordError::Lock(_) => "lock",
            RecordError::Spawn(_) => "spawn",
            RecordError::NoShell => "no_shell",
            RecordError::ArgvCaptureUnavailable(_) => "argv_capture_unavailable",
        }
    }
}

/// パス1を実行する。
///
/// **排他ロックはこの関数が保持する**（記録の全期間）。`show`/`sessions`のような
/// 読むだけの操作はロックを要さないので、起動時ではなくここで取る。
pub fn record(
    request: &RecordRequest<'_>,
    on_event: &mut dyn FnMut(RecordEvent),
) -> Result<RecordOutcome, RecordError> {
    let (lock, outcome) = RecordingLock::try_acquire().map_err(RecordError::Lock)?;
    if !outcome.can_proceed() {
        return Err(RecordError::AlreadyRecording(outcome.message().to_string()));
    }
    if outcome == LockOutcome::AcquiredAfterAbandon {
        on_event(RecordEvent::Warning(outcome.message().to_string()));
    }
    // ロックは記録が終わるまで保持する。`_lock`を早期dropさせない。
    let _lock = lock;

    // **記録1回ごとに別のディレクトリ**（`next_record_id`のdoc）。プロセス単位にすると、
    // 2回目の記録が1回目の監査ログへ追記し、1回目の観測が2回目の候補一覧に混ざる。
    let session_id = crate::session_dir::next_record_id();
    let dir = RecordSessionDir::create(request.workspace_root, &session_id).map_err(|e| {
        RecordError::SessionDir {
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
    // パス1は隔離せずに記録する（`spawn_tier0`のdoc）。**これはこの記録の読み方を左右する事実**
    // ——Tier1で録った古い記録には、Tier1固有の理由による拒否が混ざっている。
    manifest.shell_tier = Some("tier0".to_string());
    // **実体（収集）より先に「何をやっているか」を残す。** ここで落ちても、後から
    // `Running`のまま残ったマニフェストが「異常終了した記録がある」ことを示す。
    if let Err(e) = dir.write_manifest(&manifest) {
        on_event(RecordEvent::Warning(format!(
            "記録セッションのマニフェストを書けませんでした（{}）: {e}",
            dir.manifest_path().display()
        )));
    }

    let mut warnings: Vec<String> = Vec::new();

    // --- 収集器（昇格）を起こす -------------------------------------------------
    // `session_profile`はrecord-allではスコープ判定に使われない（Tier1にpackage SIDが
    // 無いため）が、昇格側が`is_session_profile_name`で形を検証するので有効な名前を送る。
    let policy = LearnPolicy {
        session_profile: harness_sandbox::tier2a::session_profile::current_profile_name(),
        workspace_root: request.workspace_root.to_path_buf(),
        fs_audit_log_path: dir.audit_log_path(),
        harness_pid: Some(std::process::id()),
        spawn_daemon_pid: None,
        record_all: true,
        // **argv観測を張るのはこの経路だけである**（段階6d、§10.3の入口の表）。
        // パス1は隔離せずに走らせるので、**子プロセスが実際に起きる唯一の記録**であり、
        // 遷移の辺の候補が取れるのはここしかない。隔離が効いている経路（パス2・
        // `--policy-learn`）で観測できるのは「断られた事実」で、それは待ち行列が既に持つ。
        //
        // **これはfail-closedである**——張れなければ記録そのものが始まらない
        // （`accept_started`）。止まるのはこのボタン1つで、通常運用のFS拒否収集は無関係である。
        capture_argv: true,
    };
    // D-56 段階2: 生きているdaemonがあれば`StartCollect`を再送するだけ（UACは出ない）。
    // 無ければ、常駐netfilterdがあればそこから連鎖起動し（D-60、`record_net::start_collector`と
    // 同じ経路）、それも無ければ`runas`で起こす。
    // **この行より後の全経路が`stop_collector`（＝`StopCollect`）を通る。**
    let (learn_prelude, chain_attempted) = if request.collector.is_live() {
        (None, false)
    } else {
        match request.wfp {
            Some(wfp) if wfp.is_live() => {
                match harness_sandbox::tier2a::policy_learnd::client::prepare_pipe() {
                    Ok(prepared) => match wfp.chain_launch_collector(prepared.name()) {
                        Ok(()) => (Some(prepared), true),
                        Err(e) => {
                            warn(
                                format!(
                                    "収集器を常駐daemonから連鎖起動できませんでした（{e}）。\
                                     代わりに直接起動します——UACがもう1回出ます。"
                                ),
                                &mut warnings,
                                on_event,
                            );
                            (None, false)
                        }
                    },
                    Err(e) => {
                        warn(
                            format!(
                                "収集器の連鎖起動用パイプを用意できませんでした（{e}）。\
                                 UACがもう1回出ます。"
                            ),
                            &mut warnings,
                            on_event,
                        );
                        (None, false)
                    }
                }
            }
            _ => (None, false),
        }
    };
    let collecting = match request
        .collector
        .start(learn_prelude, chain_attempted, policy)
    {
        Ok(collecting) => {
            on_event(RecordEvent::CollectorStarted {
                etw_available: collecting.etw_available,
                reused: collecting.reused,
            });
            if !collecting.etw_available {
                warn(
                    "収集器は起動しましたがETWセッションを張れませんでした。今回の実行では\
                     何も観測できません（理由はfs-audit.jsonlの制御レコードに残ります）。"
                        .to_string(),
                    &mut warnings,
                    on_event,
                );
            }
            Some(collecting)
        }
        // **argv観測の失敗だけは止まる**（段階6d、§10.3 fail-closed）。他の失敗と違い、
        // 続けても候補が1件も出ない記録にしかならず、それは「候補ゼロだった記録」と
        // 区別できない。**判定は変種で行う**——文面で見分けると、文面を直した日に
        // 静かにfail-openへ戻る（`B-13`）。
        Err(harness_sandbox::tier2a::policy_learnd::LearnError::ArgvCaptureUnavailable(reason)) => {
            on_event(RecordEvent::CollectorUnavailable(reason.clone()));
            // **ここで止めても後始末は要らない**——収集器は「始めなかった」と答えており、
            // この記録のためのETWセッションは1本も張られていない（`Generation::start`）。
            return Err(RecordError::ArgvCaptureUnavailable(format!(
                "argv（コマンドライン）の観測を始められなかったので、記録を中止しました。\
                 続けても遷移の候補が1件も出ません。{reason}"
            )));
        }
        Err(e) => {
            // fail-open（D-43）: 観測できないだけで、コマンドは走らせる。
            // **止めない代わりに、観測できていない事実は必ず残す。**
            on_event(RecordEvent::CollectorUnavailable(e.to_string()));
            warn(
                format!(
                    "収集器を起動できませんでした（{e}）。コマンドは実行しますが、\
                     FSアクセスは1件も記録されません。"
                ),
                &mut warnings,
                on_event,
            );
            None
        }
    };
    manifest.collector_started = collecting.is_some();
    manifest.etw_available = collecting.is_some_and(|c| c.etw_available);

    // ETWの配送が始まるまで待つ。**対象コマンドの起動前**でなければ意味が無い。
    // **daemonを再利用してもこの待ちは消えない**——セッションは記録ごとに張り直すので、
    // 配送が始まるまでの時間は毎回かかる。消えるのはUACだけである（B-32）。
    if collecting.is_some() {
        on_event(RecordEvent::WarmingUp(WARMUP));
        std::thread::sleep(WARMUP);
    }

    // --- Tier0で対象コマンドを起動 ---------------------------------------------
    // 候補にしないパスの規則は**このセッションのworkspace**から作る（BUG-103）。
    let mut aggregate = Aggregate::new(crate::exclusion::ExclusionRules::for_session(
        &manifest.workspace_root,
    ));
    let mut tail = AuditTail::new(dir.audit_log_path());

    let spawn_result = spawn_tier0(request);
    let (mut rx, kill_token) = match spawn_result {
        Ok(pair) => pair,
        Err(e) => {
            // 起動できなかった。収集器を撤収してからマニフェストを`Failed`で閉じる
            // ——**失敗経路でも後始末を飛ばさない**。
            let written = stop_collector(request.collector, collecting.is_some(), on_event);
            manifest.collector_written = written;
            manifest.warnings = warnings;
            // **理由まで残す。** `status: failed`だけでは、後から見た人にも次の記録にも
            // 「何が足りなかったか」が伝わらない（B-09）。
            manifest.fail(now_unix_ms(), e.kind(), &e);
            let _ = dir.write_manifest(&manifest);
            return Err(e);
        }
    };
    on_event(RecordEvent::ChildStarted);

    // --- 出力と監査を同時に吸う -------------------------------------------------
    // 微妙な判断（`Exited`と`OutputClosed`の独立・猶予・キャンセル）は`child_run`が持つ
    // ——パス2とまったく同じものを通す。ここで違うのは`on_tick`（何の監査ログを読むか）だけ。
    let outcome = {
        let mut sink = Pass1Sink {
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
    let exit_code = outcome.exit_code;
    let aborted = outcome.aborted;

    if let Some(code) = exit_code {
        on_event(RecordEvent::Exited(code));
    }

    // --- 収集器を撤収する（キャンセルでも必ず通る） ------------------------------
    if collecting.is_some() {
        on_event(RecordEvent::Draining(DRAIN));
        // ETWの配送遅延ぶん待つ。待っている間も監査ログは伸び続けるので読み続ける。
        let until = Instant::now() + DRAIN;
        while Instant::now() < until {
            drain_audit(&mut tail, &mut aggregate, on_event);
            std::thread::sleep(POLL_INTERVAL);
        }
    }
    let written = stop_collector(request.collector, collecting.is_some(), on_event);
    // 撤収時に最後の書込があるので、もう一度読み切る。
    drain_audit(&mut tail, &mut aggregate, on_event);

    manifest.status = match aborted {
        Some(_) => RecordStatus::Canceled,
        None => RecordStatus::Finished,
    };
    manifest.finished_unix_ms = Some(now_unix_ms());
    manifest.exit_code = exit_code;
    manifest.collector_written = written;
    manifest.warnings = warnings.clone();
    if let Err(e) = dir.write_manifest(&manifest) {
        on_event(RecordEvent::Warning(format!(
            "マニフェストを更新できませんでした: {e}"
        )));
    }

    Ok(RecordOutcome {
        session_id,
        session_dir: dir.path().to_path_buf(),
        audit_log_path: dir.audit_log_path(),
        exit_code,
        aborted,
        collector_started: manifest.collector_started,
        etw_available: manifest.etw_available,
        collector_written: written,
        warnings,
        aggregate,
    })
}

/// パス1が[`pump_child`]へ渡す出力先。**このパスに固有なのは`on_tick`（FS監査JSONLを
/// 追従読みする）だけ**で、行の切り分けも打ち切りの扱いも共有側が持つ。
struct Pass1Sink<'a> {
    on_event: &'a mut dyn FnMut(RecordEvent),
    tail: &'a mut AuditTail,
    aggregate: &'a mut Aggregate,
}

impl crate::child_run::ChildRunSink for Pass1Sink<'_> {
    fn on_line(&mut self, line: ShellLine) {
        (self.on_event)(RecordEvent::from_line(line));
    }

    fn on_tick(&mut self) {
        drain_audit(self.tail, self.aggregate, self.on_event);
    }

    fn on_abort(&mut self, reason: AbortReason) {
        (self.on_event)(RecordEvent::Aborted(reason));
    }
}

/// 伝える価値のある事実を、**その場で見せる**と同時に**マニフェストへも残す**。
/// 片方だけだと、実行中に流れていった警告が後から辿れない（またはその逆になる）。
fn warn(message: String, warnings: &mut Vec<String>, on_event: &mut dyn FnMut(RecordEvent)) {
    on_event(RecordEvent::Warning(message.clone()));
    warnings.push(message);
}

fn drain_audit(
    tail: &mut AuditTail,
    aggregate: &mut Aggregate,
    on_event: &mut dyn FnMut(RecordEvent),
) {
    let (events, skipped) = tail.poll_fs_events();
    for event in events {
        aggregate.add_event(&event);
        on_event(RecordEvent::Access(Box::new(event)));
    }
    aggregate.add_unparsable(skipped);
}

/// 現世代の収集を止める（**daemonは残す**、D-56 段階2）。書けた件数を返す。
///
/// `was_collecting`が偽なら何も送らない——収集器を起こせていないときに`StopCollect`を送ると、
/// 「畳んだ」という応答が0件で返ってきて、観測できなかったことと区別が付かなくなる。
fn stop_collector(
    collector: &SharedCollector,
    was_collecting: bool,
    on_event: &mut dyn FnMut(RecordEvent),
) -> Option<u64> {
    if !was_collecting {
        return None;
    }
    match collector.stop() {
        Ok(Some(written)) => {
            on_event(RecordEvent::CollectorStopped { written });
            Some(written)
        }
        Ok(None) => None,
        Err(e) => {
            on_event(RecordEvent::Warning(format!(
                "収集器が正常に撤収しませんでした: {e}。次の記録は収集器を起こし直すので、\
                 UACが1回出ます。"
            )));
            None
        }
    }
}

/// パス1の子へ渡す環境を組み立てる。**`secret_env`のallowlistを通さない。**
///
/// `build_child_env`（D-07）は**封じ込めのための**機構——秘密をサンドボックスの子へ流さない
/// ——で、隔離しないパス1には守るべき境界が無い。それどころか、envを削ると
/// **記録されるのが「正常動作」ではなく「環境を削られて壊れた動作」になる**。
///
/// 実際に踏んだ（2026-08-10）: allowlistは`PROGRAMDATA`を落としていたため、rustcが
/// Visual Studioを検出できず（検出はこの変数が指すインスタンスストアを読む）、PATH上の
/// GNU `link`（Git for Windows同梱）を掴んで`cargo test`が失敗した。その失敗した実行から
/// 集めた候補は「正常に動くために何が要るか」を表していない。**観測の器が対象を変えてはいけない。**
///
/// 露出は増えない——走らせるのはユーザー自身が自分のシェルで打つはずのコマンドで、
/// 同じ権限・同じ環境である。ポリシーエディタは「正常に動くプログラムを、その動作に限って
/// 許可する」ための道具なので、対象が敵対的である前提を置かない。裏返すと**パス1は何も
/// 封じ込めない**——このことは`harness_sandbox::tier0`のモジュールdocにも明記してある。
fn record_child_env_from(
    vars: impl IntoIterator<Item = (String, String)>,
    command: &str,
) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = vars.into_iter().collect();
    // コマンドはenv経由で渡す（`run_shell`と同じ形、BUG-050）。
    env.push((
        harness_tools::RUN_SHELL_COMMAND_ENV_VAR.to_string(),
        command.to_string(),
    ));
    env
}

/// Tier0（隔離なし）でコマンドを起動する。**`run_shell`とまったく同じ形**で起動する
/// （コマンドはenv経由、stdinは固定のブートストラップ、BUG-050）。
///
/// # なぜ隔離しないのか
///
/// 記録の目的は「このワークロードが何に触るか」を観測して許可を組むことなので、
/// **観測を制限下で行うと、サンドボックスの実装都合による拒否が候補一覧に混ざる**。
/// 以前はTier1（制限トークン+低IL）で起動していたが、低ILラベルはcwd 1個にしか
/// 付かないため、既存のサブディレクトリ（`src/`・`.git/`）やcwd外
/// （`$CARGO_HOME`・`~/.rustup/tmp`）への書込が**Tier1固有の理由で**拒否され、
/// それが「Tier2aで必要な許可」として候補に流れ込んでいた。
/// Tier1には許可を開けるレバーが無いのでこの汚染は避けようがなく、記録の器としては
/// 不適だった（`docs/STATUS.md`の「Tier1での拒否をTier2aで要る許可と読み替えないこと」）。
///
/// パス1を回すのはTier2aを使う人＝どちらにせよローカル管理者権限を持つ人（ETWの
/// リアルタイムセッションが昇格を要求する）なので、Tier0にしても要求は増えない。
/// 経緯は`plans/PLAN-POLICY-EDITOR-EXEC-DENIAL.md`「第11セッション」節。
///
/// ETWによるスコープ判定は`harness_pid`起点の親子継承だけで行っており、トークンの種別にも
/// package SIDにも依存しないので、Tier0でもそのまま機能する。
fn spawn_tier0(
    request: &RecordRequest<'_>,
) -> Result<
    (
        tokio::sync::mpsc::UnboundedReceiver<OutputEvent>,
        harness_sandbox::win_common::KillToken,
    ),
    RecordError,
> {
    let _ = std::fs::create_dir_all(request.cwd);
    // Tier1と違い、ここで付けるラベル（`set_low_integrity_label`）は無い。
    // 付けると記録対象自身を制限してしまい、上のdocのとおり候補一覧が汚れる。

    let bin = if which::which("pwsh").is_ok() {
        "pwsh"
    } else if which::which("powershell").is_ok() {
        "powershell"
    } else {
        return Err(RecordError::NoShell);
    };

    // **環境変数もユーザーのシェルと同じものを渡す**（allowlistを通さない）。
    //
    // `secret_env::build_child_env`は**封じ込めのための**機構（D-07。秘密をサンドボックスの
    // 子へ流さない）で、隔離しないパス1には守るべき境界が無い。それどころか、env を削ると
    // **記録されるのが「正常動作」ではなく「環境を削られて壊れた動作」になる**。
    //
    // 実際に踏んだ（2026-08-10）: allowlistは`PROGRAMDATA`を落としていたため、rustcが
    // Visual Studioを検出できずPATH上のGNU `link`（Git for Windows同梱）を掴み、
    // `cargo test`が`link.exe`絡みで失敗した。その失敗した実行から集めた候補は、
    // 「正常に動くために何が要るか」を表していない。**観測の器が対象を変えてはいけない。**
    //
    // 露出は増えない——パス1が走らせるのはユーザー自身が自分のシェルで打つはずのコマンドで、
    // 同じ権限・同じ環境である。ポリシーエディタは「正常に動くプログラムを、その動作に限って
    // 許可する」ための道具なので、対象が敵対的である前提を置かない。裏返すと、
    // **パス1は何も封じ込めない**——このことは`tier0`のモジュールdocにも明記してある。
    let env = record_child_env_from(std::env::vars(), request.command);

    let child = harness_sandbox::tier0::win_plain::spawn(
        bin,
        &["-NoProfile", "-NonInteractive", "-Command", "-"],
        request.cwd,
        &env,
        true,
    )
    .map_err(|e| RecordError::Spawn(e.to_string()))?;
    let kill_token = child
        .kill_token()
        .map_err(|e| RecordError::Spawn(e.to_string()))?;
    let rx = child.spawn_streaming(Some(&harness_tools::run_shell_bootstrap_stdin()));
    Ok((rx, kill_token))
}

#[cfg(test)]
mod record_env_tests {
    use super::*;

    /// パス1をdry-runと誤認すると、最初の実行そのものが害になる操作を記録してしまう。
    /// 警告は境界ではないが、運用で受けると決めた残存リスクと次の行動を実行前に渡す唯一の正本なので、
    /// 危険の説明と「記録しない」という行動の両方を固定する。
    #[test]
    fn pass1_notice_says_that_real_side_effects_are_not_contained() {
        assert!(ELEVATION_NOTICE.contains("dry-runではありません"));
        assert!(ELEVATION_NOTICE.contains("外部通信"));
        assert!(ELEVATION_NOTICE.contains("対象コマンドが起こした変更はマシンに残ります"));
        assert!(ELEVATION_NOTICE.contains("このパスでは記録しないでください"));
    }

    /// **記録の器が対象の環境を変えないこと。**
    ///
    /// `secret_env::build_child_env`のallowlistは`PATH`・`HOME`等ごく少数しか通さない。
    /// パス1がそれを通していた頃、`PROGRAMDATA`が落ちてrustcがMSVCリンカを見つけられず、
    /// PATH上のGNU `link`を掴んで`cargo test`が失敗した——**記録できたのは正常動作ではなく
    /// 壊れた動作**だった。ここが静かにallowlist経由へ戻ると同じことが起きるので固定する。
    ///
    /// allowlistと同じ集合を書き写すのではなく、**allowlistが落とす変数が残ること**を見る
    /// （書き写すと`secret_env`が変わったときに両方直す羽目になり、B-05の複製になる）。
    #[test]
    fn pass1_passes_the_ambient_environment_through_unfiltered() {
        let ambient = vec![
            ("PATH".to_string(), r"C:\Windows\system32".to_string()),
            ("PROGRAMDATA".to_string(), r"C:\ProgramData".to_string()),
            ("VSINSTALLDIR".to_string(), r"C:\VS".to_string()),
            ("SOME_RANDOM_VAR".to_string(), "x".to_string()),
        ];
        // 対照: 同じ入力をallowlistへ通すと、実際に落ちる変数がある。
        // これが空だとこのテストは何も証明しない（B-35: 対照群を置く）。
        let filtered = harness_sandbox::secret_env::build_child_env_from(ambient.clone());
        assert!(
            filtered.len() < ambient.len(),
            "control: the allowlist must actually drop something, otherwise this test is vacuous"
        );

        let env = record_child_env_from(ambient.clone(), "cargo test");

        for (name, value) in &ambient {
            assert!(
                env.iter().any(|(k, v)| k == name && v == value),
                "{name} must reach the recorded command unchanged — filtering the environment \
                 makes the recording describe a broken run, not a normal one"
            );
        }
        assert!(
            env.iter()
                .any(|(k, v)| k == harness_tools::RUN_SHELL_COMMAND_ENV_VAR && v == "cargo test"),
            "the command itself is still handed over via env (same shape as run_shell, BUG-050)"
        );
    }
}

#[cfg(test)]
mod error_kind_tests {
    use super::*;

    /// パス2（`RecordNetError`）と**対**の固定。片方だけタグを持つ状態を作らない（B-01）。
    #[test]
    fn every_failure_gets_its_own_label() {
        let all = [
            RecordError::AlreadyRecording("x".into()),
            RecordError::SessionDir {
                path: PathBuf::from("C:/w"),
                source: std::io::Error::other("x"),
            },
            RecordError::Lock("x".into()),
            RecordError::Spawn("x".into()),
            RecordError::NoShell,
        ];

        let mut seen: Vec<&str> = all.iter().map(|e| e.kind()).collect();
        let total = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), total, "duplicate error_kind labels: {seen:?}");
        assert!(seen.iter().all(|k| !k.is_empty()));
    }
}
