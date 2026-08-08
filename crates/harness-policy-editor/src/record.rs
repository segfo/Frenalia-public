//! **パス1**（Tier1のrecord-all記録）のオーケストレーション。
//!
//! ```text
//!   排他を取る ── 記録セッションのディレクトリを作る ── 収集器を昇格起動（UAC 1回）
//!        │                                                      │
//!        │                                           ウォームアップ 1500ms
//!        │                                                      │
//!        │                              cwdへ低ILラベル → Tier1でコマンドを起動
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

use harness_sandbox::tier1::win_restricted::{self, OutputEvent};
use harness_sandbox::tier2a::policy_learnd::{self, LearnPolicy};

use crate::aggregate::Aggregate;
use crate::audit_tail::AuditTail;
use crate::child_run::pump_child;
use crate::session_dir::{now_unix_ms, RecordManifest, RecordSessionDir, RecordStatus};
use crate::session_lock::{LockOutcome, RecordingLock};
use crate::shell_output::ShellLine;

pub use crate::child_run::AbortReason;

/// ETWセッションを張ってから対象コマンドを起動するまでの待ち（モジュールdocの表を参照）。
pub const WARMUP: Duration = Duration::from_millis(1500);
/// 対象コマンド終了後、収集器を撤収するまでの待ち（同上）。
pub const DRAIN: Duration = Duration::from_secs(4);
/// 収集器を撤収するまでの間、監査ログを読み続ける間隔。
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// 記録の要求。
pub struct RecordRequest<'a> {
    /// Tier1で走らせるコマンド（PowerShellのスクリプトとして解釈される）。
    pub command: &'a str,
    /// 作業ディレクトリ。**低ILラベルを付ける唯一のディレクトリ**でもある。
    pub cwd: &'a Path,
    /// workspaceルート。監査ログの置き場（`.harness/sandbox/`配下）の基準。
    /// 昇格側が同じ基準で再検証する。
    pub workspace_root: &'a Path,
    /// 経過したら対象コマンドを打ち切る。`None`なら待ち続ける。
    pub timeout: Option<Duration>,
    /// 真を返したら打ち切る（TUIの停止操作用、B-23(b)）。
    pub cancel: &'a dyn Fn() -> bool,
}

/// 記録中に起きたこと。呼び出し側（CLI・TUI）が表示に使う。
#[derive(Debug, Clone)]
pub enum RecordEvent {
    /// 収集器が起動した。`etw_available=false`なら**何も観測できない**。
    CollectorStarted { etw_available: bool },
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
    CollectorStopped { written: u64 },
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
    #[error("Tier1でコマンドを起動できませんでした: {0}")]
    Spawn(String),
    #[error("PowerShellが見つかりません（pwsh も powershell も PATH にありません）")]
    NoShell,
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

    let session_id = harness_sandbox::tier2a::session_profile::session_token().to_string();
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
        record_all: true,
    };
    let collector = match policy_learnd::client::start(policy) {
        Ok(handle) => {
            on_event(RecordEvent::CollectorStarted {
                etw_available: handle.etw_available(),
            });
            if !handle.etw_available() {
                warn(
                    "収集器は起動しましたがETWセッションを張れませんでした。今回の実行では\
                     何も観測できません（理由はfs-audit.jsonlの制御レコードに残ります）。"
                        .to_string(),
                    &mut warnings,
                    on_event,
                );
            }
            Some(handle)
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
    manifest.collector_started = collector.is_some();
    manifest.etw_available = collector.as_ref().is_some_and(|c| c.etw_available());

    // ETWの配送が始まるまで待つ。**対象コマンドの起動前**でなければ意味が無い。
    if collector.is_some() {
        on_event(RecordEvent::WarmingUp(WARMUP));
        std::thread::sleep(WARMUP);
    }

    // --- Tier1で対象コマンドを起動 ---------------------------------------------
    let mut aggregate = Aggregate::new();
    let mut tail = AuditTail::new(dir.audit_log_path());

    let spawn_result = spawn_tier1(request, &mut |message| {
        warn(message, &mut warnings, on_event);
    });
    let (mut rx, kill_token) = match spawn_result {
        Ok(pair) => pair,
        Err(e) => {
            // 起動できなかった。収集器を撤収してからマニフェストを`Failed`で閉じる
            // ——**失敗経路でも後始末を飛ばさない**。
            let written = stop_collector(collector, on_event);
            manifest.status = RecordStatus::Failed;
            manifest.finished_unix_ms = Some(now_unix_ms());
            manifest.collector_written = written;
            manifest.warnings = warnings;
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
    if collector.is_some() {
        on_event(RecordEvent::Draining(DRAIN));
        // ETWの配送遅延ぶん待つ。待っている間も監査ログは伸び続けるので読み続ける。
        let until = Instant::now() + DRAIN;
        while Instant::now() < until {
            drain_audit(&mut tail, &mut aggregate, on_event);
            std::thread::sleep(POLL_INTERVAL);
        }
    }
    let written = stop_collector(collector, on_event);
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

fn stop_collector(
    collector: Option<policy_learnd::client::PolicyLearnHandle>,
    on_event: &mut dyn FnMut(RecordEvent),
) -> Option<u64> {
    let handle = collector?;
    match handle.stop() {
        Ok(written) => {
            on_event(RecordEvent::CollectorStopped { written });
            Some(written)
        }
        Err(e) => {
            on_event(RecordEvent::Warning(format!(
                "収集器が正常に撤収しませんでした: {e}"
            )));
            None
        }
    }
}

/// Tier1でコマンドを起動する。**`run_shell`とまったく同じ形**で起動する
/// （コマンドはenv経由、stdinは固定のブートストラップ、BUG-050）。
fn spawn_tier1(
    request: &RecordRequest<'_>,
    warn: &mut dyn FnMut(String),
) -> Result<
    (
        tokio::sync::mpsc::UnboundedReceiver<OutputEvent>,
        win_restricted::KillToken,
    ),
    RecordError,
> {
    let _ = std::fs::create_dir_all(request.cwd);
    // 低ILラベルが付かないと、Tier1の子はcwd**内**にも書けない（BUG-088）。
    // 致命的にはしないが、**事実は必ず残す**——ここを`let _ =`にしていたことが
    // BUG-088を数か月見えなくした原因である。
    if let Err(e) = win_restricted::set_low_integrity_label(request.cwd) {
        warn(format!(
            "cwd（{}）へ低ILラベルを付けられませんでした: {e}。記録対象はcwd内にも\
             書き込めないため、本来は起きない書込拒否が記録される可能性があります。",
            request.cwd.display()
        ));
    }

    let bin = if which::which("pwsh").is_ok() {
        "pwsh"
    } else if which::which("powershell").is_ok() {
        "powershell"
    } else {
        return Err(RecordError::NoShell);
    };

    let mut env = harness_sandbox::secret_env::build_child_env();
    env.push((
        harness_tools::RUN_SHELL_COMMAND_ENV_VAR.to_string(),
        request.command.to_string(),
    ));

    let child = win_restricted::spawn(
        bin,
        &["-NoProfile", "-NonInteractive", "-Command", "-"],
        request.cwd,
        &env,
        true,
    )
    .map_err(|e| RecordError::Spawn(e.to_string()))?;
    let kill_token = child.kill_token();
    let rx = child.spawn_streaming(Some(&harness_tools::run_shell_bootstrap_stdin()));
    Ok((rx, kill_token))
}

