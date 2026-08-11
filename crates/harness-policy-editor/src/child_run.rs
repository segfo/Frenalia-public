//! 記録対象の子プロセスを回し切るループ——出力を流し、監査ログを追従読みし、
//! キャンセル／タイムアウトを見て、終了を見届けるまで。
//!
//! パス1（Tier0のFS記録）とパス2（Tier2aのドメイン記録）が**同じ関数**を通る。ここには
//! 実測で決まった微妙な判断が3つ入っており、経路ごとに書き直すと片方だけが直る:
//!
//! 1. **`Exited`を見た瞬間に抜けない。** `Exited`（待機スレッド）と出力行（読取スレッド）は
//!    独立したスレッドから送られるので、終了通知が最後の数行を追い越して届き得る。
//!    抜けるのは「出力も閉じた」か「猶予（[`OUTPUT_GRACE`]）を使い切った」ときだけ。
//! 2. **`OutputClosed`だけを待って粘りもしない。** 孫プロセスがstdout/stderrを握ったままだと
//!    EOFが遅れる（`stream_child_output`のdoc）。
//! 3. **印が一度も来なかった場合に溜め込んだ行を捨てない。** シェルがブートストラップの
//!    最初の文へ到達する前に死んだとき、その出力が唯一の手掛かりになる（BUG-086の裏返し）。
//!
//! # キャンセルの見せ方（B-23(b)）
//!
//! `cancel`が真を返したらジョブごと畳む。CLIには停止操作が無いので常に偽を返すクロージャを
//! 渡す——**「押せば止まる」ように見せない**。Ctrl-Cで本プロセスが終われば、ジョブの
//! kill-on-closeで子孫ツリーが畳まれる（寿命がOSハンドルに紐付いている）。

use std::time::{Duration, Instant};

use harness_sandbox::win_common::OutputEvent;

use crate::shell_output::{ShellLine, StartupNoiseFilter};

/// 監査ログの追従読みとキャンセル確認の間隔。
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// プロセス終了を観測してから、まだ届いていない出力を待つ猶予（モジュールdocの1番）。
const OUTPUT_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortReason {
    Canceled,
    TimedOut,
}

/// [`pump_child`]が呼び出し側へ返すもの。
#[derive(Debug, Default)]
pub struct ChildRunOutcome {
    pub exit_code: Option<i32>,
    pub aborted: Option<AbortReason>,
}

/// [`pump_child`]がループの内側から呼ぶ側。**3つを1つのtraitにまとめてある**のは、
/// どれも同じ出力先（呼び出し側のイベントコールバック）を可変で触るためで、別々の
/// クロージャにすると呼び出し側が同じものを3回可変借用することになる。
pub trait ChildRunSink {
    /// 出力1行（起動時ノイズと本文は切り分け済み）。
    fn on_line(&mut self, line: ShellLine);
    /// 毎周回1回。**監査ログの追従読みをここでやる**（記録の種類ごとに違う唯一の部分）。
    fn on_tick(&mut self);
    /// 打ち切りが決まった瞬間（表示のため。実際のkillは[`pump_child`]が行う）。
    fn on_abort(&mut self, reason: AbortReason);
}

/// 子プロセスを終わりまで回す。
///
/// `kill`は打ち切るときに呼ぶ（ジョブはkill-on-closeなので、この後`Exited`が届く）。
pub fn pump_child(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<OutputEvent>,
    kill: &dyn Fn(),
    timeout: Option<Duration>,
    cancel: &dyn Fn() -> bool,
    sink: &mut dyn ChildRunSink,
) -> ChildRunOutcome {
    let started = Instant::now();
    let mut outcome = ChildRunOutcome::default();
    let mut exited_at: Option<Instant> = None;
    let mut output_closed = false;
    let mut killed = false;
    let mut out_filter = StartupNoiseFilter::new();
    let mut err_filter = StartupNoiseFilter::new();

    loop {
        // 出力イベントを取れるだけ取る。
        loop {
            match rx.try_recv() {
                Ok(OutputEvent::Stdout(line)) => {
                    for event in out_filter.feed(line, /* stderr */ false) {
                        sink.on_line(event);
                    }
                }
                Ok(OutputEvent::Stderr(line)) => {
                    for event in err_filter.feed(line, /* stderr */ true) {
                        sink.on_line(event);
                    }
                }
                Ok(OutputEvent::Exited(code)) => {
                    outcome.exit_code = Some(code);
                    exited_at = Some(Instant::now());
                }
                Ok(OutputEvent::OutputClosed) => output_closed = true,
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    // 送り手が全員居なくなった＝これ以上出力は来ない。
                    output_closed = true;
                    break;
                }
            }
        }
        sink.on_tick();

        // モジュールdocの1番・2番。
        if let Some(exited_at) = exited_at {
            if output_closed || exited_at.elapsed() >= OUTPUT_GRACE {
                break;
            }
        }
        if !killed {
            if cancel() {
                outcome.aborted = Some(AbortReason::Canceled);
            } else if timeout.is_some_and(|limit| started.elapsed() >= limit) {
                outcome.aborted = Some(AbortReason::TimedOut);
            }
            if let Some(reason) = outcome.aborted {
                sink.on_abort(reason);
                // ジョブはkill-on-closeなので、この後`Exited`が届いて子孫ごと畳まれる。
                kill();
                killed = true;
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }

    // モジュールdocの3番。
    for line in out_filter.flush(false) {
        sink.on_line(line);
    }
    for line in err_filter.flush(true) {
        sink.on_line(line);
    }

    outcome
}
