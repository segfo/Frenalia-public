//! AppContainer子プロセスとの**長寿命双方向セッション**（`plans/DESIGN-MCP.md` §3.3）。
//!
//! Tier2aの既存のspawnは`run_shell`の実行モデル（コマンドを渡し、終わるまで待ち、出力を全部読む）
//! に合わせた一問一答である（[`AppContainerChild::write_stdin_read_output_and_wait`]）。
//! MCP stdioはこれと形が違い、**プロセスを生かしたまま、リクエストとレスポンスを何度も往復させる**。
//!
//! したがってこの経路は既存経路を**置き換えず並べて**持つ。`run_shell`は既存経路を使い続ける。
//!
//! ## 何をこのモジュールが持ち、何を持たないか
//!
//! ここが扱うのは**バイト列**までで、メッセージの切り出し（MCPの改行区切りフレーミング）は
//! 持たない。フレーミングは`harness-mcp`側（`transport_stdio`）にある——サンドボックスは
//! 「プロセスとパイプ」を知り、MCPクレートは「プロトコル」を知る、という分割線である
//! （`docs/CODE-STRUCTURE-RULES.md` 規則3「どの外部システムと話すか」）。
//!
//! ## プロセスの寿命
//!
//! 起動時にJob Objectへ割り当て済み（`spawn_impl`）なので、harnessプロセスが落ちれば
//! MCPサーバも道連れで落ちる。[`AppContainerSession::shutdown`]は「速く確実に片付ける」ための
//! 明示経路であって、正しさの要件ではない。

use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use windows::Win32::Storage::FileSystem::WriteFile;

use super::*;

/// stderrを溜め込む上限。未信頼のサーバ（`DESIGN-MCP.md` §2）がstderrへ延々と書き続けても
/// harness側のメモリを食い尽くさないようにする。超過分は**古い方から捨てる**——診断で見たいのは
/// 直近の失敗理由であって、起動直後のバナーではない。
const MAX_STDERR_BYTES: usize = 256 * 1024;

/// 1回の読み取りで受け取るバッファ長。
const READ_CHUNK: usize = 8192;

#[derive(Debug, Clone, thiserror::Error)]
pub enum SessionError {
    #[error("timed out waiting for output from the sandboxed process")]
    Timeout,
    #[error("the sandboxed process closed its output: {0}")]
    Closed(String),
    #[error("i/o with the sandboxed process failed: {0}")]
    Io(String),
}

/// 生きているAppContainer子プロセスとの双方向セッション。
pub struct AppContainerSession {
    process: HANDLE,
    job: HANDLE,
    stdin_write: HANDLE,
    /// stdout読み取りスレッドからのバイト列。**行の切り出しはしない**（モジュールdoc参照）。
    stdout_rx: Receiver<Vec<u8>>,
    stderr: Arc<Mutex<Vec<u8>>>,
    closed: bool,
}

// HANDLEは値として複数スレッド間で運んでよい（`AppContainerChild`と同じ扱い）。
unsafe impl Send for AppContainerSession {}

impl AppContainerSession {
    pub(super) fn new(
        process: HANDLE,
        job: HANDLE,
        stdin_write: HANDLE,
        stdout_read: HANDLE,
        stderr_read: HANDLE,
    ) -> Self {
        let (tx, stdout_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        spawn_reader_thread(stdout_read, move |chunk| tx.send(chunk).is_ok());

        let stderr = Arc::new(Mutex::new(Vec::new()));
        let stderr_sink = stderr.clone();
        spawn_reader_thread(stderr_read, move |chunk| {
            let Ok(mut buf) = stderr_sink.lock() else {
                return false;
            };
            buf.extend_from_slice(&chunk);
            if buf.len() > MAX_STDERR_BYTES {
                let drop_to = buf.len() - MAX_STDERR_BYTES;
                buf.drain(..drop_to);
            }
            true
        });

        Self {
            process,
            job,
            stdin_write,
            stdout_rx,
            stderr,
            closed: false,
        }
    }

    /// 子プロセスのstdinへ書く。
    pub fn write_all(&mut self, mut bytes: &[u8]) -> Result<(), SessionError> {
        if self.closed {
            return Err(SessionError::Closed(
                "session already shut down".to_string(),
            ));
        }
        while !bytes.is_empty() {
            let mut written = 0u32;
            let ok = unsafe { WriteFile(self.stdin_write, Some(bytes), Some(&mut written), None) };
            if ok.is_err() {
                return Err(SessionError::Io(format!(
                    "WriteFile to the sandboxed process failed: {}",
                    windows::core::Error::from_win32()
                )));
            }
            if written == 0 {
                // 相手が読まなくなった（プロセス終了）。書き続けても進まないので打ち切る。
                return Err(SessionError::Closed(
                    "the sandboxed process stopped reading its stdin".to_string(),
                ));
            }
            bytes = &bytes[written as usize..];
        }
        Ok(())
    }

    /// stdoutに届いているバイト列を1塊受け取る。届いていなければ`timeout`まで待つ。
    ///
    /// **行境界とは無関係**な塊が返る。呼び出し側が蓄積して切り出す。
    pub fn read_some(&mut self, timeout: Duration) -> Result<Vec<u8>, SessionError> {
        match self.stdout_rx.recv_timeout(timeout) {
            Ok(chunk) => Ok(chunk),
            Err(RecvTimeoutError::Timeout) => Err(SessionError::Timeout),
            Err(RecvTimeoutError::Disconnected) => {
                let stderr = self.take_stderr();
                let stderr = stderr.trim();
                Err(SessionError::Closed(if stderr.is_empty() {
                    "the sandboxed process exited without writing anything to stderr".to_string()
                } else {
                    format!("the sandboxed process exited; stderr: {stderr}")
                }))
            }
        }
    }

    /// これまでにstderrへ出た内容を取り出して空にする。
    pub fn take_stderr(&mut self) -> String {
        let Ok(mut buf) = self.stderr.lock() else {
            return String::new();
        };
        let bytes = std::mem::take(&mut *buf);
        crate::win_common::decode_console_bytes(&bytes)
    }

    /// プロセスを落としてハンドルを閉じる。冪等。
    ///
    /// stdinを先に閉じるのは、行儀のよいサーバがEOFを見て自分から終われるようにするため。
    /// ただし待たずにJob全体を明示終了する——未信頼のプロセスが自発的に終わることを
    /// harnessの終了処理が当てにしてはいけない（`DESIGN-MCP.md` §2）。子がさらに孫を
    /// 作っていた場合もまとめて落とした後、Job Objectを閉じる。
    pub fn shutdown(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        unsafe {
            let _ = CloseHandle(self.stdin_write);
            terminate_job_and_close(self.job);
            let _ = CloseHandle(self.process);
        }
    }
}

impl Drop for AppContainerSession {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// パイプの読み取り端を専有するスレッドを起こす。`sink`が`false`を返したら（受信側が消えた）
/// 読み取りをやめる。**ハンドルの所有権はスレッドへ移り**、終了時に閉じる。
fn spawn_reader_thread(handle: HANDLE, mut sink: impl FnMut(Vec<u8>) -> bool + Send + 'static) {
    struct SendHandle(HANDLE);
    unsafe impl Send for SendHandle {}
    let handle = SendHandle(handle);

    std::thread::spawn(move || {
        let handle = handle;
        let mut buf = vec![0u8; READ_CHUNK];
        loop {
            let mut read = 0u32;
            let ok = unsafe { ReadFile(handle.0, Some(&mut buf), Some(&mut read), None) };
            if ok.is_err() || read == 0 {
                // ERROR_BROKEN_PIPE（子プロセス終了）を含む。正常な終端。
                break;
            }
            if !sink(buf[..read as usize].to_vec()) {
                break;
            }
        }
        unsafe {
            let _ = CloseHandle(handle.0);
        }
    });
}
