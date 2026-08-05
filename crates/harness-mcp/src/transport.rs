//! `Transport` trait と、改行区切りフレーミングの共通部品。
//!
//! `plans/DESIGN-MCP.md` §6は「`Transport`はtraitとして切り、実装を差し替えられる形にする」と
//! 定める。実装は2つある——[`crate::transport_stdio`]（§6.1、AppContainerの箱の中。Windows専用）と
//! [`crate::transport_http`]（§6.2、harness本体が喋るオプトイン経路）。
//!
//! ## なぜ同期APIなのか
//!
//! stdioの実体がAppContainer子プロセスの生HANDLEパイプ（`ReadFile`/`WriteFile`）であり、
//! `harness-sandbox`の他のIPC（`netfilterd`・`vmsandboxd`）と同じくブロッキングである。
//! 呼び出し側（`Tool::call`）は`tokio::task::spawn_blocking`越しに呼ぶ——`VmShellExecutor`
//! （`harness-core`）が同期メソッドを持つのと同じ理由・同じ扱い。
//!
//! HTTP実装は非同期のHTTPクライアントを使うが、**ブロックする側を専用スレッドへ閉じ込めて**
//! この同期APIに合わせている（trait側を非同期化するとstdioが`spawn_blocking`のまま二重になる）。
//!
//! ## フレーム形式
//!
//! MCPのstdioトランスポートは**改行区切りのJSON**で、メッセージ本体に改行を含めてはならない。
//! したがって「1行＝1メッセージ」で扱ってよい（`netfilterd`の長さプレフィックス方式とは別物で、
//! こちらは相手がMCP仕様に従う任意実装なので仕様どおりの改行区切りに合わせる）。
//! Streamable HTTPの区切りはSSE（空行区切り）で、[`crate::http_wire::SseAccumulator`]が
//! [`LineAccumulator`]の上に載る。

use std::time::Duration;

use crate::McpError;

/// 1つのMCPサーバとの通信路。
///
/// **実装は`Send`だが`Sync`である必要はない**。同時に触るのは[`crate::client::McpClient`]の
/// mutexの内側だけで、リクエストとレスポンスは1往復ずつ直列化される（クライアントのdoc参照）。
pub trait Transport: Send {
    /// 1メッセージを送る。改行の付加は実装側が行う。
    fn send_line(&mut self, line: &str) -> Result<(), McpError>;

    /// 1メッセージを受け取る。`timeout`を過ぎたら[`McpError::Timeout`]。
    fn recv_line(&mut self, timeout: Duration) -> Result<String, McpError>;

    /// これまでにサーバがstderrへ出した内容を取り出して空にする。
    ///
    /// **エラー診断のためだけに使う。** MCPサーバは起動失敗の理由をstderrにしか書かないことが
    /// 多く、これが無いと「タイムアウトしました」以上のことを何も言えない。
    fn take_stderr(&mut self) -> String;

    /// プロセス/接続を落とす。冪等。
    fn shutdown(&mut self);

    /// `initialize`でネゴシエートされたプロトコルバージョンが確定したときに呼ばれる。
    ///
    /// stdioには関係が無いので既定はno-op。**Streamable HTTPはこれを必要とする**——
    /// MCP仕様は`initialize`以降の全リクエストへ`MCP-Protocol-Version`ヘッダを求めており、
    /// 送らないクライアントはサーバから2025-03-26とみなされる。バージョンを知っているのは
    /// [`crate::client::McpClient`]だけなので、トランスポートへはここで伝える。
    fn on_protocol_negotiated(&mut self, version: &str) {
        let _ = version;
    }
}

/// バイト列から改行区切りの行を切り出す蓄積バッファ。
///
/// パイプからの読み取りは行境界と無関係な塊で返るため、どの`Transport`実装でもこの分解が要る。
/// 純粋なので単体テストで固定できる（`docs/CODE-STRUCTURE-RULES.md` 規則3の副次効果）。
///
/// **`Default`は`new()`と同じ**（derive すると`max_line_bytes`が0になり、最初の1バイトで
/// 上限超過エラーになる）。
#[derive(Debug)]
pub struct LineAccumulator {
    buf: Vec<u8>,
    /// 行が来ないまま無制限にメモリを食うのを防ぐ上限。未信頼のサーバが改行を一切送らずに
    /// 出力し続ける経路（`DESIGN-MCP.md` §2「起動された後は敵対的かもしれない」）を塞ぐ。
    max_line_bytes: usize,
}

/// 1行の上限（16MiB）。MCPのツール応答は大きくなり得るが、無制限にはしない。
pub const DEFAULT_MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

impl Default for LineAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl LineAccumulator {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
        }
    }

    pub fn with_max_line_bytes(max_line_bytes: usize) -> Self {
        Self {
            buf: Vec::new(),
            max_line_bytes,
        }
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// 完成した行を1つ取り出す（無ければ`None`）。行末の`\r`は落とす（Windowsのサーバが
    /// CRLFで書く場合がある）。空行は読み飛ばす。
    pub fn take_line(&mut self) -> Result<Option<String>, McpError> {
        loop {
            let Some(line) = self.take_raw_line()? else {
                return Ok(None);
            };
            if line.bytes().all(|b| b.is_ascii_whitespace()) {
                continue;
            }
            return Ok(Some(line));
        }
    }

    /// 空行も落とさずに1行返す。
    ///
    /// **SSEは空行がイベントの区切り**（`plans/DESIGN-MCP.md` §6.2）なので、
    /// [`crate::http_wire::SseAccumulator`]はこちらを使う。JSON-RPCの改行区切り
    /// （[`take_line`](Self::take_line)）では空行に意味が無いので読み飛ばす、という違い。
    pub fn take_raw_line(&mut self) -> Result<Option<String>, McpError> {
        let Some(pos) = self.buf.iter().position(|b| *b == b'\n') else {
            if self.buf.len() > self.max_line_bytes {
                return Err(McpError::Protocol(format!(
                    "server sent more than {} bytes without a newline",
                    self.max_line_bytes
                )));
            }
            return Ok(None);
        };
        let mut line = self.buf.drain(..=pos).collect::<Vec<u8>>();
        line.pop(); // '\n'
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Ok(Some(String::from_utf8_lossy(&line).into_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_on_newlines_across_chunk_boundaries() {
        let mut acc = LineAccumulator::new();
        acc.push_bytes(b"{\"a\":");
        assert_eq!(acc.take_line().unwrap(), None);
        acc.push_bytes(b"1}\n{\"b\":2}\n");
        assert_eq!(acc.take_line().unwrap().as_deref(), Some("{\"a\":1}"));
        assert_eq!(acc.take_line().unwrap().as_deref(), Some("{\"b\":2}"));
        assert_eq!(acc.take_line().unwrap(), None);
    }

    #[test]
    fn strips_carriage_returns_and_skips_blank_lines() {
        let mut acc = LineAccumulator::new();
        acc.push_bytes(b"\r\n   \n{\"a\":1}\r\n");
        assert_eq!(acc.take_line().unwrap().as_deref(), Some("{\"a\":1}"));
    }

    /// 未信頼のサーバが改行を送らずに出力し続けても、メモリを食い尽くさずエラーになる。
    #[test]
    fn a_server_that_never_sends_a_newline_is_cut_off() {
        let mut acc = LineAccumulator::with_max_line_bytes(16);
        acc.push_bytes(&[b'x'; 8]);
        assert_eq!(acc.take_line().unwrap(), None);
        acc.push_bytes(&[b'x'; 32]);
        assert!(matches!(acc.take_line(), Err(McpError::Protocol(_))));
    }

    /// 不正UTF-8で落ちない（未信頼の入力なので、パースは後段のJSONに任せる）。
    #[test]
    fn invalid_utf8_is_lossily_decoded_rather_than_panicking() {
        let mut acc = LineAccumulator::new();
        acc.push_bytes(&[0xff, 0xfe, b'\n']);
        assert!(acc.take_line().unwrap().is_some());
    }
}
