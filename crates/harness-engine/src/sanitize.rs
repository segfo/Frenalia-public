//! Tier3（Hyper-V外層VM + Incusコンテナ）実行時に、**ホスト側の実体をモデルへ見せない**ための
//! 伏字化。`plans/DESIGN-SANDBOX-VMISOLATION.md`のTier3ではシェルがLinuxコンテナ内で走り、
//! モデルから見える世界は`/workspace`だけであるべきなので、Windows絶対パス（`C:\...`）が
//! 混じったテキストは全て`/workspace`へ潰す。
//!
//! 適用点は3つあり、いずれも「モデルへ送る／ユーザへ見せる」直前に置く:
//! [`completion_request`]（リクエスト全体）・[`content_blocks`]／[`tool_output`]（履歴へ積む前）・
//! [`visible_delta`]（ストリーミング表示）。
//!
//! **冪等**である（`X:\...`→`/workspace`の結果は再適用しても不動点になる）。
//! [`crate::turn`]と[`crate::run_agent_loop`]が同じリクエストへ二重に適用する経路があるため、
//! この性質に依存している。

use harness_core::{CompletionRequest, ContentBlock, Message, ToolCtx, ToolOutput};

/// リクエスト全体（system + messages + tools）を伏字化する。
pub(crate) fn completion_request(req: &mut CompletionRequest) {
    for block in &mut req.system {
        string(&mut block.text);
    }
    messages(&mut req.messages);
    for tool in &mut req.tools {
        string(&mut tool.description);
        json_value(&mut tool.input_schema);
    }
}

fn messages(messages: &mut [Message]) {
    for msg in messages {
        content_blocks(&mut msg.content);
    }
}

/// `thinking`/`redacted_thinking`は伏字化ではなく**除去**する（署名付きのまま伏字化すると
/// プロバイダ側の署名検証が壊れるため、Tier3では往復させない）。
pub(crate) fn content_blocks(blocks: &mut Vec<ContentBlock>) {
    blocks.retain_mut(|block| match block {
        ContentBlock::Text(text) => {
            string(text);
            true
        }
        ContentBlock::Thinking { .. } | ContentBlock::RedactedThinking { .. } => false,
        ContentBlock::ToolUse {
            id: _,
            name: _,
            input,
        } => {
            json_value(input);
            true
        }
        ContentBlock::ToolResult { content, .. } => {
            string(content);
            true
        }
        ContentBlock::Image { .. } => true,
    });
}

pub(crate) fn tool_output(output: &mut ToolOutput) {
    string(&mut output.content);
}

/// ストリーミング表示用。Tier3以外では何もしない（呼び出し側の分岐を省くためここで判定する）。
pub(crate) fn visible_delta(text: &str, ctx: &ToolCtx) -> String {
    if ctx.shell_tier.tier == harness_core::ShellTier::Tier3 {
        redact_windows_absolute_paths(text)
    } else {
        text.to_string()
    }
}

fn json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => string(s),
        serde_json::Value::Array(items) => {
            for item in items {
                json_value(item);
            }
        }
        serde_json::Value::Object(map) => {
            for (_key, value) in map {
                json_value(value);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

fn string(s: &mut String) {
    *s = redact_windows_absolute_paths(s);
}

fn redact_windows_absolute_paths(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < chars.len() {
        if is_windows_drive_path_at(&chars, i) {
            out.push_str("/workspace");
            i += 3;
            while i < chars.len() && is_windows_path_char(chars[i]) {
                i += 1;
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

fn is_windows_drive_path_at(chars: &[char], i: usize) -> bool {
    i + 2 < chars.len()
        && chars[i].is_ascii_alphabetic()
        && chars[i + 1] == ':'
        && is_windows_separator(chars[i + 2])
        && !is_url_scheme_tail_at(chars, i)
}

/// `chars[i]`がURLスキームの**末尾1文字**に過ぎない場合を弾く（[BUG-067](../../../docs/bugs/BUG-067.md)）。
///
/// 走査は文字列の任意の位置で`<英字>:<区切り>`を探すので、`https://example.com`の`s:/`・
/// `http://x`の`p:/`が「ドライブパス」に見えてしまい、URLが`http/workspace`のように壊れていた。
/// **`run_shell`のコマンドも`web_fetch`のURLも同じ経路を通る**ので、Tier3では
/// `curl`/`wget`/`git clone`/`pip install`が軒並み黙って壊れる。
///
/// URLだと言い切れるのは次の2条件が**両方**揃ったときだけにする。
///
/// 1. 直前が`[A-Za-z0-9+.-]`（RFC 3986のスキーム文字）である＝`s`や`p`がスキームの途中である
/// 2. コロンの直後が`//`である＝authority形式（`scheme://host`）
///
/// 2を必須にするのが肝で、これが無いと`-IC:/include`のような**本物のドライブパス**まで
/// 見逃して伏字化が漏れる（漏れは機密性の毀損なので、壊す側より慎重に倒す）。
/// Windowsのドライブパスが`C://foo`と書かれることは実務上無いため、この2条件で
/// 取りこぼす実パスは無い。
fn is_url_scheme_tail_at(chars: &[char], i: usize) -> bool {
    let preceded_by_scheme_char = i > 0
        && (chars[i - 1].is_ascii_alphanumeric()
            || matches!(chars[i - 1], '+' | '.' | '-'));
    let authority_form = matches!(chars.get(i + 3), Some('/'));
    preceded_by_scheme_char && authority_form
}

fn is_windows_separator(c: char) -> bool {
    c == '\\' || c == '/' || c == '¥'
}

fn is_windows_path_char(c: char) -> bool {
    !c.is_whitespace()
        && !matches!(
            c,
            '"' | '\'' | '`' | ')' | '）' | ']' | '】' | '}' | '。' | '、' | ',' | ';' | '|'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`crate::turn::TurnExecutor::raw_turn_with_deltas`]は、呼び出し側が既に伏字化済みの
    /// リクエストを渡してくる場合でも choke point として無条件に再適用する。ここが冪等で
    /// ないと、二重適用でリクエストが壊れる（＝`run_agent_loop`の圧縮リトライ経路が
    /// 既に依存している性質でもある）。
    /// BUG-067: URLのスキーム（`https:`/`http:`）の末尾1文字をドライブレターと誤認して
    /// URLを壊していた。Tier3では`run_shell`のコマンドも`web_fetch`のURLもこの経路を通る。
    #[test]
    fn urls_are_not_mistaken_for_windows_drive_paths() {
        for url in [
            "https://example.com",
            "http://x.test/a/b?q=1",
            "ftp://host/f",
            "git+ssh://git@host/repo.git",
            "socks5h://127.0.0.1:1080",
        ] {
            assert_eq!(
                redact_windows_absolute_paths(url),
                url,
                "a URL must survive redaction untouched: {url}"
            );
        }
        assert_eq!(
            redact_windows_absolute_paths("wget -qO- https://example.com | head -5"),
            "wget -qO- https://example.com | head -5"
        );
    }

    /// URLを守るために**本物のドライブパスを見逃してはいけない**（漏れは機密性の毀損）。
    /// 直前が英数字でも、`X://`というauthority形式でない限り伏字化し続ける。
    #[test]
    fn real_drive_paths_are_still_redacted_even_when_glued_to_a_flag() {
        assert_eq!(redact_windows_absolute_paths("-IC:/include"), "-I/workspace");
        assert_eq!(redact_windows_absolute_paths(r"cd C:\Users\me"), "cd /workspace");
        assert_eq!(redact_windows_absolute_paths("D:/tmp/x"), "/workspace");
        // 単独の1文字スキームは判別不能なので、安全側（伏字化）へ倒す。
        assert_eq!(redact_windows_absolute_paths("s://y"), "/workspace");
    }

    #[test]
    fn redaction_is_idempotent() {
        let original = r#"see C:\Users\me\project\src and D:/tmp/x, then "E:\q" done"#;
        let once = redact_windows_absolute_paths(original);
        let twice = redact_windows_absolute_paths(&once);
        assert_eq!(once, twice);
        assert!(!once.contains(r"C:\"), "{once}");
        assert!(once.contains("/workspace"), "{once}");
    }
}
