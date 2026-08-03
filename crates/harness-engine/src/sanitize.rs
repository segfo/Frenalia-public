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
