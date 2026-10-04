use std::sync::Mutex;

use futures::stream::{self, BoxStream};
use harness_core::{ProviderCapabilities, ProviderError, StopReason, StreamEvent};

use super::*;

const LINE: &str =
    "echo cwB5AHMAdABlAG0AaQBuAGYAbwA= | ForEach-Object { [Convert]::FromBase64String($_) }";

/// 送られた要求を控え、用意した本文を返すプロバイダ。
struct Replying {
    body: String,
    seen: Mutex<Vec<CompletionRequest>>,
}

#[async_trait]
impl LlmProvider for Replying {
    fn id(&self) -> &str {
        "replying"
    }

    async fn stream(
        &self,
        req: CompletionRequest,
    ) -> Result<BoxStream<'static, Result<StreamEvent, ProviderError>>, ProviderError> {
        self.seen.lock().unwrap().push(req);
        Ok(Box::pin(stream::iter(
            vec![
                StreamEvent::TextDelta {
                    index: 0,
                    text: self.body.clone(),
                },
                StreamEvent::Done {
                    stop_reason: StopReason::EndTurn,
                    usage: Default::default(),
                },
            ]
            .into_iter()
            .map(Ok),
        )))
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::default()
    }
}

/// **探すのも抜き出すのもハーネス。LLM は短い目印と符号化の種類だけを言う。**
///
/// 目印の直後から、その符号化で使われる文字が続くかぎりを取る。
#[test]
fn the_harness_extracts_what_the_landmark_points_at() {
    let body = r#"[{"after": "echo ", "encoding": "base64"}]"#;
    assert_eq!(
        extract_spans(body, LINE),
        vec![LocatedSpan {
            text: "cwB5AHMAdABlAG0AaQBuAGYAbwA=".into(),
            encoding: PayloadEncoding::Base64,
        }]
    );
    // **符号化が変われば、取る文字の種類も変わる。** 16進は`0-9a-fA-F`だけなので`z`で止まる。
    let hex_line = "x -bytes 73797374656d696e666fz rest";
    let hex = r#"[{"after": "-bytes ", "encoding": "hex"}]"#;
    assert_eq!(
        extract_spans(hex, hex_line),
        vec![LocatedSpan {
            text: "73797374656d696e666f".into(),
            encoding: PayloadEncoding::Hex,
        }]
    );
    // 同じ行・同じ目印でも、base64 として読めば`z`まで取る（文字の集合が違う）。
    let b64 = r#"[{"after": "-bytes ", "encoding": "base64"}]"#;
    assert_eq!(
        extract_spans(b64, hex_line)[0].text,
        "73797374656d696e666fz"
    );
}

/// **LLM が文字列を書き写しても使わない。** 取り出すのは行から探した結果だけなので、写し間違いが入る余地が無い
/// （[BUG-224]と同じ根を断つ）。行に実在しない目印は捨てる。
#[test]
fn text_the_model_writes_is_never_used_and_a_missing_landmark_yields_nothing() {
    // `text`欄は見ない（目印が無いので何も取り出さない）。
    let copied = r#"[{"text": "cwB5AHMAdABlAG0AaQBuAGYAbwA=", "encoding": "base64"}]"#;
    assert!(extract_spans(copied, LINE).is_empty());
    // 行に無い目印。
    let miss = r#"[{"after": "pwsh -enc ", "encoding": "base64"}]"#;
    assert!(extract_spans(miss, LINE).is_empty());
    // 目印は在るが、その後ろが短すぎる。
    let short =
        r#"[{"after": "ForEach-Object { [Convert]::FromBase64String($", "encoding": "base64"}]"#;
    assert!(extract_spans(short, LINE).is_empty());
}

/// **正規表現は受け取らない。** 式を書かせること自体をやめたので、式の形をした目印は
/// 「そういう文字列が行に在るか」としてしか見ない（当たらないので何も返らない）。
#[test]
fn a_regular_expression_is_not_a_landmark() {
    for pattern in ["echo ([A-Za-z0-9+/=]+)", "cwB5[A-Za-z0-9+/=]+", "([", "*"] {
        let body = format!(r#"[{{"after": "{pattern}", "encoding": "base64"}}]"#);
        assert!(extract_spans(&body, LINE).is_empty(), "{pattern}");
    }
}

/// 前後の説明文・コードの囲みがあっても JSON の配列だけを読む。知らない符号化・欄の欠けたもの・
/// 長すぎる目印は捨てる。読めない返事は「見つからなかった」と同じ（エラーにしない）。
#[test]
fn the_array_is_read_from_a_chatty_reply_and_bad_items_are_dropped() {
    let body = "Here you go:
```json
[{\"after\": \"echo \", \"encoding\": \"rot13\"},                 {\"after\": \"echo \", \"encoding\": \"base64\"}, {\"encoding\": \"hex\"}]
```";
    let markers = parse_markers(body);
    assert_eq!(markers.len(), 1, "{markers:?}");
    assert_eq!(markers[0].encoding, PayloadEncoding::Base64);

    assert!(parse_markers("no json here").is_empty());
    assert!(parse_markers("] backwards [").is_empty());
    assert!(parse_markers("[]").is_empty());
    let long = format!(
        r#"[{{"after": "{}", "encoding": "base64"}}]"#,
        "a".repeat(MAX_MARKER_CHARS + 1)
    );
    assert!(
        parse_markers(&long).is_empty(),
        "長すぎる目印を受けた（目印はモデルが書き写すので、短く保つ）"
    );
}

/// 同じ文字列は1回だけ。取り出す数にも上限がある。
#[test]
fn duplicates_are_dropped_and_the_count_is_capped() {
    let line = "x 11111111 y 22222222 y 33333333 y 44444444 y 55555555";
    let body = r#"[{"after": "y ", "encoding": "hex"}, {"after": "x ", "encoding": "hex"}]"#;
    let spans = extract_spans(body, line);
    assert_eq!(spans.len(), MAX_SPANS);
    assert_eq!(spans[0].text, "22222222");
}

/// 行は固定の指示（system）ではなく、**区切りで囲んだ材料**として送る。
/// 固定の指示は「中身を書き写すな、正規表現を書くな」と命じる。
#[tokio::test]
async fn the_line_goes_into_the_fenced_material_not_into_the_instructions() {
    let provider = Arc::new(Replying {
        body: r#"[{"after": "echo ", "encoding": "base64"}]"#.into(),
        seen: Mutex::new(Vec::new()),
    });
    let locator = LlmSpanLocator::new(provider.clone(), "m".into(), false);
    let spans = locator.locate(LINE).await.expect("返事は読める");
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].text, "cwB5AHMAdABlAG0AaQBuAGYAbwA=");

    let seen = provider.seen.lock().unwrap();
    let req = &seen[0];
    assert!(
        !req.system[0].text.contains("cwB5"),
        "行が固定の指示へ混ざった"
    );
    assert!(req.system[0]
        .text
        .contains("Never copy, quote or decode the data itself"));
    assert!(
        req.system[0]
            .text
            .contains("never write a regular expression"),
        "式を書かせない指示が落ちている"
    );
    let ContentBlock::Text(user) = &req.messages[0].content[0] else {
        panic!("本文が文字でない");
    };
    assert!(user.contains(LINE));
    let marker = user
        .split_whitespace()
        .find(|w| w.starts_with("<<<"))
        .expect("区切りが無い");
    assert_eq!(
        user.matches(marker).count(),
        3,
        "区切りは指示・始まり・終わりの3回: {user}"
    );
    assert!(req.tools.is_empty(), "道具を渡した");
}
