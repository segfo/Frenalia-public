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

/// **抜き出すのは正規表現エンジンで、LLM は取り出し方だけを書く。** 丸括弧の中が返る。
#[test]
fn the_regex_engine_extracts_what_the_pattern_points_at() {
    let body = r#"[{"pattern": "echo ([A-Za-z0-9+/=]+)", "encoding": "base64"}]"#;
    assert_eq!(
        extract_spans(body, LINE),
        vec![LocatedSpan {
            text: "cwB5AHMAdABlAG0AaQBuAGYAbwA=".into(),
            encoding: PayloadEncoding::Base64,
        }]
    );
    // 丸括弧が無い式は、当たった全体を取り出す。
    let whole = r#"[{"pattern": "cwB5[A-Za-z0-9+/=]+", "encoding": "base64"}]"#;
    assert_eq!(
        extract_spans(whole, LINE)[0].text,
        "cwB5AHMAdABlAG0AaQBuAGYAbwA="
    );
}

/// **LLM が文字列を書き写しても使わない。** 取り出すのは行に当てた結果だけなので、写し間違いが入る余地が無い
/// （[BUG-224]と同じ根を断つ）。式が当たらなければ何も返さない。
#[test]
fn text_the_model_writes_is_never_used_and_a_miss_yields_nothing() {
    // `text`欄は見ない（式が無いので何も取り出さない）。
    let copied = r#"[{"text": "cwB5AHMAdABlAG0AaQBuAGYAbwA=", "encoding": "base64"}]"#;
    assert!(extract_spans(copied, LINE).is_empty());
    // 当たらない式。
    let miss = r#"[{"pattern": "pwsh -enc ([A-Za-z0-9+/=]+)", "encoding": "base64"}]"#;
    assert!(extract_spans(miss, LINE).is_empty());
}

/// 前後の説明文・コードの囲みがあっても JSON の配列だけを読む。知らない符号化・欄の欠けたもの・長すぎる式は捨てる。
/// 読めない返事は「見つからなかった」と同じ（エラーにしない）。
#[test]
fn the_array_is_read_from_a_chatty_reply_and_bad_items_are_dropped() {
    let body = "Here you go:\n```json\n[{\"pattern\": \"echo (\\\\S+)\", \"encoding\": \"rot13\"}, \
                {\"pattern\": \"echo ([A-Za-z0-9+/=]+)\", \"encoding\": \"base64\"}, {\"encoding\": \"hex\"}]\n```";
    let patterns = parse_patterns(body);
    assert_eq!(patterns.len(), 1, "{patterns:?}");
    assert_eq!(patterns[0].encoding, PayloadEncoding::Base64);

    assert!(parse_patterns("no json here").is_empty());
    assert!(parse_patterns("] backwards [").is_empty());
    assert!(parse_patterns("[]").is_empty());
    let long = format!(
        r#"[{{"pattern": "{}", "encoding": "base64"}}]"#,
        "a".repeat(MAX_PATTERN_CHARS + 1)
    );
    assert!(parse_patterns(&long).is_empty(), "長すぎる式を受けた");
}

/// **組み立てられない式は黙って飛ばす**（モデルが書くので、使えない式が来る）。後戻りの要る書き方（後方参照）も同じ。
#[test]
fn a_pattern_that_does_not_build_is_skipped() {
    for pattern in ["([", "(?<name>", r"(\1)", "*"] {
        let body = format!(r#"[{{"pattern": "{pattern}", "encoding": "base64"}}]"#);
        let body = body.replace('\\', "\\\\");
        assert!(extract_spans(&body, LINE).is_empty(), "{pattern}");
    }
}

/// 同じ文字列は1回だけ。取り出す数にも上限がある。
#[test]
fn duplicates_are_dropped_and_the_count_is_capped() {
    let line = "a 11 22 33 44 55 66";
    let body = r#"[{"pattern": "([0-9]{2})", "encoding": "char_codes"},
                   {"pattern": "([0-9]{2})", "encoding": "hex"}]"#;
    let spans = extract_spans(body, line);
    assert_eq!(spans.len(), MAX_SPANS);
    assert_eq!(spans[0].text, "11");
    assert_eq!(spans[1].text, "22");
}

/// 行は固定の指示（system）ではなく、**区切りで囲んだ材料**として送る。固定の指示は「中身を書き写さない」と命じる。
#[tokio::test]
async fn the_line_goes_into_the_fenced_material_not_into_the_instructions() {
    let provider = Arc::new(Replying {
        body: r#"[{"pattern": "echo ([A-Za-z0-9+/=]+)", "encoding": "base64"}]"#.into(),
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
