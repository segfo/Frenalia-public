use std::sync::Mutex;

use futures::stream::{self, BoxStream};
use harness_core::{ProviderCapabilities, ProviderError, StopReason, StreamEvent};

use super::*;

const LINE: &str = "$c=[char]105+[char]101+[char]120; & $c (gc a.txt)";

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

/// 返事の JSON のうち、**行の中にそのまま在る文字列だけ**を残す。行に無い文字列（LLM が作った・書き換えた・
/// 解読してしまった）は捨てる。
#[test]
fn only_spans_that_appear_verbatim_in_the_line_are_kept() {
    let body = r#"[
        {"text": "[char]105+[char]101+[char]120", "encoding": "char_codes"},
        {"text": "iex", "encoding": "char_codes"},
        {"text": "R2V0LURhdGU=", "encoding": "base64"}
    ]"#;
    let spans = parse_spans(body, LINE);
    assert_eq!(
        spans,
        vec![LocatedSpan {
            text: "[char]105+[char]101+[char]120".into(),
            encoding: PayloadEncoding::CharCodes,
        }],
        "行に無い文字列（解読した結果の iex・作った base64）を残した"
    );
}

/// 前後の説明文・コードの囲みがあっても JSON の配列だけを読む。知らない符号化・欄の欠けたものは捨てる。
/// 読めない返事は「見つからなかった」と同じ（エラーにしない）。
#[test]
fn the_array_is_read_from_a_chatty_reply_and_unknown_encodings_are_dropped() {
    let body = "Here you go:\n```json\n[{\"text\": \"[char]105\", \"encoding\": \"rot13\"}, \
                {\"text\": \"[char]105\", \"encoding\": \"char_codes\"}, {\"encoding\": \"hex\"}]\n```";
    assert_eq!(
        parse_spans(body, LINE),
        vec![LocatedSpan {
            text: "[char]105".into(),
            encoding: PayloadEncoding::CharCodes,
        }]
    );
    assert!(parse_spans("no json here", LINE).is_empty());
    assert!(parse_spans("] backwards [", LINE).is_empty());
    assert!(parse_spans("[]", LINE).is_empty());
}

/// 同じ文字列は1回だけ、数には上限がある。
#[test]
fn duplicates_are_dropped_and_the_count_is_capped() {
    let line = "1 2 3 4 5 6";
    let body = r#"[{"text":"1","encoding":"char_codes"},{"text":"1","encoding":"char_codes"},
        {"text":"2","encoding":"char_codes"},{"text":"3","encoding":"char_codes"},
        {"text":"4","encoding":"char_codes"},{"text":"5","encoding":"char_codes"}]"#;
    let spans = parse_spans(body, line);
    assert_eq!(spans.len(), MAX_SPANS);
    assert_eq!(spans[0].text, "1");
    assert_eq!(spans[1].text, "2");
}

/// 行は固定の指示（system）ではなく、**区切りで囲んだ材料**として送る。固定の指示は「自分で解読しない」と命じる。
#[tokio::test]
async fn the_line_goes_into_the_fenced_material_not_into_the_instructions() {
    let provider = Arc::new(Replying {
        body: r#"[{"text": "[char]105+[char]101+[char]120", "encoding": "char_codes"}]"#.into(),
        seen: Mutex::new(Vec::new()),
    });
    let locator = LlmSpanLocator::new(provider.clone(), "m".into(), false);
    let spans = locator.locate(LINE).await.expect("返事は読める");
    assert_eq!(spans.len(), 1);
    let seen = provider.seen.lock().unwrap();
    let req = &seen[0];
    assert!(
        !req.system[0].text.contains("[char]105"),
        "行が固定の指示へ混ざった"
    );
    assert!(req.system[0]
        .text
        .contains("Never decode anything yourself"));
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
