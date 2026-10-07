use harness_core::human_turns::FOLD_SUMMARY_PREFIX;
use harness_core::user_reference::Transcription;

use super::*;
use crate::{Classification, PermissionArbiter, PermissionMode};

/// 害の無い長い値（16進64文字）。種ごとに中身が違い、20文字の窓で数えても他の値や文面と重ならない。
fn value(seed: u64) -> String {
    let mut x = seed;
    let text: String = (0..64)
        .map(|_| {
            x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            char::from_digit(((x >> 60) & 0xf) as u32, 16).unwrap()
        })
        .collect();
    assert!(looks_like_payload(&text), "fixture must be a long value");
    text
}

/// `out`に`value`の一部（20文字）でも出ていれば`true`。切り詰めで途中まで残った値も見つける。
fn leaks(out: &str, value: &str) -> bool {
    let chars: Vec<char> = value.chars().collect();
    chars
        .windows(20)
        .any(|w| out.contains(&w.iter().collect::<String>()))
}

fn user(text: &str) -> Message {
    Message {
        role: Role::User,
        content: vec![ContentBlock::Text(text.to_string())],
    }
}

fn assistant_text(text: &str) -> Message {
    Message {
        role: Role::Assistant,
        content: vec![ContentBlock::Text(text.to_string())],
    }
}

fn assistant_calls(calls: &[(&str, &str, serde_json::Value)]) -> Message {
    Message {
        role: Role::Assistant,
        content: calls
            .iter()
            .map(|(id, name, input)| ContentBlock::ToolUse {
                id: id.to_string(),
                name: name.to_string(),
                input: input.clone(),
            })
            .collect(),
    }
}

fn results(results: &[(&str, &str, bool)]) -> Message {
    Message {
        role: Role::User,
        content: results
            .iter()
            .map(|(id, content, is_error)| ContentBlock::ToolResult {
                tool_use_id: id.to_string(),
                content: content.to_string(),
                is_error: *is_error,
            })
            .collect(),
    }
}

/// 値を3つの人の文に1つずつ貼り、返事でいろいろな顛末のツールを呼んだ会話。
///
/// - 2つ前（K=2）: 値`a`。返事の`run_shell`は`{{val:1}}`と書き（当時の直近＝この文の1番目）、結果に値`a`がそのまま出た。
///   置き場に無い値`stray`も結果に出た
/// - 1つ前（K=1）: 値`b`。返事で値`b`を書き写して拒否され、`{{back:1:1}}`（当時の1つ前＝K=2 の1番目）で
///   ファイルを書き、取り消しと書き写しの拒否もあった
/// - いま（K=0）: 値`c`
struct Fixture {
    a: String,
    b: String,
    c: String,
    stray: String,
    messages: Vec<Message>,
}

fn fixture() -> Fixture {
    let (a, b, c, stray) = (value(1), value(2), value(3), value(4));
    let refusal = Transcription {
        back: 0,
        number: 1,
        written_chars: 63,
        value_chars: 64,
        differences: 1,
    }
    .refusal_ja("  {{val:1}} 64文字・ユーザーの文から\n");
    let messages = vec![
        user(&format!("これを実行して echo {a}")),
        assistant_calls(&[(
            "c1",
            "run_shell",
            serde_json::json!({ "command": "echo {{val:1}}" }),
        )]),
        results(&[("c1", &format!("{a}\nalso {stray}"), false)]),
        assistant_text("実行しました"),
        user(&format!("やっぱりこれ {b}")),
        assistant_calls(&[
            (
                "c2",
                "run_shell",
                serde_json::json!({ "command": format!("echo {b}") }),
            ),
            (
                "c3",
                "write_file",
                serde_json::json!({ "path": "x.txt", "content": "{{back:1:1}}" }),
            ),
            ("c4", "read_file", serde_json::json!({ "path": "x.txt" })),
            (
                "c5",
                "run_shell",
                serde_json::json!({ "command": "echo nearly-the-value" }),
            ),
        ]),
        results(&[
            (
                "c2",
                "permission denied by policy: run_shell (Exec) — no rule matched this call",
                true,
            ),
            ("c3", "wrote x.txt", false),
            ("c4", "cancelled by user", true),
            ("c5", &refusal, true),
        ]),
        user(&format!("もう一度撃って、ついでにこれも {c}")),
    ];
    Fixture {
        a,
        b,
        c,
        stray,
        messages,
    }
}

async fn run(conversation: Option<&[Message]>, input: serde_json::Value) -> ToolOutput {
    let ctx = ToolCtx::new(std::env::temp_dir());
    PastRequestsTool
        .call_in_conversation(input, &ctx, conversation)
        .await
        .expect("the tool returns a result, not an Err")
}

/// **一覧にも詳細にも、値の中身が一部でも出ない**（D-127 の3・D-116）。人の文の中の値も、ツールの結果に
/// そのまま出た値も、置き場に無い値の形の連なりも伏せる。
#[tokio::test]
async fn the_listing_and_every_detail_never_carry_a_raw_value() {
    let f = fixture();
    let mut outputs = vec![run(Some(&f.messages), serde_json::json!({})).await];
    for k in 0..3 {
        outputs.push(run(Some(&f.messages), serde_json::json!({ "back": k })).await);
    }
    for out in &outputs {
        assert!(!out.is_error, "{}", out.content);
        for raw in [&f.a, &f.b, &f.c, &f.stray] {
            assert!(!leaks(&out.content, raw), "{raw} leaked:\n{}", out.content);
        }
    }
    // 置き場に無い値は番号なしで伏せる（長さだけ）。
    let detail_2 = &outputs[3].content;
    assert!(detail_2.contains("[64文字の値・番号なし]"), "{detail_2}");
}

/// 番号の綴りは K で決まる: いまの文の値は`{{val:N}}`、それより前は`{{back:K:N}}`。
#[tokio::test]
async fn placeholders_follow_how_far_back_the_message_is() {
    let f = fixture();
    let listing = run(Some(&f.messages), serde_json::json!({})).await.content;
    let line = |k: usize| {
        listing
            .lines()
            .find(|l| l.starts_with(&format!("K={k}:")))
            .unwrap_or_else(|| panic!("no line for K={k}:\n{listing}"))
            .to_string()
    };
    assert!(line(0).contains("{{val:1}}"), "{listing}");
    assert!(line(1).contains("やっぱりこれ {{back:1:1}}"), "{listing}");
    assert!(
        line(2).contains("これを実行して echo {{back:2:1}}"),
        "{listing}"
    );
    assert!(listing.contains("全部で3個"), "{listing}");

    // 詳細の値の一覧はシステムプロンプトの一覧と同じ行（番号・長さ・出どころ）。
    let detail_0 = run(Some(&f.messages), serde_json::json!({ "back": 0 }))
        .await
        .content;
    assert!(
        detail_0.contains("{{val:1}} 64文字・ユーザーの文から"),
        "{detail_0}"
    );
    let detail_1 = run(Some(&f.messages), serde_json::json!({ "back": 1 }))
        .await
        .content;
    assert!(
        detail_1.contains("{{back:1:1}} 64文字・ユーザーの文から"),
        "{detail_1}"
    );
}

/// **昔のツール呼び出しの番号は今の綴りへ読み替えて見せる。** 会話には当時の書き方で残っている——
/// K=2 の返事の`{{val:1}}`は当時の直近（＝K=2 の文）の1番目なので`{{back:2:1}}`、K=1 の返事の`{{back:1:1}}`は
/// 当時の1つ前（＝K=2 の文）なので`{{back:2:1}}`。そのまま見せると今の文の1番目（値`c`）を指してしまう。
#[tokio::test]
async fn old_tool_inputs_are_rewritten_relative_to_now() {
    let f = fixture();
    let detail_2 = run(Some(&f.messages), serde_json::json!({ "back": 2 }))
        .await
        .content;
    assert!(
        detail_2.contains(r#"{"command":"echo {{back:2:1}}"}"#),
        "{detail_2}"
    );
    assert!(!detail_2.contains("{{val:1}}"), "{detail_2}");

    let detail_1 = run(Some(&f.messages), serde_json::json!({ "back": 1 }))
        .await
        .content;
    assert!(
        detail_1.contains(r#""content":"{{back:2:1}}""#),
        "{detail_1}"
    );
    // 書き写して拒否された呼び出しの入力は、値`b`を K=1 の番号へ伏せて見せる。
    assert!(
        detail_1.contains(r#"{"command":"echo {{back:1:1}}"}"#),
        "{detail_1}"
    );
}

/// 結果の種類はヘッドレスの JSON と同じ見分け（`RecordedOutcome`）で出す。
#[tokio::test]
async fn outcome_kinds_are_classified() {
    let f = fixture();
    let detail_1 = run(Some(&f.messages), serde_json::json!({ "back": 1 }))
        .await
        .content;
    for (call, label) in [
        ("1. run_shell", RecordedOutcome::Denied.label_ja()),
        ("2. write_file", RecordedOutcome::Ran.label_ja()),
        ("3. read_file", RecordedOutcome::Cancelled.label_ja()),
        (
            "4. run_shell",
            RecordedOutcome::RefusedTranscription.label_ja(),
        ),
    ] {
        assert!(
            detail_1.contains(&format!("{call} — {label}")),
            "{call} should be {label}:\n{detail_1}"
        );
    }
    let listing = run(Some(&f.messages), serde_json::json!({})).await.content;
    assert!(
        listing.contains("run_shell（許可の判定で拒否された）, write_file（実行した）"),
        "{listing}"
    );
    // 書き写しを断った文に添えた一覧の番号も、当時の直近（K=1）から読み替える。
    assert!(!detail_1.contains("{{val:1}}"), "{detail_1}");
}

/// 範囲外の K は、指せる範囲を添えてエラーで返す。
#[tokio::test]
async fn an_out_of_range_k_names_the_valid_range() {
    let f = fixture();
    let out = run(Some(&f.messages), serde_json::json!({ "back": 3 })).await;
    assert!(out.is_error);
    assert!(out.content.contains("0〜2"), "{}", out.content);
    assert!(out.content.contains("人が書いた文は3個"), "{}", out.content);

    // 対: 範囲の端（K=2）は読める。
    let edge = run(Some(&f.messages), serde_json::json!({ "back": 2 })).await;
    assert!(!edge.is_error, "{}", edge.content);
}

/// **会話が渡らない経路（認知レイヤー）では「使えない」と返す**（D-127「認知レイヤーの経路は未決」）。
/// 繰り返しても変わらないと言うので、モデルは同じ呼び出しを回さない。
#[tokio::test]
async fn without_the_conversation_it_says_it_cannot_be_used() {
    let out = run(None, serde_json::json!({})).await;
    assert!(out.is_error);
    assert!(out.content.contains("まだ使えません"), "{}", out.content);
    assert!(out.content.contains("繰り返しても"), "{}", out.content);

    // 対: 会話が渡れば読める。
    let f = fixture();
    let out = run(Some(&f.messages), serde_json::json!({})).await;
    assert!(!out.is_error, "{}", out.content);
}

/// 会話を渡さない呼び方（`call`）では読めないと言う（エンジンは常に`call_in_conversation`で呼ぶ）。
#[tokio::test]
async fn the_plain_call_explains_it_needs_the_conversation() {
    let ctx = ToolCtx::new(std::env::temp_dir());
    let err = PastRequestsTool
        .call(serde_json::json!({}), &ctx)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ToolError::ExecutionFailed(m) if m.contains("call_in_conversation")),
        "{err:?}"
    );
}

/// ツールの結果を運ぶ文と、会話を畳んだ要約の文は「人の文」として数えない。
#[tokio::test]
async fn tool_results_and_fold_summaries_are_not_listed_as_human_messages() {
    let messages = vec![
        user(&format!(
            "{FOLD_SUMMARY_PREFIX}3 earlier messages] 要約の本文"
        )),
        user("ひとつめ"),
        assistant_calls(&[("c1", "read_file", serde_json::json!({ "path": "a.txt" }))]),
        results(&[("c1", "ファイルの中身", false)]),
        user("ふたつめ"),
    ];
    let listing = run(Some(&messages), serde_json::json!({})).await.content;
    assert!(listing.contains("全部で2個"), "{listing}");
    assert!(listing.contains("K=0: 「ふたつめ」"), "{listing}");
    assert!(
        listing.contains("K=1: 「ひとつめ」 値なし / 返事で呼んだツール: read_file（実行した）"),
        "{listing}"
    );
    assert!(!listing.contains("要約の本文"), "{listing}");
    assert!(!listing.contains("K=2"), "{listing}");
}

/// **読むだけで承認を聞かない**: `ReadOnly`なので既定のモードで通る。対: 拒否のモードでは通らない。
/// 知らない項目を足した入力は判定の材料が作れない（判定にも実行にも進まない、D-101）。
#[tokio::test]
async fn it_is_read_only_and_needs_no_approval() {
    let ctx = ToolCtx::new(std::env::temp_dir());
    let input = serde_json::json!({ "back": 1 });
    let risk = PastRequestsTool.risk(&input);
    assert_eq!(risk, RiskClass::ReadOnly);
    let subject = PastRequestsTool
        .permission_subject(&input, &ctx)
        .await
        .unwrap();
    assert_eq!(
        subject,
        PermissionSubject::Text(format!("{PAST_REQUESTS_TOOL} back:1"))
    );

    let default = PermissionArbiter::new(PermissionMode::Default, vec![], "/workspace");
    assert_eq!(
        default.classify(PAST_REQUESTS_TOOL, risk, &subject),
        Classification::Allow
    );
    let deny = PermissionArbiter::new(PermissionMode::Deny, vec![], "/workspace");
    assert_eq!(
        deny.classify(PAST_REQUESTS_TOOL, risk, &subject),
        Classification::Deny
    );

    let unknown = serde_json::json!({ "back": 1, "path": "../x" });
    assert!(matches!(
        PastRequestsTool.permission_subject(&unknown, &ctx).await,
        Err(ToolError::InvalidInput(_))
    ));
}
