//! ユーザーが書いた長い値を、モデルに**書き写させず参照させる**仕組みの通し試験
//! （`harness_core::user_reference`。D-100 の追記）。
//!
//! 守りたいのは2つ。**モデルが番号だけを書いたとき、判定も実行もユーザーの文の値そのものを見る**ことと、
//! **差し込めない番号を書いたら、その綴りがそのまま残る**（黙って別のものを走らせない）こと。
//!
//! 実測の背景（2026-10-04、ローカルの`qwen3.6-35b`・4回）: 308文字の base64 を4回とも写し損じ、1文字違った値は
//! `systeminfo`ではなく`sDsteminfo`を走らせる命令になっていた。

use harness_core::{AgentEvent, BlockKind, ContentBlock, StopReason, StreamEvent, ToolCtx, Usage};
use harness_engine::{
    run_agent_loop, AgentLoopConfig, ConversationState, PermissionArbiter, PermissionMode,
};
use harness_providers::MockProvider;
use harness_tools::ToolRegistry;

/// 写し損じが起きた実測と同じ長さ（308文字）の値。
fn long_value() -> String {
    "cAB3AHMAaAAgAC0ALQBlAG4AYwAg".repeat(11) + "QQA="
}

fn tool_use_turn(input: serde_json::Value) -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::ToolUse {
                id: "call_1".to_string(),
                name: "write_file".to_string(),
            },
        },
        StreamEvent::ToolInputDelta {
            index: 0,
            json_fragment: input.to_string(),
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::Done {
            stop_reason: StopReason::ToolUse,
            usage: Usage::default(),
        },
    ]
}

fn end_turn() -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::Text,
        },
        StreamEvent::TextDelta {
            index: 0,
            text: "done".to_string(),
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::Done {
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        },
    ]
}

/// ユーザーの文を`user_text`にして`write_file`を1回撃ち、書かれたファイルの中身を返す（書けなければ`None`）。
///
/// **`write_file`で測る**——書いた中身を読み返せば、判定と実行が見た文字列がそのまま分かる。
async fn run_write(
    user_text: &str,
    input: serde_json::Value,
) -> (Option<String>, String, Vec<AgentEvent>) {
    let dir = tempfile::tempdir().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let provider = MockProvider::new(vec![tool_use_turn(input), end_turn()]);
    let mut state = ConversationState::new(Vec::new());
    state.push_user_text(user_text);

    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::AcceptAll, vec![], dir.path());

    run_agent_loop(
        &provider,
        &mut state,
        &tools,
        &ctx,
        &arbiter,
        AgentLoopConfig {
            model: "mock".into(),
            max_tokens: 100,
            max_turns: 5,
            compaction: Default::default(),
            degeneracy: None,
        },
        Some(&tx),
        None,
        |_| {},
    )
    .await
    .expect("the loop itself must not fail");

    let result = state
        .messages
        .iter()
        .flat_map(|m| m.content.iter())
        .find_map(|b| match b {
            ContentBlock::ToolResult { content, .. } => Some(content.clone()),
            _ => None,
        })
        .expect("the write_file call must produce a tool_result");
    (
        std::fs::read_to_string(dir.path().join("out.txt")).ok(),
        result,
        {
            drop(tx);
            let mut events = Vec::new();
            while let Ok(e) = rx.try_recv() {
                events.push(e);
            }
            events
        },
    )
}

/// 書き写しを見つけたと知らせた回数（`AgentEvent::UserValueTranscribed`）。
/// 返るのは`(違いの回数, 実行を断ったか)`。
fn transcription_notices(events: &[AgentEvent]) -> Vec<(usize, bool)> {
    events
        .iter()
        .filter_map(|e| match e {
            AgentEvent::UserValueTranscribed {
                differences,
                refused,
                ..
            } => Some((*differences, *refused)),
            _ => None,
        })
        .collect()
}

/// **モデルが書くのは番号だけ。実際に書かれるのはユーザーの文の値そのもの。**
#[tokio::test]
async fn the_harness_substitutes_the_value_so_the_model_never_transcribes_it() {
    let value = long_value();
    let (written, _, _) = run_write(
        &format!("これを書いて {value}"),
        serde_json::json!({ "path": "out.txt", "content": "payload={{user:1}}" }),
    )
    .await;
    assert_eq!(
        written.as_deref(),
        Some(format!("payload={value}").as_str())
    );
}

/// **差し込めない番号は、綴りのまま残る**（黙って空にして別のものを走らせない）。
#[tokio::test]
async fn an_unresolvable_reference_stays_visible() {
    let value = long_value();
    let (written, _, _) = run_write(
        &format!("これを書いて {value}"),
        serde_json::json!({ "path": "out.txt", "content": "payload={{user:2}}" }),
    )
    .await;
    assert_eq!(written.as_deref(), Some("payload={{user:2}}"));

    // ユーザーの文に長い値が無いときも同じ。
    let (written, _, _) = run_write(
        "短い文です",
        serde_json::json!({ "path": "out.txt", "content": "payload={{user:1}}" }),
    )
    .await;
    assert_eq!(written.as_deref(), Some("payload={{user:1}}"));
}

/// 対照: 参照を書かない入力は、1文字も変わらない（この仕組みが普通の呼び出しに触らない）。
#[tokio::test]
async fn input_without_a_reference_is_untouched() {
    let value = long_value();
    let (written, _, _) = run_write(
        &format!("これを書いて {value}"),
        serde_json::json!({ "path": "out.txt", "content": "plain text" }),
    )
    .await;
    assert_eq!(written.as_deref(), Some("plain text"));
}

/// **損じた写しは走らせない**（D-115）。ファイルは1バイトも書かれず、モデルには理由が返る。
///
/// 実測（2026-10-04）と同じ形: 参照の書き方を伝えてあるのにモデルは308文字の値を書き写した。
#[tokio::test]
async fn a_damaged_transcription_never_runs() {
    let value = long_value();
    let mut written: Vec<char> = value.chars().collect();
    written[7] = 'Z';
    let written: String = written.into_iter().collect();
    assert_ne!(written, value);

    let (file, result, events) = run_write(
        &format!("これを書いて {value}"),
        serde_json::json!({ "path": "out.txt", "content": written }),
    )
    .await;
    assert_eq!(file, None, "壊れた写しでファイルが書かれてはいけない");
    // モデルへ返るのは、何が違ったかと、**値の一覧そのもの**。どれを指すかはモデルが選ぶ
    // ——ハーネスは「どれに近いか」までしか言えない（実測で、1つに決めて返したら違う値を指した）。
    assert!(
        result.contains("書き写した値は実行しませんでした"),
        "{result}"
    );
    assert!(result.contains("{{val:1}}"), "{result}");
    assert!(result.contains("数え直す必要はありません"), "{result}");
    // 一覧には中身が1文字も入らない。
    assert!(
        !result.contains(&value),
        "一覧に値の中身が入っている:
{result}"
    );
    // 断ったことは会話の記録にも残す。
    assert_eq!(transcription_notices(&events), vec![(1, true)]);
}

/// **一字一句同じ写しは走らせる**（走るものは正しいので止める理由が無い）。ただし記録には残す。
#[tokio::test]
async fn an_exact_transcription_runs_but_is_recorded() {
    let value = long_value();
    let (file, _, events) = run_write(
        &format!("これを書いて {value}"),
        serde_json::json!({ "path": "out.txt", "content": value.clone() }),
    )
    .await;
    assert_eq!(file.as_deref(), Some(value.as_str()));
    assert_eq!(transcription_notices(&events), vec![(0, false)]);
}

/// **損じた写しの拒否が3回続いたら、次を素通りさせる**（連続拒否カウンタ、`turn/mod.rs`）。
///
/// 無限ループ対策——ファイル編集ツールの`old_string`等でモデルが番号参照に書き直せない形で
/// 詰まったときに、拒否と再試行が永遠に続くのを止める。本当に別物が走る写しなら、下流
/// （コマンドの構文失敗・承認画面・ファイル照合）がそれぞれ受ける。
#[tokio::test]
async fn after_three_damaged_transcriptions_the_fourth_runs_through() {
    let value = long_value();
    let mut damaged: Vec<char> = value.chars().collect();
    damaged[7] = 'Z';
    let damaged: String = damaged.into_iter().collect();
    assert_ne!(damaged, value);

    let dir = tempfile::tempdir().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    // 損じた写しを3回続けて撃つ。4ターン目は端のない end_turn。
    let provider = MockProvider::new(vec![
        tool_use_turn(serde_json::json!({ "path": "out.txt", "content": damaged.clone() })),
        tool_use_turn(serde_json::json!({ "path": "out.txt", "content": damaged.clone() })),
        tool_use_turn(serde_json::json!({ "path": "out.txt", "content": damaged.clone() })),
        end_turn(),
    ]);
    let mut state = ConversationState::new(Vec::new());
    state.push_user_text(format!("これを書いて {value}"));

    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::AcceptAll, vec![], dir.path());

    run_agent_loop(
        &provider,
        &mut state,
        &tools,
        &ctx,
        &arbiter,
        AgentLoopConfig {
            model: "mock".into(),
            max_tokens: 100,
            max_turns: 10,
            compaction: Default::default(),
            degeneracy: None,
        },
        Some(&tx),
        None,
        |_| {},
    )
    .await
    .expect("the loop itself must not fail");

    // 3回目で素通りして、ファイルが書かれる。
    let file = std::fs::read_to_string(dir.path().join("out.txt")).ok();
    assert_eq!(
        file.as_deref(),
        Some(damaged.as_str()),
        "3回目の素通りでファイルが書かれるはず"
    );

    drop(tx);
    let mut events = Vec::new();
    while let Ok(e) = rx.try_recv() {
        events.push(e);
    }

    // 1・2回目は拒否（`UserValueTranscribed { refused: true }`）、3回目は素通り
    // （`UserValueTranscribed { refused: false }` と `TranscriptionCheckBypassed` の対）。
    let notices = transcription_notices(&events);
    assert_eq!(
        notices,
        vec![(1, true), (1, true), (1, false)],
        "拒否→拒否→素通りの並びが崩れている: {notices:?}"
    );
    let bypass_count = events
        .iter()
        .filter(|e| matches!(e, AgentEvent::TranscriptionCheckBypassed { .. }))
        .count();
    assert_eq!(bypass_count, 1, "素通りの通知が1回出ているはず");
}

/// 対照: **別物は止めない。** モデルが自分で作った長い値はそのまま走り、記録にも出ない。
#[tokio::test]
async fn a_different_long_value_runs_untouched() {
    let other = "Z".repeat(long_value().chars().count());
    let (file, _, events) = run_write(
        &format!("これを書いて {}", long_value()),
        serde_json::json!({ "path": "out.txt", "content": other.clone() }),
    )
    .await;
    assert_eq!(file.as_deref(), Some(other.as_str()));
    assert_eq!(transcription_notices(&events), Vec::new());
}

/// **モデルへ送るリクエストに、値の一覧が実際に載っている**（D-115）。
///
/// 一覧を組む関数があることと、それがリクエストへ配線されていることは別の事実である
/// （`B-06`。ここを測らないと、組めるのに一度も送られない状態を緑のまま見逃す）。
/// あわせて**中身が1文字も載っていない**ことを対で確かめる——載せればモデルが書き写せてしまう。
#[tokio::test]
async fn the_request_carries_the_value_list_without_the_value_itself() {
    let value = long_value();
    let dir = tempfile::tempdir().unwrap();
    let record = dir.path().join("requests.jsonl");
    let provider = MockProvider::new(vec![end_turn()]).with_request_record_path(record.clone());

    let mut state = ConversationState::new(vec![harness_core::SystemBlock {
        text: "環境の事実".to_string(),
        cache: true,
    }]);
    state.push_user_text(format!("これを実行して {value}"));

    let tools = ToolRegistry::with_builtin_tools();
    let ctx = ToolCtx::new(dir.path().to_path_buf());
    let arbiter = PermissionArbiter::new(PermissionMode::Deny, vec![], dir.path());
    run_agent_loop(
        &provider,
        &mut state,
        &tools,
        &ctx,
        &arbiter,
        AgentLoopConfig {
            model: "mock".into(),
            max_tokens: 100,
            max_turns: 2,
            compaction: Default::default(),
            degeneracy: None,
        },
        None,
        None,
        |_| {},
    )
    .await
    .expect("the loop itself must not fail");

    let sent = std::fs::read_to_string(&record).expect("リクエストが記録されていない");
    let request: serde_json::Value = serde_json::from_str(sent.lines().next().unwrap()).unwrap();
    let system = request["system"].to_string();
    let chars = value.chars().count();
    assert!(
        system.contains("{{val:1}}") && system.contains(&format!("{chars}文字")),
        "値の一覧がリクエストへ載っていない:
{system}"
    );
    assert!(
        !system.contains(&value),
        "値の中身がシステムプロンプトへ載っている（書き写せてしまう）"
    );
    // 1つめの塊（環境の事実）は残っている——一覧を足したせいで消していない。
    assert!(system.contains("環境の事実"), "{system}");
}

/// **ハーネスが機械で解けた段にも番号が付く**（D-116）。モデルは中の層も番号で指せる。
///
/// 使う値は実測と同じ二重の形: 308文字の base64 を UTF-16LE として読むと
/// `pwsh --enc <さらに base64>` になり、その中は `systeminfo` である。
#[test]
fn decoded_layers_get_their_own_numbers() {
    let value = "cAB3AHMAaAAgAC0ALQBlAG4AYwAgAGMAdwBCADUAQQBIAE0AQQBkAEEAQgBsAEEARwAwAEEAYQBRAEIAdQBBAEcAWQBBAGIAdwBBAD0A";
    let store = harness_engine::value_store_for(&[harness_core::Message {
        role: harness_core::Role::User,
        content: vec![harness_core::ContentBlock::Text(format!(
            "実行して pwsh --enc {value}"
        ))],
    }]);

    let texts = store.texts();
    assert_eq!(texts[0], value, "1つ目はユーザーが書いた値そのもの");
    assert!(
        texts.iter().any(|t| t.contains("pwsh --enc")),
        "1段目（UTF-16LEとして読んだもの）に番号が付いていない: {texts:?}"
    );
    assert!(
        texts.iter().any(|t| t == "systeminfo"),
        "2段目に番号が付いていない: {texts:?}"
    );

    // 一覧には**中身が1文字も載らない**。載るのは番号・長さ・出どころだけ。
    let rendered = store.render().expect("空ではない");
    assert!(!rendered.contains("systeminfo"), "{rendered}");
    assert!(!rendered.contains(value), "{rendered}");
    assert!(rendered.contains("として解読したもの"), "{rendered}");

    // 親の番号が繋がっている（2段目の親は1段目であって、ユーザーの値ではない）。
    let last = store.len();
    assert!(matches!(
        store.get(last).map(|v| v.origin.clone()),
        Some(harness_core::value_store::Origin::Decoded { from, .. }) if from > 1
    ));
}
