use super::*;
use crate::{ContentBlock, Role};

fn blob(seed: char) -> String {
    std::iter::repeat_n(seed, 308).collect()
}

fn user(text: &str) -> Message {
    Message {
        role: Role::User,
        content: vec![ContentBlock::Text(text.to_string())],
    }
}

/// **中身は1文字もモデルへ渡さない。** 載せるのは番号・長さ・出どころだけ。
///
/// 渡せば書き写せてしまうし、解読した中身は攻撃者が書いたかもしれないデータで、この文面は
/// システムプロンプト——モデルが最も信用する位置——に載る。
#[test]
fn the_rendered_list_never_contains_the_value_itself() {
    let value = blob('a');
    let mut store = ValueStore::from_user_values(vec![value.clone()]);
    store.push_decoded(1, "base64", "systeminfo".to_string());

    let text = store.render().expect("空ではない");
    assert!(!text.contains(&value), "ユーザーの値が文面に出ている");
    assert!(
        !text.contains("systeminfo"),
        "解読した中身が文面に出ている:\n{text}"
    );
    // 代わりに出るもの。
    assert!(
        text.contains("{{val:1}} 308文字・ユーザーの文から"),
        "{text}"
    );
    assert!(
        text.contains("{{val:2}} 10文字・{{val:1}} を base64 として解読したもの"),
        "{text}"
    );
    assert_eq!(MAX_INLINE_VALUE_CHARS, 0, "中身を載せる上限は0のまま");
}

/// 置き場が空なら文面を組まない（モデルへ無意味な1段を送らない）。
#[test]
fn an_empty_store_renders_nothing() {
    assert_eq!(ValueStore::default().render(), None);
    assert_eq!(from_messages(&[user("短い文です")]).render(), None);
}

/// **同じ中身には番号を2つ付けない。** 付けると、どちらを指しても同じものが走るのに一覧だけ膨らむ。
#[test]
fn the_same_text_keeps_one_number() {
    let value = blob('a');
    let mut store = ValueStore::from_user_values(vec![value.clone()]);
    assert_eq!(store.push_decoded(1, "base64", "systeminfo".into()), 2);
    assert_eq!(store.push_decoded(1, "base64", "systeminfo".into()), 2);
    // ユーザーの値そのものを解読結果として足しても、番号は1のまま。
    assert_eq!(store.push_decoded(1, "base64", value), 1);
    assert_eq!(store.len(), 2);
}

/// 並びがそのまま番号になる（1始まり）。差し込みと審査へ渡す列も同じ並び。
#[test]
fn the_order_is_the_numbering() {
    let (a, b) = (blob('a'), blob('b'));
    let mut store = from_messages(&[user(&format!("使って {a} と {b}"))]);
    assert_eq!(store.texts(), vec![a.clone(), b.clone()]);
    assert_eq!(store.get(1).map(|v| v.text.as_str()), Some(a.as_str()));
    assert_eq!(store.get(2).map(|v| v.text.as_str()), Some(b.as_str()));
    assert_eq!(store.get(3), None);
    assert_eq!(store.get(0), None, "0は使わない（1始まり）");

    assert_eq!(store.push_decoded(2, "hex", "ls".to_string()), 3);
    assert_eq!(
        store.get(3).map(|v| v.origin.clone()),
        Some(Origin::Decoded {
            from: 2,
            encoding: "hex".to_string()
        })
    );
}
