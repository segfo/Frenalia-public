//! [`AssistantText`]の試験——足す口が1つで原文と描く結果の両方へ届くこと・終えた状態・複製・`Debug`。

use ratatui::text::Line;

use super::*;
use crate::app::TranscriptItem;

/// `source`を一度に渡した描く側で、幅80で描いた結果（足し方の試験の基準。見た目は選んだ実装が決める）。
fn drawn_at_once(source: &str) -> Rendered {
    let mut view = MarkdownView::new();
    view.push(source);
    view.render(80)
}

/// 足すと、原文にも描く結果にも同じ文章が加わる——描く結果は、全文を一度に渡したのと同じ。
///
/// T9で既定の実装が整形する実装に替わり、描いた見た目が実装で変わるようになったので、見た目を書かずに一度に渡した
/// 描く側と比べる形へ意図して書き換えた（足した文章が描く側へ届くこと、という試験の意味は同じ）。
#[test]
fn pushing_appends_to_both_the_source_and_the_rendering() {
    let mut text = AssistantText::new("前半");
    let before = text.render(80);
    text.push_str("の続き\n**次の行**");
    assert_eq!(text.as_str(), "前半の続き\n**次の行**");
    let after = text.render(80);
    assert_ne!(after, before, "足したのに描く結果が変わらない");
    assert_eq!(after, drawn_at_once("前半の続き\n**次の行**"));
}

/// 終えたことを覚え（何度終えても同じ）、終えた後に足すと流入中へ戻る。
#[test]
fn finishing_is_remembered_and_pushing_again_resumes_streaming() {
    let mut text = AssistantText::new("a");
    assert!(!text.is_finished(), "作ったばかりで終わっている");
    text.finish();
    text.finish();
    assert!(text.is_finished());
    text.push_str("b");
    assert!(!text.is_finished(), "終えた後に足しても流入中へ戻らない");
    assert_eq!(text.as_str(), "ab");
    assert_eq!(text.render(80).lines, vec![Line::from("ab")]);
}

/// 複製は同じに描き、終えていたかも引き継ぐ。複製へ足しても元は変わらない（描く側を共有しない）。
#[test]
fn a_clone_renders_the_same_keeps_whether_it_was_finished_and_is_independent() {
    for finish in [false, true] {
        let text = AssistantText::new("# a\nb");
        if finish {
            text.finish();
        }
        let mut copy = text.clone();
        assert_eq!(copy.is_finished(), finish);
        assert_eq!(copy.as_str(), text.as_str());
        assert_eq!(copy.render(80), text.render(80));
        copy.push_str("c");
        assert_eq!(text.as_str(), "# a\nb", "複製へ足したら元の原文が変わった");
        // 見た目は選んだ実装が決めるので、一度に渡した描く側と比べる（T9で意図して書き換えた。上の試験と同じ理由）。
        assert_eq!(
            text.render(80),
            drawn_at_once("# a\nb"),
            "複製へ足したら元の描く結果が変わった"
        );
        assert_eq!(copy.render(80), drawn_at_once("# a\nbc"));
    }
}

/// `Debug`は原文だけを、`String`だったときと同じ形で出す（ログや試験の失敗の文面が変わらない）。
#[test]
fn debug_prints_the_source_only_like_the_string_did() {
    let text = AssistantText::new("hi \"x\"");
    assert_eq!(format!("{text:?}"), format!("{:?}", "hi \"x\""));
    assert_eq!(
        format!("{:?}", TranscriptItem::Assistant(text)),
        r#"Assistant("hi \"x\"")"#
    );
}
