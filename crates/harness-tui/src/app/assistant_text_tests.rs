//! [`AssistantText`]の試験——足す口が1つで原文と描く結果の両方へ届くこと・終えた状態・複製・`Debug`。

use ratatui::text::Line;

use super::*;
use crate::app::TranscriptItem;

/// 足すと、原文にも描く結果にも同じ文章が加わる。
#[test]
fn pushing_appends_to_both_the_source_and_the_rendering() {
    let mut text = AssistantText::new("前半");
    text.push_str("の続き\n**次の行**");
    assert_eq!(text.as_str(), "前半の続き\n**次の行**");
    assert_eq!(
        text.render(80).lines,
        vec![Line::from("前半の続き"), Line::from("**次の行**")]
    );
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
        assert_eq!(
            text.render(80).lines,
            vec![Line::from("# a"), Line::from("b")],
            "複製へ足したら元の描く結果が変わった"
        );
        assert_eq!(
            copy.render(80).lines,
            vec![Line::from("# a"), Line::from("bc")]
        );
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
