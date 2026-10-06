//! 解析器・描画部品が落ちた（panicした）ときに、Adapterが原文のまま描く形へ落ちることの試験（モジュールdocの
//! 「落ちたとき」）。
//!
//! # 落とし方
//!
//! 本物の解析器を確実に落とす入力は、知っているもの（表の区切り行の`:`だけのセル）を`super::guard`が書き換えて
//! しまうので使えない。そこで試験のビルドだけ、Adapterの解析（`super::parse`）と描画（`super::draw`）の入口に
//! **爆弾**を置く——解析する文章に[`PARSER_BOMB`]があれば解析の入口で、描く出来事の文字に[`DRAW_BOMB`]があれば
//! 描画の入口でpanicする（[`explode`]）。製品のビルドには入らない。
//!
//! 爆弾は、落ちた瞬間にpanicを受け止める範囲（`harness_term::contain_panic`）の中だったかを記録する
//! （[`contained_at_the_last_bomb`]）。範囲の外で落ちると、製品ではpanicのフックが端末を戻してしまい、受け止めても
//! TUIの画面は壊れる——Adapterが`catch_unwind`を直接使っていないことを、これで確かめる。

use std::cell::Cell;
use std::sync::{Arc, Mutex};

use ratatui::style::Modifier;

use super::super::contract_tests::{port_contract_with, SAMPLE};
use super::super::plain::PlainText;
use super::*;

/// 解析する文章にあると、解析の入口で落ちる文字列（モジュールdoc）。
pub(super) const PARSER_BOMB: &str = "💥解析器";
/// 描く出来事の文字にあると、描画の入口で落ちる文字列（モジュールdoc）。
pub(super) const DRAW_BOMB: &str = "💥描画部品";

thread_local! {
    /// 最後の爆弾が落ちたとき、panicを受け止める範囲の中だったか。
    static CONTAINED_AT_BOMB: Cell<Option<bool>> = const { Cell::new(None) };
}

/// 爆弾を落とす（`what`は落ちた部品の名前）。そのとき受け止める範囲の中だったかを記録する。
pub(super) fn explode(what: &str) -> ! {
    CONTAINED_AT_BOMB.with(|at| at.set(Some(harness_term::panic_is_contained())));
    panic!("試験が仕込んだ{what}のpanic");
}

/// このスレッドで最後に落ちた爆弾が、受け止める範囲の中だったか（落ちていなければ`None`）。読むと消す。
fn contained_at_the_last_bomb() -> Option<bool> {
    CONTAINED_AT_BOMB.with(Cell::take)
}

/// `text`を整形しない実装（`PlainText`）で描いた結果。落ちた後のAdapterは、これと同じに描く。
fn plain(text: &str, width: u16) -> Rendered {
    let mut plain = PlainText::default();
    plain.push(text);
    plain.render(width)
}

fn fed(text: &str) -> CodewandlerMarkdown {
    let mut m = CodewandlerMarkdown::default();
    m.push(text);
    m
}

/// **解析器が落ちても描画は止まらず、その返答は原文のまま（整形しない実装と同じに）描かれる。** 落ちたのは
/// 受け止める範囲の中（端末を戻さない）。落ちた後に足された文章も原文のまま描き、解析し直して落ち直さない。
#[test]
fn a_parser_panic_falls_back_to_drawing_the_source_like_plain_text() {
    let text = format!("# 見出し\n\n**太字** と {PARSER_BOMB}\n");
    let mut m = fed(&text);
    let drawn = m.render(80);
    assert_eq!(
        contained_at_the_last_bomb(),
        Some(true),
        "受け止める範囲の外で落ちた"
    );
    assert!(m.has_fallen_back());
    assert_eq!(drawn, plain(&text, 80));

    m.push("\n- 続きの **項目**\n");
    let more = format!("{text}\n- 続きの **項目**\n");
    assert_eq!(m.render(80), plain(&more, 80));
    m.finish();
    assert_eq!(m.render(40), plain(&more, 40));
    assert_eq!(
        contained_at_the_last_bomb(),
        None,
        "落ちた後も解析し直して落ち直した"
    );
}

/// **描画部品が落ちても同じ**（解析は通り、出来事を描くところで落ちる）。終えたとき（全文を描き直すとき）に
/// 落ちても同じ。
#[test]
fn a_renderer_panic_falls_back_too_while_streaming_and_after_finishing() {
    let text = format!("段落と {DRAW_BOMB}\n");
    let mut streaming = fed(&text);
    assert_eq!(streaming.render(80), plain(&text, 80));
    assert_eq!(contained_at_the_last_bomb(), Some(true));
    assert!(streaming.has_fallen_back());

    let mut finished = fed(&text);
    finished.finish();
    assert_eq!(finished.render(80), plain(&text, 80));
    assert_eq!(contained_at_the_last_bomb(), Some(true));
    assert!(finished.has_fallen_back());
}

/// **流れ込みの途中で落ちると、それまでに持っていた結果（確定した塊・描いた行）を全部捨てる**——途中まで更新
/// された結果を、後で使わない。`reset`すると、作ったばかりのものと同じにMarkdownとして描き直す。
#[test]
fn a_panic_mid_stream_drops_every_kept_result_and_reset_formats_again() {
    let head = "# 見出し\n\n一つ目の段落\n\n二つ目の段落\n\n";
    let mut m = fed(head);
    let before = m.render(80);
    assert!(m.sealed_chunks() > 0, "試験の前提: 確定した塊がある");
    assert_ne!(before, plain(head, 80), "試験の前提: 整形して描いている");

    m.push(PARSER_BOMB);
    let whole = format!("{head}{PARSER_BOMB}");
    assert_eq!(m.render(80), plain(&whole, 80));
    assert_eq!(m.sealed_chunks(), 0, "落ちた後も確定した塊を持っている");

    m.reset();
    assert!(!m.has_fallen_back(), "空に戻しても原文のまま描く");
    m.push(head);
    assert_eq!(m.render(80), fed(head).render(80));
    assert_eq!(m.render(80), before);
}

/// **Portの契約は、途中で落ちる文章でも守られる**（どう区切っても同じ・幅は状態でない・`reset`・`finish`の冪等と
/// 再開・行と印の数・リンクの区間）。解析器で落ちる文章と、描画部品で落ちる文章の両方。
#[test]
fn the_port_contract_holds_for_text_that_makes_the_adapter_fall_back() {
    for bomb in [PARSER_BOMB, DRAW_BOMB] {
        port_contract_with(CodewandlerMarkdown::default, &format!("{SAMPLE}{bomb}"));
    }
}

/// 書かれたログを集める書き先（`tracing_subscriber`の`MakeWriter`）。
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// **落ちたことは黙らない**——ログ（会話TUIではログファイル）へ、落ちたときの文面と一緒に警告を1回書く。
/// 落ちた後に描き直しても、もう書かない（描くたびに書かない）。
#[test]
fn falling_back_is_logged_once_as_a_warning_with_the_panic_message() {
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(captured.clone())
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        // ログを書く場所（`fall_back`の`warn!`）が「誰も聞いていない」と覚えた後かもしれない——並んで走る別の試験が、
        // 聞き手の無いスレッドで先に通ることがある。聞き手を置いた後に覚え直させる（置かないと、ときどき0件になる）。
        tracing::callsite::rebuild_interest_cache();
        let mut m = fed(&format!("{PARSER_BOMB}\n"));
        m.render(80);
        m.render(40);
        m.finish();
        m.render(80);
    });
    let log = String::from_utf8(captured.0.lock().expect("lock").clone()).expect("utf-8");
    let warnings: Vec<&str> = log.lines().filter(|line| line.contains("WARN")).collect();
    assert_eq!(warnings.len(), 1, "{log}");
    assert!(
        warnings[0].contains("試験が仕込んだ解析器のpanic"),
        "落ちたときの文面が無い: {log}"
    );
}

/// 落ちていない文章は今までどおり整形する（許可側。爆弾の無い文章で落ちた扱いにならない）。
#[test]
fn text_without_a_bomb_is_formatted_and_never_falls_back() {
    let mut m = fed("**太字**\n");
    let drawn = m.render(80);
    m.finish();
    m.render(80);
    assert!(!m.has_fallen_back());
    assert_eq!(contained_at_the_last_bomb(), None);
    assert!(
        drawn.lines[0]
            .spans
            .iter()
            .any(|span| span.content == "太字" && span.style.add_modifier.contains(Modifier::BOLD)),
        "{drawn:?}"
    );
}
