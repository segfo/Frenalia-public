//! Port（[`StreamingMarkdown`]）の契約試験。
//!
//! どの実装も通すべき性質を、**実装を作る関数を受け取る1つの関数**（[`port_contract`]）にまとめる。実装を足すときは、
//! その実装の試験から`port_contract`を呼ぶ——通ることが、差し替えの合格条件になる（計画書§1.4(5)・§1.9）。
//! いまは[`PlainText`]（ここ）と、整形する実装（その実装の試験から呼ぶ。実装の名前はこのファイルに書かない——
//! `leak_tests`）に掛ける。

use ratatui::style::Style;

use super::plain::PlainText;
use super::{Rendered, StreamingMarkdown};

/// 契約を確かめる文章。Markdownの記号・入れ子・空行・フェンス・引用・全角文字・`\r\n`・リンクを含める
/// （区切る場所の候補を増やすため。リンクは[`links_stay_inside_their_lines`]が見る）。
pub(super) const SAMPLE: &str = "# 見出し\n**太字**と`code`\r\n- 項目 1\n  - 入れ子の項目\n\n```rust\nlet x = 1;\n```\n> 引用\nこれは長い日本語の段落です。[リンクの文字](https://example.com)も含みます。";

/// 確かめる幅。広い幅・狭い幅に加えて、1桁と0桁（落ちないこと）。
const WIDTHS: [u16; 5] = [120, 80, 20, 1, 0];

/// `chunks`を順に足したもの。
fn fed<M: StreamingMarkdown>(make: &impl Fn() -> M, chunks: &[&str]) -> M {
    let mut m = make();
    for chunk in chunks {
        m.push(chunk);
    }
    m
}

fn finished<M: StreamingMarkdown>(mut m: M) -> M {
    m.finish();
    m
}

/// `m`を`WIDTHS`の幅で順に描いた結果。
fn every_width<M: StreamingMarkdown>(m: &mut M) -> Vec<Rendered> {
    WIDTHS.iter().map(|&w| m.render(w)).collect()
}

/// どの実装も通すべき性質（モジュールdoc）。`make`は作ったばかりの実装を返す。確かめる文章は[`SAMPLE`]。
pub(super) fn port_contract<M: StreamingMarkdown>(make: impl Fn() -> M) {
    port_contract_with(make, SAMPLE);
}

/// [`port_contract`]を文章`sample`で確かめる。実装が途中で落ちる（panicする）文章でも契約を守るかを、その実装の
/// 試験から確かめるため（Portの「描画の経路は失敗しない」。[`StreamingMarkdown`]のdoc）。
pub(super) fn port_contract_with<M: StreamingMarkdown>(make: impl Fn() -> M, sample: &str) {
    any_split_renders_the_same(&make, sample);
    the_width_is_not_state(&make, sample);
    reset_renders_like_a_new_one(&make, sample);
    finish_is_idempotent_and_push_after_finish_continues(&make, sample);
    lines_and_joins_have_the_same_length(&make, sample);
    links_stay_inside_their_lines(&make, sample);
}

/// **どの文字の境界で2つに分けて足しても、1回で足したのと同じに描く**（流入中も、終わった後も）。
fn any_split_renders_the_same<M: StreamingMarkdown>(make: &impl Fn() -> M, sample: &str) {
    let mut whole = fed(make, &[sample]);
    let streaming = every_width(&mut whole);
    let done = every_width(&mut finished(whole));
    let boundaries = sample
        .char_indices()
        .map(|(at, _)| at)
        .chain([sample.len()]);
    for at in boundaries {
        let (head, tail) = sample.split_at(at);
        let mut split = fed(make, &[head, tail]);
        assert_eq!(
            every_width(&mut split),
            streaming,
            "{at}バイト目で分けて足すと、流入中の描画が変わった"
        );
        assert_eq!(
            every_width(&mut finished(split)),
            done,
            "{at}バイト目で分けて足すと、終わった後の描画が変わった"
        );
    }
}

/// **幅は状態ではない**——別の幅で描いた後に元の幅で描くと最初と同じ。作ったばかりのものを同じ幅で描いたのとも同じ。
fn the_width_is_not_state<M: StreamingMarkdown>(make: &impl Fn() -> M, sample: &str) {
    for finish in [false, true] {
        let prepare = || {
            let m = fed(make, &[sample]);
            if finish {
                finished(m)
            } else {
                m
            }
        };
        let mut m = prepare();
        let wide = m.render(120);
        let narrow = m.render(20);
        assert_eq!(
            m.render(120),
            wide,
            "狭い幅で描いた後、元の幅で描き直せない（終わった後={finish}）"
        );
        assert_eq!(narrow, prepare().render(20), "広い幅で描いた後の狭い幅の描画が、最初から狭い幅で描いたのと違う（終わった後={finish}）");
    }
}

/// **空に戻すと、作ったばかりのものと同じに描く**（その後に足せば、作ったばかりのものへ足したのと同じ）。
fn reset_renders_like_a_new_one<M: StreamingMarkdown>(make: &impl Fn() -> M, sample: &str) {
    for finish in [false, true] {
        let mut m = fed(make, &[sample]);
        if finish {
            m.finish();
        }
        m.reset();
        assert_eq!(
            every_width(&mut m),
            every_width(&mut make()),
            "空に戻した後が、作ったばかりのものと違う（終わった後={finish}）"
        );
        m.push(sample);
        assert_eq!(
            every_width(&mut m),
            every_width(&mut fed(make, &[sample])),
            "空に戻してから足した結果が、作ったばかりのものへ足したのと違う（終わった後={finish}）"
        );
    }
}

/// **`finish`は何度呼んでも1回と同じ。終わった後に足すと流入を再開する**（全部を流入中に足したのと同じに描き、
/// もう一度終えれば、全部を足して終えたのと同じ）。
fn finish_is_idempotent_and_push_after_finish_continues<M: StreamingMarkdown>(
    make: &impl Fn() -> M,
    sample: &str,
) {
    let mut once = finished(fed(make, &[sample]));
    let mut twice = finished(finished(fed(make, &[sample])));
    assert_eq!(
        every_width(&mut twice),
        every_width(&mut once),
        "2回目の`finish`で描画が変わった"
    );

    // 真ん中に一番近い、手前の文字の境目で分ける。
    let middle = (0..=sample.len() / 2)
        .rev()
        .find(|&at| sample.is_char_boundary(at))
        .unwrap_or(0);
    let (head, tail) = sample.split_at(middle);
    let mut resumed = finished(fed(make, &[head]));
    resumed.push(tail);
    assert_eq!(
        every_width(&mut resumed),
        every_width(&mut fed(make, &[sample])),
        "終わった後に足した文章が、流入中に足したのと同じに描かれない"
    );
    assert_eq!(
        every_width(&mut finished(resumed)),
        every_width(&mut once),
        "終わった後に足してからもう一度終えた結果が、全部を足して終えたのと違う"
    );
}

/// **行と印は同じ数**（[`Rendered`]の不変条件）。空の文章・1桁・0桁でも落ちない。
fn lines_and_joins_have_the_same_length<M: StreamingMarkdown>(make: &impl Fn() -> M, sample: &str) {
    for text in ["", "a", "\n\n", sample] {
        for finish in [false, true] {
            let mut m = fed(make, &[text]);
            if finish {
                m.finish();
            }
            for (w, rendered) in WIDTHS.iter().zip(every_width(&mut m)) {
                assert_eq!(
                    rendered.lines.len(),
                    rendered.joins.len(),
                    "{w}桁で{text:?}を描くと行と印の数が違う（終わった後={finish}）"
                );
            }
        }
    }
}

/// **リンクの区間は、指す行の文字の中に収まる**（[`Rendered`]の`links`）。行の外や文字の外を指す区間は、使う側が
/// 位置から引いたときに何にも当たらないか、別の文字を指してしまう。区間の文字は`Line::styled_graphemes`で数える
/// （範囲選択の位置と同じ数え方）。
fn links_stay_inside_their_lines<M: StreamingMarkdown>(make: &impl Fn() -> M, sample: &str) {
    for finish in [false, true] {
        let mut m = fed(make, &[sample]);
        if finish {
            m.finish();
        }
        for (w, rendered) in WIDTHS.iter().zip(every_width(&mut m)) {
            for link in &rendered.links {
                let line = rendered.lines.get(link.line).unwrap_or_else(|| {
                    panic!("{w}桁で、行の外を指すリンクの区間{link:?}（終わった後={finish}）")
                });
                let count = line.styled_graphemes(Style::default()).count();
                assert!(
                    link.start < link.end && link.end <= count,
                    "{w}桁で、行の文字（{count}文字）の外を指すリンクの区間{link:?}（終わった後={finish}）"
                );
            }
        }
    }
}

#[test]
fn plain_text_keeps_the_port_contract() {
    port_contract(PlainText::default);
}
