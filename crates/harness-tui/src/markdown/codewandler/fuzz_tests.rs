//! 乱数で作ったMarkdownらしい文章を、流れ込むときと同じ形でAdapterへ通し、解析器も描画部品も落ちない
//! （panicしない）ことを確かめる回帰試験（計画書`plans/PLAN-TUI-IMPROVEMENTS.md`§0のT9の(2)）。
//!
//! # 何のためにあるのか
//!
//! 解析器が落ちる入力は、T8で1つ見つかった（表の区切り行の`:`だけのセル。`super::guard`が渡す前に避ける）。
//! ほかにも落ちる入力があるかを、記号の多い文章を大量に作って探した。落ちてもAdapterは受け止めて原文のまま描く
//! （モジュールdocの「落ちたとき」）ので画面は壊れないが、**その返答は整形されなくなる**——だから、落ちないことを
//! 決まった乱数の列で確かめ続ける。ここで落ちたら、表示に出た入力を最小の形まで縮めて、`guard`で避けるか
//! （直せる形なら）を決める。
//!
//! # 文章の作り方
//!
//! [`markdown_like`]が、行の頭の印（見出し・リスト・番号・引用・フェンス・表の`|`・字下げ・タスクリスト・HTML・
//! 参照リンクの定義）と、行の中の記号（`|:-*_`#>[]()!<>~=+.`・数字・英小文字・全角文字・空白・タブ）を、決まった
//! 乱数（[`Rng`]。種を固定）で並べる。改行は`\n`と`\r\n`を混ぜる。流し方は[`feed`]——文章を1〜24バイトの
//! 細切れにして足し、足すたびに幅を変えて描き、最後に終えて描く（流入中の末尾の解析・確定の境界の確かめ・
//! 終えたときの全文の解析を全部通す）。
//!
//! # 一回きりの調査の結果（2026-10-06）
//!
//! この作り方と、ほかに2つの作り方（記号のごった煮・リスト／フェンス／HTML／表の行を並べるもの）で、試験より
//! ずっと多くの文章を一度だけ通した（件数と結果は`super::guard`のモジュールdocの限界）。落ちた文章はどれも、
//! 書き換えが届かない形（`super::guard::GUARD_MISSES`）だった。調査に使った使い捨ての試験と、ほかの2つの作り方は
//! 残していない（`docs/CODE-STRUCTURE-RULES.md`規則2）。ここに残すのは、この作り方で数秒で終わる件数だけである
//! ——この種と件数では、Adapterは1度も原文のまま描く形へ落ちない。
//!
//! # 限界
//!
//! - 決まった乱数の列なので、毎回同じ文章しか試さない（新しい入力は探さない）。探し直すときは種か件数を変えて
//!   一度だけ回す
//! - 落ちないことしか見ない（描いた結果が正しいかは見ない。それは他の試験が持つ）

use super::*;

/// 決まった列を返す乱数（splitmix64）。依存を足さないために自分で持つ。
pub(super) struct Rng(u64);

impl Rng {
    pub(super) fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub(super) fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// `0..n`のどれか（`n`は1以上）。
    pub(super) fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

/// 行の頭に置く印。空の文字列は「印なし」。
const LINE_STARTS: [&str; 30] = [
    "", "", "", "", "# ", "## ", "###### ", "#", "- ", "* ", "+ ", "1. ", "10) ", "> ", "> > ",
    ">", "```", "~~~", "```rust", "|", "| ", "    ", "  ", "\t", "- [ ] ", "- [x] ", "---",
    "<div>", "<!--", "[a]: ",
];

/// 行の中に並べる記号と文字。
const INLINE: [&str; 44] = [
    "|", "|", ":", ":", "-", "-", "*", "_", "`", "#", ">", "[", "]", "(", ")", "!", "<", ">", "~",
    "=", "+", ".", "0", "7", "a", "b", "x", "z", "日", "本", "語", "、", "。", " ", " ", " ", "\t",
    "\\", "**", "](", "|:", ":-", "---", "http://",
];

/// Markdownらしい文章を1つ作る（モジュールdocの「文章の作り方」）。長さは0〜十数行。
pub(super) fn markdown_like(rng: &mut Rng) -> String {
    let mut text = String::new();
    for _ in 0..rng.below(14) {
        text.push_str(rng.pick(&LINE_STARTS));
        for _ in 0..rng.below(16) {
            text.push_str(rng.pick(&INLINE));
        }
        match rng.below(8) {
            0 => {}                     // 改行で終わらない（流入中の書きかけの行）
            1 => text.push_str("\r\n"), // CRLF
            2 => text.push_str("\n\n"), // 空行（確定の境界の候補）
            _ => text.push('\n'),
        }
    }
    text
}

/// `text`を1〜24バイトの細切れ（文字の途中では切らない）にして順に足し、足すたびに描く。最後に終えて描く。
/// 描く幅も乱数で変える（0桁・1桁の狭さも含める）。
pub(super) fn feed(text: &str, rng: &mut Rng) -> CodewandlerMarkdown {
    const WIDTHS: [u16; 6] = [0, 1, 7, 20, 41, 80];
    let mut m = CodewandlerMarkdown::default();
    let mut at = 0;
    while at < text.len() {
        let mut end = (at + 1 + rng.below(24)).min(text.len());
        while !text.is_char_boundary(end) {
            end += 1;
        }
        m.push(&text[at..end]);
        m.render(WIDTHS[rng.below(WIDTHS.len())]);
        at = end;
    }
    m.finish();
    m.render(WIDTHS[rng.below(WIDTHS.len())]);
    m
}

/// 回帰試験の種（変えると試す文章が変わる）。
const SEED: u64 = 0x7439_2026_1006;
/// 回帰試験で通す文章の数（デバッグビルドで数秒に収まる数）。
const CASES: usize = 1_500;

/// **乱数で作ったMarkdownらしい文章を流し込んでも、Adapterは原文のまま描く形へ落ちない**（解析器も描画部品も
/// 落ちない）。落ちた文章は失敗の文面に出る。
#[test]
fn random_markdown_like_text_never_makes_the_adapter_fall_back() {
    let mut rng = Rng::new(SEED);
    let mut bytes = 0;
    for case in 0..CASES {
        let text = markdown_like(&mut rng);
        bytes += text.len();
        let m = feed(&text, &mut rng);
        assert!(
            !m.has_fallen_back(),
            "{case}件目の文章で解析器か描画部品が落ちた（標準エラーの文面に場所がある）: {text:?}"
        );
    }
    // 文章が作れていないのに緑になる形を止める（平均して1件あたり数十バイトある）。
    assert!(bytes > CASES * 20, "作った文章が短すぎる（{bytes}バイト）");
}
