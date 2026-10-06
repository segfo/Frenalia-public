//! 解析器（`codewandler-markdown-stream` 0.2.1）が落ちる（panicする）行を、渡す前に無害な形へ書き換える部品。
//!
//! # 何のためにあるのか
//!
//! 解析器は、`|`を含む1行だけの段落の次の行を表の区切り行（`|---|`）として読むとき、セルが空白を除いて`:`1文字
//! だと範囲外の切り出しで落ちる（`block.rs`の`parse_delim_row`の`&c[usize::from(left)..c.len() - usize::from(right)]`
//! が`&":"[1..0]`になる）。表を流しているときの書きかけの区切り行（`|:`で止まった瞬間）や、崩れた表（`| a |`の次の
//! `|:|`）で起きる。描画の経路で落ちると、panicのフック（`harness_term`）が端末を戻してTUIごと終わる——
//! `catch_unwind`で受けても、受ける前にフックが走るので防げない。そこで、Portの契約（描画の経路は失敗しない。
//! `super::super::StreamingMarkdown`）を守るために、落ちる形の行を解析器へ渡す前に書き換える。
//!
//! # 書き換え
//!
//! 空白を除くと`:`だけのセルの`:`の前に`\`を足す（`\:`）。CommonMarkでは`\:`は`:`の文字なので、段落や表のセル
//! として描く文字は変わらない。解析器が区切り行として見ても`\:`は区切りのセルではないので、落ちずに「区切り行では
//! ない」と判定する——落ちなければ下したはずの判定（`:`だけのセルは区切りのセルではない）と同じ。
//!
//! 書き換えるのは、次を全部満たす行だけ。
//!
//! - **前の行に`|`がある**（解析器が区切り行として読むのは、`|`を含む1行だけの段落の次の行だけ）
//! - **コードフェンスの外**（`super::seal`と同じ数え方。フェンスの中の文字はそのまま描くので、書き換えると見える）
//! - **落ちる形**: 行頭の空白と`>`（入れ物の印と字下げ）を除いた残りを、解析器と同じ規則（`split_row`）でセルに
//!   分けると、`:`だけのセルに、区切りのセルとして正しいセルだけを通って届く（解析器はセルを順に見て、区切りで
//!   ないセルに当たるとそこで判定を終えるので、その後ろの`:`では落ちない）
//!
//! # 限界
//!
//! - 段落や入れ物を数えないので、落ちない行を書き換えることがある（前の行に`|`があり、解析器はそれを表の行・
//!   HTMLブロックの中・リストの印の後ろとして読む等）。段落・表のセル・リストの中では描く文字は変わらない。
//!   HTMLブロックの中では`\:`がそのまま見える
//! - 同じ理由で、**落ちる行を書き換えないことがある**——フェンスの数え方は入れ物もHTMLブロックも知らないので、
//!   こちらがフェンスの中と見て、解析器はフェンスと見ない行が出る。HTMLブロックの中のフェンス風の行（`<div>`の
//!   次の` ``` `）と、入れ物が終わって暗黙に閉じるフェンス（リストの項目の中で開いたまま次の項目へ進む）である。
//!   その後ろで落ちる形の行が来ると、解析器は今も落ちる（[`GUARD_MISSES`]）。フェンスの中も書き換えれば避けられるが、
//!   **コードの中の`:`の前に`\`が見え、そのまま写る**（黙って中身が変わる）ので、そうしない。落ちたらその返答は
//!   原文のまま描く（Adapterのモジュールdocの「落ちたとき」）——落ちたことは標準エラーとログに出る
//! - 解析器がこの形のほかで落ちるかは、探した範囲でしか分からない。T8では全ての試験の入力を1文字ずつ流して、
//!   この1つを見つけた。T9（2026-10-06）では、乱数で作ったMarkdownらしい文章200万件（行の頭の印と記号を並べる
//!   作り方・記号のごった煮・リスト／フェンス／HTML／表の行を並べる作り方の3種類。releaseビルド）を、行の終わり
//!   ごとの頭（計約1,360万）で素の解析器に通し、流れ込む形でAdapterにも通した。落ちたのはどれも同じ場所
//!   （区切り行の`:`だけのセル）で、書き換えた後に落ちたのは上の「書き換えないことがある」形だけ（Adapterが
//!   原文のまま描く形へ落ちたのは248件）、描画部品は1度も落ちなかった。同じ作り方で数秒で終わる件数を、
//!   回帰試験（`super::fuzz_tests`）が決まった乱数の列で通し続ける
//! - **暫定**: 解析器が直れば要らない。今も落ちることを試験（`tests::the_parser_still_panics_on_a_lone_colon_delimiter_cell`）
//!   が見張り、落ちなくなったら赤くなる

use std::borrow::Cow;
use std::ops::Range;

use super::seal::{closes, opens, Fence};

#[cfg(test)]
#[path = "guard_tests.rs"]
mod tests;

/// 解析器へ渡す行を1行ずつ受け取り、落ちる形の行を書き換える（モジュールdoc）。文章の頭（または確定の境界）から
/// 順に渡す。
#[derive(Debug, Default)]
pub(super) struct Guard {
    /// 前の行に`|`があったか。
    after_pipe: bool,
    /// 開いているコードフェンス。
    fence: Option<Fence>,
}

impl Guard {
    /// 次の1行（行末の改行を含んでよい）を、解析器へ渡す形にして返す。書き換えないときは借りたまま返す。
    pub(super) fn line<'a>(&mut self, line: &'a str) -> Cow<'a, str> {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let body = body.strip_suffix('\r').unwrap_or(body);
        let out = match self.fence {
            Some(fence) => {
                if closes(body, fence) {
                    self.fence = None;
                }
                Cow::Borrowed(line)
            }
            None => {
                self.fence = opens(body);
                if self.after_pipe && self.fence.is_none() {
                    escape_lone_colons(line, body)
                } else {
                    Cow::Borrowed(line)
                }
            }
        };
        self.after_pipe = body.contains('|');
        out
    }
}

/// `body`（`line`から行末の改行を除いたもの）が落ちる形なら、`:`だけのセルの`:`の前に`\`を足した`line`を返す。
fn escape_lone_colons<'a>(line: &'a str, body: &str) -> Cow<'a, str> {
    let row = body.trim_start_matches(|c: char| c.is_whitespace() || c == '>');
    if !crashes(row) {
        return Cow::Borrowed(line);
    }
    let offset = body.len() - row.len();
    let mut out = line.to_string();
    let colons: Vec<usize> = cell_ranges(row)
        .into_iter()
        .filter(|cell| row[cell.clone()].trim() == ":")
        .filter_map(|cell| {
            row[cell.clone()]
                .find(':')
                .map(|at| offset + cell.start + at)
        })
        .collect();
    for at in colons.into_iter().rev() {
        out.insert(at, '\\');
    }
    Cow::Owned(out)
}

/// 解析器が`row`を区切り行として読むと落ちるか（モジュールdocの「落ちる形」。`parse_delim_row`をなぞる）。
fn crashes(row: &str) -> bool {
    if !row.contains('|') && !row.contains('-') {
        return false;
    }
    for cell in cell_ranges(row) {
        let c = row[cell].trim();
        if c == ":" {
            return true;
        }
        let left = c.starts_with(':');
        let right = c.ends_with(':');
        let mid = &c[usize::from(left)..c.len() - usize::from(right)];
        if mid.is_empty() || !mid.bytes().all(|b| b == b'-') {
            return false;
        }
    }
    false
}

/// 解析器（`split_row`）と同じ規則でセルに分けた、各セルの範囲（`row`の中のバイト位置。セルの前後の空白を含む）。
/// 前後の空白を除いた行の頭と末尾の`|`を1つずつ外し、`\`の付いていない`|`で分ける（`\`は次の1文字と組になる）。
fn cell_ranges(row: &str) -> Vec<Range<usize>> {
    let mut start = row.len() - row.trim_start().len();
    let mut end = row.trim_end().len().max(start);
    if row[start..end].starts_with('|') {
        start += 1;
    }
    if row[start..end].ends_with('|') {
        end -= 1;
    }
    let mut ranges = Vec::new();
    let mut cell_start = start;
    let mut chars = row[start..end].char_indices();
    while let Some((at, c)) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '|' => {
                ranges.push(cell_start..start + at);
                cell_start = start + at + 1;
            }
            _ => {}
        }
    }
    ranges.push(cell_start..end);
    ranges
}

/// 書き換えが届かない形（モジュールdocの限界）。どれも書き換えずに解析器へ渡り、解析器が落ちる——今もそうであることを
/// `tests::the_guard_still_misses_fences_that_the_parser_does_not_see`が見張り、落ちたときにAdapterがその返答を
/// 原文のまま描くことを`super::fallback_tests`が確かめる。T9の乱数の文章で見つけた形を、読める形に整えたもの。
#[cfg(test)]
pub(super) const GUARD_MISSES: [&str; 4] = [
    // HTMLブロック（種類6）の中のフェンス風の行。空行でHTMLブロックが終わった後も、こちらはフェンスの中と見る
    "<div>\n```\n\n| a |\n|:|\n",
    // HTMLのコメント（種類2）の中のフェンス風の行
    "<!--\n```\n-->\n\n| a |\n|:|\n",
    // リストの項目の中で開いたフェンスが、次の項目で暗黙に閉じる（表を流している途中の`|:`の形）
    "1. x\n   ```\n2. y\n\n| a | b |\n|:--|:\n",
    // リストの項目の中で開いたフェンスが、行頭から始まる段落でリストごと閉じる
    "- a\n\n  ~~~\nb\n\n| a |\n|:|\n",
];

/// `text`の全部を1行ずつ[`Guard`]に通したもの（試験の基準を、Adapterと同じ書き換えの後の文章で作るため）。
#[cfg(test)]
pub(super) fn defused(text: &str) -> String {
    let mut guard = Guard::default();
    text.split_inclusive('\n')
        .map(|line| guard.line(line).into_owned())
        .collect()
}
