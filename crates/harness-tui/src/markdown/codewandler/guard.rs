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
//! - 解析器がほかの入力で落ちるかは分からない。見つけたのはこの1つ（計画書のT8の試験で、全ての試験の入力を
//!   1文字ずつ流したとき）
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

/// `text`の全部を1行ずつ[`Guard`]に通したもの（試験の基準を、Adapterと同じ書き換えの後の文章で作るため）。
#[cfg(test)]
pub(super) fn defused(text: &str) -> String {
    let mut guard = Guard::default();
    text.split_inclusive('\n')
        .map(|line| guard.line(line).into_owned())
        .collect()
}
