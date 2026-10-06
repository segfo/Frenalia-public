//! 確定の境界の**候補**を、文章の字面だけで探す部品（計画書`plans/PLAN-TUI-IMPROVEMENTS.md`§1.4(3)の1）。
//!
//! # 何のためにあるのか
//!
//! Adapter（`super::CodewandlerMarkdown`）は、流れ込む文章を「確定した部分」と「書きかけの末尾」に分け、確定した
//! 部分を解析し直さない。分ける位置（境界）を採るかどうかは解析器に確かめて決める（`super`のモジュールdoc）。
//! 確かめるには解析が要るので、**確かめるまでもなく境界にならない行**を、ここで字面だけを見て候補から外す。
//!
//! # 候補の規則
//!
//! 次の4つを全部満たす行が候補になる（返すのはその行の範囲。行末の改行を含む）。
//!
//! 1. **直前の行が空行**（空白とタブだけの行。`\r`は行末の一部として読み飛ばす。解析器の空行と同じ）
//! 2. **行頭（字下げなし）から始まる**——最初の文字が空白でもタブでもない。字下げした行はリストの項目の続きか
//!    字下げのコードで、前の行と同じブロックに入り得る
//! 3. **コードフェンスの外**——フェンスの中の空行は、コードの中身である
//! 4. **改行まで届いている**——行の残りが届くまで、その行が何かは決まらない
//!
//! フェンスの開閉は解析器（`markdown_stream`の`block.rs`の`fence_start`・`is_closing_fence`）に合わせる。
//!
//! - 開く: 字下げ（空白は1桁、タブは次の4の倍数の桁まで）が3桁まで。空白（全角も含む）を除いた行頭が
//!   `` ` ``か`~`の3つ以上の並び。`` ` ``のフェンスの情報文字列に`` ` ``があればフェンスではない
//! - 閉じる: 空白を除いた行頭が、開いたのと同じ記号の、開いた長さ以上の並びで、後ろが空白だけ（字下げは問わない
//!   ——解析器がそう読む）
//!
//! # 限界（候補を外しすぎる・外さなすぎる所。どちらも描く結果は変えない）
//!
//! - 入れ物（リストの項目・引用）を数えないので、**入れ物の中のフェンスを最上位のフェンスとして数える**ことがある
//!   （字下げ3桁までのとき）。項目が行頭の行で終わってフェンスが暗黙に閉じると、ここでの開閉が解析器と逆になり、
//!   本当の境界を候補から外したり、フェンスの中の行を候補にしたりする。HTMLブロックの中の```` ``` ````の行も
//!   フェンスとして数える。**どちらも描く結果は変えない**——候補は解析器が確かめてから境界にするので、外しすぎれば
//!   末尾が長くなる（遅くなる）だけ、外さなすぎれば確かめる解析が増えるだけ
//! - `>`で始まる引用の中のフェンスは数えない。引用の中の空行は`>`だけの行で、本当の空行は引用を閉じるため

use std::ops::Range;

#[cfg(test)]
#[path = "seal_tests.rs"]
mod tests;

/// 開いているコードフェンス（記号と長さ）。`super::guard`も同じ数え方でフェンスの中を見分ける。
#[derive(Debug, Clone, Copy)]
pub(super) struct Fence {
    mark: u8,
    len: usize,
}

/// 確定の境界の候補を、足された文章の頭から順に探す（モジュールdoc）。
///
/// 読み終えた所を覚えておき、次の[`Self::advance`]では、その続きの**改行まで届いた行**だけを読む。
/// 同じ文章を前回より長くなっただけの形で渡し続ける前提（Adapterは文章を末尾へ足すだけで、空に戻すときは
/// 作り直す）。
#[derive(Debug, Default)]
pub(super) struct Scanner {
    /// 次に読む行の頭（バイト位置）。
    scanned: usize,
    /// 直前に読んだ行が空行か。
    after_blank: bool,
    /// 開いているフェンス。
    fence: Option<Fence>,
}

impl Scanner {
    /// `text`のうち、まだ読んでいない、改行まで届いた行を読み、候補の行の範囲（行末の改行を含む）を順に返す。
    pub(super) fn advance(&mut self, text: &str) -> Vec<Range<usize>> {
        let mut found = Vec::new();
        while let Some(newline) = text[self.scanned..].find('\n') {
            let start = self.scanned;
            let end = start + newline + 1;
            let line = &text[start..end - 1];
            if self.read(line.strip_suffix('\r').unwrap_or(line)) {
                found.push(start..end);
            }
            self.scanned = end;
        }
        found
    }

    /// 1行（改行と行末の`\r`を除いたもの）を読み、その行が候補なら`true`。
    fn read(&mut self, line: &str) -> bool {
        let candidate = match self.fence {
            Some(fence) => {
                if closes(line, fence) {
                    self.fence = None;
                }
                false
            }
            None => {
                self.fence = opens(line);
                self.after_blank && starts_at_column_zero(line)
            }
        };
        self.after_blank = is_blank(line);
        candidate
    }
}

/// 空行か（空白とタブだけ。解析器の`Cursor::is_blank`と同じ）。
fn is_blank(line: &str) -> bool {
    line.bytes().all(|b| matches!(b, b' ' | b'\t'))
}

/// 行頭（字下げなし）から文字が始まるか。空行は始まらない。
fn starts_at_column_zero(line: &str) -> bool {
    line.as_bytes()
        .first()
        .is_some_and(|b| !matches!(b, b' ' | b'\t'))
}

/// 行の頭の字下げの桁数（空白は1桁、タブは次の4の倍数の桁まで。解析器の`Cursor::indent`と同じ数え方）。
fn indent(line: &str) -> usize {
    let mut columns = 0;
    for b in line.bytes() {
        match b {
            b' ' => columns += 1,
            b'\t' => columns += 4 - columns % 4,
            _ => break,
        }
    }
    columns
}

/// この行がフェンスを開くなら、そのフェンス（モジュールdocの「開く」）。
pub(super) fn opens(line: &str) -> Option<Fence> {
    if indent(line) >= 4 {
        return None;
    }
    let trimmed = line.trim_start();
    let mark = *trimmed.as_bytes().first()?;
    if mark != b'`' && mark != b'~' {
        return None;
    }
    let len = trimmed.bytes().take_while(|&b| b == mark).count();
    if len < 3 || (mark == b'`' && trimmed[len..].contains('`')) {
        return None;
    }
    Some(Fence { mark, len })
}

/// この行が`fence`を閉じるか（モジュールdocの「閉じる」）。
pub(super) fn closes(line: &str, fence: Fence) -> bool {
    let trimmed = line.trim_start();
    let len = trimmed.bytes().take_while(|&b| b == fence.mark).count();
    len >= fence.len && trimmed[len..].trim().is_empty()
}
