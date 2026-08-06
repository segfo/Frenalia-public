//! 行単位diffとハンク分割（レビュー面の唯一の差分エンジン、`plans/PLAN-VSCODE-REVIEW.md`
//! §内蔵レビュー面）。
//!
//! **なぜ`harness-tui`ではなく`harness-sandbox`に置くのか**: ハンク単位の部分適用
//! （[`crate::SandboxFs::apply_hunks`]）は、パネルが表示したのと**同じハンク分割**を適用側で
//! 再計算する必要がある。表示と適用でアルゴリズムが違うと「見たものと違うものが適用される」
//! 事故になるため、両者が同じ1つの実装を呼ぶ。`harness-tui`は既に`harness-sandbox`へ
//! 依存しているので依存方向は変わらない（`harness-redirector`（注入DLL）へは持ち込まない）。
//!
//! **改行の扱い**: 行分割は改行文字を含めたまま行い（[`split_lines_keeping_endings`]）、
//! 合成は元のバイト列をそのまま連結する。CRLF/LFの混在や末尾改行の有無は、選んだ側の
//! 綴りがそのまま残る（部分適用が改行を書き換えないことは`compose_selected`のテストが固定する）。
//!
//! 以前ここにあった素朴fold実装（旧`harness-tui::diff::line_diff`、共通の先頭/末尾行を畳んで
//! 残りを丸ごと削除/追加とするもの）は、複数の離れた変更が1塊へ縮退するためレビュー用途では
//! 使えず、`similar`クレートへ置き換えて削除した。

use similar::{ChangeTag, TextDiff};

/// ハンクの前後に付けるコンテキスト行数。**表示側と適用側で必ず同じ値**を使うため、
/// 引数ではなく定数として1箇所に持つ（[`diff_hunks`]・[`compose_selected`]が共有）。
pub const HUNK_CONTEXT_LINES: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffKind {
    Context,
    Removed,
    Added,
}

/// 表示用の1行。`text`は**改行を除いた**行の内容（描画がそのまま1行として出せる形）。
/// 合成（[`compose_selected`]）はこの型を使わず元の文字列から直接切り出すので、
/// ここで改行を落としても適用結果の改行は失われない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    pub kind: DiffKind,
    pub text: String,
}

/// 変更塊1つ（前後に最大[`HUNK_CONTEXT_LINES`]行のコンテキストを含む）。
/// `old_start`/`new_start`は0起点の行番号で、`lines`は`Context`/`Removed`/`Added`が
/// diff順に並んだ表示用の行列。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffHunk {
    pub old_start: usize,
    pub old_len: usize,
    pub new_start: usize,
    pub new_len: usize,
    pub lines: Vec<DiffLine>,
}

impl DiffHunk {
    /// `@@ -1,4 +1,5 @@`形式の見出し（表示専用。行番号は1起点へ直す）。
    pub fn header(&self) -> String {
        format!(
            "@@ -{},{} +{},{} @@",
            self.old_start + 1,
            self.old_len,
            self.new_start + 1,
            self.new_len
        )
    }
}

/// 改行を含めたまま行へ分割する（`"a\r\nb"` → `["a\r\n", "b"]`）。空文字列は空の列。
/// `similar::TextDiff::from_lines`のトークン分割と同じ規則（`\n`の直後で切る）であること、
/// つまり[`diff_hunks`]の行番号でこの列を添字できることが本関数の契約である。
pub fn split_lines_keeping_endings(text: &str) -> Vec<&str> {
    text.split_inclusive('\n').collect()
}

fn strip_eol(line: &str) -> &str {
    line.strip_suffix('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .unwrap_or(line)
}

fn ensure_trailing_newline(text: &str) -> std::borrow::Cow<'_, str> {
    if text.is_empty() || text.ends_with('\n') {
        std::borrow::Cow::Borrowed(text)
    } else {
        std::borrow::Cow::Owned(format!("{text}\n"))
    }
}

fn kind_of(tag: ChangeTag) -> DiffKind {
    match tag {
        ChangeTag::Equal => DiffKind::Context,
        ChangeTag::Delete => DiffKind::Removed,
        ChangeTag::Insert => DiffKind::Added,
    }
}

/// `old`→`new`の行単位diffを、変更塊ごとのハンクへ分割して返す。変更が無ければ空。
pub fn diff_hunks(old: &str, new: &str) -> Vec<DiffHunk> {
    let diff = TextDiff::from_lines(old, new);
    let mut out = Vec::new();
    for ops in diff.grouped_ops(HUNK_CONTEXT_LINES) {
        let (Some(first), Some(last)) = (ops.first(), ops.last()) else {
            continue;
        };
        let old_start = first.old_range().start;
        let old_end = last.old_range().end;
        let new_start = first.new_range().start;
        let new_end = last.new_range().end;
        let mut lines = Vec::new();
        for op in &ops {
            for change in diff.iter_changes(op) {
                lines.push(DiffLine {
                    kind: kind_of(change.tag()),
                    text: strip_eol(change.value()).to_string(),
                });
            }
        }
        out.push(DiffHunk {
            old_start,
            old_len: old_end - old_start,
            new_start,
            new_len: new_end - new_start,
            lines,
        });
    }
    out
}

/// ハンクへ分けない素通しの行単位diff（`edit_file`承認モーダルの差分プレビュー用）。
/// あちらの入力は`old_string`/`new_string`という局所スニペットで、間引くほどの長さが無い。
///
/// **末尾改行の有無だけは差分として出さない**（両側とも改行終端に揃えてから比較する）。
/// 行単位diffにとって`"b"`と`"b\n"`は別トークンなので、揃えないと末尾行が常に
/// 「削除＋追加」の対として出る——`old_string`/`new_string`は改行で終わらないスニペットが
/// 普通なので、ほぼ毎回ノイズになる。旧`harness-tui::diff::line_diff`（`str::lines`で
/// 分割していた）と同じ見え方であり、ここは表示専用なので合成の正確さには影響しない
/// （[`compose_selected`]が使う[`diff_hunks`]はこの正規化をしない——ファイルの末尾改行が
/// 変わったことは実際の内容変化であり、隠すと部分適用が壊れる）。
pub fn diff_lines(old: &str, new: &str) -> Vec<DiffLine> {
    let old = ensure_trailing_newline(old);
    let new = ensure_trailing_newline(new);
    TextDiff::from_lines(old.as_ref(), new.as_ref())
        .iter_all_changes()
        .map(|change| DiffLine {
            kind: kind_of(change.tag()),
            text: strip_eol(change.value()).to_string(),
        })
        .collect()
}

/// `accepted`（[`diff_hunks`]順のハンク番号）だけを`new`側から採り、それ以外は`old`側のまま
/// 合成した内容を返す。ハンクの外（両側で共通の部分）は`old`から採る。
///
/// **ハンクの実体を外から受け取らない**のが要点で、呼び出し側が渡せるのは番号だけである
/// （`plans/PLAN-VSCODE-REVIEW.md`「部分適用はハッシュ照合＋決定的再計算」）。同じ`old`/`new`
/// からは常に同じハンク列が出るので、パネルが見たものと適用されるものが一致する。
pub fn compose_selected(old: &str, new: &str, accepted: &[usize]) -> String {
    let old_lines = split_lines_keeping_endings(old);
    let new_lines = split_lines_keeping_endings(new);
    let hunks = diff_hunks(old, new);
    let mut out = String::with_capacity(old.len().max(new.len()));
    let mut cursor = 0usize;
    for (i, hunk) in hunks.iter().enumerate() {
        for line in &old_lines[cursor..hunk.old_start] {
            out.push_str(line);
        }
        if accepted.contains(&i) {
            for line in &new_lines[hunk.new_start..hunk.new_start + hunk.new_len] {
                out.push_str(line);
            }
        } else {
            for line in &old_lines[hunk.old_start..hunk.old_start + hunk.old_len] {
                out.push_str(line);
            }
        }
        cursor = hunk.old_start + hunk.old_len;
    }
    for line in &old_lines[cursor..] {
        out.push_str(line);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn numbered(range: std::ops::Range<usize>) -> String {
        range.map(|i| format!("line{i}\n")).collect()
    }

    #[test]
    fn distant_changes_become_separate_hunks() {
        // 旧fold実装への回帰テスト: 離れた2箇所の変更が「old全部削除＋new全部追加」の
        // 1塊へ縮退してはならない。
        let old = numbered(0..30);
        let new = old
            .replace("line2\n", "CHANGED2\n")
            .replace("line25\n", "CHANGED25\n");
        let hunks = diff_hunks(&old, &new);
        assert_eq!(hunks.len(), 2, "hunks: {hunks:#?}");
        assert!(hunks[0].lines.iter().any(|l| l.text == "CHANGED2"));
        assert!(hunks[1].lines.iter().any(|l| l.text == "CHANGED25"));
        // 縮退していれば全30行が1ハンクに入る。
        assert!(hunks[0].old_len <= 2 * HUNK_CONTEXT_LINES + 1);
    }

    #[test]
    fn hunk_carries_three_context_lines_on_each_side() {
        let old = numbered(0..20);
        let new = old.replace("line10\n", "CHANGED\n");
        let hunks = diff_hunks(&old, &new);
        assert_eq!(hunks.len(), 1);
        let h = &hunks[0];
        assert_eq!(h.old_start, 10 - HUNK_CONTEXT_LINES);
        assert_eq!(h.old_len, 2 * HUNK_CONTEXT_LINES + 1);
        assert_eq!(h.header(), "@@ -8,7 +8,7 @@");
        let contexts = h
            .lines
            .iter()
            .filter(|l| l.kind == DiffKind::Context)
            .count();
        assert_eq!(contexts, 2 * HUNK_CONTEXT_LINES);
    }

    #[test]
    fn nearby_changes_merge_into_one_hunk() {
        // コンテキストが重なる距離（3行以内）の2つの変更は1ハンクにまとまる。
        let old = numbered(0..20);
        let new = old.replace("line10\n", "A\n").replace("line12\n", "B\n");
        let hunks = diff_hunks(&old, &new);
        assert_eq!(hunks.len(), 1, "hunks: {hunks:#?}");
    }

    #[test]
    fn diff_against_empty_is_all_added() {
        let hunks = diff_hunks("", "a\nb\n");
        assert_eq!(hunks.len(), 1);
        assert!(hunks[0].lines.iter().all(|l| l.kind == DiffKind::Added));
        assert_eq!(hunks[0].old_len, 0);
        assert_eq!(hunks[0].new_len, 2);
    }

    #[test]
    fn identical_content_has_no_hunks() {
        assert!(diff_hunks("a\nb\n", "a\nb\n").is_empty());
    }

    #[test]
    fn compose_takes_only_accepted_hunks() {
        let old = numbered(0..30);
        let new = old
            .replace("line2\n", "CHANGED2\n")
            .replace("line25\n", "CHANGED25\n");
        assert_eq!(diff_hunks(&old, &new).len(), 2);

        let only_first = compose_selected(&old, &new, &[0]);
        assert!(only_first.contains("CHANGED2\n"));
        assert!(!only_first.contains("CHANGED25\n"));
        assert!(only_first.contains("line25\n"));

        let only_second = compose_selected(&old, &new, &[1]);
        assert!(!only_second.contains("CHANGED2\n"));
        assert!(only_second.contains("CHANGED25\n"));

        assert_eq!(compose_selected(&old, &new, &[0, 1]), new);
        assert_eq!(compose_selected(&old, &new, &[]), old);
    }

    #[test]
    fn compose_preserves_crlf_and_lf_mix() {
        // 触っていない行の改行が書き換わらないこと（CRLF/LF混在ファイルの部分適用）。
        let old = "a\r\nb\nc\r\nd\n";
        let new = "a\r\nB\nc\r\nD\n";
        let hunks = diff_hunks(old, new);
        assert_eq!(hunks.len(), 1, "近接しているので1ハンク: {hunks:#?}");
        // 1ハンクなので全採用/全不採用のどちらでも元の綴りがそのまま残る。
        assert_eq!(compose_selected(old, new, &[]), old);
        assert_eq!(compose_selected(old, new, &[0]), new);
    }

    #[test]
    fn compose_preserves_untouched_crlf_far_from_the_change() {
        let old = format!("{}x\r\n{}", numbered(0..10), numbered(10..20));
        let new = old.replace("line15\n", "CHANGED\n");
        let composed = compose_selected(&old, &new, &[0]);
        assert!(composed.contains("x\r\n"), "composed: {composed:?}");
        assert_eq!(composed, new);
    }

    #[test]
    fn compose_does_not_add_a_trailing_newline() {
        let old = "a\nb\nc";
        let new = "a\nB\nc";
        assert_eq!(compose_selected(old, new, &[0]), "a\nB\nc");
        assert_eq!(compose_selected(old, new, &[]), "a\nb\nc");
    }

    #[test]
    fn compose_keeps_missing_trailing_newline_on_the_last_line() {
        let old = "a\nb";
        let new = "a\nb\nc";
        assert_eq!(compose_selected(old, new, &[0]), "a\nb\nc");
        assert_eq!(compose_selected(old, new, &[]), "a\nb");
    }

    #[test]
    fn diff_lines_keeps_common_prefix_and_suffix_as_context() {
        // 旧`harness-tui::diff::line_diff`のテストの移植（承認モーダルの見え方の固定）。
        let diff = diff_lines("a\nb\nc\nd", "a\nX\nc\nd");
        assert_eq!(
            diff,
            vec![
                DiffLine {
                    kind: DiffKind::Context,
                    text: "a".into()
                },
                DiffLine {
                    kind: DiffKind::Removed,
                    text: "b".into()
                },
                DiffLine {
                    kind: DiffKind::Added,
                    text: "X".into()
                },
                DiffLine {
                    kind: DiffKind::Context,
                    text: "c".into()
                },
                DiffLine {
                    kind: DiffKind::Context,
                    text: "d".into()
                },
            ]
        );
    }

    #[test]
    fn diff_lines_handles_pure_addition() {
        let diff = diff_lines("a\nb", "a\nb\nc");
        assert_eq!(
            diff,
            vec![
                DiffLine {
                    kind: DiffKind::Context,
                    text: "a".into()
                },
                DiffLine {
                    kind: DiffKind::Context,
                    text: "b".into()
                },
                DiffLine {
                    kind: DiffKind::Added,
                    text: "c".into()
                },
            ]
        );
    }

    #[test]
    fn diff_hunks_does_not_hide_a_trailing_newline_change() {
        // `diff_lines`（表示専用）と違い、ハンク側は末尾改行の変化を隠さない——隠すと
        // 「合成しても内容が一致しない」ことになり部分適用が壊れる。
        let hunks = diff_hunks("a\nb", "a\nb\n");
        assert_eq!(hunks.len(), 1, "hunks: {hunks:#?}");
        assert_eq!(compose_selected("a\nb", "a\nb\n", &[0]), "a\nb\n");
    }

    #[test]
    fn split_lines_matches_the_line_numbering_of_diff_hunks() {
        // `compose_selected`が`diff_hunks`の行番号でこの列を添字するための前提。
        let text = "a\r\nb\nc";
        assert_eq!(split_lines_keeping_endings(text), vec!["a\r\n", "b\n", "c"]);
        assert!(split_lines_keeping_endings("").is_empty());
    }
}
