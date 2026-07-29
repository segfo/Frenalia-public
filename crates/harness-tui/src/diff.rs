//! `edit_file`承認モーダル用の素朴な行単位diff（M9、DESIGN.md L349「edit_fileのold/new
//! 差分プレビューを承認モーダル内に描画」）。新規crate依存を増やさないため、Myers diff等の
//! 汎用アルゴリズムではなく、共通の先頭/末尾行を畳み込み残りを丸ごと削除/追加とする
//! 素朴な実装に留める（`old_string`/`new_string`はもともと局所的なスニペットが多く、
//! 十分実用になる）。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffKind {
    Context,
    Removed,
    Added,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    pub kind: DiffKind,
    pub text: String,
}

/// `old`→`new`の行単位diff。共通の先頭行・末尾行はそのまま`Context`として残し、
/// その間の食い違う部分を`old`側全体を`Removed`、`new`側全体を`Added`として出す。
pub fn line_diff(old: &str, new: &str) -> Vec<DiffLine> {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();

    let mut prefix = 0;
    while prefix < old_lines.len()
        && prefix < new_lines.len()
        && old_lines[prefix] == new_lines[prefix]
    {
        prefix += 1;
    }

    let mut suffix = 0;
    while suffix < old_lines.len() - prefix
        && suffix < new_lines.len() - prefix
        && old_lines[old_lines.len() - 1 - suffix] == new_lines[new_lines.len() - 1 - suffix]
    {
        suffix += 1;
    }

    let mut out = Vec::new();
    for line in &old_lines[..prefix] {
        out.push(DiffLine {
            kind: DiffKind::Context,
            text: line.to_string(),
        });
    }
    for line in &old_lines[prefix..old_lines.len() - suffix] {
        out.push(DiffLine {
            kind: DiffKind::Removed,
            text: line.to_string(),
        });
    }
    for line in &new_lines[prefix..new_lines.len() - suffix] {
        out.push(DiffLine {
            kind: DiffKind::Added,
            text: line.to_string(),
        });
    }
    for line in &old_lines[old_lines.len() - suffix..] {
        out.push(DiffLine {
            kind: DiffKind::Context,
            text: line.to_string(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_common_prefix_and_suffix_as_context() {
        let old = "a\nb\nc\nd";
        let new = "a\nX\nc\nd";
        let diff = line_diff(old, new);
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
    fn handles_pure_addition() {
        let diff = line_diff("a\nb", "a\nb\nc");
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
    fn handles_completely_different_content() {
        let diff = line_diff("one", "two");
        assert_eq!(
            diff,
            vec![
                DiffLine {
                    kind: DiffKind::Removed,
                    text: "one".into()
                },
                DiffLine {
                    kind: DiffKind::Added,
                    text: "two".into()
                },
            ]
        );
    }
}
