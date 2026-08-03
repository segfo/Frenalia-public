//! 文字列の機械的な切詰め。`plans/DESIGN-COGNITION.md` §6.2「まず機械的に切詰め →
//! 蒸留で意味的に抽出」の前段フィルタで、台帳スライスの縮約（[`crate::context`]）・
//! 生出力の遅延展開（[`crate::scratch`]）・観測の蒸留入力（[`crate::hiv::evidence`]）の
//! 3箇所が同じ関数を使う（`docs/CODE-STRUCTURE-RULES.md` 規則5）。

/// `content`が`max_chars`文字を超える場合、先頭/末尾を残し中間を省略記号に置き換える。
///
/// 文字数（`chars().count()`）で数えるのはトークン概算が文字数ベースだからで、
/// バイト数で切ると日本語で境界が壊れる。
pub(crate) fn truncate_head_tail(content: &str, max_chars: usize) -> String {
    let total = content.chars().count();
    if total <= max_chars {
        return content.to_string();
    }
    let half = max_chars / 2;
    let head: String = content.chars().take(half).collect();
    let tail: String = content.chars().skip(total - half).collect();
    let omitted = total - 2 * half;
    format!("{head}\n... [{omitted} chars truncated] ...\n{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_content_is_returned_verbatim() {
        assert_eq!(truncate_head_tail("hello", 100), "hello");
    }

    #[test]
    fn long_content_keeps_both_ends_and_reports_the_omission() {
        let out = truncate_head_tail(&"x".repeat(1_000), 100);
        assert!(out.starts_with("xxxx"));
        assert!(out.ends_with("xxxx"));
        assert!(out.contains("[900 chars truncated]"), "{out}");
    }

    /// マルチバイト文字の途中で切らない（バイト数で切るとパニックする）。
    #[test]
    fn multibyte_content_is_cut_on_character_boundaries() {
        let out = truncate_head_tail(&"あ".repeat(1_000), 100);
        assert!(out.starts_with("あああ"), "{out}");
    }
}
