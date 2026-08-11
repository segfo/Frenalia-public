//! ファイル名要素として安全な文字列かどうかの共有検査。
//!
//! [`crate::scratch::ScratchStore`]（`raw/`・`notes/`）と[`crate::recall`]
//! （`checkpoints/`・indexから読んだID）の両方が、外来の文字列（プロバイダ由来の
//! `tool_call_id`、`index.jsonl`から読んだcheckpoint ID）をファイル名要素として使う前に
//! ここを通す。**2箇所に同じ検査を別々に書かない**（`bug-pattern-rules` B-05）——
//! 片方だけ緩めてしまう事故を構造的に防ぐ。

use std::io;

/// `../`・ドライブ指定・区切り文字を含まないか検査する。
pub(crate) fn validate_id(id: &str) -> io::Result<()> {
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsafe id for a file name: {id:?}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal_and_separators() {
        for evil in [
            "../escape",
            "..\\escape",
            "a/b",
            "C:\\Windows\\System32\\evil",
            "",
            "call 1",
        ] {
            assert_eq!(
                validate_id(evil).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn accepts_normal_ids() {
        for ok in [
            "call_1",
            "toolu_01A2b3C4",
            "call-abc-123",
            "0",
            "cp-123-abcdef01",
        ] {
            validate_id(ok).unwrap();
        }
    }
}
