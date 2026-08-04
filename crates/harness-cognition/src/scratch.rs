//! ツール/MCPの生出力を台帳の外へ退避する scratch ストア。
//! `plans/DESIGN-COGNITION.md` §5「生出力の退避」・§6.3「参照渡し + 遅延展開（zoom）」。
//!
//! # なぜ台帳に入れないか
//!
//! 生出力（10kトークンのファイル等）を`WorkingMemory`へ入れると、それがそのまま
//! 毎コールのコンテキストへ乗り、素朴ループと同じ肥大が起きる。台帳は
//! [`RawRef`]ポインタだけを持ち、詳細が要るフェーズだけが[`ScratchStore::zoom`]で
//! **その断片だけ**を取りに行く。
//!
//! # 置き場所（設計書からの変更点）
//!
//! 設計書§5は「オーバーレイFSのセッションディレクトリ配下」と書くが、そのディレクトリ
//! （`StagingConfig.sandbox_dir`）は`--staged`/`--cow`指定時にしか存在せず、既定の`--live`では
//! `None`である。認知レイヤーがステージングモードに依存してしまうため、既存のセッション
//! 永続化（`.harness/sessions/session-<id>.jsonl`）と同系統の独立ディレクトリ
//! `.harness/cognition/<session-id>/` を使う。M20の`ledger.jsonl`も同じ場所へ置く。

use std::io;
use std::path::{Path, PathBuf};

use crate::memory::types::RawRef;

/// 1セッション分のscratch領域。
#[derive(Debug, Clone)]
pub struct ScratchStore {
    raw_dir: PathBuf,
}

impl ScratchStore {
    /// `<workspace_root>/.harness/cognition/<session-id>/` を割り出す。
    ///
    /// `session_id`は`SessionStore::id()`（`session-<millis>`形式）をそのまま使う。台帳と
    /// 会話履歴が同じIDで対応することで、`--resume`（M20）が両方を同時に復元できる。
    pub fn dir_for_session(workspace_root: &Path, session_id: &str) -> PathBuf {
        workspace_root
            .join(".harness")
            .join("cognition")
            .join(session_id)
    }

    /// `dir`配下に`raw/`を作って開く。
    pub fn open(dir: &Path) -> io::Result<Self> {
        let raw_dir = dir.join("raw");
        std::fs::create_dir_all(&raw_dir)?;
        Ok(Self { raw_dir })
    }

    pub fn raw_dir(&self) -> &Path {
        &self.raw_dir
    }

    /// 生出力を退避し、台帳へ載せる[`RawRef`]を返す。
    ///
    /// 戻り値の`chars`は退避した文字数そのもの。台帳を見るだけで「展開したらどれだけ
    /// 膨らむか」が分かるので、`zoom`するかどうかを予算から判断できる。
    pub fn put_raw(&self, tool_call_id: &str, content: &str) -> io::Result<RawRef> {
        let path = self.path_for(tool_call_id)?;
        std::fs::write(path, content)?;
        Ok(RawRef {
            tool_call_id: tool_call_id.to_string(),
            chars: content.chars().count(),
        })
    }

    /// 退避した生出力を全文読み戻す。
    pub fn read_raw(&self, raw_ref: &RawRef) -> io::Result<String> {
        std::fs::read_to_string(self.path_for(&raw_ref.tool_call_id)?)
    }

    /// §6.3の遅延展開。`max_chars`を超える生出力は頭尾を残して中間を省略する
    /// （`harness_engine::turn`の大出力切詰めと同じ形。まず機械的に切り詰め、
    /// 意味的な抽出はDistillフェーズのLLMコールが行う＝§6.2の2段構え）。
    pub fn zoom(&self, raw_ref: &RawRef, max_chars: usize) -> io::Result<String> {
        Ok(harness_core::text::truncate_head_tail(
            &self.read_raw(raw_ref)?,
            max_chars,
        ))
    }

    /// `tool_call_id`をファイル名として安全に使えるか検査してからパスを組む。
    ///
    /// IDはプロバイダ由来の文字列（`call_abc123`等）で、ハーネスが生成した値ではない。
    /// `../`やドライブ指定を含むIDを渡されたら、`raw/`の外へ書き出せてしまう
    /// （`docs/SECURITY-PRINCIPLES.md`の「外来の文字列をパス要素にする前に検証する」）。
    fn path_for(&self, tool_call_id: &str) -> io::Result<PathBuf> {
        if tool_call_id.is_empty()
            || !tool_call_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsafe tool_call_id for a scratch file name: {tool_call_id:?}"),
            ));
        }
        Ok(self.raw_dir.join(format!("{tool_call_id}.txt")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, ScratchStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ScratchStore::open(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn session_directory_is_independent_of_the_staging_mode() {
        let dir = ScratchStore::dir_for_session(Path::new("C:/ws"), "session-42");
        // `.harness/sandbox/`（`--staged`/`--cow`でしか存在しない）ではなく専用ディレクトリ。
        assert!(dir.ends_with("session-42"));
        assert_eq!(
            dir,
            Path::new("C:/ws")
                .join(".harness")
                .join("cognition")
                .join("session-42")
        );
    }

    #[test]
    fn raw_output_round_trips_through_the_scratch_store() {
        let (_dir, store) = store();
        let raw = store.put_raw("call_1", "hello\nworld").unwrap();
        assert_eq!(raw.tool_call_id, "call_1");
        assert_eq!(raw.chars, 11);
        assert_eq!(store.read_raw(&raw).unwrap(), "hello\nworld");
    }

    /// `chars`は**文字数**であってバイト数ではない（予算はトークン概算＝文字数ベース）。
    #[test]
    fn char_count_is_not_byte_count_for_multibyte_output() {
        let (_dir, store) = store();
        let raw = store.put_raw("call_1", "日本語テスト").unwrap();
        assert_eq!(raw.chars, 6);
        assert_eq!(store.read_raw(&raw).unwrap().len(), 18); // bytes
    }

    /// §6.3: 巨大な生出力は`zoom`で必要な分だけ取り出す（既定のコールには載らない）。
    #[test]
    fn zoom_truncates_large_output_to_the_requested_size() {
        let (_dir, store) = store();
        let big = "x".repeat(10_000);
        let raw = store.put_raw("call_big", &big).unwrap();

        let zoomed = store.zoom(&raw, 200).unwrap();
        assert!(zoomed.chars().count() < 300, "{}", zoomed.chars().count());
        assert!(zoomed.contains("chars truncated"), "{zoomed}");
        // 全文はディスクに残っており、失われてはいない。
        assert_eq!(store.read_raw(&raw).unwrap().chars().count(), 10_000);
    }

    #[test]
    fn zoom_returns_small_output_verbatim() {
        let (_dir, store) = store();
        let raw = store.put_raw("call_1", "short").unwrap();
        assert_eq!(store.zoom(&raw, 200).unwrap(), "short");
    }

    /// プロバイダ由来の`tool_call_id`をそのままパス要素にすると、`raw/`の外へ
    /// 書き出せてしまう。検証してから組む。
    #[test]
    fn traversal_in_tool_call_id_is_rejected_instead_of_escaping_the_scratch_dir() {
        let (dir, store) = store();
        for evil in [
            "../escape",
            "..\\escape",
            "a/b",
            "C:\\Windows\\System32\\evil",
            "",
            "call 1",
        ] {
            let err = store.put_raw(evil, "payload").unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "accepted {evil:?}");
        }
        // 1件もファイルが作られていない。
        let created: Vec<_> = std::fs::read_dir(dir.path().join("raw")).unwrap().collect();
        assert!(created.is_empty());
    }

    #[test]
    fn normal_provider_ids_are_accepted() {
        let (_dir, store) = store();
        for ok in ["call_1", "toolu_01A2b3C4", "call-abc-123", "0"] {
            store.put_raw(ok, "payload").unwrap();
        }
    }
}
