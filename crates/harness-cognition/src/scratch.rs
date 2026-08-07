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

use crate::fsname::validate_id;
use crate::memory::types::RawRef;

/// 1セッション分のscratch領域。
#[derive(Debug, Clone)]
pub struct ScratchStore {
    raw_dir: PathBuf,
    /// `CensusEngine`の再開性を支える蒸留済みノート（`plans/PLAN-CENSUS-ENGINE.md`段階2）。
    /// `<item-id>.md`が既にあればその項目を飛ばせる——`notes/`だけで再開性が完結するので、
    /// `WorkingMemory`の永続化（M20）を待たずに入れられる。
    notes_dir: PathBuf,
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

    /// `dir`配下に`raw/`・`notes/`を作って開く。
    pub fn open(dir: &Path) -> io::Result<Self> {
        let raw_dir = dir.join("raw");
        std::fs::create_dir_all(&raw_dir)?;
        let notes_dir = dir.join("notes");
        std::fs::create_dir_all(&notes_dir)?;
        Ok(Self { raw_dir, notes_dir })
    }

    pub fn raw_dir(&self) -> &Path {
        &self.raw_dir
    }

    pub fn notes_dir(&self) -> &Path {
        &self.notes_dir
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

    /// `item_id`のノート（蒸留済み要約）が既にあるか。あれば`CensusEngine`はその項目の
    /// `Collect`/`Distill`を打たずに飛ばす（実測で見えた「同じファイルを5回読む」を
    /// 構造的に防ぐ）。
    pub fn note_exists(&self, item_id: &str) -> io::Result<bool> {
        Ok(self.note_path_for(item_id)?.exists())
    }

    /// 1項目ぶんのノートを書く。
    pub fn put_note(&self, item_id: &str, content: &str) -> io::Result<()> {
        std::fs::write(self.note_path_for(item_id)?, content)
    }

    /// `notes/`配下の全ノートをファイル名（＝item_id）昇順で返す。`Join`はこれだけを読み、
    /// `raw/`（生出力）には一切触れない。
    pub fn list_notes(&self) -> io::Result<Vec<(String, String)>> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&self.notes_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("md") {
                continue;
            }
            let Some(id) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let content = std::fs::read_to_string(&path)?;
            entries.push((id.to_string(), content));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(entries)
    }

    /// `tool_call_id`をファイル名として安全に使えるか検査してからパスを組む。
    ///
    /// IDはプロバイダ由来の文字列（`call_abc123`等）で、ハーネスが生成した値ではない。
    /// `../`やドライブ指定を含むIDを渡されたら、`raw/`の外へ書き出せてしまう
    /// （`docs/SECURITY-PRINCIPLES.md`の「外来の文字列をパス要素にする前に検証する」）。
    fn path_for(&self, tool_call_id: &str) -> io::Result<PathBuf> {
        validate_id(tool_call_id)?;
        Ok(self.raw_dir.join(format!("{tool_call_id}.txt")))
    }

    /// [`Self::path_for`]の`notes/`版。`item_id`は`PlanOutput.items[].id`由来
    /// （モデル生成のためハーネス側でサニタイズ済みだが、検証は共有経路のまま二重に行う）。
    fn note_path_for(&self, item_id: &str) -> io::Result<PathBuf> {
        validate_id(item_id)?;
        Ok(self.notes_dir.join(format!("{item_id}.md")))
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

    // --- notes/（`plans/PLAN-SURVEY-ENGINE.md`段階2） -------------------------------

    #[test]
    fn note_round_trips_and_is_detected_by_note_exists() {
        let (_dir, store) = store();
        assert!(!store.note_exists("item_1").unwrap());
        store.put_note("item_1", "## 要約\n\n事実A").unwrap();
        assert!(store.note_exists("item_1").unwrap());
        let notes = store.list_notes().unwrap();
        assert_eq!(notes, vec![("item_1".to_string(), "## 要約\n\n事実A".to_string())]);
    }

    /// `Join`はnotesをファイル名（＝item_id）昇順で読む。
    #[test]
    fn list_notes_is_sorted_by_item_id() {
        let (_dir, store) = store();
        store.put_note("item_3", "C").unwrap();
        store.put_note("item_1", "A").unwrap();
        store.put_note("item_2", "B").unwrap();
        let ids: Vec<String> = store
            .list_notes()
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert_eq!(ids, vec!["item_1", "item_2", "item_3"]);
    }

    /// `raw/`と同じ検証を`notes/`側でも通す（共有の`validate_id`）。
    #[test]
    fn traversal_in_item_id_is_rejected_instead_of_escaping_the_notes_dir() {
        let (dir, store) = store();
        for evil in ["../escape", "a/b", ""] {
            let err = store.put_note(evil, "payload").unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "accepted {evil:?}");
        }
        let created: Vec<_> = std::fs::read_dir(dir.path().join("notes")).unwrap().collect();
        assert!(created.is_empty());
    }
}
