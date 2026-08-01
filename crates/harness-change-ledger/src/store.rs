//! CoW upperディレクトリへの実際の書込プロトコル（baseline記録・台帳追記・ext鍵写像）。
//!
//! `crates/harness-redirector`（DLL、非信頼子プロセス側）と`harness-sandbox`（host内蔵ツール
//! `write_file`/`edit_file`側）の両方がこのモジュールの関数を呼ぶ。**同じbaselineハッシュ計算・
//! 同じ台帳追記形式を2箇所で別々に実装すると値がずれ、あらゆる適用が誤って「競合」判定される
//! 致命的なリスクがある**（`plans/AppContainerベース Copy-on-Write ワークスペース設計書.md`
//! §19、[BUG-042](../../../docs/bugs/BUG-042.md)の再発防止）ため、必ずここへ一本化する。
//!
//! DLL側は同一パスへの繰り返し操作を高速化するためプロセス内メモリキャッシュ（`baseline_cache`）
//! を持つが、その正しさの根拠は本モジュールの「台帳に既存エントリがあればそれを権威とする」
//! 判定にある（キャッシュは単なるメモ化で、無くても結果は変わらない）。

use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::{
    hash_bytes, now_millis, parse_ledger, ChangeOp, CowOpEntry, COW_BASELINE_DIRNAME,
    COW_OPS_LEDGER_FILENAME,
};

/// `<upper_dir>/.harness-cow-ops.jsonl`を読み、パース済みエントリを返す（無ければ空）。
pub fn read_ledger_entries(upper_dir: &Path) -> Vec<CowOpEntry> {
    let ledger_path = upper_dir.join(COW_OPS_LEDGER_FILENAME);
    let Ok(contents) = std::fs::read_to_string(&ledger_path) else {
        return Vec::new();
    };
    parse_ledger(&contents)
}

/// `rel`（workspace相対、`/`区切り）が台帳に既に記録されたことがあれば、その最初のエントリの
/// `baseline_hash`を返す（＝「このセッションが最初に触った瞬間の実workspace側の内容」）。
/// 台帳を毎回読むため頻繁な呼び出し元（DLLのホットパス）はメモ化して呼ぶこと。
fn existing_baseline(upper_dir: &Path, rel: &str) -> Option<Option<String>> {
    read_ledger_entries(upper_dir)
        .into_iter()
        .find(|e| e.path == rel)
        .map(|e| e.baseline_hash)
}

/// `rel`のbaselineハッシュを解決する（設計書§19.5）。台帳に既存エントリがあればそれを権威として
/// 再利用し（baselineは「セッション開始時点の姿」を意味するため2回目以降も初回の値を複製する）、
/// 無ければ実workspace側の現在内容を読んでハッシュ化し、`<upper_dir>/.harness-cow-baseline/<rel>`
/// へ内容ミラーを書く（`resolve`の3-way merge材料）。実workspaceに存在しなければ`None`
/// （＝新規作成）。
pub fn baseline_hash_and_mirror(upper_dir: &Path, workspace_root: &Path, rel: &str) -> Option<String> {
    if let Some(existing) = existing_baseline(upper_dir, rel) {
        return existing;
    }
    let workspace_abs = workspace_root.join(rel);
    let bytes = std::fs::read(&workspace_abs).ok()?;
    let mirror_path = upper_dir.join(COW_BASELINE_DIRNAME).join(rel);
    if let Some(parent) = mirror_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&mirror_path, &bytes);
    Some(hash_bytes(&bytes))
}

/// 台帳（`<upper_dir>/.harness-cow-ops.jsonl`）へ1エントリを追記する。1レコード＝1行を1回の
/// 追記書込みで出す（`OpenOptions::append`、Windowsでは`FILE_APPEND_DATA`扱い、設計書§19.2
/// 「追記の並行性」）。
pub fn append_entry(upper_dir: &Path, op: ChangeOp, rel: &str, baseline_hash: Option<String>) {
    let entry = CowOpEntry {
        op,
        path: rel.to_string(),
        baseline_hash,
        ts_unix_millis: now_millis(),
    };
    let Ok(mut line) = serde_json::to_string(&entry) else {
        return;
    };
    line.push('\n');
    let ledger_path = upper_dir.join(COW_OPS_LEDGER_FILENAME);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&ledger_path)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

/// 台帳を再生し、現在「論理的に削除済み」のパス集合を返す（`crate::deleted_paths`のfs版）。
pub fn deleted_set(upper_dir: &Path) -> std::collections::HashSet<String> {
    crate::deleted_paths(&read_ledger_entries(upper_dir))
}

/// 台帳を再生し、現在の論理的な変更一覧を返す（`crate::replay`のfs版、`harness changes`・
/// `apply`/`discard`の入力）。
pub fn replay_ledger(upper_dir: &Path) -> Vec<crate::CowChange> {
    crate::replay(&read_ledger_entries(upper_dir))
}

/// `rel`のupper側実体パス（`<upper_dir>/<rel>`）。
pub fn upper_path_for(upper_dir: &Path, rel: &str) -> PathBuf {
    upper_dir.join(rel)
}

/// baselineミラー（`<upper_dir>/.harness-cow-baseline/<rel>`）の内容を読む
/// （`resolve`の`base`側材料・TUI変更パネルのdiffプレビュー用）。無ければ`None`
/// （baselineミラー導入前に発生したコンフリクト等）。
pub fn read_baseline_mirror(upper_dir: &Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(upper_dir.join(COW_BASELINE_DIRNAME).join(rel)).ok()
}

/// upper側の現在内容を読む（`resolve`の`mine`側材料・TUI変更パネルのdiffプレビュー用）。
pub fn read_overlay_content(upper_dir: &Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(upper_path_for(upper_dir, rel)).ok()
}

/// `apply`/`resolve`が実際にworkspace本体へ反映した`applied_paths`を台帳から取り除く
/// （適用済みの変更が`change_set()`に永続的に残り続けるのを防ぐ）。台帳が無ければ何もしない。
pub fn prune_ledger(upper_dir: &Path, applied_paths: &[String]) {
    let ledger_path = upper_dir.join(COW_OPS_LEDGER_FILENAME);
    let Ok(contents) = std::fs::read_to_string(&ledger_path) else {
        return;
    };
    let mut out = String::new();
    for entry in parse_ledger(&contents) {
        if applied_paths.iter().any(|p| p == &entry.path) {
            continue;
        }
        if let Ok(line) = serde_json::to_string(&entry) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    let _ = std::fs::write(&ledger_path, out);
}

/// `C:\Windows\probe.txt` → `c/Windows/probe.txt`、`/etc/passwd` → `etc/passwd` のように、
/// workspace外の絶対パスをupper内`_ext/`配下の一意な相対キーへ写像する（`overlay.rs::ext_key`の
/// 移設、CoW一本化後はhost側・DLL側の両方が同じ写像を使う）。`..`混入・UNC前置は拒否する。
pub fn ext_key(path: &str) -> Result<String, String> {
    let normalized = path.replace('\\', "/");
    if normalized.starts_with("//") {
        return Err(format!("UNC path is not allowed: {path}"));
    }
    let bytes = normalized.as_bytes();
    if bytes.len() > 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/' {
        let drive = (bytes[0] as char).to_ascii_lowercase();
        let rest = &normalized[3..];
        if rest.split('/').any(|seg| seg == "..") {
            return Err(format!("path escape (..) is not allowed: {path}"));
        }
        return Ok(format!("{drive}/{rest}"));
    }
    if let Some(rest) = normalized.strip_prefix('/') {
        if rest.split('/').any(|seg| seg == "..") {
            return Err(format!("path escape (..) is not allowed: {path}"));
        }
        return Ok(rest.to_string());
    }
    Err(format!("not an absolute path: {path}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChangeOp;

    #[test]
    fn baseline_hash_and_mirror_is_none_for_new_file() {
        let upper = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        let hash = baseline_hash_and_mirror(upper.path(), ws.path(), "new.txt");
        assert_eq!(hash, None);
        assert!(!upper.path().join(COW_BASELINE_DIRNAME).join("new.txt").exists());
    }

    #[test]
    fn baseline_hash_and_mirror_reads_existing_workspace_file_and_writes_mirror() {
        let upper = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("a.txt"), b"hello").unwrap();

        let hash = baseline_hash_and_mirror(upper.path(), ws.path(), "a.txt");
        assert_eq!(hash, Some(hash_bytes(b"hello")));
        assert_eq!(
            std::fs::read(upper.path().join(COW_BASELINE_DIRNAME).join("a.txt")).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn baseline_hash_and_mirror_reuses_ledger_entry_instead_of_recomputing() {
        let upper = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("a.txt"), b"hello").unwrap();
        append_entry(upper.path(), ChangeOp::Modify, "a.txt", Some("stale-hash".to_string()));

        // 実workspace側は変わっていても、台帳に既存エントリがあればそれを権威として使う
        // （baselineは「セッション開始時点の姿」を意味し、2回目の呼び出しで再計算してはならない）。
        std::fs::write(ws.path().join("a.txt"), b"changed-since").unwrap();
        let hash = baseline_hash_and_mirror(upper.path(), ws.path(), "a.txt");
        assert_eq!(hash, Some("stale-hash".to_string()));
    }

    #[test]
    fn append_entry_then_replay_round_trips() {
        let upper = tempfile::tempdir().unwrap();
        append_entry(upper.path(), ChangeOp::Create, "a.txt", None);
        let changes = replay_ledger(upper.path());
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "a.txt");
        assert_eq!(changes[0].op, ChangeOp::Create);
    }

    #[test]
    fn ext_key_maps_windows_drive_path() {
        assert_eq!(ext_key(r"C:\Windows\probe.txt").unwrap(), "c/Windows/probe.txt");
    }

    #[test]
    fn ext_key_maps_unix_absolute_path() {
        assert_eq!(ext_key("/etc/passwd").unwrap(), "etc/passwd");
    }

    #[test]
    fn ext_key_rejects_parent_escape() {
        assert!(ext_key(r"C:\Windows\..\evil").is_err());
    }

    #[test]
    fn ext_key_rejects_unc_path() {
        assert!(ext_key(r"\\server\share\file").is_err());
    }
}
