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
    hash_bytes, now_millis, parse_ledger, ChangeOp, CowDeniedEntry, CowOpEntry,
    COW_BASELINE_DIRNAME, COW_DENIED_LEDGER_FILENAME, COW_OPS_LEDGER_FILENAME,
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

/// `baseline_hash_and_mirror`/`baseline_hash_and_mirror_ext`共通の実体。`ledger_key`は台帳での
/// 既存エントリ照合・`source_path`は実際に読みに行く先（workspace内相対解決済みの絶対パス、
/// またはworkspace外の絶対パスそのもの）、`mirror_key`はbaselineミラーの保存先（相対、`/`区切り）。
fn baseline_hash_and_mirror_from(
    upper_dir: &Path,
    ledger_key: &str,
    source_path: &Path,
    mirror_key: &str,
) -> Option<String> {
    if let Some(existing) = existing_baseline(upper_dir, ledger_key) {
        return existing;
    }
    let bytes = std::fs::read(source_path).ok()?;
    let mirror_path = upper_dir.join(COW_BASELINE_DIRNAME).join(mirror_key);
    if let Some(parent) = mirror_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&mirror_path, &bytes);
    Some(hash_bytes(&bytes))
}

/// `rel`のbaselineハッシュを解決する（設計書§19.5）。台帳に既存エントリがあればそれを権威として
/// 再利用し（baselineは「セッション開始時点の姿」を意味するため2回目以降も初回の値を複製する）、
/// 無ければ実workspace側の現在内容を読んでハッシュ化し、`<upper_dir>/.harness-cow-baseline/<rel>`
/// へ内容ミラーを書く（`resolve`の3-way merge材料）。実workspaceに存在しなければ`None`
/// （＝新規作成）。
pub fn baseline_hash_and_mirror(upper_dir: &Path, workspace_root: &Path, rel: &str) -> Option<String> {
    baseline_hash_and_mirror_from(upper_dir, rel, &workspace_root.join(rel), rel)
}

/// workspace外の絶対パス（`_ext`、Phase 3）向けのbaselineハッシュ解決。`original_path`は
/// 台帳へ記録する形（正規化済み絶対パス文字列、例`C:/Windows/probe.txt`）、`ext_key`は
/// `store::ext_key(original_path)`の結果（baselineミラーの保存先を`_ext/<ext_key>`にする、
/// content本体の保存先`_ext/<ext_key>`と同じ命名規則）。
pub fn baseline_hash_and_mirror_ext(
    upper_dir: &Path,
    original_path: &str,
    ext_key: &str,
) -> Option<String> {
    let mirror_key = format!("_ext/{ext_key}");
    baseline_hash_and_mirror_from(upper_dir, original_path, Path::new(original_path), &mirror_key)
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

/// workspace外絶対パス（`_ext`、Phase 3）のupper側実体パス（`<upper_dir>/_ext/<ext_key>`）。
/// `ext_key`は`ext_key()`の戻り値（ドライブレターのコロンを含まない相対キー）。
pub fn upper_ext_path_for(upper_dir: &Path, ext_key: &str) -> PathBuf {
    upper_dir.join("_ext").join(ext_key)
}

/// 絶対パス文字列を台帳の`path`フィールドで使う正規化形へ変換する（`\`→`/`のみ、
/// ドライブレターは保持、大文字小文字はそのまま）。`ext_key()`が返すキー
/// （ドライブレター・コロン無し、`_ext/`配下の実体パス用）とは別物なので混同しないこと。
pub fn normalize_abs_path(path: &str) -> String {
    path.replace('\\', "/")
}

/// Phase 4（設計書§19.8）: 拒否監査台帳（`<upper_dir>/.harness-cow-denied.jsonl`）へ1件
/// 追記する。DLL（書く側）とホスト側（読む側の`read_denied_log`、将来host側で拒否を検知する
/// 経路があれば書く側にもなり得る）が同じ型・同じファイルを共有する。
pub fn append_denied_entry(upper_dir: &Path, path: &str, access_mask: u32, pid: u32) {
    let entry = CowDeniedEntry {
        path: path.to_string(),
        access_mask,
        pid,
        ts_unix_millis: now_millis(),
    };
    let Ok(mut line) = serde_json::to_string(&entry) else {
        return;
    };
    line.push('\n');
    let denied_path = upper_dir.join(COW_DENIED_LEDGER_FILENAME);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&denied_path)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

/// 拒否監査台帳を読み、パース済みエントリを返す（無ければ空）。`harness cow audit`用。
pub fn read_denied_log(upper_dir: &Path) -> Vec<CowDeniedEntry> {
    let denied_path = upper_dir.join(COW_DENIED_LEDGER_FILENAME);
    let Ok(contents) = std::fs::read_to_string(&denied_path) else {
        return Vec::new();
    };
    contents
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
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

    #[test]
    fn baseline_hash_and_mirror_ext_reads_absolute_source_and_writes_mirror_under_ext_prefix() {
        let upper = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("probe.txt");
        std::fs::write(&target, b"outside-content").unwrap();
        let original = normalize_abs_path(&target.to_string_lossy());
        let key = ext_key(&original).unwrap();

        let hash = baseline_hash_and_mirror_ext(upper.path(), &original, &key);

        assert_eq!(hash, Some(hash_bytes(b"outside-content")));
        assert_eq!(
            std::fs::read(upper.path().join(COW_BASELINE_DIRNAME).join("_ext").join(&key)).unwrap(),
            b"outside-content"
        );
    }

    #[test]
    fn baseline_hash_and_mirror_ext_reuses_ledger_entry_by_original_path() {
        let upper = tempfile::tempdir().unwrap();
        append_entry(upper.path(), ChangeOp::Modify, "C:/Windows/probe.txt", Some("stale".to_string()));

        let hash = baseline_hash_and_mirror_ext(upper.path(), "C:/Windows/probe.txt", "c/Windows/probe.txt");

        assert_eq!(hash, Some("stale".to_string()));
    }

    #[test]
    fn upper_ext_path_for_nests_under_ext_dir() {
        let upper = PathBuf::from("upper");
        assert_eq!(
            upper_ext_path_for(&upper, "c/Windows/probe.txt"),
            PathBuf::from("upper/_ext/c/Windows/probe.txt")
        );
    }
}
