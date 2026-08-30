//! CoW 差分層ディレクトリへの実際の書込プロトコル（baseline記録・台帳追記・ext鍵写像）。
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

/// `<diff_layer_dir>/.harness-cow-ops.jsonl`を読み、パース済みエントリを返す（無ければ空）。
pub fn read_ledger_entries(diff_layer_dir: &Path) -> Vec<CowOpEntry> {
    let ledger_path = diff_layer_dir.join(COW_OPS_LEDGER_FILENAME);
    let Ok(contents) = std::fs::read_to_string(&ledger_path) else {
        return Vec::new();
    };
    parse_ledger(&contents)
}

/// `rel`（workspace相対、`/`区切り）が台帳に既に記録されたことがあれば、その最初のエントリの
/// `baseline_hash`を返す（＝「このセッションが最初に触った瞬間の実workspace側の内容」）。
/// 台帳を毎回読むため頻繁な呼び出し元（DLLのホットパス）はメモ化して呼ぶこと。
fn existing_baseline(diff_layer_dir: &Path, rel: &str) -> Option<Option<String>> {
    read_ledger_entries(diff_layer_dir)
        .into_iter()
        .find(|e| e.path == rel)
        .map(|e| e.baseline_hash)
}

/// `baseline_hash_and_mirror`/`baseline_hash_and_mirror_ext`共通の実体。`ledger_key`は台帳での
/// 既存エントリ照合・`source_path`は実際に読みに行く先（workspace内相対解決済みの絶対パス、
/// またはworkspace外の絶対パスそのもの）、`mirror_key`はbaselineミラーの保存先（相対、`/`区切り）。
fn baseline_hash_and_mirror_from(
    diff_layer_dir: &Path,
    ledger_key: &str,
    source_path: &Path,
    mirror_key: &str,
) -> Option<String> {
    if let Some(existing) = existing_baseline(diff_layer_dir, ledger_key) {
        return existing;
    }
    let bytes = std::fs::read(source_path).ok()?;
    let mirror_path = diff_layer_dir.join(COW_BASELINE_DIRNAME).join(mirror_key);
    if let Some(parent) = mirror_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&mirror_path, &bytes);
    Some(hash_bytes(&bytes))
}

/// `rel`のbaselineハッシュを解決する（設計書§19.5）。台帳に既存エントリがあればそれを権威として
/// 再利用し（baselineは「セッション開始時点の姿」を意味するため2回目以降も初回の値を複製する）、
/// 無ければ実workspace側の現在内容を読んでハッシュ化し、`<diff_layer_dir>/.harness-cow-baseline/<rel>`
/// へ内容ミラーを書く（`resolve`の3-way merge材料）。実workspaceに存在しなければ`None`
/// （＝新規作成）。
pub fn baseline_hash_and_mirror(
    diff_layer_dir: &Path,
    workspace_root: &Path,
    rel: &str,
) -> Option<String> {
    baseline_hash_and_mirror_from(diff_layer_dir, rel, &workspace_root.join(rel), rel)
}

/// workspace外の絶対パス（`_ext`、Phase 3）向けのbaselineハッシュ解決。`original_path`は
/// 台帳へ記録する形（正規化済み絶対パス文字列、例`C:/Windows/probe.txt`）、`ext_key`は
/// `store::ext_key(original_path)`の結果（baselineミラーの保存先を`_ext/<ext_key>`にする、
/// content本体の保存先`_ext/<ext_key>`と同じ命名規則）。
pub fn baseline_hash_and_mirror_ext(
    diff_layer_dir: &Path,
    original_path: &str,
    ext_key: &str,
) -> Option<String> {
    let mirror_key = format!("_ext/{ext_key}");
    baseline_hash_and_mirror_from(
        diff_layer_dir,
        original_path,
        Path::new(original_path),
        &mirror_key,
    )
}

/// 台帳（`<diff_layer_dir>/.harness-cow-ops.jsonl`）へ1エントリを追記する。1レコード＝1行を1回の
/// 追記書込みで出す（`OpenOptions::append`、Windowsでは`FILE_APPEND_DATA`扱い、設計書§19.2
/// 「追記の並行性」）。
pub fn append_entry(diff_layer_dir: &Path, op: ChangeOp, rel: &str, baseline_hash: Option<String>) {
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
    let ledger_path = diff_layer_dir.join(COW_OPS_LEDGER_FILENAME);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&ledger_path)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

/// 台帳を再生し、現在「論理的に削除済み」のパス集合を返す（`crate::deleted_paths`のfs版）。
pub fn deleted_set(diff_layer_dir: &Path) -> std::collections::HashSet<String> {
    crate::deleted_paths(&read_ledger_entries(diff_layer_dir))
}

/// 台帳を再生し、現在の論理的な変更一覧を返す（`crate::replay`のfs版、`harness changes`・
/// `apply`/`discard`の入力）。
pub fn replay_ledger(diff_layer_dir: &Path) -> Vec<crate::CowChange> {
    crate::replay(&read_ledger_entries(diff_layer_dir))
}

/// `rel`の差分層側実体パス（`<diff_layer_dir>/<rel>`）。
pub fn diff_layer_path_for(diff_layer_dir: &Path, rel: &str) -> PathBuf {
    diff_layer_dir.join(rel)
}

/// workspace外絶対パス（`_ext`、Phase 3）の差分層側実体パス（`<diff_layer_dir>/_ext/<ext_key>`）。
/// `ext_key`は`ext_key()`の戻り値（ドライブレターのコロンを含まない相対キー）。
pub fn diff_layer_ext_path_for(diff_layer_dir: &Path, ext_key: &str) -> PathBuf {
    diff_layer_dir.join("_ext").join(ext_key)
}

/// 絶対パス文字列を台帳の`path`フィールドで使う正規化形へ変換する（`\`→`/`のみ、
/// ドライブレターは保持、大文字小文字はそのまま）。`ext_key()`が返すキー
/// （ドライブレター・コロン無し、`_ext/`配下の実体パス用）とは別物なので混同しないこと。
pub fn normalize_abs_path(path: &str) -> String {
    path.replace('\\', "/")
}

/// Phase 4（設計書§19.8）: 拒否監査台帳（`<diff_layer_dir>/.harness-cow-denied.jsonl`）へ1件
/// 追記する。DLL（書く側）とホスト側（読む側の`read_denied_log`、将来host側で拒否を検知する
/// 経路があれば書く側にもなり得る）が同じ型・同じファイルを共有する。
pub fn append_denied_entry(diff_layer_dir: &Path, path: &str, access_mask: u32, pid: u32) {
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
    let denied_path = diff_layer_dir.join(COW_DENIED_LEDGER_FILENAME);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&denied_path)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

/// 拒否監査台帳を読み、パース済みエントリを返す（無ければ空）。`harness cow audit`用。
pub fn read_denied_log(diff_layer_dir: &Path) -> Vec<CowDeniedEntry> {
    let denied_path = diff_layer_dir.join(COW_DENIED_LEDGER_FILENAME);
    let Ok(contents) = std::fs::read_to_string(&denied_path) else {
        return Vec::new();
    };
    contents
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// diff_layer_dir配下にある「セッションの中身」ファイルを走査し、操作台帳のキー形
/// （workspace内は`/`区切りの相対パス、`_ext/<key>`配下は絶対パス文字列）で返す。
///
/// **なぜ台帳を読むだけで済ませないのか**（[BUG-066](../../../docs/bugs/BUG-066.md)）:
/// diff_layer_dirはサンドボックス子プロセスへRW付与されている（`preflight`の
/// `grant_ace_inheritable_rw(diff_layer_dir, diff_layer_cap)`。宛先は差分層ごとの
/// capability SIDだが、**子から書けるという事実はどちらでも変わらない**）ので、子は`copy_up`もフックも経由せず、
/// 差分層の絶対パスを直接指定してファイルを置ける。実際BUG-066では、モデルが`run_shell`から
/// `Set-Content <差分層>\merge-demo.txt`と書いたために差分層には編集後の内容があるのに台帳が
/// 空で、`harness changes`が「変更なし」と答え、`discard`すれば作業ごと消える状態になっていた。
/// Redirector DLLは境界ではない（D-01）＝フックが黙って素通りしても成立する可視性が要る。
/// **実体の走査だけが、書く側が何をしようと成立する**。
///
/// 除外するのはCoW自身の帳簿だけ（[`crate::COW_METADATA_PREFIX`]で始まる差分層直下の
/// ファイル・ディレクトリ）。ディレクトリ自体は返さない（空ディレクトリは変更として扱わない
/// ——台帳経由の`mkdir`は台帳側のエントリで表現される）。
pub fn scan_diff_layer_content_files(diff_layer_dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    collect_content_files(diff_layer_dir, diff_layer_dir, &mut out);
    out.sort();
    out
}

fn collect_content_files(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        // CoW自身の帳簿は差分層直下にしか置かれないので、直下の要素名だけを見る。
        if dir == root
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(crate::COW_METADATA_PREFIX))
        {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_content_files(root, &path, out);
        } else if file_type.is_file() {
            if let Some(key) = diff_layer_path_to_ledger_key(root, &path) {
                out.push(key);
            }
        }
    }
}

/// 差分層配下の実パスを操作台帳のキーへ写す（[`scan_diff_layer_content_files`]の1件分）。
/// `_ext/<key>`配下は[`ext_key`]の逆写像で絶対パスへ戻す。
fn diff_layer_path_to_ledger_key(root: &Path, path: &Path) -> Option<String> {
    let rel =
        crate::path_rules::relative_under_root(&path.to_string_lossy(), &root.to_string_lossy())?;
    if rel.is_empty() {
        return None;
    }
    match rel.strip_prefix("_ext/") {
        Some(ext) => ext_key_to_abs_path(ext),
        None => Some(rel),
    }
}

/// [`ext_key`]の逆写像。`c/Windows/probe.txt` → `c:/Windows/probe.txt`、
/// `etc/passwd` → `/etc/passwd`。
///
/// **ドライブ文字の大小は復元できない**（`ext_key`が小文字化するため）。台帳側のエントリと
/// 突き合わせるときは必ず`ext_key`空間で比較すること（`c:/...`と`C:/...`を文字列比較すると
/// 同じファイルを別物と誤認する）。Windowsのドライブ文字は大小を区別しないので、
/// `apply`が実FSを触る用途では小文字のままで支障はない。
fn ext_key_to_abs_path(key: &str) -> Option<String> {
    let mut parts = key.splitn(2, '/');
    let head = parts.next()?;
    let rest = parts.next().unwrap_or("");
    if head.len() == 1 && head.as_bytes()[0].is_ascii_alphabetic() {
        return Some(format!("{head}:/{rest}"));
    }
    Some(format!("/{key}"))
}

/// 台帳キーの突き合わせ用の正規形。`_ext`（絶対パス）は[`ext_key`]空間へ、workspace内は
/// 区切りを`/`へ揃えたうえで、**どちらも大小無視**にする（Windowsのパスは大小を区別せず、
/// 台帳の綴りはアプリが渡した文字列、走査の綴りは実FSのディレクトリエントリなので、
/// 同じファイルでも大小が食い違い得る）。
pub fn ledger_key_match_form(key: &str) -> String {
    let normalized = if Path::new(key).is_absolute() {
        ext_key(key).unwrap_or_else(|_| key.to_string())
    } else {
        key.replace('\\', "/")
    };
    normalized.to_ascii_lowercase()
}

/// baselineミラー（`<diff_layer_dir>/.harness-cow-baseline/<rel>`）の内容を読む
/// （`resolve`の`base`側材料・TUI変更パネルのdiffプレビュー用）。無ければ`None`
/// （baselineミラー導入前に発生したコンフリクト等）。
pub fn read_baseline_mirror(diff_layer_dir: &Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(diff_layer_dir.join(COW_BASELINE_DIRNAME).join(rel)).ok()
}

/// 差分層側の現在内容を読む（`resolve`の`mine`側材料・TUI変更パネルのdiffプレビュー用）。
pub fn read_overlay_content(diff_layer_dir: &Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(diff_layer_path_for(diff_layer_dir, rel)).ok()
}

/// **部分適用（ハンク単位apply）の後始末**: `rel`のbaselineを`new_workspace`（適用直後の実
/// workspace内容）へ張り替える。baselineミラーを書き直し、台帳から`rel`の行を全て落として、
/// 新しいハッシュを持つ`Modify`エントリを1件だけ入れ直す。
///
/// **なぜ追記だけでは足りないか**: [`crate::replay`]はパスごとに**最初の**エントリの
/// `baseline_hash`を権威として採る（baselineは「セッション開始時点の姿」を意味するため、
/// 2回目以降の書込みでも初回の値を保つ設計）。追記しても再生結果のbaselineは変わらないので、
/// 意図的に張り替えるにはprune＋再appendの2手が要る。
///
/// **なぜ張り替えるのか**: 部分適用は実workspace側の内容を自分で書き換える。baselineを
/// 元のままにしておくと、次に`apply`したとき「セッション中に第三者が実workspaceを編集した」
/// と誤検知して残りのハンクが永久に適用できなくなる（`plans/PLAN-VSCODE-REVIEW.md`
/// §部分適用後の台帳整合）。
pub fn rebase_baseline(diff_layer_dir: &Path, rel: &str, new_workspace: &[u8]) {
    let mirror_path = diff_layer_dir.join(COW_BASELINE_DIRNAME).join(rel);
    if let Some(parent) = mirror_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&mirror_path, new_workspace);
    prune_ledger(diff_layer_dir, std::slice::from_ref(&rel.to_string()));
    append_entry(
        diff_layer_dir,
        ChangeOp::Modify,
        rel,
        Some(hash_bytes(new_workspace)),
    );
}

/// `apply`/`resolve`が実際にworkspace本体へ反映した`applied_paths`を台帳から取り除く
/// （適用済みの変更が`change_set()`に永続的に残り続けるのを防ぐ）。台帳が無ければ何もしない。
pub fn prune_ledger(diff_layer_dir: &Path, applied_paths: &[String]) {
    let ledger_path = diff_layer_dir.join(COW_OPS_LEDGER_FILENAME);
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
/// workspace外の絶対パスを差分層内`_ext/`配下の一意な相対キーへ写像する（`overlay.rs::ext_key`の
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
        let diff_layer = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        let hash = baseline_hash_and_mirror(diff_layer.path(), ws.path(), "new.txt");
        assert_eq!(hash, None);
        assert!(!diff_layer
            .path()
            .join(COW_BASELINE_DIRNAME)
            .join("new.txt")
            .exists());
    }

    #[test]
    fn baseline_hash_and_mirror_reads_existing_workspace_file_and_writes_mirror() {
        let diff_layer = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("a.txt"), b"hello").unwrap();

        let hash = baseline_hash_and_mirror(diff_layer.path(), ws.path(), "a.txt");
        assert_eq!(hash, Some(hash_bytes(b"hello")));
        assert_eq!(
            std::fs::read(diff_layer.path().join(COW_BASELINE_DIRNAME).join("a.txt")).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn baseline_hash_and_mirror_reuses_ledger_entry_instead_of_recomputing() {
        let diff_layer = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("a.txt"), b"hello").unwrap();
        append_entry(
            diff_layer.path(),
            ChangeOp::Modify,
            "a.txt",
            Some("stale-hash".to_string()),
        );

        // 実workspace側は変わっていても、台帳に既存エントリがあればそれを権威として使う
        // （baselineは「セッション開始時点の姿」を意味し、2回目の呼び出しで再計算してはならない）。
        std::fs::write(ws.path().join("a.txt"), b"changed-since").unwrap();
        let hash = baseline_hash_and_mirror(diff_layer.path(), ws.path(), "a.txt");
        assert_eq!(hash, Some("stale-hash".to_string()));
    }

    #[test]
    fn rebase_baseline_replaces_the_authoritative_baseline_and_mirror() {
        let diff_layer = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("a.txt"), b"v1").unwrap();
        // セッション中の書込み（baselineは"v1"で確定する）。
        let baseline = baseline_hash_and_mirror(diff_layer.path(), ws.path(), "a.txt");
        append_entry(diff_layer.path(), ChangeOp::Modify, "a.txt", baseline);

        // 部分適用でworkspaceが"v2"になった。
        rebase_baseline(diff_layer.path(), "a.txt", b"v2");

        let changes = replay_ledger(diff_layer.path());
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].op, ChangeOp::Modify);
        assert_eq!(changes[0].baseline_hash, Some(hash_bytes(b"v2")));
        assert_eq!(
            std::fs::read(diff_layer.path().join(COW_BASELINE_DIRNAME).join("a.txt")).unwrap(),
            b"v2"
        );
    }

    #[test]
    fn appending_alone_would_not_move_the_baseline() {
        // `rebase_baseline`がprune＋再appendの2手を踏む理由（`replay`は最初のエントリの
        // baselineを権威とするので、追記だけでは張り替わらない）を明示的に固定する。
        let diff_layer = tempfile::tempdir().unwrap();
        append_entry(
            diff_layer.path(),
            ChangeOp::Modify,
            "a.txt",
            Some("first".into()),
        );
        append_entry(
            diff_layer.path(),
            ChangeOp::Modify,
            "a.txt",
            Some("second".into()),
        );
        assert_eq!(
            replay_ledger(diff_layer.path())[0].baseline_hash,
            Some("first".to_string())
        );
    }

    #[test]
    fn append_entry_then_replay_round_trips() {
        let diff_layer = tempfile::tempdir().unwrap();
        append_entry(diff_layer.path(), ChangeOp::Create, "a.txt", None);
        let changes = replay_ledger(diff_layer.path());
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "a.txt");
        assert_eq!(changes[0].op, ChangeOp::Create);
    }

    #[test]
    fn ext_key_maps_windows_drive_path() {
        assert_eq!(
            ext_key(r"C:\Windows\probe.txt").unwrap(),
            "c/Windows/probe.txt"
        );
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
        let diff_layer = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("probe.txt");
        std::fs::write(&target, b"outside-content").unwrap();
        let original = normalize_abs_path(&target.to_string_lossy());
        let key = ext_key(&original).unwrap();

        let hash = baseline_hash_and_mirror_ext(diff_layer.path(), &original, &key);

        assert_eq!(hash, Some(hash_bytes(b"outside-content")));
        assert_eq!(
            std::fs::read(
                diff_layer
                    .path()
                    .join(COW_BASELINE_DIRNAME)
                    .join("_ext")
                    .join(&key)
            )
            .unwrap(),
            b"outside-content"
        );
    }

    #[test]
    fn baseline_hash_and_mirror_ext_reuses_ledger_entry_by_original_path() {
        let diff_layer = tempfile::tempdir().unwrap();
        append_entry(
            diff_layer.path(),
            ChangeOp::Modify,
            "C:/Windows/probe.txt",
            Some("stale".to_string()),
        );

        let hash = baseline_hash_and_mirror_ext(
            diff_layer.path(),
            "C:/Windows/probe.txt",
            "c/Windows/probe.txt",
        );

        assert_eq!(hash, Some("stale".to_string()));
    }

    /// BUG-066: 台帳を経由せず差分層へ直接置かれたファイルも走査で見つかること。CoW自身の
    /// 帳簿（`.harness-cow-*`）だけが除外され、入れ子のディレクトリは掘って中身を拾う。
    #[test]
    fn scan_diff_layer_content_files_finds_direct_writes_and_skips_cow_metadata() {
        let diff_layer = tempfile::tempdir().unwrap();
        std::fs::write(
            diff_layer.path().join("direct.txt"),
            b"written without the ledger",
        )
        .unwrap();
        std::fs::create_dir_all(diff_layer.path().join("sub").join("deep")).unwrap();
        std::fs::write(
            diff_layer.path().join("sub").join("deep").join("nested.txt"),
            b"x",
        )
        .unwrap();
        // CoW自身の帳簿一式（除外される側）。
        append_entry(diff_layer.path(), ChangeOp::Create, "direct.txt", None);
        append_denied_entry(diff_layer.path(), "C:/outside/x.txt", 0x4000_0000, 42);
        std::fs::write(diff_layer.path().join(".harness-cow-session.json"), b"{}").unwrap();
        std::fs::write(diff_layer.path().join(".harness-cow-warnings.jsonl"), b"{}\n").unwrap();
        std::fs::write(diff_layer.path().join(".harness-cow-debug.log"), b"log").unwrap();
        std::fs::create_dir_all(diff_layer.path().join(COW_BASELINE_DIRNAME)).unwrap();
        std::fs::write(
            diff_layer.path().join(COW_BASELINE_DIRNAME).join("direct.txt"),
            b"baseline mirror",
        )
        .unwrap();

        let found = scan_diff_layer_content_files(diff_layer.path());

        assert_eq!(
            found,
            vec!["direct.txt".to_string(), "sub/deep/nested.txt".to_string()]
        );
    }

    /// `_ext/<key>`配下は絶対パス形の台帳キーへ逆写像される（`ext_key`の逆）。
    #[test]
    fn scan_diff_layer_content_files_maps_ext_entries_back_to_absolute_paths() {
        let diff_layer = tempfile::tempdir().unwrap();
        let ext_dir = diff_layer.path().join("_ext").join("c").join("outside");
        std::fs::create_dir_all(&ext_dir).unwrap();
        std::fs::write(ext_dir.join("probe.txt"), b"x").unwrap();

        let found = scan_diff_layer_content_files(diff_layer.path());

        assert_eq!(found, vec!["c:/outside/probe.txt".to_string()]);
    }

    /// 突き合わせは`ext_key`空間・大小無視で行う（ドライブ文字の大小差・実FSの綴り差で
    /// 「台帳にあるのに未記録」と誤判定しないため）。
    #[test]
    fn ledger_key_match_form_folds_case_and_ext_key_spelling() {
        assert_eq!(
            ledger_key_match_form("C:/Windows/Probe.txt"),
            ledger_key_match_form("c:/windows/probe.txt")
        );
        assert_eq!(
            ledger_key_match_form("Sub/A.TXT"),
            ledger_key_match_form("sub/a.txt")
        );
        assert_eq!(ledger_key_match_form(r"sub\a.txt"), "sub/a.txt");
    }

    #[test]
    fn diff_layer_ext_path_for_nests_under_ext_dir() {
        let diff_layer = PathBuf::from("diff_layer");
        assert_eq!(
            diff_layer_ext_path_for(&diff_layer, "c/Windows/probe.txt"),
            PathBuf::from("diff_layer/_ext/c/Windows/probe.txt")
        );
    }
}
