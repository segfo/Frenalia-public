//! workspace本体（`preflight`が毎回付与するRW/RO継承ACE）とCoW upper_dirの生存管理。
//!
//! 「今このworkspace/upper_dirを使っている他のharnessセッションが生きているか」の判定に、
//! プロセスIDを台帳へ書いて自分でliveness確認する方式ではなく、Windowsの**名前付きmutex**を
//! 使う。名前付きmutexは、作成したプロセスが（正常終了でもクラッシュでも）いなくなると
//! Windows自身が自動的にオブジェクトを破棄するため、「まだ誰かが開いているか」を
//! `OpenMutexW`で聞くだけでliveness確認ができ、PID生存確認のような手作業のロジックが要らない。
//!
//! workspaceには、アクセスモード別に名前を分けたmutexを用意する（`KNOWN_MODES`）。同じ
//! workspaceに対して異なるモード（例: 通常起動のRWXと`--cow`のRO）を同時に動かすと、
//! ACE（ファイルに1つしか付けられない）の意味がセッション間で食い違うため、`begin_workspace_mode`
//! が起動時に他モードの生存を確認し、生きていれば起動そのものを拒否する。
//!
//! CoW upper_dirはセッション専有なので、セッションIDを名前に含めたmutexを1つ持つだけでよい
//! （他モードとの衝突チェックは不要、生きているかどうかの確認にのみ使う）。
//!
//! この生存確認とは別に、`workspace-grant-ledger.json`へ「これまで許可を付けたことがある
//! workspaceパス」を記録する。こちらは`harness fs list`/`revoke-workspace-all`が対象を
//! 列挙するための一覧に過ぎず、安全性（撤収してよいか）の判定には使わない
//! （安全性は常にmutexで判定する）。

use std::path::{Path, PathBuf};

/// 現在サポートするworkspaceアクセスモード。将来`--cow_exec`（RX、読取+実行のみ許可）を
/// 追加する場合はここに`"rx"`を足すだけでよい（mutex名の分岐だけで衝突チェックが機能する）。
pub const KNOWN_MODES: &[&str] = &["rwx", "ro"];

/// パスをWindowsカーネルオブジェクト名として安全に使える文字列へ変換する（英数字以外は`_`）。
/// 呼び出し元は事前にcanonicalizeしたパスを渡すこと（大文字小文字・相対/絶対の違いによる
/// 意図しない別名化を防ぐため）。
fn sanitize_path_for_object_name(path: &Path) -> String {
    path.to_string_lossy()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn mode_mutex_name(path_key: &str, mode: &str) -> String {
    format!("Local\\harness-ws-{mode}-{path_key}")
}

fn setup_lock_name(path_key: &str) -> String {
    format!("Local\\harness-ws-setup-{path_key}")
}

/// `name`という名前付きmutexが現在誰かに保持されているか（＝生きたセッションが存在するか）。
fn mutex_exists(name: &str) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenMutexW, SYNCHRONIZATION_SYNCHRONIZE};
    let wide = crate::win_common::wide(name);
    unsafe {
        match OpenMutexW(
            SYNCHRONIZATION_SYNCHRONIZE,
            false,
            windows::core::PCWSTR(wide.as_ptr()),
        ) {
            Ok(h) => {
                let _ = CloseHandle(h);
                true
            }
            Err(_) => false,
        }
    }
}

/// `name`という名前付きmutexを作成（既に存在すれば単にハンドルを開くだけ）し、
/// **意図的に`CloseHandle`しない**。生のWin32 `HANDLE`はDropで自動closeされないため、
/// この関数を抜けた後もハンドルはプロセスが終了するまで有効なまま残る。プロセスが
/// 正常終了・クラッシュのいずれで消えても、Windowsがこのハンドルを自動的に閉じ、
/// 参照が0になったオブジェクト自体も破棄される——それが「このモード/セッションはもう
/// 使われていない」という合図になる。
fn hold_mutex_for_process_lifetime(name: &str) -> windows::core::Result<()> {
    use windows::Win32::System::Threading::CreateMutexW;
    let wide = crate::win_common::wide(name);
    unsafe {
        CreateMutexW(None, false, windows::core::PCWSTR(wide.as_ptr()))?;
    }
    Ok(())
}

/// `path`（canonicalize済み）に対して`mode`でのアクセスを開始してよいか確認し、よければ
/// そのモード専用のmutexを作ってプロセス終了まで保持する。他のモードが既に使用中なら
/// `Err`で理由を返し、呼び出し元（`preflight`）は起動を拒否する。
///
/// 「他モードの生存確認」と「自モードのmutex作成」の2手順は、`with_named_lock`（1個の
/// セットアップ用ロック）で挟んで直列化する。挟まないと、2つのharnessプロセスがほぼ同時に
/// 異なるモードで起動した場合、どちらも「他モードは無い」と同時に判定してしまいチェックを
/// すり抜ける（早い者勝ちの事故）。セットアップ用ロックは処理中だけ保持しすぐ解放され、
/// 長期保持するのは自モードのmutexだけになる。
pub fn begin_workspace_mode(path: &Path, mode: &str) -> Result<(), String> {
    debug_assert!(KNOWN_MODES.contains(&mode), "unknown workspace mode: {mode}");
    let key = sanitize_path_for_object_name(path);
    crate::with_named_lock(&setup_lock_name(&key), || {
        for other in KNOWN_MODES.iter().filter(|m| **m != mode) {
            if mutex_exists(&mode_mutex_name(&key, other)) {
                return Err(format!(
                    "workspace {} is already in use in '{other}' mode by another harness \
                     session; cannot start in '{mode}' mode concurrently (mixing access modes \
                     on the same workspace is not allowed)",
                    path.display()
                ));
            }
        }
        hold_mutex_for_process_lifetime(&mode_mutex_name(&key, mode))
            .map_err(|e| format!("failed to create workspace mode marker: {e}"))
    })
}

/// `path`について、いずれかのモードのmutexが今も生きているか（＝使用中のセッションが
/// あるか）。生きているモード名の一覧を返す（空なら安全に撤収してよい）。
pub fn live_modes(path: &Path) -> Vec<&'static str> {
    let key = sanitize_path_for_object_name(path);
    KNOWN_MODES
        .iter()
        .copied()
        .filter(|mode| mutex_exists(&mode_mutex_name(&key, mode)))
        .collect()
}

/// CoW upper_dirはセッション専有のため、セッションIDだけで名前が決まる。
fn cow_session_mutex_name(session_id: &str) -> String {
    format!("Local\\harness-cow-{session_id}")
}

/// `--cow`起動時に呼ぶ。セッション専用mutexを作ってプロセス終了まで保持する。
pub fn hold_cow_session_marker(session_id: &str) -> windows::core::Result<()> {
    hold_mutex_for_process_lifetime(&cow_session_mutex_name(session_id))
}

/// そのセッションのCoW upper_dirがまだ使用中（＝そのセッションのharnessプロセスが
/// 生きている）かどうか。
pub fn cow_session_is_live(session_id: &str) -> bool {
    mutex_exists(&cow_session_mutex_name(session_id))
}

// --- workspace一覧台帳（安全性判定には使わない、`fs list`/`revoke-workspace-all`用） ---

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WorkspaceLedgerEntry {
    pub path: String,
    pub mode: String,
    pub granted_at_unix_secs: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct WorkspaceLedger {
    pub entries: Vec<WorkspaceLedgerEntry>,
}

fn workspace_ledger_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "harness")
        .map(|d| d.config_dir().join("workspace-grant-ledger.json"))
}

pub fn load_workspace_ledger() -> WorkspaceLedger {
    let Some(path) = workspace_ledger_path() else {
        return WorkspaceLedger::default();
    };
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => WorkspaceLedger::default(),
    }
}

/// `traverse_ledger::write_ledger_file`と同じロジックの複製（誤削除防止の2層: read-only属性＋
/// `.bak`バックアップ）。各台帳が独立して自分の書込ヘルパを持つ既存の方針を踏襲する。
fn write_ledger_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if path.exists() {
        set_file_readonly(path, false);
        let backup_path = path.with_extension("json.bak");
        let _ = std::fs::copy(path, &backup_path);
    }
    if std::fs::write(path, contents).is_ok() {
        set_file_readonly(path, true);
    }
}

fn set_file_readonly(path: &Path, readonly: bool) {
    if let Ok(metadata) = std::fs::metadata(path) {
        let mut perms = metadata.permissions();
        perms.set_readonly(readonly);
        let _ = std::fs::set_permissions(path, perms);
    }
}

pub fn save_workspace_ledger(ledger: &WorkspaceLedger) {
    let Some(path) = workspace_ledger_path() else {
        return;
    };
    if let Ok(s) = serde_json::to_string_pretty(ledger) {
        write_ledger_file(&path, &s);
    }
}

/// `preflight`成功時に呼ぶ。台帳は一覧表示専用なので、既存エントリは単純に上書きする
/// （安全性判定には使わないため、モードの食い違い自体はここでは警告のみに留める）。
pub fn record_workspace_grant(path: &Path, mode: &str) {
    let mut ledger = load_workspace_ledger();
    let path_str = path.to_string_lossy().into_owned();
    let granted_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Some(entry) = ledger.entries.iter_mut().find(|e| e.path == path_str) {
        entry.mode = mode.to_string();
        entry.granted_at_unix_secs = granted_at;
    } else {
        ledger.entries.push(WorkspaceLedgerEntry {
            path: path_str,
            mode: mode.to_string(),
            granted_at_unix_secs: granted_at,
        });
    }
    save_workspace_ledger(&ledger);
}

pub fn remove_workspace_entry(path: &Path) {
    let mut ledger = load_workspace_ledger();
    let path_str = path.to_string_lossy().into_owned();
    ledger.entries.retain(|e| e.path != path_str);
    save_workspace_ledger(&ledger);
}

// --- CoW upper_dirのセッションメタデータ・列挙（`harness cow`サブコマンド用） ---

/// upper_dir直下に置く、セッションの由来（どのworkspaceのものか）を記録する小さなマーカー
/// ファイル。upper_dirがどこにあっても自己完結して読めるように、グローバル台帳ではなく
/// upper_dir自身の中に置く（台帳が壊れる/消えても`workspace_root`が分からなくならないため）。
pub const COW_SESSION_META_FILENAME: &str = ".harness-cow-session.json";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CowSessionMeta {
    pub session_id: String,
    pub workspace_root: String,
    pub created_at_unix_secs: u64,
}

/// `preflight`が`--cow`のupper_dir作成直後に呼ぶ。
pub fn write_cow_session_meta(upper_dir: &Path, workspace_root: &Path, session_id: &str) {
    let meta = CowSessionMeta {
        session_id: session_id.to_string(),
        workspace_root: workspace_root.to_string_lossy().into_owned(),
        created_at_unix_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    if let Ok(json) = serde_json::to_string_pretty(&meta) {
        let _ = std::fs::write(upper_dir.join(COW_SESSION_META_FILENAME), json);
    }
}

pub fn read_cow_session_meta(upper_dir: &Path) -> Option<CowSessionMeta> {
    let s = std::fs::read_to_string(upper_dir.join(COW_SESSION_META_FILENAME)).ok()?;
    serde_json::from_str(&s).ok()
}

/// CoW upper_dir群の共通の親ディレクトリ（`%LOCALAPPDATA%\harness\data\cow`）。
pub fn cow_upper_root() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "harness").map(|d| d.data_local_dir().join("cow"))
}

/// `cow_upper_root()`直下にある、これまでに作られた全セッションIDを列挙する（存在しなければ
/// 空）。
pub fn list_cow_sessions() -> Vec<String> {
    let Some(root) = cow_upper_root() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter_map(|e| e.file_name().into_string().ok())
        .collect()
}

/// `upper_dir`配下にあるファイルの相対パス一覧を返す（セッションメタファイル自身は除外する）。
/// upper_dirには実際に触られたファイルしか存在しないため、この一覧がそのままworkspace本体
/// に対する変更点になる。
pub fn list_cow_upper_files(upper_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_files_relative(upper_dir, upper_dir, &mut out);
    out
}

fn collect_files_relative(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_files_relative(root, &path, out);
        } else if file_type.is_file() {
            let name = path.file_name().and_then(|n| n.to_str());
            if name == Some(COW_SESSION_META_FILENAME)
                || name == Some(harness_change_ledger::COW_OPS_LEDGER_FILENAME)
            {
                continue;
            }
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(rel.to_path_buf());
            }
        }
    }
}

/// `upper_dir`直下の操作台帳（`.harness-cow-ops.jsonl`）を読み、現在の論理的な変更一覧を返す
/// （`harness changes --source cow`・apply/discardの入力）。再生ロジック自体は
/// `harness-change-ledger`の関数を呼ぶだけで、Redirector DLL初期化時の再生と同じコードを使う
/// （2つに分かれると挙動がずれるため、`plans/AppContainerベース Copy-on-Write ワークスペース
/// 設計書.md` §19.7参照）。台帳が無ければ空（変更なし）を返す。
pub fn read_cow_ledger(upper_dir: &Path) -> Vec<harness_change_ledger::CowChange> {
    let ledger_path = upper_dir.join(harness_change_ledger::COW_OPS_LEDGER_FILENAME);
    let Ok(contents) = std::fs::read_to_string(&ledger_path) else {
        return Vec::new();
    };
    let entries = harness_change_ledger::parse_ledger(&contents);
    harness_change_ledger::replay(&entries)
}

/// `apply`が実際にworkspace本体へ反映した`applied_paths`を台帳から取り除く（適用済みの
/// 変更が`harness changes --source cow`に永続的に残り続けるのを防ぐ、`overlay.rs`の
/// `prune_manifest`と同じ発想）。台帳が無ければ何もしない。
pub fn prune_cow_ledger(upper_dir: &Path, applied_paths: &[String]) -> std::io::Result<()> {
    let ledger_path = upper_dir.join(harness_change_ledger::COW_OPS_LEDGER_FILENAME);
    let Ok(contents) = std::fs::read_to_string(&ledger_path) else {
        return Ok(());
    };
    let entries = harness_change_ledger::parse_ledger(&contents);
    let mut out = String::new();
    for e in entries {
        if applied_paths.iter().any(|p| p == &e.path) {
            continue;
        }
        if let Ok(line) = serde_json::to_string(&e) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    std::fs::write(&ledger_path, out)
}
