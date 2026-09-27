//! `harness changes`/`apply`/`discard`/`resolve`が**どのセッションの変更を対象にするか**を決める。
//!
//! 対象は2種類ある——`--staged`の置き場（ワークスペース内`.harness/sandbox/session-<id>/`）と、
//! CoWの差分層（ワークスペース外。根は`harness_sandbox::session_scope::cow_diff_layer_roots`）。
//!
//! # CoWの根を引数で受ける理由
//!
//! 差分層の根は実機の`%LOCALAPPDATA%`とボリュームごとの`.harness-cow`である。本番の根を
//! そのまま引く形にすると、テストは実機の差分層を読むことになり、`discard`を通すテストなら
//! **実機の差分層を消し得る**（`cargo test`が開発機の差分層を70件消した前例がある。
//! `startup::sandbox`の`sweep_empty_cow_diff_areas`のdoc）。だから根は呼び出し側が渡し、
//! 本番は[`production_cow_roots`]を、テストは一時フォルダを渡す。

use super::*;

/// 本番の差分層の根。CoWはWindows専用の機構なので、それ以外では空。
pub(crate) fn production_cow_roots() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        harness_sandbox::session_scope::cow_diff_layer_roots().0
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

/// `--session <id>`（省略時は最新）から、変更一覧の対象になるオーバーレイ置き場を解決する。
/// 対象は2種類——`--staged`の置き場（workspace内`.harness/sandbox/session-<id>/`）と、
/// CoWの差分層（workspace外、Windows専用）。どちらも見つからなければ`None`。
///
/// **「`session-<id>/`がある＝`--staged`のセッション」が成り立つのは、そこを作るのが
/// `--staged`だけだからである。** 監査ログの置き場は全セッションで作るが、名前が違う
/// （`audit-<id>/`、`session_scope::session_audit_dir`）。同じ名前にすると、CoWやLiveの
/// セッションまで`--staged`と読まれる。
///
/// # `--session`を省いたとき
///
/// **今のワークスペースのセッションだけ**から、stagedとCoWを合わせて更新時刻が最新のものを選び、
/// 選んだものをstderrへ出す。CoWの差分層はワークスペースの外にあるので、由来の記録
/// （`.harness-cow-session.json`）が今のワークスペースと一致するものだけを候補にする
/// ——由来が無い・読めないものも候補にしない。かつては全ワークスペースを通して最新の差分層を
/// 選んでいたので、別のリポジトリで後から作業すると、こちらの`apply`がそちらの変更を
/// こちらへ書き、`discard`がそちらの作業を消した。
///
/// # `--session`を指定したとき
///
/// そのIDの置き場を探す（別のワークスペースの差分層でも見つける。`apply`/`resolve`を
/// 拒否するかどうかは呼び出し側が[`diff_layer_origin`]で決める）。同じIDにstagedの置き場と
/// CoWの差分層の両方がある（別のモードで再開した）ときは、stagedに承認待ちがあれば
/// stagedを先に見せ、無ければCoWを選ぶ——常にstagedを選ぶと、空のstagedの置き場の陰で
/// CoWの変更に`--session`からは届かない。
pub(crate) fn resolve_session_overlay_in(
    workspace_root: &Path,
    session: Option<&str>,
    cow_roots: &[PathBuf],
) -> Option<(StagingConfig, Option<PathBuf>)> {
    match session {
        Some(id) => resolve_named_session(workspace_root, &normalize_session_id(id), cow_roots),
        None => resolve_latest_session(workspace_root, cow_roots),
    }
}

fn staged_target(session_id: &str) -> (StagingConfig, Option<PathBuf>) {
    (
        StagingConfig {
            mode: StagingMode::Staged,
            sandbox_dir: Some(sandbox_dir_for_session(session_id)),
        },
        None,
    )
}

fn cow_target(diff_layer_dir: PathBuf) -> (StagingConfig, Option<PathBuf>) {
    (StagingConfig::default(), Some(diff_layer_dir))
}

fn resolve_named_session(
    workspace_root: &Path,
    session_id: &str,
    cow_roots: &[PathBuf],
) -> Option<(StagingConfig, Option<PathBuf>)> {
    let staged_dir = workspace_root.join(sandbox_dir_for_session(session_id));
    let diff_layer = cow_diff_layer_dir_for_in(cow_roots, session_id);
    match (staged_dir.is_dir(), diff_layer) {
        (true, Some(diff_layer)) => {
            if staged_overlay_has_pending_operations(&staged_dir) {
                eprintln!(
                    "warning: session {session_id} also has a CoW diff layer ({}). Showing its \
                     staged changes first; apply or discard them to reach the diff layer.",
                    diff_layer.display()
                );
                Some(staged_target(session_id))
            } else {
                Some(cow_target(diff_layer))
            }
        }
        (true, None) => Some(staged_target(session_id)),
        (false, Some(diff_layer)) => Some(cow_target(diff_layer)),
        (false, None) => None,
    }
}

/// stagedの置き場に承認待ちの操作が残っているか（操作台帳が空でないか）。
///
/// `apply`は台帳を空にしてファイルを残す（`harness_change_ledger`の`prune`）ので、
/// 「置き場がある」だけでは承認待ちがあるとは言えない。
fn staged_overlay_has_pending_operations(staged_dir: &Path) -> bool {
    std::fs::metadata(staged_dir.join(harness_change_ledger::COW_OPS_LEDGER_FILENAME))
        .is_ok_and(|m| m.len() > 0)
}

fn resolve_latest_session(
    workspace_root: &Path,
    cow_roots: &[PathBuf],
) -> Option<(StagingConfig, Option<PathBuf>)> {
    let staged = sandbox_subdirs_named(workspace_root, "session-")
        .into_iter()
        .map(|(name, modified)| (modified, staged_target(&name), name));
    let cow = this_workspaces_diff_layers(workspace_root, cow_roots)
        .into_iter()
        .map(|(dir, modified)| {
            let name = dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            (modified, cow_target(dir), name)
        });
    let (_, target, name) = staged.chain(cow).max_by_key(|(modified, _, _)| *modified)?;
    let kind = if target.1.is_some() {
        "CoW diff layer"
    } else {
        "staged changes"
    };
    eprintln!(
        "note: no --session given; using the latest session in this workspace: {name} ({kind})"
    );
    Some(target)
}

/// 今のワークスペースの差分層を（場所, 更新時刻）で返す。由来が一致するものだけ。
/// `harness policy`（CoWの拒否ログ）も同じ候補から選ぶ。
pub(crate) fn this_workspaces_diff_layers(
    workspace_root: &Path,
    cow_roots: &[PathBuf],
) -> Vec<(PathBuf, std::time::SystemTime)> {
    diff_layers_in(cow_roots)
        .into_iter()
        .filter(|(dir, _)| diff_layer_origin(dir, workspace_root) == DiffLayerOrigin::ThisWorkspace)
        .collect()
}

/// 差分層がどのワークスペースのものか（差分層の`.harness-cow-session.json`と照合した結果）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DiffLayerOrigin {
    ThisWorkspace,
    /// 別のワークスペースのもの。記録されている綴りのまま持つ（案内に使う）。
    Other { recorded: String },
    /// 由来の記録が無い・読めない（どのワークスペースのものか確かめられない）。
    Unknown,
}

/// 差分層の由来を、今のワークスペースと照合する。
///
/// **比べる前に両側の綴りを揃える。** 由来を書く側が2つあり、綴りが揃っていない
/// ——`preflight`は`canonicalize`した`\?\C:\…`を、セッション切替（`session_scope`の
/// `prepare_cow_diff_layer`）は起動時に正規化しただけの`C:\…`を書く。両側を
/// `canonicalize`し（できなければ元の綴り）、台帳が使うのと同じ鍵
/// （`workspace_capability::workspace_key`: 大小・区切り・`\?\`を吸収）で比べる。
pub(crate) fn diff_layer_origin(diff_layer_dir: &Path, workspace_root: &Path) -> DiffLayerOrigin {
    #[cfg(windows)]
    {
        use harness_sandbox::tier2a::{workspace_capability::workspace_key, workspace_ledger};

        let read = workspace_ledger::read_cow_session_meta(diff_layer_dir);
        let Some(meta) = read.ok() else {
            return DiffLayerOrigin::Unknown;
        };
        let key = |p: &Path| workspace_key(&p.canonicalize().unwrap_or_else(|_| p.to_path_buf()));
        if key(Path::new(&meta.workspace_root)) == key(workspace_root) {
            DiffLayerOrigin::ThisWorkspace
        } else {
            DiffLayerOrigin::Other {
                recorded: meta.workspace_root.clone(),
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (diff_layer_dir, workspace_root);
        DiffLayerOrigin::Unknown
    }
}

#[cfg(test)]
#[path = "review_target_tests.rs"]
mod tests;
