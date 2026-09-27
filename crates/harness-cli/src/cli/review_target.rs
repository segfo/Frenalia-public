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

/// `--session <id>`（省略時は最新）から、そのセッションが使ったオーバーレイ置き場を解決する。
/// `--staged`置き場（workspace内`.harness/sandbox/session-<id>`）を先に試し、無ければ
/// `--sandbox tier2a-cow`置き場（workspace外CoW 差分層ディレクトリ、Windows専用）を試す。
///
/// **「`session-<id>/`がある＝`--staged`のセッション」が成り立つのは、そこを作るのが
/// `--staged`だけだからである。** 監査ログの置き場は全セッションで作るが、名前が違う
/// （`audit-<id>/`、`session_scope::session_audit_dir`）。同じ名前にすると、CoWやLiveの
/// セッションまで`--staged`と読まれる。
/// どちらも見つからなければ`None`。
pub(crate) fn resolve_session_overlay_in(
    workspace_root: &Path,
    session: Option<&str>,
    cow_roots: &[PathBuf],
) -> Option<(StagingConfig, Option<PathBuf>)> {
    if let Some(sandbox_dir) = resolve_staged_overlay_dir(workspace_root, session) {
        if workspace_root.join(&sandbox_dir).exists() {
            return Some((
                StagingConfig {
                    mode: StagingMode::Staged,
                    sandbox_dir: Some(sandbox_dir),
                },
                None,
            ));
        }
    }
    if let Some(dir) = resolve_cow_diff_layer_dir_in(cow_roots, session) {
        return Some((StagingConfig::default(), Some(dir)));
    }
    None
}

/// `--staged`の置き場（workspace相対）。省略時は`session-*`の中で更新時刻が最新のもの。
///
/// **名前で絞る。** `.harness/sandbox/`には監査ログの置き場（`audit-*`）やポリシーエディタの
/// 記録（`policy-editor-*`）も並ぶ（`setup::sandbox_subdirs_named`のdoc）。
fn resolve_staged_overlay_dir(workspace_root: &Path, session: Option<&str>) -> Option<PathBuf> {
    if let Some(id) = session {
        return Some(sandbox_dir_for_session(&normalize_session_id(id)));
    }
    sandbox_subdirs_named(workspace_root, "session-")
        .into_iter()
        .max_by_key(|(_, t)| *t)
        .map(|(name, _)| sandbox_dir_for_session(&name))
}

#[cfg(test)]
#[path = "review_target_tests.rs"]
mod tests;
