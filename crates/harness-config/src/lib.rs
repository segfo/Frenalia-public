//! harness-config: 設定階層のマージ。`plans/DESIGN.md` §設定とシークレット参照。
//!
//! 既定（空）→ユーザ（`directories`の設定ディレクトリ配下`settings.json`）→プロジェクト
//! （`<project_root>/.harness/settings.json`）の順に`serde_json::Value`をディープマージしてから
//! `Settings`へデシリアライズする。CLIフラグとのマージ（最優先）は`harness-cli`側の責務
//! （フラグが`Some`ならそちらを使う、という素朴な上書きで足りるため、ここには含めない）。
//!
//! シークレット（APIキー等）は設計書の原則通りここでは一切扱わない（env優先、
//! `harness-cli`の`main()`が直接環境変数から読む）。設定ファイルが存在しない/パースできない
//! 場合はエラーにせず警告をstderrへ出して無視する（fail-fastはシークレット欠落時のみ）。

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    pub provider: Option<String>,
    pub model: Option<String>,
    pub permission_mode: Option<String>,
    pub allow: Option<Vec<String>>,
    pub max_tokens: Option<u32>,
    pub max_turns: Option<usize>,
    pub output_format: Option<String>,
    /// `true`ならTUI入力欄でEnterが送信（後方互換モード）。既定（`None`/`false`）では
    /// Shift+Enterが送信、素のEnterは改行を挿入する（§リッチTUI「入力ボックス」）。
    pub enter_submits: Option<bool>,
}

/// `<project_root>/.harness/settings.json`（呼び出し側は`project_root`に作業ディレクトリを渡す）。
fn project_settings_path(project_root: &Path) -> std::path::PathBuf {
    project_root.join(".harness").join("settings.json")
}

/// `directories::ProjectDirs`の設定ディレクトリ配下`settings.json`（Windowsは`%APPDATA%`、
/// mac/LinuxはXDG準拠、§設定とシークレット「ユーザ（`directories`: Windows `%APPDATA%`／
/// mac/Linux XDG）」）。
fn user_settings_path() -> Option<std::path::PathBuf> {
    directories::ProjectDirs::from("", "", "harness").map(|d| d.config_dir().join("settings.json"))
}

/// ファイルを読みJSONとしてパースする。存在しない場合は`Ok(None)`、存在するが読めない/
/// パースできない場合は警告をstderrへ出し`Ok(None)`として扱う（設定ファイルの欠如・破損で
/// 起動自体を止めない）。
fn read_json(path: &Path) -> Option<serde_json::Value> {
    if !path.exists() {
        return None;
    }
    match std::fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str(&text) {
            Ok(v) => Some(v),
            Err(e) => {
                eprintln!("warning: ignoring malformed settings file {}: {e}", path.display());
                None
            }
        },
        Err(e) => {
            eprintln!("warning: could not read settings file {}: {e}", path.display());
            None
        }
    }
}

/// `overlay`のキーで`base`を上書きするディープマージ。オブジェクト同士は再帰的にマージし、
/// それ以外（スカラー/配列）は`overlay`の値で丸ごと置き換える。
fn deep_merge(base: &mut serde_json::Value, overlay: serde_json::Value) {
    match (base, overlay) {
        (serde_json::Value::Object(base_map), serde_json::Value::Object(overlay_map)) => {
            for (k, v) in overlay_map {
                match base_map.get_mut(&k) {
                    Some(existing) => deep_merge(existing, v),
                    None => {
                        base_map.insert(k, v);
                    }
                }
            }
        }
        (base_slot, overlay_value) => {
            *base_slot = overlay_value;
        }
    }
}

impl Settings {
    /// 既定（空）→ユーザ→プロジェクトの順にマージする。`project_root`はワークスペースルート
    /// （`--cwd`解決後のディレクトリ）を渡す。
    pub fn load(project_root: &Path) -> Settings {
        let mut merged = serde_json::Value::Object(Default::default());

        if let Some(user_path) = user_settings_path() {
            if let Some(user_json) = read_json(&user_path) {
                deep_merge(&mut merged, user_json);
            }
        }
        if let Some(project_json) = read_json(&project_settings_path(project_root)) {
            deep_merge(&mut merged, project_json);
        }

        serde_json::from_value(merged).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_settings_override_user_settings_which_override_default() {
        let dir = tempfile::tempdir().unwrap();
        // このテストは`directories::ProjectDirs`のユーザ設定パス（テスト実行環境依存で
        // 触れられない）は使わず、`deep_merge`単体でマージ優先順位のみを検証する。
        let mut merged = serde_json::json!({ "model": "user-model", "max_turns": 10 });
        let project_override = serde_json::json!({ "model": "project-model" });
        deep_merge(&mut merged, project_override);

        let settings: Settings = serde_json::from_value(merged).unwrap();
        assert_eq!(settings.model.as_deref(), Some("project-model"));
        assert_eq!(settings.max_turns, Some(10));
        let _ = dir; // ディレクトリ自体は使わないが構造を保つため保持
    }

    #[test]
    fn load_falls_back_to_default_when_no_settings_files_exist() {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings::load(dir.path());
        assert_eq!(settings, Settings::default());
    }

    #[test]
    fn load_reads_project_settings_json() {
        let dir = tempfile::tempdir().unwrap();
        let harness_dir = dir.path().join(".harness");
        std::fs::create_dir_all(&harness_dir).unwrap();
        std::fs::write(
            harness_dir.join("settings.json"),
            r#"{"model": "from-project", "allow": ["read_file:*"]}"#,
        )
        .unwrap();

        let settings = Settings::load(dir.path());
        assert_eq!(settings.model.as_deref(), Some("from-project"));
        assert_eq!(settings.allow, Some(vec!["read_file:*".to_string()]));
    }
}
