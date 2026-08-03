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
    /// Alt+EnterまたはShift+Enterが送信、素のEnterは改行を挿入する（§リッチTUI「入力ボックス」）。
    pub enter_submits: Option<bool>,
    /// 読取スコープ設定（M11、`plans/DESIGN-SANDBOX.md` §5）。省略時は
    /// `ReadSettings::default()`（whitelist・外部ルート無し＝M10までと等価）。
    pub read: Option<ReadSettings>,
    /// 協調プロキシ設定（M12補遺、`plans/DESIGN-SANDBOX-PRIVSEP.md` §3.1 D-15）。省略時は
    /// `NetSettings::default()`（`allow_domains`空＝全拒否ポリシーを監査付きで起動）。
    pub net: Option<NetSettings>,
    /// Tier2a fs passthrough設定（D-13、`plans/DESIGN-SANDBOX-APPPOLICY.md`補遺）。省略時は
    /// `FsSettings::default()`（`allow`空＝追加ルート無し＝M12までと等価）。
    pub fs: Option<FsSettings>,
    /// `run_shell`子プロセス向けの非シークレット設定。省略時は
    /// `RunShellSettings::default()`（追加PATH無し＝従来通り）。
    pub run_shell: Option<RunShellSettings>,
    /// 認知レイヤー設定（M13〜、`plans/DESIGN-COGNITION.md` §2.3）。省略時は
    /// `CognitionSettings::default()`（`default_level`未指定＝`CognitionLevel`の既定）。
    pub cognition: Option<CognitionSettings>,
}

/// `.harness/settings.json`の`cognition`キー。
///
/// `plans/DESIGN-COGNITION.md` §8のデルタ表は`model_tiers`/`sources`も挙げるが、
/// それぞれ読む側（ModelRouter・SourceBroker）が実装されるM17/M16で追加する。
/// 設定だけ先に受け付けても黙って無視されるだけで、誤解を招くため。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CognitionSettings {
    /// `off` | `auto` | `always`。CLIの`--cognition`が指定されていればそちらが優先。
    pub default_level: Option<harness_core::CognitionLevel>,
    /// フェーズ別トークン予算の上書き（`plans/DESIGN-COGNITION.md` §3.3の表・§6.1）。
    /// 書かなかったフェーズは既定値のまま（`harness_cognition::PhaseBudgets`が部分上書きする）。
    ///
    /// ```jsonc
    /// "cognition": { "budgets": { "distill": { "max_in": 6000, "max_out": 800 } } }
    /// ```
    pub budgets: Option<std::collections::BTreeMap<harness_core::Phase, harness_core::TokenBudget>>,
}

/// `.harness/settings.json`の`run_shell`キー。シークレットenvの転送は禁止し、PATH追加だけを扱う。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RunShellSettings {
    /// clean envで継承したPATHへ追記するディレクトリ。例: `C:\\Users\\me\\.local\\bin`。
    pub path_extra: Option<Vec<String>>,
}

impl RunShellSettings {
    pub fn path_extra(&self) -> Vec<String> {
        self.path_extra.clone().unwrap_or_default()
    }
}

/// `.harness/settings.json`の`fs`キー（D-13、Tier2a fs passthrough allowlist）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FsSettings {
    /// 追加で許可するルート。各要素は`"<path>"`（read-only既定）または`"<path>:rw"`
    /// （書込も許可、明示opt-in）。CLIの`--fs-allow`と和集合でマージされる
    /// （`net.allow_apps`と同じ役割分担、絶対パス化は`harness-cli`側）。
    pub allow: Option<Vec<String>>,
    /// 読取だけを許可するルート。
    pub read: Option<Vec<String>>,
    /// 読取・書込を許可するルート。
    pub read_write: Option<Vec<String>>,
    /// 読取・実行を許可するルート。
    pub read_exec: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsAccess {
    Read,
    ReadWrite,
    ReadExec,
}

impl FsSettings {
    /// `fs.{read,read_write,read_exec}`と旧`fs.allow`を`(パス文字列, access)`へ変換する。
    /// 旧`fs.allow`は互換のため、`:rw`ならread_write、サフィックス無しなら従来の
    /// read+execute相当（read_exec）として扱う。
    pub fn to_fs_passthrough(&self) -> Vec<(String, FsAccess)> {
        let mut out = Vec::new();
        for path in self.read.clone().unwrap_or_default() {
            push_fs_entry(&mut out, path, FsAccess::Read);
        }
        for path in self.read_write.clone().unwrap_or_default() {
            push_fs_entry(&mut out, path, FsAccess::ReadWrite);
        }
        for path in self.read_exec.clone().unwrap_or_default() {
            push_fs_entry(&mut out, path, FsAccess::ReadExec);
        }
        for entry in self.allow.clone().unwrap_or_default() {
            match entry.strip_suffix(":rw") {
                Some(path) => push_fs_entry(&mut out, path.to_string(), FsAccess::ReadWrite),
                None => push_fs_entry(&mut out, entry, FsAccess::ReadExec),
            }
        }
        out
    }
}

fn push_fs_entry(out: &mut Vec<(String, FsAccess)>, path: String, access: FsAccess) {
    if let Some((_, existing)) = out.iter_mut().find(|(p, _)| p == &path) {
        *existing = merge_fs_access(*existing, access);
    } else {
        out.push((path, access));
    }
}

fn merge_fs_access(a: FsAccess, b: FsAccess) -> FsAccess {
    if a == FsAccess::ReadWrite || b == FsAccess::ReadWrite {
        FsAccess::ReadWrite
    } else if a == FsAccess::ReadExec || b == FsAccess::ReadExec {
        FsAccess::ReadExec
    } else {
        FsAccess::Read
    }
}

/// `.harness/settings.json`の`net`キー（M12補遺、D-15/D-10）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetSettings {
    /// 協調プロキシの許可ドメイン（`*.example.com`形式のサフィックスワイルドカード対応）。
    pub allow_domains: Option<Vec<String>>,
    /// アプリ単位network制御（軸1、D-10/D-11）の信頼アプリ名リスト（Tier2aで`internetClient`を
    /// 付与する先頭exe名。basename・拡張子除去・小文字で照合）。
    pub allow_apps: Option<Vec<String>>,
}

impl NetSettings {
    /// `harness_core::NetProxyConfig`へ変換する。
    pub fn to_net_proxy_config(&self) -> harness_core::NetProxyConfig {
        harness_core::NetProxyConfig {
            allow_domains: self.allow_domains.clone().unwrap_or_default(),
            domain_policy_enabled: true,
            enforced_by_wfp: false,
            audit_log_path: None,
            proxy_addr: None,
            fake_dns_addr: None,
            ..Default::default()
        }
    }

    /// `harness_core::NetAppPolicy`へ変換する（軸1、D-10/D-11）。
    pub fn to_net_app_policy(&self) -> harness_core::NetAppPolicy {
        harness_core::NetAppPolicy {
            allow_apps: self.allow_apps.clone().unwrap_or_default(),
        }
    }
}

/// `.harness/settings.json`の`read`キー（M11）。`harness_core::ReadScopeConfig`へ変換する前の
/// 生の設定値（パス文字列のまま、`~`展開等は行わない）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ReadSettings {
    /// `"whitelist"`（既定）/`"blacklist"`。未知の値・省略時はwhitelist扱い。
    pub mode: Option<String>,
    pub allow: Option<Vec<String>>,
    pub allow_descend: Option<Vec<String>>,
    pub deny: Option<Vec<String>>,
    pub deny_descend: Option<Vec<String>>,
}

impl ReadSettings {
    /// `harness_core::ReadScopeConfig`へ変換する（`allow`/`allow_descend`はパスとして解釈）。
    pub fn to_read_scope_config(&self) -> harness_core::ReadScopeConfig {
        let mode = match self.mode.as_deref() {
            Some("blacklist") => harness_core::ReadMode::Blacklist,
            _ => harness_core::ReadMode::Whitelist,
        };
        harness_core::ReadScopeConfig {
            mode,
            allow: self
                .allow
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(std::path::PathBuf::from)
                .collect(),
            allow_descend: self
                .allow_descend
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(std::path::PathBuf::from)
                .collect(),
            deny: self.deny.clone().unwrap_or_default(),
            deny_descend: self.deny_descend.clone().unwrap_or_default(),
        }
    }
}

/// `<project_root>/.harness/settings.json`（呼び出し側は`project_root`に作業ディレクトリを渡す）。
fn project_settings_path(project_root: &Path) -> std::path::PathBuf {
    project_root.join(".harness").join("settings.json")
}

const DEFAULT_PROJECT_SETTINGS: &str = r#"{
  "run_shell": {
    "path_extra": []
  },
  "net": {
    "allow_domains": [],
    "allow_apps": []
  },
  "fs": {
    "read": [],
    "read_write": [],
    "read_exec": []
  }
}
"#;

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
                eprintln!(
                    "warning: ignoring malformed settings file {}: {e}",
                    path.display()
                );
                None
            }
        },
        Err(e) => {
            eprintln!(
                "warning: could not read settings file {}: {e}",
                path.display()
            );
            None
        }
    }
}

pub fn ensure_project_settings_file(project_root: &Path) {
    let path = project_settings_path(project_root);
    if path.exists() {
        return;
    }
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!(
                "warning: could not create settings directory {}: {e}",
                parent.display()
            );
            return;
        }
    }
    if let Err(e) = std::fs::write(&path, DEFAULT_PROJECT_SETTINGS) {
        eprintln!(
            "warning: could not create default settings file {}: {e}",
            path.display()
        );
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
        ensure_project_settings_file(project_root);

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

    /// `cognition.default_level`は`CognitionLevel`のsnake_case表現をそのまま書ける
    /// （CLIの`--cognition`と同じ綴り）。キー自体が無ければ`None`のまま。
    #[test]
    fn parses_cognition_default_level() {
        let settings: Settings = serde_json::from_value(
            serde_json::json!({ "cognition": { "default_level": "always" } }),
        )
        .unwrap();
        assert_eq!(
            settings.cognition.unwrap().default_level,
            Some(harness_core::CognitionLevel::Always)
        );

        let empty: Settings = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(empty.cognition.is_none());
    }

    /// `cognition.budgets`はフェーズ名をキーに部分指定できる（書かなかったフェーズは
    /// `harness_cognition::PhaseBudgets`の既定表のまま）。
    #[test]
    fn parses_partial_cognition_budgets() {
        let settings: Settings = serde_json::from_value(serde_json::json!({
            "cognition": { "budgets": { "distill": { "max_in": 6000, "max_out": 800 } } }
        }))
        .unwrap();

        let budgets = settings.cognition.unwrap().budgets.unwrap();
        assert_eq!(budgets.len(), 1);
        assert_eq!(
            budgets[&harness_core::Phase::Distill],
            harness_core::TokenBudget {
                max_in: 6000,
                max_out: 800
            }
        );
    }

    /// 綴りを間違えたフェーズ名は黙って無視されず、パースエラーになる
    /// （黙って既定値で走ると「設定したのに効かない」に気付けない）。
    #[test]
    fn unknown_phase_name_in_budgets_is_rejected() {
        let parsed: Result<Settings, _> = serde_json::from_value(serde_json::json!({
            "cognition": { "budgets": { "distil": { "max_in": 6000, "max_out": 800 } } }
        }));
        assert!(
            parsed.is_err(),
            "typo in a phase name must not be silently ignored"
        );
    }

    #[test]
    fn load_creates_default_project_settings_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings::load(dir.path());
        assert!(project_settings_path(dir.path()).exists());
        assert_eq!(
            settings.run_shell.unwrap_or_default().path_extra(),
            Vec::<String>::new()
        );
        assert_eq!(
            settings.net.unwrap_or_default().allow_domains,
            Some(Vec::<String>::new())
        );
        assert_eq!(
            settings.fs.unwrap_or_default().read_exec,
            Some(Vec::<String>::new())
        );
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

    /// M11: `.harness/settings.json`の`read`キーが`ReadScopeConfig`へ正しく変換される
    /// （`plans/DESIGN-SANDBOX.md` §5.1の設定キー）。
    #[test]
    fn read_settings_parse_and_convert_to_read_scope_config() {
        let dir = tempfile::tempdir().unwrap();
        let harness_dir = dir.path().join(".harness");
        std::fs::create_dir_all(&harness_dir).unwrap();
        std::fs::write(
            harness_dir.join("settings.json"),
            r#"{"read": {"mode": "blacklist", "deny": [".ssh"], "deny_descend": ["node_modules", ".git"]}}"#,
        )
        .unwrap();

        let settings = Settings::load(dir.path());
        let read = settings.read.expect("read settings present");
        assert_eq!(read.mode.as_deref(), Some("blacklist"));

        let config = read.to_read_scope_config();
        assert_eq!(config.mode, harness_core::ReadMode::Blacklist);
        assert_eq!(config.deny, vec![".ssh".to_string()]);
        assert_eq!(
            config.deny_descend,
            vec!["node_modules".to_string(), ".git".to_string()]
        );
    }

    /// D-13: 新しい`fs.{read,read_write,read_exec}`と旧`fs.allow`互換が
    /// `(パス, access)`へ正しく変換される。
    #[test]
    fn fs_settings_parses_grouped_access_and_legacy_allow_entries() {
        let dir = tempfile::tempdir().unwrap();
        let harness_dir = dir.path().join(".harness");
        std::fs::create_dir_all(&harness_dir).unwrap();
        std::fs::write(
            harness_dir.join("settings.json"),
            r#"{
                "fs": {
                    "read": ["C:\\Users\\me\\notes"],
                    "read_write": ["C:\\Users\\me\\.cargo"],
                    "read_exec": ["C:\\Users\\me\\.local\\bin"],
                    "allow": ["C:\\Users\\me\\.cargo:rw", "C:\\Users\\me\\legacy-bin"]
                }
            }"#,
        )
        .unwrap();

        let settings = Settings::load(dir.path());
        let fs = settings.fs.expect("fs settings present");
        let passthrough = fs.to_fs_passthrough();
        assert_eq!(
            passthrough,
            vec![
                ("C:\\Users\\me\\notes".to_string(), FsAccess::Read),
                ("C:\\Users\\me\\.cargo".to_string(), FsAccess::ReadWrite),
                ("C:\\Users\\me\\.local\\bin".to_string(), FsAccess::ReadExec,),
                ("C:\\Users\\me\\legacy-bin".to_string(), FsAccess::ReadExec),
            ]
        );
    }

    #[test]
    fn run_shell_settings_parse_path_extra_alongside_net_domains() {
        let dir = tempfile::tempdir().unwrap();
        let harness_dir = dir.path().join(".harness");
        std::fs::create_dir_all(&harness_dir).unwrap();
        std::fs::write(
            harness_dir.join("settings.json"),
            r#"{
                "run_shell": { "path_extra": ["C:\\Users\\me\\.local\\bin"] },
                "net": { "allow_domains": ["example.com"] }
            }"#,
        )
        .unwrap();

        let settings = Settings::load(dir.path());
        assert_eq!(
            settings.run_shell.unwrap_or_default().path_extra(),
            vec!["C:\\Users\\me\\.local\\bin".to_string()]
        );
        assert_eq!(
            settings.net.unwrap_or_default().allow_domains,
            Some(vec!["example.com".to_string()])
        );
    }
}
