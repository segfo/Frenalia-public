//! MCPサーバ宣言の型・検証・**承認ハッシュ**（`plans/DESIGN-MCP.md` §4）。
//!
//! このモジュールはI/Oを一切行わない。宣言は設定ファイル（`harness-config`）から来て、
//! 承認台帳との照合（[`crate::approval`]）と起動計画（[`crate::runtime`]）が使う。
//!
//! ## ハッシュ対象が「宣言の全体」である理由
//!
//! `DESIGN-MCP.md` §4.2は、承認の照合対象を **id・トランスポート種別・実行ファイル・引数・
//! 環境変数・per-tool RiskClass宣言・networkポリシー・workspace要求** と定める。承認は
//! 「この宣言を起動してよい」の記録であって「このサーバは安全である」の記録ではないので、
//! 起動されるプロセスの姿を決める要素が1つでも変われば別の宣言として扱い、再承認を求める。
//!
//! したがって[`McpServerDecl`]へフィールドを足すときは、[`McpServerDecl::approval_hash`]の
//! `Canonical`構造体へも必ず足すこと。**足し忘れると「承認済みの宣言を書き換えて別の挙動を
//! させる」経路になる**——`Canonical`を`..`無しで完全分解しているのはそのためで、
//! フィールドを足すとコンパイルエラーになる。

use std::collections::BTreeMap;

use harness_core::RiskClass;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// ツール名全体（`mcp__<server>__<tool>`）の上限。Anthropic/OpenAIのツール名は
/// `^[a-zA-Z0-9_-]{1,64}$`（`plans/DESIGN.md` §ツールシステム）。
pub const MAX_TOOL_NAME_LEN: usize = 64;

/// サーバidの上限。`harness.mcp.<session-token>.<server-id>`がAppContainerプロファイル名の
/// 64文字上限に収まるようにするための値でもある（接頭辞12 + トークン約16 + 区切り1 = 約29）。
pub const MAX_SERVER_ID_LEN: usize = 32;

/// ツール名の区切り。`DESIGN.md` §ツールシステム参照（`/`はプロバイダが受け付けない）。
pub const TOOL_NAME_PREFIX: &str = "mcp__";
pub const TOOL_NAME_SEPARATOR: &str = "__";

/// トランスポート種別（D-41）。既定はstdio。Streamable HTTPはM15.6で追加する。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTransportKind {
    #[default]
    Stdio,
}

/// サーバのworkspace要求（`DESIGN-MCP.md` §3.2）。既定は`None`＝ACEを一切付けない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpWorkspaceAccess {
    #[default]
    None,
    Read,
    ReadWrite,
}

/// サーバのnetwork要求（`DESIGN-MCP.md` §3.2）。既定は全拒否。
///
/// `allow_domains`が空でない場合、**そのサーバ専用の協調プロキシ**が1つ立ち、WFPはその
/// サーバのpackage SIDに対しそのプロキシのポートだけを許可する（§3.2の判断B）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpNetworkDecl {
    #[serde(default)]
    pub allow_domains: Vec<String>,
}

impl McpNetworkDecl {
    pub fn is_deny(&self) -> bool {
        self.allow_domains.is_empty()
    }
}

/// 1つのMCPサーバ宣言。設定ファイルの`mcp.servers[]`1件に対応する。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServerDecl {
    pub id: String,
    #[serde(default)]
    pub transport: McpTransportKind,
    /// 起動する実行ファイル。**ここに書かれたものをharnessがそのまま起動する**ので、
    /// 承認台帳（D-39）の照合対象の中核である。
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// サーバへ渡す追加環境変数。harness自身のenvは継承させない（clean env）。
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// per-tool `RiskClass`宣言（D-40）。**ここに無いツールは非readとして扱う**ので、
    /// 空でも宣言として妥当（すべてのツールがパーミッションゲートを通るだけ）。
    #[serde(default)]
    pub tools: BTreeMap<String, RiskClass>,
    #[serde(default)]
    pub network: McpNetworkDecl,
    #[serde(default)]
    pub workspace: McpWorkspaceAccess,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeclError {
    #[error("server id must be 1..={MAX_SERVER_ID_LEN} characters of [a-z0-9-]: {0:?}")]
    InvalidId(String),
    #[error("server {id:?} has an empty command")]
    EmptyCommand { id: String },
    #[error(
        "server {id:?} declares RiskClass for tool {tool:?}, but that name is not a valid MCP \
         tool name ([A-Za-z0-9_-], 1..=64 characters)"
    )]
    InvalidDeclaredToolName { id: String, tool: String },
    #[error(
        "server id {id:?} is too long to namespace tool {tool:?}: {TOOL_NAME_PREFIX}{id}\
         {TOOL_NAME_SEPARATOR}{tool} exceeds the {MAX_TOOL_NAME_LEN}-character provider limit"
    )]
    NamespacedNameTooLong { id: String, tool: String },
    #[error("duplicate server id: {0:?}")]
    DuplicateId(String),
}

/// サーバidとして妥当か（AppContainerプロファイル名・ツール名の両方の材料になる）。
pub fn is_valid_server_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_SERVER_ID_LEN
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// サーバが申告してきたツール名として妥当か。**サーバは未信頼**（`DESIGN-MCP.md` §2）なので、
/// `tools/list`の応答に入っている名前もここを通してから使う。
pub fn is_valid_mcp_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_TOOL_NAME_LEN
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// `mcp__<server>__<tool>`。プロバイダへ送るツール名であり、allowlistルール・承認プロンプト・
/// 監査ログでもこの表記を使う（`DESIGN.md` §ツールシステム）。
pub fn namespaced_tool_name(server_id: &str, tool: &str) -> String {
    format!("{TOOL_NAME_PREFIX}{server_id}{TOOL_NAME_SEPARATOR}{tool}")
}

impl McpServerDecl {
    /// 宣言そのものの妥当性を検査する（サーバとの通信前に行う）。
    pub fn validate(&self) -> Result<(), DeclError> {
        if !is_valid_server_id(&self.id) {
            return Err(DeclError::InvalidId(self.id.clone()));
        }
        if self.command.trim().is_empty() {
            return Err(DeclError::EmptyCommand {
                id: self.id.clone(),
            });
        }
        for tool in self.tools.keys() {
            if !is_valid_mcp_tool_name(tool) {
                return Err(DeclError::InvalidDeclaredToolName {
                    id: self.id.clone(),
                    tool: tool.clone(),
                });
            }
            self.check_namespaced_len(tool)?;
        }
        Ok(())
    }

    /// `mcp__<id>__<tool>`がプロバイダの64文字上限に収まるか。`tools/list`で初めて見る
    /// ツール名にも同じ検査を行うため公開する。
    pub fn check_namespaced_len(&self, tool: &str) -> Result<(), DeclError> {
        if namespaced_tool_name(&self.id, tool).len() > MAX_TOOL_NAME_LEN {
            return Err(DeclError::NamespacedNameTooLong {
                id: self.id.clone(),
                tool: tool.to_string(),
            });
        }
        Ok(())
    }

    /// このツールの`RiskClass`（D-40）。**宣言されたものだけがreadになり、無宣言は
    /// `Network`（＝非read）** として扱われ、パーミッションゲートを必ず通る。
    /// サーバ自身の申告（`readOnlyHint`等）は検証できないので参照しない。
    pub fn risk_for_tool(&self, tool: &str) -> RiskClass {
        self.tools
            .get(tool)
            .copied()
            .unwrap_or(RiskClass::Network)
    }

    /// 承認台帳と照合するハッシュ（`DESIGN-MCP.md` §4.2）。
    ///
    /// 正規化してからJSONへ落とし、SHA-256を16進で返す。`serde_json`のオブジェクトキー順は
    /// `BTreeMap`で決定的になり、`Vec`は宣言順を保つ（引数の順序は意味を持つため並べ替えない）。
    /// `allow_domains`だけは順序に意味が無いので並べ替え・重複除去してから含める——さもないと
    /// 同じポリシーの書き方違いで承認が失効する。
    pub fn approval_hash(&self) -> String {
        // 完全分解（`..`無し）。`McpServerDecl`へフィールドを足すとここがコンパイルエラーに
        // なり、ハッシュ対象への追加漏れ＝承認バイパスを防ぐ（モジュールdoc参照）。
        let McpServerDecl {
            id,
            transport,
            command,
            args,
            env,
            tools,
            network,
            workspace,
        } = self;

        let mut allow_domains: Vec<String> = network
            .allow_domains
            .iter()
            .map(|d| d.trim().to_ascii_lowercase())
            .collect();
        allow_domains.sort();
        allow_domains.dedup();

        #[derive(Serialize)]
        struct Canonical<'a> {
            id: &'a str,
            transport: &'a McpTransportKind,
            command: &'a str,
            args: &'a [String],
            env: &'a BTreeMap<String, String>,
            tools: &'a BTreeMap<String, RiskClass>,
            allow_domains: Vec<String>,
            workspace: &'a McpWorkspaceAccess,
        }

        let canonical = Canonical {
            id,
            transport,
            command,
            args,
            env,
            tools,
            allow_domains,
            workspace,
        };
        // `to_string`が失敗するのは`Serialize`実装がエラーを返す場合だけで、上の型は
        // すべてinfallible。それでもunwrapは避け、失敗時は決して既存の承認と一致しない
        // 値を返す（fail-closed）。
        let json = serde_json::to_string(&canonical)
            .unwrap_or_else(|_| format!("__unserializable__{id}"));
        let digest = Sha256::digest(json.as_bytes());
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// 承認プロンプト・`harness mcp list`が表示する宣言の全文。ユーザーはこれを見て
    /// 「起動してよいか」を判断するので、ハッシュ対象を1つ残らず出す。
    pub fn describe(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("  id:        {}\n", self.id));
        out.push_str(&format!("  transport: {:?}\n", self.transport));
        out.push_str(&format!("  command:   {}\n", self.command));
        out.push_str(&format!("  args:      {:?}\n", self.args));
        out.push_str("  env:\n");
        if self.env.is_empty() {
            out.push_str("    (none)\n");
        } else {
            for (k, v) in &self.env {
                out.push_str(&format!("    {k}={v}\n"));
            }
        }
        out.push_str("  tools (declared RiskClass; anything not listed is treated as non-read):\n");
        if self.tools.is_empty() {
            out.push_str("    (none declared -- every tool will go through the permission gate)\n");
        } else {
            for (k, v) in &self.tools {
                out.push_str(&format!(
                    "    {} -> {:?}\n",
                    namespaced_tool_name(&self.id, k),
                    v
                ));
            }
        }
        out.push_str(&format!(
            "  network:   {}\n",
            if self.network.is_deny() {
                "deny (no outbound sockets at all)".to_string()
            } else {
                format!(
                    "allow via a dedicated proxy: {}",
                    self.network.allow_domains.join(", ")
                )
            }
        ));
        out.push_str(&format!("  workspace: {:?}\n", self.workspace));
        out
    }
}

/// `.harness/settings.json`（およびユーザ設定）の`mcp`キー。
///
/// ```jsonc
/// "mcp": {
///   "servers": [
///     {
///       "id": "company-docs",
///       "command": "C:\\Program Files\\nodejs\\node.exe",
///       "args": ["C:\\mcp\\company-docs\\index.js"],
///       "tools": { "search": "read_only" },
///       "network": { "allow_domains": ["docs.example.com"] },
///       "workspace": "none"
///     }
///   ]
/// }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpSettings {
    #[serde(default)]
    pub servers: Vec<McpServerDecl>,
}

/// `harness-config`が運んできた生の`mcp`キーを解釈する。
///
/// **綴りを間違えた宣言を黙って無視しない**（`cognition.budgets`のフェーズ名と同じ方針）。
/// 「設定したのに効かない」に気付けないのは、MCPでは「裏取りしたつもりで裏取りしていない」に
/// 直結するため、パースエラーはそのまま返す。
pub fn parse_mcp_settings(value: Option<&serde_json::Value>) -> Result<Vec<McpServerDecl>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let settings: McpSettings = serde_json::from_value(value.clone())
        .map_err(|e| format!("invalid \"mcp\" section in settings.json: {e}"))?;
    Ok(settings.servers)
}

/// 宣言の集合を検証する（id重複はここで弾く。プロファイル名・ツール名が衝突するため）。
pub fn validate_all(decls: &[McpServerDecl]) -> Result<(), DeclError> {
    let mut seen = std::collections::BTreeSet::new();
    for decl in decls {
        decl.validate()?;
        if !seen.insert(decl.id.as_str()) {
            return Err(DeclError::DuplicateId(decl.id.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample() -> McpServerDecl {
        McpServerDecl {
            id: "company-docs".to_string(),
            transport: McpTransportKind::Stdio,
            command: "C:\\Program Files\\nodejs\\node.exe".to_string(),
            args: vec!["C:\\mcp\\docs\\index.js".to_string()],
            env: [("DOCS_ROOT".to_string(), "C:\\docs".to_string())]
                .into_iter()
                .collect(),
            tools: [("search".to_string(), RiskClass::ReadOnly)]
                .into_iter()
                .collect(),
            network: McpNetworkDecl {
                allow_domains: vec!["docs.example.com".to_string()],
            },
            workspace: McpWorkspaceAccess::None,
        }
    }

    #[test]
    fn valid_declaration_passes_validation() {
        assert_eq!(sample().validate(), Ok(()));
    }

    #[test]
    fn server_ids_are_restricted_to_profile_and_tool_name_safe_characters() {
        for bad in [
            "",
            "Company-Docs",
            "company docs",
            "company.docs",
            "company/docs",
            "company\\docs",
            &"x".repeat(MAX_SERVER_ID_LEN + 1),
        ] {
            assert!(!is_valid_server_id(bad), "should reject {bad:?}");
        }
        for good in ["a", "company-docs", "jira2", &"x".repeat(MAX_SERVER_ID_LEN)] {
            assert!(is_valid_server_id(good), "should accept {good:?}");
        }
    }

    /// サーバ申告のツール名も未信頼入力として検証する（`DESIGN-MCP.md` §2）。
    #[test]
    fn server_reported_tool_names_are_validated() {
        for bad in ["", "has space", "slash/name", "dot.name", &"x".repeat(65)] {
            assert!(!is_valid_mcp_tool_name(bad), "should reject {bad:?}");
        }
        for good in ["search", "create_issue", "list-things", "A1"] {
            assert!(is_valid_mcp_tool_name(good), "should accept {good:?}");
        }
    }

    #[test]
    fn namespaced_names_use_the_provider_safe_separator() {
        assert_eq!(
            namespaced_tool_name("company-docs", "search"),
            "mcp__company-docs__search"
        );
    }

    #[test]
    fn namespaced_names_over_the_provider_limit_are_rejected() {
        let mut decl = sample();
        decl.id = "x".repeat(MAX_SERVER_ID_LEN);
        let long_tool = "y".repeat(40);
        assert!(matches!(
            decl.check_namespaced_len(&long_tool),
            Err(DeclError::NamespacedNameTooLong { .. })
        ));
    }

    /// D-40: 宣言のあるツールだけがreadになり、無宣言は非read（＝ゲートを通る）。
    #[test]
    fn undeclared_tools_are_treated_as_non_read() {
        let decl = sample();
        assert_eq!(decl.risk_for_tool("search"), RiskClass::ReadOnly);
        assert_eq!(decl.risk_for_tool("delete_everything"), RiskClass::Network);
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let decls = vec![sample(), sample()];
        assert!(matches!(
            validate_all(&decls),
            Err(DeclError::DuplicateId(_))
        ));
    }

    #[test]
    fn hash_is_stable_across_calls() {
        let decl = sample();
        assert_eq!(decl.approval_hash(), decl.approval_hash());
    }

    /// **D-39の中核**: ハッシュ対象の7項目それぞれについて、1つ変えれば承認が失効する。
    #[test]
    fn every_hashed_field_changes_the_approval_hash() {
        let base = sample();
        let base_hash = base.approval_hash();

        let mut mutations: Vec<(&str, McpServerDecl)> = Vec::new();

        let mut m = base.clone();
        m.id = "other-docs".to_string();
        mutations.push(("id", m));

        let mut m = base.clone();
        m.command = "C:\\evil\\node.exe".to_string();
        mutations.push(("command", m));

        let mut m = base.clone();
        m.args.push("--inspect".to_string());
        mutations.push(("args", m));

        let mut m = base.clone();
        m.env.insert("NODE_OPTIONS".to_string(), "--require evil".to_string());
        mutations.push(("env", m));

        let mut m = base.clone();
        m.tools.insert("delete".to_string(), RiskClass::ReadOnly);
        mutations.push(("tools", m));

        let mut m = base.clone();
        m.network.allow_domains.push("evil.example.com".to_string());
        mutations.push(("network", m));

        let mut m = base.clone();
        m.workspace = McpWorkspaceAccess::ReadWrite;
        mutations.push(("workspace", m));

        for (label, mutated) in mutations {
            assert_ne!(
                mutated.approval_hash(),
                base_hash,
                "changing {label} must invalidate the approval"
            );
        }
    }

    /// トランスポート種別も対象（stdioで承認したものがHTTPで起動されない、D-41）。
    /// 現状バリアントが1つしか無いので、`Canonical`に`transport`が含まれていることを
    /// シリアライズ結果で確認する形で固定する。
    #[test]
    fn transport_kind_participates_in_the_hash() {
        let decl = sample();
        let json = serde_json::to_string(&decl).unwrap();
        assert!(json.contains("\"transport\":\"stdio\""), "{json}");
    }

    /// 許可ドメインは順序・大小文字・重複の書き方違いで承認が失効しない（正規化される）。
    #[test]
    fn allow_domain_ordering_and_case_do_not_invalidate_the_approval() {
        let mut a = sample();
        a.network.allow_domains = vec!["b.example.com".to_string(), "a.example.com".to_string()];
        let mut b = sample();
        b.network.allow_domains = vec![
            "A.example.com".to_string(),
            "b.example.com".to_string(),
            "a.example.com".to_string(),
        ];
        assert_eq!(a.approval_hash(), b.approval_hash());
    }

    /// 設定の`mcp`キーが最小の宣言から読める（既定値が効いている）。
    #[test]
    fn settings_parse_with_defaults_for_optional_keys() {
        let value = serde_json::json!({
            "servers": [ { "id": "docs", "command": "node.exe" } ]
        });
        let decls = parse_mcp_settings(Some(&value)).unwrap();
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].transport, McpTransportKind::Stdio);
        assert!(decls[0].args.is_empty());
        assert!(decls[0].network.is_deny());
        assert_eq!(decls[0].workspace, McpWorkspaceAccess::None);
        assert_eq!(decls[0].validate(), Ok(()));
    }

    #[test]
    fn a_missing_mcp_section_yields_no_servers() {
        assert!(parse_mcp_settings(None).unwrap().is_empty());
    }

    /// 綴り間違い・型違いは黙って無視されずエラーになる（「設定したのに効かない」を防ぐ）。
    #[test]
    fn a_malformed_mcp_section_is_an_error_rather_than_being_ignored() {
        let value = serde_json::json!({ "servers": [ { "id": "docs" } ] });
        assert!(parse_mcp_settings(Some(&value)).is_err(), "command is required");

        let value = serde_json::json!({ "servers": "not an array" });
        assert!(parse_mcp_settings(Some(&value)).is_err());

        let value = serde_json::json!({
            "servers": [ { "id": "docs", "command": "node.exe", "tools": { "search": "readonly" } } ]
        });
        assert!(
            parse_mcp_settings(Some(&value)).is_err(),
            "a misspelled RiskClass must not silently become non-read"
        );
    }

    #[test]
    fn empty_command_is_rejected() {
        let mut decl = sample();
        decl.command = "   ".to_string();
        assert!(matches!(decl.validate(), Err(DeclError::EmptyCommand { .. })));
    }
}
