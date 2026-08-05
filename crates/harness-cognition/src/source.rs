//! SourceBroker — 情報源カタログ。`plans/DESIGN-COGNITION.md` §4.2・§7.5。
//!
//! 内蔵ツール・MCP・webを**統一カタログ**にし、用途（`use_for`）と信頼度（`trust`）で
//! 横並びに評価する。MCPを「特別扱いしない」のが設計の肝で、この層から見れば
//! `mcp/company-docs/search_docs`は`read_file`と同じく「呼べる情報源のひとつ」でしかない。
//!
//! # 2つの表記
//!
//! MCPには**設定・カタログの表記**（`mcp/company-docs/search_docs`）と**登録されるツール名**
//! （`mcp__company-docs__search_docs`、[`MCP_PREFIX`]参照）の2つがある。前者は人が書く場所、
//! 後者はプロバイダのツール名の文字種制約に従う場所で、変換は[`SourceEntry::is_available`]と
//! [`split_mcp_tool_name`]が担う。
//!
//! # MCPクライアント（M15.5）に依存しない
//!
//! ここが見るのは[`ToolRegistry`]と**ツール名**だけである。したがって
//! [`SourceCatalog::available`]は「実際に登録されているツール」でカタログを絞るだけでよく、
//! MCPエントリはM15.5がツールを登録した瞬間に現れ、それまでは自然に落ちる。§4.2の
//! フォールバック（「MCPが未接続/失敗/未設定なら、ローカルファイル根拠のみで結論してよい」）が、
//! 分岐ではなく**データの有無**として表現されるということでもある。
//!
//! # 何を持たないか
//!
//! per-tool `RiskClass`宣言（D-40）は持たない。あれは`plans/DESIGN-MCP.md`が所有する機構で、
//! 認知層は`Tool::risk()`の結果に従うだけ（`crate::phase::ToolSelection`）。宣言済みreadだけが
//! Investigateで自動許可される、という結果はそれで既に満たされる。

use std::collections::BTreeSet;

use harness_tools::ToolRegistry;

use crate::memory::types::{SourceKind, SourceRef};
use crate::memory::validity::{Freshness, TrustLevel};

/// MCPツールの名前空間（`mcp__<server>__<tool>`）。
///
/// **正本は`harness_mcp::decl::{TOOL_NAME_PREFIX, TOOL_NAME_SEPARATOR}`**で、ここはその写しである。
/// `harness-mcp`へ依存しないのは、あれがWindowsで`harness-sandbox`（AppContainer隔離、D-38）を
/// 引き込むためで、認知レイヤーがサンドボックス層へ依存するとレイヤリングが崩れる
/// （`docs/INDEX.md`が「M16の依存は`harness-core`/`harness-engine`/`harness-tools`だけ」と
/// 定めており、M16をM15.5と並列に進められる理由そのものでもある）。
///
/// 写しが腐らないことは、両方へ依存する`harness-cli`側のドリフト検知テスト
/// （`crates/harness-cli/tests/mcp_namespace_drift.rs`）で担保する。
///
/// 区切りが`/`ではないのは、Anthropic/OpenAIともツール名の文字種が`^[a-zA-Z0-9_-]{1,64}$`で
/// `/`を受け付けないため（`plans/DESIGN.md` §ツールシステム）。
pub const MCP_PREFIX: &str = "mcp__";
/// サーバidとツール名の区切り。サーバidは`[a-z0-9-]`しか含まないので、
/// **最初の区切り**で切れば一意に分解できる（ツール名側は`_`を含んでよい）。
pub const MCP_SEPARATOR: &str = "__";

/// カタログ1件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEntry {
    /// 内蔵ツール名（`read_file`）、MCPサーバid（`mcp/company-docs`）、または
    /// MCPツールの完全名（`mcp/company-docs/search_docs`）。
    pub id: String,
    pub kind: SourceKind,
    /// 用途タグ。カタログに出る唯一の説明文なので、ここが空だとモデルは選べない。
    pub use_for: Vec<String>,
    pub trust: TrustLevel,
    pub freshness: Freshness,
}

impl SourceEntry {
    /// `settings.json`の`cognition.sources[]`（文字列だらけの生の宣言）から組む。
    ///
    /// 文字列の解釈をここへ置くのは、`harness-config`が「書かれたことをそのまま運ぶ」層で、
    /// 語彙の解釈は語彙を持つ側の責務だから（`ReadSettings::to_read_scope_config`と同じ形）。
    ///
    /// **未知の綴りは既定へ倒す**（エラーにしない）。設定の綴り間違いで認知レイヤーごと
    /// 止めるのは割に合わず、かつ`trust`の未知値を`High`扱いしないことが安全側の要点である
    /// （その保証は`harness_config::clamp_project_source_trust`と、ここの`default_trust`が持つ）。
    pub fn from_declaration(
        id: impl Into<String>,
        kind: Option<&str>,
        use_for: Vec<String>,
        trust: Option<&str>,
        freshness: Option<&str>,
    ) -> Self {
        let id = id.into();
        let kind = kind
            .and_then(parse_kind)
            // `kind`が無ければidから推測する（`mcp/...`ならMCP、内蔵ツール名なら種別既定）。
            .unwrap_or_else(|| infer_kind(&id));
        Self {
            trust: trust.and_then(parse_trust).unwrap_or(default_trust(kind)),
            freshness: freshness
                .and_then(parse_freshness)
                .unwrap_or(default_freshness(kind)),
            id,
            kind,
            use_for,
        }
    }

    /// この宣言が`tools`に登録されたツールで実際に呼べるか。
    ///
    /// サーバ単位の宣言（`mcp/company-docs`）は、その配下のツールが1つでも登録されていれば
    /// 呼べるとみなす——ユーザはサーバ単位で用途と信頼度を書きたいのが普通で、ツール名まで
    /// 列挙させるのは`DESIGN-MCP.md`側の承認台帳の仕事だから。
    fn is_available(&self, tools: &ToolRegistry) -> bool {
        if tools.get(&self.id).is_some() {
            return true;
        }
        if self.kind != SourceKind::Mcp {
            return false;
        }
        // ツール完全名の宣言（`mcp/company-docs/search_docs`）。
        if let Some(name) = self.mcp_tool_name() {
            if tools.get(&name).is_some() {
                return true;
            }
        }
        // サーバ単位の宣言（`mcp/company-docs`）。
        mcp_tool_prefix_for(&self.id)
            .is_some_and(|prefix| tools.iter().any(|t| t.name().starts_with(&prefix)))
    }

    /// ツール完全名の宣言なら、対応する登録名（`mcp__company-docs__search_docs`）。
    fn mcp_tool_name(&self) -> Option<String> {
        let rest = self.id.strip_prefix("mcp/")?;
        let (server, tool) = rest.split_once('/')?;
        (!server.is_empty() && !tool.is_empty())
            .then(|| format!("{MCP_PREFIX}{server}{MCP_SEPARATOR}{tool}"))
    }
}

/// 情報源カタログ。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceCatalog {
    entries: Vec<SourceEntry>,
}

impl SourceCatalog {
    /// 内蔵ツールの既定エントリだけを持つカタログ。
    ///
    /// **`trust`は種別から決まる**（§4.3「信頼度は情報源の宣言 + 種別から決める」）。
    /// ワークスペースの実ファイルとshell観測はharnessが直接観測した一次証拠なので`High`、
    /// webは第三者の主張なので`Low`（§4.2で補助扱い）。
    pub fn with_builtin_defaults() -> Self {
        let entry = |id: &str, kind: SourceKind, use_for: &[&str]| SourceEntry {
            id: id.to_string(),
            kind,
            use_for: use_for.iter().map(|s| (*s).to_string()).collect(),
            trust: default_trust(kind),
            freshness: default_freshness(kind),
        };
        Self {
            entries: vec![
                entry("read_file", SourceKind::File, &["ファイルの内容"]),
                entry("grep", SourceKind::File, &["コード内の記述の検索"]),
                entry("glob", SourceKind::File, &["ファイルの所在の確認"]),
                entry("run_shell", SourceKind::Shell, &["コマンド実行の結果"]),
                entry("web_fetch", SourceKind::Web, &["一般調査（補助）"]),
            ],
        }
    }

    /// 宣言を重ねる。同じidの既定エントリは**丸ごと置き換える**（部分上書きにしない）
    /// ——用途と信頼度は一体で意味を持つので、片方だけ既定が残ると読み手が誤解する。
    pub fn merged_with(mut self, declared: impl IntoIterator<Item = SourceEntry>) -> Self {
        for entry in declared {
            match self.entries.iter_mut().find(|e| e.id == entry.id) {
                Some(existing) => *existing = entry,
                None => self.entries.push(entry),
            }
        }
        self
    }

    pub fn entries(&self) -> &[SourceEntry] {
        &self.entries
    }

    /// **実際に呼べる**情報源だけを返す（このモジュールのdoc参照）。
    pub fn available<'a>(&'a self, tools: &ToolRegistry) -> Vec<&'a SourceEntry> {
        self.entries
            .iter()
            .filter(|e| e.is_available(tools))
            .collect()
    }

    /// 裏取りに使えるMCPが1つでもあるか（§4.2の接地優先順位2）。
    /// `false`なら`SingleSource`のまま結論してよく、その旨を回答へ明記する。
    pub fn has_mcp(&self, tools: &ToolRegistry) -> bool {
        self.available(tools)
            .iter()
            .any(|e| e.kind == SourceKind::Mcp)
    }

    /// まだ使っていない接地種別のうち、裏取りに使えるもの（§4.2のCrossSource示唆）。
    pub fn grounding_kinds_not_yet_used(
        &self,
        tools: &ToolRegistry,
        used: &BTreeSet<SourceKind>,
    ) -> BTreeSet<SourceKind> {
        self.available(tools)
            .iter()
            .map(|e| e.kind)
            .filter(|k| k.is_grounding() && !used.contains(k))
            .collect()
    }

    /// 証拠を積む時点の`trust`/`freshness`（§4.3「信頼度は情報源の宣言 + 種別から決める」）。
    /// 宣言があればそれ、無ければ種別の既定。
    pub fn validity_seed(&self, source: &SourceRef) -> (TrustLevel, Freshness) {
        let kind = source.kind();
        self.entry_for(source)
            .map(|e| (e.trust, e.freshness))
            .unwrap_or((default_trust(kind), default_freshness(kind)))
    }

    /// その出典に対応するカタログエントリ。MCPはツール完全名 → サーバidの順で探す
    /// （細かい宣言が粗い宣言に勝つ）。
    fn entry_for(&self, source: &SourceRef) -> Option<&SourceEntry> {
        let SourceRef::Mcp { server, tool, .. } = source else {
            // 内蔵ツールはツール名を持たない出典（`SourceRef::File`等）なので、
            // 種別が一致する最初の宣言を使う。
            let kind = source.kind();
            return self.entries.iter().find(|e| e.kind == kind);
        };
        // カタログのidは人が書く`/`区切りの表記（[`mcp_tool_prefix_for`]のdoc参照）。
        let full = format!("mcp/{server}/{tool}");
        let server_id = format!("mcp/{server}");
        self.entries
            .iter()
            .find(|e| e.id == full)
            .or_else(|| self.entries.iter().find(|e| e.id == server_id))
    }

    /// Investigateへ渡すカタログ（§4.2「使える情報源の一覧（id + use_for + trust）だけ」）。
    /// **中身は載せない**——載せるとこの節だけでフェーズ予算を食い潰す。
    pub fn render_for_investigate(&self, tools: &ToolRegistry) -> String {
        let available = self.available(tools);
        if available.is_empty() {
            return String::new();
        }
        let mut out = String::from("## 使える情報源\n\n");
        for e in available {
            let use_for = if e.use_for.is_empty() {
                "（用途の宣言なし）".to_string()
            } else {
                e.use_for.join(" / ")
            };
            out.push_str(&format!(
                "- `{}` — {use_for}（信頼度: {}）\n",
                e.id,
                e.trust.as_str()
            ));
        }
        out
    }
}

fn parse_kind(kind: &str) -> Option<SourceKind> {
    match kind {
        "file" => Some(SourceKind::File),
        "shell" => Some(SourceKind::Shell),
        "web" => Some(SourceKind::Web),
        "mcp" => Some(SourceKind::Mcp),
        "memory" => Some(SourceKind::Memory),
        _ => None,
    }
}

/// `kind`が書かれていないときにidから種別を推測する。
///
/// 推測できない未知のidは[`SourceKind::File`]ではなく[`SourceKind::Memory`]へ倒す
/// ——`File`は接地種別（`is_grounding`）なので、素性の分からない情報源が黙って確証の
/// 根拠になれてしまう。分からないものは弱い側へ倒すのが§4.3の姿勢である。
fn infer_kind(id: &str) -> SourceKind {
    if mcp_tool_prefix_for(id).is_some() {
        return SourceKind::Mcp;
    }
    match id {
        "read_file" | "grep" | "glob" => SourceKind::File,
        "run_shell" => SourceKind::Shell,
        "web_fetch" => SourceKind::Web,
        _ => SourceKind::Memory,
    }
}

fn parse_trust(trust: &str) -> Option<TrustLevel> {
    match trust {
        "high" => Some(TrustLevel::High),
        "medium" => Some(TrustLevel::Medium),
        "low" => Some(TrustLevel::Low),
        _ => None,
    }
}

fn parse_freshness(freshness: &str) -> Option<Freshness> {
    match freshness {
        "authoritative" => Some(Freshness::Authoritative),
        "fresh" => Some(Freshness::Fresh),
        "stale" => Some(Freshness::Stale),
        "unknown" => Some(Freshness::Unknown),
        _ => None,
    }
}

/// 種別から決まる既定の信頼度（宣言が無いとき）。
fn default_trust(kind: SourceKind) -> TrustLevel {
    match kind {
        // harnessが直接観測した一次証拠。
        SourceKind::File | SourceKind::Shell => TrustLevel::High,
        // 第三者プロセスだが、ユーザが起動を承認したもの（`DESIGN-MCP.md` §4）。
        SourceKind::Mcp => TrustLevel::Medium,
        // §4.2で補助扱い。単独では確証の根拠にならない。
        SourceKind::Web | SourceKind::Memory | SourceKind::ModelPrior => TrustLevel::Low,
    }
}

fn default_freshness(kind: SourceKind) -> Freshness {
    match kind {
        // このセッションで実際に観測したもの。
        SourceKind::File | SourceKind::Shell | SourceKind::Mcp => Freshness::Fresh,
        SourceKind::Web => Freshness::Unknown,
        // 長期記憶ノートは古い可能性があるので鵜呑みにしない（§7.4）。
        SourceKind::Memory => Freshness::Stale,
        SourceKind::ModelPrior => Freshness::Unknown,
    }
}

/// `mcp__<server>__<tool>`をサーバ名とツール名へ分解する。形が違えば`None`。
pub fn split_mcp_tool_name(name: &str) -> Option<(&str, &str)> {
    let rest = name.strip_prefix(MCP_PREFIX)?;
    let (server, tool) = rest.split_once(MCP_SEPARATOR)?;
    (!server.is_empty() && !tool.is_empty()).then_some((server, tool))
}

/// カタログのエントリid（`mcp/company-docs`）を、そのサーバのツール名の接頭辞
/// （`mcp__company-docs__`）へ直す。
///
/// **設定ファイルとカタログでは`/`区切りを使う**——人が書く場所であり、`mcp/company-docs`の方が
/// 「MCPサーバのcompany-docs」として読みやすい。プロバイダのツール名の制約（`[a-zA-Z0-9_-]`）は
/// モデルへ渡す名前にだけ掛かるもので、設定の表記まで縛る理由が無い。
fn mcp_tool_prefix_for(catalog_id: &str) -> Option<String> {
    let server = catalog_id
        .strip_prefix("mcp/")
        .or_else(|| catalog_id.strip_prefix(MCP_PREFIX))?
        .trim_end_matches('/');
    (!server.is_empty()).then(|| format!("{MCP_PREFIX}{server}{MCP_SEPARATOR}"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use harness_core::{RiskClass, Tool, ToolCtx, ToolError, ToolOutput};

    use super::*;

    /// テスト用のMCPツールの器。M15.5の実装がどうであれ、認知層から見えるのは
    /// **名前と`RiskClass`だけ**なので、これで全経路を通せる。
    pub(crate) struct StubTool {
        pub name: String,
        pub risk: RiskClass,
    }

    #[async_trait::async_trait]
    impl Tool for StubTool {
        fn name(&self) -> &str {
            &self.name
        }
        fn description(&self) -> &str {
            "stub"
        }
        fn input_schema(&self) -> serde_json::Value {
            serde_json::json!({ "type": "object", "properties": {}, "additionalProperties": false })
        }
        fn risk(&self, _input: &serde_json::Value) -> RiskClass {
            self.risk
        }
        async fn call(
            &self,
            _input: serde_json::Value,
            _ctx: &ToolCtx,
        ) -> Result<ToolOutput, ToolError> {
            Ok(ToolOutput {
                content: "stub".to_string(),
                is_error: false,
            })
        }
    }

    pub(crate) fn registry_with(names: &[(&str, RiskClass)]) -> ToolRegistry {
        let mut reg = ToolRegistry::with_builtin_tools();
        for (name, risk) in names {
            reg.register(Arc::new(StubTool {
                name: (*name).to_string(),
                risk: *risk,
            }));
        }
        reg
    }

    fn mcp_entry(id: &str, trust: TrustLevel) -> SourceEntry {
        SourceEntry {
            id: id.to_string(),
            kind: SourceKind::Mcp,
            use_for: vec!["社内仕様".to_string()],
            trust,
            freshness: Freshness::Authoritative,
        }
    }

    /// **M15.5を待たずに書ける理由そのもの**: 宣言されていても、ツールが登録されるまで
    /// カタログには出ない。
    #[test]
    fn a_declared_mcp_source_appears_only_once_its_tool_is_registered() {
        let catalog =
            SourceCatalog::with_builtin_defaults().merged_with([mcp_entry("mcp/company-docs", TrustLevel::High)]);

        let without = ToolRegistry::with_builtin_tools();
        assert!(!catalog.has_mcp(&without));
        let ids: Vec<&str> = catalog
            .available(&without)
            .iter()
            .map(|e| e.id.as_str())
            .collect();
        assert!(!ids.contains(&"mcp/company-docs"), "{ids:?}");
        assert!(ids.contains(&"read_file"), "{ids:?}");

        let with = registry_with(&[("mcp__company-docs__search_docs", RiskClass::ReadOnly)]);
        assert!(catalog.has_mcp(&with));
        assert!(catalog
            .available(&with)
            .iter()
            .any(|e| e.id == "mcp/company-docs"));
    }

    /// 未宣言の情報源も、内蔵ツールなら既定エントリで出る（カタログが空にならない）。
    #[test]
    fn builtin_sources_are_catalogued_without_any_declaration() {
        let catalog = SourceCatalog::with_builtin_defaults();
        let rendered = catalog.render_for_investigate(&ToolRegistry::with_builtin_tools());
        assert!(rendered.contains("read_file"), "{rendered}");
        assert!(rendered.contains("web_fetch"), "{rendered}");
        // **中身は載せない**（id・用途・信頼度の3つだけ）。
        assert!(!rendered.contains("description"), "{rendered}");
    }

    /// 宣言があれば種別既定より優先する（§4.3「情報源の宣言 + 種別から決める」）。
    #[test]
    fn a_declaration_overrides_the_kind_default() {
        let source = SourceRef::Mcp {
            server: "company-docs".to_string(),
            tool: "search_docs".to_string(),
            args_digest: "d".to_string(),
        };
        let bare = SourceCatalog::with_builtin_defaults();
        assert_eq!(
            bare.validity_seed(&source),
            (TrustLevel::Medium, Freshness::Fresh),
            "宣言が無ければ種別の既定"
        );

        let declared = bare.merged_with([mcp_entry("mcp/company-docs", TrustLevel::High)]);
        assert_eq!(
            declared.validity_seed(&source),
            (TrustLevel::High, Freshness::Authoritative)
        );
    }

    /// ツール完全名の宣言はサーバ単位の宣言に勝つ（細かい方が勝つ）。
    #[test]
    fn a_per_tool_declaration_wins_over_the_server_level_one() {
        let catalog = SourceCatalog::with_builtin_defaults().merged_with([
            mcp_entry("mcp/company-docs", TrustLevel::High),
            mcp_entry("mcp/company-docs/rumors", TrustLevel::Low),
        ]);
        let seed = catalog.validity_seed(&SourceRef::Mcp {
            server: "company-docs".to_string(),
            tool: "rumors".to_string(),
            args_digest: "d".to_string(),
        });
        assert_eq!(seed.0, TrustLevel::Low);
    }

    /// 同じidの再宣言は丸ごと置き換わる（用途と信頼度が混ざらない）。
    #[test]
    fn redeclaring_an_id_replaces_the_entry_entirely() {
        let catalog = SourceCatalog::with_builtin_defaults().merged_with([SourceEntry {
            id: "web_fetch".to_string(),
            kind: SourceKind::Web,
            use_for: vec!["公式ドキュメント".to_string()],
            trust: TrustLevel::Medium,
            freshness: Freshness::Fresh,
        }]);
        let entry = catalog
            .entries()
            .iter()
            .find(|e| e.id == "web_fetch")
            .unwrap();
        assert_eq!(entry.use_for, vec!["公式ドキュメント".to_string()]);
        assert_eq!(entry.trust, TrustLevel::Medium);
        assert_eq!(
            catalog.entries().iter().filter(|e| e.id == "web_fetch").count(),
            1
        );
    }

    /// 設定の生の宣言から組む。未知の綴りは既定へ倒し、エラーにしない。
    #[test]
    fn a_declaration_falls_back_to_kind_defaults_for_unknown_spellings() {
        let e = SourceEntry::from_declaration(
            "mcp/company-docs",
            Some("mcp"),
            vec!["社内仕様".to_string()],
            Some("ABSOLUTE"), // 未知の綴り
            None,
        );
        assert_eq!(e.kind, SourceKind::Mcp);
        // **未知の信頼度を`High`扱いしない**（種別既定のMediumへ倒す）。
        assert_eq!(e.trust, TrustLevel::Medium);
        assert_eq!(e.freshness, Freshness::Fresh);
    }

    /// `kind`を省いてもidから推測する。素性が分からないidは**接地種別にしない**。
    #[test]
    fn an_omitted_kind_is_inferred_from_the_id_and_unknown_ids_are_not_grounding() {
        let inferred = |id: &str| SourceEntry::from_declaration(id, None, vec![], None, None).kind;
        assert_eq!(inferred("mcp/company-docs"), SourceKind::Mcp);
        assert_eq!(inferred("read_file"), SourceKind::File);
        assert_eq!(inferred("run_shell"), SourceKind::Shell);
        assert_eq!(inferred("web_fetch"), SourceKind::Web);
        // 未知のidが黙って確証の根拠になれてはならない。
        assert!(!inferred("something-unknown").is_grounding());
    }

    /// CrossSourceの示唆: まだ使っていない接地種別だけを返す。
    #[test]
    fn cross_source_suggestions_exclude_the_kinds_already_used() {
        let catalog =
            SourceCatalog::with_builtin_defaults().merged_with([mcp_entry("mcp/company-docs", TrustLevel::High)]);
        let tools = registry_with(&[("mcp__company-docs__search_docs", RiskClass::ReadOnly)]);

        let used = BTreeSet::from([SourceKind::File]);
        let left = catalog.grounding_kinds_not_yet_used(&tools, &used);
        assert!(left.contains(&SourceKind::Mcp));
        assert!(!left.contains(&SourceKind::File));
        // webは接地種別ではないので裏取りの示唆に出ない（§4.2で補助扱い）。
        assert!(!left.contains(&SourceKind::Web));
    }

    /// 登録されるツール名の分解。サーバidは`[a-z0-9-]`だけなので**最初の区切りで切れば一意**で、
    /// ツール名側に`_`や`__`が入っていても壊れない。
    #[test]
    fn mcp_tool_names_split_into_server_and_tool() {
        assert_eq!(
            split_mcp_tool_name("mcp__company-docs__search_docs"),
            Some(("company-docs", "search_docs"))
        );
        assert_eq!(
            split_mcp_tool_name("mcp__jira__get__issue"),
            Some(("jira", "get__issue")),
            "ツール名側の区切りで切ってはならない"
        );
        for bad in [
            "read_file",
            "mcp__",
            "mcp__only-server",
            "mcp____tool",
            "mcp__s__",
            // 設定表記はツール名ではない（登録名としては受け取らない）。
            "mcp/company-docs/search_docs",
        ] {
            assert_eq!(split_mcp_tool_name(bad), None, "{bad}");
        }
    }

    /// 設定表記（`/`区切り）と登録されるツール名（`__`区切り）の対応。
    #[test]
    fn the_catalog_id_maps_onto_the_registered_tool_namespace() {
        assert_eq!(
            mcp_tool_prefix_for("mcp/company-docs").as_deref(),
            Some("mcp__company-docs__")
        );
        // 既に登録名の形で書かれていても受ける（人が書き間違えても落とさない）。
        assert_eq!(
            mcp_tool_prefix_for("mcp__company-docs").as_deref(),
            Some("mcp__company-docs__")
        );
        assert_eq!(mcp_tool_prefix_for("read_file"), None);
    }
}
