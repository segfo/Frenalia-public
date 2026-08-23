//! `PermissionArbiter`。`plans/DESIGN.md` §パーミッション（承認）システム参照。
//!
//! §エージェントループが定める「唯一の強制点」の一部で、`run_agent_loop`が全ツール呼び出しの
//! 実行前に必ずここへ問い合わせる。M4時点はTUI（M7）が無いため対話経路
//! （未マッチをモーダル表示→oneshotで応答）は実装しておらず、`decide`は常に
//! 設計書「ヘッドレス時: モード+allowlistのみで判定、プロンプトになるものは既定で自動拒否」
//! と同じ規則で決定的に`Allow`/`Deny`を返す。
//!
//! M7で`PermissionGate` traitを追加した。`decide`が畳み込んでいた「モード+allowlistで
//! 自動判定できないケース（プロンプトすべきケース）」を`Classification::Prompt`として
//! 区別できるようにし（`classify`）、`PermissionGate`実装ごとにその扱いを変えられるようにした:
//! `PermissionArbiter`自身の実装（ヘッドレス）はPromptを自動`Deny`に畳み込み既存の`decide`と
//! バイト等価に振る舞う。`harness-tui`の対話ゲートはPromptで`AgentEvent::PermissionRequired`を
//! 発行しoneshot応答を待つ（§リッチTUI「承認ダイアログ」）。

use async_trait::async_trait;
use harness_core::RiskClass;

/// §パーミッション（承認）システム「モード」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionMode {
    /// read-onlyのみ。Write/Exec/Networkは自動拒否（ドライラン）。
    Plan,
    /// read-only自動許可。Write/Exec/Networkはプロンプト（ヘッドレスは自動拒否）。
    Default,
    /// fs書込は自動許可。shell/networkはプロンプト（ヘッドレスは自動拒否）。
    AcceptEdits,
    /// 全許可。`--dangerously-allow`明示必須（§非対話モード）。
    AcceptAll,
    /// 全拒否。
    Deny,
}

/// `PermissionArbiter::decide`の判定結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    AllowAndRemember,
    Deny,
    DenyAndRemember,
}

impl Decision {
    pub fn is_allow(self) -> bool {
        matches!(self, Decision::Allow | Decision::AllowAndRemember)
    }
}

/// allowlist の1件。`(tool, pattern)` の順序付きルール
/// （例 `run_shell:git status*`、`read_file:*`）。§パーミッション「接頭辞はツール名そのもの」。
///
/// M4時点は`*`終端の前方一致・完全一致のみをサポートする素朴な実装。
/// `run_shell`の実コマンド行を安全に分解するトークナイザ・`write_file`の`src/**`のような
/// globパターンはM5/M9のスコープ（設計書「危険パターン・ヒューリスティック」節）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowlistRule {
    pub tool: String,
    pub pattern: String,
}

impl AllowlistRule {
    pub fn new(tool: impl Into<String>, pattern: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            pattern: pattern.into(),
        }
    }

    fn matches(&self, tool: &str, arg: &str) -> bool {
        if self.tool != tool {
            return false;
        }
        if self.pattern == "*" {
            return true;
        }
        match self.pattern.strip_suffix('*') {
            Some(prefix) => arg.starts_with(prefix),
            None => arg == self.pattern,
        }
    }
}

/// `tool:pattern`形式の1行を`AllowlistRule`へパースする（CLIの`--allow`フラグ用）。
pub fn parse_allowlist_rule(rule: &str) -> Option<AllowlistRule> {
    let (tool, pattern) = rule.split_once(':')?;
    if tool.is_empty() || pattern.is_empty() {
        return None;
    }
    Some(AllowlistRule::new(tool, pattern))
}

/// `classify`の判定内訳。ヘッドレス既定の自動拒否（例: `Plan`/`Deny`モード）と、
/// 「対話ならユーザに尋ねるべきケース」（M4までは両方とも`Decision::Deny`に潰していた）を
/// 区別するために持つ（M7、§パーミッション「ヘッドレス時」対「対話時」の分岐）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    Allow,
    Deny,
    Prompt,
}

/// 全ツール呼び出しの実行前に必ず参照する唯一の強制点（§パーミッション）。
///
/// `Clone`は`census`ツール（`harness-cognition`）が内側の`TurnExecutor`用に
/// 同じポリシーの複製を持つために使う（`plans/PLAN-CENSUS-ENGINE.md`段階3）。
#[derive(Clone)]
pub struct PermissionArbiter {
    mode: PermissionMode,
    allowlist: Vec<AllowlistRule>,
}

impl PermissionArbiter {
    pub fn new(mode: PermissionMode, allowlist: Vec<AllowlistRule>) -> Self {
        Self { mode, allowlist }
    }

    /// `arg_repr`は許可判定に使う具体入力の文字列表現（`run_shell`ならコマンド行、
    /// `read_file`/`write_file`ならパス、他は入力全体のcompact JSON。§パーミッション
    /// 「allowlist: (tool, RiskClass, input)に対する順序付きルール」）。
    pub fn classify(&self, tool: &str, risk: RiskClass, arg_repr: &str) -> Classification {
        if self.mode == PermissionMode::Deny {
            return Classification::Deny;
        }
        if risk == RiskClass::ReadOnly {
            return Classification::Allow;
        }
        // Plan（ドライラン）はallowlistより優先して非read-onlyを常に拒否する
        // （「未信頼入力はread-onlyのwould-doを返しmutationゼロ」§多層防御 層9）。
        if self.mode == PermissionMode::Plan {
            return Classification::Deny;
        }
        // T-09（`plans/DESIGN-SANDBOX.md` §6.4）: allowlistのコマンド分解を無効化する構文
        // （`-EncodedCommand`・`iex`・`Start-Process`・`cmd /c`・入れ子インタプリタ等）を検出したら
        // allowlist一致・`AcceptAll`より前に強制的にPromptへ落とす（ヘッドレスは自動拒否）。
        // これは追加ブロックであり安全の根拠にはしない（本命はallowlistのコマンド分解+隔離Tier、
        // `base64`/`$IFS`等で自明に回避可能。§9残存リスク3）。
        if tool == "run_shell" && looks_like_allowlist_bypass(arg_repr) {
            return Classification::Prompt;
        }
        // D-05（`plans/DESIGN-SANDBOX.md` §7）: 設定注入パス（`.git/config`・
        // `.harness/**`等）へのwrite_file/edit_fileはmode/allowlistに関わらず常に拒否する
        // （層3 hard-deny、Tier1/Tier2b内でも解除しない。T-07/T-08対策）。allowlist一致・
        // AcceptAllより前に評価する（T-09と同じ「強制」パターン）。run_shellは対象外
        // （arg_reprがコマンド行のため誤爆する。D-06のgitハードニング+overlay apply時の
        // 再チェックが担当）。
        if (tool == "write_file" || tool == "edit_file")
            && harness_core::is_config_injection_path(arg_repr)
        {
            return Classification::Deny;
        }
        if self.mode == PermissionMode::AcceptAll {
            return Classification::Allow;
        }
        if self.allowlist.iter().any(|r| r.matches(tool, arg_repr)) {
            return Classification::Allow;
        }
        if self.mode == PermissionMode::AcceptEdits && risk == RiskClass::Write {
            return Classification::Allow;
        }
        // ヘッドレスは既定でここを自動拒否に畳み込む（`decide`）。対話ゲートは
        // ここでTUIモーダル→oneshot応答を待つ（`harness-tui`側の`PermissionGate`実装）。
        Classification::Prompt
    }

    /// ヘッドレス（TTY無し前提）向けの決定的判定。`Classification::Prompt`を自動`Deny`に
    /// 畳み込む（§パーミッション「ヘッドレス時: モード+allowlistのみで判定」）。
    pub fn decide(&self, tool: &str, risk: RiskClass, arg_repr: &str) -> Decision {
        match self.classify(tool, risk, arg_repr) {
            Classification::Allow => Decision::Allow,
            Classification::Deny | Classification::Prompt => Decision::Deny,
        }
    }

    /// 対話ゲートの`AllowAndRemember`応答をallowlistへ追記する（以降の同一`arg_repr`を
    /// 自動許可にする）。§パーミッション「allowlistへの追記」。
    pub fn remember_allow(&mut self, tool: impl Into<String>, arg_repr: impl Into<String>) {
        self.allowlist.push(AllowlistRule::new(tool, arg_repr));
    }

    /// 実行時にモードを切り替える（M9スラッシュコマンド`/mode`）。
    pub fn set_mode(&mut self, mode: PermissionMode) {
        self.mode = mode;
    }

    pub fn mode(&self) -> PermissionMode {
        self.mode
    }

    /// allowlistへ任意のルールを追記する（M9スラッシュコマンド`/allow`。`remember_allow`と
    /// 異なりTUIの承認応答経由でなく、ユーザが明示コマンドで追加する経路）。
    pub fn add_rule(&mut self, rule: AllowlistRule) {
        self.allowlist.push(rule);
    }
}

/// `/mode`スラッシュコマンド・`settings.json`/CLIの`--permission-mode`と共通の文字列表現。
impl std::str::FromStr for PermissionMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "plan" => Ok(PermissionMode::Plan),
            "default" => Ok(PermissionMode::Default),
            "accept-edits" => Ok(PermissionMode::AcceptEdits),
            "accept-all" => Ok(PermissionMode::AcceptAll),
            "deny" => Ok(PermissionMode::Deny),
            other => Err(format!(
                "unknown permission mode: {other} (expected plan|default|accept-edits|accept-all|deny)"
            )),
        }
    }
}

/// ツール実行前ゲートの抽象。`run_agent_loop`はこのtrait経由でのみ許可判定を行うため、
/// ヘッドレス（`PermissionArbiter`自身、常に決定的）と対話TUI（`harness-tui`の
/// interactiveゲート、`Classification::Prompt`でモーダル表示→oneshot応答待ち）を
/// 差し替えられる（§エージェントループ「唯一の強制点」、M7）。
#[async_trait]
pub trait PermissionGate: Send + Sync {
    async fn resolve(
        &self,
        tool: &str,
        risk: RiskClass,
        arg_repr: &str,
        input: &serde_json::Value,
    ) -> Decision;
}

/// ヘッドレス実装。`Classification::Prompt`を自動`Deny`に畳み込む`decide`をそのまま使う
/// ため、M4までの挙動とバイト等価。
#[async_trait]
impl PermissionGate for PermissionArbiter {
    async fn resolve(
        &self,
        tool: &str,
        risk: RiskClass,
        arg_repr: &str,
        _input: &serde_json::Value,
    ) -> Decision {
        self.decide(tool, risk, arg_repr)
    }
}

/// T-09（`plans/DESIGN-SANDBOX.md` §6.4）: `run_shell`のコマンド行がallowlistの
/// コマンド分解を無効化しようとする構文を含むかを大小無視・部分一致で検出する。
/// 検出は追加ブロックにすぎず、安全の根拠は隔離Tier（M12）側にある。
fn looks_like_allowlist_bypass(command: &str) -> bool {
    const MARKERS: &[&str] = &[
        "-encodedcommand",
        "invoke-expression",
        "iex ",
        "iex(",
        "start-process",
        "cmd /c",
        "cmd.exe /c",
        "eval ",
        "bash -c",
        "sh -c",
        "| sh",
        "| bash",
        "base64 -d",
        "base64 --decode",
        "certutil -decode",
    ];
    let lower = command.to_ascii_lowercase();
    MARKERS.iter().any(|m| lower.contains(m))
}

/// ツール入力から許可判定用の文字列表現を抜き出す。`command`/`path`フィールドがあれば
/// それを、無ければ入力全体をcompact JSON化したものを使う（§パーミッション補足）。
pub fn arg_repr(input: &serde_json::Value) -> String {
    if let Some(s) = input.get("command").and_then(|v| v.as_str()) {
        return s.to_string();
    }
    if let Some(s) = input.get("path").and_then(|v| v.as_str()) {
        return s.to_string();
    }
    input.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mode_allows_read_only_without_allowlist() {
        let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
        assert_eq!(
            arbiter.decide("read_file", RiskClass::ReadOnly, "Cargo.toml"),
            Decision::Allow
        );
    }

    #[test]
    fn default_mode_denies_unallowlisted_exec_headless() {
        let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
        assert_eq!(
            arbiter.decide("run_shell", RiskClass::Exec, "rm -rf /"),
            Decision::Deny
        );
    }

    #[test]
    fn allowlist_prefix_match_allows_exec() {
        let arbiter = PermissionArbiter::new(
            PermissionMode::Default,
            vec![AllowlistRule::new("run_shell", "git status*")],
        );
        assert_eq!(
            arbiter.decide("run_shell", RiskClass::Exec, "git status --short"),
            Decision::Allow
        );
        assert_eq!(
            arbiter.decide("run_shell", RiskClass::Exec, "git push"),
            Decision::Deny
        );
    }

    #[test]
    fn plan_mode_denies_write_even_if_allowlisted() {
        let arbiter = PermissionArbiter::new(
            PermissionMode::Plan,
            vec![AllowlistRule::new("write_file", "*")],
        );
        assert_eq!(
            arbiter.decide("write_file", RiskClass::Write, "src/main.rs"),
            Decision::Deny
        );
        assert_eq!(
            arbiter.decide("read_file", RiskClass::ReadOnly, "src/main.rs"),
            Decision::Allow
        );
    }

    #[test]
    fn accept_edits_allows_write_but_not_exec() {
        let arbiter = PermissionArbiter::new(PermissionMode::AcceptEdits, vec![]);
        assert_eq!(
            arbiter.decide("write_file", RiskClass::Write, "src/main.rs"),
            Decision::Allow
        );
        assert_eq!(
            arbiter.decide("run_shell", RiskClass::Exec, "cargo test"),
            Decision::Deny
        );
    }

    #[test]
    fn accept_all_allows_everything() {
        let arbiter = PermissionArbiter::new(PermissionMode::AcceptAll, vec![]);
        assert_eq!(
            arbiter.decide("run_shell", RiskClass::Exec, "rm -rf /"),
            Decision::Allow
        );
    }

    #[test]
    fn deny_mode_denies_even_read_only() {
        let arbiter = PermissionArbiter::new(PermissionMode::Deny, vec![]);
        assert_eq!(
            arbiter.decide("read_file", RiskClass::ReadOnly, "Cargo.toml"),
            Decision::Deny
        );
    }

    #[test]
    fn allowlist_bypass_syntax_forces_prompt_even_under_accept_all() {
        let arbiter = PermissionArbiter::new(
            PermissionMode::AcceptAll,
            vec![AllowlistRule::new("run_shell", "*")],
        );
        // ヘッドレスの`decide`はPromptを自動Denyへ畳み込む（§パーミッション「ヘッドレス時」）。
        assert_eq!(
            arbiter.classify(
                "run_shell",
                RiskClass::Exec,
                "powershell -EncodedCommand abc"
            ),
            Classification::Prompt
        );
        assert_eq!(
            arbiter.classify(
                "run_shell",
                RiskClass::Exec,
                "git status | Invoke-Expression"
            ),
            Classification::Prompt
        );
        assert_eq!(
            arbiter.classify("run_shell", RiskClass::Exec, "echo hi | sh"),
            Classification::Prompt
        );
    }

    #[test]
    fn allowlist_bypass_syntax_does_not_affect_other_tools() {
        let arbiter = PermissionArbiter::new(PermissionMode::AcceptAll, vec![]);
        // 検出は`run_shell`限定。他ツールの引数にたまたま同じ文字列が現れても無関係。
        assert_eq!(
            arbiter.classify("write_file", RiskClass::Write, "notes/-EncodedCommand.md"),
            Classification::Allow
        );
    }

    #[test]
    fn config_injection_path_denied_even_under_accept_all() {
        let arbiter = PermissionArbiter::new(
            PermissionMode::AcceptAll,
            vec![AllowlistRule::new("write_file", "*")],
        );
        assert_eq!(
            arbiter.classify("write_file", RiskClass::Write, ".git/config"),
            Classification::Deny
        );
    }

    /// **層3 hard-deny（D-05）は表記ゆれで迂回できてはならない。**
    ///
    /// ここは`apply`の再ゲートではなく**実行前の主ゲート**なので、素の
    /// `arg_repr`（モデルが書いた文字列そのもの）が渡ってくる。`SandboxFs`側の
    /// 正規化には頼れない。実測で次の2つが素通りしていた（`docs/bugs/BUG-063.md`）。
    ///
    /// - `.GIT/config` — 判定が大小を区別するのにNTFS/APFSは区別しない
    /// - `././.git/config` — `strip_prefix("./")`が1回しか剥がさない
    ///
    /// どちらも`--sandbox tier2a-cow`とは無関係に、Liveワークスペースへ`write_file`1回で届く。
    #[test]
    fn config_injection_hard_deny_is_not_bypassable_by_path_spelling() {
        let arbiter = PermissionArbiter::new(
            PermissionMode::AcceptAll,
            vec![AllowlistRule::new("write_file", "*")],
        );
        for spelling in [
            ".GIT/config",
            ".Git/Config",
            "././.git/config",
            "./././.harness/settings.json",
            ".\\.git\\config",
            "x/../.git/config",
        ] {
            assert_eq!(
                arbiter.classify("write_file", RiskClass::Write, spelling),
                Classification::Deny,
                "spelling {spelling:?} bypassed the D-05 hard-deny"
            );
        }
    }

    #[test]
    fn config_injection_path_denied_even_if_allowlisted() {
        let arbiter = PermissionArbiter::new(
            PermissionMode::Default,
            vec![
                AllowlistRule::new("write_file", "*"),
                AllowlistRule::new("edit_file", "*"),
            ],
        );
        assert_eq!(
            arbiter.classify("write_file", RiskClass::Write, ".harness/settings.json"),
            Classification::Deny
        );
        assert_eq!(
            arbiter.classify("edit_file", RiskClass::Write, ".gitattributes"),
            Classification::Deny
        );
    }

    #[test]
    fn config_injection_check_covers_all_d05_paths() {
        let arbiter = PermissionArbiter::new(PermissionMode::AcceptAll, vec![]);
        for p in [
            ".git/config",
            ".git/hooks/pre-commit",
            ".git/info/exclude",
            ".gitattributes",
            ".harness/settings.json",
            ".github/workflows/ci.yml",
            ".gitlab-ci.yml",
            ".circleci/config.yml",
            ".vscode/settings.json",
            ".devcontainer/devcontainer.json",
        ] {
            assert_eq!(
                arbiter.classify("write_file", RiskClass::Write, p),
                Classification::Deny,
                "expected deny for {p}"
            );
        }
    }

    #[test]
    fn normal_workspace_file_unaffected_by_config_injection_check() {
        let arbiter = PermissionArbiter::new(PermissionMode::AcceptAll, vec![]);
        assert_eq!(
            arbiter.classify("write_file", RiskClass::Write, "src/main.rs"),
            Classification::Allow
        );
        // 似た名前だが対象外のパス（誤検知しないことの確認）。
        assert_eq!(
            arbiter.classify("write_file", RiskClass::Write, ".gitattributes-backup.txt"),
            Classification::Allow
        );
    }

    #[test]
    fn config_injection_check_does_not_affect_run_shell() {
        // run_shell経由の設定書換（T-07）は本チェックの対象外。D-06（gitハードニング）+
        // D-09（overlay apply時の再チェック）が担当する。ここではrun_shellの引数
        // （コマンド文字列）が誤検知でDenyにならないことだけ確認する。
        let arbiter = PermissionArbiter::new(
            PermissionMode::AcceptAll,
            vec![AllowlistRule::new("run_shell", "*")],
        );
        assert_eq!(
            arbiter.classify("run_shell", RiskClass::Exec, "cat .git/config"),
            Classification::Allow
        );
    }

    /// M15.5/D-40: MCPツールは`mcp__<server>__<tool>`という名前で通常ツールとして載り、
    /// **宣言でread-onlyと宣言されなかったものは`RiskClass::Network`になる**（`harness-mcp`側）。
    /// ここではその結果がゲートでどう扱われるかを固定する——`Default`モードでプロンプト、
    /// ヘッドレスでは自動拒否。認知レイヤーもこのゲートをバイパスしない。
    #[test]
    fn an_unallowlisted_mcp_tool_prompts_interactively_and_is_denied_headless() {
        let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
        let input = serde_json::json!({ "title": "ship it" }).to_string();

        assert_eq!(
            arbiter.classify("mcp__jira__create_issue", RiskClass::Network, &input),
            Classification::Prompt
        );
        assert_eq!(
            arbiter.decide("mcp__jira__create_issue", RiskClass::Network, &input),
            Decision::Deny
        );
    }

    /// read-onlyと宣言されたMCPツールは、組み込みのread系と同じく自動許可される。
    #[test]
    fn a_declared_read_only_mcp_tool_is_allowed_like_any_other_read() {
        let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
        assert_eq!(
            arbiter.decide("mcp__company-docs__search", RiskClass::ReadOnly, "{}"),
            Decision::Allow
        );
    }

    /// allowlistルールはMCPの名前空間付きツール名でそのまま書ける（登録名・`arg_repr`・
    /// ルールが同じ表記であることの担保、`plans/DESIGN.md` §ツールシステム）。
    #[test]
    fn allowlist_rules_can_target_mcp_tools_by_their_namespaced_name() {
        let arbiter = PermissionArbiter::new(
            PermissionMode::Default,
            vec![AllowlistRule::new("mcp__jira__create_issue", "*")],
        );
        assert_eq!(
            arbiter.decide("mcp__jira__create_issue", RiskClass::Network, "{}"),
            Decision::Allow
        );
        // 別サーバの同名ツールには波及しない。
        assert_eq!(
            arbiter.decide("mcp__other__create_issue", RiskClass::Network, "{}"),
            Decision::Deny
        );
    }

    #[test]
    fn parses_allowlist_rule() {
        let rule = parse_allowlist_rule("run_shell:git status*").unwrap();
        assert_eq!(rule.tool, "run_shell");
        assert_eq!(rule.pattern, "git status*");
        assert!(parse_allowlist_rule("no-colon").is_none());
    }
}
