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
    fn parses_allowlist_rule() {
        let rule = parse_allowlist_rule("run_shell:git status*").unwrap();
        assert_eq!(rule.tool, "run_shell");
        assert_eq!(rule.pattern, "git status*");
        assert!(parse_allowlist_rule("no-colon").is_none());
    }
}
