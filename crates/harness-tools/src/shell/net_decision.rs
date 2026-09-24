//! アプリ単位network制御（軸1、D-10/D-11）の判定。
//!
//! **どの外部システムとも話さない純粋関数だけ**を置く（`docs/CODE-STRUCTURE-RULES.md`規則3の
//! 軸1で`shell.rs`から切り出した）。ここへ副作用を持ち込まないこと——judgement（許可するか）と
//! enforcement（capabilityを積む）を同じ場所に置くと、判定だけを単体テストできなくなる。
//! 実際にcapabilityを積むのは`super::runner`のTier2a経路だけである。

/// アプリ単位network制御（軸1、D-10/D-11）の判定結果。`classify_net_app`が返す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetDecision {
    /// 許可リスト非空だが先頭execが不一致（既定）。
    Deny,
    /// 先頭execは一致したが、連鎖メタ文字（`|`/`&&`/`;`等）を含むため他exe混入の恐れがあり
    /// 安全側で拒否した（D-11の最小許可原則。連鎖内の全execを安全に列挙するのは困難なため）。
    DeniedByChaining,
    /// 先頭execが一致し、連鎖も無い単一コマンド。`internetClient`を付与してよい。
    Allow,
}

/// コマンド文字列の先頭トークンを取り出す（引用符付きなら中身、無ければ空白区切りの最初の語）。
fn first_command_token(command: &str) -> &str {
    let s = command.trim_start();
    if let Some(rest) = s.strip_prefix('"') {
        return rest.split('"').next().unwrap_or("");
    }
    if let Some(rest) = s.strip_prefix('\'') {
        return rest.split('\'').next().unwrap_or("");
    }
    s.split_whitespace().next().unwrap_or("")
}

/// 実行ファイルトークンから比較用のbasename（パス除去・拡張子除去・小文字化）を作る。
fn exe_basename(token: &str) -> String {
    let name = token.rsplit(['\\', '/']).next().unwrap_or(token);
    let stem = name.rsplit_once('.').map(|(s, _)| s).unwrap_or(name);
    stem.to_ascii_lowercase()
}

/// コマンド文字列が連鎖メタ文字（`|`/`&`/`;`/バッククォート/`$(`/改行）を含むかを判定する。
/// 単一`&`（PowerShellの呼び出し演算子等）も安全側で連鎖扱いにする（D-11の最小許可原則）。
fn contains_chaining_metachar(command: &str) -> bool {
    if command.contains(['|', '&', '`', '\n']) || command.contains("$(") {
        return true;
    }
    let mut brace_depth = 0usize;
    for ch in command.chars() {
        match ch {
            '{' => brace_depth = brace_depth.saturating_add(1),
            '}' => brace_depth = brace_depth.saturating_sub(1),
            ';' if brace_depth == 0 => return true,
            _ => {}
        }
    }
    false
}

/// `command`の先頭execが`allow_apps`（basename一致）に含まれるかを判定し、連鎖の有無も
/// 併せて評価する（軸1、D-10/D-11）。`allow_apps`が空なら常に`Deny`（既定・現状維持）。
///
/// **限界（残存リスク、T-15の具体化）**: 判定は外側のコマンド文字列にしか及ばない。
/// `pwsh ./x.ps1`のようにインタプリタ/スクリプトを許可リストへ入れると、中身が呼ぶ通信も
/// 全て通ってしまう（capabilityは子孫プロセスへ全継承）。許可リストには`git`/`npm`等の
/// 具体的で狭い実行ファイル名のみを入れることを前提とする。
pub(crate) fn classify_net_app(command: &str, allow_apps: &[String]) -> NetDecision {
    if allow_apps.is_empty() {
        return NetDecision::Deny;
    }
    let shell_allowed = allow_apps.iter().any(|allowed| {
        let basename = exe_basename(allowed);
        basename == "powershell" || basename == "pwsh"
    });
    let token = first_command_token(command);
    if token.is_empty() {
        return NetDecision::Deny;
    }
    let basename = exe_basename(token);
    let matched = allow_apps
        .iter()
        .any(|allowed| exe_basename(allowed) == basename)
        || shell_allowed;
    if !matched {
        return NetDecision::Deny;
    }
    if contains_chaining_metachar(command) {
        return NetDecision::DeniedByChaining;
    }
    NetDecision::Allow
}

/// `run_program`（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` §2.4）の`program`が`allow_apps`に含まれるか。
///
/// **[`classify_net_app`]と違って推測しない。** あちらはコマンド行の先頭の語から実行ファイルを
/// 推測し、連結されていれば他のexeが混ざる恐れがあるので拒否する。`run_program`は呼び出し1回が
/// プログラム1個で、`program`は確定している——**連結が起こりえないので
/// [`NetDecision::DeniedByChaining`]はここからは返らない**。
///
/// **`pwsh`/`powershell`を許可していても、それ以外のプログラムは通さない。**
/// [`classify_net_app`]がシェルを許可したとき全コマンドを通すのは、`run_shell`では
/// **実際に起動されるのがシェルだから**である。`run_program`はシェルを起動しない。
pub(crate) fn classify_net_program(program: &str, allow_apps: &[String]) -> NetDecision {
    let basename = exe_basename(program);
    if basename.is_empty() {
        return NetDecision::Deny;
    }
    if allow_apps
        .iter()
        .any(|allowed| exe_basename(allowed) == basename)
    {
        NetDecision::Allow
    } else {
        NetDecision::Deny
    }
}

/// Tier2aの子へ`internetClient`を積んでよいか。
///
/// **軸が2つある。** ドメイン単位の制御（軸2）を要求しているときは、WFPのdefault-denyが
/// 実際に立っている場合に限り許す——proxyだけでは環境変数を読まない子が素通りできるので、
/// WFPが無いなら**capability自体を与えない**（fail-closed。「強制されていない」のではなく
/// 「ソケットを1つも作れない」に倒す）。要求していないときはアプリ単位（軸1、D-10/D-11）の
/// 判定だけを見る。
///
/// ポリシーエディタのパス2（Tier2aでのドメイン記録、`plans/POLICY-EDITOR-TOMOYO-DIG.md`）も
/// **同じ規則**に従う必要があるため`pub`（判定を経路ごとに書き直すと片方だけ緩む）。
pub fn should_grant_tier2a_network_capability(
    net: NetDecision,
    net_proxy_enforced: bool,
    net_domain_policy_requested: bool,
) -> bool {
    if net_domain_policy_requested {
        return net_proxy_enforced;
    }
    net == NetDecision::Allow
}
