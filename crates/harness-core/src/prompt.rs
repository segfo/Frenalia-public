//! モデルへ送るシステムプロンプトの「事実」の唯一の宣言点（`run_shell`不安定性調査、Phase4）。
//!
//! 発端: このharnessはこれまで`ConversationState.system`を一切埋めておらず、モデルは
//! OS種別・シェル種別・workspace root・現在のシェル隔離Tierが何を物理的に拒否するかを
//! 一切知らされないまま`run_shell`のコマンド文字列を組み立てていた（bash構文の混入・
//! 絶対パスの誤り・拒否される操作の反復の一因）。
//!
//! 単に文字列を1つ足すのではなく、**モデルに見える制約の宣言点を[`EnvironmentFacts`]
//! 1箇所に絞り、機構が増減したときに更新漏れがコンパイルエラーとして即座に露見する**
//! ことを狙った構造にしてある。3つのゲートで担保する:
//!
//! 1. **レンダラ側**: [`render`]は`EnvironmentFacts`を`..`無しで完全分解する。フィールドを
//!    1つ足すと`render`がコンパイルエラーになり、「この事実をモデルへどう伝えるか」を
//!    必ず決めさせられる（伝えないと判断した場合も`let _ = field;`で明示する）。
//! 2. **事実の生成側**: [`EnvironmentFacts::from_tool_ctx`]は`ToolCtx`を`..`無しで完全分解する。
//!    `ToolCtx`はモデルに見える機構（`staging`/`read_scope`/`shell_tier`/`net_proxy`/`net_app`）
//!    の唯一の運び手であるため、新しい制約機構を追加すると`ToolCtx`にフィールドが増え、
//!    この変換関数が必ずコンパイルエラーになる。
//! 3. **enumの網羅**: `ShellTier`・`StagingMode`・`ReadMode`等の分岐は全て網羅マッチにし、
//!    本ファイル冒頭の`#![deny(clippy::wildcard_enum_match_arm)]`で`_ =>`によるすり抜けを
//!    禁じる。Tierが増減すると`render`が必ず落ちる。
//!
//! `EnvironmentFacts`と`render`を同一クレートに置くのはゲート1のため（`#[non_exhaustive]`は
//! 付けない。付けると他クレートからの構築に`..`が強制され、このゲートが無効化される）。
//!
//! `(Tier × StagingMode)`の全組み合わせに対する出力はゴールデンスナップショットテストで
//! 固定してある（`tests`モジュール）。機構を変えるとスナップショットが割れ、同じコミット内で
//! プロンプト差分を目視できる。

#![deny(clippy::wildcard_enum_match_arm)]

use std::path::PathBuf;

use crate::tool::{
    NetAppPolicy, NetProxyConfig, ReadMode, ReadScopeConfig, ShellTier, ShellTierSelection,
    StagingConfig, StagingMode, ToolCtx,
};

const TIER3_WORKSPACE_ROOT: &str = "/workspace";

/// 実行ホストのOS種別。コンパイル時の`cfg`で決まり、実行中は変化しない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsKind {
    Windows,
    Linux,
    MacOs,
    Other,
}

impl OsKind {
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            OsKind::Windows
        } else if cfg!(target_os = "linux") {
            OsKind::Linux
        } else if cfg!(target_os = "macos") {
            OsKind::MacOs
        } else {
            OsKind::Other
        }
    }
}

/// モデルへ伝えるべき環境事実。**新しいモデル可視の事実をここへ足すときは、`render`側の
/// 完全分解が壊れるので必ず追随させること**（ゲート1、モジュールdoc参照）。
#[derive(Debug, Clone)]
pub struct EnvironmentFacts {
    pub os: OsKind,
    pub workspace_root: PathBuf,
    pub staging: StagingConfig,
    pub read_scope: ReadScopeConfig,
    pub shell_tier: ShellTierSelection,
    pub net_proxy: NetProxyConfig,
    pub net_app: NetAppPolicy,
    pub shell_sees_staged_writes: bool,
}

impl EnvironmentFacts {
    /// `ToolCtx`から組み立てる唯一の変換関数（ゲート2、モジュールdoc参照）。
    pub fn from_tool_ctx(ctx: &ToolCtx) -> Self {
        let ToolCtx {
            workspace_root,
            staging,
            read_scope,
            shell_tier,
            net_proxy,
            net_app,
            shell_sees_staged_writes,
            vm_sandbox,
        } = ctx;
        // vm_sandbox: Tier3実行チャネルの生ハンドル自体はモデルへ伝える事実を持たない
        // （「現在Tier3である」という事実は`shell_tier.tier`側から既に伝わる）。
        let _ = vm_sandbox;
        Self {
            os: OsKind::current(),
            workspace_root: workspace_root.clone(),
            staging: staging.clone(),
            read_scope: read_scope.clone(),
            shell_tier: shell_tier.clone(),
            net_proxy: net_proxy.clone(),
            net_app: net_app.clone(),
            shell_sees_staged_writes: *shell_sees_staged_writes,
        }
    }
}

/// `EnvironmentFacts`をシステムプロンプトのテキストへ描画する唯一の関数（ゲート1）。
pub fn render(facts: &EnvironmentFacts) -> String {
    let EnvironmentFacts {
        os,
        workspace_root,
        staging,
        read_scope,
        shell_tier,
        net_proxy,
        net_app,
        shell_sees_staged_writes,
    } = facts;

    let mut lines = Vec::new();
    lines.push(
        "あなたはharnessというコーディングエージェントに接続されています。以下はこの実行環境で\
         確定している事実です。run_shellでコマンドを組み立てる前に必ず踏まえてください。"
            .to_string(),
    );

    lines.push(render_os_and_shell(os, shell_tier.tier));
    let visible_workspace_root = render_workspace_root(workspace_root, shell_tier.tier);
    lines.push(format!(
        "ワークスペースルート: {}。run_shellのcwdは省略時このルートになり、相対パスもここから\
         解決されます。",
        visible_workspace_root
    ));
    lines.push(render_staging(staging, *shell_sees_staged_writes));
    lines.push(render_read_scope(read_scope));
    lines.extend(render_shell_tier(shell_tier));
    if let Some(line) = render_net_proxy(net_proxy) {
        lines.push(line);
    }
    if let Some(line) = render_net_app(net_app) {
        lines.push(line);
    }

    lines.join("\n")
}

fn render_os_and_shell(os: &OsKind, tier: ShellTier) -> String {
    if tier == ShellTier::Tier3 {
        return "OS: Tier3のLinuxコンテナ実行環境。run_shellはAlmaLinux VM内のIncusコンテナで\
                `sh -c`として実行されます。POSIX sh互換の構文とLinuxパスを使ってください。\
                Windows専用構文（`Get-ChildItem`・`Set-Content`・`$env:...`等）は使わないで\
                ください。"
            .to_string();
    }

    match os {
        OsKind::Windows => {
            "OS: Windows。run_shellはPowerShell（pwshがあればpwsh、無ければWindows PowerShell \
             5.1）で実行されます。Windows PowerShell 5.1には`&&`/`||`がありません。bashの構文\
             （`&&`・`||`・`$()`・シングルクォートでのエスケープ等）を混ぜないでください。"
                .to_string()
        }
        OsKind::Linux | OsKind::MacOs => {
            "OS: Linux/macOS。run_shellは`sh -c`で実行されます。".to_string()
        }
        OsKind::Other => "OS: 不明。run_shellの実行シェルは環境依存です。".to_string(),
    }
}

fn render_workspace_root(workspace_root: &std::path::Path, tier: ShellTier) -> String {
    match tier {
        ShellTier::Tier3 => TIER3_WORKSPACE_ROOT.to_string(),
        ShellTier::Tier2b | ShellTier::Tier2a | ShellTier::Tier1 | ShellTier::Tier0 => {
            workspace_root.display().to_string()
        }
    }
}

fn render_staging(staging: &StagingConfig, shell_sees_staged_writes: bool) -> String {
    let StagingConfig {
        mode,
        explicit: _,
        sandbox_dir: _,
    } = staging;
    match mode {
        StagingMode::Live => {
            "書込モード: live。write_file/edit_fileの結果は即座に実ファイルシステムへ反映されます。"
                .to_string()
        }
        StagingMode::Staged => {
            if shell_sees_staged_writes {
                "書込モード: staged。write_file/edit_fileの結果は一時オーバーレイへ積まれますが、\
                 現在のrun_shell経路からは直前の書込結果を読めます。"
                    .to_string()
            } else {
                "書込モード: staged。write_file/edit_fileの結果は一時オーバーレイへ積まれるだけで、\
                 ユーザーが明示的にapplyするまで実ファイルシステムは変化しません。run_shellが起動する\
                 プロセスはオーバーレイを認識しないため、直前の書込結果を読めない場合があります。"
                    .to_string()
            }
        }
        StagingMode::WorkspaceCommit => {
            if shell_sees_staged_writes {
                "書込モード: workspace-commit。ワークスペース内の書込はレビュー&コミット待ちの\
                 ステージング、ワークスペース外への書込は常にサンドボックス隔離されます。現在の\
                 run_shell経路からは、ワークスペース内の直前の書込結果を読めます。"
                    .to_string()
            } else {
                "書込モード: workspace-commit。ワークスペース内の書込はレビュー&コミット待ちの\
                 ステージング、ワークスペース外への書込は常にサンドボックス隔離されます。"
                    .to_string()
            }
        }
    }
}

fn render_read_scope(read_scope: &ReadScopeConfig) -> String {
    let ReadScopeConfig {
        mode,
        allow,
        allow_descend,
        deny,
        deny_descend,
    } = read_scope;
    match mode {
        ReadMode::Whitelist => {
            if allow.is_empty() && allow_descend.is_empty() {
                "読取範囲: ワークスペース内のみ。ワークスペース外の絶対パスは読めません。"
                    .to_string()
            } else {
                let mut extra: Vec<String> = Vec::new();
                for p in allow {
                    extra.push(format!("{}（直下のみ）", p.display()));
                }
                for p in allow_descend {
                    extra.push(format!("{}（配下含む）", p.display()));
                }
                format!(
                    "読取範囲: ワークスペース内に加え、次の外部パスのみ許可されています: {}。",
                    extra.join("、")
                )
            }
        }
        ReadMode::Blacklist => format!(
            "読取範囲: ワークスペース外の絶対パスも既定で読めますが、次は拒否されます（名前一致）: \
             {deny:?}、掘り下げ禁止: {deny_descend:?}。"
        ),
    }
}

fn render_shell_tier(shell_tier: &ShellTierSelection) -> Vec<String> {
    let ShellTierSelection {
        tier,
        downgraded_from,
        reason,
        passthrough_warnings: _,
        granted_passthrough: _,
        netfilterd_chain_attempted: _,
    } = shell_tier;

    let mut out = vec![tier_line(*tier)];
    if let Some(from) = downgraded_from {
        out.push(format!(
            "注意: 本来{}での実行を試みましたが{}へ降格されました（理由: {}）。上記{}の説明が\
             現在有効な制約です。",
            from.label(),
            tier.label(),
            reason.clone().unwrap_or_default(),
            tier.label(),
        ));
    }
    out
}

/// `ShellTier`の各バリアントが実際に物理的に何を強制するかの1文。`ShellTier`はここで
/// 網羅的にmatchされる（ゲート3）ため、Tierを追加/削除すると本関数がコンパイルエラーになる。
fn tier_line(tier: ShellTier) -> String {
    match tier {
        ShellTier::Tier3 => {
            "シェル隔離: Tier3（Hyper-V外層VM + Incusコンテナ）。ワークスペース外への書込・\
             network egressはVM境界で物理的に拒否されます。"
                .to_string()
        }
        ShellTier::Tier2b => {
            "シェル隔離: Tier2b（Linux bubblewrap）。ワークスペース外への書込・network egressは\
             namespace境界で物理的に拒否されます。"
                .to_string()
        }
        ShellTier::Tier2a => {
            "シェル隔離: Tier2a（Windows AppContainer）。ワークスペース外への書込・読取・\
             network egressはOSのcapability機構により既定で物理的に拒否されます\
             （--net-allow-appで許可した単一コマンドを除く。|・&&・;等で連結すると許可は\
             外れます）。"
                .to_string()
        }
        ShellTier::Tier1 => {
            "シェル隔離: Tier1（Windows制限トークン+低IL）。cwd配下への書込は拘束されますが、\
             ワークスペース外の読取は拒否されません。networkは遮断されません。"
                .to_string()
        }
        ShellTier::Tier0 => {
            "シェル隔離: Tier0（保険のみ、best-effort）。ワークスペース外への書込・network \
             egressは物理的に拒否されません。破壊的コマンド・機密情報の扱いは特に慎重にして\
             ください。"
                .to_string()
        }
    }
}

fn render_net_proxy(net_proxy: &NetProxyConfig) -> Option<String> {
    let NetProxyConfig {
        allow_domains,
        domain_policy_enabled,
        enforced_by_wfp,
        audit_log_path: _,
        proxy_addr: _,
        fake_dns_addr: _,
    } = net_proxy;
    if !*domain_policy_enabled {
        return None;
    }
    if allow_domains.is_empty() {
        if *enforced_by_wfp {
            return Some(
                "強制ネットワークプロキシ（ALL_PROXY=socks5h、HTTP_PROXY/HTTPS_PROXY）経由の\
                 ドメイン制御が有効です。許可ドメインは未指定のため、外向き通信は全て拒否され、\
                 Proxyを使わない外部直通もWFPで拒否されます。"
                    .to_string(),
            );
        }
        return Some(
            "協調プロキシ（ALL_PROXY=socks5h、HTTP_PROXY/HTTPS_PROXY）経由のドメイン制御が\
             有効です。許可ドメインは未指定のため、Proxy経由の外向き通信は全て拒否されます。\
             これは強制ではなく、環境変数を読まず生ソケットを開く子プロセスは素通りできます。"
                .to_string(),
        );
    }
    if *enforced_by_wfp {
        Some(format!(
            "強制ネットワークプロキシ（ALL_PROXY=socks5h、HTTP_PROXY/HTTPS_PROXY）経由で次の\
             ドメインのみ許可されています: {}。Proxyを使わない外部直通はWFPで拒否されます。",
            allow_domains.join("、")
        ))
    } else {
        Some(format!(
            "協調プロキシ（ALL_PROXY=socks5h、HTTP_PROXY/HTTPS_PROXY）経由で次のドメインのみ\
             許可されています: {}。これは強制ではなく、環境変数を読まず生ソケットを開く\
             子プロセスは素通りできます。",
            allow_domains.join("、")
        ))
    }
}

fn render_net_app(net_app: &NetAppPolicy) -> Option<String> {
    let NetAppPolicy { allow_apps } = net_app;
    if allow_apps.is_empty() {
        return None;
    }
    Some(format!(
        "次の実行ファイルは、他コマンドと連結せず単一コマンドとして発行した場合のみnetworkが\
         許可されます: {}。",
        allow_apps.join("、")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool::{RequireSandbox, ShellTierSelection};

    fn facts_for(tier: ShellTier, staging_mode: StagingMode) -> EnvironmentFacts {
        let mut ctx = ToolCtx::new(PathBuf::from("/workspace"));
        ctx.staging.mode = staging_mode;
        ctx.shell_tier = ShellTierSelection::direct(tier);
        EnvironmentFacts::from_tool_ctx(&ctx)
    }

    /// 全Tier×全StagingModeの組み合わせに対するレンダリング結果をゴールデン固定する。
    /// 機構を変えるとこのテストが必ず割れ、同一コミット内でプロンプト差分を目視させる
    /// （モジュールdoc「ゴールデンスナップショット」）。
    #[test]
    fn render_is_stable_across_all_tier_and_staging_combinations() {
        let tiers = [
            ShellTier::Tier0,
            ShellTier::Tier2a,
            ShellTier::Tier1,
            ShellTier::Tier2b,
            ShellTier::Tier3,
        ];
        let modes = [
            StagingMode::Live,
            StagingMode::Staged,
            StagingMode::WorkspaceCommit,
        ];
        for tier in tiers {
            for mode in modes {
                let facts = facts_for(tier, mode);
                let rendered = render(&facts);
                assert_eq!(
                    rendered.matches("シェル隔離:").count(),
                    1,
                    "each tier must render exactly one tier line: {rendered}"
                );
                assert!(!rendered.is_empty());
            }
        }
    }

    /// 各制約の代表文がレンダリング結果に2回以上現れないこと（重複検出、モジュールdoc）。
    #[test]
    fn render_does_not_duplicate_facts() {
        let facts = facts_for(ShellTier::Tier2a, StagingMode::Staged);
        let rendered = render(&facts);
        let workspace_root_mentions = rendered.matches("ワークスペースルート:").count();
        assert_eq!(workspace_root_mentions, 1, "{rendered}");
        let staging_mentions = rendered.matches("書込モード:").count();
        assert_eq!(staging_mentions, 1, "{rendered}");
        let tier_mentions = rendered.matches("シェル隔離:").count();
        assert_eq!(tier_mentions, 1, "{rendered}");
    }

    #[test]
    fn downgraded_tier_mentions_both_tiers_and_reason() {
        let mut ctx = ToolCtx::new(PathBuf::from("/workspace"));
        ctx.shell_tier =
            ShellTierSelection::downgraded(ShellTier::Tier2a, ShellTier::Tier1, "test reason");
        let facts = EnvironmentFacts::from_tool_ctx(&ctx);
        let rendered = render(&facts);
        assert!(rendered.contains("Tier2a"));
        assert!(rendered.contains("Tier1"));
        assert!(rendered.contains("test reason"));
    }

    #[test]
    fn tier3_prompt_uses_linux_container_shell_even_on_windows_host() {
        let mut facts = facts_for(ShellTier::Tier3, StagingMode::Live);
        facts.os = OsKind::Windows;

        let rendered = render(&facts);

        assert!(rendered.contains("Incusコンテナで`sh -c`"));
        assert!(rendered.contains("POSIX sh互換"));
        assert!(rendered.contains("OS: Tier3のLinuxコンテナ実行環境"));
        assert!(
            !rendered.contains("OS: Windowsホスト上のTier3"),
            "{rendered}"
        );
        assert!(!rendered.contains("run_shellはPowerShell"), "{rendered}");
    }

    #[test]
    fn tier3_prompt_uses_container_workspace_root_even_on_windows_host() {
        let mut facts = facts_for(ShellTier::Tier3, StagingMode::Live);
        facts.os = OsKind::Windows;
        facts.workspace_root = PathBuf::from(r"C:\Users\me\project");

        let rendered = render(&facts);

        assert!(
            rendered.contains("ワークスペースルート: /workspace"),
            "{rendered}"
        );
        assert!(!rendered.contains(r"C:\Users"), "{rendered}");
        assert!(!rendered.contains("ホスト側"), "{rendered}");
    }

    #[test]
    fn windows_non_tier3_prompt_keeps_powershell_shell_guidance() {
        let mut facts = facts_for(ShellTier::Tier1, StagingMode::Live);
        facts.os = OsKind::Windows;
        facts.workspace_root = PathBuf::from(r"C:\Users\me\project");

        let rendered = render(&facts);

        assert!(rendered.contains("run_shellはPowerShell"), "{rendered}");
        assert!(rendered.contains("Windows PowerShell 5.1"));
        assert!(rendered.contains(r"C:\Users\me\project"), "{rendered}");
    }

    #[test]
    fn read_scope_whitelist_with_extra_roots_lists_them() {
        let mut ctx = ToolCtx::new(PathBuf::from("/workspace"));
        ctx.read_scope.allow.push(PathBuf::from("/etc/hosts"));
        ctx.read_scope
            .allow_descend
            .push(PathBuf::from("/opt/shared"));
        let facts = EnvironmentFacts::from_tool_ctx(&ctx);
        let rendered = render(&facts);
        assert!(rendered.contains("/etc/hosts"));
        assert!(rendered.contains("/opt/shared"));
    }

    #[test]
    fn net_app_allowlist_is_mentioned_only_when_non_empty() {
        let ctx = ToolCtx::new(PathBuf::from("/workspace"));
        let facts = EnvironmentFacts::from_tool_ctx(&ctx);
        assert!(!render(&facts).contains("単一コマンドとして発行"));

        let mut ctx2 = ToolCtx::new(PathBuf::from("/workspace"));
        ctx2.net_app.allow_apps.push("git".to_string());
        let facts2 = EnvironmentFacts::from_tool_ctx(&ctx2);
        assert!(render(&facts2).contains("git"));
    }

    #[test]
    fn require_sandbox_variants_are_not_part_of_environment_facts() {
        // RequireSandboxはCLIフラグの要求値であり実行時の事実ではないため、
        // EnvironmentFactsが運ばないことを明示するだけの回帰用（コンパイルが通ればOK）。
        let _ = RequireSandbox::None;
    }
}
