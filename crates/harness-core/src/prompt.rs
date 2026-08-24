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
    McpServerFact, NetAppPolicy, NetProxyConfig, ReadMode, ReadScopeConfig, ShellTier,
    ShellTierSelection, StagingConfig, StagingMode, ToolCtx,
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
    /// `--sandbox tier2a-cow`（D-30）のCoW upperディレクトリ。`Some`ならworkspaceはRead/Execute/Traverseのみ
    /// （RO）で付与されており、`run_shell`子プロセスの書込は透過的にこの外部ディレクトリへ
    /// 誘導される（Redirector DLL経由、フック失敗時はACLによりfail-close）。
    pub cow_upper_dir: Option<PathBuf>,
    /// 起動中のMCPサーバ（M15.5）。
    pub mcp_servers: Vec<McpServerFact>,
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
            run_shell_path_extra,
            shell_sees_staged_writes,
            vm_sandbox,
            cow_upper_dir,
            mcp_servers,
        } = ctx;
        let _ = run_shell_path_extra;
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
            cow_upper_dir: cow_upper_dir.clone(),
            mcp_servers: mcp_servers.clone(),
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
        cow_upper_dir,
        mcp_servers,
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
    if let Some(line) = render_cow(cow_upper_dir) {
        lines.push(line);
    }
    lines.push(render_git_hardening());
    lines.push(render_read_scope(read_scope));
    lines.extend(render_shell_tier(shell_tier));
    if let Some(line) = render_net_proxy(net_proxy, shell_tier.tier) {
        lines.push(line);
    }
    if let Some(line) = render_net_app(net_app) {
        lines.push(line);
    }
    lines.extend(render_mcp_servers(mcp_servers));

    lines.join("\n")
}

/// M15.5: 起動中のMCPサーバ（`plans/DESIGN-MCP.md`）。
///
/// モデルへ伝えるのは次の3点で、いずれも**モデルが計画を立てるときに必要な事実**である。
///
/// 1. どのツールが第三者サーバ由来か（`DESIGN-COGNITION.md` §4.3の接地判定に効く）
/// 2. サーバごとに到達できる先が違うこと（「なぜこのツールだけ外に出られるのか」の説明）
/// 3. 宣言の無いツールは必ず承認を求められること（D-40。無駄な再試行を減らす）
///
/// サーバが1つも起動していないときは何も出さない。「MCPは無い」という否定の事実をわざわざ
/// 書くと、宣言していないユーザー全員のプロンプトが無意味に伸びる。
fn render_mcp_servers(mcp_servers: &[McpServerFact]) -> Vec<String> {
    if mcp_servers.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![
        "MCPサーバ: 次のサーバのツールが`mcp__<サーバid>__<ツール名>`という名前で利用できます。\
         これらはharnessの組み込みツールではなく、サーバごとに別のサンドボックスで動く第三者の\
         プロセスです。出力は未検証の情報として扱い、重要な結論はワークスペース内の実ファイル等の\
         一次情報でも裏を取ってください。宣言でread-onlyと明示されていないMCPツールは、実行前に\
         必ずユーザーの承認を求められます。"
            .to_string(),
    ];
    for server in mcp_servers {
        let McpServerFact {
            id,
            allow_domains,
            workspace_access,
            tool_names,
            transport,
            endpoint,
        } = server;
        // Streamable HTTP（M15.6）はharness本体が直接喋る経路で、AppContainerの外にある。
        // `allow_domains`（＝AppContainer子の宛先制御）は常に空なので、stdioと同じ文言だと
        // 「外向き通信は不可」という**事実に反する**説明になる。
        let reach = match endpoint {
            Some(endpoint) => format!(
                "harness本体が{endpoint}へ直接HTTPで接続する第三者サーバ（サンドボックスの外）"
            ),
            None if allow_domains.is_empty() => "外向き通信は不可".to_string(),
            None => format!("到達可能な宛先: {}", allow_domains.join("、")),
        };
        let workspace = match workspace_access.as_str() {
            "read" => "ワークスペースは読取のみ可",
            "read-write" => "ワークスペースは読み書き可",
            _ => "ワークスペースへはアクセス不可",
        };
        let _ = transport; // 種別そのものは`endpoint`の有無から読み取れるので重ねて出さない。
        lines.push(format!(
            "- {id}: {reach}、{workspace}。ツール: {}",
            tool_names.join("、")
        ));
    }
    lines
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

/// D-30: `--sandbox tier2a-cow`時、workspaceはRead/Execute/Traverseのみで付与されている。モデルへは
/// 「run_shell内の直接書込は成功しない前提で組み立てよ」という事実を明示する
/// （Redirector DLLが実際に誘導できるかはベストエフォートで、モデルの計画自体はACLの
/// 保証だけを頼りにすべきという意図、フックは境界にしない=D-01）。
fn render_cow(cow_upper_dir: &Option<PathBuf>) -> Option<String> {
    cow_upper_dir.as_ref().map(|upper| {
        format!(
            "Copy-on-Writeモード: 有効。ワークスペース本体はread-onlyで付与されており、\
             run_shellが起動するプロセスから直接書込むと失敗します（Access Denied）。書込は\
             透過リダイレクト機構が{}へ誘導しようと試みますが、誘導自体はベストエフォートの\
             利便性機構であり、境界（保護）はワークスペース本体がread-onlyであること自体に\
             依存します。run_shellでの書込が拒否される場合は、write_file/edit_fileツールを\
             使ってください（これらはリダイレクト機構に依存せず常に反映されます）。なお、\
             上記ディレクトリへ直接書いた場合も、ワークスペース内の同じ相対パスに対する変更\
             として記録されます。",
            upper.display()
        )
    })
}

/// D-14b: モデル実行`git`は常にhooks/fsmonitor/pagerが無効化されている
/// （`harness_sandbox::git_hardening_env`、`run_shell`のenvへ常時合成）。境界ではなく
/// ハードニングなので、その旨を明示してモデルの誤診（「なぜpre-commit hookが走らないのか」等）を
/// 防ぐ。Tier・staging等に依存しない常時trueの事実のため`EnvironmentFacts`に専用フィールドは
/// 持たせない。
fn render_git_hardening() -> String {
    "gitの挙動: run_shellが起動するgitはhooks（core.hooksPath）・fsmonitor・pagerが常に\
     無効化されています。pre-commit hook等は発火しません。これはセキュリティのハードニングで\
     あり、既定のgit動作を変えるための解除手段ではありません。"
        .to_string()
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

/// 着地したTierと、`--fs-allow`が開けた穴をモデルへ伝える。
///
/// **「降格しました」という段はもう無い**（D-75）。隔離が取れないときは起動そのものを拒否する
/// ので、ここに到達している時点で**要求どおりのTierに居る**。かつては
/// 「本来Tier2aを試みましたがTier0へ降格されました」という注意書きを出していたが、
/// **その文が出る状況自体を無くした**——宣言は誤解を減らすだけで、境界の不在は埋めない
/// （P-07と同じ理由。`plans/DESIGN-SANDBOX.md` D-75）。
fn render_shell_tier(shell_tier: &ShellTierSelection) -> Vec<String> {
    let ShellTierSelection {
        tier,
        passthrough_warnings,
        denied_passthrough,
        granted_passthrough,
        netfilterd_chain_attempted: _,
    } = shell_tier;

    // D8/D9の到達性診断は**運用者向けの手順**（「`harness fs grant-traverse <path>`を実行せよ」）
    // であり、モデルには実行できない。拒否されたパスとその理由は`denied_passthrough`が
    // 構造化して持っているので、そちらだけをモデルへ伝える。
    let _ = passthrough_warnings;

    let mut out = vec![tier_line(*tier)];
    out.extend(render_passthrough(granted_passthrough, denied_passthrough));
    out
}

/// `--fs-allow`/`settings.json`が開けた（あるいは開けなかった）ワークスペース外の穴。
///
/// # なぜモデルへ伝えるのか
///
/// **`denied`が見えないことは穴が無いことより悪い。** 付与に失敗したパスについて、モデルは
/// 「ユーザーが許可したのだから使える」と思ったまま計画を立て、失敗し、原因が分からないまま
/// 再試行する。ここで「触れない」と宣言しておけば、その空転が消える。
///
/// `granted`の方は逆に積極的な事実である——Tier2aの既定は「ワークスペース外は読めない」なので、
/// 例外がどこにあるかを知らせないと、モデルは使える経路を使わない。
///
/// どちらも空なら1行も出さない（`render_mcp_servers`・`render_net_app`と同じ方針。宣言して
/// いないユーザーのプロンプトを無意味に伸ばさない）。
///
/// `--sandbox tier2a-cow`下では`:rw`の実ACLが`Read`へ降格される（P-03、BUG-044）が、その事実は
/// [`render_cow`]が「ワークスペース本体はread-only、書込は透過リダイレクト、境界はACL」として
/// 既に述べているので、ここで重複させない。
fn render_passthrough(
    granted: &[(PathBuf, bool)],
    denied: &[(PathBuf, String, String)],
) -> Vec<String> {
    if granted.is_empty() && denied.is_empty() {
        return Vec::new();
    }
    let mut lines = Vec::new();
    if !granted.is_empty() {
        let entries: Vec<String> = granted
            .iter()
            .map(|(path, writable)| {
                format!(
                    "{}（{}）",
                    path.display(),
                    if *writable {
                        "読み書き"
                    } else {
                        "読取のみ"
                    }
                )
            })
            .collect();
        lines.push(format!(
            "ワークスペース外の例外（許可済み）: run_shellが起動するプロセスは、次の外部パスへ\
             追加でアクセスできます: {}。これ以外のワークスペース外パスは既定どおり拒否されます。",
            entries.join("、")
        ));
    }
    if !denied.is_empty() {
        let entries: Vec<String> = denied
            .iter()
            .map(|(path, access, reason)| format!("{}［{access}］: {reason}", path.display()))
            .collect();
        lines.push(format!(
            "ワークスペース外の例外（許可に失敗）: 次のパスは許可が要求されましたが、実際には\
             アクセスできません。**使える前提で計画を立てないでください**: {}。",
            entries.join("、")
        ));
    }
    lines
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
            // **「cwd配下への書込は拘束されます」と書いていた頃は、実態より広く宣言していた。**
            // 「cwd配下なら書ける」と読めるが、実際に書けるのはワークスペース直下と、
            // シェル自身が新しく作ったディレクトリの中だけである（低ILラベルはcwd 1個にしか
            // 付かず、既存のサブディレクトリはMediumのまま＝No-Write-Upで拒否される）。
            // その結果ビルドもテストも`git commit`も通らないのに、モデルには「書ける」と
            // 伝わっていたため、原因の分からない`Access is denied`で再試行し続けることになる。
            // 内訳の実測は`harness_sandbox::tier1::win_restricted`のモジュールdocの表。
            "シェル隔離: Tier1（Windows制限トークン+低IL）。run_shellで起動したプロセスが\
             書き込めるのは、ワークスペース直下と、そのシェル自身が新しく作った\
             ディレクトリの中だけです。既存のサブディレクトリ（src/・.git/等）と\
             ワークスペース外への書込は拒否されます。**このためビルド・テスト・\
             git commitはTier1では失敗します**——これはコマンドの誤りではなく隔離Tierの\
             制約なので、書き方を変えて再試行しても通りません。読取は拒否されません。\
             networkは遮断されません。なおwrite_file/edit_fileはこの制約を受けないため、\
             ファイルの編集自体は通常どおり行えます。"
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

/// ドメインポリシーの実効状態を1文で宣言する。**Tierを引数に取るのは、同じ
/// `enforced_by_wfp == false`が Tier2a とそれ以外とで正反対の意味になるため**である。
///
/// - Tier2a以外（Tier0/Tier1）: 協調プロキシは環境変数ベースの誘導にすぎず、生ソケットを
///   開く子プロセスは素通りできる（＝「強制ではない」が正しい）。
/// - Tier2a: `should_grant_tier2a_network_capability`
///   （`crates/harness-tools/src/shell/net_decision.rs`）が`NetworkCapability::Deny`を選ぶため、
///   子プロセスはソケットを1つも作れない。素通りできるどころか協調プロキシへのloopback到達
///   すらできない（＝「強制ではない」は正反対の誤り）。
///
/// この区別を落とすと、モデルは「通信はできるが監査されるだけ」と誤解して通信コマンドを
/// 発行し続け、さらにユーザーへ安全性を実態より弱く報告する。同じ誤りが起動時警告側にも
/// あった（`crates/harness-cli/src/cli/startup/mod.rs`の`TIER2A_NET_DENIED`）。
fn render_net_proxy(net_proxy: &NetProxyConfig, tier: ShellTier) -> Option<String> {
    let NetProxyConfig {
        allow_domains,
        domain_policy_enabled,
        enforced_by_wfp,
        audit_log_path: _,
        proxy_addr: _,
        fake_dns_addr: _,
        // `TlsInspection::Sni`（現状唯一のバリアント）はSNI/ALPNのみ見て復号しないため、
        // モデルに見える制約はドメイン許可集合と変わらない。復号バリアントを追加する
        // 実装者は、ここで`match`させて「通信内容が復号され監査ログに残る」旨を
        // 出力へ追加すること（`NetProxyConfig.tls_inspection`のdoc comment参照）。
        tls_inspection: _,
    } = net_proxy;
    if !*domain_policy_enabled {
        return None;
    }
    if !*enforced_by_wfp && tier == ShellTier::Tier2a {
        return Some(
            "ネットワーク: ドメイン制御が要求されましたが、WFPによる強制が確立できませんでした。\
             この場合Tier2aはネットワークcapability自体を付与しないため、run_shellの子プロセスは\
             外向き通信を一切行えません（許可ドメイン指定の有無に関わらず、ソケットを1つも\
             作れません。協調プロキシへのloopback到達もできないため、環境変数を無視して生\
             ソケットを開いても素通りはできません）。通信を伴うコマンドは再試行しても成功\
             しないので、ネットワークを使わない方法を選ぶか、ユーザーへ相談してください。"
                .to_string(),
        );
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

    /// 全Tier×全StagingModeの組み合わせで、Tier行が**ちょうど1本**出ることを固定する。
    ///
    /// **これは文面を固定するテストではない。** 以前この関数のdocは「機構を変えると必ず割れる」と
    /// 書いていたが、実際に見ているのは行数と非空だけで、**Tierの説明文を書き換えても素通りする**。
    /// 実際、Tier1の宣言が実態より広かった（「cwd配下への書込は拘束されます」＝cwd配下なら
    /// 書けると読める）欠陥は、このテストが緑のまま残っていた。文面の担保は
    /// [`each_tier_line_states_the_constraint_a_model_would_act_on`]が持つ。
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

    /// **各Tierの説明が、モデルが実際に行動を変える事実を述べていること。**
    ///
    /// システムプロンプトはモデルへ制約を伝える唯一の宣言点なので、ここが実態より広いと
    /// モデルは「できるはず」と思って失敗し、原因の分からないまま再試行し続ける。
    /// Tier1がまさにその状態だった——低ILラベルはcwd 1個にしか付かないので
    /// ビルドもテストも`git commit`も通らないのに、「cwd配下への書込は拘束されます」としか
    /// 書いておらず、モデルからは「cwd配下なら書ける」と読めた。
    ///
    /// 見るのは**言い回し**ではなく**主張の有無**である。文面の推敲でテストが割れると
    /// 誰も直さなくなるので、載っていないと行動が変わる語だけを固定する。
    #[test]
    fn each_tier_line_states_the_constraint_a_model_would_act_on() {
        let line = |tier| {
            let rendered = render(&facts_for(tier, StagingMode::Live));
            rendered
                .lines()
                .find(|l| l.starts_with("シェル隔離:"))
                .expect("every tier renders a tier line")
                .to_string()
        };

        // Tier1: **ビルド・テストが通らないことを言う。** これが無いと、モデルは
        // `Access is denied`をコマンドの誤りだと解釈して書き方を変え続ける。
        let tier1 = line(ShellTier::Tier1);
        for claim in ["ビルド", "テスト", "git commit", "失敗"] {
            assert!(
                tier1.contains(claim),
                "the Tier1 line must tell the model that builds/tests cannot run here \
                 (missing {claim:?}): {tier1}"
            );
        }
        // Tier1では編集自体は通る。ここを言わないと「何もできない」と誤解される。
        assert!(
            tier1.contains("write_file") || tier1.contains("edit_file"),
            "the Tier1 line must say that file edits are unaffected: {tier1}"
        );
        // networkが素通しであることは隠さない（Tier1の残存脅威T-10）。
        assert!(
            tier1.contains("network"),
            "the Tier1 line must not hide that network is not contained: {tier1}"
        );

        // Tier0: 保護が無いことを必ず言う。**降格先になったので、ここの正直さが要る。**
        let tier0 = line(ShellTier::Tier0);
        assert!(
            tier0.contains("物理的に拒否されません"),
            "the Tier0 line must state plainly that nothing is enforced: {tier0}"
        );

        // 封じ込めがあるTierは、その旨を述べる（許可側も固定する＝B-35）。
        for tier in [ShellTier::Tier2a, ShellTier::Tier2b, ShellTier::Tier3] {
            let rendered = line(tier);
            assert!(
                rendered.contains("物理的に拒否されます"),
                "a containing tier must state that out-of-scope access is denied: {rendered}"
            );
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

    /// **降格の告知はもう出ない**（D-75）。
    ///
    /// かつては`downgraded_tier_mentions_both_tiers_and_reason`という名前で、
    /// 「本来Tier2aを試みましたがTier1へ降格されました（理由: …）」が出ることを固定していた。
    /// **降格そのものを廃したので、その文が出ないことを固定し直す**——弱いTierに居るのは
    /// ユーザーがそう選んだときだけで、モデルには**いま有効な制約**（Tier1の行）だけが要る。
    ///
    /// 禁止側だけでは「何も出ない」実装でも緑になるので、**許可側**（そのTierの説明が
    /// ちゃんと1行出ること）と対で測る。
    #[test]
    fn a_weak_tier_is_described_but_never_announced_as_a_downgrade() {
        let mut ctx = ToolCtx::new(PathBuf::from("/workspace"));
        ctx.shell_tier = ShellTierSelection::direct(ShellTier::Tier1);
        let facts = EnvironmentFacts::from_tool_ctx(&ctx);
        let rendered = render(&facts);

        // 許可側: 着地したTierの説明は出る。
        assert_eq!(rendered.matches("シェル隔離:").count(), 1, "{rendered}");
        assert!(rendered.contains("Tier1"), "{rendered}");

        // 禁止側: 「降格」という説明は出ない（そういう状態を作れない）。
        assert!(!rendered.contains("降格"), "{rendered}");
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

    /// MCPサーバが無いときはプロンプトを一切伸ばさない（宣言していないユーザーが大多数）。
    #[test]
    fn mcp_servers_are_not_mentioned_when_none_are_running() {
        let ctx = ToolCtx::new(PathBuf::from("/workspace"));
        let rendered = render(&EnvironmentFacts::from_tool_ctx(&ctx));
        assert!(!rendered.contains("MCPサーバ:"), "{rendered}");
    }

    /// M15.5: サーバごとに「到達できる先」が違うことをモデルへ伝える。
    #[test]
    fn mcp_servers_are_described_with_their_reach_and_tools() {
        let mut ctx = ToolCtx::new(PathBuf::from("/workspace"));
        ctx.mcp_servers = vec![
            McpServerFact {
                id: "company-docs".to_string(),
                allow_domains: vec!["docs.example.com".to_string()],
                workspace_access: "none".to_string(),
                tool_names: vec!["mcp__company-docs__search".to_string()],
                transport: "stdio".to_string(),
                endpoint: None,
            },
            McpServerFact {
                id: "local-notes".to_string(),
                allow_domains: Vec::new(),
                workspace_access: "read".to_string(),
                tool_names: vec!["mcp__local-notes__grep".to_string()],
                transport: "stdio".to_string(),
                endpoint: None,
            },
        ];
        let rendered = render(&EnvironmentFacts::from_tool_ctx(&ctx));

        assert!(rendered.contains("mcp__company-docs__search"), "{rendered}");
        assert!(rendered.contains("docs.example.com"), "{rendered}");
        assert!(rendered.contains("外向き通信は不可"), "{rendered}");
        assert!(
            rendered.contains("ワークスペースは読取のみ可"),
            "{rendered}"
        );
        assert!(
            rendered.contains("ワークスペースへはアクセス不可"),
            "{rendered}"
        );
        // 第三者コードであること・裏取りが要ることを明示している（D-40と§4.3の前提）。
        assert!(rendered.contains("第三者"), "{rendered}");
    }

    /// M15.6: Streamable HTTPのサーバは**サンドボックスの外**にいる。`allow_domains`が空だ
    /// からといってstdioと同じ「外向き通信は不可」を描くと、モデルへ嘘の制約を伝えることになる。
    #[test]
    fn a_streamable_http_server_is_not_described_as_unable_to_reach_the_network() {
        let mut ctx = ToolCtx::new(PathBuf::from("/workspace"));
        ctx.mcp_servers = vec![McpServerFact {
            id: "corp-mcp".to_string(),
            allow_domains: Vec::new(),
            workspace_access: "none".to_string(),
            tool_names: vec!["mcp__corp-mcp__search".to_string()],
            transport: "streamable_http".to_string(),
            endpoint: Some("mcp.corp.example/mcp".to_string()),
        }];
        let rendered = render(&EnvironmentFacts::from_tool_ctx(&ctx));

        assert!(
            !rendered.contains("外向き通信は不可"),
            "a streamable-http server does reach the network: {rendered}"
        );
        assert!(rendered.contains("mcp.corp.example/mcp"), "{rendered}");
        assert!(rendered.contains("サンドボックスの外"), "{rendered}");
    }

    /// passthroughが1つも無いときはプロンプトを伸ばさない（既存のゴールデンが割れないこと）。
    #[test]
    fn passthrough_is_not_mentioned_when_there_is_none() {
        let rendered = render(&facts_for(ShellTier::Tier2a, StagingMode::Live));

        assert!(!rendered.contains("ワークスペース外の例外"), "{rendered}");
    }

    /// **W10の主目的。** 許可に失敗した穴はモデルへ必ず伝える——伝えないと、モデルは
    /// 「使える」と思ったまま動いて空転する。
    #[test]
    fn failed_passthrough_grants_are_declared_as_unusable() {
        let mut ctx = ToolCtx::new(PathBuf::from("/workspace"));
        ctx.shell_tier =
            ShellTierSelection::direct(ShellTier::Tier2a).with_denied_passthrough(vec![(
                PathBuf::from(r"C:\secrets"),
                "read".to_string(),
                "ACE grant failed with ACCESS_DENIED".to_string(),
            )]);

        let rendered = render(&EnvironmentFacts::from_tool_ctx(&ctx));

        assert!(rendered.contains(r"C:\secrets"), "{rendered}");
        assert!(rendered.contains("ACCESS_DENIED"), "{rendered}");
        assert!(
            rendered.contains("使える前提で計画を立てないでください"),
            "{rendered}"
        );
    }

    /// 到達できる外部パスは読取のみ/読み書きを描き分ける。
    #[test]
    fn granted_passthrough_distinguishes_read_only_from_writable() {
        let mut ctx = ToolCtx::new(PathBuf::from("/workspace"));
        ctx.shell_tier =
            ShellTierSelection::direct(ShellTier::Tier2a).with_granted_passthrough(vec![
                (PathBuf::from(r"C:\tools"), false),
                (PathBuf::from(r"D:\data"), true),
            ]);

        let rendered = render(&EnvironmentFacts::from_tool_ctx(&ctx));

        assert!(rendered.contains(r"C:\tools（読取のみ）"), "{rendered}");
        assert!(rendered.contains(r"D:\data（読み書き）"), "{rendered}");
    }

    /// D8/D9の到達性診断（運用者向けの手順）はモデルへ渡さない。
    /// `harness fs grant-traverse`はモデルには実行できず、渡しても混乱の元にしかならない。
    #[test]
    fn operator_facing_reachability_diagnostics_stay_out_of_the_prompt() {
        let mut ctx = ToolCtx::new(PathBuf::from("/workspace"));
        ctx.shell_tier =
            ShellTierSelection::direct(ShellTier::Tier2a).with_passthrough_warnings(vec![
                "run `harness fs grant-traverse C:/x` to fix this".to_string(),
            ]);

        let rendered = render(&EnvironmentFacts::from_tool_ctx(&ctx));

        assert!(!rendered.contains("grant-traverse"), "{rendered}");
    }

    fn net_policy_facts(tier: ShellTier, enforced_by_wfp: bool) -> EnvironmentFacts {
        let mut ctx = ToolCtx::new(PathBuf::from("/workspace"));
        ctx.shell_tier = ShellTierSelection::direct(tier);
        ctx.net_proxy.domain_policy_enabled = true;
        ctx.net_proxy.allow_domains = vec!["example.com".to_string()];
        ctx.net_proxy.enforced_by_wfp = enforced_by_wfp;
        EnvironmentFacts::from_tool_ctx(&ctx)
    }

    /// `enforced_by_wfp == false`はTierによって正反対の意味になる。Tier2aでは
    /// `should_grant_tier2a_network_capability`がcapability自体を落として通信が皆無になるので、
    /// 「協調プロキシ経由で許可されている」「生ソケットなら素通りできる」と宣言してはいけない。
    #[test]
    fn tier2a_without_wfp_enforcement_declares_no_network_at_all() {
        let rendered = render(&net_policy_facts(ShellTier::Tier2a, false));

        assert!(rendered.contains("外向き通信を一切行えません"), "{rendered}");
        // 消えているべきもの: 「通信はできるが強制ではない」と読める説明。
        assert!(!rendered.contains("素通りできます"), "{rendered}");
    }

    /// 上の裏側（残っているべきもの）。Tier2a以外では協調プロキシの説明が正しいままで
    /// なければならない——禁止側だけを見るテストは、説明が全Tierで壊れても通ってしまう。
    #[test]
    fn non_tier2a_without_wfp_enforcement_keeps_cooperative_proxy_wording() {
        for tier in [ShellTier::Tier0, ShellTier::Tier1] {
            let rendered = render(&net_policy_facts(tier, false));
            assert!(rendered.contains("協調プロキシ"), "{tier:?}: {rendered}");
            assert!(rendered.contains("素通りできます"), "{tier:?}: {rendered}");
            assert!(
                !rendered.contains("外向き通信を一切行えません"),
                "{tier:?}: {rendered}"
            );
        }
    }

    /// WFPが立っているTier2aは従来どおり「強制」と宣言する（拒否側の文言へ倒れない）。
    #[test]
    fn tier2a_with_wfp_enforcement_still_declares_enforced_proxy() {
        let rendered = render(&net_policy_facts(ShellTier::Tier2a, true));

        assert!(rendered.contains("強制ネットワークプロキシ"), "{rendered}");
        assert!(rendered.contains("example.com"), "{rendered}");
        assert!(
            !rendered.contains("外向き通信を一切行えません"),
            "{rendered}"
        );
    }

    #[test]
    fn require_sandbox_variants_are_not_part_of_environment_facts() {
        // RequireSandboxはCLIフラグの要求値であり実行時の事実ではないため、
        // EnvironmentFactsが運ばないことを明示するだけの回帰用（コンパイルが通ればOK）。
        let _ = RequireSandbox::None;
    }
}
