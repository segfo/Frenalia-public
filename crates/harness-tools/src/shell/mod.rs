//! `run_shell`。`plans/DESIGN.md` §ツールシステム「run_shell」・§主なリスクと対策
//! 「Windowsのシェルとパス」、および`plans/DESIGN-SANDBOX.md` §6（M12）参照。
//!
//! **Windowsのシェル選択**（§実装マイルストーン M5）: pwsh7が`PATH`上に見つかればそれを、
//! 無ければ Windows PowerShell 5.1（`powershell.exe`）へフォールバックする。両者は演算子が
//! 異なる（5.1に`&&`/`||`が無い）ため、allowlistのコマンド分解が対象文法に依存する場合に備え
//! **どちらを起動したかを出力へ記録**する（§ツールシステム「シェル選択」）。
//! `-Command`への文字列補間はargvクォートバグを踏むため避け、コマンド文字列は**stdin経由**
//! （`-Command -`）で渡す。`-NoProfile -NonInteractive`を付与する。
//!
//! **M12（シェル隔離Tier）**: 子プロセスのenvは常にallowlist方式のクリーンenv
//! （`harness_sandbox::build_child_env`、D-07）。`ctx.shell_tier`（`harness-cli`が起動時に
//! 1回選択）に応じて実際の隔離機構を切り替える:
//! - Windows Tier1: Restricted Token + 低IL + Job Object（`harness_sandbox::tier1::win_restricted`）。
//! - Linux Tier2b: `bwrap`でラップ（`harness_sandbox::tier2b::linux_bwrap`）。本セッションでは実機未検証
//!   （Windows専用環境、WSL2で別途再検証が必要）。
//! - Tier0（保険・全OS）: 通常spawn + Job Object(Win)/rlimit(unix) + 出力バイト上限。
//!
//! 危険構文（`-EncodedCommand`・`iex`/`Invoke-Expression`・`Start-Process`・`cmd /c`・
//! 入れ子インタプリタ）を検出したら`AcceptEdits`下でも強制的にプロンプトへ落とす
//! （T-09、`harness-engine::permission::looks_like_allowlist_bypass`）。
//!
//! # モジュール構成
//!
//! 本体が1,000行（`docs/CODE-STRUCTURE-RULES.md`規則1）を超えたため、規則3の軸1
//! （どの外部システムと話すか）で4つへ分けた。**この`mod.rs`はモデルと話す面だけを持つ**——
//! 入力スキーマ・`Tool` trait実装・結果フッタの組み立て。
//!
//! | モジュール | 話す相手 |
//! |---|---|
//! | [`net_decision`] | 誰とも話さない（アプリ単位network制御の純粋な判定、D-10/D-11） |
//! | [`env`] | 誰とも話さない（`PATH`の合成と出力バイト上限の純粋関数） |
//! | [`runner`] | Tierごとの隔離機構（Restricted Token / AppContainer / bwrap / Incus / 素のspawn） |
//! | [`platform`] | シェル実行ファイルそのもの（起動・stdinブートストラップ・コンソール符号化） |
//! | [`program`] | `run_program`（シェルを通さずプログラムを直接起こす、D-96）。隔離・環境・フッタはここと共有する |

mod env;
mod net_decision;
mod platform;
mod program;
mod runner;
/// [BUG-208] Tier1が作業フォルダへ低ILラベルを付けられなかったことを、利用者とモデルへ言う文。
#[cfg(windows)]
mod tier1_label;
/// [段階6f-3] 拒否された遷移を、モデルが読める1行にする（§19.3.8）。
/// **ツールの名前を持っている側に置いてある**（同ファイルのモジュールdoc）。
mod transition_note;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use tokio::time::Duration;

use harness_core::{parse_tool_input, CommandSubject, PermissionSubject};
use harness_core::{RiskClass, ShellTier, StagingMode, Tool, ToolCtx, ToolError, ToolOutput};
use harness_sandbox::check_relative_path;

use crate::jail_error_to_tool_error;

use env::{append_path_extra, truncate_to_limit};
use net_decision::classify_net_app;
use platform::{merge_startup_noise, split_shell_startup_noise};
use runner::run_isolated;

/// Tier1でコマンドを走らせる4番目の経路（`harness-policy-editor`の記録モード）が使う。
/// 実体と doc は[`platform`]が持つ——印や変数名の綴りを複製しないため（B-05）。
#[cfg(windows)]
pub use platform::{
    run_shell_bootstrap_stdin, RUN_SHELL_COMMAND_ENV_VAR, RUN_SHELL_OUTPUT_SENTINEL,
};

/// Tier2aでコマンドを走らせる5番目の経路（`harness-policy-editor`のパス2）が使う。
/// **同じ規則に従わせるための公開**であって、判定を作り直させないためのもの（[`net_decision`]）。
pub use net_decision::{should_grant_tier2a_network_capability, NetDecision};

/// `run_program`（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` §2）。ツール名は判定器が名指すのに使う。
pub use program::{RunProgramTool, RUN_PROGRAM_TOOL};

#[derive(Deserialize)]
// 知らない項目は拒否する（BUG-164・D-101）。余分な項目を黙って捨てると、判定だけを騙す細工を
// 最後まで通す部品になる。
#[serde(deny_unknown_fields)]
struct RunShellInput {
    command: String,
    timeout_ms: Option<u64>,
    cwd: Option<String>,
}

/// `run_shell`の実体。
///
/// # なぜ`Default`が「Tier2aでは使えない値」なのか
///
/// Tier2aのトップレベル生成はSpawn Daemon経由でしか行わない（`plans/DESIGN-MAC-PROTOCOL.md`
/// §12）。接続を持たない`RunShellTool`はTier2aの呼び出しを**内部エラーで断る**
/// ——直接生成へ降格させない（降格すると、遷移MACが効いていないのに効いているように見える）。
///
/// **`Default`は「接続なし」を意味するので、書く側が毎回それを選んでいる形にしてある。**
/// かつてここには型と同じ名前の`const RunShellTool`があり、既存の`let tool = RunShellTool;`を
/// 1行も直さずに通していた。**その形だと、将来書かれる箇所も黙って接続なしを掴む**
/// ——しかも失敗するのはTier2aで実際に走った瞬間だけである（`B-10`: 無言で安全側から外れない）。
#[derive(Default)]
pub struct RunShellTool {
    #[cfg(windows)]
    spawn_daemon: Option<harness_sandbox::tier2a::spawnd::SharedSpawnDaemon>,
    /// [段階6f-3] 拒否された遷移を出力末尾へ注記するか（§19.3.8）。
    ///
    /// # なぜ自分で判定しないのか
    ///
    /// **注記は「`can_run_program`を引け」とモデルへ言う。** そのツールを登録するかどうかを
    /// 決めているのは`harness-cli`の`should_expose`（Tier2a・Daemon在り・生成禁止の3条件）で、
    /// **同じ値を配らないと、ツールが登録されていない構成で「引け」と書く**ことになる。
    /// 判定を2箇所に置かない（`B-06`）。
    ///
    /// **偽なら待ち行列のファイルに1度も触らない。** 今日の製品は生成禁止を積まないので
    /// 拒否が1件も起きず、費用はゼロである。
    #[cfg(windows)]
    report_transition_denials: bool,
}

impl RunShellTool {
    /// Tier2aのセッションが持つSpawn Daemon接続を注入する。**本番のTier2a経路は必ずこちら**
    /// （`harness-cli`の`stage_run_agent`が、preflightの後に1本だけ起こして渡す）。
    ///
    /// [段階6f-3] `report_transition_denials`は**呼び出し元が必ず選ぶ**
    /// （[`RunShellTool::report_transition_denials`]のdoc）。既定値を持たせないのは、
    /// 渡し忘れた経路が黙って「注記しない」側へ落ちるのを避けるためである。
    #[cfg(windows)]
    pub fn with_spawn_daemon(
        spawn_daemon: harness_sandbox::tier2a::spawnd::SharedSpawnDaemon,
        report_transition_denials: bool,
    ) -> Self {
        Self {
            spawn_daemon: Some(spawn_daemon),
            report_transition_denials,
        }
    }

    /// [段階6f-3] Daemonを持たないまま注記だけを試すための入口（**テスト専用**）。
    ///
    /// 本番では`should_expose`がDaemonの存在を条件に含むので、この組み合わせは起きない。
    /// **配線そのものを昇格なしで測れるようにするため**にだけ在る（段階6eが
    /// `should_expose`を関数へ切り出したのと同じ理由）。
    #[cfg(all(windows, test))]
    pub(crate) fn reporting_transition_denials() -> Self {
        Self {
            spawn_daemon: None,
            report_transition_denials: true,
        }
    }
}

/// [段階6f-3] コマンドを走らせる前の「ここまで既読」の位置。
///
/// **注記しない構成では`None`を返し、ファイルに1度も触らない。**
///
/// `run_shell`と`run_program`が共有する。どちらも同じTier2aの子を起こすので、
/// 断られた遷移をモデルへ届ける規則も同じでなければならない（`B-05`）。
#[cfg(windows)]
fn transition_queue_cursor(report: bool, workspace_root: &std::path::Path) -> Option<u64> {
    if !report {
        return None;
    }
    let path = harness_sandbox::tier2a::spawnd::transitions::pending_path(workspace_root);
    // 無ければ0から。**存在しないことは失敗ではない**（`read_from`のdoc）。
    Some(std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0))
}

/// [段階6f-3] コマンドの間に積まれた拒否を、出力へ足す1行にする（§19.3.8）。
///
/// # 書き出しを頼めなかったら、何も言わない
///
/// 待ち行列は**畳んで書く**ので、頼まないとカウントが実際より遅れる。頼めなかった回に
/// 古い値を読んで「このコマンドでは断られていない」と書くのは、**何も書かないより悪い**
/// （`P-11`: 観測していないものを既定値で埋めない）。
#[cfg(windows)]
fn transition_denial_note(
    spawn_daemon: Option<&harness_sandbox::tier2a::spawnd::SharedSpawnDaemon>,
    workspace_root: &std::path::Path,
    cursor: Option<u64>,
) -> Option<String> {
    let offset = cursor?;
    if let Some(daemon) = spawn_daemon {
        if let Err(e) = daemon.flush_transition_queue() {
            // **黙らせない**（`B-10`）。注記は出さないが、出せなかったことは残す。
            eprintln!("note: could not flush the transition denial queue: {e}");
            return None;
        }
    }
    let path = harness_sandbox::tier2a::spawnd::transitions::pending_path(workspace_root);
    let tail = harness_sandbox::tier2a::spawnd::transitions::read_from(&path, offset);
    transition_note::note(&tail.records)
}

/// `run_shell`と`run_program`が子へ渡す環境と、実行の間生かしておくネットワーク監査の部品。
///
/// **2つのツールは同じ隔離の中で子を起こすので、子へ渡すものも同じでなければならない**
/// （秘密を除いたenv・`path_extra`・gitのハードニング・プロキシ）。片方にだけ足すと、
/// 同じTierで動いているのに片方の子だけ見えるものが違う、が起きる（`B-05`）。
struct PreparedRun {
    env: Vec<(String, String)>,
    /// 監査ログの置き場を補った後の設定。フッタが読む。
    net_proxy: harness_core::NetProxyConfig,
    /// **実行が終わるまで生かしておく**（落とすとプロキシが止まる）。フッタが監査を読む。
    proxy: Option<crate::net_proxy::LocalProxy>,
    /// 同上。
    fake_dns: Option<crate::fake_dns::FakeDnsAgent>,
    proxy_addr: Option<std::net::SocketAddr>,
}

/// 子へ渡す環境を組み、要ればプロキシと偽DNSを立てる（[`PreparedRun`]のdoc）。
async fn prepare_run(ctx: &ToolCtx) -> PreparedRun {
    let mut env = harness_sandbox::build_child_env();
    append_path_extra(&mut env, &ctx.run_shell_path_extra);
    // D-14b: モデル実行`git`のhooks/fsmonitor/pagerを無効化する（T-07対策、
    // `harness_sandbox::git_hardening_env`のdoc参照）。envは全子孫プロセスへ自動継承される
    // ため、`git`が孫プロセスとして起動されても届く。
    env.extend(harness_sandbox::git_hardening_env());

    // 協調プロキシ（M12補遺、`plans/DESIGN-SANDBOX-PRIVSEP.md` §3.1 D-15、
    // `plans/AppContainerを用いたドメインベース通信制御アーキテクチャ設計書.md` §5）。
    // `ctx.net_proxy.domain_policy_enabled`なら、`allow_domains`が空でも全拒否ポリシーとして
    // Proxy/Fake DNS監査経路を起動する。SOCKS5 remote DNSを主経路とする`ALL_PROXY`と、
    // 既存HTTP(S)ツール互換の`HTTP_PROXY`/`HTTPS_PROXY`を子envへ足す。
    //
    // 監査ログの置き場（`net_proxy.audit_log_path`）は**起動時に1度だけ決まる**
    // （`harness-cli`の`startup::sandbox`。書込の捕まえ方に関係なく全セッションで作る）。
    // かつてはここで`--staged`の置き場から導き直していたが、それは監査ログを書込の捕まえ方へ
    // 結び付ける2つ目の点だった（D-90 反転の前提(3)）。
    let net_proxy = ctx.net_proxy.clone();
    let proxy = if net_proxy.proxy_addr.is_some() {
        None
    } else {
        crate::net_proxy::spawn_local_proxy(&net_proxy)
            .await
            .ok()
            .flatten()
    };
    let fake_dns = if net_proxy.fake_dns_addr.is_some() {
        None
    } else if net_proxy.domain_policy_enabled {
        crate::fake_dns::spawn_fake_dns(&crate::fake_dns::FakeDnsConfig {
            allow_domains: net_proxy.allow_domains.clone(),
            policy_required: net_proxy.domain_policy_enabled,
            audit_log_path: net_proxy.audit_log_path.clone(),
            preferred_port: None,
        })
        .await
        .ok()
    } else {
        None
    };
    let proxy_addr = net_proxy
        .proxy_addr
        .or_else(|| proxy.as_ref().map(|p| p.addr));
    let fake_dns_addr = net_proxy
        .fake_dns_addr
        .or_else(|| fake_dns.as_ref().map(|dns| dns.addr));
    env.extend(crate::net_proxy::proxy_env_vars(proxy_addr, fake_dns_addr));

    PreparedRun {
        env,
        net_proxy,
        proxy,
        fake_dns,
        proxy_addr,
    }
}

/// 入力の`cwd`をワークスペース内の絶対パスへ解決する。省略時はワークスペースルート。
fn resolve_cwd(cwd: Option<&str>, ctx: &ToolCtx) -> Result<std::path::PathBuf, ToolError> {
    match cwd {
        Some(c) => {
            let rel = check_relative_path(c).map_err(|e| jail_error_to_tool_error(c, e))?;
            Ok(ctx.workspace_root.join(rel))
        }
        None => Ok(ctx.workspace_root.clone()),
    }
}

/// 選ばれたTierで子を起こす。`run_shell`と`run_program`で違うのは`launch`と`net_decision`だけ。
async fn run_in_tier(
    launch: runner::Launch<'_>,
    cwd: &std::path::Path,
    dur: Duration,
    net_decision: NetDecision,
    ctx: &ToolCtx,
    prepared: &PreparedRun,
    #[cfg(windows)] spawn_daemon: Option<&harness_sandbox::tier2a::spawnd::SharedSpawnDaemon>,
) -> Result<runner::IsolatedRun, ToolError> {
    run_isolated(
        launch,
        cwd,
        &prepared.env,
        dur,
        ctx.shell_tier.tier,
        net_decision,
        ctx.net_proxy.enforced_by_wfp && ctx.net_proxy.domain_policy_enabled,
        ctx.net_proxy.domain_policy_enabled,
        ctx.vm_sandbox.as_ref(),
        &ctx.workspace_root,
        ctx.cow_diff_layer_dir.as_deref(),
        &ctx.shell_tier.granted_passthrough,
        #[cfg(windows)]
        spawn_daemon,
    )
    .await
}

/// 標準出力と標準エラーを、上限で切ってから1つにつなぐ。
fn join_output(out: String, err: String) -> String {
    let mut content = truncate_to_limit(out);
    let err = truncate_to_limit(err);
    if !err.is_empty() {
        if !content.is_empty() {
            content.push('\n');
        }
        content.push_str(&err);
    }
    content
}
const DEFAULT_TIMEOUT_MS: u64 = 120_000;
const RUN_SHELL_DEFAULT_DESCRIPTION: &str =
    "ワークスペース内でシェルコマンドを実行し、stdout+stderr+終了コードを返す。\
         ネットワーク許可アプリ（--net-allow-app）を使う場合は、|・&&・;等で他コマンドと連結せず、\
         単一コマンドとして発行すること（連結すると通信が拒否される）。";

const RUN_SHELL_TIER3_DESCRIPTION: &str =
    "Tier3のLinuxコンテナ内ワークスペースでシェルコマンドを実行し、\
         stdout+stderr+終了コードを返す。コマンドはAlmaLinux VM内のIncusコンテナで`sh -c`として\
         実行されるため、POSIX sh互換の構文とLinuxパスを使うこと。Windows専用コマンドレットや\
         `$env:...`構文は使わない。";

fn run_shell_input_schema(command_description: &str, cwd_description: &str) -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "command": { "type": "string", "description": command_description },
            "timeout_ms": { "type": "integer", "description": "タイムアウト（ミリ秒、省略時120000）" },
            "cwd": { "type": "string", "description": cwd_description }
        },
        "required": ["command"],
        "additionalProperties": false
    })
}
#[async_trait]
impl Tool for RunShellTool {
    fn name(&self) -> &str {
        "run_shell"
    }

    fn description(&self) -> &str {
        RUN_SHELL_DEFAULT_DESCRIPTION
    }

    fn input_schema(&self) -> serde_json::Value {
        run_shell_input_schema(
            "実行するシェルコマンド",
            "ワークスペースルートからの相対作業ディレクトリ",
        )
    }

    fn spec_for_ctx(&self, ctx: &ToolCtx) -> harness_core::ToolSpec {
        if ctx.shell_tier.tier == ShellTier::Tier3 {
            harness_core::ToolSpec {
                name: self.name().to_string(),
                description: RUN_SHELL_TIER3_DESCRIPTION.to_string(),
                input_schema: run_shell_input_schema(
                    "AlmaLinux VM内のIncusコンテナで`sh -c`へ渡すコマンド。POSIX sh互換の構文とLinuxパスを使う",
                    "`/workspace`からの相対作業ディレクトリ",
                ),
            }
        } else {
            harness_core::ToolSpec {
                name: self.name().to_string(),
                description: self.description().to_string(),
                input_schema: self.input_schema(),
            }
        }
    }

    fn risk(&self, _input: &serde_json::Value) -> RiskClass {
        RiskClass::Exec
    }

    /// 判定の材料（D-101）。行に字面で現れるワークスペース内のファイルを、子が読むのと同じ見え方で
    /// 縛る（D-102）。ファイルを読むので`spawn_blocking`で走らせる（B-31）。
    async fn permission_subject(
        &self,
        input: &serde_json::Value,
        ctx: &ToolCtx,
    ) -> Result<PermissionSubject, ToolError> {
        let input: RunShellInput = parse_tool_input(input)?;
        let cwd = resolve_cwd(input.cwd.as_deref(), ctx)?;
        let line = input.command;
        let ctx = ctx.clone();
        tokio::task::spawn_blocking(move || {
            // [BUG-224] 行に符号化された中身があれば、ハーネスが機械的に解読して承認画面と要約へ渡す
            // （§4.4）。**解読そのものは照合に使わない**——`ShellRule::matches`も`same_for_approval`も
            // `decoded`欄を見ない。解読は`run_program`と同じ関数を通る（綴りの表を2箇所に持たない、B-05）。
            let decoded = crate::encoded_command::decode_shell_line(&line);
            let binding = match crate::approval_binding::ChildView::for_ctx(&ctx) {
                Ok(view) => crate::approval_binding::bind_everything(&view, &cwd, &line, &decoded),
                // 見え方を開けなければ、何も確かめられない。記録と照合しない。
                Err(_) => crate::approval_binding::ShellBinding {
                    unverifiable: true,
                    ..Default::default()
                },
            };
            // 縛ったファイルの中身に入っている符号化された塊も解読する（D-122）。
            // 行だけを解いていては、`os.remove("pwsh --enc <塊>")` の中までは届かない。
            let mut decoded = decoded;
            decoded.extend(crate::approval_binding::decode_in_files(
                &binding.previews,
                true,
            ));
            PermissionSubject::Command(CommandSubject {
                line,
                files: binding.files,
                unverifiable: binding.unverifiable,
                previews: binding.previews,
                decoded,
            })
        })
        .await
        .map_err(|e| ToolError::ExecutionFailed(format!("permission subject task failed: {e}")))
    }

    async fn call(&self, input: serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let input: RunShellInput = parse_tool_input(&input)?;

        let cwd = resolve_cwd(input.cwd.as_deref(), ctx)?;
        let dur = Duration::from_millis(input.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS));
        let prepared = prepare_run(ctx).await;
        let net_decision = classify_net_app(&input.command, &ctx.net_app.allow_apps);

        // [段階6f-3] **コマンドを走らせる前に、待ち行列のどこまでが既読かを控える**（§19.3.8）。
        // 後から控えると、走っている間に積まれた拒否を「前からあったもの」として読み飛ばす。
        #[cfg(windows)]
        let transition_cursor =
            transition_queue_cursor(self.report_transition_denials, &ctx.workspace_root);

        let runner::IsolatedRun {
            out,
            err,
            code,
            launch_label: shell_label,
            setup_warning,
        } = run_in_tier(
            runner::Launch::Shell {
                command: &input.command,
            },
            &cwd,
            dur,
            net_decision,
            ctx,
            &prepared,
            #[cfg(windows)]
            self.spawn_daemon.as_ref(),
        )
        .await?;

        let code = code.unwrap_or(-1);
        // シェルがコマンドを走らせる前に吐いた分を切り離す（`RUN_SHELL_OUTPUT_SENTINEL`）。
        // 捨てずにフッターへ回すだけ——混ざったままだと、標準出力を持たないコマンドで
        // 「シェルの起動時警告」が唯一の出力になり、失敗と見分けが付かない。
        let (out_noise, out) = split_shell_startup_noise(&out);
        let (err_noise, err) = split_shell_startup_noise(&err);
        let mut content = join_output(out, err);
        content.push_str(&format!("\n[exit code: {code}]\n[shell: {shell_label}]"));
        if let Some(noise) = merge_startup_noise(&out_noise, &err_noise) {
            content.push_str(&format!(
                "\n[shell-startup-noise (コマンドの実行前にシェル自身が出したもの。\
                 コマンドの結果には影響しない): {}]",
                truncate_to_limit(noise).replace('\n', " / ")
            ));
        }
        // [段階6f-3] このコマンドの間に断られた遷移を、モデルへ届ける（§19.3.8）。
        #[cfg(windows)]
        let transition_note = transition_denial_note(
            self.spawn_daemon.as_ref(),
            &ctx.workspace_root,
            transition_cursor,
        );
        #[cfg(not(windows))]
        let transition_note = None;
        push_run_footer(
            &mut content,
            ctx,
            net_decision,
            setup_warning,
            transition_note,
            &prepared,
        );

        Ok(ToolOutput {
            content,
            is_error: code != 0,
        })
    }
}

/// 出力の末尾に付けるフッタのうち、`run_shell`と`run_program`で共通の部分
/// （着地したTier・子を起こす前の準備の警告・ネットワーク許可アプリ・断られた遷移・非隔離と
/// ステージングの警告・プロキシと偽DNSの監査）。**文言と順序はここ1箇所が持つ**（`B-05`）。
///
/// `setup_warning`は[`runner::IsolatedRun::setup_warning`]（[BUG-208]: Tier1が作業フォルダへ
/// 低ILラベルを付けられなかった）。文そのものは利用者へ出すstderrの行と同じものである。
///
/// [BUG-208]: ../../../../docs/bugs/BUG-208.md
fn push_run_footer(
    content: &mut String,
    ctx: &ToolCtx,
    net_decision: NetDecision,
    setup_warning: Option<String>,
    transition_note: Option<String>,
    prepared: &PreparedRun,
) {
    let net_domain_policy_requested = ctx.net_proxy.domain_policy_enabled;
    let PreparedRun {
        net_proxy,
        proxy,
        fake_dns,
        proxy_addr,
        ..
    } = prepared;
    // 着地したTierだけを出す。**「(downgraded from ...)」はもう付かない**——D-75で
    // 降格が消え、`select_tier`が返した時点で要求どおりのTierに居るためである。
    content.push_str(&format!("\n[tier: {}]", ctx.shell_tier.tier.label()));
    if let Some(warning) = setup_warning {
        content.push_str(&format!("\n[warning: {warning}]"));
    }
    if !ctx.net_app.allow_apps.is_empty() {
        match (
            net_domain_policy_requested,
            net_decision,
            ctx.shell_tier.tier,
        ) {
            (true, _, ShellTier::Tier2a) if ctx.net_proxy.enforced_by_wfp => {
                content.push_str("\n[net: domain policy enforced; --net-allow-app ignored]");
            }
            (true, _, ShellTier::Tier2a) => {
                content.push_str(
                    "\n[net: denied (domain policy requested but WFP enforcement is unavailable; \
                     --net-allow-app ignored)]",
                );
            }
            (true, _, other_tier) => {
                content.push_str(&format!(
                    "\n[net: denied (--net-allow-domain takes precedence over --net-allow-app; \
                     current tier is {})]",
                    other_tier.label()
                ));
            }
            (false, NetDecision::Allow, ShellTier::Tier2a) => {
                content.push_str("\n[net: internetClient]");
            }
            (false, NetDecision::Allow, other_tier) => {
                content.push_str(&format!(
                    "\n[net: denied (--net-allow-app only takes effect under Tier2a; \
                     current tier is {})]",
                    other_tier.label()
                ));
            }
            (false, NetDecision::DeniedByChaining, _) => {
                content.push_str(
                    "\n[net: denied (chained command; issue the trusted app as a single \
                     command without |, &&, ;, & to allow network)]",
                );
            }
            (false, NetDecision::Deny, _) => {
                content.push_str("\n[net: denied]");
            }
        }
    }
    if let Some(note) = transition_note {
        content.push('\n');
        content.push_str(&note);
    }
    if ctx.shell_tier.is_unisolated() {
        content.push_str(
            "\n[warning: shell isolation tier is tier0 (best-effort only); \
             out-of-workspace writes/network egress are not blocked, see plans/DESIGN-SANDBOX.md §9]",
        );
    }
    if !matches!(ctx.staging.mode, StagingMode::Live) && !ctx.shell_sees_staged_writes {
        content.push_str(
            "\n[warning: staged writes made earlier in this turn may not be visible to this \
             shell process yet (D-08 simplification, see plans/DESIGN-SANDBOX.md §8-3)]",
        );
    }
    if proxy_addr.is_some() {
        // `proxy_addr`が立っている＝`domain_policy_enabled`である（`spawn_local_proxy`は
        // 無効なら`Ok(None)`を返す）。その上で「WFP未成立」の意味はTierで正反対になる——
        // Tier2aでは`should_grant_tier2a_network_capability`がcapability自体を落とすので、
        // 「audit-only（＝通信はできるが強制されない）」ではなく通信が皆無になる。
        // 同じ誤りが起動時警告とシステムプロンプトにもあった。
        //
        // [BUG-118] **`== Tier2a`で分岐しない。** かつてここは`else`に
        // 「audit-only（素通り可）」を置いていたので、Tier2b（`--unshare-net`で全遮断）と
        // Tier3（VM境界で強制）が**実挙動の逆**を名乗っていた。判定は`ShellTier::net_egress`が
        // 1箇所で持ち、Tierを足すとそちらがコンパイルエラーになる（`B-05`/`B-06`）。
        match ctx
            .shell_tier
            .tier
            .net_egress(ctx.net_proxy.enforced_by_wfp)
            .enforcement
        {
            harness_core::EgressEnforcement::Wfp => {
                content.push_str("\n[net-proxy: enforced-by-wfp]");
            }
            harness_core::EgressEnforcement::NoEgressAtAll => {
                content.push_str(
                    "\n[net-proxy: unreachable (this tier grants no reachable network at all; \
                     the child cannot open any socket, not even to this proxy)]",
                );
            }
            harness_core::EgressEnforcement::VmBoundary => {
                content.push_str(
                    "\n[net-proxy: not used (tier3 enforces egress at the VM boundary; this \
                     host-side proxy is not on the path and its env vars are not forwarded)]",
                );
            }
            harness_core::EgressEnforcement::Cooperative => {
                content.push_str("\n[net-proxy: audit-only, not enforced against raw sockets, see plans/DESIGN-SANDBOX-PRIVSEP.md §3.1]");
            }
        }
        if let Some(p) = proxy {
            if let Some(path) = p.audit.path() {
                content.push_str(&format!("\n[net-proxy-audit: {}]", path.display()));
            }
        } else if let Some(path) = &net_proxy.audit_log_path {
            content.push_str(&format!("\n[net-proxy-audit: {}]", path.display()));
        }
        if let Some(p) = proxy {
            for e in p.audit.entries() {
                let verdict = if e.allowed { "ALLOW" } else { "DENY" };
                content.push_str(&format!("\n[net-proxy: {verdict} {}]", e.host));
            }
        }
    }
    if let Some(dns) = fake_dns {
        content.push_str(&format!(
            "\n[net-fakedns: diagnostic-only addr={}]",
            dns.addr
        ));
        if let Some(path) = dns.audit.path() {
            content.push_str(&format!("\n[net-fakedns-audit: {}]", path.display()));
        }
        for e in dns.audit.entries() {
            content.push_str(&format!(
                "\n[net-fakedns: QUERY {} {} fake_ip={}]",
                e.qtype,
                e.host,
                e.fake_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "none".to_string())
            ));
        }
    }
    if fake_dns.is_none() {
        if let Some(addr) = net_proxy.fake_dns_addr {
            content.push_str(&format!("\n[net-fakedns: diagnostic-only addr={addr}]"));
            if let Some(path) = &net_proxy.audit_log_path {
                content.push_str(&format!("\n[net-fakedns-audit: {}]", path.display()));
            }
        }
    }
}

#[cfg(test)]
#[path = "shell_tests.rs"]
mod shell_tests;

/// `run_shell`と`run_program`のテストが共有する部品（実台帳を触る後始末を1箇所に置く）。
#[cfg(test)]
mod test_support;
