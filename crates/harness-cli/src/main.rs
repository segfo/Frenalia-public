//! harness-cli: clapエントリ。`plans/DESIGN.md` §非対話（ヘッドレス）モード/§リッチTUI参照。
//!
//! M2時点では `--print` によるAnthropic/OpenAIへのストリーミング呼び出しをサポートする。
//! 受信したテキストデルタをその場でstdoutへ書き出す（トークン逐次表示、§実装マイルストーン M2）。
//! M3で `read_file`/`run_shell` を登録した `ToolRegistry` を使い `run_agent_loop` へ
//! 切り替えた。M4で `PermissionArbiter` を配線し、`--permission-mode`/`--allow` を追加した。
//! 既定モードは `Default`（read-only自動許可、Write/Exec/Networkはヘッドレスにつき自動拒否、
//! §パーミッション「ヘッドレス時」）で、M3までの「一旦allow-all」から「allowlist-or-deny」へ
//! 切り替わる（§実装マイルストーン M4）。M6で`--provider lmstudio`を追加した（実体は
//! `OpenAiProvider::lmstudio()`、`base_url=http://localhost:1234/v1`のopenai-familyプロファイル）。
//! M7で`-p/--print`を省略可にし、省略時は`harness-tui`の対話ループへ切り替える
//! （§実装マイルストーン M7「対話でストリーミング描画 + 承認ダイアログ操作」）。
//! `--allow`/`--dangerously-allow`のフラグ体系全体（危険パターンの明示要求等）はM8のスコープの
//! ため、本フェーズは`--allow <tool>:<pattern>`の素朴な繰り返し指定のみをサポートする。

use std::io::{Read, Write};
use std::process::ExitCode;

use clap::{Parser, ValueEnum};

use harness_core::{LlmProvider, ToolCtx};
use harness_engine::{
    parse_allowlist_rule, run_agent_loop, AgentLoopConfig, ConversationState, PermissionArbiter,
    PermissionMode,
};
use harness_providers::{AnthropicProvider, OpenAiProvider};
use harness_tools::ToolRegistry;

const DEFAULT_ANTHROPIC_MODEL: &str = "claude-opus-4-8";
const DEFAULT_MAX_TOKENS: u32 = 4096;
const DEFAULT_MAX_TURNS: usize = 25;

#[derive(Clone, Copy, ValueEnum)]
enum ProviderKind {
    Anthropic,
    Openai,
    Lmstudio,
}

impl ProviderKind {
    fn label(self) -> &'static str {
        match self {
            ProviderKind::Anthropic => "anthropic",
            ProviderKind::Openai => "openai",
            ProviderKind::Lmstudio => "lmstudio",
        }
    }
}

#[derive(Clone, Copy, ValueEnum, Default)]
enum PermissionModeArg {
    Plan,
    #[default]
    Default,
    AcceptEdits,
    AcceptAll,
    Deny,
}

impl From<PermissionModeArg> for PermissionMode {
    fn from(v: PermissionModeArg) -> Self {
        match v {
            PermissionModeArg::Plan => PermissionMode::Plan,
            PermissionModeArg::Default => PermissionMode::Default,
            PermissionModeArg::AcceptEdits => PermissionMode::AcceptEdits,
            PermissionModeArg::AcceptAll => PermissionMode::AcceptAll,
            PermissionModeArg::Deny => PermissionMode::Deny,
        }
    }
}

#[derive(Parser)]
#[command(name = "harness")]
struct Cli {
    /// 非対話モードでプロンプトを送信し、応答をstdoutへ出力する。値が "-" ならstdinから読む。
    /// 省略時は対話TUI（`harness-tui`）を起動する（§リッチTUI、M7）。
    #[arg(short = 'p', long = "print")]
    print: Option<String>,

    /// 使用するモデルID。省略時、Anthropicは既定モデルを使う（OpenAIは省略不可）。
    #[arg(long)]
    model: Option<String>,

    /// 使用するプロバイダ。
    #[arg(long, value_enum, default_value_t = ProviderKind::Anthropic)]
    provider: ProviderKind,

    /// パーミッションモード（§パーミッション（承認）システム「モード」）。
    #[arg(long = "permission-mode", value_enum, default_value_t = PermissionModeArg::default())]
    permission_mode: PermissionModeArg,

    /// allowlistルール（`tool:pattern`形式、繰り返し指定可）。例: `run_shell:git status*`
    #[arg(long = "allow")]
    allow: Vec<String>,

    /// プロバイダのbase_urlを明示指定する（`--provider`に応じて`ANTHROPIC_BASE_URL`/
    /// `OPENAI_BASE_URL`環境変数より優先される。§設定とシークレット「CLIフラグ（最優先）」）。
    /// 例: `--base-url http://localhost:1234/v1`
    #[arg(long = "base-url")]
    base_url: Option<String>,
}

fn build_provider(kind: ProviderKind, base_url_override: Option<String>) -> Result<Box<dyn LlmProvider>, String> {
    // §設定とシークレット: CLIフラグ > env優先、プロジェクト設定に永続化しない・ログに出さない・
    // 起動時fail-fast。
    match kind {
        ProviderKind::Anthropic => {
            let api_key =
                std::env::var("ANTHROPIC_API_KEY").map_err(|_| "ANTHROPIC_API_KEY is not set".to_string())?;
            match base_url_override.or_else(|| std::env::var("ANTHROPIC_BASE_URL").ok()) {
                Some(base_url) => Ok(Box::new(AnthropicProvider::with_base_url(api_key, base_url))),
                None => Ok(Box::new(AnthropicProvider::new(api_key))),
            }
        }
        ProviderKind::Openai => {
            // LMStudioは空キー可（§プロバイダ抽象「LMStudioは空キー可」）なので、
            // 実OpenAIと異なり未設定でもfail-fastしない。
            let api_key = std::env::var("OPENAI_API_KEY").unwrap_or_default();
            match base_url_override.or_else(|| std::env::var("OPENAI_BASE_URL").ok()) {
                Some(base_url) => Ok(Box::new(OpenAiProvider::with_base_url(api_key, base_url))),
                None => Ok(Box::new(OpenAiProvider::new(api_key))),
            }
        }
        // §設定「LMStudio は単に base_url=http://localhost:1234/v1 の openai-family
        // プロファイル」。`--base-url`/`OPENAI_API_KEY`/`OPENAI_BASE_URL`での上書きも許す。
        ProviderKind::Lmstudio => {
            let api_key = std::env::var("OPENAI_API_KEY").unwrap_or_default();
            match base_url_override.or_else(|| std::env::var("OPENAI_BASE_URL").ok()) {
                Some(base_url) => Ok(Box::new(OpenAiProvider::with_base_url(api_key, base_url))),
                None => Ok(Box::new(OpenAiProvider::lmstudio())),
            }
        }
    }
}

fn resolve_model(model: Option<String>, kind: ProviderKind) -> Result<String, String> {
    match (model, kind) {
        (Some(m), _) => Ok(m),
        (None, ProviderKind::Anthropic) => Ok(DEFAULT_ANTHROPIC_MODEL.to_string()),
        (None, ProviderKind::Openai) => Err("--model is required when --provider openai is used".into()),
        (None, ProviderKind::Lmstudio) => {
            Err("--model is required when --provider lmstudio is used".into())
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    // カレントディレクトリの`.env`があれば読み込み、プロセスのenvへ反映する（既存の環境変数は
    // 上書きしない、§設定とシークレット「ユーザ/プロジェクト設定」相当の簡易版）。無ければ無視する。
    let _ = dotenvy::dotenv();

    let cli = Cli::parse();

    let provider = match build_provider(cli.provider, cli.base_url) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let model = match resolve_model(cli.model, cli.provider) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    let workspace_root = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("failed to resolve current directory: {e}");
            return ExitCode::FAILURE;
        }
    };
    let tools = ToolRegistry::with_builtin_tools();
    let tool_ctx = ToolCtx {
        workspace_root: workspace_root.clone(),
    };

    let allowlist: Vec<_> = cli
        .allow
        .iter()
        .filter_map(|rule| {
            let parsed = parse_allowlist_rule(rule);
            if parsed.is_none() {
                eprintln!("ignoring malformed --allow rule (expected tool:pattern): {rule}");
            }
            parsed
        })
        .collect();
    let arbiter = PermissionArbiter::new(cli.permission_mode.into(), allowlist);

    match cli.print {
        Some(print) => {
            let prompt = if print == "-" {
                let mut buf = String::new();
                if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
                    eprintln!("failed to read prompt from stdin: {e}");
                    return ExitCode::FAILURE;
                }
                buf
            } else {
                print
            };

            let mut state = ConversationState::new();
            state.push_user_text(prompt);

            let mut stdout = std::io::stdout();
            let result = run_agent_loop(
                provider.as_ref(),
                &mut state,
                &tools,
                &tool_ctx,
                &arbiter,
                AgentLoopConfig {
                    model,
                    max_tokens: DEFAULT_MAX_TOKENS,
                    max_turns: DEFAULT_MAX_TURNS,
                },
                None,
                |delta| {
                    let _ = stdout.write_all(delta.as_bytes());
                    let _ = stdout.flush();
                },
            )
            .await;

            match result {
                Ok(_) => {
                    println!();
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("provider error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        None => {
            let log_dir = workspace_root.join(".harness").join("logs");
            if let Err(e) = std::fs::create_dir_all(&log_dir) {
                eprintln!("failed to create log directory {}: {e}", log_dir.display());
                return ExitCode::FAILURE;
            }
            // tracing出力先をファイルへ切り替えた後でなければTUI側の`tracing::debug!`等が
            // 直接stdoutを汚してしまう（§リッチTUI「tracingは全てtracing-appenderでファイルへ」）。
            let _log_guard = harness_tui::init_file_logging(&log_dir);

            let result = harness_tui::run(
                provider,
                tools,
                tool_ctx,
                arbiter,
                model,
                DEFAULT_MAX_TOKENS,
                DEFAULT_MAX_TURNS,
                cli.provider.label().to_string(),
            )
            .await;

            match result {
                Ok(_) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("tui error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
