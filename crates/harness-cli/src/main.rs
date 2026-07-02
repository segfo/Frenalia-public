//! harness-cli: clapエントリ。`plans/DESIGN.md` §非対話（ヘッドレス）モード参照。
//!
//! M2時点では `--print` によるAnthropic/OpenAIへのストリーミング呼び出しをサポートする。
//! 受信したテキストデルタをその場でstdoutへ書き出す（トークン逐次表示、§実装マイルストーン M2）。
//! M3で `read_file`/`run_shell` を登録した `ToolRegistry` を使い `run_agent_loop` へ
//! 切り替えた。M4で `PermissionArbiter` を配線し、`--permission-mode`/`--allow` を追加した。
//! 既定モードは `Default`（read-only自動許可、Write/Exec/Networkはヘッドレスにつき自動拒否、
//! §パーミッション「ヘッドレス時」）で、M3までの「一旦allow-all」から「allowlist-or-deny」へ
//! 切り替わる（§実装マイルストーン M4）。対話TUI・LMStudio/Responses variantはM6/M7で追加する。
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
    #[arg(short = 'p', long = "print")]
    print: String,

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
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let prompt = if cli.print == "-" {
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("failed to read prompt from stdin: {e}");
            return ExitCode::FAILURE;
        }
        buf
    } else {
        cli.print
    };

    // §設定とシークレット: env優先、プロジェクト設定に永続化しない・ログに出さない・起動時fail-fast。
    let provider: Box<dyn LlmProvider> = match cli.provider {
        ProviderKind::Anthropic => {
            let api_key = match std::env::var("ANTHROPIC_API_KEY") {
                Ok(key) => key,
                Err(_) => {
                    eprintln!("ANTHROPIC_API_KEY is not set");
                    return ExitCode::FAILURE;
                }
            };
            match std::env::var("ANTHROPIC_BASE_URL") {
                Ok(base_url) => Box::new(AnthropicProvider::with_base_url(api_key, base_url)),
                Err(_) => Box::new(AnthropicProvider::new(api_key)),
            }
        }
        ProviderKind::Openai => {
            // LMStudioは空キー可（§プロバイダ抽象「LMStudioは空キー可」）なので、
            // 実OpenAIと異なり未設定でもfail-fastしない。
            let api_key = std::env::var("OPENAI_API_KEY").unwrap_or_default();
            match std::env::var("OPENAI_BASE_URL") {
                Ok(base_url) => Box::new(OpenAiProvider::with_base_url(api_key, base_url)),
                Err(_) => Box::new(OpenAiProvider::new(api_key)),
            }
        }
    };

    let model = match (cli.model, cli.provider) {
        (Some(m), _) => m,
        (None, ProviderKind::Anthropic) => DEFAULT_ANTHROPIC_MODEL.to_string(),
        (None, ProviderKind::Openai) => {
            eprintln!("--model is required when --provider openai is used");
            return ExitCode::FAILURE;
        }
    };

    let mut state = ConversationState::new();
    state.push_user_text(prompt);

    let workspace_root = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("failed to resolve current directory: {e}");
            return ExitCode::FAILURE;
        }
    };
    let tools = ToolRegistry::with_builtin_tools();
    let tool_ctx = ToolCtx { workspace_root };

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
