//! harness-cli: clapエントリ。`plans/DESIGN.md` §非対話（ヘッドレス）モード参照。
//!
//! M1時点では `--print` によるAnthropic/OpenAIへの単発非ストリーム呼び出しのみをサポートする。
//! 対話TUI・ツールループ・LMStudio/Responses variantはM3以降・M6で追加する。

use std::io::Read;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};

use harness_core::LlmProvider;
use harness_engine::{run_single_turn, ConversationState};
use harness_providers::{AnthropicProvider, OpenAiProvider};

const DEFAULT_ANTHROPIC_MODEL: &str = "claude-opus-4-8";
const DEFAULT_MAX_TOKENS: u32 = 4096;

#[derive(Clone, Copy, ValueEnum)]
enum ProviderKind {
    Anthropic,
    Openai,
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
            let api_key = match std::env::var("OPENAI_API_KEY") {
                Ok(key) => key,
                Err(_) => {
                    eprintln!("OPENAI_API_KEY is not set");
                    return ExitCode::FAILURE;
                }
            };
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

    match run_single_turn(provider.as_ref(), &state, model, DEFAULT_MAX_TOKENS).await {
        Ok(outcome) => {
            println!("{}", outcome.text);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("provider error: {e}");
            ExitCode::FAILURE
        }
    }
}
