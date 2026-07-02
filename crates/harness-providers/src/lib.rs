//! harness-providers: `LlmProvider` の実装群。
//! M1時点ではAnthropic・OpenAIの2種（いずれも自前reqwest・非ストリーム）。
//! §プロバイダ抽象参照。OpenAIの `async-openai` 経由への移行はM6で行う（`openai.rs` 冒頭コメント参照）。

pub mod anthropic;
pub mod openai;

pub use anthropic::AnthropicProvider;
pub use openai::OpenAiProvider;
