//! harness-providers: `LlmProvider` の実装群。§プロバイダ抽象参照。
//! M6時点でAnthropic・OpenAI（tool_calls対応、LMStudioは`OpenAiProvider::lmstudio()`で同一コードパス）・
//! mock（テスト用スクリプトプロバイダ）の3種。OpenAI Responses variantは後続マイルストーンで追加する
//! （`openai.rs`冒頭コメント参照）。

pub mod anthropic;
pub mod decide;
pub mod mock;
pub mod openai;

pub use anthropic::AnthropicProvider;
pub use decide::DecideClient;
pub use mock::MockProvider;
pub use openai::OpenAiProvider;
