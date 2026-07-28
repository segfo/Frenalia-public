//! harness-core: 共有語彙（IR）とtrait定義。プロバイダ非依存・フロントエンド非依存。
//! `plans/DESIGN.md` §全体アーキテクチャ 参照。

pub mod config_injection;
pub mod event;
pub mod message;
pub mod prompt;
pub mod provider;
pub mod tool;

pub use config_injection::is_config_injection_path;
pub use event::AgentEvent;
pub use message::{ContentBlock, Message, Role};
pub use prompt::{render as render_environment_prompt, EnvironmentFacts, OsKind};
pub use provider::{
    BlockKind, CompletionRequest, LlmProvider, OutputContract, ProviderCapabilities,
    ProviderError, Sampling, StopReason, StreamEvent, SystemBlock, ToolChoice, Usage,
};
pub use tool::{
    NetAppPolicy, NetProxyConfig, ReadMode, ReadScopeConfig, RequireSandbox, RiskClass, ShellTier,
    ShellTierSelection, StagingConfig, StagingMode, Tool, ToolCtx, ToolError, ToolOutput,
    ToolResult, ToolSpec, ToolUse, VmShellExecutor,
};
