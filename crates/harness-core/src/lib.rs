//! harness-core: 共有語彙（IR）とtrait定義。プロバイダ非依存・フロントエンド非依存。
//! `plans/DESIGN.md` §全体アーキテクチャ 参照。

pub mod cognition;
pub mod config_injection;
pub mod event;
pub mod message;
pub mod net_policy;
pub mod prompt;
pub mod provider;
pub mod schema;
pub mod tool;

pub use cognition::{CognitionLevel, Phase, TokenBudget};
pub use config_injection::is_config_injection_path;
pub use event::AgentEvent;
pub use message::{ContentBlock, Message, Role};
pub use net_policy::{
    domain_match, is_ip_literal, normalize_domain_pattern, validate_domain_pattern, DomainPolicy,
    DomainPolicyDecision,
};
pub use prompt::{render as render_environment_prompt, EnvironmentFacts, OsKind};
pub use provider::{
    BlockKind, CompletionRequest, LlmProvider, OutputContract, ProviderCapabilities, ProviderError,
    Sampling, StopReason, StreamEvent, SystemBlock, ToolChoice, Usage,
};
pub use schema::{apply_schema_strategy, unwrap_forced_tool_stream, SchemaStrategy};
pub use tool::{
    NetAppPolicy, NetProxyConfig, ReadMode, ReadScopeConfig, RequireSandbox, RiskClass, ShellTier,
    ShellTierSelection, StagingConfig, StagingMode, TlsInspection, Tool, ToolCtx, ToolError,
    ToolOutput, ToolResult, ToolSpec, ToolUse, VmShellExecutor,
};
