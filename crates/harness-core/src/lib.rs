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
pub mod text;
pub mod tool;
pub mod wire_log;

pub use cognition::{CognitionLevel, Phase, TokenBudget};
pub use config_injection::is_config_injection_path;
pub use event::{discarded_marker, AgentEvent, DegenerateKind, CANCELLED_REASON};
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
pub use text::truncate_head_tail;
pub use tool::{
    McpServerFact, NetAppPolicy, NetProxyConfig, ReadMode, ReadScopeConfig, RequireSandbox,
    RiskClass, ShellTier, ShellTierSelection, StagingConfig, StagingMode, TlsInspection, Tool,
    ToolCtx, ToolError, ToolOutput, ToolResult, ToolSpec, ToolUse, VmShellExecutor, WaitReason,
    WaitReasons,
};
