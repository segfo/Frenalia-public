//! harness-core: 共有語彙（IR）とtrait定義。プロバイダ非依存・フロントエンド非依存。
//! `plans/DESIGN.md` §全体アーキテクチャ 参照。

pub mod cognition;
pub mod config_injection;
pub mod event;
pub mod git;
pub mod interpreter;
pub mod message;
pub mod net_policy;
pub mod permission_subject;
pub mod program_rule;
pub mod prompt;
pub mod provider;
pub mod schema;
pub mod text;
pub mod tool;
pub mod wire_log;

/// `tool.rs`の待機理由機構（`WaitReason`/`WaitReasons`/`WaitState`）のテスト。
/// 本体が大きいので別ファイルにしている（`docs/CODE-STRUCTURE-RULES.md`規則2）。
#[cfg(test)]
#[path = "tool_tests.rs"]
mod tool_tests;

pub use cognition::{CognitionLevel, Phase, TokenBudget};
pub use config_injection::is_config_injection_path;
pub use event::{discarded_marker, AgentEvent, DegenerateKind, CANCELLED_REASON};
pub use interpreter::{is_interpreter_program, INTERPRETER_PROGRAMS};
pub use message::{ContentBlock, Message, Role};
pub use net_policy::{
    domain_match, is_ip_literal, normalize_domain_pattern, validate_domain_pattern, DomainPolicy,
    DomainPolicyDecision,
};
pub use permission_subject::{CommandSubject, PermissionSubject, ProgramSubject};
pub use program_rule::{hole_accepts, is_format_char, ArgPattern, ProgramRule};
pub use prompt::{render as render_environment_prompt, EnvironmentFacts, OsKind};
pub use provider::{
    BlockKind, CompletionRequest, LlmProvider, OutputContract, ProviderCapabilities, ProviderError,
    Sampling, StopReason, StreamEvent, SystemBlock, ToolChoice, Usage,
};
pub use schema::{apply_schema_strategy, unwrap_forced_tool_stream, SchemaStrategy};
pub use text::truncate_head_tail;
pub use tool::{
    parse_tool_input, EgressEnforcement, GrantedPassthrough, McpServerFact, NetAppPolicy,
    NetEgress, NetProxyConfig, ReadMode, ReadScopeConfig, RequireSandbox, RiskClass,
    RunnableProgramFact, SandboxChoice, ShellTier, ShellTierSelection, StagingConfig, StagingMode,
    TlsInspection, Tool, ToolCtx, ToolError, ToolOutput, ToolResult, ToolSpec, ToolUse,
    TransitionFacts, VmShellExecutor, WaitReason, WaitReasons, WaitState,
};
