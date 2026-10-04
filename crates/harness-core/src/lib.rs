//! harness-core: 共有語彙（IR）とtrait定義。プロバイダ非依存・フロントエンド非依存。
//! `plans/DESIGN.md` §全体アーキテクチャ 参照。

pub mod cognition;
pub mod command_history;
pub mod config_injection;
pub mod decision;
pub mod event;
pub mod git;
pub mod interpreter;
pub mod message;
pub mod net_policy;
pub mod permission_subject;
pub mod program_rule;
pub mod prompt;
pub mod provider;
pub mod risk_check;
pub mod schema;
pub mod text;
pub mod tool;
pub mod user_reference;
pub mod value_store;
pub mod wire_log;

/// `tool.rs`の待機理由機構（`WaitReason`/`WaitReasons`/`WaitState`）のテスト。
/// 本体が大きいので別ファイルにしている（`docs/CODE-STRUCTURE-RULES.md`規則2）。
#[cfg(test)]
#[path = "tool_tests.rs"]
mod tool_tests;

pub use cognition::{CognitionLevel, Phase, TokenBudget};
pub use command_history::CommandHistory;
pub use config_injection::{is_config_injection_path, is_git_internal_path};
pub use decision::{
    assess_command_risk, assess_source_risk, command_context_state, command_state,
    context_questions, source_state, Answers, DecisionModel, Likelihood, Question,
    MAX_SOURCE_CHARS,
};
pub use event::{discarded_marker, AgentEvent, DegenerateKind, CANCELLED_REASON};
pub use interpreter::{
    has_script_extension, is_interpreter_program, INTERPRETER_PROGRAMS, SCRIPT_EXTENSIONS,
};
pub use message::{ContentBlock, Message, Role};
pub use net_policy::{
    domain_match, is_ip_literal, normalize_domain_pattern, validate_domain_pattern, DomainPolicy,
    DomainPolicyDecision,
};
pub use permission_subject::{
    BoundFile, CommandSubject, DecodeOutcome, DecodedLayer, EncodedSource, FilePreview,
    LocatedSpan, PayloadEncoding, PermissionSubject, ProgramSubject, TextEncoding,
};
pub use program_rule::{
    escape_for_display, fold_path_for_rule, hole_accepts, is_format_char, ArgPattern, ProgramRule,
    ShellRule,
};
pub use prompt::{render as render_environment_prompt, EnvironmentFacts, OsKind};
pub use provider::{
    BlockKind, CompletionRequest, LlmProvider, OutputContract, ProviderCapabilities, ProviderError,
    Sampling, StopReason, StreamEvent, SystemBlock, ToolChoice, Usage,
};
pub use risk_check::{RiskCheckError, RiskLevel, RiskVerdict};
pub use schema::{apply_schema_strategy, unwrap_forced_tool_stream, SchemaStrategy};
pub use text::truncate_head_tail;
pub use tool::{
    parse_tool_input, EgressEnforcement, GrantedPassthrough, McpServerFact, NetAppPolicy,
    NetEgress, NetProxyConfig, ReadMode, ReadScopeConfig, RequireSandbox, RiskClass,
    RunnableProgramFact, SandboxChoice, ShellTier, ShellTierSelection, StagingConfig, StagingMode,
    TlsInspection, Tool, ToolCtx, ToolError, ToolOutput, ToolResult, ToolSpec, ToolUse,
    TransitionFacts, VmShellExecutor, WaitReason, WaitReasons, WaitState,
};
pub use user_reference::{
    review as review_user_references, substitute as substitute_user_references,
    values_in as user_reference_values, Transcription as UserValueTranscription,
};
pub use value_store::{from_messages as value_store_for, ValueStore};
