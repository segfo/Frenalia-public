//! harness-tools: `Tool` trait実装 + `ToolRegistry`。`plans/DESIGN.md` §ツールシステム参照。
//!
//! M4で`read_file`のfsジェイルを`harness-sandbox::WorkspaceJail`（cap-std主ゲート）へ
//! 置き換えた（§実装マイルストーン M4「RiskClass・モード・allowlist・ワークスペースジェイル」）。
//! M5で`write_file`/`edit_file`/`grep`/`glob`/`web_fetch`を追加し、Windowsのシェル選択
//! （pwsh7優先→5.1フォールバック・起動シェルの記録・`-Command`文字列補間回避）を実装した
//! （§実装マイルストーン M5「全組み込みツール」）。**危険構文denylist forcing prompt
//! （`-EncodedCommand`/`iex`等を検出したらAcceptEdits下でも強制的にプロンプト）は
//! `PermissionArbiter`側の拡張を要するためM5のスコープ外**（設計書「危険パターン・
//! ヒューリスティック」節、milestone表のM5検証条件は「Windows 11で`run_shell`が
//! powershell経由で動く」のみ）。
//!
//! `run_shell`の`cwd`は子プロセスへ渡すだけの値でcap-std経由のopenが起きないため
//! （設計書「これらはrun_shell子プロセスには効かない」§ツールシステム fsジェイル）、
//! 引き続き`harness_sandbox::check_relative_path`による文字列としての形チェックに留める
//! （子プロセスの実FSアクセスを止めるのはM12のOS隔離Tierのスコープ）。
//! 実行前の許可判定（`PermissionArbiter`）はM4で`harness-engine`に実装したが、
//! ツール本体はそれを意識しない（呼ばれた時点で既に許可済み）。

mod fs_tools;
mod net_proxy;
mod search;
mod shell;
mod web;

use std::collections::HashMap;
use std::sync::Arc;

use harness_core::{Tool, ToolCtx, ToolError, ToolSpec};
use harness_sandbox::JailError;

pub use fs_tools::{EditFileTool, ReadFileTool, WriteFileTool};
pub use search::{GlobTool, GrepTool};
pub use shell::RunShellTool;
pub use web::WebFetchTool;

/// 登録済みツールの集合。`ToolSpec` へ一括展開してプロバイダへ渡す。
pub struct ToolRegistry {
    tools: HashMap<String, Arc<dyn Tool>>,
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    /// M5時点の組み込みツール一式を登録済みで返す
    /// （read_file/write_file/edit_file/run_shell/grep/glob/web_fetch）。
    pub fn with_builtin_tools() -> Self {
        let mut reg = Self::new();
        reg.register(Arc::new(ReadFileTool));
        reg.register(Arc::new(WriteFileTool));
        reg.register(Arc::new(EditFileTool));
        reg.register(Arc::new(RunShellTool));
        reg.register(Arc::new(GrepTool));
        reg.register(Arc::new(GlobTool));
        reg.register(Arc::new(WebFetchTool));
        reg
    }

    pub fn register(&mut self, tool: Arc<dyn Tool>) {
        self.tools.insert(tool.name().to_string(), tool);
    }

    pub fn get(&self, name: &str) -> Option<&Arc<dyn Tool>> {
        self.tools.get(name)
    }

    pub fn to_specs(&self) -> Vec<ToolSpec> {
        self.tools
            .values()
            .map(|t| ToolSpec {
                name: t.name().to_string(),
                description: t.description().to_string(),
                input_schema: t.input_schema(),
            })
            .collect()
    }

    pub fn to_specs_for_ctx(&self, ctx: &ToolCtx) -> Vec<ToolSpec> {
        self.tools.values().map(|t| t.spec_for_ctx(ctx)).collect()
    }
}

/// `WorkspaceJail`のエラーを`ToolError`へ写像する共通ヘルパー。全fs系ツールから使う。
pub(crate) fn jail_error_to_tool_error(path: &str, err: JailError) -> ToolError {
    match err {
        JailError::Escape(_) | JailError::UnsafePath(_) => ToolError::InvalidInput(format!(
            "path must be relative and within the workspace: {path} ({err})"
        )),
        JailError::Io(e) => ToolError::ExecutionFailed(format!("{path}: {e}")),
    }
}

/// `SandboxFs`（M10、書込ステージング）のエラーを`ToolError`へ写像する共通ヘルパー。
pub(crate) fn sandbox_error_to_tool_error(path: &str, err: harness_sandbox::SandboxError) -> ToolError {
    match err {
        harness_sandbox::SandboxError::Jail(e) => jail_error_to_tool_error(path, e),
        harness_sandbox::SandboxError::NotFound(_) => {
            ToolError::InvalidInput(format!("not found: {path}"))
        }
        harness_sandbox::SandboxError::Io(e) => ToolError::ExecutionFailed(format!("{path}: {e}")),
        harness_sandbox::SandboxError::ReadScope(e) => {
            ToolError::InvalidInput(format!("read denied by read scope config: {path} ({e})"))
        }
    }
}
