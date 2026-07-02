//! harness-tools: `Tool` trait実装 + `ToolRegistry`。`plans/DESIGN.md` §ツールシステム参照。
//!
//! M3時点では `read_file`/`run_shell` の2つのみを実装する（§実装マイルストーン M3
//! 「ToolRegistryにread_file+run_shell、蓄積→ディスパッチ→tool_result投入→継続ループ。
//! 一旦allow-allで動作確認」）。write_file/edit_file/grep/glob/web_fetchはM5、
//! パーミッション（`PermissionArbiter`によるRiskClass判定）・fsジェイル（cap-std主ゲート・
//! 予約デバイス名/ADS拒否等）はM4/M11のスコープのため、read_file/run_shellは
//! workspace_root配下への素朴な相対パス解決に留める。Windowsのシェル選択
//! （pwsh7優先→5.1フォールバック・起動シェルの記録・危険構文denylist）もM5のスコープ。

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

use harness_core::{RiskClass, Tool, ToolCtx, ToolError, ToolOutput, ToolSpec};

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

    /// M3時点の組み込みツール一式（read_file+run_shell）を登録済みで返す。
    pub fn with_builtin_tools() -> Self {
        let mut reg = Self::new();
        reg.register(Arc::new(ReadFileTool));
        reg.register(Arc::new(RunShellTool));
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
}

/// `path` を `root` 配下の相対パスとして解決する。絶対パス・`..` を含むものは拒否する。
/// これは cap-std によるTOCTOU封じ（§ツールシステム fsジェイル）の代替ではなく、
/// M4/M11実装までの暫定的な素朴チェックに過ぎない点に注意。
fn resolve_in_workspace(root: &Path, path: &str) -> Result<PathBuf, ToolError> {
    let rel = Path::new(path);
    if rel.is_absolute() || rel.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(ToolError::InvalidInput(format!(
            "path must be relative and within the workspace: {path}"
        )));
    }
    Ok(root.join(rel))
}

// --- read_file ---

#[derive(Deserialize)]
struct ReadFileInput {
    path: String,
    offset: Option<usize>,
    limit: Option<usize>,
}

pub struct ReadFileTool;

#[async_trait]
impl Tool for ReadFileTool {
    fn name(&self) -> &str {
        "read_file"
    }

    fn description(&self) -> &str {
        "ワークスペース内のファイルを cat -n 風の行番号付きで読む。"
    }

    fn input_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "ワークスペースルートからの相対パス" },
                "offset": { "type": "integer", "description": "読み取り開始行（1始まり、省略時は先頭から）" },
                "limit": { "type": "integer", "description": "読み取る最大行数（省略時は全行）" }
            },
            "required": ["path"],
            "additionalProperties": false
        })
    }

    fn risk(&self, _input: &serde_json::Value) -> RiskClass {
        RiskClass::ReadOnly
    }

    async fn call(&self, input: serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let input: ReadFileInput =
            serde_json::from_value(input).map_err(|e| ToolError::InvalidInput(e.to_string()))?;
        let path = resolve_in_workspace(&ctx.workspace_root, &input.path)?;

        let content = tokio::fs::read_to_string(&path)
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("{}: {e}", input.path)))?;

        let offset = input.offset.unwrap_or(1).max(1);
        let numbered: Vec<String> = content
            .lines()
            .enumerate()
            .skip(offset - 1)
            .take(input.limit.unwrap_or(usize::MAX))
            .map(|(i, line)| format!("{:>6}\t{}", i + 1, line))
            .collect();

        Ok(ToolOutput {
            content: numbered.join("\n"),
            is_error: false,
        })
    }
}

// --- run_shell ---

#[derive(Deserialize)]
struct RunShellInput {
    command: String,
    timeout_ms: Option<u64>,
    cwd: Option<String>,
}

pub struct RunShellTool;

const DEFAULT_TIMEOUT_MS: u64 = 120_000;

#[async_trait]
impl Tool for RunShellTool {
    fn name(&self) -> &str {
        "run_shell"
    }

    fn description(&self) -> &str {
        "ワークスペース内でシェルコマンドを実行し、stdout+stderr+終了コードを返す。"
    }

    fn input_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "command": { "type": "string", "description": "実行するシェルコマンド" },
                "timeout_ms": { "type": "integer", "description": "タイムアウト（ミリ秒、省略時120000）" },
                "cwd": { "type": "string", "description": "ワークスペースルートからの相対作業ディレクトリ" }
            },
            "required": ["command"],
            "additionalProperties": false
        })
    }

    fn risk(&self, _input: &serde_json::Value) -> RiskClass {
        RiskClass::Exec
    }

    async fn call(&self, input: serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let input: RunShellInput =
            serde_json::from_value(input).map_err(|e| ToolError::InvalidInput(e.to_string()))?;

        let cwd = match &input.cwd {
            Some(c) => resolve_in_workspace(&ctx.workspace_root, c)?,
            None => ctx.workspace_root.clone(),
        };

        let mut cmd = platform_shell_command(&input.command);
        cmd.current_dir(&cwd);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        // タイムアウト到達時にfutureをdropしただけでは子プロセスは残るため、
        // dropと同時にkillされるようにする（設計書「暴走kill」の要件）。
        cmd.kill_on_drop(true);

        let mut child = cmd
            .spawn()
            .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;

        let mut stdout = child.stdout.take().expect("stdout is piped");
        let mut stderr = child.stderr.take().expect("stderr is piped");

        let dur = Duration::from_millis(input.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS));

        let run = async {
            // stdout/stderrを並行して読む。逐次読みだと、先に読んだ方のパイプが空になるのを
            // 待っている間にもう片方のパイプがバッファ満杯になり子プロセスがブロックし得る。
            let stdout_fut = async {
                let mut s = String::new();
                let _ = stdout.read_to_string(&mut s).await;
                s
            };
            let stderr_fut = async {
                let mut s = String::new();
                let _ = stderr.read_to_string(&mut s).await;
                s
            };
            let (out, err) = tokio::join!(stdout_fut, stderr_fut);
            let status = child
                .wait()
                .await
                .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;
            Ok::<_, ToolError>((out, err, status))
        };

        match timeout(dur, run).await {
            Ok(Ok((out, err, status))) => {
                let code = status.code().unwrap_or(-1);
                let mut content = out;
                if !err.is_empty() {
                    if !content.is_empty() {
                        content.push('\n');
                    }
                    content.push_str(&err);
                }
                content.push_str(&format!("\n[exit code: {code}]"));
                Ok(ToolOutput {
                    content,
                    is_error: code != 0,
                })
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(ToolError::ExecutionFailed(format!(
                "command timed out after {}ms",
                dur.as_millis()
            ))),
        }
    }
}

/// Windowsは `cmd.exe /C` 固定。pwsh7優先起動→5.1フォールバックや、起動シェルの記録、
/// `-EncodedCommand`/`iex`等の危険構文denylistはM5のスコープ（§ツールシステム run_shell）。
#[cfg(windows)]
fn platform_shell_command(command: &str) -> Command {
    let mut cmd = Command::new("cmd");
    cmd.arg("/C").arg(command);
    cmd
}

#[cfg(not(windows))]
fn platform_shell_command(command: &str) -> Command {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(command);
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(root: PathBuf) -> ToolCtx {
        ToolCtx {
            workspace_root: root,
        }
    }

    #[tokio::test]
    async fn read_file_returns_numbered_lines() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "one\ntwo\nthree\n").unwrap();

        let tool = ReadFileTool;
        let out = tool
            .call(json!({ "path": "a.txt" }), &ctx(dir.path().to_path_buf()))
            .await
            .unwrap();

        assert!(!out.is_error);
        assert_eq!(out.content, "     1\tone\n     2\ttwo\n     3\tthree");
    }

    #[tokio::test]
    async fn read_file_rejects_path_escape() {
        let dir = tempfile::tempdir().unwrap();
        let tool = ReadFileTool;
        let err = tool
            .call(
                json!({ "path": "../outside.txt" }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn run_shell_captures_stdout_and_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let tool = RunShellTool;
        #[cfg(windows)]
        let command = "echo hello";
        #[cfg(not(windows))]
        let command = "echo hello";

        let out = tool
            .call(
                json!({ "command": command }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();

        assert!(!out.is_error);
        assert!(out.content.contains("hello"));
        assert!(out.content.contains("[exit code: 0]"));
    }

    #[tokio::test]
    async fn run_shell_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let tool = RunShellTool;
        #[cfg(windows)]
        let command = "ping -n 5 127.0.0.1 > NUL";
        #[cfg(not(windows))]
        let command = "sleep 5";

        let err = tool
            .call(
                json!({ "command": command, "timeout_ms": 200 }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, ToolError::ExecutionFailed(_)));
    }
}
