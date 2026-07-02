//! `run_shell`。`plans/DESIGN.md` §ツールシステム「run_shell」・§主なリスクと対策
//! 「Windowsのシェルとパス」参照。
//!
//! **Windowsのシェル選択**（§実装マイルストーン M5）: pwsh7が`PATH`上に見つかればそれを、
//! 無ければ Windows PowerShell 5.1（`powershell.exe`）へフォールバックする。両者は演算子が
//! 異なる（5.1に`&&`/`||`が無い）ため、allowlistのコマンド分解が対象文法に依存する場合に備え
//! **どちらを起動したかを出力へ記録**する（§ツールシステム「シェル選択」）。
//! `-Command`への文字列補間はargvクォートバグを踏むため避け、コマンド文字列は**stdin経由**
//! （`-Command -`）で渡す。`-NoProfile -NonInteractive`を付与する。
//!
//! 危険構文（`-EncodedCommand`・`iex`/`Invoke-Expression`・`Start-Process`・`cmd /c`・
//! 入れ子インタプリタ）を検出したら`AcceptEdits`下でも強制的にプロンプトへ落とす
//! denylistヒューリスティックは`PermissionArbiter`側の拡張を要するため**M5のスコープ外**
//! （milestone表のM5検証条件は「Windows 11で`run_shell`がpowershell経由で動く」のみ）。

use std::process::Stdio;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::time::{timeout, Duration};

use harness_core::{RiskClass, Tool, ToolCtx, ToolError, ToolOutput};
use harness_sandbox::check_relative_path;

use crate::jail_error_to_tool_error;

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
            Some(c) => {
                let rel = check_relative_path(c).map_err(|e| jail_error_to_tool_error(c, e))?;
                ctx.workspace_root.join(rel)
            }
            None => ctx.workspace_root.clone(),
        };

        let invocation = platform_shell_command(&input.command);
        let mut cmd = invocation.cmd;
        cmd.current_dir(&cwd);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        if invocation.stdin_payload.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }
        // タイムアウト到達時にfutureをdropしただけでは子プロセスは残るため、
        // dropと同時にkillされるようにする（設計書「暴走kill」の要件）。
        cmd.kill_on_drop(true);

        let mut child = cmd
            .spawn()
            .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;

        if let Some(payload) = invocation.stdin_payload {
            let mut stdin = child.stdin.take().expect("stdin is piped");
            stdin
                .write_all(payload.as_bytes())
                .await
                .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;
            // dropしてEOFを送る。書き込み後すぐ子プロセス側のstdin読み取りが完了できるようにする。
            drop(stdin);
        }

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
                content.push_str(&format!(
                    "\n[exit code: {code}]\n[shell: {}]",
                    invocation.shell_label
                ));
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

/// 起動する子プロセスコマンドと、記録用のシェルラベル・stdin経由で渡すコマンド文字列
/// （argvへの文字列補間を避けるためのペイロード、Windowsのみ使用）をまとめたもの。
struct ShellInvocation {
    cmd: Command,
    stdin_payload: Option<String>,
    shell_label: &'static str,
}

/// Unixは`sh -c <command>`（argvの1要素として渡るためWindowsの`-Command`文字列補間問題は無い）。
#[cfg(not(windows))]
fn platform_shell_command(command: &str) -> ShellInvocation {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(command);
    ShellInvocation {
        cmd,
        stdin_payload: None,
        shell_label: "sh",
    }
}

/// Windowsはpwsh7優先→Windows PowerShell 5.1フォールバック。コマンド文字列はargvへ
/// 埋め込まず`-Command -`でstdinから渡す（§ツールシステム run_shell「シェル選択」）。
#[cfg(windows)]
fn platform_shell_command(command: &str) -> ShellInvocation {
    let (bin, shell_label) = if which::which("pwsh").is_ok() {
        ("pwsh", "pwsh")
    } else {
        ("powershell", "powershell5.1")
    };
    let mut cmd = Command::new(bin);
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", "-"]);
    ShellInvocation {
        cmd,
        stdin_payload: Some(command.to_string()),
        shell_label,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn ctx(root: PathBuf) -> ToolCtx {
        ToolCtx {
            workspace_root: root,
        }
    }

    #[tokio::test]
    async fn run_shell_captures_stdout_and_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let tool = RunShellTool;
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

    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_records_launched_windows_shell() {
        let dir = tempfile::tempdir().unwrap();
        let tool = RunShellTool;
        let out = tool
            .call(
                json!({ "command": "Write-Output hello" }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();
        assert!(!out.is_error);
        assert!(out.content.contains("hello"));
        assert!(
            out.content.contains("[shell: pwsh]") || out.content.contains("[shell: powershell5.1]")
        );
    }

    #[tokio::test]
    async fn run_shell_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let tool = RunShellTool;
        #[cfg(windows)]
        let command = "Start-Sleep -Seconds 5";
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
