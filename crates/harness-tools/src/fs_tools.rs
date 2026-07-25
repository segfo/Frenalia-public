//! `read_file`/`write_file`/`edit_file`。`plans/DESIGN.md` §ツールシステム「組み込みツール」参照。
//!
//! M10で実FSへの直接アクセスを`harness_sandbox::SandboxFs`（オーバーレイFS）経由へ差し替えた。
//! `ctx.staging.sandbox_dir`が`None`（`StagingConfig::default()`）なら`SandboxFs`は内部の
//! `WorkspaceJail`をそのまま素通しする純live実装として振る舞うため、M9までの挙動と等価
//! （このファイルの既存ユニットテストは無改変で通る）。

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

use harness_core::{RiskClass, Tool, ToolCtx, ToolError, ToolOutput};
use harness_sandbox::SandboxFs;

use crate::sandbox_error_to_tool_error;

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

        // cap-std の Dir ハンドル経由の同期I/Oはtokioワーカースレッドをブロックしうるため、
        // spawn_blocking へ逃がす（§ツールシステム fsジェイル、cap-stdは非同期非対応）。
        let workspace_root = ctx.workspace_root.clone();
        let staging = ctx.staging.clone();
        let read_scope = ctx.read_scope.clone();
        let path_for_err = input.path.clone();
        let content = tokio::task::spawn_blocking(move || -> Result<String, ToolError> {
            let fs = SandboxFs::open_with_read_scope(&workspace_root, &staging, &read_scope)
                .map_err(|e| sandbox_error_to_tool_error(&path_for_err, e))?;
            fs.read_to_string(&path_for_err)
                .map_err(|e| sandbox_error_to_tool_error(&path_for_err, e))
        })
        .await
        .map_err(|e| ToolError::ExecutionFailed(format!("join error: {e}")))??;

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

// --- write_file ---

#[derive(Deserialize)]
struct WriteFileInput {
    path: String,
    content: String,
}

pub struct WriteFileTool;

#[async_trait]
impl Tool for WriteFileTool {
    fn name(&self) -> &str {
        "write_file"
    }

    fn description(&self) -> &str {
        "ワークスペース内へファイルを書き込む(既存内容は上書き)。親ディレクトリが無ければ作成する。"
    }

    fn input_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "ワークスペースルートからの相対パス" },
                "content": { "type": "string", "description": "書き込む内容（全体を置換）" }
            },
            "required": ["path", "content"],
            "additionalProperties": false
        })
    }

    fn risk(&self, _input: &serde_json::Value) -> RiskClass {
        RiskClass::Write
    }

    async fn call(&self, input: serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let input: WriteFileInput =
            serde_json::from_value(input).map_err(|e| ToolError::InvalidInput(e.to_string()))?;

        let workspace_root = ctx.workspace_root.clone();
        let staging = ctx.staging.clone();
        let read_scope = ctx.read_scope.clone();
        let path_for_err = input.path.clone();
        let path_for_output = input.path.clone();
        let bytes_written = input.content.len();
        tokio::task::spawn_blocking(move || -> Result<(), ToolError> {
            let fs = SandboxFs::open_with_read_scope(&workspace_root, &staging, &read_scope)
                .map_err(|e| sandbox_error_to_tool_error(&path_for_err, e))?;
            fs.write_string(&path_for_err, &input.content)
                .map_err(|e| sandbox_error_to_tool_error(&path_for_err, e))
        })
        .await
        .map_err(|e| ToolError::ExecutionFailed(format!("join error: {e}")))??;

        Ok(ToolOutput {
            content: format!("wrote {bytes_written} bytes to {path_for_output}"),
            is_error: false,
        })
    }
}

// --- edit_file ---

#[derive(Deserialize)]
struct EditFileInput {
    path: String,
    old_string: String,
    new_string: String,
    replace_all: Option<bool>,
}

pub struct EditFileTool;

#[async_trait]
impl Tool for EditFileTool {
    fn name(&self) -> &str {
        "edit_file"
    }

    fn description(&self) -> &str {
        "ファイル内の`old_string`を`new_string`へ完全一致で置換する。`old_string`が唯一に \
         見つかる場合のみ置換する（`replace_all`指定時は全出現を置換）。"
    }

    fn input_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "ワークスペースルートからの相対パス" },
                "old_string": { "type": "string", "description": "置換対象の完全一致文字列" },
                "new_string": { "type": "string", "description": "置換後の文字列" },
                "replace_all": { "type": "boolean", "description": "true なら全出現を置換（省略時false、唯一の一致のみ許可）" }
            },
            "required": ["path", "old_string", "new_string"],
            "additionalProperties": false
        })
    }

    fn risk(&self, _input: &serde_json::Value) -> RiskClass {
        RiskClass::Write
    }

    async fn call(&self, input: serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let input: EditFileInput =
            serde_json::from_value(input).map_err(|e| ToolError::InvalidInput(e.to_string()))?;
        let replace_all = input.replace_all.unwrap_or(false);

        let workspace_root = ctx.workspace_root.clone();
        let staging = ctx.staging.clone();
        let read_scope = ctx.read_scope.clone();
        let path_for_err = input.path.clone();
        tokio::task::spawn_blocking(move || -> Result<(), ToolError> {
            let fs = SandboxFs::open_with_read_scope(&workspace_root, &staging, &read_scope)
                .map_err(|e| sandbox_error_to_tool_error(&path_for_err, e))?;
            let content = fs
                .read_to_string(&path_for_err)
                .map_err(|e| sandbox_error_to_tool_error(&path_for_err, e))?;

            let occurrences = content.matches(input.old_string.as_str()).count();
            if occurrences == 0 {
                return Err(ToolError::InvalidInput(format!(
                    "old_string not found in {path_for_err}"
                )));
            }
            if !replace_all && occurrences > 1 {
                return Err(ToolError::InvalidInput(format!(
                    "old_string is not unique in {path_for_err} ({occurrences} matches); \
                     pass replace_all=true or provide more context"
                )));
            }

            let new_content = if replace_all {
                content.replace(input.old_string.as_str(), input.new_string.as_str())
            } else {
                content.replacen(input.old_string.as_str(), input.new_string.as_str(), 1)
            };

            fs.write_string(&path_for_err, &new_content)
                .map_err(|e| sandbox_error_to_tool_error(&path_for_err, e))
        })
        .await
        .map_err(|e| ToolError::ExecutionFailed(format!("join error: {e}")))??;

        Ok(ToolOutput {
            content: format!("edited {}", input.path),
            is_error: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn ctx(root: PathBuf) -> ToolCtx {
        ToolCtx::new(root)
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
    async fn write_file_creates_new_file_with_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let tool = WriteFileTool;
        let out = tool
            .call(
                json!({ "path": "sub/a.txt", "content": "hello" }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();
        assert!(!out.is_error);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("sub/a.txt")).unwrap(),
            "hello"
        );
    }

    #[tokio::test]
    async fn write_file_rejects_path_escape() {
        let dir = tempfile::tempdir().unwrap();
        let tool = WriteFileTool;
        let err = tool
            .call(
                json!({ "path": "../outside.txt", "content": "x" }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn edit_file_replaces_unique_match() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "hello world").unwrap();
        let tool = EditFileTool;
        let out = tool
            .call(
                json!({ "path": "a.txt", "old_string": "world", "new_string": "rust" }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();
        assert!(!out.is_error);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
            "hello rust"
        );
    }

    #[tokio::test]
    async fn edit_file_rejects_non_unique_match_without_replace_all() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "foo foo").unwrap();
        let tool = EditFileTool;
        let err = tool
            .call(
                json!({ "path": "a.txt", "old_string": "foo", "new_string": "bar" }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn edit_file_replace_all_replaces_every_occurrence() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "foo foo").unwrap();
        let tool = EditFileTool;
        let out = tool
            .call(
                json!({ "path": "a.txt", "old_string": "foo", "new_string": "bar", "replace_all": true }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();
        assert!(!out.is_error);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
            "bar bar"
        );
    }

    #[tokio::test]
    async fn edit_file_rejects_missing_old_string() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "hello").unwrap();
        let tool = EditFileTool;
        let err = tool
            .call(
                json!({ "path": "a.txt", "old_string": "missing", "new_string": "x" }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::InvalidInput(_)));
    }

    /// M10検証条件の核心: `--staged`相当（`StagingConfig`明示・`sandbox_dir`あり）では
    /// `write_file`が実FSへ一切触れず、read-throughで自分の書込を一貫して読める。
    #[tokio::test]
    async fn write_file_stages_without_touching_real_fs_when_staged() {
        use harness_core::{StagingConfig, StagingMode};

        let dir = tempfile::tempdir().unwrap();
        let ctx = ToolCtx {
            workspace_root: dir.path().to_path_buf(),
            staging: StagingConfig {
                mode: StagingMode::Staged,
                explicit: true,
                sandbox_dir: Some(PathBuf::from(".harness/sandbox/test-session")),
            },
            read_scope: Default::default(),
            shell_tier: Default::default(),
            net_proxy: Default::default(),
            net_app: Default::default(),
            vm_sandbox: None,
        };

        let tool = WriteFileTool;
        let out = tool
            .call(json!({ "path": "staged.txt", "content": "hi" }), &ctx)
            .await
            .unwrap();
        assert!(!out.is_error);
        assert!(!dir.path().join("staged.txt").exists(), "real FS must stay untouched");

        let read_tool = ReadFileTool;
        let read_out = read_tool
            .call(json!({ "path": "staged.txt" }), &ctx)
            .await
            .unwrap();
        assert_eq!(read_out.content, "     1\thi");
    }
}
