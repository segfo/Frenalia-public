//! MCPサーバのAppContainer隔離への橋渡し（D-38、Windows専用）。
//!
//! 実際のプロファイル作成・ACE付与は`harness_sandbox::tier2a::win_appcontainer::
//! preflight_mcp_server`が持つ。ここが持つのは**宣言からpreflight要求への変換**だけである
//! （どのパスをサーバが必要とするかの解釈）。

use std::path::{Path, PathBuf};

use harness_sandbox::tier2a::win_appcontainer::{preflight_mcp_server, McpPreflightRequest};
use harness_sandbox::FsAccess;

use crate::decl::{McpServerDecl, McpWorkspaceAccess};
use crate::runtime::PreparedServer;
use crate::McpError;

/// [`prepare`]の結果に添う診断（ACE付与に失敗したルート等）。起動は続行する。
pub struct PrepareOutcome {
    pub prepared: PreparedServer,
    pub warnings: Vec<String>,
}

/// サーバ専用のAppContainerプロファイルを用意する（起動計画の第2段、`runtime`のdoc参照）。
///
/// **プロセスはまだ起こさない。** WFPの出口強制を適用してから[`crate::runtime::McpRuntime::start`]
/// が起こす。
pub fn prepare(decl: &McpServerDecl, workspace_root: &Path) -> Result<PrepareOutcome, McpError> {
    let command = PathBuf::from(&decl.command);
    let arg_paths = existing_arg_paths(&decl.args);

    // §3.2: workspaceへのACEは**宣言が明示要求したときだけ**付ける。
    let workspace = match decl.workspace {
        McpWorkspaceAccess::None => None,
        McpWorkspaceAccess::Read => Some((workspace_root, FsAccess::Read)),
        McpWorkspaceAccess::ReadWrite => Some((workspace_root, FsAccess::ReadWrite)),
    };

    let outcome = preflight_mcp_server(&McpPreflightRequest {
        server_id: &decl.id,
        command: &command,
        arg_paths: &arg_paths,
        workspace,
    })
    .map_err(|e| McpError::Spawn {
        id: decl.id.clone(),
        reason: format!("appcontainer preflight failed: {e}"),
    })?;

    Ok(PrepareOutcome {
        prepared: PreparedServer {
            decl: decl.clone(),
            profile_name: outcome.profile_name,
            proxy_addr: None,
        },
        warnings: outcome.warnings,
    })
}

/// 引数のうち実在するパスだけを拾う。
///
/// `node.exe C:\mcp\docs\index.js`のように、サーバの実体が引数側にあるのが普通なので、
/// これを見ないとACEを付ける先が実行ファイルの隣だけになり大半のサーバが起動しない。
/// **実在するものだけ**に絞るのは、`--verbose`のようなフラグをパスと誤認しないため。
/// ここへ来る文字列はすべて承認済み宣言の内容（D-39）である。
fn existing_arg_paths(args: &[String]) -> Vec<PathBuf> {
    args.iter()
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && p.exists())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_existing_absolute_argument_paths_are_considered() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("index.js");
        std::fs::write(&script, "// mcp server").unwrap();

        let args = vec![
            "--verbose".to_string(),
            script.to_string_lossy().into_owned(),
            "C:\\definitely\\missing\\file.js".to_string(),
            "relative/path.js".to_string(),
        ];
        assert_eq!(existing_arg_paths(&args), vec![script]);
    }

    #[test]
    fn a_declaration_with_no_path_arguments_yields_nothing() {
        assert!(existing_arg_paths(&["--stdio".to_string()]).is_empty());
    }
}
