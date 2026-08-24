//! `grep`/`glob`。`plans/DESIGN.md` §ツールシステム「組み込みツール」参照。
//!
//! **【T3】走査は cap-std `Dir` 上の自前 walker で行う**: `ignore::WalkBuilder`/`grep::Walk`
//! はstdのパスベースopenで自走査しcap-stdのハンドルを経由できないため、走査本体は
//! `SandboxFs::walk_files`（`Dir::entries`＝openat相当、M10でオーバーレイ分も合流するよう
//! 拡張済み）に統一し、`globset`はglob判定にのみ使う（§ツールシステム fsジェイル）。

use async_trait::async_trait;
use grep_regex::RegexMatcherBuilder;
use grep_searcher::{Searcher, SearcherBuilder, Sink, SinkContext, SinkMatch};
use serde::Deserialize;
use serde_json::json;

use harness_core::{RiskClass, Tool, ToolCtx, ToolError, ToolOutput};
use harness_sandbox::SandboxFs;

use crate::sandbox_error_to_tool_error;

/// 走査対象ファイル数・出力行数の上限。無制限走査による暴走/巨大出力を防ぐ実務上の安全弁。
const MAX_FILES_SCANNED: usize = 2000;
const MAX_OUTPUT_LINES: usize = 500;

// --- grep ---

#[derive(Deserialize)]
struct GrepInput {
    pattern: String,
    path: Option<String>,
    glob: Option<String>,
    output_mode: Option<String>,
    #[serde(rename = "-i")]
    ignore_case: Option<bool>,
    #[serde(rename = "-n")]
    line_numbers: Option<bool>,
    context: Option<usize>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputMode {
    Content,
    FilesWithMatches,
    Count,
}

impl OutputMode {
    fn parse(s: Option<&str>) -> Self {
        match s {
            Some("files_with_matches") => OutputMode::FilesWithMatches,
            Some("count") => OutputMode::Count,
            _ => OutputMode::Content,
        }
    }
}

pub struct GrepTool;

#[async_trait]
impl Tool for GrepTool {
    fn name(&self) -> &str {
        "grep"
    }

    fn description(&self) -> &str {
        "ワークスペース内のファイルを正規表現で検索する。gitignoreは考慮しない（§実装ノート）。"
    }

    fn input_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "pattern": { "type": "string", "description": "検索する正規表現" },
                "path": { "type": "string", "description": "検索対象のサブディレクトリ（省略時ワークスペース全体）" },
                "glob": { "type": "string", "description": "対象ファイルを絞るglobパターン（例 \"*.rs\"）" },
                "output_mode": { "type": "string", "enum": ["content", "files_with_matches", "count"], "description": "出力形式（省略時content）" },
                "-i": { "type": "boolean", "description": "大文字小文字を無視する" },
                "-n": { "type": "boolean", "description": "行番号を出力する（output_mode=content時、省略時true）" },
                "context": { "type": "integer", "description": "マッチ行の前後に含める文脈行数" }
            },
            "required": ["pattern"],
            "additionalProperties": false
        })
    }

    fn risk(&self, _input: &serde_json::Value) -> RiskClass {
        RiskClass::ReadOnly
    }

    async fn call(&self, input: serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let input: GrepInput =
            serde_json::from_value(input).map_err(|e| ToolError::InvalidInput(e.to_string()))?;
        let workspace_root = ctx.workspace_root.clone();
        let staging = ctx.staging.clone();
        let read_scope = ctx.read_scope.clone();
        let cow_diff_layer_dir = ctx.cow_diff_layer_dir.clone();

        tokio::task::spawn_blocking(move || -> Result<ToolOutput, ToolError> {
            let fs = SandboxFs::open_with_cow(
                &workspace_root,
                &staging,
                &read_scope,
                cow_diff_layer_dir.as_deref(),
            )
            .map_err(|e| sandbox_error_to_tool_error("", e))?;

            let matcher = RegexMatcherBuilder::new()
                .case_insensitive(input.ignore_case.unwrap_or(false))
                .build(&input.pattern)
                .map_err(|e| ToolError::InvalidInput(format!("invalid pattern: {e}")))?;

            let glob_matcher = match &input.glob {
                Some(g) => Some(
                    globset::Glob::new(g)
                        .map_err(|e| ToolError::InvalidInput(format!("invalid glob: {e}")))?
                        .compile_matcher(),
                ),
                None => None,
            };

            let base_prefix = input.path.clone().unwrap_or_default();
            let mode = OutputMode::parse(input.output_mode.as_deref());
            let show_line_numbers = input.line_numbers.unwrap_or(true);
            let context = input.context.unwrap_or(0);

            let mut candidates = fs
                .walk_files()
                .map_err(|e| sandbox_error_to_tool_error("", e))?;
            candidates.retain(|p| {
                let s = p.to_string_lossy().replace('\\', "/");
                if !base_prefix.is_empty() && !s.starts_with(&base_prefix) {
                    return false;
                }
                match &glob_matcher {
                    Some(g) => g.is_match(&s),
                    None => true,
                }
            });
            candidates.truncate(MAX_FILES_SCANNED);

            let mut searcher_builder = SearcherBuilder::new();
            searcher_builder.line_number(true);
            searcher_builder.before_context(context);
            searcher_builder.after_context(context);
            let mut searcher: Searcher = searcher_builder.build();

            let mut content_lines: Vec<String> = Vec::new();
            let mut files_with_matches: Vec<String> = Vec::new();
            let mut counts: Vec<(String, u64)> = Vec::new();
            let mut truncated = false;

            for rel_path in &candidates {
                if content_lines.len() >= MAX_OUTPUT_LINES {
                    truncated = true;
                    break;
                }
                let rel_str = rel_path.to_string_lossy().replace('\\', "/");
                let file = match fs.open_file_for_read(&rel_str) {
                    Ok(f) => f,
                    Err(_) => continue,
                };

                let mut sink = CollectSink {
                    mode,
                    show_line_numbers,
                    lines: Vec::new(),
                    match_count: 0,
                };
                if searcher.search_reader(&matcher, file, &mut sink).is_err() {
                    continue;
                }

                if sink.match_count == 0 {
                    continue;
                }
                match mode {
                    OutputMode::Content => {
                        for line in sink.lines {
                            content_lines.push(format!("{rel_str}:{line}"));
                            if content_lines.len() >= MAX_OUTPUT_LINES {
                                truncated = true;
                                break;
                            }
                        }
                    }
                    OutputMode::FilesWithMatches => files_with_matches.push(rel_str),
                    OutputMode::Count => counts.push((rel_str, sink.match_count)),
                }
            }

            let mut out = match mode {
                OutputMode::Content => content_lines.join("\n"),
                OutputMode::FilesWithMatches => files_with_matches.join("\n"),
                OutputMode::Count => counts
                    .into_iter()
                    .map(|(p, c)| format!("{p}: {c}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            };
            if truncated {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str("[output truncated]");
            }

            Ok(ToolOutput {
                content: out,
                is_error: false,
            })
        })
        .await
        .map_err(|e| ToolError::ExecutionFailed(format!("join error: {e}")))?
    }
}

struct CollectSink {
    mode: OutputMode,
    show_line_numbers: bool,
    lines: Vec<String>,
    match_count: u64,
}

impl Sink for CollectSink {
    type Error = std::io::Error;

    fn matched(&mut self, _searcher: &Searcher, mat: &SinkMatch<'_>) -> Result<bool, Self::Error> {
        self.match_count += 1;
        if self.mode == OutputMode::Content {
            self.lines.push(format_sink_bytes(
                mat.bytes(),
                mat.line_number(),
                self.show_line_numbers,
                ':',
            ));
        }
        Ok(true)
    }

    fn context(
        &mut self,
        _searcher: &Searcher,
        ctx: &SinkContext<'_>,
    ) -> Result<bool, Self::Error> {
        if self.mode == OutputMode::Content {
            self.lines.push(format_sink_bytes(
                ctx.bytes(),
                ctx.line_number(),
                self.show_line_numbers,
                '-',
            ));
        }
        Ok(true)
    }
}

fn format_sink_bytes(
    bytes: &[u8],
    line_number: Option<u64>,
    show_line_numbers: bool,
    sep: char,
) -> String {
    let text = String::from_utf8_lossy(bytes);
    let text = text.strip_suffix('\n').unwrap_or(&text);
    match (show_line_numbers, line_number) {
        (true, Some(n)) => format!("{n}{sep}{text}"),
        _ => text.to_string(),
    }
}

// --- glob ---

#[derive(Deserialize)]
struct GlobInput {
    pattern: String,
    path: Option<String>,
}

pub struct GlobTool;

#[async_trait]
impl Tool for GlobTool {
    fn name(&self) -> &str {
        "glob"
    }

    fn description(&self) -> &str {
        "ワークスペース内のファイルをglobパターンで検索し、更新時刻の新しい順に返す。"
    }

    fn input_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "pattern": { "type": "string", "description": "globパターン（例 \"**/*.rs\"）" },
                "path": { "type": "string", "description": "検索対象のサブディレクトリ（省略時ワークスペース全体）" }
            },
            "required": ["pattern"],
            "additionalProperties": false
        })
    }

    fn risk(&self, _input: &serde_json::Value) -> RiskClass {
        RiskClass::ReadOnly
    }

    async fn call(&self, input: serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let input: GlobInput =
            serde_json::from_value(input).map_err(|e| ToolError::InvalidInput(e.to_string()))?;
        let workspace_root = ctx.workspace_root.clone();
        let staging = ctx.staging.clone();
        let read_scope = ctx.read_scope.clone();
        let cow_diff_layer_dir = ctx.cow_diff_layer_dir.clone();

        tokio::task::spawn_blocking(move || -> Result<ToolOutput, ToolError> {
            let fs = SandboxFs::open_with_cow(
                &workspace_root,
                &staging,
                &read_scope,
                cow_diff_layer_dir.as_deref(),
            )
            .map_err(|e| sandbox_error_to_tool_error("", e))?;

            let matcher = globset::Glob::new(&input.pattern)
                .map_err(|e| ToolError::InvalidInput(format!("invalid glob: {e}")))?
                .compile_matcher();

            let base_prefix = input.path.clone().unwrap_or_default();
            let files = fs
                .walk_files()
                .map_err(|e| sandbox_error_to_tool_error("", e))?;

            let epoch = cap_std::time::SystemTime::from_std(std::time::UNIX_EPOCH);
            let mut matched: Vec<(String, cap_std::time::SystemTime)> = Vec::new();
            for p in files {
                let s = p.to_string_lossy().replace('\\', "/");
                if !base_prefix.is_empty() && !s.starts_with(&base_prefix) {
                    continue;
                }
                if !matcher.is_match(&s) {
                    continue;
                }
                let mtime = fs.modified(&s).unwrap_or(epoch);
                matched.push((s, mtime));
            }
            matched.sort_by_key(|(_, mtime)| std::cmp::Reverse(*mtime));
            matched.truncate(MAX_FILES_SCANNED);

            Ok(ToolOutput {
                content: matched
                    .into_iter()
                    .map(|(p, _)| p)
                    .collect::<Vec<_>>()
                    .join("\n"),
                is_error: false,
            })
        })
        .await
        .map_err(|e| ToolError::ExecutionFailed(format!("join error: {e}")))?
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
    async fn grep_finds_matching_line_with_line_number() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "hello\nworld\nfoo bar\n").unwrap();

        let tool = GrepTool;
        let out = tool
            .call(json!({ "pattern": "wor" }), &ctx(dir.path().to_path_buf()))
            .await
            .unwrap();

        assert!(!out.is_error);
        assert_eq!(out.content, "a.txt:2:world");
    }

    #[tokio::test]
    async fn grep_files_with_matches_mode() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "needle\n").unwrap();
        std::fs::write(dir.path().join("b.txt"), "nothing\n").unwrap();

        let tool = GrepTool;
        let out = tool
            .call(
                json!({ "pattern": "needle", "output_mode": "files_with_matches" }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();

        assert_eq!(out.content, "a.txt");
    }

    #[tokio::test]
    async fn grep_respects_glob_filter() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "needle\n").unwrap();
        std::fs::write(dir.path().join("b.txt"), "needle\n").unwrap();

        let tool = GrepTool;
        let out = tool
            .call(
                json!({ "pattern": "needle", "glob": "*.rs", "output_mode": "files_with_matches" }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();

        assert_eq!(out.content, "a.rs");
    }

    #[tokio::test]
    async fn glob_matches_and_excludes_others() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "1").unwrap();
        std::fs::write(dir.path().join("b.txt"), "2").unwrap();

        let tool = GlobTool;
        let out = tool
            .call(json!({ "pattern": "*.rs" }), &ctx(dir.path().to_path_buf()))
            .await
            .unwrap();

        assert_eq!(out.content, "a.rs");
    }
}
