//! 起動時の各種解決（ステージングモード・sandbox_dir・プロバイダ構築・セッション解決）と
//! セッション一覧の表示。`startup`の各段が使う「引数から実際の値を決める」処理を集める。

use super::*;

/// `--require-sandbox[=confidential]`の文字列表現を`RequireSandbox`へ変換する
/// （M12、`plans/DESIGN-SANDBOX.md` §7 D-03）。未知の値は`write-containment`扱いにする
/// （clapの`default_missing_value`と揃える安全側フォールバック）。
pub(crate) fn parse_require_sandbox(value: Option<&str>) -> RequireSandbox {
    match value {
        None => RequireSandbox::None,
        Some("confidential") => RequireSandbox::Confidential,
        Some(_) => RequireSandbox::WriteContainment,
    }
}

/// `--live`/`--staged`/`--workspace-commit`から`StagingMode`を決める。
/// 明示指定が無い場合は常に`Live`（オプトイン。書込/読取の防御はシェル隔離Tierに委ねる、
/// D-29）。`live`分岐は他の2フラグが立っていなければ既定でも同じ結果になるため論理的には
/// 冗長だが、`cli.live`を読む唯一の箇所なのでdead-code警告を避けるために明示しておく。
pub(crate) fn resolve_staging_mode(
    live: bool,
    staged: bool,
    workspace_commit: bool,
) -> StagingMode {
    if live {
        StagingMode::Live
    } else if staged {
        StagingMode::Staged
    } else if workspace_commit {
        StagingMode::WorkspaceCommit
    } else {
        StagingMode::Live
    }
}

// `session_id` → オーバーレイの置き場、の写像は`harness_sandbox::session_scope`が正本
// （起動時のここと、セッション切替時の`harness-tui`の両方から引かれるため。以前は本ファイルと
// `tier2a::workspace_ledger`に同じ`ProjectDirs::…join("cow")`が複製されていた）。
pub(crate) use harness_sandbox::session_scope::{
    cow_upper_dir_for_session, sandbox_dir_for_session,
};

/// `--cow`フラグから`WorkspaceWriteMode`を決める。`session_id`はCoW upperの採番に使う
/// （`sandbox_dir_for_session`と同じ採番元）。`--cow`指定時に`ProjectDirs`が解決できない
/// （HOME未設定等の異常環境）場合は起動を拒否する（安全側: upperが無いままRW付与に
/// フォールバックしない）。
pub(crate) fn resolve_write_mode(
    cow: bool,
    session_id: &str,
) -> Result<WorkspaceWriteMode, String> {
    if !cow {
        return Ok(WorkspaceWriteMode::DirectRw);
    }
    let upper_dir = cow_upper_dir_for_session(session_id)
        .ok_or_else(|| "--cow: could not resolve %LOCALAPPDATA% for the CoW upper directory (is HOME/USERPROFILE set?)".to_string())?;
    Ok(WorkspaceWriteMode::Cow { upper_dir })
}

/// `--session <id>`指定が無い場合に`.harness/sandbox/`直下で最も更新日時の新しいものを選ぶ
/// （`apply`/`changes`/`discard`の既定対象）。
pub(crate) fn resolve_sandbox_dir(workspace_root: &Path, session: Option<&str>) -> Option<PathBuf> {
    if let Some(id) = session {
        let stem = id.strip_prefix("session-").unwrap_or(id);
        return Some(sandbox_dir_for_session(&format!("session-{stem}")));
    }
    let base = workspace_root.join(".harness").join("sandbox");
    let mut newest: Option<(String, std::time::SystemTime)> = None;
    let entries = std::fs::read_dir(&base).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if newest.as_ref().is_none_or(|(_, t)| modified > *t) {
            newest = Some((name.to_string(), modified));
        }
    }
    newest.map(|(name, _)| sandbox_dir_for_session(&name))
}

#[cfg(feature = "e2e-mock")]
pub(crate) fn build_mock_provider(
    mock_turns: Option<&Path>,
    mock_record_requests: Option<&Path>,
) -> Result<Box<dyn LlmProvider>, String> {
    let turns_path =
        mock_turns.ok_or_else(|| "--provider mock requires --mock-turns <path>".to_string())?;
    let mut provider = harness_providers::MockProvider::from_turns_file(turns_path)
        .map_err(|e| format!("failed to read --mock-turns {}: {e}", turns_path.display()))?;
    if let Some(record_path) = mock_record_requests {
        provider = provider.with_request_record_path(record_path.to_path_buf());
    }
    Ok(Box::new(provider))
}

pub(crate) fn build_provider(
    kind: ProviderKind,
    base_url_override: Option<String>,
    #[cfg(feature = "e2e-mock")] mock_turns: Option<&Path>,
    #[cfg(feature = "e2e-mock")] mock_record_requests: Option<&Path>,
) -> Result<Box<dyn LlmProvider>, String> {
    // §設定とシークレット: CLIフラグ > env優先、プロジェクト設定に永続化しない・ログに出さない・
    // 起動時fail-fast。
    match kind {
        #[cfg(feature = "e2e-mock")]
        ProviderKind::Mock => build_mock_provider(mock_turns, mock_record_requests),
        ProviderKind::Anthropic => {
            let api_key = std::env::var("ANTHROPIC_API_KEY")
                .map_err(|_| "ANTHROPIC_API_KEY is not set".to_string())?;
            match base_url_override.or_else(|| std::env::var("ANTHROPIC_BASE_URL").ok()) {
                Some(base_url) => Ok(Box::new(AnthropicProvider::with_base_url(
                    api_key, base_url,
                ))),
                None => Ok(Box::new(AnthropicProvider::new(api_key))),
            }
        }
        ProviderKind::Openai => {
            // LMStudioは空キー可（§プロバイダ抽象「LMStudioは空キー可」）なので、
            // 実OpenAIと異なり未設定でもfail-fastしない。
            let api_key = std::env::var("OPENAI_API_KEY").unwrap_or_default();
            match base_url_override.or_else(|| std::env::var("OPENAI_BASE_URL").ok()) {
                Some(base_url) => Ok(Box::new(OpenAiProvider::with_base_url(api_key, base_url))),
                None => Ok(Box::new(OpenAiProvider::new(api_key))),
            }
        }
        // §設定「LMStudio は単に base_url=http://localhost:1234/v1 の openai-family
        // プロファイル」。`--base-url`/`OPENAI_API_KEY`/`OPENAI_BASE_URL`での上書きも許す。
        ProviderKind::Lmstudio => {
            // 管理REST API（`/api/v1/`）のトークン。縮退ガードの (d) 段が使う
            // （`plans/DESIGN-COGNITION.md` §11.5）。この開発機のLM Studioでは認証不要のため
            // 通常は未設定で、その場合はトークンを付けずに叩く。
            let mgmt_token = std::env::var("LM_API_TOKEN").ok();
            match base_url_override.or_else(|| std::env::var("OPENAI_BASE_URL").ok()) {
                // **`with_base_url`ではなく`lmstudio_with_base_url`を使う**。前者は系統を
                // `OpenAiFamily::OpenAi`にしてしまい、`--provider lmstudio --base-url ...`が
                // `schema_with_tools:true`・`local:false`・`recycle`無効という、実体と食い違う
                // 能力表明で走っていた（縮約のローカル既定値も (d) 段も効かない）。
                Some(base_url) => Ok(Box::new(
                    OpenAiProvider::lmstudio_with_base_url(base_url).with_mgmt_token(mgmt_token),
                )),
                None => Ok(Box::new(
                    OpenAiProvider::lmstudio().with_mgmt_token(mgmt_token),
                )),
            }
        }
    }
}

/// `--resume <id>`/`--continue`/新規のいずれかで`SessionStore`を用意する
/// （M9、§非対話モード「JSONL 追記型セッション永続化」）。`resume`は値省略（空文字列、
/// ピッカー要求）を渡さない前提（呼び出し側で分岐済み）。
pub(crate) fn resolve_session(
    sessions_dir: &std::path::Path,
    resume: Option<&str>,
    continue_session: bool,
) -> Result<harness_engine::SessionStore, String> {
    if let Some(id) = resume {
        let path = harness_engine::SessionStore::resolve_path(sessions_dir, id);
        if !path.exists() {
            return Err(format!(
                "no session found for --resume {id} ({})",
                path.display()
            ));
        }
        return Ok(harness_engine::SessionStore::open(path));
    }
    if continue_session {
        return harness_engine::SessionStore::resume_latest(sessions_dir)
            .map_err(|e| format!("failed to find latest session: {e}"))?
            .ok_or_else(|| "no existing session to --continue".to_string());
    }
    harness_engine::SessionStore::create_new(sessions_dir)
        .map_err(|e| format!("failed to create session file: {e}"))
}

/// `--list-sessions`の出力レコード（`SessionSummary`はシリアライズ非対応のため、
/// `--output-format json/jsonl`用にここでJSON化可能な形へ写す）。
#[derive(serde::Serialize)]
pub(crate) struct SessionListEntry {
    id: String,
    modified_unix_millis: u128,
    message_count: usize,
    first_prompt: String,
}

impl From<&harness_engine::SessionSummary> for SessionListEntry {
    fn from(s: &harness_engine::SessionSummary) -> Self {
        Self {
            id: s.id.clone(),
            modified_unix_millis: s
                .modified
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            message_count: s.message_count,
            first_prompt: s.first_prompt.clone(),
        }
    }
}

pub(crate) fn print_session_list(
    summaries: &[harness_engine::SessionSummary],
    format: OutputFormat,
) {
    let entries: Vec<SessionListEntry> = summaries.iter().map(SessionListEntry::from).collect();
    match format {
        OutputFormat::Json => {
            if let Ok(s) = serde_json::to_string(&entries) {
                println!("{s}");
            }
        }
        OutputFormat::Jsonl => {
            for entry in &entries {
                if let Ok(s) = serde_json::to_string(entry) {
                    println!("{s}");
                }
            }
        }
        OutputFormat::Text => {
            if entries.is_empty() {
                println!("(no saved sessions)");
            }
            for entry in &entries {
                println!(
                    "{:<16} {:>4} msgs  {}",
                    entry.id, entry.message_count, entry.first_prompt
                );
            }
        }
    }
}
#[cfg(test)]
mod staging_mode_tests {
    use super::resolve_staging_mode;
    use harness_core::StagingMode;

    /// D-29: フラグ無指定時は常にLive（オプトイン、既定の安全策ではない）。
    #[test]
    fn no_flags_defaults_to_live() {
        assert_eq!(resolve_staging_mode(false, false, false), StagingMode::Live);
    }

    #[test]
    fn staged_flag_selects_staged() {
        assert_eq!(
            resolve_staging_mode(false, true, false),
            StagingMode::Staged
        );
    }

    #[test]
    fn workspace_commit_flag_selects_workspace_commit() {
        assert_eq!(
            resolve_staging_mode(false, false, true),
            StagingMode::WorkspaceCommit
        );
    }

    #[test]
    fn live_flag_selects_live() {
        assert_eq!(resolve_staging_mode(true, false, false), StagingMode::Live);
    }
}
