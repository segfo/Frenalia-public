//! harness-cli: clapエントリ。`plans/DESIGN.md` §非対話（ヘッドレス）モード/§リッチTUI参照。
//!
//! M2時点では `--print` によるAnthropic/OpenAIへのストリーミング呼び出しをサポートする。
//! 受信したテキストデルタをその場でstdoutへ書き出す（トークン逐次表示、§実装マイルストーン M2）。
//! M3で `read_file`/`run_shell` を登録した `ToolRegistry` を使い `run_agent_loop` へ
//! 切り替えた。M4で `PermissionArbiter` を配線し、`--permission-mode`/`--allow` を追加した。
//! 既定モードは `Default`（read-only自動許可、Write/Exec/Networkはヘッドレスにつき自動拒否、
//! §パーミッション「ヘッドレス時」）で、M3までの「一旦allow-all」から「allowlist-or-deny」へ
//! 切り替わる（§実装マイルストーン M4）。M6で`--provider lmstudio`を追加した（実体は
//! `OpenAiProvider::lmstudio()`、`base_url=http://localhost:1234/v1`のopenai-familyプロファイル）。
//! M7で`-p/--print`を省略可にし、省略時は`harness-tui`の対話ループへ切り替える
//! （§実装マイルストーン M7「対話でストリーミング描画 + 承認ダイアログ操作」）。
//! M8で`--output-format text|json|jsonl`（安定json/jsonl出力、実体は`harness_cli::run_headless`）と
//! `--dangerously-allow`（`--permission-mode accept-all`の明示必須化・ワイルドカード
//! `--allow`ルールの明示必須化、§非対話モード「危険/ワイルドカードは`--dangerously-allow`」）を
//! 追加した。M10で`harness_sandbox::SandboxFs`（オーバーレイFS）を配線し、`--live`/`--staged`/
//! `--workspace-commit`（明示時はそのまま採用、省略時はパス毎のgit認識型判定：追跡済み・
//! 変更ゼロ→live、それ以外→headless既定staged/TUI既定workspace_commit）、および
//! `apply`/`changes`/`discard`サブコマンドを追加した。

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use harness_cli::{run_headless, OutputFormat};
use harness_core::{LlmProvider, RequireSandbox, StagingConfig, StagingMode, ToolCtx};
use harness_engine::{
    parse_allowlist_rule, AgentLoopConfig, ConversationState, PermissionArbiter, PermissionMode,
};
use harness_providers::{AnthropicProvider, OpenAiProvider};
use harness_sandbox::{select_tier, ApplyOptions, SandboxFs};
use harness_tools::ToolRegistry;

const DEFAULT_ANTHROPIC_MODEL: &str = "claude-opus-4-8";
const DEFAULT_MAX_TOKENS: u32 = 4096;
const DEFAULT_MAX_TURNS: usize = 25;

#[derive(Clone, Copy, ValueEnum)]
enum ProviderKind {
    Anthropic,
    Openai,
    Lmstudio,
}

impl ProviderKind {
    fn label(self) -> &'static str {
        match self {
            ProviderKind::Anthropic => "anthropic",
            ProviderKind::Openai => "openai",
            ProviderKind::Lmstudio => "lmstudio",
        }
    }
}

#[derive(Clone, Copy, ValueEnum, Default)]
enum PermissionModeArg {
    Plan,
    #[default]
    Default,
    AcceptEdits,
    AcceptAll,
    Deny,
}

impl From<PermissionModeArg> for PermissionMode {
    fn from(v: PermissionModeArg) -> Self {
        match v {
            PermissionModeArg::Plan => PermissionMode::Plan,
            PermissionModeArg::Default => PermissionMode::Default,
            PermissionModeArg::AcceptEdits => PermissionMode::AcceptEdits,
            PermissionModeArg::AcceptAll => PermissionMode::AcceptAll,
            PermissionModeArg::Deny => PermissionMode::Deny,
        }
    }
}

/// ステージ済み変更（`harness_sandbox::SandboxFs`のオーバーレイ）を操作するサブコマンド
/// （§オーバーレイFS「レビュー＆コミット」、M10）。
#[derive(Subcommand)]
enum Commands {
    /// ステージ済み変更を一覧表示する。
    Changes {
        /// 対象セッションID（省略時は`.harness/sandbox/`内で最も新しいもの）。
        #[arg(long)]
        session: Option<String>,
        #[arg(long = "output-format", value_enum, default_value_t = OutputFormat::Text)]
        output_format: OutputFormat,
    },
    /// ステージ済み変更を実FSへ選択適用する。
    Apply {
        #[arg(long)]
        session: Option<String>,
        /// 選択適用フィルタ（`*`ワイルドカード対応、例 `src/*`）。省略時は全件対象。
        #[arg(long)]
        only: Option<String>,
        /// `_ext/`（workspace外ターゲット、例 `C:\Windows\x`）の適用を許可する。
        #[arg(long = "dangerously-allow", default_value_t = false)]
        dangerously_allow: bool,
        #[arg(long = "output-format", value_enum, default_value_t = OutputFormat::Text)]
        output_format: OutputFormat,
    },
    /// ステージ済み変更を全て破棄する。
    Discard {
        #[arg(long)]
        session: Option<String>,
    },
}

#[derive(Parser)]
#[command(name = "harness")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// 非対話モードでプロンプトを送信し、応答をstdoutへ出力する。値が "-" ならstdinから読む。
    /// 省略時は対話TUI（`harness-tui`）を起動する（§リッチTUI、M7）。
    #[arg(short = 'p', long = "print")]
    print: Option<String>,

    /// 使用するモデルID。省略時、Anthropicは既定モデルを使う（OpenAIは省略不可）。
    #[arg(long)]
    model: Option<String>,

    /// 使用するプロバイダ。
    #[arg(long, value_enum, default_value_t = ProviderKind::Anthropic)]
    provider: ProviderKind,

    /// パーミッションモード（§パーミッション（承認）システム「モード」）。
    #[arg(long = "permission-mode", value_enum, default_value_t = PermissionModeArg::default())]
    permission_mode: PermissionModeArg,

    /// allowlistルール（`tool:pattern`形式、繰り返し指定可）。例: `run_shell:git status*`
    /// パターンが完全ワイルドカード（`*`単体）の場合は`--dangerously-allow`が無いと無視される
    /// （§非対話モード「危険/ワイルドカードは`--dangerously-allow`」）。
    #[arg(long = "allow")]
    allow: Vec<String>,

    /// `--permission-mode accept-all`の使用、および`--allow`の完全ワイルドカード
    /// （`tool:*`）パターンを許可する明示フラグ。無いとどちらも起動時に拒否/無視される
    /// （§非対話モード「危険/ワイルドカードは`--dangerously-allow`」）。
    #[arg(long = "dangerously-allow", default_value_t = false)]
    dangerously_allow: bool,

    /// 非対話モードの出力形式（§非対話モード「出力」）。`-p`省略時（対話TUI）は無視される。
    #[arg(long = "output-format", value_enum, default_value_t = OutputFormat::Text)]
    output_format: OutputFormat,

    /// プロバイダのbase_urlを明示指定する（`--provider`に応じて`ANTHROPIC_BASE_URL`/
    /// `OPENAI_BASE_URL`環境変数より優先される。§設定とシークレット「CLIフラグ（最優先）」）。
    /// 例: `--base-url http://localhost:1234/v1`
    #[arg(long = "base-url")]
    base_url: Option<String>,

    /// 暴走ループの保険（1ターン=1プロバイダターン+ツール実行、§実装マイルストーン M9で
    /// 正式な設定項目化）。省略時は`settings.json`階層→既定値の順にフォールバックする。
    #[arg(long = "max-turns")]
    max_turns: Option<usize>,

    /// ワークスペースルートを明示指定する（省略時はカレントディレクトリ、§非対話モード）。
    #[arg(long = "cwd")]
    cwd: Option<std::path::PathBuf>,

    /// `.harness/sessions/session-<id>.jsonl`を復元して会話を継続する（M9、JSONL追記型
    /// セッション永続化）。`<id>`は`--continue`無しで起動した際にセッションファイル名から
    /// 拾える（`session-{id}.jsonl`）。値を省略した場合（`--resume`のみ）、対話TUI起動時に
    /// セッション選択ピッカーを開く。ヘッドレス（`-p`指定時）で値省略は非対話原則によりエラー。
    #[arg(long = "resume", num_args = 0..=1, default_missing_value = "")]
    resume: Option<String>,

    /// `.harness/sessions/`内の最も新しいセッションを復元して継続する。`--resume`と併用不可。
    #[arg(long = "continue", conflicts_with = "resume")]
    continue_session: bool,

    /// `--resume <id>`/`--continue`が指し示す既存セッションをForkして開始する（Claude Codeの
    /// `--fork-session`相当）。元のセッションファイルは変更せず、新規セッションへ全履歴を
    /// コピーしてから継続する。`--resume`/`--continue`のいずれかと併用必須。
    #[arg(long = "fork-session", default_value_t = false)]
    fork_session: bool,

    /// `.harness/sessions/`配下の保存済みセッションを一覧表示して終了する。プロンプトは送らない。
    #[arg(long = "list-sessions", default_value_t = false)]
    list_sessions: bool,

    /// TUI入力欄でEnterを送信キーにする（既定はShift+Enterが送信、素のEnterは改行を挿入）。
    /// 省略時は`settings.json`階層→既定値(false)の順にフォールバックする
    /// （`-p/--print`省略時＝対話TUI起動時のみ意味を持つ）。
    #[arg(long = "enter-submits")]
    enter_submits: Option<bool>,

    /// 即実FS（オーバーレイ無し）。`--staged`/`--workspace-commit`と併用不可
    /// （§書込ステージング3モード、M10）。
    #[arg(long = "live", conflicts_with_all = ["staged", "workspace_commit"])]
    live: bool,

    /// 全書込をステージングし、実FSは`harness apply`まで不変にする
    /// （headless既定、§書込ステージング3モード）。
    #[arg(long = "staged", conflicts_with_all = ["live", "workspace_commit"])]
    staged: bool,

    /// workspace内はステージング→レビュー＆コミット、workspace外は常にsandbox隔離
    /// （対話TUI既定、§書込ステージング3モード）。
    #[arg(long = "workspace-commit", conflicts_with_all = ["live", "staged"])]
    workspace_commit: bool,

    /// シェル隔離Tierの最低要求（M12、`plans/DESIGN-SANDBOX.md` §7 D-03）。指定時は
    /// 自動降格せず、要求を満たせない場合に起動を拒否する。値省略（`--require-sandbox`単体）は
    /// 「書込拘束以上」（Tier1b/Tier2でpass、Tier0で拒否）、`=confidential`は「機密性も要求」
    /// （Tier2のみpass）。省略時は制約無し（Tier0への自動降格も許容）。
    #[arg(long = "require-sandbox", num_args = 0..=1, default_missing_value = "write-containment")]
    require_sandbox: Option<String>,

    /// Windows専用の実験的Tier1a（AppContainer）を試す（`plans/DESIGN-SANDBOX.md` §6.3/§7 D-02、
    /// 既定はfalse=Tier1bのまま）。プロファイル作成/ACL付与のいずれかが失敗した場合は自動的に
    /// Tier1bへ降格し警告する（他OSでは無視される）。Windows非管理者環境で機密性まで守りたい場合
    /// （T-04/T-10対策）、または`--require-sandbox=confidential`を通したい場合に指定する。
    #[arg(long = "experimental-tier1a", default_value_t = false)]
    experimental_tier1a: bool,
}

/// `--require-sandbox[=confidential]`の文字列表現を`RequireSandbox`へ変換する
/// （M12、`plans/DESIGN-SANDBOX.md` §7 D-03）。未知の値は`write-containment`扱いにする
/// （clapの`default_missing_value`と揃える安全側フォールバック）。
fn parse_require_sandbox(value: Option<&str>) -> RequireSandbox {
    match value {
        None => RequireSandbox::None,
        Some("confidential") => RequireSandbox::Confidential,
        Some(_) => RequireSandbox::WriteContainment,
    }
}

/// `--live`/`--staged`/`--workspace-commit`から`(explicit, fallback_mode)`を決める。
/// 明示指定が無い場合、`fallback_mode`はgit認識型判定（追跡済み・変更ゼロ→live）で
/// liveと判定されなかったパスにだけ適用される既定モード（headless=Staged/TUI=WorkspaceCommit）。
fn resolve_staging_mode(live: bool, staged: bool, workspace_commit: bool, is_headless: bool) -> (bool, StagingMode) {
    if live {
        (true, StagingMode::Live)
    } else if staged {
        (true, StagingMode::Staged)
    } else if workspace_commit {
        (true, StagingMode::WorkspaceCommit)
    } else if is_headless {
        (false, StagingMode::Staged)
    } else {
        (false, StagingMode::WorkspaceCommit)
    }
}

/// `session_id`（`session-<id>`形式）に対応する`.harness/sandbox/<id>/`を
/// `workspace_root`からの相対パスで返す。
fn sandbox_dir_for_session(session_id: &str) -> PathBuf {
    PathBuf::from(".harness").join("sandbox").join(session_id)
}

/// `--session <id>`指定が無い場合に`.harness/sandbox/`直下で最も更新日時の新しいものを選ぶ
/// （`apply`/`changes`/`discard`の既定対象）。
fn resolve_sandbox_dir(workspace_root: &Path, session: Option<&str>) -> Option<PathBuf> {
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
        let Ok(metadata) = entry.metadata() else { continue };
        let Ok(modified) = metadata.modified() else { continue };
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        if newest.as_ref().is_none_or(|(_, t)| modified > *t) {
            newest = Some((name.to_string(), modified));
        }
    }
    newest.map(|(name, _)| sandbox_dir_for_session(&name))
}

fn build_provider(kind: ProviderKind, base_url_override: Option<String>) -> Result<Box<dyn LlmProvider>, String> {
    // §設定とシークレット: CLIフラグ > env優先、プロジェクト設定に永続化しない・ログに出さない・
    // 起動時fail-fast。
    match kind {
        ProviderKind::Anthropic => {
            let api_key =
                std::env::var("ANTHROPIC_API_KEY").map_err(|_| "ANTHROPIC_API_KEY is not set".to_string())?;
            match base_url_override.or_else(|| std::env::var("ANTHROPIC_BASE_URL").ok()) {
                Some(base_url) => Ok(Box::new(AnthropicProvider::with_base_url(api_key, base_url))),
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
            let api_key = std::env::var("OPENAI_API_KEY").unwrap_or_default();
            match base_url_override.or_else(|| std::env::var("OPENAI_BASE_URL").ok()) {
                Some(base_url) => Ok(Box::new(OpenAiProvider::with_base_url(api_key, base_url))),
                None => Ok(Box::new(OpenAiProvider::lmstudio())),
            }
        }
    }
}

/// `--resume <id>`/`--continue`/新規のいずれかで`SessionStore`を用意する
/// （M9、§非対話モード「JSONL 追記型セッション永続化」）。`resume`は値省略（空文字列、
/// ピッカー要求）を渡さない前提（呼び出し側で分岐済み）。
fn resolve_session(
    sessions_dir: &std::path::Path,
    resume: Option<&str>,
    continue_session: bool,
) -> Result<harness_engine::SessionStore, String> {
    if let Some(id) = resume {
        let path = harness_engine::SessionStore::resolve_path(sessions_dir, id);
        if !path.exists() {
            return Err(format!("no session found for --resume {id} ({})", path.display()));
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
struct SessionListEntry {
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

fn print_session_list(summaries: &[harness_engine::SessionSummary], format: OutputFormat) {
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

fn resolve_model(model: Option<String>, kind: ProviderKind) -> Result<String, String> {
    match (model, kind) {
        (Some(m), _) => Ok(m),
        (None, ProviderKind::Anthropic) => Ok(DEFAULT_ANTHROPIC_MODEL.to_string()),
        (None, ProviderKind::Openai) => Err("--model is required when --provider openai is used".into()),
        (None, ProviderKind::Lmstudio) => {
            Err("--model is required when --provider lmstudio is used".into())
        }
    }
}

/// `harness apply`のJSON出力（`--output-format json`）。
#[derive(serde::Serialize)]
struct ApplyReportJson {
    applied: Vec<String>,
    conflicts: Vec<String>,
    ext_blocked: Vec<String>,
    hard_denied: Vec<String>,
}

/// `apply`/`changes`/`discard`サブコマンドを処理する。プロバイダ資格情報を一切必要としない
/// （§非対話モード、プロンプトは一切送らない）。
fn run_sandbox_subcommand(cmd: Commands, workspace_root: &Path) -> ExitCode {
    let (session, output_format_and_kind) = match &cmd {
        Commands::Changes { session, output_format } => (session.clone(), Some(*output_format)),
        Commands::Apply { session, output_format, .. } => (session.clone(), Some(*output_format)),
        Commands::Discard { session } => (session.clone(), None),
    };

    let Some(sandbox_dir) = resolve_sandbox_dir(workspace_root, session.as_deref()) else {
        eprintln!("no staged sandbox found under .harness/sandbox/ (nothing to show)");
        return ExitCode::FAILURE;
    };
    let staging = StagingConfig {
        mode: StagingMode::Staged,
        explicit: true,
        sandbox_dir: Some(sandbox_dir),
    };
    let fs = match SandboxFs::open(workspace_root, &staging) {
        Ok(fs) => fs,
        Err(e) => {
            eprintln!("failed to open sandbox: {e}");
            return ExitCode::FAILURE;
        }
    };

    match cmd {
        Commands::Changes { .. } => {
            let changes = match fs.change_set() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("failed to read changes: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match output_format_and_kind.unwrap_or_default() {
                OutputFormat::Json => {
                    if let Ok(s) = serde_json::to_string(&changes) {
                        println!("{s}");
                    }
                }
                OutputFormat::Jsonl => {
                    for c in &changes {
                        if let Ok(s) = serde_json::to_string(c) {
                            println!("{s}");
                        }
                    }
                }
                OutputFormat::Text => {
                    if changes.is_empty() {
                        println!("(no staged changes)");
                    }
                    for c in &changes {
                        println!("{:?}\t{:?}\t{}", c.op, c.target, c.path);
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Commands::Apply { only, dangerously_allow, .. } => {
            let report = match fs.apply(&ApplyOptions {
                only_glob: only.as_deref(),
                only_paths: None,
                allow_ext: dangerously_allow,
            }) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("apply failed: {e}");
                    return ExitCode::FAILURE;
                }
            };
            // hard_deniedもconflicts/ext_blocked同様「apply未完了、要注意」の一種として
            // 非ゼロ終了コードに含める（D-05: 設定注入パスは絶対に解除しない）。
            let has_conflicts_or_blocked = !report.conflicts.is_empty()
                || !report.ext_blocked.is_empty()
                || !report.hard_denied.is_empty();
            match output_format_and_kind.unwrap_or_default() {
                OutputFormat::Json => {
                    let json = ApplyReportJson {
                        applied: report.applied,
                        conflicts: report.conflicts,
                        ext_blocked: report.ext_blocked,
                        hard_denied: report.hard_denied,
                    };
                    if let Ok(s) = serde_json::to_string(&json) {
                        println!("{s}");
                    }
                }
                OutputFormat::Jsonl | OutputFormat::Text => {
                    for p in &report.applied {
                        println!("applied: {p}");
                    }
                    for p in &report.conflicts {
                        println!("conflict (baseline mismatch, not applied): {p}");
                    }
                    for p in &report.ext_blocked {
                        println!("blocked (out-of-workspace, needs --dangerously-allow): {p}");
                    }
                    for p in &report.hard_denied {
                        println!("hard-denied (config-injection path, D-05): {p}");
                    }
                }
            }
            if has_conflicts_or_blocked {
                ExitCode::from(4)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Discard { .. } => match fs.discard() {
            Ok(()) => {
                println!("discarded staged changes");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("discard failed: {e}");
                ExitCode::FAILURE
            }
        },
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    // カレントディレクトリの`.env`があれば読み込み、プロセスのenvへ反映する（既存の環境変数は
    // 上書きしない、§設定とシークレット「ユーザ/プロジェクト設定」相当の簡易版）。無ければ無視する。
    let _ = dotenvy::dotenv();

    let cli = Cli::parse();

    let workspace_root = match cli.cwd.clone() {
        Some(dir) => dir,
        None => match std::env::current_dir() {
            Ok(dir) => dir,
            Err(e) => {
                eprintln!("failed to resolve current directory: {e}");
                return ExitCode::FAILURE;
            }
        },
    };

    // `apply`/`changes`/`discard`サブコマンドはプロバイダ資格情報を一切必要としないため、
    // 他のあらゆる検証より前に処理して即終了する（§非対話モード、プロンプトは一切送らない）。
    if let Some(cmd) = cli.command {
        return run_sandbox_subcommand(cmd, &workspace_root);
    }

    // `--list-sessions`はプロバイダ資格情報を一切必要としないため、他のあらゆる検証より前に
    // 処理して即終了する（§非対話モード、プロンプトは一切送らない）。
    if cli.list_sessions {
        let sessions_dir = workspace_root.join(".harness").join("sessions");
        return match harness_engine::SessionStore::list(&sessions_dir) {
            Ok(summaries) => {
                print_session_list(&summaries, cli.output_format);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("failed to list sessions in {}: {e}", sessions_dir.display());
                ExitCode::FAILURE
            }
        };
    }

    // 引数なし`--resume`（値省略、空文字列扱い）はヘッドレスでは非対話原則により拒否する。
    // ピッカーはTTYが要る対話TUIでのみ意味を持つ（§非対話モード「ヘッドレスモードは対話
    // プロンプトを一切出さない」）。
    let resume_wants_picker = cli.resume.as_deref() == Some("");
    if resume_wants_picker && cli.print.is_some() {
        eprintln!("--resume without a value opens an interactive picker and is not supported with -p/--print; pass --resume <id> explicitly");
        return ExitCode::FAILURE;
    }
    let resume_id = cli.resume.clone().filter(|s| !s.is_empty());

    if cli.fork_session && resume_id.is_none() && !cli.continue_session {
        eprintln!("--fork-session requires --resume <id> or --continue");
        return ExitCode::FAILURE;
    }
    if cli.fork_session && resume_wants_picker {
        eprintln!("--fork-session cannot be combined with a bare --resume (use the picker's 'f' key instead)");
        return ExitCode::FAILURE;
    }

    // §設定とシークレット「既定 → ユーザ → プロジェクト → CLIフラグ（最優先）」。CLIフラグが
    // 明示されていればそちらを使い、無ければ`settings.json`階層へフォールバックする
    // （`permission_mode`/`output_format`はclapの`default_value_t`で常に値を持つため
    // このフォールバックの対象外、CLI値をそのまま使う）。
    let settings = harness_config::Settings::load(&workspace_root);

    let provider = match build_provider(cli.provider, cli.base_url) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let model = match resolve_model(cli.model.or(settings.model.clone()), cli.provider) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let max_turns = cli.max_turns.or(settings.max_turns).unwrap_or(DEFAULT_MAX_TURNS);
    let enter_submits = cli.enter_submits.or(settings.enter_submits).unwrap_or(false);

    let tools = ToolRegistry::with_builtin_tools();

    // §非対話モード「危険/ワイルドカードは`--dangerously-allow`」: accept-allモードは
    // fail-fastで拒否する（`--dangerously-allow`が無いままの誤起動を防ぐ）。
    if matches!(cli.permission_mode, PermissionModeArg::AcceptAll) && !cli.dangerously_allow {
        eprintln!(
            "--permission-mode accept-all requires --dangerously-allow (see plans/DESIGN.md §非対話モード)"
        );
        return ExitCode::FAILURE;
    }

    let allowlist: Vec<_> = settings
        .allow
        .clone()
        .unwrap_or_default()
        .iter()
        .chain(cli.allow.iter())
        .filter_map(|rule| match parse_allowlist_rule(rule) {
            None => {
                eprintln!("ignoring malformed --allow rule (expected tool:pattern): {rule}");
                None
            }
            Some(r) if harness_cli::is_dangerous_wildcard(&r.pattern) && !cli.dangerously_allow => {
                eprintln!("ignoring wildcard --allow rule without --dangerously-allow: {rule}");
                None
            }
            Some(r) => Some(r),
        })
        .collect();
    let arbiter = PermissionArbiter::new(cli.permission_mode.into(), allowlist);

    // JSONL追記型セッション永続化（M9、§非対話モード「JSONL 追記型セッション永続化
    // （`--resume`/`--continue`）」）。`.harness/sessions/`直下に1ファイル1セッション。
    let sessions_dir = workspace_root.join(".harness").join("sessions");
    if let Err(e) = std::fs::create_dir_all(&sessions_dir) {
        eprintln!("failed to create sessions directory {}: {e}", sessions_dir.display());
        return ExitCode::FAILURE;
    }
    let mut session = match resolve_session(&sessions_dir, resume_id.as_deref(), cli.continue_session) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    // `--fork-session`: 解決済みの元セッションを不変のまま、全履歴を新規セッションへコピーして
    // 以降の追記先を切り替える（Claude Codeの`--fork-session`/`/branch`相当）。
    if cli.fork_session {
        let source_id = session.id();
        match harness_engine::SessionStore::fork_from(&sessions_dir, session.path()) {
            Ok(forked) => {
                eprintln!("forked session {source_id} -> {}", forked.id());
                session = forked;
            }
            Err(e) => {
                eprintln!("failed to fork session {source_id}: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    let mut state = ConversationState::new();
    match session.load_messages() {
        Ok(msgs) => state.messages = msgs,
        Err(e) => {
            eprintln!("failed to load session {}: {e}", session.path().display());
            return ExitCode::FAILURE;
        }
    }

    // 書込ステージング設定（M10）。`sandbox_dir`は`session.id()`確定後でなければ組めないため
    // ここで`ToolCtx`を構築する。明示`--live`時はオーバーレイ自体を使わない
    // （`sandbox_dir: None`、M9までの直接実FSアクセスとバイト等価・監査ログも作らない）。
    let (explicit, staging_mode) =
        resolve_staging_mode(cli.live, cli.staged, cli.workspace_commit, cli.print.is_some());
    let sandbox_dir = if explicit && staging_mode == StagingMode::Live {
        None
    } else {
        Some(sandbox_dir_for_session(&session.id()))
    };
    let read_scope = settings
        .read
        .clone()
        .unwrap_or_default()
        .to_read_scope_config();

    // シェル隔離Tier選択（M12、`plans/DESIGN-SANDBOX.md` §6/§7 D-03）。`--require-sandbox`指定時は
    // 自動降格せず起動を拒否する（既存の`--dangerously-allow`と同じfail-fastパターン）。
    let require_sandbox = parse_require_sandbox(cli.require_sandbox.as_deref());
    let shell_tier = match select_tier(require_sandbox, &workspace_root, cli.experimental_tier1a) {
        Ok(selection) => selection,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(reason) = &shell_tier.reason {
        eprintln!(
            "warning: shell isolation downgraded to {} (from {}): {reason}",
            shell_tier.tier.label(),
            shell_tier
                .downgraded_from
                .map(|t| t.label())
                .unwrap_or("?")
        );
    }
    if shell_tier.tier == harness_core::ShellTier::Tier1b {
        eprintln!(
            "note: shell isolation tier is tier1b (Windows default); this does not protect \
             against reading confidential files outside the workspace or outbound network \
             exfiltration from run_shell child processes (plans/DESIGN-SANDBOX.md §9-1). \
             Use --require-sandbox=confidential (with --experimental-tier1a) if this matters."
        );
    }

    let tool_ctx = ToolCtx {
        workspace_root: workspace_root.clone(),
        staging: StagingConfig {
            mode: staging_mode,
            explicit,
            sandbox_dir,
        },
        read_scope,
        shell_tier,
    };

    match cli.print {
        Some(print) => {
            let prompt = if print == "-" {
                let mut buf = String::new();
                if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
                    eprintln!("failed to read prompt from stdin: {e}");
                    return ExitCode::FAILURE;
                }
                buf
            } else {
                print
            };

            state.push_user_text(prompt);
            if let Err(e) = session.append_messages(&state.messages[state.messages.len() - 1..]) {
                eprintln!("failed to persist session {}: {e}", session.path().display());
                return ExitCode::FAILURE;
            }
            let before_run = state.messages.len();

            let mut stdout = std::io::stdout();
            let exit = run_headless(
                provider.as_ref(),
                &mut state,
                &tools,
                &tool_ctx,
                &arbiter,
                AgentLoopConfig {
                    model,
                    max_tokens: DEFAULT_MAX_TOKENS,
                    max_turns,
                },
                cli.output_format,
                &mut stdout,
            )
            .await;
            let _ = session.append_messages(&state.messages[before_run..]);
            exit
        }
        None => {
            let log_dir = workspace_root.join(".harness").join("logs");
            if let Err(e) = std::fs::create_dir_all(&log_dir) {
                eprintln!("failed to create log directory {}: {e}", log_dir.display());
                return ExitCode::FAILURE;
            }
            // tracing出力先をファイルへ切り替えた後でなければTUI側の`tracing::debug!`等が
            // 直接stdoutを汚してしまう（§リッチTUI「tracingは全てtracing-appenderでファイルへ」）。
            let _log_guard = harness_tui::init_file_logging(&log_dir);

            let result = harness_tui::run(
                provider,
                tools,
                tool_ctx,
                arbiter,
                model,
                DEFAULT_MAX_TOKENS,
                max_turns,
                cli.provider.label().to_string(),
                state,
                session,
                sessions_dir,
                enter_submits,
                resume_wants_picker,
            )
            .await;

            match result {
                Ok(_) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("tui error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
