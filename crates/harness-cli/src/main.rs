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
    /// fs passthrough allowlist（軸2・D-13）の台帳保守サブコマンド。
    /// `--fs-allow`実行時フラグとは独立の、ユーザグローバル台帳を操作する副コマンド
    /// （`plans/DESIGN-SANDBOX-APPPOLICY.md`補遺、`TIER1A-OPEN-ISSUES.md`項目4）。
    Fs {
        #[command(subcommand)]
        action: FsAction,
    },
}

/// `harness fs`サブコマンドの各操作。Windows Tier1a固有機能のため、Windows以外では
/// `List`以外はエラーで終了する（台帳自体はクロスプラットフォームのJSONだが、実際のACE
/// 付与・撤収はWin32のSID/ACLに依存するため）。
#[derive(Subcommand)]
enum FsAction {
    /// fs passthrough台帳（ユーザグローバル、D5）を一覧表示する。
    List,
    /// 指定ルートのfs passthroughを撤収する（再walk revoke + 検証パス + 台帳から除去、D3/D4）。
    Revoke { path: PathBuf },
    /// 台帳の全エントリを撤収する。
    RevokeAll,
    /// `target`とその全祖先（ドライブルートまで）へ`FILE_TRAVERSE | FILE_READ_ATTRIBUTES`を
    /// 連鎖付与する（D10連鎖化、`TIER1A-OPEN-ISSUES.md`項目6）。例えば
    /// `C:\Users\<user>\.cargo`を指定すると、`C:\`・`C:\Users`・`C:\Users\<user>`・
    /// `C:\Users\<user>\.cargo`の4ノード全てへ、UAC 1回で付与する。`WRITE_DAC`が要るため
    /// 非管理者では特権分離ヘルパー(D-16)経由でUACを表示する。付与に成功した各ノードは、
    /// 撤収用の別台帳(traverse台帳)へ個別に記録される。
    GrantTraverse { target: PathBuf },
    /// `grant-traverse`で付与したtraverse ACEを1件撤収する（非再帰・単一ノード、D10の巻き戻し）。
    /// 注意: `grant-traverse`が連鎖付与した祖先ノード（`C:\Users`等）は、他のpassthroughルートと
    /// **共有されている可能性がある**。この`revoke-traverse`は指定した1ノードだけを撤収するため、
    /// 他の到達性がまだその祖先ノードに依存している場合は、それを壊してしまう。祖先ノードの
    /// 要否を意識せず一括で戻したい場合は`revoke-traverse-all`を使うこと。
    RevokeTraverse { path: PathBuf },
    /// traverse台帳の全エントリを撤収する。`grant-traverse`で付与した箇所を手打ちで覚える
    /// 必要がなく、記録済みの箇所だけを自動で対象にする。
    RevokeTraverseAll,
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

    /// 協調プロキシ（M12補遺、`plans/DESIGN-SANDBOX-PRIVSEP.md` §3.1 D-15）の許可ドメインを
    /// 追加する（繰り返し指定可、`*.example.com`形式のサフィックスワイルドカード対応）。
    /// `.harness/settings.json`の`net.allow_domains`と合算する（和集合）。1つでも指定される
    /// と`run_shell`子へ`HTTP_PROXY`/`HTTPS_PROXY`を注入するローカルプロキシが起動する
    /// （**強制ではない**、環境変数を無視する生ソケット呼び出しはバイパスできる）。
    #[arg(long = "net-allow-domain")]
    net_allow_domain: Vec<String>,

    /// アプリ単位network制御（軸1、`plans/DESIGN-SANDBOX-APPPOLICY.md` D-10/D-11）の信頼アプリ名を
    /// 追加する（繰り返し指定可、実行ファイルのbasename・拡張子除去・小文字で照合。例`git`）。
    /// `.harness/settings.json`の`net.allow_apps`と合算する（和集合）。Tier1a（AppContainer）でのみ
    /// 効く: 先頭execが一致した単一コマンド（`|`/`&&`/`;`等で連結されていない）にのみ
    /// `internetClient` capabilityを付与し外向き通信を許可する（宛先無差別、T-15でプロセスツリー
    /// 全体が継承）。`--require-sandbox=confidential`と同時指定はできない（意味的に矛盾、起動拒否）。
    #[arg(long = "net-allow-app")]
    net_allow_app: Vec<String>,

    /// fs passthrough allowlist（軸2・D-13、`plans/DESIGN-SANDBOX-APPPOLICY.md`補遺）の
    /// 追加ルートを指定する（繰り返し指定可、`<path>[:rw]`形式）。省略時（末尾`:rw`無し）は
    /// read-only、`:rw`指定時は書込も許可する（D-13「read-onlyを既定とする」）。
    /// `.harness/settings.json`の`fs.allow`と合算する（和集合）。Tier1a（AppContainer）でのみ
    /// 効く: 指定ルートへpackage SIDの許可ACEを付与し、到達性をプローブする（D8）。
    /// `--require-sandbox`との組合せはD7参照（write-containmentは`:rw`のみ拒否、confidentialは
    /// `:ro`/`:rw`いずれも拒否）。
    #[arg(long = "fs-allow")]
    fs_allow: Vec<String>,
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
        // `Fs`はmain()側で`run_fs_subcommand`へ振り分け済みで、ここには到達しない
        // （workspace sandboxのstaging設定を一切必要としないため、`SandboxFs`を開く
        // このパスとは責務が別）。
        Commands::Fs { .. } => unreachable!("Commands::Fs is dispatched before run_sandbox_subcommand"),
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
        Commands::Fs { .. } => unreachable!("Commands::Fs is dispatched before run_sandbox_subcommand"),
    }
}

/// fs passthrough台帳（D5、ユーザグローバル、`directories`設定ディレクトリ配下）の1エントリ。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct FsLedgerEntry {
    path: String,
    writable: bool,
    granted_at_unix_secs: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct FsLedger {
    entries: Vec<FsLedgerEntry>,
}

/// traverse台帳（D10の巻き戻し用、`fs-passthrough-ledger.json`とは別ファイル）の1エントリ。
/// `grant-traverse`は`writable`という概念を持たない（付与するアクセス権は常に
/// `FILE_TRAVERSE | FILE_READ_ATTRIBUTES`固定）ため、`FsLedgerEntry`とは別の小さな型にする。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TraverseLedgerEntry {
    path: String,
    granted_at_unix_secs: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct TraverseLedger {
    entries: Vec<TraverseLedgerEntry>,
}

/// 台帳ファイルのパス（`%APPDATA%\harness\fs-passthrough-ledger.json`相当、`harness-config`の
/// `user_settings_path`と同じ土台）。横断的な穴を1台帳に集約し、どのプロジェクトからでも
/// 全撤収できるようにする（D5）。
fn fs_ledger_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "harness")
        .map(|d| d.config_dir().join("fs-passthrough-ledger.json"))
}

/// traverse台帳ファイルのパス。`fs-passthrough-ledger.json`と意味が異なる記録
/// （ドライブルート/祖先ディレクトリへのtraverse付与）を混在させないため、別ファイルにする。
fn traverse_ledger_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "harness")
        .map(|d| d.config_dir().join("traverse-grant-ledger.json"))
}

/// 台帳が存在しない/読めない/パースできない場合は空扱い（`harness-config`の設定読み込みと
/// 同じfail-open方針、起動を止めない）。
fn load_fs_ledger() -> FsLedger {
    let Some(path) = fs_ledger_path() else {
        return FsLedger::default();
    };
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => FsLedger::default(),
    }
}

fn load_traverse_ledger() -> TraverseLedger {
    let Some(path) = traverse_ledger_path() else {
        return TraverseLedger::default();
    };
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => TraverseLedger::default(),
    }
}

/// 台帳ファイルへの書込を、誤削除防止の2層（read-only属性＋`.bak`バックアップ）を通して行う
/// 共通ヘルパ。エージェント（コーディングツール）による無関係な一括クリーンアップの巻き込みで
/// 台帳が消えると、実際に付与済みのACE（`C:\`等の実システム変更）を追跡する手段が失われ、
/// 「付けたはずだが記録が無い」孤立した穴が残ってしまうため、次の2つを行う。
/// 1. 上書き前に既存ファイルのread-onlyを解除し、`.bak`へコピーしておく（万一の復元用）。
/// 2. 書込後にread-only属性を付与する（`-Force`無しの素の`rm`/`Remove-Item`による削除を防ぐ。
///    確信犯的な`-Force`削除までは防げない、という限界を持つ多層防御の1枚）。
fn write_ledger_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if path.exists() {
        set_file_readonly(path, false);
        let backup_path = path.with_extension("json.bak");
        let _ = std::fs::copy(path, &backup_path);
    }
    if std::fs::write(path, contents).is_ok() {
        set_file_readonly(path, true);
    }
}

/// `path`のread-only属性を切り替える（Windowsの`attrib +R`/`-R`相当）。誤削除防止の一環
/// （`write_ledger_file`参照）。非Windowsでは`set_readonly`の意味論が異なり
/// （chmodのworld-writable相当になり得る）有効な防御にならないため何もしない
/// （`readonly`がリテラル`false`でないためclippyの`permissions_set_readonly_false`は
/// 誤検知しないが、cfg分岐でも意図を明確にする）。
#[cfg(windows)]
fn set_file_readonly(path: &Path, readonly: bool) {
    if let Ok(metadata) = std::fs::metadata(path) {
        let mut perms = metadata.permissions();
        perms.set_readonly(readonly);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(windows))]
fn set_file_readonly(_path: &Path, _readonly: bool) {}

fn save_fs_ledger(ledger: &FsLedger) {
    let Some(path) = fs_ledger_path() else {
        return;
    };
    if let Ok(s) = serde_json::to_string_pretty(ledger) {
        write_ledger_file(&path, &s);
    }
}

fn save_traverse_ledger(ledger: &TraverseLedger) {
    let Some(path) = traverse_ledger_path() else {
        return;
    };
    if let Ok(s) = serde_json::to_string_pretty(ledger) {
        write_ledger_file(&path, &s);
    }
}

/// `--fs-allow`でTier1a preflightが実際にACE付与を試みたルートを台帳へ記録する（D2/D3）。
/// 同一パスは上書き（冪等）。ACE自体は「付けっぱなし」（D2）だが、台帳があるので後から
/// `harness fs revoke`/`revoke-all`で一括撤収できる。
fn record_fs_passthrough_grant(path: &Path, writable: bool) {
    let mut ledger = load_fs_ledger();
    let path_str = path.to_string_lossy().into_owned();
    let granted_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Some(entry) = ledger.entries.iter_mut().find(|e| e.path == path_str) {
        entry.writable = writable;
        entry.granted_at_unix_secs = granted_at;
    } else {
        ledger.entries.push(FsLedgerEntry {
            path: path_str,
            writable,
            granted_at_unix_secs: granted_at,
        });
    }
    save_fs_ledger(&ledger);
}

fn remove_fs_passthrough_grant(path: &Path) {
    let mut ledger = load_fs_ledger();
    let path_str = path.to_string_lossy().into_owned();
    ledger.entries.retain(|e| e.path != path_str);
    save_fs_ledger(&ledger);
}

/// `grant-traverse`が実際にACE付与を試みたパスをtraverse台帳へ記録する（D10の巻き戻し用）。
/// `record_fs_passthrough_grant`と同じ冪等upsert。
fn record_traverse_grant(path: &Path) {
    let mut ledger = load_traverse_ledger();
    let path_str = path.to_string_lossy().into_owned();
    let granted_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Some(entry) = ledger.entries.iter_mut().find(|e| e.path == path_str) {
        entry.granted_at_unix_secs = granted_at;
    } else {
        ledger.entries.push(TraverseLedgerEntry {
            path: path_str,
            granted_at_unix_secs: granted_at,
        });
    }
    save_traverse_ledger(&ledger);
}

fn remove_traverse_grant(path: &Path) {
    let mut ledger = load_traverse_ledger();
    let path_str = path.to_string_lossy().into_owned();
    ledger.entries.retain(|e| e.path != path_str);
    save_traverse_ledger(&ledger);
}

/// `harness fs`サブコマンドのディスパッチ（プロバイダ資格情報・workspace sandboxのいずれも
/// 必要としない、`run_sandbox_subcommand`とは独立のパス）。
fn run_fs_subcommand(action: FsAction) -> ExitCode {
    match action {
        FsAction::List => {
            let ledger = load_fs_ledger();
            println!("=== fs passthrough (--fs-allow) ===");
            if ledger.entries.is_empty() {
                println!("(none)");
            }
            for e in &ledger.entries {
                println!(
                    "{}\t{}\tgranted_at_unix={}",
                    e.path,
                    if e.writable { "rw" } else { "ro" },
                    e.granted_at_unix_secs
                );
            }
            let traverse_ledger = load_traverse_ledger();
            println!("=== traverse grants (grant-traverse) ===");
            if traverse_ledger.entries.is_empty() {
                println!("(none)");
            }
            for e in &traverse_ledger.entries {
                println!("{}\tgranted_at_unix={}", e.path, e.granted_at_unix_secs);
            }
            ExitCode::SUCCESS
        }
        FsAction::Revoke { path } => fs_revoke_one(&path),
        FsAction::RevokeAll => {
            let ledger = load_fs_ledger();
            if ledger.entries.is_empty() {
                println!("(no fs passthrough entries)");
                return ExitCode::SUCCESS;
            }
            let mut any_failed = false;
            for entry in ledger.entries.clone() {
                if fs_revoke_one(&PathBuf::from(&entry.path)) != ExitCode::SUCCESS {
                    any_failed = true;
                }
            }
            if any_failed {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        FsAction::GrantTraverse { target } => fs_grant_traverse(&target),
        FsAction::RevokeTraverse { path } => fs_revoke_traverse_one(&path),
        FsAction::RevokeTraverseAll => {
            let ledger = load_traverse_ledger();
            if ledger.entries.is_empty() {
                println!("(no traverse grants recorded)");
                return ExitCode::SUCCESS;
            }
            let mut any_failed = false;
            for entry in ledger.entries.clone() {
                if fs_revoke_traverse_one(&PathBuf::from(&entry.path)) != ExitCode::SUCCESS {
                    any_failed = true;
                }
            }
            if any_failed {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}

/// 指定パスのfs passthrough ACEを撤収する（D3: 再walk revoke、D4: 剥離後検証パス）。
/// 成功時のみ台帳から除去する（検証パスが残件を見つけた場合は台帳に残し、次回再試行できる
/// ようにする）。
#[cfg(windows)]
fn fs_revoke_one(path: &Path) -> ExitCode {
    let sid = match harness_sandbox::win_appcontainer::ensure_profile(
        harness_sandbox::win_appcontainer::CONTAINER_NAME,
    ) {
        Ok(sid) => sid,
        Err(e) => {
            eprintln!("failed to resolve sandbox SID: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = harness_sandbox::win_appcontainer::revoke_ace_recursive(path, sid.as_psid()) {
        eprintln!("revoke failed for {}: {e}", path.display());
        return ExitCode::FAILURE;
    }
    match harness_sandbox::win_appcontainer::assert_no_sid_ace_recursive(path, sid.as_psid()) {
        Ok(()) => {
            remove_fs_passthrough_grant(path);
            println!("revoked: {}", path.display());
            ExitCode::SUCCESS
        }
        Err(remaining) => {
            eprintln!(
                "revoke incomplete for {}: {} node(s) still carry the sandbox ACE:",
                path.display(),
                remaining.len()
            );
            for p in &remaining {
                eprintln!("  {}", p.display());
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn fs_revoke_one(_path: &Path) -> ExitCode {
    eprintln!("error: fs passthrough revoke is Windows-only (Tier1a specific)");
    ExitCode::FAILURE
}

/// ドライブルートへtraverse ACEを付与する（D10）。`WRITE_DAC`が要るため管理者権限で実行する
/// 必要がある。本体プロセス自身が既に昇格済み（`is_elevated()`）ならACL操作を直接行うが、
/// 通常の非管理者起動時は特権分離ヘルパー（D-16、`plans/DESIGN-SANDBOX-PRIVSEP.md` §5）を
/// `runas`経由で呼び出す（本体プロセス自身は非管理者のまま維持する）。
#[cfg(windows)]
fn fs_grant_traverse(target: &Path) -> ExitCode {
    if harness_sandbox::privhelper::is_elevated() {
        return fs_grant_traverse_direct(target);
    }
    match harness_sandbox::privhelper::run_privileged(
        &harness_sandbox::privhelper::PrivilegedRequest::GrantTraverse {
            target: target.to_path_buf(),
        },
    ) {
        Ok(granted) => {
            for node in &granted {
                record_traverse_grant(node);
            }
            println!(
                "granted FILE_TRAVERSE|FILE_READ_ATTRIBUTES via privilege-separation helper \
                 (UAC, one-time) on the full ancestor chain up to the drive root: {} (see \
                 docs/phases/foundation/M12-shell-isolation-tiers.md 追記8・追記13, \
                 plans/DESIGN-SANDBOX-PRIVSEP.md §5). All {} node(s) recorded in the traverse \
                 ledger; use `harness fs revoke-traverse <path>` per-node or `revoke-traverse-all` \
                 to undo",
                granted
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" -> "),
                granted.len()
            );
            ExitCode::SUCCESS
        }
        Err(harness_sandbox::privhelper::PrivHelperError::PartialGrantChain { granted, reason }) => {
            for node in &granted {
                record_traverse_grant(node);
            }
            eprintln!(
                "grant-traverse chain partially failed for {}: {reason}. {} node(s) that DID \
                 succeed before the failure were still recorded in the traverse ledger (no \
                 orphaned ACEs): {}",
                target.display(),
                granted.len(),
                granted
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            );
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("grant-traverse failed on {}: {e}", target.display());
            ExitCode::FAILURE
        }
    }
}

/// `fs_grant_traverse`の直接実行部分(本体が既に管理者トークンで動作している場合のみ呼ぶ、
/// §5.3「本体が管理者ならヘルパー機構を経由しない直接呼び出しを許すが、そもそも本体が
/// 管理者で起動されたこと自体を警告する」に対応)。
#[cfg(windows)]
fn fs_grant_traverse_direct(target: &Path) -> ExitCode {
    let sid = match harness_sandbox::win_appcontainer::ensure_profile(
        harness_sandbox::win_appcontainer::CONTAINER_NAME,
    ) {
        Ok(sid) => sid,
        Err(e) => {
            eprintln!("failed to resolve sandbox SID: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (granted, result) =
        harness_sandbox::win_appcontainer::grant_traverse_chain(target, sid.as_psid());
    for node in &granted {
        record_traverse_grant(node);
    }
    match result {
        Ok(()) => {
            println!(
                "granted FILE_TRAVERSE|FILE_READ_ATTRIBUTES (admin, one-time; see \
                 docs/phases/foundation/M12-shell-isolation-tiers.md 追記8・追記13) on the full \
                 ancestor chain up to the drive root: {}. All {} node(s) recorded in the \
                 traverse ledger; use `harness fs revoke-traverse <path>` per-node or \
                 `revoke-traverse-all` to undo",
                granted
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" -> "),
                granted.len()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "grant-traverse chain failed on {}: {e} (this requires WRITE_DAC on each \
                 ancestor node; re-run as administrator). {} node(s) that DID succeed before \
                 the failure were still recorded in the traverse ledger: {}",
                target.display(),
                granted.len(),
                granted
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn fs_grant_traverse(_target: &Path) -> ExitCode {
    eprintln!("error: fs grant-traverse is Windows-only (Tier1a specific)");
    ExitCode::FAILURE
}

/// 指定パスのtraverse ACEを撤収する（非再帰・単一ノード、D10の巻き戻し）。
/// `grant_traverse_drive_root`（`grant_ace_mask`による非継承・単一ACE付与）の逆操作なので、
/// `revoke_ace`（単一ノード）+ `assert_no_sid_ace`（単一ノード検証）を使う。
/// `revoke_ace_recursive`/`assert_no_sid_ace_recursive`（ツリー全体を再walk）は、`path`が
/// ドライブルートの場合に不要な全走査を招くため使わない。`fs_grant_traverse`と同じく、
/// 本体が既に昇格済みなら直接、それ以外は特権分離ヘルパー（D-16）経由で実行する。
#[cfg(windows)]
fn fs_revoke_traverse_one(path: &Path) -> ExitCode {
    if harness_sandbox::privhelper::is_elevated() {
        return fs_revoke_traverse_one_direct(path);
    }
    match harness_sandbox::privhelper::run_privileged(
        &harness_sandbox::privhelper::PrivilegedRequest::RevokeTraverse {
            path: path.to_path_buf(),
        },
    ) {
        Ok(_) => {
            remove_traverse_grant(path);
            println!(
                "revoked traverse ACE via privilege-separation helper: {}",
                path.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("revoke-traverse failed for {}: {e}", path.display());
            ExitCode::FAILURE
        }
    }
}

#[cfg(windows)]
fn fs_revoke_traverse_one_direct(path: &Path) -> ExitCode {
    let sid = match harness_sandbox::win_appcontainer::ensure_profile(
        harness_sandbox::win_appcontainer::CONTAINER_NAME,
    ) {
        Ok(sid) => sid,
        Err(e) => {
            eprintln!("failed to resolve sandbox SID: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = harness_sandbox::win_appcontainer::revoke_ace(path, sid.as_psid()) {
        eprintln!("revoke-traverse failed for {}: {e}", path.display());
        return ExitCode::FAILURE;
    }
    match harness_sandbox::win_appcontainer::assert_no_sid_ace(path, sid.as_psid()) {
        Ok(()) => {
            remove_traverse_grant(path);
            println!("revoked traverse ACE: {}", path.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("revoke-traverse verification failed for {}: {e}", path.display());
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn fs_revoke_traverse_one(_path: &Path) -> ExitCode {
    eprintln!("error: fs revoke-traverse is Windows-only (Tier1a specific)");
    ExitCode::FAILURE
}

#[tokio::main]
async fn main() -> ExitCode {
    // 本体プロセスが管理者権限で起動されていないかを確認する（D-16、
    // `plans/DESIGN-SANDBOX-PRIVSEP.md` §5.3）。harness本体は常に非管理者トークンで動作する
    // 設計であり、ヘルパー機構が無い間は実害が無いが（WFP/VHDX自体を使わないため）、
    // 「本体が管理者ならヘルパー経由でない直接呼び出しに倒れていないか」を明示的に確認する
    // 材料として警告ログを残す。拒否はしない。
    #[cfg(windows)]
    if harness_sandbox::privhelper::is_elevated() {
        eprintln!(
            "warning: harness is running with an elevated (administrator) token. harness is \
             designed to always run as a non-administrator process; privileged operations \
             (e.g. `harness fs grant-traverse`) should go through the privilege-separation \
             helper (D-16, plans/DESIGN-SANDBOX-PRIVSEP.md §5.3), not this elevated \
             process directly."
        );
    }

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
        return match cmd {
            Commands::Fs { action } => run_fs_subcommand(action),
            other => run_sandbox_subcommand(other, &workspace_root),
        };
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

    // 協調プロキシ設定（M12補遺、D-15）。CLI `--net-allow-domain`（繰り返し）と
    // `.harness/settings.json`の`net.allow_domains`を和集合でマージする（重複除去）。
    let mut net_proxy = settings.net.clone().unwrap_or_default().to_net_proxy_config();
    for domain in &cli.net_allow_domain {
        if !net_proxy.allow_domains.contains(domain) {
            net_proxy.allow_domains.push(domain.clone());
        }
    }

    // アプリ単位network制御（軸1、D-10/D-11）。CLI `--net-allow-app`（繰り返し）と
    // `.harness/settings.json`の`net.allow_apps`を和集合でマージする（重複除去、net_proxyと同形）。
    let mut net_app = settings.net.clone().unwrap_or_default().to_net_app_policy();
    for app in &cli.net_allow_app {
        if !net_app.allow_apps.contains(app) {
            net_app.allow_apps.push(app.clone());
        }
    }

    // シェル隔離Tier選択（M12、`plans/DESIGN-SANDBOX.md` §6/§7 D-03）。`--require-sandbox`指定時は
    // 自動降格せず起動を拒否する（既存の`--dangerously-allow`と同じfail-fastパターン）。
    let require_sandbox = parse_require_sandbox(cli.require_sandbox.as_deref());

    // confidential（外部持出し経路を作らない明示拒否モード＝通信許可リストを無効化する上位モード）
    // と net-allow-app（通信を開く）は意味的に矛盾するため、黙って無視/弱めず起動を拒否する
    // （`--require-sandbox`のsatisfiesと同じfail-fast思想、`plans/DESIGN-SANDBOX-APPPOLICY.md` §7）。
    if require_sandbox == RequireSandbox::Confidential && !net_app.allow_apps.is_empty() {
        eprintln!(
            "error: --net-allow-app conflicts with --require-sandbox=confidential (confidential \
             mode denies all outbound network unconditionally; refusing to start rather than \
             silently ignoring --net-allow-app or weakening the confidentiality guarantee)"
        );
        return ExitCode::FAILURE;
    }

    // fs passthrough allowlist（軸2・D-13）。CLI `--fs-allow`（繰り返し）と
    // `.harness/settings.json`の`fs.allow`を和集合でマージする（重複除去、net_appと同形）。
    // 各要素は`<path>[:rw]`（末尾`:rw`が無ければread-only既定、D-13）。パスは`workspace_root`
    // 基準で絶対化する（既に絶対パスなら`Path::join`はそのまま採用する）。
    let mut fs_allow_raw: Vec<(String, bool)> =
        settings.fs.clone().unwrap_or_default().to_fs_passthrough();
    for entry in &cli.fs_allow {
        let (path, writable) = match entry.strip_suffix(":rw") {
            Some(p) => (p.to_string(), true),
            None => (entry.clone(), false),
        };
        if !fs_allow_raw.iter().any(|(p, _)| p == &path) {
            fs_allow_raw.push((path, writable));
        }
    }
    let fs_passthrough: Vec<harness_sandbox::FsPassthrough> = fs_allow_raw
        .into_iter()
        .map(|(path, writable)| harness_sandbox::FsPassthrough {
            path: workspace_root.join(&path),
            writable,
        })
        .collect();
    if !fs_passthrough.is_empty() && !cfg!(windows) {
        eprintln!(
            "warning: --fs-allow / fs.allow is only supported on Windows (Tier1a); ignored on \
             this OS"
        );
    }

    // D7: --require-sandboxとの矛盾チェック。write-containmentは範囲外書込を禁じるため:rwのみ
    // 拒否（:roは書込に無関係で許可）。confidentialは範囲外を読めない保証のため:ro/:rwいずれも
    // 拒否する（外部読取穴がconfidentialの機密性保証と正面から矛盾するため、
    // `--net-allow-app`×confidentialと同じfail-fast思想）。
    let fs_has_write = fs_passthrough.iter().any(|fp| fp.writable);
    match require_sandbox {
        RequireSandbox::WriteContainment if fs_has_write => {
            eprintln!(
                "error: --fs-allow with :rw conflicts with --require-sandbox (write-containment \
                 forbids writes outside the workspace; use read-only --fs-allow entries instead, \
                 or drop --require-sandbox)"
            );
            return ExitCode::FAILURE;
        }
        RequireSandbox::Confidential if !fs_passthrough.is_empty() => {
            eprintln!(
                "error: --fs-allow conflicts with --require-sandbox=confidential (confidential \
                 mode denies reading outside the workspace unconditionally; even read-only \
                 --fs-allow breaks this guarantee; refusing to start rather than silently \
                 weakening it)"
            );
            return ExitCode::FAILURE;
        }
        _ => {}
    }

    let shell_tier = match select_tier(
        require_sandbox,
        &workspace_root,
        cli.experimental_tier1a,
        &fs_passthrough,
    ) {
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
    // fs passthrough（D2/D-13）: ACE付与自体は「付けっぱなし」（撤収はユーザ操作
    // `harness fs revoke`に委ねる）。Tier1aが実際に選択された場合のみpreflightがACE付与を
    // 試みたので、そのときだけ台帳に記録する。到達不能だった穴の診断（D8/D9）はここで表示する。
    if shell_tier.tier == harness_core::ShellTier::Tier1a {
        for fp in &fs_passthrough {
            record_fs_passthrough_grant(&fp.path, fp.writable);
            eprintln!(
                "note: fs-allow granted: {} [{}] (this ACE persists after harness exits; use \
                 `harness fs revoke {}` to undo)",
                fp.path.display(),
                if fp.writable { "rw" } else { "ro" },
                fp.path.display()
            );
        }
    }
    for warning in &shell_tier.passthrough_warnings {
        eprintln!("warning: {warning}");
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
        net_proxy,
        net_app,
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
