//! スラッシュコマンドの語彙と構文解析（純粋関数）。
//!
//! 入力欄の文字列を[`SlashCommand`]/[`FsStageCommand`]へ写すだけで、状態もI/Oも持たない。
//! キー入力の解釈（[`super::input`]）とも、エンジンからのイベント消費（[`super::events`]）とも
//! 独立している。

use super::*;

#[derive(Debug, Clone, PartialEq)]
pub enum SlashCommand {
    Model(String),
    Mode(PermissionMode),
    Allow(AllowRule),
    Compact,
    Clear,
    /// 現在のセッションをForkし、以降の追記を新しいセッションファイルへ切り替える。
    Fork,
    /// セッションピッカーを開き、既存セッションへ切り替える。
    Sessions,
    /// `/fsstage`のサブコマンド（変更パネル/ステージ済み変更の操作）。
    FsStage(FsStageCommand),
    /// `/memory`のサブコマンド（`Recall`の事後レビュー運用、`plans/PLAN-RECALL-MEMORY.md`）。
    Memory(MemoryCommand),
    /// `/workspace <path>`: 別のワークスペースへ移る。
    ///
    /// **プロセス内では移らず、そのパスで`harness.exe`を起動し直す**（`crate::RunOutcome`）。
    /// `workspace_root`はD-54のcapability台帳・モードmutex・preflight・背景`grant_job`・
    /// traverse台帳・ログ出力先・MCP・Recall記憶鍵すべての基点で、プロセス途中で動かすことは
    /// 起動パイプラインをもう一度実行するのと同義だからである（しかもmutex・loopback
    /// exemption・WFPフィルタ・昇格ヘルパーのパイプはプロセス寿命に紐付いている）。
    Workspace(String),
}

/// `/memory`のサブコマンド。
///
/// - `/memory`: 未レビューのcheckpoint一覧をtranscriptへ表示（非対話）
/// - `/memory reviewed`: 一覧表示したうえでウォーターマークを進める
/// - `/memory discard <id>`: 指定checkpointを削除
#[derive(Debug, Clone, PartialEq)]
pub enum MemoryCommand {
    List,
    MarkReviewed,
    Discard(String),
}

/// `/fsstage`のサブコマンド。
///
/// - `/fsstage` `/fsstage list`: 一覧をtranscriptへテキスト表示（非対話）
/// - `/fsstage commit`: 対話パネルを開く（ファイル毎accept/reject、旧Ctrl+G相当）
/// - `/fsstage commit <file>`: 指定ファイル1件だけを非対話で即commit
/// - `/fsstage commit_all`: 全件を非対話で即commit
/// - `/fsstage discard`: 全破棄（非対話、パネルを開かない）
/// - `/fsstage resolve` `/fsstage resolve <path>`: コンフリクト解消（非対話、結果を
///   transcriptへ積むだけ、パネルは開かない）。省略時は全コンフリクト対象、指定時は1件だけ。
#[derive(Debug, Clone, PartialEq)]
pub enum FsStageCommand {
    List,
    Open,
    CommitAll,
    CommitFile(String),
    Discard,
    Resolve(Option<String>),
}

/// `/`始まりの入力行をパースする。不正なコマンド/引数は`Err(理由)`。
pub(super) fn parse_slash_command(input: &str) -> Result<SlashCommand, String> {
    let mut parts = input.trim().splitn(2, char::is_whitespace);
    let cmd = parts.next().unwrap_or("");
    let rest = parts.next().unwrap_or("").trim();
    match cmd {
        "/model" if !rest.is_empty() => Ok(SlashCommand::Model(rest.to_string())),
        "/model" => Err("usage: /model <model-id>".to_string()),
        "/mode" => rest.parse::<PermissionMode>().map(SlashCommand::Mode),
        "/allow" => parse_allowlist_rule(rest)
            .map(SlashCommand::Allow)
            .map_err(|reason| format!("/allow: {reason}")),
        "/compact" => Ok(SlashCommand::Compact),
        "/clear" => Ok(SlashCommand::Clear),
        "/fork" => Ok(SlashCommand::Fork),
        "/sessions" => Ok(SlashCommand::Sessions),
        "/fsstage" => parse_fsstage_subcommand(rest).map(SlashCommand::FsStage),
        "/memory" => parse_memory_subcommand(rest).map(SlashCommand::Memory),
        "/workspace" if !rest.is_empty() => Ok(SlashCommand::Workspace(rest.to_string())),
        "/workspace" => Err("usage: /workspace <path>".to_string()),
        other => Err(format!("unknown command: {other}")),
    }
}

/// `/memory`の`rest`（サブコマンド以降）をパースする。
pub(super) fn parse_memory_subcommand(rest: &str) -> Result<MemoryCommand, String> {
    let mut parts = rest.splitn(2, char::is_whitespace);
    let sub = parts.next().unwrap_or("");
    let sub_rest = parts.next().unwrap_or("").trim();
    match sub {
        "" => Ok(MemoryCommand::List),
        "reviewed" => Ok(MemoryCommand::MarkReviewed),
        "discard" if !sub_rest.is_empty() => Ok(MemoryCommand::Discard(sub_rest.to_string())),
        "discard" => Err("usage: /memory discard <id>".to_string()),
        other => Err(format!("unknown /memory subcommand: {other}")),
    }
}

/// `/fsstage`の`rest`（サブコマンド以降）をパースする。
pub(super) fn parse_fsstage_subcommand(rest: &str) -> Result<FsStageCommand, String> {
    let mut parts = rest.splitn(2, char::is_whitespace);
    let sub = parts.next().unwrap_or("");
    let sub_rest = parts.next().unwrap_or("").trim();
    match sub {
        "" | "list" => Ok(FsStageCommand::List),
        "commit" if sub_rest.is_empty() => Ok(FsStageCommand::Open),
        "commit" => Ok(FsStageCommand::CommitFile(sub_rest.to_string())),
        "commit_all" => Ok(FsStageCommand::CommitAll),
        "discard" => Ok(FsStageCommand::Discard),
        "resolve" if sub_rest.is_empty() => Ok(FsStageCommand::Resolve(None)),
        "resolve" => Ok(FsStageCommand::Resolve(Some(sub_rest.to_string()))),
        other => Err(format!("unknown /fsstage subcommand: {other}")),
    }
}

/// キー入力の結果、engineアクター/oneshotへ伝えるべきアクション。
#[derive(Debug)]

pub enum Action {
    Submit(String),
    Respond(String, Decision),
    /// 承認モーダルの「恒久的に承認」（確認の一段を通ったもの）。中身は承認要求のidと、
    /// 穴にする引数の位置（D-105）。`Respond`と分けているのは、**規則を作って台帳へ書く**という
    /// 別の仕事が要るからである（`InteractiveGate::respond_remember`）。
    RespondRemember(String, Vec<usize>),
    Slash(SlashCommand),
    /// 現在進行中のターンをキャンセルする（M9、Escキー）。
    Cancel,
    Quit,
    /// 変更（changes）パネルを開く（`/fsstage commit`、旧Ctrl+G相当）。呼び出し側
    /// （`harness-tui::run`）が`SandboxFs::change_set()`を読んで`AppState::open_changes_panel`
    /// を呼ぶ（`AppState`自体はサンドボックスへアクセスしない）。既にパネルが開いていても
    /// 単に最新の変更セットで開き直す（トグルではない）。
    OpenChangesPanel,
    /// レビューパネルで`c`（コミット）を押した結果、または`/fsstage commit <file>`。
    /// ファイルまるごと適用する分（`SandboxFs::apply`の`only_paths`）と、ハンクを選んで
    /// 適用する分（`SandboxFs::apply_hunks`）の両方を持つ（`app::review::commit_selection`）。
    CommitChanges(CommitSelection),
    /// `/fsstage commit_all`（非対話、パネルを開かず全件commit）。
    CommitAllChanges,
    /// `/fsstage list`（非対話、パネルを開かずtranscriptへテキスト表示）。
    ListChanges,
    /// 変更パネルで`x`（破棄）を押した結果、または`/fsstage discard`（非対話）。
    DiscardChanges,
    /// `/fsstage resolve [path]`（非対話、パネルを開かない）。`Some(path)`なら1件だけ、
    /// `None`なら全コンフリクト対象。呼び出し側（`harness-tui::run`）が
    /// `harness_sandbox::resolve`を叩き、エディタ起動の前後で端末を中断・復帰させる。
    ResolveChanges(Option<String>),
    /// 選んだ文章をクリップボードへ写す（`Ctrl+C`・右クリック。改行はクリップボードの形の`CRLF`にしてある）。呼び出し側
    /// （`harness-tui::run`）が`harness_term::clipboard::write`で書き、結果を`AppState::note_copied`へ渡す
    /// （`AppState`自体はクリップボードへ触らない。`app::select`のモジュールdoc）。
    Copy(String),
}
