//! `AppState`: `AgentEvent`を畳み込んで保持するTUI側の状態。`plans/DESIGN.md` §リッチTUI参照。

use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEventKind};

use harness_core::{AgentEvent, RiskClass, StopReason, ToolOutput, Usage};
use harness_engine::{parse_allowlist_rule, AllowlistRule, Decision, PermissionMode};

use crate::diff::{line_diff, DiffLine};

/// transcript末尾に表示する一時的な「考え中」インジケータのスピナーグリフ。
/// `AppState::spinner_frame`でインデックスし、`lib.rs`の描画tick（33ms間隔）ごとに送る。
pub const SPINNER_FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

#[derive(Debug, Clone)]
pub enum ToolCardStatus {
    Running,
    Done { is_error: bool, output: String },
}

#[derive(Debug, Clone)]
pub enum TranscriptItem {
    User(String),
    Assistant(String),
    Thinking(String),
    ToolCard {
        id: String,
        name: String,
        input: String,
        status: ToolCardStatus,
    },
    Error(String),
    /// キャンセル/コンテキスト圧縮/スラッシュコマンド実行結果等の付随的な通知
    /// （エラーではないので`Error`と区別、M9）。
    Info(String),
}

#[derive(Debug, Clone)]
pub struct PermissionView {
    pub id: String,
    pub tool: String,
    pub risk: RiskClass,
    pub input: String,
    /// `tool == "edit_file"`の場合、`old_string`/`new_string`から計算した差分（M9、
    /// DESIGN.md L349「edit_fileの差分プレビューを承認モーダル内に描画」）。
    pub diff: Option<Vec<DiffLine>>,
}

/// `/model /mode /allow /compact /clear /fork /sessions /fsstage`（M9、DESIGN.md L349
/// 「スラッシュコマンド」+ セッションFork/一覧の拡張。`/fsstage`はM10の変更（changes）パネルを
/// キーバインドではなくスラッシュコマンドから操作するためのもの。Ctrl+GはVSCode統合ターミナルの
/// 既定ショートカットと衝突するため、`/fsstage`へ置き換えて廃止した）。
mod commands;
mod events;
mod input;

use commands::parse_slash_command;
pub use commands::{Action, FsStageCommand, SlashCommand};

#[cfg(test)]
#[path = "app_state_tests.rs"]
mod tests;

/// 変更（changes）パネルの表示用1行。`ChangeEntry`本体に加え、差分プレビュー
/// （パネルを開いた時点で一度だけ計算、`diff.rs::line_diff`）を持つ。
#[derive(Debug, Clone)]
pub struct ChangeRow {
    pub entry: harness_sandbox::ChangeEntry,
    pub diff: Vec<DiffLine>,
}

/// 変更パネルの状態。`rejected`に含まれるインデックスは`c`（コミット）から除外される
/// （既定は全件accept、reject印を付けたものだけ除外するgit-add -p同様のUX）。
#[derive(Debug, Clone)]
pub struct ChangesPanelState {
    pub rows: Vec<ChangeRow>,
    pub selected: usize,
    pub rejected: std::collections::HashSet<usize>,
}

pub struct AppState {
    pub transcript: Vec<TranscriptItem>,
    pub input: String,
    /// `input`中でのカーソル位置（バイト単位ではなく文字単位。マルチバイト文字を
    /// 誤った境界で分割しないため、挿入/削除時は`char_indices`でバイトオフセットに変換する）。
    pub input_cursor: usize,
    /// 選択のアンカー位置（文字インデックス）。`Some`のとき`input_cursor`との間が選択範囲。
    /// アンカー==カーソルは「選択なし」と同義に扱う。Shift+矢印/Ctrl+Aで設定され、
    /// Shift無しのカーソル移動・Enter・通常の編集操作で`None`に戻る。
    pub input_selection_anchor: Option<usize>,
    /// 入力欄のUndo履歴。`(input, input_cursor)`のスナップショットを変更前に積む。
    input_undo_stack: Vec<(String, usize)>,
    /// Undoした変更を取り消す（Redo）ためのスタック。新しい編集が入ると`push_undo_snapshot`
    /// でクリアされる（Undoの標準的な挙動）。
    input_redo_stack: Vec<(String, usize)>,
    /// 直前の変更が「選択なしの単純な1文字挿入」だったか。連続するタイピングを1つの
    /// Undo単位にまとめる（1文字ずつUndoすると使いづらいため）ためのフラグ。
    input_last_edit_was_insert: bool,
    pub pending_permission: Option<PermissionView>,
    pub provider_label: String,
    pub model: String,
    pub last_usage: Usage,
    pub last_stop_reason: Option<StopReason>,
    /// 直前の`TextDelta`がAssistantテキストの続きかどうか。`TurnStarted`/ツールカード挿入で
    /// リセットし、新しいターンのテキストが別の`Assistant`項目として積まれるようにする。
    turn_open: bool,
    /// 現在の試行が書き始めた`transcript`上の位置（`transcript.len()`）。
    ///
    /// 縮退で1回分の応答が破棄されたとき（`AgentEvent::TurnDiscarded`、M21）に、
    /// **画面に出てしまった本文をここまで巻き戻す**ために持つ。`TurnStarted`で設定し、
    /// 破棄を1件処理するたびに更新する（更新しないと、次の破棄で「破棄しました」の
    /// 記録行まで消えてしまう）。
    turn_transcript_mark: usize,
    pub should_quit: bool,
    /// transcriptの最新行から何行遡っているか（0=最新へ追従）。総行数は折り畳み状態に応じて
    /// 描画時にしか決まらないため、上限のクランプは`ui.rs::render_transcript`側で行う。
    pub scroll_offset: u16,
    /// `Ctrl+O`でトグルする、ツールカード/thinkingブロックの折り畳み表示状態。
    /// 既定は折り畳み（`true`）。
    pub collapsed: bool,

    /// 現在ターンが送信〜完了の間かどうか。ステータスバーが概算値（ライブ更新）と確定値
    /// （`last_usage`）のどちらを表示するかを切り替える（リアルタイムトークン表示）。
    pub turn_in_flight: bool,
    /// このターンの`AgentEvent::TurnStarted.estimated_input_tokens`（Upstream概算、
    /// ターン開始時点で一度だけ確定し以降変化しない）。
    pub current_turn_upstream_estimate: u64,
    /// このターンで`TextDelta`/`ThinkingDelta`として受信した文字数の累計
    /// （Downstream概算、chars/4がライブのoutputトークン概算になる）。
    pub current_turn_downstream_chars: u64,
    /// 完了済み全ターンの確定`Usage`の合算（セッション累計、概算は含まない）。
    pub session_usage: Usage,
    /// 「Thinking…」進捗インジケータの開始時刻。`Some`の間だけtranscript末尾に一時表示する
    /// （`app.transcript`本体には追加しない一時的な行）。最初の可視コンテンツ
    /// （`TextDelta`/`ToolCallProposed`）またはターン終了で`None`に戻す。
    pub thinking_progress: Option<Instant>,
    /// このターンで`ThinkingDelta`を1回でも受けたか。`thinking_progress`が消える際、
    /// `(thought for Ns)`という記録行を残すかどうかの判定に使う
    /// （thinking未使用のターンでは記録行を出さない）。
    saw_thinking_this_turn: bool,
    /// スピナーのフレーム送り用カウンタ。`tick()`が33ms間隔で呼ぶ。
    pub spinner_frame: usize,
    /// `true`のときEnterが送信（後方互換モード）。`false`（既定）のときEnterは入力欄に改行を
    /// 挿入し、送信はAlt+EnterまたはShift+Enterで行う（`true`のときもAlt+Enter/Shift+Enterは
    /// 常に送信）。
    /// （`.harness/settings.json`の`enter_submits`、`harness-cli`が`AppState::new`後に
    /// この`pub`フィールドへ直接設定する。他の全31箇所の`AppState::new`呼び出し
    /// ―主に既存テスト―を変更せずに済むよう、コンストラクタ引数にはしない）。
    pub enter_submits: bool,
    /// `HARNESS_KEY_DEBUG=1`のとき`true`。受信した各`KeyEvent`をtranscriptへInfo行として
    /// echoし、VS Code等の端末が実際にどんな`code`/`modifiers`を届けているかを画面で観測する
    /// （Enter系キー化けの検証用。`harness-cli`が`AppState::new`後にこのpubフィールドへ設定）。
    pub key_debug: bool,
    /// `TERM_PROGRAM=vscode`のとき`true`（`terminal::host_is_vscode`）。キー処理の分岐には
    /// 使わない（Shift+Enterが送信になるかどうかはSHIFT修飾が実際に届くか否かで自然に決まる）。
    /// 入力欄のヒント文字列（Alt+Enter/Shift+Enterどちらを案内するか）の表示専用。
    pub host_is_vscode: bool,
    /// 変更（changes）パネル（M10）。`Some`の間は他の全キー入力をパネル操作専用に奪う
    /// （`pending_permission`と同じ排他パターン）。
    pub changes_panel: Option<ChangesPanelState>,
}

/// `PageUp`/`PageDown`1回あたりのスクロール行数。端末の実際の高さは`AppState`が知らないため
/// 固定値で近似する（おおよそ1画面分）。
const PAGE_SCROLL_LINES: i32 = 10;
/// マウスホイール1ノッチあたりのスクロール行数。
const WHEEL_SCROLL_LINES: i32 = 3;

impl AppState {
    pub fn new(provider_label: String, model: String) -> Self {
        Self {
            transcript: Vec::new(),
            input: String::new(),
            input_cursor: 0,
            input_selection_anchor: None,
            input_undo_stack: Vec::new(),
            input_redo_stack: Vec::new(),
            input_last_edit_was_insert: false,
            pending_permission: None,
            provider_label,
            model,
            last_usage: Usage::default(),
            last_stop_reason: None,
            turn_open: false,
            turn_transcript_mark: 0,
            should_quit: false,
            scroll_offset: 0,
            collapsed: true,
            turn_in_flight: false,
            current_turn_upstream_estimate: 0,
            current_turn_downstream_chars: 0,
            session_usage: Usage::default(),
            thinking_progress: None,
            saw_thinking_this_turn: false,
            spinner_frame: 0,
            enter_submits: false,
            key_debug: false,
            host_is_vscode: false,
            changes_panel: None,
        }
    }

    /// 変更パネルを開く（既定で全件accept、`rejected`は空）。
    pub fn open_changes_panel(&mut self, rows: Vec<ChangeRow>) {
        self.changes_panel = Some(ChangesPanelState {
            rows,
            selected: 0,
            rejected: Default::default(),
        });
    }

    /// キーイベントecho（`note_key_event`）を有効化し、有効である旨のバナーをtranscriptへ出す。
    /// バナーは`HARNESS_KEY_DEBUG`が実際に効いているかを起動直後に一目で確認するためのもの。
    pub fn enable_key_debug(&mut self) {
        self.key_debug = true;
        self.transcript.push(TranscriptItem::Info(
            "key debug mode ON: 以降このパネルに各キーイベントをecho（HARNESS_KEY_DEBUG）".into(),
        ));
    }

    /// `key_debug`が有効なとき、受信した生`KeyEvent`をtranscriptへInfo行としてechoする
    /// （Enter系キー化けの検証用。実際の`code`/`modifiers`/`kind`を画面で確認できる）。
    /// `key_debug`が無効なら何もしない。
    pub fn note_key_event(&mut self, key: KeyEvent) {
        if !self.key_debug {
            return;
        }
        self.transcript.push(TranscriptItem::Info(format!(
            "key: code={:?} modifiers={:?} kind={:?}",
            key.code, key.modifiers, key.kind
        )));
    }

    /// 描画tick（33ms間隔）ごとに呼ぶ。スピナーのフレームを送るだけ。
    pub fn tick(&mut self) {
        self.spinner_frame = self.spinner_frame.wrapping_add(1);
    }

    /// `thinking_progress`が表示中だった場合、それを終了させる共通処理。thinkingを実際に
    /// 使ったターンだけ`(thought for Ns)`という記録行をtranscriptへ残す
    /// （§リッチTUI「Thinking…」進捗インジケータ、Claude Code CLIの"Thought for Ns"相当）。
    fn end_thinking_progress(&mut self, record: bool) {
        if let Some(started) = self.thinking_progress.take() {
            if record && self.saw_thinking_this_turn {
                let elapsed = started.elapsed().as_secs_f32();
                self.transcript
                    .push(TranscriptItem::Info(format!("(thought for {elapsed:.1}s)")));
            }
        }
    }

    /// `delta`が正なら過去方向（上）へ、負なら最新方向（下）へスクロールする。
    /// 下限0（最新）でクランプする。上限は総行数依存のため描画側でクランプする。
    pub fn scroll_lines(&mut self, delta: i32) {
        if delta >= 0 {
            self.scroll_offset = self.scroll_offset.saturating_add(delta as u16);
        } else {
            self.scroll_offset = self.scroll_offset.saturating_sub((-delta) as u16);
        }
    }

    pub fn scroll_page(&mut self, delta: i32) {
        self.scroll_lines(delta * PAGE_SCROLL_LINES);
    }

    pub fn toggle_fold(&mut self) {
        self.collapsed = !self.collapsed;
        self.scroll_offset = 0;
    }

    /// マウスホイールイベントを処理する。過去ログの閲覧を妨げないよう、承認モーダル表示中でも
    /// スクロール自体は許可する（`on_key`と異なり`pending_permission`をチェックしない）。
    pub fn on_mouse(&mut self, kind: MouseEventKind) {
        match kind {
            MouseEventKind::ScrollUp => self.scroll_lines(WHEEL_SCROLL_LINES),
            MouseEventKind::ScrollDown => self.scroll_lines(-WHEEL_SCROLL_LINES),
            _ => {}
        }
    }

    pub fn push_user_prompt(&mut self, text: String) {
        self.transcript.push(TranscriptItem::User(text));
        self.turn_open = false;
    }

    /// 入力欄の内容を送信する（スラッシュコマンドならパースして`Action::Slash`、それ以外は
    /// `Action::Submit`）。Alt+Enterと、`enter_submits`時の素のEnterから共通で呼ばれる。
    pub fn note_resumed_session(&mut self, message_count: usize) {
        self.transcript.push(TranscriptItem::Info(format!(
            "resumed session ({message_count} messages)"
        )));
    }
}
