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

/// `/model /mode /allow /compact /clear /fork /sessions`（M9、DESIGN.md L349
/// 「スラッシュコマンド」+ セッションFork/一覧の拡張）。
#[derive(Debug, Clone, PartialEq)]
pub enum SlashCommand {
    Model(String),
    Mode(PermissionMode),
    Allow(AllowlistRule),
    Compact,
    Clear,
    /// 現在のセッションをForkし、以降の追記を新しいセッションファイルへ切り替える。
    Fork,
    /// セッションピッカーを開き、既存セッションへ切り替える。
    Sessions,
}

/// `/`始まりの入力行をパースする。不正なコマンド/引数は`Err(理由)`。
fn parse_slash_command(input: &str) -> Result<SlashCommand, String> {
    let mut parts = input.trim().splitn(2, char::is_whitespace);
    let cmd = parts.next().unwrap_or("");
    let rest = parts.next().unwrap_or("").trim();
    match cmd {
        "/model" if !rest.is_empty() => Ok(SlashCommand::Model(rest.to_string())),
        "/model" => Err("usage: /model <model-id>".to_string()),
        "/mode" => rest.parse::<PermissionMode>().map(SlashCommand::Mode),
        "/allow" => parse_allowlist_rule(rest)
            .map(SlashCommand::Allow)
            .ok_or_else(|| "usage: /allow <tool>:<pattern>".to_string()),
        "/compact" => Ok(SlashCommand::Compact),
        "/clear" => Ok(SlashCommand::Clear),
        "/fork" => Ok(SlashCommand::Fork),
        "/sessions" => Ok(SlashCommand::Sessions),
        other => Err(format!("unknown command: {other}")),
    }
}

/// キー入力の結果、engineアクター/oneshotへ伝えるべきアクション。
#[derive(Debug)]
pub enum Action {
    Submit(String),
    Respond(String, Decision),
    Slash(SlashCommand),
    /// 現在進行中のターンをキャンセルする（M9、Escキー）。
    Cancel,
    Quit,
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
    /// 挿入し、送信はAlt+Enterで行う。いずれのモードでもShift+Enterは無効化（何もしない）。
    /// （`.harness/settings.json`の`enter_submits`、`harness-cli`が`AppState::new`後に
    /// この`pub`フィールドへ直接設定する。他の全31箇所の`AppState::new`呼び出し
    /// ―主に既存テスト―を変更せずに済むよう、コンストラクタ引数にはしない）。
    pub enter_submits: bool,
    /// `HARNESS_KEY_DEBUG=1`のとき`true`。受信した各`KeyEvent`をtranscriptへInfo行として
    /// echoし、VS Code等の端末が実際にどんな`code`/`modifiers`を届けているかを画面で観測する
    /// （Enter系キー化けの検証用。`harness-cli`が`AppState::new`後にこのpubフィールドへ設定）。
    pub key_debug: bool,
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
        }
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
    fn submit_input(&mut self) -> Option<Action> {
        if self.input.trim().is_empty() {
            return None;
        }
        let text = std::mem::take(&mut self.input);
        self.input_cursor = 0;
        self.input_selection_anchor = None;
        self.input_undo_stack.clear();
        self.input_redo_stack.clear();
        self.input_last_edit_was_insert = false;
        if text.trim_start().starts_with('/') {
            return match parse_slash_command(&text) {
                Ok(cmd) => {
                    self.transcript.push(TranscriptItem::Info(format!("> {text}")));
                    Some(Action::Slash(cmd))
                }
                Err(reason) => {
                    self.transcript.push(TranscriptItem::Error(reason));
                    None
                }
            };
        }
        self.push_user_prompt(text.clone());
        Some(Action::Submit(text))
    }

    /// `--resume`/`--continue`で会話を復元した際、TUI起動直後に1行だけ通知する（M9）。
    /// 復元した`ContentBlock`列をツールカード等へ完全再構成するのはコストに見合わないため、
    /// 件数のみを知らせるに留める。
    pub fn note_resumed_session(&mut self, message_count: usize) {
        self.transcript
            .push(TranscriptItem::Info(format!("resumed session ({message_count} messages)")));
    }

    pub fn apply(&mut self, ev: AgentEvent) {
        match ev {
            AgentEvent::TurnStarted { estimated_input_tokens } => {
                self.turn_open = false;
                self.turn_in_flight = true;
                self.current_turn_upstream_estimate = estimated_input_tokens;
                self.current_turn_downstream_chars = 0;
                self.saw_thinking_this_turn = false;
                self.thinking_progress = Some(Instant::now());
            }
            AgentEvent::TextDelta { text } => {
                self.current_turn_downstream_chars += text.chars().count() as u64;

                if !self.turn_open {
                    // モデル（特にLMStudio経由のローカルモデル）がチャットテンプレートの都合で
                    // 応答冒頭に意味の無い改行/空白だけのデルタを送ってくることがある。
                    // まだ非空白の内容が届いていないうちに「考え中」インジケータを消して
                    // 空のAssistant項目を作ってしまうと、インジケータが消えた場所に空行だけが
                    // 残ってしまう。実際に非空白の内容が来た最初のデルタで初めてインジケータを
                    // 終了しAssistant項目を作ることで、この空行を防ぐ
                    // （空白だけのデルタ自体は`current_turn_downstream_chars`には既に加算済み
                    // なので、ライブのトークン概算からは取りこぼさない）。
                    let visible = text.trim_start_matches(['\n', '\r', ' ', '\t']);
                    if visible.is_empty() {
                        return;
                    }
                    self.end_thinking_progress(true);
                    self.transcript.push(TranscriptItem::Assistant(visible.to_string()));
                    self.turn_open = true;
                    return;
                }

                if let Some(TranscriptItem::Assistant(s)) = self.transcript.last_mut() {
                    s.push_str(&text);
                }
            }
            AgentEvent::ThinkingDelta { text } => {
                self.current_turn_downstream_chars += text.chars().count() as u64;
                self.saw_thinking_this_turn = true;
                if let Some(TranscriptItem::Thinking(s)) = self.transcript.last_mut() {
                    s.push_str(&text);
                } else {
                    self.transcript.push(TranscriptItem::Thinking(text));
                }
            }
            AgentEvent::ToolCallProposed { id, name, input } => {
                self.end_thinking_progress(true);
                self.turn_open = false;
                self.transcript.push(TranscriptItem::ToolCard {
                    id,
                    name,
                    input: pretty(&input),
                    status: ToolCardStatus::Running,
                });
            }
            AgentEvent::PermissionRequired {
                id,
                tool,
                risk,
                input,
            } => {
                // `edit_file`は`old_string`/`new_string`から差分を作れる場合のみdiffを埋める
                // （§リッチTUI「edit_fileの差分プレビューを承認モーダル内に描画」）。
                let diff = if tool == "edit_file" {
                    let old = input.get("old_string").and_then(|v| v.as_str());
                    let new = input.get("new_string").and_then(|v| v.as_str());
                    match (old, new) {
                        (Some(old), Some(new)) => Some(line_diff(old, new)),
                        _ => None,
                    }
                } else {
                    None
                };
                self.pending_permission = Some(PermissionView {
                    id,
                    tool,
                    risk,
                    input: pretty(&input),
                    diff,
                });
            }
            AgentEvent::ToolStarted { .. } => {}
            AgentEvent::ToolProgress { id, message } => {
                tracing::debug!(id, message, "tool progress");
            }
            AgentEvent::ToolFinished { id, output } => {
                if let Some(TranscriptItem::ToolCard { status, .. }) =
                    self.transcript.iter_mut().rev().find(
                        |i| matches!(i, TranscriptItem::ToolCard { id: cid, .. } if *cid == id),
                    )
                {
                    *status = ToolCardStatus::Done {
                        is_error: output.is_error,
                        output: truncate_output(&output),
                    };
                }
            }
            AgentEvent::TurnCompleted { stop_reason, usage } => {
                self.last_stop_reason = Some(stop_reason);
                self.last_usage = usage;
                self.session_usage.input = self.session_usage.input.saturating_add(usage.input);
                self.session_usage.output = self.session_usage.output.saturating_add(usage.output);
                self.session_usage.cache_read =
                    self.session_usage.cache_read.saturating_add(usage.cache_read);
                self.session_usage.cache_creation =
                    self.session_usage.cache_creation.saturating_add(usage.cache_creation);
                self.turn_open = false;
                self.turn_in_flight = false;
                // 本文もツール呼び出しも一切無いまま終わるターン（安全網）。記録行は残さず黙って消す。
                self.end_thinking_progress(false);
            }
            AgentEvent::Error { message } => {
                self.transcript.push(TranscriptItem::Error(message));
                self.turn_open = false;
                self.turn_in_flight = false;
                self.end_thinking_progress(false);
            }
            AgentEvent::Cancelled => {
                self.transcript.push(TranscriptItem::Info("cancelled".to_string()));
                self.turn_open = false;
                self.turn_in_flight = false;
                self.end_thinking_progress(false);
            }
            AgentEvent::ContextCompacted { removed_messages } => {
                self.transcript.push(TranscriptItem::Info(format!(
                    "context compacted ({removed_messages} messages summarized)"
                )));
            }
            AgentEvent::SessionSwitched { source_id, new_id, message_count } => {
                let msg = match source_id {
                    Some(src) => format!("forked session {src} -> {new_id} ({message_count} messages)"),
                    None => format!("switched to session {new_id} ({message_count} messages)"),
                };
                self.transcript.push(TranscriptItem::Info(msg));
            }
        }
    }

    /// 現在の選択範囲を文字インデックスの`(start, end)`（`start <= end`）で返す。
    /// アンカー未設定、またはアンカーとカーソルが同一位置（選択なし）の場合は`None`。
    pub fn selection_range(&self) -> Option<(usize, usize)> {
        let anchor = self.input_selection_anchor?;
        if anchor == self.input_cursor {
            None
        } else {
            Some((anchor.min(self.input_cursor), anchor.max(self.input_cursor)))
        }
    }

    /// 選択範囲があれば削除し、カーソルを選択開始位置に置いて選択を解除する。
    fn delete_selection(&mut self) {
        if let Some((start, end)) = self.selection_range() {
            let start_byte = char_byte_index(&self.input, start);
            let end_byte = char_byte_index(&self.input, end);
            self.input.replace_range(start_byte..end_byte, "");
            self.input_cursor = start;
            self.input_selection_anchor = None;
        }
    }

    /// 各行の開始文字インデックス一覧（`input`を`\n`区切りの複数行として扱う。`\n`自体は
    /// 直前の行に属し、次の行の開始位置は`\n`の直後の文字インデックス）。空入力でも
    /// 必ず`[0]`を返す。
    fn line_start_indices(&self) -> Vec<usize> {
        let mut starts = vec![0];
        for (i, c) in self.input.chars().enumerate() {
            if c == '\n' {
                starts.push(i + 1);
            }
        }
        starts
    }

    /// `input_cursor`が属する行の`(開始, 終了)`文字インデックス（`\n`は含まない、
    /// `end`は排他的境界）。Home/End・Up/Downの行内位置計算で共有する。
    fn current_line_bounds(&self) -> (usize, usize) {
        let char_count = self.input.chars().count();
        let starts = self.line_start_indices();
        let line_idx = starts.iter().rposition(|&s| s <= self.input_cursor).unwrap_or(0);
        let start = starts[line_idx];
        let end = starts
            .get(line_idx + 1)
            .map(|&next_start| next_start - 1) // 次行の開始の1つ前 = この行の`\n`の位置
            .unwrap_or(char_count);
        (start, end)
    }

    /// 変更前に現在の入力状態をUndo履歴に積む。`coalesce_insert`が真かつ直前も単純挿入
    /// だった場合は、連続タイピングを1つのUndo単位にまとめるため何もしない。
    fn push_undo_snapshot(&mut self, coalesce_insert: bool) {
        if coalesce_insert && self.input_last_edit_was_insert {
            return;
        }
        self.input_undo_stack.push((self.input.clone(), self.input_cursor));
        self.input_redo_stack.clear();
        self.input_last_edit_was_insert = coalesce_insert;
    }

    fn undo(&mut self) {
        if let Some((prev_input, prev_cursor)) = self.input_undo_stack.pop() {
            self.input_redo_stack.push((self.input.clone(), self.input_cursor));
            self.input = prev_input;
            self.input_cursor = prev_cursor;
            self.input_selection_anchor = None;
            self.input_last_edit_was_insert = false;
        }
    }

    fn redo(&mut self) {
        if let Some((next_input, next_cursor)) = self.input_redo_stack.pop() {
            self.input_undo_stack.push((self.input.clone(), self.input_cursor));
            self.input = next_input;
            self.input_cursor = next_cursor;
            self.input_selection_anchor = None;
            self.input_last_edit_was_insert = false;
        }
    }

    /// キー入力を処理し、engineアクター/InteractiveGateへ伝えるべきアクションを返す。
    pub fn on_key(&mut self, key: KeyEvent) -> Option<Action> {
        if let Some(pending) = &self.pending_permission {
            let decision = match key.code {
                KeyCode::Char('y') => Some(Decision::Allow),
                KeyCode::Char('a') => Some(Decision::AllowAndRemember),
                KeyCode::Char('n') | KeyCode::Esc => Some(Decision::Deny),
                KeyCode::Char('d') => Some(Decision::DenyAndRemember),
                _ => None,
            };
            if let Some(decision) = decision {
                let id = pending.id.clone();
                self.pending_permission = None;
                return Some(Action::Respond(id, decision));
            }
            return None;
        }

        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
                Some(Action::Quit)
            }
            // ツールカード/thinkingブロックの折り畳み⇔展開トグル（Claude Code CLIのCtrl+O相当）。
            KeyCode::Char('o') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.toggle_fold();
                None
            }
            // 入力欄の全選択（アンカー=先頭、カーソル=末尾という選択の特殊ケース）。
            KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.input_selection_anchor = Some(0);
                self.input_cursor = self.input.chars().count();
                None
            }
            // Ctrl+Z=Undo、Ctrl+Shift+Z=Redo。端末によってはShift+文字が`Char('Z')`
            // （大文字、SHIFTフラグ無し）として届く実装もあるため、両方の届き方を吸収する。
            KeyCode::Char(c) if (c == 'z' || c == 'Z') && key.modifiers.contains(KeyModifiers::CONTROL) => {
                if c == 'Z' || key.modifiers.contains(KeyModifiers::SHIFT) {
                    self.redo();
                } else {
                    self.undo();
                }
                None
            }
            // 左右矢印キーは入力欄内のカーソル移動、粗いスクロールはPageUp/PageDownに
            // 割り当てる（マウスホイールは`on_mouse`が処理）。
            KeyCode::PageUp => {
                self.scroll_page(1);
                None
            }
            KeyCode::PageDown => {
                self.scroll_page(-1);
                None
            }
            // モーダル非表示時のEscはターン単位のキャンセル（設計書§リッチTUI「Escで
            // CancellationToken発火」）。Ctrl-Cはプロセス終了のまま維持する。
            KeyCode::Esc => Some(Action::Cancel),
            // Shift+Enterは無効化（何もしない）。SHIFT修飾を届けられる端末でのみこのアームが
            // 効き、送信キーはAlt+Enterに一本化する（下記）。
            KeyCode::Enter if key.modifiers.contains(KeyModifiers::SHIFT) => None,
            KeyCode::Enter if !(key.modifiers.contains(KeyModifiers::ALT) || self.enter_submits) =>
            {
                if self.selection_range().is_some() {
                    self.push_undo_snapshot(false);
                    self.delete_selection();
                } else {
                    self.push_undo_snapshot(true);
                    self.input_selection_anchor = None;
                }
                let idx = char_byte_index(&self.input, self.input_cursor);
                self.input.insert(idx, '\n');
                self.input_cursor += 1;
                None
            }
            // ここに来るのはAlt+Enter（送信キー）または`enter_submits`時の素のEnter。VS Code統合
            // ターミナルでも物理Alt+EnterはネイティブにESC+CRとして送られ、crosstermがESC
            // プレフィックスをAlt修飾と解釈するため、keybindingの細工なしに届く（M09で検証）。
            KeyCode::Enter => self.submit_input(),
            KeyCode::Backspace => {
                if self.selection_range().is_some() {
                    self.push_undo_snapshot(false);
                    self.delete_selection();
                } else if self.input_cursor > 0 {
                    self.push_undo_snapshot(false);
                    let idx = char_byte_index(&self.input, self.input_cursor - 1);
                    self.input.remove(idx);
                    self.input_cursor -= 1;
                    // アンカーが選択なし(anchor==cursor)のまま残っている「幽霊」状態を
                    // 掃除する（Shift+矢印で伸縮させた後に押し戻して選択が空になった場合等）。
                    self.input_selection_anchor = None;
                }
                None
            }
            KeyCode::Delete => {
                if self.selection_range().is_some() {
                    self.push_undo_snapshot(false);
                    self.delete_selection();
                } else if self.input_cursor < self.input.chars().count() {
                    self.push_undo_snapshot(false);
                    let idx = char_byte_index(&self.input, self.input_cursor);
                    self.input.remove(idx);
                    self.input_selection_anchor = None;
                }
                None
            }
            // Shift+矢印/Home/Endは選択範囲の伸縮（アンカーは動かさずカーソルだけ動かす）。
            // 左矢印は新規選択開始時のみ特別扱いする: ブロックカーソルが乗っている文字
            // （境界`p`のすぐ右）を、右矢印の初回選択と対称になるよう最初の1文字として含める
            // （アンカーを`p+1`にし、このキー入力ではカーソルを動かさない）。カーソルが
            // 末尾（乗っている文字が無い）場合と、既に選択中（2回目以降）の場合は
            // 従来通りカーソルだけ1つ戻す。
            KeyCode::Left if key.modifiers.contains(KeyModifiers::SHIFT) => {
                if self.input_selection_anchor.is_none()
                    && self.input_cursor < self.input.chars().count()
                {
                    self.input_selection_anchor = Some(self.input_cursor + 1);
                } else {
                    self.input_selection_anchor.get_or_insert(self.input_cursor);
                    self.input_cursor = self.input_cursor.saturating_sub(1);
                }
                None
            }
            KeyCode::Right if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.input_selection_anchor.get_or_insert(self.input_cursor);
                self.input_cursor = (self.input_cursor + 1).min(self.input.chars().count());
                None
            }
            // Home/Endは（複数行入力のため）現在行基準: `\n`を跨がず、行頭/行末までを対象にする。
            KeyCode::Home if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.input_selection_anchor.get_or_insert(self.input_cursor);
                self.input_cursor = self.current_line_bounds().0;
                None
            }
            KeyCode::End if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.input_selection_anchor.get_or_insert(self.input_cursor);
                self.input_cursor = self.current_line_bounds().1;
                None
            }
            // Shift無しの矢印は、選択中なら選択端へカーソルを収縮させ（標準的なテキスト
            // ボックスの挙動）、選択が無ければ1文字だけ移動する。
            KeyCode::Left => {
                if let Some((start, _)) = self.selection_range() {
                    self.input_cursor = start;
                } else {
                    self.input_cursor = self.input_cursor.saturating_sub(1);
                }
                self.input_selection_anchor = None;
                None
            }
            KeyCode::Right => {
                if let Some((_, end)) = self.selection_range() {
                    self.input_cursor = end;
                } else {
                    self.input_cursor = (self.input_cursor + 1).min(self.input.chars().count());
                }
                self.input_selection_anchor = None;
                None
            }
            KeyCode::Home => {
                self.input_selection_anchor = None;
                self.input_cursor = self.current_line_bounds().0;
                None
            }
            KeyCode::End => {
                self.input_selection_anchor = None;
                self.input_cursor = self.current_line_bounds().1;
                None
            }
            // Up/Downは行をまたいだカーソル移動（「列」= 現在行開始からの文字数を維持し、
            // 移動先の行の長さでクランプする）。単純移動なので選択は伴わない
            // （Shift+Up/Downによる複数行選択は今回のスコープ外）。
            KeyCode::Up => {
                let (line_start, _) = self.current_line_bounds();
                let column = self.input_cursor - line_start;
                if line_start > 0 {
                    let starts = self.line_start_indices();
                    let line_idx = starts.iter().rposition(|&s| s == line_start).unwrap_or(0);
                    let prev_start = starts[line_idx - 1];
                    let prev_len = line_start - 1 - prev_start; // `\n`の1つ前まで
                    self.input_cursor = prev_start + column.min(prev_len);
                }
                self.input_selection_anchor = None;
                None
            }
            KeyCode::Down => {
                let (line_start, line_end) = self.current_line_bounds();
                let char_count = self.input.chars().count();
                if line_end < char_count {
                    let column = self.input_cursor - line_start;
                    let next_start = line_end + 1; // `\n`の直後
                    let starts = self.line_start_indices();
                    let line_idx = starts.iter().rposition(|&s| s == next_start).unwrap_or(starts.len() - 1);
                    let next_end = starts.get(line_idx + 1).map(|&s| s - 1).unwrap_or(char_count);
                    let next_len = next_end - next_start;
                    self.input_cursor = next_start + column.min(next_len);
                }
                self.input_selection_anchor = None;
                None
            }
            KeyCode::Char(c) => {
                if self.selection_range().is_some() {
                    self.push_undo_snapshot(false);
                    self.delete_selection();
                } else {
                    self.push_undo_snapshot(true);
                    self.input_selection_anchor = None;
                }
                let idx = char_byte_index(&self.input, self.input_cursor);
                self.input.insert(idx, c);
                self.input_cursor += 1;
                None
            }
            _ => None,
        }
    }
}

/// `input`中の文字インデックス（`char_indices`基準）に対応するバイトオフセットを返す。
/// 末尾を指す場合は`s.len()`（マルチバイト文字境界での`insert`/`remove`パニックを防ぐ）。
fn char_byte_index(s: &str, char_idx: usize) -> usize {
    s.char_indices().nth(char_idx).map(|(i, _)| i).unwrap_or(s.len())
}

fn pretty(v: &serde_json::Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

const MAX_OUTPUT_PREVIEW: usize = 400;

fn truncate_output(output: &ToolOutput) -> String {
    if output.content.chars().count() > MAX_OUTPUT_PREVIEW {
        let head: String = output.content.chars().take(MAX_OUTPUT_PREVIEW).collect();
        format!("{head}... (truncated)")
    } else {
        output.content.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    fn code(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn parses_fork_and_sessions_slash_commands() {
        assert_eq!(parse_slash_command("/fork"), Ok(SlashCommand::Fork));
        assert_eq!(parse_slash_command("/sessions"), Ok(SlashCommand::Sessions));
    }

    #[test]
    fn rejects_unknown_slash_command() {
        assert_eq!(
            parse_slash_command("/nope"),
            Err("unknown command: /nope".to_string())
        );
    }

    /// 左矢印でカーソルを戻してから文字を打つと、末尾ではなくカーソル位置に挿入される
    /// （Backspace/Deleteも同様にカーソル基準で動くことを確認する）。
    #[test]
    fn left_right_arrows_move_cursor_for_mid_string_editing() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        for c in "hello".chars() {
            app.on_key(key(c));
        }
        assert_eq!(app.input, "hello");
        assert_eq!(app.input_cursor, 5);

        // "hello" -> "hel|lo" (2文字戻る)
        app.on_key(code(KeyCode::Left));
        app.on_key(code(KeyCode::Left));
        assert_eq!(app.input_cursor, 3);

        app.on_key(key('X'));
        assert_eq!(app.input, "helXlo");
        assert_eq!(app.input_cursor, 4);

        // 右矢印は文字列末尾でクランプされる。
        for _ in 0..10 {
            app.on_key(code(KeyCode::Right));
        }
        assert_eq!(app.input_cursor, 6);

        // Backspaceはカーソル直前を、Deleteはカーソル位置の文字を削る。
        app.on_key(code(KeyCode::Left));
        app.on_key(code(KeyCode::Backspace));
        assert_eq!(app.input, "helXo");
        assert_eq!(app.input_cursor, 4);

        app.on_key(code(KeyCode::Left));
        app.on_key(code(KeyCode::Left));
        app.on_key(code(KeyCode::Delete));
        assert_eq!(app.input, "heXo");
        assert_eq!(app.input_cursor, 2);
    }

    /// HomeとEndでカーソルが行頭/行末へ一気に移動する。
    #[test]
    fn home_and_end_keys_jump_cursor_to_line_boundaries() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        for c in "hello".chars() {
            app.on_key(key(c));
        }
        app.on_key(code(KeyCode::Home));
        assert_eq!(app.input_cursor, 0);

        app.on_key(key('X'));
        assert_eq!(app.input, "Xhello");
        assert_eq!(app.input_cursor, 1);

        app.on_key(code(KeyCode::End));
        assert_eq!(app.input_cursor, 6);

        app.on_key(key('Y'));
        assert_eq!(app.input, "XhelloY");
        assert_eq!(app.input_cursor, 7);
    }

    /// 素のEnterが改行を挿入するようになった（複数行入力）ため、Home/Endは行全体ではなく
    /// 現在行だけを対象にする。
    #[test]
    fn home_end_operate_on_current_line_in_multiline_input() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        for c in "ab".chars() {
            app.on_key(key(c));
        }
        app.on_key(code(KeyCode::Enter)); // 改行(既定): "ab\n"
        for c in "cde".chars() {
            app.on_key(key(c));
        }
        assert_eq!(app.input, "ab\ncde");
        assert_eq!(app.input_cursor, 6);

        // カーソルは2行目("cde")の末尾。Homeは2行目の先頭(3)へ、1行目の先頭(0)へは行かない。
        app.on_key(code(KeyCode::Home));
        assert_eq!(app.input_cursor, 3);

        app.on_key(code(KeyCode::End));
        assert_eq!(app.input_cursor, 6);

        // 1行目の末尾(改行の直前)にカーソルを移動してからHome/Endすると、1行目の範囲(0..2)に収まる。
        app.on_key(code(KeyCode::Left));
        app.on_key(code(KeyCode::Left));
        app.on_key(code(KeyCode::Left));
        app.on_key(code(KeyCode::Left));
        assert_eq!(app.input_cursor, 2); // "ab|\ncde"

        app.on_key(code(KeyCode::Home));
        assert_eq!(app.input_cursor, 0);
        app.on_key(code(KeyCode::End));
        assert_eq!(app.input_cursor, 2);
    }

    /// Up/Downで行をまたいでカーソルが移動し、列(行頭からの文字数)を可能な限り維持する
    /// （短い行へ移動するときはその行の長さでクランプする）。
    #[test]
    fn up_down_arrows_move_between_lines_preserving_column() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        for c in "abcde".chars() {
            app.on_key(key(c));
        }
        app.on_key(code(KeyCode::Enter)); // "abcde\n"
        for c in "xy".chars() {
            app.on_key(key(c));
        }
        app.on_key(code(KeyCode::Enter)); // "abcde\nxy\n"
        for c in "z".chars() {
            app.on_key(key(c));
        }
        assert_eq!(app.input, "abcde\nxy\nz");

        // カーソルは3行目("z")の末尾(列0からの1文字目)。Upで2行目("xy")の同じ列(1)へ。
        app.on_key(code(KeyCode::Up));
        assert_eq!(app.input_cursor, 6 + 1); // "xy"の開始(6)+列1

        // さらにUpすると1行目("abcde")、列1のまま維持される。
        app.on_key(code(KeyCode::Up));
        assert_eq!(app.input_cursor, 1);

        // 先頭行でのUpは何もしない。
        app.on_key(code(KeyCode::Up));
        assert_eq!(app.input_cursor, 1);

        // Endで1行目の末尾(列5)へ行ってからDownすると、2行目("xy"、長さ2)の列はクランプされ2になる。
        app.on_key(code(KeyCode::End));
        assert_eq!(app.input_cursor, 5);
        app.on_key(code(KeyCode::Down));
        assert_eq!(app.input_cursor, 6 + 2); // "xy"の末尾(列2、クランプ)

        // 3行目("z"、長さ1)へ: 列はクランプされ1(=末尾)になる。
        app.on_key(code(KeyCode::Down));
        assert_eq!(app.input_cursor, app.input.chars().count());

        // 最終行でのDownは何もしない。
        let cursor_at_last_line = app.input_cursor;
        app.on_key(code(KeyCode::Down));
        assert_eq!(app.input_cursor, cursor_at_last_line);
    }

    /// 左矢印は先頭で、Backspace/Deleteは範囲外では何もせずパニックしない
    /// （マルチバイト文字混じりの入力でも文字境界を跨がない）。
    #[test]
    fn cursor_edits_clamp_at_boundaries_and_handle_multibyte_chars() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        app.on_key(code(KeyCode::Left));
        app.on_key(code(KeyCode::Backspace));
        assert_eq!(app.input_cursor, 0);
        app.on_key(code(KeyCode::Delete));
        assert_eq!(app.input, "");

        for c in "例あ".chars() {
            app.on_key(key(c));
        }
        assert_eq!(app.input_cursor, 2);
        app.on_key(code(KeyCode::Left));
        app.on_key(code(KeyCode::Backspace));
        assert_eq!(app.input, "あ");
        assert_eq!(app.input_cursor, 0);
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn shift(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::SHIFT)
    }

    fn alt(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::ALT)
    }

    /// Ctrl+Aで全選択し、Deleteを押すと入力が全消去される。
    #[test]
    fn ctrl_a_selects_all_then_delete_clears_input() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        for c in "hello".chars() {
            app.on_key(key(c));
        }
        app.on_key(ctrl('a'));
        assert_eq!(app.selection_range(), Some((0, 5)));

        app.on_key(code(KeyCode::Delete));
        assert_eq!(app.input, "");
        assert_eq!(app.input_cursor, 0);
        assert_eq!(app.selection_range(), None);
    }

    /// Ctrl+Aで全選択した状態で文字を打つと、選択範囲全体がその1文字に置き換わる。
    #[test]
    fn ctrl_a_selects_all_then_typing_replaces_input() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        for c in "hello".chars() {
            app.on_key(key(c));
        }
        app.on_key(ctrl('a'));
        app.on_key(key('X'));
        assert_eq!(app.input, "X");
        assert_eq!(app.input_cursor, 1);
        assert_eq!(app.selection_range(), None);
    }

    /// Shift+矢印で選択範囲が伸縮し、選択中のBackspace/Delete/文字入力が範囲全体に効く。
    #[test]
    fn shift_arrows_extend_and_shrink_selection() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        for c in "hello".chars() {
            app.on_key(key(c));
        }
        // カーソルは末尾(5)。Shift+Leftを3回で"lo"を選択(範囲2..5)。
        app.on_key(shift(KeyCode::Left));
        app.on_key(shift(KeyCode::Left));
        app.on_key(shift(KeyCode::Left));
        assert_eq!(app.selection_range(), Some((2, 5)));

        // Shift+Rightで1文字縮む(範囲3..5)。
        app.on_key(shift(KeyCode::Right));
        assert_eq!(app.selection_range(), Some((3, 5)));

        // 選択中に文字入力すると範囲("lo")がその1文字に置き換わる。
        app.on_key(key('Z'));
        assert_eq!(app.input, "helZ");
        assert_eq!(app.input_cursor, 4);
        assert_eq!(app.selection_range(), None);

        // 選択→Backspace/Deleteでも範囲削除になることを確認。
        app.on_key(shift(KeyCode::Left));
        app.on_key(shift(KeyCode::Left));
        assert_eq!(app.selection_range(), Some((2, 4)));
        app.on_key(code(KeyCode::Backspace));
        assert_eq!(app.input, "he");
        assert_eq!(app.input_cursor, 2);
    }

    /// 選択中にShift無しの矢印を押すと、1文字動くのではなく選択範囲の端へ収縮する。
    #[test]
    fn unshifted_arrow_after_selection_collapses_to_edge_without_deleting() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        for c in "hello".chars() {
            app.on_key(key(c));
        }
        app.on_key(shift(KeyCode::Left));
        app.on_key(shift(KeyCode::Left));
        assert_eq!(app.selection_range(), Some((3, 5)));

        app.on_key(code(KeyCode::Left));
        assert_eq!(app.input, "hello");
        assert_eq!(app.input_cursor, 3);
        assert_eq!(app.selection_range(), None);

        app.on_key(shift(KeyCode::Right));
        app.on_key(shift(KeyCode::Right));
        assert_eq!(app.selection_range(), Some((3, 5)));

        app.on_key(code(KeyCode::Right));
        assert_eq!(app.input, "hello");
        assert_eq!(app.input_cursor, 5);
        assert_eq!(app.selection_range(), None);
    }

    /// Shift+Home/Endで行頭/行末までの選択範囲を作れる。
    #[test]
    fn shift_home_end_select_to_line_boundaries() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        for c in "hello".chars() {
            app.on_key(key(c));
        }
        app.on_key(code(KeyCode::Left));
        app.on_key(code(KeyCode::Left));
        assert_eq!(app.input_cursor, 3);

        app.on_key(shift(KeyCode::Home));
        assert_eq!(app.selection_range(), Some((0, 3)));

        app.on_key(code(KeyCode::Right));
        assert_eq!(app.input_cursor, 3);
        assert_eq!(app.selection_range(), None);

        app.on_key(shift(KeyCode::End));
        assert_eq!(app.selection_range(), Some((3, 5)));
    }

    fn ctrl_shift(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL | KeyModifiers::SHIFT)
    }

    /// ユーザー報告の再現: 「ああああ消したいところあああ」でカーソルを`ろ`（インデックス10）
    /// に置きShift+Leftを7回押すと、選択範囲が「消したいところ」7文字ちょうどになり
    /// （`ろ`自身もブロックカーソルの初回選択で含まれる）、Deleteで過不足なく消える。
    #[test]
    fn shift_left_selection_start_includes_char_under_cursor() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        for c in "ああああ消したいところあああ".chars() {
            app.on_key(key(c));
        }
        // カーソルを`ろ`(インデックス10)の上へ: 末尾(14)から4つ左へ。
        for _ in 0..4 {
            app.on_key(code(KeyCode::Left));
        }
        assert_eq!(app.input_cursor, 10);

        for _ in 0..7 {
            app.on_key(shift(KeyCode::Left));
        }
        assert_eq!(app.selection_range(), Some((4, 11)));

        app.on_key(code(KeyCode::Delete));
        assert_eq!(app.input, "あああああああ");
    }

    /// 回帰確認: カーソルが`消`の上にある状態からのShift+右矢印は、従来通り初回で
    /// `消`自身を選択に含める（左矢印の修正が右矢印の挙動を変えていないことの確認）。
    #[test]
    fn shift_right_selection_start_still_includes_char_under_cursor() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        for c in "ああああ消したいところあああ".chars() {
            app.on_key(key(c));
        }
        for _ in 0..10 {
            app.on_key(code(KeyCode::Left));
        }
        assert_eq!(app.input_cursor, 4);

        for _ in 0..7 {
            app.on_key(shift(KeyCode::Right));
        }
        assert_eq!(app.selection_range(), Some((4, 11)));

        app.on_key(code(KeyCode::Delete));
        assert_eq!(app.input, "あああああああ");
    }

    /// 「幽霊アンカー」バグの再現+修正確認: Shift+Rightで選択を広げた後、反対方向へ
    /// Shift+Leftを押し戻してアンカー==カーソルに一致させる（選択が見た目上消える）。
    /// この状態でBackspace/文字入力/Shift無し矢印を経由しても、内部の`anchor`が
    /// クリアされていないと後続のShift+矢印が古いアンカーを再利用してしまい、
    /// ユーザーの現在のカーソル位置からの新規選択にならない（今回の修正対象）。
    #[test]
    fn shift_selection_anchor_resets_after_returning_to_start() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        for c in "hello".chars() {
            app.on_key(key(c));
        }
        app.on_key(code(KeyCode::Home));
        assert_eq!(app.input_cursor, 0);

        // "h"を選択してから押し戻し、アンカー==カーソルに一致させる（見た目上は選択なし）。
        app.on_key(shift(KeyCode::Right));
        app.on_key(shift(KeyCode::Left));
        assert_eq!(app.selection_range(), None);
        assert_eq!(app.input_cursor, 0);

        // 選択なしのUnshifted移動を経由して幽霊アンカーが残っていないことを確認。
        app.on_key(code(KeyCode::Right));
        assert_eq!(app.input_cursor, 1);
        assert_eq!(app.selection_range(), None);

        // 直後のShift+Rightは、古いアンカー(0)ではなく「今のカーソル位置(1)」から
        // 新規に選択を開始しなければならない。
        app.on_key(shift(KeyCode::Right));
        assert_eq!(app.selection_range(), Some((1, 2)));
    }

    /// 同様に、Backspace/文字入力を経由した場合も幽霊アンカーが残らないことを確認する。
    #[test]
    fn ghost_anchor_does_not_survive_backspace_or_typing() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        for c in "hello".chars() {
            app.on_key(key(c));
        }
        app.on_key(code(KeyCode::Home));
        app.on_key(shift(KeyCode::Right));
        app.on_key(shift(KeyCode::Left));
        assert_eq!(app.selection_range(), None);

        // Backspaceは先頭なので何もしないが、幽霊アンカーは残らない。
        app.on_key(code(KeyCode::Backspace));
        app.on_key(key('X'));
        assert_eq!(app.input, "Xhello");
        assert_eq!(app.input_cursor, 1);
        assert_eq!(app.selection_range(), None);

        app.on_key(shift(KeyCode::Right));
        assert_eq!(app.selection_range(), Some((1, 2)));
    }

    /// Ctrl+Zで直前の編集を取り消し、Ctrl+Shift+Zでやり直せる。
    #[test]
    fn ctrl_z_undoes_last_insert_and_ctrl_shift_z_redoes() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        for c in "hi".chars() {
            app.on_key(key(c));
        }
        app.on_key(code(KeyCode::Backspace));
        assert_eq!(app.input, "h");

        app.on_key(ctrl('z'));
        assert_eq!(app.input, "hi");
        assert_eq!(app.input_cursor, 2);

        app.on_key(ctrl_shift('z'));
        assert_eq!(app.input, "h");
    }

    /// 連続する単純タイピングは1つのUndo単位にまとまる（1文字ずつ戻らない）。
    #[test]
    fn ctrl_z_coalesces_consecutive_plain_typing_into_one_undo_step() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        for c in "hello".chars() {
            app.on_key(key(c));
        }
        app.on_key(ctrl('z'));
        assert_eq!(app.input, "");
        assert_eq!(app.input_cursor, 0);

        // Undoできる履歴が無い状態でのCtrl+Zは何もしない。
        app.on_key(ctrl('z'));
        assert_eq!(app.input, "");
    }

    /// 選択範囲のBackspace削除・文字置換もそれぞれ1つのUndo単位として取り消せる。
    #[test]
    fn ctrl_z_undoes_selection_delete_and_replace() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        for c in "hello".chars() {
            app.on_key(key(c));
        }
        app.on_key(ctrl('a'));
        app.on_key(code(KeyCode::Delete));
        assert_eq!(app.input, "");

        app.on_key(ctrl('z'));
        assert_eq!(app.input, "hello");

        app.on_key(ctrl('a'));
        app.on_key(key('X'));
        assert_eq!(app.input, "X");

        app.on_key(ctrl('z'));
        assert_eq!(app.input, "hello");
    }

    /// 同一ターン内の`TextDelta`は直前の`Assistant`項目へ連結され、`TurnStarted`を挟むと
    /// 新しい項目として積まれる（§リッチTUI「ストリーミング描画」）。
    #[test]
    fn text_deltas_within_a_turn_accumulate_into_one_item() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        app.apply(AgentEvent::TurnStarted { estimated_input_tokens: 0 });
        app.apply(AgentEvent::TextDelta { text: "hel".into() });
        app.apply(AgentEvent::TextDelta { text: "lo".into() });

        assert_eq!(app.transcript.len(), 1);
        match &app.transcript[0] {
            TranscriptItem::Assistant(s) => assert_eq!(s, "hello"),
            other => panic!("expected Assistant item, got {other:?}"),
        }

        app.apply(AgentEvent::TurnCompleted {
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        });
        app.apply(AgentEvent::TurnStarted { estimated_input_tokens: 0 });
        app.apply(AgentEvent::TextDelta {
            text: "next turn".into(),
        });
        assert_eq!(app.transcript.len(), 2);
    }

    /// `ToolCallProposed`でカードが積まれ、`ToolFinished`で同じ`id`のカードのstatusが
    /// 更新される（§リッチTUI「ツールカード」）。
    #[test]
    fn tool_card_transitions_from_running_to_done() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        app.apply(AgentEvent::ToolCallProposed {
            id: "call_1".into(),
            name: "read_file".into(),
            input: serde_json::json!({"path": "a.txt"}),
        });
        match &app.transcript[0] {
            TranscriptItem::ToolCard { status, .. } => {
                assert!(matches!(status, ToolCardStatus::Running))
            }
            other => panic!("expected ToolCard, got {other:?}"),
        }

        app.apply(AgentEvent::ToolFinished {
            id: "call_1".into(),
            output: ToolOutput {
                content: "hello".into(),
                is_error: false,
            },
        });
        match &app.transcript[0] {
            TranscriptItem::ToolCard { status, .. } => match status {
                ToolCardStatus::Done { is_error, output } => {
                    assert!(!is_error);
                    assert_eq!(output, "hello");
                }
                ToolCardStatus::Running => panic!("expected Done"),
            },
            other => panic!("expected ToolCard, got {other:?}"),
        }
    }

    /// `PermissionRequired`はモーダル状態を立て、モーダル表示中は`y/n/a/d`のみを消費して
    /// `Action::Respond`を返す（§リッチTUI「承認ダイアログ」の`[y]/[n]/[a]/[d]`）。
    #[test]
    fn permission_modal_consumes_only_decision_keys() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        app.apply(AgentEvent::PermissionRequired {
            id: "perm-0".into(),
            tool: "run_shell".into(),
            risk: RiskClass::Exec,
            input: serde_json::json!({"command": "echo hi"}),
        });
        assert!(app.pending_permission.is_some());

        // モーダル表示中は通常の文字入力ボックスへは書き込まれない。
        assert!(app.on_key(key('x')).is_none());
        assert!(app.input.is_empty());

        let action = app.on_key(key('a')).expect("expected an action");
        match action {
            Action::Respond(id, decision) => {
                assert_eq!(id, "perm-0");
                assert_eq!(decision, Decision::AllowAndRemember);
            }
            _ => panic!("expected Respond action"),
        }
        assert!(app.pending_permission.is_none());
    }

    /// Shift+Enterは無効化されており、送信も改行もせず何も起きない（入力はそのまま）。
    /// 物理Shift+EnterはVS Code統合ターミナルではShift修飾が失われ素のEnterと区別できないため、
    /// SHIFT修飾を届けられる端末での誤送信を防ぐ目的で明示的にno-opにしている。
    #[test]
    fn shift_enter_is_disabled_and_does_nothing() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        for c in "hi".chars() {
            assert!(app.on_key(key(c)).is_none());
        }
        assert!(app.on_key(shift(KeyCode::Enter)).is_none());
        // 送信されず、改行も挿入されず、入力は保持される。
        assert_eq!(app.input, "hi");
        assert!(app.transcript.is_empty());
    }

    /// 既定（`enter_submits == false`）では、素のEnterは送信せず入力欄へ改行を挿入し、送信は
    /// Alt+Enterで行う（複数行プロンプトの組み立て）。
    #[test]
    fn enter_inserts_newline_by_default_and_alt_enter_submits() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        assert!(!app.enter_submits);
        for c in "hi".chars() {
            app.on_key(key(c));
        }
        assert!(app.on_key(code(KeyCode::Enter)).is_none());
        assert_eq!(app.input, "hi\n");
        assert_eq!(app.input_cursor, 3);

        for c in "there".chars() {
            app.on_key(key(c));
        }
        assert_eq!(app.input, "hi\nthere");

        let action = app.on_key(alt(KeyCode::Enter));
        match action {
            Some(Action::Submit(text)) => assert_eq!(text, "hi\nthere"),
            other => panic!("expected Submit action, got {other:?}"),
        }
        assert!(app.input.is_empty());
    }

    /// Alt+Enterは送信キー。VS Code統合ターミナルでも物理Alt+EnterはネイティブにESC+CRとして
    /// 送られ、crosstermがESCプレフィックスをAlt修飾と解釈するため、keybindingの細工なしに
    /// Alt+Enterとして届く（`on_key`のEnter分岐のコメント参照）。
    #[test]
    fn alt_enter_submits_input() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        for c in "hi".chars() {
            app.on_key(key(c));
        }
        let action = app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT));
        match action {
            Some(Action::Submit(text)) => assert_eq!(text, "hi"),
            other => panic!("expected Submit action, got {other:?}"),
        }
        assert!(app.input.is_empty());
    }

    /// `enter_submits`フラグが立っている（後方互換モード）と、素のEnterも送信する。
    #[test]
    fn enter_submits_when_flag_enabled() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        app.enter_submits = true;
        for c in "hi".chars() {
            app.on_key(key(c));
        }
        let action = app.on_key(code(KeyCode::Enter));
        match action {
            Some(Action::Submit(text)) => assert_eq!(text, "hi"),
            other => panic!("expected Submit action, got {other:?}"),
        }
        assert!(app.input.is_empty());
    }

    #[test]
    fn scroll_lines_clamps_at_zero_and_saturates_upward() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        assert_eq!(app.scroll_offset, 0);
        app.scroll_lines(-5);
        assert_eq!(app.scroll_offset, 0, "should not go below 0");
        app.scroll_lines(3);
        assert_eq!(app.scroll_offset, 3);
        app.scroll_lines(-1);
        assert_eq!(app.scroll_offset, 2);
    }

    #[test]
    fn page_up_and_page_down_keys_scroll_by_a_page_without_emitting_an_action() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        let action = app.on_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
        assert!(action.is_none());
        assert!(app.scroll_offset > 0);

        let after_up = app.scroll_offset;
        let action = app.on_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        assert!(action.is_none());
        assert!(app.scroll_offset < after_up);
    }

    #[test]
    fn ctrl_o_toggles_fold_and_defaults_to_collapsed() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        assert!(app.collapsed, "default should be collapsed");

        let action = app.on_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL));
        assert!(action.is_none());
        assert!(!app.collapsed);

        app.on_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL));
        assert!(app.collapsed);
    }

    #[test]
    fn mouse_wheel_scrolls_up_and_down() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        app.on_mouse(MouseEventKind::ScrollUp);
        assert_eq!(app.scroll_offset, 3);
        app.on_mouse(MouseEventKind::ScrollDown);
        assert_eq!(app.scroll_offset, 0);
        app.on_mouse(MouseEventKind::ScrollDown);
        assert_eq!(app.scroll_offset, 0, "should not go below 0");
    }

    /// スクロール操作は承認モーダル表示中でも通る（過去ログ閲覧を妨げないため、
    /// `on_key`のモーダルガードとは独立に処理される）。
    #[test]
    fn mouse_scroll_works_even_while_permission_modal_is_pending() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        app.apply(AgentEvent::PermissionRequired {
            id: "perm-0".into(),
            tool: "run_shell".into(),
            risk: RiskClass::Exec,
            input: serde_json::json!({"command": "echo hi"}),
        });
        assert!(app.pending_permission.is_some());

        app.on_mouse(MouseEventKind::ScrollUp);
        assert_eq!(app.scroll_offset, 3);
    }

    /// `TurnStarted`でUpstream概算・ライブ状態がセットされ、`TextDelta`/`ThinkingDelta`で
    /// Downstreamの文字数概算が積み上がり、`TurnCompleted`でセッション累計へ確定値が
    /// 合算されて`turn_in_flight`が`false`に戻ることを確認する（リアルタイムトークン表示）。
    #[test]
    fn tracks_live_token_estimates_and_accumulates_session_usage() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        app.apply(AgentEvent::TurnStarted { estimated_input_tokens: 42 });
        assert!(app.turn_in_flight);
        assert_eq!(app.current_turn_upstream_estimate, 42);
        assert_eq!(app.current_turn_downstream_chars, 0);

        app.apply(AgentEvent::ThinkingDelta { text: "abcd".into() });
        assert_eq!(app.current_turn_downstream_chars, 4);
        app.apply(AgentEvent::TextDelta { text: "hello".into() });
        assert_eq!(app.current_turn_downstream_chars, 9);

        app.apply(AgentEvent::TurnCompleted {
            stop_reason: StopReason::EndTurn,
            usage: Usage { input: 10, output: 5, cache_read: 1, cache_creation: 2 },
        });
        assert!(!app.turn_in_flight);
        assert_eq!(app.session_usage, Usage { input: 10, output: 5, cache_read: 1, cache_creation: 2 });

        // 2ターン目は既存の累計へ加算される。
        app.apply(AgentEvent::TurnStarted { estimated_input_tokens: 7 });
        app.apply(AgentEvent::TurnCompleted {
            stop_reason: StopReason::EndTurn,
            usage: Usage { input: 3, output: 2, cache_read: 0, cache_creation: 0 },
        });
        assert_eq!(app.session_usage, Usage { input: 13, output: 7, cache_read: 1, cache_creation: 2 });
    }

    /// thinkingを使ったターンでは、本文が届いた時点で「考え中」インジケータが消え、
    /// `(thought for ...)`という記録行がtranscriptへ1つだけ残ることを確認する。
    #[test]
    fn thinking_progress_leaves_a_record_when_thinking_was_used() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        app.apply(AgentEvent::TurnStarted { estimated_input_tokens: 0 });
        assert!(app.thinking_progress.is_some());

        app.apply(AgentEvent::ThinkingDelta { text: "hmm".into() });
        assert!(app.thinking_progress.is_some(), "still thinking, indicator stays");

        app.apply(AgentEvent::TextDelta { text: "answer".into() });
        assert!(app.thinking_progress.is_none(), "indicator clears once real content starts");

        let thought_notes = app
            .transcript
            .iter()
            .filter(|item| matches!(item, TranscriptItem::Info(s) if s.starts_with("(thought for")))
            .count();
        assert_eq!(thought_notes, 1);
    }

    /// thinkingを使わなかったターンでは、本文到達時にインジケータが黙って消えるだけで
    /// `(thought for ...)`の記録行は残らない（ノイズを避けるため）。
    #[test]
    fn no_thought_record_when_thinking_was_not_used() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        app.apply(AgentEvent::TurnStarted { estimated_input_tokens: 0 });
        app.apply(AgentEvent::TextDelta { text: "immediate answer".into() });
        assert!(app.thinking_progress.is_none());

        let thought_notes = app
            .transcript
            .iter()
            .filter(|item| matches!(item, TranscriptItem::Info(s) if s.starts_with("(thought for")))
            .count();
        assert_eq!(thought_notes, 0);
    }

    /// ツール呼び出しだけで本文が無いまま終わるターンでも、安全網として
    /// `thinking_progress`が確実に片付くことを確認する。
    #[test]
    fn tool_call_without_text_still_clears_thinking_progress() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        app.apply(AgentEvent::TurnStarted { estimated_input_tokens: 0 });
        app.apply(AgentEvent::ToolCallProposed {
            id: "call_1".into(),
            name: "read_file".into(),
            input: serde_json::json!({}),
        });
        assert!(app.thinking_progress.is_none());
    }

    /// LMStudio等のローカルモデルが応答冒頭に送ってくる意味の無い改行だけのデルタ
    /// （例:`"\n\n"`）は、まだ非空白の内容が届いていないので蓄積されず、「考え中」
    /// インジケータも消えずに残ることを確認する（消えた場所に空行だけが残る問題の回帰防止）。
    #[test]
    fn leading_whitespace_only_deltas_are_dropped_and_indicator_stays() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        app.apply(AgentEvent::TurnStarted { estimated_input_tokens: 0 });

        app.apply(AgentEvent::TextDelta { text: "\n\n".into() });
        assert!(app.thinking_progress.is_some(), "still waiting for real content");
        assert!(app.transcript.is_empty(), "whitespace-only delta must not create an item");

        app.apply(AgentEvent::TextDelta { text: "Hello".into() });
        assert!(app.thinking_progress.is_none(), "indicator clears once real content arrives");
        assert_eq!(app.transcript.len(), 1);
        assert!(matches!(&app.transcript[0], TranscriptItem::Assistant(s) if s == "Hello"));
    }

    /// 非空白の内容が複数のデルタに分かれて届く通常ケースは引き続き1つのAssistant項目へ
    /// 連結されることを確認する（回帰防止）。
    #[test]
    fn subsequent_text_deltas_still_append_to_the_same_assistant_item() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        app.apply(AgentEvent::TurnStarted { estimated_input_tokens: 0 });
        app.apply(AgentEvent::TextDelta { text: "Hel".into() });
        app.apply(AgentEvent::TextDelta { text: "lo".into() });

        assert_eq!(app.transcript.len(), 1);
        assert!(matches!(&app.transcript[0], TranscriptItem::Assistant(s) if s == "Hello"));
    }
}
