//! `AppState`: `AgentEvent`を畳み込んで保持するTUI側の状態。`plans/DESIGN.md` §リッチTUI参照。

use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEventKind};

use harness_core::{AgentEvent, RiskClass, StopReason, ToolOutput, Usage};
use harness_engine::{parse_allowlist_rule, AllowlistRule, Decision, PermissionMode};

use harness_sandbox::textdiff::{diff_lines, DiffLine};

use events::{pretty, MAX_OUTPUT_PREVIEW};

/// transcript末尾に表示する一時的な「考え中」インジケータのスピナーグリフ。
/// `AppState::spinner_frame`でインデックスし、`lib.rs`の描画tick（33ms間隔）ごとに送る。
pub const SPINNER_FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

#[derive(Debug, Clone)]
pub enum ToolCardStatus {
    Running {
        /// [BUG-082フォローアップ] ツールが実際の処理へ入る前、何らかの背景条件
        /// （D-54のworkspace ACL伝播ジョブ等）で待たされている理由。
        /// `AgentEvent::ToolProgress`で更新され、条件が無くなると`None`へ戻る
        /// （`harness_core::tool::WaitReason`のdoc参照）。`None`は「普通に実行中」。
        wait_reason: Option<String>,
    },
    Done {
        is_error: bool,
        output: String,
    },
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
    /// 差分エンジンはレビューパネルと共有の`harness_sandbox::textdiff`。
    pub diff: Option<Vec<DiffLine>>,
}

/// `/model /mode /allow /compact /clear /fork /sessions /fsstage`（M9、DESIGN.md L349
/// 「スラッシュコマンド」+ セッションFork/一覧の拡張。`/fsstage`はM10の変更（changes）パネルを
/// キーバインドではなくスラッシュコマンドから操作するためのもの。Ctrl+GはVSCode統合ターミナルの
/// 既定ショートカットと衝突するため、`/fsstage`へ置き換えて廃止した）。
mod commands;
mod events;
mod input;
mod review;

use commands::parse_slash_command;
pub use commands::{Action, FsStageCommand, MemoryCommand, SlashCommand};
pub use review::{
    commit_selection, CommitSelection, PartialFile, ReviewCommand, ReviewDiffLine, ReviewFocus,
    ReviewPanelState, ReviewRow, ReviewTarget,
};

#[cfg(test)]
#[path = "app_state_tests.rs"]
mod tests;

/// ターン以外のバックグラウンド処理（`/compact`の要約）の進捗
/// （[BUG-070](../../../docs/bugs/BUG-070.md)・[BUG-071](../../../docs/bugs/BUG-071.md)）。
///
/// **キュー待ちと実行中を別の状態として持つ**のが要点。engineは単一タスクでターンとコマンドを
/// 直列に処理するため、ターン実行中に送った`/compact`はキューで待つ。送信時点から「実行中」と
/// 見せると、ターンと要約が同時に走っているように見えてしまう。
#[derive(Debug, Clone)]
pub struct BusyProgress {
    /// コマンドをengineへ送った時刻（＝キューに入った時刻）。
    pub queued_at: Instant,
    /// engineが実際に処理を始めた時刻（`AgentEvent::ContextCompactionStarted`受信時）。
    /// キューで待っている間は`None`。
    pub started_at: Option<Instant>,
    pub label: String,
}

/// [`AppState::end_busy`]の終わり方。記録行の動詞を決めるためだけの区別だが、
/// **止めたものを「完了した」と書かない**という点でこれは事実の区別である
/// （[BUG-074](../../../docs/bugs/BUG-074.md)）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusyEnd {
    /// 最後まで走った（成功・失敗のどちらでも、走り切ったならこちら）。
    Finished,
    /// ユーザーが止めた。
    Stopped,
}

impl BusyProgress {
    /// 画面に出す経過時間。実行中なら開始から、待機中はキューに入ってからの時間。
    pub fn elapsed(&self) -> std::time::Duration {
        self.started_at.unwrap_or(self.queued_at).elapsed()
    }

    pub fn is_running(&self) -> bool {
        self.started_at.is_some()
    }
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
    /// transcriptの末尾追従スクロール位置。
    /// **実体は`harness_term::scrollback`**で、ポリシーエディタの記録画面と共有する
    /// （同じ罠を二つ持つと、片方だけが折り返しを数え損ねる――実際にそうなった）。
    pub scroll: harness_term::scrollback::Scrollback,
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
    /// いま何かがツール実行を待たせているなら、その状態（表示専用）。
    ///
    /// 現状の唯一の源はD-54/[BUG-082](../../../../docs/bugs/BUG-082.md) Part Bの
    /// workspace背景ジョブ（rootへの伝播＋保護DACL配下の救済walk）で、**ワークスペースを
    /// 初めてTier2aで開いた起動でしか出ない**。この間、対応する範囲はまだサンドボックスから
    /// 見えず、`run_shell`は完了を待つ（`grant_job`のdoc）。「TUIは出ているのにコマンドが
    /// 待たされる」理由をユーザーへ見せるための表示で、判定には一切関与しない。
    ///
    /// **TUIはどの背景ジョブが待たせているかを知らない**（`refactor-perspectives` R-01）。
    /// `lib.rs`の描画tickが`harness_tools::wait_reasons`のレジストリから取り込むだけで、
    /// 源が増えてもこのフィールドの型も描画も変わらない。
    pub wait_state: Option<harness_core::tool::WaitState>,
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
    /// `TERM_PROGRAM=vscode`のとき`true`（`harness_term::host_is_vscode`）。キー処理の分岐には
    /// 使わない（Shift+Enterが送信になるかどうかはSHIFT修飾が実際に届くか否かで自然に決まる）。
    /// 入力欄のヒント文字列（Alt+Enter/Shift+Enterどちらを案内するか）の表示専用。
    pub host_is_vscode: bool,
    /// レビューパネル（M10の変更パネルを一般化したもの、`app::review`）。`Some`の間は
    /// 他の全キー入力をパネル操作専用に奪う（`pending_permission`と同じ排他パターン）。
    pub review_panel: Option<ReviewPanelState>,
    /// ターン以外のバックグラウンド処理（`/compact`の要約）の進捗表示（BUG-070・BUG-071）。
    /// `thinking_progress`と同じくtranscript末尾への一時表示で、`transcript`本体には積まない。
    pub busy_progress: Option<BusyProgress>,
    /// いま開いているワークスペースの表示名（末尾のディレクトリ名）。`/workspace`で移動できる
    /// ようになったため、どこにいるかが画面から分かる必要がある。
    pub workspace_label: String,
    /// **いま見ている／書いているオーバーレイ**の持ち主のセッションID（`--live`では`None`）。
    ///
    /// [`Self::conversation_session_id`]と食い違うことがある——`/clear`は会話だけを捨てて
    /// オーバーレイを引き継ぐ設計なので、その後は「会話はセッションB、変更はセッションAの
    /// オーバーレイ」になる。**この食い違いは正当だが、黙っていてはいけない**（BUG-072と
    /// 同型の誤解を生む）。`ui::render_status`が両方を並べて出す。
    pub overlay_session_id: Option<String>,
    /// いま追記している会話のセッションID。
    pub conversation_session_id: String,
}

// スクロール量（`PageUp`/`PageDown`とホイール1ノッチの行数）は
// `harness_term::scrollback`が持つ。ここに複製を置くと、片方だけ変えたときに
// 会話TUIとポリシーエディタで送り量が食い違う（B-05）。

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
            scroll: Default::default(),
            collapsed: true,
            turn_in_flight: false,
            current_turn_upstream_estimate: 0,
            current_turn_downstream_chars: 0,
            session_usage: Usage::default(),
            thinking_progress: None,
            saw_thinking_this_turn: false,
            spinner_frame: 0,
            wait_state: None,
            enter_submits: false,
            key_debug: false,
            host_is_vscode: false,
            review_panel: None,
            busy_progress: None,
            workspace_label: String::new(),
            overlay_session_id: None,
            conversation_session_id: String::new(),
        }
    }

    /// いま見ているオーバーレイと、いま追記している会話を記録する（表示用）。
    ///
    /// `overlay`が空文字なら`--live`（オーバーレイ無し）とみなす。呼ぶのは`crate::run`だけで、
    /// スコープが確定した／差し替わった各点から1回ずつ。
    pub fn note_scope(&mut self, overlay: &str, conversation: &str) {
        self.overlay_session_id = (!overlay.is_empty()).then(|| overlay.to_string());
        self.conversation_session_id = conversation.to_string();
    }

    /// 変更（CoW/Staged）のレビューパネルを開く（既定で全件accept、reject印は空）。
    /// 見出しに載るオーバーレイのセッションIDは、引数ではなく[`Self::overlay_session_id`]から
    /// 取る。呼び出し側に渡させると「行はセッションBのもの、見出しはセッションA」という
    /// ずれが型で防げない（`bug-pattern-rules` B-13: 同じ事実の正本を2つ持たない）。
    pub fn open_changes_panel(&mut self, rows: Vec<ReviewRow>) {
        self.review_panel = Some(ReviewPanelState::changes(
            rows,
            self.overlay_session_id.as_deref(),
        ));
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

    /// ターン以外のバックグラウンド処理（`/compact`の要約など）を**キューへ入れた**ことを
    /// 記録し、進捗表示を始める（[BUG-070](../../../docs/bugs/BUG-070.md)・
    /// [BUG-071](../../../docs/bugs/BUG-071.md)）。
    ///
    /// `thinking_progress`と同じくtranscript末尾へ一時表示するだけで、`transcript`本体は
    /// 汚さない。**既に進行中なら`false`を返す**ので、呼び出し側はそれを見て二重起動を防ぐ
    /// （キュー待ちの間も`true`を返さない——engineのコマンドチャネルは無制限なので、
    /// ここで止めないと待っている分だけ積み上がる）。
    ///
    /// この時点ではまだ**走っていない**。実際に始まったら[`AppState::mark_busy_running`]。
    pub fn begin_busy(&mut self, label: &str) -> bool {
        if self.busy_progress.is_some() {
            return false;
        }
        self.busy_progress = Some(BusyProgress {
            queued_at: Instant::now(),
            started_at: None,
            label: label.to_string(),
        });
        true
    }

    /// キューを抜けてengineが実際に処理を始めた（BUG-071）。表示を「待機中」から「実行中」へ移す。
    /// 既に実行中なら何もしない（同じ開始通知を2回受けても時計を巻き戻さない）。
    pub fn mark_busy_running(&mut self) {
        if let Some(busy) = self.busy_progress.as_mut() {
            if busy.started_at.is_none() {
                busy.started_at = Some(Instant::now());
            }
        }
    }

    /// **engineが自分の判断で始めた**長い処理の進捗表示（BUG-078: 予防的縮約の要約コール）。
    ///
    /// [`AppState::mark_busy_running`]だけでは足りない——`/compact`コマンド経由と違って
    /// [`AppState::begin_busy`]を呼んだ者が居らず、置き場が空なので何も表示されない。
    /// 待機（キュー）を経ていないので**最初から実行中**として作る。
    pub fn begin_busy_running(&mut self, label: &str) {
        if self.busy_progress.is_none() {
            let now = Instant::now();
            self.busy_progress = Some(BusyProgress {
                queued_at: now,
                started_at: Some(now),
                label: label.to_string(),
            });
            return;
        }
        self.mark_busy_running();
    }

    /// **実行中の**進捗表示だけを畳む。キューで待っているものは畳まない——待っている間に届く
    /// `Error`/`Cancelled`/`ContextCompacted`は**先行するターンのもの**であり、畳むと要約が
    /// 始まる前に表示が消える（BUG-071/074）。
    fn end_busy_if_running(&mut self, how: BusyEnd) {
        if self.busy_progress.as_ref().is_some_and(|b| b.is_running()) {
            self.end_busy(how);
        }
    }

    /// 進行中の表示を終了し、所要時間を記録行として1行残す。
    /// キューで待った時間が実測できる場合は**それも併記する**——ターンの後ろで待っていたことが
    /// 後から分からないと、「要約に何十秒もかかった」という誤解が残る。
    ///
    /// 呼ぶのは**結果行を積む前**。`thinking_progress`が`(thought for Ns)`を応答本文の前へ
    /// 出すのと同じで、スピナーがあった位置がそのまま記録行になり、結果はその下に続く。
    pub fn end_busy(&mut self, how: BusyEnd) {
        let Some(busy) = self.busy_progress.take() else {
            return;
        };
        let line = match busy.started_at {
            Some(started) => {
                let queued = started.duration_since(busy.queued_at).as_secs_f32();
                let ran = started.elapsed().as_secs_f32();
                // BUG-074: ユーザーが止めたものを「完了した」と言わない。
                let verb = match how {
                    BusyEnd::Finished => "finished in",
                    BusyEnd::Stopped => "stopped after",
                };
                if queued >= 0.1 {
                    format!(
                        "{} {verb} {ran:.1}s ({queued:.1}s queued behind the current turn)",
                        busy.label
                    )
                } else {
                    format!("{} {verb} {ran:.1}s", busy.label)
                }
            }
            // 開始通知を受けないまま終わった（engineタスクが落ちた等）。走っていないので
            // 「所要時間」を出すと嘘になる。
            None => format!("{} ended before it started", busy.label),
        };
        self.transcript.push(TranscriptItem::Info(line));
    }

    pub fn is_busy(&self) -> bool {
        self.busy_progress.is_some()
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

    /// 直近の描画で判明した上限まで`scroll_offset`を切り詰める
    /// （[BUG-076](../../../docs/bugs/BUG-076.md)）。
    ///
    /// 総行数は折り畳み状態と端末幅に依存し**描画時にしか決まらない**ので、上限は
    /// [`crate::ui::render`]の戻り値として受け取り、1フレーム描くごとにここへ渡す。
    /// これを怠ると、先頭まで遡った後もホイールを回した分だけ`scroll_offset`が伸び続け、
    /// **同じ回数だけ下へ回さないと画面が動かない**（画面は先頭で止まって見えるので、
    /// ユーザーには操作が効かなくなったようにしか見えない）。
    pub fn clamp_scroll(&mut self, max_offset: u16) {
        self.scroll.clamp(max_offset);
    }

    /// 既存の呼び出し元・テスト向けの読み出し。
    pub fn scroll_offset(&self) -> u16 {
        self.scroll.offset()
    }

    /// `delta`が正なら過去方向（上）へ、負なら最新方向（下）へスクロールする。
    /// 下限0（最新）でクランプする。上限は総行数依存のため、描画のたびに
    /// [`AppState::clamp_scroll`]で切り詰める。
    pub fn scroll_lines(&mut self, delta: i32) {
        self.scroll.scroll_lines(delta);
    }

    pub fn scroll_page(&mut self, delta: i32) {
        self.scroll.scroll_page(delta);
    }

    pub fn toggle_fold(&mut self) {
        self.collapsed = !self.collapsed;
        self.scroll.reset();
    }

    /// マウスホイールイベントを処理する。過去ログの閲覧を妨げないよう、承認モーダル表示中でも
    /// スクロール自体は許可する（`on_key`と異なり`pending_permission`をチェックしない）。
    pub fn on_mouse(&mut self, kind: MouseEventKind) {
        match kind {
            MouseEventKind::ScrollUp => self.scroll.wheel(true),
            MouseEventKind::ScrollDown => self.scroll.wheel(false),
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

    /// 復元した会話を実際に画面へ積む（[BUG-069](../../../docs/bugs/BUG-069.md)）。
    ///
    /// 件数の通知だけでは、**ユーザーが何を再開したのか分からない**。`--resume`・ピッカーの
    /// Enter/`f`・対話中の`/sessions`/`/fork`はいずれも会話状態（engine側）を差し替えるが、
    /// 画面のトランスクリプトは空のままだった。
    pub fn restore_transcript(&mut self, messages: &[harness_core::Message]) {
        for item in restored_transcript_items(messages) {
            self.transcript.push(item);
        }
    }

    /// 画面のトランスクリプトを空にする（[BUG-072](../../../docs/bugs/BUG-072.md)）。
    ///
    /// **会話そのものが別物に入れ替わる経路からだけ呼ぶ**——`/sessions`での別セッションへの
    /// 切替と`/clear`。残したままだと前の会話と新しい会話が地続きに見え、ユーザーには
    /// 1つの長い会話として読めてしまう（モデルは前半を見ていないのに、である）。
    ///
    /// `/fork`からは呼ばない。Forkは**同じ会話の続き**なので、画面もそのまま続くのが正しい。
    pub fn clear_transcript(&mut self) {
        self.transcript.clear();
        self.turn_open = false;
        self.turn_transcript_mark = 0;
        self.scroll.reset();
    }
}

/// 復元したメッセージ列を表示要素へ写す純粋関数（副作用が無いので単体テストできる）。
///
/// **`Thinking`/`RedactedThinking`は落とす**——署名付きで再表示しても読み物にならず、Tier3では
/// そもそも履歴から除去される（`harness_engine::sanitize`）ため、あるときと無いときで
/// 見え方が変わってしまう。`Image`も同様に落とす（TUIは画像を描けない）。
pub fn restored_transcript_items(messages: &[harness_core::Message]) -> Vec<TranscriptItem> {
    use harness_core::{ContentBlock, Role};

    let mut items: Vec<TranscriptItem> = Vec::new();
    for msg in messages {
        for block in &msg.content {
            match block {
                ContentBlock::Text(text) if text.trim().is_empty() => {}
                ContentBlock::Text(text) => items.push(match msg.role {
                    Role::User => TranscriptItem::User(text.clone()),
                    _ => TranscriptItem::Assistant(text.clone()),
                }),
                ContentBlock::ToolUse { id, name, input } => items.push(TranscriptItem::ToolCard {
                    id: id.clone(),
                    name: name.clone(),
                    input: pretty(input),
                    // 履歴なので実行は既に終わっている。結果がこの後の`ToolResult`で
                    // 見つかれば上書きする（見つからなければ「結果不明」のまま残す）。
                    status: ToolCardStatus::Done {
                        is_error: false,
                        output: "(result not recorded in this session file)".to_string(),
                    },
                }),
                ContentBlock::ToolResult {
                    tool_use_id,
                    content,
                    is_error,
                } => {
                    let card = items.iter_mut().rev().find(
                        |i| matches!(i, TranscriptItem::ToolCard { id, .. } if id == tool_use_id),
                    );
                    let output = truncate_preview(content);
                    match card {
                        Some(TranscriptItem::ToolCard { status, .. }) => {
                            *status = ToolCardStatus::Done {
                                is_error: *is_error,
                                output,
                            };
                        }
                        // 対応する`ToolUse`が履歴に無い（片側だけ残った）場合も落とさない。
                        _ => items.push(TranscriptItem::Info(format!(
                            "tool result for {tool_use_id} (call not in this session file): {output}"
                        ))),
                    }
                }
                ContentBlock::Thinking { .. }
                | ContentBlock::RedactedThinking { .. }
                | ContentBlock::Image { .. } => {}
            }
        }
    }
    items
}

fn truncate_preview(content: &str) -> String {
    if content.chars().count() > MAX_OUTPUT_PREVIEW {
        let head: String = content.chars().take(MAX_OUTPUT_PREVIEW).collect();
        format!("{head}... (truncated)")
    } else {
        content.to_string()
    }
}
