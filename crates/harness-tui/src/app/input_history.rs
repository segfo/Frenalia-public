//! 入力欄の履歴（2026-10-06、ユーザーの要望）。シェルと同じく、↑で前に送った文を入力欄へ呼び戻し、↓で新しい側へ
//! 戻って最後は書きかけの文へ戻る。決めたことの正本は`plans/DESIGN.md` §リッチTUIの「入力ボックスの履歴」。
//!
//! # いつ↑↓が履歴を動かすか
//!
//! ↑↓はもともと複数行の入力で行を移るキーである（`app::input`）。両立させるため、**↑は入力の1行目にいるとき、
//! ↓は最終行にいて履歴を見ているときだけ**履歴を動かし、それ以外は今までどおり行を移る。行は`\n`で区切った行で
//! 数える（画面の折り返しは数えない。行の移動と同じ）。
//!
//! 呼び戻した後のカーソルは、古い側へ動いたら**その文の1行目の末尾**、新しい側へ動いたら**その文の末尾**に置く——
//! 複数行の文でも、同じキーを続けて押せばそのまま次の文へ進み、逆向きのキーなら文の中の行を移る。
//! 選択（`Shift+矢印`のアンカー）はどちらでも外す。
//!
//! 承認ダイアログ・レビューパネルが開いている間は、↑↓はそちらが受ける（`AppState::on_key_after_selection`の分岐の
//! 順。どちらも開いている間は全キーを先に取る）ので履歴は動かない。セッションのピッカーは別のループで、ここへキーが
//! 来ない。承認ダイアログの候補をクリックしたときに作る↑↓も、ダイアログが開いている間しか作らない（`app::pointer`）。
//!
//! # 積むもの
//!
//! 送った文をそのまま積む（`/`で始まる命令も——打ち間違いを直して送り直せるように）。**空白だけの文と、直前に
//! 積んだ文と同じ文は積まない**（離れた位置の同じ文は積む）。最大[`MAX_ENTRIES`]件で、超えたら古い側から捨てる。
//!
//! 会話を再開して起動したとき（`--resume`・`--continue`・起動時のピッカー）は、復元した会話の**人が書いた文**から
//! 作る（[`AppState::seed_input_history`]）。見分けは`harness_core::human_turns`（D-127 と同じ判定）で、ツールの
//! 結果を運ぶ文と、会話の古い側を置き換えた要約の文は入らない。積み方の規則（空白・直前と同じ・上限）は送った文と同じ。
//!
//! # 書きかけを失わない
//!
//! 初めて↑で呼び戻すとき、それまでの書きかけ・カーソル・undo/redo を退避し（[`InputDraft`]）、↓で最も新しい文を
//! 過ぎたら戻す——戻した後の`Ctrl+Z`は、書きかけの最後の編集を取り消す。呼び戻した文を**編集したら**、履歴を
//! 見るのをやめてその文が新しい書きかけになる（退避した書きかけは捨てる）。編集はどの経路も
//! `AppState::push_undo_snapshot`を通るので、そこでやめる。送ったときも捨てる（シェルと同じ）。
//!
//! # 別物
//!
//! `AppState::command_history`（`harness_core::CommandHistory`）は**実際に走ったコマンドの流れ**で、判定モデルへ
//! 渡す。こちらは人が自分の文を直して送り直すための道具で、中身が違うので共有しない。
//!
//! # 限界
//!
//! - 履歴はこのプロセスの中だけで持ち、ファイルへ書かない。
//! - 再開で戻せるのは会話に残った文だけ——`/`の命令（会話へ入らない）と、要約へ畳まれて消えた文は戻らない。
//!   起動した後の`/sessions`・`/fork`での切り替えでは作り直さない（その時点までに送った文がそのまま残る）。
//! - 呼び戻した文の上の`Ctrl+Z`は何もしない（呼び戻した文は編集の履歴を持たない）。

use std::collections::VecDeque;

use super::AppState;

/// 残す文の数の上限。
pub(super) const MAX_ENTRIES: usize = 100;

/// 入力欄の中身一式。呼び戻す前の書きかけを退避し、↓で戻すときに使う。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct InputDraft {
    pub(super) text: String,
    pub(super) cursor: usize,
    pub(super) undo: Vec<(String, usize)>,
    pub(super) redo: Vec<(String, usize)>,
    pub(super) last_edit_was_insert: bool,
}

/// ↓で入力欄へ出すもの（[`InputHistory::newer`]）。
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Newer {
    /// 1つ新しい文。
    Entry(String),
    /// 最も新しい文を過ぎた。退避していた書きかけで、履歴を見るのはここで終わる。
    Draft(InputDraft),
}

/// 送った文の履歴と、いまどれを見ているか。
#[derive(Debug, Default)]
pub(super) struct InputHistory {
    /// 古い順。
    entries: VecDeque<String>,
    /// 履歴を見ている間だけ`Some`。
    browsing: Option<Browse>,
}

/// 履歴を見ている間の状態。
#[derive(Debug)]
struct Browse {
    /// いま入力欄に出している文の、`entries`の添字。
    at: usize,
    /// 呼び戻す前の書きかけ。
    draft: InputDraft,
}

impl InputHistory {
    /// 送った文を積む。空白だけの文と、直前に積んだ文と同じ文は積まない。履歴を見るのはここで終わる
    /// （退避した書きかけは捨てる）。
    pub(super) fn record(&mut self, text: &str) {
        self.browsing = None;
        if text.trim().is_empty() || self.entries.back().is_some_and(|last| last == text) {
            return;
        }
        if self.entries.len() == MAX_ENTRIES {
            self.entries.pop_front();
        }
        self.entries.push_back(text.to_string());
    }

    /// 古い順の文を、送った文と同じ規則で積む（再開時。↑で最も新しい文から出る）。
    pub(super) fn seed<'a>(&mut self, texts: impl IntoIterator<Item = &'a str>) {
        for text in texts {
            self.record(text);
        }
    }

    /// 1つ古い文。無ければ`None`（何も変えない）。履歴を見ていなかったときは、`save`が返す書きかけを退避して
    /// 見始める（`save`はそのときだけ呼ぶ）。
    pub(super) fn older(&mut self, save: impl FnOnce() -> InputDraft) -> Option<String> {
        let at = match &mut self.browsing {
            Some(browse) => {
                browse.at = browse.at.checked_sub(1)?;
                browse.at
            }
            None => {
                let at = self.entries.len().checked_sub(1)?;
                self.browsing = Some(Browse { at, draft: save() });
                at
            }
        };
        Some(self.entries[at].clone())
    }

    /// 1つ新しい文か、最も新しい文を過ぎたら退避した書きかけ。履歴を見ていなければ`None`（何も変えない）。
    pub(super) fn newer(&mut self) -> Option<Newer> {
        let browse = self.browsing.as_mut()?;
        if browse.at + 1 < self.entries.len() {
            browse.at += 1;
            return Some(Newer::Entry(self.entries[browse.at].clone()));
        }
        self.browsing
            .take()
            .map(|browse| Newer::Draft(browse.draft))
    }

    /// 履歴を見るのをやめる（呼び戻した文を編集した。いま入力欄にある文が新しい書きかけになる）。
    pub(super) fn stop_browsing(&mut self) {
        self.browsing = None;
    }

    #[cfg(test)]
    pub(super) fn is_browsing(&self) -> bool {
        self.browsing.is_some()
    }

    #[cfg(test)]
    pub(super) fn entries(&self) -> Vec<&str> {
        self.entries.iter().map(String::as_str).collect()
    }
}

impl AppState {
    /// ↑を入力の1行目で押した。1つ古い文を入力欄へ呼び戻し、カーソルをその文の1行目の末尾に置く。古い文が
    /// 無ければ何もしない（今までどおり）。
    pub(super) fn recall_older(&mut self) {
        let Some(text) = self.input_history.older(|| InputDraft {
            text: std::mem::take(&mut self.input),
            cursor: self.input_cursor,
            undo: std::mem::take(&mut self.input_undo_stack),
            redo: std::mem::take(&mut self.input_redo_stack),
            last_edit_was_insert: self.input_last_edit_was_insert,
        }) else {
            return;
        };
        let first_line_end = text
            .split('\n')
            .next()
            .map_or(0, |line| line.chars().count());
        self.show_recalled(text, first_line_end);
    }

    /// ↓を最終行で押した。履歴を見ていれば1つ新しい文を呼び戻してカーソルを末尾に置き、最も新しい文を過ぎたら
    /// 退避した書きかけをカーソル・undo/redo ごと戻す。履歴を見ていなければ何もしない（今までどおり）。
    pub(super) fn recall_newer(&mut self) {
        match self.input_history.newer() {
            None => {}
            Some(Newer::Entry(text)) => {
                let end = text.chars().count();
                self.show_recalled(text, end);
            }
            Some(Newer::Draft(draft)) => {
                self.input = draft.text;
                self.input_cursor = draft.cursor;
                self.input_undo_stack = draft.undo;
                self.input_redo_stack = draft.redo;
                self.input_last_edit_was_insert = draft.last_edit_was_insert;
                self.input_selection_anchor = None;
            }
        }
    }

    /// 呼び戻した文を入力欄へ出す（編集の履歴は持たない）。
    fn show_recalled(&mut self, text: String, cursor: usize) {
        self.input = text;
        self.input_cursor = cursor;
        self.input_selection_anchor = None;
        self.input_undo_stack.clear();
        self.input_redo_stack.clear();
        self.input_last_edit_was_insert = false;
    }

    /// 再開した会話の人が書いた文（`harness_core::human_turns`。ツールの結果を運ぶ文と要約の文を除く）から
    /// 履歴を作る。古い順に積むので、↑で最も新しい文から出る。
    pub(super) fn seed_input_history(&mut self, messages: &[harness_core::Message]) {
        self.input_history.seed(
            harness_core::human_turns::human_turns(messages)
                .into_iter()
                .map(|turn| turn.text),
        );
    }
}

#[cfg(test)]
#[path = "input_history_tests.rs"]
mod tests;
