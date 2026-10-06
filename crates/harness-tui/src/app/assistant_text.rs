//! [`AssistantText`]: transcriptの1項目としてのassistantの返答。原文と、それを描く[`MarkdownView`]を一緒に持つ。
//!
//! # 何のためにあるのか
//!
//! 返答は流れ込みながら届き、描くたびに描く側（[`MarkdownView`]）が描き直す。原文（コピーや試験が読む元の文字列）と
//! 描く側の状態を別々の場所に置くと、片方にだけ足されてずれる。だから**足す口を[`AssistantText::push_str`]の1つに
//! し、中身の`String`を外から触れなくして、ほかの足し方を型で無くす**。切り詰め（応答の破棄）・全消去（`/clear`）・
//! セッションの復元は項目ごと作り直すか捨てるので、ずれる経路は無い（`plans/PLAN-TUI-IMPROVEMENTS.md`§1.4(4)）。
//!
//! # 限界
//!
//! - 描くのは`&AppState`からなので、描く側は`RefCell`で持つ。描いている最中に同じ項目へ足す経路は無い
//!   （描画とイベントの処理は同じループで順に走る）ので、借用が重なって止まることは無い。
//! - 原文を2か所に持つ（この型の`String`と、描く側の中の写し）。返答の長さのぶん、メモリを2倍使う。

use std::cell::{Cell, RefCell};
use std::fmt;

use crate::markdown::{MarkdownView, Rendered};

#[cfg(test)]
#[path = "assistant_text_tests.rs"]
mod tests;

/// assistantの返答（モジュールdoc）。
pub struct AssistantText {
    source: String,
    view: RefCell<MarkdownView>,
    /// 流入の終わりを伝えたか（[`Self::finish`]で立ち、[`Self::push_str`]で倒れる）。複製するときに、新しい描く側へ
    /// 同じ状態を作り直すために持つ。
    finished: Cell<bool>,
}

impl AssistantText {
    /// `source`で始まる返答（まだ流入中）。
    pub(crate) fn new(source: impl Into<String>) -> Self {
        let source = source.into();
        let mut view = MarkdownView::new();
        view.push(&source);
        Self {
            source,
            view: RefCell::new(view),
            finished: Cell::new(false),
        }
    }

    /// 末尾へ足す。**追記はここだけを通る**（原文と描く側の両方へ同じ文章を足す。モジュールdoc）。終えた後に足すと
    /// 流入を再開する。
    pub(crate) fn push_str(&mut self, chunk: &str) {
        self.source.push_str(chunk);
        self.view.get_mut().push(chunk);
        self.finished.set(false);
    }

    /// 原文（試験が読む。製品で原文を読むのは複製と`Debug`だけで、描くのは描く側が持つ写しから）。
    #[cfg(test)]
    pub(crate) fn as_str(&self) -> &str {
        &self.source
    }

    /// 流入の終わりを伝える（何度呼んでも1回と同じ）。描くときに、流入中でない項目へ掛ける（`crate::ui`）。
    pub(crate) fn finish(&self) {
        self.view.borrow_mut().finish();
        self.finished.set(true);
    }

    /// transcriptの枠の内側の幅`inner_width`で描く（[`MarkdownView::render`]）。
    pub(crate) fn render(&self, inner_width: u16) -> Rendered {
        self.view.borrow_mut().render(inner_width)
    }

    /// 流入の終わりを伝えたか（描くときの`finish`の配線を試験が確かめる）。
    #[cfg(test)]
    pub(crate) fn is_finished(&self) -> bool {
        self.finished.get()
    }
}

/// 描く側は解析の途中経過を持ち、複製できるとは限らない（解析器が`Clone`を持たないことがある）。だから原文を
/// 新しい描く側へ流し直し、終えていたなら終える——描く結果は元と同じになる（Portの契約: どう区切って足しても同じ）。
impl Clone for AssistantText {
    fn clone(&self) -> Self {
        let copy = Self::new(self.source.clone());
        if self.finished.get() {
            copy.finish();
        }
        copy
    }
}

/// 原文だけを出す（描く側の中身は出さない）。`String`だったときと同じ形（`Assistant("…")`）になる。
impl fmt::Debug for AssistantText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.source, f)
    }
}
