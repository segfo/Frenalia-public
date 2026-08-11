//! 単一行の入力欄（コマンド・作業ディレクトリ・ドメイン名）。
//!
//! `harness-tui`の入力欄（`app/input.rs`、401行）は**複数行・履歴・スラッシュコマンド・
//! 選択範囲**を持つ会話用のもので、要件が違う。ここが必要とするのは1行ぶんのカーソル移動と
//! 編集だけなので、あちらを抽出して共有するのではなく別物として持つ（規則5が禁じているのは
//! **同じロジックのコピー**であって、要件の違う小さな実装ではない）。
//!
//! 日本語を含む入力でカーソル位置がずれないよう、桁位置は`unicode_width`で数える。

use unicode_width::UnicodeWidthStr;

#[derive(Debug, Clone, Default)]
pub struct TextInput {
    text: String,
    /// カーソルのバイト位置。常に文字境界に置く。
    cursor: usize,
}

impl TextInput {
    pub fn new(text: impl Into<String>) -> Self {
        let text = text.into();
        let cursor = text.len();
        Self { text, cursor }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn is_empty(&self) -> bool {
        self.text.trim().is_empty()
    }

    /// 中身を差し替えてカーソルを末尾へ置く（ガイド付き遷移でコマンドを埋めるときに使う）。
    pub fn set_text(&mut self, text: impl Into<String>) {
        self.text = text.into();
        self.cursor = self.text.len();
    }

    pub fn insert(&mut self, ch: char) {
        self.text.insert(self.cursor, ch);
        self.cursor += ch.len_utf8();
    }

    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let prev = self.prev_boundary(self.cursor);
        self.text.replace_range(prev..self.cursor, "");
        self.cursor = prev;
    }

    pub fn delete(&mut self) {
        if self.cursor >= self.text.len() {
            return;
        }
        let next = self.next_boundary(self.cursor);
        self.text.replace_range(self.cursor..next, "");
    }

    pub fn left(&mut self) {
        self.cursor = self.prev_boundary(self.cursor);
    }

    pub fn right(&mut self) {
        self.cursor = self.next_boundary(self.cursor);
    }

    pub fn home(&mut self) {
        self.cursor = 0;
    }

    pub fn end(&mut self) {
        self.cursor = self.text.len();
    }

    /// カーソルの表示桁（全角文字を2桁として数える）。
    pub fn cursor_col(&self) -> u16 {
        self.text[..self.cursor].width() as u16
    }

    fn prev_boundary(&self, from: usize) -> usize {
        if from == 0 {
            return 0;
        }
        let mut i = from - 1;
        while i > 0 && !self.text.is_char_boundary(i) {
            i -= 1;
        }
        i
    }

    fn next_boundary(&self, from: usize) -> usize {
        let mut i = (from + 1).min(self.text.len());
        while i < self.text.len() && !self.text.is_char_boundary(i) {
            i += 1;
        }
        i
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editing_ascii_text_moves_the_cursor_by_characters() {
        let mut input = TextInput::new("cargo build");
        input.home();
        input.right();
        input.right();
        input.insert('X');

        assert_eq!(input.text(), "caXrgo build");
        assert_eq!(input.cursor_col(), 3);
    }

    /// **日本語を含む入力でも文字境界を跨がない**（バイト単位で動かすと文字が壊れる）。
    #[test]
    fn editing_multibyte_text_never_splits_a_character() {
        let mut input = TextInput::new("記録するコマンド");
        input.backspace();
        assert_eq!(input.text(), "記録するコマン");

        input.home();
        input.right();
        input.delete();
        assert_eq!(input.text(), "記するコマン");
    }

    /// カーソル桁は全角を2桁で数える（描画位置がずれると入力位置と見た目が食い違う）。
    #[test]
    fn the_cursor_column_counts_wide_characters_as_two() {
        let mut input = TextInput::new("あa");
        assert_eq!(input.cursor_col(), 3);
        input.left();
        assert_eq!(input.cursor_col(), 2);
    }

    /// 端での操作は何も壊さない（空文字列でのbackspace・末尾でのdelete）。
    #[test]
    fn editing_at_the_edges_is_a_no_op() {
        let mut input = TextInput::default();
        input.backspace();
        input.delete();
        input.left();
        assert_eq!(input.text(), "");
        assert_eq!(input.cursor_col(), 0);
    }
}
