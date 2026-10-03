//! 入力欄のキーボード操作（カーソル・選択・undo/redo・改行と送信）。
//!
//! crosstermの[`KeyEvent`]だけを入力とし、確定した意図を[`Action`]として返す。
//! エンジンからのイベント消費（[`super::events`]）とは逆向きの経路であり、両者は
//! [`AppState`]のフィールドを介してのみ交わる。

use super::*;

impl AppState {
    pub(super) fn submit_input(&mut self) -> Option<Action> {
        if self.input.trim().is_empty() {
            return None;
        }
        // A local submit starts a new visible turn. Even if the user had been
        // browsing older transcript lines, jump back to live output so the
        // prompt, Thinking indicator, and following deltas stay visible.
        self.scroll.reset();
        let text = std::mem::take(&mut self.input);
        self.input_cursor = 0;
        self.input_selection_anchor = None;
        self.input_undo_stack.clear();
        self.input_redo_stack.clear();
        self.input_last_edit_was_insert = false;
        if text.trim_start().starts_with('/') {
            return match parse_slash_command(&text) {
                Ok(SlashCommand::FsStage(fs_cmd)) => {
                    self.transcript
                        .push(TranscriptItem::Info(format!("> {text}")));
                    Some(match fs_cmd {
                        FsStageCommand::List => Action::ListChanges,
                        FsStageCommand::Open => Action::OpenChangesPanel,
                        FsStageCommand::CommitAll => Action::CommitAllChanges,
                        // 非対話の1ファイルcommitはファイル単位のまま（ハンク選択は対話UIが担う、
                        // `plans/PLAN-VSCODE-REVIEW.md`「CLIはファイル単位のまま」）。
                        FsStageCommand::CommitFile(path) => {
                            Action::CommitChanges(CommitSelection {
                                whole_files: vec![path],
                                partial: Vec::new(),
                            })
                        }
                        FsStageCommand::Discard => Action::DiscardChanges,
                        FsStageCommand::Resolve(path) => Action::ResolveChanges(path),
                    })
                }
                Ok(cmd) => {
                    self.transcript
                        .push(TranscriptItem::Info(format!("> {text}")));
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
    pub(super) fn delete_selection(&mut self) {
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
    pub(super) fn line_start_indices(&self) -> Vec<usize> {
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
    pub(super) fn current_line_bounds(&self) -> (usize, usize) {
        let char_count = self.input.chars().count();
        let starts = self.line_start_indices();
        let line_idx = starts
            .iter()
            .rposition(|&s| s <= self.input_cursor)
            .unwrap_or(0);
        let start = starts[line_idx];
        let end = starts
            .get(line_idx + 1)
            .map(|&next_start| next_start - 1) // 次行の開始の1つ前 = この行の`\n`の位置
            .unwrap_or(char_count);
        (start, end)
    }

    /// 変更前に現在の入力状態をUndo履歴に積む。`coalesce_insert`が真かつ直前も単純挿入
    /// だった場合は、連続タイピングを1つのUndo単位にまとめるため何もしない。
    pub(super) fn push_undo_snapshot(&mut self, coalesce_insert: bool) {
        if coalesce_insert && self.input_last_edit_was_insert {
            return;
        }
        self.input_undo_stack
            .push((self.input.clone(), self.input_cursor));
        self.input_redo_stack.clear();
        self.input_last_edit_was_insert = coalesce_insert;
    }

    pub(super) fn undo(&mut self) {
        if let Some((prev_input, prev_cursor)) = self.input_undo_stack.pop() {
            self.input_redo_stack
                .push((self.input.clone(), self.input_cursor));
            self.input = prev_input;
            self.input_cursor = prev_cursor;
            self.input_selection_anchor = None;
            self.input_last_edit_was_insert = false;
        }
    }

    pub(super) fn redo(&mut self) {
        if let Some((next_input, next_cursor)) = self.input_redo_stack.pop() {
            self.input_undo_stack
                .push((self.input.clone(), self.input_cursor));
            self.input = next_input;
            self.input_cursor = next_cursor;
            self.input_selection_anchor = None;
            self.input_last_edit_was_insert = false;
        }
    }

    /// 入力欄の見出しに出すキーの案内（**押せば同じキーを押したのと同じ**。`app::pointer`）。
    ///
    /// 送信と中断はここに無い——入力欄の右下のボタン（[`Self::input_buttons`]）へ移した（2026-10-03）。
    /// 残るのはキーボードの人のための案内で、`PageUp/PageDown`は1つのキーに決まらないので押せない。`Enter=改行`は
    /// 素のEnterが改行のとき（[`Self::enter_submits`]が偽）だけ出す。`Ctrl-C=終了`は押せる——ポリシーエディタのキー案内も
    /// 終了の項目を押せる（`plans/POLICY-EDITOR-TOMOYO-DIG.md`決定62の「マウスで操作できるようにした」の表の5）。
    pub fn input_key_hints(&self) -> Vec<KeyHint> {
        let mut hints = Vec::new();
        if !self.enter_submits {
            hints.push(KeyHint::press("Enter=改行", KeyCode::Enter));
        }
        hints.push(KeyHint::shown("PageUp/PageDown=スクロール"));
        hints.push(KeyHint::press_key(
            "Ctrl-C=終了",
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        ));
        hints
    }

    /// 入力欄の右下に並べるボタン（左から「中断」「送信」。2026-10-03、ユーザーが実機で「送信やキャンセルが
    /// できると直感的に分からない」と指摘した）。**押せば同じキーを押したのと同じ**（`app::pointer`）。
    ///
    /// - **送信**はいつも出す。キーは設定と端末で変わる（[`Self::enter_submits`]・[`Self::host_is_vscode`]——
    ///   VS Codeの統合ターミナルはShift+EnterのShiftを落とすので`Alt+Enter`を案内する）ので、文言もここで決める。
    ///   入力欄が空白だけの間は**押せない**（`key`が`None`。送信キーを押しても何も起きない——[`Self::submit_input`]）。
    /// - **中断**は止めるものが走っている間（[`Self::can_cancel`]）だけ出す。走っていない間に`Esc`を押しても
    ///   何も止まらないので、効かない操作を案内しない（ポリシーエディタの記録画面の`Esc 停止`と同じ。B-32）。
    ///
    /// 中断を送信の**左**に置くのは、出たり消えたりしても送信の位置が動かないようにするため。
    pub fn input_buttons(&self) -> Vec<InputButton> {
        let mut buttons = Vec::with_capacity(2);
        if self.can_cancel() {
            buttons.push(InputButton {
                hint: KeyHint::press("Esc=中断", KeyCode::Esc),
                short: "中断",
            });
        }
        let (label, key) = if self.enter_submits {
            (
                "Enter=送信",
                KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            )
        } else if self.host_is_vscode {
            (
                "Alt+Enter=送信",
                KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT),
            )
        } else {
            (
                "Shift+Enter=送信",
                KeyEvent::new(KeyCode::Enter, KeyModifiers::SHIFT),
            )
        };
        buttons.push(InputButton {
            hint: match self.input.trim().is_empty() {
                true => KeyHint::shown(label),
                false => KeyHint::press_key(label, key),
            },
            short: "送信",
        });
        buttons
    }

    /// `Esc`で止めるものが走っているか——応答中のターンか、走り始めた`/compact`の要約。
    ///
    /// `Esc`はエンジンの「いま走っているもの」の取り消しを発火させる（`crate::engine::EngineHandle::cancel_current`）。
    /// キューで待っているだけの`/compact`は、まだ取り消しの的に入っていないので数えない（BUG-071）。
    pub fn can_cancel(&self) -> bool {
        self.turn_in_flight || self.busy_progress.as_ref().is_some_and(|b| b.is_running())
    }

    /// キー入力を処理し、engineアクター/InteractiveGateへ伝えるべきアクションを返す。
    pub fn on_key(&mut self, key: KeyEvent) -> Option<Action> {
        // 承認モーダルは自分でキーを解釈する（確認の一段・穴の選択・枠のスクロールがあるので、
        // 「決定キー以外は捨てる」では足りない）。ここに残るのは**応答への写像**だけである
        // （審査パネルと同じ分け方。`app::approval`のモジュールdoc参照）。
        if let Some(pending) = &mut self.pending_permission {
            let command = pending.on_key(key)?;
            let id = pending.id.clone();
            self.pending_permission = None;
            return Some(match command {
                ApprovalCommand::Once => Action::Respond(id, Decision::Allow),
                ApprovalCommand::Deny => Action::Respond(id, Decision::Deny),
                ApprovalCommand::DenySession => Action::Respond(id, Decision::DenyAndRemember),
                ApprovalCommand::Remember(holes) => Action::RespondRemember(id, holes),
            });
        }

        // レビューパネル表示中は全キーをパネルへ渡す。骨格（選択・トグル・スクロール・
        // ハンク操作）はパネル自身が処理し、ここには**面ごとのアクションへの写像**だけが残る
        // （`app::review`のモジュールdoc参照）。
        if let Some(panel) = &mut self.review_panel {
            let command = panel.on_key(key)?;
            let panel = self.review_panel.take()?;
            return match command {
                ReviewCommand::Close => None,
                ReviewCommand::DiscardAll => Some(Action::DiscardChanges),
                ReviewCommand::Primary(outcome) => Some(Action::CommitChanges(commit_selection(
                    &panel.rows,
                    &outcome,
                ))),
            };
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
            KeyCode::Char(c)
                if (c == 'z' || c == 'Z') && key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
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
            // 送信キーはAlt+Enter・Shift+Enterの両方。VS Code統合ターミナル（xterm.js）は
            // Shift修飾を落として素のEnterとして届けるため、そちらでは自然に改行のままになる
            // （＝SHIFT修飾が実際に届くかどうか自体が端末の自動検出になっている）。
            KeyCode::Enter
                if !(key
                    .modifiers
                    .intersects(KeyModifiers::ALT | KeyModifiers::SHIFT)
                    || self.enter_submits) =>
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
            // ここに来るのはAlt+Enter・Shift+Enter（送信キー）または`enter_submits`時の素のEnter。
            // VS Code統合ターミナルでも物理Alt+EnterはネイティブにESC+CRとして送られ、crossterm
            // がESCプレフィックスをAlt修飾と解釈するため、keybindingの細工なしに届く（M09で検証）。
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
                    let line_idx = starts
                        .iter()
                        .rposition(|&s| s == next_start)
                        .unwrap_or(starts.len() - 1);
                    let next_end = starts
                        .get(line_idx + 1)
                        .map(|&s| s - 1)
                        .unwrap_or(char_count);
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
pub(super) fn char_byte_index(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(i, _)| i)
        .unwrap_or(s.len())
}
