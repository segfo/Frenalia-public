//! 入力欄のキーボード操作（カーソル・選択・undo/redo・改行と送信）。
//!
//! crosstermの[`KeyEvent`]だけを入力とし、確定した意図を[`Action`]として返す。
//! エンジンからのイベント消費（[`super::events`]）とは逆向きの経路であり、両者は
//! [`AppState`]のフィールドを介してのみ交わる。

use super::*;

impl AppState {
    /// 入力欄が空白だけか（送るものが無い）。[`Self::submit_input`]が何もしない条件と、「送信」を押せない形にする条件
    /// （[`Self::input_buttons`]）を同じこれから取る——別々に書くと「押せない見た目なのに送れる」「押せる見た目なのに
    /// 何も起きない」のずれが生まれる（B-05）。
    fn input_is_blank(&self) -> bool {
        self.input.trim().is_empty()
    }

    /// 入力欄の内容を送る。送信キー（[`Self::on_key`]）と入力欄の右の「送信」ボタン（キーを押す。`app::pointer`）が
    /// どちらもここを通る。
    ///
    /// **入力欄が空白だけなら何もしない**——送らず、transcript に何も出さず、さかのぼりの位置も変えない（2026-10-06の
    /// ユーザーの決定。`plans/PLAN-TUI-IMPROVEMENTS.md`§4.1）。その間「送信」ボタンは押せない形で描く
    /// （[`Self::input_buttons`]）ので、何も起きないことは押す前から見えている。ポリシーエディタの`start_recording`も、
    /// 空のコマンドでは知らせを出さない。
    pub(super) fn submit_input(&mut self) -> Option<Action> {
        if self.input_is_blank() {
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
    /// 送信と中断はここに無い——入力欄の右の枠付きのボタン（[`Self::input_buttons`]）へ移した（2026-10-03）。
    /// 残るのはキーボードの人のための案内で、`PageUp/PageDown`は1つのキーに決まらないので押せない。`Enter=改行`は
    /// 素のEnterが改行のとき（[`Self::enter_submits`]が偽）だけ出す。
    ///
    /// 3つめの項目は1つの場所を状態で使い分ける（項目を増やさない——見出しは幅が足りないと後ろから項目を落とす）。
    /// 写せる選択があれば`Ctrl-C=コピー`（`app::select`）。無ければ、`Esc`の二度押しが終了に数えられる間
    /// （[`Self::esc_would_count`]）だけ`Esc×2=終了`（`app::quit`）——止めるものが走っている間・重ねた枠が開いている間は
    /// `Esc`が別の働きをするので出さない（効く操作を案内する、B-32）。`Esc×2=終了`は押すと`Esc`を2回続けて押す
    /// （ポリシーエディタのキー案内の`Esc×2 終了`と同じ。`plans/POLICY-EDITOR-TOMOYO-DIG.md`決定62の
    /// 「マウスで操作できるようにした」の表の5）。
    pub fn input_key_hints(&self) -> Vec<KeyHint> {
        let mut hints = Vec::new();
        if !self.enter_submits {
            hints.push(KeyHint::press("Enter=改行", KeyCode::Enter));
        }
        hints.push(KeyHint::shown("PageUp/PageDown=スクロール"));
        if self.has_copyable_selection() {
            hints.push(KeyHint::press_key(
                "Ctrl-C=コピー",
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
            ));
        } else if self.esc_would_count() {
            hints.push(KeyHint::press_twice("Esc×2=終了", KeyCode::Esc));
        }
        hints
    }

    /// 入力欄の右に並べる枠付きのボタン（左から「送信」「中断」。2026-10-03、ユーザーが実機を見て図を描いた——
    /// 「ボタンと分かるように、枠で囲んだものを入力欄の右に」）。**押せば同じキーを押したのと同じ**（`app::pointer`）。
    ///
    /// - **送信**はいつも出す。キーは設定と端末で変わる（[`Self::enter_submits`]・[`Self::host_is_vscode`]——
    ///   VS Codeの統合ターミナルはShift+EnterのShiftを落とすので`Alt+Enter`を案内する）ので、下辺に添える綴りもここで
    ///   決める。**入力欄が空白だけの間は押せない**（`pressable`が偽。押せない形で描き、押す場所を登録しない——
    ///   `harness_term::button`の押せない形。押した結果空になった直後は、押されている形が戻るまで押されている形）。送信キーを押しても何も起きない（[`Self::submit_input`]）ので、押せる
    ///   見た目にすると壊れて見える。ポリシーエディタの「記録を開始」も、コマンド欄が空の間は同じく押せない
    ///   （`key_hints::record_buttons`）。消さずに残すのは、送る場所を最初から見せておくため。
    ///   2026-10-03〜10-06は空でも押せる形で描き、押すと理由を1行出していた（ユーザーが2つの画面のボタンの色の違いを
    ///   指摘したのに合わせた）が、2026-10-06にユーザーが「空の送信では何も出さない」と決め、押せない形に戻した
    ///   （`plans/PLAN-TUI-IMPROVEMENTS.md`§4.1）。
    /// - **中断**は止めるものが走っている間（[`Self::can_cancel`]）だけ出す。走っていない間に`Esc`を押しても
    ///   何も止まらないので、効かない操作を案内しない（ポリシーエディタの記録画面の`Esc 停止`と同じ。B-32）。
    ///
    /// 中断は送信の**右**に並ぶ（ユーザーの図のとおり）。出たり消えたりすると送信の位置が動くので、動いた直後の
    /// クリックは捨てる（`app::pointer`のモジュールdoc）。
    pub fn input_buttons(&self) -> Vec<InputButton> {
        let (key_label, key) = if self.enter_submits {
            ("Enter", KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        } else if self.host_is_vscode {
            (
                "Alt+Enter",
                KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT),
            )
        } else {
            (
                "Shift+Enter",
                KeyEvent::new(KeyCode::Enter, KeyModifiers::SHIFT),
            )
        };
        let mut buttons = vec![InputButton {
            label: "送信",
            key_label,
            key,
            pressable: !self.input_is_blank(),
        }];
        if self.can_cancel() {
            buttons.push(InputButton {
                label: "中断",
                key_label: "Esc",
                key: KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
                pressable: true,
            });
        }
        buttons
    }

    /// `Esc`で止めるものが走っているか——応答中のターンか、走り始めた`/compact`の要約。
    ///
    /// `Esc`はエンジンの「いま走っているもの」の取り消しを発火させる（`crate::engine::EngineHandle::cancel_current`）。
    /// キューで待っているだけの`/compact`は、まだ取り消しの的に入っていないので数えない（BUG-071）。
    pub fn can_cancel(&self) -> bool {
        self.turn_in_flight || self.busy_progress.as_ref().is_some_and(|b| b.is_running())
    }

    /// キー入力を処理し、engineアクター/InteractiveGateへ伝えるべきアクションを返す（いまの時刻で。[`Self::on_key_at`]）。
    pub fn on_key(&mut self, key: KeyEvent) -> Option<Action> {
        self.on_key_at(key, Instant::now())
    }

    /// [`Self::on_key`]の本体。`now`はキーを押した時刻（`Esc`の二度押しを数える。試験は時刻を作って渡す）。
    ///
    /// `Ctrl+C`はいつも選択が受ける——選んでいれば写し、選んでいなければ終了の仕方を知らせる（終了はしない）。選んでいる
    /// 文章があれば`Esc`はそれを外すだけにする（承認ダイアログ・レビューパネルが開いていても先に。`app::select`の
    /// モジュールdoc）。入力欄にキーボードで選択を作ったら、マウスの選択は外す（2つの選択を同時に持たない）。
    pub(crate) fn on_key_at(&mut self, key: KeyEvent, now: Instant) -> Option<Action> {
        // `Esc`の二度押しの1回目は、この押下が何もしていない`Esc`だったときだけ残る（`app::quit`）。ここで取り出して
        // 数え直した状態にし、数える1か所（`count_quiet_esc`）だけが戻す——`Esc`以外のキーも、他の働きをした`Esc`も、
        // 経路ごとに書き足さなくても数え直しになる。
        let first_esc = std::mem::take(&mut self.double_esc);
        if let Some(handled) = self.on_selection_key(key) {
            return handled;
        }
        let before = self.selection_range();
        let action = self.on_key_after_selection(key, first_esc, now);
        let after = self.selection_range();
        if after.is_some() && after != before {
            self.selection.clear();
        }
        action
    }

    /// [`Self::on_key_at`]の本体（選択が受けなかったキー）。`first_esc`は、このキーが何もしていない`Esc`だったときにだけ
    /// 数える二度押しの1回目。
    fn on_key_after_selection(
        &mut self,
        key: KeyEvent,
        first_esc: harness_term::double_esc::DoubleEsc,
        now: Instant,
    ) -> Option<Action> {
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

        // `Ctrl+C`はここへ来ない（いつも選択が受ける。`on_selection_key`）——終了には使わない（`app::quit`）。
        match key.code {
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
            // モーダル非表示時のEscは、止めるものが走っていればそれを止める（設計書§リッチTUI「Escで
            // CancellationToken発火」）。止めた`Esc`は二度押しに数えない（`first_esc`は捨てたまま）。
            KeyCode::Esc if self.can_cancel() => Some(Action::Cancel),
            // 何も走っていなければ、二度押しの1回目・2回目として数える（`app::quit`）。
            KeyCode::Esc => self.count_quiet_esc(first_esc, now),
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
