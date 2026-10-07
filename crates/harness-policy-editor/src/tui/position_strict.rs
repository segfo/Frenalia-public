//! 承認待ち（`F2`）の位置の木の **`s`＝Strict にする**・**`w`＝作業ディレクトリを宣言する**
//! （`plans/POLICY-EDITOR-TOMOYO-DIG.md` 決定67(3)〜(5)、手順は`plans/position-domains/P5.md`の P5.10.2）。
//!
//! # 何のためにあるのか
//!
//! Strict モード（決定66の追記）は、遷移先のドメインに`strict`の印を付け、そこへ入る辺の入力を全部固定する——引数は
//! リテラル、作業ディレクトリは宣言し、どちらも呼び出し元が書けない場所に置く。P5.10 まではエディタが作業ディレクトリを
//! 書かなかったので、Strict のドメインへ入る辺は`policy.json`に手で書くしかなかった。ここは分けた行（`u`で引数を固定した
//! 行、[`super::position_split`]）を Strict にし、作業ディレクトリの候補を出して人が直せるようにする。
//!
//! # 判定はしない（`B-13`）
//!
//! 書けるか（固定していない・呼び出し元が書けるスクリプト・作業ディレクトリ）は、Strict の印と作業ディレクトリを当てた
//! 辺を判定器に聞く（[`crate::position_view::verdicts`]＝`check_all`の規則(e)(i)）。ここは結果で予約を戻すか決めるだけ。
//!
//! # キー（決定62——同じ画面のタブで逆の向きのキーを作らない）
//!
//! - `s`は`F3`の`s`（Strict の付け外し）と同じ意味。承認待ちの他のタブには`s`の操作が無い（拒否のタブでは理由を言う）。
//! - `w`（working directory）は承認待ち・宣言画面のどのタブでも使っていなかった。予約の数を変えない（向きを持たない）。
//!
//! # 限界
//!
//! - 作業ディレクトリは記録に残らないので候補でしかない（[`crate::position_view::cwd_candidate`]）。相対パスのスクリプトなら
//!   「推定」と添える。間違っていれば実行時に`CwdMismatch`で分かる（拒否のタブから直す操作は無い——決定67の寿命）。
//! - 宣言した作業ディレクトリと違う場所からの呼び出しは断られる（決定67(4)、`plans/DESIGN-MAC-ENFORCEMENT.md` §8.3）。

use harness_policy::position_domains::PositionSource;

use crate::position_view::{cwd_candidate, key_of, EdgeVerdict};
use crate::tui::state::App;
use crate::tui::text_input::TextInput;
use crate::tui::transition_positions::Selected;
use crate::tui::transition_screen::file_name;

/// 判定器の理由の1行目（状態の行に出す）。
fn reason(verdict: &EdgeVerdict) -> String {
    match verdict {
        EdgeVerdict::Rejected { detail } => detail.lines().next().unwrap_or_default().to_string(),
        EdgeVerdict::AlreadyDeclared | EdgeVerdict::Writable | EdgeVerdict::Widens { .. } => {
            String::new()
        }
    }
}

impl App {
    /// `s`と`w`が効く行か。効かなければ理由を状態の行に出して`None`。
    fn fixed_row(&mut self, what: &str) -> Option<(Selected, String)> {
        let Some(selected) = self.selected_position() else {
            self.status = self.no_position_message();
            return None;
        };
        let name = file_name(&selected.position.exe).to_string();
        if selected.position.source == PositionSource::ExistingEdge {
            self.status = format!(
                "{name} は宣言済みの辺の行です（{what}は policy.json の辺が決めています。Strict の印は宣言画面（F3）の\
                 遷移タブで付け外しします）"
            );
            return None;
        }
        if selected.position.fixed_command_line.is_none() {
            self.status = format!(
                "{name}: 先に Space で選んで u で引数を記録どおりに固定してください（{what}を持てるのは引数を固定した\
                 行だけ——Strict の引数はリテラルだけ、決定67(5)）"
            );
            return None;
        }
        Some((selected, name))
    }

    /// `s`: 分けた行を Strict にする／やめる。判定器が断るなら変えずに理由を言う。
    pub(super) fn toggle_selected_position_strict(&mut self) {
        let Some((selected, name)) = self.fixed_row("Strict") else {
            return;
        };
        let key = key_of(&selected.position);
        let workspace_root = self.workspace_root.clone();
        let extra_fs = self.position_extra_fs();
        let Some(positions) = self.pending.positions.as_mut() else {
            return;
        };
        let reserved = positions.approve.contains(&key);
        let turning_on = !positions.strict.contains(&key);
        let flip = |positions: &mut crate::tui::transition_positions::PositionsState, on: bool| {
            if on {
                positions.strict.insert(key.clone());
            } else {
                positions.strict.remove(&key);
            }
        };
        flip(positions, turning_on);
        positions.refresh_verdicts(&workspace_root, &extra_fs);
        let verdict = positions
            .verdicts
            .get(selected.index)
            .cloned()
            .unwrap_or(EdgeVerdict::Writable);
        if !verdict.is_writable() && (turning_on || reserved) {
            // 戻す（取り直しで外れた予約も戻す。`u`の前例）。
            flip(positions, !turning_on);
            if reserved {
                positions.approve.insert(key.clone());
            }
            positions.refresh_verdicts(&workspace_root, &extra_fs);
            self.status = if turning_on {
                format!(
                    "{name}: Strict にすると検査に落ちるので Strict にしません（w で作業ディレクトリを直してから、\
                     もう一度 s）。検査の理由: {}",
                    reason(&verdict)
                )
            } else {
                format!(
                    "{name}: Strict をやめると検査に落ちるのでやめません。検査の理由: {}",
                    reason(&verdict)
                )
            };
            return;
        }
        let cwd = positions.edge_cwd(&selected.position).unwrap_or_default();
        let estimated =
            !positions.cwd.contains_key(&key) && cwd_candidate(&selected.position).estimated;
        let mut status = if turning_on {
            format!(
                "{name}: Strict にします——引数を固定し、作業ディレクトリ {cwd}{} を宣言し、遷移先 {} に strict の印を\
                 付けます。呼び出し元はこの場所へ移ってから呼ぶ必要があります（w で直せます。決定67）",
                if estimated { "（推定）" } else { "" },
                selected.to
            )
        } else {
            format!(
                "{name}: Strict をやめました（普通のモード。作業ディレクトリは w で宣言したときだけ書きます）"
            )
        };
        if !reserved && verdict.is_writable() {
            status.push_str("。Space で選ぶと確定で書きます");
        }
        self.status = status;
    }

    /// `w`: 分けた行の作業ディレクトリの欄へ入る（いまの宣言か候補が入っている）。
    pub(super) fn focus_position_cwd(&mut self) {
        let Some((selected, name)) = self.fixed_row("作業ディレクトリ") else {
            return;
        };
        let candidate = cwd_candidate(&selected.position);
        let Some(positions) = self.pending.positions.as_mut() else {
            return;
        };
        let current = positions.edge_cwd(&selected.position);
        positions.editing = Some(TextInput::new(
            current.clone().unwrap_or_else(|| candidate.dir.clone()),
        ));
        positions.editing_cwd = true;
        self.status = format!(
            "{name} の作業ディレクトリを入れてください（いま: {}／候補: {}{}。Enter で決める・空のまま Enter で宣言を外す）",
            current.as_deref().unwrap_or("宣言なし（呼び出し元の場所を引き継ぐ）"),
            candidate.dir,
            if candidate.estimated { "（推定——相対パスのスクリプトなので、実際の場所はスクリプトのある所のはず）" } else { "" }
        );
    }

    /// 作業ディレクトリの欄で`Enter`。選んでいた行が書けなくなるなら変えずに理由を言う。
    pub(super) fn apply_position_cwd(&mut self) {
        let workspace_root = self.workspace_root.clone();
        let extra_fs = self.position_extra_fs();
        let selected = self.selected_position();
        let Some(positions) = self.pending.positions.as_mut() else {
            return;
        };
        let text = positions
            .editing
            .take()
            .map(|input| input.text().trim().to_string())
            .unwrap_or_default();
        positions.editing_cwd = false;
        let Some(selected) = selected else {
            return;
        };
        let name = file_name(&selected.position.exe).to_string();
        let key = key_of(&selected.position);
        let reserved = positions.approve.contains(&key);
        let previous = positions.cwd.get(&key).cloned();
        if text.is_empty() {
            positions.cwd.remove(&key);
        } else {
            positions.cwd.insert(key.clone(), text.clone());
        }
        positions.refresh_verdicts(&workspace_root, &extra_fs);
        let verdict = positions
            .verdicts
            .get(selected.index)
            .cloned()
            .unwrap_or(EdgeVerdict::Writable);
        if reserved && !verdict.is_writable() {
            match previous {
                Some(previous) => positions.cwd.insert(key.clone(), previous),
                None => positions.cwd.remove(&key),
            };
            positions.approve.insert(key);
            positions.refresh_verdicts(&workspace_root, &extra_fs);
            self.status = format!(
                "{name}: この作業ディレクトリでは検査に落ちるので変えませんでした。検査の理由: {}",
                reason(&verdict)
            );
            return;
        }
        let strict = positions.strict.contains(&key);
        let mut status = match (text.is_empty(), strict) {
            (true, true) => format!(
                "{name}: 作業ディレクトリの宣言を外しました（Strict の行なので候補 {} を書きます）",
                cwd_candidate(&selected.position).dir
            ),
            (true, false) => {
                format!("{name}: 作業ディレクトリの宣言を外しました（呼び出し元の場所を引き継ぎます）")
            }
            (false, _) => format!(
                "{name} の作業ディレクトリを {text} にしました——呼び出し元はこの場所へ移ってから呼ぶ必要があります\
                 （違う場所からは断られます。決定67(4)）"
            ),
        };
        if let Some(note) = verdict.note().filter(|_| !verdict.is_writable()) {
            status.push_str(&format!("。まだ書けません: {note}"));
        }
        self.status = status;
    }
}

#[cfg(test)]
#[path = "position_strict_tests.rs"]
mod position_strict_tests;
