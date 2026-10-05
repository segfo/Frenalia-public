//! [段階⑦] 承認待ち画面（`F2`）の遷移タブの**確定**——予約から確認ダイアログを組み立て、
//! `y`で`policy.json`と却下印（`dismissed.json`）へ書く（`plans/POLICY-EDITOR-TOMOYO-DIG.md` 決定62・63）。
//!
//! 予約を立てる・外す操作は[`super::transition`]、描画は[`super::transition_screen`]が持つ。
//! 2026-10-05に`transition.rs`から**そのまま**移した（本体が1,000行に迫ったため。
//! `plans/position-domains/P4.md`のP4.0。振る舞いは変えていない）。

use std::collections::BTreeSet;

use harness_policy::policy_file::{self, ENTRY_DOMAIN};

use crate::transition_approve::{self, EdgeRef, TransitionRequest};
use crate::transition_candidates::Startable;
use crate::tui::state::{App, Confirm, Modal};
use crate::tui::transition::CandidateKey;
use crate::tui::transition_dismissed;

impl App {
    /// 承認・取り消し・却下の内容を組み立てて確認ダイアログを出す（**まだ書かない**）。
    pub(super) fn request_transition_commit(&mut self) {
        let (approve, remove) = self.reserved_edges();
        let (dismiss, undismiss) = self.reserved_dismissals();
        let has_policy = !approve.is_empty() || !remove.is_empty();
        let has_dismissals = !dismiss.is_empty() || !undismiss.is_empty();
        if !has_policy && !has_dismissals {
            self.status = "Spaceで選ぶか x で却下してから a を押してください\
                           （選んだものが1件もありません）"
                .to_string();
            return;
        }
        // **却下印が読めないなら、ここで止める**（何も書かない。`transition_approve`の
        // 「部分適用しない」と同じ判断）。承認だけを書きたいなら、却下の予約を外せば通る。
        if has_dismissals {
            if let Err(e) = transition_dismissed::load(&self.workspace_root) {
                self.modal = Some(Modal {
                    title: "却下印を書けません（何も書いていません）".to_string(),
                    lines: vec![
                        e.to_string(),
                        String::new(),
                        "壊れたファイルは上書きしません。直すか消すと保存できます。".to_string(),
                        "承認・取り消しだけを書くなら、x で却下の予約を外してください。"
                            .to_string(),
                    ],
                    confirm: Confirm::ReadOnly,
                });
                return;
            }
        }

        let mut lines = Vec::new();
        let mut count = 0usize;
        if has_policy {
            let Some(to_domain) = self.destination_for_commit(!approve.is_empty()) else {
                return;
            };
            let Some(policy_lines) =
                self.transition_plan_lines(&approve, &remove, &to_domain, &mut count)
            else {
                return;
            };
            lines.extend(policy_lines);
        }
        if has_dismissals {
            if !lines.is_empty() {
                lines.push(String::new());
            }
            lines.extend(transition_dismissed::confirmation_lines(
                &self.workspace_root,
                ENTRY_DOMAIN,
                &dismiss,
                &undismiss,
            ));
            count += dismiss.len() + undismiss.len();
        }

        self.modal = Some(Modal {
            title: format!("この{count}件を書きますか？"),
            lines,
            confirm: Confirm::Transition,
        });
        self.modal_scroll = 0;
    }

    /// `policy.json`へ書く分の明細。**書けないならダイアログを出して`None`**（何も書かない）。
    fn transition_plan_lines(
        &mut self,
        approve: &[EdgeRef],
        remove: &[EdgeRef],
        to_domain: &str,
        count: &mut usize,
    ) -> Option<Vec<String>> {
        let request = TransitionRequest {
            workspace_root: &self.workspace_root,
            from_domain: ENTRY_DOMAIN,
            to_domain,
            approve,
            remove,
            record_session: None,
            now_unix_ms: now_unix_ms(),
        };
        let plan = match transition_approve::plan(&request) {
            Ok(plan) => plan,
            Err(e) => {
                self.modal = Some(Modal {
                    title: "書けません（何も書いていません）".to_string(),
                    lines: e.to_string().lines().map(str::to_string).collect(),
                    confirm: Confirm::ReadOnly,
                });
                return None;
            }
        };
        *count += plan.added.len() + plan.removed.len();

        let mut lines = vec![
            format!("{}:", policy_file::path(&self.workspace_root).display()),
            format!("遷移元ドメイン: {ENTRY_DOMAIN}"),
        ];
        if !plan.added.is_empty() {
            lines.push(format!("遷移先ドメイン: {}", plan.to_domain));
        }
        lines.push(String::new());
        if !plan.added.is_empty() {
            lines.push(format!("許す遷移 {}件:", plan.added.len()));
            for edge in &plan.added {
                lines.push(format!(
                    "  + {} {} → {}",
                    edge.exe,
                    edge.argv.display(),
                    plan.to_domain
                ));
                // **書く直前に、その綴りが起こせないことを言う。**
                // 一覧でも出しているが、ここは**取り消しの効かない操作の直前**なので繰り返す。
                if let Some(note) = Startable::of(&edge.exe).note() {
                    lines.push(format!("      ⚠ {note}"));
                }
            }
        }
        if !plan.removed.is_empty() {
            lines.push(format!("取り消す遷移 {}件:", plan.removed.len()));
            for edge in &plan.removed {
                lines.push(format!("  - {} {}", edge.exe, edge.argv.display()));
            }
        }
        if !plan.already_declared.is_empty() {
            lines.push(format!(
                "既に宣言されていて増えないもの: {}件",
                plan.already_declared.len()
            ));
        }
        if !plan.not_found.is_empty() {
            lines.push(format!(
                "宣言に無くて消えないもの: {}件",
                plan.not_found.len()
            ));
        }
        lines.push(String::new());
        // 文言の持ち主は`transition_approve`（表示側で書き写さない、`B-05`）。
        lines.extend(transition_approve::ACE_NOTICE.lines().map(str::to_string));
        if !plan.added.is_empty() {
            // 遷移先を`harness.exe`が用意する見込み（用意されないなら⚠で。書くかはユーザーが決める）。
            lines.push(String::new());
            lines.extend(self.destination_notice_lines(&plan));
        }
        Some(lines)
    }

    /// 確認後に実際に書く。
    ///
    /// **`plan`は作り直す**——ダイアログを見ている間に`policy.json`が別の経路
    /// （CLI・手編集）で変わっていた場合に、古い読み込み結果で上書きしないため
    /// （候補画面・宣言画面と同じ作法）。却下印も同じで、**画面が持っている一覧ではなく、
    /// 書く直前に読み直したファイルへ予約の差分を当てる**（[`transition_dismissed::update`]）。
    ///
    /// # 書く順序
    ///
    /// (1) 却下印が読めるかを確かめる → (2) `policy.json` → (3) 却下印。
    /// 2つのファイルを1回で不可分には書けないので、**落ちやすい方を先に確かめて、
    /// 書く前に落ちれば何も書いていない**形にする。(3)だけが落ちたときは、`policy.json`は
    /// 書けたことと、却下の予約が残っていることを言う（黙って片方だけ書いたことにしない、`B-09`）。
    pub(crate) fn commit_transition(&mut self) {
        let (approve, remove) = self.reserved_edges();
        let (dismiss, undismiss) = self.reserved_dismissals();
        let has_policy = !approve.is_empty() || !remove.is_empty();
        let has_dismissals = !dismiss.is_empty() || !undismiss.is_empty();

        if has_dismissals {
            if let Err(e) = transition_dismissed::load(&self.workspace_root) {
                self.status = format!("却下印を書けませんでした（何も書いていません）: {e}");
                return;
            }
        }

        let mut done: Vec<String> = Vec::new();
        if has_policy {
            let Some(to_domain) = self.destination_for_commit(!approve.is_empty()) else {
                return;
            };
            let request = TransitionRequest {
                workspace_root: &self.workspace_root,
                from_domain: ENTRY_DOMAIN,
                to_domain: &to_domain,
                approve: &approve,
                remove: &remove,
                record_session: None,
                now_unix_ms: now_unix_ms(),
            };
            let plan = match transition_approve::plan(&request) {
                Ok(plan) => plan,
                Err(e) => {
                    self.status = format!("書けませんでした（何も書いていません）: {e}");
                    return;
                }
            };
            match transition_approve::commit(&self.workspace_root, &plan) {
                Ok(true) => done.push(format!(
                    "遷移の宣言を更新しました（許可 {}件 → {} / 取り消し {}件。ACLはいま変わりません）",
                    plan.added.len(),
                    plan.to_domain,
                    plan.removed.len()
                )),
                Ok(false) => done.push(
                    "変わるものがありませんでした（policy.jsonは書いていません）".to_string(),
                ),
                Err(e) => {
                    self.status =
                        format!("policy.jsonを書けませんでした（何も書いていません）: {e}");
                    return;
                }
            }
            self.pending.approve.clear();
            self.pending.narrow.clear();
            self.pending.remove.clear();
        }

        if has_dismissals {
            match transition_dismissed::update(
                &self.workspace_root,
                ENTRY_DOMAIN,
                &dismiss,
                &undismiss,
                now_unix_ms(),
            ) {
                Ok(applied) => {
                    done.push(if applied.wrote {
                        format!(
                            "却下 {}件 / 却下の取り消し {}件を保存しました\
                             （表示だけの印です。policy.jsonとACLは変わりません）",
                            applied.added, applied.removed
                        )
                    } else {
                        "却下印は変わりませんでした（別のエディタが先に同じ操作をしていました）"
                            .to_string()
                    });
                    self.pending.dismiss.clear();
                    self.pending.undismiss.clear();
                }
                // **予約は残す**——もう一度 a を押せば同じものを書きに行ける。
                Err(e) => done.push(format!(
                    "却下印は書けませんでした（却下の予約は残してあります）: {e}"
                )),
            }
        }

        self.status = done.join("。");
        self.reload_transitions();
    }

    /// 予約から、却下印へ足す／外すものを組み立てる。
    ///
    /// **承認を予約した行に却下印があれば、それも外す。** 却下したものを選び直して許したなら、
    /// 最後の判断は「許す」であって、宣言を後で取り消したときに「却下済み」として戻ってくるのは
    /// その判断と食い違う。外すのは**いま印がある行だけ**（確認ダイアログの件数を実際に変わる数に合わせる）。
    fn reserved_dismissals(&self) -> (BTreeSet<CandidateKey>, BTreeSet<CandidateKey>) {
        let dismiss = self.pending.dismiss.clone();
        let mut undismiss = self.pending.undismiss.clone();
        undismiss.extend(
            self.pending
                .observed
                .iter()
                .chain(self.pending.denied.iter())
                .filter(|c| self.pending.is_reserved(c) && self.pending.is_dismissed(c))
                .map(CandidateKey::of),
        );
        (dismiss, undismiss)
    }

    /// 予約から、実際に書く／消す辺を組み立てる。
    ///
    /// **予約は候補の同一性で持ち、辺はここで作る**——引数を絞るかどうかは辺の形を変えるが、
    /// ユーザーが指している行は同じだからである（[`CandidateKey`]のdoc）。
    fn reserved_edges(&self) -> (Vec<EdgeRef>, Vec<EdgeRef>) {
        let approve = self
            .pending
            .observed
            .iter()
            .chain(self.pending.denied.iter())
            .filter(|c| self.pending.is_reserved(c))
            .map(|c| c.approval_ref(self.pending.is_narrowed(c)))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let remove = self.pending.remove.iter().cloned().collect();
        (approve, remove)
    }
}

/// 承認に添える時刻。**測定にも判定にも使わない**（由来の記録だけ）。宣言画面の遷移タブの取り消しも使う。
pub(super) fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
