//! [段階⑦] 承認待ち画面（`F2`）の遷移タブの**確定**——予約から確認ダイアログを組み立て、
//! `y`で`policy.json`と却下印（`dismissed.json`）へ書く（`plans/POLICY-EDITOR-TOMOYO-DIG.md` 決定62・63）。
//!
//! 予約を立てる・外す操作は[`super::transition`]、描画は[`super::transition_screen`]が持つ。
//! 2026-10-05に`transition.rs`から**そのまま**移した（本体が1,000行に迫ったため。
//! `plans/position-domains/P4.md`のP4.0）。
//!
//! # 書くのは位置ごとのドメインの確定と同じ部品（2026-10-05、P4.6）
//!
//! 拒否の行はその行の遷移元から辺を書く（[`super::transition`]のモジュールdoc）。遷移元の違う予約を遷移元ごとに
//! 保存すると、片方だけ書けた状態が残る。そこで確定は[`super::position_commit`]の範囲`TransitionsOnly`
//! （`crate::position_approve`が1つの`policy.json`に重ねて1回だけ保存する）を通り、ここは予約から
//! （遷移元, 辺）を組み立てる2つの関数と入口だけを持つ。位置の情報がある記録では、遷移タブの`a`も
//! `request_position_commit`（ファイルの宣言・位置の辺と一緒）へ行く。

use std::collections::BTreeSet;

use crate::transition_approve::SourcedEdgeRef;
use crate::tui::position_commit::Scope;
use crate::tui::state::App;
use crate::tui::transition::CandidateKey;

impl App {
    /// 承認・取り消し・却下の内容を組み立てて確認ダイアログを出す（**まだ書かない**）。
    pub(super) fn request_transition_commit(&mut self) {
        self.request_commit(Scope::TransitionsOnly);
    }

    /// 確認後に実際に書く（[`crate::tui::state::Confirm::Transition`]の`y`）。**入力も`plan`も作り直す**
    /// （ダイアログを見ている間に`policy.json`が別の経路で変わっていた場合に、古い読み込み結果で上書きしないため）。
    pub(crate) fn commit_transition(&mut self) {
        self.commit_scoped(Scope::TransitionsOnly);
    }

    /// 予約から、却下印へ足す／外すものを組み立てる（遷移元は予約が持つ）。
    ///
    /// **承認を予約した行に却下印があれば、それも外す。** 却下したものを選び直して許したなら、
    /// 最後の判断は「許す」であって、宣言を後で取り消したときに「却下済み」として戻ってくるのは
    /// その判断と食い違う。外すのは**いま印がある行だけ**（確認ダイアログの件数を実際に変わる数に合わせる）。
    pub(super) fn reserved_dismissals(&self) -> (BTreeSet<CandidateKey>, BTreeSet<CandidateKey>) {
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

    /// 予約から、実際に書く／消す辺を（遷移元, 辺）で組み立てる。遷移元は**その行の遷移元**（P4.6）。
    ///
    /// **予約は候補の同一性で持ち、辺はここで作る**——引数を絞るかどうかは辺の形を変えるが、
    /// ユーザーが指している行は同じだからである（[`CandidateKey`]のdoc）。遷移元が記録に無い行は承認の対象に
    /// ならない（予約できない）ので、ここにも来ない。
    pub(super) fn reserved_edges(&self) -> (Vec<SourcedEdgeRef>, Vec<SourcedEdgeRef>) {
        let approve = self
            .pending
            .observed
            .iter()
            .chain(self.pending.denied.iter())
            .filter(|c| self.pending.is_reserved(c))
            .filter_map(|c| {
                Some((
                    c.from_domain.clone()?,
                    c.approval_ref(self.pending.is_narrowed(c)),
                ))
            })
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
