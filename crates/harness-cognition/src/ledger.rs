//! フェーズコールの本文へ載せる「台帳スライス」の供給元。`plans/PLAN-CENSUS-ENGINE.md`
//! 「継ぎ目は`PhaseRunner`の台帳依存」。HIVは[`crate::memory::WorkingMemory`]、
//! 網羅型は`CensusLedger`が実装する。
//!
//! 予算に収める縮約ループ（`Reduction::LEVELS`の走査、system/tools込みのトークン見積り）は
//! [`crate::context::ContextAssembler::assemble`]側に残る。このtraitは「1縮約段階ぶんの
//! スライスを1枚返す」ことだけに責務を絞る——ループごと実装側へ渡すと、`assemble`が
//! リクエスト全体のサイズで縮約段階を選ぶという既存の挙動を実装ごとに再現する必要が
//! 生まれ、段階1の「挙動が1バイトも変わらない」という受入条件を壊しかねないため。
//!
//! メソッド名を`render`ではなく`render_slice`にしているのは、`WorkingMemory`が既に
//! `pub fn render(&self, view: MemoryView, reduction: Reduction) -> String`という
//! 同名のinherentメソッドを持つため。Rustは同名のinherentメソッドがあるとトレイト
//! メソッドを完全に隠してしまう（呼び出しがinherent版に固定され、フォールバックしない）。

use harness_core::Phase;

use crate::memory::render::Reduction;

pub trait LedgerView: Sync {
    /// `phase`が見るべき台帳スライスを1縮約段階ぶん返す。`target`/`goal`は
    /// [`crate::memory::types::HypId::label`]／[`GoalId::label`](crate::memory::types::GoalId::label)
    /// 相当の文字列表現（実装側が必要なら`parse`で型付きIDへ戻す）。
    fn render_slice(
        &self,
        phase: Phase,
        target: Option<&str>,
        goal: Option<&str>,
        reduction: Reduction,
    ) -> String;
}
