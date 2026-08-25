//! fs passthrough（D-13）付与の進捗を、**同期区間の中から**UIへ届けるための唯一の口。
//!
//! # なぜイベントではなくプロセスグローバルなのか
//!
//! 付与は`preflight`の中で同期的に回る。`preflight`を呼ぶのは`select_tier`で、そこへ
//! 進捗コールバックを足すと引数が9個になり、呼び出し元5箇所すべてを触ることになる
//! （`select_tier`は既に`#[allow(clippy::too_many_arguments)]`が付いている）。
//! **同じ問題を`grant_job`が先に解いていて**、あちらは`grant_job::progress()`という
//! プロセスグローバルなスナップショットをUIが毎ティック読む形にしている（BUG-082の
//! フォローアップ）。ここも同じ形に揃える——待ち時間の見せ方を機構ごとに別設計にしない。
//!
//! # 何を防いでいるか
//!
//! これが無いと、UIは「ACE付与 0/668」を最後まで0のまま出し続ける——`preflight`が返って
//! から`PassthroughGranted`が668件まとめて発火するので、カウンタは終わった瞬間に
//! 668/668へ飛ぶ。**動かないカウンタは、出さないより悪い**（B-23(a)・B-32）:
//! ユーザーは「1件目で固まった」と読み、実際にそう読まれた。
//!
//! # 寿命
//!
//! 1プロセスに1つ。`preflight`が[`ProgressCell::begin`]で総数を宣言し、1件処理するたびに
//! [`ProgressCell::advance`]し、返ってきたガード（[`GrantPhase`]）を落とすとフェーズが終わる。
//! 終了後の[`ProgressCell::snapshot`]は`None`を返すので、UIは「もう付与フェーズではない」ことを
//! 別途判定しなくてよい。
//!
//! # なぜ「セル」が値で、グローバルが1つだけなのか（[BUG-138](../../../../../docs/bugs/BUG-138.md)）
//!
//! 以前はここが`static`の羅列で、**モジュール名を書けばどこからでも触れた**。
//! 製品では書き手も読み手も1つずつなので正しく動くが、**テストバイナリは同じプロセスで
//! 何本ものテストを並行に走らせる**ので、あるテストが「まだフェーズは立っていないはず」と
//! 断言している最中に、別のテストが製品コード経由でフェーズを立てた。
//! そのテストには「このモジュールのテストは1本に畳んである」という対策が書かれていたが、
//! **対策が覆っていたのは同じモジュールのテストだけ**で、`grant_audit::probe_all`を通る
//! 他モジュールのテストは覆っていなかった（B-06: 対策の覆う範囲を数える）。
//!
//! 直し方は「触るテストを全部数えてロックを配る」ではなく、**数えなくてよくすること**にした。
//! セルを値（[`ProgressCell`]）にしたので、**断言するテストは自分のセルを持てる**。
//! 共有したいときは[`global`]と明示的に書くしかない——暗黙に共有へ落ちる経路が無い。
//!
//! **この形が守らないもの**: [`global`]のセル自体は排他されない。並行に書く者が居ても、
//! **その値を根拠に合否を決める者が居なければ**症状にならない、というのが成立の理由である。
//! 将来「[`global`]を読んで断言する」テストが書かれたら同じ壊れ方が戻るが、
//! それをコンパイル時に落とす手段は無い。担保は`rg "passthrough_progress::global\(\)"`で
//! **数えられる**ところまでである。現在の呼び出し元は次の4つで、うち3つが製品。
//!
//! | 呼び出し元 | 何者か |
//! |---|---|
//! | `preflight` | 付与フェーズの生産側 |
//! | `grant_audit::probe_all` | 自己検証フェーズの生産側 |
//! | ポリシーエディタの`RunState::new` | 消費側（UIが毎ティック読む） |
//! | このモジュールの`a_phase_on_another_cell_...` | **書くだけで、値をassertしない**（下記） |

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// このセルがいま何の進捗を運んでいるか。
///
/// **消費側（TUI）はこれを見て表示を選ぶ。** 以前は「内訳を出すかどうか」から付与か否かを
/// 推測していたが、フェーズが増えた時点でその推測は成立しない——何のフェーズかは
/// 生産側だけが知っている事実なので、推測させずに運ぶ（B-32）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// fs passthroughのACE付与。
    Grant = 0,
    /// 付与したACEが台帳に載っているかの自己検証（`tier2a::grant_audit`、BUG-101）。
    Audit = 1,
}

impl Phase {
    fn from_usize(value: usize) -> Self {
        match value {
            1 => Phase::Audit,
            _ => Phase::Grant,
        }
    }
}

/// 付与フェーズの進捗。`done`は**判定が終わった件数**（付与した・既に十分だった・
/// 昇格へ回した、のいずれか）で、成功件数ではない——止まって見える時間の内訳を
/// 出すのが目的なので、「何件目を処理しているか」の方が意味を持つ。
///
/// # `granted`と`already`を分けて出す理由
///
/// 分けないと、**2回目以降の実行で「ACE付与 668/668」と出る**。実際には1件もACEを書いて
/// おらず全部`already_sufficient`のスキップなのに、表示は1回目と区別が付かない
/// ——「毎回ACEを付け直している（差分適用になっていない）」と読まれる。実際にそう読まれた。
///
/// D-37の穴はセッション（＝プロセス）の寿命で持つので、同じプロセスの2回目は
/// **`already`だけが増えて`granted`は0のまま**になるはずである。そうなっていなければ、
/// それは表示の問題ではなく`already_sufficient`の判定が効いていないという別の欠陥で、
/// **この2つの数を並べて初めてどちらなのかが言える**。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassthroughGrantProgress {
    /// 何の進捗か。**内訳の有無から推測させない**（[`Phase`]のdoc参照）。
    pub phase: Phase,
    pub done: usize,
    pub total: usize,
    /// 実際にACEを書いた件数（本体内・昇格経由を問わない）。`Audit`フェーズでは常に0。
    pub granted: usize,
    /// 既に十分なACEがあったのでWin32を1回も呼ばずに飛ばした件数。`Audit`フェーズでは常に0。
    pub already: usize,
}

/// 進捗を運ぶセル1つぶん。
///
/// **製品は[`global`]の1つだけを使う。** 値にしてあるのは、断言するテストが
/// 自分のセルを持てるようにするため（モジュールdocの BUG-138 節）。
pub struct ProgressCell {
    active: AtomicBool,
    total: AtomicUsize,
    done: AtomicUsize,
    granted: AtomicUsize,
    already: AtomicUsize,
    /// [`Phase`]の判別子。`AtomicBool`ではなく`usize`にしてあるのは、フェーズが3つ目に
    /// なったときに型だけ増やせばよくするため。
    phase: AtomicUsize,
    /// 自己検証フェーズの進捗。**付与フェーズのカウンタとは別に持つ**——同じ変数を使い回すと、
    /// 付与の後に走る自己検証が[`ProgressCell::last_totals`]（＝「今回は何件付けて何件飛ばしたか」を
    /// 実行後に表示するための値）を0で塗り潰す。**進捗は消えてよいが、マシンに何をしたかの
    /// 事実は消してはいけない**（この型のdocが元々宣言している不変条件）。
    audit_total: AtomicUsize,
    audit_done: AtomicUsize,
}

impl Default for ProgressCell {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressCell {
    /// **`const`であることが要点。** テストが関数内`static`やローカル変数として
    /// 自分のセルを持てる（`Box::leak`も`Arc`も要らない）。
    pub const fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            total: AtomicUsize::new(0),
            done: AtomicUsize::new(0),
            granted: AtomicUsize::new(0),
            already: AtomicUsize::new(0),
            phase: AtomicUsize::new(Phase::Grant as usize),
            audit_total: AtomicUsize::new(0),
            audit_done: AtomicUsize::new(0),
        }
    }

    /// 付与フェーズを開始する（総数を宣言する）。**返り値を捨てないこと**——
    /// ドロップした瞬間にフェーズが終わる。
    ///
    /// フェーズの終了をRAIIにしているのは、`preflight`が`?`で早期returnする経路を複数持つため。
    /// 終了を手で書くと、脱出経路が1つ増えるたびに書き忘れる形になり、UIは終わった
    /// フェーズの進捗を出し続ける（付与と撤収の対称性、B-01）。
    ///
    /// **生産側は`preflight`だけが呼ぶ**。`pub`なのは、消費側（ポリシーエディタのTUI）が
    /// 別クレートに居て、その回帰テストが生産側を動かせないと「付与中にカウンタが動く」ことを
    /// 固定できないため——固定できないなら、また0のまま張り付いても誰も気付かない。
    /// 誤って呼ばれても影響は表示カウンタだけで、境界にも権限にも関係しない。
    #[must_use = "the grant phase ends when this guard is dropped"]
    pub fn begin(&self, total: usize) -> GrantPhase<'_> {
        self.begin_phase(Phase::Grant, total)
    }

    /// 自己検証フェーズ（`tier2a::grant_audit`）を開始する。
    ///
    /// **同じセルを使い回す**——待ち時間の見せ方を機構ごとに別設計にしない
    /// （`docs/CODE-STRUCTURE-RULES.md`§5.1。付与にゲージがあるのに検証は無言、を作らない）。
    /// 自己検証は付与の**後**に走るので、付与フェーズと同時に立つことはない。
    #[must_use = "the audit phase ends when this guard is dropped"]
    pub fn begin_audit(&self, total: usize) -> GrantPhase<'_> {
        self.begin_phase(Phase::Audit, total)
    }

    fn begin_phase(&self, phase: Phase, total: usize) -> GrantPhase<'_> {
        match phase {
            Phase::Grant => {
                self.total.store(total, Ordering::Relaxed);
                self.done.store(0, Ordering::Relaxed);
                self.granted.store(0, Ordering::Relaxed);
                self.already.store(0, Ordering::Relaxed);
            }
            // **付与のカウンタには触らない**（`audit_*`のdoc参照）。自己検証は付与の後に走るので、
            // ここで0を書くと`last_totals`が「今回は0件付けた」と嘘をつく。
            Phase::Audit => {
                self.audit_total.store(total, Ordering::Relaxed);
                self.audit_done.store(0, Ordering::Relaxed);
            }
        }
        self.phase.store(phase as usize, Ordering::Relaxed);
        self.active.store(true, Ordering::Relaxed);
        GrantPhase { cell: self }
    }

    /// 1件ぶん進める（判定に入った時点で呼ぶ）。**いま立っているフェーズのカウンタを進める。**
    pub fn advance(&self) {
        match Phase::from_usize(self.phase.load(Ordering::Relaxed)) {
            Phase::Grant => self.done.fetch_add(1, Ordering::Relaxed),
            Phase::Audit => self.audit_done.fetch_add(1, Ordering::Relaxed),
        };
    }

    /// 実際にACEを書いた1件。
    pub fn record_granted(&self) {
        self.granted.fetch_add(1, Ordering::Relaxed);
    }

    /// 既に十分だったので飛ばした1件。
    pub fn record_already_sufficient(&self) {
        self.already.fetch_add(1, Ordering::Relaxed);
    }

    /// いま付与フェーズなら、その進捗。そうでなければ`None`。
    pub fn snapshot(&self) -> Option<PassthroughGrantProgress> {
        if !self.active.load(Ordering::Relaxed) {
            return None;
        }
        let phase = Phase::from_usize(self.phase.load(Ordering::Relaxed));
        Some(match phase {
            Phase::Grant => self.last_totals(),
            Phase::Audit => PassthroughGrantProgress {
                phase,
                done: self.audit_done.load(Ordering::Relaxed),
                total: self.audit_total.load(Ordering::Relaxed),
                // 自己検証は1件も付与しない（読むだけ）。内訳を出す相手が無い。
                granted: 0,
                already: 0,
            },
        })
    }

    /// **フェーズが終わった後でも読める**最終値（`snapshot`は`None`になる）。
    ///
    /// 記録が終わってから「今回は何件付けて何件飛ばしたのか」を結果として残すために要る
    /// ——進捗は消えてよいが、**マシンに何をしたかの事実は消してはいけない**。
    ///
    /// 返すのは常に**付与フェーズ**の値である（自己検証は1件も付与しないので、ここへ混ぜると
    /// 「マシンに何をしたか」が薄まる）。
    pub fn last_totals(&self) -> PassthroughGrantProgress {
        PassthroughGrantProgress {
            phase: Phase::Grant,
            done: self.done.load(Ordering::Relaxed),
            total: self.total.load(Ordering::Relaxed),
            granted: self.granted.load(Ordering::Relaxed),
            already: self.already.load(Ordering::Relaxed),
        }
    }
}

/// 製品が使う唯一のセル。
static GLOBAL: ProgressCell = ProgressCell::new();

/// 製品の配線点。**ここを名指しするのは「共有を選ぶ」という意味**なので、
/// 呼び出し元は数えられる数に保つこと（現在は`preflight`・`grant_audit::probe_all`・
/// `RunState::new`の3箇所。モジュールdocの BUG-138 節）。
pub fn global() -> &'static ProgressCell {
    &GLOBAL
}

/// 付与フェーズが続いていることを表すガード。ドロップでフェーズが終わる。
pub struct GrantPhase<'a> {
    cell: &'a ProgressCell,
}

impl Drop for GrantPhase<'_> {
    fn drop(&mut self) {
        self.cell.active.store(false, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **自分のセルで測る。** 以前はプロセスグローバルの`static`を直に触っていたため、
    /// 同じテストバイナリの別のテスト（製品コード`grant_audit::probe_all`経由で
    /// 自己検証フェーズを立てる）と踏み合って不定期に落ちた（BUG-138）。
    #[test]
    fn progress_is_visible_only_while_the_guard_is_alive() {
        let cell = ProgressCell::new();
        assert_eq!(cell.snapshot(), None, "before begin there is no grant phase");

        let phase = cell.begin(3);
        assert_eq!(
            cell.snapshot(),
            Some(PassthroughGrantProgress {
                phase: Phase::Grant,
                done: 0,
                total: 3,
                granted: 0,
                already: 0
            })
        );

        // 1件は実際に書き、1件は既に十分だった、という**2回目以降で起きる形**を作る。
        cell.advance();
        cell.record_granted();
        cell.advance();
        cell.record_already_sufficient();
        assert_eq!(
            cell.snapshot(),
            Some(PassthroughGrantProgress {
                phase: Phase::Grant,
                done: 2,
                total: 3,
                granted: 1,
                already: 1
            })
        );

        drop(phase);
        // フェーズが終わっても**マシンに何をしたかの事実は読める**（結果の表示に使う）。
        assert_eq!(cell.last_totals().granted, 1);
        assert_eq!(cell.last_totals().already, 1);
        assert_eq!(
            cell.snapshot(),
            None,
            "after the guard drops, the UI must stop showing a phase that already ended"
        );

        // **自己検証フェーズは付与の後に走る**（BUG-101の計装）。別のフェーズとして見え、
        // かつ**付与の実績を塗り潰さない**——ここを共有カウンタにすると、実行後の
        // 「今回は何件付けたか」が0件になる（マシンに何をしたかの事実が消える）。
        let audit = cell.begin_audit(2);
        cell.advance();
        assert_eq!(
            cell.snapshot(),
            Some(PassthroughGrantProgress {
                phase: Phase::Audit,
                done: 1,
                total: 2,
                granted: 0,
                already: 0
            })
        );
        assert_eq!(
            cell.last_totals().granted,
            1,
            "自己検証が付与の実績を上書きしてはいけない"
        );
        assert_eq!(cell.last_totals().phase, Phase::Grant);
        drop(audit);
        assert_eq!(cell.snapshot(), None);

        // **早期returnでもフェーズは閉じる**——ここがRAIIにしてある理由そのもの
        // （`preflight`は`?`で抜ける経路を複数持つ）。
        fn bails_out(cell: &ProgressCell) -> Result<(), ()> {
            let _phase = cell.begin(10);
            cell.advance();
            Err(())
        }
        assert!(bails_out(&cell).is_err());
        assert_eq!(
            cell.snapshot(),
            None,
            "an early return must still end the phase"
        );
    }

    /// **BUG-138の歯**（B-27）: 誰かがフェーズを立てていても、自分のセルには見えないこと。
    ///
    /// 落ちた実物は「まだ何も始まっていないはず」と断言した`snapshot() == None`で、
    /// そこへ`grant_audit::probe_all`が候補1件で立てた`Phase::Audit, 1/1`が見えていた。
    /// ここではその状況を**わざと作って**、隔離が効いていることを固定する。
    /// セルを値にする変更を戻すと、このテストはコンパイルできなくなる＝歯がある。
    ///
    /// **共有セル（[`global`]）の値そのものはassertしない。** それを合否の根拠にすることが
    /// BUG-138 そのものだからで、同じテストバイナリの他のテストがいま並行に書いている。
    /// 「フェーズが立っていれば確かに見える」という対照は、**別のローカルなセル**で取る
    /// ——こちらは誰とも共有していないので決定論的に測れる（空振り緑を避ける、B-35）。
    #[test]
    fn a_phase_on_another_cell_is_invisible_to_a_cell_of_our_own() {
        let mine = ProgressCell::new();

        // 対照: 立てた側では確かに見える。
        let theirs = ProgressCell::new();
        let their_phase = theirs.begin_audit(1);
        theirs.advance();
        assert_eq!(
            theirs.snapshot().map(|p| (p.phase, p.done, p.total)),
            Some((Phase::Audit, 1, 1)),
            "立てた側で見えないなら、この測定は何も確かめていない"
        );
        assert_eq!(
            mine.snapshot(),
            None,
            "他のセルのフェーズが自分のセルへ漏れてはいけない（BUG-138）"
        );
        drop(their_phase);

        // 製品が使う共有セルへ実際に書いても、自分のセルは動かない
        // （落ちた実物と同じ経路。**共有セル側は読まない**）。
        let global_phase = global().begin_audit(1);
        global().advance();
        assert_eq!(
            mine.snapshot(),
            None,
            "共有セルへの書き込みが自分のセルへ漏れてはいけない（BUG-138）"
        );
        drop(global_phase);
    }
}
