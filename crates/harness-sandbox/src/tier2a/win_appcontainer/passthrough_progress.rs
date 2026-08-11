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
//! 1プロセスに1つ。`preflight`が[`begin`]で総数を宣言し、1件処理するたびに[`advance`]し、
//! 返ってきたガード（[`GrantPhase`]）を落とすとフェーズが終わる。終了後の[`snapshot`]は
//! `None`を返すので、UIは「もう付与フェーズではない」ことを別途判定しなくてよい。

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static ACTIVE: AtomicBool = AtomicBool::new(false);
static TOTAL: AtomicUsize = AtomicUsize::new(0);
static DONE: AtomicUsize = AtomicUsize::new(0);
static GRANTED: AtomicUsize = AtomicUsize::new(0);
static ALREADY: AtomicUsize = AtomicUsize::new(0);

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
    pub done: usize,
    pub total: usize,
    /// 実際にACEを書いた件数（本体内・昇格経由を問わない）。
    pub granted: usize,
    /// 既に十分なACEがあったのでWin32を1回も呼ばずに飛ばした件数。
    pub already: usize,
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
pub fn begin(total: usize) -> GrantPhase {
    TOTAL.store(total, Ordering::Relaxed);
    DONE.store(0, Ordering::Relaxed);
    GRANTED.store(0, Ordering::Relaxed);
    ALREADY.store(0, Ordering::Relaxed);
    ACTIVE.store(true, Ordering::Relaxed);
    GrantPhase
}

/// 付与フェーズが続いていることを表すガード。ドロップでフェーズが終わる。
pub struct GrantPhase;

impl Drop for GrantPhase {
    fn drop(&mut self) {
        ACTIVE.store(false, Ordering::Relaxed);
    }
}

/// 1件ぶん進める（判定に入った時点で呼ぶ）。
pub fn advance() {
    DONE.fetch_add(1, Ordering::Relaxed);
}

/// 実際にACEを書いた1件。
pub fn record_granted() {
    GRANTED.fetch_add(1, Ordering::Relaxed);
}

/// 既に十分だったので飛ばした1件。
pub fn record_already_sufficient() {
    ALREADY.fetch_add(1, Ordering::Relaxed);
}

/// いま付与フェーズなら、その進捗。そうでなければ`None`。
pub fn snapshot() -> Option<PassthroughGrantProgress> {
    if !ACTIVE.load(Ordering::Relaxed) {
        return None;
    }
    Some(PassthroughGrantProgress {
        done: DONE.load(Ordering::Relaxed),
        total: TOTAL.load(Ordering::Relaxed),
        granted: GRANTED.load(Ordering::Relaxed),
        already: ALREADY.load(Ordering::Relaxed),
    })
}

/// **フェーズが終わった後でも読める**最終値（`snapshot`は`None`になる）。
///
/// 記録が終わってから「今回は何件付けて何件飛ばしたのか」を結果として残すために要る
/// ——進捗は消えてよいが、**マシンに何をしたかの事実は消してはいけない**。
pub fn last_totals() -> PassthroughGrantProgress {
    PassthroughGrantProgress {
        done: DONE.load(Ordering::Relaxed),
        total: TOTAL.load(Ordering::Relaxed),
        granted: GRANTED.load(Ordering::Relaxed),
        already: ALREADY.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **1本のテストに畳んである。** このモジュールの状態はプロセスグローバルで、
    /// cargoは同じテストバイナリのテストを並列に走らせるので、2本に分けると互いの
    /// `begin`/`drop`を踏み合って偽陽性・偽陰性のどちらも出る。
    #[test]
    fn progress_is_visible_only_while_the_guard_is_alive() {
        assert_eq!(snapshot(), None, "before begin there is no grant phase");

        let phase = begin(3);
        assert_eq!(
            snapshot(),
            Some(PassthroughGrantProgress {
                done: 0,
                total: 3,
                granted: 0,
                already: 0
            })
        );

        // 1件は実際に書き、1件は既に十分だった、という**2回目以降で起きる形**を作る。
        advance();
        record_granted();
        advance();
        record_already_sufficient();
        assert_eq!(
            snapshot(),
            Some(PassthroughGrantProgress {
                done: 2,
                total: 3,
                granted: 1,
                already: 1
            })
        );

        drop(phase);
        // フェーズが終わっても**マシンに何をしたかの事実は読める**（結果の表示に使う）。
        assert_eq!(last_totals().granted, 1);
        assert_eq!(last_totals().already, 1);
        assert_eq!(
            snapshot(),
            None,
            "after the guard drops, the UI must stop showing a phase that already ended"
        );

        // **早期returnでもフェーズは閉じる**——ここがRAIIにしてある理由そのもの
        // （`preflight`は`?`で抜ける経路を複数持つ）。
        fn bails_out() -> Result<(), ()> {
            let _phase = begin(10);
            advance();
            Err(())
        }
        assert!(bails_out().is_err());
        assert_eq!(snapshot(), None, "an early return must still end the phase");
    }
}
