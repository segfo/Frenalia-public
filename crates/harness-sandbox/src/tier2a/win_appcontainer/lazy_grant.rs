//! Lazy ACE fault-in（[D-88]、`plans/DESIGN-SANDBOX-APPPOLICY.md` §5.1.3）の準備器。
//!
//! # 何を直すものか
//!
//! ポリシーは「このワークスペースは許可する」と既に決めているのに、実装はその許可を物理DACLへ
//! 書き終えるまで**許可されていないかのように振る舞う**。承認済みの1ファイルを読むだけの
//! コマンドが32秒止まる（`plans/mac-spike/RESULTS.md` §S26-2）。**これは速度の改善ではなく、
//! 決めた許可と観測される振る舞いの食い違いを閉じる作業である。**
//!
//! 目標状態は「背景が終わること」ではない。ファイルがA〜Zまであり背景がAを処理している最中に
//! コマンドがZを開いたとき、**Zとその未準備の祖先だけを割り込みで先に付与し、コマンドは
//! そのまま走る**ことである。
//!
//! # なぜ既存の背景ジョブでは足りないのか（この2モジュールが在る理由）
//!
//! 既存の[`super::grant_job`]フェーズ0は、ツリー全体へ継承ACEを配る**単一のブロッキングOS
//! 呼び出し**（[`super::propagate_workspace_root_grants`]）である。**途中に高優先度の割り込みを
//! 差し込めず**、その実行中に別スレッドが同じDACLをread-modify-writeするとACEを失い得る。
//! だから「待つ条件を外す」だけでは割り込みが成立しない——**この段をincremental scannerへ
//! 置き換えることが必須**である（設計書§5.1.3「背景walkとオンデマンド付与の直列化」）。
//!
//! - [`writer`] — workspace内の**全DACL書込を1本のスレッドへ直列化**する。fault要求を高優先度、
//!   走査の要求を低優先度にし、低優先度はノード境界でyieldする。
//! - [`scanner`] — ツリーをstreaming列挙する。全パスを先に`Vec`へ集めない。
//! - [`broker`] — サンドボックスの子から「このパスを開こうとして断られた」を受け取り、
//!   **許可済みの範囲かを自分で確かめて**からwriterへ割り込みを出す。子から受け取るのは
//!   パスだけで、付与するSIDとマスクはbrokerが自分の設定から導出する。
//!
//! # ここが**やらない**こと（限界を同じ場所に書く）
//!
//! - **強制境界ではない。** 境界は引き続きAppContainer tokenとNTFS DACLである（D-01）。
//!   この準備器が1件も付与できなくても、失われるのは速さだけで、権限が広がる側へは倒れない。
//! - **既存の伝播＋救済walkを置き換えない。** レーンが継続不能になったときの戻り先として
//!   [`super::grant_job`]の3フェーズはそのまま残る（設計書「fallback controller」）。
//! - **跨プロセスの排他はしていない。** 直列化はこのプロセスの中だけである。別の`harness.exe`が
//!   同じworkspaceへ同時に書く場合の合流（writer-leader mutex）は未実装で、
//!   **これは現在の[`super::grant_job`]と同じ状態**である（あちらの排他もプロセスローカルな
//!   ジョブ一覧だけで、別プロセス同士は既に競合し得る）。悪化させてはいないが、直してもいない。
//!
//! [D-88]: `plans/DESIGN-SANDBOX-APPPOLICY.md`のD-88。**同じ番号が
//! `plans/DESIGN-CLI-OPTIONS.md` §9（環境変数の命名規則）にもある**ので、
//! 参照するときは必ず文書名を添えること。

pub(crate) mod broker;
pub(crate) mod scanner;
pub(crate) mod writer;

/// このレーンを有効にする環境変数（`1`/`true`/`on`で有効、既定は無効）。
///
/// **恒久的なユーザー設定ではない。** 設計書§5.1.3「検証と昇格条件」が
/// 「最初は実験的runtime probeの内側に置き、受入を満たした時点でWindows Tier2aの既定へ
/// 上げる」と定めており、これはその**probeの手動側**である。既定へ上がったら
/// **このノブごと消す**（増えた設定を残さないのが同節の趣旨）。
///
/// 名前が`HARNESS_TEST_`で始まらないのは、**本番の製品コードが読む**からである
/// （`DESIGN-CLI-OPTIONS.md` §9のD-86。`crates/harness-cli/tests/env_var_naming.rs`が
/// `cargo test`で検問する）。
pub(crate) const LAZY_LANE_ENV: &str = "HARNESS_TIER2A_LAZY_ACE";

/// このプロセスでlazyレーンを使ってよいか。
///
/// # 何を確かめているのか（**性能ではなく成立性**）
///
/// 1. **人が有効にしたか。** 既定は無効で、今日と同じ全walk待機に落ちる。
/// 2. **Redirector DLLが在るか。** 無ければ注入が必ず失敗し、毎コマンドが
///    「起動して失敗してから作り直す」という**遅くなるだけの経路**を通る。
///    在ることを先に確かめて、無ければ最初から従来経路を選ぶ。
///
/// # ここで確かめて**いない**こと（限界を同じ場所に書く）
///
/// - **子のアーキテクチャ**（x86/ARM64への注入可否）。resume前に失敗すれば
///   `launch`が1回だけ通常起動へ落とすので、**正しさの側は保たれる**が、
///   その1回ぶんは遅い。設計書の受入3（子孫到達）で測るまでは、ここは粗いままにしておく。
/// - **受付パイプが実際に開けるか。** 開くのは背景ジョブ側で、probeの時点ではまだ動いていない。
pub(crate) fn lane() -> super::grant_job::PreparationLane {
    let enabled = std::env::var(LAZY_LANE_ENV)
        .map(|v| matches!(v.trim(), "1" | "true" | "on"))
        .unwrap_or(false);
    if !enabled {
        return super::grant_job::PreparationLane::FullWalk;
    }
    if super::redirector_dll_paths().is_empty() {
        return super::grant_job::PreparationLane::FullWalk;
    }
    super::grant_job::PreparationLane::Lazy
}

#[cfg(test)]
mod lane_probe_tests {
    /// **既定は今日と同じ経路である。** ここが逆になると、受入を満たす前に
    /// 全ユーザーが実験レーンへ乗る。
    ///
    /// 環境変数を触らずに測る——テストが並列に走るプロセスで`set_var`すると、
    /// 隣のテストの`lane()`の答えを変えてしまう（`B-06`: 共有物の粒度はプロセスである）。
    #[test]
    fn the_lane_is_opt_in_and_its_switch_is_a_production_env_var() {
        assert_eq!(super::LAZY_LANE_ENV, "HARNESS_TIER2A_LAZY_ACE");
        assert!(
            !super::LAZY_LANE_ENV.starts_with("HARNESS_TEST_"),
            "this switch is read by production code, so it must not claim to be test-only (D-86)"
        );
    }
}
