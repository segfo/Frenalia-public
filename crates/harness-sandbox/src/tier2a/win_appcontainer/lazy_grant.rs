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

/// このレーンを**切る**ための環境変数（`0`/`false`/`off`で無効。**既定は有効**）。
///
/// # 既定になった経緯（2026-08-29）
///
/// もとは「既定オフ、`1`で有効」の実験スイッチだった。設計書§5.1.3「検証と昇格条件」が
/// 「受入を満たした時点でWindows Tier2aの既定へ上げる」と定めており、
/// **互換性の受入（同§の3「子孫到達」）が通ったので既定へ上げた**——
/// 実測は`lazy_descendant_reach_tests`が持つ（親・子・孫・32bitの孫の4段と、
/// ネイティブの再帰検索で未準備150件を全件、割り込み154件・拒否0件）。
///
/// **向きを反転させたのは、既定に上がったあとも切れる口が要るからである。** 注入が
/// 合わないツールに出くわしたとき、レーンごと止めれば従来の全walk待機へ戻れる
/// （遅くなるだけで、境界は1ビットも変わらない）。
///
/// # まだ残っている宿題（既定にしたことで消えたわけではない）
///
/// 跨プロセスの排他と、待ち時間のp95は**未測**である。前者は現在の背景ジョブと同じ
/// 危険度で、このレーンが持ち込んだものではない。
///
/// 名前が`HARNESS_TEST_`で始まらないのは、**本番の製品コードが読む**からである
/// （`DESIGN-CLI-OPTIONS.md` §9のD-86。`crates/harness-cli/tests/env_var_naming.rs`が
/// `cargo test`で検問する）。
pub(crate) const LAZY_LANE_ENV: &str = "HARNESS_TIER2A_LAZY_ACE";

/// **Redirector DLLを注入しないプロセス名の一覧**（`;`区切り、大文字小文字を無視）。
///
/// # 何のために在るのか（2つある）
///
/// 1. **緊急回避。** 注入と相性の悪いツールに出くわしたとき、そのプロセスだけ外して
///    残りはレーンに乗せられる。**外したプロセスは透過性を失うだけで、境界は変わらない**
///    （D-01。ACLの拒否はそのまま残る）。
/// 2. **フォールバックの検証。** 「注入できないプロセスはどうなるか」を実機で測るには、
///    注入できない状態を**意図的に作れる**必要がある（設計書§5.1.3の受入1が求める
///    fault injection）。実測は`lazy_uninjectable_tests`が持つ。
///
/// # 外したプロセスは、待たされるだけで失敗しない
///
/// - **最上位のシェル**を外すと、`launch`はlazyレーンを選ばず**全walkを待って**起動する。
/// - **子孫**を外すと、`CREATE_SUSPENDED`のまま**準備の完了を待ってから**動かす
///   （`harness-redirector`の`wait_then_resume`）。
///
/// 待たせ方が違うのは、**待てるのがまだ1行も実行していないプロセスだけ**だからである。
/// どちらもその条件を満たしている（起こす前／作られた直後）。
/// 実測は`lazy_uninjectable_tests`が対で持つ。
pub(crate) const NO_INJECT_ENV: &str = "HARNESS_REDIRECTOR_NO_INJECT";

/// [`NO_INJECT_ENV`]の一覧に`exe`（ファイル名でもフルパスでもよい）が入っているか。
pub(crate) fn injection_is_excluded_for(exe: &std::path::Path) -> bool {
    let Some(name) = exe.file_name().map(|n| n.to_string_lossy().to_lowercase()) else {
        return false;
    };
    std::env::var(NO_INJECT_ENV)
        .map(|list| {
            list.split(';')
                .map(|entry| entry.trim().to_lowercase())
                .any(|entry| !entry.is_empty() && entry == name)
        })
        .unwrap_or(false)
}

/// **一度でも「許可を付けられなかった」ワークスペースの一覧**（ラッチ）。
///
/// # なぜ要るのか
///
/// 走っている最中に許可を付けられなかった場合、そのコマンドはもう巻き戻せない
/// （[`super::launch`]の分岐図）。**次のコマンドまで同じ目に遭わせない**ために、
/// そのワークスペースではレーンを使うのをやめ、背景の準備が終わるまで従来どおり待つ。
///
/// これで「モデルがやり直せば必ず通る」が成り立つ。**ハーネスが勝手に実行し直すのではない**
/// ——設計書§5.1.3の「採らない方式」が、既に起きた書込や外部作用の二重化を理由に
/// 自動再実行を退けている。やり直すかどうかを決めるのはモデルで、こちらが用意するのは
/// 「次は必ず通る」という保証だけである。
///
/// # ラッチは倒したら戻さない
///
/// 一度失敗したレーンをそのセッションで信用し直す根拠が無い。プロセスが終われば消える
/// （次回起動では準備済みなのでそもそもレーンが要らない）。
static DISTRUSTED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::OnceLock::new();

fn distrusted() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    DISTRUSTED.get_or_init(Default::default)
}

/// ラッチのキー。`grant_job`のジョブ鍵と**同じ正規化**を使う（綴りの揺れで別物にならないように）。
fn latch_key(workspace: &std::path::Path, mode: &str) -> String {
    format!(
        "{}\u{0}{mode}",
        crate::tier2a::workspace_capability::workspace_key(workspace)
    )
}

/// このワークスペースでレーンを信用するのをやめる。**冪等**。
pub(crate) fn distrust_lane(workspace: &std::path::Path, mode: &str) {
    distrusted()
        .lock()
        .unwrap()
        .insert(latch_key(workspace, mode));
}

/// ラッチが倒れているか（倒れていれば、起動側はレーンを選ばず従来どおり待つ）。
pub(crate) fn lane_is_distrusted(workspace: &std::path::Path, mode: &str) -> bool {
    distrusted()
        .lock()
        .unwrap()
        .contains(&latch_key(workspace, mode))
}

/// このプロセスでlazyレーンを使ってよいか。**既定は使う。**
///
/// # 何を確かめているのか（**性能ではなく成立性**）
///
/// 1. **人が切っていないか。** 切られていれば今日までと同じ全walk待機に落ちる。
/// 2. **Redirector DLLが在るか。** 無ければ注入が必ず失敗し、毎コマンドが
///    「起動して失敗してから作り直す」という**遅くなるだけの経路**を通る。
///    在ることを先に確かめて、無ければ最初から従来経路を選ぶ。
///
/// # ここで確かめて**いない**こと（限界を同じ場所に書く）
///
/// - **子孫のうち注入できないものがあるか。** ここはプロセスを起こす前の判定なので
///   分からない。**分からなくてよい**——注入できなかった子孫は、その場で
///   準備の完了を待ってから動き出す（`lazy_uninjectable_tests`が実測を持つ）。
/// - **受付パイプが実際に開けるか。** 開くのは背景ジョブ側で、probeの時点ではまだ動いていない。
pub(crate) fn lane() -> super::grant_job::PreparationLane {
    let disabled = std::env::var(LAZY_LANE_ENV)
        .map(|v| matches!(v.trim(), "0" | "false" | "off"))
        .unwrap_or(false);
    if disabled {
        return super::grant_job::PreparationLane::FullWalk;
    }
    if super::redirector_dll_paths().is_empty() {
        return super::grant_job::PreparationLane::FullWalk;
    }
    super::grant_job::PreparationLane::Lazy
}

#[cfg(test)]
mod lane_probe_tests {
    /// **切る口が「無効を意味する綴り」だけを見ることを固定する。**
    ///
    /// 既定が有効になったので（2026-08-29）、危ないのは逆向きの取り違えである——
    /// 判定を「`1`のとき有効」のまま残すと、**環境変数が無い＝無効**になって
    /// レーンが黙って効かなくなる。だから`lane()`が見るのは**無効側の綴りだけ**であり、
    /// ここではその綴りの集合を固定する。
    ///
    /// 環境変数を触らずに測る——テストが並列に走るプロセスで`set_var`すると、
    /// 隣のテストの`lane()`の答えを変えてしまう（`B-06`: 共有物の粒度はプロセスである）。
    #[test]
    fn the_switch_only_recognises_the_spellings_that_turn_the_lane_off() {
        let off = |v: &str| matches!(v.trim(), "0" | "false" | "off");
        for v in ["0", "false", "off", " off "] {
            assert!(off(v), "{v:?} must turn the lane off");
        }
        // **有効側の綴りは判定に使わない。** 使うと「未設定＝無効」へ戻る。
        for v in ["1", "true", "on", "", "yes"] {
            assert!(!off(v), "{v:?} must NOT be read as turning the lane off");
        }
        assert_eq!(super::LAZY_LANE_ENV, "HARNESS_TIER2A_LAZY_ACE");
        assert!(
            !super::LAZY_LANE_ENV.starts_with("HARNESS_TEST_"),
            "this switch is read by production code, so it must not claim to be test-only (D-86)"
        );
    }
}
