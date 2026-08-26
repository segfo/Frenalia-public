//! **部分木を覆う対象から外すと、その費用は本当に消えるのか**
//! （[`plans/HANDOFF-FS-BOUNDARY-STATIC-ACE.md`](../../../../../plans/HANDOFF-FS-BOUNDARY-STATIC-ACE.md)
//! の逃げ道E「覆う範囲を狭める」の実体）。
//!
//! # なぜ測るのか
//!
//! これまでの測定はワークスペースを**分解できない一塊**として扱ってきた。分解すると、
//! このリポジトリでは**ファイルの96.1%が`target/`（ビルド生成物）**である
//! （180,848 / 188,097。`.git/`が5,845、ソースとその他すべてで1,404）。
//!
//! 費用がノード数に線形で（§S10-1、59.9〜62.0 µs/ノード）、深さの効きが小さい
//! （§S15-2、2段→129段で+14.6%）ことは既に実測されている。**したがって
//! 「費用の96%が`target/`である」は、新しく測らなくても既存の測定から導ける。**
//!
//! **導けないのは次の1点だけで、ここだけを測る。**
//!
//! > **部分木の継承を切って救済walkから外すと、その部分木ぶんの時間が実際に消えるのか。**
//!
//! 消えない可能性は2つある。**どちらも実装の構造から来る、もっともらしい疑い**である。
//!
//! 1. **伝播（OSによる継承の物理コピー）が保護で止まらないかもしれない。**
//!    止まることは`.harness/`について実機で確認されている（[BUG-083](../../../../docs/bugs/BUG-083.md)）が、
//!    あれは**小さな部分木**での確認で、時間として意味のある差になるかは別の事実である。
//! 2. **救済walkは`skip`配下も列挙する。** [`super::fix_descendants_missing_ace`]は
//!    先に[`super::acl_grant::collect_dirs_and_files`]でツリー全体を集めてから
//!    `is_skipped`で振り分けるので、**ディレクトリ走査の費用は`skip`しても払う**。
//!    省けるのはノードごとのDACL読取だけである。
//!
//! # 測り方（**対照を必ず取る**、`bug-pattern-rules` B-35）
//!
//! 実リポジトリの比率を写した木を2本作り、**除外する／しない**だけを変えて対にする。
//!
//! | 腕 | 何をするか |
//! |---|---|
//! | **A（対照＝いまの挙動）** | root へ継承ACE → 伝播 → 救済walk（`skip`なし） |
//! | **B（案a＝除外＋保護）** | `bulk/`を**1ノードだけ**保護して継承を切る → root へ継承ACE → 伝播 → 救済walk（`skip=[bulk]`） |
//!
//! **保護するのは部分木のrootだけである。** 姉妹の
//! [`super::protect_harness_control_dir_from_appcontainer`]は部分木を再帰的に保護するが、
//! それはO(ノード数)なので**測りたいものを自分で潰してしまう**（`.harness/`が小さいから
//! 成立している形である）。継承を止めるだけなら1ノードで足りる。
//!
//! # 結論を書く前に確かめること
//!
//! 時間が減ったことだけでは**「除外が効いた」と「そもそも何も配れていない」を区別できない**。
//! だから腕Bでは次の3つを実効で見る。
//!
//! - `rest/`の葉に**マスクが載っている**（陽性対照。ここが偽なら腕B全体が無意味）
//! - `bulk/`の葉に**マスクが載っていない**（除外の意図した帰結＝**これが案aの代償**）
//! - walkの`skipped`が`bulk/`のノード数と一致する（数えた対象が想定どおりか）
//!
//! # 実行
//!
//! **昇格しない。** ACEを書くのはテスト自身が作ったツリーだけで、主体は
//! `capability_sid_from_name`（純粋導出）＝台帳にもプロファイルにも何も残さない。
//!
//! ```text
//! HARNESS_SUBTREE_COST_NODES=100000 cargo test -p harness-sandbox --lib -- \
//!     --ignored --test-threads=1 --nocapture subtree_exclusion_cost
//! ```
//!
//! **判定が出たら本ファイルは削除する**（`docs/CODE-STRUCTURE-RULES.md`規則2）。

use std::path::Path;
use std::time::Instant;

use super::test_support::{build_wide_tree, TestDirGuard};
use super::*;

/// §S9・§S10・§S12・§S15と同じfanout。**形が違うと数字を並べられない。**
const FANOUT: usize = 32;

/// 既定の総ファイル数。腕を2本作るので26万は使わない（比率が同じなら結論は変わらない）。
const DEFAULT_FILE_COUNT: usize = 100_000;

/// 実リポジトリの比率（`target/`が96.1%）。**この値は実測の転記である**——
/// 2026-08-26に`find . -type f`で数えた 180,848 / 188,097。
const BULK_RATIO: f64 = 0.961;

fn file_count() -> usize {
    std::env::var("HARNESS_SUBTREE_COST_NODES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_FILE_COUNT)
}

/// 測定用のcapability SIDを**名前から導出**する（`workspace_capability_sid`は台帳へ書くので使わない）。
fn measure_capability(label: &str) -> crate::win_common::OwnedSid {
    let name = format!("harness-subtree-cost-{}-{label}", std::process::id());
    super::capability_sid_from_name(&name).expect("derive capability sid")
}

fn progress_to_stderr(label: &'static str) -> impl Fn(usize, usize) {
    move |done, total| {
        if done == total || done % 50_000 == 0 {
            eprintln!("  [{label}] {done}/{total}");
        }
    }
}

/// 実リポジトリの比率を写した木を作る。`bulk/`が96.1%、`rest/`が残り。
/// 戻り値は`(全ノード数, bulkのノード数, restのノード数)`。
fn build_repo_shaped_tree(root: &Path, total_files: usize) -> (usize, usize, usize) {
    std::fs::create_dir_all(root).expect("create tree root");
    let bulk_files = ((total_files as f64) * BULK_RATIO) as usize;
    let rest_files = total_files - bulk_files;
    let bulk_nodes = build_wide_tree(&root.join("bulk"), bulk_files, FANOUT);
    let rest_nodes = build_wide_tree(&root.join("rest"), rest_files, FANOUT);
    // root自身の1つを足す（`build_wide_tree`は各部分木のrootを自分で数えている）。
    (1 + bulk_nodes + rest_nodes, bulk_nodes, rest_nodes)
}

/// 製品の初回経路と同じ3段を1回ぶん実行する。`skip`だけが腕の違いになる。
fn product_shaped_pass(
    root: &Path,
    sid: PSID,
    mask: u32,
    skip: &[std::path::PathBuf],
    label: &'static str,
) -> (u128, u128, u128, super::DescendantFixReport) {
    let t = Instant::now();
    grant_workspace_root_rw_fast(root, sid).expect("fast (single-object) root grant");
    let fast_ms = t.elapsed().as_millis();

    let t = Instant::now();
    propagate_workspace_root_grant(root, sid, mask).expect("background propagate");
    let propagate_ms = t.elapsed().as_millis();

    let t = Instant::now();
    let walk = fix_descendants_missing_ace(root, sid, mask, skip, &progress_to_stderr(label))
        .expect("rescue walk");
    let walk_ms = t.elapsed().as_millis();

    (fast_ms, propagate_ms, walk_ms, walk)
}

/// 葉1枚の実効マスクを読む（B-25: 「呼んだ」ではなく「載った」で見る）。
fn leaf_mask(root: &Path, subtree: &str, sid: PSID) -> Option<u32> {
    let leaf = root.join(subtree).join("d000").join("f000000.txt");
    sid_effective_ace_mask(&leaf, sid).unwrap_or_else(|e| panic!("read {}: {e}", leaf.display()))
}

/// **部分木を除外すると、その費用は消えるのか。**
#[test]
#[ignore = "creates ~100k files twice and writes DACLs; run NON-elevated"]
fn subtree_exclusion_cost_removes_the_excluded_subtree_cost() {
    let count = file_count();
    let mask = workspace_rwx_mask();

    // ---------- 腕A（対照＝いまの挙動） ----------
    let dir_a = TestDirGuard::create("subtree-all");
    let root_a = dir_a.path();
    let (nodes_a, bulk_nodes_a, rest_nodes_a) = build_repo_shaped_tree(root_a, count);
    let sid_a = measure_capability("all");
    let (fast_a, prop_a, walk_ms_a, walk_a) =
        product_shaped_pass(root_a, sid_a.as_psid(), mask, &[], "all");
    let total_a = fast_a + prop_a + walk_ms_a;
    let bulk_leaf_a = leaf_mask(root_a, "bulk", sid_a.as_psid());
    let rest_leaf_a = leaf_mask(root_a, "rest", sid_a.as_psid());

    // ---------- 腕B（案a＝除外＋保護） ----------
    let dir_b = TestDirGuard::create("subtree-excl");
    let root_b = dir_b.path();
    let (nodes_b, bulk_nodes_b, _rest_nodes_b) = build_repo_shaped_tree(root_b, count);
    let sid_b = measure_capability("excl");
    let bulk_b = root_b.join("bulk");

    // **保護するのは部分木のrootだけ**（モジュールdocの注記）。時間も測る——
    // ここがO(ノード数)なら、案aは「費用を移しただけ」になる。
    let t = Instant::now();
    // 戻り値の`false`は「触るまでの間に消えた」だけを意味する。ここは作りたてなので真のはず
    // ——偽なら測定の前提が崩れているので、その場で止める。
    let protected = super::revoke::remove_sid_aces_and_protect(&bulk_b, sid_b.as_psid())
        .expect("protect the bulk subtree root");
    assert!(
        protected,
        "the bulk subtree root vanished before it could be protected; the measurement cannot \
         proceed"
    );
    let protect_ms = t.elapsed().as_millis();
    let bulk_is_protected = super::dacl_is_protected(&bulk_b).expect("read protection state");

    let skip = vec![bulk_b.clone()];
    let (fast_b, prop_b, walk_ms_b, walk_b) =
        product_shaped_pass(root_b, sid_b.as_psid(), mask, &skip, "excl");
    let total_b = protect_ms + fast_b + prop_b + walk_ms_b;
    let bulk_leaf_b = leaf_mask(root_b, "bulk", sid_b.as_psid());
    let rest_leaf_b = leaf_mask(root_b, "rest", sid_b.as_psid());

    let ratio = if total_a == 0 {
        f64::NAN
    } else {
        (total_b as f64) / (total_a as f64)
    };

    println!(
        "{}",
        serde_json::json!({
            "measurement": "does excluding a subtree actually remove its share of the cost",
            "file_count": count,
            "bulk_ratio": BULK_RATIO,
            "nodes_total": nodes_a,
            "nodes_bulk": bulk_nodes_a,
            "nodes_rest": rest_nodes_a,
            "arm_a_cover_everything": {
                "fast_root_grant_ms": fast_a,
                "propagate_ms": prop_a,
                "rescue_walk_ms": walk_ms_a,
                "total_ms": total_a,
                "walk_checked": walk_a.checked,
                "walk_skipped": walk_a.skipped,
                "walk_granted": walk_a.granted,
                "bulk_leaf_has_mask": bulk_leaf_a == Some(mask),
                "rest_leaf_has_mask": rest_leaf_a == Some(mask),
            },
            "arm_b_exclude_bulk": {
                "protect_one_node_ms": protect_ms,
                "bulk_root_is_protected": bulk_is_protected,
                "fast_root_grant_ms": fast_b,
                "propagate_ms": prop_b,
                "rescue_walk_ms": walk_ms_b,
                "total_ms": total_b,
                "walk_checked": walk_b.checked,
                "walk_skipped": walk_b.skipped,
                "walk_granted": walk_b.granted,
                "bulk_leaf_has_mask": bulk_leaf_b == Some(mask),
                "rest_leaf_has_mask": rest_leaf_b == Some(mask),
            },
            "b_over_a": ratio,
        })
    );

    // 撤収（付与と撤収は対、B-01）。ツリーは`TestDirGuard`がDropで消す。
    for (root, sid) in [(root_a, sid_a.as_psid()), (root_b, sid_b.as_psid())] {
        let report = revoke_ace_recursive(root, sid).expect("revoke the measurement ACEs");
        println!("  revoke {}: {report:?}", root.display());
    }

    assert_eq!(
        nodes_a, nodes_b,
        "the two arms must use identical trees, otherwise the times are not comparable"
    );

    // **対照が生きているか。** 腕Aで両方の葉に載っていなければ、腕Bの「載っていない」は
    // 除外の証拠にならない（B-35）。
    assert_eq!(
        (bulk_leaf_a, rest_leaf_a),
        (Some(mask), Some(mask)),
        "control arm: covering everything must reach both subtrees"
    );

    // **腕Bの陽性対照**——除外していない側には届いていること。
    assert_eq!(
        rest_leaf_b,
        Some(mask),
        "exclusion arm: the subtree that was NOT excluded must still receive the mask; if this \
         is None the arm measured 'nothing was distributed at all', not 'the exclusion worked'"
    );
    // **除外の意図した帰結**（＝案aの代償）。ここが`Some`なら継承が止まっていない。
    assert_eq!(
        bulk_leaf_b, None,
        "exclusion arm: the excluded subtree must NOT receive the mask -- that is the whole \
         point, and it is also the price of option (a): the sandbox cannot see it"
    );
    assert!(
        bulk_is_protected,
        "exclusion arm: the subtree root must actually carry SE_DACL_PROTECTED, otherwise the \
         propagation was stopped by something else and this result would not generalise \
         (BUG-083: the flag silently failed to stick for months)"
    );
    assert_eq!(
        walk_b.skipped, bulk_nodes_b,
        "exclusion arm: the walk must have skipped exactly the bulk subtree ({bulk_nodes_b} \
         nodes); a different number means the skip predicate is not covering what we think"
    );
}
