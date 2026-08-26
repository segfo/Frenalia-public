//! **現状1主体でのACL付与コストの基準線**（`plans/HANDOFF-ACL-DOMAIN-SPLIT-COST.md` のM1）。
//! 結果の正本は `plans/mac-spike/RESULTS.md` §S10。
//!
//! # なぜ測るのか
//!
//! `docs/STATUS.md` 残課題#20（ドメイン遷移の足回り——許可の宛先をセッション1つから
//! 用途ごとへ分ける）について、「D-54が性能のために一本化した当のものを逆向きに割るので重い」
//! と**推定**が書かれている。その根拠は BUG-081 の「26万ノード・毎起動60秒」1点だけで、
//! **D-54導入*前*・主体1つの構成**の数字である。**推定を実測へ置き換えるのがここの役目。**
//!
//! # §S9 との分担（重複して測らない）
//!
//! §S9（`d79_exec_split_tests`、2026-08-23）が既に **ノードあたり約60µs・5,033/20,033ノードで
//! 平坦** を出している。本モジュールが足すのは3つだけ:
//!
//! | # | 足すもの | §S9 に無い理由 |
//! |---|---|---|
//! | S10-1 | **26万ノード級でも平坦か** | §S9は20,033までで、26万は**外挿**（「約16秒」）でしか言っていない |
//! | S10-2 | **2回目**（冪等スキップが効く状態）の所要時間と書込回数 | §S9は初回しか測っていない |
//! | S10-3 | **製品と同じ順序**で伝播が既存子孫へ届くか（残課題#32の確定/否定） | §S9-5が疑いを立てたまま「次に測ること」で終わっている |
//!
//! **20,000ノードの腕は§S9との突き合わせ**である。1,224 ms（61 µs/node）から大きくずれたら、
//! 結論を書く前に**まず計器を疑う**。
//!
//! # S10-3 が最初に来る理由
//!
//! §S9-5 は「rootへ単一オブジェクト書込をした後の伝播は既存の子孫へ届かないのではないか。
//! しかも**それは製品の既定経路そのものの形**である」と疑っている（残課題#32、未確定）。
//!
//! **これが本当なら、S10-1で測る『伝播時間』は何も測っていないことになる**——実際に
//! 効いているのは後段の救済walkだけになる。**だから順序の判定を先に置く。**
//!
//! 判定に新しい計器は要らない。[`super::fix_descendants_missing_ace`]が返す
//! [`super::DescendantFixReport::granted`]が「継承が届かず明示ACEを書いた数」で、
//! そのdocが**「0であることが健全な状態」**と言っている。**ノード数に近ければ疑いは確定**する。
//!
//! # 実行
//!
//! **昇格しない。** ACEを書くのはテスト自身が作ったツリーだけなので所有者権限で足りる
//! （`d79_exec_split_tests`と同じ）。主体は`capability_sid_from_name`（純粋な導出）で、
//! **台帳にもAppContainerプロファイルにも何も残さない**。`preflight`は通さない——
//! あちらは台帳とプロファイルを作り、祖先の通過許可で昇格を誘発し得る。
//!
//! ```text
//! HARNESS_ACL_COST_NODES=20000 cargo test -p harness-sandbox --lib -- \
//!     --ignored --test-threads=1 --nocapture acl_baseline_cost
//! ```
//!
//! **判定が出たら本ファイルは削除する**（`docs/CODE-STRUCTURE-RULES.md`規則2）。

use std::path::Path;
use std::time::Instant;

use super::test_support::{build_wide_tree, TestDirGuard};
use super::*;

/// `build_wide_tree`のfanout。**§S9のコスト測定と同じ値**にする（`d79_exec_split_tests`の
/// `d79_cost_of_splitting_the_inherited_ace`が`32`を渡している）。形が違うと数字を並べられない
/// ——§S9の「5,033／20,033ノード」は`1 + 32 + count`から出ている。
const FANOUT: usize = 32;

/// 測定するファイル数。`HARNESS_ACL_COST_NODES`で上書きできる（再ビルド無しでサイズを振る）。
/// 既定は§S9との突き合わせ点。
const DEFAULT_FILE_COUNT: usize = 20_000;

/// 測定用のcapability SIDを**名前から導出**する。`workspace_capability_sid`は使わない
/// ——あちらはworkspace＋mode単位の秘密を`%APPDATA%`の台帳へ永続化するので、測定が実マシンへ
/// 記録を残す（HANDOFFの「やってはいけないこと」2番）。
fn measure_capability(label: &str) -> crate::win_common::OwnedSid {
    let name = format!("harness-acl-baseline-{}-{label}", std::process::id());
    super::capability_sid_from_name(&name).expect("derive capability sid")
}

fn file_count() -> usize {
    std::env::var("HARNESS_ACL_COST_NODES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_FILE_COUNT)
}

/// walkの進捗をstderrへ出す。**「止まっているのか遅いのか」を判別できるようにするため**で、
/// 判定には一切関与しない（26万ノードのwalkは数十秒沈黙するので、無いと失敗と遅さを取り違える）。
fn progress_to_stderr(label: &'static str) -> impl Fn(usize, usize) {
    move |done, total| {
        if done == total || done % 50_000 == 0 {
            eprintln!("  [{label}] {done}/{total}");
        }
    }
}

/// 撤収し、**残っていないことを実測してから**ツリーを消す。
///
/// 「撤収したと報告されたのに ACE が減っていなかった」実例（BUG-101）があるので、
/// `revoke`の戻り値ではなく[`super::assert_no_sid_ace_recursive`]で裏を取る（B-25）。
fn revoke_and_verify(root: &Path, sid: PSID) -> u128 {
    let started = Instant::now();
    let report = revoke_ace_recursive(root, sid).expect("revoke the measurement ACEs");
    let elapsed = started.elapsed().as_millis();
    println!("  revoke: {elapsed} ms, report={report:?}");
    if let Err(leftovers) = assert_no_sid_ace_recursive(root, sid) {
        panic!(
            "the measurement SID still has ACEs on {} node(s) after revoke; first few: {:?}",
            leftovers.len(),
            leftovers.iter().take(5).collect::<Vec<_>>()
        );
    }
    elapsed
}

/// 製品の初回経路と同じ3段（同期区間のroot付与 → 背景フェーズ0の伝播 → フェーズ1の救済walk）を
/// 1回ぶん実行し、段ごとの所要時間と救済walkの結果を返す。
///
/// **`acl_baseline_cost_first_and_second_pass`と同じ並びをここに1つ置いている**のは、
/// 一巡（付与→撤収→付与）を測るには**同じ形を2回**回す必要があるためである
/// （`docs/CODE-STRUCTURE-RULES.md`規則5: コピーを作らない）。
fn product_shaped_first_pass(
    root: &Path,
    sid: PSID,
    mask: u32,
    label: &'static str,
) -> (u128, u128, u128, super::DescendantFixReport) {
    let t = Instant::now();
    grant_workspace_root_rw_fast(root, sid).expect("fast (single-object) root grant");
    let fast_ms = t.elapsed().as_millis();

    let t = Instant::now();
    propagate_workspace_root_grant(root, sid, mask).expect("background propagate");
    let propagate_ms = t.elapsed().as_millis();

    let t = Instant::now();
    let walk = fix_descendants_missing_ace(root, sid, mask, &[], &progress_to_stderr(label))
        .expect("rescue walk");
    let walk_ms = t.elapsed().as_millis();

    (fast_ms, propagate_ms, walk_ms, walk)
}

/// **S10-3（先に置く）: 製品と同じ順序で、伝播は既存の子孫へ届くのか。**
///
/// 製品の既定経路は BUG-082 Part B で2段に割れている:
///
/// 1. `preflight`の同期区間が`grant_workspace_root_rw_fast`（`DaclWrite::SingleObject`）で
///    rootへ書く
/// 2. 背景ジョブのフェーズ0が`propagate_workspace_root_grant`（`Propagate`＋`Always`）を呼ぶ
///
/// §S9-4 は合成ツリーで「1の後に2をやると葉に何も降りない」を観測した。**ここでは
/// その形を製品と同じ順序で並べ、`granted`（継承が届かず明示ACEを書いた数）で確定させる。**
///
/// **対照を必ず取る**（B-35）——`Propagate`を1回だけ打つ腕を並べる。それが無いと、
/// `granted`が大きくても「経路の性質」なのか「このツリーの性質」なのかを言えない。
///
/// # [2026-08-25] 残課題#32は修正された。**このテストは回帰になった**
///
/// 修正前、腕Bは 2,032/2,033（20,033・100,033・260,033でも同じ割合）で、その値を
/// 「現状」として留めるassertが置いてあった。修正後は**両方の腕が0**である。
/// **したがって2つの腕は同じことを主張するようになった**が、統合せずに残してある——
/// 腕Aは「伝播そのものが健全か」（計器の検算）、腕Bは「製品の順序でも届くか」（#32の回帰）で、
/// **同じ数字が別の理由で0になっている**。片方が赤くなったときに、どちらの話かが分かる。
/// 修正の本体は[`super::acl_dacl_write`]（モジュールdocに8通りの実測表がある）。
#[test]
#[ignore = "creates tens of thousands of files and writes DACLs; run NON-elevated"]
fn acl_baseline_cost_propagation_reaches_existing_descendants() {
    let count = file_count();
    let mask = workspace_rwx_mask();

    // 腕A: `Propagate`を1回だけ（対照。届くはずの形）。
    let dir_a = TestDirGuard::create("aclbase-ctrl");
    let root_a = dir_a.path();
    let nodes = build_wide_tree(root_a, count, FANOUT);
    let sid_a = measure_capability("ctrl");
    let t = Instant::now();
    grant_workspace_root_rw(root_a, sid_a.as_psid()).expect("propagating root grant");
    let propagate_only_ms = t.elapsed().as_millis();
    let report_a = fix_descendants_missing_ace(
        root_a,
        sid_a.as_psid(),
        mask,
        &[],
        &progress_to_stderr("ctrl"),
    )
    .expect("walk after the propagating grant");

    // 腕B: 製品と同じ順序（`SingleObject`で置いてから`Propagate`＋`Always`）。
    let dir_b = TestDirGuard::create("aclbase-prod");
    let root_b = dir_b.path();
    let nodes_b = build_wide_tree(root_b, count, FANOUT);
    let sid_b = measure_capability("prod");
    let t = Instant::now();
    grant_workspace_root_rw_fast(root_b, sid_b.as_psid()).expect("fast (single-object) root grant");
    let fast_ms = t.elapsed().as_millis();
    let t = Instant::now();
    propagate_workspace_root_grant(root_b, sid_b.as_psid(), mask).expect("background propagate");
    let propagate_after_fast_ms = t.elapsed().as_millis();
    let report_b = fix_descendants_missing_ace(
        root_b,
        sid_b.as_psid(),
        mask,
        &[],
        &progress_to_stderr("prod"),
    )
    .expect("walk after the product-shaped sequence");

    println!(
        "{}",
        serde_json::json!({
            "measurement": "S10-3 does the propagation reach existing descendants",
            "nodes": nodes,
            "file_count": count,
            "fanout": FANOUT,
            "control_propagate_only": {
                "propagate_ms": propagate_only_ms,
                "walk_checked": report_a.checked,
                "walk_granted": report_a.granted,
                "walk_probe_errors": report_a.probe_errors,
            },
            "product_shaped_single_object_then_propagate": {
                "fast_root_grant_ms": fast_ms,
                "propagate_ms": propagate_after_fast_ms,
                "walk_checked": report_b.checked,
                "walk_granted": report_b.granted,
                "walk_probe_errors": report_b.probe_errors,
            },
        })
    );

    assert_eq!(nodes, nodes_b, "the two arms must use identical trees");

    // **0を読む前に、歩いたことを確かめる**（B-35）。`granted == 0`は「全部届いた」でも
    // 「1件も歩かなかった」でも成り立つので、これが無いと空ツリーでも緑になる。
    for (label, report) in [("control", &report_a), ("product-shaped", &report_b)] {
        assert_eq!(
            report.checked, nodes,
            "{label} arm: the walk must have visited every node before its `granted` can be read"
        );
        assert_eq!(
            report.skipped, 0,
            "{label} arm: nothing was passed as `skip`, so nothing may be skipped"
        );
        assert_eq!(
            report.probe_errors, 0,
            "{label} arm: a node whose DACL could not be read is counted as granted, so a \
             non-zero value here makes the comparison meaningless"
        );
    }
    // **届いた側の実効マスクまで見る**（B-25: 「設定した」ではなく実効で検証する）。
    // `granted == 0`はACEの**有無**しか言っておらず、権限が意図どおりかは別の事実である。
    for (label, root, sid) in [
        ("control", root_a, sid_a.as_psid()),
        ("product-shaped", root_b, sid_b.as_psid()),
    ] {
        let leaf = root.join("d000").join("f000000.txt");
        let effective = sid_effective_ace_mask(&leaf, sid)
            .unwrap_or_else(|e| panic!("{label} arm: read the leaf's effective mask: {e}"));
        assert_eq!(
            effective,
            Some(mask),
            "{label} arm: the leaf {} must carry exactly the mask that was propagated",
            leaf.display()
        );
    }

    revoke_and_verify(root_a, sid_a.as_psid());
    revoke_and_verify(root_b, sid_b.as_psid());

    // 対照。**伝播そのものが健全か**を測る腕で、ここが赤いなら計器が壊れている。
    assert_eq!(
        report_a.granted, 0,
        "control arm: a single Propagate write must reach every existing descendant, so the \
         rescue walk should have nothing to fix. If this is non-zero the measurement instrument \
         itself is wrong — do not read the product arm."
    );

    // **残課題#32の回帰**（2026-08-25に修正）。修正前はここが 2,032/2,033 だった
    // ——「速いはずの経路が無症状で死んでいて、O(ノード数)の明示書込を毎回払っている」状態。
    // 直し方の実測表は[`super::acl_dacl_write`]のモジュールdocが持つ。
    assert_eq!(
        report_b.granted, 0,
        "STATUS #32 regression: the product-shaped sequence (single-object root write, then a \
         propagating write) must reach every existing descendant. {} of {} nodes needed an \
         explicit grant, which means the propagation is silently doing nothing again and the \
         first pass has gone back to paying O(nodes) DACL writes.",
        report_b.granted,
        report_b.checked
    );
}

/// **S10-1 / S10-2: 初回と2回目のコスト、そして2回目の書込回数。**
///
/// 「起動時間」と「伝播完了までの時間」は**別物**なので分けて出す（BUG-082 Part Bで
/// root付与が同期のミリ秒と背景の数十秒に割れた）。混ぜると、どちらの話をしているのかが消える。
///
/// 2回目（M1-b）で見たいのは**時間ではなく書込回数**である。冪等スキップが効いていれば
/// Win32書込は0回になり、それは次の2つで観測できる:
///
/// - rootは`sid_explicit_ace(root).satisfies(...)`が真＝`grant_ace_mask_with`が書かずに戻る
/// - 子孫は`DescendantFixReport.granted == 0`＝救済walkが1件も書かない
#[test]
#[ignore = "creates tens of thousands of files and writes DACLs; run NON-elevated"]
fn acl_baseline_cost_first_and_second_pass() {
    let count = file_count();
    let mask = workspace_rwx_mask();
    let dir = TestDirGuard::create("aclbase-pass");
    let root = dir.path();

    let t = Instant::now();
    let nodes = build_wide_tree(root, count, FANOUT);
    let build_ms = t.elapsed().as_millis();

    let sid = measure_capability("pass");

    // --- 初回 ---
    let t = Instant::now();
    grant_workspace_root_rw_fast(root, sid.as_psid()).expect("first: fast root grant");
    let first_fast_ms = t.elapsed().as_millis();

    let t = Instant::now();
    propagate_workspace_root_grant(root, sid.as_psid(), mask).expect("first: propagate");
    let first_propagate_ms = t.elapsed().as_millis();

    let t = Instant::now();
    let first_walk =
        fix_descendants_missing_ace(root, sid.as_psid(), mask, &[], &progress_to_stderr("1st"))
            .expect("first: rescue walk");
    let first_walk_ms = t.elapsed().as_millis();

    // --- 2回目（冪等スキップが効く状態） ---
    let folded = sid_explicit_ace(root, sid.as_psid())
        .expect("read back the root ACE")
        .expect("the root must carry an explicit ACE after the first pass");
    let both = (CONTAINER_INHERIT_ACE.0 | OBJECT_INHERIT_ACE.0) as u8;
    let root_write_skipped = folded.satisfies(mask, both);

    let t = Instant::now();
    grant_workspace_root_rw(root, sid.as_psid()).expect("second: root grant (idempotent path)");
    let second_root_ms = t.elapsed().as_millis();

    let t = Instant::now();
    let second_walk =
        fix_descendants_missing_ace(root, sid.as_psid(), mask, &[], &progress_to_stderr("2nd"))
            .expect("second: rescue walk");
    let second_walk_ms = t.elapsed().as_millis();

    let per_node_us = |ms: u128| (ms as f64) * 1000.0 / (nodes as f64);
    println!(
        "{}",
        serde_json::json!({
            "measurement": "S10-1/S10-2 baseline cost, first vs second pass",
            "nodes": nodes,
            "file_count": count,
            "fanout": FANOUT,
            "tree_build_ms": build_ms,
            "first_pass": {
                "startup_side_fast_root_grant_ms": first_fast_ms,
                "propagate_ms": first_propagate_ms,
                "propagate_us_per_node": per_node_us(first_propagate_ms),
                "rescue_walk_ms": first_walk_ms,
                "walk_checked": first_walk.checked,
                "walk_granted": first_walk.granted,
                "walk_probe_errors": first_walk.probe_errors,
            },
            "second_pass": {
                "root_grant_ms": second_root_ms,
                "root_write_skipped": root_write_skipped,
                "rescue_walk_ms": second_walk_ms,
                "walk_granted": second_walk.granted,
                "win32_dacl_writes": (!root_write_skipped as usize) + second_walk.granted,
            },
        })
    );

    revoke_and_verify(root, sid.as_psid());

    assert!(
        root_write_skipped,
        "second pass: the root must be reported as already satisfied, otherwise every startup \
         re-writes the root DACL (folded={folded:?})"
    );
    assert_eq!(
        second_walk.granted, 0,
        "second pass: the rescue walk must not write a single explicit ACE — if it does, the \
         per-startup cost never drops and D-54's whole point (pay once per workspace) is lost"
    );
}

/// **付与 → 撤収 → 付与の一巡は、いくらか。**
///
/// # なぜこれを測るのか（`acl_baseline_cost_first_and_second_pass`では答えられない）
///
/// あちらの「2回目のWin32書込は0回」は、**ACEが載ったままもう一度付けた**ときの数字である。
/// そこから「ワークスペースにつき一度きり」と読むには、**剥がす経路が存在しない**ことが
/// 前提になる。**その前提は成り立たない**——剥がす経路は少なくとも3つある。
///
/// | 剥がれる経路 | いつ起きるか |
/// |---|---|
/// | `harness fs revoke-workspace` | ユーザーが明示的に撤収したとき |
/// | 書込モードの切替（`Live` ⇄ `--sandbox tier2a-cow`） | capability SIDは**ワークスペース＋モード単位**なので、モードが変わると別のSIDになり、そちらのACEは1本も載っていない（**D-54**） |
/// | capability台帳（`workspace-capability-ledger.json`）の剪定・喪失 | 名前の素になる秘密が消えると、次回は**別のSIDが導出される** |
///
/// **どの経路でも、次の付与は初回と同じ状態から始まる。** したがって「一度きり」は
/// ワークスペース単位ではなく **(ワークスペース × モード × capabilityの世代) 単位**である。
///
/// # 何を主張するか（時間はassertしない）
///
/// 所要時間はマシンの状態に揺れるので**判定には使わず、値として出すだけ**にする。
/// assertするのは揺れない構造の側だけ:
///
/// 1. 撤収後、rootに明示ACEが**残っていない**こと（＝冪等スキップの前提が消えている）
/// 2. 2周目の伝播が既存の子孫へ**届く**こと（残課題#32の回帰を一巡側でも押さえる）
///
/// **時間の比（2周目 ÷ 初回）はJSONに出す。** 1.0に近ければ「撤収したら全額もう一度」で、
/// 「一度きり」という説明が条件付きであることの直接の証拠になる。
#[test]
#[ignore = "creates tens of thousands of files and writes DACLs; run NON-elevated"]
fn acl_baseline_cost_regrant_after_revoke_pays_again() {
    let count = file_count();
    let mask = workspace_rwx_mask();
    let dir = TestDirGuard::create("aclbase-cycle");
    let root = dir.path();

    let nodes = build_wide_tree(root, count, FANOUT);
    let sid = measure_capability("cycle");

    // --- 1周目（まっさらなツリーへの初回付与＝製品の初回起動と同じ形） ---
    let (first_fast_ms, first_propagate_ms, first_walk_ms, first_walk) =
        product_shaped_first_pass(root, sid.as_psid(), mask, "1st");
    let first_total_ms = first_fast_ms + first_propagate_ms + first_walk_ms;

    // --- 撤収（`harness fs revoke-workspace`が通る経路と同じ再帰撤収） ---
    let revoke_ms = revoke_and_verify(root, sid.as_psid());

    // **撤収後にrootの明示ACEが消えていることを、伝播の前に確かめる。**
    // これが残っていると2周目の`grant_ace_mask_with`が冪等スキップし、
    // 「安かった」のではなく「撤収できていなかった」を測ることになる（B-25）。
    let root_ace_after_revoke = sid_explicit_ace(root, sid.as_psid()).expect("read back root ACE");

    // --- 2周目（撤収済みのツリーへ、まったく同じ形でもう一度） ---
    let (second_fast_ms, second_propagate_ms, second_walk_ms, second_walk) =
        product_shaped_first_pass(root, sid.as_psid(), mask, "2nd");
    let second_total_ms = second_fast_ms + second_propagate_ms + second_walk_ms;

    let ratio = if first_total_ms == 0 {
        f64::NAN
    } else {
        (second_total_ms as f64) / (first_total_ms as f64)
    };
    let per_node_us = |ms: u128| (ms as f64) * 1000.0 / (nodes as f64);

    println!(
        "{}",
        serde_json::json!({
            "measurement": "grant -> revoke -> grant costs the full price again",
            "nodes": nodes,
            "file_count": count,
            "fanout": FANOUT,
            "first_grant": {
                "startup_side_fast_root_grant_ms": first_fast_ms,
                "propagate_ms": first_propagate_ms,
                "rescue_walk_ms": first_walk_ms,
                "total_ms": first_total_ms,
                "us_per_node": per_node_us(first_total_ms),
                "walk_checked": first_walk.checked,
                "walk_granted": first_walk.granted,
            },
            "revoke": {
                "ms": revoke_ms,
                "us_per_node": per_node_us(revoke_ms),
                "root_explicit_ace_left": root_ace_after_revoke.is_some(),
            },
            "second_grant_after_revoke": {
                "startup_side_fast_root_grant_ms": second_fast_ms,
                "propagate_ms": second_propagate_ms,
                "rescue_walk_ms": second_walk_ms,
                "total_ms": second_total_ms,
                "us_per_node": per_node_us(second_total_ms),
                "walk_checked": second_walk.checked,
                "walk_granted": second_walk.granted,
            },
            "second_over_first": ratio,
            "full_cycle_ms": first_total_ms + revoke_ms + second_total_ms,
        })
    );

    revoke_and_verify(root, sid.as_psid());

    assert_eq!(
        root_ace_after_revoke, None,
        "the revoke must leave no explicit ACE on the root — otherwise the second grant is \
         measuring an idempotent skip, not a real re-grant"
    );
    for (label, walk) in [("first", &first_walk), ("second", &second_walk)] {
        assert_eq!(
            walk.checked, nodes,
            "{label} grant: the walk must have visited every node before its `granted` is read"
        );
        assert_eq!(
            walk.granted, 0,
            "{label} grant: the propagating write must reach every existing descendant \
             (STATUS #32 regression, now measured on the revoke-and-regrant path too)"
        );
    }
}
