//! **ACL付与コストの測定**（`plans/HANDOFF-ACL-DOMAIN-SPLIT-COST.md`）。
//! 結果の正本は `plans/mac-spike/RESULTS.md`——M1が §S10、M3が §S15。
//!
//! # 2つの寿命が同居している
//!
//! | 何 | テスト名の接頭辞 | 寿命 |
//! |---|---|---|
//! | M1 | `acl_baseline_cost_*` | **残す。**うち2本は残課題#32の回帰になった（`granted == 0`のassert） |
//! | **M3** | `acl_ace_count_cost_*` | **残課題#20の実装が終わったら消す**（下記） |
//!
//! 接頭辞が分けてあるので、`cargo test -- acl_ace_count_cost`でM3だけを回せる。
//!
//! ## M3を「§S15を書いたら消す」にしなかった理由（`docs/CODE-STRUCTURE-RULES.md`規則2の例外）
//!
//! 規則2は一回性の調査実験をテストとして残すなと言う。**M3の問いは§S15で閉じている**ので、
//! 本来はここで消える。**残してあるのは、#20の実装がいま進行中で、この測定が
//! その実装の判断に直接効くからである**——§S15が出した答えは
//! 「**部品を使えば0倍、主体ごとに伝播を呼ぶと約2.9倍**」で、**どちらに転ぶかは実装の書き方
//! だけで決まる**。実装しながら「いま書いた形はどちらか」を測り直せる状態にしておく。
//!
//! **したがって消す条件は日付ではなく出来事である**——`docs/STATUS.md`残課題#20 が
//! 実装完了になったら、`acl_ace_count_cost_*` の2本と、それだけが使っている
//! `test_support::build_chain_tree`をまとめて消すこと。**引き継ぎ側にも同じことを書いてある**
//! （`plans/HANDOFF-ISSUE-20-SUBJECT-MIGRATION.md`）。
//!
//! **同じファイルに置いてあるのは、ツリーの形と計器を共有するためである。**
//! `FANOUT`・`file_count()`・`measure_capability`・`progress_to_stderr`・`revoke_and_verify`が
//! 共通で、**形が違うと §S9／§S10 の数字と並べられない**。
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
//! HARNESS_TEST_ACL_COST_NODES=20000 cargo test -p harness-sandbox --lib -- \
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

/// 測定するファイル数。`HARNESS_TEST_ACL_COST_NODES`で上書きできる（再ビルド無しでサイズを振る）。
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
    std::env::var("HARNESS_TEST_ACL_COST_NODES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_FILE_COUNT)
}

/// 製品規模の腕のファイル数。**このリポジトリの実測が248,766ノード**なので26万を既定にする。
///
/// **`file_count`とは別の環境変数にしてある。** 同じ変数を別の既定値で2度読むと、
/// どちらの既定が効いているのかがコードから読めなくなる（`B-05`: 複製した綴りは静かにずれる）。
fn production_file_count() -> usize {
    std::env::var("HARNESS_TEST_ACL_PRODUCTION_NODES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(260_000)
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

// ===========================================================================
// M3 — 残課題#20 の費用（`plans/HANDOFF-ACL-DOMAIN-SPLIT-COST.md` のM3、結果は §S15）
//
// **§S15を書いたらこのブロックごと消すこと**（規則2）。ただし`build_chain_tree`は
// `test_support`に残す——`build_wide_tree`と対になる形の部品で、深さを測り直すときに要る。
// ===========================================================================

/// 1腕ぶんの書込の形。**これが M3-a の測る当のものである。**
#[derive(Clone, Copy, Debug)]
enum WriteShape {
    /// M本を1つのDACLへ畳んで**ノードあたり1回**書く（[`super::acl_dacl_write`]の本来の使い方）。
    Merged,
    /// 主体ごとに1回ずつ伝播させる＝**ノードあたりM回**。§S9-3が「約2倍」を出した素朴な形で、
    /// **対照としてしか使わない**——これが無いと「平坦」を「今日はマシンが速い」と
    /// 区別できない（B-35）。
    OnePerSubject,
    /// [BUG-145の案A] rootへは**配布しない口**で継承ACEを置き、**root直下の子ごとに**
    /// 配布書込を掛ける＝書込が1回から**K回**（Kは直下の子の数）。
    ///
    /// **制御ディレクトリ`.harness/`を配布の対象から外すには、この形にするしかない。**
    /// 「OSが歩くファイル数は同じなので所要時間はほぼ変わらない」という主張が
    /// 未測定のまま残っていたので、[`WriteShape::Merged`]と対で測る
    /// （`plans/mac-spike/RESULTS.md` §S31）。
    ///
    /// **rootへの単一オブジェクト書込を省かないこと。** これが無いと、準備の後に
    /// root直下へ作られる新しいファイルが継承ACEを受け取れない——製品の`preflight`が
    /// `grant_workspace_root_aces_fast`で置いているのと同じものである。
    SplitPerTopLevelChild,
}

/// M本ぶんの主体を作る。**マスクを主体ごとに変えてあるのが要点**——全部同じにすると、
/// 1本しか配れていなくても「どれかのACEが届いている」で緑になる（B-35）。
/// 順番は固定で、Mを増やしても前のM本の意味が変わらないようにしてある。
fn m_subjects(label: &str, m: usize) -> Vec<(crate::win_common::OwnedSid, u32)> {
    let masks = [
        workspace_rwx_mask(),
        fs_access_mask(FsAccess::Read),
        fs_access_mask(FsAccess::ReadExec),
    ];
    assert!(
        m >= 1 && m <= masks.len(),
        "M is bounded by the design at 3 (one declared path yields ro/rw/rx at most)"
    );
    (0..m)
        .map(|i| (measure_capability(&format!("{label}-s{i}")), masks[i]))
        .collect()
}

/// 1腕を測って結果をJSONで返す。**時間を読む前に必ず検算を通す**——§S9-4は
/// 「1.01倍と出たが、それは何もしていないから速かった」を実際に踏んでいる。
///
/// 検算は3つとも既存部品で行い、**新しい検算を足さない**
/// （[`super::acl_dacl_write`]のdocが「同じ事実を2箇所で判定しない」と定めている、B-05）。
///
/// 1. 葉（ファイルとディレクトリの両方）の実効マスクが**その主体自身のマスク**と一致する
/// 2. 救済walkが全ノードを歩き（`checked == nodes`）、**1件も書いていない**（`granted == 0`）
/// 3. 撤収後に対象SIDのACEが1本も残っていない（BUG-101）
///
/// `leaf_dir`/`leaf_file`は**そのツリーで最も深い**ものを渡すこと——浅いところだけ届いて
/// 深いところが落ちる形を拾うため（深い腕でこれを外すと測定の意味が消える）。
fn measure_arm(
    label: &str,
    root: &Path,
    nodes: usize,
    subjects: &[(crate::win_common::OwnedSid, u32)],
    leaf_dir: &Path,
    leaf_file: &Path,
    shape: WriteShape,
) -> serde_json::Value {
    use super::acl_dacl_write::{grant_aces_propagating, InheritableGrant};

    let both = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
    let grants: Vec<InheritableGrant> = subjects
        .iter()
        .map(|(sid, mask)| InheritableGrant {
            sid: sid.as_psid(),
            mask: *mask,
            inheritance: both,
        })
        .collect();

    // --- 測る区間はここだけ ---
    let started = Instant::now();
    match shape {
        WriteShape::Merged => {
            grant_aces_propagating(root, &grants, IdempotentCheck::Always).unwrap_or_else(|e| {
                panic!(
                    "{label}: one propagating write for {} subjects: {e}",
                    grants.len()
                )
            })
        }
        WriteShape::OnePerSubject => {
            for (i, grant) in grants.iter().enumerate() {
                grant_aces_propagating(root, std::slice::from_ref(grant), IdempotentCheck::Always)
                    .unwrap_or_else(|e| panic!("{label}: propagating write #{i}: {e}"));
            }
        }
        WriteShape::SplitPerTopLevelChild => {
            // root へは配布しない口で置くだけ（製品の`grant_workspace_root_aces_fast`と同じ）。
            super::acl_dacl_write::grant_aces_single_object(
                root,
                &grants,
                IdempotentCheck::Always,
            )
            .unwrap_or_else(|e| panic!("{label}: single-object write on the root: {e}"));

            // 直下の子ごとに配布。**シンボリックリンクは飛ばす**——`top_level_child_missing_aces`と
            // 同じ判断で、付与側が触らないものを検算側だけが数えるずれを作らないため。
            let entries = std::fs::read_dir(root)
                .unwrap_or_else(|e| panic!("{label}: read the top-level children: {e}"));
            let mut children = 0usize;
            for entry in entries.flatten() {
                if entry.file_type().map(|t| t.is_symlink()).unwrap_or(true) {
                    continue;
                }
                let child = entry.path();
                grant_aces_propagating(&child, &grants, IdempotentCheck::Always).unwrap_or_else(
                    |e| panic!("{label}: propagating write on {}: {e}", child.display()),
                );
                children += 1;
            }
            assert!(
                children > 0,
                "{label}: the split shape wrote to no child at all, so the timing below is \
                 meaningless"
            );
        }
    }
    let propagate_ms = started.elapsed().as_millis();

    // --- 検算1: 最深部の葉が、主体ごとに違う正しいマスクを持っているか ---
    for (i, (sid, mask)) in subjects.iter().enumerate() {
        for leaf in [leaf_file, leaf_dir] {
            let effective = sid_effective_ace_mask(leaf, sid.as_psid()).unwrap_or_else(|e| {
                panic!("{label}: read the effective mask of {}: {e}", leaf.display())
            });
            assert_eq!(
                effective,
                Some(*mask),
                "{label}: subject #{i} must carry exactly its own mask on the deepest leaf {} — \
                 if this is None the write reached nothing and the timing above is meaningless",
                leaf.display()
            );
        }
    }

    // --- 検算2: 救済walkに仕事が残っていない＝伝播が全ノードへ届いた ---
    let walk_started = Instant::now();
    for (i, (sid, mask)) in subjects.iter().enumerate() {
        let report = fix_descendants_missing_ace(root, sid.as_psid(), *mask, &[], &|_, _| {})
            .unwrap_or_else(|e| panic!("{label}: rescue walk for subject #{i}: {e}"));
        assert_eq!(
            report.checked, nodes,
            "{label}: subject #{i}: the walk must visit every node before its `granted` is read"
        );
        assert_eq!(
            report.probe_errors, 0,
            "{label}: subject #{i}: a node whose DACL could not be read is counted as granted, so \
             a non-zero value here makes the comparison meaningless"
        );
        assert_eq!(
            report.granted, 0,
            "{label}: subject #{i}: the propagating write must reach every existing descendant, \
             but {} of {} nodes still needed an explicit grant",
            report.granted, report.checked
        );
    }
    let verify_walk_ms = walk_started.elapsed().as_millis();

    // --- 撤収（M本を1回のwalkで剥がす既存部品。SIDごとに舐め直さない） ---
    let psids: Vec<PSID> = subjects.iter().map(|(sid, _)| sid.as_psid()).collect();
    let revoke_started = Instant::now();
    let revoke_report = revoke_workspace_sids_recursive(root, &psids, &progress_to_stderr("revoke"))
        .unwrap_or_else(|e| panic!("{label}: revoke every measurement subject: {e}"));
    let revoke_ms = revoke_started.elapsed().as_millis();

    // --- 検算3: 剥がれたことを戻り値ではなく読み直しで確かめる（BUG-101） ---
    for (i, (sid, _)) in subjects.iter().enumerate() {
        if let Err(leftovers) = assert_no_sid_ace_recursive(root, sid.as_psid()) {
            panic!(
                "{label}: subject #{i} still has ACEs on {} node(s) after revoke; first few: {:?}",
                leftovers.len(),
                leftovers.iter().take(5).collect::<Vec<_>>()
            );
        }
    }

    serde_json::json!({
        "arm": label,
        "subjects": subjects.len(),
        "shape": format!("{shape:?}"),
        "nodes": nodes,
        "propagate_ms": propagate_ms,
        "propagate_us_per_node": (propagate_ms as f64) * 1000.0 / (nodes as f64),
        "verify_walk_ms": verify_walk_ms,
        "revoke_ms": revoke_ms,
        "revoke_checked": revoke_report.checked,
        "revoke_rewritten": revoke_report.rewritten,
    })
}

/// 平らなツリー（[`build_wide_tree`]）の最深部。深さは2段で固定なので`d000/f000000.txt`。
///
/// **本体は[`forest_tree_leaves`]の`depth = 1`である**（規則5: 同じ組み立てを2つ持たない）。
fn wide_tree_leaves(root: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    forest_tree_leaves(root, 1)
}

/// 森ツリー（[`super::test_support::build_forest_tree`]）の**最深部**——1本目の枝の一番下の
/// ディレクトリと、そこに最初に載るファイル。
///
/// ファイルは`k * depth`個のディレクトリへ順に撒かれるので、1本目の枝の最深段
/// （並びの`depth - 1`番目）に最初に載るのは`f{depth-1:06}.txt`である。
/// **ここを外して浅い葉を見ると、深い側へ配布が届いていなくても緑になる。**
fn forest_tree_leaves(root: &Path, depth: usize) -> (std::path::PathBuf, std::path::PathBuf) {
    let mut dir = root.join("d000");
    for _ in 1..depth {
        dir = dir.join("d");
    }
    let file = dir.join(format!("f{:06}.txt", depth - 1));
    (dir, file)
}

/// 鎖ツリー（`test_support::build_chain_tree`）の**最深部**。
///
/// ファイルは`i % depth`段目へ撒かれるので、最深段（`depth-1`）に載る最初のファイルは
/// `f{depth-1}.txt`である。**ここを外して浅い葉を見ると、深い側が落ちていても緑になる。**
fn chain_tree_leaves(root: &Path, depth: usize) -> (std::path::PathBuf, std::path::PathBuf) {
    let mut dir = root.to_path_buf();
    for _ in 0..depth {
        dir = dir.join("d");
    }
    let file = dir.join(format!("f{:06}.txt", depth - 1));
    (dir, file)
}

/// `root`から`depth`段の鎖を掘り、**最深段でファイルを1つ作って読んで消せるか**を確かめる。
///
/// 2万個を撒く前の関所である。深さ128の鎖はパス長がMAX_PATH(260)を越えるので、
/// **作れるかどうかがそもそも不明**——そして作れてしまってから消せないと、
/// `TestDirGuard`のDropが黙って失敗して実マシンに残骸が残る（Dropは`Result`を捨てる）。
///
/// 掘った鎖はそのまま残す（この後の`build_chain_tree`が同じ段を使う）。
fn probe_chain_depth(root: &Path, depth: usize) -> Result<(), String> {
    let mut cursor = root.to_path_buf();
    for level in 0..depth {
        cursor = cursor.join("d");
        std::fs::create_dir_all(&cursor)
            .map_err(|e| format!("cannot create level {level} of {depth}: {e}"))?;
    }
    let probe = cursor.join("probe.txt");
    std::fs::write(&probe, b"x")
        .map_err(|e| format!("cannot write a file at depth {depth}: {e}"))?;
    std::fs::read(&probe).map_err(|e| format!("cannot read the file at depth {depth}: {e}"))?;
    std::fs::remove_file(&probe)
        .map_err(|e| format!("cannot remove the file at depth {depth}: {e}"))?;
    Ok(())
}

/// **M3-a: 同一ノードのACE本数 M を 1・2・3 と振ったときの、初回伝播の時間。**
///
/// # 何が分かれば答えになるのか
///
/// HANDOFFは仮説を2つ立てている。**支配項がどちらかで結論が正反対になる。**
///
/// | 仮説 | 支配項 | Mを増やしたときの予測 |
/// |---|---|---|
/// | A | ツリーを歩くこと | 各ノードでDACLを1回書けば済むので **Mにほとんど依存しない** |
/// | B | ノードごとの書込回数 | ACEごとに1回ずつ書くと **M倍** |
///
/// §S9-3 は素朴な実装（＝[`WriteShape::OnePerSubject`]）で 1.77〜2.03倍を出しており、
/// **仮説Bの側**である。本測定が問うのは「**1回にまとめれば平坦になるか**」だけで、
/// その部品は2026-08-26に本流へ入った（`acl_dacl_write::grant_aces_propagating`）。
///
/// **部品が在ることと、大きいツリーで平坦であることは別の事実である。**
/// 部品の受け入れテスト（`acl_dacl_write_tests`）が確かめたのは真偽（届くか）だけで、
/// **時間は1点も測っていない**（FANOUT=4・FILES=24）。それが本測定の存在理由。
///
/// # M=1 も新部品で測る理由
///
/// §S10-1（1,200 ms／59.9 µs per node）は`grant_workspace_root_rw`＝
/// `grant_ace_mask_with(Propagate)`で測っており、**この部品を通らない別経路**である。
/// そのまま並べると「Mが効いたのか経路が違うのか」が分からないので、M=1もここで測り直す。
/// §S10-1と並べるときは**別経路の値である**と断ること。
#[test]
#[ignore = "creates tens of thousands of files and writes DACLs; run NON-elevated"]
fn acl_ace_count_cost_of_folding_m_subjects_into_one_write() {
    let count = file_count();
    let mut arms = Vec::new();

    // **腕ごとにツリーを作って壊す。** 4つ同時に置くとピークのディスクが4倍になるうえ、
    // 「前の腕が残したACE」が次の腕の初期状態を変える（初回を測れなくなる）。
    for (label, m, shape) in [
        ("merged_m1", 1usize, WriteShape::Merged),
        ("merged_m2", 2, WriteShape::Merged),
        ("merged_m3", 3, WriteShape::Merged),
        ("naive_m3", 3, WriteShape::OnePerSubject),
    ] {
        let dir = TestDirGuard::create(&format!("aclm-{label}"));
        let root = dir.path();
        let nodes = build_wide_tree(root, count, FANOUT);
        let subjects = m_subjects(label, m);
        let (leaf_dir, leaf_file) = wide_tree_leaves(root);
        arms.push(measure_arm(
            label, root, nodes, &subjects, &leaf_dir, &leaf_file, shape,
        ));
        eprintln!("  [{label}] done");
    }

    let ms = |i: usize| {
        arms[i]["propagate_ms"]
            .as_u64()
            .expect("propagate_ms is a number")
    };
    let (m1, m2, m3, naive3) = (ms(0), ms(1), ms(2), ms(3));
    let ratio = |a: u64, b: u64| {
        if b == 0 {
            f64::NAN
        } else {
            (a as f64) / (b as f64)
        }
    };

    println!(
        "{}",
        serde_json::json!({
            "measurement": "S15 M3-a cost of folding M subjects into one propagating write",
            "file_count": count,
            "fanout": FANOUT,
            "tree_shape": "wide (depth 2)",
            "arms": arms,
            "merged_m2_over_m1": ratio(m2, m1),
            "merged_m3_over_m1": ratio(m3, m1),
            "naive_m3_over_merged_m3": ratio(naive3, m3),
            "naive_m3_over_m1": ratio(naive3, m1),
        })
    );

    // **対照が効いていることだけをassertする。** M軸の比は測る当のものなので固定しない。
    // 1.5倍は「3回書きが1回書きより明確に遅い」を言える最小の線で、§S9-3の実測
    // （ACE2本で1.77〜2.03倍）より緩く取ってある——閾値を実測値ぎりぎりに置くと、
    // 測定ではなくマシンのノイズを判定することになる。
    assert!(
        ratio(naive3, m3) >= 1.5,
        "the control arm is not separating: writing three ACEs one-at-a-time ({naive3} ms) must \
         be clearly slower than folding them into one write ({m3} ms). If these are the same, \
         the merged path is not actually folding — read the arm JSON above before trusting any \
         of these numbers."
    );
}

/// **[BUG-145の案A] 配布を「root直下の子ごと」に分割すると遅くなるのか。**
///
/// # なぜこれが要るのか
///
/// 制御ディレクトリ`.harness/`が準備中だけサンドボックスから書ける欠陥
/// （[BUG-145](../../../../docs/bugs/BUG-145.md)）の直し方の第一候補が、
/// **配布の対象から制御ディレクトリを外す**——つまりrootへ1回ではなく直下の子ごとに
/// 配布を掛ける形である。実測で成立は確かめてある（`plans/mac-spike/RESULTS.md` §S30 ケース4）が、
/// **「OSが歩くファイル数は同じなので所要時間はほぼ変わらない」は理屈であって測っていない。**
/// 後戻りしにくい決定を未検証の費用見積りの上で下さないために、ここで測る。
///
/// # 2つの軸
///
/// **軸1はK（root直下の子の数）。** 総ファイル数を固定してKだけを振る——**K=1なら分割しても
/// 書込は1回**で、Kが増えるほど1回あたりの固定費が効いてくる。振らないと「変わらない」と
/// 言えない。このリポジトリの直下は20件なので、その前後を挟む。
///
/// **軸2は置き場。** `acl_dacl_write`のモジュールdocが「**同じ書込列でもツリーの置き場所で
/// 伝播の挙動が反転した**」実測を持っており、§S30でも同じ軸で結果が完全に割れた。
/// **実ワークスペースはユーザープロファイル配下にあるのに、既存の費用測定はすべて`C:\`直下**
/// なので、答えを使う場所の数字が無い。だから両方測る。
///
/// # 読むのは絶対値ではなく比（**限界**）
///
/// 12腕を回すので1腕あたりのファイル数を既定の半分にしてある。**既存の§S15とは絶対値で
/// 比べられない**——読むのは同じ置き場・同じKでの「分割 / まとめて」の比だけである。
///
/// **深さは振らない。** 浅く広いツリー（root → `dNNN/` → ファイルの2段）だけで測る。
/// 深さは2つの形へ同じだけ効くはずだが、**それは測っていない**（鎖ツリーの道具は
/// 下の`acl_ace_count_cost_of_tree_depth`が持っているので、必要になったら足せる）。
///
/// # 数字を読む前に3つの検算が通る
///
/// [`measure_arm`]の検算がそのまま効く。とくに2つ目——救済walkが全ノードを歩いて
/// **1件も書いていない**——が要で、これが「速かったのは何もしていなかったから」を弾く。
/// 分割の形では配布が届かない可能性が実際にある（§S30-6: 中間にカーネル口の書込があると
/// 配布がそこで止まる）ので、**届かなければ数字を読む前に落ちる。**
#[test]
#[ignore = "creates tens of thousands of files across 12 arms and writes DACLs; run NON-elevated"]
fn acl_ace_count_cost_of_splitting_the_propagating_write_per_top_level_child() {
    // 12腕あるので1腕あたりは既定の半分にする（`HARNESS_TEST_ACL_COST_NODES`で上書き可）。
    let count = file_count() / 2;
    // **Kはroot直下の子の数**で、`build_wide_tree`の`fanout`がそのまま対応する
    // （ファイルは`dNNN/`の下へ撒かれるので、rootの直下はそのK個のディレクトリだけ）。
    const K_VALUES: [usize; 3] = [1, 20, 200];

    let placements: [(&str, std::path::PathBuf); 2] = [
        ("drive-root", std::path::PathBuf::from("C:\\")),
        ("user-temp", std::env::temp_dir()),
    ];

    let mut arms = Vec::new();
    for (place_label, base) in &placements {
        for k in K_VALUES {
            for (shape_label, shape) in [
                ("merged", WriteShape::Merged),
                ("split", WriteShape::SplitPerTopLevelChild),
            ] {
                let label = format!("{place_label}-k{k}-{shape_label}");
                // **腕ごとにツリーを作って壊す。** 同時に置くとピークのディスクが12倍になり、
                // 前の腕が残したACEが次の腕の初期状態を変える（初回を測れなくなる）。
                let dir = TestDirGuard::create_in(base, &format!("aclsplit-{label}"));
                let root = dir.path();
                let nodes = build_wide_tree(root, count, k);
                let subjects = m_subjects(&label, 1);
                let (leaf_dir, leaf_file) = wide_tree_leaves(root);
                let mut arm = measure_arm(
                    &label, root, nodes, &subjects, &leaf_dir, &leaf_file, shape,
                );
                arm["placement"] = serde_json::json!(place_label);
                arm["k_top_level_children"] = serde_json::json!(k);
                arms.push(arm);
                eprintln!("  [{label}] done");
            }
        }
    }

    let ms = |i: usize| {
        arms[i]["propagate_ms"]
            .as_u64()
            .expect("propagate_ms is a number")
    };
    let ratio = |a: u64, b: u64| {
        if b == 0 {
            f64::NAN
        } else {
            (a as f64) / (b as f64)
        }
    };
    // 腕は (置き場, K) ごとに merged→split の順で積んである。
    let mut split_over_merged = serde_json::Map::new();
    for (index, (place_label, _)) in placements.iter().enumerate() {
        for (j, k) in K_VALUES.iter().enumerate() {
            let base = (index * K_VALUES.len() + j) * 2;
            split_over_merged.insert(
                format!("{place_label}-k{k}"),
                serde_json::json!(ratio(ms(base + 1), ms(base))),
            );
        }
    }

    println!(
        "{}",
        serde_json::json!({
            "measurement": "S31 cost of splitting the propagating write per top-level child (BUG-145 案A)",
            "file_count_per_arm": count,
            "k_values": K_VALUES,
            "tree_shape": "wide (depth 2)",
            "arms": arms,
            "split_over_merged": split_over_merged,
        })
    );

    // **合否は判定しない。** 比そのものが測る当のもので、閾値を置くと
    // 「マシンのノイズ」を判定することになる（上の`..._folding_...`が対照を持つのは、
    // あちらには「素朴な形は明確に遅い」という既知の下限があるからである）。
    // ここでassertするのは**実験の前提だけ**——`measure_arm`の3検算が既に効いており、
    // 配布が届いていない腕はそこで落ちる。加えて、Kが実際に振れていることを見る。
    for (index, (place_label, _)) in placements.iter().enumerate() {
        for (j, k) in K_VALUES.iter().enumerate() {
            let base = (index * K_VALUES.len() + j) * 2;
            for offset in [0usize, 1] {
                assert_eq!(
                    arms[base + offset]["k_top_level_children"],
                    serde_json::json!(*k),
                    "[{place_label}] 腕の並びとKの対応がずれている。比の計算が別の腕を指している"
                );
            }
        }
    }
}

/// 「置き場 × 深さ × 主体の本数」の各セルで、**まとめて／分割を対で**測る。
/// 腕のJSONと、セルごとの `分割 ÷ まとめて` を返す。
///
/// **まとめて→分割は必ず隣り合わせに積む。** 時間とともに動くもの（ディスクの状態・
/// キャッシュの温まり）を、比の分子と分母へほぼ等しく乗せるためである。
///
/// **比はセルの中で作る**（腕の並びから添字で拾い直さない）。§S31のテストは後者の形なので、
/// 「腕の並びと K の対応がずれていないか」を確かめるassertを別に置く必要があった——
/// **ずれ得る書き方をやめれば、その検算ごと要らなくなる。**
///
/// `count`・`k`・`depths`・`subject_counts`だけを呼び出し側が決める。置き場と形は
/// **どの測定でも同じ2水準**なのでここに固定してある。
fn measure_split_vs_merged_cells(
    count: usize,
    ks: &[usize],
    depths: &[usize],
    subject_counts: &[usize],
    tree: TreeShape,
) -> (Vec<serde_json::Value>, serde_json::Map<String, serde_json::Value>) {
    let placements: [(&str, std::path::PathBuf); 2] = [
        ("drive-root", std::path::PathBuf::from("C:\\")),
        ("user-temp", std::env::temp_dir()),
    ];

    let mut arms = Vec::new();
    let mut ratios = serde_json::Map::new();
    for (place_label, base) in &placements {
        for &k in ks {
            for &depth in depths {
                for &m in subject_counts {
                    let cell = format!("{place_label}-k{k}-d{depth}-m{m}-{}", tree.label());
                    let mut cell_ms = [0u64; 2];
                    for (slot, (shape_label, shape)) in [
                        ("merged", WriteShape::Merged),
                        ("split", WriteShape::SplitPerTopLevelChild),
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        let label = format!("{cell}-{shape_label}");
                        // **腕ごとにツリーを作って壊す。** 同時に置くとピークのディスクが
                        // 腕数倍になり、前の腕が残したACEが次の腕の初期状態を変える
                        // （初回を測れなくなる）。
                        let dir = TestDirGuard::create_in(base, &format!("aclfor-{label}"));
                        let root = dir.path();
                        let nodes = tree.build(root, count, k, depth);
                        let subjects = m_subjects(&label, m);
                        let (leaf_dir, leaf_file) = tree.leaves(root, depth);
                        let mut arm = measure_arm(
                            &label, root, nodes, &subjects, &leaf_dir, &leaf_file, shape,
                        );
                        arm["placement"] = serde_json::json!(place_label);
                        arm["k_top_level_children"] = serde_json::json!(k);
                        arm["depth"] = serde_json::json!(depth);
                        arm["tree"] = serde_json::json!(tree.label());
                        cell_ms[slot] = arm["propagate_ms"]
                            .as_u64()
                            .expect("propagate_ms is a number");
                        arms.push(arm);
                        eprintln!("  [{label}] done");
                    }
                    let ratio = if cell_ms[0] == 0 {
                        f64::NAN
                    } else {
                        (cell_ms[1] as f64) / (cell_ms[0] as f64)
                    };
                    ratios.insert(cell, serde_json::json!(ratio));
                }
            }
        }
    }
    (arms, ratios)
}

/// ツリーの中身の**偏り方**。
///
/// **実ワークスペースは一様ではない**——このリポジトリならファイルの大半が`target/`に集まる。
/// 分割の形はroot直下の子ごとに書込を掛けるので、**1本に集中していると「Kが実質1本」に
/// 近づく**。それが比を動かすのかを見るための軸である。
#[derive(Clone, Copy, Debug)]
enum TreeShape {
    /// `k`本の枝へ均等に撒く（これまでの全測定の形）。
    Uniform,
    /// **1本目の枝へ8割**、残り2割を他の`k-1`本へ撒く。
    SkewedOneBranch,
}

impl TreeShape {
    fn label(self) -> &'static str {
        match self {
            Self::Uniform => "uniform",
            Self::SkewedOneBranch => "skewed",
        }
    }

    /// 期待ノード数。**偏った形は一様な形より1ノードだけ多い**（重い枝の付け根`dbig`のぶん）。
    /// ファイル数もディレクトリ数も他は同じなので、比の読みには影響しない。
    /// **ここを書いておくのは、腕が注文どおりの形を受け取ったかを機械で見るためである。**
    fn expected_nodes(self, count: usize, k: usize, depth: usize) -> usize {
        match self {
            Self::Uniform => 1 + k * depth + count,
            Self::SkewedOneBranch => 2 + k * depth + count,
        }
    }

    /// 検算に使う**最深部の葉**。偏った形では**重い枝の側**を見る
    /// ——ファイルの8割がそこにあるので、そこへ届いていないのに緑になっては意味が無い。
    fn leaves(self, root: &Path, depth: usize) -> (std::path::PathBuf, std::path::PathBuf) {
        match self {
            Self::Uniform => forest_tree_leaves(root, depth),
            // 重い枝は`build_forest_tree(root/dbig, …, k=1, depth)`で掘ってあるので、
            // **その`dbig`を起点にした同じ計算**がそのまま使える（規則5: 数え方を2つ持たない）。
            Self::SkewedOneBranch => forest_tree_leaves(&root.join("dbig"), depth),
        }
    }

    /// ツリーを作ってノード数を返す。
    ///
    /// 偏った形は[`super::test_support::build_forest_tree`]を**2回呼んで**作る
    /// （新しい生成器を作らない、`docs/CODE-STRUCTURE-RULES.md`規則5）。
    fn build(self, root: &Path, count: usize, k: usize, depth: usize) -> usize {
        match self {
            Self::Uniform => super::test_support::build_forest_tree(root, count, k, depth),
            Self::SkewedOneBranch => {
                assert!(k >= 2, "偏らせるには枝が2本以上要る");
                let heavy = count * 8 / 10;
                let rest = count - heavy;
                // 残り2割を`k-1`本の一様な森へ。枝の名前は`d000..d{k-2}`になる。
                let light_nodes =
                    super::test_support::build_forest_tree(root, rest, k - 1, depth);
                // 8割を`k`本目の枝（`dbig`）へ。**1本の枝＝`k=1`の森**として掘る。
                let heavy_root = root.join("dbig");
                let heavy_nodes =
                    super::test_support::build_forest_tree(&heavy_root, heavy, 1, depth);
                // `heavy_root`自身が1ノード、その配下は`heavy_nodes`（rootぶんの1を含む）。
                light_nodes + heavy_nodes
            }
        }
    }
}

/// 各腕が**注文どおりの形のツリー**を受け取ったかを見る。
///
/// [`measure_arm`]の3検算は「配布が届いたか」を見るが、**ツリーがそもそも注文した深さで
/// 作られたか**は見ていない。`build_forest_tree`が深さを無視しても、
/// `k * depth`個ではなく`k`個のディレクトリができるだけで配布は全部届き、
/// **3検算は全部通ってしまう**（`f{depth-1}.txt`が1本目の枝に載るので葉の検算も通る）。
/// **深さを振ったつもりで振れていない測定**は、そのまま結果として記録されてしまう。
fn assert_arms_got_the_tree_they_asked_for(
    arms: &[serde_json::Value],
    tree: TreeShape,
    count: usize,
) {
    for arm in arms {
        let depth = arm["depth"].as_u64().expect("depth is a number") as usize;
        let k = arm["k_top_level_children"]
            .as_u64()
            .expect("k is a number") as usize;
        let nodes = arm["nodes"].as_u64().expect("nodes is a number") as usize;
        assert_eq!(
            nodes,
            tree.expected_nodes(count, k, depth),
            "腕 {} のノード数が注文と違う。K・深さ・偏りのどれかが実際には振れていない",
            arm["arm"]
        );
    }
}

/// **[BUG-145の案A] 分割の費用は、ツリーの深さと主体の本数で変わるのか。**
///
/// # なぜこれが要るのか
///
/// §S31は分割の費用を12腕で測ったうえで、**3つの軸を振っていない**と自分で書いた——
/// 深さ・主体の本数・製品の規模である。案Aを採るかは後戻りしにくい決定なので、
/// **「振っていない」と書いたまま決めない。**
///
/// 本テストはそのうち**2つ**（深さと主体）を、§S31と同じ10,000ファイル／腕で埋める。
/// 3つ目（26万ノード）は[`acl_ace_count_cost_of_splitting_at_production_scale`]が
/// **同じ形のまま規模だけを変えて**測る。
///
/// # 軸の値はこのリポジトリの実測から取っている（**思いつきの値を振らない**）
///
/// | 軸 | 値 | 根拠 |
/// |---|---|---|
/// | K（root直下の子の数） | **20**で固定 | このリポジトリの直下が20件 |
/// | 深さ | 1 と **8** | このリポジトリのディレクトリの最大深さが8 |
/// | 主体 | 1 と **2** | 製品は`WorkspaceMode::ALL`＝2モードぶんのcapability SIDを配る（D-84） |
/// | 置き場 | `C:\`直下 と `%TEMP%`配下 | §S30では置き場で結果が完全に反転した |
///
/// # 読むのは「セルの中の比」だけである（**限界**）
///
/// 深さを変えるとディレクトリの数が変わる（K=20・深さ8なら160個）ので、
/// **深さの違う腕どうしを絶対値で比べてはいけない**。読むのは各セルの
/// `分割 ÷ まとめて` で、その比を深さ軸・主体軸に沿って並べる。
///
/// # 寿命（**M3とは別である**）
///
/// このファイルのM3ブロックは`docs/STATUS.md`残課題#20が終わったら消す約束だが、
/// 本テストと§S31のテストは**BUG-145の案Aの採否**が決まったら消す。接頭辞を共有している
/// だけで、**消す条件が違う**。
#[test]
#[ignore = "creates tens of thousands of files across 16 arms and writes DACLs; run NON-elevated"]
fn acl_ace_count_cost_of_splitting_across_depth_and_subject_count() {
    // §S31と同じ規模にする（あちらのK=20・深さ1・主体1本のセルと直接並べられるように）。
    let count = file_count() / 2;
    const K: usize = 20;
    const DEPTHS: [usize; 2] = [1, 8];
    const SUBJECT_COUNTS: [usize; 2] = [1, 2];

    let (arms, ratios) =
        measure_split_vs_merged_cells(count, &[K], &DEPTHS, &SUBJECT_COUNTS, TreeShape::Uniform);

    println!(
        "{}",
        serde_json::json!({
            "measurement": "S33 cost of splitting per top-level child, across depth and subject count (BUG-145 案A)",
            "file_count_per_arm": count,
            "k_top_level_children": K,
            "depths": DEPTHS,
            "subject_counts": SUBJECT_COUNTS,
            "arms": arms,
            "split_over_merged": ratios,
        })
    );

    // **合否は判定しない**（比そのものが測る当のもので、閾値を置くとマシンのノイズを判定する）。
    // assertするのは実験の前提だけ——`measure_arm`の3検算に加えて、
    // **注文した形のツリーで測ったこと**を見る。
    assert_eq!(
        arms.len(),
        2 * DEPTHS.len() * SUBJECT_COUNTS.len() * 2,
        "腕が欠けている。比の一覧が全セルを覆っていない"
    );
    assert_eq!(
        ratios.len(),
        2 * DEPTHS.len() * SUBJECT_COUNTS.len(),
        "セルの数と比の数が合わない"
    );
    assert_arms_got_the_tree_they_asked_for(&arms, TreeShape::Uniform, count);
}

/// **[BUG-145の案A] 製品と同じ26万ノード規模で、分割はいくら高くつくのか。**
///
/// §S31-3は「固定費の割合はツリーが大きくなるほど小さくなる」を500と10,000の2点で示し、
/// **26万への外挿は理屈であって測っていない**と書いた。ここがその1点である。
///
/// # 上の`..._across_depth_and_subject_count`と**1つしか違わない**
///
/// K=20・深さ8・主体2本・置き場2水準・形2水準まで同じで、変えるのは**ファイル数だけ**
/// （10,000 → 260,000）。だから2つの結果の比を並べれば、差はまるごと規模の効果になる。
/// ほかも一緒に変えると「規模のせいか形のせいか」が言えなくなる。
///
/// # 26万という値の根拠
///
/// **このリポジトリの実測が248,766ノード**（`find | wc -l`）で、§S10-1が基準線を取ったのも
/// 260,033ノードである。既定値を`HARNESS_TEST_ACL_PRODUCTION_NODES`で落とせる。
///
/// # 所要時間とディスク（**先に言っておく**）
///
/// §S10-1の実測から、26万ノードでは1腕あたり配布16秒・救済walk27秒×主体数・撤収19秒に
/// ツリーの生成と撤収後の読み直しが乗る。**4腕で20分前後**を見込むこと。
/// ツリーは腕ごとに作って壊すのでピークは1本ぶん（26万ファイル×クラスタで約1GB）である。
#[test]
#[ignore = "creates 260,000 files per arm across 4 arms (~20 min, ~1GB peak); run NON-elevated"]
fn acl_ace_count_cost_of_splitting_at_production_scale() {
    let count = production_file_count();
    const K: usize = 20;
    const DEPTHS: [usize; 1] = [8];
    const SUBJECT_COUNTS: [usize; 1] = [2];

    let (arms, ratios) =
        measure_split_vs_merged_cells(count, &[K], &DEPTHS, &SUBJECT_COUNTS, TreeShape::Uniform);

    println!(
        "{}",
        serde_json::json!({
            "measurement": "S33 cost of splitting per top-level child at production scale (BUG-145 案A)",
            "file_count_per_arm": count,
            "k_top_level_children": K,
            "depths": DEPTHS,
            "subject_counts": SUBJECT_COUNTS,
            "arms": arms,
            "split_over_merged": ratios,
        })
    );

    assert_eq!(arms.len(), 4, "腕が欠けている");
    assert_arms_got_the_tree_they_asked_for(&arms, TreeShape::Uniform, count);
}

/// **[BUG-145の案A] 残った2軸——Kとの交互作用、そして偏ったツリー。**
///
/// これが分割の費用について**最後に残っていた「測っていないこと」**である。
///
/// | 軸 | これまで | ここで埋めるもの |
/// |---|---|---|
/// | K × 深さ × 主体 | Kは「10,000ファイル・深さ1・主体1本」でしか振っていない | 3つを**同時に**振る |
/// | ツリーの偏り | 一様な森だけ（全枝が同じ深さ・ファイルが均等） | **1本の枝へ8割**を集める |
///
/// # 偏りが比を動かし得る理由（**なぜこの軸が要るのか**）
///
/// 分割はroot直下の子ごとに配布書込を掛けるので、**1本の枝へ集中していると
/// 「Kが実質1本」に近づく**。実ワークスペースはまさにそうで、このリポジトリなら
/// ファイルの大半が`target/`に入る。**一様な森だけで測って「変わらない」と言うのは、
/// 実物と違う形で測っている**。
///
/// # 読むのはセルの中の比だけである（**限界**）
///
/// Kも深さも偏りもノード数を変えるので、**セルをまたいだ絶対値の比較はできない**。
#[test]
#[ignore = "creates tens of thousands of files across 28 arms and writes DACLs; run NON-elevated"]
fn acl_ace_count_cost_of_splitting_across_k_and_tree_skew() {
    let count = file_count() / 2;
    const KS: [usize; 3] = [1, 20, 200];
    const DEPTHS: [usize; 2] = [1, 8];
    const SUBJECT_COUNTS: [usize; 1] = [2];

    // 軸1: K × 深さ（主体は製品と同じ2本に固定）。K=1は**分割しても書込1回**の対照。
    let (mut arms, mut ratios) =
        measure_split_vs_merged_cells(count, &KS, &DEPTHS, &SUBJECT_COUNTS, TreeShape::Uniform);
    assert_arms_got_the_tree_they_asked_for(&arms, TreeShape::Uniform, count);

    // 軸2: 偏り。**K=20・深さ8**（このリポジトリと同じ形）でだけ振る——偏りとKを
    // 同時に振ると、比が動いたときにどちらのせいか言えなくなる。
    let (skewed_arms, skewed_ratios) = measure_split_vs_merged_cells(
        count,
        &[20],
        &[8],
        &SUBJECT_COUNTS,
        TreeShape::SkewedOneBranch,
    );
    assert_arms_got_the_tree_they_asked_for(&skewed_arms, TreeShape::SkewedOneBranch, count);

    arms.extend(skewed_arms);
    for (k, v) in skewed_ratios {
        ratios.insert(k, v);
    }

    println!(
        "{}",
        serde_json::json!({
            "measurement": "S35 cost of splitting across K and tree skew (BUG-145 案A、最後の2軸)",
            "file_count_per_arm": count,
            "k_values": KS,
            "depths": DEPTHS,
            "subject_counts": SUBJECT_COUNTS,
            "arms": arms,
            "split_over_merged": ratios,
        })
    );

    // **合否は判定しない**（比そのものが測る当のもの）。腕が欠けていないことだけを見る。
    assert_eq!(
        arms.len(),
        2 * KS.len() * DEPTHS.len() * SUBJECT_COUNTS.len() * 2 + 2 * 2,
        "腕が欠けている。比の一覧が全セルを覆っていない"
    );
}

/// [`super::test_support::build_forest_tree`]の`depth = 1`が
/// [`build_wide_tree`]と**同じツリーである**こと。
///
/// `build_wide_tree`は§S9・§S10・§S15と、このファイルの既存の測定すべての土台である。
/// 深さを振れるようにするため`build_forest_tree`へ委譲させたので、**形が変わっていたら
/// 過去の数字と並べられなくなる**。委譲した瞬間だけでなく、以後どちらかを触ったときにも
/// 落ちるように、**両方を実際に作って相対パスの集合を突き合わせる**。
///
/// **`#[ignore]`を付けない。** 作るのは十数ノードでDACLを一切書かないので通常のテスト実行で
/// 走る——`#[ignore]`の側に置くと、委譲が壊れても誰も気付かないまま過去の数字と
/// 並べ続けることになる（この検算はそのためだけに在る）。
///
/// 置き場は`%TEMP%`にする。祖先を辿る口を一切通さないので[`TestDirGuard::create_in`]の
/// 条件を満たしており、`C:\`直下に置くと**通常のテスト実行がドライブルートへ書く**ことになる。
#[test]
fn forest_tree_with_depth_one_is_the_wide_tree() {
    const FILES: usize = 11;
    const K: usize = 3;

    let base = std::env::temp_dir();
    let wide = TestDirGuard::create_in(&base, "forest-eq-wide");
    let forest = TestDirGuard::create_in(&base, "forest-eq-forest");

    let wide_nodes = build_wide_tree(wide.path(), FILES, K);
    let forest_nodes = super::test_support::build_forest_tree(forest.path(), FILES, K, 1);

    let list = |root: &Path| -> Vec<String> {
        let mut dirs = Vec::new();
        let mut files = Vec::new();
        super::acl_grant::collect_dirs_and_files(root, &mut dirs, &mut files, OnVanished::Abort)
            .expect("enumerate the tree");
        let mut out: Vec<String> = dirs
            .into_iter()
            .chain(files)
            .map(|p| {
                p.strip_prefix(root)
                    .map(|r| r.to_string_lossy().to_lowercase())
                    .unwrap_or_default()
            })
            .collect();
        out.sort();
        out
    };

    assert_eq!(
        wide_nodes, forest_nodes,
        "ノード数が違う。`build_wide_tree`の数え方が変わっている"
    );
    assert_eq!(
        list(wide.path()),
        list(forest.path()),
        "ディレクトリ名かファイルの配置が違う。§S9・§S10・§S15の数字と並べられない形になっている"
    );
    // **対の検算**（`B-35`）——上のassertは「同じなら緑」なので、比較器が常に等しいと
    // 言っているだけでも通る。深さを変えれば**違うと言えること**まで見る。
    let deeper = TestDirGuard::create_in(&base, "forest-eq-deep");
    super::test_support::build_forest_tree(deeper.path(), FILES, K, 2);
    assert_ne!(
        list(wide.path()),
        list(deeper.path()),
        "深さ2の森が深さ1と同じ形に見えている。この比較器は差を検出できていない"
    );
}

/// **M3-c: 伝播のコストは、ツリーの深さで変わるのか。**
///
/// # なぜこれが要るのか
///
/// §S9・§S10 の数字はすべて[`build_wide_tree`]＝**深さ2段固定**のツリーで取られている。
/// `plans/mac-spike/RESULTS.md` は3箇所で「深さの効果は測っていない」と明記しており、
/// **実ワークスペース（`node_modules`・`target`）は平気で深くなる**ので、
/// 「ノード数に線形」という結論がその形でも成り立つかは別の事実である。
///
/// # 一変数だけ動かす
///
/// `build_chain_tree(root, F, 32)` と `build_wide_tree(root, F, 32)` は
/// **ノード数・ディレクトリ数・ファイル数が完全に一致**し、違うのは並べ方だけである
/// （前者は一列、後者は1段）。**だから`chain_d33`と`flat_d2`の差は、まるごと深さの効果になる。**
/// テストの中でノード数の一致をassertしてあるのはそのため——ここがずれたら比較が成立しない。
///
/// # 深さ129の腕だけは変数が2つ動く（**限界。外挿しないこと**）
///
/// 段名を1文字にしてあるので深さ`N`のパス長は`2N`文字ぶんしか伸びず、
/// **`chain_d65`まではWindowsの伝統的なパス長上限（MAX_PATH=260）の内側**に収まる。
/// `chain_d129`はその外側で、**深さとパス長が同時に動く**——差が出てもどちらのせいかは言えない。
///
/// **それでもこの腕を置くのは、時間ではなく真偽を測るためである。**
/// ACL側は`long_path_wide`が長いパス用の接頭辞を付けるので書けるはずだが、
/// 救済walkのディレクトリ走査と撤収が同じように通るかは確かめられていない。
/// **ここで「深いところだけACEが付かないのに成功と報告される」なら、それは実ワークスペースで
/// 現に起きうる無言失敗である**（このリポジトリが繰り返し踏んでいる形）。
///
/// 最後の腕（`chain_d33_m3`）は**2つの軸が独立か**を見る。M3-aの `merged_m3 / merged_m1` と
/// ここの `chain_d33_m3 / chain_d33` がずれたら、深さとMは掛け算にならない。
#[test]
#[ignore = "creates tens of thousands of files at up to 129 levels deep; run NON-elevated"]
fn acl_ace_count_cost_of_tree_depth() {
    let count = file_count();
    let mut arms = Vec::new();
    let mut node_counts: Vec<(&str, usize)> = Vec::new();

    // 平らな基準。M3-aの`merged_m1`と同じ形・同じ主体数で、**この測定の中でも取り直す**
    // （別々の実行の数字を混ぜないため）。
    {
        let dir = TestDirGuard::create("acld-flat");
        let root = dir.path();
        let nodes = build_wide_tree(root, count, FANOUT);
        let subjects = m_subjects("flat", 1);
        let (leaf_dir, leaf_file) = wide_tree_leaves(root);
        node_counts.push(("flat_d2", nodes));
        arms.push(measure_arm(
            "flat_d2",
            root,
            nodes,
            &subjects,
            &leaf_dir,
            &leaf_file,
            WriteShape::Merged,
        ));
        eprintln!("  [flat_d2] done");
    }

    for (label, depth, m) in [
        ("chain_d33", 32usize, 1usize),
        ("chain_d65", 64, 1),
        ("chain_d129", 128, 1),
        ("chain_d33_m3", 32, 3),
    ] {
        let dir = TestDirGuard::create(&format!("acld-{label}"));
        let root = dir.path();

        // **ファイルを2万個撒く前に、その深さが本当に使えるかを1個で確かめる。**
        // 使えないまま突っ込むと、後始末（`remove_dir_all`）も同じ上限に当たって
        // **実マシンに残骸が残る**（B-01: 付けたものを剥がせるかを先に見る）。
        if let Err(reason) = probe_chain_depth(root, depth) {
            eprintln!("  [{label}] SKIPPED: {reason}");
            arms.push(serde_json::json!({
                "arm": label,
                "depth": depth + 1,
                "usable": false,
                "reason": reason,
            }));
            continue;
        }

        let nodes = super::test_support::build_chain_tree(root, count, depth);
        let subjects = m_subjects(label, m);
        let (leaf_dir, leaf_file) = chain_tree_leaves(root, depth);
        node_counts.push((label, nodes));
        let mut arm = measure_arm(
            label,
            root,
            nodes,
            &subjects,
            &leaf_dir,
            &leaf_file,
            WriteShape::Merged,
        );
        arm["depth"] = serde_json::json!(depth + 1);
        arm["usable"] = serde_json::json!(true);
        arm["deepest_leaf_path_len"] =
            serde_json::json!(leaf_file.to_string_lossy().chars().count());
        arms.push(arm);
        eprintln!("  [{label}] done");
    }

    println!(
        "{}",
        serde_json::json!({
            "measurement": "S15 M3-c does the propagation cost depend on tree depth",
            "file_count": count,
            "arms": arms,
        })
    );

    // **深さの比較が成立する前提を固定する。** `flat_d2`と`chain_d33`はノード数まで
    // 同じでなければならない——ずれていたら、差を「深さのせい」と読めない。
    let find = |want: &str| {
        node_counts
            .iter()
            .find(|(l, _)| *l == want)
            .map(|(_, n)| *n)
    };
    if let (Some(flat), Some(chain)) = (find("flat_d2"), find("chain_d33")) {
        assert_eq!(
            flat, chain,
            "the flat and the 33-deep arm must contain exactly the same number of nodes, \
             otherwise their timings differ for a reason other than depth"
        );
    }
}
