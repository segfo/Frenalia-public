//! 2つのレーンが**同じ到達状態**を作ることを固定する（[D-88（`DESIGN-SANDBOX-APPPOLICY.md`）]）。
//!
//! # なぜこれが要るのか
//!
//! lazyレーンは「途中に割り込みを入れられる」ために伝播をやめた形で、**結果は既定レーンと
//! 同じでなければならない**。ここが違うと、レーンを切り替えた瞬間にworkspaceの一部が
//! サンドボックスから見えなくなる——そして**症状は「なぜかファイルが無いと言われる」**
//! という、原因のたどりにくい形で出る（`grant_job`のモジュールdoc）。
//!
//! **`start`ではなくレーン関数を直に呼ぶ。** `start`は`%APPDATA%`の capability 台帳へ
//! 準備状態を書くので、テストが実マシンの台帳へエントリを積む。ここで測りたいのは
//! **ツリーのDACLがどうなるか**だけなので、台帳を触らない層で測る。
//!
//! **昇格しない**（主体は純粋導出、ツリーはテスト自身が作ったもの）。

use std::sync::Arc;

use super::{run_full_walk_lane, run_lazy_lane, JobState, LazyLanePrep};
use crate::tier2a::win_appcontainer as wac;
use wac::test_support::TestDirGuard;
use wac::{capability_sid_from_name, workspace_rwx_mask, OwnedAceGrant};

fn lane_grants(label: &str) -> Vec<OwnedAceGrant> {
    let sid = capability_sid_from_name(&format!("harness-lane-{}-{label}", std::process::id()))
        .expect("derive the test capability sid");
    vec![OwnedAceGrant {
        sid,
        mask: workspace_rwx_mask(),
    }]
}

/// ツリーの全ノードについて「この主体へ届いているか」を集めた一覧を返す。
/// **rootからの相対パスで持つ**ので、2つのレーンを別々のディレクトリで走らせても比較できる。
fn reachability(root: &std::path::Path, grants: &[OwnedAceGrant]) -> Vec<(String, bool)> {
    let sids: Vec<_> = grants.iter().map(|g| g.sid.as_psid()).collect();
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    wac::acl_grant::collect_dirs_and_files(root, &mut dirs, &mut files, wac::OnVanished::Abort)
        .expect("enumerate the tree");
    let mut out: Vec<(String, bool)> = dirs
        .into_iter()
        .chain(files)
        .map(|node| {
            let rel = node
                .strip_prefix(root)
                .map(|p| p.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            let reached = wac::revoke::sid_effective_ace_masks(&node, &sids)
                .map(|masks| masks.iter().all(Option::is_some))
                .unwrap_or(false);
            (rel, reached)
        })
        .collect();
    out.sort();
    out
}

/// 比較用に**同じ形**のツリーを作る。**ノード数は11**——ディレクトリ4
/// （root・`a`・`a/nested`・`b`）＋ファイル7（root2・`a`2・`a/nested`2・`b`1）。
fn build_tree(root: &std::path::Path) {
    std::fs::create_dir_all(root.join("a").join("nested")).expect("create nested dirs");
    std::fs::create_dir_all(root.join("b")).expect("create dir b");
    for (dir, count) in [("", 2), ("a", 2), ("a/nested", 2), ("b", 1)] {
        for i in 0..count {
            let path = if dir.is_empty() {
                root.join(format!("f{i}.txt"))
            } else {
                root.join(dir).join(format!("f{i}.txt"))
            };
            std::fs::write(&path, b"x").expect("write file");
        }
    }
}

/// **同じツリー形状に対して、2つのレーンは同じ到達状態を作る。**
///
/// 対で見る（`B-35`）——「lazyで全部届いた」だけを測ると、既定レーンが実は一部を
/// 取りこぼしている場合に気付けない。**2つを並べて、かつどちらも全件届いている**ことを見る。
#[test]
fn both_lanes_leave_every_node_reachable_and_agree_with_each_other() {
    let guard = TestDirGuard::create("lane-compare");
    let eager_root = guard.path().join("eager");
    let lazy_root = guard.path().join("lazy");
    build_tree(&eager_root);
    build_tree(&lazy_root);

    let eager_grants = lane_grants("eager");
    let lazy_grants = lane_grants("lazy");

    let state = Arc::new(JobState::default());
    run_full_walk_lane(&eager_root, &eager_grants, &[], &[], &state)
        .expect("the default lane must succeed");
    let state = Arc::new(JobState::default());
    run_lazy_lane(&lazy_root, LazyLanePrep::open(&lazy_root, &lazy_grants, &[], &state), &[], &[], &state)
        .expect("the lazy lane must succeed");

    let eager = reachability(&eager_root, &eager_grants);
    let lazy = reachability(&lazy_root, &lazy_grants);

    assert_eq!(
        eager.len(),
        11,
        "the comparison is meaningless if the tree is not the shape we think it is"
    );
    assert!(
        eager.iter().all(|(_, reached)| *reached),
        "the default lane must reach every node: {eager:?}"
    );
    assert_eq!(
        lazy, eager,
        "the lazy lane must produce the same reachability as the default lane, node for node"
    );
}

/// lazyレーンは`skip`（`.harness/`）へ**降りない**。
///
/// 既定レーンは伝播が`.harness/`へ物理コピーを届け得るので**後から剥がす**形だが、
/// lazyレーンは最初から触らない。**どちらの形でも、終わったときに制御面が
/// サンドボックスから書けないことは同じでなければならない**（D-05/D-09）。
#[test]
fn the_lazy_lane_does_not_grant_inside_the_control_directory() {
    let guard = TestDirGuard::create("lane-skip");
    let root = guard.path().join("ws");
    let control = root.join(".harness");
    std::fs::create_dir_all(&control).expect("create the control dir");
    std::fs::write(control.join("state.json"), b"{}").expect("write control state");
    std::fs::write(root.join("src.txt"), b"x").expect("write a normal file");

    let grants = lane_grants("skip");
    let state = Arc::new(JobState::default());
    let skip = std::slice::from_ref(&control);
    run_lazy_lane(
        &root,
        LazyLanePrep::open(&root, &grants, skip, &state),
        &[],
        skip,
        &state,
    )
    .expect("the lazy lane must succeed");

    let map: std::collections::HashMap<String, bool> = reachability(&root, &grants)
        .into_iter()
        .collect();
    assert_eq!(
        map.get("src.txt"),
        Some(&true),
        "the workspace itself must be reachable"
    );
    assert_eq!(
        map.get(".harness"),
        Some(&false),
        "the control directory must not be granted"
    );
    assert_eq!(
        map.get(".harness\\state.json"),
        Some(&false),
        "the scan must not descend into the control directory"
    );
}

/// lazyレーンは**fault受付を開き、終わったら名前を消して件数だけ残す**。
///
/// 名前を残すと、起動側が**既に無い受付**へ子を向ける（`B-14`: 記録の存在で実体の存在を
/// 代替しない）。件数を消すと、「割り込みが成立したか」を事後に測れない
/// （設計書§5.1.3の検証6が要求する唯一の数字）。**対で見ないと、どちらの間違いも無症状である。**
#[test]
fn the_lazy_lane_opens_a_fault_receiver_and_retires_its_name_but_keeps_the_count() {
    let guard = TestDirGuard::create("lane-broker");
    let root = guard.path().join("ws");
    build_tree(&root);

    let grants = lane_grants("broker");
    let state = Arc::new(JobState::default());
    assert!(
        state.broker_pipe.lock().unwrap().is_none(),
        "nothing is published before the lane runs"
    );

    run_lazy_lane(&root, LazyLanePrep::open(&root, &grants, &[], &state), &[], &[], &state).expect("the lazy lane must succeed");

    assert!(
        state.broker_pipe.lock().unwrap().is_none(),
        "the pipe name must be retired once the receiver is closed"
    );
    assert_eq!(
        *state.broker_faults_served.lock().unwrap(),
        Some(0),
        "Some(0) means the receiver was open and no interrupt arrived; None would mean \
         it was never opened at all, and those two must never be confused"
    );
}

/// 既定レーンは受付を開かない。**`None`のままである**ことを固定する
/// ——ここが`Some(0)`になると、「受付があったのに1件も来なかった」と読めてしまう。
#[test]
fn the_default_lane_reports_no_fault_receiver_at_all() {
    let guard = TestDirGuard::create("lane-nobroker");
    let root = guard.path().join("ws");
    build_tree(&root);

    let state = Arc::new(JobState::default());
    run_full_walk_lane(&root, &lane_grants("nobroker"), &[], &[], &state)
        .expect("the default lane must succeed");

    assert_eq!(*state.broker_faults_served.lock().unwrap(), None);
    assert!(state.broker_pipe.lock().unwrap().is_none());
}

/// lazyレーンは**走査した数と書いた数の両方**を残す。
///
/// 既定レーンでは「書いた数(`rescue_granted`)が0でない」が退化の兆候だったが、
/// **このレーンでは0でないのが正常**である（`run_lazy_lane`のdoc）。だから
/// 「見た数」と対で残さないと、**1件も歩かなかった**のか**全部届いていた**のかが
/// 区別できない（`B-35`）。
#[test]
fn the_lazy_lane_records_both_how_many_it_saw_and_how_many_it_wrote() {
    use std::sync::atomic::Ordering;

    let guard = TestDirGuard::create("lane-counts");
    let root = guard.path().join("ws");
    build_tree(&root);

    let grants = lane_grants("counts");
    let state = Arc::new(JobState::default());
    run_lazy_lane(&root, LazyLanePrep::open(&root, &grants, &[], &state), &[], &[], &state).expect("first pass");
    let checked = state.rescue_checked.load(Ordering::Relaxed);
    let granted = state.rescue_granted.load(Ordering::Relaxed);
    assert_eq!(checked, 11, "every node of the tree is visited");
    assert_eq!(
        granted, 11,
        "with no propagation, the first pass writes to every node — this is the healthy state \
         for this lane, unlike the default lane where a non-zero count means degradation"
    );

    // 2周目は**1件も書かない**（既に届いている）。ここを測らないと、
    // 「毎回全ノードへ書き直している」実装でも1周目のassertだけは通る。
    let state = Arc::new(JobState::default());
    run_lazy_lane(&root, LazyLanePrep::open(&root, &grants, &[], &state), &[], &[], &state).expect("second pass");
    assert_eq!(state.rescue_checked.load(Ordering::Relaxed), 11);
    assert_eq!(
        state.rescue_granted.load(Ordering::Relaxed),
        0,
        "a second pass over an already-prepared tree must not write anything"
    );
}
