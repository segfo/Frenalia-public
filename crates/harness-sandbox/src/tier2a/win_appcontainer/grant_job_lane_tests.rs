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
use wac::test_support::{reachability, TestDirGuard};
use wac::{capability_sid_from_name, workspace_rwx_mask, OwnedAceGrant};

fn lane_grants(label: &str) -> Vec<OwnedAceGrant> {
    let sid = capability_sid_from_name(&format!("harness-lane-{}-{label}", std::process::id()))
        .expect("derive the test capability sid");
    vec![OwnedAceGrant {
        sid,
        mask: workspace_rwx_mask(),
    }]
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
    run_lazy_lane(&lazy_root, LazyLanePrep::open(&lazy_root, &lazy_grants, &[], "rwx", &state), &[], &[], &state)
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
        LazyLanePrep::open(&root, &grants, skip, "rwx", &state),
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

    run_lazy_lane(&root, LazyLanePrep::open(&root, &grants, &[], "rwx", &state), &[], &[], &state).expect("the lazy lane must succeed");

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

/// [D-88] **札は1枚しか取れず、取れなかった側は1バイトも書かずに待つ。**
///
/// これが「別の`harness.exe`と交差してDACLの書込が消える」を止める仕組みである。
/// 普段の消え方は拒否側＝安全側だが、`.harness/`の再保護だけは
/// 「読む→**外す**→書き戻す」なので、交差すると**外したはずの許可が戻る**——
/// そちらは安全側ではないので、札で止める。
///
/// **別スレッドから測る。** Windowsのミューテックスは所有者スレッドに対して再入可能なので、
/// 同じスレッドで2回取ると成功してしまう（実際にそう書いて、このテストに捕まった）。
/// 止めたいのは**別プロセス**との交差で、その性質はスレッドをまたいだときに現れる。
///
/// 対で見る（`B-35`）——取れる側だけを測ると「常に取れる」実装でも緑になる。
#[test]
fn the_preparation_lock_is_held_by_exactly_one_holder_at_a_time() {
    let name = format!(
        "Local\\harness-ws-prepare-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );

    let first = crate::try_acquire_named_lock(&name).expect("nobody holds it yet");
    let taken_by_other_thread = {
        let name = name.clone();
        std::thread::spawn(move || crate::try_acquire_named_lock(&name).is_some())
            .join()
            .expect("the probe thread must not panic")
    };
    assert!(
        !taken_by_other_thread,
        "a second holder must not get the lock while the first still holds it -- \
         otherwise two processes would write the same DACLs concurrently"
    );

    drop(first);
    let taken_after_release = {
        let name = name.clone();
        std::thread::spawn(move || crate::try_acquire_named_lock(&name).is_some())
            .join()
            .expect("the probe thread must not panic")
    };
    assert!(
        taken_after_release,
        "the lock must be free again once the holder drops it; otherwise one crashed \
         preparation would block this workspace forever"
    );
}

/// 札の名前は**workspaceとmodeで分かれ、綴りの揺れでは分かれない**。
///
/// 分かれすぎると別のworkspaceを不必要に待たせ、**分かれなさすぎると札が2枚あるのと
/// 同じ**になる（＝止めたかった交差が止まらない）。
#[test]
fn the_lock_name_separates_workspaces_and_modes_but_not_spellings() {
    use super::prepare_lock_name;
    let a = std::path::Path::new(r"C:\ws\project");
    let b = std::path::Path::new(r"c:/WS/project/");

    assert_eq!(
        prepare_lock_name(a, "rwx"),
        prepare_lock_name(b, "rwx"),
        "the same workspace spelled differently must map to the same lock"
    );
    assert_ne!(
        prepare_lock_name(a, "rwx"),
        prepare_lock_name(a, "ro"),
        "different modes prepare different subjects, so they may run at the same time"
    );
    assert_ne!(
        prepare_lock_name(a, "rwx"),
        prepare_lock_name(std::path::Path::new(r"C:\ws\other"), "rwx"),
        "different workspaces must not wait for each other"
    );
    // カーネルオブジェクト名に使えない文字が残っていないこと（残ると札が作れず、
    // **排他が黙って無くなる**、`B-10`）。
    let name = prepare_lock_name(a, "rwx");
    assert!(name.starts_with("Local\\"), "{name}");
    assert!(
        !name["Local\\".len()..].contains('\\'),
        "the name after the prefix must not contain another separator: {name}"
    );
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
    run_lazy_lane(&root, LazyLanePrep::open(&root, &grants, &[], "rwx", &state), &[], &[], &state).expect("first pass");
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
    run_lazy_lane(&root, LazyLanePrep::open(&root, &grants, &[], "rwx", &state), &[], &[], &state).expect("second pass");
    assert_eq!(state.rescue_checked.load(Ordering::Relaxed), 11);
    assert_eq!(
        state.rescue_granted.load(Ordering::Relaxed),
        0,
        "a second pass over an already-prepared tree must not write anything"
    );
}
