//! 単一ACL writerの回帰。**昇格しない**——ACEを書くのはテスト自身が作ったツリーだけで、
//! 宛先SIDは[`capability_sid_from_name`]（純粋導出）＝台帳にもプロファイルにも何も残さない
//! （`jit_grant_cost_tests`と同じ方針）。

use windows::Win32::Security::{CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE};

use super::*;
use crate::tier2a::win_appcontainer::test_support::{describe_dacl_aces, TestDirGuard};
use crate::tier2a::win_appcontainer::{capability_sid_from_name, workspace_rwx_mask};

/// テスト専用の宛先SID。**プロセスIDとラベルで分ける**——同じ名前を使い回すと、並行して走る
/// 別テストのツリーに載ったACEを自分のものと読み違える。
fn test_grants(label: &str) -> Vec<OwnedAceGrant> {
    let sid = capability_sid_from_name(&format!(
        "harness-lazy-writer-{}-{label}",
        std::process::id()
    ))
    .expect("derive the test capability sid");
    vec![OwnedAceGrant {
        sid,
        mask: workspace_rwx_mask(),
    }]
}

fn reached(path: &std::path::Path, grants: &[OwnedAceGrant]) -> bool {
    let sids: Vec<_> = grants.iter().map(|g| g.sid.as_psid()).collect();
    crate::tier2a::win_appcontainer::revoke::sid_effective_ace_masks(path, &sids)
        .map(|masks| masks.iter().all(Option::is_some))
        .unwrap_or(false)
}

fn job(is_fault: bool) -> (Job, mpsc::Receiver<Result<Vec<NodeOutcome>, String>>) {
    let (reply, rx) = mpsc::channel();
    (
        Job {
            nodes: vec![Node::file(if is_fault { "fault" } else { "scan" })],
            is_fault,
            reply,
        },
        rx,
    )
}

/// **割り込みの規則そのもの**——高優先度が1件でもあれば、低優先度より先に出る。
///
/// スレッドを使わずに固定するのは、順序を実行の速さで測ると**実装が壊れていても
/// 走り方のゆらぎで緑になり得る**ためである。
#[test]
fn a_queued_fault_is_taken_before_background_work_that_arrived_first() {
    let mut queues = Queues::default();
    let (scan_first, _scan_rx) = job(false);
    let (scan_second, _scan_rx2) = job(false);
    let (fault, _fault_rx) = job(true);
    // 背景の要求が**先に**積まれている状態を作る（ここが逆だと何も測っていない）。
    queues.low.push_back(scan_first);
    queues.low.push_back(scan_second);
    queues.high.push_back(fault);

    let taken = take_next(&mut queues).expect("a job must be available");
    assert!(
        taken.is_fault,
        "the fault must come out first even though the background work was queued earlier"
    );
    // 対で見る（`B-35`）——高優先度を空にしたら、次は積んだ順で背景が出ること。
    // ここを測らないと、「常にhighしか返さない」実装でも上のassertだけは通る。
    assert!(
        !take_next(&mut queues).expect("background work remains").is_fault,
        "after the high queue drains, background work must resume"
    );
    assert!(!take_next(&mut queues).expect("second background job").is_fault);
    assert!(
        take_next(&mut queues).is_none(),
        "an empty writer must report that there is nothing to do"
    );
}

/// [着手条件1] **ディレクトリへは継承ありで、ファイルへは継承なしで書く。**
///
/// 同じ案がACE 1ビットで勝ち負けの両側へ振れる（§S21-3: 継承ありなら課金対象503ノードで
/// 事前配布に7.8倍有利、非継承だと22,054ノードへ増えて5.6倍不利）ので、
/// **フラグそのものを読んで固定する**。
#[test]
fn a_directory_gets_inheritable_aces_and_a_file_does_not() {
    let guard = TestDirGuard::create("lazy-writer-inherit");
    let dir = guard.path().join("sub");
    std::fs::create_dir_all(&dir).expect("create the subdirectory");
    let file = dir.join("f.txt");
    std::fs::write(&file, b"x").expect("create the file");

    let grants = test_grants("inherit");
    let sid = crate::win_common::sid_to_string(grants[0].sid.as_psid()).expect("sid string");
    let mut writer = AclWriter::start(guard.path().to_path_buf(), grants.clone());
    let handle = writer.handle();
    assert_eq!(
        handle.grant_background(Node::dir(&dir)).expect("writer available"),
        Ok(NodeOutcome::Granted)
    );
    assert_eq!(
        handle.grant_background(Node::file(&file)).expect("writer available"),
        Ok(NodeOutcome::Granted)
    );
    let _ = writer.stop_at_safe_point();

    let inheritance = |path: &std::path::Path| -> u8 {
        describe_dacl_aces(path)
            .expect("read the dacl")
            .iter()
            .find(|ace| ace.ends_with(&sid))
            .map(|ace| {
                let flags = ace
                    .split(';')
                    .find_map(|f| f.strip_prefix("flags="))
                    .expect("the description carries the ace flags");
                u8::from_str_radix(flags.trim_start_matches("0x"), 16).expect("parse ace flags")
            })
            .unwrap_or_else(|| panic!("no ace for the test subject on {}", path.display()))
    };

    let dir_flags = inheritance(&dir);
    let want = (CONTAINER_INHERIT_ACE.0 | OBJECT_INHERIT_ACE.0) as u8;
    assert_eq!(
        dir_flags & want,
        want,
        "a directory must carry both inherit bits, or files created later will not inherit"
    );
    assert_eq!(
        inheritance(&file) & want,
        0,
        "a file must not carry inherit bits (there is nothing below it to inherit)"
    );
}

/// **書いたのか、もう届いていたのかを分けて数える。** 同じノードを2回渡したとき、
/// 2回目が`Granted`のままだと「毎回書き直している」ことに気付けない（`B-10`）。
#[test]
fn the_writer_separates_what_it_wrote_from_what_was_already_reached() {
    let guard = TestDirGuard::create("lazy-writer-stats");
    let file = guard.path().join("f.txt");
    std::fs::write(&file, b"x").expect("create the file");

    let grants = test_grants("stats");
    let mut writer = AclWriter::start(guard.path().to_path_buf(), grants.clone());
    let handle = writer.handle();
    assert_eq!(
        handle.grant_background(Node::file(&file)).expect("available"),
        Ok(NodeOutcome::Granted)
    );
    assert!(reached(&file, &grants), "the ace must actually be on the file");
    assert_eq!(
        handle.grant_background(Node::file(&file)).expect("available"),
        Ok(NodeOutcome::AlreadyReached),
        "a node that is already reached must not be written again"
    );
    let stats = writer.stop_at_safe_point();
    assert_eq!(stats.processed, 2);
    assert_eq!(stats.granted, 1, "only the first pass writes");
    assert_eq!(stats.probe_errors, 0);
}

/// 消えたノードは**失敗ではない**（TOCTOU）。ここを`Err`にすると、走査が1ファイルの削除で
/// 打ち切られ、残り全部が未処理のまま「成功」になる（BUG-084と同型）。
#[test]
fn a_node_that_vanished_is_reported_as_vanished_not_as_an_error() {
    let guard = TestDirGuard::create("lazy-writer-vanish");
    let missing = guard.path().join("never-existed.txt");

    let mut writer = AclWriter::start(guard.path().to_path_buf(), test_grants("vanish"));
    let outcome = writer
        .handle()
        .grant_background(Node::file(&missing))
        .expect("the writer is available");
    assert_eq!(outcome, Ok(NodeOutcome::Vanished));
    let stats = writer.stop_at_safe_point();
    assert_eq!(stats.vanished, 1);
    assert_eq!(stats.granted, 0);
}

/// [着手条件5] **止まったwriterは「拒否」ではなく「可用性の失敗」を返す。**
///
/// そのパスは既に許可済みで、届かない理由はこちら側の不調だからである。ここを拒否に翻訳すると、
/// **承認済みのアクセスが自分の不調で拒否に化ける**——だから型からして別物にしてある。
#[test]
fn after_the_safe_point_stop_new_requests_report_unavailability_not_denial() {
    let guard = TestDirGuard::create("lazy-writer-stop");
    let file = guard.path().join("f.txt");
    std::fs::write(&file, b"x").expect("create the file");

    let mut writer = AclWriter::start(guard.path().to_path_buf(), test_grants("stop"));
    let handle = writer.handle();
    assert!(handle.grant_background(Node::file(&file)).is_ok());
    let _ = writer.stop_at_safe_point();

    assert_eq!(
        handle.grant_background(Node::file(&file)),
        Err(WriterUnavailable),
        "a stopped writer must report unavailability"
    );
    assert_eq!(
        handle.grant_now(vec![Node::file(&file)]),
        Err(WriterUnavailable),
        "the fault path must report the same thing (it is the one that must not turn it into a denial)"
    );
    assert!(!handle.is_running());
}

/// faultは**祖先チェーンごと1単位**で処理する。途中に背景の要求が割り込むと
/// 「親はまだ無いのに子だけ付いた」状態を作り得るためで、そこは通過できない。
#[test]
fn a_fault_grants_the_whole_ancestor_chain_it_was_given() {
    let guard = TestDirGuard::create("lazy-writer-chain");
    let mid = guard.path().join("a");
    let leaf_dir = mid.join("b");
    std::fs::create_dir_all(&leaf_dir).expect("create the chain");
    let leaf = leaf_dir.join("deep.txt");
    std::fs::write(&leaf, b"x").expect("create the leaf");

    let grants = test_grants("chain");
    let mut writer = AclWriter::start(guard.path().to_path_buf(), grants.clone());
    let outcomes = writer
        .handle()
        .grant_now(vec![
            Node::dir(&mid),
            Node::dir(&leaf_dir),
            Node::file(&leaf),
        ])
        .expect("the writer is available")
        .expect("the chain must be granted");
    assert_eq!(outcomes.len(), 3);
    let stats = writer.stop_at_safe_point();
    assert_eq!(stats.faults_served, 1, "the chain counts as one interrupt");

    for node in [mid.as_path(), leaf_dir.as_path(), leaf.as_path()] {
        assert!(
            reached(node, &grants),
            "every node of the chain must be reachable: {}",
            node.display()
        );
    }
}
