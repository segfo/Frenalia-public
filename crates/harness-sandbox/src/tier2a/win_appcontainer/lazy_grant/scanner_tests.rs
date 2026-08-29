//! 走査器の回帰。**昇格しない**（`writer_tests`と同じ理由——主体は純粋導出、ツリーは自作）。

use std::sync::atomic::{AtomicUsize, Ordering};

use super::super::writer::AclWriter;
use super::*;
use crate::tier2a::win_appcontainer::test_support::TestDirGuard;
use crate::tier2a::win_appcontainer::{capability_sid_from_name, workspace_rwx_mask, OwnedAceGrant};

fn test_grants(label: &str) -> Vec<OwnedAceGrant> {
    let sid = capability_sid_from_name(&format!(
        "harness-lazy-scan-{}-{label}",
        std::process::id()
    ))
    .expect("derive the test capability sid");
    vec![OwnedAceGrant {
        sid,
        mask: workspace_rwx_mask(),
    }]
}

fn reached(path: &Path, grants: &[OwnedAceGrant]) -> bool {
    let sids: Vec<_> = grants.iter().map(|g| g.sid.as_psid()).collect();
    crate::tier2a::win_appcontainer::revoke::sid_effective_ace_masks(path, &sids)
        .map(|masks| masks.iter().all(Option::is_some))
        .unwrap_or(false)
}

/// `n`件目のノードで止まる[`ScanControl`]。
struct StopAfter {
    limit: usize,
    seen: AtomicUsize,
}

impl ScanControl for StopAfter {
    fn should_stop(&self) -> bool {
        self.seen.load(Ordering::Relaxed) >= self.limit
    }
    fn progress(&self, submitted: usize) {
        self.seen.store(submitted, Ordering::Relaxed);
    }
}

/// 走査は**root・全ディレクトリ・全ファイル**へ届く。
///
/// 対で見る（`B-35`）——「届いた件数」だけを数えると、**1件も歩かなかった**場合と
/// 区別できない。実際にACEが載っていることまで見る。
#[test]
fn the_scan_reaches_the_root_and_every_directory_and_file() {
    let guard = TestDirGuard::create("lazy-scan-reach");
    let root = guard.path().join("ws");
    let sub = root.join("a");
    std::fs::create_dir_all(&sub).expect("create the tree");
    let top = root.join("top.txt");
    let deep = sub.join("deep.txt");
    std::fs::write(&top, b"x").expect("create the top file");
    std::fs::write(&deep, b"x").expect("create the deep file");

    let grants = test_grants("reach");
    let mut writer = AclWriter::start(root.clone(), grants.clone());
    let report = scan(&root, &[], &writer.handle(), &RunToCompletion).expect("the writer is available");
    let _ = writer.stop_at_safe_point();

    assert_eq!(report.submitted, 4, "root + a/ + 2 files");
    assert!(!report.stopped_early);
    assert_eq!(report.skipped, 0);
    for node in [root.as_path(), sub.as_path(), top.as_path(), deep.as_path()] {
        assert!(
            reached(node, &grants),
            "the scan must place an ace on {}",
            node.display()
        );
    }
}

/// [着手条件1の後半] **走査が終わったディレクトリに、後から作ったファイルは継承で許可を受ける。**
///
/// これが「ディレクトリは自分のACEが確定してから子を列挙する」順序が在る唯一の理由で、
/// **ここが崩れると1回目のビルドが作ったファイルが2回目もfaultする**。
/// 走査の件数を数えるだけでは、この性質は1ビットも見えない。
#[test]
fn a_file_created_after_the_scan_inherits_the_ace_from_its_scanned_directory() {
    let guard = TestDirGuard::create("lazy-scan-inherit");
    let root = guard.path().join("ws");
    let sub = root.join("a");
    std::fs::create_dir_all(&sub).expect("create the tree");

    let grants = test_grants("inherit");
    let mut writer = AclWriter::start(root.clone(), grants.clone());
    scan(&root, &[], &writer.handle(), &RunToCompletion).expect("the writer is available");
    let _ = writer.stop_at_safe_point();

    // **走査の後**に生まれたファイル——ビルドの生成物がこれに当たる。
    let born_later = sub.join("built.txt");
    std::fs::write(&born_later, b"x").expect("create the file after the scan");
    assert!(
        reached(&born_later, &grants),
        "a file created after its directory was scanned must inherit the ace, \
         otherwise the second run faults on everything the first run built"
    );
}

/// `skip`配下は**触らないうえに、降りない**。
///
/// `.harness/`がここへ来る——**意図的にACEを剥がしている場所**なので、走査が付け直すと
/// 制御面の保護（D-05/D-09）が無言で外れる（`grant_job`のモジュールdocの「約束」2）。
#[test]
fn the_skip_list_is_neither_granted_nor_descended_into() {
    let guard = TestDirGuard::create("lazy-scan-skip");
    let root = guard.path().join("ws");
    let control_dir = root.join(".harness");
    let inside_control = control_dir.join("secret");
    std::fs::create_dir_all(&inside_control).expect("create the control tree");
    let buried = inside_control.join("keep-out.txt");
    std::fs::write(&buried, b"x").expect("create the buried file");
    let normal = root.join("ok.txt");
    std::fs::write(&normal, b"x").expect("create the normal file");

    let grants = test_grants("skip");
    let mut writer = AclWriter::start(root.clone(), grants.clone());
    let report = scan(
        &root,
        std::slice::from_ref(&control_dir),
        &writer.handle(),
        &RunToCompletion,
    )
    .expect("the writer is available");
    let _ = writer.stop_at_safe_point();

    assert_eq!(report.skipped, 1, "the skipped directory is counted once");
    assert!(reached(&normal, &grants), "the rest of the tree is still granted");
    // **降りていないこと**を、配下のファイルで見る。ディレクトリだけ見ると、
    // 「入り口は飛ばしたが中は歩いた」実装でも緑になる。
    assert!(
        !reached(&control_dir, &grants),
        "the control directory itself must not be granted"
    );
    assert!(
        !reached(&buried, &grants),
        "the scan must not descend into the skipped directory"
    );
}

/// **安全点で止まる**（fallback controllerとツールのキャンセルが使う口）。
/// 止まったことが戻り値に出ることまで見る——出ないと「全部やった」と読まれる（`B-10`）。
#[test]
fn the_scan_stops_at_a_node_boundary_when_asked() {
    let guard = TestDirGuard::create("lazy-scan-stop");
    let root = guard.path().join("ws");
    std::fs::create_dir_all(&root).expect("create the tree");
    for i in 0..8 {
        std::fs::write(root.join(format!("f{i}.txt")), b"x").expect("create a file");
    }

    let grants = test_grants("stop");
    let mut writer = AclWriter::start(root.clone(), grants);
    let control = StopAfter {
        limit: 3,
        seen: AtomicUsize::new(0),
    };
    let report = scan(&root, &[], &writer.handle(), &control).expect("the writer is available");
    let _ = writer.stop_at_safe_point();

    assert!(report.stopped_early, "stopping early must be visible in the report");
    assert!(
        report.submitted >= 3 && report.submitted < 9,
        "the scan must stop near the requested boundary, got {}",
        report.submitted
    );
}

/// writerが止まっていたら**走査も即座に止まる**。進めても誰もACEを書かないので、
/// 進んだぶんが「処理済み」に見えるだけ有害である。
#[test]
fn the_scan_gives_up_immediately_when_the_writer_is_gone() {
    let guard = TestDirGuard::create("lazy-scan-nowriter");
    let root = guard.path().join("ws");
    std::fs::create_dir_all(&root).expect("create the tree");
    std::fs::write(root.join("f.txt"), b"x").expect("create a file");

    let mut writer = AclWriter::start(root.clone(), test_grants("nowriter"));
    let handle = writer.handle();
    let _ = writer.stop_at_safe_point();

    assert_eq!(
        scan(&root, &[], &handle, &RunToCompletion),
        Err(WriterUnavailable)
    );
}
