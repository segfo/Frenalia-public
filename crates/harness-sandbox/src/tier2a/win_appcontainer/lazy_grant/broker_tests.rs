//! fault受付の回帰。**昇格しない**（主体は純粋導出、ツリーはテスト自身が作ったもの）。
//!
//! ここで測るのは**判定**である。AppContainerの子から実際に往復するところは、
//! 子を起こす配線（段3）と同じ場所でしか測れない——**その代わり、
//! 「AppContainerの外から来た接続は断る」という対の側は、素のテストプロセスから測れる**
//! （`B-35`: 禁止側と許可側は対で見る。ここでは禁止側が先に測れる）。

use std::path::Path;

use super::*;
use crate::tier2a::win_appcontainer::test_support::TestDirGuard;
use crate::tier2a::win_appcontainer::{capability_sid_from_name, workspace_rwx_mask};
use crate::tier2a::win_appcontainer::OwnedAceGrant;
use crate::win_common::sid_to_string;
use crate::win_pipe_ipc::connect_with_timeout;

fn test_grants(label: &str) -> Vec<OwnedAceGrant> {
    let sid = capability_sid_from_name(&format!(
        "harness-lazy-broker-{}-{label}",
        std::process::id()
    ))
    .expect("derive the test capability sid");
    vec![OwnedAceGrant {
        sid,
        mask: workspace_rwx_mask(),
    }]
}

fn shared_for(root: &Path, skip: Vec<PathBuf>, writer: WriterHandle) -> Shared {
    Shared {
        policy: FaultPolicy {
            canonical_workspace: root.canonicalize().expect("canonicalize the workspace"),
            skip,
            mode: "rwx".to_string(),
        },
        writer,
        stopping: AtomicBool::new(false),
        prepared: Mutex::new(None),
        prepared_changed: std::sync::Condvar::new(),
        served: AtomicUsize::new(0),
        denied: AtomicUsize::new(0),
        unavailable: AtomicUsize::new(0),
        rejected_clients: AtomicUsize::new(0),
        granted: Mutex::new(HashSet::new()),
    }
}

fn policy_for(root: &Path, skip: Vec<PathBuf>) -> FaultPolicy {
    FaultPolicy {
        canonical_workspace: root.canonicalize().expect("canonicalize the workspace"),
        skip,
        mode: "rwx".to_string(),
    }
}

/// **ワイヤ形式を固定する。** 子の中で動くDLLと親が別々に更新され得るので、
/// 綴りが変わったことをコンパイラは教えてくれない（`B-03`: 層をまたぐ値は両端で閉じる）。
#[test]
fn the_fault_request_and_response_wire_format_is_stable() {
    let request = FaultRequest::Grant {
        path: r"C:\ws\src\lib.rs".to_string(),
    };
    assert_eq!(
        serde_json::to_string(&request).expect("serialize"),
        r#"{"kind":"grant","path":"C:\\ws\\src\\lib.rs"}"#
    );
    assert_eq!(
        serde_json::from_str::<FaultRequest>(r#"{"kind":"grant","path":"C:\\ws\\a"}"#)
            .expect("deserialize"),
        FaultRequest::Grant {
            path: r"C:\ws\a".to_string()
        }
    );

    assert_eq!(
        serde_json::to_string(&FaultResponse::Retry).expect("serialize"),
        r#"{"kind":"retry"}"#
    );
    assert_eq!(
        serde_json::to_string(&FaultResponse::Denied {
            reason: "nope".to_string()
        })
        .expect("serialize"),
        r#"{"kind":"denied","reason":"nope"}"#
    );
    assert_eq!(
        serde_json::to_string(&FaultResponse::Unavailable {
            reason: "later".to_string()
        })
        .expect("serialize"),
        r#"{"kind":"unavailable","reason":"later"}"#
    );
}

/// 解決したパスは**rootから対象へ向かう順**で返る。祖先が先に付いていないと通過できない。
#[test]
fn the_chain_runs_from_the_workspace_root_down_to_the_target() {
    let guard = TestDirGuard::create("broker-chain");
    let root = guard.path().join("ws");
    let deep = root.join("a").join("b");
    std::fs::create_dir_all(&deep).expect("create the tree");
    let leaf = deep.join("f.txt");
    std::fs::write(&leaf, b"x").expect("create the leaf");

    let policy = policy_for(&root, Vec::new());
    let chain = resolve_chain(&policy, &leaf.to_string_lossy()).expect("the leaf is in scope");
    let names: Vec<String> = chain
        .iter()
        .map(|n| n.path.file_name().unwrap_or_default().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["ws", "a", "b", "f.txt"]);
    assert!(chain[0].is_dir && chain[1].is_dir && chain[2].is_dir);
    assert!(!chain[3].is_dir, "the leaf is a file, so it gets no inherit bits");
}

/// **まだ存在しないパスは、実在するいちばん深い祖先まで遡る。**
/// ビルドは出力を「作る」ので、要るのは対象ではなく親ディレクトリのACEである。
#[test]
fn a_path_that_does_not_exist_yet_resolves_to_its_deepest_existing_ancestor() {
    let guard = TestDirGuard::create("broker-notyet");
    let root = guard.path().join("ws");
    let out = root.join("target");
    std::fs::create_dir_all(&out).expect("create the output dir");

    let policy = policy_for(&root, Vec::new());
    let unborn = out.join("deep").join("not-built-yet.rlib");
    let chain = resolve_chain(&policy, &unborn.to_string_lossy())
        .expect("a not-yet-created output must resolve to its parent");
    assert_eq!(
        chain.last().expect("non-empty").path,
        out.canonicalize().expect("canonicalize"),
        "the chain must stop at the deepest directory that actually exists"
    );
}

/// workspace外・`skip`配下・相対パスは**ポリシー拒否**である。
///
/// `Denied`と`Unavailable`を分けるのがここの要点——`Denied`は全walkが終わっても
/// 変わらないので、子は元の拒否をそのまま返す。ここを`Unavailable`にすると、
/// **絶対に成功しない待ちへ子を送り込む**ことになる。
#[test]
fn out_of_scope_requests_are_denied_not_deferred() {
    let guard = TestDirGuard::create("broker-scope");
    let root = guard.path().join("ws");
    let control = root.join(".harness");
    std::fs::create_dir_all(&control).expect("create the control dir");
    std::fs::write(control.join("state.json"), b"{}").expect("write control state");
    let outside = guard.path().join("outside");
    std::fs::create_dir_all(&outside).expect("create an outside dir");

    let policy = policy_for(&root, vec![control.clone()]);

    assert!(
        resolve_chain(&policy, &outside.to_string_lossy())
            .unwrap_err()
            .contains("outside the workspace"),
        "a path outside the workspace must be refused"
    );
    assert!(
        resolve_chain(&policy, &control.join("state.json").to_string_lossy())
            .unwrap_err()
            .contains("never grants"),
        "the control directory must be refused"
    );
    assert!(
        resolve_chain(&policy, "src/lib.rs")
            .unwrap_err()
            .contains("absolute"),
        "a relative path must be refused (the broker resolves paths itself)"
    );
    // 対で見る（`B-35`）——拒否だけを測ると「全部拒否する」実装でも緑になる。
    std::fs::write(root.join("ok.txt"), b"x").expect("write an in-scope file");
    assert!(
        resolve_chain(&policy, &root.join("ok.txt").to_string_lossy()).is_ok(),
        "an in-scope file must still be accepted"
    );
}

/// **リパースポイント越しにworkspace外を指しても通らない。**
/// `canonicalize`が解決した先で containment を判定するので、綴りでは逃げられない。
#[test]
fn a_symlink_that_leaves_the_workspace_is_refused() {
    let guard = TestDirGuard::create("broker-reparse");
    let root = guard.path().join("ws");
    std::fs::create_dir_all(&root).expect("create the workspace");
    let outside = guard.path().join("outside");
    std::fs::create_dir_all(&outside).expect("create the outside dir");
    let secret = outside.join("secret.txt");
    std::fs::write(&secret, b"x").expect("write the outside file");

    let link = root.join("escape.txt");
    // シンボリックリンクの作成には権限が要る（開発者モードか管理者）。作れない環境では
    // **黙って緑にせずskipする**——「作れなかった」と「拒否された」は別の事実である。
    if std::os::windows::fs::symlink_file(&secret, &link).is_err() {
        eprintln!("skipping: this machine cannot create symlinks without elevation");
        return;
    }

    let policy = policy_for(&root, Vec::new());
    assert!(
        resolve_chain(&policy, &link.to_string_lossy())
            .unwrap_err()
            .contains("outside the workspace"),
        "a symlink resolving out of the workspace must be refused"
    );
}

/// 許可済みのパスは実体化され、**2回目は writer を通さずに合流する**。
#[test]
fn a_granted_path_is_materialised_once_and_merged_afterwards() {
    let guard = TestDirGuard::create("broker-grant");
    let root = guard.path().join("ws");
    std::fs::create_dir_all(root.join("src")).expect("create the tree");
    let file = root.join("src").join("lib.rs");
    std::fs::write(&file, b"x").expect("create the file");

    let grants = test_grants("grant");
    let mut writer = super::super::writer::AclWriter::start(root.clone(), grants.clone());
    let shared = shared_for(&root, Vec::new(), writer.handle());

    assert_eq!(handle_grant(&shared, &file.to_string_lossy()), FaultResponse::Retry);
    let after_first = writer.stats().faults_served;
    assert_eq!(after_first, 1, "the first request goes to the writer");

    assert_eq!(handle_grant(&shared, &file.to_string_lossy()), FaultResponse::Retry);
    assert_eq!(
        writer.stats().faults_served,
        after_first,
        "the second request for the same node must merge, not queue another write"
    );
    let _ = writer.stop_at_safe_point();

    // 実際にACEが載っていること（件数だけでは「何もしていない」と区別できない、`B-35`）。
    let sids: Vec<_> = grants.iter().map(|g| g.sid.as_psid()).collect();
    for node in [root.as_path(), root.join("src").as_path(), file.as_path()] {
        assert!(
            crate::tier2a::win_appcontainer::revoke::sid_effective_ace_masks(node, &sids)
                .map(|m| m.iter().all(Option::is_some))
                .unwrap_or(false),
            "the whole chain must be reachable: {}",
            node.display()
        );
    }
}

/// **ラッチは「こちら側の失敗」でだけ倒す。ポリシー拒否では倒さない。**
///
/// 倒すと、そのworkspaceでは以降レーンを使わなくなる（起動側が従来の待ちへ落ちる）。
/// **範囲外を叩かれただけで倒すと、敵対的な子が`.harness/`を1回叩くだけでレーンを殺せる**
/// ——だから引き金は「付与できなかった」に限る。
///
/// 対で見る（`B-35`）——倒れる側だけを測ると「常に倒す」実装でも緑になる。
#[test]
fn only_our_own_failure_trips_the_latch_never_a_policy_denial() {
    let guard = TestDirGuard::create("broker-latch");
    let root = guard.path().join("ws");
    let control = root.join(".harness");
    std::fs::create_dir_all(&control).expect("create the control dir");
    std::fs::write(control.join("state.json"), b"{}").expect("write control state");
    let file = root.join("f.txt");
    std::fs::write(&file, b"x").expect("create a file");

    let grants = test_grants("latch");
    let mut writer = super::super::writer::AclWriter::start(root.clone(), grants);
    let canonical = root.canonicalize().expect("canonicalize");
    let mode = format!("latch-{}", std::process::id());
    let shared = Shared {
        policy: FaultPolicy {
            canonical_workspace: canonical.clone(),
            skip: vec![canonical.join(".harness")],
            mode: mode.clone(),
        },
        writer: writer.handle(),
        stopping: AtomicBool::new(false),
        prepared: Mutex::new(None),
        prepared_changed: std::sync::Condvar::new(),
        served: AtomicUsize::new(0),
        denied: AtomicUsize::new(0),
        unavailable: AtomicUsize::new(0),
        rejected_clients: AtomicUsize::new(0),
        granted: Mutex::new(HashSet::new()),
    };

    // ポリシー拒否（制御ディレクトリ）。**ラッチは倒れない。**
    let denied = handle_grant(&shared, &control.join("state.json").to_string_lossy());
    assert!(matches!(denied, FaultResponse::Denied { .. }), "{denied:?}");
    assert!(
        !super::super::lane_is_distrusted(&canonical, &mode),
        "a policy denial must not disable the lane; otherwise one out-of-scope open kills it"
    );

    // こちら側の失敗（writerが畳まれている）。**ここで初めて倒れる。**
    let _ = writer.stop_at_safe_point();
    let unavailable = handle_grant(&shared, &file.to_string_lossy());
    assert!(
        matches!(unavailable, FaultResponse::Unavailable { .. }),
        "{unavailable:?}"
    );
    assert!(
        super::super::lane_is_distrusted(&canonical, &mode),
        "failing to place an ace is our own failure, so the lane must stop being used \
         for this workspace -- that is what makes the next command wait and succeed"
    );
}

/// [着手条件5] **writerが居ないことは「拒否」ではない。**
///
/// そのパスは既に許可済みで、届かない理由はこちら側の不調である。ここが`Denied`になると
/// **承認済みのアクセスが自分の不調で拒否に化ける**——子は barrier で待つべきなのに、
/// 元の拒否をそのまま返してコマンドが失敗する。
#[test]
fn a_writer_that_is_gone_yields_unavailable_never_denied() {
    let guard = TestDirGuard::create("broker-nowriter");
    let root = guard.path().join("ws");
    std::fs::create_dir_all(&root).expect("create the workspace");
    let file = root.join("f.txt");
    std::fs::write(&file, b"x").expect("create the file");

    let mut writer = super::super::writer::AclWriter::start(root.clone(), test_grants("nowriter"));
    let shared = shared_for(&root, Vec::new(), writer.handle());
    let _ = writer.stop_at_safe_point();

    match handle_grant(&shared, &file.to_string_lossy()) {
        FaultResponse::Unavailable { .. } => {}
        other => panic!("expected Unavailable so the child waits at the barrier, got {other:?}"),
    }
}

/// **AppContainerの外から来た接続は断る**（`serve_connection`の入口の検査）。
///
/// 素のテストプロセスはAppContainerの中に居ないので、ここは**実際に接続して**測れる。
/// 許可側（capabilityを積んだ子が往復できること）は子を起こす配線と同じ場所で測る
/// ——`plans/mac-spike/RESULTS.md` §S7が同じ形のパイプで既に対の実測を持っている。
#[test]
fn a_client_outside_an_appcontainer_is_refused_by_the_broker() {
    let guard = TestDirGuard::create("broker-outsider");
    let root = guard.path().join("ws");
    std::fs::create_dir_all(&root).expect("create the workspace");

    let grants = test_grants("outsider");
    let capability = sid_to_string(grants[0].sid.as_psid()).expect("sid string");
    let mut writer = super::super::writer::AclWriter::start(root.clone(), grants.clone());
    let mut broker = Broker::start(policy_for(&root, Vec::new()), writer.handle(), std::slice::from_ref(&capability))
        .expect("the broker must open its pipe");

    let client = unsafe {
        let name_w = wide(broker.pipe_name());
        CreateFileW(
            PCWSTR(name_w.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            None,
        )
        .expect("the calling user is allowed to connect (the capability side is the child's)")
    };
    // brokerは**接続直後に**断りを送る（要求を待たない）。
    let bytes = read_framed_timeout(client, IO_TIMEOUT).expect("the broker must answer");
    let response: FaultResponse = serde_json::from_slice(&bytes).expect("parse the response");
    match response {
        FaultResponse::Denied { reason } => {
            assert!(
                reason.contains("AppContainer"),
                "the reason must say why, got {reason}"
            );
        }
        other => panic!("expected the outsider to be refused, got {other:?}"),
    }
    unsafe {
        let _ = CloseHandle(client);
    }

    let stats = broker.stop();
    let _ = writer.stop_at_safe_point();
    assert_eq!(stats.rejected_clients, 1);
    assert_eq!(stats.served, 0, "no fault was served to the outsider");
}

/// brokerを畳むと**接続待ちのスレッドも畳まれる**（`stop`が自分のパイプを起こす）。
/// ここが効いていないと、`stop`が最大1時間返らない。
#[test]
fn stopping_the_broker_returns_promptly() {
    let guard = TestDirGuard::create("broker-stop");
    let root = guard.path().join("ws");
    std::fs::create_dir_all(&root).expect("create the workspace");

    let grants = test_grants("stop");
    let capability = sid_to_string(grants[0].sid.as_psid()).expect("sid string");
    let mut writer = super::super::writer::AclWriter::start(root.clone(), grants);
    let mut broker = Broker::start(policy_for(&root, Vec::new()), writer.handle(), std::slice::from_ref(&capability))
        .expect("the broker must open its pipe");

    let started = std::time::Instant::now();
    let _ = broker.stop();
    let _ = writer.stop_at_safe_point();
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "stop must wake the acceptor instead of waiting out the accept timeout, took {:?}",
        started.elapsed()
    );
}

/// 接続待ちのパイプは**この名前でしか開けない形**を保つ（`is_harness_pipe_name`）。
/// 名前は秘密ではないが、**harnessが作った形であること**は昇格側の検証が使う。
#[test]
fn the_broker_pipe_uses_the_shared_harness_naming() {
    let guard = TestDirGuard::create("broker-name");
    let root = guard.path().join("ws");
    std::fs::create_dir_all(&root).expect("create the workspace");
    let grants = test_grants("name");
    let capability = sid_to_string(grants[0].sid.as_psid()).expect("sid string");
    let mut writer = super::super::writer::AclWriter::start(root.clone(), grants);
    let mut broker = Broker::start(policy_for(&root, Vec::new()), writer.handle(), std::slice::from_ref(&capability))
        .expect("the broker must open its pipe");

    assert!(crate::win_pipe_ipc::is_harness_pipe_name(broker.pipe_name()));
    assert!(broker.pipe_name().contains("lazy-ace-broker"));
    // 開けることまで見る（名前が正しくてもパイプが無ければ意味が無い）。
    let opened = unsafe {
        let name_w = wide(broker.pipe_name());
        CreateFileW(
            PCWSTR(name_w.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            Default::default(),
            None,
        )
    };
    assert!(opened.is_ok(), "the pipe must actually exist once start returned");
    if let Ok(handle) = opened {
        unsafe {
            let _ = CloseHandle(handle);
        }
    }
    let _ = broker.stop();
    let _ = writer.stop_at_safe_point();
    let _ = connect_with_timeout;
}
