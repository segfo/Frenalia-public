//! [D-88（`plans/DESIGN-SANDBOX-APPPOLICY.md` §5.1.3）] **受入の主軸**——
//! 「要るものが、要った瞬間に開く」ことを実子プロセスで固定する。
//!
//! # 何を測るのか（速さではない）
//!
//! 設計書§5.1.3の検証6が「**割り込みが成立したことを直接測る**」と定めている。ここが
//! 崩れていると、他の指標が良くても目的は達していない。だから測るのは時間ではなく、
//! **「準備が届いていないファイルを子が開けたか」と「そのとき受付が1件処理したか」**の対である。
//!
//! # 対で見る（`B-35`）
//!
//! 許可側だけを測ると、**全部通す実装**でも緑になる。だから同じファイル・同じ子の起こし方で、
//! **レーン無しでは開けないこと**を先に確かめてから、レーン有りで開けることを測る。
//! この2つの違いは`RedirectorInject`の1引数だけにしてある——起こし方が少しでも違うと、
//! 割れた結果を「レーンのせい」と言えなくなる。
//!
//! # 昇格しない
//!
//! `preflight`を通し、ACEを書くのはテスト自身が作ったツリーだけである。
//! **`#[ignore]`が付いているのは実子プロセスを起こし実マシンのACLを変えるから**で、
//! 権限が要るからではない（他の実機E2Eと同じ扱い）。
//!
//! ```text
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 lazy_fault_in_acceptance
//! ```

use super::test_support::{
    cleanup_workspace, make_unreachable, scopeguard, workspace_grants, TestDirGuard,
};
use super::*;

/// 子へ読ませる対象。**深い位置に置く**——祖先も含めて未準備の状態を作り、
/// 「対象と未準備の祖先だけを割り込みで付与する」経路を通すため。
const TARGET_REL: &str = r"late\deep\target.txt";
const TARGET_CONTENT: &str = "lazy-fault-in-acceptance-marker";

/// **本番と同じ構成でレーンを有効にする。**
///
/// `preflight`はレーンが有効なときだけ、子がRedirector DLLを読めるようACEを付ける
/// （無ければ`LoadLibraryW`が対象プロセスでNULLを返し、注入が必ず失敗する）。
/// ここでスイッチを立てずに測ると、**本番とは違う構成を測る**ことになる（`B-08`）。
///
/// プロセス全体に効くので、この2本は`--test-threads=1`で走らせること
/// （`#[ignore]`の文面が要求している）。
fn enable_the_lane_like_production_does() {
    std::env::set_var(lazy_grant::LAZY_LANE_ENV, "1");
    assert!(
        matches!(lazy_grant::lane(), grant_job::PreparationLane::Lazy),
        "the probe must select the lazy lane; if the redirector DLL is missing next to the \
         test binary, copy target/debug/harness_redirector.dll into target/debug/deps/"
    );
}

/// 同じ子を同じ形で起こし、**注入するものだけを変えて**対象を読ませる。
fn read_target_in_child(
    session: &OwnedContainerSid,
    workspace: &std::path::Path,
    workspace_cap: PSID,
    inject: RedirectorInject<'_>,
) -> (String, String, i32) {
    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    let command = format!("Get-Content -Raw '{}\\{TARGET_REL}'", workspace.display());
    let child = spawn_with_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", &command],
        workspace,
        &env,
        false,
        session.as_psid(),
        NetworkCapability::Deny,
        inject,
        &[workspace_cap],
        DomainIdentity::Capability(workspace_cap),
    )
    .expect("spawn the child through the production path");
    let (stdout, stderr, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("read the child output");
    eprintln!("[acceptance child] exit={code}\nstdout={stdout}\nstderr={stderr}");
    (stdout, stderr, code)
}

/// **受入の主軸**: 準備が届いていないファイルを、子が待たずに開ける。
///
/// 手順は「届かなくする → 届かないことを確かめる → 受付を開く → 開けることを確かめる」。
/// 2番目を飛ばすと、**最初から届いていたものを測って**「割り込みが成立した」と言うことになる。
#[test]
#[ignore = "spawns a real AppContainer child and changes real ACLs; run NON-elevated with --test-threads=1"]
fn an_unprepared_file_opens_through_the_interrupt_instead_of_waiting() {
    enable_the_lane_like_production_does();
    let guard = TestDirGuard::create("lazy-accept");
    let workspace = guard.path().to_path_buf();
    let target = workspace.join(TARGET_REL);
    std::fs::create_dir_all(target.parent().expect("the target has a parent"))
        .expect("create the target's directories");
    std::fs::write(&target, TARGET_CONTENT).expect("create the target file");
    // 走査器が回る余地を作るため、ツリーに少しだけ厚みを持たせる。
    for i in 0..64 {
        std::fs::write(workspace.join(format!("f{i:03}.txt")), b"x").expect("fill the tree");
    }

    let outcome =
        preflight(&workspace, &[], None, &WorkspaceWriteMode::DirectRw).unwrap_or_else(|e| {
            panic!("preflight must succeed before this measurement means anything ({e:?})")
        });
    for warning in &outcome.warnings {
        eprintln!("preflight warning: {warning}");
    }
    // 既定レーンで**一度きちんと配り終える**。そのうえで対象だけを剥がすことで、
    // 「走査器がまだ来ていない1ノード」を決定的に作る。
    grant_job::wait_until_done().expect("the background grant job must finish");

    let canonical_ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.clone());
    let grants = workspace_grants(&canonical_ws);
    let session = ensure_profile(&crate::tier2a::session_profile::current_profile_name())
        .expect("the session profile must exist after preflight");
    let workspace_cap = workspace_capability_sid(&canonical_ws, "rwx")
        .expect("the rwx capability must exist after preflight");

    // 実マシンに残るもの（workspaceのACEと台帳）を、**assertが落ちても**戻す。
    let _cleanup = scopeguard({
        let canonical_ws = canonical_ws.clone();
        move || cleanup_workspace(&canonical_ws)
    });

    make_unreachable(&target, &grants);

    // --- 禁止側（`B-35`）: レーン無しでは開けない ---
    let (stdout, _, code) = read_target_in_child(
        &session,
        &workspace,
        workspace_cap.as_psid(),
        RedirectorInject::default(),
    );
    assert!(
        !stdout.contains(TARGET_CONTENT),
        "without the lane the child must NOT be able to read the unprepared file \
         (exit={code}); if it can, the setup did not actually make it unreachable and \
         the positive side below would prove nothing"
    );

    // --- 許可側: 受付を開くと、同じ子が同じファイルを開ける ---
    let mut writer = lazy_grant::writer::AclWriter::start(canonical_ws.clone(), grants.clone());
    let capabilities: Vec<String> = grants
        .iter()
        .filter_map(|g| crate::win_common::sid_to_string(g.sid.as_psid()).ok())
        .collect();
    let mut broker = lazy_grant::broker::Broker::start(
        lazy_grant::broker::FaultPolicy {
            canonical_workspace: canonical_ws.clone(),
            skip: vec![canonical_ws.join(".harness")],
            mode: "rwx".to_string(),
        },
        writer.handle(),
        &capabilities,
    )
    .expect("the fault receiver must open");

    let pipe = broker.pipe_name().to_string();
    let (stdout, stderr, code) = read_target_in_child(
        &session,
        &workspace,
        workspace_cap.as_psid(),
        RedirectorInject::lazy(&canonical_ws, &pipe),
    );

    let broker_stats = broker.stop();
    let writer_stats = writer.stop_at_safe_point();

    assert!(
        stdout.contains(TARGET_CONTENT),
        "the child must read the unprepared file through the interrupt \
         (exit={code}, stderr={stderr}); broker={broker_stats:?} writer={writer_stats:?}"
    );
    // **割り込みが成立したことを直接測る**（検証6）。読めただけでは、
    // 「実は最初から届いていた」と区別できない。
    assert!(
        broker_stats.served >= 1,
        "the receiver must have served at least one interrupt: {broker_stats:?}"
    );
    // **拒否が0件になるとは限らない。** PowerShellは起動の途中でworkspace外
    // （System32・プロファイル等）を大量に開き、そのうち拒否されたものはここへ届く。
    // 実測で92件だった——`denied`が0でないことは受付が**範囲を守っている**証拠であって、
    // 異常ではない。見るべきは「こちら側の不調が0であること」の側である。
    assert_eq!(
        broker_stats.unavailable, 0,
        "no request may fail on our side in this run: {broker_stats:?}"
    );
    assert_eq!(
        broker_stats.rejected_clients, 0,
        "the child is inside an AppContainer, so it must not be refused at the door: \
         {broker_stats:?}"
    );
    assert!(
        writer_stats.faults_served >= 1,
        "the writer must have processed the interrupt as high-priority work: {writer_stats:?}"
    );
}

/// **本番の起動経路がlazyレーンを選び、コマンドが完走すること**を固定する。
///
/// 上の受入がレーンの部品を直に組むのに対し、こちらは`spawn_shell_in_workspace`
/// （`run_shell`とポリシーエディタが共有する唯一の前口上）を通す。**待つ条件を外した
/// 配線点はここ1箇所**なので、ここが通れば2経路とも通る。
///
/// # ここが**証明していない**こと（`B-08`）
///
/// **「割り込みが成立した」はここでは測れない。** 背景の走査器が対象へ先に着けば、
/// fault無しでも読めてしまい、同じ緑になる。走査の到達順は列挙順に依存するので、
/// テストで固定できない。
///
/// **その主張を持つのは上の受入テスト**（走査器を動かさず、faultでしか開かない状況を
/// 決定的に作る）である。ここが見ているのは「レーンを選んだか（受付が開いたか）」と
/// 「コマンドが完走したか」の2つだけで、**通ったからといって速くなったとは言えない**。
#[test]
#[ignore = "spawns a real AppContainer child and changes real ACLs; run NON-elevated with --test-threads=1"]
fn the_production_launch_path_takes_the_lazy_lane_when_a_receiver_is_open() {
    enable_the_lane_like_production_does();
    let guard = TestDirGuard::create("lazy-launch");
    let workspace = guard.path().to_path_buf();
    let target = workspace.join(TARGET_REL);
    std::fs::create_dir_all(target.parent().expect("the target has a parent"))
        .expect("create the target's directories");
    std::fs::write(&target, TARGET_CONTENT).expect("create the target file");
    for i in 0..2_000 {
        std::fs::write(workspace.join(format!("f{i:04}.txt")), b"x").expect("fill the tree");
    }

    let outcome = preflight(&workspace, &[], None, &WorkspaceWriteMode::DirectRw)
        .unwrap_or_else(|e| panic!("preflight must succeed ({e:?})"));
    for warning in &outcome.warnings {
        eprintln!("preflight warning: {warning}");
    }
    grant_job::wait_until_done().expect("the initial preparation must finish");

    let canonical_ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.clone());
    let _cleanup = scopeguard({
        let canonical_ws = canonical_ws.clone();
        move || cleanup_workspace(&canonical_ws)
    });
    let grants = workspace_grants(&canonical_ws);
    make_unreachable(&target, &grants);

    // lazyレーンの背景ジョブを起こす。**世代を変えて別のジョブにする**——同じ鍵だと
    // 上の`preflight`が既に登録したジョブと衝突して`start`が偽を返す。
    let started = grant_job::start(grant_job::GrantJobRequest {
        root: &canonical_ws,
        ace_grants: grants.clone(),
        protect_sids: Vec::new(),
        skip: vec![canonical_ws.join(".harness")],
        workspace: &canonical_ws,
        mode: "rwx",
        capability_generation: "lazy-acceptance-generation",
        lane: grant_job::PreparationLane::Lazy,
    });
    assert!(
        started,
        "the lazy job must start for this measurement to mean anything"
    );

    // **待たない。** ここが`launch.rs`のlazy分岐へ入る条件そのものである。
    let request = WorkspaceSpawn {
        cwd: workspace.clone(),
        env: crate::secret_env::build_child_env(),
        workspace_root: workspace.clone(),
        cow_diff_layer_dir: None,
        granted_passthrough: Vec::new(),
        net_capability: NetworkCapability::Deny,
        policy_domain: harness_policy::policy_file::ENTRY_DOMAIN.to_string(),
    };
    let pipe_before = grant_job::lazy_broker_pipe_for(&canonical_ws, "rwx");
    assert!(
        pipe_before.is_some(),
        "the lazy job must publish its receiver, otherwise launch cannot take the lane"
    );

    let (child, _) = spawn_shell_in_workspace(request).expect("the production launch path");
    let command = format!("Get-Content -Raw '{}\\{TARGET_REL}'", workspace.display());
    let (stdout, stderr, code) = child
        .write_stdin_read_output_and_wait(Some(command.as_bytes()))
        .expect("read the child output");
    eprintln!("[launch child] exit={code}\nstdout={stdout}\nstderr={stderr}");

    grant_job::wait_until_done().expect("the lazy job must finish cleanly");
    let progress = grant_job::progress().expect("the lazy job leaves progress behind");
    assert!(
        progress.broker_faults_served.is_some(),
        "Some(_) means a receiver was open; None would mean the lane never got one \
         (and those two must never be confused): {progress:?}"
    );
    assert!(
        stdout.contains(TARGET_CONTENT),
        "the command must complete through the lazy lane (exit={code}, stderr={stderr})"
    );
}
