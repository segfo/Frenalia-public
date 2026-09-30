//! セッションメタのレビュー状態（D-82 の `review` 欄）と、メタを信じない後始末。
//! セッションメタと生存の印は Windows の CoW にだけあるので、Windows だけで走る。
#![cfg(windows)]

mod support;

use harness_review::{discard_review_artifacts, prepare_review, ReviewError};
use harness_sandbox::tier2a::workspace_ledger::{
    hold_cow_session_marker, read_cow_session_meta, set_cow_review_state, write_cow_session_meta,
    CowReviewState,
};
use support::{write, Fixture, SimOptions};

fn one_commit(fx: &Fixture, a: &std::path::Path) {
    fx.git(a, &["switch", "-q", "-c", "feature"]);
    write(&a.join("f.txt"), "f\n");
    fx.git(a, &["add", "-A"]);
    fx.git(a, &["commit", "-q", "-m", "f"]);
}

fn review_state(dl: &std::path::Path) -> Option<CowReviewState> {
    read_cow_session_meta(dl).ok().unwrap().review.clone()
}

/// レビューへ出すと「レビュー待ち」（GC が回収しない状態）になり、後始末で「済み」になる。
/// 記録される接頭辞はセッション ID から組んだもの。
#[test]
fn a_review_is_recorded_as_pending_and_then_settled() {
    let fx = Fixture::new();
    let (dl, _) = fx.session("session-st1", SimOptions::default(), |a| one_commit(&fx, a));
    assert_eq!(review_state(&dl), None);

    prepare_review(&fx.launcher, &fx.request(&dl)).expect("review");
    match review_state(&dl) {
        Some(CowReviewState::Pending { review_ref, .. }) => {
            assert_eq!(review_ref, "refs/harness/review/session-st1/")
        }
        other => panic!("expected pending, got {other:?}"),
    }

    let cleaned = discard_review_artifacts(
        &fx.launcher,
        &fx.ws,
        &dl,
        std::slice::from_ref(&fx.review_root),
    )
    .unwrap();
    assert!(cleaned.problems.is_empty(), "{:?}", cleaned.problems);
    assert!(matches!(
        review_state(&dl),
        Some(CowReviewState::Settled { .. })
    ));
}

/// 後始末はメタの `review_ref` を読まない。子が `refs/heads/main` と書き換えても、
/// 消えるのはこのセッションのレビュー用 ref だけで、本物の main は残る。
#[test]
fn a_review_ref_rewritten_by_the_child_is_not_trusted_by_cleanup() {
    let fx = Fixture::new();
    let (dl, _) = fx.session("session-st2", SimOptions::default(), |a| one_commit(&fx, a));
    prepare_review(&fx.launcher, &fx.request(&dl)).expect("review");
    let main = fx.git(&fx.ws, &["rev-parse", "refs/heads/main"]);
    set_cow_review_state(
        &dl,
        Some(CowReviewState::Pending {
            review_ref: "refs/heads/main".into(),
            fetched_at_unix_secs: 1,
        }),
    )
    .unwrap();

    let cleaned = discard_review_artifacts(
        &fx.launcher,
        &fx.ws,
        &dl,
        std::slice::from_ref(&fx.review_root),
    )
    .unwrap();
    assert_eq!(
        cleaned.refs_deleted,
        ["refs/harness/review/session-st2/heads/feature"]
    );
    assert_eq!(fx.git(&fx.ws, &["rev-parse", "refs/heads/main"]), main);
}

/// 動いているセッション（生存の印が握られている）はレビューしない。本物には何も作らず、
/// 状態も変えない。
#[test]
fn a_session_that_is_still_running_is_not_reviewed() {
    let fx = Fixture::new();
    let sid = format!("session-st3-{}", std::process::id());
    let (dl, _) = fx.session(&sid, SimOptions::default(), |a| one_commit(&fx, a));
    hold_cow_session_marker(&sid).unwrap();

    let err = prepare_review(&fx.launcher, &fx.request(&dl)).expect_err("running");
    assert!(matches!(err, ReviewError::Refused(_)), "{err}");
    assert!(!fx
        .real_refs()
        .iter()
        .any(|(n, _)| n.starts_with("refs/harness/review/")));
    assert_eq!(review_state(&dl), None);
}

/// 別のワークスペースの差分層（メタの `workspace_root` が違う）はレビューしない。
/// 許可側（同じワークスペース）は他のテストが通している。
#[test]
fn a_diff_layer_recorded_for_another_workspace_is_refused() {
    let fx = Fixture::new();
    let (dl, _) = fx.session("session-st4", SimOptions::default(), |a| one_commit(&fx, a));
    std::fs::remove_file(dl.join(".harness-cow-session.json")).unwrap();
    write_cow_session_meta(&dl, &fx.base.join("elsewhere"), "session-st4");

    let err = prepare_review(&fx.launcher, &fx.request(&dl)).expect_err("other workspace");
    assert!(err.to_string().contains("belongs to"), "{err}");
    assert!(!fx
        .real_refs()
        .iter()
        .any(|(n, _)| n.starts_with("refs/harness/review/")));
}

/// メタが無い差分層は、どのワークスペースのものか分からないのでレビューしない。
#[test]
fn a_diff_layer_without_session_metadata_is_refused() {
    let fx = Fixture::new();
    let (dl, _) = fx.session("session-st5", SimOptions::default(), |a| one_commit(&fx, a));
    std::fs::remove_file(dl.join(".harness-cow-session.json")).unwrap();
    let err = prepare_review(&fx.launcher, &fx.request(&dl)).expect_err("no meta");
    assert!(matches!(err, ReviewError::Refused(_)), "{err}");
}
