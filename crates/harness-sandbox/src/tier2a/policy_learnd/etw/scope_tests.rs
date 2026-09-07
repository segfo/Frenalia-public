//! [`crate::tier2a::policy_learnd::etw::scope`]の単体テスト。
//!
//! 3つのsignal（`PackageFullName` / 親からの継承 / `OpenProcess`照会）の優先順位・PID再利用・
//! 取りこぼしの計数を、**Win32もETWも使わずに**固定する。`probe`をクロージャで注入する設計に
//! したのはこのためである。

use super::*;

fn start(
    pid: u32,
    parent: Option<u32>,
    package: Option<&str>,
    seq: Option<u64>,
) -> ProcessStartInfo {
    ProcessStartInfo {
        pid,
        parent_pid: parent,
        image_name: Some(format!("\\Device\\HarddiskVolume3\\test\\{pid}.exe")),
        package_full_name: package.map(str::to_string),
        process_sequence_number: seq,
    }
}

/// probeを一切呼んではいけない場面で使う（呼ばれたらpanicする）。
fn never_probe(_pid: u32) -> Option<bool> {
    panic!("probe must not be called when the verdict is already known from ProcessStart");
}

const PROFILE: &str = "harness.shell.sandbox.a1b2c3";

#[test]
fn short_lived_top_level_children_accept_both_hosts_but_exclude_the_daemon_itself() {
    let mut tracker = ScopeTracker::new(PROFILE)
        .with_harness_pid(Some(10))
        .with_spawn_daemon_pid(Some(20));

    assert!(tracker.on_process_start_probing(&start(101, Some(20), None, Some(1)), |_| None));
    assert!(!tracker.on_process_start_probing(&start(20, Some(10), None, Some(2)), |_| None));
    assert!(tracker.on_process_start_probing(&start(102, Some(10), None, Some(3)), |_| None));
    assert!(!tracker.on_process_start_probing(&start(103, Some(99), None, Some(4)), |_| None));
}

// --- signal 1: PackageFullName -------------------------------------------

/// プロファイル名と完全一致する`PackageFullName`は対象。
#[test]
fn a_package_name_equal_to_the_profile_puts_the_process_in_scope() {
    let mut tracker = ScopeTracker::new(PROFILE);

    assert!(tracker.on_process_start(&start(100, None, Some(PROFILE), Some(1))));

    assert_eq!(tracker.classify(100, never_probe), ScopeVerdict::InScope);
    assert!(tracker.package_name_ever_matched());
}

/// MSIX風の装飾（`<name>_<version>_<arch>__<hash>`）が付いていても、`_`直後で切れていれば対象。
/// 電卓が`Microsoft.WindowsCalculator_11.2606.0.0_x64__8wekyb3d8bbwe`の形だった実測に合わせる。
#[test]
fn a_decorated_package_name_still_matches_the_profile() {
    let mut tracker = ScopeTracker::new(PROFILE);

    let decorated = format!("{PROFILE}_1.0.0.0_x64__8wekyb3d8bbwe");
    assert!(tracker.on_process_start(&start(100, None, Some(&decorated), Some(1))));
}

/// **別セッションのプロファイルへ前方一致で誤爆しない。**
/// `harness.shell.sandbox.a1b2c3` が `harness.shell.sandbox.a1b2c3ff` を拾ってはいけない
/// ——拾うと、あるセッションの収集器が別セッションのイベントを取り込む。
#[test]
fn a_longer_sibling_profile_name_does_not_match() {
    let mut tracker = ScopeTracker::new(PROFILE);

    assert!(!tracker.on_process_start(&start(
        100,
        None,
        Some("harness.shell.sandbox.a1b2c3ff"),
        Some(1)
    )));
    assert!(!tracker.package_name_ever_matched());
}

/// 無関係なパッケージは対象外。
#[test]
fn an_unrelated_package_is_out_of_scope() {
    let mut tracker = ScopeTracker::new(PROFILE);

    assert!(!tracker.on_process_start(&start(
        100,
        None,
        Some("Microsoft.WindowsCalculator_11.2606.0.0_x64__8wekyb3d8bbwe"),
        Some(1)
    )));
    assert_eq!(tracker.classify(100, never_probe), ScopeVerdict::OutOfScope);
}

#[test]
fn package_matching_is_case_insensitive_and_rejects_an_empty_profile() {
    assert!(package_matches_profile(
        "HARNESS.SHELL.SANDBOX.A1B2C3",
        PROFILE
    ));
    assert!(!package_matches_profile("anything", ""));
    assert!(!package_matches_profile("", PROFILE));
}

// --- signal 2: 親からの継承 ----------------------------------------------

/// **T-15**: AppContainerトークンは子孫へ無条件に継承されるので、親が対象なら子も対象。
/// `PackageFullName`が空でもこの経路で拾える。
#[test]
fn a_child_of_an_in_scope_process_is_in_scope_even_without_a_package_name() {
    let mut tracker = ScopeTracker::new(PROFILE);
    tracker.on_process_start(&start(100, None, Some(PROFILE), Some(1)));

    assert!(tracker.on_process_start(&start(200, Some(100), None, Some(2))));
    assert_eq!(tracker.classify(200, never_probe), ScopeVerdict::InScope);
}

/// 継承は世代を跨いで伝わる（孫・ひ孫）。CoWのRedirector DLL経由で起動される孫を拾うのに要る。
#[test]
fn scope_inheritance_propagates_across_generations() {
    let mut tracker = ScopeTracker::new(PROFILE);
    tracker.on_process_start(&start(100, None, Some(PROFILE), Some(1)));
    tracker.on_process_start(&start(200, Some(100), None, Some(2)));

    assert!(tracker.on_process_start(&start(300, Some(200), None, Some(3))));
    assert!(tracker.on_process_start(&start(400, Some(300), None, Some(4))));
    assert_eq!(tracker.classify(400, never_probe), ScopeVerdict::InScope);
    assert_eq!(tracker.in_scope_process_count(), 4);
}

/// 対象外プロセスの子は対象外（継承が逆向きに漏れない）。
#[test]
fn a_child_of_an_out_of_scope_process_stays_out_of_scope() {
    let mut tracker = ScopeTracker::new(PROFILE);
    tracker.on_process_start(&start(100, None, None, Some(1)));

    assert!(!tracker.on_process_start(&start(200, Some(100), None, Some(2))));
}

// --- signal 3: OpenProcess照会 -------------------------------------------

/// `ProcessStart`を観測していないPIDは照会へ回る。結果はキャッシュされ、2回目は照会しない。
#[test]
fn an_unseen_pid_falls_back_to_probing_and_the_result_is_cached() {
    let mut tracker = ScopeTracker::new(PROFILE);

    assert_eq!(tracker.classify(999, |_| Some(true)), ScopeVerdict::InScope);
    assert_eq!(tracker.classify(999, never_probe), ScopeVerdict::InScope);
}

/// **短命プロセス**: 照会できなかったら`Unknown`。捨てるが**件数を数える**（D-43は隠さない）。
#[test]
fn a_failed_probe_yields_unknown_and_is_counted() {
    let mut tracker = ScopeTracker::new(PROFILE);

    assert_eq!(tracker.classify(999, |_| None), ScopeVerdict::Unknown);
    assert_eq!(tracker.classify(998, |_| None), ScopeVerdict::Unknown);
    assert_eq!(tracker.unresolved_count(), 2);
}

/// 照会失敗は**キャッシュしない**——次のイベントでは開けるかもしれないため。
#[test]
fn a_failed_probe_is_not_cached_so_a_later_attempt_can_succeed() {
    let mut tracker = ScopeTracker::new(PROFILE);
    assert_eq!(tracker.classify(999, |_| None), ScopeVerdict::Unknown);

    assert_eq!(tracker.classify(999, |_| Some(true)), ScopeVerdict::InScope);
    assert_eq!(
        tracker.unresolved_count(),
        1,
        "only the first attempt counted"
    );
}

/// `ProcessStart`で分かっているPIDには照会しない（`never_probe`がpanicしないことで確認）。
#[test]
fn probing_is_skipped_for_pids_known_from_process_start() {
    let mut tracker = ScopeTracker::new(PROFILE);
    tracker.on_process_start(&start(100, None, Some(PROFILE), Some(1)));
    tracker.on_process_start(&start(101, None, None, Some(2)));

    assert_eq!(tracker.classify(100, never_probe), ScopeVerdict::InScope);
    assert_eq!(tracker.classify(101, never_probe), ScopeVerdict::OutOfScope);
}

// --- PID再利用 -------------------------------------------------------------

/// 同じPIDで新しい世代（大きい`ProcessSequenceNumber`）が来たら、前の判定を捨てる。
/// これをやらないと、対象だったPIDが再利用された後の無関係なプロセスまで拾ってしまう。
#[test]
fn a_reused_pid_with_a_newer_sequence_replaces_the_previous_verdict() {
    let mut tracker = ScopeTracker::new(PROFILE);
    tracker.on_process_start(&start(100, None, Some(PROFILE), Some(10)));
    assert_eq!(tracker.classify(100, never_probe), ScopeVerdict::InScope);

    // PIDが再利用され、今度は無関係なプロセス。
    assert!(!tracker.on_process_start(&start(100, None, None, Some(11))));
    assert_eq!(tracker.classify(100, never_probe), ScopeVerdict::OutOfScope);
}

/// 順序が入れ替わって届いた**古い**`ProcessStart`は、新しい判定を上書きしない。
#[test]
fn an_out_of_order_older_process_start_does_not_overwrite_a_newer_verdict() {
    let mut tracker = ScopeTracker::new(PROFILE);
    tracker.on_process_start(&start(100, None, Some(PROFILE), Some(20)));

    // 遅れて届いた古い世代のイベント。
    assert!(tracker.on_process_start(&start(100, None, None, Some(19))));
    assert_eq!(
        tracker.classify(100, never_probe),
        ScopeVerdict::InScope,
        "the newer verdict must survive"
    );
}

/// シーケンス番号が無い（古いWindows）場合は、到着順で単純に上書きする。
/// 「古い判定が新しいプロセスへ漏れる」ことは防げる。
#[test]
fn without_sequence_numbers_the_latest_process_start_wins() {
    let mut tracker = ScopeTracker::new(PROFILE);
    tracker.on_process_start(&start(100, None, Some(PROFILE), None));

    assert!(!tracker.on_process_start(&start(100, None, None, None)));
    assert_eq!(tracker.classify(100, never_probe), ScopeVerdict::OutOfScope);
}

// --- 全体の性質 -----------------------------------------------------------

/// **`PackageFullName`が一度も埋まらない環境でも収集器は動く**（実測待ちの未確定要素、
/// `plans/etw-spike/RESULTS.md` §10.2）。その場合は照会経路だけで判定が成立し、
/// `package_name_ever_matched()`が`false`のままになるので、収集器はその事実を制御レコードへ残せる。
#[test]
fn the_tracker_still_works_when_package_names_are_never_populated() {
    let mut tracker = ScopeTracker::new(PROFILE);
    tracker.on_process_start(&start(100, None, None, Some(1)));

    assert!(!tracker.package_name_ever_matched());
    assert_eq!(tracker.classify(555, |_| Some(true)), ScopeVerdict::InScope);
}

// --- ProcessStart時のprobe（実測を受けた本命の経路） --------------------------

/// **実測でharnessのAppContainerは`PackageFullName`を報告しないと判明した**
/// （`plans/etw-spike/RESULTS.md` §11）。したがって第1世代はprobeでしか識別できない。
/// `ProcessStart`の時点で聞けば、そのプロセスはまだ生きている。
#[test]
fn a_first_generation_child_is_identified_by_probing_at_process_start() {
    let mut tracker = ScopeTracker::new(PROFILE);
    // 実測と同じ形: package名は無く、親はharness自身（＝対象外）。
    let child = start(100, Some(9999), None, Some(1));

    assert!(tracker.on_process_start_probing(&child, |_| Some(true)));

    // 以後、拒否イベント時にはもうprobeしない（ProcessStart時に確定済み）。
    assert_eq!(tracker.classify(100, never_probe), ScopeVerdict::InScope);
    assert!(
        !tracker.package_name_ever_matched(),
        "package name did not help"
    );
}

/// 第1世代がprobeで確定したあとは、子孫がsignal 2（継承）で拾える——
/// `--sandbox tier2a-cow`のRedirector DLL経由で起こる孫・ひ孫はこの経路で入る。
#[test]
fn descendants_are_covered_by_inheritance_once_the_first_generation_is_probed() {
    let mut tracker = ScopeTracker::new(PROFILE);
    tracker.on_process_start_probing(&start(100, Some(9999), None, Some(1)), |_| Some(true));

    // 孫・ひ孫はprobeを呼ばずに継承だけで決まる。
    assert!(tracker.on_process_start_probing(&start(200, Some(100), None, Some(2)), never_probe));
    assert!(tracker.on_process_start_probing(&start(300, Some(200), None, Some(3)), never_probe));
    assert_eq!(tracker.classify(300, never_probe), ScopeVerdict::InScope);
}

/// 対象外プロセスもProcessStart時に確定し、以後は問い合わせ直さない
/// （マシン全体のプロセスに毎回`OpenProcess`するのを避ける）。
#[test]
fn an_unrelated_process_is_settled_once_at_process_start() {
    let mut tracker = ScopeTracker::new(PROFILE);

    assert!(!tracker.on_process_start_probing(&start(100, None, None, Some(1)), |_| Some(false)));

    assert_eq!(tracker.classify(100, never_probe), ScopeVerdict::OutOfScope);
}

/// ProcessStart時のprobeも失敗しうる（配送遅延中に終了した極端に短命なプロセス）。
/// その場合は判定を確定させず、後続の拒否イベント側で改めて試せる状態にしておく。
#[test]
fn a_failed_probe_at_process_start_leaves_the_verdict_open() {
    let mut tracker = ScopeTracker::new(PROFILE);

    assert!(!tracker.on_process_start_probing(&start(100, None, None, Some(1)), |_| None));

    // 「対象外」として固定されていない——拒否イベント時にもう一度聞ける。
    assert_eq!(tracker.classify(100, |_| Some(true)), ScopeVerdict::InScope);
}
