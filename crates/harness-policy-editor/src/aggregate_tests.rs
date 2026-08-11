//! [`crate::aggregate`]の単体テスト。record-all特有の性質——**許可も候補になる**・
//! `.harness`は候補にしない・取りこぼしを隠さない——を固定する。

use super::*;
use harness_config::FsAccess;

/// テスト用の集計器。
///
/// **workspace rootに`C:/work`を使わない**——このファイルのテストは`C:/work/...`を
/// 「候補に残るべきパス」として使っているので、そこをこのセッションのworkspaceにすると
/// [BUG-103]の除外が正しく効いて候補が消え、テストの意図が入れ替わる。
/// `%TEMP%`も**明示で渡す**（実マシンの`%TEMP%`に依存させない、B-28）。
fn test_aggregate() -> Aggregate {
    Aggregate::new(crate::exclusion::ExclusionRules::with_temp_root(
        std::path::Path::new("C:/no-such-workspace"),
        Some(std::path::Path::new("C:/no-such-temp")),
    ))
}

fn observed(path: &str, access: FsAccess, allowed: bool, ts: u64) -> FsAuditEvent {
    FsAuditEvent::observed(
        FsAuditKind::Etw,
        path,
        access,
        allowed,
        if allowed { "observed" } else { "denied" },
        ts,
    )
}

/// **record-allの核心**: 成功したアクセスも候補になる。deny-onlyの
/// `normalize_fs_audit`はこれを捨てるため、記録モードは自前で畳み込む必要がある。
#[test]
fn allowed_accesses_become_candidates_not_just_denials() {
    let mut agg = test_aggregate();
    agg.add_event(&observed("C:/work/Cargo.toml", FsAccess::Read, true, 1));
    agg.add_event(&observed("C:/work/src/lib.rs", FsAccess::Read, true, 2));

    assert_eq!(agg.allowed, 2);
    assert_eq!(agg.denied, 0);
    assert_eq!(agg.candidates().len(), 2);
    assert!(!agg.proposals(Generalization::None).is_empty());
}

/// 同じ`(パス, access)`は畳まれ、件数が積み上がる。
#[test]
fn repeated_accesses_to_the_same_path_are_folded_with_a_count() {
    let mut agg = test_aggregate();
    for ts in 1..=5 {
        agg.add_event(&observed("C:/work/Cargo.toml", FsAccess::Read, true, ts));
    }

    assert_eq!(agg.events_seen, 5);
    assert_eq!(agg.candidates().len(), 1);
    assert_eq!(agg.candidates()[0].count, 5);
}

/// access種別が違えば別候補（P-03: 要求された権限を超えて与えない）。
#[test]
fn different_access_kinds_stay_separate_candidates() {
    let mut agg = test_aggregate();
    agg.add_event(&observed("C:/work/a.txt", FsAccess::Read, true, 1));
    agg.add_event(&observed("C:/work/a.txt", FsAccess::ReadWrite, true, 2));

    assert_eq!(agg.candidates().len(), 2);
}

/// **`.harness`配下は候補にせず、件数を出す。** 提案してはいけない対象（P-08）であり、
/// かつ記録の産物自身がそこにあるため自己参照ループの原因になる。
#[test]
fn harness_control_directory_paths_are_excluded_and_counted() {
    let mut agg = test_aggregate();
    agg.add_event(&observed("C:/work/src/lib.rs", FsAccess::Read, true, 1));
    agg.add_event(&observed(
        "C:/work/.harness/sandbox/policy-editor-x/fs-audit.jsonl",
        FsAccess::Read,
        true,
        2,
    ));
    agg.add_event(&observed(
        "C:/work/.harness/settings.json",
        FsAccess::Read,
        true,
        3,
    ));

    assert_eq!(agg.candidates().len(), 1, "残るのは.harness外の1件だけ");
    assert_eq!(agg.excluded_control_dir, 2);
    // 除外しても「観測した」事実は消さない。
    assert_eq!(agg.events_seen, 3);
    assert_eq!(agg.allowed, 3);

    let text = render(&agg, Generalization::None, 10);
    assert!(text.contains("除外"), "{text}");
    assert!(text.contains("2件"), "{text}");
}

/// **BUG-099の回帰テスト**: `C:/Program Files (x86)`配下への**アクセス**は候補にしない。
///
/// 実機で起きたのはこの形である——`fs.read`候補として提案され、承認され、以後`cargo`ドメインの
/// パス2が`failed to grant traverse ACE ... アクセスが拒否されました`で毎回落ちるようになった。
/// 実行像側（D-58）は除外していたのに、アクセス側の判定が無かったのが根。
///
/// **`fs.read_write`も対象**——preflightが祖先へtraverseを付ける条件はaccessに依らないので、
/// 書き候補を残すと同じ祖先で同じ失敗をする（`breadth::check_value`が止めるのは
/// `C:/Program Files`そのものだけで、その配下の深いパスは通す）。
#[test]
fn accesses_under_a_machine_wide_install_root_are_excluded_and_counted() {
    let mut agg = test_aggregate();

    // 実機の`policy.json`に実際に入ってしまった綴りをそのまま使う。
    agg.add_event(&observed(
        "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt",
        FsAccess::Read,
        true,
        1,
    ));
    agg.add_event(&observed(
        "C:/Windows/System32/kernel32.dll",
        FsAccess::Read,
        true,
        2,
    ));
    // 書き候補も同じ祖先で同じ失敗をするので、同じく出さない。
    agg.add_event(&observed(
        "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207/out.tmp",
        FsAccess::ReadWrite,
        true,
        3,
    ));

    assert_eq!(agg.excluded_machine_wide_root, 3);
    assert!(
        agg.candidates().is_empty(),
        "approving any of these makes preflight fail on an ancestor it cannot write: {:#?}",
        agg.candidates()
    );
    assert!(
        agg.proposals(Generalization::None).is_empty(),
        "{:#?}",
        agg.proposals(Generalization::None)
    );
    // 除外は必ず見せる（B-09）。黙って捨てると「観測できなかった」と区別が付かない。
    let text = render(&agg, Generalization::None, 10);
    assert!(text.contains("C:/Program Files 配下へのアクセス 3件"), "{text}");
    // 観測した事実そのものは消さない。
    assert_eq!(agg.events_seen, 3);
    assert_eq!(agg.allowed, 3);
}

/// **対（B-35）**: 既定では届かない場所は候補に残さなければならない。
///
/// 除外側だけを固定すると、「全部除外」でもテストが緑になる——`C:/Program Files (x86)`を
/// 出さないことは、`.cargo`配下を出すことと同じ重さである（これが出なくなるとパス2が
/// 別の理由で成立しなくなり、しかも症状は「候補が空」という静かな形で出る）。
#[test]
fn accesses_outside_machine_wide_install_roots_stay_proposable() {
    let mut agg = test_aggregate();

    for (ts, path) in [
        "C:/Users/segfo/.cargo/bin/cargo.exe",
        "C:/Users/segfo/.rustup/toolchains/stable-x86_64-pc-windows-msvc/lib/rustlib",
        "C:/tools/rg.exe",
        // `Windows`/`Program Files`で始まるだけの別ディレクトリを巻き込まない（過剰一致の防止）。
        "C:/WindowsApps-mine/tool.exe",
        "C:/Program Files Custom/thing.dll",
    ]
    .iter()
    .enumerate()
    {
        agg.add_event(&observed(path, FsAccess::Read, true, ts as u64 + 1));
    }

    assert_eq!(agg.excluded_machine_wide_root, 0);
    assert_eq!(agg.candidates().len(), 5, "{:#?}", agg.candidates());
    assert!(!agg.proposals(Generalization::None).is_empty());
    // 除外0件のときは注記を出さない（出すと「何か捨てられた」と誤読される）。
    assert!(
        !render(&agg, Generalization::None, 10).contains("配下へのアクセス"),
        "{}",
        render(&agg, Generalization::None, 10)
    );
}

/// `.harness`の判定はパス要素単位で、区切り文字と大小に依存しない。
/// `.harnessrc`のような別名を巻き込まないことも同時に固定する（過剰一致の防止）。
/// **探しに行ったが無かったパスは候補にしない。**
///
/// DLL検索順・PATH探索は存在しないパスを大量に叩き、そのopenは`STATUS_ACCESS_DENIED`では
/// ないので`allowed=true`で届く。無いファイルへの許可には意味が無いので落とすが、件数は出す。
#[test]
fn paths_that_did_not_exist_are_excluded_and_counted() {
    let mut agg = test_aggregate();
    let missing = observed(r"C:\app\ntdll.dll", FsAccess::Read, true, 1).with_status(0xC000_0034); // STATUS_OBJECT_NAME_NOT_FOUND
    let present = observed(r"C:\app\real.dll", FsAccess::Read, true, 2).with_status(0);

    agg.add_event(&missing);
    agg.add_event(&present);

    assert_eq!(agg.excluded_missing_target, 1);
    assert_eq!(agg.candidates().len(), 1, "残るのは実在した方だけ");
    assert!(
        matches!(
            &agg.candidates()[0].requested,
            harness_policy::Requested::Fs { path, .. } if path == "C:/app/real.dll"
        ),
        "{:?}",
        agg.candidates()[0]
    );

    let text = render(&agg, Generalization::None, 10);
    assert!(text.contains("存在しなかったパス 1件"), "{text}");
}

/// 同じパスに「無かった」と「開けた」の両方が来たら、**候補としては残る**
/// （探した後に作られたファイル等。片方だけで判断すると本当に要る許可を落とす）。
#[test]
fn a_path_that_was_missing_once_but_opened_later_stays_a_candidate() {
    let mut agg = test_aggregate();
    agg.add_event(&observed(r"C:\work\out.tmp", FsAccess::Read, true, 1).with_status(0xC000_0034));
    agg.add_event(&observed(r"C:\work\out.tmp", FsAccess::ReadWrite, true, 2).with_status(0));

    assert_eq!(agg.excluded_missing_target, 1);
    assert_eq!(agg.candidates().len(), 1);
}

/// `status`を持たない古い監査ログは**「無かった」に倒さない**（分からないものを捨てない）。
#[test]
fn an_audit_log_without_a_status_is_not_treated_as_missing() {
    let mut agg = test_aggregate();
    agg.add_event(&observed(r"C:\old\file.txt", FsAccess::Read, true, 1));

    assert_eq!(agg.excluded_missing_target, 0);
    assert_eq!(agg.candidates().len(), 1);
}

/// 収集器の制御レコードは候補にせず、**必ず見せる**（「収集できていない」と
/// 「拒否が0件だった」を区別できないと、fail-openは隠蔽になる、D-43）。
#[test]
fn collector_control_records_are_surfaced_not_turned_into_candidates() {
    let mut agg = test_aggregate();
    agg.add_event(&FsAuditEvent::control(
        "etw_session_start_failed: access denied",
        1,
    ));

    assert!(agg.candidates().is_empty());
    assert_eq!(agg.collector_notes.len(), 1);
    let text = render(&agg, Generalization::None, 10);
    assert!(text.contains("収集器からの報告"), "{text}");
    assert!(text.contains("etw_session_start_failed"), "{text}");
}

/// 解釈できなかった行は数えて表示する（黙って捨てない、B-09）。
#[test]
fn unparsable_lines_are_counted_and_shown() {
    let mut agg = test_aggregate();
    agg.add_unparsable(3);

    let text = render(&agg, Generalization::None, 10);
    assert!(text.contains("解釈できなかった行 3件"), "{text}");
}

/// 1件も観測できなかったことは、「候補なし」ではなく**異常の可能性**として伝える。
#[test]
fn an_empty_recording_says_so_instead_of_looking_like_a_clean_run() {
    let agg = test_aggregate();
    let text = render(&agg, Generalization::None, 10);

    assert!(text.contains("1件も観測できませんでした"), "{text}");
}

/// 拒否があったときは、それが通常権限での拒否であることを注記する
/// （BUG-088の設計メモ: 低ILラベルは継承しないのでサブディレクトリ内は書けない）。
#[test]
fn denials_carry_a_note_that_tier1_denials_differ_from_tier2a_needs() {
    let mut agg = test_aggregate();
    agg.add_event(&observed(
        "C:/work/sub/out.txt",
        FsAccess::ReadWrite,
        false,
        1,
    ));

    let text = render(&agg, Generalization::None, 10);
    assert!(text.contains("通常の権限で拒否された"), "{text}");
}

/// **打ち切るなら残件数を必ず出す。** 黙って切ると、見えている分が全部だと誤解される。
#[test]
fn a_truncated_proposal_list_reports_how_many_were_hidden() {
    let mut agg = test_aggregate();
    for i in 0..10 {
        agg.add_event(&observed(
            &format!("C:/work/dir{i}/file.txt"),
            FsAccess::Read,
            true,
            i as u64,
        ));
    }

    let text = render(&agg, Generalization::None, 3);
    assert!(text.contains("他 7件"), "{text}");
}

/// プロセスツリーは親子関係で入れ子になり、親が観測範囲外のものは根になる。
#[test]
fn the_process_tree_nests_children_under_observed_parents() {
    let mut agg = test_aggregate();
    let parent = observed("C:/work/a.txt", FsAccess::Read, true, 1)
        .with_process(200, Some("pwsh.exe".to_string()))
        .with_parent_process(100); // 100は観測範囲外＝200が根になる
    let child = observed("C:/work/b.txt", FsAccess::Read, true, 2)
        .with_process(300, Some("cmd.exe".to_string()))
        .with_parent_process(200);
    agg.add_event(&parent);
    agg.add_event(&child);

    let tree = agg.process_tree();
    assert_eq!(tree.len(), 2);
    assert_eq!((tree[0].0, tree[0].1), (0, 200));
    assert_eq!((tree[1].0, tree[1].1), (1, 300));

    let text = render_process_tree(&agg);
    assert!(text.contains("pwsh.exe"), "{text}");
    assert!(text.contains("cmd.exe"), "{text}");
}

/// PID再利用で親子が閉路になっても、ツリー構築は止まらず**1件も落とさない**。
/// 根が1つも無いので素朴な走査では全件が消えるが、それは黙った取りこぼしになる（B-09）。
#[test]
fn a_cycle_in_the_parentage_does_not_hang_or_drop_processes() {
    let mut agg = test_aggregate();
    agg.add_event(
        &observed("C:/a", FsAccess::Read, true, 1)
            .with_process(1, None)
            .with_parent_process(2),
    );
    agg.add_event(
        &observed("C:/b", FsAccess::Read, true, 2)
            .with_process(2, None)
            .with_parent_process(1),
    );

    let tree = agg.process_tree();
    let pids: Vec<u32> = tree.iter().map(|(_, pid, _)| *pid).collect();
    assert_eq!(
        pids.len(),
        2,
        "閉路の中のプロセスも表示から消さない: {pids:?}"
    );
    assert!(pids.contains(&1) && pids.contains(&2));
}

/// 実行像を持つイベントを1件作る（`ProcessStart`を観測できた世代の記録）。
fn observed_from(path: &str, image: &str, pid: u32, ts: u64) -> FsAuditEvent {
    observed(path, FsAccess::Read, true, ts).with_process(pid, Some(image.to_string()))
}

/// **実行された像は`fs.read_exec`の候補になる。**
///
/// ETWは読取と実行を区別できないので、アクセスイベントから`read_exec`候補は1件も出ない
/// （実測: `cargo`ドメインは`read` 668件・`read_exec` 0件）。実行権が付くのは`read_exec`だけ
/// なので、これが無いとworkspace外のツールは永久に起動できない。
#[test]
fn the_image_of_a_started_process_becomes_a_read_exec_candidate() {
    let mut agg = test_aggregate();
    let image = "C:/Users/segfo/.cargo/bin/cargo.exe";

    agg.add_event(&observed_from("C:/work/Cargo.toml", image, 200, 1));

    let exec: Vec<&harness_policy::DeniedCandidate> = agg
        .candidates()
        .iter()
        .filter(|c| {
            matches!(&c.requested,
                harness_policy::Requested::Fs { access, .. } if *access == FsAccess::ReadExec)
        })
        .collect();
    assert_eq!(exec.len(), 1, "{:#?}", agg.candidates());
    match &exec[0].requested {
        harness_policy::Requested::Fs { path, .. } => assert_eq!(path, image),
        other => panic!("unexpected candidate: {other:?}"),
    }
}

/// **対**（B-35）: 既定で実行できる場所は候補にしない。**しかも件数を出す。**
///
/// 実データではここに`C:/Windows/System32/conhost.exe`と
/// `C:/Program Files/WindowsApps/.../pwsh.exe`が該当した。承認されると`preflight`が
/// TrustedInstaller所有ツリーへACEを付けに行き、UACが増え、最悪パス2が丸ごと落ちる。
#[test]
fn images_that_are_already_executable_are_excluded_and_counted() {
    let mut agg = test_aggregate();

    agg.add_event(&observed_from(
        "C:/work/a.txt",
        "C:/Windows/System32/conhost.exe",
        300,
        1,
    ));
    agg.add_event(&observed_from(
        "C:/work/b.txt",
        "C:/Program Files/WindowsApps/Microsoft.PowerShell_7.6.4.0_x64__8wekyb3d8bbwe/pwsh.exe",
        301,
        2,
    ));

    assert_eq!(agg.excluded_default_exec_image, 2);
    assert!(
        !agg.candidates().iter().any(|c| matches!(&c.requested,
            harness_policy::Requested::Fs { access, .. } if *access == FsAccess::ReadExec)),
        "{:#?}",
        agg.candidates()
    );
    assert!(
        render_notes(&agg).contains("既定で実行権がある"),
        "an exclusion that is not shown is indistinguishable from 'nothing was observed': {}",
        render_notes(&agg)
    );
}

/// **観測そのものは消さない。** 候補にしないだけで、プロセスツリーには従来どおり出る。
#[test]
fn an_excluded_image_still_appears_in_the_process_tree() {
    let mut agg = test_aggregate();
    agg.add_event(&observed_from(
        "C:/work/a.txt",
        "C:/Windows/System32/conhost.exe",
        300,
        1,
    ));

    let tree = render_process_tree(&agg);

    assert!(tree.contains("conhost.exe"), "{tree}");
}

/// 旧形式（`to_settings_path`を通す前）の監査ログに残るNTパスは候補にせず、件数だけ数える。
/// 非昇格側にボリューム対応表が無いので、この綴りは解けない。
#[test]
fn legacy_nt_image_paths_are_counted_but_not_proposed() {
    let mut agg = test_aggregate();

    agg.add_event(&observed_from(
        "C:/work/a.txt",
        r"\Device\HarddiskVolume3\Users\segfo\.cargo\bin\cargo.exe",
        400,
        1,
    ));

    assert_eq!(agg.excluded_legacy_image_path, 1);
    assert!(
        !agg.candidates().iter().any(|c| matches!(&c.requested,
            harness_policy::Requested::Fs { access, .. } if *access == FsAccess::ReadExec)),
        "an unresolvable spelling must not be offered as a settings value"
    );
    assert!(
        render_notes(&agg).contains("変換されていません"),
        "{}",
        render_notes(&agg)
    );
}

/// 同じイメージから何度もプロセスが起動したら**プロセス数**が観測回数になる。
/// アクセス1件ごとに数えると、そのプロセスのI/O量（実測では2.5万件超）が候補の回数欄へ出る。
#[test]
fn the_observed_count_of_an_image_is_the_number_of_processes_not_of_accesses() {
    let mut agg = test_aggregate();
    let image = "C:/Users/segfo/.cargo/bin/cargo.exe";

    // pid 200 が3件、pid 201 が1件アクセスする（プロセスは2個）。
    for ts in 1..=3 {
        agg.add_event(&observed_from("C:/work/a.txt", image, 200, ts));
    }
    agg.add_event(&observed_from("C:/work/b.txt", image, 201, 4));

    let exec = agg
        .candidates()
        .iter()
        .find(|c| {
            matches!(&c.requested,
                harness_policy::Requested::Fs { access, .. } if *access == FsAccess::ReadExec)
        })
        .expect("the exec candidate");
    assert_eq!(exec.count, 2);
}

/// `.harness`配下から起動されたものは候補にしない（アクセス側と同じ規則、P-08）。
#[test]
fn images_under_the_harness_control_directory_are_excluded() {
    let mut agg = test_aggregate();

    agg.add_event(&observed_from(
        "C:/work/a.txt",
        "C:/work/.harness/sandbox/tool.exe",
        500,
        1,
    ));

    assert!(!agg.candidates().iter().any(|c| matches!(&c.requested,
            harness_policy::Requested::Fs { access, .. } if *access == FsAccess::ReadExec)));
    assert!(agg.excluded_control_dir >= 1);
}

/// **候補ではなく「画面に出る提案」まで通ることを固定する。**
///
/// 候補（`candidates`）が正しくても、一般化・幅の判定のどこかで落ちれば`show`には現れない。
/// ユーザーが承認できるのは提案だけなので、固定すべきはこちら側である。
#[test]
fn the_exec_image_reaches_the_proposal_list_as_fs_read_exec() {
    let mut agg = test_aggregate();
    agg.add_event(&observed_from(
        "C:/work/Cargo.toml",
        "C:/Users/segfo/.cargo/bin/cargo.exe",
        200,
        1,
    ));
    agg.add_event(&observed_from(
        "C:/work/src/lib.rs",
        "C:/Users/segfo/.rustup/toolchains/stable-x86_64-pc-windows-msvc/bin/cargo.exe",
        201,
        2,
    ));

    let proposals = agg.proposals(Generalization::Directory);

    let exec: Vec<&harness_policy::RuleProposal> = proposals
        .iter()
        .filter(|p| p.key == harness_policy::generalize::SettingsKey::FsReadExec)
        .collect();
    assert_eq!(exec.len(), 2, "{proposals:#?}");
    assert!(exec
        .iter()
        .any(|p| p.value == "C:/Users/segfo/.cargo/bin/cargo.exe"));
}

// ---------------------------------------------------------------------------
// 実行前診断が名指しした実行ファイル（D-57の追記）と、記録時点の宣言（D-46）
// ---------------------------------------------------------------------------

use crate::session_dir::{DeclaredFsRule, RecordManifest, RecordStatus};

fn pass2_manifest(unreachable: Option<&str>, declared: &[(&str, FsAccess)]) -> RecordManifest {
    let mut manifest = RecordManifest::new(
        "sess-1",
        "cargo test",
        std::path::Path::new("C:/work"),
        std::path::Path::new("C:/work"),
        1_700_000_000_000,
    );
    manifest.pass = 2;
    manifest.status = RecordStatus::Finished;
    manifest.unreachable_exec = unreachable.map(str::to_string);
    manifest.declared_fs = declared
        .iter()
        .map(|(value, access)| DeclaredFsRule {
            value: (*value).to_string(),
            access: *access,
        })
        .collect();
    manifest
}

fn has_proposal(agg: &Aggregate, key: harness_policy::SettingsKey, value: &str) -> bool {
    agg.proposals(Generalization::None)
        .iter()
        .any(|p| p.key == key && p.value.eq_ignore_ascii_case(value))
}

/// **本体**: 起動を拒否された実行ファイルは`ProcessStart`を出さないので観測には出ない。
/// 実行前診断が名指しした1件を`fs.read_exec`の候補として合流させる。
#[test]
fn the_executable_named_by_the_pre_run_diagnosis_becomes_a_read_exec_candidate() {
    let mut agg = test_aggregate();
    let manifest = pass2_manifest(Some("C:/Users/segfo/.cargo/bin/cargo.exe"), &[]);

    apply_session_context(&mut agg, &manifest);

    assert!(
        has_proposal(
            &agg,
            harness_policy::SettingsKey::FsReadExec,
            "C:/Users/segfo/.cargo/bin/cargo.exe"
        ),
        "{:#?}",
        agg.proposals(Generalization::None)
    );
    assert_eq!(
        agg.diagnosed_exec.as_deref(),
        Some("C:/Users/segfo/.cargo/bin/cargo.exe")
    );
}

/// **足したことを黙っていない**（B-09）。「観測されなかった」と「意図して足した」が
/// 区別できないと、なぜこの候補があるのかを調べようがない。
#[test]
fn the_notes_say_the_diagnosed_candidate_is_not_an_observation() {
    let mut agg = test_aggregate();

    apply_session_context(
        &mut agg,
        &pass2_manifest(Some("C:/Users/segfo/.cargo/bin/cargo.exe"), &[]),
    );

    let notes = render_notes(&agg);
    assert!(notes.contains("実行前診断"), "{notes}");
    assert!(
        notes.contains("C:/Users/segfo/.cargo/bin/cargo.exe"),
        "{notes}"
    );
    assert!(
        notes.contains("これは観測ではありません"),
        "the note must not let it read as something the collector saw: {notes}"
    );
}

/// **対（B-35）**: 既定で実行できる場所は名指しされても候補にしない。
/// 承認させると`preflight`がTrustedInstaller所有ノードへACEを付けに行く（D-58・BUG-015）。
#[test]
fn a_diagnosed_executable_under_a_default_exec_root_is_never_proposed() {
    let mut agg = test_aggregate();

    apply_session_context(
        &mut agg,
        &pass2_manifest(Some("C:/Windows/System32/curl.exe"), &[]),
    );

    assert!(agg.proposals(Generalization::None).is_empty());
    assert_eq!(agg.excluded_default_exec_image, 1);
    assert!(agg.diagnosed_exec.is_none());
    assert!(render_notes(&agg).contains("C:/Windows"));
}

/// `.harness`配下も同じく候補にしない（アクセス側・実行像側と同じ規則、P-08）。
#[test]
fn a_diagnosed_executable_under_the_harness_control_directory_is_never_proposed() {
    let mut agg = test_aggregate();

    apply_session_context(
        &mut agg,
        &pass2_manifest(Some("C:/work/.harness/tools/thing.exe"), &[]),
    );

    assert!(agg.proposals(Generalization::None).is_empty());
    assert_eq!(agg.excluded_control_dir, 1);
}

/// 実行像としても観測されていた場合は**1件へ畳む**（同じ値の候補が2行に割れない）。
#[test]
fn a_diagnosed_executable_that_was_also_observed_as_an_image_stays_one_candidate() {
    let mut agg = test_aggregate();
    let image = "C:/Users/segfo/.cargo/bin/cargo.exe";
    agg.add_event(&observed_from("C:/work/a.txt", image, 200, 1));

    apply_session_context(&mut agg, &pass2_manifest(Some(image), &[]));

    let exec: Vec<_> = agg
        .proposals(Generalization::None)
        .into_iter()
        .filter(|p| p.key == harness_policy::SettingsKey::FsReadExec)
        .collect();
    assert_eq!(exec.len(), 1, "{exec:#?}");
    assert_eq!(exec[0].observed_count(), 2, "{exec:#?}");
}

/// 診断が無い記録では候補が1件も増えない（パス1・旧マニフェスト）。
#[test]
fn a_session_without_a_diagnosis_gains_no_candidate() {
    let mut agg = test_aggregate();

    apply_session_context(&mut agg, &pass2_manifest(None, &[]));

    assert!(agg.proposals(Generalization::None).is_empty());
    assert!(agg.diagnosed_exec.is_none());
    assert!(!render_notes(&agg).contains("実行前診断"));
}

/// **パス2では記録時点の宣言を渡す。** 既に`fs.read`で許可済みのパスの拒否は、
/// `fs.read`を提案し直しても`(no changes)`にしかならないので昇格候補へ差し替わる（D-46）。
#[test]
fn a_pass2_denial_on_an_already_declared_path_is_escalated() {
    let mut agg = test_aggregate();
    agg.add_event(&observed(
        "C:/Users/segfo/.rustup/toolchains/stable/bin/cargo.exe",
        FsAccess::Read,
        false,
        1,
    ));

    apply_session_context(
        &mut agg,
        &pass2_manifest(None, &[("C:/Users/segfo/.rustup", FsAccess::Read)]),
    );

    let keys: Vec<_> = agg
        .proposals(Generalization::None)
        .into_iter()
        .map(|p| p.key)
        .collect();
    assert_eq!(
        keys,
        vec![
            harness_policy::SettingsKey::FsReadWrite,
            harness_policy::SettingsKey::FsReadExec
        ],
        "read was already granted, so proposing fs.read again would change nothing"
    );
}

/// **パス1では渡さない。** あちらの候補は「拒否」ではなく「触った全部」なので、
/// 同じ推論をすると宣言済みのパスを触っただけで「readでは足りない」と言い出す。
#[test]
fn a_pass1_session_is_never_escalated_even_if_the_manifest_carries_declarations() {
    let mut agg = test_aggregate();
    agg.add_event(&observed("C:/tools/bin/a.exe", FsAccess::Read, true, 1));
    let mut manifest = pass2_manifest(Some("C:/tools/bin/a.exe"), &[("C:/tools", FsAccess::Read)]);
    manifest.pass = 1;

    apply_session_context(&mut agg, &manifest);

    let proposals = agg.proposals(Generalization::None);
    assert_eq!(proposals.len(), 1, "{proposals:#?}");
    assert_eq!(proposals[0].key, harness_policy::SettingsKey::FsRead);
    assert!(agg.diagnosed_exec.is_none());
}

/// 宣言の綴りは正規化してから突き合わせる（`policy.json`には`\`区切りも入りうる）。
#[test]
fn declared_paths_are_normalized_before_they_are_matched() {
    let mut agg = test_aggregate();
    agg.add_event(&observed(r"C:\tools\bin\x.dll", FsAccess::Read, false, 1));

    apply_session_context(
        &mut agg,
        &pass2_manifest(None, &[(r"C:\tools", FsAccess::ReadExec)]),
    );

    let keys: Vec<_> = agg
        .proposals(Generalization::None)
        .into_iter()
        .map(|p| p.key)
        .collect();
    assert_eq!(keys, vec![harness_policy::SettingsKey::FsReadWrite]);
}

// ---------------------------------------------------------------------------
// [BUG-103] 3つの新しい除外が、候補を作る**2経路とも**を通る
// ---------------------------------------------------------------------------

/// 除外規則を「このセッションのworkspace = `C:/ws`」「`%TEMP%` = `C:/temp`」で作る。
fn bug103_aggregate() -> Aggregate {
    Aggregate::new(crate::exclusion::ExclusionRules::with_temp_root(
        std::path::Path::new("C:/ws"),
        Some(std::path::Path::new("C:/temp")),
    ))
}

/// **アクセス由来**の候補（`fs.read`/`fs.read_write`）が3規則で落ち、件数が注記に出る。
#[test]
fn the_three_new_rules_drop_accesses_and_are_counted() {
    let mut agg = bug103_aggregate();
    agg.add_event(&observed("C:/ws/src/lib.rs", FsAccess::Read, true, 1));
    agg.add_event(&observed(
        "C:/temp/.tmpX3JiLI/ledger.json",
        FsAccess::ReadWrite,
        true,
        2,
    ));
    agg.add_event(&observed(
        "C:/Users/me/AppData/Local/Packages/harness.shell.sandbox.1-2/AC/x",
        FsAccess::Read,
        true,
        3,
    ));

    assert_eq!(agg.excluded_session_workspace, 1);
    assert_eq!(agg.excluded_ephemeral_temp, 1);
    assert_eq!(agg.excluded_sandbox_profile, 1);
    assert!(agg.candidates().is_empty(), "{:#?}", agg.candidates());

    // 除外は必ず見せる（B-09）。
    let text = render_notes(&agg);
    assert!(text.contains("workspace配下 1件"), "{text}");
    assert!(text.contains("%TEMP% 配下 1件"), "{text}");
    assert!(text.contains("サンドボックスプロファイル配下 1件"), "{text}");
}

/// **実行像由来**の候補（`fs.read_exec`）にも同じ3規則が効く。
///
/// BUG-099は「候補を作る経路は2つあるのに、除外は1つにしか無かった」という形だった。
/// 同じ穴を新しい規則で作り直さないよう、像側も対で固定する（B-06）。
#[test]
fn the_three_new_rules_drop_exec_images_too() {
    let mut agg = bug103_aggregate();
    // プロセスの像として観測された実行ファイル。
    agg.add_event(&observed_from(
        "C:/Users/me/.cargo/registry/a.rs",
        "C:/ws/target/debug/tool.exe",
        100,
        1,
    ));
    agg.add_event(&observed_from(
        "C:/Users/me/.cargo/registry/b.rs",
        "C:/temp/.tmpQQ/rustc.exe",
        101,
        2,
    ));
    // 実行前診断が名指しした実行ファイル（観測ではない経路）。
    agg.add_unreachable_exec(
        "C:/Users/me/AppData/Local/Packages/harness.shell.sandbox.1-2/AC/tool.exe",
        3,
    );

    let exec: Vec<&harness_policy::DeniedCandidate> = agg
        .candidates()
        .iter()
        .filter(|c| {
            matches!(&c.requested,
                harness_policy::Requested::Fs { access, .. } if *access == FsAccess::ReadExec)
        })
        .collect();
    assert!(
        exec.is_empty(),
        "none of these may become an fs.read_exec candidate: {exec:#?}"
    );
    assert_eq!(agg.excluded_session_workspace, 1);
    assert_eq!(agg.excluded_ephemeral_temp, 1);
    assert_eq!(agg.excluded_sandbox_profile, 1);
    // 診断が名指しした1件は候補にならなかったので、「足した」とは言わない（B-09）。
    assert_eq!(agg.diagnosed_exec, None);
}

/// **対（B-35）**: 除外が効きすぎていないこと。ここが落ちると「候補が空」という
/// 静かな壊れ方を検出できない。
#[test]
fn paths_outside_the_three_new_rules_stay_candidates() {
    let mut agg = bug103_aggregate();
    // 別のリポジトリ（記録対象が走査しただけ）は正当な承認対象。
    agg.add_event(&observed("C:/other-repo/src/lib.rs", FsAccess::Read, true, 1));
    // workspace・%TEMP%と前方一致するだけの兄弟。
    agg.add_event(&observed("C:/ws2/src/lib.rs", FsAccess::Read, true, 2));
    agg.add_event(&observed("C:/temp2/a.txt", FsAccess::Read, true, 3));
    // 普通の依存先。
    agg.add_event(&observed_from(
        "C:/Users/me/.cargo/registry/a.rs",
        "C:/Users/me/.cargo/bin/cargo.exe",
        200,
        4,
    ));

    assert_eq!(agg.excluded_session_workspace, 0);
    assert_eq!(agg.excluded_ephemeral_temp, 0);
    assert_eq!(agg.excluded_sandbox_profile, 0);
    assert_eq!(agg.candidates().len(), 5, "{:#?}", agg.candidates());
    // 除外0件のときは注記を出さない（出すと「何か捨てられた」と誤読される）。
    let text = render_notes(&agg);
    assert!(!text.contains("workspace配下"), "{text}");
    assert!(!text.contains("%TEMP% 配下"), "{text}");
}
