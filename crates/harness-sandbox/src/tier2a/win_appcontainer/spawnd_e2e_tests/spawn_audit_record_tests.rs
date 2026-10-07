//! [決定68] **許可した生成の記録の受け入れ**——Daemon が起こした子ごとに（通し番号, ドメイン）を、Hello で名前を
//! 受け取った記録へ書く。
//!
//! | # | 何を測るか | 期待 |
//! |---|---|---|
//! | A1 | 記録を頼んだ Daemon が、トップレベルとそれが頼んだ入れ子を起こす | 2行（`top_level`が真と偽）・ドメイン・通し番号が非0 |
//! | A2 | 記録を頼まない Daemon（`harness.exe`の形）で同じことをする | 記録のディレクトリに何も増えない |
//!
//! **A2 が無いと「いつも書く」実装で緑になり、A1 が無いと「何も書かない」実装で緑になる**（`B-35`）。
//!
//! # ここで測っていないもの
//!
//! - **通し番号が ETW の番号と一致するか**——Daemon が取った値（`NtQueryInformationProcess`）と収集器が付けた値の突き合わせは、
//!   収集器を起こすパス2の昇格E2E（`e2e-policy-editor-pass2-domains`）が測る。
//! - コンソールの保持プロセスの立て直し（`console_holder_restarted`）——保持プロセスを外から落とす腕は持たない。

use std::time::Duration;

use super::transition_acceptance_tests::{ask_daemon, policy_with_edge, request_payload, wait_for_file};
use super::*;

fn spawn_audit_path(case: &Case, record: &str) -> std::path::PathBuf {
    case.canonical_workspace
        .join(".harness")
        .join("sandbox")
        .join(record)
        .join(harness_policy::spawn_audit::SPAWN_AUDIT_FILE)
}

/// **A1**: 記録を頼んだ Daemon は、トップレベル（ホストが頼んだ）と入れ子（サンドボックスの中から頼まれた）の両方を書く。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_daemon_with_a_record_writes_the_top_level_and_the_nested_child() {
    let probe = super::super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();
    let record = "policy-editor-spawnd-e2e-1";
    let (case, profile, caps) = setup_with_spawn_audit("spawnd-p6-audit", record, |_workspace| {
        policy_with_edge(E2E_POLICY_DOMAIN, &probe_str)
    });
    let workspace = case.dir.as_ref().expect("case owns the dir").path().to_path_buf();
    let marker = workspace.join("nested-child-ran.json");
    let payload = request_payload(
        &probe_str,
        &["--emit", "nested-ok", "--report-file", &marker.to_string_lossy()],
        &workspace,
    );
    let out = ask_daemon(&case, &profile, &caps, &payload);
    assert_eq!(reply_kind(&out).as_deref(), Some("spawned"), "{out}");
    assert!(
        wait_for_file(&marker, Duration::from_secs(30)),
        "the nested child did not run: {}",
        marker.display()
    );
    let path = spawn_audit_path(&case, record);
    let text = std::fs::read_to_string(&path).expect("read the spawn audit");
    let log = harness_policy::spawn_audit::parse_spawn_audit(&text)
        .unwrap_or_else(|e| panic!("the spawn audit must parse: {e}\n{text}"));
    eprintln!("[spawnd-p6-audit] {}\n{text}", path.display());
    assert_eq!(log.spawned, 2, "the top level and the nested child: {text}");
    assert_eq!(log.without_sequence_number, 0, "{text}");
    assert_eq!(log.domains_by_sequence.len(), 2, "two distinct sequence numbers: {text}");
    assert!(
        log.domains_by_sequence.keys().all(|seq| *seq != 0),
        "{text}"
    );
    assert!(
        log.domains_by_sequence.values().all(|d| d == E2E_POLICY_DOMAIN),
        "both spawns are in the caller's domain (a self-loop): {text}"
    );
    assert!(text.contains(r#""top_level":true"#) && text.contains(r#""top_level":false"#), "{text}");
    drop(case);
}

/// **A2（対）**: 記録を頼まない Daemon は、同じ生成をしても何も書かない（ファイルも作らない）。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_daemon_without_a_record_writes_nothing() {
    let probe = super::super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();
    let (case, profile, caps) = setup_with_policy_and_transitions(
        "spawnd-p6-no-audit",
        ChildProcessPolicy::Unrestricted,
        |_workspace| policy_with_edge(E2E_POLICY_DOMAIN, &probe_str),
    );
    let workspace = case.dir.as_ref().expect("case owns the dir").path().to_path_buf();
    let marker = workspace.join("nested-child-ran.json");
    let payload = request_payload(
        &probe_str,
        &["--emit", "nested-ok", "--report-file", &marker.to_string_lossy()],
        &workspace,
    );
    let out = ask_daemon(&case, &profile, &caps, &payload);
    assert_eq!(reply_kind(&out).as_deref(), Some("spawned"), "{out}");
    assert!(wait_for_file(&marker, Duration::from_secs(30)), "the nested child did not run");
    let sandbox = case.canonical_workspace.join(".harness").join("sandbox");
    let written: Vec<_> = walk(&sandbox)
        .into_iter()
        .filter(|p| p.file_name().is_some_and(|n| n == harness_policy::spawn_audit::SPAWN_AUDIT_FILE))
        .collect();
    assert!(written.is_empty(), "a daemon without a record wrote {written:?}");
    drop(case);
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}
