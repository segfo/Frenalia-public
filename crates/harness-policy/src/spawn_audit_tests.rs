//! [`super`]（許可した生成の記録の形と読み方・パス2のファイル操作の振り分け）の試験。

use super::*;
use crate::event::{FsAuditEvent, FsAuditKind};
use harness_config::FsAccess;

const HEADER_LINE: &str = r#"{"kind":"header","schema_version":1}"#;
const SPAWNED_LINE: &str = r#"{"kind":"spawned","ts_unix_ms":7,"pid":4242,"process_sequence_number":665736,"domain":"p6-child","exe":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","top_level":false}"#;
const SPAWNED_WITHOUT_SEQ_LINE: &str = r#"{"kind":"spawned","ts_unix_ms":8,"pid":4243,"domain":"workspace-shell","exe":"C:\\x.exe","top_level":true}"#;
const RESTARTED_LINE: &str = r#"{"kind":"console_holder_restarted","ts_unix_ms":9,"domain":"p6-child","old_pid":10,"old_exit_code":3221225786,"new_pid":11}"#;
const OVERFLOW_LINE: &str = r#"{"kind":"overflow","ts_unix_ms":10,"dropped":5}"#;

fn spawned(seq: Option<u64>, domain: &str) -> SpawnAuditRecord {
    SpawnAuditRecord::Spawned {
        ts_unix_ms: 7,
        pid: 4242,
        process_sequence_number: seq,
        domain: domain.to_string(),
        exe: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
        top_level: false,
    }
}

/// 書く側（Daemon）と読む側（エディタ）が同じ綴りを使うことを、行のバイト列で固定する。番号が取れなかった行は欄ごと書かない
/// （推測で埋めない。`null`も書かない）。
#[test]
fn spawn_audit_wire_format_is_stable() {
    let header = SpawnAuditRecord::Header {
        schema_version: SPAWN_AUDIT_SCHEMA_VERSION,
    };
    assert_eq!(header.to_jsonl_line().unwrap(), HEADER_LINE);
    assert_eq!(
        spawned(Some(665_736), "p6-child").to_jsonl_line().unwrap(),
        SPAWNED_LINE
    );
    let without = SpawnAuditRecord::Spawned {
        ts_unix_ms: 8,
        pid: 4243,
        process_sequence_number: None,
        domain: crate::policy_file::ENTRY_DOMAIN.to_string(),
        exe: r"C:\x.exe".to_string(),
        top_level: true,
    };
    assert_eq!(without.to_jsonl_line().unwrap(), SPAWNED_WITHOUT_SEQ_LINE);
    let restarted = SpawnAuditRecord::ConsoleHolderRestarted {
        ts_unix_ms: 9,
        domain: "p6-child".to_string(),
        old_pid: 10,
        old_exit_code: Some(0xC000_013A),
        new_pid: 11,
    };
    assert_eq!(restarted.to_jsonl_line().unwrap(), RESTARTED_LINE);
    let overflow = SpawnAuditRecord::Overflow {
        ts_unix_ms: 10,
        dropped: 5,
    };
    assert_eq!(overflow.to_jsonl_line().unwrap(), OVERFLOW_LINE);
    for (line, record) in [
        (SPAWNED_LINE, spawned(Some(665_736), "p6-child")),
        (SPAWNED_WITHOUT_SEQ_LINE, without),
        (RESTARTED_LINE, restarted),
        (OVERFLOW_LINE, overflow),
    ] {
        assert_eq!(serde_json::from_str::<SpawnAuditRecord>(line).unwrap(), record);
    }
}

fn file(lines: &[&str]) -> String {
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

/// 知らない新しい版を、知っている形として読まない。
#[test]
fn a_future_version_is_refused() {
    let text = file(&[r#"{"kind":"header","schema_version":2}"#, SPAWNED_LINE]);
    assert_eq!(
        parse_spawn_audit(&text),
        Err(SpawnAuditError::FutureSchema {
            found: 2,
            supported: SPAWN_AUDIT_SCHEMA_VERSION
        })
    );
}

/// 版の行で始まらないファイルは読まない。**空のファイル（エディタが先に作り、Daemon が1行も書かなかった）は空の記録**
/// ——「読めない」と「生成が無かった」を分ける。
#[test]
fn a_file_without_a_header_is_not_read_but_an_empty_one_is_empty() {
    assert!(matches!(
        parse_spawn_audit(&file(&[SPAWNED_LINE])),
        Err(SpawnAuditError::MissingHeader { .. })
    ));
    assert_eq!(parse_spawn_audit(""), Ok(SpawnAuditLog::default()));
}

/// 読めない行は黙って捨てずに数える。書きかけの最後の行（改行が無い）は数えない。
#[test]
fn an_unreadable_line_is_counted() {
    let mut text = file(&[HEADER_LINE, "not json", SPAWNED_LINE]);
    text.push_str(r#"{"kind":"spawn"#);
    let log = parse_spawn_audit(&text).unwrap();
    assert_eq!(log.unreadable_lines, 1);
    assert_eq!(log.spawned, 1);
    assert_eq!(log.domains_by_sequence.get(&665_736).map(String::as_str), Some("p6-child"));
}

/// あふれた件数・番号の無い生成・立て直しの回数を読み出す（読む側が「記録できなかった子がある」と言えるように）。
#[test]
fn an_overflow_line_is_reported() {
    let text = file(&[
        HEADER_LINE,
        SPAWNED_LINE,
        SPAWNED_WITHOUT_SEQ_LINE,
        RESTARTED_LINE,
        OVERFLOW_LINE,
    ]);
    let log = parse_spawn_audit(&text).unwrap();
    assert_eq!(log.spawned, 2);
    assert_eq!(log.without_sequence_number, 1);
    assert_eq!(log.console_holder_restarts, 1);
    assert_eq!(log.dropped, 5);
}

fn denial(path: &str, seq: Option<u64>) -> FsAuditEvent {
    let event = FsAuditEvent::denied(FsAuditKind::Etw, path, FsAccess::Read, "STATUS_ACCESS_DENIED", 1);
    match seq {
        Some(seq) => event.with_process_sequence_number(seq),
        None => event,
    }
}

fn log_of(pairs: &[(u64, &str)]) -> SpawnAuditLog {
    SpawnAuditLog {
        domains_by_sequence: pairs.iter().map(|(seq, d)| (*seq, d.to_string())).collect(),
        spawned: pairs.len(),
        ..SpawnAuditLog::default()
    }
}

/// **拒否は、その操作をしたプロセスを Daemon が起こしたドメインへ振り分ける**（決定68の前例の(1)）。
/// 入口が直接した操作は入口へ、子がした操作は子へ——子孫の分を親へ足さない（決定65(5)）。
#[test]
fn denials_are_partitioned_by_the_domain_the_daemon_spawned_into() {
    let events = vec![
        denial(r"C:\marker\child.txt", Some(10)),
        denial(r"C:\marker\other.txt", Some(20)),
        denial(r"C:\marker\other2.txt", Some(20)),
    ];
    let log = log_of(&[(10, crate::policy_file::ENTRY_DOMAIN), (20, "p6-child")]);
    let partition = partition_fs_by_spawns(&events, &log);
    let entry = &partition.by_domain[crate::policy_file::ENTRY_DOMAIN];
    assert_eq!(entry.events.len(), 1);
    assert_eq!(entry.events[0].path.as_deref(), Some(r"C:\marker\child.txt"));
    assert_eq!(partition.by_domain["p6-child"].events.len(), 2);
    assert_eq!(partition.unattributed, crate::position_domains::Unattributed::default());
}

/// **どのドメインにも引けない拒否は入口に寄せず件数だけ**（決定65 Q4）。番号の無い行・記録に無い番号の行の2つ。
/// 制御の行は振り分けも数えもしない（位置ごとのドメインの振り分けと同じ）。
#[test]
fn a_denial_without_or_with_an_unknown_sequence_number_is_unattributed() {
    let events = vec![
        denial(r"C:\a", None),
        denial(r"C:\b", Some(99)),
        FsAuditEvent::control("collector started", 1),
    ];
    let log = log_of(&[(10, crate::policy_file::ENTRY_DOMAIN)]);
    let partition = partition_fs_by_spawns(&events, &log);
    assert!(partition.by_domain.is_empty(), "{:?}", partition.by_domain.keys());
    assert_eq!(partition.unattributed.without_sequence_number, 1);
    assert_eq!(partition.unattributed.unknown_sequence_number, 1);
    assert_eq!(partition.unattributed.unassigned_instance, 0);
}
