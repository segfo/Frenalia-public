//! `process-audit.jsonl`の型（[`super`]）の試験。書く側（昇格した収集プロセス）と読む側（エディタ）が
//! 別のプロセス・別の版で動くので、**行の形をバイト列で固定する**（`LearnPolicy`のワイヤ形式の試験、D-34と同じ）。

use super::*;

const HEADER_LINE: &str = r#"{"kind":"header","schema_version":1}"#;

/// 親の番号を欄から取り、引数が結び付いたインスタンス（2段目の`cmd`の形）。
const EXACT_LINE: &str = r#"{"kind":"instance","seq":665737,"parent_seq":665736,"parent_seq_source":"etw-field","pid":51916,"parent_pid":34852,"image_path":"C:/Windows/System32/cmd.exe","argv":{"state":"exact","command_line":"cmd  /c cmd /c type run-a.txt","truncation":"none"},"is_scope_root":false,"timestamp_unix_ms":1700000000123}"#;

/// 親の番号が無く（欄が無い版）、引数も来なかったインスタンス。**欠けた欄はキーごと出ない**。
const MISSING_LINE: &str = r#"{"kind":"instance","seq":665736,"parent_seq_source":"unresolved","pid":34852,"argv":{"state":"missing","reason":"no_argv_observed"},"is_scope_root":false,"timestamp_unix_ms":1700000000120}"#;

const CONTROL_LINE: &str =
    r#"{"kind":"control","reason":"argv_binding: exact=2 no_argv_observed=1","timestamp_unix_ms":42}"#;

fn exact_instance() -> ProcessInstance {
    ProcessInstance {
        seq: 665_737,
        parent_seq: Some(665_736),
        parent_seq_source: ParentSeqSource::EtwField,
        pid: 51_916,
        parent_pid: Some(34_852),
        image_path: Some("C:/Windows/System32/cmd.exe".to_string()),
        argv: ArgvBinding::Exact {
            command_line: "cmd  /c cmd /c type run-a.txt".to_string(),
            truncation: ArgvTruncation::None,
        },
        is_scope_root: false,
        timestamp_unix_ms: 1_700_000_000_123,
    }
}

fn missing_instance() -> ProcessInstance {
    ProcessInstance {
        seq: 665_736,
        parent_seq: None,
        parent_seq_source: ParentSeqSource::Unresolved,
        pid: 34_852,
        parent_pid: None,
        image_path: None,
        argv: ArgvBinding::Missing {
            reason: ArgvMissingReason::NoArgvObserved,
        },
        is_scope_root: false,
        timestamp_unix_ms: 1_700_000_000_120,
    }
}

/// **行の形を固定する。** 書く側と読む側は別のプロセスで、常駐の収集プロセスは前のビルドのことがある
/// （D-56）。形が黙って変わると、読む側は「その欄が無い記録」として読み違える。
///
/// 4つの形（版の行・引数が結び付いた行・欄が欠けた行・制御の行）を文字列で比べ、読み戻して元と
/// 等しいことも見る。**欠けた欄はキーごと出ない**（`null`を書かない。`FsAuditEvent`と同じ）。
#[test]
fn process_audit_wire_format_is_stable() {
    let header = ProcessAuditRecord::Header {
        schema_version: PROCESS_AUDIT_SCHEMA_VERSION,
    };
    assert_eq!(header.to_jsonl_line().unwrap(), HEADER_LINE);

    let exact = ProcessAuditRecord::Instance(exact_instance());
    assert_eq!(exact.to_jsonl_line().unwrap(), EXACT_LINE);

    let missing = ProcessAuditRecord::Instance(missing_instance());
    let missing_line = missing.to_jsonl_line().unwrap();
    assert_eq!(missing_line, MISSING_LINE);
    for absent in ["parent_seq\"", "parent_pid", "image_path", "null"] {
        assert!(
            !missing_line.contains(absent),
            "欠けた欄 {absent} が行に出ている: {missing_line}"
        );
    }

    let control = ProcessAuditRecord::Control {
        reason: "argv_binding: exact=2 no_argv_observed=1".to_string(),
        timestamp_unix_ms: 42,
    };
    assert_eq!(control.to_jsonl_line().unwrap(), CONTROL_LINE);

    for (line, record) in [
        (HEADER_LINE, header),
        (EXACT_LINE, exact),
        (MISSING_LINE, missing),
        (CONTROL_LINE, control),
    ] {
        let read_back: ProcessAuditRecord = serde_json::from_str(line).unwrap();
        assert_eq!(read_back, record, "{line}");
    }

    // 列挙の綴り（読む側はこの文字列で分岐する）。
    assert_eq!(spell(ParentSeqSource::EtwField), r#""etw-field""#);
    assert_eq!(spell(ParentSeqSource::Unresolved), r#""unresolved""#);
    assert_eq!(spell(ArgvTruncation::None), r#""none""#);
    assert_eq!(spell(ArgvTruncation::Suspected), r#""suspected""#);
    assert_eq!(spell(ArgvTruncation::Certain), r#""certain""#);
    assert_eq!(
        spell(ArgvMissingReason::NoArgvObserved),
        r#""no_argv_observed""#
    );
    assert_eq!(
        spell(ArgvMissingReason::AmbiguousWithinWindow),
        r#""ambiguous_within_window""#
    );
    assert_eq!(
        spell(ArgvMissingReason::NoCommandLineField),
        r#""no_command_line_field""#
    );
}

fn spell<T: serde::Serialize>(value: T) -> String {
    serde_json::to_string(&value).unwrap()
}

/// **知らない新しい版を、知っている形として読まない。** 欄の意味が変わっていても形が合えば
/// 読めてしまうので、版の行で断る（`policy.json`の`FutureSchema`と同じ姿勢）。
///
/// 対の側（`B-35`）: 同じ版なら読めて、インスタンスと制御の行が取り出せる。これが無いと
/// 「常に断る」読み手でも緑になる。
#[test]
fn a_future_version_is_refused() {
    let future_header = format!(
        "{{\"kind\":\"header\",\"schema_version\":{}}}",
        PROCESS_AUDIT_SCHEMA_VERSION + 1
    );
    let future = format!("{future_header}\n{EXACT_LINE}\n");
    match parse_process_audit(&future) {
        Err(ProcessAuditError::FutureSchema { found, supported }) => {
            assert_eq!(found, PROCESS_AUDIT_SCHEMA_VERSION + 1);
            assert_eq!(supported, PROCESS_AUDIT_SCHEMA_VERSION);
        }
        other => panic!("新しい版を読んでしまった: {other:?}"),
    }

    // 途中に新しい版の行が現れても断る（版の行はどれも確かめる）。
    let later = format!("{HEADER_LINE}\n{EXACT_LINE}\n{future_header}\n{MISSING_LINE}\n");
    assert!(
        matches!(
            parse_process_audit(&later),
            Err(ProcessAuditError::FutureSchema { .. })
        ),
        "途中の新しい版の行を見落としている"
    );

    let current = format!("{HEADER_LINE}\n{EXACT_LINE}\n{CONTROL_LINE}\n{MISSING_LINE}\n");
    let log = parse_process_audit(&current).expect("今の版が読めない");
    assert_eq!(log.instances, vec![exact_instance(), missing_instance()]);
    assert_eq!(
        log.controls,
        vec!["argv_binding: exact=2 no_argv_observed=1".to_string()]
    );
    assert_eq!(log.skipped_lines, 0);
}

/// **版の行で始まらないファイルは読まない。** 版を名乗らない行の並びは、どの版の形か分からない。
///
/// 対の側: 中身の無いファイル（依頼側が先に作ったが、記録が始まらなかった）は空として読める。
/// これを断ると、始まらなかった記録がエラーに見える。
#[test]
fn a_file_without_a_header_is_refused() {
    let headless = format!("{EXACT_LINE}\n");
    assert!(
        matches!(
            parse_process_audit(&headless),
            Err(ProcessAuditError::MissingHeader { .. })
        ),
        "版の行が無いのに読んでしまった"
    );

    for empty in ["", "\n", "\r\n\r\n"] {
        let log = parse_process_audit(empty).expect("空のファイルが読めない");
        assert_eq!(log, ProcessAuditLog::default(), "{empty:?}");
    }
}

/// **書きかけの最後の行は「壊れた行」に数えない。** 収集プロセスが書いている最中に読むことがある
/// （`transitions_log::read_folded`と同じ扱い。最後の改行より後は読まない）。
///
/// 対の側: 改行で終わっている読めない行は、黙って捨てずに数える。
#[test]
fn a_half_written_last_line_is_not_counted_as_broken() {
    let half = format!("{HEADER_LINE}\n{EXACT_LINE}\n{{\"kind\":\"inst");
    let log = parse_process_audit(&half).expect("書きかけの行で読めなくなった");
    assert_eq!(log.instances.len(), 1);
    assert_eq!(log.skipped_lines, 0, "書きかけの行を壊れた行として数えている");

    let broken = format!("{HEADER_LINE}\nnot a json line\n{EXACT_LINE}\n");
    let log = parse_process_audit(&broken).expect("壊れた行が1つあるだけで読めなくなった");
    assert_eq!(log.instances.len(), 1);
    assert_eq!(log.skipped_lines, 1, "読めない行を黙って捨てている");

    // 改行がCRLFでも読める（書く側はLFだが、人が開いて保存し直すとCRLFになりうる）。
    let crlf = format!("{HEADER_LINE}\r\n{EXACT_LINE}\r\n");
    let log = parse_process_audit(&crlf).expect("CRLFの行が読めない");
    assert_eq!(log.instances, vec![exact_instance()]);
}

/// **欄が無い・0の親は「決めない」。** 0を番号として書くと、読む側はそれを本物の親の番号として
/// 引き、存在しない親（または番号0のSystem Idle Process）の下へ置く。
///
/// 対の側: 0でない欄はそのまま親の番号になり、出どころは`etw-field`。
#[test]
fn a_missing_or_zero_parent_field_is_unresolved() {
    assert_eq!(
        ParentSeqSource::from_etw_field(None),
        (None, ParentSeqSource::Unresolved)
    );
    assert_eq!(
        ParentSeqSource::from_etw_field(Some(0)),
        (None, ParentSeqSource::Unresolved)
    );
    assert_eq!(
        ParentSeqSource::from_etw_field(Some(665_736)),
        (Some(665_736), ParentSeqSource::EtwField)
    );
}
