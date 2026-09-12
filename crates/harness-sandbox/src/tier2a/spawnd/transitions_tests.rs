//! [段階6c] 拒否の待ち行列の単体テスト。
//!
//! **Win32を呼ばないので昇格は要らない**（`cargo test -p harness-sandbox --lib`に入る）。
//! 実機でしか測れないもの——「宣言していない遷移を撃つと1行増える」「宣言した遷移では
//! 増えない」——は`win_appcontainer::spawnd_e2e_tests`が持つ。

use super::*;

use harness_policy::transition::TransitionDenial;

fn transition(denial: TransitionDenial) -> DenyReason {
    DenyReason::Transition { denial }
}

/// Daemon経由の拒否で**実際に観測できるもの**（ドメインもcwdも取れる）。
fn observed<'a>(exe: &'a str, argv: &'a str, reason: &'a DenyReason) -> Observation<'a> {
    Observation {
        from_domain: Some("workspace"),
        exe,
        argv,
        cwd: Some("C:/work"),
        reason,
    }
}

fn read_records(path: &Path) -> Vec<PendingRecord> {
    let text = std::fs::read_to_string(path).expect("pending.jsonl should exist");
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<PendingRecord>(l).expect("each line is one record"))
        .collect()
}

// --- 分類表（決定1） -------------------------------------------------------

/// **宣言で直るものと直らないものが、別の値になること。**
///
/// 片側だけを確かめると「常に`FixTheDeclaration`を返す」実装でも通る（`B-35`）。
#[test]
fn the_remedy_table_separates_declaration_problems_from_harness_limits() {
    // 宣言を足す／直せば通るもの（判定器が断った4つ）。
    for denial in [
        TransitionDenial::UnknownSourceDomain,
        TransitionDenial::NoMatchingEdge,
        TransitionDenial::AmbiguousPattern { matched: 2 },
        TransitionDenial::CwdMismatch {
            declared: "C:/a".to_string(),
            actual: "C:/b".to_string(),
        },
    ] {
        assert_eq!(
            remedy(&transition(denial.clone())),
            Remedy::FixTheDeclaration,
            "判定器の拒否は宣言で直る: {denial:?}"
        );
    }

    // [暫定] 宣言は足りているが、harness側がドメインの権限一式を発行できない。
    assert_eq!(
        remedy(&DenyReason::TargetDomainNotProvisioned {
            to: "build".to_string()
        }),
        Remedy::BlockedUntilHarnessImplementsIt,
        "別ドメインへの遷移は宣言では直らない。`FixTheDeclaration`にすると、\
         policy.jsonと突き合わせた読む側が「解決済み」と判定して画面から消す"
    );

    // 宣言とも実装とも関係ないもの。
    for reason in [
        DenyReason::NotRegistered,
        DenyReason::PidReused,
        DenyReason::MalformedRequest,
    ] {
        assert_eq!(
            remedy(&reason),
            Remedy::NotAboutPolicy,
            "宣言候補として画面に出してはいけない: {reason:?}"
        );
    }
}

// --- 行の形（決定2の欄も含む） ---------------------------------------------

/// Daemon側の行が往復すること、および**`kind`が最上位に1つだけ**であること。
///
/// 後半は2026-09-12に実際に踏んだ事故の再発防止である——外側の列挙も内側の列挙も
/// `kind`をタグ名に使っていたため、`{"kind":"...","kind":"..."}`という
/// **書き出せるが読み戻すと片方が消える**JSONになっていた。
#[test]
fn a_daemon_denial_line_round_trips_and_has_exactly_one_top_level_kind() {
    let record = PendingRecord::DeniedByDaemon(Denial {
        from_domain: Some("workspace".to_string()),
        exe: r"C:\Windows\System32\cmd.exe".to_string(),
        argv: r#""C:\Windows\System32\cmd.exe" /c exit 0"#.to_string(),
        cwd: Some(r"C:\work".to_string()),
        reason: transition(TransitionDenial::NoMatchingEdge),
        count: 1,
        first_ts: 1_700_000_000_000,
        last_ts: 1_700_000_000_000,
        argv_truncation: false,
    });

    let json = serde_json::to_string(&record).expect("serialize");
    let back: PendingRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, record, "往復で値が変わってはいけない");

    let value: serde_json::Value = serde_json::from_str(&json).expect("as value");
    let object = value.as_object().expect("record is an object");
    assert_eq!(
        object.get("kind").and_then(|k| k.as_str()),
        Some("denied_by_daemon"),
        "最上位の`kind`は「誰が拒否したか」だけを答える"
    );
    // 理由の`kind`は`reason`の**中**に入れ子になっていること（同じ階層に2つ置かない）。
    assert_eq!(
        object
            .get("reason")
            .and_then(|r| r.get("kind"))
            .and_then(|k| k.as_str()),
        Some("transition"),
        "拒否の理由は構造のまま`reason`の中に入る。文字列へ潰さない"
    );
}

/// **カーネル拒否では観測していない欄が`null`のまま往復すること。**
///
/// 空文字や既定値で埋めると「観測していない」と「観測したが空だった」が区別できなくなる
/// （`P-11`）。欄ごと省くのも駄目で、古い版が書いた行と見分けが付かなくなる。
#[test]
fn a_kernel_denial_line_keeps_unobserved_fields_null() {
    let record = PendingRecord::DeniedByKernel(Denial {
        from_domain: None,
        exe: r"C:\Windows\System32\cmd.exe".to_string(),
        argv: r#""C:\Windows\System32\cmd.exe" /c exit 0"#.to_string(),
        cwd: None,
        reason: DenyReason::MalformedRequest,
        count: 2,
        first_ts: 1,
        last_ts: 2,
        argv_truncation: true,
    });

    let json = serde_json::to_string(&record).expect("serialize");
    let value: serde_json::Value = serde_json::from_str(&json).expect("as value");
    let object = value.as_object().expect("record is an object");
    for field in ["from_domain", "cwd"] {
        assert_eq!(
            object.get(field),
            Some(&serde_json::Value::Null),
            "{field}は欄を出したうえで`null`（＝観測していない）にする"
        );
    }

    let back: PendingRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, record, "読み戻しても既定値で埋まらない");
}

#[test]
fn argv_truncation_is_only_suspected_at_exactly_the_threshold() {
    let at = "a".repeat(1_024);
    let below = "a".repeat(1_023);
    let above = "a".repeat(1_025);
    assert!(argv_is_possibly_truncated(&at));
    assert!(!argv_is_possibly_truncated(&below));
    assert!(
        !argv_is_possibly_truncated(&above),
        "閾値を超えているなら切られていない（切られていればちょうどになる）"
    );
}

// --- 畳み込み ---------------------------------------------------------------

/// **同じ拒否は種類として1つに畳まれ、1件目はその場で書かれる。**
#[test]
fn the_first_denial_of_a_kind_is_written_immediately() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue = TransitionQueue::new(dir.path());

    let outcome = queue
        .record_daemon_denial(
            observed(
                "cmd.exe",
                "cmd.exe /c exit 0",
                &transition(TransitionDenial::NoMatchingEdge),
            ),
            10,
        )
        .expect("record");
    assert_eq!(outcome, Recorded::AppendedFirst);

    let records = read_records(queue.path());
    assert_eq!(records.len(), 1, "1件目は畳まずにすぐ書く");
    match &records[0] {
        PendingRecord::DeniedByDaemon(denial) => {
            assert_eq!(denial.count, 1);
            assert_eq!(denial.first_ts, 10);
            assert_eq!(denial.last_ts, 10);
        }
        other => panic!("expected a daemon denial, got {other:?}"),
    }
}

/// **2件目以降は数えるだけで、前回書いた数の2倍に達したときだけ更新行が出る。**
///
/// この対がないと、「毎回1行追記する」実装でも「一度も更新しない」実装でも緑になる。
#[test]
fn repeats_are_folded_and_written_when_the_count_doubles() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue = TransitionQueue::new(dir.path());
    let reason = transition(TransitionDenial::NoMatchingEdge);

    let mut outcomes = Vec::new();
    for i in 1..=5u64 {
        outcomes.push(
            queue
                .record_daemon_denial(observed("cmd.exe", "cmd.exe /c exit 0", &reason), i)
                .expect("record"),
        );
    }

    assert_eq!(
        outcomes,
        vec![
            Recorded::AppendedFirst,                  // 1回目: 即時
            Recorded::AppendedUpdate { count: 2 },    // 2回目: 1の2倍
            Recorded::FoldedOnly { count: 3 },        // 3回目: まだ4に届かない
            Recorded::AppendedUpdate { count: 4 },    // 4回目: 2の2倍
            Recorded::FoldedOnly { count: 5 },
        ],
        "書くのは1・2・4回目だけ（回数の対数）"
    );

    let records = read_records(queue.path());
    assert_eq!(records.len(), 3, "5件の拒否で書かれた行は3行");

    // 読む側は同じ鍵の**最後の行**を採る。
    match records.last().expect("last") {
        PendingRecord::DeniedByDaemon(denial) => assert_eq!(denial.count, 4),
        other => panic!("expected a daemon denial, got {other:?}"),
    }

    // 畳まれずに残った分は、畳みどきに書き出される。
    let written = queue.flush(99).expect("flush");
    assert_eq!(written, 1);
    let records = read_records(queue.path());
    match records.last().expect("last") {
        PendingRecord::DeniedByDaemon(denial) => {
            assert_eq!(denial.count, 5, "flushで最後の回数まで書き切る");
            assert_eq!(denial.last_ts, 5, "最後に観測した時刻であって、flushの時刻ではない");
        }
        other => panic!("expected a daemon denial, got {other:?}"),
    }

    // 二度目のflushは書くものが無い。
    assert_eq!(queue.flush(100).expect("flush again"), 0);
}

/// **理由が違えば別の種類になる。** 同じコマンドでも直し方が違うものを1行に混ぜない。
#[test]
fn denials_with_different_reasons_are_different_kinds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue = TransitionQueue::new(dir.path());

    for reason in [
        transition(TransitionDenial::NoMatchingEdge),
        DenyReason::TargetDomainNotProvisioned {
            to: "build".to_string(),
        },
    ] {
        assert_eq!(
            queue
                .record_daemon_denial(observed("cmd.exe", "cmd.exe /c exit 0", &reason), 1)
                .expect("record"),
            Recorded::AppendedFirst
        );
    }

    let records = read_records(queue.path());
    assert_eq!(records.len(), 2);
    let remedies: Vec<Remedy> = records
        .iter()
        .map(|r| match r {
            PendingRecord::DeniedByDaemon(d) => remedy(&d.reason),
            other => panic!("expected a daemon denial, got {other:?}"),
        })
        .collect();
    assert_eq!(
        remedies,
        vec![Remedy::FixTheDeclaration, Remedy::BlockedUntilHarnessImplementsIt],
        "同じコマンドでも、直し方が違う2件として読める"
    );
}

/// **種類の上限を超えた拒否は、黙って消えずに件数として残る。**
#[test]
fn denials_beyond_the_cap_are_counted_not_dropped_silently() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue = TransitionQueue::new(dir.path());
    let reason = transition(TransitionDenial::NoMatchingEdge);

    for i in 0..MAX_DISTINCT_KEYS {
        let exe = format!("cmd{i}.exe");
        assert_eq!(
            queue
                .record_daemon_denial(observed(&exe, "x", &reason), 1)
                .expect("record"),
            Recorded::AppendedFirst
        );
    }
    // 上限を超えた2件。
    for _ in 0..2 {
        assert_eq!(
            queue
                .record_daemon_denial(observed("overflow.exe", "x", &reason), 2)
                .expect("record"),
            Recorded::DroppedByCap
        );
    }

    assert_eq!(queue.flush(50).expect("flush"), 1, "あふれの報告が1行出る");
    let records = read_records(queue.path());
    match records.last().expect("last") {
        PendingRecord::Overflowed { dropped, last_ts } => {
            assert_eq!(*dropped, 2);
            assert_eq!(*last_ts, 50);
        }
        other => panic!("expected an overflow record, got {other:?}"),
    }
    // 報告済みのあふれを二重に報告しない。
    assert_eq!(queue.flush(51).expect("flush again"), 0);
}

/// **書けなかった拒否は、次の機会に書き直せる状態へ戻る。**
///
/// 戻さないと、1回の書込失敗でその種類が永久に待ち行列へ現れなくなる——覚えている側は
/// 「書いた」と思っているので二度と書こうとしない（`B-15`）。
#[test]
fn a_failed_append_is_rolled_back_so_the_next_denial_retries() {
    let dir = tempfile::tempdir().expect("tempdir");
    // `.harness`を**ファイル**にしておくと、置き場のディレクトリが作れない。
    std::fs::write(dir.path().join(".harness"), b"not a directory").expect("write blocker");

    let queue = TransitionQueue::new(dir.path());
    let reason = transition(TransitionDenial::NoMatchingEdge);
    let record = |ts| queue.record_daemon_denial(observed("cmd.exe", "x", &reason), ts);

    assert!(record(1).is_err(), "置き場が作れないので書けない");
    assert!(
        record(2).is_err(),
        "2件目も「1件目」としてやり直す。覚えたままだと黙って数えるだけになる"
    );

    // 邪魔をどけると、次の1件が普通に書ける。
    std::fs::remove_file(dir.path().join(".harness")).expect("remove blocker");
    assert_eq!(record(3).expect("record"), Recorded::AppendedFirst);
    let records = read_records(queue.path());
    assert_eq!(records.len(), 1);
    match &records[0] {
        PendingRecord::DeniedByDaemon(denial) => assert_eq!(denial.count, 1),
        other => panic!("expected a daemon denial, got {other:?}"),
    }
}

// --- 置き場 -----------------------------------------------------------------

/// **置き場は`.harness`配下から動かさない。**
///
/// 自己参照ループ（記録の産物が次の記録の候補になること）を断っているのは
/// `harness_policy_editor::exclusion::is_harness_control_path`で、同関数が見るのは
/// パス要素`.harness`だけである。**その照合は`harness-policy-editor`側のテストが持つ**
/// （依存の向きが逆なのでここからは呼べない）。ここでは形だけを固定する。
#[test]
fn the_queue_lives_under_the_harness_control_directory() {
    let path = pending_path(Path::new("C:/work"));
    let components: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    assert!(
        components.iter().any(|c| c == ".harness"),
        "パス要素として`.harness`を含むこと（これが自己参照ループの遮断の成立条件）: {path:?}"
    );
    assert!(path.ends_with("transitions/pending.jsonl") || path.ends_with(r"transitions\pending.jsonl"));
}
