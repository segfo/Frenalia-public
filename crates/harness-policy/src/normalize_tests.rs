//! [`crate::normalize`]の単体テスト。M15.7の完了条件「拒否4経路の正規化の純粋関数の単体テスト」
//! （`docs/INDEX.md`）にあたる。各経路につき「正常に拾えること」と「壊れた入力で止まらないこと」
//! （D-43 fail-open）を対にして固定する。

use super::*;

// --- 収集源1: preflight -----------------------------------------------------

/// 台帳の`denied_entries`が`(path, access, reason)`のまま候補になり、秒→ミリ秒へ揃う。
#[test]
fn preflight_denied_entries_become_candidates() {
    let ledger = r#"{
        "entries": [{"path": "C:\\granted", "writable": false, "granted_at_unix_secs": 1}],
        "denied_entries": [
            {"path": "C:\\Users\\me\\.cargo", "access": "read_exec",
             "reason": "path does not exist", "last_denied_at_unix_secs": 1700000000, "count": 3}
        ]
    }"#;

    let report = normalize_preflight(ledger);

    assert!(report.available);
    assert_eq!(report.candidates.len(), 1);
    let c = &report.candidates[0];
    assert_eq!(c.source, Source::Preflight);
    assert_eq!(
        c.requested,
        Requested::Fs {
            path: "C:/Users/me/.cargo".to_string(),
            access: FsAccess::ReadExec
        }
    );
    assert_eq!(c.count, 3);
    assert_eq!(c.last_seen_unix_ms, 1_700_000_000_000);
}

/// 未知のaccess綴りは黙って`Read`へ丸めず、候補から落として理由を残す
/// （丸めると要求より広い/狭い権限を提案してしまう。P-03）。
#[test]
fn preflight_unknown_access_label_is_skipped_with_a_note() {
    let ledger = r#"{"denied_entries": [
        {"path": "C:\\x", "access": "read_write_exec_everything", "reason": "r",
         "last_denied_at_unix_secs": 1, "count": 1}
    ]}"#;

    let report = normalize_preflight(ledger);

    assert!(report.available);
    assert!(report.candidates.is_empty());
    assert_eq!(report.notes.len(), 1);
    assert!(report.notes[0].contains("read_write_exec_everything"));
}

/// 台帳が壊れていても`Err`にせず`available: false`で返す（起動もCLIも止めない、D-43）。
#[test]
fn preflight_malformed_ledger_is_reported_as_unavailable_not_an_error() {
    let report = normalize_preflight("{ this is not json");

    assert!(!report.available);
    assert!(report.candidates.is_empty());
    assert!(report.notes[0].contains("could not be parsed"));
}

// --- 収集源2: network -------------------------------------------------------

/// 拒否行だけを拾い、`host`と`remote_host`の両方の綴りを吸収し、同一ホストは畳んで数える。
#[test]
fn net_audit_folds_denied_hosts_from_both_key_spellings() {
    let jsonl = concat!(
        r#"{"kind":"proxy","allowed":true,"host":"allowed.example","reason":"domain_allowed"}"#,
        "\n",
        r#"{"kind":"proxy","allowed":false,"host":"Blocked.Example.","reason":"domain_denied","timestamp_unix_ms":10}"#,
        "\n",
        r#"{"kind":"wfp","allowed":false,"remote_host":"blocked.example","reason":"classify_drop","timestamp_unix_ms":20}"#,
        "\n",
    );

    let report = normalize_net_audit(jsonl);

    assert!(report.available);
    assert_eq!(report.candidates.len(), 1);
    let c = &report.candidates[0];
    assert_eq!(
        c.requested,
        Requested::Net {
            domain: "blocked.example".to_string()
        }
    );
    assert_eq!(c.count, 2, "the two spellings fold into one candidate");
    assert_eq!(c.last_seen_unix_ms, 20);
}

/// ホスト名を持たない拒否（WFPのIP-only drop）は提案にしない。`net.allow_domains`は
/// IPリテラルを受け付けないため、提案しても適用できないから。理由はnotesへ残す。
#[test]
fn net_audit_ip_only_denials_are_counted_but_not_proposed() {
    let jsonl = concat!(
        r#"{"kind":"wfp","allowed":false,"remote_addr":"198.18.0.1","reason":"classify_drop"}"#,
        "\n",
        r#"{"kind":"wfp","allowed":false,"remote_addr":"198.18.0.2","remote_host":"","reason":"classify_drop"}"#,
        "\n",
    );

    let report = normalize_net_audit(jsonl);

    assert!(report.candidates.is_empty());
    assert_eq!(report.notes.len(), 1);
    assert!(report.notes[0].contains("2 denied network event"));
    assert!(report.notes[0].contains("IP-only"));
}

/// **制御レコードはネットワークイベントとして数えない。**
///
/// 昇格側（`netfilterd`）が自分の状態を残す行は`protocol:"control"`を持ち、`allowed:false`かつ
/// ホスト名が無い。素通しすると「ホスト名を持たない拒否」に混ざり、**嘘の注記**が出る
/// ——BUG-093のセッション`7476-1786226894-1`の実データがまさにこれで、通信は1件も無いのに
/// 「1件のネットワークイベントがホスト名を持たなかった」と出ていた。
#[test]
fn net_audit_control_records_are_not_counted_as_network_events() {
    // 実データそのまま（`.harness/sandbox/policy-editor-7476-1786226894-1/net-audit.jsonl`）。
    let jsonl = concat!(
        r#"{"timestamp_unix_ms":1786226932961,"kind":"wfp","protocol":"control","allowed":false,"#,
        r#""reason":"net_event_collection_enable_failed","local_addr":null,"local_port":0,"#,
        r#""remote_addr":null,"remote_host":null,"remote_port":0,"filter_id":null,"layer_id":null}"#,
        "\n",
    );

    let report = normalize_net_audit(jsonl);

    assert!(report.available);
    assert!(report.candidates.is_empty());
    assert!(
        report.notes.is_empty(),
        "a control record must not produce an IP-only note: {:?}",
        report.notes
    );
}

/// 上の対（B-35）: **本物の**ホスト名なし拒否は従来どおり数える。
/// 制御レコードの除外が「ホスト名なしの拒否を全部黙らせる」形になっていたら、この2つの
/// テストは同時には通らない。
#[test]
fn net_audit_control_records_are_skipped_but_real_ip_only_denials_still_count() {
    let jsonl = concat!(
        r#"{"kind":"wfp","protocol":"control","allowed":false,"reason":"net_event_collection_enable_failed"}"#,
        "\n",
        r#"{"kind":"wfp","protocol":"tcp","allowed":false,"remote_addr":"198.18.0.1","reason":"classify_drop"}"#,
        "\n",
    );

    let report = normalize_net_audit(jsonl);

    assert!(report.candidates.is_empty());
    assert_eq!(report.notes.len(), 1);
    assert!(
        report.notes[0].contains("1 denied network event"),
        "only the real IP-only drop must be counted: {}",
        report.notes[0]
    );
}

/// 記録モード（`NetIntake::All`）でも制御レコードは候補にならない
/// ——`All`は`allowed`を見ないので、除外が`allowed`側の分岐に紛れていたら漏れる。
#[test]
fn net_audit_control_records_are_skipped_in_record_all_intake_too() {
    let jsonl = concat!(
        r#"{"kind":"wfp","protocol":"control","allowed":false,"reason":"policy_learnd_chain_verify_rejected pipe=x env_present=false: nope"}"#,
        "\n",
        r#"{"kind":"proxy","protocol":"tcp","allowed":true,"host":"crates.io","reason":"record_all"}"#,
        "\n",
    );

    let report = normalize_net_audit_with_mode(jsonl, NetIntake::All);

    assert_eq!(report.candidates.len(), 1);
    assert_eq!(
        report.candidates[0].requested,
        Requested::Net {
            domain: "crates.io".to_string()
        }
    );
    assert!(report.notes.is_empty(), "{:?}", report.notes);
}

/// 判定そのもの: `protocol`が`control`のときだけ真。`kind`では判定しない
/// （`kind:"wfp"`は本物のdropレコードにも付く）。
#[test]
fn is_net_control_record_looks_at_protocol_only() {
    let control: serde_json::Value =
        serde_json::from_str(r#"{"kind":"wfp","protocol":"control","reason":"x"}"#).unwrap();
    let drop_event: serde_json::Value =
        serde_json::from_str(r#"{"kind":"wfp","protocol":"tcp","reason":"classify_drop"}"#)
            .unwrap();
    let proxy: serde_json::Value =
        serde_json::from_str(r#"{"kind":"proxy","host":"a.example"}"#).unwrap();

    assert!(is_net_control_record(&control));
    assert!(!is_net_control_record(&drop_event));
    assert!(!is_net_control_record(&proxy), "no protocol key at all");
}

/// 壊れた行があっても、その行だけ飛ばして残りを読む。
#[test]
fn net_audit_skips_malformed_lines_and_keeps_going() {
    let jsonl = concat!(
        "not json at all\n",
        r#"{"kind":"proxy","allowed":false,"host":"blocked.example","reason":"domain_denied"}"#,
        "\n",
    );

    let report = normalize_net_audit(jsonl);

    assert_eq!(report.candidates.len(), 1);
    assert!(report.notes[0].contains("line 1"));
}

// --- 収集源3: CoW -----------------------------------------------------------

/// 書込ビットが立っていれば`ReadWrite`、立っていなければ`Read`。同一パスは畳む。
#[test]
fn cow_denied_maps_access_mask_and_folds_repeats() {
    // 0x0002 = FILE_WRITE_DATA
    let jsonl = concat!(
        r#"{"path":"C:\\Users\\me\\.gitconfig","access_mask":2,"pid":100,"ts_unix_millis":5}"#,
        "\n",
        r#"{"path":"C:/Users/me/.gitconfig","access_mask":2,"pid":101,"ts_unix_millis":9}"#,
        "\n",
    );

    let report = normalize_cow_denied(jsonl);

    assert_eq!(report.candidates.len(), 1);
    let c = &report.candidates[0];
    assert_eq!(
        c.requested,
        Requested::Fs {
            path: "C:/Users/me/.gitconfig".to_string(),
            access: FsAccess::ReadWrite
        }
    );
    assert_eq!(c.count, 2);
    assert_eq!(c.last_seen_unix_ms, 9);
}

/// **BUG-048の再発防止**: `FILE_GENERIC_READ`（`0x0012_0089`。`SYNCHRONIZE`と`READ_CONTROL`を
/// 含む複合マスク）を書込と誤判定しないこと。個別ビットの明示列挙で判定しているかを固定する。
#[test]
fn cow_read_only_masks_are_not_mistaken_for_write_intent() {
    const FILE_GENERIC_READ: u32 = 0x0012_0089;
    const FILE_GENERIC_EXECUTE: u32 = 0x0012_00A0;

    assert_eq!(access_from_mask(FILE_GENERIC_READ), FsAccess::Read);
    assert_eq!(access_from_mask(FILE_GENERIC_EXECUTE), FsAccess::Read);
    assert_eq!(access_from_mask(0x0002), FsAccess::ReadWrite); // FILE_WRITE_DATA
    assert_eq!(access_from_mask(0x0001_0000), FsAccess::ReadWrite); // DELETE
    assert_eq!(access_from_mask(0x0004_0000), FsAccess::ReadWrite); // WRITE_DAC
}

// --- 収集源4: OS監査 --------------------------------------------------------

/// 拒否イベントが候補になり、許可イベントは無視され、同一（パス, access）は畳まれる。
#[test]
fn fs_audit_folds_denials_and_ignores_allowed_events() {
    let jsonl = concat!(
        r#"{"kind":"etw","path":"C:/Users/me/.rustup/x","access":"read_exec","allowed":false,"reason":"STATUS_ACCESS_DENIED","timestamp_unix_ms":1}"#,
        "\n",
        r#"{"kind":"etw","path":"C:/Users/me/.rustup/x","access":"read_exec","allowed":false,"reason":"STATUS_ACCESS_DENIED","timestamp_unix_ms":4}"#,
        "\n",
        r#"{"kind":"etw","path":"C:/Windows/win.ini","access":"read","allowed":true,"reason":"ok","timestamp_unix_ms":5}"#,
        "\n",
    );

    let report = normalize_fs_audit(jsonl);

    assert!(report.available);
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].count, 2);
    assert_eq!(report.candidates[0].last_seen_unix_ms, 4);
    assert_eq!(report.candidates[0].source, Source::Etw);
}

/// **D-43 fail-openの本体**: 収集器が起動に失敗して制御行だけを書いた場合、
/// 「拒否0件」ではなく`available: false`として返す。この2つを混同すると、
/// 収集器が動いていないのに「もう許可すべきものは無い」と読めてしまう。
#[test]
fn fs_audit_with_only_a_control_failure_is_unavailable_not_empty() {
    let jsonl = r#"{"kind":"control","allowed":false,"reason":"etw_session_start_failed: access denied","timestamp_unix_ms":1}"#;

    let report = normalize_fs_audit(jsonl);

    assert!(!report.available);
    assert!(report.candidates.is_empty());
    assert!(report
        .notes
        .iter()
        .any(|n| n.contains("etw_session_start_failed")));
    assert!(report.notes.iter().any(|n| n.contains("fall back")));
}

/// 制御行があっても実際の拒否を1件でも観測できていれば`available`。
#[test]
fn fs_audit_stays_available_when_denials_were_observed_despite_a_control_record() {
    let jsonl = concat!(
        r#"{"kind":"control","allowed":false,"reason":"provider dropped 3 events","timestamp_unix_ms":1}"#,
        "\n",
        r#"{"kind":"etw","path":"C:/x","access":"read","allowed":false,"reason":"denied","timestamp_unix_ms":2}"#,
        "\n",
    );

    let report = normalize_fs_audit(jsonl);

    assert!(report.available);
    assert_eq!(report.candidates.len(), 1);
}

/// 収集器がまだ1行も書いていない（＝ファイルが空）ときも`available: false`。
/// 「起動していない」と「観測ゼロ」を区別できないため、安全側（未収集）へ倒す。
#[test]
fn fs_audit_empty_file_is_unavailable() {
    let report = normalize_fs_audit("");

    assert!(!report.available);
    assert!(report.candidates.is_empty());
}

// --- 経路をまたぐ性質 -------------------------------------------------------

/// パス区切りは全経路で`/`へ揃う（同じパスが経路ごとに別候補へ割れないように）。
#[test]
fn path_separators_are_normalized_uniformly_across_sources() {
    let preflight = normalize_preflight(
        r#"{"denied_entries":[{"path":"C:\\a\\b","access":"read","reason":"r","last_denied_at_unix_secs":1,"count":1}]}"#,
    );
    let cow =
        normalize_cow_denied(r#"{"path":"C:\\a\\b","access_mask":2,"pid":1,"ts_unix_millis":1}"#);
    let audit = normalize_fs_audit(
        r#"{"kind":"etw","path":"C:\\a\\b","access":"read","allowed":false,"reason":"r","timestamp_unix_ms":1}"#,
    );

    for report in [&preflight, &cow, &audit] {
        let Requested::Fs { path, .. } = &report.candidates[0].requested else {
            panic!("expected an fs candidate");
        };
        assert_eq!(path, "C:/a/b");
    }
}

// --- FsFolder（record-all向けの畳み込み） -----------------------------------

/// **畳み込みの実装が2つある以上、同値であることをテストで固定する**（B-01）。
/// 同じ入力列に対し、既存の`fold_fs`（deny-onlyが使う線形走査）と`FsFolder`（record-allが
/// 使うHashMap）が**同じ候補列**を返すこと。片方だけ直る事故はここで落ちる。
#[test]
fn fs_folder_and_fold_fs_agree_on_the_same_input() {
    let input = [
        (r"C:\a\b.txt", FsAccess::Read, 10u64),
        ("C:/a/b.txt", FsAccess::Read, 20),  // 区切り違い＝同一
        (r"C:\A\B.TXT", FsAccess::Read, 15), // 大小違い＝同一
        (r"C:\a\b.txt", FsAccess::ReadWrite, 30), // accessが違えば別候補
        (r"C:\c.txt", FsAccess::Read, 5),
    ];

    let mut legacy: Vec<DeniedCandidate> = Vec::new();
    let mut folder = FsFolder::new();
    for (path, access, ts) in input {
        fold_fs(&mut legacy, Source::Etw, path, access, "observed", ts);
        folder.add(Source::Etw, path, access, "observed", ts);
    }

    assert_eq!(folder.into_candidates(), legacy);
    assert_eq!(legacy.len(), 3, "3つの異なる(パス, access)へ畳まれる");
    assert_eq!(legacy[0].count, 3);
    assert_eq!(
        legacy[0].last_seen_unix_ms, 20,
        "最新のタイムスタンプを保つ"
    );
}

/// record-allの主目的: **許可されたアクセスも候補になる**。`FsFolder`は`allowed`を見ない
/// （見るのは呼び出し側の責務）ので、成功アクセスもそのまま畳み込める。
#[test]
fn fs_folder_folds_observed_accesses_regardless_of_the_outcome() {
    let mut folder = FsFolder::new();
    folder.add(Source::Etw, "C:/ok.txt", FsAccess::Read, "observed", 1);
    folder.add(
        Source::Etw,
        "C:/ng.txt",
        FsAccess::Read,
        "STATUS_ACCESS_DENIED",
        2,
    );

    let candidates = folder.into_candidates();
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].reason, "observed");
    assert_eq!(candidates[1].reason, "STATUS_ACCESS_DENIED");
}

/// 空のまま取り出しても壊れない（記録が1件も観測できなかった場合）。
#[test]
fn fs_folder_starts_empty() {
    let folder = FsFolder::new();
    assert!(folder.is_empty());
    assert_eq!(folder.len(), 0);
    assert!(folder.into_candidates().is_empty());
}
