//! `net_aggregate`のテスト（`docs/CODE-STRUCTURE-RULES.md`の`#[path]`分離）。
//!
//! 一番大事なのは**「record-allで走らせた記録から候補が出ること」**である。deny-onlyの
//! 取り込み口を通すとここが0件になり、しかも「通信が無かった」と見分けが付かない。

use super::*;

fn proxy_event(host: &str, allowed: bool, reason: &str) -> serde_json::Value {
    serde_json::json!({
        "timestamp_unix_ms": 1_700_000_000_000u64,
        "kind": "proxy",
        "protocol": "tls_sni",
        "host": host,
        "port": 443,
        "allowed": allowed,
        "reason": reason,
    })
}

/// **record-allで走らせた記録（全部`allowed: true`）から候補が出る。**
/// deny-onlyの取り込み口だとここが0件になる（`normalize.rs`が拒否行以外を捨てるため）。
#[test]
fn allowed_events_from_a_record_all_run_still_produce_candidates() {
    let mut aggregate = NetAggregate::new();
    aggregate.add_event(&proxy_event("crates.io", true, "record_all"));
    aggregate.add_event(&proxy_event("static.crates.io", true, "record_all"));

    let proposals = aggregate.proposals(Generalization::None);

    let values: Vec<&str> = proposals.iter().map(|p| p.value.as_str()).collect();
    assert!(
        values.contains(&"crates.io") && values.contains(&"static.crates.io"),
        "record-allの記録から候補が出ないと、パス2の成果が丸ごと消える: {values:?}"
    );
    assert!(proposals
        .iter()
        .all(|p| p.key == harness_policy::generalize::SettingsKey::NetAllowDomains));
}

/// 対のテスト（B-35）: 通常の（deny-onlyの）取り込み口では同じ入力から候補が出ない
/// ——上のテストが「取り込み口に関係なく出ている」だけで通っていないことを示す。
#[test]
fn the_normal_denied_only_intake_would_have_produced_nothing_from_the_same_input() {
    let jsonl = format!(
        "{}\n{}",
        serde_json::to_string(&proxy_event("crates.io", true, "record_all")).unwrap(),
        serde_json::to_string(&proxy_event("static.crates.io", true, "record_all")).unwrap()
    );

    let denied_only = harness_policy::normalize::normalize_net_audit(&jsonl);

    assert!(
        denied_only.candidates.is_empty(),
        "deny-onlyの取り込み口はrecord-allの記録から何も拾えない（だから専用の口が要る）"
    );
}

/// 同じホストへの複数回の接続は1件へ畳まれ、回数が積まれる。
#[test]
fn repeated_hosts_are_folded_with_their_observation_count() {
    let mut aggregate = NetAggregate::new();
    for _ in 0..3 {
        aggregate.add_event(&proxy_event("crates.io", true, "record_all"));
    }

    assert_eq!(aggregate.host_count(), 1);
    assert_eq!(aggregate.hosts(), vec![("crates.io", 3)]);
    let proposals = aggregate.proposals(Generalization::None);
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].observed_count(), 3);
}

/// **ホスト名を持たないイベントは黙って消さず数える。** これは既知の盲点
/// （IP直打ち・OSリゾルバを経由しない自前DNS）の指標そのものである（B-09）。
#[test]
fn events_without_a_hostname_are_counted_rather_than_dropped_silently() {
    let mut aggregate = NetAggregate::new();
    aggregate.add_event(&serde_json::json!({
        "kind": "wfp",
        "remote_addr": "8.8.8.8:443",
        "allowed": false,
        "reason": "wfp_drop",
    }));

    assert_eq!(aggregate.without_host, 1);
    assert_eq!(aggregate.host_count(), 0);
    assert!(
        aggregate.notes().iter().any(|n| n.contains("IP-only")),
        "件数の説明が候補一覧に出ないと「通信が無かった」と区別できない: {:?}",
        aggregate.notes()
    );
}

/// 拒否も数える。record-allでも**IPリテラル宛は拒否される**（`evaluate_host`の仕様）。
#[test]
fn denied_events_are_counted_separately_from_allowed_ones() {
    let mut aggregate = NetAggregate::new();
    aggregate.add_event(&proxy_event("crates.io", true, "record_all"));
    aggregate.add_event(&proxy_event("93.184.216.34", false, "ip_literal_denied"));

    assert_eq!(aggregate.allowed, 1);
    assert_eq!(aggregate.denied, 1);
}

/// 記録済みのJSONLを読み直しても同じ結果になる（`show --net`の経路）。
#[test]
fn reading_the_log_back_produces_the_same_candidates() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("net-audit.jsonl");
    let text = format!(
        "{}\n{}\n",
        serde_json::to_string(&proxy_event("crates.io", true, "record_all")).unwrap(),
        serde_json::to_string(&proxy_event("index.crates.io", true, "record_all")).unwrap()
    );
    std::fs::write(&path, text).unwrap();

    let aggregate = from_log(&path);

    assert_eq!(aggregate.events_seen, 2);
    assert_eq!(aggregate.host_count(), 2);
    assert_eq!(aggregate.proposals(Generalization::None).len(), 2);
}

/// 何も観測できなかったときは、**候補が空である以上のことを言う**（B-09）。
#[test]
fn an_empty_recording_says_so_instead_of_just_showing_no_candidates() {
    let aggregate = NetAggregate::new();

    let text = render(&aggregate, Generalization::None, 40);

    assert!(text.contains("1件も観測できませんでした"), "{text}");
    assert!(
        text.contains("繋がらない"),
        "WFPで落ちている可能性へ誘導しないと、原因に辿り着けない: {text}"
    );
}
