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

    let proposals = aggregate.proposals();

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
    let proposals = aggregate.proposals();
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

    let aggregate = from_log(&path, NetMode::RecordAll);

    assert_eq!(aggregate.events_seen, 2);
    assert_eq!(aggregate.host_count(), 2);
    assert_eq!(aggregate.proposals().len(), 2);
}

/// 何も観測できなかったときは、**候補が空である以上のことを言う**（B-09）。
#[test]
fn an_empty_recording_says_so_instead_of_just_showing_no_candidates() {
    let aggregate = NetAggregate::new();

    let text = render(&aggregate, 40);

    assert!(text.contains("1件も観測できませんでした"), "{text}");
    assert!(
        text.contains("繋がらない"),
        "WFPで落ちている可能性へ誘導しないと、原因に辿り着けない: {text}"
    );
}

/// **昇格側の制御レコードはネットワークイベントとして数えない**（BUG-093）。
///
/// 制御レコードは`allowed:false`かつホスト名を持たないので、素通しすると
/// 「拒否1件・ホスト名なし1件」として集計され、注記にも嘘が出る。
/// ただし**黙って捨てもしない**——理由は`control_reasons()`から取れる。
#[test]
fn control_records_from_the_elevated_side_are_kept_but_not_counted_as_traffic() {
    let control = serde_json::json!({
        "timestamp_unix_ms": 1_786_226_932_961u64,
        "kind": "wfp",
        "protocol": "control",
        "allowed": false,
        "reason": "policy_learnd_chain_verify_rejected pipe=x env_present=false: nope",
    });

    let mut aggregate = NetAggregate::new();
    aggregate.add_event(&control);

    assert_eq!(aggregate.events_seen, 0, "通信の記録ではない");
    assert_eq!(aggregate.denied, 0);
    assert_eq!(
        aggregate.without_host, 0,
        "ホスト名なしの拒否として数えない"
    );
    assert!(aggregate.candidates().is_empty());
    assert!(aggregate.notes().is_empty(), "{:?}", aggregate.notes());
    assert_eq!(
        aggregate.control_reasons(),
        ["policy_learnd_chain_verify_rejected pipe=x env_present=false: nope"],
        "理由は捨てない（昇格側の失敗を伝える唯一の経路）"
    );
}

/// 対のテスト（B-35）: 制御レコードの除外が**本物の通信まで**落としていないこと。
/// 同じ`kind:"wfp"`でも`protocol`が`control`でなければ従来どおり数える。
#[test]
fn a_real_wfp_drop_is_still_counted_alongside_a_control_record() {
    let control = serde_json::json!({
        "kind": "wfp", "protocol": "control", "allowed": false,
        "reason": "net_event_collection_enable_failed: FwpmEngineSetOption0 returned 0x00000005",
    });
    let real_drop = serde_json::json!({
        "kind": "wfp", "protocol": "tcp", "allowed": false,
        "remote_addr": "198.18.0.1", "remote_port": 443, "reason": "classify_drop",
    });

    let mut aggregate = NetAggregate::new();
    aggregate.add_event(&control);
    aggregate.add_event(&real_drop);

    assert_eq!(aggregate.events_seen, 1);
    assert_eq!(aggregate.denied, 1);
    assert_eq!(
        aggregate.without_host, 1,
        "本物のIP-only dropは盲点として数える"
    );
    assert_eq!(aggregate.control_reasons().len(), 1);
}

/// 記録済みのJSONLを読み直す経路（`show`／編集画面）でも制御レコードの理由が取れる
/// ——ライブ表示を見逃した後でも、`show`で「なぜ収集器が居ないのか」に辿り着ける。
#[test]
fn control_reasons_survive_reading_the_log_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("net-audit.jsonl");
    std::fs::write(
        &path,
        concat!(
            r#"{"kind":"wfp","protocol":"control","allowed":false,"reason":"policy_learnd_chain_child_exited code=0x00000065"}"#,
            "\n",
        ),
    )
    .unwrap();

    let aggregate = from_log(&path, NetMode::RecordAll);

    assert_eq!(aggregate.events_seen, 0);
    assert_eq!(
        aggregate.control_reasons(),
        ["policy_learnd_chain_child_exited code=0x00000065"]
    );
}

/// `show`で記録を開き直したときにも昇格側の報告が出る（FS側の`collector_notes`と対称）。
/// ライブの警告は流れて消えるので、**後から見返す経路にも同じ事実が要る**。
#[test]
fn the_rendered_notes_surface_what_the_elevated_side_reported() {
    let mut aggregate = NetAggregate::new();
    aggregate.add_event(&serde_json::json!({
        "kind": "wfp", "protocol": "control", "allowed": false,
        "reason": "policy_learnd_chain_verify_rejected pipe=p env_present=false: writable",
    }));

    let text = render_notes(&aggregate);

    assert!(text.contains("昇格側からの報告"), "{text}");
    assert!(
        text.contains("policy_learnd_chain_verify_rejected"),
        "{text}"
    );
    assert!(
        !text.contains("ホスト名を持たないイベント"),
        "制御レコードを通信の盲点として数えてはいけない: {text}"
    );
}

/// [決定64] **強制で走らせた記録は、断られた宛先だけを候補にする。** 許された宛先は宣言済みで、
/// 候補に並べると「何が足りなかったのか」が埋もれる。同じ入力を記録モードで読むと両方が出る
/// ——取り込み口が実際にモードで切り替わっていることの対（B-35）。
#[test]
fn a_declared_run_proposes_only_the_refused_hosts() {
    let events = [
        proxy_event("crates.io", true, "domain_allowed"),
        proxy_event("example.com", false, "domain_denied"),
    ];
    let mut declared = NetAggregate::for_mode(NetMode::Declared);
    let mut record_all = NetAggregate::for_mode(NetMode::RecordAll);
    for event in &events {
        declared.add_event(event);
        record_all.add_event(event);
    }

    let declared_values: Vec<String> =
        declared.proposals().into_iter().map(|p| p.value).collect();
    let mut record_all_values: Vec<String> =
        record_all.proposals().into_iter().map(|p| p.value).collect();
    record_all_values.sort();

    assert_eq!(declared_values, vec!["example.com".to_string()]);
    assert_eq!(
        record_all_values,
        vec!["crates.io".to_string(), "example.com".to_string()]
    );
    // 件数は取り込み口と無関係に、観測したとおりに数える。
    assert_eq!((declared.allowed, declared.denied), (1, 1));
}

/// 記録を開き直す経路（`show`・編集画面）でも、マニフェストのモードで取り込み口が決まる。
#[test]
fn reading_the_log_back_uses_the_mode_it_was_run_with() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("net-audit.jsonl");
    let text = format!(
        "{}\n{}\n",
        serde_json::to_string(&proxy_event("crates.io", true, "domain_allowed")).unwrap(),
        serde_json::to_string(&proxy_event("example.com", false, "domain_denied")).unwrap()
    );
    std::fs::write(&path, text).unwrap();

    assert_eq!(from_log(&path, NetMode::Declared).proposals().len(), 1);
    assert_eq!(from_log(&path, NetMode::RecordAll).proposals().len(), 2);
}

/// 注記はどちらのモードで走らせたかを先頭に出し、候補の見出しもモードで変える
/// （強制の候補を「観測された値そのまま」と書くと、許された宛先まで入っていると読まれる）。
#[test]
fn the_rendered_text_names_the_mode() {
    let declared = NetAggregate::for_mode(NetMode::Declared);
    let record_all = NetAggregate::new();

    let declared_text = render(&declared, 10);
    let record_all_text = render(&record_all, 10);

    assert!(
        declared_text.contains(NetMode::Declared.label()),
        "{declared_text}"
    );
    assert!(declared_text.contains("宣言の外で断られた宛先"), "{declared_text}");
    assert!(
        record_all_text.contains(NetMode::RecordAll.label()),
        "{record_all_text}"
    );
    assert!(
        record_all_text.contains("観測された値そのまま"),
        "{record_all_text}"
    );
}

// --- [決定69 の前例の(7)] ドメインの印で候補を振り分ける ---

fn proxy_event_of(domain: &str, host: &str) -> serde_json::Value {
    let mut event = proxy_event(host, true, "record_all");
    event["domain"] = serde_json::Value::String(domain.to_string());
    event
}

/// **ドメインの印を持つ行は、そのドメインの候補になる**（印の無い行は入口）。
///
/// 1つの`net-audit.jsonl`へ入口とドメインのプロキシが追記するので、ファイル単位では分けられない
/// ——行の印だけが「どのドメインが触った宛先か」を知っている。
#[test]
fn a_line_with_a_domain_tag_becomes_that_domains_candidate() {
    let mut aggregate = NetAggregate::new();
    aggregate.add_event(&proxy_event("entry.example.com", true, "record_all"));
    aggregate.add_event(&proxy_event_of("ssh", "github.com"));

    let by_domain = aggregate.proposals_by_domain();
    let pairs: Vec<(&str, &str)> = by_domain
        .iter()
        .map(|(domain, proposal)| (domain.as_str(), proposal.value.as_str()))
        .collect();
    assert_eq!(
        pairs,
        vec![
            (crate::policy_file::ENTRY_DOMAIN, "entry.example.com"),
            ("ssh", "github.com"),
        ],
        "印で振り分けていない（または入口が先に来ていない）"
    );
    assert!(aggregate.has_domain_tags());
}

/// **禁止側の対**: 印の無い記録（古いパス2）は全部入口の候補で、ドメインの段を出さない。
#[test]
fn a_recording_without_tags_keeps_every_candidate_on_the_entry_domain() {
    let mut aggregate = NetAggregate::new();
    aggregate.add_event(&proxy_event("crates.io", true, "record_all"));

    assert!(!aggregate.has_domain_tags());
    let by_domain = aggregate.proposals_by_domain();
    assert_eq!(by_domain.len(), 1);
    assert_eq!(by_domain[0].0, crate::policy_file::ENTRY_DOMAIN);
}

/// 全体の候補（`proposals`）は**ドメインをまたいで**作る（注記と件数の見出しがこれまでと同じ計算のまま）。
#[test]
fn the_whole_recording_still_produces_one_combined_candidate_list() {
    let mut aggregate = NetAggregate::new();
    aggregate.add_event(&proxy_event("entry.example.com", true, "record_all"));
    aggregate.add_event(&proxy_event_of("ssh", "github.com"));

    let proposals = aggregate.proposals();
    let values: Vec<&str> = proposals.iter().map(|p| p.value.as_str()).collect();
    assert!(values.contains(&"entry.example.com") && values.contains(&"github.com"), "{values:?}");
    assert_eq!(aggregate.events_seen, 2);
}
