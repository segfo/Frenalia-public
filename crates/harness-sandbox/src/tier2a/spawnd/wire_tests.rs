//! ワイヤ形式の characterization test。**バイト列そのものを固定する。**
//!
//! # なぜ形を固定するのか
//!
//! この電文は**プロセス境界を越える**（harness ⇄ Daemon ⇄ サンドボックスの子）。
//! 片側だけを更新して配れる形なので、型の変更が**実行時にだけ**壊れる。
//! 同じ理由で`privhelper`は`pipe_ipc_characterization`を持っており、ここもそれに倣う
//! （`docs/CODE-STRUCTURE-RULES.md`規則6）。
//!
//! **このテストが赤くなったら、それは「壊れた」ではなく「形を変えた」の合図である。**
//! 変えてよいかは、Daemonの実行ファイルとharnessが常に同じビルドから来るか
//! （＝隣に置いた`harness-spawnd.exe`を使う）で決まる。同じビルドなら期待値を更新してよい。
//!
//! # 誤検知してはならない側（問4）
//!
//! **[`SpawnRequest`]にドメインの欄が生えていないこと**を、形の側から見張る。
//! 生えた瞬間、§12が禁じた「クライアントにドメインを申告させる」形になる。

use super::*;

#[test]
fn control_request_hello_keeps_its_wire_shape() {
    let json = serde_json::to_string(&ControlRequest::Hello {
        harness_process: 4660,
        protocol_version: PROTOCOL_VERSION,
        policy: Box::new(harness_policy::policy_file::PolicyFile::default()),
        workspace_root: "C:/w".to_string(),
    })
    .expect("serialize");
    assert_eq!(
        json,
        r#"{"kind":"hello","harness_process":4660,"protocol_version":4,"policy":{"schema_version":2,"domains":[]},"workspace_root":"C:/w"}"#
    );
}

#[test]
fn control_request_spawn_top_level_keeps_its_wire_shape() {
    let request = ControlRequest::SpawnTopLevel(Box::new(SpawnTopLevelRequest {
        exe: "C:/w/pwsh.exe".to_string(),
        args: vec!["-NoProfile".to_string()],
        cwd: "C:/w".to_string(),
        env: vec![("K".to_string(), "V".to_string())],
        domain: DomainSpec {
            name: "pwsh-workspace".to_string(),
            policy_domain: "workspace-shell".to_string(),
            container_sid: "S-1-15-2-1".to_string(),
            capability_sids: vec!["S-1-15-3-1024-1".to_string()],
            identity: DomainIdentitySpec::Capability {
                sid: "S-1-15-3-1024-9".to_string(),
            },
        },
        handles: ChildHandles {
            job: 16,
            stdin_read: Some(20),
            stdout_write: 24,
            stderr_write: 28,
        },
        redirector: Some(RedirectorSpec::Lazy {
            workspace_root: "C:/w".to_string(),
            broker_pipe: r"\\.\pipe\lazy".to_string(),
        }),
        // [段階⑤] この電文の`exe`はpwshなので、コンソールが要る側である。
        console: ConsoleNeed::Required,
    }));
    let json = serde_json::to_string(&request).expect("serialize");
    assert_eq!(
        json,
        r#"{"kind":"spawn_top_level","exe":"C:/w/pwsh.exe","args":["-NoProfile"],"cwd":"C:/w","env":[["K","V"]],"domain":{"name":"pwsh-workspace","policy_domain":"workspace-shell","container_sid":"S-1-15-2-1","capability_sids":["S-1-15-3-1024-1"],"identity":{"kind":"capability","sid":"S-1-15-3-1024-9"}},"handles":{"job":16,"stdin_read":20,"stdout_write":24,"stderr_write":28},"redirector":{"kind":"lazy","workspace_root":"C:/w","broker_pipe":"\\\\.\\pipe\\lazy"},"console":"required"}"#
    );
    let back: ControlRequest = serde_json::from_str(&json).expect("round trip");
    assert_eq!(back, request);
}

#[test]
fn control_responses_keep_their_wire_shape() {
    let ready = ControlResponse::Ready {
        request_pipe: r"\\.\pipe\harness-spawnd-1-0-2".to_string(),
        daemon_pid: 1234,
        protocol_version: PROTOCOL_VERSION,
    };
    assert_eq!(
        serde_json::to_string(&ready).expect("serialize"),
        r#"{"kind":"ready","request_pipe":"\\\\.\\pipe\\harness-spawnd-1-0-2","daemon_pid":1234,"protocol_version":4}"#
    );
    assert_eq!(
        serde_json::to_string(&ControlResponse::Spawned {
            pid: 4200,
            process: 64
        })
        .expect("serialize"),
        r#"{"kind":"spawned","pid":4200,"process":64}"#
    );
    assert_eq!(
        serde_json::to_string(&ControlResponse::Failed {
            failure_kind: SpawnFailureKind::Spawn,
            reason: "CreateProcessW: boom".to_string()
        })
        .expect("serialize"),
        r#"{"kind":"failed","failure_kind":"spawn","reason":"CreateProcessW: boom"}"#
    );
}

/// **版が「合わない」を、欄が「無い」とは別に測る。**
///
/// 直下のテストは欄そのものが無い場合（＝段階③以前のバイナリ）を見ているが、
/// **欄はあるが値が違う**場合はそこを通らない。判定は`==`でなければならない——
/// `>=`にすると、古いDaemonが新しい注入欄を無視して**注入なしで起動して成功する**
/// （CoWの透過が丸ごと消えたまま、症状が出ない）。
#[test]
fn a_peer_that_reports_a_different_protocol_version_is_rejected_in_both_directions() {
    assert!(
        protocol_version_mismatch(PROTOCOL_VERSION).is_none(),
        "同じ版を拒んでいる。全セッションが起動できない"
    );
    for peer in [PROTOCOL_VERSION - 1, PROTOCOL_VERSION + 1] {
        let reason = protocol_version_mismatch(peer)
            .unwrap_or_else(|| panic!("版{peer}を受理した。新旧混在がspawn前に止まらない"));
        assert!(
            reason.contains(&peer.to_string()),
            "拒否の理由に相手の版が出ていない（どちらを建て直せばよいか分からない）: {reason}"
        );
    }
}

#[test]
fn old_peers_without_a_protocol_version_are_rejected() {
    assert!(
        serde_json::from_str::<ControlRequest>(r#"{"kind":"hello","harness_process":4660}"#)
            .is_err()
    );
    assert!(serde_json::from_str::<ControlResponse>(
        r#"{"kind":"ready","request_pipe":"p","daemon_pid":1}"#
    )
    .is_err());
}

/// **要求受付パイプの電文にドメインの欄が無いこと**を形の側から固定する（§12）。
///
/// 生えたら「クライアントにドメインを申告させる」形になり、`{"domain":"trusted"}`と
/// 名乗るだけで境界が消える。**型の変更で静かに生えないよう、バイト列で見張る。**
#[test]
fn a_spawn_request_carries_no_domain_field() {
    let json = serde_json::to_string(&SpawnRequest::Spawn {
        exe: "git.exe".to_string(),
        args: vec!["status".to_string()],
        cwd: "C:/w".to_string(),
    })
    .expect("serialize");
    assert_eq!(
        json,
        r#"{"kind":"spawn","exe":"git.exe","args":["status"],"cwd":"C:/w"}"#
    );
    assert!(
        !json.contains("domain"),
        "要求受付パイプの電文にドメインの欄が生えている。\
         §12「Domainはクライアントから申告させない」が形の側から崩れる: {json}"
    );
}

/// 拒否の理由は**別々の文字列**として運ばれる。
///
/// 同じ綴りへ丸めると、受け入れテストが「台帳の判定が効いている」と
/// 「ポリシーの判定が効いている」を区別できなくなる（`B-35`）。
#[test]
fn every_deny_reason_has_a_distinct_wire_value() {
    use harness_policy::transition::TransitionDenial;

    let reasons = [
        DenyReason::NotRegistered,
        DenyReason::PidReused,
        DenyReason::MalformedRequest,
        // [段階6b] 判定器の答えは**変種ごとに別々に運ばれる**。
        // 「宣言していないから拒否」と「呼び出し元のドメインを知らないから拒否」は
        // 直し方が違う（前者は辺を足す、後者はドメイン名が合っていない）。
        DenyReason::Transition {
            denial: TransitionDenial::UnknownSourceDomain,
        },
        DenyReason::Transition {
            denial: TransitionDenial::NoMatchingEdge,
        },
        DenyReason::Transition {
            denial: TransitionDenial::AmbiguousPattern { matched: 2 },
        },
        DenyReason::Transition {
            denial: TransitionDenial::CwdMismatch {
                declared: "C:/w".to_string(),
                actual: "C:/other".to_string(),
            },
        },
        DenyReason::TargetDomainNotProvisioned {
            to: "other-domain".to_string(),
        },
    ];
    let mut seen: Vec<String> = reasons
        .iter()
        .map(|r| serde_json::to_string(r).expect("serialize"))
        .collect();
    let total = seen.len();
    seen.sort();
    seen.dedup();
    assert_eq!(
        seen.len(),
        total,
        "拒否理由のワイヤ表現が重複している。理由の区別が受信側で失われる: {seen:?}"
    );

    assert_eq!(
        serde_json::to_string(&SpawnResponse::Denied {
            reason: DenyReason::NotRegistered
        })
        .expect("serialize"),
        r#"{"kind":"denied","reason":{"kind":"not_registered"}}"#
    );

    // **書き出せることは、読み戻せることを意味しない。**
    //
    // 2026-09-12に実際に踏んだ: `DenyReason`も`TransitionDenial`も`kind`をタグ名に使うので、
    // 判定器の答えをnewtypeで包むと`{"kind":"transition","kind":"..."}`という
    // **`kind`が2つあるJSON**が出る。書き出しは成功し、上の「重複していない」検査も通り、
    // 壊れるのは**読み戻した側**だけだった。だから往復まで測る。
    for reason in &reasons {
        let json = serde_json::to_string(reason).expect("serialize");
        assert_eq!(
            json.matches(r#""kind":"#).count(),
            if matches!(reason, DenyReason::Transition { .. }) {
                2 // 外側の`kind`と、入れ子になった`denial`の中の`kind`。**同じ階層に2つではない。**
            } else {
                1
            },
            "タグが同じ階層で重複している（読み戻すと片方が消える）: {json}"
        );
        let back: DenyReason = serde_json::from_str(&json).expect("round trip");
        assert_eq!(&back, reason, "往復で値が変わった: {json}");
    }
}

/// [段階6b・**暫定を固定するテスト**] 遷移先が別ドメインの辺は、**専用の理由**で断られる。
///
/// # このテストは何のために在るのか
///
/// **暫定措置が残っていることを見張るためだけに在る。** 別ドメインへ遷移するには、
/// そのドメイン用の`(package SID, capability SIDの組)`が要るが、ドメインを鍵にした
/// AppContainerプロファイル発行器は未実装である
/// （`plans/DESIGN-MAC-BROKER.md` §22.9が7つの配線点を挙げている作業）。
///
/// # §22.9が着地したら、このテストごと消すのが正しい畳み方である
///
/// 一緒に消えるのは次の3つで、**どれか1つでも残ると「別ドメインへ遷移できない」が
/// 理由の分からない拒否として残り続ける**。
///
/// 1. [`DenyReason::TargetDomainNotProvisioned`]（この変種そのもの）
/// 2. `server.rs`の`serve_spawn_request`で「遷移先が呼び出し元と同じか」を見ている分岐
/// 3. このテスト
///
/// **件数ではなく綴りで固定している**——件数だと、別の理由を1つ足したときにも赤くなって
/// 「何が起きたか」が分からなくなる。
#[test]
fn a_cross_domain_transition_is_refused_until_per_domain_profiles_exist() {
    let json = serde_json::to_string(&SpawnResponse::Denied {
        reason: DenyReason::TargetDomainNotProvisioned {
            to: "build-tools".to_string(),
        },
    })
    .expect("serialize");

    assert_eq!(
        json,
        r#"{"kind":"denied","reason":{"kind":"target_domain_not_provisioned","to":"build-tools"}}"#,
        "別ドメインへの遷移を断る暫定措置の形が変わった。\
         §22.9（ドメイン単位のプロファイル発行器）が着地して暫定を外したのなら、\
         このテストと DenyReason::TargetDomainNotProvisioned と \
         server.rs の同一ドメイン判定の3つを**まとめて**消すこと（同変種のdoc）"
    );
}

/// 上限を超えたフレームは**受け取らない**という約束を、数の側で固定する。
///
/// Daemonはサンドボックスからの入力を直接パースする最初のフルトラスト常駐なので
/// （§10.1）、上限が消えると相手の言い値でメモリを確保することになる。
///
/// **実行時のassertではなくコンパイル時にする**——どちらも定数なので、実行時に測っても
/// 「テストが走った」以上の意味が無い（clippyもそう言う）。ビルドで落ちるほうが強い。
const _: () = assert!(
    MAX_FRAME_BYTES <= 1024 * 1024,
    "1フレームの上限が緩すぎる。相手の言い値で確保する形に近づく"
);
const _: () = assert!(
    MAX_FRAME_BYTES >= 4096,
    "上限が小さすぎて、正当な要求（長いコマンドライン）が通らない"
);
