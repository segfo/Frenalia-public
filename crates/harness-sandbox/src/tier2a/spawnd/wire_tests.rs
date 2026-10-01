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
        // [#55] **追加は必ず末尾へ。** この電文は別プロセス（`harness-spawnd.exe`）が
        // 読むワイヤ形式で、下の文字列がその表現を固定している。
        domains: Vec::new(),
        // [残課題 サンドボックス周辺 #65] 空でない値で固定する——空だと、欄が
        // 落ちても`[]`と区別の付かない形でしか見えない。
        writable_outside_policy: vec!["C:/tools".to_string()],
    })
    .expect("serialize");
    assert_eq!(
        json,
        r#"{"kind":"hello","harness_process":4660,"protocol_version":8,"policy":{"schema_version":2,"domains":[]},"workspace_root":"C:/w","domains":[],"writable_outside_policy":["C:/tools"]}"#
    );
}

/// [残課題 サンドボックス周辺 #65] **`writable_outside_policy`の無い`Hello`は読めない。**
///
/// この欄が空であることは検査が緩くなる向き（書ける場所を書けないと見る）なので、
/// 欄の無い電文を黙って空として受け付けない（`serde(default)`を付けていないことの固定）。
#[test]
fn a_hello_without_writable_outside_policy_is_refused() {
    let without = r#"{"kind":"hello","harness_process":4660,"protocol_version":8,"policy":{"schema_version":2,"domains":[]},"workspace_root":"C:/w","domains":[]}"#;
    assert!(
        serde_json::from_str::<ControlRequest>(without).is_err(),
        "a Hello missing writable_outside_policy must not parse as an empty list"
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

/// [BUG-180] **CoWの注入設定は、差分層の宛先SIDを必ず運ぶ。**
///
/// この欄が落ちると、Daemonは別ドメインへ移った子へ差分層のSIDを積めない。
/// 子は差分層へ届かないまま起動に成功し、変更前の中身を黙って読む。
#[test]
fn a_cow_redirector_spec_carries_its_diff_layer_capability() {
    let spec = RedirectorSpec::Cow {
        workspace_root: "C:/w".to_string(),
        diff_layer_dir: "C:/d".to_string(),
        ext_capture_roots: vec!["C:/x".to_string()],
        // **追加は必ず末尾へ**（上の`Hello`と同じ理由）。
        diff_layer_capability_sid: "S-1-15-3-1024-7".to_string(),
    };
    let json = serde_json::to_string(&spec).expect("serialize");
    assert_eq!(
        json,
        r#"{"kind":"cow","workspace_root":"C:/w","diff_layer_dir":"C:/d","ext_capture_roots":["C:/x"],"diff_layer_capability_sid":"S-1-15-3-1024-7"}"#
    );
    let back: RedirectorSpec = serde_json::from_str(&json).expect("round trip");
    assert_eq!(back, spec);
}

/// **対の側**（`B-35`）: 宛先SIDの欄が無いCoWの注入設定は、**読めない**。
///
/// 既定値で埋めて受け付けると、「積むSIDが空」の設定で注入することになる
/// ——古い電文を黙って通す形で、欄を足した意味が消える。
#[test]
fn a_cow_spec_without_the_diff_layer_capability_does_not_parse() {
    let old =
        r#"{"kind":"cow","workspace_root":"C:/w","diff_layer_dir":"C:/d","ext_capture_roots":[]}"#;
    let parsed = serde_json::from_str::<RedirectorSpec>(old);
    assert!(
        parsed.is_err(),
        "差分層の宛先SIDが無いCoWの注入設定を受け付けた: {parsed:?}"
    );
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
        r#"{"kind":"ready","request_pipe":"\\\\.\\pipe\\harness-spawnd-1-0-2","daemon_pid":1234,"protocol_version":8}"#
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
    // [段階6f-3] 待ち行列の書き出し。**0行は失敗ではない**ので、欄は必ず出す。
    assert_eq!(
        serde_json::to_string(&ControlResponse::Flushed { lines: 0 }).expect("serialize"),
        r#"{"kind":"flushed","lines":0}"#
    );
}

/// [段階6f-3] 待ち行列の書き出し要求は、**引数を1つも持たない**（§19.3.8）。
///
/// # 欄を足さないこと
///
/// 置き場のパスも対象の種類も運ばない。**非昇格の親が指定したパスへDaemonが書く経路を
/// 作らない**という待ち行列の設計（`transitions::pending_path`のdoc、`P-01`）は、
/// この要求にもそのまま効く——欄を1つ足した瞬間に、その設計が崩れる。
#[test]
fn the_flush_request_carries_nothing() {
    let json = serde_json::to_string(&ControlRequest::FlushTransitionQueue).expect("serialize");
    assert_eq!(json, r#"{"kind":"flush_transition_queue"}"#);
    let back: ControlRequest = serde_json::from_str(&json).expect("round trip");
    assert_eq!(back, ControlRequest::FlushTransitionQueue);
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
        image: "C:/bin/git.exe".to_string(),
        command_line: "\"git.exe\" status".to_string(),
        cwd: "C:/w".to_string(),
        env: Some(vec![("FOO".to_string(), "1".to_string())]),
        handles: crate::tier2a::spawnd::CallerHandles {
            stdin: None,
            stdout: Some(0x1c),
            stderr: Some(0x20),
        },
        console: ConsoleNeed::NotNeeded,
        suspended: false,
    })
    .expect("serialize");
    assert_eq!(
        json,
        r#"{"kind":"spawn","image":"C:/bin/git.exe","command_line":"\"git.exe\" status","cwd":"C:/w","env":[["FOO","1"]],"handles":{"stdin":null,"stdout":28,"stderr":32},"console":"not_needed","suspended":false}"#
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
        // **この一覧は型が守らない**（手で並べている）。2026-10-01まで`SpawnFailed`が
        // 抜けていたので、固定辺の拒否を足した回に一緒に入れた。変種を足したらここにも足すこと。
        DenyReason::SpawnFailed,
        DenyReason::FixedInputWritable,
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

/// 用意できなかった遷移先への要求は、**専用の理由**で断られる（電文の形を固定する）。
///
/// # このテストの役目は2026-09-20に変わった
///
/// かつては**暫定措置が残っていることを見張るためだけに在った**——別ドメインへは一切
/// 遷移できず、[`DenyReason::TargetDomainNotProvisioned`]はその見張りの綴りだった。
/// 「§22.9が着地したらこのテストごと消す」と書いてあったが、**着地しても消えていない。**
///
/// 発行器（`win_appcontainer/domain_provision.rs`）は入り、用意できた遷移先では実際に
/// 別package SIDの子が起きる。**それでも用意できないドメインは残る**ので、
/// この拒否理由は暫定ではなく**恒常的な形**になった。だからこのテストは
/// 「暫定の見張り」から「**電文の形の固定**」へ役目が移っている。
///
/// # 別ドメインへ遷移できることを確かめるのはここではない
///
/// ここは文字列の形しか見ない。実際に**別のpackage SIDで起きること**と、
/// **用意できないドメインが断られること**は実機の受入2本が対で見ている
/// （`a_cross_domain_transition_runs_the_child_under_a_different_package_sid`と
/// `a_transition_into_a_domain_that_could_not_be_provisioned_is_refused`）。
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
        "用意できなかった遷移先を断るときの電文の形が変わった。\
         読む側（分類表 transitions::remedy と拒否の待ち行列）が同じ綴りを前提にしているので、\
         変えるなら両方を同じ回で直すこと"
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

/// [段階6f-1] **電文は読み戻せなければ意味が無い。**
///
/// 書き出しだけを固定していると、**Daemon側が1件も解釈できない**状態で緑のままになる
/// （2026-09-17に実機でこれを踏んだ——全要求が`malformed_request`で断られた）。
#[test]
fn a_spawn_request_round_trips_through_the_wire() {
    let original = SpawnRequest::Spawn {
        image: r"C:\bin\git.exe".to_string(),
        command_line: "\"git.exe\" status".to_string(),
        cwd: r"C:\w".to_string(),
        env: Some(vec![("FOO".to_string(), "1".to_string())]),
        handles: crate::tier2a::spawnd::CallerHandles {
            stdin: None,
            stdout: Some(0x1c),
            stderr: Some(0x20),
        },
        console: ConsoleNeed::Required,
        suspended: true,
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let parsed: SpawnRequest = serde_json::from_str(&json)
        .unwrap_or_else(|e| panic!("要求電文を読み戻せない（Daemonは全部断る）: {e} / {json}"));
    assert_eq!(parsed, original);
}

/// [段階6f-2] **Redirector DLLが組んだ電文が、そのまま読めること。**
///
/// # なぜここに写しが在るのか（意図された複製である）
///
/// `harness-redirector`は**注入先の非信頼プロセスで動く**ので、このクレートに依存しない
/// （あちらの`Cargo.toml`の宣言）。したがって電文は**両端で別々に実装されており、
/// ずれてもコンパイラは何も言わない**。下の文字列は
/// `harness-redirector`の`spawn_broker::request_tests`が固定しているものと**1文字も
/// 違ってはいけない**——あちらが「こう組む」を固定し、ここが「こう読める」を固定する。
///
/// **片方だけでは守れない。** 書き出しの形だけを固定していると、読めない綴りを
/// 固定したまま緑になる（2026-09-17に実機で踏んだ形そのもの）。
#[test]
fn the_wire_the_redirector_dll_writes_is_the_wire_this_crate_reads() {
    // `harness-redirector/src/spawn_broker_tests.rs` の
    // `the_request_is_the_wire_the_daemon_expects` と同じ文字列。
    const FROM_THE_DLL: &str = r#"{"command_line":"\"C:\\Windows\\System32\\cmd.exe\" /c echo hi","console":"required","cwd":"C:\\ws","env":[["PATH","C:\\bin"]],"handles":{"stderr":456,"stdin":null,"stdout":123},"image":"C:\\Windows\\System32\\cmd.exe","kind":"spawn","suspended":false}"#;

    let parsed: SpawnRequest = serde_json::from_str(FROM_THE_DLL).unwrap_or_else(|e| {
        panic!(
            "DLLが組む電文をDaemonが読めない。**サンドボックスの中からの生成要求が\n         \
             1件も通らない**（全部`malformed_request`で断られる）: {e}"
        )
    });
    let SpawnRequest::Spawn {
        image,
        command_line,
        cwd,
        env,
        handles,
        console,
        suspended,
    } = parsed;
    assert_eq!(image, r"C:\Windows\System32\cmd.exe");
    assert_eq!(command_line, r#""C:\Windows\System32\cmd.exe" /c echo hi"#);
    assert_eq!(cwd, r"C:\ws");
    assert_eq!(
        env,
        Some(vec![("PATH".to_string(), r"C:\bin".to_string())]),
        "**フックは常に環境を申告する**（`None`のまま運ぶと、呼び出し元がプロセス内で\n         設定した変数が子から消える）"
    );
    assert_eq!(
        handles,
        crate::tier2a::spawnd::CallerHandles {
            stdin: None,
            stdout: Some(123),
            stderr: Some(456),
        }
    );
    assert_eq!(console, ConsoleNeed::Required);
    assert!(!suspended);
}

/// 欄を持たない古い形（段階6bの綴り）も読める——**足りない欄は既定へ落ちる**。
#[test]
fn a_spawn_request_without_the_new_fields_still_parses() {
    let json = r#"{"kind":"spawn","image":"C:/bin/git.exe","command_line":"\"git.exe\"","cwd":"C:/w"}"#;
    let parsed: SpawnRequest = serde_json::from_str(json).expect("parse the minimal form");
    let SpawnRequest::Spawn {
        env,
        handles,
        console,
        suspended,
        ..
    } = parsed;
    assert_eq!(
        env, None,
        "欄が無いのに「空だと申告した」になっている。**`SystemRoot`の無い環境ブロックで\n         子を起こすことになる**（`SpawnRequest::Spawn::env`のdoc）"
    );
    assert_eq!(handles, Default::default());
    assert_eq!(console, ConsoleNeed::NotNeeded);
    assert!(!suspended);
}
