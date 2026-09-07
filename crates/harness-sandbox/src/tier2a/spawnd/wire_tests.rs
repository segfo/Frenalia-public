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
    })
    .expect("serialize");
    assert_eq!(json, r#"{"kind":"hello","harness_process":4660}"#);
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
        token_default_dacl_sddl: None,
    }));
    let json = serde_json::to_string(&request).expect("serialize");
    assert_eq!(
        json,
        r#"{"kind":"spawn_top_level","exe":"C:/w/pwsh.exe","args":["-NoProfile"],"cwd":"C:/w","env":[["K","V"]],"domain":{"name":"pwsh-workspace","container_sid":"S-1-15-2-1","capability_sids":["S-1-15-3-1024-1"],"identity":{"kind":"capability","sid":"S-1-15-3-1024-9"}},"handles":{"job":16,"stdin_read":20,"stdout_write":24,"stderr_write":28},"token_default_dacl_sddl":null}"#
    );
    let back: ControlRequest = serde_json::from_str(&json).expect("round trip");
    assert_eq!(back, request);
}

#[test]
fn control_responses_keep_their_wire_shape() {
    let ready = ControlResponse::Ready {
        request_pipe: r"\\.\pipe\harness-spawnd-1-0-2".to_string(),
        daemon_pid: 1234,
    };
    assert_eq!(
        serde_json::to_string(&ready).expect("serialize"),
        r#"{"kind":"ready","request_pipe":"\\\\.\\pipe\\harness-spawnd-1-0-2","daemon_pid":1234}"#
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
            reason: "CreateProcessW: boom".to_string()
        })
        .expect("serialize"),
        r#"{"kind":"failed","reason":"CreateProcessW: boom"}"#
    );
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
    let reasons = [
        DenyReason::NotRegistered,
        DenyReason::PidReused,
        DenyReason::PolicyNotImplemented,
        DenyReason::MalformedRequest,
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
        r#"{"kind":"denied","reason":"not_registered"}"#
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
