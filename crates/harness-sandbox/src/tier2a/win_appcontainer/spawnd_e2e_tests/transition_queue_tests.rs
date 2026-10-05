//! [段階6c] **拒否の待ち行列の受け入れ**——拒否が`.harness/transitions/pending.jsonl`へ残る。
//!
//! # 合格条件は「対で4本」である
//!
//! | # | 何を撃つか | 期待 |
//! |---|---|---|
//! | Q1 | 宣言していない遷移を1件 | 1行増え、理由が`no_matching_edge`（種別が潰れていない） |
//! | Q2 | **宣言した**遷移を1件 | **1行も増えない**（許可は拒否の待ち行列に載らない） |
//! | Q3 | **遷移先が別ドメイン**の辺を1件 | 1行増え、分類が「宣言では直らない」側になる |
//! | Q4 | 同じ拒否を繰り返す | 種類は1つのまま、回数が増える。畳みどきに残りが書き切られる |
//!
//! **Q1が無いと「一度も積まない」実装で緑になり、Q2が無いと「常に積む」実装で緑になる**（`B-35`）。
//! **Q3が判別しているもの**は、暫定由来の拒否を「宣言を直せ」の顔で積んでいないかである
//! ——積むと、`policy.json`と突き合わせた読む側が**「解決済み」と判定して画面から消す**のに、
//! 機械は拒否し続ける。症状の出ない誤りになる。
//!
//! # ここで測っていないもの
//!
//! - **カーネル拒否の行**。購読者は6cでは作っていない（製品は生成禁止を1度も積んでいないので
//!   届くイベントが0件である）。行の形だけは`spawnd::transitions`の単体テストが固定している
//! - **却下印（`dismissed.json`）**。書き手はポリシーエディタの遷移画面で、試験もそちら
//!   （`harness-policy-editor`の`tui::transition_dismissed_tests`）にある。Spawn Daemonは読まない
//! - **読む側の「解決済み」計算**。同じく段階⑦
//!
//! # ファイルを分けてあるがモジュールは`spawnd_e2e_tests`の下にある
//!
//! 昇格の的`spawn-daemon`のフィルタが`win_appcontainer::spawnd_e2e_tests`なので、
//! 外へ出すと0件マッチで黙って走らなくなる（BUG-056）。

use harness_policy::policy_file::{PolicyDomain, PolicyFile};

use crate::tier2a::spawnd::transitions::{self, PendingRecord, Remedy};

use super::transition_acceptance_tests::{ask_daemon, policy_with_edge, request_payload};
use super::*;

/// いま待ち行列に積まれている行。
///
/// **`Case`が生きているうちに読む。** `Case`のdropはワークスペースごと畳むので、
/// 落としてから読むと「1行も無い」に見える。
///
/// [BUG-230] 測定（`cmd_nested_spawn_tests`）も同じ読み方を要るので`pub(super)`にしてある（写しを作らない）。
pub(super) fn queue_records(case: &Case) -> Vec<PendingRecord> {
    let path = transitions::pending_path(&case.canonical_workspace);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "待ち行列が読めない（**harnessが`Hello`を送る前に先行作成しているはず**）: {}: {e}",
            path.display()
        )
    });
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str::<PendingRecord>(l)
                .unwrap_or_else(|e| panic!("待ち行列の1行が読めない: {l}: {e}"))
        })
        .collect()
}

/// 行から「誰が拒否したか」と「何をすれば直るか」を取り出す。
pub(super) fn daemon_denial(record: &PendingRecord) -> &transitions::Denial {
    match record {
        PendingRecord::DeniedByDaemon(denial) => denial,
        other => panic!("Daemonが拒否した行のはずだが、別の種類だった: {other:?}"),
    }
}

/// 遷移先が**別のドメイン**を指す辺を1本だけ持つ宣言。
///
/// 遷移先のドメインも宣言に置く——置かないと、辺を組む段階（編集時検査）で弾かれて
/// **Daemonが起動しない**ので、「暫定で断られた」を測る手前で落ちる。
fn policy_with_cross_domain_edge(from: &str, to: &str, exe: &str) -> PolicyFile {
    let mut file = PolicyFile::default();
    let mut entry = PolicyDomain::new(from);
    entry.process = serde_json::from_value(serde_json::json!({
        "transitions": [
            { "exe": { "literal": exe }, "argv": { "any": true }, "to": to }
        ]
    }))
    .expect("the transition declaration must parse");
    file.domains.push(entry);
    file.domains.push(PolicyDomain::new(to));
    file
}

/// **Q1（積む側）**: 宣言していない遷移は、理由ごと待ち行列へ残る。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn an_undeclared_transition_lands_in_the_queue_with_its_reason_intact() {
    let probe = super::super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();

    let (case, profile, caps) = setup_with_policy_and_transitions(
        "spawnd-6c-queue-deny",
        ChildProcessPolicy::Unrestricted,
        |_workspace| policy_with_edge(E2E_POLICY_DOMAIN, &probe_str),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();

    assert!(
        queue_records(&case).is_empty(),
        "何も撃っていないのに待ち行列に行がある。**先行作成が空でないか、前回の残骸**"
    );

    // 宣言してあるのはプローブだけ。`cmd.exe`は1本も宣言されていない。
    let payload = request_payload(
        r"C:\Windows\System32\cmd.exe",
        &["/c", "exit", "0"],
        &workspace,
    );
    let out = ask_daemon(&case, &profile, &caps, &payload);
    assert_eq!(
        reply_kind(&out).as_deref(),
        Some("denied"),
        "前提が崩れている。拒否されていないなら待ち行列を測る意味が無い: {out}"
    );

    let records = queue_records(&case);
    assert_eq!(
        records.len(),
        1,
        "拒否が1件なのに待ち行列の行数が1ではない。**0なら積んでいない**、\
         2以上なら1件を複数行に分けている: {records:?}"
    );
    let denial = daemon_denial(&records[0]);
    assert_eq!(
        denial.reason,
        crate::tier2a::spawnd::DenyReason::Transition {
            denial: harness_policy::transition::TransitionDenial::NoMatchingEdge
        },
        "理由が潰れている。「宣言が無い」「ドメインを知らない」「cwdが違う」の区別が\
         **そのままユーザーが何を直せばよいか**なので、文字列へ丸めてはいけない"
    );
    assert_eq!(
        transitions::remedy(&denial.reason),
        Remedy::FixTheDeclaration,
        "未宣言の拒否は宣言を足せば通る。ここが別の値だと、画面が承認候補として出さない"
    );
    assert_eq!(
        denial.from_domain.as_deref(),
        Some(E2E_POLICY_DOMAIN),
        "**判定に使ったのと同じ遷移元ドメイン**が残っていない。残らないと、\
         どのドメインへ辺を足せばよいかが分からない"
    );
    assert_eq!(
        denial.cwd.as_deref(),
        Some(workspace.to_string_lossy().as_ref()),
        "Daemon経由なので実cwdは**観測できている**。`null`になっているなら、\
         カーネル拒否と同じ「観測していない」に見えてしまう"
    );
    assert_eq!(denial.count, 1);

    drop(case);
}

/// **Q2（積まない側）**: 宣言した遷移は通り、待ち行列に1行も載らない。
///
/// **Q1と同じ宣言で測る。** 変えるのは要求する実行ファイル1つだけなので、
/// 待ち行列の差はそこに帰せる。これが無いと「常に積む」実装でも緑になる。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn an_allowed_transition_does_not_land_in_the_queue() {
    let probe = super::super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();

    let (case, profile, caps) = setup_with_policy_and_transitions(
        "spawnd-6c-queue-allow",
        ChildProcessPolicy::Unrestricted,
        |_workspace| policy_with_edge(E2E_POLICY_DOMAIN, &probe_str),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let marker = workspace.join("queued-allow-child-ran.json");

    let payload = request_payload(
        &probe_str,
        &[
            "--emit",
            "nested-ok",
            "--report-file",
            &marker.to_string_lossy(),
        ],
        &workspace,
    );
    let out = ask_daemon(&case, &profile, &caps, &payload);
    assert_eq!(
        reply_kind(&out).as_deref(),
        Some("spawned"),
        "前提が崩れている。許可されていないなら「許可は積まない」を測れない: {out}"
    );

    assert!(
        queue_records(&case).is_empty(),
        "**許可した生成が拒否の待ち行列に載っている。** 載せると、承認済みの遷移が\
         毎回「まだ承認していないもの」として画面へ出続ける"
    );

    drop(case);
}

/// **Q3**: 暫定由来の拒否は積むが、「宣言を直せ」の顔では積まない。
///
/// # この1本が判別しているもの
///
/// 拒否の理由を**すべて同じ扱い**で積んでいないか。遷移先が別ドメインの辺は
/// **宣言としては正しい**（辺は一致する）ので、`policy.json`と突き合わせる読む側は
/// 「解決済み」と判定する。分類で分けていないと、この行は画面から消えたまま
/// 機械だけが拒否し続ける。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_provisional_denial_is_queued_but_not_as_a_declaration_problem() {
    let probe = super::super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();
    const TARGET_DOMAIN: &str = "spawnd-e2e-target-domain";

    let (case, profile, caps) = setup_with_policy_and_transitions(
        "spawnd-6c-queue-provisional",
        ChildProcessPolicy::Unrestricted,
        |_workspace| policy_with_cross_domain_edge(E2E_POLICY_DOMAIN, TARGET_DOMAIN, &probe_str),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let marker = workspace.join("cross-domain-child-ran.json");

    let payload = request_payload(
        &probe_str,
        &[
            "--emit",
            "cross-domain",
            "--report-file",
            &marker.to_string_lossy(),
        ],
        &workspace,
    );
    let out = ask_daemon(&case, &profile, &caps, &payload);
    assert_eq!(
        reply_kind(&out).as_deref(),
        Some("denied"),
        "別ドメインへの遷移が起きている。**暫定が外れている**（§22.9はまだ着地していない）: {out}"
    );
    assert!(
        !marker.exists(),
        "断ったのに子が走っている: {}",
        marker.display()
    );

    let records = queue_records(&case);
    assert_eq!(
        records.len(),
        1,
        "暫定由来の拒否が待ち行列に残っていない。**残さないと、宣言も正しいのに\
         起動だけが失敗する理由がどこにも無い状態になる**: {records:?}"
    );
    let denial = daemon_denial(&records[0]);
    assert_eq!(
        denial.reason,
        crate::tier2a::spawnd::DenyReason::TargetDomainNotProvisioned {
            to: TARGET_DOMAIN.to_string()
        },
        "理由が専用のものになっていない。`no_matching_edge`に丸めると、\
         宣言を直しても直らない拒否が「未宣言」の顔で積まれる"
    );
    assert_eq!(
        transitions::remedy(&denial.reason),
        Remedy::BlockedUntilHarnessImplementsIt,
        "**暫定由来の拒否が「宣言を直せ」に分類されている。** この分類のまま\
         `policy.json`と突き合わせると辺は一致するので「解決済み」と出る——\
         画面から消え、機械は拒否し続ける"
    );

    drop(case);
}

/// **Q4**: 同じ拒否は種類として1つに畳まれ、畳みどきに残りが書き切られる。
///
/// [段階6f-3] **畳まずに、頼んだだけで書き切れる**（§19.3.8）。
///
/// # なぜ要るのか
///
/// 直下のテストが示すとおり、同じ拒否の**3件目は1行も増えない**（回数の対数でしか書かない）。
/// `run_shell`は「このコマンドの間に何件断られたか」をモデルへ出すので、そのままだと
/// **断られたのに何も出ない回**が生まれる。かといってセッションを畳むわけにいかない。
///
/// # 対で見るもの
///
/// | 見るもの | 無いと何が通るか |
/// |---|---|
/// | 頼む**前**は2行のまま | 「常に全部書く」実装（畳み込みが消えている）が緑になる |
/// | 頼んだ**後**は3行・回数3 | **何もしない`flush`**が緑になる |
/// | 頼んだ**後もDaemonが生きている** | 制御電文を1つ足したせいで接続が壊れる形を見逃す |
#[test]
#[ignore = "starts a real spawn daemon and AppContainer children; run through spawn-daemon"]
fn the_queue_can_be_flushed_on_demand_without_shutting_the_daemon_down() {
    let probe = super::super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();

    let (case, profile, caps) = setup_with_policy_and_transitions(
        "spawnd-6f3-flush",
        ChildProcessPolicy::Unrestricted,
        |_workspace| policy_with_edge(E2E_POLICY_DOMAIN, &probe_str),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();

    let payload = request_payload(
        r"C:\Windows\System32\cmd.exe",
        &["/c", "exit", "0"],
        &workspace,
    );
    for _ in 0..3 {
        let out = ask_daemon(&case, &profile, &caps, &payload);
        assert_eq!(reply_kind(&out).as_deref(), Some("denied"), "{out}");
    }

    let before = queue_records(&case);
    assert_eq!(
        before.len(),
        2,
        "前提が崩れている——3件目がもう書かれているなら、頼む意味そのものが無い: {before:?}"
    );

    let daemon = case.daemon.as_ref().expect("case owns the daemon");
    let lines = daemon
        .flush_transition_queue()
        .expect("待ち行列の書き出しを頼めること");
    assert_eq!(
        lines, 1,
        "書き切るべき1種類ぶんが書かれていない（`flush`が何もしていない）"
    );

    let after = queue_records(&case);
    assert_eq!(after.len(), 3, "頼んでも増えていない: {after:?}");
    assert_eq!(
        daemon_denial(after.last().expect("last")).count,
        3,
        "書き切った回数が実際と合っていない"
    );

    // **Daemonは生きたままであること。** 畳んで書き切る経路とは別物である。
    let out = ask_daemon(&case, &profile, &caps, &payload);
    assert_eq!(
        reply_kind(&out).as_deref(),
        Some("denied"),
        "書き出しを頼んだ後にDaemonが応答しない＝制御電文を足したせいで接続が壊れている: {out}"
    );

    drop(case);
}

/// **1件ごとに1行ではない**（§10.2）。フックがDaemonへ頼むようになった日（6f）に
/// `cargo build`1回で数千のプロセスが起きるので、生で書くとログ量が破綻する。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer children; run through spawn-daemon"]
fn repeated_denials_are_folded_into_one_kind() {
    let probe = super::super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();

    let (mut case, profile, caps) = setup_with_policy_and_transitions(
        "spawnd-6c-queue-fold",
        ChildProcessPolicy::Unrestricted,
        |_workspace| policy_with_edge(E2E_POLICY_DOMAIN, &probe_str),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();

    let payload = request_payload(
        r"C:\Windows\System32\cmd.exe",
        &["/c", "exit", "0"],
        &workspace,
    );
    for _ in 0..3 {
        let out = ask_daemon(&case, &profile, &caps, &payload);
        assert_eq!(reply_kind(&out).as_deref(), Some("denied"), "{out}");
    }

    // 1・2件目は即時に書かれ、3件目は畳まれたまま（前回書いた数の2倍に届いていない）。
    let records = queue_records(&case);
    assert_eq!(
        records.len(),
        2,
        "3件の同じ拒否が3行になっている＝畳んでいない（または1行も書いていない）: {records:?}"
    );
    let counts: Vec<u64> = records.iter().map(|r| daemon_denial(r).count).collect();
    assert_eq!(counts, vec![1, 2], "回数の対数でしか書かない: {counts:?}");

    // **Daemonを畳むと、残っていた回数が書き切られる。**
    drop(case.daemon.take());
    let records = queue_records(&case);
    assert_eq!(
        records.len(),
        3,
        "畳みどきに書き切っていない。**回数が最後の書込のところで止まる**: {records:?}"
    );
    let last = daemon_denial(records.last().expect("last"));
    assert_eq!(
        last.count, 3,
        "畳んだ回数が残っていない。どの遷移を先に宣言すべきかは回数で決まる"
    );
    assert_eq!(
        last.first_ts.min(last.last_ts),
        last.first_ts,
        "最初と最後の時刻が逆転している"
    );

    drop(case);
}
