//! [段階6b] **遷移ポリシーの受け入れ**——Daemonが宣言を引いて、許可された生成を実際に起こす。
//!
//! # 合格条件は「対で3本」である（`docs/guide/11a-mac-enforcement-map.md`§3の⑥の行）
//!
//! | # | 何を測るか | 期待 |
//! |---|---|---|
//! | T1 | 宣言した辺の要求 | **通る**。しかも**子が実際に走った**ことをファイルで確かめる |
//! | T2 | 宣言していない実行ファイルの要求 | `no_matching_edge`で拒否 |
//! | T3 | **別のドメインのために宣言した辺**を、その辺を持たないドメインから要求 | 拒否 |
//!
//! **T1が無いと「全部拒否する」実装で緑になり、T2が無いと「全部許可する」実装で緑になる**（`B-35`）。
//!
//! **T3が判別しているもの**: 宣言を**辺の集合**として持っているか、**経路の集合**として
//! 持っているか。全ドメインの辺を1つの表に混ぜて引く実装だと、T1もT2も緑のまま
//! **T3だけが落ちる**。逆に言えば、T3が無いと「どのドメインから頼んでも同じ答えを返す」
//! 実装が素通りする。
//!
//! # 6f（DLLの透過化）を待っていない
//!
//! 要求受付パイプへは**プローブが直接繋ぐ**（`e2e-mcp-spawn-reach`と同じ形）。
//! フックが`CreateProcessW`をDaemonへの依頼に付け替えるのは6fで、そこを待つと
//! 「判定の不具合」と「透過化の不具合」が同じ回に混ざる。
//!
//! # ここで測っていないもの（**6bが残した限界**）
//!
//! - **遷移先が別ドメインの辺**。ドメイン単位のAppContainerプロファイル発行器が未実装で、
//!   専用の理由で断っている（`spawnd::DenyReason::TargetDomainNotProvisioned`）。
//!   形の固定は`spawnd/wire_tests.rs`にあり、**§22.9が着地したら一緒に消す**
//! - **起こした子の標準出力**。nestedの子のstdioは`NUL`へ捨てている（`server::spawn_nested`）。
//!   だから成否は**ファイル**で見る
//! - **`CHILD_PROCESS_RESTRICTED`との組み合わせ**。ここは`Unrestricted`で測る——
//!   生成禁止を積むと、起こした子自身がコンソールを要るかどうかの申告が要る（同関数の限界）

use std::time::{Duration, Instant};

use harness_policy::policy_file::{PolicyDomain, PolicyFile};

use super::*;

/// 宣言を1本だけ持つ`policy.json`を組む。
///
/// `to`は**必ず遷移元と同じドメイン**にしている。別ドメインを指す辺は6bでは起こせないので
/// （上記の限界）、ここで別ドメインを指すと3本とも「実体が無い」で断られ、
/// **判定が効いているのかどうかが測れなくなる**。
fn policy_with_edge(domain: &str, exe: &str) -> PolicyFile {
    let mut file = PolicyFile::default();
    let mut entry = PolicyDomain::new(domain);
    entry.process = serde_json::from_value(serde_json::json!({
        "transitions": [
            { "exe": { "literal": exe }, "argv": { "any": true }, "to": domain }
        ]
    }))
    .expect("the transition declaration must parse");
    file.domains.push(entry);
    file
}

/// プローブへ渡す1件の生成要求。
fn request_payload(exe: &str, args: &[&str], cwd: &std::path::Path) -> String {
    serde_json::to_string(&crate::tier2a::spawnd::SpawnRequest::Spawn {
        exe: exe.to_string(),
        args: args.iter().map(|a| a.to_string()).collect(),
        cwd: cwd.to_string_lossy().into_owned(),
    })
    .expect("serialize the spawn request")
}

/// ファイルが現れるまで待つ。**現れなければ`false`**（panicしない——呼び出し側が
/// 「何が起きなかったか」を書いたメッセージで落とすため）。
///
/// # なぜポーリングなのか
///
/// Daemonが返す`Spawned`は**起こしたこと**しか意味しない。子が走り終えたかは別の事実で、
/// そこを待たずにファイルを見ると、実装が正しくても競合で落ちる（`B-30`の逆向き）。
/// ハンドルで待てないのは、6bの応答がPIDしか返さないためである（`SpawnResponse::Spawned`のdoc）。
fn wait_for_file(path: &std::path::Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// 要求受付パイプへ1件投げて、プローブのstdoutを返す。
fn ask_daemon(case: &Case, profile: &OwnedContainerSid, caps: &[crate::win_common::OwnedSid], payload: &str) -> String {
    let daemon = case.daemon.as_ref().expect("case owns the daemon");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let spawn_cap = spawn_request_capability_sid().expect("spawn request capability");

    let (child, job, out, err) = super::spawn_via_daemon(
        daemon,
        profile,
        &workspace,
        domain_spec(profile, caps, Some(&spawn_cap)),
        &[
            "--pipe-client",
            daemon.request_pipe(),
            "--pipe-payload",
            payload,
            "--timeout-secs",
            "60",
        ],
    );
    eprintln!("[spawnd 6b] stdout={out}\nstderr={err}");
    super::wait_and_close(&child, job);
    out
}

/// **T1（許可側）**: 宣言した辺の要求は通り、**子が実際に走る**。
///
/// # 「通った」を応答だけで判定しない
///
/// `{"kind":"spawned"}`が返ることは、Daemonが`CreateProcessW`を呼んだことしか意味しない。
/// **起こした子が本当に動いたか**は別の事実なので、子にファイルを1つ書かせて確かめる
/// ——応答だけを見ると、`Spawned`を返して何も起こさない実装でも緑になる。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_declared_transition_is_allowed_and_the_child_actually_runs() {
    let probe = super::super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();

    let (case, profile, caps) = setup_with_policy_and_transitions(
        "spawnd-6b-allow",
        ChildProcessPolicy::Unrestricted,
        |_workspace| policy_with_edge(E2E_POLICY_DOMAIN, &probe_str),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    // **マーカーはワークスペースの中へ書かせる。** ここが書けるのは、Daemonが
    // 呼び出し元と同じドメイン（＝同じcapabilityの組）で起こしているからである
    // ——別のトークンで起こしていれば`ACCESS_DENIED`になり、このテストが落ちる。
    let marker = workspace.join("nested-child-ran.json");

    let payload = request_payload(
        &probe_str,
        &["--emit", "nested-ok", "--report-file", &marker.to_string_lossy()],
        &workspace,
    );
    let out = ask_daemon(&case, &profile, &caps, &payload);

    assert_eq!(
        report_field(&out, "connected").and_then(|v| v.as_bool()),
        Some(true),
        "要求受付パイプへ接続できていない。判定以前の配線（DACL・capability）が壊れている: {out}"
    );
    assert_eq!(
        reply_kind(&out).as_deref(),
        Some("spawned"),
        "宣言した辺の要求が拒否された。拒否理由が `unknown_source_domain` なら\
         遷移元ドメイン名が宣言と一致していない、`no_matching_edge` なら辺の照合\
         （実行ファイルの畳み込み）が効いていない: {out}"
    );
    assert!(
        wait_for_file(&marker, Duration::from_secs(30)),
        "Daemonは `spawned` と答えたのに、起こされたはずの子が1バイトも書いていない。\
         `CreateProcessW`は成功したが子が即座に落ちている（トークン・cwd・継承ハンドルの\
         いずれかが不正）か、そもそも起こしていない: {}",
        marker.display()
    );

    drop(case);
}

/// **T2（拒否側）**: 宣言していない実行ファイルの要求は`no_matching_edge`で断られる。
///
/// **T1と同じ宣言・同じドメインで測る。** 変えるのは要求する実行ファイル1つだけなので、
/// 結果の違いはそこに帰せる。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn an_undeclared_executable_is_refused_with_no_matching_edge() {
    let probe = super::super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();

    let (case, profile, caps) = setup_with_policy_and_transitions(
        "spawnd-6b-deny",
        ChildProcessPolicy::Unrestricted,
        |_workspace| policy_with_edge(E2E_POLICY_DOMAIN, &probe_str),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();

    // 宣言してあるのはプローブだけである。`cmd.exe`は1本も宣言されていない。
    let payload = request_payload(
        r"C:\Windows\System32\cmd.exe",
        &["/c", "exit", "0"],
        &workspace,
    );
    let out = ask_daemon(&case, &profile, &caps, &payload);

    assert_eq!(
        reply_kind(&out).as_deref(),
        Some("denied"),
        "宣言していない実行ファイルが起動を許された。**未宣言＝DENYが成立していない**: {out}"
    );
    assert_eq!(
        deny_reason(&out).as_deref(),
        Some("no_matching_edge"),
        "拒否はされたが理由が違う。`unknown_source_domain` なら遷移元ドメインが\
         グラフに無い（宣言の配線が壊れている）ので、**このテストは未宣言の拒否を\
         測れていない**——同じ「拒否」でも意味が違う（`B-35`）: {out}"
    );

    drop(case);
}

/// **T3**: **別のドメインのために宣言した辺は横取りできない。**
///
/// # この1本が判別しているもの
///
/// 宣言を**辺の集合**として持っているか、**経路の集合**として持っているか。
/// 全ドメインの辺を1つの表へ混ぜて引く実装だと、T1もT2も緑のまま**ここだけが落ちる**。
///
/// # 呼び出し元のドメインも宣言してある
///
/// **そうしないと測れない。** 呼び出し元のドメインをグラフに入れないと答えが
/// `unknown_source_domain`になり、「宣言が無いから断られた」のか
/// 「他人の宣言を引かなかったから断られた」のかが区別できない。
/// だから呼び出し元にも**別の**実行ファイルの辺を1本持たせ、
/// **ドメインは知っているが、この実行ファイルの辺は持っていない**状態を作る。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn an_edge_declared_for_another_domain_cannot_be_borrowed() {
    let probe = super::super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();
    const OTHER_DOMAIN: &str = "spawnd-e2e-other-domain";

    let (case, profile, caps) = setup_with_policy_and_transitions(
        "spawnd-6b-steal",
        ChildProcessPolicy::Unrestricted,
        |_workspace| {
            // 呼び出し元のドメイン: `cmd.exe`だけを宣言する（プローブは宣言しない）。
            let mut file = policy_with_edge(E2E_POLICY_DOMAIN, r"C:\Windows\System32\cmd.exe");
            // **別のドメイン**: プローブを宣言する。呼び出し元はここへ属していない。
            let other = policy_with_edge(OTHER_DOMAIN, &probe_str);
            file.domains.extend(other.domains);
            file
        },
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let marker = workspace.join("stolen-child-ran.json");

    // 別ドメインのために宣言された辺（プローブ）を、その辺を持たないドメインから頼む。
    let payload = request_payload(
        &probe_str,
        &["--emit", "stolen", "--report-file", &marker.to_string_lossy()],
        &workspace,
    );
    let out = ask_daemon(&case, &profile, &caps, &payload);

    assert_eq!(
        reply_kind(&out).as_deref(),
        Some("denied"),
        "**別のドメインのために宣言した辺を横取りできている。** 宣言が経路の集合として\
         引かれており、どのドメインから頼んでも同じ答えが返っている: {out}"
    );
    assert_eq!(
        deny_reason(&out).as_deref(),
        Some("no_matching_edge"),
        "拒否はされたが理由が違う。`unknown_source_domain` だと、\
         **呼び出し元のドメインを知らなかっただけ**かもしれず、\
         「他人の辺を引かなかった」ことの証明にならない: {out}"
    );
    assert!(
        !marker.exists(),
        "拒否と答えたのに子が走っている。**判定の後で起こす側が判定を見ていない**: {}",
        marker.display()
    );

    drop(case);
}
