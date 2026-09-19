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
pub(super) fn policy_with_edge(domain: &str, exe: &str) -> PolicyFile {
    policy_with_edges(domain, &[exe])
}

/// 実行ファイルを複数宣言する版（`to`はどれも遷移元と同じドメイン）。
///
/// **辺を足せるようにしてあるのは、1回の起動で2つの実行ファイルを起こす腕があるため**
/// （段階6f-2の受け入れは`cmd.exe`とシェルの両方を起こす）。分けて撃つと、
/// 実機のワークスペース作成とDaemon起動を2回払うことになる。
pub(super) fn policy_with_edges(domain: &str, exes: &[&str]) -> PolicyFile {
    let mut file = PolicyFile::default();
    let mut entry = PolicyDomain::new(domain);
    let transitions: Vec<serde_json::Value> = exes
        .iter()
        .map(|exe| {
            serde_json::json!({ "exe": { "literal": exe }, "argv": { "any": true }, "to": domain })
        })
        .collect();
    entry.process = serde_json::from_value(serde_json::json!({ "transitions": transitions }))
        .expect("the transition declaration must parse");
    file.domains.push(entry);
    file
}

/// プローブへ渡す1件の生成要求。
///
/// [段階6f-1] 電文は`exe`＋`args`ではなく**実行ファイルの絶対パスと逐語のコマンドライン**を
/// 運ぶようになった（`SpawnRequest::Spawn::image`のdoc）。呼び出し側の書き味は変えずに、
/// ここで`command_line_for`（本物の生成で使うのと同じ関数）を通して組む。
pub(super) fn request_payload(exe: &str, args: &[&str], cwd: &std::path::Path) -> String {
    request_payload_with(exe, args, cwd, Default::default(), false)
}

/// [段階6f-1] ハンドルと一時停止の指定まで含めて組む版。
pub(super) fn request_payload_with(
    exe: &str,
    args: &[&str],
    cwd: &std::path::Path,
    handles: crate::tier2a::spawnd::CallerHandles,
    suspended: bool,
) -> String {
    serde_json::to_string(&crate::tier2a::spawnd::SpawnRequest::Spawn {
        image: exe.to_string(),
        command_line: crate::tier2a::win_appcontainer::command_line_for(exe, args),
        cwd: cwd.to_string_lossy().into_owned(),
        env: None,
        handles,
        console: crate::tier2a::spawnd::ConsoleNeed::NotNeeded,
        suspended,
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
pub(super) fn wait_for_file(path: &std::path::Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// [段階6f-1] **フックの役を演じるプローブ**を起こして、その報告JSONを返す。
///
/// [`ask_daemon`]との違いは1つだけである——あちらはテストが組んだ電文をそのまま投げるが、
/// こちらは**プローブ自身が電文を組む**（自分でファイルハンドルを作って載せるため）。
/// 呼び出し元のハンドルは、その呼び出し元のプロセスの中にしか存在しないので、
/// テスト側からは載せられない。
#[allow(clippy::too_many_arguments)]
pub(super) fn ask_daemon_as_a_hook(
    case: &Case,
    profile: &OwnedContainerSid,
    caps: &[crate::win_common::OwnedSid],
    image: &str,
    command_line: &str,
    stdout_file: &std::path::Path,
    console: &str,
) -> String {
    let daemon = case.daemon.as_ref().expect("case owns the daemon");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let spawn_cap = spawn_request_capability_sid().expect("spawn request capability");
    let workspace_str = workspace.to_string_lossy().into_owned();
    let stdout_str = stdout_file.to_string_lossy().into_owned();

    let (child, job, out, err) = super::spawn_via_daemon(
        daemon,
        profile,
        &workspace,
        domain_spec(profile, caps, Some(&spawn_cap)),
        &[
            "--spawn-via-daemon",
            daemon.request_pipe(),
            "--spawn-image",
            image,
            "--spawn-command-line",
            command_line,
            "--spawn-cwd",
            &workspace_str,
            "--spawn-stdout",
            &stdout_str,
            "--spawn-console",
            console,
            "--timeout-secs",
            "60",
        ],
    );
    eprintln!("[spawnd 6f-1] stdout={out}\nstderr={err}");
    super::wait_and_close(&child, job);
    out
}

/// 要求受付パイプへ1件投げて、プローブのstdoutを返す。
pub(super) fn ask_daemon(
    case: &Case,
    profile: &OwnedContainerSid,
    caps: &[crate::win_common::OwnedSid],
    payload: &str,
) -> String {
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
        &[
            "--emit",
            "stolen",
            "--report-file",
            &marker.to_string_lossy(),
        ],
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

// ---------------------------------------------------------------------------
// [段階6f-1] 呼び出し元の持ち物で起こす（残課題#46・#47を閉じる3本）
// ---------------------------------------------------------------------------

/// `cmd.exe`のフルパス。**`%SystemRoot%`から組む**——32bitのテストバイナリから
/// `C:\Windows\System32`を直書きするとWOW64のリダイレクトで別の実体を指し得る。
pub(super) fn cmd_exe() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    format!(r"{root}\System32\cmd.exe")
}

/// Windows PowerShell 5.1のフルパス。
///
/// # なぜ`resolve_shell`ではないのか
///
/// あれが返すのは**この機でpreflightが選んだシェル**で、今日それはストアの実行エイリアスである。
/// エイリアスで起きたプロセスは**既に誰かが入っているJobへ入れられない**
/// （[§S59](../../../../../../plans/mac-spike/RESULTS.md)。系統Jobには必ず呼び出し元が居るので、
/// nestedの遷移先にできない）。**ここで測りたいのはコンソール要否の申告**なので、
/// その制約に当たらない実体のパスを使う。
///
/// 5.1を選ぶのは**どのWindowsにも必ず在る**からである（pwsh 7は入っていない機がある）。
/// コンソールが無いと何も実行せず終了コード0で終わる性質は5.1でも同じで、
/// [§7.1](../../../../../../plans/DESIGN-MAC-ENFORCEMENT.md)の実測表は「PowerShell」として
/// その挙動を書いている。
pub(super) fn windows_powershell_51() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe")
}

/// **T4（#46を閉じる）**: 呼び出し元が渡したハンドルへ、起こされた子の標準出力が落ちる。
/// あわせて、**返ったプロセスハンドルで待って終了コードが読める**。
///
/// # 1本で3つ見ているのはなぜか
///
/// 3つとも「**Daemonが1回の生成で持ち物を運べたか**」という同じ問いの側面であり、
/// 別々のテストにすると同じ実機の起動（数秒）を3回払うことになる。**ただし表明は分ける**
/// ——どれが落ちたのかがメッセージで分かるようにする。
///
/// # `cmd.exe`を使うのは、終了コードを自分で決められるからである
///
/// プローブの`--emit`は常に0で終わる。0は「走った」とも「何も起きなかった」とも読めるので、
/// **0以外**を返させないと、返ったハンドルが本当にこの子を指しているのか言えない。
///
/// # 逐語のコマンドラインでなければ成立しない
///
/// `cmd /c echo ... & exit 37` は、cmdが**自分でコマンドラインを解釈する**形である。
/// 段階6bのように`exe`＋`args`から組み直すと、引数がそれぞれ引用符で囲まれて
/// `&`が別の意味になる。**このテストは、逐語で運んでいることの証拠でもある。**
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn the_callers_own_stdout_handle_receives_the_childs_output_and_the_returned_handle_can_be_waited_on(
) {
    const MARKER: &str = "HARNESS-6F1-NESTED-STDOUT";
    const EXIT_CODE: u64 = 37;
    let cmd = cmd_exe();

    let (case, profile, caps) = setup_with_policy_and_transitions(
        "spawnd-6f1-stdio",
        ChildProcessPolicy::Unrestricted,
        |_workspace| policy_with_edge(E2E_POLICY_DOMAIN, &cmd),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let captured = workspace.join("nested-stdout.txt");

    let out = ask_daemon_as_a_hook(
        &case,
        &profile,
        &caps,
        &cmd,
        &format!("\"{cmd}\" /c echo {MARKER} & exit {EXIT_CODE}"),
        &captured,
        "not_needed",
    );

    assert_eq!(
        report_field(&out, "reply_kind").and_then(|v| v.as_str().map(str::to_string)),
        Some("spawned".to_string()),
        "宣言した辺の要求が拒否された: {out}"
    );
    assert_eq!(
        report_field(&out, "got_process_handle").and_then(|v| v.as_bool()),
        Some(true),
        "応答にプロセスハンドルが載っていない。**フックは`PROCESS_INFORMATION`を\
         組み立てられない**——呼び出し元のプログラムは子を待つことも終了コードを読むことも\
         できなくなる: {out}"
    );
    assert_eq!(
        report_field(&out, "child_exit_code").and_then(|v| v.as_u64()),
        Some(EXIT_CODE),
        "返ったハンドルで終了コードが読めない（か、値が違う）。**そのハンドルが\
         起こした子を指していない**: {out}"
    );

    let text = std::fs::read_to_string(&captured).unwrap_or_default();
    assert!(
        text.contains(MARKER),
        "**呼び出し元が渡したハンドルへ、子の標準出力が落ちていない**（残課題#46）。\
         段階6bはここを`NUL`へ捨てていた。捨てたままだと、フックを付け替えた日に\
         サンドボックスの中のコマンドが1文字も出力を返さなくなる: file={} content={text:?} {out}",
        captured.display()
    );

    drop(case);
}

/// **T5（#47を閉じる。許可側）**: 生成禁止を積んだ構成で、**コンソールが要ると申告した**
/// nestedのシェルは、保持プロセスのコンソールを借りて実際にコマンドを走らせる。
///
/// 段階⑤の同型テスト（`child_process_restricted_tests`）は**トップレベル**を測っている。
/// こちらは**要求受付パイプ経由**で、申告が電文で運ばれることまで見る。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_nested_shell_that_declares_it_needs_a_console_actually_runs_its_command() {
    const MARKER: &str = "HARNESS-6F1-NESTED-SHELL";
    // **`resolve_shell`は使わない**（2026-09-17の切り分け、[§S59](../../../../../../plans/mac-spike/RESULTS.md)）。
    // この機でそれが返すのはストアの実行エイリアスで、**エイリアスで起きたプロセスは
    // 既に誰かが入っているJobへ入れられない**（OSの制約。系統Jobには必ず呼び出し元が居る）。
    // ここで測りたいのは**コンソール要否の申告が効くか**なので、その制約に当たらない
    // 実体のパスを使う——当たる側は残課題#50で追う。
    let shell_exe = windows_powershell_51();
    let (case, profile, caps) = setup_with_policy_and_transitions(
        "spawnd-6f1-console-yes",
        ChildProcessPolicy::Restricted,
        |_workspace| policy_with_edge(E2E_POLICY_DOMAIN, &shell_exe),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let captured = workspace.join("nested-shell-required.txt");

    let out = ask_daemon_as_a_hook(
        &case,
        &profile,
        &caps,
        &shell_exe,
        &format!("\"{shell_exe}\" -NoProfile -NonInteractive -Command \"Write-Output '{MARKER}'\""),
        &captured,
        "required",
    );

    assert_eq!(
        report_field(&out, "reply_kind").and_then(|v| v.as_str().map(str::to_string)),
        Some("spawned".to_string()),
        "コンソールを借りる要求が拒否された。借りられないと`console holder:`で\
         失敗するので、理由が`spawn_failed`ならそちらである: {out}"
    );
    let text = std::fs::read_to_string(&captured).unwrap_or_default();
    assert!(
        text.contains(MARKER),
        "**コンソールを借りたはずのシェルが実行印を出していない。** PowerShellは\
         コンソールが無いと何も実行せず終了コード0で終わる（§7.1の無言失敗）: \
         file={} content={text:?} {out}",
        captured.display()
    );

    drop(case);
}

/// **T6（#47を閉じる。対の禁止側）**: 同じシェルを**「コンソールは要らない」と申告して**
/// 頼むと、**何も実行せずに終了コード0で終わる**。
///
/// # この1本が無いと、T5は「常に借りる」実装でも緑になる
///
/// 申告を読んでいるかどうかは、**読まなかったときに違う結果になること**でしか示せない
/// （`B-35`）。そしてここで起きる違いは**症状の出ない失敗**そのものである——
/// 終了コードは0、エラーも出ない、ただ何も起きない。**§7.1がこれを実測した表を持っている。**
///
/// 落ちる向きが逆（`not_needed`でも走ってしまう）なら、生成禁止が積まれていないか、
/// コンソールを常に借りている。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn the_same_shell_declared_as_not_needing_a_console_silently_does_nothing() {
    const MARKER: &str = "HARNESS-6F1-NESTED-SHELL";
    // **`resolve_shell`は使わない**（2026-09-17の切り分け、[§S59](../../../../../../plans/mac-spike/RESULTS.md)）。
    // この機でそれが返すのはストアの実行エイリアスで、**エイリアスで起きたプロセスは
    // 既に誰かが入っているJobへ入れられない**（OSの制約。系統Jobには必ず呼び出し元が居る）。
    // ここで測りたいのは**コンソール要否の申告が効くか**なので、その制約に当たらない
    // 実体のパスを使う——当たる側は残課題#50で追う。
    let shell_exe = windows_powershell_51();
    let (case, profile, caps) = setup_with_policy_and_transitions(
        "spawnd-6f1-console-no",
        ChildProcessPolicy::Restricted,
        |_workspace| policy_with_edge(E2E_POLICY_DOMAIN, &shell_exe),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let captured = workspace.join("nested-shell-not-needed.txt");

    let out = ask_daemon_as_a_hook(
        &case,
        &profile,
        &caps,
        &shell_exe,
        &format!("\"{shell_exe}\" -NoProfile -NonInteractive -Command \"Write-Output '{MARKER}'\""),
        &captured,
        "not_needed",
    );

    // **起動そのものは成功する。** そこがこの失敗の分かりにくさである。
    assert_eq!(
        report_field(&out, "reply_kind").and_then(|v| v.as_str().map(str::to_string)),
        Some("spawned".to_string()),
        "この腕は「起きるが何もしない」を測るものなので、起動に失敗したら測れていない: {out}"
    );
    let text = std::fs::read_to_string(&captured).unwrap_or_default();
    assert!(
        !text.contains(MARKER),
        "**「コンソールは要らない」と申告したのに実行印が出ている。** 申告が読まれておらず\
         常にコンソールを借りているなら、T5は何も証明していない（`B-35`）: \
         file={} content={text:?} {out}",
        captured.display()
    );

    drop(case);
}

/// **T7**: 生成禁止を積んだ系統でも、**コンソールを要らない子は素直に起きる**。
///
/// # T5・T6の対照である
///
/// あの2本はシェル（実行エイリアス）を起こす。ここは`cmd.exe`を起こす——
/// **変えているのは「何を起こすか」1つだけ**なので、T5・T6が落ちたときに
/// 「生成禁止の下では何も起こせない」のか「そのプログラムだけ起こせない」のかが分かれる。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_nested_child_starts_even_when_the_lineage_is_restricted() {
    const MARKER: &str = "HARNESS-6F1-RESTRICTED-NESTED";
    let cmd = cmd_exe();

    let (case, profile, caps) = setup_with_policy_and_transitions(
        "spawnd-6f1-restricted",
        ChildProcessPolicy::Restricted,
        |_workspace| policy_with_edge(E2E_POLICY_DOMAIN, &cmd),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let captured = workspace.join("restricted-nested.txt");

    let out = ask_daemon_as_a_hook(
        &case,
        &profile,
        &caps,
        &cmd,
        &format!("\"{cmd}\" /c echo {MARKER}"),
        &captured,
        "not_needed",
    );

    assert_eq!(
        report_field(&out, "reply_kind").and_then(|v| v.as_str().map(str::to_string)),
        Some("spawned".to_string()),
        "生成禁止を積んだ系統では、Daemon経由でも子を起こせていない: {out}"
    );
    let text = std::fs::read_to_string(&captured).unwrap_or_default();
    assert!(
        text.contains(MARKER),
        "起きたはずの子が何も書いていない: file={} content={text:?} {out}",
        captured.display()
    );

    drop(case);
}
