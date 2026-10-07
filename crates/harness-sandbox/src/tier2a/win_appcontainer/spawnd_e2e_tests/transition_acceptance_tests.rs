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
//! - （かつてここに「遷移先が別ドメインの辺は発行器が未実装で断っている」と書いていた。
//!   §22.9の骨格は2026-09-20に着地し、別ドメインへの遷移はこのファイルの受入2本——用意できた
//!   遷移は別package SIDで起きる／用意できないものは断る——が対で測っている）
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
    // [#49] `CREATE_SUSPENDED`で頼むか。**返ったハンドルの権限を測る腕だけが`true`**
    // ——測る前に子が終わると、注入が失敗した理由が「絞れたから」か「死んでいたから」か
    // 区別できない（`spawn_report::record_handle_rights`のdoc）。
    suspended: bool,
) -> String {
    ask_daemon_as_a_hook_with_stdin(
        case,
        profile,
        caps,
        image,
        command_line,
        stdout_file,
        None,
        None,
        console,
        suspended,
    )
}

/// [P5.4b] 上に**子の標準入力にするファイル**を足した版（`stdin_file`。`None`なら電文の`stdin`は`null`）。
///
/// **`ask_daemon_as_a_hook`はこれを`None`で呼ぶ薄い包みである**（組み立てを2箇所に書かない、
/// `docs/CODE-STRUCTURE-RULES.md`規則5）。標準入力が子へ届いたかは「子が何を読んだか」でしか分からないので、
/// 呼び出し側は目印を書いたファイルを渡して、子にそれを標準出力へ写させて確かめる（`edge_stdio_tests`）。
///
/// [P5.4d] `cwd`は呼び出し元が申告する作業ディレクトリ（`--spawn-cwd`）。`None`ならワークスペース。Strict の辺は
/// 作業ディレクトリを呼び出し元が書けない場所に宣言するので（[`policy_with_strict_edge`]）、同じ値をここへ渡す。
#[allow(clippy::too_many_arguments)]
pub(super) fn ask_daemon_as_a_hook_with_stdin(
    case: &Case,
    profile: &OwnedContainerSid,
    caps: &[crate::win_common::OwnedSid],
    image: &str,
    command_line: &str,
    stdout_file: &std::path::Path,
    stdin_file: Option<&std::path::Path>,
    cwd: Option<&std::path::Path>,
    console: &str,
    suspended: bool,
) -> String {
    let daemon = case.daemon.as_ref().expect("case owns the daemon");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let spawn_cap = spawn_request_capability_sid().expect("spawn request capability");
    let cwd_str = cwd.unwrap_or(&workspace).to_string_lossy().into_owned();
    let stdout_str = stdout_file.to_string_lossy().into_owned();
    let stdin_str = stdin_file.map(|p| p.to_string_lossy().into_owned());

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
            &cwd_str,
            "--spawn-stdout",
            &stdout_str,
            "--spawn-console",
            console,
            "--timeout-secs",
            "60",
        ]
        .iter()
        .copied()
        .chain(suspended.then_some("--spawn-suspended"))
        .chain(
            stdin_str
                .iter()
                .flat_map(|path| ["--spawn-stdin", path.as_str()]),
        )
        .collect::<Vec<&str>>(),
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
        false,
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
        false,
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
        false,
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
        false,
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

// ---------------------------------------------------------------------------
// [#55] 別のドメインで起こす（§22.9の骨格）
// ---------------------------------------------------------------------------

/// 遷移先ドメインの名前。**入口ドメインと綴りを変える**——同じだと自己ループになり、
/// 表を引かずに通ってしまう（この測定が何も測らなくなる）。
const TARGET_DOMAIN: &str = "spawnd-s55-target";

/// 入口ドメインから`TARGET_DOMAIN`への辺を1本持ち、遷移先の定義も持つ宣言。
///
/// 遷移先は**宣言を1件も持たない**——骨格では「既に許可済みの宣言」しか引けないので、
/// 宣言を持たせると用意できずにこの測定が成立しない（それは別の腕で測る）。
fn policy_with_cross_domain_edge(exe: &str) -> PolicyFile {
    let mut file = PolicyFile::default();
    let mut entry = PolicyDomain::new(E2E_POLICY_DOMAIN);
    entry.process = serde_json::from_value(serde_json::json!({
        "transitions": [
            { "exe": { "literal": exe }, "argv": { "any": true }, "to": TARGET_DOMAIN }
        ]
    }))
    .expect("the transition declaration must parse");
    file.domains.push(entry);
    file.domains.push(PolicyDomain::new(TARGET_DOMAIN));
    file
}

/// **T4（本体）**: 遷移先ドメインで起こした子は、**呼び出し元とは違うpackage SID**で動く。
///
/// # 壊れた状態を一文で
///
/// **「ドメインを分けた」と言いながら、全部が同じ入れ物で動いている。**
/// §10.1.2が名指しで却下した逃げ方——呼び出し元のcapabilityのまま名前だけ遷移先にする——が
/// 入ると、宣言では狭めたつもりの遷移が**1ビットも狭まらず、しかも症状として出ない**。
/// だから「起きたか」ではなく**「どのSIDで起きたか」**を見る。
///
/// # なぜ子自身に報告させるのか
///
/// 起こした側（Daemon）が「このSIDで起こした」と言っても、それは**依頼の記録**であって
/// 結果ではない。子のトークンを子自身が読んで書き出したものだけが、実際に効いた値である
/// （`B-33`: 他人の成功報告を根拠にしない）。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_cross_domain_transition_runs_the_child_under_a_different_package_sid() {
    let probe = super::super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();

    let (case, profile, caps) = setup_with_provisioned_domains(
        "spawnd-s55-cross",
        ChildProcessPolicy::Unrestricted,
        |_workspace| policy_with_cross_domain_edge(&probe_str),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let marker = workspace.join("cross-domain-child.json");

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
        Some("spawned"),
        "別ドメインへの遷移が断られている。`target_domain_not_provisioned` なら\
         遷移先の実体が表に載っていない（用意できなかった理由が起動時の警告に出ているはず）: {out}"
    );
    assert!(
        wait_for_file(&marker, Duration::from_secs(30)),
        "Daemonは `spawned` と答えたのに、子が1バイトも書いていない: {}",
        marker.display()
    );

    // 子が自分で読んだpackage SID。**呼び出し元のもの（このテストのプロファイル）と違うこと。**
    let report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&marker).expect("the child must have written its report"),
    )
    .expect("the child report must be json");
    let child_sid = report
        .get("identity")
        .and_then(|v| v.get("appcontainer_sid"))
        .and_then(|v| v.as_str())
        .expect("the probe must report its AppContainer SID");
    let caller_sid = crate::win_common::sid_to_string(profile.as_psid())
        .expect("the caller's package SID must be readable");

    assert_ne!(
        child_sid, caller_sid,
        "**遷移先の子が呼び出し元と同じpackage SIDで動いている。** ドメインを分けたつもりで\
         1つの入れ物のまま——名前付きカーネルオブジェクト経由の横断チャネルが開いたままであり、\
         §10.1.2が却下した「名前だけ遷移先にする」形そのものである"
    );

    drop(case);
}

/// **対の側**（`B-35`）: 用意できなかったドメインへの遷移は断られる。
///
/// これが無いと「表を引かずに常に起こす」実装でも上のT4は緑になり、
/// **宣言だけあって実体の無いドメインでも子が動いてしまう**（どのトークンで動くのかは不定）。
///
/// ここでは遷移先の名前を**入れ物の名前にできない長さ**にする。宣言としては通る
/// （ドメイン名の上限は50文字）が、入れ物の名前は64文字までなので作れない
/// ——**宣言は正しいのに実体が作れない**形である。
///
/// # 試した2つが使えなかった理由（2026-09-20に実機で確認）
///
/// | 試した形 | なぜ腕にならないか |
/// |---|---|
/// | 遷移先が**許可されていない宣言**を持つ | 宣言の時点で落ちる。遷移先が呼び出し元より広い権限を持つと、編集時検査が「権限を広げる（または狭まることを証明できない）」として**宣言ごと拒否**する（§19.3.4の縮小性）。Daemonが起動しない |
/// | 遷移先の**定義が無い** | 同じく宣言ごと拒否される（グラフの構築が落ちる） |
///
/// **どちらも「用意できなかったから断った」ではなく「宣言が不正だった」である。**
/// 測りたいのは前者なので、宣言が正しいまま実体だけ作れない形を選んだ。
#[test]
#[ignore = "starts a real spawn daemon; run through spawn-daemon"]
fn a_transition_into_a_domain_that_could_not_be_provisioned_is_refused() {
    let probe = super::super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();

    let (case, profile, caps) = setup_with_provisioned_domains(
        "spawnd-s55-unprovisioned",
        ChildProcessPolicy::Unrestricted,
        |_workspace| {
            let mut file = policy_with_cross_domain_edge(&probe_str);
            // 遷移先の名前を**入れ物の名前にできない長さ**にする。
            //
            // 宣言としては通る（ドメイン名の上限は50文字）が、入れ物の名前は
            // `harness.domain.<セッションの印>.<ドメイン名>`で64文字までなので作れない。
            // **宣言は正しいのに実体が作れない**形で、まさに「用意できなかった」である。
            let long = "x".repeat(50);
            for domain in &mut file.domains {
                if domain.name == TARGET_DOMAIN {
                    domain.name = long.clone();
                }
                for edge in &mut domain.process.transitions {
                    if edge.to == TARGET_DOMAIN {
                        edge.to = long.clone();
                    }
                }
            }
            file
        },
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let marker = workspace.join("unprovisioned-child.json");

    let payload = request_payload(
        &probe_str,
        &[
            "--emit",
            "unprovisioned",
            "--report-file",
            &marker.to_string_lossy(),
        ],
        &workspace,
    );
    let out = ask_daemon(&case, &profile, &caps, &payload);

    assert_eq!(
        reply_kind(&out).as_deref(),
        Some("denied"),
        "用意できなかったドメインへの遷移が通っている。**どのトークンで動いているのかが不定**で、\
         最悪は呼び出し元の権限のまま動いている: {out}"
    );
    assert_eq!(
        deny_reason(&out).as_deref(),
        Some("target_domain_not_provisioned"),
        "拒否はされたが理由が違う。`no_matching_edge` だと**宣言の照合で落ちた**ことになり、\
         「実体が無いから断った」ことの証明にならない: {out}"
    );
    assert!(
        !marker.exists(),
        "拒否と答えたのに子が走っている: {}",
        marker.display()
    );

    drop(case);
}

// ---------------------------------------------------------------------------
// [#49・BUG-161] 固定辺の約束——呼び出し元はコードを1バイトも渡せない
// ---------------------------------------------------------------------------

/// プローブが報告した「返ったハンドルで何ができたか」から、1本の結果を引く。
///
/// **見つからないことと失敗したことを混ぜない**（`B-10`）——`None`は「その試行が
/// 報告に無い」で、`Some(false)`は「撃って断られた」である。
fn handed_handle_can(out: &str, access_contains: &str) -> Option<bool> {
    report_field(out, "handle_rights")?
        .as_array()?
        .iter()
        .find(|a| {
            a.get("access")
                .and_then(|v| v.as_str())
                .is_some_and(|access| access.contains(access_contains))
        })
        .and_then(|a| a.get("ok").and_then(|v| v.as_bool()))
}

/// **T6（#49の本体）**: 別ドメインで起こした子へ、呼び出し元は**書き込めない**。
///
/// # 壊れた状態を一文で
///
/// **狭めたはずの子へ、呼び出し元が好きなコードを流し込める。**
/// §19.3.4が固定辺を到達閉包から外す根拠は「固定辺では呼び出し元がコードを1バイトも
/// 注入できない」であり、ここが緩むと**編集時検査が広げる辺を通した根拠ごと崩れる**
/// ——固定できるのはプログラムと引数であって、走り始めた後の振る舞いではない。
///
/// # DACLが緑であることを根拠にしない
///
/// `domain_isolation_tests`は「別ドメインから`OpenProcess`できない」ことを測っているが、
/// **それはこの穴を覆っていない**。アクセス検査は**開く瞬間に1回だけ**行われるので、
/// Daemonが手渡したハンドルはその検査を通らない（`B-33`と同じ姿勢で、別の測定の緑を
/// こちらの根拠にしない）。
///
/// # なぜ一時停止で頼むのか
///
/// 終了済みのプロセスへの`VirtualAllocEx`も失敗する。**測る前に子が終わってしまうと、
/// 「絞れたから失敗した」と「死んでいたから失敗した」が区別できない**——だから止めたまま
/// 測り、`ResumeThread`そのものを測定の最後の1本にする。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_cross_domain_child_cannot_be_written_into_through_the_handle_the_caller_gets_back() {
    let probe = super::super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();

    let (case, profile, caps) = setup_with_provisioned_domains(
        "spawnd-s49-cross",
        ChildProcessPolicy::Unrestricted,
        |_workspace| policy_with_cross_domain_edge(&probe_str),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let captured = workspace.join("s49-cross-stdout.txt");

    let out = ask_daemon_as_a_hook(
        &case,
        &profile,
        &caps,
        &probe_str,
        &format!("\"{probe_str}\" --emit s49-cross"),
        &captured,
        "not_needed",
        true,
    );

    assert_eq!(
        report_field(&out, "reply_kind").and_then(|v| v.as_str().map(str::to_string)),
        Some("spawned".to_string()),
        "別ドメインへの遷移が断られている（この腕は起きた後を測るものなので成立しない）: {out}"
    );

    // **注入できないこと。** 確保できた時点で注入は成立するので、ここが本体である。
    assert_eq!(
        handed_handle_can(&out, "VirtualAllocEx"),
        Some(false),
        "**別ドメインの子へメモリを確保できている。** 返したハンドルに\
         `PROCESS_VM_OPERATION`が載っている——`WriteProcessMemory`＋`CreateRemoteThread`で\
         遷移先ドメインの中で任意コードが走る。§19.3.4が閉包の除外の根拠にしている\
         「呼び出し元はコードを1バイトも注入できない」が成立していない: {out}"
    );
    // 確保が断られていれば書き込みの試行は報告に出ない。**出ていたら必ず失敗側であること。**
    if let Some(wrote) = handed_handle_can(&out, "WriteProcessMemory") {
        assert!(!wrote, "別ドメインの子のメモリへ書き込めている: {out}");
    }

    // **契約の側**（対。`B-35`）: 絞りすぎていたら、呼び出し元は素の`CreateProcessW`と
    // 同じことができなくなる。これが無いと「跨ぐときは何も渡さない」実装でも上が緑になる。
    assert_eq!(
        handed_handle_can(&out, "GetExitCodeProcess"),
        Some(true),
        "終了コードを読めない。フックが組み立てた`PROCESS_INFORMATION`が使い物にならない: {out}"
    );
    assert_eq!(
        handed_handle_can(&out, "ResumeThread"),
        Some(true),
        "一時停止で頼んだ子を再開できない。**呼び出し元は永久に止まったままの子を掴む**: {out}"
    );
    assert_eq!(
        report_field(&out, "waited_ok").and_then(|v| v.as_bool()),
        Some(true),
        "返ったハンドルで待てない: {out}"
    );

    drop(case);
}

/// **T7（対の側。`B-35`）**: 同じドメインの子へは、今までどおり**書き込める**。
///
/// # これが無いと何が素通りするか
///
/// **「跨ぐときだけ絞る」ではなく「いつでも絞る」実装**が、T6だけでは緑のまま通る。
/// 絞ってしまうと、サンドボックスの中のビルドツールが自分の子を触れなくなる
/// ——`cargo`が`rustc`を殺せない、という形で**守る相手が居ない場所だけが壊れる**。
///
/// **ここが赤くなるのは正常な変化ではない。** 同一ドメインでも絞ると決めたのなら、
/// その決定を`plans/DESIGN-MAC-ENFORCEMENT.md` §10.1.2へ書いてからこのテストを畳むこと。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_same_domain_child_is_still_fully_reachable_through_the_handle_the_caller_gets_back() {
    let probe = super::super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();

    let (case, profile, caps) = setup_with_policy_and_transitions(
        "spawnd-s49-same",
        ChildProcessPolicy::Unrestricted,
        |_workspace| policy_with_edge(E2E_POLICY_DOMAIN, &probe_str),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let captured = workspace.join("s49-same-stdout.txt");

    let out = ask_daemon_as_a_hook(
        &case,
        &profile,
        &caps,
        &probe_str,
        &format!("\"{probe_str}\" --emit s49-same"),
        &captured,
        "not_needed",
        true,
    );

    assert_eq!(
        report_field(&out, "reply_kind").and_then(|v| v.as_str().map(str::to_string)),
        Some("spawned".to_string()),
        "自己ループの遷移が断られている: {out}"
    );
    assert_eq!(
        handed_handle_can(&out, "VirtualAllocEx"),
        Some(true),
        "**同じドメインの子へも触れなくなっている。** 跨いでいないのに絞った\
         ——ここで絞っても守る相手が居らず、サンドボックスの中のビルドツールが\
         自分の子を殺せなくなるだけである: {out}"
    );

    drop(case);
}

/// [P5.4a] Strict の印を付けた遷移先ドメイン（[`policy_with_strict_edge`]）。宣言を1件も持たない
/// ——用意できるのは宣言が無いドメインだけだからである（[`policy_with_cross_domain_edge`]と同じ理由）。
pub(super) const STRICT_DOMAIN: &str = "spawnd-strict-target";

/// **Strict の辺**（Strict の印が付いたドメインへ入り、**リテラルargv＋cwd宣言**で入力を固定した辺）を1本だけ持つ宣言。
/// 起こすには遷移先を用意する土台（[`setup_with_provisioned_domains`]）が要る。
///
/// # なぜ別ドメインへ入る辺なのか（P5.4a）
///
/// 固定値の書込可否（規則(i)・起こす直前の検査）と標準入力を断つ扱いは、決定66の追記で**Strict のドメインへ
/// 入る辺にだけ**掛かるようになった。かつてここは同じドメインへの自己ループで固定辺を作っていたが、自己ループは
/// 入る辺ではないので、今は何も掛からない（普通のモード）。
///
/// # 固定値に呼び出し元が書ける場所を含めてはいけない
///
/// 編集時検査は、リテラルargvの中の絶対パスがワークスペース配下なら**辺ごと拒否する**
/// （「固定値が指す先を呼び出し元が書き換えられるなら、引数を固定しても無意味」）。
/// だからこの辺の引数には**ワークスペースの中のパスを1つも書かない**——
/// 走ったことは`exit`の終了コードで確かめる。
///
/// **作業ディレクトリ（`cwd`）も同じ**（P5.4d。決定66の追記の束「呼び出し元が書ける場所なら断る」）。ワークスペースを
/// 渡すと`Hello`のグラフ組み立てが辺ごと拒否するので、呼び出し元が書けない場所（[`strict_cwd`]）を渡し、
/// 頼むときも同じ値を`--spawn-cwd`に渡す（宣言と違う作業ディレクトリは`cwd_mismatch`で断られる）。
pub(super) fn policy_with_strict_edge(
    exe: &str,
    command_line: &str,
    cwd: &std::path::Path,
) -> PolicyFile {
    let mut file = PolicyFile::default();
    let mut entry = PolicyDomain::new(E2E_POLICY_DOMAIN);
    entry.process = serde_json::from_value(serde_json::json!({
        "transitions": [{
            "exe": { "literal": exe },
            "argv": { "literal": command_line },
            "cwd": cwd.to_string_lossy(),
            "to": STRICT_DOMAIN,
        }]
    }))
    .expect("the strict transition declaration must parse");
    file.domains.push(entry);
    let mut target = PolicyDomain::new(STRICT_DOMAIN);
    target.strict = true;
    file.domains.push(target);
    file
}

/// [P5.4d] Strict の辺の作業ディレクトリにする、**呼び出し元が何の権利も持たない**ディレクトリ。
///
/// `C:\`直下に作るだけで、呼び出し元（セッションのpackage SID）へのACEも workspace capability も付けない
/// （`fixed_input_tests`の3で、同じ作り方の場所を起こす直前の検査が「書けない」と判定することを確かめている）。
/// 戻り値を生かしている間だけ在る。
pub(super) fn strict_cwd(label: &str) -> TestDirGuard {
    TestDirGuard::create(&format!("{label}-cwd"))
}

// **T8（BUG-161の本体）はP5.4bで`edge_stdio_tests.rs`へ移した。** かつてここに在った
// `a_fixed_edge_does_not_hand_the_callers_stdout_to_the_child`は「固定辺では標準入出力を3本まとめて断つ」を
// 測っていたが、決定66の追記でStrictの辺は標準入力だけを断ち、出力は辺の設定に従う形になった。
// Daemonが判定器の指示を読んでいること（BUG-161の要点）は、出力を捨てる辺・Strictの辺・広げる辺の3本が
// 対で見張る。
