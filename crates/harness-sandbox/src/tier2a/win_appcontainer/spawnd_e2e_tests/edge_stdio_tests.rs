//! [P5.4b] **辺ごとの出力の設定と Strict の印が、子へ渡る標準入出力を実機で変える**（決定66(3)(4)と追記。
//! `plans/position-domains/P5.md` の P5.4b）——**対で3本**。
//!
//! | # | 辺 | 標準入力 | 標準出力 | 何が壊れていたら赤になるか |
//! |---|---|---|---|---|
//! | 1 | 普通の辺（自己ループ）で**出力を捨てる**（`"output":"discard"`） | 渡す | **渡さない** | 捨てる設定を読んでいない（古い Daemon は欄を捨てて読む） |
//! | 2 | **広がる**普通の辺（遷移先の先に広い権限がある） | **渡す** | **渡す** | P5.3 までの「広げる辺には呼び出し元の標準入出力を渡さない」が残っている |
//! | 3 | **Strict の辺**（印の付いたドメインへ入る固定辺） | **渡さない** | **渡す** | 印を読んでいない（1本も断たない）／3本まとめて断っている（旧 BUG-161 の形） |
//!
//! **3本が互いの対になっている。** 1が無ければ「常に渡す」実装で2が緑になり、2が無ければ「常に断つ」実装で
//! 1と3が緑になる。3の標準出力は、**断つ範囲が広がりすぎていないこと**（Strict のログ分析が結果を返せること。
//! 決定66の追記の束の表）を見張る。
//!
//! # 標準入力が届いたかの測り方
//!
//! 「子が何を読んだか」でしか分からないので、目印を1行書いたファイルを呼び出し元（プローブ）が読み取りで開いて
//! 電文へ載せ、子に`set /p`で読ませて標準出力へ写させる。**標準出力の側と同じ受け皿で見る**ので、
//! 「読めなかった」と「書けなかった」は終了コードと標準出力の目印で切り分ける。
//!
//! 起こすのは`cmd.exe`（`/v:on`で遅延展開を有効にする）。PowerShellは**コンソールが無いと何も実行しない**ので
//! 使わない（`the_same_shell_declared_as_not_needing_a_console_silently_does_nothing`の§7.1）。

use harness_policy::policy_file::{PolicyDomain, PolicyFile};

use super::transition_acceptance_tests::{
    ask_daemon_as_a_hook, ask_daemon_as_a_hook_with_stdin, cmd_exe, STRICT_DOMAIN,
};
use super::*;

/// 子が標準入力から読む目印（この綴りが標準出力の受け皿に出れば、標準入力が子へ渡った）。
const FROM_STDIN: &str = "HARNESS-P54B-FROM-STDIN";
/// 子が自分で書く目印（標準出力が子へ渡ったことの印）。
const FROM_CHILD: &str = "HARNESS-P54B-FROM-CHILD";
/// 子の終了コード。**0以外にする**——0は「走った」とも「何も起きなかった」とも読める。
const EXIT_CODE: u64 = 43;

/// 標準入力を1行読み、自分の目印とその行を書いて、決めた終了コードで終わるコマンドライン。
///
/// `set /p`は標準入力が無ければ変数を立てないので、そのとき`!X!`は空になる（目印は出ない）。
fn echo_stdin_command_line(cmd: &str) -> String {
    format!(r#""{cmd}" /v:on /c set /p X= & echo {FROM_CHILD} & echo !X! & exit {EXIT_CODE}"#)
}

/// `FROM_STDIN`を1行書いたファイルを作って返す。
fn write_stdin_file(workspace: &std::path::Path) -> std::path::PathBuf {
    let path = workspace.join("edge-stdio-stdin.txt");
    std::fs::write(&path, format!("{FROM_STDIN}\r\n")).expect("write the stdin file");
    path
}

/// 子が走ったことを終了コードで確かめる（**出力が無いことと起きなかったことを分ける**）。
fn assert_the_child_ran(out: &str, what: &str) {
    assert_eq!(
        reply_kind(out).as_deref(),
        Some("spawned"),
        "{what}: 要求が拒否された（`cwd_mismatch`なら理由に宣言値と実値が載る）: {out}"
    );
    assert_eq!(
        report_field(out, "child_exit_code").and_then(|v| v.as_u64()),
        Some(EXIT_CODE),
        "{what}: 子が走っていない（か、終了コードを読めていない）: {out}"
    );
}

/// 出力を捨てる自己ループ辺を1本だけ持つ宣言。
fn policy_with_a_discarding_edge(exe: &str) -> PolicyFile {
    let mut file = PolicyFile::default();
    let mut entry = PolicyDomain::new(E2E_POLICY_DOMAIN);
    entry.process = serde_json::from_value(serde_json::json!({
        "transitions": [{
            "exe": { "literal": exe },
            "argv": { "any": true },
            "to": E2E_POLICY_DOMAIN,
            "output": "discard",
        }]
    }))
    .expect("the discarding transition declaration must parse");
    file.domains.push(entry);
    file
}

/// **1（禁止側）**: 出力を捨てる辺では、呼び出し元の標準出力ハンドルが子へ渡らない。
///
/// 対になるのは出力を返す既存の腕
/// （`the_callers_own_stdout_handle_receives_the_childs_output_and_the_returned_handle_can_be_waited_on`）で、
/// あちらは**同じ受け皿に出力が落ちてくること**を固定している。違うのは`policy.json`の`output`の1語だけである。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn an_output_discarding_edge_does_not_hand_the_callers_stdout_to_the_child() {
    let cmd = cmd_exe();
    let (case, profile, caps) = setup_with_policy_and_transitions(
        "spawnd-p54b-discard",
        ChildProcessPolicy::Unrestricted,
        |_workspace| policy_with_a_discarding_edge(&cmd),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let captured = workspace.join("discarding-edge-stdout.txt");

    let out = ask_daemon_as_a_hook(
        &case,
        &profile,
        &caps,
        &cmd,
        &format!(r#""{cmd}" /c echo {FROM_CHILD} & exit {EXIT_CODE}"#),
        &captured,
        "not_needed",
        false,
    );

    assert_the_child_ran(&out, "出力を捨てる辺");
    let text = std::fs::read_to_string(&captured).unwrap_or_default();
    assert!(
        !text.contains(FROM_CHILD),
        "**出力を捨てる辺なのに、呼び出し元が渡した受け皿へ子の出力が落ちている。** Daemonが辺の`output`を\
         読んでいない（古いバイナリは欄そのものを知らないので、プロトコルの版で止める）: file={} content={text:?} {out}",
        captured.display()
    );

    drop(case);
}

/// 入口 → `mid` → `wide` の鎖を持つ宣言。**入口から`mid`への辺が「広げる」**——`mid`自身は何も宣言しないが、
/// その先の`wide`が読み取りを宣言しているので、到達閉包（§19.3.4）で数えると入口は`mid`を通してその読み取りを使える。
///
/// `wide`は用意できない（宣言を持つドメインには、このセッションで許可が付いていないと実体を作らない）。
/// **それでよい**——この腕が頼むのは入口→`mid`の辺で、`wide`へは誰も遷移しない。用意できなかった理由は
/// 起動時の警告に出る（`domain_provision`の`skipped`）。
fn policy_with_a_widening_edge(exe: &str) -> PolicyFile {
    let mut file = PolicyFile::default();
    let mut entry = PolicyDomain::new(E2E_POLICY_DOMAIN);
    entry.process = serde_json::from_value(serde_json::json!({
        "transitions": [{ "exe": { "literal": exe }, "argv": { "any": true }, "to": "p54b-mid" }]
    }))
    .expect("the widening transition declaration must parse");
    file.domains.push(entry);
    let mut mid = PolicyDomain::new("p54b-mid");
    mid.process = serde_json::from_value(serde_json::json!({
        "transitions": [{ "exe": { "literal": exe }, "argv": { "any": true }, "to": "p54b-wide" }]
    }))
    .expect("the onward transition declaration must parse");
    file.domains.push(mid);
    let mut wide = PolicyDomain::new("p54b-wide");
    wide.fs.read.push("C:/Users/x/p54b-secret/**".to_string());
    file.domains.push(wide);
    file
}

/// **2（許可側）**: 広がる辺では、呼び出し元の標準入力**と**標準出力が子へ渡る（決定66(3)(4)。既定）。
///
/// # これが P5.3 で未測定だったもの
///
/// P5.3 は「固定していない、かつ広げない」辺でしか標準入出力を渡しておらず（`inherit_handles`の式を据え置いた）、
/// **広げる辺の子は呼び出し元から何も受け取れなかった**。守る線を子のドメインの権限へ移した決定66では、
/// 普通の辺は向きに関わらず渡す。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_widening_edge_hands_the_callers_stdin_and_stdout_to_the_child() {
    let cmd = cmd_exe();
    let (case, profile, caps) = setup_with_provisioned_domains(
        "spawnd-p54b-widening",
        ChildProcessPolicy::Unrestricted,
        |_workspace| policy_with_a_widening_edge(&cmd),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let captured = workspace.join("widening-edge-stdout.txt");
    let stdin_file = write_stdin_file(&workspace);

    let out = ask_daemon_as_a_hook_with_stdin(
        &case,
        &profile,
        &caps,
        &cmd,
        &echo_stdin_command_line(&cmd),
        &captured,
        Some(&stdin_file),
        "not_needed",
        false,
    );

    assert_the_child_ran(&out, "広げる辺");
    let text = std::fs::read_to_string(&captured).unwrap_or_default();
    assert!(
        text.contains(FROM_CHILD),
        "**広げる辺の子へ、呼び出し元の標準出力が渡っていない。** P5.3 までの「広げる辺には渡さない」が\
         残っている（決定66(4)の既定は返す）: file={} content={text:?} {out}",
        captured.display()
    );
    assert!(
        text.contains(FROM_STDIN),
        "**広げる辺の子へ、呼び出し元の標準入力が渡っていない。** 決定66(3)は普通の辺で標準入力を渡す\
         （断つのは Strict の辺だけ）: file={} content={text:?} {out}",
        captured.display()
    );

    drop(case);
}

/// **3（禁止側と許可側を1本で）**: Strict の辺では標準入力が断たれ、**標準出力は渡る**。
///
/// # 断つのは標準入力だけである
///
/// 固定argvのシェルは、標準入力が端末でなければ**そこからコマンドを読んで実行する**ので、引数を固定しても
/// 呼び出し元がスクリプトを流し込めばその辺の権限で任意コードが走る（BUG-161）。一方、出力は辺ごとの設定に従う
/// ——Strict の用途（機密のログを固定した分析スクリプトで集計する）は**結果を返すのが目的**だからである
/// （決定66の追記の束の表）。旧 BUG-161 の修正は3本まとめて断っており、その代償をここで解いている。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_strict_edge_cuts_the_callers_stdin_but_still_returns_the_childs_output() {
    let cmd = cmd_exe();
    let command_line = echo_stdin_command_line(&cmd);
    let declared = command_line.clone();
    let (case, profile, caps) = setup_with_provisioned_domains(
        "spawnd-p54b-strict",
        ChildProcessPolicy::Unrestricted,
        |workspace| {
            super::transition_acceptance_tests::policy_with_strict_edge(&cmd, &declared, workspace)
        },
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let captured = workspace.join("strict-edge-stdout.txt");
    let stdin_file = write_stdin_file(&workspace);

    let out = ask_daemon_as_a_hook_with_stdin(
        &case,
        &profile,
        &caps,
        &cmd,
        &command_line,
        &captured,
        Some(&stdin_file),
        "not_needed",
        false,
    );

    assert_the_child_ran(&out, format!("Strict の辺（{STRICT_DOMAIN}へ入る）").as_str());
    let text = std::fs::read_to_string(&captured).unwrap_or_default();
    assert!(
        text.contains(FROM_CHILD),
        "**Strict の辺で、子の出力まで断たれている。** 断つのは標準入力だけである（決定66の追記の束の表。\
         旧 BUG-161 の「3本まとめて断つ」へ戻っている）: file={} content={text:?} {out}",
        captured.display()
    );
    assert!(
        !text.contains(FROM_STDIN),
        "**Strict の辺なのに、呼び出し元の標準入力が子へ渡っている。** 引数を固定しても、標準入力から\
         コマンドを流し込めばその辺の権限で任意コードが走る（BUG-161）: file={} content={text:?} {out}",
        captured.display()
    );

    drop(case);
}
