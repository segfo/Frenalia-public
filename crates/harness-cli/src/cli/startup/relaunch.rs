//! `/workspace <path>`（`harness_tui::RunOutcome::Relaunch`）の再起動。
//!
//! ワークスペースの切替をプロセス内で行わない理由は`RunOutcome`のdocが持つ。ここは
//! 「同じ引数のまま、別のワークスペースで起動し直す」という**それだけ**を実装する。
//!
//! ## 置き場所が末尾でなければならない
//!
//! 呼ぶのは[`super::run_agent::stage_run_agent`]の**最後**——MCP停止 → WFP撤収 →
//! policy-learn撤収 → `session_profile::end_session` を全部通した後である。ここより前で
//! 起こすと、それらのteardownを迂回した上に、親がまだ握っている資源（モードmutex・
//! loopback exemption・WFPフィルタ）と子が衝突する。
//!
//! ## 親の終了を待たせる（`--wait-for-pid`）
//!
//! Windowsに`exec`（自プロセスの置換）は無いので、子を起こして親が終わる形になる。ところが
//! 名前付きmutex（`workspace_ledger::begin_workspace_mode`・CoWのセッションマーカー）は
//! **プロセス寿命に紐付いている**ため、親が消える前に子がpreflightへ入ると
//! 「同じworkspaceを別モードで開いている」と誤判定されて起動を拒否され得る（同じ
//! ワークスペースへ`/workspace`した場合に確実に起きる）。子は`--wait-for-pid <親>`で
//! 親ハンドルの終了を待ってからStage4へ進む（`bug-pattern-rules` B-17: 生存判定は
//! OSオブジェクトへ預ける。スリープで誤魔化さない）。

use std::ffi::OsString;
use std::path::Path;

/// 再起動時に**必ず落として付け直す**引数。値を取るものは`--flag value`と`--flag=value`の
/// 両形を落とす。
///
/// - `--cwd`: 移動先で付け直す（これが再起動の目的）
/// - `--resume` / `--continue` / `--fork-session`: 移動先のセッションを引き継げない
///   （セッションファイルはワークスペースごと）。代わりに`--resume`（引数なし＝ピッカー）を
///   足して、移動先のセッション一覧から選ばせる
/// - `--wait-for-pid`: 前回の再起動の残骸。二重に付けない
const REPLACED_FLAGS: &[(&str, bool)] = &[
    ("--cwd", true),
    ("--resume", true),
    ("--continue", false),
    ("--fork-session", false),
    ("--wait-for-pid", true),
];

/// 元のargv（`argv[0]`を含まない）から、移動先で起動するための引数列を組み立てる。
///
/// **純粋関数**にしてあるのは、フラグ名が文字列リテラルの複製だからである（`Cli`の
/// `#[arg(long = "…")]`とコンパイラが結び付けてくれない、`bug-pattern-rules` B-05）。
/// テストは書き換え結果を**実物の`Cli::try_parse_from`へ食わせて**検算する——フラグ名が
/// 変わればそのテストが落ちる。
pub(super) fn relaunch_args(
    original: &[OsString],
    workspace: &Path,
    parent_pid: u32,
) -> Vec<OsString> {
    let mut out: Vec<OsString> = Vec::with_capacity(original.len() + 5);
    let mut skip_next = false;
    for arg in original {
        if skip_next {
            skip_next = false;
            continue;
        }
        let text = arg.to_string_lossy();
        let mut replaced = false;
        for (flag, takes_value) in REPLACED_FLAGS {
            if text == *flag {
                // `--resume`は値省略可（`num_args = 0..=1`）なので、次が値かどうかは
                // 「`-`で始まらないか」で見る。ここを無条件に飛ばすと、`--resume`の直後に
                // 来た別のフラグまで落ちる。
                skip_next = *takes_value
                    && original
                        .iter()
                        .skip_while(|a| *a != arg)
                        .nth(1)
                        .is_some_and(|next| !next.to_string_lossy().starts_with('-'));
                replaced = true;
                break;
            }
            if *takes_value && text.starts_with(&format!("{flag}=")) {
                replaced = true;
                break;
            }
        }
        if !replaced {
            out.push(arg.clone());
        }
    }
    out.push(OsString::from("--cwd"));
    out.push(workspace.as_os_str().to_os_string());
    // 引数なし`--resume`＝移動先のセッションピッカーを出す（`Cli`の`default_missing_value`）。
    out.push(OsString::from("--resume"));
    out.push(OsString::from("--wait-for-pid"));
    out.push(OsString::from(parent_pid.to_string()));
    out
}

/// 移動先のワークスペースで自分自身を起動し直す。**この関数から戻ったら親は即座に終了する**
/// （子は`--wait-for-pid`でそれを待っている）。
///
/// 失敗しても`Err`を返すだけで、呼び出し側はそのまま普通に終了する——再起動できないことと、
/// 端末を壊すことは別である（`bug-pattern-rules` B-10: 理由は必ず出す）。
pub(super) fn relaunch_in(workspace: &Path) -> Result<(), String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("could not resolve the harness executable path: {e}"))?;
    let original: Vec<OsString> = std::env::args_os().skip(1).collect();
    let args = relaunch_args(&original, workspace, std::process::id());
    std::process::Command::new(&exe)
        .args(&args)
        .current_dir(workspace)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("could not relaunch {}: {e}", exe.display()))
}

/// 子側。`--wait-for-pid`で指定された親プロセスの終了を待つ（上限[`WAIT_TIMEOUT`]）。
///
/// 待てなかった場合も**先へ進む**。親が既に消えている（ハンドルを開けない）のが正常系で、
/// タイムアウトした場合はpreflightのモード衝突チェックが自分で断るので、ここで起動を
/// 止める必要が無い（止めると「親が固まると子も起動できない」を新設することになる）。
pub(crate) fn wait_for_parent_exit(pid: u32) {
    #[cfg(windows)]
    if !harness_sandbox::win_common::wait_for_process_exit(pid, WAIT_TIMEOUT_MS) {
        eprintln!(
            "warning: the previous harness process (pid {pid}) is still running after \
             {WAIT_TIMEOUT_MS}ms; continuing anyway (startup may refuse if it still holds this \
             workspace)"
        );
    }
    // `/workspace`はTUI専用で、TUIはWindows以外でも動く。非Windowsでは
    // `begin_workspace_mode`（Tier2a、Windows専用）が無いので待つ必要が無い。
    #[cfg(not(windows))]
    let _ = pid;
}

const WAIT_TIMEOUT_MS: u32 = 10_000;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{sandbox_choice_of, Cli, SandboxChoiceArg};
    use clap::Parser;
    use harness_core::SandboxChoice;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn strings(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    /// 書き換え結果を**実物のパーサへ食わせて**検算する。フラグ名を変えたのに
    /// `REPLACED_FLAGS`を直し忘れたら、ここが落ちる（B-05）。
    fn parsed(args: &[OsString]) -> Cli {
        let mut argv = vec![OsString::from("harness")];
        argv.extend(args.iter().cloned());
        Cli::try_parse_from(argv).expect("rewritten argv must still parse")
    }

    #[test]
    fn the_new_workspace_and_a_picker_resume_are_always_appended() {
        let out = relaunch_args(&os(&[]), Path::new(r"C:\ws\next"), 4242);
        assert_eq!(
            strings(&out),
            vec!["--cwd", r"C:\ws\next", "--resume", "--wait-for-pid", "4242"]
        );
        let cli = parsed(&out);
        assert_eq!(cli.cwd.as_deref(), Some(Path::new(r"C:\ws\next")));
        // 値なし`--resume`＝ピッカーを出す（`default_missing_value = ""`）。
        assert_eq!(cli.resume.as_deref(), Some(""));
        assert_eq!(cli.wait_for_pid, Some(4242));
    }

    /// 元の`--cwd`/`--resume`は落として付け直す（両方付くと後勝ちに頼ることになる）。
    #[test]
    fn the_previous_workspace_and_session_selection_are_dropped() {
        let out = relaunch_args(
            &os(&["--cwd", r"C:\ws\old", "--resume", "session-abc", "--staged"]),
            Path::new(r"C:\ws\next"),
            7,
        );
        let text = strings(&out);
        assert!(!text.contains(&r"C:\ws\old".to_string()), "{text:?}");
        assert!(!text.contains(&"session-abc".to_string()), "{text:?}");
        assert!(text.contains(&"--staged".to_string()), "{text:?}");
        let cli = parsed(&out);
        assert_eq!(cli.cwd.as_deref(), Some(Path::new(r"C:\ws\next")));
        assert!(cli.staged);
    }

    /// [⑤'] **遷移MACの強制は、`/workspace`で移動しても落ちない。**
    ///
    /// 落ちると、移動先のセッションだけが**黙って無防備になる**——画面には何も出ず、
    /// 「なぜかこの回だけ拒否されない」としてしか現れない。`--staged`と同じ形の1本だが、
    /// 落ちたときに失われるものがセキュリティ境界なので別に固定する。
    #[test]
    fn enforcing_transitions_survives_a_workspace_move() {
        let out = relaunch_args(
            &os(&["--cwd", r"C:\ws\old", "--sandbox", "tier2a", "--enforce-transitions"]),
            Path::new(r"C:\ws\next"),
            7,
        );
        assert!(
            strings(&out).contains(&"--enforce-transitions".to_string()),
            "{:?}",
            strings(&out)
        );
        assert!(parsed(&out).enforce_transitions);
    }

    /// `--resume`は値を省略できる（`num_args = 0..=1`）。直後に別のフラグが来ているとき、
    /// それを「`--resume`の値」とみなして落としてはいけない。
    #[test]
    fn a_valueless_resume_does_not_swallow_the_next_flag() {
        let out = relaunch_args(
            &os(&["--resume", "--sandbox", "tier2a-cow"]),
            Path::new(r"C:\ws\next"),
            7,
        );
        assert!(
            strings(&out).contains(&"--sandbox".to_string()),
            "{:?}",
            strings(&out)
        );
        assert_eq!(parsed(&out).sandbox, Some(SandboxChoiceArg::Tier2aCow));
    }

    #[test]
    fn the_equals_form_is_dropped_too() {
        let out = relaunch_args(
            &os(&[
                r"--cwd=C:\ws\old",
                "--continue",
                "--fork-session",
                "--sandbox=tier1",
            ]),
            Path::new(r"C:\ws\next"),
            7,
        );
        let text = strings(&out);
        assert!(!text.iter().any(|a| a.contains(r"C:\ws\old")), "{text:?}");
        assert!(!text.contains(&"--continue".to_string()), "{text:?}");
        assert!(!text.contains(&"--fork-session".to_string()), "{text:?}");
        assert!(text.contains(&"--sandbox=tier1".to_string()), "{text:?}");
        let cli = parsed(&out);
        assert!(!cli.continue_session);
        assert_eq!(cli.sandbox, Some(SandboxChoiceArg::Tier1));
    }

    /// **`--sandbox`の綴りと値の集合を、実物のパーサで固定する。**
    ///
    /// `harness_core::SandboxChoice`の各variantが`--sandbox <値>`として通ること、
    /// その値が`value_label()`と**同じ綴り**であること、`vm`が`tier3`の別名であること、
    /// **値を書かなければ`OsDefault`になる**こと、そして**未知の値がパースエラーになる**ことを
    /// まとめて測る。
    ///
    /// 綴りは`harness-core`側（エラーメッセージ用）と`SandboxChoiceArg`側（CLI表面）の
    /// 2箇所にあり、コンパイラは結び付けてくれない（`bug-pattern-rules` B-05）。
    /// 未知値の側を測るのは、`--require-sandbox`が打ち間違いを黙って`write-containment`へ
    /// 落としていた欠陥（BUG-114）と同じ轍を踏まないためである——「全部受理する」実装でも
    /// 許可側のテストだけなら緑になる。
    ///
    /// **`auto`が禁止側に入っているのが今回の改訂点**（D-72）。廃止した綴りが黙って
    /// 受理され続けると、打った人は「既定に戻した」つもりで別の意味になる。
    #[test]
    fn every_sandbox_choice_has_a_cli_spelling_and_unknown_values_are_rejected() {
        for choice in SandboxChoice::ALL {
            let Some(label) = choice.value_label() else {
                // **綴りが無いのは`OsDefault`だけ**——`--sandbox`を書かなかった状態で、
                // 下で別に測る。`spelling_of`が`None`を返すことと突き合わせておく。
                assert_eq!(choice, SandboxChoice::OsDefault);
                assert_eq!(SandboxChoiceArg::spelling_of(choice), None);
                continue;
            };
            let mut full = vec![OsString::from("harness")];
            full.extend(os(&["--sandbox", label]));
            let cli = Cli::try_parse_from(full).unwrap_or_else(|e| {
                panic!("--sandbox {label} must parse (value_label and the ValueEnum spelling drifted): {e}")
            });
            assert_eq!(
                sandbox_choice_of(cli.sandbox),
                choice,
                "--sandbox {label} parsed into a different choice"
            );
            assert_eq!(
                SandboxChoiceArg::spelling_of(choice),
                cli.sandbox,
                "--sandbox {label} does not round-trip through spelling_of"
            );
        }

        // `vm`は旧`--vm-sandbox`からの別名。
        let cli = Cli::try_parse_from(os(&["harness", "--sandbox", "vm"])).unwrap();
        assert_eq!(sandbox_choice_of(cli.sandbox), SandboxChoice::Tier3);

        // **値を書かなければ「そのOSの既定Tierを要求する」**（D-72。旧`auto`の位置）。
        let cli = Cli::try_parse_from(os(&["harness"])).unwrap();
        assert_eq!(cli.sandbox, None);
        assert_eq!(sandbox_choice_of(cli.sandbox), SandboxChoice::OsDefault);

        // **禁止側**: 打ち間違いも、**廃止した綴り**も、黙って既定へ落ちずパースエラーになる。
        for bogus in ["auto", "tier2", "cow", "tier2a_cow", "TIER1x", "warm"] {
            assert!(
                Cli::try_parse_from(os(&["harness", "--sandbox", bogus])).is_err(),
                "--sandbox {bogus} must be a parse error, not a silent fallback"
            );
        }
    }

    /// **`--require-sandbox`の綴りと値の集合を、実物のパーサで固定する**（BUG-114の修正）。
    ///
    /// 打ち間違い（`confidentail`）が**パースエラーになる**側と、正しい3通り（フラグ無し・
    /// 値省略・`=confidential`）が**通る**側を対で測る。禁止側だけを測ると「全部拒否する」
    /// 実装でも緑になり、許可側だけを測ると**元の欠陥そのもの**（全部受理して弱い方へ落とす）が
    /// 緑になる（`test-logic-rules`「禁止側と許可側を対にする」）。
    ///
    /// `match`を`RequireSandbox`の全variantに対して書いてあるのは検問である——variantを
    /// 足したら、ここが非網羅になってコンパイルが落ちる（`bug-pattern-rules` B-05）。
    #[test]
    fn every_require_sandbox_level_has_a_cli_spelling_and_typos_are_rejected() {
        use harness_core::RequireSandbox;

        for level in [
            RequireSandbox::None,
            RequireSandbox::WriteContainment,
            RequireSandbox::Confidential,
        ] {
            // **綴りが無いのは「フラグを打たない」ことで表す段だけ**である。
            let spelling: Option<&str> = match level {
                RequireSandbox::None => None,
                RequireSandbox::WriteContainment => Some("write-containment"),
                RequireSandbox::Confidential => Some("confidential"),
            };
            let argv = match spelling {
                None => vec![OsString::from("harness")],
                Some(value) => os(&["harness", "--require-sandbox", value]),
            };
            let cli = Cli::try_parse_from(argv)
                .unwrap_or_else(|e| panic!("--require-sandbox {spelling:?} must parse: {e}"));
            assert_eq!(
                crate::cli::setup::parse_require_sandbox(cli.require_sandbox),
                level,
                "--require-sandbox {spelling:?} resolved to a different level"
            );
        }

        // 値省略（`--require-sandbox`単体）は「書込拘束以上」（`default_missing_value`）。
        let cli = Cli::try_parse_from(os(&["harness", "--require-sandbox"])).unwrap();
        assert_eq!(
            crate::cli::setup::parse_require_sandbox(cli.require_sandbox),
            RequireSandbox::WriteContainment
        );

        // **禁止側**: 打ち間違いは黙って`write-containment`へ落ちず、パースエラーになる。
        // かつてはこれが全部通り、**要求より弱い保証で起動していた**（BUG-114）。
        for bogus in ["confidentail", "write_containment", "none", "tier2a"] {
            assert!(
                Cli::try_parse_from(os(&["harness", "--require-sandbox", bogus])).is_err(),
                "--require-sandbox {bogus} must be a parse error, not a silent downgrade"
            );
        }
    }

    /// **`--policy-learn`は裸で打てて、`=false`で打ち消せる**（§4.9 対象3）。
    ///
    /// 3つの状態を区別する必要がある——「打たなかった」（設定へフォールバック）・
    /// 「打った」（有効）・「偽で打った」（設定が有効でもこの実行だけ無効）。
    /// 裸の形は**docが以前から案内していたのに必ずclapエラーになっていた**ので、
    /// 実物のパーサで固定する。
    #[test]
    fn policy_learn_can_be_bare_or_explicitly_false() {
        let cli = Cli::try_parse_from(os(&["harness"])).unwrap();
        assert_eq!(cli.policy_learn, None, "打たなければ設定側へ委ねる");

        let cli = Cli::try_parse_from(os(&["harness", "--policy-learn"])).unwrap();
        assert_eq!(cli.policy_learn, Some(true), "裸で打てること");

        let cli = Cli::try_parse_from(os(&["harness", "--policy-learn=false"])).unwrap();
        assert_eq!(cli.policy_learn, Some(false), "明示的に無効化できること");

        // 裸の`--policy-learn`が次のフラグを値として吸わないこと（`--resume`と同じ論点）。
        let cli = Cli::try_parse_from(os(&["harness", "--policy-learn", "--staged"])).unwrap();
        assert_eq!(cli.policy_learn, Some(true));
        assert!(cli.staged);
    }

    /// 2回続けて`/workspace`しても`--wait-for-pid`が積み上がらない。
    #[test]
    fn wait_for_pid_is_replaced_not_appended() {
        let once = relaunch_args(&os(&[]), Path::new(r"C:\a"), 1);
        let twice = relaunch_args(&once, Path::new(r"C:\b"), 2);
        let text = strings(&twice);
        assert_eq!(text.iter().filter(|a| *a == "--wait-for-pid").count(), 1);
        assert_eq!(parsed(&twice).wait_for_pid, Some(2));
    }
}
