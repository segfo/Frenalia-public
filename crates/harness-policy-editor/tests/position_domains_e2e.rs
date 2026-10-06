//! 位置ごとのドメイン（決定65）の昇格E2E。**エディタがパス1の記録から位置ごとに書いた辺で、
//! `harness.exe --enforce-transitions`が記録した連鎖だけを通すか**を、本番の経路で確かめる
//! （`plans/position-domains/P4.md`の Task P4.8）。**管理者権限が要る**（パス1の収集器が張る ETW の
//! リアルタイムセッションと、Tier2a の準備が付ける祖先 traverse のため）。
//!
//! 実行: `dev-elevated-run.exe e2e-policy-editor-position-domains`。事前に
//! `cargo build --workspace`（収集器`harness-policy-learnd.exe`ほか）と
//! `cargo build -p harness-cli --features e2e-mock`（模擬プロバイダつきの`harness.exe`）。
//! **後から`cargo build --workspace`を撃つと e2e-mock でない`harness.exe`で上書きされる**ので、
//! 撃つ直前に[`harness_exe`]が`--help`に`--mock-turns`があるかを確かめ、無ければ落ちる（`B-09`）。
//!
//! # ユーザーの例と、この試験の連鎖
//!
//! ```text
//! ユーザーの例（決定65）:  cmd → pwsh → calc        ／ cmd → pwsh → mspaint
//! この試験:               シェル → 中の段 → hostname ／ シェル → 中の段 → whoami
//! ```
//!
//! - **1段目は入口のドメインのシェルそのもの**である（ユーザーの例の`cmd`に当たる）。記録では
//!   パス1の`pwsh`、強制では`harness.exe`のシェル（中の段と同じ候補から preflight が起こして選ぶ）で、どちらも
//!   入口のドメイン`workspace-shell`にいる。根の実行ファイルは位置の鍵に入らない
//!   （位置の鍵は〔親のドメイン, exe〕、決定65 Q1）ので、根の綴りが違っても同じ位置になる
//! - `calc`・`mspaint`は Windows 11 ではストアアプリで、遷移の強制を積んだ構成では起こせない
//!   （`Startable::NotThroughTheAppModel`）。System32 の`hostname.exe`・`whoami.exe`で代える。
//!   どちらもファイルの候補が出ない（子が親の持たないファイルを触らない）ので、鎖は広げる遷移にならない
//!   （書いた当時の決定65(6)の暫定「広がる位置は P5 まで書けない」は、決定66で外した。P5.3）
//! - **中の段は、ストアアプリでない`pwsh`があればそれ、無ければ`powershell.exe`（System32 の 5.1）**である
//!   （[`middle_shell`]。ドメインの名前は葉名で`pwsh`か`powershell`）。選ぶのは`harness_sandbox`の
//!   `shell_candidates_from`を生成禁止（`ChildProcessPolicy::Restricted`）で呼んだ候補の先頭で、`harness.exe`が
//!   強制の下で自分のシェルの候補を作るのと**同じ判断**である（写さない、`B-05`）。ストアアプリの`pwsh`
//!   （`WindowsApps`の実行エイリアス／MSIX の実体）は生成禁止を積んだ子の中から起こせない
//!   （`plans/mac-spike/RESULTS.md` §S62）ので候補から外れ、外したことを出力に出す。MSI・zip で入れた`pwsh`
//!   （`C:\Program Files\PowerShell\7\pwsh.exe`等）は普通の exe なので中の段にできるはずだが、
//!   **この開発機には無く、その枝は一度も撃っていない**（2026-10-05）
//! - **`cmd.exe`は中の段に使えない（2026-10-05 の実測）。** 入口のドメインから`cmd.exe`を起こすところまでは
//!   通るのに（検算の腕`control-one-hop`の前身がそれを確かめた）、その`cmd.exe`が次のプログラムを
//!   起こそうとすると**Spawn Daemon の記録（待ち行列・標準エラー）に何も残らないまま**`アクセスが拒否されました`で
//!   終わった。`git.exe`が次の段を頼める（`tier2a_e2e.rs`の`the_git_config_trap_chain_is_judged_across_domains`）
//!   のと食い違うので、**`cmd.exe`に固有の未解明**として`docs/bugs/BUG-230.md`へ残し、この試験は
//!   `cmd.exe`を連鎖に入れない——入れると、位置ごとのドメインの良し悪しではなくその未解明を測ることになる
//! - 辺は「任意の引数」（決定65 Q2）なので、引数の綴りは判定に効かない。記録と強制で**同じ行**を撃つ
//!
//! # 何を確かめるか（`B-35`: 通る側と断る側を同じ回で）
//!
//! 1. 記録（パス1を2回）: 各記録の`process-audit.jsonl`に「根 → 中の段 → 葉」の鎖がある
//!    （無ければ収集の失敗として落とす。後の判定の前提）
//! 2. 承認: エディタの画面（`App`）で観測のタブを開き、鎖の行を`Space`→`a`→`y`。2回目の記録では
//!    1回目に書いた辺が`ExistingEdge`として引かれ（生成物が入力へ戻る一周、`B-28`）、葉の辺だけを書く。
//!    `policy.json`の辺がちょうど3本になる
//! 3. 強制（検算1本＋通る2本＋断る3本。各腕の前に`pending.jsonl`を消す）:
//!
//! | 腕 | 行が起こす連鎖 | 期待 |
//! |---|---|---|
//! | 検算 | シェル → 中の段（その中で終わる） | 印が返る・拒否0件（**1段目が通ることを先に確かめる**） |
//! | 通る1 | シェル → 中の段 → hostname | 葉の出力が届き、拒否0件 |
//! | 通る2 | シェル → 中の段 → whoami | 同上 |
//! | 断る1 | シェル → 中の段 → 中の段 → whoami | 中の段のドメインから中の段の実行ファイルを`no_matching_edge`で断る（ユーザーの例の`pwsh→pwsh`） |
//! | 断る2 | シェル → 中の段 → notepad | 中の段のドメインから`notepad.exe`を断る（記録に無いプログラム） |
//! | 断る3 | シェル → hostname | `workspace-shell`から`hostname.exe`を断る（**同じプログラムでも位置が違えば断る**） |
//!
//! 断る腕の遷移元が中の段のドメインであること自体が、中の段がそのドメインで動いていた証拠になる。
//!
//! 4. 後始末: `harness.exe`が作った AppContainer プロファイル（セッションの入れ物と遷移先ドメインの入れ物）が
//!    撃つ前より増えていない（`harness_sandbox::tier2a::session_profile::token_of_profile`で族を見分ける）
//!
//! # 写した部品（`B-05`: 写しが片方だけ変わったら気付けるよう、写し元を書く）
//!
//! この試験は別クレートの`tests/`なので、`harness-cli`の試験の補助を呼べない。次を最小限で写した。
//!
//! - 模擬応答の1ターン（[`tool_use_turn`]・[`end_turn`]）: `crates/harness-cli/tests/tier2a_e2e.rs`の
//!   `tool_use_turn`（79行）・`end_turn`（100行）・`run_shell_script_turns`（132行）
//! - `harness.exe`の起こし方（[`run_harness`]）: 同`run_harness_driven`（301行）の`Driver::Mock`の引数の並びと
//!   `HARNESS_TEST_RECALL_DATA_ROOT`、`scripted_shell_rule_args`（149行。撃つ行を`--allow run_shell:<行>`に）
//! - 出力の読み方: 同`Outcome::first_tool_result`（513行。`tool_calls[0].result`だけを見る＝BUG-137）・
//!   `assert_prompt_sane`（461行。強制が効いている回にだけモデルへ見える`can_run_program`）
//! - 待ち行列の読み方: 同`run_arm_collecting_denials_in`（9235行。撃つ前に消す・あふれと読めない行で無効）
//! - 記録の起こし方: `tests/record_e2e.rs`（`record --workspace <ws> --cwd <ws> --limit 0 -- <行>`と
//!   `HARNESS_ALLOW_USER_WRITABLE_ELEVATED_HELPERS=1`）
//! - 中の段のシェルを探す場所（[`middle_shell`]の`which::which("pwsh")`と`SystemRoot`）:
//!   `harness-sandbox`の`win_appcontainer/spawn.rs`の`shell_candidates`。**どれを外し、どれを最後に積むかの
//!   判断は写さず**、公開した`shell_candidates_from`を呼ぶ
//!
//! # ワークスペースの置き場
//!
//! `C:\harness-e2e\policy-editor-position-domains`（`%TEMP%`は使わない。Tier2a の準備がプロファイル全階層の
//! traverse を恒久付与するため——`tier2a_e2e.rs`のモジュール doc）。緑なら消し、赤なら調査のため残す。

#![cfg(windows)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use harness_core::{BlockKind, CompletionRequest, StopReason, StreamEvent, Usage};
use harness_policy::policy_file::{self, ENTRY_DOMAIN};
use harness_policy::position_domains::PositionSource;
use harness_policy::process_event::{parse_process_audit, ProcessInstance, PROCESS_AUDIT_FILE};
use harness_policy::transition::TransitionDenial;
use harness_policy_editor::position_view::EdgeVerdict;
use harness_policy_editor::tui::state::{App, Confirm};
use harness_sandbox::tier2a::spawnd::client::DAEMON_STDERR_ENV;
use harness_sandbox::tier2a::spawnd::transitions::{pending_path, read_from, PendingRecord};
use harness_sandbox::tier2a::spawnd::{ChildProcessPolicy, DenyReason};
use harness_sandbox::tier2a::win_appcontainer::shell_candidates_from;

/// この試験の置き場の根（`tier2a_e2e.rs`の`CASE_ROOT`と同じ）。
const CASE_ROOT: &str = r"C:\harness-e2e";
/// ワークスペースの名前。
const CASE: &str = "policy-editor-position-domains";

/// 1段だけの遷移が通ることを確かめる腕の印（中の段の`Write-Output`がそのまま返す）。
const CONTROL_MARKER: &str = "PD_CONTROL_MARKER";

/// e2e-mock でない`harness.exe`を見つけたときの文言（[`harness_exe`]）。
const BUILD_E2E_MOCK: &str =
    "先に `cargo build -p harness-cli --features e2e-mock` を実行してください";

fn editor_exe() -> &'static str {
    env!("CARGO_BIN_EXE_harness-policy-editor")
}

/// 模擬プロバイダつきの`harness.exe`（このテストの実行ファイルの2つ上＝`target/debug/`）。
///
/// **違うビルドを黙って撃たない**（`B-09`）。e2e-mock でないビルドは`--provider mock`を知らず、
/// 起動の引数エラーで落ちる——それを「遷移が断られた」と読まないよう、撃つ前に`--help`で確かめる。
fn harness_exe() -> PathBuf {
    let test_exe = std::env::current_exe().expect("current_exe");
    let dir = test_exe
        .parent()
        .and_then(Path::parent)
        .expect("target/debug/deps の2つ上");
    let exe = dir.join("harness.exe");
    assert!(exe.is_file(), "{} が無い。{BUILD_E2E_MOCK}", exe.display());
    let help = Command::new(&exe)
        .arg("--help")
        .output()
        .unwrap_or_else(|e| panic!("{} --help を起こせない: {e}", exe.display()));
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(
        text.contains("--mock-turns"),
        "{} は e2e-mock でないビルド（`--help`に`--mock-turns`が無い）。{BUILD_E2E_MOCK}",
        exe.display()
    );
    exe
}

fn system_root() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string())
}

fn system32(name: &str) -> String {
    format!(r"{}\System32\{name}", system_root())
}

/// 連鎖の中の段のシェル（[`middle_shell`]が選ぶ）。
struct MiddleShell {
    /// 実行ファイルのフルパス（行にそのまま書く）。
    path: String,
    /// 実行ファイル名（`pwsh.exe`／`powershell.exe`。木と辺の照合に使う）。
    exe: String,
    /// 割り当てで付くドメインの名前（葉名。`pwsh`／`powershell`）。
    domain: String,
}

/// 中の段のシェルを`harness.exe`と**同じ判断**で選ぶ（`B-05`）。強制の下では生成禁止を積むので
/// `ChildProcessPolicy::Restricted`で聞く——ストアアプリの`pwsh`は`dropped`へ回り（§S62）、
/// 先頭はストアアプリでない`pwsh`か、無ければ 5.1 になる。**選んだものと外したものを必ず出す**
/// （黙って 5.1 へ落ちると、`pwsh`の枝を撃ったのかどうかが記録から分からない。`B-10`）。
/// `harness.exe`の preflight と違って候補を起こして確かめはしない——起こせない先頭なら検算の腕が赤くなる。
fn middle_shell() -> MiddleShell {
    let choices = shell_candidates_from(
        which::which("pwsh").ok(),
        &system_root(),
        ChildProcessPolicy::Restricted,
    );
    if choices.dropped.is_empty() {
        println!("[position-domains] 中の段の候補から外した綴り: なし");
    }
    for dropped in &choices.dropped {
        println!(
            "[position-domains] 中の段の候補から外した綴り: {dropped}\
             （ストアアプリの綴りは遷移の強制の下で起こせない。§S62）"
        );
    }
    let (path, label) = choices
        .candidates
        .into_iter()
        .next()
        .expect("shell_candidates_from always yields at least PowerShell 5.1");
    let exe = file_name(&path);
    let domain = exe.strip_suffix(".exe").unwrap_or(&exe).to_string();
    println!("[position-domains] 中の段のシェル: {path}（{label}、ドメイン {domain}）");
    MiddleShell { path, exe, domain }
}

/// パスの最後の要素を小文字で（`C:/Windows/System32/cmd.exe` → `cmd.exe`）。
fn file_name(path: &str) -> String {
    path.rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase()
}

/// 1本の`run_shell`の行（記録でも強制でも同じものを撃つ）。`name`は台本と要求の記録のファイル名に使う。
struct Script {
    name: &'static str,
    line: String,
}

/// 1段だけの遷移（入口のドメイン → 中の段）を撃つ腕。**それ以上プロセスを起こさない**
/// （`Write-Output`は PowerShell の中で終わる）。
fn control_script(shell: &MiddleShell) -> Script {
    Script {
        name: "control-one-hop",
        line: ps_run(shell, &format!("Write-Output {CONTROL_MARKER}")),
    }
}

/// 中の段のシェルに1行を撃たせる綴り。**実行ファイルも1行も PowerShell の単引用符の文字列にし、`&`で呼ぶ**
/// ——MSI の`pwsh`（`C:\Program Files\PowerShell\7\pwsh.exe`）はパスに空白を含むので、囲まないと割れる。
/// 単引用符の中で特別な文字は`'`だけ（`''`に重ねる）で、外の段が1重剥がしたものが次の段の`-Command`に届く。
/// 二重引用符は使わない——子へ渡すときの`"`の扱いが 5.1 と 7 で違う（`$PSNativeCommandArgumentPassing`）。
/// `-NoProfile -NonInteractive -Command`は`pwsh`と 5.1 で同じ綴りで通る。
fn ps_run(shell: &MiddleShell, rest: &str) -> String {
    let quote = |s: &str| format!("'{}'", s.replace('\'', "''"));
    format!(
        "& {} -NoProfile -NonInteractive -Command {}",
        quote(&shell.path),
        quote(rest)
    )
}

/// ユーザーの例の「通る」2本（記録する連鎖でもある）と、「断る」3本。
fn scripts(shell: &MiddleShell) -> (Script, Script, Vec<(Script, Refusal)>) {
    let hostname = system32("hostname.exe");
    let whoami = system32("whoami.exe");
    let notepad = system32("notepad.exe");
    let pass_hostname = Script {
        name: "pass-hostname",
        line: ps_run(shell, &hostname),
    };
    let pass_whoami = Script {
        name: "pass-whoami",
        line: ps_run(shell, &whoami),
    };
    let refused = vec![
        (
            // ユーザーの例の`cmd→pwsh→pwsh`（同じプログラムを2段続ける）。
            Script {
                name: "refuse-ps-ps-whoami",
                line: ps_run(shell, &ps_run(shell, &whoami)),
            },
            Refusal {
                from: shell.domain.clone(),
                exe: shell.exe.clone(),
                leaf_output: Some(Leaf::Whoami),
            },
        ),
        (
            // ユーザーの例の`cmd→cmd→notepad`に当たる「記録に無いプログラム」。
            Script {
                name: "refuse-ps-notepad",
                line: ps_run(shell, &notepad),
            },
            Refusal {
                from: shell.domain.clone(),
                exe: "notepad.exe".to_string(),
                leaf_output: None,
            },
        ),
        (
            // **同じプログラムでも位置が違えば断る**（葉の辺は中の段のドメインから伸びている）。
            Script {
                name: "refuse-entry-hostname",
                line: hostname.clone(),
            },
            Refusal {
                from: ENTRY_DOMAIN.to_string(),
                exe: "hostname.exe".to_string(),
                leaf_output: Some(Leaf::Hostname),
            },
        ),
    ];
    (pass_hostname, pass_whoami, refused)
}

/// 断る腕の期待。**断ったのは誰か（遷移元）と、何を起こそうとしたか**で言う。
struct Refusal {
    from: String,
    exe: String,
    /// 断られたら出ないはずの葉の出力。
    leaf_output: Option<Leaf>,
}

#[derive(Clone, Copy)]
enum Leaf {
    Hostname,
    Whoami,
}

/// 葉のプログラムをサンドボックスの外で1回撃った出力（比べる相手。綴りを推測しない）。
struct LeafOutputs {
    hostname: String,
    whoami: String,
}

impl LeafOutputs {
    fn capture() -> Self {
        let run = |exe: String| {
            let out = Command::new(&exe)
                .output()
                .unwrap_or_else(|e| panic!("{exe} を起こせない: {e}"));
            assert!(out.status.success(), "{exe} が失敗した: {out:?}");
            let text = String::from_utf8_lossy(&out.stdout)
                .trim()
                .to_ascii_lowercase();
            assert!(!text.is_empty(), "{exe} の出力が空");
            text
        };
        Self {
            hostname: run(system32("hostname.exe")),
            whoami: run(system32("whoami.exe")),
        }
    }

    fn of(&self, leaf: Leaf) -> &str {
        match leaf {
            Leaf::Hostname => &self.hostname,
            Leaf::Whoami => &self.whoami,
        }
    }
}

#[test]
#[ignore = "requires administrator rights (records pass 1 with the ETW collector and runs harness.exe with --enforce-transitions); run through dev-elevated-run"]
fn position_domains_written_by_the_editor_let_only_the_recorded_chains_through_harness() {
    let harness = harness_exe();
    let shell = middle_shell();
    let leaves = LeafOutputs::capture();
    let ws = case_dir();
    std::fs::create_dir_all(ws.join(".harness").join("sandbox")).unwrap();
    let (pass_hostname, pass_whoami, refused) = scripts(&shell);

    // --- 1・2. 記録して位置ごとに承認する（1回目: hostname の連鎖、2回目: whoami の連鎖） ---
    let first = record(&ws, &shell, &pass_hostname, &leaves.hostname, "hostname.exe");
    approve_positions(&ws, &shell, &first, "hostname.exe", false);
    let second = record(&ws, &shell, &pass_whoami, &leaves.whoami, "whoami.exe");
    approve_positions(&ws, &shell, &second, "whoami.exe", true);

    let edges = written_edges(&ws);
    eprintln!("[position-domains] 書かれた辺: {edges:#?}");
    let expected: BTreeSet<(String, String, String)> = [
        (ENTRY_DOMAIN, shell.exe.as_str(), shell.domain.as_str()),
        (shell.domain.as_str(), "hostname.exe", "hostname"),
        (shell.domain.as_str(), "whoami.exe", "whoami"),
    ]
    .into_iter()
    .map(|(f, e, t)| (f.to_string(), e.to_string(), t.to_string()))
    .collect();
    assert_eq!(
        edges, expected,
        "policy.json の辺が記録した2本の連鎖の3段と一致しない"
    );

    // --- 3. harness.exe --enforce-transitions で撃つ ---
    let profiles_before = harness_profiles();
    let mut failures: Vec<String> = Vec::new();

    // **計器の検算: 1段だけの遷移が通るか**（`measurement-review`の検問1）。
    //
    // 記録した連鎖の1段目（入口のドメイン → 中の段）だけを使い、その子の中で**それ以上
    // プロセスを起こさない**（`Write-Output`は PowerShell の中で終わる）。ここが通らないなら、後の腕の
    // 「葉の出力が無い」は位置ごとのドメインの話ではなく、**別のドメインで子を1つも
    // 起こせない**ことを測っている——順序を分けないと、断る腕の緑が「全部断る」実装でも
    // 揃ってしまう（`B-35`）。
    let control = control_script(&shell);
    let arm = run_arm(&harness, &ws, &control);
    arm.print(control.name);
    if !arm.result.contains(CONTROL_MARKER) {
        failures.push(format!(
            "{}: **1段目の遷移（入口のドメイン → {}）が通っていない。** 位置ごとのドメインの\
             良し悪しではなく、別のドメインで子を起こせていない。拒否: {:?}／本文:\n{}",
            control.name, shell.domain, arm.denials, arm.result
        ));
    }
    if !arm.denials.is_empty() {
        failures.push(format!(
            "{}: 宣言した1段目で拒否が積まれた: {:?}",
            control.name, arm.denials
        ));
    }

    for (script, leaf) in [
        (&pass_hostname, Leaf::Hostname),
        (&pass_whoami, Leaf::Whoami),
    ] {
        let arm = run_arm(&harness, &ws, script);
        arm.print(script.name);
        if !arm.result.to_ascii_lowercase().contains(leaves.of(leaf)) {
            failures.push(format!(
                "{}: 通るはずの連鎖の葉の出力（{}）が届いていない。本文:\n{}",
                script.name,
                leaves.of(leaf),
                arm.result
            ));
        }
        if !arm.denials.is_empty() {
            failures.push(format!(
                "{}: 通るはずの連鎖で拒否が積まれた: {:?}",
                script.name, arm.denials
            ));
        }
    }
    for (script, refusal) in &refused {
        let arm = run_arm(&harness, &ws, script);
        arm.print(script.name);
        let expected = (
            Some(refusal.from.clone()),
            refusal.exe.clone(),
            DenyReason::Transition {
                denial: TransitionDenial::NoMatchingEdge,
            },
        );
        if arm.denials != vec![expected.clone()] {
            failures.push(format!(
                "{}: 断った記録が期待（{expected:?}）とちょうど1件で一致しない: {:?}",
                script.name, arm.denials
            ));
        }
        if let Some(leaf) = refusal.leaf_output {
            if arm.result.to_ascii_lowercase().contains(leaves.of(leaf)) {
                failures.push(format!(
                    "{}: 断られるはずの連鎖の葉の出力（{}）が届いた。本文:\n{}",
                    script.name,
                    leaves.of(leaf),
                    arm.result
                ));
            }
        }
    }

    // --- 4. harness.exe が作った入れ物が残っていない ---
    let left: Vec<String> = harness_profiles()
        .difference(&profiles_before)
        .cloned()
        .collect();
    if !left.is_empty() {
        failures.push(format!(
            "harness.exe の終了後に AppContainer プロファイルが残った: {left:?}"
        ));
    }

    assert!(
        failures.is_empty(),
        "位置ごとのドメインの強制で{}件の問題（ワークスペース {} を調査のため残す）:\n- {}",
        failures.len(),
        ws.display(),
        failures.join("\n- ")
    );
    let _ = std::fs::remove_dir_all(&ws);
    let _ = std::fs::remove_dir_all(scratch_dir());
}

/// ケース専用ワークスペース。既存があれば作り直す（前回失敗の残骸を引き継がない）。
fn case_dir() -> PathBuf {
    let dir = Path::new(CASE_ROOT).join(CASE);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create case workspace");
    dir
}

/// 台本・要求の記録・Recall の置き場（ワークスペースの外。緑なら消す）。
fn scratch_dir() -> PathBuf {
    let dir = Path::new(CASE_ROOT).join("_scratch").join(CASE);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

// --- 記録（パス1） ---------------------------------------------------------------

/// パス1で`script`を1回記録し、記録のディレクトリを返す。木に「根 → 中の段 → `leaf`」の鎖が
/// あることを確かめる（**無ければ収集の失敗**。後の承認と強制の判定の前提が崩れる）。
fn record(
    ws: &Path,
    shell: &MiddleShell,
    script: &Script,
    leaf_output: &str,
    leaf: &str,
) -> PathBuf {
    let before = record_dirs(ws);
    let output = Command::new(editor_exe())
        .args([
            "record",
            "--workspace",
            &ws.to_string_lossy(),
            "--cwd",
            &ws.to_string_lossy(),
            "--limit",
            "0",
            "--",
            &script.line,
        ])
        // 開発ビルド（`target/debug`）は必ずユーザー書込可なので、D-44の逃がし弁が要る（`record_e2e.rs`と同じ）。
        .env("HARNESS_ALLOW_USER_WRITABLE_ELEVATED_HELPERS", "1")
        .output()
        .expect("the policy editor binary should run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!(
        "[position-domains] record {}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        script.name
    );
    assert!(output.status.success(), "record が失敗した: {stderr}");
    assert!(
        stdout.to_ascii_lowercase().contains(leaf_output),
        "記録の中で連鎖の葉が走っていない（出力に {leaf_output} が無い）"
    );

    let dir = record_dirs(ws)
        .difference(&before)
        .next()
        .cloned()
        .expect("新しい記録のディレクトリ");
    let text = std::fs::read_to_string(dir.join(PROCESS_AUDIT_FILE))
        .unwrap_or_else(|e| panic!("{PROCESS_AUDIT_FILE} が無い: {e}"));
    let tree = parse_process_audit(&text).expect("process-audit.jsonl starts with its header");
    for i in &tree.instances {
        eprintln!(
            "[position-domains] 木: seq={} parent={:?} ({:?}) root={} exe={:?} argv={:?}",
            i.seq, i.parent_seq, i.parent_seq_source, i.is_scope_root, i.image_path, i.argv
        );
    }
    let root = tree
        .instances
        .iter()
        .find(|i| i.is_scope_root)
        .expect("記録の根が木にある");
    let middle = child_named(&tree.instances, root, &shell.exe);
    child_named(&tree.instances, middle, leaf);
    dir
}

/// `parent`の子で実行ファイル名が`name`のインスタンス（無ければ落とす）。
fn child_named<'a>(
    instances: &'a [ProcessInstance],
    parent: &ProcessInstance,
    name: &str,
) -> &'a ProcessInstance {
    instances
        .iter()
        .find(|i| {
            i.parent_seq == Some(parent.seq)
                && i.image_path.as_deref().map(file_name).as_deref() == Some(name)
        })
        .unwrap_or_else(|| {
            panic!(
                "木に {name} が {:?}（seq={}）の子として無い——収集の失敗（後の判定の前提が無い）",
                parent.image_path, parent.seq
            )
        })
}

/// 記録のディレクトリ（`record-session.json`を持つもの）の集合。
fn record_dirs(ws: &Path) -> BTreeSet<PathBuf> {
    let sandbox = ws.join(".harness").join("sandbox");
    std::fs::read_dir(&sandbox)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|dir| dir.join("record-session.json").is_file())
                .collect()
        })
        .unwrap_or_default()
}

// --- 承認（エディタの画面） -------------------------------------------------------

fn press(app: &mut App, code: KeyCode) {
    app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
}

/// 観測のタブを開き、`record_dir`の記録の鎖の行（中の段・`leaf`）のうち書くものを`Space`で予約し、
/// `a`→`y`で1回に書く。**ファイルの候補は選ばない**（`hostname`・`whoami`は既定で実行できる場所＝D-58）。
///
/// `reuses_edges`: 1回目の記録で書いた辺が、この記録の中の段の位置に`ExistingEdge`として引かれるはずか。
fn approve_positions(
    ws: &Path,
    shell: &MiddleShell,
    record_dir: &Path,
    leaf: &str,
    reuses_edges: bool,
) {
    let chain = [shell.exe.as_str(), leaf];
    let mut app = App::new(ws.to_path_buf(), harness_core::RequireSandbox::None);
    press(&mut app, KeyCode::F(2));
    press(&mut app, KeyCode::F(2));
    let selected = app.selected_session().expect("記録が選ばれている");
    assert_eq!(
        selected.dir.path(),
        record_dir,
        "選んでいる記録がいま記録したものではない"
    );
    let positions = app.pending.positions.as_ref().unwrap_or_else(|| {
        panic!(
            "位置の木が出ていない（観測のタブの注記: {:?}）",
            app.pending.notes
        )
    });
    assert_eq!(positions.view.session_id, selected.dir.id());

    // 全部の位置（書かないものも）を出す——記録された木の位置とドメインの名前が報告の材料になる。
    for position in &positions.view.assignment.positions {
        eprintln!(
            "[position-domains] 位置: depth={} {} --{}--> {} ({:?})",
            position.depth,
            position.from_domain,
            file_name(&position.exe),
            position.to_domain,
            position.source
        );
    }
    for position in &positions.view.assignment.positions {
        let name = file_name(&position.exe);
        if reuses_edges && name == shell.exe {
            assert_eq!(
                position.source,
                PositionSource::ExistingEdge,
                "1回目に書いた辺が {name} の位置で引かれていない（名前を作り直している）"
            );
        }
    }

    let visible: Vec<(usize, String, EdgeVerdict)> = positions
        .visible()
        .iter()
        .map(|row| {
            let position = &positions.view.assignment.positions[row.position];
            (
                row.position,
                file_name(&position.exe),
                positions.verdicts[row.position].clone(),
            )
        })
        .collect();
    let mut reserved = 0usize;
    for (i, (index, name, verdict)) in visible.iter().enumerate() {
        let current = app.pending.positions.as_ref().unwrap();
        assert_eq!(current.row, i, "選択が行を1つずつ下りていない");
        if chain.contains(&name.as_str()) {
            // 書けない判定になったら、その判定の文言を出して止める——そのときは連鎖のプログラムを選び直す
            // （P4.md の Step 3。広げる向きは決定66から書ける＝`is_writable`）。
            assert!(
                verdict.is_writable(),
                "鎖の位置 {name}（添字 {index}）が書けない判定: {verdict:?}"
            );
            press(&mut app, KeyCode::Char(' '));
            reserved += 1;
        } else {
            eprintln!("[position-domains] 鎖の外の位置は選ばない: {name} {verdict:?}");
        }
        press(&mut app, KeyCode::Down);
    }
    let expected_reserved = if reuses_edges { 1 } else { 2 };
    assert_eq!(
        reserved, expected_reserved,
        "書く鎖の位置の数が違う（見えている行: {visible:?}）"
    );
    assert_eq!(
        app.pending.positions.as_ref().unwrap().approve.len(),
        expected_reserved,
        "予約の数が押した数と違う: {}",
        app.status
    );
    assert!(app.accepted.is_empty(), "ファイルの候補を選んでいる");

    press(&mut app, KeyCode::Char('a'));
    let modal = app
        .modal
        .as_ref()
        .unwrap_or_else(|| panic!("確認ダイアログが出ない: {}", app.status));
    assert_eq!(modal.confirm, Confirm::Position);
    eprintln!(
        "[position-domains] 確認ダイアログ:\n{}",
        modal.lines.join("\n")
    );
    press(&mut app, KeyCode::Char('y'));
    assert!(app.modal.is_none(), "y でダイアログが閉じない");
    eprintln!("[position-domains] 確定の後: {}", app.status);
    assert!(
        app.pending
            .positions
            .as_ref()
            .is_some_and(|p| p.approve.is_empty()),
        "書いた予約が残っている（書けなかった？）: {}",
        app.status
    );
}

/// `policy.json`の辺を（遷移元, 実行ファイル名, 遷移先）で。
fn written_edges(ws: &Path) -> BTreeSet<(String, String, String)> {
    let file = policy_file::load(ws).expect("policy.json を読める");
    let mut edges = BTreeSet::new();
    for domain in &file.domains {
        for edge in &domain.process.transitions {
            let exe = match &edge.exe {
                harness_policy::transition::ExeMatcher::Literal(path) => file_name(path),
                other => panic!("エディタがリテラルでない辺を書いた: {other:?}"),
            };
            edges.insert((domain.name.clone(), exe, edge.to.clone()));
        }
    }
    edges
}

// --- 強制（harness.exe） ----------------------------------------------------------

/// 1本の腕の結果。
#[derive(Debug)]
struct Arm {
    /// `run_shell`の結果本文（`tool_calls[0].result`）。
    result: String,
    /// 待ち行列の Daemon の拒否（遷移元, 実行ファイル名, 理由）。同じ種類の更新行は畳む。
    denials: Vec<(Option<String>, String, DenyReason)>,
    /// Spawn Daemon の標準エラー（`DAEMON_STDERR_ENV`で張った受け皿）。Daemon はコンソールを持たないので、
    /// 張らないと起こし損ねた理由がどこにも届かない（`tier2a_e2e.rs`の`run_arm_collecting_denials_in`と同じ）。
    daemon_stderr: String,
    /// `harness.exe`の標準エラー（遷移先ドメインを用意できなかった警告などが出る）。
    harness_stderr: String,
}

impl Arm {
    /// 報告の材料（各腕の本文・拒否・Daemon と harness の標準エラー）を読める形で出す。
    fn print(&self, name: &str) {
        eprintln!(
            "[position-domains] --- 腕 {name} ---
拒否: {:?}
--- run_shell の本文 ---
{}
\r
             --- Daemon の標準エラー ---
{}
--- harness の標準エラー ---
{}
[position-domains] --- 腕 {name} ここまで ---",
            self.denials, self.result, self.daemon_stderr, self.harness_stderr
        );
    }
}

/// `script`を`run_shell`で1回撃つ。**撃つ前に`pending.jsonl`を消す**（前の腕の拒否を数えない）。
fn run_arm(harness: &Path, ws: &Path, script: &Script) -> Arm {
    let queue = pending_path(ws);
    let _ = std::fs::remove_file(&queue);
    let line = &script.line;
    let scratch = scratch_dir();
    let turns_path = scratch.join(format!("{}-turns.json", script.name));
    let record_path = scratch.join(format!("{}-requests.jsonl", script.name));
    let _ = std::fs::remove_file(&record_path);
    // **腕ごとに1本、撃つ前に消す**（前の腕の失敗を今の腕の説明として読まない）。
    let daemon_log = scratch.join(format!("{}-spawnd.log", script.name));
    let _ = std::fs::remove_file(&daemon_log);
    let turns = vec![
        tool_use_turn(
            "call_1",
            "run_shell",
            serde_json::json!({ "command": line }),
        ),
        end_turn("done"),
    ];
    std::fs::write(&turns_path, serde_json::to_string(&turns).unwrap()).expect("write turns");

    let output = Command::new(harness)
        .args([
            "--provider",
            "mock",
            "--mock-turns",
            turns_path.to_str().unwrap(),
            "--mock-record-requests",
            record_path.to_str().unwrap(),
            "--cwd",
            &ws.to_string_lossy(),
            "--permission-mode",
            "accept-all",
            "--dangerously-allow",
            "--output-format",
            "json",
            "-p",
            "(scripted; prompt text is ignored by the mock provider)",
            "--allow",
            &format!("run_shell:{line}"),
            "--sandbox",
            "tier2a",
            "--enforce-transitions",
        ])
        .env(
            "HARNESS_TEST_RECALL_DATA_ROOT",
            scratch.join("recall-memory"),
        )
        .env(DAEMON_STDERR_ENV, &daemon_log)
        .output()
        .expect("failed to spawn harness.exe");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        output.status.success(),
        "{}: harness.exe 自体が失敗した（{}）。**拒否ではなく起動の失敗である**: {stderr}",
        script.name,
        output.status
    );
    assert_enforcement_visible(&record_path, script.name);
    let outcome: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout が JSON でない: {e}\nstdout={stdout}\nstderr={stderr}"));
    let call = &outcome["tool_calls"][0];
    assert_eq!(
        call["decision"].as_str(),
        Some("allowed"),
        "{}: run_shell が許可の層で止まった（サンドボックスへ届いていない）: {call}\nstderr={stderr}",
        script.name
    );
    let result = call["result"]
        .as_str()
        .unwrap_or_else(|| panic!("no tool_calls[0].result in outcome: {outcome}"))
        .to_string();

    let tail = read_from(&queue, 0);
    assert_eq!(
        tail.skipped, 0,
        "{}: 待ち行列の行が読めなかった（断った一覧が欠けている）",
        script.name
    );
    let mut denials: Vec<(Option<String>, String, DenyReason)> = Vec::new();
    for record in &tail.records {
        let key = match record {
            PendingRecord::DeniedByDaemon(d) => {
                (d.from_domain.clone(), file_name(&d.exe), d.reason.clone())
            }
            PendingRecord::DeniedByKernel(d) => panic!(
                "{}: カーネルの拒否が積まれた（今日これを書く者は居ないはず）: {d:?}",
                script.name
            ),
            PendingRecord::Overflowed { dropped, .. } => {
                panic!(
                    "{}: 待ち行列が{dropped}件あふれた（断った一覧が欠けている）",
                    script.name
                )
            }
        };
        if !denials.contains(&key) {
            denials.push(key);
        }
    }
    Arm {
        result,
        denials,
        daemon_stderr: std::fs::read_to_string(&daemon_log).unwrap_or_default(),
        harness_stderr: stderr,
    }
}

/// 強制が効いている回にだけモデルへ見える`can_run_program`が、送ったシステムプロンプトにあるか
/// （`tier2a_e2e.rs`の`assert_prompt_sane`。旗が届いていないまま「通った」と読まない）。
fn assert_enforcement_visible(record_path: &Path, arm: &str) {
    let data = std::fs::read_to_string(record_path).unwrap_or_else(|e| {
        panic!(
            "{arm}: 要求の記録 {} を読めない: {e}",
            record_path.display()
        )
    });
    let first = data
        .lines()
        .next()
        .unwrap_or_else(|| panic!("{arm}: 模擬プロバイダが1度も呼ばれていない"));
    let request: CompletionRequest =
        serde_json::from_str(first).expect("recorded request is CompletionRequest JSON");
    let system: String = request
        .system
        .iter()
        .map(|b| b.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        system.contains("can_run_program"),
        "{arm}: システムプロンプトに can_run_program が無い——遷移の強制が効いていない回を撃っている"
    );
}

/// ツール呼び出しだけを返すターン（`tier2a_e2e.rs`の`tool_use_turn`の写し）。
fn tool_use_turn(id: &str, name: &str, input: serde_json::Value) -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::ToolUse {
                id: id.to_string(),
                name: name.to_string(),
            },
        },
        StreamEvent::ToolInputDelta {
            index: 0,
            json_fragment: input.to_string(),
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::Done {
            stop_reason: StopReason::ToolUse,
            usage: Usage::default(),
        },
    ]
}

/// 文章だけを返して終わるターン（`tier2a_e2e.rs`の`end_turn`の写し）。
fn end_turn(text: &str) -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::Text,
        },
        StreamEvent::TextDelta {
            index: 0,
            text: text.to_string(),
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::Done {
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        },
    ]
}

// --- 後始末の確かめ ---------------------------------------------------------------

/// このユーザーの AppContainer プロファイルのうち、harness の族（セッション・MCP・遷移先ドメイン）の名前。
///
/// 族の見分けは`harness_sandbox`の`token_of_profile`に聞く（接頭辞を写さない、`B-05`）。
/// **一覧を取れなかったことを「1つも無い」と読まない**（`B-09`）——`reg`が失敗したら落とす。
fn harness_profiles() -> BTreeSet<String> {
    let output = Command::new(system32("reg.exe"))
        .args([
            "query",
            r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings",
            "/s",
            "/v",
            "Moniker",
        ])
        .output()
        .expect("reg.exe を起こせない");
    assert!(
        output.status.success(),
        "AppContainer プロファイルの一覧を取れない: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next(), parts.next()) {
                (Some("Moniker"), Some("REG_SZ"), Some(name)) => Some(name.to_string()),
                _ => None,
            }
        })
        .filter(|name| harness_sandbox::tier2a::session_profile::token_of_profile(name).is_some())
        .collect()
}
