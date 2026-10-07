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
//! # 共通の補助
//!
//! `harness.exe`の起こし方・待ち行列の読み方・記録の起こし方・後始末の確かめなど、
//! 広げる遷移の E2E（`widening_transitions_e2e.rs`）と共有する部品は[`common`]にある
//! （どこから写したかも向こうの doc が持つ）。
//!
//! # ワークスペースの置き場
//!
//! `C:\harness-e2e\policy-editor-position-domains`（`%TEMP%`は使わない。Tier2a の準備がプロファイル全階層の
//! traverse を恒久付与するため——`tier2a_e2e.rs`のモジュール doc）。緑なら消し、赤なら調査のため残す。

#![cfg(windows)]

mod common;

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use crossterm::event::KeyCode;
use harness_policy::policy_file::ENTRY_DOMAIN;
use harness_policy::position_domains::PositionSource;
use harness_policy::transition::TransitionDenial;
use harness_policy_editor::position_view::EdgeVerdict;
use harness_policy_editor::tui::state::{App, Confirm};
use harness_sandbox::tier2a::spawnd::DenyReason;

use common::{
    case_dir, file_name, harness_exe, harness_profiles, middle_shell, press, ps_run, record,
    run_arm, scratch_dir, system32, written_edges, MiddleShell, Script,
};

/// ワークスペースの名前。
const CASE: &str = "policy-editor-position-domains";

/// 1段だけの遷移が通ることを確かめる腕の印（中の段の`Write-Output`がそのまま返す）。
const CONTROL_MARKER: &str = "PD_CONTROL_MARKER";

/// 1段だけの遷移（入口のドメイン → 中の段）を撃つ腕。**それ以上プロセスを起こさない**
/// （`Write-Output`は PowerShell の中で終わる）。
fn control_script(shell: &MiddleShell) -> Script {
    Script {
        name: "control-one-hop",
        line: ps_run(shell, &format!("Write-Output {CONTROL_MARKER}")),
    }
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
    let ws = case_dir(CASE);
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
    let arm = run_arm(&harness, &ws, CASE, &control);
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
        let arm = run_arm(&harness, &ws, CASE, script);
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
        let arm = run_arm(&harness, &ws, CASE, script);
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
    let _ = std::fs::remove_dir_all(scratch_dir(CASE));
}

// --- 承認（エディタの画面） -------------------------------------------------------

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
