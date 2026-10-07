//! [D-112・決定69(2)] `approve-declared`——既に`policy.json`にあるファイルと**通信**の宣言を、このマシンで承認する。
//!
//! 2026-10-07に`main.rs`から**そのまま**移した（本体が1,000行を超えているため。`plans/position-domains/P7.md`の P7.7。
//! 通信の宣言を受ける`--net`を足す前に置き場を分けた）。

use std::path::PathBuf;
use std::process::ExitCode;

use super::{confirm_write, resolve_require_sandbox, resolve_workspace, Consent};

/// [D-112] `approve-declared`: 既に`policy.json`にあるファイル宣言を、このマシンで承認する。
pub(super) fn run_approve_declared(
    domain: &str,
    workspace: Option<PathBuf>,
    values: &[String],
    access: Option<&str>,
    net_values: &[String],
    require_sandbox: Option<&str>,
    consent: Consent,
) -> ExitCode {
    use harness_policy::generalize::SettingsKey;
    use harness_policy_editor::approve_declared;
    use harness_policy_editor::unapprove::UnapproveTarget;

    let Some(require_sandbox) = resolve_require_sandbox(require_sandbox) else {
        return ExitCode::FAILURE;
    };
    // [決定69(2)] `--fs`（種類が要る）と`--net`（種類は`net.allow_domains`）を1回の承認で受ける。
    // **どちらも無ければ何をするか決められない**ので断る（空の承認を「成功」と言わない）。
    if values.is_empty() && net_values.is_empty() {
        eprintln!("承認する宣言を指定してください（--fs <値> --access <種別> / --net <宛先>）");
        return ExitCode::FAILURE;
    }
    // 語彙は`unapprove --access`と同じ（新しい綴りを作らない）。
    let key = match access {
        Some("read") => SettingsKey::FsRead,
        Some("read_write") => SettingsKey::FsReadWrite,
        Some("read_exec") => SettingsKey::FsReadExec,
        Some(other) => {
            eprintln!("--access は read / read_write / read_exec のいずれかです（指定: {other}）");
            return ExitCode::FAILURE;
        }
        None if values.is_empty() => SettingsKey::FsRead, // `--fs`が無いので使われない
        None => {
            eprintln!("--fs には --access <read|read_write|read_exec> を付けてください");
            return ExitCode::FAILURE;
        }
    };
    let workspace_root = resolve_workspace(workspace);
    let targets: Vec<UnapproveTarget> = values
        .iter()
        .map(|value| UnapproveTarget {
            domain: domain.to_string(),
            key,
            value: value.clone(),
        })
        .chain(net_values.iter().map(|value| UnapproveTarget {
            domain: domain.to_string(),
            key: SettingsKey::NetAllowDomains,
            value: value.clone(),
        }))
        .collect();
    let plan = match approve_declared::plan(&workspace_root, &targets, require_sandbox) {
        Ok(plan) => plan,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "{}:",
        harness_policy_editor::policy_file::path(&workspace_root).display()
    );
    if !plan.approve.is_empty() {
        println!("  このマシンで承認する宣言 {}件:", plan.approve.len());
        for target in &plan.approve {
            println!("    + [{}] {} {}", target.domain, target.key.dotted(), target.value);
        }
    }
    for target in &plan.already {
        println!(
            "  = [{}] {} {}（承認済みでした）",
            target.domain,
            target.key.dotted(),
            target.value
        );
    }
    // **断った宣言と無かった指定を黙らない**（B-09）。「承認しました」だけを見せると、
    // 綴りの間違いや検査で止まった宣言に許可が付くと思い込む。
    for (target, reason) in &plan.refused {
        println!(
            "  ✗ [{}] {} {}: {reason}",
            target.domain,
            target.key.dotted(),
            target.value
        );
    }
    for target in &plan.not_found {
        println!(
            "  ? [{}] {} {}（policy.jsonにありません）",
            target.domain,
            target.key.dotted(),
            target.value
        );
    }
    // **部分適用しない**（`approve`と同じ判断）。名指しした宣言の1件でも断る・無いなら何も書かない
    // ——指定の誤りを直してから撃ち直す方が、一部だけ通った状態より読み違えにくい。
    if !plan.refused.is_empty() || !plan.not_found.is_empty() {
        eprintln!("承認できない指定があるので、何も書いていません");
        return ExitCode::FAILURE;
    }
    if plan.is_empty() {
        return ExitCode::SUCCESS;
    }
    println!();
    println!(
        "承認すると、次の record-net と harness.exe の起動でこの宣言に許可（ACE）が付きます。"
    );
    // policy.json を変えない（このマシンの承認台帳だけ）ので、広がりは空（`cli_consent`のモジュールdoc）。
    if !confirm_write(consent, &Default::default()) {
        println!("何も書いていません");
        return ExitCode::FAILURE;
    }
    match approve_declared::commit(&workspace_root, &plan) {
        Ok(count) => {
            println!("このマシンで{count}件を承認しました");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
