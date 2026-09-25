//! `harness approvals`サブコマンド（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` §3.1・D-107）。
//!
//! 承認画面で「恒久的に承認」を選んだ記録は、ユーザー層の台帳
//! （`%APPDATA%\harness\config\run-approval-ledger.json`）に残り、次の起動から自動承認に使われる。
//! **記録するだけで剥がせない片側を作らない**ため、一覧と取り消しをここに置く
//! （`harness mcp list`/`revoke`と同じ位置づけで、サンドボックスもプロバイダ資格情報も要らない）。
//!
//! **番号は[`ApprovalStore::list`]の並び**（検証の前の生の並び）である。読み込み時に捨てられる記録
//! （版が古い・検証に通らない）も一覧には出る——**捨てられたものこそ取り消せないと消せない**。

use std::process::ExitCode;

use harness_engine::approval_ledger::{ApprovalStore, RunApproval};

use super::*;

/// `harness approvals`サブコマンドの各操作。
#[derive(Subcommand)]
pub(crate) enum ApprovalsAction {
    /// 記録された承認を番号付きで一覧表示する。
    List,
    /// 番号を指定して1件取り消す。
    Revoke {
        /// `harness approvals list`が出す番号。
        number: usize,
    },
    /// 記録された承認を全部取り消す。
    RevokeAll {
        /// 確認プロンプトを出さずに取り消す（スクリプト用）。
        #[arg(long = "yes", default_value_t = false)]
        yes: bool,
    },
}

pub(crate) fn run_approvals(action: ApprovalsAction) -> ExitCode {
    let store = ApprovalStore::open_default();
    match action {
        ApprovalsAction::List => list(&store),
        ApprovalsAction::Revoke { number } => revoke(&store, number),
        ApprovalsAction::RevokeAll { yes } => revoke_all(&store, yes),
    }
}

fn list(store: &ApprovalStore) -> ExitCode {
    for line in list_lines(&store.list()) {
        println!("{line}");
    }
    if let Some(path) = store.path() {
        println!("approval ledger: {}", path.display());
    }
    ExitCode::SUCCESS
}

/// 一覧の本文。**番号は引数の並びそのもの**——`revoke <番号>`が同じ並びを使うので、
/// ここで並べ替えたり、使われない記録を隠したりしてはいけない
/// （隠すと、読み込み時に捨てられた記録を取り消す手段が無くなる）。
fn list_lines(approvals: &[RunApproval]) -> Vec<String> {
    if approvals.is_empty() {
        return vec![
            "(no recorded approvals) -- choosing \"恒久的に承認\" in the approval screen for \
             run_program / run_shell records one here."
                .to_string(),
        ];
    }
    let mut out = Vec::new();
    for (i, a) in approvals.iter().enumerate() {
        out.push(format!("{i:<4}{}", a.rule.describe()));
        out.extend(details(a).into_iter().map(|d| format!("      {d}")));
    }
    out
}

/// 1件の内訳（ワークスペース・承認時刻・縛ったファイル）。**ハッシュは先頭12桁だけ出す**
/// ——全部出しても読み比べられないし、一覧が縦に伸びて肝心の呼び出しが見えなくなる。
fn details(a: &RunApproval) -> Vec<String> {
    let mut out = vec![
        format!("workspace: {}", a.rule.workspace().unwrap_or("(any)")),
        format!("approved at: {} (unix)", a.approved_at_unix_secs),
    ];
    if a.format_version != harness_engine::approval_ledger::FORMAT_VERSION {
        out.push(format!(
            "note: recorded in format version {} and is not used for auto-approval",
            a.format_version
        ));
    }
    for f in a.rule.files() {
        let listing = match f.dir_listing_sha256.is_some() {
            true => " (+ the names next to it)",
            false => "",
        };
        out.push(format!(
            "bound: {} sha256={}…{listing}",
            f.rel_path,
            &f.sha256[..f.sha256.len().min(12)]
        ));
    }
    out
}

fn revoke(store: &ApprovalStore, number: usize) -> ExitCode {
    match store.revoke(number) {
        Ok(removed) => {
            println!("revoked {}.", removed.rule.describe());
            ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!("error: {reason}. `harness approvals list` shows the numbers.");
            ExitCode::FAILURE
        }
    }
}

fn revoke_all(store: &ApprovalStore, yes: bool) -> ExitCode {
    let n = store.list().len();
    if n == 0 {
        println!("(no recorded approvals); nothing to revoke.");
        return ExitCode::SUCCESS;
    }
    if !yes && !super::mcp_cmd::confirm(&format!("Revoke all {n} recorded approval(s)?")) {
        println!("not revoked.");
        return ExitCode::FAILURE;
    }
    println!("revoked {} approval(s).", store.revoke_all());
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use harness_core::{ArgPattern, BoundFile, ProgramRule, ShellRule};
    use harness_engine::approval_ledger::RecordedRule;

    fn approval(rule: RecordedRule, format_version: u32) -> RunApproval {
        RunApproval {
            format_version,
            approved_at_unix_secs: 1_700_000_000,
            rule,
            snapshots: Vec::new(),
        }
    }

    /// 番号は並びそのもので、**読み込み時に捨てられる記録（版が古い）も一覧に出る**
    /// ——出さないと取り消せない。縛ったファイルはハッシュの先頭だけ見せる。
    #[test]
    fn the_listing_numbers_every_record_including_the_ones_that_are_not_used() {
        let script = RecordedRule::RunProgram(ProgramRule {
            program: "python".to_string(),
            args: vec![ArgPattern::Exact("build.py".to_string())],
            resolved: Some("C:/Python/python.exe".to_string()),
            files: vec![BoundFile {
                rel_path: "build.py".to_string(),
                sha256: "abcdef0123456789".repeat(4),
                dir_listing_sha256: Some("f".repeat(64)),
            }],
            workspace: Some("c:/ws".to_string()),
        });
        let shell = RecordedRule::RunShell(ShellRule {
            line: "cargo test".to_string(),
            files: Vec::new(),
            workspace: Some("c:/ws".to_string()),
        });

        let lines = list_lines(&[approval(script, 0), approval(shell, 1)]);
        let text = lines.join("\n");
        assert!(text.starts_with("0   run_program python"), "{text}");
        assert!(text.contains("\n1   run_shell \"cargo test\""), "{text}");
        assert!(
            text.contains("format version 0 and is not used for auto-approval"),
            "{text}"
        );
        assert!(
            text.contains("bound: build.py sha256=abcdef012345… (+ the names next to it)"),
            "{text}"
        );
    }

    #[test]
    fn an_empty_ledger_says_where_records_come_from() {
        let lines = list_lines(&[]);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("no recorded approvals"), "{:?}", lines[0]);
    }
}
