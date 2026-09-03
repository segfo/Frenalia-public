//! `harness fs`サブコマンド群。付与済みACEの一覧・撤収・traverse付与を担う。
//!
//! プロバイダ資格情報もworkspace sandboxも必要としない独立した経路で、`main`の
//! 起動パイプラインより前にディスパッチされる。

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Subcommand, ValueEnum};

mod prepare;
mod progress;
mod prune;
mod revoke;
mod traverse;
mod workspace;

// 台帳そのもの（型・ロック・記録関数）は`harness-sandbox`が持つ。ACEを実際に付与するのは
// `win_appcontainer::preflight`（あちら側）であり、**付与した側が記録する**形にしないと
// 台帳に載らない付与＝孤立ACEが生まれるため（同モジュールのdoc参照）。ここに残るのは
// `harness fs`が提供する操作——一覧・撤収・prune——だけである。
pub(crate) use harness_sandbox::tier2a::fs_passthrough_ledger::*;
use harness_sandbox::tier2a::workspace_ledger::WorkspaceMode;

// `main`（binターゲット）の起動パイプラインから直接呼ぶものだけ`pub`で再エクスポートする
// （`harness fs`の公開面を移設前と変えない）。
pub use harness_sandbox::tier2a::fs_passthrough_ledger::{
    record_fs_passthrough_denials, record_fs_passthrough_grants, FsPassthroughGrantRecord,
};
pub(crate) use prepare::fs_prepare_workspace;
pub(crate) use prune::fs_prune;
pub use revoke::reconcile_fs_ledger_for_workspace;
pub(crate) use revoke::*;
pub(crate) use traverse::*;
pub(crate) use workspace::*;

/// `harness fs`サブコマンドの各操作。Windows Tier2a固有機能のため、Windows以外では
/// `List`以外はエラーで終了する（台帳自体はクロスプラットフォームのJSONだが、実際のACE
/// 付与・撤収はWin32のSID/ACLに依存するため）。
#[derive(Subcommand)]
pub enum FsAction {
    /// fs passthrough台帳（ユーザグローバル、D5）を一覧表示する。
    List,
    /// 到達不能/付与失敗だったfs passthrough候補だけを一覧表示する。
    Denied,
    /// workspaceのAppContainer用ACEを作業開始前に準備する。通常起動と同じ永続capability・
    /// 伝播・救済walkを使い、完了まで進捗を表示する。
    PrepareWorkspace {
        path: PathBuf,
        /// `rwx`は通常Tier2a、`ro`はTier2a CoWの実workspaceと同じ権限。
        #[arg(long, value_enum)]
        mode: WorkspacePrepareMode,
    },
    /// 指定ルートのfs passthroughを撤収する（再walk revoke + 検証パス + 台帳から除去、D3/D4）。
    Revoke { path: PathBuf },
    /// 台帳の全エントリを撤収する。
    RevokeAll,
    /// **実在しないパスを指す台帳エントリ**を4台帳（fs-passthrough・traverse-grant・
    /// workspace-grant・workspace-capability）から落とす（D-53）。台帳は`preflight`が起動の
    /// たびに追記する一方、明示的な`revoke-*`を呼ばない限り誰も消さないため記録が積もる。
    ///
    /// **ACEは一切撤収しない**（触るのは台帳の記録だけ）。「消えた」と確定できるのは
    /// **ボリュームルートが到達可能でかつパスが存在しない**ときだけで、未マウントの
    /// リムーバブル/オフラインのネットワークドライブ上のエントリは判定不能として残す
    /// （実体とACEが生きている可能性があるため）。ドライブ/共有のルート自体も常に残す。
    Prune {
        /// 台帳を書き換えず、落とす対象と内訳を表示するだけにする。
        #[arg(long = "dry-run", default_value_t = false)]
        dry_run: bool,
    },
    /// `target`とその全祖先（ドライブルートまで）へ`FILE_TRAVERSE | FILE_READ_ATTRIBUTES`を
    /// 連鎖付与する（D10連鎖化、`TIER1A-OPEN-ISSUES.md`項目6）。例えば
    /// `C:\Users\<user>\.cargo`を指定すると、`C:\`・`C:\Users`・`C:\Users\<user>`・
    /// `C:\Users\<user>\.cargo`の4ノード全てへ、UAC 1回で付与する。`WRITE_DAC`が要るため
    /// 非管理者では特権分離ヘルパー(D-16)経由でUACを表示する。付与に成功した各ノードは、
    /// 撤収用の別台帳(traverse台帳)へ個別に記録される。
    GrantTraverse {
        target: PathBuf,
        /// 実際には何も書き込まず、付与予定の祖先チェーンと各ノードの既存ACE有無だけを
        /// 表示する（`GetNamedSecurityInfoW`のみ、`SetNamedSecurityInfoW`は一切呼ばない）。
        /// UACも表示されない。プロファイルルート近傍への書込みは実機で病的に遅くなりうる
        /// ため（BUG-011）、本実行の前に対象ノードを確認したい場合に使う。
        #[arg(long = "dry-run", default_value_t = false)]
        dry_run: bool,
    },
    /// `grant-traverse`で付与したtraverse ACEを1件撤収する（非再帰・単一ノード、D10の巻き戻し）。
    /// 注意: `grant-traverse`が連鎖付与した祖先ノード（`C:\Users`等）は、他のpassthroughルートと
    /// **共有されている可能性がある**。この`revoke-traverse`は指定した1ノードだけを撤収するため、
    /// 他の到達性がまだその祖先ノードに依存している場合は、それを壊してしまう。祖先ノードの
    /// 要否を意識せず一括で戻したい場合は`revoke-traverse-all`を使うこと。
    RevokeTraverse { path: PathBuf },
    /// traverse台帳の全エントリを撤収する。`grant-traverse`で付与した箇所を手打ちで覚える
    /// 必要がなく、記録済みの箇所だけを自動で対象にする。
    RevokeTraverseAll,
    /// `preflight`が起動のたびに付与するworkspace本体のACE（通常起動=RWX、`--sandbox tier2a-cow`=RO）を
    /// 撤収する。同じworkspaceを今も使っている他のharnessセッションが無いことを名前付き
    /// mutexで確認し、あれば「使用中」として拒否する（`harness_sandbox::tier2a::workspace_ledger`
    /// 参照）。CoWのdiff_layer_dirには一切触れない（別コマンド`harness cow discard`が担当）。
    RevokeWorkspace { path: PathBuf },
    /// これまで許可を付けたことがある全workspaceに対して`revoke-workspace`と同じ処理をする。
    /// 使用中のworkspaceは自動的にスキップされる（一覧に表示のみ）。
    RevokeWorkspaceAll,
}

/// `harness fs`サブコマンドのディスパッチ（プロバイダ資格情報・workspace sandboxのいずれも
/// 必要としない、起動パイプラインとは独立の経路）。
pub fn run_fs_subcommand(action: FsAction) -> ExitCode {
    // [BUG-112 / D-89] traverse台帳の未確定の予定を、**この経路の入口で1回だけ**畳む。
    // ここに置くのは、traverse台帳を読む`harness fs`側の口が4つあるためである
    // （`list`・`prune`・`revoke-traverse`・`revoke-traverse-all`）。それぞれに書くと、
    // 次に足された5つ目が黙って素通りする（`B-06`）。もう一方の配線点は`preflight`で、
    // 合わせて読み手6経路すべてがどちらかを通る。
    //
    // 畳まないと、UACを断った回に積まれた「実体の無い予定」が`list`では付与済みと同じ行で
    // 表示され、`revoke-traverse-all`では件数に数えられる。
    #[cfg(windows)]
    harness_sandbox::tier2a::traverse_ledger::settle_pending_traverse_grants();
    match action {
        FsAction::List => {
            let ledger = load_fs_ledger();
            println!("=== fs passthrough (--fs-allow) ===");
            if ledger.entries.is_empty() {
                println!("(none)");
            }
            for e in &ledger.entries {
                // [D-63] 範囲を出す。**`ro`/`rw`だけでは「どこまで」が読めない**——同じ`ro`でも
                // オブジェクト単体とサブツリー全体では意味がまるで違う（そこがD-62/D-63の主題）。
                // これは台帳の記録であって実DACLではない旨は`FsLedgerEntry::scope`のdocが持つ。
                println!(
                    "{}\t{}\t{}{}\tgranted_at_unix={}",
                    e.path,
                    if e.writable { "rw" } else { "ro" },
                    e.scope.label(),
                    if e.forced { " [forced]" } else { "" },
                    e.granted_at_unix_secs
                );
            }
            let traverse_ledger = harness_sandbox::tier2a::traverse_ledger::load_traverse_ledger();
            println!("=== traverse grants (grant-traverse) ===");
            if traverse_ledger.entries.is_empty() {
                println!("(none)");
            }
            for e in &traverse_ledger.entries {
                println!("{}\tgranted_at_unix={}", e.path, e.granted_at_unix_secs);
            }
            #[cfg(windows)]
            {
                let workspace_ledger =
                    harness_sandbox::tier2a::workspace_ledger::load_workspace_ledger();
                println!("=== workspace grants (preflight) ===");
                if workspace_ledger.entries.is_empty() {
                    println!("(none)");
                }
                for e in &workspace_ledger.entries {
                    use harness_sandbox::tier2a::win_appcontainer::{
                        workspace_preparation_state, WorkspacePreparationState,
                    };
                    let live = harness_sandbox::tier2a::workspace_ledger::live_modes(
                        &PathBuf::from(&e.path),
                    );
                    let use_status = if live.is_empty() {
                        "idle".to_string()
                    } else {
                        format!("in use: {}", live.join(", "))
                    };
                    let preparation = match e.mode.as_str() {
                        "rwx" => Some(WorkspaceMode::Rwx),
                        "ro" => Some(WorkspaceMode::Ro),
                        _ => None,
                    }
                    .map(|mode| workspace_preparation_state(&PathBuf::from(&e.path), mode));
                    let preparation_status = match preparation {
                        Some(Ok(WorkspacePreparationState::Unprepared)) => "unprepared".to_string(),
                        Some(Ok(WorkspacePreparationState::Preparing)) => "preparing".to_string(),
                        Some(Ok(WorkspacePreparationState::Ready)) => "ready".to_string(),
                        Some(Ok(WorkspacePreparationState::Stale)) => "stale".to_string(),
                        Some(Ok(WorkspacePreparationState::Failed(reason))) => {
                            format!("failed: {reason}")
                        }
                        Some(Err(reason)) => format!("stale: {reason}"),
                        None => "stale: unknown mode".to_string(),
                    };
                    println!(
                        "{}\tmode={}\tgranted_at_unix={}\tpreparation={}\t{use_status}",
                        e.path, e.mode, e.granted_at_unix_secs, preparation_status
                    );
                }
            }
            println!("=== denied fs passthrough candidates ===");
            if ledger.denied_entries.is_empty() {
                println!("(none)");
            }
            for e in &ledger.denied_entries {
                println!(
                    "{}\t{}\tcount={}\tlast_denied_at_unix={}\t{}",
                    e.path, e.access, e.count, e.last_denied_at_unix_secs, e.reason
                );
            }
            ExitCode::SUCCESS
        }
        FsAction::Denied => {
            let ledger = load_fs_ledger();
            if ledger.denied_entries.is_empty() {
                println!("(no denied fs passthrough candidates recorded)");
            }
            for e in &ledger.denied_entries {
                println!(
                    "{}\t{}\tcount={}\tlast_denied_at_unix={}\t{}",
                    e.path, e.access, e.count, e.last_denied_at_unix_secs, e.reason
                );
            }
            ExitCode::SUCCESS
        }
        FsAction::PrepareWorkspace { path, mode } => fs_prepare_workspace(&path, mode),
        FsAction::Revoke { path } => fs_revoke_one(&path),
        FsAction::RevokeAll => fs_revoke_all(),
        FsAction::Prune { dry_run } => fs_prune(dry_run),
        FsAction::GrantTraverse { target, dry_run } => {
            if dry_run {
                fs_grant_traverse_preview(&target)
            } else {
                fs_grant_traverse(&target)
            }
        }
        FsAction::RevokeWorkspace { path } => fs_revoke_workspace(&path),
        FsAction::RevokeWorkspaceAll => fs_revoke_workspace_all(),
        FsAction::RevokeTraverse { path } => fs_revoke_traverse_one(&path),
        // **単発版をループしないこと。** 台帳の件数だけUACが出る（`B-02`、実機563件で操作不能）。
        FsAction::RevokeTraverseAll => fs_revoke_traverse_all(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum WorkspacePrepareMode {
    Rwx,
    Ro,
}

#[cfg(test)]
mod argument_tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn workspace_prepare_modes_use_the_public_rwx_and_ro_vocabulary() {
        assert_eq!(WorkspacePrepareMode::value_variants().len(), 2);
        assert_eq!(
            WorkspacePrepareMode::Rwx
                .to_possible_value()
                .unwrap()
                .get_name(),
            "rwx"
        );
        assert_eq!(
            WorkspacePrepareMode::Ro
                .to_possible_value()
                .unwrap()
                .get_name(),
            "ro"
        );
    }

    #[test]
    fn prepare_workspace_is_wired_into_the_real_cli_and_unknown_modes_are_rejected() {
        crate::cli::Cli::try_parse_from([
            "harness",
            "fs",
            "prepare-workspace",
            r"C:\work",
            "--mode",
            "ro",
        ])
        .expect("public prepare-workspace spelling must parse");
        assert!(crate::cli::Cli::try_parse_from([
            "harness",
            "fs",
            "prepare-workspace",
            r"C:\work",
            "--mode",
            "rw",
        ])
        .is_err());
    }
}
