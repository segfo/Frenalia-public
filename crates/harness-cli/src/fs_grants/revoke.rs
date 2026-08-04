//! 付与済みACEの撤収（`harness fs revoke` / `revoke-all`）と、`.harness/settings.json`の
//! 宣言に合わせた自動整合（D-27の`reconcile_fs_ledger_for_workspace`）。

use super::*;
/// `path`のfs passthrough ACEを、本体プロセス内（非管理者）で撤収を試み、3値で結果を返す
/// （D3: 再walk revoke、D4: 剥離後検証パス）。ユーザー所有パス（workspace・`%USERPROFILE%`配下等）は
/// ここで完結する。システム保護パス（`BUG-015`でヘルパー経由により付与できるようになったパス）は
/// root自体を撤収できず`Failed`になる（呼び出し側がヘルパーへエスカレーションする）。
/// `RootClearedDescendantsBlocked`は「rootは撤収できたが一部の子孫（TrustedInstaller所有等）に
/// ACEが残る」ケースで、孤立ACEにはならないため台帳から除去してよい（BUG-016のrevoke非対称の解消）。
/// `forced`（`--force-system-acl`で付与したエントリ）なら`SeRestorePrivilege`を有効化した状態で
/// 撤収する。非管理者プロセスでは特権を有効化できず`revoke_passthrough`が特権無しで走る
/// （システム保護パスならroot撤収に失敗し`Failed`→ヘルパーへエスカレーション）。管理者プロセス
/// （`is_elevated`）なら特権が有効化され、TrustedInstaller所有ノードも含めて撤収できる。
#[cfg(windows)]
pub(crate) fn revoke_passthrough_outcome(
    path: &Path,
    sid: &harness_sandbox::tier2a::win_appcontainer::OwnedContainerSid,
    forced: bool,
) -> harness_sandbox::tier2a::win_appcontainer::RevokeOutcome {
    if forced {
        harness_sandbox::tier2a::win_appcontainer::with_restore_privilege(|| {
            harness_sandbox::tier2a::win_appcontainer::revoke_passthrough(path, sid.as_psid())
        })
    } else {
        harness_sandbox::tier2a::win_appcontainer::revoke_passthrough(path, sid.as_psid())
    }
}

/// 撤収対象パスが台帳で`forced`（`--force-system-acl`）記録かを引く（無ければ`false`）。
#[cfg(windows)]
pub(crate) fn ledger_forced_flag(path: &Path) -> bool {
    let target = path.to_string_lossy();
    load_fs_ledger()
        .entries
        .iter()
        .any(|e| e.path == target && e.forced)
}

/// 指定パスのfs passthrough ACEを撤収する（`BUG-015`の裏対称: grant側と同じく
/// 「本体内試行→ヘルパーへエスカレーション」の2段構え）。成功時のみ台帳から除去する
/// （検証パスが残件を見つけた場合は台帳に残し、次回再試行できるようにする）。
#[cfg(windows)]
pub(crate) fn fs_revoke_one(path: &Path) -> ExitCode {
    let sid = match harness_sandbox::tier2a::win_appcontainer::ensure_profile(
        harness_sandbox::tier2a::win_appcontainer::CONTAINER_NAME,
    ) {
        Ok(sid) => sid,
        Err(e) => {
            eprintln!("failed to resolve sandbox SID: {e}");
            return ExitCode::FAILURE;
        }
    };
    // D-37: fs-allowの穴はセッション固有SID宛にもなり得る。**生きていないセッション**のぶんを
    // 先に非昇格で剥がしておく（実行中のセッションのACEは触らない）。旧共有プロファイル宛の
    // 撤収は下の既存フロー（昇格エスカレーション付き）がそのまま担当する。
    //
    // **既知の限界**: 死んだセッションがシステム保護パスへ付けたACEは、ここでは剥がせない
    // （昇格が要る）。ただしそのSIDは二度と生成されないため、残っても不活性である。
    for profile in harness_sandbox::tier2a::session_profile::revocable_profile_names()
        .into_iter()
        .filter(|p| harness_sandbox::tier2a::session_profile::is_session_profile_name(p))
    {
        if let Ok(dead_sid) = harness_sandbox::tier2a::win_appcontainer::ensure_profile(&profile) {
            let _ = harness_sandbox::tier2a::win_appcontainer::revoke_ace_recursive(
                path,
                dead_sid.as_psid(),
            );
        }
    }

    let forced = ledger_forced_flag(path);
    use harness_sandbox::tier2a::win_appcontainer::RevokeOutcome;
    match revoke_passthrough_outcome(path, &sid, forced) {
        RevokeOutcome::FullyRevoked => {
            remove_fs_passthrough_grant(path);
            println!("revoked: {}", path.display());
            return ExitCode::SUCCESS;
        }
        RevokeOutcome::RootClearedDescendantsBlocked => {
            remove_fs_passthrough_grant(path);
            println!(
                "revoked: {} (root and all writable nodes cleared; some TrustedInstaller-owned \
                 descendants keep ACEs beyond our control -- not orphaned, entry removed from ledger)",
                path.display()
            );
            return ExitCode::SUCCESS;
        }
        RevokeOutcome::Failed => {}
    }

    // 本体内で完結しなかった（システム保護パスの可能性）→特権分離ヘルパーへ委譲する。
    if harness_sandbox::tier2a::privhelper::is_elevated() {
        // 本体が既に管理者（§5.3、fs_grant_traverse_directと同じ考え方）: 直接再試行する。
        match revoke_passthrough_outcome(path, &sid, forced) {
            RevokeOutcome::FullyRevoked | RevokeOutcome::RootClearedDescendantsBlocked => {
                remove_fs_passthrough_grant(path);
                println!("revoked: {}", path.display());
                return ExitCode::SUCCESS;
            }
            RevokeOutcome::Failed => {
                eprintln!(
                    "revoke failed for {} (already running elevated)",
                    path.display()
                );
                return ExitCode::FAILURE;
            }
        }
    }
    let revoke_entry = harness_sandbox::tier2a::privhelper::FsAllowRevoke {
        path: path.to_path_buf(),
        forced,
    };
    match harness_sandbox::tier2a::privhelper::run_privileged_revoke_fs_allow(vec![revoke_entry]) {
        Ok((revoked, root_cleared, failures)) => {
            let cleared = revoked.iter().chain(root_cleared.iter()).any(|p| p == path);
            // 撤収できたパス（root_cleared含む）は台帳から除去する。
            for p in revoked.iter().chain(root_cleared.iter()) {
                remove_fs_passthrough_grant(p);
            }
            if failures.is_empty() && cleared {
                println!(
                    "revoked via privilege-separation helper (UAC, one-time): {}",
                    path.display()
                );
                ExitCode::SUCCESS
            } else {
                eprintln!(
                    "revoke incomplete for {} via privilege-separation helper:",
                    path.display()
                );
                for (p, reason) in &failures {
                    eprintln!("  {} : {reason}", p.display());
                }
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("revoke failed for {}: {e}", path.display());
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
pub(crate) fn fs_revoke_one(_path: &Path) -> ExitCode {
    eprintln!("error: fs passthrough revoke is Windows-only (Tier2a specific)");
    ExitCode::FAILURE
}

/// `entries`のfs passthrough ACEを撤収する共通処理（元は`fs_revoke_all`本体）。まず全エントリを
/// 本体内で試行し（UAC無し）、残ったパスだけを**1回のヘルパー要求へまとめて**エスカレーションする
/// （`BUG-015`決定：起動あたりUAC最小化、grant側`preflight`と同じ考え方）。撤収に成功したパスは
/// `on_revoked`で台帳から除去する（`fs_revoke_all`は常に除去、`reconcile_fs_ledger_for_workspace`は
/// TOCTOU再チェック付きの除去を渡す。D-27）。返り値は`(実際に撤収できたパス, (失敗パス, 理由))`。
#[cfg(windows)]
pub(crate) fn revoke_fs_ledger_entries(
    entries: &[FsLedgerEntry],
    note: &str,
    on_revoked: fn(&Path),
) -> (Vec<PathBuf>, Vec<(PathBuf, String)>) {
    let sid = match harness_sandbox::tier2a::win_appcontainer::ensure_profile(
        harness_sandbox::tier2a::win_appcontainer::CONTAINER_NAME,
    ) {
        Ok(sid) => sid,
        Err(e) => {
            let reason = format!("failed to resolve sandbox SID: {e}");
            return (
                Vec::new(),
                entries
                    .iter()
                    .map(|entry| (PathBuf::from(&entry.path), reason.clone()))
                    .collect(),
            );
        }
    };

    use harness_sandbox::tier2a::win_appcontainer::RevokeOutcome;
    let mut remaining: Vec<harness_sandbox::tier2a::privhelper::FsAllowRevoke> = Vec::new();
    let mut revoked_paths: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let path = PathBuf::from(&entry.path);
        match revoke_passthrough_outcome(&path, &sid, entry.forced) {
            RevokeOutcome::FullyRevoked => {
                on_revoked(&path);
                println!("{note}: {}", path.display());
                revoked_paths.push(path);
            }
            RevokeOutcome::RootClearedDescendantsBlocked => {
                on_revoked(&path);
                println!(
                    "{note}: {} (root cleared; TrustedInstaller-owned descendants beyond our \
                     control -- not orphaned)",
                    path.display()
                );
                revoked_paths.push(path);
            }
            RevokeOutcome::Failed => remaining.push(harness_sandbox::tier2a::privhelper::FsAllowRevoke {
                path,
                forced: entry.forced,
            }),
        }
    }

    if remaining.is_empty() {
        return (revoked_paths, Vec::new());
    }

    let escalated: Result<harness_sandbox::tier2a::privhelper::FsAllowRevokeOutcome, String> =
        if harness_sandbox::tier2a::privhelper::is_elevated() {
            // 本体が既に管理者: 直接再試行する（ヘルパーもUACも不要）。
            let mut revoked = Vec::new();
            let mut root_cleared = Vec::new();
            let mut failures = Vec::new();
            for entry in &remaining {
                match revoke_passthrough_outcome(&entry.path, &sid, entry.forced) {
                    RevokeOutcome::FullyRevoked => revoked.push(entry.path.clone()),
                    RevokeOutcome::RootClearedDescendantsBlocked => {
                        root_cleared.push(entry.path.clone())
                    }
                    RevokeOutcome::Failed => failures.push((
                        entry.path.clone(),
                        "revoke failed (already running elevated)".to_string(),
                    )),
                }
            }
            Ok((revoked, root_cleared, failures))
        } else {
            harness_sandbox::tier2a::privhelper::run_privileged_revoke_fs_allow(remaining.clone())
                .map_err(|e| e.to_string())
        };

    match escalated {
        Ok((revoked, root_cleared, failures)) => {
            for path in revoked.iter().chain(root_cleared.iter()) {
                on_revoked(path);
                println!(
                    "{note} via privilege-separation helper (UAC, one-time): {}",
                    path.display()
                );
                revoked_paths.push(path.clone());
            }
            (revoked_paths, failures)
        }
        Err(reason) => {
            let failures = remaining
                .iter()
                .map(|entry| (entry.path.clone(), reason.clone()))
                .collect();
            (revoked_paths, failures)
        }
    }
}

/// 台帳の全fs passthroughエントリを撤収する（`harness fs revoke-all`本体）。
#[cfg(windows)]
pub(crate) fn fs_revoke_all() -> ExitCode {
    let ledger = load_fs_ledger();
    if ledger.entries.is_empty() {
        println!("(no fs passthrough entries)");
        return ExitCode::SUCCESS;
    }
    let (_, failures) = revoke_fs_ledger_entries(&ledger.entries, "revoked", remove_fs_passthrough_grant);
    if failures.is_empty() {
        ExitCode::SUCCESS
    } else {
        for (path, reason) in &failures {
            eprintln!("revoke incomplete for {} : {reason}", path.display());
        }
        ExitCode::FAILURE
    }
}

#[cfg(not(windows))]
pub(crate) fn fs_revoke_all() -> ExitCode {
    eprintln!("error: fs passthrough revoke is Windows-only (Tier2a specific)");
    ExitCode::FAILURE
}

/// 起動のたびに、このワークスペースの`.harness/settings.json`が現在宣言しているfs passthrough
/// パス集合（`settings_fs_paths`）と台帳の`settings_workspaces`参照カウントを突き合わせ、
/// (1)このワークスペースが新規に宣言したパスへタグを追加し、(2)もう宣言していないパスから
/// タグを外す（D-27）。タグを外した結果、どのワークスペースからも参照されなくなった
/// `settings_managed`エントリだけをACE撤収対象にする（`--fs-allow`専用のエントリは
/// `settings_managed`が立たないため対象外＝既存のsticky挙動を維持）。
/// Tier2aが実際に選択されるかどうかとは独立に、`select_tier`（preflight）より前に毎回呼ぶ。
#[cfg(windows)]
pub fn reconcile_fs_ledger_for_workspace(
    workspace_root: &Path,
    settings_fs_paths: &std::collections::HashSet<String>,
) {
    let ws = workspace_root.to_string_lossy().into_owned();
    let orphan_candidates: Vec<FsLedgerEntry> = fs_ledger().update(|ledger| {
        for entry in ledger.entries.iter_mut() {
            let declared_now = settings_fs_paths.contains(&entry.path);
            let was_tagged = entry.settings_workspaces.iter().any(|w| w == &ws);
            if declared_now && !was_tagged {
                entry.settings_workspaces.push(ws.clone());
                entry.settings_managed = true;
            } else if !declared_now && was_tagged {
                entry.settings_workspaces.retain(|w| w != &ws);
            }
        }
        ledger
            .entries
            .iter()
            .filter(|entry| entry.settings_managed && entry.settings_workspaces.is_empty())
            .cloned()
            .collect()
    });

    if orphan_candidates.is_empty() {
        return;
    }
    eprintln!(
        "note: the following fs passthrough paths are no longer declared by any workspace's \
         .harness/settings.json; auto-revoking their ACE (D-27):"
    );
    for entry in &orphan_candidates {
        eprintln!("  {}", entry.path);
    }
    let (_, failures) = revoke_fs_ledger_entries(
        &orphan_candidates,
        "auto-revoked",
        remove_fs_passthrough_grant_if_still_orphaned,
    );
    for (path, reason) in &failures {
        eprintln!("warning: auto-revoke failed for {} : {reason}", path.display());
    }
}

