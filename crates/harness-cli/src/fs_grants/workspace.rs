//! preflightがworkspace本体へ付与した継承ACEの撤収（`harness fs revoke-workspace` /
//! `revoke-workspace-all`）。生存中のセッションが使っているworkspaceは撤収しない
//! （判定は`workspace_ledger`の名前付きmutex）。

use super::progress::{Spinner, WalkProgress};
use super::*;

/// workspace本体のACE（`preflight`が毎回付与するRWX/RO）を撤収する。名前付きmutexで
/// 「今もこのworkspaceを使っている他のharnessセッションが無いか」を確認してから撤収する
/// （`harness_sandbox::tier2a::workspace_ledger`参照）。CoWのdiff_layer_dirには一切触れない。
///
/// [BUG-082] 撤収対象のSID（workspace capability最大2＋撤収可能なharnessプロファイル）を
/// 先に全て解決し、`revoke_workspace_sids_recursive`で**1回のツリー走査**に一括する。
/// 旧実装はSIDごとに`revoke_ace_recursive`を呼び直しており、D-54以降ツリーのACEは
/// capability SID宛（プロファイルSID宛ではない）なので、プロファイルSIDでの撤収walkは
/// 全ノードが空振りの読取+書込になっていた（docs/bugs/BUG-082.md）。
#[cfg(windows)]
pub(crate) fn fs_revoke_workspace(path: &Path) -> ExitCode {
    // [BUG-082フォローアップ] canonicalize〜SID解決は通常ミリ秒オーダーだが、ユーザーからの
    // 実機報告により「最初の1行が出るまで無反応に見える」区間がある以上、ここも空で待たせない。
    let mut spinner = Some(Spinner::start(
        "harness: preparing to revoke workspace access...",
    ));

    let canonical = match path.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            drop(spinner.take());
            eprintln!("failed to canonicalize {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let live = harness_sandbox::tier2a::workspace_ledger::live_modes(&canonical);
    if !live.is_empty() {
        drop(spinner.take());
        eprintln!(
            "workspace {} is still in use by another harness session (mode(s): {}); refusing \
             to revoke",
            canonical.display(),
            live.join(", ")
        );
        return ExitCode::FAILURE;
    }

    // D-54: workspaceツリーのACEの**現在の主体**は、workspace＋モード単位のcapability SIDで
    // ある。これはセッションより長生きする（明示的に消すまで残る）ので、`fs revoke-workspace`が
    // 唯一の撤収経路になる。D-37時代の残骸（package SID宛のACE）も同じ機会に剥がす。撤収対象は
    // 「旧共有プロファイル」＋「生きていないセッションのプロファイル」で、実行中のセッションの
    // ぶんは触らない（実行中の他セッションから権限を奪わない、BUG-053と同じ原則）。
    //
    // [D-84] **付与が2本なら撤収も2本である。** `preflight`は起動のたびに全モードのバッジ宛
    // ACEを配るので、ここが自モードのぶんだけを剥がすと**もう一方のバッジ宛ACEがツリーに
    // 残る**——しかもその主体は台帳を消した瞬間に導出できなくなり、どのコマンドでも剥がせない
    // （[BUG-101](../../../docs/bugs/BUG-101.md)と同型）。だから回すのは
    // `WorkspaceMode::ALL`であって「いま走っているモード」ではない（`B-01`）。
    //
    // **秘密から導出し直すのではなく、台帳に載っている名前を索引にする。** 台帳に無い＝
    // 一度も配っていないので、`lookup_`（発行しない側）で足りる。
    let mut resolve_failures = Vec::new();
    let mut capability_targets = Vec::new();
    for mode in harness_sandbox::tier2a::workspace_ledger::WorkspaceMode::ALL {
        let mode = mode.as_str();
        let Some(name) =
            harness_sandbox::tier2a::workspace_capability::lookup_capability_name(&canonical, mode)
        else {
            continue;
        };
        match harness_sandbox::tier2a::win_appcontainer::workspace_capability_sid(&canonical, mode)
        {
            Ok(sid) => capability_targets.push((mode, name, sid)),
            Err(e) => resolve_failures.push(format!("{name} ({mode}): failed to resolve SID: {e}")),
        }
    }
    let mut profile_targets = Vec::new();
    for profile in harness_sandbox::tier2a::session_profile::revocable_profile_names() {
        // [BUG-101] 撤収側は`ensure_profile`（存在しなければ作る）を通さない。剥がしに来た
        // コマンドが削除済みプロファイルを復活させてしまう（`derive_profile_sid`のdoc）。
        match harness_sandbox::tier2a::win_appcontainer::derive_profile_sid(&profile) {
            Ok(sid) => profile_targets.push((profile, sid)),
            Err(e) => resolve_failures.push(format!("{profile}: failed to resolve SID: {e}")),
        }
    }
    if !resolve_failures.is_empty() {
        drop(spinner.take());
        eprintln!(
            "failed to revoke workspace access for {}: {}",
            canonical.display(),
            resolve_failures.join("; ")
        );
        return ExitCode::FAILURE;
    }
    if capability_targets.is_empty() && profile_targets.is_empty() {
        drop(spinner.take());
        harness_sandbox::tier2a::workspace_ledger::remove_workspace_entry(&canonical);
        // 台帳が空でも、過去のセッションが`.harness/**`へ立てた継承遮断は残り得る。
        report_harness_control_dir_unprotected(&canonical);
        println!("(nothing recorded to revoke for {})", canonical.display());
        return ExitCode::SUCCESS;
    }

    let all_sids: Vec<_> = capability_targets
        .iter()
        .map(|(_, _, sid)| sid.as_psid())
        .chain(profile_targets.iter().map(|(_, sid)| sid.as_psid()))
        .collect();

    drop(spinner.take());
    eprintln!(
        "harness: revoking workspace access for {} ({} workspace capability/capabilities, {} \
         harness profile(s))...",
        canonical.display(),
        capability_targets.len(),
        profile_targets.len()
    );

    // `collect_dirs_and_files`（walk本体の中）は対象数が定まるまで進捗を出せない。定まるまでは
    // スピナー、定まったら同じ行を数値進捗で上書きする（`progress::WalkProgress`）。
    let walk_progress = WalkProgress::start(
        "harness: scanning workspace tree...",
        "harness: revoking workspace access",
    );
    let result = harness_sandbox::tier2a::win_appcontainer::revoke_workspace_sids_recursive(
        &canonical,
        &all_sids,
        &|done, total| walk_progress.on_progress(done, total),
    );
    let last_reported = walk_progress.last_reported();
    walk_progress.finish();

    match result {
        Ok(report) => {
            // ACEを剥がし終えてから台帳を落とす——順序が逆だと主体を引けなくなり、撤収経路の
            // 無い孤立ACEがツリーに残る（`forget_capability`のdoc、BUG-017/BUG-059と同じ不変条件）。
            for (mode, _, _) in &capability_targets {
                harness_sandbox::tier2a::workspace_capability::forget_capability(&canonical, mode);
            }
            harness_sandbox::tier2a::workspace_ledger::remove_workspace_entry(&canonical);
            report_harness_control_dir_unprotected(&canonical);
            println!(
                "revoked workspace access for {}: checked {} node(s), rewrote {} node(s) \
                 ({} workspace capability/capabilities, {} harness profile(s))",
                canonical.display(),
                report.checked,
                report.rewritten,
                capability_targets.len(),
                profile_targets.len()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            // 台帳エントリは意図的に残す——どのノードまで剥がせたか（＝どのSIDが本当に
            // 消えたか）が分からない部分完了なので、ここで`forget_capability`すると
            // 撤収経路の無い孤立ACEを作りかねない。再実行すれば同じ対象を再度解決できる。
            eprintln!(
                "failed to revoke workspace access for {}: {e} (checked up to node {}; workspace \
                 capability and profile ledger entries were left intact so a retry finds the same \
                 targets)",
                canonical.display(),
                last_reported
            );
            ExitCode::FAILURE
        }
    }
}

/// [BUG-083] `.harness/**`に立てた継承遮断（`SE_DACL_PROTECTED`）を落として報告する。
///
/// **必ずACEの撤収walkが終わった後に呼ぶこと。** 解除はaclapiに継承を計算し直させる操作なので、
/// 先に呼ぶと**まだworkspace rootに残っているcapability SIDの継承ACEが`.harness/**`へ
/// 降りてきてしまう**（撤収の直前に制御面を汚す）。
///
/// 失敗は警告に留めてコマンド全体は失敗させない——ACEの撤収は既に完了しており、そちらが
/// セキュリティ上の本体である。保護が残ること自体は「ユーザーのリポジトリに余分な設定が
/// 残る」問題であって、権限が漏れる方向の失敗ではない。
#[cfg(windows)]
fn report_harness_control_dir_unprotected(canonical: &Path) {
    match harness_sandbox::tier2a::win_appcontainer::unprotect_harness_control_dir(canonical) {
        Ok(0) => {}
        Ok(n) => println!(
            "restored DACL inheritance on {n} node(s) under {}\\.harness (BUG-083 rollback)",
            canonical.display()
        ),
        Err(e) => eprintln!(
            "warning: failed to restore DACL inheritance under {}\\.harness: {e} (the ACEs were \
             revoked; re-run `harness fs revoke-workspace` or clear the \"disable inheritance\" \
             flag from Explorer's advanced security dialog)",
            canonical.display()
        ),
    }
}

#[cfg(not(windows))]
pub(crate) fn fs_revoke_workspace(_path: &Path) -> ExitCode {
    eprintln!("error: workspace revoke is Windows-only (Tier2a specific)");
    ExitCode::FAILURE
}

/// 記録済みの全workspaceに対して`fs_revoke_workspace`を試みる。使用中のworkspaceは
/// スキップし、それ以外を撤収する。
#[cfg(windows)]
pub(crate) fn fs_revoke_workspace_all() -> ExitCode {
    let ledger = harness_sandbox::tier2a::workspace_ledger::load_workspace_ledger();
    if ledger.entries.is_empty() {
        println!("(no workspace grants recorded)");
        return ExitCode::SUCCESS;
    }
    let mut any_failed = false;
    for entry in &ledger.entries {
        let path = PathBuf::from(&entry.path);
        let live = harness_sandbox::tier2a::workspace_ledger::live_modes(&path);
        if !live.is_empty() {
            println!(
                "skipping {} (in use by another harness session, mode(s): {})",
                path.display(),
                live.join(", ")
            );
            continue;
        }
        if fs_revoke_workspace(&path) != ExitCode::SUCCESS {
            any_failed = true;
        }
    }
    if any_failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(not(windows))]
pub(crate) fn fs_revoke_workspace_all() -> ExitCode {
    eprintln!("error: workspace revoke is Windows-only (Tier2a specific)");
    ExitCode::FAILURE
}
