//! `harness fs prune` — 実在しないパスを指す台帳エントリを落とす（D-53）。
//!
//! 台帳は`preflight`が起動のたびに追記する一方、明示的な`revoke-*`を呼ばない限り誰も消さない
//! ため記録が積もる。判定規則（何を「消えた」と見なすか、なぜボリューム到達性で裏取りするか）は
//! [`harness_grant_ledger::prune`]のモジュールdocが持つ。ここが持つのは**4台帳を順に掃いて
//! 内訳を報告する**という手続きだけである。
//!
//! **この機能はACEを一切撤収しない。** 触るのは台帳の記録だけで、実ACLには読み取りでしか
//! 触れない（実在するパスは残すので、そもそも撤収すべきものが判定対象に残らない）。ACEを
//! 剥がしたいなら`fs revoke`/`revoke-traverse`/`revoke-workspace`を使う。

use std::path::Path;
use std::process::ExitCode;

use harness_grant_ledger::prune::{verdict_for, PruneVerdict};

use super::prune_fs_ledger_entries;

/// 1台帳ぶんの内訳。`removed`以外は「残した理由」の内訳になる。
#[derive(Default)]
struct LedgerReport {
    removed: Vec<String>,
    alive: usize,
    /// ボリュームへ到達できず判定できなかったパス。**黙って飛ばさず名指しで出す**
    /// （D-43「失敗を隠さない」と同じ思想。「掃除したのに減らない」の理由が分かるように）。
    unreachable: Vec<String>,
    roots: usize,
}

impl LedgerReport {
    fn print(&self, ledger_name: &str, dry_run: bool) {
        let verb = if dry_run { "would remove" } else { "removed" };
        println!(
            "=== {ledger_name} === {} {}, kept {} (alive) + {} (unreachable) + {} (root)",
            self.removed.len(),
            verb,
            self.alive,
            self.unreachable.len(),
            self.roots
        );
        for path in &self.removed {
            println!("  - {path}");
        }
        for path in &self.unreachable {
            println!(
                "  ? {path} (volume not reachable; keeping the entry -- the object and its ACE may \
                 still be alive on an unmounted or offline volume)"
            );
        }
    }
}

/// 与えられたパス一覧を判定し、落とす対象を`should_remove`側へ伝えるための集計器。
///
/// 台帳ごとに「まず全エントリを判定して内訳を作る」→「`Gone`だったものだけを落とす」の2段に
/// 分けてある。台帳側の`prune_*_entries`が受け取るのは述語なので、内訳（`alive`/`root`の件数）は
/// ここで別途数えておかないと報告に出せない。
fn classify_all(paths: &[String]) -> (LedgerReport, Vec<String>) {
    let mut report = LedgerReport::default();
    let mut gone = Vec::new();
    for path in paths {
        match verdict_for(Path::new(path)) {
            PruneVerdict::Gone => gone.push(path.clone()),
            PruneVerdict::Alive => report.alive += 1,
            PruneVerdict::Unreachable => report.unreachable.push(path.clone()),
            PruneVerdict::Root => report.roots += 1,
        }
    }
    (report, gone)
}

/// `harness fs prune [--dry-run]` の本体。
pub(crate) fn fs_prune(dry_run: bool) -> ExitCode {
    if dry_run {
        println!("(dry run: no ledger is modified)");
    }

    let mut total_removed = 0usize;
    let mut total_unreachable = 0usize;

    // --- fs passthrough（entries + denied_entries） ---
    let ledger = super::load_fs_ledger();
    let fs_paths: Vec<String> = ledger
        .entries
        .iter()
        .map(|e| e.path.clone())
        .chain(ledger.denied_entries.iter().map(|e| e.path.clone()))
        .collect();
    let (mut report, gone) = classify_all(&fs_paths);
    if !dry_run && !gone.is_empty() {
        // 判定は上で済ませてあるので、述語は「その集合に入っているか」だけを見る
        // （台帳ロックを握っている間にFSを再観測しない＝ロック保持時間を延ばさない）。
        let removed = prune_fs_ledger_entries(|p| gone.contains(&p.to_string_lossy().to_string()));
        report.removed = removed;
    } else {
        report.removed = gone;
    }
    total_removed += report.removed.len();
    total_unreachable += report.unreachable.len();
    report.print("fs-passthrough-ledger.json", dry_run);

    // --- traverse ---
    let traverse = harness_sandbox::tier2a::traverse_ledger::load_traverse_ledger();
    let traverse_paths: Vec<String> = traverse.entries.iter().map(|e| e.path.clone()).collect();
    let (mut report, gone) = classify_all(&traverse_paths);
    if !dry_run && !gone.is_empty() {
        report.removed = harness_sandbox::tier2a::traverse_ledger::prune_traverse_entries(|p| {
            gone.contains(&p.to_string_lossy().to_string())
        });
    } else {
        report.removed = gone;
    }
    total_removed += report.removed.len();
    total_unreachable += report.unreachable.len();
    report.print("traverse-grant-ledger.json", dry_run);

    // --- workspace ---
    #[cfg(windows)]
    {
        let workspace = harness_sandbox::tier2a::workspace_ledger::load_workspace_ledger();
        let workspace_paths: Vec<String> =
            workspace.entries.iter().map(|e| e.path.clone()).collect();
        let (mut report, gone) = classify_all(&workspace_paths);
        if !dry_run && !gone.is_empty() {
            report.removed =
                harness_sandbox::tier2a::workspace_ledger::prune_workspace_entries(|p| {
                    gone.contains(&p.to_string_lossy().to_string())
                });
        } else {
            report.removed = gone;
        }
        total_removed += report.removed.len();
        total_unreachable += report.unreachable.len();
        report.print("workspace-grant-ledger.json", dry_run);
    }

    // --- workspace capability（D-54） ---
    //
    // 使い捨てworkspace（テストのtempdir等）を開くたびに1件増えるので、掃かないと
    // **秘密の記録が際限なく積もる**。消えたツリーのACEを撤収できなくなる心配は無い
    // ——ツリーが無いので撤収すべきものが存在しない。
    #[cfg(windows)]
    {
        let entries = harness_sandbox::tier2a::workspace_capability::all_entries();
        let paths: Vec<String> = entries.iter().map(|e| e.workspace.clone()).collect();
        let (mut report, gone) = classify_all(&paths);
        if !dry_run && !gone.is_empty() {
            report.removed =
                harness_sandbox::tier2a::workspace_capability::prune_capability_entries(|p| {
                    gone.contains(&p.to_string_lossy().to_string())
                });
        } else {
            report.removed = gone;
        }
        total_removed += report.removed.len();
        total_unreachable += report.unreachable.len();
        report.print("workspace-capability-ledger.json", dry_run);
    }

    println!();
    if dry_run {
        println!("{total_removed} entries would be removed (re-run without --dry-run to apply)");
    } else {
        println!("{total_removed} entries removed");
    }
    if total_unreachable > 0 {
        println!(
            "{total_unreachable} entries were left alone because their volume is not reachable \
             right now; reconnect the volume and re-run if you want them evaluated"
        );
    }
    ExitCode::SUCCESS
}
