//! `harness memory`サブコマンド（`Recall`の事後レビュー運用、`plans/PLAN-RECALL-MEMORY.md`
//! 「レビュー運用」）。
//!
//! 判断ロジック（bigram検索・checkpointの決定的変換・git履歴化）は`harness-cognition::recall`が
//! 持ち、このファイルはファイルI/Oの起点と表示だけを担う（`docs/CODE-STRUCTURE-RULES.md`規則3）。

use super::*;

use harness_cognition::{format_checkpoint_line, RecallStore, ReviewedWatermark, WorkspaceSummary};

fn open_store(workspace_root: &Path) -> Result<RecallStore, ExitCode> {
    match RecallStore::for_workspace(workspace_root) {
        Ok(store) => {
            if let Err(e) = store.open() {
                eprintln!("error: failed to open the recall store: {e}");
                return Err(ExitCode::FAILURE);
            }
            Ok(store)
        }
        Err(reason) => {
            eprintln!("error: {reason}");
            Err(ExitCode::FAILURE)
        }
    }
}

#[derive(serde::Serialize)]
struct CheckpointJson {
    id: String,
    created_at_ms: u64,
    summary: String,
    tags: Vec<String>,
    reviewed: bool,
}

pub(crate) fn run_memory_subcommand(action: MemoryAction, workspace_root: &Path) -> ExitCode {
    match action {
        MemoryAction::List { all, output_format } => run_list(workspace_root, all, output_format),
        MemoryAction::Show { id } => run_show(workspace_root, &id),
        MemoryAction::Review { mark_reviewed } => run_review(workspace_root, mark_reviewed),
        MemoryAction::Discard { id } => run_discard(workspace_root, &id),
        MemoryAction::Reindex => run_reindex(workspace_root),
        MemoryAction::Forget { yes } => run_forget(workspace_root, yes),
        MemoryAction::Gc { yes } => run_gc(yes),
    }
}

fn run_list(workspace_root: &Path, all: bool, output_format: OutputFormat) -> ExitCode {
    let Ok(store) = open_store(workspace_root) else {
        return ExitCode::FAILURE;
    };
    let list = if all {
        store.list()
    } else {
        store.unreviewed()
    };
    let list = match list {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: failed to list checkpoints: {e}");
            return ExitCode::FAILURE;
        }
    };
    let watermark = store.reviewed_watermark();

    match output_format {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<CheckpointJson> = list
                .iter()
                .map(|m| CheckpointJson {
                    id: m.id.clone(),
                    created_at_ms: m.created_at_ms,
                    summary: m.summary.clone(),
                    tags: m.tags.clone(),
                    reviewed: store.is_reviewed(m, &watermark),
                })
                .collect();
            match output_format {
                OutputFormat::Json => println!("{}", serde_json::to_string(&rows).unwrap()),
                OutputFormat::Jsonl => {
                    for row in rows {
                        println!("{}", serde_json::to_string(&row).unwrap());
                    }
                }
                OutputFormat::Text => unreachable!(),
            }
        }
        OutputFormat::Text => {
            if list.is_empty() {
                println!(
                    "{}",
                    if all {
                        "no checkpoints yet."
                    } else {
                        "no unreviewed checkpoints."
                    }
                );
                return ExitCode::SUCCESS;
            }
            for m in &list {
                println!("{}", format_checkpoint_line(m, store.is_reviewed(m, &watermark)));
            }
        }
    }
    ExitCode::SUCCESS
}

fn run_show(workspace_root: &Path, id: &str) -> ExitCode {
    let Ok(store) = open_store(workspace_root) else {
        return ExitCode::FAILURE;
    };
    match store.read(id) {
        Ok(cp) => {
            println!("{}", cp.to_file_contents());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: failed to read checkpoint {id}: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_review(workspace_root: &Path, mark_reviewed: bool) -> ExitCode {
    let Ok(store) = open_store(workspace_root) else {
        return ExitCode::FAILURE;
    };
    let unreviewed = match store.unreviewed() {
        Ok(u) => u,
        Err(e) => {
            eprintln!("error: failed to list unreviewed checkpoints: {e}");
            return ExitCode::FAILURE;
        }
    };
    if unreviewed.is_empty() {
        println!("no unreviewed checkpoints.");
        return ExitCode::SUCCESS;
    }
    for m in &unreviewed {
        println!("{}: {}", m.id, m.summary);
    }
    if mark_reviewed {
        // 辞書式で最大の(created_at_ms, id)を新しいウォーターマークにする（B-07）。
        if let Some(latest) = unreviewed
            .iter()
            .max_by(|a, b| (a.created_at_ms, &a.id).cmp(&(b.created_at_ms, &b.id)))
        {
            store.mark_reviewed(ReviewedWatermark {
                created_at_ms: latest.created_at_ms,
                id: latest.id.clone(),
            });
            println!("marked {} checkpoint(s) as reviewed.", unreviewed.len());
        }
    }
    ExitCode::SUCCESS
}

fn run_discard(workspace_root: &Path, id: &str) -> ExitCode {
    let Ok(store) = open_store(workspace_root) else {
        return ExitCode::FAILURE;
    };
    match store.discard(id) {
        Ok(()) => {
            println!("discarded {id}.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: failed to discard {id}: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_reindex(workspace_root: &Path) -> ExitCode {
    let Ok(store) = open_store(workspace_root) else {
        return ExitCode::FAILURE;
    };
    match store.rebuild_index() {
        Ok(()) => {
            println!("index rebuilt.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: failed to rebuild the index: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_forget(workspace_root: &Path, yes: bool) -> ExitCode {
    if !yes {
        eprintln!(
            "this deletes all checkpoints for this workspace. re-run with --yes to confirm."
        );
        return ExitCode::FAILURE;
    }
    let store = match RecallStore::for_workspace(workspace_root) {
        Ok(s) => s,
        Err(reason) => {
            eprintln!("error: {reason}");
            return ExitCode::FAILURE;
        }
    };
    match store.forget() {
        Ok(()) => {
            println!("forgot all checkpoints for this workspace.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: failed to forget this workspace's memory: {e}");
            ExitCode::FAILURE
        }
    }
}

/// **既定では何も削除しない**（設計変更G）。`--yes`はまだ実装しない——一覧だけを見て、
/// 個々の削除は`memory forget`をワークスペースごとに実行してもらう（一括削除の
/// ショートハンドを用意しない方針は`policy apply`の「全件受理」不採用と同じ理由）。
fn run_gc(yes: bool) -> ExitCode {
    let data_root = match RecallStore::data_root() {
        Ok(d) => d,
        Err(reason) => {
            eprintln!("error: {reason}");
            return ExitCode::FAILURE;
        }
    };
    let workspaces: Vec<WorkspaceSummary> = match RecallStore::list_all_workspaces(&data_root) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("error: failed to list workspaces: {e}");
            return ExitCode::FAILURE;
        }
    };
    if workspaces.is_empty() {
        println!("no recall data on this machine.");
        return ExitCode::SUCCESS;
    }
    for w in &workspaces {
        println!("{}: {} checkpoint(s)", w.workspace_root, w.checkpoint_count);
    }
    if yes {
        eprintln!(
            "note: --yes is not implemented for `memory gc` yet. use `memory forget` from \
             within the workspace you want to clear (path presence is not a safe deletion \
             signal — an unmounted drive looks identical to a deleted workspace)."
        );
    }
    ExitCode::SUCCESS
}
