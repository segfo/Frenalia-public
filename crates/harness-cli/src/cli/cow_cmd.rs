//! `harness cow`サブコマンド。CoW差分層の一覧・回収（GC、D-82）と、ACLで拒否された
//! 書込試行の監査ログ表示。
//!
//! 差分層の置き場はワークスペースのボリュームで決まる（D-81）ので、**根は1つではない**。
//! 列挙・解決はすべて`harness_sandbox::session_scope`（写像の正本）を通す。

use super::*;

#[cfg(windows)]
pub(crate) fn run_cow_subcommand(action: CowAction) -> ExitCode {
    match action {
        CowAction::List => cow_list(),
        CowAction::Audit {
            session,
            output_format,
        } => cow_audit(session.as_deref(), output_format),
        CowAction::Gc {
            dry_run,
            with_changes,
            older_than_days,
        } => cow_gc(dry_run, with_changes, older_than_days),
    }
}

#[cfg(not(windows))]
pub(crate) fn run_cow_subcommand(_action: CowAction) -> ExitCode {
    eprintln!("error: harness cow is Windows-only (Tier2a --cow specific)");
    ExitCode::FAILURE
}

/// セッションIDから差分層の位置を引く。**全部の根を探す**（D-81で根が複数になった）。
#[cfg(windows)]
pub(crate) fn cow_upper_dir_for(session_id: &str) -> Option<PathBuf> {
    let (roots, _unreachable) = harness_sandbox::session_scope::cow_upper_roots();
    roots
        .into_iter()
        .map(|root| harness_sandbox::session_scope::cow_upper_dir_in(&root, session_id))
        .find(|dir| dir.is_dir())
}

/// `harness cow audit`: `.harness-cow-denied.jsonl`（Phase 4、設計書§19.8）を表示する。
#[cfg(windows)]
pub(crate) fn cow_audit(session: Option<&str>, output_format: OutputFormat) -> ExitCode {
    let Some(upper_dir) = resolve_cow_upper_dir(session) else {
        eprintln!("no CoW upper directory found (nothing to show)");
        return ExitCode::FAILURE;
    };
    let entries = harness_change_ledger::store::read_denied_log(&upper_dir);
    match output_format {
        OutputFormat::Json => {
            if let Ok(s) = serde_json::to_string(&entries) {
                println!("{s}");
            }
        }
        OutputFormat::Jsonl => {
            for e in &entries {
                if let Ok(s) = serde_json::to_string(e) {
                    println!("{s}");
                }
            }
        }
        OutputFormat::Text => {
            if entries.is_empty() {
                println!("(no denied write attempts recorded)");
            }
            // BUG-066: workspace内への拒否は意味が正反対（封じ込めではなく**透過性の失敗**＝
            // その変更は失われている）なので、1件ずつ区別して見せる。
            let workspace_root = crate::cli::workspace_cmd::cow_session_workspace_root(&upper_dir);
            let mut inside = 0usize;
            for e in &entries {
                let is_inside = workspace_root.as_deref().is_some_and(|root| {
                    harness_change_ledger::path_rules::relative_under_root(&e.path, root).is_some()
                });
                if is_inside {
                    inside += 1;
                }
                println!(
                    "denied: {} (access_mask={:#x}, pid={}){}",
                    e.path,
                    e.access_mask,
                    e.pid,
                    if is_inside {
                        "  <-- INSIDE the workspace: the CoW redirect failed here, this change was lost"
                    } else {
                        ""
                    }
                );
            }
            if inside > 0 {
                println!(
                    "WARNING: {inside} of {} denied attempt(s) targeted the workspace itself. \
                     Those writes should have been redirected to the CoW upper directory; see \
                     docs/bugs/BUG-066.md.",
                    entries.len()
                );
            }
        }
    }
    ExitCode::SUCCESS
}

#[cfg(windows)]
pub(crate) fn cow_list() -> ExitCode {
    use harness_sandbox::tier2a::workspace_ledger as wl;

    let (facts, unreachable) = wl::collect_cow_session_facts();
    if facts.is_empty() {
        println!("(no CoW upper directories found)");
        report_unreachable_volumes(unreachable);
        return ExitCode::SUCCESS;
    }
    // 表示する状態は**GCが使うのと同じ判定**から引く（`bug-pattern-rules` B-13: 同じ事実の
    // 正本を2つ持たない）。一覧が「空」と言うのにGCが回収しない、という食い違いが起きない。
    let verdicts = wl::plan_cow_gc(
        &facts,
        harness_grant_ledger::now_unix_secs(),
        wl::COW_GC_DEFAULT_GRACE_SECS,
        cow_gc_policy(),
    );
    for (fact, (_, verdict)) in facts.iter().zip(verdicts) {
        println!(
            "{}\tworkspace={}\t{}\tchanged_files={}\tupper={}",
            fact.session_id,
            fact.workspace_root
                .as_deref()
                .unwrap_or("(unknown, no readable session metadata)"),
            state_label(verdict),
            fact.content_files,
            fact.upper_dir.display()
        );
    }
    report_unreachable_volumes(unreachable);
    ExitCode::SUCCESS
}

/// 一覧に出す状態名。GCの判定（[`wl::CowGcVerdict`]）と1:1で、**表示専用の別判定を作らない**。
#[cfg(windows)]
fn state_label(verdict: harness_sandbox::tier2a::workspace_ledger::CowGcVerdict) -> &'static str {
    use harness_sandbox::tier2a::workspace_ledger::CowGcVerdict as V;
    match verdict {
        V::KeepRunning => "live",
        V::KeepProtected => "protected",
        V::KeepReviewPending => "review-pending",
        V::KeepUndecidable => "undecidable",
        V::KeepHasChanges => "has-changes",
        V::KeepTooYoung => "just-created",
        V::Collect => "collectable",
    }
}

/// 到達できなかったボリュームがあれば必ず言う。**「0件」の意味が2つに割れるのを防ぐ**
/// （本当に無いのか、媒体が抜かれていて見えていないのか）。
#[cfg(windows)]
fn report_unreachable_volumes(unreachable: usize) {
    if unreachable > 0 {
        println!(
            "note: {unreachable} volume(s) could not be examined right now (removable media \
             unplugged, or an offline network drive). CoW diff areas on them are neither listed \
             nor collected."
        );
    }
}

/// 回収の方針を**ユーザ層の設定だけ**から作る（D-82）。`cow list`の状態表示と
/// `cow gc`の回収が**同じ方針**を見る——ここが分かれると、一覧で「回収予定」と出たものを
/// `gc`が消さない（またはその逆）という食い違いになる。
#[cfg(windows)]
fn cow_gc_policy() -> harness_sandbox::tier2a::workspace_ledger::CowGcPolicy {
    let settings = harness_config::user_cow_gc_settings();
    harness_sandbox::tier2a::workspace_ledger::CowGcPolicy {
        protect_network_volumes: settings.protect_network_volumes(),
    }
}

/// `harness cow gc`: 何も残っていない差分層を回収する（D-82）。
///
/// 既定で回収するのは「空（台帳の再生も実体ファイルも0）・実行中でない・レビュー待ちでない・
/// メタが読める・作りたてでない」ものだけ。**判定できないものは残す**——ここで守っているのは
/// 境界ではなく事故防止のガードだが、ガードしている操作が削除で不可逆だからである。
#[cfg(windows)]
pub(crate) fn cow_gc(dry_run: bool, with_changes: bool, older_than_days: u64) -> ExitCode {
    use harness_sandbox::tier2a::workspace_ledger as wl;

    if dry_run {
        println!("(dry run: nothing is deleted)");
    }
    let now = harness_grant_ledger::now_unix_secs();
    let older_than_secs = older_than_days.saturating_mul(24 * 60 * 60);

    // `--with-changes`は**規則を書き換えるのではなく、人の明示的な指示として例外を1つ通す**。
    // 変更を抱えているものだけが対象で、実行中・レビュー待ち・判定不能はここでも回収しない
    // ——「まとめて消したい」で消えてはいけないものが混ざるのが、この種の掃除機能の
    // いちばんありふれた壊れ方である。
    let also_collect = |fact: &wl::CowSessionFacts, verdict: wl::CowGcVerdict| {
        with_changes
            && verdict.is_only_holding_changes()
            && now.saturating_sub(fact.created_at_unix_secs) >= older_than_secs
    };

    let outcome = wl::run_cow_gc(
        dry_run,
        wl::COW_GC_DEFAULT_GRACE_SECS,
        cow_gc_policy(),
        &also_collect,
    );

    let verb = if dry_run { "would collect" } else { "collected" };
    println!("{verb} {} CoW diff area(s)", outcome.collected.len());
    for id in &outcome.collected {
        println!("  - {id}");
    }

    // **見送りを黙らせない。** 理由別にまとめて出す（`shared-state-exclusion` 問6）。
    if !outcome.kept.is_empty() {
        let mut by_reason: std::collections::BTreeMap<&str, Vec<&str>> =
            std::collections::BTreeMap::new();
        for (id, verdict) in &outcome.kept {
            by_reason.entry(verdict.reason()).or_default().push(id);
        }
        println!("kept {} :", outcome.kept.len());
        for (reason, ids) in by_reason {
            println!("  {} kept because {reason}", ids.len());
            for id in ids {
                println!("    - {id}");
            }
        }
    }

    for (id, e) in &outcome.failures {
        eprintln!("failed to remove the CoW diff area for {id}: {e}");
    }
    report_unreachable_volumes(outcome.unreachable_volumes);

    if with_changes {
        println!(
            "note: --with-changes was given, so diff areas older than {older_than_days} day(s) \
             that still held unapplied changes were included."
        );
    } else if outcome
        .kept
        .iter()
        .any(|(_, v)| v.is_only_holding_changes())
    {
        println!(
            "note: some diff areas were kept only because they still hold unapplied changes. \
             Review them with `harness changes --session <id>`, or re-run with \
             `--with-changes --older-than <days>` to remove them."
        );
    }

    if outcome.failures.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// `resolve_session_overlay`のCoW側解決に使う。セッションIDまたは「最も新しいCoW
/// 置き場」からupper_dirを解決する。`resolve_sandbox_dir`のstaged版と同じ
/// 「最新セッションを選ぶ」考え方をCoW側にも適用する。
#[cfg(windows)]
pub(crate) fn resolve_cow_upper_dir(session: Option<&str>) -> Option<PathBuf> {
    if let Some(id) = session {
        return cow_upper_dir_for(id);
    }
    // D-81で根が複数になったので、**全部の根を横断して**最新を選ぶ。1つの根だけを見ると、
    // 別ボリュームのワークスペースで作った差分層が「無い」ことにされる。
    let (roots, _unreachable) = harness_sandbox::session_scope::cow_upper_roots();
    let mut newest: Option<(PathBuf, std::time::SystemTime)> = None;
    for root in roots {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            let Ok(modified) = metadata.modified() else {
                continue;
            };
            if newest.as_ref().is_none_or(|(_, t)| modified > *t) {
                newest = Some((path, modified));
            }
        }
    }
    newest.map(|(p, _)| p)
}
