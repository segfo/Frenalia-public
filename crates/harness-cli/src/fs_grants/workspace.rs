//! preflightがworkspace本体へ付与した継承ACEの撤収（`harness fs revoke-workspace` /
//! `revoke-workspace-all`）。生存中のセッションが使っているworkspaceは撤収しない
//! （判定は`workspace_ledger`の名前付きmutex）。

use super::*;

/// [BUG-082フォローアップ] 止めるまで`stderr`へスピナー（TUIと同じ点字フレーム、
/// `harness-tui`の`SPINNER_FRAMES`と同一）を1行で回し続けるバックグラウンドスレッド。
///
/// `fs revoke-workspace`はSID解決や`collect_dirs_and_files`（対象数が定まるまで進捗を
/// 出せないディレクトリ走査）の間、無反応に見える区間を持つ——ユーザーからの実機報告
/// （コマンド実行後、最初の1行が出るまで長く待たされる）を受けて追加した。`Drop`で
/// スレッドを止め、行を空白で上書きしてから`\r`だけ残す（次の出力がスピナーの残骸と
/// 混ざらないように）。
struct Spinner {
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Spinner {
    fn start(label: impl Into<String>) -> Self {
        let label = label.into();
        let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let running_thread = std::sync::Arc::clone(&running);
        let handle = std::thread::spawn(move || {
            const FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
            let mut i = 0usize;
            while running_thread.load(std::sync::atomic::Ordering::Relaxed) {
                eprint!("\r{} {label}", FRAMES[i % FRAMES.len()]);
                let _ = std::io::Write::flush(&mut std::io::stderr());
                i += 1;
                std::thread::sleep(std::time::Duration::from_millis(80));
            }
        });
        Self {
            running,
            handle: Some(handle),
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.running.store(false, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        // 直前のスピナー行を空白で上書きしてから復帰する。次にこの行へ書く側
        // （数値進捗・完了メッセージ）がスピナーの残骸を引きずらないようにするため。
        eprint!("\r{}\r", " ".repeat(120));
        let _ = std::io::Write::flush(&mut std::io::stderr());
    }
}

/// workspace本体のACE（`preflight`が毎回付与するRWX/RO）を撤収する。名前付きmutexで
/// 「今もこのworkspaceを使っている他のharnessセッションが無いか」を確認してから撤収する
/// （`harness_sandbox::tier2a::workspace_ledger`参照）。CoWのupper_dirには一切触れない。
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
    let mut resolve_failures = Vec::new();
    let mut capability_targets = Vec::new();
    for mode in harness_sandbox::tier2a::workspace_ledger::KNOWN_MODES {
        let Some(name) =
            harness_sandbox::tier2a::workspace_capability::lookup_capability_name(&canonical, mode)
        else {
            continue;
        };
        match harness_sandbox::tier2a::win_appcontainer::workspace_capability_sid(&canonical, mode) {
            Ok(sid) => capability_targets.push((mode, name, sid)),
            Err(e) => resolve_failures.push(format!("{name} ({mode}): failed to resolve SID: {e}")),
        }
    }
    let mut profile_targets = Vec::new();
    for profile in harness_sandbox::tier2a::session_profile::revocable_profile_names() {
        match harness_sandbox::tier2a::win_appcontainer::ensure_profile(&profile) {
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
        println!(
            "(nothing recorded to revoke for {})",
            canonical.display()
        );
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
    // スピナー、定まったら同じ行を数値進捗で上書きする（`RefCell`は進捗コールバックが
    // `&dyn Fn`のため——このプロセスはシングルスレッドで呼ぶので`Mutex`は不要）。
    let scan_spinner = std::cell::RefCell::new(Some(Spinner::start(
        "harness: scanning workspace tree...",
    )));
    let last_reported = std::cell::Cell::new(0usize);
    let result = harness_sandbox::tier2a::win_appcontainer::revoke_workspace_sids_recursive(
        &canonical,
        &all_sids,
        &|done, total| {
            // 初回呼び出し（`revoke_workspace_sids_recursive`がtotal確定直後に必ず1回
            // `(0, total)`で呼ぶ）でスキャン用スピナーを止める。2回目以降は既に`None`なので
            // no-op。
            drop(scan_spinner.borrow_mut().take());
            last_reported.set(done);
            let percent = (done.min(total) * 100).checked_div(total).unwrap_or(0);
            eprint!(
                "\rharness: revoking workspace access: {done}/{total} node(s) checked ({percent}%)   "
            );
            let _ = std::io::Write::flush(&mut std::io::stderr());
        },
    );
    drop(scan_spinner.into_inner());
    eprintln!();

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
                last_reported.get()
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
