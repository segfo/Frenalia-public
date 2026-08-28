//! preflightがworkspace本体へ付与した継承ACEの撤収（`harness fs revoke-workspace` /
//! `revoke-workspace-all`）。生存中のセッションが使っているworkspaceは撤収しない
//! （判定は`workspace_ledger`の名前付きmutex）。

use super::progress::{Spinner, WalkProgress};
use super::*;

/// [B-01] **撤収が終わったworkspaceについて、台帳から落としてよい記録の鍵。**
///
/// 台帳の記録は「そのACEの主体をもう一度導出するための唯一の名前」なので、
/// これを作ってよいのは**ACEを剥がし終えたあと**だけである（順序が逆だと、
/// 撤収経路の無い孤立ACEがツリーに残る。`forget_capability`のdoc、BUG-017/BUG-059）。
///
/// 値として持ち回るのは`revoke-workspace-all`のためである——N件を1件ずつ落とすと
/// 台帳の全文読み書きがN×3回走る（[`forget_revoked_ledger_records`]のdoc）。
#[cfg(windows)]
struct ForgettableWorkspace {
    /// canonicalize済みのworkspaceパス（`workspace_ledger`側の鍵）。
    path: PathBuf,
    /// capability台帳から落としてよいモードの綴り（`rwx`/`ro`）。**撤収の対象にしたものだけ**。
    modes: Vec<&'static str>,
}

/// 1つのworkspaceに対する撤収の結末。**台帳を触ってよいかどうかだけを呼び出し側へ伝える。**
#[cfg(windows)]
enum WorkspaceRevokeOutcome {
    /// 剥がし終えた。記録を落としてよい。
    Revoked(ForgettableWorkspace),
    /// 撤収が完了しなかった（使用中・SID解決に失敗・剥がせないノードが残った）。
    /// **台帳の記録は残す**（B-01）。理由は既に[`unfinished_workspace`]が印字している。
    ///
    /// **昇格へ委譲する結末は無い。** 一度は足したが製品から取り除いた——理由は
    /// [`unfinished_workspace`]のdocが持つ。
    Incomplete,
}

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
    match revoke_one_workspace(path) {
        WorkspaceRevokeOutcome::Revoked(forgettable) => {
            forget_revoked_ledger_records(std::slice::from_ref(&forgettable));
            ExitCode::SUCCESS
        }
        WorkspaceRevokeOutcome::Incomplete => ExitCode::FAILURE,
    }
}

/// [`fs_revoke_workspace`]の本体から**台帳の書換だけを外したもの**。
///
/// 分けてあるのは`revoke-workspace-all`のためである。あちらはN件を回すので、
/// 台帳の書換を1件ずつ行うと全文の読み書きがN×3回走る（[`forget_revoked_ledger_records`]）。
/// **判定と印字はここ、記録を落とすのは呼び出し側**、という分け方にしてあり、
/// 「剥がせたか」の判定を2箇所へ書かない（B-05）。
#[cfg(windows)]
fn revoke_one_workspace(path: &Path) -> WorkspaceRevokeOutcome {
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
            return WorkspaceRevokeOutcome::Incomplete;
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
        return WorkspaceRevokeOutcome::Incomplete;
    }

    // D-54: workspaceツリーのACEの**現在の主体**は、workspace＋モード単位のcapability SIDで
    // ある。これはセッションより長生きする（明示的に消すまで残る）ので、`fs revoke-workspace`が
    // 唯一の撤収経路になる。D-37時代の残骸（package SID宛のACE）も同じ機会に剥がす。撤収対象は
    // 「旧共有プロファイル」＋「生きていないセッションのプロファイル」で、実行中のセッションの
    // ぶんは触らない（実行中の他セッションから権限を奪わない、BUG-053と同じ原則）。
    //
    // [D-84] **付与が2本なら撤収も2本である。** `preflight`は起動のたびに全モードの
    // capability SID宛ACEを配るので、ここが自モードのぶんだけを剥がすと**もう一方の
    // capability SID宛ACEがツリーに
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
        return WorkspaceRevokeOutcome::Incomplete;
    }
    if capability_targets.is_empty() && profile_targets.is_empty() {
        drop(spinner.take());
        // 台帳が空でも、過去のセッションが`.harness/**`へ立てた継承遮断は残り得る。
        report_harness_control_dir_unprotected(&canonical);
        println!("(nothing recorded to revoke for {})", canonical.display());
        // 剥がす主体が1つも無い＝ツリーに残せるACEも無いので、workspace一覧の記録は落としてよい。
        // capability台帳には元から何も無いので`modes`は空。
        return WorkspaceRevokeOutcome::Revoked(ForgettableWorkspace {
            path: canonical,
            modes: Vec::new(),
        });
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
        // [BUG-103] walkは1ノードの失敗では止まらなくなったので、**「剥がせなかったノードが
        // 在るか」は`Err`ではなく`report.blocked`が持つ**。`Err`が来るのはrootにすら触れなかった
        // ときだけである。ここで`blocked`を無視して成功扱いにすると、剥がし残しがあるのに
        // 台帳を落とす形になり、直した`?`中断より悪い状態（主体を導出できない孤立ACE）になる。
        Ok(report) => match report.blocked_summary(5) {
            // --- 完全撤収 ---
            None => {
                // ACEを剥がし終えてから台帳を落とす——順序が逆だと主体を引けなくなり、撤収経路の
                // 無い孤立ACEがツリーに残る（`forget_capability`のdoc、BUG-017/BUG-059と同じ
                // 不変条件）。実際に落とすのは呼び出し側で、ここは「落としてよい」だけを返す。
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
                WorkspaceRevokeOutcome::Revoked(ForgettableWorkspace {
                    modes: capability_targets.iter().map(|(mode, _, _)| *mode).collect(),
                    path: canonical,
                })
            }
            // --- 部分完了: ツリーの大半は剥がれたが、剥がせないノードが残った ---
            Some(summary) => {
                // **件数ではなく名前を出す**（B-09）。`0x80070005`（アクセス拒否）で残った
                // ノードは`icacls <path> /remove:g *<SID>`でしか片付かず、名前が無いと
                // どこを叩けばよいのか分からない。文面の作法（先頭5件＋残件数）は
                // `RevokeReport::blocked_summary`と`ReclaimOutcome::summary`に揃えてある。
                unfinished_workspace(
                    canonical,
                    format!(
                        "{summary} (checked {} node(s), rewrote {} node(s))",
                        report.checked, report.rewritten
                    ),
                )
            }
        },
        Err(e) => {
            // rootにすら触れなかった（あるいはツリーを列挙できなかった）。1ノードも剥がせて
            // いない。
            unfinished_workspace(canonical, format!("{e} (checked up to node {last_reported})"))
        }
    }
}

/// 本体プロセス内で剥がしきれなかったときの報告。
///
/// # ここから昇格へ委譲しない（拘束的決定。`plans/DESIGN-SANDBOX-PRIVSEP.md` D-16の系列）
///
/// 一度は「剥がせなかったら特権分離ヘルパーへ委譲する」経路を足したが、**製品から取り除いた**。
/// 理由は、実運用でそれが要る場面を**1つも数えられなかった**ことである——実機で
/// `revoke-workspace-all`を撃つと14件中12件は非昇格のまま剥がせ、残る2件は**デバッグで昇格して
/// 走らせたテストが作った残骸**だった（本番のworkspaceはユーザー自身のリポジトリで、
/// 所有者はユーザーである）。
///
/// 委譲を足す先（`privhelper/server.rs`）は「レビュー時はここだけを見れば**管理者権限で何が
/// 実行されうるか**が尽きる」ための総目録なので、**必要が示せないものを載せない**。
/// 「付与側が昇格できるのだから撤収側も」という対称性は、必要の証明ではない。
///
/// 覆すとしたら、**テスト以外で**「非昇格では剥がせないノード」の実例を1つ数えてからにすること。
///
/// # 黙って終わらせない
///
/// 委譲しない代わりに、**剥がせなかったノードを名前で出して次の一手を書く**（`B-09`）。
/// `0x80070005`（アクセス拒否）で残ったノードは名前が無いとどこを叩けばよいのか分からない。
///
/// # 台帳エントリは残す
///
/// 台帳に載っている名前は、そのACEの主体（capability SID）を導出するための**唯一の索引**
/// である。先に捨てると、残ったACEはどのコマンドでも剥がせない孤児になる
/// （`B-01`: 名前で到達する設計では、名前を捨てる操作を最後に置く）。
#[cfg(windows)]
fn unfinished_workspace(canonical: PathBuf, reason: String) -> WorkspaceRevokeOutcome {
    eprintln!(
        "failed to revoke workspace access for {}: {reason}",
        canonical.display()
    );
    eprintln!(
        "  the workspace capability and profile ledger entries were left intact so a retry finds \
         the same targets. If these nodes cannot be rewritten as this user (they are usually owned \
         by another account), re-run this command from an elevated shell, or strip the ACE \
         directly with `icacls \"{}\" /remove:g *<SID>`.",
        canonical.display()
    );
    WorkspaceRevokeOutcome::Incomplete
}

/// [B-01] 撤収が終わったworkspaceの台帳記録を、**2つの台帳それぞれ1回のupdateで**まとめて落とす。
///
/// # なぜ1件ずつ落とさないのか
///
/// `Ledger::update`は1回ごとに「ロック→全文読み→直列化→`.bak`へ全文コピー→全文書き」を行う
/// （`harness-grant-ledger/src/lib.rs`）。1件ずつだと`forget_capability`が2回＋
/// `remove_workspace_entry`が1回、つまり**1エントリあたり台帳の全文読み書きが3回**走る。
/// `revoke-workspace-all`は台帳のN件を回すので、そのままN倍になる。
/// **述語を受けてまとめて落とす部品は既にある**ので、そこへ繋ぐだけでよい
/// （`prune_capability_entries`・`prune_workspace_entries`。どちらも`harness fs prune`が使う）。
///
/// # 渡してよいのは「撤収に成功した集合」だけである
///
/// 剥がせなかったエントリを混ぜてはならない。台帳に載っている名前は、そのACEの主体
/// （capability SID）を導出するための**唯一の索引**であり、先に捨てると残ったACEは
/// どのコマンドでも剥がせない孤児になる。呼び出し側は[`WorkspaceRevokeOutcome::Revoked`]
/// だけをここへ集めること。
///
/// # 途中で落ちたらどうなるか
///
/// `revoke-workspace-all`はN件のACEを剥がし終えてから台帳を1回書く。途中でプロセスが死ぬと、
/// **既に剥がしたworkspaceの記録が残る**——再実行すると同じ対象を解決し、ACEが無いツリーを
/// もう一度歩いて（`revoke_sids_from_node`が0件なら書込を省くので読取だけで）記録を落とす。
/// 逆向き（記録を先に落として途中で死ぬ）は孤立ACEを作るので、倒す方向はこちらで正しい。
#[cfg(windows)]
fn forget_revoked_ledger_records(revoked: &[ForgettableWorkspace]) {
    if revoked.is_empty() {
        return;
    }
    // 突合の綴りは台帳側の畳み込み規則（`workspace_key`）をそのまま借りる。ここで自前に
    // 小文字化や区切りの正規化を書くと、FS軸の畳み込みが2つになって`C:/x`と`c:\x`が
    // 別物になる（`B-19`/§22.5）。
    let keys: Vec<(String, &[&'static str])> = revoked
        .iter()
        .map(|w| {
            (
                harness_sandbox::tier2a::workspace_capability::workspace_key(&w.path),
                w.modes.as_slice(),
            )
        })
        .collect();

    // capability台帳。**`declaration`が`Some`のエントリは落とさない**——あれが指すACEは
    // workspaceの外の宣言パスに載っているので、workspaceを撤収したことはそのACEが消えたことを
    // 意味しない（`WorkspaceCapabilityEntry::declaration`のdoc、`B-01`）。1件ずつ呼んでいた
    // `forget_capability(ws, mode)`と同じ突合（workspace・declaration無し・mode一致）である。
    harness_sandbox::tier2a::workspace_capability::prune_capability_entries(|entry| {
        entry.declaration.is_none()
            && keys.iter().any(|(key, modes)| {
                modes.contains(&entry.mode.as_str())
                    && harness_sandbox::tier2a::workspace_capability::workspace_key(Path::new(
                        &entry.workspace,
                    )) == *key
            })
    });

    // workspace一覧台帳。突合は`remove_workspace_entry`と同じ`same_ledger_path`を使う
    // （こちらの台帳は末尾の`\`まで畳む別の規則を持っているので、capability側の鍵で
    // 代用しない）。
    harness_sandbox::tier2a::workspace_ledger::prune_workspace_entries(|entry_path| {
        let entry_path = entry_path.to_string_lossy();
        revoked.iter().any(|w| {
            harness_grant_ledger::same_ledger_path(&entry_path, &w.path.to_string_lossy())
        })
    });
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

/// 記録済みの全workspaceに対して撤収を試みる。使用中のworkspaceはスキップし、それ以外を撤収する。
///
/// **台帳の書換はループの外で1回だけ行う**（[`forget_revoked_ledger_records`]）。1件ずつ
/// 落としていたころは、`Ledger::update`が毎回台帳の全文を読み書きするうえに1エントリあたり
/// 3回呼ばれるので、記録が積もった実機（実測1,043件・155KB）では書換だけで時間を食っていた。
#[cfg(windows)]
pub(crate) fn fs_revoke_workspace_all() -> ExitCode {
    let ledger = harness_sandbox::tier2a::workspace_ledger::load_workspace_ledger();
    if ledger.entries.is_empty() {
        println!("(no workspace grants recorded)");
        return ExitCode::SUCCESS;
    }
    let mut any_failed = false;
    // [B-01] **撤収に成功したものだけ**を集める。剥がせなかったエントリを混ぜると、
    // 残ったACEの主体を導出する索引ごと消えて孤児になる。
    let mut forgettable = Vec::new();
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
        match revoke_one_workspace(&path) {
            WorkspaceRevokeOutcome::Revoked(w) => forgettable.push(w),
            WorkspaceRevokeOutcome::Incomplete => any_failed = true,
        }
    }
    forget_revoked_ledger_records(&forgettable);
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
