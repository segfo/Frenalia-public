//! 付与済みACEの撤収（`harness fs revoke` / `revoke-all`）と、`.harness/settings.json`の
//! 宣言に合わせた自動整合（D-27の`reconcile_fs_ledger_for_workspace`）。

use super::progress::WalkProgress;
use super::*;

/// この撤収対象パスについて台帳が記録している「付与先のSID」（[BUG-101]の判定規則3）。
///
/// 綴りではなく対象で突き合わせる（`same_ledger_path`、B-19）。同じディレクトリが2つの綴りで
/// 積もっていた実例があるので、片方だけ見ると記録があるのに使えない。
#[cfg(windows)]
pub(crate) fn ledger_granted_sids(path: &Path) -> Vec<String> {
    let target = path.to_string_lossy();
    load_fs_ledger()
        .entries
        .iter()
        .filter(|e| {
            harness_sandbox::tier2a::fs_passthrough_ledger::same_ledger_path(&e.path, &target)
        })
        .flat_map(|e| e.granted_sids.clone())
        .collect()
}

/// 撤収対象パスが台帳で`forced`（`--force-system-acl`）記録かを引く（無ければ`false`）。
#[cfg(windows)]
pub(crate) fn ledger_forced_flag(path: &Path) -> bool {
    let target = path.to_string_lossy();
    // 台帳は書き手によって区切り文字が揃わないので、綴りではなく対象で突き合わせる（B-19）。
    load_fs_ledger().entries.iter().any(|e| {
        harness_sandbox::tier2a::fs_passthrough_ledger::same_ledger_path(&e.path, &target)
            && e.forced
    })
}

/// 撤収の結果をユーザーへ報告する。**ACE側と台帳側を別々に数えて、別々に出す**のが
/// この関数の存在理由です（BUG-101の欠陥②）。
///
/// # なぜ台帳の件数だけでは駄目なのか
///
/// 旧実装は「台帳から何件落ちたか」だけを見て`revoked:`と言っていました。ACE側の件数を
/// 持っていないので、**1件も剥がしていないこと**が原理的に見えません。実マシンの6箇所で
/// 「`revoked: … (1 ledger entry removed)`と報告されたのに`icacls`のパッケージSID数は
/// 1つも減らない」が再現しています（B-09: 「やった」と「うまくいった」は別の事実）。
///
/// # [§22.3] 主体が2系統になったので、数え方も2系統ある
///
/// `report`は**package SIDの分類器**（パスのDACLに実在する主体を分類して剥がす）、
/// `decl`は**宣言capabilityの名指し撤収**（台帳の索引から導出したSIDを剥がす）です。
/// 片方が0件でももう片方が剥がしていれば撤収は成立しているので、**両方を足して判定します**
/// ——`--fs-allow`の移行後は前者が常に0件になるため、package側だけで判定すると
/// 正常系が全部「何も一致しなかった」（exit 1）に見えます。
///
/// 終了コードの規則（「剥がした」はpackage側・宣言側のどちらでもよい）:
///
/// | ACE側 | 対象 | 台帳 | 判定 | exit |
/// |---|---|---|---|---|
/// | >0 | >0 | 任意 | 撤収成立 | 0 |
/// | 0 | **0**（rootにharness ACEが無い） | >0 | 台帳の掃除だけ | 0 |
/// | 0 | **>0**（在ったのに剥がせなかった） | – | 失敗。台帳エントリは残す | 1 |
/// | 0 | 0 | 0 | 何も一致しなかった | 1 |
#[cfg(windows)]
fn report_revoke_result(
    path: &Path,
    report: &harness_sandbox::tier2a::win_appcontainer::HarnessRevokeReport,
    decl: &harness_sandbox::tier2a::win_appcontainer::DeclarationRevokeReport,
    removed: usize,
    note: Option<&str>,
) -> ExitCode {
    let targeted = report.targeted();
    let unfinished = report.unfinished();
    let left_alone = report.left_alone();

    let say_details = |stream_err: bool| {
        let ace_line = if report.root_missing {
            "  ACEs   : the path no longer exists, so there is nothing to strip".to_string()
        } else if report.cleared_elsewhere > 0 {
            format!(
                "  ACEs   : {} subject(s) cleared by the privilege-separation helper; {targeted} \
                 still targeted here",
                report.cleared_elsewhere
            )
        } else {
            format!(
                "  ACEs   : {targeted} subject(s) targeted, {} node(s) checked, {} rewritten",
                report.walk.checked,
                report.rewritten()
            )
        };
        // [§22.3] 宣言capability側は**別の行で数える**。package側と足して1つの数字にすると、
        // 「どちらの探し方で見つけた0件なのか」が読めなくなる。
        let decl_line = if decl.targeted.is_empty() {
            "  decls  : no declaration capability is recorded for this path".to_string()
        } else if decl.root_missing {
            format!(
                "  decls  : {} subject(s) known, but the path no longer exists",
                decl.targeted.len()
            )
        } else if decl.cleared_elsewhere > 0 {
            format!(
                "  decls  : {} subject(s) cleared by the privilege-separation helper; {} still \
                 targeted here",
                decl.cleared_elsewhere,
                decl.still_on_root.len()
            )
        } else {
            format!(
                "  decls  : {} subject(s) targeted, {} node(s) checked, {} rewritten",
                decl.targeted.len(),
                decl.checked,
                decl.rewritten
            )
        };
        let ledger_line = format!(
            "  ledger : {removed} entr{} removed",
            if removed == 1 { "y" } else { "ies" }
        );
        if stream_err {
            eprintln!("{ace_line}");
            eprintln!("{decl_line}");
            eprintln!("{ledger_line}");
        } else {
            println!("{ace_line}");
            println!("{decl_line}");
            println!("{ledger_line}");
        }
    };

    // 剥がせなかった対象が残っている＝**撤収は成立していない**。台帳エントリは呼び出し側が
    // 残しているので、そのことも言う（次回`fs revoke`が同じ対象を見つけられる）。
    let still: Vec<&str> = unfinished
        .iter()
        .copied()
        .chain(decl.still_on_root.iter().map(|s| s.as_str()))
        .collect();
    if !still.is_empty() {
        eprintln!("revoke incomplete for {}", path.display());
        say_details(true);
        for sid in &still {
            eprintln!("  still on the root: {sid}");
        }
        eprintln!(
            "  note: the ledger entry was kept so a retry finds the same target. If the ACE \
             cannot be removed by harness at all, strip it directly: \
             icacls \"{}\" /remove:g *{}",
            path.display(),
            still[0]
        );
        return ExitCode::FAILURE;
    }

    // [§22.3] **宣言capabilityを1本でも剥がしたなら「何も一致しなかった」ではない。**
    // 移行後のfs-allowパスはpackage側が常に0件になるので、ここへpackage側だけの条件を
    // 残すと正常系がすべて失敗として報告される。
    if targeted == 0
        && report.rewritten() == 0
        && report.cleared_elsewhere == 0
        && decl.rewritten == 0
        && decl.cleared_elsewhere == 0
        && removed == 0
        && !report.root_missing
    {
        eprintln!(
            "nothing to revoke for {}: no ledger entry matched, and the path carries no ACE \
             that harness can claim as its own.",
            path.display()
        );
        say_details(true);
        for (sid, reason) in &left_alone {
            eprintln!("  left alone: {sid} ({reason})");
        }
        if let Some(e) = &report.classification_error {
            eprintln!("  note: {e}");
        }
        if !decl.targeted.is_empty() {
            // 「索引は引けたが、そのACEはもう載っていなかった」を黙って0件と混ぜない（B-10）。
            eprintln!(
                "  note: {} declaration capability subject(s) are recorded for this path, but \
                 none of their ACEs were on it (already revoked?)",
                decl.targeted.len()
            );
        }
        eprintln!(
            "  note: an ACE granted by a session whose AppContainer profile has since been \
             deleted cannot be removed by name -- its SID is no longer derivable. \
             Check `icacls` for leftover S-1-15-2-* entries (see docs/bugs/BUG-101.md)."
        );
        return ExitCode::FAILURE;
    }

    println!("revoked: {}", path.display());
    say_details(false);
    if let Some(note) = note {
        println!("  note   : {note}");
    }
    for (sid, reason) in &left_alone {
        println!("  left alone: {sid} ({reason})");
    }
    if let Some(e) = &report.classification_error {
        println!("  note   : {e}");
    }
    ExitCode::SUCCESS
}

/// `path`から、**そのパスのDACLに実在するharness由来の主体**のACEを撤収する
/// （進捗表示つき。`forced`なら`SeRestorePrivilege`下で走る）。
#[cfg(windows)]
fn revoke_subjects_with_progress(
    path: &Path,
    ledger_sids: &[String],
    forced: bool,
) -> Result<
    harness_sandbox::tier2a::win_appcontainer::HarnessRevokeReport,
    harness_sandbox::tier2a::win_appcontainer::AppContainerError,
> {
    let walk_progress = WalkProgress::start(
        "harness: scanning for AppContainer ACEs...",
        "harness: revoking fs passthrough access",
    );
    let run = || {
        harness_sandbox::tier2a::win_appcontainer::revoke_harness_subjects(
            path,
            ledger_sids,
            &|done, total| walk_progress.on_progress(done, total),
        )
    };
    let result = if forced {
        harness_sandbox::tier2a::win_appcontainer::with_restore_privilege(run)
    } else {
        run()
    };
    walk_progress.finish();
    if let Ok(report) = &result {
        if let Some(summary) = report.walk.blocked_summary(5) {
            eprintln!("  note: {summary}");
        }
    }
    result
}

/// [§22.2.1] `path`から**宣言capability**（`--fs-allow`の主体）のACEを名指しで撤収する
/// （進捗表示つき。`forced`なら`SeRestorePrivilege`下で走る）。
///
/// 上の`revoke_subjects_with_progress`（package SIDの分類器）と**対で呼ぶ**。主体が2系統
/// あるので撤収も2段になり、どちらか片方だけでは「対象パスにharnessのACEが0本」を名乗れない。
///
/// `workspace`が`None`＝そのパスへ発行された全workspaceの主体。**明示コマンド専用**で、
/// 暗黙の経路は必ず`Some`で絞る（`revoke_declaration_capabilities`のdoc）。
///
/// **進捗の文言を分けてある**——`--fs-allow`の移行後は撤収の実体がこちら側なので、
/// 「何を剥がしている最中なのか」が package 側と区別できないと、数分かかるwalkが
/// 「同じ処理を2回やっている」ように見える（B-23(a)）。
#[cfg(windows)]
fn revoke_declarations_with_progress(
    path: &Path,
    workspace: Option<&Path>,
    forced: bool,
) -> Result<
    harness_sandbox::tier2a::win_appcontainer::DeclarationRevokeReport,
    harness_sandbox::tier2a::win_appcontainer::AppContainerError,
> {
    let walk_progress = WalkProgress::start(
        "harness: scanning for declaration capability ACEs...",
        "harness: revoking declared fs-allow access",
    );
    let run = || {
        harness_sandbox::tier2a::win_appcontainer::revoke_declaration_capabilities(
            path,
            workspace,
            &|done, total| walk_progress.on_progress(done, total),
        )
    };
    let result = if forced {
        harness_sandbox::tier2a::win_appcontainer::with_restore_privilege(run)
    } else {
        run()
    };
    walk_progress.finish();
    result
}

/// 指定パスのfs passthrough ACEを撤収する（`BUG-015`の裏対称: grant側と同じく
/// 「本体内試行→ヘルパーへエスカレーション」の2段構え）。撤収できた場合のみ台帳から除去する
/// （残件がある場合は台帳に残し、次回再試行できるようにする）。
///
/// # [BUG-101] 撤収する主体は「名前から導出したSID」ではなく「パスに実在するSID」
///
/// 旧実装は(1)`revocable_profile_names()`の死んだセッションSIDごとにツリー全walkを回し、
/// (2)最終判定だけを**旧共有プロファイル**（`CONTAINER_NAME`）のSIDで行っていた。実際に
/// 載っているのがセッション固有SIDだと(2)は「探す相手が違う」ので何も見つからず、
/// `revoke_passthrough`が対象0件を`FullyRevoked`として返すため、**ACEを1件も剥がさずに
/// `revoked:`＋exit 0**になっていた（実マシンの6箇所で再現）。しかも台帳エントリだけは
/// 消えるので、それまで「台帳に載った剥がせるACE」だったものが「harnessがもう存在すら
/// 記録していない孤立ACE」になり、実行前より状態が悪くなっていた。
///
/// いまは`revoke_harness_subjects`が対象パスのDACLを読み、そこに実在するパッケージSIDだけを
/// 分類して**1回のwalk**で剥がす（死んだプロファイルの数だけwalkを回すこともしない）。
///
/// # [§22.2.1] 主体が2系統あるので、撤収も2段である
///
/// 上の分類器は`S-1-15-2-`（package SID）しか列挙しない。`--fs-allow`の主体は
/// **宣言ごとのcapability SID**（`S-1-15-3-`）へ移ったので、分類器だけでは1本も剥がれない
/// ——**このコマンドが「名前の付いた扉」である**（分類器へcapability SIDを混ぜると
/// [BUG-046](../../../../docs/bugs/BUG-046.md)の再現になるので、混ぜずに段を足す）。
///
/// **どちらか片方の失敗でも昇格へ回す。** capability側もシステム保護パスでは`ACCESS_DENIED`に
/// なるので、package側だけを見て「本体内で完結した」と判定すると、そこで静かに終わる。
#[cfg(windows)]
pub(crate) fn fs_revoke_one(path: &Path) -> ExitCode {
    let forced = ledger_forced_flag(path);
    let ledger_sids = ledger_granted_sids(path);

    let report = match revoke_subjects_with_progress(path, &ledger_sids, forced) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("revoke failed for {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    // [§22.2.1] 宣言capabilityは**名指しで**剥がす（明示コマンドなので全workspace＝`None`）。
    // walkが`Err`で返るのは「昇格が要る」の主症状なので、ここでコマンドを失敗させず
    // 下のエスカレーションへ落とす（理由は`decl_error`として持ち回り、最後まで黙らせない）。
    let (mut decl, decl_error) = match revoke_declarations_with_progress(path, None, forced) {
        Ok(decl) => (decl, None),
        Err(e) => (
            harness_sandbox::tier2a::win_appcontainer::DeclarationRevokeReport {
                // **失敗を「対象0件」と同じ値にしない**（B-10）。索引は引けているので、
                // 残存として名指ししたうえで昇格へ回す。
                still_on_root: harness_sandbox::tier2a::win_appcontainer::declaration_capabilities_on_root(
                    path, None,
                ),
                ..Default::default()
            },
            Some(e.to_string()),
        ),
    };
    if report.unfinished().is_empty() && decl.is_clean() {
        // **台帳を落としてよいのは、剥がすべきものが残っていないときだけ**（B-01: 資源へ
        // 到達する手段を捨てる操作は最後）。生きているセッションがACEを持っている場合も残す。
        let removed = if report.may_remove_ledger_entry() {
            remove_fs_passthrough_grant(path)
        } else {
            0
        };
        return report_revoke_result(path, &report, &decl, removed, None);
    }
    if let Some(reason) = &decl_error {
        eprintln!("  note: in-process declaration revoke could not finish: {reason}");
    }

    // 本体内で完結しなかった（システム保護パスの可能性）→特権分離ヘルパーへ委譲する。
    if harness_sandbox::tier2a::privhelper::is_elevated() {
        // 本体が既に管理者（§5.3、fs_grant_traverse_directと同じ考え方）: 直接再試行する。
        let retry = match revoke_subjects_with_progress(path, &ledger_sids, forced) {
            Ok(report) => report,
            Err(e) => {
                eprintln!("revoke failed for {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        };
        let retry_decl = match revoke_declarations_with_progress(path, None, forced) {
            Ok(decl) => decl,
            Err(e) => {
                eprintln!("revoke failed for {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        };
        let removed = if retry.may_remove_ledger_entry() && retry_decl.is_clean() {
            remove_fs_passthrough_grant(path)
        } else {
            0
        };
        return report_revoke_result(
            path,
            &retry,
            &retry_decl,
            removed,
            Some("already running elevated"),
        );
    }

    let revoke_entry = harness_sandbox::tier2a::privhelper::FsAllowRevoke {
        path: path.to_path_buf(),
        forced,
    };
    match harness_sandbox::tier2a::privhelper::run_privileged_revoke_fs_allow(vec![revoke_entry]) {
        Ok((_revoked, _root_cleared, failures)) => {
            // **ヘルパーの応答だけを根拠に成功を名乗らない**（B-25/B-33: 他人の成功報告を
            // 自分の結論にしない）。rootのDACLを読み直して、対象がまだ載っていないかを見る。
            // 単一ノードの読取1回なので、全walkをもう一度回す必要はない。
            let mut after =
                match harness_sandbox::tier2a::win_appcontainer::classify_subjects_on_root(
                    path,
                    &ledger_sids,
                ) {
                    Ok(after) => after,
                    Err(e) => {
                        eprintln!("revoke verification failed for {}: {e}", path.display());
                        return ExitCode::FAILURE;
                    }
                };
            // エスカレーション前に対象だった数を持ち込む。持ち込まないと、ヘルパーが全部
            // 剥がした結果「対象0件」に見えて「何も一致しなかった」と報告してしまう（B-09）。
            after.cleared_elsewhere = report.targeted().saturating_sub(after.targeted());
            // 宣言capability側も**同じ形で**検算する（ヘルパーの応答を根拠にしない）。
            // 読むのはrootの明示ACEだけなので、ここでツリーを再walkはしない。
            let still_decl =
                harness_sandbox::tier2a::win_appcontainer::declaration_capabilities_on_root(
                    path, None,
                );
            decl.cleared_elsewhere = decl.still_on_root.len().saturating_sub(still_decl.len());
            decl.still_on_root = still_decl;
            for (p, reason) in &failures {
                eprintln!("  helper could not revoke {} : {reason}", p.display());
            }
            let removed = if after.may_remove_ledger_entry() && decl.is_clean() {
                remove_fs_passthrough_grant(path)
            } else {
                0
            };
            report_revoke_result(
                path,
                &after,
                &decl,
                removed,
                Some("via privilege-separation helper (UAC, one-time)"),
            )
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

/// 撤収の進捗をどちらのストリームへ出すか。
///
/// **stdoutは`--output-format json`/`jsonl`の機械可読な出力そのもの**なので、エージェント起動中に
/// 走る自動整合（D-27）が1行でも混ぜると`jq`が壊れる（[BUG-064](../../../../docs/bugs/BUG-064.md)）。
/// 明示コマンド（`harness fs revoke-all`）の側は出力そのものがユーザーへの回答なのでstdoutが正しい。
/// **どちらが正しいかは呼び出し文脈でしか決まらない**ため、共通処理側では決め打ちにせず引数で受ける。
#[cfg(windows)]
#[derive(Clone, Copy)]
pub(crate) enum RevokeAnnounce {
    /// `harness fs revoke`/`revoke-all`。この出力自体がコマンドの結果である。
    Stdout,
    /// エージェント起動中の自動整合。stdoutは機械可読出力に予約されているので触らない。
    Stderr,
}

#[cfg(windows)]
impl RevokeAnnounce {
    fn say(self, msg: &str) {
        match self {
            RevokeAnnounce::Stdout => println!("{msg}"),
            RevokeAnnounce::Stderr => eprintln!("{msg}"),
        }
    }
}

/// `entries`のfs passthrough ACEを撤収する共通処理（元は`fs_revoke_all`本体）。まず全エントリを
/// 本体内で試行し（UAC無し）、残ったパスだけを**1回のヘルパー要求へまとめて**エスカレーションする
/// （`BUG-015`決定：起動あたりUAC最小化、grant側`preflight`と同じ考え方）。撤収に成功したパスは
/// `on_revoked`で台帳から除去する（`fs_revoke_all`は常に除去、`reconcile_fs_ledger_for_workspace`は
/// TOCTOU再チェック付きの除去を渡す。D-27）。返り値は`(実際に撤収できたパス, (失敗パス, 理由))`。
///
/// # [BUG-097] D-37対応が単発`fs revoke`にしか無かった
///
/// かつてここは`ensure_profile(CONTAINER_NAME)`＝**旧共有プロファイル**のSID1つだけを見ており、
/// 「死んでいるセッション固有SIDのACEを剥がす」ループは`fs_revoke_one`にしか無かった。
/// そのため`fs revoke-all`は**台帳からエントリを消すだけで実体のACEは残していた**。
/// いまは両方が同じ`revoke_harness_subjects`（パスのDACLに実在する主体を剥がす）を通るので、
/// 片方にだけ対応が入る形が構造的に無くなった（B-06）。
///
/// # [§22.2.1] `workspace_scope`——宣言capabilityをどの範囲で剥がすか
///
/// `None`は「そのパスへ発行された**全workspace**の主体」で、**そのパスを名指しした明示操作**
/// （`harness fs revoke` / `revoke-all`）だけが使ってよい。起動時の自動整合（D-27）のような
/// 暗黙の経路は必ず`Some(workspace)`で絞ること——絞らないと、同じパスを宣言している別の
/// ワークスペースの主体まで剥がすことになり、[BUG-046](../../../../docs/bugs/BUG-046.md)
/// （他人が使っているACEを純減させる）と同じ形になる。
#[cfg(windows)]
pub(crate) fn revoke_fs_ledger_entries(
    entries: &[FsLedgerEntry],
    note: &str,
    on_revoked: fn(&Path) -> usize,
    announce: RevokeAnnounce,
    workspace_scope: Option<&Path>,
) -> (Vec<PathBuf>, Vec<(PathBuf, String)>) {
    let mut remaining: Vec<harness_sandbox::tier2a::privhelper::FsAllowRevoke> = Vec::new();
    let mut revoked_paths: Vec<PathBuf> = Vec::new();
    let mut failures: Vec<(PathBuf, String)> = Vec::new();
    for entry in entries {
        let path = PathBuf::from(&entry.path);
        let report = match revoke_subjects_with_progress(&path, &entry.granted_sids, entry.forced) {
            Ok(report) => report,
            Err(e) => {
                failures.push((path, e.to_string()));
                continue;
            }
        };
        // [§22.2.1] 宣言capabilityの段。package側と**同じ判定**（残っていれば昇格へ回す）を
        // 通すので、片方だけが静かに残ることが無い。
        let decl = revoke_declarations_with_progress(&path, workspace_scope, entry.forced);
        let decl_clean = decl.as_ref().map(|d| d.is_clean()).unwrap_or(false);
        if !report.unfinished().is_empty() || !decl_clean {
            if let Err(e) = &decl {
                announce.say(&format!(
                    "escalating: {} (in-process declaration revoke could not finish: {e})",
                    path.display()
                ));
            }
            remaining.push(harness_sandbox::tier2a::privhelper::FsAllowRevoke {
                path,
                forced: entry.forced,
            });
            continue;
        }
        let decl = decl.unwrap_or_default();
        if !report.may_remove_ledger_entry() {
            // 生きているセッションがまだACEを持っている。剥がさないし記録も消さない
            // （BUG-053）。**黙って飛ばさない**——`revoke-all`が「全部消した」と読まれるため。
            announce.say(&format!(
                "skipped: {} ({})",
                path.display(),
                report
                    .left_alone()
                    .first()
                    .map(|(_, reason)| reason.clone())
                    .unwrap_or_else(|| "still in use by a running session".to_string())
            ));
            continue;
        }
        on_revoked(&path);
        announce.say(&format!(
            "{note}: {} ({} package subject(s), {} declaration subject(s), {} node(s) rewritten)",
            path.display(),
            report.targeted(),
            decl.targeted.len(),
            report.rewritten() + decl.rewritten
        ));
        revoked_paths.push(path);
    }

    if remaining.is_empty() {
        return (revoked_paths, failures);
    }

    let escalated: Result<harness_sandbox::tier2a::privhelper::FsAllowRevokeOutcome, String> =
        if harness_sandbox::tier2a::privhelper::is_elevated() {
            // 本体が既に管理者: 直接再試行する（ヘルパーもUACも不要）。
            let mut revoked = Vec::new();
            let mut elevated_failures = Vec::new();
            for entry in &remaining {
                let sids = ledger_granted_sids(&entry.path);
                // 宣言capability側も昇格下で再試行する（片方だけ昇格させない、B-02）。
                let decl =
                    revoke_declarations_with_progress(&entry.path, workspace_scope, entry.forced);
                let decl_left = match &decl {
                    Ok(d) => d.still_on_root.clone(),
                    Err(e) => vec![format!("declaration revoke failed: {e}")],
                };
                match revoke_subjects_with_progress(&entry.path, &sids, entry.forced) {
                    Ok(report) if report.unfinished().is_empty() && decl_left.is_empty() => {
                        revoked.push(entry.path.clone())
                    }
                    Ok(report) => elevated_failures.push((
                        entry.path.clone(),
                        format!(
                            "still on the root after an elevated retry: {}",
                            report
                                .unfinished()
                                .iter()
                                .map(|s| s.to_string())
                                .chain(decl_left)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    )),
                    Err(e) => elevated_failures.push((entry.path.clone(), e.to_string())),
                }
            }
            Ok((revoked, Vec::new(), elevated_failures))
        } else {
            harness_sandbox::tier2a::privhelper::run_privileged_revoke_fs_allow(remaining.clone())
                .map_err(|e| e.to_string())
        };

    match escalated {
        Ok((revoked, root_cleared, helper_failures)) => {
            for path in revoked.iter().chain(root_cleared.iter()) {
                // **ヘルパーの応答だけを根拠に台帳を落とさない**（B-25）。rootのDACLを読み
                // 直して、剥がすべき主体が残っていないことを確かめてから記録を捨てる。
                let sids = ledger_granted_sids(path);
                // 宣言capability側も同じ根拠（実DACL）で確かめる。読むのはrootの明示ACEだけ。
                let decl_left =
                    harness_sandbox::tier2a::win_appcontainer::declaration_capabilities_on_root(
                        path,
                        workspace_scope,
                    );
                match harness_sandbox::tier2a::win_appcontainer::classify_subjects_on_root(
                    path, &sids,
                ) {
                    Ok(after) if after.may_remove_ledger_entry() && decl_left.is_empty() => {
                        on_revoked(path);
                        announce.say(&format!(
                            "{note} via privilege-separation helper (UAC, one-time): {}",
                            path.display()
                        ));
                        revoked_paths.push(path.clone());
                    }
                    Ok(after) => failures.push((
                        path.clone(),
                        format!(
                            "the helper reported success but ACEs are still on the root: {}",
                            after
                                .unfinished()
                                .iter()
                                .map(|s| s.to_string())
                                .chain(decl_left)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    )),
                    Err(e) => failures.push((path.clone(), e.to_string())),
                }
            }
            failures.extend(helper_failures);
            (revoked_paths, failures)
        }
        Err(reason) => {
            failures.extend(
                remaining
                    .iter()
                    .map(|entry| (entry.path.clone(), reason.clone())),
            );
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
    let (_, failures) = revoke_fs_ledger_entries(
        &ledger.entries,
        "revoked",
        remove_fs_passthrough_grant,
        RevokeAnnounce::Stdout,
        // 明示コマンドなので全workspaceの宣言主体が対象（`revoke_fs_ledger_entries`のdoc）。
        None,
    );
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
///
/// # [§22.2.1] これが「宣言が消えた次セッション開始時の差分」である
///
/// `--fs-allow`の主体が宣言ごとのcapability SIDへ移り、そのACEは**永続**になった
/// （セッション終了時に剥がすと、同じワークスペースの並行セッションが互いの許可を落とす）。
/// 通常の撤収経路は「宣言が消えたら次の起動で剥がす」差分で、その差分を既に計算しているのが
/// この関数である——**新しい差分機構は作らない**（検問7/8）。足りないのは
/// 「消えた宣言の主体を実ACLから剥がす」段だけで、それは`revoke_fs_ledger_entries`が持つ。
///
/// **対象は`.harness/settings.json`の宣言だけ**である。`--fs-allow`のCLI宣言を差分の材料に
/// しないのは、宣言集合が**起動ごとに違い得る**ためで、材料にすると
/// (a) 同じワークスペースを別の`--fs-allow`で開いた2セッションのうち後発が先発の穴を剥がし、
/// (b) ドメインごとに`preflight`を回すポリシーエディタのパス2が互いの宣言を剥がす。
/// どちらも生存判定を足さないと塞げず、それは§22.2.1が明示的に避けた道である。
/// CLI宣言のACEは従来どおり`harness fs revoke <path>`（名前の付いた扉）で消す。
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
    // [§22.2.1] **暗黙の経路なので、宣言capabilityはこのワークスペースのものだけに絞る。**
    // 絞らないと、同じパスを宣言している別ワークスペースの主体まで剥がす（BUG-046と同型）。
    // 台帳の突合は`workspace_key`が綴りを畳むが、`..`や8.3短縮名までは畳まないので
    // canonicalizeしてから渡す（付与側の`preflight`が使っているのと同じ形）。
    let canonical = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    let (_, failures) = revoke_fs_ledger_entries(
        &orphan_candidates,
        "auto-revoked",
        remove_fs_passthrough_grant_if_still_orphaned,
        // BUG-064: この経路はエージェント起動の途中で走る。stdoutは`--output-format json`/`jsonl`
        // の機械可読出力に予約されているので、1行たりとも混ぜない。
        RevokeAnnounce::Stderr,
        Some(&canonical),
    );
    for (path, reason) in &failures {
        eprintln!(
            "warning: auto-revoke failed for {} : {reason}",
            path.display()
        );
    }
}
