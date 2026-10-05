//! 祖先ディレクトリチェーンへのtraverse ACE付与と撤収（D10、`harness fs grant-traverse` /
//! `revoke-traverse`）。書込前に対象ノードを列挙する`--dry-run`プレビューを持つ。
//!
//! **付与先はharness共通のcapability SID**（D-37）。package SIDはセッションごとに変わるため、
//! 祖先traverseをそこへ紐付けると起動のたびに昇格が要る。capability SIDは全harnessサンドボックスの
//! トークンへ積まれるので、**一度きりの付与**で以後の全セッションが祖先を辿れる。

use super::*;

/// `grant-traverse --dry-run`本体。`target`の祖先チェーン（ドライブルートまで）を、一切書込まず
/// 読み取り専用（`GetNamedSecurityInfoW`のみ）で列挙する。`WRITE_DAC`もUACも不要
/// （`win_appcontainer::ensure_profile`はAppContainerプロファイルの作成/導出のみでACL変更を
/// 伴わない）。ユーザーが本実行の前にどのノードへ書込みが起きるか確認できるようにする
/// （プロファイルルート近傍への`SetNamedSecurityInfoW`はこの種の実機で病的に遅くなりうる、
/// BUG-011）。
#[cfg(windows)]
pub(crate) fn fs_grant_traverse_preview(target: &Path) -> ExitCode {
    let sid = match harness_sandbox::tier2a::win_appcontainer::traverse_capability_sid() {
        Ok(sid) => sid,
        Err(e) => {
            eprintln!("dry-run: failed to resolve sandbox SID: {e}");
            return ExitCode::FAILURE;
        }
    };
    let preview =
        harness_sandbox::tier2a::win_appcontainer::preview_traverse_chain(target, sid.as_psid());
    println!("=== grant-traverse --dry-run: {} ===", target.display());
    println!("(read-only: no ACE has been written, no UAC prompt was shown)");
    for node in &preview {
        let status = if node.already_sufficient {
            "already has FILE_TRAVERSE|FILE_READ_ATTRIBUTES|SYNCHRONIZE -- write will be SKIPPED"
        } else {
            match node.existing_mask {
                Some(_) => "has some sandbox-SID ACE, but not sufficient -- WILL WRITE",
                None => "no sandbox-SID ACE yet -- WILL WRITE",
            }
        };
        println!("  {} : {status}", node.path.display());
    }
    println!(
        "run without --dry-run to actually grant (requires WRITE_DAC on each node still \
         needing a write; non-administrators will see a UAC prompt via the privilege-separation \
         helper, D-16)"
    );
    ExitCode::SUCCESS
}

#[cfg(not(windows))]
pub(crate) fn fs_grant_traverse_preview(_target: &Path) -> ExitCode {
    eprintln!("error: fs grant-traverse --dry-run is Windows-only (Tier2a specific)");
    ExitCode::FAILURE
}

/// ドライブルートへtraverse ACEを付与する（D10）。`WRITE_DAC`が要るため管理者権限で実行する
/// 必要がある。本体プロセス自身が既に昇格済み（`is_elevated()`）ならACL操作を直接行うが、
/// 通常の非管理者起動時は特権分離ヘルパー（D-16、`plans/DESIGN-SANDBOX-PRIVSEP.md` §5）を
/// `runas`経由で呼び出す（本体プロセス自身は非管理者のまま維持する）。
#[cfg(windows)]
pub(crate) fn fs_grant_traverse(target: &Path) -> ExitCode {
    // 事前チェック（決定2、`TIER1A-PRIVHELPER-HANG.md`「引き継ぎTODO」）: 祖先チェーン全ノードが
    // 既にFILE_TRAVERSE|FILE_READ_ATTRIBUTES|SYNCHRONIZEを持っているなら、privhelperもUACも一切呼ばず
    // 即座に成功する。`preview_traverse_chain`は`--dry-run`が使うのと同じ読み取り専用ヘルパで、
    // `WRITE_DAC`もUACも要らない。
    if let Ok(sid) = harness_sandbox::tier2a::win_appcontainer::traverse_capability_sid() {
        let preview = harness_sandbox::tier2a::win_appcontainer::preview_traverse_chain(
            target,
            sid.as_psid(),
        );
        if !preview.is_empty() && preview.iter().all(|node| node.already_sufficient) {
            let paths: Vec<PathBuf> = preview.iter().map(|node| node.path.clone()).collect();
            harness_sandbox::tier2a::traverse_ledger::record_traverse_grants(&paths);
            println!(
                "grant-traverse: all {} ancestor node(s) already have \
                 FILE_TRAVERSE|FILE_READ_ATTRIBUTES|SYNCHRONIZE -- skipped the privilege-separation helper \
                 entirely (no UAC prompt): {}",
                preview.len(),
                preview
                    .iter()
                    .map(|n| n.path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            );
            return ExitCode::SUCCESS;
        }
    }
    if harness_sandbox::tier2a::privhelper::is_elevated() {
        return fs_grant_traverse_direct(target);
    }
    let target_paths = vec![target.to_path_buf()];
    let (_, outcome) = harness_sandbox::tier2a::traverse_ledger::with_recorded_traverse_grants(
        &target_paths,
        || match harness_sandbox::tier2a::privhelper::run_privileged(
            &harness_sandbox::tier2a::privhelper::PrivilegedRequest::GrantTraverse {
                target: target.to_path_buf(),
            },
        ) {
            Ok(granted) => (granted.clone(), Ok(granted)),
            Err(harness_sandbox::tier2a::privhelper::PrivHelperError::PartialGrantChain {
                granted,
                reason,
            }) => (
                granted.clone(),
                Err(
                    harness_sandbox::tier2a::privhelper::PrivHelperError::PartialGrantChain {
                        granted,
                        reason,
                    },
                ),
            ),
            Err(e) => (Vec::new(), Err(e)),
        },
    );
    match outcome {
        Ok(granted) => {
            println!(
                "granted FILE_TRAVERSE|FILE_READ_ATTRIBUTES|SYNCHRONIZE via privilege-separation helper \
                 (UAC, one-time) on the full ancestor chain up to the drive root: {} (see \
                 docs/phases/foundation/M12-shell-isolation-tiers.md 追記8・追記13, \
                 plans/DESIGN-SANDBOX-PRIVSEP.md §5). All {} node(s) recorded in the traverse \
                 ledger; use `harness fs revoke-traverse <path>` per-node or `revoke-traverse-all` \
                 to undo",
                granted
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" -> "),
                granted.len()
            );
            ExitCode::SUCCESS
        }
        Err(harness_sandbox::tier2a::privhelper::PrivHelperError::PartialGrantChain {
            granted,
            reason,
        }) => {
            eprintln!(
                "grant-traverse chain partially failed for {}: {reason}. {} node(s) that DID \
                 succeed before the failure were still recorded in the traverse ledger (no \
                 orphaned ACEs): {}",
                target.display(),
                granted.len(),
                granted
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            );
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("grant-traverse failed on {}: {e}", target.display());
            ExitCode::FAILURE
        }
    }
}

/// `fs_grant_traverse`の直接実行部分(本体が既に管理者トークンで動作している場合のみ呼ぶ、
/// §5.3「本体が管理者ならヘルパー機構を経由しない直接呼び出しを許すが、そもそも本体が
/// 管理者で起動されたこと自体を警告する」に対応)。
#[cfg(windows)]
pub(crate) fn fs_grant_traverse_direct(target: &Path) -> ExitCode {
    let sid = match harness_sandbox::tier2a::win_appcontainer::traverse_capability_sid() {
        Ok(sid) => sid,
        Err(e) => {
            eprintln!("failed to resolve sandbox SID: {e}");
            return ExitCode::FAILURE;
        }
    };
    let target_paths = vec![target.to_path_buf()];
    let (granted, result) = harness_sandbox::tier2a::traverse_ledger::with_recorded_traverse_grants(
        &target_paths,
        || harness_sandbox::tier2a::win_appcontainer::grant_traverse_chain(target, sid.as_psid()),
    );
    match result {
        Ok(()) => {
            println!(
                "granted FILE_TRAVERSE|FILE_READ_ATTRIBUTES|SYNCHRONIZE (admin, one-time; see \
                 docs/phases/foundation/M12-shell-isolation-tiers.md 追記8・追記13) on the full \
                 ancestor chain up to the drive root: {}. All {} node(s) recorded in the \
                 traverse ledger; use `harness fs revoke-traverse <path>` per-node or \
                 `revoke-traverse-all` to undo",
                granted
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" -> "),
                granted.len()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "grant-traverse chain failed on {}: {e} (this requires WRITE_DAC on each \
                 ancestor node; re-run as administrator). {} node(s) that DID succeed before \
                 the failure were still recorded in the traverse ledger: {}",
                target.display(),
                granted.len(),
                granted
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
pub(crate) fn fs_grant_traverse(_target: &Path) -> ExitCode {
    eprintln!("error: fs grant-traverse is Windows-only (Tier2a specific)");
    ExitCode::FAILURE
}

/// 指定パスのtraverse ACEを撤収する（非再帰・単一ノード、D10の巻き戻し）。
/// `grant_traverse_drive_root`（`grant_ace_mask`による非継承・単一ACE付与）の逆操作なので、
/// `revoke_traverse_grant`（単一ノードの撤収＋単一ノードの検証、D-48の正規の扉）を使う。
/// `revoke_ace_recursive`/`assert_no_sid_ace_recursive`（ツリー全体を再walk）は、`path`が
/// ドライブルートの場合に不要な全走査を招くため使わない。`fs_grant_traverse`と同じく、
/// 本体が既に昇格済みなら直接、それ以外は特権分離ヘルパー（D-16）経由で実行する。
#[cfg(windows)]
pub(crate) fn fs_revoke_traverse_one(path: &Path) -> ExitCode {
    // D-48: 走行中の他セッションがあるなら剥がさない。**委譲より前に**見るのは、UACを1回
    // 払わせてから拒否しても払わせた意味が無いためである。判定は昇格側と同じ関数
    // （`traverse_revoke_guard`）を通し、昇格側は昇格側でもう一度自分で見る
    // （D-16。ここを通ったことを昇格側は信用しない）。
    //
    // **一括撤収はここを通らない。** 台帳の全件をこの関数でループすると件数ぶんUACが出る
    // ので、`fs_revoke_traverse_all`が要求を1本へ束ねる（`B-02`）。
    if let Err(e) = harness_sandbox::tier2a::win_appcontainer::traverse_revoke_guard(path) {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }
    if harness_sandbox::tier2a::privhelper::is_elevated() {
        return fs_revoke_traverse_one_direct(path);
    }
    match harness_sandbox::tier2a::privhelper::run_privileged(
        &harness_sandbox::tier2a::privhelper::PrivilegedRequest::RevokeTraverse {
            path: path.to_path_buf(),
        },
    ) {
        Ok(_) => {
            harness_sandbox::tier2a::traverse_ledger::remove_traverse_grant(path);
            println!(
                "revoked traverse ACE via privilege-separation helper: {}",
                path.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("revoke-traverse failed for {}: {e}", path.display());
            ExitCode::FAILURE
        }
    }
}

#[cfg(windows)]
pub(crate) fn fs_revoke_traverse_one_direct(path: &Path) -> ExitCode {
    // D-48: 撤収と撤収済み検証は`revoke_traverse_grant`が一体で行う（宛先のcapability SIDは
    // 関数内で導出されるので、ここでSIDを取り違えようがない）。台帳エントリの除去だけが
    // 呼び出し側の責務として残る。
    match harness_sandbox::tier2a::win_appcontainer::revoke_traverse_grant(path) {
        Ok(()) => {
            harness_sandbox::tier2a::traverse_ledger::remove_traverse_grant(path);
            println!("revoked traverse ACE: {}", path.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("revoke-traverse failed for {}: {e}", path.display());
            ExitCode::FAILURE
        }
    }
}

/// 台帳に載った traverse ACE を**まとめて撤収する**（`harness fs revoke-traverse-all`）。
///
/// # なぜ単発版のループではないのか（`B-02`）
///
/// 付与側は既に束ねてある——`grant-traverse`は祖先チェーン全部を "UAC, one-time" で付与し、
/// 起動時の付与（`GrantWorkspaceAccess`）も複数targetを1回で処理する。
/// 撤収側だけが単発しか持っておらず、以前のこの関数は
/// [`fs_revoke_traverse_one`]を台帳の件数だけ呼んでいた——**実機の563件で563回UACが出た**。
///
/// # 台帳から落とすのは「剥がせたもの」だけ
///
/// 失敗した分の記録を消すと、実マシンに残ったACEの在り処が分からなくなる（`B-01`）。
/// 昇格側の応答は撤収できたパスと失敗を分けて返すので、前者だけを台帳から除去する。
#[cfg(windows)]
pub(crate) fn fs_revoke_traverse_all() -> ExitCode {
    let ledger = harness_sandbox::tier2a::traverse_ledger::load_traverse_ledger();
    if ledger.entries.is_empty() {
        println!("(no traverse grants recorded)");
        return ExitCode::SUCCESS;
    }
    let paths: Vec<PathBuf> = ledger
        .entries
        .iter()
        .map(|e| PathBuf::from(&e.path))
        .collect();

    // 昇格済みならヘルパーを起こす理由が無い（UAC 0回）。単発版と同じ関数を通す。
    if harness_sandbox::tier2a::privhelper::is_elevated() {
        let mut any_failed = false;
        for path in &paths {
            if fs_revoke_traverse_one_direct(path) != ExitCode::SUCCESS {
                any_failed = true;
            }
        }
        return if any_failed {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        };
    }

    println!(
        "revoking {} traverse ACE(s) through the privilege-separation helper (one UAC prompt)...",
        paths.len()
    );
    match harness_sandbox::tier2a::privhelper::run_privileged_revoke_traverse_batch(paths.clone()) {
        Ok((revoked, failures)) => {
            for path in &revoked {
                harness_sandbox::tier2a::traverse_ledger::remove_traverse_grant(path);
            }
            println!("revoked traverse ACE on {} node(s)", revoked.len());
            if failures.is_empty() {
                return ExitCode::SUCCESS;
            }
            // **残した理由を黙らせない。** 件数だけだと「なぜ残ったか」が追えず、
            // 走行中セッションによる正当な拒否（D-48）と本物の失敗が混ざる。
            eprintln!(
                "{} node(s) were left in place (ledger entries kept so a retry finds them):",
                failures.len()
            );
            for (path, reason) in &failures {
                eprintln!("  {} : {reason}", path.display());
            }
            ExitCode::FAILURE
        }
        Err(e) => {
            // **1件も台帳から落とさない。** 要求ごと失敗しているので、どのACEが
            // 剥がれたかを名乗れる情報が無い（部分適用を勝手に仮定しない）。
            eprintln!("revoke-traverse-all failed: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
pub(crate) fn fs_revoke_traverse_one(_path: &Path) -> ExitCode {
    eprintln!("error: fs revoke-traverse is Windows-only (Tier2a specific)");
    ExitCode::FAILURE
}

#[cfg(not(windows))]
pub(crate) fn fs_revoke_traverse_all() -> ExitCode {
    eprintln!("error: fs revoke-traverse-all is Windows-only (Tier2a specific)");
    ExitCode::FAILURE
}
