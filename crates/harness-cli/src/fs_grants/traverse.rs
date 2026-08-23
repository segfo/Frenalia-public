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
            "already has FILE_TRAVERSE|FILE_READ_ATTRIBUTES -- write will be SKIPPED"
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
    // 既にFILE_TRAVERSE|FILE_READ_ATTRIBUTESを持っているなら、privhelperもUACも一切呼ばず
    // 即座に成功する。`preview_traverse_chain`は`--dry-run`が使うのと同じ読み取り専用ヘルパで、
    // `WRITE_DAC`もUACも要らない。
    if let Ok(sid) = harness_sandbox::tier2a::win_appcontainer::traverse_capability_sid() {
        let preview = harness_sandbox::tier2a::win_appcontainer::preview_traverse_chain(
            target,
            sid.as_psid(),
        );
        if !preview.is_empty() && preview.iter().all(|node| node.already_sufficient) {
            for node in &preview {
                harness_sandbox::tier2a::traverse_ledger::record_traverse_grant(&node.path);
            }
            println!(
                "grant-traverse: all {} ancestor node(s) already have \
                 FILE_TRAVERSE|FILE_READ_ATTRIBUTES -- skipped the privilege-separation helper \
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
    match harness_sandbox::tier2a::privhelper::run_privileged(
        &harness_sandbox::tier2a::privhelper::PrivilegedRequest::GrantTraverse {
            target: target.to_path_buf(),
        },
    ) {
        Ok(granted) => {
            for node in &granted {
                harness_sandbox::tier2a::traverse_ledger::record_traverse_grant(node);
            }
            println!(
                "granted FILE_TRAVERSE|FILE_READ_ATTRIBUTES via privilege-separation helper \
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
            for node in &granted {
                harness_sandbox::tier2a::traverse_ledger::record_traverse_grant(node);
            }
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
    let (granted, result) =
        harness_sandbox::tier2a::win_appcontainer::grant_traverse_chain(target, sid.as_psid());
    for node in &granted {
        harness_sandbox::tier2a::traverse_ledger::record_traverse_grant(node);
    }
    match result {
        Ok(()) => {
            println!(
                "granted FILE_TRAVERSE|FILE_READ_ATTRIBUTES (admin, one-time; see \
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
    // 払わせてから拒否しても払わせた意味が無いためで、`revoke-traverse-all`では台帳に載った
    // 件数だけUACが出る。判定は昇格側と同じ関数（`traverse_revoke_guard`）を通し、
    // 昇格側は昇格側でもう一度自分で見る（D-16。ここを通ったことを昇格側は信用しない）。
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
    // D-48: 撤収と撤収済み検証は`revoke_traverse_grant`が一体で行う（主体のcapability SIDは
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

#[cfg(not(windows))]
pub(crate) fn fs_revoke_traverse_one(_path: &Path) -> ExitCode {
    eprintln!("error: fs revoke-traverse is Windows-only (Tier2a specific)");
    ExitCode::FAILURE
}
