//! D9診断（`describe_passthrough_chain`）の単体テスト。**管理者権限も実機も要らない**。
//!
//! 診断の材料集め（`sid_ace_mask`によるDACL読取）と判定を分けたのは、判定の側を
//! ここで全数テストできる形に保つためである（`docs/CODE-STRUCTURE-RULES.md`規則3）。
//!
//! 固定したいのは[BUG-058](../../../../../docs/bugs/BUG-058.md)の核心
//! ——**祖先とleafはSIDの系統が違う**（D-37）。祖先の通過権は永続capability SID、
//! leafへのアクセス権はセッション限りのpackage SIDが持つ。旧実装は両方をセッションSIDで
//! 見ていたため、traverseが正常でも全祖先を「ACEが無い」と報告していた。

use std::path::{Path, PathBuf};

use windows::Win32::Storage::FileSystem::{
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_READ_ATTRIBUTES, FILE_TRAVERSE,
};

use super::preflight::{describe_passthrough_chain, PassthroughChainFacts};

/// 祖先が「通過できる」状態のマスク（`grant_traverse_chain`が実際に付与する値）。
const TRAVERSE_OK: u32 = FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0;
/// `FsAccess::ReadExec`（`--fs-allow`の既定、F8）が要求するマスク。
const READ_EXEC: u32 = FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0;

const LEAF: &str = r"C:\Users\someone\.cargo";

/// leafの親からドライブルートまで（浅い順）。**leaf自身は含まない**。
fn ancestors(masks: [Option<u32>; 3]) -> Vec<(PathBuf, Option<u32>)> {
    [r"C:\", r"C:\Users", r"C:\Users\someone"]
        .into_iter()
        .map(PathBuf::from)
        .zip(masks)
        .collect()
}

fn facts(leaf_mask: Option<u32>, ancestor_masks: [Option<u32>; 3]) -> PassthroughChainFacts {
    PassthroughChainFacts {
        leaf_mask,
        required_leaf_mask: READ_EXEC,
        ancestors: ancestors(ancestor_masks),
    }
}

/// **BUG-058の回帰そのもの**: 祖先がcapability SIDのtraverseを持ち、leafがsession SIDの
/// 十分なマスクを持つなら、診断は祖先を問題として挙げてはならない。
#[test]
fn a_healthy_chain_does_not_blame_the_ancestors() {
    let message = describe_passthrough_chain(
        Path::new(LEAF),
        "Access to the path is denied.",
        &facts(Some(READ_EXEC), [Some(TRAVERSE_OK); 3]),
    );

    assert!(
        !message.contains("missing traverse ACE"),
        "a fully granted chain must not be reported as missing traverse ACEs: {message}"
    );
    assert!(
        !message.contains("the target itself"),
        "a sufficient leaf mask must not be reported as a leaf problem: {message}"
    );
    assert!(
        message.contains("cause unknown"),
        "with nothing missing, the diagnosis must fall back to 'cause unknown': {message}"
    );
    // 生エラーは常に残す（D-43「失敗を隠さない」）。
    assert!(message.contains("Access to the path is denied."), "{message}");
}

/// 中間の祖先だけが欠けているとき、**そのノードだけ**を名指しする。
/// leafはtraverse ACEを持つ必要が無いので、欠落一覧へ混ぜてはならない。
#[test]
fn only_the_missing_intermediate_ancestor_is_named() {
    let message = describe_passthrough_chain(
        Path::new(LEAF),
        "probe error",
        &facts(
            Some(READ_EXEC),
            [Some(TRAVERSE_OK), None, Some(TRAVERSE_OK)],
        ),
    );

    assert!(
        message.contains("on 1 ancestor node(s)"),
        "exactly one ancestor is missing: {message}"
    );
    assert!(
        message.contains(r"C:\Users (no ACE for the traverse capability SID)"),
        "{message}"
    );
    // leafはメッセージ先頭と修復コマンドには出るので、「文中に出ない」ではなく
    // **欠落一覧の中に出ない**ことを確かめる（旧実装は`ancestors()`にleafを含めていた）。
    let after_list_header = message
        .split("ancestor node(s): ")
        .nth(1)
        .expect("the missing-node list must be present");
    let missing_list = after_list_header
        .split(" -- fix")
        .next()
        .expect("split always yields at least one element");
    assert!(
        !missing_list.contains(".cargo"),
        "the leaf must not appear in the missing-ancestor list: {missing_list}"
    );
    assert!(
        message.contains(&format!("harness fs grant-traverse {LEAF}")),
        "the one-shot repair command must be offered: {message}"
    );
}

/// 祖先に`FILE_TRAVERSE`はあるが`FILE_READ_ATTRIBUTES`が無い場合も欠落として扱う
/// （M12追記8: `FILE_TRAVERSE`単独ではRead Attributesの拒否が残り不十分）。
#[test]
fn a_partial_ancestor_mask_still_counts_as_missing() {
    let message = describe_passthrough_chain(
        Path::new(LEAF),
        "probe error",
        &facts(
            Some(READ_EXEC),
            [Some(TRAVERSE_OK), Some(FILE_TRAVERSE.0), Some(TRAVERSE_OK)],
        ),
    );

    assert!(
        message.contains(
            r"C:\Users (has a traverse-capability ACE but missing FILE_TRAVERSE|FILE_READ_ATTRIBUTES)"
        ),
        "{message}"
    );
}

/// leafのマスクが要求を満たさないときは、**祖先ではなくleafの問題**として報告する。
#[test]
fn an_insufficient_leaf_mask_is_reported_as_a_leaf_problem() {
    let message = describe_passthrough_chain(
        Path::new(LEAF),
        "probe error",
        // 読取だけ付いていて実行ビットが無い＝`ReadExec`の要求を満たさない。
        &facts(Some(FILE_GENERIC_READ.0), [Some(TRAVERSE_OK); 3]),
    );

    assert!(
        !message.contains("missing traverse ACE"),
        "the ancestors are fine; do not blame them: {message}"
    );
    assert!(
        message.contains("the target itself carries a session SID ACE"),
        "{message}"
    );
    assert!(
        message.contains(&format!("{:#010x}", READ_EXEC)),
        "the requested mask must be printed so the gap is inspectable: {message}"
    );
}

/// leafにACEが1つも無い場合（付与自体が失敗していた等）。
#[test]
fn a_missing_leaf_ace_is_reported_as_a_leaf_problem() {
    let message = describe_passthrough_chain(
        Path::new(LEAF),
        "probe error",
        &facts(None, [Some(TRAVERSE_OK); 3]),
    );

    assert!(
        message.contains("no ACE for this session's package SID"),
        "{message}"
    );
    assert!(!message.contains("missing traverse ACE"), "{message}");
}

/// 祖先とleafが同時に壊れているときは両方を報告する（片方で打ち切らない）。
#[test]
fn both_problems_are_reported_together() {
    let message = describe_passthrough_chain(
        Path::new(LEAF),
        "probe error",
        &facts(None, [Some(TRAVERSE_OK), None, None]),
    );

    assert!(message.contains("on 2 ancestor node(s)"), "{message}");
    assert!(
        message.contains("no ACE for this session's package SID"),
        "{message}"
    );
}
