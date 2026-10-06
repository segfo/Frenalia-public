//! [BUG-231](../../../../docs/bugs/BUG-231.md) の回帰試験。**カーネル経由でDACLを書く本番の3経路が、
//! 書いたノードの`SE_DACL_AUTO_INHERITED`（`AI`）を書く前のまま保つ**ことを固定する。
//!
//! 3経路: 付与（[`super::set_dacl_single_object`]、`grant_ace_mask`経由）・撤収
//! （[`set_dacl_single_object_with_protection`]、`revoke_sids_from_node`経由）・書込可否の確認
//! （`win_common::can_write_dacl`）。どれかで`keep_auto_inherited`を外すと、その経路の
//! 「印が残る」試験が赤くなる。
//!
//! 対で「印の無いノードには印を作らない」も見る——「常に`AI`を立てる」実装でも前者は通るため（B-35）。
//! 試験用のツリーは自分で`AI`を立てた一時ディレクトリに作る（`%TEMP%`自身の印の有無に左右されない）。

use super::*;

use super::dacl_auto_inherit_probe_tests::{
    add_inheritable_ace_via_aclapi, auto_inherited_tempdir, flags_text, has_inherited_ace_for,
    set_auto_inherited,
};

const TRAVERSE_LIKE_MASK: u32 = 0x0010_00a0;

fn has_ai(path: &Path) -> bool {
    dacl_control(path).expect("read the control bits") & SE_DACL_AUTO_INHERITED.0 != 0
}

fn control_text(path: &Path) -> String {
    flags_text(dacl_control(path).expect("read the control bits"))
}

/// 印付きの親の下に子を作り、子が印を受け継いだことを確かめて返す。
fn auto_inherited_child(root: &Path, name: &str) -> std::path::PathBuf {
    let child = root.join(name);
    std::fs::create_dir(&child).expect("create the child");
    assert!(
        has_ai(&child),
        "precondition: a child created under an AI parent must carry AI ({})",
        control_text(&child)
    );
    child
}

#[test]
fn granting_keeps_the_auto_inherited_flag() {
    let root = auto_inherited_tempdir();
    let node = auto_inherited_child(root.path(), "node");
    let sid = capability_sid_from_name("harnessBug231Grant").expect("sid");

    grant_ace_mask(&node, sid.as_psid(), TRAVERSE_LIKE_MASK, NO_INHERITANCE).expect("grant");

    assert!(
        sid_ace_mask(&node, sid.as_psid())
            .expect("read the ACE")
            .is_some(),
        "the grant must actually have written (otherwise this measures nothing)"
    );
    assert!(
        has_ai(&node),
        "granting an ACE must not clear SE_DACL_AUTO_INHERITED (BUG-231): {}",
        control_text(&node)
    );
}

#[test]
fn granting_does_not_invent_the_auto_inherited_flag() {
    let root = auto_inherited_tempdir();
    let node = auto_inherited_child(root.path(), "node");
    set_auto_inherited(&node, false);
    let sid = capability_sid_from_name("harnessBug231GrantNoAi").expect("sid");

    grant_ace_mask(&node, sid.as_psid(), TRAVERSE_LIKE_MASK, NO_INHERITANCE).expect("grant");

    assert!(
        !has_ai(&node),
        "a node without AI must stay without it (the fix keeps the state, it does not create it): {}",
        control_text(&node)
    );
}

#[test]
fn revoking_keeps_the_auto_inherited_flag_and_really_removes_an_inherited_ace() {
    let root = auto_inherited_tempdir();
    let parent = auto_inherited_child(root.path(), "parent");
    let inherited = capability_sid_from_name("harnessBug231RevokeInherited").expect("sid");
    add_inheritable_ace_via_aclapi(&parent, inherited.as_psid());
    let child = auto_inherited_child(&parent, "child");
    let inherited_string =
        crate::win_common::sid_to_string(inherited.as_psid()).expect("sid string");
    assert!(
        has_inherited_ace_for(&child, &inherited_string),
        "precondition: the child must have inherited the probe ACE"
    );

    let rewrote = revoke_sids_from_node(&child, &[inherited.as_psid()]).expect("revoke");

    assert!(rewrote, "the revoke must actually have written");
    assert!(
        !describe_dacl_aces_for_test(&child)
            .iter()
            .any(|a| a.ends_with(&inherited_string)),
        "the inherited ACE must really be gone after the revoke (AR must not bring it back)"
    );
    assert!(
        has_ai(&child),
        "revoking must not clear SE_DACL_AUTO_INHERITED (BUG-231): {}",
        control_text(&child)
    );
}

#[test]
fn revoking_does_not_invent_the_auto_inherited_flag() {
    let root = auto_inherited_tempdir();
    let node = auto_inherited_child(root.path(), "node");
    let sid = capability_sid_from_name("harnessBug231RevokeNoAi").expect("sid");
    grant_ace_mask(&node, sid.as_psid(), TRAVERSE_LIKE_MASK, NO_INHERITANCE).expect("grant");
    set_auto_inherited(&node, false);

    assert!(revoke_sids_from_node(&node, &[sid.as_psid()]).expect("revoke"));

    assert!(
        !has_ai(&node),
        "a node without AI must stay without it after a revoke: {}",
        control_text(&node)
    );
}

#[test]
fn checking_whether_the_dacl_is_writable_keeps_the_auto_inherited_flag() {
    let root = auto_inherited_tempdir();
    let node = auto_inherited_child(root.path(), "node");

    assert!(
        crate::win_common::can_write_dacl(&node),
        "we own the node, so it is writable"
    );

    assert!(
        has_ai(&node),
        "can_write_dacl claims to leave the node unchanged, so it must keep AI (BUG-231): {}",
        control_text(&node)
    );
}

fn describe_dacl_aces_for_test(path: &Path) -> Vec<String> {
    super::test_support::describe_dacl_aces(path).expect("list the ACEs")
}
