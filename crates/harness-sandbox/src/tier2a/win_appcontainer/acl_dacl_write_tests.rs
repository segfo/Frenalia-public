//! [`super::acl_dacl_write`]（1ノードあたりDACL書込1回でM本のACEを配る部品）の受け入れ。
//!
//! **使い捨てではない。** 残課題#32が再発したら——つまり「rootへ1回書けば子孫へ行き渡る」が
//! また黙って効かなくなったら——ここが赤くなる。同じ回帰は
//! `acl_baseline_cost_tests`が製品の順序（同期区間→背景フェーズ0）でも押さえており、
//! **こちらは部品そのものの契約**（M本・順序・限界）を固定する。
//!
//! # ここで固定する3つの契約
//!
//! 1. **M本を1回で配る**——`InheritableGrant`をM本渡したら、M本すべてが既存の子孫へ届く。
//!    これが残課題#20の費用測定（M3）が要求している形である。
//! 2. **配る前に外す操作で、元々あった許可が狭まらない**——部品は伝播書込の直前に対象の宛先SIDの
//!    ACEを外すので、順序を間違えると別の形のACE（D-63の非継承object ACE等）が黙って消える。
//! 3. **保護DACL配下には届かない**——これは直っていない仕様であり、救済walkの担当である。
//!    「部品を入れたから救済walkは要らない」という誤読を、テストの形で塞ぐ。
//!
//! **非昇格**。ツリーもSIDもテスト自身が作ったものだけを触る（SIDは
//! [`super::capability_sid_from_name`]の純粋導出で、台帳には何も残さない）。

use super::test_support::{protect_dacl_preserve_inherited, TestDirGuard};
use super::*;

use crate::tier2a::win_appcontainer::acl_dacl_write::{grant_aces_propagating, InheritableGrant};

/// 小さく作る。**ここで測るのは時間ではなく真偽**なので、大きさに意味は無い
/// （コストは`acl_baseline_cost_tests`が持つ）。
const FANOUT: usize = 4;
const FILES: usize = 24;

fn subject(label: &str) -> crate::win_common::OwnedSid {
    let name = format!("harness-dacl-write-{}-{label}", std::process::id());
    super::capability_sid_from_name(&name).expect("derive capability sid")
}

/// 撤収して、**残っていないことを実測してから**戻る（BUG-101）。
fn revoke_and_verify(root: &std::path::Path, sid: PSID) {
    let _ = revoke_ace_recursive(root, sid).expect("revoke");
    if let Err(leftovers) = assert_no_sid_ace_recursive(root, sid) {
        panic!(
            "{} node(s) still carry the subject after revoke; first few: {:?}",
            leftovers.len(),
            leftovers.iter().take(3).collect::<Vec<_>>()
        );
    }
}

/// 契約1: **M本を1つのDACLへ畳んで1回書けば、M本すべてが既存の子孫へ届く。**
///
/// M=3は設計上の上限である（1つの宣言パスにつき`ro`/`rw`/`rx`の3種類まで。
/// `plans/HANDOFF-ACL-DOMAIN-SPLIT-COST.md`「変数はKではなくM」）。**8や16は測らない**
/// ——実ポリシーで到達しない値を測っても判断の材料にならない。
///
/// **宛先SIDごとにマスクを変えてある。** 全部同じマスクだと、1本しか配れていなくても
/// 「どれかのACEが届いている」で緑になり得る（B-35: 区別できる形で測る）。
#[test]
#[ignore = "creates files and writes DACLs; run NON-elevated"]
fn one_propagating_write_carries_every_subject_to_the_existing_descendants() {
    let dir = TestDirGuard::create("daclwrite-many");
    let root = dir.path();
    let nodes = super::test_support::build_wide_tree(root, FILES, FANOUT);

    let ro = subject("ro");
    let rx = subject("rx");
    let rwx = subject("rwx");
    let subjects = [
        (&ro, fs_access_mask(FsAccess::Read)),
        (&rx, fs_access_mask(FsAccess::ReadExec)),
        (&rwx, workspace_rwx_mask()),
    ];

    let grants: Vec<InheritableGrant> = subjects
        .iter()
        .map(|(sid, mask)| InheritableGrant {
            sid: sid.as_psid(),
            mask: *mask,
            inheritance: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
        })
        .collect();
    grant_aces_propagating(root, &grants, IdempotentCheck::Always)
        .expect("one propagating write for all three subjects");

    let leaf_file = root.join("d000").join("f000000.txt");
    let leaf_dir = root.join("d000");
    for (sid, mask) in subjects {
        for leaf in [&leaf_file, &leaf_dir] {
            assert_eq!(
                sid_effective_ace_mask(leaf, sid.as_psid()).expect("read the effective mask"),
                Some(mask),
                "{} must carry exactly this subject's own mask after the single write",
                leaf.display()
            );
        }
        // 救済walkに仕事が残っていないこと＝伝播が全ノードへ届いたこと。
        let report = fix_descendants_missing_ace(root, sid.as_psid(), mask, &[], &|_, _| {})
            .expect("rescue walk");
        assert_eq!(
            report.checked, nodes,
            "the walk must have visited every node before its `granted` can be read"
        );
        assert_eq!(
            report.granted, 0,
            "the single propagating write must have reached every existing descendant, but {} of \
             {} nodes still needed an explicit grant",
            report.granted, report.checked
        );
    }

    for (sid, _) in subjects {
        revoke_and_verify(root, sid.as_psid());
    }
}

/// **残課題#32そのもの（部品の水準での回帰）。**
///
/// 上の契約1のテストは、rootにその宛先SIDのACEが**まだ無い**状態から配る。それは修正前でも
/// 届く形なので、**あれは#32の回帰になっていない**（`B-27`: 歯があるか）。
/// ここは伝播しない口（`DaclWrite::SingleObject`）で**同じ宛先SID・同じ継承フラグ**のACEを
/// 先に置いてから配る——修正前はこの順序で 0/209 しか届かなかった。
///
/// 製品の順序（`preflight`の同期区間→背景フェーズ0）でも同じことを
/// `acl_baseline_cost_tests`が押さえているが、**あちらは経路の回帰、ここは部品の回帰**である。
/// 部品を別の呼び出し元から使ったときにも同じ保証が要る（残課題#20のM3・T1が使う）。
#[test]
#[ignore = "writes DACLs; run NON-elevated"]
fn the_write_reaches_descendants_even_when_the_subject_already_carried_that_ace() {
    let dir = TestDirGuard::create("daclwrite-preplaced");
    let root = dir.path();
    let nodes = super::test_support::build_wide_tree(root, FILES, FANOUT);
    let sid = subject("preplaced");
    let mask = workspace_rwx_mask();
    let both = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;

    // 製品の同期区間（`grant_workspace_root_rw_fast`）と同じ底＝伝播しない書込。
    grant_ace_mask(root, sid.as_psid(), mask, both).expect("the single-object root write");
    // この時点で子孫へは何も降りていないことを先に固定する（そうでないと、次の書込が
    // 何かをしたのかどうかが言えない）。
    let leaf = root.join("d000").join("f000000.txt");
    assert_eq!(
        sid_effective_ace_mask(&leaf, sid.as_psid()).expect("read the leaf mask"),
        None,
        "the non-propagating write must not have reached the descendants — if it did, this test \
         can no longer tell whether the propagating write did anything"
    );

    grant_aces_propagating(
        root,
        &[InheritableGrant {
            sid: sid.as_psid(),
            mask,
            inheritance: both,
        }],
        IdempotentCheck::Always,
    )
    .expect("the propagating grant");

    assert_eq!(
        sid_effective_ace_mask(&leaf, sid.as_psid()).expect("read the leaf mask"),
        Some(mask),
        "STATUS #32: the propagating write did not reach the existing descendants although the \
         subject already carried the same ACE on the root"
    );
    let report =
        fix_descendants_missing_ace(root, sid.as_psid(), mask, &[], &|_, _| {}).expect("walk");
    assert_eq!(report.checked, nodes, "the walk must have visited every node");
    assert_eq!(
        report.granted, 0,
        "the rescue walk had to write {} of {} nodes explicitly, which means the propagation is \
         doing nothing again",
        report.granted, report.checked
    );

    revoke_and_verify(root, sid.as_psid());
}

/// 冪等スキップは**M本すべてが満たされているときだけ**効く。
///
/// 半端に「足りない本だけ」を書くとノードあたりの書込が本数に比例し、この部品の目的
/// （1ノードあたり1回）が消える。だから判定は全称で、1本でも足りなければまとめて書き直す。
///
/// **両方向を対で測る**（`B-35`）——満たしているときに省くことと、1本でも足りなければ
/// 省かないこと。片方だけだと「常に省く」実装でも「常に書く」実装でも緑になる。
#[test]
#[ignore = "writes DACLs; run NON-elevated"]
fn the_idempotent_skip_needs_every_grant_to_be_satisfied() {
    let dir = TestDirGuard::create("daclwrite-skip");
    let root = dir.path();
    super::test_support::build_wide_tree(root, FILES, FANOUT);
    let a = subject("skip-a");
    let b = subject("skip-b");
    let both = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
    let mask = workspace_rwx_mask();
    let grant = |sid: PSID| InheritableGrant {
        sid,
        mask,
        inheritance: both,
    };
    let leaf = root.join("d000").join("f000000.txt");

    // 2本とも配る。
    grant_aces_propagating(
        root,
        &[grant(a.as_psid()), grant(b.as_psid())],
        IdempotentCheck::Always,
    )
    .expect("the initial grant");
    assert_eq!(
        sid_effective_ace_mask(&leaf, b.as_psid()).expect("read the leaf mask"),
        Some(mask)
    );

    // 満たしている側だけを`SkipIfSufficient`で撃つ＝何も起きてはいけない。**「起きなかった」を
    // 実際に見る**ため、先に葉のACEを剥がしておく——省かれたなら剥がしたままのはずである。
    revoke_ace_unguarded(&leaf, b.as_psid()).expect("strip the leaf ACE");
    grant_aces_propagating(root, &[grant(b.as_psid())], IdempotentCheck::SkipIfSufficient)
        .expect("the satisfied grant");
    assert_eq!(
        sid_effective_ace_mask(&leaf, b.as_psid()).expect("read the leaf mask"),
        None,
        "the write must have been skipped, so the leaf should still be missing its ACE"
    );

    // 1本でも足りなければ省かない。`a`は満たしているが`b`は要求マスクを広げてある。
    let wider = mask | WRITE_DAC.0;
    grant_aces_propagating(
        root,
        &[
            grant(a.as_psid()),
            InheritableGrant {
                sid: b.as_psid(),
                mask: wider,
                inheritance: both,
            },
        ],
        IdempotentCheck::SkipIfSufficient,
    )
    .expect("the partially unsatisfied grant");
    assert_eq!(
        sid_effective_ace_mask(&leaf, b.as_psid()).expect("read the leaf mask"),
        Some(wider),
        "one unsatisfied grant must make the whole set be written again"
    );

    revoke_and_verify(root, a.as_psid());
    revoke_and_verify(root, b.as_psid());
}

/// 契約2: **伝播書込の直前に対象の宛先SIDのACEを外しても、元々あった別の形のACEは残る。**
///
/// 部品は「組んでから外して書く」順序で動く。これを「外してから組む」に取り違えると、
/// D-63で同じパスに載り得る**非継承のobject ACE**が黙って消え、rootでの実効権限が狭まる
/// ——しかも狭まったことは成功に見える（`B-01`の非対称、`B-10`の無言失敗）。
///
/// ここでは先に**広いマスクの非継承ACE**を置き、そのうえで**狭いマスクの継承ACE**を
/// 伝播させる。畳んだ結果が広い方を含んでいなければ、順序が壊れている。
#[test]
#[ignore = "writes DACLs; run NON-elevated"]
fn the_existing_object_scoped_ace_survives_the_propagating_write() {
    let dir = TestDirGuard::create("daclwrite-order");
    let root = dir.path();
    super::test_support::build_wide_tree(root, FILES, FANOUT);
    let sid = subject("order");

    let wide = workspace_rwx_mask();
    let narrow = fs_access_mask(FsAccess::Read);
    // D-63の`GrantScope::Object`と同じ形（非継承・単一オブジェクト書込）。
    grant_ace_mask(root, sid.as_psid(), wide, NO_INHERITANCE).expect("the object-scoped grant");

    grant_aces_propagating(
        root,
        &[InheritableGrant {
            sid: sid.as_psid(),
            mask: narrow,
            inheritance: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
        }],
        IdempotentCheck::Always,
    )
    .expect("the propagating grant");

    let folded = sid_explicit_ace(root, sid.as_psid())
        .expect("read the root ACEs")
        .expect("the root must still carry this subject");
    assert_eq!(
        folded.mask & wide,
        wide,
        "the wider object-scoped ACE was silently dropped by the propagating write \
         (folded={folded:?})"
    );
    let both = (CONTAINER_INHERIT_ACE.0 | OBJECT_INHERIT_ACE.0) as u8;
    assert_eq!(
        folded.inherit & both,
        both,
        "the inheritable ACE is missing, so nothing would reach the descendants \
         (folded={folded:?})"
    );
    // 配下へ降りたのは**狭い方だけ**である。ここが広いなら、非継承で宣言したはずの権限が
    // ツリー全体へ漏れている（D-63が畳み込みを廃した理由そのもの）。
    let leaf = root.join("d000").join("f000000.txt");
    assert_eq!(
        sid_effective_ace_mask(&leaf, sid.as_psid()).expect("read the leaf mask"),
        Some(narrow),
        "the descendants must receive only the inheritable ACE's mask"
    );

    revoke_and_verify(root, sid.as_psid());
}

/// 契約3: **保護DACL配下には届かない。救済walkがそこを救う。**
///
/// 「部品が入ったので救済walkは要らない」という誤読を塞ぐためのテストである。
/// 保護（`SE_DACL_PROTECTED`）は継承そのものを止めるので、伝播がいくら効いていても
/// その配下は空のままになる——これは欠陥ではなく、`fix_descendants_missing_ace`が
/// 引き受けている当の仕事である（`grant_job`のフェーズ1）。
#[test]
#[ignore = "writes DACLs; run NON-elevated"]
fn a_protected_subtree_is_not_reached_by_propagation_and_the_rescue_walk_is_what_fixes_it() {
    let dir = TestDirGuard::create("daclwrite-protected");
    let root = dir.path();
    super::test_support::build_wide_tree(root, FILES, FANOUT);
    let sid = subject("protected");
    let mask = workspace_rwx_mask();

    let protected_dir = root.join("d001");
    protect_dacl_preserve_inherited(&protected_dir).expect("protect the subtree");

    grant_aces_propagating(
        root,
        &[InheritableGrant {
            sid: sid.as_psid(),
            mask,
            inheritance: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
        }],
        IdempotentCheck::Always,
    )
    .expect("the propagating grant");

    // 保護されていない側は届いている（陽性対照。これが無いと「全部届いていない」と
    // 区別が付かない）。
    assert_eq!(
        sid_effective_ace_mask(&root.join("d000"), sid.as_psid()).expect("read the mask"),
        Some(mask),
        "the unprotected subtree must have been reached by the propagation"
    );
    // 保護された側は届いていない。
    assert_eq!(
        sid_effective_ace_mask(&protected_dir, sid.as_psid()).expect("read the mask"),
        None,
        "a protected node must not receive the inherited ACE — if it does, the protection \
         (D-05/D-09 layer 3) is not holding and `.harness/**` would be writable from the sandbox"
    );

    // 救済walkがそこだけを直す。
    let report =
        fix_descendants_missing_ace(root, sid.as_psid(), mask, &[], &|_, _| {}).expect("walk");
    assert!(
        report.granted > 0,
        "the rescue walk is what covers protected subtrees; if it has nothing to do here, this \
         test is no longer measuring that division of labour"
    );
    assert_eq!(
        sid_effective_ace_mask(&protected_dir, sid.as_psid()).expect("read the mask"),
        Some(mask),
        "the rescue walk must have granted the protected node explicitly"
    );

    revoke_and_verify(root, sid.as_psid());
}
