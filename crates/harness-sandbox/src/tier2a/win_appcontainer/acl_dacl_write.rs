//! **1ノードあたりDACL書込1回で、M本のACEを既存の子孫まで行き渡らせる部品**
//! （`docs/STATUS.md` 残課題#32の修正本体、`plans/handoff-issue-20/INDEX.md` T3）。
//!
//! # 何のためにあるのか
//!
//! ツリー全体へ許可を配る安い方法は「rootへ継承ありのACEを1本書いて、あとはOSに配らせる」で、
//! 書込は1回で済む。高い方法は「全ノードを歩いて1件ずつ書く」で、ノード数に比例する。
//! **この2つは同じ結果を作るので、安い方が黙って効かなくなっても機能は壊れない。**
//! 実際にそうなっていた（残課題#32）。
//!
//! ここは安い方の口を1つに束ね、**効かなくなる条件を型と実装の側で潰す**ためのモジュールである。
//!
//! # 実測で分かったこと（2026-08-25、`acl_propagation_probe_tests`）
//!
//! **rootのDACLを`SetKernelObjectSecurity`（伝播しない口）で書いたあとに
//! `SetNamedSecurityInfoW`（伝播する口）で同じ宛先SID・同じ継承フラグのACEを書くと、
//! 既存の子孫へ1件も届かないことがある。** 209ノードの対で 0/209 対 208/209。
//!
//! 1差分ずつ並べて切り分けた（`granted`=救済walkが明示ACEを書いた数。`C:\`直下のツリー）。
//!
//! | 1回目の書込 | 2回目の書込 | 届いたか |
//! |---|---|---|
//! | なし | aclapi | **届く** |
//! | kernel | aclapi | 届かない |
//! | kernel（`SE_DACL_AUTO_INHERITED`を立てる） | aclapi | 届かない |
//! | kernel | aclapi＋`UNPROTECTED_DACL_SECURITY_INFORMATION` | 届かない |
//! | kernel → **そのACEを剥がす** | aclapi | **届く** |
//! | kernel（狭いマスク） | aclapi（広いマスク） | 届かない |
//! | **aclapi**（狭いマスク） | aclapi（広いマスク） | **届く** |
//! | kernel（**非継承**） | aclapi（継承あり） | **届く** |
//!
//! **`plans/mac-spike/RESULTS.md` §S10-3 と `docs/STATUS.md` 残課題#32 に書かれている推定**
//! （`SetKernelObjectSecurity`が`SE_DACL_AUTO_INHERITED`を立てないため）**は誤りである。**
//! 制御ビットは全通りで最終的に`0x400`が立っており、**明示的に立てても直らず**、
//! `UNPROTECTED_DACL_SECURITY_INFORMATION`でも直らなかった。
//!
//! ## **書込列だけでは決まらない。ツリーの置き場所でも変わる**
//!
//! **同じ内容・同じ書込列のツリーを別の親の下に置くと、結果が反転する**（1,174ノード、
//! `preflight`を実際に通した測定）。
//!
//! | ワークスペース | 修正前の`granted` | 修正後 |
//! |---|---|---|
//! | `C:\harness-t3-loc-a` | **1,173 / 1,174** | **0 / 1,174** |
//! | `C:\Users\…\Documents\AI\harness-t3-loc-b`（内容は上と同一） | 0 / 1,174 | 0 / 1,174 |
//!
//! 親を振って挟み撃ちした結果、**`C:\`直下と`C:\harness-t3-base`（`C:\`直下に作った平のディレクトリ）
//! では再現し、ユーザープロファイル配下では再現しない**。`SE_DACL_AUTO_INHERITED`が親に
//! 立っているかでは説明が付かない（`C:\Users\segfo`は`AI=False`だが再現しない）。
//!
//! **したがって「どういう規則で決まるのか」は未確定である。** 分かっているのは
//! **どの条件で壊れるか**（上の2つの表）と、**この部品を通せばどちらの置き場でも届く**ことだけ。
//! **外挿しないこと**——とくに「ユーザープロファイル配下なら安全」と読まないこと。
//! 測ったのは2つの親であって、規則ではない。
//!
//! ### **似た「置き場で割れる」が別件で解決したが、これはその現象ではない**
//!
//! [BUG-145](../../../../docs/bugs/BUG-145.md)でも「`C:\`直下では壊れ`%TEMP%`では壊れない」が
//! 出て、そちらは**置き場ではなく「自分がその状態を書いたか」で割れていた**と確定した
//! （`plans/mac-spike/RESULTS.md` §S34）。**同じ説明をここへ持ち込まないこと。**
//! あちらが測ったのは**保護（`SE_DACL_PROTECTED`）が落ちるか**で、ここが測っているのは
//! **配布が既存の子孫へ届くか**である。**別の現象で、こちらは依然として未確定である。**
//!
//! ## 影響範囲についての帰結（**severityの読み替え**）
//!
//! §S10-3 の「26万ノードで初回42.9秒→21.6秒」は **`C:\harness-Tier2a-verify-*`**、つまり
//! **`C:\`直下の合成ツリー**での測定である。上のとおり置き場所で結果が変わるので、
//! **あの数字をすべてのワークスペースへ一般化できない。** 実際、この開発機の
//! `C:\Users\…\Documents\AI\` 配下のワークスペースは**修正前から`granted=0`**だった。
//!
//! # だからこの部品は何をするか
//!
//! 伝播する書込の**直前に、これから書く宛先SIDのACEをそのノードから外す**。外したうえで
//! M本まとめたDACLを1回書く。1つ目の表の5行目（剥がしてから伝播＝届く）そのものである。
//!
//! **機序が未確定でも、この形を選べる理由**: 8通り×2箇所の実測で「届く」側にいるのは
//! 「伝播書込の時点でその宛先SIDのACEがrootに無い」形だけで、**それは剥がせば必ず作れる**。
//! 未確定なのは「なぜ在ると届かないのか」であって、「無ければ届く」ではない。
//!
//! **外す前にDACLを組み終えておく**のが要点で、こうすると「元々そこに在った別の形のACE
//! （非継承のobject ACE等、D-63）」も組み上がったDACLの中に残る——**外す操作で権限が
//! 狭まらない**。順序を逆にすると、剥がした側が黙って消える（`B-01`の非対称）。
//!
//! # 限界（**ここで守っていないもの**）
//!
//! - **保護DACL（`SE_DACL_PROTECTED`）配下には依然として届かない。** それはOSの仕様であり、
//!   救済walk（[`super::fix_descendants_missing_ace`]）が引き続き担当する。
//!   **この部品は救済walkを不要にしない。**
//! - **届いたことをこの部品は確かめない。** 確かめているのは呼び出し側の救済walkで、
//!   その`granted`が0でなければ伝播が効いていない（`grant_job`が値を出す）。
//!   ここで別の検算を足すと、同じ事実を2箇所で判定することになる（`B-05`）。
//! - **一瞬だけ、rootにその宛先SIDのACEが無い状態が生まれる。** 子プロセスはこのジョブの完了を
//!   `grant_job::wait_until_done`で待つ（fail-closed）ので、その窓を踏まない。
//!   窓の途中でプロセスが死んだ場合は、次回起動の`top_level_child_missing_ace`が拾って
//!   ジョブが回り直す。

use super::*;

/// 1回の伝播書込に載せる1本ぶんの許可。
///
/// **M本を1つのDACLへ畳んで1回で書く**ためにある（残課題#20の費用測定M3が要求している形。
/// `plans/mac-spike/RESULTS.md` §S9-4・§S15-1——素直に「宛先SIDごとに1回ずつ伝播」と書くと
/// ノードあたりM回の書込になり、実測で約2倍になる）。
#[derive(Debug, Clone, Copy)]
pub(crate) struct InheritableGrant {
    pub sid: PSID,
    pub mask: u32,
    pub inheritance: windows::Win32::Security::ACE_FLAGS,
}

/// `root`のDACLへ`grants`の全本を**まとめて1回で**書き、既存の子孫へ伝播させる。
///
/// 書込回数は**ノードあたり1回**（rootへの伝播書込1回。剥がす側は対象ACEが在るときだけ
/// 追加でもう1回で、これはノード数に依存しない定数である）。子孫へはOSが配る。
///
/// **`grants`が空なら何もしない。** 「配るものが無い」は失敗ではない。
///
/// `idempotent`は[`super::IdempotentCheck`]と同じ意味で、**M本すべてが既に満たされているときだけ**
/// 省く（1本でも足りなければ、まとめて1回書く——半端に「足りない本だけ」を書くと
/// ノードあたりの書込が本数に比例して増え、この部品の目的そのものが消える）。
/// `IdempotentCheck::Always`を渡す呼び出し（`grant_job`のフェーズ0）は省かない。
pub(crate) fn grant_aces_propagating(
    root: &Path,
    grants: &[InheritableGrant],
    idempotent: IdempotentCheck,
) -> Result<(), AppContainerError> {
    grant_aces(root, grants, idempotent, DaclWrite::Propagate)
}

/// [`grant_aces_propagating`]の**このオブジェクトだけ**版（[`DaclWrite::SingleObject`]）。
///
/// M本を1つのDACLへ畳んで1回で書くところは同じで、違うのは**子孫へ配らない**ことだけである。
/// [D-84]で「両モードのcapability SID宛ACEを同時に置く」ようになったあと、これが要る場所は2つある——
/// `preflight`の同期区間（rootへの高速付与）と、救済walk（継承が届かなかったノードへの
/// 個別付与）。**どちらもノードあたりの書込を1回に保つためにここを通る**
/// （宛先SIDごとに`grant_ace_mask`を呼び直すと、`plans/mac-spike/RESULTS.md` §S15-1が測った
/// 「素朴な実装は約2.9倍」をそのまま払う）。
pub(crate) fn grant_aces_single_object(
    path: &Path,
    grants: &[InheritableGrant],
    idempotent: IdempotentCheck,
) -> Result<(), AppContainerError> {
    grant_aces(path, grants, idempotent, DaclWrite::SingleObject)
}

/// [`grant_aces_propagating`]／[`grant_aces_single_object`]の共通の実体。
///
/// **書込の口だけが違う**ので1つにしてある（`docs/CODE-STRUCTURE-RULES.md` §5.0）。
/// 冪等判定・DACLの畳み方・計装はどちらの口でも同じでなければならない——分けて書くと、
/// 片方にだけ入れた手当てがもう片方から抜ける（`B-02`）。
fn grant_aces(
    root: &Path,
    grants: &[InheritableGrant],
    idempotent: IdempotentCheck,
    write: DaclWrite,
) -> Result<(), AppContainerError> {
    if grants.is_empty() {
        return Ok(());
    }
    if matches!(idempotent, IdempotentCheck::SkipIfSufficient)
        && grants.iter().all(|grant| {
            matches!(
                sid_explicit_ace(root, grant.sid),
                Ok(Some(existing)) if existing.satisfies(grant.mask, grant.inheritance.0 as u8)
            )
        })
    {
        return Ok(());
    }
    // [BUG-101] 低レベルの付与口はどれも計装の対象にする。**入口が1つ増えたときに黙って
    // 対象外にならないようにするため**で、`grant_ace_mask_with_checked`が同じ理由で
    // 同じ呼び出しを持っている（B-06）。
    for grant in grants {
        crate::tier2a::grant_audit::note_low_level_grant(root, grant.sid);
    }

    let to_err = |e: windows::core::Error| AppContainerError::AclGrant {
        path: root.to_path_buf(),
        reason: e.to_string(),
    };
    unsafe {
        let path_w = long_path_wide(root);
        let mut existing_dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing_dacl),
            None,
            &mut sd,
        )
        .ok()
        .map_err(to_err)?;

        // M本を**1回の`SetEntriesInAclW`で**畳む。ここが「ノードあたり1回」の実体で、
        // 既存呼び出し（`grant_ace_mask_with_checked`）が配列の口へ1本しか渡していなかった
        // のを広げただけである（新しい機構ではない）。
        let entries: Vec<EXPLICIT_ACCESS_W> = grants
            .iter()
            .map(|grant| {
                let mut trustee = TRUSTEE_W::default();
                BuildTrusteeWithSidW(&mut trustee, grant.sid);
                EXPLICIT_ACCESS_W {
                    grfAccessPermissions: grant.mask,
                    grfAccessMode: GRANT_ACCESS,
                    grfInheritance: grant.inheritance,
                    Trustee: trustee,
                }
            })
            .collect();
        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        let merged = SetEntriesInAclW(
            Some(&entries),
            Some(existing_dacl as *const _),
            &mut new_dacl,
        )
        .ok();
        // `existing_dacl`は`sd`の中を指しているので、畳み終えたここで解放してよい。
        let _ = LocalFree(HLOCAL(sd.0));
        merged.map_err(to_err)?;

        let result = match write {
            DaclWrite::Propagate => {
                let sids: Vec<PSID> = grants.iter().map(|g| g.sid).collect();
                propagate_merged_dacl(root, &sids, new_dacl)
            }
            // **こちらは剥がさない。** 剥がすのは「伝播が既存の子孫へ届かない」ための手当てで
            // （モジュールdocの表）、子孫へ配らないこの口では要らない。ここで剥がすと、
            // 書込の直前にrootの許可が一瞬消える窓を、必要も無いのに作ることになる。
            DaclWrite::SingleObject => super::set_dacl_single_object(root, new_dacl).map_err(|e| {
                AppContainerError::AclGrant {
                    path: root.to_path_buf(),
                    reason: e.to_string(),
                }
            }),
        };
        let _ = LocalFree(HLOCAL(new_dacl as *mut _));
        result
    }
}

/// **組み上がったDACLを、伝播が実際に効く形で1回書く**（モジュールdocの表の5行目）。
///
/// `trustees`は「これから書くDACLに載っている宛先SID」で、書込の**直前にそのノードから外す**。
/// `new_dacl`は**外す前に組み終えていること**——外した後の状態から組むと、元々そこに在った
/// 別の形のACEが消える。
///
/// # 安全性
///
/// `new_dacl`は有効なACLを指していること。呼び出し側が解放を持つ。
pub(crate) unsafe fn propagate_merged_dacl(
    path: &Path,
    trustees: &[PSID],
    new_dacl: *mut ACL,
) -> Result<(), AppContainerError> {
    // 伝播しない口（`SetKernelObjectSecurity`）で置かれた同一の宛先SID・同一継承フラグのACEが
    // 残っていると、この後の書込は既存の子孫へ1件も届かない（モジュールdocの実測表）。
    // **対象ACEが無ければ`revoke_sids_from_node`は書込ごと省く**ので、初回のような
    // 「元々無い」ケースで余計な書込は起きない。
    revoke_sids_from_node(path, trustees)?;
    unsafe { set_dacl_propagating(path, new_dacl) }.map_err(|e| AppContainerError::AclGrant {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })
}
