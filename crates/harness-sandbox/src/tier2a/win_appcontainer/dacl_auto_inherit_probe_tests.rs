//! [BUG-231](../../../../docs/bugs/BUG-231.md) の実測プローブ。
//! **カーネル経由（`SetKernelObjectSecurity`）でDACLを書くと、`SE_DACL_AUTO_INHERITED`（`AI`）は
//! どうなるのか**を、渡す制御ビットを1つずつ変えて1回で測る。
//!
//! # なぜ測るのか
//!
//! `AI`は「このDACLの受け継いだACEは、自動継承の規則で配られたものだ」という印である。印の無い
//! フォルダの下に作った子にも印が付かず、印の無いノードでは`icacls /inheritance:r`などのaclapi系の
//! 道具が**受け継いだACEを明示ACEとして扱う**（消さずに残す）。2026-10-06、祖先への通行許可の
//! 書直し（BUG-230のマスク変更が引き金）で`%TEMP%`の印が消え、`icacls`で仕込みを作る試験2本が
//! 前提ごと崩れた。
//!
//! 本番のカーネル経由の書込（[`super::set_dacl_single_object`]・
//! [`set_dacl_single_object_with_protection`]・`win_common::can_write_dacl`）は、空のSDに
//! DACLだけを入れて書く。直し方を決めるには次の4点が要る:
//!
//! - **M0** 制御ビット0で書く（修正前の本番）→ 印は消えるか（再現）
//! - **M1** `AI`だけ渡す（`AR`=`SE_DACL_AUTO_INHERIT_REQ`無し）→ 印は残るか
//! - **M2** `AR|AI`を渡す → 印は残り、ACEの並びは変わらないか
//! - **M3** `AR|AI`で**受け継いだACE（`INHERITED_ACE`付き）を1本抜いた**DACLを書く → 本当に消えるか
//!   （撤収は受け継いだACEも剥がす。カーネルが古いDACLから受け継いだACEを戻すなら、撤収が無言で空振りする）
//! - **M3b** 同じ抜き方を`AR`無しで → 消えるか（M3の対照）
//! - **M4** `P|AR|AI`を渡す → `PAI`になるか（撤収は保護状態を保って書く）
//!
//! **合否を判定しない観測用**（`dacl_protection_probe_tests`と同じ思想）。アサートは前提だけ。
//! `%TEMP%`配下の自分で作ったツリーだけを書く。管理者権限は要らない。

use super::*;

use windows::Win32::Security::{
    SetSecurityDescriptorControl, SECURITY_DESCRIPTOR_CONTROL, SE_DACL_AUTO_INHERIT_REQ,
};

/// 受け継がせるACEに使うマスク（読取＋実行）。値に意味は無い。
const INHERITED_MASK: u32 = 0x0012_00a9;
/// `INHERITED_ACE`（WinNT.h）。
const INHERITED_ACE_FLAG: u8 = 0x10;

/// `path`へ`new_dacl`をカーネル経由で書く。制御ビットは`mask`の範囲で`value`にする
/// （`mask`が0なら`SetSecurityDescriptorControl`を呼ばない＝修正前の本番と同じ）。
pub(super) unsafe fn kernel_write(
    path: &Path,
    new_dacl: *mut ACL,
    mask: u16,
    value: u16,
) -> windows::core::Result<()> {
    unsafe {
        let path_w = long_path_wide(path);
        let handle = CreateFileW(
            PCWSTR(path_w.as_ptr()),
            (WRITE_DAC | READ_CONTROL).0,
            FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )?;
        let mut sd = SECURITY_DESCRIPTOR::default();
        let sd_ptr = PSECURITY_DESCRIPTOR(&mut sd as *mut _ as *mut _);
        let result = (|| -> windows::core::Result<()> {
            InitializeSecurityDescriptor(sd_ptr, SECURITY_DESCRIPTOR_REVISION)?;
            SetSecurityDescriptorDacl(sd_ptr, true, Some(new_dacl as *const _), false)?;
            if mask != 0 {
                SetSecurityDescriptorControl(
                    sd_ptr,
                    SECURITY_DESCRIPTOR_CONTROL(mask),
                    SECURITY_DESCRIPTOR_CONTROL(value),
                )?;
            }
            SetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION, sd_ptr)
        })();
        let _ = CloseHandle(handle);
        result
    }
}

/// `path`の今のDACLから`remove`宛のACEを除いた写しを作り、カーネル経由で書く。
fn rewrite(path: &Path, remove: &[PSID], mask: u16, value: u16) -> windows::core::Result<()> {
    unsafe {
        let path_w = long_path_wide(path);
        let mut existing: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing),
            None,
            &mut sd,
        )
        .ok()?;
        let mut buf = Vec::new();
        let copied = copy_dacl_excluding_sids(existing as *const _, remove, &mut buf);
        let _ = LocalFree(HLOCAL(sd.0));
        let (new_dacl, _removed) = copied?;
        kernel_write(path, new_dacl, mask, value)
    }
}

/// `path`の`AI`を、DACLの中身はそのままで`on`にする（`AR`の有無で立てる／落とす。M0・M2の結果）。
pub(super) fn set_auto_inherited(path: &Path, on: bool) {
    let ai = SE_DACL_AUTO_INHERITED.0;
    let ar = SE_DACL_AUTO_INHERIT_REQ.0;
    let (mask, value) = if on { (ai | ar, ai | ar) } else { (0, 0) };
    rewrite(path, &[], mask, value).expect("rewrite the DACL to set AI");
    let control = dacl_control(path).expect("read the control back");
    assert_eq!(
        control & ai != 0,
        on,
        "could not put AI={on} on {} (control {})",
        path.display(),
        flags_text(control)
    );
}

/// `%TEMP%`の下に、**自分で`AI`を立てた**一時ディレクトリを作る。`%TEMP%`自身の印の有無
/// （BUG-231で実際に消えた）に測定を左右させないため。
pub(super) fn auto_inherited_tempdir() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("tempdir");
    set_auto_inherited(root.path(), true);
    root
}

/// `parent`へ、`sid`宛の受け継がれるACE（`OI|CI`）をaclapiで足す（aclapiは`AI`を保つ）。
pub(super) fn add_inheritable_ace_via_aclapi(parent: &Path, sid: PSID) {
    unsafe {
        let path_w = long_path_wide(parent);
        let mut existing: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing),
            None,
            &mut sd,
        )
        .ok()
        .expect("read the parent DACL");
        let mut trustee = TRUSTEE_W::default();
        BuildTrusteeWithSidW(&mut trustee, sid);
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: INHERITED_MASK,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
            Trustee: trustee,
        };
        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        SetEntriesInAclW(Some(&[ea]), Some(existing as *const _), &mut new_dacl)
            .ok()
            .expect("merge the inheritable ACE");
        set_dacl_propagating(parent, new_dacl).expect("write the parent DACL via aclapi");
        let _ = LocalFree(HLOCAL(new_dacl as *mut _));
        let _ = LocalFree(HLOCAL(sd.0));
    }
}

/// `sid`宛の、受け継いだ（`INHERITED_ACE`付き）ACEが`path`に載っているか。
pub(super) fn has_inherited_ace_for(path: &Path, sid_string: &str) -> bool {
    describe_dacl_aces(path)
        .expect("list the ACEs")
        .iter()
        .any(|ace| ace.ends_with(sid_string) && ace_flags(ace) & INHERITED_ACE_FLAG != 0)
}

fn ace_flags(described: &str) -> u8 {
    described
        .split(';')
        .find_map(|part| part.strip_prefix("flags="))
        .and_then(|hex| u8::from_str_radix(hex.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0)
}

use super::test_support::describe_dacl_aces;

pub(super) fn flags_text(control: u16) -> String {
    let mut out = String::new();
    if control & SE_DACL_PROTECTED.0 != 0 {
        out.push('P');
    }
    if control & SE_DACL_AUTO_INHERITED.0 != 0 {
        out.push_str("AI");
    }
    if control & SE_DACL_AUTO_INHERIT_REQ.0 != 0 {
        out.push_str("(AR)");
    }
    if out.is_empty() {
        out.push('-');
    }
    format!("{out} (0x{control:04x})")
}

/// [BUG-231] カーネル経由の書込で`AI`がどうなるかを、渡す制御ビットごとに測る。
#[test]
#[ignore = "実FSのDACLを書き換える観測用プローブ（%TEMP%配下のみ、管理者権限不要）。結果はdocs/bugs/BUG-231.mdへ転記する"]
fn kernel_dacl_write_and_the_auto_inherited_flag_probe() {
    let root = auto_inherited_tempdir();
    let parent = root.path().join("parent");
    std::fs::create_dir(&parent).expect("parent");
    let sid = capability_sid_from_name("harnessBug231Probe").expect("probe sid");
    let sid_string = crate::win_common::sid_to_string(sid.as_psid()).expect("sid string");
    add_inheritable_ace_via_aclapi(&parent, sid.as_psid());

    // 前提: 親に`AI`が立っていること（無ければ子にも付かず、以下は何も測らない）。
    let parent_control = dacl_control(&parent).expect("parent control");
    assert!(
        parent_control & SE_DACL_AUTO_INHERITED.0 != 0,
        "precondition: the probe parent must carry AI, got {}",
        flags_text(parent_control)
    );

    let ai = SE_DACL_AUTO_INHERITED.0;
    let ar = SE_DACL_AUTO_INHERIT_REQ.0;
    let p = SE_DACL_PROTECTED.0;
    let all = ai | ar | p;
    let none: &[PSID] = &[];
    let target = [sid.as_psid()];
    // (名前, 受け継いだACEを抜くか, mask, value)
    let cases: [(&str, bool, u16, u16); 6] = [
        ("M0 control 0 (pre-fix production)", false, 0, 0),
        ("M1 AI only, no AR", false, all, ai),
        ("M2 AR|AI, same DACL", false, all, ar | ai),
        ("M3 AR|AI, inherited ACE removed", true, all, ar | ai),
        ("M3b no AR, inherited ACE removed", true, 0, 0),
        ("M4 P|AR|AI, same DACL", false, all, p | ar | ai),
    ];

    println!("\n=== BUG-231: kernel DACL write vs SE_DACL_AUTO_INHERITED ===");
    for (index, (name, remove, mask, value)) in cases.iter().enumerate() {
        let child = parent.join(format!("c{index}"));
        std::fs::create_dir(&child).expect("child");
        let before = dacl_control(&child).expect("control before");
        let aces_before = describe_dacl_aces(&child).expect("aces before");
        // 前提: 子は印を受け継ぎ、受け継いだACEを持っている。
        assert!(
            before & ai != 0 && has_inherited_ace_for(&child, &sid_string),
            "precondition for {name}: the fresh child must carry AI and the inherited probe ACE \
             (control {}, aces {aces_before:?})",
            flags_text(before)
        );

        let result = rewrite(&child, if *remove { &target } else { none }, *mask, *value);
        let after = dacl_control(&child).expect("control after");
        let aces_after = describe_dacl_aces(&child).expect("aces after");
        let inherited_still_there = has_inherited_ace_for(&child, &sid_string);
        let any_probe_ace = aces_after.iter().any(|a| a.ends_with(&sid_string));
        println!(
            "{name}\n    write={result:?}\n    control {} -> {}\n    ACE list unchanged: {}\n    \
             probe ACE after: inherited={inherited_still_there} any={any_probe_ace}",
            flags_text(before),
            flags_text(after),
            aces_before == aces_after
        );
        if aces_before != aces_after {
            println!("    before: {aces_before:?}\n    after : {aces_after:?}");
        }
    }
}
