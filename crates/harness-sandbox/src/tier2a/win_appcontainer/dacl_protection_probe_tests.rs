//! [BUG-083](../../../../docs/bugs/BUG-083.md) の実測プローブ。
//! **どのWin32書込経路なら`SE_DACL_PROTECTED`が実際に立つのか**を、候補を並べて1回で測る。
//!
//! `.harness/`制御面保護（D-05/D-09の層3、[`super::protect_harness_control_dir_from_appcontainer`]）は
//! ACEを剥がしたうえで`SE_DACL_PROTECTED`を立てる設計だが、**実機では立っていない**
//! （このリポジトリの`.harness`で`Get-Acl .AreAccessRulesProtected`が`False`、
//! 全ACEが`ID`付きのまま）。BUG-083は原因を3候補まで絞ったが区別できていない:
//!
//! - **候補A**: カーネル経路は保護状態を**SDのcontrolビット**から取り、`SECURITY_INFORMATION`の
//!   `PROTECTED_DACL_SECURITY_INFORMATION`修飾子はaclapi層でしか解釈されない。
//! - **候補B**: カーネル経路（`SetKernelObjectSecurity`＝`NtSetSecurityObject`）は保護状態を
//!   一切扱わず、aclapi（`SetNamedSecurityInfoW`）でしか設定できない。
//! - **候補C**: `INHERITED_ACE`付きACEを含むDACLを保護状態で書こうとしたため無視された
//!   （保護DACLに継承由来ACEが残るのは自己不整合であるため）。
//!
//! ## このプローブの2つの観測軸
//!
//! **フラグと挙動を混同しない**——BUG-083の教訓そのもの（「機能テストが緑」は「設計意図どおりに
//! 動いている」を意味しない）。そこで各ケースで次の両方を測る。
//!
//! 1. `GetSecurityDescriptorControl`が返すcontrolビット（16進で全ビット出す。
//!    `SE_DACL_PROTECTED`(0x1000)だけでなく`SE_DACL_AUTO_INHERITED`(0x400)の動きも見たい）。
//! 2. **機能面の実効**: 保護を適用した後で[`super::propagate_workspace_root_grant`]
//!    （＝`grant_job`の背景フェーズ0が本番でまさに呼ぶ関数）を親で走らせ、保護したノードの
//!    **下**のファイルへACEが届いてしまうかどうか。届かないケースがあれば、そのケースでは
//!    フェーズ0.5（`.harness/`の再保護）が不要になる。
//!
//! ## なぜ結果を残すのか（テストが後始末しない理由）
//!
//! BUG-083は「Rustの読取ロジックの実装ミスではない」ことをPowerShellの`Get-Acl`で独立に
//! 確認して初めて切り出したバグである。同じ二重確認をできるようにするため、実験用ツリーは
//! `%TEMP%\harness-bug083-probe\`という**既知の固定パス**に置き、テスト終了後も消さない。
//! 走らせるたびに先頭で作り直すので、残骸が結果を汚すことはない。後始末は
//! `Remove-Item -Recurse -Force "$env:TEMP\harness-bug083-probe"`。
//!
//! ```powershell
//! Get-ChildItem "$env:TEMP\harness-bug083-probe" -Directory | ForEach-Object {
//!   $s = Join-Path $_.FullName 'sub'
//!   '{0}: protected={1}' -f $_.Name, (Get-Acl -LiteralPath $s).AreAccessRulesProtected
//! }
//! ```
//!
//! ## 前提と安全性
//!
//! - **管理者権限は不要**。`%TEMP%`配下の自分が作ったツリーなので`WRITE_DAC`が通る。
//! - `test_support::TestDirGuard`が`%TEMP%`を避けて`C:\`直下を使うのは`grant_traverse_chain`が
//!   `Path::ancestors()`で**祖先**のDACLまで触るため（BUG-011）。**このプローブは祖先を
//!   一切触らない**——[`super::propagate_workspace_root_grant`]は対象ノードとその子孫にしか
//!   及ばないので、`%TEMP%`配下で問題ない。
//! - SIDは[`super::capability_sid_from_name`]の純粋導出のみを使う。`workspace_capability_sid`は
//!   `%APPDATA%`の台帳へ実体を作る副作用があるので**使わない**（CLAUDE.md「絶対に消しては
//!   いけないファイル」）。

use super::*;

use windows::Win32::Security::SetSecurityDescriptorControl;

/// 試す書込経路。
///
/// **修正後の対照関係**: `Production`は修正が入ったので`SdControlBit`と等価になった。
/// この一致は`dacl_protection_write_path_matrix_probe`末尾でアサートしており、ローカル実装が
/// 本番からずれた（＝以降のケースの差分を1点の意図した違いに帰属できなくなった）ことの検出器を
/// 兼ねる。`LocalBaseline`（制御ビットを立てない）は**修正前の挙動の再現**として残してある
/// ——回帰したときにこの表を1回走らせれば、本番がどちら側へ落ちたかが一目で分かる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WritePath {
    /// 本番そのまま（[`super::remove_sid_aces_and_protect`]）。修正後は保護が立つ。
    Production,
    /// 制御ビットを立てないローカル実装＝**BUG-083の再現**（修正前の本番と同じ内容）。
    LocalBaseline,
    /// 書込前にSDのcontrolビットへ`SE_DACL_PROTECTED`を直接立てる（候補A）。
    SdControlBit,
    /// コピーしたACEから`INHERITED_ACE`を落としてから書く（候補C）。
    StripInherited,
    /// 候補Aと候補Cの合わせ技（片方だけでは足りない可能性のため）。
    SdControlBitAndStripInherited,
    /// aclapi（`SetNamedSecurityInfoW`）で書く（候補B）。
    AclApi,
}

impl WritePath {
    /// ディレクトリ名とログの見出しに使う。
    fn label(self) -> &'static str {
        match self {
            Self::Production => "1-production",
            Self::LocalBaseline => "2-local-baseline",
            Self::SdControlBit => "3-sd-control-bit",
            Self::StripInherited => "4-strip-inherited",
            Self::SdControlBitAndStripInherited => "5-control-bit-and-strip",
            Self::AclApi => "6-aclapi-setnamedsecurityinfo",
        }
    }

    fn kernel_opts(self) -> Option<KernelWriteOpts> {
        match self {
            Self::Production | Self::AclApi => None,
            Self::LocalBaseline => Some(KernelWriteOpts {
                set_control_bit: false,
                strip_inherited: false,
            }),
            Self::SdControlBit => Some(KernelWriteOpts {
                set_control_bit: true,
                strip_inherited: false,
            }),
            Self::StripInherited => Some(KernelWriteOpts {
                set_control_bit: false,
                strip_inherited: true,
            }),
            Self::SdControlBitAndStripInherited => Some(KernelWriteOpts {
                set_control_bit: true,
                strip_inherited: true,
            }),
        }
    }
}

const CASES: &[WritePath] = &[
    WritePath::Production,
    WritePath::LocalBaseline,
    WritePath::SdControlBit,
    WritePath::StripInherited,
    WritePath::SdControlBitAndStripInherited,
    WritePath::AclApi,
];

#[derive(Debug, Clone, Copy)]
struct KernelWriteOpts {
    /// `SetSecurityDescriptorControl(sd, SE_DACL_PROTECTED, SE_DACL_PROTECTED)`を挟むか。
    set_control_bit: bool,
    /// 書き戻すDACLのACEから`INHERITED_ACE`を落とすか。
    strip_inherited: bool,
}

/// 1ケースの観測結果。
struct CaseResult {
    label: &'static str,
    /// 書込前のcontrol（全ケースで`SE_DACL_PROTECTED`が落ちていることが前提）。
    control_before: u16,
    /// 書込後のcontrol。
    control_after: u16,
    /// **別の複製ノード**へ同じ書込を行い、直後に解除方向（`protected=false`）で
    /// 書き戻した後のcontrol。
    ///
    /// 複製で測るのは2つの理由による。(1) 保護後の`sub`をそのまま解除してしまうと、
    /// テストが残す実験ツリーが「解除後の状態」になり、モジュールdocの目的である
    /// PowerShell独立クロスチェック（保護が立っていることの確認）ができなくなる。
    /// (2) `sub`は間に伝播ステップ（aclapi）を挟んでおり、解除方向だけを見たいときの
    /// 交絡になる。
    control_after_unprotect: u16,
    /// 保護したノードの**下**のファイルへ、親からの伝播でACEが届いたか。
    /// `false`なら継承が実際に遮断されている。
    propagation_reached_child: bool,
    /// 保護直後の、保護したノード自身のACE一覧。
    aces_after_write: Vec<String>,
    /// 親でaclapiの伝播を走らせた**後**の、同じノードのACE一覧。
    ///
    /// [耐久確認] `INHERITED_ACE`付きACEを残したまま保護すると
    /// 「保護DACLなのにACEが継承由来を名乗る」自己不整合な状態になる。この状態が後続の
    /// aclapi操作に耐えず、ACEが継承元の消えた残骸として掃除されてしまうなら、
    /// Administrators/SYSTEM/所有者のアクセスごと失う事故になり得る。
    ///
    /// **問うのは「増えたか」ではなく「失われたか」**（[`CaseResult::lost_aces`]）——保護
    /// できていないケースでは伝播でACEが1本増えるのが正しい挙動であり、それを
    /// 「耐えなかった」と数えると観測が意味を持たない。
    aces_after_propagate: Vec<String>,
    write_elapsed: std::time::Duration,
    /// 書込・伝播・解除のいずれかが失敗したときの理由（観測は続行する）。
    errors: Vec<String>,
}

impl CaseResult {
    fn protected_after(&self) -> bool {
        self.control_after & SE_DACL_PROTECTED.0 != 0
    }

    /// 保護直後にあったのに、aclapiの伝播後には消えていたACE。**空であるべき**。
    fn lost_aces(&self) -> Vec<&str> {
        self.aces_after_write
            .iter()
            .filter(|ace| !self.aces_after_propagate.contains(ace))
            .map(String::as_str)
            .collect()
    }
}

/// 実験用ツリーの置き場。モジュールdocの「結果を残す」理由によりテストは消さない。
fn probe_root() -> std::path::PathBuf {
    std::env::temp_dir().join("harness-bug083-probe")
}

// `path`のDACLのACEを1件ずつ「種別;フラグ;マスク;SID」の文字列にして返す部品。
// 耐久確認（`CaseResult::aces_after_propagate`）のために、件数だけでなくtrusteeとマスクまで
// 比較できる形にしてある——件数が同じでも中身が入れ替わっていれば、
// 「Administratorsを失っていない」とは言えないため。
//
// **実体は`test_support`へ移した**——`acl_dacl_size_limit_tests`（DACLの上限に当たったとき
// 無言で切り捨てられるか）が2箇所目の利用者になったため（`docs/CODE-STRUCTURE-RULES.md`規則5）。
use super::test_support::describe_dacl_aces;

// 継承由来フラグを落とす部品（候補C）は`test_support`が持つ。**BUG-145のプローブが
// 2箇所目の利用者になったので移した**（規則5）——同じ変換を2つ持つと、片方だけ直ったときに
// 2つのプローブの結果が比べられなくなる。
use super::test_support::strip_inherited_ace_flags as strip_inherited_flags;

/// `super::set_dacl_single_object_with_protection`（＝本番のカーネル経路）の実験用の写し。
/// **本番と違うのは`opts`の2点だけ**で、`opts`が両方`false`なら本番と等価になる
/// （その等価性は`WritePath::LocalBaseline`が`Production`と一致することで示す）。
unsafe fn protect_via_kernel_object(
    path: &Path,
    opts: KernelWriteOpts,
) -> windows::core::Result<()> {
    unsafe {
        let path_w = long_path_wide(path);
        let mut existing_dacl: *mut ACL = std::ptr::null_mut();
        let mut sd_read = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing_dacl),
            None,
            &mut sd_read,
        )
        .ok()?;

        // `sids`を空にすると「1本も除かないコピー」になる——本番の
        // `remove_sid_aces_and_protect`が「対象SIDのACEを持たないノード」に対して行うのと
        // 同じ内容（BUG-083の`.harness/`はまさにこの状態にある）。
        let mut buf: Vec<u8> = Vec::new();
        let copied = copy_dacl_excluding_sids(existing_dacl as *const _, &[], &mut buf);
        let _ = LocalFree(HLOCAL(sd_read.0));
        let (new_dacl, _removed) = copied?;

        if opts.strip_inherited {
            strip_inherited_flags(new_dacl)?;
        }

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
            if opts.set_control_bit {
                // 候補A: `SECURITY_INFORMATION`の修飾子ではなく、SD自身のcontrolビットで
                // 保護を宣言する。`SetSecurityDescriptorControl`は仕様上、継承の自動伝播に
                // 関わる制御ビット（`SE_DACL_PROTECTED`を含む）だけを設定できる。
                SetSecurityDescriptorControl(sd_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED)?;
            }
            SetKernelObjectSecurity(
                handle,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                sd_ptr,
            )
        })();

        let _ = CloseHandle(handle);
        result
    }
}

/// `path`のDACLをそのまま読み書きし直して、保護状態だけを`protected`にする。
/// 解除方向（`false`）の実効性を測るために使う——本番の`revoke_sids_from_node`が
/// `was_protected`を復元する経路と同じ形。
fn rewrite_with_protection(path: &Path, protected: bool) -> windows::core::Result<()> {
    unsafe {
        let path_w = long_path_wide(path);
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
        .ok()?;

        let mut buf: Vec<u8> = Vec::new();
        let copied = copy_dacl_excluding_sids(existing_dacl as *const _, &[], &mut buf);
        let _ = LocalFree(HLOCAL(sd.0));
        let (new_dacl, _removed) = copied?;

        set_dacl_single_object_with_protection(
            path,
            new_dacl,
            if protected {
                super::DaclProtection::Protected
            } else {
                super::DaclProtection::Unprotected
            },
        )
    }
}

/// 1ケースを走らせる。**失敗しても`panic!`せず`errors`へ積んで観測を続ける**
/// ——1ケースが落ちて残り5ケースの数字が取れないと、この実験自体の目的
/// （候補A/B/Cの判別）が果たせないため。
fn run_case(index: usize, write: WritePath) -> CaseResult {
    let mut errors = Vec::new();
    let case_root = probe_root().join(write.label());
    let sub = case_root.join("sub");
    let child = sub.join("f.txt");
    std::fs::create_dir_all(&sub).expect("create the case tree");
    std::fs::write(&child, b"bug-083 probe\n").expect("seed the child file");
    // 解除方向は複製ノードで測る（`CaseResult::control_after_unprotect`のdoc参照）。
    let unprotect_probe = case_root.join("unprotect-probe");
    std::fs::create_dir_all(&unprotect_probe).expect("create the unprotect probe dir");

    // 台帳を経由しない純粋な導出SID（ケースごとに別のSIDにして、ケース間の干渉を断つ）。
    let sid = capability_sid_from_name(&format!("harnessBug083Probe{index}"))
        .expect("derive a probe capability SID");

    let control_before = dacl_control(&sub).expect("read the control bits before the write");

    let apply = |target: &Path| -> Result<(), String> {
        match (write, write.kernel_opts()) {
            // [BUG-084] `Ok(false)`は「触る前に消えていた」。このプローブは自分で作った
            // ツリーを測るので起こり得ないが、起きたなら測定が成立しないので失敗として扱う。
            (WritePath::Production, _) => {
                match remove_sid_aces_and_protect(target, sid.as_psid()) {
                    Ok(o) if o.is_protected() => Ok(()),
                    Ok(_) => Err("the probe target vanished before it was protected".to_string()),
                    Err(e) => Err(e.to_string()),
                }
            }
            (WritePath::AclApi, _) => super::test_support::protect_dacl_preserve_inherited(target)
                .map_err(|e| e.to_string()),
            (_, Some(opts)) => {
                unsafe { protect_via_kernel_object(target, opts) }.map_err(|e| e.to_string())
            }
            (_, None) => unreachable!("every non-production, non-aclapi case has kernel options"),
        }
    };

    let started = std::time::Instant::now();
    let write_result = apply(&sub);
    let write_elapsed = started.elapsed();
    if let Err(e) = write_result {
        errors.push(format!("write: {e}"));
    }

    let control_after = dacl_control(&sub).expect("read the control bits after the write");
    let aces_after_write = describe_dacl_aces(&sub).expect("list the ACEs after the write");

    // 解除方向（`SE_DACL_PROTECTED`を落とす向き）が効くか。同じ書込を複製ノードへ行い、
    // **伝播を挟まずに**すぐ解除して測る。
    if let Err(e) = apply(&unprotect_probe) {
        errors.push(format!("write (unprotect probe): {e}"));
    }
    if let Err(e) = rewrite_with_protection(&unprotect_probe, false) {
        errors.push(format!("unprotect: {e}"));
    }
    let control_after_unprotect =
        dacl_control(&unprotect_probe).expect("read the control bits after the unprotect");

    // 機能面の実効: 本番の背景フェーズ0がまさに呼ぶ関数で、親から継承ACEを伝播させる。
    // 保護が実際に効いていれば、`sub`の下の`f.txt`へは届かないはず。
    if let Err(e) = propagate_workspace_root_grant(&case_root, sid.as_psid(), workspace_rwx_mask())
    {
        errors.push(format!("propagate: {e}"));
    }
    let propagation_reached_child = match sid_effective_ace_mask(&child, sid.as_psid()) {
        Ok(mask) => mask.is_some(),
        Err(e) => {
            errors.push(format!("probe child: {e}"));
            false
        }
    };
    // [耐久確認] 保護したノード自身のACEが、aclapiの伝播を挟んでも失われていないか。
    let aces_after_propagate =
        describe_dacl_aces(&sub).expect("list the ACEs after the parent propagated");

    CaseResult {
        label: write.label(),
        control_before,
        control_after,
        control_after_unprotect,
        propagation_reached_child,
        aces_after_write,
        aces_after_propagate,
        write_elapsed,
        errors,
    }
}

/// controlビットのうち、この実験で意味を持つものを人が読める形にする。
fn describe_control(control: u16) -> String {
    let mut flags = Vec::new();
    for (bit, name) in [
        (0x0004u16, "DACL_PRESENT"),
        (0x0100, "DACL_AUTO_INHERIT_REQ"),
        (0x0400, "DACL_AUTO_INHERITED"),
        (0x1000, "DACL_PROTECTED"),
        (0x8000, "SELF_RELATIVE"),
    ] {
        if control & bit != 0 {
            flags.push(name);
        }
    }
    format!("0x{control:04x} [{}]", flags.join("|"))
}

/// [BUG-083] `SE_DACL_PROTECTED`がどの書込経路で立つかを1回で測る。
///
/// **合否を判定しない観測用テスト**である（`ace_grant_revoke_tests`の`run_probe`と同じ思想）。
/// 「どのケースも立たなかった」も立派な観測結果で、その場合は候補A/B/Cが全て外れであることが
/// 分かる——`panic!`させてしまうとその区別が出力に残らない。したがってアサートするのは
/// **実験の前提が崩れていないか**だけに限る。
#[test]
#[ignore = "実FSのDACLを書き換える観測用プローブ（%TEMP%配下のみ、管理者権限不要）。結果はdocs/bugs/BUG-083.mdへ転記する"]
fn dacl_protection_write_path_matrix_probe() {
    let root = probe_root();
    // 前回の残骸が結果を汚さないよう、毎回作り直す（残すのは実行「後」だけ）。
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create the probe root");

    let results: Vec<CaseResult> = CASES
        .iter()
        .enumerate()
        .map(|(index, &write)| run_case(index, write))
        .collect();

    println!("\n=== BUG-083: SE_DACL_PROTECTED write-path matrix ===");
    println!("probe root: {}", root.display());
    for r in &results {
        println!("\n--- {} ---", r.label);
        println!(
            "  control before      : {}",
            describe_control(r.control_before)
        );
        println!(
            "  control after write : {}",
            describe_control(r.control_after)
        );
        println!(
            "  SE_DACL_PROTECTED   : {}",
            if r.protected_after() {
                "SET"
            } else {
                "not set"
            }
        );
        println!(
            "  inheritance blocked : {} (child {} an ACE after the parent propagated)",
            !r.propagation_reached_child,
            if r.propagation_reached_child {
                "GOT"
            } else {
                "did not get"
            }
        );
        println!(
            "  control after unprot: {}",
            describe_control(r.control_after_unprotect)
        );
        let lost = r.lost_aces();
        println!(
            "  own ACEs lost to aclapi: {} ({} ACE(s) after write, {} after the parent propagated)",
            lost.len(),
            r.aces_after_write.len(),
            r.aces_after_propagate.len()
        );
        if !lost.is_empty() {
            println!("    lost: {lost:?}");
        }
        println!("  write elapsed       : {:?}", r.write_elapsed);
        if !r.errors.is_empty() {
            println!("  errors              : {:?}", r.errors);
        }
    }

    let winners: Vec<&str> = results
        .iter()
        .filter(|r| r.protected_after())
        .map(|r| r.label)
        .collect();
    let blockers: Vec<&str> = results
        .iter()
        .filter(|r| !r.propagation_reached_child)
        .map(|r| r.label)
        .collect();
    let fragile: Vec<&str> = results
        .iter()
        .filter(|r| !r.lost_aces().is_empty())
        .map(|r| r.label)
        .collect();
    println!("\n=== verdict ===");
    println!("  paths that actually set SE_DACL_PROTECTED : {winners:?}");
    println!("  paths that actually blocked inheritance   : {blockers:?}");
    println!("  paths that LOST one of their own ACEs     : {fragile:?}");
    println!(
        "  cross-check with PowerShell (the tree is intentionally left behind):\n\
         \x20   Get-ChildItem \"$env:TEMP\\harness-bug083-probe\" -Directory | ForEach-Object {{ \
         '{{0}}: protected={{1}}' -f $_.Name, (Get-Acl -LiteralPath (Join-Path $_.FullName 'sub')).AreAccessRulesProtected }}"
    );

    // --- ここから下は「実験の前提」だけを固定する。結果そのものは判定しない ---

    for r in &results {
        assert_eq!(
            r.control_before & SE_DACL_PROTECTED.0,
            0,
            "precondition failed for {}: a freshly created directory must not already be \
             protected, otherwise this case measures nothing",
            r.label
        );
    }

    let production = results
        .iter()
        .find(|r| r.label == WritePath::Production.label())
        .expect("the production case must be in the matrix");
    let equivalent = results
        .iter()
        .find(|r| r.label == WritePath::SdControlBit.label())
        .expect("the sd-control-bit case must be in the matrix");
    assert_eq!(
        production.control_after, equivalent.control_after,
        "after the BUG-083 fix the production write path must behave exactly like the \
         sd-control-bit case (that is what the fix does); if these differ, the deltas measured \
         by the other cases cannot be attributed to their one intended difference"
    );
    assert_eq!(
        production.propagation_reached_child, equivalent.propagation_reached_child,
        "the production write path must block inheritance exactly like the sd-control-bit case"
    );

    // 回帰検出: 修正が外れると本番は`LocalBaseline`（制御ビット無し＝修正前）側へ落ちる。
    let pre_fix = results
        .iter()
        .find(|r| r.label == WritePath::LocalBaseline.label())
        .expect("the pre-fix reproduction case must be in the matrix");
    assert!(
        production.protected_after() && !pre_fix.protected_after(),
        "the production path must set SE_DACL_PROTECTED and the pre-fix reproduction must not; \
         if production stopped setting it, the BUG-083 fix (SetSecurityDescriptorControl in \
         set_dacl_single_object_with_protection) has regressed"
    );
}
