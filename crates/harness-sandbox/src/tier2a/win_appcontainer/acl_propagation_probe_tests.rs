//! **残課題#32の機序を1回で決めるプローブ**（`docs/STATUS.md` 残課題#32、
//! `plans/mac-spike/RESULTS.md` §S10-3）。
//!
//! # 何が分かっていて、何が分かっていないのか
//!
//! **分かっていること**: 製品の既定経路は、workspace rootへ
//! (1)`SetKernelObjectSecurity`（伝播なし）で書いてから (2)`SetNamedSecurityInfoW`（伝播あり）で
//! 書き直す形で、**(2)が既存の子孫へ1件も届いていない**。26万ノードで260,032/260,033が
//! 救済walk送りになることが実測されている（§S10-3、3サイズとも例外なし）。
//!
//! **分かっていないこと**: **なぜ届かないのか**。§S10-3も`d79_exec_split_tests`も
//! 「`SetKernelObjectSecurity`が`SE_DACL_AUTO_INHERITED`を立てないため、と考えると説明が付くが
//! **推定である**」で止めている。
//!
//! # なぜ機序を先に決めるのか
//!
//! 直し方が機序で変わるからである（`bug-fix-workflow`: 原因を確定してから直す）。
//!
//! - **制御ビット説**が正なら、同期区間の書込へ`SE_DACL_AUTO_INHERITED`を立てるだけで直る。
//! - **差分説**（aclapiは新旧DACLの差分ぶんしか子孫へ配らない）が正なら、制御ビットをいくら
//!   立てても直らず、rootの当該ACEを一度外してから伝播する形が要る。
//! - **修飾子説**（`UNPROTECTED_DACL_SECURITY_INFORMATION`が要る）が正なら直りはするが、
//!   **その修飾子はrootのDACLの保護（`SE_DACL_PROTECTED`）を外す**。`--fs-allow`が任意の
//!   ユーザーパスへ同じ経路を通す以上、**そのパスの継承を勝手に復活させる**副作用を持つので、
//!   これを採るなら射程を限る判断が別に要る。
//!
//! **推測のまま直すと、実在しない原因を「修正済み」として記録することになる**（`B-29`）。
//!
//! # 測り方（`dacl_protection_probe_tests`と同じ「候補を並べて1回で測る」形）
//!
//! 腕ごとに**別のツリー・別のSID**を使い、`root`への書込の順序と口だけを変える。
//! 各腕で3つ出す——葉の実効マスク・rootのSD制御ビット・救済walkの`granted`。
//!
//! **対照（腕A）が届かなければ計器が壊れている**ので、そこで止めて他の腕を読まない（`B-35`）。
//!
//! # 前提と安全性
//!
//! - **管理者権限は不要**。`C:\harness-Tier2a-verify-*`配下の自分が作ったツリーだけを触る。
//! - SIDは[`super::capability_sid_from_name`]（純粋導出）のみ。`workspace_capability_sid`は
//!   `%APPDATA%`の台帳へ実体を作るので**使わない**（CLAUDE.md「絶対に消してはいけないファイル」）。
//! - 各腕は終了時に撤収し、[`super::assert_no_sid_ace_recursive`]で**残っていないことを実測**する
//!   （BUG-101: 「撤収したと報告されたのにACEが減っていなかった」）。
//!
//! ```text
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture acl_propagation
//! ```
//!
//! # このファイルは使い捨てである
//!
//! **機序が確定したら削除する**（`docs/CODE-STRUCTURE-RULES.md`規則2: 一回性の調査実験を
//! テストとして残さない）。結論は`plans/handoff-issue-20/T3.md`と、直した側のdocコメントが持つ。
//! **回帰テストはここではなく`acl_dacl_write_tests`と`acl_baseline_cost_tests`が持つ。**

use std::path::Path;

use super::test_support::{build_wide_tree, TestDirGuard};
use super::*;

use windows::Win32::Security::SE_DACL_AUTO_INHERITED;

/// プローブ用ツリーの大きさ。**機序の判定に大きさは要らない**——§S10-3は20,033・100,033・
/// 260,033の3サイズで同じ結果を出しており、ここで測るのは時間ではなく真偽である。
const PROBE_FILES: usize = 200;
const PROBE_FANOUT: usize = 8;

/// rootへの書込の「口」。**同じ情報を渡す口が2つあり、効く方が関数ごとに違う**（`B-26`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootWrite {
    /// `SetKernelObjectSecurity`（=`NtSetSecurityObject`）。製品の同期区間
    /// （`grant_workspace_root_rw_fast`→`set_dacl_single_object`）と同じ底。
    /// `auto_inherited`で、SDの制御ビットへ`SE_DACL_AUTO_INHERITED`を立てるかを切り替える。
    Kernel { auto_inherited: bool },
    /// `SetNamedSecurityInfoW`（aclapi）。製品のフェーズ0
    /// （`propagate_workspace_root_grant`→`set_dacl_propagating`）と同じ底。
    /// `unprotect`で`UNPROTECTED_DACL_SECURITY_INFORMATION`修飾子の有無を切り替える。
    AclApi { unprotect: bool },
}

/// 1回ぶんの書込（口・マスク・継承フラグ）。
#[derive(Debug, Clone, Copy)]
struct Write {
    how: RootWrite,
    mask: u32,
    inheritance: windows::Win32::Security::ACE_FLAGS,
}

/// 1つの腕がrootへ順に行う書込。
#[derive(Debug, Clone, Copy)]
struct Arm {
    label: &'static str,
    /// 1回目（製品の同期区間に相当）。`None`なら「同期区間なし」＝対照。
    first: Option<Write>,
    /// 1回目と2回目の間でrootの当該SIDのACEを剥がすか（差分説の検証）。
    revoke_between: bool,
    /// 2回目（製品のフェーズ0に相当）。
    second: Write,
}

/// 腕の結果。**真偽と数だけ**を持つ（時間は測らない。ここは機序の判定であってコスト測定ではない）。
#[derive(Debug)]
struct ArmResult {
    label: &'static str,
    /// 葉のファイルへ`sid`のアクセスが届いたか（継承経由・明示ACE経由を問わない）。
    leaf_file_mask: Option<u32>,
    /// 葉のディレクトリへ届いたか。
    leaf_dir_mask: Option<u32>,
    /// rootのSD制御ビット（16進で全ビット）。
    root_control: u16,
    /// 救済walkが明示ACEを書いた数。**0が「届いた」である。**
    granted: usize,
    checked: usize,
}

impl ArmResult {
    fn reached(&self) -> bool {
        self.granted == 0
    }
}

fn probe_capability(label: &str) -> crate::win_common::OwnedSid {
    let name = format!("harness-acl-prop-{}-{label}", std::process::id());
    super::capability_sid_from_name(&name).expect("derive capability sid")
}

/// `path`の既存DACLへ`sid`宛の継承ACEを1本マージし、`write`が指す口で書く。
///
/// **マージまでは製品と同じ**（`grant_ace_mask_with_checked`の`GetNamedSecurityInfoW`→
/// `SetEntriesInAclW`）。腕の間で変わるのは**最後の書込の口だけ**である——そこが
/// 1差分になっていないと、観測された差をどの変数へ帰属させてよいか分からなくなる。
fn write_root_ace(path: &Path, sid: PSID, write: Write) -> windows::core::Result<()> {
    let Write {
        how,
        mask,
        inheritance,
    } = write;
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

        let mut trustee = TRUSTEE_W::default();
        BuildTrusteeWithSidW(&mut trustee, sid);
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: mask,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: inheritance,
            Trustee: trustee,
        };
        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        if let Err(e) =
            SetEntriesInAclW(Some(&[ea]), Some(existing as *const _), &mut new_dacl).ok()
        {
            let _ = LocalFree(HLOCAL(sd.0));
            return Err(e);
        }

        let result = match how {
            RootWrite::Kernel { auto_inherited } => {
                write_via_kernel(path, new_dacl, auto_inherited)
            }
            RootWrite::AclApi { unprotect } => {
                let info = if unprotect {
                    DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION
                } else {
                    DACL_SECURITY_INFORMATION
                };
                SetNamedSecurityInfoW(
                    PCWSTR(path_w.as_ptr()),
                    SE_FILE_OBJECT,
                    info,
                    None,
                    None,
                    Some(new_dacl as *const _),
                    None,
                )
                .ok()
            }
        };

        let _ = LocalFree(HLOCAL(new_dacl as *mut _));
        let _ = LocalFree(HLOCAL(sd.0));
        result
    }
}

/// `set_dacl_single_object`（製品）と同じ形。ただし**SDの制御ビットを立てられる**ようにしてある
/// ——BUG-083で「カーネル経路はSDのControlしか見ない」ことが実測済みなので、
/// `SE_DACL_AUTO_INHERITED`もそこから宣言できるはずである、という候補を測るため。
unsafe fn write_via_kernel(
    path: &Path,
    new_dacl: *mut ACL,
    auto_inherited: bool,
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
            if auto_inherited {
                SetSecurityDescriptorControl(
                    sd_ptr,
                    SE_DACL_AUTO_INHERITED,
                    SE_DACL_AUTO_INHERITED,
                )?;
            }
            SetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION, sd_ptr)
        })();
        let _ = CloseHandle(handle);
        result
    }
}

fn run_arm(arm: Arm) -> ArmResult {
    let dir = TestDirGuard::create(&format!("aclprop-{}", arm.label));
    let root = dir.path();
    build_wide_tree(root, PROBE_FILES, PROBE_FANOUT);
    let sid = probe_capability(arm.label);

    if let Some(first) = arm.first {
        write_root_ace(root, sid.as_psid(), first).expect("first root write");
    }
    if arm.revoke_between {
        // rootの当該SIDのACEだけを剥がす（既存の撤収部品を使う。新しく書かない）。
        revoke_ace_unguarded(root, sid.as_psid()).expect("revoke the root ACE between the writes");
    }
    write_root_ace(root, sid.as_psid(), arm.second).expect("second root write");
    let mask = arm.second.mask;

    let leaf_file = root.join("d000").join("f000000.txt");
    let leaf_dir = root.join("d000");
    let leaf_file_mask = sid_effective_ace_mask(&leaf_file, sid.as_psid()).unwrap_or(None);
    let leaf_dir_mask = sid_effective_ace_mask(&leaf_dir, sid.as_psid()).unwrap_or(None);
    // 制御ビットの読み方は`revoke`が既に持っている（同じDACLの読み方を2つ作らない、`B-05`）。
    let root_control = dacl_control(root).unwrap_or(0);

    let report = fix_descendants_missing_ace(root, sid.as_psid(), mask, &[], &|_, _| {})
        .expect("rescue walk");

    // 撤収は測定の一部である（`B-01`）。残ったまま次の腕へ進むと、次の腕のSIDは違うので
    // 結果は汚れないが、**マシンには残る**。
    let _ = revoke_ace_recursive(root, sid.as_psid()).expect("revoke the probe ACEs");
    if let Err(leftovers) = assert_no_sid_ace_recursive(root, sid.as_psid()) {
        panic!(
            "arm {}: {} node(s) still carry the probe SID after revoke; first few: {:?}",
            arm.label,
            leftovers.len(),
            leftovers.iter().take(3).collect::<Vec<_>>()
        );
    }

    ArmResult {
        label: arm.label,
        leaf_file_mask,
        leaf_dir_mask,
        root_control,
        granted: report.granted,
        checked: report.checked,
    }
}

/// **残課題#32の機序を1回で決める。**
///
/// 腕の並べ方は「1回目の書込の口 × 2回目の書込の口 × 間で剥がすか」の1差分ずつで、
/// **どの腕も2回目は伝播ありの書込**である（そこが製品のフェーズ0に当たる）。
#[test]
#[ignore = "creates a few hundred files and writes DACLs; run NON-elevated"]
fn acl_propagation_mechanism_probe() {
    let rwx = workspace_rwx_mask();
    // 差分説の切り分け用。1回目に「狭いマスク」を置いて2回目に広げると、DACLは**必ず変わる**。
    let narrow = FILE_GENERIC_READ.0;
    let both = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
    let kernel = RootWrite::Kernel {
        auto_inherited: false,
    };
    let aclapi = RootWrite::AclApi { unprotect: false };
    let w = |how, mask, inheritance| Write {
        how,
        mask,
        inheritance,
    };

    let arms = [
        Arm {
            label: "A-propagate-only",
            first: None,
            revoke_between: false,
            second: w(aclapi, rwx, both),
        },
        Arm {
            label: "B-product-shape",
            first: Some(w(kernel, rwx, both)),
            revoke_between: false,
            second: w(aclapi, rwx, both),
        },
        Arm {
            label: "C-kernel-auto-inherited",
            first: Some(w(
                RootWrite::Kernel {
                    auto_inherited: true,
                },
                rwx,
                both,
            )),
            revoke_between: false,
            second: w(aclapi, rwx, both),
        },
        Arm {
            label: "D-aclapi-unprotect",
            first: Some(w(kernel, rwx, both)),
            revoke_between: false,
            second: w(RootWrite::AclApi { unprotect: true }, rwx, both),
        },
        Arm {
            label: "E-revoke-between",
            first: Some(w(kernel, rwx, both)),
            revoke_between: true,
            second: w(aclapi, rwx, both),
        },
        Arm {
            label: "F-widen-the-mask",
            first: Some(w(kernel, narrow, both)),
            revoke_between: false,
            second: w(aclapi, rwx, both),
        },
        // **`SetKernelObjectSecurity`が犯人なのかを切り分ける。** 1回目も伝播ありの口で書く。
        // ここが届かないなら、原因は「伝播しない口で先に書いたこと」ではなく
        // 「**そのACEが既に在ったこと**」である——docの書き方が変わる。
        Arm {
            label: "G-aclapi-then-aclapi",
            first: Some(w(aclapi, narrow, both)),
            revoke_between: false,
            second: w(aclapi, rwx, both),
        },
        // **継承フラグが違えば「新しいACE」なのかを切り分ける**（D-63の
        // `grant_ace_object_access`→`grant_ace_inheritable_access`がこの形）。
        // 届くなら、その経路は#32の射程外である。
        Arm {
            label: "H-object-then-inheritable",
            first: Some(w(kernel, rwx, NO_INHERITANCE)),
            revoke_between: false,
            second: w(aclapi, rwx, both),
        },
    ];

    let results: Vec<ArmResult> = arms.into_iter().map(run_arm).collect();

    println!(
        "{}",
        serde_json::json!({
            "measurement": "STATUS #32 mechanism probe",
            "files": PROBE_FILES,
            "fanout": PROBE_FANOUT,
            "arms": results.iter().map(|r| serde_json::json!({
                "arm": r.label,
                "leaf_file_mask": r.leaf_file_mask.map(|m| format!("0x{m:08x}")),
                "leaf_dir_mask": r.leaf_dir_mask.map(|m| format!("0x{m:08x}")),
                "root_control": format!("0x{:04x}", r.root_control),
                "root_dacl_auto_inherited": r.root_control & SE_DACL_AUTO_INHERITED.0 != 0,
                "root_dacl_protected": r.root_control & SE_DACL_PROTECTED.0 != 0,
                "walk_checked": r.checked,
                "walk_granted": r.granted,
                "reached_existing_descendants": r.reached(),
            })).collect::<Vec<_>>(),
        })
    );

    let arm = |label: &str| -> &ArmResult {
        results
            .iter()
            .find(|r| r.label == label)
            .unwrap_or_else(|| panic!("arm {label} missing"))
    };

    // 計器の健全性を先に見る。ここが赤いなら他の腕は読めない（`B-35`の陽性対照）。
    assert!(
        arm("A-propagate-only").reached(),
        "control arm: a single propagating write must reach every existing descendant \
         (granted={}, checked={}). If this fails the instrument is broken — do not read the \
         other arms.",
        arm("A-propagate-only").granted,
        arm("A-propagate-only").checked
    );
    // 陰性対照。現状の再現が取れないなら、以降の「直った」は何の話か分からない。
    assert!(
        !arm("B-product-shape").reached(),
        "the product-shaped sequence was expected to still be broken here (that is STATUS #32); \
         granted={} of {}",
        arm("B-product-shape").granted,
        arm("B-product-shape").checked
    );
}

/// **同じ書込列を、置き場所だけ変えて測る。**
///
/// 上の[`acl_propagation_mechanism_probe`]は`C:\`直下（`TestDirGuard`の置き場）で測っている。
/// ところが**同じ内容のツリーを`C:\Users\...\Documents\AI\`の下に置くと、製品の順序でも
/// 伝播が届く**ことが実測で出た（1,174ノードで 1,173/1,174 対 0/1,174）。
/// つまり**「届かない」は書込列だけでは決まらない**——効いている変数がもう1つある。
///
/// ここはその変数を、`HARNESS_ACL_PROBE_BASES`（`;`区切りの親ディレクトリ）を振って挟み撃ちする。
/// 既定は`C:\`とユーザープロファイル配下の2点。**各腕でrootのSDDLも出す**——DACLの中身が
/// どう違うかを見ないと、位置そのものが効いているのか、位置に伴うDACLの形が効いているのかを
/// 言い分けられない。
#[test]
#[ignore = "creates a few hundred files under two parents and writes DACLs; run NON-elevated"]
fn acl_propagation_mechanism_depends_on_where_the_tree_sits() {
    let bases: Vec<std::path::PathBuf> = std::env::var("HARNESS_ACL_PROBE_BASES")
        .unwrap_or_else(|_| {
            format!(
                "C:\\;{}",
                std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\".to_string())
            )
        })
        .split(';')
        .filter(|s| !s.trim().is_empty())
        .map(std::path::PathBuf::from)
        .collect();

    let rwx = workspace_rwx_mask();
    let both = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
    let kernel = RootWrite::Kernel {
        auto_inherited: false,
    };
    let aclapi = RootWrite::AclApi { unprotect: false };
    let mut rows = Vec::new();

    for base in &bases {
        for (label, first) in [
            (
                "A-propagate-only",
                None::<Write>,
            ),
            (
                "B-product-shape",
                Some(Write {
                    how: kernel,
                    mask: rwx,
                    inheritance: both,
                }),
            ),
        ] {
            let root = base.join(format!(
                "harness-aclprop-{}-{}-{label}",
                std::process::id(),
                rows.len()
            ));
            std::fs::create_dir_all(&root).expect("create the probe tree root");
            let cleanup = super::test_support::scopeguard(|| {
                let _ = std::fs::remove_dir_all(&root);
            });
            build_wide_tree(&root, PROBE_FILES, PROBE_FANOUT);
            let sid = probe_capability(&format!("loc{}", rows.len()));

            if let Some(first) = first {
                write_root_ace(&root, sid.as_psid(), first).expect("first write");
            }
            let control_before = dacl_control(&root).unwrap_or(0);
            write_root_ace(
                &root,
                sid.as_psid(),
                Write {
                    how: aclapi,
                    mask: rwx,
                    inheritance: both,
                },
            )
            .expect("second write");

            let leaf = root.join("d000").join("f000000.txt");
            let report = fix_descendants_missing_ace(&root, sid.as_psid(), rwx, &[], &|_, _| {})
                .expect("rescue walk");
            rows.push(serde_json::json!({
                "base": base.display().to_string(),
                "arm": label,
                "root_control_before_the_propagating_write": format!("0x{control_before:04x}"),
                "leaf_mask": sid_effective_ace_mask(&leaf, sid.as_psid())
                    .unwrap_or(None).map(|m| format!("0x{m:08x}")),
                "walk_checked": report.checked,
                "walk_granted": report.granted,
                "reached": report.granted == 0,
            }));
            let _ = revoke_ace_recursive(&root, sid.as_psid());
            drop(cleanup);
        }
    }

    println!(
        "{}",
        serde_json::json!({
            "measurement": "STATUS #32: does the location change the outcome",
            "rows": rows,
        })
    );
}

/// **実ワークスペースを`preflight`に通して、救済walkが何件書いているかを測る。**
///
/// §S10-3 は「測っていないもの」に **`preflight`経由での再現** を挙げている——あちらが測ったのは
/// 合成ツリーへ基本操作を**直接呼んだ**形で、経路が同じ*形*であることはコードで確認したものの、
/// 製品の入口そのものは一度も通していない。ここがその1点を埋める。
///
/// # なぜ「本物のリポジトリ」でなければならないのか
///
/// 合成ツリー（`build_wide_tree`）は深さ2段・保護DACLなし・全ノードが同じ形で、**実際の
/// ワークスペースが持つ性質**（深いネスト・`.git`・ビルド生成物・混在する所有者）を1つも持たない。
/// 「製品経路でも同じ結果になるか」は、その性質ごと通してみないと言えない。
///
/// # 対象の選び方（**本体リポジトリを指してはいけない**）
///
/// `HARNESS_ACL_REAL_WORKSPACE`が指すパス。既定は**このワークツリー自身**（`CARGO_MANIFEST_DIR`
/// から2つ上）。
///
/// **本体リポジトリ（`...\AI\harness`）を指すと測れない**——`workspace-capability-ledger.json`に
/// `tree_verified_at_unix_secs`が既に入っているため、`preflight`は背景ジョブを**開始しない**。
/// 「速かった」ではなく「走らなかった」を測ることになる（HANDOFFの「やってはいけないこと」6番と
/// 同じ形の罠）。
///
/// # このテストは実マシンに何を残すか（**他のプローブと違う。ここだけ製品経路を通す**）
///
/// `preflight`は台帳（workspace-capability / workspace-grant）へエントリを作り、AppContainerの
/// セッションプロファイルを1件作り、対象ツリーへcapability SID宛のACEを配る。**測定の副作用では
/// なく、それ自体が測定対象**である。後片付けは`harness fs revoke-workspace <path>`と
/// `harness tier2a gc`で、`plans/handoff-issue-20/T3.md`に実測で残すこと。
#[test]
#[ignore = "runs the real preflight against a real workspace; leaves ledger entries — NON-elevated"]
fn acl_propagation_real_workspace_rescue_walk_size() {
    let workspace = std::env::var("HARNESS_ACL_REAL_WORKSPACE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .canonicalize()
                .expect("canonicalize the worktree root")
        });
    assert!(
        workspace.is_dir(),
        "the workspace to measure does not exist: {}",
        workspace.display()
    );

    let started = std::time::Instant::now();
    let outcome = preflight(&workspace, &[], None, &WorkspaceWriteMode::DirectRw)
        .expect("preflight the real workspace");
    let sync_ms = started.elapsed().as_millis();

    let started = std::time::Instant::now();
    let waited = grant_job::wait_until_done();
    let background_ms = started.elapsed().as_millis();
    let progress = grant_job::progress();

    println!(
        "{}",
        serde_json::json!({
            "measurement": "STATUS #32 through the product entry point (preflight)",
            "workspace": workspace.display().to_string(),
            "preflight_sync_ms": sync_ms,
            "background_job_ms": background_ms,
            "background_job_ok": waited.is_ok(),
            "background_job_error": waited.as_ref().err().cloned(),
            "preflight_warnings": outcome.warnings,
            "rescue": progress.as_ref().map(|p| serde_json::json!({
                "checked": p.rescue_checked,
                "granted": p.rescue_granted,
                "probe_errors": p.rescue_probe_errors,
                "protected_nodes": p.protected_nodes,
            })),
        })
    );

    let progress = progress.expect(
        "the background job must have run — if this is None the workspace was already recorded as \
         verified, and this run measured nothing (pick a workspace path that preflight has never \
         seen)",
    );
    assert!(
        progress.finished && progress.error.is_none(),
        "the background job did not finish cleanly: {progress:?}"
    );
    assert!(
        progress.rescue_checked > 0,
        "the rescue walk saw no nodes at all — `granted == 0` would be meaningless here (B-35)"
    );
}
