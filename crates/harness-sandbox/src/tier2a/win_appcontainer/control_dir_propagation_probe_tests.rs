//! [BUG-145](../../../../docs/bugs/BUG-145.md) の実測プローブ。
//! **保護したノード「自身」が、親の伝播で保護を失うのか**を測る。
//!
//! # 既存の2本が測っていない場所
//!
//! 同じ対象を測るプローブは既に2本ある。**どちらも保護したノード自身は見ていない。**
//!
//! - [`super::dacl_protection_probe_tests`]（BUG-083）は「どの書込口なら保護が立つか」と、
//!   **保護したノードの「下」のファイル**へ伝播が届くかを測る（`child = sub/f.txt`）。
//!   保護ノード自身のACE一覧は伝播後も記録しているが、**判定に使っているのは「失われた」ACEだけ**で、
//!   「増えた」ACEも保護ビットの行方も見ていない。
//! - [`super::super::acl_propagation_probe_tests`]（残課題#32）は伝播が既存の子孫へ届くかを測る。
//!   保護そのものを扱っていない。
//!
//! BUG-145で観測されたのは**保護ノード自身**が保護を失い、継承由来の許可ACEを載せる現象なので、
//! どちらの計器にも写らない。
//!
//! # 2つの軸で振る
//!
//! **軸1（手順）**は5ケース。**軸2（置き場）は2水準で、これを外すと再現しない可能性がある**
//! ——[`super::super::acl_dacl_write`]のモジュールdocは「同じ書込列でもツリーの置き場所で
//! 伝播の挙動が反転した」実測を持っており、BUG-145の実測は`C:\`直下
//! （`C:\harness-Tier2a-verify-*`）だった。**`%TEMP%`だけで測ると取り逃す。**
//!
//! # 判定に使わない値を1つ必ず読む（**対照**）
//!
//! `open/f.txt`（保護していない兄弟の配下）へ伝播が届いたかを毎回読む。**ここが届いて
//! いなければ、そのケースは「伝播が不発だった」のであって「保護が効いた」ではない。**
//! これが無いと、何も起きなかった状態を合格と読む。
//!
//! # 前提と安全性
//!
//! - **管理者権限は不要**。祖先のDACLには一切触れない（伝播はケースrootとその配下にしか及ばない）。
//! - **台帳を触らない**。主体は[`super::super::capability_sid_from_name`]の純粋導出のみを使う
//!   （`workspace_capability_sid`は`%APPDATA%`へ実体を作るので使わない）。
//! - **合否を判定しない観測用テスト**である（BUG-083のプローブと同じ思想）。アサートするのは
//!   実験の前提が崩れていないかだけで、`panic!`させるとどのケースがどう出たかが出力に残らない。
//! - 実験ツリーは**消さない**（PowerShellの`Get-Acl`で独立に確かめられるようにするため）。
//!   毎回先頭で作り直す。後始末:
//!
//! ```powershell
//! Remove-Item -Recurse -Force C:\harness-bug145-probe, "$env:TEMP\harness-bug145-probe"
//! ```

use super::*;

use windows::Win32::Security::Authorization::DENY_ACCESS;

// DACLのACEを1件ずつ「種別;フラグ;マスク;SID」の文字列にする部品。BUG-083のプローブと
// **同じものを使う**——同じDACLを2つの実装で読むと、どちらが正しいかを別途決めることになる。
use super::test_support::describe_dacl_aces;

/// 実験用ツリーの置き場。**2水準あるのがこのプローブの要点の1つ**（モジュールdoc参照）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    /// BUG-145の実測と同じ置き場。
    DriveRoot,
    /// ユーザープロファイル配下。既存のBUG-083プローブはここだけで測っている。
    UserTemp,
}

impl Placement {
    fn label(self) -> &'static str {
        match self {
            Self::DriveRoot => "C-drive-root",
            Self::UserTemp => "user-temp",
        }
    }

    fn root(self) -> PathBuf {
        match self {
            Self::DriveRoot => PathBuf::from("C:\\harness-bug145-probe"),
            Self::UserTemp => std::env::temp_dir().join("harness-bug145-probe"),
        }
    }
}

const PLACEMENTS: &[Placement] = &[Placement::DriveRoot, Placement::UserTemp];

/// 伝播書込をどこへ撃つか。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PropagateTo {
    /// 撃たない（対照）。
    Nowhere,
    /// ケースroot（＝製品と同じ。保護ノードの親）。
    CaseRoot,
    /// 保護していない兄弟だけ（案①の前提）。
    SiblingOnly,
}

/// 試す手順。**ケース2を基準に、1つずつ差分を作ってある。**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Case {
    /// 高速付与 → 保護 → **伝播しない**。対照。伝播以外の理由で保護が落ちていないこと。
    NoPropagate,
    /// 高速付与 → 保護 → ケースrootへ伝播。**製品と同じ形。**
    Production,
    /// 保護 → ケースrootへ伝播（**高速付与を抜く**）。直前のカーネル口の書込が引き金か。
    NoPriorRootWrite,
    /// 高速付与 → 保護 → **兄弟だけ**へ伝播。**案①の前提**（配布経路から外せば無傷か）。
    SiblingOnly,
    /// 高速付与 → 保護＋明示の拒否ACE → ケースrootへ伝播。**案②の前提**（明示ACEは生き延びるか）。
    ExplicitDeny,
    /// 高速付与 → 保護 → **同じDACLを保護つきでもう一度書く**（拒否ACEは足さない）→ ケースrootへ伝播。
    ///
    /// **ケース5の交絡を外すためだけに在る。** ケース5はケース2に対して2つ違う——
    /// 「拒否ACEが載っている」ことと「保護の書込がもう1回走った」こと。**どちらが効いたのかは、
    /// 拒否ACEを外した書込をもう1本並べないと分からない**（`B-29`: 1差分×1ケース）。
    ReprotectNoDeny,
    /// 高速付与 → **剥がす＋拒否ACE＋保護を1回の書込で** → ケースrootへ伝播。
    ///
    /// **案②を本当に測れるのはここだけである。** ケース5は書込が2回になった副作用で保護が
    /// 守られてしまい、**拒否ACEが「保護が落ちた状態でも残るか」を一度も試していない**。
    /// 書込を1回に戻せば保護は落ちるはずなので、そこで拒否ACEが生き延びるかを見る。
    DenyInOneWrite,
    /// **ケース2をそのまま繰り返すだけ。** 実行順そのものが結果を作っていないことを見る対照で、
    /// ケース2と同じ手順を行列の最後に置く。**ここが2と食い違ったら、読んでいるのは手順ではなく
    /// 実行順である**（`B-28`: 1回のテストは反復を保証しない）。
    ProductionRepeat,
}

const CASES: &[Case] = &[
    Case::NoPropagate,
    Case::Production,
    Case::NoPriorRootWrite,
    Case::SiblingOnly,
    Case::ExplicitDeny,
    Case::ReprotectNoDeny,
    Case::DenyInOneWrite,
    Case::ProductionRepeat,
];

impl Case {
    fn label(self) -> &'static str {
        match self {
            Self::NoPropagate => "1-no-propagate",
            Self::Production => "2-production",
            Self::NoPriorRootWrite => "3-no-prior-root-write",
            Self::SiblingOnly => "4-sibling-only",
            Self::ExplicitDeny => "5-explicit-deny",
            Self::ReprotectNoDeny => "6-reprotect-no-deny",
            Self::DenyInOneWrite => "7-deny-in-one-write",
            Self::ProductionRepeat => "8-production-repeat",
        }
    }

    /// 保護の前にケースrootへ高速付与（伝播しない口）を通すか。
    fn fast_grants_root(self) -> bool {
        !matches!(self, Self::NoPriorRootWrite)
    }

    fn propagate_to(self) -> PropagateTo {
        match self {
            Self::NoPropagate => PropagateTo::Nowhere,
            Self::SiblingOnly => PropagateTo::SiblingOnly,
            Self::Production
            | Self::NoPriorRootWrite
            | Self::ExplicitDeny
            | Self::ReprotectNoDeny
            | Self::DenyInOneWrite
            | Self::ProductionRepeat => PropagateTo::CaseRoot,
        }
    }

    /// 製品の保護（[`remove_sid_aces_and_protect`]）を通すか。ケース7だけは
    /// 剥がす・拒否・保護を1回の書込でまとめるので、こちらを通さない。
    fn uses_production_protect(self) -> bool {
        !matches!(self, Self::DenyInOneWrite)
    }

    fn writes_deny(self) -> bool {
        matches!(self, Self::ExplicitDeny)
    }

    /// 保護のあとに、同じDACLを保護つきでもう一度書くか（ケース5の交絡を外す対照）。
    fn rewrites_protection(self) -> bool {
        matches!(self, Self::ReprotectNoDeny)
    }
}

/// 1ケースの観測結果。**保護直後と伝播直後を対で持つ**——片方だけでは
/// 「落ちた」と「そもそも立っていなかった」が区別できない。
struct CaseResult {
    placement: &'static str,
    case: &'static str,
    /// **親（ケースroot）**の制御ビット。ツリーを作った直後。
    root_control_initial: u16,
    /// 高速付与のあと（＝伝播書込の直前）。**高速付与が親の制御ビットに何をするか**が見える。
    root_control_before_propagate: u16,
    /// 伝播書込のあと。
    root_control_after_propagate: u16,
    /// 保護直後のDACL制御ビット。**ここで`SE_DACL_PROTECTED`が立っていなければ測定は不成立。**
    control_after_protect: u16,
    /// 伝播直後の同じ値。伝播しないケースでは同じ時点をもう一度読む。
    control_after_propagate: u16,
    /// 保護ノード自身へこの主体の**許可**が届いているか（`sid_effective_ace_mask`は
    /// allow ACEだけを数えるので、拒否ACEはここに現れない）。
    guarded_allow_after_protect: Option<u32>,
    guarded_allow_after_propagate: Option<u32>,
    /// 保護ノードの**子**。BUG-145の実測では一度も露出しなかった。
    inner_allow_after: Option<u32>,
    /// **対照**。保護していない兄弟の配下。ここが`None`なら伝播が走っていない。
    open_allow_after: Option<u32>,
    /// この主体宛の**拒否**ACEの本数（ケース5の生存確認）。
    deny_aces_after_protect: usize,
    deny_aces_after_propagate: usize,
    /// 保護直後には無く、伝播後に増えたACE。**BUG-145の現象そのもの。**
    added_aces: Vec<String>,
    /// 保護直後にはあったのに、伝播後に消えたACE。
    lost_aces: Vec<String>,
    errors: Vec<String>,
}

impl CaseResult {
    fn protected_after_protect(&self) -> bool {
        self.control_after_protect & SE_DACL_PROTECTED.0 != 0
    }

    fn protected_after_propagate(&self) -> bool {
        self.control_after_propagate & SE_DACL_PROTECTED.0 != 0
    }

    /// 保護ノード自身が、伝播によって**新たに許可を得たか**。これが真ならBUG-145の再現である。
    fn guarded_became_reachable(&self) -> bool {
        self.guarded_allow_after_protect.is_none() && self.guarded_allow_after_propagate.is_some()
    }
}

/// `path`のDACLに載っている`sid_text`宛の拒否ACE（`type=0x01`）の本数。
///
/// [`super::test_support::describe_dacl_aces`]が出す `type=0x..;flags=0x..;mask=0x..;S-1-...`
/// の綴りをそのまま数える。**新しい読み取り器を作らない**——同じDACLを2つの実装で読むと、
/// どちらが正しいかを別途決めなければならなくなる（`B-05`）。
fn count_deny_aces(aces: &[String], sid_text: &str) -> usize {
    aces.iter()
        .filter(|ace| ace.starts_with("type=0x01;") && ace.ends_with(sid_text))
        .count()
}

/// `path`から`sid`宛のACEを剥がし、拒否ACEを足し、保護を立てる——**すべて1回の書込で**
/// （ケース7専用）。
///
/// 製品の[`remove_sid_aces_and_protect`]と**書込の回数と口を揃えてある**のが要点で、
/// ケース5との差はそこだけである。剥がす部分は製品と同じ[`copy_dacl_excluding_sids`]を通す。
///
/// # 安全性
///
/// `sid`は有効なSIDを指していること。
unsafe fn protect_with_deny_in_one_write(
    path: &Path,
    sid: PSID,
    mask: u32,
) -> windows::core::Result<()> {
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

        let mut stripped_buf: Vec<u8> = Vec::new();
        let stripped = copy_dacl_excluding_sids(existing as *const _, &[sid], &mut stripped_buf);
        let mut trustee = TRUSTEE_W::default();
        BuildTrusteeWithSidW(&mut trustee, sid);
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: mask,
            grfAccessMode: DENY_ACCESS,
            grfInheritance: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
            Trustee: trustee,
        };
        let mut merged: *mut ACL = std::ptr::null_mut();
        let merge_result = match stripped {
            Ok((dacl, _removed)) => {
                SetEntriesInAclW(Some(&[entry]), Some(dacl as *const _), &mut merged).ok()
            }
            Err(e) => Err(e),
        };
        let _ = LocalFree(HLOCAL(sd.0));
        merge_result?;

        let result = set_dacl_single_object_with_protection(path, merged, true);
        let _ = LocalFree(HLOCAL(merged as *mut _));
        result
    }
}

/// `path`のDACLを**一切変えずに**、保護つきでもう一度書き戻す（ケース6専用）。
///
/// ケース5との違いは拒否ACEを足さないことだけで、**書込の回数と口は同じ**にしてある。
///
/// # 安全性
///
/// 呼び出し側は`path`が存在することを保証すること。
unsafe fn rewrite_with_protection(path: &Path) -> windows::core::Result<()> {
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
        let result = set_dacl_single_object_with_protection(path, existing, true);
        let _ = LocalFree(HLOCAL(sd.0));
        result
    }
}

/// `path`へ`sid`宛の**明示の拒否ACE**を1本足し、保護を立てたまま書き戻す（ケース5専用）。
///
/// **製品コードは変えない。** 案②を採るかはまだ決まっていないので、ここでローカルに書く。
/// 継承フラグを立てるのは、実際に採るならその形になるからである（配下のファイルにも効かせる）。
///
/// # 安全性
///
/// `sid`は有効なSIDを指していること。
unsafe fn add_explicit_deny(path: &Path, sid: PSID, mask: u32) -> windows::core::Result<()> {
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
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: mask,
            grfAccessMode: DENY_ACCESS,
            grfInheritance: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
            Trustee: trustee,
        };
        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        // `SetEntriesInAclW`が正規順（拒否を許可より前）へ並べ替える。
        let merged =
            SetEntriesInAclW(Some(&[entry]), Some(existing as *const _), &mut new_dacl).ok();
        let _ = LocalFree(HLOCAL(sd.0));
        merged?;

        let result = set_dacl_single_object_with_protection(path, new_dacl, true);
        let _ = LocalFree(HLOCAL(new_dacl as *mut _));
        result
    }
}

/// 1ケースを走らせる。ツリーの形は全ケースで同じ。
///
/// ```text
/// <case_root>/
///   ├─ guarded/          ← `.harness` 相当。ここを保護する
///   │    └─ inner.txt
///   └─ open/             ← 兄弟。伝播が届くべき対照
///        └─ f.txt
/// ```
fn run_case(placement: Placement, case: Case, index: usize) -> CaseResult {
    let mut errors = Vec::new();
    let case_root = placement.root().join(case.label());
    let guarded = case_root.join("guarded");
    let inner = guarded.join("inner.txt");
    let open = case_root.join("open");
    let open_file = open.join("f.txt");
    std::fs::create_dir_all(&guarded).expect("create the guarded dir");
    std::fs::create_dir_all(&open).expect("create the open dir");
    std::fs::write(&inner, b"bug-145 probe\n").expect("seed the inner file");
    std::fs::write(&open_file, b"bug-145 probe\n").expect("seed the open file");

    // ケースごとに別のSIDにして、ケース間の干渉を断つ（台帳は経由しない純粋導出）。
    let sid = capability_sid_from_name(&format!("harnessBug145Probe{index}"))
        .expect("derive a probe capability SID");
    let sid_text = crate::win_common::sid_to_string(sid.as_psid())
        .expect("render the probe SID as a string");
    let mask = workspace_rwx_mask();
    let grants = [AceGrant {
        sid: sid.as_psid(),
        mask,
    }];

    // **親（ケースroot）の制御ビットも読む。** 置き場で結果が割れたとき、親の側に何の差が
    // あるのかを見ないと原因の名前を付けられない。
    let root_control_initial = dacl_control(&case_root).expect("read the case root control bits");

    if case.fast_grants_root() {
        if let Err(e) = grant_workspace_root_aces_fast(&case_root, &grants) {
            errors.push(format!("fast root grant: {e}"));
        }
    }
    let root_control_before_propagate =
        dacl_control(&case_root).expect("read the case root control bits before propagate");

    if case.uses_production_protect() {
        match remove_sid_aces_and_protect(&guarded, sid.as_psid()) {
            Ok(true) => {}
            // [BUG-084] `Ok(false)`は「触る前に消えていた」。自分で作ったツリーなので起こり得ないが、
            // 起きたなら測定が成立しない。
            Ok(false) => {
                errors.push("protect: the guarded dir vanished before it was protected".into())
            }
            Err(e) => errors.push(format!("protect: {e}")),
        }
    } else if let Err(e) = unsafe { protect_with_deny_in_one_write(&guarded, sid.as_psid(), mask) } {
        errors.push(format!("protect+deny in one write: {e}"));
    }
    if case.writes_deny() {
        if let Err(e) = unsafe { add_explicit_deny(&guarded, sid.as_psid(), mask) } {
            errors.push(format!("explicit deny: {e}"));
        }
    }
    if case.rewrites_protection() {
        if let Err(e) = unsafe { rewrite_with_protection(&guarded) } {
            errors.push(format!("reprotect: {e}"));
        }
    }

    let control_after_protect = dacl_control(&guarded).expect("read the control bits after protect");
    let aces_after_protect =
        describe_dacl_aces(&guarded).expect("list the ACEs after protect");
    let guarded_allow_after_protect = match sid_effective_ace_mask(&guarded, sid.as_psid()) {
        Ok(m) => m,
        Err(e) => {
            errors.push(format!("read guarded after protect: {e}"));
            None
        }
    };

    match case.propagate_to() {
        PropagateTo::Nowhere => {}
        PropagateTo::CaseRoot => {
            if let Err(e) = propagate_workspace_root_grant(&case_root, sid.as_psid(), mask) {
                errors.push(format!("propagate (case root): {e}"));
            }
        }
        PropagateTo::SiblingOnly => {
            if let Err(e) = propagate_workspace_root_grant(&open, sid.as_psid(), mask) {
                errors.push(format!("propagate (sibling): {e}"));
            }
        }
    }

    let control_after_propagate =
        dacl_control(&guarded).expect("read the control bits after propagate");
    let aces_after_propagate =
        describe_dacl_aces(&guarded).expect("list the ACEs after propagate");
    let read_mask = |path: &Path, what: &str, errors: &mut Vec<String>| -> Option<u32> {
        match sid_effective_ace_mask(path, sid.as_psid()) {
            Ok(m) => m,
            Err(e) => {
                errors.push(format!("read {what}: {e}"));
                None
            }
        }
    };
    let guarded_allow_after_propagate = read_mask(&guarded, "guarded after propagate", &mut errors);
    let inner_allow_after = read_mask(&inner, "inner after propagate", &mut errors);
    let open_allow_after = read_mask(&open_file, "open/f.txt after propagate", &mut errors);

    let added_aces: Vec<String> = aces_after_propagate
        .iter()
        .filter(|ace| !aces_after_protect.contains(ace))
        .cloned()
        .collect();
    let lost_aces: Vec<String> = aces_after_protect
        .iter()
        .filter(|ace| !aces_after_propagate.contains(ace))
        .cloned()
        .collect();

    let root_control_after_propagate =
        dacl_control(&case_root).expect("read the case root control bits after propagate");

    CaseResult {
        placement: placement.label(),
        case: case.label(),
        root_control_initial,
        root_control_before_propagate,
        root_control_after_propagate,
        control_after_protect,
        control_after_propagate,
        guarded_allow_after_protect,
        guarded_allow_after_propagate,
        inner_allow_after,
        open_allow_after,
        deny_aces_after_protect: count_deny_aces(&aces_after_protect, &sid_text),
        deny_aces_after_propagate: count_deny_aces(&aces_after_propagate, &sid_text),
        added_aces,
        lost_aces,
        errors,
    }
}

/// controlビットのうち、この実験で意味を持つものを人が読める形にする。
/// **BUG-083のプローブと同じ綴り**にしてある（2つの出力を並べて読むため）。
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

fn describe_mask(mask: Option<u32>) -> String {
    match mask {
        Some(m) => format!("0x{m:08x}"),
        None => "-".to_string(),
    }
}

/// [BUG-145] **保護したノード自身が、親の伝播で保護を失うのか。**
///
/// 判定表（何が出たらどう読むか）は`docs/bugs/BUG-145.md`の「原因」節へ転記する。
#[test]
#[ignore = "実FSのDACLを書き換える観測用プローブ（C:\\harness-bug145-probe と %TEMP% のみ、管理者権限不要）。結果はdocs/bugs/BUG-145.mdへ転記する"]
fn control_dir_propagation_matrix_probe() {
    let mut results = Vec::new();
    let mut index = 0usize;
    for placement in PLACEMENTS {
        let root = placement.root();
        // 前回の残骸が結果を汚さないよう毎回作り直す（残すのは実行「後」だけ）。
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create the probe root");
        for case in CASES {
            index += 1;
            results.push(run_case(*placement, *case, index));
        }
    }

    for r in &results {
        println!("--- [{}] {} ---", r.placement, r.case);
        println!(
            "  ROOT control            : {} -> {} -> {}   (作成直後 -> 高速付与後 -> 伝播後)",
            describe_control(r.root_control_initial),
            describe_control(r.root_control_before_propagate),
            describe_control(r.root_control_after_propagate)
        );
        println!(
            "  control after protect   : {}",
            describe_control(r.control_after_protect)
        );
        println!(
            "  control after propagate : {}",
            describe_control(r.control_after_propagate)
        );
        println!(
            "  guarded allow           : {} -> {}   (protect -> propagate)",
            describe_mask(r.guarded_allow_after_protect),
            describe_mask(r.guarded_allow_after_propagate)
        );
        println!(
            "  guarded deny ACEs       : {} -> {}",
            r.deny_aces_after_protect, r.deny_aces_after_propagate
        );
        println!(
            "  guarded/inner.txt allow : {}",
            describe_mask(r.inner_allow_after)
        );
        println!(
            "  open/f.txt allow        : {}   <- 対照（伝播が走ったか）",
            describe_mask(r.open_allow_after)
        );
        for ace in &r.added_aces {
            println!("  + gained ACE            : {ace}");
        }
        for ace in &r.lost_aces {
            println!("  - lost ACE              : {ace}");
        }
        for e in &r.errors {
            println!("  !! error                : {e}");
        }
    }

    println!("=== verdict ===");
    for placement in PLACEMENTS {
        let label = placement.label();
        let mine: Vec<&CaseResult> = results.iter().filter(|r| r.placement == label).collect();
        let lost_protection: Vec<&str> = mine
            .iter()
            .filter(|r| r.protected_after_protect() && !r.protected_after_propagate())
            .map(|r| r.case)
            .collect();
        let became_reachable: Vec<&str> = mine
            .iter()
            .filter(|r| r.guarded_became_reachable())
            .map(|r| r.case)
            .collect();
        let deny_survived: Vec<&str> = mine
            .iter()
            .filter(|r| r.deny_aces_after_protect > 0 && r.deny_aces_after_propagate > 0)
            .map(|r| r.case)
            .collect();
        println!("  [{label}] lost SE_DACL_PROTECTED : {lost_protection:?}");
        println!("  [{label}] guarded became reachable: {became_reachable:?}");
        println!("  [{label}] explicit deny survived  : {deny_survived:?}");
    }

    // --- ここから下は「実験の前提が崩れていないか」だけを見る（合否は判定しない） ---
    for r in &results {
        assert!(
            r.protected_after_protect(),
            "[{}] {}: 保護が立たなかったので、以降の観測は別のものを測っている（control={}）",
            r.placement,
            r.case,
            describe_control(r.control_after_protect)
        );
    }
    for r in results.iter().filter(|r| r.case != Case::NoPropagate.label()) {
        assert!(
            r.open_allow_after.is_some(),
            "[{}] {}: 対照の open/f.txt へ伝播が届いていない。このケースは『保護が効いた』ではなく \
             『伝播が走っていない』を測っている",
            r.placement,
            r.case
        );
    }
    // 対照の対（`B-35`）——伝播しないケースでは兄弟にも届かないこと。届いていたら、
    // 高速付与が伝播していることになり、このプローブの前提そのものが崩れる。
    for r in results.iter().filter(|r| r.case == Case::NoPropagate.label()) {
        assert!(
            r.open_allow_after.is_none(),
            "[{}] {}: 伝播していないのに兄弟へ届いている。高速付与が伝播しない口である \
             という前提が崩れている",
            r.placement,
            r.case
        );
    }
}
