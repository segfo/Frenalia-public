//! 固定辺の起動直前に、**固定したファイルを呼び出し元が書き換えられないか**を、
//! 呼び出し元のトークンでOSに聞く（`plans/DESIGN-MAC.md` §19.1「固定値が指すファイルの書込可否」）。
//!
//! # なぜ文字列の検査だけでは足りないのか
//!
//! 読み込み時の検査（`harness_policy::transition`の`caller_writable_fixed_paths`）は、
//! 固定したパスが「書ける場所」のパスの下にあるかを**綴りで**比べる。別名——8.3形式の短い名前・
//! シンボリックリンク・ジャンクション・ハードリンク——を挟むと、実体は書ける場所にあるのに綴りが
//! 一致しない。**ハードリンクはパスをどう解決しても見つからない**（1つの実体に付いた名前はどれも対等で、
//! `GetFinalPathNameByHandleW`は開くのに使った名前を返す）。
//!
//! そこで名前ではなく**実体**に聞く。ファイルのアクセス制御リストは全部の名前で共通なので、
//! 実体のセキュリティ記述子と呼び出し元のトークンを`AccessCheck`へ渡せば、どの名前で
//! 書かれていても同じ答えになる。
//!
//! # 判定の正本を置き換えない
//!
//! これは**拒否を足すだけ**の検査である。宣言による判定（読み込み時の検査）はそのまま残す
//! ——`plans/DESIGN-MAC-BROKER.md` §22.8が`AccessCheck`を判定の正本にする案を却下した理由
//! （実体のずれを正しいものとして追認する）は、緩める向きが無いこの使い方には当たらない。
//! 逆に、Redirector DLLが差分層へ振り向ける書込はACLに現れないので、この検査からは見えない
//! （そちらは読み込み時の検査が受け持つ）。
//!
//! # 使うトークン
//!
//! Daemonが持っている**呼び出し元のプロセスハンドル**（`CreateProcessW`の戻り値）から開く。
//! PIDから開き直さないのは、Daemonが既に持っている値のほうが、PIDの再利用に左右されないため
//! である。雛形はTier3の`harness-sandbox-vm`の`duplicate_client_token_for_access_check`と
//! `access_check_write`（`vmsandboxd/authz.rs`）で、違いは次の3つ。
//!
//! - PIDではなくハンドルから開き、開く前にハンドルが指すプロセスのPIDを確かめる
//! - 真偽値ではなく、**付与される権利の集合**（`MAXIMUM_ALLOWED`）を返す——書込だけでなく
//!   削除・アクセス制御リストの書換えも見るため
//! - **整合性ラベルも読む**——AppContainerのトークンは低い整合性レベルで動くので、
//!   ラベルを渡さないと`AccessCheck`が実際と違う答えを返し得る

use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE};
use windows::Win32::Security::{
    AccessCheck, DuplicateToken, GetKernelObjectSecurity, SecurityImpersonation,
    DACL_SECURITY_INFORMATION, GENERIC_MAPPING, GROUP_SECURITY_INFORMATION,
    LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PRIVILEGE_SET, PSECURITY_DESCRIPTOR,
    TOKEN_DUPLICATE, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ALL_ACCESS, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
};
use windows::Win32::System::Threading::{GetProcessId, OpenProcessToken};

use crate::win_common::long_path_wide;

/// `MAXIMUM_ALLOWED`（`winnt.h`）。付与され得る権利を全部返させる。
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

// 権利のビット（`winnt.h`）。ディレクトリでは`FILE_WRITE_DATA`が`FILE_ADD_FILE`、
// `FILE_APPEND_DATA`が`FILE_ADD_SUBDIRECTORY`と同じビットである。
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const FILE_DELETE_CHILD: u32 = 0x0000_0040;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;

/// 断る理由の文面（Daemonの標準エラーへ出す。**サンドボックスへは返さない**）。
fn right_names(mask: u32) -> String {
    const NAMES: &[(u32, &str)] = &[
        (FILE_WRITE_DATA, "FILE_WRITE_DATA/FILE_ADD_FILE"),
        (FILE_APPEND_DATA, "FILE_APPEND_DATA/FILE_ADD_SUBDIRECTORY"),
        (FILE_DELETE_CHILD, "FILE_DELETE_CHILD"),
        (FILE_WRITE_ATTRIBUTES, "FILE_WRITE_ATTRIBUTES"),
        (DELETE, "DELETE"),
        (WRITE_DAC, "WRITE_DAC"),
        (WRITE_OWNER, "WRITE_OWNER"),
    ];
    NAMES
        .iter()
        .filter(|(bit, _)| mask & bit != 0)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join("|")
}

/// 呼び出し元のトークンを複製した、`AccessCheck`専用のimpersonationトークン。
///
/// **このスレッドを呼び出し元へ偽装することには使わない**——`AccessCheck`の入力にするだけである
/// （Tier3の雛形と同じ方針）。`Drop`で閉じる。
pub(crate) struct CallerToken(HANDLE);

impl CallerToken {
    /// Daemonが持っている呼び出し元のプロセスハンドルから開く。
    ///
    /// # なぜ先にPIDを確かめるのか
    ///
    /// Daemonの刈り取りスレッドは、終わった呼び出し元のハンドルを閉じる。判定の途中で閉じられ、
    /// 同じ値のハンドルが別のプロセスへ使い回されると、**別のプロセスの権利で判定する**ことになる。
    /// ハンドルが指すプロセスのPIDが呼び出し元のものと違えば、判定せずに失敗させる
    /// （呼び出し側はこれを「判定できない」として断る）。
    pub(crate) fn from_process(process: HANDLE, expected_pid: u32) -> Result<Self, String> {
        unsafe {
            let actual_pid = GetProcessId(process);
            if actual_pid != expected_pid {
                return Err(format!(
                    "the caller's process handle now refers to pid {actual_pid}, not {expected_pid}"
                ));
            }
            let mut primary = HANDLE::default();
            OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &mut primary)
                .map_err(|e| format!("OpenProcessToken(pid {expected_pid}): {e}"))?;
            let mut impersonation = HANDLE::default();
            let duplicated = DuplicateToken(primary, SecurityImpersonation, &mut impersonation);
            let _ = CloseHandle(primary);
            duplicated.map_err(|e| format!("DuplicateToken(pid {expected_pid}): {e}"))?;
            Ok(Self(impersonation))
        }
    }
}

impl Drop for CallerToken {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// ハンドルを閉じるだけの最小の後始末。
struct OpenedObject(HANDLE);

impl Drop for OpenedObject {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// `path`が指すオブジェクトについて、`token`へ**付与される権利の集合**を返す。
///
/// `follow_last_link`が`false`なら、末端がリンク（シンボリックリンク・ジャンクション）でも
/// **リンクそのもの**を見る（`FILE_FLAG_OPEN_REPARSE_POINT`）。リンクを消して別の先へ
/// 向け直せるかは、リンク自身の権利で決まるからである。途中の要素のリンクはどちらでも辿る。
///
/// 開くのは`READ_CONTROL`だけ（中身は読まない）で、共有は全許可にする——判定のために
/// 対象を掴んで他の書込を止めると、呼び出し元の意図しない排他になる。
pub(crate) fn granted_access(
    path: &Path,
    token: &CallerToken,
    follow_last_link: bool,
) -> Result<u32, String> {
    let path_w = long_path_wide(path);
    let mut flags: FILE_FLAGS_AND_ATTRIBUTES = FILE_FLAG_BACKUP_SEMANTICS;
    if !follow_last_link {
        flags |= FILE_FLAG_OPEN_REPARSE_POINT;
    }
    unsafe {
        let handle = CreateFileW(
            PCWSTR(path_w.as_ptr()),
            READ_CONTROL.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
        .map_err(|e| format!("CreateFileW({}): {e}", path.display()))?;
        let object = OpenedObject(handle);

        let requested = OWNER_SECURITY_INFORMATION
            | GROUP_SECURITY_INFORMATION
            | DACL_SECURITY_INFORMATION
            | LABEL_SECURITY_INFORMATION;
        let mut needed = 0u32;
        // 1回目は必要な大きさを聞くだけ（必ず失敗する）。
        let _ = GetKernelObjectSecurity(
            object.0,
            requested.0,
            PSECURITY_DESCRIPTOR::default(),
            0,
            &mut needed,
        );
        if needed == 0 {
            return Err(format!(
                "GetKernelObjectSecurity({}) did not report a size",
                path.display()
            ));
        }
        let mut descriptor = vec![0u8; needed as usize];
        GetKernelObjectSecurity(
            object.0,
            requested.0,
            PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr() as *mut _),
            needed,
            &mut needed,
        )
        .map_err(|e| format!("GetKernelObjectSecurity({}): {e}", path.display()))?;

        let mapping = GENERIC_MAPPING {
            GenericRead: FILE_GENERIC_READ.0,
            GenericWrite: FILE_GENERIC_WRITE.0,
            GenericExecute: FILE_GENERIC_EXECUTE.0,
            GenericAll: FILE_ALL_ACCESS.0,
        };
        let mut privilege_set = [0u8; 1024];
        let mut privilege_set_len = privilege_set.len() as u32;
        let mut granted = 0u32;
        let mut status = BOOL(0);
        AccessCheck(
            PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr() as *mut _),
            token.0,
            MAXIMUM_ALLOWED,
            &mapping,
            Some(privilege_set.as_mut_ptr() as *mut PRIVILEGE_SET),
            &mut privilege_set_len,
            &mut granted,
            &mut status,
        )
        .map_err(|e| format!("AccessCheck({}): {e}", path.display()))?;
        // 何も付与されないときは`status`が偽になる。そのとき`granted`は意味を持たないので0にする。
        Ok(if status.as_bool() { granted } else { 0 })
    }
}

/// 鎖の1要素（判定に掛けるオブジェクト1つ）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChainLink {
    pub path: std::path::PathBuf,
    /// `false`なら末端のリンクを辿らず**リンクそのもの**を見る（[`granted_access`]）。
    pub follow_last_link: bool,
    /// この要素がリンク（リパースポイント）として見られているか。リンクは向け先を変えられるかも見る。
    pub is_link: bool,
}

/// 固定したパス1つについての、**葉から根へ**並べた鎖。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Chain {
    /// 断る理由の文面で、どちらの鎖で見つかったかを言うための名前。
    pub label: &'static str,
    /// `links[0]`が葉、`links[i + 1]`が`links[i]`の親。
    pub links: Vec<ChainLink>,
    /// 葉が固定したパスそのものか（`false`なら、まだ無いパスの**実在する一番深い祖先**）。
    pub leaf_is_the_fixed_path: bool,
    /// 葉がディレクトリか（固定した引数がディレクトリを指すことがある）。
    pub leaf_is_dir: bool,
}

/// 固定したパス1つについて、判定に掛ける**2本の鎖**を作る。
///
/// ```text
/// C:\link\gen.exe   （C:\link は C:\tools へのジャンクション）
///
/// 書いた綴りの鎖   C:\link\gen.exe → C:\link（リンクそのもの）→ C:\
/// 実体の鎖         C:\tools\gen.exe → C:\tools → C:\
/// ```
///
/// - **書いた綴りの鎖**: リンクを消したり向け先を変えたりできるかは、リンク自身とその親の権利で
///   決まる。だから各要素を末端のリンクを辿らずに開く。`..`と`.`は先に文字の上で解決する
///   （`CreateProcessW`もそう解決してから開く。リンクは辿らない）
/// - **実体の鎖**: ジャンクションの先の本当の親（上の`C:\tools`）は、書いた綴りの鎖に現れない
///
/// **ハードリンクはここで何もしない**——アクセス制御リストはファイル実体に1つだけあり、
/// 全部の名前で共通なので、葉の判定がどの名前で開いても同じ答えを返す。
///
/// まだ無いパス（出力先の引数など）は、**実在する一番深い祖先を葉にする**——呼び出し元が
/// そこへ同じ名前のものを先に置けるかが問いになる。
pub(crate) fn chains(fixed_path: &Path) -> Result<Vec<Chain>, String> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

    let literal = std::path::absolute(fixed_path)
        .map_err(|e| format!("absolute({}): {e}", fixed_path.display()))?;
    // 名前そのものが在るか（リンク切れのリンクも「在る」。辿らない）。
    let link_metadata = |p: &Path| std::fs::symlink_metadata(p).ok();
    let Some(leaf) = literal.ancestors().find(|p| link_metadata(p).is_some()) else {
        return Err(format!("none of {} or its ancestors exists", literal.display()));
    };
    let leaf_is_the_fixed_path = leaf == literal.as_path();
    let leaf_is_dir = std::fs::metadata(leaf).map(|m| m.is_dir()).unwrap_or(true);

    let written = Chain {
        label: "the path as written",
        links: leaf
            .ancestors()
            .map(|p| ChainLink {
                path: p.to_path_buf(),
                follow_last_link: false,
                is_link: link_metadata(p)
                    .map(|m| m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
                    .unwrap_or(false),
            })
            .collect(),
        leaf_is_the_fixed_path,
        leaf_is_dir,
    };
    let resolved = std::fs::canonicalize(leaf)
        .map_err(|e| format!("canonicalize({}): {e}", leaf.display()))?;
    let real = Chain {
        label: "the resolved path",
        links: resolved
            .ancestors()
            .map(|p| ChainLink {
                path: p.to_path_buf(),
                follow_last_link: true,
                is_link: false,
            })
            .collect(),
        leaf_is_the_fixed_path,
        leaf_is_dir,
    };
    Ok(vec![written, real])
}

/// 鎖の各要素について付与される権利（`granted[i]`が`chain.links[i]`のもの）から、
/// **呼び出し元が固定したパスの中身を決められるか**を判定する。決められるなら
/// `(要素の添字, 効いた権利, 理由)`を返す。
///
/// **OSを呼ばない純粋な関数である**——規則は権利の組み合わせだけで決まるので、
/// 組み合わせを単体テストで固定する。規則は位置ごとに違う。
///
/// | 位置 | 断る条件 | なぜ |
/// |---|---|---|
/// | どこでも | `WRITE_DAC`・`WRITE_OWNER` | 自分に何でも与え直せる |
/// | 書いた綴りの鎖のリンク | `FILE_WRITE_DATA`・`FILE_WRITE_ATTRIBUTES`・`DELETE` | 向け先を変える・消す |
/// | 葉（固定したファイル） | `FILE_WRITE_DATA`・`FILE_APPEND_DATA`・`FILE_WRITE_ATTRIBUTES` | 中身を書き換える |
/// | 葉（固定したディレクトリ） | `FILE_ADD_FILE`・`FILE_ADD_SUBDIRECTORY`・`FILE_DELETE_CHILD`・`FILE_WRITE_ATTRIBUTES` | 中に置く・差し替える |
/// | 葉（まだ無いパスの一番深い祖先） | `FILE_ADD_FILE`・`FILE_ADD_SUBDIRECTORY` | 同じ名前のものを先に置ける |
/// | 固定したパスの**直接の親** | `FILE_ADD_FILE`・`FILE_ADD_SUBDIRECTORY` | 隣に置ける——実行ファイルの隣のDLL、スクリプトの隣のモジュールは先に読まれる |
/// | 隣り合う子と親 | (子の`DELETE`か親の`FILE_DELETE_CHILD`) **かつ** 親の`FILE_ADD_FILE`・`FILE_ADD_SUBDIRECTORY` | 消して同じ名前で作り直す。**片方だけでは差し替えられない**（作れても既に在る名前は取れず、消せても置き直せない） |
pub(crate) fn verdict(chain: &Chain, granted: &[u32]) -> Option<(usize, u32, &'static str)> {
    const ADD: u32 = FILE_WRITE_DATA | FILE_APPEND_DATA; // ディレクトリでは ADD_FILE | ADD_SUBDIRECTORY
    debug_assert_eq!(chain.links.len(), granted.len());
    for (i, (link, &g)) in chain.links.iter().zip(granted).enumerate() {
        let hit = g & (WRITE_DAC | WRITE_OWNER);
        if hit != 0 {
            return Some((i, hit, "can rewrite its access control list or owner"));
        }
        if link.is_link {
            let hit = g & (FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | DELETE);
            if hit != 0 {
                return Some((i, hit, "can retarget or remove this link"));
            }
        }
    }
    let leaf = granted.first().copied().unwrap_or(0);
    let leaf_rights = match (chain.leaf_is_the_fixed_path, chain.leaf_is_dir) {
        (true, false) => FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES,
        (true, true) => ADD | FILE_DELETE_CHILD | FILE_WRITE_ATTRIBUTES,
        (false, _) => ADD,
    };
    if leaf & leaf_rights != 0 {
        let why = if chain.leaf_is_the_fixed_path {
            "can modify the fixed file itself"
        } else {
            "can create the fixed path, which does not exist yet"
        };
        return Some((0, leaf & leaf_rights, why));
    }
    if chain.leaf_is_the_fixed_path {
        if let Some(&parent) = granted.get(1) {
            if parent & ADD != 0 {
                return Some((
                    1,
                    parent & ADD,
                    "can place files next to the fixed path (they are searched first)",
                ));
            }
        }
    }
    for i in 0..granted.len().saturating_sub(1) {
        let (child, parent) = (granted[i], granted[i + 1]);
        let can_remove = child & DELETE != 0 || parent & FILE_DELETE_CHILD != 0;
        if can_remove && parent & ADD != 0 {
            let used = (child & DELETE) | (parent & (FILE_DELETE_CHILD | ADD));
            return Some((i + 1, used, "can delete an entry on the path and recreate it"));
        }
    }
    None
}

/// 固定したパス1つについて、呼び出し元が書き換えられるなら**その理由**を返す。
pub(crate) fn rewritable(fixed_path: &Path, token: &CallerToken) -> Result<Option<String>, String> {
    for chain in chains(fixed_path)? {
        let granted = chain
            .links
            .iter()
            .map(|link| granted_access(&link.path, token, link.follow_last_link))
            .collect::<Result<Vec<u32>, String>>()?;
        if let Some((i, rights, why)) = verdict(&chain, &granted) {
            return Ok(Some(format!(
                "{} is fixed by the transition, but the caller {why}: holds {} on {} (checked via {})",
                fixed_path.display(),
                right_names(rights),
                chain.links[i].path.display(),
                chain.label
            )));
        }
    }
    Ok(None)
}

/// 固定辺を起こしてよいか。**断るべきなら、その理由**（Daemonの標準エラー用）を返す。
///
/// 見るのは**実際に`CreateProcessW`へ渡す値**——要求された実行ファイルと、呼び出し元の
/// コマンドライン——から`harness_policy::transition::fixed_file_paths`が取り出したファイルである。
/// 宣言の綴りで聞くと、判定したのと別のファイルが起き得る（B-21）。
///
/// **判定できないときも断る**（トークンを開けない・記述子を読めない等）。
/// この検査が効かない状態で起こすと、固定の前提を確かめないまま広い権限で走らせることになる。
pub(crate) fn refusal(
    caller_process: HANDLE,
    caller_pid: u32,
    image: &str,
    command_line: &str,
) -> Option<String> {
    let token = match CallerToken::from_process(caller_process, caller_pid) {
        Ok(token) => token,
        Err(e) => return Some(format!("could not open the caller's token: {e}")),
    };
    for path in harness_policy::transition::fixed_file_paths(image, command_line) {
        match rewritable(Path::new(&path), &token) {
            Ok(None) => continue,
            Ok(Some(reason)) => return Some(reason),
            Err(e) => return Some(format!("could not verify {path}: {e}")),
        }
    }
    None
}

#[cfg(test)]
#[path = "fixed_inputs_tests.rs"]
mod fixed_inputs_tests;
