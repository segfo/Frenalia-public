//! 昇格プロセスを起こす側・昇格プロセスが受け取る側の共通ガード。
//!
//! harnessには昇格したヘルパーが3種類ある（`privhelper` / `netfilterd` / `policy-learnd`）。
//! いずれも**非昇格の親から指示を受けて管理者権限で動く**ため、親と子の境界に2つの弱点が生まれる。
//! このモジュールはその両方を1箇所で塞ぐ。
//!
//! | 弱点 | 対策 | 実装 |
//! |---|---|---|
//! | 起動する実行ファイル自体を差し替えられる（T-21） | 起動前に配置のDACLを検査する（D-44） | [`verify_elevation_target`] |
//! | 親が指定した任意パスへ昇格側が書き込む | 受信側で書込先を検証する | [`validate_audit_sink_path`] |
//!
//! # なぜ署名ではなくDACLなのか（D-44）
//!
//! 検証する側（例: `harness-netfilterd.exe`）と検証される側（`harness-policy-learnd.exe`）が
//! **同じディレクトリに居る**以上、ヘルパーを差し替えられる攻撃者は検証子そのものも差し替えられる。
//! Authenticode署名でもハッシュpinでも、この循環は破れない（pinを持つバイナリごと書き換えられる）。
//! 自己署名の信頼アンカーを`CurrentUser\Root`へ置けば中IL攻撃者が自分の証明書を足して素通りでき、
//! `LocalMachine\Root`へ置けば「開発ツールがマシン全体の信頼アンカーを増やす」という、
//! 防ごうとした問題より重い変更になる。
//!
//! **実際に効くのは配置の性質だけ**——「そのディレクトリが非管理者から書けないこと」。
//! ユーザーがUACで同意した1つのバイナリを起点に、その兄弟は同等に信頼される、という構造だからである。
//! したがってここは「署名の代用」ではなく、**その構造を可視化して破れているなら止める**ためのゲートである。

use std::path::{Path, PathBuf};

/// 開発ビルド用の逃がし弁。`target/debug\`は必ずユーザー書込可なので、これが無いと
/// 開発中に一切ヘルパーを起こせなくなる。**設定しても黙って通さない**（毎回警告を出す）。
pub const ALLOW_USER_WRITABLE_HELPERS_ENV: &str = "HARNESS_ALLOW_USER_WRITABLE_ELEVATED_HELPERS";

/// 「非管理者が実行ファイルを差し替えられる」を意味する書込系アクセス権。
///
/// **個別ビットを明示列挙する**。`FILE_GENERIC_WRITE`のような複合マスクで判定すると
/// `SYNCHRONIZE`/`READ_CONTROL`を共有する読み取り専用のACEまで書込扱いになる
/// （[BUG-048]で実際に踏んだ誤判定。`docs/SECURITY-PRINCIPLES.md`末尾の注意）。
///
/// [BUG-048]: ../../docs/bugs/BUG-048.md
const DANGEROUS_WRITE_BITS: u32 = 0x0002 // FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x0004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x0010 // FILE_WRITE_EA
    | 0x0100 // FILE_WRITE_ATTRIBUTES
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x1000_0000 // GENERIC_ALL
    | 0x4000_0000; // GENERIC_WRITE

/// 昇格対象の配置が信用できない。
#[derive(Debug, thiserror::Error)]
pub enum ElevationTargetError {
    #[error("{path} does not exist")]
    Missing { path: PathBuf },
    #[error("could not read the security descriptor of {path}: {reason}")]
    Unreadable { path: PathBuf, reason: String },
    #[error(
        "{path} is writable by {trustee} (access mask {mask:#010x}). Elevating a helper from a \
         location that a non-administrator can modify is a local privilege escalation: whoever \
         can replace the file gets code execution as administrator. Set {env}=1 to continue \
         anyway (development builds under target\\debug always trip this)."
    )]
    WritableByNonAdmin {
        path: PathBuf,
        trustee: String,
        mask: u32,
        env: &'static str,
    },
}

/// 昇格起動する実行ファイルと**その親ディレクトリ**の配置を検証する（T-21 / D-44）。
///
/// 親ディレクトリも見るのは、ディレクトリへ書ける者はファイルを消して置き換えられるためである
/// （ファイル自身のDACLだけを見ても意味が無い）。
///
/// 既定は拒否（P-05）。[`ALLOW_USER_WRITABLE_HELPERS_ENV`]が設定されているときだけ、
/// **警告を出したうえで**続行する。
pub fn verify_elevation_target(exe: &Path) -> Result<(), ElevationTargetError> {
    let result = check_target(exe);
    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            if std::env::var_os(ALLOW_USER_WRITABLE_HELPERS_ENV).is_some() {
                eprintln!(
                    "WARNING: elevating a helper from a location that is not administrator-only: \
                     {e}\n  Continuing because {ALLOW_USER_WRITABLE_HELPERS_ENV} is set. This is \
                     acceptable on a development machine and nowhere else."
                );
                return Ok(());
            }
            Err(e)
        }
    }
}

fn check_target(exe: &Path) -> Result<(), ElevationTargetError> {
    if !exe.exists() {
        return Err(ElevationTargetError::Missing {
            path: exe.to_path_buf(),
        });
    }
    check_one(exe)?;
    if let Some(parent) = exe.parent() {
        check_one(parent)?;
    }
    Ok(())
}

#[cfg(windows)]
fn check_one(path: &Path) -> Result<(), ElevationTargetError> {
    for (trustee, mask) in read_allow_aces(path)? {
        if is_dangerous_trustee_grant(&trustee, mask) {
            return Err(ElevationTargetError::WritableByNonAdmin {
                path: path.to_path_buf(),
                trustee,
                mask,
                env: ALLOW_USER_WRITABLE_HELPERS_ENV,
            });
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn check_one(_path: &Path) -> Result<(), ElevationTargetError> {
    // 昇格ヘルパー機構自体がWindows専用。非Windowsでは呼ばれない。
    Ok(())
}

/// DACLの**許可**ACEを`(SID文字列, アクセスマスク)`で列挙する。
///
/// **継承ACEも含める**。`GetExplicitEntriesFromAclW`は継承ACEを飛ばすため使わない
/// （この罠は`grant_ace_inheritable_ro`の実装時にも踏んでいる）。ここで継承ACEを
/// 見落とすと、`target\debug`がユーザープロファイルから継承した`Users:Modify`を
/// 見逃して「安全」と判定してしまう——それはこのゲートが防ぎたいものそのものである。
#[cfg(windows)]
fn read_allow_aces(path: &Path) -> Result<Vec<(String, u32)>, ElevationTargetError> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetAce, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID,
    };

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

    let to_err = |reason: String| ElevationTargetError::Unreadable {
        path: path.to_path_buf(),
        reason,
    };
    let path_w = crate::win_common::long_path_wide(path);
    let mut entries = Vec::new();

    unsafe {
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        )
        .ok()
        .map_err(|e| to_err(e.to_string()))?;

        if dacl.is_null() {
            // NULL DACL = 誰でもフルアクセス。最悪の状態なので明示的に危険側へ倒す。
            let _ = LocalFree(HLOCAL(sd.0));
            return Ok(vec![("(null DACL: everyone)".to_string(), u32::MAX)]);
        }

        let count = (*dacl).AceCount as u32;
        for index in 0..count {
            let mut ace_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
            if GetAce(dacl, index, &mut ace_ptr).is_err() || ace_ptr.is_null() {
                continue;
            }
            let header = ace_ptr as *const ACE_HEADER;
            if (*header).AceType != ACCESS_ALLOWED_ACE_TYPE {
                continue; // DENY・監査ACEは「書ける」の根拠にならない
            }
            let ace = ace_ptr as *const ACCESS_ALLOWED_ACE;
            let mask = (*ace).Mask;
            let sid = PSID(&(*ace).SidStart as *const u32 as *mut core::ffi::c_void);
            let mut sid_string = windows::core::PWSTR::null();
            if ConvertSidToStringSidW(sid, &mut sid_string).is_ok() && !sid_string.is_null() {
                entries.push((sid_string.to_string().unwrap_or_default(), mask));
                let _ = LocalFree(HLOCAL(sid_string.0 as *mut _));
            }
        }
        let _ = LocalFree(HLOCAL(sd.0));
    }

    Ok(entries)
}

/// **純粋な判定**: この`(SID, マスク)`は「非管理者が差し替えられる」ことを意味するか。
///
/// 管理者・SYSTEM・TrustedInstallerが書けるのは正常である（そもそも昇格した先の権限と同じ）。
/// それ以外のアカウントに書込系ビットが与えられていれば、そのアカウントは昇格ヘルパーを差し替えられる。
pub fn is_dangerous_trustee_grant(sid: &str, mask: u32) -> bool {
    if mask & DANGEROUS_WRITE_BITS == 0 {
        return false;
    }
    !is_admin_equivalent_sid(sid)
}

/// 昇格後の権限と同等（＝書けても新しい権限を与えない）アカウントか。
fn is_admin_equivalent_sid(sid: &str) -> bool {
    matches!(
        sid,
        "S-1-5-32-544" // BUILTIN\Administrators
            | "S-1-5-18" // NT AUTHORITY\SYSTEM
            | "S-1-5-19" // LOCAL SERVICE（サービス系。書込を持つ既定構成がある）
            | "S-1-5-20" // NETWORK SERVICE
            | "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" // TrustedInstaller
    )
}

/// 監査ログの書込先として受理できないパスだった。
#[derive(Debug, thiserror::Error)]
pub enum AuditSinkPathError {
    #[error("audit sink path must be absolute, got {0}")]
    NotAbsolute(PathBuf),
    #[error("audit sink path must live under <workspace>/.harness/sandbox/, got {0}")]
    OutsideSandboxDir(PathBuf),
    #[error("audit sink path could not be canonicalized ({path}): {reason}")]
    Unresolvable { path: PathBuf, reason: String },
    #[error("audit sink path escapes the sandbox directory after resolution: {0}")]
    EscapesAfterResolution(PathBuf),
}

/// 昇格側が受け取った「ここへ監査ログを書け」というパスを検証する。
///
/// **非昇格の親が指定した任意`PathBuf`へ昇格プロセスが追記する**構造は、そのままでは
/// **管理者権限での任意パス追記プリミティブ**である（既存の`NetfilterPolicy.audit_log_path`が
/// これに当たる）。書込先を`<workspace_root>/.harness/sandbox/`配下に限定して閉じる。
///
/// 検証は**受信側（昇格側）で**行う。送信側で検証しても、送信側は非特権で攻撃者と同じ権限だから
/// 意味を持たない（P-01）。
///
/// シンボリックリンク・ジャンクションによる脱出は、親ディレクトリを`canonicalize`してから
/// 前方一致を見ることで潰す（`canonicalize`はreparse pointを解決する）。ファイル自身は
/// まだ存在しないことがあるため、**親ディレクトリを解決してからファイル名を足す**。
pub fn validate_audit_sink_path(
    requested: &Path,
    workspace_root: &Path,
) -> Result<PathBuf, AuditSinkPathError> {
    validate_sink_under(
        requested,
        &workspace_root.join(".harness").join("sandbox"),
    )
}

/// [`validate_audit_sink_path`]の一般形——**書込先を`allowed_dir`配下に限定する**。
///
/// # なぜ2つ目の入口が要るのか
///
/// 昇格側が書くファイルが`.harness/sandbox/`の外にも生まれたためである
/// （段階6dの`.harness/transitions/observed.jsonl`、§10.3）。**検証をそちらへ複製すると、
/// ジャンクションの解決を片方だけ直した日に穴が開く**——`canonicalize`してから前方一致、
/// という順序はここ1箇所が持つ。
///
/// **`allowed_dir`は呼び出し側が固定値から組むこと。** 要求から受け取った文字列を
/// そのまま渡すと、限定そのものが攻撃者の指定になる。
pub fn validate_sink_under(
    requested: &Path,
    allowed_dir: &Path,
) -> Result<PathBuf, AuditSinkPathError> {
    if !requested.is_absolute() {
        return Err(AuditSinkPathError::NotAbsolute(requested.to_path_buf()));
    }

    let sandbox_root = allowed_dir.to_path_buf();
    // 文字列レベルの前方一致を先に見る（解決前に明らかに外なら、そこで落とす）。
    if !starts_with_ignore_case(requested, &sandbox_root) {
        return Err(AuditSinkPathError::OutsideSandboxDir(
            requested.to_path_buf(),
        ));
    }

    let file_name = requested
        .file_name()
        .ok_or_else(|| AuditSinkPathError::OutsideSandboxDir(requested.to_path_buf()))?;
    let parent = requested
        .parent()
        .ok_or_else(|| AuditSinkPathError::OutsideSandboxDir(requested.to_path_buf()))?;

    // reparse point（symlink/junction）を解決したうえでもう一度確かめる。
    let resolved_parent = parent
        .canonicalize()
        .map_err(|e| AuditSinkPathError::Unresolvable {
            path: parent.to_path_buf(),
            reason: e.to_string(),
        })?;
    let resolved_sandbox_root =
        sandbox_root
            .canonicalize()
            .map_err(|e| AuditSinkPathError::Unresolvable {
                path: sandbox_root.clone(),
                reason: e.to_string(),
            })?;
    if !starts_with_ignore_case(&resolved_parent, &resolved_sandbox_root) {
        return Err(AuditSinkPathError::EscapesAfterResolution(
            requested.to_path_buf(),
        ));
    }

    Ok(resolved_parent.join(file_name))
}

/// Windowsのパス比較は大小を区別しない。`Path::starts_with`はコンポーネント単位で比較するので
/// `C:\a\bc`が`C:\a\b`の配下と誤判定されることは無いが、大小の違いを吸収しないため自前で行う。
fn starts_with_ignore_case(path: &Path, prefix: &Path) -> bool {
    let mut path_components = path.components();
    for prefix_component in prefix.components() {
        match path_components.next() {
            Some(actual) => {
                let actual = actual.as_os_str().to_string_lossy();
                let expected = prefix_component.as_os_str().to_string_lossy();
                if !actual.eq_ignore_ascii_case(&expected) {
                    return false;
                }
            }
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `.harness/sandbox/`配下の素直なパスは受理され、解決済みの絶対パスが返る。
    #[test]
    fn a_path_inside_the_sandbox_directory_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path();
        let session = workspace.join(".harness").join("sandbox").join("session-x");
        std::fs::create_dir_all(&session).unwrap();

        let requested = session.join("fs-audit.jsonl");
        let resolved = validate_audit_sink_path(&requested, workspace).expect("accepted");

        assert_eq!(resolved.file_name().unwrap(), "fs-audit.jsonl");
        assert!(resolved.is_absolute());
    }

    /// workspace外は拒否する（**管理者権限での任意パス追記**を許さない）。
    #[test]
    fn a_path_outside_the_workspace_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path();
        std::fs::create_dir_all(workspace.join(".harness").join("sandbox")).unwrap();

        let err = validate_audit_sink_path(Path::new(r"C:\Windows\System32\evil.jsonl"), workspace)
            .unwrap_err();

        assert!(
            matches!(err, AuditSinkPathError::OutsideSandboxDir(_)),
            "{err}"
        );
    }

    /// workspace内でも`.harness/sandbox/`の外は拒否する（`.git/config`等へ書かせない）。
    #[test]
    fn a_path_inside_the_workspace_but_outside_the_sandbox_dir_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path();
        std::fs::create_dir_all(workspace.join(".harness").join("sandbox")).unwrap();

        let err = validate_audit_sink_path(&workspace.join(".git").join("config"), workspace)
            .unwrap_err();

        assert!(
            matches!(err, AuditSinkPathError::OutsideSandboxDir(_)),
            "{err}"
        );
    }

    /// `..`で外へ出ようとする経路は、解決後の前方一致で落ちる。
    #[test]
    fn a_path_escaping_with_dotdot_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path();
        let sandbox = workspace.join(".harness").join("sandbox");
        std::fs::create_dir_all(&sandbox).unwrap();

        let escaping = sandbox
            .join("..")
            .join("..")
            .join("..")
            .join("escaped.jsonl");
        let err = validate_audit_sink_path(&escaping, workspace).unwrap_err();

        assert!(
            matches!(
                err,
                AuditSinkPathError::EscapesAfterResolution(_)
                    | AuditSinkPathError::Unresolvable { .. }
            ),
            "{err}"
        );
    }

    /// 相対パスは受け付けない（基準が曖昧なまま昇格側で解決させない）。
    #[test]
    fn a_relative_path_is_rejected() {
        let dir = tempfile::tempdir().unwrap();

        let err = validate_audit_sink_path(Path::new("fs-audit.jsonl"), dir.path()).unwrap_err();

        assert!(matches!(err, AuditSinkPathError::NotAbsolute(_)), "{err}");
    }

    /// 大小の違いは同一視する（Windowsのパス比較に合わせる）。逆に、コンポーネント境界を
    /// 跨いだ前方一致（`sandbox-evil`が`sandbox`の配下に見える）は起こらない。
    #[test]
    fn comparison_is_case_insensitive_but_respects_component_boundaries() {
        let a = Path::new(r"C:\Work\.harness\sandbox\session-x");
        assert!(starts_with_ignore_case(
            a,
            Path::new(r"c:\work\.HARNESS\SANDBOX")
        ));
        assert!(!starts_with_ignore_case(
            Path::new(r"C:\Work\.harness\sandbox-evil\x"),
            Path::new(r"C:\Work\.harness\sandbox")
        ));
    }
}

#[cfg(test)]
mod elevation_target_tests {
    use super::*;

    /// 管理者・SYSTEMが書けるのは正常（昇格後の権限と同等なので、新しい権限を与えない）。
    #[test]
    fn admin_equivalent_trustees_may_hold_write_access() {
        for sid in [
            "S-1-5-32-544", // BUILTIN\Administrators
            "S-1-5-18",     // SYSTEM
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", // TrustedInstaller
        ] {
            assert!(
                !is_dangerous_trustee_grant(sid, 0x1F01FF),
                "{sid} holding full control must be accepted"
            );
        }
    }

    /// 一般ユーザー・Everyone・Authenticated Usersの書込は拒否する
    /// ——そのアカウントは昇格ヘルパーを差し替えられる（T-21）。
    #[test]
    fn non_admin_trustees_holding_write_access_are_rejected() {
        for sid in [
            "S-1-5-32-545",                                   // BUILTIN\Users
            "S-1-1-0",                                        // Everyone
            "S-1-5-11",                                       // Authenticated Users
            "S-1-5-21-1111111111-2222222222-3333333333-1001", // 具体的なユーザー
        ] {
            assert!(
                is_dangerous_trustee_grant(sid, 0x0002),
                "{sid} with FILE_WRITE_DATA must be rejected"
            );
        }
    }

    /// **BUG-048型の誤判定を起こさない**: 読み取り専用の複合マスクを書込扱いしない。
    /// `FILE_GENERIC_READ`/`FILE_GENERIC_EXECUTE`は`SYNCHRONIZE`/`READ_CONTROL`を含むので、
    /// 複合マスク同士のANDで判定すると誤爆する。
    #[test]
    fn read_only_masks_are_not_treated_as_write_access() {
        const FILE_GENERIC_READ: u32 = 0x0012_0089;
        const FILE_GENERIC_EXECUTE: u32 = 0x0012_00A0;
        const READ_CONTROL_AND_SYNCHRONIZE: u32 = 0x0002_0000 | 0x0010_0000;

        for mask in [
            FILE_GENERIC_READ,
            FILE_GENERIC_EXECUTE,
            READ_CONTROL_AND_SYNCHRONIZE,
            0x0001, // FILE_READ_DATA
            0x0080, // FILE_READ_ATTRIBUTES
        ] {
            assert!(
                !is_dangerous_trustee_grant("S-1-5-32-545", mask),
                "mask {mask:#010x} is read-only and must not be flagged"
            );
        }
    }

    /// 差し替えに繋がる個々のビットはすべて拾う（削除・DACL書換・所有者変更を含む）。
    /// ファイルを消せれば置き換えられるので、`DELETE`も「書込」と同じ扱いにする。
    #[test]
    fn every_bit_that_enables_replacement_is_flagged() {
        for (name, mask) in [
            ("FILE_WRITE_DATA", 0x0002u32),
            ("FILE_APPEND_DATA", 0x0004),
            ("FILE_WRITE_EA", 0x0010),
            ("FILE_WRITE_ATTRIBUTES", 0x0100),
            ("DELETE", 0x0001_0000),
            ("WRITE_DAC", 0x0004_0000),
            ("WRITE_OWNER", 0x0008_0000),
            ("GENERIC_ALL", 0x1000_0000),
            ("GENERIC_WRITE", 0x4000_0000),
        ] {
            assert!(
                is_dangerous_trustee_grant("S-1-5-32-545", mask),
                "{name} ({mask:#010x}) must be flagged"
            );
        }
    }

    /// 存在しないパスは`Missing`（「検査したら安全だった」と区別する）。
    #[test]
    fn a_missing_target_is_reported_as_missing() {
        let dir = tempfile::tempdir().unwrap();

        let err = check_target(&dir.path().join("no-such-helper.exe")).unwrap_err();

        assert!(matches!(err, ElevationTargetError::Missing { .. }), "{err}");
    }

    /// **この開発機のtarget/debugは必ずユーザー書込可**なので、実際に引っ掛かることを確かめる。
    /// ここが通らない（=安全と判定される）なら、継承ACEを見落としている疑いが濃い。
    #[cfg(windows)]
    #[test]
    fn the_development_build_directory_is_detected_as_user_writable() {
        let Ok(current) = std::env::current_exe() else {
            return;
        };
        let Some(dir) = current.parent() else {
            return;
        };
        // テストバイナリは`target/debug/deps/`にある。判定は「非管理者が書けるか」なので、
        // dev環境では必ずErrになるはず。
        let result = check_one(dir);
        assert!(
            result.is_err(),
            "target/debug should be user-writable on a development machine; if this passes, \
             inherited ACEs are probably being skipped (GetExplicitEntriesFromAclW trap)"
        );
    }
}
