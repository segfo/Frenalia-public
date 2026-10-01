//! RedirectionGuard（`PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY`）を**自分自身に掛けてから**、
//! 指定されたパスを読取で開くモード（`--redirection-trust <none|enforce|audit>` と
//! `--redirection-open <ラベル>:<パス>`、後者は繰り返し可）。
//!
//! # なぜ要るのか
//!
//! ハーネス自身がサンドボックスの外で行う操作（差分層の変更を本物へ戻す処理・アクセス制御リストへの書込）は、
//! サンドボックスより強い権限で動きながら、サンドボックス内のコードが書ける場所のパスを辿る。そこへ
//! ジャンクションを置かれると、本来触るはずのない場所を強い権限で書き換える恐れがある
//! （`docs/STATUS.md`の残課題 サンドボックス周辺 #68。2026-10-01に閉じたが、**この計器は残す**——
//! ハーネス側へ新しくワークスペース配下を歩く処理を足すときに、同じ問いを撃ち直すためである）。
//!
//! この緩和策は「管理者でないユーザーが作ったリパースポイントを辿らない」ことをプロセス単位で有効にする。
//! **誰が作ったリンクに効くのか・互換性を壊さないか**は測らないと分からないので、その計器である。
//!
//! # 何も書かない
//!
//! 開くのは`FILE_GENERIC_READ`だけで、開けたら閉じる。対象の中身は1バイトも変わらない。
//!
//! # 緩和策は一度掛けると外せない
//!
//! だから**このプロセス（子）に掛ける**。テスト側のプロセスに掛けると、以後の全テストに効いてしまう。
//!
//! 報告の`last_error`の読み方: `0`＝開けた、`448`（`ERROR_UNTRUSTED_MOUNT_POINT`）＝
//! 緩和策が辿るのを断った、`5`＝アクセス拒否、`2`＝見つからない。

use serde_json::{json, Value};

/// `Flags`のビット（`winnt.h`の`PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY`）。
const ENFORCE_REDIRECTION_TRUST: u32 = 0x1;
const AUDIT_REDIRECTION_TRUST: u32 = 0x2;

#[cfg(windows)]
pub fn run(mode: &str, specs: &[String]) -> Value {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GetLastError};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::SystemServices::PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY;
    use windows::Win32::System::Threading::{
        GetCurrentProcess, GetProcessMitigationPolicy, ProcessRedirectionTrustPolicy,
        SetProcessMitigationPolicy,
    };

    let requested_flags = match mode {
        "none" => 0,
        "enforce" => ENFORCE_REDIRECTION_TRUST,
        "audit" => AUDIT_REDIRECTION_TRUST,
        "enforce-audit" => ENFORCE_REDIRECTION_TRUST | AUDIT_REDIRECTION_TRUST,
        other => {
            return json!({
                "redirection_trust": { "error": format!("unknown mode {other:?}") }
            })
        }
    };

    // --- 緩和策を掛ける（`none`なら掛けない＝対照） ---
    let mut applied = true;
    let mut apply_error = 0u32;
    if requested_flags != 0 {
        let mut policy = PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY::default();
        policy.Anonymous.Flags = requested_flags;
        unsafe {
            match SetProcessMitigationPolicy(
                ProcessRedirectionTrustPolicy,
                &policy as *const _ as *const core::ffi::c_void,
                core::mem::size_of::<PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY>(),
            ) {
                Ok(()) => {}
                Err(_) => {
                    applied = false;
                    apply_error = GetLastError().0;
                }
            }
        }
    }

    // --- 読み戻す（掛かったことを別の口で確かめる。掛けたつもりで測らないため） ---
    let mut readback_flags: Option<u32> = None;
    let mut readback_error = 0u32;
    unsafe {
        let mut policy = PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY::default();
        match GetProcessMitigationPolicy(
            GetCurrentProcess(),
            ProcessRedirectionTrustPolicy,
            &mut policy as *mut _ as *mut core::ffi::c_void,
            core::mem::size_of::<PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY>(),
        ) {
            Ok(()) => readback_flags = Some(policy.Anonymous.Flags),
            Err(_) => readback_error = GetLastError().0,
        }
    }

    // --- 対象を読取で開く ---
    let mut attempts = Vec::new();
    for spec in specs {
        let Some((label, path)) = spec.split_once(':') else {
            attempts.push(json!({ "spec": spec, "error": "expected <label>:<path>" }));
            continue;
        };
        // ドライブ文字の`:`で切れないように、1文字のラベルは許さない形で呼ぶ約束にしている。
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let (ok, last_error) = unsafe {
            match CreateFileW(
                PCWSTR(wide.as_ptr()),
                FILE_GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                // ディレクトリも同じ呼び方で開くために要る。
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            ) {
                Ok(handle) => {
                    let _ = CloseHandle(handle);
                    (true, 0u32)
                }
                Err(_) => (false, GetLastError().0),
            }
        };
        attempts.push(json!({
            "label": label,
            "path": path,
            "opened": ok,
            "last_error": last_error,
        }));
    }

    json!({
        "redirection_trust": {
            "mode": mode,
            "requested_flags": requested_flags,
            "applied": applied,
            "apply_last_error": apply_error,
            "readback_flags": readback_flags,
            "readback_last_error": readback_error,
            "opens": attempts,
        }
    })
}

#[cfg(not(windows))]
pub fn run(_mode: &str, _specs: &[String]) -> Value {
    json!({ "redirection_trust": { "error": "windows only" } })
}

/// 管理者でないユーザーがシンボリックリンクを作れるかを測る（`--make-symlink <file|dir>:<リンク>:<対象>`）。
///
/// `CreateSymbolicLinkW`に`SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE`（`0x2`）を付けて呼ぶ。
/// このフラグは**開発者モードが有効なときだけ**効き、無効なら特権が要る（`ERROR_PRIVILEGE_NOT_HELD`＝1314）。
/// **作れなかったことも測定結果である**ので、失敗を報告に載せて終了コードは0のままにする。
#[cfg(windows)]
pub fn make_symlink(specs: &[String]) -> Value {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::GetLastError;
    use windows::Win32::Storage::FileSystem::{
        CreateSymbolicLinkW, SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
        SYMBOLIC_LINK_FLAG_DIRECTORY,
    };

    let mut attempts = Vec::new();
    for spec in specs {
        let parts: Vec<&str> = spec.splitn(3, '|').collect();
        if parts.len() != 3 {
            attempts.push(json!({ "spec": spec, "error": "expected <file|dir>|<link>|<target>" }));
            continue;
        }
        let (kind, link, target) = (parts[0], parts[1], parts[2]);
        let mut flags = SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE.0;
        if kind == "dir" {
            flags |= SYMBOLIC_LINK_FLAG_DIRECTORY.0;
        }
        let link_w: Vec<u16> = link.encode_utf16().chain(std::iter::once(0)).collect();
        let target_w: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();
        let (ok, last_error) = unsafe {
            let created = CreateSymbolicLinkW(
                PCWSTR(link_w.as_ptr()),
                PCWSTR(target_w.as_ptr()),
                windows::Win32::Storage::FileSystem::SYMBOLIC_LINK_FLAGS(flags),
            );
            if created.as_bool() {
                (true, 0u32)
            } else {
                (false, GetLastError().0)
            }
        };
        attempts.push(json!({
            "kind": kind,
            "link": link,
            "target": target,
            "created": ok,
            "last_error": last_error,
        }));
    }
    json!({ "make_symlink": attempts })
}

#[cfg(not(windows))]
pub fn make_symlink(_specs: &[String]) -> Value {
    json!({ "make_symlink": [], "error": "windows only" })
}

/// ジャンクション（ディレクトリのマウントポイント）を**このプロセス自身が**作る
/// （`--make-junction <リンク>|<対象>`）。
///
/// # なぜ`mklink`を呼ばずに自分で作るのか
///
/// 測りたいのは「**この**プロセスのトークンで作られたリパースポイントを、RedirectionGuardが
/// 辿らなくなるか」である。外部コマンドに作らせると、作った主体が本当にこのトークンだったかを
/// 別に確かめる必要が生まれる（AppContainerの中では`cmd.exe`が起動できるかも別の問いになる）。
///
/// `FSCTL_SET_REPARSE_POINT`へ渡す`REPARSE_DATA_BUFFER`は可変長で`windows`クレートに型が無いので、
/// バイト列を手で組む（`ntifs.h`の定義。マウントポイント用の形）。
#[cfg(windows)]
pub fn make_junction(specs: &[String]) -> Value {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GetLastError};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;
    use windows::Win32::System::IO::DeviceIoControl;

    /// `IO_REPARSE_TAG_MOUNT_POINT`（`winnt.h`）。
    const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;

    let mut attempts = Vec::new();
    for spec in specs {
        let Some((link, target)) = spec.split_once('|') else {
            attempts.push(json!({ "spec": spec, "error": "expected <link>|<target>" }));
            continue;
        };
        // リンクになるディレクトリを先に作る（空でなければならない）。
        if let Err(e) = std::fs::create_dir_all(link) {
            attempts.push(json!({
                "link": link, "target": target, "created": false,
                "stage": "create_dir", "error": e.to_string(),
            }));
            continue;
        }
        // 対象はNT形式（`\??\C:\…`）で書く。印字名は人が読む側の綴りで、そのまま入れる。
        let substitute: Vec<u16> = format!(r"\??\{target}").encode_utf16().collect();
        let print_name: Vec<u16> = target.encode_utf16().collect();
        let sub_bytes = substitute.len() * 2;
        let print_bytes = print_name.len() * 2;
        // ReparseTag(4) + ReparseDataLength(2) + Reserved(2) + 4つのu16(8) + 2つのNUL終端(4)
        let data_len = 8 + sub_bytes + 2 + print_bytes + 2;
        let mut buf: Vec<u8> = Vec::with_capacity(8 + data_len);
        buf.extend_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
        buf.extend_from_slice(&(data_len as u16).to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        buf.extend_from_slice(&0u16.to_le_bytes()); // SubstituteNameOffset
        buf.extend_from_slice(&(sub_bytes as u16).to_le_bytes()); // SubstituteNameLength
        buf.extend_from_slice(&((sub_bytes + 2) as u16).to_le_bytes()); // PrintNameOffset
        buf.extend_from_slice(&(print_bytes as u16).to_le_bytes()); // PrintNameLength
        for u in &substitute {
            buf.extend_from_slice(&u.to_le_bytes());
        }
        buf.extend_from_slice(&0u16.to_le_bytes());
        for u in &print_name {
            buf.extend_from_slice(&u.to_le_bytes());
        }
        buf.extend_from_slice(&0u16.to_le_bytes());

        let link_w: Vec<u16> = link.encode_utf16().chain(std::iter::once(0)).collect();
        let (ok, stage, last_error) = unsafe {
            match CreateFileW(
                PCWSTR(link_w.as_ptr()),
                FILE_GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            ) {
                Err(_) => (false, "open", GetLastError().0),
                Ok(handle) => {
                    let result = DeviceIoControl(
                        handle,
                        FSCTL_SET_REPARSE_POINT,
                        Some(buf.as_ptr() as *const core::ffi::c_void),
                        buf.len() as u32,
                        None,
                        0,
                        None,
                        None,
                    );
                    let err = if result.is_err() { GetLastError().0 } else { 0 };
                    let _ = CloseHandle(handle);
                    (result.is_ok(), "fsctl", err)
                }
            }
        };
        attempts.push(json!({
            "link": link, "target": target, "created": ok,
            "stage": stage, "last_error": last_error,
        }));
    }
    json!({ "make_junction": attempts })
}

#[cfg(not(windows))]
pub fn make_junction(_specs: &[String]) -> Value {
    json!({ "make_junction": [], "error": "windows only" })
}

/// ハードリンクを**このプロセス自身が**作る（`--make-hardlink <リンク>|<対象>`）。
///
/// サンドボックスの中からハードリンクを作れるかは、設計書が未測定として残していた問い
/// （`plans/DESIGN-MAC-POC.md` §20項目12）。作れなければ、許可された場所から許可されていない
/// ファイルへ別名を張る経路は成立しない。
#[cfg(windows)]
pub fn make_hardlink(specs: &[String]) -> Value {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::GetLastError;
    use windows::Win32::Storage::FileSystem::CreateHardLinkW;

    let mut attempts = Vec::new();
    for spec in specs {
        let Some((link, target)) = spec.split_once('|') else {
            attempts.push(json!({ "spec": spec, "error": "expected <link>|<target>" }));
            continue;
        };
        let link_w: Vec<u16> = link.encode_utf16().chain(std::iter::once(0)).collect();
        let target_w: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();
        let (ok, last_error) = unsafe {
            match CreateHardLinkW(PCWSTR(link_w.as_ptr()), PCWSTR(target_w.as_ptr()), None) {
                Ok(()) => (true, 0u32),
                Err(_) => (false, GetLastError().0),
            }
        };
        attempts.push(json!({
            "link": link, "target": target, "created": ok, "last_error": last_error,
        }));
    }
    json!({ "make_hardlink": attempts })
}

#[cfg(not(windows))]
pub fn make_hardlink(_specs: &[String]) -> Value {
    json!({ "make_hardlink": [], "error": "windows only" })
}

/// アクセス制御リストを**読んでそのまま書き戻す**（`--write-dacl <パス>`、繰り返し可）。
///
/// # 何のための計器か
///
/// 管理者権限で動く`harness-privhelper.exe`は、ユーザーが`--fs-allow`で指定したパスへ
/// `SetNamedSecurityInfoW`でアクセス制御リストを書く。**この関数はパスを辿る**ので、
/// RedirectionGuardを掛けたときに、リンクを含むパスへ書けなくなるかを測る必要がある
/// （`docs/STATUS.md`の残課題 サンドボックス周辺 #68の多層防御）。
///
/// # 対象は1ビットも変わらない
///
/// 読んだ内容をそのまま書き戻すので、成功しても中身は変わらない。権限を足して消す形にすると、
/// 途中で落ちたときに足したものが残る（`harness-sandbox`の`can_write_dacl`と同じ理由）。
///
/// `last_error`の読み方: `0`＝書けた、`448`（`ERROR_UNTRUSTED_MOUNT_POINT`）＝
/// RedirectionGuardが辿るのを断った、`5`＝アクセス拒否。
#[cfg(windows)]
pub fn write_dacl_identity(paths: &[String]) -> Value {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{GetLastError, LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

    let mut attempts = Vec::new();
    for path in paths {
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let (read_ok, read_error, wrote, write_error) = unsafe {
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            let read = GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                &mut descriptor,
            );
            if read.is_err() {
                (false, read.0, false, 0u32)
            } else {
                let write = SetNamedSecurityInfoW(
                    PCWSTR(wide.as_ptr()),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    None,
                    None,
                    Some(dacl),
                    None,
                );
                let werr = if write.is_err() { write.0 } else { 0 };
                let _ = LocalFree(HLOCAL(descriptor.0));
                (true, 0, write.is_ok(), werr)
            }
        };
        let _ = GetLastError;
        attempts.push(json!({
            "path": path,
            "read_ok": read_ok,
            "read_last_error": read_error,
            "wrote": wrote,
            "write_last_error": write_error,
        }));
    }
    json!({ "write_dacl": attempts })
}

#[cfg(not(windows))]
pub fn write_dacl_identity(_paths: &[String]) -> Value {
    json!({ "write_dacl": [], "error": "windows only" })
}
