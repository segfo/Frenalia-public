//! ホスト側に置く資格情報の生成と保護。話す相手はファイルシステムとNTFS ACL。
//!
//! Incus mTLSのクライアント証明書（`%APPDATA%\harness\config\tier3-incus-client\`）と、
//! 外層VMへのSSH鍵（同`tier3-ssh\`）。秘密鍵は`harden_private_key_acl`で所有者のみへ
//! アクセスを絞る（`ssh.exe`が緩いパーミッションの鍵を拒否するため実用上も必須）。

use super::*;

/// クライアント証明書のホスト側保存先（`%APPDATA%\harness\config\tier3-incus-client\`）。
pub(crate) fn client_cert_dir() -> Result<PathBuf, VmError> {
    directories::ProjectDirs::from("", "", "harness")
        .map(|d| d.config_dir().join("tier3-incus-client"))
        .ok_or_else(|| VmError::Io("could not resolve config dir".to_string()))
}

/// harness専用のIncus mTLSクライアント証明書を用意する（無ければ`openssl`で自己署名生成、
/// あれば再利用）。Phase 1ではこの証明書をホスト側に保持し、`VmSession::start`のたびに
/// Incusサーバーへペアリングする（ゴールデン像への焼き込みは別ラウンド、モジュールdoc参照）。
///
/// # **秘密鍵はSSH鍵と同じく締める**（[BUG-154](../../../../docs/bugs/BUG-154.md)）
///
/// モジュールdocは「秘密鍵は`harden_private_key_acl`で所有者のみへ絞る」と**両方について**
/// 書いていたが、実際に呼んでいたのは`ensure_ssh_keypair`だけだった。実マシンでは
/// この`client.key`に`%APPDATA%\harness\config\`からの継承で`CodexSandboxUsers`の
/// 読取・実行が載っており、**Incus REST APIへ認証できる秘密鍵を別のローカルグループが
/// 読める**状態だった——SSH鍵を締める理由として同じdocが名指ししている相手である。
///
/// `ssh.exe`のようにパーミッションを検査してくれる相手が居ないぶん、こちらは
/// **緩くても何の症状も出ない**。対の片方だけ締める形にしない（`B-01`）。
pub fn ensure_client_cert() -> Result<(PathBuf, PathBuf), VmError> {
    let dir = client_cert_dir()?;
    std::fs::create_dir_all(&dir)?;
    let crt = dir.join("client.crt");
    let key = dir.join("client.key");
    if crt.exists() && key.exists() {
        // 既存の鍵でも毎回締め直す（`ensure_ssh_keypair`と同じ形。過去の緩いACLの救済）。
        harden_private_key_acl(&key)?;
        return Ok((crt, key));
    }
    let status = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            &key.to_string_lossy(),
            "-out",
            &crt.to_string_lossy(),
            "-days",
            "3650",
            "-nodes",
            "-subj",
            "/CN=harness-tier3-client",
        ])
        .status()
        .map_err(|e| VmError::Io(format!("failed to spawn openssl: {e}")))?;
    if !status.success() {
        return Err(VmError::Io(format!(
            "openssl req failed with status {status:?}"
        )));
    }
    harden_private_key_acl(&key)?;
    Ok((crt, key))
}

/// harness専用のSSH鍵ペアのホスト側保存先（`%APPDATA%\harness\config\tier3-ssh\`、
/// `client_cert_dir`と同じ`ProjectDirs::config_dir()`配下）。
pub(crate) fn ssh_keypair_dir() -> Result<PathBuf, VmError> {
    directories::ProjectDirs::from("", "", "harness")
        .map(|d| d.config_dir().join("tier3-ssh"))
        .ok_or_else(|| VmError::Io("could not resolve config dir".to_string()))
}

/// Phase 2: AlmaLinux VM自体（外層ホストOS）へSNIプロキシ・nftablesを設定するための
/// ホスト制御チャネル（`plans/DESIGN-SANDBOX-VMISOLATION.md`が将来像として挙げる
/// hvsocketゲストエージェントの代わりに、SSH鍵認証で代替する。ユーザー承認済みの設計、
/// `plans/TIER1A-OPEN-ISSUES.md`項目9参照）。無ければ`ssh-keygen`で生成し、あれば再利用する。
/// 公開鍵はゴールデン像の`/root/.ssh/authorized_keys`へ焼き込み済み（実機作業）。
pub fn ensure_ssh_keypair() -> Result<PathBuf, VmError> {
    let dir = ssh_keypair_dir()?;
    std::fs::create_dir_all(&dir)?;
    let private_key = dir.join("id_ed25519");
    let public_key = dir.join("id_ed25519.pub");
    if private_key.exists() && public_key.exists() {
        // 既存鍵でも毎回ACLを締め直す（後述の罠を踏んだ既存鍵が残っている場合の救済）。
        harden_private_key_acl(&private_key)?;
        return Ok(private_key);
    }
    let status = std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", "harness-tier3", "-f"])
        .arg(&private_key)
        .status()
        .map_err(|e| VmError::Io(format!("failed to spawn ssh-keygen: {e}")))?;
    if !status.success() {
        return Err(VmError::Io(format!(
            "ssh-keygen failed with status {status:?}"
        )));
    }
    harden_private_key_acl(&private_key)?;
    Ok(private_key)
}

/// 秘密鍵ファイルのWindows ACLを本人のみへ締める（Unixの`chmod 600`相当）。
/// **実機で判明した罠**: `ssh-keygen`が作るファイルは既定で親ディレクトリのACLを継承する。
/// このマシンでは`%APPDATA%\harness\config\`の継承ACLに他ユーザー/グループ（例:
/// `CodexSandboxUsers`）への読み取り権限が含まれており、Windows版OpenSSHクライアント
/// （`C:\Windows\System32\OpenSSH\ssh.exe`）はこれを検知すると
/// `UNPROTECTED PRIVATE KEY FILE`警告を出して鍵の使用自体を拒否する（`Permission denied`）。
/// Git BashのMSYS版`ssh.exe`はこのACLチェックをしない/緩いため、bashから手動で`ssh -i`を
/// 叩いた検証では再現せず、原因特定に時間を要した。`icacls`で継承を切り本人のみに絞る。
///
/// # **2つのicaclsは「本人のみ」を作らない**（[BUG-154](../../../../docs/bugs/BUG-154.md)）
///
/// `/inheritance:r`が消すのは**継承ACE**だけ、`/grant:r`が置き換えるのは**指定した相手の
/// ACE**だけである。したがって**他人の明示ACEは2つとも素通りする**。実マシンでは
/// この鍵にAppContainer（サンドボックス）のpackage SID宛のACEが3本、明示で載っており、
/// `ssh.exe`が鍵を拒否してTier3が丸ごと起動できなくなっていた。
///
/// この関数は`ensure_ssh_keypair`から**毎起動呼ばれていた**のに、3本はそのまま残り続けた
/// ——つまり名乗っている不変条件を一度も確かめていなかった。
///
/// そこで**締めたあとに読み返し、本人以外のACEが1本でも残っていたら失敗させる**。
/// 外部コマンドの見た目の成功（終了コード0）を不変条件の成立と読まない。
pub(crate) fn harden_private_key_acl(path: &Path) -> Result<(), VmError> {
    let username = std::env::var("USERNAME")
        .map_err(|_| VmError::Io("USERNAME environment variable not set".to_string()))?;
    let status = std::process::Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r"])
        .status()
        .map_err(|e| VmError::Io(format!("failed to spawn icacls (inheritance): {e}")))?;
    if !status.success() {
        return Err(VmError::Io(format!(
            "icacls /inheritance:r failed with status {status:?}"
        )));
    }
    let status = std::process::Command::new("icacls")
        .arg(path)
        .args(["/grant:r", &format!("{username}:F")])
        .status()
        .map_err(|e| VmError::Io(format!("failed to spawn icacls (grant): {e}")))?;
    if !status.success() {
        return Err(VmError::Io(format!(
            "icacls /grant:r failed with status {status:?}"
        )));
    }
    #[cfg(windows)]
    enforce_owner_only_dacl(path)?;
    Ok(())
}

/// [`harden_private_key_acl`]の検算段。**本人のSID以外のACEを剥がし、剥がれたことを
/// 読み返して確かめる**。剥がしきれなければ`Err`で止める（fail closed）。
///
/// **消えたことと残ったことの両方を見る**——本人のACEが消えていたら`ssh.exe`は鍵を読めないので、
/// 「他人が0本」だけでは合格にしない。
#[cfg(windows)]
fn enforce_owner_only_dacl(path: &Path) -> Result<(), VmError> {
    let me = current_user_sid_string()?;

    let foreign: Vec<String> = dacl_sid_strings(path)?
        .into_iter()
        .filter(|sid| *sid != me)
        .collect();
    for sid in &foreign {
        // `/remove`は許可・拒否の両方を落とす（`/remove:g`は許可だけ）。
        let status = std::process::Command::new("icacls")
            .arg(path)
            .args(["/remove", &format!("*{sid}")])
            .status()
            .map_err(|e| VmError::Io(format!("failed to spawn icacls (remove {sid}): {e}")))?;
        if !status.success() {
            return Err(VmError::Io(format!(
                "icacls /remove *{sid} failed with status {status:?} on {}",
                path.display()
            )));
        }
    }

    // **ここが本体である。** 上のicaclsが成功を返したことではなく、実DACLがどうなったかを見る。
    let after = dacl_sid_strings(path)?;
    let still_foreign: Vec<&String> = after.iter().filter(|sid| **sid != me).collect();
    if !still_foreign.is_empty() {
        return Err(VmError::Io(format!(
            "the private key {} still grants access to {} identit(y/ies) other than the current \
             user after hardening: {:?}. ssh.exe refuses keys whose ACL is not owner-only, so \
             refusing to continue rather than failing later with `bad permissions`.",
            path.display(),
            still_foreign.len(),
            still_foreign
        )));
    }
    if !after.contains(&me) {
        return Err(VmError::Io(format!(
            "the private key {} has no ACE for the current user ({me}) after hardening; \
             ssh.exe would not be able to read it",
            path.display()
        )));
    }
    Ok(())
}

/// いまのプロセスのユーザーSIDの文字列表現。
#[cfg(windows)]
fn current_user_sid_string() -> Result<String, VmError> {
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let win32 = |what: &str, e: windows::core::Error| VmError::Io(format!("{what}: {e}"));
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|e| win32("OpenProcessToken", e))?;
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        let read = GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            len,
            &mut len,
        );
        let _ = CloseHandle(token);
        read.map_err(|e| win32("GetTokenInformation(TokenUser)", e))?;
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut sid_str = windows::core::PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut sid_str)
            .map_err(|e| win32("ConvertSidToStringSidW", e))?;
        let s = sid_str
            .to_string()
            .map_err(|e| VmError::Io(format!("the user SID is not valid utf-16: {e}")))?;
        let _ = LocalFree(HLOCAL(sid_str.0 as *mut _));
        Ok(s)
    }
}

/// `path`のDACLに載っている宛先SIDを文字列で列挙する（許可・拒否の両方）。
///
/// **知らない種類のACEが1件でもあれば`Err`にする。** 素通りさせると「本人以外は0本」という
/// 検算が、読めなかったぶんだけ嘘になる。秘密鍵ファイルに現れる種類は許可か拒否だけである。
#[cfg(windows)]
fn dacl_sid_strings(path: &Path) -> Result<Vec<String>, VmError> {
    use std::ffi::c_void;
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
    const ACCESS_DENIED_ACE_TYPE: u8 = 1;

    let wide: Vec<u16> = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        )
        .ok()
        .map_err(|e| VmError::Io(format!("GetNamedSecurityInfoW({}): {e}", path.display())))?;

        let mut out = Vec::new();
        let mut unknown: Vec<u8> = Vec::new();
        if !dacl.is_null() {
            for index in 0..(*dacl).AceCount as u32 {
                let mut ace_ptr: *mut c_void = std::ptr::null_mut();
                if GetAce(dacl, index, &mut ace_ptr).is_err() || ace_ptr.is_null() {
                    unknown.push(u8::MAX);
                    continue;
                }
                let header = &*(ace_ptr as *const ACE_HEADER);
                if header.AceType != ACCESS_ALLOWED_ACE_TYPE
                    && header.AceType != ACCESS_DENIED_ACE_TYPE
                {
                    unknown.push(header.AceType);
                    continue;
                }
                // 許可ACEと拒否ACEはSIDの位置まで同じレイアウトである。
                let ace = &*(ace_ptr as *const ACCESS_ALLOWED_ACE);
                let sid = PSID(&ace.SidStart as *const u32 as *mut c_void);
                let mut sid_str = windows::core::PWSTR::null();
                if ConvertSidToStringSidW(sid, &mut sid_str).is_ok() {
                    if let Ok(s) = sid_str.to_string() {
                        out.push(s);
                    }
                    let _ = LocalFree(HLOCAL(sid_str.0 as *mut _));
                }
            }
        }
        let _ = LocalFree(HLOCAL(sd.0));
        if !unknown.is_empty() {
            return Err(VmError::Io(format!(
                "the DACL of {} contains {} ACE(s) whose trustee could not be read (types {:?}); \
                 refusing to claim the key is owner-only",
                path.display(),
                unknown.len(),
                unknown
            )));
        }
        Ok(out)
    }
}

/// SSHの`known_hosts`書き込み先（実ファイル）。`plans/vm-spike`のホスト鍵はセッションごとに
/// 再生成される（firstboot）ため検証はしない（`StrictHostKeyChecking=no`）が、その書き込み先
/// **実機で判明した罠**: 当初Unix流に`UserKnownHostsFile=NUL`（Windowsのnullデバイス）を
/// 指定していたところ、Rustの`std::process::Command::new("ssh")`経由（＝`C:\Windows\System32\
/// OpenSSH\ssh.exe`、ネイティブWindows版OpenSSHクライアント）では書き込みに失敗し非ゼロ終了
/// していた（stderrには害の無い"Permanently added..."警告しか出ないため原因特定に時間を要した）。
/// Git BashのMSYS版`ssh.exe`（bashから直接叩いた場合に解決される別バイナリ）ではこの問題が
/// 再現しなかった——ビルドの違いにより`NUL`の扱いが異なる。実在する書き込み可能ファイルへの
/// 実パスを指定することで解消する（`tier3-ssh`ディレクトリ配下、セッションをまたいで蓄積
/// しても実害は無い——検証自体をスキップしているため単なるスクラッチファイル）。
pub(crate) fn known_hosts_file() -> Result<PathBuf, VmError> {
    let dir = ssh_keypair_dir()?;
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("known_hosts"))
}

/// **実機で判明した罠**: `guest_ip`はセッションをまたいで常に同一の固定IP
/// （`VmSandboxConfig::default`参照）だが、SSHホスト鍵はfirstbootのたびに個体ごと
/// 再生成される。`known_hosts_file()`が返す実ファイルへセッションをまたいで書き込みが
/// 蓄積されると、2セッション目以降は同一IPに対し「既知だが鍵が変わった」状態になり、
/// `StrictHostKeyChecking=no`は素通りしない（OpenSSHは「未知のホストへの初回接続」だけを
/// 許容し、MITM疑いのある「鍵が変わった」状態は無条件に拒否するため）。検証自体を最初から
/// 行わない設計（D-20/D-21）である以上、このファイルを残す理由が無いため、セッション開始の
/// たびに空へ戻す。
pub(crate) fn reset_known_hosts_file() -> Result<(), VmError> {
    let path = known_hosts_file()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(VmError::Io(e.to_string())),
    }
}

#[cfg(all(test, windows))]
mod owner_only_dacl_tests {
    use super::*;

    /// **`icacls /inheritance:r` と `/grant:r` だけでは「本人のみ」にならない。**
    ///
    /// 前者が消すのは継承ACE、後者が置き換えるのは指定した相手のACEだけなので、
    /// **他人の明示ACEはどちらも素通りする**。実マシンではこれでTier3のSSH秘密鍵に
    /// サンドボックスのACEが3本残り、`ssh.exe`が鍵を拒否してTier3が起動できなくなっていた
    /// （BUG-154）。
    ///
    /// この測定は`Everyone`（`S-1-1-0`）を明示で1本足してから締め直し、**消えたこと**と
    /// **本人のぶんが残っていること**の両方を見る（B-35）。検算段（`enforce_owner_only_dacl`）を
    /// 外すと`Everyone`が残って赤くなる。
    #[test]
    fn hardening_removes_a_foreign_explicit_ace_and_keeps_the_owner() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = dir.path().join("id_ed25519");
        std::fs::write(&key, b"not a real key").expect("seed the fake key");

        // [BUG-231] 前提の確認: 鍵のDACLに「自動継承」の印（`SE_DACL_AUTO_INHERITED`）が
        // 立っていること。印が無いと`icacls /inheritance:r`は受け継いだACEを消さず明示ACEとして
        // 残し、`%TEMP%`から受け継いだ名前に引けないSIDの`/remove`が1332で落ちる——締め直しの
        // 欠陥ではなく、試験の置き場が壊れているという意味になる。
        assert!(
            dacl_is_auto_inherited(&key),
            "precondition: the fake key under {} must carry SE_DACL_AUTO_INHERITED, otherwise \
             `icacls /inheritance:r` keeps the inherited ACEs as explicit ones and this test \
             measures the broken parent instead of the hardening. Check whether %TEMP% lost the \
             flag (docs/bugs/BUG-231.md)",
            dir.path().display()
        );

        // 明示ACEを1本足す（継承ではないので`/inheritance:r`では落ちない）。
        let granted = std::process::Command::new("icacls")
            .arg(&key)
            .args(["/grant", "*S-1-1-0:(R)"])
            .status()
            .expect("spawn icacls");
        assert!(
            granted.success(),
            "the test setup must add the Everyone ACE"
        );
        assert!(
            dacl_sid_strings(&key)
                .expect("read the dacl back")
                .iter()
                .any(|sid| sid == "S-1-1-0"),
            "the setup must actually land the foreign ACE, otherwise this test measures nothing"
        );

        harden_private_key_acl(&key).expect("hardening must succeed");

        let after = dacl_sid_strings(&key).expect("read the dacl after hardening");
        assert!(
            !after.iter().any(|sid| sid == "S-1-1-0"),
            "the foreign ACE must be gone after hardening: {after:?}"
        );
        let me = current_user_sid_string().expect("current user sid");
        assert!(
            after.contains(&me),
            "the owner must keep access, otherwise ssh.exe cannot read the key: {after:?}"
        );
    }

    /// `path`のDACLに`SE_DACL_AUTO_INHERITED`が立っているか（[BUG-231]の前提確認用）。
    fn dacl_is_auto_inherited(path: &Path) -> bool {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows::Win32::Security::{
            GetSecurityDescriptorControl, ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            SE_DACL_AUTO_INHERITED,
        };
        let wide: Vec<u16> = path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let mut sd = PSECURITY_DESCRIPTOR::default();
            GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                &mut sd,
            )
            .ok()
            .expect("read the DACL");
            let mut control: u16 = 0;
            let mut revision: u32 = 0;
            let read = GetSecurityDescriptorControl(sd, &mut control, &mut revision);
            let _ = LocalFree(HLOCAL(sd.0));
            read.expect("read the control bits");
            control & SE_DACL_AUTO_INHERITED.0 != 0
        }
    }
}
