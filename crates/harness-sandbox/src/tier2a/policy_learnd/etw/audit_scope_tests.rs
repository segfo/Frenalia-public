//! **`auditpol /resourceSACL`をAppContainerのpackage SIDへ絞れるか**の実測（`docs/STATUS.md`の項目`c`）。
//!
//! 実行:
//! ```text
//! dev-elevated-run.exe etw-audit-scope
//! ```
//!
//! # なぜこれを測るのか
//!
//! Security Audit 4656 は、ETWでは原理的に取れない`DesiredAccess`（`AccessMask`）を運ぶ
//! （`plans/etw-spike/RESULTS.md` §6.4）。しかし採用の障害が2つあった。
//!
//! 1. **購読できない** — harness自身のETWセッションへは配送されない（§13で実測・決着）。
//!    → Windows Event Log API（`wevtapi`）でSecurityログを購読すれば解決する
//! 2. **量** — Global Object Access Auditingを有効にすると**マシン上の全ファイルアクセス**が
//!    監査され、Securityログを埋めて他のセキュリティ的に重要な記録を押し流す
//!
//! 2が本命の障害である。`auditpol /resourceSACL`は`/user:<ユーザー>`を取るので、そこへ
//! **AppContainerのpackage SID**を指定できれば、監査対象が「このサンドボックスのプロセスに
//! よるアクセスだけ」に縮む。SACLはDACLと同じくトークン内のSIDと照合され、AppContainerトークンは
//! package SIDを持つので、**理屈の上では成立する**。理屈であって実測ではないので、ここで確かめる。
//!
//! # このテストはマシンの状態を変える
//!
//! 監査ポリシー（サブカテゴリ`Object Access > File System`とresourceSACL）を一時的に変更する。
//! 撤去は[`AuditPolicyGuard`]のDropで行うので**panicしても残らない**。後始末をテストの最後の行に
//! 置かないのは、途中で落ちたときに設定が残って監査ログを出し続けるのを避けるため。

use crate::shell_tier::WorkspaceWriteMode;
use crate::tier2a::win_appcontainer::{preflight, resolve_shell, spawn, NetworkCapability};

/// `Object Access > File System`サブカテゴリのGUID。**ロケール非依存で指定するため**に使う
/// （この機のauditpolは日本語で「ファイル システム」と表示する）。
const SUBCATEGORY_FILE_SYSTEM: &str = "{0CCE921D-69AE-11D9-BED3-505054503030}";

fn auditpol(args: &[&str]) -> (bool, String) {
    match std::process::Command::new("auditpol").args(args).output() {
        Ok(out) => (
            out.status.success(),
            format!(
                "{}{}",
                crate::win_common::decode_console_bytes(&out.stdout),
                crate::win_common::decode_console_bytes(&out.stderr)
            ),
        ),
        Err(e) => (false, format!("failed to run auditpol: {e}")),
    }
}

/// 監査ポリシーを必ず元へ戻すためのガード。
struct AuditPolicyGuard {
    sid: String,
    disable_failure_on_drop: bool,
}

impl Drop for AuditPolicyGuard {
    fn drop(&mut self) {
        let user = format!("/user:{}", self.sid);
        let (removed, out) = auditpol(&["/resourceSACL", "/remove", "/type:File", &user]);
        println!("[#c] cleanup: resourceSACL /remove ok={removed} {}", out.trim());
        if self.disable_failure_on_drop {
            let subcategory = format!("/subcategory:{SUBCATEGORY_FILE_SYSTEM}");
            let (ok, out) = auditpol(&["/set", &subcategory, "/failure:disable"]);
            println!("[#c] cleanup: File System failure auditing disabled ok={ok} {}", out.trim());
        }
        let (_, view) = auditpol(&["/resourceSACL", "/view", "/type:File"]);
        println!("[#c] cleanup: resourceSACL now = [{}]", view.trim());
    }
}

/// SIDを文字列化する。
fn sid_to_string(sid: windows::Win32::Security::PSID) -> String {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    unsafe {
        let mut out = windows::core::PWSTR::null();
        if ConvertSidToStringSidW(sid, &mut out).is_err() || out.is_null() {
            return String::new();
        }
        let s = out.to_string().unwrap_or_default();
        let _ = LocalFree(HLOCAL(out.0 as *mut _));
        s
    }
}

/// Securityログから、指定時刻以降の4656を読んで`ObjectName`/`AccessMask`/`ProcessId`を出す。
fn read_4656_since(unix_secs: u64) -> String {
    let script = format!(
        r#"$since=[DateTimeOffset]::FromUnixTimeSeconds({unix_secs}).LocalDateTime
$e = Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4656; StartTime=$since}} -ErrorAction SilentlyContinue
if ($null -eq $e) {{ 'COUNT=0' }} else {{
  'COUNT=' + @($e).Count
  @($e) | Select-Object -First 10 | ForEach-Object {{
    $x = [xml]$_.ToXml()
    $d = $x.Event.EventData.Data
    $obj  = ($d | Where-Object {{ $_.Name -eq 'ObjectName' }}).'#text'
    $mask = ($d | Where-Object {{ $_.Name -eq 'AccessMask' }}).'#text'
    $pid2 = ($d | Where-Object {{ $_.Name -eq 'ProcessId' }}).'#text'
    'OBJ=' + $obj + ' MASK=' + $mask + ' PID=' + $pid2
  }}
}}"#
    );
    match std::process::Command::new("pwsh")
        .args(["-NoProfile", "-Command", &script])
        .output()
    {
        Ok(out) => format!(
            "{}{}",
            crate::win_common::decode_console_bytes(&out.stdout),
            crate::win_common::decode_console_bytes(&out.stderr)
        ),
        Err(e) => format!("failed to read the Security log: {e}"),
    }
}

#[test]
#[ignore = "MODIFIES THE MACHINE AUDIT POLICY (restored on drop); run via dev-elevated-run.exe etw-audit-scope"]
fn can_global_object_access_auditing_be_scoped_to_an_appcontainer_package_sid() {
    // --- 0. 変更前の状態を退避 ---
    let (_, before_sacl) = auditpol(&["/resourceSACL", "/view", "/type:File"]);
    let subcategory = format!("/subcategory:{SUBCATEGORY_FILE_SYSTEM}");
    let (_, before_policy) = auditpol(&["/get", &subcategory]);
    println!("[#c] BEFORE resourceSACL = [{}]", before_sacl.trim());
    println!("[#c] BEFORE File System policy = [{}]", before_policy.trim());

    // --- 1. AppContainerのpackage SIDを得る ---
    let workspace = tempfile::tempdir().expect("workspace");
    let outside = tempfile::tempdir().expect("outside");
    let secret = outside.path().join("audit-scope-secret.txt");
    std::fs::write(&secret, b"secret").expect("write the secret file");

    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
    let profile = crate::tier2a::session_profile::current_profile_name();
    let sid_owned = crate::tier2a::win_appcontainer::ensure_profile(&profile).expect("package SID");
    let sid_string = sid_to_string(sid_owned.as_psid());
    println!("[#c] AppContainer package SID = {sid_string}");
    assert!(
        sid_string.starts_with("S-1-15-2-"),
        "expected an AppContainer package SID, got {sid_string:?}"
    );

    // --- 2. Q1: auditpol は package SID を受け付けるか ---
    let guard = AuditPolicyGuard {
        sid: sid_string.clone(),
        disable_failure_on_drop: true,
    };
    let user_arg = format!("/user:{sid_string}");
    let (set_ok, set_out) = auditpol(&[
        "/resourceSACL",
        "/set",
        "/type:File",
        "/failure",
        &user_arg,
        "/access:FA",
    ]);
    println!("[#c] Q1 resourceSACL /set with the package SID: ok={set_ok} [{}]", set_out.trim());
    let (_, view_after_set) = auditpol(&["/resourceSACL", "/view", "/type:File"]);
    println!("[#c] Q1 resourceSACL after set = [{}]", view_after_set.trim());

    let accepted = set_ok && view_after_set.contains(&sid_string);
    println!("[#c] Q1 RESULT: package SID accepted = {accepted}");
    if !accepted {
        println!(
            "[#c] Q1 CONCLUSION: the audit scope CANNOT be narrowed to the sandbox. Enabling 4656 \
             would audit the whole machine, polluting the Security log and pushing out other \
             security-relevant records. That settles it -- 4656 is not worth adopting."
        );
        drop(guard);
        crate::tier2a::session_profile::end_session(
            &crate::tier2a::win_appcontainer::revoke_session_grant,
        );
        return;
    }

    // --- 3. File System サブカテゴリの失敗監査を有効化 ---
    let (policy_ok, policy_out) = auditpol(&["/set", &subcategory, "/failure:enable"]);
    println!("[#c] File System failure auditing enabled: ok={policy_ok} [{}]", policy_out.trim());

    // --- 4. AppContainer子に拒否を起こさせる（読取と削除の両方） ---
    let mark = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    std::thread::sleep(std::time::Duration::from_secs(1));

    let command = format!(
        "$ErrorActionPreference='SilentlyContinue'; Get-Content -LiteralPath '{}' | Out-Null; \
         Remove-Item -LiteralPath '{}'; Write-Output done",
        secret.display(),
        secret.display()
    );
    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    let child = spawn(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", &command],
        workspace.path(),
        &env,
        false,
        sid_owned.as_psid(),
        NetworkCapability::Deny,
        None,
    )
    .expect("spawn the AppContainer child");
    let child_pid = child.pid();
    let _ = child.write_stdin_read_output_and_wait(None);
    println!("[#c] AppContainer child pid = {child_pid} (denied read + denied delete attempted)");
    std::thread::sleep(std::time::Duration::from_secs(3));

    // --- 5. Q2/Q3: 4656 が出たか / AccessMask に何が入っているか ---
    let events = read_4656_since(mark);
    println!("[#c] Q2/Q3 Security log 4656 events since the mark:");
    for line in events.lines().take(24) {
        if !line.trim().is_empty() {
            println!("[#c]   {}", line.trim());
        }
    }
    println!(
        "[#c] Q2/Q3 HOW TO READ: COUNT>0 with an ObjectName matching audit-scope-secret.txt means \
         package-SID-scoped auditing works AND 4656 delivers the AccessMask that ETW cannot. \
         A MASK containing 0x10000 (DELETE) for the Remove-Item attempt would resolve the \
         'a delete denial is proposed as fs.read' problem (RESULTS.md §12.4). \
         COUNT=0 means the SACL was accepted syntactically but does not actually match \
         AppContainer tokens -- in which case the scoping idea fails and 4656 stays unattractive."
    );

    drop(guard);
    crate::tier2a::session_profile::end_session(
        &crate::tier2a::win_appcontainer::revoke_session_grant,
    );

    // --- 6. 復旧の突き合わせ ---
    let (_, after_sacl) = auditpol(&["/resourceSACL", "/view", "/type:File"]);
    println!("[#c] AFTER resourceSACL = [{}]", after_sacl.trim());
    assert!(
        !after_sacl.contains(&sid_string),
        "the resourceSACL entry for our package SID was not removed: {after_sacl}"
    );
}
