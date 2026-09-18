//! **MAC/Spawn Daemon設計 §20項目1の実現性スパイク専用モード**（`plans/mac-spike/RESULTS.md`）。
//!
//! `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY` +
//! `PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`を積んで起動されたAppContainer子から、
//! **プロセス生成のあらゆる経路**を1つずつ試し、どれが拒否されるかを報告する。
//! 設計書§9「User-mode Hookをセキュリティ境界にしない」は
//! 「フックを迂回してもカーネルが拒否する」という前提の上に立っており、その前提が
//! 実機で成立するかはこのリポジトリで一度も測られていない。
//!
//! ## 測る経路
//!
//! | 経路 | 何を確かめるか |
//! |---|---|
//! | `createprocessw` / `createprocessa` / `winexec` / `createprocessasuserw` | kernel32の通常経路 |
//! | `shellexecuteexw` | シェル経由（`try_runas`の非昇格版） |
//! | `ntcreateuserprocess` | **kernel32のフックを越えてntdllを直接叩く**（x64のみ、下記） |
//! | `wmi` | **ブローカー生成**: 生成者が`WmiPrvSE.exe`になるので、mitigationは原理的に効かない |
//! | `taskscheduler` | 同上（生成者が`svchost`のスケジューラサービスになる） |
//!
//! ブローカー生成の2つは、mitigationの効かない**既知のクラス**である。したがってここで
//! 効いているのはmitigationではなく「AppContainerからそのRPC/COMサーバへ到達できるか」で
//! あり、それこそが未測定の点である。
//!
//! ## 判定は「API が成功したか」ではなく**マーカーファイルの有無**で行う（B-25）
//!
//! 各経路は`cmd.exe /c echo <method>> <marker_dir>\<method>.txt`を起動しようとする。
//! **実際に子が動いたかどうかはドライバ側がマーカーファイルの有無で測る**——
//! `WinExec`のように生成の成否をまともに返さないAPIがあり、APIの戻り値だけでは
//! 「拒否された」と「起動して何もしなかった」を区別できないためである。
//!
//! ## `taskscheduler`は**このプロセスを落とす**（OS内部の欠陥。撃ち方を分けること）
//!
//! `taskscheduler`の`CoCreateInstance`は、AppContainerの中で`combase.dll`→`ntdll.dll`の
//! ヒープ経路を壊す（`ntdll.dll+0x41ebd`で読みのアクセス違反。両腕で同一。
//! 計測は`plans/mac-spike/RESULTS.md`§S61、撃ち直しは`dev-elevated-run.exe spawn-daemon-pageheap`）。
//! **OS内部の欠陥なので、こちら側では直せない。**
//!
//! ```text
//!   8経路を1回で撃つ  : taskschedulerで落ちる → **他の7経路の報告まで失われる**
//!                       しかも7経路の結果は「最後にヒープが壊れたプロセス」の産物になる
//!   経路を分けて撃つ  : 7経路の回は壊れる経路に一度も触れない → 報告が残り、素性も綺麗
//! ```
//!
//! **だから、報告（標準出力のJSON）を読みたい測定は[`run_selected`]で経路を分けて撃つこと。**
//! [`run`]（全部）を使うのは、落ちること自体を測りたいときだけである。
//! `taskscheduler`だけを撃つ回は落ちる前提で、**足跡（`starting taskscheduler`）と
//! マーカーの有無**で判定する——報告に合否を預けない。
//!
//! ## このモードは制限あり／制限なしの**両方**で回す（B-35）
//!
//! 拒否側のassertだけでは、機構が効いているのか**プローブ自身が壊れている**のかを
//! 区別できない。特に`ntcreateuserprocess`は未文書構造体を手で組むので、実装を誤れば
//! 制限の有無に関わらず失敗する。ドライバは同じプローブを制限なしでも起動し、
//! 「制限なしでは成功する経路が、制限ありでは失敗する」という**差**だけを結論に使う。

use serde_json::{json, Value};

/// 測る経路の名前。マーカーファイル名にもなる（ドライバはこの名前で有無を数える）。
pub const METHODS: &[&str] = &[
    "createprocessw",
    "createprocessa",
    "winexec",
    "createprocessasuserw",
    "shellexecuteexw",
    "ntcreateuserprocess",
    "wmi",
    "taskscheduler",
];

#[cfg(windows)]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `cmd.exe`の絶対パス。AppContainerからストアアプリの実行エイリアスを踏まないよう、
/// `SystemRoot`から組み立てる（`resolve_shell`が同じ理由で`System32`の実体を使う）。
#[cfg(windows)]
fn cmd_exe() -> String {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    format!("{system_root}\\System32\\cmd.exe")
}

/// その経路が起動を試みるコマンドライン（マーカーを1つ書くだけ）。
#[cfg(windows)]
fn marker_command(marker_dir: &str, method: &str) -> String {
    format!(
        "\"{}\" /c echo {method}> \"{marker_dir}\\{method}.txt\"",
        cmd_exe()
    )
}

/// `cmd.exe`へ渡す引数だけ（`ShellExecuteExW`・WMI・タスクスケジューラ用）。
#[cfg(windows)]
fn marker_args(marker_dir: &str, method: &str) -> String {
    format!("/c echo {method}> \"{marker_dir}\\{method}.txt\"")
}

#[cfg(windows)]
fn report(method: &str, api_ok: bool, last_error: u32, detail: impl Into<String>) -> Value {
    json!({
        "method": method,
        "api_ok": api_ok,
        "last_error": last_error,
        "detail": detail.into(),
    })
}

/// 生成に成功してしまった子の後始末。マーカーを書き終えるだけの時間（最大3秒）待ってから、
/// 生きていれば終了させる。**待つのは「制限なし」の対照実行でマーカーが確実に生まれるため**で、
/// ここを省くとドライバ側の実効判定が競合で揺れる。
#[cfg(windows)]
unsafe fn settle_child(process: windows::Win32::Foundation::HANDLE) {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
    unsafe {
        let _ = WaitForSingleObject(process, 3000);
        let _ = TerminateProcess(process, 1);
        let _ = CloseHandle(process);
    }
}

#[cfg(windows)]
fn via_create_process_w(marker_dir: &str) -> Value {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, GetLastError};
    use windows::Win32::System::Threading::{
        CreateProcessW, CREATE_NO_WINDOW, PROCESS_INFORMATION, STARTUPINFOW,
    };

    let mut cmdline = wide(&marker_command(marker_dir, "createprocessw"));
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut info = PROCESS_INFORMATION::default();
    let result = unsafe {
        CreateProcessW(
            None,
            PWSTR(cmdline.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_NO_WINDOW,
            None,
            None,
            &startup,
            &mut info,
        )
    };
    match result {
        Ok(()) => {
            unsafe {
                let _ = CloseHandle(info.hThread);
                settle_child(info.hProcess);
            }
            report("createprocessw", true, 0, "child created")
        }
        Err(e) => report(
            "createprocessw",
            false,
            unsafe { GetLastError() }.0,
            e.to_string(),
        ),
    }
}

#[cfg(windows)]
fn via_create_process_a(marker_dir: &str) -> Value {
    use windows::core::{PCSTR, PSTR};
    use windows::Win32::Foundation::{CloseHandle, GetLastError};
    use windows::Win32::System::Threading::{
        CreateProcessA, CREATE_NO_WINDOW, PROCESS_INFORMATION, STARTUPINFOA,
    };

    let mut cmdline: Vec<u8> = marker_command(marker_dir, "createprocessa")
        .bytes()
        .chain(std::iter::once(0))
        .collect();
    let startup = STARTUPINFOA {
        cb: std::mem::size_of::<STARTUPINFOA>() as u32,
        ..Default::default()
    };
    let mut info = PROCESS_INFORMATION::default();
    let result = unsafe {
        CreateProcessA(
            PCSTR::null(),
            PSTR(cmdline.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_NO_WINDOW,
            None,
            PCSTR::null(),
            &startup,
            &mut info,
        )
    };
    match result {
        Ok(()) => {
            unsafe {
                let _ = CloseHandle(info.hThread);
                settle_child(info.hProcess);
            }
            report("createprocessa", true, 0, "child created")
        }
        Err(e) => report(
            "createprocessa",
            false,
            unsafe { GetLastError() }.0,
            e.to_string(),
        ),
    }
}

#[cfg(windows)]
fn via_win_exec(marker_dir: &str) -> Value {
    use windows::core::PCSTR;
    use windows::Win32::System::Threading::WinExec;

    let mut cmdline: Vec<u8> = marker_command(marker_dir, "winexec")
        .bytes()
        .chain(std::iter::once(0))
        .collect();
    // `WinExec`はプロセスハンドルを返さないので、マーカーが書かれる猶予をここで取る
    // （返り値>31が成功の慣習だが、実効判定はドライバのマーカー検査）。
    let code = unsafe { WinExec(PCSTR(cmdline.as_mut_ptr()), 0) };
    std::thread::sleep(std::time::Duration::from_millis(1500));
    report(
        "winexec",
        code > 31,
        if code > 31 { 0 } else { code },
        format!("WinExec returned {code}"),
    )
}

/// 自プロセスのトークンをprimaryとして複製し、`CreateProcessAsUserW`で起動する。
/// 通常は`SeAssignPrimaryTokenPrivilege`が要るので失敗する見込みだが、**失敗の理由が
/// 特権不足なのかmitigationなのか**を区別するために制限なし側の対照と突き合わせる。
#[cfg(windows)]
fn via_create_process_as_user_w(marker_dir: &str) -> Value {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
    use windows::Win32::Security::{
        DuplicateTokenEx, SecurityImpersonation, TokenPrimary, TOKEN_ALL_ACCESS,
    };
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, GetCurrentProcess, OpenProcessToken, CREATE_NO_WINDOW,
        PROCESS_INFORMATION, STARTUPINFOW,
    };

    let mut token = HANDLE::default();
    if let Err(e) = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut token) } {
        return report(
            "createprocessasuserw",
            false,
            unsafe { GetLastError() }.0,
            format!("OpenProcessToken: {e}"),
        );
    }
    let mut primary = HANDLE::default();
    let dup = unsafe {
        DuplicateTokenEx(
            token,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut primary,
        )
    };
    unsafe {
        let _ = CloseHandle(token);
    }
    if let Err(e) = dup {
        return report(
            "createprocessasuserw",
            false,
            unsafe { GetLastError() }.0,
            format!("DuplicateTokenEx: {e}"),
        );
    }

    let mut cmdline = wide(&marker_command(marker_dir, "createprocessasuserw"));
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut info = PROCESS_INFORMATION::default();
    let result = unsafe {
        CreateProcessAsUserW(
            primary,
            None,
            PWSTR(cmdline.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_NO_WINDOW,
            None,
            None,
            &startup,
            &mut info,
        )
    };
    let out = match result {
        Ok(()) => {
            unsafe {
                let _ = CloseHandle(info.hThread);
                settle_child(info.hProcess);
            }
            report("createprocessasuserw", true, 0, "child created")
        }
        Err(e) => report(
            "createprocessasuserw",
            false,
            unsafe { GetLastError() }.0,
            e.to_string(),
        ),
    };
    unsafe {
        let _ = CloseHandle(primary);
    }
    out
}

/// `try_runas`の**非昇格版**（`lpVerb`を`open`にする）。シェル経由の生成が
/// mitigationの下でどう見えるかを測る。
#[cfg(windows)]
fn via_shell_execute_ex_w(marker_dir: &str) -> Value {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GetLastError};
    use windows::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    };
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let verb_w = wide("open");
    let file_w = wide(&cmd_exe());
    let params_w = wide(&marker_args(marker_dir, "shellexecuteexw"));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI,
        lpVerb: PCWSTR(verb_w.as_ptr()),
        lpFile: PCWSTR(file_w.as_ptr()),
        lpParameters: PCWSTR(params_w.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    let ok = unsafe { ShellExecuteExW(&mut info) };
    if let Err(e) = ok {
        return report(
            "shellexecuteexw",
            false,
            unsafe { GetLastError() }.0,
            e.to_string(),
        );
    }
    // packed構造体のフィールドを直接借用しない（i686でE0793、`try_runas`と同じ理由）。
    let h_process = info.hProcess;
    if !h_process.is_invalid() {
        unsafe { settle_child(h_process) };
    } else {
        std::thread::sleep(std::time::Duration::from_millis(1500));
        unsafe {
            let _ = CloseHandle(h_process);
        }
    }
    report("shellexecuteexw", true, 0, "ShellExecuteExW returned Ok")
}

/// `ntdll!NtCreateUserProcess`を直接呼ぶ（kernel32のフックを越える経路）。
///
/// **x64専用**。`PS_CREATE_INFO`はアーキテクチャごとにサイズが違い、カーネルは
/// `Size`フィールドを厳密に検査する。x86（WOW64）版の正しいサイズを推測で書くと
/// 「拒否された」と「構造体が壊れている」を取り違えるので、x86では**実装していない**と
/// 明示的に報告する（設計上のspawn経路はx64である）。
#[cfg(all(windows, target_arch = "x86_64"))]
fn via_nt_create_user_process(marker_dir: &str) -> Value {
    use std::ffi::c_void;
    use windows::core::PCSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    /// `PS_CREATE_INFO`（x64で0x58バイト: Size 8 + State 4 + pad 4 + union 72）。
    /// union部分は使わないのでゼロのバイト列として持つ。
    #[repr(C)]
    struct PsCreateInfo {
        size: usize,
        state: u32,
        _pad: u32,
        union_area: [u8; 72],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct PsAttribute {
        attribute: usize,
        size: usize,
        value: usize,
        return_length: *mut usize,
    }

    #[repr(C)]
    struct PsAttributeList {
        total_length: usize,
        attributes: [PsAttribute; 1],
    }

    /// `PS_ATTRIBUTE_IMAGE_NAME`。これだけが必須の属性である。
    const PS_ATTRIBUTE_IMAGE_NAME: usize = 0x2_0005;
    const PROCESS_ALL: u32 = 0x1FFFFF;

    type RtlCreateProcessParametersEx = unsafe extern "system" fn(
        *mut *mut c_void,
        *const UnicodeString,
        *const UnicodeString,
        *const UnicodeString,
        *const UnicodeString,
        *mut c_void,
        *const UnicodeString,
        *const UnicodeString,
        *const UnicodeString,
        *const UnicodeString,
        u32,
    ) -> i32;
    type NtCreateUserProcess = unsafe extern "system" fn(
        *mut HANDLE,
        *mut HANDLE,
        u32,
        u32,
        *const c_void,
        *const c_void,
        u32,
        u32,
        *mut c_void,
        *mut PsCreateInfo,
        *mut PsAttributeList,
    ) -> i32;

    fn unicode_string(buf: &mut Vec<u16>) -> UnicodeString {
        // 末尾のNULは`Length`に含めない（`MaximumLength`には含める）のがNTの約束。
        let chars = buf.len().saturating_sub(1);
        UnicodeString {
            length: (chars * 2) as u16,
            maximum_length: (buf.len() * 2) as u16,
            buffer: buf.as_mut_ptr(),
        }
    }

    unsafe {
        let ntdll = match GetModuleHandleA(PCSTR(c"ntdll.dll".as_ptr() as *const u8)) {
            Ok(h) => h,
            Err(e) => {
                return report(
                    "ntcreateuserprocess",
                    false,
                    0,
                    format!("GetModuleHandleA(ntdll): {e}"),
                )
            }
        };
        let Some(create_params) = GetProcAddress(
            ntdll,
            PCSTR(c"RtlCreateProcessParametersEx".as_ptr() as *const u8),
        ) else {
            return report(
                "ntcreateuserprocess",
                false,
                0,
                "GetProcAddress(RtlCreateProcessParametersEx) failed",
            );
        };
        let Some(create_process) =
            GetProcAddress(ntdll, PCSTR(c"NtCreateUserProcess".as_ptr() as *const u8))
        else {
            return report(
                "ntcreateuserprocess",
                false,
                0,
                "GetProcAddress(NtCreateUserProcess) failed",
            );
        };
        let create_params: RtlCreateProcessParametersEx = std::mem::transmute(create_params);
        let create_process: NtCreateUserProcess = std::mem::transmute(create_process);

        let mut nt_image = wide(&format!("\\??\\{}", cmd_exe()));
        let mut dos_image = wide(&cmd_exe());
        let mut cmdline = wide(&marker_command(marker_dir, "ntcreateuserprocess"));
        let mut cwd = wide(&format!(
            "{}\\System32\\",
            std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string())
        ));

        let image_us = unicode_string(&mut dos_image);
        let cmdline_us = unicode_string(&mut cmdline);
        let cwd_us = unicode_string(&mut cwd);

        let mut params: *mut c_void = std::ptr::null_mut();
        // Flags=1（RTL_USER_PROC_PARAMS_NORMALIZED）: 正規化済みのポインタで渡す。
        let status = create_params(
            &mut params,
            &image_us,
            std::ptr::null(),
            &cwd_us,
            &cmdline_us,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            1,
        );
        if status < 0 || params.is_null() {
            return report(
                "ntcreateuserprocess",
                false,
                status as u32,
                format!("RtlCreateProcessParametersEx returned {status:#x}"),
            );
        }

        let nt_image_us = unicode_string(&mut nt_image);
        let mut attributes = PsAttributeList {
            total_length: std::mem::size_of::<PsAttributeList>(),
            attributes: [PsAttribute {
                attribute: PS_ATTRIBUTE_IMAGE_NAME,
                size: nt_image_us.length as usize,
                value: nt_image_us.buffer as usize,
                return_length: std::ptr::null_mut(),
            }],
        };
        let mut create_info = PsCreateInfo {
            size: std::mem::size_of::<PsCreateInfo>(),
            state: 0, // PsCreateInitialState
            _pad: 0,
            union_area: [0u8; 72],
        };
        let mut process = HANDLE::default();
        let mut thread = HANDLE::default();
        let status = create_process(
            &mut process,
            &mut thread,
            PROCESS_ALL,
            PROCESS_ALL,
            std::ptr::null(),
            std::ptr::null(),
            0,
            0,
            params,
            &mut create_info,
            &mut attributes,
        );
        if status < 0 {
            return report(
                "ntcreateuserprocess",
                false,
                status as u32,
                format!("NtCreateUserProcess returned {status:#x}"),
            );
        }
        let _ = CloseHandle(thread);
        settle_child(process);
        report(
            "ntcreateuserprocess",
            true,
            0,
            "NtCreateUserProcess succeeded",
        )
    }
}

#[cfg(all(windows, not(target_arch = "x86_64")))]
fn via_nt_create_user_process(_marker_dir: &str) -> Value {
    report(
        "ntcreateuserprocess",
        false,
        0,
        "not implemented for this architecture (PS_CREATE_INFO layout differs; see module doc)",
    )
}

/// **ブローカー生成その1**: WMIの`Win32_Process.Create`。
///
/// 成功すると子を作るのは`WmiPrvSE.exe`であり、呼び出し元のmitigationは効かない。
/// したがってここで問うているのは「AppContainerからWMIへ到達できるか」である。
/// 到達の各段（COM活性化 → `ConnectServer` → `ExecMethod`）を別々に報告する
/// ——どこで止まったかが分からないと、次に塞ぐ場所が決まらない。
#[cfg(windows)]
fn via_wmi(marker_dir: &str) -> Value {
    use windows::core::{BSTR, PCWSTR, VARIANT};
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoSetProxyBlanket, CLSCTX_INPROC_SERVER,
        COINIT_MULTITHREADED, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
    };
    use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
    use windows::Win32::System::Wmi::{
        IWbemClassObject, IWbemLocator, IWbemServices, WbemLocator, WBEM_FLAG_RETURN_WBEM_COMPLETE,
    };

    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        let locator: IWbemLocator = match CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)
        {
            Ok(l) => l,
            Err(e) => {
                return report(
                    "wmi",
                    false,
                    e.code().0 as u32,
                    format!("stage=CoCreateInstance(WbemLocator): {e}"),
                )
            }
        };
        let services: IWbemServices = match locator.ConnectServer(
            &BSTR::from("ROOT\\CIMV2"),
            &BSTR::new(),
            &BSTR::new(),
            &BSTR::new(),
            0,
            &BSTR::new(),
            None,
        ) {
            Ok(s) => s,
            Err(e) => {
                return report(
                    "wmi",
                    false,
                    e.code().0 as u32,
                    format!("stage=ConnectServer: {e}"),
                )
            }
        };
        if let Err(e) = CoSetProxyBlanket(
            &services,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            None,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        ) {
            return report(
                "wmi",
                false,
                e.code().0 as u32,
                format!("stage=CoSetProxyBlanket: {e}"),
            );
        }

        let mut class_obj: Option<IWbemClassObject> = None;
        if let Err(e) = services.GetObject(
            &BSTR::from("Win32_Process"),
            WBEM_FLAG_RETURN_WBEM_COMPLETE,
            None,
            Some(&mut class_obj),
            None,
        ) {
            return report(
                "wmi",
                false,
                e.code().0 as u32,
                format!("stage=GetObject(Win32_Process): {e}"),
            );
        }
        let Some(class_obj) = class_obj else {
            return report("wmi", false, 0, "stage=GetObject returned no object");
        };

        let mut in_signature: Option<IWbemClassObject> = None;
        let mut out_signature: Option<IWbemClassObject> = None;
        let name = wide("Create");
        if let Err(e) = class_obj.GetMethod(
            PCWSTR(name.as_ptr()),
            0,
            &mut in_signature,
            &mut out_signature,
        ) {
            return report(
                "wmi",
                false,
                e.code().0 as u32,
                format!("stage=GetMethod(Create): {e}"),
            );
        }
        let Some(in_signature) = in_signature else {
            return report("wmi", false, 0, "stage=GetMethod returned no in-signature");
        };
        let in_params = match in_signature.SpawnInstance(0) {
            Ok(p) => p,
            Err(e) => {
                return report(
                    "wmi",
                    false,
                    e.code().0 as u32,
                    format!("stage=SpawnInstance: {e}"),
                )
            }
        };
        let command_line = VARIANT::from(marker_command(marker_dir, "wmi").as_str());
        let prop = wide("CommandLine");
        if let Err(e) = in_params.Put(PCWSTR(prop.as_ptr()), 0, &command_line, 0) {
            return report(
                "wmi",
                false,
                e.code().0 as u32,
                format!("stage=Put(CommandLine): {e}"),
            );
        }

        let mut out_params: Option<IWbemClassObject> = None;
        if let Err(e) = services.ExecMethod(
            &BSTR::from("Win32_Process"),
            &BSTR::from("Create"),
            Default::default(),
            None,
            &in_params,
            Some(&mut out_params),
            None,
        ) {
            return report(
                "wmi",
                false,
                e.code().0 as u32,
                format!("stage=ExecMethod: {e}"),
            );
        }
        // マーカーが書かれる猶予（生成はWmiPrvSE側で非同期に進む）。
        std::thread::sleep(std::time::Duration::from_millis(2000));
        report("wmi", true, 0, "stage=ExecMethod returned Ok")
    }
}

/// **ブローカー生成その2**: タスクスケジューラ。
///
/// **到達性の段までしか測っていない**（`CoCreateInstance` → `ITaskService::Connect`）。
/// ここが失敗するなら経路として閉じているので結論は出る。**成功した場合はこのプローブでは
/// 結論を出せない**ので、ドライバ側は「タスク登録まで実装してから判定せよ」と言って
/// 落ちる（fail-closed。到達できるのに「生成できない」と書かないため）。
#[cfg(windows)]
fn via_task_scheduler(_marker_dir: &str) -> Value {
    use windows::core::VARIANT;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
    };
    use windows::Win32::System::TaskScheduler::{ITaskService, TaskScheduler};

    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        let service: ITaskService =
            match CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) {
                Ok(s) => s,
                Err(e) => {
                    return report(
                        "taskscheduler",
                        false,
                        e.code().0 as u32,
                        format!("stage=CoCreateInstance(TaskScheduler): {e}"),
                    )
                }
            };
        match service.Connect(
            &VARIANT::default(),
            &VARIANT::default(),
            &VARIANT::default(),
            &VARIANT::default(),
        ) {
            Ok(()) => report(
                "taskscheduler",
                true,
                0,
                "stage=Connect succeeded (reachability only; task registration NOT implemented)",
            ),
            Err(e) => report(
                "taskscheduler",
                false,
                e.code().0 as u32,
                format!("stage=Connect: {e}"),
            ),
        }
    }
}

/// 経路の名前と実装を**1つの表**で持つ。
///
/// 名前の配列と実装の配列を添字で突き合わせると、片方だけ並べ替えたときに
/// **別の経路の名前で報告する**形になり、コンパイラは何も言わない（`B-05`）。
/// 1経路の実装。マーカー置き場を受けて、その経路の報告を返す。
#[cfg(windows)]
type MethodFn = fn(&str) -> Value;

#[cfg(windows)]
fn method_table() -> Vec<(&'static str, MethodFn)> {
    vec![
        ("createprocessw", via_create_process_w as MethodFn),
        ("createprocessa", via_create_process_a),
        ("winexec", via_win_exec),
        ("createprocessasuserw", via_create_process_as_user_w),
        ("shellexecuteexw", via_shell_execute_ex_w),
        ("ntcreateuserprocess", via_nt_create_user_process),
        ("wmi", via_wmi),
        ("taskscheduler", via_task_scheduler),
    ]
}

/// **プロセスごと落ちることが分かっている経路**（残課題#52改め`plans/mac-spike/RESULTS.md`§S61）。
///
/// `taskscheduler`の`CoCreateInstance`はAppContainerの中で`combase.dll`→`ntdll.dll`の
/// ヒープ経路を壊す。**OS内部の欠陥で、こちら側では直せない。**
/// だから**同じ回で他の経路と一緒に撃たない**——落ちると他の7経路の報告まで失われるうえ、
/// それらの結果が「最後にヒープが壊れたプロセス」の産物になってしまう。
#[cfg(windows)]
pub const CRASHES_THE_PROBE: &[&str] = &["taskscheduler"];

/// 指定された経路だけを順に試し、`{"marker_dir", "attempts": [...]}`を返す。
///
/// # 1本ごとに標準エラーへ出す（2026-09-17）
///
/// 報告は**最後にまとめて**標準出力へ出るので、途中でこのプロセスが落ちると
/// **何も残らない**。`eprintln!`は行ごとに出るので、**どこまで進んだか**が落ちた後でも
/// 読める（`B-10`: 失敗を黙らせない）。実際にこの足跡が§S61で犯人を指した。
///
/// # 知らない名前が来たら**1本も走らせない**
///
/// 綴りを間違えた指定を黙って無視すると、「その経路は拒否された」と読める報告が出る。
/// `unknown_methods`へ入れて、`attempts`は空で返す（fail-closed）。
#[cfg(windows)]
pub fn run_selected(marker_dir: &str, requested: &[String]) -> Value {
    let table = method_table();
    let unknown: Vec<&String> = requested
        .iter()
        .filter(|name| !table.iter().any(|(known, _)| *known == name.as_str()))
        .collect();
    if !unknown.is_empty() {
        eprintln!("[spawn-matrix] unknown methods: {unknown:?} (nothing was attempted)");
        return json!({
            "marker_dir": marker_dir,
            "pid": std::process::id(),
            "attempts": [],
            "methods_missing": requested,
            "unknown_methods": unknown,
        });
    }

    // **落とす経路が混ざっていることを先に言う。** 報告が出ないまま終わった回に、
    // 「なぜ消えたのか」が足跡だけで読めるようにするため（`B-10`: 失敗を黙らせない）。
    for crashing in CRASHES_THE_PROBE {
        if requested.iter().any(|r| r == crashing) {
            eprintln!(
                "[spawn-matrix] note: {crashing} crashes this process inside the OS \
                 (see plans/mac-spike/RESULTS.md S61); the report may never be printed"
            );
        }
    }

    let mut attempts = Vec::new();
    for (name, attempt) in table
        .iter()
        .filter(|(name, _)| requested.iter().any(|r| r == name))
    {
        eprintln!("[spawn-matrix] starting {name}");
        let value = attempt(marker_dir);
        eprintln!("[spawn-matrix] finished {name}: {value}");
        attempts.push(value);
    }
    // **頼まれた経路を全部試したか**を自分で検算する——1つ落としても実行時には何も
    // 起きず、ドライバ側では「その経路は拒否された」に見えてしまうため。
    let missing: Vec<&String> = requested
        .iter()
        .filter(|method| {
            !attempts
                .iter()
                .any(|a| a.get("method").and_then(Value::as_str) == Some(method.as_str()))
        })
        .collect();
    json!({
        "marker_dir": marker_dir,
        "pid": std::process::id(),
        "requested": requested,
        "attempts": attempts,
        "methods_missing": missing,
        "unknown_methods": [],
    })
}

/// 宣言された経路を**全部**試す。
///
/// **`taskscheduler`を含むので、この呼び方は落ちうる**（[`CRASHES_THE_PROBE`]）。
/// 報告を読みたい測定は[`run_selected`]で経路を分けて撃つこと。
#[cfg(windows)]
pub fn run(marker_dir: &str) -> Value {
    let all: Vec<String> = METHODS.iter().map(|m| (*m).to_string()).collect();
    run_selected(marker_dir, &all)
}

#[cfg(not(windows))]
pub fn run(marker_dir: &str) -> Value {
    json!({"marker_dir": marker_dir, "attempts": [], "error": "windows-only"})
}

#[cfg(not(windows))]
pub fn run_selected(marker_dir: &str, _requested: &[String]) -> Value {
    run(marker_dir)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// **宣言した名前と、実際に走る表が一致すること。**
    ///
    /// ドライバ側はこの名前でマーカーを数えるので、ずれると「その経路は拒否された」に
    /// 見える（`B-05`: 別々に持つ綴りはコンパイラが見張らない）。
    #[test]
    fn the_declared_names_and_the_table_agree() {
        let table: Vec<&str> = method_table().iter().map(|(name, _)| *name).collect();
        assert_eq!(table, METHODS.to_vec());
    }

    /// **落とす経路は、宣言した名前の中に在ること。** 綴りが違うと「分けて撃つ」が
    /// 効かず、分けたつもりで全部撃つことになる。
    #[test]
    fn the_crashing_method_is_one_of_the_declared_ones() {
        for name in CRASHES_THE_PROBE {
            assert!(METHODS.contains(name), "{name} is not declared");
        }
    }

    /// **知らない名前は1本も走らせない**（fail-closed）。黙って無視すると、
    /// 「その経路は拒否された」と読める報告が出る。
    #[test]
    fn an_unknown_method_name_runs_nothing() {
        let report = run_selected("C:\nowhere", &["nosuchmethod".to_string()]);
        assert_eq!(report["attempts"].as_array().map(Vec::len), Some(0));
        assert_eq!(
            report["unknown_methods"],
            serde_json::json!(["nosuchmethod"])
        );
    }
}
