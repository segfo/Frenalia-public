//! **MAC/Spawn Daemon設計 §20項目10の実現性スパイク専用モード**（`plans/mac-spike/RESULTS.md`）。
//!
//! `win_appcontainer/spawn.rs`の`appcontainer_pipe`のdocが書いている前提——
//! 「package SID宛ACEが無ければアクセス不可というdefault-denyが、ファイル・レジストリだけで
//! なく**名前無しパイプ等のカーネルオブジェクトにも及ぶ可能性が高い**……**これは設計上の
//! 予測であり実機未検証**」——を型ごとに実測する。
//!
//! この1項目で3つの未解決が同時に決まる（設計書§20項目10）。
//!
//! - ドメイン間のプロセス相互アクセス（§22.8が引き受けたリスク）
//! - ハンドル継承の型ゲート（§22.6.2の適用範囲）
//! - Spawn DaemonのIPCのDACLを境界にできるか（§10.1）
//!
//! **開けたかどうかを実際のオープンで測る**（B-25）。ドライバはこのプローブを
//! 「同一package SID」「別package SID（MCPプロファイル）」の2構成で起動し、同じ的へ
//! 撃たせて差を見る。

use serde_json::{json, Value};

/// このモードが受け取る的の指定。
#[derive(Default)]
pub struct ReachSpec {
    /// `OpenProcess`の的（別ドメインのプロセスのPID）。
    pub process: Option<u32>,
    /// `OpenThread`の的（複数可）。**起動時のスレッドと、後から生えたスレッドの両方**を
    /// 撃てるようにしてある——`lpThreadAttributes`が効くのは最初の1本だけなので、
    /// 「プロセスとスレッドのDACLを絞る」候補機構の穴はここでしか見えない（S2b）。
    pub threads: Vec<u32>,
    /// `CreateFileW`で開こうとする名前付きパイプ（`\\.\pipe\...`）。
    pub pipes: Vec<String>,
    /// 同名パイプの**追加インスタンス**を作れるか（サーバ偽装、§10.1）。
    pub create_pipe_instances: Vec<String>,
    /// パイプの名前空間（`\\.\pipe\*`）を**列挙**できるか（T4）。
    /// 一意な名前が「秘密」として成立しているかどうかがこれで決まる——列挙できるなら、
    /// 名前の推測不能性は防御に数えられない（DACLだけが境界になる）。
    pub enumerate_pipes: bool,
    /// **まだ存在しない**名前でパイプを作れるか（名前の先取り＝占拠、T4）。
    /// [`create_pipe_instances`](Self::create_pipe_instances)が「既にある的への相乗り」なのに対し、
    /// こちらは「harnessが後から使う名前を先に取る」——別の問いなので別の的として測る。
    pub create_new_pipes: Vec<String>,
    /// `type:name`形式の名前付きカーネルオブジェクト（`mutex` / `event` / `section` / `job`）。
    pub objects: Vec<String>,
}

#[cfg(windows)]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn attempt(kind: &str, target: &str, access: &str, ok: bool, last_error: u32) -> Value {
    json!({
        "kind": kind,
        "target": target,
        "access": access,
        "ok": ok,
        "last_error": last_error,
    })
}

#[cfg(windows)]
fn probe_process(pid: u32) -> Vec<Value> {
    use windows::Win32::Foundation::{CloseHandle, GetLastError};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_ALL_ACCESS, PROCESS_CREATE_THREAD,
        PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_VM_READ, PROCESS_VM_WRITE,
    };

    let masks: &[(&str, PROCESS_ACCESS_RIGHTS)] = &[
        (
            "PROCESS_QUERY_LIMITED_INFORMATION",
            PROCESS_QUERY_LIMITED_INFORMATION,
        ),
        ("PROCESS_QUERY_INFORMATION", PROCESS_QUERY_INFORMATION),
        ("PROCESS_VM_READ", PROCESS_VM_READ),
        ("PROCESS_VM_WRITE", PROCESS_VM_WRITE),
        ("PROCESS_CREATE_THREAD", PROCESS_CREATE_THREAD),
        ("PROCESS_DUP_HANDLE", PROCESS_DUP_HANDLE),
        ("PROCESS_ALL_ACCESS", PROCESS_ALL_ACCESS),
    ];
    masks
        .iter()
        .map(|(label, mask)| {
            let result = unsafe { OpenProcess(*mask, false, pid) };
            match result {
                Ok(h) => {
                    unsafe {
                        let _ = CloseHandle(h);
                    }
                    attempt("process", &pid.to_string(), label, true, 0)
                }
                Err(_) => attempt(
                    "process",
                    &pid.to_string(),
                    label,
                    false,
                    unsafe { GetLastError() }.0,
                ),
            }
        })
        .collect()
}

#[cfg(windows)]
fn probe_thread(tid: u32) -> Vec<Value> {
    use windows::Win32::Foundation::{CloseHandle, GetLastError};
    use windows::Win32::System::Threading::{
        OpenThread, THREAD_ACCESS_RIGHTS, THREAD_ALL_ACCESS, THREAD_QUERY_LIMITED_INFORMATION,
        THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
    };

    let masks: &[(&str, THREAD_ACCESS_RIGHTS)] = &[
        (
            "THREAD_QUERY_LIMITED_INFORMATION",
            THREAD_QUERY_LIMITED_INFORMATION,
        ),
        ("THREAD_SUSPEND_RESUME", THREAD_SUSPEND_RESUME),
        ("THREAD_SET_CONTEXT", THREAD_SET_CONTEXT),
        ("THREAD_ALL_ACCESS", THREAD_ALL_ACCESS),
    ];
    masks
        .iter()
        .map(
            |(label, mask)| match unsafe { OpenThread(*mask, false, tid) } {
                Ok(h) => {
                    unsafe {
                        let _ = CloseHandle(h);
                    }
                    attempt("thread", &tid.to_string(), label, true, 0)
                }
                Err(_) => attempt(
                    "thread",
                    &tid.to_string(),
                    label,
                    false,
                    unsafe { GetLastError() }.0,
                ),
            },
        )
        .collect()
}

/// 名前付きパイプを**クライアントとして**開く（`\\.\pipe\...`）。
/// §10.1の「要求受付パイプへ到達できるか」と、その裏の「ユーザー専有DACLのパイプへは
/// 到達できないはず」の両方をこの1関数で測る（的の名前が違うだけ）。
#[cfg(windows)]
fn probe_pipe_open(name: &str) -> Value {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GetLastError, GENERIC_READ, GENERIC_WRITE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_MODE, OPEN_EXISTING,
    };

    let name_w = wide(name);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(name_w.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };
    match handle {
        Ok(h) => {
            unsafe {
                let _ = CloseHandle(h);
            }
            attempt("pipe-open", name, "GENERIC_READ|GENERIC_WRITE", true, 0)
        }
        Err(_) => attempt(
            "pipe-open",
            name,
            "GENERIC_READ|GENERIC_WRITE",
            false,
            unsafe { GetLastError() }.0,
        ),
    }
}

/// 同名パイプの**追加インスタンス**を作れるか。作れると、サンドボックス内プロセスが
/// 後続クライアントを横取りできる（サーバ偽装、§10.1）。
#[cfg(windows)]
fn probe_pipe_instance(name: &str) -> Value {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GetLastError};
    use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    let name_w = wide(name);
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(name_w.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            16,
            4096,
            4096,
            0,
            None,
        )
    };
    if handle.is_invalid() {
        return attempt(
            "pipe-create-instance",
            name,
            "PIPE_ACCESS_DUPLEX",
            false,
            unsafe { GetLastError() }.0,
        );
    }
    unsafe {
        let _ = CloseHandle(handle);
    }
    attempt("pipe-create-instance", name, "PIPE_ACCESS_DUPLEX", true, 0)
}

/// パイプの名前空間を列挙できるか（T4）。`\\.\pipe\*`を`FindFirstFileW`で走査する。
///
/// **開けるかどうかとは別の問い**である。DACLで開けなくても、名前が見えるなら
/// 「一意な名前だから推測できない」という前提は成立しない。逆に列挙できなければ、
/// サンドボックス内から的の名前を知る経路が1つ減る（**塞がっている根拠にはしない**——
/// 名前は親から環境変数・引数・ファイル経由でも漏れうる）。
///
/// 名前そのものは返さず、**件数と接頭辞の内訳**だけを返す。名前にはセッション固有の
/// 値が入りうるので、測定ログへ丸ごと落とさない。
#[cfg(windows)]
fn probe_pipe_enumerate() -> Value {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::GetLastError;
    use windows::Win32::Storage::FileSystem::{
        FindClose, FindFirstFileW, FindNextFileW, WIN32_FIND_DATAW,
    };

    let pattern = wide(r"\\.\pipe\*");
    let mut data = WIN32_FIND_DATAW::default();
    let find = unsafe { FindFirstFileW(PCWSTR(pattern.as_ptr()), &mut data) };
    let find = match find {
        Ok(h) => h,
        Err(_) => {
            let mut report = attempt("pipe-enumerate", r"\\.\pipe\*", "FindFirstFileW", false, {
                unsafe { GetLastError() }.0
            });
            report["total"] = json!(0);
            report["harness_prefixed"] = json!(0);
            report["privhelper_prefixed"] = json!(0);
            return report;
        }
    };

    let mut total = 0u32;
    let mut harness_prefixed = 0u32;
    let mut privhelper_prefixed = 0u32;
    loop {
        let name_len = data
            .cFileName
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(data.cFileName.len());
        let name = String::from_utf16_lossy(&data.cFileName[..name_len]);
        total += 1;
        if name.starts_with("harness-") {
            harness_prefixed += 1;
            if name.starts_with("harness-privhelper-") {
                privhelper_prefixed += 1;
            }
        }
        if unsafe { FindNextFileW(find, &mut data) }.is_err() {
            break;
        }
    }
    unsafe {
        let _ = FindClose(find);
    }

    let mut report = attempt("pipe-enumerate", r"\\.\pipe\*", "FindFirstFileW", true, 0);
    report["total"] = json!(total);
    report["harness_prefixed"] = json!(harness_prefixed);
    report["privhelper_prefixed"] = json!(privhelper_prefixed);
    report
}

/// **まだ存在しない**名前でパイプを作れるか（名前の先取り、T4）。
///
/// `FILE_FLAG_FIRST_PIPE_INSTANCE`を付ける——付けないと「既にある同名パイプへ相乗りした」
/// 場合も成功が返り、[`probe_pipe_instance`]と区別が付かなくなる。成功＝**その名前は空いていて、
/// 自分が最初のインスタンスを取った**という一意な意味になる。
///
/// 作れた場合、サンドボックス内プロセスはharnessが後から使う名前を先に取れる。それが
/// 何を引き起こすか（本体側の作成が落ちて止まるだけか、昇格側を騙せるか）は**この測定では
/// 決まらない**——ここで測るのは「取れるか」だけである。
#[cfg(windows)]
fn probe_pipe_create_new(name: &str) -> Value {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GetLastError};
    use windows::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
    use windows::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    let name_w = wide(name);
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(name_w.as_ptr()),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            4096,
            4096,
            0,
            None,
        )
    };
    let access = "PIPE_ACCESS_DUPLEX|FIRST_PIPE_INSTANCE";
    if handle.is_invalid() {
        return attempt(
            "pipe-create-new",
            name,
            access,
            false,
            unsafe { GetLastError() }.0,
        );
    }
    // **測定なので占拠したままにしない。** 即座に閉じる（閉じ忘れると、この後に本体が
    // 同じ名前を使う経路を無関係に壊す）。
    unsafe {
        let _ = CloseHandle(handle);
    }
    attempt("pipe-create-new", name, access, true, 0)
}

/// `type:name`（`mutex` / `event` / `section` / `job`）を開く。
#[cfg(windows)]
fn probe_named_object(spec: &str) -> Value {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
    use windows::Win32::System::JobObjects::OpenJobObjectW;
    use windows::Win32::System::Memory::{OpenFileMappingW, FILE_MAP_READ};
    use windows::Win32::System::Threading::{
        OpenEventW, OpenMutexW, EVENT_ALL_ACCESS, SYNCHRONIZATION_ACCESS_RIGHTS,
    };

    /// `JOB_OBJECT_ALL_ACCESS`は`windows` 0.58が生成していないので、SDKの定義
    /// （`STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3F`）を書く。
    const JOB_OBJECT_ALL_ACCESS: u32 = 0x001F_001F;

    let (kind, name) = match spec.split_once(':') {
        Some(parts) => parts,
        None => return attempt("named-object", spec, "-", false, 0),
    };
    let name_w = wide(name);
    let opened: Result<HANDLE, ()> = unsafe {
        match kind {
            "mutex" => OpenMutexW(
                SYNCHRONIZATION_ACCESS_RIGHTS(0x1F0001),
                false,
                PCWSTR(name_w.as_ptr()),
            )
            .map_err(|_| ()),
            "event" => OpenEventW(EVENT_ALL_ACCESS, false, PCWSTR(name_w.as_ptr())).map_err(|_| ()),
            "section" => {
                OpenFileMappingW(FILE_MAP_READ.0, false, PCWSTR(name_w.as_ptr())).map_err(|_| ())
            }
            "job" => OpenJobObjectW(JOB_OBJECT_ALL_ACCESS, false, PCWSTR(name_w.as_ptr()))
                .map_err(|_| ()),
            _ => return attempt("named-object", spec, "unknown-kind", false, 0),
        }
    };
    match opened {
        Ok(h) => {
            unsafe {
                let _ = CloseHandle(h);
            }
            attempt("named-object", spec, kind, true, 0)
        }
        Err(()) => attempt(
            "named-object",
            spec,
            kind,
            false,
            unsafe { GetLastError() }.0,
        ),
    }
}

#[cfg(windows)]
pub fn run(spec: &ReachSpec) -> Value {
    let mut attempts: Vec<Value> = Vec::new();
    if let Some(pid) = spec.process {
        attempts.extend(probe_process(pid));
    }
    for tid in &spec.threads {
        attempts.extend(probe_thread(*tid));
    }
    for pipe in &spec.pipes {
        attempts.push(probe_pipe_open(pipe));
    }
    for pipe in &spec.create_pipe_instances {
        attempts.push(probe_pipe_instance(pipe));
    }
    if spec.enumerate_pipes {
        attempts.push(probe_pipe_enumerate());
    }
    for pipe in &spec.create_new_pipes {
        attempts.push(probe_pipe_create_new(pipe));
    }
    for object in &spec.objects {
        attempts.push(probe_named_object(object));
    }
    json!({
        "pid": std::process::id(),
        "attempts": attempts,
    })
}

#[cfg(not(windows))]
pub fn run(_spec: &ReachSpec) -> Value {
    json!({"attempts": [], "error": "windows-only"})
}
