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
    /// `type:name`形式の名前付きカーネルオブジェクト（`mutex` / `event` / `section` / `job`）。
    pub objects: Vec<String>,
}

#[cfg(windows)]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 1回の「開こう／触ろうとした」の記録。
///
/// **`spawn_report`も同じ形で報告する**（[#49]の「返ったハンドルで何ができるか」）。
/// 形を写すと、2つのモードの結果を同じ道具で読めなくなる（`docs/CODE-STRUCTURE-RULES.md` §5.0）。
#[cfg(windows)]
pub(crate) fn attempt(kind: &str, target: &str, access: &str, ok: bool, last_error: u32) -> Value {
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
