//! **MAC/Spawn Daemon設計の実現性スパイク（バッチ2: S5・S6・S7）**。結果の正本は
//! `plans/mac-spike/RESULTS.md`、設計の正本は設計書§22.6.2（「改A」6手順）・§10.1.1（Job）・
//! §10.1（要求受付パイプ）である。
//!
//! バッチ1は「mitigationとcapabilityが効くか」を測った。ここで測るのは
//! **Daemon方式を実装できるか**——Daemonが持つべき3つの能力が実機で成立するか、である。
//!
//! | # | 問い | 否だったときに崩れるもの |
//! |---|---|---|
//! | S5 | Daemon役が呼び出し元のハンドルを複製し、実体のパスを解決し、権限を絞って子へ渡せるか | §22.6.2「改A」（採らなかった案C＝全出力中継へ戻る） |
//! | S6 | Jobの封じ込めがDaemon方式（＝複製ハンドルが1本増える）でも保てるか | §10.1.1（キャンセルを`TerminateJobObject`へ変える根拠） |
//! | S7 | capability SID宛ACEを持つ名前付きパイプへ、サンドボックスから往復できるか | §10.1（要求受付パイプそのもの） |
//!
//! 実行（**昇格しないこと**）:
//!
//! ```text
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture mac_spike_daemon_tests
//! ```

use std::ffi::c_void;

use windows::Win32::Foundation::{
    DuplicateHandle, DUPLICATE_HANDLE_OPTIONS, DUPLICATE_SAME_ACCESS,
};

use super::mac_spike_tests::{
    last_json_line, probe_exe, workspace_capability_for, SpikeConsole, SpikeSpawn,
};
use super::*;

/// 実験用workspaceを1つ用意し、`preflight`まで通した状態を返す。
fn spike_workspace() -> (
    tempfile::TempDir,
    OwnedContainerSid,
    Vec<crate::win_common::OwnedSid>,
) {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let sid = session_sid();
    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
    grant_job::wait_until_done().expect("background grant job");
    let mut caps = vec![traverse_capability_sid().expect("traverse capability")];
    if let Some(cap) = workspace_capability_for(workspace.path()) {
        caps.push(cap);
    }
    (workspace, sid, caps)
}

/// `NtQueryObject(ObjectBasicInformation)`で許可アクセスマスクを取る（§22.6.2手順3）。
/// `windows`クレートのWdk名前空間はこのクレートで有効化していないので、ntdllから直に引く。
fn granted_access(handle: HANDLE) -> Option<u32> {
    #[repr(C)]
    #[derive(Default)]
    struct PublicObjectBasicInformation {
        attributes: u32,
        granted_access: u32,
        handle_count: u32,
        pointer_count: u32,
        reserved: [u32; 10],
    }
    type NtQueryObject = unsafe extern "system" fn(HANDLE, u32, *mut c_void, u32, *mut u32) -> i32;
    unsafe {
        let ntdll = GetModuleHandleW(PCWSTR(wide("ntdll.dll").as_ptr())).ok()?;
        let proc = GetProcAddress(
            ntdll,
            windows::core::PCSTR(c"NtQueryObject".as_ptr() as *const u8),
        )?;
        let query: NtQueryObject = std::mem::transmute(proc);
        let mut info = PublicObjectBasicInformation::default();
        let mut len = 0u32;
        let status = query(
            handle,
            0, // ObjectBasicInformation
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<PublicObjectBasicInformation>() as u32,
            &mut len,
        );
        if status < 0 {
            return None;
        }
        Some(info.granted_access)
    }
}

/// `GetFinalPathNameByHandleW`。Daemon役（AppContainerの外）でのみ動く（§22.6.2の注記）。
fn final_path(handle: HANDLE) -> Result<String, u32> {
    use windows::Win32::Storage::FileSystem::{GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED};
    let mut buf = vec![0u16; 4096];
    let len = unsafe { GetFinalPathNameByHandleW(handle, &mut buf, FILE_NAME_NORMALIZED) };
    if len == 0 {
        return Err(unsafe { GetLastError() }.0);
    }
    Ok(String::from_utf16_lossy(&buf[..len as usize]))
}

/// S5: §22.6.2「改A」の6手順（複製→最終パス解決→マスク取得→照合→絞って複製→子へ渡す）が
/// 実機で成立するか。
///
/// **呼び出し元が申告するのはハンドル値（数値）だけ**という設計をそのまま写している。
#[test]
#[ignore = "spawns real AppContainer children; run NON-elevated with --test-threads=1"]
fn s5_daemon_can_duplicate_resolve_and_narrow_a_callers_handle() {
    let (workspace, sid, caps) = spike_workspace();
    let _cleanup = super::test_support::scopeguard(|| {
        super::mac_spike_tests::forget_workspace_capability(workspace.path())
    });
    let caps_psid: Vec<PSID> = caps.iter().map(|c| c.as_psid()).collect();
    let probe = probe_exe();
    let probe_str = probe
        .to_str()
        .expect("probe path is valid utf-8")
        .to_string();

    // 呼び出し元役: workspace内のファイルを書込で開いて、ハンドル値だけを申告する。
    let target_file = workspace.path().join("s5-target.txt");
    let target_file_str = target_file.to_string_lossy().into_owned();
    let report = workspace.path().join("s5-report.json");
    let report_str = report.to_string_lossy().into_owned();
    let caller = SpikeSpawn {
        exe: &probe_str,
        args: &[
            "--hold-file",
            &target_file_str,
            "--report-file",
            &report_str,
            "--idle-secs",
            "20",
            "--timeout-secs",
            "60",
        ],
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &caps_psid,
        child_process_restricted: false,
        stdout_override: None,
        extra_inherit: &[],
        process_sddl: None,
        thread_sddl: None,
        token_default_dacl_sddl: None,
        no_appcontainer: false,
        console: SpikeConsole::NoWindow,
    }
    .spawn()
    .expect("spawn the caller child");

    let mut raw_handle: u64 = 0;
    for _ in 0..50 {
        if let Ok(body) = std::fs::read_to_string(&report) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                raw_handle = v.get("handle").and_then(|h| h.as_u64()).unwrap_or(0);
                if raw_handle != 0 {
                    break;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        raw_handle != 0,
        "呼び出し元役がハンドル値を申告しなかった（{}）",
        std::fs::read_to_string(&report).unwrap_or_default()
    );

    // --- 手順1: Daemon役（このテストプロセス）へ複製する ---
    let mut duplicated = HANDLE::default();
    let dup_ok = unsafe {
        DuplicateHandle(
            caller.process(),
            HANDLE(raw_handle as usize as *mut c_void),
            GetCurrentProcess(),
            &mut duplicated,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    };
    eprintln!("[S5] 手順1 DuplicateHandle(呼び出し元→Daemon): {dup_ok:?}");
    assert!(
        dup_ok.is_ok(),
        "Daemon役が呼び出し元のハンドルを複製できない。§22.6.2「改A」の手順1が成立しない: {dup_ok:?}"
    );

    // --- 手順2: 最終パスを解決する ---
    let resolved = final_path(duplicated);
    eprintln!("[S5] 手順2 GetFinalPathNameByHandleW: {resolved:?}");
    let resolved = resolved.expect("final path must resolve for a file handle");
    let expected = target_file.canonicalize().unwrap_or(target_file.clone());
    assert!(
        resolved.to_ascii_lowercase().contains(
            &expected
                .to_string_lossy()
                .to_ascii_lowercase()
                .replace("\\\\?\\", "")
        ),
        "解決した最終パスが対象と一致しない: resolved={resolved} expected={}",
        expected.display()
    );

    // --- 手順3: 許可アクセスマスクを取る ---
    let mask = granted_access(duplicated);
    eprintln!(
        "[S5] 手順3 NtQueryObject(GrantedAccess) = {mask:?} ({:?})",
        mask.map(|m| format!("{m:#x}"))
    );
    assert!(
        mask.is_some(),
        "NtQueryObjectで許可アクセスマスクを取れない。手順3が成立しない"
    );

    // --- 手順5-6: 権限を絞って複製し、遷移先の子へstdoutとして渡す ---
    let mut narrowed = HANDLE::default();
    let narrow_ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            duplicated,
            GetCurrentProcess(),
            &mut narrowed,
            FILE_GENERIC_WRITE.0,
            true, // 子へ継承させる
            DUPLICATE_HANDLE_OPTIONS(0),
        )
    };
    eprintln!("[S5] 手順5 絞った複製 (FILE_GENERIC_WRITE, inheritable): {narrow_ok:?}");
    assert!(
        narrow_ok.is_ok(),
        "権限を絞った複製に失敗した: {narrow_ok:?}"
    );
    eprintln!(
        "[S5] 絞った後のGrantedAccess = {:?}",
        granted_access(narrowed).map(|m| format!("{m:#x}"))
    );

    let mut receiver = SpikeSpawn {
        exe: &probe_str,
        args: &["--emit", "HELLO-FROM-DOMAIN-B"],
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &caps_psid,
        child_process_restricted: false,
        stdout_override: Some(narrowed),
        extra_inherit: &[],
        process_sddl: None,
        thread_sddl: None,
        token_default_dacl_sddl: None,
        no_appcontainer: false,
        console: SpikeConsole::NoWindow,
    }
    .spawn()
    .expect("spawn the receiver child");
    let (_out, err, code) = receiver.wait_and_read();
    eprintln!("[S5] 受け手の子: exit={code} stderr={err:?}");

    // --- パスを持たない型では手順2が失敗すること（§22.6.2「適用範囲」の根拠） ---
    let (pipe_read, pipe_write) = create_pipe_with_sddl("D:(A;;GA;;;WD)(A;;GA;;;AC)")
        .expect("anonymous-ish pipe for the negative case");
    let pipe_path = final_path(pipe_read);
    eprintln!("[S5] pipeハンドルへのGetFinalPathNameByHandleW: {pipe_path:?}");
    unsafe {
        let _ = CloseHandle(pipe_read);
        let _ = CloseHandle(pipe_write);
        let _ = CloseHandle(narrowed);
        let _ = CloseHandle(duplicated);
    }
    drop(caller);

    let written = std::fs::read_to_string(&target_file).unwrap_or_default();
    eprintln!("[S5] 対象ファイルの中身: {written:?}");
    assert!(
        written.contains("HELLO-FROM-DOMAIN-B"),
        "絞って渡したハンドルへ遷移先の子が書けていない。§22.6.2「改A」の手順6が成立しない: \
         content={written:?}"
    );
    assert!(
        pipe_path.is_err(),
        "pipeハンドルから最終パスが取れてしまった。§22.6.2「適用範囲」（fileハンドルにしか\
         適用できない）の前提が変わる: {pipe_path:?}"
    );
}

/// S6: Jobの封じ込めが「複製ハンドルが1本増えた」状態でも保てるか（§10.1.1）。
///
/// §10.1.1は「Daemonが複製を持つとハンドルが1本残るので、harnessが閉じても子孫が死なない」
/// という**予測**を根拠に、キャンセルを`TerminateJobObject`へ変えると決めた。その予測を測る。
///
/// **限界**: 複製の保持者はこのテストプロセス自身であって、別プロセスのDaemonではない。
/// kill-on-closeは「最後のハンドルが閉じたとき」に発火する仕様なので、**保持者が誰かは
/// 関係しない**——が、Daemonが別プロセスから`AssignProcessToJobObject`できるかは
/// **この測定では分からない**（RESULTS.mdへ限界として明記する）。
#[test]
#[ignore = "spawns real AppContainer children; run NON-elevated with --test-threads=1"]
fn s6_job_containment_survives_a_duplicated_job_handle() {
    let (workspace, sid, caps) = spike_workspace();
    let _cleanup = super::test_support::scopeguard(|| {
        super::mac_spike_tests::forget_workspace_capability(workspace.path())
    });
    let caps_psid: Vec<PSID> = caps.iter().map(|c| c.as_psid()).collect();
    let probe = probe_exe();
    let probe_str = probe
        .to_str()
        .expect("probe path is valid utf-8")
        .to_string();

    let mut child = SpikeSpawn {
        exe: &probe_str,
        args: &["--idle-secs", "25", "--timeout-secs", "60"],
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &caps_psid,
        child_process_restricted: false,
        stdout_override: None,
        extra_inherit: &[],
        process_sddl: None,
        thread_sddl: None,
        token_default_dacl_sddl: None,
        no_appcontainer: false,
        console: SpikeConsole::NoWindow,
    }
    .spawn()
    .expect("spawn the job child");

    // Daemon役が持つぶんの複製（§10.1.1「系統Jobハンドルの複製をDaemonへ渡す」）。
    let mut job_dup = HANDLE::default();
    unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            child.job(),
            GetCurrentProcess(),
            &mut job_dup,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    }
    .expect("duplicate the job handle");

    // **生存確認用のプロセスハンドルは、childを畳む前に複製しておく**。
    // `SpikeChild::drop`はプロセスハンドルも閉じるので、閉じた後の`GetExitCodeProcess`は
    // 「死んだ」ではなく「無効なハンドル」を返す——最初の測定でこれを踏み、
    // 機構の失敗と測定の失敗を取り違えかけた（B-29）。
    let mut process = HANDLE::default();
    unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            child.process(),
            GetCurrentProcess(),
            &mut process,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    }
    .expect("duplicate the process handle for liveness checks");
    let pid = child.pid();
    let alive = |label: &str| -> bool {
        let mut code = 0u32;
        let ok = unsafe { GetExitCodeProcess(process, &mut code) }.is_ok();
        eprintln!("[S6] {label}: GetExitCodeProcess ok={ok} code={code} (259=STILL_ACTIVE)");
        code == 259
    };
    assert!(
        alive("spawn直後"),
        "子が起動していない（測定の前提が崩れている）"
    );

    // harness役が**jobハンドルだけ**を閉じる（stdioのパイプは開けたまま）。
    // 変数を1つに絞らないと、子の死因が「kill-on-close」なのか「パイプが閉じた」なのか
    // 区別できない——最初の測定では`drop(child)`で両方を同時に閉じてしまい、
    // 子がexit 101（Rustのpanic終了コード＝stdout書込失敗）で死んだのを
    // 「kill-on-closeが発火した」と読み違えかけた（B-29）。
    let harness_job = child.take_job();
    unsafe {
        let _ = CloseHandle(harness_job);
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
    let survived = alive("harness役がjobハンドルを閉じた後");

    // 明示的な`TerminateJobObject`（§10.1.1が新しいキャンセル手段として選んだもの）。
    let terminate = unsafe { windows::Win32::System::JobObjects::TerminateJobObject(job_dup, 1) };
    std::thread::sleep(std::time::Duration::from_millis(500));
    let mut code_after = 0u32;
    let _ = unsafe { GetExitCodeProcess(process, &mut code_after) };
    eprintln!("[S6] TerminateJobObject: {terminate:?} → 子のexit_code={code_after}");
    unsafe {
        let _ = CloseHandle(job_dup);
        let _ = CloseHandle(process);
    }

    assert!(
        survived,
        "複製ハンドルが1本残っているのに kill-on-close が発火して子が死んだ。\
         §10.1.1の前提（Daemonが複製を持つとharnessが閉じても子孫が死なない）が誤りになる。pid={pid}"
    );
    assert!(
        terminate.is_ok(),
        "TerminateJobObjectが失敗した。§10.1.1の新しいキャンセル手段が成立しない: {terminate:?}"
    );
    assert_ne!(
        code_after, 259,
        "TerminateJobObject後も子が生きている。キャンセルが効いていない。pid={pid}"
    );
}

/// S7: 要求受付パイプ（§10.1）。**capability SID宛ACEを持つ名前付きパイプへ、
/// サンドボックスから往復できるか**を、`win_pipe_ipc`と同じフレーム形式で測る。
///
/// 対で測る（B-35）——capabilityを積んだ子は往復でき、**積まない子は到達すらできない**こと。
/// 後者が成立すれば、§22.2.2の`process: deny`が「パイプに到達できない」という二重のdenyになる。
#[test]
#[ignore = "spawns real AppContainer children and creates a named pipe; run NON-elevated with --test-threads=1"]
fn s7_request_pipe_is_reachable_only_with_the_spawn_capability() {
    use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile, PIPE_ACCESS_DUPLEX};
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    let (workspace, sid, caps) = spike_workspace();
    let _cleanup = super::test_support::scopeguard(|| {
        super::mac_spike_tests::forget_workspace_capability(workspace.path())
    });
    let probe = probe_exe();
    let probe_str = probe
        .to_str()
        .expect("probe path is valid utf-8")
        .to_string();

    // spawn要求用capability（§10.1で「session package SIDではなくcapability SID宛」と決めたもの）。
    let spawn_cap = super::capability_sid_from_name(&format!(
        "harness-mac-spike-spawnreq-{}",
        std::process::id()
    ))
    .expect("derive the spawn-request capability");
    let cap_sid_string =
        crate::win_common::sid_to_string(spawn_cap.as_psid()).expect("capability sid string");
    let user_sid = crate::win_pipe_ipc::current_user_sid_string().expect("current user sid");

    // **`FILE_CREATE_PIPE_INSTANCE`(0x4)を含めない**マスク（§10.1）。
    // `FILE_GENERIC_WRITE`(0x120116)はこのビットを含むので、そのまま与えてはいけない。
    const READ_WRITE_WITHOUT_CREATE_INSTANCE: u32 = 0x0012_019B;
    let sddl = format!(
        "D:(A;;GA;;;{user_sid})(A;;0x{:x};;;{cap_sid_string})",
        READ_WRITE_WITHOUT_CREATE_INSTANCE
    );
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide(&sddl).as_ptr()),
            windows::Win32::Security::Authorization::SDDL_REVISION_1,
            &mut sd,
            None,
        )
    }
    .expect("convert the request-pipe SDDL");
    let sa = windows::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };

    let pipe_name = crate::win_pipe_ipc::unique_pipe_name("mac-spike-request");
    let pipe_name_w = wide(&pipe_name);
    // `FILE_FLAG_FIRST_PIPE_INSTANCE`（§10.1の占拠対策）。定数は`Storage::FileSystem`にある。
    let first_instance = windows::Win32::Storage::FileSystem::FILE_FLAG_FIRST_PIPE_INSTANCE;
    let server = unsafe {
        CreateNamedPipeW(
            PCWSTR(pipe_name_w.as_ptr()),
            PIPE_ACCESS_DUPLEX | first_instance,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            4,
            4096,
            4096,
            0,
            Some(&sa as *const _),
        )
    };
    assert!(!server.is_invalid(), "要求受付パイプを作れなかった: {sddl}");
    let _pipe_guard = super::test_support::scopeguard(|| unsafe {
        let _ = CloseHandle(server);
        let _ = LocalFree(HLOCAL(sd.0));
    });

    // サーバ役: 1往復だけして終わる（`win_pipe_ipc`と同じ長さプレフィックス形式）。
    struct SendHandle(HANDLE);
    unsafe impl Send for SendHandle {}
    let server_handle = SendHandle(server);
    let server_thread = std::thread::spawn(move || {
        let h = server_handle;
        unsafe {
            let _ = ConnectNamedPipe(h.0, None);
            let mut len_buf = [0u8; 4];
            let mut read = 0u32;
            if ReadFile(h.0, Some(&mut len_buf), Some(&mut read), None).is_err() || read != 4 {
                return String::new();
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut body = vec![0u8; len.min(4096)];
            let _ = ReadFile(h.0, Some(&mut body), Some(&mut read), None);
            let request = String::from_utf8_lossy(&body[..read as usize]).into_owned();
            let reply = b"spawn-denied-by-policy";
            let mut frame = (reply.len() as u32).to_le_bytes().to_vec();
            frame.extend_from_slice(reply);
            let mut written = 0u32;
            let _ = WriteFile(h.0, Some(&frame), Some(&mut written), None);
            request
        }
    });

    // --- 対の測定: capabilityを積んだ子（往復できるはず） ---
    let mut caps_with: Vec<PSID> = caps.iter().map(|c| c.as_psid()).collect();
    caps_with.push(spawn_cap.as_psid());
    let mut client = SpikeSpawn {
        exe: &probe_str,
        args: &["--pipe-client", &pipe_name, "--timeout-secs", "60"],
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &caps_with,
        child_process_restricted: false,
        stdout_override: None,
        extra_inherit: &[],
        process_sddl: None,
        thread_sddl: None,
        token_default_dacl_sddl: None,
        no_appcontainer: false,
        console: SpikeConsole::NoWindow,
    }
    .spawn()
    .expect("spawn the capable client");
    let (out_with, err_with, _) = client.wait_and_read();
    eprintln!("[S7] capabilityあり: {out_with}\nstderr={err_with}");
    let report_with = last_json_line(&out_with)
        .unwrap_or_else(|| panic!("capableクライアントがJSONを出さなかった: {out_with}"));
    let seen_request = server_thread.join().unwrap_or_default();
    eprintln!("[S7] サーバが受け取った要求: {seen_request:?}");

    // --- capabilityを積まない子（到達できないはず） ---
    let caps_without: Vec<PSID> = caps.iter().map(|c| c.as_psid()).collect();
    let mut client_without = SpikeSpawn {
        exe: &probe_str,
        args: &["--pipe-client", &pipe_name, "--timeout-secs", "60"],
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &caps_without,
        child_process_restricted: false,
        stdout_override: None,
        extra_inherit: &[],
        process_sddl: None,
        thread_sddl: None,
        token_default_dacl_sddl: None,
        no_appcontainer: false,
        console: SpikeConsole::NoWindow,
    }
    .spawn()
    .expect("spawn the incapable client");
    let (out_without, _, _) = client_without.wait_and_read();
    eprintln!("[S7] capabilityなし: {out_without}");
    let report_without = last_json_line(&out_without)
        .unwrap_or_else(|| panic!("incapableクライアントがJSONを出さなかった: {out_without}"));

    let connected = |v: &serde_json::Value| v.get("connected").and_then(|c| c.as_bool());
    assert_eq!(
        connected(&report_with),
        Some(true),
        "spawn要求用capabilityを積んだ子が要求受付パイプへ接続できない。§10.1のDACL設計が\
         成立しない: {report_with}"
    );
    assert!(
        seen_request.contains("spawn-request-from-pid-"),
        "サーバ側が要求を受け取れていない（フレーム形式が往復していない）: {seen_request:?}"
    );
    assert_eq!(
        report_with.get("reply_ok").and_then(|c| c.as_bool()),
        Some(true),
        "応答を読めていない（1往復が成立していない）: {report_with}"
    );
    assert_eq!(
        connected(&report_without),
        Some(false),
        "capabilityを積んでいない子が要求受付パイプへ到達できた。§22.2.2の`process: deny`が\
         「パイプに到達すらできない」という二重のdenyにならない: {report_without}"
    );
}
