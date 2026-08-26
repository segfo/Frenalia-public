//! **MAC/Spawn Daemon設計の実現性スパイク（バッチ1のS1・S2）**。結果の正本は
//! `plans/mac-spike/RESULTS.md`（Journal）で、設計の正本は
//! `plans/DESIGN-MAC.md`を入口とする`plans/DESIGN-MAC*.md`群である（§9は`-ENFORCEMENT`、
//! §20項目1・§20項目10は`-POC`。§番号→ファイルの索引は入口にある）。
//!
//! ## なぜスパイクなのか
//!
//! 設計は§22まで決着しているが、その土台に**一度も測っていない前提**が残っている。
//! `CHILD_PROCESS_RESTRICTED`はこのリポジトリに1行も実装が無く（`grep`で0件）、
//! `appcontainer_pipe`のdoc（`spawn.rs`）は自分で「**これは設計上の予測であり実機未検証**」と
//! 書いている。実装を積んでから前提が崩れると技術選定からやり直しになるので、
//! **着手前にここで確定させる**。
//!
//! ## 実行（**昇格しないこと**）
//!
//! ```text
//! cargo build -p tier2a-proc-probe
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture mac_spike_tests
//! ```
//!
//! **`dev-elevated-run.exe`から回さない。** 昇格したテストからAppContainer子を起こすと、
//! 親トークンが管理者のものになり、測っている世界が実運用（非昇格のharness）と変わる
//! （`bug-pattern-rules` B-08、BUG-109が同じ形で刺さった）。ETWで拒否を観測するアーム
//! （§20項目1の2）は昇格が要るので、**そちらだけ**を別ターゲットに分けてある。
//!
//! ## 生産コードを変えない
//!
//! mitigation付きのspawnは、このファイル内に独立実装（[`SpikeSpawn`]）として持つ。
//! `spawn.rs`の`spawn_impl`から必要な部分だけを写したコピーであり、**意図的な重複**である。
//!
//! - `run_shell`系統へ`CHILD_PROCESS_RESTRICTED`を入れてよいのは§8.1（Redirector常時注入＋
//!   注入主体のDaemon移管）が揃った後、という着手順序の拘束がある
//!   （`plans/PLAN-MAC-DOMAIN-TRANSITION.md`段階5b）。**測定と適用は別物**
//! - `policy_learnd/etw`のスパイクが確立した作法（生産コードを触らず、独立した実装を
//!   スパイク側に閉じる）と同じ
//!
//! ## 判定が出たらこのファイルは消す
//!
//! `docs/CODE-STRUCTURE-RULES.md`規則2（一回性の調査実験をテストとして残さない）に従う。
//! 本番機構が着地する時点で回帰テストとして要るもの（mitigationの強制力・capabilityの差・
//! Jobの解体）は、そのとき**本体側のテストとして書き直す**——スパイクの写しを残さない。

use std::path::{Path, PathBuf};

use windows::Win32::System::Threading::PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY;

use super::*;

/// `PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`。`windows` 0.58は
/// `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY`（=131086）は生成しているが、この値は
/// 生成していないのでSDK（`processthreadsapi.h`）の定義を書く。
const PROCESS_CREATION_CHILD_PROCESS_RESTRICTED: u32 = 0x0000_0001;

/// スパイクの子へ渡すstdioパイプのSDDL。`WD`（Everyone）だけではAppContainerから触れないので
/// `AC`（ALL APPLICATION PACKAGES）も付ける。**本番の`appcontainer_pipe`はセッションの
/// package SIDを名指しする**（こちらの方が狭い）が、ここはstdioの配管であって測定対象では
/// ないため、プロファイルを跨いで使える`AC`で足りる。
const SPIKE_PIPE_SDDL: &str = "D:(A;;GA;;;WD)(A;;GA;;;AC)";

const SE_GROUP_ENABLED: u32 = 0x0000_0004;

/// スパイクが起こしたAppContainer子。Dropでjobごと畳む（kill-on-closeなので子孫も死ぬ）。
pub(super) struct SpikeChild {
    process: HANDLE,
    job: HANDLE,
    pid: u32,
    thread_id: u32,
    stdout_read: HANDLE,
    stderr_read: HANDLE,
}

unsafe impl Send for SpikeChild {}

impl SpikeChild {
    pub(super) fn pid(&self) -> u32 {
        self.pid
    }

    /// 主スレッドのID（§20項目10の`OpenThread`の的）。
    pub(super) fn thread_id(&self) -> u32 {
        self.thread_id
    }

    pub(super) fn process(&self) -> HANDLE {
        self.process
    }

    pub(super) fn job(&self) -> HANDLE {
        self.job
    }

    /// jobハンドルの所有権を呼び出し側へ移す（Dropは閉じなくなる）。
    ///
    /// S6で「**jobハンドルを閉じたこと**だけ」を変数にするために要る——`Drop`はstdioの
    /// パイプもプロセスハンドルも一緒に閉じるので、そのまま畳むと子の死因が
    /// 「kill-on-close」なのか「パイプが閉じた」なのか分からない（B-29）。
    pub(super) fn take_job(&mut self) -> HANDLE {
        std::mem::replace(&mut self.job, INVALID_HANDLE_VALUE)
    }

    /// stdout/stderrをEOFまで読み、終了を待って終了コードを返す。
    pub(super) fn wait_and_read(&mut self) -> (String, String, i32) {
        let (out, err) = read_two_pipes_to_strings(self.stdout_read, self.stderr_read);
        unsafe {
            WaitForSingleObject(self.process, 120_000);
            let mut code: u32 = 0;
            let _ = GetExitCodeProcess(self.process, &mut code);
            (out, err, code as i32)
        }
    }
}

impl Drop for SpikeChild {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.stdout_read);
            let _ = CloseHandle(self.stderr_read);
            // jobを閉じるとkill-on-closeで子孫ごと畳まれる（`create_job_object`のdoc）。
            let _ = CloseHandle(self.job);
            let _ = CloseHandle(self.process);
        }
    }
}

/// スパイク専用のAppContainer spawn（`spawn_impl`の必要部分のコピー、モジュールdoc参照）。
pub(super) struct SpikeSpawn<'a> {
    pub exe: &'a str,
    pub args: &'a [&'a str],
    pub cwd: &'a Path,
    pub container_sid: PSID,
    /// トークンへ積むcapability SID。`spawn_with_workspace`がtraverse/workspace/networkを
    /// 積むのと同じ場所へ、スパイクは任意の組を積む。
    pub capabilities: &'a [PSID],
    /// `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY`を積むか（S1の測定軸）。
    pub child_process_restricted: bool,
    /// `hStdOutput`をこのハンドルに差し替える（§22.6.2の「絞って複製したハンドルを渡す」）。
    pub stdout_override: Option<HANDLE>,
    /// `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`へ追加で載せるハンドル（§20項目3）。
    pub extra_inherit: &'a [HANDLE],
    /// 子**プロセスオブジェクト自身**のDACLをSDDLで指定する（`lpProcessAttributes`）。
    ///
    /// S2で「同一package SID内は`PROCESS_ALL_ACCESS`まで通る」と分かったので、その穴を
    /// 塞ぐ候補として測る軸。既定（`None`）はOSの既定DACL＝package SIDへのACEを含む。
    pub process_sddl: Option<&'a str>,
    /// **最初のスレッド**オブジェクトのDACL（`lpThreadAttributes`）。
    /// プロセスを絞ってもスレッドは別オブジェクトなので、対で絞らないと
    /// `SetThreadContext`経由の乗っ取りが残る（S2bの実測）。
    pub thread_sddl: Option<&'a str>,
    /// 子トークンの**既定DACL**（`TokenDefaultDacl`）をSDDLで差し替える（S2c＝案A）。
    ///
    /// S2bで残った穴——「起動後にプロセス自身が作ったスレッドは開いたまま」——の出所は、
    /// 新しいカーネルオブジェクトの既定DACLがトークンから来ることだと見ている。
    /// `CREATE_SUSPENDED`の窓で差し替えれば、**後から生えるオブジェクトにも効く**はずである。
    /// この`Option`が`Some`のときだけ、Resumeの直前に`SetTokenInformation`を呼ぶ。
    pub token_default_dacl_sddl: Option<&'a str>,
    /// **AppContainerにしない**（`SECURITY_CAPABILITIES`を積まない）。
    ///
    /// Q1の対照用。「コンソール無しでシェルが動かない」のがAppContainer固有の性質なのか、
    /// Windows一般の性質なのかは、この軸を外した対照を撃たないと決められない（B-29）。
    pub no_appcontainer: bool,
    /// コンソールの与え方（S1で分かれた3つ目の軸）。
    ///
    /// **`CREATE_NO_WINDOW`はコンソールを「隠す」だけで、割り当て自体は行う**——そして
    /// コンソールの割り当ては`conhost.exe`という**子プロセスの生成**を伴う。この軸を
    /// 分けておかないと、`CHILD_PROCESS_RESTRICTED`下の起動失敗が
    /// 「mitigationがコンソールを潰した」のか「別の理由」なのか区別できない（B-29）。
    pub console: SpikeConsole,
}

/// 子へコンソールをどう与えるか。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SpikeConsole {
    /// `CREATE_NO_WINDOW`。**本番の`spawn_impl`が3Tierとも使っている既定**。
    NoWindow,
    /// `DETACHED_PROCESS`。コンソールを一切持たせない。
    Detached,
    /// フラグ無し＝**親のコンソールを継承する**。conhostの生成を伴わない唯一の形。
    Inherit,
}

impl SpikeSpawn<'_> {
    pub(super) fn spawn(&self) -> Result<SpikeChild, String> {
        let step = |label: &str, e: windows::core::Error| format!("{label}: {e}");

        let job = create_job_object().map_err(|e| step("create_job_object", e))?;
        let (stdout_read, stdout_write) =
            create_pipe_with_sddl(SPIKE_PIPE_SDDL).map_err(|e| step("pipe(stdout)", e))?;
        clear_inherit(stdout_read);
        let (stderr_read, stderr_write) =
            create_pipe_with_sddl(SPIKE_PIPE_SDDL).map_err(|e| step("pipe(stderr)", e))?;
        clear_inherit(stderr_read);

        let mut cmdline = format!("\"{}\"", self.exe);
        for a in self.args {
            cmdline.push(' ');
            cmdline.push('"');
            cmdline.push_str(&a.replace('"', "\\\""));
            cmdline.push('"');
        }
        let mut cmdline_w = wide(&cmdline);
        let cwd_w = wide(&self.cwd.to_string_lossy());
        let env = crate::secret_env::build_child_env();
        let mut env_block = build_env_block(&env);

        let mut capabilities_buf: Vec<SID_AND_ATTRIBUTES> = self
            .capabilities
            .iter()
            .map(|sid| SID_AND_ATTRIBUTES {
                Sid: *sid,
                Attributes: SE_GROUP_ENABLED,
            })
            .collect();
        let mut security_capabilities = SECURITY_CAPABILITIES {
            AppContainerSid: self.container_sid,
            Capabilities: if capabilities_buf.is_empty() {
                std::ptr::null_mut()
            } else {
                capabilities_buf.as_mut_ptr()
            },
            CapabilityCount: capabilities_buf.len() as u32,
            Reserved: 0,
        };

        let stdout_handle = self.stdout_override.unwrap_or(stdout_write);
        let mut inherit_handles: Vec<HANDLE> = vec![stdout_handle, stderr_write];
        inherit_handles.extend_from_slice(self.extra_inherit);

        let mut child_policy: u32 = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
        // 属性の本数はこの2つの軸で決まる（数え違えると`UpdateProcThreadAttribute`が
        // `ERROR_INVALID_PARAMETER`で落ちる）。
        let attribute_count: u32 = 1 // HANDLE_LIST（常に積む）
            + u32::from(!self.no_appcontainer) // SECURITY_CAPABILITIES
            + u32::from(self.child_process_restricted); // CHILD_PROCESS_POLICY

        // プロセス／スレッドオブジェクトのDACL（S2bの測定軸）。SDが`CreateProcessW`の
        // 呼び出し中だけ生きていればよいので、この関数のスコープで確保して最後に`LocalFree`する。
        let security_attributes_from =
            |sddl: &str| -> Result<windows::Win32::Security::SECURITY_ATTRIBUTES, String> {
                unsafe {
                    use windows::Win32::Security::Authorization::{
                        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
                    };
                    let sddl_w = wide(sddl);
                    let mut sd = PSECURITY_DESCRIPTOR::default();
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        PCWSTR(sddl_w.as_ptr()),
                        SDDL_REVISION_1,
                        &mut sd,
                        None,
                    )
                    .map_err(|e| step("ConvertStringSecurityDescriptorToSecurityDescriptorW", e))?;
                    Ok(windows::Win32::Security::SECURITY_ATTRIBUTES {
                        nLength: std::mem::size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>(
                        ) as u32,
                        lpSecurityDescriptor: sd.0,
                        bInheritHandle: false.into(),
                    })
                }
            };
        let process_sa = match self.process_sddl {
            Some(sddl) => Some(security_attributes_from(sddl)?),
            None => None,
        };
        let thread_sa = match self.thread_sddl {
            Some(sddl) => Some(security_attributes_from(sddl)?),
            None => None,
        };

        let result: Result<PROCESS_INFORMATION, String> = unsafe {
            let mut attr_list_size: usize = 0;
            let _ = InitializeProcThreadAttributeList(
                LPPROC_THREAD_ATTRIBUTE_LIST::default(),
                attribute_count,
                0,
                &mut attr_list_size,
            );
            let mut attr_list_buf = vec![0u8; attr_list_size];
            let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_list_buf.as_mut_ptr() as *mut c_void);
            InitializeProcThreadAttributeList(attr_list, attribute_count, 0, &mut attr_list_size)
                .map_err(|e| step("InitializeProcThreadAttributeList", e))?;

            let out = (|| -> Result<PROCESS_INFORMATION, String> {
                if !self.no_appcontainer {
                    UpdateProcThreadAttribute(
                        attr_list,
                        0,
                        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                        Some(&mut security_capabilities as *mut _ as *const c_void),
                        std::mem::size_of::<SECURITY_CAPABILITIES>(),
                        None,
                        None,
                    )
                    .map_err(|e| step("UpdateProcThreadAttribute(SECURITY_CAPABILITIES)", e))?;
                }
                UpdateProcThreadAttribute(
                    attr_list,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    Some(inherit_handles.as_mut_ptr() as *const c_void),
                    inherit_handles.len() * std::mem::size_of::<HANDLE>(),
                    None,
                    None,
                )
                .map_err(|e| step("UpdateProcThreadAttribute(HANDLE_LIST)", e))?;
                if self.child_process_restricted {
                    UpdateProcThreadAttribute(
                        attr_list,
                        0,
                        PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY as usize,
                        Some(&mut child_policy as *mut _ as *const c_void),
                        std::mem::size_of::<u32>(),
                        None,
                        None,
                    )
                    .map_err(|e| step("UpdateProcThreadAttribute(CHILD_PROCESS_POLICY)", e))?;
                }

                let startup_info_ex = STARTUPINFOEXW {
                    StartupInfo: STARTUPINFOW {
                        cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                        dwFlags: STARTF_USESTDHANDLES,
                        hStdOutput: stdout_handle,
                        hStdError: stderr_write,
                        hStdInput: INVALID_HANDLE_VALUE,
                        ..Default::default()
                    },
                    lpAttributeList: attr_list,
                };
                let mut process_info = PROCESS_INFORMATION::default();
                let console_flag = match self.console {
                    SpikeConsole::NoWindow => CREATE_NO_WINDOW,
                    SpikeConsole::Detached => windows::Win32::System::Threading::DETACHED_PROCESS,
                    SpikeConsole::Inherit => {
                        windows::Win32::System::Threading::PROCESS_CREATION_FLAGS(0)
                    }
                };
                CreateProcessW(
                    None,
                    PWSTR(cmdline_w.as_mut_ptr()),
                    process_sa.as_ref().map(|sa| sa as *const _),
                    thread_sa.as_ref().map(|sa| sa as *const _),
                    true,
                    EXTENDED_STARTUPINFO_PRESENT
                        | console_flag
                        | CREATE_UNICODE_ENVIRONMENT
                        | CREATE_SUSPENDED,
                    Some(env_block.as_mut_ptr() as *mut _),
                    PCWSTR(cwd_w.as_ptr()),
                    &startup_info_ex.StartupInfo,
                    &mut process_info,
                )
                .map_err(|e| step("CreateProcessW", e))?;
                Ok(process_info)
            })();

            DeleteProcThreadAttributeList(attr_list);
            out
        };

        unsafe {
            let _ = CloseHandle(stdout_write);
            let _ = CloseHandle(stderr_write);
            for sa in [process_sa.as_ref(), thread_sa.as_ref()]
                .into_iter()
                .flatten()
            {
                let _ = LocalFree(HLOCAL(sa.lpSecurityDescriptor));
            }
        }

        let process_info = match result {
            Ok(pi) => pi,
            Err(e) => {
                unsafe {
                    let _ = CloseHandle(job);
                    let _ = CloseHandle(stdout_read);
                    let _ = CloseHandle(stderr_read);
                }
                return Err(e);
            }
        };

        unsafe {
            // suspendedのうちにJobへ入れてからResumeする（`spawn_impl`と同じ順序。
            // 起こす前に割り当てないと、子がJobの外で孫を作れる窓ができる）。
            if let Err(e) = AssignProcessToJobObject(job, process_info.hProcess) {
                let _ = TerminateProcess(process_info.hProcess, 1);
                let _ = CloseHandle(process_info.hThread);
                let _ = CloseHandle(process_info.hProcess);
                let _ = CloseHandle(job);
                let _ = CloseHandle(stdout_read);
                let _ = CloseHandle(stderr_read);
                return Err(step("AssignProcessToJobObject", e));
            }

            // S2c（案A）: **Resumeする前に**トークンの既定DACLを差し替える。
            // ここを窓に選ぶ理由は、子がまだ1つもオブジェクトを作っていないからである
            // ——起動後に差し替えると、それまでに生えたスレッドは古い既定DACLのまま残る。
            if let Some(sddl) = self.token_default_dacl_sddl {
                use windows::Win32::Security::Authorization::{
                    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
                };
                use windows::Win32::Security::{
                    GetSecurityDescriptorDacl, SetTokenInformation, TokenDefaultDacl,
                    TOKEN_ADJUST_DEFAULT, TOKEN_DEFAULT_DACL,
                };
                let sddl_w = wide(sddl);
                let mut sd = PSECURITY_DESCRIPTOR::default();
                if let Err(e) = ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    PCWSTR(sddl_w.as_ptr()),
                    SDDL_REVISION_1,
                    &mut sd,
                    None,
                ) {
                    let _ = TerminateProcess(process_info.hProcess, 1);
                    return Err(step("ConvertStringSecurityDescriptor(default dacl)", e));
                }
                let mut dacl: *mut windows::Win32::Security::ACL = std::ptr::null_mut();
                let mut present = windows::Win32::Foundation::BOOL::from(false);
                let mut defaulted = windows::Win32::Foundation::BOOL::from(false);
                let dacl_ok =
                    GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted);
                let mut token = HANDLE::default();
                let token_ok = OpenProcessToken(
                    process_info.hProcess,
                    TOKEN_ADJUST_DEFAULT | TOKEN_QUERY,
                    &mut token,
                );
                let set = match (dacl_ok, token_ok) {
                    (Ok(()), Ok(())) => {
                        let info = TOKEN_DEFAULT_DACL { DefaultDacl: dacl };
                        SetTokenInformation(
                            token,
                            TokenDefaultDacl,
                            &info as *const _ as *const c_void,
                            std::mem::size_of::<TOKEN_DEFAULT_DACL>() as u32,
                        )
                    }
                    (Err(e), _) => Err(e),
                    (_, Err(e)) => Err(e),
                };
                let _ = CloseHandle(token);
                let _ = LocalFree(HLOCAL(sd.0));
                if let Err(e) = set {
                    // **失敗を握り潰さない**（B-10）。既定DACLが差し替わっていないのに
                    // 起動を続けると、「案Aが効いた」を測っているつもりで素の状態を測る。
                    let _ = TerminateProcess(process_info.hProcess, 1);
                    let _ = CloseHandle(process_info.hThread);
                    let _ = CloseHandle(process_info.hProcess);
                    let _ = CloseHandle(job);
                    let _ = CloseHandle(stdout_read);
                    let _ = CloseHandle(stderr_read);
                    return Err(step("SetTokenInformation(TokenDefaultDacl)", e));
                }
            }

            let _ = ResumeThread(process_info.hThread);
            let _ = CloseHandle(process_info.hThread);
        }

        Ok(SpikeChild {
            process: process_info.hProcess,
            job,
            pid: process_info.dwProcessId,
            thread_id: process_info.dwThreadId,
            stdout_read,
            stderr_read,
        })
    }
}

/// `tier2a_proc_probe.exe`（テストバイナリの隣）。無ければビルド手順を添えて落ちる。
pub(super) fn probe_exe() -> PathBuf {
    let current = std::env::current_exe().expect("current_exe");
    let dir = current
        .parent()
        .expect("current_exe has parent")
        .to_path_buf();
    let exe = dir.join("tier2a_proc_probe.exe");
    assert!(
        exe.exists(),
        "tier2a_proc_probe.exe not found at {} (build it with `cargo build -p tier2a-proc-probe` \
         and copy it next to the test binary; see docs/DEV-ENVIRONMENT.md)",
        exe.display()
    );
    exe
}

/// このworkspaceのcapability SID（`test_support::spawn_in_workspace`と同じ引き方）。
/// `preflight`が張ったworkspaceツリーのACEの主体で、これを積まないと子はworkspaceを見られない。
///
/// **[D-83] モードを`rwx`に固定してある。** 以前は「台帳に載っている方」を探していたが、
/// D-83で両モードのバッジが常に載るようになり、探索は意味を失った（必ず先頭が当たる）。
/// このスパイク群のworkspaceは全て`WorkspaceWriteMode::DirectRw`で`preflight`しているので
/// `rwx`が正しい——**CoWのスパイクをここへ足すときは`ro`を選ぶこと**（`rwx`のバッジを
/// 積んだ子はworkspace本体へ直接書けてしまい、測っている隔離が別物になる）。
pub(super) fn workspace_capability_for(workspace: &Path) -> Option<crate::win_common::OwnedSid> {
    let canonical = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.to_path_buf());
    let mode = crate::tier2a::workspace_ledger::WorkspaceMode::Rwx;
    crate::tier2a::workspace_capability::lookup_capability_name(&canonical, mode.as_str())
        .and_then(|_| workspace_capability_sid(&canonical, mode.as_str()).ok())
}

/// スパイクが作ったworkspace capabilityの台帳エントリを落とす（使い捨てworkspaceの記録が
/// 積もらないように）。**ACEはworkspaceごと消えるので、順序の不変条件
/// （ACEを剥がしてから台帳を消す）は満たされている。**
pub(super) fn forget_workspace_capability(workspace: &Path) {
    let canonical = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.to_path_buf());
    let _ = crate::tier2a::workspace_capability::forget_capability(&canonical, "");
}

/// 子のstdoutに流れたJSON（最終行）を取り出す。プローブは1行のJSONを出す約束だが、
/// 前置きが混ざり得るので**最後に現れたJSON行**を採る（`tier2a-proc-probe`が孫の出力を
/// 拾うときと同じ作法、B-33）。
pub(super) fn last_json_line(stdout: &str) -> Option<serde_json::Value> {
    stdout
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str(line.trim()).ok())
}

// ---------------------------------------------------------------------------
// S1: CHILD_PROCESS_RESTRICTEDの強制力（§20項目1・未解決7）
// ---------------------------------------------------------------------------

/// 制限あり／なしの**対**で回し、「制限なしでは通る経路が、制限ありでは通らない」という
/// 差だけを結論に使う（B-35）。拒否側だけを見ると、機構が効いているのか**プローブ自身が
/// 壊れている**のかを区別できない——特に`ntcreateuserprocess`は未文書構造体を手で組むので、
/// 実装を誤れば制限の有無に関わらず失敗する。
///
/// 判定は**マーカーファイルの有無**で行う（B-25）。`WinExec`のように生成の成否を返さない
/// APIがあり、APIの戻り値だけでは「拒否された」と「起動して何もしなかった」を区別できない。
#[test]
#[ignore = "spawns real AppContainer children and creates a session profile; run NON-elevated with --test-threads=1"]
fn child_process_restricted_denies_every_direct_creation_path() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let _cleanup =
        super::test_support::scopeguard(|| forget_workspace_capability(workspace.path()));

    let sid = session_sid();
    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
    grant_job::wait_until_done().expect("background grant job");

    let traverse = traverse_capability_sid().expect("traverse capability");
    let workspace_cap = workspace_capability_for(workspace.path());
    let mut capabilities = vec![traverse.as_psid()];
    if let Some(cap) = &workspace_cap {
        capabilities.push(cap.as_psid());
    }

    let probe = probe_exe();
    let probe_str = probe
        .to_str()
        .expect("probe path is valid utf-8")
        .to_string();

    // --- 素の可用性（設計書§20項目1には無いが、Daemonが代理すべき生成の一覧を出すのに要る）
    // mitigationを積んだだけで**そのプロセス自身が動かなくなる**種類があるかを先に測る。
    // ここを飛ばすと、後段の「マーカーが無い＝生成が拒否された」が
    // 「そもそもプローブが起動していない」と区別できない（B-27/B-29）。
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let cmd_exe = format!("{system_root}\\System32\\cmd.exe");
    let (shell, shell_label) = resolve_shell();
    let canaries: Vec<(&str, String, Vec<&str>)> = vec![
        ("cmd.exe", cmd_exe.clone(), vec!["/c", "exit 7"]),
        (
            shell_label,
            shell.clone(),
            vec!["-NoProfile", "-NonInteractive", "-Command", "exit 7"],
        ),
        // コンソール無しでシェルが**コマンドを実行したか**を出力で確かめる。終了コードだけを
        // 見ていると「動いていないのに0」を成功と読む（B-09: 0件と成功を同じ値へ潰さない）。
        (
            "shell+stdout",
            shell.clone(),
            vec![
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Write-Output SHELL-RAN; exit 7",
            ],
        ),
        ("tier2a_proc_probe", probe_str.clone(), vec!["--emit", "ok"]),
    ];
    let mut canary_results: Vec<(String, bool, SpikeConsole, i32, String)> = Vec::new();
    for (label, exe, args) in &canaries {
        for restricted in [false, true] {
            for console in [
                SpikeConsole::NoWindow,
                SpikeConsole::Detached,
                SpikeConsole::Inherit,
            ] {
                let mut child = SpikeSpawn {
                    exe,
                    args,
                    cwd: workspace.path(),
                    container_sid: sid.as_psid(),
                    capabilities: &capabilities,
                    child_process_restricted: restricted,
                    stdout_override: None,
                    extra_inherit: &[],
                    process_sddl: None,
                    thread_sddl: None,
                    token_default_dacl_sddl: None,
                    no_appcontainer: false,
                    console,
                }
                .spawn()
                .unwrap_or_else(|e| {
                    panic!(
                        "spawn canary {label} (restricted={restricted} console={console:?}): {e}"
                    )
                });
                let (out, err, code) = child.wait_and_read();
                eprintln!(
                    "[S1/canary] {label} restricted={restricted} console={console:?} \
                     exit={code} (0x{:08X}) out={out:?} err={err:?}",
                    code as u32
                );
                canary_results.push(((*label).to_string(), restricted, console, code, out));
            }
        }
    }

    // **この行列そのものが結論である**（RESULTS.md §S1）。
    // `CREATE_NO_WINDOW`はコンソールを隠すだけで割り当てはする。コンソールの割り当ては
    // `conhost.exe`の生成を伴うため、`CHILD_PROCESS_RESTRICTED`下では**プロセス自身が
    // 起動できずに`0xC0000142`（STATUS_DLL_INIT_FAILED）で死ぬ**。
    // 本番の`spawn_impl`は3Tierとも`CREATE_NO_WINDOW`で起こしているので、mitigationを
    // 入れるなら`DETACHED_PROCESS`への変更が**対で**要る。
    let canary = |label: &str, restricted: bool, console: SpikeConsole| -> Option<(i32, String)> {
        canary_results
            .iter()
            .find(|(l, r, c, _, _)| l == label && *r == restricted && *c == console)
            .map(|(_, _, _, code, out)| (*code, out.clone()))
    };
    const STATUS_DLL_INIT_FAILED: i32 = -1_073_741_502; // 0xC0000142
    assert_eq!(
        canary("tier2a_proc_probe", true, SpikeConsole::NoWindow).map(|(code, _)| code),
        Some(STATUS_DLL_INIT_FAILED),
        "CREATE_NO_WINDOW（本番の既定）＋CHILD_PROCESS_RESTRICTEDで起動できてしまった。\
         この観測が変わったなら、RESULTS.md §S1の結論（conhost生成が拒否される）を測り直すこと。\
         canaries={canary_results:?}"
    );
    assert_eq!(
        canary("tier2a_proc_probe", true, SpikeConsole::Detached).map(|(code, _)| code),
        Some(0),
        "DETACHED_PROCESS＋CHILD_PROCESS_RESTRICTEDでも起動できない。この経路が塞がると、\
         mitigationを積んだままCLIを動かす手段が無くなる。canaries={canary_results:?}"
    );
    // **CLI互換性の本丸**（§20項目2の前提）。シェルは終了コードだけを見ると
    // 「動いていないのに0」を成功と読むので、**出力で走ったことを確かめる**（B-09）。
    let shell_runs = |console: SpikeConsole| -> bool {
        canary("shell+stdout", true, console)
            .map(|(_, out)| out.contains("SHELL-RAN"))
            .unwrap_or(false)
    };
    eprintln!(
        "[S1] mitigation下でシェルがコマンドを実行できるコンソール構成: NoWindow={} Detached={} Inherit={}",
        shell_runs(SpikeConsole::NoWindow),
        shell_runs(SpikeConsole::Detached),
        shell_runs(SpikeConsole::Inherit),
    );

    let mut runs: Vec<(bool, std::collections::BTreeSet<String>, serde_json::Value)> = Vec::new();
    for restricted in [false, true] {
        let marker_dir = workspace.path().join(if restricted {
            "markers-restricted"
        } else {
            "markers-control"
        });
        std::fs::create_dir_all(&marker_dir).expect("marker dir");
        let marker_dir_str = marker_dir.to_string_lossy().into_owned();

        let mut child = SpikeSpawn {
            exe: &probe_str,
            args: &["--spawn-matrix", &marker_dir_str, "--timeout-secs", "180"],
            cwd: workspace.path(),
            container_sid: sid.as_psid(),
            capabilities: &capabilities,
            child_process_restricted: restricted,
            stdout_override: None,
            extra_inherit: &[],
            process_sddl: None,
            thread_sddl: None,
            token_default_dacl_sddl: None,
            no_appcontainer: false,
            // 上の行列で分かったとおり、mitigation下ではコンソールを割り当てられない。
            // **両方の実行を`DETACHED_PROCESS`に揃える**——揃えないと、比べているのが
            // mitigationの効果ではなくコンソールの有無になる（対照の条件を1つに絞る、B-29）。
            console: SpikeConsole::Detached,
        }
        .spawn()
        .unwrap_or_else(|e| panic!("spawn probe (restricted={restricted}): {e}"));

        let (stdout, stderr, code) = child.wait_and_read();
        eprintln!("[S1] restricted={restricted} exit={code}\nstdout={stdout}\nstderr={stderr}");
        let report = last_json_line(&stdout).unwrap_or_else(|| {
            panic!("probe produced no JSON (restricted={restricted}): {stdout}")
        });

        let markers: std::collections::BTreeSet<String> = std::fs::read_dir(&marker_dir)
            .expect("read marker dir")
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                e.path()
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
            })
            .collect();
        runs.push((restricted, markers, report));
    }

    let (_, control_markers, control_report) = &runs[0];
    let (_, restricted_markers, restricted_report) = &runs[1];

    eprintln!("[S1] control markers   = {control_markers:?}");
    eprintln!("[S1] restricted markers= {restricted_markers:?}");
    eprintln!("[S1] control report    = {control_report}");
    eprintln!("[S1] restricted report = {restricted_report}");

    // プローブ自身の検算（B-05）: 宣言した経路を全部試したか。
    for (restricted, _, report) in &runs {
        let missing = report
            .get("methods_missing")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(usize::MAX);
        assert_eq!(
            missing, 0,
            "the probe did not attempt every declared method (restricted={restricted}): {report}"
        );
    }

    // 土台の確認（B-27）: 制限なしで1つも子が生まれないなら、測っているのはmitigationではない。
    assert!(
        control_markers.contains("createprocessw"),
        "the control run created no child via CreateProcessW; the spike setup itself is broken \
         (workspace capability? probe exe reachable?) -- nothing below can be trusted"
    );

    // 本題: 制限なしで通った経路が、制限ありでも通っていないか。
    let leaked: Vec<&String> = restricted_markers
        .iter()
        .filter(|m| control_markers.contains(*m))
        .collect();
    assert!(
        leaked.is_empty(),
        "these creation paths still produced a child under CHILD_PROCESS_RESTRICTED: {leaked:?}\n\
         §9（Hook bypass ≠ Sandbox escape）はこれらの経路については成立していない。\n\
         control={control_markers:?} restricted={restricted_markers:?}"
    );

    // タスクスケジューラは到達性の段までしか実装していない（プローブのdoc参照）。
    // **到達できたのに「生成できない」と書かない**ため、到達できたらここで落とす（fail-closed）。
    let task_reachable = restricted_report
        .get("attempts")
        .and_then(|a| a.as_array())
        .map(|attempts| {
            attempts.iter().any(|a| {
                a.get("method").and_then(|m| m.as_str()) == Some("taskscheduler")
                    && a.get("api_ok").and_then(|o| o.as_bool()) == Some(true)
            })
        })
        .unwrap_or(false);
    assert!(
        !task_reachable,
        "ITaskService::Connect succeeded from inside the AppContainer. The probe only measures \
         reachability for this route -- extend it to actually register and run a task before \
         concluding anything about brokered creation via the task scheduler."
    );
}

// ---------------------------------------------------------------------------
// S2: AppContainerのdefault-denyはどのオブジェクト型まで及ぶか（§20項目10・最優先）
// ---------------------------------------------------------------------------

/// ユーザー専有DACLの名前付きパイプを1本立て、サンドボックスから到達できるかを測る的にする。
/// **これは§10.1が「制御パイプはユーザーSID専有で足りる」と書いている前提そのもの**である。
fn user_only_pipe() -> (String, HANDLE) {
    use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    let name = crate::win_pipe_ipc::unique_pipe_name("mac-spike-useronly");
    let sid = crate::win_pipe_ipc::current_user_sid_string().expect("current user sid");
    let mut sa =
        crate::win_pipe_ipc::user_only_security_attributes(&sid).expect("user-only security attrs");
    let name_w = wide(&name);
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(name_w.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            16,
            4096,
            4096,
            0,
            Some(&mut sa as *const _),
        )
    };
    assert!(!handle.is_invalid(), "could not create the user-only pipe");
    (name, handle)
}

/// 同一package SID内（＝§22.8が引き受けたリスク）と、別package SID（MCPプロファイル）から、
/// 各種カーネルオブジェクトへ到達できるかを型ごとに測る。
///
/// **判定は「実際に開けたか」**（B-25）。表はRESULTS.mdへ転記する。
#[test]
#[ignore = "spawns real AppContainer children and creates session/MCP profiles; run NON-elevated with --test-threads=1"]
fn appcontainer_default_deny_across_object_types() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let _cleanup =
        super::test_support::scopeguard(|| forget_workspace_capability(workspace.path()));

    let sid = session_sid();
    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
    grant_job::wait_until_done().expect("background grant job");

    let traverse = traverse_capability_sid().expect("traverse capability");
    let workspace_cap = workspace_capability_for(workspace.path());
    let mut caps_with_workspace = vec![traverse.as_psid()];
    if let Some(cap) = &workspace_cap {
        caps_with_workspace.push(cap.as_psid());
    }

    let probe = probe_exe();
    let probe_str = probe
        .to_str()
        .expect("probe path is valid utf-8")
        .to_string();

    // 的その1: 別ドメイン役のプロセス（同じpackage SID、workspace capability付き）。
    let target = SpikeSpawn {
        exe: &probe_str,
        args: &["--idle-secs", "25", "--timeout-secs", "60"],
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &caps_with_workspace,
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
    .expect("spawn the target child");
    let target_pid = target.pid();
    let target_tid = target.thread_id();

    // 的その2: ユーザー専有DACLの名前付きパイプ。
    let (pipe_name, pipe_handle) = user_only_pipe();
    let _pipe_guard = super::test_support::scopeguard(|| unsafe {
        let _ = CloseHandle(pipe_handle);
    });

    // 的その3: 名前付きカーネルオブジェクト。AppContainerは**自分専用の名前空間**を持つ
    // 可能性があり、その場合は「拒否(5)」ではなく「見つからない(2)」が返る——どちらなのかは
    // エラーコードで区別できるので、両方の綴り（素の名前と`Global\`）を撃たせる。
    let object_suffix = format!("harness-mac-spike-{}", std::process::id());
    let mutex_name = format!("{object_suffix}-mutex");
    let event_name = format!("{object_suffix}-event");
    let mutex_w = wide(&mutex_name);
    let event_w = wide(&event_name);
    let (mutex, event) = unsafe {
        use windows::Win32::System::Threading::{CreateEventW, CreateMutexW};
        (
            CreateMutexW(None, false, PCWSTR(mutex_w.as_ptr())).expect("create mutex"),
            CreateEventW(None, true, false, PCWSTR(event_w.as_ptr())).expect("create event"),
        )
    };
    let _objects_guard = super::test_support::scopeguard(|| unsafe {
        let _ = CloseHandle(mutex);
        let _ = CloseHandle(event);
    });

    let reach_args: Vec<String> = vec![
        "--reach-process".into(),
        target_pid.to_string(),
        "--reach-thread".into(),
        target_tid.to_string(),
        "--reach-pipe".into(),
        pipe_name.clone(),
        "--reach-create-pipe-instance".into(),
        pipe_name.clone(),
        "--reach-object".into(),
        format!("mutex:{mutex_name}"),
        "--reach-object".into(),
        format!("mutex:Global\\{mutex_name}"),
        "--reach-object".into(),
        format!("event:{event_name}"),
        "--timeout-secs".into(),
        "60".into(),
    ];
    let reach_args_ref: Vec<&str> = reach_args.iter().map(|s| s.as_str()).collect();

    // --- 観測1: 同一package SID・別ドメイン（workspace capabilityを持たない） ---
    let mut same_package = SpikeSpawn {
        exe: &probe_str,
        args: &reach_args_ref,
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &[traverse.as_psid()],
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
    .expect("spawn the same-package probe");
    let (same_stdout, same_stderr, same_code) = same_package.wait_and_read();
    eprintln!("[S2] same package SID: exit={same_code} stderr={same_stderr}\n{same_stdout}");
    let same_report = last_json_line(&same_stdout)
        .unwrap_or_else(|| panic!("same-package probe produced no JSON: {same_stdout}"));

    // --- 観測2: 別package SID（MCPプロファイル、D-38） ---
    let mcp = preflight_mcp_server(&McpPreflightRequest {
        server_id: "macspike",
        command: &probe,
        arg_paths: &[],
        workspace: None,
    })
    .expect("mcp preflight");
    let mcp_sid = ensure_profile(&mcp.profile_name).expect("mcp profile sid");
    let mcp_cwd = tempfile::tempdir().expect("mcp cwd");
    grant_ace_inheritable_access(mcp_cwd.path(), mcp_sid.as_psid(), FsAccess::ReadExec)
        .expect("grant mcp cwd");

    let mut other_package = SpikeSpawn {
        exe: &probe_str,
        args: &reach_args_ref,
        cwd: mcp_cwd.path(),
        container_sid: mcp_sid.as_psid(),
        capabilities: &[traverse.as_psid()],
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
    .expect("spawn the mcp-package probe");
    let (mcp_stdout, mcp_stderr, mcp_code) = other_package.wait_and_read();
    eprintln!("[S2] other package SID (MCP): exit={mcp_code} stderr={mcp_stderr}\n{mcp_stdout}");
    let mcp_report = last_json_line(&mcp_stdout)
        .unwrap_or_else(|| panic!("mcp-package probe produced no JSON: {mcp_stdout}"));

    // 後始末は判定より先に（assertで落ちてもプロファイルを残さない、mcp_e2e_testsと同じ作法）。
    drop(target);
    unsafe {
        let w = wide(&mcp.profile_name);
        let _ = windows::Win32::Security::Isolation::DeleteAppContainerProfile(PCWSTR(w.as_ptr()));
    }

    let find = |report: &serde_json::Value, kind: &str, access: &str| -> Option<bool> {
        report
            .get("attempts")?
            .as_array()?
            .iter()
            .find(|a| {
                a.get("kind").and_then(|k| k.as_str()) == Some(kind)
                    && a.get("access").and_then(|k| k.as_str()) == Some(access)
            })
            .and_then(|a| a.get("ok").and_then(|o| o.as_bool()))
    };

    // 設計が前提にしている予測を明示的に固定する。**破れたらここで落ちる**——
    // そのときは設計側（§22.8・§10.1・§22.6.2の適用範囲）を書き換える合図である。
    let vm_write_same = find(&same_report, "process", "PROCESS_VM_WRITE");
    let create_thread_same = find(&same_report, "process", "PROCESS_CREATE_THREAD");
    let dup_handle_same = find(&same_report, "process", "PROCESS_DUP_HANDLE");
    eprintln!(
        "[S2] same package: VM_WRITE={vm_write_same:?} CREATE_THREAD={create_thread_same:?} \
         DUP_HANDLE={dup_handle_same:?}"
    );
    // **実測はこうだった（2026-08-13）**: 同一package SID内では`PROCESS_ALL_ACCESS`まで通る。
    // §22.8が「実測待ち」として引き受けたリスクは**現実だった**——capability群だけでは
    // ドメイン越境（コード注入）を止められない。結論はRESULTS.md §S2、設計側の帰結は
    // 設計書§22.8・§22.1へ書く。ここでは**測った事実**を固定して、逆向きの変化
    // （将来のWindowsで塞がる／こちらの構成が変わる）にも気付けるようにする。
    assert_eq!(
        vm_write_same,
        Some(true),
        "同一package SID内の PROCESS_VM_WRITE が拒否されるようになった。RESULTS.md §S2の\
         結論（capability群はプロセス相互アクセスを止めない）を測り直すこと。report={same_report}"
    );
    let vm_write_mcp = find(&mcp_report, "process", "PROCESS_VM_WRITE");
    let query_mcp = find(&mcp_report, "process", "PROCESS_QUERY_LIMITED_INFORMATION");
    eprintln!("[S2] other package: VM_WRITE={vm_write_mcp:?} QUERY_LIMITED={query_mcp:?}");
    assert_eq!(
        query_mcp,
        Some(false),
        "別package SID（MCPプロファイル）からプロセスを開けた。プロファイル分離（D-38）が\
         効いていないことになる。report={mcp_report}"
    );

    let pipe_same = find(&same_report, "pipe-open", "GENERIC_READ|GENERIC_WRITE");
    let pipe_mcp = find(&mcp_report, "pipe-open", "GENERIC_READ|GENERIC_WRITE");
    eprintln!("[S2] user-only pipe reachable? same={pipe_same:?} mcp={pipe_mcp:?}");
    assert_eq!(
        pipe_same,
        Some(false),
        "ユーザー専有DACLの名前付きパイプへAppContainerから到達できた。§10.1が\
         「制御パイプはユーザーSID専有で足りる」と書いた前提が崩れる。report={same_report}"
    );
    assert_eq!(
        pipe_mcp,
        Some(false),
        "別プロファイル（MCP）からもユーザー専有パイプへ到達できた。report={mcp_report}"
    );

    let instance_same = find(&same_report, "pipe-create-instance", "PIPE_ACCESS_DUPLEX");
    eprintln!("[S2] additional pipe instance creatable? same={instance_same:?}");
    assert_eq!(
        instance_same,
        Some(false),
        "サンドボックスから同名パイプの追加インスタンスを作れた（サーバ偽装が成立する）。\
         §10.1の`FILE_FLAG_FIRST_PIPE_INSTANCE`＋マスク制限だけでは足りない。report={same_report}"
    );
}

// ---------------------------------------------------------------------------
// S2b: プロセスオブジェクトのDACLで、同一package SID内の相互アクセスを塞げるか
// ---------------------------------------------------------------------------

/// S2で「同一package SID内は`PROCESS_ALL_ACCESS`まで通る」ことが分かった。これは
/// 「ドメイン＝同一package SID内のcapability群」（§22.1）が**コード注入に対しては
/// 境界にならない**ことを意味する。§22.8はドメインごとの別package SIDを却下しているので、
/// 却下を維持するなら**別の追加機構**が要る。
///
/// その候補が「子プロセスオブジェクト自身のDACLから package SID を外す」ことである
/// （`CreateProcessW`の`lpProcessAttributes`）。ここで測るのは次の3点。
///
/// 1. そのDACLでもプロセスが**正常に起動して動く**か（可用性を壊さないか）
/// 2. 同一package SIDの別プロセスから`OpenProcess`が**拒否される**か（穴が閉じるか）
/// 3. 生成した側（harness/Daemon役）は引き続き**待てる・殺せる**か
///
/// **1と3が壊れるなら、この候補は使えない**——だから対で測る（B-35）。
#[test]
#[ignore = "spawns real AppContainer children; run NON-elevated with --test-threads=1"]
fn s2b_a_custom_process_dacl_can_close_the_same_package_open_process_hole() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let _cleanup =
        super::test_support::scopeguard(|| forget_workspace_capability(workspace.path()));

    let sid = session_sid();
    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
    grant_job::wait_until_done().expect("background grant job");

    let traverse = traverse_capability_sid().expect("traverse capability");
    let workspace_cap = workspace_capability_for(workspace.path());
    let mut capabilities = vec![traverse.as_psid()];
    if let Some(cap) = &workspace_cap {
        capabilities.push(cap.as_psid());
    }

    let probe = probe_exe();
    let probe_str = probe
        .to_str()
        .expect("probe path is valid utf-8")
        .to_string();

    // 的: **ユーザーSIDだけ**を許すDACLを持つプロセス（package SIDのACEを持たない）。
    let user_sid = crate::win_pipe_ipc::current_user_sid_string().expect("current user sid");
    let process_sddl = format!("D:(A;;GA;;;{user_sid})");
    let target_report = workspace.path().join("s2b-target.json");
    let target_report_str = target_report.to_string_lossy().into_owned();
    let target = SpikeSpawn {
        exe: &probe_str,
        args: &[
            "--idle-secs",
            "20",
            "--timeout-secs",
            "60",
            "--report-file",
            &target_report_str,
        ],
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &capabilities,
        child_process_restricted: false,
        stdout_override: None,
        extra_inherit: &[],
        process_sddl: Some(&process_sddl),
        // **対で絞る**（S2bの1回目の実測: プロセスだけ絞ってもスレッドは開けた）。
        thread_sddl: Some(&process_sddl),
        token_default_dacl_sddl: None,
        no_appcontainer: false,
        console: SpikeConsole::NoWindow,
    }
    .spawn()
    .expect("spawn the hardened target child");
    let target_pid = target.pid();
    let target_tid = target.thread_id();

    // (1) 起動して動いているか（`GetExitCodeProcess`が`STILL_ACTIVE`＝259を返すこと）。
    // **「起動できた」を`CreateProcessW`の成功だけで判定しない**——0xC0000142のように
    // 生成には成功して初期化で死ぬ形があるため（S1で実際に踏んだ）。
    std::thread::sleep(std::time::Duration::from_millis(800));
    let mut code: u32 = 0;
    let alive = unsafe {
        let _ = GetExitCodeProcess(target.process(), &mut code);
        code == 259
    };
    eprintln!("[S2b] hardened target: pid={target_pid} alive={alive} exit_code={code}");

    // 起動**後**に生えたスレッドのIDを的に加える。`lpThreadAttributes`は最初の1本にしか
    // 効かないので、ここが開いていれば「プロセスとスレッドのDACLを絞る」候補は不完全である。
    let mut extra_tid: u64 = 0;
    for _ in 0..40 {
        if let Ok(body) = std::fs::read_to_string(&target_report) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                extra_tid = v
                    .get("extra_thread_id")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0);
                if extra_tid != 0 {
                    break;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    eprintln!("[S2b] target main tid={target_tid} extra tid={extra_tid}");

    let reach_args: Vec<String> = vec![
        "--reach-process".into(),
        target_pid.to_string(),
        "--reach-thread".into(),
        target_tid.to_string(),
        "--reach-thread".into(),
        extra_tid.to_string(),
        "--timeout-secs".into(),
        "60".into(),
    ];
    let reach_args_ref: Vec<&str> = reach_args.iter().map(|s| s.as_str()).collect();
    let mut attacker = SpikeSpawn {
        exe: &probe_str,
        args: &reach_args_ref,
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &[traverse.as_psid()],
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
    .expect("spawn the attacker probe");
    let (stdout, stderr, _code) = attacker.wait_and_read();
    eprintln!("[S2b] attacker report: {stdout}\nstderr={stderr}");
    let report = last_json_line(&stdout)
        .unwrap_or_else(|| panic!("attacker probe produced no JSON: {stdout}"));

    // (3) 生成した側は引き続き殺せるか（Dropのjob closeで畳めること）。
    drop(target);

    let find_target = |kind: &str, access: &str, target: &str| -> Option<bool> {
        report
            .get("attempts")?
            .as_array()?
            .iter()
            .find(|a| {
                a.get("kind").and_then(|k| k.as_str()) == Some(kind)
                    && a.get("access").and_then(|k| k.as_str()) == Some(access)
                    && a.get("target").and_then(|k| k.as_str()) == Some(target)
            })
            .and_then(|a| a.get("ok").and_then(|o| o.as_bool()))
    };
    let find = |kind: &str, access: &str| -> Option<bool> {
        report
            .get("attempts")?
            .as_array()?
            .iter()
            .find(|a| {
                a.get("kind").and_then(|k| k.as_str()) == Some(kind)
                    && a.get("access").and_then(|k| k.as_str()) == Some(access)
            })
            .and_then(|a| a.get("ok").and_then(|o| o.as_bool()))
    };
    let extra_thread_open = find_target("thread", "THREAD_ALL_ACCESS", &extra_tid.to_string());
    eprintln!(
        "[S2b] 起動後に生えたスレッド({extra_tid})を THREAD_ALL_ACCESS で開けたか: \
         {extra_thread_open:?}"
    );

    assert!(
        alive,
        "package SIDのACEを持たないDACLで起動したプロセスが動いていない（exit_code={code}）。\
         この候補機構は可用性を壊すので使えない。"
    );
    assert_eq!(
        find("process", "PROCESS_VM_WRITE"),
        Some(false),
        "プロセスオブジェクトのDACLからpackage SIDを外しても、同一package SIDの別プロセスから\
         PROCESS_VM_WRITEで開けてしまう。この候補では§22.8の穴を塞げない。report={report}"
    );
    assert_eq!(
        find_target("thread", "THREAD_ALL_ACCESS", &target_tid.to_string()),
        Some(false),
        "プロセスのDACLを絞ってもスレッドは開けてしまう（スレッドオブジェクトのDACLは別物）。\
         塞ぐならスレッド側にも同じ手当てが要る。report={report}"
    );
    // **候補機構の限界**: `lpThreadAttributes`が効くのは最初のスレッドだけである。
    // 起動後にプロセス自身が作ったスレッドは既定のDACLを持つので、そこが開いていれば
    // `SetThreadContext`経由の乗っ取りが残り、この候補だけでは§22.8の穴は閉じない。
    // **実測をそのまま固定する**（値が逆になったら結論を測り直す合図）。
    assert_eq!(
        extra_thread_open,
        Some(true),
        "起動後に生えたスレッドが開けなくなった。RESULTS.md §S2bの結論\
         （lpThreadAttributesは最初の1本にしか効かない）を測り直すこと。report={report}"
    );
}
