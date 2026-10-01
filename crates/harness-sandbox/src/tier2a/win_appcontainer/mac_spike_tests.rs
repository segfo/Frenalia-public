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
//!   注入するプロセスのDaemon移管）が揃った後、という着手順序の拘束がある
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
    /// 測定用のコンソール保持プロセス。新しいコンソールを作るが、ウィンドウは表示しない。
    ///
    /// §7.1.1の本命は[`Self::NoWindow`]である。この腕は、本命が失敗したときに
    /// `AttachConsole`以降の計器まで壊れているのかを分ける対照にだけ使う。
    NewHidden,
}

impl SpikeSpawn<'_> {
    /// 起こして**すぐ動かす**（このスパイク群の既定）。
    ///
    /// `CREATE_SUSPENDED`で作ってから即Resumeする形は変えていない——変えたのは
    /// 「Resumeをいつ撃つか」を呼び出し側が選べるようにしたことだけである
    /// （§7.1.1のコンソール貸与では、Resumeが**コンソールを借りている窓の内側か外側か**が
    /// 測定軸になる。窓の外でResumeすると、DLL初期化＝§7.1が`0xC0000142`を観測した場所が
    /// `FreeConsole`の後に来る）。
    pub(super) fn spawn(&self) -> Result<SpikeChild, String> {
        Ok(self.spawn_suspended()?.resume())
    }

    /// 起こすが**まだ動かさない**。呼び出し側が[`SuspendedSpikeChild::resume`]を撃つまで、
    /// 子は`CREATE_SUSPENDED`のまま止まっている。
    pub(super) fn spawn_suspended(&self) -> Result<SuspendedSpikeChild, String> {
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

                let (console_flag, hide_console_window) = match self.console {
                    SpikeConsole::NoWindow => (CREATE_NO_WINDOW, false),
                    SpikeConsole::Detached => {
                        (windows::Win32::System::Threading::DETACHED_PROCESS, false)
                    }
                    SpikeConsole::Inherit => (
                        windows::Win32::System::Threading::PROCESS_CREATION_FLAGS(0),
                        false,
                    ),
                    SpikeConsole::NewHidden => {
                        (windows::Win32::System::Threading::CREATE_NEW_CONSOLE, true)
                    }
                };
                let startup_flags = if hide_console_window {
                    STARTF_USESTDHANDLES | windows::Win32::System::Threading::STARTF_USESHOWWINDOW
                } else {
                    STARTF_USESTDHANDLES
                };
                let startup_info_ex = STARTUPINFOEXW {
                    StartupInfo: STARTUPINFOW {
                        cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                        dwFlags: startup_flags,
                        wShowWindow: if hide_console_window {
                            windows::Win32::UI::WindowsAndMessaging::SW_HIDE.0 as u16
                        } else {
                            0
                        },
                        hStdOutput: stdout_handle,
                        hStdError: stderr_write,
                        hStdInput: INVALID_HANDLE_VALUE,
                        ..Default::default()
                    },
                    lpAttributeList: attr_list,
                };
                let mut process_info = PROCESS_INFORMATION::default();
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
        }

        Ok(SuspendedSpikeChild {
            child: Some(SpikeChild {
                process: process_info.hProcess,
                job,
                pid: process_info.dwProcessId,
                thread_id: process_info.dwThreadId,
                stdout_read,
                stderr_read,
            }),
            thread: process_info.hThread,
        })
    }
}

/// `CREATE_SUSPENDED`のまま止まっている子。[`Self::resume`]で動かす。
///
/// **`Resume`を独立した1手にしてあるのは測定軸だからである。** §7.1.1のコンソール貸与では
/// 「借りている窓の内側で動かすか、`FreeConsole`の後で動かすか」で、子のDLL初期化が走る時点が
/// 変わる——§7.1が`0xC0000142`（`STATUS_DLL_INIT_FAILED`）を観測したのはまさにそこである。
pub(super) struct SuspendedSpikeChild {
    /// `resume`でムーブアウトするので`Option`。`None`は「もう動かした」を意味する。
    child: Option<SpikeChild>,
    thread: HANDLE,
}

unsafe impl Send for SuspendedSpikeChild {}

impl SuspendedSpikeChild {
    /// 止まっている子のプロセスハンドル（所有権は移さない）。
    ///
    /// **動かす前に子のトークンを取り出す**ために要る——固定辺の検査の計器
    /// （`spawnd::fixed_inputs`）が、子が何かをする前の時点で判定できることを測る。
    pub(super) fn process(&self) -> HANDLE {
        self.child
            .as_ref()
            .expect("the child has not been resumed yet")
            .process
    }

    pub(super) fn pid(&self) -> u32 {
        self.child
            .as_ref()
            .expect("the child has not been resumed yet")
            .pid
    }

    /// 主スレッドを動かし始める。スレッドハンドルは`Drop`が閉じる。
    pub(super) fn resume(mut self) -> SpikeChild {
        let child = self
            .child
            .take()
            .expect("resume consumes the suspended child exactly once");
        unsafe {
            let _ = ResumeThread(self.thread);
        }
        child
    }
}

impl Drop for SuspendedSpikeChild {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.thread);
        }
        // `child`が残っていれば（Resumeせずに捨てた）`SpikeChild::drop`がjobごと畳む。
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
    refresh_probe_if_stale(&exe, &dir);
    assert!(
        exe.exists(),
        "tier2a_proc_probe.exe not found at {} (build it with `cargo build -p tier2a-proc-probe` \
         and copy it next to the test binary; see docs/DEV-ENVIRONMENT.md)",
        exe.display()
    );
    exe
}

/// テストバイナリの隣のプローブが**cargoの出力より古ければ写し直す**（2026-09-17に追加）。
///
/// # なぜ要るのか——**古い写しは、緑を別の理由で作る**
///
/// `deps/tier2a_proc_probe.exe`は手で置いた写しで、`cargo build`は更新しない
/// （cargoが書くのは`target/debug/`側と、ハッシュ付きの名前だけ）。
/// **写しが古いと、新しく足したモードを知らないプローブが走る**——引数を無視して
/// 別のモードで終わり、テストは「届かなかった」「何も起きなかった」として赤くなるか、
/// 悪くすると**別の理由で緑になる**。
///
/// 段階6dで同じ形を実際に踏んでいる（収集器の写しが古く、受け入れが「版がずれている」で
/// 落ちた。そのときは**同じエラーが「枠が無い」でも出るので、緑が正しい理由の緑か
/// 分からなかった**）。だから見つけたら直すのではなく、**毎回そろえる**。
///
/// **失敗しても止めない。** 写せないのは誰かが掴んでいるとき（前の回の子が残っている等）で、
/// そのときは既にある写しで進む——止めると、直せる不具合まで測れなくなる。
/// ただし**黙らない**（`B-10`）。
fn refresh_probe_if_stale(exe: &Path, dir: &Path) {
    let Some(built) = dir.parent().map(|up| up.join("tier2a_proc_probe.exe")) else {
        return;
    };
    let stamp = |path: &Path| {
        std::fs::metadata(path)
            .and_then(|m| Ok((m.len(), m.modified()?)))
            .ok()
    };
    let Some(fresh) = stamp(&built) else {
        return;
    };
    if stamp(exe) == Some(fresh) {
        return;
    }
    match std::fs::copy(&built, exe) {
        Ok(_) => eprintln!(
            "[probe] refreshed {} from {} (the hand-placed copy was stale)",
            exe.display(),
            built.display()
        ),
        Err(e) => eprintln!(
            "[probe] warning: could not refresh {} from {} ({e}); \
             the test will run against the older copy",
            exe.display(),
            built.display()
        ),
    }
}

/// このworkspaceのcapability SID（`test_support::spawn_in_workspace`と同じ引き方）。
/// `preflight`が張ったworkspaceツリーのACEの宛先SIDで、これを積まないと子はworkspaceを見られない。
///
/// **[D-84] モードを`rwx`に固定してある。** 以前は「台帳に載っている方」を探していたが、
/// D-84で両モードのcapability SIDが常に台帳に載るようになり、探索は意味を失った
/// （必ず先頭が当たる）。このスパイク群のworkspaceは全て`WorkspaceWriteMode::DirectRw`で
/// `preflight`しているので`rwx`が正しい——**CoWのスパイクをここへ足すときは`ro`を選ぶこと**
/// （`rwx`のcapability SIDを積んだ子はworkspace本体へ直接書けてしまい、測っている隔離が
/// 別物になる）。
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

/// `--reach-*`プローブが出したJSONから、試行1件の可否を引く。
///
/// `None`＝その試行がレポートに無い（プローブが撃っていない）。`Some(false)`＝撃って拒否された。
/// **この2つを混同しないこと**——前者は計器が動いていない可能性であり、
/// 「拒否された」の根拠にはできない。だから`bool`ではなく`Option<bool>`で返す。
///
/// `target`に`None`を渡すと的を問わず最初の一致を返す（的が1つしかない測定用）。
/// 同じ`kind`・`access`の的が複数あるときは必ず`Some`で指定する——指定しないと
/// **どの的の結果を読んだのかが結果から分からない**。
pub(super) fn reach_attempt_ok(
    report: &serde_json::Value,
    kind: &str,
    access: &str,
    target: Option<&str>,
) -> Option<bool> {
    report
        .get("attempts")?
        .as_array()?
        .iter()
        .find(|a| {
            a.get("kind").and_then(|k| k.as_str()) == Some(kind)
                && a.get("access").and_then(|k| k.as_str()) == Some(access)
                && target.is_none_or(|t| a.get("target").and_then(|k| k.as_str()) == Some(t))
        })
        .and_then(|a| a.get("ok").and_then(|o| o.as_bool()))
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
        reach_attempt_ok(report, kind, access, None)
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
        reach_attempt_ok(&report, kind, access, Some(target))
    };
    let find = |kind: &str, access: &str| -> Option<bool> {
        reach_attempt_ok(&report, kind, access, None)
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

// ---------------------------------------------------------------------------
// 固定辺の検査の計器（`spawnd::fixed_inputs`）は、AppContainerのトークンで正しく答えるか
// ---------------------------------------------------------------------------

/// Spawn Daemonは固定辺の起動直前に、**呼び出し元のトークン**で`AccessCheck`を掛けて
/// 「固定したファイルを書き換えられるか」を判定する（`plans/DESIGN-MAC.md` §19.1）。
/// このリポジトリには**AppContainerのトークンで`AccessCheck`を測った記録が無かった**
/// （Tier3の`vmsandboxd`は非AppContainerのトークンでしか使っていない）。AppContainerの子は
/// 低い整合性レベルで動き、Tier2aは整合性ラベルを付けないので、答えが実際と食い違い得る。
///
/// **同じ子について2つを突き合わせる**: (1) 止まっている子のトークンで計器が返す権利、
/// (2) 動かした後に、その子が同じ権利を要求して実際に開けたか（開くだけで何も書かない）。
/// 1件でも食い違えば、この計器を判定に使ってはいけない（B-29）。
#[test]
#[ignore = "spawns a real AppContainer child; run NON-elevated with --test-threads=1"]
fn access_check_with_an_appcontainer_token_matches_what_the_child_can_open() {
    use crate::tier2a::spawnd::fixed_inputs::{granted_access, CallerToken};

    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let _cleanup =
        super::test_support::scopeguard(|| forget_workspace_capability(workspace.path()));
    let sid = session_sid();
    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
    grant_job::wait_until_done().expect("background grant job");
    let traverse = traverse_capability_sid().expect("traverse capability");
    let workspace_cap = workspace_capability_for(workspace.path());
    let mut caps = vec![traverse.as_psid()];
    if let Some(cap) = &workspace_cap {
        caps.push(cap.as_psid());
    }

    // 書込を許したディレクトリと、読取＋実行だけを許したディレクトリ（宛先はこの子のpackage SID）。
    // ファイルは付与の**後**に作るので、ディレクトリのACEを継承する。
    let writable = tempfile::tempdir().expect("writable dir");
    grant_ace_inheritable_access(writable.path(), sid.as_psid(), FsAccess::ReadWriteExec)
        .expect("grant read/write/exec");
    let writable_file = writable.path().join("fixed.txt");
    std::fs::write(&writable_file, b"x").expect("writable file");
    let readonly = tempfile::tempdir().expect("read-only dir");
    grant_ace_inheritable_access(readonly.path(), sid.as_psid(), FsAccess::ReadExec)
        .expect("grant read/exec");
    let readonly_file = readonly.path().join("fixed.txt");
    std::fs::write(&readonly_file, b"x").expect("read-only file");
    let workspace_file = workspace.path().join("fixed.txt");
    std::fs::write(&workspace_file, b"x").expect("workspace file");
    // **整合性ラベルが「低」のファイル**。AppContainerの子が自分で作ったファイルにはこのラベルが付くので、
    // ラベルの無いファイルだけで一致しても、ラベル付きの側で食い違わないとは言えない。
    let low_label = |path: &Path| {
        std::fs::write(path, b"x").expect("low-label file");
        let status = std::process::Command::new("icacls")
            .arg(path)
            .args(["/setintegritylevel", "Low"])
            .stdout(std::process::Stdio::null())
            .status()
            .expect("run icacls");
        assert!(status.success(), "icacls /setintegritylevel Low {}", path.display());
    };
    let writable_low_file = writable.path().join("low.txt");
    low_label(&writable_low_file);
    let readonly_low_file = readonly.path().join("low.txt");
    low_label(&readonly_low_file);

    let system_root =
        PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string()));
    // (パス, ディレクトリか)。システムの側は**書き換えられないはずの対照**である。
    let objects: Vec<(PathBuf, bool)> = vec![
        (writable_file.clone(), false),
        (writable.path().to_path_buf(), true),
        (readonly_file.clone(), false),
        (readonly.path().to_path_buf(), true),
        (workspace_file.clone(), false),
        (workspace.path().to_path_buf(), true),
        (writable_low_file.clone(), false),
        (readonly_low_file.clone(), false),
        (system_root.join("System32").join("cmd.exe"), false),
        (system_root.join("System32"), true),
        (system_root.clone(), true),
        (PathBuf::from(r"C:\"), true),
    ];
    const FILE_RIGHTS: &[&str] = &[
        "write_data",
        "append_data",
        "write_attributes",
        "delete",
        "write_dac",
        "write_owner",
    ];
    const DIRECTORY_RIGHTS: &[&str] = &[
        "write_data",
        "append_data",
        "delete_child",
        "write_attributes",
        "delete",
        "write_dac",
        "write_owner",
    ];
    // プローブへ渡す綴り。**`\`で終わる引数は渡さない**——`SpikeSpawn`は引数を`"…"`で囲むので、
    // `C:\`の末尾の`\"`がエスケープとして読まれ、次の引数と連結される（1回目の実測で起きた）。
    // Win32は`C:\.`を`C:\`へ正規化して開くので、同じオブジェクトを指す。
    let arg_path = |path: &Path| -> String {
        let text = path.display().to_string();
        if text.ends_with('\\') {
            format!("{text}.")
        } else {
            text
        }
    };
    let mut args: Vec<String> = Vec::new();
    for (path, is_dir) in &objects {
        let rights = if *is_dir { DIRECTORY_RIGHTS } else { FILE_RIGHTS };
        for right in rights {
            args.push("--open-rights".to_string());
            args.push(format!("{right}:{}", arg_path(path)));
        }
    }
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let probe = probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();

    let suspended = SpikeSpawn {
        exe: &probe_str,
        args: &arg_refs,
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &caps,
        child_process_restricted: false,
        stdout_override: None,
        extra_inherit: &[],
        process_sddl: None,
        thread_sddl: None,
        token_default_dacl_sddl: None,
        no_appcontainer: false,
        console: SpikeConsole::NoWindow,
    }
    .spawn_suspended()
    .expect("spawn the suspended probe");

    // (1) 子が何もしていないうちに、子のトークンで計器に答えさせる。
    let token = CallerToken::from_process(suspended.process(), suspended.pid())
        .expect("duplicate the child's token");
    let predicted: Vec<(String, u32)> = objects
        .iter()
        .map(|(path, _)| {
            let granted = granted_access(path, &token, true)
                .unwrap_or_else(|e| panic!("granted_access({}): {e}", path.display()));
            // 照合の鍵はプローブへ渡した綴りにそろえる（報告はその綴りで返ってくる）。
            (arg_path(path), granted)
        })
        .collect();
    drop(token);

    // (2) 同じ子を動かし、同じ権利を要求して実際に開かせる。
    let mut child = suspended.resume();
    let (stdout, stderr, code) = child.wait_and_read();
    let report = last_json_line(&stdout)
        .unwrap_or_else(|| panic!("the probe produced no JSON: exit={code} stderr={stderr}\n{stdout}"));
    let attempts = report["open_rights"]
        .as_array()
        .unwrap_or_else(|| panic!("no open_rights array: {report}"));
    assert_eq!(attempts.len(), args.len() / 2, "every requested open must be reported: {report}");

    let mut mismatches = Vec::new();
    for attempt in attempts {
        let path = attempt["path"].as_str().expect("path");
        let right = attempt["right"].as_str().expect("right");
        let mask = attempt["mask"].as_u64().expect("mask") as u32;
        let last_error = attempt["last_error"].as_u64().expect("last_error");
        // 32＝共有違反は、アクセス判定を**通った後**に共有の判定で断られたもの。
        let actual = last_error == 0 || last_error == 32;
        let granted = predicted
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, g)| *g)
            .unwrap_or_else(|| panic!("no prediction for {path}"));
        let said = granted & mask != 0;
        eprintln!(
            "[fixed-inputs] {path} {right}: AccessCheck={said} opened={actual} \
             (last_error={last_error}, granted=0x{granted:08x})"
        );
        if said != actual {
            mismatches.push(format!(
                "{path} {right}: AccessCheck={said} opened={actual} (last_error={last_error}, granted=0x{granted:08x})"
            ));
        }
    }

    // 計器が常に同じ答えを返していないこと（対。書込を許したファイルは書ける、読取だけのものは書けない）。
    let writable_granted = predicted
        .iter()
        .find(|(p, _)| *p == writable_file.display().to_string())
        .map(|(_, g)| *g)
        .expect("writable file prediction");
    let readonly_granted = predicted
        .iter()
        .find(|(p, _)| *p == readonly_file.display().to_string())
        .map(|(_, g)| *g)
        .expect("read-only file prediction");
    eprintln!(
        "[fixed-inputs] writable file granted=0x{writable_granted:08x} read-only file granted=0x{readonly_granted:08x}"
    );
    assert!(
        mismatches.is_empty(),
        "AccessCheck with the AppContainer child's token disagreed with what the child could \
         actually open ({} of {}). Do not use it as the spawn-time check until this is explained:\n{}",
        mismatches.len(),
        attempts.len(),
        mismatches.join("\n")
    );
    assert_ne!(
        writable_granted & 0x2,
        0,
        "the writable file must be writable (otherwise the pair measures nothing)"
    );
    assert_eq!(
        readonly_granted & 0x2,
        0,
        "the read-only file must not be writable"
    );
}

// ---------------------------------------------------------------------------
// RedirectionGuard: 誰が作ったリンクを辿らなくなるか（残課題#68）
// ---------------------------------------------------------------------------

/// ハーネス自身がサンドボックスの外で行う操作（差分層の変更を本物へ戻す処理・アクセス制御リストへの書込）は、
/// サンドボックスより強い権限で動きながら、サンドボックス内のコードが書ける場所のパスを辿る。
/// そこへジャンクションを置かれると、本来触るはずのない場所を強い権限で書き換える恐れがある（残課題#68）。
///
/// Windows 11のプロセス単位の緩和策RedirectionGuard（`PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY`）は
/// 「管理者でないユーザーが作ったリパースポイントを辿らない」ことを有効にする。**誰が作ったリンクに効くのか・
/// 互換性を壊さないか**を測る。
///
/// # 対照を必ず混ぜる
///
/// 緩和策を掛けない腕（`none`）で**全部開けること**を同じ回で確かめる。これが無いと、
/// 全部断られたのを「緩和策が効いた」と読んでしまう（仕込みの不備と区別できない）。
/// 普通のファイル（リンクを1つも挟まない）も毎回測る——これが断られたら緩和策ではなく計器の問題である。
///
/// # 開発者モードで2回撃つ
///
/// 開発者モードは**管理者でないユーザーがシンボリックリンクを作れるか**を決める。この試験は
/// 設定を変えない（ユーザーが切り替える）。実行時の値を報告に載せるので、どちらの回の数字かは後から分かる。
#[test]
#[ignore = "spawns a real AppContainer child and creates junctions; run NON-elevated with --test-threads=1"]
fn redirection_guard_refuses_links_made_by_unprivileged_actors() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let _cleanup =
        super::test_support::scopeguard(|| forget_workspace_capability(workspace.path()));
    let sid = session_sid();
    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
    grant_job::wait_until_done().expect("background grant job");
    let traverse = traverse_capability_sid().expect("traverse capability");
    let workspace_cap = workspace_capability_for(workspace.path());
    let mut caps = vec![traverse.as_psid()];
    if let Some(cap) = &workspace_cap {
        caps.push(cap.as_psid());
    }
    let probe = probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();

    // **開発者モードの値を報告へ載せる**（どちらの回の数字かを取り違えないため）。
    let dev_mode = std::process::Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock",
            "/v",
            "AllowDevelopmentWithoutDevLicense",
        ])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("0x1"))
        .unwrap_or(false);
    eprintln!("[redirection-guard] developer mode ON? {dev_mode}");

    // --- 的を用意する ---
    let outside = tempfile::tempdir().expect("outside tempdir");
    let real = outside.path().join("real");
    std::fs::create_dir(&real).expect("real dir");
    let target_file = real.join("f.txt");
    std::fs::write(&target_file, b"x").expect("target file");
    let hard = outside.path().join("hard.txt");
    std::fs::hard_link(&target_file, &hard).expect("hard link");

    // (a) **このテストのプロセス**（管理者でない今のユーザー）が作ったジャンクション。
    let user_junction = outside.path().join("user-junction");
    let out = run_probe_locally(
        &probe_str,
        &[
            "--make-junction",
            &format!("{}|{}", user_junction.display(), real.display()),
        ],
    );
    assert_eq!(
        last_json_line(&out).and_then(|v| v["make_junction"][0]["created"].as_bool()),
        Some(true),
        "このユーザーがジャンクションを作れないと、(a)の腕が測れない: {out}"
    );

    // (d) 同じプロセスがシンボリックリンクを作れるか。**作れないことも測定結果**である。
    let user_symlink_file = outside.path().join("user-symlink-f.txt");
    let user_symlink_dir = outside.path().join("user-symlink-d");
    let out = run_probe_locally(
        &probe_str,
        &[
            "--make-symlink",
            &format!("file|{}|{}", user_symlink_file.display(), target_file.display()),
            "--make-symlink",
            &format!("dir|{}|{}", user_symlink_dir.display(), real.display()),
        ],
    );
    let symlink_report = last_json_line(&out).unwrap_or_else(|| panic!("no JSON: {out}"));
    let user_symlink_file_made = symlink_report["make_symlink"][0]["created"]
        .as_bool()
        .unwrap_or(false);
    let user_symlink_dir_made = symlink_report["make_symlink"][1]["created"]
        .as_bool()
        .unwrap_or(false);
    eprintln!(
        "[redirection-guard] user symlink: file={user_symlink_file_made} dir={user_symlink_dir_made} \
         (dev mode ON? {dev_mode}) report={symlink_report}"
    );

    // (b)(e) **AppContainerの子**（サンドボックス役）に、ワークスペースの中でリンクを作らせる。
    let sandbox_junction = workspace.path().join("sandbox-junction");
    let sandbox_symlink = workspace.path().join("sandbox-symlink-d");
    let junction_arg = format!("{}|{}", sandbox_junction.display(), real.display());
    let mut sandbox_child = SpikeSpawn {
        exe: &probe_str,
        args: &["--make-junction", &junction_arg],
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &caps,
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
    .expect("spawn the sandbox child that makes a junction");
    let (sandbox_out, sandbox_err, sandbox_code) = sandbox_child.wait_and_read();
    eprintln!(
        "[redirection-guard] sandbox junction: exit={sandbox_code} stderr={sandbox_err}\n{sandbox_out}"
    );
    let sandbox_junction_made = last_json_line(&sandbox_out)
        .and_then(|v| v["make_junction"][0]["created"].as_bool())
        .unwrap_or(false);

    // **交絡を潰す**: 上の腕は対象がワークスペースの**外**（子が読めない場所）なので、
    // 断られたのが「リパースポイントを作れない」のか「対象へ到達できない」のか区別できない。
    // 対象をワークスペースの**中**にした腕を同じ回で撃つ。
    let inside_target = workspace.path().join("inside-target");
    std::fs::create_dir(&inside_target).expect("target dir inside the workspace");
    std::fs::write(inside_target.join("f.txt"), b"x").expect("file inside the workspace");
    let sandbox_junction_inside = workspace.path().join("sandbox-junction-inside");
    let junction_inside_arg = format!(
        "{}|{}",
        sandbox_junction_inside.display(),
        inside_target.display()
    );
    let mut sandbox_inside_child = SpikeSpawn {
        exe: &probe_str,
        args: &["--make-junction", &junction_inside_arg],
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &caps,
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
    .expect("spawn the sandbox child that makes a junction inside the workspace");
    let (inside_out, _inside_err, _inside_code) = sandbox_inside_child.wait_and_read();
    eprintln!("[redirection-guard] sandbox junction (target inside the workspace):\n{inside_out}");
    let sandbox_junction_inside_made = last_json_line(&inside_out)
        .and_then(|v| v["make_junction"][0]["created"].as_bool())
        .unwrap_or(false);

    // サンドボックスの中から**ハードリンク**を作れるか（`plans/DESIGN-MAC-POC.md` §20項目12）。
    // 2本測る——(1) ワークスペースの中から中へ、(2) ワークスペースの中から**外のファイル**へ。
    // (2)が通ると、許可されていないファイルへ許可された場所から別名を張れることになる。
    let sandbox_hard_inside = workspace.path().join("sandbox-hard-inside.txt");
    let sandbox_hard_outside = workspace.path().join("sandbox-hard-outside.txt");
    let hard_inside_arg = format!(
        "{}|{}",
        sandbox_hard_inside.display(),
        inside_target.join("f.txt").display()
    );
    let hard_outside_arg = format!("{}|{}", sandbox_hard_outside.display(), target_file.display());
    let mut sandbox_hard_child = SpikeSpawn {
        exe: &probe_str,
        args: &[
            "--make-hardlink",
            &hard_inside_arg,
            "--make-hardlink",
            &hard_outside_arg,
        ],
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &caps,
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
    .expect("spawn the sandbox child that makes hard links");
    let (hard_out, _hard_err, _hard_code) = sandbox_hard_child.wait_and_read();
    eprintln!("[redirection-guard] sandbox hard links:\n{hard_out}");

    // シンボリックリンクも**対象の場所で2本**撃つ（ジャンクションと同じ交絡を潰す）。
    let sandbox_symlink_inside = workspace.path().join("sandbox-symlink-inside");
    let symlink_outside_arg = format!("dir|{}|{}", sandbox_symlink.display(), real.display());
    let symlink_inside_arg = format!(
        "dir|{}|{}",
        sandbox_symlink_inside.display(),
        inside_target.display()
    );
    let mut sandbox_sym_child = SpikeSpawn {
        exe: &probe_str,
        args: &[
            "--make-symlink",
            &symlink_outside_arg,
            "--make-symlink",
            &symlink_inside_arg,
        ],
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &caps,
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
    .expect("spawn the sandbox child that makes symlinks");
    let (sym_out, _sym_err, _sym_code) = sandbox_sym_child.wait_and_read();
    eprintln!("[redirection-guard] sandbox symlinks (dev mode ON? {dev_mode}):\n{sym_out}");
    let sandbox_symlink_made = last_json_line(&sym_out)
        .and_then(|v| v["make_symlink"][0]["created"].as_bool())
        .unwrap_or(false);
    let sandbox_symlink_inside_made = last_json_line(&sym_out)
        .and_then(|v| v["make_symlink"][1]["created"].as_bool())
        .unwrap_or(false);

    // --- 測る対象を並べる（作れなかったものは外す） ---
    let install_junction = PathBuf::from(r"C:\Documents and Settings\segfo");
    let mut targets: Vec<(&str, PathBuf, bool)> = vec![
        // (ラベル, 開くパス, 緩和策が断ることを期待するか)
        ("plain-file", target_file.clone(), false),
        ("hard-link", hard.clone(), false),
        ("user-junction", user_junction.join("f.txt"), true),
    ];
    if install_junction.exists() {
        // インストール時からあるジャンクション（管理者が作った）。**断られないことを期待する**
        // ——ここが断られるなら、この緩和策は普通の運用を壊す。
        targets.push(("install-junction", install_junction, false));
    }
    if sandbox_junction_made {
        targets.push(("sandbox-junction", sandbox_junction.join("f.txt"), true));
    }
    if sandbox_junction_inside_made {
        targets.push((
            "sandbox-junction-inside",
            sandbox_junction_inside.join("f.txt"),
            true,
        ));
    }
    if user_symlink_file_made {
        targets.push(("user-symlink-file", user_symlink_file, true));
    }
    if user_symlink_dir_made {
        targets.push(("user-symlink-dir", user_symlink_dir.join("f.txt"), true));
    }
    if sandbox_symlink_made {
        targets.push(("sandbox-symlink-dir", sandbox_symlink.join("f.txt"), true));
    }
    if sandbox_symlink_inside_made {
        targets.push((
            "sandbox-symlink-inside",
            sandbox_symlink_inside.join("f.txt"),
            true,
        ));
    }

    let mut specs: Vec<String> = Vec::new();
    for (label, path, _) in &targets {
        specs.push("--redirection-open".to_string());
        specs.push(format!("{label}:{}", path.display()));
    }

    // --- 3つの設定で撃つ（対照を同じ回に混ぜる） ---
    let mut results: Vec<(&str, serde_json::Value)> = Vec::new();
    for mode in ["none", "enforce", "audit"] {
        let mut args: Vec<&str> = vec!["--redirection-trust", mode];
        args.extend(specs.iter().map(String::as_str));
        let out = run_probe_locally(&probe_str, &args);
        let report = last_json_line(&out)
            .unwrap_or_else(|| panic!("no JSON for mode {mode}: {out}"))["redirection_trust"]
            .clone();
        eprintln!("[redirection-guard] mode={mode} report={report}");
        // **掛かったことを別の口で確かめる**（掛けたつもりで測らない）。
        let expected_flags = match mode {
            "none" => 0,
            "enforce" => 1,
            _ => 2,
        };
        assert_eq!(
            report["readback_flags"].as_u64(),
            Some(expected_flags),
            "緩和策が実際に掛かっていない（この回の数字は使えない）: mode={mode} {report}"
        );
        results.push((mode, report));
    }

    let opened = |report: &serde_json::Value, label: &str| -> Option<(bool, u64)> {
        report["opens"].as_array()?.iter().find_map(|o| {
            if o["label"].as_str() != Some(label) {
                return None;
            }
            Some((o["opened"].as_bool()?, o["last_error"].as_u64()?))
        })
    };

    // **対照**: 緩和策なしでは全部開ける。1つでも開けないなら仕込みが壊れている。
    let none = &results[0].1;
    for (label, path, _) in &targets {
        assert_eq!(
            opened(none, label).map(|(ok, _)| ok),
            Some(true),
            "緩和策なしで開けないものがある（仕込みの不備。この回の数字は使えない）: \
             {label} path={} report={none}",
            path.display()
        );
    }

    // **強制**: 期待する向きまで確かめる。断る側と断らない側を同じ表で読む。
    let enforce = &results[1].1;
    for (label, path, should_refuse) in &targets {
        let (ok, err) = opened(enforce, label)
            .unwrap_or_else(|| panic!("{label}の結果が無い: {enforce}"));
        if *should_refuse {
            assert!(
                !ok && err == 448,
                "**管理者でない主体が作ったリンクを、緩和策が辿っている。** \
                 ハーネス側の操作をこの緩和策で守る案（残課題#68）が成立しない: \
                 {label} path={} last_error={err} report={enforce}",
                path.display()
            );
        } else {
            assert!(
                ok,
                "**緩和策が、守る相手ではないものまで断った。** 掛けると普通の運用が壊れる: \
                 {label} path={} last_error={err} report={enforce}",
                path.display()
            );
        }
    }

    // **監査だけ**: 断らない（記録するだけ）。強制と同じ結果なら、2つのモードを区別していない。
    let audit = &results[2].1;
    for (label, path, _) in &targets {
        assert_eq!(
            opened(audit, label).map(|(ok, _)| ok),
            Some(true),
            "監査だけのモードで断られた（強制と区別できていない）: {label} path={} report={audit}",
            path.display()
        );
    }
}

/// プローブを**AppContainerに入れずに**（このテストと同じトークンで）起こし、標準出力を返す。
///
/// ハーネス自身がサンドボックスの外で動く側を演じる腕で使う。
fn run_probe_locally(probe: &str, args: &[&str]) -> String {
    let out = std::process::Command::new(probe)
        .args(args)
        .output()
        .expect("run the probe");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// [残課題#68] **`--fs-allow <path>:rw`で開けた場所から、サンドボックスの子は
/// 「読めないファイル」へハードリンクを張れるか。**
///
/// # なぜこれだけ別に測るのか
///
/// RedirectionGuard（管理者でないユーザーが作ったリパースポイントを辿らない緩和策）は
/// **ハードリンクには効かない**（`plans/mac-spike/RESULTS.md` §S81）。ハードリンクは1つの
/// ファイル実体に付いた対等な名前なので、パスをどう解決しても見つからないからである。
///
/// §S81では「子はワークスペースの外のファイルへハードリンクを作れない（アクセス拒否）」まで測った。
/// **ただしあれは、リンクを作る場所がワークスペースの中の場合である。** `--fs-allow X:rw`は
/// ワークスペースの外に書ける場所Xを開けるので、**Xの中に、Xの外のファイルへのリンクを張れるか**は
/// 別の問いとして残っていた（§S81の「言えないこと」の`--fs-allow`の行）。
///
/// # 何が起きると困るのか
///
/// 張れると、子が読めないはずのファイルに、子が読める場所から別名が付く。しかも
/// RedirectionGuardでは止まらない。
///
/// # 対照を混ぜる
///
/// **Xの中からXの中のファイルへのリンク**も同じ回で張らせる。これが成功しないと、
/// 外向きが失敗したのを「ハードリンクそのものを作れない」と読んでしまう（§18.5の交絡）。
#[test]
#[ignore = "spawns a real AppContainer child and grants an fs-allow ACE; run NON-elevated with --test-threads=1"]
fn a_sandboxed_child_cannot_hard_link_an_unreadable_file_into_an_fs_allow_directory() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let _cleanup =
        super::test_support::scopeguard(|| forget_workspace_capability(workspace.path()));

    // `--fs-allow X:rw`で開ける場所X（ワークスペースの外）。
    let allowed = tempfile::tempdir().expect("fs-allow tempdir");
    std::fs::write(allowed.path().join("inside.txt"), b"readable").expect("file inside X");
    // 子が読めないはずのファイル（どこからも許可していない場所）。
    let secret_root = tempfile::tempdir().expect("secret tempdir");
    let secret = secret_root.path().join("id_rsa");
    std::fs::write(&secret, b"TOP-SECRET-KEY").expect("seed secret");

    let passthrough = vec![crate::FsPassthrough {
        path: allowed.path().to_path_buf(),
        access: crate::FsAccess::ReadWrite,
        forced: false,
        scope: harness_policy::GrantScope::Recursive,
    }];
    let sid = session_sid();
    preflight(
        workspace.path(),
        &passthrough,
        None,
        &WorkspaceWriteMode::DirectRw,
    )
    .expect("preflight with an fs-allow entry");
    grant_job::wait_until_done().expect("background grant job");
    let traverse = traverse_capability_sid().expect("traverse capability");
    let workspace_cap = workspace_capability_for(workspace.path());
    let mut caps = vec![traverse.as_psid()];
    if let Some(cap) = &workspace_cap {
        caps.push(cap.as_psid());
    }
    // `--fs-allow`の穴は**宣言ごとのcapability SID**宛に開く。子のトークンへ積まないと、
    // Xそのものへ到達できず「書けないから張れない」を測ることになる。
    let canonical_workspace = workspace
        .path()
        .canonicalize()
        .unwrap_or_else(|_| workspace.path().to_path_buf());
    let declaration_caps: Vec<crate::win_common::OwnedSid> =
        fs_allow_capability_sids_for_declarations(
            &canonical_workspace,
            &[(allowed.path(), crate::FsAccess::ReadWrite)],
        )
        .into_iter()
        .filter_map(Result::ok)
        .collect();
    for cap in &declaration_caps {
        caps.push(cap.as_psid());
    }

    let probe = probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();
    // (1) Xの中 → Xの中（対照。これが成功しないと外向きの失敗を読めない）
    // (2) Xの中 → 読めないファイル（本題）
    let inside_arg = format!(
        "{}|{}",
        allowed.path().join("link-inside.txt").display(),
        allowed.path().join("inside.txt").display()
    );
    let secret_arg = format!(
        "{}|{}",
        allowed.path().join("link-secret.txt").display(),
        secret.display()
    );
    let mut child = SpikeSpawn {
        exe: &probe_str,
        args: &["--make-hardlink", &inside_arg, "--make-hardlink", &secret_arg],
        cwd: workspace.path(),
        container_sid: sid.as_psid(),
        capabilities: &caps,
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
    .expect("spawn the sandbox child that makes hard links");
    let (stdout, stderr, code) = child.wait_and_read();
    eprintln!(
        "MEASUREMENT: hard links from a sandboxed child into an --fs-allow :rw directory -> \
         exit={code} stderr={stderr}\n{stdout}"
    );
    let report = last_json_line(&stdout)
        .unwrap_or_else(|| panic!("the probe produced no JSON: {stdout}"));
    let inside_made = report["make_hardlink"][0]["created"].as_bool();
    let secret_made = report["make_hardlink"][1]["created"].as_bool();

    // 後始末は判定より先に（`--fs-allow`で開けた穴を、assertで落ちても残さない）。
    for cap in &declaration_caps {
        let _ = revoke_ace(allowed.path(), cap.as_psid());
    }

    // **対照**: Xの中からXの中へは張れる。張れないなら、下の判定は意味を持たない。
    assert_eq!(
        inside_made,
        Some(true),
        "`--fs-allow X:rw`で開けたXの中で、Xの中のファイルへハードリンクを張れない。\
         これでは外向きの失敗を「権限が無いから」と読めない（交絡）: {report}"
    );
    // **本題**: 読めないファイルへは張れない。
    assert_eq!(
        secret_made,
        Some(false),
        "**サンドボックスの子が、読めないはずのファイルへ、書ける場所から別名を張った。** \
         ハードリンクはRedirectionGuardでは止まらないので、この経路が成立するなら\
         残課題#68の受容の前提（サンドボックスは許可されていないファイルへ別名を張れない）が崩れる: \
         {report}"
    );
}

// ---------------------------------------------------------------------------
// 残課題#68の未確認2経路（S82の表の「未確認」）
// ---------------------------------------------------------------------------

/// ジャンクション（ディレクトリのリパースポイント）を作る。**昇格は要らない**。
#[cfg(test)]
fn make_junction_for_test(link: &std::path::Path, target: &std::path::Path) {
    let status = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .stdout(std::process::Stdio::null())
        .status()
        .expect("run mklink");
    assert!(
        status.success(),
        "mklink /J {} {} failed; the arm cannot be measured",
        link.display(),
        target.display()
    );
}

/// [残課題#68] **差分層を消す処理は、中に置かれたジャンクションの先まで消さない。**
///
/// # なぜ確かめるのか
///
/// `remove_overlay_dir`（`session_scope.rs`）は`std::fs::remove_dir_all`をそのまま呼ぶ。
/// サンドボックスの子は既定のモードで差分層の中へ書けるので、そこへジャンクションを置ける。
/// **辿って消すなら、子が指した任意のディレクトリの中身が消える**——起動時の回収
/// （`run_cow_gc`）でも同じ処理が走るので、消える先はユーザーのファイルになり得る。
///
/// 辿らないのはRustの`remove_dir_all`がリパースポイントをリンクとして消すからだが、
/// **言語の実装に依存した暗黙の防御**である。破れたら赤くなるようにする。
#[test]
#[cfg(windows)]
fn removing_the_diff_layer_does_not_delete_through_a_junction_planted_inside_it() {
    let diff_layer = tempfile::tempdir().expect("diff layer tempdir");
    let outside = tempfile::tempdir().expect("outside tempdir");
    let secret = outside.path().join("id_rsa");
    std::fs::write(&secret, b"TOP-SECRET-KEY").expect("seed secret");
    // 差分層の中の普通のファイル（走査ではなく削除が動いていることの対照）。
    std::fs::write(diff_layer.path().join("real.txt"), b"x").expect("plain file");

    make_junction_for_test(&diff_layer.path().join("link"), outside.path());

    crate::session_scope::remove_overlay_dir(diff_layer.path()).expect("remove the diff layer");

    // **対照**: 差分層そのものは消えている。消えていないなら下の判定は意味を持たない。
    assert!(
        !diff_layer.path().exists(),
        "the diff layer itself was not removed, so the arm below means nothing"
    );
    // **本題**: ジャンクションの先のファイルは残っている。
    assert!(
        secret.exists(),
        "**removing the diff layer followed a junction and deleted a file outside it.** \
         A sandboxed child can plant junctions in the diff layer, so this would let it delete \
         arbitrary directories: {}",
        secret.display()
    );
    assert_eq!(
        std::fs::read(&secret).expect("read the secret back"),
        b"TOP-SECRET-KEY",
        "the file outside the diff layer was modified"
    );
}

/// [残課題#68] **祖先への通行許可の付与は、途中のジャンクションの先へ許可を付けるか。**
///
/// # なぜ確かめるのか
///
/// `grant_traverse_chain_with_progress`（`traverse.rs`）は`target.ancestors()`を歩き、
/// 各段へ`FILE_TRAVERSE | FILE_READ_ATTRIBUTES`の許可を書く。**`canonicalize`しない**ので、
/// 途中の段がジャンクションなら、許可はリンクの先のディレクトリへ付く可能性がある
/// （`SetNamedSecurityInfoW`はパスを辿る）。
///
/// 付くなら、サンドボックスが自分で張ったリンクで**許可を付ける先を選べる**ことになる。
/// 付くのは「通過」と「属性の読取」だけで中身を読む許可ではないが、意図した相手ではない。
///
/// # これは測定であって受け入れではない
///
/// **どちらの結果でも記録する。** 付くなら残課題として残し、付かないなら根拠として残す。
#[test]
#[cfg(windows)]
fn granting_traverse_through_a_junction_shows_where_the_ace_lands() {
    let root = tempfile::tempdir().expect("tempdir");
    let real = root.path().join("real");
    std::fs::create_dir(&real).expect("real dir");
    std::fs::create_dir(real.join("deep")).expect("deep dir");
    let link = root.path().join("link");
    make_junction_for_test(&link, &real);

    // 付与の宛先は、このテスト専用に作る入れ物の識別子にする（他の機構の宛先を汚さない）。
    let sid = traverse_capability_sid().expect("traverse capability");

    // リンク越しの綴りで、その下の段を標的にする。
    let target = link.join("deep");
    let (granted, result) = grant_traverse_chain_with_progress(&target, sid.as_psid(), |_, _, _| {});
    let grant_outcome = format!("{result:?}");

    // リンクそのものと、リンクの先の実体に許可が付いたかを読む。
    let on_link = sid_ace_mask(&link, sid.as_psid()).ok().flatten();
    let on_real = sid_ace_mask(&real, sid.as_psid()).ok().flatten();

    // 後始末は判定より先に（assertで落ちても許可を残さない）。
    for node in &granted {
        let _ = revoke_ace(node, sid.as_psid());
    }
    let _ = revoke_ace(&real, sid.as_psid());
    let _ = revoke_ace(&link, sid.as_psid());

    println!(
        "MEASUREMENT: granting traverse through a junction -> result={grant_outcome} \
         granted_nodes={granted:?}\n  ace on the link itself: {on_link:?}\n  \
         ace on the junction's real target: {on_real:?}"
    );

    // **実測（2026-10-01）**: 許可は**リンクの先の実体**に付き、リンク自身には付かなかった
    // （`FILE_TRAVERSE | FILE_READ_ATTRIBUTES` = 0xa0 = 160）。`SetNamedSecurityInfoW`が
    // パスを辿るためである。**この事実を固定する**——向きが変わったら（辿らなくなったら）
    // ここが赤くなり、残課題#68の記述を読み直す合図になる。
    const TRAVERSE_AND_READ_ATTRIBUTES: u32 = 0xa0;
    assert_eq!(
        on_real,
        Some(TRAVERSE_AND_READ_ATTRIBUTES),
        "祖先への通行許可の付与がジャンクションを辿らなくなった（または別のマスクが付いた）。\
         残課題#68の「辿る」という記述と、`plans/mac-spike/RESULTS.md` §S82を読み直すこと: \
         link={on_link:?} real={on_real:?} result={grant_outcome}"
    );
    assert_eq!(
        on_link, None,
        "リンク自身にも許可が付いた（実測ではリンクの先だけに付いていた）: \
         link={on_link:?} real={on_real:?}"
    );
}
