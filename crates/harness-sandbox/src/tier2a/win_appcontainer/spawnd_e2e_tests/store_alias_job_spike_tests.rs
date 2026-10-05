//! [実行エイリアスの道のA1] **ストアの実行エイリアスのpwshを、Daemonと同じ条件で
//! 新しい空のJobへ入れられるか**の測定。判定の規則は`plans/mac-spike/RESULTS.md` §S84が持ち、
//! **そのコミット（`ddfd44c`）はこの測定より前にある**。
//!
//! # 何が分からないのか
//!
//! エイリアス（`%LOCALAPPDATA%\Microsoft\WindowsApps\pwsh.exe`。中身0バイトの飛び先で、
//! OSがアプリの仕組みを通して本体を起こす）で起きたプロセスは、**OSが自分のJob**
//! （プロセスの群れをまとめて始末する入れ物）**へ先に入れる**。Jobの階層は入れ子でなければ
//! ならないので、こちらのJobに誰か1人でも居ると`AssignProcessToJobObject`が拒否される（§S59）。
//! だから遷移の強制の下では遷移先にできない（§S62）。
//!
//! **空のJobなら入れられる**ことは§S59が測ってあるが、あれは**AppContainerも生成禁止も無い**
//! 形だった。ここで測るのは「Daemonと同じ条件で、新しい空のJobへ入れて動かし、
//! Jobごと終わらせられるか」である。
//!
//! # 測り方——Daemonの「最上位の子」の経路を借りる（製品のコードは変えない）
//!
//! Daemonには、入れ子の子を新しいJobへ入れる経路がまだ無い（`spawnd/table.rs`の
//! `register_in_lineage`が「系統Jobは新しく作らない」と決めている）。**最上位の子**は
//! harnessが作ったJobへDaemonが入れるので、試験がharnessの役をして空のJobを渡せば、
//! 測りたい形がそのまま作れる。
//!
//! ```text
//! 試験（harnessの役）: create_job_object() → 空のJob J
//!   └─ Daemon.spawn_top_level(エイリアスのpwsh, J, フックの注入, 生成禁止, コンソール要)
//!         CreateProcessW(SUSPENDED) → AssignProcessToJobObject(J) → DLL注入 → 台帳登録 → 再開
//!         OSのJob ⊃ J [pwsh]
//!                        └─ pwshが.NETのProcess.Start → フック → Daemonへ依頼
//!                             Daemonが自分を親として5.1を起こし、pwshの系統のJob（＝J）へ入れる
//! 試験: TerminateJobObject(J) → pwshと子が終わる
//! ```
//!
//! 本番の入れ子との違い3つ（`lpApplicationName`を渡さない・Jobを作るのが試験・
//! 子が入るJob）と、それでも結論を変えないと見立てた理由は§S84が持つ。**ここへ写さない。**
//!
//! # 条件を1つだけ変えて撃つ測定の一覧
//!
//! | 名前 | 何をするか | 役割 |
//! |---|---|---|
//! | `N-C` | DLLを注入したプローブ（系統Jobに居る呼び出し元）が、本物のフック経由で5.1を頼む | 正の対照（入れ子） |
//! | `N-A1` | 同じプローブが、`lpApplicationName`にエイリアスを渡して頼む | 負の対照＝§S59の再現 |
//! | `N-A2` | 同じプローブが、`lpApplicationName`を渡さず行だけで頼む（実行ファイルはフックが探す） | 同上。フックがエイリアスを解決できるかも見る |
//! | `T-C` | 5.1を新しい空のJobへ起こす | 正の対照（最上位）＝計器が生きている証拠 |
//! | `T-A` | **エイリアスのpwshを新しい空のJobへ起こす** | 本命 |
//! | `T-C'`・`T-A'` | 同じ形で起こし、**先にDaemonを止め**、それから試験がJobの最後の取っ手を閉じる | Jobの取っ手を閉じたら終わるか |
//!
//! `T-C'`は**§S84を書いた後に足した対照**である。理由: Daemonを止めるとコンソールを貸している
//! 保持プロセスも終わるので、**シェルがコンソールの消滅で巻き添えになる**可能性がある。
//! エイリアスの側だけで撃つと、それを「Jobの取っ手の話」と取り違える。
//!
//! # ここで測っていないもの（**limitation**）
//!
//! §S84の「走らせる前から分かっている測らないこと」が正本である（Daemon自身が新しいJobを作る形・
//! Storeの更新中のずれ・系統の終わりの知り方・非昇格・1台1版・MSIXの実体の綴り）。**ここへ写さない。**
//!
//! # 寿命: 判定が出て実装が入ったら消す
//!
//! A3（Daemonが入れ子の子のために追加の空のJobを作る）の昇格E2Eが緑になったコミットで、
//! **このファイル・`spawnd_e2e_tests.rs`のmod行・`targets.rs`のキー`spike-spawnd-store-alias-job`と
//! `spawn-daemon`の`--skip`の2行**を一緒に消す（`docs/CODE-STRUCTURE-RULES.md`規則2の使い捨ての側）。
//! 結論は`plans/mac-spike/RESULTS.md` §S84が持つ。

use std::path::Path;
use std::time::{Duration, Instant};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, BOOL, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::JobObjects::{
    IsProcessInJob, JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
    PROCESS_NAME_NATIVE, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};

use super::transition_acceptance_tests::{policy_with_edges, wait_for_file, windows_powershell_51};
use super::transparent_hook_tests::{
    process_hooks, redirector_log_path, run_probe_with_hooks, REDIRECTOR_LOG_ENV,
};
use super::*;
use crate::cancel_descendants::{ps_literal, CANCEL_TIMEOUT};
use crate::tier2a::policy_learnd::etw::parse::to_settings_path;
use crate::tier2a::policy_learnd::etw::session::{
    ProbedEvent, ProviderProbeSession, KERNEL_PROCESS_PROVIDER_GUID,
};
use crate::tier2a::policy_learnd::etw::volumes::drive_letter_map;

/// シェルが「自分は走った」と書く印。
const SHELL_MARKER: &str = "HARNESS-A1-SHELL-RAN";

/// 入れ子で起こした5.1が標準出力へ出す印。
const NESTED_MARKER: &str = "HARNESS-A1-NESTED-RAN";

/// アプリ実行エイリアスのリパースポイントの種別
/// （`IO_REPARSE_TAG_APPEXECLINK`。`plans/mac-spike/RESULTS.md`で既に観測されている値）。
const IO_REPARSE_TAG_APPEXECLINK: u32 = 0x8000_001B;

/// リパースポイントの中身を読む制御コード（`FSCTL_GET_REPARSE_POINT`）。
///
/// **`windows`クレートの`Win32_System_Ioctl`機能を増やさずに済ませる**ため、ここで定義する
/// （値はWindows SDKの`winioctl.h`。この測定だけが使う）。
const FSCTL_GET_REPARSE_POINT: u32 = 0x0009_00A8;

/// リパースポイントの中身の上限（`MAXIMUM_REPARSE_DATA_BUFFER_SIZE`）。
const MAX_REPARSE_BUFFER: usize = 16 * 1024;

/// 1つのJobの、測りたい性質。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct JobFacts {
    /// 生きているプロセスの数（`ActiveProcesses`）。
    active: u32,
    /// このJobに入ったことのあるプロセスの数（`TotalProcesses`）。
    total: u32,
    /// 拡張制限の旗。**`create_job_object`が立てるのはkill-on-closeだけ**なので、
    /// 他の旗が立っていたらJobへ入れた副作用で性質が変わったことになる。
    limit_flags: u32,
}

fn job_facts(job: HANDLE) -> Result<JobFacts, String> {
    let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    unsafe {
        QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            &mut accounting as *mut _ as *mut _,
            std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            None,
        )
        .map_err(|e| format!("QueryInformationJobObject(accounting): {e}"))?;
        QueryInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &mut limits as *mut _ as *mut _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            None,
        )
        .map_err(|e| format!("QueryInformationJobObject(limits): {e}"))?;
    }
    Ok(JobFacts {
        active: accounting.ActiveProcesses,
        total: accounting.TotalProcesses,
        limit_flags: limits.BasicLimitInformation.LimitFlags.0,
    })
}

/// そのプロセスはこのJobのメンバか。**読めなかったことを`false`に畳まない。**
fn in_job(process: HANDLE, job: HANDLE) -> Result<bool, String> {
    let mut result = BOOL(0);
    unsafe {
        IsProcessInJob(process, job, &mut result).map_err(|e| format!("IsProcessInJob: {e}"))?;
    }
    Ok(result.as_bool())
}

/// 実行中のプロセスの実行ファイルのパスを、2つの書き方で読む。
fn image_paths(process: HANDLE) -> (Option<String>, Option<String>) {
    let read = |format| -> Option<String> {
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        unsafe { QueryFullProcessImageNameW(process, format, PWSTR(buf.as_mut_ptr()), &mut len) }
            .ok()?;
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    };
    (read(PROCESS_NAME_WIN32), read(PROCESS_NAME_NATIVE))
}

/// リパースポイントの中身。
#[derive(Debug, Clone)]
struct ReparseFacts {
    tag: u32,
    /// 中身に並んでいる文字列（アプリ実行エイリアスは、パッケージの族名・アプリの識別子・
    /// 実行ファイルのパス・種別の4つが並ぶ）。
    strings: Vec<String>,
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `path`自身（辿らない）のリパースポイントの中身を読む。リパースポイントでなければ`Err`。
fn read_reparse_point(path: &str) -> Result<ReparseFacts, String> {
    let path_w = wide(path);
    let mut buf = vec![0u8; MAX_REPARSE_BUFFER];
    let mut returned = 0u32;
    unsafe {
        let handle = CreateFileW(
            PCWSTR(path_w.as_ptr()),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        .map_err(|e| format!("CreateFileW({path}): {e}"))?;
        let result = DeviceIoControl(
            handle,
            FSCTL_GET_REPARSE_POINT,
            None,
            0,
            Some(buf.as_mut_ptr() as *mut _),
            buf.len() as u32,
            Some(&mut returned),
            None,
        );
        let _ = CloseHandle(handle);
        result.map_err(|e| format!("FSCTL_GET_REPARSE_POINT({path}): {e}"))?;
    }
    let returned = returned as usize;
    if returned < 8 {
        return Err(format!("リパースポイントの中身が短すぎる（{returned}バイト）"));
    }
    let tag = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let data_len = u16::from_le_bytes([buf[4], buf[5]]) as usize;
    // 先頭8バイトは種別・長さ・予備。アプリ実行エイリアスはそのあとに版（4バイト）が入る。
    let body_start = if tag == IO_REPARSE_TAG_APPEXECLINK {
        12
    } else {
        8
    };
    let body_end = (8 + data_len).min(returned).max(body_start);
    let strings = utf16_strings(&buf[body_start..body_end]);
    Ok(ReparseFacts { tag, strings })
}

/// NULで区切られたUTF-16の文字列の並びを取り出す（空の要素は落とす）。
fn utf16_strings(bytes: &[u8]) -> Vec<String> {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    units
        .split(|unit| *unit == 0)
        .filter(|part| !part.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

/// 試験が握っておくプロセスの取っ手。
///
/// # なぜ`DescendantProbe`を使わないのか
///
/// あちらは`SYNCHRONIZE`と`TERMINATE`だけで開く（`cancel_descendants.rs`）。この測定は
/// **`IsProcessInJob`と`QueryFullProcessImageNameW`**を撃つので
/// `PROCESS_QUERY_LIMITED_INFORMATION`が要る。生死の待ち方と後始末はあちらと同じ形にしてある。
struct Watched {
    pid: u32,
    handle: HANDLE,
}

impl Watched {
    /// PIDの書かれたファイルを待ち、**読んだ直後に取っ手で固定する**（PIDの使い回し対策）。
    fn wait_for_pid_file(pid_file: &Path, timeout: Duration) -> Result<Self, String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(text) = std::fs::read_to_string(pid_file) {
                if let Ok(pid) = text.trim().parse::<u32>() {
                    let handle = unsafe {
                        OpenProcess(
                            PROCESS_SYNCHRONIZE
                                | PROCESS_TERMINATE
                                | PROCESS_QUERY_LIMITED_INFORMATION,
                            false,
                            pid,
                        )
                    }
                    .map_err(|e| format!("OpenProcess({pid}): {e}"))?;
                    return Ok(Self { pid, handle });
                }
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "PIDのファイルが{timeout:?}以内に現れない: {}",
                    pid_file.display()
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn alive(&self) -> bool {
        unsafe { WaitForSingleObject(self.handle, 0) == WAIT_TIMEOUT }
    }

    /// 終わるまで待つ。終わったら`true`。
    fn wait_exit(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if unsafe { WaitForSingleObject(self.handle, 0) } == WAIT_OBJECT_0 {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Watched {
    fn drop(&mut self) {
        unsafe {
            if WaitForSingleObject(self.handle, 0) != WAIT_OBJECT_0 {
                let _ = TerminateProcess(self.handle, 1);
                let _ = WaitForSingleObject(self.handle, CANCEL_TIMEOUT.as_millis() as u32);
            }
            let _ = CloseHandle(self.handle);
        }
    }
}

/// 最上位で起こすシェルの台本と、そこから生まれるファイルの置き場。
struct ShellScript {
    args: Vec<String>,
    shell_file: std::path::PathBuf,
    child_pid_file: std::path::PathBuf,
    reported_pid_file: std::path::PathBuf,
    error_file: std::path::PathBuf,
}

/// 「印とPIDを書く → 5.1を子として起こす → 眠り続ける」台本を組む。
///
/// **子に`cmd.exe`を使わない**——生成禁止の下では`cmd.exe`が次のプログラムを起こせない
/// （BUG-230）。**子にプローブを使わない**——プローブの置き場（`target\debug\deps`）は
/// サンドボックスの中から一覧も属性の読み取りもできない（BUG-230の測定で分かった）。
fn shell_script(workspace: &Path, prefix: &str) -> ShellScript {
    let shell_file = workspace.join(format!("{prefix}-shell.txt"));
    let child_pid_file = workspace.join(format!("{prefix}-child.pid"));
    let reported_pid_file = workspace.join(format!("{prefix}-child-reported.pid"));
    let error_file = workspace.join(format!("{prefix}-shell.error"));

    // 子（5.1）へ渡す引数。自分のPIDを書いて眠る。
    //
    // **二重引用符を1つも使わない。** PowerShellは`-Command`の**後ろの引数を空白1つでつないで**
    // 1つのコマンドとして読むので、本体を二重引用符で囲む必要が無い。囲むと、外側のシェルへ
    // `-Command`で台本を渡すときに二重引用符が混ざり、**PowerShellが台本を読み直す段で
    // 黙って別のコマンドになり得る**（2026-10-05にサンドボックスの外で確かめた）。
    // **`$PID`はここでは展開させない**——単一引用符で包むので、展開するのは子自身である。
    // そのため**空白を2つ続けて書かない**（つなぎ直しで余分な空白が入らないようにする）。
    let child_args = format!(
        "-NoProfile -NonInteractive -Command [IO.File]::WriteAllText({}, [string]$PID); \
         Start-Sleep -Seconds 120",
        ps_literal(&child_pid_file.to_string_lossy())
    );

    let script = format!(
        "$ErrorActionPreference='Stop'; \
         [IO.File]::WriteAllText({shell}, '{marker} ' + [string]$PID); \
         try {{ \
           $psi=[Diagnostics.ProcessStartInfo]::new(); \
           $psi.FileName={ps51}; \
           $psi.Arguments={child_args}; \
           $psi.UseShellExecute=$false; \
           $psi.CreateNoWindow=$false; \
           $p=[Diagnostics.Process]::Start($psi); \
           [IO.File]::WriteAllText({reported}, [string]$p.Id) \
         }} catch {{ [IO.File]::WriteAllText({error}, ($_ | Out-String)) }}; \
         while ($true) {{ Start-Sleep -Milliseconds 200 }}",
        shell = ps_literal(&shell_file.to_string_lossy()),
        marker = SHELL_MARKER,
        ps51 = ps_literal(&windows_powershell_51()),
        child_args = ps_literal(&child_args),
        reported = ps_literal(&reported_pid_file.to_string_lossy()),
        error = ps_literal(&error_file.to_string_lossy()),
    );

    ShellScript {
        args: vec![
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            script,
        ],
        shell_file,
        child_pid_file,
        reported_pid_file,
        error_file,
    }
}

/// 最上位で1本起こして観測したもの。
struct TopLevelObserved {
    label: &'static str,
    exe: String,
    /// シェルが印を書いたか。
    shell_ran: bool,
    shell_in_job: Result<bool, String>,
    job_after_start: Result<JobFacts, String>,
    shell_image_win32: Option<String>,
    shell_image_native: Option<String>,
    /// シェルの台本が子を起こすときに書いた失敗の中身。
    shell_error: String,
    /// 子（5.1）のPIDを**3つの源**で持つ: 子が自分で書いた値・シェルが受け取った値・
    /// 試験が取っ手で固定した値。**同じ源から出た2つは突き合わせにならない**ので、
    /// 子自身とシェルという独立な2つに、固定した値を足して3つにしてある。
    child_pid_self: Option<u32>,
    child_pid_reported: Option<u32>,
    child_pid_pinned: Option<u32>,
    child_in_job: Option<Result<bool, String>>,
    /// フックがDaemonへ頼んだ行（シェルのPIDが書いたもの）。
    brokering_lines: Vec<String>,
    /// 終わらせる直前に、両方が生きていたか。
    alive_before_end: (bool, Option<bool>),
    /// 終わらせたあと、両方が終わったか。
    exited_after_end: (bool, Option<bool>),
    /// Daemonを止めた直後に、両方が生きていたか（`T-C'`・`T-A'`だけ）。
    alive_after_daemon_stop: Option<(bool, Option<bool>)>,
    job_after_end: Result<JobFacts, String>,
    /// 記録（ETW）に残ったプロセスの開始の通知のうち、このシェルのもの。
    etw_lines: Vec<String>,
}

impl TopLevelObserved {
    fn print(&self) {
        let mut text = format!("\n===== [A1 {}] exe={} =====\n", self.label, self.exe);
        text += &format!("(1) シェルが印を書いたか: {}\n", self.shell_ran);
        text += &format!("    シェルがJ のメンバか: {:?}\n", self.shell_in_job);
        text += &format!("    起こした直後のJ: {:?}\n", self.job_after_start);
        text += &format!(
            "    実行ファイル（Win32形式）: {:?}\n    実行ファイル（NT形式）: {:?}\n",
            self.shell_image_win32, self.shell_image_native
        );
        text += &format!(
            "(2a) フックが頼んだ行（{}本）:\n",
            self.brokering_lines.len()
        );
        for line in &self.brokering_lines {
            text += &format!("  {line}\n");
        }
        text += &format!(
            "(2b) 子のPID（子自身が書いた）: {:?} / （シェルが受け取った）: {:?} / \
             （試験が取っ手で固定した）: {:?}\n",
            self.child_pid_self, self.child_pid_reported, self.child_pid_pinned
        );
        text += &format!("     子がJ のメンバか: {:?}\n", self.child_in_job);
        if !self.shell_error.trim().is_empty() {
            text += &format!(
                "     シェルが書いた失敗の中身:\n{}\n",
                indent(&self.shell_error)
            );
        }
        if let Some(alive) = self.alive_after_daemon_stop {
            text += &format!(
                "(3b) Daemonを止めた直後に生きていたか（シェル, 子）: {alive:?}\n"
            );
        }
        text += &format!(
            "(3) 終わらせる直前に生きていたか: {:?} / 終わったか: {:?}\n",
            self.alive_before_end, self.exited_after_end
        );
        text += &format!("    終わらせたあとのJ: {:?}\n", self.job_after_end);
        if !self.etw_lines.is_empty() {
            text += &format!("(5) 記録（ETW）に残った綴り（{}件）:\n", self.etw_lines.len());
            for line in &self.etw_lines {
                text += &format!("  {line}\n");
            }
        }
        eprintln!("{text}");
    }

    /// (1)(2a)(3) が全部通ったか——採否に使う組。
    fn started_asked_and_ended(&self) -> bool {
        self.shell_ran
            && self.shell_in_job == Ok(true)
            && !self.brokering_lines.is_empty()
            && self.alive_before_end.0
            && self.exited_after_end.0
    }
}

fn indent(text: &str) -> String {
    if text.trim().is_empty() {
        return "  （無し）".to_string();
    }
    text.lines()
        .map(|line| format!("  {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn pid_in_file(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()
}

/// シェルのPIDが書いた「頼んだ」行（DLLの診断ログの書式は`[<ms> pid=<pid>] <msg>`）。
fn brokering_lines_of(log: &str, pid: u32) -> Vec<String> {
    let tag = format!(" pid={pid}]");
    log.lines()
        .filter(|line| line.contains(&tag) && line.contains(": brokering "))
        .map(str::to_string)
        .collect()
}

fn handle_alive(process: HANDLE) -> bool {
    unsafe { WaitForSingleObject(process, 0) == WAIT_TIMEOUT }
}

fn wait_handle_exit(process: HANDLE, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if unsafe { WaitForSingleObject(process, 0) } == WAIT_OBJECT_0 {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// パイプを**上限時間つきで**読み切る。読み切れなかったら取っ手を閉じずに諦める。
///
/// # なぜ`assert_cancel_completes`を使わないのか
///
/// あちらは読み切れないと`panic`する（P6ではそれが測定対象そのものだからである）。
/// **ここは測定なので、途中で落ちると全部の観測の印字を失う**——読み切れなかったことを
/// 値として持ち帰り、判定は呼び出し側が行う。読み切った側が取っ手を閉じるので、
/// 諦めた回は取っ手を閉じない（読んでいるスレッドが使い続けている）。
fn drain_pipes_bounded(stdout: HANDLE, stderr: HANDLE, timeout: Duration) -> (String, String, bool) {
    let out_pipe = crate::win_common::SendHandle(stdout);
    let err_pipe = crate::win_common::SendHandle(stderr);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (out_pipe, err_pipe) = (out_pipe, err_pipe);
        let _ = tx.send(crate::win_common::read_two_pipes_to_strings(
            out_pipe.0, err_pipe.0,
        ));
    });
    match rx.recv_timeout(timeout) {
        Ok((out, err)) => (out, err, true),
        Err(_) => (String::new(), String::new(), false),
    }
}

/// 記録（ETW）のプロセス開始の通知のうち、`pid`のものを読める形へ直す。
fn etw_lines_for(events: &[ProbedEvent], pid: u32) -> Vec<String> {
    let volumes = drive_letter_map();
    events
        .iter()
        .filter(|event| event.numbers.get("ProcessID").copied() == Some(u64::from(pid)))
        .map(|event| {
            let raw = event.strings.get("ImageName");
            format!(
                "ImageName（生）={:?} 寄せた値={:?} PackageFullName={:?} version={}",
                raw,
                raw.and_then(|r| to_settings_path(r, &volumes)),
                event.strings.get("PackageFullName"),
                event.version
            )
        })
        .collect()
}

/// 記録（ETW）で見るプロセスの通知の種別と範囲。
const WINEVENT_KEYWORD_PROCESS: u64 = 0x10;
const EVENT_ID_PROCESS_START: u16 = 1;

/// 最上位で1本起こす指定。
struct TopLevelPlan<'a> {
    label: &'static str,
    /// 実マシンの作業ディレクトリの名前に入る綴り（空白もバックスラッシュも入れない）。
    dir_label: &'a str,
    /// ワークスペースの中に作るファイルの名前の頭。
    prefix: &'a str,
    exe: &'a str,
    /// 終わらせ方。真なら**Daemonを先に止めてJobの最後の取っ手を閉じる**、
    /// 偽なら`TerminateJobObject`を撃つ。
    close_job_instead_of_terminate: bool,
    /// 記録（ETW）を張るか。
    watch_etw: bool,
}

fn run_top_level_arm(plan: &TopLevelPlan<'_>) -> TopLevelObserved {
    let ps51 = windows_powershell_51();
    let (mut case, profile, caps) = setup_with_policy_and_transitions(
        &format!("spawnd-a1-{}", plan.dir_label),
        // **生成禁止を積む。** 積まないとシェルが自分で子を起こせてしまい、
        // 「Daemonへ頼めたか」を測っていないことになる。
        ChildProcessPolicy::Restricted,
        |_workspace| policy_with_edges(E2E_POLICY_DOMAIN, &[&ps51]),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let script = shell_script(&workspace, plan.prefix);
    let spawn_cap = spawn_request_capability_sid().expect("spawn request capability");
    let redirector_log = redirector_log_path(&workspace);
    let args: Vec<&str> = script.args.iter().map(String::as_str).collect();

    let etw = if plan.watch_etw {
        match ProviderProbeSession::start(
            &format!("harness-a1-{}", plan.dir_label),
            KERNEL_PROCESS_PROVIDER_GUID,
            WINEVENT_KEYWORD_PROCESS,
            &[EVENT_ID_PROCESS_START],
            &["ImageName", "PackageFullName"],
            &["ProcessID", "ParentProcessID"],
        ) {
            Ok(session) => Some(session),
            Err(e) => {
                eprintln!("[A1 {}] 記録（ETW）を張れなかった: {e}", plan.label);
                None
            }
        }
    } else {
        None
    };

    let started = start_top_level_detached(
        case.daemon.as_ref().expect("case owns the daemon"),
        &profile,
        &workspace,
        TopLevelArm {
            exe: plan.exe,
            args: &args,
            domain: domain_spec(&profile, &caps, Some(&spawn_cap)),
            // **コンソールを要と申告する。** 借りられないとPowerShellは何も実行せず
            // 終了コード0で終わる（§7.1の無言失敗）。
            console: ConsoleNeed::Required,
            redirector: process_hooks(&workspace),
            extra_env: vec![(
                REDIRECTOR_LOG_ENV.to_string(),
                redirector_log.to_string_lossy().into_owned(),
            )],
        },
    );

    let shell_ran = wait_for_file(&script.shell_file, Duration::from_secs(20))
        && std::fs::read_to_string(&script.shell_file)
            .map(|text| text.contains(SHELL_MARKER))
            .unwrap_or(false);
    let shell_in_job = in_job(started.child.process, started.job);
    let job_after_start = job_facts(started.job);
    let (shell_image_win32, shell_image_native) = image_paths(started.child.process);

    // 子（5.1）を待つ。起きていなければ`None`のまま進む——(2b)は採否を変えない項目である。
    let child = match Watched::wait_for_pid_file(&script.child_pid_file, Duration::from_secs(30)) {
        Ok(watched) => Some(watched),
        Err(e) => {
            eprintln!("[A1 {}] 子を取っ手で固定できなかった: {e}", plan.label);
            None
        }
    };
    let child_pid_self = pid_in_file(&script.child_pid_file);
    let child_pid_reported = pid_in_file(&script.reported_pid_file);
    let child_pid_pinned = child.as_ref().map(|watched| watched.pid);
    let child_in_job = child
        .as_ref()
        .map(|watched| in_job(watched.handle, started.job));
    let shell_error = std::fs::read_to_string(&script.error_file).unwrap_or_default();

    let log = std::fs::read_to_string(&redirector_log).unwrap_or_default();
    let brokering_lines = brokering_lines_of(&log, started.child.pid);
    let etw_lines = match etw {
        Some(session) => etw_lines_for(&session.stop().events, started.child.pid),
        None => Vec::new(),
    };

    // **Daemonを先に止める腕**（Jobの最後の取っ手で終わるかを見る側）。
    let alive_after_daemon_stop = if plan.close_job_instead_of_terminate {
        drop(case.daemon.take());
        std::thread::sleep(Duration::from_secs(1));
        Some((
            handle_alive(started.child.process),
            child.as_ref().map(|watched| watched.alive()),
        ))
    } else {
        None
    };

    // **終わらせる直前に生きていたことを確かめる**（G4）。これが無いと、
    // 「終わった」を「もともと起きていなかった」と区別できない。
    let alive_before_end = (
        handle_alive(started.child.process),
        child.as_ref().map(|watched| watched.alive()),
    );

    let job = started.job;
    if plan.close_job_instead_of_terminate {
        unsafe {
            let _ = CloseHandle(job);
        }
    } else {
        let kill = crate::win_common::KillToken::duplicate(job).expect("duplicate the job handle");
        kill.kill();
    }
    let (drained_out, drained_err, drained) =
        drain_pipes_bounded(started.stdout_read, started.stderr_read, CANCEL_TIMEOUT);
    eprintln!(
        "[A1 {}] シェルの標準出力・標準エラー（読み切れた={drained}）:\n{}\n{}",
        plan.label,
        indent(&drained_out),
        indent(&drained_err)
    );

    let exited_after_end = (
        wait_handle_exit(started.child.process, CANCEL_TIMEOUT),
        child
            .as_ref()
            .map(|watched| watched.wait_exit(CANCEL_TIMEOUT)),
    );
    let job_after_end = if plan.close_job_instead_of_terminate {
        Err("Jobの取っ手を閉じたので読めない".to_string())
    } else {
        job_facts(job)
    };

    unsafe {
        let _ = CloseHandle(started.child.process);
        if !plan.close_job_instead_of_terminate {
            let _ = CloseHandle(job);
        }
    }
    drop(child);
    drop(case);

    TopLevelObserved {
        label: plan.label,
        exe: plan.exe.to_string(),
        shell_ran,
        shell_in_job,
        job_after_start,
        shell_image_win32,
        shell_image_native,
        shell_error,
        child_pid_self,
        child_pid_reported,
        child_pid_pinned,
        child_in_job,
        brokering_lines,
        alive_before_end,
        exited_after_end,
        alive_after_daemon_stop,
        job_after_end,
        etw_lines,
    }
}

/// 入れ子（本物のフック経由）で1本頼んで観測したもの。
struct NestedObserved {
    label: &'static str,
    exe: String,
    /// `lpApplicationName`を渡したか。
    passed_application_name: bool,
    created: Option<bool>,
    last_error: Option<u64>,
    /// 頼んだ先が実際に走ったか（印が出たか）。
    nested_ran: bool,
    /// `CreateProcessW`が返した失敗の文面。
    ///
    /// **Daemonの応答（`reply`）はここでは読めない。** 透過の経路の報告
    /// （`tier2a-proc-probe`の`spawn_transparently`）は`created`・`last_error`・`child_pid`しか
    /// 持たず、応答の欄を持つのは電文を自分で組む経路（`--pipe-client`）だけである。
    /// **空の欄を置くと「応答が無かった」と読める**ので、読める値の側を記録する。
    create_error: String,
    report: String,
}

impl NestedObserved {
    fn print(&self) {
        eprintln!(
            "\n===== [A1 {}] exe={} lpApplicationName={} =====\n\
             CreateProcessWが成功したか: {:?} / last_error: {:?}\n\
             頼んだ先が走ったか（印）: {}\n\
             CreateProcessWが返した失敗の文面: {}\n\
             プローブの報告: {}",
            self.label,
            self.exe,
            if self.passed_application_name {
                "渡した"
            } else {
                "渡さない"
            },
            self.created,
            self.last_error,
            self.nested_ran,
            if self.create_error.is_empty() {
                "（無し）"
            } else {
                &self.create_error
            },
            self.report.trim()
        );
    }
}

/// 入れ子の3本を、同じDaemon・同じ宣言で順に撃つ。
fn run_nested_arms(alias: &str) -> Vec<NestedObserved> {
    let ps51 = windows_powershell_51();
    let (mut case, profile, caps) = setup_with_policy_and_transitions(
        "spawnd-a1-nested",
        ChildProcessPolicy::Restricted,
        |_workspace| policy_with_edges(E2E_POLICY_DOMAIN, &[alias, &ps51]),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();

    struct Arm<'a> {
        label: &'static str,
        exe: &'a str,
        pass_application_name: bool,
    }
    let arms = [
        Arm {
            label: "N-C（正の対照・5.1）",
            exe: &ps51,
            pass_application_name: true,
        },
        Arm {
            label: "N-A1（エイリアス・実行ファイルを渡す）",
            exe: alias,
            pass_application_name: true,
        },
        Arm {
            label: "N-A2（エイリアス・行だけ）",
            exe: alias,
            pass_application_name: false,
        },
    ];

    let mut observed = Vec::new();
    for (index, arm) in arms.iter().enumerate() {
        let captured = workspace.join(format!("nested-{index}.txt"));
        let command_line = crate::tier2a::win_appcontainer::command_line_for(
            arm.exe,
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!("Write-Output '{NESTED_MARKER}'"),
            ],
        );
        let mut args: Vec<String> = vec![
            "--spawn-transparently".to_string(),
            "none".to_string(),
            "--spawn-command-line".to_string(),
            command_line,
            "--spawn-stdout".to_string(),
            captured.to_string_lossy().into_owned(),
            "--timeout-secs".to_string(),
            "60".to_string(),
        ];
        if arm.pass_application_name {
            args.push("--spawn-image".to_string());
            args.push(arm.exe.to_string());
        }
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let (out, err) = run_probe_with_hooks(&case, &profile, &caps, &borrowed);
        eprintln!("[A1 {}] probe stdout={out}\nprobe stderr={err}", arm.label);

        observed.push(NestedObserved {
            label: arm.label,
            exe: arm.exe.to_string(),
            passed_application_name: arm.pass_application_name,
            created: report_field(&out, "created").and_then(|v| v.as_bool()),
            last_error: report_field(&out, "last_error").and_then(|v| v.as_u64()),
            nested_ran: std::fs::read_to_string(&captured)
                .map(|text| text.contains(NESTED_MARKER))
                .unwrap_or(false),
            create_error: report_field(&out, "create_error")
                .and_then(|value| value.as_str().map(str::to_string))
                .unwrap_or_default(),
            report: out,
        });
    }

    // **Daemonを止めてから診断を読む**（生きている間は最後の1行がまだ書かれていない）。
    drop(case.daemon.take());
    let daemon_log = std::fs::read_to_string(&case.daemon_log).unwrap_or_default();
    eprintln!("[A1 入れ子] Daemonの標準エラー:\n{}", indent(&daemon_log));
    drop(case);
    observed
}

/// **§S84**: ストアの実行エイリアスのpwshを、Daemonと同じ条件で新しい空のJobへ入れて動かし、
/// Jobごと終わらせられるかを測る。
///
/// **合否にするのは計器の検算（G1〜G4）と対照だけである。** 本命の観測は印字し、
/// §S84.2の採否の規則に当てた結果を最後の行に出す——ここで知りたいのは「どう動くか」であり、
/// 動かないこと自体は既に測ってある（§S62）。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer children; run through spike-spawnd-store-alias-job"]
fn whether_the_store_alias_pwsh_can_live_in_a_fresh_empty_job() {
    let alias = super::super::mac_spike_followup_tests::store_alias_pwsh_path().expect(
        "この機にストアの実行エイリアス（%LOCALAPPDATA%\\Microsoft\\WindowsApps\\pwsh.exe）が無いので、\
         **この測定の前提そのものが成り立たない**。`Get-AppxPackage Microsoft.PowerShell`が空なら\
         ストア版が入っていない——そのときは実行エイリアスの道の作業自体が要らない",
    );

    // [G3] 腕の入力の指紋。**撃つ前に読む**——「エイリアスのつもりで実体を撃った」を排除する。
    let alias_reparse = read_reparse_point(&alias);
    let ps51_reparse = read_reparse_point(&windows_powershell_51());
    eprintln!(
        "\n[A1 G3] 入力の指紋\n  エイリアス {alias}\n    {alias_reparse:?}\n  \
         5.1 {}\n    {ps51_reparse:?}",
        windows_powershell_51()
    );

    let nested = run_nested_arms(&alias);
    for observed in &nested {
        observed.print();
    }

    let plans = [
        TopLevelPlan {
            label: "T-C（正の対照・5.1）",
            dir_label: "tc",
            prefix: "tc",
            exe: &windows_powershell_51(),
            close_job_instead_of_terminate: false,
            watch_etw: false,
        },
        TopLevelPlan {
            label: "T-A（本命・エイリアス）",
            dir_label: "ta",
            prefix: "ta",
            exe: &alias,
            close_job_instead_of_terminate: false,
            watch_etw: true,
        },
        TopLevelPlan {
            label: "T-C'（対照・5.1・Daemonを先に止める）",
            dir_label: "tcx",
            prefix: "tcx",
            exe: &windows_powershell_51(),
            close_job_instead_of_terminate: true,
            watch_etw: false,
        },
        TopLevelPlan {
            label: "T-A'（エイリアス・Daemonを先に止める）",
            dir_label: "tax",
            prefix: "tax",
            exe: &alias,
            close_job_instead_of_terminate: true,
            watch_etw: false,
        },
    ];
    let observed: Vec<TopLevelObserved> = plans.iter().map(run_top_level_arm).collect();
    for arm in &observed {
        arm.print();
    }

    // ---- 計器の検算（崩れたものを全部数える。1つ目で止めない） ----
    let mut failures: Vec<String> = Vec::new();

    match &alias_reparse {
        Ok(facts) if facts.tag == IO_REPARSE_TAG_APPEXECLINK => {}
        other => failures.push(format!(
            "[G3] エイリアスとして撃った綴りが、アプリ実行エイリアスのリパースポイント\
             （0x{IO_REPARSE_TAG_APPEXECLINK:08X}）ではない: {other:?}。\
             **この回はエイリアスを測っていない**"
        )),
    }
    if ps51_reparse.is_ok() {
        failures.push(format!(
            "[G3] 対照の5.1がリパースポイントになっている: {ps51_reparse:?}。\
             **対照が対照になっていない**"
        ));
    }

    let nested_control = &nested[0];
    if !nested_control.nested_ran {
        failures.push(format!(
            "[G2] 正の対照（本物のフック経由で5.1を頼む）で、頼んだ先が走っていない。\
             **この回はフックの経路が動いていない**ので、エイリアスの測定の「断られた」は読めない: \
             created={:?} last_error={:?} 失敗の文面={}",
            nested_control.created, nested_control.last_error, nested_control.create_error
        ));
    }

    let top_control = &observed[0];
    if !top_control.started_asked_and_ended() {
        failures.push(format!(
            "[G1] 正の対照（5.1を新しい空のJobへ）で、起動・依頼・終了のどれかが通っていない。\
             **台本か計器が壊れている**ので、エイリアスの腕の結果は読めない: \
             印={} J のメンバ={:?} 頼んだ行={}本 終わらせる前に生きていた={:?} 終わった={:?}",
            top_control.shell_ran,
            top_control.shell_in_job,
            top_control.brokering_lines.len(),
            top_control.alive_before_end,
            top_control.exited_after_end
        ));
    }
    if top_control.child_in_job != Some(Ok(true)) {
        failures.push(format!(
            "[G1] 正の対照で、シェルが頼んだ子が同じJobに入っていない: {:?}（子のPID: 自分={:?} 受け取り={:?}）。\
             **(2b)の計器が効いていない**ので、エイリアスの腕の同じ項目は読めない",
            top_control.child_in_job, top_control.child_pid_self, top_control.child_pid_reported
        ));
    }

    // ---- 負の対照（§S62の見張り） ----
    for arm in nested.iter().skip(1) {
        if arm.nested_ran {
            failures.push(format!(
                "[対照] 今の製品の入れ子（呼び出し元が居る系統Jobへ入れる形）で、\
                 エイリアスが起きて走った（{}）。**これはテストの失敗ではなく朗報の可能性**である\
                 ——OS側の制約が外れたか、この機のPowerShellの入り方が変わった。\
                 §S62の見張り（shell_target_tests）も赤くなっているはずなので、\
                 A2へ進まずに撤収の箇所をそちらの文面で確かめること",
                arm.label
            ));
        }
    }

    // ---- 採否（§S84.2の規則。観測なので赤にしない） ----
    let target = &observed[1];
    let target_closed = &observed[3];
    let rule1 = target.started_asked_and_ended()
        && target_closed.alive_after_daemon_stop.map(|alive| alive.0) == Some(true)
        && target_closed.exited_after_end.0;
    eprintln!(
        "\n[A1 判定] §S84.2の{}。\n  \
         T-A: (1)起動={} J のメンバ={:?} (2a)頼んだ行={}本 (3a)終わった={:?}\n  \
         T-A': Daemonを止めた直後に生きていた={:?} 取っ手を閉じて終わった={:?}\n  \
         T-C'（対照）: Daemonを止めた直後に生きていた={:?} 取っ手を閉じて終わった={:?}\n  \
         （(2b)子がJ のメンバか: T-A={:?} / T-C={:?} は採否を変えない）",
        if rule1 {
            "規則1に当たる（A2へ進める）"
        } else {
            "規則2に当たる（止めてユーザーへ報告する）"
        },
        target.shell_ran,
        target.shell_in_job,
        target.brokering_lines.len(),
        target.exited_after_end,
        target_closed.alive_after_daemon_stop,
        target_closed.exited_after_end,
        observed[2].alive_after_daemon_stop,
        observed[2].exited_after_end,
        target.child_in_job,
        top_control.child_in_job
    );

    assert!(
        failures.is_empty(),
        "計器の検算または対照が{}件崩れた。**この回の本命の観測は読まない**:\n- {}",
        failures.len(),
        failures.join("\n- ")
    );
}

/// 実行エイリアスは**アプリ実行エイリアスのリパースポイント**で、中身が実行ファイルを名指しする。
///
/// A4（記録の版番号入りの実体のパスと、強制の回のエイリアスのパスを対応づける）の案が
/// 成り立つかの入口である。**昇格もDaemonも要らない**ので普通の`cargo test`で走る。
#[test]
fn the_store_alias_is_an_app_execution_link_that_names_the_real_executable() {
    let Some(alias) = super::super::mac_spike_followup_tests::store_alias_pwsh_path() else {
        eprintln!(
            "この機にストアの実行エイリアスが無いので測っていない。\
             **「エイリアスは読めない」と読まないこと。**"
        );
        return;
    };
    let facts = read_reparse_point(&alias)
        .unwrap_or_else(|e| panic!("エイリアス{alias}のリパースポイントを読めない: {e}"));
    eprintln!("[A4の入口] {alias}\n  {facts:?}");

    assert_eq!(
        facts.tag, IO_REPARSE_TAG_APPEXECLINK,
        "エイリアスの種別がアプリ実行エイリアス（0x{IO_REPARSE_TAG_APPEXECLINK:08X}）ではない: \
         0x{:08X}。**A4の案（中身を読んで実体のパスと対応づける）はこの種別を前提にしている**",
        facts.tag
    );
    assert!(
        facts
            .strings
            .iter()
            .any(|value| value.to_ascii_lowercase().ends_with("pwsh.exe")),
        "中身が`pwsh.exe`で終わるパスを1つも名指ししていない: {:?}。\
         **A4は中身から実体のパスを引く**ので、これが無いと案が成り立たない",
        facts.strings
    );
}
