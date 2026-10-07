//! コンソール保持プロセス（`plans/DESIGN-MAC-ENFORCEMENT.md`§7.1.1・§7.1.2）。
//!
//! # なぜこんなものが要るのか
//!
//! 子プロセス生成を禁じられたプロセスは、**自分のコンソールを作れない**。コンソールの
//! 割り当ては`conhost.exe`という子プロセスの生成を伴うからである。ところがPowerShellは
//! コンソールが無いと**何も実行せず終了コード0で終わる**（無言失敗）。
//!
//! そこで「コンソールを持つためだけに居るプロセス」をサンドボックスの外に1つ置き、
//! **シェルを起こす瞬間だけ**Daemonがそのコンソールを借りて、借りたまま子を起こす。
//!
//! ```text
//!   Daemon（普段はコンソールに繋がっていない）
//!     └ シェルの生成要求ごとに、ロックの内側で:
//!          保持プロセスのハンドルで生存を確認
//!            └ 死んでいる／まだ無い → その場で起こす
//!          AttachConsole(保持プロセスのPID)   ← ここから窓が開く
//!          CreateProcessW(コンソールのフラグ無し, CREATE_SUSPENDED)
//!          FreeConsole()                      ← 窓を閉じる
//!          ResumeThread()                     ← 窓の外で動かす
//! ```
//!
//! # 落とすと壊れるもの
//!
//! - **保持プロセスをサンドボックスの中に置かない。** 置くと、そこは
//!   「生成禁止を積んでいないプロセスがサンドボックス内に常駐している」状態になり、
//!   乗っ取れば制限のない生成能力が手に入る＝機構全体が無意味になる
//! - **Daemonはコンソールに繋がったままにしない。** 同じコンソールに繋がったプロセスは
//!   互いに制御イベント（Ctrl+C・Ctrl+Break）を撃てるので、繋がったままだと
//!   **サンドボックスからDaemonを落とせる**。窓は`CreateProcessW`の前後だけに閉じる
//! - **生存判定はハンドルで行う**（§7.1.2の決定3）。PIDは再利用され得るので、
//!   PID・プロセス名・一覧の存在で代用しない
//!
//! # この回で縮退させたもの（**設計と実装が食い違っている箇所。隠さない**）
//!
//! | 設計の指定 | 実態 | ここでどうしたか |
//! |---|---|---|
//! | 立て直しの記録は§10.2の「許可した生成の記録」と同じシンクへ`kind`を1つ足す | **§10.2のシンクは1行も実装されていない** | 新しいシンクを作らず、Daemonの標準エラーへ出すに留めた。**本番ではこの出力は誰にも届かない**（Daemonはコンソールを持たない）ので、**立て直しが起きた事実は今日どこにも残らない**。§10.2が着地する回に束ねる |
//! | 回収は§22.9のプロファイル・アロケータの台帳が持つ寿命へ束ねる | **§22.9のアロケータは未実装** | 設計が「保険」と呼んでいるDaemon所有のJob（最後の取っ手を閉じるとOSが中身を始末する）を、当面の唯一の回収経路にした |

use std::sync::Mutex;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_TIMEOUT};
use windows::Win32::System::Console::{AttachConsole, FreeConsole};
use windows::Win32::System::Threading::{
    CreateProcessW, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT,
    PROCESS_INFORMATION, STARTUPINFOW,
};

use crate::win_common::{create_job_object, terminate_job_and_close, wide};

/// `harness-spawnd.exe`を保持プロセスとして起こすときの引数。
///
/// **読む側（`harness-spawnd`の`main`）と同じ定数を使う。** 綴りを2箇所に書くと、
/// 片方だけ直したときに保持プロセスが**Daemonとして起動しようとして即死する**
/// （そして症状は「コンソールを借りられない」という遠い場所に出る）。
pub const CONSOLE_HOLDER_ARG: &str = "--console-holder";

/// `AttachConsole`が成功するまで待つ上限。
///
/// **これは「生きているか」の判定ではなく「資源が現れたか」の待ちである。** 保持プロセスの
/// コンソールはプロセス生成と同時にOSが割り当てるが、割り当てが済む前に借りに行くと失敗する。
/// 生存そのものはハンドルで判定しており（§7.1.2の決定3）、ここでポーリングしているのは
/// **所有権ではなく初期化の完了**である。
const ATTACH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);
const ATTACH_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

/// 1つのドメインが使うコンソール保持プロセス。
struct Holder {
    /// **生存判定はこのハンドルで行う**（PIDでは行わない。§7.1.2の決定3）。
    process: HANDLE,
    pid: u32,
    /// kill-on-closeのJob。**Daemonが死ねばこの取っ手が閉じ、OSが保持プロセスを畳む。**
    /// §22.9のプロファイル回収が実装されるまで、これが唯一の回収経路である（モジュールdoc）。
    job: HANDLE,
}

// `HANDLE`はカーネルオブジェクトへのポインタ値で、別スレッドから使ってもOSレベルでは安全
// （`SpawnDaemonHandle`のSend実装と同じ理由）。
unsafe impl Send for Holder {}

impl Holder {
    /// まだ生きているか。**`WaitForSingleObject`が待たずに戻るかで見る。**
    fn is_alive(&self) -> bool {
        unsafe { WaitForSingleObject(self.process, 0) == WAIT_TIMEOUT }
    }

    /// 終了コード（診断用。**「撃たれた」の証拠ではない**——§7.1.2の決定4が
    /// 「`STATUS_CONTROL_C_EXIT`は他の理由でも出る」と釘を刺している）。
    fn exit_code(&self) -> Option<u32> {
        let mut code = 0u32;
        let ok = unsafe {
            windows::Win32::System::Threading::GetExitCodeProcess(self.process, &mut code)
        };
        ok.is_ok().then_some(code)
    }

    /// **付与と撤収を対にする**（`B-01`）。Jobを畳めば中の保持プロセスも終わる。
    fn close(self) {
        terminate_job_and_close(self.job);
        unsafe {
            let _ = CloseHandle(self.process);
        }
    }
}

/// ドメインごとの保持プロセスの表。
///
/// **ロックは1本で、ドメインを跨いで直列になる**（§7.1.1の「直列化」欄）。
/// 1つのプロセスが同時に繋がれるコンソールは1つだけなので、**この不変条件は
/// Daemonのプロセス内で閉じている**——跨プロセスの排他（名前付きカーネルオブジェクト）は
/// 要らない。
#[derive(Default)]
pub(crate) struct ConsoleHolders {
    inner: Mutex<Vec<(String, Holder)>>,
}

impl ConsoleHolders {
    /// そのドメインのコンソールを借りる。**返り値を持っている間だけ窓が開いている。**
    ///
    /// 借りる直前に生存を確認し、死んでいる／まだ無ければ**その場で起こす**
    /// （§7.1.2の決定2。初回作成と立て直しを別経路にしない）。
    ///
    /// # 失敗したら黙って続けない
    ///
    /// 起こせない・借りられないときは`Err`を返す。呼び出し側は**そのspawn要求ごと失敗させる**
    /// （§7.1.2の決定4）。コンソール無しでシェルを起こすと`0xC0000142`で落ちるか、
    /// 何も実行せず終了コード0で終わり、どちらも「シェルが壊れた」としか見えない。
    ///
    /// `on_restarted`は立て直したときに（旧PID・旧終了コード・新PID）で呼ばれる（§7.1.2 決定4。記録が無ければ何もしない側が渡る）。
    pub(crate) fn borrow(
        &self,
        domain_key: &str,
        on_restarted: &dyn Fn(u32, Option<u32>, u32),
    ) -> Result<ConsoleWindow<'_>, String> {
        let mut table = self
            .inner
            .lock()
            .map_err(|_| "the console holder table mutex was poisoned".to_string())?;

        let index = table.iter().position(|(key, _)| key == domain_key);
        // **死んでいたら、その場で起こし直す。** 旧ハンドルは先に閉じる（`B-01`）。
        let mut restarted: Option<(u32, Option<u32>)> = None;
        if let Some(index) = index {
            if !table[index].1.is_alive() {
                let (_, dead) = table.remove(index);
                let dead_pid = dead.pid;
                let dead_exit = dead.exit_code();
                dead.close();
                restarted = Some((dead_pid, dead_exit));
                // [縮退] 記録の無い Daemon（`harness.exe`）では標準エラーだけである——**本番ではこの行は誰にも届かない。**
                // 記録がある Daemon（ポリシーエディタのパス2）は、起こし直した後で`on_restarted`が同じ記録へ書く（決定68）。
                eprintln!(
                    "harness-spawnd: console holder for {domain_key} died \
                     (pid={dead_pid}, exit={dead_exit:?}); rebuilding"
                );
            }
        }
        if !table.iter().any(|(key, _)| key == domain_key) {
            let holder = launch_holder()?;
            if let Some((old_pid, old_exit)) = restarted {
                on_restarted(old_pid, old_exit, holder.pid);
            }
            table.push((domain_key.to_string(), holder));
        }

        let pid = table
            .iter()
            .find(|(key, _)| key == domain_key)
            .map(|(_, holder)| holder.pid)
            .expect("the holder was just ensured to exist");

        attach_console_with_deadline(pid)?;
        Ok(ConsoleWindow {
            _table: table,
            attached: true,
        })
    }

    /// 全部畳む。**Daemonの終了時に呼ぶ**（Jobのkill-on-closeは保険であって、
    /// 畳む手段としてはこちらが正面である。§10.1.1がキャンセルについて採ったのと同じ形）。
    pub(crate) fn shutdown(&self) {
        let Ok(mut table) = self.inner.lock() else {
            return;
        };
        for (_, holder) in table.drain(..) {
            holder.close();
        }
    }
}

/// コンソールを借りている間だけ生きるガード。**落ちると窓が閉じる。**
///
/// 表のロックを握ったまま持つのは、窓が開いている間に別のスレッドが
/// 同じDaemonで別のコンソールを借りに行くのを止めるためである（1プロセスが同時に
/// 繋がれるコンソールは1つだけ）。
pub(crate) struct ConsoleWindow<'a> {
    _table: std::sync::MutexGuard<'a, Vec<(String, Holder)>>,
    attached: bool,
}

impl Drop for ConsoleWindow<'_> {
    fn drop(&mut self) {
        if self.attached {
            unsafe {
                let _ = FreeConsole();
            }
        }
    }
}

/// 保持プロセスを1つ起こす。**サンドボックスの外**（AppContainerでない・capabilityを
/// 1つも持たない）で、`CREATE_NO_WINDOW`＝窓を出さずにコンソールを割り当てる。
fn launch_holder() -> Result<Holder, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("could not resolve the spawn daemon's own exe path: {e}"))?;
    let mut cmdline = wide(&format!("\"{}\" {CONSOLE_HOLDER_ARG}", exe.display()));

    // Daemonが死ねば保持プロセスも畳まれるように、先にJobを作る。
    let job = create_job_object().map_err(|e| format!("create_job_object(console holder): {e}"))?;

    let mut info = PROCESS_INFORMATION::default();
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let spawned = unsafe {
        CreateProcessW(
            None,
            PWSTR(cmdline.as_mut_ptr()),
            None,
            None,
            // **ハンドルを1つも継承させない。** 保持プロセスはコンソールを持つだけの
            // 存在で、Daemonが握っている制御パイプ・系統Job・子のstdioを渡す理由が無い。
            false,
            // **一時停止で起こしてJobへ入れてから動かす**（`create_suspended_in_job`と
            // 同じ理由）。素で起こすと、Jobへ入る前に保持プロセスが子を作れる窓ができる。
            CREATE_NO_WINDOW
                | CREATE_UNICODE_ENVIRONMENT
                | windows::Win32::System::Threading::CREATE_SUSPENDED,
            None,
            PCWSTR::null(),
            &startup,
            &mut info,
        )
    };
    if let Err(e) = spawned {
        terminate_job_and_close(job);
        return Err(format!("CreateProcessW({}): {e}", exe.display()));
    }

    let assigned =
        unsafe { windows::Win32::System::JobObjects::AssignProcessToJobObject(job, info.hProcess) };
    if let Err(e) = assigned {
        // 一時停止のままなので、保持プロセスはまだ1行も実行していない。
        unsafe {
            let _ = windows::Win32::System::Threading::TerminateProcess(info.hProcess, 1);
            let _ = CloseHandle(info.hThread);
            let _ = CloseHandle(info.hProcess);
        }
        terminate_job_and_close(job);
        return Err(format!("AssignProcessToJobObject(console holder): {e}"));
    }

    unsafe {
        windows::Win32::System::Threading::ResumeThread(info.hThread);
        let _ = CloseHandle(info.hThread);
    }

    Ok(Holder {
        process: info.hProcess,
        pid: info.dwProcessId,
        job,
    })
}

/// 保持プロセスのコンソールを借りる。**現れるまで待つ**（[`ATTACH_DEADLINE`]のdoc）。
fn attach_console_with_deadline(pid: u32) -> Result<(), String> {
    // **借りる前に必ず手放す。** 既定では繋がっていないが、前回の窓が
    // 異常経路で閉じ切らなかった場合、`AttachConsole`は
    // `ERROR_ACCESS_DENIED`（＝既に繋がっている）で失敗する。
    unsafe {
        let _ = FreeConsole();
    }

    let deadline = std::time::Instant::now() + ATTACH_DEADLINE;
    let last: windows::core::Error = loop {
        match unsafe { AttachConsole(pid) } {
            Ok(()) => return Ok(()),
            Err(e) => {
                if std::time::Instant::now() >= deadline {
                    break e;
                }
            }
        }
        std::thread::sleep(ATTACH_RETRY_INTERVAL);
    };
    Err(format!(
        "could not attach to the console holder (pid={pid}) within {ATTACH_DEADLINE:?}: {last}"
    ))
}

/// 保持プロセスとして走る（`harness-spawnd.exe --console-holder`）。
///
/// やることは2つだけである。
///
/// 1. **自分に届く制御イベントを握り潰す**（§7.1.2の決定1）。同じコンソールに繋がった
///    サンドボックスの子は`CTRL_BREAK_EVENT`を撃てるので、守らないと落とされて
///    **そのドメインは以後シェルを起こせなくなる**（失われるのは可用性だけで、
///    画面バッファの読み取りはAppContainerが閉じている）
/// 2. **終わらずに待つ。** 畳むのはDaemon側で、Jobの取っ手が閉じればOSが始末する
///    ——**自分ではタイマーも上限も持たない**（寿命をOSハンドルに紐付ける、§10.1と同じ形）
pub fn run_as_console_holder() -> Result<(), String> {
    if unsafe {
        windows::Win32::System::Console::SetConsoleCtrlHandler(Some(swallow_ctrl_event), true)
    }
    .is_err()
    {
        // **黙って続けない。** ハンドラ無しで待つと、サンドボックスの子が撃った
        // `CTRL_BREAK_EVENT`で落ちる——そのとき症状は「シェルが起こせない」という
        // 遠い場所に出る（`B-10`）。
        return Err(
            "SetConsoleCtrlHandler failed; refusing to hold a console unguarded".to_string(),
        );
    }

    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// 制御イベントを「処理した」と答えて既定の終了を止める（§7.1.2の決定1）。
///
/// **入れるのは保持プロセスだけで、シェルには入れない。** 同じドメインのシェル同士が
/// 互いを落とせることは設計上の想定内である（§19.3.3）。
unsafe extern "system" fn swallow_ctrl_event(_ctrl_type: u32) -> windows::Win32::Foundation::BOOL {
    windows::Win32::Foundation::BOOL(1)
}
