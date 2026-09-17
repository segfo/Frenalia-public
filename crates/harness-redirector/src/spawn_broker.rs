//! [段階6f-2] サンドボックスの中の`CreateProcessW`系の呼び出しを、
//! **Spawn Daemonへの依頼**へ変換する。
//!
//! # 何のためにあるのか
//!
//! 生成禁止（`CHILD_PROCESS_RESTRICTED`。OSが子プロセス生成そのものを拒否する緩和策）を
//! 積まれたプロセスは、**どんな方法でも自力では子を作れない**。代わりに起こすのが
//! Spawn Daemonで、このモジュールは「`CreateProcessW`の引数」を「Daemonへの1件の要求」へ
//! 組み替える——**許可証ではない**。許否を決めるのはDaemon側の遷移ポリシーである。
//!
//! ```text
//!   アプリ → CreateProcessW → フック → [ここ] → 要求受付パイプ → Daemon
//!                                 ↑                                  │
//!                        PROCESS_INFORMATION へ詰めて返す ←──────────┘
//!                          （プロセス／スレッドのハンドルは複製済みで返る）
//! ```
//!
//! # 頼むのは「自力で作れない」ときだけである
//!
//! [`child_process_creation_is_blocked`]が偽なら、このモジュールは1行も働かない。
//! 今日の製品の既定（生成禁止を積まない）では**挙動が1ビットも変わらない**
//! ——`docs/STATUS.md`残課題#44が「自分の状態は自分に聞く」と決めた形をそのまま使う。
//!
//! # ここが決める4つ（`plans/DESIGN-MAC-ENFORCEMENT.md` §10.1.2）
//!
//! | 何を | どう決めるか |
//! |---|---|
//! | 実行ファイル | `lpApplicationName`があればそれ。無ければ**コマンドラインの先頭から**（[`image_candidates`]） |
//! | コンソール要否 | **呼び出し元の生成フラグから導く**（[`console_need_from_flags`]）。実行ファイル名から推測しない |
//! | 環境変数 | 呼び出し元が渡した環境ブロック。`NULL`なら**自分の環境を読んで載せる** |
//! | 標準入出力 | `STARTUPINFO`の3本、指定が無ければ`GetStdHandle`の3本 |
//!
//! # 運べないもの（**limitation**）
//!
//! - **標準の3本以外の継承ハンドル。** 呼び出し元が`bInheritHandles`で渡すつもりだった
//!   ハンドルは子へ届かない。今日は**3本とも届いていない**（生成禁止を積めば起動すらしない）
//!   ので後退ではないが、閉じていない（`docs/STATUS.md`の残課題）
//! - **`CreateProcessAsUserW`の`hToken`。** 電文にトークンの欄は無く、Daemonは系統の
//!   ドメインで起こす。AppContainerの中で得られるのは自分のトークンの複製だけなので、
//!   実測（`plans/mac-spike/RESULTS.md` §S1）で起きていた子と同じ文脈になる
//! - **コンソールと一時停止以外の生成フラグ**（優先度クラス・`CREATE_NEW_PROCESS_GROUP`等）。
//!   `CREATE_BREAKAWAY_FROM_JOB`が落ちるのは**意図**である（系統Jobから抜けさせない）
//! - **フックを迂回する経路**（`ntdll!NtCreateUserProcess`直叩き等）。カーネルが拒否したままで、
//!   それが正しい（D-01: フックは境界ではない）
//!
//! # ワイヤは両端で別々に実装されている
//!
//! このクレートは注入先の非信頼プロセスで動くので`harness-sandbox`に依存しない
//! （`Cargo.toml`の宣言）。**ずれてもコンパイラは教えてくれない**ので、
//! [`request_tests`]がバイト列を固定し、`harness-sandbox`側の`spawnd::wire_tests`に
//! **同じバイト列を`SpawnRequest`として読む守り**がある。

use std::ffi::c_void;
use std::sync::OnceLock;

use serde_json::{json, Value};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{SetLastError, BOOL, HANDLE, INVALID_HANDLE_VALUE, WIN32_ERROR};
use windows::Win32::Storage::FileSystem::{GetFullPathNameW, SearchPathW};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Threading::{GetThreadId, PROCESS_INFORMATION, STARTUPINFOW};

use super::*;
use crate::pipe_io::{connect, roundtrip};

/// 要求受付パイプの名前を運ぶ環境変数。
///
/// **`harness-sandbox`の`spawnd::REQUEST_PIPE_ENV`と同じ綴りでなければならない**
/// （クレートを跨いだ文字列の複製。`config::PROCESS_HOOKS_ENV`と同じ事情）。
pub(crate) const REQUEST_PIPE_ENV: &str = "HARNESS_SPAWN_REQUEST_PIPE";

/// 1往復に掛ける上限。**新しい数字を増やさない**——`harness-sandbox`の`spawnd::IO_TIMEOUT`
/// （5秒）と同じ値である。ここに引っ掛かるのは「Daemonが居るのに返事が来ない」ときで、
/// そのときは起こせなかったものとして呼び出し元へ失敗を返す。
const ROUNDTRIP_TIMEOUT_MS: u32 = 5_000;

/// 呼び出し元が`DETACHED_PROCESS`を指定した（＝コンソールを持たせない意思）。
const DETACHED_PROCESS: u32 = 0x0000_0008;
/// 呼び出し元が`CREATE_NO_WINDOW`を指定した（同上）。
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// `lpEnvironment`がUTF-16である。**立っていなければANSIである**——`CreateProcessW`でも
/// このフラグが無ければ環境ブロックはANSIとして読まれる（取り違えると環境が丸ごと化ける）。
const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;

/// 環境ブロックを読むときの上限。**NUL終端が壊れていても無限に読み進めない**ための安全弁
/// （`config::CONFIG_BLOB_MAX_LEN`と同じ役目）。Windowsの環境ブロックの実上限は32767文字だが、
/// 呼び出し元が作った任意のブロックを読むので余裕を持たせてある。
const ENV_BLOCK_MAX_CHARS: usize = 512 * 1024;

/// **このプロセス自身が、子プロセスを作れない状態にされているか**
/// （`PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`。段階⑤）。
///
/// # なぜ注入側から伝えず、子が自分で見るのか
///
/// 生成禁止は`CreateProcessW`の属性として**起動の瞬間に決まる**もので、
/// 注入する設定とは別の経路で入る。設定の欄として渡すと、渡し忘れた経路だけが
/// 「積まれているのに積まれていないつもり」になる——しかもその取り違えは、
/// **フックが無い子が静かに何もできない**という遠い症状でしか現れない。
/// **自分の状態は自分に聞くのが、経路を1つも数えなくてよい唯一の形である。**
///
/// # 1回だけ読む
///
/// 緩和策は起動の瞬間に決まり、**後から付けることも外すこともできない**（`ChildProcessPolicy`の
/// doc）。だから`OnceLock`で1回だけ問い合わせる——プロセス生成のたびに聞いても答えは同じである。
///
/// # 判定できなかったときは「積まれていない」へ倒す
///
/// 問い合わせに失敗したときに「積まれている」へ倒すと、**今日の既定（CoW/lazy）で
/// フック設置が失敗しただけの子が起動しなくなる**——危険が無い側で可用性だけを落とす。
/// 逆へ倒した場合に失われるのは、致命化と**この変換**であり、そのときも境界
/// （ACL・AppContainer）は1ミリも動かない（D-01: フックは境界ではない）。
pub(crate) fn child_process_creation_is_blocked() -> bool {
    static BLOCKED: OnceLock<bool> = OnceLock::new();
    *BLOCKED.get_or_init(query_child_process_policy)
}

fn query_child_process_policy() -> bool {
    use windows::Win32::System::SystemServices::PROCESS_MITIGATION_CHILD_PROCESS_POLICY;
    use windows::Win32::System::Threading::{
        GetCurrentProcess, GetProcessMitigationPolicy, ProcessChildProcessPolicy,
    };

    let mut policy = PROCESS_MITIGATION_CHILD_PROCESS_POLICY::default();
    let ok = unsafe {
        GetProcessMitigationPolicy(
            GetCurrentProcess(),
            ProcessChildProcessPolicy,
            &mut policy as *mut _ as *mut core::ffi::c_void,
            core::mem::size_of::<PROCESS_MITIGATION_CHILD_PROCESS_POLICY>(),
        )
    };
    if ok.is_err() {
        debug_log("spawn_broker: GetProcessMitigationPolicy(ProcessChildProcessPolicy) failed");
        return false;
    }
    // 最下位ビットが`NoChildProcessCreation`。`windows`のビットフィールドは
    // 匿名unionの`Anonymous`側にしか出ないので、生の`u32`として読む。
    let blocked = unsafe { policy.Anonymous.Flags } & 0x0000_0001 != 0;
    debug_log(&format!(
        "spawn_broker: child process creation blocked for self = {blocked}"
    ));
    blocked
}

/// 1件の`CreateProcess*`呼び出しのうち、**変換に要る引数だけ**を文字列へ起こした形。
///
/// # なぜ構造体なのか
///
/// 4本のフック（`CreateProcessW`／`AsUserW`／`A`／`WinExec`経由）が同じ関数を呼ぶ。
/// 引数が7つあり、うち3つは文字列なので、並びで渡すと**入れ替えてもコンパイルが通る**。
pub(crate) struct CreateCall {
    /// どのフックから来たか（診断のためだけに使う）。
    pub caller: &'static str,
    /// `lpApplicationName`。`None`は「コマンドラインの先頭から決めてほしい」。
    pub application_name: Option<String>,
    /// `lpCommandLine`。`None`は「実行ファイルだけで起こす」。
    pub command_line: Option<String>,
    pub creation_flags: u32,
    /// `lpEnvironment`。`NULL`は「自分の環境を継がせたい」。
    pub environment: *const c_void,
    /// `lpCurrentDirectory`。`None`は「呼び出し元と同じ」。
    pub current_directory: Option<String>,
    /// `lpStartupInfo`（`STARTUPINFOW`か`STARTUPINFOEXW`、あるいは`STARTUPINFOA`）。
    pub startup_info: *const c_void,
}

/// 頼めなかった理由。**呼び出し元へ返すエラーコードを分ける**ために型で持つ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BrokerFailure {
    /// 窓口の名前が環境変数に無い（＝Daemonの系統に居ない）。
    NoPipe,
    /// 実行ファイルを決められなかった。
    Unresolved,
    /// 窓口へ届かない・返事が来ない。
    Transport,
    /// **Daemonが断った**（遷移ポリシー・台帳・電文のいずれか）。
    Denied,
}

impl BrokerFailure {
    /// `SetLastError`へ渡す値。
    ///
    /// # なぜ拒否を`ERROR_ACCESS_DENIED`にするのか
    ///
    /// カーネルが生成を拒否したときは`ERROR_CHILD_PROCESS_BLOCKED`(367)が返る
    /// （`plans/mac-spike/RESULTS.md` §S1で実測）。**同じ値にすると、呼び出し元から見て
    /// 「Daemonが断った」と「カーネルが断った」が区別できない**——
    /// `plans/DESIGN-MAC-ENFORCEMENT.md` §10.2がその2つを分けて記録すると定めているのに、
    /// 呼び出し元の側でだけ混ざることになる。
    /// # 4つを4つのまま返す
    ///
    /// 呼び出し元へ返せるのは`FALSE`と**1つのエラーコード**だけである。だから
    /// **4つの原因に4つの値を割り当てる**——畳むと、実機で止まったときに
    /// 「宣言が無いのか、窓口へ届かないのか、そもそも系統に居ないのか」が読めない
    /// （2026-09-17の受け入れで、`NoPipe`と`Transport`を同じ値にしていたために
    /// 1往復を余計に使った）。
    pub(crate) fn last_error(self) -> u32 {
        match self {
            // 実行ファイルが見つからないのは、OSが返すのと同じ`ERROR_FILE_NOT_FOUND`。
            BrokerFailure::Unresolved => 2,
            // **窓口の名前が環境に無い**（`ERROR_ENVVAR_NOT_FOUND`）。綴りがそのまま原因を言う。
            BrokerFailure::NoPipe => 203,
            // 名前は在るが届かない・返事が来ない（`ERROR_PIPE_NOT_CONNECTED`）。
            BrokerFailure::Transport => 233,
            BrokerFailure::Denied => 5,
        }
    }
}

/// Daemonが起こした子。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Spawned {
    pub pid: u32,
    /// **呼び出し元のプロセスへ複製済み**のハンドル値（閉じるのは呼び出し元）。
    pub process: u64,
    pub thread: u64,
}

/// 頼む形なら頼んで、結果を`lpProcessInformation`へ詰めて返す。
///
/// 戻り値の`None`は「**頼む形ではない**」——呼び出し元のフックは今までどおり本物を呼ぶ。
/// `Some(BOOL(0))`は「頼んだが起こせなかった」で、`SetLastError`は済ませてある。
///
/// # Safety
/// `process_information`は`PROCESS_INFORMATION`を指すか`NULL`。`call`の各ポインタは
/// 呼び出し元のプロセスで読めること。
pub(crate) unsafe fn try_broker(
    call: &CreateCall,
    process_information: *mut c_void,
) -> Option<BOOL> {
    if !child_process_creation_is_blocked() {
        return None;
    }
    // **戻り値の置き場が無いなら横取りしない。** 起こしてから返せないと、
    // 誰も待てず誰も閉じられない子が残る。本物を呼べばカーネルが拒否して終わる。
    if process_information.is_null() {
        debug_log(&format!(
            "{}: lpProcessInformation is null; not brokering",
            call.caller
        ));
        return None;
    }
    match unsafe { broker(call) } {
        Ok(spawned) => {
            let pi = unsafe { &mut *(process_information as *mut PROCESS_INFORMATION) };
            let process = HANDLE(spawned.process as usize as *mut c_void);
            let thread = HANDLE(spawned.thread as usize as *mut c_void);
            pi.hProcess = process;
            pi.hThread = thread;
            pi.dwProcessId = spawned.pid;
            // **スレッドIDは電文に無い。** ハンドルから引く——`PROCESS_INFORMATION`の
            // 欄を0のままにすると、`PostThreadMessage`等を使う呼び出し元が静かに外す。
            pi.dwThreadId = unsafe { GetThreadId(thread) };
            debug_log(&format!(
                "{}: brokered pid={} thread_id={}",
                call.caller, spawned.pid, pi.dwThreadId
            ));
            Some(BOOL(1))
        }
        Err(failure) => {
            debug_log(&format!(
                "{}: the spawn daemon did not start the child ({failure:?}); \
                 returning FALSE with last error {}",
                call.caller,
                failure.last_error()
            ));
            unsafe { SetLastError(WIN32_ERROR(failure.last_error())) };
            Some(BOOL(0))
        }
    }
}

/// 1往復して、起きた子を返す。
///
/// # Safety
/// [`try_broker`]と同じ。
unsafe fn broker(call: &CreateCall) -> Result<Spawned, BrokerFailure> {
    // **自分のファイルフックへ戻るので、ガードを握ってから開く**（[`crate::pipe_io`]のdoc）。
    // 既に握られていれば`None`が返るだけで、そのときも素通し済みなので続けてよい。
    let _guard = ReentryGuard::try_acquire();

    let Some(pipe_name) = get_env(REQUEST_PIPE_ENV) else {
        return Err(BrokerFailure::NoPipe);
    };
    debug_log(&format!(
        "{}: brokering (flags={:#x}) command_line={:?}",
        call.caller, call.creation_flags, call.command_line
    ));
    let Some(image) = resolve_image(
        call.application_name.as_deref(),
        call.command_line.as_deref(),
    ) else {
        return Err(BrokerFailure::Unresolved);
    };
    // 呼び出し元がコマンドラインを渡さなかったなら、実行ファイルだけの1本を組む
    // （**電文の`command_line`は空にできない**——`lpCommandLine`が空だと子のargvが空になる）。
    let command_line = match call.command_line.as_deref() {
        Some(line) if !line.trim().is_empty() => line.to_string(),
        _ => format!("\"{image}\""),
    };
    let cwd = call
        .current_directory
        .as_deref()
        .and_then(full_path)
        .or_else(|| {
            std::env::current_dir()
                .ok()
                .map(|p| p.to_string_lossy().into_owned())
        })
        .unwrap_or_default();
    let env = unsafe { environment_for(call) };
    let (stdin, stdout, stderr) = unsafe { caller_handles(call.startup_info) };

    let payload = build_request(
        &image,
        &command_line,
        &cwd,
        &env,
        stdin,
        stdout,
        stderr,
        console_need_from_flags(call.creation_flags),
        call.creation_flags & CREATE_SUSPENDED_FLAG != 0,
    );

    // **接続は毎回開いて閉じる**（受付への接続と違って張りっぱなしにしない。
    // `crate::pipe_io`のモジュールdocに理由がある）。
    let Some(pipe) = connect(&pipe_name) else {
        debug_log(&format!(
            "{}: cannot open the spawn request pipe {pipe_name}",
            call.caller
        ));
        return Err(BrokerFailure::Transport);
    };
    debug_log(&format!(
        "{}: sending {} bytes for image={image}",
        call.caller,
        payload.len()
    ));
    let reply = roundtrip(pipe, payload.as_bytes(), ROUNDTRIP_TIMEOUT_MS);
    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(pipe);
    }
    let Some(reply) = reply else {
        return Err(BrokerFailure::Transport);
    };
    debug_log(&format!(
        "{}: reply={}",
        call.caller,
        String::from_utf8_lossy(&reply)
    ));
    match parse_reply(&reply) {
        Reply::Spawned(spawned) => Ok(spawned),
        Reply::Denied => {
            debug_log(&format!(
                "{}: denied by the spawn daemon: {}",
                call.caller,
                String::from_utf8_lossy(&reply)
            ));
            Err(BrokerFailure::Denied)
        }
    }
}

/// Daemonの答え。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reply {
    Spawned(Spawned),
    /// 断られた。**理由は運ばない**——呼び出し元へ返せるのは`FALSE`と1つのエラーコードだけで、
    /// 理由はDaemon側の待ち行列（`.harness/transitions/`）に残る。
    Denied,
}

/// 応答JSONから結論を取り出す。**知らない綴りは拒否側へ倒す**
/// ——「起きた」と読み違えると、呼び出し元は空のハンドルで待つことになる。
pub(crate) fn parse_reply(reply: &[u8]) -> Reply {
    let Ok(value) = serde_json::from_slice::<Value>(reply) else {
        return Reply::Denied;
    };
    if value.get("kind").and_then(Value::as_str) != Some("spawned") {
        return Reply::Denied;
    }
    let (Some(pid), Some(process), Some(thread)) = (
        value.get("pid").and_then(Value::as_u64),
        value.get("process").and_then(Value::as_u64),
        value.get("thread").and_then(Value::as_u64),
    ) else {
        return Reply::Denied;
    };
    // **0のハンドルを「起きた」として通さない。** 呼び出し元はこれで待とうとする。
    if process == 0 || thread == 0 {
        return Reply::Denied;
    }
    Reply::Spawned(Spawned {
        pid: pid as u32,
        process,
        thread,
    })
}

/// 電文（`SpawnRequest::Spawn`）を組む。
///
/// **欄の綴りは`harness-sandbox`の`spawnd::SpawnRequest`と1文字も違ってはいけない**
/// （モジュールdoc「ワイヤは両端で別々に実装されている」）。
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_request(
    image: &str,
    command_line: &str,
    cwd: &str,
    env: &[(String, String)],
    stdin: Option<u64>,
    stdout: Option<u64>,
    stderr: Option<u64>,
    console: &str,
    suspended: bool,
) -> String {
    json!({
        "kind": "spawn",
        "image": image,
        "command_line": command_line,
        "cwd": cwd,
        // **`null`は「申告していない」で、`[]`は「空だと申告した」である**（`P-11`）。
        // フックは常に申告する——`None`のまま運ぶと、呼び出し元がプロセス内で
        // 設定した変数が子から消える（`SpawnRequest::Spawn::env`のdocの指示）。
        "env": env,
        "handles": { "stdin": stdin, "stdout": stdout, "stderr": stderr },
        "console": console,
        "suspended": suspended,
    })
    .to_string()
}

/// 呼び出し元の生成フラグから、子がコンソールを要るかを導く。
///
/// **実行ファイル名から推測しない**（`ConsoleNeed`のdocが禁じている形）。
/// `CREATE_NO_WINDOW`も`DETACHED_PROCESS`も付けていない呼び出し元は、
/// **自分のコンソールを子へ継承させるつもり**である。
///
/// `CREATE_NEW_CONSOLE`（新しいコンソールが欲しい）はここでは`required`になる
/// ——Daemonは新しいコンソールを作らないが、保持プロセスのコンソールを貸すのが
/// 「要る」側の最も近い答えで、貸さないと**何も実行せずexit 0**になる。
pub(crate) fn console_need_from_flags(creation_flags: u32) -> &'static str {
    if creation_flags & (CREATE_NO_WINDOW | DETACHED_PROCESS) != 0 {
        "not_needed"
    } else {
        "required"
    }
}

/// 子へ渡す環境。
///
/// # Safety
/// `call.environment`は`NULL`か、有効な環境ブロックの先頭。
unsafe fn environment_for(call: &CreateCall) -> Vec<(String, String)> {
    if call.environment.is_null() {
        // **呼び出し元は「自分の環境を継がせたい」と言っている。** 自分で読んで載せる
        // ——申告しないまま運ぶと、プロセス内で`SetEnvironmentVariableW`した値が消える。
        return own_environment();
    }
    if call.creation_flags & CREATE_UNICODE_ENVIRONMENT != 0 {
        let block = unsafe { read_env_block_utf16(call.environment as *const u16) };
        parse_env_block_utf16(&block)
    } else {
        let block = unsafe { read_env_block_ansi(call.environment as *const u8) };
        parse_env_block_utf16(&ansi_to_wide(&block))
    }
}

/// 自プロセスの環境を`(名前, 値)`で。
///
/// **`vars_os`を使う**——`vars`はUnicodeにできない値でpanicする。JSONはUTF-8なので
/// 化けるものは化けるが、**そこで落ちるより渡すほうが害が小さい**。
fn own_environment() -> Vec<(String, String)> {
    std::env::vars_os()
        .map(|(name, value)| {
            (
                name.to_string_lossy().into_owned(),
                value.to_string_lossy().into_owned(),
            )
        })
        .collect()
}

/// 環境ブロック（NUL区切り・末尾は二重NUL）を`(名前, 値)`へ。
///
/// # 先頭が`=`の項目を落とす
///
/// `=C:`のような項目は**ドライブごとのカレントディレクトリ**を持つ隠し変数で、
/// 名前が空になる。標準ライブラリの`vars_os`も同じ理由で飛ばす。
/// Daemonはcwdを別の欄で受け取るので、落としても失われるものは無い。
pub(crate) fn parse_env_block_utf16(block: &[u16]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in block.split(|&c| c == 0) {
        if entry.is_empty() {
            continue;
        }
        let text = String::from_utf16_lossy(entry);
        if text.starts_with('=') {
            continue;
        }
        if let Some((name, value)) = text.split_once('=') {
            out.push((name.to_string(), value.to_string()));
        }
    }
    out
}

/// ANSIのバイト列を、**埋め込まれたNULごと**UTF-16へ。
///
/// 環境ブロックは項目の区切りにNULを使うので、文字列として1項目ずつ変換するのではなく
/// **長さを指定してまとめて変換する**（`MultiByteToWideChar`は長さを渡せばNULも変換する）。
fn ansi_to_wide(bytes: &[u8]) -> Vec<u16> {
    use windows::Win32::Globalization::{MultiByteToWideChar, CP_ACP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS};

    if bytes.is_empty() {
        return Vec::new();
    }
    let needed = unsafe {
        MultiByteToWideChar(CP_ACP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0), bytes, None)
    };
    if needed <= 0 {
        return Vec::new();
    }
    let mut wide = vec![0u16; needed as usize];
    let written = unsafe {
        MultiByteToWideChar(
            CP_ACP,
            MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0),
            bytes,
            Some(&mut wide),
        )
    };
    wide.truncate(written.max(0) as usize);
    wide
}

/// ANSIの1本の文字列（NULを含まない）をRustの文字列へ。
///
/// **既定のコードページで変換する**（日本語環境ならCP932）。`from_utf8_lossy`で済ませると、
/// パスに含まれる非ASCII文字が化けて解決できなくなる。
pub(crate) fn ansi_to_string(bytes: &[u8]) -> String {
    String::from_utf16_lossy(&ansi_to_wide(bytes))
}

/// UTF-16の環境ブロックを、二重NULまで読み出す。
///
/// # Safety
/// `block`は`NULL`でなく、二重NULで終わる領域を指すこと。
unsafe fn read_env_block_utf16(block: *const u16) -> Vec<u16> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < ENV_BLOCK_MAX_CHARS {
        let c = unsafe { *block.add(i) };
        if c == 0 && i > 0 && unsafe { *block.add(i - 1) } == 0 {
            break;
        }
        if c == 0 && i == 0 {
            break;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// ANSIの環境ブロックを、二重NULまで読み出す。
///
/// # Safety
/// [`read_env_block_utf16`]と同じ。
unsafe fn read_env_block_ansi(block: *const u8) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < ENV_BLOCK_MAX_CHARS {
        let c = unsafe { *block.add(i) };
        if c == 0 && i > 0 && unsafe { *block.add(i - 1) } == 0 {
            break;
        }
        if c == 0 && i == 0 {
            break;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// 子へ渡す標準入出力（呼び出し元のプロセスの中の値）。
///
/// `STARTF_USESTDHANDLES`が立っていれば`STARTUPINFO`の3本、立っていなければ
/// **呼び出し元自身の標準ハンドル**——後者が「フラグを立てない呼び出し元は自分の3本を
/// 継承させるつもり」という`CreateProcess`の既定そのものである。
///
/// # Safety
/// `startup_info`は`STARTUPINFOW`／`STARTUPINFOEXW`／`STARTUPINFOA`のいずれかを指すか`NULL`。
/// **どれでも先頭の並びは同じ**なので、読む3本と`dwFlags`の位置は共通である
/// （`STARTUPINFOA`と`STARTUPINFOW`は文字列の型だけが違い、どちらもポインタ幅）。
unsafe fn caller_handles(startup_info: *const c_void) -> (Option<u64>, Option<u64>, Option<u64>) {
    const STARTF_USESTDHANDLES: u32 = 0x0000_0100;

    if !startup_info.is_null() {
        let si = unsafe { &*(startup_info as *const STARTUPINFOW) };
        if si.dwFlags.0 & STARTF_USESTDHANDLES != 0 {
            return (
                handle_value(si.hStdInput),
                handle_value(si.hStdOutput),
                handle_value(si.hStdError),
            );
        }
    }
    unsafe {
        (
            GetStdHandle(STD_INPUT_HANDLE).ok().and_then(handle_value),
            GetStdHandle(STD_OUTPUT_HANDLE).ok().and_then(handle_value),
            GetStdHandle(STD_ERROR_HANDLE).ok().and_then(handle_value),
        )
    }
}

/// 電文へ載せられるハンドル値か。**無効な値を`0`として載せない**
/// ——Daemonは`null`を「申告なし＝`NUL`へ捨てる」と読むので、そちらへ倒す。
fn handle_value(handle: HANDLE) -> Option<u64> {
    if handle.is_invalid() || handle == INVALID_HANDLE_VALUE {
        return None;
    }
    Some(handle.0 as usize as u64)
}

/// 起こす実行ファイルの絶対パス。
///
/// # `lpApplicationName`があるとき
///
/// **それだけを見る**（拡張子は補わない——`CreateProcess`もこの引数には補わない）。
/// 相対パスは**呼び出し元のcwd**で解決する。`lpCurrentDirectory`は使わない
/// ——`CreateProcess`のこの引数は子のcwdであって、実行ファイルの解決には関与しない。
///
/// # `NULL`のとき
///
/// コマンドラインの先頭から候補を作り（[`image_candidates`]）、**OSと同じ探索順**で
/// 最初に見つかったものを返す。`SearchPathW`は「実行像のあるディレクトリ → カレント
/// ディレクトリ → System32 → Windows → `PATH`」の順で探し、拡張子が無ければ`.exe`を補う。
pub(crate) fn resolve_image(
    application_name: Option<&str>,
    command_line: Option<&str>,
) -> Option<String> {
    if let Some(name) = application_name {
        let full = full_path(name)?;
        // **存在まで確かめる。** 確かめないと、起こせない理由が「Daemonが断った」の顔で返る。
        return std::path::Path::new(&full).is_file().then_some(full);
    }
    let command_line = command_line?;
    image_candidates(command_line)
        .into_iter()
        .find_map(|candidate| search_path(&candidate))
}

/// `lpApplicationName`が`NULL`のときに、コマンドラインの先頭から作る実行ファイルの候補列。
///
/// # 規則（`CreateProcessW`のdocumented behaviour）
///
/// - 引用符で始まるなら、**閉じ引用符まで**が実行ファイル（候補は1つ）
/// - そうでなければ、**空白で区切った前置を順に**試す。
///   `c:\program files\sub dir\app name` なら `c:\program`→`c:\program files\sub`→… の順
///
/// **ここをOSとずらしてはいけない**——ずらすと、判定したのと違う実行ファイルが起きる。
/// だから期待値を手で書いたテストではなく、**OSに実際に起こさせて突き合わせる**
/// （[`resolution_tests`]）。
pub(crate) fn image_candidates(command_line: &str) -> Vec<String> {
    let trimmed = command_line.trim_start_matches([' ', '\t']);
    if let Some(rest) = trimmed.strip_prefix('"') {
        let end = rest.find('"').unwrap_or(rest.len());
        let quoted = &rest[..end];
        return if quoted.is_empty() {
            Vec::new()
        } else {
            vec![quoted.to_string()]
        };
    }
    let mut out: Vec<String> = Vec::new();
    let mut push = |candidate: &str| {
        let candidate = candidate.trim_end_matches([' ', '\t']);
        if !candidate.is_empty() && !out.iter().any(|existing| existing == candidate) {
            out.push(candidate.to_string());
        }
    };
    for (index, byte) in trimmed.bytes().enumerate() {
        if byte == b' ' || byte == b'\t' {
            push(&trimmed[..index]);
        }
    }
    push(trimmed);
    out
}

/// `SearchPathW`で1つ解決する。**拡張子が無ければ`.exe`を補う**（`CreateProcess`と同じ）。
fn search_path(name: &str) -> Option<String> {
    let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let extension: Vec<u16> = ".exe".encode_utf16().chain(std::iter::once(0)).collect();
    let mut buffer = vec![0u16; 1024];
    let written = unsafe {
        SearchPathW(
            PCWSTR::null(),
            PCWSTR(name_w.as_ptr()),
            PCWSTR(extension.as_ptr()),
            Some(&mut buffer),
            None,
        )
    };
    if written == 0 || written as usize >= buffer.len() {
        return None;
    }
    Some(String::from_utf16_lossy(&buffer[..written as usize]))
}

/// 相対パスを**呼び出し元のcwd**で絶対にする（存在は確かめない）。
fn full_path(path: &str) -> Option<String> {
    let path_w: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut buffer = vec![0u16; 1024];
    let written = unsafe {
        GetFullPathNameW(
            PCWSTR(path_w.as_ptr()),
            Some(&mut buffer),
            None::<*mut PWSTR>,
        )
    };
    if written == 0 || written as usize >= buffer.len() {
        return None;
    }
    Some(String::from_utf16_lossy(&buffer[..written as usize]))
}

#[cfg(test)]
#[path = "spawn_broker_tests.rs"]
mod spawn_broker_tests;
