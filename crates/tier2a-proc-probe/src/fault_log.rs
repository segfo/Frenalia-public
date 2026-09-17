//! [残課題#52] **壊した瞬間の場所を記録する受け皿**（VEH＝ベクトル化例外ハンドラ）。
//!
//! # なぜこれだけでは足りないのか（**先に読むこと**）
//!
//! いまプローブが落ちる`0xC0000374`（ヒープ破壊）は、**このハンドラでは捕まらない**。
//! ヒープ破壊はアロケータが`fail-fast`（誰にも捕まえさせず即死させるWindowsの仕組み）で
//! 落とすので、例外ハンドラを飛び越えるためである。
//!
//! ```text
//!   素のまま         : どこかで破壊 → 後の確保/解放で検知 → fail-fast（ここを飛び越えて即死）
//!   Page Heap(Full)  : 破壊した瞬間に番兵ページを踏む → ただのアクセス違反 → ここで捕まる
//! ```
//!
//! **つまりこのモジュールはPage Heap(Full)と対で使う。** 片方だけでは何も出ない。
//! 有効化はテスト側（`harness-sandbox`の`page_heap`）がレジストリで行う。
//!
//! # 捕まえるが、**握りつぶさない**
//!
//! 記録したら`EXCEPTION_CONTINUE_SEARCH`を返し、**既定の死に方へ渡す**。
//! `EXCEPTION_CONTINUE_EXECUTION`で続行すると、壊れたヒープの上を走ることになり、
//! テスト用のプローブであっても未定義である（捕まえる目的は「場所を知ること」であって
//! 「落ちないこと」ではない）。
//!
//! # ハンドラの中で確保しない
//!
//! 呼ばれる時点でヒープが壊れている可能性があるので、`format!`・`String`・`Vec`のような
//! **確保を伴うものを1つも踏まない**。記録先のパスは登録時に用意して漏らし（`Box::leak`）、
//! 本文はスタック上の固定長バッファへ手で組み、素の`CreateFileW`＋`WriteFile`で書く。
//!
//! # 張られたときだけ動く
//!
//! [`FAULT_LOG_ENV`]が無ければ**ハンドラを登録しない**。同じプローブは
//! `cow-diagnostics`など他の的でも使われるので、既定では挙動を1ビットも変えない
//! （6f-2で足した`HARNESS_REDIRECTOR_DEBUG_LOG`と同じ、張ったときだけ中身が出る形）。

#[cfg(windows)]
use std::sync::OnceLock;

/// 記録先のパスを渡す環境変数。**テストからしか読まれない**ので`HARNESS_TEST_`で始める
/// （`crates/harness-cli/tests/env_var_naming.rs`が機械判定する規約D-86）。
pub const FAULT_LOG_ENV: &str = "HARNESS_TEST_PROBE_FAULT_LOG";

/// 記録する例外コード。**全部を書かない**——COM/RPCは第一機会の例外を正常系で投げるので、
/// 何でも書くと本命の1行が埋もれる。ここに挙げたのは「これが出たら普通は死ぬ」ものだけ。
#[cfg(windows)]
const FATAL_CODES: &[u32] = &[
    0xC000_0005, // ACCESS_VIOLATION（Page Heapの番兵ページを踏むとこれになる）
    0xC000_0006, // IN_PAGE_ERROR
    0xC000_001D, // ILLEGAL_INSTRUCTION
    0xC000_008C, // ARRAY_BOUNDS_EXCEEDED
    0xC000_0374, // HEAP_CORRUPTION（fail-fastで来ないこともあるが、来たら書く）
    0xC000_0409, // STACK_BUFFER_OVERRUN
];

#[cfg(windows)]
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

/// 記録先（UTF-16・NUL終端）。**登録時に用意して漏らす**ので、ハンドラ内では読むだけ。
#[cfg(windows)]
static LOG_PATH: OnceLock<&'static [u16]> = OnceLock::new();

/// スタック上だけで1行を組む固定長バッファ（確保しない）。
#[cfg(windows)]
struct Line {
    bytes: [u8; 4096],
    len: usize,
}

#[cfg(windows)]
impl Line {
    fn new() -> Self {
        Line {
            bytes: [0; 4096],
            len: 0,
        }
    }

    fn put(&mut self, s: &[u8]) {
        for &b in s {
            if self.len < self.bytes.len() {
                self.bytes[self.len] = b;
                self.len += 1;
            }
        }
    }

    /// `0x`付きの16進。**`format!`を使わない**（確保するため）。
    fn hex(&mut self, value: usize) {
        self.put(b"0x");
        let mut started = false;
        let bits = usize::BITS as usize;
        let mut shift = bits;
        while shift >= 4 {
            shift -= 4;
            let nibble = ((value >> shift) & 0xF) as u8;
            if nibble != 0 || started || shift == 0 {
                started = true;
                self.put(&[if nibble < 10 {
                    b'0' + nibble
                } else {
                    b'a' + (nibble - 10)
                }]);
            }
        }
    }

    fn dec(&mut self, value: u32) {
        if value >= 10 {
            self.dec(value / 10);
        }
        self.put(&[b'0' + (value % 10) as u8]);
    }
}

/// [`FAULT_LOG_ENV`]が張られていればVEHを1つ登録する。**張られていなければ何もしない。**
///
/// `main`の**いちばん最初**で呼ぶこと——引数解析の途中で落ちても記録が残るようにするため。
#[cfg(windows)]
pub fn install_if_requested() {
    use windows::Win32::System::Diagnostics::Debug::AddVectoredExceptionHandler;

    let Ok(path) = std::env::var(FAULT_LOG_ENV) else {
        return;
    };
    if path.is_empty() {
        return;
    }
    // ここでの確保は安全（まだ壊れていない）。以後ハンドラは読むだけ。
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    if LOG_PATH.set(Box::leak(wide.into_boxed_slice())).is_err() {
        return; // 二重登録はしない
    }
    // 第1引数が非0＝**最初に呼ばれる**。他のハンドラが先に握って握り潰す形を避ける。
    unsafe { AddVectoredExceptionHandler(1, Some(on_exception)) };
}

#[cfg(not(windows))]
pub fn install_if_requested() {}

/// ハンドラを**登録したか**。
///
/// # なぜ名乗らせるのか
///
/// 「張らなければ登録しない」は、記録ファイルの有無だけでは検算できない
/// ——登録してしまう実装でも、**書き先が違えば**こちらの指定した場所には現れず、
/// テストは緑のまま通る（実際に変異テストで素通りした）。
/// だから**登録したかどうかを本人に言わせて**、そこを的にする
/// （`--idle-secs`の腕が`ctrl_guard`を名乗るのと同じ形）。
#[cfg(windows)]
pub fn installed() -> bool {
    LOG_PATH.get().is_some()
}

#[cfg(not(windows))]
pub fn installed() -> bool {
    false
}

#[cfg(windows)]
unsafe extern "system" fn on_exception(
    info: *mut windows::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS,
) -> i32 {
    unsafe {
        if info.is_null() || (*info).ExceptionRecord.is_null() {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        let record = &*(*info).ExceptionRecord;
        let code = record.ExceptionCode.0 as u32;
        if !FATAL_CODES.contains(&code) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        if let Some(path) = LOG_PATH.get() {
            write_record(path, record);
        }
    }
    // **握りつぶさない。** 既定の死に方へ渡す（モジュールdoc参照）。
    EXCEPTION_CONTINUE_SEARCH
}

#[cfg(windows)]
unsafe fn write_record(
    path: &[u16],
    record: &windows::Win32::System::Diagnostics::Debug::EXCEPTION_RECORD,
) {
    use windows::Win32::System::Diagnostics::Debug::RtlCaptureStackBackTrace;

    let mut line = Line::new();
    line.put(b"[probe-fault] pid=");
    line.dec(std::process::id());
    line.put(b" code=");
    // **`u32`を経由する。** `NTSTATUS`は`i32`なので、そのまま`usize`にすると
    // `0xffffffffc0000005`のように符号拡張して、既知のコードと目で照合できなくなる。
    line.hex(record.ExceptionCode.0 as u32 as usize);
    line.put(b" at=");
    let fault_ip = record.ExceptionAddress as usize;
    line.hex(fault_ip);
    line.put(b" ");
    unsafe { put_module(&mut line, fault_ip) };

    // アクセス違反だけは「読みか書きか」と「触ったアドレス」が分かる。
    // **観測していない欄を既定値で埋めない**（`P-11`）ので、分かるときだけ書く。
    if record.ExceptionCode.0 as u32 == 0xC000_0005 && record.NumberParameters >= 2 {
        line.put(b" access=");
        line.put(match record.ExceptionInformation[0] {
            0 => b"read".as_slice(),
            1 => b"write".as_slice(),
            8 => b"execute".as_slice(),
            _ => b"unknown".as_slice(),
        });
        line.put(b" target=");
        line.hex(record.ExceptionInformation[1]);
    }
    line.put(b"\r\n");

    // 戻りアドレス列。**シンボルは引かない**（AppContainerの中で`dbghelp`は当てにできない）。
    // モジュール名＋オフセットで「こちらのコードか、システムのDLLか」は判る。
    let mut frames: [*mut core::ffi::c_void; 24] = [core::ptr::null_mut(); 24];
    let captured = unsafe { RtlCaptureStackBackTrace(1, &mut frames, None) };
    for frame in frames.iter().take(captured as usize) {
        line.put(b"[probe-fault]   frame ");
        let addr = *frame as usize;
        line.hex(addr);
        line.put(b" ");
        unsafe { put_module(&mut line, addr) };
        line.put(b"\r\n");
    }

    unsafe { append(path, &line.bytes[..line.len]) };
}

/// アドレスを`モジュール名+0xオフセット`にする。解決できなければ`?`。
#[cfg(windows)]
unsafe fn put_module(line: &mut Line, addr: usize) {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::System::LibraryLoader::{
        GetModuleFileNameW, GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    };

    let mut module = HMODULE::default();
    let got = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            PCWSTR(addr as *const u16),
            &mut module,
        )
    };
    if got.is_err() || module.is_invalid() {
        line.put(b"?");
        return;
    }
    let mut name = [0u16; 260];
    let written = unsafe { GetModuleFileNameW(module, &mut name) } as usize;
    // 末尾の要素名だけを取る（フルパスは長いうえ、知りたいのはどのDLLかである）。
    let slice = &name[..written.min(name.len())];
    let start = slice
        .iter()
        .rposition(|&c| c == b'\\' as u16 || c == b'/' as u16)
        .map_or(0, |i| i + 1);
    for &c in &slice[start..] {
        // ASCII以外は`?`にする。**ここで変換器を呼ぶと確保する**ため。
        line.put(&[if c < 0x80 { c as u8 } else { b'?' }]);
    }
    line.put(b"+");
    line.hex(addr.wrapping_sub(module.0 as usize));
}

/// 追記で1回書く。**標準ライブラリのファイルIOを使わない**（バッファと確保を踏むため）。
#[cfg(windows)]
unsafe fn append(path: &[u16], bytes: &[u8]) {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, WriteFile, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_ALWAYS,
    };

    unsafe {
        let Ok(handle) = CreateFileW(
            PCWSTR(path.as_ptr()),
            FILE_APPEND_DATA.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        ) else {
            return;
        };
        let mut written = 0u32;
        let _ = WriteFile(handle, Some(bytes), Some(&mut written), None);
        let _ = CloseHandle(handle);
    }
}

/// **わざと壊す的**（`--fault-self`）。**2つの別々の問い**を、別々のモードで確かめる。
///
/// | mode | 何をするか | 落ちる条件 | 何の判定か |
/// |---|---|---|---|
/// | `overflow` | 64バイト確保の**1バイト先**へ書く | **Page Heap(Full)が効いているときだけ**（無効ならヒープの遊びに収まって黙って通る） | **Page Heapが本当に効いているか** |
/// | `null` | アドレス0へ書く | **常に**（Page Heapと無関係） | **VEHが本当に記録するか** |
/// | `none` | 何もしない | 落ちない | 対照 |
///
/// **2つを1つのモードで兼ねられない。** `overflow`はPage Heapが無ければ落ちないので
/// VEHの検算にならず、`null`は常に落ちるのでPage Heapの検算にならない。
/// 兼ねようとすると「VEHが壊れている」と「Page Heapが効いていない」を取り違える。
///
/// 戻り値の`survived`が`true`で返るのは**落ちなかったとき**だけである
/// （落ちたらこの関数からは返らない）。
pub fn run(mode: &str) -> serde_json::Value {
    match mode {
        // Page Heapの検算。
        "overflow" => {
            let mut buffer: Vec<u8> = vec![0u8; 64];
            let base = buffer.as_mut_ptr();
            // 最適化で消えないよう`write_volatile`で書く。
            unsafe { std::ptr::write_volatile(base.add(64), 0x41) };
            std::hint::black_box(&buffer);
            report("overflow")
        }
        // VEHの検算。**Page Heapが無くても落ちる**ので非昇格のテストから撃てる。
        "null" => {
            unsafe { std::ptr::write_volatile(std::ptr::null_mut::<u8>(), 0x41) };
            report("null")
        }
        other => report(other),
    }
}

/// **腕は自分で名乗る。** `veh_installed`は「受け皿を張ったときだけ登録する」の的で、
/// 記録ファイルの有無では代用できない（[`installed`]のdoc）。
fn report(mode: &str) -> serde_json::Value {
    serde_json::json!({
        "mode": mode,
        "survived": true,
        "veh_installed": installed(),
    })
}
