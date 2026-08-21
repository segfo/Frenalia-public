//! **Classic ETW（MOF / System Logger系）**でのFSアクセス拒否収集。
//!
//! # このモジュールは意図的に残してある（消さないこと）
//!
//! **本番の収集経路は[`super::session`]（マニフェストベース）であり、こちらは使っていない。**
//! それでも残すのは、`docs/CODE-STRUCTURE-RULES.md`規則2（一回性の調査実験をテストとして
//! 残さない）に対する**明示的な例外**としてである。理由は2つ:
//!
//! 1. **採否の根拠が実測値である**（イベント量9倍差・private system loggerの8本制限）。
//!    数値で決めた判断は、環境が変われば覆りうる。再測定できる状態を残しておく価値がある。
//! 2. **マニフェスト系統は「OSバージョンで増減しやすい」**のに対しMOFは古くから安定している。
//!    将来マニフェスト側が捉えきれない事象に当たったとき、**対比して切り分けるための対照群**が要る。
//!
//! 両系統の実測比較と採否の根拠は`plans/etw-spike/RESULTS.md` §8。
//! 対比を再実行するには`dev-elevated-run.exe spike-etw-fs`
//! （`spike_tests::compare_mof_and_manifest_paths_for_absolute_and_relative_opens`）。
//!
//! # 系統の違い
//!
//! [`super::session`]（マニフェストベース＝Modern ETW）とは**別系統**である。両者は
//! 「同じものの書き方違い」ではなく、識別・有効化・メタデータ解決・イベント内容のすべてが違う。
//!
//! | 観点 | MOF / NT Kernel Logger（本モジュール） | マニフェスト（[`super::session`]） |
//! |---|---|---|
//! | 世代 | Classic ETW | Modern ETW |
//! | 定義 | MOFクラス・イベント型 | XMLマニフェスト |
//! | 識別 | クラスGUID + Opcode(EventType) + Version | プロバイダGUID + Event ID + Version |
//! | 有効化 | `EVENT_TRACE_PROPERTIES.EnableFlags` | `EnableTraceEx2`のLevel + 64bit Keywords |
//! | セッション | System Logger系 | 通常のETWセッション |
//! | メタデータ | MOF定義（WMIに登録済み） | マニフェスト |
//! | 互換性 | 古くから安定 | OSバージョンで増減しやすい |
//!
//! # 対応関係（MSDNのMOF定義より）
//!
//! `FileIo`クラスGUID `{90CBDC39-4A3E-11D1-84F4-0000F80464E3}`、`EventVersion(2)`。
//!
//! | MOF | フィールド | マニフェスト側の対応 |
//! |---|---|---|
//! | `FileIo_Create`（EventType **64**） | `IrpPtr`, `TTID`, `FileObject`, `CreateOptions`, `FileAttributes`, `ShareAccess`, **`OpenPath`** | `Create`(Id=12) |
//! | `FileIo_OpEnd`（EventType **76**） | `IrpPtr`, `ExtraInfo`, **`NtStatus`** | `OperationEnd`(Id=24) |
//! | `FileIo_Name`（EventType 0/32/35/**36**） | `FileObject`, `FileName` | Id=10/11 |
//!
//! **`DesiredAccess`はMOF側にも無い**（`FileIo_Create`は上記7項目のみ）。この制約は系統に依らない。
//!
//! # なぜ両系統を試すのか
//!
//! `FileIo_Create.OpenPath`はMOFで「Path to the file」と定義されており、マニフェスト側の
//! `FileName`と**同じ値とは限らない**。特にRootDirectory相対のopen（`cmd.exe`の`>`リダイレクト等、
//! [BUG-033](../../../../../docs/bugs/BUG-033.md)で踏んだ形）で完全パスになるかどうかは
//! 系統ごとに違いうる。実測して比べる。
//!
//! またMOF側には**EventType 36（File rundown）＝トレース終了時に全オープンファイルを列挙**する
//! 仕組みがあり、これはマニフェスト側に対応が見当たらない。トレース開始前に開かれた
//! ファイルオブジェクトの名前解決に効く可能性がある。
//!
//! # `Process`クラス — こちらにしか無いもの（2026-08-15追記）
//!
//! **`Process_V4_TypeGroup1`は`CommandLine`を持つ**。マニフェスト側の
//! `Microsoft-Windows-Kernel-Process`の`ProcessStart`(Id=1)には**v0〜v4のどれにも
//! コマンドラインのフィールドが無い**（同プロバイダの全43イベントで0件。実測）。
//! MAC遷移ポリシーのargv軸（`plans/PLAN-MAC-RECURSIVE-DESCENDANTS.md`決定14）は
//! 観測側でargvを拾えることを前提にしているので、**それが取れる唯一のETW経路がここ**である。
//!
//! 同クラスは`PackageFullName`も持つ。`plans/etw-spike/RESULTS.md` §8.4の採否比較表は
//! 「MOFの`Process`イベントに同等フィールドが見当たらない」と書いているが、これは誤りである
//! （§22で訂正）。
//!
//! 入口は[`MofFsSession::start_process_only`]（`EnableFlags`は`PROCESS`のみ）。FileIo系の
//! キーワードを開けないので、§8.4がマニフェストを採った決め手のひとつ「イベント量9倍差」は
//! **この使い方には当たらない**（あの差は`DISK_FILE_IO`のname系が不可避で付いてくることに由来する）。
//!
//! # セッションの張り方
//!
//! `KERNEL_LOGGER_NAME`（"NT Kernel Logger"）は**マシン全体で1本**しか張れず、他のツール
//! （WPR・xperf・EDR）と正面衝突する。そこでWindows 8以降の
//! `EVENT_TRACE_SYSTEM_LOGGER_MODE`（**private system logger**、最大8本）を使い、
//! 任意名のセッションとして張る。harnessが他のツールの計測を壊さないための選択である。

use std::sync::{Arc, Mutex};

use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, OpenTraceW, ProcessTrace, StartTraceW, CONTROLTRACE_HANDLE,
    EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_FLAG, EVENT_TRACE_FLAG_DISK_FILE_IO,
    EVENT_TRACE_FLAG_FILE_IO, EVENT_TRACE_FLAG_FILE_IO_INIT, EVENT_TRACE_FLAG_IMAGE_LOAD,
    EVENT_TRACE_FLAG_PROCESS, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, EVENT_TRACE_SYSTEM_LOGGER_MODE, PROCESSTRACE_HANDLE,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, WNODE_FLAG_TRACED_GUID,
};

use super::parse::{Correlator, Denial, PendingCreate};
use super::tdh;
use crate::win_common::wide;

/// `FileIo` MOFクラスのGUID（`{90CBDC39-4A3E-11D1-84F4-0000F80464E3}`）。
pub const FILE_IO_GUID: GUID = GUID::from_u128(0x90CB_DC39_4A3E_11D1_84F4_0000_F804_64E3);

/// `FileIo_Create`のEventType。**Opcodeとして届く**（マニフェスト側のEvent Idではない）。
pub const EVENT_TYPE_CREATE: u8 = 64;
/// `FileIo_OpEnd`のEventType。
pub const EVENT_TYPE_OP_END: u8 = 76;
/// `FileIo_Name`系（0=Name / 32=FileCreate / 35=FileDelete / 36=FileRundown）。
pub const EVENT_TYPE_NAME: u8 = 0;
pub const EVENT_TYPE_FILE_CREATE: u8 = 32;
pub const EVENT_TYPE_FILE_RUNDOWN: u8 = 36;

/// `Process` MOFクラスのGUID（`{3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C}`）。
/// **`FileIo`とは別のクラス**なので、同じセッションでも`ProviderId`で振り分ける。
pub const PROCESS_GUID: GUID = GUID::from_u128(0x3D6F_A8D0_FE05_11D0_9DDA_00C0_4FD7_BA7C);

/// `Process_V4_TypeGroup1`のEventType（実測: このクラスは`1,2,3,4,39`を覆う）。
/// 1=Start / 2=End / 3=DCStart（セッション開始時に**既存の全プロセス**を列挙するrundown）/
/// 4=DCEnd / 39=Defunct。
pub const EVENT_TYPE_PROCESS_START: u8 = 1;
pub const EVENT_TYPE_PROCESS_DC_START: u8 = 3;

const PENDING_CREATE_CAPACITY: usize = 4096;

/// 捕捉するプロセス生成イベントの上限。DCStartのrundownだけで数百件来るので、
/// 診断であっても無制限にはしない。超えた分は捨てて**件数を数える**（B-09/B-10）。
const PROCESS_CAPTURE_CAPACITY: usize = 20_000;

#[derive(Debug, thiserror::Error)]
pub enum MofEtwError {
    #[error(
        "StartTraceW (system logger) failed: {0:?} (requires administrator rights; \
             EVENT_TRACE_SYSTEM_LOGGER_MODE requires Windows 8 or later)"
    )]
    StartTrace(WIN32_ERROR),
    #[error("OpenTraceW failed: {0:?}")]
    OpenTrace(WIN32_ERROR),
}

/// `Process`クラスのプロセス生成イベント1件。
///
/// **`command_line`が本命**（`plans/PLAN-MAC-RECURSIVE-DESCENDANTS.md`決定14のargv軸）。
/// マニフェスト側の[`super::session::ProcessStartInfo`]には対応するフィールドが**存在しない**
/// ——同じ`None`でも「プロパティを引けなかった」と「フィールドが無い」は別の事実なので、
/// どのバージョンのイベントが届いたか（[`Self::version`]）を必ず一緒に持つ。
#[derive(Debug, Clone)]
pub struct MofProcessStart {
    /// `Opcode`として届くMOFの`EventType`（1=Start / 3=DCStart）。
    pub event_type: u8,
    /// MOFの`EventVersion`（`Process_V4_TypeGroup1`なら4）。`CommandLine`は
    /// **V2以降にしかない**ので、`None`の解釈にはこれが要る。
    pub version: u8,
    pub pid: Option<u32>,
    pub parent_pid: Option<u32>,
    pub session_id: Option<u32>,
    /// クラス定義にある`Flags`。**切り詰めを示すビットがあるかを確かめるために読む**
    /// ——無ければ`CommandLine`の切り詰めは呼び出し側から検出できない（無言）。
    pub flags: Option<u64>,
    pub image_file_name: Option<String>,
    /// **未解決#8の測定対象。**
    pub command_line: Option<String>,
    /// V4以降。AppContainer/パッケージ化プロセスの識別（`RESULTS.md` §8.4の訂正材料）。
    pub package_full_name: Option<String>,
    /// 実体はEPROCESSのポインタ。
    ///
    /// **マニフェスト側の`ProcessSequenceNumber`の代わりにはならない**（実測で確定、
    /// `plans/etw-spike/RESULTS.md` §23.1）。601件の実起動に対して**9種類しか現れず**、
    /// 1つの値が65個のpidに付いた例がある——短命プロセスを連続で起こすと解放された
    /// EPROCESSが再利用されるためである。**同じpid・同じこの値で別インスタンス**という
    /// 実例が観測されており、プロセスの同一性の根拠には使えない。
    ///
    /// （この行は当初「`ProcessSequenceNumber`に相当する役割を持つ」と書いていた。
    /// *相当する*であって*等しい*ではない、という限定詞では足りず、実測では役割自体が
    /// 相当しなかった。）
    pub unique_process_key: Option<u64>,

    // --- 以下は測定M1・M2・M5のために足したもの（`PLAN-MAC-ARGV-MEASUREMENTS.md`）---
    /// イベントヘッダのタイムスタンプ。**マニフェスト側との突合を「pid＋開始時刻の窓」で
    /// 行う場合の窓幅を実測する**ために要る（M1）。MOF側とマニフェスト側は別セッションなので、
    /// 同じプロセスでも配送時刻が一致する保証は無い。
    pub timestamp_unix_ms: u64,
    /// `CommandLine`の**生のUTF-16単位数**。
    ///
    /// **[`Self::command_line`]に`chars().count()`を掛けた値とは別物である**
    /// （サロゲートペアを含む文字列で分かれる）。§22.3.1が確定した上限「1024」が
    /// UTF-16単位なのか文字数なのかは、こちらでしか判定できない（M5）。
    pub command_line_utf16_len: Option<usize>,
    /// `CommandLine`の**末尾8単位まで**（生のUTF-16）。切り詰めがサロゲートペアの途中で
    /// 起きたなら、ここに対にならない高位サロゲート（`0xD800..=0xDBFF`）が残る（M5）。
    /// 全単位を保持しないのは、容量[`PROCESS_CAPTURE_CAPACITY`]件ぶんのメモリを避けるため。
    pub command_line_tail_units: Option<Vec<u16>>,
    /// `Process_V4_TypeGroup1`の`ApplicationId`。**UTF-16とANSIの両方で読む**
    /// ——同じイベントの中で`CommandLine`がUTF-16・`ImageFileName`がANSIという混在が
    /// 実在し（§22.7）、幅を間違えても誰もエラーを返さないため、どちらが正しいかは
    /// 両方を出して人が見るまで決められない（M2）。
    pub application_id_utf16: Option<String>,
    pub application_id_ansi: Option<String>,
}

struct MofSink {
    correlator: Mutex<Correlator>,
    denials: Mutex<Vec<Denial>>,
    /// **`FileIo`クラスのイベント数**。`RESULTS.md` §8.4の比較表（89,850 vs 9,756）が
    /// 引用している値なので、**意味を広げない**——プロセスイベントは
    /// [`MofSink::process_events`]で別に数える。
    seen_events: Mutex<u64>,
    /// `FileIo_Create`で観測した`OpenPath`をそのまま貯める（マニフェスト側の`FileName`と
    /// 比較して、相対openで形が違わないかを見るための材料）。
    observed_paths: Mutex<Vec<String>>,
    /// `FileIo_Name`系（0/32/35/36）で観測した`FileName`。rundownがどれだけ拾えるかの材料。
    name_events: Mutex<Vec<String>>,
    /// `Process`クラスで観測した生成イベント（Start/DCStart）。
    process_starts: Mutex<Vec<MofProcessStart>>,
    /// `Process`クラスのイベント総数（Start/DCStart以外＝End等も含む）。
    /// 「1件も届いていない」と「届いたが生成イベントではなかった」を区別するために数える。
    process_events: Mutex<u64>,
    /// 容量超過で捨てたプロセス生成イベントの数。
    process_dropped: Mutex<u64>,
}

/// MOF（System Logger）セッション。
pub struct MofFsSession {
    session_handle: CONTROLTRACE_HANDLE,
    session_name: Vec<u16>,
    trace_handle: PROCESSTRACE_HANDLE,
    worker: Option<std::thread::JoinHandle<()>>,
    sink: Arc<MofSink>,
}

#[derive(Debug, Clone)]
pub struct MofFsOutcome {
    pub denials: Vec<Denial>,
    /// **`FileIo`クラスのイベント数**（[`MofSink::seen_events`]のdoc参照）。
    pub seen_events: u64,
    pub observed_paths: Vec<String>,
    pub name_events: Vec<String>,
    /// `Process`クラスの生成イベント（Start/DCStart）。
    pub process_starts: Vec<MofProcessStart>,
    /// `Process`クラスのイベント総数。
    pub process_events: u64,
    /// 容量超過で捨てたプロセス生成イベントの数。
    pub process_dropped: u64,
}

impl MofFsSession {
    /// private system logger（`EVENT_TRACE_SYSTEM_LOGGER_MODE`）としてセッションを張る。
    ///
    /// `EnableFlags`には次を立てる:
    /// - `DISK_FILE_IO`: `FileIo_Name`系（FileObject→パス対応）
    /// - `FILE_IO`: 完了時イベント（`OpEnd`を含む）
    /// - `FILE_IO_INIT`: 開始時イベント（`Create`。MOFは既定で「操作の開始時に記録」だが、
    ///   `Create`/`OpEnd`の対を得るには両方立てる）
    /// - `PROCESS` / `IMAGE_LOAD`: プロセス・イメージの文脈（§7の検証用）
    pub fn start(session_name: &str) -> Result<Self, MofEtwError> {
        Self::start_with_flags(
            session_name,
            EVENT_TRACE_FLAG_DISK_FILE_IO
                | EVENT_TRACE_FLAG_FILE_IO
                | EVENT_TRACE_FLAG_FILE_IO_INIT
                | EVENT_TRACE_FLAG_PROCESS
                | EVENT_TRACE_FLAG_IMAGE_LOAD,
        )
    }

    /// **プロセス生成イベントだけ**を購読する（`EnableFlags`は`PROCESS`のみ）。
    ///
    /// FSのキーワードを開けないので、`RESULTS.md` §8.4がマニフェストを採った決め手の
    /// 「イベント量9倍差」（＝`DISK_FILE_IO`のname系が不可避で付いてくること）は
    /// この入口には当たらない。用途は`CommandLine`の観測
    /// （`plans/PLAN-MAC-RECURSIVE-DESCENDANTS.md`決定14・未解決#8）。
    ///
    /// 撤収は[`Self::stop`]／`Drop`——[`Self::start`]とまったく同じ経路を通る。
    pub fn start_process_only(session_name: &str) -> Result<Self, MofEtwError> {
        Self::start_with_flags(session_name, EVENT_TRACE_FLAG_PROCESS)
    }

    fn start_with_flags(
        session_name: &str,
        enable_flags: EVENT_TRACE_FLAG,
    ) -> Result<Self, MofEtwError> {
        let name_w = wide(session_name);
        let (_props, session_handle) = start_system_trace(&name_w, enable_flags)?;

        let sink = Arc::new(MofSink {
            correlator: Mutex::new(Correlator::new(PENDING_CREATE_CAPACITY)),
            denials: Mutex::new(Vec::new()),
            seen_events: Mutex::new(0),
            observed_paths: Mutex::new(Vec::new()),
            name_events: Mutex::new(Vec::new()),
            process_starts: Mutex::new(Vec::new()),
            process_events: Mutex::new(0),
            process_dropped: Mutex::new(0),
        });

        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: windows::core::PWSTR(name_w.as_ptr() as *mut u16),
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(mof_event_callback);
        logfile.Context = Arc::as_ptr(&sink) as *mut core::ffi::c_void;

        let trace_handle = unsafe { OpenTraceW(&mut logfile) };
        if trace_handle.Value == u64::MAX {
            let error = WIN32_ERROR(unsafe { windows::Win32::Foundation::GetLastError().0 });
            stop_system_trace(session_handle, &name_w);
            return Err(MofEtwError::OpenTrace(error));
        }

        let worker_sink = Arc::clone(&sink);
        let worker = std::thread::spawn(move || {
            let _keep_alive = worker_sink;
            let _ = unsafe { ProcessTrace(&[trace_handle], None, None) };
        });

        Ok(Self {
            session_handle,
            session_name: name_w,
            trace_handle,
            worker: Some(worker),
            sink,
        })
    }

    pub fn stop(mut self) -> MofFsOutcome {
        self.shutdown()
    }

    fn shutdown(&mut self) -> MofFsOutcome {
        if self.worker.is_some() {
            stop_system_trace(self.session_handle, &self.session_name);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
            unsafe {
                let _ = CloseTrace(self.trace_handle);
            }
        }
        MofFsOutcome {
            denials: self
                .sink
                .denials
                .lock()
                .map(|d| d.clone())
                .unwrap_or_default(),
            seen_events: self.sink.seen_events.lock().map(|c| *c).unwrap_or(0),
            observed_paths: self
                .sink
                .observed_paths
                .lock()
                .map(|p| p.clone())
                .unwrap_or_default(),
            name_events: self
                .sink
                .name_events
                .lock()
                .map(|p| p.clone())
                .unwrap_or_default(),
            process_starts: self
                .sink
                .process_starts
                .lock()
                .map(|p| p.clone())
                .unwrap_or_default(),
            process_events: self.sink.process_events.lock().map(|c| *c).unwrap_or(0),
            process_dropped: self.sink.process_dropped.lock().map(|c| *c).unwrap_or(0),
        }
    }
}

impl Drop for MofFsSession {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

/// `EVENT_TRACE_PROPERTIES` + セッション名。System Logger用に`Wnode.Guid`と`EnableFlags`を設定する。
fn system_properties_buffer(name_w: &[u16], enable_flags: EVENT_TRACE_FLAG) -> Vec<u8> {
    let struct_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let total = struct_size + std::mem::size_of_val(name_w);
    let mut buf = vec![0u8; total];

    let properties = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    unsafe {
        (*properties).Wnode.BufferSize = total as u32;
        (*properties).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*properties).Wnode.ClientContext = 1; // QPC
                                               // **private system logger**（Win8+）。`KERNEL_LOGGER_NAME`の単一インスタンス制約を
                                               // 避けるため、`SystemTraceControlGuid`は設定せず任意名で張る。
        (*properties).LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
        (*properties).EnableFlags = enable_flags;
        (*properties).LoggerNameOffset = struct_size as u32;
    }
    let name_slot = &mut buf[struct_size..];
    for (i, unit) in name_w.iter().enumerate() {
        let bytes = unit.to_le_bytes();
        name_slot[i * 2] = bytes[0];
        name_slot[i * 2 + 1] = bytes[1];
    }
    buf
}

fn start_system_trace(
    name_w: &[u16],
    enable_flags: EVENT_TRACE_FLAG,
) -> Result<(Vec<u8>, CONTROLTRACE_HANDLE), MofEtwError> {
    for attempt in 0..2 {
        let mut buf = system_properties_buffer(name_w, enable_flags);
        let mut handle = CONTROLTRACE_HANDLE::default();
        let status = unsafe {
            StartTraceW(
                &mut handle,
                PCWSTR(name_w.as_ptr()),
                buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            )
        };
        if status == ERROR_SUCCESS {
            return Ok((buf, handle));
        }
        if status == ERROR_ALREADY_EXISTS && attempt == 0 {
            stop_system_trace(CONTROLTRACE_HANDLE::default(), name_w);
            continue;
        }
        return Err(MofEtwError::StartTrace(status));
    }
    Err(MofEtwError::StartTrace(ERROR_ALREADY_EXISTS))
}

fn stop_system_trace(handle: CONTROLTRACE_HANDLE, name_w: &[u16]) {
    let mut buf = system_properties_buffer(name_w, EVENT_TRACE_FLAG(0));
    unsafe {
        let _ = ControlTraceW(
            handle,
            PCWSTR(name_w.as_ptr()),
            buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

/// Classic（MOF）イベントのコールバック。
///
/// **マニフェスト側と識別方法が違う**: イベントの種類は`EventDescriptor.Id`ではなく
/// `EventDescriptor.Opcode`（＝MOFの`EventType`）に載り、プロバイダはクラスGUID
/// （`EventHeader.ProviderId`）で判別する。
unsafe extern "system" fn mof_event_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let record = &*record;
    let context = record.UserContext as *const MofSink;
    if context.is_null() {
        return;
    }
    let sink = &*context;

    // `Process`クラス（`FileIo`とは別クラス）。**FileIo側の`seen_events`には数えない**
    // ——あの数は`RESULTS.md` §8.4の比較値なので意味を変えない。
    if record.EventHeader.ProviderId == PROCESS_GUID {
        if let Ok(mut count) = sink.process_events.lock() {
            *count = count.saturating_add(1);
        }
        let opcode = record.EventHeader.EventDescriptor.Opcode;
        if opcode != EVENT_TYPE_PROCESS_START && opcode != EVENT_TYPE_PROCESS_DC_START {
            return;
        }
        // 生のUTF-16単位で1回だけ引き、そこから文字列・単位数・末尾を作る（M5）。
        // `property_string`を別途呼ぶとTDHを2回叩くうえ、`from_utf16_lossy`後の値からは
        // 単位数も切り詰めの痕跡も復元できない。
        let command_line_units = tdh::property_utf16_units(record, "CommandLine");
        let info = MofProcessStart {
            event_type: opcode,
            version: record.EventHeader.EventDescriptor.Version,
            pid: tdh::property_u64(record, "ProcessId").map(|v| v as u32),
            parent_pid: tdh::property_u64(record, "ParentId").map(|v| v as u32),
            session_id: tdh::property_u64(record, "SessionId").map(|v| v as u32),
            flags: tdh::property_u64(record, "Flags"),
            // **ANSIで読む。** このクラスは`CommandLine`がUTF-16・`ImageFileName`がANSIという
            // 混在である（実測。[`tdh::property_ansi_string`]のdoc参照）。
            image_file_name: tdh::property_ansi_string(record, "ImageFileName"),
            // **V2以降にしか無い**。無い版が届いたら`None`になるだけで壊れない
            // （`version`と併せて読むこと）。
            command_line: command_line_units
                .as_ref()
                .map(|units| String::from_utf16_lossy(units)),
            // V4以降。
            package_full_name: tdh::property_string(record, "PackageFullName"),
            unique_process_key: tdh::property_u64(record, "UniqueProcessKey"),
            timestamp_unix_ms: filetime_to_unix_ms(record.EventHeader.TimeStamp),
            command_line_utf16_len: command_line_units.as_ref().map(|units| units.len()),
            command_line_tail_units: command_line_units
                .as_ref()
                .map(|units| units[units.len().saturating_sub(8)..].to_vec()),
            application_id_utf16: tdh::property_string(record, "ApplicationId"),
            application_id_ansi: tdh::property_ansi_string(record, "ApplicationId"),
        };
        if let Ok(mut starts) = sink.process_starts.lock() {
            if starts.len() < PROCESS_CAPTURE_CAPACITY {
                starts.push(info);
            } else if let Ok(mut dropped) = sink.process_dropped.lock() {
                *dropped = dropped.saturating_add(1);
            }
        }
        return;
    }

    if record.EventHeader.ProviderId != FILE_IO_GUID {
        return;
    }
    if let Ok(mut count) = sink.seen_events.lock() {
        *count = count.saturating_add(1);
    }

    let opcode = record.EventHeader.EventDescriptor.Opcode;
    let pid = record.EventHeader.ProcessId;
    let timestamp_unix_ms = filetime_to_unix_ms(record.EventHeader.TimeStamp);

    match opcode {
        EVENT_TYPE_CREATE => {
            let Some(irp) = tdh::property_u64(record, "IrpPtr") else {
                return;
            };
            let Some(open_path) = tdh::property_string(record, "OpenPath") else {
                return;
            };
            if let Ok(mut paths) = sink.observed_paths.lock() {
                paths.push(open_path.clone());
            }
            let create_options = tdh::property_u64(record, "CreateOptions").unwrap_or(0) as u32;
            if let Ok(mut correlator) = sink.correlator.lock() {
                correlator.on_create(
                    irp,
                    PendingCreate {
                        file_name: open_path,
                        pid,
                        create_options,
                        timestamp_unix_ms,
                    },
                );
            }
        }
        EVENT_TYPE_OP_END => {
            let Some(irp) = tdh::property_u64(record, "IrpPtr") else {
                return;
            };
            // MOF側のフィールド名は`NtStatus`（マニフェスト側は`Status`）。
            let Some(status) = tdh::property_u64(record, "NtStatus") else {
                return;
            };
            let denial = sink
                .correlator
                .lock()
                .ok()
                .and_then(|mut c| c.on_operation_end(irp, status as u32));
            if let Some(denial) = denial {
                if let Ok(mut denials) = sink.denials.lock() {
                    denials.push(denial);
                }
            }
        }
        EVENT_TYPE_NAME | EVENT_TYPE_FILE_CREATE | EVENT_TYPE_FILE_RUNDOWN | 35 => {
            if let Some(name) = tdh::property_string(record, "FileName") {
                if let Ok(mut names) = sink.name_events.lock() {
                    names.push(name);
                }
            }
        }
        _ => {}
    }
}

fn filetime_to_unix_ms(filetime: i64) -> u64 {
    const EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000;
    let unix_100ns = filetime - EPOCH_DIFF_100NS;
    if unix_100ns <= 0 {
        return 0;
    }
    (unix_100ns / 10_000) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// System Logger用のプロパティバッファは`EnableFlags`と`SYSTEM_LOGGER_MODE`を持つ
    /// （ここがマニフェスト側との構造上の違いそのもの）。
    #[test]
    fn system_logger_properties_carry_enable_flags_and_the_system_logger_mode() {
        let name = wide("harness-mof-spike");
        let flags = EVENT_TRACE_FLAG_DISK_FILE_IO | EVENT_TRACE_FLAG_FILE_IO;
        let buf = system_properties_buffer(&name, flags);

        let properties = buf.as_ptr() as *const EVENT_TRACE_PROPERTIES;
        unsafe {
            assert_eq!((*properties).EnableFlags, flags);
            assert_ne!(
                (*properties).LogFileMode & EVENT_TRACE_SYSTEM_LOGGER_MODE,
                0,
                "must be a private system logger, not the singleton NT Kernel Logger"
            );
            assert_ne!((*properties).LogFileMode & EVENT_TRACE_REAL_TIME_MODE, 0);
            assert_eq!(
                (*properties).LoggerNameOffset as usize,
                std::mem::size_of::<EVENT_TRACE_PROPERTIES>()
            );
        }
    }

    /// MOFのEventType値がMSDNの定義どおりであること（Opcodeとして届く値）。
    #[test]
    fn mof_event_type_values_match_the_documented_definitions() {
        assert_eq!(EVENT_TYPE_CREATE, 64); // FileIo_Create
        assert_eq!(EVENT_TYPE_OP_END, 76); // FileIo_OpEnd
        assert_eq!(EVENT_TYPE_NAME, 0); // FileIo_Name
        assert_eq!(EVENT_TYPE_FILE_CREATE, 32);
        assert_eq!(EVENT_TYPE_FILE_RUNDOWN, 36);
    }

    /// `Process`クラスのGUIDとEventTypeが、このマシンのMOF定義と一致すること
    /// （実測: `Get-CimClass -Namespace root/wmi -ClassName Process_V4` の
    /// `CimClassQualifiers` が `Guid = {3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}`・
    /// `Process_V4_TypeGroup1` が `EventType = 1,2,3,4,39`）。
    ///
    /// GUIDの綴りはコンパイラが検証しないので実行時に検算する（B-05）。ずれていても
    /// コールバックが「1件も来ない」ように見えるだけで、エラーは1つも出ない。
    #[test]
    fn process_class_guid_and_event_types_match_the_mof_definition() {
        assert_eq!(
            format!("{PROCESS_GUID:?}").to_uppercase(),
            "3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C"
        );
        assert_eq!(EVENT_TYPE_PROCESS_START, 1); // Process_Start
        assert_eq!(EVENT_TYPE_PROCESS_DC_START, 3); // Process_DCStart（rundown）
    }

    /// FileIoクラスGUIDが`{90CBDC39-4A3E-11D1-84F4-0000F80464E3}`であること。
    #[test]
    fn file_io_class_guid_matches_the_mof_definition() {
        assert_eq!(
            format!("{FILE_IO_GUID:?}").to_uppercase(),
            "90CBDC39-4A3E-11D1-84F4-0000F80464E3"
        );
    }
}
