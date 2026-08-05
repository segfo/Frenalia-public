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

const PENDING_CREATE_CAPACITY: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum MofEtwError {
    #[error("StartTraceW (system logger) failed: {0:?} (requires administrator rights; \
             EVENT_TRACE_SYSTEM_LOGGER_MODE requires Windows 8 or later)")]
    StartTrace(WIN32_ERROR),
    #[error("OpenTraceW failed: {0:?}")]
    OpenTrace(WIN32_ERROR),
}

struct MofSink {
    correlator: Mutex<Correlator>,
    denials: Mutex<Vec<Denial>>,
    seen_events: Mutex<u64>,
    /// `FileIo_Create`で観測した`OpenPath`をそのまま貯める（マニフェスト側の`FileName`と
    /// 比較して、相対openで形が違わないかを見るための材料）。
    observed_paths: Mutex<Vec<String>>,
    /// `FileIo_Name`系（0/32/35/36）で観測した`FileName`。rundownがどれだけ拾えるかの材料。
    name_events: Mutex<Vec<String>>,
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
    pub seen_events: u64,
    pub observed_paths: Vec<String>,
    pub name_events: Vec<String>,
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
        let name_w = wide(session_name);
        let enable_flags = EVENT_TRACE_FLAG_DISK_FILE_IO
            | EVENT_TRACE_FLAG_FILE_IO
            | EVENT_TRACE_FLAG_FILE_IO_INIT
            | EVENT_TRACE_FLAG_PROCESS
            | EVENT_TRACE_FLAG_IMAGE_LOAD;

        let (_props, session_handle) = start_system_trace(&name_w, enable_flags)?;

        let sink = Arc::new(MofSink {
            correlator: Mutex::new(Correlator::new(PENDING_CREATE_CAPACITY)),
            denials: Mutex::new(Vec::new()),
            seen_events: Mutex::new(0),
            observed_paths: Mutex::new(Vec::new()),
            name_events: Mutex::new(Vec::new()),
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
            denials: self.sink.denials.lock().map(|d| d.clone()).unwrap_or_default(),
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
        (*properties).LogFileMode =
            EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
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

    /// FileIoクラスGUIDが`{90CBDC39-4A3E-11D1-84F4-0000F80464E3}`であること。
    #[test]
    fn file_io_class_guid_matches_the_mof_definition() {
        assert_eq!(format!("{FILE_IO_GUID:?}").to_uppercase(), "90CBDC39-4A3E-11D1-84F4-0000F80464E3");
    }
}
