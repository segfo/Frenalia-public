//! `Microsoft-Windows-Kernel-File`のリアルタイムETWセッション（**昇格側で動く**、M15.7）。
//!
//! 相関・分類の判断は[`super::parse`]（純粋関数、単体テスト済み）が持ち、ここは
//! **Win32との会話だけ**を担当する（`docs/CODE-STRUCTURE-RULES.md`規則3の「どの外部システムと話すか」）。
//!
//! # 流れ
//!
//! 1. [`StartTraceW`] でリアルタイムセッションを作る（管理者権限が要る）。
//! 2. [`EnableTraceEx2`] で Kernel-File を `CREATE | OP_END` の2キーワードだけ有効にする。
//!    `READ`/`WRITE` まで開けると全ファイルI/Oが流れてきて桁違いの量になるが、拒否の観測に
//!    必要なのは「要求」と「結果」の2つだけなので開けない。
//! 3. [`OpenTraceW`] + [`ProcessTrace`] を専用スレッドで回す（`ProcessTrace`はセッションが
//!    止まるまで返らないブロッキング呼び出し）。
//! 4. 停止は [`ControlTraceW`]`(EVENT_TRACE_CONTROL_STOP)`。これで`ProcessTrace`が返り、
//!    スレッドがjoinできる。
//!
//! # fail-open（D-43）
//!
//! どの段階で失敗しても`Err`を返すだけで、**呼び出し側はharnessを止めない**。収集器は境界では
//! ないので（P-07）、張れないことを理由に可用性を削らない。失敗の事実は呼び出し側が
//! `fs-audit.jsonl`の制御レコードとして残す。

use std::sync::{Arc, Mutex};

use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    CONTROLTRACE_HANDLE, EVENT_CONTROL_CODE_DISABLE_PROVIDER, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID,
};

use super::parse::{
    Correlator, Denial, PendingCreate, EVENT_ID_CREATE, EVENT_ID_OPERATION_END,
    KERNEL_FILE_PROVIDER_GUID,
};
use super::tdh;
use crate::win_common::wide;

/// Kernel-Fileのキーワード。`Create`（要求）と`OperationEnd`（結果）だけを開ける。
const KERNEL_FILE_KEYWORD_OP_END: u64 = 0x40;
const KERNEL_FILE_KEYWORD_CREATE: u64 = 0x80;

/// `FileKey`→`FileName`の対応イベント（Id=10/11）を開けるキーワード。
pub const KERNEL_FILE_KEYWORD_FILENAME: u64 = 0x10;
/// `SetInformation`(17)・`SetDelete`(18)・`Rename`(19)等を開けるキーワード。
pub const KERNEL_FILE_KEYWORD_FILEIO: u64 = 0x20;
/// `Read`(15)を開けるキーワード。
pub const KERNEL_FILE_KEYWORD_READ: u64 = 0x100;
/// `Write`(16)を開けるキーワード。
pub const KERNEL_FILE_KEYWORD_WRITE: u64 = 0x200;

/// 生イベント捕捉の上限。マシン全体のFSアクセスが流れてくる（実測で5.9秒に20万件）ので、
/// **診断であっても無制限にメモリを使わない**。超えた分は捨てて件数だけ数える。
const RAW_CAPTURE_CAPACITY: usize = 400_000;

/// 生イベント1件（**診断専用**）。
///
/// 本番の収集経路は`Create`＋`OperationEnd`しか見ないが、
/// [a-2](../../../../../docs/STATUS.md)（削除・リネームの拒否の取りこぼし）を直すには
/// 「拒否が実際にどのイベント列として現れるか」をまず知る必要がある。
/// **設計を決める前に事実を採るための器**であり、production pathでは捕捉しない。
#[derive(Debug, Clone)]
pub struct RawFsEvent {
    pub event_id: u16,
    pub pid: u32,
    pub irp: Option<u64>,
    pub file_object: Option<u64>,
    pub file_key: Option<u64>,
    /// `SetInformation`系が運ぶ`FILE_INFORMATION_CLASS`。削除は
    /// `FileDispositionInformation`(13)/`FileDispositionInformationEx`(64)、
    /// リネームは`FileRenameInformation`(10)/`FileRenameInformationEx`(65)。
    pub info_class: Option<u64>,
    pub status: Option<u64>,
    /// `Create`(12)とId=10/11だけが運ぶ。それ以外のイベントでパスを知るには
    /// `FileObject`／`FileKey`からの解決が要る——**それが成立するかが実測の主眼**。
    pub file_name: Option<String>,
    pub timestamp_unix_ms: u64,
}

/// 結果待ちにできる`Create`の上限。超えた分は古いものから捨てる（[`Correlator`]）。
const PENDING_CREATE_CAPACITY: usize = 4096;

/// `Microsoft-Windows-Kernel-Process`（`{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`）。
/// **同じセッションへ2つ目のプロバイダとして載せる**（`EnableTraceEx2`をもう1回呼ぶだけ）。
pub const KERNEL_PROCESS_PROVIDER_GUID: GUID =
    GUID::from_u128(0x22FB_2CD6_0E7B_422B_A0C7_2FAD_1FD0_E716);
/// `WINEVENT_KEYWORD_PROCESS`。ProcessStart/ProcessStopだけを開ける
/// （THREAD・IMAGE・JOB等は要らない）。
const KERNEL_PROCESS_KEYWORD_PROCESS: u64 = 0x10;
/// `ProcessStart`のevent id。
const EVENT_ID_PROCESS_START: u16 = 1;

/// `ProcessStart`から取り出す、収集器がスコープ判定に使う情報。
///
/// **`package_full_name`が本命**（v2以降）。これが取れれば、AppContainer子プロセスかどうかを
/// *プロセス開始時点で*判定でき、`OpenProcess`+`TokenAppContainerSid`の事後照会が要らなくなる
/// ——短命なプロセスでも取りこぼさない。`process_sequence_number`（v3以降）はPID再利用に対する
/// 本来の識別子で、`(pid, 生成時刻)`より厳密である。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessStartInfo {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub image_name: Option<String>,
    pub package_full_name: Option<String>,
    pub process_sequence_number: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum EtwError {
    #[error("StartTraceW failed: {0:?} (an ETW real-time session requires administrator rights)")]
    StartTrace(WIN32_ERROR),
    #[error("EnableTraceEx2 failed for Microsoft-Windows-Kernel-File: {0:?}")]
    EnableProvider(WIN32_ERROR),
    #[error("OpenTraceW failed: {0:?}")]
    OpenTrace(WIN32_ERROR),
}

/// コールバックとオーナースレッドが共有する状態。
///
/// `EVENT_RECORD`のコールバックはETWのスレッドから呼ばれるため、相関表と収集結果は
/// `Mutex`で守る。`Arc`の生ポインタを`UserContext`へ載せ、セッションのライフタイムの間だけ
/// 有効であることを`EtwFsSession`の所有関係で保証する。
struct Sink {
    correlator: Mutex<Correlator>,
    denials: Mutex<Vec<Denial>>,
    /// 観測したイベント総数。0のままなら「セッションは張れたがイベントが流れてこなかった」
    /// ことが分かる——「拒否が無かった」との区別に要る（D-43）。
    seen_events: Mutex<u64>,
    /// `Create`で観測した`FileName`（拒否かどうかに関わらず）。MOF側の`OpenPath`と
    /// 突き合わせて、系統間でパスの報告形式が違わないかを実測するための材料
    /// （`plans/etw-spike/RESULTS.md` §6.5）。
    observed_paths: Mutex<Vec<String>>,
    /// `Kernel-Process`の`ProcessStart`（スコープ判定の材料）。
    process_starts: Mutex<Vec<ProcessStartInfo>>,
    /// event id ごとの出現回数（診断用）。「このキーワードで何が流れてくるか」を実測するのに使う
    /// ——`DELETE_PATH`等が**失敗時にも発火するか**は、これを見ないと分からない。
    event_histogram: Mutex<std::collections::BTreeMap<u16, u64>>,
    /// 生イベント列（**診断専用**、[`RawFsEvent`]）。`None`なら捕捉しない。
    /// production pathではここが`None`なので、TDHの追加呼び出しも発生しない。
    raw_events: Option<Mutex<Vec<RawFsEvent>>>,
    /// 容量超過で捨てた生イベントの数。捕捉が途中で切れたことを隠さないために数える。
    raw_dropped: Mutex<u64>,
}

/// 稼働中のETWセッション。[`EtwFsSession::stop`]（またはDrop）で確実に撤収する。
pub struct EtwFsSession {
    session_handle: CONTROLTRACE_HANDLE,
    session_name: Vec<u16>,
    trace_handle: PROCESSTRACE_HANDLE,
    worker: Option<std::thread::JoinHandle<()>>,
    sink: Arc<Sink>,
    /// `Kernel-Process`を同一セッションへ載せられたか。載せられなかった場合は
    /// `PackageFullName`によるスコープ判定が使えないので、呼び出し側は
    /// `OpenProcess`+`TokenAppContainerSid`のフォールバックへ回る。
    kernel_process_enabled: bool,
}

/// 収集の結果。
#[derive(Debug, Clone)]
pub struct EtwFsOutcome {
    pub denials: Vec<Denial>,
    /// 観測したイベント総数（拒否かどうかに関わらず）。
    pub seen_events: u64,
    /// `Create`で観測した`FileName`（系統間比較用）。
    pub observed_paths: Vec<String>,
    /// `Kernel-Process`の`ProcessStart`（スコープ判定の材料）。
    pub process_starts: Vec<ProcessStartInfo>,
    /// ETWが取りこぼしたイベント数。**0でないことは境界の欠落を意味しない**（P-07）が、
    /// 取りこぼした事実は隠さず制御レコードとして残す（D-43は失敗を隠すことではない）。
    pub events_lost: u32,
    pub realtime_buffers_lost: u32,
    /// event id ごとの出現回数（診断用）。
    pub event_histogram: std::collections::BTreeMap<u16, u64>,
    /// 相関表が容量超過で捨てた`Create`の数（`PENDING_CREATE_CAPACITY`の妥当性の実測）。
    pub correlator_evicted: u64,
    /// 相関相手が居なかった`OperationEnd`の数。**大きくても異常ではない**——`OP_END`キーワードは
    /// `Create`以外の操作の完了も報告するため、開始側を購読していない操作の分はここへ落ちる。
    pub correlator_unmatched_operation_ends: u64,
    /// 結果待ちのまま残った`Create`の数（セッション停止時点）。
    pub correlator_pending: usize,
}

impl EtwFsSession {
    /// リアルタイムセッションを開始する。`session_name`はマシン全体で一意な名前
    /// （`harness-policy-learn-<session-token>`）。
    pub fn start(session_name: &str) -> Result<Self, EtwError> {
        Self::start_with_extra_keywords(session_name, 0)
    }

    /// **診断専用**: 追加キーワードを開けたうえで、生イベント列も捕捉する。
    ///
    /// 「拒否が実際にどのイベント列として現れるか」を採るための入口
    /// （`docs/STATUS.md`のa-2）。捕捉は[`RAW_CAPTURE_CAPACITY`]で頭打ちにする。
    pub fn start_with_raw_capture(
        session_name: &str,
        extra_keywords: u64,
    ) -> Result<Self, EtwError> {
        Self::start_inner(session_name, extra_keywords, true)
    }

    /// 捕捉した生イベント列と、容量超過で捨てた件数。
    pub fn raw_events(&self) -> (Vec<RawFsEvent>, u64) {
        let events = self
            .sink
            .raw_events
            .as_ref()
            .and_then(|r| r.lock().ok().map(|e| e.clone()))
            .unwrap_or_default();
        let dropped = self.sink.raw_dropped.lock().map(|d| *d).unwrap_or(0);
        (events, dropped)
    }

    /// 診断用に追加キーワードを開けて張る。**本番経路は[`Self::start`]（`CREATE|OP_END`のみ）**
    /// ——キーワードを広げるとイベント量が跳ね上がるので、既定では開けない。
    /// 「`DELETE_PATH`が失敗時にも発火するか」のような問いを実測するためだけの入口。
    pub fn start_with_extra_keywords(
        session_name: &str,
        extra_keywords: u64,
    ) -> Result<Self, EtwError> {
        Self::start_inner(session_name, extra_keywords, false)
    }

    fn start_inner(
        session_name: &str,
        extra_keywords: u64,
        capture_raw: bool,
    ) -> Result<Self, EtwError> {
        let name_w = wide(session_name);
        let (mut properties_buf, session_handle) = start_trace(&name_w)?;

        let enable = unsafe {
            EnableTraceEx2(
                session_handle,
                &KERNEL_FILE_PROVIDER_GUID as *const GUID,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_INFORMATION as u8,
                KERNEL_FILE_KEYWORD_CREATE | KERNEL_FILE_KEYWORD_OP_END | extra_keywords,
                0,
                0,
                None,
            )
        };
        if enable != ERROR_SUCCESS {
            stop_trace(session_handle, &name_w, &mut properties_buf);
            return Err(EtwError::EnableProvider(enable));
        }

        // 2つ目のプロバイダを**同じセッションへ**載せる。`Kernel-Process`のProcessStartが
        // 運ぶ`PackageFullName`で、AppContainer子かどうかをプロセス開始時点で判定できる
        // （`OpenProcess`の事後照会は短命プロセスで失敗するため、そちらに頼らない）。
        //
        // **失敗しても致命的にしない**。これはスコープ判定の精度を上げるための補助であって、
        // 拒否の収集そのものは`Kernel-File`だけで成立する（D-43 fail-open）。
        let process_enable = unsafe {
            EnableTraceEx2(
                session_handle,
                &KERNEL_PROCESS_PROVIDER_GUID as *const GUID,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_INFORMATION as u8,
                KERNEL_PROCESS_KEYWORD_PROCESS,
                0,
                0,
                None,
            )
        };
        let kernel_process_enabled = process_enable == ERROR_SUCCESS;

        let sink = Arc::new(Sink {
            correlator: Mutex::new(Correlator::new(PENDING_CREATE_CAPACITY)),
            denials: Mutex::new(Vec::new()),
            seen_events: Mutex::new(0),
            observed_paths: Mutex::new(Vec::new()),
            process_starts: Mutex::new(Vec::new()),
            event_histogram: Mutex::new(std::collections::BTreeMap::new()),
            raw_events: capture_raw.then(|| Mutex::new(Vec::new())),
            raw_dropped: Mutex::new(0),
        });

        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR_from(&name_w),
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);
        logfile.Context = Arc::as_ptr(&sink) as *mut core::ffi::c_void;

        let trace_handle = unsafe { OpenTraceW(&mut logfile) };
        if trace_handle.Value == u64::MAX {
            let error = WIN32_ERROR(unsafe { windows::Win32::Foundation::GetLastError().0 });
            stop_trace(session_handle, &name_w, &mut properties_buf);
            return Err(EtwError::OpenTrace(error));
        }

        // `ProcessTrace`はセッションが止まるまで返らないので専用スレッドで回す。
        // `sink`のクローンを渡してコールバックが参照するメモリの生存を保証する。
        let worker_sink = Arc::clone(&sink);
        let worker = std::thread::spawn(move || {
            // `worker_sink`はここで所有され、スレッド終了まで生きる（コールバックが持つ
            // 生ポインタの寿命を、このスレッドの寿命が下から支える）。
            let _keep_alive = worker_sink;
            let _ = unsafe { ProcessTrace(&[trace_handle], None, None) };
        });

        Ok(Self {
            session_handle,
            session_name: name_w,
            trace_handle,
            worker: Some(worker),
            sink,
            kernel_process_enabled,
        })
    }

    /// **未処理分だけ**を取り出す（取り出した分はセッション側から消える）。
    ///
    /// 収集器はこれを定期的に呼んで`fs-audit.jsonl`へ追記する。teardown時に一括で書くと
    /// クラッシュで全損するうえ、セッション実行中に`harness policy suggest`しても何も見えない。
    ///
    /// `process_starts`を**拒否より先に**返すのは、スコープ判定（[`super::scope::ScopeTracker`]）が
    /// 「親が対象なら子も対象」を解決するのに`ProcessStart`を先に食う必要があるため。
    pub fn drain(&self) -> (Vec<ProcessStartInfo>, Vec<Denial>) {
        let starts = self
            .sink
            .process_starts
            .lock()
            .map(|mut p| std::mem::take(&mut *p))
            .unwrap_or_default();
        let denials = self
            .sink
            .denials
            .lock()
            .map(|mut d| std::mem::take(&mut *d))
            .unwrap_or_default();
        (starts, denials)
    }

    /// これまでに観測した拒否を取り出す（セッションは動いたまま）。
    pub fn snapshot(&self) -> EtwFsOutcome {
        EtwFsOutcome {
            denials: self.sink.denials.lock().map(|d| d.clone()).unwrap_or_default(),
            seen_events: self.sink.seen_events.lock().map(|c| *c).unwrap_or(0),
            observed_paths: self
                .sink
                .observed_paths
                .lock()
                .map(|p| p.clone())
                .unwrap_or_default(),
            process_starts: self
                .sink
                .process_starts
                .lock()
                .map(|p| p.clone())
                .unwrap_or_default(),
            events_lost: 0,
            realtime_buffers_lost: 0,
            event_histogram: self
                .sink
                .event_histogram
                .lock()
                .map(|h| h.clone())
                .unwrap_or_default(),
            correlator_evicted: self
                .sink
                .correlator
                .lock()
                .map(|c| c.evicted_count())
                .unwrap_or(0),
            correlator_unmatched_operation_ends: self
                .sink
                .correlator
                .lock()
                .map(|c| c.unmatched_operation_end_count())
                .unwrap_or(0),
            correlator_pending: self
                .sink
                .correlator
                .lock()
                .map(|c| c.pending_len())
                .unwrap_or(0),
        }
    }

    /// セッションを停止し、収集結果を返す。
    pub fn stop(mut self) -> EtwFsOutcome {
        let outcome = self.shutdown();
        // `Drop`で二重停止しないよう、停止済みであることをworkerの不在で表す。
        outcome
    }

    /// `Kernel-Process`を同一セッションへ載せられたか（スコープ判定の可否）。
    pub fn kernel_process_enabled(&self) -> bool {
        self.kernel_process_enabled
    }

    fn shutdown(&mut self) -> EtwFsOutcome {
        let mut lost = (0u32, 0u32);
        if self.worker.is_some() {
            let mut properties_buf = properties_buffer(&self.session_name);
            stop_trace(self.session_handle, &self.session_name, &mut properties_buf);
            // `ControlTraceW(STOP)`はプロパティへセッション統計を書き戻す。
            // 取りこぼしを黙って捨てないための唯一の入手経路。
            unsafe {
                let properties = properties_buf.as_ptr() as *const EVENT_TRACE_PROPERTIES;
                lost = ((*properties).EventsLost, (*properties).RealTimeBuffersLost);
            }
            // `ControlTraceW(STOP)`により`ProcessTrace`が返る。
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
            unsafe {
                let _ = CloseTrace(self.trace_handle);
            }
        }
        EtwFsOutcome {
            denials: self.sink.denials.lock().map(|d| d.clone()).unwrap_or_default(),
            seen_events: self.sink.seen_events.lock().map(|c| *c).unwrap_or(0),
            observed_paths: self
                .sink
                .observed_paths
                .lock()
                .map(|p| p.clone())
                .unwrap_or_default(),
            process_starts: self
                .sink
                .process_starts
                .lock()
                .map(|p| p.clone())
                .unwrap_or_default(),
            events_lost: lost.0,
            realtime_buffers_lost: lost.1,
            event_histogram: self
                .sink
                .event_histogram
                .lock()
                .map(|h| h.clone())
                .unwrap_or_default(),
            correlator_evicted: self
                .sink
                .correlator
                .lock()
                .map(|c| c.evicted_count())
                .unwrap_or(0),
            correlator_unmatched_operation_ends: self
                .sink
                .correlator
                .lock()
                .map(|c| c.unmatched_operation_end_count())
                .unwrap_or(0),
            correlator_pending: self
                .sink
                .correlator
                .lock()
                .map(|c| c.pending_len())
                .unwrap_or(0),
        }
    }
}

impl Drop for EtwFsSession {
    /// `stop`を呼ばずに落ちた場合でもETWセッションを残さない。リアルタイムセッションは
    /// プロセスが死んでもOSに残り続ける（`logman query -ets`に出る）ため、後始末は必須。
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

/// **診断用**: 任意のプロバイダを自前のリアルタイムセッションで有効化できるかだけを試す。
///
/// `Microsoft-Windows-Security-Auditing`のように「OSの`EventLog-Security`セッションだけが
/// 有効化できる」種類のプロバイダがあるため、**採否を論じる前に購読できるかを確かめる**ための入口。
/// セッションは張って即座に畳むので、**マシンの状態は何も変えない**（監査ポリシーにも触れない）。
///
/// 戻り値は`EnableTraceEx2`の生の戻り値（`ERROR_SUCCESS`なら有効化そのものは通った）。
///
/// **注意**: `ERROR_SUCCESS`は「有効化できた」であって「イベントが流れてくる」ではない。
/// 実際に届くかは、そのプロバイダがイベントを生成する条件（4656なら監査ポリシーとSACL）が
/// 揃っているかに依る。
pub fn try_enable_provider(session_name: &str, provider: GUID) -> Result<WIN32_ERROR, EtwError> {
    let name_w = wide(session_name);
    let (mut properties_buf, session_handle) = start_trace(&name_w)?;
    let status = unsafe {
        EnableTraceEx2(
            session_handle,
            &provider as *const GUID,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            TRACE_LEVEL_INFORMATION as u8,
            u64::MAX, // 全キーワード（購読可否だけが問いなので絞らない）
            0,
            0,
            None,
        )
    };
    stop_trace(session_handle, &name_w, &mut properties_buf);
    Ok(status)
}

/// **診断用**: 任意のプロバイダを有効化したうえで、**実際にイベントが届くか**を数える。
///
/// [`try_enable_provider`]は`EnableTraceEx2`の戻り値しか見ないが、ETWの有効化は
/// 「登録は受け付けたが配送はしない」場合でも成功を返しうる。購読可否を決めるには
/// **届いた件数**を見るしかない。
///
/// マシンの状態は変えない（セッションを張って畳むだけ。監査ポリシーには触れない）。
pub fn count_provider_events(
    session_name: &str,
    provider: GUID,
    duration: std::time::Duration,
) -> Result<(WIN32_ERROR, u64), EtwError> {
    let name_w = wide(session_name);
    let (mut properties_buf, session_handle) = start_trace(&name_w)?;
    let enable = unsafe {
        EnableTraceEx2(
            session_handle,
            &provider as *const GUID,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            TRACE_LEVEL_INFORMATION as u8,
            u64::MAX,
            0,
            0,
            None,
        )
    };
    if enable != ERROR_SUCCESS {
        stop_trace(session_handle, &name_w, &mut properties_buf);
        return Ok((enable, 0));
    }

    let counter = Arc::new(Mutex::new(0u64));
    let mut logfile = EVENT_TRACE_LOGFILEW {
        LoggerName: PWSTR_from(&name_w),
        ..Default::default()
    };
    logfile.Anonymous1.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.Anonymous2.EventRecordCallback = Some(counting_callback);
    logfile.Context = Arc::as_ptr(&counter) as *mut core::ffi::c_void;

    let trace_handle = unsafe { OpenTraceW(&mut logfile) };
    if trace_handle.Value == u64::MAX {
        stop_trace(session_handle, &name_w, &mut properties_buf);
        return Ok((enable, 0));
    }
    let worker_counter = Arc::clone(&counter);
    let worker = std::thread::spawn(move || {
        let _keep_alive = worker_counter;
        let _ = unsafe { ProcessTrace(&[trace_handle], None, None) };
    });

    std::thread::sleep(duration);
    stop_trace(session_handle, &name_w, &mut properties_buf);
    let _ = worker.join();
    unsafe {
        let _ = CloseTrace(trace_handle);
    }
    let received = counter.lock().map(|c| *c).unwrap_or(0);
    Ok((enable, received))
}

unsafe extern "system" fn counting_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let context = (*record).UserContext as *const Mutex<u64>;
    if context.is_null() {
        return;
    }
    if let Ok(mut count) = (*context).lock() {
        *count = count.saturating_add(1);
    }
}

#[allow(non_snake_case)]
fn PWSTR_from(name_w: &[u16]) -> windows::core::PWSTR {
    windows::core::PWSTR(name_w.as_ptr() as *mut u16)
}

/// `EVENT_TRACE_PROPERTIES` + セッション名を1つの連続バッファへ確保する
/// （ETWはこの構造体の直後に名前が置かれていることを要求する）。
fn properties_buffer(name_w: &[u16]) -> Vec<u8> {
    let struct_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let name_bytes = std::mem::size_of_val(name_w);
    let total = struct_size + name_bytes;
    let mut buf = vec![0u8; total];

    // SAFETY: `buf`は`EVENT_TRACE_PROPERTIES`より大きく、先頭は十分にアラインされている
    // （`Vec<u8>`のアロケーションは最大アラインメント要件を満たす）。
    let properties = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    unsafe {
        (*properties).Wnode.BufferSize = total as u32;
        (*properties).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*properties).Wnode.ClientContext = 1; // QPC
        (*properties).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*properties).LoggerNameOffset = struct_size as u32;
    }
    // 名前は構造体の直後へ置く。
    let name_slot = &mut buf[struct_size..];
    for (i, unit) in name_w.iter().enumerate() {
        let bytes = unit.to_le_bytes();
        name_slot[i * 2] = bytes[0];
        name_slot[i * 2 + 1] = bytes[1];
    }
    buf
}

/// セッションを開始する。同名の残留セッション（前回の異常終了分）があれば1度だけ止めて再試行する。
fn start_trace(name_w: &[u16]) -> Result<(Vec<u8>, CONTROLTRACE_HANDLE), EtwError> {
    for attempt in 0..2 {
        let mut buf = properties_buffer(name_w);
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
            // 前回のharnessが異常終了して残したセッション。名前で止めてから作り直す。
            let mut stale = properties_buffer(name_w);
            unsafe {
                let _ = ControlTraceW(
                    CONTROLTRACE_HANDLE::default(),
                    PCWSTR(name_w.as_ptr()),
                    stale.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            continue;
        }
        return Err(EtwError::StartTrace(status));
    }
    Err(EtwError::StartTrace(ERROR_ALREADY_EXISTS))
}

fn stop_trace(handle: CONTROLTRACE_HANDLE, name_w: &[u16], buf: &mut [u8]) {
    unsafe {
        // プロバイダを先に無効化してからセッションを止める（止めた後に残ったイベントが
        // コールバックへ流れてくる窓を短くする）。失敗はベストエフォートで無視する。
        let _ = EnableTraceEx2(
            handle,
            &KERNEL_FILE_PROVIDER_GUID as *const GUID,
            EVENT_CONTROL_CODE_DISABLE_PROVIDER.0,
            0,
            0,
            0,
            0,
            None,
        );
        let _ = ControlTraceW(
            handle,
            PCWSTR(name_w.as_ptr()),
            buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

/// ETWスレッドから呼ばれるイベントコールバック。
///
/// **ここでは重い処理をしない**——ETWのバッファはコールバックが返るまで解放されず、
/// 遅れるとイベント落ち（`EventsLost`）になる。相関とVec追記だけに留める。
unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let record = &*record;
    let context = record.UserContext as *const Sink;
    if context.is_null() {
        return;
    }
    let sink = &*context;

    if let Ok(mut count) = sink.seen_events.lock() {
        *count = count.saturating_add(1);
    }

    let event_id = record.EventHeader.EventDescriptor.Id;
    if record.EventHeader.ProviderId == KERNEL_FILE_PROVIDER_GUID {
        if let Ok(mut histogram) = sink.event_histogram.lock() {
            *histogram.entry(event_id).or_insert(0) += 1;
        }
    }
    let pid = record.EventHeader.ProcessId;
    let timestamp_unix_ms = filetime_to_unix_ms(record.EventHeader.TimeStamp);

    if record.EventHeader.ProviderId == KERNEL_PROCESS_PROVIDER_GUID {
        if event_id == EVENT_ID_PROCESS_START {
            let info = ProcessStartInfo {
                pid: tdh::property_u64(record, "ProcessID").unwrap_or(pid as u64) as u32,
                parent_pid: tdh::property_u64(record, "ParentProcessID").map(|v| v as u32),
                image_name: tdh::property_string(record, "ImageName"),
                // v2以降にのみ存在する。無い版では`None`になるだけで壊れない。
                package_full_name: tdh::property_string(record, "PackageFullName"),
                process_sequence_number: tdh::property_u64(record, "ProcessSequenceNumber"),
            };
            if let Ok(mut starts) = sink.process_starts.lock() {
                starts.push(info);
            }
        }
        return;
    }

    // 生イベント捕捉（診断専用）。**本番経路は`raw_events`が`None`なので何もしない**
    // ——TDHの追加呼び出しが走らないことを、この分岐の外へ出さないことで保証する。
    if let Some(raw) = sink.raw_events.as_ref() {
        if let Ok(mut events) = raw.lock() {
            if events.len() < RAW_CAPTURE_CAPACITY {
                events.push(RawFsEvent {
                    event_id,
                    pid,
                    irp: tdh::property_u64(record, "Irp"),
                    file_object: tdh::property_u64(record, "FileObject"),
                    file_key: tdh::property_u64(record, "FileKey"),
                    info_class: tdh::property_u64(record, "InfoClass"),
                    status: tdh::property_u64(record, "Status"),
                    file_name: tdh::property_string(record, "FileName"),
                    timestamp_unix_ms,
                });
            } else if let Ok(mut dropped) = sink.raw_dropped.lock() {
                *dropped = dropped.saturating_add(1);
            }
        }
    }

    match event_id {
        EVENT_ID_CREATE => {
            let Some(irp) = tdh::property_u64(record, "Irp") else {
                return;
            };
            let Some(file_name) = tdh::property_string(record, "FileName") else {
                return;
            };
            if let Ok(mut paths) = sink.observed_paths.lock() {
                paths.push(file_name.clone());
            }
            let create_options = tdh::property_u64(record, "CreateOptions").unwrap_or(0) as u32;
            if let Ok(mut correlator) = sink.correlator.lock() {
                correlator.on_create(
                    irp,
                    PendingCreate {
                        file_name,
                        pid,
                        create_options,
                        timestamp_unix_ms,
                    },
                );
            }
        }
        EVENT_ID_OPERATION_END => {
            let Some(irp) = tdh::property_u64(record, "Irp") else {
                return;
            };
            let Some(status) = tdh::property_u64(record, "Status") else {
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
        _ => {}
    }
}

/// ETWの`TimeStamp`（100ns単位のFILETIME、1601-01-01起点）をUnixミリ秒へ。
fn filetime_to_unix_ms(filetime: i64) -> u64 {
    /// 1601-01-01から1970-01-01までの100ns単位の差。
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

    /// `EVENT_TRACE_PROPERTIES`のバッファは構造体＋名前を連続で持ち、`LoggerNameOffset`が
    /// 名前の先頭を指す（ETWはこのレイアウトを前提にしている）。
    #[test]
    fn properties_buffer_places_the_session_name_right_after_the_struct() {
        let name = wide("harness-policy-learn-test");
        let buf = properties_buffer(&name);

        let struct_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
        assert_eq!(buf.len(), struct_size + name.len() * 2);

        let properties = buf.as_ptr() as *const EVENT_TRACE_PROPERTIES;
        unsafe {
            assert_eq!((*properties).LoggerNameOffset as usize, struct_size);
            assert_eq!((*properties).Wnode.BufferSize as usize, buf.len());
            assert_eq!((*properties).LogFileMode, EVENT_TRACE_REAL_TIME_MODE);
        }

        let name_back: Vec<u16> = buf[struct_size..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(name_back, name);
    }

    /// FILETIME→Unixミリ秒の変換。1970-01-01のFILETIMEは0msになる。
    #[test]
    fn filetime_converts_to_unix_milliseconds() {
        assert_eq!(filetime_to_unix_ms(116_444_736_000_000_000), 0);
        // +1秒
        assert_eq!(filetime_to_unix_ms(116_444_736_000_000_000 + 10_000_000), 1000);
        // 1970年より前（あり得ないが、負のオーバーフローで巨大な値にしない）
        assert_eq!(filetime_to_unix_ms(0), 0);
    }
}
