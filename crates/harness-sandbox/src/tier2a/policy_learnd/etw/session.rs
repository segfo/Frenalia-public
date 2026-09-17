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
    AccessRecord, Correlator, Denial, PendingCreate, EVENT_ID_CREATE, EVENT_ID_OPERATION_END,
    KERNEL_FILE_PROVIDER_GUID,
};
use super::tdh;
use crate::win_common::wide;

/// Kernel-Fileのキーワード。`Create`（要求）と`OperationEnd`（結果）だけを開ける。
const KERNEL_FILE_KEYWORD_OP_END: u64 = 0x40;
const KERNEL_FILE_KEYWORD_CREATE: u64 = 0x80;

/// `FileKey`→`FileName`の対応イベント（Id=10/11）を開けるキーワード。
#[cfg(test)]
pub const KERNEL_FILE_KEYWORD_FILENAME: u64 = 0x10;
/// `SetInformation`(17)・`SetDelete`(18)・`Rename`(19)等を開けるキーワード。
#[cfg(test)]
pub const KERNEL_FILE_KEYWORD_FILEIO: u64 = 0x20;
/// `Read`(15)を開けるキーワード。
#[cfg(test)]
pub const KERNEL_FILE_KEYWORD_READ: u64 = 0x100;
/// `Write`(16)を開けるキーワード。
#[cfg(test)]
pub const KERNEL_FILE_KEYWORD_WRITE: u64 = 0x200;

/// 生イベント捕捉の上限。マシン全体のFSアクセスが流れてくる（実測で5.9秒に20万件）ので、
/// **診断であっても無制限にメモリを使わない**。超えた分は捨てて件数だけ数える。
#[cfg(test)]
const RAW_CAPTURE_CAPACITY: usize = 400_000;

/// 生イベント1件（**診断専用**、テストビルドにしか存在しない）。
///
/// 本番の収集経路は`Create`＋`OperationEnd`しか見ない。この器は
/// [a-2](../../../../../docs/STATUS.md)（削除・リネームの拒否の取りこぼし）が本当に
/// あるのかを実測するために足したもので、答えは**無い**だった
/// （`plans/etw-spike/RESULTS.md` §18: ACL起因の拒否は必ず`Create`段に出る）。
/// 結論が出た以上、本番バイナリへ載せる理由は無いので`#[cfg(test)]`で締める
/// ——「本番経路では`raw_events`が`None`だから安全」という**実行時の約束を、
/// コンパイル時の不在へ格上げする**。同じ問いが再燃したときの実測器としては
/// `super::operation_denial_tests`が残る。
#[cfg(test)]
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

/// **診断専用**: 本番セッションへ**3本目のプロバイダとして**載せる指定（測定M3）。
///
/// 問いは「[`EtwFsSession::start_inner`]が張るセッション——`Kernel-File`＋`Kernel-Process`を
/// 既に載せているもの——へ、`Microsoft-Windows-Security-Mitigations`をもう1本載せられるか」
/// である（`plans/PLAN-MAC-ARGV-MEASUREMENTS.md` M3、決定17(3)の常駐構成が変わる）。
///
/// **等価に組んだ別セッション（[`ProviderProbeSession`]）で測らない。** それは
/// `plans/etw-spike/RESULTS.md` §21.4が記録した「測ったのは調査に使った側で、実際に使われる側では
/// なかった」と同じ取り違えになる。ここでは本番の入口そのものへ載せる。
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct ExtraProvider {
    pub provider: GUID,
    pub keywords: u64,
    /// 捕捉時に名前で引く文字列プロパティ。
    pub string_props: Vec<String>,
    /// 同・整数プロパティ。
    pub u64_props: Vec<String>,
}

/// 本番ビルドでの[`ExtraProvider`]は**構築できない型**である。
///
/// `start_inner`の引数の形を両ビルドで揃えるためだけに置いている（値は常に`None`）。
/// 「診断の器を本番へ持ち込まない」を実行時の約束ではなく**型として**表す
/// ——[`RawFsEvent`]が`#[cfg(test)]`で同じことをしているのと同じ姿勢である。
#[cfg(not(test))]
pub enum ExtraProvider {}

/// [`ExtraProvider`]の捕捉先（[`Sink`]が持つ）。
#[cfg(test)]
struct ExtraCapture {
    provider: GUID,
    string_props: Vec<String>,
    u64_props: Vec<String>,
    events: Mutex<Vec<ProbedEvent>>,
}

/// 結果待ちにできる`Create`の上限。超えた分は古いものから捨てる（[`Correlator`]）。
const PENDING_CREATE_CAPACITY: usize = 4096;

/// `Microsoft-Windows-Kernel-Process`（`{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`）。
/// **同じセッションへ2つ目のプロバイダとして載せる**（`EnableTraceEx2`をもう1回呼ぶだけ）。
pub const KERNEL_PROCESS_PROVIDER_GUID: GUID =
    GUID::from_u128(0x22FB_2CD6_0E7B_422B_A0C7_2FAD_1FD0_E716);
/// `WINEVENT_KEYWORD_PROCESS`。ProcessStart/ProcessStopだけを開ける
/// （THREAD・IMAGE・JOB等は要らない）。
pub const KERNEL_PROCESS_KEYWORD_PROCESS: u64 = 0x10;
/// `ProcessStart`のevent id。
pub const EVENT_ID_PROCESS_START: u16 = 1;

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
    /// record-allモード（ポリシー定義モードのTier1パス）専用。`record_all=false`のときは
    /// 常に空のまま——deny-onlyモードは従来通り`denials`だけを使う（B-06: 呼び出し元は
    /// `start`/`start_record_all`のどちらかで固定され、両方へ同時に書くことはない）。
    records: Mutex<Vec<AccessRecord>>,
    /// `true`なら`EVENT_ID_OPERATION_END`受信時に`on_operation_end_any`（拒否・成功を問わず
    /// 記録）を使う。`false`（既定）なら従来通り`on_operation_end`（拒否のみ）。
    record_all: bool,
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
    /// **本番ビルドにはこのフィールド自体が存在しない**（`#[cfg(test)]`）。
    #[cfg(test)]
    raw_events: Option<Mutex<Vec<RawFsEvent>>>,
    /// 容量超過で捨てた生イベントの数。捕捉が途中で切れたことを隠さないために数える。
    #[cfg(test)]
    raw_dropped: Mutex<u64>,
    /// **プロバイダ×event idごと**の出現回数（測定M3、診断専用）。
    ///
    /// 既存の[`Sink::event_histogram`]は`Kernel-File`専用なので**意味を広げない**
    /// ——3本目を載せたときに「どのプロバイダが実際に届いているか」は別に数える。
    /// `EnableTraceEx2`が`ERROR_SUCCESS`でも配送が無いことがあるため、
    /// 戻り値だけでは相乗りの可否を判定できない（`count_provider_events`のdocと同じ理由）。
    #[cfg(test)]
    provider_histogram: Mutex<std::collections::BTreeMap<(u128, u16), u64>>,
    /// 3本目のプロバイダの捕捉先（[`ExtraProvider`]を指定したときだけ`Some`）。
    #[cfg(test)]
    extra: Option<ExtraCapture>,
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
    /// 3本目のプロバイダ（[`ExtraProvider`]）に対する`EnableTraceEx2`の**生の戻り値**（測定M3）。
    /// 指定しなかった場合は`ERROR_SUCCESS`のまま。**失敗しても`Err`にしない**
    /// ——「載らなかった」こと自体が測定結果なので、そこで落とすと何も分からなくなる。
    #[cfg(test)]
    extra_provider_status: WIN32_ERROR,
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
    /// プロバイダ×event idごとの出現回数（測定M3、診断専用。[`Sink::provider_histogram`]）。
    #[cfg(test)]
    pub provider_histogram: std::collections::BTreeMap<(u128, u16), u64>,
    /// 3本目のプロバイダで捕捉したイベント（測定M3、診断専用）。
    #[cfg(test)]
    pub extra_events: Vec<ProbedEvent>,
}

impl EtwFsSession {
    /// リアルタイムセッションを開始する。`session_name`はマシン全体で一意な名前
    /// （`harness-policy-learn-<session-token>`）。
    pub fn start(session_name: &str) -> Result<Self, EtwError> {
        Self::start_with_extra_keywords(session_name, 0)
    }

    /// **診断専用**（測定M3）: 本番と同じセッションへ**3本目のプロバイダ**を載せて張る。
    ///
    /// 通る経路は[`Self::start`]と同一で、違うのは`EnableTraceEx2`がもう1回呼ばれることだけ
    /// である。3本目の有効化に失敗しても`Err`にはせず、戻り値を
    /// [`Self::extra_provider_status`]で公開する（[`ExtraProvider`]のdoc参照）。
    #[cfg(test)]
    pub fn start_with_extra_provider(
        session_name: &str,
        extra: ExtraProvider,
    ) -> Result<Self, EtwError> {
        Self::start_inner(session_name, 0, false, false, Some(extra))
    }

    /// 3本目のプロバイダに対する`EnableTraceEx2`の生の戻り値（測定M3）。
    #[cfg(test)]
    pub fn extra_provider_status(&self) -> WIN32_ERROR {
        self.extra_provider_status
    }

    /// ポリシー定義モード（Tier1、`record_all`）向け: 拒否だけでなく成功も含めて
    /// 全アクセスを記録する。読み出しは[`Self::drain_records`]/[`Self::snapshot_records`]を使う
    /// ——[`Self::drain`]/[`Self::snapshot`]（deny-onlyモード用）は常に空を返す
    /// （`Sink.denials`へは書かないため）。
    pub fn start_record_all(session_name: &str) -> Result<Self, EtwError> {
        Self::start_inner(session_name, 0, false, true, None)
    }

    /// **診断専用**: 追加キーワードを開けたうえで、生イベント列も捕捉する。
    ///
    /// 「拒否が実際にどのイベント列として現れるか」を採るための入口
    /// （`docs/STATUS.md`のa-2、結論は`plans/etw-spike/RESULTS.md` §18）。
    /// 捕捉は[`RAW_CAPTURE_CAPACITY`]で頭打ちにする。
    #[cfg(test)]
    pub fn start_with_raw_capture(
        session_name: &str,
        extra_keywords: u64,
    ) -> Result<Self, EtwError> {
        Self::start_inner(session_name, extra_keywords, true, false, None)
    }

    /// 捕捉した生イベント列と、容量超過で捨てた件数。
    #[cfg(test)]
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
        Self::start_inner(session_name, extra_keywords, false, false, None)
    }

    fn start_inner(
        session_name: &str,
        extra_keywords: u64,
        capture_raw: bool,
        record_all: bool,
        extra: Option<ExtraProvider>,
    ) -> Result<Self, EtwError> {
        // 生イベント捕捉はテストビルドにしか存在しない（[`RawFsEvent`]のdoc参照）ので、
        // 本番ビルドではこの引数に行き先が無い。関数全体を`allow(unused_variables)`で
        // 黙らせると将来の別の未使用まで巻き込むため、ここだけを潰す。
        #[cfg(not(test))]
        let _ = capture_raw;
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

        // 3本目のプロバイダ（測定M3）。**同じ`session_handle`へ`EnableTraceEx2`をもう1回**
        // 呼ぶだけで、セッションは増えない——それが「相乗りできるか」の問いの実体である。
        // 失敗しても`Err`にしない（[`ExtraProvider`]のdoc）。
        #[cfg(test)]
        let extra_provider_status = match extra.as_ref() {
            Some(extra) => unsafe {
                EnableTraceEx2(
                    session_handle,
                    &extra.provider as *const GUID,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                    TRACE_LEVEL_INFORMATION as u8,
                    extra.keywords,
                    0,
                    0,
                    None,
                )
            },
            None => ERROR_SUCCESS,
        };
        #[cfg(not(test))]
        let _ = extra;

        let sink = Arc::new(Sink {
            correlator: Mutex::new(Correlator::new(PENDING_CREATE_CAPACITY)),
            denials: Mutex::new(Vec::new()),
            records: Mutex::new(Vec::new()),
            record_all,
            seen_events: Mutex::new(0),
            observed_paths: Mutex::new(Vec::new()),
            process_starts: Mutex::new(Vec::new()),
            event_histogram: Mutex::new(std::collections::BTreeMap::new()),
            #[cfg(test)]
            raw_events: capture_raw.then(|| Mutex::new(Vec::new())),
            #[cfg(test)]
            raw_dropped: Mutex::new(0),
            #[cfg(test)]
            provider_histogram: Mutex::new(std::collections::BTreeMap::new()),
            #[cfg(test)]
            extra: extra.map(|extra| ExtraCapture {
                provider: extra.provider,
                string_props: extra.string_props,
                u64_props: extra.u64_props,
                events: Mutex::new(Vec::new()),
            }),
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
            #[cfg(test)]
            extra_provider_status,
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

    /// [`Self::drain`]のrecord-all版。`Self::start_record_all`で開始したセッションで使う
    /// ——deny-onlyセッション（`Self::start`）で呼んでも常に空を返す（`Sink.records`へは
    /// 書かれないため）。
    pub fn drain_records(&self) -> (Vec<ProcessStartInfo>, Vec<AccessRecord>) {
        let starts = self
            .sink
            .process_starts
            .lock()
            .map(|mut p| std::mem::take(&mut *p))
            .unwrap_or_default();
        let records = self
            .sink
            .records
            .lock()
            .map(|mut r| std::mem::take(&mut *r))
            .unwrap_or_default();
        (starts, records)
    }

    /// これまでに観測した拒否を取り出す（セッションは動いたまま）。
    pub fn snapshot(&self) -> EtwFsOutcome {
        EtwFsOutcome {
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
            #[cfg(test)]
            provider_histogram: self.provider_histogram_snapshot(),
            #[cfg(test)]
            extra_events: self.extra_events_snapshot(),
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

    /// プロバイダ×event idごとの出現回数（測定M3）。
    #[cfg(test)]
    fn provider_histogram_snapshot(&self) -> std::collections::BTreeMap<(u128, u16), u64> {
        self.sink
            .provider_histogram
            .lock()
            .map(|h| h.clone())
            .unwrap_or_default()
    }

    /// 3本目のプロバイダで捕捉したイベント（測定M3）。
    #[cfg(test)]
    fn extra_events_snapshot(&self) -> Vec<ProbedEvent> {
        self.sink
            .extra
            .as_ref()
            .and_then(|extra| extra.events.lock().ok().map(|e| e.clone()))
            .unwrap_or_default()
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
            #[cfg(test)]
            provider_histogram: self.provider_histogram_snapshot(),
            #[cfg(test)]
            extra_events: self.extra_events_snapshot(),
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

// ---------------------------------------------------------------------------
// 診断: 任意のプロバイダのイベント本体を名前で引く（`try_enable_provider`・
// `count_provider_events`と同じ「採否を論じる前に測る」ための入口）
// ---------------------------------------------------------------------------

/// [`ProviderProbeSession`]が捕捉したイベント1件。
///
/// **`version`を必ず持つ**——マニフェストのイベントはバージョンでフィールドが増減するので、
/// プロパティが`None`のとき「フィールドが無い版だった」と「あるが空だった」を
/// 呼び出し側が区別できないと、測定として成立しない。
#[derive(Debug, Clone)]
pub struct ProbedEvent {
    pub event_id: u16,
    pub version: u8,
    pub process_id: u32,
    pub timestamp_unix_ms: u64,
    /// 要求した文字列プロパティのうち、引けたもの。
    pub strings: std::collections::BTreeMap<String, String>,
    /// 要求した整数プロパティのうち、引けたもの。
    pub numbers: std::collections::BTreeMap<String, u64>,
}

/// 捕捉の上限。診断でも無制限にメモリを使わない（超過分は数えるだけ）。
const PROBE_CAPTURE_CAPACITY: usize = 50_000;

struct ProbeSink {
    string_props: Vec<String>,
    u64_props: Vec<String>,
    /// 捕捉対象のevent id。空なら全部。
    event_ids: Vec<u16>,
    events: Mutex<Vec<ProbedEvent>>,
    seen: Mutex<u64>,
    dropped: Mutex<u64>,
}

/// **診断専用**: 任意のマニフェストプロバイダを購読し、**イベント本体を名前で引いて**貯める。
///
/// [`count_provider_events`]は件数しか返さないので「届いた」までしか言えない。
/// 「**どのフィールドが埋まるか**」を測るにはこちらが要る（例:
/// `Microsoft-Windows-Security-Mitigations`の子プロセス生成拒否が、呼び出し元と子の
/// コマンドラインを運ぶか——`plans/mac-spike/RESULTS.md`・[§20項目1](../../../../../plans/DESIGN-MAC-POC.md)の2）。
///
/// マシンの状態は変えない（セッションを張って畳むだけ）。撤収は[`Self::stop`]／`Drop`。
pub struct ProviderProbeSession {
    session_handle: CONTROLTRACE_HANDLE,
    session_name: Vec<u16>,
    provider: GUID,
    trace_handle: PROCESSTRACE_HANDLE,
    worker: Option<std::thread::JoinHandle<()>>,
    sink: Arc<ProbeSink>,
}

/// [`ProviderProbeSession::stop`]の結果。
#[derive(Debug, Clone)]
pub struct ProviderProbeOutcome {
    pub events: Vec<ProbedEvent>,
    /// このセッションへ届いたイベント総数（`event_ids`で絞る前）。
    /// **0なら「拒否が無かった」ではなく「配送が無かった」**——この区別に要る。
    pub seen_events: u64,
    /// 容量超過で捨てた件数。
    pub dropped: u64,
    pub events_lost: u32,
    pub realtime_buffers_lost: u32,
}

impl ProviderProbeSession {
    /// `provider`を`keywords`（`u64::MAX`で全部）で有効化し、`event_ids`が空でなければ
    /// そのidのイベントだけを捕捉する。プロパティは名前で指定する。
    pub fn start(
        session_name: &str,
        provider: GUID,
        keywords: u64,
        event_ids: &[u16],
        string_props: &[&str],
        u64_props: &[&str],
    ) -> Result<Self, EtwError> {
        let name_w = wide(session_name);
        let (mut properties_buf, session_handle) = start_trace(&name_w)?;

        let enable = unsafe {
            EnableTraceEx2(
                session_handle,
                &provider as *const GUID,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_INFORMATION as u8,
                keywords,
                0,
                0,
                None,
            )
        };
        if enable != ERROR_SUCCESS {
            stop_trace_for(session_handle, &name_w, &mut properties_buf, provider);
            return Err(EtwError::EnableProvider(enable));
        }

        let sink = Arc::new(ProbeSink {
            string_props: string_props.iter().map(|s| s.to_string()).collect(),
            u64_props: u64_props.iter().map(|s| s.to_string()).collect(),
            event_ids: event_ids.to_vec(),
            events: Mutex::new(Vec::new()),
            seen: Mutex::new(0),
            dropped: Mutex::new(0),
        });

        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR_from(&name_w),
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(probe_callback);
        logfile.Context = Arc::as_ptr(&sink) as *mut core::ffi::c_void;

        let trace_handle = unsafe { OpenTraceW(&mut logfile) };
        if trace_handle.Value == u64::MAX {
            let error = WIN32_ERROR(unsafe { windows::Win32::Foundation::GetLastError().0 });
            stop_trace_for(session_handle, &name_w, &mut properties_buf, provider);
            return Err(EtwError::OpenTrace(error));
        }

        let worker_sink = Arc::clone(&sink);
        let worker = std::thread::spawn(move || {
            let _keep_alive = worker_sink;
            let _ = unsafe { ProcessTrace(&[trace_handle], None, None) };
        });

        Ok(Self {
            session_handle,
            session_name: name_w,
            provider,
            trace_handle,
            worker: Some(worker),
            sink,
        })
    }

    pub fn stop(mut self) -> ProviderProbeOutcome {
        self.shutdown()
    }

    fn shutdown(&mut self) -> ProviderProbeOutcome {
        let mut lost = (0u32, 0u32);
        if self.worker.is_some() {
            let mut properties_buf = properties_buffer(&self.session_name);
            stop_trace_for(
                self.session_handle,
                &self.session_name,
                &mut properties_buf,
                self.provider,
            );
            unsafe {
                let properties = properties_buf.as_ptr() as *const EVENT_TRACE_PROPERTIES;
                lost = ((*properties).EventsLost, (*properties).RealTimeBuffersLost);
            }
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
            unsafe {
                let _ = CloseTrace(self.trace_handle);
            }
        }
        ProviderProbeOutcome {
            events: self
                .sink
                .events
                .lock()
                .map(|e| e.clone())
                .unwrap_or_default(),
            seen_events: self.sink.seen.lock().map(|c| *c).unwrap_or(0),
            dropped: self.sink.dropped.lock().map(|c| *c).unwrap_or(0),
            events_lost: lost.0,
            realtime_buffers_lost: lost.1,
        }
    }
}

impl Drop for ProviderProbeSession {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

unsafe extern "system" fn probe_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let record = &*record;
    let context = record.UserContext as *const ProbeSink;
    if context.is_null() {
        return;
    }
    let sink = &*context;

    if let Ok(mut seen) = sink.seen.lock() {
        *seen = seen.saturating_add(1);
    }

    let event_id = record.EventHeader.EventDescriptor.Id;
    if !sink.event_ids.is_empty() && !sink.event_ids.contains(&event_id) {
        return;
    }

    let mut strings = std::collections::BTreeMap::new();
    for name in &sink.string_props {
        if let Some(value) = tdh::property_string(record, name) {
            strings.insert(name.clone(), value);
        }
    }
    let mut numbers = std::collections::BTreeMap::new();
    for name in &sink.u64_props {
        if let Some(value) = tdh::property_u64(record, name) {
            numbers.insert(name.clone(), value);
        }
    }

    if let Ok(mut events) = sink.events.lock() {
        if events.len() < PROBE_CAPTURE_CAPACITY {
            events.push(ProbedEvent {
                event_id,
                version: record.EventHeader.EventDescriptor.Version,
                process_id: record.EventHeader.ProcessId,
                timestamp_unix_ms: filetime_to_unix_ms(record.EventHeader.TimeStamp),
                strings,
                numbers,
            });
        } else if let Ok(mut dropped) = sink.dropped.lock() {
            *dropped = dropped.saturating_add(1);
        }
    }
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

/// ポリシー学習の収集器が張るETWセッション名の接頭辞。
///
/// **綴りの正本はここ1つ**（`B-13`）。張る側（`policy_learnd::server`）と、
/// 所有者の死んだものを回収する側（[`stop_orphaned_fs_sessions`]）が同じ綴りを見る。
pub const FS_SESSION_PREFIX: &str = "harness-policy-learn-";

/// argv観測（段階6d、`super::mof::MofFsSession`）が張るセッション名の接頭辞。
///
/// **FS側と別の接頭辞にしてあるのは、両方が同時に張られるからである**——1つの記録が
/// マニフェストの通常セッション（FS）とprivate system logger（プロセス生成）の2本を使う
/// （`plans/etw-spike/RESULTS.md` §22.5）。同じ名前は付けられない。
///
/// **こちらの残留はFS側より重い。** FS側の残留は「購読者が居ないのに発火し続ける」無駄だが、
/// こちらは**マシン全体で8本しかない枠を1本占有したまま返さない**（実測の空きは5本）。
/// 積もると次の記録が始められなくなる——argv観測はfail-closedだからである（§10.3）。
pub const ARGV_SESSION_PREFIX: &str = "harness-policy-learn-argv-";

/// ETWセッション名から、その**所有者のセッショントークン**を取り出す
/// （[BUG-117](../../../../../docs/bugs/BUG-117.md)）。回収の対象にできないものは`None`。
///
/// 収集器が張る名前は`harness-policy-learn-harness.shell.sandbox.<token>`と、
/// argv観測の`harness-policy-learn-argv-harness.shell.sandbox.<token>`である。
/// 接頭辞のあとがharnessのセッションプロファイル名になっていなければ`None`を返す——
/// **スパイクやテストが張る`harness-policy-learn-<任意>`は所有者を判定できない**ので、
/// 回収の対象にしない（判定できないものを止めない、fail-closed）。
///
/// # 剥がす順序が効く（段階6dで足した）
///
/// `ARGV_SESSION_PREFIX`は`FS_SESSION_PREFIX`で**前方一致する**（後者が前者の接頭辞）。
/// FS側から先に剥がすと、argvのセッション名は残りが`argv-harness.shell.sandbox.<token>`に
/// なってプロファイル名として通らず、**「所有者を判定できない」＝回収しない側へ落ちる**。
/// **長い方から試す**こと。この順序は[`super::session_tests`]の対のテストが固定している。
pub fn orphan_candidate_token(session_name: &str) -> Option<&str> {
    let profile = session_name
        .strip_prefix(ARGV_SESSION_PREFIX)
        .or_else(|| session_name.strip_prefix(FS_SESSION_PREFIX))?;
    if !crate::tier2a::session_profile::is_session_profile_name(profile) {
        return None;
    }
    crate::tier2a::session_profile::token_of_profile(profile)
}

/// このセッション名を**止めてよいか**（所有者が死んでいるか）。
///
/// 生存判定は引数で受け取る——**実装は`session_profile::token_owner_is_live`ただ1つ**で、
/// ここで受けるのは単体テストのためである（名前付きmutexは実プロセスが要る）。
pub fn is_orphaned_session(session_name: &str, owner_is_live: impl Fn(&str) -> bool) -> bool {
    match orphan_candidate_token(session_name) {
        Some(token) => !owner_is_live(token),
        None => false,
    }
}

/// 所有者の死んだ`harness-policy-learn-*`セッションをOSから止める
/// （[BUG-117](../../../../../docs/bugs/BUG-117.md) 案A）。戻り値は止めた件数。
///
/// # なぜ起動側でやるのか
///
/// **撤収の経路が`stop()`と`Drop`しかなく、どちらもプロセスの生存が前提だからである。**
/// `TerminateProcess`・`panic = "abort"`・電源断のいずれでも`Drop`は走らず、
/// リアルタイムセッションはOSに登録されたまま残る（`logman query -ets`に出る）。
/// 残っている間、`Microsoft-Windows-Kernel-File`は購読者不在のまま有効で、
/// **マシン全体のファイル操作に対して発火し続ける。**
///
/// 起動側には`ERROR_ALREADY_EXISTS`で名前を止め直す分岐が元からあったが、
/// **セッション名は起動のたびに変わる**（`{pid}-{unix_secs}`）ので、
/// 残留セッションの名前と一致することは無い——効くのは同一プロセス内だけだった。
/// だから**名前で引くのをやめて、接頭辞で列挙する。**
///
/// # 何を止めないか（**同じ場所で言う**）
///
/// - **所有者を判定できない名前は止めない。** スパイクとテストは
///   `harness-policy-learn-<任意>`を張るので、接頭辞だけで判断すると
///   並行して走っている測定を殺す（[`orphan_candidate_token`]）。
/// - **所有者が生きているセッションは止めない。** 判定は名前付きmutexで、
///   [`crate::tier2a::session_profile::token_owner_is_live`]が唯一の実装を持つ。
/// - 列挙・停止に失敗しても**何も言わずに0を返さない**——呼び出し側がログへ出せるよう
///   件数だけを返し、個々の失敗は握り潰す（収集器は境界ではないのでfail-open、P-07/D-43）。
///
/// **管理者権限が要る**（収集器は昇格側で動くので満たしている）。
#[cfg(windows)]
pub fn stop_orphaned_fs_sessions() -> usize {
    use windows::Win32::System::Diagnostics::Etw::QueryAllTracesW;

    // ETWのセッション数はマシン全体で64〜256程度（`logman query -ets`の実測で数十）。
    // 足りなければ`ERROR_MORE_DATA`が返るので、そのときも取れたぶんは処理する。
    const MAX_SESSIONS: usize = 256;
    const NAME_CHARS: usize = 512;

    let struct_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let entry_size = struct_size + NAME_CHARS * 2 * 2;
    let mut storage: Vec<Vec<u8>> = (0..MAX_SESSIONS).map(|_| vec![0u8; entry_size]).collect();
    let mut ptrs: Vec<*mut EVENT_TRACE_PROPERTIES> = Vec::with_capacity(MAX_SESSIONS);
    for buf in storage.iter_mut() {
        let p = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        // SAFETY: `buf`は`EVENT_TRACE_PROPERTIES`＋2つの名前領域ぶん確保済みで、
        // `Vec<u8>`のアロケーションは最大アラインメント要件を満たす。
        unsafe {
            (*p).Wnode.BufferSize = entry_size as u32;
            (*p).LoggerNameOffset = struct_size as u32;
            (*p).LogFileNameOffset = (struct_size + NAME_CHARS * 2) as u32;
        }
        ptrs.push(p);
    }

    let mut count: u32 = 0;
    // SAFETY: `ptrs`の各要素は`storage`が生きている間有効で、各バッファは
    // `BufferSize`ぶん確保済み。
    let status = unsafe { QueryAllTracesW(&mut ptrs, &mut count) };
    // `ERROR_MORE_DATA`は「配列が足りなかった」で、取れたぶんは有効である。
    if status != ERROR_SUCCESS && status.0 != 234 {
        return 0;
    }

    let mut stopped = 0usize;
    for p in ptrs.iter().take(count as usize) {
        // SAFETY: `QueryAllTracesW`が埋めた領域を読むだけ。名前は`LoggerNameOffset`から
        // NUL終端のUTF-16で入る。
        let name = unsafe {
            let base = *p as *const u8;
            let offset = (**p).LoggerNameOffset as usize;
            if offset == 0 || offset + 2 > entry_size {
                continue;
            }
            let wide_ptr = base.add(offset) as *const u16;
            let mut len = 0usize;
            while len < NAME_CHARS && *wide_ptr.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(wide_ptr, len))
        };
        if !is_orphaned_session(&name, crate::tier2a::session_profile::token_owner_is_live) {
            continue;
        }
        let name_w = wide(&name);
        let mut buf = properties_buffer(&name_w);
        // SAFETY: `buf`は`properties_buffer`が組んだ正しい形で、名前はNUL終端。
        let rc = unsafe {
            ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                PCWSTR(name_w.as_ptr()),
                buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        if rc == ERROR_SUCCESS {
            stopped += 1;
        }
    }
    stopped
}

#[cfg(not(windows))]
pub fn stop_orphaned_fs_sessions() -> usize {
    0
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
    stop_trace_for(handle, name_w, buf, KERNEL_FILE_PROVIDER_GUID);
}

/// [`stop_trace`]の一般形（無効化するプロバイダを選べる）。**本番経路の挙動は変わらない**
/// ——`stop_trace`は`KERNEL_FILE_PROVIDER_GUID`を渡して委譲するだけである。
fn stop_trace_for(handle: CONTROLTRACE_HANDLE, name_w: &[u16], buf: &mut [u8], provider: GUID) {
    unsafe {
        // プロバイダを先に無効化してからセッションを止める（止めた後に残ったイベントが
        // コールバックへ流れてくる窓を短くする）。失敗はベストエフォートで無視する。
        let _ = EnableTraceEx2(
            handle,
            &provider as *const GUID,
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

    // 測定M3（診断専用）: **どのプロバイダが実際に届いているか**を数える。
    // `EnableTraceEx2`の戻り値だけでは相乗りの可否を判定できない（`count_provider_events`のdoc）。
    #[cfg(test)]
    if let Ok(mut histogram) = sink.provider_histogram.lock() {
        *histogram
            .entry((
                record.EventHeader.ProviderId.to_u128(),
                record.EventHeader.EventDescriptor.Id,
            ))
            .or_insert(0) += 1;
    }

    // 3本目のプロバイダのイベントは、以降のKernel-File向けの処理へ流さずここで畳む
    // （event idの意味がプロバイダごとに違うため、混ぜると別イベントを`Create`として扱いうる）。
    #[cfg(test)]
    if let Some(extra) = sink.extra.as_ref() {
        if record.EventHeader.ProviderId == extra.provider {
            let mut strings = std::collections::BTreeMap::new();
            for name in &extra.string_props {
                if let Some(value) = tdh::property_string(record, name) {
                    strings.insert(name.clone(), value);
                }
            }
            let mut numbers = std::collections::BTreeMap::new();
            for name in &extra.u64_props {
                if let Some(value) = tdh::property_u64(record, name) {
                    numbers.insert(name.clone(), value);
                }
            }
            if let Ok(mut events) = extra.events.lock() {
                if events.len() < PROBE_CAPTURE_CAPACITY {
                    events.push(ProbedEvent {
                        event_id: record.EventHeader.EventDescriptor.Id,
                        version: record.EventHeader.EventDescriptor.Version,
                        process_id: record.EventHeader.ProcessId,
                        timestamp_unix_ms: filetime_to_unix_ms(record.EventHeader.TimeStamp),
                        strings,
                        numbers,
                    });
                }
            }
            return;
        }
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

    // 生イベント捕捉（診断専用）。**この分岐は本番ビルドに存在しない**（`#[cfg(test)]`）
    // ——TDHの追加呼び出しが走らないことを、実行時の`raw_events == None`ではなく
    // コンパイル時の不在で保証する（[`RawFsEvent`]のdoc参照）。
    #[cfg(test)]
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
            if sink.record_all {
                let record = sink
                    .correlator
                    .lock()
                    .ok()
                    .and_then(|mut c| c.on_operation_end_any(irp, status as u32));
                if let Some(record) = record {
                    if let Ok(mut records) = sink.records.lock() {
                        records.push(record);
                    }
                }
            } else {
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
        assert_eq!(
            filetime_to_unix_ms(116_444_736_000_000_000 + 10_000_000),
            1000
        );
        // 1970年より前（あり得ないが、負のオーバーフローで巨大な値にしない）
        assert_eq!(filetime_to_unix_ms(0), 0);
    }
}

#[cfg(test)]
mod orphan_sweep_tests {
    use super::{is_orphaned_session, orphan_candidate_token, FS_SESSION_PREFIX};

    fn live_session_name(token: &str) -> String {
        format!(
            "{FS_SESSION_PREFIX}{}",
            crate::tier2a::session_profile::profile_name_for(token)
        )
    }

    /// **[BUG-117] 許可側。** 所有者の死んだ収集器セッションは回収の対象になる。
    ///
    /// 撤収は`stop()`と`Drop`の2経路しかなく、**どちらも`TerminateProcess`では走らない**。
    /// 起動側にあった`ERROR_ALREADY_EXISTS`の回収分岐は、セッション名が起動のたびに
    /// 変わる（`{pid}-{unix_secs}`）ので**残留セッションの名前とは一致しない**——
    /// 効くのは同一プロセス内だけだった。
    #[test]
    fn a_session_whose_owner_is_gone_is_collected() {
        let name = live_session_name("4321-1700000000");
        assert_eq!(orphan_candidate_token(&name), Some("4321-1700000000"));
        assert!(is_orphaned_session(&name, |_| false));
    }

    /// **[BUG-117] 禁止側（対）。** 所有者が生きているセッションは止めない。
    ///
    /// **この対が無いと「接頭辞が合えば全部止める」でも許可側が通る**——
    /// それは走行中の別セッションの収集器を殺す（`B-35`）。
    #[test]
    fn a_session_whose_owner_is_alive_is_left_alone() {
        let name = live_session_name("4321-1700000000");
        assert!(!is_orphaned_session(&name, |_| true));
    }

    /// **所有者を判定できない名前は止めない**（fail-closed）。
    ///
    /// スパイクとテストは`harness-policy-learn-<任意>`という名前を張る
    /// （`harness-policy-learn-access-matrix`等）。接頭辞だけで判断すると、
    /// **並行して走っている測定のセッションを止めてしまう。**
    #[test]
    fn a_session_we_cannot_attribute_is_never_stopped() {
        for name in [
            "harness-policy-learn-access-matrix",
            "harness-policy-learn-diag-load",
            "harness-policy-learn-",
            // 接頭辞が違うものは論外（他製品のセッション）
            "Eventlog-Security",
            "harness-something-else",
        ] {
            assert_eq!(orphan_candidate_token(name), None, "{name}");
            assert!(!is_orphaned_session(name, |_| false), "{name}");
        }
    }

    /// 接頭辞の綴りは1箇所が持つ（張る側と回収する側が同じ値を見る）。
    #[test]
    fn the_prefix_matches_what_the_collector_actually_starts() {
        let started = format!(
            "harness-policy-learn-{}",
            crate::tier2a::session_profile::profile_name_for("1-2")
        );
        assert!(started.starts_with(FS_SESSION_PREFIX));
        assert_eq!(orphan_candidate_token(&started), Some("1-2"));
    }

    /// **[段階6d] argv観測のセッションも回収の対象になる。**
    ///
    /// こちらの残留はFS側より重い——**8本しかない枠を1本占有したまま返さない**ので、
    /// 積もると次の記録がfail-closedで始められなくなる（§10.3）。
    #[test]
    fn an_argv_session_whose_owner_is_gone_is_collected_too() {
        let name = format!(
            "{}{}",
            super::ARGV_SESSION_PREFIX,
            crate::tier2a::session_profile::profile_name_for("4321-1700000000")
        );
        assert_eq!(orphan_candidate_token(&name), Some("4321-1700000000"));
        assert!(is_orphaned_session(&name, |_| false));
        // 所有者が生きているなら止めない（FS側と同じ対）。
        assert!(!is_orphaned_session(&name, |_| true));
    }

    /// **対の側**（`B-35`）: **剥がす順序を逆にすると回収されなくなる**ことを固定する。
    ///
    /// `ARGV_SESSION_PREFIX`は`FS_SESSION_PREFIX`で前方一致するので、FS側から先に剥がすと
    /// 残りが`argv-harness.shell.sandbox.<token>`になり、プロファイル名として通らない。
    /// 上のテストだけだと**「長い方から剥がす」を壊しても、なぜ壊れたかが分からない**——
    /// ここで壊れ方そのものを書いておく。
    #[test]
    fn stripping_the_shorter_prefix_first_would_lose_the_owner() {
        let name = format!(
            "{}{}",
            super::ARGV_SESSION_PREFIX,
            crate::tier2a::session_profile::profile_name_for("4321-1700000000")
        );
        // 順序を逆にした場合の剥がし方を、その場で再現する。
        let wrong = name.strip_prefix(FS_SESSION_PREFIX).unwrap();
        assert!(
            !crate::tier2a::session_profile::is_session_profile_name(wrong),
            "短い方から剥がすと所有者が読めなくなる: {wrong}"
        );
        // 正しい順序では読める。
        assert_eq!(orphan_candidate_token(&name), Some("4321-1700000000"));
    }
}
