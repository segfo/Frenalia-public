//! `Microsoft-Windows-Kernel-Process`の通知を本番のセッションへ載せ、`ProcessStart`を解読する
//! （**昇格側で動く**、M15.7）。
//!
//! [`super::session`]の本番セッション（`Kernel-File`）へ2つ目のプロバイダとして相乗りする。
//! プロセスの通知に関する部分だけをここへ置くのは、`session.rs`の本体が1,000行を超えていたため
//! である（`docs/CODE-STRUCTURE-RULES.md`規則1・規則3の「どの外部システムと話すか」）。
//! 2026-10-05に`session.rs`からそのまま移した（式は1文字も変えていない。解読と有効化を関数に
//! 包んだだけ）。
//!
//! 呼び出し側が使う名前（[`ProcessStartInfo`]と3つの定数）は`session.rs`から再公開している——
//! `super::session::ProcessStartInfo`の綴りはそのまま通る。

use windows::core::GUID;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Diagnostics::Etw::{
    EnableTraceEx2, CONTROLTRACE_HANDLE, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD,
    TRACE_LEVEL_INFORMATION,
};

use super::tdh;

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

/// 2つ目のプロバイダを**同じセッションへ**載せる。`Kernel-Process`のProcessStartが
/// 運ぶ`PackageFullName`で、AppContainer子かどうかをプロセス開始時点で判定できる
/// （`OpenProcess`の事後照会は短命プロセスで失敗するため、そちらに頼らない）。
///
/// **失敗しても致命的にしない**。これはスコープ判定の精度を上げるための補助であって、
/// 拒否の収集そのものは`Kernel-File`だけで成立する（D-43 fail-open）。
///
/// 戻り値は載せられたか（`EnableTraceEx2`が`ERROR_SUCCESS`を返したか）。
pub(super) fn enable_on(session_handle: CONTROLTRACE_HANDLE) -> bool {
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
    process_enable == ERROR_SUCCESS
}

/// `Kernel-Process`の通知1件を[`ProcessStartInfo`]へ解読する。`ProcessStart`以外は`None`
/// （`ProcessStop`等は同じキーワードで届くが、収集器は読まない）。
///
/// ETWスレッドのイベントコールバック（`session::event_record_callback`）から呼ばれる——
/// **ここでは重い処理をしない**（遅れるとイベント落ちになる）。
///
/// `pid`はイベントヘッダの`ProcessId`。`ProcessID`プロパティが引けなかったときだけ使う。
///
/// # Safety
/// `record`はETWコールバックが渡した有効な`EVENT_RECORD`でなければならない（[`tdh`]の要件）。
pub(super) unsafe fn decode_process_start(
    record: &EVENT_RECORD,
    pid: u32,
) -> Option<ProcessStartInfo> {
    if record.EventHeader.EventDescriptor.Id != EVENT_ID_PROCESS_START {
        return None;
    }
    Some(ProcessStartInfo {
        pid: tdh::property_u64(record, "ProcessID").unwrap_or(pid as u64) as u32,
        parent_pid: tdh::property_u64(record, "ParentProcessID").map(|v| v as u32),
        image_name: tdh::property_string(record, "ImageName"),
        // v2以降にのみ存在する。無い版では`None`になるだけで壊れない。
        package_full_name: tdh::property_string(record, "PackageFullName"),
        process_sequence_number: tdh::property_u64(record, "ProcessSequenceNumber"),
    })
}
