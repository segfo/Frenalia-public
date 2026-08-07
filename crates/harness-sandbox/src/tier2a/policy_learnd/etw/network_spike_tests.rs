//! **ネットワーク可視化 実現性スパイク（判定ゲート）**: `Microsoft-Windows-Kernel-Network`と
//! `Microsoft-Windows-DNS-Client`のリアルタイムETWセッションで、「どのPIDが」「どのドメイン/IPへ」
//! 接続しようとしたかが実際に観測できるか。
//!
//! `plans/POLICY-EDITOR-TOMOYO-DIG.md`のポリシー設定モード（Tier1）構想で、ネットワーク側の
//! 可視化をETWで作れるかを問うている。Tier2aのWFP強制は AppContainer の package SID に紐づくが、
//! Tier1プロセスには package SID が無いため、**PIDだけで相関できるか**がここでの核心の問い。
//!
//! 机上調査（マニフェスト・公開ドキュメント）で分かった前提:
//! - `Kernel-Network`のTCP接続イベント（`KERNEL_NETWORK_TASK_TCPIP`、Id=12 Connectionattempted等）は
//!   1イベントの中に`PID`・`daddr`（宛先IP）・`dport`を同時に持つ（Kernel-Fileの`Create`/`OperationEnd`
//!   のような2イベント相関は不要、という報告がある）
//! - `DNS-Client`（Id=3006 クエリ開始 / Id=3008 クエリ完了）は`QueryName`（ドメイン名）・
//!   `QueryResults`（解決されたIP）を持ち、発生源プロセスの`EventHeader.ProcessId`と結び付く
//! - 上記が正しければ、「同一PIDが直前にDNSで引いたドメイン」と「そのPIDが接続したIP」を
//!   PIDと時刻だけで突き合わせられ、Kernel-Audit-API-Callsで踏んだ「必要な2フィールドが別
//!   プロバイダに分かれている」罠には当たらない可能性が高い——が、**実測していない**
//!
//! このファイルは机上調査を実機で検証する。既存の`etw/`配下の生産コード（`session.rs`・
//! `parse.rs`等）は一切変更せず、独立したセッション実装をここに閉じて持つ
//! （`spike_tests.rs`と同じ「使い捨てスパイク」の位置付け）。
//!
//! 実行:
//! ```text
//! dev-elevated-run.exe spike-etw-net
//! ```
//!
//! **判定が否だった場合、このファイルは削除し、結論だけを`plans/POLICY-EDITOR-TOMOYO-DIG.md`へ
//! 残す**（`docs/CODE-STRUCTURE-RULES.md`規則2「一回性の調査実験をテストとして残さない」、
//! `spike_tests.rs:17-18`と同じ規約）。

use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    CONTROLTRACE_HANDLE, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID,
};

use super::tdh;
use crate::win_common::wide;

/// `daddr`/`dport`はTDHの型情報上`win:UnicodeString`ではなく生バイト列（`win:InAddr`/`win:UInt16`
/// 相当）で運ばれてくることが実測で分かった（1回目の実行では`tdh::property_string`で読んで
/// 文字化けした）。`tdh::property_bytes`は非公開なので、このスパイク専用に最小限だけ複製する。
///
/// # Safety
/// `record`はETWコールバックが渡した有効な`EVENT_RECORD`でなければならない。
unsafe fn property_raw_bytes(record: &EVENT_RECORD, name: &str) -> Option<Vec<u8>> {
    use windows::Win32::System::Diagnostics::Etw::{
        TdhGetProperty, TdhGetPropertySize, PROPERTY_DATA_DESCRIPTOR,
    };
    let name_w = wide(name);
    let descriptors = [PROPERTY_DATA_DESCRIPTOR {
        PropertyName: name_w.as_ptr() as u64,
        ArrayIndex: 0,
        Reserved: 0,
    }];
    let mut size: u32 = 0;
    let status = TdhGetPropertySize(record, None, &descriptors, &mut size);
    if status != ERROR_SUCCESS.0 || size == 0 {
        return None;
    }
    let mut buffer = vec![0u8; size as usize];
    let status = TdhGetProperty(record, None, &descriptors, &mut buffer);
    if status != ERROR_SUCCESS.0 {
        return None;
    }
    Some(buffer)
}

/// `daddr`(IPv4)を生の4バイトから`"a.b.c.d"`へ。バイト順はそのままdotted-decimalの並びと一致する
/// （実測で確認済み。ネットワークバイト順のオクテット列がそのまま表示順）。
fn ipv4_from_raw(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 4 {
        return None;
    }
    Some(format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]))
}

/// `dport`はネットワークバイト順(big-endian)の16bit値。`tdh::property_u64`はホスト側の
/// little-endianとして読むため、ポートはバイトスワップして解釈する必要がある（実測で確認済み）。
fn port_from_raw_be(bytes: &[u8]) -> Option<u64> {
    if bytes.len() != 2 {
        return None;
    }
    Some(u16::from_be_bytes([bytes[0], bytes[1]]) as u64)
}

/// `Microsoft-Windows-Kernel-Network`（`{7DD42A49-5329-4832-8DFD-43D979153A88}`）。
const KERNEL_NETWORK_PROVIDER_GUID: GUID =
    GUID::from_u128(0x7DD4_2A49_5329_4832_8DFD_43D9_7915_3A88);
/// `Microsoft-Windows-DNS-Client`（`{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}`）。
const DNS_CLIENT_PROVIDER_GUID: GUID = GUID::from_u128(0x1C95_126E_7EEA_49A9_A3FE_A378_B03D_DB4D);

/// `KERNEL_NETWORK_TASK_TCPIPConnectionattempted`のevent id。
const EVENT_ID_TCP_CONNECT_ATTEMPTED: u16 = 12;
/// DNS-Clientのクエリ完了イベント（結果=`QueryResults`を持つ）。
const EVENT_ID_DNS_QUERY_COMPLETED: u16 = 3008;

/// 観測したTCP接続試行1件。
#[derive(Debug, Clone)]
struct TcpConnectEvent {
    pid: u32,
    daddr: Option<String>,
    dport: Option<u64>,
}

/// 観測したDNSクエリ完了1件。
#[derive(Debug, Clone)]
struct DnsQueryEvent {
    pid: u32,
    query_name: Option<String>,
    query_results: Option<String>,
}

struct Sink {
    seen_events: Mutex<u64>,
    tcp_connects: Mutex<Vec<TcpConnectEvent>>,
    dns_queries: Mutex<Vec<DnsQueryEvent>>,
    /// `Kernel-Network`プロバイダのイベントであれば、event idを問わず全てのPIDを記録する
    /// (UDP送信のような、`TcpConnectEvent`ではデコードしていないイベント種別の存在確認用)。
    kernel_network_event_pids: Mutex<Vec<u32>>,
}

/// 観測結果。
struct NetSpikeOutcome {
    seen_events: u64,
    tcp_connects: Vec<TcpConnectEvent>,
    dns_queries: Vec<DnsQueryEvent>,
    kernel_network_event_pids: Vec<u32>,
}

/// 使い捨てのリアルタイムETWセッション。`Kernel-Network`と`DNS-Client`を同一セッションへ
/// 両方載せる（`session.rs`が`Kernel-File`＋`Kernel-Process`を相乗りさせているのと同じ構造）。
///
/// **意図的に`session.rs`のプライベート関数を再利用せず、ここへ最小限を複製している**——
/// 使い捨てスパイクのために生産コードの可視性を広げたくない（判定が否だったらこのファイルごと
/// 消える）。
struct NetSpikeSession {
    session_handle: CONTROLTRACE_HANDLE,
    session_name: Vec<u16>,
    trace_handle: PROCESSTRACE_HANDLE,
    worker: Option<std::thread::JoinHandle<()>>,
    sink: Arc<Sink>,
}

#[derive(Debug, thiserror::Error)]
enum NetSpikeError {
    #[error("StartTraceW failed: {0:?} (requires administrator rights)")]
    StartTrace(WIN32_ERROR),
    #[error("EnableTraceEx2 failed for {1}: {0:?}")]
    EnableProvider(WIN32_ERROR, &'static str),
    #[error("OpenTraceW failed: {0:?}")]
    OpenTrace(WIN32_ERROR),
}

impl NetSpikeSession {
    fn start(session_name: &str) -> Result<Self, NetSpikeError> {
        let name_w = wide(session_name);
        let (mut properties_buf, session_handle) = start_trace(&name_w)?;

        // 両プロバイダとも「届くかどうか」自体が問い。キーワードは絞らず全て開ける
        // （`session.rs`の`count_provider_events`と同じ診断的な広さ）。
        for (guid, label) in [
            (KERNEL_NETWORK_PROVIDER_GUID, "Kernel-Network"),
            (DNS_CLIENT_PROVIDER_GUID, "DNS-Client"),
        ] {
            let enable = unsafe {
                EnableTraceEx2(
                    session_handle,
                    &guid as *const GUID,
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
                return Err(NetSpikeError::EnableProvider(enable, label));
            }
        }

        let sink = Arc::new(Sink {
            seen_events: Mutex::new(0),
            tcp_connects: Mutex::new(Vec::new()),
            dns_queries: Mutex::new(Vec::new()),
            kernel_network_event_pids: Mutex::new(Vec::new()),
        });

        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: windows::core::PWSTR(name_w.as_ptr() as *mut u16),
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
            return Err(NetSpikeError::OpenTrace(error));
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

    fn stop(mut self) -> NetSpikeOutcome {
        self.shutdown()
    }

    fn shutdown(&mut self) -> NetSpikeOutcome {
        if self.worker.is_some() {
            let mut properties_buf = properties_buffer(&self.session_name);
            stop_trace(self.session_handle, &self.session_name, &mut properties_buf);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
            unsafe {
                let _ = CloseTrace(self.trace_handle);
            }
        }
        NetSpikeOutcome {
            seen_events: self.sink.seen_events.lock().map(|c| *c).unwrap_or(0),
            tcp_connects: self
                .sink
                .tcp_connects
                .lock()
                .map(|v| v.clone())
                .unwrap_or_default(),
            dns_queries: self
                .sink
                .dns_queries
                .lock()
                .map(|v| v.clone())
                .unwrap_or_default(),
            kernel_network_event_pids: self
                .sink
                .kernel_network_event_pids
                .lock()
                .map(|v| v.clone())
                .unwrap_or_default(),
        }
    }
}

impl Drop for NetSpikeSession {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

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
    let pid = record.EventHeader.ProcessId;

    if record.EventHeader.ProviderId == KERNEL_NETWORK_PROVIDER_GUID {
        if let Ok(mut pids) = sink.kernel_network_event_pids.lock() {
            pids.push(tdh::property_u64(record, "PID").map(|v| v as u32).unwrap_or(pid));
        }
    }

    if record.EventHeader.ProviderId == KERNEL_NETWORK_PROVIDER_GUID
        && event_id == EVENT_ID_TCP_CONNECT_ATTEMPTED
    {
        let event = TcpConnectEvent {
            // `PID`はテンプレートの明示フィールド（`daddr`/`dport`と同じイベントに同居する）。
            // 取れなければ`EventHeader.ProcessId`へフォールバックする。
            pid: tdh::property_u64(record, "PID").map(|v| v as u32).unwrap_or(pid),
            daddr: property_raw_bytes(record, "daddr").and_then(|b| ipv4_from_raw(&b)),
            dport: property_raw_bytes(record, "dport").and_then(|b| port_from_raw_be(&b)),
        };
        if let Ok(mut connects) = sink.tcp_connects.lock() {
            connects.push(event);
        }
        return;
    }

    if record.EventHeader.ProviderId == DNS_CLIENT_PROVIDER_GUID
        && event_id == EVENT_ID_DNS_QUERY_COMPLETED
    {
        let event = DnsQueryEvent {
            pid,
            query_name: tdh::property_string(record, "QueryName"),
            query_results: tdh::property_string(record, "QueryResults"),
        };
        if let Ok(mut queries) = sink.dns_queries.lock() {
            queries.push(event);
        }
    }
}

fn properties_buffer(name_w: &[u16]) -> Vec<u8> {
    let struct_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let name_bytes = std::mem::size_of_val(name_w);
    let total = struct_size + name_bytes;
    let mut buf = vec![0u8; total];

    let properties = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    unsafe {
        (*properties).Wnode.BufferSize = total as u32;
        (*properties).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*properties).Wnode.ClientContext = 1; // QPC
        (*properties).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
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

fn start_trace(name_w: &[u16]) -> Result<(Vec<u8>, CONTROLTRACE_HANDLE), NetSpikeError> {
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
        return Err(NetSpikeError::StartTrace(status));
    }
    Err(NetSpikeError::StartTrace(ERROR_ALREADY_EXISTS))
}

fn stop_trace(handle: CONTROLTRACE_HANDLE, name_w: &[u16], buf: &mut [u8]) {
    unsafe {
        let _ = ControlTraceW(
            handle,
            PCWSTR(name_w.as_ptr()),
            buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

const WARMUP: Duration = Duration::from_millis(1500);
const DRAIN: Duration = Duration::from_secs(4);

/// **判定ゲート1**: `Kernel-Network`のTCP接続試行イベントに、単一イベントの中で
/// 自プロセスのPID・宛先IP・宛先ポートが同時に載っているか。
#[test]
#[ignore = "requires administrator rights (ETW real-time session); run via dev-elevated-run.exe spike-etw-net"]
fn etw_kernel_network_observes_pid_and_destination_for_a_tcp_connect() {
    let session = NetSpikeSession::start("harness-policy-learn-spike-net")
        .expect("start the ETW session (Kernel-Network)");
    std::thread::sleep(WARMUP);

    // 8.8.8.8:53への接続を試みる。応答が来るかどうかは問題ではない——SYNが出ればよい。
    let target = "8.8.8.8:53".parse().expect("valid socket addr");
    let attempt =
        std::net::TcpStream::connect_timeout(&target, std::time::Duration::from_millis(500));
    println!("connect attempt result: {attempt:?}");

    std::thread::sleep(DRAIN);
    let outcome = session.stop();

    println!(
        "observed {} total events, {} TCP connect-attempted event(s)",
        outcome.seen_events,
        outcome.tcp_connects.len()
    );
    for c in &outcome.tcp_connects {
        println!("  pid={} daddr={:?} dport={:?}", c.pid, c.daddr, c.dport);
    }

    assert!(
        outcome.seen_events > 0,
        "no events reached the callback at all -- the provider could not be enabled, \
         or the session was not actually collecting"
    );

    let my_pid = std::process::id();
    let matched = outcome.tcp_connects.iter().find(|c| c.pid == my_pid);
    let matched = matched.unwrap_or_else(|| {
        panic!(
            "no TCP connect-attempted event was attributed to this process (pid={my_pid}). \
             observed: {:#?}",
            outcome.tcp_connects
        )
    });
    assert_eq!(matched.daddr.as_deref(), Some("8.8.8.8"));
    assert_eq!(matched.dport, Some(53));
}

/// **判定ゲート2**: `DNS-Client`のクエリ完了イベントに、自プロセスのPID・クエリ名・
/// 解決結果が載っているか。
#[test]
#[ignore = "requires administrator rights (ETW real-time session); run via dev-elevated-run.exe spike-etw-net"]
fn etw_dns_client_observes_pid_and_domain_for_a_query() {
    let session = NetSpikeSession::start("harness-policy-learn-spike-dns")
        .expect("start the ETW session (DNS-Client)");
    std::thread::sleep(WARMUP);

    // 名前解決を発生させる(OSのDNSクライアントサービス経由でDNS-Clientイベントが出るのは
    // `ToSocketAddrs`のような、実際に名前解決APIを呼ぶ経路のみ)。
    let resolved = "dns.google:443".to_socket_addrs();
    println!("resolution attempt result: {resolved:?}");

    std::thread::sleep(DRAIN);
    let outcome = session.stop();

    println!(
        "observed {} total events, {} DNS query-completed event(s)",
        outcome.seen_events,
        outcome.dns_queries.len()
    );
    for q in &outcome.dns_queries {
        println!(
            "  pid={} query_name={:?} query_results={:?}",
            q.pid, q.query_name, q.query_results
        );
    }

    assert!(outcome.seen_events > 0, "no events reached the callback at all");

    // **実測で判明した罠**: 1回の高レベルなクエリに対し、Id=3008(クエリ完了)は複数回発火する
    // （実行結果ではQueryResults=Noneのものが先に1件、Some(...)が後で1件、pidは同一）。
    // 「最初に見つかった3008」ではなく「QueryResultsが非空の3008」を拾う必要がある。
    let my_pid = std::process::id();
    let matched = outcome.dns_queries.iter().find(|q| {
        q.pid == my_pid
            && q.query_name.as_deref().is_some_and(|n| n.contains("dns.google"))
            && q.query_results.as_deref().is_some_and(|r| !r.is_empty())
    });
    let matched = matched.unwrap_or_else(|| {
        panic!(
            "no DNS query-completed event for dns.google with a non-empty QueryResults was \
             attributed to this process (pid={my_pid}). observed: {:#?}",
            outcome.dns_queries
        )
    });
    println!("matched: pid={} query_results={:?}", matched.pid, matched.query_results);
}

/// `QueryResults`は`;`区切りのIPリストで、IPv4は`::ffff:8.8.8.8`のようなIPv4-mapped IPv6表記に
/// なる（実測で確認済み）。`daddr`側の素のIPv4文字列と比較できる形へ正規化する。
fn query_results_contains_ipv4(query_results: &str, ipv4: &str) -> bool {
    query_results.split(';').any(|entry| {
        let entry = entry.trim();
        entry == ipv4 || entry == format!("::ffff:{ipv4}")
    })
}

/// **判定ゲート3(本命)**: `Kernel-Network`の接続イベントと`DNS-Client`のクエリ完了イベントを
/// 「同一PID・IPv4が一致」だけで突き合わせて、**接続先IPから逆に問い合わせたドメイン名を
/// 復元できるか**。これができれば、Tier1でもProxyを経由させずに「このコマンドはどのドメインへ
/// 触ったか」というドメイン単位の記録を作れる。
#[test]
#[ignore = "requires administrator rights (ETW real-time session); run via dev-elevated-run.exe spike-etw-net"]
fn etw_correlates_a_tcp_connect_back_to_the_domain_that_was_queried() {
    let session = NetSpikeSession::start("harness-policy-learn-spike-corr")
        .expect("start the ETW session (Kernel-Network + DNS-Client)");
    std::thread::sleep(WARMUP);

    // 1. 名前解決（DNS-Clientイベントを発生させる）。
    let addrs: Vec<_> = "dns.google:443"
        .to_socket_addrs()
        .expect("resolve dns.google")
        .collect();
    println!("resolved: {addrs:?}");
    let ipv4_target = addrs
        .iter()
        .find_map(|a| match a {
            std::net::SocketAddr::V4(v4) => Some(*v4),
            _ => None,
        })
        .expect("at least one IPv4 address for dns.google");

    // 2. 解決したIPv4へ実際に接続を試みる(Kernel-Networkイベントを発生させる)。
    let attempt = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::V4(ipv4_target),
        std::time::Duration::from_millis(800),
    );
    println!("connect attempt to {ipv4_target}: {attempt:?}");

    std::thread::sleep(DRAIN);
    let outcome = session.stop();
    println!(
        "observed {} total events, {} TCP connects, {} DNS completions",
        outcome.seen_events,
        outcome.tcp_connects.len(),
        outcome.dns_queries.len()
    );

    let my_pid = std::process::id();
    let expected_ip = ipv4_target.ip().to_string();

    // 3. 自PIDの接続イベントから、実際に繋いだIPを取り出す。
    let connect = outcome
        .tcp_connects
        .iter()
        .find(|c| c.pid == my_pid && c.daddr.as_deref() == Some(expected_ip.as_str()))
        .unwrap_or_else(|| {
            panic!(
                "no TCP connect to {expected_ip} was attributed to this process (pid={my_pid}). \
                 observed: {:#?}",
                outcome.tcp_connects
            )
        });

    // 4. そのIPを`QueryResults`に含むDNS完了イベントを、同一PIDの中から探す
    //    (Proxyを経由せず、PID+IP一致だけでドメイン名を逆引きする)。
    let dns = outcome
        .dns_queries
        .iter()
        .find(|q| {
            q.pid == my_pid
                && q.query_results
                    .as_deref()
                    .is_some_and(|r| query_results_contains_ipv4(r, &expected_ip))
        })
        .unwrap_or_else(|| {
            panic!(
                "no DNS query-completed event whose QueryResults contains {expected_ip} was \
                 found for pid={my_pid}. observed: {:#?}",
                outcome.dns_queries
            )
        });

    println!(
        "correlation succeeded: pid={} connected to {}:{:?} <- resolved from domain {:?}",
        connect.pid, expected_ip, connect.dport, dns.query_name
    );
    assert_eq!(dns.query_name.as_deref(), Some("dns.google"));
}

/// **判定ゲート4**: OSのDNSキャッシュが温まっている状態(2回目以降の解決)でも、
/// `DNS-Client`のクエリ完了イベントは発火するか。**観測が主目的**——キャッシュ命中時に
/// イベント自体が出ないなら、「セッション開始前に別コマンドが引いたドメイン」を
/// このセッションの相関では拾えない、という相関の限界が判明する。
#[test]
#[ignore = "requires administrator rights (ETW real-time session); run via dev-elevated-run.exe spike-etw-net"]
fn etw_dns_client_on_a_cache_warm_resolution() {
    // セッション開始「前」に1回引いてキャッシュを温める。
    let warmup_resolve = "dns.google:443".to_socket_addrs();
    println!("warmup resolve (outside the ETW session, fills the OS cache): {warmup_resolve:?}");

    let session = NetSpikeSession::start("harness-policy-learn-spike-cache")
        .expect("start the ETW session (DNS-Client)");
    std::thread::sleep(WARMUP);

    // 同じドメインをもう一度引く。OSのDNSクライアントキャッシュが効いていれば、
    // 実際のネットワーク問い合わせは飛ばずキャッシュから即座に返るはず。
    let cached_resolve = "dns.google:443".to_socket_addrs();
    println!("cached resolve (inside the ETW session): {cached_resolve:?}");

    std::thread::sleep(DRAIN);
    let outcome = session.stop();

    let my_pid = std::process::id();
    let matches: Vec<_> = outcome
        .dns_queries
        .iter()
        .filter(|q| q.pid == my_pid && q.query_name.as_deref().is_some_and(|n| n.contains("dns.google")))
        .collect();
    println!(
        "observed {} total events; {} DNS-Client event(s) for this pid+domain during the \
         cache-warm window: {:#?}",
        outcome.seen_events,
        matches.len(),
        matches
    );

    if matches.is_empty() {
        println!(
            "CONCLUSION: cache-hit resolutions do NOT surface a DNS-Client event -- a domain \
             resolved before this session's window (e.g. by an earlier command, or by Windows' \
             own prefetching) cannot be recovered by this correlation."
        );
    } else {
        println!(
            "CONCLUSION: DNS-Client still surfaces an event even on a cache hit -- the \
             correlation survives repeated/cached resolutions within the observation window."
        );
    }
}

/// **判定ゲート5**: 解決API(`getaddrinfo`相当)をこのセッションの観測窓の中で一切呼ばずに
/// 既知のIPへ直接接続した場合、`DNS-Client`イベントは(当然ながら)出ないことを確認する。
/// これは相関の**既知の盲点**を実証するためのテスト——「アプリが自前でIPをキャッシュしている」
/// 「接続を使い回している(keep-alive)」場合、この相関ではドメイン名を復元できない。
#[test]
#[ignore = "requires administrator rights (ETW real-time session); run via dev-elevated-run.exe spike-etw-net"]
fn etw_no_dns_event_when_connecting_by_ip_without_resolving_in_window() {
    // セッション開始「前」に解決だけ済ませ、IPを手元に持っておく(名前解決APIを窓の外で使う)。
    let addrs: Vec<_> = "dns.google:443"
        .to_socket_addrs()
        .expect("resolve dns.google outside the session window")
        .collect();
    let ipv4_target = addrs
        .iter()
        .find_map(|a| match a {
            std::net::SocketAddr::V4(v4) => Some(*v4),
            _ => None,
        })
        .expect("at least one IPv4 address for dns.google");

    let session = NetSpikeSession::start("harness-policy-learn-spike-nodns")
        .expect("start the ETW session (Kernel-Network + DNS-Client)");
    std::thread::sleep(WARMUP);

    // 観測窓の中では、既に持っているIPへ直接つなぐだけで、名前解決APIは一切呼ばない。
    let attempt = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::V4(ipv4_target),
        std::time::Duration::from_millis(800),
    );
    println!("connect attempt (no resolve call in-window) to {ipv4_target}: {attempt:?}");

    std::thread::sleep(DRAIN);
    let outcome = session.stop();

    let my_pid = std::process::id();
    let connect_seen = outcome.tcp_connects.iter().any(|c| c.pid == my_pid);
    let dns_seen = outcome
        .dns_queries
        .iter()
        .any(|q| q.pid == my_pid && q.query_name.as_deref().is_some_and(|n| n.contains("dns.google")));
    println!(
        "observed {} total events; this pid's TCP connect observed={connect_seen}, \
         this pid's DNS-Client event for dns.google observed={dns_seen}",
        outcome.seen_events
    );

    assert!(
        connect_seen,
        "the TCP connect itself must still be observed even without a resolve call"
    );
    assert!(
        !dns_seen,
        "unexpectedly saw a DNS-Client event for dns.google even though no resolve API was \
         called in-window -- the blind spot may not exist after all, re-check this finding"
    );
}

/// **判定ゲート6**: ポリシー設定モードが実際に起動するのは**子プロセス**であって、この
/// テストプロセス自身ではない。ここまでの相関は全部「自分自身が解決・接続した」場合でしか
/// 確かめていなかった——子プロセスの接続・DNSイベントが、正しく**子のPID**に帰属するかを
/// 実測する（FS側は`appcontainer_child_denials_are_observable_and_attributable`で
/// 確認済みだが、ネットワーク側では未確認だった）。
#[test]
#[ignore = "requires administrator rights (ETW real-time session); run via dev-elevated-run.exe spike-etw-net"]
fn etw_attributes_events_to_a_child_process_not_the_parent() {
    let session = NetSpikeSession::start("harness-policy-learn-spike-child")
        .expect("start the ETW session (Kernel-Network + DNS-Client)");
    std::thread::sleep(WARMUP);

    // Windows標準のcurl.exe(WinHTTP/Schannel経由、OSのリゾルバを使う)を子プロセスとして起動する。
    let mut child = std::process::Command::new(r"C:\Windows\System32\curl.exe")
        .args(["-s", "-o", "NUL", "--max-time", "5", "https://dns.google"])
        .spawn()
        .expect("spawn C:\\Windows\\System32\\curl.exe");
    let child_pid = child.id();
    println!("spawned child curl.exe, pid={child_pid}");
    let status = child.wait();
    println!("child exited: {status:?}");

    std::thread::sleep(DRAIN);
    let outcome = session.stop();

    let my_pid = std::process::id();
    let child_connects: Vec<_> =
        outcome.tcp_connects.iter().filter(|c| c.pid == child_pid).collect();
    let child_dns: Vec<_> = outcome
        .dns_queries
        .iter()
        .filter(|q| q.pid == child_pid && q.query_name.is_some())
        .collect();
    let misattributed_to_parent: Vec<_> = outcome
        .tcp_connects
        .iter()
        .filter(|c| c.pid == my_pid && c.daddr.is_some())
        .collect();

    println!(
        "observed {} total events; child(pid={child_pid}) TCP connects={}, child DNS events={}, \
         parent(pid={my_pid}) TCP connects={}",
        outcome.seen_events,
        child_connects.len(),
        child_dns.len(),
        misattributed_to_parent.len()
    );
    for c in &child_connects {
        println!("  child connect: daddr={:?} dport={:?}", c.daddr, c.dport);
    }
    for q in &child_dns {
        println!("  child dns: query_name={:?} query_results={:?}", q.query_name, q.query_results);
    }

    assert!(
        !child_connects.is_empty() || !child_dns.is_empty(),
        "no event at all was attributed to the child process (pid={child_pid}) -- child-process \
         attribution may not work the way it does for Kernel-File"
    );
}

/// **判定ゲート7**: OSのDNSクライアント(`getaddrinfo`/`DnsQuery`)を経由せず、自前でUDPの
/// DNSクエリを組んで送るプログラム(pure-Goリゾルバ等)がいた場合、`DNS-Client`には本当に
/// 何も出ないかを実測する。`Kernel-Network`側はパケットが飛べば見えるはずなので、
/// 「`Kernel-Network`は見えるのに`DNS-Client`だけ空」という不一致が実際に起きることを示す。
#[test]
#[ignore = "requires administrator rights (ETW real-time session); run via dev-elevated-run.exe spike-etw-net"]
fn etw_dns_client_is_blind_to_a_raw_udp_query_that_bypasses_the_os_resolver() {
    let session = NetSpikeSession::start("harness-policy-learn-spike-rawdns")
        .expect("start the ETW session (Kernel-Network + DNS-Client)");
    std::thread::sleep(WARMUP);

    // "dns.google"のAレコードを問い合わせる最小限のDNSクエリを自分で組み立て、Win32の
    // 名前解決API(getaddrinfo/DnsQuery)を一切呼ばずに生のUDPソケットで8.8.8.8:53へ送る
    // (pure-Goリゾルバ等、OSのDnscacheを経由しない実装のシミュレーション)。
    let query = build_minimal_dns_query_a_record(0x1234, "dns.google");
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind a UDP socket");
    socket
        .send_to(&query, "8.8.8.8:53")
        .expect("send the raw DNS query");
    let mut buf = [0u8; 512];
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("set a read timeout");
    let response = socket.recv_from(&mut buf);
    println!("raw UDP DNS query sent; response: {response:?}");

    std::thread::sleep(DRAIN);
    let outcome = session.stop();

    let my_pid = std::process::id();
    let kernel_network_saw_us =
        outcome.kernel_network_event_pids.iter().filter(|&&p| p == my_pid).count();
    let dns_client_saw_us = outcome
        .dns_queries
        .iter()
        .any(|q| q.pid == my_pid && q.query_name.as_deref().is_some_and(|n| n.contains("dns.google")));

    println!(
        "observed {} total events; Kernel-Network events for this pid={kernel_network_saw_us}, \
         DNS-Client saw a dns.google query for this pid={dns_client_saw_us}",
        outcome.seen_events
    );

    assert!(
        kernel_network_saw_us > 0,
        "Kernel-Network did not see any traffic from this pid at all -- the raw UDP query may \
         not have actually gone out, so this run proves nothing"
    );
    assert!(
        !dns_client_saw_us,
        "unexpectedly saw a DNS-Client event for a query that bypassed getaddrinfo/DnsQuery -- \
         the resolver-bypass blind spot may not exist after all, re-check this finding"
    );
}

/// `qname`(例: "dns.google")のAレコードを問い合わせる最小限のDNSクエリメッセージを組み立てる。
fn build_minimal_dns_query_a_record(id: u16, qname: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: standard query, recursion desired
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    msg.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0
    msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0
    for label in qname.split('.') {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0); // root label
    msg.extend_from_slice(&1u16.to_be_bytes()); // QTYPE=A
    msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
    msg
}
