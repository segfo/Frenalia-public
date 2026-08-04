//! Windows Filtering Platform (WFP) 出口強制フィルタ（Layer2、`plans/DESIGN-SANDBOX-PRIVSEP.md`
//! §3・`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`）。
//!
//! `harness-netfilterd`（常駐デーモン、`crate::tier2a::netfilterd`）の中でのみ呼ばれる。本体プロセス
//! （非管理者）はここのWin32 APIを直接呼ばない。`FWPM_SESSION_FLAG_DYNAMIC`で開いたセッションは
//! エンジンハンドルを閉じた瞬間（＝このプロセスの終了時）にBFEが登録済みのプロバイダ・
//! サブレイヤー・フィルタを自動削除するため（付録A #1）、`WfpSession`はプロセス生存期間の
//! 管理を`netfilterd`側に委ねる（このモジュール自体はエンジンハンドルの開閉とルール投入/撤収
//! だけを扱う）。
//!
//! **本ラウンドでの意図的な範囲縮小**（仕様書付録Bチェックリスト参照。
//! `plans/TIER1A-OPEN-ISSUES.md`項目3.5にて対応しないと決定済み、2026-08-01）:
//! - ドメイン解決は起動時に一度だけ行う（§5.4のTTL準拠バックグラウンド再解決・
//!   Make-before-break・削除猶予は対応しない）。
//! - `FwpmNetEventSubscribe`によるDROPイベントログはベストエフォートでJSONLへ追記する。
//! - 許可ドメインのIP解決済みアドレスをWFPで直接allowする旧経路は使わない。v1では
//!   Local Proxy/Fake DNSのloopback実ポートだけを許可する。

use std::ffi::c_void;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use windows::core::GUID;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmEngineSetOption0, FwpmFilterAdd0,
    FwpmFilterCreateEnumHandle0, FwpmFilterDeleteById0, FwpmFilterDestroyEnumHandle0,
    FwpmFilterEnum0, FwpmFreeMemory0, FwpmNetEventSubscribe0, FwpmNetEventUnsubscribe0,
    FwpmProviderAdd0, FwpmProviderDeleteByKey0, FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0,
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0,
    FWPM_ACTION0_0, FWPM_CONDITION_ALE_PACKAGE_ID, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0,
    FWPM_ENGINE_COLLECT_NET_EVENTS, FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_NONE,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_NET_EVENT1,
    FWPM_NET_EVENT_SUBSCRIPTION0, FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, FWPM_PROVIDER0, FWPM_SESSION0,
    FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
    FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_IP_VERSION_V4, FWP_IP_VERSION_V6,
    FWP_MATCH_EQUAL, FWP_SID, FWP_UINT16, FWP_UINT32, FWP_UINT64, FWP_UINT8, FWP_V4_ADDR_AND_MASK,
    FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, PSID, SID};

use crate::tier2a::loopback_exemption::{self, LoopbackExemptionGuard};

/// harness専用のWFPプロバイダ・サブレイヤーGUIDの**名前空間**（固定、仕様書§4.2）。
///
/// この2値そのものをキーとして使っていた頃は、2セッション目の`apply`が
/// `cleanup_stale_objects`で**先行セッションのフィルタを全削除**し、後発が終了すると先行が
/// `internetClient`を持ったままdefault-denyだけ失う（fail-open）という欠陥があった
/// （実機で再現・`docs/STATUS.md`旧Tier2a残課題#8）。D-37でpackage SIDがセッション単位に
/// なったのに合わせ、**キー自体もセッション単位に導出する**。上位96bitを固定して
/// 「harnessのオブジェクトである」ことは判別可能なまま、下位32bitへセッション固有値を混ぜる。
const PROVIDER_KEY_NAMESPACE: u128 = 0x8f2c1a90_5e4b_4b8a_9c3d_1a2b00000000;
const SUBLAYER_KEY_NAMESPACE: u128 = 0x8f2c1a91_5e4b_4b8a_9c3d_1a2b00000000;

/// セッション固有値。**フィルタを条件付けるのと同じ識別子（セッションプロファイル名）から
/// 決定論的に導出する**——`apply`と`teardown`が同じキーを見る必要があり、かつ別セッションとは
/// 必ず違う値でなければならないため、乱数でもプロセス固有値でもなく名前のハッシュを使う
/// （`netfilterd`はセッションごとに別プロセスだが、キーの根拠をデーモン側のプロセスIDに
/// 置くと「なぜ衝突しないのか」がフィルタの意味と結びつかなくなる）。
fn session_key_suffix(session_profile: &str) -> u32 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    session_profile.hash(&mut hasher);
    // 0は「名前空間そのもの」と紛らわしいので避ける。
    (hasher.finish() as u32) | 1
}

/// 1セッション分のWFPオブジェクトキー。`apply`が決めて`WfpSession`が持ち続ける。
#[derive(Debug, Clone, Copy)]
struct SessionKeys {
    provider: GUID,
    sublayer: GUID,
}

impl SessionKeys {
    fn for_session(session_profile: &str) -> Self {
        let suffix = session_key_suffix(session_profile) as u128;
        Self {
            provider: GUID::from_u128(PROVIDER_KEY_NAMESPACE | suffix),
            sublayer: GUID::from_u128(SUBLAYER_KEY_NAMESPACE | suffix),
        }
    }
}

/// サブレイヤー内でのweight（仕様書§4.5）。許可ルールは拒否ルールより高い値にする。
const WEIGHT_ALLOW: u64 = 0xF00;
const WEIGHT_DENY: u64 = 0x10;

#[derive(Debug, thiserror::Error)]
pub enum WfpError {
    #[error("win32 call failed: {0}")]
    Win32(String),
    #[error("failed to configure AppContainer loopback exemption: {0}")]
    LoopbackExemption(String),
    /// v1では構築されない。WFP層で許可ドメインをIP解決して外部宛先を直接allowする設計
    /// （仕様書の旧案）へ戻す場合に使う枠として、エラー分類を仕様書と対応させたまま残す。
    #[allow(dead_code)]
    #[error("domain resolution failed for {domain}: {reason}")]
    DnsResolve { domain: String, reason: String },
    #[error("no IP addresses resolved for any allowed domain")]
    NoAddressesResolved,
}

impl From<windows::core::Error> for WfpError {
    fn from(e: windows::core::Error) -> Self {
        WfpError::Win32(e.to_string())
    }
}

fn check(status: u32, op: &str) -> Result<(), WfpError> {
    if status == 0 {
        Ok(())
    } else {
        Err(WfpError::Win32(format!(
            "{op} failed with FWP status 0x{status:08X}"
        )))
    }
}

/// `WfpApplyRules`要求のオプション（仕様書§6のCLIオプションに対応）。
///
/// `netfilterd::NetfilterPolicy`（IPCワイヤ形式）と同じ3フィールドを持つが、レイヤーが違う
/// （こちらはWFPエンジンへ渡す層）。旧IPC互換のためだけに存在し実体を持たなかった
/// `allow_domains`・`allow_loopback`・`allow_loopback_ports`・`allow_direct_dns`はR-02で
/// 両型から削除した（`docs/STATUS.md`参照）。
#[derive(Debug, Clone, Default)]
pub struct WfpOptions {
    /// このWFPセッションが属するharnessセッションのプロファイル名（D-37）。フィルタを
    /// 条件付けるpackage SIDと、プロバイダ/サブレイヤーGUIDの導出元を兼ねる。
    pub session_profile: String,
    /// TCPで許可するloopback宛先ポート。Local Proxy AgentとFake DNS TCPをここへ入れる。
    pub allow_loopback_tcp_ports: Vec<u16>,
    /// UDPで許可するloopback宛先ポート。Fake DNS UDPをここへ入れる。
    pub allow_loopback_udp_ports: Vec<u16>,
    /// WFP block/drop監査イベントを追記するJSONLパス。`None`ならWFP監査購読を起動しない。
    pub audit_log_path: Option<PathBuf>,
}

/// 適用済みWFPセッション。`teardown`を呼ぶまでエンジンハンドルを保持し続ける
/// （＝フィルタが有効であり続ける、DYNAMICセッションの性質そのもの）。
pub struct WfpSession {
    keys: SessionKeys,
    engine: HANDLE,
    event_subscription: Option<HANDLE>,
    audit_context: Option<*mut WfpAuditSink>,
    loopback_exemption: Option<LoopbackExemptionGuard>,
}

// HANDLEは値として複数スレッド間で運んでよい（他の`win_*`モジュールと同じ扱い）。
unsafe impl Send for WfpSession {}

#[derive(Debug)]
struct WfpAuditSink {
    path: PathBuf,
}

#[derive(Debug, Serialize)]
struct WfpAuditEntry {
    timestamp_unix_ms: u128,
    kind: &'static str,
    protocol: &'static str,
    allowed: bool,
    reason: &'static str,
    local_addr: Option<String>,
    local_port: u16,
    remote_addr: Option<String>,
    remote_host: Option<String>,
    remote_port: u16,
    filter_id: Option<u64>,
    layer_id: Option<u16>,
}

impl WfpAuditSink {
    fn record(&self, entry: &WfpAuditEntry) {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            if let Ok(line) = serde_json::to_string(entry) {
                let _ = writeln!(file, "{line}");
            }
        }
    }

    fn lookup_fake_dns_host(&self, remote_addr: &str) -> Option<String> {
        let text = std::fs::read_to_string(&self.path).ok()?;
        text.lines().rev().find_map(|line| {
            let value = serde_json::from_str::<serde_json::Value>(line).ok()?;
            if value.get("kind")?.as_str()? != "fake_dns" {
                return None;
            }
            if value.get("fake_ip")?.as_str()? != remote_addr {
                return None;
            }
            value.get("host")?.as_str().map(ToOwned::to_owned)
        })
    }
}

unsafe extern "system" fn wfp_net_event_callback(
    context: *mut core::ffi::c_void,
    event: *const FWPM_NET_EVENT1,
) {
    if context.is_null() || event.is_null() {
        return;
    }
    let sink = &*(context as *const WfpAuditSink);
    let event = &*event;
    if event.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
        return;
    }

    let header = event.header;
    let (local_addr, remote_addr) = match header.ipVersion {
        FWP_IP_VERSION_V4 => (
            Some(std::net::Ipv4Addr::from(header.Anonymous1.localAddrV4).to_string()),
            Some(std::net::Ipv4Addr::from(header.Anonymous2.remoteAddrV4).to_string()),
        ),
        FWP_IP_VERSION_V6 => (
            Some(std::net::Ipv6Addr::from(header.Anonymous1.localAddrV6.byteArray16).to_string()),
            Some(std::net::Ipv6Addr::from(header.Anonymous2.remoteAddrV6.byteArray16).to_string()),
        ),
        _ => (None, None),
    };

    let drop = event.Anonymous.classifyDrop.as_ref();
    let remote_host = remote_addr
        .as_deref()
        .and_then(|addr| sink.lookup_fake_dns_host(addr));
    let entry = WfpAuditEntry {
        timestamp_unix_ms: now_unix_ms(),
        kind: "wfp",
        protocol: protocol_name(header.ipProtocol),
        allowed: false,
        reason: "classify_drop",
        local_addr,
        local_port: header.localPort,
        remote_addr,
        remote_host,
        remote_port: header.remotePort,
        filter_id: drop.map(|d| d.filterId),
        layer_id: drop.map(|d| d.layerId),
    };
    sink.record(&entry);
}

fn protocol_name(protocol: u8) -> &'static str {
    match protocol {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        58 => "icmpv6",
        _ => "ip",
    }
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

/// loopback exemptionの確保（D-36）。「既に載っていれば何もしない／自分が載せた場合だけ外す」
/// というプロセスローカルな判断は、複数セッションが同一のpackage SIDを共有する構造では成立
/// しない（BUG-053）。所有権は[`crate::tier2a::loopback_exemption`]の台帳が持つ。
fn ensure_loopback_exemption(container_sid: PSID) -> Result<LoopbackExemptionGuard, WfpError> {
    loopback_exemption::acquire(container_sid)
        .map_err(|e| WfpError::LoopbackExemption(e.to_string()))
}

fn remove_loopback_exemption(guard: LoopbackExemptionGuard) -> Result<(), WfpError> {
    loopback_exemption::release(guard).map_err(|e| WfpError::LoopbackExemption(e.to_string()))
}

impl WfpSession {
    /// `container_sid`宛のALLOW/DENYルールを投入する（仕様書§5.1・§5.2）。
    pub fn apply(container_sid: PSID, opts: &WfpOptions) -> Result<Self, WfpError> {
        if opts.allow_loopback_tcp_ports.is_empty() && opts.allow_loopback_udp_ports.is_empty() {
            return Err(WfpError::NoAddressesResolved);
        }

        let keys = SessionKeys::for_session(&opts.session_profile);
        cleanup_stale_objects(keys);
        let engine = open_dynamic_engine()?;

        let result = (|| -> Result<(), WfpError> {
            unsafe {
                check(FwpmTransactionBegin0(engine, 0), "FwpmTransactionBegin0")?;
            }

            let txn_result = apply_within_transaction(engine, container_sid, opts, keys);

            unsafe {
                match &txn_result {
                    Ok(()) => check(FwpmTransactionCommit0(engine), "FwpmTransactionCommit0")?,
                    Err(_) => {
                        // ベストエフォート: abort自体の失敗はtxn_resultのエラーを覆わない。
                        let _ = FwpmTransactionAbort0(engine);
                    }
                }
            }
            txn_result
        })();

        match result {
            Ok(()) => {
                let loopback_exemption = match ensure_loopback_exemption(container_sid) {
                    Ok(guard) => Some(guard),
                    Err(e) => {
                        unsafe {
                            let _ = FwpmEngineClose0(engine);
                        }
                        return Err(e);
                    }
                };
                let (event_subscription, audit_context) =
                    start_wfp_drop_audit(engine, opts.audit_log_path.clone());
                Ok(WfpSession {
                    keys,
                    engine,
                    event_subscription,
                    audit_context,
                    loopback_exemption,
                })
            }
            Err(e) => {
                unsafe {
                    let _ = FwpmEngineClose0(engine);
                }
                Err(e)
            }
        }
    }

    /// 投入したフィルタ・サブレイヤー・プロバイダを撤収し、エンジンハンドルを閉じる
    /// （仕様書§5.5正常系）。呼び出し後、`self`は消費される。
    pub fn teardown(mut self) -> Result<(), WfpError> {
        let engine = self.engine;
        let keys = self.keys;
        let event_subscription = self.event_subscription;
        let audit_context = self.audit_context;
        let loopback_exemption = self.loopback_exemption.take();
        std::mem::forget(self); // Dropで二重close/二重teardownしないよう所有権をここで断つ。

        let result = (|| -> Result<(), WfpError> {
            unsafe {
                if let Some(subscription) = event_subscription {
                    let _ = FwpmNetEventUnsubscribe0(engine, subscription);
                }
                check(
                    FwpmTransactionBegin0(engine, 0),
                    "FwpmTransactionBegin0 (teardown)",
                )?;
                // フィルタはサブレイヤー削除では自動的に消えないため、サブレイヤー/プロバイダより
                // 前に個別削除するのが本来だが、本ラウンドはフィルタIDを保持していないため、
                // サブレイヤー・プロバイダの削除のみ行う。DYNAMICセッションではエンジンクローズ時に
                // 残りのフィルタもBFEにより自動削除される（付録A #1、フェイルセーフとして機能する）。
                let _ = FwpmSubLayerDeleteByKey0(engine, &keys.sublayer as *const GUID);
                let _ = FwpmProviderDeleteByKey0(engine, &keys.provider as *const GUID);
            }
            unsafe {
                check(
                    FwpmTransactionCommit0(engine),
                    "FwpmTransactionCommit0 (teardown)",
                )?;
            }
            Ok(())
        })();

        let loopback_result = if let Some(exemption) = loopback_exemption {
            remove_loopback_exemption(exemption)
        } else {
            Ok(())
        };
        unsafe {
            if let Some(context) = audit_context {
                drop(Box::from_raw(context));
            }
            let _ = FwpmEngineClose0(engine);
        }
        result.and(loopback_result)
    }
}

impl Drop for WfpSession {
    /// `teardown`を呼ばずに`WfpSession`がドロップされた場合（異常系・呼び出し忘れ）でも、
    /// 最低限エンジンハンドルは閉じる。DYNAMICセッションの性質により、これだけで登録済みの
    /// プロバイダ・サブレイヤー・フィルタもBFE側で自動削除される（仕様書§5.5異常系と同じ経路）。
    fn drop(&mut self) {
        unsafe {
            if let Some(subscription) = self.event_subscription.take() {
                let _ = FwpmNetEventUnsubscribe0(self.engine, subscription);
            }
            if let Some(context) = self.audit_context.take() {
                drop(Box::from_raw(context));
            }
            if let Some(exemption) = self.loopback_exemption.take() {
                let _ = remove_loopback_exemption(exemption);
            }
            let _ = FwpmEngineClose0(self.engine);
        }
    }
}

fn start_wfp_drop_audit(
    engine: HANDLE,
    audit_log_path: Option<PathBuf>,
) -> (Option<HANDLE>, Option<*mut WfpAuditSink>) {
    let Some(path) = audit_log_path else {
        return (None, None);
    };
    unsafe {
        let value = FWP_VALUE0 {
            r#type: FWP_UINT32,
            Anonymous: FWP_VALUE0_0 { uint32: 1 },
        };
        let set_status = FwpmEngineSetOption0(engine, FWPM_ENGINE_COLLECT_NET_EVENTS, &value);
        let sink = Box::new(WfpAuditSink { path });
        let sink_ptr = Box::into_raw(sink);
        if set_status != 0 {
            let sink = Box::from_raw(sink_ptr);
            sink.record(&WfpAuditEntry {
                timestamp_unix_ms: now_unix_ms(),
                kind: "wfp",
                protocol: "control",
                allowed: false,
                reason: "net_event_collection_enable_failed",
                local_addr: None,
                local_port: 0,
                remote_addr: None,
                remote_host: None,
                remote_port: 0,
                filter_id: None,
                layer_id: None,
            });
            return (None, None);
        }

        let subscription = FWPM_NET_EVENT_SUBSCRIPTION0::default();
        let mut handle = HANDLE::default();
        let status = FwpmNetEventSubscribe0(
            engine,
            &subscription,
            Some(wfp_net_event_callback),
            Some(sink_ptr as *const core::ffi::c_void),
            &mut handle,
        );
        if status == 0 {
            (Some(handle), Some(sink_ptr))
        } else {
            let sink = Box::from_raw(sink_ptr);
            sink.record(&WfpAuditEntry {
                timestamp_unix_ms: now_unix_ms(),
                kind: "wfp",
                protocol: "control",
                allowed: false,
                reason: "net_event_subscribe_failed",
                local_addr: None,
                local_port: 0,
                remote_addr: None,
                remote_host: None,
                remote_port: 0,
                filter_id: None,
                layer_id: None,
            });
            (None, None)
        }
    }
}

fn open_dynamic_engine() -> Result<HANDLE, WfpError> {
    unsafe {
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };
        let mut engine = HANDLE::default();
        check(
            FwpmEngineOpen0(
                windows::core::PCWSTR::null(),
                windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT,
                None,
                Some(&session as *const FWPM_SESSION0),
                &mut engine as *mut HANDLE,
            ),
            "FwpmEngineOpen0",
        )?;
        Ok(engine)
    }
}

fn cleanup_stale_objects(keys: SessionKeys) {
    unsafe {
        let mut engine = HANDLE::default();
        let status = FwpmEngineOpen0(
            windows::core::PCWSTR::null(),
            windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT,
            None,
            None,
            &mut engine as *mut HANDLE,
        );
        if status != 0 {
            return;
        }

        delete_filters_in_own_sublayer(engine, keys);
        let _ = FwpmSubLayerDeleteByKey0(engine, &keys.sublayer as *const GUID);
        let _ = FwpmProviderDeleteByKey0(engine, &keys.provider as *const GUID);
        let _ = FwpmEngineClose0(engine);
    }
}

unsafe fn delete_filters_in_own_sublayer(engine: HANDLE, keys: SessionKeys) {
    let mut enum_handle = HANDLE::default();
    if FwpmFilterCreateEnumHandle0(engine, None, &mut enum_handle) != 0 {
        return;
    }

    loop {
        let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
        let mut returned = 0u32;
        let status = FwpmFilterEnum0(engine, enum_handle, 64, &mut entries, &mut returned);
        if status != 0 || returned == 0 {
            if !entries.is_null() {
                let mut memory = entries as *mut c_void;
                FwpmFreeMemory0(&mut memory);
            }
            break;
        }

        let slice = std::slice::from_raw_parts(entries, returned as usize);
        for filter_ptr in slice {
            if filter_ptr.is_null() {
                continue;
            }
            let filter = &**filter_ptr;
            if filter.subLayerKey == keys.sublayer {
                let _ = FwpmFilterDeleteById0(engine, filter.filterId);
            }
        }

        let mut memory = entries as *mut c_void;
        FwpmFreeMemory0(&mut memory);
    }

    let _ = FwpmFilterDestroyEnumHandle0(engine, enum_handle);
}

fn apply_within_transaction(
    engine: HANDLE,
    container_sid: PSID,
    opts: &WfpOptions,
    keys: SessionKeys,
) -> Result<(), WfpError> {
    unsafe {
        // 1. プロバイダ登録。
        let provider = FWPM_PROVIDER0 {
            providerKey: keys.provider,
            displayData: display_data("harness netfilterd", "harness WFP egress guard (Layer2)"),
            ..Default::default()
        };
        check(
            FwpmProviderAdd0(
                engine,
                &provider as *const FWPM_PROVIDER0,
                PSECURITY_DESCRIPTOR::default(),
            ),
            "FwpmProviderAdd0",
        )?;

        // 2. サブレイヤー登録。
        let mut provider_key_for_sublayer = keys.provider;
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: keys.sublayer,
            displayData: display_data("harness netfilterd", "harness WFP egress guard sublayer"),
            providerKey: &mut provider_key_for_sublayer as *mut GUID,
            weight: 0x100,
            ..Default::default()
        };
        check(
            FwpmSubLayerAdd0(
                engine,
                &sublayer as *const FWPM_SUBLAYER0,
                PSECURITY_DESCRIPTOR::default(),
            ),
            "FwpmSubLayerAdd0",
        )?;

        // 3. デフォルト拒否フィルタ（v4/v6両方）。
        add_default_deny_filter(engine, container_sid, FWPM_LAYER_ALE_AUTH_CONNECT_V4, keys)?;
        add_default_deny_filter(engine, container_sid, FWPM_LAYER_ALE_AUTH_CONNECT_V6, keys)?;

        // 4. ループバック許可（任意）。Proxy/Fake DNSの待受だけを開けるため、
        // v1ではポート指定の限定allowだけを張る。
        let mut tcp_ports = opts.allow_loopback_tcp_ports.clone();
        tcp_ports.sort_unstable();
        tcp_ports.dedup();
        let mut udp_ports = opts.allow_loopback_udp_ports.clone();
        udp_ports.sort_unstable();
        udp_ports.dedup();
        if !tcp_ports.is_empty() {
            add_allow_v4_loopback_ports_filter(engine, container_sid, &tcp_ports, 6, keys)?;
            add_allow_v6_loopback_ports_filter(engine, container_sid, &tcp_ports, 6, keys)?;
        }
        if !udp_ports.is_empty() {
            add_allow_v4_loopback_ports_filter(engine, container_sid, &udp_ports, 17, keys)?;
            add_allow_v6_loopback_ports_filter(engine, container_sid, &udp_ports, 17, keys)?;
        }
    }
    Ok(())
}

fn display_data(name: &str, description: &str) -> FWPM_DISPLAY_DATA0 {
    // FWPM_DISPLAY_DATA0はWFPが内部でコピーする(FwpmProviderAdd0/FwpmSubLayerAdd0/FwpmFilterAdd0
    // 呼び出し中に読み取られるだけ)ため、呼び出し完了までポインタが生きていればよい。
    // ここではリークさせて`'static`扱いにする — このプロセス(netfilterd)は1回のアプリ実行に
    // つき1回しかこの経路を通らず、常駐時間も対象アプリの生存期間程度に限られるため実害はない。
    let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let desc_w: Vec<u16> = description
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    FWPM_DISPLAY_DATA0 {
        name: windows::core::PWSTR(Box::leak(name_w.into_boxed_slice()).as_mut_ptr()),
        description: windows::core::PWSTR(Box::leak(desc_w.into_boxed_slice()).as_mut_ptr()),
    }
}

unsafe fn package_id_condition(container_sid: PSID) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_ALE_PACKAGE_ID,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_SID,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                sid: container_sid.0 as *mut SID,
            },
        },
    }
}

unsafe fn add_default_deny_filter(
    engine: HANDLE,
    container_sid: PSID,
    layer: GUID,
    keys: SessionKeys,
) -> Result<(), WfpError> {
    let mut weight_value = WEIGHT_DENY;
    let condition = package_id_condition(container_sid);
    let mut provider_key_value = keys.provider;
    let filter = FWPM_FILTER0 {
        filterKey: GUID::new().map_err(WfpError::from)?,
        displayData: display_data(
            "harness default-deny",
            "AppContainer SID scoped default deny",
        ),
        flags: FWPM_FILTER_FLAG_NONE,
        providerKey: &mut provider_key_value as *mut GUID,
        layerKey: layer,
        subLayerKey: keys.sublayer,
        weight: FWP_VALUE0 {
            r#type: FWP_UINT64,
            Anonymous: FWP_VALUE0_0 {
                uint64: &mut weight_value as *mut u64,
            },
        },
        numFilterConditions: 1,
        filterCondition: &condition as *const FWPM_FILTER_CONDITION0 as *mut FWPM_FILTER_CONDITION0,
        action: FWPM_ACTION0 {
            r#type: FWP_ACTION_BLOCK,
            Anonymous: FWPM_ACTION0_0 {
                filterType: GUID::zeroed(),
            },
        },
        ..Default::default()
    };
    check(
        FwpmFilterAdd0(
            engine,
            &filter as *const FWPM_FILTER0,
            PSECURITY_DESCRIPTOR::default(),
            None,
        ),
        "FwpmFilterAdd0 (default deny)",
    )
}

unsafe fn add_allow_v4_loopback_ports_filter(
    engine: HANDLE,
    container_sid: PSID,
    ports: &[u16],
    protocol: u8,
    keys: SessionKeys,
) -> Result<(), WfpError> {
    let loopback = FWP_V4_ADDR_AND_MASK {
        addr: u32::from(std::net::Ipv4Addr::LOCALHOST),
        mask: u32::MAX,
    };
    let mut conditions = loopback_port_conditions_v4(container_sid, &loopback, ports, protocol);
    add_allow_filter(engine, FWPM_LAYER_ALE_AUTH_CONNECT_V4, &mut conditions, keys)
}

unsafe fn add_allow_v6_loopback_ports_filter(
    engine: HANDLE,
    container_sid: PSID,
    ports: &[u16],
    protocol: u8,
    keys: SessionKeys,
) -> Result<(), WfpError> {
    let loopback = FWP_V6_ADDR_AND_MASK {
        addr: std::net::Ipv6Addr::LOCALHOST.octets(),
        prefixLength: 128,
    };
    let mut conditions = loopback_port_conditions_v6(container_sid, &loopback, ports, protocol);
    add_allow_filter(engine, FWPM_LAYER_ALE_AUTH_CONNECT_V6, &mut conditions, keys)
}

unsafe fn loopback_port_conditions_v4(
    container_sid: PSID,
    loopback: &FWP_V4_ADDR_AND_MASK,
    ports: &[u16],
    protocol: u8,
) -> Vec<FWPM_FILTER_CONDITION0> {
    let mut conditions = Vec::with_capacity(ports.len() + 3);
    conditions.push(FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_V4_ADDR_MASK,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                v4AddrMask: loopback as *const FWP_V4_ADDR_AND_MASK as *mut FWP_V4_ADDR_AND_MASK,
            },
        },
    });
    conditions.push(protocol_condition(protocol));
    conditions.extend(remote_port_conditions(ports));
    conditions.push(package_id_condition(container_sid));
    conditions
}

unsafe fn loopback_port_conditions_v6(
    container_sid: PSID,
    loopback: &FWP_V6_ADDR_AND_MASK,
    ports: &[u16],
    protocol: u8,
) -> Vec<FWPM_FILTER_CONDITION0> {
    let mut conditions = Vec::with_capacity(ports.len() + 3);
    conditions.push(FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_V6_ADDR_MASK,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                v6AddrMask: loopback as *const FWP_V6_ADDR_AND_MASK as *mut FWP_V6_ADDR_AND_MASK,
            },
        },
    });
    conditions.push(protocol_condition(protocol));
    conditions.extend(remote_port_conditions(ports));
    conditions.push(package_id_condition(container_sid));
    conditions
}

fn protocol_condition(protocol: u8) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_PROTOCOL,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint8: protocol },
        },
    }
}

fn remote_port_conditions(ports: &[u16]) -> Vec<FWPM_FILTER_CONDITION0> {
    ports
        .iter()
        .map(|port| FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT16,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint16: *port },
            },
        })
        .collect()
}

unsafe fn add_allow_filter(
    engine: HANDLE,
    layer: GUID,
    conditions: &mut [FWPM_FILTER_CONDITION0],
    keys: SessionKeys,
) -> Result<(), WfpError> {
    let mut weight_value = WEIGHT_ALLOW;
    let mut provider_key_value = keys.provider;
    let filter = FWPM_FILTER0 {
        filterKey: GUID::new().map_err(WfpError::from)?,
        displayData: display_data("harness allow", "harness WFP egress allow-list entry"),
        flags: FWPM_FILTER_FLAG_NONE,
        providerKey: &mut provider_key_value as *mut GUID,
        layerKey: layer,
        subLayerKey: keys.sublayer,
        weight: FWP_VALUE0 {
            r#type: FWP_UINT64,
            Anonymous: FWP_VALUE0_0 {
                uint64: &mut weight_value as *mut u64,
            },
        },
        numFilterConditions: conditions.len() as u32,
        filterCondition: conditions.as_mut_ptr(),
        action: FWPM_ACTION0 {
            r#type: FWP_ACTION_PERMIT,
            Anonymous: FWPM_ACTION0_0 {
                filterType: GUID::zeroed(),
            },
        },
        ..Default::default()
    };
    check(
        FwpmFilterAdd0(
            engine,
            &filter as *const FWPM_FILTER0,
            PSECURITY_DESCRIPTOR::default(),
            None,
        ),
        "FwpmFilterAdd0 (allow)",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 実際のWFP呼び出し(要管理者権限・BFE)は行わず、GUIDの形だけを確認する
    /// (実機WFP検証は`netfilterd`の手動E2Eで行う)。
    ///
    /// D-37でキーはセッション単位になった。**プロセス内では安定**（`apply`と`teardown`が
    /// 同じキーを見る必要がある）かつ**プロバイダとサブレイヤーは別値**、そして
    /// **上位96bitは名前空間として固定**（harnessのオブジェクトだと判別できる）ことを固定する。
    #[test]
    fn provider_and_sublayer_keys_are_distinct_stable_and_namespaced() {
        let keys = SessionKeys::for_session("harness.shell.sandbox.1-100");
        assert_ne!(keys.provider, keys.sublayer);
        assert_eq!(
            keys.provider,
            SessionKeys::for_session("harness.shell.sandbox.1-100").provider,
            "同じセッションなら同じキー（applyとteardownが一致する必要がある）"
        );

        const NAMESPACE_MASK: u128 = !0xFFFF_FFFFu128;
        assert_eq!(keys.provider.to_u128() & NAMESPACE_MASK, PROVIDER_KEY_NAMESPACE);
        assert_eq!(keys.sublayer.to_u128() & NAMESPACE_MASK, SUBLAYER_KEY_NAMESPACE);
    }

    /// セッション（プロファイル名）が違えばキーも違う。これが#8（後発の`apply`が先行の
    /// フィルタを消す）を構造的に閉じている根拠なので、名前→キーの写像を直接固定する。
    #[test]
    fn different_sessions_get_different_keys() {
        let a = SessionKeys::for_session("harness.shell.sandbox.1-100");
        let b = SessionKeys::for_session("harness.shell.sandbox.2-100");
        assert_ne!(a.provider, b.provider);
        assert_ne!(a.sublayer, b.sublayer);
        assert_eq!(
            session_key_suffix("harness.shell.sandbox.1-100") & 1,
            1,
            "0にはしない（名前空間そのものと紛らわしいため）"
        );
    }

    #[test]
    fn allow_weight_is_higher_than_deny_weight() {
        const _: () = assert!(WEIGHT_ALLOW > WEIGHT_DENY);
    }

    /// R-02で削除した旧IPC互換フィールド（`allow_domains`・`allow_loopback`・
    /// `allow_direct_dns`）が持っていた「TCP/UDPどちらのloopbackポートも指定しなければ
    /// fail-closedになる」という性質そのものは、フィールド削除後も`WfpOptions::default()`
    /// で変わらず確認できる。
    #[test]
    fn options_without_any_loopback_ports_are_fail_closed() {
        let opts = WfpOptions::default();
        match WfpSession::apply(PSID::default(), &opts) {
            Err(WfpError::NoAddressesResolved) => {}
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("empty loopback port options must not open any allow path"),
        }
    }

    #[test]
    fn remote_port_conditions_use_ip_remote_port_field() {
        let conditions = remote_port_conditions(&[18080, 18053]);
        assert_eq!(conditions.len(), 2);
        assert_eq!(conditions[0].fieldKey, FWPM_CONDITION_IP_REMOTE_PORT);
        assert_eq!(conditions[1].fieldKey, FWPM_CONDITION_IP_REMOTE_PORT);
        assert_eq!(conditions[0].conditionValue.r#type, FWP_UINT16);
        assert_eq!(conditions[1].conditionValue.r#type, FWP_UINT16);
        unsafe {
            assert_eq!(conditions[0].conditionValue.Anonymous.uint16, 18080);
            assert_eq!(conditions[1].conditionValue.Anonymous.uint16, 18053);
        }
    }

    #[test]
    fn loopback_port_conditions_include_ip_protocol_field() {
        let loopback = FWP_V4_ADDR_AND_MASK {
            addr: u32::from(std::net::Ipv4Addr::LOCALHOST),
            mask: u32::MAX,
        };
        let conditions =
            unsafe { loopback_port_conditions_v4(PSID::default(), &loopback, &[18080], 6) };
        assert!(
            conditions
                .iter()
                .any(|condition| condition.fieldKey == FWPM_CONDITION_IP_PROTOCOL
                    && condition.conditionValue.r#type == FWP_UINT8
                    && unsafe { condition.conditionValue.Anonymous.uint8 } == 6),
            "loopback permit filters must be protocol-scoped"
        );
    }

    #[test]
    fn protocol_name_maps_common_ip_protocol_numbers() {
        assert_eq!(protocol_name(6), "tcp");
        assert_eq!(protocol_name(17), "udp");
        assert_eq!(protocol_name(1), "icmp");
        assert_eq!(protocol_name(58), "icmpv6");
        assert_eq!(protocol_name(132), "ip");
    }

    #[test]
    fn wfp_audit_sink_appends_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("net-audit.jsonl");
        let sink = WfpAuditSink { path: path.clone() };
        sink.record(&WfpAuditEntry {
            timestamp_unix_ms: 123,
            kind: "wfp",
            protocol: "tcp",
            allowed: false,
            reason: "classify_drop",
            local_addr: Some("127.0.0.1".to_string()),
            local_port: 50000,
            remote_addr: Some("127.0.0.1".to_string()),
            remote_host: None,
            remote_port: 18080,
            filter_id: Some(42),
            layer_id: Some(44),
        });

        let text = std::fs::read_to_string(path).unwrap();
        let line = text.lines().next().unwrap();
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(value["kind"], "wfp");
        assert_eq!(value["protocol"], "tcp");
        assert_eq!(value["allowed"], false);
        assert_eq!(value["reason"], "classify_drop");
        assert_eq!(value["remote_port"], 18080);
        assert_eq!(text.lines().count(), 1);
    }

    #[test]
    fn wfp_audit_sink_resolves_fake_dns_mapping_from_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net-audit.jsonl");
        std::fs::write(
            &path,
            concat!(
                r#"{"kind":"fake_dns","host":"old.example","fake_ip":"198.18.0.1"}"#,
                "\n",
                r#"{"kind":"proxy","host":"ignored.example"}"#,
                "\n",
                r#"{"kind":"fake_dns","host":"latest.example","fake_ip":"198.18.0.1"}"#,
                "\n",
                r#"{"kind":"fake_dns","host":"other.example","fake_ip":"198.18.0.2"}"#,
                "\n"
            ),
        )
        .unwrap();

        let sink = WfpAuditSink { path };
        assert_eq!(
            sink.lookup_fake_dns_host("198.18.0.1"),
            Some("latest.example".to_string())
        );
        assert_eq!(sink.lookup_fake_dns_host("198.18.0.99"), None);
    }

    #[test]
    fn wfp_audit_entry_can_include_fake_dns_remote_host() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net-audit.jsonl");
        let sink = WfpAuditSink { path: path.clone() };
        sink.record(&WfpAuditEntry {
            timestamp_unix_ms: 124,
            kind: "wfp",
            protocol: "tcp",
            allowed: false,
            reason: "classify_drop",
            local_addr: Some("127.0.0.1".to_string()),
            local_port: 50001,
            remote_addr: Some("198.18.0.1".to_string()),
            remote_host: Some("example.com".to_string()),
            remote_port: 443,
            filter_id: Some(43),
            layer_id: Some(44),
        });

        let text = std::fs::read_to_string(path).unwrap();
        let value: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(value["remote_addr"], "198.18.0.1");
        assert_eq!(value["remote_host"], "example.com");
    }

    /// `docs/STATUS.md` Tier2a残課題#8の再現。プロバイダ/サブレイヤーGUIDは固定値なので、
    /// 2セッション目の`apply`が`cleanup_stale_objects()`で**先行セッションのフィルタを消す**
    /// （＝先行の出口強制が無音で外れる）のか、`FwpmProviderAdd0`が`ALREADY_EXISTS`で
    /// **失敗する**（fail-closed）のかを実機で確かめる。
    ///
    /// 実行例（要管理者権限）: `dev-elevated-run.exe e2e-wfp-multisession`
    #[cfg(windows)]
    #[test]
    #[ignore = "requires administrator token and BFE; mutates machine-global WFP state"]
    fn e2e_a_second_session_does_not_disturb_the_first_sessions_filters() {
        if !crate::tier2a::privhelper::is_elevated() {
            panic!("WFP multi-session E2E requires an elevated administrator token");
        }
        let sid = crate::tier2a::win_appcontainer::ensure_profile(
            crate::tier2a::win_appcontainer::CONTAINER_NAME,
        )
        .expect("ensure AppContainer profile");

        /// 自サブレイヤー配下に今あるフィルタのID集合（実機の観測値）。
        fn filter_ids_in_sublayer(keys: SessionKeys) -> std::collections::BTreeSet<u64> {
            let mut ids = std::collections::BTreeSet::new();
            unsafe {
                let mut engine = HANDLE::default();
                if FwpmEngineOpen0(
                    windows::core::PCWSTR::null(),
                    windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT,
                    None,
                    None,
                    &mut engine as *mut HANDLE,
                ) != 0
                {
                    return ids;
                }
                let mut enum_handle = HANDLE::default();
                if FwpmFilterCreateEnumHandle0(engine, None, &mut enum_handle) == 0 {
                    loop {
                        let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
                        let mut returned = 0u32;
                        let status =
                            FwpmFilterEnum0(engine, enum_handle, 64, &mut entries, &mut returned);
                        if status != 0 || returned == 0 {
                            if !entries.is_null() {
                                let mut memory = entries as *mut c_void;
                                FwpmFreeMemory0(&mut memory);
                            }
                            break;
                        }
                        let slice = std::slice::from_raw_parts(entries, returned as usize);
                        for filter_ptr in slice.iter().filter(|f| !f.is_null()) {
                            let filter = &**filter_ptr;
                            if filter.subLayerKey == keys.sublayer {
                                ids.insert(filter.filterId);
                            }
                        }
                        let mut memory = entries as *mut c_void;
                        FwpmFreeMemory0(&mut memory);
                    }
                    let _ = FwpmFilterDestroyEnumHandle0(engine, enum_handle);
                }
                let _ = FwpmEngineClose0(engine);
            }
            ids
        }

        // 実運用では2セッションのLocal Proxyポートは別々になる。同じにすると
        // 「Aのフィルタが消えてもBのフィルタが同じ穴を開ける」ため差分が見えない。
        let listener_a = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let listener_b = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        // D-37: 2つの**別セッション**（別プロファイル名）を模す。実運用ではセッションごとに
        // 別プロセスの`harness-netfilterd`が動くが、キーもフィルタ条件もプロファイル名から
        // 決まるので、1プロセス内でも同じ構造を再現できる。
        let profile_a = crate::tier2a::session_profile::profile_name_for("wfp-test-a");
        let profile_b = crate::tier2a::session_profile::profile_name_for("wfp-test-b");
        let keys_a = SessionKeys::for_session(&profile_a);
        let keys_b = SessionKeys::for_session(&profile_b);
        let opts_a = WfpOptions {
            session_profile: profile_a.clone(),
            allow_loopback_tcp_ports: vec![listener_a.local_addr().unwrap().port()],
            allow_loopback_udp_ports: Vec::new(),
            audit_log_path: None,
        };
        let opts_b = WfpOptions {
            session_profile: profile_b.clone(),
            allow_loopback_tcp_ports: vec![listener_b.local_addr().unwrap().port()],
            allow_loopback_udp_ports: Vec::new(),
            audit_log_path: None,
        };

        let session_a = WfpSession::apply(sid.as_psid(), &opts_a).expect("session A apply");
        let ids_a = filter_ids_in_sublayer(keys_a);
        eprintln!("[e2e] セッションAのフィルタ: {ids_a:?}");
        assert!(!ids_a.is_empty(), "Aのフィルタが投入されていない");

        let session_b = WfpSession::apply(sid.as_psid(), &opts_b).expect("session B apply");
        let ids_b = filter_ids_in_sublayer(keys_b);
        let a_after_b = filter_ids_in_sublayer(keys_a);
        eprintln!("[e2e] セッションBのフィルタ: {ids_b:?}");
        eprintln!("[e2e] B適用後もAに残っているフィルタ: {a_after_b:?}");

        // **これが#8の修正点**: 後発の`apply`（`cleanup_stale_objects`込み）が先行のフィルタを
        // 削らない。以前は共有サブレイヤーだったため、ここでAの4件が全滅していた。
        assert_eq!(
            a_after_b, ids_a,
            "後発セッションのapplyが先行セッションのフィルタを削っている（先行の出口強制が無音で外れる）"
        );
        assert!(
            ids_a.is_disjoint(&ids_b),
            "セッションごとにフィルタは別物であるべき: A={ids_a:?} B={ids_b:?}"
        );

        // 後発だけ終了させても、先行のフィルタは残る（DYNAMICセッションは自分のぶんだけ消す）。
        session_b.teardown().expect("session B teardown");
        let a_after_b_teardown = filter_ids_in_sublayer(keys_a);
        eprintln!("[e2e] B終了後にAに残っているフィルタ: {a_after_b_teardown:?}");
        assert_eq!(
            a_after_b_teardown, ids_a,
            "後発の終了で先行セッションのフィルタまで消えている（実行中のサンドボックスが無防備になる）"
        );

        session_a.teardown().expect("session A teardown");
        let after_all = filter_ids_in_sublayer(keys_a);
        eprintln!("[e2e] 全終了後: {after_all:?}");
        assert!(after_all.is_empty(), "全セッション終了後にフィルタが残っている");
    }

    /// 管理者権限+BFE有効なWindows実機でのみ手動実行するE2E。
    ///
    /// 実行例:
    /// `cargo test -p harness-sandbox wfp::tests::e2e_wfp_blocks_direct_external_connect_and_logs_drop -- --ignored --nocapture`
    ///
    /// このテストは、対象AppContainerに`internetClient`を付与したうえで、WFPを
    /// default-deny + loopbackポート限定allowとして適用する。loopback許可ポートへの接続は成功し、
    /// 外部IPへの直接connectは失敗し、可能ならWFP dropイベントがJSONLへ記録されることを確認する。
    #[cfg(windows)]
    #[test]
    #[ignore = "requires administrator token, BFE, and real Windows AppContainer/WFP state"]
    fn e2e_wfp_blocks_direct_external_connect_and_logs_drop() {
        if !crate::tier2a::privhelper::is_elevated() {
            panic!("WFP E2E requires an elevated administrator token");
        }

        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("net-audit.jsonl");
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let allowed_port = listener.local_addr().unwrap().port();
        let accept_thread = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok(_) => return,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(25));
                    }
                    Err(_) => return,
                }
            }
        });

        // D-37: 本番と同じ形——WFPの条件も子プロセスも「このセッションのプロファイル」で揃える。
        let session_profile = crate::tier2a::session_profile::current_profile_name();
        let sid = crate::tier2a::win_appcontainer::ensure_profile(&session_profile)
            .expect("ensure AppContainer profile");
        crate::tier2a::win_appcontainer::grant_ace_recursive(dir.path(), sid.as_psid())
            .expect("grant temp dir ACE to AppContainer");
        let opts = WfpOptions {
            session_profile: session_profile.clone(),
            allow_loopback_tcp_ports: vec![allowed_port],
            allow_loopback_udp_ports: Vec::new(),
            audit_log_path: Some(audit_path.clone()),
        };
        let session = WfpSession::apply(sid.as_psid(), &opts).expect("apply WFP rules");
        let (shell, _) = crate::tier2a::win_appcontainer::resolve_shell();
        let env = crate::secret_env::build_child_env();
        let command = format!(
            "$ErrorActionPreference = 'Stop'; \
             $ok = $false; \
             try {{ $c = [Net.Sockets.TcpClient]::new(); $c.Connect('127.0.0.1', {allowed_port}); $c.Close(); $ok = $true }} catch {{ }}; \
             $blocked = $false; \
             try {{ $c = [Net.Sockets.TcpClient]::new(); $c.Connect('8.8.8.8', 53); $c.Close() }} catch {{ $blocked = $true }}; \
             if ($ok -and $blocked) {{ Write-Output 'HARNESS_WFP_E2E_OK'; exit 0 }} else {{ Write-Output \"ok=$ok blocked=$blocked\"; exit 7 }}"
        );
        let child = crate::tier2a::win_appcontainer::spawn(
            &shell,
            &["-NoProfile", "-NonInteractive", "-Command", &command],
            dir.path(),
            &env,
            false,
            sid.as_psid(),
            crate::tier2a::win_appcontainer::NetworkCapability::InternetClient,
            None,
        )
        .expect("spawn AppContainer child");
        let (stdout, stderr, code) = child.write_stdin_read_output_and_wait(None).unwrap();
        let _ = accept_thread.join();
        assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
        assert!(
            stdout.contains("HARNESS_WFP_E2E_OK"),
            "stdout={stdout}\nstderr={stderr}"
        );

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut saw_drop = false;
        while std::time::Instant::now() < deadline {
            let text = std::fs::read_to_string(&audit_path).unwrap_or_default();
            saw_drop = text.lines().any(|line| {
                let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                    return false;
                };
                value.get("kind").and_then(|v| v.as_str()) == Some("wfp")
                    && value.get("allowed").and_then(|v| v.as_bool()) == Some(false)
            });
            if saw_drop {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        session.teardown().expect("teardown WFP rules");
        assert!(
            saw_drop,
            "expected WFP drop event in {}",
            audit_path.display()
        );
    }
}
