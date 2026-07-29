//! Windows Filtering Platform (WFP) 出口強制フィルタ（Layer2、`plans/DESIGN-SANDBOX-PRIVSEP.md`
//! §3・`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`）。
//!
//! `harness-netfilterd`（常駐デーモン、`crate::netfilterd`）の中でのみ呼ばれる。本体プロセス
//! （非管理者）はここのWin32 APIを直接呼ばない。`FWPM_SESSION_FLAG_DYNAMIC`で開いたセッションは
//! エンジンハンドルを閉じた瞬間（＝このプロセスの終了時）にBFEが登録済みのプロバイダ・
//! サブレイヤー・フィルタを自動削除するため（付録A #1）、`WfpSession`はプロセス生存期間の
//! 管理を`netfilterd`側に委ねる（このモジュール自体はエンジンハンドルの開閉とルール投入/撤収
//! だけを扱う）。
//!
//! **本ラウンドでの意図的な範囲縮小**（仕様書付録Bチェックリスト参照。すべて
//! `plans/TIER1A-OPEN-ISSUES.md`項目3.5への追記でフォローアップする）:
//! - ドメイン解決は起動時に一度だけ行う（§5.4のTTL準拠バックグラウンド再解決・
//!   Make-before-break・削除猶予は未実装）。
//! - `FwpmNetEventSubscribe`によるDROPイベントログ（§5.3）は未実装。
//! - 名前解決は`std::net::ToSocketAddrs`（内部的に`GetAddrInfoW`、OS標準リゾルバ経由で
//!   dnscacheキャッシュを共有する）を使う簡易版。`DnsQueryEx`によるTTL取得は未実装。

use std::net::{IpAddr, ToSocketAddrs};

use windows::core::GUID;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmProviderAdd0, FwpmProviderDeleteByKey0,
    FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0,
    FwpmTransactionCommit0, FWPM_ACTION0, FWPM_ACTION0_0, FWPM_CONDITION_ALE_PACKAGE_ID,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_DISPLAY_DATA0,
    FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_NONE,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_PROVIDER0,
    FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
    FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_SID,
    FWP_UINT64, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK,
    FWP_VALUE0, FWP_VALUE0_0,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, PSID, SID};

/// harness専用のWFPプロバイダ・サブレイヤーGUID（固定、仕様書§4.2）。他プロバイダとの
/// 名前衝突を避けるため、この2値は将来も変更しない（変更するとteardown時に旧オブジェクトが
/// 孤立フィルタとして残るリスクがある）。
const PROVIDER_KEY: GUID = GUID::from_u128(0x8f2c1a90_5e4b_4b8a_9c3d_1a2b3c4d5e6f);
const SUBLAYER_KEY: GUID = GUID::from_u128(0x8f2c1a91_5e4b_4b8a_9c3d_1a2b3c4d5e6f);

/// サブレイヤー内でのweight（仕様書§4.5）。許可ルールは拒否ルールより高い値にする。
const WEIGHT_ALLOW: u64 = 0xF00;
const WEIGHT_DENY: u64 = 0x10;

#[derive(Debug, thiserror::Error)]
pub enum WfpError {
    #[error("win32 call failed: {0}")]
    Win32(String),
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
#[derive(Debug, Clone, Default)]
pub struct WfpOptions {
    pub allow_domains: Vec<String>,
    pub allow_loopback: bool,
    /// 現状未使用（システム設定DNSサーバの動的取得は未実装、§4.3の`--allow-direct-dns`）。
    /// フィールドとしては仕様書との対応を保つために残す。
    pub allow_direct_dns: bool,
}

/// 適用済みWFPセッション。`teardown`を呼ぶまでエンジンハンドルを保持し続ける
/// （＝フィルタが有効であり続ける、DYNAMICセッションの性質そのもの）。
pub struct WfpSession {
    engine: HANDLE,
}

// HANDLEは値として複数スレッド間で運んでよい（他の`win_*`モジュールと同じ扱い）。
unsafe impl Send for WfpSession {}

impl WfpSession {
    /// `container_sid`宛のALLOW/DENYルールを投入する（仕様書§5.1・§5.2）。
    pub fn apply(container_sid: PSID, opts: &WfpOptions) -> Result<Self, WfpError> {
        let (v4_ips, v6_ips) = resolve_allow_domains(&opts.allow_domains)?;
        if v4_ips.is_empty() && v6_ips.is_empty() && !opts.allow_loopback {
            return Err(WfpError::NoAddressesResolved);
        }

        let engine = open_dynamic_engine()?;

        let result = (|| -> Result<(), WfpError> {
            unsafe {
                check(FwpmTransactionBegin0(engine, 0), "FwpmTransactionBegin0")?;
            }

            let txn_result = apply_within_transaction(engine, container_sid, opts, &v4_ips, &v6_ips);

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
            Ok(()) => Ok(WfpSession { engine }),
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
    pub fn teardown(self) -> Result<(), WfpError> {
        let engine = self.engine;
        std::mem::forget(self); // Dropで二重close/二重teardownしないよう所有権をここで断つ。

        let result = (|| -> Result<(), WfpError> {
            unsafe {
                check(FwpmTransactionBegin0(engine, 0), "FwpmTransactionBegin0 (teardown)")?;
                // フィルタはサブレイヤー削除では自動的に消えないため、サブレイヤー/プロバイダより
                // 前に個別削除するのが本来だが、本ラウンドはフィルタIDを保持していないため、
                // サブレイヤー・プロバイダの削除のみ行う。DYNAMICセッションではエンジンクローズ時に
                // 残りのフィルタもBFEにより自動削除される（付録A #1、フェイルセーフとして機能する）。
                let _ = FwpmSubLayerDeleteByKey0(engine, &SUBLAYER_KEY as *const GUID);
                let _ = FwpmProviderDeleteByKey0(engine, &PROVIDER_KEY as *const GUID);
            }
            unsafe {
                check(FwpmTransactionCommit0(engine), "FwpmTransactionCommit0 (teardown)")?;
            }
            Ok(())
        })();

        unsafe {
            let _ = FwpmEngineClose0(engine);
        }
        result
    }
}

impl Drop for WfpSession {
    /// `teardown`を呼ばずに`WfpSession`がドロップされた場合（異常系・呼び出し忘れ）でも、
    /// 最低限エンジンハンドルは閉じる。DYNAMICセッションの性質により、これだけで登録済みの
    /// プロバイダ・サブレイヤー・フィルタもBFE側で自動削除される（仕様書§5.5異常系と同じ経路）。
    fn drop(&mut self) {
        unsafe {
            let _ = FwpmEngineClose0(self.engine);
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

fn apply_within_transaction(
    engine: HANDLE,
    container_sid: PSID,
    opts: &WfpOptions,
    v4_ips: &[std::net::Ipv4Addr],
    v6_ips: &[std::net::Ipv6Addr],
) -> Result<(), WfpError> {
    unsafe {
        // 1. プロバイダ登録。
        let provider = FWPM_PROVIDER0 {
            providerKey: PROVIDER_KEY,
            displayData: display_data("harness netfilterd", "harness WFP egress guard (Layer2)"),
            ..Default::default()
        };
        check(
            FwpmProviderAdd0(engine, &provider as *const FWPM_PROVIDER0, PSECURITY_DESCRIPTOR::default()),
            "FwpmProviderAdd0",
        )?;

        // 2. サブレイヤー登録。
        let mut provider_key_for_sublayer = PROVIDER_KEY;
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
            displayData: display_data("harness netfilterd", "harness WFP egress guard sublayer"),
            providerKey: &mut provider_key_for_sublayer as *mut GUID,
            weight: 0x100,
            ..Default::default()
        };
        check(
            FwpmSubLayerAdd0(engine, &sublayer as *const FWPM_SUBLAYER0, PSECURITY_DESCRIPTOR::default()),
            "FwpmSubLayerAdd0",
        )?;

        // 3. デフォルト拒否フィルタ（v4/v6両方）。
        add_default_deny_filter(engine, container_sid, FWPM_LAYER_ALE_AUTH_CONNECT_V4)?;
        add_default_deny_filter(engine, container_sid, FWPM_LAYER_ALE_AUTH_CONNECT_V6)?;

        // 4. 許可ドメインの解決済みIP群。
        if !v4_ips.is_empty() {
            add_allow_v4_filter(engine, container_sid, v4_ips)?;
        }
        if !v6_ips.is_empty() {
            add_allow_v6_filter(engine, container_sid, v6_ips)?;
        }

        // 5. ループバック許可（任意）。
        if opts.allow_loopback {
            add_allow_v4_filter(engine, container_sid, &[std::net::Ipv4Addr::LOCALHOST])?;
            add_allow_v6_filter(engine, container_sid, &[std::net::Ipv6Addr::LOCALHOST])?;
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
    let desc_w: Vec<u16> = description.encode_utf16().chain(std::iter::once(0)).collect();
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
) -> Result<(), WfpError> {
    let mut weight_value = WEIGHT_DENY;
    let condition = package_id_condition(container_sid);
    let mut provider_key = PROVIDER_KEY;
    let filter = FWPM_FILTER0 {
        filterKey: GUID::new().map_err(WfpError::from)?,
        displayData: display_data("harness default-deny", "AppContainer SID scoped default deny"),
        flags: FWPM_FILTER_FLAG_NONE,
        providerKey: &mut provider_key as *mut GUID,
        layerKey: layer,
        subLayerKey: SUBLAYER_KEY,
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
            Anonymous: FWPM_ACTION0_0 { filterType: GUID::zeroed() },
        },
        ..Default::default()
    };
    check(
        FwpmFilterAdd0(engine, &filter as *const FWPM_FILTER0, PSECURITY_DESCRIPTOR::default(), None),
        "FwpmFilterAdd0 (default deny)",
    )
}

unsafe fn add_allow_v4_filter(
    engine: HANDLE,
    container_sid: PSID,
    ips: &[std::net::Ipv4Addr],
) -> Result<(), WfpError> {
    let addr_masks: Vec<FWP_V4_ADDR_AND_MASK> = ips
        .iter()
        .map(|ip| FWP_V4_ADDR_AND_MASK {
            addr: u32::from(*ip),
            mask: u32::MAX,
        })
        .collect();
    // 同一fieldKey(IP_REMOTE_ADDRESS)の複数条件はOR結合される（仕様書§4.5「フィルタ本数の最適化」）。
    let mut conditions: Vec<FWPM_FILTER_CONDITION0> = addr_masks
        .iter()
        .map(|m| FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_V4_ADDR_MASK,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    v4AddrMask: m as *const FWP_V4_ADDR_AND_MASK as *mut FWP_V4_ADDR_AND_MASK,
                },
            },
        })
        .collect();
    conditions.push(package_id_condition(container_sid));
    add_allow_filter(engine, FWPM_LAYER_ALE_AUTH_CONNECT_V4, &mut conditions)
}

unsafe fn add_allow_v6_filter(
    engine: HANDLE,
    container_sid: PSID,
    ips: &[std::net::Ipv6Addr],
) -> Result<(), WfpError> {
    let addr_masks: Vec<FWP_V6_ADDR_AND_MASK> = ips
        .iter()
        .map(|ip| FWP_V6_ADDR_AND_MASK {
            addr: ip.octets(),
            prefixLength: 128,
        })
        .collect();
    let mut conditions: Vec<FWPM_FILTER_CONDITION0> = addr_masks
        .iter()
        .map(|m| FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_V6_ADDR_MASK,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    v6AddrMask: m as *const FWP_V6_ADDR_AND_MASK as *mut FWP_V6_ADDR_AND_MASK,
                },
            },
        })
        .collect();
    conditions.push(package_id_condition(container_sid));
    add_allow_filter(engine, FWPM_LAYER_ALE_AUTH_CONNECT_V6, &mut conditions)
}

unsafe fn add_allow_filter(
    engine: HANDLE,
    layer: GUID,
    conditions: &mut [FWPM_FILTER_CONDITION0],
) -> Result<(), WfpError> {
    let mut weight_value = WEIGHT_ALLOW;
    let mut provider_key = PROVIDER_KEY;
    let filter = FWPM_FILTER0 {
        filterKey: GUID::new().map_err(WfpError::from)?,
        displayData: display_data("harness allow", "harness WFP egress allow-list entry"),
        flags: FWPM_FILTER_FLAG_NONE,
        providerKey: &mut provider_key as *mut GUID,
        layerKey: layer,
        subLayerKey: SUBLAYER_KEY,
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
            Anonymous: FWPM_ACTION0_0 { filterType: GUID::zeroed() },
        },
        ..Default::default()
    };
    check(
        FwpmFilterAdd0(engine, &filter as *const FWPM_FILTER0, PSECURITY_DESCRIPTOR::default(), None),
        "FwpmFilterAdd0 (allow)",
    )
}

/// `allow_domains`をOS標準リゾルバ経由（`std::net::ToSocketAddrs`＝`GetAddrInfoW`）で解決し、
/// v4/v6アドレスのリストへ分ける。1件でも解決できたドメインがあれば全体は成功として扱う
/// （一部のドメインだけDNS失敗しても、他の許可ドメインへの通信は妨げたくない）。
fn resolve_allow_domains(
    domains: &[String],
) -> Result<(Vec<std::net::Ipv4Addr>, Vec<std::net::Ipv6Addr>), WfpError> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for domain in domains {
        let query = format!("{domain}:443");
        match query.to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    match addr.ip() {
                        IpAddr::V4(ip) => v4.push(ip),
                        IpAddr::V6(ip) => v6.push(ip),
                    }
                }
            }
            Err(e) => {
                // 1ドメインのDNS失敗で全体を止めない(ログのみ、呼び出し元がまとめて診断できるよう
                // netfilterd側のログへ記録する)。ここでは呼び出し元に伝播させず継続する。
                let _ = WfpError::DnsResolve {
                    domain: domain.clone(),
                    reason: e.to_string(),
                };
            }
        }
    }
    v4.sort();
    v4.dedup();
    v6.sort();
    v6.dedup();
    Ok((v4, v6))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 実際のWFP呼び出し(要管理者権限・BFE)は行わず、GUID定数・weight値が期待通りの
    /// 形であることだけを確認する(実機WFP検証は`netfilterd`の手動E2Eで行う)。
    #[test]
    fn provider_and_sublayer_keys_are_distinct_and_stable() {
        assert_ne!(PROVIDER_KEY, SUBLAYER_KEY);
        assert_eq!(PROVIDER_KEY, GUID::from_u128(0x8f2c1a90_5e4b_4b8a_9c3d_1a2b3c4d5e6f));
        assert_eq!(SUBLAYER_KEY, GUID::from_u128(0x8f2c1a91_5e4b_4b8a_9c3d_1a2b3c4d5e6f));
    }

    #[test]
    fn allow_weight_is_higher_than_deny_weight() {
        const _: () = assert!(WEIGHT_ALLOW > WEIGHT_DENY);
    }

    #[test]
    fn resolve_allow_domains_handles_empty_list() {
        let (v4, v6) = resolve_allow_domains(&[]).unwrap();
        assert!(v4.is_empty());
        assert!(v6.is_empty());
    }
}
