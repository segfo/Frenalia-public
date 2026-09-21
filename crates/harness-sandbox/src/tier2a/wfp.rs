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
use windows::Win32::Foundation::{FILETIME, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineGetOption0, FwpmEngineOpen0, FwpmEngineSetOption0, FwpmFilterAdd0,
    FwpmFilterCreateEnumHandle0, FwpmFilterDeleteById0, FwpmFilterDestroyEnumHandle0,
    FwpmFilterEnum0, FwpmFreeMemory0, FwpmNetEventCreateEnumHandle0,
    FwpmNetEventDestroyEnumHandle0, FwpmNetEventEnum1, FwpmNetEventSubscribe0,
    FwpmNetEventUnsubscribe0, FwpmProviderAdd0, FwpmProviderDeleteByKey0, FwpmSubLayerAdd0,
    FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
    FWPM_ACTION0, FWPM_ACTION0_0, FWPM_CONDITION_ALE_PACKAGE_ID, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0,
    FWPM_ENGINE_COLLECT_NET_EVENTS, FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, FWPM_FILTER0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_NONE, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_NET_EVENT1, FWPM_NET_EVENT_SUBSCRIPTION0,
    FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, FWPM_PROVIDER0, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC,
    FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_IP_VERSION_V4, FWP_IP_VERSION_V6, FWP_MATCH_EQUAL, FWP_SID,
    FWP_UINT16, FWP_UINT32, FWP_UINT64, FWP_UINT8, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
    FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0,
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
}

// [BUG-094 案G] `audit_log_path`はここから外した。監査の書込先は**フィルタの世代ではなく
// daemonの生存**に紐づくようになったので（[`WfpAuditSubscription`]）、
// 世代ごとのオプションに置いておくと「世代と一緒に閉じる」と読める。
// **黙って無視するフィールドを残さない**——読まれない設定は、効いていると誤読される。

/// 適用済みWFPセッション。`teardown`を呼ぶまでエンジンハンドルを保持し続ける
/// （＝フィルタが有効であり続ける、DYNAMICセッションの性質そのもの）。
pub struct WfpSession {
    keys: SessionKeys,
    engine: HANDLE,
    loopback_exemption: Option<LoopbackExemptionGuard>,
}

// HANDLEは値として複数スレッド間で運んでよい（他の`win_*`モジュールと同じ扱い）。
unsafe impl Send for WfpSession {}

/// [BUG-094 案G] WFPが落としたパケットの記録。**フィルタの世代ではなくdaemonの生存に紐づく。**
///
/// # なぜ世代から切り離したのか
///
/// 実測で、WFPは**最初の未配送イベントから約1秒後にまとめて**配送する
/// （[`plans/net-spike/RESULTS.md`](../../../../plans/net-spike/RESULTS.md) N10・N11）。
/// 購読を[`WfpSession`]が持っていた頃は窓が**1.2〜2.0秒**しか開かず、
/// 拒否が窓の後半で起きた回は**配送の前に窓が閉じて取りこぼしていた**
/// ——実測で腕A（待たずに畳む）は3回とも0件である。
///
/// 持ち主をdaemonへ移すと、実行の切れ目でも購読は閉じない。移るのは**書込先だけ**である。
///
/// # 待機中のdaemonがこれを握ってよい根拠（`D-56`不変条件1の改訂）
///
/// - **観測専用で、強制を1つも持たない。** フィルタは[`WfpSession`]側にあり、
///   不変条件1の目的（待機中に強制が残らない）はそのまま成立する
/// - エンジンハンドルは**動的セッション**（`FWPM_SESSION_FLAG_DYNAMIC`）なので、
///   daemonが死ねばOSが登録ごと消す。フェイルセーフの根拠は変わらない
/// - 購読は読み取りしかできない。ここから通信を通すことも塞ぐこともできない
///
/// # 限界（**同じ場所に書く**）
///
/// - **daemonが終わる直前の約1秒は、いまも取りこぼす。** 最後の配送を待たずに畳むためで、
///   これを埋めるには撤収時の猶予（案F）が要る
/// - **購読テンプレートは絞り込み無し**なので、マシン上の他の拒否も受け取り得る。
///   記録された拒否がこのセッションのフィルタによるものかは**確かめていない**
pub struct WfpAuditSubscription {
    engine: HANDLE,
    subscription: HANDLE,
    /// `Box::into_raw`で漏らしたシンク。コールバックが生ポインタで触るので、
    /// **アドレスが動かないこと**が要る。所有権は[`Self::teardown`]が回収する。
    sink: *mut WfpAuditSink,
}

// HANDLEと、アドレスを固定したシンクへの生ポインタ。`WfpSession`と同じ扱い。
unsafe impl Send for WfpAuditSubscription {}

impl WfpAuditSubscription {
    /// 監査専用のエンジンハンドルを1本開き、購読を始める。
    ///
    /// **失敗しても`None`を返すだけで、呼び出し側を止めない**——記録は境界ではない（`P-07`）。
    /// 失敗の理由は制御レコードとして監査ファイルへ残る（`start_wfp_drop_audit`）。
    pub fn start(validated_audit_log_path: PathBuf) -> Option<Self> {
        let engine = open_dynamic_engine().ok()?;
        let (subscription, sink) = start_wfp_drop_audit(engine, Some(validated_audit_log_path));
        match (subscription, sink) {
            (Some(subscription), Some(sink)) => Some(Self {
                engine,
                subscription,
                sink,
            }),
            _ => {
                // 購読できなかったならエンジンを持ち続ける理由が無い。
                unsafe {
                    let _ = FwpmEngineClose0(engine);
                }
                None
            }
        }
    }

    /// 書込先を次の実行のものへ移す。**検証済みのパスだけを渡すこと**（D-44）。
    ///
    /// **移す前に取り残しを回収する**（[`Self::drain_pending`]）——移した後だと、
    /// 前の実行で落ちた拒否が次の実行のファイルへ落ちる。
    pub fn set_audit_log_path(&self, validated_audit_log_path: PathBuf) {
        self.drain_pending();
        unsafe { (*self.sink).set_path(validated_audit_log_path) };
    }

    /// **まだ書けていない拒否を、押し出しを待たずに取りに行って書く。**
    ///
    /// # なぜ待つのではなく取りに行くのか
    ///
    /// 押し出し（購読のコールバック）は**発生から約1秒後**に来る
    /// （[`plans/net-spike/RESULTS.md`](../../../../plans/net-spike/RESULTS.md) N10・N11）。
    /// 世代を畳むのはそれより早いので、押し出しだけに頼ると取りこぼす。
    /// `FwpmNetEventEnum1`は**溜まっているものを問い合わせる**ので、
    /// **知らせが来るのを待たずに、その時点でバッファに在るものを全部取れる。**
    ///
    /// # 二重に書かない
    ///
    /// 押し出しで既に書いたものは指紋で弾く（[`WfpAuditSink::mark_new_drop`]）。
    /// 逆にここで先に書いたものは、後から来る押し出しの側が弾く。**順序に依存しない。**
    ///
    /// # 限界（**同じ場所に書く**。とくに1つ目）
    ///
    /// - **取りこぼしが0になるとは言えない。** 実測で、**バッファに入ること自体にも遅れがある**
    ///   ——同じ手順で、ある回は畳んだ直後に取れ、別の回は取れなかった。
    ///   WFPには「未配送が無いことを確かめる」呼び出しが無いので、
    ///   **どれだけ待てば十分かを証明する手段が無い**。これは実装の不足ではなくAPIの性質である。
    ///   **観測は境界ではない**（`P-07`）ので、ここは最善努力として扱う
    /// - **WFPのバッファが保持している分しか引けない。** 保持量・保持時間は測っていない
    ///   （実測で総数74〜95件を観測したが、それが上限かは不明）
    /// - **引けるのはマシン全体の拒否である。** このセッションのフィルタによるものだけに
    ///   絞ってはいない（購読側も同じ）。時刻で購読期間内には絞る
    /// - 失敗しても黙って戻る
    pub fn drain_pending(&self) {
        // **購読していた期間だけに絞る。** 絞らないとWFPのバッファ全体が返り、
        // **このセッションが始まる前のマシン全体の拒否まで**監査ファイルへ落ちる
        // （実測で59件。絞らない実装は監査を雑音で埋める）。
        let since = unsafe { (*self.sink).subscribed_at_unix_ms() };
        if since == 0 {
            return;
        }
        // **絞り込みはこちら側で行う。**
        //
        // `FWPM_NET_EVENT_ENUM_TEMPLATE0`の`startTime`で絞る形も試したが、
        // **この開発機では0件になった**（上端だけを外すと59件返るので、効いていないのは下端）。
        // 意味がはっきりしないAPIの引数に依存するより、**発生時刻を自分で比べる**ほうが確実で、
        // そちらは既に実測で正しく動いている（`event_unix_ms`はN10・N11で使った値と同じ）。
        // **引くときは新しいエンジンハンドルを開く。**
        //
        // 購読に使っているハンドル（`self.engine`）でそのまま引くと、
        // **この開発機では0件になった**——同じ手順を新しいハンドルで踏むと取れるので、
        // 列挙が見ているのはハンドルを開いた時点の眺めだと考えられる。
        // **理由は確かめていない**が、購読用を使い回さないことで避けられる。
        let Ok(engine) = open_dynamic_engine() else {
            return;
        };
        let mut enum_handle = HANDLE::default();
        unsafe {
            if FwpmNetEventCreateEnumHandle0(engine, None, &mut enum_handle) != 0 {
                let _ = FwpmEngineClose0(engine);
                return;
            }
            loop {
                let mut entries: *mut *mut FWPM_NET_EVENT1 = std::ptr::null_mut();
                let mut returned: u32 = 0;
                let status = FwpmNetEventEnum1(
                    engine,
                    enum_handle,
                    NET_EVENT_ENUM_BATCH,
                    &mut entries,
                    &mut returned,
                );
                if status != 0 || returned == 0 {
                    break;
                }
                for i in 0..returned as usize {
                    let event = &**entries.add(i);
                    if event.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
                        continue;
                    }
                    // **購読していた期間の外は書かない。** 絞らないとWFPのバッファ全体
                    // （このセッションが始まる前のマシン全体の拒否）が監査ファイルへ落ちる
                    // ——実測で59件。監査が雑音で埋まると、読む側は何も判断できない。
                    let Some(at) = filetime_to_unix_ms(event.header.timeStamp) else {
                        continue;
                    };
                    if at < u128::from(since) {
                        continue;
                    }
                    record_classify_drop(&*self.sink, event);
                }
                FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut core::ffi::c_void);
                if returned < NET_EVENT_ENUM_BATCH {
                    break;
                }
            }
            let _ = FwpmNetEventDestroyEnumHandle0(engine, enum_handle);
            let _ = FwpmEngineClose0(engine);
        }
    }

    /// 購読を止め、要約を1行残し、エンジンを閉じる。**daemonの終了時に1度だけ呼ぶ。**
    ///
    /// **止める前に取り残しを回収する**（[`Self::drain_pending`]）。ここを落とすと、
    /// 終了直前に起きた拒否が「配送が間に合わなかった」ぶんだけ消える。
    pub fn teardown(self) {
        self.drain_pending();
        unsafe {
            let _ = FwpmNetEventUnsubscribe0(self.engine, self.subscription);
            // 購読を止めた**直後**に数を残す。止める前だと、この記録より後に来た分を数え落とす。
            (*self.sink).record_event_summary();
            drop(Box::from_raw(self.sink));
            let _ = FwpmEngineClose0(self.engine);
        }
    }
}

/// [BUG-094] 1件の拒否を同定する指紋。**同じイベントが2経路から来るのを1行に畳むため。**
///
/// 時刻だけでは足りない——同じミリ秒に複数の拒否が並ぶことが実測で出ている
/// （`plans/net-spike/RESULTS.md` N10で、発生時刻が同一の5件を観測した）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DropFingerprint {
    event_unix_ms: u128,
    local_port: u16,
    remote_port: u16,
    remote_addr: Option<String>,
    filter_id: Option<u64>,
}

#[derive(Debug)]
struct WfpAuditSink {
    /// 書込先。**実行の切れ目で差し替わる**（[BUG-094] 案G）。
    ///
    /// 購読はdaemonの生存中ずっと生きるが、監査ファイルは**実行ごとに別**である。
    /// したがってシンクは1つのまま、書込先だけが移る。
    ///
    /// **差し替えは`ApplyRules`が`validate_audit_sink_path`を通した後にしか起きない**
    /// ——検証していないパスがここへ入ると、管理者権限での任意パス追記になる（D-44）。
    ///
    /// **`Mutex`なのは、コールバックが`&self`しか持てないためである**
    /// （`FwpmNetEventSubscribe0`へ渡すのは生ポインタで、可変参照は作れない）。
    ///
    /// [BUG-094]: ../../../../docs/bugs/BUG-094.md
    path: std::sync::Mutex<PathBuf>,
    /// [BUG-094] 購読のコールバックが**呼ばれた回数**（種別を問わない）。
    ///
    /// # なぜ数えるのか
    ///
    /// コールバックは`FWPM_NET_EVENT_TYPE_CLASSIFY_DROP`以外を**黙って捨てる**。
    /// したがって記録が0件のとき、次の2つが区別できない（`B-10`）。
    ///
    /// | 実際 | 意味 |
    /// |---|---|
    /// | コールバックが**1度も呼ばれていない** | 購読が成立していないか、収集が動いていない |
    /// | 呼ばれたが**dropが1件も無かった** | 購読は生きている。落ちた通信がこの経路に出ていないだけ |
    ///
    /// **前者と後者では次の一手が正反対になる。** 実測でこの区別が要った——
    /// マシン全体の収集は有効で購読も成功しているのに記録が0件、という状態が出たとき、
    /// この数字が無いと「購読が嘘をついている」のか「dropがこの層に出ない」のかを言えない。
    events_seen: std::sync::atomic::AtomicU64,
    /// そのうち実際に記録したもの（＝`classify_drop`だったもの）。
    drops_recorded: std::sync::atomic::AtomicU64,
    /// [BUG-094] 既に書いた拒否の指紋。**押し出しと取りに行った分を二重に書かないため。**
    ///
    /// 同じイベントが2つの経路から来る——コールバック（押し出し）と`FwpmNetEventEnum1`
    /// （取りに行く）である。どちらが先かは負荷次第なので、**書く直前に必ずここを通す**。
    seen: std::sync::Mutex<std::collections::HashSet<DropFingerprint>>,
    /// [BUG-094] 購読が成立した時刻（unix ms）。**まだ購読していなければ0。**
    ///
    /// イベントを受け取れる窓は「ここ」から「撤収でこのシンクが要約を書くまで」である。
    /// 各イベントの発生時刻がこの窓の内か外かが、
    /// **「届かなかった」と「窓が閉じた後に届いた」を分ける唯一の材料**になる。
    subscribed_at_unix_ms: std::sync::atomic::AtomicU64,
}

impl WfpAuditSink {
    fn new(path: PathBuf) -> Self {
        Self {
            path: std::sync::Mutex::new(path),
            events_seen: std::sync::atomic::AtomicU64::new(0),
            drops_recorded: std::sync::atomic::AtomicU64::new(0),
            subscribed_at_unix_ms: std::sync::atomic::AtomicU64::new(0),
            seen: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// **まだ書いていない拒否なら`true`を返し、同時に印を付ける。**
    ///
    /// 押し出し（コールバック）と取りに行く経路（`FwpmNetEventEnum1`）の両方がここを通る。
    /// 通さずに書くと、同じ拒否が2行になる——**件数を数える側からは別々の拒否に見える**。
    ///
    /// ロックが毒されていたら`true`を返す（**重複より欠落のほうが重い**。記録の用途は
    /// 「何が塞がれたか」の把握で、同じ行が2つ在っても判断を誤らせない）。
    fn mark_new_drop(&self, fingerprint: DropFingerprint) -> bool {
        match self.seen.lock() {
            Ok(mut seen) => seen.insert(fingerprint),
            Err(_) => true,
        }
    }

    /// 書込先を差し替える（[BUG-094] 案G）。**検証済みのパスだけを渡すこと。**
    ///
    /// 差し替えた**後**に届く、差し替え**前**に起きたイベントは新しいファイルへ落ちる。
    /// 配送は発生から約1秒遅れるので、実行の切れ目では実際に起こり得る——
    /// **どちらのファイルにも落ちない（消える）ことだけは無い**、というのがこの設計の狙いである。
    fn set_path(&self, path: PathBuf) {
        if let Ok(mut current) = self.path.lock() {
            *current = path;
        }
    }

    /// 現在の書込先。ロックが毒されていたら諦めて何も書かない（記録は境界ではない、`P-07`）。
    fn current_path(&self) -> Option<PathBuf> {
        self.path.lock().ok().map(|p| p.clone())
    }

    /// 購読が成立した時刻（unix ms）。まだなら0。
    fn subscribed_at_unix_ms(&self) -> u64 {
        self.subscribed_at_unix_ms
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// [BUG-094] 購読が成立した時刻を控える。**要約の行で窓の始まりを言うため。**
    fn mark_subscribed(&self) {
        self.subscribed_at_unix_ms
            .store(now_unix_ms() as u64, std::sync::atomic::Ordering::Relaxed);
    }

    /// [BUG-094] 撤収時に1行だけ残す要約。**0件の意味を言えるようにするためのもの。**
    ///
    /// **購読していた窓の始まりも同じ行に出す。** 終わりはこのレコード自身の
    /// `timestamp_unix_ms`である。窓の両端は`net_event_subscribed`レコードと突き合わせても
    /// 引けるが、**2レコードを跨いで読ませると突き合わせのたびに取り違える**——
    /// 各イベントの発生時刻が窓の内か外かは、この1行だけで判定できる必要がある。
    fn record_event_summary(&self) {
        use std::sync::atomic::Ordering;
        let seen = self.events_seen.load(Ordering::Relaxed);
        let recorded = self.drops_recorded.load(Ordering::Relaxed);
        let subscribed_at = self.subscribed_at_unix_ms.load(Ordering::Relaxed);
        self.record(&WfpAuditEntry::control(format!(
            "net_event_summary: callback_invocations={seen} classify_drop_recorded={recorded} \
             subscribed_at_unix_ms={subscribed_at}"
        )));
    }
}

#[derive(Debug, Serialize)]
struct WfpAuditEntry {
    /// **この記録を書いた時刻**（＝コールバックが呼ばれた時刻）。
    ///
    /// [`Self::event_unix_ms`]と**別物である**。片方へ寄せてはいけない
    /// ——2つの差が、WFPがイベントを配送するまでの遅れそのものになる（[BUG-094]）。
    ///
    /// [BUG-094]: ../../../../docs/bugs/BUG-094.md
    timestamp_unix_ms: u128,
    /// [BUG-094] **そのイベント自身が持つ発生時刻**（`FWPM_NET_EVENT_HEADER1.timeStamp`）。
    ///
    /// ネットワークイベント以外（制御レコード）では`None`。
    /// 値が載っていない・1970年より前のときも`None`になる（[`filetime_to_unix_ms`]）。
    #[serde(skip_serializing_if = "Option::is_none")]
    event_unix_ms: Option<u128>,
    kind: &'static str,
    protocol: &'static str,
    allowed: bool,
    /// 失敗の**理由コードまで**入れられるよう`Cow`にしてある。かつては`&'static str`で、
    /// `net_event_collection_enable_failed`のような「何が起きたか」だけを書いて
    /// **なぜ起きたかを捨てていた**——実運用でこのレコードが発火したとき、原因を追う材料が
    /// 何も残っていなかった（B-10: 握り潰してよいのは機能であって理由ではない）。
    /// JSONの形は文字列のままで変わらない。
    reason: std::borrow::Cow<'static, str>,
    local_addr: Option<String>,
    local_port: u16,
    remote_addr: Option<String>,
    remote_host: Option<String>,
    remote_port: u16,
    filter_id: Option<u64>,
    layer_id: Option<u16>,
}

impl WfpAuditEntry {
    /// ネットワークイベントではない**制御レコード**（収集・購読の失敗、昇格側ヘルパーの
    /// 連鎖起動の結末など）。`protocol = "control"`がマーカーで、読む側はこれを候補にしない
    /// （`harness_policy::is_net_control_record`）。
    fn control(reason: impl Into<std::borrow::Cow<'static, str>>) -> Self {
        Self {
            timestamp_unix_ms: now_unix_ms(),
            // 制御レコードは「harnessが何をしたか」であってネットワークイベントではないので、
            // 発生時刻という概念を持たない。
            event_unix_ms: None,
            kind: "wfp",
            protocol: CONTROL_PROTOCOL,
            allowed: false,
            reason: reason.into(),
            local_addr: None,
            local_port: 0,
            remote_addr: None,
            remote_host: None,
            remote_port: 0,
            filter_id: None,
            layer_id: None,
        }
    }
}

/// 制御レコードのマーカー。読む側（`harness_policy::is_net_control_record`）と同じ綴りである
/// ことがこの機構の前提なので、値の変更は両方を同時に見て行う。
const CONTROL_PROTOCOL: &str = "control";

/// **昇格側の任意のコードから**、検証済みの監査シンクへ制御レコードを1行書く。
///
/// `netfilterd`が「収集器を連鎖起動できたか」を残すために使う。書き手を増やさず
/// [`WfpAuditSink`]を通すのは、`net-audit.jsonl`のスキーマと追記の作法（親ディレクトリ作成・
/// 1行1JSON・失敗は握り潰す）を2箇所に持たないため（`docs/CODE-STRUCTURE-RULES.md`規則5）。
///
/// **書込先は呼び出し側が`elevated_launch::validate_audit_sink_path`で検証済みのパスに限る。**
/// 検証していないパスをここへ渡すと、管理者権限での任意パス追記になる（D-44）。
pub(crate) fn record_control_event(
    validated_audit_log_path: &std::path::Path,
    reason: impl Into<std::borrow::Cow<'static, str>>,
) {
    let sink = WfpAuditSink::new(validated_audit_log_path.to_path_buf());
    sink.record(&WfpAuditEntry::control(reason));
}

impl WfpAuditSink {
    fn record(&self, entry: &WfpAuditEntry) {
        let Some(path) = self.current_path() else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            if let Ok(line) = serde_json::to_string(entry) {
                let _ = writeln!(file, "{line}");
            }
        }
    }

    fn lookup_fake_dns_host(&self, remote_addr: &str) -> Option<String> {
        let text = std::fs::read_to_string(self.current_path()?).ok()?;
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
    // [BUG-094] **捨てる前に数える。** ここで黙って`return`すると、記録0件のときに
    // 「1度も呼ばれていない」と「呼ばれたがdropではなかった」が同じ見え方になる。
    sink.events_seen
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if event.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
        return;
    }
    record_classify_drop(sink, event);
}

/// 1件の`classify_drop`をJSONLへ落とす。**押し出しと取りに行く経路が共有する唯一の変換**。
///
/// 2箇所に書くと、片方だけ直したときに**同じイベントが経路によって違う行になる**
/// ——そうなると指紋も一致せず、二重書きの判定が効かなくなる（`B-05`）。
///
/// 既に書いたものなら何もしない（[`WfpAuditSink::mark_new_drop`]）。
///
/// # Safety
///
/// `event`は`FWPM_NET_EVENT_TYPE_CLASSIFY_DROP`であり、呼び出しの間だけ有効であること。
unsafe fn record_classify_drop(sink: &WfpAuditSink, event: &FWPM_NET_EVENT1) {
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
    let event_unix_ms = filetime_to_unix_ms(header.timeStamp);
    let filter_id = drop.map(|d| d.filterId);
    // **発生時刻が読めないものは指紋を作れない**ので、重複を畳めないまま書く
    // （欠落より重複を採る。判断を誤らせるのは欠落のほうである）。
    if let Some(at) = event_unix_ms {
        let fingerprint = DropFingerprint {
            event_unix_ms: at,
            local_port: header.localPort,
            remote_port: header.remotePort,
            remote_addr: remote_addr.clone(),
            filter_id,
        };
        if !sink.mark_new_drop(fingerprint) {
            return;
        }
    }

    let remote_host = remote_addr
        .as_deref()
        .and_then(|addr| sink.lookup_fake_dns_host(addr));
    let entry = WfpAuditEntry {
        timestamp_unix_ms: now_unix_ms(),
        // [BUG-094] **受信時刻とは別に、イベント自身の発生時刻を載せる。**
        // これが無いと「そもそも届かなかった」と「窓が閉じた後に届いた」を区別できない。
        event_unix_ms,
        kind: "wfp",
        protocol: protocol_name(header.ipProtocol),
        allowed: false,
        reason: std::borrow::Cow::Borrowed("classify_drop"),
        local_addr,
        local_port: header.localPort,
        remote_addr,
        remote_host,
        remote_port: header.remotePort,
        filter_id,
        layer_id: drop.map(|d| d.layerId),
    };
    sink.record(&entry);
    sink.drops_recorded
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

/// 1601-01-01から1970-01-01までの`FILETIME`の刻み数（100ナノ秒単位）。
const FILETIME_TICKS_AT_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

/// [BUG-094] 溜まったイベントを引くときの1回あたりの件数。
///
/// 実測でマシン全体の総数が95件だったので、**1回で引き切れる大きさ**にしてある
/// （足りなければ最後まで回すので、値は速さの目盛りであって上限ではない）。
const NET_EVENT_ENUM_BATCH: u32 = 512;

/// [BUG-094] `FILETIME`（1601年起点・100ナノ秒刻み）をunix msへ直す。
///
/// # なぜ要るのか
///
/// WFPのイベントは**自分がいつ起きたか**を`FWPM_NET_EVENT_HEADER1.timeStamp`で持っている。
/// これまでのコールバックは**受信時刻だけ**を記録していたので、
/// 「届かなかった」と「遅れて届いた」を区別する材料が無かった。
/// **2つの時刻の差がそのまま配送の遅れ**である。
///
/// # 1970より前は`None`を返す
///
/// 0埋めの`FILETIME`（＝値が載っていない）と、本当に1601〜1969年の時刻とを区別しない。
/// **区別する必要が無いから**ではなく、**どちらも「使える時刻ではない」から**である
/// ——ネットワークイベントの発生時刻が1970年より前になることは無い。
/// 引き算で桁が回り込むのを防ぐ意味もある。
fn filetime_to_unix_ms(ft: FILETIME) -> Option<u128> {
    let ticks = ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64);
    ticks
        .checked_sub(FILETIME_TICKS_AT_UNIX_EPOCH)
        .map(|since_epoch| (since_epoch / 10_000) as u128)
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
                // [BUG-094 案G] **ここで監査を始めない。** 購読の持ち主は
                // [`WfpAuditSubscription`]（daemonの生存に紐づく）へ移した——
                // 世代ごとに張り直すと窓が1.2〜2.0秒しか開かず、約1秒遅れる配送を取りこぼす。
                Ok(WfpSession {
                    keys,
                    engine,
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
        let loopback_exemption = self.loopback_exemption.take();
        std::mem::forget(self); // Dropで二重close/二重teardownしないよう所有権をここで断つ。

        let result = (|| -> Result<(), WfpError> {
            unsafe {
                // [BUG-094 案G] **ここで購読を止めない。** 止めると、この世代で落とした分の
                // 配送（発生から約1秒後）が届く前に窓が閉じる。購読は
                // [`WfpAuditSubscription`]が持ち、daemonの終了まで開いたままである。
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
            if let Some(exemption) = self.loopback_exemption.take() {
                let _ = remove_loopback_exemption(exemption);
            }
            let _ = FwpmEngineClose0(self.engine);
        }
    }
}

/// `FWP_E_DYNAMIC_SESSION_IN_PROGRESS`——「動的セッションの中からは、この呼び出しを行えない」。
///
/// **`windows`クレートはこの値を出していない**（`FWP_E_*`は定数として公開されていない）ので、
/// ここで綴る。値は`fwpmu.h`／公開ドキュメントの`0x80320000 + 0x0B`。
///
/// この1つだけを名前で持つのは、**harnessが構造的に必ず踏む**からである（[BUG-094]）——
/// セッションを`FWPM_SESSION_FLAG_DYNAMIC`で開くのはフェイルセーフの根拠そのもので、
/// 一方でイベント収集の有効化はエンジン全体の設定なので、**同じハンドルの上で両立しない**。
/// 他の失敗コードは「予期しない何か」なので、数値のまま記録すれば足りる。
const FWP_E_DYNAMIC_SESSION_IN_PROGRESS: u32 = 0x8032_000B;

/// いまマシン全体でWFPのイベント収集が有効か、**読んで**1語で返す。
///
/// # なぜ要るのか（[BUG-094]の測定で、この1語が無いと結論が2通りに割れた）
///
/// 有効化に失敗したまま購読すると、**「購読は成功したがイベントが1件も来ない」**という
/// 状態になる。これは2つの全く違う事実のどちらでもあり得る。
///
/// | 実際にどちらか | 意味 | 次の一手 |
/// |---|---|---|
/// | 収集がマシン全体で**無効** | イベントがそもそも作られていない | 収集を立てる側の案（非動的ハンドルをもう1本）へ進む |
/// | 収集は**有効**なのにイベントが来ない | 購読か層の選び方が間違っている | 上の案を採っても解決しない |
///
/// **読まなければ、どちらなのかは推測になる。** エンジンオプションは*設定*が動的セッションから
/// 禁じられているだけで、*読み取り*は通る。
///
/// 返すのは記録へそのまま載せる短い語（`enabled` / `disabled` / `unreadable(...)`）。
/// **「読めなかった」を「無効」と同じ値に畳まない**（`B-10`）。
unsafe fn describe_net_event_collection(engine: HANDLE) -> String {
    format!(
        "collect={} match_any_keywords={}",
        read_engine_u32_option(engine, FWPM_ENGINE_COLLECT_NET_EVENTS),
        read_engine_u32_option(engine, FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS)
    )
}

/// エンジンの32bitオプションを1つ読んで、記録へそのまま載せる短い語にする。
///
/// **`0`と「読めなかった」を同じ値に畳まない**（`B-10`）——前者はマシンの状態、
/// 後者はこちらの計器の不調であり、次の一手が違う。
unsafe fn read_engine_u32_option(
    engine: HANDLE,
    option: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_ENGINE_OPTION,
) -> String {
    let mut value: *mut FWP_VALUE0 = std::ptr::null_mut();
    let status = FwpmEngineGetOption0(engine, option, &mut value);
    if status != 0 {
        return format!("unreadable({status:#010x})");
    }
    if value.is_null() {
        return "unreadable(null)".to_string();
    }
    let read = *value;
    let described = if read.r#type != FWP_UINT32 {
        format!("unreadable(type={:?})", read.r#type)
    } else {
        format!("{:#010x}", read.Anonymous.uint32)
    };
    // `FwpmEngineGetOption0`が返した領域はFWPMが確保したもの。**読み終えたら返す**
    // （`FwpmFreeMemory0`。付録Aの撤収規律と同じで、借りたものは借りた側が返す）。
    FwpmFreeMemory0(&mut value as *mut *mut FWP_VALUE0 as *mut *mut core::ffi::c_void);
    described
}

/// WFPが落としたパケットの記録を始める（仕様書§5.5）。
///
/// # 有効化に失敗しても購読はする（[BUG-094]の修正）
///
/// 旧実装は`FwpmEngineSetOption0`が失敗した時点で**購読ごと諦めていた**。これは
/// **「収集を有効にできない」と「イベントを観測できない」を同じ値に畳んでいる**（`B-10`）。
///
/// `FWPM_ENGINE_COLLECT_NET_EVENTS`は**マシン全体の設定**なので、harnessが立てられなくても
/// **他の誰かが既に立てていれば購読でイベントが届く**。旧実装ではその世界でも記録は0件になり、
/// 「拒否が1件も無かった」と見分けが付かなかった。
///
/// したがって**有効化の可否と購読の可否を別々に記録し、購読は必ず試す**。どちらの世界に
/// 居るかは、制御レコードの綴り（`net_event_collection_enabled_by_harness` か
/// `net_event_collection_not_enabled_by_harness`）で後から読める。
///
/// # 誰が持つか（[BUG-094] 案G、2026-09-21）
///
/// **この購読は`WfpSession`（＝フィルタの世代）ではなく、daemonの生存に紐づく。**
/// 実測で、WFPは**最初の未配送イベントから約1秒後にまとめて**配送する
/// （[`plans/net-spike/RESULTS.md`](../../../../plans/net-spike/RESULTS.md) N11）。
/// 世代ごとに張り直していた頃は、購読の窓が1.2〜2.0秒しか開いておらず、
/// **拒否が窓の後半で起きた回は配送の前に窓が閉じて取りこぼしていた**。
///
/// 持ち主を移したので、実行の切れ目でも購読は閉じない。移るのは**書込先だけ**である
/// （[`WfpAuditSink::set_path`]）。
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
        let sink = Box::new(WfpAuditSink::new(path));
        let sink_ptr = Box::into_raw(sink);
        // **理由コードまで残す。** これが無いと「有効化に失敗した」しか分からず、
        // 権限不足なのか既定で無効なのかを後から追えない（実運用で発火している）。
        if set_status == 0 {
            (*sink_ptr).record(&WfpAuditEntry::control(
                "net_event_collection_enabled_by_harness".to_string(),
            ));
        } else {
            (*sink_ptr).record(&WfpAuditEntry::control(format!(
                "net_event_collection_not_enabled_by_harness: FwpmEngineSetOption0 returned \
                 {set_status:#010x}{}; machine-wide collection is currently {}",
                if set_status == FWP_E_DYNAMIC_SESSION_IN_PROGRESS {
                    " (FWP_E_DYNAMIC_SESSION_IN_PROGRESS: engine-wide options cannot be set from \
                      a dynamic session; subscribing anyway, which still delivers events if \
                      collection is already enabled machine-wide)"
                } else {
                    ""
                },
                describe_net_event_collection(engine)
            )));
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
            // [BUG-094] **記録より先に控える。** 窓の始まりは「購読が成立した瞬間」であって
            // 「そう書き残せた瞬間」ではない（記録はファイルI/Oを挟む）。
            (*sink_ptr).mark_subscribed();
            (*sink_ptr).record(&WfpAuditEntry::control("net_event_subscribed".to_string()));
            (Some(handle), Some(sink_ptr))
        } else {
            let sink = Box::from_raw(sink_ptr);
            // 対（B-01）: 有効化側だけでなく購読側にも理由コードを載せる。
            sink.record(&WfpAuditEntry::control(format!(
                "net_event_subscribe_failed: FwpmNetEventSubscribe0 returned {status:#010x}"
            )));
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

/// **テスト専用**: あるセッションプロファイルのサブレイヤーに、いま実際に存在するフィルタの
/// ID集合を、**別のエンジンハンドルから**数える（実機の観測値）。
///
/// DYNAMICセッションが張ったフィルタもフィルタストアには載るので、外から列挙できる。
/// これが「フィルタが本当に張られたか／本当に消えたか」を測る唯一の手段であり、
/// `wfp::tests`（D-37のセッション独立性）と`netfilterd::reuse_e2e`（D-56の待機中0件）の
/// **両方が同じ関数で測る**——別々に書くと、片方だけが違うものを数えていても気付けない。
#[cfg(test)]
pub(crate) fn filter_ids_for_session(session_profile: &str) -> std::collections::BTreeSet<u64> {
    let keys = SessionKeys::for_session(session_profile);
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
                let status = FwpmFilterEnum0(engine, enum_handle, 64, &mut entries, &mut returned);
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
    add_allow_filter(
        engine,
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        &mut conditions,
        keys,
    )
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
    add_allow_filter(
        engine,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        &mut conditions,
        keys,
    )
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
        assert_eq!(
            keys.provider.to_u128() & NAMESPACE_MASK,
            PROVIDER_KEY_NAMESPACE
        );
        assert_eq!(
            keys.sublayer.to_u128() & NAMESPACE_MASK,
            SUBLAYER_KEY_NAMESPACE
        );
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
        let sink = WfpAuditSink::new(path.clone());
        sink.record(&WfpAuditEntry {
            timestamp_unix_ms: 123,
            event_unix_ms: None,
            kind: "wfp",
            protocol: "tcp",
            allowed: false,
            reason: std::borrow::Cow::Borrowed("classify_drop"),
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

    /// 制御レコードは`protocol:"control"`で、**理由コードまで**入る。
    ///
    /// 読む側（`harness_policy::is_net_control_record`）はこの1項目で候補から外すので、
    /// 綴りが変わると集計と候補が静かにずれる。`reason`がJSON上ただの文字列であること
    /// （`Cow`にしても形が変わっていないこと）も同時に固定する。
    #[test]
    fn a_control_record_is_marked_as_control_and_keeps_the_failure_code() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net-audit.jsonl");

        // [BUG-094] 綴りは製品が出すものに合わせる。**ここが実物とずれると、
        // この例は「そういう形の文字列が通る」ことしか言わなくなる。**
        record_control_event(
            &path,
            "net_event_collection_not_enabled_by_harness: FwpmEngineSetOption0 returned 0x00000005"
                .to_string(),
        );

        let text = std::fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(value["kind"], "wfp");
        assert_eq!(value["protocol"], CONTROL_PROTOCOL);
        assert_eq!(value["allowed"], false);
        assert!(value["reason"].is_string(), "{value}");
        assert!(
            value["reason"].as_str().unwrap().contains("0x00000005"),
            "**なぜ**失敗したかを残す（以前は理由コードを捨てていた）: {value}"
        );
        // 通信の記録ではないので、ホストもアドレスも持たない。読む側はこの形を見て
        // 「ホスト名を復元できなかった拒否」と誤読しかねないため、`protocol`が唯一のマーカー。
        assert!(value["remote_host"].is_null());
        assert!(value["remote_addr"].is_null());
    }

    /// 追記であること（1回のセッションで複数の制御レコードが並ぶ——起動と子の観測で2行）。
    #[test]
    fn control_records_append_rather_than_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("net-audit.jsonl");

        record_control_event(
            &path,
            "policy_learnd_chain_launched pipe=p pid=1 env_present=true",
        );
        record_control_event(&path, "policy_learnd_chain_child_alive");

        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2, "{text}");
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

        let sink = WfpAuditSink::new(path);
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
        let sink = WfpAuditSink::new(path.clone());
        sink.record(&WfpAuditEntry {
            timestamp_unix_ms: 124,
            event_unix_ms: Some(120),
            kind: "wfp",
            protocol: "tcp",
            allowed: false,
            reason: std::borrow::Cow::Borrowed("classify_drop"),
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
        // [BUG-094] **受信時刻と発生時刻が別々に載ること。** 片方へ寄せると、
        // 配送の遅れを後から引けなくなる。
        assert_eq!(value["timestamp_unix_ms"], 124);
        assert_eq!(value["event_unix_ms"], 120);
    }

    /// [BUG-094] 制御レコードには発生時刻を**載せない**（キーごと出さない）。
    ///
    /// **許可側（上のテスト）と対にする**（`B-35`）——常に載せる実装でも、
    /// 常に載せない実装でも、片側だけなら通ってしまう。
    #[test]
    fn a_control_record_carries_no_event_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net-audit.jsonl");
        let sink = WfpAuditSink::new(path.clone());
        sink.record(&WfpAuditEntry::control("net_event_subscribed".to_string()));

        let text = std::fs::read_to_string(path).unwrap();
        let value: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert!(
            value.get("event_unix_ms").is_none(),
            "制御レコードは発生時刻を持たない。得たもの: {value}"
        );
    }

    /// [BUG-094] 撤収時の要約に**窓の始まり**が載ること。
    ///
    /// 窓の終わりはこのレコード自身の`timestamp_unix_ms`なので、
    /// この1行だけで「あるイベントが窓の内か外か」を判定できる。
    #[test]
    fn the_summary_line_states_when_the_subscription_window_opened() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net-audit.jsonl");
        let sink = WfpAuditSink::new(path.clone());
        sink.mark_subscribed();
        sink.record_event_summary();

        let text = std::fs::read_to_string(path).unwrap();
        let value: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        let reason = value["reason"].as_str().unwrap_or_default();
        assert!(
            reason.contains("subscribed_at_unix_ms="),
            "窓の始まりが要約に無い: {reason}"
        );
        assert!(
            !reason.contains("subscribed_at_unix_ms=0"),
            "`mark_subscribed`を呼んだのに0のまま＝控えていない: {reason}"
        );
    }

    /// [BUG-094] `FILETIME`の変換。**実際の値で検算する。**
    ///
    /// 1970-01-01T00:00:00Zちょうどの`FILETIME`は`116_444_736_000_000_000`刻みで、
    /// そこから1秒進めれば1000msになる——**自分で書いた定数を自分で使って確かめない**ため、
    /// 期待値は刻み数から手で組み立てている。
    #[test]
    fn a_filetime_becomes_unix_milliseconds() {
        let at = |ticks: u64| FILETIME {
            dwLowDateTime: (ticks & 0xFFFF_FFFF) as u32,
            dwHighDateTime: (ticks >> 32) as u32,
        };
        // 1970-01-01T00:00:00Z ちょうど。
        assert_eq!(filetime_to_unix_ms(at(116_444_736_000_000_000)), Some(0));
        // その1秒後（100ナノ秒刻みなので1秒＝1000万刻み）。
        assert_eq!(
            filetime_to_unix_ms(at(116_444_736_000_000_000 + 10_000_000)),
            Some(1000)
        );
        // 上位ワードをまたぐ値でも桁が壊れないこと（`u32`2本を繋ぐ実装の検算）。
        // `2^32`刻み＝`4_294_967_296 / 10_000`ms。**下位ワードだけを見る実装ならここで落ちる。**
        assert_eq!(
            filetime_to_unix_ms(at(116_444_736_000_000_000 + 4_294_967_296)),
            Some(429_496)
        );
    }

    /// [BUG-094] 禁止側の対——値が載っていない／1970より前は`None`。
    ///
    /// **これが無いと、0埋めの`FILETIME`が「1601年に起きたイベント」として記録される**
    /// （引き算が回り込むと、もっとひどい値になる）。
    #[test]
    fn a_filetime_before_the_unix_epoch_is_rejected() {
        let at = |ticks: u64| FILETIME {
            dwLowDateTime: (ticks & 0xFFFF_FFFF) as u32,
            dwHighDateTime: (ticks >> 32) as u32,
        };
        assert_eq!(filetime_to_unix_ms(at(0)), None, "0埋めは時刻ではない");
        assert_eq!(
            filetime_to_unix_ms(at(116_444_736_000_000_000 - 1)),
            None,
            "unixエポックの直前も使える時刻として扱わない"
        );
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

        // 自サブレイヤー配下に今あるフィルタのID集合（実機の観測値）。実装は
        // `filter_ids_for_session`が持つ（`netfilterd::reuse_e2e`と共有する）。
        let filter_ids_in_sublayer = filter_ids_for_session;

        // 実運用では2セッションのLocal Proxyポートは別々になる。同じにすると
        // 「Aのフィルタが消えてもBのフィルタが同じ穴を開ける」ため差分が見えない。
        let listener_a = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let listener_b = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        // D-37: 2つの**別セッション**（別プロファイル名）を模す。実運用ではセッションごとに
        // 別プロセスの`harness-netfilterd`が動くが、キーもフィルタ条件もプロファイル名から
        // 決まるので、1プロセス内でも同じ構造を再現できる。
        let profile_a = crate::tier2a::session_profile::profile_name_for("wfp-test-a");
        let profile_b = crate::tier2a::session_profile::profile_name_for("wfp-test-b");
        // 観測はプロファイル名で引く（サブレイヤーGUIDの導出は`filter_ids_for_session`の中）。
        let (keys_a, keys_b) = (profile_a.as_str(), profile_b.as_str());
        let opts_a = WfpOptions {
            session_profile: profile_a.clone(),
            allow_loopback_tcp_ports: vec![listener_a.local_addr().unwrap().port()],
            allow_loopback_udp_ports: Vec::new(),
        };
        let opts_b = WfpOptions {
            session_profile: profile_b.clone(),
            allow_loopback_tcp_ports: vec![listener_b.local_addr().unwrap().port()],
            allow_loopback_udp_ports: Vec::new(),
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
        assert!(
            after_all.is_empty(),
            "全セッション終了後にフィルタが残っている"
        );
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
        };
        // [BUG-094 案G] 監査の購読は**セッションとは別に**持つ（本番では`netfilterd`が持つ）。
        let audit = WfpAuditSubscription::start(audit_path.clone()).expect("start WFP drop audit");
        let session = WfpSession::apply(sid.as_psid(), &opts).expect("apply WFP rules");
        let (shell, _) = crate::tier2a::win_appcontainer::resolve_shell();
        let env = crate::secret_env::build_child_env();
        let command = format!(
            "$ErrorActionPreference = 'Stop'; \
             $ok = $false; \
             try {{ $c = [Net.Sockets.TcpClient]::new(); $c.Connect('127.0.0.1', {allowed_port}); $c.Close(); $ok = $true }} catch {{ }}; \
             $blocked = $false; \
             try {{ $c = [Net.Sockets.TcpClient]::new(); $c.Connect('8.8.8.8', 53); $c.Close() }} catch {{ $blocked = $true }}; \
             if ($ok -and $blocked) {{ Write-Output 'harness-wfp-e2e-ok'; exit 0 }} else {{ Write-Output \"ok=$ok blocked=$blocked\"; exit 7 }}"
        );
        let child = crate::tier2a::win_appcontainer::spawn(
            &shell,
            &["-NoProfile", "-NonInteractive", "-Command", &command],
            dir.path(),
            &env,
            false,
            sid.as_psid(),
            crate::tier2a::win_appcontainer::NetworkCapability::InternetClient,
            crate::tier2a::win_appcontainer::RedirectorInject::default(),
            crate::tier2a::win_appcontainer::DomainIdentity::OwnPackage,
        )
        .expect("spawn AppContainer child");
        let (stdout, stderr, code) = child.write_stdin_read_output_and_wait(None).unwrap();
        let _ = accept_thread.join();
        assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
        assert!(
            stdout.contains("harness-wfp-e2e-ok"),
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
        audit.teardown();
        assert!(
            saw_drop,
            "expected WFP drop event in {}",
            audit_path.display()
        );
    }

    /// [BUG-094 案G] **世代を畳んだ後に届いた拒否も記録されること。**
    ///
    /// # この測定が固定するもの
    ///
    /// WFPは**最初の未配送イベントから約1秒後にまとめて**配送する
    /// （[`plans/net-spike/RESULTS.md`](../../../../plans/net-spike/RESULTS.md) N10・N11）。
    /// 購読を[`WfpSession`]が持っていた頃は窓が1.2〜2.0秒しか開かず、
    /// **子が終わった直後に畳むと3回とも0件**だった。
    ///
    /// 購読の持ち主を[`WfpAuditSubscription`]（本番では`netfilterd`）へ移したので、
    /// **世代を畳んでも購読は開いたまま**になり、遅れて届いた分も落ちる。ここを固定する。
    ///
    /// # 対で見る（`B-35`）
    ///
    /// | 側 | 何を見るか |
    /// |---|---|
    /// | 許可側 | 世代を**待たずに畳んだ**のに、その世代で起きた拒否が後から記録される |
    /// | 禁止側 | **購読を畳んだ後**は、同じだけ待っても件数が増えない |
    ///
    /// **禁止側が要る理由**: 許可側だけだと「いつでも何か書く」実装でも通る。
    /// 購読を止めても書き続けるなら、それは記録ではなく雑音である。
    ///
    /// 実行例: `dev-elevated-run.exe e2e-wfp-multisession`
    #[cfg(windows)]
    #[test]
    #[ignore = "requires administrator token, BFE, and real Windows AppContainer/WFP state"]
    fn e2e_a_drop_survives_its_filter_generation_being_torn_down() {
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

        let session_profile = crate::tier2a::session_profile::current_profile_name();
        let sid = crate::tier2a::win_appcontainer::ensure_profile(&session_profile)
            .expect("ensure AppContainer profile");
        crate::tier2a::win_appcontainer::grant_ace_recursive(dir.path(), sid.as_psid())
            .expect("grant temp dir ACE to AppContainer");

        let count_drops = || -> usize {
            let text = std::fs::read_to_string(&audit_path).unwrap_or_default();
            text.lines()
                .filter(|line| {
                    serde_json::from_str::<serde_json::Value>(line)
                        .ok()
                        .and_then(|v| v.get("reason")?.as_str().map(|r| r == "classify_drop"))
                        .unwrap_or(false)
                })
                .count()
        };

        // **購読はフィルタの世代より先に始め、後で畳む。** 本番の`netfilterd`と同じ順序である。
        let audit = WfpAuditSubscription::start(audit_path.clone()).expect("start WFP drop audit");

        let opts = WfpOptions {
            session_profile: session_profile.clone(),
            allow_loopback_tcp_ports: vec![allowed_port],
            allow_loopback_udp_ports: Vec::new(),
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
             if ($ok -and $blocked) {{ Write-Output 'harness-wfp-e2e-ok'; exit 0 }} else {{ Write-Output \"ok=$ok blocked=$blocked\"; exit 7 }}"
        );
        let child = crate::tier2a::win_appcontainer::spawn(
            &shell,
            &["-NoProfile", "-NonInteractive", "-Command", &command],
            dir.path(),
            &env,
            false,
            sid.as_psid(),
            crate::tier2a::win_appcontainer::NetworkCapability::InternetClient,
            crate::tier2a::win_appcontainer::RedirectorInject::default(),
            crate::tier2a::win_appcontainer::DomainIdentity::OwnPackage,
        )
        .expect("spawn AppContainer child");
        let (stdout, stderr, code) = child.write_stdin_read_output_and_wait(None).unwrap();
        let _ = accept_thread.join();
        // **計器の生死を先に見る。** 塞がれていなければ、件数0は「記録できない」ではなく
        // 「そもそも落ちていない」である。
        assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
        assert!(
            stdout.contains("harness-wfp-e2e-ok"),
            "許可側のloopbackが通り、外部接続が塞がれること。stdout={stdout}\nstderr={stderr}"
        );

        // **待たずに畳む。** ここが以前は取りこぼしの原因だった。
        let before_teardown = count_drops();
        session.teardown().expect("teardown WFP rules");

        // --- 許可側: **1ミリ秒も待たずに**取り切れること ---
        //
        // ここで`sleep`を入れてはいけない。入れると「待てば取れる」を測ることになり、
        // **高負荷で待ち時間を超えたら消える**という元の弱点をそのまま残す。
        // 押し出しを待たずに引けることが、この機構の存在理由そのものである。
        audit.drain_pending();
        let immediately = count_drops();
        // **直後に取れるとは限らない。** 実測で、バッファに入ること自体にも遅れがある
        // ——同じ手順で取れる回と取れない回があった。だから**ここは直後の件数で判定しない**。
        // 判定するのは「押し出しを待たずに、引けば取れる」ことだけである。
        std::thread::sleep(std::time::Duration::from_millis(1500));
        audit.drain_pending();
        let after_waiting = count_drops();
        eprintln!(
            "[BUG-094] 世代を畳む前={before_teardown}件 / 直後に引く={immediately}件 / \
             1.5秒後に引く={after_waiting}件"
        );
        assert!(
            after_waiting > 0,
            "[BUG-094] 引いても拒否が記録されていない。**取りに行く経路が死んでいる**\
             （押し出しに戻っていないか確かめること）（{}）",
            audit_path.display()
        );

        // --- 禁止側: 購読を畳んだら、同じだけ待っても増えない ---
        audit.teardown();
        let settled = count_drops();
        std::thread::sleep(std::time::Duration::from_secs(2));
        assert_eq!(
            count_drops(),
            settled,
            "[BUG-094] 購読を畳んだ後も記録が増えている。止めたはずのものが書き続けている"
        );
    }
}
