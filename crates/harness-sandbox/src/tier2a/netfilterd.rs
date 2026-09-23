//! WFP専用の常駐デーモン制御（Layer2、`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`
//! 付録C「アーキテクチャ決定」参照）。
//!
//! `harness-privhelper`（`crate::tier2a::privhelper`）とは意図的に別プロセス・別モジュールにしている。
//! `FWPM_SESSION_FLAG_DYNAMIC`のフィルタは、エンジンハンドルを保持するプロセスが生きている
//! 間だけ有効（`crate::tier2a::wfp`参照）であり、これは「1起動=1操作で即終了、常駐しない」という
//! `harness-privhelper`の設計原則（D-16）と本質的に相容れない。そのため`harness-netfilterd`は
//! **harnessセッション全体**（`harness`本体プロセス1回の起動、複数の`run_shell`呼び出しに
//! またがる）の生存期間中だけ昇格トークンのまま常駐する専用バイナリとして新設した。
//! セッションにつき最大1回だけ起動する session-scoped singleton として扱う（UAC起動回数の
//! 最小化、`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`付録D）。
//!
//! IPCの配線（named pipe + JSON、`user_only_security_attributes`、`ShellExecuteExW runas`
//! 昇格起動、タイムアウト付きoverlapped I/O）自体は`privhelper.rs`と同じパターンを踏襲する
//! （要求ライフサイクルが異なる——1往復で終わるか、2回目のメッセージを常駐待ちするか——ため
//! 汎用化はせず複製する）。
//!
//! **プロトコル（D-56）**: 接続してから`Teardown`（またはパイプ切断）まで、**要求を受け続ける**。
//!
//! ```text
//! 接続 → loop {
//!     ApplyRules → 現世代のフィルタを畳む → 検証し直す → 適用 → Applied
//!     ClearRules → 現世代のフィルタを畳む → Cleared      ← 実行の切れ目で送る
//!     Teardown   → 現世代のフィルタを畳む → TornDown → 終了
//!     壊れたフレーム → Err → 終了（プロトコル違反）
//!     パイプ切断・タイムアウト → 畳んで終了（応答は送らない）
//! }
//! ```
//!
//! harness本体（`crates/harness-cli/src/cli/startup/run_agent.rs`）は`ApplyRules`を1回だけ送り、
//! セッション終了時に`Teardown`を送る——つまり**旧来の1往復はこのループの特殊形**であって、
//! 本体側の呼び方は何も変わっていない。ループが要るのはポリシーエディタ（`harness-policy-editor`）で、
//! 1回の起動で記録を何度も走らせるため、実行のたびにdaemonを起こし直すとそのたびUACが出る。
//!
//! **`ClearRules`が別のオペコードとして要る理由**: 「許可ポートが空の`ApplyRules`」では代用できない。
//! `WfpSession::apply`はTCP/UDPどちらのloopback許可も空なら`NoAddressesResolved`で即座に返る
//! （`wfp.rs`冒頭のガード＝親から見ればfail-closed）ので、それは「畳む」ではなく「失敗」になる。
//!
//! **待機中はフィルタを持たない**（D-56の不変条件1）。実行の切れ目で`ClearRules`を受けて畳むため、
//! 待機中のdaemonが握っているのはパイプのハンドルと昇格トークンだけである。畳んでよいのは、
//! Tier2aの子が`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`のJob Objectに入っており、`Exited`の直後に
//! ジョブが閉じられて子孫ごと終了するため（`crate::win_common::stream_child_output`／
//! `create_job_object`）——**待機中に対象セッションSIDを持つプロセスは1つも残らない**。
//!
//! **旧仕様からの意図的な削除**: かつては「1件目が`ApplyRules`以外ならプロトコル違反として終了」
//! という規則があったが、ループ化で意味を失ったため削除した。1件目の`Teardown`は
//! 「何も適用していない世代を畳んで終了する」という正常な要求として`TornDown`を返す
//! （`the_first_message_may_be_a_teardown`が固定している）。
//!
//! **2つの起動シナリオ**（付録D）: (A) `--fs-allow`のシステム保護パス等で特権分離ヘルパー
//! （`privhelper`）が既に昇格起動される場合、そのヘルパーが自分の昇格済みトークンを引き継いで
//! `CreateProcessW`（`runas`は使わない）でdaemonを連鎖起動する（[`NetfilterHandle::connect_after_chain_launch`]）。
//! (B) それ以外の場合、`harness`本体が直接`runas`で起動する（[`NetfilterHandle::start`]）。
//! いずれもUACは最大1回に抑えられる。
//!
//! **フェイルセーフ**: 親（本体）がクラッシュ等でパイプを閉じずに消えた場合、daemon側の
//! 2回目の`ReadFile`が`ERROR_BROKEN_PIPE`で失敗する。これを「親死亡」のシグナルとして扱い、
//! 同じteardown経路を実行してから終了する。daemonプロセス自体が強制終了された場合の最終防波堤は
//! 引き続き`FWPM_SESSION_FLAG_DYNAMIC`のBFE自動削除に委ねる（`wfp::WfpSession`のDrop実装）。

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_CANCELLED, HANDLE, HLOCAL, WAIT_OBJECT_0,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows::Win32::System::Threading::WaitForSingleObject;
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

use crate::tier2a::wfp::{WfpOptions, WfpSession};
use crate::tier2a::win_appcontainer;
use crate::win_common::wide;

/// daemonへ投入させるネットワークポリシー一式（`ApplyRules`のペイロード）。
///
/// この3項目は`NetfilterHandle::start`→`connect_and_apply`、および
/// `NetfilterHandle::connect_after_chain_launch`→`connect_and_apply`という経路を、
/// 常に「まとめて1つ」として貫通する。
///
/// **serde表現は`ApplyRules`のstruct variantだった頃とバイト等価**（外部タグ付き列挙型の
/// newtype variantは、内側の構造体をそのままタグの値として書くため）。`netfilterd.exe`は
/// 別プロセスとしてこのJSONを読むので、表現の不変は
/// `apply_rules_request_json_wire_format_is_stable`が固定している。旧IPC互換のためだけに
/// 存在し実体を持たなかった`allow_domains`・`allow_loopback`・`allow_loopback_ports`・
/// `allow_direct_dns`はR-02で削除した（`docs/STATUS.md`参照）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetfilterPolicy {
    /// D-37: WFPフィルタを条件付けるAppContainerのセッションプロファイル名。
    ///
    /// **SIDではなく名前を運ぶ**（privhelperと同じ方針）。昇格側は
    /// `mcp_profile::is_harness_profile_name`で形を検証してから`ensure_profile`で
    /// 導出するので、任意のAppContainerへフィルタを張らせることはできない。
    #[serde(default)]
    pub session_profile: String,
    #[serde(default)]
    pub allow_loopback_tcp_ports: Vec<u16>,
    #[serde(default)]
    pub allow_loopback_udp_ports: Vec<u16>,
    #[serde(default)]
    pub audit_log_path: Option<PathBuf>,
    /// D-38（M15.5）: MCPサーバごとの出口ポリシー。**追加は必ず末尾へ**——このJSONは
    /// 別プロセス（`harness-netfilterd.exe`）が読むワイヤ形式で、
    /// `apply_rules_request_json_wire_format_is_stable`が表現を固定している。
    ///
    /// サーバごとに別のpackage SIDを持つので（`plans/DESIGN-MCP.md` §3.1）、
    /// **サーバ別の宛先allowlistがWFP＋専用プロキシの組で自然に書ける**（§3.2）。
    /// 各エントリはそのサーバ専用プロキシのloopbackポートだけを許可する。
    #[serde(default)]
    pub mcp_profiles: Vec<McpNetfilterPolicy>,
    /// workspaceルート。**`audit_log_path`を昇格側で検証するためだけに運ぶ**（M15.7 / D-44）。
    ///
    /// これが無いと、非昇格の親が渡した任意`PathBuf`へ昇格daemonが追記することになり、
    /// **管理者権限での任意パス追記プリミティブ**になる。基準を親から受け取る点は変わらないが、
    /// 「`<workspace_root>/.harness/sandbox/`配下であること」という制約は受信側で強制できるので、
    /// 親が嘘の基準を送っても書ける先はその嘘の基準の配下に限られる——`C:\Windows`のような
    /// 任意の場所へは向けられない（`crate::elevated_launch::validate_audit_sink_path`が
    /// reparse pointも解決してから再確認する）。
    ///
    /// **追加は必ず末尾へ**（`apply_rules_request_json_wire_format_is_stable`が表現を固定している）。
    #[serde(default)]
    pub workspace_root: Option<PathBuf>,
    /// M15.7: OS監査収集器（`harness-policy-learnd.exe`）を、このdaemonの昇格トークンのまま
    /// 連鎖起動する先のパイプ名。`None`なら連鎖起動しない。
    ///
    /// **これがあると`--policy-learn`で追加のUACが出ない。** 無い場合、非特権側は
    /// `policy_learnd::client::start`（`runas`）へフォールバックしUACが1回増える
    /// ——機能は同じで、増えるのはプロンプトの回数だけ（`privhelper`→`netfilterd`の
    /// シナリオ(A)/(B)と同じ構図）。
    ///
    /// **追加は必ず末尾へ**（`apply_rules_request_json_wire_format_is_stable`が表現を固定している）。
    #[serde(default)]
    pub chain_launch_policy_learnd: Option<String>,
}

/// 1つのMCPサーバに対する出口ポリシー（D-38）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpNetfilterPolicy {
    /// `harness.mcp.<session-token>.<server-id>`。昇格側が形を検証してからSIDを導出する。
    #[serde(default)]
    pub profile: String,
    /// このサーバが到達してよいloopbackのTCPポート（＝このサーバ専用プロキシの待受ポート）。
    /// **空なら外向き通信は一切できない**（capability自体も付かないので二重にdenyされる）。
    #[serde(default)]
    pub allow_loopback_tcp_ports: Vec<u16>,
    #[serde(default)]
    pub allow_loopback_udp_ports: Vec<u16>,
}

/// 親→daemonへ送るメッセージ。`Teardown`（またはパイプ切断）まで何度でも送れる
/// （D-56、モジュールdocのプロトコル図を参照）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetfilterRequest {
    ApplyRules(NetfilterPolicy),
    /// 現世代のフィルタを畳むが、daemonは待機を続ける（実行の切れ目で送る）。
    ///
    /// **「許可ポートが空の`ApplyRules`」では代用できない**——それは`WfpSession::apply`の
    /// `NoAddressesResolved`ガードに当たり「畳む」ではなく「失敗」になる（モジュールdoc参照）。
    ClearRules,
    /// D-60: **常駐している昇格トークンのまま、固定名の兄弟ヘルパーを連鎖起動する。**
    ///
    /// 運ぶのは親が用意したパイプ名だけで、**起動する実行ファイル名は昇格側が持つ固定値**
    /// （親から任意パスを受け取らない）。netfilterdはヘルパーの仕事の中身を知らず、
    /// 親は自分のパイプでそのヘルパーと通常のハンドシェイクをする。
    ///
    /// これが要るのは、`harness-policy-editor`が「記録→承認→パス2」の対話ループで
    /// **後から**特権操作を必要とするためである。そのときnetfilterdは既に生きているので、
    /// `privhelper`は連鎖元を持たず単独で`runas`してUACを1回増やしていた（D-60の経緯）。
    ChainLaunchHelper {
        helper: SiblingHelper,
        pipe_name: String,
    },
    /// **起こすだけで何も適用しない**（起動時前倒し）。daemonはWFPへ一切触らず、
    /// フィルタ0件のまま次の要求を待つ。
    ///
    /// # なぜ「許可ポートが空の`ApplyRules`」で代用できないのか
    ///
    /// `WfpSession::apply`は「TCP/UDPどちらのloopback許可も空」だと`NoAddressesResolved`で
    /// **fail-closedして失敗を返す**（`wfp.rs`冒頭のガード）。許可ポートは記録ごとの
    /// Proxy/Fake DNSに依存するので**起動時にはまだ決まっていない**——つまり起動時に
    /// 送れる`ApplyRules`は存在しない。`ClearRules`も同じ理由で代用にならない
    /// （あちらは「張った世代を畳む」であって「起こす」ではない）。
    ///
    /// # なぜ起動時に起こしたいのか
    ///
    /// UACの要求が**長い準備の後**に来ると見逃される。実測（2026-08-09）では、
    /// workspace外ルート668件のドメインでパス2を走らせたとき、UACが出るのは
    /// **約140秒の無音の後**で、そこで拒否されて記録が丸ごと失敗した
    /// （`record-session.json`の`error_kind: "no_wfp"`）。起動時に1回出しておけば、
    /// ユーザーが画面を見ている瞬間に出て、以後の記録はすべて再利用で済む。
    ///
    /// D-56の不変条件1「待機中のdaemonはフィルタを持たない」は、この状態を**既に
    /// 正当なものとして認めている**（`ClearRules`後と同じ状態）。
    Standby,
    Teardown,
}

/// D-60で連鎖起動できる兄弟ヘルパー。**列挙で閉じる**——実行ファイル名を親から受け取らないための型。
///
/// 収集器（`harness-policy-learnd`）はここに入れない。あちらは`ApplyRules`の
/// [`NetfilterPolicy::chain_launch_policy_learnd`]で既に起動しており、WFPの適用と同時に
/// 起こす意味があるため経路を分けたままにする（2つの経路が同じ実装を共有する点は
/// [`launch_sibling_helper_chained`]で担保する）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SiblingHelper {
    /// `harness-privhelper.exe`（ACE付与・撤収。1起動1操作で常駐しない＝D-16）。
    Privhelper,
    /// `harness-policy-learnd.exe`（ETW収集器）。
    ///
    /// **`ApplyRules`相乗りの経路とは使いどころが違う。** あちらは「netfilterdをこれから
    /// 起こす」ときにWFPの適用と同時に起こすもので、**daemonが既に生きているときは使えない**
    /// （昇格側の`chain_launched`ガードが1接続1回に制限している）。起動時前倒しで
    /// netfilterdが常駐すると毎回そちらの条件になるので、そのままでは収集器だけが
    /// `runas`＝UAC1回に落ちる。この列挙子はその穴を塞ぐためのもので、
    /// **消えたUACが別のヘルパーで復活しないこと**が目的である。
    PolicyLearnd,
}

impl SiblingHelper {
    /// 起動する実行ファイル名。**昇格側が持つ固定値**で、IPCでは運ばない。
    fn exe_name(self) -> &'static str {
        match self {
            SiblingHelper::Privhelper => "harness-privhelper.exe",
            SiblingHelper::PolicyLearnd => "harness-policy-learnd.exe",
        }
    }
}

/// 収集器の連鎖起動を依頼された`ApplyRules`に対して、**昇格側が実際にどこまで行ったか**
/// （BUG-093）。
///
/// これが無かった頃、非特権側は「起こした」と「起こそうとして失敗した」を区別できず、
/// 失敗しても`ConnectNamedPipe`が60秒タイムアウトするまで待ってからfail-openしていた。
/// 多段の副作用は到達点を返す（B-09）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainLaunchReport {
    /// 起こした。呼び出し側はこのパイプでハンドシェイクしてよい。
    Launched { pid: u32 },
    /// 起こせなかった。**呼び出し側は待たずに自前の`runas`起動へ落ちること。**
    Failed { reason: String },
}

impl ChainLaunchReport {
    /// 連鎖起動が成立したか。偽なら呼び出し側は接続を待たない。
    pub fn launched(&self) -> bool {
        matches!(self, ChainLaunchReport::Launched { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetfilterResponse {
    /// WFPの適用に成功した。
    ///
    /// **ワイヤ形式が`"Applied"`（unit variant）から`{"Applied":{...}}`へ変わっている。**
    /// `chain_launch`は`#[serde(default)]`なので`{"Applied":{}}`は読めるが、旧形式の
    /// 文字列`"Applied"`は読めない——`harness-netfilterd.exe`は本体と同時にビルドされる
    /// 兄弟バイナリなので版ずれは起きない前提で、その前提を
    /// `apply_rules_response_json_wire_format_is_stable`が固定する（B-24）。
    Applied {
        /// 収集器の連鎖起動を**依頼された場合だけ**`Some`。依頼していなければ`None`。
        #[serde(default)]
        chain_launch: Option<ChainLaunchReport>,
    },
    /// [`NetfilterRequest::ClearRules`]に対する応答。この時点でdaemonはフィルタを1件も持たない。
    Cleared,
    /// [`NetfilterRequest::ChainLaunchHelper`]の結末（D-60）。**失敗も`Err`ではなくここで返す**
    /// ——呼び出し側は「起こせなかった」と分かれば自前の`runas`へ落ちればよく、接続を維持したまま
    /// 次の要求へ進める（`Err`はプロトコル違反として接続を切る側の応答である）。
    HelperLaunched(ChainLaunchReport),
    /// [`NetfilterRequest::Standby`]への応答。**この時点でフィルタは0件**で、daemonは
    /// 次の要求（通常は最初の`ApplyRules`）を待っている。
    Standing,
    TornDown,
    Err(String),
}

#[derive(Debug, thiserror::Error)]
pub enum NetfilterError {
    #[error("elevation was declined or failed (UAC canceled?): {0}")]
    ElevationDeclined(String),
    #[error("ipc error: {0}")]
    Ipc(String),
    #[error("daemon rejected the request: {0}")]
    Rejected(String),
    #[error("win32 call failed: {0}")]
    Win32(String),
}

impl From<windows::core::Error> for NetfilterError {
    fn from(e: windows::core::Error) -> Self {
        NetfilterError::Win32(e.to_string())
    }
}

const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const REQUEST_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// `ApplyRules`応答（WFPルール投入完了）を待つタイムアウト。ドメイン解決を含むため
/// `privhelper.rs`のACL操作と同程度の余裕を持たせる。
const APPLY_RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// `Teardown`応答を待つタイムアウト。
const TEARDOWN_RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// `ClearRules`応答（現世代のフィルタの撤収完了）を待つタイムアウト。
///
/// `TEARDOWN_RESPONSE_TIMEOUT`と同値だが**別の定数として持つ**——どちらもWFPの撤収を待つが、
/// 片方を伸ばしたときにもう片方が黙って追随するのは意図ではない。
const CLEAR_RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// daemon側が**次の要求**（`ApplyRules`の再送・`ClearRules`・`Teardown`、または親のクラッシュに
/// よるパイプ切断）を待つ時間。対象アプリの実行時間そのもの、さらにD-56ではユーザーが
/// エディタを開いたまま考えている時間にも依存するため、実質無期限に近い値にする
/// （`WaitForSingleObject`の最大値、約49.7日）。
///
/// **1件目の読取にはこれを使わない**——最初のハンドシェイクは即座に来るべきもので、
/// そこで無期限に待つと「daemonは起きたが親が要求を送らない」状態が検知できなくなる
/// （1件目は`APPLY_RESPONSE_TIMEOUT`）。
const DAEMON_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(u32::MAX as u64);

// 名前付きパイプIPCの下回り（DACL・オーバーラップドI/O・フレーミング）は
// `crate::win_pipe_ipc`が持つ。以前はこのファイル・`tier2a/privhelper.rs`・
// `tier3/vmsandboxd.rs`の3箇所に同じ一式がコピーされていた。
use crate::win_pipe_ipc::{
    connect_with_timeout, current_user_sid_string, read_framed_timeout,
    user_only_security_attributes, write_framed_timeout,
};

/// このモジュール用のパイプ名。
fn unique_pipe_name() -> String {
    crate::win_pipe_ipc::unique_pipe_name("netfilterd")
}

impl From<crate::win_pipe_ipc::PipeIpcError> for NetfilterError {
    fn from(e: crate::win_pipe_ipc::PipeIpcError) -> Self {
        NetfilterError::Ipc(e.into_message())
    }
}

fn daemon_exe_path() -> Result<PathBuf, NetfilterError> {
    let current = std::env::current_exe()
        .map_err(|e| NetfilterError::Ipc(format!("failed to resolve current exe: {e}")))?;
    let dir = current
        .parent()
        .ok_or_else(|| NetfilterError::Ipc("current exe has no parent directory".to_string()))?;
    Ok(dir.join("harness-netfilterd.exe"))
}

unsafe fn launch_daemon_elevated(
    daemon_path: &std::path::Path,
    pipe_name: &str,
) -> Result<HANDLE, NetfilterError> {
    // T-21/D-44: 昇格する前に、その実行ファイルと置き場が非管理者から書けないことを確かめる。
    crate::elevated_launch::verify_elevation_target(daemon_path)
        .map_err(|e| NetfilterError::Win32(format!("refusing to elevate the WFP daemon: {e}")))?;

    let verb_w = wide("runas");
    let file_w = wide(&daemon_path.to_string_lossy());
    let params_w = wide(pipe_name);

    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb_w.as_ptr()),
        lpFile: PCWSTR(file_w.as_ptr()),
        lpParameters: PCWSTR(params_w.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };

    let ok = ShellExecuteExW(&mut info);
    if ok.is_err() {
        let err = GetLastError();
        if err == ERROR_CANCELLED {
            return Err(NetfilterError::ElevationDeclined(
                "UAC prompt was canceled by the user".to_string(),
            ));
        }
        return Err(NetfilterError::Win32(format!(
            "ShellExecuteExW failed: {err:?}"
        )));
    }

    Ok(info.hProcess)
}

/// 常駐daemonへの接続を表す。`stop`を呼ぶまでパイプ・プロセスハンドルを保持し続ける
/// （＝WFPフィルタが有効であり続ける）。呼び出し側（`run_shell`のTier2a起動経路）は
/// harnessセッション全体（複数の`run_shell`呼び出しにまたがる）の生存期間中これを保持し、
/// セッション終了時に`stop`を呼ぶ（`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`付録D）。
///
/// `daemon_process`は`start`（シナリオB、本体が直接`runas`起動）でのみ`Some`になる。
/// シナリオA（`privhelper`が連鎖起動、[`prepare_pipe`]→特権分離ヘルパー経由の起動→
/// [`connect_and_apply`]という流れ）では、起動したのが本体ではなくprivhelperのため
/// プロセスハンドルを持たず`None`のままになる——`stop`時の強制終了フォールバックが
/// 使えない（IPC経由のTeardownのみに頼る）点が唯一の違い。
pub struct NetfilterHandle {
    pipe: HANDLE,
    daemon_process: Option<HANDLE>,
}

unsafe impl Send for NetfilterHandle {}

/// [`prepare_pipe`]の返り値。呼び出し元（`harness-cli`）が`windows`クレートに直接依存せずに
/// 済むよう、生の`HANDLE`をラップし「未消費のままドロップされたら自動的に閉じる」動作を持つ
/// （シナリオ(B)/(C)で結局このパイプを使わなかった場合の後始末を、呼び出し元に`CloseHandle`を
/// 書かせずに済ませる）。実際に使う場合（シナリオ(A)、`NetfilterHandle::connect_after_chain_launch`
/// へ渡す）は[`PreparedPipe::into_handle`]で中身を取り出す。
pub struct PreparedPipe {
    handle: HANDLE,
    name: String,
}

unsafe impl Send for PreparedPipe {}

impl PreparedPipe {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 生ハンドルを取り出す（`NetfilterHandle::connect_after_chain_launch`専用）。以後の
    /// 自動クローズは行われなくなる（呼び出し先がハンドルの所有権を引き継ぐ）。
    pub fn into_handle(self) -> HANDLE {
        let handle = self.handle;
        std::mem::forget(self);
        handle
    }
}

impl Drop for PreparedPipe {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// パイプ作成だけを行う（シナリオA/B共通の前段）。返り値の[`PreparedPipe::name`]は、
/// シナリオBなら[`NetfilterHandle::start`]相当の続きへ、シナリオAなら特権分離ヘルパーの
/// `chain_netfilterd_pipe`引数へそのまま渡す。
pub fn prepare_pipe() -> Result<PreparedPipe, NetfilterError> {
    let pipe_name = unique_pipe_name();
    let sid = current_user_sid_string()?;
    let mut sa = user_only_security_attributes(&sid)?;

    let pipe = unsafe {
        let pipe_name_w = wide(&pipe_name);
        let handle = CreateNamedPipeW(
            PCWSTR(pipe_name_w.as_ptr()),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            4096,
            4096,
            0,
            Some(&mut sa as *mut _),
        );
        let _ = LocalFree(HLOCAL(sa.lpSecurityDescriptor));
        if handle.is_invalid() {
            return Err(NetfilterError::from(windows::core::Error::from_win32()));
        }
        handle
    };
    Ok(PreparedPipe {
        handle: pipe,
        name: pipe_name,
    })
}

/// `ApplyRules`を1件送って応答を待つ（**初回のハンドシェイクと2回目以降の再適用が共有する**）。
///
/// 初回（[`connect_and_apply`]）と再利用（[`NetfilterHandle::apply_on_existing`]）で要求の
/// 組み立てを2箇所に持つと、片方だけがフィールドの追加に追随しない
/// （`docs/CODE-STRUCTURE-RULES.md`規則5）。**失敗してもパイプは閉じない**——後始末の判断は
/// 呼び出し元が持つ（初回は閉じる、再利用時はエラーの種類で分ける）。
///
/// 戻り値は**収集器の連鎖起動の結末**（依頼していなければ`None`）。呼び出し側はこれを見て、
/// 起きていないなら**接続を待たずに**`runas`のフォールバックへ移る（BUG-093）。
fn send_apply(
    pipe: HANDLE,
    policy: NetfilterPolicy,
) -> Result<Option<ChainLaunchReport>, NetfilterError> {
    let req = NetfilterRequest::ApplyRules(policy);
    let bytes = serde_json::to_vec(&req)
        .map_err(|e| NetfilterError::Ipc(format!("failed to serialize request: {e}")))?;
    write_framed_timeout(pipe, &bytes, REQUEST_WRITE_TIMEOUT)?;
    let response_bytes = read_framed_timeout(pipe, APPLY_RESPONSE_TIMEOUT)?;
    let response: NetfilterResponse = serde_json::from_slice(&response_bytes)
        .map_err(|e| NetfilterError::Ipc(format!("failed to parse response: {e}")))?;
    match response {
        NetfilterResponse::Applied { chain_launch } => Ok(chain_launch),
        NetfilterResponse::Err(msg) => Err(NetfilterError::Rejected(msg)),
        other => Err(NetfilterError::Ipc(format!(
            "unexpected {other:?} response for an ApplyRules request"
        ))),
    }
}

/// 既に接続待ち可能な状態のパイプへ、daemonの接続を待ってから`ApplyRules`を送り応答を待つ
/// （シナリオA/B共通の後段）。`daemon_process`は呼び出し元が既に把握しているプロセス
/// ハンドル（シナリオBのみ、[`NetfilterHandle::start`]参照）。
///
/// 戻り値の第2要素は**収集器の連鎖起動の結末**（[`ChainLaunchReport`]）。
/// 接続直後に送る1件目。**`Standby`はWFPへ一切触らない**（[`NetfilterRequest::Standby`]）。
enum FirstRequest {
    Apply(NetfilterPolicy),
    Standby,
}

/// `Standby`を1件送って応答を待つ（[`send_apply`]と対）。
fn send_standby(pipe: HANDLE) -> Result<(), NetfilterError> {
    let bytes = serde_json::to_vec(&NetfilterRequest::Standby)
        .map_err(|e| NetfilterError::Ipc(format!("failed to serialize Standby: {e}")))?;
    write_framed_timeout(pipe, &bytes, REQUEST_WRITE_TIMEOUT)?;
    let response_bytes = read_framed_timeout(pipe, APPLY_RESPONSE_TIMEOUT)?;
    let response: NetfilterResponse = serde_json::from_slice(&response_bytes)
        .map_err(|e| NetfilterError::Ipc(format!("failed to parse response: {e}")))?;
    match response {
        NetfilterResponse::Standing => Ok(()),
        NetfilterResponse::Err(msg) => Err(NetfilterError::Rejected(msg)),
        other => Err(NetfilterError::Ipc(format!(
            "unexpected {other:?} response for a Standby request"
        ))),
    }
}

fn connect_and_apply(
    pipe: HANDLE,
    daemon_process: Option<HANDLE>,
    policy: NetfilterPolicy,
) -> Result<(NetfilterHandle, Option<ChainLaunchReport>), HandshakeFailure> {
    connect_and_handshake(pipe, daemon_process, FirstRequest::Apply(policy))
}

fn connect_and_handshake(
    pipe: HANDLE,
    daemon_process: Option<HANDLE>,
    first: FirstRequest,
) -> Result<(NetfilterHandle, Option<ChainLaunchReport>), HandshakeFailure> {
    let connect_result = connect_with_timeout(pipe, CONNECT_TIMEOUT).map_err(|e| {
        NetfilterError::Ipc(format!(
            "waiting for netfilterd to connect: {e} (daemon may not have launched, or UAC \
             is still pending user interaction)"
        ))
    });
    if let Err(e) = connect_result {
        unsafe {
            let _ = CloseHandle(pipe);
            if let Some(h) = daemon_process {
                let _ = CloseHandle(h);
            }
        }
        // 接続が来ていない＝相手が居ない。残せるものは無い。
        return Err(HandshakeFailure::without_daemon(e));
    }

    let apply_result = match first {
        FirstRequest::Apply(policy) => send_apply(pipe, policy),
        FirstRequest::Standby => send_standby(pipe).map(|()| None),
    };

    match apply_result {
        Ok(chain_launch) => Ok((
            NetfilterHandle {
                pipe,
                daemon_process,
            },
            chain_launch,
        )),
        // **daemonは生きていて要求を拒んだだけ。** ここでパイプを閉じると、UACを1回払って
        // 起こしたばかりのdaemonが`ERROR_BROKEN_PIPE`で撤収し、**次の実行がもう1回払う**。
        // 生死の判定は再利用経路と同じ`daemon_is_dead`を通す（規則を2つ持たない、B-05）。
        Err(e) if !daemon_is_dead(&e) => Err(HandshakeFailure {
            error: e,
            surviving_daemon: Some(NetfilterHandle {
                pipe,
                daemon_process,
            }),
        }),
        Err(e) => {
            unsafe {
                let _ = DisconnectNamedPipe(pipe);
                let _ = CloseHandle(pipe);
                if let Some(h) = daemon_process {
                    let _ = CloseHandle(h);
                }
            }
            Err(HandshakeFailure::without_daemon(e))
        }
    }
}

/// 初回ハンドシェイクに失敗したときの結末。**daemonが生き残っているかどうかで意味が違う。**
///
/// # なぜ理由だけでは足りないのか
///
/// `ApplyRules`が[`NetfilterError::Rejected`]で返るのは「daemonは生きていて、この要求を
/// 拒んだ」という意味で、そのdaemonは**フィルタを1件も持っていない**
/// （`handle_apply_rules`は張る前に畳み、途中で失敗した分も畳んでから`Err`を返す）。
/// つまりD-56の不変条件1「待機中はフィルタを持たない」を満たしたまま保持できる。
///
/// 保持しないと、UACを1回払って起こしたdaemonをその場で捨てることになり、
/// **次の実行がもう1回払う**。再利用経路（[`NetfilterHandle::apply_on_existing`]）は
/// 以前からこの区別を持っていたが、初回だけが持っていなかった（B-02: 片側にだけ入れた判断）。
pub struct HandshakeFailure {
    pub error: NetfilterError,
    /// `Some`なら**daemonは生きている**（拒否されただけ）。呼び出し側が保持すれば
    /// 次の`ApplyRules`で再利用でき、UACは出ない。
    /// `None`なら相手が居ない（接続待ちのタイムアウト・パイプ破損・起動そのものの失敗）。
    pub surviving_daemon: Option<NetfilterHandle>,
}

impl HandshakeFailure {
    fn without_daemon(error: NetfilterError) -> Self {
        Self {
            error,
            surviving_daemon: None,
        }
    }

    /// daemonを捨てて理由だけ取る。
    ///
    /// **1回の起動で1度しかここを通らない呼び出し側**（`harness.exe`の起動シーケンス）は
    /// 保持しても使う相手が居ないので、明示的に捨てる。捨てるとパイプが閉じ、daemonは
    /// フェイルセーフ経路で自発撤収する（従来どおりの振る舞い）。
    pub fn into_error(self) -> NetfilterError {
        self.error
    }
}

impl std::fmt::Display for HandshakeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

/// `NetfilterHandle`は生ハンドルの持ち主なので`Debug`を持たない。**残ったか否か**だけを出す
/// ——`expect`のメッセージで中身まで見せる必要は無い。
impl std::fmt::Debug for HandshakeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeFailure")
            .field("error", &self.error)
            .field("daemon_survived", &self.surviving_daemon.is_some())
            .finish()
    }
}

impl NetfilterHandle {
    /// daemonを昇格起動し、`ApplyRules`を送って応答を待つ（親側、非管理者本体から呼ぶ、
    /// シナリオB＝特権分離ヘルパーが不要なケース）。
    pub fn start(
        policy: NetfilterPolicy,
    ) -> Result<(Self, Option<ChainLaunchReport>), HandshakeFailure> {
        let prepared = prepare_pipe().map_err(HandshakeFailure::without_daemon)?;
        let pipe_name = prepared.name().to_string();
        let pipe = prepared.into_handle();

        let daemon_path = daemon_exe_path().map_err(HandshakeFailure::without_daemon)?;
        let daemon_process = match unsafe { launch_daemon_elevated(&daemon_path, &pipe_name) } {
            Ok(h) => h,
            Err(e) => {
                unsafe {
                    let _ = CloseHandle(pipe);
                }
                // 起動そのものが失敗した（UACの拒否を含む）。**daemonは1つも起きていない。**
                return Err(HandshakeFailure::without_daemon(e));
            }
        };

        connect_and_apply(pipe, Some(daemon_process), policy)
    }

    /// **daemonを起こすだけ**（`ApplyRules`は送らない、[`NetfilterRequest::Standby`]）。
    ///
    /// 起動時前倒し専用。UACはここで1回出て、以後の`ApplyRules`は再利用になる。
    /// 許可ポートがまだ決まっていない時点で呼べるのがこの経路の存在理由である。
    pub fn start_standby() -> Result<Self, HandshakeFailure> {
        let prepared = prepare_pipe().map_err(HandshakeFailure::without_daemon)?;
        let pipe_name = prepared.name().to_string();
        let pipe = prepared.into_handle();

        let daemon_path = daemon_exe_path().map_err(HandshakeFailure::without_daemon)?;
        let daemon_process = match unsafe { launch_daemon_elevated(&daemon_path, &pipe_name) } {
            Ok(h) => h,
            Err(e) => {
                unsafe {
                    let _ = CloseHandle(pipe);
                }
                return Err(HandshakeFailure::without_daemon(e));
            }
        };

        connect_and_handshake(pipe, Some(daemon_process), FirstRequest::Standby)
            .map(|(handle, _no_chain_launch)| handle)
    }

    /// 既に（特権分離ヘルパー経由で）daemonの起動を依頼済みのパイプへ接続し、`ApplyRules`を
    /// 送って応答を待つ（親側、シナリオA＝`privhelper`が連鎖起動したケース）。呼び出し元は
    /// [`prepare_pipe`]で作った`pipe`を渡す。起動者がprivhelperであるため、ここでは
    /// プロセスハンドルを持たない（`daemon_process: None`、構造体docの注記参照）。
    pub fn connect_after_chain_launch(
        pipe: HANDLE,
        policy: NetfilterPolicy,
    ) -> Result<(Self, Option<ChainLaunchReport>), HandshakeFailure> {
        connect_and_apply(pipe, None, policy)
    }

    /// **既に立っているdaemonへ`ApplyRules`を再送する**（D-56、2回目以降の実行）。
    ///
    /// 昇格も起動もしないので**UACは出ない**。daemonは現世代のフィルタを畳んでから
    /// 新しいポリシーを適用し直す（ポートは実行ごとに変わる——Proxy/Fake DNSを起こし直すため）。
    ///
    /// **エラーの種類で意味が違う**（呼び出し側＝[`NetfilterSession::apply`]がここで分岐する）:
    /// - [`NetfilterError::Rejected`] — daemonは生きていて要求を拒んだ。起こし直しても同じ拒否になる。
    /// - それ以外（`Ipc`/`Win32`） — パイプが壊れた＝daemonが死んでいる。起こし直しの対象。
    ///
    /// **再利用時に連鎖起動は依頼しない**（呼び出し側が`is_live()`で塞いでいる、B-23(c)）ので、
    /// 戻り値の[`ChainLaunchReport`]は常に`None`になる。ここでは捨てずに返し、
    /// 判断は呼び出し側に持たせる。
    pub fn apply_on_existing(
        &self,
        policy: NetfilterPolicy,
    ) -> Result<Option<ChainLaunchReport>, NetfilterError> {
        send_apply(self.pipe, policy)
    }

    /// **後から必要になった昇格を、常駐daemonの昇格トークンから起こす**（D-60、UACは出ない）。
    ///
    /// 呼び出し側は先に自分のパイプを作り（`prepare_pipe`相当）、その名前をここへ渡す。
    /// 起動できたら、そのパイプで**ヘルパーと通常のハンドシェイク**をする——daemonは
    /// ヘルパーの仕事の中身を知らない。
    ///
    /// 失敗は`Err`ではなく[`ChainLaunchReport::Failed`]として返る（接続は維持される）ので、
    /// 呼び出し側は自前の`runas`へ落ちればよい。
    pub fn chain_launch_helper(
        &self,
        helper: SiblingHelper,
        pipe_name: &str,
    ) -> Result<ChainLaunchReport, NetfilterError> {
        let req = NetfilterRequest::ChainLaunchHelper {
            helper,
            pipe_name: pipe_name.to_string(),
        };
        let bytes = serde_json::to_vec(&req).map_err(|e| {
            NetfilterError::Ipc(format!("failed to serialize ChainLaunchHelper: {e}"))
        })?;
        write_framed_timeout(self.pipe, &bytes, REQUEST_WRITE_TIMEOUT)?;
        let response_bytes = read_framed_timeout(self.pipe, APPLY_RESPONSE_TIMEOUT)?;
        let response: NetfilterResponse = serde_json::from_slice(&response_bytes)
            .map_err(|e| NetfilterError::Ipc(format!("failed to parse response: {e}")))?;
        match response {
            NetfilterResponse::HelperLaunched(report) => Ok(report),
            NetfilterResponse::Err(msg) => Err(NetfilterError::Rejected(msg)),
            other => Err(NetfilterError::Ipc(format!(
                "unexpected {other:?} response for a ChainLaunchHelper request"
            ))),
        }
    }

    /// 現世代のフィルタを畳ませる（実行の切れ目、D-56の不変条件1）。**daemonは生き続ける。**
    ///
    /// 失敗したら呼び出し側はこのハンドルを捨てること——「畳めたか分からないdaemon」を
    /// 抱えたまま次の実行へ進むと、待機中にフィルタが残っているのかどうかを誰も言えなくなる。
    pub fn clear(&self) -> Result<(), NetfilterError> {
        let bytes = serde_json::to_vec(&NetfilterRequest::ClearRules)
            .map_err(|e| NetfilterError::Ipc(format!("failed to serialize ClearRules: {e}")))?;
        write_framed_timeout(self.pipe, &bytes, REQUEST_WRITE_TIMEOUT)?;
        let response_bytes = read_framed_timeout(self.pipe, CLEAR_RESPONSE_TIMEOUT)?;
        let response: NetfilterResponse = serde_json::from_slice(&response_bytes)
            .map_err(|e| NetfilterError::Ipc(format!("failed to parse response: {e}")))?;
        match response {
            NetfilterResponse::Cleared => Ok(()),
            NetfilterResponse::Err(msg) => Err(NetfilterError::Rejected(msg)),
            other => Err(NetfilterError::Ipc(format!(
                "unexpected {other:?} response for a ClearRules request"
            ))),
        }
    }

    /// `Teardown`を送ってdaemonの終了を待つ（対象アプリ終了を検知した親から呼ぶ、正常系）。
    pub fn stop(self) -> Result<(), NetfilterError> {
        let pipe = self.pipe;
        let daemon_process = self.daemon_process;
        std::mem::forget(self); // Dropで二重stopしないよう所有権をここで断つ。

        let result = (|| -> Result<(), NetfilterError> {
            let bytes = serde_json::to_vec(&NetfilterRequest::Teardown)
                .map_err(|e| NetfilterError::Ipc(format!("failed to serialize teardown: {e}")))?;
            write_framed_timeout(pipe, &bytes, REQUEST_WRITE_TIMEOUT)?;
            let response_bytes = read_framed_timeout(pipe, TEARDOWN_RESPONSE_TIMEOUT)?;
            let response: NetfilterResponse = serde_json::from_slice(&response_bytes)
                .map_err(|e| NetfilterError::Ipc(format!("failed to parse response: {e}")))?;
            match response {
                NetfilterResponse::TornDown => Ok(()),
                NetfilterResponse::Err(msg) => Err(NetfilterError::Rejected(msg)),
                other => Err(NetfilterError::Ipc(format!(
                    "unexpected {other:?} response for a Teardown request"
                ))),
            }
        })();

        unsafe {
            let _ = DisconnectNamedPipe(pipe);
            let _ = CloseHandle(pipe);
            // daemon_processはシナリオB（本体が直接runas起動）のみ`Some`。シナリオA
            // （privhelperが連鎖起動）ではプロセスハンドルを持たないため、強制終了
            // フォールバックは使えず、IPC経由のTeardown応答（上のresult）のみに頼る
            // （NetfilterHandle構造体docの注記参照）。
            if let Some(daemon_process) = daemon_process {
                let wait = WaitForSingleObject(daemon_process, 5000);
                if wait != WAIT_OBJECT_0 {
                    let _ = windows::Win32::System::Threading::TerminateProcess(daemon_process, 1);
                    let _ = WaitForSingleObject(daemon_process, 2000);
                }
                let _ = CloseHandle(daemon_process);
            }
        }

        result
    }
}

impl Drop for NetfilterHandle {
    /// `stop`を呼ばずにドロップされた場合（異常系）でも、パイプを閉じてdaemonプロセスへ
    /// 通知する。daemon側は2件目のメッセージ待ちが`ERROR_BROKEN_PIPE`で失敗し、
    /// フェイルセーフのteardown経路（モジュールdoc参照）へ入る。
    fn drop(&mut self) {
        unsafe {
            let _ = DisconnectNamedPipe(self.pipe);
            let _ = CloseHandle(self.pipe);
            if let Some(daemon_process) = self.daemon_process {
                let _ = CloseHandle(daemon_process);
            }
        }
    }
}

/// [`NetfilterSession::apply`]の結果。`reused`が真なら**daemonを起こしていない＝UACが出ていない**。
///
/// これを呼び出し側へ返すのは、ユーザーが「UACが出なかった」ことを
/// 「強制が掛かっていない」と読み違えるのを防ぐため（B-32）。表示に出す義務がここから生まれる。
/// 同時に、E2Eが「2回目でUACが出ない」ことを**目視ではなく`reused == true`という同値命題で**
/// 検査できるようにする（`tier2a_chain_launch_*`と同じ手法）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub reused: bool,
    /// 収集器の連鎖起動を依頼していた場合の**結末**（BUG-093）。依頼していなければ`None`。
    ///
    /// 呼び出し側はこれが`Some(Failed{..})`なら、**収集器の接続を待たずに**自前の`runas`
    /// 起動へ移ること。待つと`ConnectNamedPipe`が60秒タイムアウトしてから同じ場所に着く。
    pub chain_launch: Option<ChainLaunchReport>,
}

impl Applied {
    /// 収集器の連鎖起動が**実際に成立した**か。依頼していない場合も偽になる
    /// （＝呼び出し側は自前で起こす必要がある、という同じ扱いで正しい）。
    pub fn collector_chain_launched(&self) -> bool {
        self.chain_launch.as_ref().is_some_and(|r| r.launched())
    }
}

/// **daemonの寿命を呼び出し側プロセスの寿命に合わせる**ための持ち手（D-56）。
///
/// 1回の起動で記録を何度も走らせる`harness-policy-editor`が使う。実行のたびに
/// [`NetfilterHandle`]を作って`stop`すると、そのたびに`runas`＝UACが出る。
///
/// # 待機中に何を持っているか
///
/// 実行の切れ目で[`Self::clear`]を呼ぶので、**待機中のdaemonはWFPフィルタを1件も持たない**
/// （モジュールdocの不変条件1）。持っているのはパイプのハンドルと昇格トークンだけである。
/// パイプは呼び出しユーザー専有DACL（`win_pipe_ipc::user_only_security_attributes`）で、
/// 接続数は1に固定されている（`prepare_pipe`）ため、接続済みの間は他のクライアントが入れない。
///
/// # 落ちたときにどうなるか
///
/// `Drop`が走らない終わり方（`std::process::exit`・クラッシュ）でも、プロセス消滅で
/// パイプが閉じ、daemon側の`read_framed_timeout`が`ERROR_BROKEN_PIPE`で失敗して自発的に撤収する。
/// 残ったフィルタは`FWPM_SESSION_FLAG_DYNAMIC`によりBFEが消す。**寿命はOSハンドルに
/// 紐付いたままで、タイマーもファイルポーリングも使わない**（グローバル`CLAUDE.md`の
/// 「常駐昇格キュー禁止」に適合する条件そのもの）。
pub struct NetfilterSession {
    handle: Option<NetfilterHandle>,
}

impl Default for NetfilterSession {
    fn default() -> Self {
        Self::new()
    }
}

impl NetfilterSession {
    pub fn new() -> Self {
        Self { handle: None }
    }

    /// 生きているdaemonを持っているか。
    ///
    /// **呼び出し側はこれを見て、`prepare_pipe`と「privhelperへの連鎖起動依頼」を省く**——
    /// 省かないと、2回目にworkspace外の新しい穴が要る場合（privhelperが起動する場合）に
    /// **2つ目のnetfilterdが連鎖起動される**（B-23(c) 二重起動ガード）。
    pub fn is_live(&self) -> bool {
        self.handle.is_some()
    }

    /// ポリシーを適用する。生きているdaemonがあれば再送するだけ、無ければ起こす。
    ///
    /// `prelude`/`chain_attempted`は**daemonを起こす場合にだけ**使う（シナリオA＝privhelperが
    /// 連鎖起動済み／シナリオB＝自分で`runas`）。生きているdaemonがある場合、`prelude`は
    /// dropされてパイプが閉じる（`PreparedPipe`のDropが後始末する）。
    pub fn apply(
        &mut self,
        prelude: Option<PreparedPipe>,
        chain_attempted: bool,
        policy: NetfilterPolicy,
    ) -> Result<Applied, NetfilterError> {
        if let Some(handle) = self.handle.take() {
            // 再利用時は投機的パイプを使わない（`PreparedPipe`のDropが閉じる）。
            drop(prelude);
            match handle.apply_on_existing(policy.clone()) {
                Ok(chain_launch) => {
                    self.handle = Some(handle);
                    return Ok(Applied {
                        reused: true,
                        chain_launch,
                    });
                }
                // daemonは生きていて要求を拒んだ。起こし直しても同じ拒否になるだけで、
                // UACを1回増やして同じ場所に着く。**そのまま伝播してfail-closedにする。**
                Err(e) if !daemon_is_dead(&e) => {
                    self.handle = Some(handle);
                    return Err(e);
                }
                // パイプが壊れた＝daemonが死んでいる。**黙って強制なしで走らせない**ために、
                // ここで1度だけ起こし直す。再試行は1回に固定する（起こし直しの失敗は伝播）。
                Err(e) => {
                    // ハンドルを落とす＝パイプが閉じる＝死にかけのdaemonが残っていても撤収する。
                    drop(handle);
                    eprintln!(
                        "warning: the WFP daemon stopped answering ({e}); restarting it \
                         (one UAC prompt)"
                    );
                    // 連鎖起動用のパイプはもう無いので、起こし直しは必ずシナリオB。
                    match NetfilterHandle::start(policy) {
                        Ok((handle, chain_launch)) => {
                            self.handle = Some(handle);
                            return Ok(Applied {
                                reused: false,
                                chain_launch,
                            });
                        }
                        Err(failure) => return Err(self.keep_surviving_daemon(failure)),
                    }
                }
            }
        }
        match start_handle(prelude, chain_attempted, policy) {
            Ok((handle, chain_launch)) => {
                self.handle = Some(handle);
                Ok(Applied {
                    reused: false,
                    chain_launch,
                })
            }
            Err(failure) => Err(self.keep_surviving_daemon(failure)),
        }
    }

    /// ハンドシェイクに失敗しても、**daemonが生きているなら手放さない**（[`HandshakeFailure`]）。
    ///
    /// この実行はそのまま失敗させる（fail-closed）。変えるのは「**次の実行がUACを
    /// もう1回払うかどうか**」だけである。
    fn keep_surviving_daemon(&mut self, failure: HandshakeFailure) -> NetfilterError {
        if let Some(handle) = failure.surviving_daemon {
            self.handle = Some(handle);
        }
        failure.error
    }

    /// **daemonを先に起こしておく**（起動時前倒し。[`NetfilterRequest::Standby`]）。
    ///
    /// 既に生きていれば何もしない（二重起動ガード、B-23(c)）。`Ok(true)`は
    /// 「この呼び出しで起こした＝UACが1回出た」、`Ok(false)`は「既に居た＝出ていない」。
    ///
    /// 失敗しても**呼び出し側は続行してよい**——起こせなかっただけで、必要になった時点で
    /// 従来どおり`apply`が起こす（UACはそのとき出る）。
    pub fn standby(&mut self) -> Result<bool, NetfilterError> {
        if self.handle.is_some() {
            return Ok(false);
        }
        match NetfilterHandle::start_standby() {
            Ok(handle) => {
                self.handle = Some(handle);
                Ok(true)
            }
            Err(failure) => Err(self.keep_surviving_daemon(failure)),
        }
    }

    /// **生きているdaemonがあれば、そこから兄弟ヘルパーを連鎖起動する**（D-60）。
    ///
    /// 生きていなければ`None`を返す——呼び出し側は自前の`runas`へ落ちる（UACが1回）。
    /// **ここでdaemonを起こしはしない**：daemonを起こすなら`runas`が1回出るので、
    /// それなら目的のヘルパーを直接`runas`した方が回数が同じで経路が短い。
    pub fn chain_launch_helper(
        &self,
        helper: SiblingHelper,
        pipe_name: &str,
    ) -> Option<Result<ChainLaunchReport, NetfilterError>> {
        self.handle
            .as_ref()
            .map(|handle| handle.chain_launch_helper(helper, pipe_name))
    }

    /// 現世代のフィルタを畳ませる（実行の切れ目）。**daemonは次の実行のために残す。**
    ///
    /// 失敗したらハンドルを捨てる——畳めたか分からないdaemonを抱えたまま次の実行へ進むと、
    /// 「待機中はフィルタを持たない」という不変条件を誰も言えなくなる。捨てた場合、
    /// 次の[`Self::apply`]はdaemonを起こし直す（UACが1回）。
    pub fn clear(&mut self) -> Result<(), NetfilterError> {
        let Some(handle) = self.handle.as_ref() else {
            return Ok(());
        };
        match handle.clear() {
            Ok(()) => Ok(()),
            Err(e) => {
                // ハンドルを落とす＝パイプが閉じる＝daemon側がフェイルセーフ経路で撤収する。
                self.handle = None;
                Err(e)
            }
        }
    }

    /// `Teardown`を送ってdaemonを終了させる。`Drop`からも呼ばれる。
    pub fn stop(&mut self) -> Result<(), NetfilterError> {
        match self.handle.take() {
            Some(handle) => handle.stop(),
            None => Ok(()),
        }
    }
}

impl Drop for NetfilterSession {
    fn drop(&mut self) {
        if let Err(e) = self.stop() {
            eprintln!("warning: failed to cleanly tear down the WFP daemon: {e}");
        }
    }
}

/// 再利用中の`ApplyRules`が失敗したとき、**daemonが死んでいる**と判断してよいか。
///
/// この分け方が[`NetfilterSession::apply`]の再試行方針そのものである:
/// - [`NetfilterError::Rejected`] — daemonは生きていて要求を拒んだ。起こし直しても同じ拒否に
///   なるだけでUACが1回増える。**伝播してfail-closedにする。**
/// - それ以外（`Ipc`＝パイプI/Oの失敗・`Win32`） — 相手が居ない。起こし直しの対象。
///
/// `ElevationDeclined`は再利用経路では出ない（昇格を試みていないため）が、
/// 万一出たら「相手が居ない」側で扱う——起こし直せばユーザーにもう一度UACが提示される。
fn daemon_is_dead(e: &NetfilterError) -> bool {
    !matches!(e, NetfilterError::Rejected(_))
}

/// [`NetfilterSession::apply`]がdaemonを起こすときの、シナリオA/Bの選択。
///
/// この分岐は`run_agent.rs`（harness本体）にも同型で存在する。あちらは1回しか通らない
/// 一発勝負なので寄せていない——**寄せると本体側の経路まで本計画の変更範囲に入る**。
fn start_handle(
    prelude: Option<PreparedPipe>,
    chain_attempted: bool,
    policy: NetfilterPolicy,
) -> Result<(NetfilterHandle, Option<ChainLaunchReport>), HandshakeFailure> {
    match (chain_attempted, prelude) {
        // シナリオA: privhelperが既に連鎖起動を試みている。同じパイプでハンドシェイクする。
        (true, Some(prepared)) => {
            NetfilterHandle::connect_after_chain_launch(prepared.into_handle(), policy)
        }
        // シナリオB: 連鎖起動は発生しなかった。投機的パイプは使わない（`start`が自前で
        // 新規パイプを作るため）、dropして自動的に閉じる。
        (_, prelude) => {
            drop(prelude);
            NetfilterHandle::start(policy)
        }
    }
}

/// daemon側エントリポイント（`harness-netfilterd.exe`のmainから呼ぶ、昇格トークンで実行される）。
pub fn serve(pipe_name: &str) -> Result<(), NetfilterError> {
    let pipe = unsafe {
        let pipe_name_w = wide(pipe_name);
        CreateFileW(
            PCWSTR(pipe_name_w.as_ptr()),
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            None,
        )
        .map_err(NetfilterError::from)?
    };

    let result = serve_inner(pipe);
    unsafe {
        let _ = CloseHandle(pipe);
    }
    result
}

/// 1つのpackage SIDへ張る出口ポリシー（IPCワイヤ形式から昇格側の作業単位へ均した形）。
///
/// `run_shell`セッション（D-37）とMCPサーバ（D-38）は、**WFPから見れば同じ形**——
/// 「あるpackage SIDに対しdefault-deny、指定のloopbackポートだけallow」——なので、
/// ここで1つの型へ均してから適用ループを1本にする。
#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyTarget {
    profile: String,
    tcp_ports: Vec<u16>,
    udp_ports: Vec<u16>,
}

/// ポリシーを適用単位の一覧へ均す（純粋関数。Win32もWFPも触らないので単体テストできる）。
fn policy_targets(policy: &NetfilterPolicy) -> Vec<PolicyTarget> {
    let mut targets = vec![PolicyTarget {
        profile: policy.session_profile.clone(),
        tcp_ports: policy.allow_loopback_tcp_ports.clone(),
        udp_ports: policy.allow_loopback_udp_ports.clone(),
    }];
    for mcp in &policy.mcp_profiles {
        targets.push(PolicyTarget {
            profile: mcp.profile.clone(),
            tcp_ports: mcp.allow_loopback_tcp_ports.clone(),
            udp_ports: mcp.allow_loopback_udp_ports.clone(),
        });
    }
    targets
}

/// 1つのプロファイルに対してWFPフィルタを張る（**名前検証はここが唯一のゲート**）。
///
/// [BUG-094 案G] **監査の書込先はここで受け取らない。** 購読はフィルタの世代ではなく
/// daemonの生存に紐づくようになった（`serve_inner`が`WfpAuditSubscription`を1つ持つ）。
fn apply_one(target: &PolicyTarget) -> Result<WfpSession, NetfilterError> {
    if !crate::tier2a::mcp_profile::is_harness_profile_name(&target.profile) {
        return Err(NetfilterError::Ipc(format!(
            "rejected malformed appcontainer profile name: {:?}",
            target.profile
        )));
    }
    // [BUG-107] **導出であって作成ではない。** ここは昇格した別プロセス（`harness-netfilterd`）
    // なので、`ensure_profile`を呼ぶと**親のセッション名で親の資源を作る**——親のプロセスでは
    // ないため台帳への登録（`begin_session`）が発火せず、回収できないプロファイルが1件残る
    // （`cargo test`のたびに1件積まれていた実測値の正体がこれ）。
    //
    // WFPのフィルタ条件（`FWPM_CONDITION_ALE_PACKAGE_ID`）が要るのは**SIDの値だけ**で、
    // プロファイルの実在は要らない。実在させる責任は親の`preflight`／`preflight_mcp_server`にあり、
    // 本番の順序でも親が先（`select_tier`→`preflight`→ここ）である。
    // 導出は名前のハッシュからの決定論なので、昇格先が別の管理者アカウント（別HKCU）でも同じ値になる。
    let sid = win_appcontainer::derive_profile_sid(&target.profile)
        .map_err(|e| NetfilterError::Ipc(format!("failed to resolve sandbox SID: {e}")))?;

    // `NetfilterPolicy`はIPCワイヤ形式、`WfpOptions`はWFPエンジンへ渡す層のオプションで、
    // フィールドは同形だが所有するレイヤーが違う。型は分けたまま、ここで明示的に写す。
    let opts = WfpOptions {
        session_profile: target.profile.clone(),
        allow_loopback_tcp_ports: target.tcp_ports.clone(),
        allow_loopback_udp_ports: target.udp_ports.clone(),
    };
    WfpSession::apply(sid.as_psid(), &opts)
        .map_err(|e| NetfilterError::Ipc(format!("WFP rule application failed: {e}")))
}

/// **現世代**のWFPフィルタを全部畳む。1つの失敗が他の撤収を止めないよう、最初のエラーだけを
/// 覚えて最後まで回す（残したフィルタはDYNAMICセッションなのでプロセス終了時にBFEが消すが、
/// 「片付け損ねた」ことを応答から隠さない）。
///
/// **呼び出し後、`sessions`は必ず空になる**——ここが「待機中はフィルタを持たない」
/// （D-56の不変条件1）を成立させる唯一の場所なので、部分的に残す経路を作らない。
fn teardown_generation(sessions: &mut Vec<WfpSession>) -> Result<(), crate::tier2a::wfp::WfpError> {
    let mut first_error: Result<(), crate::tier2a::wfp::WfpError> = Ok(());
    for session in sessions.drain(..) {
        if let Err(e) = session.teardown() {
            if first_error.is_ok() {
                first_error = Err(e);
            }
        }
    }
    first_error
}

/// `ApplyRules`1件を処理する。成功したら`sessions`へ新しい世代を入れる。
///
/// **要件2（検証は要求ごとにやり直す）**: プロファイル名（`is_harness_profile_name`、`apply_one`の中）と
/// 監査ログの書込先（`validate_audit_sink_path`）は、**2回目以降の`ApplyRules`でも必ず通す**。
/// 1回目だけ検証して以後を素通りにすると、そこが「非特権側が任意のAppContainerへWFPフィルタを
/// 張らせる／任意パスへ管理者権限で追記させる」経路になる。親（非昇格）は攻撃者と同じ権限で
/// 動きうる（P-01）ので、送信側で検証しても意味が無い。
///
/// 監査ログ検証はプロファイルごとではなく**ここで1回だけ**行う——同じ値を複数の`apply_one`へ
/// 配るので、判定が分かれる余地を作らない。`workspace_root`を運ばない旧形式の要求は
/// **監査ログを無効化して続行する**（WFPの出口強制そのものは監査に依存しないので、境界は
/// 落とさずに任意パス追記だけを閉じられる、P-07）。
///
/// **戻り値は検証済みの監査シンク**（無効化された場合は`None`）。呼び出し側はこれを使って
/// 「収集器を連鎖起動できたか」の制御レコードを書く（BUG-093）——昇格側の`eprintln!`は
/// `SW_HIDE`のコンソールへ消えるので、**検証済みのシンクだけが唯一の伝達路**である。
fn handle_apply_rules(
    policy: &NetfilterPolicy,
    sessions: &mut Vec<WfpSession>,
) -> Result<Option<PathBuf>, String> {
    // **張る前に畳む。** 逆順にすると、新旧2世代のallowフィルタが一瞬だけ和集合になる。
    // 畳んでから張って失敗した場合はフィルタ0件になるが、親は`Err`を受けて子を起こさない
    // （fail-closed）ので、中途半端に強制された状態は残らない。
    if let Err(e) = teardown_generation(sessions) {
        return Err(format!("failed to tear down the previous filters: {e}"));
    }

    let audit_log_path = match (&policy.audit_log_path, &policy.workspace_root) {
        (Some(path), Some(root)) => {
            match crate::elevated_launch::validate_audit_sink_path(path, root) {
                Ok(resolved) => Some(resolved),
                Err(e) => return Err(format!("rejected audit log path: {e}")),
            }
        }
        (Some(_), None) | (None, _) => None,
    };

    for target in policy_targets(policy) {
        match apply_one(&target) {
            Ok(session) => sessions.push(session),
            Err(e) => {
                // 1つでも張れなければ全体を失敗させる（fail-closed）。既に張った分は
                // ここで畳んでから返す——中途半端に一部だけ強制された状態を残さない。
                let _ = teardown_generation(sessions);
                return Err(e.to_string());
            }
        }
    }
    Ok(audit_log_path)
}

fn serve_inner(pipe: HANDLE) -> Result<(), NetfilterError> {
    // 現世代のWFPフィルタ。`ClearRules`／`Teardown`／次の`ApplyRules`で必ず空へ戻る。
    let mut sessions: Vec<WfpSession> = Vec::new();
    // M15.7: 収集器の連鎖起動は**最初の`ApplyRules`でだけ**行う（下記の理由）。
    let mut chain_launched = false;
    let mut first_request = true;
    // 直近の`ApplyRules`で検証に通った監査シンク。**`ApplyRules`以外の分岐（D-60の
    // `ChainLaunchHelper`）でも制御レコードを書けるように保持する**——昇格側の`eprintln!`は
    // `SW_HIDE`のコンソールへ消えるので、これが唯一の伝達路である（BUG-093）。
    // `ApplyRules`より前に`ChainLaunchHelper`が来ればまだ`None`で、そのときは記録先が無い
    // （検証していないパスへは書かない、D-44）。
    let mut last_audit_sink: Option<PathBuf> = None;
    // [BUG-094 案G] **WFPの拒否監査はここが持つ。** フィルタの世代（`sessions`）と寿命が違う。
    //
    // 世代ごとに張り直していた頃は購読の窓が1.2〜2.0秒しか開かず、**約1秒遅れて届く配送**を
    // 取りこぼしていた（`plans/net-spike/RESULTS.md` N10・N11）。ここで持てば、実行の
    // 切れ目でも購読は閉じず、移るのは書込先だけになる。
    //
    // **待機中のdaemonがこれを握ってよい根拠**は`D-56`不変条件1の改訂に書いた——
    // 観測専用で強制を1つも持たず、動的セッションなのでdaemonが死ねばOSが消す。
    let mut audit: Option<crate::tier2a::wfp::WfpAuditSubscription> = None;

    let outcome: Result<(), NetfilterError> = loop {
        // 1件目は短く待つ（ハンドシェイクは即座に来るべき）。2件目以降は実質無期限
        // ——ユーザーがエディタを開いたまま考えている時間を待つのがD-56の目的そのもの。
        let timeout = if first_request {
            APPLY_RESPONSE_TIMEOUT
        } else {
            DAEMON_IDLE_TIMEOUT
        };
        first_request = false;

        // パイプ切断・タイムアウトは「親が死んだ」のシグナル。フェイルセーフ経路として
        // 畳んで終了する（**応答は送らない**——送り先の親が既に存在しない可能性が高い）。
        let Ok(request_bytes) = read_framed_timeout(pipe, timeout) else {
            break Ok(());
        };

        match serde_json::from_slice::<NetfilterRequest>(&request_bytes) {
            Ok(NetfilterRequest::ApplyRules(policy)) => {
                match handle_apply_rules(&policy, &mut sessions) {
                    Ok(audit_sink) => {
                        last_audit_sink = audit_sink.clone();
                        // [BUG-094 案G] 書込先を今回の実行のものへ移す。初回だけ購読を始める。
                        // **`validate_audit_sink_path`を通った値しかここへ来ない**
                        // （`handle_apply_rules`が検証してから返す）——D-44。
                        if let Some(path) = audit_sink.clone() {
                            match &audit {
                                Some(existing) => existing.set_audit_log_path(path),
                                None => {
                                    audit = crate::tier2a::wfp::WfpAuditSubscription::start(path);
                                }
                            }
                            // [BUG-094] **いま張ったフィルタのIDを監査シンクへ渡す。**
                            // これが無いと、届いた拒否が「harnessが落とした分」なのか
                            // 「マシン上の無関係な通信」なのかを記録から言えない
                            // （購読も列挙もマシン全体が対象で、絞り込む手段が無い）。
                            //
                            // **2分岐のうち2分岐**（購読を始めた側・既存へ移した側）で渡す。
                            // 片方だけに書くと、daemonの2回目以降の実行で注記が
                            // 黙って`"other"`に化ける（`B-06`）。
                            if let Some(audit) = &audit {
                                let ids: Vec<u64> = sessions
                                    .iter()
                                    .flat_map(|s| s.filter_ids().iter().copied())
                                    .collect();
                                audit.add_owned_filter_ids(&ids);
                            }
                        }
                        // M15.7: OS監査収集器の連鎖起動。**WFPの適用が終わってから**行う
                        // （順序に依存は無いが、出口強制の確立を遅らせないため後ろに置く）。
                        //
                        // **`Applied`を送る前に行う**（BUG-093の修正）。以前は応答を先に送り、
                        // 失敗はベストエフォートで無視していたため、非特権側には「起こした」と
                        // 「起こそうとして失敗した」の区別が届かず、`ConnectNamedPipe`が60秒
                        // タイムアウトするまで待ってからでないと分からなかった。結末を応答に
                        // 載せれば呼び出し側は即座にフォールバックできる（B-09: 多段の副作用は
                        // 到達点を返す）。連鎖起動は`CreateProcessW`1回なので、この順序変更で
                        // 親が待たされる時間はミリ秒単位である。
                        //
                        // 収集器は境界ではない（P-07）ので、起こせなくてもWFPの出口強制は続く
                        // ——失敗しても`Applied`は返す。**捨てるのは機能であって理由ではない**（B-10）。
                        let mut chain_report = None;
                        let mut launched_child = None;
                        if let Some(learn_pipe) = policy.chain_launch_policy_learnd.as_deref() {
                            let outcome = if chain_launched {
                                // **黙って無視しない。** 無視すると呼び出し側は収集器が起きたと
                                // 思って接続待ちでタイムアウトする（B-32）。収集器を実行ごとに
                                // 起こし直せるようにするのは段階2の仕事で、それまでは
                                // 「できない」と言い切る。
                                ChainLaunchOutcome::RefusedSecondLaunch {
                                    pipe: learn_pipe.to_string(),
                                }
                            } else {
                                unsafe { launch_policy_learnd_chained(learn_pipe) }
                            };
                            launched_child = outcome.launched_child();
                            if launched_child.is_some() {
                                chain_launched = true;
                            }
                            // 理由の全文は監査シンクへ（応答へは要約だけを載せる——応答は
                            // 制御フローのためのもので、調査のための正本はJSONL側にある）。
                            record_chain_launch(audit_sink.as_deref(), &outcome);
                            chain_report = Some(outcome.to_report());
                        }

                        if let Err(e) = send_response(
                            pipe,
                            &NetfilterResponse::Applied {
                                chain_launch: chain_report,
                            },
                        ) {
                            break Err(e);
                        }

                        // H2（起こせたが収集器が接続前に死んだ）を分けるための短い観測。
                        // **`Applied`を送り終えた後に行う**ので、この2秒で親は止まらない。
                        if let Some(child) = launched_child {
                            let probe = unsafe { probe_chain_child(child) };
                            record_chain_child_probe(audit_sink.as_deref(), &probe);
                        }
                    }
                    Err(message) => {
                        // **接続は維持する。** 要求が拒まれただけでdaemonを畳むと、
                        // 回復可能な失敗（監査ディレクトリの作成漏れ等）がUACの追加1回になる。
                        // 親はこの`Err`を`Rejected`として受け、fail-closedで中止する。
                        if let Err(e) = send_response(pipe, &NetfilterResponse::Err(message)) {
                            break Err(e);
                        }
                    }
                }
            }
            Ok(NetfilterRequest::ChainLaunchHelper { helper, pipe_name }) => {
                // D-60: 後から必要になった昇格を、常駐している昇格トークンのまま起こす。
                //
                // **形の検証は受信側で行う**（D-56 不変条件2 / P-01: 親は攻撃者と同じ権限で
                // 動きうる）。運ばれてくるのはパイプ名だけで、実行ファイル名は`helper`から
                // 昇格側が導出する——親から任意パスを受け取らない。
                let outcome = if !crate::win_pipe_ipc::is_harness_pipe_name(&pipe_name) {
                    ChainLaunchOutcome::VerifyRejected {
                        pipe: pipe_name.clone(),
                        error: "rejected malformed pipe name (not a harness pipe)".to_string(),
                    }
                } else {
                    unsafe { launch_sibling_helper_chained(helper.exe_name(), &pipe_name) }
                };
                let launched_child = outcome.launched_child();
                record_chain_launch(last_audit_sink.as_deref(), &outcome);
                let report = outcome.to_report();
                if let Err(e) = send_response(pipe, &NetfilterResponse::HelperLaunched(report)) {
                    break Err(e);
                }
                // 起動できた子の短時間観測（応答送信後なので親を待たせない）。
                // **privhelperは1操作で終了する設計**（D-16）なので、2秒窓で終了を観測しても
                // 異常ではない——終了コードごと残して呼び出し側の判断材料にする。
                if let Some(child) = launched_child {
                    let probe = unsafe { probe_chain_child(child) };
                    record_chain_child_probe(last_audit_sink.as_deref(), &probe);
                }
            }
            Ok(NetfilterRequest::ClearRules) => {
                // 畳めなかったことは応答で伝えるが、**接続は維持する**（親はハンドルを捨てて
                // 起こし直す判断をこちらに委ねない）。`sessions`は成否によらず空になる。
                let resp = match teardown_generation(&mut sessions) {
                    Ok(()) => NetfilterResponse::Cleared,
                    Err(e) => NetfilterResponse::Err(format!("clear failed: {e}")),
                };
                if let Err(e) = send_response(pipe, &resp) {
                    break Err(e);
                }
            }
            Ok(NetfilterRequest::Standby) => {
                // **何もしない。** WFPへ触らないことがこのオペコードの唯一の中身で、
                // 応答は「起きて待っている」という事実だけを返す。
                //
                // 触らないので`sessions`は空のまま——D-56の不変条件1（待機中はフィルタを
                // 持たない）はここで自動的に満たされる。**`teardown_generation`すら呼ばない**
                // （呼ぶと「畳んだ」という別の意味が混ざるうえ、空のVecを回すだけである）。
                if let Err(e) = send_response(pipe, &NetfilterResponse::Standing) {
                    break Err(e);
                }
            }
            Ok(NetfilterRequest::Teardown) => {
                let result = teardown_generation(&mut sessions);
                let resp = match &result {
                    Ok(()) => NetfilterResponse::TornDown,
                    Err(e) => NetfilterResponse::Err(format!("teardown failed: {e}")),
                };
                // 応答送信の失敗はここでは致命的としない（親が既に読み取りを諦めている可能性がある）。
                let _ = send_response(pipe, &resp);
                // 撤収に失敗したなら**daemonの終了コードにも残す**（変更前と同じ扱い）。
                break result.map_err(|e| NetfilterError::Ipc(e.to_string()));
            }
            Err(e) => {
                // 相手がこのプロトコルを喋っていない。ここは接続を維持しない。
                let _ = send_response(
                    pipe,
                    &NetfilterResponse::Err(format!("malformed request: {e}")),
                );
                break Err(NetfilterError::Ipc(format!("malformed request: {e}")));
            }
        }
    };

    // どの抜け方をしても現世代は必ず畳む（`Teardown`/`ClearRules`で既に空なら何も起きない）。
    let residual = teardown_generation(&mut sessions);
    // [BUG-094 案G] 監査の購読は**ここで1度だけ**畳む。フィルタより後に置くのは、
    // 撤収そのものが生む拒否まで拾うためである。
    //
    // **限界**: ここで止めるので、**daemonが終わる直前の約1秒ぶんは今も取りこぼす**
    // （配送は発生から約1秒後）。埋めるには撤収時の猶予が要るが、それは別の決定である。
    if let Some(audit) = audit.take() {
        audit.teardown();
    }
    outcome.and(residual.map_err(|e| NetfilterError::Ipc(e.to_string())))
}

/// 連鎖起動の結末。**どの分岐も監査シンクへ1行残す**（BUG-093）。
///
/// 「起こした」と「起こそうとして失敗した」を非特権側が区別できないことが、60秒の空待ちの
/// 核だった。ここでは少なくとも**理由が残る**ようにする（B-09: 多段の副作用は到達点を返す）。
///
/// 「親が依頼しなかった」はこの列挙に**入れない**——依頼したかどうかを知っているのは親で、
/// 親側が自分の記録に残す。ここへ入れると、`--policy-learn`を使わない通常のharness実行が
/// 毎回1行ずつ「依頼されませんでした」を書くことになる。
#[derive(Debug, Clone, PartialEq, Eq)]
enum ChainLaunchOutcome {
    /// 収集器の実行ファイルの場所を決められなかった。
    ResolveFailed { error: String },
    /// 1接続につき1回のガードで断った（D-56 段階2より前の制約）。
    RefusedSecondLaunch { pipe: String },
    /// D-44の配置検査（`verify_elevation_target`）が拒否した。
    VerifyRejected { pipe: String, error: String },
    /// `CreateProcessW`そのものが失敗した。
    CreateProcessFailed { pipe: String, error: String },
    /// 起こした。`child`は[`probe_chain_child`]へ渡して閉じる。
    Launched {
        pipe: String,
        pid: u32,
        child: HANDLE,
    },
}

impl ChainLaunchOutcome {
    /// 起動できた場合の子プロセスハンドル。**呼び出し側が必ず[`probe_chain_child`]へ渡す**
    /// （そこで閉じる）。
    fn launched_child(&self) -> Option<HANDLE> {
        match self {
            ChainLaunchOutcome::Launched { child, .. } => Some(*child),
            _ => None,
        }
    }

    /// 応答に載せる要約へ落とす。**エラーの全文は監査シンク側にある**——応答は呼び出し側の
    /// 制御フロー（待つか、自分で起こすか）を決めるためのもので、調査の正本ではない。
    /// それでも`reason`を空にしないのは、非特権側の警告文に「なぜ」を1行出せるようにするため。
    fn to_report(&self) -> ChainLaunchReport {
        match self {
            ChainLaunchOutcome::Launched { pid, .. } => ChainLaunchReport::Launched { pid: *pid },
            other => ChainLaunchReport::Failed {
                reason: chain_launch_reason(other, elevation_escape_hatch_present()),
            },
        }
    }
}

/// 起こした収集器がすぐ死んでいないかの短い観測。
#[derive(Debug, Clone, PartialEq, Eq)]
enum ChainChildProbe {
    /// 観測窓のうちに終了した（＝接続する前に死んだ）。
    Exited { code: u32 },
    /// まだ生きている（正常な状態）。
    StillRunning,
    /// 観測そのものに失敗した。
    ProbeFailed { error: String },
}

/// 起こした子がすぐ死んでいないかを見る窓。**これを超えて待たない**——ここで待つのは
/// 診断のためだけで、収集器は本来ずっと常駐する。`Applied`は送信済みなので親は止まらない。
const CHAIN_CHILD_PROBE: std::time::Duration = std::time::Duration::from_secs(2);

/// 昇格側の逃がし弁（D-44）が**この昇格プロセスの環境に**在るか。
///
/// **親のシェルではなく自分の環境を測る**ことが要点である。`runas`（AppInfo）で起きた
/// プロセスが呼び出し元の環境ブロックを引き継ぐとは限らず、BUG-093の最有力仮説は
/// まさにそこにある。親側で測ると、測定対象を取り違える（B-29）。
fn elevation_escape_hatch_present() -> bool {
    std::env::var_os(crate::elevated_launch::ALLOW_USER_WRITABLE_HELPERS_ENV).is_some()
}

/// 連鎖起動の結末を、監査シンクへ書く1行の理由文字列にする。
///
/// **純関数**にしてあるのは、実機・管理者権限なしで全分岐の文言を固定できるようにするため。
/// 接頭辞`policy_learnd_chain_`は機械可読なマーカーで、調査時に`rg`で1行に絞れる。
fn chain_launch_reason(outcome: &ChainLaunchOutcome, env_present: bool) -> String {
    match outcome {
        ChainLaunchOutcome::ResolveFailed { error } => format!(
            "policy_learnd_chain_resolve_failed env_present={env_present}: {error}"
        ),
        ChainLaunchOutcome::RefusedSecondLaunch { pipe } => format!(
            "policy_learnd_chain_refused_second_launch pipe={pipe} env_present={env_present}"
        ),
        ChainLaunchOutcome::VerifyRejected { pipe, error } => format!(
            "policy_learnd_chain_verify_rejected pipe={pipe} env_present={env_present}: {error}"
        ),
        ChainLaunchOutcome::CreateProcessFailed { pipe, error } => format!(
            "policy_learnd_chain_createprocess_failed pipe={pipe} env_present={env_present}: {error}"
        ),
        ChainLaunchOutcome::Launched { pipe, pid, .. } => format!(
            "policy_learnd_chain_launched pipe={pipe} pid={pid} env_present={env_present}"
        ),
    }
}

/// 子プロセスの短時間観測の結果を1行の理由文字列にする（[`chain_launch_reason`]と同じ理由で純関数）。
fn chain_child_reason(probe: &ChainChildProbe) -> String {
    match probe {
        ChainChildProbe::Exited { code } => {
            format!("policy_learnd_chain_child_exited code={code:#010x}")
        }
        ChainChildProbe::StillRunning => "policy_learnd_chain_child_alive".to_string(),
        ChainChildProbe::ProbeFailed { error } => {
            format!("policy_learnd_chain_child_probe_failed: {error}")
        }
    }
}

/// 結末を監査シンクへ書き、同時にstderrにも出す（stderrは`SW_HIDE`で見えないが、
/// `harness-netfilterd.exe`を手で前面起動して調べるときのために残す）。
fn record_chain_launch(audit_sink: Option<&std::path::Path>, outcome: &ChainLaunchOutcome) {
    let reason = chain_launch_reason(outcome, elevation_escape_hatch_present());
    eprintln!("harness-netfilterd: {reason}");
    // シンクが無い＝親が`audit_log_path`か`workspace_root`を送っていない。この場合は
    // **書ける先が無い**（検証していないパスへは書かない、D-44）。
    if let Some(path) = audit_sink {
        crate::tier2a::wfp::record_control_event(path, reason);
    }
}

fn record_chain_child_probe(audit_sink: Option<&std::path::Path>, probe: &ChainChildProbe) {
    let reason = chain_child_reason(probe);
    eprintln!("harness-netfilterd: {reason}");
    if let Some(path) = audit_sink {
        crate::tier2a::wfp::record_control_event(path, reason);
    }
}

/// 起こした子が観測窓のうちに死んでいないかを見て、**ハンドルを閉じる**。
unsafe fn probe_chain_child(child: HANDLE) -> ChainChildProbe {
    let wait = WaitForSingleObject(child, CHAIN_CHILD_PROBE.as_millis() as u32);
    let probe = if wait == WAIT_OBJECT_0 {
        let mut code = 0u32;
        match windows::Win32::System::Threading::GetExitCodeProcess(child, &mut code) {
            Ok(()) => ChainChildProbe::Exited { code },
            Err(e) => ChainChildProbe::ProbeFailed {
                error: format!("GetExitCodeProcess failed: {e}"),
            },
        }
    } else {
        // タイムアウト（＝まだ生きている）が正常。それ以外の戻り値も「終了は観測できなかった」
        // として同じ扱いにはせず、値を残す。
        match wait {
            windows::Win32::Foundation::WAIT_TIMEOUT => ChainChildProbe::StillRunning,
            other => ChainChildProbe::ProbeFailed {
                error: format!("WaitForSingleObject returned {:#010x}", other.0),
            },
        }
    };
    let _ = CloseHandle(child);
    probe
}

/// 昇格済みトークンのまま`harness-policy-learnd.exe`を子として起動する（M15.7）。
///
/// `ShellExecuteExW(runas)`は使わない——既に管理者トークンを持つプロセスからの通常の
/// `CreateProcessW`はそのトークンを子へ継承させるため、2回目のUACが出ない。これが
/// この経路の存在理由そのものである（`privhelper`→`netfilterd`と同じ構図）。
///
/// **UACを出さない経路なので、差し替えられた実行ファイルはユーザーの目に触れずに管理者として走る。**
/// したがってD-44の配置検査はここでも落とせない。
///
/// 戻り値は[`ChainLaunchOutcome`]で、**失敗も成功も同じ粒度で表す**——呼び出し側が
/// 「どこまで行ったか」を監査シンクへ残せるようにするため（BUG-093）。
/// `Launched`のプロセスハンドルは呼び出し側が[`probe_chain_child`]へ渡して閉じる。
unsafe fn launch_policy_learnd_chained(pipe_name: &str) -> ChainLaunchOutcome {
    launch_sibling_helper_chained("harness-policy-learnd.exe", pipe_name)
}

/// **兄弟ヘルパーを1つ、昇格トークンのまま連鎖起動する**（D-60で共有化した実体）。
///
/// `exe_name`は**呼び出し側が持つ固定値**で、IPCから来た文字列を渡してはいけない
/// （[`SiblingHelper::exe_name`]／[`launch_policy_learnd_chained`]がその唯一の供給元）。
/// 収集器とprivhelperで2つ実装を持つと、片方だけがD-44検査や結末の記録を失う（B-05）。
unsafe fn launch_sibling_helper_chained(exe_name: &str, pipe_name: &str) -> ChainLaunchOutcome {
    let collector = match std::env::current_exe()
        .map_err(|e| format!("failed to resolve current exe: {e}"))
        .and_then(|current| {
            current
                .parent()
                .map(|dir| dir.join(exe_name))
                .ok_or_else(|| "current exe has no parent directory".to_string())
        }) {
        Ok(path) => path,
        Err(error) => return ChainLaunchOutcome::ResolveFailed { error },
    };

    if let Err(e) = crate::elevated_launch::verify_elevation_target(&collector) {
        return ChainLaunchOutcome::VerifyRejected {
            pipe: pipe_name.to_string(),
            error: e.to_string(),
        };
    }

    // 第0引数（実行ファイルパス）はCreateProcessWの規約上quoteが要る。
    let cmdline = format!("\"{}\" {}", collector.display(), pipe_name);
    let mut cmdline_w = wide(&cmdline);
    let startup_info = windows::Win32::System::Threading::STARTUPINFOW {
        cb: std::mem::size_of::<windows::Win32::System::Threading::STARTUPINFOW>() as u32,
        dwFlags: windows::Win32::System::Threading::STARTF_USESHOWWINDOW,
        wShowWindow: SW_HIDE.0 as u16,
        ..Default::default()
    };
    let mut process_info = windows::Win32::System::Threading::PROCESS_INFORMATION::default();
    if let Err(e) = windows::Win32::System::Threading::CreateProcessW(
        PCWSTR::null(),
        windows::core::PWSTR(cmdline_w.as_mut_ptr()),
        None,
        None,
        false,
        windows::Win32::System::Threading::PROCESS_CREATION_FLAGS(0),
        None,
        PCWSTR::null(),
        &startup_info as *const _,
        &mut process_info,
    ) {
        return ChainLaunchOutcome::CreateProcessFailed {
            pipe: pipe_name.to_string(),
            error: format!("CreateProcessW failed: {e}"),
        };
    }

    // 収集器はharnessセッションの生存期間中、独立して常駐する。**プロセスハンドルだけは
    // 短時間残す**——「起こしたが接続前に死んだ」を観測するため（`probe_chain_child`が閉じる）。
    let _ = CloseHandle(process_info.hThread);
    ChainLaunchOutcome::Launched {
        pipe: pipe_name.to_string(),
        pid: process_info.dwProcessId,
        child: process_info.hProcess,
    }
}

fn send_response(pipe: HANDLE, resp: &NetfilterResponse) -> Result<(), NetfilterError> {
    let bytes = serde_json::to_vec(resp)
        .map_err(|e| NetfilterError::Ipc(format!("failed to serialize response: {e}")))?;
    write_framed_timeout(pipe, &bytes, TEARDOWN_RESPONSE_TIMEOUT)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **応答のワイヤ形式を固定する**（B-24）。`harness-netfilterd.exe`は別プロセスとして
    /// このJSONを書くので、綴りが変われば版ずれで通信できなくなる。
    ///
    /// `Applied`はBUG-093の修正でunit variantからstruct variantへ変えた。**旧形式の
    /// 文字列`"Applied"`は読めなくなる**——兄弟バイナリは常に同時ビルドされるという前提に
    /// 乗った変更であり、その前提をここに書き留めておく。
    #[test]
    fn apply_rules_response_json_wire_format_is_stable() {
        assert_eq!(
            serde_json::to_string(&NetfilterResponse::Applied { chain_launch: None }).unwrap(),
            r#"{"Applied":{"chain_launch":null}}"#
        );
        assert_eq!(
            serde_json::to_string(&NetfilterResponse::Applied {
                chain_launch: Some(ChainLaunchReport::Launched { pid: 4242 })
            })
            .unwrap(),
            r#"{"Applied":{"chain_launch":{"Launched":{"pid":4242}}}}"#
        );
        assert_eq!(
            serde_json::to_string(&NetfilterResponse::Applied {
                chain_launch: Some(ChainLaunchReport::Failed {
                    reason: "nope".to_string()
                })
            })
            .unwrap(),
            r#"{"Applied":{"chain_launch":{"Failed":{"reason":"nope"}}}}"#
        );
        // 項目を持たない`{"Applied":{}}`は`#[serde(default)]`で読める（依頼していない扱い）。
        let decoded: NetfilterResponse = serde_json::from_str(r#"{"Applied":{}}"#).unwrap();
        assert_eq!(decoded, NetfilterResponse::Applied { chain_launch: None });
        // 他のvariantの綴りは変えていない。
        assert_eq!(
            serde_json::to_string(&NetfilterResponse::Cleared).unwrap(),
            r#""Cleared""#
        );
        assert_eq!(
            serde_json::to_string(&NetfilterResponse::TornDown).unwrap(),
            r#""TornDown""#
        );
    }

    /// D-60の新オペコードのワイヤ形式を固定する（B-24）。**実行ファイル名はワイヤに載らない**
    /// ——載せると親が任意パスを指定できてしまうので、`helper`の列挙から昇格側が導出する。
    #[test]
    fn chain_launch_helper_json_wire_format_is_stable() {
        let req = NetfilterRequest::ChainLaunchHelper {
            helper: SiblingHelper::Privhelper,
            pipe_name: r"\\.\pipe\harness-privhelper-1-0-2".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            json,
            r#"{"ChainLaunchHelper":{"helper":"Privhelper","pipe_name":"\\\\.\\pipe\\harness-privhelper-1-0-2"}}"#
        );
        assert!(
            !json.contains(".exe"),
            "実行ファイル名がワイヤに載ってはいけない: {json}"
        );
        let decoded: NetfilterRequest = serde_json::from_str(&json).unwrap();
        match decoded {
            NetfilterRequest::ChainLaunchHelper { helper, pipe_name } => {
                assert_eq!(helper, SiblingHelper::Privhelper);
                assert_eq!(pipe_name, r"\\.\pipe\harness-privhelper-1-0-2");
            }
            other => panic!("unexpected: {other:?}"),
        }

        assert_eq!(
            serde_json::to_string(&NetfilterResponse::HelperLaunched(
                ChainLaunchReport::Launched { pid: 9 }
            ))
            .unwrap(),
            r#"{"HelperLaunched":{"Launched":{"pid":9}}}"#
        );

        // 収集器も同じオペコードで起こせる（起動時前倒しでdaemonが常駐すると、
        // `ApplyRules`相乗りの経路が使えなくなるため）。**実行ファイル名は載らない。**
        let learn = serde_json::to_string(&NetfilterRequest::ChainLaunchHelper {
            helper: SiblingHelper::PolicyLearnd,
            pipe_name: r"\\.\pipe\harness-policy-learnd-1-0-2".to_string(),
        })
        .unwrap();
        assert_eq!(
            learn,
            r#"{"ChainLaunchHelper":{"helper":"PolicyLearnd","pipe_name":"\\\\.\\pipe\\harness-policy-learnd-1-0-2"}}"#
        );
        assert!(!learn.contains(".exe"), "{learn}");
    }

    /// 起動時前倒しのワイヤ形式（B-24）。**別プロセスが読む契約**なので綴りを固定する。
    #[test]
    fn standby_json_wire_format_is_stable() {
        assert_eq!(
            serde_json::to_string(&NetfilterRequest::Standby).unwrap(),
            r#""Standby""#
        );
        assert_eq!(
            serde_json::to_string(&NetfilterResponse::Standing).unwrap(),
            r#""Standing""#
        );
        let decoded: NetfilterRequest = serde_json::from_str(r#""Standby""#).unwrap();
        assert!(matches!(decoded, NetfilterRequest::Standby));

        // **`Standby`は何も運ばない。** ポリシーを載せられる形にすると、「起こすだけ」という
        // 意味が薄れて`ApplyRules`と役割が重なる（D-56「自由形式は1つも増やさない」）。
        assert!(!serde_json::to_string(&NetfilterRequest::Standby)
            .unwrap()
            .contains(':'));
    }

    /// 昇格側が導出する実行ファイル名は**固定名で、`SiblingHelper`ごとに1つ**。
    #[test]
    fn each_sibling_helper_maps_to_one_fixed_exe_name() {
        // **列挙のすべてを書く。** 実行ファイル名はワイヤに載らない＝昇格側が持つ唯一の値なので、
        // ここが綴りの正本になる（間違えると昇格側が別の実行ファイルを起こす）。
        let all = [SiblingHelper::Privhelper, SiblingHelper::PolicyLearnd];
        assert_eq!(
            all.map(|h| h.exe_name()),
            ["harness-privhelper.exe", "harness-policy-learnd.exe"]
        );
        // 同じexeへ2つの列挙子が向かないこと（向いていたら列挙で閉じる意味が無い）。
        let mut names: Vec<&str> = all.iter().map(|h| h.exe_name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), all.len());
    }

    /// **「起こした」だけが待ってよい状態である。**
    ///
    /// この真理値表が`Applied`の意味そのもので、これが崩れると呼び出し側は起きていない
    /// 収集器の接続を60秒待つ（BUG-093の症状）。「依頼していない（`None`）」も偽側に入るのが
    /// 要点——**呼び出し側は自分で起こす必要がある、という点で失敗と同じ扱いで正しい**。
    #[test]
    fn only_a_launched_report_tells_the_caller_it_may_wait_for_the_collector() {
        let launched = Applied {
            reused: false,
            chain_launch: Some(ChainLaunchReport::Launched { pid: 7 }),
        };
        let failed = Applied {
            reused: false,
            chain_launch: Some(ChainLaunchReport::Failed {
                reason: "verify rejected".to_string(),
            }),
        };
        let not_requested = Applied {
            reused: true,
            chain_launch: None,
        };

        assert!(launched.collector_chain_launched());
        assert!(!failed.collector_chain_launched());
        assert!(
            !not_requested.collector_chain_launched(),
            "依頼していない場合も「自分で起こす」側へ倒す（待つと必ずタイムアウトする）"
        );
    }

    // --- 連鎖起動の結末の記録（BUG-093）-------------------------------------
    //
    // 昇格側の`eprintln!`は`SW_HIDE`のコンソールへ消えるため、監査シンクへ書く1行が
    // 唯一の伝達路である。**文言そのものが機構の出力**なので、全分岐を純関数として固定する。

    /// どの分岐も`policy_learnd_chain_`で始まる——調査時に`rg`で1行に絞れることが要件。
    #[test]
    fn every_chain_launch_outcome_is_greppable_by_a_common_prefix() {
        let outcomes = [
            ChainLaunchOutcome::ResolveFailed {
                error: "no parent".to_string(),
            },
            ChainLaunchOutcome::RefusedSecondLaunch {
                pipe: r"\\.\pipe\p".to_string(),
            },
            ChainLaunchOutcome::VerifyRejected {
                pipe: r"\\.\pipe\p".to_string(),
                error: "writable".to_string(),
            },
            ChainLaunchOutcome::CreateProcessFailed {
                pipe: r"\\.\pipe\p".to_string(),
                error: "boom".to_string(),
            },
            ChainLaunchOutcome::Launched {
                pipe: r"\\.\pipe\p".to_string(),
                pid: 4242,
                child: HANDLE::default(),
            },
        ];

        for outcome in &outcomes {
            let reason = chain_launch_reason(outcome, false);
            assert!(
                reason.starts_with("policy_learnd_chain_"),
                "{outcome:?} -> {reason}"
            );
        }
        // 5分岐が5通りの文言になる（どれかが同じ綴りだと区別が付かない）。
        let reasons: std::collections::BTreeSet<String> = outcomes
            .iter()
            .map(|o| chain_launch_reason(o, false))
            .collect();
        assert_eq!(reasons.len(), outcomes.len());
    }

    /// **H1（環境変数が昇格側へ届いていない）を1行で決める**ための項目。
    /// `verify_elevation_target`の拒否理由と`env_present`が同じ行に載る。
    #[test]
    fn a_rejected_verification_records_the_error_and_whether_the_escape_hatch_was_visible() {
        let outcome = ChainLaunchOutcome::VerifyRejected {
            pipe: r"\\.\pipe\policy-learnd-1".to_string(),
            error: "target\\debug is writable by S-1-5-32-545".to_string(),
        };

        let without = chain_launch_reason(&outcome, false);
        assert!(
            without.contains("policy_learnd_chain_verify_rejected"),
            "{without}"
        );
        assert!(without.contains("env_present=false"), "{without}");
        assert!(
            without.contains("S-1-5-32-545"),
            "理由の全文を残す: {without}"
        );

        let with = chain_launch_reason(&outcome, true);
        assert!(with.contains("env_present=true"), "{with}");
    }

    /// 成功した場合もpidとパイプ名を残す——親側の記録と突き合わせて「同じ要求の話をしている」
    /// ことを確かめられるようにするため。
    #[test]
    fn a_successful_launch_records_the_pid_and_the_pipe_it_was_told_to_use() {
        let reason = chain_launch_reason(
            &ChainLaunchOutcome::Launched {
                pipe: r"\\.\pipe\policy-learnd-7".to_string(),
                pid: 1234,
                child: HANDLE::default(),
            },
            true,
        );

        assert!(reason.contains("pid=1234"), "{reason}");
        assert!(
            reason.contains(r"pipe=\\.\pipe\policy-learnd-7"),
            "{reason}"
        );
    }

    /// **H2（起こせたが接続前に死んだ）と「生きている」を書き分ける。**
    /// 同じ文言になると、収集器が死んだのかパイプ接続で詰まったのかを区別できない。
    #[test]
    fn the_child_probe_distinguishes_an_early_exit_from_a_live_collector() {
        let exited = chain_child_reason(&ChainChildProbe::Exited { code: 101 });
        let alive = chain_child_reason(&ChainChildProbe::StillRunning);
        let failed = chain_child_reason(&ChainChildProbe::ProbeFailed {
            error: "handle closed".to_string(),
        });

        assert!(
            exited.contains("policy_learnd_chain_child_exited"),
            "{exited}"
        );
        assert!(exited.contains("0x00000065"), "終了コードを残す: {exited}");
        assert_eq!(alive, "policy_learnd_chain_child_alive");
        assert!(
            failed.contains("policy_learnd_chain_child_probe_failed"),
            "{failed}"
        );
        assert_ne!(exited, alive);
    }

    /// `Launched`だけがプロセスハンドルを持つ——失敗分岐で`probe_chain_child`を呼ぶと
    /// 無効ハンドルを待つことになる。
    #[test]
    fn only_a_successful_launch_yields_a_child_handle_to_probe() {
        assert!(ChainLaunchOutcome::Launched {
            pipe: "p".to_string(),
            pid: 1,
            child: HANDLE::default(),
        }
        .launched_child()
        .is_some());
        assert!(ChainLaunchOutcome::VerifyRejected {
            pipe: "p".to_string(),
            error: "e".to_string(),
        }
        .launched_child()
        .is_none());
        assert!(ChainLaunchOutcome::RefusedSecondLaunch {
            pipe: "p".to_string(),
        }
        .launched_child()
        .is_none());
    }

    #[test]
    fn apply_rules_request_roundtrips_through_json() {
        let req = NetfilterRequest::ApplyRules(NetfilterPolicy {
            session_profile: "harness.shell.sandbox.1234-5678".to_string(),
            allow_loopback_tcp_ports: vec![18080, 18053],
            allow_loopback_udp_ports: vec![18053],
            audit_log_path: Some(PathBuf::from(".harness/sandbox/session-x/net-audit.jsonl")),
            mcp_profiles: Vec::new(),
            workspace_root: None,
            chain_launch_policy_learnd: None,
        });
        let bytes = serde_json::to_vec(&req).unwrap();
        let decoded: NetfilterRequest = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            NetfilterRequest::ApplyRules(NetfilterPolicy {
                session_profile,
                allow_loopback_tcp_ports,
                allow_loopback_udp_ports,
                audit_log_path,
                mcp_profiles: _,
                workspace_root: _,
                chain_launch_policy_learnd: _,
            }) => {
                assert_eq!(session_profile, "harness.shell.sandbox.1234-5678");
                assert_eq!(allow_loopback_tcp_ports, vec![18080, 18053]);
                assert_eq!(allow_loopback_udp_ports, vec![18053]);
                assert_eq!(
                    audit_log_path,
                    Some(PathBuf::from(".harness/sandbox/session-x/net-audit.jsonl"))
                );
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    /// `NetfilterRequest`のJSON表現そのものを固定する。上の往復テストは encode→decode が
    /// 対称でありさえすれば通るため、ワイヤ形式が変わったことを検出できない。この列挙型は
    /// 別プロセス（`harness-netfilterd`）との名前付きパイプIPCで交換される境界の形なので、
    /// 表現を変えるときは意図的な変更であることがここで分かるようにする。
    #[test]
    fn apply_rules_request_json_wire_format_is_stable() {
        let req = NetfilterRequest::ApplyRules(NetfilterPolicy {
            session_profile: "harness.shell.sandbox.1-2".to_string(),
            allow_loopback_tcp_ports: vec![18080],
            allow_loopback_udp_ports: vec![18053],
            audit_log_path: Some(PathBuf::from("net-audit.jsonl")),
            mcp_profiles: vec![McpNetfilterPolicy {
                profile: "harness.mcp.1-2.docs".to_string(),
                allow_loopback_tcp_ports: vec![19090],
                allow_loopback_udp_ports: vec![],
            }],
            workspace_root: None,
            chain_launch_policy_learnd: None,
        });
        // D-37で`session_profile`を先頭へ追加した（昇格側はこの名前を検証してからSIDを導出する）。
        // D-38（M15.5）で`mcp_profiles`を、M15.7（D-44）で`workspace_root`を、いずれも**末尾へ**
        // 追加した——既存フィールドの位置を動かすと、旧`harness-netfilterd.exe`との組み合わせで
        // 静かに壊れる。`workspace_root`は`audit_log_path`を受信側で検証するためだけに運ぶ。
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"ApplyRules":{"session_profile":"harness.shell.sandbox.1-2","allow_loopback_tcp_ports":[18080],"allow_loopback_udp_ports":[18053],"audit_log_path":"net-audit.jsonl","mcp_profiles":[{"profile":"harness.mcp.1-2.docs","allow_loopback_tcp_ports":[19090],"allow_loopback_udp_ports":[]}],"workspace_root":null,"chain_launch_policy_learnd":null}}"#
        );
        assert_eq!(
            serde_json::to_string(&NetfilterRequest::Teardown).unwrap(),
            r#""Teardown""#
        );
    }

    /// **D-56**: ループ化で足した`ClearRules`/`Cleared`のワイヤ表現を固定する。
    /// `NetfilterPolicy`のフィールドを1つも触っていない以上、既存の表現も変わってはいけない
    /// （上の`apply_rules_request_json_wire_format_is_stable`が無改変で通ることがその確認）。
    #[test]
    fn clear_rules_request_and_response_wire_format_is_stable() {
        assert_eq!(
            serde_json::to_string(&NetfilterRequest::ClearRules).unwrap(),
            r#""ClearRules""#
        );
        assert_eq!(
            serde_json::to_string(&NetfilterResponse::Cleared).unwrap(),
            r#""Cleared""#
        );
        let decoded: NetfilterRequest = serde_json::from_str(r#""ClearRules""#).unwrap();
        assert!(matches!(decoded, NetfilterRequest::ClearRules));
    }

    /// 再利用中の`ApplyRules`が失敗したとき、起こし直す／伝播するの分け方を固定する
    /// （[`NetfilterSession::apply`]の再試行方針そのもの）。
    ///
    /// **`Rejected`だけが「daemonは生きている」側**である。ここが逆になると、
    /// 回復不能な拒否のたびにUACが1回出て、しかも同じ拒否に着く。
    #[test]
    fn only_a_rejected_response_means_the_daemon_is_still_alive() {
        assert!(!daemon_is_dead(&NetfilterError::Rejected("nope".into())));
        assert!(daemon_is_dead(&NetfilterError::Ipc("broken pipe".into())));
        assert!(daemon_is_dead(&NetfilterError::Win32("boom".into())));
        assert!(daemon_is_dead(&NetfilterError::ElevationDeclined(
            "canceled".into()
        )));
    }

    /// MCPサーバを1つも使わない（＝これまでどおりの）起動では、`mcp_profiles`が空配列として
    /// 載るだけで他は一切変わらない。
    #[test]
    fn a_policy_without_mcp_servers_keeps_the_previous_shape_plus_an_empty_list() {
        let req = NetfilterRequest::ApplyRules(NetfilterPolicy {
            session_profile: "harness.shell.sandbox.1-2".to_string(),
            allow_loopback_tcp_ports: vec![18080],
            allow_loopback_udp_ports: vec![18053],
            audit_log_path: None,
            mcp_profiles: Vec::new(),
            workspace_root: None,
            chain_launch_policy_learnd: None,
        });
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"ApplyRules":{"session_profile":"harness.shell.sandbox.1-2","allow_loopback_tcp_ports":[18080],"allow_loopback_udp_ports":[18053],"audit_log_path":null,"mcp_profiles":[],"workspace_root":null,"chain_launch_policy_learnd":null}}"#
        );
    }

    /// `mcp_profiles`を知らない旧クライアントのJSONも読める（`#[serde(default)]`）。
    #[test]
    fn a_request_without_mcp_profiles_still_deserializes() {
        let legacy = r#"{"ApplyRules":{"session_profile":"harness.shell.sandbox.1-2","allow_loopback_tcp_ports":[18080],"allow_loopback_udp_ports":[],"audit_log_path":null}}"#;
        let decoded: NetfilterRequest = serde_json::from_str(legacy).unwrap();
        match decoded {
            NetfilterRequest::ApplyRules(policy) => assert!(policy.mcp_profiles.is_empty()),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    /// **M15.7 / D-44**: `workspace_root`を運ぶ要求では、`audit_log_path`が
    /// `<workspace_root>/.harness/sandbox/`配下に限定される。ここが緩むと、非昇格の親が
    /// 昇格daemonに任意パスへ追記させられる（管理者権限での任意パス追記プリミティブ）。
    ///
    /// `serve_inner`はWin32ハンドルを要求するので直接は呼べない。判定の実体である
    /// `validate_audit_sink_path`を、`serve_inner`が渡すのと同じ組み合わせで確かめる。
    #[test]
    fn the_audit_sink_path_is_constrained_to_the_declared_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path();
        std::fs::create_dir_all(workspace.join(".harness").join("sandbox").join("session-x"))
            .unwrap();

        let good = workspace
            .join(".harness")
            .join("sandbox")
            .join("session-x")
            .join("net-audit.jsonl");
        assert!(crate::elevated_launch::validate_audit_sink_path(&good, workspace).is_ok());

        // 親が「ここへ書け」と言っても、workspace外なら昇格側が拒否する。
        for evil in [
            std::path::PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts"),
            workspace.join(".git").join("config"),
            workspace.join(".harness").join("settings.json"),
        ] {
            assert!(
                crate::elevated_launch::validate_audit_sink_path(&evil, workspace).is_err(),
                "{} must be rejected as an audit sink",
                evil.display()
            );
        }
    }

    /// D-38: `run_shell`セッションとMCPサーバは、WFPから見れば同じ「SID＋許可ポート」の形へ
    /// 均される。順序は`session_profile`が先で、以降は宣言順。
    #[test]
    fn policy_targets_flattens_the_session_and_every_mcp_server() {
        let policy = NetfilterPolicy {
            session_profile: "harness.shell.sandbox.1-2".to_string(),
            allow_loopback_tcp_ports: vec![18080],
            allow_loopback_udp_ports: vec![18053],
            audit_log_path: None,
            mcp_profiles: vec![
                McpNetfilterPolicy {
                    profile: "harness.mcp.1-2.docs".to_string(),
                    allow_loopback_tcp_ports: vec![19090],
                    allow_loopback_udp_ports: vec![],
                },
                McpNetfilterPolicy {
                    profile: "harness.mcp.1-2.jira".to_string(),
                    allow_loopback_tcp_ports: vec![19091],
                    allow_loopback_udp_ports: vec![],
                },
            ],
            workspace_root: None,
            chain_launch_policy_learnd: None,
        };
        let targets = policy_targets(&policy);
        assert_eq!(
            targets
                .iter()
                .map(|t| t.profile.as_str())
                .collect::<Vec<_>>(),
            vec![
                "harness.shell.sandbox.1-2",
                "harness.mcp.1-2.docs",
                "harness.mcp.1-2.jira"
            ]
        );
        // サーバごとに許可ポートが違う＝サーバ別の宛先allowlistになっている（§3.2）。
        assert_eq!(targets[1].tcp_ports, vec![19090]);
        assert_eq!(targets[2].tcp_ports, vec![19091]);
    }

    /// **信頼境界**: 昇格側は、渡された名前がharness由来のプロファイルの形であることを
    /// 確認してからSIDを導出する。この判定が緩むと任意のAppContainerへフィルタを張れる。
    #[test]
    fn only_harness_profile_names_are_accepted_by_the_elevated_side() {
        use crate::tier2a::mcp_profile::is_harness_profile_name;
        assert!(is_harness_profile_name("harness.shell.sandbox.1-2"));
        assert!(is_harness_profile_name("harness.mcp.1-2.docs"));
        for bad in [
            "",
            "harness.shell.sandbox",
            "harness.mcp",
            "windows.immersivecontrolpanel",
        ] {
            assert!(!is_harness_profile_name(bad), "should reject {bad:?}");
        }
    }

    #[test]
    fn teardown_request_roundtrips_through_json() {
        let bytes = serde_json::to_vec(&NetfilterRequest::Teardown).unwrap();
        let decoded: NetfilterRequest = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(decoded, NetfilterRequest::Teardown));
    }

    #[test]
    fn responses_roundtrip_through_json() {
        for resp in [
            NetfilterResponse::Applied { chain_launch: None },
            NetfilterResponse::Applied {
                chain_launch: Some(ChainLaunchReport::Launched { pid: 4242 }),
            },
            NetfilterResponse::Applied {
                chain_launch: Some(ChainLaunchReport::Failed {
                    reason: "nope".to_string(),
                }),
            },
            NetfilterResponse::TornDown,
            NetfilterResponse::Err("boom".to_string()),
        ] {
            let bytes = serde_json::to_vec(&resp).unwrap();
            let decoded: NetfilterResponse = serde_json::from_slice(&bytes).unwrap();
            match (&resp, &decoded) {
                (
                    NetfilterResponse::Applied { chain_launch: a },
                    NetfilterResponse::Applied { chain_launch: b },
                ) => assert_eq!(a, b),
                (NetfilterResponse::TornDown, NetfilterResponse::TornDown) => {}
                (NetfilterResponse::Err(a), NetfilterResponse::Err(b)) => assert_eq!(a, b),
                _ => panic!("roundtrip mismatch: {resp:?} vs {decoded:?}"),
            }
        }
    }

    #[test]
    fn malformed_bytes_are_rejected_not_panicking() {
        let garbage = b"{\"not\":\"a valid NetfilterRequest\"}";
        let result = serde_json::from_slice::<NetfilterRequest>(garbage);
        assert!(result.is_err());
    }

    /// R-02で削除した旧IPC互換フィールド（`allow_domains`・`allow_loopback`・
    /// `allow_direct_dns`）だけを持つ、実在しない旧クライアントのJSONを渡しても、
    /// 未知フィールドとして無視されて読める（壊れない）ことを確認する
    /// （`docs/STATUS.md` R-02、削除の根拠）。
    #[test]
    fn apply_rules_request_ignores_removed_legacy_fields_in_json() {
        let legacy =
            r#"{"ApplyRules":{"allow_domains":[],"allow_loopback":true,"allow_direct_dns":false}}"#;
        let decoded: NetfilterRequest = serde_json::from_str(legacy).unwrap();
        match decoded {
            NetfilterRequest::ApplyRules(NetfilterPolicy {
                session_profile,
                allow_loopback_tcp_ports,
                allow_loopback_udp_ports,
                audit_log_path,
                mcp_profiles,
                workspace_root,
                chain_launch_policy_learnd,
            }) => {
                // 名前が欠落したJSONは空文字として読める。空文字は
                // `is_harness_profile_name`が拒否するので、`serve_inner`はfail-closedになる。
                assert!(session_profile.is_empty());
                assert!(allow_loopback_tcp_ports.is_empty());
                assert!(allow_loopback_udp_ports.is_empty());
                // `workspace_root`が無い旧形式。`serve_inner`はこの場合、監査ログを無効化して
                // 続行する（任意パス追記を閉じつつ、WFPの出口強制そのものは落とさない）。
                assert_eq!(workspace_root, None);
                assert_eq!(chain_launch_policy_learnd, None);
                assert_eq!(audit_log_path, None);
                assert!(mcp_profiles.is_empty());
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    fn short_timeout() -> std::time::Duration {
        std::time::Duration::from_secs(5)
    }

    /// パイプの配線を、昇格・別プロセス起動なしで検証する（`privhelper.rs`の同名テストと
    /// 同じ手法。WFP呼び出し自体は含まない、実機E2Eで別途検証する）。
    #[test]
    fn framed_message_roundtrips_over_a_real_named_pipe() {
        let pipe_name = unique_pipe_name();
        let sid = current_user_sid_string().expect("current_user_sid_string");
        let mut sa = user_only_security_attributes(&sid).expect("user_only_security_attributes");

        let server = unsafe {
            let pipe_name_w = wide(&pipe_name);
            let handle = CreateNamedPipeW(
                PCWSTR(pipe_name_w.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                Some(&mut sa as *mut _),
            );
            let _ = LocalFree(HLOCAL(sa.lpSecurityDescriptor));
            assert!(!handle.is_invalid());
            handle
        };

        let pipe_name_for_client = pipe_name.clone();
        let client_thread = std::thread::spawn(move || unsafe {
            let pipe_name_w = wide(&pipe_name_for_client);
            CreateFileW(
                PCWSTR(pipe_name_w.as_ptr()),
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                None,
            )
            .expect("client CreateFileW")
            .0 as usize
        });

        connect_with_timeout(server, short_timeout()).expect("connect_with_timeout");
        let client = HANDLE(client_thread.join().unwrap() as *mut _);

        write_framed_timeout(client, b"hello from client", short_timeout())
            .expect("write_framed_timeout");
        let received = read_framed_timeout(server, short_timeout()).expect("read_framed_timeout");
        assert_eq!(received, b"hello from client");

        unsafe {
            let _ = DisconnectNamedPipe(server);
            let _ = CloseHandle(server);
            let _ = CloseHandle(client);
        }
    }
}

/// **D-56のプロトコル（要求の連続）を、昇格もWFPも使わずに検証する。**
///
/// クライアント側（[`NetfilterSession`]）は偽daemonを相手に、daemon側（`serve_inner`）は
/// **WFPへ一度も触らない要求だけ**（`ClearRules`・`Teardown`——どちらも適用済みフィルタが
/// 0件なら`teardown_generation`が空のVecを回すだけ）を相手に測る。`ApplyRules`が実際に
/// フィルタを張る／畳むところは管理者権限が要るので[`super::reuse_e2e`]が持つ。
#[cfg(windows)]
#[cfg(test)]
mod protocol_tests {
    use super::*;

    fn short_timeout() -> std::time::Duration {
        std::time::Duration::from_secs(10)
    }

    fn test_policy(tcp_port: u16) -> NetfilterPolicy {
        NetfilterPolicy {
            session_profile: crate::tier2a::session_profile::current_profile_name(),
            allow_loopback_tcp_ports: vec![tcp_port],
            ..Default::default()
        }
    }

    /// 偽daemonの振る舞い。**再利用が失敗する2通りを撃ち分けるために分けてある**
    /// （`daemon_is_dead`の表と対応する）。
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum FakeBehavior {
        /// 実daemonと同じ応答を返す（WFPは触らない）。
        Normal,
        /// 2件目以降の`ApplyRules`へ`Err`を返す＝**daemonは生きていて拒んだ**。
        RejectAfterFirstApply,
        /// 2件目以降の`ApplyRules`に答えずパイプを閉じる＝**daemonが死んだ**。
        DieAfterFirstApply,
        /// **1件目**の`ApplyRules`へ`Err`を返す＝初回ハンドシェイクでの拒否。
        /// daemonは生きたまま次の要求を待つ（実daemonの`serve_inner`と同じ）。
        RejectFirstApply,
        /// **1件目**の`ApplyRules`に答えずパイプを閉じる＝起こしたが死んだ。
        DieOnFirstApply,
    }

    /// 偽daemonを起こし、（まだ接続していない）サーバ側パイプと、受け取った要求の記録を返す。
    ///
    /// 実daemonと同じくクライアントとして接続してくる（`serve`と同じ`CreateFileW`）。
    fn spawn_fake_daemon(
        behavior: FakeBehavior,
    ) -> (PreparedPipe, std::thread::JoinHandle<Vec<&'static str>>) {
        let prepared = prepare_pipe().expect("prepare_pipe");
        let name = prepared.name().to_string();
        let join = std::thread::spawn(move || {
            let client = unsafe {
                let name_w = wide(&name);
                CreateFileW(
                    PCWSTR(name_w.as_ptr()),
                    (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                    windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                    None,
                )
                .expect("fake daemon CreateFileW")
            };
            let mut seen: Vec<&'static str> = Vec::new();
            let mut applies = 0usize;
            while let Ok(bytes) = read_framed_timeout(client, short_timeout()) {
                let Ok(request) = serde_json::from_slice::<NetfilterRequest>(&bytes) else {
                    break;
                };
                let (label, response, last) = match request {
                    NetfilterRequest::ApplyRules(_) => {
                        applies += 1;
                        let repeat = applies > 1;
                        match behavior {
                            FakeBehavior::DieAfterFirstApply if repeat => {
                                seen.push("ApplyRules");
                                break; // 応答せずパイプを閉じる。
                            }
                            FakeBehavior::RejectAfterFirstApply if repeat => (
                                "ApplyRules",
                                NetfilterResponse::Err("mock refusal".to_string()),
                                false,
                            ),
                            FakeBehavior::DieOnFirstApply => {
                                seen.push("ApplyRules");
                                break; // 応答せずパイプを閉じる（初回）。
                            }
                            FakeBehavior::RejectFirstApply if !repeat => (
                                "ApplyRules",
                                NetfilterResponse::Err("mock refusal".to_string()),
                                false,
                            ),
                            _ => (
                                "ApplyRules",
                                NetfilterResponse::Applied { chain_launch: None },
                                false,
                            ),
                        }
                    }
                    NetfilterRequest::ClearRules => {
                        ("ClearRules", NetfilterResponse::Cleared, false)
                    }
                    // 偽daemonはD-60の連鎖起動を実装しない（このテストの関心はD-56の
                    // 再利用プロトコルであり、連鎖起動は実daemonのE2Eで見る）。
                    // **黙って無視せず、応答で「できない」と言い切る。**
                    NetfilterRequest::ChainLaunchHelper { .. } => (
                        "ChainLaunchHelper",
                        NetfilterResponse::HelperLaunched(ChainLaunchReport::Failed {
                            reason: "fake daemon does not chain-launch".to_string(),
                        }),
                        false,
                    ),
                    // 偽daemonも「起こすだけ」に答える（実daemonと同じくWFPへ触らない）。
                    NetfilterRequest::Standby => ("Standby", NetfilterResponse::Standing, false),
                    NetfilterRequest::Teardown => ("Teardown", NetfilterResponse::TornDown, true),
                };
                seen.push(label);
                let payload = serde_json::to_vec(&response).expect("serialize response");
                if write_framed_timeout(client, &payload, short_timeout()).is_err() {
                    break;
                }
                if last {
                    break;
                }
            }
            unsafe {
                let _ = CloseHandle(client);
            }
            seen
        });
        (prepared, join)
    }

    /// **本命**: 1本の接続で`ApplyRules`→`ApplyRules`→`ClearRules`→`Teardown`が通り、
    /// 2回目の`apply`が`reused == true`（＝daemonを起こしていない＝UACが出ていない）になる。
    #[test]
    fn one_daemon_serves_repeated_applies_over_a_single_connection() {
        let (prepared, daemon) = spawn_fake_daemon(FakeBehavior::Normal);
        let mut session = NetfilterSession::new();

        let first = session
            .apply(
                Some(prepared),
                /* chain_attempted */ true,
                test_policy(18080),
            )
            .expect("first apply");
        assert_eq!(
            first,
            Applied {
                reused: false,
                chain_launch: None
            },
            "the first apply has to start a daemon"
        );
        assert!(session.is_live());

        // 2回目は**投機的パイプも連鎖起動依頼も渡さない**（呼び出し側の二重起動ガードと同じ形）。
        let second = session
            .apply(None, /* chain_attempted */ false, test_policy(18081))
            .expect("second apply");
        assert_eq!(
            second,
            Applied {
                reused: true,
                chain_launch: None
            },
            "the second apply must reuse the running daemon (this is the same statement as \
             'no UAC prompt appeared')"
        );

        session.clear().expect("clear");
        assert!(
            session.is_live(),
            "clearing filters must not drop the daemon"
        );
        session.stop().expect("stop");
        assert!(!session.is_live());

        assert_eq!(
            daemon.join().expect("fake daemon thread"),
            vec!["ApplyRules", "ApplyRules", "ClearRules", "Teardown"],
            "the daemon must have seen exactly one connection carrying all four requests"
        );
    }

    /// 再利用中に**拒否**されたら、そのまま伝播する（fail-closed）。daemonは捨てない
    /// ——起こし直しても同じ拒否に着くだけで、UACが1回増える。
    #[test]
    fn a_rejected_reapply_is_propagated_and_keeps_the_daemon() {
        let (prepared, daemon) = spawn_fake_daemon(FakeBehavior::RejectAfterFirstApply);
        let mut session = NetfilterSession::new();
        session
            .apply(Some(prepared), true, test_policy(18080))
            .expect("first apply");

        let err = session
            .apply(None, false, test_policy(18081))
            .expect_err("the second apply must fail");
        assert!(
            matches!(err, NetfilterError::Rejected(ref m) if m.contains("mock refusal")),
            "a well-formed refusal must surface as Rejected, not as an I/O error: {err}"
        );
        assert!(
            session.is_live(),
            "a refusal does not mean the daemon died; keeping it avoids an extra UAC prompt"
        );

        session.stop().expect("stop");
        assert_eq!(
            daemon.join().expect("fake daemon thread"),
            vec!["ApplyRules", "ApplyRules", "Teardown"]
        );
    }

    /// **起動時前倒し**: `Standby`で起こしておくと、後の`ApplyRules`が再利用で通る。
    ///
    /// 「UACが1回で済む」という主張の中身はこれ——`reused: true`は「daemonを起こしていない」
    /// と同義である。加えて、`Standby`が**WFPへ触っていない**ことを、daemonが受け取った
    /// 要求列（`ApplyRules`が1件だけ）で示す。
    #[test]
    fn a_standby_daemon_serves_the_first_real_apply_without_starting_anything() {
        let (prepared, daemon) = spawn_fake_daemon(FakeBehavior::Normal);
        let mut session = NetfilterSession::new();

        // 実装上の入口は`NetfilterHandle::start_standby`だが、あれは`runas`＝UACを伴うので
        // 非昇格のテストでは通らない。**ハンドシェイクの中身だけ**を同じ関数で再現する
        // （テストのために本番APIを増やさない）。
        let (handle, _no_chain) =
            connect_and_handshake(prepared.into_handle(), None, FirstRequest::Standby)
                .map_err(|failure| failure.error)
                .expect("standby handshake");
        session.handle = Some(handle);
        assert!(session.is_live());

        let applied = session
            .apply(None, false, test_policy(18080))
            .expect("the first real apply must go to the standing daemon");
        assert_eq!(
            applied,
            Applied {
                reused: true,
                chain_launch: None
            },
            "'reused: true' is the same statement as 'no UAC prompt for this recording'"
        );

        session.stop().expect("stop");
        assert_eq!(
            daemon.join().expect("fake daemon thread"),
            vec!["Standby", "ApplyRules", "Teardown"],
            "Standby must not turn into an ApplyRules (it exists precisely because there are \
             no ports to apply yet)"
        );
    }

    /// **初回のハンドシェイクで拒否されても、daemonは手放さない。**
    ///
    /// 拒否したdaemonはフィルタを0件しか持たず（`handle_apply_rules`は張る前に畳む）、
    /// 次の要求を待ち続ける。ここで捨てると、UACを1回払って起こしたばかりのプロセスが
    /// `ERROR_BROKEN_PIPE`で撤収し、**次の実行がもう1回払う**——それが欠陥①である。
    ///
    /// 「保持した」ことの意味は`is_live()`ではなく、**次の`apply`が`reused: true`で通ること**で
    /// 測る（ハンドルを持っているだけで実際には使えない、という状態を緑にしないため）。
    #[test]
    fn a_rejected_first_apply_keeps_the_daemon_for_the_next_run() {
        let (prepared, daemon) = spawn_fake_daemon(FakeBehavior::RejectFirstApply);
        let mut session = NetfilterSession::new();

        let err = session
            .apply(
                Some(prepared),
                /* chain_attempted */ true,
                test_policy(18080),
            )
            .expect_err("the first apply must fail");

        assert!(
            matches!(err, NetfilterError::Rejected(ref m) if m.contains("mock refusal")),
            "a well-formed refusal must surface as Rejected: {err}"
        );
        assert!(
            session.is_live(),
            "the daemon answered, so it is alive; dropping it here wastes the UAC prompt that \
             was already paid for"
        );

        // **本命の検算**: 保持したハンドルが実際に使える（2回目はdaemonを起こさない）。
        let second = session
            .apply(None, false, test_policy(18081))
            .expect("the retained daemon must still serve the next apply");
        assert_eq!(
            second,
            Applied {
                reused: true,
                chain_launch: None
            },
            "'reused: true' is the same statement as 'no second UAC prompt'"
        );

        session.stop().expect("stop");
        assert_eq!(
            daemon.join().expect("fake daemon thread"),
            vec!["ApplyRules", "ApplyRules", "Teardown"]
        );
    }

    /// 対の側: **初回に死んだdaemonは手放す**（B-35）。
    ///
    /// 拒否と切断を同じ「保持する」に倒すと、死体のハンドルを抱えたまま次の実行が
    /// 「再利用できるはず」と判断し、そこでまた壊れたパイプを踏む。
    #[test]
    fn a_daemon_that_dies_during_the_first_handshake_is_not_kept() {
        let (prepared, daemon) = spawn_fake_daemon(FakeBehavior::DieOnFirstApply);
        let mut session = NetfilterSession::new();

        let err = session
            .apply(Some(prepared), true, test_policy(18080))
            .expect_err("the first apply must fail");

        assert!(
            daemon_is_dead(&err),
            "a closed pipe must be classified as 'the daemon is gone': {err}"
        );
        assert!(
            !session.is_live(),
            "keeping a dead handle would make the next run think it can reuse the daemon"
        );
        let _ = daemon.join();
    }

    /// 再利用中に**daemonが死んで**いたら、I/O層のエラーになる（＝起こし直しの対象）。
    ///
    /// **[`NetfilterSession::apply`]ではなく[`NetfilterHandle`]の層で測る**——sessionの側は
    /// ここから`NetfilterHandle::start`（`runas`＝UAC）へ進むので、非昇格の通常テストでは
    /// 起こし直しそのものを走らせられない。起こし直すかどうかの判断は
    /// `only_a_rejected_response_means_the_daemon_is_still_alive`が別に固定している。
    #[test]
    fn a_reapply_to_a_dead_daemon_fails_at_the_io_layer() {
        let (prepared, daemon) = spawn_fake_daemon(FakeBehavior::DieAfterFirstApply);
        let handle =
            NetfilterHandle::connect_after_chain_launch(prepared.into_handle(), test_policy(18080))
                .expect("first apply");
        let (handle, _chain) = handle;

        let err = handle
            .apply_on_existing(test_policy(18081))
            .expect_err("the daemon closed the pipe, so the reapply must fail");
        assert!(
            daemon_is_dead(&err),
            "a broken pipe must be classified as 'the daemon is gone' so that the caller \
             restarts it instead of silently running without enforcement: {err}"
        );
        let _ = daemon.join();
        // `stop`は相手が居ないので失敗する。ハンドルは`Drop`で閉じる。
        let _ = handle.stop();
    }

    /// **テストバイナリの隣にある実`harness-netfilterd.exe`が、D-56のプロトコルを喋るか。**
    /// 非昇格で走る（`ClearRules`は適用済みフィルタが0件ならWFPへ一度も触らない）。
    ///
    /// これは**古いdaemonを黙って測ることの検出器**でもある。実daemonを起動するテスト
    /// （`real_daemon_failure_tests`・`reuse_e2e`）は`target/debug/harness-netfilterd.exe`を
    /// コピーして使うが、`cargo test -p harness-sandbox`は別パッケージであるそのバイナリを
    /// **リビルドしない**——ライブラリだけ直してビルドし忘れると、直したはずの挙動を
    /// 確かめたつもりで前のビルドを測ることになる。旧プロトコルのdaemonは`ClearRules`という
    /// バリアントを知らないので`Err`を返して終了し、ここで落ちる。
    #[test]
    fn the_real_daemon_next_to_the_test_binary_speaks_the_reusable_protocol() {
        let daemon = ensure_daemon_next_to_test_binary();
        let prepared = prepare_pipe().expect("prepare pipe");
        let pipe_name = prepared.name().to_string();
        let server = prepared.into_handle();

        // 昇格させない。`ClearRules`はWFPを触らないので、非昇格でも本来の応答が返る。
        let mut child = std::process::Command::new(&daemon)
            .arg(&pipe_name)
            .spawn()
            .expect("spawn the real netfilterd");
        connect_with_timeout(server, short_timeout()).expect("daemon should connect");

        let ask = |request: NetfilterRequest| -> NetfilterResponse {
            let bytes = serde_json::to_vec(&request).expect("serialize");
            write_framed_timeout(server, &bytes, short_timeout()).expect("write request");
            let response = read_framed_timeout(server, short_timeout()).expect("read response");
            serde_json::from_slice(&response).expect("parse response")
        };

        // **起動時前倒しの1件目を実exeで測る。** 非昇格でも通る（WFPへ触らないオペコード
        // だからである）。ここが`Err`になるのは、隣のdaemonが`Standby`を知らない古いビルドの
        // ときで、それは**起動時前倒しが実運用で無言に失敗する**という意味そのものになる。
        match ask(NetfilterRequest::Standby) {
            NetfilterResponse::Standing => {}
            other => panic!(
                "the daemon next to the test binary answered {other:?} to Standby. It is almost \
                 certainly a stale build that predates the startup pre-warm -- run \
                 `cargo build --workspace` and re-run."
            ),
        }
        match ask(NetfilterRequest::ClearRules) {
            NetfilterResponse::Cleared => {}
            other => panic!(
                "the daemon next to the test binary answered {other:?} to ClearRules. It is \
                 almost certainly a stale build that predates D-56 -- run \
                 `cargo build --workspace` and re-run. Without this check, the tests that drive \
                 the real daemon would silently measure the previous binary."
            ),
        }
        // **畳んだあとも接続が生きている**ことまで確かめる（1往復固定ならここで切れている）。
        match ask(NetfilterRequest::Teardown) {
            NetfilterResponse::TornDown => {}
            other => panic!("expected TornDown after ClearRules, got {other:?}"),
        }

        let status = child.wait().expect("wait for the daemon");
        assert!(
            status.success(),
            "the daemon should exit cleanly after a Teardown: {status:?}"
        );
        unsafe {
            let _ = DisconnectNamedPipe(server);
            let _ = CloseHandle(server);
        }
    }

    /// daemon側の状態機械を実物（`serve_inner`）で測る。**WFPには一度も触らない**
    /// ——適用済みフィルタが0件なので`ClearRules`も`Teardown`も空のVecを畳むだけ。
    ///
    /// ここが固定するのは2つ:
    /// 1. `ClearRules`は`Cleared`を返し、**接続を維持する**（次の要求を受け付ける）
    /// 2. **1件目が`Teardown`でも`TornDown`を返す**——ループ化で意味を失った
    ///    「1件目は`ApplyRules`でなければプロトコル違反」を削除したことの明示的な固定
    ///    （無言で消さない、`safe-refactoring`段階1-7）
    #[test]
    fn the_daemon_answers_clear_then_teardown_and_accepts_a_teardown_first() {
        for (label, requests, expected) in [
            (
                "clear then teardown",
                vec![NetfilterRequest::ClearRules, NetfilterRequest::Teardown],
                vec!["Cleared", "TornDown"],
            ),
            (
                "teardown as the very first message",
                vec![NetfilterRequest::Teardown],
                vec!["TornDown"],
            ),
            // 起動時前倒し: **`Standby`を1件目に置いても接続は続く**（これが無いと、
            // 起こしただけのdaemonが最初の`ApplyRules`を受け取れない）。
            (
                "standby first, then keep serving",
                vec![
                    NetfilterRequest::Standby,
                    NetfilterRequest::ClearRules,
                    NetfilterRequest::Teardown,
                ],
                vec!["Standing", "Cleared", "TornDown"],
            ),
        ] {
            let prepared = prepare_pipe().expect("prepare_pipe");
            let name = prepared.name().to_string();
            let server = prepared.into_handle();

            // 実daemonと同じ入口（`serve`）を通す。`serve`はパイプをクライアントとして開き、
            // `serve_inner`へ渡す。
            let daemon = std::thread::spawn(move || serve(&name));

            connect_with_timeout(server, short_timeout()).expect("connect");
            let mut answers: Vec<&'static str> = Vec::new();
            for request in requests {
                let bytes = serde_json::to_vec(&request).expect("serialize");
                write_framed_timeout(server, &bytes, short_timeout()).expect("write request");
                let response_bytes =
                    read_framed_timeout(server, short_timeout()).expect("read response");
                let response: NetfilterResponse =
                    serde_json::from_slice(&response_bytes).expect("parse response");
                answers.push(match response {
                    NetfilterResponse::Applied { .. } => "Applied",
                    NetfilterResponse::Cleared => "Cleared",
                    NetfilterResponse::HelperLaunched(_) => "HelperLaunched",
                    NetfilterResponse::Standing => "Standing",
                    NetfilterResponse::TornDown => "TornDown",
                    NetfilterResponse::Err(ref m) => panic!("[{label}] unexpected Err: {m}"),
                });
            }
            assert_eq!(answers, expected, "[{label}]");
            daemon
                .join()
                .expect("daemon thread")
                .unwrap_or_else(|e| panic!("[{label}] the daemon should exit cleanly: {e}"));

            unsafe {
                let _ = DisconnectNamedPipe(server);
                let _ = CloseHandle(server);
            }
        }
    }
}

/// **テストから実`harness-netfilterd.exe`を起動できるようにする**（見つからなければpanic）。
///
/// `daemon_exe_path`は`current_exe().parent()`の隣を見るが、テストバイナリが置かれるのは
/// `target/debug/deps/`で、そこに`harness-netfilterd.exe`は**置かれない**（cargoが実行ファイルを
/// 置くのは`target/debug/`）。つまりテストから見た解決先は常に空振りする。
///
/// これを`SKIP`で流すと[BUG-056](../../../../docs/bugs/BUG-056.md)と同じ形になる——
/// 「テストが走っていない」と「テストが通った」が外形上区別できず、実daemonを測っているつもりの
/// テストが永久に何も測らない。実際、`real_daemon_failure_tests`はこの形でSKIPし続けていた。
/// **見つからないことを異常として扱い、直せる場合は直す。**
///
/// **コピーはテストプロセスにつき1回だけ**行う（`OnceLock`）。テストは既定で並列に走るので、
/// あるテストが`fs::copy`している最中に別のテストが同じファイルを`CreateProcess`すると、
/// 共有違反（`ERROR_SHARING_VIOLATION`）でどちらかが落ちる——実際に踏んだ。
#[cfg(windows)]
#[cfg(test)]
fn ensure_daemon_next_to_test_binary() -> PathBuf {
    static PLACED: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    PLACED.get_or_init(place_daemon_next_to_test_binary).clone()
}

#[cfg(windows)]
#[cfg(test)]
fn place_daemon_next_to_test_binary() -> PathBuf {
    let target = daemon_exe_path().expect("resolve the daemon path next to the test binary");
    let build_output = target
        .parent()
        .and_then(|deps| deps.parent()) // target/debug/deps -> target/debug
        .map(|dir| dir.join("harness-netfilterd.exe"));

    let Some(source) = build_output.filter(|p| p.exists()) else {
        assert!(
            target.exists(),
            "harness-netfilterd.exe was found neither next to the test binary ({}) nor in the \
             cargo output directory above it. Run `cargo build --workspace` first.",
            target.display()
        );
        return target;
    };

    // 既に同じものがあるならコピーしない（実行中のdaemonがあると上書きに失敗するため）。
    // **サイズか更新時刻が違えば必ず上書きする**——古いコピーを黙って測ると、直したはずの
    // daemonの挙動を確かめたつもりで前のビルドを測ることになる。
    let same = (|| -> Option<bool> {
        let (a, b) = (
            std::fs::metadata(&source).ok()?,
            std::fs::metadata(&target).ok()?,
        );
        Some(a.len() == b.len() && a.modified().ok()? == b.modified().ok()?)
    })()
    .unwrap_or(false);
    if !same {
        std::fs::copy(&source, &target).unwrap_or_else(|e| {
            panic!(
                "failed to place a fresh {} next to the test binary ({e}). If a previous \
                 harness-netfilterd.exe is still running, stop it and re-run.",
                target.display()
            )
        });
    }
    target
}

/// **D-56の機構E2E**: 実daemonを`apply → clear → apply → teardown`と駆動し、各段で
/// **実際にWFPフィルタが何件あるか**を数える。
///
/// 実行: `dev-elevated-run.exe netfilterd-reuse`（管理者権限が要る）。
#[cfg(windows)]
#[cfg(test)]
mod reuse_e2e {
    use super::*;

    /// このE2Eが固定する主張は3つ。
    ///
    /// 1. **`ClearRules`のあと、そのセッションのフィルタは0件**（D-56の不変条件1
    ///    「待機中はフィルタを持たない」）。ポリシーエディタは実行の切れ目でこれを送る。
    /// 2. **畳んだ直後の再適用が成功する**——同一プロファイル名のプロバイダ/サブレイヤーを
    ///    作り直す経路（`cleanup_stale_objects`→`FwpmProviderAdd0`）が、同じdaemonプロセスの
    ///    中で2回通るか。**ここは実機でしか分からない唯一の未知**だったので、明示的に測る。
    /// 3. **`Teardown`でdaemonが終了する**（＝寿命が延びたままにならない）。
    ///
    /// あわせて、2回目の`apply`が`reused == true`——すなわち`ShellExecuteExW(runas)`を
    /// 通っていない＝**UACが出ていない**——ことも固定する。「UACが出ないことを目視する」は
    /// 再実行も自動検証もできないので、同値な機械可読の命題へ置き換える
    /// （`tier2a_chain_launch_*`が採ったのと同じ手法）。
    #[test]
    #[ignore = "requires administrator rights (WFP/BFE) and mutates machine-global WFP state"]
    fn one_elevated_daemon_serves_apply_clear_apply_and_holds_no_filters_while_idle() {
        assert!(
            crate::tier2a::privhelper::is_elevated(),
            "this E2E must run elevated (a non-elevated daemon cannot write the filter store); \
             use `dev-elevated-run.exe netfilterd-reuse`"
        );
        // 存在しないと`NetfilterHandle::start`が解決に失敗するだけで、何も測れない。
        let _ = ensure_daemon_next_to_test_binary();

        let profile = crate::tier2a::session_profile::current_profile_name();
        // 実運用と同じく、実行ごとにProxy/Fake DNSのポートが変わる状況を作る。
        let listener_a = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind a");
        let listener_b = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind b");
        let policy = |port: u16| NetfilterPolicy {
            session_profile: profile.clone(),
            allow_loopback_tcp_ports: vec![port],
            ..Default::default()
        };

        let mut session = NetfilterSession::new();
        let first = session
            .apply(None, false, policy(listener_a.local_addr().unwrap().port()))
            .expect("first apply");
        assert_eq!(
            first,
            Applied {
                reused: false,
                chain_launch: None
            }
        );
        let ids_first = crate::tier2a::wfp::filter_ids_for_session(&profile);
        eprintln!("[e2e] 1回目のフィルタ: {ids_first:?}");
        assert!(
            !ids_first.is_empty(),
            "the first apply installed no filters at all -- nothing below this point measures \
             anything"
        );

        // 主張1: 実行の切れ目で畳むと、本当に0件になる。
        session.clear().expect("clear");
        let ids_idle = crate::tier2a::wfp::filter_ids_for_session(&profile);
        eprintln!("[e2e] ClearRules後（待機中）のフィルタ: {ids_idle:?}");
        assert!(
            ids_idle.is_empty(),
            "the daemon still holds filters while idle, so 'the waiting daemon has installed \
             nothing' is false: {ids_idle:?}"
        );
        assert!(session.is_live(), "clearing must not kill the daemon");

        // 主張2: 畳んだ直後の再適用が、同じdaemonプロセスの中で通る。
        let second = session
            .apply(None, false, policy(listener_b.local_addr().unwrap().port()))
            .expect(
                "the second apply must succeed -- if this fails, re-registering the provider and \
                 sublayer for the same profile name inside one daemon process does not work, and \
                 the whole reuse design is invalid",
            );
        assert_eq!(
            second,
            Applied {
                reused: true,
                chain_launch: None
            },
            "the second apply must have reused the running daemon (this is the same statement \
             as 'no UAC prompt appeared')"
        );
        let ids_second = crate::tier2a::wfp::filter_ids_for_session(&profile);
        eprintln!("[e2e] 2回目のフィルタ: {ids_second:?}");
        assert!(
            !ids_second.is_empty(),
            "the second apply installed no filters"
        );

        // 主張3: Teardownで畳まれ、daemonが終了する。
        session.stop().expect("stop");
        assert!(!session.is_live());
        let ids_after = crate::tier2a::wfp::filter_ids_for_session(&profile);
        eprintln!("[e2e] Teardown後のフィルタ: {ids_after:?}");
        assert!(
            ids_after.is_empty(),
            "filters survived the teardown: {ids_after:?}"
        );
    }
}

#[cfg(windows)]
#[cfg(test)]
mod real_daemon_failure_tests {
    use super::*;

    /// **`docs/STATUS.md` Tier2a残課題#2の「`FwpmEngineOpen0`自体の失敗」を、実daemon・実WFP
    /// APIで測る。** マシン全体の状態は一切変えない。
    ///
    /// `net_case_07`（`tier2a_e2e.rs`）はモックがパイプを閉じるので`connect_and_apply`の
    /// **I/O失敗**分岐しか通らない。`net_case_10`はモックが`Err`応答を返すので`Rejected`分岐を
    /// 通るが、返しているのはモックである。ここが埋めるのは最後の1マス——
    /// **本物の`harness-netfilterd.exe`が、本物の`FwpmEngineOpen0`に失敗したとき、
    /// 本当に`NetfilterResponse::Err`を返すのか**。
    ///
    /// 失敗させる方法は「daemonを非昇格で起動する」だけである。**BFEサービスを止める必要は
    /// ない**——止めるとWindows Defender Firewall（`mpssvc`が`bfe`に依存している）を巻き込む
    /// うえ、観測できるのは結局「daemonが`Err`を返す」ことで、この経路と同じである。
    ///
    /// **実測で分かったこと（当初の想定は誤りでした）**: 非管理者でも`FwpmEngineOpen0`は
    /// **成功します**。エンジンハンドルを開くこと自体は許可されており、拒否されるのは
    /// フィルタストアを書き換える段——実測では`FwpmTransactionBegin0`が
    /// `FWP status 0x00000005`（`ERROR_ACCESS_DENIED`）で落ちます。
    /// したがって`docs/STATUS.md`残課題#2の「`FwpmEngineOpen0`自体の失敗」は、
    /// **権限不足では再現しない**別の条件（BFEサービス停止等でRPC先が消えている場合）を
    /// 指しています。このテストが埋めるのは「実daemンが実WFP APIの失敗をどう報告するか」で、
    /// 失敗する具体的な関数名までは固定しません。
    ///
    /// **昇格下では自己スキップする。** 管理者で走らせると`FwpmEngineOpen0`が成功して
    /// 実フィルタが張られてしまい、測定の前提が消えるうえ副作用が残る。
    #[test]
    fn a_non_elevated_real_daemon_reports_wfp_failure_as_a_rejected_response() {
        if crate::tier2a::privhelper::is_elevated() {
            println!(
                "SKIP: this test must run non-elevated (an elevated daemon would actually open \
                 the WFP engine and install real filters)"
            );
            return;
        }
        let daemon = ensure_daemon_next_to_test_binary();

        let prepared = prepare_pipe().expect("prepare pipe");
        let pipe_name = prepared.name().to_string();
        let pipe = prepared.into_handle();

        // **昇格させずに**起動する（`launch_daemon_elevated`は使わない）。これが故障注入。
        let mut child = std::process::Command::new(&daemon)
            .arg(&pipe_name)
            .spawn()
            .expect("spawn the real netfilterd non-elevated");

        // **loopbackポートを必ず1つ入れる。** `WfpSession::apply`は
        // 「TCP/UDPどちらのloopback許可も空」なら`NoAddressesResolved`で**即座に返り、
        // `open_dynamic_engine`まで到達しない**（`wfp.rs`冒頭のガード）。空のポリシーで
        // 回すと「WFP rule application failed: no IP addresses resolved...」という
        // *別の*失敗で緑になり、`FwpmEngineOpen0`を一度も呼ばないまま
        // 「エンジンの失敗を測った」と誤認する（この形で1度踏んだ）。
        let policy = NetfilterPolicy {
            session_profile: crate::tier2a::session_profile::current_profile_name(),
            allow_loopback_tcp_ports: vec![18080],
            ..Default::default()
        };
        // 拒否されたdaemonは**生きているので保持される**（`HandshakeFailure`）。この故障注入は
        // 再利用しないので、**`child.wait()`より前に**捨てる——捨てないとパイプが開いたままで、
        // daemonは次の要求を実質無期限に待ち続け、`wait`が返らない。
        // （保持そのものは`a_rejected_first_apply_keeps_the_daemon_for_the_next_run`が固定する。）
        let result = NetfilterHandle::connect_after_chain_launch(pipe, policy)
            .map_err(|failure| failure.into_error());
        let _ = child.wait();

        match result {
            Err(NetfilterError::Rejected(msg)) => {
                println!("MEASUREMENT: non-elevated real netfilterd -> Rejected({msg})");
                // **実WFP APIの呼び出しが失敗したことまで要求する。** 「WFP」を含むだけで通す
                // 緩い判定にすると、APIへ到達する前の事前チェック（`NoAddressesResolved`等）でも
                // 緑になってしまう。実際に一度その形で緑になった。
                assert!(
                    msg.contains("win32 call failed"),
                    "expected a real WFP API call to fail (that is what makes this a stand-in for \
                     a stopped BFE). A failure before reaching the API would mean this test is \
                     not measuring the WFP path at all: {msg}"
                );
            }
            Err(other) => panic!(
                "expected the daemon to answer with NetfilterResponse::Err (mapped to Rejected), \
                 but the handshake failed at a different layer: {other}. That means the \
                 `FwpmEngineOpen0`-failure path does NOT reach the Rejected branch, and \
                 net_case_10's mock is not standing in for a real failure mode."
            ),
            Ok(_handle) => panic!(
                "the non-elevated daemon reported success -- either this process is elevated \
                 after all, or WFP no longer requires elevation. Either way the fault injection \
                 did not happen and this test proves nothing."
            ),
        }
    }

    /// **[BUG-107](../../../../docs/bugs/BUG-107.md)の回帰テスト（症状そのもの）。**
    ///
    /// `ApplyRules`を受けたdaemonは対象プロファイルの**SIDを導出する**だけで、
    /// `CreateAppContainerProfile`を呼ばない。かつてここは`ensure_profile`だったため、
    /// **親のセッション名で親の資源を作りながら台帳には載せられず**（`begin_session`が発火するのは
    /// 持ち主のプロセスだけ）、`cargo test`のたびに回収不能なプロファイルが1件ずつ実マシンへ
    /// 積まれていた（実測で67件到達）。
    ///
    /// この欠陥は戻り値にも応答にも現れず、**実マシンの資源にしか現れない**。測るのは
    /// **daemonへ送った名前ちょうど1件の実在**で、プロファイル全体の集合ではない
    /// （`test-logic-rules`「何を測れば壊れたと言えるか」）。
    ///
    /// 集合で測ってはいけない理由は実測で分かっている——`existing_profiles()`は
    /// `%LOCALAPPDATA%\Packages`を**列挙**し、`read_dir`が失敗すると空を返す。同じテストバイナリの
    /// 別テスト（`ProbeProfile`）が並行でプロファイルを作り消ししているので、この列挙は揺れ、
    /// **無関係な理由で赤くなる**（集合で書いた初版は6回中2回落ちた）。
    #[test]
    fn a_real_daemon_applying_rules_creates_no_appcontainer_profile() {
        if crate::tier2a::privhelper::is_elevated() {
            println!(
                "SKIP: this test must run non-elevated (an elevated daemon would install real \
                 WFP filters as a side effect)"
            );
            return;
        }
        let daemon = ensure_daemon_next_to_test_binary();
        // このプロセスのセッション名。**他のテストは触らない**（作るとしたら持ち主である
        // このプロセスだけで、通常実行でそれをするテストは無い）。
        let target = crate::tier2a::session_profile::current_profile_name();
        let before = crate::tier2a::session_profile::profile_exists(&target);

        let prepared = prepare_pipe().expect("prepare pipe");
        let pipe_name = prepared.name().to_string();
        let pipe = prepared.into_handle();
        let mut child = std::process::Command::new(&daemon)
            .arg(&pipe_name)
            .spawn()
            .expect("spawn the real netfilterd non-elevated");

        // 送る名前は**このプロセスのセッション名**——daemonから見れば他人のセッションであり、
        // まさにこれを作ってしまっていた。ポートを1つ入れるのは、空だとWFPへ到達する前に
        // 別の理由で返ってしまい、`apply_one`のSID解決を通らないため（隣のテストの教訓）。
        let policy = NetfilterPolicy {
            session_profile: target.clone(),
            allow_loopback_tcp_ports: vec![18081],
            ..Default::default()
        };
        // 応答の成否は問わない（非昇格なのでWFPは失敗する）。`ensure_profile`はWFPの適用より
        // **前**に呼ばれていたので、失敗する経路でもプロファイルだけは作られていた。
        let _ = NetfilterHandle::connect_after_chain_launch(pipe, policy)
            .map_err(|failure| failure.into_error());
        let _ = child.wait();

        assert_eq!(
            crate::tier2a::session_profile::profile_exists(&target),
            before,
            "the daemon changed whether {target} exists. It runs in a different process than the \
             session that owns this name, so anything it creates there carries no session-ledger \
             entry and can never be reclaimed (BUG-107). It must derive the SID, not ensure the \
             profile."
        );
    }
}
