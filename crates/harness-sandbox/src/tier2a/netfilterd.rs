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
//! **プロトコル**: 1回のセッションで2往復のメッセージをやり取りする。
//! 1. 親→daemon: [`NetfilterRequest::ApplyRules`] → daemon: [`NetfilterResponse::Applied`]
//!    （ここでdaemonはパイプを閉じずに待機を続ける。以降harnessセッションが終わるまで、
//!    Tier2aの`run_shell`は何度呼ばれてもこの1つのdaemonが引き続き宛先を強制する）
//! 2. 親→daemon: [`NetfilterRequest::Teardown`] → daemon: [`NetfilterResponse::TornDown`] → daemon終了
//!    （`harness`本体プロセスの終了時に1回だけ送る、`crates/harness-cli/src/main.rs`参照）
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

/// 親→daemonへ送るメッセージ。1セッションで`ApplyRules`→`Teardown`の順に2回送る。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetfilterRequest {
    ApplyRules(NetfilterPolicy),
    Teardown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetfilterResponse {
    Applied,
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
/// daemon側が2件目のメッセージ（`Teardown`、または親のクラッシュによるパイプ切断）を
/// 待つ時間。対象アプリの実行時間そのものに依存するため実質無期限に近い値にする
/// （`WaitForSingleObject`の最大値、約49.7日）。
const DAEMON_WAIT_FOR_TEARDOWN_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(u32::MAX as u64);

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

/// 既に接続待ち可能な状態のパイプへ、daemonの接続を待ってから`ApplyRules`を送り応答を待つ
/// （シナリオA/B共通の後段）。`daemon_process`は呼び出し元が既に把握しているプロセス
/// ハンドル（シナリオBのみ、[`NetfilterHandle::start`]参照）。
fn connect_and_apply(
    pipe: HANDLE,
    daemon_process: Option<HANDLE>,
    policy: NetfilterPolicy,
) -> Result<NetfilterHandle, NetfilterError> {
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
        return Err(e);
    }

    let req = NetfilterRequest::ApplyRules(policy);
    let apply_result = (|| -> Result<(), NetfilterError> {
        let bytes = serde_json::to_vec(&req)
            .map_err(|e| NetfilterError::Ipc(format!("failed to serialize request: {e}")))?;
        write_framed_timeout(pipe, &bytes, REQUEST_WRITE_TIMEOUT)?;
        let response_bytes = read_framed_timeout(pipe, APPLY_RESPONSE_TIMEOUT)?;
        let response: NetfilterResponse = serde_json::from_slice(&response_bytes)
            .map_err(|e| NetfilterError::Ipc(format!("failed to parse response: {e}")))?;
        match response {
            NetfilterResponse::Applied => Ok(()),
            NetfilterResponse::Err(msg) => Err(NetfilterError::Rejected(msg)),
            NetfilterResponse::TornDown => Err(NetfilterError::Ipc(
                "unexpected TornDown response for an ApplyRules request".to_string(),
            )),
        }
    })();

    match apply_result {
        Ok(()) => Ok(NetfilterHandle {
            pipe,
            daemon_process,
        }),
        Err(e) => {
            unsafe {
                let _ = DisconnectNamedPipe(pipe);
                let _ = CloseHandle(pipe);
                if let Some(h) = daemon_process {
                    let _ = CloseHandle(h);
                }
            }
            Err(e)
        }
    }
}

impl NetfilterHandle {
    /// daemonを昇格起動し、`ApplyRules`を送って応答を待つ（親側、非管理者本体から呼ぶ、
    /// シナリオB＝特権分離ヘルパーが不要なケース）。
    pub fn start(policy: NetfilterPolicy) -> Result<Self, NetfilterError> {
        let prepared = prepare_pipe()?;
        let pipe_name = prepared.name().to_string();
        let pipe = prepared.into_handle();

        let daemon_path = daemon_exe_path()?;
        let daemon_process = match unsafe { launch_daemon_elevated(&daemon_path, &pipe_name) } {
            Ok(h) => h,
            Err(e) => {
                unsafe {
                    let _ = CloseHandle(pipe);
                }
                return Err(e);
            }
        };

        connect_and_apply(pipe, Some(daemon_process), policy)
    }

    /// 既に（特権分離ヘルパー経由で）daemonの起動を依頼済みのパイプへ接続し、`ApplyRules`を
    /// 送って応答を待つ（親側、シナリオA＝`privhelper`が連鎖起動したケース）。呼び出し元は
    /// [`prepare_pipe`]で作った`pipe`を渡す。起動者がprivhelperであるため、ここでは
    /// プロセスハンドルを持たない（`daemon_process: None`、構造体docの注記参照）。
    pub fn connect_after_chain_launch(
        pipe: HANDLE,
        policy: NetfilterPolicy,
    ) -> Result<Self, NetfilterError> {
        connect_and_apply(pipe, None, policy)
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
                NetfilterResponse::Applied => Err(NetfilterError::Ipc(
                    "unexpected Applied response for a Teardown request".to_string(),
                )),
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

/// 1つのプロファイルに対してWFPフィルタを張る（**名前検証はここが唯一の関門**）。
fn apply_one(
    target: &PolicyTarget,
    audit_log_path: Option<PathBuf>,
) -> Result<WfpSession, NetfilterError> {
    if !crate::tier2a::mcp_profile::is_harness_profile_name(&target.profile) {
        return Err(NetfilterError::Ipc(format!(
            "rejected malformed appcontainer profile name: {:?}",
            target.profile
        )));
    }
    let sid = win_appcontainer::ensure_profile(&target.profile)
        .map_err(|e| NetfilterError::Ipc(format!("failed to resolve sandbox SID: {e}")))?;

    // `NetfilterPolicy`はIPCワイヤ形式、`WfpOptions`はWFPエンジンへ渡す層のオプションで、
    // フィールドは同形だが所有するレイヤーが違う。型は分けたまま、ここで明示的に写す。
    let opts = WfpOptions {
        session_profile: target.profile.clone(),
        allow_loopback_tcp_ports: target.tcp_ports.clone(),
        allow_loopback_udp_ports: target.udp_ports.clone(),
        audit_log_path,
    };
    WfpSession::apply(sid.as_psid(), &opts)
        .map_err(|e| NetfilterError::Ipc(format!("WFP rule application failed: {e}")))
}

fn serve_inner(pipe: HANDLE) -> Result<(), NetfilterError> {
    // 1回目: ApplyRules を待つ。
    let request_bytes = read_framed_timeout(pipe, APPLY_RESPONSE_TIMEOUT)?;
    let policy = match serde_json::from_slice::<NetfilterRequest>(&request_bytes) {
        Ok(NetfilterRequest::ApplyRules(policy)) => policy,
        Ok(NetfilterRequest::Teardown) => {
            let resp = NetfilterResponse::Err(
                "expected ApplyRules as the first message, got Teardown".to_string(),
            );
            send_response(pipe, &resp)?;
            return Err(NetfilterError::Ipc("protocol violation".to_string()));
        }
        Err(e) => {
            let resp = NetfilterResponse::Err(format!("malformed ApplyRules request: {e}"));
            send_response(pipe, &resp)?;
            return Err(NetfilterError::Ipc(format!("malformed request: {e}")));
        }
    };

    // D-37/D-38: フィルタの条件になるpackage SIDは、要求で受け取ったプロファイル名から導出する。
    // 名前の形を先に検証し、harness由来のプロファイル（`run_shell`セッション用またはMCPサーバ用）
    // 以外は拒否する。ここが緩むと、非特権側が任意のAppContainerへWFPフィルタを張らせられる。
    let mut sessions: Vec<WfpSession> = Vec::new();
    for target in policy_targets(&policy) {
        match apply_one(&target, policy.audit_log_path.clone()) {
            Ok(session) => sessions.push(session),
            Err(e) => {
                // 1つでも張れなければ全体を失敗させる（fail-closed）。既に張った分は
                // ここで畳んでから返す——中途半端に一部だけ強制された状態を残さない。
                for session in sessions {
                    let _ = session.teardown();
                }
                let resp = NetfilterResponse::Err(e.to_string());
                send_response(pipe, &resp)?;
                return Err(NetfilterError::Ipc(e.to_string()));
            }
        }
    }
    send_response(pipe, &NetfilterResponse::Applied)?;

    // 2回目: Teardown、または親のクラッシュによるパイプ切断を待つ。
    let teardown_result = read_framed_timeout(pipe, DAEMON_WAIT_FOR_TEARDOWN_TIMEOUT);
    let is_explicit_teardown = matches!(
        &teardown_result,
        Ok(bytes) if matches!(
            serde_json::from_slice::<NetfilterRequest>(bytes),
            Ok(NetfilterRequest::Teardown)
        )
    );

    // 全プロファイル分を畳む。1つの失敗が他の撤収を止めないよう、最初のエラーだけを覚えて
    // 最後まで回す（残したフィルタはDYNAMICセッションなのでプロセス終了時にBFEが消すが、
    // 「片付け損ねた」ことを応答から隠さない）。
    let mut session_teardown: Result<(), crate::tier2a::wfp::WfpError> = Ok(());
    for session in sessions {
        if let Err(e) = session.teardown() {
            if session_teardown.is_ok() {
                session_teardown = Err(e);
            }
        }
    }

    if is_explicit_teardown {
        let resp = match &session_teardown {
            Ok(()) => NetfilterResponse::TornDown,
            Err(e) => NetfilterResponse::Err(format!("teardown failed: {e}")),
        };
        // 応答送信の失敗はここでは致命的としない（親が既に読み取りを諦めている可能性がある）。
        let _ = send_response(pipe, &resp);
    }
    // フェイルセーフ経路（パイプ切断・タイムアウト）では応答を送らない
    // （送り先の親が既に存在しない可能性が高いため、送信を試みても無意味）。

    session_teardown.map_err(|e| NetfilterError::Ipc(e.to_string()))
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

    #[test]
    fn apply_rules_request_roundtrips_through_json() {
        let req = NetfilterRequest::ApplyRules(NetfilterPolicy {
            session_profile: "harness.shell.sandbox.1234-5678".to_string(),
            allow_loopback_tcp_ports: vec![18080, 18053],
            allow_loopback_udp_ports: vec![18053],
            audit_log_path: Some(PathBuf::from(".harness/sandbox/session-x/net-audit.jsonl")),
            mcp_profiles: Vec::new(),
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
        });
        // D-37で`session_profile`を先頭へ追加した（昇格側はこの名前を検証してからSIDを導出する）。
        // D-38（M15.5）で`mcp_profiles`を**末尾へ**追加した——既存フィールドの位置を動かすと、
        // 旧`harness-netfilterd.exe`との組み合わせで静かに壊れる。
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"ApplyRules":{"session_profile":"harness.shell.sandbox.1-2","allow_loopback_tcp_ports":[18080],"allow_loopback_udp_ports":[18053],"audit_log_path":"net-audit.jsonl","mcp_profiles":[{"profile":"harness.mcp.1-2.docs","allow_loopback_tcp_ports":[19090],"allow_loopback_udp_ports":[]}]}}"#
        );
        assert_eq!(
            serde_json::to_string(&NetfilterRequest::Teardown).unwrap(),
            r#""Teardown""#
        );
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
        });
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"ApplyRules":{"session_profile":"harness.shell.sandbox.1-2","allow_loopback_tcp_ports":[18080],"allow_loopback_udp_ports":[18053],"audit_log_path":null,"mcp_profiles":[]}}"#
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
        for bad in ["", "harness.shell.sandbox", "harness.mcp", "windows.immersivecontrolpanel"] {
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
            NetfilterResponse::Applied,
            NetfilterResponse::TornDown,
            NetfilterResponse::Err("boom".to_string()),
        ] {
            let bytes = serde_json::to_vec(&resp).unwrap();
            let decoded: NetfilterResponse = serde_json::from_slice(&bytes).unwrap();
            match (&resp, &decoded) {
                (NetfilterResponse::Applied, NetfilterResponse::Applied) => {}
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
            }) => {
                // 名前が欠落したJSONは空文字として読める。空文字は
                // `is_harness_profile_name`が拒否するので、`serve_inner`はfail-closedになる。
                assert!(session_profile.is_empty());
                assert!(allow_loopback_tcp_ports.is_empty());
                assert!(allow_loopback_udp_ports.is_empty());
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
