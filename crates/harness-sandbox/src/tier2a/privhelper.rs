//! 特権分離ヘルパー（D-16、`plans/DESIGN-SANDBOX-PRIVSEP.md` §5・§6）。
//!
//! harness本体（LLMループ・ツールディスパッチを含む）は常に非管理者トークンで動作し続ける。
//! `WRITE_DAC`が要る管理者操作（現時点ではドライブルートへのtraverse ACE付与/撤収、D10）だけを、
//! 本体から切り出した極小の別バイナリ（`harness-privhelper.exe`、`crates/harness-privhelper`）へ
//! 委譲する。IPCは名前付きパイプ＋固定enumスキーマに限定し、自由形式のコマンド文字列は受理しない
//! （§5.1）。
//!
//! **役割分担**: 親（本体、非管理者）がパイプserverを開いてから`runas`でヘルパーを昇格起動し、
//! ヘルパーはclientとして接続する（順序が逆だと、ヘルパー起動前に接続待ちする側が要らない
//! ポーリングを持つことになる）。パイプのDACLは現在ユーザのSIDへ限定するため、`runas`で
//! 昇格したヘルパーのトークンも「同一ユーザの別integrity level」であり接続できる一方、
//! 他ユーザのプロセスからは接続できない。
//!
//! **SIDは受け渡さない**: 要求スキーマにPSIDを含めない。ヘルパー自身が安定定数
//! （`CONTAINER_NAME`・`TRAVERSE_CAPABILITY_NAME`）またはIPCで受けた**形を検証済みの**
//! プロファイル名からSIDを導出する。生ポインタをプロセス境界・特権境界を越えて
//! IPCで渡す必要自体を無くす設計判断。
//!
//! **例外: WFP連鎖起動**（`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`付録D）。UAC起動回数を
//! 最小化するため、`GrantWorkspaceAccess`要求が同時に「処理完了後、指定named pipeで`harness-netfilterd`を
//! 起動してほしい」という指示（[`PrivilegedRequestEnvelope::chain_netfilterd_pipe`]）を伴うことが
//! ある。この場合だけ、ヘルパーはACL操作の応答を送った**後**に`CreateProcessW`（`runas`は使わない、
//! 自分の昇格済みトークンをそのまま子へ継承させる）で`harness-netfilterd.exe`を追加起動してから
//! 終了する。「1起動=1操作で常駐しない」という原則は、「ACL操作1件＋（指示があれば）子プロセスを
//! 1つ起動する」までを1操作とみなす形で維持する（ヘルパー自身は常駐しない。常駐するのはあくまで
//! 子として起動された`harness-netfilterd`側）。

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_CANCELLED, HANDLE, HLOCAL, WAIT_OBJECT_0,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenElevation, PSID, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken, TerminateProcess, WaitForSingleObject,
};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

use crate::shell_tier::FsAccess;
use crate::tier2a::win_appcontainer::{self, AppContainerError, CONTAINER_NAME};
use crate::win_common::wide;

/// ヘルパーへ委譲する操作。自由形式のコマンド文字列ではなく固定スキーマに限定する（D-16）。
/// 将来の特権操作（WFPフィルタ設置・VHDXマウント等、`DESIGN-SANDBOX-PRIVSEP.md` §5.2）は
/// ここへvariantを追加する形で拡張する。
/// `--fs-allow`の1エントリ（`GrantWorkspaceAccess`要求のペイロード）。`shell_tier::FsPassthrough`と
/// 同形だが、IPCでシリアライズする要求スキーマとして独立させる（`shell_tier::FsPassthrough`は
/// IPCを経由しない本体内部の値であり、両者の変更を意図せず連動させないため）。
#[derive(Debug, Clone, Serialize)]
pub struct FsAllowGrant {
    pub path: PathBuf,
    pub access: FsAccess,
    /// `--force-system-acl`（D-19）: システム保護パス（`WRITE_DAC`不可）へ
    /// `SeRestorePrivilege`を有効化して強制付与する。dispatch側で`is_force_grant_forbidden`の
    /// ゲートを通過したもののみ`with_restore_privilege`下で付与する。既定false。
    #[serde(default)]
    pub forced: bool,
}

impl<'de> Deserialize<'de> for FsAllowGrant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            path: PathBuf,
            access: Option<FsAccess>,
            writable: Option<bool>,
            #[serde(default)]
            forced: bool,
        }

        let raw = Raw::deserialize(deserializer)?;
        let access = raw.access.unwrap_or_else(|| {
            if raw.writable.unwrap_or(false) {
                FsAccess::ReadWrite
            } else {
                FsAccess::ReadExec
            }
        });
        Ok(Self {
            path: raw.path,
            access,
            forced: raw.forced,
        })
    }
}

/// `RevokeFsAllow`要求の1エントリ。`forced`なパス（`--force-system-acl`で付与したもの）は
/// 撤収時も`SeRestorePrivilege`が要るため、grantと対称に`forced`を運ぶ（新たな非対称を作らない）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsAllowRevoke {
    pub path: PathBuf,
    #[serde(default)]
    pub forced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivilegedRequest {
    /// `target`とその全祖先（ドライブルートまで）へ`FILE_TRAVERSE | FILE_READ_ATTRIBUTES`を
    /// 連鎖付与する（`harness fs grant-traverse`、`win_appcontainer::grant_traverse_chain`、
    /// `TIER1A-OPEN-ISSUES.md`項目6の連鎖化。旧`drive`フィールドから`target`へ改称——
    /// ドライブルート単体に限らない任意パスを受け付けるようになったため）。
    GrantTraverse { target: PathBuf },
    /// `GrantTraverse`で付与したACEを1件撤収する（`harness fs revoke-traverse`）。
    RevokeTraverse { path: PathBuf },
    /// `harness fs revoke`/`revoke-all`が本体プロセス内（非管理者）で撤収しきれなかった
    /// パス（`GrantWorkspaceAccess`でシステム保護パスへ付与したACE等）をまとめて1回のUACで
    /// 撤収する（付与側の裏対称、`BUG-015`参照）。各エントリは`revoke_passthrough`
    /// （ツリー全体を再walk＋root再プローブ）で撤収する。`forced`なパスは`SeRestorePrivilege`下で
    /// 撤収する（grantと対称に`forced`を運び新たな非対称を作らない、`FsAllowRevoke`参照）。
    ///
    /// **付与側と違い、こちらは旧共有プロファイル（`CONTAINER_NAME`）のSIDを使う。** D-37以前に
    /// 付けたACEと、既に終了したセッションのACEを掃除するのが役目だからである（生きている
    /// セッションのSID宛ACEには触らない。判定は非昇格側の`harness fs revoke`が持つ）。
    RevokeFsAllow { entries: Vec<FsAllowRevoke> },
    /// **非管理者からのTier2a起動が特権を要するときに通る唯一の要求**。
    /// `win_appcontainer::preflight`が自動検知した、workspace_root/upper_dir祖先チェーンの
    /// traverse不足（複数ターゲットあり得る、`--cow`ではworkspace_rootとupper_dirの2つ）と
    /// `--fs-allow`昇格要求を、1回のUACへまとめて処理する（起動あたりUAC最大1回の原則、
    /// `plans/DESIGN-SANDBOX-PRIVSEP.md` D-16/D-31「特権昇格デーモンを使う際の注意点」参照）。
    /// `preflight`はtraverse不足の有無で分岐せず、常にこの1本へ束ねる。
    ///
    /// 残る`GrantTraverse`/`RevokeTraverse`は`harness fs grant-traverse`/`revoke-traverse`
    /// （単一target、起動とは独立した手動コマンド）専用である。
    GrantWorkspaceAccess {
        traverse_targets: Vec<PathBuf>,
        fs_allow_entries: Vec<FsAllowGrant>,
        /// D-37: `fs_allow_entries`の付与先package SIDを決めるセッションプロファイル名。
        ///
        /// **SIDそのものではなく名前を運ぶ**（生ポインタを特権境界へ渡さないという既存方針の
        /// 維持）。受信側は`session_profile::is_session_profile_name`で形を検証してから
        /// `ensure_profile`で導出するので、任意のAppContainerへACEを付けさせることはできない。
        /// `traverse_targets`側は名前に依存しない——祖先traverseはharness共通のcapability SID
        /// （固定名から昇格側が自ら導出する）宛に付与するため、こちらは従来どおりIPCで
        /// SID識別子を一切受け取らない。
        #[serde(default)]
        session_profile: String,
    },
}

/// IPCワイヤ上のトップレベル型。`PrivilegedRequest`本体を薄く包み、WFP連鎖起動の指示
/// （モジュールdoc「例外: WFP連鎖起動」参照）を運ぶ。`PrivilegedRequest`自体のvariant・
/// 処理ロジック（`dispatch()`）は無変更のまま、この封筒だけを新設する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegedRequestEnvelope {
    pub request: PrivilegedRequest,
    /// `Some(pipe_name)`なら、ヘルパーは`request`の処理・応答送信を終えた後、
    /// `CreateProcessW`（`runas`は使わない）で`harness-netfilterd.exe <pipe_name>`を追加起動
    /// してから終了する。`pipe_name`は呼び出し元（`harness`本体）が事前に開いておいた
    /// named pipeの名前で、`harness-netfilterd`はこれへclientとして接続する
    /// （`netfilterd::NetfilterHandle`が直接`runas`起動する経路と同じハンドシェイクを、
    /// 起動者だけがヘルパー経由に変わる形で流用する）。
    #[serde(default)]
    pub chain_netfilterd_pipe: Option<String>,
}

impl From<PrivilegedRequest> for PrivilegedRequestEnvelope {
    fn from(request: PrivilegedRequest) -> Self {
        PrivilegedRequestEnvelope {
            request,
            chain_netfilterd_pipe: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivilegedResponse {
    /// データを返す必要がない操作の単純成功（`RevokeTraverse`）。
    Ok,
    /// `GrantTraverse`の結果。祖先チェーンのうち実際にACE付与が成功したノードの一覧を、
    /// 成否に関わらず必ず返す。`error`が`Some`なら途中のノードで付与が失敗し、それ以降は
    /// 未処理。`granted`に含まれるノードは実際にディスク上でACEが変更済みなので、呼び出し側は
    /// `error`の有無に関わらず`granted`の全ノードを台帳へ記録しなければならない（孤立ACE防止）。
    GrantChain {
        granted: Vec<PathBuf>,
        error: Option<String>,
    },
    /// `RevokeFsAllow`の結果。エントリごとに成否が独立（`GrantChain`と違い連鎖ではないため、
    /// 1エントリの失敗が他エントリの処理を止めない）。
    /// `root_cleared`は「rootのACEは消えたが一部の子孫（TrustedInstaller所有等）にACEが残る」
    /// パス（BUG-016のrevoke非対称の解消、`RevokeOutcome::RootClearedDescendantsBlocked`）。
    /// 呼び出し側は`revoked`と`root_cleared`の両方を台帳から除去する（後者は孤立ACEにならない）。
    RevokeFsAllowResult {
        revoked: Vec<PathBuf>,
        root_cleared: Vec<PathBuf>,
        failures: Vec<(PathBuf, String)>,
    },
    /// 要求全体を拒否した場合の単純な失敗（スキーマ不一致等、部分適用の概念が無い操作）。
    Err(String),
    /// `GrantWorkspaceAccess`の結果。`traverse_granted`/`traverse_error`は`GrantChain`と同じ意味
    /// （複数targetを順に処理し、途中のtargetで失敗した場合はそこで打ち切るが、それまでに
    /// 成功したノードは全ターゲット分`traverse_granted`へ積む。呼び出し側は`traverse_error`の
    /// 有無に関わらず`traverse_granted`の全ノードを台帳へ記録しなければならない）。
    /// `fs_allow_granted`はACE付与に成功したパスの一覧、`fs_allow_failures`は`(path, reason)`。
    /// エントリごとに成否が独立する（traverseの連鎖と違い、1件の失敗が他を止めない）。
    /// 呼び出し側は`fs_allow_granted`を台帳へ記録し、`fs_allow_failures`は警告として表示する
    /// （D8の既存の扱いに合わせる）。
    WorkspaceAccessResult {
        traverse_granted: Vec<PathBuf>,
        traverse_error: Option<String>,
        fs_allow_granted: Vec<PathBuf>,
        fs_allow_failures: Vec<(PathBuf, String)>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum PrivHelperError {
    #[error("elevation was declined or failed (UAC canceled?): {0}")]
    ElevationDeclined(String),
    #[error("ipc error: {0}")]
    Ipc(String),
    #[error("helper rejected the request: {0}")]
    Rejected(String),
    #[error("win32 call failed: {0}")]
    Win32(String),
    /// `GrantTraverse`（連鎖付与）が途中のノードで失敗した場合。`granted`には失敗するまでに
    /// 実際にACEが付与された（=ディスク上で変更済みの）ノードが入る。呼び出し側は、この
    /// エラーを受け取っても`granted`を台帳へ記録しなければならない（孤立ACE防止）。
    #[error("grant-traverse chain partially failed after granting {granted:?}: {reason}")]
    PartialGrantChain {
        granted: Vec<PathBuf>,
        reason: String,
    },
}

impl From<windows::core::Error> for PrivHelperError {
    fn from(e: windows::core::Error) -> Self {
        PrivHelperError::Win32(e.to_string())
    }
}

/// 呼び出し元プロセスのトークンが昇格済み（管理者）かどうかを判定する（§5.3）。
/// 判定に失敗した場合は`false`を返す（fail-safe: 誤って「昇格済み」と扱い直接特権操作へ
/// 倒れることを避け、判定不能時はヘルパー経由の遅い経路へ寄せる）。
pub fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        let _ = CloseHandle(token);
        match ok {
            Ok(()) => elevation.TokenIsElevated != 0,
            Err(_) => false,
        }
    }
}

// 名前付きパイプIPCの下回り（DACL・オーバーラップドI/O・フレーミング）は
// `crate::win_pipe_ipc`が持つ。以前はこのファイル・`tier2a/netfilterd.rs`・
// `tier3/vmsandboxd.rs`の3箇所に同じ一式がコピーされていた（そのうち`run_overlapped`の
// タイムアウトのクランプが本ファイルにだけ無い、という劣化も起きていた）。
use crate::win_pipe_ipc::{
    connect_with_timeout, current_user_sid_string, read_framed_timeout,
    user_only_security_attributes, write_framed_timeout,
};

/// このモジュール用のパイプ名。
fn unique_pipe_name() -> String {
    crate::win_pipe_ipc::unique_pipe_name("privhelper")
}

impl From<crate::win_pipe_ipc::PipeIpcError> for PrivHelperError {
    fn from(e: crate::win_pipe_ipc::PipeIpcError) -> Self {
        PrivHelperError::Ipc(e.into_message())
    }
}

/// 親がヘルパーの接続を待つ上限（`ShellExecuteExW`のUACダイアログ操作自体はここに含まれない。
/// `ConnectNamedPipe`は「ヘルパーが起動してパイプへ接続してくる」のを待つ処理であり、
/// UACダイアログの表示中はまだこの待ちに入っていない）。
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// 要求送信のタイムアウト。接続済みの相手が即座に読み取り待ちに入っている前提の
/// ローカル通信なので短くてよい。
const REQUEST_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// 応答受信のタイムアウト。プロファイルルート近傍への`SetNamedSecurityInfoW`が
/// この実機で病的に遅くなりうること（BUG-011で実測済み、`icacls`単体でも30秒超）を
/// 踏まえ、余裕を持たせた値。Phase 2の実測結果次第で調整する。
const RESPONSE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);
// --- 信頼境界で分けたサブモジュール（docs/CODE-STRUCTURE-RULES.md 規則3） ---
//
// どのコードが昇格した権限で動くのかをファイル単位で判別できるようにするため、
// 非特権側（client）と管理者権限側（server）を別ファイルにする。上のワイヤプロトコル型と
// エラー型は両者が共有するため、このモジュールルートに置く。

mod client;
mod server;

pub use client::{
    run_privileged, run_privileged_revoke_fs_allow, run_privileged_workspace_access,
    FsAllowRevokeOutcome,
};
pub use server::serve;


/// 名前付きパイプIPC下回りの現行の振る舞いを固定するcharacterization test。
///
/// この9関数（`run_overlapped`・`connect_with_timeout`・`write_all_timeout`・
/// `read_exact_timeout`・`write_framed_timeout`・`read_framed_timeout`・
/// `user_only_security_attributes`・`unique_pipe_name`・`current_user_sid_string`）は
/// `tier2a::netfilterd`・`tier3::vmsandboxd`にもコピーとして存在し、共通モジュールへ
/// 1本化する予定である（`docs/CODE-STRUCTURE-RULES.md`規則5）。統合の前後で振る舞いが
/// 変わっていないことを示す基準としてここに置く（規則6）。統合後はテストごと共通モジュールへ移す。
///
/// 既存の`framed_message_roundtrips_over_a_real_named_pipe`（`netfilterd`/`vmsandboxd`側）は
/// write→readが対称でありさえすれば通るため、**ワイヤ上のバイト列が変わったことを検出できない**。
/// 別プロセス間で交換する形なので、ここではバイト列そのものを固定する。
#[cfg(all(windows, test))]
mod pipe_ipc_characterization {
    use super::*;
    use crate::win_pipe_ipc::read_exact_timeout;
    use windows::Win32::Security::Authorization::SDDL_REVISION_1;
    use windows::Win32::Security::PSECURITY_DESCRIPTOR;

    fn short_timeout() -> std::time::Duration {
        std::time::Duration::from_secs(5)
    }

    /// テスト用の接続済みパイプ対を作る。戻り値は(server, client)。
    fn connected_pipe_pair() -> (HANDLE, HANDLE, String) {
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
            assert!(!handle.is_invalid(), "CreateNamedPipeW failed");
            handle
        };

        let name_for_client = pipe_name.clone();
        let client_thread = std::thread::spawn(move || unsafe {
            let pipe_name_w = wide(&name_for_client);
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
        (server, client, pipe_name)
    }

    fn close_pair(server: HANDLE, client: HANDLE) {
        unsafe {
            let _ = DisconnectNamedPipe(server);
            let _ = CloseHandle(server);
            let _ = CloseHandle(client);
        }
    }

    /// フレーム形式は「4バイトのリトルエンディアン長プレフィックス + ペイロード」。
    /// 生バイト列を読み出して固定する（往復テストでは検出できない変化を捕まえるため）。
    #[test]
    fn a_frame_is_a_4_byte_little_endian_length_prefix_followed_by_the_payload() {
        let (server, client, _) = connected_pipe_pair();

        write_framed_timeout(client, b"hi", short_timeout()).expect("write_framed_timeout");

        let mut raw = [0u8; 6];
        read_exact_timeout(server, &mut raw, short_timeout()).expect("read_exact_timeout");
        assert_eq!(raw, [0x02, 0x00, 0x00, 0x00, b'h', b'i']);

        close_pair(server, client);
    }

    /// 長さ0のフレームは長さプレフィックスだけを書き、読み側は空のVecを返す
    /// （`read_framed_timeout`が`len > 0`のときだけペイロードを読む分岐）。
    #[test]
    fn a_zero_length_frame_writes_only_the_prefix_and_reads_back_empty() {
        let (server, client, _) = connected_pipe_pair();

        write_framed_timeout(client, b"", short_timeout()).expect("write_framed_timeout");
        let received = read_framed_timeout(server, short_timeout()).expect("read_framed_timeout");
        assert!(received.is_empty());

        close_pair(server, client);
    }

    /// 複数フレームを続けて書いても、境界が保たれたまま1つずつ読み出せる
    /// （バイトストリームモードのパイプ上で長さプレフィックスがフレーム境界を担う）。
    #[test]
    fn consecutive_frames_keep_their_boundaries() {
        let (server, client, _) = connected_pipe_pair();

        write_framed_timeout(client, b"first", short_timeout()).unwrap();
        write_framed_timeout(client, b"second-longer", short_timeout()).unwrap();

        assert_eq!(
            read_framed_timeout(server, short_timeout()).unwrap(),
            b"first"
        );
        assert_eq!(
            read_framed_timeout(server, short_timeout()).unwrap(),
            b"second-longer"
        );

        close_pair(server, client);
    }

    /// データが来ない状態での読取はタイムアウトでエラーになる（無限待ちしない）。
    #[test]
    fn reading_with_nothing_on_the_wire_times_out_instead_of_blocking_forever() {
        let (server, client, _) = connected_pipe_pair();

        let started = std::time::Instant::now();
        let result = read_framed_timeout(server, std::time::Duration::from_millis(300));
        assert!(result.is_err(), "expected a timeout error, got {result:?}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "read should have returned promptly after the timeout"
        );

        close_pair(server, client);
    }

    /// パイプ名は呼び出しごとに一意で、この機構専用の接頭辞を持つ。
    #[test]
    fn pipe_names_are_unique_and_prefixed_for_this_mechanism() {
        let a = unique_pipe_name();
        let b = unique_pipe_name();
        assert_ne!(a, b);
        assert!(a.starts_with(r"\\.\pipe\harness-privhelper-"), "got {a}");
        assert!(a.contains(&std::process::id().to_string()));
    }

    /// パイプのDACLは呼び出しユーザーのSIDだけを許可する（他ユーザ・Administratorsは
    /// DACLに列挙されないtrusteeとして暗黙deny）。SDDLの生成結果に自分のSIDが含まれ、
    /// かつ他のtrusteeが入っていないことを、セキュリティ記述子から確認する。
    #[test]
    fn the_pipe_dacl_names_only_the_calling_user() {
        let sid = current_user_sid_string().expect("current_user_sid_string");
        let sa = user_only_security_attributes(&sid).expect("user_only_security_attributes");

        // 生成に使ったSDDLと同じ形へ戻せることを、記述子を文字列化して確認する。
        let mut out = windows::core::PWSTR::null();
        let ok = unsafe {
            windows::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW(
                PSECURITY_DESCRIPTOR(sa.lpSecurityDescriptor),
                SDDL_REVISION_1,
                windows::Win32::Security::DACL_SECURITY_INFORMATION,
                &mut out,
                None,
            )
        };
        assert!(ok.is_ok(), "ConvertSecurityDescriptorToStringSecurityDescriptorW failed");
        let sddl = crate::win_common::pwstr_to_string(out);
        unsafe {
            let _ = LocalFree(HLOCAL(out.0 as *mut _));
            let _ = LocalFree(HLOCAL(sa.lpSecurityDescriptor));
        }

        // 生成元は`D:(A;;GA;;;<sid>)`。ACEはちょうど1件で、呼び出しユーザーへ
        // GENERIC_ALLのみ。Administratorsを含む他のtrusteeは列挙されない＝暗黙deny。
        assert_eq!(
            sddl,
            format!("D:(A;;GA;;;{sid})"),
            "the pipe DACL must grant GENERIC_ALL to the calling user and no one else"
        );
        // `P`（protected、継承ACEを受け付けない）は付いていない。名前付きパイプは
        // 継承元のコンテナを持たないため実効的な差が無く、付与していないのが現行の挙動。
        assert!(!sddl.contains("D:P"), "unexpected protected flag in {sddl}");
        // ハンドル自体は子プロセスへ継承させない。
        assert_eq!(sa.bInheritHandle.0, 0, "the pipe handle must not be inheritable");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `PrivilegedRequestEnvelope`（WFP連鎖起動、`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`
    /// 付録D）が`chain_netfilterd_pipe`の有無どちらでもラウンドトリップすることを確認する。
    #[test]
    fn envelope_roundtrips_with_and_without_netfilterd_chain() {
        let envelope = PrivilegedRequestEnvelope {
            request: PrivilegedRequest::GrantWorkspaceAccess {
                traverse_targets: Vec::new(),
                fs_allow_entries: vec![FsAllowGrant {
                    path: PathBuf::from(r"C:\ProgramData\Microsoft\VisualStudio\Setup"),
                    access: FsAccess::ReadExec,
                    forced: false,
                }],
                session_profile: "harness.shell.sandbox.1234-5678".to_string(),
            },
            chain_netfilterd_pipe: Some(r"\\.\pipe\harness-netfilterd-1234-0".to_string()),
        };
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let decoded: PrivilegedRequestEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            decoded.chain_netfilterd_pipe,
            Some(r"\\.\pipe\harness-netfilterd-1234-0".to_string())
        );
        match decoded.request {
            PrivilegedRequest::GrantWorkspaceAccess {
                fs_allow_entries, ..
            } => assert_eq!(fs_allow_entries.len(), 1),
            other => panic!("unexpected variant: {other:?}"),
        }

        let envelope = PrivilegedRequestEnvelope::from(PrivilegedRequest::RevokeTraverse {
            path: PathBuf::from(r"C:\Users"),
        });
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let decoded: PrivilegedRequestEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.chain_netfilterd_pipe, None);
    }

    /// この機能導入前のスキーマ（`chain_netfilterd_pipe`フィールドが無いJSON）でも
    /// `#[serde(default)]`により`None`として読める（前方/後方互換、`forced`フィールドと同じ理由）。
    #[test]
    fn envelope_defaults_chain_netfilterd_pipe_to_none_when_absent() {
        let json = r#"{"request":{"RevokeTraverse":{"path":"C:\\Users"}}}"#;
        let decoded: PrivilegedRequestEnvelope = serde_json::from_str(json).unwrap();
        assert_eq!(decoded.chain_netfilterd_pipe, None);
    }

    #[test]
    fn request_roundtrips_through_json() {
        let req = PrivilegedRequest::GrantTraverse {
            target: PathBuf::from(r"C:\Users\example\.cargo"),
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let decoded: PrivilegedRequest = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            PrivilegedRequest::GrantTraverse { target } => {
                assert_eq!(target, PathBuf::from(r"C:\Users\example\.cargo"))
            }
            other => panic!("unexpected variant: {other:?}"),
        }

        let req = PrivilegedRequest::RevokeTraverse {
            path: PathBuf::from(r"C:\Users"),
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let decoded: PrivilegedRequest = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            PrivilegedRequest::RevokeTraverse { path } => {
                assert_eq!(path, PathBuf::from(r"C:\Users"))
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    /// fs-allowエントリの`access`と`forced`が、エントリごとに独立してワイヤを渡ることを
    /// 固定する。**`forced`は`SeRestorePrivilege`の有効化（D-19）を決めるフラグ**なので、
    /// ここが黙って落ちたり別エントリの値と混ざったりすると、意図しないパスへ全DACLを
    /// バイパスして書く経路になる。`grant_workspace_access_request_roundtrips_through_json`は
    /// エントリ数しか見ないので、中身の検査はこちらが持つ。
    #[test]
    fn fs_allow_entries_keep_their_access_and_forced_flags_over_the_wire() {
        let req = PrivilegedRequest::GrantWorkspaceAccess {
            traverse_targets: Vec::new(),
            fs_allow_entries: vec![
                FsAllowGrant {
                    path: PathBuf::from(r"C:\ProgramData\Microsoft\VisualStudio\Setup"),
                    access: FsAccess::ReadExec,
                    forced: false,
                },
                FsAllowGrant {
                    path: PathBuf::from(r"C:\Program Files\SomeTool"),
                    access: FsAccess::ReadWrite,
                    forced: true,
                },
            ],
            session_profile: "harness.shell.sandbox.1234-5678".to_string(),
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let decoded: PrivilegedRequest = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            PrivilegedRequest::GrantWorkspaceAccess {
                fs_allow_entries, ..
            } => {
                assert_eq!(fs_allow_entries.len(), 2);
                assert_eq!(
                    fs_allow_entries[0].path,
                    PathBuf::from(r"C:\ProgramData\Microsoft\VisualStudio\Setup")
                );
                assert_eq!(fs_allow_entries[0].access, FsAccess::ReadExec);
                assert!(!fs_allow_entries[0].forced);
                assert_eq!(fs_allow_entries[1].access, FsAccess::ReadWrite);
                assert!(fs_allow_entries[1].forced);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    /// `GrantWorkspaceAccess`（`preflight`のtraverse自動付与+fs-allow昇格の合成リクエスト）が
    /// 複数targets/entriesを保持したままラウンドトリップすることを確認する。
    #[test]
    fn grant_workspace_access_request_roundtrips_through_json() {
        let req = PrivilegedRequest::GrantWorkspaceAccess {
            traverse_targets: vec![
                PathBuf::from(r"C:\Users\example\workspace"),
                PathBuf::from(r"C:\Users\example\AppData\Local\harness\cow\session-1"),
            ],
            fs_allow_entries: vec![FsAllowGrant {
                path: PathBuf::from(r"C:\ProgramData\Microsoft\VisualStudio\Setup"),
                access: FsAccess::ReadExec,
                forced: false,
            }],
            session_profile: "harness.shell.sandbox.1234-5678".to_string(),
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let decoded: PrivilegedRequest = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            PrivilegedRequest::GrantWorkspaceAccess {
                traverse_targets,
                fs_allow_entries,
                session_profile,
            } => {
                assert_eq!(session_profile, "harness.shell.sandbox.1234-5678");
                assert_eq!(traverse_targets.len(), 2);
                assert_eq!(
                    traverse_targets[1],
                    PathBuf::from(r"C:\Users\example\AppData\Local\harness\cow\session-1")
                );
                assert_eq!(fs_allow_entries.len(), 1);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    /// D-34: プロセス境界を越える形はバイト列そのものを固定する。D-37で`session_profile`を
    /// 足したので、その位置と名前もここで固定される（昇格側は受け取った名前を
    /// `is_session_profile_name`で検証してから使うため、形が変わったら気付ける必要がある）。
    #[test]
    fn grant_workspace_access_request_json_wire_format_is_stable() {
        let req = PrivilegedRequest::GrantWorkspaceAccess {
            traverse_targets: vec![PathBuf::from("C:/ws")],
            fs_allow_entries: Vec::new(),
            session_profile: "harness.shell.sandbox.1-2".to_string(),
        };
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"GrantWorkspaceAccess":{"traverse_targets":["C:/ws"],"fs_allow_entries":[],"session_profile":"harness.shell.sandbox.1-2"}}"#
        );
    }

    /// 昇格側が受け取るプロファイル名は検証される（任意のAppContainerへACEを付けさせない）。
    #[test]
    fn only_session_profile_names_are_accepted_by_the_elevated_side() {
        use crate::tier2a::session_profile::is_session_profile_name;
        assert!(is_session_profile_name("harness.shell.sandbox.1-2"));
        assert!(!is_session_profile_name(
            "Microsoft.WindowsTerminal_8wekyb3d8bbwe"
        ));
        assert!(!is_session_profile_name("harness.shell.sandbox"));
    }

    /// `WorkspaceAccessResult`応答が、traverse側のエラーとfs-allow側の成否混在の両方を
    /// 失わずにラウンドトリップできることを確認する。
    #[test]
    fn workspace_access_result_roundtrips_through_json() {
        let response = PrivilegedResponse::WorkspaceAccessResult {
            traverse_granted: vec![PathBuf::from(r"C:\"), PathBuf::from(r"C:\Users")],
            traverse_error: Some(r"C:\Users\example\workspace: access denied".to_string()),
            fs_allow_granted: vec![PathBuf::from(r"C:\ProgramData\Tool")],
            fs_allow_failures: vec![(PathBuf::from(r"C:\Windows\System32"), "denied".to_string())],
        };
        let bytes = serde_json::to_vec(&response).unwrap();
        let decoded: PrivilegedResponse = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            PrivilegedResponse::WorkspaceAccessResult {
                traverse_granted,
                traverse_error,
                fs_allow_granted,
                fs_allow_failures,
            } => {
                assert_eq!(traverse_granted.len(), 2);
                assert_eq!(
                    traverse_error,
                    Some(r"C:\Users\example\workspace: access denied".to_string())
                );
                assert_eq!(fs_allow_granted.len(), 1);
                assert_eq!(fs_allow_failures.len(), 1);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    /// `FsAllowGrant`/`FsAllowRevoke`の`forced`は`#[serde(default)]`なので、フィールドが
    /// 欠けたJSON（この機能導入前のスキーマ）でも`false`として読める（前方/後方互換）。
    #[test]
    fn forced_field_defaults_to_false_when_absent() {
        let grant: FsAllowGrant =
            serde_json::from_str(r#"{"path":"C:\\x","writable":false}"#).unwrap();
        assert_eq!(grant.access, FsAccess::ReadExec);
        assert!(!grant.forced);
        let grant: FsAllowGrant =
            serde_json::from_str(r#"{"path":"C:\\x","writable":true}"#).unwrap();
        assert_eq!(grant.access, FsAccess::ReadWrite);
        let revoke: FsAllowRevoke = serde_json::from_str(r#"{"path":"C:\\x"}"#).unwrap();
        assert!(!revoke.forced);
    }

    #[test]
    fn revoke_fs_allow_request_roundtrips_through_json() {
        let req = PrivilegedRequest::RevokeFsAllow {
            entries: vec![
                FsAllowRevoke {
                    path: PathBuf::from(r"C:\ProgramData\Microsoft\VisualStudio\Setup"),
                    forced: false,
                },
                FsAllowRevoke {
                    path: PathBuf::from(r"C:\Program Files\SomeTool"),
                    forced: true,
                },
            ],
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let decoded: PrivilegedRequest = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            PrivilegedRequest::RevokeFsAllow { entries } => {
                assert_eq!(entries.len(), 2);
                assert_eq!(
                    entries[0].path,
                    PathBuf::from(r"C:\ProgramData\Microsoft\VisualStudio\Setup")
                );
                assert!(!entries[0].forced);
                assert!(entries[1].forced);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    /// `RevokeFsAllowResult`応答も`FsAllowResult`と同じく、成功パスと失敗パスが混在する状態で
    /// 両方を失わずにラウンドトリップできることを確認する。
    #[test]
    fn revoke_fs_allow_result_response_roundtrips_with_mixed_outcomes() {
        let resp = PrivilegedResponse::RevokeFsAllowResult {
            revoked: vec![PathBuf::from(
                r"C:\ProgramData\Microsoft\VisualStudio\Setup",
            )],
            root_cleared: vec![PathBuf::from(
                r"C:\ProgramData\Microsoft\Windows\Start Menu",
            )],
            failures: vec![(
                PathBuf::from(r"C:\Windows\System32\config"),
                "access denied".to_string(),
            )],
        };
        let bytes = serde_json::to_vec(&resp).unwrap();
        let decoded: PrivilegedResponse = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            PrivilegedResponse::RevokeFsAllowResult {
                revoked,
                root_cleared,
                failures,
            } => {
                assert_eq!(
                    revoked,
                    vec![PathBuf::from(
                        r"C:\ProgramData\Microsoft\VisualStudio\Setup"
                    )]
                );
                assert_eq!(
                    root_cleared,
                    vec![PathBuf::from(
                        r"C:\ProgramData\Microsoft\Windows\Start Menu"
                    )]
                );
                assert_eq!(failures.len(), 1);
                assert_eq!(failures[0].0, PathBuf::from(r"C:\Windows\System32\config"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn malformed_bytes_are_rejected_not_panicking() {
        let garbage = b"{\"not\":\"a valid PrivilegedRequest\"}";
        let result = serde_json::from_slice::<PrivilegedRequest>(garbage);
        assert!(result.is_err());
    }

    #[test]
    fn unknown_variant_is_rejected() {
        let unknown = br#"{"NukeSystem":{}}"#;
        let result = serde_json::from_slice::<PrivilegedRequest>(unknown);
        assert!(result.is_err());
    }

    /// `GrantChain`応答が、成功（`error: None`）・部分失敗（`error: Some`）のどちらでも
    /// `granted`一覧を失わずラウンドトリップできることを確認する（孤立ACE防止の前提）。
    #[test]
    fn grant_chain_response_roundtrips_with_partial_failure() {
        let resp = PrivilegedResponse::GrantChain {
            granted: vec![PathBuf::from(r"C:\"), PathBuf::from(r"C:\Users")],
            error: Some("access denied on C:\\Users\\example".to_string()),
        };
        let bytes = serde_json::to_vec(&resp).unwrap();
        let decoded: PrivilegedResponse = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            PrivilegedResponse::GrantChain { granted, error } => {
                assert_eq!(
                    granted,
                    vec![PathBuf::from(r"C:\"), PathBuf::from(r"C:\Users")]
                );
                assert!(error.is_some());
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn is_elevated_returns_a_bool_without_panicking() {
        let _: bool = is_elevated();
    }

    fn short_timeout() -> std::time::Duration {
        std::time::Duration::from_secs(5)
    }

    /// パイプの配線（DACL作成・`CreateNamedPipeW`・オーバーラップド`ConnectNamedPipe`・
    /// `write_framed_timeout`/`read_framed_timeout`のフレーミング）を、昇格・別プロセス起動
    /// なしで検証する。同一プロセス内でserver端（`CreateNamedPipeW`）とclient端
    /// （`CreateFileW`）の両方を開き、実際に`run_privileged`/`serve`が使うのと同じ
    /// タイムアウト付き関数でメッセージを1往復させる。特権操作（`WRITE_DAC`）自体は
    /// テストしない（`dispatch`の中身は別途、実機の手動E2Eで検証する。
    /// `docs/phases/foundation/M12-shell-isolation-tiers.md`参照）。
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

        write_framed_timeout(server, b"hello from server", short_timeout())
            .expect("write_framed_timeout");
        let received = read_framed_timeout(client, short_timeout()).expect("read_framed_timeout");
        assert_eq!(received, b"hello from server");

        unsafe {
            let _ = DisconnectNamedPipe(server);
            let _ = CloseHandle(server);
            let _ = CloseHandle(client);
        }
    }

    /// タイムアウト経路そのものを検証する: serverを立てるがclientを一切接続させないまま
    /// 短いタイムアウトで`connect_with_timeout`を呼び、有限時間で明示エラーを返すこと
    /// （無期限ハングしないこと）を確認する。前回セッションで実際に起きた「UAC/IPCが
    /// 無言でハングし、staleなヘルパープロセスが残留する」不具合の再発防止（本ファイル
    /// 冒頭のコンテキスト、`docs/bugs/BUG-010.md`/`BUG-011.md`参照）。
    #[test]
    fn connect_with_timeout_returns_an_error_instead_of_hanging_when_nobody_connects() {
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

        let started = std::time::Instant::now();
        let result = connect_with_timeout(server, std::time::Duration::from_millis(500));
        let elapsed = started.elapsed();

        assert!(result.is_err(), "expected a timeout error, got Ok(())");
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "connect_with_timeout took {elapsed:?}, expected it to return promptly after its \
             own 500ms timeout instead of hanging"
        );

        unsafe {
            let _ = CloseHandle(server);
        }
    }
}
