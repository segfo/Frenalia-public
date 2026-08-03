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
//! **SIDは受け渡さない**: 要求スキーマにPSIDを含めない。ヘルパー自身が`ensure_profile`で
//! `CONTAINER_NAME`（安定定数）からSIDを導出する。生ポインタをプロセス境界・特権境界を越えて
//! IPCで渡す必要自体を無くす設計判断。
//!
//! **例外: WFP連鎖起動**（`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`付録D）。UAC起動回数を
//! 最小化するため、`GrantFsAllow`要求が同時に「処理完了後、指定named pipeで`harness-netfilterd`を
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
    CloseHandle, GetLastError, LocalFree, ERROR_CANCELLED, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED,
    HANDLE, HLOCAL, WAIT_OBJECT_0,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenElevation, TokenUser, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenProcessToken, TerminateProcess, WaitForSingleObject,
};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

use crate::shell_tier::FsAccess;
use crate::tier2a::win_appcontainer::{self, AppContainerError, CONTAINER_NAME};
use crate::win_common::wide;

/// ヘルパーへ委譲する操作。自由形式のコマンド文字列ではなく固定スキーマに限定する（D-16）。
/// 将来の特権操作（WFPフィルタ設置・VHDXマウント等、`DESIGN-SANDBOX-PRIVSEP.md` §5.2）は
/// ここへvariantを追加する形で拡張する。
/// `--fs-allow`の1エントリ（`GrantFsAllow`要求のペイロード）。`shell_tier::FsPassthrough`と
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
    /// `--fs-allow`/`fs.allow`が本体プロセス内（非管理者）で`ACCESS_DENIED`になったエントリを
    /// まとめて1回のUACで昇格付与する（システム保護パス、例`C:\ProgramData\...\VisualStudio\Setup`
    /// への読取専用付与。`TIER1A-PRIVHELPER-HANG.md`「引き継ぎTODO」参照）。呼び出し側
    /// （`win_appcontainer::preflight`）が事前にユーザ所有パスを本体内で処理済みなので、
    /// ここに載るのは昇格が要ると判明したエントリのみ＝起動あたりUAC最大1回に抑えられる。
    GrantFsAllow { entries: Vec<FsAllowGrant> },
    /// `harness fs revoke`/`revoke-all`が本体プロセス内（非管理者）で撤収しきれなかった
    /// パス（`GrantFsAllow`でシステム保護パスへ付与したACE等）をまとめて1回のUACで撤収する
    /// （`GrantFsAllow`の裏対称、`BUG-015`参照）。各エントリは`revoke_passthrough`
    /// （ツリー全体を再walk＋root再プローブ）で撤収する。`forced`なパスは`SeRestorePrivilege`下で
    /// 撤収する（grantと対称に`forced`を運び新たな非対称を作らない、`FsAllowRevoke`参照）。
    RevokeFsAllow { entries: Vec<FsAllowRevoke> },
    /// `win_appcontainer::preflight`が自動検知した、workspace_root/upper_dir祖先チェーンの
    /// traverse不足（複数ターゲットあり得る、`--cow`ではworkspace_rootとupper_dirの2つ）と
    /// `--fs-allow`昇格要求を、1回のUACへまとめて処理する（起動あたりUAC最大1回の原則、
    /// `plans/DESIGN-SANDBOX-PRIVSEP.md` D-16「特権昇格デーモンを使う際の注意点」参照）。
    /// 既存の`GrantTraverse`（単一target、`harness fs grant-traverse`専用）・`GrantFsAllow`は
    /// このvariant導入後も変更しない——`preflight`がtraverse不足を検知しない通常起動では、
    /// この新variantを一切通らず既存の`GrantFsAllow`単体パスのまま動く。
    GrantWorkspaceAccess {
        traverse_targets: Vec<PathBuf>,
        fs_allow_entries: Vec<FsAllowGrant>,
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
    /// `GrantFsAllow`の結果。エントリごとに成否が独立（`GrantChain`と違い連鎖ではないため、
    /// 1エントリの失敗が他エントリの処理を止めない）。`granted`は実際にACEが付与された
    /// パスの一覧、`failures`は`(path, reason)`の一覧。呼び出し側は`granted`を台帳へ記録し、
    /// `failures`は警告として表示する（D8の既存の扱いに合わせる）。
    FsAllowResult {
        granted: Vec<PathBuf>,
        failures: Vec<(PathBuf, String)>,
    },
    /// `RevokeFsAllow`の結果。`FsAllowResult`と同形だが、フィールド名を`granted`ではなく
    /// `revoked`にして意味を明確にする。エントリごとに成否が独立する点も`FsAllowResult`と同じ。
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
    /// `fs_allow_granted`/`fs_allow_failures`は`FsAllowResult`と同じ意味。
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

/// 現在プロセスのユーザSIDを`S-1-...`形式の文字列で取得する（named pipeのDACLを
/// このユーザへ限定するため）。
fn current_user_sid_string() -> windows::core::Result<String> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;

        let mut ret_len = 0u32;
        // 1回目は必要バッファサイズを問い合わせるだけの呼び出し（ERROR_INSUFFICIENT_BUFFERを
        // 無視する、Win32の定型パターン）。
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut ret_len);
        let mut buf = vec![0u8; ret_len as usize];
        let get_result = GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            ret_len,
            &mut ret_len,
        );
        let _ = CloseHandle(token);
        get_result?;

        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let sid = token_user.User.Sid;
        let mut sid_str_ptr = windows::core::PWSTR::null();
        ConvertSidToStringSidW(sid, &mut sid_str_ptr)?;
        let sid_str = crate::win_common::pwstr_to_string(sid_str_ptr);
        let _ = LocalFree(HLOCAL(sid_str_ptr.0 as *mut _));
        Ok(sid_str)
    }
}

/// 現在ユーザのSIDのみへフルアクセスを許可するセキュリティ記述子を作る（named pipe用）。
/// 他ユーザ（Administrators含む、`sid`以外の全て）は既定拒否（DACLに列挙されないtrusteeへの
/// 暗黙deny）。
fn user_only_security_attributes(sid: &str) -> windows::core::Result<SECURITY_ATTRIBUTES> {
    let sddl = format!("D:(A;;GA;;;{sid})");
    unsafe {
        let sddl_w = wide(&sddl);
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )?;
        Ok(SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        })
    }
}

/// 一意なパイプ名を作る（PID + 単調増加カウンタで衝突回避、暗号論的乱数は不要 — 名前の
/// 推測可能性はDACLで既に閉じているため、名前自体の秘匿性には依存しない設計）。
fn unique_pipe_name() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        r"\\.\pipe\harness-privhelper-{}-{}-{}",
        std::process::id(),
        n,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    )
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

/// オーバーラップドI/O 1回分（`ConnectNamedPipe`/`ReadFile`/`WriteFile`のいずれか）を
/// `timeout`以内に完了させる。`start`は対応するWin32 I/O開始APIを呼び出すクロージャで、
/// `ERROR_IO_PENDING`（正常系、非同期処理が始まった）と`ERROR_PIPE_CONNECTED`
/// （`ConnectNamedPipe`固有の「相手が呼び出し前に既に繋がっていた」正常系）はここで吸収する。
/// タイムアウト時は`CancelIoEx`で取り消してから返るため、staleな非同期I/Oをハンドルに
/// 残さない（呼び出し側がすぐハンドルを閉じても問題ない状態にする）。
fn run_overlapped<F>(
    handle: HANDLE,
    timeout: std::time::Duration,
    op_name: &str,
    start: F,
) -> Result<u32, PrivHelperError>
where
    F: FnOnce(*mut OVERLAPPED) -> windows::core::Result<()>,
{
    unsafe {
        let event = CreateEventW(None, true, false, PCWSTR::null())
            .map_err(|e| PrivHelperError::Ipc(format!("{op_name}: CreateEventW failed: {e}")))?;
        let mut overlapped = OVERLAPPED {
            hEvent: event,
            ..Default::default()
        };

        let pending = match start(&mut overlapped as *mut _) {
            Ok(()) => false,
            Err(e) => {
                let code = e.code();
                if code == windows::core::HRESULT::from_win32(ERROR_IO_PENDING.0) {
                    true
                } else if code == windows::core::HRESULT::from_win32(ERROR_PIPE_CONNECTED.0) {
                    // クライアントが`ConnectNamedPipe`呼び出し前に既に接続済みだった（synchronous
                    // completion）。MSDNの既知の注意点: このケースではOVERLAPPEDのイベントは
                    // シグナルされないため、後続の`GetOverlappedResult`を呼んではいけない
                    // （呼ぶと`ERROR_IO_INCOMPLETE`で失敗する）。ここで即座に成功として返す。
                    // 【2026-07-25実機E2Eで発見・修正】従来この関数は昇格の`runas`起動（低速、
                    // クライアントが繋がるまで数秒かかる）でしか使われておらず、この競合が
                    // 顕在化しなかった。WFP連鎖起動（`netfilterd`が特権分離ヘルパー経由で即座に
                    // 接続してくる、UAC待ちが無い経路）を追加した際、この機種で実際に
                    // `ERROR_IO_INCOMPLETE`が発生し発覚した（`netfilterd.rs`の同名関数と同じ修正）。
                    let _ = CloseHandle(event);
                    return Ok(0);
                } else {
                    let _ = CloseHandle(event);
                    return Err(PrivHelperError::Ipc(format!(
                        "{op_name} failed to start: {e}"
                    )));
                }
            }
        };

        if pending {
            let wait = WaitForSingleObject(event, timeout.as_millis() as u32);
            if wait != WAIT_OBJECT_0 {
                // タイムアウトまたは待機自体の失敗。取り消して、取り消し完了(bWait=true)まで
                // 待ってから返る — ハンドルをこの後すぐ閉じても`OVERLAPPED`がstaleに
                // ならないようにするため。
                let _ = CancelIoEx(handle, Some(&overlapped as *const _));
                let mut transferred = 0u32;
                let _ = GetOverlappedResult(handle, &overlapped, &mut transferred, true);
                let _ = CloseHandle(event);
                return Err(PrivHelperError::Ipc(format!(
                    "{op_name} timed out after {timeout:?}"
                )));
            }
        }

        let mut transferred = 0u32;
        let result = GetOverlappedResult(handle, &overlapped, &mut transferred, false);
        let _ = CloseHandle(event);
        result.map_err(|e| {
            PrivHelperError::Ipc(format!("{op_name}: GetOverlappedResult failed: {e}"))
        })?;
        Ok(transferred)
    }
}

fn connect_with_timeout(pipe: HANDLE, timeout: std::time::Duration) -> Result<(), PrivHelperError> {
    run_overlapped(pipe, timeout, "ConnectNamedPipe", |ov| unsafe {
        ConnectNamedPipe(pipe, Some(ov))
    })?;
    Ok(())
}

fn write_all_timeout(
    handle: HANDLE,
    buf: &[u8],
    timeout: std::time::Duration,
) -> Result<(), PrivHelperError> {
    let mut offset = 0usize;
    while offset < buf.len() {
        let slice = &buf[offset..];
        let written = run_overlapped(handle, timeout, "WriteFile", |ov| unsafe {
            WriteFile(handle, Some(slice), None, Some(ov))
        })?;
        if written == 0 {
            return Err(PrivHelperError::Ipc("WriteFile wrote 0 bytes".to_string()));
        }
        offset += written as usize;
    }
    Ok(())
}

fn read_exact_timeout(
    handle: HANDLE,
    buf: &mut [u8],
    timeout: std::time::Duration,
) -> Result<(), PrivHelperError> {
    let mut offset = 0usize;
    while offset < buf.len() {
        let slice = &mut buf[offset..];
        let read = run_overlapped(handle, timeout, "ReadFile", |ov| unsafe {
            ReadFile(handle, Some(slice), None, Some(ov))
        })?;
        if read == 0 {
            return Err(PrivHelperError::Ipc(
                "ReadFile read 0 bytes (pipe closed?)".to_string(),
            ));
        }
        offset += read as usize;
    }
    Ok(())
}

/// `write_framed`のオーバーラップド・タイムアウト付き版。
fn write_framed_timeout(
    handle: HANDLE,
    payload: &[u8],
    timeout: std::time::Duration,
) -> Result<(), PrivHelperError> {
    let len = (payload.len() as u32).to_le_bytes();
    write_all_timeout(handle, &len, timeout)?;
    write_all_timeout(handle, payload, timeout)?;
    Ok(())
}

/// `read_framed`のオーバーラップド・タイムアウト付き版。
fn read_framed_timeout(
    handle: HANDLE,
    timeout: std::time::Duration,
) -> Result<Vec<u8>, PrivHelperError> {
    let mut len_buf = [0u8; 4];
    read_exact_timeout(handle, &mut len_buf, timeout)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        read_exact_timeout(handle, &mut payload, timeout)?;
    }
    Ok(payload)
}

/// ヘルパー実行ファイル（`harness-privhelper.exe`）のパスを、本体exeと同じディレクトリから
/// 解決する（PATH検索に頼らない固定ロケーション、D-16の「小さく独立にビルド・監査可能な
/// 別バイナリ」を確実に本体と対で配布する前提）。
fn helper_exe_path() -> Result<PathBuf, PrivHelperError> {
    let current = std::env::current_exe()
        .map_err(|e| PrivHelperError::Ipc(format!("failed to resolve current exe: {e}")))?;
    let dir = current
        .parent()
        .ok_or_else(|| PrivHelperError::Ipc("current exe has no parent directory".to_string()))?;
    Ok(dir.join("harness-privhelper.exe"))
}

/// 特権操作をヘルパーへ委譲し、完了まで待つ（client側、非管理者本体から呼ぶ）。
/// 1. 現在ユーザSID限定DACLでnamed pipe serverを作る。
/// 2. `runas`でヘルパーをパイプ名引数付きで昇格起動する（UACが表示される）。
/// 3. ヘルパーの接続を待ち、要求を送信し、応答を受け取る。
///
/// 返り値は「実際にACEが付与されたノードの一覧」（`GrantTraverse`のみ意味を持つ。
/// `RevokeTraverse`成功時は常に空`Vec`）。`Err(PrivHelperError::PartialGrantChain { granted, .. })`
/// の場合も`granted`に途中まで成功したノードが入るため、呼び出し側は`Err`だからと無視せず
/// 中身を確認して台帳へ反映する必要がある（孤立ACE防止）。`GrantFsAllow`はエントリごとに
/// 成否が独立するため、この関数ではなく[`run_privileged_fs_allow`]を使う。
pub fn run_privileged(req: &PrivilegedRequest) -> Result<Vec<PathBuf>, PrivHelperError> {
    let envelope = PrivilegedRequestEnvelope::from(req.clone());
    match run_privileged_raw(&envelope)? {
        PrivilegedResponse::Ok => Ok(Vec::new()),
        PrivilegedResponse::GrantChain {
            granted,
            error: None,
        } => Ok(granted),
        PrivilegedResponse::GrantChain {
            granted,
            error: Some(reason),
        } => Err(PrivHelperError::PartialGrantChain { granted, reason }),
        PrivilegedResponse::FsAllowResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected FsAllowResult response for a non-GrantFsAllow request".to_string(),
        )),
        PrivilegedResponse::RevokeFsAllowResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected RevokeFsAllowResult response for a non-RevokeFsAllow request".to_string(),
        )),
        PrivilegedResponse::WorkspaceAccessResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected WorkspaceAccessResult response for a non-GrantWorkspaceAccess request"
                .to_string(),
        )),
        PrivilegedResponse::Err(msg) => Err(PrivHelperError::Rejected(msg)),
    }
}

/// `run_privileged_fs_allow`の成功値（`granted`パス一覧、`(path, reason)`失敗一覧）。
pub type FsAllowGrantOutcome = (Vec<PathBuf>, Vec<(PathBuf, String)>);

/// `run_privileged_revoke_fs_allow`の成功値（`revoked`完全撤収一覧、`root_cleared`
/// root撤収済み・子孫ブロック一覧、`(path, reason)`失敗一覧）。`revoked`と`root_cleared`は
/// どちらも台帳から除去してよい（`root_cleared`は孤立ACEにならない、`RevokeOutcome`参照）。
pub type FsAllowRevokeOutcome = (Vec<PathBuf>, Vec<PathBuf>, Vec<(PathBuf, String)>);

/// `GrantFsAllow`専用の委譲関数。`run_privileged`と異なりエントリごとの成否（`granted`/
/// `failures`）を両方とも呼び出し側へそのまま返す（1エントリの失敗が「エラー」ではなく
/// 正常な部分結果であるため、`run_privileged`の`Result<Vec<PathBuf>, _>`という単一成功値の
/// 形には馴染まない）。WFP連鎖起動が不要な既存呼び出し元向けの薄いラッパー
/// （[`run_privileged_fs_allow_with_netfilterd_chain`]を`chain_pipe: None`で呼ぶだけ）。
pub fn run_privileged_fs_allow(
    entries: Vec<FsAllowGrant>,
) -> Result<FsAllowGrantOutcome, PrivHelperError> {
    run_privileged_fs_allow_with_netfilterd_chain(entries, None)
}

/// `run_privileged_fs_allow`のWFP連鎖起動対応版（`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`
/// 付録D シナリオ(A)）。`chain_pipe`が`Some`なら、ヘルパーはこのACL操作の応答を送った後、
/// 指定named pipeで`harness-netfilterd`を追加起動してから終了する
/// （モジュールdoc「例外: WFP連鎖起動」参照）。
pub fn run_privileged_fs_allow_with_netfilterd_chain(
    entries: Vec<FsAllowGrant>,
    chain_pipe: Option<String>,
) -> Result<FsAllowGrantOutcome, PrivHelperError> {
    let envelope = PrivilegedRequestEnvelope {
        request: PrivilegedRequest::GrantFsAllow { entries },
        chain_netfilterd_pipe: chain_pipe,
    };
    match run_privileged_raw(&envelope)? {
        PrivilegedResponse::FsAllowResult { granted, failures } => Ok((granted, failures)),
        PrivilegedResponse::Ok => Ok((Vec::new(), Vec::new())),
        PrivilegedResponse::GrantChain { granted, error } => {
            // スキーマ上あり得ないはずの応答だが、fail-safeとして「全て失敗」扱いにはせず
            // grantedをそのまま伝える（孤立ACE防止の原則を維持）。
            Ok((
                granted,
                error.map(|e| vec![(PathBuf::new(), e)]).unwrap_or_default(),
            ))
        }
        PrivilegedResponse::RevokeFsAllowResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected RevokeFsAllowResult response for a GrantFsAllow request".to_string(),
        )),
        PrivilegedResponse::WorkspaceAccessResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected WorkspaceAccessResult response for a GrantFsAllow request".to_string(),
        )),
        PrivilegedResponse::Err(msg) => Err(PrivHelperError::Rejected(msg)),
    }
}

/// `run_privileged_workspace_access`の成功値（traverse付与ノード一覧・traverse失敗理由・
/// fs-allow付与一覧・fs-allow失敗一覧）。
pub type WorkspaceAccessOutcome = (Vec<PathBuf>, Option<String>, Vec<PathBuf>, Vec<(PathBuf, String)>);

/// `GrantWorkspaceAccess`専用の委譲関数（`win_appcontainer::preflight`がtraverse不足を自動検知
/// したときに呼ぶ）。`run_privileged_fs_allow_with_netfilterd_chain`と同じく`chain_pipe`で
/// WFP連鎖起動にも対応する——**新しい特権操作を追加する際の注意点**: 同一起動内で2回目の
/// `run_privileged*`（＝2回目のUAC）を独立に呼び出してはならない。この関数のように、
/// 1回の起動で必要になり得る特権操作をすべて1つの`PrivilegedRequestEnvelope`へ束ねること
/// （`plans/DESIGN-SANDBOX-PRIVSEP.md` D-16参照）。
pub fn run_privileged_workspace_access(
    traverse_targets: Vec<PathBuf>,
    fs_allow_entries: Vec<FsAllowGrant>,
    chain_pipe: Option<String>,
) -> Result<WorkspaceAccessOutcome, PrivHelperError> {
    let envelope = PrivilegedRequestEnvelope {
        request: PrivilegedRequest::GrantWorkspaceAccess {
            traverse_targets,
            fs_allow_entries,
        },
        chain_netfilterd_pipe: chain_pipe,
    };
    match run_privileged_raw(&envelope)? {
        PrivilegedResponse::WorkspaceAccessResult {
            traverse_granted,
            traverse_error,
            fs_allow_granted,
            fs_allow_failures,
        } => Ok((
            traverse_granted,
            traverse_error,
            fs_allow_granted,
            fs_allow_failures,
        )),
        PrivilegedResponse::Ok => Ok((Vec::new(), None, Vec::new(), Vec::new())),
        PrivilegedResponse::GrantChain { granted, error } => {
            Ok((granted, error, Vec::new(), Vec::new()))
        }
        PrivilegedResponse::FsAllowResult { granted, failures } => {
            Ok((Vec::new(), None, granted, failures))
        }
        PrivilegedResponse::RevokeFsAllowResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected RevokeFsAllowResult response for a GrantWorkspaceAccess request"
                .to_string(),
        )),
        PrivilegedResponse::Err(msg) => Err(PrivHelperError::Rejected(msg)),
    }
}

/// `RevokeFsAllow`専用の委譲関数（`run_privileged_fs_allow`の裏対称、`BUG-015`参照）。
/// `entries`は`harness fs revoke`/`revoke-all`が本体プロセス内で撤収しきれなかったパス
/// （`forced`情報付き）の一覧。
pub fn run_privileged_revoke_fs_allow(
    entries: Vec<FsAllowRevoke>,
) -> Result<FsAllowRevokeOutcome, PrivHelperError> {
    let envelope = PrivilegedRequestEnvelope::from(PrivilegedRequest::RevokeFsAllow { entries });
    match run_privileged_raw(&envelope)? {
        PrivilegedResponse::RevokeFsAllowResult {
            revoked,
            root_cleared,
            failures,
        } => Ok((revoked, root_cleared, failures)),
        PrivilegedResponse::Ok => Ok((Vec::new(), Vec::new(), Vec::new())),
        PrivilegedResponse::GrantChain { granted, error } => Ok((
            granted,
            Vec::new(),
            error.map(|e| vec![(PathBuf::new(), e)]).unwrap_or_default(),
        )),
        PrivilegedResponse::FsAllowResult { granted, failures } => {
            Ok((granted, Vec::new(), failures))
        }
        PrivilegedResponse::WorkspaceAccessResult { .. } => Err(PrivHelperError::Ipc(
            "unexpected WorkspaceAccessResult response for a RevokeFsAllow request".to_string(),
        )),
        PrivilegedResponse::Err(msg) => Err(PrivHelperError::Rejected(msg)),
    }
}

fn run_privileged_raw(
    envelope: &PrivilegedRequestEnvelope,
) -> Result<PrivilegedResponse, PrivHelperError> {
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
            return Err(PrivHelperError::from(windows::core::Error::from_win32()));
        }
        handle
    };

    let helper_path = helper_exe_path()?;
    // 【重要】ここでヘルパープロセスの終了を待ってはいけない。ヘルパー（`serve`）は
    // 「親から要求を受信する」ことを待っており、親はまだ要求を送っていない。もしここで
    // ヘルパーの終了を待つと、親は「ヘルパー終了待ち」・ヘルパーは「親からの送信待ち」の
    // 循環待機（デッドロック）に陥る（実機のUACテストで実際に発生を確認、`launch_helper_elevated`
    // 内部で`WaitForSingleObject(INFINITE)`していた旧実装のバグ）。プロセスハンドルは
    // IPC完了後に回収する。
    let helper_process = match unsafe { launch_helper_elevated(&helper_path, &pipe_name) } {
        Ok(h) => h,
        Err(e) => {
            unsafe {
                let _ = CloseHandle(pipe);
            }
            return Err(e);
        }
    };

    let result = run_ipc_exchange(pipe, envelope);

    unsafe {
        let _ = DisconnectNamedPipe(pipe);
        let _ = CloseHandle(pipe);
        if !helper_process.is_invalid() {
            // ヘルパーは応答送信直後（またはIPCタイムアウト後の異常系）に終了するはずなので、
            // 短いタイムアウトで待つ（既にIPCが完了/断念した後の後始末であり、ここでの待機は
            // デッドロックを起こさない）。
            let wait = WaitForSingleObject(helper_process, 5000);
            if wait != WAIT_OBJECT_0 {
                // 5秒経っても終了しない = staleの疑い。前回セッションで「非昇格からkillできない
                // stale privhelper.exeが残留する」不具合が起きたため、ここで強制終了する。
                // `ShellExecuteExW`(SEE_MASK_NOCLOSEPROCESS)で取得したこのハンドルは、
                // 起動時点で既に十分なアクセス権を保持しているため、非昇格プロセスからでも
                // `TerminateProcess`が成功する（`OpenProcess`を後から呼ぶ経路ではない）。
                let _ = TerminateProcess(helper_process, 1);
                let _ = WaitForSingleObject(helper_process, 2000);
            }
            let _ = CloseHandle(helper_process);
        }
    }

    result
}

/// パイプ接続・要求送信・応答受信の本体（ヘルパープロセスの生死待ちとは独立させる、
/// デッドロック回避のため`run_privileged_raw`から分離）。応答の解釈は行わず、パースした
/// `PrivilegedResponse`をそのまま返す（要求variantごとの解釈は呼び出し元
/// `run_privileged`/`run_privileged_fs_allow`の責務）。
fn run_ipc_exchange(
    pipe: HANDLE,
    envelope: &PrivilegedRequestEnvelope,
) -> Result<PrivilegedResponse, PrivHelperError> {
    connect_with_timeout(pipe, CONNECT_TIMEOUT).map_err(|e| {
        PrivHelperError::Ipc(format!(
            "waiting for helper to connect: {e} (helper may not have launched, or UAC is still \
             pending user interaction)"
        ))
    })?;

    let request_bytes = serde_json::to_vec(envelope)
        .map_err(|e| PrivHelperError::Ipc(format!("failed to serialize request: {e}")))?;
    write_framed_timeout(pipe, &request_bytes, REQUEST_WRITE_TIMEOUT)?;

    let response_bytes = read_framed_timeout(pipe, RESPONSE_READ_TIMEOUT).map_err(|e| {
        PrivHelperError::Ipc(format!(
            "{e} (the privileged operation may still be in progress on a slow node — this \
             machine has previously shown pathologically slow DACL writes near the user \
             profile root, see docs/bugs/BUG-011.md; check %APPDATA%\\harness\\privhelper.log \
             for per-node timing)"
        ))
    })?;
    serde_json::from_slice(&response_bytes)
        .map_err(|e| PrivHelperError::Ipc(format!("failed to parse helper response: {e}")))
}

/// `runas`でヘルパーを昇格起動する。ユーザがUACを拒否した場合は`ERROR_CANCELLED`が返るため
/// `ElevationDeclined`へ変換する（親側がハングせず即座にエラーを返せる）。起動した
/// プロセスのハンドルを返すのみで、終了は待たない（呼び出し側がIPC完了後に待つ、
/// デッドロック回避）。
unsafe fn launch_helper_elevated(
    helper_path: &std::path::Path,
    pipe_name: &str,
) -> Result<HANDLE, PrivHelperError> {
    let verb_w = wide("runas");
    let file_w = wide(&helper_path.to_string_lossy());
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
            return Err(PrivHelperError::ElevationDeclined(
                "UAC prompt was canceled by the user".to_string(),
            ));
        }
        return Err(PrivHelperError::Win32(format!(
            "ShellExecuteExW failed: {err:?}"
        )));
    }

    Ok(info.hProcess)
}

/// ヘルパー側のファイルログ（`%APPDATA%\harness\config\privhelper.log`、台帳と同じ`config_dir`）。
/// ヘルパーは`runas`+`SW_HIDE`（[`launch_helper_elevated`]参照）で起動されるため
/// `eprintln!`の出力先が無く、UAC/IPCが無応答になった際に「どのノードで何秒かかって
/// いたか」を事後に一切確認できない（前回セッションでUAC不表示/`ERROR_BROKEN_PIPE`が
/// 起きた際、原因の切り分けができなかった実体験に基づく）。台帳ファイル
/// （`fs-passthrough-ledger.json`/`traverse-grant-ledger.json`）には一切触れず、完全に
/// 別ファイルへ追記のみ行う（`CLAUDE.md`の台帳誤削除防止ルールと同じ理由で、既存台帳の
/// 読み書きコードパスとは独立させる）。
mod log {
    use std::io::Write;

    fn log_path() -> Option<std::path::PathBuf> {
        directories::ProjectDirs::from("", "", "harness")
            .map(|d| d.config_dir().join("privhelper.log"))
    }

    /// ログ書込み自体の失敗はヘルパーの処理を止めない（診断用の副次経路であり、ログ書込み
    /// 失敗が特権操作そのものの失敗理由になってはならない）。
    pub fn line(msg: &str) {
        let Some(path) = log_path() else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = writeln!(f, "[{now_ms}] pid={} {msg}", std::process::id());
        }
    }
}

/// ヘルパー側エントリポイント（`harness-privhelper.exe`のmainから呼ぶ、昇格トークンで実行される）。
/// 親が開いたパイプへclientとして接続し、1件の要求を処理して応答を返し終了する
/// （1起動=1操作、常駐しない）。
pub fn serve(pipe_name: &str) -> Result<(), PrivHelperError> {
    log::line(&format!("serve: starting, pipe={pipe_name}"));
    // FILE_FLAG_OVERLAPPED: 親と同じくオーバーラップドI/Oで受信・送信を有限時間化する
    // （§1c、親が既に諦めて`CloseHandle`した後もこちら側が無期限に`ReadFile`し続けて
    // stale化する事故を防ぐ、常駐しない原則の徹底）。
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
    };
    let pipe = match pipe {
        Ok(h) => {
            log::line("serve: connected to parent pipe");
            h
        }
        Err(e) => {
            log::line(&format!("serve: CreateFileW failed: {e}"));
            return Err(PrivHelperError::from(e));
        }
    };

    let request_bytes = match read_framed_timeout(pipe, REQUEST_WRITE_TIMEOUT) {
        Ok(b) => {
            log::line(&format!("serve: received request ({} bytes)", b.len()));
            b
        }
        Err(e) => {
            log::line(&format!("serve: read request failed/timed out: {e}"));
            unsafe {
                let _ = CloseHandle(pipe);
            }
            return Err(e);
        }
    };
    let (response, chain_netfilterd_pipe) =
        match serde_json::from_slice::<PrivilegedRequestEnvelope>(&request_bytes) {
            Ok(envelope) => (dispatch(envelope.request), envelope.chain_netfilterd_pipe),
            Err(e) => {
                log::line(&format!("serve: malformed request: {e}"));
                (
                    PrivilegedResponse::Err(format!(
                        "malformed or unknown request (schema mismatch): {e}"
                    )),
                    None,
                )
            }
        };
    let response_bytes = serde_json::to_vec(&response)
        .map_err(|e| PrivHelperError::Ipc(format!("failed to serialize response: {e}")))?;
    log::line("serve: writing response");
    let write_result = write_framed_timeout(pipe, &response_bytes, RESPONSE_READ_TIMEOUT);
    match &write_result {
        Ok(()) => log::line("serve: response written, exiting"),
        Err(e) => log::line(&format!("serve: write response failed/timed out: {e}")),
    }
    unsafe {
        let _ = CloseHandle(pipe);
    }

    // 応答を送り終えた**後**にのみ連鎖起動する（モジュールdoc「例外: WFP連鎖起動」参照）。
    // ACL操作の成否に関わらず試みる — WFP起動の可否とACL操作の成否は独立した関心事であり、
    // ACL側が失敗したからといって呼び出し元が期待しているWFP起動まで巻き添えで諦める理由はない。
    if let Some(chain_pipe) = chain_netfilterd_pipe {
        log::line(&format!(
            "serve: chain-launching netfilterd, pipe={chain_pipe}"
        ));
        match unsafe { launch_netfilterd_chained(&chain_pipe) } {
            Ok(()) => log::line("serve: netfilterd chain-launch succeeded"),
            Err(e) => log::line(&format!("serve: netfilterd chain-launch failed: {e}")),
        }
    }

    write_result
}

/// ヘルパー実行ファイルと同じディレクトリから`harness-netfilterd.exe`を解決する
/// （[`helper_exe_path`]と同じロジック、対象exe名だけが異なる）。
fn netfilterd_exe_path() -> Result<PathBuf, PrivHelperError> {
    let current = std::env::current_exe()
        .map_err(|e| PrivHelperError::Ipc(format!("failed to resolve current exe: {e}")))?;
    let dir = current
        .parent()
        .ok_or_else(|| PrivHelperError::Ipc("current exe has no parent directory".to_string()))?;
    Ok(dir.join("harness-netfilterd.exe"))
}

/// 昇格済みトークンのまま`harness-netfilterd.exe`を子として起動する（`ShellExecuteExW`の
/// `runas`は使わない——既に管理者トークンを持つプロセスからの通常の`CreateProcessW`は、
/// そのトークンをそのまま子へ継承させるため、2回目のUACダイアログは出ない）。起動した
/// プロセスのハンドルは待たない（netfilterdはharnessセッション全体の生存期間中、独立して
/// 常駐し続けるデーモンであり、ヘルパー自身はこの直後に終了する）。
unsafe fn launch_netfilterd_chained(pipe_name: &str) -> Result<(), PrivHelperError> {
    let netfilterd_path = netfilterd_exe_path()?;
    // コマンドラインの第0引数（実行ファイルパス）はCreateProcessWの規約上quoteが要る。
    let cmdline = format!("\"{}\" {}", netfilterd_path.display(), pipe_name);
    let mut cmdline_w = wide(&cmdline);

    let startup_info = windows::Win32::System::Threading::STARTUPINFOW {
        cb: std::mem::size_of::<windows::Win32::System::Threading::STARTUPINFOW>() as u32,
        dwFlags: windows::Win32::System::Threading::STARTF_USESHOWWINDOW,
        wShowWindow: SW_HIDE.0 as u16,
        ..Default::default()
    };
    let mut process_info = windows::Win32::System::Threading::PROCESS_INFORMATION::default();

    windows::Win32::System::Threading::CreateProcessW(
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
    )
    .map_err(PrivHelperError::from)?;

    let _ = CloseHandle(process_info.hProcess);
    let _ = CloseHandle(process_info.hThread);
    Ok(())
}

/// `GrantFsAllow`/`GrantWorkspaceAccess`共通の実処理。エントリごとに成否が独立する
/// （`GrantTraverse`のような連鎖ではないため、1エントリの失敗が他エントリを止めない）。
fn grant_fs_allow_entries(
    sid: PSID,
    entries: Vec<FsAllowGrant>,
) -> (Vec<PathBuf>, Vec<(PathBuf, String)>) {
    let mut granted = Vec::new();
    let mut failures = Vec::new();
    for entry in entries {
        let started = std::time::Instant::now();
        // forced（--force-system-acl, D-19）は`SeRestorePrivilege`で全DACLをバイパスして
        // 書くため、書込前に必ず host パスの絶対拒否ゲートを通す（唯一の防壁）。
        if entry.forced {
            if let Some(reason) = win_appcontainer::is_force_grant_forbidden(&entry.path) {
                log::line(&format!(
                    "  entry {} : forced grant REFUSED by deny-gate: {reason}",
                    entry.path.display()
                ));
                failures.push((entry.path, reason));
                continue;
            }
        }
        let do_grant =
            || win_appcontainer::grant_ace_inheritable_access(&entry.path, sid, entry.access);
        // forcedのみ`SeRestorePrivilege`を有効化して実行する（TrustedInstaller所有ノードへも
        // 所有権を変えずにACEを書ける）。非forcedは従来どおり特権無しで実行する。
        let result = if entry.forced {
            win_appcontainer::with_restore_privilege(do_grant)
        } else {
            do_grant()
        };
        match result {
            Ok(()) => {
                log::line(&format!(
                    "  entry {} [{}{}] : granted in {}ms",
                    entry.path.display(),
                    if entry.access.is_read_write() { "rw" } else { "ro" },
                    if entry.forced { ",forced" } else { "" },
                    started.elapsed().as_millis()
                ));
                granted.push(entry.path);
            }
            Err(e) => {
                log::line(&format!(
                    "  entry {} [{}{}] : FAILED after {}ms: {e}",
                    entry.path.display(),
                    if entry.access.is_read_write() { "rw" } else { "ro" },
                    if entry.forced { ",forced" } else { "" },
                    started.elapsed().as_millis()
                ));
                failures.push((entry.path, e.to_string()));
            }
        }
    }
    (granted, failures)
}

/// `GrantWorkspaceAccess`用: 複数のtraverseターゲット（`--cow`ならworkspace_root・upper_dirの
/// 2つ）を独立に処理する。`GrantTraverse`（単一target）と異なり、1ターゲットのチェーンが
/// 途中で失敗しても他のターゲットの処理は続行する（workspace_rootとupper_dirは別の祖先
/// チェーンであり、片方の失敗がもう片方を無意味にするとは限らないため）。最初に発生した
/// エラーのみ`traverse_error`へ載せる（`target: reason`形式でどのターゲットの失敗か分かるようにする）。
/// いずれの場合も、実際にACEが付与された全ノードを`granted`へ積む（孤立ACE防止、`GrantChain`と
/// 同じ不変条件）。
fn grant_traverse_targets(
    sid: PSID,
    targets: Vec<PathBuf>,
) -> (Vec<PathBuf>, Option<String>) {
    let mut all_granted = Vec::new();
    let mut first_error: Option<String> = None;
    for target in targets {
        let (granted, result) = win_appcontainer::grant_traverse_chain_with_progress(
            &target,
            sid,
            |node, node_result, elapsed| match node_result {
                Ok(()) => log::line(&format!(
                    "  node {} : granted in {}ms",
                    node.display(),
                    elapsed.as_millis()
                )),
                Err(e) => log::line(&format!(
                    "  node {} : FAILED after {}ms: {e}",
                    node.display(),
                    elapsed.as_millis()
                )),
            },
        );
        all_granted.extend(granted);
        if let Err(e) = result {
            if first_error.is_none() {
                first_error = Some(format!("{}: {e}", target.display()));
            }
        }
    }
    (all_granted, first_error)
}

/// 固定スキーマの要求だけを実行する（D-16の核: ここに到達する時点でスキーマ検証済み、
/// 自由形式のコマンド文字列は一切扱わない）。SIDはIPCで受け取らず、安定定数
/// `CONTAINER_NAME`から`ensure_profile`で自ら導出する。
fn dispatch(req: PrivilegedRequest) -> PrivilegedResponse {
    let sid = match win_appcontainer::ensure_profile(CONTAINER_NAME) {
        Ok(sid) => sid,
        Err(e) => {
            log::line(&format!("dispatch: ensure_profile failed: {e}"));
            return PrivilegedResponse::Err(format!("failed to resolve sandbox SID: {e}"));
        }
    };
    match req {
        PrivilegedRequest::GrantTraverse { target } => {
            log::line(&format!(
                "dispatch: GrantTraverse target={}",
                target.display()
            ));
            let (granted, result) = win_appcontainer::grant_traverse_chain_with_progress(
                &target,
                sid.as_psid(),
                |node, node_result, elapsed| match node_result {
                    Ok(()) => log::line(&format!(
                        "  node {} : granted in {}ms",
                        node.display(),
                        elapsed.as_millis()
                    )),
                    Err(e) => log::line(&format!(
                        "  node {} : FAILED after {}ms: {e}",
                        node.display(),
                        elapsed.as_millis()
                    )),
                },
            );
            log::line(&format!(
                "dispatch: GrantTraverse done, {} node(s) granted, error={:?}",
                granted.len(),
                result.as_ref().err()
            ));
            PrivilegedResponse::GrantChain {
                granted,
                error: result.err().map(|e| e.to_string()),
            }
        }
        PrivilegedRequest::RevokeTraverse { path } => {
            log::line(&format!("dispatch: RevokeTraverse path={}", path.display()));
            let result: Result<(), AppContainerError> =
                win_appcontainer::revoke_ace(&path, sid.as_psid())
                    .and_then(|()| win_appcontainer::assert_no_sid_ace(&path, sid.as_psid()));
            log::line(&format!(
                "dispatch: RevokeTraverse done, error={:?}",
                result.as_ref().err()
            ));
            match result {
                Ok(()) => PrivilegedResponse::Ok,
                Err(e) => PrivilegedResponse::Err(e.to_string()),
            }
        }
        PrivilegedRequest::GrantFsAllow { entries } => {
            log::line(&format!(
                "dispatch: GrantFsAllow {} entrie(s)",
                entries.len()
            ));
            let (granted, failures) = grant_fs_allow_entries(sid.as_psid(), entries);
            log::line(&format!(
                "dispatch: GrantFsAllow done, {} granted, {} failed",
                granted.len(),
                failures.len()
            ));
            PrivilegedResponse::FsAllowResult { granted, failures }
        }
        PrivilegedRequest::GrantWorkspaceAccess {
            traverse_targets,
            fs_allow_entries,
        } => {
            log::line(&format!(
                "dispatch: GrantWorkspaceAccess {} traverse target(s), {} fs-allow entrie(s)",
                traverse_targets.len(),
                fs_allow_entries.len()
            ));
            let (traverse_granted, traverse_error) =
                grant_traverse_targets(sid.as_psid(), traverse_targets);
            let (fs_allow_granted, fs_allow_failures) =
                grant_fs_allow_entries(sid.as_psid(), fs_allow_entries);
            log::line(&format!(
                "dispatch: GrantWorkspaceAccess done, {} traverse node(s) granted (error={:?}), \
                 {} fs-allow granted, {} fs-allow failed",
                traverse_granted.len(),
                traverse_error,
                fs_allow_granted.len(),
                fs_allow_failures.len()
            ));
            PrivilegedResponse::WorkspaceAccessResult {
                traverse_granted,
                traverse_error,
                fs_allow_granted,
                fs_allow_failures,
            }
        }
        PrivilegedRequest::RevokeFsAllow { entries } => {
            log::line(&format!(
                "dispatch: RevokeFsAllow {} path(s)",
                entries.len()
            ));
            let mut revoked = Vec::new();
            let mut root_cleared = Vec::new();
            let mut failures = Vec::new();
            for entry in entries {
                let path = entry.path;
                let started = std::time::Instant::now();
                // forcedなパス（--force-system-aclで付与したACE）は撤収時も`SeRestorePrivilege`が要る。
                let do_revoke = || win_appcontainer::revoke_passthrough(&path, sid.as_psid());
                let outcome = if entry.forced {
                    win_appcontainer::with_restore_privilege(do_revoke)
                } else {
                    do_revoke()
                };
                match outcome {
                    win_appcontainer::RevokeOutcome::FullyRevoked => {
                        log::line(&format!(
                            "  path {} : revoked in {}ms",
                            path.display(),
                            started.elapsed().as_millis()
                        ));
                        revoked.push(path);
                    }
                    win_appcontainer::RevokeOutcome::RootClearedDescendantsBlocked => {
                        log::line(&format!(
                            "  path {} : root cleared (descendants blocked) in {}ms",
                            path.display(),
                            started.elapsed().as_millis()
                        ));
                        root_cleared.push(path);
                    }
                    win_appcontainer::RevokeOutcome::Failed => {
                        log::line(&format!(
                            "  path {} : FAILED after {}ms (root ACE still present)",
                            path.display(),
                            started.elapsed().as_millis()
                        ));
                        failures.push((
                            path,
                            "root ACE still present after revoke attempt".to_string(),
                        ));
                    }
                }
            }
            log::line(&format!(
                "dispatch: RevokeFsAllow done, {} revoked, {} root-cleared, {} failed",
                revoked.len(),
                root_cleared.len(),
                failures.len()
            ));
            PrivilegedResponse::RevokeFsAllowResult {
                revoked,
                root_cleared,
                failures,
            }
        }
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
            request: PrivilegedRequest::GrantFsAllow {
                entries: vec![FsAllowGrant {
                    path: PathBuf::from(r"C:\ProgramData\Microsoft\VisualStudio\Setup"),
                    access: FsAccess::ReadExec,
                    forced: false,
                }],
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
            PrivilegedRequest::GrantFsAllow { entries } => assert_eq!(entries.len(), 1),
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

    #[test]
    fn grant_fs_allow_request_roundtrips_through_json() {
        let req = PrivilegedRequest::GrantFsAllow {
            entries: vec![
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
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let decoded: PrivilegedRequest = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            PrivilegedRequest::GrantFsAllow { entries } => {
                assert_eq!(entries.len(), 2);
                assert_eq!(
                    entries[0].path,
                    PathBuf::from(r"C:\ProgramData\Microsoft\VisualStudio\Setup")
                );
                assert_eq!(entries[0].access, FsAccess::ReadExec);
                assert!(!entries[0].forced);
                assert_eq!(entries[1].access, FsAccess::ReadWrite);
                assert!(entries[1].forced);
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
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let decoded: PrivilegedRequest = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            PrivilegedRequest::GrantWorkspaceAccess {
                traverse_targets,
                fs_allow_entries,
            } => {
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

    /// `FsAllowResult`応答が、成功エントリと失敗エントリが混在する状態でも両方を失わずに
    /// ラウンドトリップできることを確認する（`GrantChain`と違い連鎖ではないので、1件の失敗が
    /// 他の成功エントリを消してはならない）。
    #[test]
    fn fs_allow_result_response_roundtrips_with_mixed_outcomes() {
        let resp = PrivilegedResponse::FsAllowResult {
            granted: vec![PathBuf::from(
                r"C:\ProgramData\Microsoft\VisualStudio\Setup",
            )],
            failures: vec![(
                PathBuf::from(r"C:\Windows\System32\config"),
                "access denied".to_string(),
            )],
        };
        let bytes = serde_json::to_vec(&resp).unwrap();
        let decoded: PrivilegedResponse = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            PrivilegedResponse::FsAllowResult { granted, failures } => {
                assert_eq!(
                    granted,
                    vec![PathBuf::from(
                        r"C:\ProgramData\Microsoft\VisualStudio\Setup"
                    )]
                );
                assert_eq!(failures.len(), 1);
                assert_eq!(failures[0].0, PathBuf::from(r"C:\Windows\System32\config"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
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
