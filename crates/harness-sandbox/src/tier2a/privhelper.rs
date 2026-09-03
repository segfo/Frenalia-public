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
//! （`CONTAINER_NAME`・`TRAVERSE_CAPABILITY_NAME`）またはIPCで受けた入力からSIDを
//! **自ら導出する**。生ポインタをプロセス境界・特権境界を越えてIPCで渡す必要自体を無くす
//! 設計判断。
//!
//! **[§22.3.1] `--fs-allow`の宛先SIDは「秘密」から導出する**（2026-08-25）。以前はセッションの
//! プロファイル**名**を受け取り、形を検証してからpackage SIDを導出していた。付与先が
//! 宣言ごとのcapability SIDへ移ったので、いま受け取るのは
//! [`FsAllowGrant::secret_hex`]（導出の前像）で、ヘルパーは
//! `(その秘密, **自分で畳み込んだ書込先のパス**, access級)`から宛先SIDを導出する。
//! **「SIDはIPCで受け取らず、受信側が自ら導出する」は字義どおり保たれている**——加えて、
//! 導出入力に書込先のパスが入るぶん**現行より束縛が強い**（宣言Aの秘密で別のパスBへ
//! AのSIDを付けさせられない）。
//!
//! **秘密をログへ出さないこと。** このモジュールの`log::line`はユーザーのプロファイル配下の
//! 平文ファイルへ追記する。要求の中身を素直に書くと秘密がそこへ落ちる（実装制約、§22.3.1）。
//!
//! **例外: WFP連鎖起動**（`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`付録D）。UAC起動回数を
//! 最小化するため、`GrantWorkspaceAccess`要求が同時に「処理完了後、指定named pipeで`harness-netfilterd`を
//! 起動してほしい」という指示（[`PrivilegedRequestEnvelope::chain_netfilterd_pipe`]）を伴うことが
//! ある。この場合だけ、ヘルパーはACL操作を終えたあと`CreateProcessW`（`runas`は使わない、
//! 自分の昇格済みトークンをそのまま子へ継承させる）で`harness-netfilterd.exe`を追加起動し、
//! **その結末を応答に載せてから**終了する。「1起動=1操作で常駐しない」という原則は、
//! 「ACL操作1件＋（指示があれば）子プロセスを1つ起動する」までを1操作とみなす形で維持する
//! （ヘルパー自身は常駐しない。常駐するのはあくまで子として起動された`harness-netfilterd`側）。
//!
//! **連鎖起動は応答より前に行う**（2026-08-09、BUG-093の修正で順序を変えた）。以前は応答を
//! 先に送り、連鎖起動の失敗は`log::line`だけで握り潰していたため、失敗しても呼び出し元には
//! 何も届かず、親は`ConnectNamedPipe`が30秒タイムアウトするまで待ってから`NoWfp`で
//! fail-closedしていた（この機で実際に発生し、`privhelper.log`にだけ記録が残っていた）。
//! 結末を[`PrivilegedResponse::WorkspaceAccessResult::netfilterd_chain`]で返せば、親は
//! 待たずにシナリオ(B)（自前の`runas`起動）へ移れる。**順序を変えても競合は起きない**——
//! 起こされたnetfilterdが親の`ConnectNamedPipe`より先に接続してくる場合は
//! `ERROR_PIPE_CONNECTED`として`win_pipe_ipc::run_overlapped`が既に成功扱いにしている。

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_CANCELLED, HANDLE, HLOCAL, WAIT_OBJECT_0,
};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::{
    CheckTokenMembership, GetTokenInformation, TokenElevation, TokenElevationType, PSID,
    TOKEN_ELEVATION, TOKEN_ELEVATION_TYPE, TOKEN_QUERY,
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

use crate::shell_tier::{FsAccess, GrantScope};
use crate::tier2a::win_appcontainer::{self, AppContainerError};
use crate::win_common::wide;

/// ヘルパーへ委譲する操作。自由形式のコマンド文字列ではなく固定スキーマに限定する（D-16）。
/// 将来の特権操作（WFPフィルタ設置・VHDXマウント等、`DESIGN-SANDBOX-PRIVSEP.md` §5.2）は
/// ここへvariantを追加する形で拡張する。
/// `--fs-allow`の1エントリ（`GrantWorkspaceAccess`要求のペイロード）。`shell_tier::FsPassthrough`と
/// 同形だが、IPCでシリアライズする要求スキーマとして独立させる（`shell_tier::FsPassthrough`は
/// IPCを経由しない本体内部の値であり、両者の変更を意図せず連動させないため）。
///
/// **`Debug`は手書きである**（[`FsAllowGrant::secret_hex`]の理由）。`derive`のままだと
/// `{:?}`を書いた瞬間に秘密がログへ落ちる。
#[derive(Clone, Serialize)]
pub struct FsAllowGrant {
    pub path: PathBuf,
    pub access: FsAccess,
    /// `--force-system-acl`（D-19）: システム保護パス（`WRITE_DAC`不可）へ
    /// `SeRestorePrivilege`を有効化して強制付与する。dispatch側で`is_force_grant_forbidden`の
    /// ゲートを通過したもののみ`with_restore_privilege`下で付与する。既定false。
    #[serde(default)]
    pub forced: bool,
    /// [D-63] 付与範囲。宣言値が`<path>/**`なら`Recursive`、素のパスなら`Object`。
    ///
    /// **昇格側も同じ分岐を通らなければ意味が無い。** 非昇格側だけがオブジェクト単体にしても、
    /// システム保護パスへ回ったエントリだけ従来どおり継承ACEになる——「対の片方だけ実装する」の
    /// 典型（B-02）。
    ///
    /// **欠落時の既定は`Recursive`**（[`default_grant_scope`]）。この形の電文を送ってくるのは
    /// D-63以前のビルドだけで、**その送り手が意味していたのは再帰**だからである。狭い方へ
    /// 倒すと「成功と報告しながら宣言どおりに開かない」無言失敗になる（B-10）。
    #[serde(default = "default_grant_scope")]
    pub scope: GrantScope,
    /// [§22.3.1] この宣言のcapabilityの**導出の前像**（16進の秘密）。
    ///
    /// # なぜSIDでも名前でもなく秘密なのか
    ///
    /// 昇格側は`(この秘密, **自分で畳み込んだ`path`**, `access`の級)`から宛先SIDを導出する。
    /// パスが導出入力に入っているので、**宣言Aの秘密を使って別のパスBへAのSIDを
    /// 付けさせることができない**（現行のpackage SID方式には無かった束縛）。
    ///
    /// SID値を渡す案は却下されている——「形」で分かるのはcapability SIDであることまでで、
    /// **そのSIDを呼び出し元が正当に持つか**は判定できない。台帳を昇格側に読ませる案も
    /// 却下——`%APPDATA%`はアカウントごとで、`runas`の昇格先が別の管理者アカウントなら
    /// 別物を指すため、秘密の置き場の移設を要求してしまう（§22.3.1の却下表）。
    ///
    /// **空文字は「移行前のビルドからの電文」を意味する。** 受信側はそれを
    /// **拒否する**（fail-closed）——空を許すと、秘密を持たない要求が
    /// package SID宛の旧挙動へ黙って落ちる。
    ///
    /// **この値をログへ出さないこと**（§22.3.1の実装制約1）。受信側は要求内容を
    /// 詳細に記録するので、素直に足すと`privhelper.log`へ秘密が落ちる。
    #[serde(default)]
    pub secret_hex: String,
}

/// [`FsAllowGrant::scope`]が欠けている電文の既定（D-63以前のビルドの意味＝再帰）。
fn default_grant_scope() -> GrantScope {
    GrantScope::Recursive
}

/// [§22.3.1] **秘密を持つ要求型の`Debug`は手書きにして、秘密の欄そのものを落とす。**
///
/// 整形の呼び出し側で伏字化する形にすると、`{:?}`を使う経路が1つ増えるたびに漏れが復活する
/// ——**書き手が気をつける形にしない**（設計側の決定そのもの）。ここでは「有無」だけを出す:
/// 移行前ビルドの電文（秘密なし）を診断できる必要があり、そこは秘密の中身を要さない。
///
/// `harness-engine`の`sanitize`は流用しない。あれはプロバイダへ送るリクエスト全体から
/// Windowsの絶対パスを消す層で、対象も入力も別物である。
fn fmt_secret_presence(secret_hex: &str) -> &'static str {
    if secret_hex.is_empty() {
        "<none>"
    } else {
        "<redacted>"
    }
}

impl std::fmt::Debug for FsAllowGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsAllowGrant")
            .field("path", &self.path)
            .field("access", &self.access)
            .field("forced", &self.forced)
            .field("scope", &self.scope)
            .field("secret_hex", &fmt_secret_presence(&self.secret_hex))
            .finish()
    }
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
            // [D-63] **`Raw`にも足すこと。** 手書きの`Deserialize`があるので、`FsAllowGrant`側の
            // `#[serde(default)]`はこの経路では一切効かない（フィールドを足したのに読まれない、
            // というプロセス境界の無言失敗になる）。
            #[serde(default = "default_grant_scope")]
            scope: GrantScope,
            // [§22.3.1] 同上。ここへ足し忘れると、秘密は**送られているのに読まれず**、
            // 受信側は空文字を見て全エントリを拒否する（幸い fail-closed 側だが、
            // 症状は「昇格経由の穴だけが全部失敗する」になる）。
            #[serde(default)]
            secret_hex: String,
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
            scope: raw.scope,
            secret_hex: raw.secret_hex,
        })
    }
}

/// [§22.3.1] `RevokeFsAllow`が剥がす**宣言capabilityの宛先SID 1件**。
///
/// 付与（[`FsAllowGrant`]）とまったく同じ形で渡す——**SIDも名前も送らず、秘密とaccess級だけ**を
/// 送り、受信側が`(この秘密, 自分で畳み込んだ対象パス, access級)`から導出する。撤収でだけ
/// SIDを受け取る形にすると、「導出はこの側で行う」という`privhelper`の原則が撤収側にだけ
/// 無いことになる（対の片方だけ別の作りにしない、B-02）。
///
/// 1つの宣言パスに対して複数のaccess級が発行され得る（§22.3.3）ので、エントリは配列で運ぶ。
///
/// **`Debug`は手書きである**（[`fmt_secret_presence`]）。
#[derive(Clone, Serialize, Deserialize)]
pub struct FsAllowRevokeSubject {
    /// 宣言capabilityの導出の前像（16進の秘密）。**ログへ出さない。**
    pub secret_hex: String,
    /// 導出鍵のaccess級。**付与したときと同じ値**でなければ別の宛先SIDになる
    /// （CoWでRO降格した宣言は降格後の級で発行されている）。
    pub access: FsAccess,
}

impl std::fmt::Debug for FsAllowRevokeSubject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsAllowRevokeSubject")
            .field("secret_hex", &fmt_secret_presence(&self.secret_hex))
            .field("access", &self.access)
            .finish()
    }
}

/// `RevokeFsAllow`要求の1エントリ。`forced`なパス（`--force-system-acl`で付与したもの）は
/// 撤収時も`SeRestorePrivilege`が要るため、grantと対称に`forced`を運ぶ（新たな非対称を作らない）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsAllowRevoke {
    pub path: PathBuf,
    #[serde(default)]
    pub forced: bool,
    /// [§22.2.1] このパスへ発行済みの**宣言capability**の前像一覧。
    ///
    /// **空は「移行前ビルドからの電文」か「宣言capabilityが1件も無いパス」を意味する。**
    /// 付与側と違い、ここでは**空を拒否しない**——撤収を止めると、剥がせないACEが実マシンに
    /// 残ったままになる（fail-closedが逆に働く唯一の場所）。代わりに受信側は
    /// 「package SIDの分は剥がしたが、宣言capabilityは1件も見ていない」と応答で区別できる形にし、
    /// **非昇格側が自分の台帳で実DACLを検算する**（`declaration_capabilities_on_root`）。
    #[serde(default)]
    pub subjects: Vec<FsAllowRevokeSubject>,
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
    /// `GrantTraverse`で付与したACEを**まとめて1回のUACで**撤収する
    /// （`harness fs revoke-traverse-all`）。
    ///
    /// # なぜ単発版と別に要るのか（`B-02`: 片側に入れた変更は逆操作へ波及させる）
    ///
    /// **付与側は既に束ねてある**——[`PrivilegedRequest::GrantWorkspaceAccess`]の
    /// `traverse_targets`は複数targetを1回のUACで処理し、[`PrivilegedRequest::GrantTraverse`]
    /// 自身も祖先チェーン全部を1回で付与する（コマンドの説明文も "UAC, one-time" と名乗る）。
    /// ところが撤収側は単発の[`PrivilegedRequest::RevokeTraverse`]しか無く、
    /// `revoke-traverse-all`は**それを台帳の件数だけループする**実装だった
    /// ——実機の563件で563回UACが出て、操作そのものが成立しなかった。
    ///
    /// **エントリごとに成否は独立する**（`RevokeFsAllow`と同じで、`GrantTraverse`のような
    /// 連鎖ではない）。走行中セッションによる撤収拒否（D-48）も1件の失敗として扱い、
    /// 他のエントリを止めない——1件で打ち切ると、残りのACEが実マシンに残ったまま
    /// 「撤収した」と読める終わり方になる。
    RevokeTraverseBatch { paths: Vec<PathBuf> },
    /// `harness fs revoke`/`revoke-all`が本体プロセス内（非管理者）で撤収しきれなかった
    /// パス（`GrantWorkspaceAccess`でシステム保護パスへ付与したACE等）をまとめて1回のUACで
    /// 撤収する（付与側の裏対称、`BUG-015`参照）。各エントリは`revoke_harness_subjects`
    /// （ツリー全体を再walk＋root再プローブ）で撤収する。`forced`なパスは`SeRestorePrivilege`下で
    /// 撤収する（grantと対称に`forced`を運び新たな非対称を作らない、`FsAllowRevoke`参照）。
    ///
    /// # [BUG-101] 宛先SIDは名前ではなく**対象パスのDACL**から決める
    ///
    /// 以前は旧共有プロファイル（`CONTAINER_NAME`）のSID固定で、「D-37以前に付けたACEを
    /// 掃除するのが役目」と説明していた。しかし実際に載っているのはセッション固有SIDなので、
    /// **探す相手が違って1件も剥がれない**（実マシンの6箇所で再現）。いまは対象パスのDACLに
    /// 実在するパッケージSIDを分類して剥がす。生きているセッションのSID宛ACEに触らないのは
    /// 従来どおり（判定は`revoke_subjects`の規則1が持つ）。
    ///
    /// **SIDはIPCで運ばない**（D-16の原則は不変）。昇格側は渡されたパスを自分で読む。
    /// ただし昇格側では「台帳の記録」と「未登録SIDのマスク指紋」による判定は使わない
    /// ——`runas`の昇格先が別の管理者アカウントだと`HKCU`が別ハイブになるため（`server.rs`参照）。
    RevokeFsAllow { entries: Vec<FsAllowRevoke> },
    /// **非管理者からのTier2a起動が特権を要するときに通る唯一の要求**。
    /// `win_appcontainer::preflight`が自動検知した、workspace_root/diff_layer_dir祖先チェーンの
    /// traverse不足（複数ターゲットあり得る、`--sandbox tier2a-cow`ではworkspace_rootとdiff_layer_dirの2つ）と
    /// `--fs-allow`昇格要求を、1回のUACへまとめて処理する（起動あたりUAC最大1回の原則、
    /// `plans/DESIGN-SANDBOX-PRIVSEP.md` D-16/D-31「特権昇格デーモンを使う際の注意点」参照）。
    /// `preflight`はtraverse不足の有無で分岐せず、常にこの1本へ束ねる。
    ///
    /// 残る`GrantTraverse`/`RevokeTraverse`は`harness fs grant-traverse`/`revoke-traverse`
    /// （単一target、起動とは独立した手動コマンド）専用である。
    /// # [§22.3.1] `session_profile`は無くなった
    ///
    /// D-37の頃、この要求は`fs_allow_entries`の付与先を決めるために**セッションプロファイル名**を
    /// 運んでいた（受信側が形を検証してからpackage SIDを導出する形）。`--fs-allow`の宛先SIDが
    /// 宣言ごとのcapability SIDへ移ったので、その名前はもう何も決めない——**残しておくと
    /// 「これが付与先を決めている」という誤読を招く**ので落とした。付与先を決めるのは
    /// いま各[`FsAllowGrant::secret_hex`]と、受信側が畳み込む`path`である。
    ///
    /// `traverse_targets`側は従来どおり名前に依存しない（祖先traverseはharness共通の
    /// capability SID宛で、昇格側が固定名から自ら導出する）。
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
    /// `RevokeTraverseBatch`の結果。エントリごとに成否が独立する（連鎖ではない）。
    ///
    /// **呼び出し側が台帳から除去してよいのは`revoked`だけである。**
    /// `failures`の分まで消すと、実マシンに残ったACEへ**二度と到達できなくなる**
    /// ——traverse ACEの宛先SIDは固定名から導出されるので名前は失われないが、
    /// 「どのパスに付けたか」は台帳にしか無い（`B-01`「名前を捨てる操作は最後に置き、
    /// 剥がせたことを確認できたときだけ捨てる」）。
    RevokeTraverseBatchResult {
        revoked: Vec<PathBuf>,
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
        /// WFP連鎖起動（[`PrivilegedRequestEnvelope::chain_netfilterd_pipe`]）の**結末**。
        ///
        /// - `None` — 連鎖起動を依頼されていない
        /// - `Some(Ok(()))` — 起こした。呼び出し側はそのパイプでハンドシェイクしてよい
        /// - `Some(Err(reason))` — 起こせなかった。**呼び出し側は待たずにシナリオB
        ///   （`NetfilterHandle::start`＝`runas`）へ落ちること**
        ///
        /// これが無かった頃、失敗は`privhelper.log`にしか残らず、親は`ConnectNamedPipe`が
        /// 30秒タイムアウトしてから`NoWfp`でfail-closedしていた（BUG-093と同型、実機で発生）。
        ///
        /// **追加は必ず末尾へ**。`#[serde(default)]`なので、この項目を持たない旧応答も読める。
        #[serde(default)]
        netfilterd_chain: Option<Result<(), String>>,
    },
}

impl PrivilegedResponse {
    /// WFP連鎖起動の結末を応答へ添える（`WorkspaceAccessResult`以外は素通し）。
    ///
    /// 連鎖起動を依頼できるのは`GrantWorkspaceAccess`だけなので、他のvariantには
    /// 載せる場所を作らない——**載る余地のある型を作ると、載っていないことの意味が曖昧になる**。
    pub(crate) fn with_netfilterd_chain_result(
        mut self,
        result: Option<Result<(), String>>,
    ) -> Self {
        if let PrivilegedResponse::WorkspaceAccessResult {
            ref mut netfilterd_chain,
            ..
        } = self
        {
            *netfilterd_chain = result;
        }
        self
    }
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

/// このユーザーが**そもそも昇格できるか**（UACに応じれば管理者になれるか）。
///
/// [`is_elevated`]（＝いま昇格しているか）とは別の問いである。この2つを混同すると、
/// **UACを1回キャンセルしただけのユーザーを「管理者権限が無い人」と扱ってしまう**。
/// Tier選択はこの区別に依存している——昇格できないなら保護の無いTier0へ宣言付きで降格し、
/// 昇格できるのに今回失敗しただけなら起動時エラーにする（`shell_tier::best_effort_tier`）。
/// 区別せずに降格させると、UACの押し間違い1回で保護が黙って外れる。
///
/// 判定は3つの状態を見る。
///
/// 1. 既に昇格済み（`TokenIsElevated`）——当然できる。
/// 2. **分割トークン**（`TokenElevationTypeLimited`）——UACが有効な管理者。応じれば昇格できる。
/// 3. UACが無効な管理者（`TokenElevationTypeDefault`かつBUILTIN\Administratorsのメンバー）。
///
/// 2の状態では`CheckTokenMembership`はAdministratorsに対して**偽を返す**
/// （フィルタ済みトークンではDENY_ONLY属性が付く）ので、3の判定だけでは足りない。
///
/// 判定に失敗したときは`true`を返す（[`is_elevated`]のfail-safeとは**向きが逆**）。
/// ここでの安全側は「勝手に保護を外さない」ことなので、分からないなら
/// 「昇格できるかもしれない」＝降格しない側へ倒す。
pub fn can_elevate() -> bool {
    if is_elevated() {
        return true;
    }
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return true;
        }
        let mut elevation_type = TOKEN_ELEVATION_TYPE::default();
        let mut ret_len = 0u32;
        let queried = GetTokenInformation(
            token,
            TokenElevationType,
            Some(&mut elevation_type as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION_TYPE>() as u32,
            &mut ret_len,
        );
        let _ = CloseHandle(token);
        if queried.is_err() {
            return true;
        }
        // TokenElevationTypeLimited == 3（分割トークン＝UACが有効な管理者）。
        if elevation_type.0 == 3 {
            return true;
        }

        // 残るのはTypeDefault。UACを無効にした管理者がここに来るので、素の所属を見る。
        let sid_w = crate::win_common::wide("S-1-5-32-544"); // BUILTIN\Administrators
        let mut sid = PSID::default();
        if ConvertStringSidToSidW(PCWSTR(sid_w.as_ptr()), &mut sid).is_err() {
            return true;
        }
        let mut is_member = windows::Win32::Foundation::BOOL(0);
        // 第1引数`None`＝呼び出しスレッドの実効トークン。
        let checked = CheckTokenMembership(None, sid, &mut is_member);
        let _ = LocalFree(HLOCAL(sid.0));
        match checked {
            Ok(()) => is_member.as_bool(),
            Err(_) => true,
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
    run_privileged, run_privileged_revoke_fs_allow, run_privileged_revoke_traverse_batch,
    run_privileged_workspace_access, ChainLauncher, FsAllowRevokeOutcome,
    TraverseRevokeBatchOutcome, HELPER_EXE_NAME,
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
        assert!(
            ok.is_ok(),
            "ConvertSecurityDescriptorToStringSecurityDescriptorW failed"
        );
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
        assert_eq!(
            sa.bInheritHandle.0, 0,
            "the pipe handle must not be inheritable"
        );
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
                    scope: GrantScope::Recursive,
                    secret_hex: "00112233445566778899aabbccddeeff".to_string(),
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
                    scope: GrantScope::Recursive,
                    secret_hex: "00112233445566778899aabbccddeeff".to_string(),
                },
                FsAllowGrant {
                    path: PathBuf::from(r"C:\Program Files\SomeTool"),
                    access: FsAccess::ReadWrite,
                    forced: true,
                    scope: GrantScope::Recursive,
                    secret_hex: "00112233445566778899aabbccddeeff".to_string(),
                },
            ],
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
                scope: GrantScope::Recursive,
                secret_hex: "00112233445566778899aabbccddeeff".to_string(),
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
                // [§22.3.1] **秘密がプロセス境界を越えて生き残ること。** ここが落ちると
                // 昇格側は宛先SIDを導出できず、システム保護パスの穴が全部失敗する。
                assert_eq!(
                    fs_allow_entries[0].secret_hex,
                    "00112233445566778899aabbccddeeff"
                );
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    /// D-34: プロセス境界を越える形はバイト列そのものを固定する。
    ///
    /// [§22.3.1] **`session_profile`は消え、`secret_hex`が載った。** 付与先を決めるものが
    /// 「セッションのプロファイル名」から「宣言の秘密＋受信側が畳み込む書込先のパス」へ
    /// 変わったので、綴りごとここで固定し直す。この行が黙って変わったら、
    /// **昇格側と非昇格側のどちらかだけが移行している**ことを意味する。
    #[test]
    fn grant_workspace_access_request_json_wire_format_is_stable() {
        let req = PrivilegedRequest::GrantWorkspaceAccess {
            traverse_targets: vec![PathBuf::from("C:/ws")],
            fs_allow_entries: vec![FsAllowGrant {
                path: PathBuf::from("C:/x"),
                access: FsAccess::Read,
                forced: false,
                scope: GrantScope::Object,
                secret_hex: "00112233445566778899aabbccddeeff".to_string(),
            }],
        };
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"GrantWorkspaceAccess":{"traverse_targets":["C:/ws"],"fs_allow_entries":[{"path":"C:/x","access":"read","forced":false,"scope":"Object","secret_hex":"00112233445566778899aabbccddeeff"}]}}"#
        );
    }

    /// D-34: 撤収要求も**バイト列そのものを固定する**（付与側と対称。B-02）。
    ///
    /// [§22.2.1] `subjects`が載ったことで、昇格が要るパスからも宣言capabilityを剥がせるように
    /// なった。この行が黙って変わったら、**昇格側と非昇格側のどちらかだけが移行している**
    /// ことを意味する——付与だけを固定して撤収を固定しないと、その非対称が検出できない。
    #[test]
    fn revoke_fs_allow_request_json_wire_format_is_stable() {
        let req = PrivilegedRequest::RevokeFsAllow {
            entries: vec![FsAllowRevoke {
                path: PathBuf::from("C:/x"),
                forced: false,
                subjects: vec![FsAllowRevokeSubject {
                    secret_hex: "00112233445566778899aabbccddeeff".to_string(),
                    access: FsAccess::Read,
                }],
            }],
        };
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"RevokeFsAllow":{"entries":[{"path":"C:/x","forced":false,"subjects":[{"secret_hex":"00112233445566778899aabbccddeeff","access":"read"}]}]}}"#
        );
    }

    /// `revoke-traverse-all`が**1回のUAC**で撤収するための要求と応答の形を固定する（`B-02`）。
    ///
    /// **単発の`RevokeTraverse`と別の形であることに意味がある**——応答がパスごとの成否を
    /// 運べないと、呼び出し側は「どれを台帳から落としてよいか」を決められず、
    /// 剥がせていないACEの記録まで消してしまう（`B-01`）。
    #[test]
    fn revoke_traverse_batch_request_and_result_json_wire_format_is_stable() {
        let req = PrivilegedRequest::RevokeTraverseBatch {
            paths: vec![PathBuf::from("C:/x"), PathBuf::from("C:/y")],
        };
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"RevokeTraverseBatch":{"paths":["C:/x","C:/y"]}}"#
        );

        let res = PrivilegedResponse::RevokeTraverseBatchResult {
            revoked: vec![PathBuf::from("C:/x")],
            failures: vec![(PathBuf::from("C:/y"), "in use".to_string())],
        };
        assert_eq!(
            serde_json::to_string(&res).unwrap(),
            r#"{"RevokeTraverseBatchResult":{"revoked":["C:/x"],"failures":[["C:/y","in use"]]}}"#
        );
    }

    /// [§22.3.1] **秘密を持たない電文は拒否される**（fail-closed）。
    ///
    /// 移行前のビルドが送ってくる形がこれで、通すと「宛先SIDを決められないまま何かへ付与する」
    /// ことになる。受信側の判定は`grant_fs_allow_entries`が持つので、ここでは
    /// **その判定材料が電文から復元できること**（空文字として読めること）を固定する。
    #[test]
    fn a_pre_migration_entry_arrives_without_a_secret() {
        let grant: FsAllowGrant =
            serde_json::from_str(r#"{"path":"C:/x","access":"read","scope":"Object"}"#).unwrap();
        assert_eq!(grant.secret_hex, "");
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
            netfilterd_chain: Some(Err("refusing to chain-launch the WFP daemon".to_string())),
        };
        let bytes = serde_json::to_vec(&response).unwrap();
        let decoded: PrivilegedResponse = serde_json::from_slice(&bytes).unwrap();
        match decoded {
            PrivilegedResponse::WorkspaceAccessResult {
                traverse_granted,
                traverse_error,
                fs_allow_granted,
                fs_allow_failures,
                netfilterd_chain,
            } => {
                // **連鎖起動の結末が往復すること**（BUG-093）。これが落ちると、親は
                // 「起こせなかった」を知れずに30秒待ってからfail-closedへ倒れる。
                assert_eq!(
                    netfilterd_chain,
                    Some(Err("refusing to chain-launch the WFP daemon".to_string()))
                );
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

    /// **和の値（`ReadWriteExec`）がIPCを越える形を固定する。**
    ///
    /// `FsAccess`は昇格側（`harness-privhelper.exe`）が別プロセスとして読むJSONに載る。
    /// variantを足すこと自体は末尾追加で後方互換だが、**古いビルドの昇格側はこの綴りを読めない**
    /// （`unknown variant`でデシリアライズが落ちる）。綴りをここで固定しておけば、
    /// 送信側だけ改名して受信側が取り残される事故（B-03）はテストで止まる。
    #[test]
    fn the_combined_access_has_a_stable_wire_spelling() {
        let grant = FsAllowGrant {
            path: PathBuf::from(r"C:\x"),
            access: FsAccess::ReadWriteExec,
            forced: false,
            scope: GrantScope::Recursive,
            secret_hex: "00112233445566778899aabbccddeeff".to_string(),
        };

        let json = serde_json::to_string(&grant).unwrap();

        assert!(json.contains(r#""access":"read_write_exec""#), "{json}");
        let decoded: FsAllowGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.access, FsAccess::ReadWriteExec);
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
                    subjects: vec![FsAllowRevokeSubject {
                        secret_hex: "00112233445566778899aabbccddeeff".to_string(),
                        access: FsAccess::Read,
                    }],
                },
                FsAllowRevoke {
                    path: PathBuf::from(r"C:\Program Files\SomeTool"),
                    forced: true,
                    subjects: Vec::new(),
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
                // [§22.3.1] **秘密が境界を越えて生き残ること**が撤収側の成立条件そのもの
                // （受信側はこれとパスから宛先SIDを導出する。落ちれば1本も剥がれない）。
                assert_eq!(
                    entries[0].subjects[0].secret_hex,
                    "00112233445566778899aabbccddeeff"
                );
                assert_eq!(entries[0].subjects[0].access, FsAccess::Read);
                assert!(entries[1].subjects.is_empty());
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    /// [§22.3.1] **移行前のビルドが送ってくる撤収要求**（`subjects`が無い）を、受信側が
    /// 電文として読めること。
    ///
    /// **付与側と倒す向きが逆である**——あちらは秘密の無い電文を拒否する（宛先SIDを決められない
    /// まま何かへ付与するのを止める）。撤収でそれをやると、剥がせないACEが実マシンに残る。
    /// ここは読めた上で「宣言capabilityは1件も見ていない」として通し、実際に剥がれたかは
    /// **非昇格側が自分の台帳で実DACLを検算する**（`declaration_capabilities_on_root`）。
    #[test]
    fn a_pre_migration_revoke_entry_arrives_without_subjects() {
        let revoke: FsAllowRevoke =
            serde_json::from_str(r#"{"path":"C:\\x","forced":false}"#).unwrap();
        assert!(
            revoke.subjects.is_empty(),
            "a wire form without `subjects` must read as 'no declaration subject supplied', not \
             fail to parse -- refusing here would leave the ACE unremovable"
        );
    }

    /// **秘密は`{:?}`から落ちる**（§22.3.1の実装制約1。伏字化ではなく出力しない）。
    ///
    /// 受信側は要求内容をログへ書くので、`Debug`が素通しだと`privhelper.log`へ平文の秘密が
    /// 残り続ける。**整形の呼び出し側で伏字化する形にしない**——`{:?}`を使う経路が1つ増える
    /// たびに漏れが復活するためで、型の側で落とせば増えた経路も自動的に安全になる。
    #[test]
    fn the_capability_secret_never_appears_in_debug_output() {
        let secret = "00112233445566778899aabbccddeeff";
        let grant = FsAllowGrant {
            path: PathBuf::from(r"C:\x"),
            access: FsAccess::Read,
            forced: false,
            scope: GrantScope::Recursive,
            secret_hex: secret.to_string(),
        };
        let subject = FsAllowRevokeSubject {
            secret_hex: secret.to_string(),
            access: FsAccess::Read,
        };
        let revoke = FsAllowRevoke {
            path: PathBuf::from(r"C:\x"),
            forced: false,
            subjects: vec![subject],
        };

        for rendered in [
            format!("{grant:?}"),
            format!("{revoke:?}"),
            // 要求ごと丸ごと出す形（実際にヘルパーがやりがちな`{req:?}`）も塞がっていること。
            format!(
                "{:?}",
                PrivilegedRequest::RevokeFsAllow {
                    entries: vec![revoke.clone()]
                }
            ),
            format!(
                "{:?}",
                PrivilegedRequest::GrantWorkspaceAccess {
                    traverse_targets: Vec::new(),
                    fs_allow_entries: vec![grant.clone()],
                }
            ),
        ] {
            assert!(
                !rendered.contains(secret),
                "the capability secret leaked into Debug output: {rendered}"
            );
            assert!(
                rendered.contains("<redacted>"),
                "the field must still be visible as present/absent for diagnosis: {rendered}"
            );
        }

        // 「無い」と「伏せた」を区別できること（移行前ビルドの電文を診断するのに要る）。
        let empty = FsAllowRevokeSubject {
            secret_hex: String::new(),
            access: FsAccess::Read,
        };
        assert!(format!("{empty:?}").contains("<none>"));
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
