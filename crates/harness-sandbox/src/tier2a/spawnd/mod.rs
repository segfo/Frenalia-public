//! Spawn Daemon（遷移MAC 段階5）のワイヤ形式と、そこで交わす語彙。
//!
//! # 何のためにあるのか
//!
//! 遷移MACは、サンドボックスの中のプログラムから**子プロセスを起こす能力そのもの**を
//! 取り上げる（`CHILD_PROCESS_RESTRICTED`）。取り上げただけでは何も動かなくなるので、
//! **代わりに起こす人**が要る。それがSpawn Daemonで、本モジュールはそのDaemonと
//! やり取りする電文の形だけを持つ。
//!
//! 設計の正本は`plans/DESIGN-MAC-ENFORCEMENT.md`§10.1・§10.1.1と
//! `plans/DESIGN-MAC-PROTOCOL.md`§12。
//!
//! # パイプが2本ある（§10.1）
//!
//! | パイプ | 誰が繋ぐか | DACL | 運ぶもの |
//! |---|---|---|---|
//! | **制御パイプ** | harnessだけ | ユーザーSID専有 | [`ControlRequest`] |
//! | **要求受付パイプ** | サンドボックスの中のプロセス | ユーザーSID ＋ spawn要求用capability SID | [`SpawnRequest`] |
//!
//! **区別を検証ロジックではなくDACLで引く**のがこの2本の意味である（P-01）。
//! harnessを特権クライアントとして扱えるのは、制御パイプへ到達できるのが
//! harnessだけだからであって、電文の中身を信じているからではない。
//!
//! # ドメインをクライアントに申告させない（§12）
//!
//! [`SpawnRequest`]に**ドメインの欄が無い**のは意図である。要求元のドメインは
//! Daemonが接続元PIDからProcess Table（[`table`]）を引いて決める。
//! 申告させると`{"domain":"trusted"}`と名乗るだけで境界が消える。
//!
//! **[`ControlRequest::SpawnTopLevel`]にはドメインの欄がある**——こちらの送り手は
//! harnessであり、§12が「唯一の信頼された呼び出し元」として自己申告禁止の対象外に
//! している。**この非対称は設計であって漏れではない。**
//!
//! # ハンドルは値だけを載せる
//!
//! 電文に載る`u64`のハンドル値は、**送る前に受け手のプロセスへ`DuplicateHandle`済み**の
//! ものである。値そのものは別プロセスでは意味を持たないので、複製していない値を載せると
//! 「たまたま同じ番号の別オブジェクト」を掴む。複製と送信を1つの関数に閉じ込めるのは
//! そのためで、実装は[`client`]が持つ。

/// Process Table（PIDからドメインと系統Jobを引く台帳）。Win32を直接は呼ばないので
/// 昇格なしで単体テストできる。
pub mod table;

#[cfg(windows)]
pub mod client;
#[cfg(windows)]
pub mod server;
#[cfg(windows)]
pub use client::{SharedSpawnDaemon, SpawnDaemonHandle, SpawnedChild, TopLevelSpawn};

#[cfg(test)]
#[path = "wire_tests.rs"]
mod wire_tests;

use serde::{Deserialize, Serialize};

/// 1往復のI/Oに掛ける上限。**新しい数字を増やさない**——D-88のfault受付
/// （`lazy_grant::broker`）が使っている5秒と同じ値を使う。
pub const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// クライアントの接続を待つ上限。**要求のタイムアウトではない**（居ない相手を待つ時間）。
pub const ACCEPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3600);

/// 1フレームの上限。Daemonは**サンドボックスからの入力を直接パースする最初のフルトラスト
/// 常駐**なので、長さの上限をプロトコルの側で持つ（§10.1「Daemonの入力の扱い」）。
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// 制御パイプのプロトコル版。
///
/// Redirector注入のように、古いDaemonが未知の欄を無視すると隔離の意味が変わる変更では
/// `Hello`と`Ready`の両方で完全一致を要求する。片方だけ新しいバイナリでもspawn前に止まる。
pub const PROTOCOL_VERSION: u32 = 2;

/// 相手が名乗った制御プロトコルの版を判定する。合わなければ理由の文面を返す。
///
/// # なぜ`==`であって`>=`ではないのか
///
/// 版が上がるのは「古い側が未知の欄を無視すると隔離の意味が変わる」ときだけである
/// （例: [`RedirectorSpec`]。古いDaemonが注入欄を無視すると、**注入なしで起動して成功する**
/// ——CoWの透過が丸ごと消えたまま、症状が出ない）。**「新しいほうが上位互換」は成り立たない**
/// ので、範囲ではなく一致で見る。
///
/// # なぜ関数にしてあるのか
///
/// **harnessとDaemonの両方がこれを通る。** 判定を両側で別々に書くと、片側だけ
/// 条件が変わった状態が黙って成立する（`B-05`: コンパイラが守らない複製）。
/// 純粋関数なので、混在の拒否を昇格もパイプも無しで測れる。
pub fn protocol_version_mismatch(peer: u32) -> Option<String> {
    (peer != PROTOCOL_VERSION).then(|| {
        format!(
            "spawn daemon control protocol mismatch: this build speaks {PROTOCOL_VERSION}, \
             the peer reported {peer} (rebuild harness-spawnd.exe together with harness.exe)"
        )
    })
}

/// Daemon経由で起動したトップレベル子へ渡す要求受付パイプ名。
pub const REQUEST_PIPE_ENV: &str = "HARNESS_SPAWN_REQUEST_PIPE";

/// 子のプロセス／スレッド／トークン既定DACLに載せる**ドメインの宛先SID**（§22.1.1）。
///
/// `win_appcontainer::DomainIdentity`をワイヤへ載せた形である。あちらが
/// **`Option`にせず必ず選ばせる**設計なので、こちらも既定値を持たない
/// ——既定があると呼び出し側が黙って落とせてしまい、落ちた経路だけが素のDACLで起動する。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DomainIdentitySpec {
    /// このドメインを識別するcapability SID（例: D-54のworkspace capability）。
    ///
    /// **traverse capabilityを渡してはいけない**——全Tier2a子が共有するので分離にならない。
    Capability { sid: String },
    /// **package SIDそのものがドメイン**である場合（プロファイルが1ドメインに対応する）。
    OwnPackage,
}

/// 起動するプロセスのドメイン（§22.1「ドメイン = (package SID, capabilityの組)」）。
///
/// SIDを**文字列で運ぶ**のは、`PSID`が生ポインタでプロセス境界を越えられないためである。
/// 復元は`win_common::sid_from_string`（`sid_to_string`の対）が行う。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainSpec {
    /// ドメイン名（記録と診断のためだけに使う。判定には使わない）。
    pub name: String,
    /// AppContainerのpackage SID（`S-1-15-2-…`）。
    pub container_sid: String,
    /// トークンへ積むcapability SID（`S-1-15-3-…`）。traverse capabilityを含む。
    pub capability_sids: Vec<String>,
    /// 子のDACLに載せる宛先（上記）。
    pub identity: DomainIdentitySpec,
}

/// Spawn Daemonがsuspended状態の子へ行うRedirector注入。
///
/// 借用を含む[`crate::tier2a::win_appcontainer::RedirectorInject`]はプロセス境界を越せないため、
/// 同じ意味を所有値で運ぶ。`None`は注入しない（MCP stdioとlazy対象外の現行動作）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RedirectorSpec {
    Cow {
        workspace_root: String,
        diff_layer_dir: String,
        ext_capture_roots: Vec<String>,
    },
    Lazy {
        workspace_root: String,
        broker_pipe: String,
    },
}

/// 制御要求が失敗した段階。lazy注入だけを安全に1回再試行するため、文言とは別の値で返す。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpawnFailureKind {
    Spawn,
    RedirectorInjection,
    Protocol,
    Transport,
}

/// 子へ引き継がせるハンドル一式。**すべて受け手（Daemon）のプロセスへ複製済みの値**である。
///
/// 作るのはharnessで、Daemonは受け取った端をそのまま`STARTUPINFO`へ載せる
/// （§10.1「子のstdioパイプを作るプロセス」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildHandles {
    /// 系統Jobの複製（§10.1.1）。Daemonはこれへ子を入れる。
    pub job: u64,
    /// 子のstdin（読み側）。`None`なら子は標準入力を持たない。
    pub stdin_read: Option<u64>,
    /// 子のstdout（書き側）。
    pub stdout_write: u64,
    /// 子のstderr（書き側）。
    pub stderr_write: u64,
}

/// harness → Daemon（制御パイプ）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ControlRequest {
    /// 接続直後に1回だけ送る。**harness自身のプロセスハンドルの複製**を渡す。
    ///
    /// Daemonが起こした子のプロセスハンドルをharnessへ返す（[`ControlResponse::Spawned`]）ためには、
    /// 複製先としてharnessのプロセスハンドルが要る。**Daemonに`OpenProcess`させない**
    /// ——harnessが自分で`PROCESS_DUP_HANDLE`だけに絞った複製を渡すほうが、
    /// Daemonへ与える能力が小さい（P-01: 必要最小限）。
    Hello {
        /// `PROCESS_DUP_HANDLE`のみへ絞ったharnessプロセスハンドルの複製。
        harness_process: u64,
        /// [`PROTOCOL_VERSION`]と完全一致しなければ、1件もspawnせず接続を閉じる。
        protocol_version: u32,
    },
    /// トップレベルのプロセスを起こす（§12「harnessもSpawn Daemon経由でspawnを依頼する」）。
    ///
    /// **中身を`Box`に入れてあるのは、この変種だけが他より桁違いに大きいためである**
    /// （`clippy::large_enum_variant`）。ワイヤ上の形は変わらない——serdeの
    /// internally-taggedは、構造体を包んだnewtype変種をタグ＋その構造体のフィールドとして
    /// 平らに書く（`wire_tests`がバイト列で固定している）。
    SpawnTopLevel(Box<SpawnTopLevelRequest>),
    /// 畳んで終了する。**送らなくてもよい**——制御パイプが閉じれば同じ経路を通る。
    Shutdown,
}

/// [`ControlRequest::SpawnTopLevel`]の中身。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnTopLevelRequest {
    pub exe: String,
    pub args: Vec<String>,
    pub cwd: String,
    pub env: Vec<(String, String)>,
    pub domain: DomainSpec,
    pub handles: ChildHandles,
    /// suspended窓で行うRedirector注入。`None`なら現行の無注入経路。
    pub redirector: Option<RedirectorSpec>,
}

// **トークンの既定DACL（§22.1.1）の欄は置かない**（2026-09-07に削除）。
//
// かつてここに`token_default_dacl_sddl: Option<String>`が在り、docは「`None`なら
// 差し替えない」と書いていた。**その記述は誤りだった**——Daemonはこの欄を一度も読まず、
// `create_suspended_in_job`が`domain`から自分でSDDLを組んで**常に**差し替えている。
// 製品の唯一の書き手も`None`を入れるだけだった。
//
// **差し替えを電文で切れるように見せるほうが危ない。** 既定DACLの差し替えは
// 「起動後に生えたスレッドが素のまま残る」穴（§S2b）を塞ぐ2つで1組の対策の片方であり、
// 呼び出し側が落とせる設定ではない。**落とせる形の欄を置くと、いつか落とされる。**

/// Daemon → harness（制御パイプ）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ControlResponse {
    /// [`ControlRequest::Hello`]を受け取った。
    Ready {
        /// 要求受付パイプの名前。harnessはこれを子の環境変数などで伝える。
        request_pipe: String,
        /// Daemon自身のPID。**観測側の配線に要る**（残課題#42: ETWのスコープ判定が
        /// 「親がharnessか」を手掛かりにしており、Daemonが親になると意味が変わる）。
        daemon_pid: u32,
        protocol_version: u32,
    },
    /// 起こした。`process`は**harnessのプロセスへ複製済み**のハンドル値。
    Spawned { pid: u32, process: u64 },
    /// 起こせなかった。`reason`はどのWin32呼び出しで落ちたかを含む。
    Failed {
        failure_kind: SpawnFailureKind,
        reason: String,
    },
    /// 畳んだ。この応答の後、Daemonは終了する。
    ShuttingDown,
}

/// サンドボックスの中のプロセス → Daemon（要求受付パイプ）。
///
/// **ドメインの欄が無いのは意図である**（モジュールdoc）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpawnRequest {
    /// この実行ファイルを、この引数で起こしたい。
    Spawn {
        exe: String,
        args: Vec<String>,
        cwd: String,
    },
}

/// Daemon → サンドボックスの中のプロセス（要求受付パイプ）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpawnResponse {
    /// 拒否した。**理由を分ける**のは、拒否した側と拒否の根拠が別の事実だからである
    /// （§10.2が`denied_by_daemon`と`denied_by_kernel`を分けたのと同じ理屈）。
    Denied { reason: DenyReason },
}

/// 拒否の理由。**「拒否された」だけでは、台帳の判定が効いているのかポリシーが
/// 効いているのか区別できない。**
///
/// 段階5の受け入れテストは、まさにこの2つが**別の値になること**を確かめる
/// ——同じ値にすると「常に拒否する」実装でも合格してしまう（`B-35`: 禁止側だけを測らない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// 接続元PIDがProcess Tableに無い（§12の既定拒否）。
    ///
    /// **「初期ドメイン」等の緩い既定へ倒さない。** Daemonが落ちて立ち上がり直した場合も
    /// ここへ落ちる——Process Tableは再構築できないので、それが正しい（§10.1）。
    NotRegistered,
    /// 接続元PIDは台帳に在るが、保持しているプロセスハンドルが終了済みだった
    /// ＝**PIDの再利用**（§12「PID再利用への対処」）。
    PidReused,
    /// 台帳には在るが、遷移ポリシーがまだ実装されていない。
    ///
    /// **段階Eでポリシー評価が入るまでの既定である。** fail-closedの側へ倒してあるので、
    /// この状態のまま`CHILD_PROCESS_RESTRICTED`を積むとサンドボックスの中で
    /// 子プロセスが1つも作れなくなる——だから⑤は段階Eの後に来る。
    PolicyNotImplemented,
    /// 電文が壊れている・長すぎる・接続元がAppContainerの外だった。
    MalformedRequest,
}

impl DenyReason {
    /// 診断用の短い説明。**ユーザーへ出す文面ではない**（画面の文言は呼び出し側が持つ）。
    pub fn as_str(self) -> &'static str {
        match self {
            DenyReason::NotRegistered => "caller pid is not in the process table",
            DenyReason::PidReused => "caller pid was reused by another process",
            DenyReason::PolicyNotImplemented => "transition policy is not implemented yet",
            DenyReason::MalformedRequest => "malformed request",
        }
    }
}
