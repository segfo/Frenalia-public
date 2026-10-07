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

/// [段階6c] 拒否の待ち行列（`<workspace>/.harness/transitions/`、§10.2）。
/// [`table`]と同じくWin32を直接は呼ばないので、昇格なしで単体テストできる。
pub mod transitions;

/// Daemonが起こす子1人ぶんの持ち物（トークンへ積むcapability・注入するRedirectorの設定）を
/// 1か所で決める。トップレベルと入れ子の両方がここを通る。
#[cfg(windows)]
mod child_plan;
#[cfg(windows)]
pub mod client;
/// [段階⑤] コンソール保持プロセス（§7.1.1・§7.1.2）。Win32のコンソールAPIを直接叩くので
/// windows専用。**Daemon側だけが使う**——harness本体はコンソールを借りない。
#[cfg(windows)]
pub mod console_holder;
/// Strict の辺の起こす直前に、固定したファイルを呼び出し元が書き換えられないかを
/// 呼び出し元のトークンでOSに聞く（`plans/DESIGN-MAC.md` §19.1）。
#[cfg(windows)]
pub(crate) mod fixed_inputs;
/// 入れ子の子へ渡す入力（環境変数・要求受付パイプの名前）を組む関数。`server`から移した（P5.1）。
#[cfg(windows)]
mod nested_inputs;
/// 子プロセスを作れるかの姿勢（[`ChildProcessPolicy`]）と、このプロセスが選んだ姿勢の宣言・読み口。
/// `mod.rs`の本体が上限に達したのでそのまま移した（P6.4 の準備）。Win32を呼ばないのでwindows専用にしない。
mod child_process_policy;
pub use child_process_policy::{
    child_process_policy_for_this_process, declare_child_process_policy, ChildProcessPolicy,
};
#[cfg(windows)]
pub mod server;
/// [決定68] Daemon が許可して起こした生成の記録（`spawn-audit.jsonl`）の書き手。
#[cfg(windows)]
mod spawn_audit;
#[cfg(windows)]
pub use client::{SharedSpawnDaemon, SpawnDaemonHandle, SpawnedChild, TopLevelSpawn};

#[cfg(test)]
#[path = "wire_tests.rs"]
mod wire_tests;

/// **要求受付パイプへ毎秒何本の要求が来るのか**を、現実の並列ビルドから見積もる測定
/// （`docs/STATUS.md`残課題#43）。**昇格は要らない**ので`KNOWN_TARGETS`には入れない。
#[cfg(all(windows, test))]
#[path = "spawn_rate_tests.rs"]
mod spawn_rate_tests;

use serde::{Deserialize, Serialize};

/// 1往復のI/Oに掛ける上限。**新しい数字を増やさない**——D-88のfault受付
/// （`lazy_grant::broker`）が使っている5秒と同じ値を使う。
pub const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// クライアントの接続を待つ上限。**要求のタイムアウトではない**（居ない相手を待つ時間）。
pub const ACCEPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3600);

/// 1フレームの上限。Daemonは**サンドボックスからの入力を直接パースする最初のフルトラスト
/// 常駐**なので、長さの上限をプロトコルの側で持つ（§10.1「Daemonの入力の扱い」）。
///
/// # なぜ64 KiBでは足りなくなったのか（2026-09-17、段階6f-1）
///
/// [`SpawnRequest::Spawn`]が**呼び出し元の環境変数一式**を運ぶようになった。Windowsの
/// 環境ブロックは数十KiBに達することがあり、JSONのエスケープでさらに膨らむ。
/// **足りないと`MalformedRequest`になる**——呼び出し元から見ると「環境変数が多いときだけ
/// 生成が拒否される」という、理由の想像できない形で出る。
///
/// **上限そのものは外さない。** 外すと、サンドボックスが1フレームでDaemonのメモリを
/// 好きなだけ確保させられる。
pub const MAX_FRAME_BYTES: usize = 256 * 1024;

/// 制御パイプのプロトコル版。
///
/// Redirector注入のように、古いDaemonが未知の欄を無視すると隔離の意味が変わる変更では
/// `Hello`と`Ready`の両方で完全一致を要求する。片方だけ新しいバイナリでもspawn前に止まる。
///
/// **3へ上げたのは段階⑤である。** 生成禁止（[`ChildProcessPolicy`]）はこの電文ではなく
/// `harness-spawnd.exe`の起動引数で決まるので、**古いDaemonのバイナリは第2引数を読まず、
/// 生成禁止を積まないまま正常に起動してしまう**——harness側は積んだつもりでいるのに、
/// 強制だけが黙って消える。これがこの定数のdocが言う「隔離の意味が変わる」の形そのものである。
/// あわせて[`ConsoleNeed`]も足しており、古いDaemonはこれを無視して`CREATE_NO_WINDOW`で
/// 起こすため、生成禁止と対になった日にシェルが`0xC0000142`で起動できなくなる。
///
/// **4へ上げたのは段階6bである。** [`ControlRequest::Hello`]が遷移ポリシーの宣言そのものを
/// 運ぶようになった（`plans/DESIGN-MAC-PROTOCOL.md` §12.1）。古いDaemonのバイナリは
/// この欄を読まないので、**harness側は宣言を渡したつもりでいるのに、Daemonは
/// 「グラフが空のまま」で立ち上がる**——結果、あらゆる生成要求が「宣言が無い」として
/// 拒否される。強制が消えるのではなく**全部拒否になる**向きだが、
/// どちらにせよ「渡したつもり」と実際が食い違う点はこの定数のdocが言うとおりである。
/// **5へ上げたのは段階6f-3である。** [`ControlRequest::FlushTransitionQueue`]を足した。
/// ここだけは理由の形が他と違う——古いDaemonはこの要求を**無視するのではなく解析に失敗する**
/// ので、Helloを通り抜けたあと**セッションの途中で制御ループごと畳んでしまう**
/// （`read_control`が`Err`を返した時点でループを抜ける設計である）。
/// 版を上げないと、その死に方は「なぜかDaemonが消えた」という遠い症状で出る。
/// **`harness-spawnd.exe`はテストのビルドで作り直されない**ので、古い個体は実在する。
/// **6へ上げたのは#55の骨格である。** [`ControlRequest::Hello`]が**遷移先ドメインの実体**
/// （package SIDとcapabilityの組）の表を運ぶようになった。古いDaemonのバイナリは
/// この欄を読まないので、**harness側は用意したつもりでいるのに、Daemonは別ドメインへの
/// 遷移を全部断る**——倒れる向きは安全側（拒否）だが、「渡したつもり」と実際が食い違う点は
/// 段階6bで版を上げたときと同じである。
/// **7へ上げたのはBUG-180である。** [`RedirectorSpec::Cow`]が**差分層の宛先SID**
/// （`diff_layer_capability_sid`）を運ぶようになった。古いDaemonのバイナリはこの欄を読まずに
/// 注入だけ行うので、**別ドメインへ移った子が差分層を読めないまま起動して成功する**
/// ——そのとき子は変更前の中身を黙って読む（BUG-180の症状そのもの）。
/// 倒れる向きが「拒否」ではなく「嘘の見え方」なので、版の一致で止める。
/// **8へ上げたのは残課題 サンドボックス周辺 #65である。** [`ControlRequest::Hello`]が
/// **`policy.json`の外で書込を許した場所**（`writable_outside_policy`）を運ぶようになった。
/// 古いDaemonのバイナリはこの欄を読まないので、**Daemonの遷移の検査だけがその場所を
/// 「書けない」と見る**——固定した遷移の先を呼び出し元が書き換えられても通してしまう向きで、
/// 検査が黙って緩くなるので版の一致で止める。
/// **9へ上げたのは P5.4b（決定66(3)(4)）である。** `Hello`が運ぶ`policy.json`の辺に**子の出力の設定**
/// （`"output": "discard"`）が載るようになり、Daemonが子へ渡す標準入出力の決め方も変わった。古いDaemonは
/// 欄を捨てて**捨てたつもりの出力を返し**、普通の辺の標準入力も断ったままになる——黙って意味が変わるので止める。
/// **10へ上げたのは P5.4c（決定66(5)と追記）である。** ここだけは**電文の形が1バイトも変わっていない**——
/// 変わったのは Daemon が同じ`policy.json`から組む環境変数の意味で、Strict の辺が
/// 「harness の基準の値＋辺の差分」になった。版9の古い Daemon は同じ宣言を読んで**呼び出し元の環境変数を
/// Strict の子へ渡す**ので、固定した操作の中身を呼び出し元が環境変数で選べる（黙って緩くなる向き）。
/// **`harness-spawnd.exe`はテストのビルドで作り直されない**ので、版9の個体は実在し得る。
/// **11へ上げたのは P5.4d である**（電文の形は不変）。Strict の辺の作業ディレクトリも起こす直前に検査するようになり、版10の Daemon は黙って通す。
/// **12へ上げたのは P6.4（決定68）である。** `Hello`に記録の名前（`spawn_audit_record`）が載った。版11の Daemon は欄を捨て、許可した生成の記録を黙って書かない。
pub const PROTOCOL_VERSION: u32 = 12;

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
    /// AppContainerプロファイルの名前（`run_shell`経路）またはMCPサーバの宣言id。
    ///
    /// **記録と診断のためだけに使う。遷移の判定には使わない**——判定に使うのは
    /// [`DomainSpec::policy_domain`]である。この2つは値が違う: この欄に入るプロファイル名は
    /// **セッションごとに変わる**ので、`policy.json`に書ける綴りではない。
    pub name: String,
    /// **遷移の判定における「呼び出し元ドメイン」の名前**（`policy.json`の`domains[].name`）。
    ///
    /// # なぜ[`DomainSpec::name`]と別に持つのか（2026-09-12、段階6b）
    ///
    /// 判定器は呼び出し元がグラフのどのノードに居るかを名前で引く
    /// （`harness_policy::transition::SpawnAttempt::from_domain`）。ところが`name`に実際に
    /// 入っているのは**AppContainerプロファイル名**（セッションごとに変わる）と
    /// **MCPの宣言id**であり、前者は`policy.json`へ書けない。**同じ欄に2つの意味を
    /// 持たせると、片方の経路だけが宣言と一致しなくなる**ので、欄を分ける。
    ///
    /// # 誰が何を入れるか
    ///
    /// 由来は経路ごとに違う（`plans/DESIGN-MAC-PROTOCOL.md` §12.1の表）。
    /// `run_shell`とポリシーエディタのパス2は入口の固定名（`harness_policy::policy_file::ENTRY_DOMAIN`。
    /// パス2は決定68から常に入口で始める）、MCPは宣言idである。
    ///
    /// **`Option`にしない。** 既定を持たせると、4つ目の経路を足す人が選ばずに通れてしまい、
    /// **その経路だけが黙って別ドメイン扱いになる**（`DomainIdentitySpec`と同じ姿勢）。
    pub policy_domain: String,
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
        /// [BUG-180] **この差分層へ届くためのcapability SID**（`S-1-15-3-…`の文字列）。
        ///
        /// # なぜ注入設定と一緒に運ぶのか
        ///
        /// Redirectorは子の中で動くので、差分層へ書けるかどうかは**子のトークン**で決まる。
        /// 差分層のACEは差分層ごとのcapability SID宛にしか付いていない（§22.3.2）ので、
        /// **この設定で注入する子には、必ずこのSIDを積まなければならない**。積まないと、
        /// 書込は拒否されるうえ、読取は変更前の中身を黙って返す（BUG-180）。
        ///
        /// 積むのはDaemonの`spawnd::child_plan`で、トップレベルでも入れ子でも同じ規則を通る。
        ///
        /// # なぜDaemonが自分で引かないのか
        ///
        /// 宛先SIDは台帳（`workspace-capability-ledger.json`）にある秘密から導出される。
        /// Daemonが台帳を読むと、入力の出どころが電文と台帳の2つに割れる
        /// （[`ControlRequest::Hello`]の`policy`の欄が同じ理由でDaemonにファイルを読ませていない）。
        ///
        /// # なぜ起動時の表（`Hello`）に入れないのか
        ///
        /// 差分層は`/sessions`・`/fork`で作り直され、宛先SIDも変わる。起動時に1回だけ
        /// 渡すと古い差分層のSIDを持ち続けるので、**トップレベルを起こすたびに**運ぶ。
        ///
        /// **`serde(default)`を付けない。** 欄の無い電文を黙って受け付けると、
        /// 「積むべきSIDが空」の設定で注入することになる。
        diff_layer_capability_sid: String,
    },
    Lazy {
        workspace_root: String,
        broker_pipe: String,
    },
    /// [段階5b（`plans/DESIGN-MAC-ENFORCEMENT.md` §8.1）] **誘導するものも受け付けるものも
    /// 無いが、プロセス生成フックを置くために注入する。**
    ///
    /// 段階⑤で`CHILD_PROCESS_RESTRICTED`（OSが子プロセス生成そのものを拒否する緩和策）を
    /// 積むと、サンドボックスの中のプログラムは自力で子を作れなくなりSpawn Daemonへ頼む形に
    /// なる。**その頼み方へ変換するのがこのフック**なので、フックの入っていないプロセスが
    /// 1つでも居る状態で⑤は積めない。
    ///
    /// `workspace_root`が`None`のことがある——MCPサーバにはワークスペースが無い。
    /// DLLはそのときファイル系フックを1本も置かない（`harness-redirector`の`Config`のdoc）。
    ProcessHooks { workspace_root: Option<String> },
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

/// [段階6b] Daemonを起こすときに渡す遷移ポリシー一式。
///
/// # なぜまとめて1つの型で受けるのか
///
/// 判定できるグラフを組むには**宣言・ワークスペースルート・`policy.json`の外で書込を許した場所**
/// が揃って要る（後の2つは「固定値が呼び出し元から書ける場所にあるか」の検査に使う。
/// `harness_policy::transition::GraphInput::caller_writable_roots`のdoc）。
/// 別々の引数にすると、一部だけ渡して**検査の一部が黙って効かない**構成が作れてしまう。
///
/// # 誰が作るか
///
/// 製品のホスト2つ（`harness.exe`とポリシーエディタ）が
/// `harness_policy::policy_file::load`の結果から作る。**読めなければDaemonを起こさない**
/// ——直接生成へ降格しないのと同じ扱いである（`plans/DESIGN-MAC-PROTOCOL.md` §12.1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionPolicy {
    pub policy: harness_policy::policy_file::PolicyFile,
    pub workspace_root: String,
    /// [残課題 サンドボックス周辺 #65] **`policy.json`の外で書込を許した場所**
    /// （`settings.json`の`fs.read_write`・`--fs-allow <path>:rw`）。
    ///
    /// harness側が`policy_file::load_for_session`へ渡したのと**同じ一覧**を入れる——
    /// 2つのプロセスの検査が別の入力を見ると、Daemonだけが緩い判定でグラフを組む。
    /// ポリシーエディタは宣言の外で書込を許す経路を持たないので空である。
    pub writable_outside_policy: Vec<String>,
    /// [#55] このセッションで**用意できた**遷移先ドメインの実体
    /// （`ControlRequest::Hello::domains`のdocが意味を持つ）。
    ///
    /// **宣言と一緒に運ぶ。** 別々に渡すと、宣言だけ届いて表が届かない瞬間ができ、
    /// その窓の間に来た遷移だけが「用意されていない」として断られる。
    pub domains: Vec<DomainSpec>,
    /// [決定68] 許可した生成の記録を書く**記録のディレクトリの名前**（パスの1要素）。`None`なら書かない
    /// （`harness.exe`。量の上限と回転を決めていないので暫定。`ControlRequest::Hello::spawn_audit_record`のdoc）。
    pub spawn_audit_record: Option<String>,
}

impl TransitionPolicy {
    /// 宣言が1件も無い状態。**製品コードで使わない**——ワークスペースの宣言を読まずに
    /// Daemonを起こすと、宣言してある遷移まで拒否される。テストと、
    /// ワークスペースを持たない呼び出し（`policy.json`が存在しないケースは
    /// `load`が空を返すので、こちらではない）のための出発点である。
    pub fn empty(workspace_root: impl Into<String>) -> Self {
        Self {
            policy: harness_policy::policy_file::PolicyFile::default(),
            workspace_root: workspace_root.into(),
            // 宣言が無ければ固定した遷移も無いので、検査に渡す書込場所も要らない。
            writable_outside_policy: Vec::new(),
            // 宣言が無ければ遷移先も無い。**空は「用意できなかった」と同じ扱い**で、
            // Daemonは別ドメインへの遷移を断る（fail-closed）。
            domains: Vec::new(),
            // 記録を頼まない（テストと、記録の無い呼び出しの出発点）。
            spawn_audit_record: None,
        }
    }
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
        /// [段階6b] 遷移ポリシーの宣言（`policy.json`の中身そのもの）。
        ///
        /// # なぜ`Hello`に載っているのか（`plans/DESIGN-MAC-PROTOCOL.md` §12.1）
        ///
        /// `server::serve`は`Hello`を読み終えてから要求受付パイプの受付スレッドを起こす。
        /// ここに載せることで、**宣言を持たないDaemonが要求を受け付ける瞬間が原理的に
        /// 存在しなくなる**。別の制御要求にすると、その窓の間に来た要求だけが
        /// 「宣言が無い」として拒否される。
        ///
        /// # なぜDaemonが自分で`policy.json`を読まないのか
        ///
        /// 遷移先ドメインの実体（package SIDとcapability SIDの組）は`policy.json`に
        /// 書かれておらず、`preflight`が実行時に発行する。**どちらにせよharnessから
        /// 渡すものがある**ので、Daemonがファイルを開いても入力源が2つに割れるだけである。
        /// 加えて、親が指定したパスをDaemonに開かせる経路を新設することになる
        /// （`is_harness_pipe_name`が同じ理由で避けている形）。
        ///
        /// # 縮小版の型を作っていない理由
        ///
        /// 同じ宣言の表現を2つ持つと片方だけ古くなる（`B-13`）。判定へ使うのは`process`だけだが、
        /// **読み口（`policy_file::load`）が返す型をそのまま運ぶ**。
        policy: Box<harness_policy::policy_file::PolicyFile>,
        /// [段階6b] ワークスペースルート。**編集時検査の入力である**——
        /// 「固定値が指すファイルが呼び出し元から書けない場所にあること」を確かめるのに、
        /// 宣言だけを見るとワークスペースが抜ける（`GraphInput::caller_writable_roots`のdoc）。
        workspace_root: String,
        /// [#55] **このセッションで用意できた遷移先ドメインの実体**
        /// （`plans/DESIGN-MAC-BROKER.md` §22.9）。
        ///
        /// # なぜ宣言と一緒に運ぶのか
        ///
        /// 宣言（上の`policy`）は「Dへ移してよい」までしか言わない。**Dで実際に起こすには
        /// Dのpackage SIDとcapabilityの組が要る**が、それは`policy.json`に書かれておらず、
        /// harnessが起動時に用意する（この変種のdocの「Daemonが自分で読まない理由」）。
        /// 宣言と同じ電文に載せることで、**表を持たないDaemonが要求を捌く瞬間が
        /// 原理的に存在しなくなる**。
        ///
        /// # 空であることは「用意できなかった」を意味する
        ///
        /// 用意できないドメイン（宣言が許可済みでない・通信を宣言している）は**載らない**。
        /// Daemonはそれを「そのドメインへは起こせない」として断る——
        /// **載っていないものを既定で通さない**（`P-11`: 観測していないものを既定値で埋めない）。
        ///
        /// 並びは`policy_domain`で引ける形にしてある。**同じ名前が2つ載ることは無い**
        /// （用意する側が1ドメイン1件で作る）。
        #[serde(default)]
        domains: Vec<DomainSpec>,
        /// [残課題 サンドボックス周辺 #65] **`policy.json`の外で書込を許した場所**
        /// （[`TransitionPolicy::writable_outside_policy`]）。`workspace_root`と同じく
        /// **編集時検査の入力である**——宣言には現れないが、呼び出し元はそこへ書ける。
        ///
        /// **`serde(default)`を付けない。** `domains`と違い、この欄が空であることは
        /// 「検査が緩くなる」向きに倒れる（書ける場所を書けないと見る）。欄の無い電文を
        /// 黙って空として受け付けると、その緩さが症状を出さずに成立する
        /// （[`RedirectorSpec::Cow`]の`diff_layer_capability_sid`と同じ姿勢）。
        writable_outside_policy: Vec<String>,
        /// [決定68] 許可した生成の記録を書く**記録のディレクトリの名前**（`.harness/sandbox/`の下の1要素）。
        ///
        /// **パスではなく名前を運ぶ。** Daemon が`workspace_root`から置き場を組み立て、区切りや`.`で始まる名前を断り、
        /// 在るファイルにしか追記しない（`spawnd::spawn_audit`。拒否の待ち行列が`workspace_root`から導くのと同じ作法、§10.2）。
        /// `None`は「書かない」（`harness.exe`。暫定——決定68の前例の(4)）。**追加は必ず末尾へ**（`wire_tests`）。
        spawn_audit_record: Option<String>,
    },
    /// トップレベルのプロセスを起こす（§12「harnessもSpawn Daemon経由でspawnを依頼する」）。
    ///
    /// **中身を`Box`に入れてあるのは、この変種だけが他より桁違いに大きいためである**
    /// （`clippy::large_enum_variant`）。ワイヤ上の形は変わらない——serdeの
    /// internally-taggedは、構造体を包んだnewtype変種をタグ＋その構造体のフィールドとして
    /// 平らに書く（`wire_tests`がバイト列で固定している）。
    SpawnTopLevel(Box<SpawnTopLevelRequest>),
    /// [段階6f-3] 拒否の待ち行列を**いま書き出させる**
    /// （`plans/DESIGN-MAC-TRANSITION-POLICY.md` §19.3.8）。
    ///
    /// # なぜ要るのか
    ///
    /// 待ち行列は**畳んで書く**——1件目は即時、以後は前回書いた数の**2倍**に達したときだけ
    /// 追記する（[`crate::tier2a::transitions_log`]のモジュールdoc）。量を回数の対数へ
    /// 抑えるための設計だが、そのぶん**ファイルのカウントは実際より遅れる**
    /// （3件目・5件目では1行も増えない）。
    ///
    /// `run_shell`は「このコマンドの間に何件断られたか」を注記へ出すので、
    /// **読む直前にこれを送って鮮度を作る**。読み取り用の問い合わせを足さないのは、
    /// **正本を2つ持たない**ためである（`B-13`）——ファイルが正本のままなら、
    /// 将来カーネル拒否の購読者が現れても同じ経路に乗る。
    ///
    /// # これは読み取りではない
    ///
    /// Daemonは**自分が覚えている分を自分のファイルへ書く**だけで、中身を返さない。
    /// 呼び出し元へ渡すのは追記した行数だけである（[`ControlResponse::Flushed`]）。
    FlushTransitionQueue,
    /// 畳んで終了する。**送らなくてもよい**——制御パイプが閉じれば同じ経路を通る。
    Shutdown,
}

/// 起こす子プログラムがコンソールを必要とするか（設計書§7.1の実測表）。
///
/// # なぜ呼び出し側に選ばせるのか
///
/// [`ChildProcessPolicy::Restricted`]を積むと、**コンソールの与え方で結果が3通りに割れる**
/// （`plans/mac-spike/RESULTS.md`§S1・§S1b）。コンソールの割り当ては`conhost.exe`という
/// **子プロセスの生成**を伴うので、生成を禁じられたプロセスは自分ではコンソールを作れない。
///
/// | コンソールの与え方 | `Restricted`下の挙動 |
/// |---|---|
/// | `CREATE_NO_WINDOW`（今日の既定） | **起動できない**（`0xC0000142`） |
/// | `DETACHED_PROCESS` | node・git・`cmd.exe`は動く。**PowerShellは何も実行せずexit 0**（無言失敗） |
/// | フラグ無し（呼び出し側のコンソールを継承） | **動く**。シェルもコマンドを実行し終了コードも伝わる |
///
/// つまり**シェルだけがコンソールを要求する**（PowerShell自身の性質であって、
/// AppContainer固有ではない——素のユーザーで起こしても同じになる）。
/// 取り違えると`Required`側は起動失敗、`NotNeeded`側は**exit 0の無言失敗**になるので、
/// `DomainIdentity`と同じく**既定値を持たせず、経路ごとに必ず選ばせる**。
///
/// # `Unrestricted`のときは何も変わらない
///
/// 生成禁止を積んでいない構成では、どちらを選んでも`CREATE_NO_WINDOW`のままである
/// （今日の挙動を1ビットも変えないため）。**この欄が効き始めるのは`Restricted`と
/// 対になったときだけ**で、それでも`Option`にしないのは、積んだ日に
/// 「全経路が既定値を掴んでいた」を作らないためである。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsoleNeed {
    /// コンソールが要る（pwsh・powershell）。`Restricted`のとき、Daemonは
    /// **`CreateProcessW`の前にコンソール保持プロセスへ`AttachConsole`する義務がある**
    /// ——生成側はコンソールのフラグを1つも積まないので、そのとき繋がっているコンソールが
    /// そのまま子へ渡る。繋がっていなければ子はコンソール無しで起き、**無言でexit 0**する。
    Required,
    /// 要らない（node・git・rustc・MCPサーバ等）。`Restricted`のとき`DETACHED_PROCESS`で起こす。
    NotNeeded,
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
    /// [段階⑤] 起こすプログラムがコンソールを要るか。
    ///
    /// **これは「切れる設定」ではなく「どんなプログラムか」の申告である。** Daemonは
    /// 実行ファイル名から推測しない——推測は当たらない側へ倒れたとき無言だからである
    /// （`ConsoleNeed::Required`を`NotNeeded`と取り違えると、シェルは何も実行せずexit 0する）。
    ///
    /// 生成禁止を積んでいない構成では**この欄は結果に効かない**（どちらでも
    /// `CREATE_NO_WINDOW`のまま）。それでも`Option`にしないのは、
    /// 積んだ日に「全経路が既定値を掴んでいた」を作らないためである。
    pub console: ConsoleNeed,
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
    /// [段階6f-3] 待ち行列を書き出した。`lines`は**この呼び出しで追記した行数**。
    ///
    /// **0は失敗ではない**——「書くべき差分が無かった」という観測である
    /// （`P-11`: 観測していないことと0件は別だが、ここは**数えたうえでの0**である）。
    Flushed { lines: usize },
    /// 畳んだ。この応答の後、Daemonは終了する。
    ShuttingDown,
}

/// [段階6f-1] 呼び出し元が子へ引き継がせたいハンドル。
///
/// # [`ChildHandles`]と**向きが逆**である
///
/// あちらは「送る前に受け手（Daemon）のプロセスへ複製済み」の値だが、こちらは
/// **呼び出し元のプロセスの中でしか意味を持たない生の値**である。サンドボックスの中の
/// プロセスはDaemonのプロセスハンドルを開けないので、自分で複製して渡すことができない
/// ——だから**Daemonが引き抜く**（`DuplicateHandle`の第1引数に呼び出し元を置く）。
///
/// **型を分けてあるのはこの向きの違いのためである。** 同じ`u64`で意味が逆なので、
/// 混ぜると「たまたま同じ番号の別オブジェクト」を掴む（モジュールdocの「ハンドルは値だけを載せる」）。
///
/// # 嘘を書かれても、呼び出し元の権限は増えない
///
/// 引き抜けるのは**呼び出し元が既に持っているハンドル**だけである。別の番号を書いても、
/// 自分が持っていない物は指せない。
///
/// # ただし**渡してよい辺かどうかは別の話**である（BUG-161、2026-09-20）
///
/// 増えないのは**呼び出し元の**権限で、**子の**側は増える——遷移先の子へ呼び出し元が自分の持ち物を手渡せる。
/// 判定器が辺ごとに答える（P5.4b）: 標準入力は Strict の辺で断ち（`Allowed::strict`。固定argvのシェルは
/// stdinからコマンドを読む）、標準出力・標準エラーは辺の出力の設定（`Allowed::output`）に従う。
///
/// **この欄を読むのは`server::serve_spawn_request`ただ1箇所である。** 渡さないと決めたものは、ここに何が
/// 載っていても`nested_inputs::caller_handles_for`で`None`に差し替えてから`spawn_nested`へ渡す。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CallerHandles {
    /// 子の標準入力にしたいハンドル（**呼び出し元の中の値**）。`None`なら標準入力を持たない。
    #[serde(default)]
    pub stdin: Option<u64>,
    /// 子の標準出力。`None`なら`NUL`へ捨てる（段階6bまでの唯一の挙動）。
    #[serde(default)]
    pub stdout: Option<u64>,
    /// 子の標準エラー。`None`なら`NUL`へ捨てる。
    #[serde(default)]
    pub stderr: Option<u64>,
}

/// サンドボックスの中のプロセス → Daemon（要求受付パイプ）。
///
/// **ドメインの欄が無いのは意図である**（モジュールdoc）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpawnRequest {
    /// この実行ファイルを、このコマンドラインで起こしたい。
    Spawn {
        /// 起こす実行ファイルの**絶対パス**（`CreateProcessW`の`lpApplicationName`）。
        ///
        /// # なぜ絶対でなければならないのか（2026-09-17、段階6f-1）
        ///
        /// `lpApplicationName`の相対パスは**呼び出し側プロセスのcwd基準**で解決される。
        /// 起こすのはDaemonなので、相対パスを通すと**Daemonのcwdから見た別の実行ファイル**が
        /// 起きる。`lpCurrentDirectory`（＝`cwd`欄）は`lpApplicationName`の解決には使われない。
        /// 絶対でない値は[`DenyReason::MalformedRequest`]で断る。
        ///
        /// # なぜ`lpCommandLine`任せにしないのか
        ///
        /// 判定に使う実行ファイルと、実際に起きる実行ファイルを**同一の値**にするためである
        /// （§8.2をコマンドラインから実行ファイルへ広げたもの）。コマンドラインの先頭から
        /// 実行ファイルを決める規則は、引用符の無い空白入りパスで**複数の候補を順に試す**
        /// ——こちらの解釈とOSの解釈がずれると、**判定したのと別のファイルが起きる**。
        image: String,
        /// `CreateProcessW`の`lpCommandLine`へ**逐語で**渡す文字列。
        ///
        /// **`exe`＋`args`から組み直さない**（段階6bまではそうしていた）。組み直すと
        /// 引用符の付け方が変わり、`cmd /c "a & b"`のように自分でコマンドラインを解釈する
        /// プログラムの意味が変わる。§8.2の「評価した値と起動に使う値を同一にする」は、
        /// **逐語で運ぶほうが直接に満たされる**。
        command_line: String,
        cwd: String,
        /// [段階6f-1] 呼び出し元が子へ渡したい環境変数一式。
        ///
        /// **そのまま使うわけではない。** harnessが所有する名前（窓口のパイプ名・Redirectorの
        /// 設定）は、系統の基準envの値で**必ず上書きされる**（`server::env_for_nested`）。
        /// 上書きしないと`PATH`や窓口名を差し替えられる、というのが§10.1.2が
        /// 「envの欄を置いてもいけない」と書いた理由だった——**その名前だけを塞げば足りる**と
        /// 判断を改めたのが段階6f-1である。
        ///
        /// # `None`と`Some(空)`は別の意味である（`P-11`）
        ///
        /// | 値 | 意味 | 子が受け取る環境 |
        /// |---|---|---|
        /// | `None`（欄が無い） | **申告していない** | 系統の基準env（段階6bと同じ） |
        /// | `Some([])` | **空だと申告した** | ほぼ空（harness所有の名前だけ） |
        ///
        /// **混ぜると起動そのものが落ちる。** `SystemRoot`の無い環境ブロックを渡された
        /// `CreateProcessW`は`ERROR_ENVVAR_NOT_FOUND`(203)で失敗する——2026-09-17の実機で
        /// 実際に踏んだ（空の申告を「申告なし」と同じに扱っていたため、**許可された遷移が
        /// 全部「起こそうとして失敗した」になった**）。
        ///
        /// `lpEnvironment`に`NULL`を渡す呼び出し元（＝「自分の環境を継がせたい」）を
        /// フックが運ぶときは、**フックが自分の環境を読んで`Some`で渡す**——
        /// `None`のまま運ぶと、呼び出し元がプロセス内で設定した変数が消える。
        #[serde(default)]
        env: Option<Vec<(String, String)>>,
        /// [段階6f-1] 子へ引き継がせるハンドル（[`CallerHandles`]）。
        #[serde(default)]
        handles: CallerHandles,
        /// [段階6f-1] 起こすプログラムがコンソールを要るか。
        ///
        /// **呼び出し元が`CreateProcessW`へ渡した生成フラグから導く**のが決めた形である
        /// （2026-09-17）——`CREATE_NO_WINDOW`も`DETACHED_PROCESS`も付いていないなら、
        /// 呼び出し元は「自分のコンソールを子に継承させる」つもりである。
        /// **実行ファイル名からの推測ではない**ので、[`ConsoleNeed`]のdocが禁じている形には
        /// 当たらない。
        ///
        /// 古い要求（欄を持たない）は`NotNeeded`として読む——段階6bの挙動そのものである。
        #[serde(default = "console_need_not_needed")]
        console: ConsoleNeed,
        /// [段階6f-1] 呼び出し元が`CREATE_SUSPENDED`を指定していたか。
        ///
        /// `true`ならDaemonは`ResumeThread`を撃たず、スレッドハンドルを返す
        /// （動かすのは呼び出し元）。**台帳への登録はどちらでもresumeの前に済ませる**。
        #[serde(default)]
        suspended: bool,
    },
}

/// [`SpawnRequest::Spawn::console`]の既定。**関数にしてあるのはserdeの`default`が
/// 値ではなくパスを要求するためで、意味は「段階6bと同じ」である。**
fn console_need_not_needed() -> ConsoleNeed {
    ConsoleNeed::NotNeeded
}

/// Daemon → サンドボックスの中のプロセス（要求受付パイプ）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpawnResponse {
    /// [段階6b] 遷移が許可されたので、**Daemonが実際に起こした**。
    ///
    /// # ハンドルは**要求元のプロセスへ複製済み**である（段階6f-1で追加）
    ///
    /// [`CallerHandles`]とは向きが逆で、こちらは[`ChildHandles`]と同じ「送る前に受け手へ
    /// 複製済み」の形である。要求元はこの2つを`PROCESS_INFORMATION`へ入れて
    /// `CreateProcessW`の呼び出し元へ返す——待つ・終了コードを読む・
    /// （一時停止で頼んだなら）再開する、はすべてこのハンドルで行われる。
    ///
    /// **閉じるのは要求元である。** Daemon側の原本は生成の直後に閉じてある。
    Spawned { pid: u32, process: u64, thread: u64 },
    /// 拒否した。**理由を分ける**のは、拒否した側と拒否の根拠が別の事実だからである
    /// （§10.2が`denied_by_daemon`と`denied_by_kernel`を分けたのと同じ理屈）。
    Denied { reason: DenyReason },
}

/// 拒否の理由。**「拒否された」だけでは、台帳の判定が効いているのかポリシーが
/// 効いているのか区別できない。**
///
/// 段階5の受け入れテストは、まさにこの2つが**別の値になること**を確かめる
/// ——同じ値にすると「常に拒否する」実装でも合格してしまう（`B-35`: 禁止側だけを測らない）。
///
/// # `Hash`を導出している理由（2026-09-12、段階6c）
///
/// 拒否の待ち行列（[`transitions`]）が**種類ごとに1行**へ畳むとき、この値が鍵の一部になる。
/// 理由を文字列へ潰さないのが引き継ぎの指示であり、`TransitionDenial`側にも同じ導出がある。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DenyReason {
    /// 接続元PIDがProcess Tableに無い（§12の既定拒否）。
    ///
    /// **「初期ドメイン」等の緩い既定へ倒さない。** Daemonが落ちて立ち上がり直した場合も
    /// ここへ落ちる——Process Tableは再構築できないので、それが正しい（§10.1）。
    NotRegistered,
    /// 接続元PIDは台帳に在るが、保持しているプロセスハンドルが終了済みだった
    /// ＝**PIDの再利用**（§12「PID再利用への対処」）。
    PidReused,
    /// [段階6b] **遷移ポリシーが断った。** 判定器の答えをそのまま運ぶ。
    ///
    /// **ここで語彙を作り直さない**（`B-13`）——判定器が理由を1つ増やしたとき、
    /// 電文側の写しだけが古くなる形を作らないためである。
    ///
    /// # なぜ`Transition(..)`（newtype）ではなく名前付きの欄なのか
    ///
    /// **どちらのenumも`kind`というタグ名を使っているためである。** newtypeにすると
    /// serdeは内側の構造を平らに書き出すので、`{"kind":"transition","kind":"..."}`という
    /// **`kind`が2つあるJSON**になる。書き出しはエラーにならず、読み戻しで片方が消える
    /// ——2026-09-12に実際にこの形で作ってしまい、`run_shell`のE2Eが拾った。
    /// 欄に名前を付けると`{"kind":"transition","denial":{"kind":"..."}}`と入れ子になる。
    Transition {
        denial: harness_policy::transition::TransitionDenial,
    },
    /// 辺は許可だが、**遷移先ドメインの実体がこのセッションに無い**。
    ///
    /// # 意味が狭まった（2026-09-20、#55の骨格）
    ///
    /// かつてこれは「**機構そのものが無い**ので別ドメインへは一切遷移できない」という
    /// 暫定の理由だった。発行器（`win_appcontainer/domain_provision.rs`）が入ったので、
    /// いまは「**このセッションでは用意できなかった**」を意味する。
    ///
    /// ドメインのセキュリティコンテキストは`(package SID, capability SIDの組)`であり
    /// （[§22.1](../../../../plans/DESIGN-MAC-DOMAIN.md)）、これは`policy.json`に書かれていない
    /// ——harnessが起動時に用意して[`ControlRequest::Hello`]の`domains`で渡す。
    /// **その表に載っていない遷移先は起こせない。**
    ///
    /// # 用意できない理由は3通りあるが、**この値はどれだったかを運ばない**
    ///
    /// 通信を宣言している（ドメインごとの出口制御が未実装）・宣言が許可済みでない
    /// （ユーザーが直せる）・入れ物の名前にできない（ユーザーが直せる）。
    /// **直せるものと直せないものが同じ値に丸まっている**ので、分類器
    /// （[`transitions::remedy`]）は保守的な側へ倒してある。
    /// 直し方の案内は**起動時の警告**が持つ（`Provisioned::skipped`の理由文）。
    ///
    /// # いつ消えるか
    ///
    /// **通信を含めてどのドメインも用意できるようになった日**である。
    /// 骨格の着地では消えない（上記）。
    ///
    /// **呼び出し元のcapabilityのまま名前だけ遷移先にする、という逃げ方は採らない。**
    /// 宣言では狭めたつもりの遷移が1ビットも狭まらず、しかもその食い違いは症状として出ない。
    TargetDomainNotProvisioned {
        /// 辺が指していた遷移先ドメイン名。
        to: String,
    },
    /// 電文が壊れている・長すぎる・接続元がAppContainerの外だった。
    MalformedRequest,
    /// [段階6c] **辺は許可だったが、起こそうとして失敗した。**
    ///
    /// # なぜ[`DenyReason::MalformedRequest`]と分けたのか（2026-09-12）
    ///
    /// 6bはこの経路を`MalformedRequest`で返していた。**「宣言が無い」へ丸めるのは避けていた**
    /// （同経路のコメントがその意図を書いている）が、残ったラベルは
    /// 「要求元が壊れた電文を送った」という**別の嘘**だった。
    ///
    /// 拒否の待ち行列（[`transitions`]）が入った段階6cで、この取り違えは
    /// **消えずに残る記録**になる——`CreateProcess`が落ちただけの拒否が、
    /// 待ち行列に「電文が壊れていた」の顔で積み上がる。直し方を探す人が
    /// 要求元のコードを読みに行くことになるので、分けた。
    ///
    /// **失敗の中身はこの値に載せない。** 要求元（サンドボックスの中）へ返るのも、
    /// 待ち行列へ積まれるのも「起こせなかった」までである——この型は電文と待ち行列の
    /// **両方**が使うので、ここへ詳細を足すとサンドボックスの中へパスや構成が漏れる。
    ///
    /// # ではどのWin32呼び出しで落ちたのかはどこにあるのか
    ///
    /// **Daemonの標準エラーだけ**である（`server.rs`が同じ分岐で`eprintln!`する）。
    /// Daemonはコンソールを持たないので、**既定ではどこにも届かない**——読むには
    /// [`client::DAEMON_STDERR_ENV`]（`HARNESS_SPAWND_STDERR`）に行き先を指しておく。
    ///
    /// **待ち行列を読んでも理由は出てこない。** 2026-09-19の測定（`plans/mac-spike/RESULTS.md`
    /// §S67）はここを取り違えて、待ち行列に理由が在るつもりで1往復を失った。
    SpawnFailed,
    /// **Strict の辺（P5.4a）は許可だったが、固定したファイルか作業ディレクトリ（P5.4d）を呼び出し元が書き換えられる**
    /// （`plans/DESIGN-MAC.md` §19.1）。起こす直前に、呼び出し元のトークンで実体の
    /// アクセス制御リストを評価して分かった（[`fixed_inputs`]）。判定できなかったときもこれで断る。
    ///
    /// # 宣言を直しても通らない
    ///
    /// 辺そのものは宣言どおりである。直し方は、固定したプログラム・作業ディレクトリを呼び出し元が書けない場所へ
    /// 移すか、その場所への書込許可を外すことで、**`policy.json`の側ではない**
    /// （[`transitions::Remedy::FixTheEnvironment`]）。
    ///
    /// **どのパスのどの権利かはこの値に載せない**——[`DenyReason::SpawnFailed`]と同じく、
    /// この型は電文と待ち行列の両方が使うので、載せるとサンドボックスの中へパスが漏れる。
    /// 中身はDaemonの標準エラーにだけ出る。
    FixedInputWritable,
}

impl DenyReason {
    /// 診断用の短い説明。**ユーザーへ出す文面ではない**（画面の文言は呼び出し側が持つ）。
    pub fn as_str(&self) -> &'static str {
        match self {
            DenyReason::NotRegistered => "caller pid is not in the process table",
            DenyReason::PidReused => "caller pid was reused by another process",
            DenyReason::Transition { denial } => denial.as_str(),
            DenyReason::TargetDomainNotProvisioned { .. } => {
                "the target domain was not prepared in this session (it is not in the table harness sent at startup)"
            }
            DenyReason::MalformedRequest => "malformed request",
            DenyReason::SpawnFailed => "the transition was allowed but the process could not be started",
            DenyReason::FixedInputWritable => {
                "the transition fixes a file or working directory that the caller can modify (or that could not be verified)"
            }
        }
    }
}
