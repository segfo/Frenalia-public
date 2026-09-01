//! TOMOYO風ポリシーエディタ（`plans/POLICY-EDITOR-TOMOYO-DIG.md`）。
//!
//! `harness.exe`（会話エージェント）とは別に**ユーザーが直接起動する2つ目のバイナリ**で、
//! LLMを介さずに「このコマンドに何を許すか」を対話的に決めるための道具である。
//!
//! # 記録は2パスで行う（このクレートの中心的な設計）
//!
//! FSのpermissiveさ（隔離しないこと）とネットワーク強制（Tier2aのpackage SIDが
//! 持つ性質）は**同一トークンでは両立しない**——AppContainerのFS制限は、package SIDを
//! 与えるlowboxトークン自体に備わる追加アクセスチェックだからである。そこで同時にではなく
//! **順番に**使う。
//!
//! | パス | Tier | 何を得るか | なぜそのTierか |
//! |---|---|---|---|
//! | 1 | **隔離なし（Tier0）** | 触ったファイル（record-all） | 記録したいのは「正常に動くときに何へ触るか」なので、**観測の器が対象の動きを変えてはいけない**。環境変数もユーザーのシェルと同じものを渡す（allowlistを通さない） |
//! | （中間） | — | FS候補をユーザーが承認して付与 | D-42（適用は常に明示操作） |
//! | 2 | Tier2a（AppContainer） | 接続したドメイン | package SIDがプロセスツリー全体を覆うのでWFP強制が効く |
//!
//! 依存の向きが要点で、FSの穴が開いていないとパス2が途中で落ち、ネットワークの学習が
//! そもそも成立しない。
//!
//! **`FWPM_CONDITION_ALE_APP_ID`でTier1を対象化する案は不可**（撤回済み）。APP_ID条件は
//! ソケットを所有するプロセスの実行ファイルにしか一致せず、**子プロセスへ継承されない**。
//! 記録対象は`cargo test`のように実際に通信するのが子孫プロセスであるため、
//! トップのシェルにdefault-denyを張っても子孫は素通しになり、fail-openなのに
//! 強制できているように見えるという最悪の形になる。
//!
//! # UIは3状態（記録 → 編集 ⇄ テスト）のうち2つまで実装した
//!
//! [`tui`]が**記録画面と編集画面**を持つ（端末から引数なしで起動すると開く）。記録画面が
//! パス1／パス2のどちらを走らせるかを選び、承認は編集画面で行う。ユーザーから見ると
//! 「コマンドを打って記録する」1つの行為で、途中にFS付与の承認だけが入る。
//!
//! **テスト画面（`policy.json`の宣言だけを許可して走らせ、想定外の拒否を見る＝ポリシー強制
//! モードでの検証）はまだ無い。** その実行系自体が未実装で、現行の[`record_net`]は
//! `DomainPolicy::record_all()`（全許可）を注入している。テストモードで想定外の拒否が出たら
//! 記録モードへ戻って追加のライブ記録もできる、という往復（編集⇄テスト）は将来の話である。
//!
//! CLI（`record`→`approve`→`record-net`と`show`/`sessions`）も**そのまま使える**。TUIは
//! その上に載るだけで、コマンドは**互いに独立**している（決定13：記録し直す・過去の記録を
//! 別の一般化度合いで見直す、をいつでも行えるようにするため）。
//!
//! # ACEを付ける経路は1つだけ（決定18）
//!
//! [`approve`]は`policy.json`へ書くだけで、実マシンには何も残さない。実際のACE付与と
//! 台帳への記録は[`record_net`]が`select_tier`→`preflight`経由で行う。承認時にも付けられる
//! ようにすると付与経路が2つになり、片方だけが台帳へ記録する／片方だけが撤収できる、
//! という形の事故になる（BUG-017の孤立ACEと同型）。
//!
//! # パス2は強制の上に成り立つ観測である（決定19）
//!
//! パス1が観測（fail-open、D-43）なのに対し、パス2は①Tier2aへ着地しなければ中止、
//! ②WFPが立たなければ中止、の2箇所でfail-closedにする。強制が無い状態の観測を同じ顔で
//! 出すと、ユーザーは「このドメインだけ使う」と読んでしまうため。
//!
//! # このクレートが持つもの / 借りるもの
//!
//! | 用途 | どこから |
//! |---|---|
//! | Tier0/Tier2a起動・ストリーミング出力 | `harness_sandbox`（`win_common::stream_child_output`を各Tierが共有） |
//! | Tier2a起動の前口上（宛先SIDの導出・背景walkの待ち） | `harness_sandbox::tier2a::win_appcontainer::spawn_shell_in_workspace`（`run_shell`と共有、D-54） |
//! | シェル起動の作法（コマンドはenv経由・stdinは固定ブートストラップ・境界印） | `harness_tools`（`run_shell`と共有、B-05） |
//! | ETW収集器（record-all） | `harness_sandbox::tier2a::policy_learnd`（`LearnPolicy.record_all`） |
//! | Local Proxy / Fake DNS | `harness_tools::net_proxy` / `fake_dns`（`*_with_policy`でポリシー注入・`proxy_env_vars`で環境変数注入） |
//! | WFPの出口強制 | `harness_sandbox::tier2a::netfilterd` |
//! | ACE付与と台帳 | `harness_sandbox`（`select_tier`→`preflight`・`tier2a::fs_passthrough_ledger`） |
//! | 候補の畳み込みと正規表現の提案 | `harness_policy`（`FsFolder` / `generalize` / `NetIntake::All`） |
//! | ネットワーク全許可（パス2） | `harness_core::DomainPolicy::record_all()` |
//! | **パス1のオーケストレーション** | 本クレート [`record`] |
//! | **パス2のオーケストレーション** | 本クレート [`record_net`] |
//! | **承認（中間ステップ）** | 本クレート [`approve`] |
//! | **`policy.json`（ドメイン型のポリシー）** | 本クレート [`policy_file`] |
//! | **記録セッションの置き場とマニフェスト** | 本クレート [`session_dir`] |
//! | **観測イベントの集計と表示** | 本クレート [`aggregate`]（FS）/ [`net_aggregate`]（ドメイン） |
//! | **子プロセスを回すループ・出力の切り分け** | 本クレート [`child_run`] / [`shell_output`]（パス1・2で共有） |
//! | **監査JSONLの追記追従読み** | 本クレート [`audit_tail`] |
//! | **記録セッションの排他** | 本クレート [`session_lock`]（パス1・2で共通の1本） |
//! | **記録・編集の2画面（TUI）** | 本クレート [`tui`] |
//! | 端末の生モード/オルタネートスクリーンの復帰 | `harness_term`（会話TUIと共有、規則5） |
//!
//! `harness-policy`は「**ファイルを読まない**」を明示的な契約にしているので、
//! tailerはそちらへは置けない（同クレートのlib.rs参照）。
//!
//! # 画面遷移の順序を強制しない
//!
//! 記録（[`record`]）と閲覧（[`aggregate`]＋[`session_dir`]）は独立していて、
//! 間の状態はワークスペース上のファイル（`fs-audit.jsonl`と`record-session.json`）が持つ。
//! 「記録し終えたら編集画面へ進む」ような一方通行のウィザードにしないためで、
//! 記録し直す・過去の記録を別の一般化度合いで見直す、をいつでも行える。
//!
//! TUIもこの上に載る。記録が終わると編集画面へ進む**ガイド**は出すが、`F1`/`F2`で
//! いつでも行き来できる（提案であって一方通行ではない）。

pub mod aggregate;
pub mod approve;
pub mod audit_tail;
/// **候補にしてはいけないパスの判定**（[BUG-103](../../../docs/bugs/BUG-103.md)）。
/// 候補を作る2経路（観測イベント・実行像）が同じ規則を通るための1箇所。
pub mod exclusion;
/// パス2の実行前に「そのコマンドの実行ファイルへ届くか」を測る（純粋関数、警告のみ）。
pub mod exec_reach;
pub mod net_aggregate;
pub mod policy_file;
pub mod session_dir;
pub mod session_lock;
pub mod shell_output;
/// 承認済み宣言の取り消し（[`approve`]の対）。`policy.json`から宣言を消す。**ACEは触らない**
/// ——撤収は付与と同じライフサイクル点（パス2の開始時と、プロセス終了時）が担当する。
pub mod unapprove;

/// 記録対象の子プロセスを回し切るループ（パス1・パス2が共有）。Windows専用の
/// `OutputEvent`を扱うため、モジュールごとwindows専用にする。
#[cfg(windows)]
pub mod child_run;

pub use aggregate::Aggregate;
pub use audit_tail::AuditTail;
pub use policy_file::{PolicyDomain, PolicyFile, PolicyFileError};
pub use session_dir::{RecordManifest, RecordSessionDir, RecordStatus};
pub use session_lock::{LockOutcome, RECORDING_MUTEX_NAME};

/// 記録・編集の2画面のTUI。記録（[`record`]・[`record_net`]）がwindows専用なのでこちらも
/// windows専用にする。**テスト画面（ポリシー強制モードでの検証）はまだ無い。**
#[cfg(windows)]
pub mod tui;

#[cfg(windows)]
pub mod record;
/// パス2（Tier2aでのドメイン記録）。AppContainer・WFP・Proxyに依存するためwindows専用。
#[cfg(windows)]
pub mod record_net;

#[cfg(windows)]
pub use record::{record, RecordError, RecordEvent, RecordOutcome, RecordRequest};
#[cfg(windows)]
pub use record_net::{
    record_net, NetRecordEvent, RecordNetError, RecordNetOutcome, RecordNetRequest, SessionGrants,
    SharedNetfilter,
};

#[cfg(windows)]
pub use session_lock::RecordingLock;
