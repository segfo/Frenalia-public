//! TOMOYO風ポリシーエディタ（`plans/POLICY-EDITOR-TOMOYO-DIG.md`）。
//!
//! `harness.exe`（会話エージェント）とは別に**ユーザーが直接起動する2つ目のバイナリ**で、
//! LLMを介さずに「このコマンドに何を許すか」を対話的に決めるための道具である。
//!
//! # 記録は2パスで行う（このクレートの中心的な設計）
//!
//! FSのpermissiveさ（Tier1の低ILが持つ性質）とネットワーク強制（Tier2aのpackage SIDが
//! 持つ性質）は**同一トークンでは両立しない**——AppContainerのFS制限は、package SIDを
//! 与えるlowboxトークン自体に備わる追加アクセスチェックだからである。そこで同時にではなく
//! **順番に**使う。
//!
//! | パス | Tier | 何を得るか | なぜそのTierか |
//! |---|---|---|---|
//! | 1 | Tier1（制限トークン＋低IL） | 触ったファイル（record-all） | 低ILは既定で何でも読めるのでコマンドが完走する |
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
//! # UIは3状態（記録 → 編集 ⇄ テスト）
//!
//! 記録モードが内部で上記2パスを進める。ユーザーから見ると「コマンドを打って記録する」
//! 1つの行為で、途中にFS付与の承認だけが入る。テストモードで想定外の拒否が出たら、
//! 編集モードでの手直しだけに閉じず**記録モードへ戻って追加のライブ記録**もできる
//! （本当に必要なアクセスを見落としたまま正規表現だけ書き足すのは推測に頼ることになるため）。
//!
//! **現状のUIはCLIだけで、3画面のTUIは未実装。** CLIは`record`（パス1）→`approve`（承認）→
//! `record-net`（パス2）と`show`/`sessions`で、**互いに独立したコマンド**である（決定13：
//! 記録し直す・過去の記録を別の一般化度合いで見直す、をいつでも行えるようにするため）。
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
//! | Tier1/Tier2a起動・ストリーミング出力 | `harness_sandbox`（`win_common::stream_child_output`を両Tierが共有） |
//! | Tier2a起動の前口上（主体の導出・背景walkの待ち） | `harness_sandbox::tier2a::win_appcontainer::spawn_shell_in_workspace`（`run_shell`と共有、D-54） |
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

pub mod aggregate;
pub mod approve;
pub mod audit_tail;
pub mod net_aggregate;
pub mod policy_file;
pub mod session_dir;
pub mod session_lock;
pub mod shell_output;

/// 記録対象の子プロセスを回し切るループ（パス1・パス2が共有）。Windows専用の
/// `OutputEvent`を扱うため、モジュールごとwindows専用にする。
#[cfg(windows)]
pub mod child_run;

pub use aggregate::Aggregate;
pub use audit_tail::AuditTail;
pub use policy_file::{PolicyDomain, PolicyFile, PolicyFileError};
pub use session_dir::{RecordManifest, RecordSessionDir, RecordStatus};
pub use session_lock::{LockOutcome, RECORDING_MUTEX_NAME};

#[cfg(windows)]
pub mod record;
/// パス2（Tier2aでのドメイン記録）。AppContainer・WFP・Proxyに依存するためwindows専用。
#[cfg(windows)]
pub mod record_net;

#[cfg(windows)]
pub use record::{record, RecordError, RecordEvent, RecordOutcome, RecordRequest};
#[cfg(windows)]
pub use record_net::{record_net, NetRecordEvent, RecordNetError, RecordNetOutcome, RecordNetRequest};

#[cfg(windows)]
pub use session_lock::RecordingLock;
