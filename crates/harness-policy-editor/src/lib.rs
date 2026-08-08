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
//! # このクレートが持つもの / 借りるもの
//!
//! | 用途 | どこから |
//! |---|---|
//! | Tier1起動・ストリーミング出力 | `harness_sandbox::tier1::win_restricted`（`spawn_streaming`） |
//! | ETW収集器（record-all） | `harness_sandbox::tier2a::policy_learnd`（`LearnPolicy.record_all`） |
//! | Local Proxy / Fake DNS | `harness_tools::net_proxy` / `fake_dns`（`proxy_env_vars`で環境変数注入） |
//! | 正規表現の提案 | `harness_policy::generalize` |
//! | ネットワーク全許可（パス2） | `harness_core::DomainPolicy::record_all()` |
//! | **監査JSONLの追記追従読み** | 本クレート [`audit_tail`] |
//! | **記録セッションの排他** | 本クレート [`session_lock`] |
//!
//! `harness-policy`は「**ファイルを読まない**」を明示的な契約にしているので、
//! tailerはそちらへは置けない（同クレートのlib.rs参照）。

pub mod audit_tail;
pub mod session_lock;

pub use audit_tail::AuditTail;
pub use session_lock::{LockOutcome, RECORDING_MUTEX_NAME};

#[cfg(windows)]
pub use session_lock::RecordingLock;
