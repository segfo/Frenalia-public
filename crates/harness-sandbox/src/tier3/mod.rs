//! Tier3: Hyper-V外層VM + Incusコンテナによる二層分離。`--vm-sandbox`で明示的に選ぶ。
//!
//! マルチセッション対応は「1VM + 常駐daemon + Incusコンテナ複数」で確定している
//! （`plans/DESIGN-SANDBOX-VMISOLATION.md` D-25・D-26。別方針を再提案する前に必ず読むこと）。
//!
//! | モジュール | 役割 |
//! |---|---|
//! | [`vmsandbox`] | Incus RESTクライアント・SSH実行・セッションのライフサイクル |
//! | [`vmsandboxd`] | 常駐daemonとのIPC（名前付きパイプ）と呼び出し元認証 |
//! | [`vmsandboxd_progress`] | 準備画面の合成進捗ticker |
//! | `vm_host` | 外層VM（Hyper-V）の起動/撤収と参照カウント |
//! | `vm_ledger` | 実マシンへ作ったVM・差分VHDX・SMB共有の記録 |
//! | `smb_share` | ワークスペース共有用の使い捨てSMBアカウント/共有 |
//!
//! 下3つはこのTier内部の実装詳細のため`pub(crate)`。Tier3を別クレートへ切り出す場合
//! （`docs/STATUS.md` R-03）、このディレクトリをそのまま昇格させればよい配置にしてある。

pub mod vmsandbox;
pub mod vmsandboxd;
pub mod vmsandboxd_progress;

pub(crate) mod smb_share;
pub(crate) mod vm_host;
pub(crate) mod vm_ledger;
