//! harness-sandbox-vm: Tier3（Hyper-V外層VM + Incusコンテナによる二層分離）。
//! `--sandbox tier3`で明示的に選ぶ。`harness-sandbox`の**上**に載るクレートで、
//! `harness_sandbox::tier2a::win_appcontainer`のACL関数（`smb_share`が使う）と
//! `harness_sandbox::tier2a::privhelper::is_elevated`（`vmsandboxd`が使う）にのみ依存する
//! （逆方向の依存＝`harness-sandbox`が本クレートを知ることは無い、`plans/DESIGN.md`
//! §ワークスペース構成参照）。
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
//! 下3つはこのクレート内部の実装詳細のため`pub(crate)`。

pub mod vmsandbox;
pub mod vmsandboxd;
pub mod vmsandboxd_progress;

pub(crate) mod smb_share;
pub(crate) mod vm_host;
pub(crate) mod vm_ledger;
