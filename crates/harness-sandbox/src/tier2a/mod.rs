//! Tier2a（Windows）: AppContainer による OSレベル分離。既定のシェル隔離Tier。
//!
//! **境界はACL**（D-01）。AppContainerのpackage SIDに対して、許可したいパスへ明示的に
//! ACEを付ける以外に子プロセスがファイルへ到達する経路が無い、というOS側のdefault-denyに
//! 全面的に乗る。フックは境界にしない（`harness-redirector`のRedirector DLLは`--cow`の
//! 透過性のためだけに存在し、境界としては数えない）。
//!
//! | モジュール | 役割 |
//! |---|---|
//! | [`win_appcontainer`] | プロファイル/SID・ACE付与/撤収・子プロセス起動・preflight |
//! | [`privhelper`] | 特権分離ヘルパー（D-16）。管理者権限が要る操作だけを別プロセスへ委譲する |
//! | [`netfilterd`] | ネットワークポリシーを適用する常駐daemonとのIPC（WFPフィルタ投入を依頼する） |
//! | [`traverse_ledger`] | 祖先ディレクトリへ付与したtraverse ACEの記録（D10の巻き戻し用） |
//! | [`workspace_ledger`] | workspace/CoW upper_dirの生存管理（名前付きmutex）と付与済みworkspaceの一覧 |
//! | `wfp` | Windows Filtering Platformの薄いラッパ。`netfilterd`（昇格側）からのみ使う |
//! | `loopback_exemption` | AppContainer loopback exemption（マシン全体で1本）のプロセス跨ぎ所有権管理（D-36） |
//! | [`session_profile`] | セッション単位のAppContainerプロファイル名・生存マーカー・台帳・孤児回収（D-37） |
//! | [`mcp_profile`] | MCPサーバごとのAppContainerプロファイル名と、信頼境界での名前検証（D-38） |
//!
//! 設計正本は`plans/DESIGN-SANDBOX-APPPOLICY.md`、CoWモード（D-30）は
//! `plans/AppContainerベース Copy-on-Write ワークスペース設計書.md`。

/// セッション単位のAppContainerプロファイル管理（D-37）。**windows専用ではない**
/// （純粋な名前生成・回収判定は他プラットフォームでもコンパイル・テストできる）。
pub mod session_profile;

/// MCPサーバごとのAppContainerプロファイル名（D-38）。`session_profile`と同じ理由で
/// windows専用にしない（名前生成と検証は純粋関数）。
pub mod mcp_profile;

/// 付与したtraverse ACEの記録。**windows専用ではない**（`harness fs list`のような表示系
/// コマンドが非Windowsでも空台帳を表示できるよう、全プラットフォームでコンパイルする）。
/// Tier2a本体（下記）はWin32 API依存のためwindows専用。
pub mod traverse_ledger;

#[cfg(windows)]
pub mod netfilterd;
#[cfg(windows)]
pub mod privhelper;
#[cfg(windows)]
pub mod win_appcontainer;
/// workspace本体/CoW upper_dirの生存管理（名前付きmutex）はWin32 API依存。
#[cfg(windows)]
pub mod workspace_ledger;

/// WFPフィルタ投入の実体。クレート外からは使わない（`netfilterd`のdaemon側だけが呼ぶ。
/// 昇格プロセス内でのみ意味を持つため、非昇格の呼び出し元へ見せる理由が無い）。
#[cfg(windows)]
pub(crate) mod wfp;

/// loopback exemptionの所有権管理（D-36）。`wfp`と同じく昇格プロセス内でのみ意味を持つ。
#[cfg(windows)]
pub(crate) mod loopback_exemption;
