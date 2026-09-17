//! Tier2a（Windows）: AppContainer による OSレベル分離。既定のシェル隔離Tier。
//!
//! **境界はACL**（D-01）。AppContainerのpackage SIDに対して、許可したいパスへ明示的に
//! ACEを付ける以外に子プロセスがファイルへ到達する経路が無い、というOS側のdefault-denyに
//! 全面的に乗る。フックは境界にしない（`harness-redirector`のRedirector DLLは`--sandbox tier2a-cow`の
//! 透過性のためだけに存在し、境界としては数えない）。
//!
//! | モジュール | 役割 |
//! |---|---|
//! | [`win_appcontainer`] | プロファイル/SID・ACE付与/撤収・子プロセス起動・preflight |
//! | [`privhelper`] | 特権分離ヘルパー（D-16）。管理者権限が要る操作だけを別プロセスへ委譲する |
//! | [`netfilterd`] | ネットワークポリシーを適用する常駐daemonとのIPC（WFPフィルタ投入を依頼する） |
//! | [`traverse_ledger`] | 祖先ディレクトリへ付与したtraverse ACEの記録（D10の巻き戻し用） |
//! | [`workspace_ledger`] | workspace/CoW diff_layer_dirの生存管理（名前付きmutex）と付与済みworkspaceの一覧 |
//! | [`workspace_capability`] | workspace＋モード単位のFS付与の宛先SID（capability名とその秘密、D-54） |
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

/// CoWセッションを起こす前に、Redirector DLL 2本（x64・WOW64用x86）の**版がそろっているか**を
/// 検算する。`session_profile`と同じ理由でwindows専用にしない（走査と突き合わせは純粋関数で、
/// 他プラットフォームでもコンパイル・テストできる）。
pub mod redirector_identity;

/// 「付与したACEが台帳に載っているか」の自己検証（BUG-101欠陥①）。突き合わせの判定は
/// 純粋関数なので、`session_profile`と同じ理由でwindows専用にしない（DACLの実測だけがcfg分岐）。
pub mod grant_audit;

/// 付与したtraverse ACEの記録。**windows専用ではない**（`harness fs list`のような表示系
/// コマンドが非Windowsでも空台帳を表示できるよう、全プラットフォームでコンパイルする）。
/// Tier2a本体（下記）はWin32 API依存のためwindows専用。
pub mod traverse_ledger;

/// 付与したfs passthrough ACE（`--fs-allow`・`.harness/settings.json`の`fs.*`）の記録。
/// `traverse_ledger`と同じ理由で全プラットフォームでコンパイルする。
pub mod fs_passthrough_ledger;

/// workspace＋モード単位のcapability名とその秘密（D-54）。`session_profile`と同じ理由で
/// windows専用にしない（名前の導出・台帳・検証は純粋関数で、CSPRNGだけがcfg分岐する）。
pub mod workspace_capability;

/// `.harness/transitions/`へ積む記録の共通部品（段階6c・6d）。**拒否（Spawn Daemonが書く）と
/// 候補（収集器が書く）で数え方を揃えるためにここに置く**——同じ画面が両方を読むので、
/// 片方だけ`count`の意味が違うと読み手が取り違える。`spawnd`と同じ理由でwindows専用にしない
/// （畳み込みと行の形は純粋で、昇格なしに単体テストできることが検証の要である）。
pub mod transitions_log;

/// Spawn Daemon（遷移MAC 段階5）のワイヤ形式とProcess Table。`session_profile`と同じ理由で
/// モジュールごとwindows専用にはしない——電文の形とProcess Tableの判定は純粋で、
/// **昇格なしに単体テストできることがこの機構の検証の要**だからである（§12の既定拒否・
/// 系統Jobの回収条件）。Win32を呼ぶDaemon本体とクライアントだけがwindows専用。
pub mod spawnd;

#[cfg(windows)]
pub mod netfilterd;
/// ポリシー学習ヘルパー（M15.7、OS監査によるFSアクセス拒否の収集）。ETWセッションが
/// Windows専用のため、モジュールごとwindows専用にする。
#[cfg(windows)]
pub mod policy_learnd;
#[cfg(windows)]
pub mod privhelper;

/// **ヘルパーを起こす代わりの手段**（D-60）。パイプ名を受け取り、`Ok(())`なら
/// 「そのパイプへ接続してくるヘルパーが起きた」ことを意味する。意味と使い方は
/// [`privhelper::client`]のdocが持つ（あちらはこの別名を再輸出しているだけ）。
///
/// **なぜWindows専用モジュールの外に置くのか。** 実体は関数ポインタの別名にすぎず
/// OSに依存しないが、これを`privhelper`（`#[cfg(windows)]`）の中に置くと、
/// この型を引数に取る[`crate::shell_tier::select_tier`]の**シグネチャ自体**が
/// 非Windowsで解決できなくなる。実際にそうなっており、`harness-sandbox`は
/// Linux/macOS向けに`cargo check`が通らない状態が続いていた（`E0433`）。
/// **型の置き場が、その型を1度も使わないOSのビルドを落とす**という形である。
pub type ChainLauncher<'a> = &'a dyn Fn(&str) -> Result<(), String>;
#[cfg(windows)]
pub mod win_appcontainer;
/// workspace本体/CoW diff_layer_dirの生存管理（名前付きmutex）はWin32 API依存。
#[cfg(windows)]
pub mod workspace_ledger;

/// WFPフィルタ投入の実体。クレート外からは使わない（`netfilterd`のdaemon側だけが呼ぶ。
/// 昇格プロセス内でのみ意味を持つため、非昇格の呼び出し元へ見せる理由が無い）。
#[cfg(windows)]
pub(crate) mod wfp;

/// loopback exemptionの所有権管理（D-36）。`wfp`と同じく昇格プロセス内でのみ意味を持つ。
#[cfg(windows)]
pub(crate) mod loopback_exemption;

/// **測定専用スパイク**（BUG-111の残り: シナリオ(A)のE2Eが成立するかの前提を測る）。
/// 昇格した`dev-elevated-runner`配下から非昇格の子を起こせるか。
/// **判定が出たら削除する**（`docs/CODE-STRUCTURE-RULES.md`規則2）。
///
/// **モジュール名は`KNOWN_TARGETS`の`spike-deelevation`のフィルタ文字列と一致していること**
/// （改名すると0件マッチで黙って緑になる。BUG-056）。
#[cfg(all(windows, test))]
mod deelevation_spike_tests;
