//! CLIの引数定義（clap）と起動パイプライン。
//!
//! `main.rs`（binターゲット）は`#[tokio::main]`と`cli::run()`の呼び出しだけを持ち、
//! 実体はここにある。`harness-cli`はワークスペースの終端クレート（誰にも依存されていない）
//! なので、libへ置いても公開面が外部の契約になることが無く、代わりに`tests/`から
//! 起動パイプラインへ到達できるようになる（`docs/CODE-STRUCTURE-RULES.md`規則4）。
//!
//! | モジュール | 役割 |
//! |---|---|
//! | 本ファイル | clap定義（`Cli`・`Commands`・各Action）とサブコマンドのディスパッチ |
//! | [`setup`] | 引数から実際の値を決める解決処理・セッション一覧 |
//! | [`startup`] | 起動パイプライン本体（`run`） |
//! | [`workspace_cmd`] | `changes`/`apply`/`discard`/`resolve`/`prompt` |
//! | [`net_cmd`] | `net`（監査ログ表示）とloopback許可ポート算出 |
//! | [`tier3_cmd`] | `tier3`（常駐daemonの状態確認とGC） |
//! | [`cow_cmd`] | `cow`（diff_layer_dir一覧・拒否監査） |
//! | [`approvals_cmd`] | `approvals`（承認台帳の一覧・取り消し） |

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};

use crate::{run_headless, OutputFormat};
use harness_cognition::{CensusTool, CognitiveOrchestrator, RecallTool};
use harness_core::{
    normalize_domain_pattern, CognitionLevel, LlmProvider, NetProxyConfig, RequireSandbox,
    SandboxChoice, StagingConfig, StagingMode, ToolCtx,
};
use harness_engine::{
    parse_allowlist_rule, AgentLoopConfig, ConversationState, PermissionArbiter, PermissionGate,
    PermissionMode,
};
use harness_providers::{AnthropicProvider, OpenAiProvider};
use harness_sandbox::{
    select_tier, ApplyOptions, ChangeCategory, SandboxFs, WorkspaceWriteMode,
};
use harness_tools::ToolRegistry;

const DEFAULT_ANTHROPIC_MODEL: &str = "claude-opus-4-8";
const DEFAULT_MAX_TOKENS: u32 = 4096;
const DEFAULT_MAX_TURNS: usize = 25;

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum ProviderKind {
    Anthropic,
    Openai,
    Lmstudio,
    /// out-of-processのTier2a E2Eテスト専用（`e2e-mock` feature必須）。
    /// `docs/DEV-ENVIRONMENT.md`「Tier2a E2Eテストの実行方法」参照。
    #[cfg(feature = "e2e-mock")]
    Mock,
}

impl ProviderKind {
    fn label(self) -> &'static str {
        match self {
            ProviderKind::Anthropic => "anthropic",
            ProviderKind::Openai => "openai",
            ProviderKind::Lmstudio => "lmstudio",
            #[cfg(feature = "e2e-mock")]
            ProviderKind::Mock => "mock",
        }
    }
}

#[derive(Clone, Copy, ValueEnum, Default)]
pub(crate) enum PermissionModeArg {
    Plan,
    #[default]
    Default,
    AcceptEdits,
    AcceptAll,
    Deny,
}

/// `--cognition off|auto|always|census`（`plans/DESIGN-COGNITION.md` §2.3、
/// `census`は`plans/PLAN-CENSUS-ENGINE.md`段階2）。
/// `harness_core::CognitionLevel`と1対1で、clapの`ValueEnum`をcoreへ持ち込まないための橋。
#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum CognitionLevelArg {
    Off,
    Auto,
    Always,
    Census,
}

/// `--require-sandbox[=<write-containment|confidential>]`——**最低要求の保証**（M12、
/// `plans/DESIGN-SANDBOX.md` §7 D-03）。
///
/// **`ValueEnum`にしてあるのは、打ち間違いを黙って吸わないためである。** かつては
/// `Option<String>`を`setup::parse_require_sandbox`が自前で`match`しており、未知の値は
/// すべて`write-containment`へ落ちていた——`--require-sandbox=confidentail`と打った人は
/// **読取の機密性を要求したつもりで、それを守らないTierで起動する**（[BUG-114](../../../docs/bugs/BUG-114.md)）。
/// 値の集合をclapへ知らせれば、同じ打ち間違いは起動前のパースエラーになる。
///
/// 綴りを`#[value(name = ...)]`で明示する理由は[`SandboxChoiceArg`]と同じ（derive既定の
/// kebab化に頼ると、綴りがclapの実装詳細で決まってしまう）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum RequireSandboxArg {
    #[value(name = "write-containment")]
    WriteContainment,
    #[value(name = "confidential")]
    Confidential,
}

impl From<RequireSandboxArg> for RequireSandbox {
    fn from(v: RequireSandboxArg) -> Self {
        match v {
            RequireSandboxArg::WriteContainment => RequireSandbox::WriteContainment,
            RequireSandboxArg::Confidential => RequireSandbox::Confidential,
        }
    }
}

/// `--sandbox tier0|tier1|tier2a|tier2a-cow|tier2b|tier3|tier3-warm`（`vm`は`tier3`の別名）。
/// `harness_core::SandboxChoice`と**「値を書いたとき」だけ**1対1で、`CognitionLevelArg`と同じく
/// **clapの`ValueEnum`をcoreへ持ち込まないための橋**である。
///
/// **`SandboxChoice::OsDefault`に対応する綴りは無い**——あれは*フラグを書かなかった*状態で、
/// CLI側では`Option<SandboxChoiceArg>`の`None`が担う。旧`auto`はその状態に綴りを与えていた
/// だけの値で、D-75で降格が消えたときにWindows上の`tier2a`と区別が付かなくなり廃止した（D-72）。
///
/// 綴りを`#[value(name = ...)]`で明示しているのは、derive既定のkebab化に頼ると
/// `Tier2aCow`が何になるかがclapの実装詳細で決まってしまうためである。この綴りが
/// [`harness_core::SandboxChoice::value_label`]（エラーメッセージ側の綴り）と一致することは
/// `startup::relaunch`の`every_sandbox_choice_has_a_cli_spelling_and_unknown_values_are_rejected`
/// が実パーサへ食わせて検算する（`bug-pattern-rules` B-05）。**置き場が再起動argvのモジュールに
/// なっているのは、`Cli::try_parse_from`を使うテストがそこにしか無いためである。**
///
/// **未知の値はパースエラーになる。** 値の集合を`ValueEnum`でclapに知らせているためで、
/// 打ち間違いが黙って別の値へ落ちることがない。`--require-sandbox`も同じ理由で
/// [`RequireSandboxArg`]へ移した（かつては`Option<String>`を自前で`match`しており、
/// `--require-sandbox=confidentail`が`write-containment`へ落ちていた＝BUG-114）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum SandboxChoiceArg {
    #[value(name = "tier0")]
    Tier0,
    #[value(name = "tier1")]
    Tier1,
    #[value(name = "tier2a")]
    Tier2a,
    #[value(name = "tier2a-cow")]
    Tier2aCow,
    #[value(name = "tier2b")]
    Tier2b,
    /// `vm`でも指定できる（旧`--vm-sandbox`からの別名）。
    #[value(name = "tier3", alias = "vm")]
    Tier3,
    #[value(name = "tier3-warm")]
    Tier3Warm,
}

impl From<SandboxChoiceArg> for SandboxChoice {
    fn from(v: SandboxChoiceArg) -> Self {
        match v {
            SandboxChoiceArg::Tier0 => SandboxChoice::Tier0,
            SandboxChoiceArg::Tier1 => SandboxChoice::Tier1,
            SandboxChoiceArg::Tier2a => SandboxChoice::Tier2a,
            SandboxChoiceArg::Tier2aCow => SandboxChoice::Tier2aCow,
            SandboxChoiceArg::Tier2b => SandboxChoice::Tier2b,
            SandboxChoiceArg::Tier3 => SandboxChoice::Tier3,
            SandboxChoiceArg::Tier3Warm => SandboxChoice::Tier3Warm,
        }
    }
}

/// **`--sandbox`を書かなかったときを`OsDefault`へ写す唯一の場所。**
///
/// `Option`のまま持ち回すと、受け取った側が`unwrap_or_default()`で好きな既定を当てられて
/// しまう——「値を書かなかった」の意味を決めてよいのはここだけである。
pub(crate) fn sandbox_choice_of(arg: Option<SandboxChoiceArg>) -> SandboxChoice {
    match arg {
        None => SandboxChoice::OsDefault,
        Some(v) => v.into(),
    }
}

#[cfg(test)]
impl SandboxChoiceArg {
    /// 逆向きの写像。**使うのはテストだけだが、置いてあるのは検問のためである**——
    /// `SandboxChoice`にvariantを足したときにこの`match`が非網羅になり、
    /// 「coreには在るのにCLIから選べない値」を無言で作れなくする（B-06）。
    /// **検問は`cargo test`で発火する**（本番ビルドから見ると未使用なので`cfg(test)`にしてある）。
    ///
    /// `OsDefault`だけは`None`（＝綴りが無い＝フラグを書かない）へ写る。
    /// （孤児則のため`From`ではなく関連関数にしてある——`SandboxChoice`も`Option`も
    /// このクレートの型ではない。）
    pub(crate) fn spelling_of(v: SandboxChoice) -> Option<SandboxChoiceArg> {
        match v {
            SandboxChoice::OsDefault => None,
            SandboxChoice::Tier0 => Some(SandboxChoiceArg::Tier0),
            SandboxChoice::Tier1 => Some(SandboxChoiceArg::Tier1),
            SandboxChoice::Tier2a => Some(SandboxChoiceArg::Tier2a),
            SandboxChoice::Tier2aCow => Some(SandboxChoiceArg::Tier2aCow),
            SandboxChoice::Tier2b => Some(SandboxChoiceArg::Tier2b),
            SandboxChoice::Tier3 => Some(SandboxChoiceArg::Tier3),
            SandboxChoice::Tier3Warm => Some(SandboxChoiceArg::Tier3Warm),
        }
    }
}

impl From<CognitionLevelArg> for CognitionLevel {
    fn from(v: CognitionLevelArg) -> Self {
        match v {
            CognitionLevelArg::Off => CognitionLevel::Off,
            CognitionLevelArg::Auto => CognitionLevel::Auto,
            CognitionLevelArg::Always => CognitionLevel::Always,
            CognitionLevelArg::Census => CognitionLevel::Census,
        }
    }
}

impl From<PermissionModeArg> for PermissionMode {
    fn from(v: PermissionModeArg) -> Self {
        match v {
            PermissionModeArg::Plan => PermissionMode::Plan,
            PermissionModeArg::Default => PermissionMode::Default,
            PermissionModeArg::AcceptEdits => PermissionMode::AcceptEdits,
            PermissionModeArg::AcceptAll => PermissionMode::AcceptAll,
            PermissionModeArg::Deny => PermissionMode::Deny,
        }
    }
}

/// ステージ済み変更（`harness_sandbox::SandboxFs`のオーバーレイ）・CoW操作台帳を操作する
/// サブコマンド（§オーバーレイFS「レビュー＆コミット」、M10）。CoW一本化（Phase 2）により
/// `--staged`/`--sandbox tier2a-cow`は同じ`SandboxFs`バックエンドを使うため、以前あった`--source
/// staged|cow|all`は廃止した——`--session <id>`が指すセッションの置き場を、`--staged`用・
/// CoW用の両方から自動的に探す。`--session`を省くと、**今のワークスペースの**セッションから
/// 最新のものを選ぶ。選び方の正本は`review_target::resolve_session_overlay_in`のdoc。
#[derive(Subcommand)]
pub(crate) enum Commands {
    /// 変更を一覧表示する。
    Changes {
        /// 対象セッションID（省略時は、今のワークスペースで最も新しいセッション）。
        #[arg(long)]
        session: Option<String>,
        #[arg(long = "output-format", value_enum, default_value_t = OutputFormat::Text)]
        output_format: OutputFormat,
    },
    /// 変更を実FSへ選択適用する。
    Apply {
        #[arg(long)]
        session: Option<String>,
        /// 選択適用フィルタ（`*`ワイルドカード対応、例 `src/*`）。省略時は全件対象。
        #[arg(long)]
        only: Option<String>,
        /// workspace外ターゲット（例 `C:\Windows\x`）の適用を許可する。
        ///
        /// **これはオーバーレイに溜まった変更をワークスペースの外の実FSへ出す唯一のゲートである。**
        /// モデルが`write_file`/`edit_file`に絶対パスを渡すと、その書込は`_ext/<key>`として
        /// オーバーレイに記録される（この時点で実FSは無傷）。`harness apply`はフラグ無しなら
        /// `blocked (out-of-workspace, needs --dangerously-allow)`と出して拒否し、
        /// **このフラグを付けたときだけ実FSへ書き込む**。
        ///
        /// `run_shell`の子プロセスはそもそも`SandboxFs`を通らないので、そちらを押さえるのは
        /// Tierの隔離である（このフラグの守備範囲ではない）。
        #[arg(long = "dangerously-allow", default_value_t = false)]
        dangerously_allow: bool,
        /// オーバーレイに実体はあるが操作台帳に記録が無い変更（`changes`で`[unledgered]`と
        /// 表示されるもの）も適用する。セッション開始時点の内容が分からないため、
        /// **実workspace側を他の誰かが編集していても検知できない**まま上書きする
        /// （docs/bugs/BUG-066.md）。workspace側に実体が無い新規作成は、このフラグ無しでも
        /// 適用される。
        #[arg(long = "adopt-unledgered", default_value_t = false)]
        adopt_unledgered: bool,
        /// 完全に適用し切った後もCoW差分層を消さずに残す（D-82）。
        ///
        /// 既定では、1件も残さず適用できた差分層はその場で畳む——作る側と消す側を対にして
        /// おかないと、セッションのたびに置き場が1つずつ積もるためである。中身をもう一度
        /// 見たい・別のツールで調べたい場合にこれを指定する。
        #[arg(long = "keep-diff-layer", default_value_t = false)]
        keep_diff_layer: bool,
        #[arg(long = "output-format", value_enum, default_value_t = OutputFormat::Text)]
        output_format: OutputFormat,
    },
    /// `apply`がbaseline照合の相違で拒否したコンフリクトを`git merge-file`の3-way mergeで
    /// 解消する。非コンフリクト分はこのコマンドの実行過程で先に実FSへ適用される（`apply`と
    /// 同じ経路を通るため）。自動マージできなかった分だけ`$VISUAL`/`$EDITOR`（Windowsは
    /// 既定`notepad.exe`）を起動して手で解消させる。
    Resolve {
        #[arg(long)]
        session: Option<String>,
        /// 自動マージできた分もエディタで確認したい場合に指定する（既定はオフ＝
        /// 自動マージできた分は即適用する）。
        #[arg(long = "always-edit", default_value_t = false)]
        always_edit: bool,
    },
    /// 変更を全て破棄する。
    Discard {
        #[arg(long)]
        session: Option<String>,
    },
    /// fs passthrough allowlist（軸2・D-13）の台帳保守サブコマンド。
    /// `--fs-allow`実行時フラグとは独立の、ユーザグローバル台帳を操作する副コマンド
    /// （`plans/DESIGN-SANDBOX-APPPOLICY.md`補遺、`TIER1A-OPEN-ISSUES.md`項目4）。
    Fs {
        #[command(subcommand)]
        action: crate::fs_grants::FsAction,
    },
    /// Tier2a（AppContainer）の運用保守サブコマンド（`plans/DESIGN-CLI-OPTIONS.md` §3.3）。
    /// 死んだセッションが残したプロファイルの回収と、生存判定の内訳表示。
    /// `harness tier3 gc`と対になる口で、**回収の実装は元から在り、ここは配線だけ**である。
    Tier2a {
        #[command(subcommand)]
        action: Tier2aAction,
    },
    /// Tier3（Hyper-V外層VM + Incusコンテナ）の運用保守サブコマンド
    /// （`plans/DESIGN-SANDBOX-VMISOLATION.md` §2.6 D-24）。
    Tier3 {
        #[command(subcommand)]
        action: Tier3Action,
    },
    /// `--sandbox tier2a-cow`の差分層置き場（`%LOCALAPPDATA%\harness\data\cow\<session-id>`）を確認・
    /// workspace本体へ反映・破棄するサブコマンド。差分層置き場はセッション終了時に
    /// 自動削除されない（エージェントの作業内容そのものが入っているため）ので、
    /// クラッシュ・強制終了で中断したセッションも`--resume <id> --sandbox tier2a-cow`で再開して
    /// 中身を確認できる。
    Cow {
        #[command(subcommand)]
        action: CowAction,
    },
    /// ネットワーク監査ログ（`net-audit.jsonl`）を表示する。
    Net {
        #[command(subcommand)]
        action: NetAction,
    },
    /// ゴールを横断する永続記憶（`Recall`、`plans/PLAN-RECALL-MEMORY.md`）の保守サブコマンド。
    Memory {
        #[command(subcommand)]
        action: MemoryAction,
    },
    /// ポリシー学習ヘルパー（M15.7、`plans/DESIGN-SANDBOX-APPPOLICY.md` §11）。
    /// サンドボックスが拒否した資源を4経路（preflight・network・CoW・OS監査）から集め、
    /// 「では何を許せばよいか」を`.harness/settings.json`への差分として提案する。
    /// **提案が自動適用されることはない**（D-42）——反映は`apply --accept <id>`という
    /// 明示操作を経てのみ行われ、変更は次回起動から発効する。
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// MCPサーバ宣言の承認台帳（M15.5、`plans/DESIGN-MCP.md` §4.2 D-39）を操作する。
    /// **宣言は承認台帳と一致したときだけ起動に使われる**——`.harness/settings.json`への
    /// 既存の多層防御はすべて「書込」への防御であり、リポジトリに同梱された宣言には一度も
    /// 発火しないため、ワークスペース外の台帳との照合が要る。
    Mcp {
        #[command(subcommand)]
        action: McpAction,
    },
    /// 承認画面で「恒久的に承認」した`run_program`・`run_shell`の記録
    /// （`plans/DESIGN-RUNSHELL-ALLOWLIST.md` §3.1）を一覧・取り消しする。
    /// **記録するだけで剥がせない片側を作らない**ためのコマンドで、台帳は
    /// ユーザー層（`%APPDATA%\harness\config`）にあり、ワークスペースには置かれない。
    Approvals {
        #[command(subcommand)]
        action: crate::cli::approvals_cmd::ApprovalsAction,
    },
    /// 現在のフラグ・`.harness/settings.json`構成から実際に組み立てられるシステムプロンプト
    /// （`harness_core::EnvironmentFacts`のレンダリング結果）をそのまま標準出力へ出して終了する。
    /// 「今モデルは何を知らされているのか」を確認するための読み取り専用診断コマンド
    /// （`run_shell`不安定性調査、Phase4-4）。プロンプトは送らない。
    ///
    /// シェル隔離Tierの選択は通常起動と同じ実プローブを伴う（AppContainerプロファイル作成等の
    /// 副作用がある）。`--fs-allow`/`--force-system-acl`はこのコマンドではサポートしない。
    Prompt,
}

/// `harness tier2a`サブコマンドの各操作。Windows専用機能（AppContainer）のため、
/// Windows以外ではエラーで終了する（`harness tier3`と同じ扱い）。
#[derive(Subcommand)]
pub(crate) enum Tier2aAction {
    /// OSネイティブ・パス制御の実験contractを副作用無しでprobeする。exportの有無だけでなく、
    /// runtime capability query（無い過渡期buildでは失敗専用create call）まで行う。
    NativePathSupport,
    /// 死んだセッションが残したAppContainerプロファイルとACEを回収する。
    ///
    /// 通常はharnessの起動時（preflight）に同じ処理が走るが、**harnessを起動せずに
    /// 片付けたい**ときの明示コマンド。`harness fs revoke-workspace*`とは守備範囲が
    /// 一部重なる——あちらは**指定したパス／台帳エントリ**、こちらは**死んだセッション**が対象。
    Gc,
    /// 走行中セッションの判定材料（台帳・`%LOCALAPPDATA%\Packages`・名前付きmutex）の
    /// 内訳を出す。
    ///
    /// **「0件」の意味が2つに割れる**ため段ごとに出す——本当に走行中セッションが無いのか、
    /// 材料が見えていないのか。後者はGCのガードにとってfail-openの穴になる。
    List,
}

/// `harness tier3`サブコマンドの各操作。Windows専用機能のため、Windows以外では
/// エラーで終了する（`harness fs`の非Windows時挙動と同じ、Tier3自体がWindows専用）。
#[derive(Subcommand)]
pub(crate) enum Tier3Action {
    /// 前回セッションの孤児VM・差分VHDXを台帳(D-24)+実機照会に基づき撤収する。
    /// 通常は新規Tier3セッション開始直前にdaemonが自動実行するが（`serve_inner`）、
    /// daemonクラッシュ直後の障害調査・手動運用のための明示コマンド。
    Gc,
    /// アクティブセッションが無い場合だけ常駐Tier3 daemonを終了する。
    StopDaemon,
    /// 常駐daemonが同時に受け付けるセッション数の上限を置く（既定4、
    /// `DESIGN-SANDBOX-VMISOLATION.md`「実装確定サマリー」項目6-a）。
    ///
    /// **限界: 走っているdaemonには効かない。** 上限はdaemonプロセスの起動引数としてのみ
    /// 受け付ける（後から接続する2本目以降のセッションが書き換えられては意味が無いため）。
    /// 既に常駐daemonが居るなら、先に`harness tier3 stop-daemon`で落とすこと。
    ///
    /// カウント対象はTier3セッションだけで、Tier0/Tier2a/Tier1/Tier2bはこのdaemonへ
    /// 接続しないため対象外。**かつてはルートフラグ`--tier3-max-sessions`だった**が、
    /// 値を伴う修飾は値へ畳めず、掛かる先（`--sandbox tier3`）の名前空間へ寄せた
    /// （`plans/DESIGN-CLI-OPTIONS.md` §3.3・§5.1）。
    SetMaxSessions {
        /// 上限（1以上。0を書いても1として扱う）。
        n: u8,
    },
}

/// `harness net`サブコマンドの各操作。
#[derive(Subcommand)]
pub(crate) enum NetAction {
    /// セッション単位の`net-audit.jsonl`を表示する。
    Audit {
        /// 対象セッションID（省略時は`.harness/sandbox/`内で最も新しいもの）。
        #[arg(long)]
        session: Option<String>,
        /// 監査ログJSONLへの直接パス。指定時は`--session`より優先する。
        #[arg(long)]
        path: Option<PathBuf>,
        /// `proxy` / `fake_dns` / `wfp` など、kindで絞り込む。
        #[arg(long)]
        kind: Option<String>,
        /// 拒否イベントだけを表示する。
        #[arg(long = "deny-only", default_value_t = false)]
        deny_only: bool,
        #[arg(long = "output-format", value_enum, default_value_t = OutputFormat::Text)]
        output_format: OutputFormat,
    },
}

/// `harness memory`サブコマンドの各操作（`plans/PLAN-RECALL-MEMORY.md`「レビュー運用」）。
#[derive(Subcommand)]
pub(crate) enum MemoryAction {
    /// checkpoint一覧。既定は未レビュー分のみ、`--all`で全件。
    List {
        #[arg(long, default_value_t = false)]
        all: bool,
        #[arg(long = "output-format", value_enum, default_value_t = OutputFormat::Text)]
        output_format: OutputFormat,
    },
    /// 1件の本文を表示する。
    Show { id: String },
    /// 未レビューのcheckpointを一覧し、`--mark-reviewed`でウォーターマークを進める。
    /// 外部diffビュワー起動は`plans/PLAN-VSCODE-REVIEW.md`が持つ（未実装）。
    Review {
        #[arg(long = "mark-reviewed", default_value_t = false)]
        mark_reviewed: bool,
    },
    /// 1件を削除する（ファイル削除＋index再構築。gitがあれば削除もコミット）。
    Discard { id: String },
    /// `checkpoints/*.md`から`index.jsonl`を強制的に再構築する。
    Reindex,
    /// このワークスペースの記憶ディレクトリを丸ごと削除する。
    Forget {
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
    /// このマシン上の全ワークスペースの記憶ディレクトリを一覧する。**既定では何も削除しない**
    /// （dry-run）。元ワークスペースのパスが現在存在しないことは削除の根拠にしない
    /// （未マウントのドライブと区別できないため）。
    Gc {
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
}

/// `harness policy`サブコマンドの各操作（M15.7）。
///
/// `--source`は`suggest`と`apply`の**両方**が受け取る。提案idは「どの経路を採ったか」に
/// 依存するため、同じ提案を指すには同じ条件で再計算する必要があるからである
/// （idだけを別条件で使い回すと別のものが適用される）。
///
/// **一般化（`--generalize`）はD-62で廃止した。** 候補は観測された値そのままで、
/// ディレクトリやワイルドカードへ畳まない。
#[derive(Subcommand)]
pub(crate) enum PolicyAction {
    /// 拒否された資源から許可ルールの候補を生成し、`.harness/settings.json`への差分として
    /// 表示する。**このコマンドは何も書き込まない。**
    Suggest {
        /// 対象セッションID（省略時は`.harness/sandbox/`内で最も新しいもの）。
        #[arg(long)]
        session: Option<String>,
        /// 収集源の限定（`all`（既定）/`preflight`/`net`/`cow`/`etw`）。
        #[arg(long)]
        source: Option<String>,
        #[arg(long = "output-format", value_enum, default_value_t = OutputFormat::Text)]
        output_format: OutputFormat,
    },
    /// 選んだ提案だけを`.harness/settings.json`へ書き込む（D-42の「明示操作」）。
    ///
    /// 「全件受理」のショートハンドは意図的に用意していない。1件でも未知のid・
    /// `--require-sandbox`と矛盾する提案があれば、**何も書かずに**失敗する（部分適用しない）。
    /// 書き込んだ変更は次回起動から発効する（harnessは自分のconfigを実行中に再読込しない）。
    Apply {
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        source: Option<String>,
        /// 受理する提案のid（`fs-1`・`net-2`）。カンマ区切り・繰り返し指定の両方に対応する。
        #[arg(long)]
        accept: Vec<String>,
        /// 対話確認を省略する。stdinが端末でない場合（パイプ・CI）は指定が必須。
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
    /// 正規化済みの拒否候補を4経路横断で一覧表示する（提案へ畳む前の生の材料）。
    Audit {
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        source: Option<String>,
        #[arg(long = "output-format", value_enum, default_value_t = OutputFormat::Text)]
        output_format: OutputFormat,
    },
    /// OS監査収集器（`harness-policy-learnd.exe`）を単体で起動し、指定時間だけFSアクセス拒否を
    /// 集めてから提案を表示する（M15.7）。**UACが1回出る**——ETWリアルタイムセッションの
    /// 開始には管理者権限が要るため。
    ///
    /// セッション中ずっと集めたい場合は`--policy-learn`フラグを使う。こちらは
    /// 「この操作をサンドボックス下で走らせたら何が拒否されるか」を単発で調べる用途。
    ///
    /// 収集器が起動できない環境（非管理者・ETWプロバイダ不在）でも**エラーにはしない**——
    /// その事実を明示して、既存3経路の記録だけで提案する（D-43 fail-open）。
    Learn {
        /// 収集する秒数。省略時は60秒。
        #[arg(long, default_value_t = 60)]
        duration: u64,
        /// 対象セッションID（省略時は`.harness/sandbox/`内で最も新しいもの）。
        #[arg(long)]
        session: Option<String>,
        #[arg(long = "output-format", value_enum, default_value_t = OutputFormat::Text)]
        output_format: OutputFormat,
    },
}

/// `harness cow`サブコマンドの各操作。Windows Tier2a `--sandbox tier2a-cow`固有機能のため、Windows以外は
/// エラーで終了する。単一セッション向けの一覧・適用・破棄は`harness changes`/`apply`/
/// `discard`（`--session`で対象のCoWセッションを自動的に見つける）へ統合済み（Phase 2）
/// ——`list`だけは全workspace横断の棚卸し用として引き続きここに残す。
#[derive(Subcommand)]
pub(crate) enum CowAction {
    /// 全ボリュームの差分層を一覧表示する（D-81で置き場はワークスペースのボリュームごとになった）。
    /// 各行の状態は`gc`が使うのと同じ判定から引く。
    List,
    /// ACLで実際に拒否された（`STATUS_ACCESS_DENIED`）workspace外書込試行の監査ログ
    /// （`.harness-cow-denied.jsonl`、Phase 4・設計書§19.8）を表示する。境界自体はACLが
    /// 既に保証しているため、これは可視性・監査目的のコマンドであり空でも異常ではない。
    Audit {
        /// 対象セッションID（省略時は最も新しいCoWセッション）。
        #[arg(long)]
        session: Option<String>,
        #[arg(long = "output-format", value_enum, default_value_t = OutputFormat::Text)]
        output_format: OutputFormat,
    },
    /// 何も残っていない差分層を回収する（D-82）。
    ///
    /// **既定では「空」のものしか消さない。** 実行中のセッション・D-80のレビュー待ち・
    /// メタが読めないもの・未適用の変更を抱えたものは残し、**残した理由を必ず表示する**。
    Gc {
        /// 判定だけ行い、1件も削除しない。
        #[arg(long)]
        dry_run: bool,
        /// **未適用の変更を抱えた差分層も回収対象に含める**（`--older-than`と併用）。
        /// 実行中・レビュー待ち・判定不能なものは、この指定でも回収しない。
        #[arg(long)]
        with_changes: bool,
        /// `--with-changes`が対象にする最小の経過日数。既定30日。
        #[arg(long = "older-than", default_value_t = 30)]
        older_than_days: u64,
    },
}

#[derive(Parser)]
#[command(name = "harness")]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// 非対話モードでプロンプトを送信し、応答をstdoutへ出力する。値が "-" ならstdinから読む。
    /// 省略時は対話TUI（`harness-tui`）を起動する（§リッチTUI、M7）。
    #[arg(short = 'p', long = "print")]
    print: Option<String>,

    /// 使用するモデルID。省略時、Anthropicは既定モデルを使う（OpenAIは省略不可）。
    #[arg(long)]
    model: Option<String>,

    /// 使用するプロバイダ。
    #[arg(long, value_enum, default_value_t = ProviderKind::Anthropic)]
    provider: ProviderKind,

    /// パーミッションモード（§パーミッション（承認）システム「モード」）。
    #[arg(long = "permission-mode", value_enum, default_value_t = PermissionModeArg::default())]
    permission_mode: PermissionModeArg,

    /// allowlistルール（`tool:pattern`形式、繰り返し指定可）。例: `run_shell:cargo test`（完全一致だけ）、
    /// `run_program:["git","log","-n",null]`（引数の配列。`null`は毎回変わってよい引数1個）、
    /// `write_file:src/*`（前方一致は書込先パスにだけ使える）。読めない規則は理由を出して無視する
    /// （`plans/DESIGN-RUNSHELL-ALLOWLIST.md` §3.4）。
    #[arg(long = "allow")]
    allow: Vec<String>,

    /// `--permission-mode accept-all`（とTUIの`/mode accept-all`）を許可する明示フラグ。無いと起動時に拒否する
    /// （§非対話モード）。`--allow`のワイルドカードには要らない（ユーザー自身が書いた規則なので。D-95）。
    #[arg(long = "dangerously-allow", default_value_t = false)]
    dangerously_allow: bool,

    /// 非対話モードの出力形式（§非対話モード「出力」）。`-p`省略時（対話TUI）は無視される。
    #[arg(long = "output-format", value_enum, default_value_t = OutputFormat::Text)]
    output_format: OutputFormat,

    /// プロバイダのbase_urlを明示指定する（`--provider`に応じて`ANTHROPIC_BASE_URL`/
    /// `OPENAI_BASE_URL`環境変数より優先される。§設定とシークレット「CLIフラグ（最優先）」）。
    /// 例: `--base-url http://localhost:1234/v1`
    #[arg(long = "base-url")]
    base_url: Option<String>,

    /// 暴走ループの保険（1ターン=1プロバイダターン+ツール実行、§実装マイルストーン M9で
    /// 正式な設定項目化）。省略時は`settings.json`階層→既定値の順にフォールバックする。
    #[arg(long = "max-turns")]
    max_turns: Option<usize>,

    /// コンテキスト縮約の判定に使う分母（トークン）。省略時は`settings.json`の
    /// `compaction.context_window`→プロバイダの`ProviderCapabilities.context_window`の順。
    ///
    /// **LMStudioでは実質必須**。`capabilities()`は128,000を返すが、実`n_ctx`はサーバの
    /// ロード設定依存で8k–32kのことが多く、合っていないと使用率閾値が意味を持たない
    /// （`plans/PLAN-COMPACTION.md`）。比率（`trigger_ratio`/`target_ratio`）は
    /// `settings.json`のみで、フラグは持たない——実機検証のたびに書き換えるのは分母だけだから。
    #[arg(long = "context-window")]
    context_window: Option<u32>,

    /// 認知レイヤーの段階（`plans/DESIGN-COGNITION.md` §2）。省略時は`settings.json`の
    /// `cognition.default_level`→既定値の順にフォールバックする。
    ///
    /// **現在実行できるのは`off`（素朴ループ）と`always`（HIVループのライト構成: 仮説→調査→
    /// 蒸留→検証→決定）**で、`auto`（難易度ルータ）を指定すると起動時にエラーになる
    /// （黙って`off`へ降格しない）。実装マイルストーンは`docs/INDEX.md`。
    #[arg(long = "cognition", value_enum)]
    cognition: Option<CognitionLevelArg>,

    /// ワークスペースルートを明示指定する（省略時はカレントディレクトリ、§非対話モード）。
    #[arg(long = "cwd")]
    cwd: Option<std::path::PathBuf>,

    /// 内部用（`/workspace`の再起動が自分で付ける、`startup::relaunch`）。指定されたPIDの
    /// プロセスが終了するまでStage4（preflight）へ進まない。
    ///
    /// 名前付きmutex（workspaceのモードマーカー・CoWのセッションマーカー）は**プロセス寿命に
    /// 紐付いている**ため、前のharnessが消える前に新しい方がpreflightへ入ると「同じworkspaceを
    /// 別モードで使用中」と誤判定され得る。人が手で打つものではないので`hide`する。
    #[arg(long = "wait-for-pid", hide = true)]
    wait_for_pid: Option<u32>,

    /// `.harness/sessions/session-<id>.jsonl`を復元して会話を継続する（M9、JSONL追記型
    /// セッション永続化）。`<id>`は`--continue`無しで起動した際にセッションファイル名から
    /// 拾える（`session-{id}.jsonl`）。値を省略した場合（`--resume`のみ）、対話TUI起動時に
    /// セッション選択ピッカーを開く。ヘッドレス（`-p`指定時）で値省略は非対話原則によりエラー。
    #[arg(long = "resume", num_args = 0..=1, default_missing_value = "")]
    resume: Option<String>,

    /// `.harness/sessions/`内の最も新しいセッションを復元して継続する。`--resume`と併用不可。
    #[arg(long = "continue", conflicts_with = "resume")]
    continue_session: bool,

    /// `--resume <id>`/`--continue`が指し示す既存セッションをForkして開始する（Claude Codeの
    /// `--fork-session`相当）。元のセッションファイルは変更せず、新規セッションへ全履歴を
    /// コピーしてから継続する。`--resume`/`--continue`のいずれかと併用必須。
    #[arg(long = "fork-session", default_value_t = false)]
    fork_session: bool,

    /// `.harness/sessions/`配下の保存済みセッションを一覧表示して終了する。プロンプトは送らない。
    #[arg(long = "list-sessions", default_value_t = false)]
    list_sessions: bool,

    /// TUI入力欄でEnterを送信キーにする（既定はShift+Enterが送信、素のEnterは改行を挿入）。
    /// 省略時は`settings.json`階層→既定値(false)の順にフォールバックする
    /// （`-p/--print`省略時＝対話TUI起動時のみ意味を持つ）。
    #[arg(long = "enter-submits")]
    enter_submits: Option<bool>,

    /// 即実FS（オーバーレイ無し）。省略時の既定と同じ動作（D-29）。`--staged`/
    /// `--workspace-commit`と併用不可（§書込ステージング3モード、M10）。
    ///
    /// **`--sandbox tier2a-cow`とも併用不可**（§5.2 A10）。CoWの差分層は`harness apply`まで
    /// 書込を実FSへ通さないので、「即実FS」と同時には成立しない。**かつては「意味的に
    /// 矛盾しない」として排他にしておらず、`--live`が黙って無視されていた**——その状態では
    /// モデルへ「即座に実FSへ反映されます」と「ワークスペース本体はread-only」が同時に
    /// 届いていた。この排他だけは値依存なのでclapでは宣言できず、
    /// `setup::resolve_staging_mode_checked`が実行時に拒否する。
    #[arg(long = "live", conflicts_with_all = ["staged", "workspace_commit"])]
    live: bool,

    /// 全書込をステージングし、実FSは`harness apply`まで不変にする。明示指定時のみ
    /// 有効なオプトイン機能で、既定の安全策ではない（§書込ステージング3モード、D-29）。
    /// `--sandbox tier2a-cow`とは互いに排他（マニフェスト方式とCoW方式という別々の書込捕捉
    /// 機構を同時に有効化しない）。**この排他だけはclapでは宣言できない**——「`--sandbox`が
    /// 特定の値のときだけ排他」は`conflicts_with`で表せないため、実行時判定
    /// （`setup::resolve_staging_and_write_mode`）が拒否する。
    #[arg(long = "staged", conflicts_with_all = ["live", "workspace_commit"])]
    staged: bool,

    /// workspace内はステージング→レビュー＆コミット、workspace外は常にsandbox隔離。
    /// 明示指定時のみ有効なオプトイン機能で、既定の安全策ではない
    /// （§書込ステージング3モード、D-29）。`--sandbox tier2a-cow`とは互いに排他
    /// （`staged`と同じ理由・同じ拒否点）。
    #[arg(long = "workspace-commit", conflicts_with_all = ["live", "staged"])]
    workspace_commit: bool,

    /// シェル隔離Tierの**最低要求**（M12、`plans/DESIGN-SANDBOX.md` §7 D-03）。着地したTierが
    /// 要求を満たさなければ起動を拒否する。
    ///
    /// - 値省略（`--require-sandbox`単体）＝`write-containment`: 書込拘束以上
    ///   （Tier3/Tier2a/Tier1/Tier2bでpass、Tier0で拒否）
    /// - `=confidential`: 機密性も要求（Tier3/Tier2a/Tier2bのみpass。Tier1も拒否）
    ///
    /// **D-75以後、下の段（`write-containment`）は既定と同じ意味になった。** 自動降格が
    /// 無くなり、Tier0で走るのは`--sandbox tier0`と明示したときだけなので、「Tier0を除く」は
    /// 既定で成り立つ。**実質的な意味を持つのは`=confidential`（Tier1も除く）だけ**である。
    /// 綴りとしては両方残してある（`plans/DESIGN-CLI-OPTIONS.md` §4.9）。
    #[arg(
        long = "require-sandbox",
        value_enum,
        num_args = 0..=1,
        default_missing_value = "write-containment"
    )]
    require_sandbox: Option<RequireSandboxArg>,

    /// **どの形の隔離で走るか**（M12、`plans/DESIGN-SANDBOX.md` §6/§7、D-72）。
    ///
    /// **値を書かなければ、そのOSの既定Tierを「要求」する**（Windows=Tier2a、Linux=Tier2b、
    /// その他OS=既定なし＝起動拒否）。**「既定」は委任ではない**——取れなければ起動を拒否する
    /// （D-75）。**どの値でも、要求したTierへ届かなければ弱いTierへ落ちずに止まる。**
    ///
    /// - `tier0`: **隔離なしで走ることを明示的に選ぶ。** `run_shell`の子はharness本体と同じ
    ///   権限で動く。昇格できないアカウント・bwrapが無いLinux・macOSでharnessを使うときの
    ///   逃がし弁で、**機械が勝手にここへ落とすことはもう無い**
    /// - `tier1`: Windows Tier1（Restricted Token + 低Integrity Level + Job Object）へ固定する。
    ///   preflightを通さない逃がし弁で、Tier2aの機密性/network遮断は諦める
    /// - `tier2a`: Tier2a（AppContainer）を要求する
    /// - `tier2a-cow`: Tier2a + Copy-on-Write（D-30、`plans/AppContainerベース Copy-on-Write
    ///   ワークスペース設計書.md`）。workspaceへのACLをRead/Execute/Traverseのみ（既定の
    ///   Read/Write/Execute/DeleteではなくD-13と同じread-onlyマスク）へ切り替え、`run_shell`
    ///   子プロセスの書込をworkspace外のCoW 差分層（`%LOCALAPPDATA%\harness\data\cow\
    ///   <session-id>\`）へRedirector DLLで誘導する。フックが無効・回避されても、ACLが
    ///   RO付与済みである限りworkspace本体への書込は`ACCESS_DENIED`でfail-closeする
    ///   （フックは境界にしない、D-01不変）
    /// - `tier2b`: Linuxのbubblewrapを要求する。**Linux以外では起動を拒否する**
    /// - `tier3`（別名`vm`）: Windows専用のTier3（Hyper-V外層AlmaLinux VM + Incus内層
    ///   コンテナ）を要求する。VM起動オーバーヘッドが高いため既定では試さない。ゴールデン像
    ///   VHDXが無い等で起動できない場合は**Tier2aへカスケードせず拒否する**（D-75）——Tier3は
    ///   vNIC単位で出口を強制できる唯一のTierなので、Tier2aは要求より弱い実態になる
    /// - `tier3-warm`: `tier3`をウォームスタート（production checkpointからの
    ///   `Restore-VMSnapshot`）で起こす（`plans/DESIGN-SANDBOX-VMISOLATION.md` §2.1）。初回は
    ///   テンプレートprovisioningのためコールドブート並みだが、2回目以降は起動が大幅に短い。
    ///   ウォームVMはマシン全体で1つに固定され、直列化ロックで排他される。
    ///   **空振りする条件が2つある**（[BUG-125](../../../docs/bugs/BUG-125.md)）——
    ///   (1) Tier3自体が成立しないとき、(2) **常駐VMが既に走っているとき**。
    ///   (2)では先に起こしたセッションへ相乗りするだけで、この値は何の効果も持たない
    ///   （速いのは相乗りだからであって、ウォームスタートが働いたからではない）。
    ///   **空振りしたときは`attach`がその旨を標準エラーへ1行出す**
    ///
    /// **かつては`--tier1`/`--vm-sandbox`/`--cow`という3本の真偽フラグだった。** 値1本へ
    /// 畳んだのは、`--tier1 --cow`のような「Tier2a以外でのCoW」が受理され、ACLを一度も
    /// 触らないまま「workspaceはread-only」とモデルへ宣言していたためである（BUG-113）。
    /// **`auto`と`--tier3-warm`も同じ理由でこの値集合へ畳んだ**（D-72、2026-08-24）。
    ///
    /// `tier2a-cow`は`--staged`/`--workspace-commit`と併用不可（マニフェスト方式とCoW方式と
    /// いう別々の書込捕捉機構を同時に有効化しない）。**`--live`とも併用不可**（書込が実FSへ
    /// 即座に届かないため。§5.2 A10）。これらは値依存の排他なのでclapでは宣言できず、
    /// `setup::resolve_staging_and_write_mode`が実行時に拒否する。
    #[arg(long = "sandbox", value_enum)]
    sandbox: Option<SandboxChoiceArg>,

    /// **ドメイン遷移MACを強制する**（段階⑤、`plans/DESIGN-MAC-ENFORCEMENT.md` §7・§10.1.2）。
    /// Tier2aの子へ**子プロセス生成の禁止**（`CHILD_PROCESS_RESTRICTED`。OSが生成そのものを
    /// 拒否する緩和策）を積み、生成はSpawn Daemonへの依頼に変える。Daemonは
    /// `.harness/policy.json`の`process`（遷移の宣言）と照合し、**宣言していない組み合わせを
    /// 断る**。断られた遷移は`run_shell`の出力末尾へ注記され、モデルは`can_run_program`で
    /// 「いま何を起こせるか」を引けるようになる。
    ///
    /// **明示指定時のみ有効なオプトインで、既定の安全策ではない。** 宣言を1本も書いていない
    /// ワークスペースでこれを立てると、**サンドボックスの中から外部プログラムを1つも
    /// 起動できない**（シェル自体は起きる）。まず何が断られるかを見てから宣言を書くこと。
    ///
    /// **Tier2a以外では意味を持たない**（Daemonが居ない）。指定しても静かに無視される
    /// のではなく、Daemonを起こさないTierではそもそも生成の窓口が無い。
    ///
    /// **この旗は暫定である**——⑤を製品の既定へ入れる日に、既定値を反転して畳む
    /// （`ChildProcessPolicy::PRODUCT_DEFAULT`のdoc）。
    #[arg(long = "enforce-transitions", default_value_t = false)]
    enforce_transitions: bool,

    /// ドメイン単位network制御の許可ドメインを追加する（繰り返し指定可、
    /// `*.example.com`形式のサフィックスワイルドカード対応）。
    /// `.harness/settings.json`の`net.allow_domains`と合算する（和集合）。`run_shell`子には既定で
    /// `ALL_PROXY=socks5h://...`と`HTTP_PROXY`/`HTTPS_PROXY`を注入するLocal Proxy Agentが起動し、
    /// 許可ドメイン未指定なら全拒否として監査ログに残す。Tier2aでWFPが使える場合は外部直通を
    /// default-denyし、Proxy/Fake DNSのloopback実ポートだけを許可する。WFPが使えない場合は
    /// 協調Proxyとして動作し、外部直通を強制遮断できないことを出力へ明記する。
    #[arg(long = "net-allow-domain")]
    net_allow_domain: Vec<String>,

    /// アプリ単位network制御（軸1、`plans/DESIGN-SANDBOX-APPPOLICY.md` D-10/D-11）の信頼アプリ名を
    /// 追加する（繰り返し指定可、実行ファイルのbasename・拡張子除去・小文字で照合。例`git`）。
    /// `.harness/settings.json`の`net.allow_apps`と合算する（和集合）。Tier2a（AppContainer）でのみ
    /// 効く: 先頭execが一致した単一コマンド（`|`/`&&`/`;`等で連結されていない）にのみ
    /// `internetClient` capabilityを付与し外向き通信を許可する（宛先無差別、T-15でプロセスツリー
    /// 全体が継承）。`--require-sandbox=confidential`と同時指定はできない（意味的に矛盾、起動拒否）。
    #[arg(long = "net-allow-app")]
    net_allow_app: Vec<String>,

    /// fs passthrough allowlist（軸2・D-13、`plans/DESIGN-SANDBOX-APPPOLICY.md`補遺）の
    /// 追加ルートを指定する（繰り返し指定可、`<path>[:rw]`形式）。省略時（末尾`:rw`無し）は
    /// read-only、`:rw`指定時は書込も許可する（D-13「read-onlyを既定とする」）。
    /// `.harness/settings.json`の`fs.allow`と合算する（和集合）。Tier2a（AppContainer）でのみ
    /// 効く: 指定ルートへpackage SIDの許可ACEを付与し、到達性をプローブする（D8）。
    /// `--require-sandbox`との組合せはD7参照（write-containmentは`:rw`のみ拒否、confidentialは
    /// `:ro`/`:rw`いずれも拒否）。
    #[arg(long = "fs-allow")]
    fs_allow: Vec<String>,

    /// `--fs-allow`のシステム保護パス（`NT SERVICE\TrustedInstaller`所有等でAdministrator昇格でも
    /// `WRITE_DAC`不可）へ、特権分離ヘルパーが`SeRestorePrivilege`を有効化して**強制付与**する
    /// （D-19、既定オフ）。所有権は変えない（非破壊）。危険な拡張のためread-only専用
    /// （`:rw`との併用は拒否）で、`%SystemRoot%`配下やドライブルート等の中核パスは
    /// `is_force_grant_forbidden`ゲートで拒否する。付与したACEはharness終了後も残るため
    /// `harness fs revoke`で撤収すること。
    #[arg(long = "force-system-acl")]
    force_system_acl: bool,

    /// セッション中、OS監査によるFSアクセス拒否の収集を有効にする（M15.7、
    /// `plans/DESIGN-SANDBOX-APPPOLICY.md` §11）。**指定するとUACが1回出る**——ETWリアルタイム
    /// セッションの開始に管理者権限が要るため、収集器（`harness-policy-learnd.exe`）を昇格起動する。
    ///
    /// 集めた拒否は`.harness/sandbox/session-<id>/fs-audit.jsonl`へ書かれ、`harness policy suggest`が
    /// 既存3経路（preflight・network・CoW）と合わせて許可ルールの候補を提案する。
    /// **収集は提案の材料を増やすだけで、権限を自動で広げることは一切しない**（D-42）。
    ///
    /// 収集器が起動できなくてもharnessは止まらない（D-43 fail-open）。その場合は
    /// 「収集できていない」ことが`fs-audit.jsonl`の制御レコードとして残る。
    /// 省略時は`settings.json`の`policy.learn`→既定(false)の順にフォールバックする。
    ///
    /// **裸で打てる**（`--policy-learn`＝有効化）。`--policy-learn=false`と書けば、設定側で
    /// 有効になっていてもこの実行だけ無効にできる——だから真偽フラグではなく`Option<bool>`の
    /// ままである（「打たなかった」と「打って偽にした」を区別する必要がある）。
    /// かつては値が必須で、**docが案内していた裸の形が必ずclapエラーになっていた**
    /// （`plans/DESIGN-CLI-OPTIONS.md` §4.9 対象3）。
    #[arg(long = "policy-learn", num_args = 0..=1, default_missing_value = "true")]
    policy_learn: Option<bool>,

    /// Streamable HTTPのMCPサーバとして接続してよい宛先を足す（繰り返し指定可、M15.6、D-41/D-49）。
    ///
    /// **この指定自体が、この実行でのStreamable HTTPの有効化である。** 宛先を1つも書かなければ
    /// 1つも起動しない（closed-by-default）——「有効化したのに宛先が無くて何も起きない」と
    /// 「宛先を書いたのに有効化フラグが無くて無視された」という2つの空振りを、
    /// 口を1つにすることで消してある（`plans/DESIGN-CLI-OPTIONS.md` §5.6 B1-3）。
    ///
    /// 値の書式が緩和の内容を決める（`harness_mcp::parse_http_allow_value`）。
    ///
    /// - `mcp.corp.example` / `https://mcp.corp.example` — httpsのみ
    /// - `http://legacy.corp.example` — **そのドメインだけ**平文httpも許す（他へは広がらない）
    /// - `*.corp.example` — サフィックスワイルドカード
    ///
    /// ユーザ設定の`mcp.http_allow_domains`と合算する（和集合。設定側は常にhttpsのみ）。
    /// 恒久的に有効化するなら**ユーザ設定**の`settings.json`へ書く（プロジェクトの
    /// `.harness/settings.json`からは有効化できない）。stdioのMCPサーバと違い、この経路は
    /// harness本体が直接HTTPで喋るため、AppContainer・WFPの出口強制・協調プロキシの
    /// いずれも掛からない（`plans/DESIGN-MCP.md` §6.2）。loopbackは免除される。
    ///
    /// **かつては3本に分かれていた**（`--allow-mcp-http`・`--allow-mcp-http-domain`・
    /// `--allow-mcp-http-plaintext`）。平文が単一の真偽フラグだったため、1ホストのために
    /// 打つと許可リスト全体が平文可になっていた。
    #[arg(long = "mcp-http-allow")]
    mcp_http_allow: Vec<String>,

    /// `--provider mock`用の台本ファイル（`Vec<Vec<StreamEvent>>`のJSON）。
    /// out-of-processのTier2a E2Eテスト専用（`e2e-mock` feature必須）。
    #[cfg(feature = "e2e-mock")]
    #[arg(long = "mock-turns")]
    mock_turns: Option<PathBuf>,

    /// `--provider mock`が受信した`CompletionRequest`をJSONLへ追記する先。
    /// out-of-processのTier2a E2Eテスト専用（`e2e-mock` feature必須）。
    #[cfg(feature = "e2e-mock")]
    #[arg(long = "mock-record-requests")]
    mock_record_requests: Option<PathBuf>,
}

/// ルート位置に置かれた`--dangerously-allow`が、サブコマンド経路では効かないことを検出する
/// （[BUG-120](../../../docs/bugs/BUG-120.md) 案A）。効かないなら**理由を返す**。
///
/// # なぜ必要か
///
/// `--dangerously-allow`は**同じ綴りで2本ある**。ルート側は「`--permission-mode accept-all`と
/// ワイルドカード`--allow`の解禁」、`apply`側は「ワークスペース外への実FS適用の解禁」で、
/// **意味が別**である。そして`harness --dangerously-allow apply`は
/// **clapがエラーを出さずに受理する**——サブコマンドの前にルート引数を置くのは正しい構文だからで、
/// 綴りが違えば出る終了コード2が、位置が違うだけのときは出ない。
///
/// 結果、`apply`側の値は`false`のまま走り、ユーザーには
/// `blocked (out-of-workspace, needs --dangerously-allow)`だけが見える。
/// **「付けたのに拒否された」ように読めて、付けた場所が違うという情報がどこにも出ない。**
///
/// # なぜ`global = true`で揃えないのか
///
/// `global`は落とすのではなく**併合する**。意味の違う2つのゲートが1つの値になるので、
/// ルート側に付けただけで`_ext`の適用まで開く——**倒れる向きが安全側から危険側へ反転する。**
/// 綴りの衝突そのものは`cli_structure_tests.rs`が宣言を強制して見張る。
pub(crate) fn misplaced_root_dangerously_allow(cli: &Cli) -> Option<String> {
    if cli.command.is_none() || !cli.dangerously_allow {
        return None;
    }
    Some(
        "--dangerously-allow was given before the subcommand, where it only unlocks \
         --permission-mode accept-all and wildcard --allow for an agent run. It does not reach \
         the subcommand. If you meant to allow applying changes outside the workspace, put it \
         after the subcommand: `harness apply --dangerously-allow`."
            .to_string(),
    )
}

#[cfg(test)]
#[path = "cli_structure_tests.rs"]
mod cli_structure_tests;

pub mod approvals_cmd;
pub mod cow_cmd;
pub mod mcp_cmd;
pub mod memory_cmd;
pub mod net_cmd;
pub mod policy_cmd;
pub mod review_target;
pub mod setup;
pub mod startup;
pub mod tier2a_cmd;
pub mod tier3_cmd;
pub mod workspace_cmd;

pub(crate) use cow_cmd::*;
pub(crate) use mcp_cmd::*;
pub(crate) use memory_cmd::*;
pub(crate) use net_cmd::*;
pub(crate) use policy_cmd::*;
pub(crate) use review_target::*;
pub(crate) use setup::*;
pub(crate) use tier2a_cmd::*;
pub(crate) use tier3_cmd::*;
pub(crate) use workspace_cmd::*;

pub use startup::run;
