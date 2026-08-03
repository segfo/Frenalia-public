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
//! | [`cow_cmd`] | `cow`（upper_dir一覧・拒否監査） |

use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use crate::{run_headless, OutputFormat};
use harness_cognition::CognitiveOrchestrator;
use harness_core::{
    normalize_domain_pattern, CognitionLevel, LlmProvider, NetProxyConfig, RequireSandbox,
    StagingConfig, StagingMode, ToolCtx,
};
use harness_engine::{
    parse_allowlist_rule, AgentLoopConfig, ConversationState, PermissionArbiter, PermissionMode,
};
use harness_providers::{AnthropicProvider, OpenAiProvider};
use harness_sandbox::{select_tier, ApplyOptions, SandboxFs, WorkspaceWriteMode};
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

/// `--cognition off|auto|always`（`plans/DESIGN-COGNITION.md` §2.3）。
/// `harness_core::CognitionLevel`と1対1で、clapの`ValueEnum`をcoreへ持ち込まないための橋。
#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum CognitionLevelArg {
    Off,
    Auto,
    Always,
}

impl From<CognitionLevelArg> for CognitionLevel {
    fn from(v: CognitionLevelArg) -> Self {
        match v {
            CognitionLevelArg::Off => CognitionLevel::Off,
            CognitionLevelArg::Auto => CognitionLevel::Auto,
            CognitionLevelArg::Always => CognitionLevel::Always,
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
/// `--staged`/`--cow`は同じ`SandboxFs`バックエンドを使うため、以前あった`--source
/// staged|cow|all`は廃止した——`--session <id>`（省略時は最新）が指すセッションを
/// `--staged`用の置き場・`--cow`用の置き場の順で自動的に探す（1セッションは常にどちらか
/// 一方でしか起動されない、Phase 0の`conflicts_with_all`）。
#[derive(Subcommand)]
pub(crate) enum Commands {
    /// 変更を一覧表示する。
    Changes {
        /// 対象セッションID（省略時は最も新しいもの）。
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
        /// workspace外ターゲット（例 `C:\Windows\x`）の適用を許可する。Phase 2時点では
        /// workspace外書込自体を記録しないため常に無関係（Phase 3で復活予定）。
        #[arg(long = "dangerously-allow", default_value_t = false)]
        dangerously_allow: bool,
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
    /// Tier3（Hyper-V外層VM + Incusコンテナ）の運用保守サブコマンド
    /// （`plans/DESIGN-SANDBOX-VMISOLATION.md` §2.6 D-24）。
    Tier3 {
        #[command(subcommand)]
        action: Tier3Action,
    },
    /// `--cow`のupper置き場（`%LOCALAPPDATA%\harness\data\cow\<session-id>`）を確認・
    /// workspace本体へ反映・破棄するサブコマンド。upper置き場はセッション終了時に
    /// 自動削除されない（エージェントの作業内容そのものが入っているため）ので、
    /// クラッシュ・強制終了で中断したセッションも`--resume <id> --cow`で再開して
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
    /// 現在のフラグ・`.harness/settings.json`構成から実際に組み立てられるシステムプロンプト
    /// （`harness_core::EnvironmentFacts`のレンダリング結果）をそのまま標準出力へ出して終了する。
    /// 「今モデルは何を知らされているのか」を確認するための読み取り専用診断コマンド
    /// （`run_shell`不安定性調査、Phase4-4）。プロンプトは送らない。
    ///
    /// シェル隔離Tierの選択は通常起動と同じ実プローブを伴う（AppContainerプロファイル作成等の
    /// 副作用がある）。`--fs-allow`/`--force-system-acl`はこのコマンドではサポートしない。
    Prompt,
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

/// `harness cow`サブコマンドの各操作。Windows Tier2a `--cow`固有機能のため、Windows以外は
/// エラーで終了する。単一セッション向けの一覧・適用・破棄は`harness changes`/`apply`/
/// `discard`（`--session`で対象のCoWセッションを自動的に見つける）へ統合済み（Phase 2）
/// ——`list`だけは全workspace横断の棚卸し用として引き続きここに残す。
#[derive(Subcommand)]
pub(crate) enum CowAction {
    /// `%LOCALAPPDATA%\harness\data\cow\`配下にある全upper置き場を一覧表示する。
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

    /// allowlistルール（`tool:pattern`形式、繰り返し指定可）。例: `run_shell:git status*`
    /// パターンが完全ワイルドカード（`*`単体）の場合は`--dangerously-allow`が無いと無視される
    /// （§非対話モード「危険/ワイルドカードは`--dangerously-allow`」）。
    #[arg(long = "allow")]
    allow: Vec<String>,

    /// `--permission-mode accept-all`の使用、および`--allow`の完全ワイルドカード
    /// （`tool:*`）パターンを許可する明示フラグ。無いとどちらも起動時に拒否/無視される
    /// （§非対話モード「危険/ワイルドカードは`--dangerously-allow`」）。
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

    /// 認知レイヤーの段階（`plans/DESIGN-COGNITION.md` §2）。省略時は`settings.json`の
    /// `cognition.default_level`→既定値の順にフォールバックする。
    ///
    /// **現在実行できるのは`off`（素朴ループ）だけ**で、`auto`/`always`を指定すると
    /// 起動時にエラーになる（黙って`off`へ降格しない）。実装マイルストーンは`docs/INDEX.md`。
    #[arg(long = "cognition", value_enum)]
    cognition: Option<CognitionLevelArg>,

    /// ワークスペースルートを明示指定する（省略時はカレントディレクトリ、§非対話モード）。
    #[arg(long = "cwd")]
    cwd: Option<std::path::PathBuf>,

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
    #[arg(long = "live", conflicts_with_all = ["staged", "workspace_commit"])]
    live: bool,

    /// 全書込をステージングし、実FSは`harness apply`まで不変にする。明示指定時のみ
    /// 有効なオプトイン機能で、既定の安全策ではない（§書込ステージング3モード、D-29）。
    /// `--cow`とは互いに排他（マニフェスト方式とCoW方式という別々の書込捕捉機構を
    /// 同時に有効化しない）。
    #[arg(long = "staged", conflicts_with_all = ["live", "workspace_commit", "cow"])]
    staged: bool,

    /// workspace内はステージング→レビュー＆コミット、workspace外は常にsandbox隔離。
    /// 明示指定時のみ有効なオプトイン機能で、既定の安全策ではない
    /// （§書込ステージング3モード、D-29）。`--cow`とは互いに排他（`staged`と同じ理由）。
    #[arg(long = "workspace-commit", conflicts_with_all = ["live", "staged", "cow"])]
    workspace_commit: bool,

    /// シェル隔離Tierの最低要求（M12、`plans/DESIGN-SANDBOX.md` §7 D-03）。指定時は
    /// 自動降格せず、要求を満たせない場合に起動を拒否する。値省略（`--require-sandbox`単体）は
    /// 「書込拘束以上」（Tier3/Tier2a/Tier1/Tier2bでpass、Tier0で拒否）、
    /// `=confidential`は「機密性も要求」（Tier3/Tier2a/Tier2bのみpass）。省略時は
    /// 制約無し（Tier0への自動降格も許容）。
    #[arg(long = "require-sandbox", num_args = 0..=1, default_missing_value = "write-containment")]
    require_sandbox: Option<String>,

    /// Windows専用のTier3（Hyper-V外層AlmaLinux VM + Incus内層コンテナ）を明示的に使う。
    /// VM起動オーバーヘッドが高いため既定では試さない。ゴールデン像VHDXが無い等で起動
    /// できない場合はTier2aへカスケードするが、Tier2aも使えない場合は起動を拒否する。
    #[arg(long = "vm-sandbox", default_value_t = false, conflicts_with = "tier1")]
    vm_sandbox: bool,

    /// Windows Tier1（Restricted Token + 低Integrity Level + Job Object）を明示的に使う。
    /// Tier2aの機密性/network遮断を諦めるオプトインであり、Tier2a preflight失敗時の
    /// 逃がし弁として使う。
    #[arg(long = "tier1", default_value_t = false, conflicts_with = "vm_sandbox")]
    tier1: bool,

    /// Tier3起動をウォームスタート（production checkpointからの`Restore-VMSnapshot`）で行う
    /// （`plans/DESIGN-SANDBOX-VMISOLATION.md` §2.1、既定はfalse=毎回コールドブート）。
    /// `--vm-sandbox`と併用が前提（Tier3自体が無効なら無視される）。初回はテンプレート
    /// provisioningのため通常のコールドブート並みの時間がかかるが、2回目以降のセッションは
    /// 起動レイテンシが大幅に短縮される。固定静的IPの制約上Tier3は元々同時1セッションのみが
    /// 前提のため、ウォームVMはマシン全体で1つに固定され、直列化ロックで排他される。
    #[arg(long = "tier3-warm", default_value_t = false)]
    tier3_warm: bool,

    /// Tier3常駐daemonが同時に受け付けるセッション数の上限（`DESIGN-SANDBOX-VMISOLATION.md`
    /// 「実装確定サマリー」項目6-a）。既定4。**daemon起動時にのみ渡す値**——後から接続する
    /// 2本目以降のセッションがこの上限を書き換えられると意味が無いため、`StartSession`の
    /// ペイロードではなくdaemonプロセスの起動引数として渡す（daemonが既に起動済みの場合、
    /// この値は無視される）。カウント対象はTier3セッション（daemon内の登録簿）のみで、
    /// Tier0/Tier2a/Tier1/Tier2bはこのdaemonへ接続しないため対象外。
    #[arg(long = "tier3-max-sessions", default_value_t = 4)]
    tier3_max_sessions: u8,

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

    /// Tier2a限定のCopy-on-Writeモード（D-30、`plans/AppContainerベース Copy-on-Write
    /// ワークスペース設計書.md`）。指定時、workspaceへのACLをRead/Execute/Traverseのみ
    /// （既定のRead/Write/Execute/DeleteではなくD-13と同じread-onlyマスク）へ切り替え、
    /// `run_shell`子プロセスの書込をworkspace外のCoW upper（`%LOCALAPPDATA%\harness\cow\
    /// <session-id>\`）へRedirector DLLで誘導する。フックが無効・回避されても、ACLが
    /// RO付与済みである限りworkspace本体への書込は`ACCESS_DENIED`でfail-closeする
    /// （フックは境界にしない、D-01不変）。既定（フラグ無指定）はD-29のまま
    /// `Live`＋workspace RWを維持する完全なオプトイン。Tier2a以外では起動を拒否する。
    /// `--staged`/`--workspace-commit`とは互いに排他（マニフェスト方式とCoW方式という
    /// 別々の書込捕捉機構を同時に有効化しない。`--live`とは意味的に矛盾しないため排他にしない）。
    #[arg(long = "cow", default_value_t = false, conflicts_with_all = ["staged", "workspace_commit"])]
    cow: bool,

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

pub mod cow_cmd;
pub mod net_cmd;
pub mod setup;
pub mod startup;
pub mod tier3_cmd;
pub mod workspace_cmd;

pub(crate) use cow_cmd::*;
pub(crate) use net_cmd::*;
pub(crate) use setup::*;
pub(crate) use tier3_cmd::*;
pub(crate) use workspace_cmd::*;

pub use startup::run;
