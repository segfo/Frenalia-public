//! harness-cli: clapエントリ。`plans/DESIGN.md` §非対話（ヘッドレス）モード/§リッチTUI参照。
//!
//! M2時点では `--print` によるAnthropic/OpenAIへのストリーミング呼び出しをサポートする。
//! 受信したテキストデルタをその場でstdoutへ書き出す（トークン逐次表示、§実装マイルストーン M2）。
//! M3で `read_file`/`run_shell` を登録した `ToolRegistry` を使い `run_agent_loop` へ
//! 切り替えた。M4で `PermissionArbiter` を配線し、`--permission-mode`/`--allow` を追加した。
//! 既定モードは `Default`（read-only自動許可、Write/Exec/Networkはヘッドレスにつき自動拒否、
//! §パーミッション「ヘッドレス時」）で、M3までの「一旦allow-all」から「allowlist-or-deny」へ
//! 切り替わる（§実装マイルストーン M4）。M6で`--provider lmstudio`を追加した（実体は
//! `OpenAiProvider::lmstudio()`、`base_url=http://localhost:1234/v1`のopenai-familyプロファイル）。
//! M7で`-p/--print`を省略可にし、省略時は`harness-tui`の対話ループへ切り替える
//! （§実装マイルストーン M7「対話でストリーミング描画 + 承認ダイアログ操作」）。
//! M8で`--output-format text|json|jsonl`（安定json/jsonl出力、実体は`harness_cli::run_headless`）と
//! `--dangerously-allow`（`--permission-mode accept-all`の明示必須化・ワイルドカード
//! `--allow`ルールの明示必須化、§非対話モード「危険/ワイルドカードは`--dangerously-allow`」）を
//! 追加した。M10で`harness_sandbox::SandboxFs`（オーバーレイFS）を配線し、`--live`/`--staged`/
//! `--workspace-commit`（明示時はそのまま採用、省略時はパス毎のgit認識型判定：追跡済み・
//! 変更ゼロ→live、それ以外→headless既定staged/TUI既定workspace_commit）、および
//! `apply`/`changes`/`discard`サブコマンドを追加した。

use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use harness_cli::{run_headless, OutputFormat};
use harness_core::{
    normalize_domain_pattern, LlmProvider, NetProxyConfig, RequireSandbox, StagingConfig,
    StagingMode, ToolCtx,
};
use harness_engine::{
    parse_allowlist_rule, AgentLoopConfig, ConversationState, PermissionArbiter, PermissionMode,
};
use harness_providers::{AnthropicProvider, OpenAiProvider};
use harness_sandbox::{select_tier, ApplyOptions, SandboxFs};
use harness_tools::ToolRegistry;

const DEFAULT_ANTHROPIC_MODEL: &str = "claude-opus-4-8";
const DEFAULT_MAX_TOKENS: u32 = 4096;
const DEFAULT_MAX_TURNS: usize = 25;

#[derive(Clone, Copy, ValueEnum)]
enum ProviderKind {
    Anthropic,
    Openai,
    Lmstudio,
}

impl ProviderKind {
    fn label(self) -> &'static str {
        match self {
            ProviderKind::Anthropic => "anthropic",
            ProviderKind::Openai => "openai",
            ProviderKind::Lmstudio => "lmstudio",
        }
    }
}

#[derive(Clone, Copy, ValueEnum, Default)]
enum PermissionModeArg {
    Plan,
    #[default]
    Default,
    AcceptEdits,
    AcceptAll,
    Deny,
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

/// ステージ済み変更（`harness_sandbox::SandboxFs`のオーバーレイ）を操作するサブコマンド
/// （§オーバーレイFS「レビュー＆コミット」、M10）。
#[derive(Subcommand)]
enum Commands {
    /// ステージ済み変更を一覧表示する。
    Changes {
        /// 対象セッションID（省略時は`.harness/sandbox/`内で最も新しいもの）。
        #[arg(long)]
        session: Option<String>,
        #[arg(long = "output-format", value_enum, default_value_t = OutputFormat::Text)]
        output_format: OutputFormat,
    },
    /// ステージ済み変更を実FSへ選択適用する。
    Apply {
        #[arg(long)]
        session: Option<String>,
        /// 選択適用フィルタ（`*`ワイルドカード対応、例 `src/*`）。省略時は全件対象。
        #[arg(long)]
        only: Option<String>,
        /// `_ext/`（workspace外ターゲット、例 `C:\Windows\x`）の適用を許可する。
        #[arg(long = "dangerously-allow", default_value_t = false)]
        dangerously_allow: bool,
        #[arg(long = "output-format", value_enum, default_value_t = OutputFormat::Text)]
        output_format: OutputFormat,
    },
    /// ステージ済み変更を全て破棄する。
    Discard {
        #[arg(long)]
        session: Option<String>,
    },
    /// fs passthrough allowlist（軸2・D-13）の台帳保守サブコマンド。
    /// `--fs-allow`実行時フラグとは独立の、ユーザグローバル台帳を操作する副コマンド
    /// （`plans/DESIGN-SANDBOX-APPPOLICY.md`補遺、`TIER1A-OPEN-ISSUES.md`項目4）。
    Fs {
        #[command(subcommand)]
        action: FsAction,
    },
    /// Tier3（Hyper-V外層VM + Incusコンテナ）の運用保守サブコマンド
    /// （`plans/DESIGN-SANDBOX-VMISOLATION.md` §2.6 D-24）。
    Tier3 {
        #[command(subcommand)]
        action: Tier3Action,
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
enum Tier3Action {
    /// 前回セッションの孤児VM・差分VHDXを台帳(D-24)+実機照会に基づき撤収する。
    /// 通常は新規Tier3セッション開始直前にdaemonが自動実行するが（`serve_inner`）、
    /// daemonクラッシュ直後の障害調査・手動運用のための明示コマンド。
    Gc,
    /// アクティブセッションが無い場合だけ常駐Tier3 daemonを終了する。
    StopDaemon,
}

/// `harness net`サブコマンドの各操作。
#[derive(Subcommand)]
enum NetAction {
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

/// `harness fs`サブコマンドの各操作。Windows Tier2a固有機能のため、Windows以外では
/// `List`以外はエラーで終了する（台帳自体はクロスプラットフォームのJSONだが、実際のACE
/// 付与・撤収はWin32のSID/ACLに依存するため）。
#[derive(Subcommand)]
enum FsAction {
    /// fs passthrough台帳（ユーザグローバル、D5）を一覧表示する。
    List,
    /// 指定ルートのfs passthroughを撤収する（再walk revoke + 検証パス + 台帳から除去、D3/D4）。
    Revoke { path: PathBuf },
    /// 台帳の全エントリを撤収する。
    RevokeAll,
    /// `target`とその全祖先（ドライブルートまで）へ`FILE_TRAVERSE | FILE_READ_ATTRIBUTES`を
    /// 連鎖付与する（D10連鎖化、`TIER1A-OPEN-ISSUES.md`項目6）。例えば
    /// `C:\Users\<user>\.cargo`を指定すると、`C:\`・`C:\Users`・`C:\Users\<user>`・
    /// `C:\Users\<user>\.cargo`の4ノード全てへ、UAC 1回で付与する。`WRITE_DAC`が要るため
    /// 非管理者では特権分離ヘルパー(D-16)経由でUACを表示する。付与に成功した各ノードは、
    /// 撤収用の別台帳(traverse台帳)へ個別に記録される。
    GrantTraverse {
        target: PathBuf,
        /// 実際には何も書き込まず、付与予定の祖先チェーンと各ノードの既存ACE有無だけを
        /// 表示する（`GetNamedSecurityInfoW`のみ、`SetNamedSecurityInfoW`は一切呼ばない）。
        /// UACも表示されない。プロファイルルート近傍への書込みは実機で病的に遅くなりうる
        /// ため（BUG-011）、本実行の前に対象ノードを確認したい場合に使う。
        #[arg(long = "dry-run", default_value_t = false)]
        dry_run: bool,
    },
    /// `grant-traverse`で付与したtraverse ACEを1件撤収する（非再帰・単一ノード、D10の巻き戻し）。
    /// 注意: `grant-traverse`が連鎖付与した祖先ノード（`C:\Users`等）は、他のpassthroughルートと
    /// **共有されている可能性がある**。この`revoke-traverse`は指定した1ノードだけを撤収するため、
    /// 他の到達性がまだその祖先ノードに依存している場合は、それを壊してしまう。祖先ノードの
    /// 要否を意識せず一括で戻したい場合は`revoke-traverse-all`を使うこと。
    RevokeTraverse { path: PathBuf },
    /// traverse台帳の全エントリを撤収する。`grant-traverse`で付与した箇所を手打ちで覚える
    /// 必要がなく、記録済みの箇所だけを自動で対象にする。
    RevokeTraverseAll,
}

#[derive(Parser)]
#[command(name = "harness")]
struct Cli {
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

    /// 即実FS（オーバーレイ無し）。`--staged`/`--workspace-commit`と併用不可
    /// （§書込ステージング3モード、M10）。
    #[arg(long = "live", conflicts_with_all = ["staged", "workspace_commit"])]
    live: bool,

    /// 全書込をステージングし、実FSは`harness apply`まで不変にする
    /// （headless既定、§書込ステージング3モード）。
    #[arg(long = "staged", conflicts_with_all = ["live", "workspace_commit"])]
    staged: bool,

    /// workspace内はステージング→レビュー＆コミット、workspace外は常にsandbox隔離
    /// （対話TUI既定、§書込ステージング3モード）。
    #[arg(long = "workspace-commit", conflicts_with_all = ["live", "staged"])]
    workspace_commit: bool,

    /// シェル隔離Tierの最低要求（M12、`plans/DESIGN-SANDBOX.md` §7 D-03）。指定時は
    /// 自動降格せず、要求を満たせない場合に起動を拒否する。値省略（`--require-sandbox`単体）は
    /// 「書込拘束以上」（Tier3/Tier2a/Tier1/Tier2bでpass、Tier0で拒否）、
    /// `=confidential`は「機密性も要求」（Tier3/Tier2a/Tier2bのみpass）。省略時は
    /// 制約無し（Tier0への自動降格も許容）。
    #[arg(long = "require-sandbox", num_args = 0..=1, default_missing_value = "write-containment")]
    require_sandbox: Option<String>,

    /// 【非推奨・no-op】Windowsでは`--sandbox`自動カスケード実装ラウンドよりTier2a
    /// （AppContainer）がフラグ無しで既定プローブされるようになったため、このフラグは
    /// 効果を持たない（`plans/DESIGN-SANDBOX.md` §6.3/§7 D-02改訂版参照）。指定した場合は
    /// 起動時に非推奨noteを表示するのみ。Tier3も含めて試したい場合は`--sandbox`を使うこと。
    #[arg(long = "experimental-tier1a", default_value_t = false)]
    experimental_tier2a: bool,

    /// Windows専用の実験的Tier3（Hyper-V外層AlmaLinux VM + Incus内層コンテナ）を試す
    /// （`plans/DESIGN-SANDBOX-VMISOLATION.md`、既定はfalse）。`run_shell`はコンテナ内実行に
    /// 委譲される。ゴールデン像VHDX（`C:\ProgramData\harness\golden-images\almalinux-golden.vhdx`）
    /// が無い等で起動できない場合はTier2aへカスケードし（Tier2aも失敗すればTier1へ）警告する。
    /// 管理者昇格（Hyper-V操作用の常駐デーモン`harness-vmsandboxd`、D-21）を1回要する。
    /// `--sandbox`と同じ効果（便利エイリアス、どちらを指定してもTier3が有効化される）。
    #[arg(long = "experimental-tier3", default_value_t = false)]
    experimental_tier3: bool,

    /// シェル隔離の完全カスケードを有効化する（Windowsのみ意味を持つ: Tier3→Tier2a→Tier1を
    /// 順に試す）。既定はfalse。`--experimental-tier3`と同じ効果を持つ便利エイリアスであり、
    /// どちらか一方を指定すればよい。Tier2a単体は`--sandbox`/`--experimental-tier3`を指定
    /// しなくてもフラグ無しで既定プローブされるため、本フラグが追加で有効化するのは
    /// Tier3（VM）の試行のみ（`plans/DESIGN-SANDBOX.md` §6.3/§7 D-02改訂版）。Linuxでは
    /// Tier2bが既に既定の上限のため事実上ノーオプ。
    #[arg(long = "sandbox", default_value_t = false)]
    sandbox: bool,

    /// Tier3起動をウォームスタート（production checkpointからの`Restore-VMSnapshot`）で行う
    /// （`plans/DESIGN-SANDBOX-VMISOLATION.md` §2.1、既定はfalse=毎回コールドブート）。
    /// `--experimental-tier3`と併用が前提（Tier3自体が無効なら無視される）。初回はテンプレート
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
}

/// `--require-sandbox[=confidential]`の文字列表現を`RequireSandbox`へ変換する
/// （M12、`plans/DESIGN-SANDBOX.md` §7 D-03）。未知の値は`write-containment`扱いにする
/// （clapの`default_missing_value`と揃える安全側フォールバック）。
fn parse_require_sandbox(value: Option<&str>) -> RequireSandbox {
    match value {
        None => RequireSandbox::None,
        Some("confidential") => RequireSandbox::Confidential,
        Some(_) => RequireSandbox::WriteContainment,
    }
}

/// `--live`/`--staged`/`--workspace-commit`から`(explicit, fallback_mode)`を決める。
/// 明示指定が無い場合、`fallback_mode`はgit認識型判定（追跡済み・変更ゼロ→live）で
/// liveと判定されなかったパスにだけ適用される既定モード（headless=Staged/TUI=WorkspaceCommit）。
fn resolve_staging_mode(
    live: bool,
    staged: bool,
    workspace_commit: bool,
    is_headless: bool,
) -> (bool, StagingMode) {
    if live {
        (true, StagingMode::Live)
    } else if staged {
        (true, StagingMode::Staged)
    } else if workspace_commit {
        (true, StagingMode::WorkspaceCommit)
    } else if is_headless {
        (false, StagingMode::Staged)
    } else {
        (false, StagingMode::WorkspaceCommit)
    }
}

/// `session_id`（`session-<id>`形式）に対応する`.harness/sandbox/<id>/`を
/// `workspace_root`からの相対パスで返す。
fn sandbox_dir_for_session(session_id: &str) -> PathBuf {
    PathBuf::from(".harness").join("sandbox").join(session_id)
}

/// `--session <id>`指定が無い場合に`.harness/sandbox/`直下で最も更新日時の新しいものを選ぶ
/// （`apply`/`changes`/`discard`の既定対象）。
fn resolve_sandbox_dir(workspace_root: &Path, session: Option<&str>) -> Option<PathBuf> {
    if let Some(id) = session {
        let stem = id.strip_prefix("session-").unwrap_or(id);
        return Some(sandbox_dir_for_session(&format!("session-{stem}")));
    }
    let base = workspace_root.join(".harness").join("sandbox");
    let mut newest: Option<(String, std::time::SystemTime)> = None;
    let entries = std::fs::read_dir(&base).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if newest.as_ref().is_none_or(|(_, t)| modified > *t) {
            newest = Some((name.to_string(), modified));
        }
    }
    newest.map(|(name, _)| sandbox_dir_for_session(&name))
}

fn build_provider(
    kind: ProviderKind,
    base_url_override: Option<String>,
) -> Result<Box<dyn LlmProvider>, String> {
    // §設定とシークレット: CLIフラグ > env優先、プロジェクト設定に永続化しない・ログに出さない・
    // 起動時fail-fast。
    match kind {
        ProviderKind::Anthropic => {
            let api_key = std::env::var("ANTHROPIC_API_KEY")
                .map_err(|_| "ANTHROPIC_API_KEY is not set".to_string())?;
            match base_url_override.or_else(|| std::env::var("ANTHROPIC_BASE_URL").ok()) {
                Some(base_url) => Ok(Box::new(AnthropicProvider::with_base_url(
                    api_key, base_url,
                ))),
                None => Ok(Box::new(AnthropicProvider::new(api_key))),
            }
        }
        ProviderKind::Openai => {
            // LMStudioは空キー可（§プロバイダ抽象「LMStudioは空キー可」）なので、
            // 実OpenAIと異なり未設定でもfail-fastしない。
            let api_key = std::env::var("OPENAI_API_KEY").unwrap_or_default();
            match base_url_override.or_else(|| std::env::var("OPENAI_BASE_URL").ok()) {
                Some(base_url) => Ok(Box::new(OpenAiProvider::with_base_url(api_key, base_url))),
                None => Ok(Box::new(OpenAiProvider::new(api_key))),
            }
        }
        // §設定「LMStudio は単に base_url=http://localhost:1234/v1 の openai-family
        // プロファイル」。`--base-url`/`OPENAI_API_KEY`/`OPENAI_BASE_URL`での上書きも許す。
        ProviderKind::Lmstudio => {
            let api_key = std::env::var("OPENAI_API_KEY").unwrap_or_default();
            match base_url_override.or_else(|| std::env::var("OPENAI_BASE_URL").ok()) {
                Some(base_url) => Ok(Box::new(OpenAiProvider::with_base_url(api_key, base_url))),
                None => Ok(Box::new(OpenAiProvider::lmstudio())),
            }
        }
    }
}

/// `--resume <id>`/`--continue`/新規のいずれかで`SessionStore`を用意する
/// （M9、§非対話モード「JSONL 追記型セッション永続化」）。`resume`は値省略（空文字列、
/// ピッカー要求）を渡さない前提（呼び出し側で分岐済み）。
fn resolve_session(
    sessions_dir: &std::path::Path,
    resume: Option<&str>,
    continue_session: bool,
) -> Result<harness_engine::SessionStore, String> {
    if let Some(id) = resume {
        let path = harness_engine::SessionStore::resolve_path(sessions_dir, id);
        if !path.exists() {
            return Err(format!(
                "no session found for --resume {id} ({})",
                path.display()
            ));
        }
        return Ok(harness_engine::SessionStore::open(path));
    }
    if continue_session {
        return harness_engine::SessionStore::resume_latest(sessions_dir)
            .map_err(|e| format!("failed to find latest session: {e}"))?
            .ok_or_else(|| "no existing session to --continue".to_string());
    }
    harness_engine::SessionStore::create_new(sessions_dir)
        .map_err(|e| format!("failed to create session file: {e}"))
}

/// `--list-sessions`の出力レコード（`SessionSummary`はシリアライズ非対応のため、
/// `--output-format json/jsonl`用にここでJSON化可能な形へ写す）。
#[derive(serde::Serialize)]
struct SessionListEntry {
    id: String,
    modified_unix_millis: u128,
    message_count: usize,
    first_prompt: String,
}

impl From<&harness_engine::SessionSummary> for SessionListEntry {
    fn from(s: &harness_engine::SessionSummary) -> Self {
        Self {
            id: s.id.clone(),
            modified_unix_millis: s
                .modified
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            message_count: s.message_count,
            first_prompt: s.first_prompt.clone(),
        }
    }
}

fn print_session_list(summaries: &[harness_engine::SessionSummary], format: OutputFormat) {
    let entries: Vec<SessionListEntry> = summaries.iter().map(SessionListEntry::from).collect();
    match format {
        OutputFormat::Json => {
            if let Ok(s) = serde_json::to_string(&entries) {
                println!("{s}");
            }
        }
        OutputFormat::Jsonl => {
            for entry in &entries {
                if let Ok(s) = serde_json::to_string(entry) {
                    println!("{s}");
                }
            }
        }
        OutputFormat::Text => {
            if entries.is_empty() {
                println!("(no saved sessions)");
            }
            for entry in &entries {
                println!(
                    "{:<16} {:>4} msgs  {}",
                    entry.id, entry.message_count, entry.first_prompt
                );
            }
        }
    }
}

fn net_audit_path(
    workspace_root: &Path,
    session: Option<&str>,
    explicit_path: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(path) = explicit_path {
        return Some(path.to_path_buf());
    }
    resolve_sandbox_dir(workspace_root, session)
        .map(|dir| workspace_root.join(dir).join("net-audit.jsonl"))
}

fn validate_and_merge_net_allow_domains(
    net_proxy: &mut NetProxyConfig,
    cli_domains: &[String],
) -> Result<(), String> {
    let mut normalized = Vec::new();
    for domain in &net_proxy.allow_domains {
        let domain = normalize_domain_pattern(domain)?;
        if !normalized.contains(&domain) {
            normalized.push(domain);
        }
    }
    for domain in cli_domains {
        let domain = normalize_domain_pattern(domain)?;
        if !normalized.contains(&domain) {
            normalized.push(domain);
        }
    }
    net_proxy.allow_domains = normalized;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetLoopbackPorts {
    tcp: Vec<u16>,
    udp: Vec<u16>,
}

fn sorted_unique_ports(mut ports: Vec<u16>) -> Vec<u16> {
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn net_loopback_ports_for_agents(
    proxy_addr: Option<SocketAddr>,
    fake_dns_addr: Option<SocketAddr>,
) -> NetLoopbackPorts {
    let mut tcp = Vec::new();
    let mut udp = Vec::new();
    if let Some(addr) = proxy_addr {
        tcp.push(addr.port());
    }
    if let Some(addr) = fake_dns_addr {
        tcp.push(addr.port());
        udp.push(addr.port());
    }
    NetLoopbackPorts {
        tcp: sorted_unique_ports(tcp),
        udp: sorted_unique_ports(udp),
    }
}

fn event_string<'a>(event: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    event.get(key).and_then(|v| v.as_str())
}

fn event_bool(event: &serde_json::Value, key: &str) -> Option<bool> {
    event.get(key).and_then(|v| v.as_bool())
}

fn event_u64(event: &serde_json::Value, key: &str) -> Option<u64> {
    event.get(key).and_then(|v| v.as_u64())
}

fn filter_net_audit_events(
    events: Vec<serde_json::Value>,
    kind: Option<&str>,
    deny_only: bool,
) -> Vec<serde_json::Value> {
    events
        .into_iter()
        .filter(|event| {
            if let Some(kind) = kind {
                if event_string(event, "kind") != Some(kind) {
                    return false;
                }
            }
            if deny_only && event_bool(event, "allowed") != Some(false) {
                return false;
            }
            true
        })
        .collect()
}

fn format_net_audit_text(events: &[serde_json::Value]) -> String {
    if events.is_empty() {
        return "(no matching net audit events)\n".to_string();
    }
    let mut output = String::new();
    for event in events {
        let kind = event_string(event, "kind").unwrap_or("unknown");
        let protocol = event_string(event, "protocol").unwrap_or("-");
        let allowed = event_bool(event, "allowed")
            .map(|v| if v { "ALLOW" } else { "DENY" })
            .unwrap_or("-");
        let reason = event_string(event, "reason").unwrap_or("-");
        let host = event_string(event, "host")
            .or_else(|| event_string(event, "remote_host"))
            .unwrap_or("-");
        let port = event_u64(event, "port")
            .or_else(|| event_u64(event, "remote_port"))
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".to_string());
        let remote = event_string(event, "remote_addr").unwrap_or("-");
        output.push_str(&format!(
            "{kind:<8} {protocol:<8} {allowed:<5} {host:<40} {port:<5} {remote:<39} {reason}\n"
        ));
    }
    output
}

fn format_net_audit_output(events: &[serde_json::Value], output_format: OutputFormat) -> String {
    match output_format {
        OutputFormat::Json => serde_json::to_string(events).unwrap_or_else(|_| "[]".to_string()),
        OutputFormat::Jsonl => {
            let mut output = String::new();
            for event in events {
                if let Ok(s) = serde_json::to_string(event) {
                    output.push_str(&s);
                    output.push('\n');
                }
            }
            output
        }
        OutputFormat::Text => format_net_audit_text(events),
    }
}

fn run_net_subcommand(action: NetAction, workspace_root: &Path) -> ExitCode {
    match action {
        NetAction::Audit {
            session,
            path,
            kind,
            deny_only,
            output_format,
        } => {
            let Some(path) = net_audit_path(workspace_root, session.as_deref(), path.as_deref())
            else {
                eprintln!("no sandbox session found under .harness/sandbox/ (no net audit log)");
                return ExitCode::FAILURE;
            };
            let text = match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(e) => {
                    eprintln!("failed to read net audit log {}: {e}", path.display());
                    return ExitCode::FAILURE;
                }
            };
            let mut events = Vec::new();
            for (idx, line) in text.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let event = match serde_json::from_str::<serde_json::Value>(line) {
                    Ok(event) => event,
                    Err(e) => {
                        eprintln!(
                            "failed to parse net audit log {} line {}: {e}",
                            path.display(),
                            idx + 1
                        );
                        return ExitCode::FAILURE;
                    }
                };
                events.push(event);
            }
            let events = filter_net_audit_events(events, kind.as_deref(), deny_only);

            print!("{}", format_net_audit_output(&events, output_format));
            ExitCode::SUCCESS
        }
    }
}

fn resolve_model(model: Option<String>, kind: ProviderKind) -> Result<String, String> {
    match (model, kind) {
        (Some(m), _) => Ok(m),
        (None, ProviderKind::Anthropic) => Ok(DEFAULT_ANTHROPIC_MODEL.to_string()),
        (None, ProviderKind::Openai) => {
            Err("--model is required when --provider openai is used".into())
        }
        (None, ProviderKind::Lmstudio) => {
            Err("--model is required when --provider lmstudio is used".into())
        }
    }
}

/// `harness apply`のJSON出力（`--output-format json`）。
#[derive(serde::Serialize)]
struct ApplyReportJson {
    applied: Vec<String>,
    conflicts: Vec<String>,
    ext_blocked: Vec<String>,
    hard_denied: Vec<String>,
}

/// `harness prompt`: 現在のフラグ・`.harness/settings.json`構成から実際に組み立てられる
/// システムプロンプト（`harness_core::EnvironmentFacts`のレンダリング結果）をそのまま
/// 標準出力へ出す（Phase4-4、`run_shell`不安定性調査）。プロバイダ資格情報を一切必要としない
/// （プロンプトは送らない、`run_sandbox_subcommand`と同じ非対話原則）。
///
/// シェル隔離Tierの選択（`select_tier`）は通常起動と同じ実プローブ（Windows AppContainer
/// プロファイル作成等）を伴う点に注意する。これは意図的な設計判断: プローブを省略した
/// 推測値ではなく「実際に送られる」プロンプトを見せるため。`--fs-allow`/`--force-system-acl`
/// （fs passthrough allowlist）はUAC連鎖・台帳記録を伴う複雑な経路のため、この診断コマンドでは
/// サポートしない（指定されていれば無視する旨を1行警告する）。
fn run_prompt_subcommand(cli: &Cli, workspace_root: &Path) -> ExitCode {
    let settings = harness_config::Settings::load(workspace_root);

    let (explicit, staging_mode) = resolve_staging_mode(
        cli.live,
        cli.staged,
        cli.workspace_commit,
        cli.print.is_some(),
    );
    let read_scope = settings
        .read
        .clone()
        .unwrap_or_default()
        .to_read_scope_config();

    let mut net_proxy = settings
        .net
        .clone()
        .unwrap_or_default()
        .to_net_proxy_config();
    if let Err(e) = validate_and_merge_net_allow_domains(&mut net_proxy, &cli.net_allow_domain) {
        eprintln!("error: invalid network domain policy: {e}");
        return ExitCode::FAILURE;
    }
    let mut net_app = settings.net.clone().unwrap_or_default().to_net_app_policy();
    for app in &cli.net_allow_app {
        if !net_app.allow_apps.contains(app) {
            net_app.allow_apps.push(app.clone());
        }
    }

    if !cli.fs_allow.is_empty() || cli.force_system_acl {
        eprintln!(
            "note: --fs-allow/--force-system-acl are ignored by `harness prompt` (fs passthrough \
             is not probed by this diagnostic command); the printed prompt reflects read-scope/\
             net settings only."
        );
    }

    let require_sandbox = parse_require_sandbox(cli.require_sandbox.as_deref());
    let opt_in_tier3 = cli.sandbox || cli.experimental_tier3;
    let shell_tier = match select_tier(require_sandbox, workspace_root, opt_in_tier3, &[], None) {
        Ok(sel) => sel,
        Err(e) => {
            eprintln!("error: shell tier selection failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let ctx = ToolCtx {
        workspace_root: workspace_root.to_path_buf(),
        staging: StagingConfig {
            mode: staging_mode,
            explicit,
            sandbox_dir: None,
        },
        read_scope,
        shell_sees_staged_writes: shell_sees_staged_writes(&shell_tier),
        shell_tier,
        net_proxy,
        net_app,
        vm_sandbox: None,
    };
    for block in harness_engine::system_blocks_for(&ctx) {
        println!("{}", block.text);
    }
    ExitCode::SUCCESS
}

fn shell_sees_staged_writes(shell_tier: &harness_core::ShellTierSelection) -> bool {
    #[cfg(windows)]
    {
        use harness_sandbox::vmsandbox::{VmSandboxConfig, WorkspaceShareMode};

        shell_tier.tier == harness_core::ShellTier::Tier3
            && VmSandboxConfig::default().workspace_share_mode == WorkspaceShareMode::Cifs
    }
    #[cfg(not(windows))]
    {
        let _ = shell_tier;
        false
    }
}

/// `apply`/`changes`/`discard`サブコマンドを処理する。プロバイダ資格情報を一切必要としない
/// （§非対話モード、プロンプトは一切送らない）。
fn run_sandbox_subcommand(cmd: Commands, workspace_root: &Path) -> ExitCode {
    let (session, output_format_and_kind) = match &cmd {
        Commands::Changes {
            session,
            output_format,
        } => (session.clone(), Some(*output_format)),
        Commands::Apply {
            session,
            output_format,
            ..
        } => (session.clone(), Some(*output_format)),
        Commands::Discard { session } => (session.clone(), None),
        // `Fs`/`Tier3`/`Prompt`はmain()側でそれぞれ専用の振り分け先へ処理済みで、ここには
        // 到達しない（workspace sandboxのstaging設定を一切必要としないため、`SandboxFs`を開く
        // このパスとは責務が別）。
        Commands::Fs { .. } => {
            unreachable!("Commands::Fs is dispatched before run_sandbox_subcommand")
        }
        Commands::Tier3 { .. } => {
            unreachable!("Commands::Tier3 is dispatched before run_sandbox_subcommand")
        }
        Commands::Net { .. } => {
            unreachable!("Commands::Net is dispatched before run_sandbox_subcommand")
        }
        Commands::Prompt => {
            unreachable!("Commands::Prompt is dispatched before run_sandbox_subcommand")
        }
    };

    let Some(sandbox_dir) = resolve_sandbox_dir(workspace_root, session.as_deref()) else {
        eprintln!("no staged sandbox found under .harness/sandbox/ (nothing to show)");
        return ExitCode::FAILURE;
    };
    let staging = StagingConfig {
        mode: StagingMode::Staged,
        explicit: true,
        sandbox_dir: Some(sandbox_dir),
    };
    let fs = match SandboxFs::open(workspace_root, &staging) {
        Ok(fs) => fs,
        Err(e) => {
            eprintln!("failed to open sandbox: {e}");
            return ExitCode::FAILURE;
        }
    };

    match cmd {
        Commands::Changes { .. } => {
            let changes = match fs.change_set() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("failed to read changes: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match output_format_and_kind.unwrap_or_default() {
                OutputFormat::Json => {
                    if let Ok(s) = serde_json::to_string(&changes) {
                        println!("{s}");
                    }
                }
                OutputFormat::Jsonl => {
                    for c in &changes {
                        if let Ok(s) = serde_json::to_string(c) {
                            println!("{s}");
                        }
                    }
                }
                OutputFormat::Text => {
                    if changes.is_empty() {
                        println!("(no staged changes)");
                    }
                    for c in &changes {
                        println!("{:?}\t{:?}\t{}", c.op, c.target, c.path);
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Commands::Apply {
            only,
            dangerously_allow,
            ..
        } => {
            let report = match fs.apply(&ApplyOptions {
                only_glob: only.as_deref(),
                only_paths: None,
                allow_ext: dangerously_allow,
            }) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("apply failed: {e}");
                    return ExitCode::FAILURE;
                }
            };
            // hard_deniedもconflicts/ext_blocked同様「apply未完了、要注意」の一種として
            // 非ゼロ終了コードに含める（D-05: 設定注入パスは絶対に解除しない）。
            let has_conflicts_or_blocked = !report.conflicts.is_empty()
                || !report.ext_blocked.is_empty()
                || !report.hard_denied.is_empty();
            match output_format_and_kind.unwrap_or_default() {
                OutputFormat::Json => {
                    let json = ApplyReportJson {
                        applied: report.applied,
                        conflicts: report.conflicts,
                        ext_blocked: report.ext_blocked,
                        hard_denied: report.hard_denied,
                    };
                    if let Ok(s) = serde_json::to_string(&json) {
                        println!("{s}");
                    }
                }
                OutputFormat::Jsonl | OutputFormat::Text => {
                    for p in &report.applied {
                        println!("applied: {p}");
                    }
                    for p in &report.conflicts {
                        println!("conflict (baseline mismatch, not applied): {p}");
                    }
                    for p in &report.ext_blocked {
                        println!("blocked (out-of-workspace, needs --dangerously-allow): {p}");
                    }
                    for p in &report.hard_denied {
                        println!("hard-denied (config-injection path, D-05): {p}");
                    }
                }
            }
            if has_conflicts_or_blocked {
                ExitCode::from(4)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Discard { .. } => match fs.discard() {
            Ok(()) => {
                println!("discarded staged changes");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("discard failed: {e}");
                ExitCode::FAILURE
            }
        },
        Commands::Fs { .. } => {
            unreachable!("Commands::Fs is dispatched before run_sandbox_subcommand")
        }
        Commands::Tier3 { .. } => {
            unreachable!("Commands::Tier3 is dispatched before run_sandbox_subcommand")
        }
        Commands::Net { .. } => {
            unreachable!("Commands::Net is dispatched before run_sandbox_subcommand")
        }
        Commands::Prompt => {
            unreachable!("Commands::Prompt is dispatched before run_sandbox_subcommand")
        }
    }
}

/// fs passthrough台帳（D5、ユーザグローバル、`directories`設定ディレクトリ配下）の1エントリ。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct FsLedgerEntry {
    path: String,
    writable: bool,
    granted_at_unix_secs: u64,
    /// `--force-system-acl`（D-19）で`SeRestorePrivilege`を使って強制付与したか。
    /// 撤収時も同じ特権が要るため記録する。旧台帳（このフィールド欠落）は`false`扱い（後方互換）。
    #[serde(default)]
    forced: bool,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct FsLedger {
    entries: Vec<FsLedgerEntry>,
}

/// traverse台帳（D10の巻き戻し用、`fs-passthrough-ledger.json`とは別ファイル）の1エントリ。
/// `grant-traverse`は`writable`という概念を持たない（付与するアクセス権は常に
/// `FILE_TRAVERSE | FILE_READ_ATTRIBUTES`固定）ため、`FsLedgerEntry`とは別の小さな型にする。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TraverseLedgerEntry {
    path: String,
    granted_at_unix_secs: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct TraverseLedger {
    entries: Vec<TraverseLedgerEntry>,
}

/// 台帳ファイルのパス（`%APPDATA%\harness\config\fs-passthrough-ledger.json`相当、`harness-config`の
/// `user_settings_path`と同じ土台）。横断的な穴を1台帳に集約し、どのプロジェクトからでも
/// 全撤収できるようにする（D5）。
fn fs_ledger_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "harness")
        .map(|d| d.config_dir().join("fs-passthrough-ledger.json"))
}

/// traverse台帳ファイルのパス。`fs-passthrough-ledger.json`と意味が異なる記録
/// （ドライブルート/祖先ディレクトリへのtraverse付与）を混在させないため、別ファイルにする。
fn traverse_ledger_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "harness")
        .map(|d| d.config_dir().join("traverse-grant-ledger.json"))
}

/// 台帳が存在しない/読めない/パースできない場合は空扱い（`harness-config`の設定読み込みと
/// 同じfail-open方針、起動を止めない）。
fn load_fs_ledger() -> FsLedger {
    let Some(path) = fs_ledger_path() else {
        return FsLedger::default();
    };
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => FsLedger::default(),
    }
}

fn load_traverse_ledger() -> TraverseLedger {
    let Some(path) = traverse_ledger_path() else {
        return TraverseLedger::default();
    };
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => TraverseLedger::default(),
    }
}

/// 台帳ファイルへの書込を、誤削除防止の2層（read-only属性＋`.bak`バックアップ）を通して行う
/// 共通ヘルパ。エージェント（コーディングツール）による無関係な一括クリーンアップの巻き込みで
/// 台帳が消えると、実際に付与済みのACE（`C:\`等の実システム変更）を追跡する手段が失われ、
/// 「付けたはずだが記録が無い」孤立した穴が残ってしまうため、次の2つを行う。
/// 1. 上書き前に既存ファイルのread-onlyを解除し、`.bak`へコピーしておく（万一の復元用）。
/// 2. 書込後にread-only属性を付与する（`-Force`無しの素の`rm`/`Remove-Item`による削除を防ぐ。
///    確信犯的な`-Force`削除までは防げない、という限界を持つ多層防御の1枚）。
fn write_ledger_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if path.exists() {
        set_file_readonly(path, false);
        let backup_path = path.with_extension("json.bak");
        let _ = std::fs::copy(path, &backup_path);
    }
    if std::fs::write(path, contents).is_ok() {
        set_file_readonly(path, true);
    }
}

/// `path`のread-only属性を切り替える（Windowsの`attrib +R`/`-R`相当）。誤削除防止の一環
/// （`write_ledger_file`参照）。非Windowsでは`set_readonly`の意味論が異なり
/// （chmodのworld-writable相当になり得る）有効な防御にならないため何もしない
/// （`readonly`がリテラル`false`でないためclippyの`permissions_set_readonly_false`は
/// 誤検知しないが、cfg分岐でも意図を明確にする）。
#[cfg(windows)]
fn set_file_readonly(path: &Path, readonly: bool) {
    if let Ok(metadata) = std::fs::metadata(path) {
        let mut perms = metadata.permissions();
        perms.set_readonly(readonly);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(windows))]
fn set_file_readonly(_path: &Path, _readonly: bool) {}

fn save_fs_ledger(ledger: &FsLedger) {
    let Some(path) = fs_ledger_path() else {
        return;
    };
    if let Ok(s) = serde_json::to_string_pretty(ledger) {
        write_ledger_file(&path, &s);
    }
}

fn save_traverse_ledger(ledger: &TraverseLedger) {
    let Some(path) = traverse_ledger_path() else {
        return;
    };
    if let Ok(s) = serde_json::to_string_pretty(ledger) {
        write_ledger_file(&path, &s);
    }
}

/// `--fs-allow`でTier2a preflightが実際にACE付与を試みたルートを台帳へ記録する（D2/D3）。
/// 同一パスは上書き（冪等）。ACE自体は「付けっぱなし」（D2）だが、台帳があるので後から
/// `harness fs revoke`/`revoke-all`で一括撤収できる。
fn record_fs_passthrough_grant(path: &Path, writable: bool, forced: bool) {
    let mut ledger = load_fs_ledger();
    let path_str = path.to_string_lossy().into_owned();
    let granted_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Some(entry) = ledger.entries.iter_mut().find(|e| e.path == path_str) {
        entry.writable = writable;
        entry.granted_at_unix_secs = granted_at;
        entry.forced = forced;
    } else {
        ledger.entries.push(FsLedgerEntry {
            path: path_str,
            writable,
            granted_at_unix_secs: granted_at,
            forced,
        });
    }
    save_fs_ledger(&ledger);
}

fn remove_fs_passthrough_grant(path: &Path) {
    let mut ledger = load_fs_ledger();
    let path_str = path.to_string_lossy().into_owned();
    ledger.entries.retain(|e| e.path != path_str);
    save_fs_ledger(&ledger);
}

/// `grant-traverse`が実際にACE付与を試みたパスをtraverse台帳へ記録する（D10の巻き戻し用）。
/// `record_fs_passthrough_grant`と同じ冪等upsert。
fn record_traverse_grant(path: &Path) {
    let mut ledger = load_traverse_ledger();
    let path_str = path.to_string_lossy().into_owned();
    let granted_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Some(entry) = ledger.entries.iter_mut().find(|e| e.path == path_str) {
        entry.granted_at_unix_secs = granted_at;
    } else {
        ledger.entries.push(TraverseLedgerEntry {
            path: path_str,
            granted_at_unix_secs: granted_at,
        });
    }
    save_traverse_ledger(&ledger);
}

fn remove_traverse_grant(path: &Path) {
    let mut ledger = load_traverse_ledger();
    let path_str = path.to_string_lossy().into_owned();
    ledger.entries.retain(|e| e.path != path_str);
    save_traverse_ledger(&ledger);
}

/// `harness fs`サブコマンドのディスパッチ（プロバイダ資格情報・workspace sandboxのいずれも
/// 必要としない、`run_sandbox_subcommand`とは独立のパス）。
/// `harness tier3`サブコマンドの処理本体（A9、D-24）。
#[cfg(windows)]
fn run_tier3_subcommand(action: Tier3Action) -> ExitCode {
    match action {
        Tier3Action::Gc => match harness_sandbox::vmsandboxd::run_gc_only() {
            Ok(reaped) => {
                if reaped.is_empty() {
                    println!("(no orphaned Tier3 VMs found)");
                } else {
                    println!("reaped orphaned Tier3 VMs:");
                    for vm_name in &reaped {
                        println!("  {vm_name}");
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("tier3 gc failed: {e}");
                ExitCode::FAILURE
            }
        },
        Tier3Action::StopDaemon => {
            match harness_sandbox::vmsandboxd::stop_resident_daemon_if_idle() {
                Ok(true) => {
                    println!("Tier3 daemon is stopping");
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    println!("(Tier3 daemon is not running)");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("tier3 stop-daemon failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

#[cfg(not(windows))]
fn run_tier3_subcommand(_action: Tier3Action) -> ExitCode {
    eprintln!("error: Tier3 (Hyper-V VM isolation) is Windows-only");
    ExitCode::FAILURE
}

fn run_fs_subcommand(action: FsAction) -> ExitCode {
    match action {
        FsAction::List => {
            let ledger = load_fs_ledger();
            println!("=== fs passthrough (--fs-allow) ===");
            if ledger.entries.is_empty() {
                println!("(none)");
            }
            for e in &ledger.entries {
                println!(
                    "{}\t{}{}\tgranted_at_unix={}",
                    e.path,
                    if e.writable { "rw" } else { "ro" },
                    if e.forced { " [forced]" } else { "" },
                    e.granted_at_unix_secs
                );
            }
            let traverse_ledger = load_traverse_ledger();
            println!("=== traverse grants (grant-traverse) ===");
            if traverse_ledger.entries.is_empty() {
                println!("(none)");
            }
            for e in &traverse_ledger.entries {
                println!("{}\tgranted_at_unix={}", e.path, e.granted_at_unix_secs);
            }
            ExitCode::SUCCESS
        }
        FsAction::Revoke { path } => fs_revoke_one(&path),
        FsAction::RevokeAll => fs_revoke_all(),
        FsAction::GrantTraverse { target, dry_run } => {
            if dry_run {
                fs_grant_traverse_preview(&target)
            } else {
                fs_grant_traverse(&target)
            }
        }
        FsAction::RevokeTraverse { path } => fs_revoke_traverse_one(&path),
        FsAction::RevokeTraverseAll => {
            let ledger = load_traverse_ledger();
            if ledger.entries.is_empty() {
                println!("(no traverse grants recorded)");
                return ExitCode::SUCCESS;
            }
            let mut any_failed = false;
            for entry in ledger.entries.clone() {
                if fs_revoke_traverse_one(&PathBuf::from(&entry.path)) != ExitCode::SUCCESS {
                    any_failed = true;
                }
            }
            if any_failed {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}

/// `path`のfs passthrough ACEを、本体プロセス内（非管理者）で撤収を試み、3値で結果を返す
/// （D3: 再walk revoke、D4: 剥離後検証パス）。ユーザー所有パス（workspace・`%USERPROFILE%`配下等）は
/// ここで完結する。システム保護パス（`BUG-015`でヘルパー経由により付与できるようになったパス）は
/// root自体を撤収できず`Failed`になる（呼び出し側がヘルパーへエスカレーションする）。
/// `RootClearedDescendantsBlocked`は「rootは撤収できたが一部の子孫（TrustedInstaller所有等）に
/// ACEが残る」ケースで、孤立ACEにはならないため台帳から除去してよい（BUG-016のrevoke非対称の解消）。
/// `forced`（`--force-system-acl`で付与したエントリ）なら`SeRestorePrivilege`を有効化した状態で
/// 撤収する。非管理者プロセスでは特権を有効化できず`revoke_passthrough`が特権無しで走る
/// （システム保護パスならroot撤収に失敗し`Failed`→ヘルパーへエスカレーション）。管理者プロセス
/// （`is_elevated`）なら特権が有効化され、TrustedInstaller所有ノードも含めて撤収できる。
#[cfg(windows)]
fn revoke_passthrough_outcome(
    path: &Path,
    sid: &harness_sandbox::win_appcontainer::OwnedContainerSid,
    forced: bool,
) -> harness_sandbox::win_appcontainer::RevokeOutcome {
    if forced {
        harness_sandbox::win_appcontainer::with_restore_privilege(|| {
            harness_sandbox::win_appcontainer::revoke_passthrough(path, sid.as_psid())
        })
    } else {
        harness_sandbox::win_appcontainer::revoke_passthrough(path, sid.as_psid())
    }
}

/// 撤収対象パスが台帳で`forced`（`--force-system-acl`）記録かを引く（無ければ`false`）。
#[cfg(windows)]
fn ledger_forced_flag(path: &Path) -> bool {
    let target = path.to_string_lossy();
    load_fs_ledger()
        .entries
        .iter()
        .any(|e| e.path == target && e.forced)
}

/// 指定パスのfs passthrough ACEを撤収する（`BUG-015`の裏対称: grant側と同じく
/// 「本体内試行→ヘルパーへエスカレーション」の2段構え）。成功時のみ台帳から除去する
/// （検証パスが残件を見つけた場合は台帳に残し、次回再試行できるようにする）。
#[cfg(windows)]
fn fs_revoke_one(path: &Path) -> ExitCode {
    let sid = match harness_sandbox::win_appcontainer::ensure_profile(
        harness_sandbox::win_appcontainer::CONTAINER_NAME,
    ) {
        Ok(sid) => sid,
        Err(e) => {
            eprintln!("failed to resolve sandbox SID: {e}");
            return ExitCode::FAILURE;
        }
    };
    let forced = ledger_forced_flag(path);
    use harness_sandbox::win_appcontainer::RevokeOutcome;
    match revoke_passthrough_outcome(path, &sid, forced) {
        RevokeOutcome::FullyRevoked => {
            remove_fs_passthrough_grant(path);
            println!("revoked: {}", path.display());
            return ExitCode::SUCCESS;
        }
        RevokeOutcome::RootClearedDescendantsBlocked => {
            remove_fs_passthrough_grant(path);
            println!(
                "revoked: {} (root and all writable nodes cleared; some TrustedInstaller-owned \
                 descendants keep ACEs beyond our control -- not orphaned, entry removed from ledger)",
                path.display()
            );
            return ExitCode::SUCCESS;
        }
        RevokeOutcome::Failed => {}
    }

    // 本体内で完結しなかった（システム保護パスの可能性）→特権分離ヘルパーへ委譲する。
    if harness_sandbox::privhelper::is_elevated() {
        // 本体が既に管理者（§5.3、fs_grant_traverse_directと同じ考え方）: 直接再試行する。
        match revoke_passthrough_outcome(path, &sid, forced) {
            RevokeOutcome::FullyRevoked | RevokeOutcome::RootClearedDescendantsBlocked => {
                remove_fs_passthrough_grant(path);
                println!("revoked: {}", path.display());
                return ExitCode::SUCCESS;
            }
            RevokeOutcome::Failed => {
                eprintln!(
                    "revoke failed for {} (already running elevated)",
                    path.display()
                );
                return ExitCode::FAILURE;
            }
        }
    }
    let revoke_entry = harness_sandbox::privhelper::FsAllowRevoke {
        path: path.to_path_buf(),
        forced,
    };
    match harness_sandbox::privhelper::run_privileged_revoke_fs_allow(vec![revoke_entry]) {
        Ok((revoked, root_cleared, failures)) => {
            let cleared = revoked.iter().chain(root_cleared.iter()).any(|p| p == path);
            // 撤収できたパス（root_cleared含む）は台帳から除去する。
            for p in revoked.iter().chain(root_cleared.iter()) {
                remove_fs_passthrough_grant(p);
            }
            if failures.is_empty() && cleared {
                println!(
                    "revoked via privilege-separation helper (UAC, one-time): {}",
                    path.display()
                );
                ExitCode::SUCCESS
            } else {
                eprintln!(
                    "revoke incomplete for {} via privilege-separation helper:",
                    path.display()
                );
                for (p, reason) in &failures {
                    eprintln!("  {} : {reason}", p.display());
                }
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("revoke failed for {}: {e}", path.display());
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn fs_revoke_one(_path: &Path) -> ExitCode {
    eprintln!("error: fs passthrough revoke is Windows-only (Tier2a specific)");
    ExitCode::FAILURE
}

/// 台帳の全fs passthroughエントリを撤収する。`fs_revoke_one`をループで呼ぶと
/// システム保護パスの数だけUACが出かねないため、まず全エントリを本体内で試行し（UAC無し）、
/// 残ったパスだけを**1回のヘルパー要求へまとめて**エスカレーションする（`BUG-015`決定：
/// 起動あたりUAC最小化、grant側`preflight`と同じ考え方）。
#[cfg(windows)]
fn fs_revoke_all() -> ExitCode {
    let ledger = load_fs_ledger();
    if ledger.entries.is_empty() {
        println!("(no fs passthrough entries)");
        return ExitCode::SUCCESS;
    }
    let sid = match harness_sandbox::win_appcontainer::ensure_profile(
        harness_sandbox::win_appcontainer::CONTAINER_NAME,
    ) {
        Ok(sid) => sid,
        Err(e) => {
            eprintln!("failed to resolve sandbox SID: {e}");
            return ExitCode::FAILURE;
        }
    };

    use harness_sandbox::win_appcontainer::RevokeOutcome;
    // 本体内で撤収しきれなかったパスを`forced`情報付きで集める（ヘルパーで撤収時、forcedなら
    // `SeRestorePrivilege`を有効化して撤収するため）。
    let mut remaining: Vec<harness_sandbox::privhelper::FsAllowRevoke> = Vec::new();
    for entry in &ledger.entries {
        let path = PathBuf::from(&entry.path);
        match revoke_passthrough_outcome(&path, &sid, entry.forced) {
            RevokeOutcome::FullyRevoked => {
                remove_fs_passthrough_grant(&path);
                println!("revoked: {}", path.display());
            }
            RevokeOutcome::RootClearedDescendantsBlocked => {
                remove_fs_passthrough_grant(&path);
                println!(
                    "revoked: {} (root cleared; TrustedInstaller-owned descendants beyond our \
                     control -- not orphaned)",
                    path.display()
                );
            }
            RevokeOutcome::Failed => remaining.push(harness_sandbox::privhelper::FsAllowRevoke {
                path,
                forced: entry.forced,
            }),
        }
    }

    if remaining.is_empty() {
        return ExitCode::SUCCESS;
    }

    let escalated: Result<harness_sandbox::privhelper::FsAllowRevokeOutcome, String> =
        if harness_sandbox::privhelper::is_elevated() {
            // 本体が既に管理者: 直接再試行する（ヘルパーもUACも不要）。
            let mut revoked = Vec::new();
            let mut root_cleared = Vec::new();
            let mut failures = Vec::new();
            for entry in &remaining {
                match revoke_passthrough_outcome(&entry.path, &sid, entry.forced) {
                    RevokeOutcome::FullyRevoked => revoked.push(entry.path.clone()),
                    RevokeOutcome::RootClearedDescendantsBlocked => {
                        root_cleared.push(entry.path.clone())
                    }
                    RevokeOutcome::Failed => failures.push((
                        entry.path.clone(),
                        "revoke failed (already running elevated)".to_string(),
                    )),
                }
            }
            Ok((revoked, root_cleared, failures))
        } else {
            harness_sandbox::privhelper::run_privileged_revoke_fs_allow(remaining.clone())
                .map_err(|e| e.to_string())
        };

    match escalated {
        Ok((revoked, root_cleared, failures)) => {
            for path in revoked.iter().chain(root_cleared.iter()) {
                remove_fs_passthrough_grant(path);
                println!(
                    "revoked via privilege-separation helper (UAC, one-time): {}",
                    path.display()
                );
            }
            if failures.is_empty() {
                ExitCode::SUCCESS
            } else {
                for (path, reason) in &failures {
                    eprintln!("revoke incomplete for {} : {reason}", path.display());
                }
                ExitCode::FAILURE
            }
        }
        Err(reason) => {
            for entry in &remaining {
                eprintln!("revoke failed for {}: {reason}", entry.path.display());
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn fs_revoke_all() -> ExitCode {
    eprintln!("error: fs passthrough revoke is Windows-only (Tier2a specific)");
    ExitCode::FAILURE
}

/// `grant-traverse --dry-run`本体。`target`の祖先チェーン（ドライブルートまで）を、一切書込まず
/// 読み取り専用（`GetNamedSecurityInfoW`のみ）で列挙する。`WRITE_DAC`もUACも不要
/// （`win_appcontainer::ensure_profile`はAppContainerプロファイルの作成/導出のみでACL変更を
/// 伴わない）。ユーザーが本実行の前にどのノードへ書込みが起きるか確認できるようにする
/// （プロファイルルート近傍への`SetNamedSecurityInfoW`はこの種の実機で病的に遅くなりうる、
/// BUG-011）。
#[cfg(windows)]
fn fs_grant_traverse_preview(target: &Path) -> ExitCode {
    let sid = match harness_sandbox::win_appcontainer::ensure_profile(
        harness_sandbox::win_appcontainer::CONTAINER_NAME,
    ) {
        Ok(sid) => sid,
        Err(e) => {
            eprintln!("dry-run: failed to resolve sandbox SID: {e}");
            return ExitCode::FAILURE;
        }
    };
    let preview = harness_sandbox::win_appcontainer::preview_traverse_chain(target, sid.as_psid());
    println!("=== grant-traverse --dry-run: {} ===", target.display());
    println!("(read-only: no ACE has been written, no UAC prompt was shown)");
    for node in &preview {
        let status = if node.already_sufficient {
            "already has FILE_TRAVERSE|FILE_READ_ATTRIBUTES -- write will be SKIPPED"
        } else {
            match node.existing_mask {
                Some(_) => "has some sandbox-SID ACE, but not sufficient -- WILL WRITE",
                None => "no sandbox-SID ACE yet -- WILL WRITE",
            }
        };
        println!("  {} : {status}", node.path.display());
    }
    println!(
        "run without --dry-run to actually grant (requires WRITE_DAC on each node still \
         needing a write; non-administrators will see a UAC prompt via the privilege-separation \
         helper, D-16)"
    );
    ExitCode::SUCCESS
}

#[cfg(not(windows))]
fn fs_grant_traverse_preview(_target: &Path) -> ExitCode {
    eprintln!("error: fs grant-traverse --dry-run is Windows-only (Tier2a specific)");
    ExitCode::FAILURE
}

/// ドライブルートへtraverse ACEを付与する（D10）。`WRITE_DAC`が要るため管理者権限で実行する
/// 必要がある。本体プロセス自身が既に昇格済み（`is_elevated()`）ならACL操作を直接行うが、
/// 通常の非管理者起動時は特権分離ヘルパー（D-16、`plans/DESIGN-SANDBOX-PRIVSEP.md` §5）を
/// `runas`経由で呼び出す（本体プロセス自身は非管理者のまま維持する）。
#[cfg(windows)]
fn fs_grant_traverse(target: &Path) -> ExitCode {
    // 事前チェック（決定2、`TIER1A-PRIVHELPER-HANG.md`「引き継ぎTODO」）: 祖先チェーン全ノードが
    // 既にFILE_TRAVERSE|FILE_READ_ATTRIBUTESを持っているなら、privhelperもUACも一切呼ばず
    // 即座に成功する。`preview_traverse_chain`は`--dry-run`が使うのと同じ読み取り専用ヘルパで、
    // `WRITE_DAC`もUACも要らない。
    if let Ok(sid) = harness_sandbox::win_appcontainer::ensure_profile(
        harness_sandbox::win_appcontainer::CONTAINER_NAME,
    ) {
        let preview =
            harness_sandbox::win_appcontainer::preview_traverse_chain(target, sid.as_psid());
        if !preview.is_empty() && preview.iter().all(|node| node.already_sufficient) {
            for node in &preview {
                record_traverse_grant(&node.path);
            }
            println!(
                "grant-traverse: all {} ancestor node(s) already have \
                 FILE_TRAVERSE|FILE_READ_ATTRIBUTES -- skipped the privilege-separation helper \
                 entirely (no UAC prompt): {}",
                preview.len(),
                preview
                    .iter()
                    .map(|n| n.path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            );
            return ExitCode::SUCCESS;
        }
    }
    if harness_sandbox::privhelper::is_elevated() {
        return fs_grant_traverse_direct(target);
    }
    match harness_sandbox::privhelper::run_privileged(
        &harness_sandbox::privhelper::PrivilegedRequest::GrantTraverse {
            target: target.to_path_buf(),
        },
    ) {
        Ok(granted) => {
            for node in &granted {
                record_traverse_grant(node);
            }
            println!(
                "granted FILE_TRAVERSE|FILE_READ_ATTRIBUTES via privilege-separation helper \
                 (UAC, one-time) on the full ancestor chain up to the drive root: {} (see \
                 docs/phases/foundation/M12-shell-isolation-tiers.md 追記8・追記13, \
                 plans/DESIGN-SANDBOX-PRIVSEP.md §5). All {} node(s) recorded in the traverse \
                 ledger; use `harness fs revoke-traverse <path>` per-node or `revoke-traverse-all` \
                 to undo",
                granted
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" -> "),
                granted.len()
            );
            ExitCode::SUCCESS
        }
        Err(harness_sandbox::privhelper::PrivHelperError::PartialGrantChain {
            granted,
            reason,
        }) => {
            for node in &granted {
                record_traverse_grant(node);
            }
            eprintln!(
                "grant-traverse chain partially failed for {}: {reason}. {} node(s) that DID \
                 succeed before the failure were still recorded in the traverse ledger (no \
                 orphaned ACEs): {}",
                target.display(),
                granted.len(),
                granted
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            );
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("grant-traverse failed on {}: {e}", target.display());
            ExitCode::FAILURE
        }
    }
}

/// `fs_grant_traverse`の直接実行部分(本体が既に管理者トークンで動作している場合のみ呼ぶ、
/// §5.3「本体が管理者ならヘルパー機構を経由しない直接呼び出しを許すが、そもそも本体が
/// 管理者で起動されたこと自体を警告する」に対応)。
#[cfg(windows)]
fn fs_grant_traverse_direct(target: &Path) -> ExitCode {
    let sid = match harness_sandbox::win_appcontainer::ensure_profile(
        harness_sandbox::win_appcontainer::CONTAINER_NAME,
    ) {
        Ok(sid) => sid,
        Err(e) => {
            eprintln!("failed to resolve sandbox SID: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (granted, result) =
        harness_sandbox::win_appcontainer::grant_traverse_chain(target, sid.as_psid());
    for node in &granted {
        record_traverse_grant(node);
    }
    match result {
        Ok(()) => {
            println!(
                "granted FILE_TRAVERSE|FILE_READ_ATTRIBUTES (admin, one-time; see \
                 docs/phases/foundation/M12-shell-isolation-tiers.md 追記8・追記13) on the full \
                 ancestor chain up to the drive root: {}. All {} node(s) recorded in the \
                 traverse ledger; use `harness fs revoke-traverse <path>` per-node or \
                 `revoke-traverse-all` to undo",
                granted
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" -> "),
                granted.len()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "grant-traverse chain failed on {}: {e} (this requires WRITE_DAC on each \
                 ancestor node; re-run as administrator). {} node(s) that DID succeed before \
                 the failure were still recorded in the traverse ledger: {}",
                target.display(),
                granted.len(),
                granted
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn fs_grant_traverse(_target: &Path) -> ExitCode {
    eprintln!("error: fs grant-traverse is Windows-only (Tier2a specific)");
    ExitCode::FAILURE
}

/// 指定パスのtraverse ACEを撤収する（非再帰・単一ノード、D10の巻き戻し）。
/// `grant_traverse_drive_root`（`grant_ace_mask`による非継承・単一ACE付与）の逆操作なので、
/// `revoke_ace`（単一ノード）+ `assert_no_sid_ace`（単一ノード検証）を使う。
/// `revoke_ace_recursive`/`assert_no_sid_ace_recursive`（ツリー全体を再walk）は、`path`が
/// ドライブルートの場合に不要な全走査を招くため使わない。`fs_grant_traverse`と同じく、
/// 本体が既に昇格済みなら直接、それ以外は特権分離ヘルパー（D-16）経由で実行する。
#[cfg(windows)]
fn fs_revoke_traverse_one(path: &Path) -> ExitCode {
    if harness_sandbox::privhelper::is_elevated() {
        return fs_revoke_traverse_one_direct(path);
    }
    match harness_sandbox::privhelper::run_privileged(
        &harness_sandbox::privhelper::PrivilegedRequest::RevokeTraverse {
            path: path.to_path_buf(),
        },
    ) {
        Ok(_) => {
            remove_traverse_grant(path);
            println!(
                "revoked traverse ACE via privilege-separation helper: {}",
                path.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("revoke-traverse failed for {}: {e}", path.display());
            ExitCode::FAILURE
        }
    }
}

#[cfg(windows)]
fn fs_revoke_traverse_one_direct(path: &Path) -> ExitCode {
    let sid = match harness_sandbox::win_appcontainer::ensure_profile(
        harness_sandbox::win_appcontainer::CONTAINER_NAME,
    ) {
        Ok(sid) => sid,
        Err(e) => {
            eprintln!("failed to resolve sandbox SID: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = harness_sandbox::win_appcontainer::revoke_ace(path, sid.as_psid()) {
        eprintln!("revoke-traverse failed for {}: {e}", path.display());
        return ExitCode::FAILURE;
    }
    match harness_sandbox::win_appcontainer::assert_no_sid_ace(path, sid.as_psid()) {
        Ok(()) => {
            remove_traverse_grant(path);
            println!("revoked traverse ACE: {}", path.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "revoke-traverse verification failed for {}: {e}",
                path.display()
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn fs_revoke_traverse_one(_path: &Path) -> ExitCode {
    eprintln!("error: fs revoke-traverse is Windows-only (Tier2a specific)");
    ExitCode::FAILURE
}

#[tokio::main]
async fn main() -> ExitCode {
    // 本体プロセスが管理者権限で起動されていないかを確認する（D-16、
    // `plans/DESIGN-SANDBOX-PRIVSEP.md` §5.3）。harness本体は常に非管理者トークンで動作する
    // 設計であり、ヘルパー機構が無い間は実害が無いが（WFP/VHDX自体を使わないため）、
    // 「本体が管理者ならヘルパー経由でない直接呼び出しに倒れていないか」を明示的に確認する
    // 材料として警告ログを残す。拒否はしない。
    #[cfg(windows)]
    if harness_sandbox::privhelper::is_elevated() {
        eprintln!(
            "warning: harness is running with an elevated (administrator) token. harness is \
             designed to always run as a non-administrator process; privileged operations \
             (e.g. `harness fs grant-traverse`) should go through the privilege-separation \
             helper (D-16, plans/DESIGN-SANDBOX-PRIVSEP.md §5.3), not this elevated \
             process directly."
        );
    }

    // カレントディレクトリの`.env`があれば読み込み、プロセスのenvへ反映する（既存の環境変数は
    // 上書きしない、§設定とシークレット「ユーザ/プロジェクト設定」相当の簡易版）。無ければ無視する。
    let _ = dotenvy::dotenv();

    let mut cli = Cli::parse();

    let workspace_root = match cli.cwd.clone() {
        Some(dir) => dir,
        None => match std::env::current_dir() {
            Ok(dir) => dir,
            Err(e) => {
                eprintln!("failed to resolve current directory: {e}");
                return ExitCode::FAILURE;
            }
        },
    };

    // `apply`/`changes`/`discard`サブコマンドはプロバイダ資格情報を一切必要としないため、
    // 他のあらゆる検証より前に処理して即終了する（§非対話モード、プロンプトは一切送らない）。
    // `.take()`（`mem::replace`でNoneに戻す）を使うのは、`Commands::Prompt`分岐で`&cli`を
    // 丸ごと借用したいため。単純な`cli.command`のムーブだと`cli.command`フィールドだけが
    // 部分ムーブされ、以降`&cli`が取れなくなる。
    if let Some(cmd) = cli.command.take() {
        return match cmd {
            Commands::Fs { action } => run_fs_subcommand(action),
            Commands::Tier3 { action } => run_tier3_subcommand(action),
            Commands::Net { action } => run_net_subcommand(action, &workspace_root),
            Commands::Prompt => run_prompt_subcommand(&cli, &workspace_root),
            other => run_sandbox_subcommand(other, &workspace_root),
        };
    }

    // `--list-sessions`はプロバイダ資格情報を一切必要としないため、他のあらゆる検証より前に
    // 処理して即終了する（§非対話モード、プロンプトは一切送らない）。
    if cli.list_sessions {
        let sessions_dir = workspace_root.join(".harness").join("sessions");
        return match harness_engine::SessionStore::list(&sessions_dir) {
            Ok(summaries) => {
                print_session_list(&summaries, cli.output_format);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("failed to list sessions in {}: {e}", sessions_dir.display());
                ExitCode::FAILURE
            }
        };
    }

    // 引数なし`--resume`（値省略、空文字列扱い）はヘッドレスでは非対話原則により拒否する。
    // ピッカーはTTYが要る対話TUIでのみ意味を持つ（§非対話モード「ヘッドレスモードは対話
    // プロンプトを一切出さない」）。
    let resume_wants_picker = cli.resume.as_deref() == Some("");
    if resume_wants_picker && cli.print.is_some() {
        eprintln!("--resume without a value opens an interactive picker and is not supported with -p/--print; pass --resume <id> explicitly");
        return ExitCode::FAILURE;
    }
    let resume_id = cli.resume.clone().filter(|s| !s.is_empty());

    if cli.fork_session && resume_id.is_none() && !cli.continue_session {
        eprintln!("--fork-session requires --resume <id> or --continue");
        return ExitCode::FAILURE;
    }
    if cli.fork_session && resume_wants_picker {
        eprintln!("--fork-session cannot be combined with a bare --resume (use the picker's 'f' key instead)");
        return ExitCode::FAILURE;
    }

    // §設定とシークレット「既定 → ユーザ → プロジェクト → CLIフラグ（最優先）」。CLIフラグが
    // 明示されていればそちらを使い、無ければ`settings.json`階層へフォールバックする
    // （`permission_mode`/`output_format`はclapの`default_value_t`で常に値を持つため
    // このフォールバックの対象外、CLI値をそのまま使う）。
    let settings = harness_config::Settings::load(&workspace_root);

    let early_require_sandbox = parse_require_sandbox(cli.require_sandbox.as_deref());
    if early_require_sandbox == RequireSandbox::Confidential {
        let mut early_net_proxy = settings
            .net
            .clone()
            .unwrap_or_default()
            .to_net_proxy_config();
        if let Err(e) =
            validate_and_merge_net_allow_domains(&mut early_net_proxy, &cli.net_allow_domain)
        {
            eprintln!("error: invalid network domain policy: {e}");
            return ExitCode::FAILURE;
        }
        let mut early_net_app = settings.net.clone().unwrap_or_default().to_net_app_policy();
        for app in &cli.net_allow_app {
            if !early_net_app.allow_apps.contains(app) {
                early_net_app.allow_apps.push(app.clone());
            }
        }
        if !early_net_proxy.allow_domains.is_empty() || !early_net_app.allow_apps.is_empty() {
            eprintln!(
                "error: network allow rules (--net-allow-domain / --net-allow-app / settings \
                 net.*) conflict with --require-sandbox=confidential (confidential mode denies \
                 all outbound network unconditionally; refusing to start rather than silently \
                 ignoring network allow rules or weakening the confidentiality guarantee)"
            );
            return ExitCode::FAILURE;
        }
    }

    let provider = match build_provider(cli.provider, cli.base_url) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let model = match resolve_model(cli.model.or(settings.model.clone()), cli.provider) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let max_turns = cli
        .max_turns
        .or(settings.max_turns)
        .unwrap_or(DEFAULT_MAX_TURNS);
    let enter_submits = cli
        .enter_submits
        .or(settings.enter_submits)
        .unwrap_or(false);

    let tools = ToolRegistry::with_builtin_tools();

    // §非対話モード「危険/ワイルドカードは`--dangerously-allow`」: accept-allモードは
    // fail-fastで拒否する（`--dangerously-allow`が無いままの誤起動を防ぐ）。
    if matches!(cli.permission_mode, PermissionModeArg::AcceptAll) && !cli.dangerously_allow {
        eprintln!(
            "--permission-mode accept-all requires --dangerously-allow (see plans/DESIGN.md §非対話モード)"
        );
        return ExitCode::FAILURE;
    }

    let allowlist: Vec<_> = settings
        .allow
        .clone()
        .unwrap_or_default()
        .iter()
        .chain(cli.allow.iter())
        .filter_map(|rule| match parse_allowlist_rule(rule) {
            None => {
                eprintln!("ignoring malformed --allow rule (expected tool:pattern): {rule}");
                None
            }
            Some(r) if harness_cli::is_dangerous_wildcard(&r.pattern) && !cli.dangerously_allow => {
                eprintln!("ignoring wildcard --allow rule without --dangerously-allow: {rule}");
                None
            }
            Some(r) => Some(r),
        })
        .collect();
    let arbiter = PermissionArbiter::new(cli.permission_mode.into(), allowlist);

    // JSONL追記型セッション永続化（M9、§非対話モード「JSONL 追記型セッション永続化
    // （`--resume`/`--continue`）」）。`.harness/sessions/`直下に1ファイル1セッション。
    let sessions_dir = workspace_root.join(".harness").join("sessions");
    if let Err(e) = std::fs::create_dir_all(&sessions_dir) {
        eprintln!(
            "failed to create sessions directory {}: {e}",
            sessions_dir.display()
        );
        return ExitCode::FAILURE;
    }
    let mut session =
        match resolve_session(&sessions_dir, resume_id.as_deref(), cli.continue_session) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        };

    // `--fork-session`: 解決済みの元セッションを不変のまま、全履歴を新規セッションへコピーして
    // 以降の追記先を切り替える（Claude Codeの`--fork-session`/`/branch`相当）。
    if cli.fork_session {
        let source_id = session.id();
        match harness_engine::SessionStore::fork_from(&sessions_dir, session.path()) {
            Ok(forked) => {
                eprintln!("forked session {source_id} -> {}", forked.id());
                session = forked;
            }
            Err(e) => {
                eprintln!("failed to fork session {source_id}: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // `ConversationState`自体は`tool_ctx`確定後（下記）に組み立てる。systemは`tool_ctx`が運ぶ
    // 環境事実（`harness_engine::system_blocks_for`）から作るため、先に`tool_ctx`が要る
    // （`run_shell`不安定性調査で見つかった「systemが一切送られていない」欠陥への対処、
    // `plans/DESIGN.md` §システムプロンプト参照）。
    let session_messages = match session.load_messages() {
        Ok(msgs) => msgs,
        Err(e) => {
            eprintln!("failed to load session {}: {e}", session.path().display());
            return ExitCode::FAILURE;
        }
    };

    // 書込ステージング設定（M10）。`sandbox_dir`は`session.id()`確定後でなければ組めないため
    // ここで`ToolCtx`を構築する。明示`--live`時はオーバーレイ自体を使わない
    // （`sandbox_dir: None`、M9までの直接実FSアクセスとバイト等価・監査ログも作らない）。
    let (explicit, staging_mode) = resolve_staging_mode(
        cli.live,
        cli.staged,
        cli.workspace_commit,
        cli.print.is_some(),
    );
    let sandbox_dir = if explicit && staging_mode == StagingMode::Live {
        None
    } else {
        Some(sandbox_dir_for_session(&session.id()))
    };
    let read_scope = settings
        .read
        .clone()
        .unwrap_or_default()
        .to_read_scope_config();

    // 協調プロキシ設定（M12補遺、D-15）。CLI `--net-allow-domain`（繰り返し）と
    // `.harness/settings.json`の`net.allow_domains`を和集合でマージする（重複除去）。
    let mut net_proxy = settings
        .net
        .clone()
        .unwrap_or_default()
        .to_net_proxy_config();
    if let Err(e) = validate_and_merge_net_allow_domains(&mut net_proxy, &cli.net_allow_domain) {
        eprintln!("error: invalid network domain policy: {e}");
        return ExitCode::FAILURE;
    }
    if net_proxy.audit_log_path.is_none() {
        if let Some(dir) = &sandbox_dir {
            net_proxy.audit_log_path = Some(workspace_root.join(dir).join("net-audit.jsonl"));
        }
    }

    // アプリ単位network制御（軸1、D-10/D-11）。CLI `--net-allow-app`（繰り返し）と
    // `.harness/settings.json`の`net.allow_apps`を和集合でマージする（重複除去、net_proxyと同形）。
    let mut net_app = settings.net.clone().unwrap_or_default().to_net_app_policy();
    for app in &cli.net_allow_app {
        if !net_app.allow_apps.contains(app) {
            net_app.allow_apps.push(app.clone());
        }
    }

    // シェル隔離Tier選択（M12、`plans/DESIGN-SANDBOX.md` §6/§7 D-03）。`--require-sandbox`指定時は
    // 自動降格せず起動を拒否する（既存の`--dangerously-allow`と同じfail-fastパターン）。
    let require_sandbox = parse_require_sandbox(cli.require_sandbox.as_deref());

    // confidential（外部持出し経路を作らない明示拒否モード＝通信許可リストを無効化する上位モード）
    // と net-allow-domain/net-allow-app（通信を開く）は意味的に矛盾するため、黙って無視/弱めず起動を拒否する
    // （`--require-sandbox`のsatisfiesと同じfail-fast思想、`plans/DESIGN-SANDBOX-APPPOLICY.md` §7）。
    if require_sandbox == RequireSandbox::Confidential
        && (!net_proxy.allow_domains.is_empty() || !net_app.allow_apps.is_empty())
    {
        eprintln!(
            "error: network allow rules (--net-allow-domain / --net-allow-app / settings net.*) \
             conflict with --require-sandbox=confidential (confidential \
             mode denies all outbound network unconditionally; refusing to start rather than \
             silently ignoring network allow rules or weakening the confidentiality guarantee)"
        );
        return ExitCode::FAILURE;
    }

    // fs passthrough allowlist（軸2・D-13）。CLI `--fs-allow`（繰り返し）と
    // `.harness/settings.json`の`fs.allow`を和集合でマージする（重複除去、net_appと同形）。
    // 各要素は`<path>[:rw]`（末尾`:rw`が無ければread-only既定、D-13）。パスは`workspace_root`
    // 基準で絶対化する（既に絶対パスなら`Path::join`はそのまま採用する）。
    let mut fs_allow_raw: Vec<(String, bool)> =
        settings.fs.clone().unwrap_or_default().to_fs_passthrough();
    for entry in &cli.fs_allow {
        let (path, writable) = match entry.strip_suffix(":rw") {
            Some(p) => (p.to_string(), true),
            None => (entry.clone(), false),
        };
        if !fs_allow_raw.iter().any(|(p, _)| p == &path) {
            fs_allow_raw.push((path, writable));
        }
    }
    // --force-system-acl（D-19）はread-only専用（システムディレクトリへの書込強制は危険すぎる）。
    // `:rw`エントリが1つでもあれば起動を拒否する（fail-fast、--require-sandboxのD7と同じ思想）。
    if cli.force_system_acl && fs_allow_raw.iter().any(|(_, writable)| *writable) {
        eprintln!(
            "error: --force-system-acl requires read-only --fs-allow entries (a :rw entry is \
             present); forcing writable ACEs into system-protected paths is refused. Drop :rw or \
             drop --force-system-acl."
        );
        return ExitCode::FAILURE;
    }
    let fs_passthrough: Vec<harness_sandbox::FsPassthrough> = fs_allow_raw
        .into_iter()
        .map(|(path, writable)| harness_sandbox::FsPassthrough {
            path: workspace_root.join(&path),
            writable,
            forced: cli.force_system_acl,
        })
        .collect();
    if !fs_passthrough.is_empty() && !cfg!(windows) {
        eprintln!(
            "warning: --fs-allow / fs.allow is only supported on Windows (Tier2a); ignored on \
             this OS"
        );
    }

    // D7: --require-sandboxとの矛盾チェック。write-containmentは範囲外書込を禁じるため:rwのみ
    // 拒否（:roは書込に無関係で許可）。confidentialは範囲外を読めない保証のため:ro/:rwいずれも
    // 拒否する（外部読取穴がconfidentialの機密性保証と正面から矛盾するため、
    // `--net-allow-app`×confidentialと同じfail-fast思想）。
    let fs_has_write = fs_passthrough.iter().any(|fp| fp.writable);
    match require_sandbox {
        RequireSandbox::WriteContainment if fs_has_write => {
            eprintln!(
                "error: --fs-allow with :rw conflicts with --require-sandbox (write-containment \
                 forbids writes outside the workspace; use read-only --fs-allow entries instead, \
                 or drop --require-sandbox)"
            );
            return ExitCode::FAILURE;
        }
        RequireSandbox::Confidential if !fs_passthrough.is_empty() => {
            eprintln!(
                "error: --fs-allow conflicts with --require-sandbox=confidential (confidential \
                 mode denies reading outside the workspace unconditionally; even read-only \
                 --fs-allow breaks this guarantee; refusing to start rather than silently \
                 weakening it)"
            );
            return ExitCode::FAILURE;
        }
        _ => {}
    }

    // `--experimental-tier1a`は非推奨・no-op化した（`--sandbox`自動カスケード実装ラウンドより
    // Tier2aはフラグ無しで既定プローブされるため）。指定された場合は一度だけ情報表示する。
    if cli.experimental_tier2a {
        eprintln!(
            "note: --experimental-tier1a is deprecated and has no effect; Tier2a (AppContainer) \
             is now attempted automatically on Windows. Use --sandbox (or --experimental-tier3) \
             to also attempt Tier3."
        );
    }

    // WFP 出口強制（Layer2、`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`付録D）の
    // named pipeを、`select_tier`（内部で`preflight`を呼ぶ）より前に用意しておく。
    // Tier2aはフラグ無しで既定プローブされるため（`--sandbox`カスケードの中間フォールバック
    // としても到達し得る）、ドメインポリシー監査が有効な場合は常に投機的に用意しておく
    // （そうでなければWFPは不要＝シナリオ(C)、パイプすら作らずUACゼロを保つ）。ここで作った
    // パイプ名は、`preflight`経由で特権分離ヘルパーへ「処理完了後この名前でnetfilterdを
    // 連鎖起動してほしい」という指示として渡す（シナリオ(A)）。実際にTier2aへ降格せずに
    // 終わる、またはprivhelperへの委譲が発生しなかった場合（シナリオ(B)/(C)）は、この
    // パイプは未使用のまま閉じるか、`NetfilterHandle::start`の直接起動へ切り替える
    // （下記`net_wfp`解決を参照）。
    #[cfg(windows)]
    let wfp_prelude: Option<harness_sandbox::netfilterd::PreparedPipe> =
        if net_proxy.domain_policy_enabled {
            match harness_sandbox::netfilterd::prepare_pipe() {
                Ok(prepared) => Some(prepared),
                Err(e) => {
                    eprintln!(
                        "warning: failed to prepare WFP netfilterd pipe (Layer2 network \
                         enforcement will be unavailable this session, falling back to the \
                         cooperative proxy only): {e}"
                    );
                    None
                }
            }
        } else {
            None
        };
    #[cfg(not(windows))]
    let wfp_prelude: Option<String> = None;
    #[cfg(windows)]
    let wfp_chain_pipe = wfp_prelude.as_ref().map(|p| p.name().to_string());
    #[cfg(not(windows))]
    let wfp_chain_pipe: Option<String> = None;

    let shell_tier = match select_tier(
        require_sandbox,
        &workspace_root,
        cli.experimental_tier3 || cli.sandbox,
        &fs_passthrough,
        wfp_chain_pipe,
    ) {
        Ok(selection) => selection,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    let _session_proxy = if net_proxy.domain_policy_enabled {
        match harness_tools::net_proxy::spawn_local_proxy(&net_proxy).await {
            Ok(Some(proxy)) => {
                net_proxy.proxy_addr = Some(proxy.addr);
                Some(proxy)
            }
            Ok(None) => None,
            Err(e) => {
                if shell_tier.tier == harness_core::ShellTier::Tier2a {
                    eprintln!(
                        "warning: failed to start session-scoped local proxy; Tier2a domain \
                         enforcement will remain fail-closed instead of opening network: {e}"
                    );
                } else {
                    eprintln!(
                        "warning: failed to start session-scoped local proxy; run_shell will try \
                         a per-command proxy instead: {e}"
                    );
                }
                None
            }
        }
    } else {
        None
    };
    let _session_fake_dns = if net_proxy.domain_policy_enabled {
        match harness_tools::fake_dns::spawn_fake_dns(&harness_tools::fake_dns::FakeDnsConfig {
            allow_domains: net_proxy.allow_domains.clone(),
            policy_required: net_proxy.domain_policy_enabled,
            audit_log_path: net_proxy.audit_log_path.clone(),
            preferred_port: Some(53),
        })
        .await
        {
            Ok(agent) => {
                net_proxy.fake_dns_addr = Some(agent.addr);
                Some(agent)
            }
            Err(e) => {
                eprintln!(
                    "warning: failed to start session-scoped Fake DNS diagnostic agent; run_shell \
                     will try a per-command Fake DNS agent instead: {e}"
                );
                None
            }
        }
    } else {
        None
    };
    let net_loopback_ports =
        net_loopback_ports_for_agents(net_proxy.proxy_addr, net_proxy.fake_dns_addr);

    // WFPシナリオ(A)/(B)/(C)の最終確定。`shell_tier`が実際にTier2aへ着地し、かつ許可ドメインが
    // あるときだけ有効化する（`experimental_tier2a`はオプトインの意図であって、preflight失敗で
    // Tier1へ降格した場合はWFPも当然無効）。
    #[cfg(windows)]
    let net_wfp: Option<harness_sandbox::netfilterd::NetfilterHandle> = {
        let domain_policy_requested = net_proxy.domain_policy_enabled;
        let tier2a_domain_policy =
            shell_tier.tier == harness_core::ShellTier::Tier2a && domain_policy_requested;
        let session_proxy_ready = net_proxy.proxy_addr.is_some();
        let wfp_needed = tier2a_domain_policy && session_proxy_ready;
        if !wfp_needed {
            if tier2a_domain_policy && !session_proxy_ready {
                eprintln!(
                    "warning: session-scoped local proxy did not start; WFP domain enforcement \
                     will not be enabled and Tier2a run_shell network capability will remain \
                     denied (fail-closed)"
                );
            }
            // シナリオ(C)、または投機的に作ったパイプが結局不要だった場合。`wfp_prelude`を
            // dropするだけで`PreparedPipe`が自動的にパイプを閉じる（後始末コード不要）。
            drop(wfp_prelude);
            None
        } else if shell_tier.netfilterd_chain_attempted {
            // シナリオ(A): privhelperが既に連鎖起動を試みている。同じパイプでハンドシェイクする。
            match wfp_prelude {
                Some(prepared) => {
                    match harness_sandbox::netfilterd::NetfilterHandle::connect_after_chain_launch(
                        prepared.into_handle(),
                        Vec::new(),
                        false,
                        Vec::new(),
                        net_loopback_ports.tcp.clone(),
                        net_loopback_ports.udp.clone(),
                        false,
                        net_proxy.audit_log_path.clone(),
                    ) {
                        Ok(handle) => Some(handle),
                        Err(e) => {
                            eprintln!(
                                "warning: WFP netfilterd chain-launch handshake failed (network \
                                 egress will only be enforced by the cooperative proxy, Layer1, \
                                 this session): {e}"
                            );
                            None
                        }
                    }
                }
                None => None,
            }
        } else {
            // シナリオ(B): privhelperの連鎖起動は発生しなかった（fs-allowの昇格が不要だった等）。
            // 投機的パイプは使わない（`NetfilterHandle::start`が自前で新規パイプを作るため）、
            // dropして自動的に閉じる。
            drop(wfp_prelude);
            match harness_sandbox::netfilterd::NetfilterHandle::start(
                Vec::new(),
                false,
                Vec::new(),
                net_loopback_ports.tcp.clone(),
                net_loopback_ports.udp.clone(),
                false,
                net_proxy.audit_log_path.clone(),
            ) {
                Ok(handle) => Some(handle),
                Err(e) => {
                    eprintln!(
                        "warning: failed to start WFP netfilterd (network egress will only be \
                         enforced by the cooperative proxy, Layer1, this session): {e}"
                    );
                    None
                }
            }
        }
    };
    #[cfg(not(windows))]
    let _net_wfp: Option<()> = None;
    if let Some(reason) = &shell_tier.reason {
        eprintln!(
            "warning: shell isolation downgraded to {} (from {}): {reason}",
            shell_tier.tier.label(),
            shell_tier.downgraded_from.map(|t| t.label()).unwrap_or("?")
        );
    }
    if shell_tier.tier == harness_core::ShellTier::Tier1 {
        eprintln!(
            "note: shell isolation tier is Tier1; Tier2a (AppContainer) was attempted \
             automatically but unavailable this session (see the warning above for the reason). \
             Tier1 does not protect against reading confidential files outside the workspace \
             or outbound network exfiltration from run_shell child processes \
             (plans/DESIGN-SANDBOX.md §9-1). --require-sandbox=confidential refuses to start \
             at Tier1 rather than silently weakening this guarantee."
        );
    }
    // fs passthrough（D2/D-13）: ACE付与自体は「付けっぱなし」（撤収はユーザ操作
    // `harness fs revoke`に委ねる）。Tier2aが実際に選択された場合のみpreflightがACE付与を
    // 試みたので、そのときだけ台帳に記録する。`granted_passthrough`（実際にACEが確認できた
    // ルートのみ）を基準にする——`fs_passthrough`全件を無条件に記録すると、システム保護パス等で
    // `ACCESS_DENIED`になり実際には付与されなかったエントリまで台帳に載る「幻の台帳エントリ」を
    // 生んでしまうため（`TIER1A-PRIVHELPER-HANG.md`「引き継ぎTODO」）。到達不能だった穴の診断
    // （D8/D9）は`passthrough_warnings`としてこの下で表示する。
    if shell_tier.tier == harness_core::ShellTier::Tier2a {
        for (path, writable) in &shell_tier.granted_passthrough {
            // このエントリが`--force-system-acl`対象だったか（元のfs_passthroughから引く）。
            // forcedなら撤収時も`SeRestorePrivilege`が要るため台帳へ記録しておく。
            let forced = fs_passthrough
                .iter()
                .find(|fp| &fp.path == path)
                .map(|fp| fp.forced)
                .unwrap_or(false);
            record_fs_passthrough_grant(path, *writable, forced);
            if forced {
                eprintln!(
                    "WARNING: forced system ACL grant (--force-system-acl, SeRestorePrivilege): {} \
                     [{}] -- a sandbox read ACE was written into a system-protected path by \
                     bypassing its DACL (ownership unchanged). This ACE persists after harness \
                     exits; run `harness fs revoke {}` to undo.",
                    path.display(),
                    if *writable { "rw" } else { "ro" },
                    path.display()
                );
            } else {
                eprintln!(
                    "note: fs-allow granted: {} [{}] (this ACE persists after harness exits; use \
                     `harness fs revoke {}` to undo)",
                    path.display(),
                    if *writable { "rw" } else { "ro" },
                    path.display()
                );
            }
        }
    }
    for warning in &shell_tier.passthrough_warnings {
        eprintln!("warning: {warning}");
    }

    // Tier3（`plans/DESIGN-SANDBOX-VMISOLATION.md`）: VM+コンテナ起動デーモン
    // （`harness-vmsandboxd`、D-21）の昇格起動・起動待ちはコールドブートで数分かかり得る
    // （`docs/STATUS.md`Tier3残課題#3）ため、無進捗のままここでブロッキングせず、`cli.print`の
    // 分岐後（TUIならターミナル準備画面の中、非対話ならstderr進捗行と共に）まで遅延させる。
    // ここでは`vm_sandbox: None`のまま`ToolCtx`を構築し、各分岐が準備完了後に書き戻す
    // （`system_blocks_for`は`vm_sandbox`を参照しないため後書きで安全、`prompt.rs`参照）。
    if net_wfp.is_some() {
        net_proxy.enforced_by_wfp = true;
    }

    let mut tool_ctx = ToolCtx {
        workspace_root: workspace_root.clone(),
        staging: StagingConfig {
            mode: staging_mode,
            explicit,
            sandbox_dir,
        },
        read_scope,
        shell_sees_staged_writes: shell_sees_staged_writes(&shell_tier),
        shell_tier,
        net_proxy,
        net_app,
        vm_sandbox: None,
    };

    let mut state = ConversationState::new(harness_engine::system_blocks_for(&tool_ctx));
    state.messages = session_messages;

    let exit_code = match cli.print {
        Some(print) => {
            let prompt = if print == "-" {
                let mut buf = String::new();
                if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
                    eprintln!("failed to read prompt from stdin: {e}");
                    return ExitCode::FAILURE;
                }
                buf
            } else {
                print
            };

            state.push_user_text(prompt);
            if let Err(e) = session.append_messages(&state.messages[state.messages.len() - 1..]) {
                eprintln!(
                    "failed to persist session {}: {e}",
                    session.path().display()
                );
                return ExitCode::FAILURE;
            }
            let before_run = state.messages.len();

            // Tier3準備（VM+コンテナ起動、コールドブート数分/ウォーム再利用約20秒）を
            // ここで行い、待機中はstderrへ進捗行を出す（TUI分岐は`harness_tui::run`内で
            // 同様の役割を果たす、`crates/harness-tui/src/lib.rs`参照）。
            #[cfg(windows)]
            let vm_sandbox_handle: Option<
                std::sync::Arc<harness_sandbox::vmsandboxd::VmSandboxHandle>,
            > = if tool_ctx.shell_tier.tier == harness_core::ShellTier::Tier3 {
                start_tier3_with_progress(
                    &tool_ctx.workspace_root,
                    &tool_ctx.net_proxy.allow_domains,
                    cli.tier3_warm,
                    cli.tier3_max_sessions.max(1),
                )
                .await
            } else {
                None
            };
            #[cfg(not(windows))]
            let vm_sandbox_handle: Option<std::sync::Arc<()>> = None;

            #[cfg(windows)]
            {
                tool_ctx.vm_sandbox = vm_sandbox_handle
                    .clone()
                    .map(|h| h as std::sync::Arc<dyn harness_core::VmShellExecutor>);
            }

            let mut stdout = std::io::stdout();
            let exit = run_headless(
                provider.as_ref(),
                &mut state,
                &tools,
                &tool_ctx,
                &arbiter,
                AgentLoopConfig {
                    model,
                    max_tokens: DEFAULT_MAX_TOKENS,
                    max_turns,
                },
                cli.output_format,
                &mut stdout,
            )
            .await;
            let _ = session.append_messages(&state.messages[before_run..]);

            #[cfg(windows)]
            if let Some(handle) = vm_sandbox_handle {
                if let Err(e) = handle.stop() {
                    eprintln!("warning: failed to cleanly tear down Tier3 VM sandbox session: {e}");
                }
            }

            exit
        }
        None => {
            let log_dir = workspace_root.join(".harness").join("logs");
            if let Err(e) = std::fs::create_dir_all(&log_dir) {
                eprintln!("failed to create log directory {}: {e}", log_dir.display());
                return ExitCode::FAILURE;
            }
            // tracing出力先をファイルへ切り替えた後でなければTUI側の`tracing::debug!`等が
            // 直接stdoutを汚してしまう（§リッチTUI「tracingは全てtracing-appenderでファイルへ」）。
            let _log_guard = harness_tui::init_file_logging(&log_dir);

            let result = harness_tui::run(
                provider,
                tools,
                tool_ctx,
                arbiter,
                model,
                DEFAULT_MAX_TOKENS,
                max_turns,
                cli.provider.label().to_string(),
                state,
                session,
                sessions_dir,
                enter_submits,
                resume_wants_picker,
                cli.tier3_warm,
                cli.tier3_max_sessions.max(1),
            )
            .await;

            match result {
                Ok(_) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("tui error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    };

    // セッション終了時のWFP netfilterdのteardown（headless・対話モード共通の末尾）。
    // ここに到達せずにmainが早期returnした場合（このブロックより前のエラーパス）は、
    // `net_wfp`のDropフェイルセーフ（パイプ断検知でdaemon側が自発的にteardownする、
    // `netfilterd.rs`のモジュールdoc参照）に委ねる。Ctrl+C等のシグナル割り込みも同様に
    // フェイルセーフへ委ねる（本ラウンドではシグナルハンドラを追加しない、
    // `~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`付録D手順5参照）。
    // Tier3 VMサンドボックスのteardownは、準備開始をTier3の実際の使用側（TUIは
    // `harness_tui::run`内部、非対話は上の`Some(print)`アーム）へ遅延させたのに合わせて
    // それぞれの分岐内で完結させている（進捗表示のため、`plans/DESIGN-SANDBOX-VMISOLATION.md`
    // 追記・本コミット参照）。早期returnパスは従来通り`VmSandboxHandle`のDropフェイルセーフ
    // （パイプ切断検知でdaemon側が自発的にteardownする）に委ねる。

    #[cfg(windows)]
    if let Some(handle) = net_wfp {
        if let Err(e) = handle.stop() {
            eprintln!("warning: failed to cleanly tear down WFP netfilterd session: {e}");
        }
    }

    exit_code
}

/// 非対話モード（`--print`）専用: Tier3 VMサンドボックスの起動をブロッキングのまま
/// （`tokio::task::spawn_blocking`越しに）待ちつつ、`vmsandboxd_progress`の合成進捗
/// （経過時間ベースの推測、daemonの実測値ではない——`harness_sandbox::vmsandboxd_progress`の
/// モジュールdoc・`plans/DESIGN-SANDBOX-VMISOLATION.md`参照）をstderrへ間引いて出力する。
/// TUI分岐（`harness_tui::run`内の`sandbox_prep::run_prep_screen`）と対になる非対話側の実装。
#[cfg(windows)]
async fn start_tier3_with_progress(
    workspace_root: &std::path::Path,
    allow_domains: &[String],
    tier3_warm: bool,
    tier3_max_sessions: u8,
) -> Option<std::sync::Arc<harness_sandbox::vmsandboxd::VmSandboxHandle>> {
    use harness_sandbox::vmsandboxd::VmSandboxHandle;
    use harness_sandbox::vmsandboxd_progress::{run_synthetic_ticker, SandboxPrepEvent};

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<SandboxPrepEvent>();
    let ticker = tokio::spawn(run_synthetic_ticker(tx, tier3_warm));

    let workspace_root = workspace_root.to_path_buf();
    let allow_domains = allow_domains.to_vec();
    let start_task = tokio::task::spawn_blocking(move || {
        VmSandboxHandle::start(
            &workspace_root,
            &allow_domains,
            tier3_warm,
            tier3_max_sessions,
        )
    });
    tokio::pin!(start_task);

    // ラベルが変わった時か、同一フェーズ内でも約5秒おきにのみ1行stderrへ出す
    // （250ms間隔のtickerをそのまま出力すると流れすぎる — cadenceはticker側で
    // 一定に保ち、間引きはこの呼び出し側の責務とする）。
    let mut last_label: Option<String> = None;
    let mut last_printed_secs: u64 = 0;

    let result = loop {
        tokio::select! {
            biased;
            res = &mut start_task => break res,
            Some(ev) = rx.recv() => {
                let secs = ev.elapsed.as_secs();
                let label_changed = last_label.as_deref() != Some(ev.label.as_str());
                if label_changed || secs.saturating_sub(last_printed_secs) >= 5 {
                    eprintln!("[sandbox] {} (経過 {secs}秒)", ev.label);
                    last_label = Some(ev.label.clone());
                    last_printed_secs = secs;
                }
            }
        }
    };
    ticker.abort();

    match result {
        Ok(Ok(handle)) => Some(std::sync::Arc::new(handle)),
        Ok(Err(e)) => {
            eprintln!(
                "error: tier3 was selected but the VM sandbox failed to start: {e}\n\
                 run_shell will fail until this is resolved (see \
                 plans/TIER1A-OPEN-ISSUES.md item 9)."
            );
            None
        }
        Err(join_err) => {
            eprintln!("error: tier3 sandbox prep task panicked: {join_err}");
            None
        }
    }
}

#[cfg(test)]
mod fs_ledger_tests {
    use super::{FsLedger, FsLedgerEntry};

    /// D-19以前に書かれた台帳（`forced`フィールドが無いJSON）が、`#[serde(default)]`で
    /// `forced=false`として読めることを確認する（後方互換）。台帳が読めないと既存のACEを
    /// 追跡できなくなり「付与した記憶はあるが記録が無い」孤立ACEに直結するため重要。
    #[test]
    fn legacy_ledger_without_forced_field_deserializes_as_not_forced() {
        let legacy = r#"{"entries":[
            {"path":"C:\\ProgramData\\Microsoft\\Windows\\Start Menu","writable":false,"granted_at_unix_secs":1700000000}
        ]}"#;
        let ledger: FsLedger = serde_json::from_str(legacy).expect("legacy ledger must parse");
        assert_eq!(ledger.entries.len(), 1);
        assert!(
            !ledger.entries[0].forced,
            "missing forced field must default to false"
        );
    }

    /// `forced=true`の台帳が正しくラウンドトリップすることを確認する。
    #[test]
    fn forced_entry_roundtrips() {
        let ledger = FsLedger {
            entries: vec![FsLedgerEntry {
                path: r"C:\ProgramData\Microsoft\Windows\Start Menu".to_string(),
                writable: false,
                granted_at_unix_secs: 1_700_000_000,
                forced: true,
            }],
        };
        let json = serde_json::to_string(&ledger).unwrap();
        let back: FsLedger = serde_json::from_str(&json).unwrap();
        assert!(back.entries[0].forced);
    }
}

#[cfg(test)]
mod net_audit_tests {
    use super::{
        filter_net_audit_events, format_net_audit_output, net_audit_path,
        net_loopback_ports_for_agents, validate_and_merge_net_allow_domains, NetLoopbackPorts,
        OutputFormat,
    };
    use harness_core::NetProxyConfig;
    use serde_json::json;
    use std::path::Path;

    #[test]
    fn explicit_net_audit_path_takes_precedence() {
        let workspace = Path::new(r"C:\workspace");
        let explicit = Path::new(r"C:\logs\net-audit.jsonl");

        assert_eq!(
            net_audit_path(workspace, Some("ignored"), Some(explicit)),
            Some(explicit.to_path_buf())
        );
    }

    #[test]
    fn session_net_audit_path_resolves_under_sandbox_dir() {
        let workspace = Path::new(r"C:\workspace");

        assert_eq!(
            net_audit_path(workspace, Some("abc123"), None),
            Some(
                workspace
                    .join(".harness")
                    .join("sandbox")
                    .join("session-abc123")
                    .join("net-audit.jsonl")
            )
        );
        assert_eq!(
            net_audit_path(workspace, Some("session-abc123"), None),
            Some(
                workspace
                    .join(".harness")
                    .join("sandbox")
                    .join("session-abc123")
                    .join("net-audit.jsonl")
            )
        );
    }

    #[test]
    fn loopback_ports_are_protocol_scoped_for_proxy_and_fake_dns() {
        let ports = net_loopback_ports_for_agents(
            Some("127.0.0.1:18080".parse().unwrap()),
            Some("127.0.0.1:18053".parse().unwrap()),
        );

        assert_eq!(
            ports,
            NetLoopbackPorts {
                tcp: vec![18053, 18080],
                udp: vec![18053],
            }
        );
    }

    #[test]
    fn loopback_ports_are_deduplicated_without_widening_protocols() {
        let ports = net_loopback_ports_for_agents(
            Some("127.0.0.1:18053".parse().unwrap()),
            Some("127.0.0.1:18053".parse().unwrap()),
        );

        assert_eq!(ports.tcp, vec![18053]);
        assert_eq!(ports.udp, vec![18053]);
    }

    #[test]
    fn net_allow_domains_are_validated_and_deduplicated() {
        let mut config = NetProxyConfig {
            allow_domains: vec!["Example.COM.".to_string()],
            ..Default::default()
        };

        validate_and_merge_net_allow_domains(
            &mut config,
            &["example.com".to_string(), "*.Trusted.Example.".to_string()],
        )
        .unwrap();

        assert_eq!(
            config.allow_domains,
            vec!["example.com".to_string(), "*.trusted.example".to_string()]
        );
    }

    #[test]
    fn net_allow_domains_reject_ip_literals_at_cli_merge_boundary() {
        let mut config = NetProxyConfig::default();

        let err = validate_and_merge_net_allow_domains(&mut config, &["127.0.0.1".to_string()])
            .unwrap_err();

        assert!(err.contains("IP literals"));
    }

    #[test]
    fn net_audit_filter_selects_kind_and_deny_only() {
        let events = vec![
            json!({
                "kind": "proxy",
                "protocol": "socks5",
                "host": "example.com",
                "allowed": true,
                "reason": "domain_allowed"
            }),
            json!({
                "kind": "fake_dns",
                "protocol": "dns_udp",
                "host": "blocked.example",
                "allowed": false,
                "reason": "domain_denied"
            }),
            json!({
                "kind": "wfp",
                "protocol": "tcp",
                "remote_addr": "198.18.0.1",
                "remote_host": "blocked.example",
                "allowed": false,
                "reason": "classify_drop"
            }),
        ];

        let filtered = filter_net_audit_events(events, Some("wfp"), true);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0]["kind"], "wfp");
        assert_eq!(filtered[0]["allowed"], false);
        assert_eq!(filtered[0]["remote_host"], "blocked.example");
    }

    #[test]
    fn net_audit_output_formats_json_jsonl_and_text() {
        let events = vec![json!({
            "kind": "wfp",
            "protocol": "tcp",
            "allowed": false,
            "remote_addr": "198.18.0.1",
            "remote_port": 443,
            "remote_host": "blocked.example",
            "reason": "classify_drop"
        })];

        let json_output = format_net_audit_output(&events, OutputFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();
        assert_eq!(parsed[0]["kind"], "wfp");

        let jsonl_output = format_net_audit_output(&events, OutputFormat::Jsonl);
        assert_eq!(jsonl_output.lines().count(), 1);
        let parsed_line: serde_json::Value = serde_json::from_str(jsonl_output.trim()).unwrap();
        assert_eq!(parsed_line["remote_host"], "blocked.example");

        let text_output = format_net_audit_output(&events, OutputFormat::Text);
        assert!(text_output.contains("wfp"));
        assert!(text_output.contains("DENY"));
        assert!(text_output.contains("blocked.example"));
        assert!(text_output.contains("classify_drop"));
    }
}
