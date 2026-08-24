use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// プロバイダへ正規化して渡すツール仕様。アダプタが各ワイヤ形式へ再ラップする。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolUse {
    pub id: String,
    pub name: String,
    pub input: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolResult {
    pub tool_use_id: String,
    pub content: String,
    pub is_error: bool,
}

/// 書込ステージング3モード（`plans/DESIGN.md` §書込ステージング3モード、M10）。
/// パーミッション層（`RiskClass`/`PermissionArbiter`）とは直交する軸で、
/// 「許可された書込の実FS効果をどこへ落とすか」だけを決める。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagingMode {
    /// 即実FS（オーバーレイ無し）。フラグ無指定時の既定（D-29、`SandboxFs`ステージングは
    /// 既定の安全策ではなくオプトインのレビュー用機能。書込/読取の実防御はシェル隔離Tier
    /// （既定Tier2a=AppContainer）に一本化する）。
    Live,
    /// 全書込staging、実FSは手動`apply`まで不変。`--staged`明示指定時のみ。
    Staged,
    /// workspace内はstaging→レビュー&コミット、workspace外は常にsandbox隔離。
    /// `--workspace-commit`明示指定時のみ。
    WorkspaceCommit,
}

/// ツールのステージング設定。`mode`をそのまま使う（M10当時あった「パス毎のgit認識型判定への
/// 委譲」は削除済み、D-29参照）。
///
/// `PartialEq`を持つのは、セッション切替（`/sessions`・`/fork`）でこの値が差し替わるように
/// なったため——「切り替わったか」を判定できないと、切替の有無をテストで固定できない
/// （`harness_sandbox::session_scope`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingConfig {
    pub mode: StagingMode,
    /// オーバーレイ・マニフェストの置き場所。**`workspace_root`からの相対パス**
    /// （例 `.harness/sandbox/<session-id>`）で持つ。オーバーレイの実体を常にworkspace内に
    /// 置くことで、`WorkspaceJail`（cap-std主ゲート）1つだけで実FS・オーバーレイの両方を
    /// 仲介できる（`harness-sandbox::SandboxFs`参照）。`None`なら純live（オーバーレイを
    /// 一切使わない、既存コードとの後方互換用）。
    pub sandbox_dir: Option<std::path::PathBuf>,
}

impl Default for StagingConfig {
    fn default() -> Self {
        Self {
            mode: StagingMode::Live,
            sandbox_dir: None,
        }
    }
}

/// 読取スコープの反転モード（`plans/DESIGN-SANDBOX.md` §5、M11）。既定は`Whitelist`
/// （安全既定＝列挙した外部ルートのみ読取可）。`Blacklist`は列挙した禁止パスのみを拒否し、
/// それ以外の外部絶対パスは読取可とする（オプトインの緩和モード）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReadMode {
    #[default]
    Whitelist,
    Blacklist,
}

/// 読取スコープ設定（M11）。`harness-sandbox::read_scope::ReadScope`が判定の実体を持つ
/// （`harness-core`は値を運ぶだけ、`StagingConfig`と同じ役割分担）。
#[derive(Debug, Clone, Default)]
pub struct ReadScopeConfig {
    pub mode: ReadMode,
    /// 読取を許可する外部ルート（workspaceは暗黙に含むためここには含めない）。
    /// 既定で直下のみ読取可（掘り下げ不可）。
    pub allow: Vec<std::path::PathBuf>,
    /// 再帰読取を許可する外部ルート。
    pub allow_descend: Vec<std::path::PathBuf>,
    /// 読取禁止（blacklistモードで使用）。絶対パス、またはworkspace内の任意の階層に現れる
    /// 名前（例 `.git`）のいずれかとして解釈する。
    pub deny: Vec<String>,
    /// 掘り下げ禁止（配下をwalkしない）。whitelist/blacklist両モードで使う
    /// （例 `node_modules`・`.git`）。
    pub deny_descend: Vec<String>,
}

/// シェル隔離Tier（M12、`plans/DESIGN-SANDBOX.md` §6）。
/// Tier2a（AppContainer）/Tier2b（bubblewrap）は既定の上限Tierとして実装済み。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellTier {
    /// Windows: Hyper-V外層VM（AlmaLinux）+ Incus内層コンテナ（`plans/DESIGN-SANDBOX-VMISOLATION.md`）。
    /// vNIC単位で出口を強制できる唯一のTier。VM起動オーバーヘッドが高いため`--sandbox tier3`
    /// で明示オプトインする。`run_shell`は`ToolCtx.vm_sandbox`経由でコンテナ内実行に
    /// 委譲する（他Tierと異なり実プロセスをホスト側にspawnしない）。
    Tier3,
    /// Linux: bubblewrap（user+mount+network namespace + OverlayFS）。
    Tier2b,
    /// Windows: AppContainer（package SID + capability SID）。範囲外書込の物理拒否に加え、network を
    /// capabilityゲートでdefault-denyにする（T-04/T-10対策の核）。
    Tier2a,
    /// Windows: Restricted Token + 低Integrity Level + Job Object。
    Tier1,
    /// 保険（cwd拘束のみ・secret env strip・timeout/出力上限、best-effort）。
    Tier0,
}

impl ShellTier {
    pub fn label(self) -> &'static str {
        match self {
            ShellTier::Tier3 => "tier3",
            ShellTier::Tier2b => "tier2b",
            ShellTier::Tier2a => "tier2a",
            ShellTier::Tier1 => "tier1",
            ShellTier::Tier0 => "tier0",
        }
    }
}

/// `--require-sandbox[=confidential]`（`plans/DESIGN-SANDBOX.md` §7 D-03）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RequireSandbox {
    #[default]
    None,
    /// 書込拘束以上（Tier3/Tier2a/Tier1/Tier2bでpass、Tier0で拒否）。
    WriteContainment,
    /// 機密性も要求（Tier3/Tier2a/Tier2bのみpass、Tier1/Tier0で拒否）。判定の実体は
    /// `harness-sandbox::shell_tier::satisfies`（§8-2の判定表）。
    Confidential,
}

/// `--sandbox <auto|tier1|tier2a|tier2a-cow|tier3>`——**ユーザーが選んだ隔離の形**。
///
/// # なぜ1本の値フラグなのか
///
/// かつては`--tier1`・`--vm-sandbox`・`--cow`という3本の独立した真偽フラグで、
/// **不正な組合せが型として表現できてしまっていた**。
///
/// - `opt_in_tier1: bool`と`opt_in_tier3: bool`の2引数は「両方真」という到達不能で
///   あるべき状態を持てた。それを防いでいたのは`shell_tier.rs`の分岐の**順序だけ**である
///   （clapの`conflicts_with`は本番のargvしか見ないので、ライブラリ呼び出しには効かない）。
/// - `--cow`はTierを要求できない独立の真偽フラグだったため、`--tier1 --cow`のような
///   「Tier2a以外でのCoW」が受理された。ACLを一度も触らないまま「workspaceはread-only」と
///   モデルへ宣言する経路で、[BUG-113](../../../docs/bugs/BUG-113.md)として記録されている。
///
/// **不正な組合せを表現できないことがこの型の役目である。** 値は排他なので、
/// 「Tier1なのにCoW」も「Tier1かつTier3」も書けない。
///
/// **ただし、この型だけでBUG-113の形が消えるわけではない。** `select_tier`は
/// `choice`と`write_mode`を**独立した2引数**で受けるので、ライブラリ境界では
/// `select_tier(Tier1, Cow{..})`が今も書ける。CLIから作れないのは、両方が
/// `harness-cli`の`setup::resolve_staging_and_write_mode`という**1回の呼び出しから出る**
/// ためであって、型が禁じているからではない。保証の在り処を取り違えないこと——
/// 対を1つの値へ畳むまでは、ここは「CLIの配線が守っている」段階である。
///
/// clapの`ValueEnum`はここには付けない（`harness-core`はCLIフレームワークに依存しない）。
/// CLI表面の綴りは`harness-cli`の`SandboxChoiceArg`が持ち、[`SandboxChoice::value_label`]と
/// 綴りが一致することを同クレートのテストが検算する（`bug-pattern-rules` B-05）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SandboxChoice {
    /// 既定。Tier2aを常時プローブし、届かなければ昇格可否で分岐する（従来のフラグ無指定）。
    /// 昇格**できない**アカウントだけがTier0へ宣言付きで降格する。
    #[default]
    Auto,
    /// preflightを通さずTier1へ固定する逃がし弁（従来の`--tier1`）。
    Tier1,
    /// Tier2aを要求する。届かなければ起動を拒否する（**新設**。従来は表現できなかった）。
    Tier2a,
    /// Tier2a + Copy-on-Write（D-30）を要求する。Tier2aへ届かなければ起動を拒否する
    /// （従来の`--cow`）。**「届かなければ拒否」が従来との差**で、旧`--cow`は
    /// Tier1/Tier3/Tier0へ着地してもCoWを名乗り続けていた（BUG-113）。
    Tier2aCow,
    /// Tier3を優先し、不成立ならTier2aへカスケードする（従来の`--vm-sandbox`）。
    Tier3,
}

impl SandboxChoice {
    /// **全variantの列挙。** CLI表面の綴り（`harness-cli`の`SandboxChoiceArg`）が
    /// この型の全variantを覆っていることを、あちら側のテストが本配列で確かめる
    /// ——覆えていないvariantは「CLIから選べない値」で、無言で存在しないのと同じになる。
    ///
    /// **手書きのリストを別の場所に作らないこと**（B-05）。下の[`SandboxChoice::index_in_all`]と
    /// `const _`ブロックが、variantの追加・順序違い・重複をコンパイル時に落とす
    /// （`harness_sandbox::FsAccess::ALL`と同じ2段ゲート）。
    pub const ALL: [SandboxChoice; 5] = [
        SandboxChoice::Auto,
        SandboxChoice::Tier1,
        SandboxChoice::Tier2a,
        SandboxChoice::Tier2aCow,
        SandboxChoice::Tier3,
    ];

    /// [`SandboxChoice::ALL`]の網羅性を**コンパイル時に**強制するためだけの写像。
    const fn index_in_all(self) -> usize {
        match self {
            SandboxChoice::Auto => 0,
            SandboxChoice::Tier1 => 1,
            SandboxChoice::Tier2a => 2,
            SandboxChoice::Tier2aCow => 3,
            SandboxChoice::Tier3 => 4,
        }
    }

    /// `--sandbox`へ渡す値の綴り。**エラーメッセージが「何を指定したせいでこうなったか」を
    /// 名指しするために要る**（`--sandbox tier2a`は降格しない、と言うために）。
    pub fn value_label(self) -> &'static str {
        match self {
            SandboxChoice::Auto => "auto",
            SandboxChoice::Tier1 => "tier1",
            SandboxChoice::Tier2a => "tier2a",
            SandboxChoice::Tier2aCow => "tier2a-cow",
            SandboxChoice::Tier3 => "tier3",
        }
    }

    /// Copy-on-Write（D-30）を要求する指定か。
    ///
    /// 「Tier2aへ**必ず**着地しなければならないか」（`Tier2a`と`Tier2aCow`）を判定する述語は
    /// **あえて置いていない**。それを判定している場所は
    /// `harness_sandbox::shell_tier::best_effort_tier`のOSごとの`match`ただ1つで、そこは
    /// `_`を持たない網羅マッチである——述語へ逃がすと、variantを足したときに
    /// 「どちらに倒すか」を決め忘れてもコンパイルが通ってしまう（`bug-pattern-rules` B-06）。
    pub fn wants_cow(self) -> bool {
        matches!(self, SandboxChoice::Tier2aCow)
    }
}

/// [`SandboxChoice::ALL`]が全variantを過不足なく1回ずつ持つことの**コンパイル時**検算。
const _: () = {
    let mut i = 0;
    while i < SandboxChoice::ALL.len() {
        assert!(SandboxChoice::ALL[i].index_in_all() == i);
        i += 1;
    }
};

/// `harness-sandbox::shell_tier::select_tier`の結果。`ToolCtx`が運ぶ「値」であり、
/// 判定ロジックの実体（OS能力プローブ）は`harness-sandbox`側にある
/// （`StagingConfig`/`ReadScopeConfig`と同じ役割分担）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellTierSelection {
    pub tier: ShellTier,
    pub downgraded_from: Option<ShellTier>,
    pub reason: Option<String>,
    /// D8（`plans/DESIGN-SANDBOX-APPPOLICY.md`補遺・fs passthrough）: 到達不能だった
    /// `--fs-allow`穴の診断メッセージ一覧。空なら全穴到達可、または該当なし。Tier選択自体
    /// （`tier`/`downgraded_from`）には影響しない（壊れた穴があってもTier2a・workspaceは継続）。
    pub passthrough_warnings: Vec<String>,
    /// D8: 到達不能/付与失敗だったfs passthroughの構造化リスト。
    /// `harness-cli`はこれをユーザグローバル台帳へ記録し、後から`.harness/settings.json`の
    /// `fs.read`/`fs.read_write`/`fs.read_exec`へ追加するための材料として表示する。
    pub denied_passthrough: Vec<(std::path::PathBuf, String, String)>,
    /// `--fs-allow`/`fs.allow`のうち、実際にACE付与が確認できた（既存で十分だった場合を含む）
    /// ルートの一覧（`(path, writable)`）。`harness-cli`側の台帳記録はこれだけを書くことで、
    /// `ACCESS_DENIED`で失敗したのに記録だけ残る「幻の台帳エントリ」を防ぐ
    /// （`TIER1A-PRIVHELPER-HANG.md`「引き継ぎTODO: --fs-allowの特権分離ヘルパー化」）。
    pub granted_passthrough: Vec<(std::path::PathBuf, bool)>,
    /// WFP連鎖起動（`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`付録D シナリオ(A)）を
    /// `preflight`が実際に試みたか。`true`なら呼び出し元（`harness-cli`）は特権分離ヘルパー
    /// 経由で`harness-netfilterd`が起動済み（またはベストエフォートで失敗済み）と見なし、
    /// シナリオ(B)（直接`runas`起動）を重ねて行わない。`false`なら連鎖起動を試みていないため、
    /// ドメインポリシー監査が有効ならシナリオ(B)へフォールバックする必要がある。
    pub netfilterd_chain_attempted: bool,
}

impl ShellTierSelection {
    pub fn direct(tier: ShellTier) -> Self {
        Self {
            tier,
            downgraded_from: None,
            reason: None,
            passthrough_warnings: Vec::new(),
            denied_passthrough: Vec::new(),
            granted_passthrough: Vec::new(),
            netfilterd_chain_attempted: false,
        }
    }

    pub fn downgraded(from: ShellTier, to: ShellTier, reason: impl Into<String>) -> Self {
        Self {
            tier: to,
            downgraded_from: Some(from),
            reason: Some(reason.into()),
            passthrough_warnings: Vec::new(),
            denied_passthrough: Vec::new(),
            granted_passthrough: Vec::new(),
            netfilterd_chain_attempted: false,
        }
    }

    /// D8: fs passthroughの到達不能診断を積む（`direct`/`downgraded`と組み合わせて使う）。
    pub fn with_passthrough_warnings(mut self, warnings: Vec<String>) -> Self {
        self.passthrough_warnings = warnings;
        self
    }

    /// 到達不能/付与失敗だったpassthroughルートの一覧を積む。
    pub fn with_denied_passthrough(
        mut self,
        denied: Vec<(std::path::PathBuf, String, String)>,
    ) -> Self {
        self.denied_passthrough = denied;
        self
    }

    /// 実際にACE付与が確認できたpassthroughルートの一覧を積む（`direct`と組み合わせて使う。
    /// `preflight`が失敗した`downgraded`経路では常に空のまま）。
    pub fn with_granted_passthrough(mut self, granted: Vec<(std::path::PathBuf, bool)>) -> Self {
        self.granted_passthrough = granted;
        self
    }

    /// WFP連鎖起動を`preflight`が試みたかを積む（`direct`と組み合わせて使う）。
    pub fn with_netfilterd_chain_attempted(mut self, attempted: bool) -> Self {
        self.netfilterd_chain_attempted = attempted;
        self
    }

    /// 非隔離（Tier0）かどうか。`run_shell`出力への警告付与判定に使う
    /// （M12受入条件「非隔離時警告」）。
    pub fn is_unisolated(&self) -> bool {
        self.tier == ShellTier::Tier0
    }
}

impl Default for ShellTierSelection {
    /// `ToolCtx::new`（テスト等）向けの既定値。実際の選択は`harness-sandbox::select_tier`が行う。
    fn default() -> Self {
        Self::direct(ShellTier::Tier0)
    }
}

/// ドメイン単位network制御設定（`plans/AppContainerを用いたドメインベース通信制御アーキテクチャ設計書.md`）。
/// `run_shell`子へ`ALL_PROXY=socks5h://...`と`HTTP_PROXY`/`HTTPS_PROXY`を注入するLocal Proxy
/// Agentの許可ドメインを運ぶ。Tier2aでWFP default-deny + loopback実ポート限定allowを併用できる
/// 場合のみ、Proxy非対応の直接connect/raw socketも強制的に遮断できる。WFPが無いTierや
/// `enforced_by_wfp=false`では協調Proxyに留まり、その限界は`run_shell`出力へ明記する。
/// `harness-core`は値を運ぶだけ、判定・Proxy/Fake DNS実体は`harness-tools`、WFP強制は
/// `harness-sandbox`が担う（`StagingConfig`/`ReadScopeConfig`と同じ役割分担）。
#[derive(Debug, Clone)]
pub struct NetProxyConfig {
    /// 許可ドメイン（`*.example.com`形式のサフィックスワイルドカードに対応）。空なら
    /// `domain_policy_enabled=true`のもとで全拒否ポリシーとして扱う。
    pub allow_domains: Vec<String>,
    /// ドメイン単位network制御を起動するか。既定true: 許可ドメインが空でもProxy/Fake DNS/WFP
    /// 監査経路を起動し、全拒否を`net-audit.jsonl`へ残す。falseはテスト・内部互換用。
    pub domain_policy_enabled: bool,
    /// Tier2aでWFP default-deny + loopback allowが有効化されており、Proxy経由通信に必要な
    /// AppContainer network capabilityを安全に付与できるか。falseならfail-closedのため、
    /// `--net-allow-domain`だけではTier2a子へ`internetClient`を付けない。
    pub enforced_by_wfp: bool,
    /// 詳細監査ログのJSONL出力先。`None`なら従来通りプロセス内メモリの短いサマリだけを保持する。
    pub audit_log_path: Option<std::path::PathBuf>,
    /// CLIがセッションスコープで先に起動したLocal Proxy Agentの待受アドレス。`Some`なら
    /// `run_shell`は新規Proxyを起動せず、このアドレスを子プロセスenvへ注入する。
    pub proxy_addr: Option<std::net::SocketAddr>,
    /// CLIがセッションスコープで先に起動したFake DNS Agentの待受アドレス。`Some`なら
    /// `run_shell`は新規Fake DNSを起動せず、このアドレスを診断envへ注入する。
    pub fake_dns_addr: Option<std::net::SocketAddr>,
    /// CONNECT/SOCKS5トンネル内のTLSをどこまで検査するか（`harness_tools::tunnel::TunnelHandler`の
    /// 実装選択に対応）。既定`Sni`はClientHelloのSNI/ALPNのみを見て復号しない。
    pub tls_inspection: TlsInspection,
}

/// CONNECT/SOCKS5トンネル内のTLS検査強度。`harness_tools::tunnel`の`TunnelHandler`実装選択に
/// 対応する。バリアントを追加する実装者は、このenumを`match`で分解している箇所（本ファイルの
/// `Default`実装、`crates/harness-core/src/prompt.rs`の`render_net_proxy`）が全て追随することを
/// 確認すること——特に復号を伴うバリアントを追加する場合は、通信内容が復号され監査ログに残る旨を
/// 必ずシステムプロンプトへ宣言すること（`plans/DESIGN-SANDBOX-PRIVSEP.md` D-32）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsInspection {
    /// ClientHelloのSNI/ALPNのみallowlist評価する。トンネル内容は復号しない。
    Sni,
}

impl Default for NetProxyConfig {
    fn default() -> Self {
        Self {
            allow_domains: Vec::new(),
            domain_policy_enabled: true,
            enforced_by_wfp: false,
            audit_log_path: None,
            proxy_addr: None,
            fake_dns_addr: None,
            tls_inspection: TlsInspection::Sni,
        }
    }
}

/// アプリ単位network制御設定（軸1、`plans/DESIGN-SANDBOX-APPPOLICY.md` D-10/D-11）。
/// Tier2a（AppContainer）で、先頭exe名が`allow_apps`に一致する信頼コマンドにのみ
/// `internetClient` capabilityを付与するための許可リストを運ぶ。空なら常にdeny（既定・
/// 現状維持＝network全遮断）。判定（`classify_net_app`）とcapability適用は`harness-tools`/
/// `harness-sandbox`側で行い、`harness-core`は値を運ぶだけ（`NetProxyConfig`と同じ役割分担）。
///
/// **Tier2a限定**: Tier3/Tier2b/Tier1/Tier0はAppContainer capability機構を持たないため、これらのTierでは`allow_apps`は
/// 効かない（`run_shell`がその旨をフッタに明記する）。
#[derive(Debug, Clone, Default)]
pub struct NetAppPolicy {
    /// 信頼アプリの実行ファイル名リスト（basename・拡張子除去・小文字で照合。例`git`/`npm`）。
    /// インタプリタ/スクリプト名を入れると中身が呼ぶ全通信が通る（T-15、子孫全継承）ため、
    /// 具体的で狭い実行ファイル名のみを推奨する（D-11）。
    pub allow_apps: Vec<String>,
}

/// Tier3（`ShellTier::Tier3`）の`run_shell`実行チャネル。開いた集合（実装は`harness-sandbox`が
/// 持つ、Hyper-V VM + Incusコンテナへの生きたIPCハンドル）を`harness-core`の「重い依存ゼロ」
/// 原則を保ったまま`ToolCtx`へ運ぶためのtrait境界（`LlmProvider`/`Tool`と同じ設計原則、
/// `CLAUDE.md`「変動点を2つのtrait境界に押し込む」参照）。同期メソッドなのは、実体が
/// `harness-sandbox::vmsandboxd::VmSandboxHandle`のブロッキングWin32名前付きパイプIPC
/// （`crate::netfilterd`と同型）であるため。呼び出し元（`harness-tools::shell`）は
/// `tokio::task::spawn_blocking`越しに呼ぶ。
pub trait VmShellExecutor: Send + Sync + std::fmt::Debug {
    /// コンテナ内で`cmd`を実行し、標準出力・標準エラー・終了コードを返す。`cwd`は
    /// ワークスペースルートからの相対パスとしてコンテナ内`/workspace`配下へマッピングされる
    /// （実際のマッピングは`harness-sandbox::vmsandbox`側の責務）。
    fn exec(
        &self,
        cmd: &str,
        cwd: &std::path::Path,
        env: &[(String, String)],
        timeout: std::time::Duration,
    ) -> Result<(String, String, Option<i32>), String>;
}

/// 起動中のMCPサーバ1件について、モデルへ伝える事実（M15.5、`plans/DESIGN-MCP.md`）。
///
/// MCPサーバのツールは組み込みツールと同じ姿で`ToolRegistry`に載るが、**実体は第三者プロセス
/// であり、それぞれ別のサンドボックス（別package SID）で動き、到達できる先が違う**。モデルが
/// 「なぜこのツールはネットワークに出られてあのツールは出られないのか」を説明できる必要が
/// あるため、`EnvironmentFacts`が宣言する（`crates/harness-core/src/prompt.rs`）。
///
/// 値の生成は`harness-mcp`の`McpRuntime::facts`が行う（`harness-core`は「重い依存ゼロ」原則の
/// ため値を運ぶだけ、`StagingConfig`/`ReadScopeConfig`と同じ役割分担）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServerFact {
    /// 宣言のid（ツール名`mcp__<id>__<tool>`の中央部分）。
    pub id: String,
    /// このサーバだけが到達できる許可ドメイン。空なら外向き通信は一切できない。
    pub allow_domains: Vec<String>,
    /// ワークスペースへのアクセス（`none` / `read` / `read-write`）。既定は`none`
    /// （MCPサーバにはworkspaceへのACEを一切付けない、`DESIGN-MCP.md` §3.2）。
    pub workspace_access: String,
    /// 登録されたツール名（名前空間付き）。
    pub tool_names: Vec<String>,
    /// `stdio` | `streamable_http`（M15.6、`DESIGN-MCP.md` §6）。
    pub transport: String,
    /// Streamable HTTPのときの接続先（`host[:port]/path`）。stdioでは`None`。
    ///
    /// **これが`Some`のサーバはサンドボックスの外にある**（D-50）。`allow_domains`は
    /// AppContainer子の宛先制御を表す値なのでHTTPでは常に空になり、この項目が無いと
    /// システムプロンプトが「外向き通信は不可」と事実に反する説明をしてしまう。
    pub endpoint: Option<String>,
}

/// 実行前ゲート（`PermissionArbiter`）が参照するリスク分類。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    ReadOnly,
    Write,
    Exec,
    Network,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolOutput {
    pub content: String,
    pub is_error: bool,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ToolError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("execution failed: {0}")]
    ExecutionFailed(String),
    #[error("cancelled")]
    Cancelled,
}

/// ツール実行のコンテキスト。ジェイル・キャンセル・イベント通知への足がかり。
/// 具体的な実装（cap-std の `Dir` ハンドル等）は `harness-sandbox`/`harness-engine` が注入する
/// （`harness-core` は「重い依存ゼロ」原則のためワークスペースルートはパスのみで表現する）。
#[derive(Debug, Clone)]
pub struct ToolCtx {
    pub workspace_root: std::path::PathBuf,
    /// 書込ステージング設定（M10）。既定（`StagingConfig::default()`）は純live＝
    /// M9までと等価な直接実FSアクセス。
    pub staging: StagingConfig,
    /// 読取スコープ設定（M11）。既定（`ReadScopeConfig::default()`）はwhitelistかつ
    /// 外部ルート未設定＝M10までと等価（workspace外の絶対パス読取は一切不可）。
    pub read_scope: ReadScopeConfig,
    /// シェル隔離Tier選択結果（M12）。既定（`ShellTierSelection::default()`＝Tier0）は
    /// `harness-sandbox::select_tier`を呼ばないテスト経路向けのプレースホルダで、
    /// 実行時は`harness-cli`が起動時に1回選択した値を積む。
    pub shell_tier: ShellTierSelection,
    /// 協調プロキシ設定（M12補遺、`plans/DESIGN-SANDBOX-PRIVSEP.md` §3.1 D-15）。既定
    /// （`NetProxyConfig::default()`＝空allowlistの全拒否監査）はプロキシを起動する。
    pub net_proxy: NetProxyConfig,
    /// アプリ単位network制御（軸1、D-10/D-11）。既定（`NetAppPolicy::default()`＝`allow_apps`空）は
    /// 常にdeny（Tier2a子はcapability空でnetwork全遮断＝現状維持）。
    pub net_app: NetAppPolicy,
    /// `run_shell`子プロセスのclean envにあるPATHへ追記するディレクトリ一覧。設定ファイル由来の
    /// 非シークレット値だけを運び、任意env転送は行わない。
    pub run_shell_path_extra: Vec<String>,
    /// `run_shell`で起動される子が、直前の`write_file`/`edit_file`によるstaging上の変更を
    /// 読めるかどうか。既定はfalse（多くのTierは実FSだけを見る）で、Tier3+CIFSライブ共有の
    /// ようにstaging変更が子から見える経路だけ呼び出し側がtrueへ上書きする。
    pub shell_sees_staged_writes: bool,
    /// Tier3実行チャネル（`ShellTier::Tier3`選択時のみ`Some`）。`net_wfp`（`harness-cli`の
    /// `main()`ローカル変数、`ToolCtx`を経由しない設計）とは異なり、こちらは`run_shell`の
    /// 呼び出しのたびに実際に使われる（VM/コンテナへコマンドを都度送る必要があるため）ので
    /// `ToolCtx`を経由させる。`Arc`は`ToolCtx`が`Clone`である前提（既存フィールドと同様、
    /// 生ハンドルではなく共有可能な参照を運ぶ）。
    pub vm_sandbox: Option<std::sync::Arc<dyn VmShellExecutor>>,
    /// `--sandbox tier2a-cow`（D-30）指定時のCoW 差分層ディレクトリ（workspace外）。`Some`はTier2aで
    /// workspaceがRead/Execute/Traverseのみ（RO）で付与されており、`run_shell`子プロセスの
    /// 書込はRedirector DLLによりこのディレクトリへ誘導される（フック失敗時はACLにより
    /// `ACCESS_DENIED`でfail-close、`plans/DESIGN-SANDBOX.md §7 D-30`）。`None`は既定
    /// （D-29、workspace RW直接）。
    pub cow_diff_layer_dir: Option<std::path::PathBuf>,
    /// 起動中のMCPサーバ（M15.5、`plans/DESIGN-MCP.md`）。空なら宣言が無いか、いずれも
    /// 承認されていないか、このOSでは起動しない（P-05）。
    pub mcp_servers: Vec<McpServerFact>,
}

impl ToolCtx {
    /// live既定（オーバーレイ無し）・読取スコープ既定（外部ルート無し）で`ToolCtx`を作る。
    /// 既存の`ToolCtx { workspace_root }`呼び出し箇所（主にテスト）の置き換え先。
    pub fn new(workspace_root: std::path::PathBuf) -> Self {
        Self {
            workspace_root,
            staging: StagingConfig::default(),
            read_scope: ReadScopeConfig::default(),
            shell_tier: ShellTierSelection::default(),
            net_proxy: NetProxyConfig::default(),
            net_app: NetAppPolicy::default(),
            run_shell_path_extra: Vec::new(),
            shell_sees_staged_writes: false,
            vm_sandbox: None,
            cow_diff_layer_dir: None,
            mcp_servers: Vec::new(),
        }
    }
}

/// 変動点（ツール実装）を隠す唯一のtrait境界。開いた集合なので trait object で拡張可能。
#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    /// schemars + strict変換で生成する入力スキーマ。
    fn input_schema(&self) -> serde_json::Value;
    /// モデルへ渡すツール仕様。既定では静的な説明・スキーマを返すが、`run_shell`のように
    /// 実行環境（Tier等）でモデルに見える意味が変わるツールはここを上書きする。
    fn spec_for_ctx(&self, ctx: &ToolCtx) -> ToolSpec {
        let _ = ctx;
        ToolSpec {
            name: self.name().to_string(),
            description: self.description().to_string(),
            input_schema: self.input_schema(),
        }
    }
    /// 実行前ゲート。具体入力（実際のコマンド行/書込先）に基づき申告する。
    fn risk(&self, input: &serde_json::Value) -> RiskClass;
    async fn call(&self, input: serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError>;
}

/// [BUG-082フォローアップ] ツール呼び出しが実際の処理に入る**前**、何らかの背景条件で
/// 無反応に見えている理由を説明できるもの（例: D-54のworkspace ACL伝播ジョブ）。
///
/// 開発者は「初回起動でrun_shellがACL伝播を待つ」ことを知っているが、一般利用者から見ると
/// ツールカードが理由も無く"running"のまま数十秒動かないのは起動失敗と区別が付かない
/// （`docs/bugs/BUG-082.md`のユーザー報告）。この trait はその理由を**汎用の形**で外へ出す
/// ための唯一の境界であり、`grant_job`のような個々の背景ジョブがこれを実装することで、
/// 呼び出し側（`harness-engine`のツール実行ループ）は「何が原因か」を一切知らないまま
/// 待機理由をポーリングして`AgentEvent::ToolProgress`へ変換できる。**将来、他の背景条件
/// （例: 昇格ヘルパーの起動待ち）が増えても、この trait を実装する側が増えるだけで、
/// 呼び出し側の変更は不要**（`docs/CODE-STRUCTURE-RULES.md`規則5の「同じヘルパーの複製を
/// 作らない」を待機理由の集約という形で満たす）。
pub trait WaitReason: Send + Sync {
    /// 今まさに何かを待たせているなら、その状態を返す。待たせていなければ`None`。
    ///
    /// **待たせているかどうかの判定はこの1メソッドだけが持つ。** 説明文と進捗を別々の
    /// メソッドで返す形にすると「終わっていたら`None`」の判定が2箇所に生まれ、片方だけが
    /// 更新されて食い違う（`bug-pattern-rules` B-02: 対の片方だけ実装する）。実際、TUIの
    /// ステータスバーが`grant_job::progress()`を直接読んでいた頃は、まさにその二重実装が
    /// あった（`refactor-perspectives` R-01）。
    ///
    /// 呼び出し側は**33msごと**（TUIの描画tick）に呼び得るので、重い処理（実際のI/O等）を
    /// ここで行わないこと——既存の状態を読むだけに留める。
    fn active(&self) -> Option<WaitState>;
}

/// 「今なぜ待たされているか」の1件分。表示文字列は**具象側（`grant_job`等）が作る**——
/// どの背景ジョブかによって言い回しが全く変わるドメイン固有の知識であり、汎用の側へ
/// 持ち上げても結局どこかの具象に置くことになる（`refactor-perspectives` R-01の「誤検出」節）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitState {
    /// ツールカードへ出す一文（`AgentEvent::ToolProgress`として流れる）。
    pub description: String,
    /// ステータスバーのような狭い場所へ出す短い一行。
    ///
    /// **百分率や件数を組み立てるのも具象側の仕事**にしてある。ここに`(done, total)`を
    /// 生で持たせて表示側で組み立てさせると、「件数が未確定の段では出さない」という判定が
    /// 表示面の数だけ複製される（旧実装がまさにそれで、`total > 0`のガードがTUIと
    /// `grant_job`の両方にあった）。表示面が増えても具象側の1箇所だけを見ればよい形に保つ。
    pub label: String,
}

/// [`WaitReason`]の集合。**最初に何か言ってきたものが勝つ**（複数の待機理由を1行に
/// 合成すると長くなり、かえって分かりにくいため）。
#[derive(Clone, Default)]
pub struct WaitReasons(std::sync::Arc<[std::sync::Arc<dyn WaitReason>]>);

impl WaitReasons {
    pub fn new(sources: Vec<std::sync::Arc<dyn WaitReason>>) -> Self {
        Self(sources.into())
    }

    /// 登録済みの`WaitReason`を順に問い合わせ、最初に`Some`を返したものを返す。
    pub fn active_state(&self) -> Option<WaitState> {
        self.0.iter().find_map(|source| source.active())
    }

    /// [`Self::active_state`]の説明文だけを取る便宜メソッド。**どの源が勝つかは
    /// `active_state`と必ず同じ**（同じ関数から導いているため、選ばれる源が食い違わない）。
    pub fn describe_active(&self) -> Option<String> {
        self.active_state().map(|state| state.description)
    }
}
