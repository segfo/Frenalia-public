//! MCPサーバ宣言の型・検証・**承認ハッシュ**（`plans/DESIGN-MCP.md` §4）。
//!
//! このモジュールはI/Oを一切行わない。宣言は設定ファイル（`harness-config`）から来て、
//! 承認台帳との照合（[`crate::approval`]）と起動計画（[`crate::runtime`]）が使う。
//!
//! ## ハッシュ対象が「宣言の全体」である理由
//!
//! `DESIGN-MCP.md` §4.2は、承認の照合対象を **id・トランスポート種別・実行ファイル・引数・
//! 環境変数・per-tool RiskClass宣言・networkポリシー・workspace要求** と定める。承認は
//! 「この宣言を起動してよい」の記録であって「このサーバは安全である」の記録ではないので、
//! 起動されるプロセスの姿を決める要素が1つでも変われば別の宣言として扱い、再承認を求める。
//!
//! したがって[`McpServerDecl`]へフィールドを足すときは、[`McpServerDecl::approval_hash`]の
//! `Canonical`構造体へも必ず足すこと。**足し忘れると「承認済みの宣言を書き換えて別の挙動を
//! させる」経路になる**——`Canonical`を`..`無しで完全分解しているのはそのためで、
//! フィールドを足すとコンパイルエラーになる。

use std::collections::BTreeMap;

use harness_core::RiskClass;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 承認台帳へ記録する、**宣言の形の版**（`DESIGN-MCP.md` §4.2）。
///
/// # 何のために在るのか
///
/// [`McpServerDecl`]へフィールドを足すと、[`McpServerDecl::approval_hash`]が変わって
/// **既存の承認が一斉に失効する**。これは意図した動作（挙動が無言で変わらない代償）だが、
/// 失効の理由を伝える手段が無いと、ユーザーには
/// **「あなたが宣言を書き換えたので失効した」という嘘**として届く。
///
/// この版はそこを塞ぐ。**版が古い承認は「無かったもの」として扱う**ので、断り文は
/// 既存の「宣言はあるが未承認」1本で足りる——**その文は、本人が同時に宣言を
/// 書き換えていた場合でも正しい**。新しい断り文も新しい状態も作らない。
///
/// # 次にフィールドを足すときも同じ手順である
///
/// 1. この定数を1つ上げる
/// 2. 起動時に出す1行（`harness-cli`の`prepare_mcp_servers`）へ、増えた欄の名前を書く
///
/// **版ごとの分岐を書かない。** ここが持っているのは「現行かどうか」だけで、
/// 「1から2へ何が変わったか」は持たない——持つと、足すたびに分岐が1つ増える。
///
/// | 版 | 何が違うか |
/// |---|---|
/// | 1 | `process`を持たない（版そのものが無かった頃。台帳では`None`として現れる） |
/// | 2 | `process`（`DESIGN-MAC-DOMAIN.md` §22.2.2）を持つ |
pub const DECL_FORMAT_VERSION: u32 = 2;

/// [`DECL_FORMAT_VERSION`]がこの版で増やした欄の名前。**起動時に出す1行が使う唯一の文字列**で、
/// 版を上げるときはここも一緒に書き換える（版ごとの分岐を作らないための1本化）。
pub const DECL_FORMAT_VERSION_ADDED_FIELD: &str = "process";

/// ツール名全体（`mcp__<server>__<tool>`）の上限。Anthropic/OpenAIのツール名は
/// `^[a-zA-Z0-9_-]{1,64}$`（`plans/DESIGN.md` §ツールシステム）。
pub const MAX_TOOL_NAME_LEN: usize = 64;

/// サーバidの上限。`harness.mcp.<session-token>.<server-id>`がAppContainerプロファイル名の
/// 64文字上限に収まるようにするための値でもある（接頭辞12 + トークン約16 + 区切り1 = 約29）。
pub const MAX_SERVER_ID_LEN: usize = 32;

/// ツール名の区切り。`DESIGN.md` §ツールシステム参照（`/`はプロバイダが受け付けない）。
pub const TOOL_NAME_PREFIX: &str = "mcp__";
pub const TOOL_NAME_SEPARATOR: &str = "__";

/// トランスポート種別（D-41）。既定はstdio。
///
/// **`StreamableHttp`はharness本体が直接喋る経路**で、AppContainerの箱の外にある（§6.2）。
/// したがってWFPの`FWPM_CONDITION_ALE_PACKAGE_ID`条件にも協調プロキシにも掛からない。
/// 有効化がユーザー層設定/CLIからのオプトインなのはこのため（D-49）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTransportKind {
    #[default]
    Stdio,
    StreamableHttp,
}

impl McpTransportKind {
    pub fn label(self) -> &'static str {
        match self {
            McpTransportKind::Stdio => "stdio",
            McpTransportKind::StreamableHttp => "streamable_http",
        }
    }
}

/// サーバのworkspace要求（`DESIGN-MCP.md` §3.2）。既定は`None`＝ACEを一切付けない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpWorkspaceAccess {
    #[default]
    None,
    Read,
    ReadWrite,
}

/// サーバが**子プロセスを生成してよいか**（`DESIGN-MCP.md` §3.2、正本は
/// `DESIGN-MAC-DOMAIN.md` §22.2.2）。既定は`Deny`。
///
/// # なぜ既定が`Deny`なのか
///
/// AppContainerのcapabilityは**トークン属性でプロセスツリー全体が継承する**（T-15）。したがって
/// `network`を宣言したサーバが子を自由に生めると、**そのegressを持つ子を好きなだけ生める**
/// ——D-38がサーバ単位に絞ったはずの権限が、サーバが選んだ任意のコードへ渡る。
/// 既定を`Broker`にすると、統制が要るサーバほど何も宣言しないまま素通りする。
///
/// # 今日の意味と、`CHILD_PROCESS_RESTRICTED`適用後の意味は違う
///
/// | | 今日（段階⑤の前） | `CHILD_PROCESS_RESTRICTED`適用後 |
/// |---|---|---|
/// | `Deny` | spawn要求用capabilityを積まない＝Spawn Daemonの要求受付パイプへ**到達できない**。ただしOSの緩和策をまだ積んでいないので、**サーバ自身は直接子を生める** | 加えてOSが子プロセス生成そのものを拒否する（二重のdeny） |
/// | `Broker` | capabilityを積むので窓口へ**届く**。ただし遷移ポリシーの評価が未実装（段階E）なので、答えは常に`unknown_source_domain`である | Daemon経由の遷移としてポリシーが判定する |
///
/// **「宣言したから今日から窓口経由になる」ではない。** いま`Broker`が変えるのは
/// 「窓口に話しかけられるか」だけで、子プロセスの作られ方は変わらない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpProcessAccess {
    #[default]
    Deny,
    Broker,
}

impl McpProcessAccess {
    pub fn is_deny(self) -> bool {
        matches!(self, McpProcessAccess::Deny)
    }
}

/// サーバのnetwork要求（`DESIGN-MCP.md` §3.2）。既定は全拒否。
///
/// `allow_domains`が空でない場合、**そのサーバ専用の協調プロキシ**が1つ立ち、WFPはその
/// サーバのpackage SIDに対しそのプロキシのポートだけを許可する（§3.2の判断B）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpNetworkDecl {
    #[serde(default)]
    pub allow_domains: Vec<String>,
}

impl McpNetworkDecl {
    pub fn is_deny(&self) -> bool {
        self.allow_domains.is_empty()
    }
}

/// 1つのMCPサーバ宣言。設定ファイルの`mcp.servers[]`1件に対応する。
///
/// **トランスポートごとに意味を持つ項目が違う**（stdioは`command`/`args`/`env`/`network`/
/// `workspace`、Streamable HTTPは`url`/`headers`）。他方の項目が書かれていたら
/// [`McpServerDecl::validate`]がエラーにする——書いても効かない項目を黙って無視すると、
/// 「設定したのに効かない」に気付けないため（[`parse_mcp_settings`]と同じ方針）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServerDecl {
    pub id: String,
    #[serde(default)]
    pub transport: McpTransportKind,
    /// 【stdio】起動する実行ファイル。**ここに書かれたものをharnessがそのまま起動する**ので、
    /// 承認台帳（D-39）の照合対象の中核である。
    #[serde(default)]
    pub command: String,
    /// 【stdio】
    #[serde(default)]
    pub args: Vec<String>,
    /// 【stdio】サーバへ渡す追加環境変数。harness自身のenvは継承させない（clean env）。
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// 【HTTP】接続先のMCPエンドポイント。**このホストが承認・allowlistの対象**であり、
    /// リダイレクトを追わない（D-49）ので、実際に喋る相手はここに書かれたホストだけになる。
    #[serde(default)]
    pub url: String,
    /// 【HTTP】毎リクエストに付ける追加ヘッダ。値に`${env:NAME}`と書くと起動時にharness自身の
    /// 環境変数から解決する（[`crate::http_wire::expand_headers`]）。
    ///
    /// **承認ハッシュ・[`McpServerDecl::describe`]が見るのは展開前の文字列**なので、
    /// トークンの実値は承認台帳にもプロンプトにも出ない。
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// 【HTTP】サーバ証明書のピン（`sha256:<64桁の16進>`。D-52）。
    ///
    /// 指定すると、**通常の証明書検証（CA連鎖と名前）の代わりに**「提示された証明書のDERの
    /// SHA-256がこの値と一致すること」だけを見る。私有CAを立てられない社内サーバの
    /// 自己署名証明書を、OS証明書ストアを触らずに、しかも**その1枚に限って**受け入れるための
    /// 経路である（SSHの`known_hosts`と同じモデル）。
    ///
    /// 省略時（`None`）は通常の検証。**「検証しない」という選択肢はどちらにも無い。**
    #[serde(default)]
    pub tls_pin: Option<String>,
    /// per-tool `RiskClass`宣言（D-40）。**ここに無いツールは非readとして扱う**ので、
    /// 空でも宣言として妥当（すべてのツールがパーミッションゲートを通るだけ）。
    #[serde(default)]
    pub tools: BTreeMap<String, RiskClass>,
    /// 【stdio】
    #[serde(default)]
    pub network: McpNetworkDecl,
    /// 【stdio】
    #[serde(default)]
    pub workspace: McpWorkspaceAccess,
    /// 【stdio】子プロセスを生成してよいか（`DESIGN-MAC-DOMAIN.md` §22.2.2）。既定は`Deny`。
    ///
    /// **書かなくても書いても、既定値なら承認ハッシュは同じ**である（`serde`の既定値が
    /// 埋めた後の値をハッシュするため）。書き忘れで承認が失効することはない。
    #[serde(default)]
    pub process: McpProcessAccess,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeclError {
    #[error("server id must be 1..={MAX_SERVER_ID_LEN} characters of [a-z0-9-]: {0:?}")]
    InvalidId(String),
    #[error("server {id:?} has an empty command")]
    EmptyCommand { id: String },
    #[error(
        "server {id:?} declares RiskClass for tool {tool:?}, but that name is not a valid MCP \
         tool name ([A-Za-z0-9_-], 1..=64 characters)"
    )]
    InvalidDeclaredToolName { id: String, tool: String },
    #[error(
        "server id {id:?} is too long to namespace tool {tool:?}: {TOOL_NAME_PREFIX}{id}\
         {TOOL_NAME_SEPARATOR}{tool} exceeds the {MAX_TOOL_NAME_LEN}-character provider limit"
    )]
    NamespacedNameTooLong { id: String, tool: String },
    #[error("duplicate server id: {0:?}")]
    DuplicateId(String),
    #[error("server {id:?} uses the streamable_http transport but has an empty \"url\"")]
    EmptyUrl { id: String },
    #[error("server {id:?} has an unusable \"url\": {reason}")]
    InvalidUrl { id: String, reason: String },
    /// 書いても効かない項目を**黙って無視しない**（型の doc 参照）。
    #[error(
        "server {id:?} uses the {transport} transport, which ignores {field:?}; remove it rather \
         than leaving a setting that has no effect"
    )]
    FieldNotApplicable {
        id: String,
        transport: &'static str,
        field: &'static str,
    },
    #[error(
        "server {id:?} declares the http header {header:?}, which is not a valid header name \
         (RFC 9110 token characters only)"
    )]
    InvalidHeaderName { id: String, header: String },
    /// harness自身が組み立てるヘッダを宣言側から上書きさせない（プロトコル状態が壊れる）。
    #[error("server {id:?} declares the http header {header:?}, which harness sets itself")]
    ReservedHeaderName { id: String, header: String },
    #[error("server {id:?} has an unusable \"tls_pin\": {reason}")]
    InvalidTlsPin { id: String, reason: String },
    /// ピンは接続先の同一性そのものなので、平文では意味を持たない（D-52）。
    #[error(
        "server {id:?} declares a \"tls_pin\" but its url is plaintext http; a certificate pin \
         only means something over TLS"
    )]
    TlsPinWithoutTls { id: String },
}

/// harnessがStreamable HTTPで自分で組み立てるヘッダ。宣言側からの指定を拒否する。
pub const RESERVED_HTTP_HEADERS: &[&str] = &[
    "accept",
    "content-type",
    "mcp-session-id",
    "mcp-protocol-version",
];

/// RFC 9110のfield-name（token）として妥当か。
pub fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c))
}

/// サーバidとして妥当か（AppContainerプロファイル名・ツール名の両方の材料になる）。
pub fn is_valid_server_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_SERVER_ID_LEN
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// サーバが申告してきたツール名として妥当か。**サーバは未信頼**（`DESIGN-MCP.md` §2）なので、
/// `tools/list`の応答に入っている名前もここを通してから使う。
pub fn is_valid_mcp_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_TOOL_NAME_LEN
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// `mcp__<server>__<tool>`。プロバイダへ送るツール名であり、allowlistルール・承認プロンプト・
/// 監査ログでもこの表記を使う（`DESIGN.md` §ツールシステム）。
pub fn namespaced_tool_name(server_id: &str, tool: &str) -> String {
    format!("{TOOL_NAME_PREFIX}{server_id}{TOOL_NAME_SEPARATOR}{tool}")
}

impl McpServerDecl {
    /// 宣言そのものの妥当性を検査する（サーバとの通信前に行う）。
    ///
    /// **ここで見るのは宣言の形だけ**である。接続してよい相手かどうか（ドメインallowlist・
    /// 平文の可否・トランスポートの有効化）はセッション側のゲートで、
    /// [`crate::runtime::McpRuntime::plan`]が判定する。
    pub fn validate(&self) -> Result<(), DeclError> {
        if !is_valid_server_id(&self.id) {
            return Err(DeclError::InvalidId(self.id.clone()));
        }
        match self.transport {
            McpTransportKind::Stdio => self.validate_stdio_fields()?,
            McpTransportKind::StreamableHttp => self.validate_http_fields()?,
        }
        for tool in self.tools.keys() {
            if !is_valid_mcp_tool_name(tool) {
                return Err(DeclError::InvalidDeclaredToolName {
                    id: self.id.clone(),
                    tool: tool.clone(),
                });
            }
            self.check_namespaced_len(tool)?;
        }
        Ok(())
    }

    /// stdio宣言に、HTTPでしか意味を持たない項目が書かれていないか。
    fn validate_stdio_fields(&self) -> Result<(), DeclError> {
        let not_applicable = |field| DeclError::FieldNotApplicable {
            id: self.id.clone(),
            transport: "stdio",
            field,
        };
        if !self.url.trim().is_empty() {
            return Err(not_applicable("url"));
        }
        if !self.headers.is_empty() {
            return Err(not_applicable("headers"));
        }
        if self.tls_pin.is_some() {
            return Err(not_applicable("tls_pin"));
        }
        if self.command.trim().is_empty() {
            return Err(DeclError::EmptyCommand {
                id: self.id.clone(),
            });
        }
        Ok(())
    }

    /// HTTP宣言に、stdioでしか意味を持たない項目が書かれていないか＋URLとヘッダ名の形。
    ///
    /// `command`/`args`/`env`はAppContainer子プロセスが無いので使い道が無く、
    /// `network`/`workspace`は与える先のpackage SIDが存在しない（§6.2）。
    fn validate_http_fields(&self) -> Result<(), DeclError> {
        let not_applicable = |field| DeclError::FieldNotApplicable {
            id: self.id.clone(),
            transport: "streamable_http",
            field,
        };
        if !self.command.trim().is_empty() {
            return Err(not_applicable("command"));
        }
        if !self.args.is_empty() {
            return Err(not_applicable("args"));
        }
        if !self.env.is_empty() {
            return Err(not_applicable("env"));
        }
        if !self.network.is_deny() {
            return Err(not_applicable("network"));
        }
        if self.workspace != McpWorkspaceAccess::None {
            return Err(not_applicable("workspace"));
        }
        // Streamable HTTPには**閉じ込める子プロセスが存在しない**（喋るのはharness本体、§6.2）。
        // 生成統制の対象そのものが無いので、`process`を書いても効かない。
        if !self.process.is_deny() {
            return Err(not_applicable("process"));
        }

        if self.url.trim().is_empty() {
            return Err(DeclError::EmptyUrl {
                id: self.id.clone(),
            });
        }
        // URLの解析は`http_wire`の1実装だけが持つ（セッションゲートも同じ関数を通る）。
        let parsed =
            crate::http_wire::parse_endpoint_url(&self.url).map_err(|e| DeclError::InvalidUrl {
                id: self.id.clone(),
                reason: e.to_string(),
            })?;

        if let Some(pin) = &self.tls_pin {
            crate::http_wire::parse_cert_pin(pin).map_err(|e| DeclError::InvalidTlsPin {
                id: self.id.clone(),
                reason: e.to_string(),
            })?;
            if !parsed.is_tls() {
                return Err(DeclError::TlsPinWithoutTls {
                    id: self.id.clone(),
                });
            }
        }

        for header in self.headers.keys() {
            if !is_valid_header_name(header) {
                return Err(DeclError::InvalidHeaderName {
                    id: self.id.clone(),
                    header: header.clone(),
                });
            }
            if RESERVED_HTTP_HEADERS.contains(&header.to_ascii_lowercase().as_str()) {
                return Err(DeclError::ReservedHeaderName {
                    id: self.id.clone(),
                    header: header.clone(),
                });
            }
        }
        Ok(())
    }

    /// `mcp__<id>__<tool>`がプロバイダの64文字上限に収まるか。`tools/list`で初めて見る
    /// ツール名にも同じ検査を行うため公開する。
    pub fn check_namespaced_len(&self, tool: &str) -> Result<(), DeclError> {
        if namespaced_tool_name(&self.id, tool).len() > MAX_TOOL_NAME_LEN {
            return Err(DeclError::NamespacedNameTooLong {
                id: self.id.clone(),
                tool: tool.to_string(),
            });
        }
        Ok(())
    }

    /// このツールの`RiskClass`（D-40）。**宣言されたものだけがreadになり、無宣言は
    /// `Network`（＝非read）** として扱われ、パーミッションゲートを必ず通る。
    /// サーバ自身の申告（`readOnlyHint`等）は検証できないので参照しない。
    pub fn risk_for_tool(&self, tool: &str) -> RiskClass {
        self.tools.get(tool).copied().unwrap_or(RiskClass::Network)
    }

    /// 承認台帳と照合するハッシュ（`DESIGN-MCP.md` §4.2）。
    ///
    /// 正規化してからJSONへ落とし、SHA-256を16進で返す。`serde_json`のオブジェクトキー順は
    /// `BTreeMap`で決定的になり、`Vec`は宣言順を保つ（引数の順序は意味を持つため並べ替えない）。
    /// `allow_domains`だけは順序に意味が無いので並べ替え・重複除去してから含める——さもないと
    /// 同じポリシーの書き方違いで承認が失効する。
    pub fn approval_hash(&self) -> String {
        // 完全分解（`..`無し）。`McpServerDecl`へフィールドを足すとここがコンパイルエラーに
        // なり、ハッシュ対象への追加漏れ＝承認バイパスを防ぐ（モジュールdoc参照）。
        let McpServerDecl {
            id,
            transport,
            command,
            args,
            env,
            url,
            headers,
            tls_pin,
            tools,
            network,
            workspace,
            process,
        } = self;

        let mut allow_domains: Vec<String> = network
            .allow_domains
            .iter()
            .map(|d| d.trim().to_ascii_lowercase())
            .collect();
        allow_domains.sort();
        allow_domains.dedup();

        #[derive(Serialize)]
        struct Canonical<'a> {
            id: &'a str,
            transport: &'a McpTransportKind,
            command: &'a str,
            args: &'a [String],
            env: &'a BTreeMap<String, String>,
            url: &'a str,
            /// **展開前**の値（`${env:NAME}`のまま）。実値をハッシュすると、トークンを
            /// ローテートしただけで承認が失効し、かつ台帳が実値の存在を示唆してしまう。
            headers: &'a BTreeMap<String, String>,
            /// **必ずハッシュへ入れる**（D-52）。ピンは「どの証明書を受け入れるか」そのもので、
            /// 承認後に差し替えられたら、ユーザーが目で確かめた1枚とは別の証明書が通る。
            /// 表記ゆれ（区切り・大小文字）で承認が失効しないよう正規化してから入れる。
            tls_pin: Option<String>,
            tools: &'a BTreeMap<String, RiskClass>,
            allow_domains: Vec<String>,
            workspace: &'a McpWorkspaceAccess,
            /// **必ずハッシュへ入れる**（`DESIGN-MAC-DOMAIN.md` §22.2.2）。`broker`は
            /// 「このサーバはSpawn Daemonへ生成を頼んでよい」という許可そのものなので、
            /// 承認後に`deny`から差し替えられてはいけない。
            process: &'a McpProcessAccess,
        }

        let canonical = Canonical {
            id,
            transport,
            command,
            args,
            env,
            url,
            headers,
            tls_pin: tls_pin.as_ref().map(|raw| {
                crate::http_wire::parse_cert_pin(raw)
                    .map(|pin| pin.to_declaration_string())
                    // 不正なピンは`validate`が起動を止めるが、ハッシュは常に計算されうる。
                    // 正規化できない値は生のまま入れる（別の値として扱われるだけで安全側）。
                    .unwrap_or_else(|_| raw.clone())
            }),
            tools,
            allow_domains,
            workspace,
            process,
        };
        // `to_string`が失敗するのは`Serialize`実装がエラーを返す場合だけで、上の型は
        // すべてinfallible。それでもunwrapは避け、失敗時は決して既存の承認と一致しない
        // 値を返す（fail-closed）。
        let json =
            serde_json::to_string(&canonical).unwrap_or_else(|_| format!("__unserializable__{id}"));
        let digest = Sha256::digest(json.as_bytes());
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// 承認プロンプト・`harness mcp list`が表示する宣言の全文。ユーザーはこれを見て
    /// 「起動してよいか」を判断するので、ハッシュ対象を1つ残らず出す。
    pub fn describe(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("  id:        {}\n", self.id));
        out.push_str(&format!("  transport: {}\n", self.transport.label()));
        match self.transport {
            McpTransportKind::Stdio => {
                out.push_str(&format!("  command:   {}\n", self.command));
                out.push_str(&format!("  args:      {:?}\n", self.args));
                out.push_str("  env:\n");
                if self.env.is_empty() {
                    out.push_str("    (none)\n");
                } else {
                    for (k, v) in &self.env {
                        out.push_str(&format!("    {k}={v}\n"));
                    }
                }
            }
            McpTransportKind::StreamableHttp => {
                out.push_str(&format!("  url:       {}\n", self.url));
                match &self.tls_pin {
                    Some(pin) => {
                        // 目視照合しやすい形で出す（D-52。ユーザーはこの値をサーバ運用者と
                        // 突き合わせて承認可否を決める）。
                        let readable = crate::http_wire::parse_cert_pin(pin)
                            .map(|p| p.to_readable())
                            .unwrap_or_else(|_| format!("{pin} (UNPARSABLE)"));
                        out.push_str(&format!("  tls pin:   sha256 {readable}\n"));
                    }
                    None => out.push_str(
                        "  tls pin:   (none -- the certificate is validated normally, against \
                         the OS certificate store)\n",
                    ),
                }
                out.push_str("  headers:\n");
                if self.headers.is_empty() {
                    out.push_str("    (none)\n");
                } else {
                    // 値は展開前のまま出す。`${env:TOKEN}`と書かれていれば実値は出ない。
                    for (k, v) in &self.headers {
                        out.push_str(&format!("    {k}: {v}\n"));
                    }
                }
                // D-41の「有効化した時点でこの経路がharnessの出口制御の外にあることを明示する」。
                out.push_str(
                    "  NOTE: harness itself makes this connection. Unlike a stdio server, it does \
                     NOT run in an AppContainer, and its traffic is NOT subject to the WFP egress \
                     filters or the cooperative proxy. What it can reach is decided by the URL \
                     above (redirects are refused) and by whatever the server operator allows.\n",
                );
                if self.tls_pin.is_some() {
                    // D-52: ピンは連鎖と名前の検証を**置き換える**。何を承認しているのかを書く。
                    out.push_str(
                        "  NOTE: the tls pin REPLACES normal certificate validation for this \
                         server -- the certificate chain and the host name are not checked, and \
                         only a certificate whose sha256 matches exactly is accepted. Verify the \
                         fingerprint with whoever runs the server before approving.\n",
                    );
                }
            }
        }
        out.push_str("  tools (declared RiskClass; anything not listed is treated as non-read):\n");
        if self.tools.is_empty() {
            out.push_str("    (none declared -- every tool will go through the permission gate)\n");
        } else {
            for (k, v) in &self.tools {
                out.push_str(&format!(
                    "    {} -> {:?}\n",
                    namespaced_tool_name(&self.id, k),
                    v
                ));
            }
        }
        // network/workspaceはstdio（AppContainerのpackage SID）にだけ意味がある。HTTPでは
        // `validate`が既定値以外を拒否しているので、出しても「deny/None」しか言えず紛らわしい。
        if self.transport == McpTransportKind::Stdio {
            out.push_str(&format!(
                "  network:   {}\n",
                if self.network.is_deny() {
                    "deny (no outbound sockets at all)".to_string()
                } else {
                    format!(
                        "allow via a dedicated proxy: {}",
                        self.network.allow_domains.join(", ")
                    )
                }
            ));
            out.push_str(&format!("  workspace: {:?}\n", self.workspace));
            // **今日どこまで効くかを正直に書く。** `CHILD_PROCESS_RESTRICTED`（OSが子プロセス
            // 生成そのものを拒否する緩和策）はまだ積んでおらず、遷移ポリシーの評価も未実装なので、
            // ここで承認する内容と今日の実際の挙動は一致しない。**一致しないことを書く**
            // （書かないと「宣言したから今日から統制されている」と読める）。
            out.push_str(&format!(
                "  process:   {}\n",
                match self.process {
                    McpProcessAccess::Deny =>
                        "deny (it may not ask harness to spawn anything; NOTE: the OS-level child \
                         process block is not applied yet, so today this server can still start \
                         child processes on its own)",
                    McpProcessAccess::Broker =>
                        "BROKER (it may ask harness to spawn programs on its behalf; NOTE: the \
                         transition policy is not implemented yet, so every such request is \
                         refused for now)",
                }
            ));
        }
        out
    }
}

/// `.harness/settings.json`（およびユーザ設定）の`mcp`キー。
///
/// ```jsonc
/// "mcp": {
///   "servers": [
///     {
///       "id": "company-docs",
///       "command": "C:\\Program Files\\nodejs\\node.exe",
///       "args": ["C:\\mcp\\company-docs\\index.js"],
///       "tools": { "search": "read_only" },
///       "network": { "allow_domains": ["docs.example.com"] },
///       "workspace": "none"
///     },
///     {
///       "id": "corp-mcp",
///       "transport": "streamable_http",
///       "url": "https://mcp.corp.example/mcp",
///       "headers": { "Authorization": "Bearer ${env:CORP_MCP_TOKEN}" },
///       "tools": { "search": "read_only" }
///     }
///   ],
///   "allow_streamable_http": true,
///   "http_allow_domains": ["mcp.corp.example"]
/// }
/// ```
///
/// **`servers`以外の3キーはユーザ層設定でしか効かない**（D-49）。プロジェクト層
/// （`<root>/.harness/settings.json`）に書かれた分は`harness_config::clamp_project_mcp_http_gates`
/// がマージの過程で剥がす——宣言そのものはリポジトリ同梱でよいが、その宣言を**起動してよいと
/// 決める側**まで同じ場所から動かせると、D-41のオプトインをリポジトリが自称できてしまう。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpSettings {
    #[serde(default)]
    pub servers: Vec<McpServerDecl>,
    /// Streamable HTTPトランスポートを有効にする（D-41/D-49。既定は無効）。
    #[serde(default)]
    pub allow_streamable_http: bool,
    /// HTTP MCPエンドポイントとして接続してよいドメイン。**空なら1つも起動しない**
    /// （closed-by-default）。構文は`net.allow_domains`と同一（`*.example.com`）。
    #[serde(default)]
    pub http_allow_domains: Vec<String>,
    /// 私有CAのPEMバンドル。OS証明書ストアに入れられない場合の逃げ道で、既定は不要。
    #[serde(default)]
    pub http_ca_bundle: Option<String>,
}

/// [`parse_mcp_http_gates`]が返す、宣言以外の`mcp`キー（＝セッション側のゲート）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct McpHttpSettings {
    pub allow_streamable_http: bool,
    pub http_allow_domains: Vec<String>,
    pub http_ca_bundle: Option<String>,
}

/// `harness-config`が運んできた生の`mcp`キーを解釈する。
///
/// **綴りを間違えた宣言を黙って無視しない**（`cognition.budgets`のフェーズ名と同じ方針）。
/// 「設定したのに効かない」に気付けないのは、MCPでは「裏取りしたつもりで裏取りしていない」に
/// 直結するため、パースエラーはそのまま返す。
pub fn parse_mcp_settings(value: Option<&serde_json::Value>) -> Result<Vec<McpServerDecl>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    Ok(parse_mcp_section(value)?.servers)
}

/// 宣言以外の`mcp`キー（HTTPトランスポートのゲート）を解釈する。
///
/// `parse_mcp_settings`と同じ`McpSettings`を通すので、綴り間違い・型違いはここでも
/// エラーになる（`"allow_streamable_http": "true"`が黙って無効にならない）。
pub fn parse_mcp_http_gates(value: Option<&serde_json::Value>) -> Result<McpHttpSettings, String> {
    let Some(value) = value else {
        return Ok(McpHttpSettings::default());
    };
    let settings = parse_mcp_section(value)?;
    Ok(McpHttpSettings {
        allow_streamable_http: settings.allow_streamable_http,
        http_allow_domains: settings.http_allow_domains,
        http_ca_bundle: settings.http_ca_bundle,
    })
}

fn parse_mcp_section(value: &serde_json::Value) -> Result<McpSettings, String> {
    serde_json::from_value(value.clone())
        .map_err(|e| format!("invalid \"mcp\" section in settings.json: {e}"))
}

/// 宣言の集合を検証する（id重複はここで弾く。プロファイル名・ツール名が衝突するため）。
pub fn validate_all(decls: &[McpServerDecl]) -> Result<(), DeclError> {
    let mut seen = std::collections::BTreeSet::new();
    for decl in decls {
        decl.validate()?;
        if !seen.insert(decl.id.as_str()) {
            return Err(DeclError::DuplicateId(decl.id.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample() -> McpServerDecl {
        McpServerDecl {
            id: "company-docs".to_string(),
            transport: McpTransportKind::Stdio,
            command: "C:\\Program Files\\nodejs\\node.exe".to_string(),
            args: vec!["C:\\mcp\\docs\\index.js".to_string()],
            env: [("DOCS_ROOT".to_string(), "C:\\docs".to_string())]
                .into_iter()
                .collect(),
            url: String::new(),
            headers: Default::default(),
            tls_pin: None,
            tools: [("search".to_string(), RiskClass::ReadOnly)]
                .into_iter()
                .collect(),
            network: McpNetworkDecl {
                allow_domains: vec!["docs.example.com".to_string()],
            },
            workspace: McpWorkspaceAccess::None,
            process: McpProcessAccess::Deny,
        }
    }

    #[test]
    fn valid_declaration_passes_validation() {
        assert_eq!(sample().validate(), Ok(()));
    }

    #[test]
    fn server_ids_are_restricted_to_profile_and_tool_name_safe_characters() {
        for bad in [
            "",
            "Company-Docs",
            "company docs",
            "company.docs",
            "company/docs",
            "company\\docs",
            &"x".repeat(MAX_SERVER_ID_LEN + 1),
        ] {
            assert!(!is_valid_server_id(bad), "should reject {bad:?}");
        }
        for good in ["a", "company-docs", "jira2", &"x".repeat(MAX_SERVER_ID_LEN)] {
            assert!(is_valid_server_id(good), "should accept {good:?}");
        }
    }

    /// サーバ申告のツール名も未信頼入力として検証する（`DESIGN-MCP.md` §2）。
    #[test]
    fn server_reported_tool_names_are_validated() {
        for bad in ["", "has space", "slash/name", "dot.name", &"x".repeat(65)] {
            assert!(!is_valid_mcp_tool_name(bad), "should reject {bad:?}");
        }
        for good in ["search", "create_issue", "list-things", "A1"] {
            assert!(is_valid_mcp_tool_name(good), "should accept {good:?}");
        }
    }

    #[test]
    fn namespaced_names_use_the_provider_safe_separator() {
        assert_eq!(
            namespaced_tool_name("company-docs", "search"),
            "mcp__company-docs__search"
        );
    }

    #[test]
    fn namespaced_names_over_the_provider_limit_are_rejected() {
        let mut decl = sample();
        decl.id = "x".repeat(MAX_SERVER_ID_LEN);
        let long_tool = "y".repeat(40);
        assert!(matches!(
            decl.check_namespaced_len(&long_tool),
            Err(DeclError::NamespacedNameTooLong { .. })
        ));
    }

    /// D-40: 宣言のあるツールだけがreadになり、無宣言は非read（＝ゲートを通る）。
    #[test]
    fn undeclared_tools_are_treated_as_non_read() {
        let decl = sample();
        assert_eq!(decl.risk_for_tool("search"), RiskClass::ReadOnly);
        assert_eq!(decl.risk_for_tool("delete_everything"), RiskClass::Network);
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let decls = vec![sample(), sample()];
        assert!(matches!(
            validate_all(&decls),
            Err(DeclError::DuplicateId(_))
        ));
    }

    /// **フィールドを足したら、承認の形の版を上げたか一度考える。**
    ///
    /// `approval_hash`の完全分解は「ハッシュ対象へ足したか」を強制するが、
    /// **「版を上げたか」は強制しない**。ここが`..`無しで分解しているので、
    /// [`McpServerDecl`]へフィールドを足すと**このテストがコンパイルエラーになる**——
    /// そのとき [`DECL_FORMAT_VERSION`] を上げ、下の数値も合わせること。
    ///
    /// 版を上げ忘れると、既存の承認は失効するのに**「あなたが宣言を変えた」という
    /// 誤った理由**で案内される（失効そのものは正しく起きるので、テストでは気付けない）。
    #[test]
    fn adding_a_declaration_field_forces_a_look_at_the_format_version() {
        let McpServerDecl {
            id: _,
            transport: _,
            command: _,
            args: _,
            env: _,
            url: _,
            headers: _,
            tls_pin: _,
            tools: _,
            network: _,
            workspace: _,
            process: _,
        } = sample();
        assert_eq!(
            DECL_FORMAT_VERSION, 2,
            "宣言の欄を増やしたら DECL_FORMAT_VERSION を上げ、起動時に出す1行へ欄の名前を足すこと"
        );
    }

    #[test]
    fn hash_is_stable_across_calls() {
        let decl = sample();
        assert_eq!(decl.approval_hash(), decl.approval_hash());
    }

    /// **D-39の中核**: ハッシュ対象の7項目それぞれについて、1つ変えれば承認が失効する。
    #[test]
    fn every_hashed_field_changes_the_approval_hash() {
        let base = sample();
        let base_hash = base.approval_hash();

        let mut mutations: Vec<(&str, McpServerDecl)> = Vec::new();

        let mut m = base.clone();
        m.id = "other-docs".to_string();
        mutations.push(("id", m));

        let mut m = base.clone();
        m.command = "C:\\evil\\node.exe".to_string();
        mutations.push(("command", m));

        let mut m = base.clone();
        m.args.push("--inspect".to_string());
        mutations.push(("args", m));

        let mut m = base.clone();
        m.env
            .insert("NODE_OPTIONS".to_string(), "--require evil".to_string());
        mutations.push(("env", m));

        let mut m = base.clone();
        m.tools.insert("delete".to_string(), RiskClass::ReadOnly);
        mutations.push(("tools", m));

        let mut m = base.clone();
        m.network.allow_domains.push("evil.example.com".to_string());
        mutations.push(("network", m));

        let mut m = base.clone();
        m.workspace = McpWorkspaceAccess::ReadWrite;
        mutations.push(("workspace", m));

        // §22.2.2: `broker`は「Spawn Daemonへ生成を頼んでよい」という許可そのものなので、
        // 承認後に差し替えられてはいけない。
        let mut m = base.clone();
        m.process = McpProcessAccess::Broker;
        mutations.push(("process", m));

        for (label, mutated) in mutations {
            assert_ne!(
                mutated.approval_hash(),
                base_hash,
                "changing {label} must invalidate the approval"
            );
        }
    }

    /// トランスポート種別も対象（stdioで承認したものがHTTPで起動されない、D-41）。
    /// 現状バリアントが1つしか無いので、`Canonical`に`transport`が含まれていることを
    /// シリアライズ結果で確認する形で固定する。
    #[test]
    fn transport_kind_participates_in_the_hash() {
        let decl = sample();
        let json = serde_json::to_string(&decl).unwrap();
        assert!(json.contains("\"transport\":\"stdio\""), "{json}");
    }

    /// 許可ドメインは順序・大小文字・重複の書き方違いで承認が失効しない（正規化される）。
    #[test]
    fn allow_domain_ordering_and_case_do_not_invalidate_the_approval() {
        let mut a = sample();
        a.network.allow_domains = vec!["b.example.com".to_string(), "a.example.com".to_string()];
        let mut b = sample();
        b.network.allow_domains = vec![
            "A.example.com".to_string(),
            "b.example.com".to_string(),
            "a.example.com".to_string(),
        ];
        assert_eq!(a.approval_hash(), b.approval_hash());
    }

    /// 設定の`mcp`キーが最小の宣言から読める（既定値が効いている）。
    #[test]
    fn settings_parse_with_defaults_for_optional_keys() {
        let value = serde_json::json!({
            "servers": [ { "id": "docs", "command": "node.exe" } ]
        });
        let decls = parse_mcp_settings(Some(&value)).unwrap();
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].transport, McpTransportKind::Stdio);
        assert!(decls[0].args.is_empty());
        assert!(decls[0].network.is_deny());
        assert_eq!(decls[0].workspace, McpWorkspaceAccess::None);
        assert_eq!(decls[0].process, McpProcessAccess::Deny);
        assert_eq!(decls[0].validate(), Ok(()));
    }

    /// **書き忘れで承認が失効しない。** `"process": "deny"`と書いても書かなくても、
    /// `serde`の既定値が埋めた後の同じ値をハッシュするので結果は一致する
    /// （`workspace`が既にそうなっているのと同じ形）。
    #[test]
    fn omitting_the_process_key_hashes_the_same_as_writing_the_default() {
        let with = serde_json::json!({
            "servers": [ { "id": "docs", "command": "node.exe", "process": "deny" } ]
        });
        let without = serde_json::json!({
            "servers": [ { "id": "docs", "command": "node.exe" } ]
        });
        let with = parse_mcp_settings(Some(&with)).unwrap();
        let without = parse_mcp_settings(Some(&without)).unwrap();
        assert_eq!(with[0].approval_hash(), without[0].approval_hash());
    }

    /// 綴り間違いを黙って既定値にしない（`"process": "brokre"`が`deny`にならない）。
    #[test]
    fn a_misspelled_process_value_is_an_error_rather_than_a_silent_deny() {
        let value = serde_json::json!({
            "servers": [ { "id": "docs", "command": "node.exe", "process": "brokre" } ]
        });
        assert!(parse_mcp_settings(Some(&value)).is_err());
    }

    /// **承認画面は「今日どこまで効くか」まで書く**（`DESIGN-MAC-DOMAIN.md` §22.2.2）。
    ///
    /// `CHILD_PROCESS_RESTRICTED`も遷移ポリシーの評価も未実装なので、宣言と今日の挙動は
    /// 一致しない。**一致しないことが承認前に読める**ことをここで固定する——
    /// 書かないと「宣言したから今日から統制されている」と読める。
    #[test]
    fn describe_says_how_far_the_process_declaration_actually_reaches_today() {
        let denied = sample().describe();
        assert!(denied.contains("not applied yet"), "{denied}");

        let mut brokered = sample();
        brokered.process = McpProcessAccess::Broker;
        let brokered = brokered.describe();
        assert!(brokered.contains("BROKER"), "{brokered}");
        assert!(brokered.contains("not implemented yet"), "{brokered}");
    }

    #[test]
    fn a_missing_mcp_section_yields_no_servers() {
        assert!(parse_mcp_settings(None).unwrap().is_empty());
    }

    /// `command`が無い宣言は、パースは通るが**検証で落ちる**。
    ///
    /// M15.6で`command`はトランスポート依存になったので（HTTPには実行ファイルが無い）、
    /// serdeの必須フィールドでは表せなくなった。落とす場所がパースから検証へ移っただけで、
    /// 黙って起動しないという点は変わらない（`SkipReason::Invalid`として報告される）。
    #[test]
    fn a_stdio_declaration_without_a_command_is_rejected_at_validation_time() {
        let value = serde_json::json!({ "servers": [ { "id": "docs" } ] });
        let decls = parse_mcp_settings(Some(&value)).unwrap();
        assert!(matches!(
            decls[0].validate(),
            Err(DeclError::EmptyCommand { .. })
        ));
    }

    /// 綴り間違い・型違いは黙って無視されずエラーになる（「設定したのに効かない」を防ぐ）。
    #[test]
    fn a_malformed_mcp_section_is_an_error_rather_than_being_ignored() {
        let value = serde_json::json!({ "servers": "not an array" });
        assert!(parse_mcp_settings(Some(&value)).is_err());

        let value = serde_json::json!({
            "servers": [ { "id": "docs", "command": "node.exe", "tools": { "search": "readonly" } } ]
        });
        assert!(
            parse_mcp_settings(Some(&value)).is_err(),
            "a misspelled RiskClass must not silently become non-read"
        );
    }

    #[test]
    fn empty_command_is_rejected() {
        let mut decl = sample();
        decl.command = "   ".to_string();
        assert!(matches!(
            decl.validate(),
            Err(DeclError::EmptyCommand { .. })
        ));
    }

    // --- M15.6: Streamable HTTP ---

    fn http_sample() -> McpServerDecl {
        McpServerDecl {
            id: "corp-mcp".to_string(),
            transport: McpTransportKind::StreamableHttp,
            command: String::new(),
            args: Vec::new(),
            env: Default::default(),
            url: "https://mcp.corp.example/mcp".to_string(),
            headers: [(
                "Authorization".to_string(),
                "Bearer ${env:CORP_MCP_TOKEN}".to_string(),
            )]
            .into_iter()
            .collect(),
            tls_pin: None,
            tools: [("search".to_string(), RiskClass::ReadOnly)]
                .into_iter()
                .collect(),
            network: McpNetworkDecl::default(),
            workspace: McpWorkspaceAccess::None,
            process: McpProcessAccess::Deny,
        }
    }

    #[test]
    fn a_valid_streamable_http_declaration_passes_validation() {
        assert_eq!(http_sample().validate(), Ok(()));
    }

    #[test]
    fn the_settings_parser_understands_the_streamable_http_transport() {
        let value = serde_json::json!({
            "servers": [ {
                "id": "corp-mcp",
                "transport": "streamable_http",
                "url": "https://mcp.corp.example/mcp"
            } ]
        });
        let decls = parse_mcp_settings(Some(&value)).unwrap();
        assert_eq!(decls[0].transport, McpTransportKind::StreamableHttp);
        assert_eq!(decls[0].validate(), Ok(()));
    }

    /// **書いても効かない項目を黙って無視しない。** stdio専用の項目をHTTP宣言へ書いたら落とす。
    #[test]
    fn stdio_only_fields_on_an_http_declaration_are_rejected_rather_than_ignored() {
        type Mutation = (&'static str, Box<dyn Fn(&mut McpServerDecl)>);
        let cases: Vec<Mutation> = vec![
            (
                "command",
                Box::new(|d: &mut McpServerDecl| d.command = "node.exe".to_string()),
            ),
            (
                "args",
                Box::new(|d: &mut McpServerDecl| d.args = vec!["x".to_string()]),
            ),
            (
                "env",
                Box::new(|d: &mut McpServerDecl| {
                    d.env.insert("K".to_string(), "V".to_string());
                }),
            ),
            (
                "network",
                Box::new(|d: &mut McpServerDecl| {
                    d.network.allow_domains = vec!["a.example".to_string()]
                }),
            ),
            (
                "workspace",
                Box::new(|d: &mut McpServerDecl| d.workspace = McpWorkspaceAccess::Read),
            ),
            (
                "process",
                Box::new(|d: &mut McpServerDecl| d.process = McpProcessAccess::Broker),
            ),
        ];
        for (field, mutate) in cases {
            let mut decl = http_sample();
            mutate(&mut decl);
            match decl.validate() {
                Err(DeclError::FieldNotApplicable { field: got, .. }) => assert_eq!(got, field),
                other => panic!("{field} should be rejected on an http declaration: {other:?}"),
            }
        }
    }

    /// 逆向きも同じ（stdio宣言にurl/headersを書いたら落とす）。
    #[test]
    fn http_only_fields_on_a_stdio_declaration_are_rejected_rather_than_ignored() {
        let mut decl = sample();
        decl.url = "https://mcp.corp.example/mcp".to_string();
        assert!(matches!(
            decl.validate(),
            Err(DeclError::FieldNotApplicable { field: "url", .. })
        ));

        let mut decl = sample();
        decl.headers
            .insert("Authorization".to_string(), "Bearer x".to_string());
        assert!(matches!(
            decl.validate(),
            Err(DeclError::FieldNotApplicable {
                field: "headers",
                ..
            })
        ));
    }

    #[test]
    fn an_http_declaration_needs_a_usable_url() {
        let mut decl = http_sample();
        decl.url = "  ".to_string();
        assert!(matches!(decl.validate(), Err(DeclError::EmptyUrl { .. })));

        for bad in ["ftp://example.com/mcp", "file:///c:/x", "not a url"] {
            let mut decl = http_sample();
            decl.url = bad.to_string();
            assert!(
                matches!(decl.validate(), Err(DeclError::InvalidUrl { .. })),
                "should reject {bad:?}"
            );
        }
    }

    /// harnessが自分で組み立てるヘッダを宣言側から差し替えさせない（プロトコル状態が壊れる）。
    #[test]
    fn headers_that_harness_sets_itself_are_rejected() {
        for reserved in [
            "Mcp-Session-Id",
            "mcp-protocol-version",
            "Accept",
            "Content-Type",
        ] {
            let mut decl = http_sample();
            decl.headers.insert(reserved.to_string(), "x".to_string());
            assert!(
                matches!(decl.validate(), Err(DeclError::ReservedHeaderName { .. })),
                "should reject {reserved:?}"
            );
        }
    }

    #[test]
    fn malformed_header_names_are_rejected() {
        for bad in ["has space", "colon:name", "", "quote\"name"] {
            let mut decl = http_sample();
            decl.headers.insert(bad.to_string(), "x".to_string());
            assert!(
                matches!(decl.validate(), Err(DeclError::InvalidHeaderName { .. })),
                "should reject {bad:?}"
            );
        }
    }

    /// **D-39**: url・headersも承認ハッシュ対象。承認後に接続先やトークン参照を差し替えられない。
    #[test]
    fn the_url_and_headers_participate_in_the_approval_hash() {
        let base = http_sample();
        let base_hash = base.approval_hash();

        let mut moved = base.clone();
        moved.url = "https://evil.example/mcp".to_string();
        assert_ne!(moved.approval_hash(), base_hash, "url must be hashed");

        let mut extra_header = base.clone();
        extra_header
            .headers
            .insert("X-Tenant".to_string(), "other".to_string());
        assert_ne!(
            extra_header.approval_hash(),
            base_hash,
            "headers must be hashed"
        );
    }

    /// **D-41**: stdioで承認したものがHTTPで起動されない（トランスポート種別もハッシュ対象）。
    #[test]
    fn an_approval_does_not_carry_across_transports() {
        let stdio = sample();
        let http = McpServerDecl {
            transport: McpTransportKind::StreamableHttp,
            command: String::new(),
            args: Vec::new(),
            env: Default::default(),
            url: "https://mcp.corp.example/mcp".to_string(),
            ..sample()
        };
        assert_ne!(stdio.approval_hash(), http.approval_hash());
    }

    /// 承認プロンプト（`describe`）は、実トークンではなく**展開前の参照**を見せる。
    #[test]
    fn describe_shows_the_unexpanded_header_value_not_the_secret() {
        let described = http_sample().describe();
        assert!(described.contains("${env:CORP_MCP_TOKEN}"), "{described}");
        assert!(
            described.contains("https://mcp.corp.example/mcp"),
            "{described}"
        );
        // D-41: この経路がharnessの出口制御の外にあることを承認時に明示する。
        assert!(
            described.contains("NOT run in an AppContainer"),
            "{described}"
        );
    }

    // --- D-52: 証明書ピン ---

    const PIN: &str = "sha256:9f6aab9ea64d8e00eeffbc2a5b57aacfecdf76000520fcfb84b0c36d6d113f0f";

    #[test]
    fn a_declaration_with_a_certificate_pin_is_valid() {
        let mut decl = http_sample();
        decl.tls_pin = Some(PIN.to_string());
        assert_eq!(decl.validate(), Ok(()));
    }

    #[test]
    fn a_malformed_certificate_pin_is_rejected() {
        for bad in ["sha1:aabb", "sha256:短すぎ", "not-a-pin"] {
            let mut decl = http_sample();
            decl.tls_pin = Some(bad.to_string());
            assert!(
                matches!(decl.validate(), Err(DeclError::InvalidTlsPin { .. })),
                "should reject {bad:?}"
            );
        }
    }

    /// 平文httpにピンを書いても意味が無い（見る証明書が無い）ので、黙って無視せず落とす。
    #[test]
    fn a_certificate_pin_on_a_plaintext_url_is_rejected() {
        let mut decl = http_sample();
        decl.url = "http://mcp.corp.internal/mcp".to_string();
        decl.tls_pin = Some(PIN.to_string());
        assert!(matches!(
            decl.validate(),
            Err(DeclError::TlsPinWithoutTls { .. })
        ));
    }

    /// stdio宣言にピンを書いても効かないので、黙って無視せず落とす
    /// （このテストで実際に取りこぼしが見つかった）。
    #[test]
    fn a_certificate_pin_on_a_stdio_declaration_is_rejected() {
        let mut decl = sample();
        decl.tls_pin = Some(PIN.to_string());
        assert!(
            matches!(
                decl.validate(),
                Err(DeclError::FieldNotApplicable {
                    field: "tls_pin",
                    ..
                })
            ),
            "a stdio server has no tls to pin: {:?}",
            decl.validate()
        );
    }

    /// **D-52/D-39**: ピンは承認ハッシュ対象。承認後に別の証明書へ差し替えられない。
    #[test]
    fn the_certificate_pin_participates_in_the_approval_hash() {
        let base = http_sample();
        let mut pinned = base.clone();
        pinned.tls_pin = Some(PIN.to_string());
        assert_ne!(pinned.approval_hash(), base.approval_hash());

        let mut other = base.clone();
        other.tls_pin = Some(format!("sha256:{}", "a".repeat(64)));
        assert_ne!(other.approval_hash(), pinned.approval_hash());
    }

    /// 表記ゆれ（区切り・大小文字）で承認が失効しない——同じ証明書を指しているため。
    #[test]
    fn pin_formatting_does_not_invalidate_the_approval() {
        let mut a = http_sample();
        a.tls_pin = Some(PIN.to_string());
        let mut b = http_sample();
        b.tls_pin = Some(
            "SHA256:9F6AAB9E:A64D8E00:EEFFBC2A:5B57AACF:ECDF7600:0520FCFB:84B0C36D:6D113F0F"
                .to_string(),
        );
        assert_eq!(a.approval_hash(), b.approval_hash());
    }

    /// 承認プロンプトは指紋を目視照合できる形で出し、**何を置き換えるのか**も書く。
    #[test]
    fn describe_shows_the_pin_and_what_it_replaces() {
        let mut decl = http_sample();
        decl.tls_pin = Some(PIN.to_string());
        let described = decl.describe();
        assert!(described.contains("9f6aab9e a64d8e00"), "{described}");
        assert!(
            described.contains("REPLACES normal certificate validation"),
            "{described}"
        );
    }

    /// ピンが無い宣言は「通常の検証を通る」と明示する（沈黙させない）。
    #[test]
    fn describe_says_when_there_is_no_pin() {
        assert!(
            http_sample().describe().contains("validated normally"),
            "{}",
            http_sample().describe()
        );
    }

    /// 宣言以外の`mcp`キー（セッションゲート）も型で読む。
    #[test]
    fn the_http_gates_are_parsed_from_the_mcp_section() {
        let value = serde_json::json!({
            "servers": [],
            "allow_streamable_http": true,
            "http_allow_domains": ["mcp.corp.example"]
        });
        let gates = parse_mcp_http_gates(Some(&value)).unwrap();
        assert!(gates.allow_streamable_http);
        assert_eq!(
            gates.http_allow_domains,
            vec!["mcp.corp.example".to_string()]
        );
        assert_eq!(gates.http_ca_bundle, None);
    }

    /// 既定は無効（D-41）。書かなければ閉じている。
    #[test]
    fn the_http_transport_is_disabled_when_the_gates_are_absent() {
        assert!(!parse_mcp_http_gates(None).unwrap().allow_streamable_http);
        let value = serde_json::json!({ "servers": [] });
        assert!(
            !parse_mcp_http_gates(Some(&value))
                .unwrap()
                .allow_streamable_http
        );
    }

    /// `"true"`のような型違いを黙ってfalseにしない（有効化したつもりで無効を防ぐ）。
    #[test]
    fn a_misspelled_gate_value_is_an_error_rather_than_a_silent_default() {
        let value = serde_json::json!({ "servers": [], "allow_streamable_http": "true" });
        assert!(parse_mcp_http_gates(Some(&value)).is_err());
    }
}
