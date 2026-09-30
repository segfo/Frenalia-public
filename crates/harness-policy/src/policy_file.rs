//! `policy.json`——ポリシーエディタが承認結果を書く先（dig決定6・7）。
//!
//! # なぜ`settings.json`ではないのか（決定7: ドメイン型）
//!
//! `.harness/settings.json`の`fs.read`/`fs.read_write`/`fs.read_exec`は**ワークスペース全体**に
//! 効く。一方このエディタが決めているのは「**このコマンド**に何を許すか」であり、
//! TOMOYOのドメインポリシーと同じ単位である。settings.jsonへ書くとその単位が失われ、
//! `cargo`のために開けた穴が無関係なコマンドにも効いてしまう。加えて、ポリシーエディタが
//! 会話エージェント本体（`harness.exe`）の設定を横から書き換えることにもなる。
//!
//! # 今のスコープ（正直に書く）
//!
//! - **ワークスペーススコープだけ**を実装している。決定8の3層（会話セッション＞ワークスペース
//!   ＞ユーザー）のうち残り2つは未実装。
//! - 決定6の後半「settings.jsonの`fs.*`をここへ**移設**しsettings.json側からは撤去する」は
//!   **未実施**。harness本体の設定読取経路を変える話なので別件で、現状は**併存**している
//!   （**`fs.*`と`net.*`はharness.exeからは読まれない**。段階6bで`harness.exe`が
//!   このファイルを読むようになったが、それが使うのは`process`——遷移の宣言だけである）。
//! - 同名ドメインへの承認は**和集合マージ**（[`PolicyFile::merge_approved`]）。
//!   **取り消しは`harness_policy_editor::unapprove`が持つ**（宣言画面`F4`とCLIの`unapprove`）。
//!   かつてここには「追記のみ。削除の操作は無い（手で編集する）。中途半端な削除UIは
//!   付与の対（撤収）にならない」と書いてあったが、**その判断は撤回した**——理由は
//!   「付与の対」が何なのかが実測で分かったことである。ACEが付くのはパス2の開始時で、
//!   剥がすのはプロセス終了時と（宣言が縮んだときは）次のパス2の開始時なので、
//!   **宣言を消す操作は`policy.json`だけを触れば対になる**。詳細は`unapprove`のモジュールdoc。
//! - 値の**編集**（accessの付け替え等）は依然として無い。取り消してから承認し直す。
//!
//! # 値の意味は「著者支援」であって実行時マッチャではない（決定2）
//!
//! ここに入るのは`crate::generalize`が出した設定値の綴り（`C:\...\**`等）そのままで、
//! 実行時にこのパターンでアクセスを判定する機構は無い。**強制するのは常にOS ACL**である
//! ——パス2（`record_net`）がこの値を`FsPassthrough`へ変換し、`preflight`が実際にACEを付ける。
//!
//! # `.harness`配下に置く理由
//!
//! P-08（制御ディレクトリはサンドボックスから開けない）側に置くことで、記録対象のコマンドが
//! 自分のポリシーを書き換えられない。同時に、`aggregate::is_harness_control_path`が`.harness`を
//! 候補から外すので、**このファイル自身が次回の記録の候補に混ざる自己参照ループにもならない**
//! （決定15と同じ理屈）。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::transition::{self, DomainView, GraphInput, TransitionRules};
use crate::{generalize::SettingsKey, RuleProposal};
use serde::{Deserialize, Serialize};

/// ワークスペーススコープの置き場（`<workspace>/.harness/policy.json`）。
pub const POLICY_FILE_NAME: &str = "policy.json";

/// `harness.exe`が起こすTier2aのシェルが居るドメインの名前（**入口ドメイン**）。
///
/// # なぜ固定名なのか
///
/// 遷移の判定は「呼び出し元がどのドメインに居るか」を名前で引く（[`transition::SpawnAttempt`]の
/// `from_domain`）。`run_shell`のシェルには宣言由来の名前が無いので、ここで1つ決めておかないと
/// **`policy.json`に辺を1本も書けない**。ワークスペースごとに変えないのは、このファイル自体が
/// そのワークスペースの`.harness/`配下にあり、ファイルが違えば宣言も既に別だからである
/// ——名前を実行時に変えると、宣言を書く人が自分のワークスペースの綴りを先に調べる羽目になる。
///
/// # これは暫定である（2026-09-12、段階6b。ユーザー判断）
///
/// **可変にできない理由があるわけではない。** 必要が出たら設定・CLIフラグで指定できるように
/// してよい。ただしそのときは**既定値を持たせず必ず選ばせる**こと
/// （`ConsoleNeed`・`DomainIdentity`と同じ姿勢）——指定を渡さない呼び出し経路が生まれると
/// **そこだけ黙って別ドメイン扱いになり**、症状は「なぜか拒否される」としてしか出ない。
/// 正本は`plans/DESIGN-MAC-TRANSITION-POLICY.md` §19.3.14の「入口ドメインの名前は固定名1つである」。
///
/// # 由来が違う2つの名前と混ぜないこと
///
/// ポリシーエディタのパス2は**記録中のドメイン名**、MCPサーバは**宣言id**を使う
/// （`plans/DESIGN-MAC-PROTOCOL.md` §12.1の表）。入口ドメインが固定なのは`run_shell`経路だけである。
pub const ENTRY_DOMAIN: &str = "workspace-shell";

/// 読む側が想定外の形を黙って解釈しないために持つ。
///
/// **2へ上げたのは段階⑥a**（遷移の宣言＝[`PolicyDomain::process`]を足した回）。
/// `process`を知らないバイナリが新しい`policy.json`を読むと、**遷移の宣言を黙って無視して
/// 「FSとnetだけのポリシー」として扱う**——[`PolicyFileError::FutureSchema`]はまさにこれを
/// 止めるためにある（`plans/DESIGN-MAC.md` §5.1(7)）。
pub const POLICY_SCHEMA_VERSION: u32 = 2;

/// `process`を1件も持たないファイルが名乗る版。
///
/// **上げるかどうかは内容で決まる**（[`PolicyFile::required_schema_version`]）。
/// 遷移を1本も使っていないワークスペースを、古いバイナリから読めなくする理由が無いためである。
const SCHEMA_VERSION_WITHOUT_TRANSITIONS: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum PolicyFileError {
    #[error("policy.json を読めませんでした（{path}）: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("policy.json の形が壊れています（{path}）: {source}")]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error(
        "policy.json のスキーマ版 {found} はこのバイナリ（対応版 {supported}）より新しいものです\
         （{path}）。新しい harness-policy-editor で開いてください"
    )]
    FutureSchema {
        path: PathBuf,
        found: u32,
        supported: u32,
    },
    #[error("policy.json を書けませんでした（{path}）: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(
        "policy.json のスキーマ版が {found} なのに遷移の宣言（process）が入っています（{path}）。\
         この形のファイルは、遷移を知らない古い harness が**黙って無視して**読みます。\
         schema_version を {required} にしてください"
    )]
    UnversionedTransitions {
        path: PathBuf,
        found: u32,
        required: u32,
    },
    #[error("policy.json の遷移の宣言を受け付けられません（{path}）: {reason}")]
    RejectedTransitions { path: PathBuf, reason: String },
}

/// ドメイン1件のFSルール。キーは`crate::SettingsKey`と1:1で対応させる
/// （新しい語彙を作らない——提案からの振り分けを機械的にするため）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsRules {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub read_write: Vec<String>,
    #[serde(default)]
    pub read_exec: Vec<String>,
}

impl FsRules {
    fn bucket_mut(&mut self, key: SettingsKey) -> Option<&mut Vec<String>> {
        match key {
            SettingsKey::FsRead => Some(&mut self.read),
            SettingsKey::FsReadWrite => Some(&mut self.read_write),
            SettingsKey::FsReadExec => Some(&mut self.read_exec),
            SettingsKey::NetAllowDomains => None,
        }
    }

    /// `(値, access)`の平坦な一覧。パス2が`FsPassthrough`へ変換するのに使う。
    pub fn entries(&self) -> Vec<(&str, harness_config::FsAccess)> {
        use harness_config::FsAccess;
        let mut out: Vec<(&str, FsAccess)> = Vec::new();
        for value in &self.read {
            out.push((value.as_str(), FsAccess::Read));
        }
        for value in &self.read_write {
            out.push((value.as_str(), FsAccess::ReadWrite));
        }
        for value in &self.read_exec {
            out.push((value.as_str(), FsAccess::ReadExec));
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.read.is_empty() && self.read_write.is_empty() && self.read_exec.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetRules {
    #[serde(default)]
    pub allow_domains: Vec<String>,
}

/// 承認がどの記録から来たかの由来。**判断の材料であって、判定には使わない。**
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// 承認の根拠になった記録セッションのid（新しいものを末尾へ追加）。
    #[serde(default)]
    pub record_sessions: Vec<String>,
    #[serde(default)]
    pub updated_unix_ms: u64,
}

/// 「このコマンドに何を許すか」1件（TOMOYOのドメインに相当）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDomain {
    /// ドメイン名。ユーザーが`--domain`で指定する識別子。
    pub name: String,
    /// このドメインで記録したコマンド（**由来の記録であって実行時マッチャではない**）。
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
    #[serde(default)]
    pub fs: FsRules,
    #[serde(default)]
    pub net: NetRules,
    /// このドメインから、どのプログラムをどの引数で起こしてよいか（遷移MACの宣言軸）。
    ///
    /// **`commands`とは別物である。** あちらは「このドメインで記録したコマンド」という
    /// **由来の記録**で、実行時マッチャではない（`plans/DESIGN-MAC.md` §4・§5.1(8)が
    /// 流用しないと明記している）。こちらは**判定に使う**。
    ///
    /// 形と判定規則の正本は[`crate::transition`]で、**このファイルは持たない**。
    #[serde(default, skip_serializing_if = "TransitionRules::is_empty")]
    pub process: TransitionRules,
    #[serde(default)]
    pub provenance: Provenance,
}

impl PolicyDomain {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            commands: Vec::new(),
            cwd: None,
            fs: FsRules::default(),
            net: NetRules::default(),
            process: TransitionRules::default(),
            provenance: Provenance::default(),
        }
    }

    /// この`value`（パスまたはドメイン）**そのもの**を宣言しているキーを全部返す。
    ///
    /// # なぜaccessを問わず引くのか
    ///
    /// 候補一覧に「もう宣言済み」を重ねる（同じ場所へ二重にチェックを付けさせない）のに使う。
    /// **ETWは読取と実行を区別できない**（RESULTS.md §17）ので、`fs.read_exec`として承認した
    /// 実行ファイルは次の記録でも`fs.read`の顔で候補に出てくる。accessまで一致を要求すると、
    /// 承認済みの実行ファイルが毎回「未宣言」として現れることになる。
    ///
    /// 同じ値に複数のキーが立つことはある（`read`と`read_exec`の両方など）ので、
    /// 1つに畳まず全部返す——どのaccessで宣言済みかは画面に出す材料である。
    ///
    /// 比較は大文字小文字を無視する（Windowsのパス・DNS名のどちらも区別しない）。
    pub fn declared_keys_for_value(&self, value: &str) -> Vec<SettingsKey> {
        let mut out = Vec::new();
        for (declared, access) in self.fs.entries() {
            if declared.eq_ignore_ascii_case(value) {
                out.push(SettingsKey::from_access(access));
            }
        }
        if self
            .net
            .allow_domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(value))
        {
            out.push(SettingsKey::NetAllowDomains);
        }
        out
    }

    /// `value`を**祖先として覆っている**FS宣言（`value`自身の宣言は含めない）。
    ///
    /// # なぜ「覆っているだけ」を宣言済みと扱わないのか
    ///
    /// `C:/x/y`が`C:/x`（`fs.read_write`）に覆われているとき、この行に`[x]`を付けて
    /// 「外せば消える」ように見せると嘘になる——実際に消せるのは`C:/x`の宣言で、それを消すと
    /// **兄弟の`C:/x/z`の許可も一緒に消える**。外したときに消えるものが行の見た目と一致しない。
    /// そこでこの関係は「注記」として出すだけにし、取り消しは宣言そのものの行で行わせる。
    ///
    /// 覆うかどうかの規則は[`crate::insufficient::covers`]が唯一の正本である（B-05）。
    pub fn covering_fs_declaration(&self, value: &str) -> Option<(SettingsKey, String)> {
        self.fs
            .entries()
            .into_iter()
            .filter(|(declared, _)| !declared.eq_ignore_ascii_case(value))
            .find(|(declared, _)| crate::insufficient::covers(declared, value))
            .map(|(declared, access)| (SettingsKey::from_access(access), declared.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyFile {
    /// **読み込んだ時点でファイルが名乗っていた版**である。
    ///
    /// 書くときはこの値を使わず、内容から決め直す（[`PolicyFile::required_schema_version`]）。
    /// この欄を書き戻す側の正本にすると、遷移を足しても版が上がらない。
    pub schema_version: u32,
    #[serde(default)]
    pub domains: Vec<PolicyDomain>,
}

impl Default for PolicyFile {
    fn default() -> Self {
        Self {
            schema_version: POLICY_SCHEMA_VERSION,
            domains: Vec::new(),
        }
    }
}

/// 1回の承認で何が増えたか。**「既にある」と「増えた」を区別して見せる**ためのもの
/// ——差分が空なのに「書きました」と言わないため（B-09）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// 新しく追加された`(キーのドット表記, 値)`。
    pub added: Vec<(&'static str, String)>,
    /// 既に同じ値があったので何もしなかった`(キーのドット表記, 値)`。
    pub already_present: Vec<(&'static str, String)>,
    /// このドメインを新規に作ったか。
    pub created_domain: bool,
    /// このコマンドを`commands`へ新しく足したか。
    pub added_command: bool,
}

impl MergeReport {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && !self.created_domain && !self.added_command
    }
}

/// 承認1回ぶんの文脈（提案そのもの以外に記録したいこと）。
pub struct ApprovalContext<'a> {
    pub domain: &'a str,
    /// 記録対象のコマンド（由来として`commands`へ足す）。
    pub command: Option<&'a str>,
    pub cwd: Option<&'a Path>,
    /// 承認の根拠になった記録セッションのid。
    pub record_session: Option<&'a str>,
    pub now_unix_ms: u64,
}

impl PolicyFile {
    pub fn domain(&self, name: &str) -> Option<&PolicyDomain> {
        self.domains.iter().find(|d| d.name == name)
    }

    /// 受理した提案をドメインへ**和集合で**取り込む。
    ///
    /// 既にある値は増やさない（冪等）。値の削除はここでは行わない——このファイルは追記のみで、
    /// 減らす操作は手編集に委ねる（モジュールdoc）。
    pub fn merge_approved(
        &mut self,
        accepted: &[&RuleProposal],
        ctx: &ApprovalContext<'_>,
    ) -> MergeReport {
        let mut report = MergeReport::default();

        if self.domain(ctx.domain).is_none() {
            self.domains.push(PolicyDomain::new(ctx.domain));
            report.created_domain = true;
        }
        // 並びを安定させる（人が読むファイルなので、承認の順序で行が飛び回らない方がよい）。
        self.domains.sort_by(|a, b| a.name.cmp(&b.name));
        let entry = self
            .domains
            .iter_mut()
            .find(|d| d.name == ctx.domain)
            .expect("just inserted or already present");

        if let Some(command) = ctx.command {
            if !entry.commands.iter().any(|c| c == command) {
                entry.commands.push(command.to_string());
                report.added_command = true;
            }
        }
        if entry.cwd.is_none() {
            entry.cwd = ctx.cwd.map(|p| p.to_path_buf());
        }

        for proposal in accepted {
            let dotted = proposal.key.dotted();
            let bucket = match proposal.key {
                SettingsKey::NetAllowDomains => &mut entry.net.allow_domains,
                other => entry
                    .fs
                    .bucket_mut(other)
                    .expect("non-net keys always have an fs bucket"),
            };
            if bucket.iter().any(|v| v == &proposal.value) {
                report
                    .already_present
                    .push((dotted, proposal.value.clone()));
            } else {
                bucket.push(proposal.value.clone());
                report.added.push((dotted, proposal.value.clone()));
            }
        }

        // 値の並びも安定させる（同上）。
        entry.fs.read.sort();
        entry.fs.read_write.sort();
        entry.fs.read_exec.sort();
        entry.net.allow_domains.sort();

        if !report.is_empty() {
            if let Some(session) = ctx.record_session {
                if !entry
                    .provenance
                    .record_sessions
                    .iter()
                    .any(|s| s == session)
                {
                    entry.provenance.record_sessions.push(session.to_string());
                }
            }
            entry.provenance.updated_unix_ms = ctx.now_unix_ms;
        }

        report
    }

    /// この内容を表すのに**最低限必要な**スキーマ版。
    ///
    /// # なぜ「今のバイナリの版」をそのまま書かないのか
    ///
    /// 遷移を1本も使っていないワークスペースを、古いバイナリから読めなくする理由が無いためである。
    /// 逆に遷移が1本でもあれば、**無視されると意味が変わる**ので上げなければならない
    /// （`plans/DESIGN-MAC.md` §5.1(7)）。
    ///
    /// **版の正本は内容そのもの**にしてある——[`save`]はこの値を書くので、
    /// ファイルの中の`schema_version`と中身が食い違う状態を作れない（`B-13`: 正本を2つ持たない）。
    pub fn required_schema_version(&self) -> u32 {
        if self.domains.iter().any(|d| !d.process.is_empty()) {
            POLICY_SCHEMA_VERSION
        } else {
            SCHEMA_VERSION_WITHOUT_TRANSITIONS
        }
    }

    /// 遷移の判定器へ渡す「ドメインの見え方」。
    ///
    /// 「呼び出し元から書ける場所」として、宣言の外にあるものを2つ受ける——**宣言だけを見ると
    /// ここが抜ける**。固定したargvが指すスクリプトがそこにあれば、呼び出し元がそれを
    /// 書き換えられるので固定の意味が無くなる（`plans/DESIGN-MAC.md` §19.1）。
    ///
    /// - `workspace_root`: ワークスペースルート
    /// - `writable_outside_policy`: **`policy.json`の外で書込を許した場所**
    ///   （`settings.json`の`fs.read_write`・`--fs-allow <path>:rw`。残課題 サンドボックス周辺 #65）。
    ///   これを持つのは`harness.exe`だけで、ポリシーエディタは`--fs-allow`も`settings.json`も
    ///   読まないので空を渡す
    ///
    /// **どちらも既定値を持たない。** 呼び出し元ごとに何を渡すかを選ばせる——既定があると、
    /// 新しい呼び出し元が選ばずに通れてしまい、その経路だけ検査が黙って緩くなる。
    pub fn transition_graph_input<'a>(
        &'a self,
        workspace_root: Option<&'a str>,
        writable_outside_policy: &'a [String],
    ) -> GraphInput<'a> {
        GraphInput {
            domains: self
                .domains
                .iter()
                .map(|domain| DomainView {
                    name: domain.name.as_str(),
                    fs: domain.fs.entries(),
                    net: domain
                        .net
                        .allow_domains
                        .iter()
                        .map(|d| d.as_str())
                        .collect(),
                    process: &domain.process,
                })
                .collect(),
            caller_writable_roots: workspace_root
                .into_iter()
                .chain(writable_outside_policy.iter().map(String::as_str))
                .collect(),
        }
    }

    /// 全ドメインが宣言しているFSパスの集合（重複除去）。`harness_policy`の
    /// 「既に許可済みなのに拒否された＝その許可では足りない」判定へ渡すのに使う。
    pub fn all_fs_entries(&self) -> Vec<(String, harness_config::FsAccess)> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for domain in &self.domains {
            for (value, access) in domain.fs.entries() {
                if seen.insert((value.to_string(), access)) {
                    out.push((value.to_string(), access));
                }
            }
        }
        out
    }
}

/// ドメイン名の既定値——コマンドの先頭トークンのbasename（`cargo build` → `cargo`、
/// `C:\tools\gh.exe pr list` → `gh`）。
///
/// **実行時マッチャではなく識別子**なので、衝突したら呼び出し側が明示させる（CLIなら
/// `--domain`、TUIなら編集画面の入力欄）。CLIとTUIで既定値がずれると、同じコマンドを
/// 記録したのに別のドメインへ書き込まれるので、規則はここ1箇所に持つ。
pub fn default_domain_name(command: &str) -> String {
    let token = command.split_whitespace().next().unwrap_or("");
    let token = token.trim_matches(['"', '\'']);
    let name = token.rsplit(['\\', '/']).next().unwrap_or(token);
    name.rsplit_once('.')
        .map(|(s, _)| s)
        .unwrap_or(name)
        .to_string()
}

/// `<workspace>/.harness/policy.json`。
pub fn path(workspace_root: &Path) -> PathBuf {
    workspace_root.join(".harness").join(POLICY_FILE_NAME)
}

/// 読み込む。**存在しない場合だけ空として扱う**——読めない・壊れている場合はエラーにする。
///
/// 黙って空にすると、承認済みのルールが消えたまま「承認できました」と言い続けることになる
/// （そのままパス2を走らせると、開くべき穴が開いていない状態で動く）。B-10。
///
/// **`policy.json`の外で書込を許した場所を持たない呼び出し元のための形**である
/// （ポリシーエディタ。`--fs-allow`も`settings.json`も読まない）。
/// それを持つ`harness.exe`は[`load_for_session`]を使う。
pub fn load(workspace_root: &Path) -> Result<PolicyFile, PolicyFileError> {
    load_for_session(workspace_root, &[])
}

/// [`load`]と同じだが、遷移の編集時検査に**`policy.json`の外で書込を許した場所**も数える
/// （[`PolicyFile::transition_graph_input`]の`writable_outside_policy`）。
///
/// # なぜ要るのか（残課題 サンドボックス周辺 #65）
///
/// 固定した遷移は、固定値が指すファイルを呼び出し元が書き換えられないことを前提にしている
/// （`plans/DESIGN-MAC.md` §19.1）。`settings.json`の`fs.read_write`や`--fs-allow <path>:rw`で
/// 書込を許した場所は宣言に現れないので、ここで渡さないと検査が見落とす——そこに置いた
/// 遷移先のプログラムを、ワークスペース内のコードが書き換えて遷移先の権限で走らせられる。
///
/// **Daemonへも同じ一覧を渡すこと**（`TransitionPolicy::writable_outside_policy`）。
/// 片側だけに渡すと、2つのプロセスの検査が別の入力を見る。
pub fn load_for_session(
    workspace_root: &Path,
    writable_outside_policy: &[String],
) -> Result<PolicyFile, PolicyFileError> {
    let path = path(workspace_root);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(PolicyFile::default()),
        Err(e) => return Err(PolicyFileError::Read { path, source: e }),
    };
    let file: PolicyFile = serde_json::from_str(&text).map_err(|e| PolicyFileError::Parse {
        path: path.clone(),
        source: e,
    })?;
    if file.schema_version > POLICY_SCHEMA_VERSION {
        return Err(PolicyFileError::FutureSchema {
            path,
            found: file.schema_version,
            supported: POLICY_SCHEMA_VERSION,
        });
    }
    // **版が内容に追いついていないファイルを拒否する**（`plans/DESIGN-MAC.md` §5.1(7)）。
    // [`save`]が版を内容から決めるので、この形は手で書いたときにしか生まれない——
    // だが生まれてしまうと、遷移を知らない古いバイナリが**黙って無視して**読む。
    // 書く側と読む側を対にして初めて塞がる（`B-01`）。
    let required = file.required_schema_version();
    if file.schema_version < required {
        return Err(PolicyFileError::UnversionedTransitions {
            path,
            found: file.schema_version,
            required,
        });
    }
    // **編集時検査をここへ置く理由**: 検査を書いても呼ぶ人が居なければ、手で書いた危険な辺が
    // 素通りする（`B-01`: 対の片方だけ実装しない）。この関数は`policy.json`を読む唯一の関数
    // （[`load`]もここへ委譲する）なので、ここを通せば読む側の全経路が通る。
    // 宣言画面は書く前に**同じ検査関数**（`transition::check_all`）を呼ぶ。
    let workspace = workspace_root.to_string_lossy();
    let input = file.transition_graph_input(Some(workspace.as_ref()), writable_outside_policy);
    let rejected = match transition::check_all(&input) {
        Ok(rejections) => rejections.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
        Err(e) => vec![e.to_string()],
    };
    if !rejected.is_empty() {
        return Err(PolicyFileError::RejectedTransitions {
            path,
            reason: rejected.join("; "),
        });
    }
    Ok(file)
}

/// 書き出す（上書き）。親ディレクトリ（`.harness`）が無ければ作る。
///
/// **スキーマ版は内容から決めて書く**（[`PolicyFile::required_schema_version`]）。
/// 渡された`file`が持っている`schema_version`は読み込んだ時点の値なので、そのまま書き戻すと
/// **遷移を足したのに版が上がらない**——古いバイナリが黙って無視して読む形が残る。
pub fn save(workspace_root: &Path, file: &PolicyFile) -> Result<(), PolicyFileError> {
    let path = path(workspace_root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| PolicyFileError::Write {
            path: path.clone(),
            source: e,
        })?;
    }
    let file = &PolicyFile {
        schema_version: file.required_schema_version(),
        domains: file.domains.clone(),
    };
    let mut text = serde_json::to_string_pretty(file).map_err(|e| PolicyFileError::Write {
        path: path.clone(),
        source: std::io::Error::other(e.to_string()),
    })?;
    text.push('\n');
    std::fs::write(&path, text).map_err(|e| PolicyFileError::Write { path, source: e })
}

#[cfg(test)]
#[path = "policy_file_tests.rs"]
mod policy_file_tests;
