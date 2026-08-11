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
//!   （このファイルはharness.exeからは読まれない）。
//! - 同名ドメインへの承認は**和集合マージ**（[`PolicyFile::merge_approved`]）。
//!   **取り消しは[`crate::unapprove`]が持つ**（宣言画面`F4`とCLIの`unapprove`）。
//!   かつてここには「追記のみ。削除の操作は無い（手で編集する）。中途半端な削除UIは
//!   付与の対（撤収）にならない」と書いてあったが、**その判断は撤回した**——理由は
//!   「付与の対」が何なのかが実測で分かったことである。ACEが付くのはパス2の開始時で、
//!   剥がすのはプロセス終了時と（宣言が縮んだときは）次のパス2の開始時なので、
//!   **宣言を消す操作は`policy.json`だけを触れば対になる**。詳細は`unapprove`のモジュールdoc。
//! - 値の**編集**（accessの付け替え等）は依然として無い。取り消してから承認し直す。
//!
//! # 値の意味は「著者支援」であって実行時マッチャではない（決定2）
//!
//! ここに入るのは`harness_policy::generalize`が出した設定値の綴り（`C:\...\**`等）そのままで、
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

use harness_policy::{generalize::SettingsKey, RuleProposal};
use serde::{Deserialize, Serialize};

/// ワークスペーススコープの置き場（`<workspace>/.harness/policy.json`）。
pub const POLICY_FILE_NAME: &str = "policy.json";

/// 読む側が想定外の形を黙って解釈しないために持つ。
pub const POLICY_SCHEMA_VERSION: u32 = 1;

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
}

/// ドメイン1件のFSルール。キーは`harness_policy::SettingsKey`と1:1で対応させる
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
    /// 覆うかどうかの規則は[`harness_policy::insufficient::covers`]が唯一の正本である（B-05）。
    pub fn covering_fs_declaration(&self, value: &str) -> Option<(SettingsKey, String)> {
        self.fs
            .entries()
            .into_iter()
            .filter(|(declared, _)| !declared.eq_ignore_ascii_case(value))
            .find(|(declared, _)| harness_policy::insufficient::covers(declared, value))
            .map(|(declared, access)| (SettingsKey::from_access(access), declared.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyFile {
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
pub fn load(workspace_root: &Path) -> Result<PolicyFile, PolicyFileError> {
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
    Ok(file)
}

/// 書き出す（上書き）。親ディレクトリ（`.harness`）が無ければ作る。
pub fn save(workspace_root: &Path, file: &PolicyFile) -> Result<(), PolicyFileError> {
    let path = path(workspace_root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| PolicyFileError::Write {
            path: path.clone(),
            source: e,
        })?;
    }
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
