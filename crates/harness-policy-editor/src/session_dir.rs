//! 記録セッションの置き場と、そこに残すマニフェスト。
//!
//! # 置き場が`.harness/sandbox/`配下でなければならない理由
//!
//! 監査ログを書くのは**昇格した収集器**で、その書込先は昇格側が
//! `harness_sandbox::elevated_launch::validate_audit_sink_path`で検証する
//! ——`<workspace>/.harness/sandbox/`配下でなければ拒否される。非昇格の親が指定した
//! 任意パスへ管理者権限で追記できてしまうと、それは任意パス追記プリミティブそのものだからである。
//! したがって記録セッションのディレクトリは**この場所以外に置けない**（好みの問題ではない）。
//!
//! 検証は親ディレクトリを`canonicalize`するので、**`StartCollect`を送る前にディレクトリが
//! 実在していなければならない**。[`RecordSessionDir::create`]が先に作る理由がこれ。
//!
//! # 正本はJSONLであってマニフェストではない
//!
//! `fs-audit.jsonl`が観測の唯一の正本で、[`RecordManifest`]は「いつ・どのコマンドを・
//! どの条件で記録したか」という**文脈**と、後から計算し直せない事実（終了コード・
//! 収集器が起動できたか）だけを持つ。候補の集計値はここに保存しない——
//! `show`は毎回JSONLから計算し直す（同じ事実の正本を2つ持たない、B-13）。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// 記録セッションのディレクトリ名の接頭辞。`.harness/sandbox/`には会話セッションの
/// ディレクトリ（`session-<id>`）も並ぶので、接頭辞で見分ける。
pub const RECORD_DIR_PREFIX: &str = "policy-editor-";
/// 収集器が書く監査ログのファイル名（deny-onlyの`harness policy learn`と同じ名前）。
pub const AUDIT_LOG_FILE_NAME: &str = "fs-audit.jsonl";
/// パス2でProxy・Fake DNS・WFPが書く監査ログのファイル名（`harness net audit`と同じ名前）。
pub const NET_AUDIT_LOG_FILE_NAME: &str = "net-audit.jsonl";
/// 記録セッションのマニフェスト。
pub const MANIFEST_FILE_NAME: &str = "record-session.json";

/// マニフェストの形式。読む側が想定外の形を黙って解釈しないように持つ。
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// 記録セッションの進行状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordStatus {
    /// 記録中。**このまま残っていたら異常終了である**（正常な経路は必ず上書きする）。
    Running,
    /// 対象コマンドが終了し、収集器も撤収した。
    Finished,
    /// ユーザーのキャンセル、またはタイムアウトで打ち切った。
    Canceled,
    /// 記録を開始できなかった（収集器の起動失敗・記録対象のspawn失敗）。
    Failed,
}

impl RecordStatus {
    pub fn label(self) -> &'static str {
        match self {
            RecordStatus::Running => "記録中（このまま残っていれば異常終了）",
            RecordStatus::Finished => "完了",
            RecordStatus::Canceled => "中断",
            RecordStatus::Failed => "失敗",
        }
    }
}

/// `pass`フィールドを持たない旧マニフェストはパス1（FS記録）として読む。
fn default_pass() -> u8 {
    1
}

/// 記録セッション1回分の文脈。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordManifest {
    pub schema_version: u32,
    pub id: String,
    /// 2パス記録のどちらか（1=FS記録、2=Tier2aでのドメイン記録）。
    /// **旧マニフェスト（このフィールドが無いもの）はパス1として読む**（後方互換）。
    #[serde(default = "default_pass")]
    pub pass: u8,
    /// **記録対象をどのシェル隔離Tierで走らせたか**（`"tier0"`・`"tier1"`・`"tier2a"`）。
    ///
    /// パス1は2026-08-10にTier1からTier0へ移した。Tier1では低ILラベルがcwd 1個にしか
    /// 付かないため、既存サブディレクトリやcwd外への書込が**Tier1固有の理由で**拒否され、
    /// それが候補一覧へ流れ込んでいたからである（`tier0`のモジュールdoc参照）。
    ///
    /// **したがって、この札が無い／`tier1`である古い記録は、Tier1の実装都合による拒否を
    /// 含んでいる可能性がある。** 札を持たないと新旧の記録を見分けられず、汚れた候補を
    /// そのまま承認しかねないので、記録側の事実として残す。
    /// 旧マニフェストは`None`＝「記録されていない」で、`tier1`と断定はしない
    /// （観測しなかったことと、値がそうだったことを混ぜない）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell_tier: Option<String>,
    /// パス2で使ったポリシードメイン名（パス1では`None`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// 走らせたコマンド（そのままの綴り）。
    pub command: String,
    pub cwd: PathBuf,
    pub workspace_root: PathBuf,
    pub started_unix_ms: u64,
    pub status: RecordStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// 収集器（`harness-policy-learnd.exe`）が起動できたか。
    pub collector_started: bool,
    /// ETWセッションが実際に張れたか。`false`なら**何も観測できていない**
    /// ——「拒否が0件だった」と区別できないと、fail-openは単なる隠蔽になる（D-43）。
    pub etw_available: bool,
    /// 収集器の自己申告による書込件数。JSONLの実際の行数とは独立の事実として残す
    /// （食い違ったら、それ自体が調査の手掛かりになる）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector_written: Option<u64>,
    /// 記録中に起きた、ユーザーへ伝える価値のある事実（低ILラベルの付与失敗等）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// **記録できなかった理由**（`status: Failed`のときだけ入る）。
    ///
    /// これが無かった頃、失敗した記録には`status: failed`しか残らず、
    /// 「WFPのdaemonが拒んだのか」「Tier2aへ着地しなかったのか」「実行ファイルを起こせなかったのか」を
    /// 後から区別できなかった——**次の一手を決める材料がどこにも無い**状態である（B-09/B-10）。
    /// 進行ログは末尾しか見せない窓なので、実行が終わった時点で理由は画面からも消える。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// 失敗の種別（`no_wfp`・`not_tier2a`・`spawn`…）。**機械可読の安定した札**で、
    /// 文面（[`Self::error`]）を変えても壊れない。綴りの正本は`RecordNetError::kind`と
    /// `RecordError::kind`で、どちらもワイルドカード無しの`match`なので
    /// **variantを足すとビルドが落ちる**（札の付け忘れをコンパイラが捕まえる）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    /// 実行前診断（`exec_reach`）が「このままでは起動できない」と**名指しした実行ファイル**。
    /// 綴りは設定へそのまま書ける形（パス2だけが書く）。
    ///
    /// **観測ではないのでJSONLには書けない。** `fs-audit.jsonl`は昇格した収集器が書く観測の
    /// 唯一の正本で、非昇格の親が導出値を混ぜると「観測した」と「そう判断した」が
    /// 区別できなくなる（モジュールdoc）。一方これは**後から計算し直せない事実**
    /// （そのときのPATHとそのときの宣言で解決した結果）なので、マニフェストが持つ。
    /// 読む側は[`crate::aggregate::from_session`]が`fs.read_exec`の候補として合流させる。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreachable_exec: Option<String>,
    /// **この記録を走らせた時点の**ドメインのFS宣言（パス2だけが書く）。
    ///
    /// 候補の昇格（D-46「既に許可済みなのに拒否された＝その許可では足りない」）に使う。
    /// 現在の`policy.json`を読み直すのでは駄目である——承認して1周した後に古い記録を
    /// 開き直すと、**当時は成立していなかった診断**が出る（「read_execは許可済みなのに
    /// 拒否された→書込が要る」）。ここも「後から計算し直せない事実」にあたる。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_fs: Vec<DeclaredFsRule>,
}

/// 記録時点で宣言されていたFSルール1件（[`RecordManifest::declared_fs`]）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclaredFsRule {
    /// `policy.json`に書かれている綴りそのまま。
    pub value: String,
    pub access: harness_config::FsAccess,
}

impl RecordManifest {
    pub fn new(
        id: impl Into<String>,
        command: impl Into<String>,
        cwd: &Path,
        workspace_root: &Path,
        started_unix_ms: u64,
    ) -> Self {
        Self {
            schema_version: MANIFEST_SCHEMA_VERSION,
            id: id.into(),
            pass: default_pass(),
            // 実際に着地したTierは記録を始める側（`record`/`record_net`）しか知らないので、
            // ここでは空にしておき、Tierが確定した時点で代入する。
            shell_tier: None,
            domain: None,
            command: command.into(),
            cwd: cwd.to_path_buf(),
            workspace_root: workspace_root.to_path_buf(),
            started_unix_ms,
            status: RecordStatus::Running,
            finished_unix_ms: None,
            exit_code: None,
            collector_started: false,
            etw_available: false,
            collector_written: None,
            warnings: Vec::new(),
            error: None,
            error_kind: None,
            unreachable_exec: None,
            declared_fs: Vec::new(),
        }
    }

    /// 記録を**失敗として閉じる**。`status`・`finished_unix_ms`・`error`・`error_kind`を
    /// まとめて立てる。
    ///
    /// # なぜ個別代入をやめたのか
    ///
    /// `status = Failed`だけを書ける形が残っていると、理由の欄はいずれ片方だけ更新されて
    /// 空のまま残る（B-01: 対の片方だけ書ける形を残さない）。実際、この関数が入る前の
    /// `Err`経路は`status`と`finished_unix_ms`しか埋めておらず、実マシンの記録3件が
    /// **理由の無い`failed`**として残っていた。
    pub fn fail(
        &mut self,
        finished_unix_ms: u64,
        kind: &'static str,
        error: &dyn std::fmt::Display,
    ) {
        self.status = RecordStatus::Failed;
        self.finished_unix_ms = Some(finished_unix_ms);
        self.error_kind = Some(kind.to_string());
        self.error = Some(error.to_string());
    }

    /// 失敗した記録を見せるときの1件（CLIの`show`/`sessions`・TUIの注記と⚠欄が共有する）。
    ///
    /// **文言の持ち主はここ1箇所**（`docs/CODE-STRUCTURE-RULES.md`規則5）。表示側で書き写すと、
    /// 経路ごとに違う言い方になり、片方だけが更新される。
    ///
    /// 理由の欄が入る前に書かれた古いマニフェストは`error`が無い。そのとき
    /// **「理由が無い」と「理由が空だった」を混ぜない**——後者に見せると、
    /// 記録側の欠陥が「そういう失敗だった」として読まれる（D-43）。
    pub fn failure_note(&self) -> Option<String> {
        if self.status != RecordStatus::Failed {
            return None;
        }
        Some(match (&self.error, &self.error_kind) {
            (Some(error), Some(kind)) => failure_note_text(kind, error),
            (Some(error), None) => format!("記録できなかった理由: {error}"),
            (None, _) => "記録できなかった理由: （記録されていません——この記録は理由の欄が\
                          入る前のものです）"
                .to_string(),
        })
    }
}

/// 失敗の文言。**記録した直後（エラー値を持っている側）と、後から読み直した側の両方**が
/// これを通す——同じ失敗が画面によって別の言い方になると、ユーザーは同じ事実を2つの
/// 出来事として読む（B-32・規則5）。
pub fn failure_note_text(kind: &str, error: &dyn std::fmt::Display) -> String {
    format!("記録できなかった理由（{kind}）: {error}")
}

/// 記録セッション1回分のディレクトリ。
#[derive(Debug, Clone)]
pub struct RecordSessionDir {
    path: PathBuf,
    id: String,
}

impl RecordSessionDir {
    /// ディレクトリを作る。**`StartCollect`より前に呼ぶ**（モジュールdoc参照）。
    pub fn create(workspace_root: &Path, id: &str) -> std::io::Result<Self> {
        let path = sandbox_root(workspace_root).join(format!("{RECORD_DIR_PREFIX}{id}"));
        std::fs::create_dir_all(&path)?;
        Ok(Self {
            path,
            id: id.to_string(),
        })
    }

    /// 既存のディレクトリを開く（`show`用。作らない）。
    pub fn open(workspace_root: &Path, id: &str) -> Option<Self> {
        let path = sandbox_root(workspace_root).join(format!("{RECORD_DIR_PREFIX}{id}"));
        path.is_dir().then_some(Self {
            path,
            id: id.to_string(),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn audit_log_path(&self) -> PathBuf {
        self.path.join(AUDIT_LOG_FILE_NAME)
    }

    /// パス2の監査ログ。**FS側と同じディレクトリの別ファイル**にする——1回の記録という
    /// 単位は同じで、スキーマが違うだけだからである（`harness net audit`が読む形と同じ）。
    pub fn net_audit_log_path(&self) -> PathBuf {
        self.path.join(NET_AUDIT_LOG_FILE_NAME)
    }

    pub fn manifest_path(&self) -> PathBuf {
        self.path.join(MANIFEST_FILE_NAME)
    }

    /// マニフェストを書く（上書き）。**失敗しても記録そのものは止めない**が、
    /// 呼び出し側が事実を表示できるよう`Err`は返す（握り潰さない、B-10）。
    pub fn write_manifest(&self, manifest: &RecordManifest) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(manifest)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        std::fs::write(self.manifest_path(), json)
    }

    pub fn read_manifest(&self) -> Option<RecordManifest> {
        let text = std::fs::read_to_string(self.manifest_path()).ok()?;
        serde_json::from_str(&text).ok()
    }
}

/// `<workspace>/.harness/sandbox`。
pub fn sandbox_root(workspace_root: &Path) -> PathBuf {
    workspace_root.join(".harness").join("sandbox")
}

/// **記録1回ごとに**新しいディレクトリを使うためのid（`<セッショントークン>-<連番>`）。
///
/// # なぜプロセス単位ではいけないのか
///
/// かつてidは`session_profile::session_token()`そのものだった。これは**プロセス内で一度だけ
/// 確定する`OnceLock`**なので、1プロセスで2回記録すると2回目の[`RecordSessionDir::create`]が
/// 1回目と同じディレクトリを開き、同じ`fs-audit.jsonl`/`net-audit.jsonl`へ追記し、
/// `AuditTail`はオフセット0から読み直す——つまり**1回目の観測が2回目の候補一覧に混ざり、
/// マニフェストは上書きされる**。「1プロセス＝1回の記録」という、どこにも書かれていない等価関係に
/// 依存していた（B-07）。ポリシーエディタは1回の起動で記録を何度も走らせる道具なので、
/// D-56（昇格daemonの再利用）で繰り返しが「普通の使い方」になった時点で実害の出る位置に来た。
///
/// # セッションプロファイル名とは別物である
///
/// **ここで返すidをAppContainerのプロファイル名に使ってはいけない。** package SIDの単位は
/// D-37のとおり「セッション＝プロセスの寿命」のままで、`current_profile_name()`が正本である。
/// 分けているのは*記録の置き場*だけで、権限の主体は分けていない。
pub fn next_record_id() -> String {
    static SERIAL: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let serial = SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    format!(
        "{}-{serial}",
        harness_sandbox::tier2a::session_profile::session_token()
    )
}

/// 記録セッションを新しい順（`started_unix_ms`の降順）に列挙する。
///
/// マニフェストが読めないディレクトリは飛ばす——記録の途中で電源が落ちた場合など、
/// ディレクトリだけがある状態は起こり得る。
pub fn list_sessions(workspace_root: &Path) -> Vec<(RecordSessionDir, RecordManifest)> {
    let Ok(entries) = std::fs::read_dir(sandbox_root(workspace_root)) else {
        return Vec::new();
    };
    let mut sessions: Vec<(RecordSessionDir, RecordManifest)> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if !path.is_dir() {
                return None;
            }
            let name = path.file_name()?.to_str()?;
            let id = name.strip_prefix(RECORD_DIR_PREFIX)?;
            let dir = RecordSessionDir {
                path: path.clone(),
                id: id.to_string(),
            };
            let manifest = dir.read_manifest()?;
            Some((dir, manifest))
        })
        .collect();
    sessions.sort_by_key(|(_, manifest)| std::cmp::Reverse(manifest.started_unix_ms));
    sessions
}

/// 最も新しい記録セッション。
pub fn latest_session(workspace_root: &Path) -> Option<(RecordSessionDir, RecordManifest)> {
    list_sessions(workspace_root).into_iter().next()
}

pub fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(sandbox_root(dir.path())).unwrap();
        dir
    }

    /// **Tierの札が無い古いマニフェストは`None`として読む。**
    ///
    /// パス1をTier1からTier0へ移した2026-08-10より前の記録には`shell_tier`が無い。
    /// ここを`tier1`で埋めてしまうと「観測しなかった」と「Tier1だった」が混ざるので、
    /// 欠落は欠落のまま読む（`RecordManifest::shell_tier`のdoc）。
    /// 新しい記録が札を持つことも同時に固定する——片方だけだと、
    /// 「そもそも一度も書かれていない」状態を検出できない（B-35）。
    #[test]
    fn a_manifest_without_a_tier_tag_reads_as_unknown_not_as_tier1() {
        let old = r#"{
            "schema_version": 1,
            "id": "old-1",
            "command": "cargo test",
            "cwd": "C:/w",
            "workspace_root": "C:/w",
            "started_unix_ms": 1,
            "status": "finished",
            "collector_started": true,
            "etw_available": true
        }"#;
        let parsed: RecordManifest = serde_json::from_str(old).expect("old manifests must parse");
        assert_eq!(
            parsed.shell_tier, None,
            "a missing tier tag means 'not recorded', which is not the same as 'it was tier1'"
        );

        let mut fresh = RecordManifest::new(
            "new-1",
            "cargo test",
            Path::new("C:/w"),
            Path::new("C:/w"),
            1,
        );
        fresh.shell_tier = Some("tier0".to_string());
        let round_tripped: RecordManifest =
            serde_json::from_str(&serde_json::to_string(&fresh).unwrap()).unwrap();
        assert_eq!(
            round_tripped.shell_tier.as_deref(),
            Some("tier0"),
            "a recorded tier tag must survive a write/read round trip"
        );
    }

    /// 監査ログの置き場は`<workspace>/.harness/sandbox/policy-editor-<id>/`でなければ
    /// 昇格側に拒否される（モジュールdoc）。**その形を固定する。**
    #[test]
    fn the_audit_log_lives_where_the_elevated_side_will_accept_it() {
        let ws = workspace();
        let dir = RecordSessionDir::create(ws.path(), "abc-1").unwrap();

        let sink = dir.audit_log_path();
        assert!(sink.starts_with(sandbox_root(ws.path())));
        assert_eq!(sink.file_name().unwrap(), AUDIT_LOG_FILE_NAME);
        assert!(
            dir.path().is_dir(),
            "the directory must exist before StartCollect (validate_audit_sink_path canonicalizes it)"
        );
    }

    /// マニフェストは書いて読み戻せる（往復）。
    #[test]
    fn the_manifest_round_trips() {
        let ws = workspace();
        let dir = RecordSessionDir::create(ws.path(), "abc-2").unwrap();
        let mut manifest = RecordManifest::new(
            "abc-2",
            "cargo build",
            Path::new("C:/work"),
            ws.path(),
            1_700_000_000_000,
        );
        manifest.status = RecordStatus::Finished;
        manifest.exit_code = Some(0);
        manifest.collector_started = true;
        manifest.etw_available = true;
        manifest.collector_written = Some(42);
        manifest.warnings.push("low-IL label failed".to_string());
        manifest.unreachable_exec = Some("C:/Users/me/.cargo/bin/cargo.exe".to_string());
        manifest.declared_fs = vec![DeclaredFsRule {
            value: "C:/Users/me/.cargo/bin".to_string(),
            access: harness_config::FsAccess::Read,
        }];

        dir.write_manifest(&manifest).unwrap();
        let read_back = dir.read_manifest().expect("manifest must be readable");

        assert_eq!(read_back.id, "abc-2");
        assert_eq!(read_back.command, "cargo build");
        assert_eq!(read_back.status, RecordStatus::Finished);
        assert_eq!(read_back.exit_code, Some(0));
        assert_eq!(read_back.collector_written, Some(42));
        assert_eq!(read_back.warnings, vec!["low-IL label failed".to_string()]);
        // 観測に現れない事実（実行前診断・記録時点の宣言）も往復すること
        // ——ここが落ちると、候補の合流と昇格がどちらも黙って無効になる。
        assert_eq!(
            read_back.unreachable_exec.as_deref(),
            Some("C:/Users/me/.cargo/bin/cargo.exe")
        );
        assert_eq!(read_back.declared_fs, manifest.declared_fs);
    }

    /// **開始時点で`Running`として書く**ので、異常終了したセッションは`Running`のまま残る。
    /// これを「完了」と区別できることが、後から見たときに嘘をつかない条件（B-09）。
    #[test]
    fn a_session_that_never_finished_stays_visible_as_running() {
        let ws = workspace();
        let dir = RecordSessionDir::create(ws.path(), "abc-3").unwrap();
        let manifest = RecordManifest::new("abc-3", "sleep 999", ws.path(), ws.path(), 1);
        dir.write_manifest(&manifest).unwrap();

        let (_, read_back) = latest_session(ws.path()).expect("one session");
        assert_eq!(read_back.status, RecordStatus::Running);
        assert!(read_back.finished_unix_ms.is_none());
    }

    /// 列挙は新しい順で、会話セッションのディレクトリ（`session-*`）は混ざらない。
    #[test]
    fn sessions_are_listed_newest_first_and_conversation_dirs_are_ignored() {
        let ws = workspace();
        for (id, started) in [("old", 100u64), ("new", 300), ("mid", 200)] {
            let dir = RecordSessionDir::create(ws.path(), id).unwrap();
            dir.write_manifest(&RecordManifest::new(
                id,
                "cmd",
                ws.path(),
                ws.path(),
                started,
            ))
            .unwrap();
        }
        // 会話セッションのディレクトリ（別機構が作る）は記録セッションではない。
        std::fs::create_dir_all(sandbox_root(ws.path()).join("session-42")).unwrap();

        let ids: Vec<String> = list_sessions(ws.path())
            .into_iter()
            .map(|(_, m)| m.id)
            .collect();

        assert_eq!(ids, vec!["new", "mid", "old"]);
    }

    /// マニフェストが無いディレクトリは列挙されない（記録の途中で落ちてディレクトリだけ
    /// 残った場合。**壊れた入力で止まらない**、D-43）。
    #[test]
    fn a_directory_without_a_manifest_is_skipped_instead_of_failing() {
        let ws = workspace();
        RecordSessionDir::create(ws.path(), "no-manifest").unwrap();

        assert!(list_sessions(ws.path()).is_empty());
        assert!(latest_session(ws.path()).is_none());
    }

    /// **同じプロセスで2回記録しても、置き場が別になる。**
    ///
    /// idが`session_token()`そのものだった頃は2回目が1回目のディレクトリを開き、同じ
    /// `fs-audit.jsonl`へ追記していた（[`next_record_id`]のdoc）。ここで固定するのは
    /// 「idが違う」ことではなく**1回目の観測が2回目の監査ログに現れない**ことである
    /// ——混ざるかどうかが実害の所在で、idの綴りはその手段でしかない。
    #[test]
    fn two_recordings_in_one_process_do_not_share_an_audit_log() {
        let ws = workspace();

        let first = RecordSessionDir::create(ws.path(), &next_record_id()).unwrap();
        std::fs::write(first.audit_log_path(), "first-run\n").unwrap();
        let second = RecordSessionDir::create(ws.path(), &next_record_id()).unwrap();

        assert_ne!(first.path(), second.path());
        assert!(
            !second.audit_log_path().exists(),
            "the second recording must start from an empty audit log, not append to the first"
        );
        assert_eq!(
            list_sessions(ws.path()).len(),
            0,
            "manifests not written yet"
        );
    }

    /// idはセッショントークン（＝package SIDの単位）を**含む**が、それと同一ではない。
    /// 同一に戻すと上のテストが壊れるので、ここは「何を手段にしているか」の記録である。
    #[test]
    fn the_record_id_is_derived_from_the_session_token_but_is_not_it() {
        let token = harness_sandbox::tier2a::session_profile::session_token();

        let id = next_record_id();

        assert!(id.starts_with(token), "id={id} token={token}");
        assert_ne!(id, token);
        assert_ne!(next_record_id(), id, "each recording gets its own id");
    }

    /// **失敗した記録には理由が必ず入る。**
    ///
    /// `fail`を通す形にしたのは、`status = Failed`だけを書ける経路が残っていると
    /// 理由の欄がいずれ空のまま放置されるから（B-01）。ここで固定するのは
    /// 「4つが同時に立つ」ことであって、綴りではない。
    #[test]
    fn a_failed_recording_always_carries_its_reason() {
        let mut manifest =
            RecordManifest::new("f-1", "cargo test", Path::new("C:/w"), Path::new("C:/w"), 1);

        manifest.fail(999, "no_wfp", &"WFPのdaemonを起動できませんでした");

        assert_eq!(manifest.status, RecordStatus::Failed);
        assert_eq!(manifest.finished_unix_ms, Some(999));
        assert_eq!(manifest.error_kind.as_deref(), Some("no_wfp"));
        assert!(manifest
            .error
            .as_deref()
            .is_some_and(|e| e.contains("WFPのdaemon")));
        let note = manifest.failure_note().expect("a failed record has a note");
        assert!(note.contains("no_wfp"), "{note}");
        assert!(note.contains("WFPのdaemon"), "{note}");
    }

    /// 対の側: **成功した記録には理由の欄が出ない**（`Failed`以外で`failure_note`は`None`）。
    ///
    /// 片側だけ固定すると「常に理由が出る」実装でもテストは緑になる（B-35）。
    #[test]
    fn a_successful_recording_has_no_reason_on_disk_or_on_screen() {
        let ws = workspace();
        let dir = RecordSessionDir::create(ws.path(), "ok-1").unwrap();
        let mut manifest = RecordManifest::new("ok-1", "cargo build", ws.path(), ws.path(), 1);
        manifest.status = RecordStatus::Finished;

        assert!(manifest.failure_note().is_none());
        dir.write_manifest(&manifest).unwrap();
        let json = std::fs::read_to_string(dir.manifest_path()).unwrap();
        assert!(!json.contains("\"error\""), "{json}");
        assert!(!json.contains("\"error_kind\""), "{json}");
    }

    /// 失敗した記録では、その2つのキーが**JSONの表に出る**（後から`jq`で拾える）。
    /// 形式そのものを固定する（B-24）——読む側は`show`だけではない。
    #[test]
    fn a_failed_recording_writes_the_reason_into_the_json() {
        let ws = workspace();
        let dir = RecordSessionDir::create(ws.path(), "f-2").unwrap();
        let mut manifest = RecordManifest::new("f-2", "cargo test", ws.path(), ws.path(), 1);
        manifest.fail(2, "spawn", &"Tier2aでコマンドを起動できませんでした");

        dir.write_manifest(&manifest).unwrap();

        let json = std::fs::read_to_string(dir.manifest_path()).unwrap();
        assert!(json.contains("\"error_kind\": \"spawn\""), "{json}");
        assert!(json.contains("\"error\":"), "{json}");
        let read_back = dir.read_manifest().expect("readable");
        assert_eq!(read_back.error_kind.as_deref(), Some("spawn"));
    }

    /// **理由の欄が入る前に書かれたマニフェスト**（実マシンに3件ある）も読めること。
    /// かつ、そこで「理由が無い」と「理由が空だった」を混ぜないこと（D-43）。
    #[test]
    fn a_manifest_written_before_the_reason_field_existed_still_loads_and_says_so() {
        let ws = workspace();
        let dir = RecordSessionDir::create(ws.path(), "old-1").unwrap();
        // 実データ（`policy-editor-7100-1786239920-1`）と同じ形。
        let legacy = r#"{
            "schema_version": 1,
            "id": "old-1",
            "pass": 2,
            "domain": "cargo",
            "command": "cargo test",
            "cwd": "C:\\w",
            "workspace_root": "C:\\w",
            "started_unix_ms": 1786239920284,
            "status": "failed",
            "finished_unix_ms": 1786240063296,
            "collector_started": false,
            "etw_available": false,
            "warnings": ["実行前診断"]
        }"#;
        std::fs::write(dir.manifest_path(), legacy).unwrap();

        let manifest = dir
            .read_manifest()
            .expect("legacy manifests must still load");

        assert_eq!(manifest.status, RecordStatus::Failed);
        assert!(manifest.error.is_none());
        let note = manifest
            .failure_note()
            .expect("failed records always get a line");
        assert!(
            note.contains("記録されていません"),
            "it must not look like 'the reason was empty': {note}"
        );
        // 後から足した欄（実行前診断・記録時点の宣言）も、無い形のJSONで落ちないこと。
        // 空＝「合流するものが無い」であって、読めないことではない。
        assert!(manifest.unreachable_exec.is_none());
        assert!(manifest.declared_fs.is_empty());
    }

    /// `open`は作らない（`show`が存在しないidを指定したときに空のディレクトリを
    /// 増やさない）。
    #[test]
    fn open_does_not_create_the_directory() {
        let ws = workspace();
        assert!(RecordSessionDir::open(ws.path(), "missing").is_none());
        assert!(!sandbox_root(ws.path())
            .join(format!("{RECORD_DIR_PREFIX}missing"))
            .exists());
    }
}
