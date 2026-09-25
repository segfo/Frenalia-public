//! 承認の台帳（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` §3.1、D-97・D-102・D-104・D-106）。
//!
//! 承認画面で「恒久的に承認」した`run_program`・`run_shell`の呼び出しを、ユーザー層の設定ディレクトリの
//! `run-approval-ledger.json`へ残す。**ワークスペースには置かない**（D-95。ワークスペースは`run_shell`から
//! 書け、クローンしたリポジトリが同梱できる）。
//!
//! # 読む側で検証する（`docs/SECURITY-PRINCIPLES.md` P-01）
//!
//! 台帳はファイルなので、書いたのが harness だとは限らない。読むときに、形の版が古いもの・
//! 穴を持つインタプリタの規則・形の崩れたハッシュ・制御文字を含むものを捨て、捨てた件数を返す
//! （起動時に告知する）。**Tier0 では台帳を守れない**——子がユーザー層の設定ディレクトリへ書けるので、
//! 形の正しい偽の記録は拾えない（MCP サーバ宣言の承認台帳と同じ立場、§8）。
//!
//! # 差分用の写し（D-106）
//!
//! 恒久承認のとき、画面に見せたのと同じ中身を非ローミングのユーザーデータ
//! （`%LOCALAPPDATA%\harness\data\approved-scripts\<中身のSHA-256>.txt`）へ置く。スクリプトは秘密を
//! 含みうるので、`%APPDATA%`のローミングで他の機械へ運ばない。**写しは表示専用で、判定には使わない**
//! ——判定の正本は台帳のハッシュだけで、写しが消えても書き換えられても判定は変わらない
//! （記録が2つあると片方だけが古くなる、`bug-pattern-rules` B-13）。読むときは写しの中身のハッシュを
//! 台帳の記録と照合し、合わなければ「写しが壊れている」と返す。どの記録からも参照されない写しは、
//! 台帳の更新と同じ排他の中で消す。

use std::path::{Path, PathBuf};

use harness_core::{
    is_format_char, is_interpreter_program, ArgPattern, BoundFile, FilePreview, ProgramRule,
    ShellRule,
};
use harness_grant_ledger::Ledger;
use serde::{Deserialize, Serialize};

/// 台帳の形の版。**形を変えたら上げる**——古い版の記録は無かったものとして扱う
/// （MCP サーバ宣言の承認台帳 `DESIGN-MCP.md` §4.2 と同じ作法。版ごとの分岐は書かない）。
pub const FORMAT_VERSION: u32 = 1;

const FILE_NAME: &str = "run-approval-ledger.json";
const LOCK_NAME: &str = r"Local\harness-run-approval-ledger";
const SNAPSHOT_DIR: &str = "approved-scripts";

/// 台帳の中身。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunApprovalLedger {
    #[serde(default)]
    pub approvals: Vec<RunApproval>,
}

/// 承認の記録1件。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunApproval {
    /// 記録した時点の形の版（`0`は版を持たない＝無効）。
    #[serde(default)]
    pub format_version: u32,
    #[serde(default)]
    pub approved_at_unix_secs: u64,
    pub rule: RecordedRule,
    /// 差分用の写しへの参照（表示用、照合には使わない）。
    #[serde(default)]
    pub snapshots: Vec<SnapshotRef>,
}

/// 記録した規則。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tool", rename_all = "snake_case")]
pub enum RecordedRule {
    RunProgram(ProgramRule),
    RunShell(ShellRule),
}

impl RecordedRule {
    /// 同じ呼び出しを指す記録か（置き換えの判定）。縛ったファイルの中身は見ない——中身が変わって
    /// 承認し直したら、古い記録を置き換える。
    fn same_call(&self, other: &RecordedRule) -> bool {
        match (self, other) {
            (RecordedRule::RunProgram(a), RecordedRule::RunProgram(b)) => {
                a.program == b.program
                    && a.args == b.args
                    && a.resolved == b.resolved
                    && a.workspace == b.workspace
            }
            (RecordedRule::RunShell(a), RecordedRule::RunShell(b)) => {
                a.line == b.line && a.workspace == b.workspace
            }
            _ => false,
        }
    }

    fn files(&self) -> &[BoundFile] {
        match self {
            RecordedRule::RunProgram(r) => &r.files,
            RecordedRule::RunShell(r) => &r.files,
        }
    }

    /// 一覧に出す1行。
    pub fn describe(&self) -> String {
        match self {
            RecordedRule::RunProgram(r) => {
                let args: Vec<String> = r
                    .args
                    .iter()
                    .map(|a| match a {
                        ArgPattern::Exact(v) => format!("{v:?}"),
                        ArgPattern::Hole => "<穴>".to_string(),
                    })
                    .collect();
                format!("run_program {} [{}]", r.program, args.join(", "))
            }
            RecordedRule::RunShell(r) => format!("run_shell {:?}", r.line),
        }
    }

    /// 縛ったワークスペース（全体で共通なら`None`）。
    pub fn workspace(&self) -> Option<&str> {
        match self {
            RecordedRule::RunProgram(r) => r.workspace.as_deref(),
            RecordedRule::RunShell(r) => r.workspace.as_deref(),
        }
    }
}

/// 差分用の写し1つへの参照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRef {
    pub rel_path: String,
    /// そのファイルの中身の SHA-256（写しのファイル名にもなる）。
    pub file_sha256: String,
    /// 写しに書いた文字列の SHA-256（読むときの照合用）。
    pub text_sha256: String,
    /// 画面に見せた中身が上限で切られていたか。
    #[serde(default)]
    pub truncated: bool,
}

/// 台帳を読んだ結果。
#[derive(Debug, Default)]
pub struct Loaded {
    pub rules: Vec<RecordedRule>,
    /// 形の版が古くて無効にした件数。
    pub voided_by_version: usize,
    /// 検証に通らず捨てた件数（穴を持つインタプリタ・形の崩れたハッシュ・制御文字等）。
    pub dropped_invalid: usize,
}

/// 承認の台帳。
pub struct ApprovalStore {
    ledger: Ledger<RunApprovalLedger>,
    snapshot_dir: Option<PathBuf>,
}

impl ApprovalStore {
    /// 実運用の置き場（台帳は`%APPDATA%\harness\config`、写しは`%LOCALAPPDATA%\harness\data`）。
    pub fn open_default() -> Self {
        Self {
            ledger: Ledger::in_config_dir(FILE_NAME, Some(LOCK_NAME)),
            snapshot_dir: directories::ProjectDirs::from("", "", "harness")
                .map(|d| d.data_local_dir().join(SNAPSHOT_DIR)),
        }
    }

    /// 明示した置き場（テストで実際のユーザー層を汚さないための注入点）。
    pub fn at(ledger_path: PathBuf, snapshot_dir: PathBuf) -> Self {
        Self {
            ledger: Ledger::at_path(ledger_path, None),
            snapshot_dir: Some(snapshot_dir),
        }
    }

    /// 台帳ファイルの場所（一覧でユーザーへ示す）。
    pub fn path(&self) -> Option<&Path> {
        self.ledger.path()
    }

    /// 台帳を読み、**読む側で検証した**規則だけを返す（モジュールdoc）。
    pub fn load_valid(&self) -> Loaded {
        let mut out = Loaded::default();
        for approval in self.ledger.load().approvals {
            if approval.format_version != FORMAT_VERSION {
                out.voided_by_version += 1;
            } else if is_valid_rule(&approval.rule) {
                out.rules.push(approval.rule);
            } else {
                out.dropped_invalid += 1;
            }
        }
        out
    }

    /// 一覧（検証の前の生の記録。取り消しの番号はこの並び）。
    pub fn list(&self) -> Vec<RunApproval> {
        self.ledger.load().approvals
    }

    /// 恒久承認を記録する。同じ呼び出しの古い記録は置き換える。`previews`は画面に見せた中身で、
    /// 差分用の写しとして置く（照合には使わない）。
    pub fn record(&self, rule: RecordedRule, previews: &[FilePreview]) -> Result<(), String> {
        if !is_valid_rule(&rule) {
            return Err("refusing to record a malformed approval".to_string());
        }
        let snapshots: Vec<SnapshotRef> = rule
            .files()
            .iter()
            .filter_map(|f| {
                let p = previews.iter().find(|p| p.rel_path == f.rel_path)?;
                Some(SnapshotRef {
                    rel_path: f.rel_path.clone(),
                    file_sha256: f.sha256.clone(),
                    text_sha256: harness_tools::approval_binding::sha256_hex(p.text.as_bytes()),
                    truncated: p.truncated,
                })
            })
            .collect();
        let approval = RunApproval {
            format_version: FORMAT_VERSION,
            approved_at_unix_secs: harness_grant_ledger::now_unix_secs(),
            rule,
            snapshots,
        };
        let snapshot_dir = self.snapshot_dir.clone();
        self.ledger.update(|ledger| {
            ledger
                .approvals
                .retain(|a| !a.rule.same_call(&approval.rule));
            if let Some(dir) = &snapshot_dir {
                write_snapshots(dir, &approval.snapshots, previews);
            }
            ledger.approvals.push(approval);
            if let Some(dir) = &snapshot_dir {
                collect_garbage(dir, &ledger.approvals);
            }
        });
        Ok(())
    }

    /// `index`番目（[`Self::list`]の並び）の記録を取り消す。
    pub fn revoke(&self, index: usize) -> Result<RunApproval, String> {
        let snapshot_dir = self.snapshot_dir.clone();
        self.ledger.update(|ledger| {
            if index >= ledger.approvals.len() {
                return Err(format!(
                    "no approval #{index} (there are {})",
                    ledger.approvals.len()
                ));
            }
            let removed = ledger.approvals.remove(index);
            if let Some(dir) = &snapshot_dir {
                collect_garbage(dir, &ledger.approvals);
            }
            Ok(removed)
        })
    }

    /// 全部取り消す。取り消した件数を返す。
    pub fn revoke_all(&self) -> usize {
        let snapshot_dir = self.snapshot_dir.clone();
        self.ledger.update(|ledger| {
            let n = ledger.approvals.len();
            ledger.approvals.clear();
            if let Some(dir) = &snapshot_dir {
                collect_garbage(dir, &ledger.approvals);
            }
            n
        })
    }

    /// 同じ呼び出しの前回の承認で、`rel_path`に置いた写しを読む（差分表示用）。
    /// 写しが無ければ`None`、壊れていれば`Some(Err)`。
    pub fn previous_snapshot(
        &self,
        rule: &RecordedRule,
        rel_path: &str,
    ) -> Option<Result<String, String>> {
        let dir = self.snapshot_dir.as_ref()?;
        let approvals = self.ledger.load().approvals;
        let snap = approvals
            .iter()
            .filter(|a| a.format_version == FORMAT_VERSION && a.rule.same_call(rule))
            .flat_map(|a| a.snapshots.iter())
            .find(|s| s.rel_path == rel_path)?;
        Some(read_snapshot(dir, snap))
    }
}

/// 読む側の検証（モジュールdoc）。
fn is_valid_rule(rule: &RecordedRule) -> bool {
    let visible = |s: &str| !s.chars().any(|c| c.is_control() || is_format_char(c));
    let files_ok = |files: &[BoundFile]| {
        files.iter().all(|f| {
            is_sha256_hex(&f.sha256)
                && f.dir_listing_sha256.as_deref().is_none_or(is_sha256_hex)
                && visible(&f.rel_path)
                && harness_change_ledger::validate_relative_path(&f.rel_path).is_ok()
        })
    };
    match rule {
        RecordedRule::RunProgram(r) => {
            let interpreter = is_interpreter_program(&r.program);
            !r.program.is_empty()
                && visible(&r.program)
                && r.args.iter().all(|a| match a {
                    ArgPattern::Exact(v) => visible(v),
                    ArgPattern::Hole => true,
                })
                && !(interpreter && r.has_hole())
                && !(interpreter && r.workspace.is_none())
                && files_ok(&r.files)
        }
        RecordedRule::RunShell(r) => {
            !r.line.is_empty() && r.workspace.is_some() && files_ok(&r.files)
        }
    }
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn snapshot_path(dir: &Path, file_sha256: &str) -> Option<PathBuf> {
    is_sha256_hex(file_sha256).then(|| dir.join(format!("{file_sha256}.txt")))
}

fn write_snapshots(dir: &Path, snapshots: &[SnapshotRef], previews: &[FilePreview]) {
    if snapshots.is_empty() {
        return;
    }
    if std::fs::create_dir_all(dir).is_err() {
        return; // 写しは表示専用。置けなくても判定は変わらない
    }
    for s in snapshots {
        let (Some(path), Some(p)) = (
            snapshot_path(dir, &s.file_sha256),
            previews.iter().find(|p| p.rel_path == s.rel_path),
        ) else {
            continue;
        };
        let _ = std::fs::write(path, p.text.as_bytes());
    }
}

fn read_snapshot(dir: &Path, snap: &SnapshotRef) -> Result<String, String> {
    let path = snapshot_path(dir, &snap.file_sha256).ok_or("malformed snapshot reference")?;
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("the saved copy is missing: {e}"))?;
    if harness_tools::approval_binding::sha256_hex(text.as_bytes()) != snap.text_sha256 {
        return Err(
            "the saved copy is corrupted (its contents do not match the record)".to_string(),
        );
    }
    Ok(text)
}

/// どの記録からも参照されない写しを消す。**写しの置き場の中の、写しの名前の形のファイルだけ**を見る。
fn collect_garbage(dir: &Path, approvals: &[RunApproval]) {
    let referenced: std::collections::HashSet<&str> = approvals
        .iter()
        .flat_map(|a| a.snapshots.iter())
        .map(|s| s.file_sha256.as_str())
        .collect();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".txt") else {
            continue;
        };
        if is_sha256_hex(stem) && !referenced.contains(stem) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
#[path = "approval_ledger_tests.rs"]
mod tests;
