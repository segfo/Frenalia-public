//! ハンク単位のレビュー材料の計算（[`SandboxFs::review_file`]）と部分適用
//! （[`SandboxFs::apply_hunks`]）。`plans/PLAN-VSCODE-REVIEW.md` §ハンク単位accept/rejectと部分適用。
//!
//! **表示側と適用側で同じハンク分割を使う**のが本モジュールの存在理由である。パネルは選択結果
//! として「path＋パネルを開いた時点の両側内容のハッシュ＋acceptしたハンク番号」しか渡せず、
//! 適用側は現在の内容のハッシュを照合したうえで[`crate::textdiff`]で**ハンクを再計算**して
//! 番号で選ぶ。ハンクの実体を外から受け取らないので、「見たものと違うものが適用される」事故が
//! 構造的に起きない（ハッシュが違えば`conflicts`として何も書かずに拒否する）。
//!
//! **既存の門はすべて通る**（P-08）: 台帳パスの正規形検査（[BUG-062](../../docs/bugs/BUG-062.md)）→
//! D-09 hard-deny再チェック → 適用可否の降格判定 → ハッシュ照合、の順は
//! `overlay::apply_overlay_changes`と同じで、どれもバイパスしない。

use harness_change_ledger::{hash_bytes, store, ChangeOp};

use crate::overlay::{canonical_ledger_path, ApplyReport, ChangeEntry, SandboxError, SandboxFs};
use crate::textdiff::{compose_selected, diff_hunks, DiffHunk};

/// ハンク単位の操作を提供できない理由（提供できるときは`None`）。**表示は best-effort でも、
/// 適用は正確でなければならない**ため、少しでも根拠が欠けるケースはファイル単位へ降格させる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HunkBlock {
    /// 新規作成（全か無か。部分的に「存在する」ファイルは作れない）。
    Create,
    /// 削除（全か無か）。
    Delete,
    /// 台帳に記録が無い（baselineが不明なので、部分適用後に張り替えるべき値も決まらない）。
    Unledgered,
    /// workspace外の絶対パス（`_ext`）。適用に`--dangerously-allow`という別の門が要る。
    External,
    /// どちらかの側がUTF-8として読めない（行の合成が正確にできない）。
    NonUtf8,
    /// 台帳の`path`が相対パスとして受け付けられない形（BUG-062）。
    Malformed,
    /// オーバーレイが無効（純live構成）。
    NoOverlay,
}

impl HunkBlock {
    /// パネルのdiffペインへ1行で出す理由。
    pub fn reason(self) -> &'static str {
        match self {
            HunkBlock::Create => "new file: accept/reject applies to the whole file",
            HunkBlock::Delete => "deletion: accept/reject applies to the whole file",
            HunkBlock::Unledgered => {
                "not recorded in the operations ledger (baseline unknown): whole file only"
            }
            HunkBlock::External => "outside the workspace: whole file only (needs `harness apply`)",
            HunkBlock::NonUtf8 => "not valid UTF-8: preview only, whole file only",
            HunkBlock::Malformed => "malformed ledger path: cannot be applied",
            HunkBlock::NoOverlay => "no overlay for this session",
        }
    }
}

/// 1エントリのレビュー材料。パネルは**開いた時点で一度だけ**これを作り、`c`を押すまで持ち回る。
#[derive(Debug, Clone, Default)]
pub struct FileReview {
    /// 実workspace側（old）→オーバーレイ側（new）のハンク列。
    pub hunks: Vec<DiffHunk>,
    /// ハンク単位操作が使えない理由（`None`なら使える）。
    pub hunk_block: Option<HunkBlock>,
    /// このレビューを作った時点の両側の内容ハッシュ（[`SandboxFs::apply_hunks`]のTOCTOU照合用）。
    /// 実体が無い側は`None`。
    pub workspace_hash: Option<String>,
    pub overlay_hash: Option<String>,
}

impl FileReview {
    pub fn hunks_selectable(&self) -> bool {
        self.hunk_block.is_none() && !self.hunks.is_empty()
    }
}

/// [`SandboxFs::apply_hunks`]への入力。**ハンクの実体ではなく番号だけ**を渡す。
#[derive(Debug, Clone)]
pub struct HunkSelection<'a> {
    /// 台帳に載っている綴りのパス（`ChangeEntry::path`をそのまま）。
    pub path: &'a str,
    /// [`FileReview`]を作った時点の実workspace側の内容ハッシュ。
    pub workspace_hash: String,
    /// 同じくオーバーレイ側の内容ハッシュ。
    pub overlay_hash: String,
    /// acceptしたハンクの番号（[`crate::textdiff::diff_hunks`]順、0起点）。
    pub accepted: &'a [usize],
}

impl SandboxFs {
    /// 1エントリ分のレビュー材料（ハンク・両側ハッシュ・降格理由）を計算する。
    ///
    /// 読取は**適用時とまったく同じ経路**（workspace側は`WorkspaceJail`、オーバーレイ側は
    /// オーバーレイの`WorkspaceJail`）で行う。別の読み方をすると、ここで採ったハッシュが
    /// 適用時の再計算値と一致せず、正当な部分適用が常に`conflicts`になる。
    pub fn review_file(&self, entry: &ChangeEntry) -> FileReview {
        let Some(overlay) = &self.overlay else {
            return FileReview {
                hunk_block: Some(HunkBlock::NoOverlay),
                ..Default::default()
            };
        };

        // 読みに行く先を決める。`_ext`（workspace外）はjailに閉じられないので、表示のためだけに
        // 生の`std::fs`で読む（適用は`HunkBlock::External`で降格させるため、ここは表示専用）。
        let is_ext = std::path::Path::new(&entry.path).is_absolute();
        let canonical = if is_ext {
            Ok(entry.path.clone())
        } else {
            canonical_ledger_path(&entry.path)
        };
        let (workspace_bytes, overlay_bytes) = match &canonical {
            Ok(rel) if is_ext => {
                let key = store::ext_key(rel).ok();
                let overlay_rel = key.map(|k| format!("_ext/{k}"));
                (
                    std::fs::read(rel).ok(),
                    overlay_rel.and_then(|r| overlay.jail.read_bytes(&r).ok()),
                )
            }
            Ok(rel) => (
                self.jail.read_bytes(rel).ok(),
                overlay.jail.read_bytes(rel).ok(),
            ),
            Err(_) => (None, None),
        };
        // 削除エントリのオーバーレイ側は「無い」ことそのものが内容なので、空として差分を出す
        // （全行が`Removed`になる）。
        let overlay_bytes = if entry.op == ChangeOp::Delete {
            Some(Vec::new())
        } else {
            overlay_bytes
        };

        let workspace_hash = workspace_bytes.as_deref().map(hash_bytes);
        let overlay_hash = overlay_bytes.as_deref().map(hash_bytes);

        let old = workspace_bytes.unwrap_or_default();
        let new = overlay_bytes.unwrap_or_default();
        let both_utf8 = std::str::from_utf8(&old).is_ok() && std::str::from_utf8(&new).is_ok();
        let old_text = String::from_utf8_lossy(&old).into_owned();
        let new_text = String::from_utf8_lossy(&new).into_owned();

        // 降格理由は「より根本的なもの」から順に見る（台帳の形 → 置き場所 → 由来 → 操作種別 →
        // 内容の読めなさ）。表示自体はどの理由でも best-effort で出す。
        let hunk_block = if canonical.is_err() {
            Some(HunkBlock::Malformed)
        } else if is_ext {
            Some(HunkBlock::External)
        } else if entry.unledgered {
            Some(HunkBlock::Unledgered)
        } else if entry.op == ChangeOp::Create {
            Some(HunkBlock::Create)
        } else if entry.op == ChangeOp::Delete {
            Some(HunkBlock::Delete)
        } else if !both_utf8 {
            Some(HunkBlock::NonUtf8)
        } else {
            None
        };

        FileReview {
            hunks: diff_hunks(&old_text, &new_text),
            hunk_block,
            workspace_hash,
            overlay_hash,
        }
    }

    /// 1ファイルの**一部のハンクだけ**を実workspaceへ適用する（`git add -p`相当）。
    ///
    /// rejectしたハンクは**非破壊**でオーバーレイに残る（ファイル単位rejectの既存の意味論・
    /// `git add -p`のunstagedと同じ）。捨てたいときは`discard`か`resolve`を明示的に使う。
    ///
    /// 結果は既存の[`ApplyReport`]語彙で返す（`conflicts`＝ハッシュ不一致で再レビュー要求、
    /// `hard_denied`＝D-09、`rejected`＝ハンク適用不可またはパス不正）。
    pub fn apply_hunks(&self, sel: &HunkSelection) -> Result<ApplyReport, SandboxError> {
        let mut report = ApplyReport::default();
        let Some(overlay) = &self.overlay else {
            return Ok(report);
        };
        let path = sel.path.to_string();

        // 「このセッションに何があるか」は`change_set`（＝`effective_changes`）が唯一の答えを
        // 持つ。パネルが持ってきたパスを台帳の外から適用できないようにするための照合でもある。
        let entries = self.change_set()?;
        let Some(entry) = entries.iter().find(|e| e.path == sel.path) else {
            report
                .rejected
                .push((path, "no such change in this session".to_string()));
            return Ok(report);
        };

        let canonical = match canonical_ledger_path(&entry.path) {
            Ok(p) => p,
            Err(reason) => {
                report.rejected.push((path, reason));
                return Ok(report);
            }
        };
        if harness_core::is_config_injection_path(&canonical) {
            report.hard_denied.push(path);
            return Ok(report);
        }

        let review = self.review_file(entry);
        if let Some(block) = review.hunk_block {
            report.rejected.push((path, block.reason().to_string()));
            return Ok(report);
        }
        if sel.accepted.iter().any(|i| *i >= review.hunks.len()) {
            report.rejected.push((
                path,
                format!(
                    "hunk index out of range (this file has {} hunk(s))",
                    review.hunks.len()
                ),
            ));
            return Ok(report);
        }
        if sel.accepted.is_empty() {
            // 選ばれたハンクが1つも無い＝適用するものが無い。台帳もbaselineも触らない。
            return Ok(report);
        }

        // TOCTOU照合: パネルが見た内容と今の内容が同じであることを機械検証する。
        // どちらか一方でも変わっていたら**1バイトも書かずに**再レビューを要求する。
        let (Ok(ws_bytes), Ok(ov_bytes)) = (
            self.jail.read_bytes(&canonical),
            overlay.jail.read_bytes(&canonical),
        ) else {
            report.conflicts.push(path);
            return Ok(report);
        };
        if hash_bytes(&ws_bytes) != sel.workspace_hash || hash_bytes(&ov_bytes) != sel.overlay_hash
        {
            report.conflicts.push(path);
            return Ok(report);
        }
        let (Ok(old), Ok(new)) = (
            String::from_utf8(ws_bytes),
            String::from_utf8(ov_bytes.clone()),
        ) else {
            report
                .rejected
                .push((path, HunkBlock::NonUtf8.reason().to_string()));
            return Ok(report);
        };

        let composed = compose_selected(&old, &new, sel.accepted);
        self.jail.write_bytes(&canonical, composed.as_bytes())?;

        if composed == new {
            // 全ハンクを採ったのと同じ結果になった＝通常の`apply`と同じ後始末をする。
            // オーバーレイ実体を残すと、Redirectorのcopy_upが「既に差分層にある＝このセッションで
            // 一度触った」と誤認して次の変更を台帳へ記録しなくなる（BUG-034）。
            let _ = overlay.jail.remove_file(&canonical);
            store::prune_ledger(&overlay.dir, std::slice::from_ref(&path));
        } else {
            // 部分適用。**オーバーレイ実体はそのまま残す**——設計書のいう「新workspace内容⊕
            // rejectハンク」はオーバーレイの現在内容そのもの（合成の恒等式）なので、書き直す
            // 必要がない。残ったハンクは次回のレビューでそのまま差分として出る。
            //
            // 一方、baselineは**必ず張り替える**。放置すると自分が書いた内容が
            // 「セッション中に人が実workspaceを編集した」と誤検知され、残りのハンクが
            // 永久に適用できなくなる。
            store::rebase_baseline(&overlay.dir, &entry.path, composed.as_bytes());
        }
        report.applied.push(path);
        Ok(report)
    }
}

#[cfg(test)]
#[path = "overlay_hunks_tests.rs"]
mod tests;
