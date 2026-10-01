//! [段階⑦] 承認待ち画面（`F2`）の遷移タブで**却下した候補の印**を`dismissed.json`へ残す
//! （`plans/POLICY-EDITOR-TOMOYO-DIG.md` 決定62「却下印の永続化を実装した（2026-10-01）」）。
//!
//! # 何のためにあるのか
//!
//! 遷移の候補（観測した生成・断られた生成）には、ユーザーが「これは許可しない」と決めたものが
//! 混ざる。印を残さないと、**決めたものが毎回「保留中」に出続け**、まだ決めていないものが
//! その中に埋もれる。ここはその印だけを読み書きする。
//!
//! # 印は表示だけに効く（守らないもの）
//!
//! - **強制には一切効かない。** Spawn Daemonもカーネルもこのファイルを読まない。却下しても
//!   その生成は断られ続け、`pending.jsonl`にも積まれ続ける（**記録でも強制でもなく、表示の絞り込み**）。
//! - **モデルへの注記にも効かない。** `run_shell`がモデルへ返す「このコマンドの間に断られたもの」
//!   （`harness_tools::shell`が`pending.jsonl`の続きを読む）は、却下に関係なく出る。
//! - **`policy.json`も実マシンのACLも変えない。**
//!
//! # 1件の鍵は`(遷移元ドメイン, exe, argv)`
//!
//! 遷移元ドメインは**画面が辺を書く先**（今日は`policy_file::ENTRY_DOMAIN`に固定）であって、
//! 観測した呼び出し元ではない——観測（`observed.jsonl`）は隔離していないので呼び出し元の
//! ドメインを持たない。**承認と同じ3つ組で持つ**（承認の予約`CandidateKey`と辺の指定`EdgeRef`が
//! 遷移元を画面の1つに預けているのと同じ形）ので、却下は「承認したら書かれる辺を、書かない」と
//! 読める。exeとargvは**観測された綴りそのまま**書き、比べるときだけ
//! `fold_for_pattern_comparison`で畳む——宣言済みの判定（`transition_candidates`）と同じ畳み方で、
//! 判定器が同じ生成とみなすものを、却下でも同じものとみなす。
//!
//! # 壊れていたら空として読み、書かない
//!
//! | 状態 | 読み（表示） | 書き |
//! |---|---|---|
//! | 無い | 空（正常。まだ1件も却下していない） | 作る |
//! | 読めない・壊れている・知らない版 | **空**＋呼び出し側が警告を出す | **断る**（壊れた中身を上書きしない） |
//!
//! 空へ倒すのは、印が表示だけに効くからである——空なら**保留中に多く出る**側へ倒れ、
//! 隠すものが減るだけで権限は1つも増えない。書くのを断るのは、`policy.json`が読めないときに
//! エディタが書かない（`transition_approve::plan`が読み込みの失敗で止まる）のと、CoWの
//! セッションメタが読めないときに「left as is」で書き換えない
//! （`harness_sandbox::tier2a::workspace_ledger`）のと同じ扱いである。
//!
//! # 書き方
//!
//! **読んで、変えて、書き戻す**ので、エディタを2つ同時に開くと片方の却下がもう片方の書き戻しで
//! 消え得る。そこで (1) 書き戻しは名前付きミューテックス（[`harness_grant_ledger::with_named_lock`]。
//! 承認台帳`PolicyApprovalStore`が同じ部品で同じ問題を解いている）の中で行い、(2) 書くのは
//! **画面が持っている一覧ではなく、ロックの中で読み直したファイルへ予約の差分を当てたもの**にする。
//! 一時ファイルへ書いてから名前の変更で差し替える（`workspace_ledger`のセッションメタと同じ形）
//! ので、途中で落ちても半分だけ書かれたファイルは残らない。
//!
//! **限界**: ミューテックスは`Local\`名前空間なので、**別のログオンセッション**（リモート
//! デスクトップの別セッション等）で同じワークスペースを開いたエディタとは排他しない。
//! ミューテックスを作れなかったときも排他せずに書く（`with_named_lock`のfail-open）——これは
//! 事故防止のガードであって境界ではないので、通す側へ倒す。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use harness_change_ledger::path_rules::fold_for_pattern_comparison;
use serde::{Deserialize, Serialize};

use crate::tui::transition::CandidateKey;

/// 置き場（`<workspace>/.harness/transitions/`の中）。
///
/// **書くのは非特権のエディタだけ**（`plans/DESIGN-MAC-ENFORCEMENT.md` §10.2の置き場の図）。
/// ディレクトリが無ければこのエディタが作る——非昇格の側が作るので、所有者の問題
/// （BUG-109）は起きない。
const DISMISSED_FILE: &str = "dismissed.json";

/// ファイルの形の版。**照合の意味か欄の意味を変えたら上げる。**
///
/// 知らない版のファイルは読まない（空として扱い、書かない）。`policy.json`が新しい版を
/// 読まずに断るのと同じで、**古いエディタが新しい形を黙って古い形で書き戻す**のを防ぐ。
pub const SCHEMA_VERSION: u32 = 1;

/// 読み書きの直列化に使う名前。**可変なものを混ぜない**——ワークスペースごとに分けると
/// 正規化が要り、取り違えると排他が一度も成立しない。書き戻しは一瞬なので1本で足りる。
const LOCK_NAME: &str = r"Local\harness-policy-editor-dismissed";

/// 却下が何に効くかの説明。**この文言の持ち主はここだけ**（確認ダイアログが出す）。
///
/// 承認と同じ画面・同じ確定で書くので、**何も起きないことを言わないと**「拒否が止まる」
/// 「`policy.json`から消える」と読まれる（`transition_approve::ACE_NOTICE`が書く側のモジュールに
/// 文言を持っているのと同じ作法）。
pub const NOTICE: &str = concat!(
    "注: 却下はこの画面の表示だけに効く印です。policy.jsonも実マシンのACLも変わらず、\n",
    "    強制中の拒否も止まりません（断られた生成は pending.jsonl に積まれ続けます）。"
);

/// 確認ダイアログに出す明細（**何も書かない**）。件数と1件ずつの綴りを出し、最後に[`NOTICE`]。
pub fn confirmation_lines(
    workspace_root: &Path,
    from_domain: &str,
    dismiss: &BTreeSet<CandidateKey>,
    undismiss: &BTreeSet<CandidateKey>,
) -> Vec<String> {
    let mut lines = vec![
        format!("{}:", path(workspace_root).display()),
        format!("遷移元ドメイン: {from_domain}"),
    ];
    if !dismiss.is_empty() {
        lines.push(format!("却下する {}件:", dismiss.len()));
        for key in dismiss {
            lines.push(format!("  × {} {}", key.exe, key.argv));
        }
    }
    if !undismiss.is_empty() {
        lines.push(format!(
            "却下印を外す {}件（保留中へ戻す・承認するもの）:",
            undismiss.len()
        ));
        for key in undismiss {
            lines.push(format!("  ↺ {} {}", key.exe, key.argv));
        }
    }
    lines.push(String::new());
    lines.extend(NOTICE.lines().map(str::to_string));
    lines
}

/// `dismissed.json`のパス。**綴りを他で組み立てない**（置き場の正本はこの関数）。
pub fn path(workspace_root: &Path) -> PathBuf {
    harness_sandbox::tier2a::spawnd::transitions::transitions_dir(workspace_root)
        .join(DISMISSED_FILE)
}

/// ファイルの中身。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DismissedFile {
    schema_version: u32,
    dismissed: Vec<DismissedEntry>,
}

/// 却下1件。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DismissedEntry {
    /// 遷移元ドメイン（**承認したら辺を書く先**。観測した呼び出し元ではない。モジュールdoc）。
    pub from_domain: String,
    /// 観測された綴りそのまま。
    pub exe: String,
    /// 観測されたコマンドラインそのまま。
    pub argv: String,
    /// 却下した時刻。**由来の記録だけで、判定にも表示の絞り込みにも使わない。**
    pub dismissed_unix_ms: u64,
}

impl DismissedEntry {
    /// この印はその`(遷移元, exe, argv)`のことか。**比べ方はここ1箇所**（足す・消す・表示が同じものを通る）。
    fn refers_to(&self, from_domain: &str, exe: &str, argv: &str) -> bool {
        self.from_domain == from_domain
            && fold_for_pattern_comparison(&self.exe) == fold_for_pattern_comparison(exe)
            && fold_for_pattern_comparison(&self.argv) == fold_for_pattern_comparison(argv)
    }
}

/// 読めなかった・書けなかった理由。**画面に出す文面**でもある（`B-10`: 理由を捨てない）。
#[derive(Debug, thiserror::Error)]
pub enum DismissedError {
    #[error("{path}を読めませんでした: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}の形が読めません（壊れています）: {message}")]
    Parse { path: PathBuf, message: String },
    #[error(
        "{path}は版{found}の形で書かれていて、このエディタ（版{supported}まで）では読めません"
    )]
    UnsupportedVersion {
        path: PathBuf,
        found: u32,
        supported: u32,
    },
    #[error("{path}を書けませんでした: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// いまの却下印の一覧。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dismissals {
    entries: Vec<DismissedEntry>,
}

impl Dismissals {
    /// その`(遷移元, exe, argv)`は却下されているか。
    pub fn contains(&self, from_domain: &str, exe: &str, argv: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.refers_to(from_domain, exe, argv))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 予約の差分を当てる。**消す方を先にやる**（`transition_approve::plan`と同じ順序）。
    fn apply(
        &mut self,
        from_domain: &str,
        dismiss: &BTreeSet<CandidateKey>,
        undismiss: &BTreeSet<CandidateKey>,
        now_unix_ms: u64,
    ) -> Applied {
        let mut applied = Applied::default();
        for key in undismiss {
            let before = self.entries.len();
            self.entries
                .retain(|e| !e.refers_to(from_domain, &key.exe, &key.argv));
            if self.entries.len() == before {
                applied.not_found += 1;
            } else {
                applied.removed += 1;
            }
        }
        for key in dismiss {
            if self.contains(from_domain, &key.exe, &key.argv) {
                applied.already += 1;
                continue;
            }
            self.entries.push(DismissedEntry {
                from_domain: from_domain.to_string(),
                exe: key.exe.clone(),
                argv: key.argv.clone(),
                dismissed_unix_ms: now_unix_ms,
            });
            applied.added += 1;
        }
        applied
    }
}

/// 書いた結果。**「足した」と「元からあった」、「外した」と「元から無かった」を区別する**（`B-09`）
/// ——区別しないと、別のエディタが先に同じものを却下していたときに「却下しました」と二重に数える。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Applied {
    pub added: usize,
    pub already: usize,
    pub removed: usize,
    pub not_found: usize,
    /// ファイルを書いたか（**変わらなければ書かない**）。
    pub wrote: bool,
}

/// 読む。**無いのは正常で空**、それ以外の読めない理由は`Err`で返す（呼び出し側が警告を出し、空として扱う）。
pub fn load(workspace_root: &Path) -> Result<Dismissals, DismissedError> {
    let path = path(workspace_root);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Dismissals::default()),
        Err(source) => return Err(DismissedError::Read { path, source }),
    };
    // 版を先に読む。**知らない版を、知っている形として読まない**（欄の意味が変わっていても
    // 形が合えば読めてしまう）。
    #[derive(Deserialize)]
    struct VersionOnly {
        schema_version: u32,
    }
    let version: VersionOnly =
        serde_json::from_str(&text).map_err(|e| DismissedError::Parse {
            path: path.clone(),
            message: e.to_string(),
        })?;
    if version.schema_version != SCHEMA_VERSION {
        return Err(DismissedError::UnsupportedVersion {
            path,
            found: version.schema_version,
            supported: SCHEMA_VERSION,
        });
    }
    let file: DismissedFile = serde_json::from_str(&text).map_err(|e| DismissedError::Parse {
        path: path.clone(),
        message: e.to_string(),
    })?;
    Ok(Dismissals {
        entries: file.dismissed,
    })
}

/// 却下の予約を書く。**ロックの中で読み直したファイルへ差分を当てる**（モジュールdoc「書き方」）。
///
/// 読めないファイルには書かない（`Err`）。そのとき予約は呼び出し側に残る。
pub fn update(
    workspace_root: &Path,
    from_domain: &str,
    dismiss: &BTreeSet<CandidateKey>,
    undismiss: &BTreeSet<CandidateKey>,
    now_unix_ms: u64,
) -> Result<Applied, DismissedError> {
    harness_grant_ledger::with_named_lock(LOCK_NAME, || {
        let mut current = load(workspace_root)?;
        let before = current.clone();
        let mut applied = current.apply(from_domain, dismiss, undismiss, now_unix_ms);
        if current == before {
            return Ok(applied);
        }
        store(workspace_root, &current)?;
        applied.wrote = true;
        Ok(applied)
    })
}

/// 一時ファイルへ書いてから名前の変更で差し替える。**書く口はここだけ。**
fn store(workspace_root: &Path, dismissals: &Dismissals) -> Result<(), DismissedError> {
    let path = path(workspace_root);
    let write_error = |source| DismissedError::Write {
        path: path.clone(),
        source,
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(write_error)?;
    }
    let file = DismissedFile {
        schema_version: SCHEMA_VERSION,
        dismissed: dismissals.entries.clone(),
    };
    let mut text = serde_json::to_string_pretty(&file)
        .map_err(|e| write_error(std::io::Error::other(e.to_string())))?;
    text.push('\n');
    // 名前にプロセスIDを入れる。ミューテックスを作れずに排他せず書いた（fail-open）ときに、
    // 2つのエディタが同じ一時ファイルを書き合わないため。
    let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    let written = std::fs::write(&tmp, text).and_then(|()| std::fs::rename(&tmp, &path));
    match written {
        Ok(()) => Ok(()),
        Err(e) => Err(write_error(with_leftover_note(e, &tmp))),
    }
}

/// 書けなかったときに一時ファイルを消す。**消せなかったことも理由に足す**——
/// ファイルシステムに残るものを黙って置き去りにしない（`B-10`）。
fn with_leftover_note(error: std::io::Error, tmp: &Path) -> std::io::Error {
    match std::fs::remove_file(tmp) {
        Ok(()) => error,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => error,
        Err(e) => std::io::Error::new(
            error.kind(),
            format!(
                "{error}（一時ファイル{}も消せずに残っています: {e}）",
                tmp.display()
            ),
        ),
    }
}

#[cfg(test)]
#[path = "transition_dismissed_tests.rs"]
mod transition_dismissed_tests;
