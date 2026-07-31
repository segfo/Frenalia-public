//! CoW操作台帳（`.harness-cow-ops.jsonl`）の共有データ型・ハッシュ関数・再生ロジック。
//!
//! `crates/harness-redirector`（書く側、AppContainer子プロセスへ注入されるDLL）と
//! `crates/harness-sandbox`（読む側・適用する側）の両方がこのクレートを参照する。
//! ハッシュ関数・レコード型を2箇所に別々実装すると値がずれ、あらゆる適用が誤って
//! 「競合」判定される致命的なリスクがあるため、必ずここへ一本化する
//! （`plans/AppContainerベース Copy-on-Write ワークスペース設計書.md` §19参照）。

use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

/// 台帳ファイル名。`<upper_dir>/.harness-cow-ops.jsonl`に置く
/// （`.harness-cow-session.json`と同じ階層、命名も揃える）。
pub const COW_OPS_LEDGER_FILENAME: &str = ".harness-cow-ops.jsonl";

/// baseline内容ミラーのディレクトリ名。`<upper_dir>/.harness-cow-baseline/<rel>`に
/// セッションが最初に触った瞬間の実workspace内容を保存する（3-way merge用の材料、
/// `harness resolve`が読む。台帳の`baseline_hash`はハッシュ値のみでmerge材料にならない）。
pub const COW_BASELINE_DIRNAME: &str = ".harness-cow-baseline";

/// 操作種別。移動/リネームには専用の種別を作らず「旧パスの`Delete`＋新パスの`Create`」の
/// 2レコードへ分解して記録する（§19「移動・リネーム・コピー＋削除の扱い」決定事項）。
///
/// `harness-sandbox::manifest::ManifestOp`と変種名・serde表現が完全に一致する
/// （そちら側は`pub use harness_change_ledger::ChangeOp as ManifestOp;`で受け直す）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeOp {
    Create,
    Modify,
    Delete,
}

/// 台帳1行分のレコード。`path`はworkspaceルートからの相対パス（`/`区切り）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CowOpEntry {
    pub op: ChangeOp,
    pub path: String,
    /// そのパスをそのセッションで最初に触った瞬間の実workspace側の内容ハッシュ。
    /// 実workspaceに存在しなければ`None`（＝新規作成）。2回目以降の同一パスへの操作では
    /// 最初に記録した値をそのまま引き継ぐ（baselineは「このセッションが触る前の姿」を
    /// 意味するため、書く側は初回の値をキャッシュして以降のエントリにも複製すること）。
    pub baseline_hash: Option<String>,
    pub ts_unix_millis: u128,
}

/// 現在時刻をUnixミリ秒で返す。
pub fn now_millis() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

/// バイト列のTOCTOU検知用ハッシュ（暗号強度不要、`overlay.rs::hash_content`と同じ発想の
/// バイト列版）。DLLが記録した値をharness-sandbox側が検証するため、両者は必ずこの実装を
/// 共有する。`overlay.rs::hash_content`（文字列版、staged系専用）とは値が一致しなくてよい
/// （staged系とCoW系はそれぞれ自分の記録と自分の計算だけを突き合わせる）。
pub fn hash_bytes(content: &[u8]) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    content.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// 台帳ファイルの中身（JSONL）をパースする。壊れた行は黙って読み飛ばす
/// （台帳は追記専用ログであり、途中の1行が壊れていても後続行の再生を止めたくないため）。
pub fn parse_ledger(contents: &str) -> Vec<CowOpEntry> {
    contents
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// 台帳を再生して得た、あるパスに対する現在の論理的な変更。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CowChange {
    pub path: String,
    pub op: ChangeOp,
    pub baseline_hash: Option<String>,
}

struct PathState {
    baseline_hash: Option<String>,
    currently_present: bool,
    order: usize,
}

/// 台帳エントリを順に再生し、パスごとの「セッション開始時点と比べた最終的な変更」の一覧を
/// 返す（`harness changes --source cow`・apply/discardの入力になる）。
///
/// リネームは「旧パスのDelete＋新パスのCreate」という2つの独立したパスへのエントリとして
/// 記録されているため、ここでは特別扱いせずパスごとに素直に畳み込む。ある1つのパスが
/// セッション中に「新規作成→削除」のように往復して最終的に元の状態（存在しない）へ
/// 戻った場合は、変更なしとして結果から除外する（ネッティング）。
pub fn replay(entries: &[CowOpEntry]) -> Vec<CowChange> {
    let mut states: std::collections::HashMap<String, PathState> = std::collections::HashMap::new();
    for entry in entries {
        let next_order = states.len();
        let state = states.entry(entry.path.clone()).or_insert_with(|| PathState {
            baseline_hash: entry.baseline_hash.clone(),
            currently_present: false,
            order: next_order,
        });
        state.currently_present = !matches!(entry.op, ChangeOp::Delete);
    }
    let mut out: Vec<(usize, CowChange)> = states
        .into_iter()
        .filter_map(|(path, state)| {
            let originally_existed = state.baseline_hash.is_some();
            let op = match (originally_existed, state.currently_present) {
                (true, true) => ChangeOp::Modify,
                (false, true) => ChangeOp::Create,
                (true, false) => ChangeOp::Delete,
                (false, false) => return None,
            };
            Some((
                state.order,
                CowChange {
                    path,
                    op,
                    baseline_hash: state.baseline_hash,
                },
            ))
        })
        .collect();
    out.sort_by_key(|(order, _)| *order);
    out.into_iter().map(|(_, change)| change).collect()
}

/// 台帳を再生し、現在「論理的に削除済み」のパス集合を返す（Redirector DLLの読み取りフック
/// 用、`replay`より軽量。`replay`と違いネッティング判定は不要——単純に最後の操作が`Delete`か
/// どうかだけを見る）。
pub fn deleted_paths(entries: &[CowOpEntry]) -> HashSet<String> {
    let mut deleted = HashSet::new();
    for entry in entries {
        match entry.op {
            ChangeOp::Delete => {
                deleted.insert(entry.path.clone());
            }
            ChangeOp::Create | ChangeOp::Modify => {
                deleted.remove(&entry.path);
            }
        }
    }
    deleted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(op: ChangeOp, path: &str, baseline_hash: Option<&str>) -> CowOpEntry {
        CowOpEntry {
            op,
            path: path.to_string(),
            baseline_hash: baseline_hash.map(|s| s.to_string()),
            ts_unix_millis: now_millis(),
        }
    }

    #[test]
    fn hash_bytes_is_deterministic() {
        assert_eq!(hash_bytes(b"hello"), hash_bytes(b"hello"));
        assert_ne!(hash_bytes(b"hello"), hash_bytes(b"world"));
    }

    #[test]
    fn replay_new_create_is_create() {
        let entries = vec![entry(ChangeOp::Create, "a.txt", None)];
        let changes = replay(&entries);
        assert_eq!(changes, vec![CowChange { path: "a.txt".into(), op: ChangeOp::Create, baseline_hash: None }]);
    }

    #[test]
    fn replay_modify_existing_is_modify() {
        let entries = vec![entry(ChangeOp::Modify, "a.txt", Some("h1"))];
        let changes = replay(&entries);
        assert_eq!(
            changes,
            vec![CowChange { path: "a.txt".into(), op: ChangeOp::Modify, baseline_hash: Some("h1".into()) }]
        );
    }

    #[test]
    fn replay_delete_existing_is_delete() {
        let entries = vec![entry(ChangeOp::Delete, "a.txt", Some("h1"))];
        let changes = replay(&entries);
        assert_eq!(
            changes,
            vec![CowChange { path: "a.txt".into(), op: ChangeOp::Delete, baseline_hash: Some("h1".into()) }]
        );
    }

    #[test]
    fn replay_rename_is_delete_plus_create() {
        // 旧パスDelete + 新パスCreateの2レコードで表現されるリネーム。
        let entries = vec![
            entry(ChangeOp::Delete, "old.txt", Some("h1")),
            entry(ChangeOp::Create, "new.txt", None),
        ];
        let mut changes = replay(&entries);
        changes.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(
            changes,
            vec![
                CowChange { path: "new.txt".into(), op: ChangeOp::Create, baseline_hash: None },
                CowChange { path: "old.txt".into(), op: ChangeOp::Delete, baseline_hash: Some("h1".into()) },
            ]
        );
    }

    #[test]
    fn replay_create_then_delete_nets_to_no_change() {
        let entries = vec![
            entry(ChangeOp::Create, "a.txt", None),
            entry(ChangeOp::Delete, "a.txt", None),
        ];
        assert_eq!(replay(&entries), vec![]);
    }

    #[test]
    fn replay_delete_then_recreate_is_modify() {
        // 削除を取り消して再作成した場合、セッション開始時点と比べると「変更」として残る。
        let entries = vec![
            entry(ChangeOp::Delete, "a.txt", Some("h1")),
            entry(ChangeOp::Create, "a.txt", Some("h1")),
        ];
        assert_eq!(
            replay(&entries),
            vec![CowChange { path: "a.txt".into(), op: ChangeOp::Modify, baseline_hash: Some("h1".into()) }]
        );
    }

    #[test]
    fn deleted_paths_tracks_latest_state() {
        let entries = vec![
            entry(ChangeOp::Delete, "a.txt", Some("h1")),
            entry(ChangeOp::Create, "b.txt", None),
            entry(ChangeOp::Delete, "b.txt", None),
        ];
        let deleted = deleted_paths(&entries);
        assert!(deleted.contains("a.txt"));
        assert!(deleted.contains("b.txt"));
    }

    #[test]
    fn deleted_paths_removes_on_recreate() {
        let entries = vec![
            entry(ChangeOp::Delete, "a.txt", Some("h1")),
            entry(ChangeOp::Create, "a.txt", Some("h1")),
        ];
        let deleted = deleted_paths(&entries);
        assert!(!deleted.contains("a.txt"));
    }

    #[test]
    fn parse_ledger_skips_malformed_lines() {
        let contents = "{\"op\":\"create\",\"path\":\"a.txt\",\"baseline_hash\":null,\"ts_unix_millis\":1}\nnot json\n";
        let entries = parse_ledger(contents);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "a.txt");
    }
}
