//! 変更マニフェスト（JSONL）。`plans/DESIGN.md` §オーバーレイFS「変更マニフェスト」参照。
//!
//! 1行1`ManifestEntry`の追記型ログ。`SandboxFs`は`WorkspaceJail`の`read_to_string`/
//! `write_string`（read-modify-write）でこのファイルを読み書きする（M10のスコープでは
//! 追記の原子性・並行アクセスは要件外、単一プロセス・単一セッション前提）。

use serde::{Deserialize, Serialize};

/// マニフェスト1件の操作種別。`crates/harness-change-ledger`の`ChangeOp`をそのまま使う
/// （CoW操作台帳と変種名・serde表現が完全に一致するため、同じ意味の列挙を2箇所で育てて
/// 片方だけ古くなる事故を防ぐ）。
pub use harness_change_ledger::ChangeOp as ManifestOp;

/// 書込先の分類。`Live`は実FSへ直接書いた際の監査専用エントリ（`changes()`には出ない）、
/// `Tree`はworkspace内オーバーレイミラー（`<sandbox_dir>/tree/<rel>`）、`Ext`はworkspace外
/// オーバーレイ（`<sandbox_dir>/_ext/<mapped>`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestTarget {
    Live,
    Tree,
    Ext,
    /// `--cow`操作台帳由来の変更（TUI変更パネル・`harness changes --source cow`統合表示用、
    /// Phase 2）。stagedマニフェスト（`SandboxFs::change_set()`/`apply()`）からは出力しない
    /// ——`overlay.rs`の網羅マッチにこの腕があるのは型の網羅性を満たすためだけの到達不能
    /// コードで、CoW側の実際の適用は`harness_sandbox::changes::apply_unified_changes`が担う。
    Cow,
}

/// マニフェスト1行分のレコード。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub op: ManifestOp,
    pub target: ManifestTarget,
    /// `Tree`ならworkspaceルートからの相対パス（`/`区切り）、`Ext`なら正規化した絶対パス
    /// （`\`を`/`に統一、ドライブレターは大文字のまま）、`Live`は実際に書いた相対パス。
    pub path: String,
    /// オーバーレイ内の実体パス（workspaceルートからの相対、`/`区切り）。`Live`は空文字列。
    pub overlay_path: String,
    /// 書込直前の実FS上の内容ハッシュ（新規作成なら`None`）。
    pub baseline_hash: Option<String>,
    /// 書込後の内容ハッシュ（`Delete`は`None`）。
    pub new_hash: Option<String>,
    pub ts_unix_millis: u128,
}

/// 現在時刻をUnixミリ秒で返す（`ManifestEntry::ts_unix_millis`用）。
pub fn now_millis() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
