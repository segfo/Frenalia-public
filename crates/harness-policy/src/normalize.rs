//! 4つの収集源を1つの候補列へ正規化する（`plans/DESIGN-SANDBOX-APPPOLICY.md` §11.1）。
//!
//! 各収集源はそれぞれ別の理由で・別の層が書いたもので、レコードの形も揃っていない。
//! ここが唯一の合流点であり、以降（[`crate::generalize`]・[`crate::diff`]）は
//! 収集源の違いを知らない。
//!
//! | 収集源 | 入力 | 何を捉えるか |
//! |---|---|---|
//! | [`Source::Preflight`] | `fs-passthrough-ledger.json`（JSON） | 設定済みpassthroughのpath不在・ACE付与失敗・付与後probe失敗 |
//! | [`Source::Network`] | `net-audit.jsonl`（JSONL） | 協調プロキシ/Fake DNS/WFPが拒否したドメイン |
//! | [`Source::Cow`] | `.harness-cow-denied.jsonl`（JSONL） | `--cow`時のworkspace外書込のACL拒否 |
//! | [`Source::Etw`] | `fs-audit.jsonl`（JSONL） | 実行中にOSが拒否した任意のFSアクセス |
//!
//! **壊れた行・読めなかったファイルはエラーにしない**（D-43）。[`SourceReport::notes`]へ
//! 事実を積んで、読めた分だけで先へ進む。収集は境界ではない（P-07）ので、ここで止めると
//! 安全性を1つも増やさずに可用性だけを削ることになる。

use serde::{Deserialize, Serialize};

use harness_config::FsAccess;

/// 拒否記録の出どころ。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Preflight,
    Network,
    Cow,
    Etw,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Preflight => "preflight",
            Source::Network => "net",
            Source::Cow => "cow",
            Source::Etw => "etw",
        }
    }

    /// `--source`の値からの解決。`all`は呼び出し側が全経路を選ぶ意味なのでここでは扱わない。
    pub fn parse(s: &str) -> Option<Source> {
        match s {
            "preflight" => Some(Source::Preflight),
            "net" | "network" => Some(Source::Network),
            "cow" => Some(Source::Cow),
            "etw" | "os" | "fs-audit" => Some(Source::Etw),
            _ => None,
        }
    }

    pub const ALL: [Source; 4] = [Source::Preflight, Source::Network, Source::Cow, Source::Etw];
}

/// 何を要求して拒否されたのか。FSとnetworkは提案の出力先（設定キー）が違うため、
/// 正規化の時点で型として分けておく（後段で文字列を見て振り分けない）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "target", rename_all = "snake_case")]
pub enum Requested {
    Fs { path: String, access: FsAccess },
    Net { domain: String },
}

/// 正規化された拒否候補1件。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeniedCandidate {
    pub source: Source,
    #[serde(flatten)]
    pub requested: Requested,
    pub reason: String,
    /// 同一（対象, access）で観測した回数。台帳側が既に数えている経路（preflight）はその値、
    /// JSONLを畳んだ経路は畳んだ行数。
    pub count: u64,
    pub last_seen_unix_ms: u64,
}

impl DeniedCandidate {
    pub fn fs(
        source: Source,
        path: impl Into<String>,
        access: FsAccess,
        reason: impl Into<String>,
        count: u64,
        last_seen_unix_ms: u64,
    ) -> Self {
        Self {
            source,
            requested: Requested::Fs {
                path: normalize_path(&path.into()),
                access,
            },
            reason: reason.into(),
            count,
            last_seen_unix_ms,
        }
    }

    pub fn net(
        source: Source,
        domain: impl Into<String>,
        reason: impl Into<String>,
        count: u64,
        last_seen_unix_ms: u64,
    ) -> Self {
        Self {
            source,
            requested: Requested::Net {
                domain: domain.into().trim_end_matches('.').to_ascii_lowercase(),
            },
            reason: reason.into(),
            count,
            last_seen_unix_ms,
        }
    }
}

/// 1つの収集源を読んだ結果。**読めなかった経路も`available: false`のレポートとして残す**
/// （D-43。黙って空にすると「収集器が動いていない」と「本当に拒否が無かった」が区別できない）。
#[derive(Debug, Clone)]
pub struct SourceReport {
    pub source: Source,
    pub available: bool,
    pub candidates: Vec<DeniedCandidate>,
    pub notes: Vec<String>,
}

impl SourceReport {
    pub fn unavailable(source: Source, note: impl Into<String>) -> Self {
        Self {
            source,
            available: false,
            candidates: Vec::new(),
            notes: vec![note.into()],
        }
    }
}

/// パス表記の正規化（`\`→`/`のみ）。大文字小文字は**変えない**——Windowsのファイルシステムは
/// 大小を区別しないが、ユーザーが設定ファイルで読む文字列としては元の見た目を保つ方がよく、
/// 比較が要る場面（重複除去）だけ`eq_ignore_ascii_case`で吸収する。
fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn parse_access(label: &str) -> Option<FsAccess> {
    match label {
        "read" => Some(FsAccess::Read),
        "read_write" | "rw" => Some(FsAccess::ReadWrite),
        "read_exec" => Some(FsAccess::ReadExec),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// 収集源1: preflight（`fs-passthrough-ledger.json`）
// ---------------------------------------------------------------------------

/// `fs-passthrough-ledger.json`のうち、この機構が読む2つの配列。
///
/// `denied_entries`は提案の**材料**（何が拒否されたか）、`entries`（実際に付与済みのACE）は
/// 提案の**判定材料**（既に許可済みなのに拒否されたのか）である。役割が違うので混ぜない。
#[derive(Debug, Deserialize)]
struct PreflightLedger {
    #[serde(default)]
    denied_entries: Vec<PreflightDeniedEntry>,
    #[serde(default)]
    entries: Vec<PreflightGrantedEntry>,
}

/// 実際にACE付与が確認できたルート1件。**台帳は`writable`しか持たない**ので、
/// `read`と`read_exec`はここでは区別できない（[`granted_from_ledger`]のdoc参照）。
#[derive(Debug, Deserialize)]
struct PreflightGrantedEntry {
    path: String,
    #[serde(default)]
    writable: bool,
}

#[derive(Debug, Deserialize)]
struct PreflightDeniedEntry {
    path: String,
    access: String,
    reason: String,
    #[serde(default)]
    last_denied_at_unix_secs: u64,
    #[serde(default)]
    count: u64,
}

/// `fs-passthrough-ledger.json`の中身（JSON文字列）から候補を取り出す。
pub fn normalize_preflight(ledger_json: &str) -> SourceReport {
    let mut notes = Vec::new();
    let ledger: PreflightLedger = match serde_json::from_str(ledger_json) {
        Ok(l) => l,
        Err(e) => {
            return SourceReport::unavailable(
                Source::Preflight,
                format!("fs-passthrough-ledger.json could not be parsed: {e}"),
            )
        }
    };

    let mut candidates = Vec::new();
    for entry in ledger.denied_entries {
        let Some(access) = parse_access(&entry.access) else {
            notes.push(format!(
                "skipped a denied entry with an unknown access label {:?} (path {})",
                entry.access, entry.path
            ));
            continue;
        };
        candidates.push(DeniedCandidate::fs(
            Source::Preflight,
            entry.path,
            access,
            entry.reason,
            entry.count.max(1),
            entry.last_denied_at_unix_secs.saturating_mul(1000),
        ));
    }

    SourceReport {
        source: Source::Preflight,
        available: true,
        candidates,
        notes,
    }
}

/// `fs-passthrough-ledger.json`の`entries`から「既に許可済みのパス」を取り出す
/// （[`crate::insufficient::GrantedPaths::merged`]の入力、`plans/PLAN-M15.7-FOLLOWUP.md` W4）。
///
/// 台帳は`writable: bool`しか持たないので、access種別はこう対応させる。
///
/// | `writable` | access | 根拠 |
/// |---|---|---|
/// | `true` | `ReadWrite` | `--fs-allow <path>:rw` |
/// | `false` | `ReadExec` | **`--fs-allow <path>`の既定は`Read`ではなく`ReadExec`**（`harness-cli`の`--fs-allow`解釈） |
///
/// **既知の不正確さ**: `--cow`下では`:rw`の実ACLが`Read`へ降格される（P-03、BUG-044）のに、
/// 台帳へはユーザーが要求した`writable=true`が記録される。この場合ここは`ReadWrite`と見なすので
/// 過大評価になる。ただし`--cow`下のworkspace外書込はRedirector DLLがupperへ捕捉するため、
/// `:rw`パスのACL拒否が提案経路まで来ること自体が稀であり、追跡はしない。
///
/// 壊れた台帳は**空として扱う**（D-43。読めないことを理由に提案そのものを止めない）。
pub fn granted_from_ledger(ledger_json: &str) -> Vec<(String, FsAccess)> {
    let Ok(ledger) = serde_json::from_str::<PreflightLedger>(ledger_json) else {
        return Vec::new();
    };
    ledger
        .entries
        .into_iter()
        .map(|entry| {
            let access = if entry.writable {
                FsAccess::ReadWrite
            } else {
                FsAccess::ReadExec
            };
            (normalize_path(&entry.path), access)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 収集源2: network（`net-audit.jsonl`）
// ---------------------------------------------------------------------------

/// `net-audit.jsonl`から拒否ドメインを取り出す。
///
/// 記録側（協調プロキシ・Fake DNS・WFP）でホスト名の入るキーが`host`と`remote_host`に
/// 分かれているため両方を見る（`net_cmd::format_net_audit_text`が表示で同じ吸収をしている）。
/// **ホスト名が無い行は候補にしない**——WFPのdropはIPしか持たないことがあり、IPリテラルは
/// `net.allow_domains`が受け付けない（`normalize_domain_pattern`が拒否する）ため、
/// 提案にしても適用できないから。
pub fn normalize_net_audit(jsonl: &str) -> SourceReport {
    let mut notes = Vec::new();
    let mut folded: Vec<DeniedCandidate> = Vec::new();
    let mut ip_only_denies = 0usize;

    for (idx, line) in jsonl.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                notes.push(format!("skipped malformed line {}: {e}", idx + 1));
                continue;
            }
        };
        if event.get("allowed").and_then(|v| v.as_bool()) != Some(false) {
            continue;
        }
        let reason = event
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("denied")
            .to_string();
        let host = event
            .get("host")
            .and_then(|v| v.as_str())
            .or_else(|| event.get("remote_host").and_then(|v| v.as_str()))
            .map(str::trim)
            .filter(|h| !h.is_empty());
        let Some(host) = host else {
            ip_only_denies += 1;
            continue;
        };
        let timestamp = event
            .get("timestamp_unix_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        fold_net(&mut folded, host, reason, timestamp);
    }

    if ip_only_denies > 0 {
        notes.push(format!(
            "{ip_only_denies} denied network event(s) carried no hostname (IP-only drops); \
             net.allow_domains cannot express those, so they are not proposed"
        ));
    }

    SourceReport {
        source: Source::Network,
        available: true,
        candidates: folded,
        notes,
    }
}

fn fold_net(folded: &mut Vec<DeniedCandidate>, host: &str, reason: String, timestamp: u64) {
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    if let Some(existing) = folded.iter_mut().find(|c| {
        matches!(&c.requested, Requested::Net { domain } if domain == &normalized)
    }) {
        existing.count = existing.count.saturating_add(1);
        existing.last_seen_unix_ms = existing.last_seen_unix_ms.max(timestamp);
    } else {
        folded.push(DeniedCandidate::net(
            Source::Network,
            normalized,
            reason,
            1,
            timestamp,
        ));
    }
}

// ---------------------------------------------------------------------------
// 収集源3: CoW（`.harness-cow-denied.jsonl`）
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CowDeniedLine {
    path: String,
    #[serde(default)]
    access_mask: u32,
    #[serde(default)]
    ts_unix_millis: u128,
}

/// Windowsのアクセスマスクのうち書込を意味するビット。`FILE_GENERIC_WRITE`のような
/// 複合マスクで判定すると`SYNCHRONIZE`/`READ_CONTROL`を共有する読み取りopenまで
/// 「書込」と誤判定する（[BUG-048]で実際に起きた）ため、**個別ビットの明示列挙**で判定する。
///
/// [BUG-048]: ../../../docs/bugs/BUG-048.md
const WRITE_INTENT_BITS: u32 = 0x0002 // FILE_WRITE_DATA
    | 0x0004 // FILE_APPEND_DATA
    | 0x0010 // FILE_WRITE_EA
    | 0x0100 // FILE_WRITE_ATTRIBUTES
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000; // WRITE_OWNER

/// アクセスマスクから要求されたaccess種別を導く。CoWの拒否台帳はACLで実際に弾かれた
/// **書込試行**を記録するものなので通常は`ReadWrite`になるが、マスクに書込ビットが
/// 立っていない記録（読取だけで弾かれた）は`Read`として扱う——P-03のとおり、
/// 要求されていない権限を提案へ混ぜない。
pub fn access_from_mask(access_mask: u32) -> FsAccess {
    if access_mask & WRITE_INTENT_BITS != 0 {
        FsAccess::ReadWrite
    } else {
        FsAccess::Read
    }
}

/// `.harness-cow-denied.jsonl`から候補を取り出す。同一（パス, access）は畳んで数える。
pub fn normalize_cow_denied(jsonl: &str) -> SourceReport {
    let mut notes = Vec::new();
    let mut folded: Vec<DeniedCandidate> = Vec::new();

    for (idx, line) in jsonl.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: CowDeniedLine = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                notes.push(format!("skipped malformed line {}: {e}", idx + 1));
                continue;
            }
        };
        let access = access_from_mask(entry.access_mask);
        let timestamp = u64::try_from(entry.ts_unix_millis).unwrap_or(u64::MAX);
        fold_fs(
            &mut folded,
            Source::Cow,
            &entry.path,
            access,
            "write outside the workspace was denied by ACL",
            timestamp,
        );
    }

    SourceReport {
        source: Source::Cow,
        available: true,
        candidates: folded,
        notes,
    }
}

// ---------------------------------------------------------------------------
// 収集源4: OS監査（`fs-audit.jsonl`）
// ---------------------------------------------------------------------------

/// `fs-audit.jsonl`から候補を取り出す。
///
/// [`crate::event::FsAuditKind::Control`]の行は**候補にしない**（収集器自身の状態であって
/// 拒否ではない）が、`notes`へ写して可視化する。制御行しか無いファイルは
/// `available: false`として扱う——収集器は起動したが実際には観測できていない状態であり、
/// 「拒否が0件だった」と区別できなければならない（D-43）。
pub fn normalize_fs_audit(jsonl: &str) -> SourceReport {
    use crate::event::{FsAuditEvent, FsAuditKind};

    let mut notes = Vec::new();
    let mut folded: Vec<DeniedCandidate> = Vec::new();
    let mut saw_control_failure = false;
    let mut saw_any_event = false;

    for (idx, line) in jsonl.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event: FsAuditEvent = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                notes.push(format!("skipped malformed line {}: {e}", idx + 1));
                continue;
            }
        };
        saw_any_event = true;
        if event.kind == FsAuditKind::Control {
            saw_control_failure = true;
            notes.push(format!("collector reported: {}", event.reason));
            continue;
        }
        if event.allowed {
            continue;
        }
        let (Some(path), Some(access)) = (event.path.as_deref(), event.access) else {
            notes.push(format!(
                "skipped a denial on line {} that carried no path/access",
                idx + 1
            ));
            continue;
        };
        fold_fs(
            &mut folded,
            Source::Etw,
            path,
            access,
            &event.reason,
            event.timestamp_unix_ms,
        );
    }

    let available = !(saw_control_failure && folded.is_empty()) && saw_any_event;
    if !available && saw_control_failure {
        notes.push(
            "the OS audit collector did not observe any denial (it reported a failure above); \
             proposals fall back to the other sources"
                .to_string(),
        );
    }

    SourceReport {
        source: Source::Etw,
        available,
        candidates: folded,
        notes,
    }
}

fn fold_fs(
    folded: &mut Vec<DeniedCandidate>,
    source: Source,
    path: &str,
    access: FsAccess,
    reason: &str,
    timestamp: u64,
) {
    let normalized = normalize_path(path);
    if let Some(existing) = folded.iter_mut().find(|c| {
        matches!(&c.requested, Requested::Fs { path, access: a }
            if *a == access && path.eq_ignore_ascii_case(&normalized))
    }) {
        existing.count = existing.count.saturating_add(1);
        existing.last_seen_unix_ms = existing.last_seen_unix_ms.max(timestamp);
    } else {
        folded.push(DeniedCandidate::fs(
            source, normalized, access, reason, 1, timestamp,
        ));
    }
}

#[cfg(test)]
#[path = "normalize_tests.rs"]
mod normalize_tests;
