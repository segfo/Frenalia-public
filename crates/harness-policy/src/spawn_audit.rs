//! `spawn-audit.jsonl`の1行分レコード——**Spawn Daemon が許可して起こした生成の記録**
//! （`plans/DESIGN-MAC-ENFORCEMENT.md` §10.2「許可した生成の記録」。置き場と切り分けは
//! `plans/POLICY-EDITOR-TOMOYO-DIG.md`の決定68の前例の(1)〜(6)）。
//!
//! **書く側は Spawn Daemon**（`harness-sandbox`の`tier2a::spawnd`。昇格しない）、**読む側は非特権のポリシーエディタ**である。
//! [`crate::process_event`]と同じ理由で、型の定義はここだけに置く——書く側と読む側に別々の型があると、
//! 片側だけ形が変わっても誰も気付かないまま静かに読み違える。
//!
//! # 何のためにあるのか
//!
//! ポリシーエディタのパス2は遷移を強制して走る（決定68(1)）ので、サンドボックスの中のプロセスは全部 Daemon が起こす。
//! パス2で断られたファイル操作には、操作したプロセスの通し番号（`ProcessSequenceNumber`）が付く
//! （[`crate::event::FsAuditEvent::process_sequence_number`]）。Daemon が「その番号の子を、どのドメインで起こしたか」を
//! 1行ずつ書けば、エディタは拒否を**起こされたドメインへ**振り分けて候補にできる（[`partition_fs_by_spawns`]）。
//! 木を組む必要は無い——遷移先を決めたのは Daemon 自身なので、その答えをそのまま書かせる。
//!
//! # 書く場所と寿命
//!
//! ポリシーエディタの記録のディレクトリ（`fs-audit.jsonl`の隣）。**`harness.exe`の Daemon は書かない**（量の上限と
//! 回転を決めていない。決定68の前例の(4)、暫定）。1つの記録に書くのは[`SPAWN_AUDIT_MAX_LINES`]行まで——超えた分は
//! 数えて、Daemon が畳むときに[`SpawnAuditRecord::Overflow`]を1行書く。
//!
//! # 版
//!
//! 1行目は[`SpawnAuditRecord::Header`]で、[`SPAWN_AUDIT_SCHEMA_VERSION`]を名乗る（`process-audit.jsonl`と同じ作法）。
//! 読む側（[`parse_spawn_audit`]）は知らない新しい版を、知っている形として読まない。

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::event::FsAuditEvent;
use crate::position_domains::Partition;

/// Daemon が書くファイルの名前。**書く側（Daemon）・先に作る側（エディタ。BUG-109 と同じく、書く側にファイルを作らせない）・
/// 読む側（エディタ）・fork で持っていかない一覧（`harness-sandbox`の`session_scope`）がこの1つを参照する**（`B-05`）。
pub const SPAWN_AUDIT_FILE: &str = "spawn-audit.jsonl";

/// この形の版。欄の意味を変えたら上げる。
pub const SPAWN_AUDIT_SCHEMA_VERSION: u32 = 1;

/// 1つの記録に書く行の上限（版の行を除く。決定68の前例の(5)）。`cargo build`1回で数千の生成が起きる規模を見込み、
/// 待ち行列と同じく「上限つきにして、あふれを数える」（§10.2）。
pub const SPAWN_AUDIT_MAX_LINES: usize = 100_000;

/// `spawn-audit.jsonl`の1行。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpawnAuditRecord {
    /// 1行目。この行が無い・読めないファイルは読まない（[`parse_spawn_audit`]）。Daemon が記録を開いたときに書く。
    Header { schema_version: u32 },
    /// Daemon が許可して起こした子1人（トップレベルも入れ子も）。
    Spawned {
        ts_unix_ms: u64,
        pid: u32,
        /// 子の`ProcessSequenceNumber`。**取れなかったら`None`で、欄ごと書かない**（推測で埋めない、`P-11`）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        process_sequence_number: Option<u64>,
        /// 子を起こしたドメイン（`policy.json`の名前）。
        domain: String,
        /// 起こした実行ファイル（Daemon が`lpApplicationName`に渡した綴り）。
        exe: String,
        /// ホスト（エディタ・`harness.exe`）が直接頼んだトップレベルか。偽なら入れ子（サンドボックスの中から頼まれた）。
        top_level: bool,
    },
    /// コンソールの保持プロセスを立て直した（`DESIGN-MAC-ENFORCEMENT.md` §7.1.2 決定4）。**終了コードは手掛かりであって
    /// 証拠ではない**——「撃たれた」とは書かない。
    ConsoleHolderRestarted {
        ts_unix_ms: u64,
        domain: String,
        old_pid: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old_exit_code: Option<u32>,
        new_pid: u32,
    },
    /// [`SPAWN_AUDIT_MAX_LINES`]を超えて書かなかった行の数（Daemon が畳むときに1行）。
    Overflow { ts_unix_ms: u64, dropped: u64 },
}

impl SpawnAuditRecord {
    /// JSONL 1行へ直列化する（末尾改行は含めない）。
    pub fn to_jsonl_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// [`parse_spawn_audit`]が読み出したもの。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpawnAuditLog {
    /// 通し番号 → 起こしたドメイン。
    pub domains_by_sequence: BTreeMap<u64, String>,
    /// 生成の行の数（番号の有無を問わない）。
    pub spawned: usize,
    /// 番号を取れなかった生成の数（その子の拒否はどのドメインにも引けない）。
    pub without_sequence_number: usize,
    pub console_holder_restarts: usize,
    /// 上限を超えて書かれなかった生成の数（[`SpawnAuditRecord::Overflow`]の和）。
    pub dropped: u64,
    /// 読めなかった完全な行の数。**黙って捨てずに数える**（書きかけの最後の行は数えない）。
    pub unreadable_lines: usize,
}

/// `spawn-audit.jsonl`を読めなかった理由。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpawnAuditError {
    #[error(
        "spawn-audit.jsonl が版の行で始まっていません（先頭の行: {first_line}）。\
         どの版の形か分からないので読みません"
    )]
    MissingHeader { first_line: String },
    #[error(
        "spawn-audit.jsonl の版 {found} はこのバイナリ（対応版 {supported}）より新しいものです。\
         新しい harness-policy-editor で開いてください"
    )]
    FutureSchema { found: u32, supported: u32 },
}

/// `spawn-audit.jsonl`の中身を読む（**ファイルは読まない**。読み込み済みの文字列を受け取る——このクレートの純粋性）。
///
/// 読み方は`process-audit.jsonl`（[`crate::process_event::parse_process_audit`]）と同じ:
/// 最後の改行より後（書きかけの行）は読まない／完全な行が1つも無ければ空の`Ok`（エディタが先に作った空のファイル）／
/// 最初の空でない完全な行が版の行でなければ[`SpawnAuditError::MissingHeader`]／版の行は**どれも**確かめる／
/// 読めない完全な行は[`SpawnAuditLog::unreadable_lines`]に数える。
pub fn parse_spawn_audit(text: &str) -> Result<SpawnAuditLog, SpawnAuditError> {
    let complete = match text.rfind('\n') {
        Some(index) => &text[..=index],
        None => "",
    };
    let mut log = SpawnAuditLog::default();
    let mut header_seen = false;
    for line in complete.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parsed = serde_json::from_str::<SpawnAuditRecord>(line);
        if !header_seen {
            match parsed {
                Ok(SpawnAuditRecord::Header { schema_version }) => {
                    refuse_future(schema_version)?;
                    header_seen = true;
                    continue;
                }
                _ => {
                    return Err(SpawnAuditError::MissingHeader {
                        first_line: line.chars().take(80).collect(),
                    })
                }
            }
        }
        match parsed {
            Ok(SpawnAuditRecord::Header { schema_version }) => refuse_future(schema_version)?,
            Ok(SpawnAuditRecord::Spawned {
                process_sequence_number,
                domain,
                ..
            }) => {
                log.spawned += 1;
                match process_sequence_number {
                    Some(seq) => {
                        log.domains_by_sequence.insert(seq, domain);
                    }
                    None => log.without_sequence_number += 1,
                }
            }
            Ok(SpawnAuditRecord::ConsoleHolderRestarted { .. }) => log.console_holder_restarts += 1,
            Ok(SpawnAuditRecord::Overflow { dropped, .. }) => {
                log.dropped = log.dropped.saturating_add(dropped)
            }
            Err(_) => log.unreadable_lines += 1,
        }
    }
    Ok(log)
}

fn refuse_future(schema_version: u32) -> Result<(), SpawnAuditError> {
    if schema_version > SPAWN_AUDIT_SCHEMA_VERSION {
        return Err(SpawnAuditError::FutureSchema {
            found: schema_version,
            supported: SPAWN_AUDIT_SCHEMA_VERSION,
        });
    }
    Ok(())
}

/// パス2のファイル操作を、操作したプロセスを Daemon が起こしたドメインへ振り分ける（決定68の前例の(1)(7)）。
///
/// 結果の型と振り分けの本体は位置ごとのドメイン（[`crate::position_domains::partition_fs`]）と共有する——
/// 2つ目の振り分けを書かない（`B-13`）。引けない操作は入口へ寄せず件数だけ数える（決定65 Q4）。
/// 「割り当てなかった起動」（`unassigned_instance`）はパス2には無いので、いつも0。
pub fn partition_fs_by_spawns<'e>(events: &'e [FsAuditEvent], log: &SpawnAuditLog) -> Partition<'e> {
    let domains: BTreeMap<u64, &str> = log
        .domains_by_sequence
        .iter()
        .map(|(seq, domain)| (*seq, domain.as_str()))
        .collect();
    let mut partition = Partition::default();
    crate::position_domains::partition_by_sequence(events, &domains, &BTreeSet::new(), &mut partition);
    partition
}

#[cfg(test)]
#[path = "spawn_audit_tests.rs"]
mod spawn_audit_tests;
