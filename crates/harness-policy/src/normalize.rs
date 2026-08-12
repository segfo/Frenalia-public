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
///
/// 候補・提案の値はすべてこの綴りで揃っている。**それらと突き合わせる側も同じ関数を通すこと**
/// ——綴りを揃える規則を2つ持つとBUG-066/BUG-068と同型の穴になるので`pub`にしてある
/// （ポリシーエディタの承認が、提案の値とワークスペースrootを比較するのに使う）。
pub fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
}

/// ワイルドカードを含む値の**確定部分**（最初の`*`を含む要素の手前まで）。
///
/// # なぜ1箇所に置くのか（D-63）
///
/// この境目は**ACEが実際に付く場所そのもの**である。`C:/x/**`という宣言に対して付与されるのは
/// `C:/x`のACEであって、`**`という名前のオブジェクトではない。したがって
///
/// - 幅の判定（[`crate::breadth`]）は**この確定部分**に対して行わなければならない。
///   値の見た目の深さで判定すると、`C:/Users/<誰か>`は拒否するのに`C:/Users/<誰か>/**`は
///   通してしまう（実際にそうなっていた——後者の方が広いのに）。
/// - 付与ルートの算出（ポリシーエディタの`approve::grant_root`）も同じ境目を使う。
///
/// 2箇所が別々に切ると、**判定した値と付与する値が食い違う**（B-05）。だからここに置いて共有する。
///
/// **区切りは`/`と`\`の両方を受ける。** 呼び出し側が[`normalize_path`]を通しているとは限らない
/// ——`breadth`は生の宣言値をそのまま judge する経路を持つ。片方だけ見ていると、
/// `C:\ws\**`のような値で確定部分が**空文字**になり、「ファイルシステムのルート」として
/// 拒否する（実際にそうなった）。
pub fn literal_prefix(value: &str) -> &str {
    match value.find('*') {
        None => value,
        Some(star) => {
            // `*`を含む**要素ごと**落とす（`C:/a/b*c/d` → `C:/a`）。
            let cut = value[..star].rfind(['/', '\\']).unwrap_or(0);
            value[..cut].trim_end_matches(['/', '\\'])
        }
    }
}

/// 宣言値1件が**どこまでACEを開くか**（D-63）。
///
/// [`literal_prefix`]と対になる値である——あちらが「どのオブジェクトへ付けるか」を決め、
/// こちらが「そのオブジェクトだけか、配下もか」を決める。2つ揃って初めて付与が定まる。
///
/// # なぜ宣言の**書き方**で決めるのか
///
/// 提案の値は観測されたものそのままで、畳まない（**D-62**）。畳まないなら、付与も観測された
/// 範囲に留まらなければ意味が無い——「観測された2件を承認したのにサブツリー全体が開く」のが
/// D-62で塞いだ穴そのものだからである。範囲を広げたいという意思は、値に`/**`と**書く**という
/// 明示的な操作でしか表せないようにする（ポリシーエディタの`R`キー、または設定の手編集）。
///
/// この型は`harness-sandbox`（ACEを実際に付ける側）と`harness-cli`・ポリシーエディタ
/// （宣言を読む側）の両方が使う。判定を各自が持つと、**書いた値と付く範囲が食い違う**（B-05）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GrantScope {
    /// そのオブジェクト1つだけ（非継承ACE）。素のパスの宣言はこれ。
    Object,
    /// 配下すべてと、今後そこに作られるもの（継承ACE）。`<path>/**`と書いたときだけ。
    Recursive,
}

impl GrantScope {
    pub fn is_recursive(self) -> bool {
        matches!(self, GrantScope::Recursive)
    }

    /// 表示・台帳用の短い綴り。
    pub fn label(self) -> &'static str {
        match self {
            GrantScope::Object => "object",
            GrantScope::Recursive => "recursive",
        }
    }
}

/// 宣言値が要求している範囲（D-63）。**末尾が`**`のときだけ再帰**。
///
/// 末尾の区切りは無視する（`C:/x/**/`も再帰）。それ以外のワイルドカード
/// （`C:/x/*/bin`のような中間の`*`）は**再帰にしない**——[`literal_prefix`]は`C:/x`まで戻るので、
/// 再帰にすると宣言よりはるかに広い範囲が開く（D-62で`--generalize=auto`を廃した理由そのもの）。
/// その形の値は付与層が名指しで拒否する（`preflight`）。ここで再帰へ格上げして黙って通さない。
pub fn declared_scope(value: &str) -> GrantScope {
    let trimmed = value.trim_end_matches(['/', '\\']);
    if trimmed.ends_with("**") {
        GrantScope::Recursive
    } else {
        GrantScope::Object
    }
}

/// 宣言値に**確定部分より後ろのワイルドカード**が残っているか（＝`<path>/**`でも素のパスでもない形）。
///
/// `C:/x/*/bin`・`C:/x/lib*`のような値がこれに当たる。[`literal_prefix`]が`C:/x`まで戻るため、
/// 付与できるのは「`C:/x`のオブジェクト単体」か「`C:/x`配下すべて」のどちらかしかなく、
/// **前者は宣言より狭く（何も開かない）、後者は宣言よりはるかに広い**。どちらを選んでも
/// 宣言と付与が一致しないので、値そのものを受け付けない側に倒す（付与層が理由を添えて弾く）。
pub fn has_unsupported_wildcard(value: &str) -> bool {
    let trimmed = value.trim_end_matches(['/', '\\']);
    let body = match trimmed.strip_suffix("**") {
        // `<path>/**`の`**`は正規の書き方なので、判定からは外す。
        Some(head) => head.trim_end_matches(['/', '\\']),
        None => trimmed,
    };
    body.contains('*')
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
    normalize_net_audit_with_mode(jsonl, NetIntake::DeniedOnly)
}

/// `net-audit.jsonl`のどの行を候補にするか。
///
/// FS側の`Correlator::on_operation_end_any`（record-allモード）とまったく同じ形の分岐である
/// ——収集器を「全部記録する」設定で回したとき、拒否だけを拾う正規化を通すと候補が**0件**に
/// なるため、取り込み口の側にモードが要る。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetIntake {
    /// 通常運用（`harness net` / `harness policy suggest`）: 拒否された行だけを候補にする。
    DeniedOnly,
    /// ポリシーエディタのパス2（`DomainPolicy::record_all`で走らせた記録）:
    /// **許可された行も候補にする**。全許可で走らせているので、拒否だけを見ると何も残らない。
    All,
}

/// `net-audit.jsonl`の1行が**ネットワークイベントではなく制御レコード**か。
///
/// 制御レコード（`protocol == "control"`）は、昇格側が自分の状態——WFPイベント収集を
/// 有効化できなかった、収集器を連鎖起動できなかった等——を残すために書く1行である
/// （`wfp.rs`の`record_control_event`が唯一の書き手）。FS側の[`crate::FsAuditKind::Control`]と
/// 同じ役割で、**候補には昇格しない**。
///
/// この判定が要るのは、制御レコードが`allowed: false`かつホスト名を持たないため、
/// 素通しすると「拒否されたがホスト名を復元できなかったネットワークイベント」として
/// 数えられてしまうからである——実データ（BUG-093のセッション`7476-1786226894-1`）で
/// 「1件のネットワークイベントがホスト名を持たなかった」という**嘘の注記**が出ていた。
pub fn is_net_control_record(event: &serde_json::Value) -> bool {
    event.get("protocol").and_then(|v| v.as_str()) == Some("control")
}

/// [`normalize_net_audit`]の取り込み口を選べる版（[`NetIntake`]参照）。
pub fn normalize_net_audit_with_mode(jsonl: &str, intake: NetIntake) -> SourceReport {
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
        // 制御レコードは「通信の記録」ではない。ここで落とさないと、ホスト名を持たない
        // 拒否として`ip_only_denies`に混ざる（`is_net_control_record`のdoc参照）。
        if is_net_control_record(&event) {
            continue;
        }
        if intake == NetIntake::DeniedOnly
            && event.get("allowed").and_then(|v| v.as_bool()) != Some(false)
        {
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
        // 件数は必ず出す（黙って捨てると「通信が無かった」と区別できない、B-09）。
        notes.push(match intake {
            NetIntake::DeniedOnly => format!(
                "{ip_only_denies} denied network event(s) carried no hostname (IP-only drops); \
                 net.allow_domains cannot express those, so they are not proposed"
            ),
            NetIntake::All => format!(
                "{ip_only_denies} network event(s) carried no hostname (IP-only); \
                 net.allow_domains cannot express those, so they are not proposed. \
                 これは既知の盲点です——OSのリゾルバを経由しない自前DNS実装や、IPを直接指定した \
                 接続はドメイン名を復元できません"
            ),
        });
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
    if let Some(existing) = folded
        .iter_mut()
        .find(|c| matches!(&c.requested, Requested::Net { domain } if domain == &normalized))
    {
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

/// **大量観測向け**の逐次畳み込み器（ポリシーエディタの記録モード＝record-all用）。
///
/// # なぜ[`fold_fs`]と別に要るのか
///
/// | | [`fold_fs`]（既存、deny-only） | 本型（record-all） |
/// |---|---|---|
/// | 入力 | 拒否だけ（`normalize_fs_audit`が`allowed`を捨てる） | 拒否＋許可の両方 |
/// | 件数の規模 | 数十件 | 実測3,131件、`cargo build`規模ならさらに桁が増える |
/// | 畳み込み | `Vec`の線形走査（O(n·m)） | `HashMap`（O(n)） |
///
/// deny-onlyの規模では線形走査で十分だったが、record-allは**成功したアクセスも全部載る**ので
/// 桁が変わる。既存経路の挙動を変えずに済ませるため、置き換えではなく並存させる。
/// **両者が同じ結果を返すことは[`normalize_tests`]の同値性テストで固定する**——畳み込みの
/// 実装が2つある以上、片方だけ直る事故（B-01）はテストでしか止められない。
///
/// # `DeniedCandidate`をrecord-allでも使う理由
///
/// 型名は"denied"だが、実体は「許可ルールが要る要求1件」であり、[`crate::generalize`]は
/// この型でしか動かない。record-allでは`reason`に観測時の理由（`observed`等）が入り、
/// 「拒否された」という含意は持たない。
#[derive(Debug, Default)]
pub struct FsFolder {
    /// キーは`(小文字化したパス, access)`。Windowsのパス比較は大小を区別しないので、
    /// 畳み込みも大小を無視する（[`fold_fs`]の`eq_ignore_ascii_case`と同じ規則）。
    seen: std::collections::HashMap<(String, FsAccess), usize>,
    folded: Vec<DeniedCandidate>,
}

impl FsFolder {
    pub fn new() -> Self {
        Self::default()
    }

    /// 1件を畳み込む。同じ`(パス, access)`が既にあれば件数を増やし、無ければ追加する。
    /// 最初に見た`reason`を保持する（後から来た同一パスの理由で上書きしない）。
    pub fn add(
        &mut self,
        source: Source,
        path: &str,
        access: FsAccess,
        reason: &str,
        timestamp: u64,
    ) {
        let normalized = normalize_path(path);
        let key = (normalized.to_ascii_lowercase(), access);
        match self.seen.get(&key) {
            Some(&index) => {
                let existing = &mut self.folded[index];
                existing.count = existing.count.saturating_add(1);
                existing.last_seen_unix_ms = existing.last_seen_unix_ms.max(timestamp);
            }
            None => {
                self.seen.insert(key, self.folded.len());
                self.folded.push(DeniedCandidate::fs(
                    source, normalized, access, reason, 1, timestamp,
                ));
            }
        }
    }

    /// 観測順（初出順）の候補列。[`crate::generalize`]は入力順に依存しないので、
    /// ここでの並びは表示・テストのための決定性だけを担う。
    pub fn into_candidates(self) -> Vec<DeniedCandidate> {
        self.folded
    }

    pub fn candidates(&self) -> &[DeniedCandidate] {
        &self.folded
    }

    /// 畳み込み後の件数（＝異なる`(パス, access)`の数）。
    pub fn len(&self) -> usize {
        self.folded.len()
    }

    pub fn is_empty(&self) -> bool {
        self.folded.is_empty()
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
