//! `Microsoft-Windows-Kernel-File`のイベント列から「拒否された1件」を組み立てる純粋ロジック
//! （M15.7、`plans/DESIGN-SANDBOX-APPPOLICY.md` §11）。
//!
//! # なぜ2つのイベントを相関させる必要があるのか
//!
//! Kernel-Fileの`Create`（event id 12）は**要求**を報告するだけで、その結果（NTSTATUS）を
//! 持たない。結果は`OperationEnd`（event id 24）が別イベントとして報告し、両者は`Irp`
//! （I/O Request Packetのポインタ値）でしか結び付かない。つまり「どのパスへのアクセスが
//! 拒否されたか」は、この2つを突き合わせて初めて分かる。
//!
//! 相関表は無限に伸びうる（`OperationEnd`が来ないまま`Create`だけが積まれる：バッファ落ち・
//! セッション開始直後の片側だけの観測）ため、**容量上限付きのFIFOで古いものから捨てる**。
//! 取りこぼしは境界の欠落を意味しない（P-07・D-43）ので、ここで無制限にメモリを使う理由が無い。
//!
//! # 意図的な制約: この経路では`DesiredAccess`が取れない（実測で確定、2026-08-04）
//!
//! Kernel-Fileの`Create`が持つのは`CreateOptions`・`CreateAttributes`・`ShareAccess`であり、
//! **`DesiredAccess`は含まれない**。マニフェストを実機で引いて確認済み
//! （`Get-WinEvent -ListProvider Microsoft-Windows-Kernel-File`、Id=12はv0/v1とも
//! `Irp` / `FileObject` / `ThreadId`(v1は`IssuingThreadId`) / `CreateOptions` /
//! `CreateAttributes` / `ShareAccess` / `FileName` の7項目のみ）。したがって
//! 「読もうとして拒否されたのか、書こうとして拒否されたのか」をこの経路だけでは決められない。
//!
//! **`Microsoft-Windows-Kernel-Audit-API-Calls`は代替にならない**（同じく実測で確認）。
//! 名前に反して、`DesiredAccess`を持つのはId=3（オブジェクトマネージャのシンボリックリンク）・
//! Id=5（`NtOpenProcess`）・Id=6（`NtOpenThread`）の3つで、**8イベントのどれもファイルパスを
//! 運ばない**。あれはプロセス/スレッドハンドルのopen（LSASSハンドル取得の検知等）を対象にした
//! プロバイダであり、ファイルオブジェクトは扱わない。
//!
//! ファイルの`DesiredAccess`を正確に取れるのはWindows Security Auditing（4656の`AccessMask`）
//! だが、対象パスへのSACL設定という**実FSの永続的改変**が要るため採らない（M15.7の判断、
//! `docs/STATUS.md`）。
//!
//! そこでここでは`CreateDisposition`（`CreateOptions`の上位8bit）から判る範囲だけを使い、
//! **判らない場合は`Read`へ倒す**（[`access_from_create_options`]）。
//!
//! # なぜ2/4/5だけ`ReadWrite`へ寄せてよいのか（非対称の根拠、D-46）
//!
//! この非対称は精度の妥協でも恣意でもなく、**片側だけ証明が成立する**ことの反映である。
//! 根拠は実測で固定してある（`disposition_semantics_tests.rs`、管理者権限もETWも要らないので
//! `cargo test`で常時走る）。
//!
//! | 観測 | read許可**だけ**の状態での結果 | そこから言えること |
//! |---|---|---|
//! | disposition 4/5/0 | **必ず拒否**（P1/P2/P3） | `fs.read`をいくら足しても直らない ⇒ `ReadWrite`が要る |
//! | disposition 3 で読む | 成功（N1） | `fs.read`は有効な修正になりうる |
//! | disposition 3 で書く | 拒否（N2） | 3からは読/書を区別できない |
//!
//! 4/5/0が必ず拒否になるのは、**IOマネージャがdispositionを見て`FILE_WRITE_DATA`を実効マスクへ
//! 足す**からである。呼び出し側が`DesiredAccess`に書込を1ビットも入れていなくても足される
//! （許可DACLの下では、読取専用のハンドル要求でファイルが0バイトに切り詰められることを実測した）。
//! したがって「拒否された」という観測と組み合わせたときだけ、dispositionは
//! **`read`では足りないことの証明**になる。
//!
//! この向きの推定は`ReadWrite`を提案しても**要求されていた権限を超えない**ので、P-03とも整合する。
//!
//! **逆向き（3を`ReadWrite`へ寄せる）は成立しない。** N1が示すとおり3はread許可で通ることが
//! あり、寄せると読み取りしか要らなかった場所に書込許可を提案することになる。提案が狭すぎた
//! 場合はユーザーが直せるが、広すぎる提案は気付かれずに受理されうる。
//!
//! # 残る不完全さと、その回収経路
//!
//! N2のとおり書込も`FILE_OPEN_IF`(3)を通るため、**書込の拒否が`fs.read`として提案されうる**
//! （`Add-Content`がまさにこれ。RESULTS.md §17.4）。ここは狭い側に外しているので危険ではないが、
//! 黙っていると「提案どおりにしたのに直らない」になる。回収するのは推定側ではなく
//! **昇格の梯子**である——既に`fs.read`で許可済みのパスで拒否が観測されたら、readでは足りない
//! ことが確定するので、提案そのものを`fs.read_write`/`fs.read_exec`へ差し替える
//! （`harness_policy::insufficient`・`harness_policy::generalize`、D-46）。
//!
//! なお`--sandbox tier2a-cow`セッションではRedirector DLLが`NtCreateFile`の生の`DesiredAccess`を
//! `.harness-cow-denied.jsonl`へ記録しており、そちらは正確である。2つの収集源は補完関係にある
//! ——フックは精度を持つが境界にならず（P-02）、ETWは網羅性を持つが精度が落ちる。

use std::collections::{HashMap, VecDeque};

use harness_config::FsAccess;

/// `STATUS_ACCESS_DENIED`。ACLで弾かれたときにIOマネージャが返すNTSTATUS。
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

/// `Microsoft-Windows-Kernel-File`のプロバイダGUID（`{EDD08927-9CC4-4E65-B970-C2560FB5C289}`）。
pub const KERNEL_FILE_PROVIDER_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(0xEDD0_8927_9CC4_4E65_B970_C256_0FB5_C289);

/// `Create`（要求）のevent id。
pub const EVENT_ID_CREATE: u16 = 12;
/// `OperationEnd`（結果とNTSTATUS）のevent id。
pub const EVENT_ID_OPERATION_END: u16 = 24;

/// `CreateOptions`の上位8bitに載る`CreateDisposition`。
///
/// `FILE_SUPERSEDE`（値0）は意味としては上書きだが、**`CreateOptions`全体が0のとき
/// （プロパティを引けなかった・報告されなかった場合の既定値）と区別が付かない**ため、
/// 書込側として扱わない。判らないものを`ReadWrite`へ倒すのはP-03違反になる
/// （[`access_from_create_options`]のdoc、および同名のテスト参照）。
const FILE_CREATE: u32 = 2;
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;

/// `Create`イベントから取り出した、結果待ちの1件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCreate {
    /// NT形式のファイル名（`\Device\HarddiskVolume3\...`のことも、`\??\C:\...`のこともある）。
    pub file_name: String,
    pub pid: u32,
    pub create_options: u32,
    pub timestamp_unix_ms: u64,
}

/// 相関が成立した「拒否された1件」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    pub file_name: String,
    pub pid: u32,
    pub access: FsAccess,
    pub status: u32,
    pub timestamp_unix_ms: u64,
    /// `Create`が報告した生の`CreateOptions`（上位8bitが`CreateDisposition`）。
    /// **`DesiredAccess`が無い以上、イベント側で読み書きを見分ける材料はこれしかない。**
    /// 診断で「操作の種類ごとに値が変わるか」を見るために保持する。
    pub create_options: u32,
}

/// 相関が成立した「観測された1件」（拒否・成功のいずれも含む）。record-allモード用。
///
/// [`Denial`]とほぼ同じ形だが`allowed`を持つ。統合せず並存させているのは、
/// `Denial`が既にサーバ側・複数のテストファイルで「拒否のみ」という前提のまま
/// 広く参照されており、record-allは今回新設するTier1経路専用の別系統だから
/// （`docs/CODE-STRUCTURE-RULES.md`規則5は「型が違うだけの重複」を戒めるが、
/// ここは意味が違う——deny-onlyの利用側を無変更に保つ方を優先した）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRecord {
    pub file_name: String,
    pub pid: u32,
    pub access: FsAccess,
    pub status: u32,
    pub allowed: bool,
    pub timestamp_unix_ms: u64,
    pub create_options: u32,
}

/// `Create`と`OperationEnd`を`Irp`で突き合わせる相関表。
#[derive(Debug)]
pub struct Correlator {
    pending: HashMap<u64, PendingCreate>,
    /// 挿入順。容量超過時に最も古い`Irp`から捨てるために持つ。
    order: VecDeque<u64>,
    capacity: usize,
    /// 容量超過で捨てた`Create`の数（＝結果を知らずに諦めた件数）。
    /// **容量4096が妥当かを測る唯一の材料**なので数えておく。
    evicted: u64,
    /// 相関する`Create`が無かった`OperationEnd`の数（セッション開始前に始まったIRP・バッファ落ち）。
    unmatched_operation_ends: u64,
}

impl Correlator {
    /// `capacity`は同時に結果待ちにできる`Create`の数。超えた分は古いものから捨てる。
    pub fn new(capacity: usize) -> Self {
        Self {
            pending: HashMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
            evicted: 0,
            unmatched_operation_ends: 0,
        }
    }

    pub fn on_create(&mut self, irp: u64, create: PendingCreate) {
        // 同じIrpポインタは使い回される（前のIRPが完了した後に再利用される）。既存の
        // エントリがあれば新しい方で置き換える——古い方の`OperationEnd`はもう来ないため。
        if self.pending.insert(irp, create).is_none() {
            self.order.push_back(irp);
        }
        while self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                if self.pending.remove(&oldest).is_some() {
                    self.evicted = self.evicted.saturating_add(1);
                }
            }
        }
    }

    /// `Irp`に対応する`Create`を相関表から取り出す。見つからなければ
    /// `unmatched_operation_ends`を増やして`None`（バッファ落ち・セッション開始前に
    /// 始まったIRP）。deny-only/record-allの両モードが共有する下回り。
    fn take_pending(&mut self, irp: u64) -> Option<PendingCreate> {
        let Some(create) = self.pending.remove(&irp) else {
            self.unmatched_operation_ends = self.unmatched_operation_ends.saturating_add(1);
            return None;
        };
        self.order.retain(|i| *i != irp);
        Some(create)
    }

    /// `OperationEnd`を受け取り、拒否だった場合だけ[`Denial`]を返す（deny-onlyモード）。
    /// 相関する`Create`が無い場合は`None`。
    pub fn on_operation_end(&mut self, irp: u64, status: u32) -> Option<Denial> {
        let create = self.take_pending(irp)?;
        if status != STATUS_ACCESS_DENIED {
            return None;
        }
        Some(Denial {
            access: access_from_create_options(create.create_options),
            file_name: create.file_name,
            pid: create.pid,
            status,
            timestamp_unix_ms: create.timestamp_unix_ms,
            create_options: create.create_options,
        })
    }

    /// `OperationEnd`を受け取り、拒否・成功を問わず[`AccessRecord`]を返す（record-allモード）。
    /// 相関する`Create`が無い場合のみ`None`——`on_operation_end`と違い、結果の値では
    /// 絞り込まない。
    pub fn on_operation_end_any(&mut self, irp: u64, status: u32) -> Option<AccessRecord> {
        let create = self.take_pending(irp)?;
        Some(AccessRecord {
            access: access_from_create_options(create.create_options),
            file_name: create.file_name,
            pid: create.pid,
            status,
            allowed: status != STATUS_ACCESS_DENIED,
            timestamp_unix_ms: create.timestamp_unix_ms,
            create_options: create.create_options,
        })
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// 容量超過で捨てた`Create`の数（`capacity`の妥当性を測る材料）。
    pub fn evicted_count(&self) -> u64 {
        self.evicted
    }

    /// 相関相手が居なかった`OperationEnd`の数。
    pub fn unmatched_operation_end_count(&self) -> u64 {
        self.unmatched_operation_ends
    }
}

/// `CreateOptions`から要求されたアクセス種別を推定する。
///
/// 上位8bitの`CreateDisposition`が「作る/上書きする」を意味する場合だけ`ReadWrite`とし、
/// それ以外（`FILE_OPEN`・`FILE_OPEN_IF`等、既存を開くだけ）は**判らないので`Read`**とする。
///
/// **この非対称は片側だけ証明が成立することの反映である**（実測はモジュールdocの表、
/// `disposition_semantics_tests.rs`）。read許可だけの状態でdisposition 4/5/0は必ず拒否されるので、
/// その拒否に対して`fs.read`を提案しても直らないことが**確定している**。逆に disposition 3 は
/// read許可で通ることがあるため、`ReadWrite`へ寄せるとP-03（要求された権限を超えて与えない）に反する。
pub fn access_from_create_options(create_options: u32) -> FsAccess {
    let disposition = (create_options >> 24) & 0xFF;
    match disposition {
        FILE_CREATE | FILE_OVERWRITE | FILE_OVERWRITE_IF => FsAccess::ReadWrite,
        // `FILE_SUPERSEDE`(0)も含めてここへ落ちる。0は「情報が無い」と同じ値なので、
        // 上書き意図として扱わない（上のconst定義のコメント参照）。
        _ => FsAccess::Read,
    }
}

/// ETWが報告するNT形式のパスを、設定ファイルへ書ける形（`C:/...`）へ寄せる。
///
/// 変換できない形（`\Device\HarddiskVolumeN\...`のうちドライブ文字を解決できないもの、
/// 名前付きパイプ等の非ファイルオブジェクト）は`None`を返して**候補にしない**——
/// 設定へ書けないものを提案しても適用できないため（`net-audit.jsonl`のIP-only dropを
/// 提案しないのと同じ判断）。`volume_map`は`\Device\HarddiskVolume3` -> `C:`の対応。
pub fn to_settings_path(nt_path: &str, volume_map: &[(String, String)]) -> Option<String> {
    let path = nt_path.trim();
    if path.is_empty() {
        return None;
    }
    // `\??\C:\x` / `\\?\C:\x` 形式。
    for prefix in [r"\??\", r"\\?\"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            return normalize_dos_path(rest);
        }
    }
    // `\Device\HarddiskVolumeN\x` 形式。
    for (device, drive) in volume_map {
        if let Some(rest) = path.strip_prefix(device.as_str()) {
            if rest.is_empty() || rest.starts_with('\\') {
                return normalize_dos_path(&format!("{drive}{rest}"));
            }
        }
    }
    // 既にDOSパス（`C:\x`）。
    if path.len() >= 3 && path.as_bytes()[1] == b':' {
        return normalize_dos_path(path);
    }
    None
}

fn normalize_dos_path(path: &str) -> Option<String> {
    if path.len() < 2 || path.as_bytes()[1] != b':' {
        return None;
    }
    if !path.as_bytes()[0].is_ascii_alphabetic() {
        return None;
    }
    Some(path.replace('\\', "/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create(name: &str, pid: u32, options: u32) -> PendingCreate {
        PendingCreate {
            file_name: name.to_string(),
            pid,
            create_options: options,
            timestamp_unix_ms: 7,
        }
    }

    /// 相関の基本: `Create`のパスと`OperationEnd`のstatusが1件へ合流する。
    #[test]
    fn create_and_operation_end_correlate_by_irp() {
        let mut correlator = Correlator::new(16);
        correlator.on_create(0xFFFF_1000, create(r"\??\C:\secret.txt", 4242, 0));

        let denial = correlator
            .on_operation_end(0xFFFF_1000, STATUS_ACCESS_DENIED)
            .expect("a denial is produced");

        assert_eq!(denial.file_name, r"\??\C:\secret.txt");
        assert_eq!(denial.pid, 4242);
        assert_eq!(denial.status, STATUS_ACCESS_DENIED);
        assert_eq!(denial.timestamp_unix_ms, 7);
        assert_eq!(correlator.pending_len(), 0, "the entry is consumed");
    }

    /// 成功したCreateは拒否ではないので何も返さないが、相関表からは消える
    /// （消さないと成功したIRPが表を埋め尽くす）。
    #[test]
    fn successful_operations_are_dropped_without_producing_a_denial() {
        let mut correlator = Correlator::new(16);
        correlator.on_create(1, create(r"\??\C:\ok.txt", 1, 0));

        assert!(correlator.on_operation_end(1, 0).is_none());
        assert_eq!(correlator.pending_len(), 0);
    }

    /// `STATUS_ACCESS_DENIED`以外の失敗（`STATUS_OBJECT_NAME_NOT_FOUND`等）は拒否ではない。
    /// 存在しないパスをallowlistへ提案しても意味が無い。
    #[test]
    fn other_failure_statuses_are_not_treated_as_denials() {
        let mut correlator = Correlator::new(16);
        correlator.on_create(1, create(r"\??\C:\missing.txt", 1, 0));

        assert!(correlator
            .on_operation_end(1, 0xC000_0034 /* OBJECT_NAME_NOT_FOUND */)
            .is_none());
    }

    /// 相関する`Create`が無い`OperationEnd`（セッション開始前に始まったIRP・バッファ落ち）は
    /// 黙って無視する。
    #[test]
    fn operation_end_without_a_matching_create_is_ignored() {
        let mut correlator = Correlator::new(16);

        assert!(correlator
            .on_operation_end(0xDEAD, STATUS_ACCESS_DENIED)
            .is_none());
    }

    /// 結果の来ない`Create`が積もっても、容量上限で古いものから捨てて無制限に伸びない。
    #[test]
    fn pending_creates_are_bounded_and_evict_oldest_first() {
        let mut correlator = Correlator::new(3);
        for irp in 1..=5u64 {
            correlator.on_create(irp, create(&format!(r"\??\C:\{irp}.txt"), 1, 0));
        }

        assert_eq!(correlator.pending_len(), 3);
        assert!(
            correlator
                .on_operation_end(1, STATUS_ACCESS_DENIED)
                .is_none(),
            "the oldest entries were evicted"
        );
        let denial = correlator
            .on_operation_end(5, STATUS_ACCESS_DENIED)
            .expect("the newest entry survives");
        assert_eq!(denial.file_name, r"\??\C:\5.txt");
    }

    /// Irpポインタは再利用される。同じIrpで新しい`Create`が来たら新しい方を採る。
    #[test]
    fn a_reused_irp_pointer_replaces_the_previous_entry() {
        let mut correlator = Correlator::new(8);
        correlator.on_create(42, create(r"\??\C:\old.txt", 1, 0));
        correlator.on_create(42, create(r"\??\C:\new.txt", 2, 0));

        assert_eq!(correlator.pending_len(), 1);
        let denial = correlator
            .on_operation_end(42, STATUS_ACCESS_DENIED)
            .unwrap();
        assert_eq!(denial.file_name, r"\??\C:\new.txt");
        assert_eq!(denial.pid, 2);
    }

    /// **P-03**: `CreateDisposition`が「作る/上書きする」でない限り`Read`へ倒す。
    #[test]
    fn access_is_read_unless_the_disposition_clearly_implies_writing() {
        // 下位24bitのCreateOptionsは判定に影響しない。
        assert_eq!(access_from_create_options(0x0000_0060), FsAccess::Read); // FILE_SUPERSEDE(0)
        assert_eq!(access_from_create_options(0x0100_0000), FsAccess::Read); // FILE_OPEN
        assert_eq!(access_from_create_options(0x0300_0060), FsAccess::Read); // FILE_OPEN_IF

        assert_eq!(access_from_create_options(0x0200_0000), FsAccess::ReadWrite); // FILE_CREATE
        assert_eq!(access_from_create_options(0x0400_0000), FsAccess::ReadWrite); // FILE_OVERWRITE
        assert_eq!(access_from_create_options(0x0500_0060), FsAccess::ReadWrite);
        // FILE_OVERWRITE_IF
    }

    /// `FILE_SUPERSEDE`（disposition 0）は意味としては上書きだが、`CreateOptions`が
    /// まるごと0のとき（disposition 0）と区別が付かないため、実際には`Read`側へ倒れる。
    /// この既知の取りこぼしを**テストとして明示**しておく（後から「なぜ拾えないのか」を
    /// 追わなくて済むように）。
    #[test]
    fn zero_create_options_are_indistinguishable_from_file_supersede() {
        assert_eq!(access_from_create_options(0), FsAccess::Read);
    }

    /// record-allモード: 成功した操作も`allowed=true`で返る（deny-onlyモードなら消える件）。
    #[test]
    fn record_all_mode_returns_successful_operations_as_allowed() {
        let mut correlator = Correlator::new(16);
        correlator.on_create(1, create(r"\??\C:\ok.txt", 7, 0));

        let record = correlator
            .on_operation_end_any(1, 0)
            .expect("record-all mode returns successes too");

        assert_eq!(record.file_name, r"\??\C:\ok.txt");
        assert_eq!(record.pid, 7);
        assert_eq!(record.status, 0);
        assert!(record.allowed);
        assert_eq!(correlator.pending_len(), 0);
    }

    /// record-allモード: 拒否は`allowed=false`で返り、statusは維持される。
    #[test]
    fn record_all_mode_returns_denials_as_not_allowed() {
        let mut correlator = Correlator::new(16);
        correlator.on_create(1, create(r"\??\C:\secret.txt", 4242, 0x0200_0000));

        let record = correlator
            .on_operation_end_any(1, STATUS_ACCESS_DENIED)
            .expect("a record is produced");

        assert_eq!(record.file_name, r"\??\C:\secret.txt");
        assert_eq!(record.pid, 4242);
        assert_eq!(record.status, STATUS_ACCESS_DENIED);
        assert!(!record.allowed);
        assert_eq!(record.access, FsAccess::ReadWrite);
    }

    /// record-allモードでも、相関する`Create`が無い`OperationEnd`は黙って無視する
    /// （deny-onlyモードと同じ下回りを共有しているため）。
    #[test]
    fn record_all_mode_ignores_operation_end_without_a_matching_create() {
        let mut correlator = Correlator::new(16);

        assert!(correlator.on_operation_end_any(0xDEAD, 0).is_none());
        assert_eq!(correlator.unmatched_operation_end_count(), 1);
    }

    /// record-allモードでも容量上限は共有される（古いCreateから捨てる）。
    #[test]
    fn record_all_mode_shares_the_same_capacity_bound_as_deny_only() {
        let mut correlator = Correlator::new(3);
        for irp in 1..=5u64 {
            correlator.on_create(irp, create(&format!(r"\??\C:\{irp}.txt"), 1, 0));
        }

        assert_eq!(correlator.pending_len(), 3);
        assert!(correlator.on_operation_end_any(1, 0).is_none());
        let record = correlator
            .on_operation_end_any(5, 0)
            .expect("the newest entry survives");
        assert_eq!(record.file_name, r"\??\C:\5.txt");
    }

    /// deny-onlyとrecord-allは同じ相関表を共有できる——record-allで一度取り出したIrpを
    /// deny-onlyで再度問い合わせても、既に消費済みなので`None`になる（二重計上しない）。
    #[test]
    fn a_record_consumed_by_one_mode_is_not_double_counted_by_the_other() {
        let mut correlator = Correlator::new(16);
        correlator.on_create(1, create(r"\??\C:\x.txt", 1, 0));

        assert!(correlator
            .on_operation_end_any(1, STATUS_ACCESS_DENIED)
            .is_some());
        assert!(correlator
            .on_operation_end(1, STATUS_ACCESS_DENIED)
            .is_none());
    }

    /// NTパスは設定へ書ける`C:/...`形式へ寄せる。
    #[test]
    fn nt_paths_are_converted_to_settings_paths() {
        let volumes = vec![(r"\Device\HarddiskVolume3".to_string(), "C:".to_string())];

        assert_eq!(
            to_settings_path(r"\??\C:\Users\me\x.txt", &volumes).as_deref(),
            Some("C:/Users/me/x.txt")
        );
        assert_eq!(
            to_settings_path(r"\\?\D:\data", &volumes).as_deref(),
            Some("D:/data")
        );
        assert_eq!(
            to_settings_path(r"\Device\HarddiskVolume3\Users\me\x.txt", &volumes).as_deref(),
            Some("C:/Users/me/x.txt")
        );
        assert_eq!(
            to_settings_path(r"C:\already\dos", &volumes).as_deref(),
            Some("C:/already/dos")
        );
    }

    /// 設定へ書けない形は候補にしない（名前付きパイプ・未知のボリューム）。
    #[test]
    fn unconvertible_nt_paths_are_dropped_instead_of_guessed() {
        let volumes = vec![(r"\Device\HarddiskVolume3".to_string(), "C:".to_string())];

        assert_eq!(to_settings_path(r"\Device\NamedPipe\foo", &volumes), None);
        assert_eq!(
            to_settings_path(r"\Device\HarddiskVolume9\x", &volumes),
            None
        );
        assert_eq!(to_settings_path("", &volumes), None);
        // `\Device\HarddiskVolume30`が`\Device\HarddiskVolume3`の接頭辞一致で
        // 誤って`C:0`にならないこと。
        assert_eq!(
            to_settings_path(r"\Device\HarddiskVolume30\x", &volumes),
            None
        );
    }
}
