//! `process-audit.jsonl`の1行分レコード——**記録したプロセスの木**
//! （`plans/PLAN-MAC-RECURSIVE-DESCENDANTS.md`決定23、転記先は`plans/DESIGN-MAC-TRANSITION-POLICY.md`
//! §19.3.13。親の番号の取り方は`plans/POLICY-EDITOR-TOMOYO-DIG.md`の「決定65の追記」）。
//!
//! **書く側は昇格した収集プロセス**（`harness-sandbox`の`tier2a::policy_learnd`。ポリシーエディタの
//! パス1＝引数の観測を張った記録でだけ書く）、**読む側は非特権のポリシーエディタ**である。
//! [`crate::event`]と同じ理由で、型の定義はここだけに置く——書く側と読む側に別々の型があると、
//! 片側だけ形が変わっても誰も気付かないまま静かに読み違える。
//!
//! # 1行が表すもの
//!
//! 1行は「**どのプロセスのインスタンスが、どのインスタンスから、どの実行ファイルとコマンドラインで
//! 起きたか**」である（[`ProcessInstance`]）。ポリシーエディタはこれだけで「記録した木の位置」を組み、
//! 位置ごとに遷移先のドメインを提案する（決定65(1)）。
//!
//! # なぜ`fs-audit.jsonl`へ混ぜないのか
//!
//! FS監査の1行は「1件のアクセス」を表し、`path`・`access`・`allowed`が意味を持つ。プロセスの
//! インスタンスにはどれも意味が無く、混ぜると集計の数（観測件数・許可・拒否）が汚れる（決定23(1)）。
//! FS監査の行は、どのインスタンスのアクセスかを[`crate::event::FsAuditEvent::process_sequence_number`]で
//! 指す（決定23(6)）。
//!
//! # 同一性は`seq`（`ProcessSequenceNumber`）であって pid ではない
//!
//! pid は使い回される（実測で403のpidのうち153に2回以上の実起動、`plans/etw-spike/RESULTS.md` §23.1）。
//! **読む側は pid で親を引き直さない**——親は[`ProcessInstance::parent_seq`]だけで引く
//! （決定65の追記(3)。後から引く pid の表は使い回しの下で誤る、§24.3 の A4 で 32/600）。
//!
//! カーネルが持つ別の識別子（MOF の`UniqueProcessKey`）は**載せない**——601件の実起動に9種類しか
//! 現れず（§23.1）、載せると誰かが鍵に使う。
//!
//! # 作業ディレクトリは「観測していない」
//!
//! ETWの通知に作業ディレクトリの欄が無いので、この記録は作業ディレクトリを持てない。
//! **これは「制御していない」ではない**——強制側（Spawn Daemon）は宣言値を渡し、実際の値が違えば
//! 拒否する（`plans/DESIGN-MAC-ENFORCEMENT.md` §8.3）。欠けているのは候補を作る材料だけである
//! （P-11の書き分け）。
//!
//! # 版
//!
//! 1行目は[`ProcessAuditRecord::Header`]で、[`PROCESS_AUDIT_SCHEMA_VERSION`]を名乗る。
//! 読む側（[`parse_process_audit`]）は**知らない新しい版を、知っている形として読まない**
//! （`policy.json`の`FutureSchema`・エディタの`transition_dismissed`の`UnsupportedVersion`と同じ姿勢）。
//! 欄を足すだけで古い読み手が困らないなら版は上げない（`#[serde(default)]`で足す）。

use serde::{Deserialize, Serialize};

/// 収集プロセスが書くファイルの名前。`fs-audit.jsonl`と同じ記録のディレクトリに置く（決定23(1)）。
///
/// **書く側（収集プロセス）・先に作る側（非昇格の依頼側。BUG-109）・読む側（エディタ）・
/// fork で持っていかない一覧（`harness-sandbox`の`session_scope`）がこの1つを参照する**
/// ——綴りを写すと片方だけ変わる（`bug-pattern-rules` B-05）。
pub const PROCESS_AUDIT_FILE: &str = "process-audit.jsonl";

/// この形の版。欄の意味を変えたら上げる。
pub const PROCESS_AUDIT_SCHEMA_VERSION: u32 = 1;

/// `process-audit.jsonl`の1行。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProcessAuditRecord {
    /// 1行目。この行が無い・読めないファイルは読まない（[`parse_process_audit`]）。
    Header { schema_version: u32 },
    /// プロセスのインスタンス1つ。
    Instance(ProcessInstance),
    /// 収集プロセス自身の状態と歩留まり（結び付いた件数・取りこぼした件数）。**木の節点にはならない**
    /// （`FsAuditEvent::control`・D-43 と同じ作法。自分の統計は自分のファイルへ、決定23(4)）。
    Control {
        reason: String,
        timestamp_unix_ms: u64,
    },
}

impl ProcessAuditRecord {
    /// JSONL 1行へ直列化する（末尾改行は含めない）。
    pub fn to_jsonl_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// プロセスのインスタンス1つ（決定23(2)。決定との違いは`plans/position-domains/P2.md`
/// 「決定23 との対応と、食い違うところ」）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInstance {
    /// **同一性。** マニフェスト側（`Microsoft-Windows-Kernel-Process`）の`ProcessStart`の
    /// `ProcessSequenceNumber`。この欄を持てない版（v0〜v2）のインスタンスは書かれない。
    pub seq: u64,
    /// 親のインスタンスの`seq`。**ETWの`ParentProcessSequenceNumber`の欄そのもの**で、pid から
    /// 引き直したものではない（決定65の追記(1)）。欄が無い・0 のときは`None`（出どころは
    /// [`ParentSeqSource::Unresolved`]）。
    ///
    /// **番号があっても、その親のインスタンスが記録に在るとは限らない**——記録の根の親
    /// （記録を始める前から居たプロセス）や、開始を取りこぼした親は記録に無い。読む側は
    /// それを「親を引けない子」として数える（決定65の追記(2)）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_seq: Option<u64>,
    /// `parent_seq`の出どころ（決定65の追記(2)）。
    pub parent_seq_source: ParentSeqSource,
    /// 表示と、古い記録との突き合わせ用。**同一性には使わない。**
    pub pid: u32,
    /// 同上（ETWの`ParentProcessID`）。親を引く鍵には使わない。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u32>,
    /// 実行ファイルの**フルパス**を設定の綴り（`C:/…`）へ寄せたもの。マニフェスト側の`ImageName`
    /// から取る（MOF側の`ImageFileName`は葉の名前しか持たない）。寄せられなかった（未知のボリューム）
    /// ときは`None`——**生のNTパスを載せない**（読む側で「宣言へ書ける値」と誤解されるため）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_path: Option<String>,
    /// コマンドラインを結び付けた結果（MOF側の`CommandLine`）。
    pub argv: ArgvBinding,
    /// **記録の根**（親が harness 本体、またはSpawn Daemon）か。根の辺は観測から作らず、起動する
    /// 当のコードから合成する（§19.3.12）ので、読む側はこの印で根を見分ける。判定は収集プロセスの
    /// スコープ判定（`ScopeTracker`）が持つ式と同じもの（決定23(2)）。
    pub is_scope_root: bool,
    /// `ProcessStart`の時刻（Unixミリ秒）。既存の2つの記録と同じ単位。**生の100ns値は書かない**
    /// ——結び付けは収集プロセスの中で済んでおり、読む側に並べ替え直させない（決定23(2)）。
    pub timestamp_unix_ms: u64,
}

/// [`ProcessInstance::parent_seq`]の出どころ（決定65の追記(2)）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParentSeqSource {
    /// ETWの`ProcessStart`の`ParentProcessSequenceNumber`から取った（実測で親の段の番号と
    /// 60/60・本当の親と 600/600 一致、`plans/etw-spike/RESULTS.md` §24.3）。
    EtwField,
    /// 欄が無い（`ProcessStart` v0〜v2）か 0 だった。**親を決めない**——位置の割り当てでは
    /// どの位置にも引かず、件数と理由を出す（決定65の追記(2)・細目4）。
    Unresolved,
}

impl ParentSeqSource {
    /// ETWの欄の値から、記録に書く親の番号と出どころを決める。
    ///
    /// **0 は「無い」と同じに扱う。** 0 を番号として書くと、読む側はそれを本物の親の番号として
    /// 引いてしまう。
    pub fn from_etw_field(field: Option<u64>) -> (Option<u64>, ParentSeqSource) {
        match field {
            Some(seq) if seq != 0 => (Some(seq), ParentSeqSource::EtwField),
            _ => (None, ParentSeqSource::Unresolved),
        }
    }
}

/// コマンドラインを、マニフェスト側のインスタンスへ結び付けた結果。
///
/// 結び付けは収集プロセスの中で閉じる——「pid が同じで、開始の時刻の差が 2ms 以内」の候補が
/// ちょうど1つのときだけ結び付ける（決定65の追記(4)）。**曖昧なときは結び付けない**
/// （誤った細分化をしない、§19.3.11）。
///
/// **コマンドラインと切り詰めの判定は`Exact`の中にしか無い**——「結び付かなかったのに
/// コマンドラインがある」「結び付かなかったのに切り詰めの疑いがある」は書けない。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ArgvBinding {
    /// ちょうど1つの候補と結び付いた。
    Exact {
        /// **畳み込み前の生の文字列**（起こした側が`CreateProcess`へ渡した綴りのまま）。
        /// 比べるときの畳み込みは編集時に行う（`fold_for_comparison`、決定21）。
        command_line: String,
        /// 1,024 UTF-16単位で切られた疑い。**収集プロセスが UTF-16 のまま判定した結果**で、
        /// 読む側は`command_line`から判定し直せない（`String`へ落とすと対にならないサロゲートが
        /// 置換文字へ潰れて痕跡が消える、§23.3）。
        truncation: ArgvTruncation,
    },
    /// 結び付かなかった。**記録を捨てない**——インスタンスは木の節点として残り、理由を持つ
    /// （捨てると「そのコマンドは走らなかった」と区別が付かなくなる、§19.3.11）。
    Missing { reason: ArgvMissingReason },
}

/// コマンドラインが切り詰められているか（1,024 UTF-16単位、`plans/etw-spike/RESULTS.md` §23.3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgvTruncation {
    /// 1,024単位ちょうどではない（切られていない）。
    None,
    /// 1,024単位ちょうど。たまたまその長さだったのか切られたのか区別できない
    /// ——**リテラルの辺の候補にしない**（`plans/DESIGN-MAC.md` §5.1(6)）。
    Suspected,
    /// 1,024単位ちょうどで、末尾が対にならない高位サロゲート。**確実に切られている。**
    Certain,
}

/// コマンドラインが結び付かなかった理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgvMissingReason {
    /// 待っても MOF 側の開始が来なかった（取りこぼし・配送の遅れが持ち越しを超えた）。
    NoArgvObserved,
    /// 時刻の窓の中に、同じ pid の候補が2つ以上あった。どれの引数か決めない（§19.3.11）。
    AmbiguousWithinWindow,
    /// MOF 側の開始とは結び付いたが、コマンドラインの欄が無かった（古い版の`Process`クラス）。
    NoCommandLineField,
}

/// [`parse_process_audit`]が読み出したもの。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessAuditLog {
    pub instances: Vec<ProcessInstance>,
    /// 制御の行の`reason`（書かれた順）。
    pub controls: Vec<String>,
    /// 読めなかった完全な行の数。**黙って捨てずに数える**（書きかけの最後の行は数えない）。
    pub skipped_lines: usize,
}

/// `process-audit.jsonl`を読めなかった理由。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProcessAuditError {
    #[error(
        "process-audit.jsonl が版の行で始まっていません（先頭の行: {first_line}）。\
         どの版の形か分からないので読みません"
    )]
    MissingHeader { first_line: String },
    #[error(
        "process-audit.jsonl の版 {found} はこのバイナリ（対応版 {supported}）より新しいものです。\
         新しい harness-policy-editor で開いてください"
    )]
    FutureSchema { found: u32, supported: u32 },
}

/// `process-audit.jsonl`の中身を読む（**ファイルは読まない**。読み込み済みの文字列を受け取る——
/// このクレートの純粋性、`lib.rs`のモジュールdoc）。
///
/// - **最後の改行より後（書きかけの行）は読まない**（`harness-sandbox`の`transitions_log::read_folded`と
///   同じ扱い。収集プロセスが書いている最中に読むことがある）
/// - 完全な行が1つも無ければ空の`Ok`（依頼側が先に作った空のファイル＝記録が始まらなかった）
/// - 最初の空でない完全な行が[`ProcessAuditRecord::Header`]として読めなければ
///   [`ProcessAuditError::MissingHeader`]
/// - 版の行は**どれも**確かめ、[`PROCESS_AUDIT_SCHEMA_VERSION`]より新しければ
///   [`ProcessAuditError::FutureSchema`]
/// - 読めない完全な行は[`ProcessAuditLog::skipped_lines`]に数える
pub fn parse_process_audit(text: &str) -> Result<ProcessAuditLog, ProcessAuditError> {
    let complete = match text.rfind('\n') {
        Some(index) => &text[..=index],
        None => "",
    };
    let mut log = ProcessAuditLog::default();
    let mut header_seen = false;
    for line in complete.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parsed = serde_json::from_str::<ProcessAuditRecord>(line);
        if !header_seen {
            match parsed {
                Ok(ProcessAuditRecord::Header { schema_version }) => {
                    refuse_future(schema_version)?;
                    header_seen = true;
                    continue;
                }
                _ => {
                    return Err(ProcessAuditError::MissingHeader {
                        first_line: line.chars().take(80).collect(),
                    })
                }
            }
        }
        match parsed {
            Ok(ProcessAuditRecord::Header { schema_version }) => refuse_future(schema_version)?,
            Ok(ProcessAuditRecord::Instance(instance)) => log.instances.push(instance),
            Ok(ProcessAuditRecord::Control { reason, .. }) => log.controls.push(reason),
            Err(_) => log.skipped_lines += 1,
        }
    }
    Ok(log)
}

fn refuse_future(schema_version: u32) -> Result<(), ProcessAuditError> {
    if schema_version > PROCESS_AUDIT_SCHEMA_VERSION {
        return Err(ProcessAuditError::FutureSchema {
            found: schema_version,
            supported: PROCESS_AUDIT_SCHEMA_VERSION,
        });
    }
    Ok(())
}

#[cfg(test)]
#[path = "process_event_tests.rs"]
mod process_event_tests;
