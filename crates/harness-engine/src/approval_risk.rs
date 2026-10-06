//! 承認画面の危険度（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` D-100 の追記）を組み立てる。
//!
//! # 何のためにあるのか
//!
//! 承認画面は、人が「このコマンドを走らせてよいか」を決めるための道具である。画面には**「危険度: 要確認」
//! 「危険度: 中」「危険度: 高」**のどれかを出し、中と高のときは理由を並べる。**「要確認」は安全という意味ではない**——
//! 見つけた危険が無かった、というだけで、人が中身を確かめることに変わりはない（「低」「安全」と書かないのはそのため）。
//! **「中」も安全ではない**——字面で場所を見る機械が被害を見つけ、中身を読む判定モデルが低いと言った、
//! つまり**性質の違う2つの判定が食い違った**ことを表す（D-100 の 2026-10-06 追記）。
//!
//! # 流れ
//!
//! ```text
//! ① 機械の判定（machine。すぐ終わり、ネットワークを使わず、いつも動く）
//!    行・解読した各段・縛ったスクリプトの中身に、システムへの被害の判定（harness-tools の system_damage）を掛ける
//! ② 判定モデル（Ollaya。設定で有効なときだけ）に2回を同時に聞く（harness-core の decision の「測った2つの形」）
//!    ・危険度だけ                  → コマンドの危険度
//!    ・流れと一緒に4問              → 解読が要るか・ファイルからコードを読むか・流れと合わせた危険度
//!    この2つの危険度は保留し、③で行が「解けた包み」と分かれば数えない（D-126。下）
//! ③ 必要なときだけ追加で聞く
//!    ・「解読が要る」と出たのに機械の解読が何も取れていなければ、LLM に場所を選ばせてハーネスが解読する（encoded_span）
//!    ・解読できた各段（機械の解読・LLM が場所を示したもの）の中身を、機械の判定と判定モデルに通す
//!      （「解けた包み」の途中の段は判定モデルへ聞かない。D-126）
//!    ・ファイルからコードを読む（または run_program でコードを走らせる）なら、縛ったファイルの中身の危険度
//! ④ 段階を決める（[`RiskOutcome::severity`]。D-100 の 2026-10-06 追記）
//!    ・判定モデルが高（行・流れ・解いた段・ファイルのどれか）、または解析しきれない難読化（D-124） → 「高」
//!    ・機械だけが高で、機械が引っ掛けた材料を判定モデルが全部読んだうえで低い                  → 「中」
//!    ・機械だけが高で、判定モデルを使えない・読んでいない材料に引っ掛けた                      → 「高」
//!    ・どれも見つけない                                                                      → 「要確認」
//! ```
//!
//! **「読んだうえで低い」に限る。** 上限（[`MAX_DECODED_TO_ASK`]・[`MAX_FILES_TO_ASK`]）で聞いていない材料、
//! D-126 で点数を数えない行・段、呼び出しが失敗した材料に機械が引っ掛けたときは中へ下げない——読んでいないものを
//! 根拠に下げない（D-124 と同じ向き）。材料は出どころ（[`Origin`]）でなく**位置**で数える（同じ深さの兄弟の段は
//! 同じ`Origin`になるので、出どころでは「どの段を読んだか」を区別できない）。
//!
//! 判定モデルが無い・落ちているときは①だけで決め、画面には「機械判定のみ」と添える（[`RiskBasis`]）。
//!
//! **解けた包み**（D-126）は、中で見つけた塊（直下の段）が1つ以上あり、全部が文字として解けた文字列（行か段）。
//! 符号化した塊を含む文字列への判定モデルの点数は中身でなく外側の綴りに反応する（無害で 1.20〜1.55、危険で
//! 0.82〜1.58。`plans/risk-judge-spike/RESULTS.md` §1.10）ので、その点数は数えず、解いた段への点数と機械の判定で決める。
//! 解けない塊が1つでも混じれば、今どおり数える。縛ったファイルの中で見つけた段は、行を解けた包みにしない。
//!
//! # これは境界ではない
//!
//! 通す・止めるは決めない。聞くか聞かないかは判定器（`PermissionArbiter`）のままで、ここは画面の表示と、
//! 要約への固定の一言にだけ使う。判定モデルは攻撃者が書いたかもしれない入力を読むので曲げられ得るし、
//! 機械の判定は字面しか見ない（`system_damage`のモジュールdoc）。**だから「高」が出ないことは安全を意味しない。**
//! 記録済みで自動で通る行には承認画面が出ないので、ここも動かない。
//!
//! # 限界（同じ場所で言う）
//!
//! - 判定モデルが拾えないものがある（`plans/risk-judge-spike/RESULTS.md` §1）——流れの危険は陽性6組のうち2組、
//!   ソースコードは埋もれた1行を見落とす。機械の判定は字面に出ない場所を読めない
//! - 判定モデルへ送るソースコードは先頭[`harness_core::MAX_SOURCE_CHARS`]字だけ。機械の判定はファイル全体を見る
//! - 解読が要りそうなのに、機械の解読も LLM が示した箇所の解読も何も取れなかったときは、注記を出すだけである
//!   （LLM が場所を示さなかった・示した文字列が行に無かった・示された符号化として読めなかった）
//! - 解けた包みの行では、塊の**外**にある平文を判定モデルが読まない（D-126）。システムの場所への被害は
//!   機械の判定が拾う（判定モデルが読んでいないので中へは下げず高）が、それ以外は要確認に落ちる
//! - 「中」は判定モデルの低い点数で機械の高を下げたものなので、判定モデルが曲げられれば中に見える
//!   （だから要確認までは下げず、黄で残す）。判定モデルを待つ間は機械の判定だけで出すので、高から中へ変わり得る

use std::collections::BTreeSet;

use async_trait::async_trait;
use futures::future::join;
use harness_core::decision::questions;
use harness_core::{
    assess_command_risk, assess_source_risk, command_context_state, context_questions,
    DecisionModel, DecodeOutcome, DecodedLayer, FilePreview, PermissionSubject, RiskLevel,
    RiskVerdict,
};
use harness_tools::system_damage::{self, DamageFinding};

use crate::encoded_span::SpanLocator;

/// 判定モデル（Ollaya）が使えないときの、重い LLM による危険度判定（D-125）。
///
/// # 何のためにあるのか
///
/// Ollaya（速い専用の判定サーバ）が落ちているとき、機械の判定は字面しか読めず、解読器が字面で見つけ
/// られる難読化も base64 系に限られる（文字コードの並び・hex・base32 等は見つけられない）。そこで、
/// 要約や解読箇所の特定に使っている LMStudio の LLM に、コマンドの危険度を判定させる段を1つ挟む。
/// Ollaya → **この LLM 判定** → 機械判定＋ハッシュ（fail-closed）の3段フォールバックの真ん中。
///
/// # 限界
///
/// LLM の呼び出しは重い（要約と同じ程度）。だから**設定で飛ばせる**（`approval.use_llm_fallback`）。
/// **本実装（実際に LMStudio を呼んで JSON の危険度を返させる `LlmFallbackJudge`）は後回しで、今は
/// [`MockFallbackJudge`] が入っている**（常に判定しないので、挙動は3段目の機械判定と同じ）。本実装は
/// 認知レイヤーの設計（`plans/DESIGN-COGNITION.md`）に置く。
#[async_trait]
pub trait FallbackJudge: Send + Sync {
    /// コマンドの行を判定する。判定できなければ `Ok(None)`（3段目の機械判定へ落ちる）。
    async fn judge(&self, line: &str) -> Result<Option<RiskVerdict>, String>;
}

/// LLM フォールバック判定の土台のモック（D-125）。常に `Ok(None)`（判定しない）を返す。
///
/// **本実装が入るまでの暫定。** `LlmFallbackJudge`（LMStudio を呼ぶ）に差し替わったら、この型は消す。
/// モックは判定しないので、これを入れても挙動は機械判定（fail-closed）と変わらない——土台（trait・配線・
/// 設定）だけが先に入る。
pub struct MockFallbackJudge;

#[async_trait]
impl FallbackJudge for MockFallbackJudge {
    async fn judge(&self, _line: &str) -> Result<Option<RiskVerdict>, String> {
        Ok(None)
    }
}

/// 解読できた段のうち、判定モデルへ危険度を聞く数の上限（段ごとに1回の呼び出し、約1秒）。
pub const MAX_DECODED_TO_ASK: usize = 4;
/// 縛ったファイルのうち、判定モデルへ中身の危険度を聞く数の上限（長さに比例して遅い。4,000字で約12秒）。
pub const MAX_FILES_TO_ASK: usize = 3;

/// 画面に出す危険度の段階（決め方は[`RiskOutcome::severity`]）。
///
/// **中はここにだけ置き、判定モデルの点数の段階（[`RiskLevel`]）には足さない。** 点数で引く黄の帯は、無害な行と
/// 危険な行の点数が重なるので外した（`harness_core::risk_check`の`RiskLevel`の doc）。中は帯ではなく、
/// 2つの判定の食い違いである（D-100 の 2026-10-06 追記）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// 見つけた危険は無い。**安全という意味ではない**（人が中身を確かめる）。
    NeedsReview,
    /// 機械の判定は被害を見つけたが、機械が引っ掛けた材料を判定モデルが全部読んだうえで低いと見た。
    /// **安全という意味ではない**（判定モデルは曲げられ得る）。
    Medium,
    /// 判定モデルが危険と見た・解析しきれない難読化がある・機械が被害を見つけて判定モデルがそれを読んでいない。
    High,
}

impl Severity {
    pub fn label_ja(self) -> &'static str {
        match self {
            Severity::NeedsReview => "要確認",
            Severity::Medium => "中",
            Severity::High => "高",
        }
    }

    /// 要約へ渡す段階（高のときだけ、固定の英文1行。[`RiskLevel::summary_instruction`]）。
    /// **中は何も足さない**（判定モデルの低いと同じ扱い。D-100 の 2026-10-06 追記）。
    pub fn summary_hint(self) -> Option<RiskLevel> {
        match self {
            Severity::High => Some(RiskLevel::Danger),
            Severity::Medium | Severity::NeedsReview => None,
        }
    }
}

/// どこを見て危険と判定したか。
#[derive(Debug, Clone, PartialEq)]
pub enum Origin {
    /// コマンドの行そのもの（`run_program`はプログラムと引数）。
    Command,
    /// ハーネスが解読した段の中身。
    Decoded { depth: u32 },
    /// 縛ったファイルの中身。
    File { path: String },
}

impl Origin {
    fn suffix_ja(&self) -> String {
        match self {
            Origin::Command => String::new(),
            Origin::Decoded { depth } => format!("（解読した{depth}段目の中）"),
            Origin::File { path } => format!("（{path} の中）"),
        }
    }
}

/// 「中」「高」の理由1つ。
#[derive(Debug, Clone, PartialEq)]
pub enum RiskReason {
    /// 機械の判定（システムへの被害）。
    Damage {
        finding: DamageFinding,
        origin: Origin,
    },
    /// 判定モデルの危険度（[`harness_core::risk_check::DANGER_FROM`]以上）。
    Model {
        verdict: RiskVerdict,
        origin: Origin,
    },
    /// 判定モデルの、これまでの流れと合わせた危険度。
    Sequence(RiskVerdict),
    /// 難読化された中身を安全と確かめられなかった（fail-closed。D-124）。解析しきれないものは
    /// 危険側へ倒す——**確かめられなかっただけで、危険と判明したわけではない**（境界ではない）。
    OpaqueObfuscation(ObfuscationCause),
}

/// 難読化を解析しきれなかった理由（D-124）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfuscationCause {
    /// 判定モデル（Ollaya）が使えないのに、**解読できない**難読化された中身がある。機械でも中身を読めず、
    /// 判定モデルも無いので、安全かを確かめる手段が無い。解読できた段は機械が読むので、ここには当たらない。
    ModelUnavailable,
    /// 解読の上限に達し、その先にまだ難読化が残っている（底まで解けていない）。一番下で何が走るかを
    /// 見ていない。
    DepthLimited,
}

impl RiskReason {
    /// 画面に出す一文。**判定モデルが返した文字列は使わない**（数値と、こちらの固定の言い回しだけ）。
    pub fn describe_ja(&self) -> String {
        match self {
            RiskReason::Damage { finding, origin } => {
                format!("機械判定: {}{}", finding.describe_ja(), origin.suffix_ja())
            }
            RiskReason::Model { verdict, origin } => format!(
                "判定モデル: {:.2} / 2（{}）{}",
                verdict.score,
                verdict.level.reason_ja(),
                origin.suffix_ja()
            ),
            RiskReason::Sequence(verdict) => format!(
                "これまでの流れと合わせると: {:.2} / 2（{}）",
                verdict.score,
                verdict.level.reason_ja()
            ),
            RiskReason::OpaqueObfuscation(cause) => match cause {
                ObfuscationCause::ModelUnavailable => {
                    "難読化された中身があるが、判定モデルを使えないので安全と確かめられない".to_string()
                }
                ObfuscationCause::DepthLimited => {
                    "解読の上限に達し、その先にまだ難読化が残っている（底まで解けていない）".to_string()
                }
            },
        }
    }
}

/// 「高」ではないが、見る人に知らせること。
#[derive(Debug, Clone, PartialEq)]
pub enum RiskNote {
    /// 判定モデルが答えなかった（理由）。この分は機械の判定だけで決めている。
    ModelUnavailable(String),
    /// ファイルの中身の先頭だけを判定モデルへ送った（長いファイル）。
    FileCut { path: String },
    /// 解読が要りそうな中身があるが、ハーネスは何も解読できていない。
    UndecodedPayload { probability: f32 },
    /// ファイルからコードを読みそうだが、読む先のファイルを縛れていない（中身を見ていない）。
    UnboundSource { probability: f32 },
}

impl RiskNote {
    pub fn describe_ja(&self) -> String {
        match self {
            RiskNote::ModelUnavailable(reason) => format!("判定モデルを使えなかった理由: {reason}"),
            RiskNote::FileCut { path } => {
                format!("{path} は長いので、判定モデルへは先頭だけを送った（機械の判定は全体を見た）")
            }
            RiskNote::UndecodedPayload { probability } => format!(
                "解読しないと何が走るか分からない中身がありそうだが、ハーネスは解読できていない（判定モデル {:.2}）",
                probability
            ),
            RiskNote::UnboundSource { probability } => format!(
                "ファイルから読んだコードを走らせそうだが、そのファイルの中身を確かめていない（判定モデル {:.2}）",
                probability
            ),
        }
    }
}

/// 判定に何を使ったか。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskBasis {
    /// 機械の判定だけ（判定モデルも LLM フォールバックも使えなかった）。
    MachineOnly,
    /// 判定モデル（Ollaya）も使った。
    WithModel,
    /// 判定モデルが使えず、LLM フォールバック判定（LMStudio）で決めた（D-125）。
    WithFallback,
}

/// 組み立てた結果。
#[derive(Debug, Clone, PartialEq)]
pub struct RiskOutcome {
    /// 「中」「高」の理由。空なら「要確認」。段階は[`RiskOutcome::severity`]が決める。
    pub reasons: Vec<RiskReason>,
    pub notes: Vec<RiskNote>,
    pub basis: RiskBasis,
    /// LLM が場所を示し、ハーネスが解読した段（[`crate::encoded_span`]）。承認画面と要約に、
    /// 機械の解読（材料の`decoded`）と並べて出す。**表示と要約・判定のためだけで、照合に使わない。**
    pub extra_decoded: Vec<DecodedLayer>,
    /// 数えた判定モデルの点数のうち最大のもの（線より下でも残す。「中」の行に出す）。D-126 で数えない
    /// 行・流れ・途中の段の点数は入らない。判定モデルを使っていなければ`None`。
    pub model_peak: Option<RiskVerdict>,
    /// 機械が被害を見つけた材料のうち、判定モデルの点数を数えていないものがある（上限で聞いていない・
    /// D-126 で数えない・呼び出しが失敗した）。立っていれば機械の高を中へ下げない。
    pub unjudged_damage: bool,
}

/// 機械の判定・判定モデルが見た材料1つ。**位置で区別する**——同じ深さの兄弟の段は出どころ（[`Origin`]）が
/// 同じになるので、出どころでは「判定モデルがどの段を読んだか」を数えられない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Material {
    /// コマンドの行そのもの。
    Line,
    /// 機械の解読（材料の`decoded`）の位置。
    Layer(usize),
    /// LLM が場所を示して解読した段（`extra_decoded`）の位置。
    Extra(usize),
    /// 縛ったファイル（材料の`previews`）の位置。判定モデルへは並べ替えてから聞くが、元の位置で数える。
    Preview(usize),
}

impl RiskOutcome {
    /// 段階（D-100 の 2026-10-06 追記）。判定モデルが高・解析しきれない難読化 → 高。機械だけが高なら、
    /// 判定モデルを使えて、機械が引っ掛けた材料を全部読んでいるときだけ中、そうでなければ高。何も無ければ要確認。
    pub fn severity(&self) -> Severity {
        let mut damage = false;
        for reason in &self.reasons {
            match reason {
                RiskReason::Model { .. }
                | RiskReason::Sequence(_)
                | RiskReason::OpaqueObfuscation(_) => return Severity::High,
                RiskReason::Damage { .. } => damage = true,
            }
        }
        match damage {
            false => Severity::NeedsReview,
            true if self.basis != RiskBasis::MachineOnly && !self.unjudged_damage => {
                Severity::Medium
            }
            true => Severity::High,
        }
    }

    /// 「中」のときだけ、判定モデルの点数の最大を1行で言う。**固定の言い回しと数値だけ**で、判定モデルが返した
    /// 文字列は使わない。「安全」とは書かない。
    pub fn model_low_ja(&self) -> Option<String> {
        if self.severity() != Severity::Medium {
            return None;
        }
        let peak = self.model_peak?;
        Some(format!(
            "判定モデル: 最大 {:.2} / 2（{}）——機械の判定と食い違うので「中」",
            peak.score,
            peak.level.reason_ja()
        ))
    }

    /// 判定モデルを使えなかった理由（あれば）。会話の記録へ1回だけ書くのに使う。
    pub fn model_error(&self) -> Option<&str> {
        self.notes.iter().find_map(|n| match n {
            RiskNote::ModelUnavailable(reason) => Some(reason.as_str()),
            _ => None,
        })
    }

    fn push_reason(&mut self, reason: RiskReason) {
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }

    fn note_model_error(&mut self, reason: String) {
        if self.model_error().is_none() {
            self.notes.push(RiskNote::ModelUnavailable(reason));
        }
    }

    /// 数えた判定モデルの点数を最大へ入れる（理由にするかは呼び出し側）。
    fn note_peak(&mut self, verdict: RiskVerdict) {
        if self
            .model_peak
            .is_none_or(|peak| verdict.score > peak.score)
        {
            self.model_peak = Some(verdict);
        }
    }

    /// 材料1つへの判定モデルの点数を数える——最大へ入れ、線を越えていれば理由にする。
    fn count_model(&mut self, verdict: RiskVerdict, origin: Origin) {
        self.note_peak(verdict);
        if verdict.level == RiskLevel::Danger {
            self.push_reason(RiskReason::Model { verdict, origin });
        }
    }

    /// 難読化を解析しきれなかったときは、危険側へ倒す（fail-closed。D-124）。**判定の最後に1回だけ呼ぶ。**
    ///
    /// `basis` が確定した後に掛ける——判定モデルが**待ち**の段階（機械の判定だけを先に出している間）では
    /// 呼ばない。待ちは「使えない」ではないので、ここで倒すと待っている間だけ高に見えてしまう。
    ///
    /// - 判定モデルが使えない（機械判定のみ）＋難読化がある → 高（ルール1）
    /// - 判定モデルが使える＋解読の上限で止まり、その先が残っている → 高（ルール2）
    ///
    /// 底まで解けて普通のコードになった段は、その中身を普通に判定する（ここでは倒さない）。
    /// 許可済みで自動で通る行は承認画面に届かないので、ここも動かない（「許可されている物を除く」）。
    pub fn apply_fail_closed(&mut self, subject: &PermissionSubject) {
        match self.basis {
            RiskBasis::MachineOnly => {
                if has_opaque_obfuscation(subject) {
                    self.push_reason(RiskReason::OpaqueObfuscation(
                        ObfuscationCause::ModelUnavailable,
                    ));
                }
            }
            // 判定モデルも LLM フォールバックも、解読の上限の先は見ていない（行を判定しただけ）。
            // LLM が場所を示して解読した段（`extra_decoded`）で止めた場合も同じ。
            RiskBasis::WithModel | RiskBasis::WithFallback => {
                if hit_decode_limit(decoded_layers(subject))
                    || hit_decode_limit(&self.extra_decoded)
                {
                    self.push_reason(RiskReason::OpaqueObfuscation(ObfuscationCause::DepthLimited));
                }
            }
        }
    }
}

/// **解読できない**難読化がある（ハーネスが符号化された塊を見つけたが、中身を読める形まで解けていない）。
/// これが fail-closed の引き金である（D-124 ルール1）。
///
/// **解読できた段（`Text`）は外す**——その中身は機械の被害判定（`damage_in_decoded`）が既に読んでいるので、
/// 読んだ結果で判定すればよい。難読化を使っていること自体を引き金にすると、無害な `pwsh -enc <Get-Date>`
/// まで「高」になってしまう（機械が解読できたケースの漏れ。2026-10-04 修正）。
fn has_opaque_obfuscation(subject: &PermissionSubject) -> bool {
    decoded_layers(subject).iter().any(|l| {
        matches!(
            l.outcome,
            DecodeOutcome::NotText
                | DecodeOutcome::DepthLimit { .. }
                | DecodeOutcome::SizeLimit { .. }
                | DecodeOutcome::CountLimit { .. }
                | DecodeOutcome::Unreadable
        )
    })
}

/// 解読の上限（深さ・大きさ・段数）で止めた段がある＝その先にまだ難読化が残っている（D-124 ルール2）。
fn hit_decode_limit(layers: &[DecodedLayer]) -> bool {
    layers.iter().any(|l| {
        matches!(
            l.outcome,
            DecodeOutcome::DepthLimit { .. }
                | DecodeOutcome::SizeLimit { .. }
                | DecodeOutcome::CountLimit { .. }
        )
    })
}

/// 判定モデルへ送るコマンドの行。`run_shell`は行そのもの、`run_program`は人が読む1行（[`harness_core::ProgramSubject::describe`]）。
/// 判定しない材料（書込先・その他）は`None`。
pub fn subject_line(subject: &PermissionSubject) -> Option<String> {
    subject.command_line()
}

/// 同じ判定を2回しないための鍵。**判定に使う材料そのもの**（行・流れ・縛ったファイルの中身・解読した中身）で作る。
/// 各欄は長さを前に付けて並べる（区切りの文字だけで並べると、中身に区切りを書けば別の組と同じ鍵を作れる——BUG-220）。
pub fn cache_key(subject: &PermissionSubject, history: &[String]) -> Option<String> {
    let mut key = String::new();
    let mut put = |s: &str| key.push_str(&format!("{}:{s}", s.len()));
    put(&subject_line(subject)?);
    for h in history {
        put(h);
    }
    put("|");
    for p in previews(subject) {
        put(&p.rel_path);
        put(&p.text);
    }
    put("|");
    for text in decoded_texts(subject) {
        put(text);
    }
    Some(key)
}

/// ①機械の判定だけで組み立てる（すぐ返る）。判定しない材料は`None`。判定モデルは何も読んでいないので、
/// 機械が被害を見つけていれば`unjudged_damage`が立つ（判定モデルを待つ間も、使えないときも高）。
pub fn machine(subject: &PermissionSubject) -> Option<RiskOutcome> {
    let (mut out, flagged) = machine_parts(subject)?;
    out.unjudged_damage = !flagged.is_empty();
    Some(out)
}

/// ①の本体。機械が被害を見つけた材料（位置）も返す——判定モデルがそれを全部読んだかを④で見る。
fn machine_parts(subject: &PermissionSubject) -> Option<(RiskOutcome, BTreeSet<Material>)> {
    let mut out = RiskOutcome {
        reasons: Vec::new(),
        notes: Vec::new(),
        basis: RiskBasis::MachineOnly,
        extra_decoded: Vec::new(),
        model_peak: None,
        unjudged_damage: false,
    };
    let mut flagged = BTreeSet::new();
    let line_findings = match subject {
        PermissionSubject::Command(c) => system_damage::assess_line(&c.line),
        PermissionSubject::Program(p) => system_damage::assess_program(&p.program, &p.args),
        PermissionSubject::WritePath(_) | PermissionSubject::Text(_) => return None,
    };
    if add_damage(&mut out, line_findings, Origin::Command) {
        flagged.insert(Material::Line);
    }
    let layers = damage_in_decoded(&mut out, decoded_layers(subject));
    flagged.extend(layers.into_iter().map(Material::Layer));
    for (i, preview) in previews(subject).iter().enumerate() {
        if goes_to_machine(subject, preview)
            && add_damage(
                &mut out,
                system_damage::assess_line(&preview.text),
                Origin::File {
                    path: preview.rel_path.clone(),
                },
            )
        {
            flagged.insert(Material::Preview(i));
        }
    }
    Some((out, flagged))
}

/// 機械の判定のうち「高」に当たるものを理由へ足す。1つでも当たれば`true`（同じ理由が既にあっても、
/// この材料が当たったことに変わりはない）。
fn add_damage(out: &mut RiskOutcome, findings: Vec<DamageFinding>, origin: Origin) -> bool {
    let mut hit = false;
    for finding in findings.into_iter().filter(DamageFinding::is_high) {
        hit = true;
        out.push_reason(RiskReason::Damage {
            finding,
            origin: origin.clone(),
        });
    }
    hit
}

/// 解読できた段の中身に、機械の判定を掛ける。当たった段の位置を返す。
fn damage_in_decoded(out: &mut RiskOutcome, layers: &[DecodedLayer]) -> Vec<usize> {
    let mut hit = Vec::new();
    for (i, layer) in layers.iter().enumerate() {
        if let DecodeOutcome::Text { text, .. } = &layer.outcome {
            if add_damage(out, system_damage::assess_line(text), origin_of(layer)) {
                hit.push(i);
            }
        }
    }
    hit
}

/// その段をどこで見つけたか。ファイルの中で見つけた段は、**そのファイルの名前で言う**（D-122）
/// ——「3段目の中」とだけ言われても、人はどこを見ればよいか分からない。
fn origin_of(layer: &DecodedLayer) -> Origin {
    match &layer.in_file {
        Some(path) => Origin::File { path: path.clone() },
        None => Origin::Decoded { depth: layer.depth },
    }
}

/// `layers[i]` が解けた包み（D-126）か。直下の段は、前順でその後ろに続く深い段のうち深さがちょうど1つ深いもの
/// （深さが戻るか、見つけたファイルが変わったところで終わる）。
fn wraps_decoded_text(layers: &[DecodedLayer], i: usize) -> bool {
    let parent = &layers[i];
    matches!(parent.outcome, DecodeOutcome::Text { .. })
        && all_text(
            layers[i + 1..]
                .iter()
                .take_while(|l| l.depth > parent.depth && l.in_file == parent.in_file)
                .filter(|l| l.depth == parent.depth + 1),
        )
}

/// 行が解けた包み（D-126）か。行の直下の段は、行から見つけた1段目と LLM が場所を示した1段目
/// （縛ったファイルの中で見つけた段は、ファイルごとに深さ1から並ぶので含めない）。
fn line_wraps_decoded_text(decoded: &[DecodedLayer], extra: &[DecodedLayer]) -> bool {
    all_text(
        decoded
            .iter()
            .filter(|l| l.in_file.is_none())
            .chain(extra)
            .filter(|l| l.depth == 1),
    )
}

/// 1つ以上あり、全部が文字として解けた。
fn all_text<'a>(layers: impl Iterator<Item = &'a DecodedLayer>) -> bool {
    let mut layers = layers.peekable();
    layers.peek().is_some() && layers.all(|l| matches!(l.outcome, DecodeOutcome::Text { .. }))
}

/// 解読できた段の中身の危険度を判定モデルに聞く（上限[`MAX_DECODED_TO_ASK`]段）。解けた包みの途中の段は
/// 聞かない（D-126）——上限は内側の段に使う。点数を数えた段は`judged`へ`material(位置)`で入れる。
async fn model_on_decoded(
    out: &mut RiskOutcome,
    layers: &[DecodedLayer],
    model: &dyn DecisionModel,
    judged: &mut BTreeSet<Material>,
    material: fn(usize) -> Material,
) {
    let texts = layers
        .iter()
        .enumerate()
        .filter_map(|(i, layer)| match &layer.outcome {
            DecodeOutcome::Text { text, .. } if !wraps_decoded_text(layers, i) => {
                Some((i, layer, text))
            }
            _ => None,
        });
    for (i, layer, text) in texts.take(MAX_DECODED_TO_ASK) {
        match assess_command_risk(model, text).await {
            Ok(verdict) => {
                out.basis = RiskBasis::WithModel;
                out.count_model(verdict, origin_of(layer));
                judged.insert(material(i));
            }
            Err(e) => out.note_model_error(e.to_string()),
        }
    }
}

/// ①〜④を全部行う。`model`が`None`（判定モデルを使わない設定）なら①だけ。`history`はこのセッションで
/// 既に走らせたコマンド（古い順）。`locator`は解読する箇所を選ばせる LLM（要約と同じもの。`None`なら選ばせない）。
/// 判定しない材料は`None`。
pub async fn assess(
    subject: &PermissionSubject,
    history: &[String],
    model: Option<&dyn DecisionModel>,
    locator: Option<&dyn SpanLocator>,
    fallback: Option<&dyn FallbackJudge>,
) -> Option<RiskOutcome> {
    let (mut out, mut flagged) = machine_parts(subject)?;
    // 判定モデル（またはフォールバック）の点数を数えた材料。④で、機械が引っ掛けた材料を全部含むかを見る。
    let mut judged = BTreeSet::new();
    let Some(model) = model else {
        // 判定モデルを使わない設定。LLM フォールバックがあれば聞き、無ければ機械の判定だけで決める
        // （3段フォールバックの② → ③。D-125）。
        consult_fallback(&mut out, subject, fallback, &mut judged).await;
        out.apply_fail_closed(subject);
        out.unjudged_damage = !flagged.is_subset(&judged);
        return Some(out);
    };
    let line = subject_line(subject)?;

    // ② 2回を同時に（判定モデルが1回ずつ処理しても、待ち時間は長い方に寄る）。
    let context_state = command_context_state(&line, history);
    let context_questions = context_questions();
    let (risk, context) = join(
        assess_command_risk(model, &line),
        model.decide(&context_state, &context_questions),
    )
    .await;
    // 行と流れの危険度は保留する。行が解けた包みかは③の LLM の解読まで決まらない（D-126）。
    let mut line_verdict = None;
    match risk {
        Ok(verdict) => {
            out.basis = RiskBasis::WithModel;
            line_verdict = Some(verdict);
        }
        Err(e) => out.note_model_error(e.to_string()),
    }
    let mut sequence_verdict = None;
    let mut undecoded = None;
    match context {
        Ok(answers) => {
            out.basis = RiskBasis::WithModel;
            // 流れが空なら、流れの危険度はコマンドの危険度と同じものを測っているだけなので足さない。
            if !history.is_empty() {
                sequence_verdict = questions::read_sequence_risk(&answers).ok();
            }
            if let Ok(decode) = questions::read_needs_decoding(&answers) {
                if decode.yes && decoded_texts(subject).is_empty() {
                    undecoded = Some(decode.probability);
                }
            }
            // 「ソースコードを読むか」の答えは**注記にだけ使う**。中身を判定するかどうかの
            // 分かれ目には使わない——縛れたかどうかはハーネスが知っている事実だから（下の③）。
            if let Ok(source) = questions::read_reads_source(&answers) {
                if source.yes && previews(subject).is_empty() {
                    out.notes.push(RiskNote::UnboundSource {
                        probability: source.probability,
                    });
                }
            }
        }
        Err(e) => out.note_model_error(e.to_string()),
    }

    // ③ 解読が要るのに機械の解読が何も取れていなければ、LLM に場所を選ばせてハーネスが解読する。
    if let Some(probability) = undecoded {
        let located = match locator {
            Some(locator) => match locator.locate(&line).await {
                Ok(spans) => harness_tools::encoded_payload::decode_located(&line, &spans),
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        };
        if !located
            .iter()
            .any(|l| matches!(l.outcome, DecodeOutcome::Text { .. }))
        {
            out.notes.push(RiskNote::UndecodedPayload { probability });
        }
        let hit = damage_in_decoded(&mut out, &located);
        flagged.extend(hit.into_iter().map(Material::Extra));
        out.extra_decoded = located;
    }
    // 解けた包みの行への点数は、中身でなく綴りに反応するので数えない（D-126）。数えないなら、判定モデルは
    // 行を読んでいない扱い（行の平文に機械が引っ掛けても中へ下げない）。
    if !line_wraps_decoded_text(decoded_layers(subject), &out.extra_decoded) {
        if let Some(verdict) = line_verdict {
            out.count_model(verdict, Origin::Command);
            judged.insert(Material::Line);
        }
        // 流れの点数は最大にだけ入れ、行を読んだ根拠にはしない（他の問いと一緒に聞くと点数が下がる。
        // `harness_core::risk_check::DANGER_FROM`）。
        if let Some(verdict) = sequence_verdict {
            out.note_peak(verdict);
            if verdict.level == RiskLevel::Danger {
                out.push_reason(RiskReason::Sequence(verdict));
            }
        }
    }

    // ③ 解読できた段の中身（機械の解読と、LLM が場所を示したもの）。
    model_on_decoded(
        &mut out,
        decoded_layers(subject),
        model,
        &mut judged,
        Material::Layer,
    )
    .await;
    let extra = out.extra_decoded.clone();
    model_on_decoded(&mut out, &extra, model, &mut judged, Material::Extra).await;

    // ③ 縛ったファイルの中身。**コードとして縛れたものは、必ず聞く。**
    //
    // 以前は「このコマンドはソースコードを読むか」という判定モデルの答えが「はい」のときだけ聞いていた。
    // ところが**モデルが見るのはコマンドの行だけ**なので、`powershell -EncodedCommand <塊>` のように
    // 行からはファイルが見えない形では「読まない」と答える。実測（2026-10-04）: 解読して出てきた
    // `uv run test.py` の `test.py` は縛れて中身も手元にあるのに、**中身の判定が一度も走らず
    // 「要確認」のままだった**。
    //
    // **縛れたかどうかはハーネスが知っている事実で、モデルに聞くことではない**（`plans/DESIGN-COGNITION.md`
    // §0 の分業）。
    //
    // **判定モデルへは縛れたファイルを全部送る**（D-123／ユーザー決定）。機械の被害判定は字面で
    // 危険な処理を探すので拡張子のあるコードに絞ってよいが、判定モデルは中身を読んで点数を付けるので、
    // 拡張子の無いスクリプトや紛れた塊も見せる値がある。ただし1回が高価（長さ比例。4,000字で約10秒）
    // なので`MAX_FILES_TO_ASK`件まで。**どの件を落とすかで危険を見逃さないよう、スクリプトの拡張子を
    // 持つものを先に送る**（`zzz.py`が`aaa.txt`に押し出されない）。
    //
    // 並べ替えても、読んだ印は元の位置（`previews`の位置）で付ける——機械が引っ掛けた位置と突き合わせるため。
    let mut ordered: Vec<(usize, &FilePreview)> = previews(subject).iter().enumerate().collect();
    ordered.sort_by_key(|(_, p)| !harness_core::has_script_extension(&p.rel_path));
    for (i, preview) in ordered.into_iter().take(MAX_FILES_TO_ASK) {
        match assess_source_risk(model, &preview.rel_path, &preview.text).await {
            Ok((verdict, cut)) => {
                out.basis = RiskBasis::WithModel;
                out.count_model(
                    verdict,
                    Origin::File {
                        path: preview.rel_path.clone(),
                    },
                );
                judged.insert(Material::Preview(i));
                if cut || preview.truncated {
                    out.notes.push(RiskNote::FileCut {
                        path: preview.rel_path.clone(),
                    });
                }
            }
            Err(e) => out.note_model_error(e.to_string()),
        }
    }
    // 判定モデルの呼び出しが全部失敗していれば basis は MachineOnly のまま。LLM フォールバックがあれば
    // 聞く（②）。それでも判定できなければ機械の fail-closed（③。D-124/D-125）。
    consult_fallback(&mut out, subject, fallback, &mut judged).await;
    out.apply_fail_closed(subject);
    // ④ 機械が引っ掛けた材料のうち、判定モデルが読んでいないものがあれば中へ下げない。
    out.unjudged_damage = !flagged.is_subset(&judged);
    Some(out)
}

/// 判定モデルが使えなかった（basis が MachineOnly の）ときだけ、LLM フォールバック判定を聞く（D-125）。
/// 判定できたら basis を `WithFallback` にして理由へ足す。判定できなければ何もしない（③の機械判定へ）。
/// フォールバックが読むのは行だけなので、判定できたら行を読んだ印を付ける。
async fn consult_fallback(
    out: &mut RiskOutcome,
    subject: &PermissionSubject,
    fallback: Option<&dyn FallbackJudge>,
    judged: &mut BTreeSet<Material>,
) {
    if out.basis != RiskBasis::MachineOnly {
        return;
    }
    let Some(fallback) = fallback else {
        return;
    };
    let Some(line) = subject_line(subject) else {
        return;
    };
    match fallback.judge(&line).await {
        Ok(Some(verdict)) => {
            out.basis = RiskBasis::WithFallback;
            out.count_model(verdict, Origin::Command);
            judged.insert(Material::Line);
        }
        Ok(None) => {}
        Err(e) => out.note_model_error(e),
    }
}

fn previews(subject: &PermissionSubject) -> &[FilePreview] {
    match subject {
        PermissionSubject::Command(c) => &c.previews,
        PermissionSubject::Program(p) => &p.previews,
        PermissionSubject::WritePath(_) | PermissionSubject::Text(_) => &[],
    }
}

fn decoded_layers(subject: &PermissionSubject) -> &[DecodedLayer] {
    match subject {
        PermissionSubject::Command(c) => &c.decoded,
        PermissionSubject::Program(p) => &p.decoded,
        PermissionSubject::WritePath(_) | PermissionSubject::Text(_) => &[],
    }
}

fn decoded_texts(subject: &PermissionSubject) -> Vec<&str> {
    decoded_layers(subject)
        .iter()
        .filter_map(|layer| match &layer.outcome {
            DecodeOutcome::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

/// 縛ったファイルに**機械の被害判定**（`system_damage`。字面で危険な処理を探す）を掛けるか。
/// `run_program`でコードを走らせるなら全部、そうでなければスクリプトの拡張子のものだけ
/// （`cat notes.txt`のメモに書いた`rm -rf /`を拾わない）。
///
/// **判定モデル（中身をLLMが点数化）の方は全ファイルに掛ける**（D-123。呼び出し側で絞らず全部送る）。
/// 機械の判定とモデルの判定で対象が違うのは意図的で、同じ条件の複製ではない——共有するのは
/// 拡張子の一覧（`harness_core::SCRIPT_EXTENSIONS`）だけで、ここが1つなら静かにずれない（`B-05`）。
///
/// **拡張子の一覧は`harness_core::has_script_extension`の1つだけを見る。** 以前はここと
/// `harness_tools::approval_binding`が別々の一覧を持っていて中身がずれており、`deploy.pyw`のような
/// ファイルは**中身を読んでハッシュで縛り判定モデルへも送るのに、機械の被害判定だけ掛からない**
/// 状態だった（2026-10-04）。
fn goes_to_machine(subject: &PermissionSubject, preview: &FilePreview) -> bool {
    matches!(subject, PermissionSubject::Program(p) if p.runs_code)
        || harness_core::has_script_extension(&preview.rel_path)
}

#[cfg(test)]
#[path = "approval_risk_tests.rs"]
mod tests;
