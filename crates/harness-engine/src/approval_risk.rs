//! 承認画面の危険度（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` D-100 の追記）を組み立てる。
//!
//! # 何のためにあるのか
//!
//! 承認画面は、人が「このコマンドを走らせてよいか」を決めるための道具である。画面には**「危険度: 要確認」か
//! 「危険度: 高」**のどちらかを出し、高のときは理由を並べる。**「要確認」は安全という意味ではない**——
//! 見つけた危険が無かった、というだけで、人が中身を確かめることに変わりはない（「低」「安全」と書かないのはそのため）。
//!
//! # 流れ
//!
//! ```text
//! ① 機械の判定（machine。すぐ終わり、ネットワークを使わず、いつも動く）
//!    行・解読した各段・縛ったスクリプトの中身に、システムへの被害の判定（harness-tools の system_damage）を掛ける
//! ② 判定モデル（Ollaya。設定で有効なときだけ）に2回を同時に聞く（harness-core の decision の「測った2つの形」）
//!    ・危険度だけ                  → コマンドの危険度
//!    ・流れと一緒に4問              → 解読が要るか・ファイルからコードを読むか・流れと合わせた危険度
//! ③ 必要なときだけ追加で聞く
//!    ・「解読が要る」と出たのに機械の解読が何も取れていなければ、LLM に場所を選ばせてハーネスが解読する（encoded_span）
//!    ・解読できた各段（機械の解読・LLM が場所を示したもの）の中身を、機械の判定と判定モデルに通す
//!    ・ファイルからコードを読む（または run_program でコードを走らせる）なら、縛ったファイルの中身の危険度
//! ④ どれか1つでも高なら「高」、それ以外は「要確認」
//! ```
//!
//! 判定モデルが無い・落ちているときは①だけで決め、画面には「機械判定のみ」と添える（[`RiskBasis`]）。
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

use futures::future::join;
use harness_core::decision::questions;
use harness_core::{
    assess_command_risk, assess_source_risk, command_context_state, context_questions,
    DecisionModel, DecodeOutcome, DecodedLayer, FilePreview, PermissionSubject, RiskLevel,
    RiskVerdict,
};
use harness_tools::system_damage::{self, DamageFinding};

use crate::encoded_span::SpanLocator;

/// 解読できた段のうち、判定モデルへ危険度を聞く数の上限（段ごとに1回の呼び出し、約1秒）。
pub const MAX_DECODED_TO_ASK: usize = 4;
/// 縛ったファイルのうち、判定モデルへ中身の危険度を聞く数の上限（長さに比例して遅い。4,000字で約12秒）。
pub const MAX_FILES_TO_ASK: usize = 3;

/// 画面に出す危険度の段階。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// 見つけた危険は無い。**安全という意味ではない**（人が中身を確かめる）。
    NeedsReview,
    /// 機械の判定か判定モデルのどれかが危険と見た。
    High,
}

impl Severity {
    pub fn label_ja(self) -> &'static str {
        match self {
            Severity::NeedsReview => "要確認",
            Severity::High => "高",
        }
    }

    /// 要約へ渡す段階（高のときだけ、固定の英文1行。[`RiskLevel::summary_instruction`]）。
    pub fn summary_hint(self) -> Option<RiskLevel> {
        match self {
            Severity::High => Some(RiskLevel::Danger),
            Severity::NeedsReview => None,
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

/// 「高」の理由1つ。
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
    /// 機械の判定だけ（判定モデルを使わない設定か、使えなかった）。
    MachineOnly,
    /// 判定モデルも使った。
    WithModel,
}

/// 組み立てた結果。
#[derive(Debug, Clone, PartialEq)]
pub struct RiskOutcome {
    /// 「高」の理由。空なら「要確認」。
    pub reasons: Vec<RiskReason>,
    pub notes: Vec<RiskNote>,
    pub basis: RiskBasis,
    /// LLM が場所を示し、ハーネスが解読した段（[`crate::encoded_span`]）。承認画面と要約に、
    /// 機械の解読（材料の`decoded`）と並べて出す。**表示と要約・判定のためだけで、照合に使わない。**
    pub extra_decoded: Vec<DecodedLayer>,
}

impl RiskOutcome {
    pub fn severity(&self) -> Severity {
        if self.reasons.is_empty() {
            Severity::NeedsReview
        } else {
            Severity::High
        }
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

/// ①機械の判定だけで組み立てる（すぐ返る）。判定しない材料は`None`。
pub fn machine(subject: &PermissionSubject) -> Option<RiskOutcome> {
    let mut out = RiskOutcome {
        reasons: Vec::new(),
        notes: Vec::new(),
        basis: RiskBasis::MachineOnly,
        extra_decoded: Vec::new(),
    };
    match subject {
        PermissionSubject::Command(c) => add_damage(
            &mut out,
            system_damage::assess_line(&c.line),
            Origin::Command,
        ),
        PermissionSubject::Program(p) => add_damage(
            &mut out,
            system_damage::assess_program(&p.program, &p.args),
            Origin::Command,
        ),
        PermissionSubject::WritePath(_) | PermissionSubject::Text(_) => return None,
    }
    damage_in_decoded(&mut out, decoded_layers(subject));
    for preview in previews(subject).iter().filter(|p| is_code(subject, p)) {
        add_damage(
            &mut out,
            system_damage::assess_line(&preview.text),
            Origin::File {
                path: preview.rel_path.clone(),
            },
        );
    }
    Some(out)
}

/// 機械の判定のうち「高」に当たるものを理由へ足す。
fn add_damage(out: &mut RiskOutcome, findings: Vec<DamageFinding>, origin: Origin) {
    for finding in findings.into_iter().filter(DamageFinding::is_high) {
        out.push_reason(RiskReason::Damage {
            finding,
            origin: origin.clone(),
        });
    }
}

/// 解読できた段の中身に、機械の判定を掛ける。
fn damage_in_decoded(out: &mut RiskOutcome, layers: &[DecodedLayer]) {
    for layer in layers {
        if let DecodeOutcome::Text { text, .. } = &layer.outcome {
            add_damage(
                out,
                system_damage::assess_line(text),
                Origin::Decoded { depth: layer.depth },
            );
        }
    }
}

/// 解読できた段の中身の危険度を判定モデルに聞く（上限[`MAX_DECODED_TO_ASK`]段）。
async fn model_on_decoded(
    out: &mut RiskOutcome,
    layers: &[DecodedLayer],
    model: &dyn DecisionModel,
) {
    let texts = layers.iter().filter_map(|layer| match &layer.outcome {
        DecodeOutcome::Text { text, .. } => Some((layer.depth, text)),
        _ => None,
    });
    for (depth, text) in texts.take(MAX_DECODED_TO_ASK) {
        match assess_command_risk(model, text).await {
            Ok(verdict) => {
                out.basis = RiskBasis::WithModel;
                if verdict.level == RiskLevel::Danger {
                    out.push_reason(RiskReason::Model {
                        verdict,
                        origin: Origin::Decoded { depth },
                    });
                }
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
) -> Option<RiskOutcome> {
    let mut out = machine(subject)?;
    let Some(model) = model else {
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
    match risk {
        Ok(verdict) => {
            out.basis = RiskBasis::WithModel;
            if verdict.level == RiskLevel::Danger {
                out.push_reason(RiskReason::Model {
                    verdict,
                    origin: Origin::Command,
                });
            }
        }
        Err(e) => out.note_model_error(e.to_string()),
    }
    let mut reads_source = false;
    let mut undecoded = None;
    match context {
        Ok(answers) => {
            out.basis = RiskBasis::WithModel;
            // 流れが空なら、流れの危険度はコマンドの危険度と同じものを測っているだけなので足さない。
            if !history.is_empty() {
                if let Ok(verdict) = questions::read_sequence_risk(&answers) {
                    if verdict.level == RiskLevel::Danger {
                        out.push_reason(RiskReason::Sequence(verdict));
                    }
                }
            }
            if let Ok(decode) = questions::read_needs_decoding(&answers) {
                if decode.yes && decoded_texts(subject).is_empty() {
                    undecoded = Some(decode.probability);
                }
            }
            if let Ok(source) = questions::read_reads_source(&answers) {
                reads_source = source.yes;
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
        damage_in_decoded(&mut out, &located);
        out.extra_decoded = located;
    }

    // ③ 解読できた段の中身（機械の解読と、LLM が場所を示したもの）。
    model_on_decoded(&mut out, decoded_layers(subject), model).await;
    let extra = out.extra_decoded.clone();
    model_on_decoded(&mut out, &extra, model).await;

    // ③ 縛ったファイルの中身（コードを走らせるときだけ）。
    let runs_code = matches!(subject, PermissionSubject::Program(p) if p.runs_code);
    if runs_code || reads_source {
        for preview in previews(subject).iter().take(MAX_FILES_TO_ASK) {
            match assess_source_risk(model, &preview.rel_path, &preview.text).await {
                Ok((verdict, cut)) => {
                    out.basis = RiskBasis::WithModel;
                    if verdict.level == RiskLevel::Danger {
                        out.push_reason(RiskReason::Model {
                            verdict,
                            origin: Origin::File {
                                path: preview.rel_path.clone(),
                            },
                        });
                    }
                    if cut || preview.truncated {
                        out.notes.push(RiskNote::FileCut {
                            path: preview.rel_path.clone(),
                        });
                    }
                }
                Err(e) => out.note_model_error(e.to_string()),
            }
        }
    }
    Some(out)
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

/// 縛ったファイルをコードとして機械の判定に掛けるか。`run_program`でコードを走らせるなら全部、
/// `run_shell`ならスクリプトの拡張子のものだけ（`cat notes.txt`のメモに書いた`rm -rf /`を拾わない）。
///
/// **拡張子の一覧は`harness_core::SCRIPT_EXTENSIONS`の1つだけを見る。** 以前はここと
/// `harness_tools::approval_binding`が別々の一覧を持っていて中身がずれており、`deploy.pyw`のような
/// ファイルは**中身を読んでハッシュで縛り判定モデルへも送るのに、機械の被害判定だけ掛からない**
/// 状態だった（2026-10-04）。
fn is_code(subject: &PermissionSubject, preview: &FilePreview) -> bool {
    matches!(subject, PermissionSubject::Program(p) if p.runs_code)
        || harness_core::has_script_extension(&preview.rel_path)
}

#[cfg(test)]
#[path = "approval_risk_tests.rs"]
mod tests;
