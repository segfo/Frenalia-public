//! 妥当性評価（Validity）。`plans/DESIGN-COGNITION.md` §4.3。
//!
//! ここは**純粋な型と純粋関数**だけで、台帳にもファイルにも触れない。「無批判に事実化しない」
//! という§4のユーザ要件を、プロンプトへの祈りではなく機械規則として書き下ろした場所である。
//!
//! # 値の権限が2つに分かれている
//!
//! [`Validity`]は1つの構造体だが、フィールドの決まり方は2種類ある。
//!
//! | フィールド | 誰が決めるか | いつ |
//! |---|---|---|
//! | `trust` / `freshness` | [`crate::source::SourceCatalog`]（宣言があればそれ、無ければ種別既定） | 証拠を積む時点で確定。以後不変 |
//! | `grade` / `conflicts` | [`crate::memory::WorkingMemory`]（台帳の他の証拠に依存する派生値） | 台帳の全変異の直後に再計算 |
//!
//! 派生値をフィールドとして持つのは§4.3・§3.4（「各EvidenceはSourceRefとValidityを保持」）に
//! 従うためで、陳腐化を防ぐ責任は台帳側の再計算1箇所に集約されている。

use serde::{Deserialize, Serialize};

use super::types::{EvidenceId, SourceKind};

/// 証拠の妥当性グレード（§4.3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Grade {
    /// 別種のソースで裏取りできている（CrossSource成立）。
    Corroborated,
    /// 接地種別で観測できているが、裏取りは1系統のみ。
    SingleSource,
    /// 単独では確証の根拠にできない（`Web`/`Memory`/`ModelPrior`単独、仮説に紐付かない観測）。
    Unverified,
    /// 他の証拠と矛盾しており、まだ決着していない。
    Conflicting,
}

impl Grade {
    /// レンダリング用の短い表現。
    pub fn as_str(self) -> &'static str {
        match self {
            Grade::Corroborated => "corroborated",
            Grade::SingleSource => "single_source",
            Grade::Unverified => "unverified",
            Grade::Conflicting => "conflicting",
        }
    }

    /// [`evidence_strength`]の重み付けに使う係数。`Conflicting`が0なのは、
    /// 決着していない矛盾を「弱い根拠」ではなく「根拠として数えない」ものとして扱うため。
    fn weight(self) -> i32 {
        match self {
            Grade::Corroborated => 3,
            Grade::SingleSource => 2,
            Grade::Unverified => 1,
            Grade::Conflicting => 0,
        }
    }
}

/// 情報源の宣言信頼度（`settings.json`の`cognition.sources[].trust`由来、§4.2）。
///
/// 【T5】プロジェクト同梱設定は既定を**引き下げられるが引き上げられない**。その上限の
/// 適用は設定の層がまだ分かる`harness_config::Settings::load`が持つ。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    Low,
    Medium,
    High,
}

impl TrustLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            TrustLevel::Low => "low",
            TrustLevel::Medium => "medium",
            TrustLevel::High => "high",
        }
    }

    fn weight(self) -> i32 {
        match self {
            TrustLevel::High => 3,
            TrustLevel::Medium => 2,
            TrustLevel::Low => 1,
        }
    }
}

/// 情報の鮮度（§4.3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    /// 判断の材料として最も古びない（権威ある一次資料）。
    Unknown,
    Stale,
    Fresh,
    Authoritative,
}

impl Freshness {
    pub fn as_str(self) -> &'static str {
        match self {
            Freshness::Authoritative => "authoritative",
            Freshness::Fresh => "fresh",
            Freshness::Stale => "stale",
            Freshness::Unknown => "unknown",
        }
    }
}

/// 1件の証拠に対する妥当性評価（§4.3）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validity {
    pub grade: Grade,
    pub trust: TrustLevel,
    pub freshness: Freshness,
    /// 矛盾している他の証拠のうち、**まだ決着していない**もの。
    /// 決着した相手は[`resolve_conflict`]の結果に従ってここから外れる。
    pub conflicts: Vec<EvidenceId>,
    /// 矛盾の決着で優先された相手（自分が負けた場合）。
    ///
    /// 負けた観測を台帳から**消さない**のは、台帳が「何を観測したか」の記録であり、
    /// 決着の経緯まで含めて監査できる必要があるため（§4.3 監査性）。代わりに
    /// [`grade_for`]がこれを見て[`Grade::Unverified`]へ落とし、確証の根拠から外す。
    pub superseded_by: Option<EvidenceId>,
}

impl Validity {
    /// 証拠を積む時点の初期値。`grade`は台帳が直後に再計算するので、ここでは最も弱い
    /// [`Grade::Unverified`]から始める（**強い方から始めると、再計算し忘れが安全側に倒れない**）。
    pub fn seed(trust: TrustLevel, freshness: Freshness) -> Self {
        Self {
            grade: Grade::Unverified,
            trust,
            freshness,
            conflicts: Vec::new(),
            superseded_by: None,
        }
    }

    /// レンダリング用の1行表現（`single_source/trust:high`）。矛盾に負けていればそれも出す
    /// ——「なぜこの観測を根拠に使わないのか」が台帳と最終回答から読めるようにするため。
    pub fn describe(&self) -> String {
        let mut out = format!("{}/trust:{}", self.grade.as_str(), self.trust.as_str());
        if let Some(winner) = self.superseded_by {
            out.push_str(&format!("／{winner}に優先された"));
        }
        out
    }

    /// この証拠を§3.4【E1】の接地として数えてよいか。
    ///
    /// 種別が接地種別であることに加え、**矛盾に負けていないこと**を要求する。決着で退けた
    /// 観測がそのまま確証の根拠に使えると、決着に意味が無くなる。
    pub fn counts_as_grounding(&self, kind: SourceKind) -> bool {
        kind.is_grounding() && self.superseded_by.is_none()
    }
}

/// [`grade_for`]へ渡す1件分の材料。台帳の内部表現を`validity.rs`へ持ち込まないための、
/// 判定に要る事実だけの射影。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GradeInput {
    /// この証拠自身の出典種別。
    pub kind: SourceKind,
    /// 未決着の矛盾を持っているか。
    pub has_unresolved_conflict: bool,
    /// 矛盾の決着で退けられたか。
    pub superseded: bool,
    /// 同じ仮説を**支持する**証拠に、自分と別種の接地種別があるか。
    pub corroborated_by_other_kind: bool,
    /// どれかの仮説に支持/反証として紐付いているか。
    pub linked_to_hypothesis: bool,
}

/// 妥当性グレードの判定（§4.3を機械規則へ写したもの）。
///
/// 順序に意味がある——矛盾は他のどの条件よりも優先し、決着で退けられた観測は根拠から外れ、
/// 裏取りの成立は単独接地よりも強い。`ModelPrior`は`kind.is_grounding()`が偽なので必ず
/// [`Grade::Unverified`]へ落ちる（§4.3「ModelPriorは常に最弱＝必ず裏取り対象」）。
pub fn grade_for(input: GradeInput) -> Grade {
    if input.has_unresolved_conflict {
        return Grade::Conflicting;
    }
    if input.superseded {
        return Grade::Unverified;
    }
    if input.linked_to_hypothesis && input.corroborated_by_other_kind {
        return Grade::Corroborated;
    }
    if input.kind.is_grounding() {
        return Grade::SingleSource;
    }
    Grade::Unverified
}

/// 矛盾の決着結果（§4.3「新しい/信頼度高いソースを優先、決着不能ならOpenQuestion」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// 1つ目の引数が勝った。
    First,
    /// 2つ目の引数が勝った。
    Second,
    /// 決着できない。呼び出し側は`OpenQuestion`を立て、両者を`Conflicting`のまま残す。
    Undecided,
}

/// 矛盾する2件の証拠を決着させる。**追加のLLMコールを使わない**——決着の規則は§4.3が
/// 既に決めており、モデルに問い直すと同じ入力から違う答えが返り得るため。
pub fn resolve_conflict(
    a: (TrustLevel, Freshness),
    b: (TrustLevel, Freshness),
) -> Resolution {
    match a.0.cmp(&b.0) {
        std::cmp::Ordering::Greater => return Resolution::First,
        std::cmp::Ordering::Less => return Resolution::Second,
        std::cmp::Ordering::Equal => {}
    }
    match a.1.cmp(&b.1) {
        std::cmp::Ordering::Greater => Resolution::First,
        std::cmp::Ordering::Less => Resolution::Second,
        std::cmp::Ordering::Equal => Resolution::Undecided,
    }
}

/// 仮説の根拠の強さ（§3.4「表示・監査には`evidence_strength`を用いる」）。
///
/// 自己申告の`Hypothesis.confidence`(f32)の代わりに使う。**ハーネスが決定的に算出する**ので、
/// モデル層を跨いでも同じ台帳からは同じ値が出る。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStrength {
    /// 根拠が無い、または反証が支持を上回っている。
    Ungrounded,
    Weak,
    Moderate,
    Strong,
}

impl EvidenceStrength {
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceStrength::Strong => "strong",
            EvidenceStrength::Moderate => "moderate",
            EvidenceStrength::Weak => "weak",
            EvidenceStrength::Ungrounded => "ungrounded",
        }
    }
}

/// 支持/反証の`Validity`から根拠の強さを算出する（§3.4「supporting/refutingの件数 ×
/// `Validity.grade`からハーネスが決定的に算出」）。
///
/// 区切りは「**単一ソースだけでは`Strong`にならない**」ように置いてある——最も信頼できる
/// 情報源からの単独観測（`SingleSource`×`High` = 6）が`Moderate`、別種ソースでの裏取りが
/// 成立して初めて（`Corroborated`×`High` = 9）`Strong`になる。§4.2が単一ソースを
/// 「結論は出せるが裏取りできていない状態」と位置付けているので、強さの表示もそれに揃える。
///
/// **区切り値そのものは未校正**である（実運用のデータで詰めていない）。`Grade`と`TrustLevel`の
/// 重みも同様に恣意的だが、恣意的でも**決定的**であることに意味がある——自己申告のconfidenceと
/// 違い、同じ台帳からは必ず同じ値が出るので、監査のときに「なぜこの強さになったか」を再現できる。
pub fn evidence_strength<'a>(
    supporting: impl Iterator<Item = &'a Validity>,
    refuting: impl Iterator<Item = &'a Validity>,
) -> EvidenceStrength {
    let weigh = |v: &Validity| v.grade.weight() * v.trust.weight();
    let score: i32 = supporting.map(weigh).sum::<i32>() - refuting.map(weigh).sum::<i32>();
    match score {
        s if s >= 9 => EvidenceStrength::Strong,
        s if s >= 5 => EvidenceStrength::Moderate,
        s if s >= 1 => EvidenceStrength::Weak,
        _ => EvidenceStrength::Ungrounded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(kind: SourceKind) -> GradeInput {
        GradeInput {
            kind,
            has_unresolved_conflict: false,
            superseded: false,
            corroborated_by_other_kind: false,
            linked_to_hypothesis: true,
        }
    }

    fn validity(grade: Grade, trust: TrustLevel) -> Validity {
        Validity {
            grade,
            trust,
            freshness: Freshness::Fresh,
            conflicts: Vec::new(),
            superseded_by: None,
        }
    }

    /// 未決着の矛盾は他のどの条件よりも優先する（裏取りが成立していても`Conflicting`）。
    #[test]
    fn an_unresolved_conflict_outranks_every_other_condition() {
        let g = grade_for(GradeInput {
            has_unresolved_conflict: true,
            corroborated_by_other_kind: true,
            ..input(SourceKind::File)
        });
        assert_eq!(g, Grade::Conflicting);
    }

    /// 別種ソースでの裏取りが成立していれば`Corroborated`（§4.2のCrossSource）。
    #[test]
    fn cross_source_corroboration_beats_single_source() {
        let g = grade_for(GradeInput {
            corroborated_by_other_kind: true,
            ..input(SourceKind::File)
        });
        assert_eq!(g, Grade::Corroborated);
    }

    /// 接地種別（File/Shell/Mcp）の単独観測は`SingleSource`。
    #[test]
    fn a_lone_grounded_observation_is_single_source() {
        for kind in [SourceKind::File, SourceKind::Shell, SourceKind::Mcp] {
            assert_eq!(grade_for(input(kind)), Grade::SingleSource, "{kind:?}");
        }
    }

    /// **§4.3の底線**: web・記憶ノート・モデルの内部知識は単独では`Unverified`のまま。
    #[test]
    fn web_memory_and_model_prior_never_reach_single_source_on_their_own() {
        for kind in [SourceKind::Web, SourceKind::Memory, SourceKind::ModelPrior] {
            assert_eq!(grade_for(input(kind)), Grade::Unverified, "{kind:?}");
        }
    }

    /// 決着で退けられた観測は根拠から外れる（接地種別でも`Unverified`）。
    #[test]
    fn a_superseded_observation_is_demoted_and_stops_counting_as_grounding() {
        let g = grade_for(GradeInput {
            superseded: true,
            corroborated_by_other_kind: true,
            ..input(SourceKind::File)
        });
        assert_eq!(g, Grade::Unverified);

        let mut v = validity(Grade::Unverified, TrustLevel::High);
        assert!(v.counts_as_grounding(SourceKind::File));
        v.superseded_by = Some(EvidenceId(7));
        assert!(!v.counts_as_grounding(SourceKind::File));
        assert!(v.describe().contains("E7"), "{}", v.describe());
    }

    /// どの仮説にも紐付かない観測は、接地種別でも裏取り扱いにしない。
    #[test]
    fn an_unlinked_observation_cannot_be_corroborated() {
        let g = grade_for(GradeInput {
            corroborated_by_other_kind: true,
            linked_to_hypothesis: false,
            ..input(SourceKind::File)
        });
        assert_eq!(g, Grade::SingleSource);
    }

    /// 決着は信頼度優先、同値なら鮮度（§4.3）。
    #[test]
    fn conflicts_are_decided_by_trust_then_freshness() {
        assert_eq!(
            resolve_conflict(
                (TrustLevel::High, Freshness::Unknown),
                (TrustLevel::Low, Freshness::Authoritative)
            ),
            Resolution::First,
            "信頼度が鮮度より優先する"
        );
        assert_eq!(
            resolve_conflict(
                (TrustLevel::Medium, Freshness::Stale),
                (TrustLevel::Medium, Freshness::Fresh)
            ),
            Resolution::Second
        );
    }

    /// 信頼度も鮮度も同じなら決着させない（呼び出し側が`OpenQuestion`を立てる）。
    #[test]
    fn an_evenly_matched_conflict_stays_undecided() {
        assert_eq!(
            resolve_conflict(
                (TrustLevel::High, Freshness::Fresh),
                (TrustLevel::High, Freshness::Fresh)
            ),
            Resolution::Undecided
        );
    }

    /// 強さは支持で上がり反証で下がる（単調性）。
    #[test]
    fn strength_rises_with_support_and_falls_with_refutation() {
        let strong = validity(Grade::Corroborated, TrustLevel::High);
        let weak = validity(Grade::Unverified, TrustLevel::Low);

        assert_eq!(
            evidence_strength([&strong].into_iter(), std::iter::empty()),
            EvidenceStrength::Strong
        );
        assert_eq!(
            evidence_strength([&weak].into_iter(), std::iter::empty()),
            EvidenceStrength::Weak
        );
        assert_eq!(
            evidence_strength([&strong].into_iter(), [&strong].into_iter()),
            EvidenceStrength::Ungrounded,
            "同格の反証が来れば根拠は相殺される"
        );
        assert_eq!(
            evidence_strength(std::iter::empty(), std::iter::empty()),
            EvidenceStrength::Ungrounded
        );
    }

    /// **区切りの意図**: 単一ソースだけでは`Strong`にならない（§4.2の位置付けに合わせる）。
    #[test]
    fn a_single_source_alone_never_reaches_the_strongest_grade() {
        let single = validity(Grade::SingleSource, TrustLevel::High);
        assert_eq!(
            evidence_strength([&single].into_iter(), std::iter::empty()),
            EvidenceStrength::Moderate
        );
        let corroborated = validity(Grade::Corroborated, TrustLevel::High);
        assert_eq!(
            evidence_strength([&corroborated].into_iter(), std::iter::empty()),
            EvidenceStrength::Strong
        );
    }

    /// 未決着の矛盾は根拠として数えない（重み0）。
    #[test]
    fn a_conflicting_evidence_contributes_nothing_to_the_strength() {
        let conflicting = validity(Grade::Conflicting, TrustLevel::High);
        assert_eq!(
            evidence_strength([&conflicting].into_iter(), std::iter::empty()),
            EvidenceStrength::Ungrounded
        );
    }

    /// 同じ入力からは必ず同じ強さが出る（自己申告confidenceと違い監査で再現できる）。
    #[test]
    fn strength_is_deterministic() {
        let v = [
            validity(Grade::SingleSource, TrustLevel::High),
            validity(Grade::Unverified, TrustLevel::Medium),
        ];
        let first = evidence_strength(v.iter(), std::iter::empty());
        let second = evidence_strength(v.iter(), std::iter::empty());
        assert_eq!(first, second);
    }
}
