//! 承認画面の「危険度: 要確認／中／高」の行と枠の見出し（D-100 の追記。組み立ては`harness_engine::approval_risk`）。
//!
//! `approval.rs`の子モジュール（同じ行の部品`ApprovalLine`・`LineStyle`をそのまま使う）。
//! 色はここで決めない——行の意味（`LineStyle`）と見出しの調子（[`TitleTone`]）だけを付け、色は`ui::approval`が決める。

use std::time::Instant;

use harness_engine::approval_risk::{
    Origin, RiskBasis, RiskNote, RiskOutcome, RiskReason, Severity,
};

use super::{ApprovalLine, LineStyle, PermissionView, WaitClock};
use crate::app::spinner_glyph;

/// 承認画面が持つ危険度の状態。
#[derive(Debug, Clone)]
pub struct RiskView {
    /// いま出している結果。開いた時点では機械の判定で、判定モデルの結果が届いたら置き換わる。
    pub outcome: RiskOutcome,
    /// 判定モデルの結果を待っているか。待っている間は機械の判定を出し、「判定中」を添える。
    pub waiting: Option<Instant>,
    /// 判定モデルの出どころ（サーバ／モデル）。判定モデルを使わない設定なら`None`。
    pub source: Option<String>,
}

impl RiskView {
    /// 決まった結果（機械の判定だけの設定・前に判定した同じ材料）。
    pub fn done(outcome: RiskOutcome, source: Option<String>) -> Self {
        Self {
            outcome,
            waiting: None,
            source,
        }
    }

    /// 機械の判定を出しながら、判定モデルの結果を待つ。
    pub fn waiting(machine: RiskOutcome, source: String, since: Instant) -> Self {
        Self {
            outcome: machine,
            waiting: Some(since),
            source: Some(source),
        }
    }

    /// `rel_path`のファイルの中身に当たった、機械の被害判定だけを引く（D-121）。
    ///
    /// 承認画面が「危険な処理に当たった行」をその場で見せるために使う。判定モデルの分は含めない
    /// ——点数には行が無いので、指す先が無い。
    pub fn flagged_in<'a>(
        &'a self,
        rel_path: &'a str,
    ) -> impl Iterator<Item = &'a harness_tools::system_damage::DamageFinding> + 'a {
        self.outcome.reasons.iter().filter_map(move |r| match r {
            RiskReason::Damage {
                finding,
                origin: Origin::File { path },
            } if path == rel_path => Some(finding),
            _ => None,
        })
    }

    pub fn severity(&self) -> Severity {
        self.outcome.severity()
    }
}

/// 枠の見出しの調子。色は`ui::approval`が決める。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TitleTone {
    /// 今までと同じ見た目（要確認・判定しない材料）。
    Plain,
    /// 危険度が中（機械の判定と判定モデルが食い違った）。
    Caution,
    /// 危険度が高。
    Danger,
}

impl PermissionView {
    /// 枠の見出しと、その調子（枠の色に使う）。**要確認・判定しない材料は今までと同じ「承認が必要です」**で、
    /// 安全だとも書かない。段階を足したら、ここで見出しを決めるまでコンパイルが通らない（`_`の腕を置かない）。
    pub fn title(&self) -> (&'static str, TitleTone) {
        match self.assessment.as_ref().map(RiskView::severity) {
            Some(Severity::High) => ("危険なコマンド — 承認が必要です", TitleTone::Danger),
            Some(Severity::Medium) => ("注意が必要なコマンド — 承認が必要です", TitleTone::Caution),
            Some(Severity::NeedsReview) | None => ("承認が必要です", TitleTone::Plain),
        }
    }

    /// `危険度: 要確認`／`中`／`高`の行と、中・高の理由・注記・判定中の行。判定しない材料（書込先・その他）は何も出さない。
    ///
    /// **「要確認」は安全という意味ではない**——見つけた危険が無かっただけで、人が中身を確かめる（「低」「安全」と書かない）。
    /// **「中」も安全ではない**——機械が見つけた被害を、判定モデルが低いと見ただけである。
    pub(super) fn risk_lines(&self, clock: WaitClock) -> Vec<ApprovalLine> {
        let Some(view) = &self.assessment else {
            return Vec::new();
        };
        let severity = view.severity();
        let basis = match (view.waiting, view.outcome.basis, &view.source) {
            (Some(_), _, _) => String::new(),
            (None, RiskBasis::MachineOnly, None) => {
                "（機械判定のみ。判定モデルを使わない設定）".to_string()
            }
            (None, RiskBasis::MachineOnly, Some(_)) => {
                "（機械判定のみ。判定モデルを使えなかった）".to_string()
            }
            (None, RiskBasis::WithModel, Some(source)) => {
                format!("（機械判定と判定モデル {source}）")
            }
            (None, RiskBasis::WithModel, None) => "（機械判定と判定モデル）".to_string(),
            // 判定モデルが使えず、LLM フォールバック判定で決めた（D-125。本実装が入るまではモックなので
            // 当面ここは出ない）。
            (None, RiskBasis::WithFallback, _) => "（機械判定とLLMフォールバック判定）".to_string(),
        };
        let style = match severity {
            Severity::High => LineStyle::Danger,
            Severity::Medium => LineStyle::Warn,
            Severity::NeedsReview => LineStyle::Normal,
        };
        let mut out = vec![ApprovalLine::new(
            style,
            format!("危険度: {}{basis}", severity.label_ja()),
        )];
        for reason in &view.outcome.reasons {
            out.push(ApprovalLine::new(
                LineStyle::Normal,
                format!("  ・{}", reason.describe_ja()),
            ));
        }
        // 中のときは、なぜ中か（判定モデルの点数の最大）を理由と同じ形で添える。理由の一つなので注記（Dim）にしない。
        if let Some(low) = view.outcome.model_low_ja() {
            out.push(ApprovalLine::new(LineStyle::Normal, format!("  ・{low}")));
        }
        for note in &view.outcome.notes {
            let style = match note {
                RiskNote::ModelUnavailable(_) | RiskNote::FileCut { .. } => LineStyle::Dim,
                RiskNote::UndecodedPayload { .. } | RiskNote::UnboundSource { .. } => {
                    LineStyle::Warn
                }
            };
            out.push(ApprovalLine::new(
                style,
                format!("  ・{}", note.describe_ja()),
            ));
        }
        if let Some(since) = view.waiting {
            let source = view.source.as_deref().unwrap_or("判定モデル");
            out.push(ApprovalLine::new(
                LineStyle::Dim,
                format!(
                    "  {} 判定モデル（{source}）で判定中…（{:.1}s。いまは機械の判定だけを出している）",
                    spinner_glyph(clock.spinner_frame),
                    clock.now.saturating_duration_since(since).as_secs_f32()
                ),
            ));
        }
        out
    }
}
