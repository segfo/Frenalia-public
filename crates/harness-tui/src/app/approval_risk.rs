//! 承認画面の「危険度: 要確認／高」の行（D-100 の追記。組み立ては`harness_engine::approval_risk`）。
//!
//! `approval.rs`の子モジュール（同じ行の部品`ApprovalLine`・`LineStyle`をそのまま使う）。
//! 色はここで決めない——行の意味（`LineStyle`）だけを付け、色は`ui::approval`が決める。

use std::time::Instant;

use harness_engine::approval_risk::{RiskBasis, RiskNote, RiskOutcome, Severity};

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

    pub fn severity(&self) -> Severity {
        self.outcome.severity()
    }
}

impl PermissionView {
    /// `危険度: 要確認`／`危険度: 高`の行と、高の理由・注記・判定中の行。判定しない材料（書込先・その他）は何も出さない。
    ///
    /// **「要確認」は安全という意味ではない**——見つけた危険が無かっただけで、人が中身を確かめる（「低」「安全」と書かない）。
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
        };
        let style = match severity {
            Severity::High => LineStyle::Danger,
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
