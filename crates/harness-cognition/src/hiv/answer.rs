//! 台帳から最終回答を組み立てる。**追加のLLMコールを使わない**。
//!
//! 設計上の理由が2つある。
//!
//! 1. **監査性**（`plans/DESIGN.md` §監査性）: 最終回答の各主張が「どのソースの・どの
//!    妥当性の情報に基づくか」まで辿れる必要がある。台帳から決定的に組めば、回答と台帳が
//!    ずれようがない。要約コールを挟むと、そこで根拠の無い一文が混ざり得る。
//! 2. **§3.5「どれも確証できない時は『不確実である』ことを結論として返す（でっち上げない）」**:
//!    確証済み仮説が無いときに何を書くかは、モデルの裁量ではなく台帳の状態で決まる。

use crate::hiv::HivStop;
use crate::memory::types::HypStatus;
use crate::memory::WorkingMemory;

/// 最終回答（Markdown）。
pub(crate) fn render(mem: &WorkingMemory, stop: &HivStop) -> String {
    let mut out = String::new();

    out.push_str("## 結論\n\n");
    match mem.decisions().last() {
        Some(decision) => {
            out.push_str(&format!("{}\n", decision.action));
        }
        None => {
            out.push_str(&format!("{}\n", unresolved_reason(stop)));
        }
    }

    let confirmed: Vec<_> = mem
        .hypotheses()
        .iter()
        .filter(|h| h.status == HypStatus::Confirmed)
        .collect();

    if confirmed.is_empty() {
        out.push_str(
            "\n**確証できた仮説はない。** 以下は調査の途中経過であり、確証済みの事実として\
             扱ってはならない。\n",
        );
    }

    let shown: Vec<_> = if confirmed.is_empty() {
        mem.hypotheses().iter().collect()
    } else {
        confirmed
    };

    if !shown.is_empty() {
        out.push_str("\n## 根拠\n\n");
        for h in shown {
            out.push_str(&format!("- {} [{:?}] {}\n", h.id, h.status, h.statement));
            for id in h.supporting.iter().chain(h.refuting.iter()) {
                let Some(e) = mem.evidence_by_id(*id) else {
                    continue;
                };
                let mark = if h.refuting.contains(id) {
                    "反証"
                } else {
                    "支持"
                };
                out.push_str(&format!(
                    "  - [{mark}] {} {}（出典: {}）\n",
                    e.id,
                    e.claim,
                    e.source.describe()
                ));
            }
            if let Some(v) = mem.latest_verification(h.id) {
                out.push_str(&format!("  - 検証: {:?} — {}\n", v.verdict, v.note));
            }
        }
    }

    // Decideの`then_verify`は「この行動が効いたかをどう確かめるか」。M15は確認まで
    // 走らせない（1ゴール1行動）ので、手段としてそのまま提示する。
    if let Some(hint) = mem
        .decisions()
        .last()
        .and_then(|d| d.verify_hint.as_deref())
        .filter(|h| !h.trim().is_empty())
    {
        out.push_str(&format!("\n## 確認方法\n\n{hint}\n"));
    }

    let open: Vec<_> = mem.open_questions().iter().collect();
    if !open.is_empty() {
        out.push_str("\n## 未解決の問い\n\n");
        for q in open {
            let mark = if q.blocking { "**[要判断]** " } else { "" };
            out.push_str(&format!("- {mark}{}\n", q.text));
        }
    }

    out
}

fn unresolved_reason(stop: &HivStop) -> String {
    match stop {
        HivStop::Decided => {
            // Decideまで進んだのに決定が無い＝スキーマは通ったが空だった場合の保険。
            "行動を決められなかった。".to_string()
        }
        HivStop::Blocked { reason } => format!(
            "調査を完了できなかった（{reason}）。確証されていない推測を結論として返すことは\
             しない。"
        ),
        HivStop::BudgetExhausted => "予算（調査ラウンド・コール数の上限）内では決着しなかった。\
             現時点で分かっているのは以下までである。"
            .to_string(),
        HivStop::Cancelled => "中断された。".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::types::{
        Decision, Evidence, SourceRef, Verdict, Verification, VerifyMethod,
    };

    fn confirmed_memory() -> WorkingMemory {
        let mut mem = WorkingMemory::new();
        let g = mem.add_goal("テストの失敗を直す", vec!["cargo testが緑".into()]);
        let h = mem.add_hypothesis(
            g,
            "原因はロック順序",
            vec!["単一スレッドでは緑".into()],
            0.8,
        );
        mem.add_evidence(
            |id| Evidence {
                id,
                claim: "2箇所で逆順にlockを取得している".to_string(),
                source: SourceRef::File {
                    path: "src/lib.rs".to_string(),
                    lines: (40, 52),
                },
                raw_ref: None,
            },
            Some((h, true)),
        );
        mem.record_verification(Verification {
            hyp: h,
            method: VerifyMethod::RunTest,
            verdict: Verdict::Confirms,
            missing: vec![],
            note: "並列時のみ再現した".into(),
        });
        mem.set_hypothesis_status(h, HypStatus::Confirmed);
        mem.add_decision(Decision {
            goal: g,
            action: "lockの取得順を揃える".to_string(),
            based_on: vec![h],
            verify_hint: Some("cargo test --workspace".to_string()),
        });
        mem
    }

    #[test]
    fn a_decided_goal_reports_the_action_with_its_grounded_evidence() {
        let out = render(&confirmed_memory(), &HivStop::Decided);
        assert!(out.contains("lockの取得順を揃える"), "{out}");
        assert!(out.contains("2箇所で逆順にlockを取得している"), "{out}");
        // 出典が必ず付く（監査性）。
        assert!(out.contains("src/lib.rs:40-52"), "{out}");
        assert!(out.contains("cargo test --workspace"), "{out}");
    }

    /// **§3.5**: 確証できなかったときに、それらしい結論をでっち上げない。
    #[test]
    fn without_a_confirmed_hypothesis_the_answer_says_so_explicitly() {
        let mut mem = WorkingMemory::new();
        let g = mem.add_goal("原因を特定する", vec![]);
        mem.add_hypothesis(g, "原因はキャッシュ", vec!["消せば直る".into()], 0.5);
        mem.add_open_question("再現条件が不明", true);

        let out = render(&mem, &HivStop::BudgetExhausted);
        assert!(out.contains("確証できた仮説はない"), "{out}");
        assert!(out.contains("予算"), "{out}");
        assert!(out.contains("**[要判断]** 再現条件が不明"), "{out}");
        // 未確証の仮説は「途中経過」として出すが、結論として書かない。
        assert!(out.contains("原因はキャッシュ"), "{out}");
    }

    #[test]
    fn a_blocked_goal_explains_why_it_stopped() {
        let mem = WorkingMemory::new();
        let out = render(
            &mem,
            &HivStop::Blocked {
                reason: "hypothesize が3回ともスキーマ検証に落ちた".to_string(),
            },
        );
        assert!(out.contains("スキーマ検証に落ちた"), "{out}");
        assert!(out.contains("推測を結論として返すことはしない"), "{out}");
    }
}
