//! フェーズ出力の抽出と意味検証。`plans/DESIGN-COGNITION.md` §3.4
//! 「typed structured output による強制」のハーネス側。
//!
//! # なぜスキーマ強制の上に検証層が要るか
//!
//! `OutputContract`の写像（`harness_core::schema`）は3経路あり、そのうち
//! `PromptEmbedded`（native強制もツール強制も使えないプロバイダ）は**モデルが従うとは
//! 限らない**。さらにJSON Schemaで表現できるのは形だけで、「`predicts`が空配列でない」
//! ような**意味の制約**は表現できない（`minItems`はスキーマ規約で禁止＝小型モデルの
//! grammar制約デコードで通らないため）。
//!
//! したがって「仮説なしに調査へ進めない」（§3.4）を実際に担保するのはここの検証関数で、
//! 落ちたら[`crate::hiv::call`]が理由を添えて同じフェーズを再実行する。

use serde::de::DeserializeOwned;

use crate::memory::types::EvidenceId;
use crate::schema::{
    DecideOutput, DistillOutput, HypothesizeOutput, InvestigateOutput, VerifyOutput,
};

/// モデル出力のテキストからフェーズ出力を取り出す。
///
/// 失敗時の`Err`は**そのまま再実行時の修復指示**としてモデルへ返る文字列なので、
/// 「何がどう不正だったか」を具体的に書く（「invalid json」だけでは直しようがない）。
pub(crate) fn parse_phase_output<T: DeserializeOwned>(text: &str) -> Result<T, String> {
    let Some(json) = extract_json_object(text) else {
        return Err(
            "出力にJSONオブジェクトが1つも含まれていなかった。前置き・後書き・コードフェンスを\
             付けず、JSONオブジェクト単体で返すこと。"
                .to_string(),
        );
    };
    serde_json::from_str::<T>(json).map_err(|e| {
        format!("JSONはスキーマに適合していなかった（{e}）。必須フィールドを省略せず、指定の型で返すこと。")
    })
}

/// テキスト中の最初の**均衡した**JSONオブジェクトを切り出す。
///
/// コードフェンス（```json ... ```）や前置きの1文を付けてくるモデルがあり、
/// それだけで全フェーズが止まるのは割に合わない。文字列リテラル中の`{`/`}`と
/// エスケープを数えないよう、深さを数えながら走査する。
fn extract_json_object(text: &str) -> Option<&str> {
    let start = text.find('{')?;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, ch) in text[start..].char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[start..start + offset + ch.len_utf8()]);
                }
            }
            _ => {}
        }
    }
    None
}

/// **§3.4「反証優先」の担保点**。反証条件を書けない主張は仮説として受け取らない。
pub(crate) fn validate_hypothesize(out: &HypothesizeOutput) -> Result<(), String> {
    if out.hypotheses.is_empty() {
        return Err("hypothesesが空だった。少なくとも1つの仮説を出すこと。".to_string());
    }
    for (i, h) in out.hypotheses.iter().enumerate() {
        if h.statement.trim().is_empty() {
            return Err(format!("hypotheses[{i}].statementが空だった。"));
        }
        if h.predicts.iter().all(|p| p.trim().is_empty()) {
            return Err(format!(
                "hypotheses[{i}].predicts（反証条件）が空だった。「何が観測されればこの仮説が\
                 偽だと分かるか」を最低1つ書くこと。書けない主張は仮説として出さない。"
            ));
        }
    }
    Ok(())
}

/// 蒸留は**空を許す**（プロンプトが「関係する記述が無ければ空で返す」と指示しており、
/// 無理に何かを書かせると生出力に無い事実をでっち上げさせることになる）。
pub(crate) fn validate_distill(out: &DistillOutput) -> Result<(), String> {
    for (i, e) in out.evidence.iter().enumerate() {
        if e.claim.trim().is_empty() {
            return Err(format!(
                "evidence[{i}].claimが空だった。事実を書けないなら、その要素自体を出さない。"
            ));
        }
    }
    Ok(())
}

/// `note`（判定の理由）を必須にする。理由の無い判定は台帳にも最終回答にも使えず、
/// 「根拠なく確証した」ことを後から検出できなくなる。
pub(crate) fn validate_verify(out: &VerifyOutput) -> Result<(), String> {
    if out.note.trim().is_empty() {
        return Err(
            "noteが空だった。どの証拠をどう読んでその判定に至ったかを1〜2文で書くこと。"
                .to_string(),
        );
    }
    Ok(())
}

/// 調査計画は best-effort（実際の産物はツール呼び出しの方）だが、出したなら中身を伴うこと。
pub(crate) fn validate_investigate(out: &InvestigateOutput) -> Result<(), String> {
    for (i, step) in out.plan.iter().enumerate() {
        if step.source.trim().is_empty() {
            return Err(format!(
                "plan[{i}].sourceが空だった。使う情報源（ツール名）を書くこと。"
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_decide(out: &DecideOutput) -> Result<(), String> {
    if out.action.trim().is_empty() {
        return Err("actionが空だった。次に取る行動を1つ書くこと。".to_string());
    }
    Ok(())
}

/// Distillが申告した`contradicts`（E番号）のうち、**台帳に実在するものだけ**を返す。
///
/// スキーマ検証に落とさず黙って捨てるのは、矛盾の申告が蒸留の主産物ではないため
/// ——存在しない番号を1つ書いただけで蒸留全体をやり直させると、正しく抽出できた事実まで
/// 失うことになる。捏造されたIDを**台帳へ通さない**ことだけをここで担保する
/// （`crate::hiv::evidence`の「出典はハーネスが決める」と同じ姿勢）。
///
/// `known`は台帳に実在する証拠ID、`own`はいま積もうとしている証拠自身（自己参照の除外用）。
pub(crate) fn resolve_contradicts(
    labels: &[String],
    known: &[EvidenceId],
    own: Option<EvidenceId>,
) -> Vec<EvidenceId> {
    let mut out: Vec<EvidenceId> = Vec::new();
    for label in labels {
        let Some(id) = known
            .iter()
            .find(|id| id.label().eq_ignore_ascii_case(label.trim()))
        else {
            continue;
        };
        if Some(*id) == own || out.contains(id) {
            continue;
        }
        out.push(*id);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::ProposedHypothesis;

    fn hypothesize(predicts: Vec<&str>) -> HypothesizeOutput {
        HypothesizeOutput {
            hypotheses: vec![ProposedHypothesis {
                statement: "原因はロック順序".to_string(),
                predicts: predicts.into_iter().map(str::to_string).collect(),
                confidence: 0.7,
            }],
        }
    }

    #[test]
    fn plain_json_object_round_trips() {
        let out: HypothesizeOutput = parse_phase_output(
            r#"{"hypotheses":[{"statement":"X","predicts":["Y"],"confidence":0.5}]}"#,
        )
        .unwrap();
        assert_eq!(out.hypotheses[0].statement, "X");
    }

    /// コードフェンスや前置きを付けてくるモデルでフェーズが止まらないこと。
    #[test]
    fn fenced_and_prefixed_output_is_still_extracted() {
        for text in [
            "```json\n{\"action\":\"直す\",\"then_verify\":\"cargo test\"}\n```",
            "承知しました。\n{\"action\":\"直す\",\"then_verify\":\"cargo test\"}",
            "{\"action\":\"直す\",\"then_verify\":\"cargo test\"}\nよろしいですか？",
        ] {
            let out: DecideOutput = parse_phase_output(text).unwrap();
            assert_eq!(out.action, "直す");
        }
    }

    /// 文字列リテラル中の波括弧で切り出しを打ち切らないこと。
    #[test]
    fn braces_inside_strings_do_not_terminate_the_object() {
        let out: DecideOutput =
            parse_phase_output(r#"{"action":"`if x { y }` を直す","then_verify":"cargo test"}"#)
                .unwrap();
        assert_eq!(out.action, "`if x { y }` を直す");
        assert_eq!(out.then_verify, "cargo test");
    }

    #[test]
    fn missing_json_reports_a_repairable_reason() {
        let err = parse_phase_output::<DecideOutput>("すみません、分かりません。").unwrap_err();
        assert!(err.contains("JSONオブジェクト"), "{err}");
    }

    /// **M15の受入条件の片方**: 反証条件の無い仮説は受け取らない。
    #[test]
    fn hypothesis_without_falsification_conditions_is_rejected() {
        let err = validate_hypothesize(&hypothesize(vec![])).unwrap_err();
        assert!(err.contains("predicts"), "{err}");
        // 空白だけの反証条件も「書いた」ことにしない。
        let err = validate_hypothesize(&hypothesize(vec!["   "])).unwrap_err();
        assert!(err.contains("predicts"), "{err}");
        validate_hypothesize(&hypothesize(vec!["単一スレッドでは緑"])).unwrap();
    }

    #[test]
    fn empty_hypothesis_list_is_rejected() {
        let err = validate_hypothesize(&HypothesizeOutput { hypotheses: vec![] }).unwrap_err();
        assert!(err.contains("hypotheses"), "{err}");
    }

    /// 蒸留の空出力は正当（生出力に関係する記述が無かった、という結果）。
    #[test]
    fn empty_distillation_is_accepted() {
        validate_distill(&DistillOutput { evidence: vec![] }).unwrap();
    }

    /// **§4.3の矛盾検出の入口**: 台帳に実在するE番号だけを通す。捏造・自己参照・重複は捨てる。
    #[test]
    fn only_existing_evidence_ids_are_accepted_as_contradictions() {
        // 自分自身（E7）も台帳には既に載っている（先に積んでからIDを解決するため）。
        let known = [EvidenceId(3), EvidenceId(5), EvidenceId(7)];
        let labels = [
            "E3".to_string(),   // 実在
            "E9".to_string(),   // 捏造
            "E5".to_string(),   // 実在
            "E3".to_string(),   // 重複
            "E7".to_string(),   // いま積もうとしている自分自身
            "".to_string(),     // 空
            "H3".to_string(),   // 種別違い（仮説ID）
        ];
        let resolved = resolve_contradicts(&labels, &known, Some(EvidenceId(7)));
        assert_eq!(resolved, vec![EvidenceId(3), EvidenceId(5)]);
    }

    /// 前後の空白と大小文字は吸収する（モデルの表記ゆれで矛盾を取り逃さない）。
    #[test]
    fn contradiction_labels_tolerate_whitespace_and_case() {
        let known = [EvidenceId(3)];
        assert_eq!(
            resolve_contradicts(&[" e3 ".to_string()], &known, None),
            vec![EvidenceId(3)]
        );
    }
}
