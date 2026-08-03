//! 各フェーズの出力スキーマと、その受け皿になるRust型。
//! `plans/DESIGN-COGNITION.md` §3.3の「出力スキーマ」列・§3.4「typed structured outputによる強制」。
//!
//! # スキーマ規約（`plans/DESIGN.md` §構造化出力）
//!
//! 3プロバイダ・grammar制約デコード・小型モデルの最大公約数に合わせる:
//! **深さ≤2・union禁止・`additionalProperties:false`・`format`/`minLength`不使用・
//! enumと単純型中心**。unionが要る箇所は平坦化する（例:
//! `supports:HypId|refutes:HypId` → `{relation:"supports"|"refutes", hyp}`）。
//!
//! 手書きなのは、`harness-tools`のツール入力スキーマと同じ理由——schemars由来の
//! strict変換ユーティリティがワークスペースに無く、規約を満たす形を直接書く方が
//! 「何をモデルへ要求しているか」がその場で読めるため。Rust型との一致は
//! 往復デシリアライズのテストで固定する。

use harness_core::{OutputContract, Phase};
use serde::{Deserialize, Serialize};

/// そのフェーズが要求する出力契約。`Phase`ごとに1つ。
pub fn output_contract(phase: Phase) -> OutputContract {
    OutputContract::JsonSchema {
        name: format!("{}_output", phase.as_str()),
        schema: schema_for(phase),
        strict: true,
    }
}

fn schema_for(phase: Phase) -> serde_json::Value {
    match phase {
        Phase::Orient => object(
            &[
                ("restated_goal", string_prop()),
                ("done_criteria", string_array()),
                ("unknowns", string_array()),
            ],
            &["restated_goal", "done_criteria", "unknowns"],
        ),
        Phase::Hypothesize => object(
            &[(
                "hypotheses",
                array_of(object(
                    &[
                        ("statement", string_prop()),
                        ("predicts", string_array()),
                        ("confidence", number_prop()),
                    ],
                    // `predicts`をrequiredにすることで「反証条件の無い仮説」を
                    // スキーマレベルで作れなくする（§3.4「反証優先」）。
                    &["statement", "predicts", "confidence"],
                )),
            )],
            &["hypotheses"],
        ),
        Phase::Investigate => object(
            &[(
                "plan",
                array_of(object(
                    &[
                        ("source", string_prop()),
                        ("query", string_prop()),
                        ("expects", string_prop()),
                    ],
                    &["source", "query", "expects"],
                )),
            )],
            &["plan"],
        ),
        Phase::Distill => object(
            &[(
                "evidence",
                array_of(object(
                    &[
                        ("claim", string_prop()),
                        // union（supports|refutes）の平坦化。
                        ("relation", enum_prop(&["supports", "refutes", "neutral"])),
                        ("source", string_prop()),
                    ],
                    &["claim", "relation", "source"],
                )),
            )],
            &["evidence"],
        ),
        Phase::Verify => object(
            &[
                (
                    "verdict",
                    enum_prop(&["confirms", "refutes", "inconclusive"]),
                ),
                ("missing", string_array()),
                ("note", string_prop()),
            ],
            // confidenceは出させない（§3.4「遷移に不使用」）。出させると
            // モデルがそれを根拠として扱い始める。
            &["verdict", "missing", "note"],
        ),
        Phase::Critic => object(
            &[
                ("refuted", bool_prop()),
                ("weakest_link", string_prop()),
                ("counter_evidence_needed", string_array()),
            ],
            &["refuted", "weakest_link", "counter_evidence_needed"],
        ),
        Phase::Decide => object(
            &[("action", string_prop()), ("then_verify", string_prop())],
            &["action", "then_verify"],
        ),
    }
}

// --- スキーマ組み立ての小道具（規約を1箇所に閉じ込める） ---

fn object(props: &[(&str, serde_json::Value)], required: &[&str]) -> serde_json::Value {
    let map: serde_json::Map<String, serde_json::Value> = props
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect();
    serde_json::json!({
        "type": "object",
        "properties": map,
        "required": required,
        "additionalProperties": false,
    })
}

fn array_of(items: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "type": "array", "items": items })
}

fn string_prop() -> serde_json::Value {
    serde_json::json!({ "type": "string" })
}

fn number_prop() -> serde_json::Value {
    serde_json::json!({ "type": "number" })
}

fn bool_prop() -> serde_json::Value {
    serde_json::json!({ "type": "boolean" })
}

fn string_array() -> serde_json::Value {
    array_of(string_prop())
}

fn enum_prop(values: &[&str]) -> serde_json::Value {
    serde_json::json!({ "type": "string", "enum": values })
}

// --- 受け皿のRust型（M15の状態機械がここへデシリアライズする） ---

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrientOutput {
    pub restated_goal: String,
    pub done_criteria: Vec<String>,
    pub unknowns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HypothesizeOutput {
    pub hypotheses: Vec<ProposedHypothesis>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProposedHypothesis {
    pub statement: String,
    pub predicts: Vec<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvestigateOutput {
    pub plan: Vec<InvestigationStep>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvestigationStep {
    /// 情報源のid（内蔵ツール名またはMCPの`mcp/<server>/<tool>`。カタログはM16）。
    pub source: String,
    pub query: String,
    pub expects: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DistillOutput {
    pub evidence: Vec<DistilledEvidence>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DistilledEvidence {
    pub claim: String,
    pub relation: EvidenceRelation,
    pub source: String,
}

/// `supports:HypId|refutes:HypId`の平坦化（スキーマ規約のunion禁止）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRelation {
    Supports,
    Refutes,
    Neutral,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifyOutput {
    pub verdict: VerifyVerdict,
    pub missing: Vec<String>,
    pub note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyVerdict {
    Confirms,
    Refutes,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CriticOutput {
    pub refuted: bool,
    pub weakest_link: String,
    pub counter_evidence_needed: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecideOutput {
    pub action: String,
    pub then_verify: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema(phase: Phase) -> serde_json::Value {
        match output_contract(phase) {
            OutputContract::JsonSchema { schema, .. } => schema,
            OutputContract::JsonObject => panic!("phases must declare a schema"),
        }
    }

    /// スキーマ規約（`plans/DESIGN.md` §構造化出力）を全フェーズについて機械的に検査する。
    /// 小型モデル・grammar制約デコードで通らない形を書いてしまうと、認知レイヤーの
    /// 全フェーズが動かなくなるので、規約はコードで縛る。
    #[test]
    fn every_phase_schema_satisfies_the_schema_conventions() {
        for phase in Phase::ALL {
            let s = schema(phase);
            check_conventions(&s, &mut 0, phase);
        }
    }

    fn check_conventions(node: &serde_json::Value, depth: &mut usize, phase: Phase) {
        let Some(obj) = node.as_object() else { return };

        // union禁止: `type`は常に単一の文字列（`["string","null"]`のような配列にしない）。
        if let Some(t) = obj.get("type") {
            assert!(t.is_string(), "{phase}: union type is not allowed: {t}");
        }
        for banned in [
            "oneOf",
            "anyOf",
            "allOf",
            "$ref",
            "$defs",
            "format",
            "minLength",
        ] {
            assert!(
                !obj.contains_key(banned),
                "{phase}: `{banned}` is not allowed by the schema conventions"
            );
        }

        if obj.get("type").and_then(|t| t.as_str()) == Some("object") {
            assert_eq!(
                obj.get("additionalProperties"),
                Some(&serde_json::Value::Bool(false)),
                "{phase}: objects must set additionalProperties:false"
            );
            // strictは全プロパティがrequiredであることを要求する。
            let props: Vec<&String> = obj["properties"].as_object().unwrap().keys().collect();
            let required: Vec<&str> = obj["required"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            assert_eq!(
                props.len(),
                required.len(),
                "{phase}: every property must be required under strict mode"
            );

            *depth += 1;
            assert!(*depth <= 2, "{phase}: schema depth must stay <= 2");
            for v in obj["properties"].as_object().unwrap().values() {
                check_conventions(v, &mut depth.clone(), phase);
            }
        }

        if obj.get("type").and_then(|t| t.as_str()) == Some("array") {
            check_conventions(&obj["items"], depth, phase);
        }
    }

    /// 契約名はフェーズ名から機械的に決まる（M15のログ・デバッグで対応が付くように）。
    #[test]
    fn contract_names_are_derived_from_the_phase_name() {
        for phase in Phase::ALL {
            let OutputContract::JsonSchema { name, strict, .. } = output_contract(phase) else {
                panic!("phases must declare a schema");
            };
            assert_eq!(name, format!("{}_output", phase.as_str()));
            assert!(strict);
        }
    }

    /// スキーマとRust型が一致していること。片方だけ直すと、モデルは正しく答えているのに
    /// ハーネスがデシリアライズに失敗する（＝原因が最も分かりにくい壊れ方）。
    #[test]
    fn schema_shaped_json_deserializes_into_the_matching_rust_type() {
        let orient: OrientOutput = serde_json::from_value(serde_json::json!({
            "restated_goal": "テストの失敗原因を特定する",
            "done_criteria": ["原因が1つに絞れている"],
            "unknowns": ["並列時のみ失敗する理由"]
        }))
        .unwrap();
        assert_eq!(orient.unknowns.len(), 1);

        let hyp: HypothesizeOutput = serde_json::from_value(serde_json::json!({
            "hypotheses": [
                { "statement": "原因はロック順序", "predicts": ["単一スレッドでは緑"], "confidence": 0.7 }
            ]
        }))
        .unwrap();
        assert_eq!(hyp.hypotheses[0].predicts, vec!["単一スレッドでは緑"]);

        let inv: InvestigateOutput = serde_json::from_value(serde_json::json!({
            "plan": [{ "source": "read_file", "query": "src/lib.rs", "expects": "lockの取得順" }]
        }))
        .unwrap();
        assert_eq!(inv.plan[0].source, "read_file");

        let distill: DistillOutput = serde_json::from_value(serde_json::json!({
            "evidence": [{ "claim": "2箇所で逆順に取得している", "relation": "supports", "source": "src/lib.rs:40-52" }]
        }))
        .unwrap();
        assert_eq!(distill.evidence[0].relation, EvidenceRelation::Supports);

        let verify: VerifyOutput = serde_json::from_value(serde_json::json!({
            "verdict": "confirms", "missing": [], "note": "再現した"
        }))
        .unwrap();
        assert_eq!(verify.verdict, VerifyVerdict::Confirms);

        let critic: CriticOutput = serde_json::from_value(serde_json::json!({
            "refuted": false, "weakest_link": "再現が1回のみ", "counter_evidence_needed": ["連続10回"]
        }))
        .unwrap();
        assert!(!critic.refuted);

        let decide: DecideOutput = serde_json::from_value(serde_json::json!({
            "action": "ロック順序を揃える", "then_verify": "cargo test --workspace"
        }))
        .unwrap();
        assert_eq!(decide.then_verify, "cargo test --workspace");
    }

    /// enumの綴りがスキーマとserdeで一致していること（ずれるとモデルの正答が
    /// デシリアライズで落ちる）。
    #[test]
    fn enum_spellings_match_between_schema_and_serde() {
        let verify = schema(Phase::Verify);
        let allowed: Vec<&str> = verify["properties"]["verdict"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        for value in &allowed {
            let parsed: VerifyVerdict =
                serde_json::from_value(serde_json::Value::String((*value).to_string())).unwrap();
            assert_eq!(serde_json::to_value(parsed).unwrap(), *value);
        }
        assert_eq!(allowed, vec!["confirms", "refutes", "inconclusive"]);

        let distill = schema(Phase::Distill);
        let relations: Vec<&str> = distill["properties"]["evidence"]["items"]["properties"]
            ["relation"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        for value in &relations {
            let parsed: EvidenceRelation =
                serde_json::from_value(serde_json::Value::String((*value).to_string())).unwrap();
            assert_eq!(serde_json::to_value(parsed).unwrap(), *value);
        }
    }

    /// §3.4「仮説なしに調査へ進めない」の、スキーマ側の担保。`predicts`が必須なので
    /// 反証条件の無い仮説はそもそもスキーマ適合しない。
    #[test]
    fn hypothesize_schema_requires_falsification_conditions() {
        let s = schema(Phase::Hypothesize);
        let required: Vec<&str> = s["properties"]["hypotheses"]["items"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(required.contains(&"predicts"), "{required:?}");
    }

    /// §3.4「confidenceは遷移ゲートに使わない」の、スキーマ側の担保。Verifyには
    /// confidenceを出させない。
    #[test]
    fn verify_schema_does_not_ask_for_a_self_reported_confidence() {
        let s = schema(Phase::Verify);
        assert!(s["properties"].get("confidence").is_none(), "{s}");
    }
}
