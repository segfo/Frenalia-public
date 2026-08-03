//! 構造化出力（`OutputContract`）をプロバイダの実機構へ写す、**唯一の判断点**。
//! `plans/DESIGN.md` §プロバイダ抽象「構造化出力（`OutputContract` の写像）」の表がここに来る。
//!
//! # なぜアダプタではなくここに置くか
//!
//! 写像表を`openai.rs`と`anthropic.rs`へ書き写すと、片方だけ直る事故になる
//! （[`docs/CODE-STRUCTURE-RULES.md`](../../../docs/CODE-STRUCTURE-RULES.md) 規則5
//! 「同じロジックのコピーを作らない」）。判断（[`SchemaStrategy::select`]）と、その結果の
//! **IRレベルの書き換え**（[`apply_schema_strategy`]）をここ1箇所に置き、アダプタは
//! 「`Native`をワイヤ形式にする」ことだけを担う。降格経路（`ForcedTool`/`PromptEmbedded`）は
//! IRの書き換えだけで完結するので、アダプタ側に分岐が増えない。
//!
//! # 応答側の非対称性
//!
//! `ForcedTool`降格では、モデルの答えが**テキストではなく`tool_use`ブロック**として返る。
//! 認知レイヤーからプロバイダ差が見えてはならないので、[`unwrap_forced_tool_stream`]が
//! それを`Native`と同じ「JSONテキスト」の`StreamEvent`列へ戻す。

use futures::stream::{BoxStream, StreamExt};

use crate::provider::{
    BlockKind, CompletionRequest, OutputContract, ProviderCapabilities, ProviderError, StreamEvent,
    SystemBlock, ToolChoice,
};
use crate::tool::ToolSpec;

/// `PromptEmbedded`降格でスキーマを説明するsystemブロックの前置き。
const PROMPT_EMBED_PREAMBLE: &str =
    "回答は次のJSON Schemaに厳密に適合する**JSONオブジェクト単体**で出力すること。\
 コードフェンス・前置き・後書きを一切付けない。";

/// `OutputContract`をどの機構で強制するか（`plans/DESIGN.md` §構造化出力の写像表）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaStrategy {
    /// `output`指定なし。**リクエストを一切書き換えない**。
    None,
    /// `response_format:{type:"json_schema",...}` / Anthropic structured outputs。
    Native,
    /// スキーマを`input_schema`とする単一ツール + `tool_choice`強制。応答は
    /// [`unwrap_forced_tool_stream`]でテキストへ戻す。
    ForcedTool { name: String },
    /// systemへスキーマを埋め込み、検証はハーネス側で行う（最終手段）。
    PromptEmbedded,
}

impl SchemaStrategy {
    /// 写像表そのもの。`has_tools`は「このコールで実ツールを呼ばせるか」。
    ///
    /// 【T7】スキーマ強制と実ツール呼び出しの同時可否はプロバイダ依存なので、
    /// 両立できないプロバイダで両方が要求されたら**ツールを黙って捨てない**方（＝スキーマを
    /// プロンプト降格）へ倒す。ツールを落とすとモデルが調査できなくなり、失敗が
    /// 「何も観測しないまま結論する」という最も気付きにくい形で出るため。
    pub fn select(
        caps: &ProviderCapabilities,
        output: Option<&OutputContract>,
        has_tools: bool,
    ) -> SchemaStrategy {
        let Some(output) = output else {
            return SchemaStrategy::None;
        };
        if has_tools && !caps.schema_with_tools {
            return SchemaStrategy::PromptEmbedded;
        }
        if caps.native_json_schema {
            return SchemaStrategy::Native;
        }
        // ツール強制降格は「単一ツールだけを候補に置く」ことで成立するので、
        // 実ツールが同居するコールには使えない。
        if caps.forced_tool_choice && !has_tools {
            if let OutputContract::JsonSchema { name, .. } = output {
                return SchemaStrategy::ForcedTool { name: name.clone() };
            }
        }
        SchemaStrategy::PromptEmbedded
    }
}

/// `req`をプロバイダが実際に送れる形へ書き換え、採った戦略を返す。
///
/// `req.output`が`None`のときは[`SchemaStrategy::None`]を返し、**`req`を1バイトも触らない**。
/// 素朴ループ（`CognitionLevel::Off`）の全リクエストがこの経路なので、この不変条件が
/// M13で確立したバイト等価性（`docs/phases/cognition/M13-executor-extraction.md`）を守る。
pub fn apply_schema_strategy(
    req: &mut CompletionRequest,
    caps: &ProviderCapabilities,
) -> SchemaStrategy {
    let strategy = SchemaStrategy::select(caps, req.output.as_ref(), !req.tools.is_empty());
    match &strategy {
        SchemaStrategy::None | SchemaStrategy::Native => {}
        SchemaStrategy::ForcedTool { name } => {
            let (description, schema) = match &req.output {
                Some(OutputContract::JsonSchema { name, schema, .. }) => (
                    format!("Return the answer as the arguments of this tool ({name})."),
                    schema.clone(),
                ),
                // `select`が`ForcedTool`を返すのは`JsonSchema`のときだけ。
                _ => unreachable!("ForcedTool is only selected for OutputContract::JsonSchema"),
            };
            req.tools.push(ToolSpec {
                name: name.clone(),
                description,
                input_schema: schema,
            });
            req.tool_choice = ToolChoice::Tool(name.clone());
            req.output = None;
        }
        SchemaStrategy::PromptEmbedded => {
            req.system.push(SystemBlock {
                text: prompt_embed_text(req.output.as_ref().expect("checked by select")),
                // 台帳スライスと違いフェーズ内で不変だが、`system`末尾＝キャッシュ
                // ブレークポイント位置なので、既存の`system_blocks_for`と同じくtrueにする。
                cache: true,
            });
            req.output = None;
        }
    }
    strategy
}

fn prompt_embed_text(output: &OutputContract) -> String {
    match output {
        OutputContract::JsonSchema { name, schema, .. } => {
            let pretty = serde_json::to_string_pretty(schema)
                .unwrap_or_else(|_| "{\"type\":\"object\"}".to_string());
            format!("{PROMPT_EMBED_PREAMBLE}\n\nスキーマ名: {name}\n\n```json\n{pretty}\n```")
        }
        OutputContract::JsonObject => {
            format!("{PROMPT_EMBED_PREAMBLE}\n\n（スキーマ指定なし。任意のJSONオブジェクト。）")
        }
    }
}

/// `ForcedTool`降格で返ってきた`tool_use`ブロックを、`Native`と同じテキストの
/// `StreamEvent`列へ戻す。
///
/// 変換するのは名前が一致する`tool_use`ブロックだけで、他のブロック（並走する実ツール
/// 呼び出し等）はそのまま流す。ブロックの`index`は保存するので、呼び出し側の
/// 蓄積ロジック（`harness_engine::turn`の`BlockAccum`）はそのまま動く。
pub fn unwrap_forced_tool_stream(
    stream: BoxStream<'static, Result<StreamEvent, ProviderError>>,
    tool_name: String,
) -> BoxStream<'static, Result<StreamEvent, ProviderError>> {
    // 対象ブロックのindexを覚えておき、そのindexのToolInputDeltaだけをTextDeltaへ写す。
    let mut forced_index: Option<usize> = None;
    let mapped = stream.map(move |ev| {
        let Ok(ev) = ev else {
            return ev;
        };
        Ok(match ev {
            StreamEvent::BlockStart {
                index,
                kind: BlockKind::ToolUse { id: _, name },
            } if name == tool_name => {
                forced_index = Some(index);
                StreamEvent::BlockStart {
                    index,
                    kind: BlockKind::Text,
                }
            }
            StreamEvent::ToolInputDelta {
                index,
                json_fragment,
            } if forced_index == Some(index) => StreamEvent::TextDelta {
                index,
                text: json_fragment,
            },
            other => other,
        })
    });
    Box::pin(mapped)
}

/// `ForcedTool`降格を使ったターンで、`stop_reason`が`ToolUse`になって返るのを`EndTurn`へ
/// 戻す必要があるかの判定に使う、応答側の目印。
///
/// `unwrap_forced_tool_stream`はブロック種別を書き換えるが、`Done`の`stop_reason`までは
/// 触らない（プロバイダが実際に何を返したかの情報を消さないため）。呼び出し側
/// （認知レイヤー、M15）は「スキーマ強制コールに`tool_calls`は現れない」ことを
/// [`SchemaStrategy`]から知れるので、`stop_reason`を見て分岐しない。
pub fn is_degraded_to_tool(strategy: &SchemaStrategy) -> bool {
    matches!(strategy, SchemaStrategy::ForcedTool { .. })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{ContentBlock, Message, Role};
    use crate::provider::{Sampling, StopReason, Usage};

    fn caps(native: bool, forced: bool, with_tools: bool) -> ProviderCapabilities {
        ProviderCapabilities {
            native_json_schema: native,
            forced_tool_choice: forced,
            schema_with_thinking: true,
            schema_with_tools: with_tools,
            prompt_caching: false,
            context_window: 128_000,
        }
    }

    fn contract() -> OutputContract {
        OutputContract::JsonSchema {
            name: "hypothesize_output".to_string(),
            schema: serde_json::json!({
                "type": "object",
                "properties": { "statement": { "type": "string" } },
                "required": ["statement"],
                "additionalProperties": false
            }),
            strict: true,
        }
    }

    fn request(output: Option<OutputContract>, tools: Vec<ToolSpec>) -> CompletionRequest {
        CompletionRequest {
            system: vec![SystemBlock {
                text: "env".to_string(),
                cache: true,
            }],
            messages: vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text("go".to_string())],
            }],
            tools,
            tool_choice: ToolChoice::Auto,
            output,
            parallel_tool_calls: Some(false),
            max_tokens: 512,
            sampling: Sampling::default(),
            model: "m".to_string(),
        }
    }

    fn read_tool() -> ToolSpec {
        ToolSpec {
            name: "read_file".to_string(),
            description: "read".to_string(),
            input_schema: serde_json::json!({ "type": "object" }),
        }
    }

    /// 写像表（`plans/DESIGN.md` §構造化出力）そのもの。行が増減したらここが落ちる。
    #[test]
    fn strategy_table_matches_the_design_document() {
        let c = contract();
        // output指定なし → 常にNone（現行の全経路）
        assert_eq!(
            SchemaStrategy::select(&caps(true, true, true), None, false),
            SchemaStrategy::None
        );
        // OpenAI / LMStudio（native可）
        assert_eq!(
            SchemaStrategy::select(&caps(true, true, true), Some(&c), false),
            SchemaStrategy::Native
        );
        // Anthropic（native不可・tool強制可・ツール無し）→ 単一ツール強制へ降格
        assert_eq!(
            SchemaStrategy::select(&caps(false, true, false), Some(&c), false),
            SchemaStrategy::ForcedTool {
                name: "hypothesize_output".to_string()
            }
        );
        // いずれも不可 → プロンプト埋込
        assert_eq!(
            SchemaStrategy::select(&caps(false, false, false), Some(&c), false),
            SchemaStrategy::PromptEmbedded
        );
        // 実ツールが同居し、かつ融合不可 → スキーマ側を降格（ツールは残す）
        assert_eq!(
            SchemaStrategy::select(&caps(true, true, false), Some(&c), true),
            SchemaStrategy::PromptEmbedded
        );
        // 融合可なら実ツールがあってもnative
        assert_eq!(
            SchemaStrategy::select(&caps(true, true, true), Some(&c), true),
            SchemaStrategy::Native
        );
        // ツール強制降格は実ツールと同居できない（単一ツールだけを候補に置く機構のため）
        assert_eq!(
            SchemaStrategy::select(&caps(false, true, true), Some(&c), true),
            SchemaStrategy::PromptEmbedded
        );
        // JsonObject（スキーマ無し）はツール強制で表現できない
        assert_eq!(
            SchemaStrategy::select(
                &caps(false, true, false),
                Some(&OutputContract::JsonObject),
                false
            ),
            SchemaStrategy::PromptEmbedded
        );
    }

    /// **M13のバイト等価性を守る不変条件**: `output`が`None`ならリクエストは無改変。
    /// 素朴ループの全リクエストがこの経路なので、ここが破れると既存のgolden transcriptが
    /// 全て意味を失う。
    #[test]
    fn no_contract_leaves_the_request_untouched() {
        let mut req = request(None, vec![read_tool()]);
        let before = req.clone();
        let strategy = apply_schema_strategy(&mut req, &caps(true, true, true));
        assert_eq!(strategy, SchemaStrategy::None);
        assert_eq!(req, before);
    }

    /// nativeはIRを書き換えない（アダプタが`output`をそのままワイヤ形式へ写す）。
    #[test]
    fn native_leaves_the_contract_in_place_for_the_adapter() {
        let mut req = request(Some(contract()), vec![]);
        let before = req.clone();
        let strategy = apply_schema_strategy(&mut req, &caps(true, true, true));
        assert_eq!(strategy, SchemaStrategy::Native);
        assert_eq!(req, before);
    }

    #[test]
    fn forced_tool_rewrites_the_request_into_a_single_forced_tool() {
        let mut req = request(Some(contract()), vec![]);
        let strategy = apply_schema_strategy(&mut req, &caps(false, true, false));
        assert_eq!(
            strategy,
            SchemaStrategy::ForcedTool {
                name: "hypothesize_output".to_string()
            }
        );
        assert!(is_degraded_to_tool(&strategy));
        assert_eq!(req.tools.len(), 1);
        assert_eq!(req.tools[0].name, "hypothesize_output");
        assert_eq!(
            req.tools[0].input_schema["properties"]["statement"]["type"],
            "string"
        );
        assert_eq!(
            req.tool_choice,
            ToolChoice::Tool("hypothesize_output".to_string())
        );
        // アダプタが二重に強制しないよう、契約自体は消す。
        assert!(req.output.is_none());
    }

    #[test]
    fn prompt_embedded_appends_the_schema_to_system_and_keeps_tools() {
        let mut req = request(Some(contract()), vec![read_tool()]);
        let strategy = apply_schema_strategy(&mut req, &caps(true, true, false));
        assert_eq!(strategy, SchemaStrategy::PromptEmbedded);
        assert!(req.output.is_none());
        // ツールは落とさない（落とすと「何も観測せずに結論する」失敗になる）。
        assert_eq!(req.tools.len(), 1);
        assert_eq!(req.tools[0].name, "read_file");
        assert_eq!(req.system.len(), 2);
        let embedded = &req.system[1].text;
        assert!(embedded.contains("hypothesize_output"), "{embedded}");
        assert!(embedded.contains("additionalProperties"), "{embedded}");
    }

    fn events(evs: Vec<StreamEvent>) -> BoxStream<'static, Result<StreamEvent, ProviderError>> {
        Box::pin(futures::stream::iter(evs.into_iter().map(Ok)))
    }

    fn drain(s: BoxStream<'static, Result<StreamEvent, ProviderError>>) -> Vec<StreamEvent> {
        futures::executor::block_on(s.map(|e| e.unwrap()).collect())
    }

    /// 降格経路の応答が、native経路と**同じ形**（テキストブロック1枚にJSON）で見えること。
    /// 認知レイヤーがプロバイダ差を意識しないための要。
    #[test]
    fn forced_tool_response_is_normalized_back_to_text() {
        let stream = events(vec![
            StreamEvent::BlockStart {
                index: 0,
                kind: BlockKind::ToolUse {
                    id: "call_1".to_string(),
                    name: "hypothesize_output".to_string(),
                },
            },
            StreamEvent::ToolInputDelta {
                index: 0,
                json_fragment: "{\"statement\":".to_string(),
            },
            StreamEvent::ToolInputDelta {
                index: 0,
                json_fragment: "\"it is X\"}".to_string(),
            },
            StreamEvent::BlockStop { index: 0 },
            StreamEvent::Done {
                stop_reason: StopReason::ToolUse,
                usage: Usage::default(),
            },
        ]);

        let out = drain(unwrap_forced_tool_stream(
            stream,
            "hypothesize_output".to_string(),
        ));

        assert_eq!(
            out[0],
            StreamEvent::BlockStart {
                index: 0,
                kind: BlockKind::Text
            }
        );
        let text: String = out
            .iter()
            .filter_map(|e| match e {
                StreamEvent::TextDelta { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(text, r#"{"statement":"it is X"}"#);
        assert!(!out
            .iter()
            .any(|e| matches!(e, StreamEvent::ToolInputDelta { .. })));
    }

    /// 名前が一致しないツール呼び出し（実ツール）は素通しする。
    #[test]
    fn unrelated_tool_blocks_pass_through_untouched() {
        let original = vec![
            StreamEvent::BlockStart {
                index: 0,
                kind: BlockKind::ToolUse {
                    id: "call_1".to_string(),
                    name: "read_file".to_string(),
                },
            },
            StreamEvent::ToolInputDelta {
                index: 0,
                json_fragment: "{\"path\":\"a.txt\"}".to_string(),
            },
            StreamEvent::BlockStop { index: 0 },
        ];
        let out = drain(unwrap_forced_tool_stream(
            events(original.clone()),
            "hypothesize_output".to_string(),
        ));
        assert_eq!(out, original);
    }
}
