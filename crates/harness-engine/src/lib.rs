//! harness-engine: 中核ループの入口。`plans/DESIGN.md` §エージェントループ参照。
//!
//! M3で `run_single_turn`（単発ターン、M2まで）に加え `run_agent_loop` を追加した。
//! M4で `PermissionArbiter`（§パーミッション（承認）システム）を実装し、`run_agent_loop`が
//! 各`ToolUse`の実行前に必ず問い合わせるようにした（§エージェントループ「唯一の強制点」）。
//! 拒否されたツール呼び出しは実行されず、エラーの`ToolResult`を合成して履歴へ積み戻す
//! （§エージェントループ 手順4「拒否→エラーToolResultを合成」）。
//! **M4時点のスコープ外**: cap-stdによる読取スコープ反転モード（whitelist/blacklist、M11）・
//! 対話TUIの承認モーダル（M7、そのため`decide`は常にヘッドレス相当で決定的に判定する）・
//! キャンセル整合（M9）・コンテキスト圧縮（M9）。

pub mod permission;

use futures::StreamExt;

use harness_core::{
    BlockKind, CompletionRequest, ContentBlock, LlmProvider, Message, ProviderError, Role,
    Sampling, StopReason, StreamEvent, SystemBlock, ToolChoice, ToolCtx, ToolOutput, Usage,
};
use harness_tools::ToolRegistry;

pub use permission::{
    arg_repr, parse_allowlist_rule, AllowlistRule, Decision, PermissionArbiter, PermissionMode,
};

/// 会話のIR履歴。
#[derive(Debug, Clone, Default)]
pub struct ConversationState {
    pub system: Vec<SystemBlock>,
    pub messages: Vec<Message>,
}

impl ConversationState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_user_text(&mut self, text: impl Into<String>) {
        self.messages.push(Message {
            role: Role::User,
            content: vec![ContentBlock::Text(text.into())],
        });
    }
}

/// 1ターン分の結果。テキスト・停止理由・使用トークン量を蓄積したもの。
#[derive(Debug, Clone)]
pub struct TurnOutcome {
    pub text: String,
    pub stop_reason: StopReason,
    pub usage: Usage,
}

/// 1プロバイダターンを実行する。ツール呼び出しへのディスパッチ・継続ループは
/// `run_agent_loop` が担う（§エージェントループの「1回のステップ」のうち、
/// ここではステップ1〜3のみを担う）。
/// `on_text_delta` は `StreamEvent::TextDelta` 受信の都度呼ばれる（トークン逐次表示用）。
pub async fn run_single_turn<F>(
    provider: &dyn LlmProvider,
    state: &ConversationState,
    model: String,
    max_tokens: u32,
    mut on_text_delta: F,
) -> Result<TurnOutcome, ProviderError>
where
    F: FnMut(&str),
{
    let req = CompletionRequest {
        system: state.system.clone(),
        messages: state.messages.clone(),
        tools: Vec::new(),
        tool_choice: ToolChoice::Auto,
        output: None,
        parallel_tool_calls: None,
        max_tokens,
        sampling: Sampling::default(),
        model,
    };

    let mut stream = provider.stream(req).await?;
    let mut text = String::new();
    let mut stop_reason = StopReason::EndTurn;
    let mut usage = Usage::default();

    while let Some(event) = stream.next().await {
        match event? {
            StreamEvent::TextDelta { text: delta, .. } => {
                on_text_delta(&delta);
                text.push_str(&delta);
            }
            StreamEvent::Done {
                stop_reason: sr,
                usage: u,
            } => {
                stop_reason = sr;
                usage = u;
            }
            _ => {}
        }
    }

    Ok(TurnOutcome {
        text,
        stop_reason,
        usage,
    })
}

/// `run_agent_loop` の結果。複数ターンにまたがる最終的なテキスト・停止理由・
/// 直近ターンの使用トークン量を返す。
#[derive(Debug, Clone)]
pub struct AgentLoopOutcome {
    pub text: String,
    pub stop_reason: StopReason,
    pub usage: Usage,
}

/// ストリーム受信中のブロックを蓄積する作業用構造体。
/// `StreamEvent`はブロック単位に一般化されているため、`BlockStart`〜`BlockStop`の間に届く
/// デルタをindexごとに蓄積し、ストリーム完了後に`ContentBlock`へ組み立てる
/// （§プロバイダ抽象「ブロック単位に一般化」）。
struct BlockAccum {
    index: usize,
    kind: BlockKind,
    text: String,
    signature: Option<String>,
    tool_input_raw: String,
}

impl BlockAccum {
    fn into_content_block(self) -> Result<ContentBlock, ProviderError> {
        match self.kind {
            BlockKind::Text => Ok(ContentBlock::Text(self.text)),
            BlockKind::Thinking => Ok(ContentBlock::Thinking {
                text: self.text,
                signature: self.signature,
            }),
            BlockKind::RedactedThinking => Ok(ContentBlock::RedactedThinking { data: self.text }),
            BlockKind::ToolUse { id, name } => {
                // OpenAIは引数文字列断片・Anthropicは部分JSONオブジェクト断片だが、
                // いずれも連結すれば1つのJSONテキストになるため、BlockStop相当の
                // このタイミングで一度だけパースする（§プロバイダ抽象「ツール引数の正規化」）。
                let input = if self.tool_input_raw.trim().is_empty() {
                    serde_json::Value::Object(Default::default())
                } else {
                    serde_json::from_str(&self.tool_input_raw).map_err(|_| {
                        ProviderError::InvalidRequest {
                            msg: format!("malformed tool_use input for {name}"),
                        }
                    })?
                };
                Ok(ContentBlock::ToolUse { id, name, input })
            }
        }
    }
}

/// `run_agent_loop` のターン単位パラメータ。素の引数列だと `clippy::too_many_arguments` に
/// 触れるため1つにまとめた（値自体の意味は各フィールドのコメント通り）。
pub struct AgentLoopConfig {
    pub model: String,
    pub max_tokens: u32,
    /// 暴走ループの保険（`--max-turns` としての正式な設定化はM9のスコープ）。
    pub max_turns: usize,
}

/// 1回のステップ = 1プロバイダターン + 承認済みツール実行（§エージェントループ）を
/// `stop_reason != ToolUse` になるまで繰り返す。`arbiter`が全ツール呼び出しの実行前に
/// 必ず参照される唯一の強制点で（§パーミッション（承認）システム）、`Decision::Deny`の場合は
/// ツールを実行せずエラーの`ToolResult`を合成する（§エージェントループ 手順4）。
pub async fn run_agent_loop<F>(
    provider: &dyn LlmProvider,
    state: &mut ConversationState,
    tools: &ToolRegistry,
    ctx: &ToolCtx,
    arbiter: &PermissionArbiter,
    config: AgentLoopConfig,
    mut on_text_delta: F,
) -> Result<AgentLoopOutcome, ProviderError>
where
    F: FnMut(&str),
{
    let tool_specs = tools.to_specs();

    for _ in 0..config.max_turns {
        let req = CompletionRequest {
            system: state.system.clone(),
            messages: state.messages.clone(),
            tools: tool_specs.clone(),
            tool_choice: if tool_specs.is_empty() {
                ToolChoice::None
            } else {
                ToolChoice::Auto
            },
            output: None,
            parallel_tool_calls: None,
            max_tokens: config.max_tokens,
            sampling: Sampling::default(),
            model: config.model.clone(),
        };

        let mut stream = provider.stream(req).await?;
        let mut blocks: Vec<BlockAccum> = Vec::new();
        let mut stop_reason = StopReason::EndTurn;
        let mut usage = Usage::default();

        while let Some(event) = stream.next().await {
            match event? {
                StreamEvent::BlockStart { index, kind } => blocks.push(BlockAccum {
                    index,
                    kind,
                    text: String::new(),
                    signature: None,
                    tool_input_raw: String::new(),
                }),
                StreamEvent::TextDelta { index, text } => {
                    on_text_delta(&text);
                    if let Some(b) = blocks.iter_mut().find(|b| b.index == index) {
                        b.text.push_str(&text);
                    }
                }
                StreamEvent::ThinkingDelta { index, text } => {
                    if let Some(b) = blocks.iter_mut().find(|b| b.index == index) {
                        b.text.push_str(&text);
                    }
                }
                StreamEvent::SignatureDelta { index, sig } => {
                    if let Some(b) = blocks.iter_mut().find(|b| b.index == index) {
                        b.signature = Some(sig);
                    }
                }
                StreamEvent::ToolInputDelta {
                    index,
                    json_fragment,
                } => {
                    if let Some(b) = blocks.iter_mut().find(|b| b.index == index) {
                        b.tool_input_raw.push_str(&json_fragment);
                    }
                }
                StreamEvent::BlockStop { .. } => {}
                StreamEvent::Done {
                    stop_reason: sr,
                    usage: u,
                } => {
                    stop_reason = sr;
                    usage = u;
                }
            }
        }

        let mut content = Vec::with_capacity(blocks.len());
        for b in blocks {
            content.push(b.into_content_block()?);
        }

        state.messages.push(Message {
            role: Role::Assistant,
            content: content.clone(),
        });

        if stop_reason != StopReason::ToolUse {
            let text = content
                .into_iter()
                .filter_map(|b| match b {
                    ContentBlock::Text(t) => Some(t),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("");
            return Ok(AgentLoopOutcome {
                text,
                stop_reason,
                usage,
            });
        }

        let mut results = Vec::new();
        for block in &content {
            if let ContentBlock::ToolUse { id, name, input } = block {
                let output = match tools.get(name) {
                    Some(tool) => {
                        let risk = tool.risk(input);
                        let decision = arbiter.decide(name, risk, &arg_repr(input));
                        if decision.is_allow() {
                            tool.call(input.clone(), ctx).await.unwrap_or_else(|e| ToolOutput {
                                content: e.to_string(),
                                is_error: true,
                            })
                        } else {
                            ToolOutput {
                                content: format!(
                                    "permission denied by policy: {name} ({risk:?})"
                                ),
                                is_error: true,
                            }
                        }
                    }
                    None => ToolOutput {
                        content: format!("unknown tool: {name}"),
                        is_error: true,
                    },
                };
                results.push(ContentBlock::ToolResult {
                    tool_use_id: id.clone(),
                    content: output.content,
                    is_error: output.is_error,
                });
            }
        }

        state.messages.push(Message {
            role: Role::User,
            content: results,
        });
    }

    Err(ProviderError::InvalidRequest {
        msg: format!("agent loop exceeded max_turns ({})", config.max_turns),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use futures::stream;

    /// あらかじめ用意したターンごとの`StreamEvent`列を順番に返すテスト用プロバイダ。
    /// §実装マイルストーン M6で導入予定の本物のmockプロバイダ（golden-transcript向け）とは別に、
    /// M4はこの最小限のローカルmockでパーミッション判定の統合テストのみを行う。
    struct MockProvider {
        turns: Mutex<Vec<Vec<StreamEvent>>>,
    }

    #[async_trait]
    impl LlmProvider for MockProvider {
        fn id(&self) -> &str {
            "mock"
        }

        async fn stream(
            &self,
            _req: CompletionRequest,
        ) -> Result<futures::stream::BoxStream<'static, Result<StreamEvent, ProviderError>>, ProviderError>
        {
            let mut turns = self.turns.lock().unwrap();
            let events = turns.remove(0);
            Ok(Box::pin(stream::iter(events.into_iter().map(Ok))))
        }
    }

    fn tool_use_turn(id: &str, name: &str, input: serde_json::Value) -> Vec<StreamEvent> {
        vec![
            StreamEvent::BlockStart {
                index: 0,
                kind: BlockKind::ToolUse {
                    id: id.to_string(),
                    name: name.to_string(),
                },
            },
            StreamEvent::ToolInputDelta {
                index: 0,
                json_fragment: input.to_string(),
            },
            StreamEvent::BlockStop { index: 0 },
            StreamEvent::Done {
                stop_reason: StopReason::ToolUse,
                usage: Usage::default(),
            },
        ]
    }

    fn end_turn(text: &str) -> Vec<StreamEvent> {
        vec![
            StreamEvent::BlockStart {
                index: 0,
                kind: BlockKind::Text,
            },
            StreamEvent::TextDelta {
                index: 0,
                text: text.to_string(),
            },
            StreamEvent::BlockStop { index: 0 },
            StreamEvent::Done {
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            },
        ]
    }

    fn find_tool_result(state: &ConversationState) -> (String, bool) {
        state
            .messages
            .iter()
            .rev()
            .find_map(|m| {
                m.content.iter().find_map(|b| match b {
                    ContentBlock::ToolResult {
                        content, is_error, ..
                    } => Some((content.clone(), *is_error)),
                    _ => None,
                })
            })
            .expect("tool_result should be present")
    }

    /// §実装マイルストーン M4 検証条件「未許可shellが拒否されるユニットテスト」。
    /// allowlist未登録の`run_shell`（RiskClass=Exec）がDefaultモード・ヘッドレス相当の判定で
    /// 拒否され、`RunShellTool::call`が一度も呼ばれない（=実際にコマンドが実行されない）ことを、
    /// 拒否理由を含むエラーtool_resultが積まれ`EndTurn`まで正常にループが継続することで確認する。
    #[tokio::test]
    async fn denies_unauthorized_run_shell_without_executing() {
        let dir = tempfile::tempdir().unwrap();
        let provider = MockProvider {
            turns: Mutex::new(vec![
                tool_use_turn(
                    "call_1",
                    "run_shell",
                    serde_json::json!({ "command": "echo should-not-run" }),
                ),
                end_turn("done"),
            ]),
        };
        let mut state = ConversationState::new();
        state.push_user_text("run a shell command");
        let tools = harness_tools::ToolRegistry::with_builtin_tools();
        let ctx = ToolCtx {
            workspace_root: dir.path().to_path_buf(),
        };
        let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);

        let outcome = run_agent_loop(
            &provider,
            &mut state,
            &tools,
            &ctx,
            &arbiter,
            AgentLoopConfig {
                model: "mock".into(),
                max_tokens: 100,
                max_turns: 5,
            },
            |_| {},
        )
        .await
        .unwrap();

        assert_eq!(outcome.stop_reason, StopReason::EndTurn);
        let (content, is_error) = find_tool_result(&state);
        assert!(is_error, "denied tool call should be recorded as an error");
        assert!(content.contains("permission denied"));
    }

    /// §実装マイルストーン M4 検証条件のもう一方「ジェイル脱出が拒否される」に対する、
    /// パーミッション層側の対照テスト: allowlist未登録でもread-onlyの`read_file`は
    /// Defaultモードで自動許可され、実際にファイル内容が読めることを確認する
    /// （fsジェイル自体のユニットテストは`harness-sandbox`側に別途ある）。
    #[tokio::test]
    async fn allows_read_only_tool_without_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "hello").unwrap();
        let provider = MockProvider {
            turns: Mutex::new(vec![
                tool_use_turn("call_1", "read_file", serde_json::json!({ "path": "a.txt" })),
                end_turn("summarized"),
            ]),
        };
        let mut state = ConversationState::new();
        state.push_user_text("read a.txt");
        let tools = harness_tools::ToolRegistry::with_builtin_tools();
        let ctx = ToolCtx {
            workspace_root: dir.path().to_path_buf(),
        };
        let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);

        let outcome = run_agent_loop(
            &provider,
            &mut state,
            &tools,
            &ctx,
            &arbiter,
            AgentLoopConfig {
                model: "mock".into(),
                max_tokens: 100,
                max_turns: 5,
            },
            |_| {},
        )
        .await
        .unwrap();

        assert_eq!(outcome.text, "summarized");
        let (content, is_error) = find_tool_result(&state);
        assert!(!is_error);
        assert!(content.contains("hello"));
    }

    /// allowlistで`run_shell:echo*`を明示した場合は、Defaultモードのヘッドレス既定拒否を
    /// 上書きして許可される（§パーミッション「allowlist: closed-by-default」）。
    #[tokio::test]
    async fn allowlisted_run_shell_executes() {
        let dir = tempfile::tempdir().unwrap();
        let provider = MockProvider {
            turns: Mutex::new(vec![
                tool_use_turn(
                    "call_1",
                    "run_shell",
                    serde_json::json!({ "command": "echo allowed" }),
                ),
                end_turn("done"),
            ]),
        };
        let mut state = ConversationState::new();
        state.push_user_text("run an allowed shell command");
        let tools = harness_tools::ToolRegistry::with_builtin_tools();
        let ctx = ToolCtx {
            workspace_root: dir.path().to_path_buf(),
        };
        let arbiter = PermissionArbiter::new(
            PermissionMode::Default,
            vec![AllowlistRule::new("run_shell", "echo*")],
        );

        run_agent_loop(
            &provider,
            &mut state,
            &tools,
            &ctx,
            &arbiter,
            AgentLoopConfig {
                model: "mock".into(),
                max_tokens: 100,
                max_turns: 5,
            },
            |_| {},
        )
        .await
        .unwrap();

        let (content, is_error) = find_tool_result(&state);
        assert!(!is_error);
        assert!(content.contains("allowed"));
    }
}
