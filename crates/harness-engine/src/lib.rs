//! harness-engine: 中核ループの入口。`plans/DESIGN.md` §エージェントループ参照。
//!
//! M3で `run_single_turn`（単発ターン、M2まで）に加え `run_agent_loop` を追加した。
//! M4で `PermissionArbiter`（§パーミッション（承認）システム）を実装し、`run_agent_loop`が
//! 各`ToolUse`の実行前に必ず問い合わせるようにした（§エージェントループ「唯一の強制点」）。
//! 拒否されたツール呼び出しは実行されず、エラーの`ToolResult`を合成して履歴へ積み戻す
//! （§エージェントループ 手順4「拒否→エラーToolResultを合成」）。
//! **M4時点のスコープ外**: cap-stdによる読取スコープ反転モード（whitelist/blacklist、M11）・
//! 対話TUIの承認モーダル（M7、そのため`decide`は常にヘッドレス相当で決定的に判定する）。
//! M9で キャンセル整合・コンテキスト圧縮（`compaction`モジュール）・大出力切詰め・
//! リトライ/リアクティブ圧縮・JSONLセッション永続化（`session`モジュール）を追加した。

pub mod compaction;
pub mod permission;
pub mod session;

use std::time::Duration;

use futures::StreamExt;
use tokio_util::sync::CancellationToken;

use harness_core::{
    AgentEvent, BlockKind, CompletionRequest, ContentBlock, LlmProvider, Message, ProviderError,
    Role, Sampling, StopReason, StreamEvent, SystemBlock, ToolChoice, ToolCtx, ToolOutput, Usage,
};
use harness_tools::ToolRegistry;

pub use permission::{
    arg_repr, parse_allowlist_rule, AllowlistRule, Classification, Decision, PermissionArbiter,
    PermissionGate, PermissionMode,
};
pub use session::{SessionStore, SessionSummary};

/// TUI等のフロントエンドへ`AgentEvent`を流すための送信口。ヘッドレスCLIは`None`を渡し
/// 従来通り`on_text_delta`コールバックのみでstdout出力する（§非対話モード、既存挙動を維持）。
pub type EventSink = tokio::sync::mpsc::UnboundedSender<AgentEvent>;

fn emit(events: Option<&EventSink>, ev: AgentEvent) {
    if let Some(tx) = events {
        let _ = tx.send(ev);
    }
}

/// ツール出力がこれを超える文字数なら頭尾切詰めする（M9、DESIGN.md L349「大出力 head+tail
/// 切詰め」）。会話履歴に積む前に適用するため、モデルへ送るコンテキスト自体を圧迫しない。
const MAX_TOOL_OUTPUT_CHARS: usize = 8_000;

/// `content`が`max_chars`文字を超える場合、先頭/末尾を残し中間を省略記号に置き換える。
fn truncate_head_tail(content: &str, max_chars: usize) -> String {
    let total = content.chars().count();
    if total <= max_chars {
        return content.to_string();
    }
    let half = max_chars / 2;
    let head: String = content.chars().take(half).collect();
    let tail: String = content.chars().skip(total - half).collect();
    let omitted = total - 2 * half;
    format!("{head}\n... [{omitted} chars truncated] ...\n{tail}")
}

/// リクエスト全体（system+messages+tools）をJSONシリアライズした文字数からの粗い近似
/// （chars/4）。`AgentEvent::TurnStarted.estimated_input_tokens`用（TUIのリアルタイム表示、
/// §リッチTUI「ライブ表示」）。プロバイダの正確なinputトークン数は`TurnCompleted`の
/// `usage.input`でしか分からないため、送信直後にひとまず出す概算値に過ぎない。
fn estimate_tokens(req: &CompletionRequest) -> u64 {
    serde_json::to_string(req)
        .map(|s| (s.chars().count() as u64) / 4)
        .unwrap_or(0)
}

/// リトライ可能な`ProviderError`（`RateLimited`/`Overloaded`/`Transport{retriable:true}`）かどうか。
/// `ContextTooLong`はここに含めない（呼び出し側でコンテキスト圧縮を挟んでから明示的に再試行する、
/// §主なリスクと対策「分類を確定。外周の共通リトライラッパがこれを見てリトライ可否・待機を決める」）。
fn is_retriable(e: &ProviderError) -> bool {
    matches!(
        e,
        ProviderError::RateLimited { .. }
            | ProviderError::Overloaded
            | ProviderError::Transport { retriable: true }
    )
}

fn retry_delay(e: &ProviderError, attempt: u32) -> Duration {
    if let ProviderError::RateLimited { retry_after: Some(d) } = e {
        return *d;
    }
    Duration::from_millis(200 * 2u64.saturating_pow(attempt))
}

const MAX_RETRIES: u32 = 3;

/// `provider.stream`をリトライ可能なエラーに対して指数バックオフで最大`MAX_RETRIES`回まで
/// 再試行する。`ContextTooLong`はここでは扱わず、そのまま呼び出し側へ伝播する
/// （`run_agent_loop`側でコンテキスト圧縮を挟んだ1回限りの再試行を行う）。
async fn stream_with_retry(
    provider: &dyn LlmProvider,
    req: &CompletionRequest,
) -> Result<futures::stream::BoxStream<'static, Result<StreamEvent, ProviderError>>, ProviderError>
{
    let mut attempt = 0;
    loop {
        match provider.stream(req.clone()).await {
            Ok(s) => return Ok(s),
            Err(e) if attempt < MAX_RETRIES && is_retriable(&e) => {
                tokio::time::sleep(retry_delay(&e, attempt)).await;
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

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
    /// キャンセルされて終了した場合`true`（M9）。この場合`text`は空、`stop_reason`は
    /// `StopReason::Other("cancelled")`になる。`state`自体は次の`run_agent_loop`呼び出しが
    /// 400にならない形（tool_use/tool_resultの対応が崩れていない状態）に保たれている。
    pub cancelled: bool,
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
/// `stop_reason != ToolUse` になるまで繰り返す。`gate`が全ツール呼び出しの実行前に
/// 必ず参照される唯一の強制点で（§パーミッション（承認）システム）、`Decision::Deny`の場合は
/// ツールを実行せずエラーの`ToolResult`を合成する（§エージェントループ 手順4）。
/// `events`が`Some`なら`AgentEvent`をその都度発行する（M7、`harness-tui`の`AppState`が
/// これを畳み込んで描画する。§リッチTUI「`AppState`は`AgentEvent`を畳み込んで更新」）。
#[allow(clippy::too_many_arguments)]
pub async fn run_agent_loop<F>(
    provider: &dyn LlmProvider,
    state: &mut ConversationState,
    tools: &ToolRegistry,
    ctx: &ToolCtx,
    gate: &dyn PermissionGate,
    config: AgentLoopConfig,
    events: Option<&EventSink>,
    cancel: Option<&CancellationToken>,
    mut on_text_delta: F,
) -> Result<AgentLoopOutcome, ProviderError>
where
    F: FnMut(&str),
{
    let tool_specs = tools.to_specs();

    /// キャンセルによる早期returnの共通形。§エージェントループ「ストリーム途中は部分assistant
    /// 破棄／ツール実行中は全tool_useへcancelled合成」のいずれの経路も、この形の
    /// `AgentLoopOutcome`を返す（`state`は呼び出し側で既に整合が取れる形に調整済み）。
    fn cancelled_outcome() -> AgentLoopOutcome {
        AgentLoopOutcome {
            text: String::new(),
            stop_reason: StopReason::Other("cancelled".to_string()),
            usage: Usage::default(),
            cancelled: true,
        }
    }

    for _ in 0..config.max_turns {
        if cancel.is_some_and(|c| c.is_cancelled()) {
            emit(events, AgentEvent::Cancelled);
            return Ok(cancelled_outcome());
        }

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
        emit(
            events,
            AgentEvent::TurnStarted {
                estimated_input_tokens: estimate_tokens(&req),
            },
        );

        let mut stream = match stream_with_retry(provider, &req).await {
            Ok(s) => s,
            Err(ProviderError::ContextTooLong) => {
                let removed =
                    compaction::compact(provider, state, &config.model, compaction::DEFAULT_KEEP_RECENT_TURNS)
                        .await?;
                if removed == 0 {
                    let e = ProviderError::ContextTooLong;
                    emit(events, AgentEvent::Error { message: e.to_string() });
                    return Err(e);
                }
                emit(events, AgentEvent::ContextCompacted { removed_messages: removed });
                let retry_req = CompletionRequest {
                    messages: state.messages.clone(),
                    ..req
                };
                match stream_with_retry(provider, &retry_req).await {
                    Ok(s) => s,
                    Err(e) => {
                        emit(events, AgentEvent::Error { message: e.to_string() });
                        return Err(e);
                    }
                }
            }
            Err(e) => {
                emit(events, AgentEvent::Error { message: e.to_string() });
                return Err(e);
            }
        };
        let mut blocks: Vec<BlockAccum> = Vec::new();
        let mut stop_reason = StopReason::EndTurn;
        let mut usage = Usage::default();

        loop {
            let next = match cancel {
                Some(c) => tokio::select! {
                    _ = c.cancelled() => None,
                    ev = stream.next() => Some(ev),
                },
                None => Some(stream.next().await),
            };
            let Some(event) = next else {
                // ストリーム途中でキャンセルされた: 蓄積中のblocksはstateへ一切pushせず破棄する
                // （§エージェントループ キャンセル整合「ストリーム途中は部分assistant破棄」）。
                emit(events, AgentEvent::Cancelled);
                return Ok(cancelled_outcome());
            };
            let Some(event) = event else {
                break;
            };
            let event = match event {
                Ok(e) => e,
                Err(e) => {
                    emit(events, AgentEvent::Error { message: e.to_string() });
                    return Err(e);
                }
            };
            match event {
                StreamEvent::BlockStart { index, kind } => blocks.push(BlockAccum {
                    index,
                    kind,
                    text: String::new(),
                    signature: None,
                    tool_input_raw: String::new(),
                }),
                StreamEvent::TextDelta { index, text } => {
                    on_text_delta(&text);
                    emit(events, AgentEvent::TextDelta { text: text.clone() });
                    if let Some(b) = blocks.iter_mut().find(|b| b.index == index) {
                        b.text.push_str(&text);
                    }
                }
                StreamEvent::ThinkingDelta { index, text } => {
                    emit(events, AgentEvent::ThinkingDelta { text: text.clone() });
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
            emit(
                events,
                AgentEvent::TurnCompleted {
                    stop_reason: stop_reason.clone(),
                    usage,
                },
            );
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
                cancelled: false,
            });
        }

        let mut results = Vec::new();
        let mut cancelled_mid_tool = false;
        for block in &content {
            if let ContentBlock::ToolUse { id, name, input } = block {
                if !cancelled_mid_tool && cancel.is_some_and(|c| c.is_cancelled()) {
                    cancelled_mid_tool = true;
                }
                if cancelled_mid_tool {
                    // 残り全てのtool_useへcancelledなtool_resultを合成する
                    // （§エージェントループ キャンセル整合「ツール実行中は全tool_useへ
                    // cancelled合成 → 続行で400にならない」、実際にツールは呼ばない）。
                    results.push(ContentBlock::ToolResult {
                        tool_use_id: id.clone(),
                        content: "cancelled by user".to_string(),
                        is_error: true,
                    });
                    continue;
                }
                emit(
                    events,
                    AgentEvent::ToolCallProposed {
                        id: id.clone(),
                        name: name.clone(),
                        input: input.clone(),
                    },
                );
                let output = match tools.get(name) {
                    Some(tool) => {
                        let risk = tool.risk(input);
                        let decision = gate.resolve(name, risk, &arg_repr(input), input).await;
                        if decision.is_allow() {
                            emit(
                                events,
                                AgentEvent::ToolStarted {
                                    id: id.clone(),
                                    name: name.clone(),
                                },
                            );
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
                let truncated_content = truncate_head_tail(&output.content, MAX_TOOL_OUTPUT_CHARS);
                emit(
                    events,
                    AgentEvent::ToolFinished {
                        id: id.clone(),
                        output: ToolOutput {
                            content: truncated_content.clone(),
                            is_error: output.is_error,
                        },
                    },
                );
                results.push(ContentBlock::ToolResult {
                    tool_use_id: id.clone(),
                    content: truncated_content,
                    is_error: output.is_error,
                });
            }
        }

        state.messages.push(Message {
            role: Role::User,
            content: results,
        });

        if cancelled_mid_tool {
            emit(events, AgentEvent::Cancelled);
            return Ok(cancelled_outcome());
        }
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

    #[test]
    fn estimate_tokens_grows_with_request_size() {
        let small = CompletionRequest {
            system: vec![],
            messages: vec![],
            tools: vec![],
            tool_choice: ToolChoice::None,
            output: None,
            parallel_tool_calls: None,
            max_tokens: 100,
            sampling: Sampling::default(),
            model: "mock".into(),
        };
        let mut large = small.clone();
        large.messages.push(Message {
            role: Role::User,
            content: vec![ContentBlock::Text("x".repeat(4000))],
        });

        assert!(estimate_tokens(&large) > estimate_tokens(&small));
    }

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
            None,
            None,
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
            None,
            None,
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
            None,
            None,
            |_| {},
        )
        .await
        .unwrap();

        let (content, is_error) = find_tool_result(&state);
        assert!(!is_error);
        assert!(content.contains("allowed"));
    }

    /// ストリーム開始後、応答が完了する前に応答が返らないプロバイダ
    /// （キャンセルによる中断を`tokio::select!`で確実に踏ませるためのテスト専用実装）。
    struct HangingProvider;

    #[async_trait]
    impl LlmProvider for HangingProvider {
        fn id(&self) -> &str {
            "hanging"
        }
        async fn stream(
            &self,
            _req: CompletionRequest,
        ) -> Result<futures::stream::BoxStream<'static, Result<StreamEvent, ProviderError>>, ProviderError>
        {
            let partial = vec![
                Ok(StreamEvent::BlockStart { index: 0, kind: BlockKind::Text }),
                Ok(StreamEvent::TextDelta { index: 0, text: "partial".to_string() }),
            ];
            Ok(Box::pin(stream::iter(partial).chain(stream::pending())))
        }
    }

    /// §エージェントループ キャンセル整合「ストリーム途中は部分assistant破棄」。
    /// ストリーム受信中にキャンセルすると、蓄積中だったテキストは`state.messages`へ一切
    /// pushされず（呼び出し前と後でメッセージ数が変わらない）、`AgentLoopOutcome.cancelled`が
    /// `true`になることを確認する。
    #[tokio::test]
    async fn cancel_mid_stream_discards_partial_assistant() {
        let dir = tempfile::tempdir().unwrap();
        let provider = HangingProvider;
        let mut state = ConversationState::new();
        state.push_user_text("hi");
        let messages_before = state.messages.len();
        let tools = harness_tools::ToolRegistry::with_builtin_tools();
        let ctx = ToolCtx { workspace_root: dir.path().to_path_buf() };
        let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
        let cancel = CancellationToken::new();

        let outcome = {
            let run_fut = run_agent_loop(
                &provider,
                &mut state,
                &tools,
                &ctx,
                &arbiter,
                AgentLoopConfig { model: "mock".into(), max_tokens: 100, max_turns: 5 },
                None,
                Some(&cancel),
                |_| {},
            );
            tokio::pin!(run_fut);
            let cancel_after_delay = async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                cancel.cancel();
            };
            let (outcome, ()) = tokio::join!(run_fut, cancel_after_delay);
            outcome.unwrap()
        };

        assert!(outcome.cancelled);
        assert_eq!(state.messages.len(), messages_before);
    }

    /// キャンセルされるまで`call()`内で意図的にsleepするテスト専用ツール。
    struct SlowTool;

    #[async_trait]
    impl harness_core::Tool for SlowTool {
        fn name(&self) -> &str {
            "slow_tool"
        }
        fn description(&self) -> &str {
            "test-only slow tool"
        }
        fn input_schema(&self) -> serde_json::Value {
            serde_json::json!({ "type": "object" })
        }
        fn risk(&self, _input: &serde_json::Value) -> harness_core::RiskClass {
            harness_core::RiskClass::ReadOnly
        }
        async fn call(
            &self,
            _input: serde_json::Value,
            _ctx: &ToolCtx,
        ) -> Result<ToolOutput, harness_core::ToolError> {
            tokio::time::sleep(Duration::from_millis(30)).await;
            Ok(ToolOutput { content: "slow-done".to_string(), is_error: false })
        }
    }

    fn multi_tool_use_turn(calls: &[(&str, &str, serde_json::Value)]) -> Vec<StreamEvent> {
        let mut events = Vec::new();
        for (index, (id, name, input)) in calls.iter().enumerate() {
            events.push(StreamEvent::BlockStart {
                index,
                kind: BlockKind::ToolUse { id: id.to_string(), name: name.to_string() },
            });
            events.push(StreamEvent::ToolInputDelta { index, json_fragment: input.to_string() });
            events.push(StreamEvent::BlockStop { index });
        }
        events.push(StreamEvent::Done { stop_reason: StopReason::ToolUse, usage: Usage::default() });
        events
    }

    /// §エージェントループ キャンセル整合「ツール実行中は全tool_useへcancelled合成 →
    /// 続行で400にならない」の契約テスト。1回目のツール呼び出し中にキャンセルすると、
    /// (a) 既に実行が始まっていた1件目は正常完了扱いのまま、(b) まだ手を付けていない2件目は
    /// 実行されず`cancelled by user`なtool_resultが合成され、(c) assistantのtool_use 2件と
    /// tool_result 2件が過不足なく対応した状態で会話が終わるため、(d) 続けて次のプロンプトを
    /// 送っても（=もう一度`run_agent_loop`を呼んでも）プロバイダ層のエラーにならないことを
    /// 確認する。
    #[tokio::test]
    async fn cancel_mid_tool_execution_synthesizes_cancelled_results_and_continuation_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let provider = MockProvider {
            turns: Mutex::new(vec![
                multi_tool_use_turn(&[
                    ("call_1", "slow_tool", serde_json::json!({})),
                    ("call_2", "slow_tool", serde_json::json!({})),
                ]),
                end_turn("continued fine"),
            ]),
        };
        let mut state = ConversationState::new();
        state.push_user_text("run two slow tools");
        let mut tools = harness_tools::ToolRegistry::new();
        tools.register(std::sync::Arc::new(SlowTool));
        let ctx = ToolCtx { workspace_root: dir.path().to_path_buf() };
        let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
        let cancel = CancellationToken::new();

        let outcome = {
            let run_fut = run_agent_loop(
                &provider,
                &mut state,
                &tools,
                &ctx,
                &arbiter,
                AgentLoopConfig { model: "mock".into(), max_tokens: 100, max_turns: 5 },
                None,
                Some(&cancel),
                |_| {},
            );
            tokio::pin!(run_fut);
            // 1件目の`SlowTool::call`（30ms sleep）が始まった後、2件目に手を付ける前にキャンセルする。
            let cancel_after_delay = async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                cancel.cancel();
            };
            let (outcome, ()) = tokio::join!(run_fut, cancel_after_delay);
            outcome.unwrap()
        };
        assert!(outcome.cancelled);

        let tool_results: Vec<(String, String, bool)> = state
            .messages
            .last()
            .unwrap()
            .content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::ToolResult { tool_use_id, content, is_error } => {
                    Some((tool_use_id.clone(), content.clone(), *is_error))
                }
                _ => None,
            })
            .collect();
        assert_eq!(tool_results.len(), 2, "both tool_use blocks must have a matching tool_result");
        let call1 = tool_results.iter().find(|(id, ..)| id == "call_1").unwrap();
        assert_eq!(call1.1, "slow-done");
        assert!(!call1.2);
        let call2 = tool_results.iter().find(|(id, ..)| id == "call_2").unwrap();
        assert_eq!(call2.1, "cancelled by user");
        assert!(call2.2);

        // 続行: 新しいCancellationTokenでもう一度呼んでも、tool_use/tool_resultの対応が
        // 崩れていないため`ProviderError`にならず正常終了する（M9受入条件そのもの）。
        let outcome2 = run_agent_loop(
            &provider,
            &mut state,
            &tools,
            &ctx,
            &arbiter,
            AgentLoopConfig { model: "mock".into(), max_tokens: 100, max_turns: 5 },
            None,
            None,
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(outcome2.text, "continued fine");
    }
}
