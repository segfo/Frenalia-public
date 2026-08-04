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
mod sanitize;
pub mod session;
pub mod turn;

use tokio_util::sync::CancellationToken;

use harness_core::{
    AgentEvent, CompletionRequest, ContentBlock, LlmProvider, Message, ProviderError, Role,
    Sampling, StopReason, SystemBlock, ToolChoice, ToolCtx, ToolSpec, Usage,
};
use harness_tools::ToolRegistry;

pub use permission::{
    arg_repr, parse_allowlist_rule, AllowlistRule, Classification, Decision, PermissionArbiter,
    PermissionGate, PermissionMode,
};
pub use session::{SessionStore, SessionSummary};
pub use turn::{
    CompletedToolCall, EngineError, Executor, RawTurn, RawTurnRequest, RawTurnResult,
    ToolCallDecision, TurnExecutor, TurnVisibility,
};

/// TUI等のフロントエンドへ`AgentEvent`を流すための送信口。ヘッドレスCLIは`None`を渡し
/// 従来通り`on_text_delta`コールバックのみでstdout出力する（§非対話モード、既存挙動を維持）。
pub type EventSink = tokio::sync::mpsc::UnboundedSender<AgentEvent>;

/// `EventSink`が繋がっていればイベントを流す（受信側が落ちていても無視する）。
///
/// 認知レイヤー（`harness-cognition`）もフェーズ遷移・台帳更新のイベントを同じ
/// `EventSink`へ流すため公開している。送信の形を2箇所に持たないための1関数
/// （`docs/CODE-STRUCTURE-RULES.md` 規則5）。
pub fn emit_event(events: Option<&EventSink>, ev: AgentEvent) {
    if let Some(tx) = events {
        let _ = tx.send(ev);
    }
}

pub(crate) fn emit(events: Option<&EventSink>, ev: AgentEvent) {
    emit_event(events, ev);
}

/// リクエスト全体（system+messages+tools）をJSONシリアライズした文字数からの粗い近似
/// （chars/4）。`AgentEvent::TurnStarted.estimated_input_tokens`用（TUIのリアルタイム表示、
/// §リッチTUI「ライブ表示」）。プロバイダの正確なinputトークン数は`TurnCompleted`の
/// `usage.input`でしか分からないため、送信直後にひとまず出す概算値に過ぎない。
///
/// 認知レイヤーの`ContextAssembler`（M14）も**同じ推定器**でフェーズ別予算を会計する。
/// TUI表示と予算会計がずれないようにするためで、推定器のコピーを作らない
/// （`docs/CODE-STRUCTURE-RULES.md` 規則5）。
pub fn estimate_tokens(req: &CompletionRequest) -> u64 {
    estimate_json_tokens(req)
}

/// 任意のIR値をJSONシリアライズした文字数からの粗い近似（chars/4）。
///
/// [`estimate_tokens`]（リクエスト全体）と[`estimate_messages`]（履歴の一部）の**共通のコア**で、
/// 推定式を1箇所に閉じるために抽出してある（`docs/CODE-STRUCTURE-RULES.md` 規則5）。
/// 縮約の発火判定（`plans/PLAN-COMPACTION.md`）は「リクエスト全体」ではなく「前ターン以降に
/// 積んだメッセージだけ」を測る必要があり、同じ式の2つ目の実装を作らないための土台。
///
/// シリアライズに失敗したら`0`を返す。推定値は判定を**早める**方向にしか使わないので、
/// 0へ倒しても「縮約しそこねてリアクティブ経路が受け止める」だけで済む（fail-open だが、
/// この値は保護境界ではない）。
pub fn estimate_json_tokens<T: serde::Serialize>(value: &T) -> u64 {
    serde_json::to_string(value)
        .map(|s| (s.chars().count() as u64) / 4)
        .unwrap_or(0)
}

/// メッセージ列だけのトークン概算。[`estimate_tokens`]と同じ推定器に載る。
///
/// 縮約の(B)超過直前トリガが「前ターンの実測`usage`に反映されていない未計測分」を積むのに使う。
pub fn estimate_messages(messages: &[Message]) -> u64 {
    estimate_json_tokens(&messages)
}

/// 会話のIR履歴。
///
/// `system`は`ConversationState::new`で必ず渡す（`Default`は導出しない）。かつては
/// 引数無しの`ConversationState::new()`が空`system`を暗黙に作れてしまい、`harness-cli`/
/// `harness-tui`のどこからも実際にsystemを埋めていなかった（`run_shell`不安定性調査で
/// 発覚。モデルがOS・シェル種別・workspace root・シェル隔離Tierの制約を一切知らされて
/// いなかった）。`new`にシグネチャ変更したのは、今後この抜けを黙って再発させないため
/// （`harness_core::prompt`のゲート1/2と同じ「フィールド追加/呼び出し追加を強制コンパイル
/// エラーで検出する」設計方針）。
#[derive(Debug, Clone)]
pub struct ConversationState {
    pub system: Vec<SystemBlock>,
    pub messages: Vec<Message>,
}

impl ConversationState {
    pub fn new(system: Vec<SystemBlock>) -> Self {
        Self {
            system,
            messages: Vec::new(),
        }
    }

    pub fn push_user_text(&mut self, text: impl Into<String>) {
        self.messages.push(Message {
            role: Role::User,
            content: vec![ContentBlock::Text(text.into())],
        });
    }
}

/// `ToolCtx`が運ぶ環境事実（`harness_core::EnvironmentFacts`）から`SystemBlock`列を組み立てる。
/// `ConversationState::new`へ渡すsystemの、`harness-cli`/`harness-tui`共通の唯一の組み立て元
/// （個々のフロントエンドが独自にプロンプト文字列を書かないようにするため）。
pub fn system_blocks_for(ctx: &ToolCtx) -> Vec<SystemBlock> {
    let facts = harness_core::EnvironmentFacts::from_tool_ctx(ctx);
    vec![SystemBlock {
        text: harness_core::render_environment_prompt(&facts),
        cache: true,
    }]
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

/// `run_agent_loop` のターン単位パラメータ。素の引数列だと `clippy::too_many_arguments` に
/// 触れるため1つにまとめた（値自体の意味は各フィールドのコメント通り）。
pub struct AgentLoopConfig {
    pub model: String,
    pub max_tokens: u32,
    /// 暴走ループの保険（`--max-turns` としての正式な設定化はM9のスコープ）。
    pub max_turns: usize,
    /// コンテキスト縮約のポリシー（`plans/PLAN-COMPACTION.md`）。
    /// `CompactionPolicy::resolve`で解決済みのものを渡す（解決の失敗は起動時に止める）。
    pub compaction: compaction::CompactionPolicy,
}

/// `ConversationState`全体を1リクエストへ写す。認知レイヤー（M14以降）はここを通らず、
/// `ContextAssembler`が組んだ最小コンテキストを直接[`TurnExecutor`]へ渡す。
fn build_request(
    state: &ConversationState,
    tool_specs: &[ToolSpec],
    config: &AgentLoopConfig,
) -> CompletionRequest {
    CompletionRequest {
        system: state.system.clone(),
        messages: state.messages.clone(),
        tools: tool_specs.to_vec(),
        tool_choice: if tool_specs.is_empty() {
            ToolChoice::None
        } else {
            ToolChoice::Auto
        },
        output: None,
        // Phase5-D（run_shell不安定性調査）: 並列tool_callを明示的に抑止する。LMStudio実機
        // 観測で、2件目以降の`arguments`断片チャンクが`index`を省略することがあり
        // （`harness-providers::openai::WireToolCallDelta`のコメント参照）、複数tool_callが
        // 同時に開いていると引数JSONの取り違えが起きる。`parallel_tool_calls:false`は
        // プロバイダに1回のターンで最大1個のtool_callしか出させないための一次防御であり、
        // 二次防御としてopenai.rs側も`index`省略時は「直近に開いたブロック」へ倒す
        // （0固定より安全）。
        parallel_tool_calls: Some(false),
        max_tokens: config.max_tokens,
        sampling: Sampling::default(),
        model: config.model.clone(),
    }
}

/// 素朴なエージェントループ（`CognitionLevel::Off`の実体、`plans/DESIGN-COGNITION.md` §1）。
/// [`TurnExecutor::raw_turn_with_deltas`]（1ステップ）を、`tool_use`が出なくなるまで繰り返す。
///
/// ここが持つのは**1ステップの外側の責務だけ**: ターン予算（`max_turns`）・会話履歴への追記・
/// `ContextTooLong`のリアクティブ圧縮・ターン境界のイベント発行。プロバイダ呼び出し・
/// ストリーム消費・パーミッション判定・ツール実行は全て[`crate::turn`]側にある。
///
/// `gate`が全ツール呼び出しの実行前に必ず参照される唯一の強制点である性質
/// （§パーミッション（承認）システム）は[`TurnExecutor`]へ移ったが、認知レイヤーも同じ
/// 経路しか持たないため強制点は1箇所のまま保たれる。
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
    let tool_specs = tools.to_specs_for_ctx(ctx);
    let executor = TurnExecutor::new(provider, tools, ctx, gate, events, cancel);
    let tier3 = ctx.shell_tier.tier == harness_core::ShellTier::Tier3;

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

    // 縮約のヒステリシス状態（`plans/PLAN-COMPACTION.md`「ヒステリシス」）。
    // `mark`は前ターンの実測`usage`がカバーする範囲の終端。0初期化なので、`--resume`で
    // 復元した履歴全体が初回の「未計測分」として数えられる。
    let mut last_usage: Option<Usage> = None;
    let mut mark: usize = 0;
    // ②ローリング要約を既に打ったか。**1回の`run_agent_loop`で②は高々1回**に制限する。
    //
    // `plans/PLAN-COMPACTION.md`は「削減量が0だったら履歴が伸びるまで再試行しない」という
    // 長さベースのクールダウンを指定しているが、このループは毎周回で必ずメッセージが増える
    // （assistant応答＋tool_result）ため、その条件は**構造的に一度も成立しない**。
    // 実際に止めたい振動は「①が少しだけ削って目標に届かず、毎ターン②の要約コールを打つ」で、
    // ①が成功している限り長さベースの判定では止まらない。
    //
    // ②は「直近`keep_recent_turns`件より前」を丸ごと畳む操作なので、同じ`run_agent_loop`の
    // 中で2回目を打っても、新しい外部ユーザターンが無い以上ほぼ何も足せない一方、
    // 要約を要約し直して情報を失い、prompt cacheを再び全ミスさせる。1回に制限してよい。
    let mut summarized = false;

    for _ in 0..config.max_turns {
        if cancel.is_some_and(|c| c.is_cancelled()) {
            emit(events, AgentEvent::Cancelled);
            return Ok(cancelled_outcome());
        }

        let mut req = build_request(state, &tool_specs, &config);
        if tier3 {
            sanitize::completion_request(&mut req);
        }

        // 予防的縮約は`TurnStarted`を出す**前**に行う。こうすると
        // `estimated_input_tokens`が縮約後の値になり、TUI表示と実送信量が一致する。
        let pressure = assess_pressure(state, mark, last_usage, estimate_tokens(&req), &config);
        if pressure.should_compact() {
            let outcome =
                relieve_pressure(provider, state, &config, events, &pressure, summarized).await?;
            summarized |= outcome.summarized;
            if outcome.relieved {
                req = build_request(state, &tool_specs, &config);
                if tier3 {
                    sanitize::completion_request(&mut req);
                }
            }
            // 何も縮められなくてもエラーにはせずそのまま送る——推定は外れ得るので、
            // 推定だけを根拠に送信を止めない（外れていればリアクティブ経路が受け止める）。
        }

        emit(
            events,
            AgentEvent::TurnStarted {
                estimated_input_tokens: estimate_tokens(&req),
            },
        );

        let result = match executor
            .raw_turn_with_deltas(RawTurnRequest::user_facing(req.clone()), &mut on_text_delta)
            .await
        {
            Ok(r) => r,
            // 圧縮リトライは**ストリーム開始前**の失敗にだけ効く。受信中に届いた
            // `ContextTooLong`（`EngineError::Stream`）は下の一般アームでそのまま返す。
            Err(EngineError::Call(ProviderError::ContextTooLong)) => {
                let removed = compaction::compact(
                    provider,
                    state,
                    &config.model,
                    compaction::DEFAULT_KEEP_RECENT_TURNS,
                    compaction::summarize::chunk_tokens_for(config.compaction.context_window),
                )
                .await?;
                if removed > 0 {
                    emit(
                        events,
                        AgentEvent::ContextCompacted {
                            removed_messages: removed,
                        },
                    );
                } else {
                    // 直近2ターンだけで超過している等、要約では畳めない形。諦める前に
                    // **保護なし・深い下限**の切詰めを1回だけ試す（最後の手段）。
                    //
                    // ここでポリシーの`target_savings`を使ってはいけない。この経路に来た時点で
                    // 「推定は超過していないと言ったのにプロバイダが超過だと言った」＝分母
                    // （`context_window`）が実態と合っていないことが確定しており、その分母から
                    // 導いた目標は0になり得る。削減目標は置かず、**下限まで削り切る**。
                    let scope = state.messages.len();
                    let out = compaction::shrink_largest_tool_results(
                        &mut state.messages,
                        scope,
                        u64::MAX,
                        compaction::shrink::FALLBACK_FLOOR_CHARS,
                    );
                    if out.is_noop() {
                        let e = ProviderError::ContextTooLong;
                        emit(
                            events,
                            AgentEvent::Error {
                                message: e.to_string(),
                            },
                        );
                        return Err(e);
                    }
                    emit(
                        events,
                        AgentEvent::ContextShrunk {
                            truncated_blocks: out.blocks,
                            saved_tokens: out.saved_tokens,
                        },
                    );
                }
                let mut retry_req = CompletionRequest {
                    messages: state.messages.clone(),
                    ..req
                };
                if tier3 {
                    sanitize::completion_request(&mut retry_req);
                }
                match executor
                    .raw_turn_with_deltas(
                        RawTurnRequest::user_facing(retry_req),
                        &mut on_text_delta,
                    )
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        emit(
                            events,
                            AgentEvent::Error {
                                message: e.to_string(),
                            },
                        );
                        return Err(e.into_provider_error());
                    }
                }
            }
            Err(e) => {
                emit(
                    events,
                    AgentEvent::Error {
                        message: e.to_string(),
                    },
                );
                return Err(e.into_provider_error());
            }
        };

        let raw = match result {
            RawTurnResult::Completed(raw) => raw,
            RawTurnResult::CancelledMidStream => {
                emit(events, AgentEvent::Cancelled);
                return Ok(cancelled_outcome());
            }
        };

        state.messages.push(Message {
            role: Role::Assistant,
            content: raw.content,
        });
        // 実測`usage`は「このリクエストの入力＋その応答」をカバーする。assistantメッセージを
        // 積んだ**この時点**が計測済みの終端で、この後に積むtool_resultは次ターンの未計測分。
        last_usage = Some(raw.usage);
        mark = state.messages.len();

        // Phase5-C: `stop_reason`（プロバイダの`finish_reason`）ではなく、実際に`ToolUse`が
        // 積まれたかどうかで分岐する。LMStudio実機観測で、tool_callが積まれているのに
        // `finish_reason:"stop"`が返る揺れがあったため（Phase1候補C）。`tool_calls`は
        // `content`中の`ToolUse`と1対1で対応するので、空＝ツール呼び出し無し。
        if raw.tool_calls.is_empty() {
            emit(
                events,
                AgentEvent::TurnCompleted {
                    stop_reason: raw.stop_reason.clone(),
                    usage: raw.usage,
                },
            );
            return Ok(AgentLoopOutcome {
                text: raw.text,
                stop_reason: raw.stop_reason,
                usage: raw.usage,
                cancelled: false,
            });
        }

        state.messages.push(Message {
            role: Role::User,
            content: raw.tool_calls.iter().map(|c| c.to_tool_result()).collect(),
        });

        if raw.cancelled_mid_tool {
            emit(events, AgentEvent::Cancelled);
            return Ok(cancelled_outcome());
        }
    }

    Err(ProviderError::InvalidRequest {
        msg: format!("agent loop exceeded max_turns ({})", config.max_turns),
    })
}

/// 現時点のコンテキスト圧を測る。`mark`以降のメッセージが「前ターンの実測`usage`に
/// 反映されていない未計測分」。
fn assess_pressure(
    state: &ConversationState,
    mark: usize,
    last_usage: Option<Usage>,
    fallback_estimate: u64,
    config: &AgentLoopConfig,
) -> compaction::ContextPressure {
    let unmeasured = estimate_messages(&state.messages[mark.min(state.messages.len())..]);
    compaction::assess(
        last_usage,
        fallback_estimate,
        unmeasured,
        config.max_tokens,
        &config.compaction,
    )
}

/// [`relieve_pressure`]の結果。
struct Relief {
    /// 履歴が実際に小さくなったか（`true`ならリクエストを組み直す）。
    relieved: bool,
    /// このコールで②ローリング要約を打ったか（1回の`run_agent_loop`で高々1回に制限する）。
    summarized: bool,
}

/// 予防的縮約。**安い順に①→②**（`plans/PLAN-COMPACTION.md`「縮約の順序」）。
///
/// 目標に届かなくてもエラーにはしない——推定は外れ得るので、推定だけを根拠に送信を止めない
/// （外れていればリアクティブ経路が受け止める）。
///
/// `already_summarized`が`true`なら②を飛ばして①だけ行う（振動防止）。
async fn relieve_pressure(
    provider: &dyn LlmProvider,
    state: &mut ConversationState,
    config: &AgentLoopConfig,
    events: Option<&EventSink>,
    pressure: &compaction::ContextPressure,
    already_summarized: bool,
) -> Result<Relief, ProviderError> {
    let target = pressure.target_savings();
    let mut relieved = false;

    // ① tool_resultの選択的切詰め。LLMコール0・ブロック対応を壊さない・prompt cacheも壊さない。
    // 直近1ターンは保護する（モデルがまさに参照中の出力なので削らない）。
    let protect_from = compaction::protect_boundary(&state.messages, 1).unwrap_or(0);
    let out = compaction::shrink_largest_tool_results(
        &mut state.messages,
        protect_from,
        target,
        compaction::shrink::PREVENTIVE_FLOOR_CHARS,
    );
    if !out.is_noop() {
        relieved = true;
        emit(
            events,
            AgentEvent::ContextShrunk {
                truncated_blocks: out.blocks,
                saved_tokens: out.saved_tokens,
            },
        );
    }
    if out.saved_tokens >= target || already_summarized {
        return Ok(Relief {
            relieved,
            summarized: false,
        });
    }

    // ② ローリング要約。不可逆でprompt cacheを全ミスさせるので①で足りなければ初めて使う。
    let removed = compaction::compact(
        provider,
        state,
        &config.model,
        compaction::DEFAULT_KEEP_RECENT_TURNS,
        compaction::summarize::chunk_tokens_for(config.compaction.context_window),
    )
    .await?;
    if removed > 0 {
        relieved = true;
        emit(
            events,
            AgentEvent::ContextCompacted {
                removed_messages: removed,
            },
        );
    }
    Ok(Relief {
        relieved,
        summarized: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    use async_trait::async_trait;
    use futures::{stream, StreamExt};
    use harness_core::{BlockKind, StreamEvent, ToolOutput};

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

    /// `estimate_tokens`・`estimate_messages`が**同一のコア**（`estimate_json_tokens`）に
    /// 載っていること。縮約の発火判定はリクエスト全体ではなく未計測のメッセージだけを測るため
    /// 別入口が要るが、推定式が枝分かれすると「TUI表示の概算」と「縮約の判定」がずれる
    /// （`docs/CODE-STRUCTURE-RULES.md` 規則5）。
    #[test]
    fn the_request_and_message_estimators_share_one_core() {
        let messages = vec![Message {
            role: Role::User,
            content: vec![ContentBlock::Text("あ".repeat(1000))],
        }];
        let req = CompletionRequest {
            system: vec![],
            messages: messages.clone(),
            tools: vec![],
            tool_choice: ToolChoice::None,
            output: None,
            parallel_tool_calls: None,
            max_tokens: 100,
            sampling: Sampling::default(),
            model: "mock".into(),
        };

        assert_eq!(estimate_tokens(&req), estimate_json_tokens(&req));
        assert_eq!(
            estimate_messages(&messages),
            estimate_json_tokens(&messages)
        );
        // メッセージ単体の見積りはリクエスト全体を上回らない（包含関係）。
        assert!(estimate_messages(&messages) < estimate_tokens(&req));
        // 空なら実質ゼロ（JSONの`[]`ぶんだけ）。
        assert_eq!(estimate_messages(&[]), 0);
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
        ) -> Result<
            futures::stream::BoxStream<'static, Result<StreamEvent, ProviderError>>,
            ProviderError,
        > {
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

    struct RecordingProvider {
        seen_requests: std::sync::Arc<Mutex<Vec<CompletionRequest>>>,
    }

    #[async_trait]
    impl LlmProvider for RecordingProvider {
        fn id(&self) -> &str {
            "recording"
        }

        async fn stream(
            &self,
            req: CompletionRequest,
        ) -> Result<
            futures::stream::BoxStream<'static, Result<StreamEvent, ProviderError>>,
            ProviderError,
        > {
            self.seen_requests.lock().unwrap().push(req);
            Ok(Box::pin(stream::iter(end_turn("done").into_iter().map(Ok))))
        }
    }

    #[tokio::test]
    async fn run_agent_loop_sends_tier3_specific_run_shell_tool_spec() {
        let dir = tempfile::tempdir().unwrap();
        let seen_requests = std::sync::Arc::new(Mutex::new(Vec::new()));
        let provider = RecordingProvider {
            seen_requests: std::sync::Arc::clone(&seen_requests),
        };
        let tools = harness_tools::ToolRegistry::with_builtin_tools();
        let mut ctx = ToolCtx::new(dir.path().to_path_buf());
        ctx.workspace_root = std::path::PathBuf::from(r"C:\Users\me\project");
        ctx.shell_tier = harness_core::ShellTierSelection::direct(harness_core::ShellTier::Tier3);
        let mut state = ConversationState::new(system_blocks_for(&ctx));
        state.messages.push(Message {
            role: Role::Assistant,
            content: vec![
                ContentBlock::Text(r"old thought mentioned C:\Users\me\project".to_string()),
                ContentBlock::Thinking {
                    text: r"signed thought mentioned C:\Users\me\project".to_string(),
                    signature: Some("signed".to_string()),
                },
                ContentBlock::RedactedThinking {
                    data: r"redacted thought mentioned C:\Users\me\project".to_string(),
                },
                ContentBlock::ToolUse {
                    id: "old_call".to_string(),
                    name: "run_shell".to_string(),
                    input: serde_json::json!({
                        "command": r#"Get-ChildItem "C:\Users\me\project""#,
                    }),
                },
            ],
        });
        state.messages.push(Message {
            role: Role::User,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: "old_call".to_string(),
                content: r"old result mentioned C:\Users\me\project".to_string(),
                is_error: true,
            }],
        });
        state.push_user_text("list files");
        let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);

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
                compaction: Default::default(),
            },
            None,
            None,
            |_| {},
        )
        .await
        .unwrap();

        let requests = seen_requests.lock().unwrap();
        let run_shell = requests[0]
            .tools
            .iter()
            .find(|spec| spec.name == "run_shell")
            .expect("run_shell spec should be sent");
        assert!(
            run_shell.description.contains("`sh -c`"),
            "{}",
            run_shell.description
        );
        assert!(!run_shell.description.contains("PowerShell"));
        assert_eq!(requests[0].system.len(), 1);
        let system = &requests[0].system[0].text;
        assert!(
            system.contains("ワークスペースルート: /workspace"),
            "{system}"
        );
        assert!(!system.contains(r"C:\Users"), "{system}");
        let request_json = serde_json::to_string(&requests[0]).unwrap();
        assert!(!request_json.contains(r"C:\Users"), "{request_json}");
        assert!(!request_json.contains("Windowsホスト"), "{request_json}");
        assert!(!request_json.contains("ホスト側"), "{request_json}");
        assert!(!request_json.contains("ホストOS"), "{request_json}");
        assert!(!request_json.contains("signed thought"), "{request_json}");
        assert!(!request_json.contains("redacted thought"), "{request_json}");
        assert!(request_json.contains("/workspace"), "{request_json}");
    }

    #[tokio::test]
    async fn tier3_text_deltas_are_sanitized_before_display() {
        let dir = tempfile::tempdir().unwrap();
        let provider = MockProvider {
            turns: Mutex::new(vec![end_turn(r"checking C:\Users\me\project")]),
        };
        let tools = harness_tools::ToolRegistry::with_builtin_tools();
        let mut ctx = ToolCtx::new(dir.path().to_path_buf());
        ctx.shell_tier = harness_core::ShellTierSelection::direct(harness_core::ShellTier::Tier3);
        let mut state = ConversationState::new(system_blocks_for(&ctx));
        state.push_user_text("hi");
        let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let visible = std::sync::Arc::new(Mutex::new(String::new()));
        let visible_for_callback = std::sync::Arc::clone(&visible);

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
                compaction: Default::default(),
            },
            Some(&events_tx),
            None,
            |delta| visible_for_callback.lock().unwrap().push_str(delta),
        )
        .await
        .unwrap();

        let callback_text = visible.lock().unwrap().clone();
        let mut event_text = String::new();
        while let Ok(event) = events_rx.try_recv() {
            if let AgentEvent::TextDelta { text } = event {
                event_text.push_str(&text);
            }
        }

        assert!(!outcome.text.contains(r"C:\Users"), "{}", outcome.text);
        assert!(!callback_text.contains(r"C:\Users"), "{callback_text}");
        assert!(!event_text.contains(r"C:\Users"), "{event_text}");
        assert!(outcome.text.contains("/workspace"), "{}", outcome.text);
        assert!(callback_text.contains("/workspace"), "{callback_text}");
        assert!(event_text.contains("/workspace"), "{event_text}");
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
        let mut state = ConversationState::new(Vec::new());
        state.push_user_text("run a shell command");
        let tools = harness_tools::ToolRegistry::with_builtin_tools();
        let ctx = ToolCtx::new(dir.path().to_path_buf());
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
                compaction: Default::default(),
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
                tool_use_turn(
                    "call_1",
                    "read_file",
                    serde_json::json!({ "path": "a.txt" }),
                ),
                end_turn("summarized"),
            ]),
        };
        let mut state = ConversationState::new(Vec::new());
        state.push_user_text("read a.txt");
        let tools = harness_tools::ToolRegistry::with_builtin_tools();
        let ctx = ToolCtx::new(dir.path().to_path_buf());
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
                compaction: Default::default(),
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
        let mut state = ConversationState::new(Vec::new());
        state.push_user_text("run an allowed shell command");
        let tools = harness_tools::ToolRegistry::with_builtin_tools();
        let ctx = ToolCtx::new(dir.path().to_path_buf());
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
                compaction: Default::default(),
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
        ) -> Result<
            futures::stream::BoxStream<'static, Result<StreamEvent, ProviderError>>,
            ProviderError,
        > {
            let partial = vec![
                Ok(StreamEvent::BlockStart {
                    index: 0,
                    kind: BlockKind::Text,
                }),
                Ok(StreamEvent::TextDelta {
                    index: 0,
                    text: "partial".to_string(),
                }),
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
        let mut state = ConversationState::new(Vec::new());
        state.push_user_text("hi");
        let messages_before = state.messages.len();
        let tools = harness_tools::ToolRegistry::with_builtin_tools();
        let ctx = ToolCtx::new(dir.path().to_path_buf());
        let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
        let cancel = CancellationToken::new();

        let outcome = {
            let run_fut = run_agent_loop(
                &provider,
                &mut state,
                &tools,
                &ctx,
                &arbiter,
                AgentLoopConfig {
                    model: "mock".into(),
                    max_tokens: 100,
                    max_turns: 5,
                    compaction: Default::default(),
                },
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
            Ok(ToolOutput {
                content: "slow-done".to_string(),
                is_error: false,
            })
        }
    }

    fn multi_tool_use_turn(calls: &[(&str, &str, serde_json::Value)]) -> Vec<StreamEvent> {
        let mut events = Vec::new();
        for (index, (id, name, input)) in calls.iter().enumerate() {
            events.push(StreamEvent::BlockStart {
                index,
                kind: BlockKind::ToolUse {
                    id: id.to_string(),
                    name: name.to_string(),
                },
            });
            events.push(StreamEvent::ToolInputDelta {
                index,
                json_fragment: input.to_string(),
            });
            events.push(StreamEvent::BlockStop { index });
        }
        events.push(StreamEvent::Done {
            stop_reason: StopReason::ToolUse,
            usage: Usage::default(),
        });
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
        let mut state = ConversationState::new(Vec::new());
        state.push_user_text("run two slow tools");
        let mut tools = harness_tools::ToolRegistry::new();
        tools.register(std::sync::Arc::new(SlowTool));
        let ctx = ToolCtx::new(dir.path().to_path_buf());
        let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
        let cancel = CancellationToken::new();

        let outcome = {
            let run_fut = run_agent_loop(
                &provider,
                &mut state,
                &tools,
                &ctx,
                &arbiter,
                AgentLoopConfig {
                    model: "mock".into(),
                    max_tokens: 100,
                    max_turns: 5,
                    compaction: Default::default(),
                },
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
                ContentBlock::ToolResult {
                    tool_use_id,
                    content,
                    is_error,
                } => Some((tool_use_id.clone(), content.clone(), *is_error)),
                _ => None,
            })
            .collect();
        assert_eq!(
            tool_results.len(),
            2,
            "both tool_use blocks must have a matching tool_result"
        );
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
            AgentLoopConfig {
                model: "mock".into(),
                max_tokens: 100,
                max_turns: 5,
                compaction: Default::default(),
            },
            None,
            None,
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(outcome2.text, "continued fine");
    }

    /// characterization test（M13: `raw_turn`抽出の回帰ガード）。mid-toolキャンセルで
    /// 「まだ手を付けていない残りの`tool_use`」は、対応する`tool_result`だけが合成され
    /// `AgentEvent`は**一切出ない**（`ToolCallProposed`/`ToolStarted`/`ToolFinished`の
    /// どれも発行されない）。ツール実行ループを`raw_turn`側へ移すとき、合成経路にも
    /// うっかりイベント発行を足すと`harness-cli`の`tool_calls`集計（`ToolCallProposed`と
    /// `ToolFinished`をidで対応付ける）に実行されていない呼び出しが混ざるため、ここで固定する。
    #[tokio::test]
    async fn cancelled_remaining_tool_calls_emit_no_events() {
        let dir = tempfile::tempdir().unwrap();
        let provider = MockProvider {
            turns: Mutex::new(vec![multi_tool_use_turn(&[
                ("call_1", "slow_tool", serde_json::json!({})),
                ("call_2", "slow_tool", serde_json::json!({})),
            ])]),
        };
        let mut state = ConversationState::new(Vec::new());
        state.push_user_text("run two slow tools");
        let mut tools = harness_tools::ToolRegistry::new();
        tools.register(std::sync::Arc::new(SlowTool));
        let ctx = ToolCtx::new(dir.path().to_path_buf());
        let arbiter = PermissionArbiter::new(PermissionMode::Default, vec![]);
        let cancel = CancellationToken::new();
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();

        let outcome = {
            let run_fut = run_agent_loop(
                &provider,
                &mut state,
                &tools,
                &ctx,
                &arbiter,
                AgentLoopConfig {
                    model: "mock".into(),
                    max_tokens: 100,
                    max_turns: 5,
                    compaction: Default::default(),
                },
                Some(&events_tx),
                Some(&cancel),
                |_| {},
            );
            tokio::pin!(run_fut);
            let cancel_after_delay = async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                cancel.cancel();
            };
            let (outcome, ()) = tokio::join!(run_fut, cancel_after_delay);
            outcome.unwrap()
        };
        assert!(outcome.cancelled);

        let mut tool_events: Vec<(&'static str, String)> = Vec::new();
        while let Ok(ev) = events_rx.try_recv() {
            match ev {
                AgentEvent::ToolCallProposed { id, .. } => {
                    tool_events.push(("ToolCallProposed", id))
                }
                AgentEvent::ToolStarted { id, .. } => tool_events.push(("ToolStarted", id)),
                AgentEvent::ToolFinished { id, .. } => tool_events.push(("ToolFinished", id)),
                _ => {}
            }
        }

        assert_eq!(
            tool_events,
            vec![
                ("ToolCallProposed", "call_1".to_string()),
                ("ToolStarted", "call_1".to_string()),
                ("ToolFinished", "call_1".to_string()),
            ],
            "the cancelled second tool_use must not emit any tool event"
        );
    }
}
