//! harness-cli のライブラリ部分。`plans/DESIGN.md` §非対話（ヘッドレス）モード参照。
//!
//! M8で`--output-format text|json|jsonl`の3形式出力を担う`run_headless`をここへ切り出した。
//! `main.rs`（binターゲット）は薄いclapエントリのみを持ち、`MockProvider`
//! （`harness-providers`）を使ったユニットテストがしやすいよう、実際にstdoutへ書き出す
//! ロジックを`W: std::io::Write`に対する汎用関数として公開する
//! （§実装マイルストーン M8検証条件「`harness -p ... --output-format json | jq`が安定スキーマ」）。

/// `harness fs`サブコマンド群（付与済みACEの一覧・撤収・traverse付与）。
///
/// `main.rs`（binターゲット）はclap定義とディスパッチだけを持ち、実処理はlib側の
/// このモジュールが持つ（`docs/CODE-STRUCTURE-RULES.md`規則4: 終端クレートなので
/// テスト可能性を優先してlibへ置く）。
pub mod cli;
pub mod fs_grants;

use std::collections::HashMap;
use std::io::Write;
use std::process::ExitCode;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use harness_core::{AgentEvent, LlmProvider, ProviderError, StopReason, ToolCtx, Usage};
use harness_engine::{run_agent_loop, AgentLoopConfig, ConversationState, PermissionGate};
use harness_tools::ToolRegistry;

/// `--output-format`の3値（§非対話モード「出力」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Jsonl,
}

/// `json`出力の安定オブジェクト（§非対話モード「出力」`json`）。
/// `stop_reason`/`error`は`Option`のままシリアライズし（`null`として出力）、
/// キー自体は常に存在させることで`jq`から見たスキーマを安定させる。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonOutcome {
    pub result: String,
    pub stop_reason: Option<StopReason>,
    pub turns: usize,
    pub tool_calls: Vec<JsonToolCall>,
    pub usage: Usage,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonToolCall {
    pub name: String,
    pub input: serde_json::Value,
    pub result: String,
    /// `"allowed"` | `"denied"`。`PermissionGate`が拒否した呼び出しは`run_agent_loop`が
    /// 合成するエラー`ToolResult`の文言（`permission denied by policy`接頭辞）で判別する
    /// （`crates/harness-engine/src/lib.rs`のツールディスパッチ参照）。
    pub decision: String,
}

const DENIAL_PREFIX: &str = "permission denied by policy";

/// `AgentEvent`列から`turns`/`usage`/`tool_calls`を畳み込む。`ToolCallProposed`と
/// `ToolFinished`はidで対応付ける（`run_agent_loop`は同一idで両方を必ず1回ずつ発行する）。
fn record_event(
    ev: &AgentEvent,
    turns: &mut usize,
    usage: &mut Usage,
    pending: &mut HashMap<String, (String, serde_json::Value)>,
    tool_calls: &mut Vec<JsonToolCall>,
) {
    match ev {
        AgentEvent::TurnStarted { .. } => *turns += 1,
        AgentEvent::TurnCompleted { usage: u, .. } => *usage = *u,
        AgentEvent::ToolCallProposed { id, name, input } => {
            pending.insert(id.clone(), (name.clone(), input.clone()));
        }
        AgentEvent::ToolFinished { id, output } => {
            if let Some((name, input)) = pending.remove(id) {
                let decision = if output.content.starts_with(DENIAL_PREFIX) {
                    "denied"
                } else {
                    "allowed"
                };
                tool_calls.push(JsonToolCall {
                    name,
                    input,
                    result: output.content.clone(),
                    decision: decision.to_string(),
                });
            }
        }
        _ => {}
    }
}

/// §非対話モード「終了コード: 成功0／プロバイダ・ツール・パーミッション失敗は非0
/// （`stop_reason`を反映）」。プロバイダ層のエラー（ネットワーク/認証/`max_turns`超過等）は
/// `run_agent_loop`が`Err`で返すため一律1、正常終了した`AgentLoopOutcome`は`stop_reason`ごとに
/// 割り振る。ツール呼び出し個々の失敗・パーミッション拒否は`tool_result`としてモデルへ
/// 返され通常ループが継続する設計（§エージェントループ 手順4）のため、ここでは扱わない。
fn exit_code_for(result: &Result<harness_engine::AgentLoopOutcome, ProviderError>) -> ExitCode {
    match result {
        Err(_) => ExitCode::FAILURE,
        Ok(outcome) => match outcome.stop_reason {
            StopReason::EndTurn | StopReason::StopSequence => ExitCode::SUCCESS,
            StopReason::MaxTokens => ExitCode::from(2),
            StopReason::Refusal => ExitCode::from(3),
            StopReason::ToolUse | StopReason::Other(_) => ExitCode::from(4),
        },
    }
}

/// 非対話モードの1回分の実行。`output_format`に応じて`writer`へ書き出す内容を切り替える。
///
/// - `Text`: `TextDelta`をその場で`writer`へ流す（M2以来の既存挙動、`events`は使わない）
/// - `Json`: 完了後に1行の安定オブジェクト（`JsonOutcome`）のみを書く
/// - `Jsonl`: `AgentEvent`を受信の都度1行ずつ書く（`tokio::select!`で`run_agent_loop`の
///   `Future`と`events`受信を並行に進める。`run_agent_loop`はstream待ちの`.await`点でしか
///   executorに制御を返さないため、これが無いとイベントがまとめて末尾に出てしまう）
#[allow(clippy::too_many_arguments)]
pub async fn run_headless<W: Write>(
    provider: &dyn LlmProvider,
    state: &mut ConversationState,
    tools: &ToolRegistry,
    ctx: &ToolCtx,
    gate: &dyn PermissionGate,
    config: AgentLoopConfig,
    output_format: OutputFormat,
    writer: &mut W,
) -> ExitCode {
    match output_format {
        OutputFormat::Text => {
            let result = run_agent_loop(
                provider,
                state,
                tools,
                ctx,
                gate,
                config,
                None,
                None,
                |delta| {
                    let _ = writer.write_all(delta.as_bytes());
                    let _ = writer.flush();
                },
            )
            .await;
            match &result {
                Ok(_) => {
                    let _ = writeln!(writer);
                }
                Err(e) => {
                    eprintln!("provider error: {e}");
                }
            }
            exit_code_for(&result)
        }
        OutputFormat::Json | OutputFormat::Jsonl => {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let loop_fut = run_agent_loop(
                provider,
                state,
                tools,
                ctx,
                gate,
                config,
                Some(&tx),
                None,
                |_delta| {},
            );
            tokio::pin!(loop_fut);

            let mut turns = 0usize;
            let mut usage = Usage::default();
            let mut pending = HashMap::new();
            let mut tool_calls = Vec::new();

            let result = loop {
                tokio::select! {
                    maybe_ev = rx.recv() => {
                        let Some(ev) = maybe_ev else { continue };
                        if output_format == OutputFormat::Jsonl {
                            if let Ok(line) = serde_json::to_string(&ev) {
                                let _ = writeln!(writer, "{line}");
                            }
                        }
                        record_event(&ev, &mut turns, &mut usage, &mut pending, &mut tool_calls);
                    }
                    res = &mut loop_fut => {
                        break res;
                    }
                }
            };
            // `run_agent_loop`完了後もチャンネルに未読の`AgentEvent`が残り得る
            // （`Future`側が先に`Ready`になった`select!`分岐で終わるレース）ため排出する。
            while let Ok(ev) = rx.try_recv() {
                if output_format == OutputFormat::Jsonl {
                    if let Ok(line) = serde_json::to_string(&ev) {
                        let _ = writeln!(writer, "{line}");
                    }
                }
                record_event(&ev, &mut turns, &mut usage, &mut pending, &mut tool_calls);
            }

            if output_format == OutputFormat::Json {
                let outcome = JsonOutcome {
                    result: result.as_ref().map(|o| o.text.clone()).unwrap_or_default(),
                    stop_reason: result.as_ref().ok().map(|o| o.stop_reason.clone()),
                    turns,
                    tool_calls,
                    usage,
                    error: result.as_ref().err().map(|e| e.to_string()),
                };
                if let Ok(line) = serde_json::to_string(&outcome) {
                    let _ = writeln!(writer, "{line}");
                }
            }

            exit_code_for(&result)
        }
    }
}

/// `--allow`ルールのうち、パターンが完全ワイルドカード（`*`、そのツールの全入力を許可）の
/// ものは`--dangerously-allow`が無いと危険すぎるため無視する
/// （§非対話モード「危険/ワイルドカードは`--dangerously-allow`」）。前方一致の
/// `git status*`のような具体的パターンはこの制限を受けない。
pub fn is_dangerous_wildcard(pattern: &str) -> bool {
    pattern == "*"
}
