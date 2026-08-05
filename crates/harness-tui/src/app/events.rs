//! `harness-engine`から流れてくる[`AgentEvent`]の消費。
//!
//! トランスクリプト（[`TranscriptItem`]）・ツールカード・権限モーダルといった「画面に出るもの」を
//! イベントから組み立てる責務だけを持つ。キー入力は扱わない（[`super::input`]）。

use super::*;

impl AppState {
    pub fn apply(&mut self, ev: AgentEvent) {
        match ev {
            AgentEvent::TurnStarted {
                estimated_input_tokens,
            } => {
                self.turn_open = false;
                self.turn_in_flight = true;
                self.turn_transcript_mark = self.transcript.len();
                self.current_turn_upstream_estimate = estimated_input_tokens;
                self.current_turn_downstream_chars = 0;
                self.saw_thinking_this_turn = false;
                self.thinking_progress = Some(Instant::now());
            }
            AgentEvent::TextDelta { text } => {
                self.current_turn_downstream_chars += text.chars().count() as u64;

                if !self.turn_open {
                    // モデル（特にLMStudio経由のローカルモデル）がチャットテンプレートの都合で
                    // 応答冒頭に意味の無い改行/空白だけのデルタを送ってくることがある。
                    // まだ非空白の内容が届いていないうちに「考え中」インジケータを消して
                    // 空のAssistant項目を作ってしまうと、インジケータが消えた場所に空行だけが
                    // 残ってしまう。実際に非空白の内容が来た最初のデルタで初めてインジケータを
                    // 終了しAssistant項目を作ることで、この空行を防ぐ
                    // （空白だけのデルタ自体は`current_turn_downstream_chars`には既に加算済み
                    // なので、ライブのトークン概算からは取りこぼさない）。
                    let visible = text.trim_start_matches(['\n', '\r', ' ', '\t']);
                    if visible.is_empty() {
                        return;
                    }
                    self.end_thinking_progress(true);
                    self.transcript
                        .push(TranscriptItem::Assistant(visible.to_string()));
                    self.turn_open = true;
                    return;
                }

                if let Some(TranscriptItem::Assistant(s)) = self.transcript.last_mut() {
                    s.push_str(&text);
                }
            }
            AgentEvent::ThinkingDelta { text } => {
                self.current_turn_downstream_chars += text.chars().count() as u64;
                self.saw_thinking_this_turn = true;
                if let Some(TranscriptItem::Thinking(s)) = self.transcript.last_mut() {
                    s.push_str(&text);
                } else {
                    self.transcript.push(TranscriptItem::Thinking(text));
                }
            }
            AgentEvent::ToolCallProposed { id, name, input } => {
                self.end_thinking_progress(true);
                self.turn_open = false;
                self.transcript.push(TranscriptItem::ToolCard {
                    id,
                    name,
                    input: pretty(&input),
                    status: ToolCardStatus::Running,
                });
            }
            AgentEvent::PermissionRequired {
                id,
                tool,
                risk,
                input,
            } => {
                // `edit_file`は`old_string`/`new_string`から差分を作れる場合のみdiffを埋める
                // （§リッチTUI「edit_fileの差分プレビューを承認モーダル内に描画」）。
                let diff = if tool == "edit_file" {
                    let old = input.get("old_string").and_then(|v| v.as_str());
                    let new = input.get("new_string").and_then(|v| v.as_str());
                    match (old, new) {
                        (Some(old), Some(new)) => Some(line_diff(old, new)),
                        _ => None,
                    }
                } else {
                    None
                };
                self.pending_permission = Some(PermissionView {
                    id,
                    tool,
                    risk,
                    input: pretty(&input),
                    diff,
                });
            }
            AgentEvent::ToolStarted { .. } => {}
            AgentEvent::ToolProgress { id, message } => {
                tracing::debug!(id, message, "tool progress");
            }
            AgentEvent::ToolFinished { id, output } => {
                if let Some(TranscriptItem::ToolCard { status, .. }) =
                    self.transcript.iter_mut().rev().find(
                        |i| matches!(i, TranscriptItem::ToolCard { id: cid, .. } if *cid == id),
                    )
                {
                    *status = ToolCardStatus::Done {
                        is_error: output.is_error,
                        output: truncate_output(&output),
                    };
                }
            }
            AgentEvent::TurnCompleted { stop_reason, usage } => {
                self.last_stop_reason = Some(stop_reason);
                self.last_usage = usage;
                self.session_usage.input = self.session_usage.input.saturating_add(usage.input);
                self.session_usage.output = self.session_usage.output.saturating_add(usage.output);
                self.session_usage.cache_read = self
                    .session_usage
                    .cache_read
                    .saturating_add(usage.cache_read);
                self.session_usage.cache_creation = self
                    .session_usage
                    .cache_creation
                    .saturating_add(usage.cache_creation);
                self.turn_open = false;
                self.turn_in_flight = false;
                // 本文もツール呼び出しも一切無いまま終わるターン（安全網）。記録行は残さず黙って消す。
                self.end_thinking_progress(false);
            }
            AgentEvent::Error { message } => {
                self.transcript.push(TranscriptItem::Error(message));
                self.turn_open = false;
                self.turn_in_flight = false;
                self.end_thinking_progress(false);
            }
            AgentEvent::Cancelled => {
                self.transcript
                    .push(TranscriptItem::Info("cancelled".to_string()));
                self.turn_open = false;
                self.turn_in_flight = false;
                self.end_thinking_progress(false);
            }
            AgentEvent::ContextCompacted { removed_messages } => {
                self.transcript.push(TranscriptItem::Info(format!(
                    "context compacted ({removed_messages} messages summarized)"
                )));
            }
            // モデルが既に見たツール出力を静かに縮めるのは、ユーザに見えるべき副作用。
            // メッセージは1件も消えていないので`ContextCompacted`とは別の文面にする。
            AgentEvent::ContextShrunk {
                truncated_blocks,
                saved_tokens,
            } => {
                self.transcript.push(TranscriptItem::Info(format!(
                    "context shrunk ({truncated_blocks} tool results truncated, \
                     ~{saved_tokens} tokens saved)"
                )));
            }
            // 縮退した応答を破棄した（M21、`plans/DESIGN-COGNITION.md` §11.4）。
            // **画面に出てしまった本文をこの試行の開始位置まで巻き戻す**——捨てた出力が
            // 残っていると、次の試行の本文と連結して読めてしまう。
            //
            // 巻き戻した後に記録行を1本置き、markをその後ろへ進める。進めないと、
            // 同じターンで2回目の破棄が起きたときにこの記録行まで消えてしまい、
            // 「何回捨てたのか」がユーザから見えなくなる。
            AgentEvent::TurnDiscarded {
                kind,
                reason,
                next_rung,
                ..
            } => {
                self.transcript
                    .truncate(self.turn_transcript_mark.min(self.transcript.len()));
                let next = match &next_rung {
                    Some(rung) => format!("再試行: {rung}"),
                    None => "再試行の手立てを使い切った".to_string(),
                };
                self.transcript.push(TranscriptItem::Info(format!(
                    "[縮退] 応答を破棄した（{kind}）: {reason} — {next}"
                )));
                self.turn_transcript_mark = self.transcript.len();
                self.turn_open = false;
                self.end_thinking_progress(false);
            }
            // --- 認知レイヤー（M15）---
            // 台帳ビュー（推論パネル、`plans/DESIGN-COGNITION.md` §8）はまだ作らず、
            // トランスクリプトへ1行ずつ残す。フェーズ本文はモデルが返した構造化出力
            // （`TurnVisibility::Internal`）なのでここには一切流れてこない——見えるのは
            // 「今どのフェーズか」「何を仮説にしたか」「何を観測したか」「判定はどうだったか」
            // という**推論の骨格だけ**になる。
            AgentEvent::PhaseChanged { phase } => {
                // フェーズ境界で「考え中」インジケータを畳む（次フェーズが新たに開く）。
                self.end_thinking_progress(false);
                self.transcript
                    .push(TranscriptItem::Info(format!("[認知] {phase}")));
            }
            AgentEvent::HypothesisFormed {
                id,
                statement,
                predicts,
            } => {
                self.transcript.push(TranscriptItem::Info(format!(
                    "[仮説] {id} {statement}（反証条件: {}）",
                    predicts.join(" / ")
                )));
            }
            AgentEvent::EvidenceAdded {
                id,
                claim,
                source,
                validity,
            } => {
                self.transcript.push(TranscriptItem::Info(format!(
                    "[証拠] {id} {claim}（出典: {source}／妥当性: {validity}）"
                )));
            }
            AgentEvent::VerificationResult {
                hyp,
                verdict,
                missing,
                promoted,
                strength,
            } => {
                let mut line = format!("[検証] {hyp} {verdict}（根拠: {strength}）");
                if promoted {
                    line.push_str("（確証）");
                }
                if !missing.is_empty() {
                    line.push_str(&format!("／不足: {}", missing.join(" / ")));
                }
                self.transcript.push(TranscriptItem::Info(line));
            }
            AgentEvent::SessionSwitched {
                source_id,
                new_id,
                message_count,
            } => {
                let msg = match source_id {
                    Some(src) => {
                        format!("forked session {src} -> {new_id} ({message_count} messages)")
                    }
                    None => format!("switched to session {new_id} ({message_count} messages)"),
                };
                self.transcript.push(TranscriptItem::Info(msg));
            }
        }
    }
}

pub(super) fn pretty(v: &serde_json::Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

const MAX_OUTPUT_PREVIEW: usize = 400;

pub(super) fn truncate_output(output: &ToolOutput) -> String {
    if output.content.chars().count() > MAX_OUTPUT_PREVIEW {
        let head: String = output.content.chars().take(MAX_OUTPUT_PREVIEW).collect();
        format!("{head}... (truncated)")
    } else {
        output.content.clone()
    }
}
