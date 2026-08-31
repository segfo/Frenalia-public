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
                // BUG-078: 予防的縮約はターン開始**前**に走る。ここへ来た時点でそれは終わって
                // いるので、進捗表示を畳んでから（＝記録行をターン境界のマーカーより前に置いてから）
                // ターンの状態へ移る。要約が0件で`ContextCompacted`が出なかった場合の受け皿も
                // これが兼ねる。
                self.end_busy_if_running(BusyEnd::Finished);
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
                    status: ToolCardStatus::Running { wait_reason: None },
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
                        (Some(old), Some(new)) => Some(diff_lines(old, new)),
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
            // [BUG-082フォローアップ] `run_shell`等が背景条件（D-54のworkspace ACL伝播ジョブ等）
            // で待たされている理由をツールカードへ映す。空文字列は「待機理由が無くなった」の
            // 合図（`call_with_wait_reasons`のdoc参照、`harness-engine`）——直前の理由を
            // 実行終了まで表示し続けないよう`None`へ戻す。
            AgentEvent::ToolProgress { id, message } => {
                tracing::debug!(id, message, "tool progress");
                if let Some(TranscriptItem::ToolCard {
                    status: ToolCardStatus::Running { wait_reason },
                    ..
                }) =
                    self.transcript.iter_mut().rev().find(
                        |i| matches!(i, TranscriptItem::ToolCard { id: cid, .. } if *cid == id),
                    )
                {
                    *wait_reason = if message.is_empty() {
                        None
                    } else {
                        Some(message)
                    };
                }
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
                self.end_busy_if_running(BusyEnd::Finished);
                self.transcript.push(TranscriptItem::Error(message));
                self.turn_open = false;
                self.turn_in_flight = false;
                self.end_thinking_progress(false);
            }
            AgentEvent::Cancelled => {
                // BUG-074: 止めたものを「完了した」と書かない。
                self.end_busy_if_running(BusyEnd::Stopped);
                self.transcript
                    .push(TranscriptItem::Info("cancelled".to_string()));
                self.turn_open = false;
                self.turn_in_flight = false;
                self.end_thinking_progress(false);
            }
            // BUG-071: 開始したこと自体はtranscriptへ積まない。進捗は`busy_progress`が持つ
            // 一時行で表す。`/compact`コマンド経由なら`lib.rs`が既に`begin_busy`で置き場を
            // 作っているので「待機中→実行中」へ移すだけ。**engineが自分の判断で始めた**
            // 予防的縮約の要約（BUG-078）では置き場が無いので、ここで作る。
            AgentEvent::ContextCompactionStarted => {
                self.begin_busy_running("Compacting context");
            }
            AgentEvent::ContextCompacted { removed_messages } => {
                // 記録行は**結果行より先**に積む（スピナーがあった位置がそのまま記録になり、
                // 結果はその下に続く）。
                self.end_busy_if_running(BusyEnd::Finished);
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
            // ③段。切詰め（機械的・欠けが見て取れる）と違い**モデルが書いた要約**への
            // 置き換えなので、別の文面で「digest」と名指しする。取りこぼしを疑ってツールを
            // 再実行するかどうかはユーザー（とモデル）の判断材料になる。
            AgentEvent::ToolResultsDigested {
                digested_blocks,
                saved_tokens,
            } => {
                self.end_busy_if_running(BusyEnd::Finished);
                self.transcript.push(TranscriptItem::Info(format!(
                    "tool outputs digested ({digested_blocks} outputs summarized in place, \
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
            // BUG-079: ツール呼び出しが本文テキストとして出た。
            //
            // `retrying`なら`TurnDiscarded`と同じ扱い——**画面に出てしまった本文をこの試行の
            // 開始位置まで巻き戻す**（捨てた出力が次の試行の本文と連結して読めてしまう）。
            // `retrying`が`false`のときは本文をそのまま答えとして採用するので**巻き戻さない**。
            AgentEvent::ToolCallWrittenAsText {
                marker, retrying, ..
            } => {
                if retrying {
                    self.transcript
                        .truncate(self.turn_transcript_mark.min(self.transcript.len()));
                    self.transcript.push(TranscriptItem::Info(format!(
                        "[ツール呼び出し] 本文に書かれていたため実行されなかった（{marker}）\
                         : 応答を破棄し、呼び出し直すよう伝えて再送する"
                    )));
                    self.turn_transcript_mark = self.transcript.len();
                    self.turn_open = false;
                    self.end_thinking_progress(false);
                } else {
                    self.transcript.push(TranscriptItem::Info(format!(
                        "[ツール呼び出し] 本文に書かれた呼び出し（{marker}）は実行していない\
                         。再送しても同じだったため、この応答をそのまま採用した"
                    )));
                }
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
            // --- Recall（`plans/PLAN-RECALL-MEMORY.md`）---
            // `skipped`が無音にならないよう、成功/スキップのどちらも1行残す（B-10）。
            AgentEvent::MemoryRecalled {
                candidates,
                injected,
                skipped,
            } => {
                let line = match skipped {
                    Some(reason) => format!("[記憶] 読出しスキップ: {reason}"),
                    None if candidates == 0 => "[記憶] 該当する過去の記憶なし".to_string(),
                    None => format!("[記憶] {candidates}件ヒット→{injected}件を採用"),
                };
                self.transcript.push(TranscriptItem::Info(line));
            }
            AgentEvent::MemoryCheckpointed { id, skipped } => {
                let line = match (id, skipped) {
                    (Some(id), _) => format!("[記憶] 保存: {id}"),
                    (None, Some(reason)) => format!("[記憶] 保存スキップ: {reason}"),
                    (None, None) => "[記憶] 保存条件を満たさなかった".to_string(),
                };
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

pub(super) const MAX_OUTPUT_PREVIEW: usize = 400;

pub(super) fn truncate_output(output: &ToolOutput) -> String {
    if output.content.chars().count() > MAX_OUTPUT_PREVIEW {
        let head: String = output.content.chars().take(MAX_OUTPUT_PREVIEW).collect();
        format!("{head}... (truncated)")
    } else {
        output.content.clone()
    }
}
