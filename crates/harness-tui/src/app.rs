//! `AppState`: `AgentEvent`を畳み込んで保持するTUI側の状態。`plans/DESIGN.md` §リッチTUI参照。

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use harness_core::{AgentEvent, RiskClass, StopReason, ToolOutput, Usage};
use harness_engine::Decision;

#[derive(Debug, Clone)]
pub enum ToolCardStatus {
    Running,
    Done { is_error: bool, output: String },
}

#[derive(Debug, Clone)]
pub enum TranscriptItem {
    User(String),
    Assistant(String),
    Thinking(String),
    ToolCard {
        id: String,
        name: String,
        input: String,
        status: ToolCardStatus,
    },
    Error(String),
}

#[derive(Debug, Clone)]
pub struct PermissionView {
    pub id: String,
    pub tool: String,
    pub risk: RiskClass,
    pub input: String,
}

/// キー入力の結果、engineアクター/oneshotへ伝えるべきアクション。
#[derive(Debug)]
pub enum Action {
    Submit(String),
    Respond(String, Decision),
    Quit,
}

pub struct AppState {
    pub transcript: Vec<TranscriptItem>,
    pub input: String,
    pub pending_permission: Option<PermissionView>,
    pub provider_label: String,
    pub model: String,
    pub last_usage: Usage,
    pub last_stop_reason: Option<StopReason>,
    /// 直前の`TextDelta`がAssistantテキストの続きかどうか。`TurnStarted`/ツールカード挿入で
    /// リセットし、新しいターンのテキストが別の`Assistant`項目として積まれるようにする。
    turn_open: bool,
    pub should_quit: bool,
}

impl AppState {
    pub fn new(provider_label: String, model: String) -> Self {
        Self {
            transcript: Vec::new(),
            input: String::new(),
            pending_permission: None,
            provider_label,
            model,
            last_usage: Usage::default(),
            last_stop_reason: None,
            turn_open: false,
            should_quit: false,
        }
    }

    pub fn push_user_prompt(&mut self, text: String) {
        self.transcript.push(TranscriptItem::User(text));
        self.turn_open = false;
    }

    pub fn apply(&mut self, ev: AgentEvent) {
        match ev {
            AgentEvent::TurnStarted => {
                self.turn_open = false;
            }
            AgentEvent::TextDelta { text } => {
                if self.turn_open {
                    if let Some(TranscriptItem::Assistant(s)) = self.transcript.last_mut() {
                        s.push_str(&text);
                        return;
                    }
                }
                self.transcript.push(TranscriptItem::Assistant(text));
                self.turn_open = true;
            }
            AgentEvent::ThinkingDelta { text } => {
                if let Some(TranscriptItem::Thinking(s)) = self.transcript.last_mut() {
                    s.push_str(&text);
                } else {
                    self.transcript.push(TranscriptItem::Thinking(text));
                }
            }
            AgentEvent::ToolCallProposed { id, name, input } => {
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
                self.pending_permission = Some(PermissionView {
                    id,
                    tool,
                    risk,
                    input: pretty(&input),
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
                self.turn_open = false;
            }
            AgentEvent::Error { message } => {
                self.transcript.push(TranscriptItem::Error(message));
                self.turn_open = false;
            }
        }
    }

    /// キー入力を処理し、engineアクター/InteractiveGateへ伝えるべきアクションを返す。
    pub fn on_key(&mut self, key: KeyEvent) -> Option<Action> {
        if let Some(pending) = &self.pending_permission {
            let decision = match key.code {
                KeyCode::Char('y') => Some(Decision::Allow),
                KeyCode::Char('a') => Some(Decision::AllowAndRemember),
                KeyCode::Char('n') | KeyCode::Esc => Some(Decision::Deny),
                KeyCode::Char('d') => Some(Decision::DenyAndRemember),
                _ => None,
            };
            if let Some(decision) = decision {
                let id = pending.id.clone();
                self.pending_permission = None;
                return Some(Action::Respond(id, decision));
            }
            return None;
        }

        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
                Some(Action::Quit)
            }
            KeyCode::Enter => {
                if self.input.trim().is_empty() {
                    return None;
                }
                let text = std::mem::take(&mut self.input);
                self.push_user_prompt(text.clone());
                Some(Action::Submit(text))
            }
            KeyCode::Backspace => {
                self.input.pop();
                None
            }
            KeyCode::Char(c) => {
                self.input.push(c);
                None
            }
            _ => None,
        }
    }
}

fn pretty(v: &serde_json::Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

const MAX_OUTPUT_PREVIEW: usize = 400;

fn truncate_output(output: &ToolOutput) -> String {
    if output.content.chars().count() > MAX_OUTPUT_PREVIEW {
        let head: String = output.content.chars().take(MAX_OUTPUT_PREVIEW).collect();
        format!("{head}... (truncated)")
    } else {
        output.content.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    /// 同一ターン内の`TextDelta`は直前の`Assistant`項目へ連結され、`TurnStarted`を挟むと
    /// 新しい項目として積まれる（§リッチTUI「ストリーミング描画」）。
    #[test]
    fn text_deltas_within_a_turn_accumulate_into_one_item() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        app.apply(AgentEvent::TurnStarted);
        app.apply(AgentEvent::TextDelta { text: "hel".into() });
        app.apply(AgentEvent::TextDelta { text: "lo".into() });

        assert_eq!(app.transcript.len(), 1);
        match &app.transcript[0] {
            TranscriptItem::Assistant(s) => assert_eq!(s, "hello"),
            other => panic!("expected Assistant item, got {other:?}"),
        }

        app.apply(AgentEvent::TurnCompleted {
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        });
        app.apply(AgentEvent::TurnStarted);
        app.apply(AgentEvent::TextDelta {
            text: "next turn".into(),
        });
        assert_eq!(app.transcript.len(), 2);
    }

    /// `ToolCallProposed`でカードが積まれ、`ToolFinished`で同じ`id`のカードのstatusが
    /// 更新される（§リッチTUI「ツールカード」）。
    #[test]
    fn tool_card_transitions_from_running_to_done() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        app.apply(AgentEvent::ToolCallProposed {
            id: "call_1".into(),
            name: "read_file".into(),
            input: serde_json::json!({"path": "a.txt"}),
        });
        match &app.transcript[0] {
            TranscriptItem::ToolCard { status, .. } => {
                assert!(matches!(status, ToolCardStatus::Running))
            }
            other => panic!("expected ToolCard, got {other:?}"),
        }

        app.apply(AgentEvent::ToolFinished {
            id: "call_1".into(),
            output: ToolOutput {
                content: "hello".into(),
                is_error: false,
            },
        });
        match &app.transcript[0] {
            TranscriptItem::ToolCard { status, .. } => match status {
                ToolCardStatus::Done { is_error, output } => {
                    assert!(!is_error);
                    assert_eq!(output, "hello");
                }
                ToolCardStatus::Running => panic!("expected Done"),
            },
            other => panic!("expected ToolCard, got {other:?}"),
        }
    }

    /// `PermissionRequired`はモーダル状態を立て、モーダル表示中は`y/n/a/d`のみを消費して
    /// `Action::Respond`を返す（§リッチTUI「承認ダイアログ」の`[y]/[n]/[a]/[d]`）。
    #[test]
    fn permission_modal_consumes_only_decision_keys() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        app.apply(AgentEvent::PermissionRequired {
            id: "perm-0".into(),
            tool: "run_shell".into(),
            risk: RiskClass::Exec,
            input: serde_json::json!({"command": "echo hi"}),
        });
        assert!(app.pending_permission.is_some());

        // モーダル表示中は通常の文字入力ボックスへは書き込まれない。
        assert!(app.on_key(key('x')).is_none());
        assert!(app.input.is_empty());

        let action = app.on_key(key('a')).expect("expected an action");
        match action {
            Action::Respond(id, decision) => {
                assert_eq!(id, "perm-0");
                assert_eq!(decision, Decision::AllowAndRemember);
            }
            _ => panic!("expected Respond action"),
        }
        assert!(app.pending_permission.is_none());
    }

    /// モーダルが無いときのEnterは入力欄の内容を`Action::Submit`として返し、
    /// トランスクリプトへユーザ発言として積む。
    #[test]
    fn enter_submits_input_and_records_user_turn() {
        let mut app = AppState::new("mock".into(), "mock-model".into());
        for c in "hi".chars() {
            assert!(app.on_key(key(c)).is_none());
        }
        let action = app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        match action {
            Some(Action::Submit(text)) => assert_eq!(text, "hi"),
            other => panic!("expected Submit action, got {other:?}"),
        }
        assert!(app.input.is_empty());
        assert!(matches!(&app.transcript[0], TranscriptItem::User(s) if s == "hi"));
    }
}
