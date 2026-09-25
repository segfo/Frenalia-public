//! 対話用`PermissionGate`実装。`plans/DESIGN.md` §リッチTUI「承認ダイアログ」参照。
//!
//! `PermissionArbiter::classify`が`Classification::Prompt`を返すケース（モード+allowlistでは
//! 自動判定できない）でのみ`AgentEvent::PermissionRequired`を発行し、ユーザがキー入力で
//! 応答するまで`decide`の戻り値をoneshotチャネルで待つ。`Allow`/`Deny`は即座にヘッドレスと
//! 同じ規則で決定されるため、モーダルは実際にプロンプトが要るケースにのみ出る。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use tokio::sync::oneshot;

use harness_core::{AgentEvent, PermissionSubject, RiskClass};
use harness_engine::{
    AllowRule, Classification, Decision, PermissionArbiter, PermissionGate, PermissionMode,
};

pub struct InteractiveGate {
    arbiter: Mutex<PermissionArbiter>,
    events: harness_engine::EventSink,
    pending: Mutex<HashMap<String, oneshot::Sender<Decision>>>,
    next_id: AtomicU64,
}

impl InteractiveGate {
    pub fn new(arbiter: PermissionArbiter, events: harness_engine::EventSink) -> Self {
        Self {
            arbiter: Mutex::new(arbiter),
            events,
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
        }
    }

    /// 承認モーダルでのキー入力（`[y]/[n]/[a]/[d]`）を、待機中のoneshotへ届ける。
    /// 対応するリクエストが既に無ければ（二重応答等）何もしない。
    pub fn respond(&self, id: &str, decision: Decision) {
        if let Some(tx) = self.pending.lock().unwrap().remove(id) {
            let _ = tx.send(decision);
        }
    }

    /// `/mode`スラッシュコマンド（M9）。engineタスクを介さず直接`arbiter`を書き換える
    /// （`arbiter`は`Mutex`越しに参照されるだけなので、進行中のツール判定と競合しない）。
    /// `accept-all`は起動時に許された場合だけ（`Err`は画面へ出す理由）。
    pub fn set_mode(&self, mode: PermissionMode) -> Result<(), String> {
        self.arbiter.lock().unwrap().set_mode(mode)
    }

    pub fn mode(&self) -> PermissionMode {
        self.arbiter.lock().unwrap().mode()
    }

    /// `/allow`スラッシュコマンド（M9）。
    pub fn add_allow(&self, rule: AllowRule) {
        self.arbiter.lock().unwrap().add_rule(rule);
    }
}

#[async_trait]
impl PermissionGate for InteractiveGate {
    async fn resolve(
        &self,
        tool: &str,
        risk: RiskClass,
        subject: &PermissionSubject,
        input: &serde_json::Value,
    ) -> Decision {
        let classification = self.arbiter.lock().unwrap().classify(tool, risk, subject);
        match classification {
            Classification::Allow => Decision::Allow,
            Classification::Deny => Decision::Deny,
            Classification::Prompt => {
                let id = format!("perm-{}", self.next_id.fetch_add(1, Ordering::Relaxed));
                let (tx, rx) = oneshot::channel();
                self.pending.lock().unwrap().insert(id.clone(), tx);
                let _ = self.events.send(AgentEvent::PermissionRequired {
                    id,
                    tool: tool.to_string(),
                    risk,
                    input: input.clone(),
                });
                let decision = rx.await.unwrap_or(Decision::Deny);
                if matches!(decision, Decision::AllowAndRemember) {
                    self.arbiter.lock().unwrap().remember_allow(tool, subject);
                }
                decision
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use harness_core::CommandSubject;
    use harness_engine::PermissionMode;

    fn command(line: &str) -> PermissionSubject {
        PermissionSubject::Command(CommandSubject {
            line: line.to_string(),
        })
    }

    /// `/mode accept-all`は、起動時に許された場合だけ効く（S1-8）。許されていなければモードは変わらない。
    #[test]
    fn slash_mode_accept_all_is_refused_unless_permitted_at_startup() {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let gate = InteractiveGate::new(
            PermissionArbiter::new(PermissionMode::Default, vec![], "/workspace"),
            tx,
        );
        assert!(gate.set_mode(PermissionMode::AcceptAll).is_err());
        assert_eq!(gate.mode(), PermissionMode::Default);

        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let gate = InteractiveGate::new(
            PermissionArbiter::new(PermissionMode::Default, vec![], "/workspace")
                .with_accept_all_permitted(true),
            tx,
        );
        assert!(gate.set_mode(PermissionMode::AcceptAll).is_ok());
        assert_eq!(gate.mode(), PermissionMode::AcceptAll);
    }

    /// read_onlyはallowlist/モードだけで判定できるため、モーダル（`PermissionRequired`）を
    /// 出さずに即座に`Allow`を返す（§パーミッション「ヘッドレス既定」と同じ自動判定経路）。
    #[tokio::test]
    async fn allows_read_only_without_prompting() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let gate = InteractiveGate::new(
            PermissionArbiter::new(PermissionMode::Default, vec![], "/workspace"),
            tx,
        );

        let decision = gate
            .resolve(
                "read_file",
                RiskClass::ReadOnly,
                &PermissionSubject::Text("a.txt".to_string()),
                &serde_json::json!({}),
            )
            .await;

        assert_eq!(decision, Decision::Allow);
        assert!(
            rx.try_recv().is_err(),
            "no event should be emitted for auto-allow"
        );
    }

    /// allowlist未登録のExecは`Classification::Prompt`となり、`PermissionRequired`を発行して
    /// oneshot応答を待つ。`AllowAndRemember`で応答すると以降の同じ判定の材料はallowlist経由で
    /// 自動許可される（§パーミッション「allowlistへの追記」、§リッチTUI「承認ダイアログ」）。
    #[tokio::test]
    async fn prompts_then_remembers_allow() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let gate = Arc::new(InteractiveGate::new(
            PermissionArbiter::new(PermissionMode::Default, vec![], "/workspace"),
            tx,
        ));

        let gate_task = gate.clone();
        let handle = tokio::spawn(async move {
            gate_task
                .resolve(
                    "run_shell",
                    RiskClass::Exec,
                    &command("echo hi"),
                    &serde_json::json!({"command": "echo hi"}),
                )
                .await
        });

        let ev = rx
            .recv()
            .await
            .expect("PermissionRequired should be emitted");
        let id = match ev {
            AgentEvent::PermissionRequired { id, tool, .. } => {
                assert_eq!(tool, "run_shell");
                id
            }
            other => panic!("expected PermissionRequired, got {other:?}"),
        };

        gate.respond(&id, Decision::AllowAndRemember);
        let decision = handle.await.unwrap();
        assert_eq!(decision, Decision::AllowAndRemember);

        // 同じ材料の再呼び出しはallowlist経由で自動許可され、二度目のプロンプトは出ない。
        let decision2 = gate
            .resolve(
                "run_shell",
                RiskClass::Exec,
                &command("echo hi"),
                &serde_json::json!({"command": "echo hi"}),
            )
            .await;
        assert_eq!(decision2, Decision::Allow);
        assert!(rx.try_recv().is_err());
    }
}
