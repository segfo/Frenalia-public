use super::*;
use crate::{CommandSubject, ProgramSubject};

fn shell(line: &str) -> PermissionSubject {
    PermissionSubject::Command(CommandSubject::line_only(line))
}

/// 走ったコマンドと書いた先を古い順に覚える。読むだけのツールは覚えない。書いた中身は入れない。
#[test]
fn commands_and_write_targets_are_kept_in_order_but_reads_are_not() {
    let mut history = CommandHistory::default();
    history.record("run_shell", &shell("curl http://x/a.ps1 -o a.ps1"));
    history.record("read_file", &PermissionSubject::Text("notes.txt".into()));
    history.record(
        "write_file",
        &PermissionSubject::WritePath("setup.ps1".into()),
    );
    history.record(
        "run_program",
        &PermissionSubject::Program(ProgramSubject::plain(
            "pwsh",
            vec!["-File".into(), "a b.ps1".into()],
        )),
    );
    assert_eq!(
        history.entries(),
        [
            "curl http://x/a.ps1 -o a.ps1",
            "write_file setup.ps1",
            "pwsh -File \"a b.ps1\"",
        ]
    );
}

/// 件数と文字数の上限を越えたら、古いものから落とす。長い1件は切る。
#[test]
fn the_oldest_entries_are_dropped_past_the_limits() {
    let mut history = CommandHistory::default();
    for i in 0..(MAX_HISTORY_ENTRIES + 5) {
        history.record("run_shell", &shell(&format!("echo {i}")));
    }
    let entries = history.entries();
    assert_eq!(entries.len(), MAX_HISTORY_ENTRIES);
    assert_eq!(entries[0], "echo 5");
    assert_eq!(
        entries.last().unwrap(),
        &format!("echo {}", MAX_HISTORY_ENTRIES + 4)
    );

    let mut long = CommandHistory::default();
    for _ in 0..20 {
        long.record("run_shell", &shell(&"x".repeat(MAX_ENTRY_CHARS * 2)));
    }
    let entries = long.entries();
    assert!(entries.iter().all(|e| e.chars().count() == MAX_ENTRY_CHARS));
    assert!(entries.iter().map(|e| e.chars().count()).sum::<usize>() <= MAX_HISTORY_CHARS);
    assert_eq!(entries.len(), MAX_HISTORY_CHARS / MAX_ENTRY_CHARS);
}

/// **標準出力の契約（`--output-format jsonl`）に材料を載せない**——`ToolStarted`を JSON にしても、材料（縛ったファイルの
/// 中身を含む）は出ない。ここが赤くなったら、`AgentEvent::ToolStarted.subject`から`serde(skip)`が外れた。
#[test]
fn the_subject_on_tool_started_is_not_written_to_the_jsonl_output() {
    let mut subject = CommandSubject::line_only("pwsh ./setup.ps1");
    subject.previews.push(crate::FilePreview {
        rel_path: "setup.ps1".into(),
        text: "SECRET-CONTENT".into(),
        truncated: false,
    });
    let event = crate::AgentEvent::ToolStarted {
        id: "call_1".into(),
        name: "run_shell".into(),
        subject: Some(PermissionSubject::Command(subject)),
    };
    let json = serde_json::to_string(&event).unwrap();
    assert_eq!(
        json,
        r#"{"ToolStarted":{"id":"call_1","name":"run_shell"}}"#
    );
}
