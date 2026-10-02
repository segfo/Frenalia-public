//! 承認モーダルの回帰テスト（D-106・D-107）。内部の状態（段・穴・カーソル）へ触れるため
//! `#[cfg(test)]`のまま別ファイルへ分けている（`docs/CODE-STRUCTURE-RULES.md`規則2）。

use super::SummaryState;
use super::*;
use harness_core::{CommandSubject, ProgramSubject};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, crossterm::event::KeyModifiers::NONE)
}

fn view(subject: PermissionSubject) -> PermissionView {
    let mut v = PermissionView::new(
        "perm-0".to_string(),
        "run_program".to_string(),
        RiskClass::Exec,
        subject,
        "{}".to_string(),
        None,
        "C:/ws".to_string(),
    );
    // 入力を捨てる窓を過ぎた状態にする（時間に依存しないテストにするため）。
    v.opened_at = Instant::now() - MODAL_INPUT_GRACE - Duration::from_millis(1);
    v
}

fn program(program: &str, args: &[&str]) -> PermissionSubject {
    PermissionSubject::Program(ProgramSubject::plain(
        program,
        args.iter().map(|a| a.to_string()).collect(),
    ))
}

/// キー案内の文言を全部つないだもの（どの項目が出ているかを見る）。
fn hint_labels(v: &PermissionView) -> String {
    v.key_hints()
        .concat()
        .into_iter()
        .map(|hint| hint.label)
        .collect::<Vec<_>>()
        .join("   ")
}

fn body_text(v: &PermissionView) -> String {
    v.body()
        .into_iter()
        .map(|l| l.text)
        .collect::<Vec<_>>()
        .join("\n")
}

/// モーダルを出した直後の打鍵は捨てる（D-106）。捨てないと、次の依頼を打っていた手が
/// そのまま承認になる。窓を過ぎれば同じキーが効く（**禁止と許可の対**）。
#[test]
fn keys_within_the_grace_window_are_discarded() {
    let mut v = view(program("git", &["status"]));
    v.opened_at = Instant::now();
    assert_eq!(v.on_key(key(KeyCode::Char('y'))), None);
    assert_eq!(v.on_key(key(KeyCode::Char('a'))), None);
    assert_eq!(v.stage, ApprovalStage::Choose, "確認の一段へも進まない");

    v.opened_at = Instant::now() - MODAL_INPUT_GRACE - Duration::from_millis(1);
    assert_eq!(
        v.on_key(key(KeyCode::Char('y'))),
        Some(ApprovalCommand::Once)
    );
}

/// `[a]`だけでは記録しない——確認の一段を通って Enter を押したときだけ応答になる（D-106）。
/// Esc で選ぶ段へ戻れる。
#[test]
fn permanent_approval_needs_the_confirmation_step() {
    let mut v = view(program("git", &["status"]));
    assert_eq!(v.on_key(key(KeyCode::Char('a'))), None);
    assert_eq!(v.stage, ApprovalStage::Confirm);

    assert_eq!(v.on_key(key(KeyCode::Esc)), None);
    assert_eq!(v.stage, ApprovalStage::Choose);

    v.on_key(key(KeyCode::Char('a')));
    assert_eq!(
        v.on_key(key(KeyCode::Enter)),
        Some(ApprovalCommand::Remember(Vec::new()))
    );
}

/// 穴は確認の一段で選ぶ。候補は**今の値が穴に当たる引数だけ**——`-n`のようなオプションに
/// 開けても二度と当たらないので、選ばせない（D-105）。
#[test]
fn holes_are_chosen_in_the_confirmation_step_and_only_where_they_can_match() {
    let mut v = view(program("git", &["log", "-n", "5"]));
    assert_eq!(v.hole_candidates(), vec![0, 2], "`-n`は候補にしない");

    v.on_key(key(KeyCode::Char('a')));
    // カーソルは候補の並びを動く（引数の添字ではない）。
    v.on_key(key(KeyCode::Down));
    v.on_key(key(KeyCode::Char(' ')));
    assert_eq!(v.selected_holes(), vec![2]);
    // もう一度押すと外れる。
    v.on_key(key(KeyCode::Char(' ')));
    assert_eq!(v.selected_holes(), Vec::<usize>::new());

    v.on_key(key(KeyCode::Char(' ')));
    assert_eq!(
        v.on_key(key(KeyCode::Enter)),
        Some(ApprovalCommand::Remember(vec![2]))
    );
}

/// コードを走らせる呼び出しには穴を開けられない（引数がコードそのものだから）。
#[test]
fn an_interpreter_offers_no_holes() {
    let v = view(program("python", &["build.py"]));
    assert!(v.hole_candidates().is_empty());
}

/// 恒久的に承認できない呼び出しでは`[a]`を出さないし、押しても何も起きない
/// （押せるのに何も起きない、を作らない）。
#[test]
fn a_call_that_cannot_be_remembered_does_not_offer_permanent_approval() {
    let mut unverifiable = CommandSubject::line_only("cat secret.bin");
    unverifiable.unverifiable = true;
    let mut v = view(PermissionSubject::Command(unverifiable));
    assert!(!v.can_remember());
    assert!(!hint_labels(&v).contains("[a]"));
    assert_eq!(v.on_key(key(KeyCode::Char('a'))), None);
    assert_eq!(v.stage, ApprovalStage::Choose);
    assert!(body_text(&v).contains("恒久的には承認できない"));
}

/// 見えない文字は綴りで描く（D-106）。端末は双方向制御をそのまま解釈するので、
/// 人が見た並びと実際に渡る並びが違うものを承認させられる。
#[test]
fn invisible_characters_are_visible_in_the_modal() {
    let v = view(program("pwsh", &["gp\u{202E}yp.exe", "a\u{200B}b"]));
    let text = body_text(&v);
    assert!(text.contains(r"gp\u{202E}yp.exe"), "{text}");
    assert!(text.contains(r"a\u{200B}b"), "{text}");
    assert!(!text.contains('\u{202E}'), "生の双方向制御が残っている");
}

/// 引数は1行1要素で、番号を付けて出す（D-106）。1行に並べると、どこまでが1つの引数か分からない。
#[test]
fn arguments_are_one_per_line_with_their_position() {
    let v = view(program("git", &["commit", "-m", "a b c"]));
    let lines: Vec<String> = v.body().into_iter().map(|l| l.text).collect();
    assert!(lines.iter().any(|l| l == "  [0] commit"), "{lines:?}");
    assert!(lines.iter().any(|l| l == "  [1] -m"), "{lines:?}");
    assert!(lines.iter().any(|l| l == "  [2] a b c"), "{lines:?}");
}

/// 枠を開いているときの`Esc`は枠を閉じるだけ——**拒否にしない**。
/// 開いていなければ拒否になる（対）。
#[test]
fn escape_closes_an_open_pane_before_it_denies() {
    let mut v = view(program("git", &["status"]));
    v.on_key(key(KeyCode::Char('v')));
    assert_eq!(v.pane, ApprovalPane::Content);
    assert_eq!(v.on_key(key(KeyCode::Esc)), None);
    assert_eq!(v.pane, ApprovalPane::None);
    assert_eq!(v.on_key(key(KeyCode::Esc)), Some(ApprovalCommand::Deny));
}

/// 写しが無ければ差分は出せないので、`[f]`は何もしない（案内にも出さない）。
#[test]
fn the_diff_pane_needs_a_saved_copy_from_the_previous_approval() {
    let mut v = view(program("python", &["build.py"]));
    assert!(!v.has_diff());
    assert!(!hint_labels(&v).contains("[f]"));
    assert_eq!(v.on_key(key(KeyCode::Char('f'))), None);
    assert_eq!(v.pane, ApprovalPane::None);

    v.previous = Some(vec![PreviousCopy {
        rel_path: "build.py".to_string(),
        text: Ok("print('v1')".to_string()),
    }]);
    assert!(v.has_diff());
    assert!(hint_labels(&v).contains("[f]"));
    v.on_key(key(KeyCode::Char('f')));
    assert_eq!(v.pane, ApprovalPane::Diff);
}

/// 台帳に残らないツールでは「恒久的に承認」と書かない（消えるものを恒久と呼ばない）。
#[test]
fn a_tool_without_a_ledger_entry_says_the_approval_is_session_scoped() {
    let mut v = view(PermissionSubject::Text("https://example.com".to_string()));
    v.tool = "web_fetch".to_string();
    assert!(v.can_remember());
    assert!(!v.remember_is_recorded());
    assert!(hint_labels(&v).contains("このセッション中は許可"));
    v.on_key(key(KeyCode::Char('a')));
    assert!(body_text(&v).contains("このセッション中だけ許可する"));
}

/// 要約には**出どころ**を添える（D-100）。中身がどこへ出たのかを後から見て分かるようにする。
/// 要約は「補助。中身と差分を必ず確認」と一緒にしか出さない。
#[test]
fn the_summary_says_where_it_came_from_and_that_it_is_only_an_aid() {
    let mut v = view(program("python", &["build.py"]));
    v.summary_source = Some("lmstudio / qwen3-8b".to_string());
    v.summary = SummaryState::Running;
    assert!(
        body_text(&v).contains("要約を作成中…（lmstudio / qwen3-8b へ中身を送っている）")
            || body_text(&v).contains("lmstudio / qwen3-8b")
    );

    v.summary = SummaryState::Done("ネットワークへ出る。".to_string());
    let text = body_text(&v);
    assert!(
        text.contains("補助。中身と差分を必ず確認すること"),
        "{text}"
    );
    assert!(text.contains("lmstudio / qwen3-8b"), "{text}");
    assert!(text.contains("ネットワークへ出る。"), "{text}");

    v.summary = SummaryState::Failed("接続できない".to_string());
    assert!(body_text(&v).contains("要約を作れなかった: 接続できない"));
}
