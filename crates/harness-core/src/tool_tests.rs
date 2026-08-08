//! `WaitReason`／`WaitReasons`（[BUG-082]フォローアップの待機理由機構）の単体テスト。
//!
//! **この領域には2026-08-08まで自動テストが1件も無かった。** `refactor-perspectives` R-01
//! （TUIステータスバーが`grant_job::progress()`を直接読み、finished判定が2箇所にあった）を
//! 直すにあたり、`safe-refactoring`段階0の「網に歯があるか」を確かめようとして0件だと判明し、
//! 直す前にここへ網を張った（規則6: 統合の前にcharacterization testを書く）。
//!
//! 実機の`WorkspaceAclWaitReason`（Windows専用・背景ジョブの実状態を読む）はここでは使えない
//! ので、trait の契約だけを固定する。**固定するのは「どの源が勝つか」と「説明と進捗が同じ源から
//! 来ること」**——この2つが崩れると、ツールカードとステータスバーが別の事実を表示する。

use super::tool::{WaitReason, WaitReasons, WaitState};
use std::sync::Arc;

/// 常に同じ`WaitState`を返すテスト用の源。
struct Fixed(Option<WaitState>);

impl WaitReason for Fixed {
    fn active(&self) -> Option<WaitState> {
        self.0.clone()
    }
}

fn state(description: &str, label: &str) -> WaitState {
    WaitState {
        description: description.to_string(),
        label: label.to_string(),
    }
}

fn reasons(states: Vec<Option<WaitState>>) -> WaitReasons {
    WaitReasons::new(
        states
            .into_iter()
            .map(|s| Arc::new(Fixed(s)) as Arc<dyn WaitReason>)
            .collect(),
    )
}

#[test]
fn no_registered_source_means_nothing_is_waiting() {
    assert_eq!(WaitReasons::default().active_state(), None);
    assert_eq!(WaitReasons::default().describe_active(), None);
}

#[test]
fn a_source_that_is_not_waiting_is_skipped() {
    let r = reasons(vec![None]);
    assert_eq!(r.active_state(), None);
    assert_eq!(r.describe_active(), None);
}

#[test]
fn the_first_source_that_answers_wins() {
    let r = reasons(vec![
        None,
        Some(state("二番目の説明", "二番目")),
        Some(state("三番目の説明", "三番目")),
    ]);
    assert_eq!(r.active_state().unwrap().label, "二番目");
    assert_eq!(r.describe_active().as_deref(), Some("二番目の説明"));
}

/// R-01の核心。`describe_active`と`active_state`が**別々に源を選ばない**こと。
/// 別々に選ぶ実装だと、説明文はA・進捗はBという食い違った表示が起き得る。
#[test]
fn the_description_always_comes_from_the_same_source_as_the_progress() {
    let r = reasons(vec![
        Some(state("Aの説明", "Aの短縮表示")),
        Some(state("Bの説明", "Bの短縮表示")),
    ]);
    let picked = r.active_state().unwrap();
    assert_eq!(
        r.describe_active().as_deref(),
        Some(picked.description.as_str())
    );
    assert_eq!(picked.label, "Aの短縮表示");
}

/// ツールカード用の一文とステータスバー用の一行は**別々の文字列として運ぶ**。
/// 片方をもう片方から機械的に導けると考えて省略すると、狭い場所に長文が出るか、
/// ツールカードに文脈の無い断片が出るかのどちらかになる。
#[test]
fn the_two_surfaces_carry_their_own_wording() {
    let r = reasons(vec![Some(state(
        "実行ブロック中: 保護されたノードを検証中 75% (3/4)",
        "workspace ACL 75% (保護ノード検証 3/4)",
    ))]);
    let picked = r.active_state().unwrap();
    assert_eq!(
        picked.description,
        "実行ブロック中: 保護されたノードを検証中 75% (3/4)"
    );
    assert_eq!(picked.label, "workspace ACL 75% (保護ノード検証 3/4)");
}
