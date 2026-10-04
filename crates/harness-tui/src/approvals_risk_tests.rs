//! 承認画面の危険度判定（外の判定モデル）の配線の回帰テスト（D-100の追記）。
//!
//! 守りたいことは2つある。**判定が間に合ったときだけ、色・見出し・1行・要約の一言が足される**ことと、
//! **判定が無い・低い・落ちている・遅いときの画面と要約は、判定を使わない構成と同じ**であること。
//! 後者は「足さない」だけでなく「待たせない・止めない」まで含む。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use harness_core::{
    assess_command_risk, Answers, CommandSubject, DecisionModel, PermissionSubject, ProgramSubject,
    Question, ReadScopeConfig, RiskCheckError, RiskLevel, RiskVerdict,
};
use tokio_util::sync::CancellationToken;

use super::approvals_tests::{app_with, apply_until_ready, open_scope, Capturing};
use super::*;
use crate::app::{TranscriptItem, WaitClock};

const DANGEROUS_LINE: &str = "rm C:\\Windows\\System32\\calc.exe";

/// 決まった危険度を返す判定モデル。`delay`の間は返さない。呼ばれた行（`state.command`）と回数を控える。
struct FakeRisk {
    reply: Result<f32, String>,
    delay: Duration,
    calls: AtomicUsize,
    lines: Mutex<Vec<String>>,
}

impl FakeRisk {
    fn scoring(score: f32) -> Arc<Self> {
        Self::new(Ok(score), Duration::ZERO)
    }

    fn new(reply: Result<f32, String>, delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            reply,
            delay,
            calls: AtomicUsize::new(0),
            lines: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl DecisionModel for FakeRisk {
    async fn decide(
        &self,
        state: &serde_json::Value,
        _questions: &[Question],
    ) -> Result<Answers, RiskCheckError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let line = state["command"].as_str().unwrap_or_default().to_string();
        self.lines.lock().unwrap().push(line);
        tokio::time::sleep(self.delay).await;
        match &self.reply {
            Ok(score) => Ok(Answers::new(
                serde_json::json!({ "risk": { "score": score } }),
                false,
            )),
            Err(reason) => Err(RiskCheckError(reason.clone())),
        }
    }
}

fn risk_of(fake: &Arc<FakeRisk>) -> ApprovalRisk {
    ApprovalRisk {
        check: fake.clone(),
        label: "ollaya / test".into(),
    }
}

fn summary_with(provider: &Arc<Capturing>) -> ApprovalSummary {
    ApprovalSummary {
        provider: provider.clone(),
        model: "m".into(),
        label: "mock / ".into(),
    }
}

fn shell_app(line: &str) -> AppState {
    app_with(PermissionSubject::Command(CommandSubject::line_only(line)))
}

fn clock() -> WaitClock {
    WaitClock {
        spinner_frame: 0,
        now: Instant::now(),
    }
}

/// 製品の入口（判定を起こす→要約を起こす）で、要約が届くまで画面へ反映する。送った要約の要求を返す。
/// `risk`が`None`なら判定を使わない構成（今までと同じ）。
async fn run_dialog(
    app: &mut AppState,
    risk: Option<&ApprovalRisk>,
    cache: &mut SummaryCache,
) -> harness_core::CompletionRequest {
    let provider = Arc::new(Capturing::default());
    let summary = summary_with(&provider);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let scope = open_scope(ReadScopeConfig::default());
    let cancel = CancellationToken::new();
    let gate = risk.and_then(|r| start_risk(r, &tx, app, &cancel));
    assert!(
        start_summary(&summary, &tx, app, cache, &scope, false, None, gate).is_some(),
        "要約が起きなかった"
    );
    apply_until_ready(&mut rx, app, cache).await;
    // 判定の結果（`RiskReady`）が要約より後ろに並んだ場合に備えて、残りも反映する。
    while let Ok(event) = rx.try_recv() {
        on_background(event, app, cache, Instant::now());
    }
    let seen = provider.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    seen[0].clone()
}

fn view(app: &AppState) -> &crate::app::PermissionView {
    app.pending_permission.as_ref().unwrap()
}

/// **危険と判定されたら、画面（見出し・1行）にも要約への一言にも届く。** 画面の見出しは赤の段階で、
/// 要約へ足すのは固定の英文1行（判定モデルの返した文字列は載らない）。
#[tokio::test]
async fn a_dangerous_verdict_reaches_the_title_the_line_and_the_summary() {
    let fake = FakeRisk::scoring(1.73);
    let mut app = shell_app(DANGEROUS_LINE);
    let mut cache = SummaryCache::new();
    let req = run_dialog(&mut app, Some(&risk_of(&fake)), &mut cache).await;

    assert_eq!(view(&app).verdict.map(|v| v.level), Some(RiskLevel::Danger));
    assert_eq!(view(&app).title().1, Some(RiskLevel::Danger));
    assert!(view(&app).title().0.contains("危険なコマンド"));
    let body = view(&app).body(clock());
    let line = body
        .iter()
        .find(|l| l.style == crate::app::LineStyle::Danger)
        .expect("危険の行が出ていない");
    assert!(line.text.contains("1.73 / 2"), "{}", line.text);
    assert!(
        line.text.contains("ollaya / test"),
        "出どころが無い: {}",
        line.text
    );
    assert!(line.text.contains("安全の保証ではない"), "{}", line.text);

    let system = &req.system[0].text;
    assert!(
        system.contains("DANGEROUS"),
        "要約へ危険度が渡っていない: {system}"
    );
    // 要約の呼び出しへ渡るのは固定の綴りだけ——コマンドの文字列が system へ混ざっていない。
    assert!(!system.contains("System32"), "{system}");
    // 画面に出ている出どころ。
    assert_eq!(fake.lines.lock().unwrap().as_slice(), [DANGEROUS_LINE]);
}

/// **危険の線（1.5）に届かない数値は、何も足さない。** 測った範囲では、危険な行にも届かないもの
/// （`rm C:	est.txt` 0.80〜0.93）があるが、同じ範囲に無害な行（`cargo build` 1.26 など）も居る。
/// 黄色の帯を引くと無害なコマンドが黄色になるので、線に届かなければ判定を使わない構成と同じにする。
#[tokio::test]
async fn a_score_below_the_danger_line_adds_nothing_even_when_it_is_not_tiny() {
    let fake = FakeRisk::scoring(1.26);
    let mut with_check = shell_app("cargo build");
    let mut plain = shell_app("cargo build");
    let mut cache = SummaryCache::new();
    let checked = run_dialog(&mut with_check, Some(&risk_of(&fake)), &mut cache).await;
    let mut cache = SummaryCache::new();
    let unchecked = run_dialog(&mut plain, None, &mut cache).await;

    assert_eq!(fake.calls(), 1, "対照: 判定は呼ばれている");
    assert_eq!(view(&with_check).title(), view(&plain).title());
    assert_eq!(checked.system[0].text, unchecked.system[0].text);
    assert!(!view(&with_check)
        .body(clock())
        .iter()
        .any(|l| l.style == crate::app::LineStyle::Danger));
}

/// **低いと判定されても、何も足さない。** 低いは安全の保証ではないので、見出しも1行も要約への一言も
/// 判定を使わない構成と同じである（安心させる向きに曲げさせない）。
#[tokio::test]
async fn a_low_verdict_adds_nothing_so_it_cannot_read_as_a_guarantee() {
    let fake = FakeRisk::scoring(0.13);
    let mut with_check = shell_app("systeminfo");
    let mut plain = shell_app("systeminfo");
    let mut cache = SummaryCache::new();
    let checked = run_dialog(&mut with_check, Some(&risk_of(&fake)), &mut cache).await;
    let mut cache = SummaryCache::new();
    let unchecked = run_dialog(&mut plain, None, &mut cache).await;

    assert_eq!(fake.calls(), 1, "対照: 判定は呼ばれている");
    assert_eq!(
        view(&with_check).verdict.map(|v| v.level),
        Some(RiskLevel::Low)
    );
    assert_eq!(view(&with_check).title(), view(&plain).title());
    assert_eq!(view(&with_check).title().0, "承認が必要です");
    let styles = |app: &AppState| {
        view(app)
            .body(clock())
            .iter()
            .map(|l| l.style)
            .collect::<Vec<_>>()
    };
    assert_eq!(styles(&with_check), styles(&plain), "行の並びが変わった");
    assert_eq!(
        checked.system[0].text, unchecked.system[0].text,
        "低いのに要約への要求が変わった"
    );
}

/// **判定が落ちていても、画面も要約も判定を使わない構成と同じ。** 画面へは出さず、会話の記録へ
/// セッションにつき1回だけ書く（毎回の承認で繰り返さない）。
#[tokio::test]
async fn a_failed_check_leaves_the_dialog_as_it_was_and_says_so_once() {
    let fake = FakeRisk::new(Err("接続を拒まれた".into()), Duration::ZERO);
    let mut with_check = shell_app(DANGEROUS_LINE);
    let mut plain = shell_app(DANGEROUS_LINE);
    let mut cache = SummaryCache::new();
    let checked = run_dialog(&mut with_check, Some(&risk_of(&fake)), &mut cache).await;
    let mut cache = SummaryCache::new();
    let unchecked = run_dialog(&mut plain, None, &mut cache).await;

    assert_eq!(fake.calls(), 1);
    assert_eq!(view(&with_check).verdict, None);
    assert_eq!(view(&with_check).title(), view(&plain).title());
    assert_eq!(checked.system[0].text, unchecked.system[0].text);
    assert!(
        !view(&with_check)
            .body(clock())
            .iter()
            .any(|l| l.text.contains("危険度")),
        "失敗が画面に出ている"
    );
    let notes = |app: &AppState| {
        app.transcript
            .iter()
            .filter(
                |i| matches!(i, TranscriptItem::Info(t) if t.contains("危険度判定を使えなかった")),
            )
            .count()
    };
    assert_eq!(notes(&with_check), 1, "失敗が記録に出ていない");
    assert_eq!(notes(&plain), 0, "対照: 判定を使わない構成は何も書かない");

    // 2回目の失敗は書かない。
    on_background(
        BackgroundEvent::RiskUnavailable {
            reason: "また失敗".into(),
        },
        &mut with_check,
        &mut SummaryCache::new(),
        Instant::now(),
    );
    assert_eq!(notes(&with_check), 1, "毎回の承認で繰り返している");
}

/// **遅い判定は、要約を待たせ続けない。** 上限を超えたら「間に合わなかった」で、失敗ではない。
/// 間に合えば受け取る（対照）。
#[tokio::test]
async fn a_slow_check_does_not_hold_the_summary_past_the_wait() {
    let slow = FakeRisk::new(Ok(1.9), Duration::from_millis(600));
    let (tx, rx) = oneshot::channel();
    let started = Instant::now();
    let check = slow.clone();
    tokio::spawn(async move {
        if let Ok(v) = assess_command_risk(&*check, "x").await {
            let _ = tx.send(v);
        }
    });
    let outcome = wait_for_verdict(
        RiskGate::Pending(rx),
        Duration::from_millis(50),
        &CancellationToken::new(),
    )
    .await;
    assert!(matches!(outcome, GateOutcome::Missing));
    assert!(
        started.elapsed() < Duration::from_millis(400),
        "上限を超えて待った: {:?}",
        started.elapsed()
    );

    // 対照: 上限の内に届けば受け取る。
    let quick = FakeRisk::scoring(1.9);
    let (tx, rx) = oneshot::channel();
    let check = quick.clone();
    tokio::spawn(async move {
        let _ = tx.send(assess_command_risk(&*check, "x").await.unwrap());
    });
    let outcome = wait_for_verdict(
        RiskGate::Pending(rx),
        Duration::from_secs(5),
        &CancellationToken::new(),
    )
    .await;
    assert!(matches!(outcome, GateOutcome::Verdict(v) if v.level == RiskLevel::Danger));
}

/// **承認要求が移ったら、判定を待っている要約は降りる**（前の中身の判定を待ち続けない）。
#[tokio::test]
async fn moving_on_cancels_the_wait_for_the_verdict() {
    let (_tx, rx) = oneshot::channel::<RiskVerdict>();
    let cancel = CancellationToken::new();
    cancel.cancel();
    let outcome = wait_for_verdict(RiskGate::Pending(rx), Duration::from_secs(60), &cancel).await;
    assert!(matches!(outcome, GateOutcome::Cancelled));
}

/// **同じ行は2回判定しない。** 1回目が届いた後、同じ行の承認は聞き直さずに画面へ出す。
#[tokio::test]
async fn the_same_line_is_not_asked_twice() {
    let fake = FakeRisk::scoring(1.73);
    let risk = risk_of(&fake);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let cancel = CancellationToken::new();
    let mut app = shell_app(DANGEROUS_LINE);
    assert!(matches!(
        start_risk(&risk, &tx, &mut app, &cancel),
        Some(RiskGate::Pending(_))
    ));
    let event = rx.recv().await.expect("判定が届かない");
    on_background(event, &mut app, &mut SummaryCache::new(), Instant::now());
    assert_eq!(fake.calls(), 1);

    // 同じ行の次の承認。
    let mut again = shell_app(DANGEROUS_LINE);
    again.risk_seen = app.risk_seen.clone();
    let gate = start_risk(&risk, &tx, &mut again, &cancel);
    assert!(matches!(gate, Some(RiskGate::Ready(v)) if v.level == RiskLevel::Danger));
    assert_eq!(fake.calls(), 1, "同じ行を聞き直した");
    assert_eq!(
        view(&again).verdict.map(|v| v.level),
        Some(RiskLevel::Danger)
    );
}

/// 判定が届いたとき、**別の承認要求へ移っていたらその画面へは出さない**（前のコマンドの判定を、
/// いま聞かれているコマンドの危険度として出さない）。判定そのものは覚えておく。
#[test]
fn a_verdict_for_an_earlier_request_does_not_color_a_later_one() {
    let mut app = shell_app("ls");
    let verdict = RiskVerdict::from_score(1.9).unwrap();
    on_background(
        BackgroundEvent::RiskReady {
            request: "perm-OTHER".into(),
            line: DANGEROUS_LINE.into(),
            verdict,
        },
        &mut app,
        &mut SummaryCache::new(),
        Instant::now(),
    );
    assert_eq!(view(&app).verdict, None, "前の要求の判定が出ている");
    assert_eq!(app.risk_seen.get(DANGEROUS_LINE), Some(&verdict));
}

/// **判定するのは`run_shell`のコマンド行だけ。** ほかの材料（プログラムの起動・書込先）は判定へ出さない。
#[tokio::test]
async fn only_shell_command_lines_are_sent_to_the_check() {
    let fake = FakeRisk::scoring(1.9);
    let risk = risk_of(&fake);
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let cancel = CancellationToken::new();
    for subject in [
        PermissionSubject::Program(ProgramSubject::plain("git", vec!["status".into()])),
        PermissionSubject::WritePath("a.txt".into()),
        PermissionSubject::Text("hello".into()),
    ] {
        let mut app = app_with(subject);
        assert!(start_risk(&risk, &tx, &mut app, &cancel).is_none());
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(fake.calls(), 0, "コマンド行でないものを判定へ出した");
}

/// **キャンセルされた判定は、何も送らない**（承認画面はもう別のものを見ている）。
#[tokio::test]
async fn a_cancelled_check_sends_nothing() {
    let fake = FakeRisk::new(Ok(1.9), Duration::from_millis(300));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let cancel = CancellationToken::new();
    let mut app = shell_app(DANGEROUS_LINE);
    let gate = start_risk(&risk_of(&fake), &tx, &mut app, &cancel);
    assert!(gate.is_some());
    cancel.cancel();
    let none = tokio::time::timeout(Duration::from_millis(600), rx.recv()).await;
    assert!(none.is_err(), "キャンセル後に何かが届いた: {none:?}");
}

/// 要約の使い回しの鍵は、危険度の段階で変わる。**低い・判定なしは同じ鍵**（今までと同じ要求だから）。
/// 含めないと、同じ中身で判定だけ違うときに、危険と言っていない前の要約が出る。
#[test]
fn the_reuse_key_changes_with_the_risk_level_that_reaches_the_summary() {
    let pieces = vec![SummaryPiece {
        label: "the shell line".into(),
        text: DANGEROUS_LINE.into(),
    }];
    let none = summary_key(&pieces, None, None);
    let low = summary_key(&pieces, None, Some(RiskLevel::Low));
    let danger = summary_key(&pieces, None, Some(RiskLevel::Danger));
    assert_eq!(none, low, "低いは今までと同じ要求なので同じ鍵");
    assert_ne!(none, danger);
}

/// 判定済みの危険な行は、**判定なしで作った要約を使い回さない**。鍵に段階が入るので、別の鍵で聞き直す。
#[tokio::test]
async fn a_summary_made_without_the_verdict_is_not_reused_for_a_dangerous_line() {
    let mut cache = SummaryCache::new();
    // 1回目: 判定が無い構成で要約した（今までと同じ）。
    let mut first = shell_app(DANGEROUS_LINE);
    run_dialog(&mut first, None, &mut cache).await;
    assert_eq!(cache.len(), 1);

    // 2回目: 同じ行が危険と判定された。前の要約（危険と言っていない）を出さず、危険度つきで作り直す。
    let fake = FakeRisk::scoring(1.73);
    let mut second = shell_app(DANGEROUS_LINE);
    let req = run_dialog(&mut second, Some(&risk_of(&fake)), &mut cache).await;
    assert!(req.system[0].text.contains("DANGEROUS"));
    assert_eq!(cache.len(), 2, "危険度つきの要約が別の鍵で残っていない");
}

/// 温めは、依頼を送るたびではなく**間隔を空けて**1回だけ。固定の無害な1行だけを送り、
/// ユーザーの文もコマンドも送らない。
#[tokio::test]
async fn warming_up_sends_one_harmless_fixed_line_and_not_on_every_prompt() {
    let fake = FakeRisk::scoring(0.1);
    let risk = risk_of(&fake);
    let mut warm = RiskWarmUp::new();
    let t0 = Instant::now();
    assert!(warm.nudge(&risk, t0));
    assert!(
        !warm.nudge(&risk, t0 + Duration::from_secs(10)),
        "間隔内に2度呼んだ"
    );
    assert!(
        warm.nudge(&risk, t0 + Duration::from_secs(61)),
        "間隔を空けても呼ばない"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(fake.calls(), 2);
    assert_eq!(fake.lines.lock().unwrap().as_slice(), ["echo", "echo"]);
}

/// **判定が低い・無いなら、前の要約は今までどおり使い回す**（LLMを呼ばない）。判定を待っている間は
/// 使い回しを確定させないが、決まったのが「危険度なし」の段階なら、引いておいた候補をそのまま出す。
#[tokio::test]
async fn a_cached_summary_is_still_reused_when_the_verdict_is_low_or_missing() {
    for reply in [Ok(0.13), Err("接続を拒まれた".to_string())] {
        let mut cache = SummaryCache::new();
        let mut first = shell_app("systeminfo");
        run_dialog(&mut first, None, &mut cache).await;
        assert_eq!(cache.len(), 1);

        let fake = FakeRisk::new(reply.clone(), Duration::ZERO);
        let provider = Arc::new(Capturing::default());
        let summary = summary_with(&provider);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let scope = open_scope(ReadScopeConfig::default());
        let mut again = shell_app("systeminfo");
        let gate = start_risk(&risk_of(&fake), &tx, &mut again, &CancellationToken::new());
        assert!(
            start_summary(&summary, &tx, &mut again, &cache, &scope, false, None, gate).is_some()
        );
        apply_until_ready(&mut rx, &mut again, &mut cache).await;

        assert!(
            provider.seen.lock().unwrap().is_empty(),
            "{reply:?}: 使い回せる要約があるのにLLMを呼んだ"
        );
        assert!(matches!(
            &view(&again).summary,
            crate::app::SummaryState::Done { text, .. } if text == "ファイルを消す。"
        ));
    }
}
