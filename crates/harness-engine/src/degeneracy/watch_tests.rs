//! [`CallWatch`]の単体テスト——検知器・ゲート・統計の**組み合わせ**が意図通りに繋がっているか。
//!
//! 個々の判定式は`detect_tests.rs`・`gate_tests.rs`が固定しているので、ここでは
//! 「どの入口がどの検知器を起こすか」「ゲートの理由が発火理由へ前置きされるか」
//! 「母集団へ入るのは縮退しなかったコールだけか」を見る。

use super::*;

fn detector() -> DegeneracyDetector {
    DegeneracyDetector::new(DegeneracyConfig::default())
}

/// 統計を温める（母集団を「平常＝短い出力」で埋める）。
fn warm(d: &DegeneracyDetector, model: &str, max_tokens: u32) {
    for _ in 0..16 {
        let mut w = d.watch(model, max_tokens);
        w.on_text("了解。");
        w.record_clean();
    }
}

/// ①はゲート不要で常時ON——統計が1件も無い状態でも字句反復は捕まる。
#[test]
fn a_lexical_repeat_is_caught_even_with_no_statistics() {
    let d = detector();
    let mut w = d.watch("m", 1_000);
    let hit = w.on_thinking(&"？".repeat(512));
    let hit = hit.expect("①は常時ON");
    assert_eq!(hit.kind, DegenerateKind::ShortPeriodRepeat);
}

/// ③は`on_done`でしか出ない。実機で最も多く踏む形（`length`で終わり本文0文字）。
#[test]
fn finishing_at_max_tokens_without_output_is_caught_on_done() {
    let d = detector();
    let mut w = d.watch("m", 1_000);
    // thinkingだけが出て本文が0。まだ④の閾値には届かない量。
    assert!(w.on_thinking("考え中。").is_none());
    let hit = w.on_done(&StopReason::MaxTokens).expect("③");
    assert_eq!(hit.kind, DegenerateKind::NoOutputAtMaxTokens);
}

/// 本文が出ていれば③は発火しない（正常に打ち切られただけのターン）。
#[test]
fn finishing_at_max_tokens_with_output_is_not_degenerate() {
    let d = detector();
    let mut w = d.watch("m", 1_000);
    assert!(w.on_text("結論はこうです。").is_none());
    assert_eq!(w.on_done(&StopReason::MaxTokens), None);
}

/// `tool_use`が出ていれば③は発火しない。
#[test]
fn a_tool_call_disarms_the_no_output_detector() {
    let d = detector();
    let mut w = d.watch("m", 1_000);
    w.on_tool_use_block();
    assert!(w.on_tool_args(r#"{"path":"a.rs"}"#).is_none());
    assert_eq!(w.on_done(&StopReason::MaxTokens), None);
}

/// ④はゲートが開いて初めて評価される。統計が無ければコールドスタートの固定比率
/// （`max_tokens × 4 × 0.75`）を超えたところで開く。
#[test]
fn the_reasoning_only_detector_needs_the_gate_to_open() {
    let d = detector();
    // max_tokens=100 → ④の閾値は 100*4*0.6 = 240文字、ゲートは 100*4*0.75 = 300文字。
    // つまりゲートが開くのが先に来ないので、④はゲートが開いた直後に発火する。
    let mut w = d.watch("m", 100);
    let mut fired = None;
    for i in 0..40 {
        // ①②を起こさないよう、毎回内容の違う文を積む（④だけを見たい）。
        let chunk = format!(
            "検討{i}: 経路{}を通る場合の前提は{}であり、帰結は{}になる。",
            i * 37 % 101,
            i * 7 % 13,
            i * 11 % 17
        );
        if let Some(hit) = w.on_thinking(&chunk) {
            fired = Some(hit);
            break;
        }
    }
    let hit = fired.expect("thinkingだけが枠を食えば④が出る");
    assert_eq!(hit.kind, DegenerateKind::ReasoningOnly);
    assert!(hit.reason.contains("疑い状態"), "{}", hit.reason);
}

/// **発火理由が1行で説明できる**（§11.2）。ゲートが開いた理由が前置きされる。
#[test]
fn the_reason_explains_both_the_gate_and_the_detector() {
    let d = detector();
    warm(&d, "m", 1_000);
    let mut w = d.watch("m", 1_000);
    // 平常は「了解。」の3文字。その3倍を超えると疑い状態に入る。
    let para = "この問題の原因はおそらく設定ファイルの読み込み順序にある。順序を入れ替えれば直るはずだ。\
                しかし本当にそうだろうか。もう一度確かめる必要がある。";
    let hit = w.on_text(&para.repeat(40)).expect("②");
    assert_eq!(hit.kind, DegenerateKind::NoveltyCollapse);
    assert!(hit.reason.starts_with("疑い状態（"), "{}", hit.reason);
    assert!(hit.reason.contains("出力量が平常の"), "{}", hit.reason);
    assert!(hit.reason.contains("既出"), "{}", hit.reason);
}

/// **母集団へ入るのは`record_clean`したコールだけ**。縮退したコールを入れないという
/// 呼び出し規約が守られている限り、閾値はずり上がらない（§11.2）。
#[test]
fn only_clean_calls_widen_the_population() {
    let d = detector();
    warm(&d, "m", 1_000);
    let budget_before = d.watch("m", 1_000).recovery_budget();
    assert!(budget_before.is_some(), "統計が温まっていれば回復予算が出る");

    // 縮退したコールは`record_clean`せずに捨てる。
    for _ in 0..50 {
        let mut w = d.watch("m", 1_000);
        let _ = w.on_thinking(&"？".repeat(512));
        drop(w);
    }
    assert_eq!(d.watch("m", 1_000).recovery_budget(), budget_before);
}

/// 統計が無いうちは回復予算も出ない（梯子は段数だけで進む）。
#[test]
fn a_cold_detector_has_no_recovery_budget() {
    let d = detector();
    assert_eq!(d.watch("m", 1_000).recovery_budget(), None);
}

/// 回復予算は `median_elapsed × recovery_multiplier`。
#[test]
fn the_recovery_budget_is_the_median_times_the_multiplier() {
    let d = DegeneracyDetector::new(DegeneracyConfig {
        recovery_multiplier: 3.0,
        ..DegeneracyConfig::default()
    });
    {
        let mut stats = d.stats.lock().unwrap();
        for _ in 0..16 {
            stats.record_clean(
                StatKey {
                    model: "m".to_string(),
                    max_tokens: 1_000,
                },
                Sample {
                    chars: 100,
                    elapsed: Duration::from_secs(10),
                },
            );
        }
    }
    assert_eq!(
        d.watch("m", 1_000).recovery_budget(),
        Some(Duration::from_secs(30)),
        "平常10秒のコールに、回復まで含めて30秒以上かけない"
    );
}

/// `auto_recycle`の既定は`false`——他セッションの推論を巻き添えで殺す操作なので、
/// 暗黙の既定にはしない（§11.5）。
#[test]
fn recycling_is_off_by_default() {
    assert!(!DegeneracyConfig::default().auto_recycle);
    let d = detector();
    assert!(!d.watch("m", 1_000).recycle_enabled());
}

/// 別モデル・別`max_tokens`は別母集団（§11.2）。認知レイヤーのフェーズ予算がそのまま
/// フェーズ別の統計になる性質を、`CallWatch`越しにも確認する。
#[test]
fn watches_are_keyed_by_model_and_max_tokens() {
    let d = detector();
    warm(&d, "m", 800);
    assert!(d.watch("m", 800).recovery_budget().is_some());
    assert_eq!(d.watch("m", 4_096).recovery_budget(), None);
    assert_eq!(d.watch("other", 800).recovery_budget(), None);
}
