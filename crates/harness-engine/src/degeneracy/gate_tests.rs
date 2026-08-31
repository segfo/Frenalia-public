//! 異常ゲートと移動統計の単体テスト。
//!
//! 最重要なのは「**縮退した実行が母集団を汚さない**」ことの固定（§11.2の自己敗北的
//! フィードバック）。これが壊れると、縮退が続くほど閾値が上がって検知が黙るという、
//! 症状からは絶対に気付けない壊れ方をする。

use super::*;

fn key() -> StatKey {
    StatKey {
        model: "test-model".to_string(),
        max_tokens: 1_000,
    }
}

fn sample(chars: u64, secs: f64) -> Sample {
    Sample {
        chars,
        elapsed: Duration::from_secs_f64(secs),
    }
}

fn warm(stats: &mut Stats, chars: u64, secs: f64) {
    for _ in 0..WINDOW {
        stats.record_clean(key(), sample(chars, secs));
    }
}

#[test]
fn the_window_must_fill_before_medians_are_available() {
    let mut stats = Stats::default();
    for i in 0..(WINDOW - 1) {
        stats.record_clean(key(), sample(100 + i as u64, 1.0));
        assert!(!stats.is_warm(&key()), "{i}件目ではまだ中央値を出さない");
        assert_eq!(stats.median_chars(&key()), None);
    }
    stats.record_clean(key(), sample(100, 1.0));
    assert!(stats.is_warm(&key()));
    assert!(stats.median_chars(&key()).is_some());
}

#[test]
fn the_median_is_the_middle_of_the_last_window() {
    let mut stats = Stats::default();
    for i in 0..WINDOW {
        stats.record_clean(key(), sample(i as u64 * 10, f64::from(i as u32)));
    }
    // 0,10,...,150 の中央（上側）は 80。
    assert_eq!(stats.median_chars(&key()), Some(80));
    assert_eq!(stats.median_elapsed(&key()), Some(Duration::from_secs(8)));
}

/// 窓は直近`WINDOW`件だけ。古いサンプルは押し出される。
#[test]
fn the_window_slides() {
    let mut stats = Stats::default();
    warm(&mut stats, 100, 1.0);
    assert_eq!(stats.median_chars(&key()), Some(100));
    warm(&mut stats, 900, 9.0);
    assert_eq!(
        stats.median_chars(&key()),
        Some(900),
        "古い100件は押し出された"
    );
}

/// **§11.2の核心**: 縮退と判定した実行を`record_clean`しない限り、母集団は汚れない。
#[test]
fn degenerate_runs_never_enter_the_population() {
    let mut stats = Stats::default();
    warm(&mut stats, 100, 1.0);
    let before = stats.median_chars(&key()).unwrap();

    // 縮退した実行（巨大な出力量）は記録しない、という呼び出し規約をここで表現する。
    // 記録しなければ中央値は動かず、閾値は上がらない。
    for _ in 0..100 {
        let verdict = stats.gate(&key(), 1_000_000, Duration::from_secs(600), 3.0);
        assert!(verdict.open, "この出力量なら疑い状態に入る");
        // ここで record_clean を呼ばないのが規約。
    }
    assert_eq!(
        stats.median_chars(&key()),
        Some(before),
        "閾値がずり上がらない"
    );
    assert!(
        stats
            .gate(&key(), 1_000_000, Duration::from_secs(600), 3.0)
            .open
    );
}

#[test]
fn the_gate_opens_on_output_volume() {
    let mut stats = Stats::default();
    warm(&mut stats, 100, 1.0);
    assert!(
        !stats.gate(&key(), 300, Duration::from_secs(1), 3.0).open,
        "3倍ちょうどは開かない"
    );
    let v = stats.gate(&key(), 301, Duration::from_secs(1), 3.0);
    assert!(v.open);
    assert!(v.reason.contains("出力量"), "{}", v.reason);
}

/// 出力量では拾えない故障（推論サーバのハング・デルタ停止・GPU OOM後の無応答）を
/// 同じゲートで拾うため、経過時間もORで見る。
#[test]
fn the_gate_also_opens_on_elapsed_time_alone() {
    let mut stats = Stats::default();
    warm(&mut stats, 100, 1.0);
    let v = stats.gate(&key(), 10, Duration::from_secs(4), 3.0);
    assert!(v.open, "出力量は平常以下でも、時間が3倍を超えれば疑う");
    assert!(v.reason.contains("所要時間"), "{}", v.reason);
}

/// **平常が極端に速い母集団でゲートが開きっぱなしにならない**。
///
/// mockプロバイダ・キャッシュヒット・短い解釈コールでは中央値がミリ秒未満になり、
/// 比率だけで見ると数ミリ秒かかっただけで「平常の3倍」になってしまう。経過時間のORが
/// 拾いたいのは秒単位の故障（ハング・無応答）なので、絶対下限で切る。
#[test]
fn a_very_fast_population_does_not_leave_the_time_gate_permanently_open() {
    let mut stats = Stats::default();
    warm(&mut stats, 100, 0.000_1);
    // 中央値0.1msの3倍は0.3msだが、5msかかった程度では疑わない。
    assert!(!stats.gate(&key(), 10, Duration::from_millis(5), 3.0).open);
    assert!(
        !stats.gate(&key(), 10, MIN_SUSPICIOUS_ELAPSED, 3.0).open,
        "下限ちょうどは開かない"
    );
    assert!(
        stats.gate(&key(), 10, Duration::from_secs(2), 3.0).open,
        "秒単位なら疑う"
    );
}

#[test]
fn a_cold_population_keeps_the_gate_closed() {
    let stats = Stats::default();
    assert!(
        !stats
            .gate(&key(), 1_000_000, Duration::from_secs(600), 3.0)
            .open
    );
    assert!(!stats.is_warm(&key()));
}

/// コールドスタート時は`max_tokens`からの固定比率だけで見る。
#[test]
fn the_cold_start_fallback_uses_a_fixed_ratio_of_the_budget() {
    // max_tokens=1000 → 4000文字の75% = 3000文字。
    assert!(!Stats::cold_start_gate(3_000, 1_000).open);
    let v = Stats::cold_start_gate(3_001, 1_000);
    assert!(v.open);
    assert!(v.reason.contains("統計未蓄積"), "{}", v.reason);
}

/// 母集団は`(model, max_tokens)`で分かれる。認知レイヤーのフェーズ予算が`max_tokens`へ
/// 入るため、これがそのままフェーズ別の統計になる（§11.2）。
#[test]
fn populations_are_keyed_by_model_and_max_tokens() {
    let mut stats = Stats::default();
    let distill = StatKey {
        model: "m".to_string(),
        max_tokens: 800,
    };
    let naive = StatKey {
        model: "m".to_string(),
        max_tokens: 4_096,
    };
    for _ in 0..WINDOW {
        stats.record_clean(distill.clone(), sample(200, 1.0));
    }
    assert!(stats.is_warm(&distill));
    assert!(!stats.is_warm(&naive), "別の予算のターンは別母集団");

    for _ in 0..WINDOW {
        stats.record_clean(naive.clone(), sample(6_000, 30.0));
    }
    assert_eq!(stats.median_chars(&distill), Some(200));
    assert_eq!(stats.median_chars(&naive), Some(6_000));
    // 小さい予算のフェーズで6,000文字も出れば疑うが、大きい予算のターンでは平常。
    assert!(
        stats
            .gate(&distill, 6_000, Duration::from_secs(1), 3.0)
            .open
    );
    assert!(!stats.gate(&naive, 6_000, Duration::from_secs(1), 3.0).open);
}
