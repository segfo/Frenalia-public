//! 回復の梯子の単体テスト。
//!
//! 固定したいのは3点——**必ず有限で止まる**こと、**(c)がプロンプトキャッシュを壊さない**こと
//! （§6.5・§11.3）、そして**予算切れで最終段へジャンプする**こと（§11.3の「無駄に燃やした量で進む」）。

use super::*;
use harness_core::{Message, Sampling, ToolChoice};

fn request() -> CompletionRequest {
    CompletionRequest {
        system: vec![SystemBlock {
            text: "環境事実（キャッシュ済み）".to_string(),
            cache: true,
        }],
        messages: vec![Message {
            role: harness_core::Role::User,
            content: vec![harness_core::ContentBlock::Text("やって".to_string())],
        }],
        tools: vec![],
        tool_choice: ToolChoice::None,
        output: None,
        parallel_tool_calls: None,
        max_tokens: 1_000,
        sampling: Sampling::default(),
        model: "m".to_string(),
    }
}

/// 予算が無い（コールドスタート）ときは段数だけで進み、必ず`Exhausted`へ到達する。
#[test]
fn without_a_budget_the_ladder_walks_the_rungs_and_terminates() {
    let mut l = Ladder::new(None, false);
    assert_eq!(l.current(), Rung::Jitter);
    assert_eq!(l.advance(Duration::ZERO), Rung::Jitter, "(b)を2回試す");
    assert_eq!(l.advance(Duration::ZERO), Rung::JitterWithNotice);
    assert_eq!(l.advance(Duration::ZERO), Rung::JitterWithNotice, "(c)を2回試す");
    // (d) が無効なので (c) の次は即 (f)。
    assert_eq!(l.advance(Duration::ZERO), Rung::Exhausted);
    assert_eq!(l.advance(Duration::ZERO), Rung::Exhausted, "以後も終端のまま");
}

/// (d) が有効なら (c) の後に1回だけ再ロードを試してから諦める。
#[test]
fn recycle_is_tried_once_before_giving_up() {
    let mut l = Ladder::new(None, true);
    for _ in 0..4 {
        l.advance(Duration::ZERO);
    }
    assert_eq!(l.current(), Rung::Recycle);
    assert_eq!(l.advance(Duration::ZERO), Rung::Exhausted, "再ロードは1回だけ");
}

/// **§11.3の進行規則**: 予算を使い切ったら段を飛ばして最終段へジャンプする。
/// ④で50秒燃えたなら (b) を丁寧に2回試さず、即座に再ロードへ落ちる。
#[test]
fn burning_the_budget_jumps_straight_to_the_last_resort() {
    let mut l = Ladder::new(Some(Duration::from_secs(30)), true);
    assert_eq!(l.advance(Duration::from_secs(50)), Rung::Recycle);
}

/// (d) が無効なら、予算切れのジャンプ先は (f)。
#[test]
fn burning_the_budget_without_recycle_gives_up_immediately() {
    let mut l = Ladder::new(Some(Duration::from_secs(30)), false);
    assert_eq!(l.advance(Duration::from_secs(50)), Rung::Exhausted);
}

/// 予算内なら通常どおり段を登る（①で7秒ずつ切れているなら (b) を数回試せる）。
#[test]
fn staying_inside_the_budget_keeps_climbing_normally() {
    let mut l = Ladder::new(Some(Duration::from_secs(30)), true);
    assert_eq!(l.advance(Duration::from_secs(7)), Rung::Jitter);
    assert_eq!(l.advance(Duration::from_secs(7)), Rung::JitterWithNotice);
    assert_eq!(l.advance(Duration::from_secs(7)), Rung::JitterWithNotice);
    // ここまでで28秒。次の1回で予算超過→最終段へ。
    assert_eq!(l.advance(Duration::from_secs(7)), Rung::Recycle);
}

/// (b) はサンプリングだけを触る。systemもmessagesも変えない。
#[test]
fn jitter_only_touches_sampling() {
    let mut req = request();
    let before_system = req.system.clone();
    let before_messages = req.messages.clone();
    apply(&mut req, Rung::Jitter, 1);

    assert_eq!(req.sampling.temperature, Some(0.7 + 0.2));
    assert_eq!(req.sampling.frequency_penalty, Some(0.4));
    assert_eq!(req.sampling.presence_penalty, Some(0.4));
    assert_eq!(req.system, before_system);
    assert_eq!(req.messages, before_messages);
}

/// 呼び出し側が温度を明示していれば、そこから積む。
#[test]
fn an_explicit_temperature_is_the_base_for_the_jitter() {
    let mut req = request();
    req.sampling.temperature = Some(0.1);
    apply(&mut req, Rung::Jitter, 2);
    assert_eq!(req.sampling.temperature, Some(0.1 + 0.4));
}

/// 温度は青天井にしない（上げ続けると別種の壊れ方になる）。
#[test]
fn the_temperature_is_capped() {
    let mut req = request();
    req.sampling.temperature = Some(1.4);
    apply(&mut req, Rung::Jitter, 10);
    assert_eq!(req.sampling.temperature, Some(1.5));
}

/// **(c) はプロンプトキャッシュを壊さない**（§6.5）。既存の`cache:true`ブロックは
/// テキストも順序も不変で、末尾に`cache:false`のブロックが1つ増えるだけ。
#[test]
fn the_notice_is_appended_as_a_non_cached_block_and_leaves_the_prefix_intact() {
    let mut req = request();
    let original = req.system[0].clone();
    apply(&mut req, Rung::JitterWithNotice, 1);

    assert_eq!(req.system.len(), 2);
    assert_eq!(req.system[0], original, "キャッシュ済みプレフィクスは1バイトも変えない");
    assert!(!req.system[1].cache, "追加ブロックはキャッシュしない");
    assert!(req.system[1].text.contains("反復"), "{}", req.system[1].text);
    // messagesへは足さない（role交替が崩れる）。
    assert_eq!(req.messages.len(), 1);
    // (c) は (b) を含む。
    assert!(req.sampling.temperature.is_some());
}

/// 終端段はリクエストを一切触らない（もう送らないので）。
#[test]
fn the_exhausted_rung_does_not_touch_the_request() {
    let mut req = request();
    let before = req.clone();
    apply(&mut req, Rung::Exhausted, 1);
    assert_eq!(req, before);
}

#[test]
fn every_rung_has_a_distinct_stable_name() {
    let names = [Rung::Jitter, Rung::JitterWithNotice, Rung::Recycle, Rung::Exhausted]
        .map(Rung::as_str);
    let unique: std::collections::BTreeSet<_> = names.iter().collect();
    assert_eq!(unique.len(), names.len());
}
