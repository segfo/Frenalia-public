//! 検知器4種の単体テスト。**発火することと同じくらい、発火しないことを固定するのが目的**
//! （`docs/INDEX.md` M21行の完了条件「誤検知してはならない入力で発火しないユニットテスト」）。
//!
//! 誤検知の基準線は実機の実測値に合わせてある（`tools/lmstudio_mgmt_probe.py`の
//! 「実測結果（2026-08-04）」）。正当に完走した長文回答は最小周期512（＝非周期）・
//! 既出率0.00、正当な長考は既出率0.64が上限だった。ここのテストはその性質を、
//! 実機に依存しない合成入力で表現している。

use super::*;
use harness_core::StopReason;

fn watcher() -> StreamWatcher {
    StreamWatcher::new(ShortPeriodConfig::default(), NgramConfig::default())
}

/// 本番（[`super::super::CallWatch`]）と同じ「追加 → ゲート → 評価」の順で1回分を流す。
fn feed(w: &mut StreamWatcher, text: &str, gate_open: bool) -> Option<(DegenerateKind, String)> {
    if !w.push(text) {
        return None;
    }
    w.evaluate(gate_open)
}

// --- ① 短周期反復 ---

/// 実機で確認した誘発プロンプト（`forced-repeat`）が返すのと同じ形。最小周期1。
#[test]
fn a_single_repeated_character_is_a_short_period_repeat() {
    let mut w = watcher();
    let hit = feed(&mut w, &"？".repeat(512), false);
    let (kind, reason) = hit.expect("512文字の同一文字は縮退");
    assert_eq!(kind, DegenerateKind::ShortPeriodRepeat);
    assert!(reason.contains("最小周期が1文字"), "{reason}");
}

/// 32文字ちょうどの塊が繰り返される形（閾値の内側）。
#[test]
fn a_repeating_block_at_the_period_limit_still_fires() {
    let mut w = watcher();
    let block: String = "あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほ0123"
        .chars()
        .take(32)
        .collect();
    assert_eq!(block.chars().count(), 32);
    let hit = feed(&mut w, &block.repeat(16), false);
    assert_eq!(hit.map(|h| h.0), Some(DegenerateKind::ShortPeriodRepeat));
}

/// 周期が`max_period`を1つ超えると発火しない（境界の外側）。
#[test]
fn a_period_just_over_the_limit_does_not_fire() {
    let mut w = watcher();
    let block: String = ('あ'..).take(33).collect();
    assert_eq!(block.chars().count(), 33);
    assert_eq!(feed(&mut w, &block.repeat(16), false), None);
}

/// 反復回数が足りなければ発火しない（`min_repeats`の境界）。
#[test]
fn too_few_repeats_do_not_fire() {
    let mut w = watcher();
    // 周期32を4回＝128文字。ウィンドウ下限（256文字）にも届かない。
    let block: String = ('a'..).take(32).collect();
    assert_eq!(feed(&mut w, &block.repeat(4), false), None);
}

/// **誤検知してはならない**: 正当な日本語散文。
///
/// 「同じ段落を並べて長くする」形の入力は使えない——それは②が捕まえるべき本物の縮退であり
/// （実際、当初この形で書いたテストは②で落ちた）、①が発火しないことの証明にならない。
/// 節ごとに内容が進む文章にする。
#[test]
fn ordinary_prose_is_not_a_short_period_repeat() {
    let mut w = watcher();
    let topics = [
        ("所有権", "値の破棄責任がただ1つの束縛に紐づく"),
        ("借用", "参照を通じて一時的なアクセスだけを渡す"),
        (
            "ライフタイム",
            "参照が有効な範囲をコンパイラへ伝える注釈である",
        ),
        (
            "内部可変性",
            "共有参照の下でも変更を許す型が明示的に用意されている",
        ),
        (
            "Send と Sync",
            "スレッド間で値や参照を渡してよいかを型が表明する",
        ),
        (
            "Drop 順序",
            "束縛の逆順で解放され、その順序が観測可能な副作用になる",
        ),
    ];
    let mut text = String::new();
    for (i, (name, gist)) in topics.iter().cycle().take(24).enumerate() {
        text.push_str(&format!(
            "第{i}節では{name}を扱う。要点は、{gist}という一点に尽きる。\
             ここで注意したいのは、{i}番目の例が示すとおり、規則そのものより\
             「なぜその規則で安全性が保証されるのか」を追う方が理解が早いことだ。\
             反例として、識別子{}番の経路を考えてみると、境界を跨いだ瞬間に\
             前提が崩れることが分かる。",
            i * 37 % 101
        ));
    }
    assert!(text.chars().count() > 2_000);
    // ゲートを開けた状態でも（＝②も評価しても）発火しない。
    assert_eq!(feed(&mut w, &text, true), None);
}

// --- ② 新規性率 ---

/// 同じ段落を繰り返すと新規性が枯れる。周期は段落長なので①では捕まらない形。
#[test]
fn a_looping_paragraph_collapses_novelty() {
    let mut w = watcher();
    let para =
        "この問題の原因はおそらく設定ファイルの読み込み順序にある。順序を入れ替えれば直るはずだ。\
                しかし本当にそうだろうか。もう一度確かめる必要がある。";
    assert!(
        para.chars().count() > 32,
        "①の周期上限より長い段落であること"
    );
    let hit = feed(&mut w, &para.repeat(40), true);
    let (kind, reason) = hit.expect("同一段落の反復は新規性が枯れる");
    assert_eq!(kind, DegenerateKind::NoveltyCollapse);
    assert!(reason.contains("既出"), "{reason}");
}

/// **連続性の要求そのものの固定**: 1区間だけホットでも発火しない。必要区間数(2)に届く
/// 2区間目まで積んで初めて発火する。
#[test]
fn a_single_hot_section_alone_does_not_fire() {
    let cfg = NgramConfig {
        window: 256,
        n: 16,
        seen_ratio_max: 0.80,
        min_hot_sections: 2,
        min_hot_sections_suspect: 2,
    };
    let mut w = StreamWatcher::new(ShortPeriodConfig::default(), cfg);
    let para =
        "この問題の原因はおそらく設定ファイルの読み込み順序にある。順序を入れ替えれば直るはずだ。";
    assert!(para.chars().count() > cfg.n, "①②の対象になる長さであること");
    // ちょうど1区間分（256文字）を同一段落の反復で埋める。
    let one_section: String = para.repeat(10).chars().take(256).collect();
    assert_eq!(
        feed(&mut w, &one_section, true),
        None,
        "1区間だけでは連続性の要求(2区間)に届かないはず"
    );
    assert!(
        w.max_section_ratio() > cfg.seen_ratio_max,
        "この区間自体はホットのはず（前提が崩れていないか確認）: {}",
        w.max_section_ratio()
    );
    // 2区間目もホットになるまで埋めると、必要区間数に達して発火する。
    let hit = feed(&mut w, &one_section, true);
    assert_eq!(hit.map(|h| h.0), Some(DegenerateKind::NoveltyCollapse));
}

/// ②はゲートの状態に関係なく常に評価されるが、**必要な連続ホット区間数**がゲートで変わる
/// （§11.2「疑わしいときだけ厳しく見る」を、on/offではなく厳しさの量で表現する、BUG-087）。
/// 同じ蓄積量でも、ゲートが閉じている（平常時）間は`min_hot_sections`（既定6）の連続を要求されて
/// 届かず、ゲートを開く（疑い状態）と`min_hot_sections_suspect`（既定3）で足りて発火する。
#[test]
fn novelty_needs_more_consecutive_hot_sections_while_the_gate_is_closed() {
    let mut w = watcher();
    let para =
        "この問題の原因はおそらく設定ファイルの読み込み順序にある。順序を入れ替えれば直るはずだ。\
                しかし本当にそうだろうか。もう一度確かめる必要がある。";
    assert_eq!(feed(&mut w, &para.repeat(40), false), None);
    // 同じ蓄積のままゲートを開けると、必要区間数が下がって発火する＝差はゲートだけ。
    assert_eq!(
        w.evaluate(true).map(|h| h.0),
        Some(DegenerateKind::NoveltyCollapse)
    );
}

/// **誤検知してはならない**: 長いMarkdown文書。見出し・箇条書きの定型が混じっても、
/// 内容が新しい限り通る（§11.1「長いではなく新しいことを言わなくなったを測る」）。
#[test]
fn a_long_markdown_document_does_not_collapse_novelty() {
    let mut w = watcher();
    let mut doc = String::from("# 設計メモ\n\n");
    for i in 0..80 {
        doc.push_str(&format!(
            "## 第{i}節 — 論点{i}\n\n\
             この節では、識別子{i}番の経路がどの境界を跨ぐかを検討する。\
             入力は呼び出し元{i}から渡り、検証は層{}で行われ、結果は台帳{}へ記録される。\n\n\
             - 前提{i}: 呼び出し元が正規化済みのパスを渡すこと\n\
             - 帰結{i}: 失敗時は{}番のエラーコードで畳む\n\n",
            i % 7,
            i * 3,
            i + 100
        ));
    }
    assert!(doc.chars().count() > 4_000);
    assert_eq!(feed(&mut w, &doc, true), None);
    // `seen_ratio_max`（既定0.80）への引き下げに実測の余裕があることを固定する。
    assert!(
        w.max_section_ratio() < NgramConfig::default().seen_ratio_max,
        "最大区間既出率{}が閾値に迫っている",
        w.max_section_ratio()
    );
}

/// **誤検知してはならない**: 同型の`impl`ブロックが並ぶ正当なコード。
/// 定型の骨格は反復するが、識別子と本体が毎回変わる。
#[test]
fn repetitive_but_legitimate_code_does_not_collapse_novelty() {
    let mut w = watcher();
    let mut code = String::new();
    for i in 0..60 {
        code.push_str(&format!(
            "impl Handler for Route{i} {{\n    fn name(&self) -> &str {{ \"route-{i}\" }}\n    \
             fn handle(&self, req: Request) -> Response {{\n        \
             let parsed = parse_{i}(req.body())?;\n        Response::ok(parsed.field_{i})\n    }}\n}}\n\n",
        ));
    }
    assert!(code.chars().count() > 3_000);
    assert_eq!(feed(&mut w, &code, true), None);
    assert!(
        w.max_section_ratio() < NgramConfig::default().seen_ratio_max,
        "最大区間既出率{}が閾値に迫っている",
        w.max_section_ratio()
    );
}

/// **誤検知してはならない**: 大きなJSON配列。構造の反復が最も激しい正当な形。
#[test]
fn a_large_json_array_does_not_collapse_novelty() {
    let mut w = watcher();
    let items: Vec<_> = (0..200)
        .map(|i| {
            serde_json::json!({
                "id": i,
                "path": format!("crates/pkg-{i}/src/module_{}.rs", i * 7 % 53),
                "bytes": 1024 + i * 37,
                "sha": format!("{:08x}{:08x}", i * 2654435761u64, i * 40503),
            })
        })
        .collect();
    let text = serde_json::to_string_pretty(&items).unwrap();
    assert!(text.chars().count() > 8_000);
    assert_eq!(feed(&mut w, &text, true), None);
    // 構造反復が最も激しいケースなので、ここが閾値に迫っていないかを特に注視する。
    assert!(
        w.max_section_ratio() < NgramConfig::default().seen_ratio_max,
        "最大区間既出率{}が閾値に迫っている",
        w.max_section_ratio()
    );
}

/// 窓を埋めるだけの分量が無いうちは②を判定しない（短い出力を誤って捕まえない）。
#[test]
fn a_short_output_is_never_a_novelty_collapse() {
    let mut w = watcher();
    // 100文字を繰り返しても、②の窓（1024）に届かないうちは黙る。
    assert_eq!(feed(&mut w, &"ねえ、".repeat(30), true), None);
    assert!(w.len() < NgramConfig::default().window);
}

// --- ③ 完走時の無産出 ---

#[test]
fn max_tokens_with_no_text_and_no_tools_is_degenerate() {
    let hit = no_output_at_max_tokens(&StopReason::MaxTokens, 0, 0);
    assert_eq!(hit.map(|h| h.0), Some(DegenerateKind::NoOutputAtMaxTokens));
}

/// 3つの条件のうち1つでも欠けたら発火しない。
#[test]
fn every_condition_is_required_for_the_no_output_detector() {
    assert_eq!(no_output_at_max_tokens(&StopReason::EndTurn, 0, 0), None);
    assert_eq!(no_output_at_max_tokens(&StopReason::MaxTokens, 1, 0), None);
    assert_eq!(no_output_at_max_tokens(&StopReason::MaxTokens, 0, 1), None);
    // ツールを呼んで打ち切られたターンは、本文が無くても産出はある。
    assert_eq!(no_output_at_max_tokens(&StopReason::ToolUse, 0, 1), None);
}

// --- ④ reasoning-only 上限 ---

#[test]
fn reasoning_that_eats_the_budget_without_output_is_degenerate() {
    // max_tokens=1000 → 枠は4000文字相当、その60%=2400文字を超えたら発火。
    assert_eq!(
        reasoning_only(2_400, 0, 0, 1_000, 0.6),
        None,
        "境界ちょうどは発火しない"
    );
    let hit = reasoning_only(2_401, 0, 0, 1_000, 0.6);
    assert_eq!(hit.map(|h| h.0), Some(DegenerateKind::ReasoningOnly));
}

/// 本文かツールが1つでも出ていれば、thinkingがいくら長くても縮退ではない。
#[test]
fn any_real_output_disarms_the_reasoning_only_detector() {
    assert_eq!(reasoning_only(100_000, 1, 0, 1_000, 0.6), None);
    assert_eq!(reasoning_only(100_000, 0, 1, 1_000, 0.6), None);
}

// --- ブロック種別の独立性 ---

/// **種別ごとのバッファを混ぜない**（§11.1）。thinkingが反復していても、
/// 別種別のwatcherは自分が見た文字だけで判定する。
#[test]
fn watchers_for_different_block_kinds_do_not_share_state() {
    let mut thinking = watcher();
    let mut text = watcher();
    assert!(feed(&mut thinking, &"？".repeat(512), false).is_some());
    assert_eq!(
        feed(&mut text, "了解しました。ファイルを読みます。", false),
        None
    );
    assert_eq!(
        text.len(),
        "了解しました。ファイルを読みます。".chars().count()
    );
}

// --- 最小周期そのもの ---

#[test]
fn the_minimal_period_of_a_non_periodic_string_is_its_length() {
    let s: Vec<char> = "abcdefghij".chars().collect();
    assert_eq!(min_period(&s), s.len());
}

#[test]
fn the_minimal_period_of_a_repeated_block_is_the_block_length() {
    let s: Vec<char> = "abcabcabcabc".chars().collect();
    assert_eq!(min_period(&s), 3);
    let s: Vec<char> = "xxxxxxxx".chars().collect();
    assert_eq!(min_period(&s), 1);
    assert_eq!(min_period(&[]), 0);
}

/// 末尾が途中で切れた反復（`abcabcab`）でも周期は3として取れる。
#[test]
fn a_truncated_repetition_still_reports_the_block_length() {
    let s: Vec<char> = "abcabcab".chars().collect();
    assert_eq!(min_period(&s), 3);
}
