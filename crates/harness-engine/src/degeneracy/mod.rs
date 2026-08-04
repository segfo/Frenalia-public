//! 縮退ガード — degenerate outputの検知・破棄・再推論（`plans/DESIGN-COGNITION.md` §11、M21）。
//!
//! # 何を解いているか
//!
//! ローカルモデルで、**1回のLLMコールが同一トークンの反復に陥り、有意な出力を生成しないまま
//! 出力上限に達する**現象への対処。`？？？？・・・・`のような字句反復と、reasoningストリームが
//! 同じ推論を巡回する思考ループの2形態がある。
//!
//! これは§3.5の収束保証とは**別の層の問題**である。§3.5は「複数コールにまたがってゴールへ
//! 近づかない」ことを扱い、ここは「**1コールの中で出力が壊れる**」ことを扱う。前者はゴールの
//! 進め方を変えて畳み、後者はそのコールの出力を捨ててやり直す。検知器も対処も共有しない。
//!
//! 本機構は認知レイヤー固有ではない。**`CognitionLevel::Off`（素朴ループ）でも同じ故障が起きる**
//! ため、強制点は`harness-engine`側（[`crate::turn::TurnExecutor`]）に置く。認知レイヤーは
//! 1ゴールあたり多数のフェーズコールを投げるぶん、踏む頻度が高い利用者にすぎない。
//!
//! # モジュール構成
//!
//! | ファイル | 責務 |
//! |---|---|
//! | [`detect`] | 検知器4種（§11.1）。純粋関数 |
//! | [`gate`] | 異常ゲートと移動統計（§11.2）。純粋 |
//! | [`ladder`] | 回復の梯子（§11.3）。純粋 |
//! | 本ファイル | 設定・セッション寿命の[`DegeneracyDetector`]・1コール分の[`CallWatch`] |
//!
//! # 統計の寿命と所有権
//!
//! 統計の寿命は**セッション全体**だが、[`crate::turn::TurnExecutor`]は1発話ごとに構築し直される。
//! そこで[`DegeneracyDetector`]は`Arc`で中身を共有する`Clone`型にし、**セッション側
//! （`harness-cli`/`harness-tui`）が1つ所有して[`crate::AgentLoopConfig`]へcloneして渡す**。
//! これで`TurnExecutor`は「状態を持たない実行器」という不変条件を保ち、テストは毎回新品を注入できる。
//! ディスクへは永続化しない。
//!
//! > 設計文書§11.2は`Option<&DegeneracyDetector>`を`events`/`cancel`と同じ引数として渡す形を
//! > 描いているが、それだと`CognitiveOrchestrator::run`と`run_agent_loop`（どちらも既に9引数）の
//! > 両方へ引数が増える。既存の`compaction`と同じ「起動時に解決して`AgentLoopConfig`へ畳む」形に
//! > 揃えた。§11.2が守れと言っている2点（統計の寿命・実行器の無状態性）はどちらも保たれる。

pub mod detect;
pub mod gate;
pub mod ladder;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use harness_core::{DegenerateKind, StopReason};

pub use detect::{NgramConfig, ShortPeriodConfig};
pub use gate::{Sample, StatKey};
pub use ladder::Rung;

/// 縮退ガードの設定（`.harness/settings.json`の`degeneracy`キー、§11.6）。
///
/// `harness-config`の`DegeneracySettings`（全フィールド`Option`）から`harness-cli`が畳んで作る。
/// `harness-engine`は設定型を知らないという既存の依存の向き（`CompactionOverrides`と同じ）を保つ。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DegeneracyConfig {
    /// (d) 段（モデル再ロード）を使うか。**既定`false`**。
    ///
    /// 推論サーバは複数のharnessセッションで共有され得るため、再ロードは**もう片方の
    /// 進行中の推論を巻き添えで殺す**。他者に影響する操作を暗黙の既定にはできない。
    pub auto_recycle: bool,
    /// 平常中央値の何倍で「疑い」状態へ入るか。
    pub gate_multiplier: f32,
    /// 回復に使ってよい壁時計時間 = 中央値 × これ。
    pub recovery_multiplier: f32,
    pub short_period: ShortPeriodConfig,
    pub ngram: NgramConfig,
    /// `max_tokens`の何割をthinkingだけで食ったら打ち切るか（④）。
    pub reasoning_only_ratio: f32,
}

impl Default for DegeneracyConfig {
    /// §11.6の既定値そのもの。
    fn default() -> Self {
        Self {
            auto_recycle: false,
            gate_multiplier: 3.0,
            recovery_multiplier: 3.0,
            short_period: ShortPeriodConfig::default(),
            ngram: NgramConfig::default(),
            reasoning_only_ratio: 0.6,
        }
    }
}

/// セッション全体を寿命とする移動統計の持ち主。
///
/// `enabled: false`（§11.6）は「この型を`None`で渡す」で表現する——**この機構が本来正常な
/// 動作を阻害し得る唯一のクラスの機能**（他の機構は「拒否する」方向で、これは「捨ててやり直す」方向）
/// なので、想定外の誤検知に当たった人がハーネス全体を使えなくなる前に切れる口を1つ確保する。
#[derive(Debug, Clone)]
pub struct DegeneracyDetector {
    config: DegeneracyConfig,
    stats: Arc<Mutex<gate::Stats>>,
}

impl DegeneracyDetector {
    pub fn new(config: DegeneracyConfig) -> Self {
        Self {
            config,
            stats: Arc::new(Mutex::new(gate::Stats::default())),
        }
    }

    pub fn config(&self) -> &DegeneracyConfig {
        &self.config
    }

    /// このコール用の観測器を開く。母集団のキーは`(model, max_tokens)`。
    pub fn watch(&self, model: &str, max_tokens: u32) -> CallWatch<'_> {
        CallWatch {
            detector: self,
            key: StatKey {
                model: model.to_string(),
                max_tokens,
            },
            max_tokens,
            started: Instant::now(),
            text: detector_watcher(&self.config),
            thinking: detector_watcher(&self.config),
            tool_args: detector_watcher(&self.config),
            tool_use_blocks: 0,
            gate_reason: None,
        }
    }

    /// 回復に使ってよい壁時計時間。統計が無ければ`None`（段数だけで進む）。
    fn recovery_budget(&self, key: &StatKey) -> Option<Duration> {
        let stats = self.stats.lock().ok()?;
        stats
            .median_elapsed(key)
            .map(|m| m.mul_f64(f64::from(self.config.recovery_multiplier).max(0.0)))
    }
}

fn detector_watcher(config: &DegeneracyConfig) -> detect::StreamWatcher {
    detect::StreamWatcher::new(config.short_period, config.ngram)
}

/// 縮退の判定結果。
#[derive(Debug, Clone, PartialEq)]
pub struct Degenerate {
    pub kind: DegenerateKind,
    /// 発火理由の1行説明。異常ゲートが開いていた場合はその理由も連結する
    /// （「疑い状態（出力量が平常の3.4倍）→ 新規性率0.94で縮退判定」、§11.2）。
    pub reason: String,
}

/// 1回のプロバイダ呼び出しに対応する観測器。ストリームの進行に合わせて文字を流し込む。
///
/// **ブロック種別ごとに独立したリングバッファを持ち混ぜない**（§11.1）。
pub struct CallWatch<'a> {
    detector: &'a DegeneracyDetector,
    key: StatKey,
    max_tokens: u32,
    started: Instant,
    text: detect::StreamWatcher,
    thinking: detect::StreamWatcher,
    tool_args: detect::StreamWatcher,
    tool_use_blocks: usize,
    /// 異常ゲートが開いた理由（一度開いたらこのコールの間は開いたまま）。
    gate_reason: Option<String>,
}

impl CallWatch<'_> {
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// 回復に使ってよい壁時計時間。
    pub fn recovery_budget(&self) -> Option<Duration> {
        self.detector.recovery_budget(&self.key)
    }

    /// (d) 段を使ってよいか（設定側の可否だけ。プロバイダ側の可否は`recycle`の戻り値で分かる）。
    pub fn recycle_enabled(&self) -> bool {
        self.detector.config.auto_recycle
    }

    pub fn text_chars(&self) -> usize {
        self.text.len()
    }

    /// 可視テキストのデルタ。
    pub fn on_text(&mut self, s: &str) -> Option<Degenerate> {
        if !self.text.push(s) {
            return None;
        }
        // ゲートは**追加した後の**出力量・経過時間で引く。追加前の状態で引くと、
        // 大きなデルタが1回で届いた場合にそのデルタ自身が判定に反映されない。
        let open = self.refresh_gate();
        let hit = self.text.evaluate(open);
        self.finish(hit)
    }

    /// thinking（reasoning）のデルタ。
    pub fn on_thinking(&mut self, s: &str) -> Option<Degenerate> {
        if !self.thinking.push(s) {
            return None;
        }
        let open = self.refresh_gate();
        if let Some(hit) = self.thinking.evaluate(open) {
            return self.finish(Some(hit));
        }
        // ④ は「thinkingだけが枠を食い潰している」ことの早期検知なので、
        // thinkingが伸びたこの瞬間にだけ評価すればよい。
        if !open {
            return None;
        }
        let hit = detect::reasoning_only(
            self.thinking.len(),
            self.text.len(),
            self.tool_use_blocks,
            self.max_tokens,
            self.detector.config.reasoning_only_ratio,
        );
        self.finish(hit)
    }

    /// `tool_use`の引数JSON断片。
    pub fn on_tool_args(&mut self, s: &str) -> Option<Degenerate> {
        if !self.tool_args.push(s) {
            return None;
        }
        let open = self.refresh_gate();
        let hit = self.tool_args.evaluate(open);
        self.finish(hit)
    }

    /// `tool_use`ブロックが開いた。③④の前提（産出がゼロ）を崩す。
    pub fn on_tool_use_block(&mut self) {
        self.tool_use_blocks += 1;
    }

    /// ストリームが終わった時点の判定（③と、刻みで取りこぼした末尾ぶんの①②）。
    ///
    /// **③はここでしか評価できない**（`stop_reason`が要る）が、`ToolUse`ゼロが発火条件なので、
    /// ここで縮退と判定してもツールは1つも実行されていない。
    pub fn on_done(&mut self, stop_reason: &StopReason) -> Option<Degenerate> {
        let open = self.refresh_gate();
        for w in [&self.text, &self.thinking, &self.tool_args] {
            if let Some(hit) = w.evaluate(open) {
                return self.finish(Some(hit));
            }
        }
        let hit =
            detect::no_output_at_max_tokens(stop_reason, self.text.len(), self.tool_use_blocks);
        self.finish(hit)
    }

    /// 縮退しなかったコールを母集団へ入れる。**縮退したコールでは呼ばない**
    /// （§11.2の自己敗北的フィードバックを避けるため）。
    pub fn record_clean(self) {
        let sample = Sample {
            chars: (self.text.len() + self.thinking.len()) as u64,
            elapsed: self.started.elapsed(),
        };
        if let Ok(mut stats) = self.detector.stats.lock() {
            stats.record_clean(self.key, sample);
        }
    }

    /// 異常ゲートを引き直す。一度開いたらこのコールの間は開いたまま（出力が伸びる方向にしか
    /// 進まないので、閉じ直す意味が無い）。
    fn refresh_gate(&mut self) -> bool {
        if self.gate_reason.is_some() {
            return true;
        }
        let chars = (self.text.len() + self.thinking.len()) as u64;
        let elapsed = self.started.elapsed();
        let verdict = match self.detector.stats.lock() {
            Ok(stats) if stats.is_warm(&self.key) => {
                stats.gate(&self.key, chars, elapsed, self.detector.config.gate_multiplier)
            }
            // 統計が無い（コールドスタート）／ロックが毒された場合は固定比率へ倒す。
            _ => gate::Stats::cold_start_gate(chars, self.max_tokens),
        };
        if verdict.open {
            self.gate_reason = Some(verdict.reason);
            return true;
        }
        false
    }

    /// 検知器の戻り値を[`Degenerate`]へ仕上げる（ゲートの理由を前置きする）。
    fn finish(&self, hit: Option<(DegenerateKind, String)>) -> Option<Degenerate> {
        let (kind, why) = hit?;
        let reason = match &self.gate_reason {
            Some(g) => format!("疑い状態（{g}）→ {why}"),
            None => why,
        };
        Some(Degenerate { kind, reason })
    }
}

#[cfg(test)]
#[path = "watch_tests.rs"]
mod watch_tests;
