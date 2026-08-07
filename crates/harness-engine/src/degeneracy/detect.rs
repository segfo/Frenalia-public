//! 検知器4種の判定ロジック（`plans/DESIGN-COGNITION.md` §11.1）。**すべて純粋関数**で、
//! プロバイダにもストリームにも依存しない。
//!
//! ブロック種別（`Text` / `Thinking` / `ToolUse`引数）ごとに独立した[`StreamWatcher`]を持ち、
//! **混ぜない**。混ぜると「reasoningが長く回っている間に本文が少しだけ出る」正常な形が、
//! 合算では反復に見えてしまう。
//!
//! | # | 名前 | 判定 | ゲート |
//! |---|---|---|---|
//! | ① | 短周期反復 | 直近`window`文字の最小周期`p`が`p ≤ max_period`かつ`window/p ≥ min_repeats` | 不要（常時ON） |
//! | ② | 新規性率 | `window/2`ごとの区間で既出`n`-gram比率が`seen_ratio_max`超の状態が連続`min_hot_sections`区間続く | 常時評価（ゲートは必要区間数を変える） |
//! | ③ | 完走時の無産出 | `MaxTokens` ∧ `Text`合計0文字 ∧ `ToolUse`ゼロ | 不要（常時ON） |
//! | ④ | reasoning-only上限 | thinking累積 > `max_tokens × 4 × ratio` ∧ `Text`/`ToolUse`がまだ0 | 統計が温まっているときのみ |
//!
//! ②を「反復回数」ではなく「新規性率」で定義するのは、**正当な長文と縮退を長さでは区別できない**
//! ためである。正当な長文は最後まで新しい情報を出し続けるのに対し、縮退は新規性がゼロに漸近する。
//! 「長い」ではなく「新しいことを言わなくなった」を測ることで、正当な長文が通ることが式として保証される。
//!
//! **②は「単発の閾値超過」ではなく「連続した区間で超過し続けているか」を見る。** 単発判定は
//! 誤検知を避けるために閾値を高く（0.90）取らざるを得ず、コールドスタート時はさらに異常ゲートで
//! 評価そのものを遅らせる必要があった（BUG-087）。連続性を証拠として要求すると、それ自体が
//! 「これはループだ」の強い裏付けになるので、閾値を下げても誤検知は増えない。異常ゲートは
//! 「評価するかどうか」ではなく「何区間の連続を要求するか」を変える形に変わる。

use std::collections::HashMap;

use harness_core::DegenerateKind;

/// ①短周期反復の設定（§11.6 `degeneracy.short_period`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShortPeriodConfig {
    pub window: usize,
    pub max_period: usize,
    pub min_repeats: usize,
}

impl Default for ShortPeriodConfig {
    fn default() -> Self {
        Self {
            window: 512,
            max_period: 32,
            min_repeats: 8,
        }
    }
}

/// ②新規性率の設定（§11.6 `degeneracy.ngram`）。
///
/// `window`文字の窓を`window/2`ごとにずらしながら既出n-gram比率を測り、`seen_ratio_max`を
/// 超えた区間が`min_hot_sections`（ゲート開時は`min_hot_sections_suspect`）連続したら発火する。
/// 単発の閾値超過ではなく連続性を証拠にすることで、`seen_ratio_max`を0.90より低く取っても
/// 誤検知が増えない（BUG-087）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NgramConfig {
    pub window: usize,
    pub n: usize,
    pub seen_ratio_max: f64,
    /// 異常ゲートが閉じている（平常時）に必要な連続ホット区間数。
    pub min_hot_sections: usize,
    /// 異常ゲートが開いている（疑い状態）に必要な連続ホット区間数。平常時より少なくてよい。
    pub min_hot_sections_suspect: usize,
}

impl Default for NgramConfig {
    fn default() -> Self {
        Self {
            window: 1_024,
            n: 32,
            seen_ratio_max: 0.80,
            min_hot_sections: 6,
            min_hot_sections_suspect: 3,
        }
    }
}

/// 記憶するn-gramの上限。長い正常出力（数万文字）でも頭打ちにするための保険で、
/// 超えたら新しいn-gramの記録をやめる（既存の判定は続く＝検知が緩む方向にしか倒れない）。
const MAX_TRACKED_NGRAMS: usize = 65_536;

/// 検知器を評価する間隔（文字）。デルタごとに512/1024文字を再走査すると、
/// 1トークンずつ届くストリームでは二乗のコストになる。
///
/// 設定に出さないのは、これが**閾値ではなく実装上の刻み**だからである。ここを大きくすると
/// 発火が最大この文字数ぶん遅れるだけで、判定式そのものは変わらない。
const EVAL_STRIDE: usize = 64;

/// 1つのブロック種別に対する観測。文字を流し込み、①②の判定を返す。
///
/// 文字単位（`char`）で扱うのは、トークン概算も切詰めも文字数ベースだからで、
/// バイト数で数えると日本語で境界が壊れる（`harness_core::text::truncate_head_tail`と同じ理由）。
#[derive(Debug)]
pub struct StreamWatcher {
    short_period: ShortPeriodConfig,
    ngram: NgramConfig,
    /// 蓄積した全文字（最小周期・n-gramの両方が末尾からの窓を見る）。
    chars: Vec<char>,
    /// n-gramのハッシュ → 初出位置（gramの終端index、1始まり）。
    first_seen: HashMap<u64, usize>,
    /// `gram_hashes[i]` = 終端が `i + n` のn-gramのハッシュ。1文字追加ごとに1件伸びる。
    /// 判定のたびに窓ぶんを再ハッシュしないために持つ（②は64文字ごとに1024文字を見る）。
    gram_hashes: Vec<u64>,
    /// 次に評価する文字数のしきい。
    next_eval_at: usize,
    /// ②の次の区間境界（この文字数に達したら1区間分の既出率を測る）。`window`刻みで開始し、
    /// 以後`window/2`ずつ進む。
    next_section_at: usize,
    /// 直近まで連続してホット（既出率が`seen_ratio_max`超）だった区間数。
    hot_run: usize,
    /// 直近に測った区間の既出率（発火理由の文言・テストの観測点）。
    last_section_ratio: f64,
    /// これまでに測った区間既出率の最大値（テストで実測の余裕を固定する観測点）。
    max_section_ratio: f64,
}

impl StreamWatcher {
    pub fn new(short_period: ShortPeriodConfig, ngram: NgramConfig) -> Self {
        Self {
            short_period,
            ngram,
            chars: Vec::new(),
            first_seen: HashMap::new(),
            gram_hashes: Vec::new(),
            next_eval_at: EVAL_STRIDE,
            next_section_at: ngram.window,
            hot_run: 0,
            last_section_ratio: 0.0,
            max_section_ratio: 0.0,
        }
    }

    /// 直近に測った②の区間既出率。テスト・観測用。
    pub fn last_section_ratio(&self) -> f64 {
        self.last_section_ratio
    }

    /// これまでに測った②の区間既出率の最大値。テスト・観測用
    /// （誤検知してはならない入力が閾値へどれだけ余裕を持っているかを固定する）。
    pub fn max_section_ratio(&self) -> f64 {
        self.max_section_ratio
    }

    pub fn len(&self) -> usize {
        self.chars.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chars.is_empty()
    }

    /// 文字列を追加する。戻り値は**この時点で[`StreamWatcher::evaluate`]を呼ぶべきか**
    /// （`EVAL_STRIDE`の刻みで間引く）。
    ///
    /// 判定そのものを返さないのは、②の可否を決める異常ゲートが**追加した後の**出力量と
    /// 経過時間で決まるためである。「追加 → ゲートを引き直す → 評価」の順を呼び出し側
    /// （[`super::CallWatch`]）に強制する形にして、順序を取り違えられないようにしている。
    pub fn push(&mut self, text: &str) -> bool {
        if text.is_empty() {
            return false;
        }
        for ch in text.chars() {
            self.chars.push(ch);
            self.track_ngram();
        }
        if self.chars.len() < self.next_eval_at {
            return false;
        }
        self.next_eval_at = self.chars.len() + EVAL_STRIDE;
        true
    }

    /// 蓄積が止まった時点で明示的に評価する（`EVAL_STRIDE`の刻みで取りこぼした末尾ぶん）。
    ///
    /// `&mut self`なのは、②が区間境界を跨ぐたびに`hot_run`を更新する内部状態を持つため。
    pub fn evaluate(&mut self, gate_open: bool) -> Option<(DegenerateKind, String)> {
        if let Some(reason) = self.short_period_reason() {
            return Some((DegenerateKind::ShortPeriodRepeat, reason));
        }
        if let Some(reason) = self.novelty_reason(gate_open) {
            return Some((DegenerateKind::NoveltyCollapse, reason));
        }
        None
    }

    /// ① 直近`window`文字の最小周期が短く、かつ十分な回数繰り返されているか。
    fn short_period_reason(&self) -> Option<String> {
        let cfg = self.short_period;
        let window = cfg.window.min(self.chars.len());
        // 最低でも`max_period × min_repeats`文字は見ないと「8回繰り返した」と言えない。
        if window < cfg.max_period.saturating_mul(cfg.min_repeats).min(cfg.window) {
            return None;
        }
        let tail = &self.chars[self.chars.len() - window..];
        let p = min_period(tail);
        if p == 0 || p > cfg.max_period || window / p < cfg.min_repeats {
            return None;
        }
        Some(format!(
            "直近{window}文字の最小周期が{p}文字（{}回反復）",
            window / p
        ))
    }

    /// ② `window/2`ごとの区間で既出n-gram比率を測り、`seen_ratio_max`超が連続する区間数を数える。
    ///
    /// `gate_open`はホット区間の測定自体には関係しない（証拠はゲート状態に関係なく積む）。
    /// 使うのは「何区間連続したら発火とみなすか」の判定だけ——ゲートが閉じている平常時は
    /// より多くの連続を要求し、開いている疑い状態では少ない連続で発火させる。
    fn novelty_reason(&mut self, gate_open: bool) -> Option<String> {
        let cfg = self.ngram;
        // 窓を埋めるだけの分量が無いうちは判定しない（短い出力を誤って捕まえないため）。
        if cfg.n == 0 || cfg.window < cfg.n {
            return None;
        }
        // 大きなデルタが複数区間を跨いでも取りこぼさないよう、追いつくまで処理する。
        let step = (cfg.window / 2).max(1);
        while self.chars.len() >= self.next_section_at {
            let ratio = self.section_ratio(self.next_section_at, cfg.window, cfg.n);
            self.last_section_ratio = ratio;
            self.max_section_ratio = self.max_section_ratio.max(ratio);
            if ratio > cfg.seen_ratio_max {
                self.hot_run += 1;
            } else {
                self.hot_run = 0;
            }
            self.next_section_at += step;
        }
        let required = if gate_open {
            cfg.min_hot_sections_suspect
        } else {
            cfg.min_hot_sections
        };
        if required == 0 || self.hot_run < required {
            return None;
        }
        Some(format!(
            "直近{}文字中{}区間連続で既出率が{:.0}%を超えた（直近区間{:.0}%、{}-gram、閾値{:.0}%）",
            cfg.window,
            self.hot_run,
            cfg.seen_ratio_max * 100.0,
            self.last_section_ratio * 100.0,
            cfg.n,
            cfg.seen_ratio_max * 100.0
        ))
    }

    /// `end`文字目までの`window`文字窓における既出n-gram比率。
    fn section_ratio(&self, end: usize, window: usize, n: usize) -> f64 {
        let window_start = end.saturating_sub(window);
        if end < window_start + n {
            return 0.0;
        }
        let mut counted = 0usize;
        let mut seen = 0usize;
        for pos in (window_start + n)..=end {
            let hash = self.gram_hashes[pos - n];
            counted += 1;
            // `track_ngram`が全位置を記録済みなので、初出位置が今より前なら「既出」。
            if self.first_seen.get(&hash).is_some_and(|first| *first < pos) {
                seen += 1;
            }
        }
        if counted == 0 {
            return 0.0;
        }
        seen as f64 / counted as f64
    }

    /// 末尾で終わるn-gramのハッシュと初出位置を記録する（1文字追加ごとに1件）。
    fn track_ngram(&mut self) {
        let n = self.ngram.n;
        if n == 0 || self.chars.len() < n {
            return;
        }
        let end = self.chars.len();
        let hash = hash_ngram(&self.chars[end - n..end]);
        self.gram_hashes.push(hash);
        // 初出位置の表だけ頭打ちにする（`gram_hashes`は窓の判定に要るので必ず伸ばす）。
        // 超えた分は「未記録＝新規」として数えられるので、**検知が緩む方向にしか倒れない**。
        if self.first_seen.len() < MAX_TRACKED_NGRAMS {
            self.first_seen.entry(hash).or_insert(end);
        }
    }
}

/// 文字列の最小周期。KMPのfailure functionから `len - failure[len-1]` として求まる。
///
/// 周期が見つからない場合は`len`（＝非周期）を返す。空なら0。
pub fn min_period(s: &[char]) -> usize {
    let n = s.len();
    if n == 0 {
        return 0;
    }
    let mut fail = vec![0usize; n];
    let mut k = 0usize;
    for i in 1..n {
        while k > 0 && s[i] != s[k] {
            k = fail[k - 1];
        }
        if s[i] == s[k] {
            k += 1;
        }
        fail[i] = k;
    }
    n - fail[n - 1]
}

/// n-gramのハッシュ。衝突は「既出でないものを既出と誤判定する」方向に効くが、
/// 64bitで数万件なら実質起きない（誕生日限界まで遠い）。
fn hash_ngram(gram: &[char]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    gram.hash(&mut h);
    h.finish()
}

/// ③ 完走時の無産出（§11.1）。`MaxTokens`で終わったのに`Text`が0文字で`ToolUse`も無い。
///
/// **最後の砦**として常時ONで評価する。④が完走前に捕まえるので通常はここまで来ないが、
/// ④はゲート付きなので、平常時の出力量が大きい母集団では④が沈黙し得る。
pub fn no_output_at_max_tokens(
    stop_reason: &harness_core::StopReason,
    text_chars: usize,
    tool_use_blocks: usize,
) -> Option<(DegenerateKind, String)> {
    if *stop_reason != harness_core::StopReason::MaxTokens || text_chars > 0 || tool_use_blocks > 0 {
        return None;
    }
    Some((
        DegenerateKind::NoOutputAtMaxTokens,
        "出力上限に達したが本文もツール呼び出しも一切生成されなかった".to_string(),
    ))
}

/// ④ reasoning-only上限（§11.1）。thinkingだけが出力枠を食い潰している。
///
/// **これが③の穴を塞ぐ**——③は完走を待つので`max_tokens`を全消費する（4096ならローカル35Bで
/// 50–100秒）。④を入れると全経路が`max_tokens`より手前で切れるようになり、初めて
/// 「安い手段から順に登る」梯子（§11.3）が常に正当化される。
pub fn reasoning_only(
    thinking_chars: usize,
    text_chars: usize,
    tool_use_blocks: usize,
    max_tokens: u32,
    ratio: f32,
) -> Option<(DegenerateKind, String)> {
    if text_chars > 0 || tool_use_blocks > 0 {
        return None;
    }
    let limit = (f64::from(max_tokens) * 4.0 * f64::from(ratio)) as usize;
    if thinking_chars <= limit {
        return None;
    }
    Some((
        DegenerateKind::ReasoningOnly,
        format!(
            "thinkingが{thinking_chars}文字（出力枠の{:.0}%相当={limit}文字）に達したが本文もツール呼び出しも無い",
            f64::from(ratio) * 100.0
        ),
    ))
}

#[cfg(test)]
#[path = "detect_tests.rs"]
mod detect_tests;
