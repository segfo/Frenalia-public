//! 回復の梯子（`plans/DESIGN-COGNITION.md` §11.3）。**外へ`Discarded`を返すのは使い切ったときだけ**。
//!
//! | 段 | 内容 | 位置づけ |
//! |---|---|---|
//! | (a) | 同一リクエストを素で再送 | **採らない**。`temperature=0`では決定的に同じ結果になる |
//! | (b) | サンプリングを揺らして再送 | 第1段（[`Rung::Jitter`]） |
//! | (c) | (b) に加え、反復に陥った旨を`req.system`末尾へ伝える | 第2段（[`Rung::JitterWithNotice`]） |
//! | (d) | `LlmProvider::recycle`でモデルを再ロードして再送 | 第3段（既定OFF、[`Rung::Recycle`]） |
//! | (e) | 上位tierのモデルへエスカレーション | **枠のみ。M17（ModelRouter）待ち** |
//! | (f) | `RawTurnResult::Discarded`を返す | fail-closed（[`Rung::Exhausted`]） |
//!
//! # 進行規則は「段数」ではなく「無駄に燃やした量」で決める
//!
//! 回復予算は§11.2の移動統計を再利用し、新しい定数を1つも増やさない。
//!
//! ```text
//! budget = median_elapsed(model, max_tokens) × recovery_multiplier
//! 現在の段を最大 ATTEMPTS_PER_RUNG 回まで試す → 次の段へ
//! budget を使い切ったら → 最終段 (d) へジャンプ（無効なら即 (f)）
//! ```
//!
//! 意味は「平常なら10秒で返る種類のコールに、回復まで含めて30秒以上かけない」。①で7秒ずつ
//! 切れているなら (b) を数回試せ、④で50秒燃えたなら即座に再ロードへ落ちる、という自己調整が
//! そのまま得られる。
//!
//! **中央値が取れないコールドスタート時は壁時計予算を課さず、段数だけで進む**（設計§11.3は
//! この場合を定義していない。段数自体が有限なので停止性は保たれる）。

use std::time::Duration;

use harness_core::{CompletionRequest, SystemBlock};

/// 1つの段を何回まで試すか（§11.3「現在の段を最大2回まで試す」）。
const ATTEMPTS_PER_RUNG: u32 = 2;

/// (b) 段の温度の刻み。試行ごとにこれだけ上げる。
const TEMPERATURE_STEP: f32 = 0.2;

/// `sampling.temperature`が未設定のときに仮定する基準値。
///
/// ハーネスは通常`temperature`を送らず、推論サーバ側の既定（多くの実装で0.7〜0.8）に任せている。
/// (b)段は「決定的に同じ結果を避ける」ことが目的なので、未設定なら**平均的な既定値を仮定して
/// そこから上げる**。0から上げると、サーバ既定より低い温度になって逆効果になり得る。
const ASSUMED_BASE_TEMPERATURE: f32 = 0.7;

/// (b) 段で投入するペナルティ。反復そのものを抑える方向のパラメタで、
/// **OpenAI系にしか写らない**（`harness_core::Sampling`のdoc参照）。
const FREQUENCY_PENALTY: f32 = 0.4;
const PRESENCE_PENALTY: f32 = 0.4;

/// 梯子の段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rung {
    /// (b) サンプリングを揺らして再送。
    Jitter,
    /// (c) (b) に加え、反復に陥った旨を`req.system`末尾の非キャッシュブロックで伝える。
    JitterWithNotice,
    /// (d) モデルを再ロードして再送（既定OFF）。
    Recycle,
    /// (f) 使い切った。`RawTurnResult::Discarded`を返す。
    Exhausted,
}

impl Rung {
    /// イベント（`AgentEvent::TurnDiscarded.next_rung`）とログに出す安定した名前。
    pub fn as_str(self) -> &'static str {
        match self {
            Rung::Jitter => "jitter",
            Rung::JitterWithNotice => "jitter_with_notice",
            Rung::Recycle => "recycle",
            Rung::Exhausted => "exhausted",
        }
    }
}

/// 梯子の現在位置。1回のターンにつき1つ作る。
#[derive(Debug)]
pub struct Ladder {
    rung: Rung,
    attempts_on_rung: u32,
    /// 回復に使ってよい壁時計時間。`None`なら統計が無いので時間では打ち切らない。
    budget: Option<Duration>,
    /// これまでの再送で燃やした時間の合計。
    burned: Duration,
    /// (d) 段が使えるか（`auto_recycle` かつプロバイダが対応）。
    recycle_enabled: bool,
}

impl Ladder {
    /// `budget`は`median_elapsed × recovery_multiplier`。統計が無ければ`None`。
    pub fn new(budget: Option<Duration>, recycle_enabled: bool) -> Self {
        Self {
            rung: Rung::Jitter,
            attempts_on_rung: 0,
            budget,
            burned: Duration::ZERO,
            recycle_enabled,
        }
    }

    pub fn current(&self) -> Rung {
        self.rung
    }

    /// 縮退を1回踏んだ。`elapsed`はその試行が燃やした時間。**次に登る段**を返す。
    ///
    /// 戻り値が[`Rung::Exhausted`]なら、これ以上再送せず`Discarded`を返す。
    pub fn advance(&mut self, elapsed: Duration) -> Rung {
        self.burned = self.burned.saturating_add(elapsed);
        self.attempts_on_rung += 1;

        // 予算を使い切ったら最終段（(d)）へジャンプする。「(b)を丁寧に2回試す」より
        // 「もう手遅れなので一番強い手を打つか諦める」方が速いという判断（§11.3）。
        if self.budget.is_some_and(|b| self.burned >= b) {
            self.rung = self.last_resort();
            self.attempts_on_rung = 0;
            return self.rung;
        }

        // (d) は1回試したら終わり。再ロードしてなお縮退するなら、もう一度再ロードしても同じで、
        // そのたびに他セッションの推論を巻き添えにする（§11.5）。ここだけ試行回数が1。
        if self.rung != Rung::Recycle && self.attempts_on_rung < ATTEMPTS_PER_RUNG {
            return self.rung;
        }

        self.attempts_on_rung = 0;
        self.rung = match self.rung {
            Rung::Jitter => Rung::JitterWithNotice,
            Rung::JitterWithNotice => self.last_resort(),
            Rung::Recycle | Rung::Exhausted => Rung::Exhausted,
        };
        self.rung
    }

    /// 予算切れ・(c)の次に来る段。(d)が使えなければ即 (f)。
    fn last_resort(&self) -> Rung {
        if self.recycle_enabled {
            Rung::Recycle
        } else {
            Rung::Exhausted
        }
    }
}

/// 段に応じてリクエストを書き換える。
///
/// `attempt`は**そのターンで何回目の再送か**（1始まり）。温度の刻みに使う。
///
/// **`TurnExecutor`は会話履歴を持たない**ので、ここが触るのは`req`のコピーだけで、
/// **履歴は一切汚れない**。
pub fn apply(req: &mut CompletionRequest, rung: Rung, attempt: u32) {
    match rung {
        Rung::Jitter => jitter(req, attempt),
        Rung::JitterWithNotice => {
            jitter(req, attempt);
            append_notice(req, REPETITION_NOTICE);
        }
        // (d) はリクエストを触らない（モデル側をリセットしてから素の再送を行う）。
        // ただし決定的な同一結果を避けるため、揺らしは残す。
        Rung::Recycle => jitter(req, attempt),
        Rung::Exhausted => {}
    }
}

fn jitter(req: &mut CompletionRequest, attempt: u32) {
    let base = req.sampling.temperature.unwrap_or(ASSUMED_BASE_TEMPERATURE);
    // 上限を設けるのは、温度を上げ続けると別種の壊れ方（意味を成さない出力）になるため。
    req.sampling.temperature = Some((base + TEMPERATURE_STEP * attempt as f32).min(1.5));
    req.sampling.frequency_penalty = Some(FREQUENCY_PENALTY);
    req.sampling.presence_penalty = Some(PRESENCE_PENALTY);
}

/// (c) 段の文面。
const REPETITION_NOTICE: &str = "直前の応答は同じ内容の反復に陥り、有意な出力に到達しないまま\
破棄された。今回は反復を避け、簡潔に、結論から書くこと。同じ文・同じ語の連続を出さないこと。";

/// 再送時の通知を載せる**唯一の場所**。`req.system`の末尾に新しい非キャッシュブロックを足す。
///
/// 既存の`cache:true`ブロックのテキストを書き換えるとプロンプトキャッシュが無効化される（§6.5）。
/// 末尾に非キャッシュブロックを足せばキャッシュ済みプレフィクスは保たれる。
/// `messages`側に足すとrole交替が崩れる危険がある。
///
/// 呼び出しは2つ。(c)段の反復通知（[`REPETITION_NOTICE`]）と、本文へツール呼び出しを書いた
/// ときの通知（`turn::text_tool_call::NOTICE`、[BUG-079](../../../../docs/bugs/BUG-079.md)）。
/// **後者は縮退ではない**が、「壊れた応答を捨てて通知付きで再送する」という形は同じなので、
/// この制約付きの足し方を2箇所へ書き写さない。
pub(crate) fn append_notice(req: &mut CompletionRequest, text: &str) {
    req.system.push(SystemBlock {
        text: text.to_string(),
        cache: false,
    });
}

#[cfg(test)]
#[path = "ladder_tests.rs"]
mod ladder_tests;
