//! Ollaya（選択肢を選ぶ判定モデルのサーバ）への接続。承認画面の危険度判定に使う
//! （`harness_core::risk_check`）。
//!
//! # なぜ`LlmProvider`ではないのか
//!
//! Ollaya は文章を作らない。`/api/chat`・`/api/generate`は「判定モデルは文章を作らない。
//! `POST /api/decide`を使え」と拒否される（2026-10-04の実測）。だから OpenAI 互換の
//! [`OpenAiProvider`](crate::OpenAiProvider)では呼べず、`stream()`の形にも合わない。
//!
//! # 呼び方
//!
//! `POST {base_url}/api/decide`、本文は`{"model":…,"preset":"agent","state":"<コマンド1行>"}`。
//! 返りの`answers.risk.score`（0〜2）だけを読む。**同じ応答の`action`・`destructive`は使わない**——
//! 実測で`mimikatz`は destructive が「無」でも最も危険な部類で、`action`の確率は揺れる
//! （同じ入力が ask と block に割れた）が、`risk`の数値は2群にきれいに割れた。
//!
//! # 待ちの上限
//!
//! 接続は1秒で諦める（サーバが無いときに承認画面を待たせない）。応答全体は60秒で諦める
//! （モデルの読み込みに、`decider:0.8b` で約11秒、`winnow:e4b`（8GB）はそれ以上かかり得る）。上限を超えたら`Err`で、呼び出し側は
//! 判定が無かったものとして今までどおり進める。

use std::time::Duration;

use async_trait::async_trait;
use harness_core::{RiskCheck, RiskCheckError, RiskVerdict};
use serde::Deserialize;

/// 接続を諦める時間。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
/// 応答全体を諦める時間（モデルの初回の読み込み込み）。
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Ollaya の判定設定の名前。コマンドを判定する設定（`GET /api/presets`の`agent`）。
const PRESET: &str = "agent";

/// Ollaya の判定クライアント。
pub struct DecideClient {
    http: reqwest::Client,
    url: String,
    model: String,
}

impl DecideClient {
    /// `base_url`は`http://127.0.0.1:11435`のような形（末尾の`/`は有っても無くてもよい）。
    pub fn new(base_url: &str, model: &str) -> Result<Self, String> {
        let base = base_url.trim().trim_end_matches('/');
        if base.is_empty() {
            return Err("risk_base_url が空".to_string());
        }
        if model.trim().is_empty() {
            return Err("risk_model が空".to_string());
        }
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| format!("HTTPクライアントを作れなかった: {e}"))?;
        Ok(Self {
            http,
            url: format!("{base}/api/decide"),
            model: model.trim().to_string(),
        })
    }

    /// 画面とログに出す出どころ（どこへコマンドが出たのかが後から分かるように）。
    pub fn label(&self) -> String {
        format!("ollaya / {}", self.model)
    }
}

#[derive(Deserialize)]
struct DecideResponse {
    answers: Answers,
}

#[derive(Deserialize)]
struct Answers {
    risk: RiskAnswer,
}

#[derive(Deserialize)]
struct RiskAnswer {
    score: f64,
}

/// 応答の本文から危険度を取り出す。**純関数**（HTTP を伴わない試験のために切ってある）。
pub fn parse_risk(body: &str) -> Result<RiskVerdict, RiskCheckError> {
    let parsed: DecideResponse = serde_json::from_str(body).map_err(|e| {
        RiskCheckError(format!(
            "判定モデルの応答を読めなかった（answers.risk.score が無い）: {e}"
        ))
    })?;
    RiskVerdict::from_score(parsed.answers.risk.score as f32)
}

#[async_trait]
impl RiskCheck for DecideClient {
    async fn assess(&self, command_line: &str) -> Result<RiskVerdict, RiskCheckError> {
        let body = serde_json::json!({
            "model": self.model,
            "preset": PRESET,
            "state": command_line,
        });
        let response = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                RiskCheckError(format!("判定モデルへ繋げなかった（{}）: {e}", self.url))
            })?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| RiskCheckError(format!("判定モデルの応答を読み切れなかった: {e}")))?;
        if !status.is_success() {
            // 本文はサーバの自由文なので、長さを切って理由へ入れる（画面には出ず、1回だけ記録へ出る）。
            let head: String = text.chars().take(200).collect();
            return Err(RiskCheckError(format!(
                "判定モデルがエラーを返した（HTTP {status}）: {head}"
            )));
        }
        parse_risk(&text)
    }
}

#[cfg(test)]
#[path = "decide_tests.rs"]
mod decide_tests;
