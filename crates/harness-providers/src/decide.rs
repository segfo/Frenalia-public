//! Ollaya（問いに確率や点数で答える判定モデルのサーバ）への接続。承認画面の危険度判定に使う
//! （問いの文と聞き方は`harness_core::decision`）。
//!
//! # なぜ`LlmProvider`ではないのか
//!
//! Ollaya は文章を作らない。`/api/chat`・`/api/generate`は「判定モデルは文章を作らない。
//! `POST /api/decide`を使え」と拒否される（2026-10-04の実測）。だから OpenAI 互換の
//! [`OpenAiProvider`](crate::OpenAiProvider)では呼べず、`stream()`の形にも合わない。
//!
//! # 呼び方
//!
//! `POST {base_url}/api/decide`、本文は`{"model":…,"state":{…},"questions":{"<id>":{type・instructions・criteria}}}`。
//! **問いはその場で渡す**——Ollaya の設定（preset）を登録しないので、使う側のマシンの Ollaya に手を入れずに済む。
//! 返りの`answers.<id>`と`state_truncated`を[`Answers`]へ入れて返し、どの欄を読むかは問いの側（`decision::questions`）が決める。
//!
//! 以前は組み込みの`agent`設定で聞き、`answers.risk.score`だけを読んでいた。同じ応答の`action`・`destructive`は
//! 使わなかった（実測で`mimikatz`は destructive が「無」でも最も危険な部類で、`action`の確率は揺れた）。
//!
//! # 待ちの上限
//!
//! 接続は1秒で諦める（サーバが無いときに承認画面を待たせない）。応答全体は60秒で諦める
//! （モデルの読み込みに、`decider:0.8b` で約11秒、`winnow:e4b`（8GB）はそれ以上かかり得る）。上限を超えたら`Err`で、呼び出し側は
//! 判定が無かったものとして今までどおり進める。

use std::time::Duration;

use async_trait::async_trait;
use harness_core::{Answers, DecisionModel, Question, RiskCheckError};
use serde::Deserialize;
use serde_json::Value;

/// 接続を諦める時間。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
/// 応答全体を諦める時間（モデルの初回の読み込み込み）。
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

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
    answers: serde_json::Map<String, Value>,
    #[serde(default)]
    state_truncated: bool,
}

/// 応答の本文から答えを取り出す。**純関数**（HTTP を伴わない試験のために切ってある）。
/// 欄が足りるかは読む側（`decision::questions::read_*`）が見て、足りなければ`Err`にする。
pub fn parse_answers(body: &str) -> Result<Answers, RiskCheckError> {
    let parsed: DecideResponse = serde_json::from_str(body).map_err(|e| {
        RiskCheckError(format!(
            "判定モデルの応答を読めなかった（answers が無い）: {e}"
        ))
    })?;
    Ok(Answers::new(
        Value::Object(parsed.answers),
        parsed.state_truncated,
    ))
}

/// 送る本文。問いは`id`を鍵にした1つのオブジェクトにする（Ollaya の`questions`の形）。
fn request_body(model: &str, state: &Value, questions: &[Question]) -> Value {
    let questions: serde_json::Map<String, Value> = questions
        .iter()
        .map(|q| (q.id.to_string(), q.spec.clone()))
        .collect();
    serde_json::json!({ "model": model, "state": state, "questions": questions })
}

#[async_trait]
impl DecisionModel for DecideClient {
    async fn decide(
        &self,
        state: &Value,
        questions: &[Question],
    ) -> Result<Answers, RiskCheckError> {
        let body = request_body(&self.model, state, questions);
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
        parse_answers(&text)
    }
}

#[cfg(test)]
#[path = "decide_tests.rs"]
mod decide_tests;
