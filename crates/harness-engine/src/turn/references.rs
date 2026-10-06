//! ツール呼び出し1件の入力に対する**値の参照の処理**（D-113・D-115・D-116）。
//!
//! 順序は固定で、**判定の材料を作るより前**に行う（[`super::TurnExecutor::execute_tool_calls`]から呼ぶ）。
//!
//! 1. **書き写しの審査**（D-115）——モデルが番号を使わずに値を書き写していないか。損じていたら断る
//! 2. **断るか、素通りさせるか**——連続で断った回数が[`super::TRANSCRIPTION_REFUSAL_BYPASS_THRESHOLD`]に
//!    届いたら、カウンタを0に戻して素通りさせる（直せない形で詰まったときの無限ループ止め）
//! 3. **差し込み**（D-113）——番号を中身へ置き換える
//!
//! **審査は差し込みより前**でなければならない。差し込んだ後では、番号を正しく書いた呼び出しにも
//! 値が入っているので、書き写したものと区別できない。

use harness_core::{AgentEvent, ToolOutput};

use super::{
    CompletedToolCall, ToolCallDecision, TurnExecutor, TRANSCRIPTION_REFUSAL_BYPASS_THRESHOLD,
};
use crate::emit;

/// 値の参照の処理の結果。
pub(super) enum Screened {
    /// 損じた書き写しなので**実行しない**。履歴へ積む結果（理由をモデルへ返す）。
    Refused(Box<CompletedToolCall>),
    /// 審査を通った。番号を中身へ置き換えた後の入力で、判定・承認・実行はこれを見る。
    Proceed(serde_json::Value),
}

impl TurnExecutor<'_> {
    /// 1件のツール呼び出しの入力に、書き写しの審査と差し込みを掛ける（[モジュールdoc](self)の順序）。
    pub(super) fn screen_references(
        &self,
        id: &str,
        name: &str,
        input: &serde_json::Value,
        values: &harness_core::ValueStore,
    ) -> Screened {
        // モデルが参照の書き方を使わず**書き写していないか**を先に見る（D-115）。
        // **差し込みより前**に見る——差し込んだ後では、`{{user:1}}`と正しく書いた呼び出しにも
        // 値が入っているので、書き写したものと区別できなくなる。
        let references = values.texts();
        let transcriptions = harness_core::review_user_references(input, &references);
        let damaged = transcriptions.iter().find(|t| !t.is_exact());
        let bypass_damaged = damaged.is_some()
            && self
                .transcription_refusal_streak
                .load(std::sync::atomic::Ordering::Relaxed)
                + 1
                >= TRANSCRIPTION_REFUSAL_BYPASS_THRESHOLD;
        for t in &transcriptions {
            emit(
                self.events,
                AgentEvent::UserValueTranscribed {
                    value_chars: t.value_chars,
                    differences: t.differences,
                    refused: damaged.is_some() && !bypass_damaged,
                },
            );
        }
        if let Some(damaged) = damaged {
            if bypass_damaged {
                // 連続拒否の閾値に達した。**カウンタを0に戻して、この呼び出しは素通りさせる**
                // ——モデルは番号参照で書き直せない形で詰まっていて（`edit_file`の`old_string`等）、
                // 拒否を続けると無限ループになる。下流（コマンドの構文失敗・承認画面・ファイル照合）が
                // 本当に別物の実行を受けるので、ここで止め続ける意味は薄い。
                self.transcription_refusal_streak
                    .store(0, std::sync::atomic::Ordering::Relaxed);
                emit(
                    self.events,
                    AgentEvent::TranscriptionCheckBypassed {
                        value_chars: damaged.value_chars,
                        differences: damaged.differences,
                    },
                );
                // 素通りなので、下の正常な実行経路（差し込み→承認→実行）へ流す。
            } else {
                // **走らせない。** 壊れた写しは別のものを実行する命令なので、人に承認を聞く意味も無い。
                // 断った理由はツールの結果としてモデルへ返し、番号で書き直させる。
                self.transcription_refusal_streak
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Screened::Refused(Box::new(CompletedToolCall {
                    id: id.to_string(),
                    name: name.to_string(),
                    input: input.clone(),
                    output: ToolOutput {
                        // **一覧をそのまま渡して、どれを指すかはモデルに選ばせる**
                        // （ハーネスは「どれに近いか」までしか言えない。`Transcription::refusal_ja`）。
                        content: damaged.refusal_ja(&values.render().unwrap_or_default()),
                        is_error: true,
                    },
                    decision: ToolCallDecision::TranscribedValue,
                    subject: None,
                }));
            }
        }

        // **ユーザーの文の値を差し込むのはここ1か所だけ**（`harness_core::user_reference`）。危険度の判定・
        // 承認画面の材料・実際の実行・画面のカード、どれもこの後ろにあるので、**同じ文字列**を見る
        // （D-101「判定器が見る材料」と、走るものを食い違わせない）。
        Screened::Proceed(harness_core::substitute_user_references(input, &references))
    }
}
