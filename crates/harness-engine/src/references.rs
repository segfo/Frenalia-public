//! 値の置き場（`harness_core::value_store`）を会話の文から組み立てる（D-116・D-127）。
//!
//! 置き場そのもの（番号・一覧の文面）は`harness-core`にあり、ここは**解読の段に番号を付ける**ところだけを
//! 持つ——解読に使う関数（`harness_tools::encoded_command::decode_shell_line`）が`harness-tools`にあり、
//! `harness-core`からは見えないため。
//!
//! # 組み立ては1か所
//!
//! モデルへ一覧を見せる段（[`crate::build_request`]）と、番号を中身へ置き換える段（[`crate::turn`]）が
//! **同じ会話の文で[`References::from_messages`]を呼ぶ**ので、モデルが見た番号と差し込まれる値が
//! 食い違わない。中身は`messages`だけで決まるので、2回呼んでも同じものが返る。
//! ここを通らずに番号を振る経路を作らないこと。
//!
//! # 「本物の会話か」はここで持つ
//!
//! 会話を読む道具（`past_requests`）へ会話を渡してよいのは、置き場を**本物の会話**から組んだときだけである。
//! その事実は[`References::from_conversation`]で組んだときにだけ立つ（[`References::conversation`]が`Some`）。
//! [`References::from_messages`]は送る文から組むだけで、それが会話かどうかを知らないので立てない
//! ——認知レイヤーは作業記憶から組み直した文を送るので、それを会話として読ませてはいけない
//! （D-127「認知レイヤーの経路は未決」）。どちらで組むかを決めるのは`crate::turn::RawTurnRequest`の作り方である。
//!
//! # ここが守らないもの
//!
//! - **前の文の置き場は、会話に残っている人の文の数だけ毎ターン作り直す（上限なし）。** 長い値の無い文は
//!   語を分けるだけで済むが、長い値のある文は毎回解読し直す。その費用は測っていない
//! - **畳まれた文の値は指せない**（元の文が会話から消えている。`harness_core::human_turns`）

use std::sync::Arc;

use harness_core::human_turns::{human_turns, nth_back};
use harness_core::{Message, ReferenceBook, SystemBlock, ValueStore};

/// 1つの人の文から置き場を組む。ユーザーの文の長い値に加え、**ハーネスが機械で解けた解読の段にも
/// 番号を付ける**ので、モデルは中の層も番号で指せる（`pwsh --enc {{val:2}}` のように）。
///
/// 解読に使うのは `run_shell` の行と同じ関数（`harness_tools::encoded_command::decode_shell_line`）で、
/// 承認画面に出る段と**同じ解き方**である。読めなかった段（符号化でなかった・上限に当たった）は
/// 番号を取らない——中身の無いものを指せても意味が無い。
pub fn store_for_text(text: &str) -> ValueStore {
    use harness_core::DecodeOutcome;

    let mut store = ValueStore::from_user_values(harness_core::user_reference::long_values(text));
    // 元の値それぞれを解いて、読めた段に番号を付ける。`depth`は1から始まり、深い段の親は
    // 1つ浅い段である（親の番号を`depth`ごとに控えて引き継ぐ）。
    for number in 1..=store.len() {
        let Some(text) = store.get(number).map(|v| v.text.clone()) else {
            continue;
        };
        let mut parent: Vec<usize> = vec![number];
        for layer in harness_tools::encoded_command::decode_shell_line(&text) {
            let DecodeOutcome::Text { encoding, text } = &layer.outcome else {
                continue;
            };
            let depth = layer.depth as usize;
            let Some(from) = parent.get(depth - 1).copied() else {
                continue; // 浅い段が読めていない（親を特定できない）
            };
            let at = store.push_decoded(from, encoding.name(), text.clone());
            if parent.len() <= depth {
                parent.resize(depth + 1, at);
            }
            parent[depth] = at;
        }
    }
    store
}

/// 人が書いた直近の文の置き場（`{{val:N}}`が指すもの）。値が無ければ空。
///
/// 前の文の置き場も要るなら[`References::from_messages`]を使う。
pub fn value_store_for(messages: &[Message]) -> ValueStore {
    nth_back(messages, 0)
        .map(|turn| store_for_text(turn.text))
        .unwrap_or_default()
}

/// 1ターンぶんの値の置き場（人の文ごと。D-127）。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct References {
    pub book: ReferenceBook,
    /// 置き場を組んだ会話。**本物の会話から組んだときだけ`Some`**（[モジュールdoc](self)）。外からは書けない。
    conversation: Option<Arc<[Message]>>,
}

impl References {
    /// 送る文から組む。人が書いた文（`harness_core::human_turns`）を新しい順に1つずつ置き場にする
    /// ——直近の文が`{{val:N}}`、その1つ前が`{{back:1:N}}`、…。ツールの結果の文と畳んだ要約の文は数えない。
    ///
    /// `messages`が会話そのものかは知らないので、会話は持たない（[`References::conversation`]は`None`）。
    pub fn from_messages(messages: &[Message]) -> Self {
        let mut stores = human_turns(messages)
            .into_iter()
            .rev()
            .map(|turn| store_for_text(turn.text));
        let current = stores.next().unwrap_or_default();
        Self {
            book: ReferenceBook {
                current,
                back: stores.collect(),
            },
            conversation: None,
        }
    }

    /// **本物の会話**から組む。置き場は[`References::from_messages`]と同じで、加えて会話を持つので、
    /// 会話を読む道具（`Tool::call_in_conversation`）へ渡せる。
    ///
    /// `messages`が会話そのものだと**呼び出し側が知っているときだけ**使う（素朴ループのターン、
    /// または会話から置き場を組んで`RawTurnRequest::with_references`で渡す呼び出し側）。
    /// 会話を1回写すので、その分の費用がかかる（送る文の写しと同じ大きさ）。
    pub fn from_conversation(messages: &[Message]) -> Self {
        Self {
            conversation: Some(Arc::from(messages)),
            ..Self::from_messages(messages)
        }
    }

    /// 置き場を組んだ会話。本物の会話から組んでいなければ`None`。
    pub fn conversation(&self) -> Option<&[Message]> {
        self.conversation.as_deref()
    }

    /// システムプロンプトの2つめの塊として送る一覧（`harness_core::ReferenceBook::render_menu`）。
    /// 並べるのは直近の文の値だけ。何も無ければ`None`。
    ///
    /// **`cache: false`。** 中身がターンごとに変わるので、送り直しを前提にする
    /// （1つめの塊＝環境の事実は変わらないので、そちらの使い回しは壊さない）。
    pub fn menu_block(&self) -> Option<SystemBlock> {
        self.book
            .render_menu()
            .map(|text| SystemBlock { text, cache: false })
    }
}

#[cfg(test)]
#[path = "references_tests.rs"]
mod tests;
