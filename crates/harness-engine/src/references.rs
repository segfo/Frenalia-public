//! 値の置き場（`harness_core::value_store`）を会話の文から組み立てる（D-116）。
//!
//! 置き場そのもの（番号・一覧の文面）は`harness-core`にあり、ここは**解読の段に番号を付ける**ところだけを
//! 持つ——解読に使う関数（`harness_tools::encoded_command::decode_shell_line`）が`harness-tools`にあり、
//! `harness-core`からは見えないため。

/// 会話の文から**値の置き場**を組む（D-116）。ユーザーの文の長い値に加え、**ハーネスが機械で
/// 解けた解読の段にも番号を付ける**ので、モデルは中の層も番号で指せる
/// （`pwsh --enc {{val:2}}` のように）。
///
/// **組み立てはこの関数の1か所だけを通すこと。** モデルへ一覧を見せる段（[`crate::build_request`]）と、
/// 番号を中身へ置き換える段（[`crate::turn`]）が同じ会話の文でこれを呼ぶので、**モデルが見た番号と
/// 差し込まれる値が食い違わない**。中身は`messages`だけで決まるので、2回呼んでも同じものが返る。
///
/// 解読に使うのは `run_shell` の行と同じ関数（`harness_tools::encoded_command::decode_shell_line`）で、
/// 承認画面に出る段と**同じ解き方**である。読めなかった段（符号化でなかった・上限に当たった）は
/// 番号を取らない——中身の無いものを指せても意味が無い。
pub fn value_store_for(messages: &[harness_core::Message]) -> harness_core::ValueStore {
    use harness_core::DecodeOutcome;

    let mut store = harness_core::value_store_for(messages);
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
