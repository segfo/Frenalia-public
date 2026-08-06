//! 「ツール呼び出しが構造化フィールドではなく**本文テキスト**として出た」の検出（純粋）。
//! 発端は[BUG-079](../../../../docs/bugs/BUG-079.md)。
//!
//! # 何を直すのか
//!
//! `run_agent_loop`は`tool_calls`が空なら「モデルは喋っただけ」と見てターンを正常終了させる。
//! ところがローカルモデルは、テンプレートの都合で呼び出しを`<tool_call>…`のような**本文**として
//! 吐くことがある。するとハーネスから見て差し戻す`tool_result`も無く、**エージェントの作業が
//! そこで止まる**（ユーザーからは「推論が止まった」に見える）。
//!
//! # テキストは引き金にしか使わない
//!
//! **本文からツール名も引数も取らないし、実行もしない。** ここが返すのは「やり直させるか否か」の
//! 真偽値（と、何を見て判定したかのマーカー）だけである。実行されるのは、通知付きで再送した結果
//! モデルが**構造化フィールドで出し直した**呼び出しだけで、それは通常の許可ゲートを通る。
//!
//! 本文を解釈して実行する方式を採らないのは、それが**プロンプトインジェクションの増幅器**に
//! なるからである。`read_file`したファイルの中身に`<tool_call>`が書いてあり、モデルがそれを
//! 引用しただけでも呼び出しが成立してしまう。allowlist運用や`--dangerously-allow`では自動で通る。
//!
//! # 誤検出の扱い
//!
//! 検出自体は本文の影響を受ける（引用でも当たる）。被害はLLMコール1本と、その試行の表示の
//! 巻き戻しだけで、実行は起きない。それでも「モデルがツール呼び出しの書き方を説明していた」
//! ケースで答えを失わないよう、**再送は1回だけ**にして、2回目は本文をそのまま答えとして
//! 受け入れる（呼び出し側`turn::TurnExecutor`の責務）。

use harness_core::ContentBlock;

/// 本文に混じった「ツール呼び出しの体裁」の目印。
///
/// 意図的に**列挙**にしてある（正規表現で緩く拾わない）。誤検出のコストは無駄なコール1本、
/// 見逃しのコストは従来どおりターンが止まるだけなので、増やすのは実際に踏んだ形を確認してから。
///
/// | 目印 | 出どころ |
/// |---|---|
/// | `<tool_call>` | Qwen / Hermes 系のテンプレート |
/// | `<function=` | この開発機で実測（[BUG-079](../../../../docs/bugs/BUG-079.md)、`<function=write_file>`） |
/// | `<tool_use>` | Anthropic風XMLを覚えたfine-tune |
/// | `<invoke name=` | 同上 |
/// | `<\|tool_call\|>` | 特殊トークン形式が素通しされた場合 |
/// | `<\|python_tag\|>` | Llama 3.1系のツール構文 |
pub(crate) const MARKERS: &[&str] = &[
    "<tool_call>",
    "<function=",
    "<tool_use>",
    "<invoke name=",
    "<|tool_call|>",
    "<|python_tag|>",
];

/// 本文テキストへ混じったツール呼び出しを検出する。当たった目印を返す。
///
/// 条件は2つ。**`ToolUse`ブロックが1つも無い**こと（1つでもあれば正規の経路が動いているので
/// 触らない）と、`Text`ブロックに[`MARKERS`]のいずれかが現れること。
///
/// `Thinking`は見ない。モデルが思考の中で呼び出しの形を書くのは普通のことで、そこで反応すると
/// 正常なターンを何度も捨てることになる。
pub(crate) fn detect(content: &[ContentBlock]) -> Option<&'static str> {
    if content
        .iter()
        .any(|b| matches!(b, ContentBlock::ToolUse { .. }))
    {
        return None;
    }
    content.iter().find_map(|block| match block {
        ContentBlock::Text(text) => MARKERS.iter().copied().find(|m| text.contains(m)),
        _ => None,
    })
}

/// 再送時にモデルへ伝える文面。**何が起きたか・どうすればよいか・繰り返すなを**この順で書く。
///
/// 付け方（`req.system`末尾の非キャッシュブロック）は`degeneracy::ladder::append_notice`が持つ
/// ——`messages`側へ足すとrole交替が崩れ、キャッシュ済みブロックを書き換えるとprompt cacheが
/// 全ミスする、という既に検証済みの制約があるため、経路は1つに寄せている。
pub(crate) const NOTICE: &str = "直前の応答は、ツール呼び出しをメッセージ本文の中に書いていた\
（例: `<tool_call>`・`<function=…>`）。**本文に書かれた呼び出しは実行されない**ため、その応答は\
破棄した。ツールを使うときは、必ずAPIのツール呼び出し機構（tool_calls）で呼び出すこと。\
同じ内容を本文へ書き写さないこと。";

#[cfg(test)]
mod tests {
    use super::*;

    fn text(s: &str) -> ContentBlock {
        ContentBlock::Text(s.to_string())
    }

    fn tool_use() -> ContentBlock {
        ContentBlock::ToolUse {
            id: "call_1".into(),
            name: "write_file".into(),
            input: serde_json::json!({}),
        }
    }

    /// BUG-079の実測（2枚目のスクリーンショットの本文をそのまま縮めたもの）。
    #[test]
    fn the_observed_function_form_is_detected() {
        let content = vec![text(
            "バグファイルが68件あります。\n\n<tool_call>\n<function=write_file>\n\
             <parameter=path>\ntmp/collect_bugs.ps1\n</parameter>\n</function>\n</tool_call>",
        )];
        assert_eq!(detect(&content), Some("<tool_call>"));
    }

    #[test]
    fn every_marker_is_detected() {
        for marker in MARKERS {
            let content = vec![text(&format!("説明します。\n{marker}write_file")); 1];
            assert_eq!(detect(&content), Some(*marker), "{marker}");
        }
    }

    /// **`ToolUse`が1つでもあれば触らない。** 正規の経路が動いているので、本文に体裁が残って
    /// いても（モデルが呼び出しを説明しながら実際にも呼んだ場合）やり直させる理由が無い。
    #[test]
    fn a_real_tool_use_suppresses_the_detection() {
        let content = vec![text("これから呼びます: <tool_call>"), tool_use()];
        assert_eq!(detect(&content), None);
    }

    /// 思考（`Thinking`）の中の体裁は見ない。呼び出しの形を考えるのは普通のことで、
    /// ここで反応すると正常なターンを捨て続ける。
    #[test]
    fn a_marker_inside_thinking_is_ignored() {
        let content = vec![
            ContentBlock::Thinking {
                text: "<tool_call> と書けばいいのかな".into(),
                signature: None,
            },
            text("結論だけ書きます。"),
        ];
        assert_eq!(detect(&content), None);
    }

    #[test]
    fn ordinary_text_is_not_detected() {
        let content = vec![text("バグカタログの傾向は次の3点です。1) …")];
        assert_eq!(detect(&content), None);
        assert_eq!(detect(&[]), None);
    }
}
