//! ユーザーが書いた長い値を、モデルに**書き写させず参照させる**仕組み。
//!
//! # 何のためにあるのか
//!
//! モデルは、ユーザーの文を読んで自分でコマンドを組み立て直す。そのとき長い値（符号化された塊・ハッシュ・鍵）を
//! **書き写すと、1文字でも違えば別のものが走る**。実測（2026-10-04、ローカルの`qwen3.6-35b`・4回）では、308文字の
//! base64 を4回とも写し損じた——1文字違いが2回、64文字短いものが2回。1文字違った値は`systeminfo`ではなく
//! `sDsteminfo`を走らせる命令になっていた。
//!
//! だから**書き写させない**。モデルが書くのは「ユーザーの文の何番目の長い値か」だけで、**その値を取り出して
//! 差し込むのはハーネス**である。
//!
//! ```text
//! ユーザー: pwsh --enc cAB3AHMAaAAg……（308文字）
//! モデル:   run_shell { command: "pwsh --enc {{user:1}}" }
//! ハーネス: pwsh --enc cAB3AHMAaAAg……（ユーザーの文から取り出してそのまま差し込む）
//! ```
//!
//! # 差し込んだ後の文字列が、判定にも実行にも使われる
//!
//! 差し込みは**判定の材料を作るより前**に1か所で行う（`harness_engine::turn`）。だから承認画面に出る文字列・
//! 判定器が照合する文字列・実際に走る文字列は同じものである（D-101「判定器が見る材料」を崩さない）。
//!
//! # 書き写した値は走らせない
//!
//! モデルは決まりを守らないことがある（実測: 2026-10-04、決まりを伝えた状態でも`qwen3.6-35b`は書き写した）。
//! そこで、**モデルが書いた長い値がユーザーの文の値を写したものだと分かったら、損じている限り実行しない**
//! （[`review`]）。断ったことはツールの結果としてモデルへ返し、番号で書き直させる。
//!
//! | モデルが書いたもの | ハーネスの動き |
//! |---|---|
//! | ユーザーの値と**一字一句同じ** | そのまま走らせる（会話の記録に1行残す） |
//! | 値を写したが**損じている** | **走らせない。** ツールの結果でモデルへ理由を返す |
//! | どの値とも**似ていない** | そのまま走らせる（モデルが自分で作った値） |
//!
//! **「損じを直して走らせる」という扱いは採らない**（2026-10-04に一度入れて外した）。直す側に回すと
//! 「どこからが別物か」の線引きが残り、線の外側——実測では308文字のうち64文字（20.8%）が落ちた形——が
//! 黙って走る。**断る側に倒すと、壊れた写しが走らないことが機構として成り立つ。**
//!
//! # ここが守らないもの
//!
//! - **差し込めなかったときは、書いた綴りがそのまま残る**（勝手に消さない）。承認画面にも`{{user:1}}`が見えるので、
//!   人は「モデルが指した値が無い」と分かって断れる。黙って空文字へ畳むと、別のコマンドが静かに走る
//! - **参照できるのは、長い値を含む直近のユーザーの文1つだけ**。それより前の文・ツールの出力・ファイルの中身は
//!   参照できない（モデルはそれらを書き写すしかなく、この仕組みでは守れない）
//! - **差し込む中身はユーザー自身が書いたもの**である。中身がコマンドの意味を変えること（`; rm -rf /`）は
//!   止めない——止めるのは承認画面と判定器の仕事で、人は差し込んだ後の文字列を見て決める

use serde_json::Value;

use crate::{Message, Role};

/// モデルが書いた語を「ユーザーの値を写したもの」とみなす、違いの割合の上限
/// （ユーザーの値の長さに対して）。
///
/// 違いの数え方は**文字を足す・消す・書き換える回数の合計**（レーベンシュタイン距離）で、
/// **長さが変わる損じも数えられる**。実測（2026-10-04）の2つの損じは2回（0.6%）と64回（20.8%）で、
/// どちらもこの内側に入る。
///
/// **これを超える違いは写しとみなさない**——モデルが自分で作った別の値として素通りさせる。
/// 無関係な値がここへ入ることは実質無い: 40文字の16進の値を2つ並べても違いは37回前後（92%）になる。
pub const MAX_TRANSCRIPTION_RATIO: f32 = 0.5;

/// 審査の対象として見る、空白で区切った1語の長さの上限（文字）。
///
/// 探す費用は「語の長さ × 値の長さ」で増えるので、際限なく長い語は見ない。モデルの出力は1回の応答の
/// 上限で頭打ちになるため、**実際にここへ当たることはほぼ無い**（当たった語は審査せずそのまま走る）。
const MAX_SCANNED_WORD_CHARS: usize = 65_536;

/// 参照できる「長い値」とみなす最短の長さ（文字）。空白を含まない連なりで数える。
///
/// **短い値は対象にしない**——`-Force`のような普通の語まで参照の対象にすると、モデルが番号を数え間違える余地が増える。
/// 書き写しで事故が起きるのは、人が目で照合できない長さの値である。
pub const MIN_REFERENCE_CHARS: usize = 40;

/// モデルへ伝える書き方（システムプロンプトと、ここの取り出しが同じ綴りを見る）。
pub const SYNTAX_EXAMPLE: &str = "{{user:1}}";

/// `messages`から、モデルが参照できる値を取り出す（並び順が番号になる。1つ目が`{{user:1}}`）。
///
/// **長い値を含む直近のユーザーの文1つ**だけを見る。前の文まで通して数えると、文脈の圧縮（古い文を畳む）で
/// 番号がずれて、別の値が差し込まれる。
pub fn values_in(messages: &[Message]) -> Vec<String> {
    messages
        .iter()
        .rev()
        .filter(|m| m.role == Role::User)
        .map(|m| long_values(&text_of(m)))
        .find(|values| !values.is_empty())
        .unwrap_or_default()
}

/// 1つの文に出てくる長い値（出てきた順）。
fn long_values(text: &str) -> Vec<String> {
    text.split_whitespace()
        .filter(|word| word.chars().count() >= MIN_REFERENCE_CHARS)
        .map(str::to_string)
        .collect()
}

/// メッセージの文字の中身（文字でないブロックは無視する）。
fn text_of(message: &Message) -> String {
    message
        .content
        .iter()
        .filter_map(|block| match block {
            crate::ContentBlock::Text(text) => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// ツールの入力の**すべての文字列**の中の`{{user:N}}`を、`values`のN番目（1始まり）へ置き換える。
///
/// 置き換えるのは番号が在るものだけで、**無い番号はそのまま残す**（モジュールdoc「守らないもの」）。
pub fn substitute(input: &Value, values: &[String]) -> Value {
    match input {
        Value::String(text) => Value::String(substitute_text(text, values)),
        Value::Array(items) => Value::Array(items.iter().map(|v| substitute(v, values)).collect()),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(k, v)| (k.clone(), substitute(v, values)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// 1つの文字列の中の`{{user:N}}`を置き換える。
fn substitute_text(text: &str, values: &[String]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("{{user:") {
        let (before, from_marker) = rest.split_at(at);
        out.push_str(before);
        let after_marker = &from_marker["{{user:".len()..];
        let Some(end) = after_marker.find("}}") else {
            // 閉じていない。これ以降は綴りとして残す。
            out.push_str(from_marker);
            return out;
        };
        let (number, after) = (&after_marker[..end], &after_marker[end + "}}".len()..]);
        match number
            .parse::<usize>()
            .ok()
            .filter(|n| *n >= 1)
            .and_then(|n| values.get(n - 1))
        {
            Some(value) => out.push_str(value),
            // 番号が無い・数でない: 書いた綴りをそのまま残す（人が承認画面で見て気付ける）。
            None => out.push_str(&from_marker[..="{{user:".len() + end + 1]),
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// モデルがユーザーの値を**書き写していた**という審査の結果1件（[`review`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transcription {
    /// 何番目のユーザーの値を写したか（1始まり。`{{user:N}}`のN）。
    pub number: usize,
    /// モデルが書いた部分の長さ（文字）。
    pub written_chars: usize,
    /// ユーザーの値の長さ（文字）。
    pub value_chars: usize,
    /// 違いの回数（足す・消す・書き換えるの合計）。**0なら一字一句同じ。**
    pub differences: usize,
}

impl Transcription {
    /// 一字一句同じか。`false`なら**そのツール呼び出しを実行してはいけない**。
    pub fn is_exact(&self) -> bool {
        self.differences == 0
    }

    /// 参照の書き方（`{{user:N}}`）。
    pub fn reference(&self) -> String {
        format!("{{{{user:{}}}}}", self.number)
    }

    /// 実行を断ったことを**モデルへ**伝える文（ツールの結果として返す）。
    ///
    /// 何が違ったかを数で言い、次に何を書けばよいかを1つだけ示す——曖昧に断ると、モデルは
    /// 同じ値をもう一度書き写す。
    pub fn refusal_ja(&self) -> String {
        let reference = self.reference();
        format!(
            "書き写した値は実行しません。あなたが書いた{written}文字の値は、ユーザーが書いた\
             {value}文字の値と{differences}文字分違います（足す・消す・書き換えるの合計）。\
             1文字でも違えば別のものが走るので、値を書き写さずに {reference} と書いてください。\
             ハーネスがユーザーの文からその値を取り出して差し込みます。",
            written = self.written_chars,
            value = self.value_chars,
            differences = self.differences,
        )
    }
}

/// ツールの入力の中に、ユーザーの値を**書き写した**跡が無いかを調べる。
///
/// **[`substitute`]より前に通すこと。** 差し込んだ後では、参照の書き方を正しく使った呼び出しにも
/// 値が入っているので、「モデルが書き写した」と区別できなくなる。
///
/// [`Transcription::is_exact`]が`false`のものが1つでもあれば、呼び出し側は**そのツール呼び出しを
/// 実行してはいけない**。一字一句同じものは走らせてよい（記録には残す）。
pub fn review(input: &Value, values: &[String]) -> Vec<Transcription> {
    let mut found = Vec::new();
    review_value(input, values, &mut found);
    found
}

fn review_value(input: &Value, values: &[String], found: &mut Vec<Transcription>) {
    match input {
        Value::String(text) => {
            for word in text.split_whitespace() {
                if let Some(t) = transcription_of(word, values) {
                    found.push(t);
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|v| review_value(v, values, found)),
        Value::Object(fields) => fields.values().for_each(|v| review_value(v, values, found)),
        _ => {}
    }
}

/// `word`がどのユーザーの値を写したものか。写していないなら`None`。
///
/// **語まるごとを比べてはいけない。** モデルは値の前後に自分で飾りを付ける（`payload=`・引用符・
/// `--enc=`）ので、まるごと比べると飾りの分まで違いに数え、短い値では写しを見落とす。
/// だから[`closest_region`]で**語の中の、値に当たる部分だけ**を見る。
fn transcription_of(word: &str, values: &[String]) -> Option<Transcription> {
    let written: Vec<char> = word.chars().collect();
    if written.len() > MAX_SCANNED_WORD_CHARS {
        return None;
    }
    let mut best: Option<Transcription> = None;
    for (index, value) in values.iter().enumerate() {
        let user_value: Vec<char> = value.chars().collect();
        // **上限はユーザーの値の長さで決める。** モデルが短く切り詰めても基準が動かない。
        let limit = (user_value.len() as f32 * MAX_TRANSCRIPTION_RATIO) as usize;
        if user_value.len() < MIN_REFERENCE_CHARS || written.len() + limit < user_value.len() {
            continue; // 短すぎて入らない
        }
        let Some((differences, start, end)) = closest_region(&written, &user_value, limit) else {
            continue;
        };
        if best.as_ref().is_none_or(|b| differences < b.differences) {
            best = Some(Transcription {
                number: index + 1,
                written_chars: end - start,
                value_chars: user_value.len(),
                differences,
            });
        }
    }
    best
}

/// `word`の中で`value`に最も近い部分を探し、`(違いの回数, 始まり, 終わり)`を返す。
/// `limit`を超えると分かった時点で`None`。
///
/// 違いの数え方は**文字を足す・消す・書き換える回数の合計**（レーベンシュタイン距離）である。
/// **書き換えだけを数えると、1文字消す損じを拾えない**——消すと以降が1つずつずれるので、
/// 残り全部が「違う文字」に見えて上限を大きく超える（実測で実際にこれが起きた）。
///
/// `value`は全部使い、`word`は**前後を自由に飛ばせる**（飾りの分）。表を1行ずつ進め、
/// 各マスに「その並べ方が`word`の何文字目から始まったか」を一緒に持ち回る。
fn closest_region(word: &[char], value: &[char], limit: usize) -> Option<(usize, usize, usize)> {
    let n = word.len();
    // `value`を0文字使った段は、`word`のどこから始めても違い0（前の飾りは飛ばしてよい）。
    let mut prev_cost: Vec<usize> = vec![0; n + 1];
    let mut prev_start: Vec<usize> = (0..=n).collect();
    let (mut cost, mut start) = (vec![0usize; n + 1], vec![0usize; n + 1]);
    for (i, cv) in value.iter().enumerate() {
        cost[0] = i + 1;
        start[0] = 0;
        for (j, cw) in word.iter().enumerate() {
            let same = prev_cost[j] + usize::from(cv != cw); // 書き換えるか、一致
            let drop_value = prev_cost[j + 1] + 1; // `value`の文字が`word`から消えている
            let drop_word = cost[j] + 1; // `word`に余計な文字がある
            if same <= drop_value && same <= drop_word {
                (cost[j + 1], start[j + 1]) = (same, prev_start[j]);
            } else if drop_value <= drop_word {
                (cost[j + 1], start[j + 1]) = (drop_value, prev_start[j + 1]);
            } else {
                (cost[j + 1], start[j + 1]) = (drop_word, start[j]);
            }
        }
        // 違いは段をまたいで減らないので、この段の最小が上限を超えたら以降も超える。
        if cost.iter().min().is_some_and(|m| *m > limit) {
            return None;
        }
        std::mem::swap(&mut prev_cost, &mut cost);
        std::mem::swap(&mut prev_start, &mut start);
    }
    // 違いが同じなら**`word`を長く使う方**を採る。`a`が並んだだけの値では「末尾の1文字を書き換えた」と
    // 「末尾の1文字を余らせた」が同じ違いの回数になり、後者を採ると余った文字が語に残る。
    (0..=n)
        .map(|j| (prev_cost[j], prev_start[j], j))
        .filter(|(differences, ..)| *differences <= limit)
        .min_by_key(|(differences, _, j)| (*differences, std::cmp::Reverse(*j)))
}

#[cfg(test)]
#[path = "user_reference_tests.rs"]
mod tests;
