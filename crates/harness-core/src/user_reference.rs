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
//! # 参照を使わずに書き写したときは、ハーネスが直す
//!
//! モデルは決まりを守らないことがある（実測: 2026-10-04、決まりを伝えた状態でも`qwen3.6-35b`は書き写した）。
//! そこで、**モデルが書いた長い値がユーザーの文の値とほぼ同じなら、ユーザーの値へ差し替える**（[`repair`]）。
//! 「ほぼ同じ」は、長さが同じで違う文字が[`MAX_REPAIR_RATIO`]以下のときだけである——**書き写しの損じだけを直し、
//! 別物を直さない**。直したことは呼び出し側へ返して承認画面に出す（黙って書き換えない）。
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

/// 書き写しの損じとして直してよい、違う文字の割合の上限。
///
/// **これを超える違いは直さない**——モデルが意図して別の値を書いた可能性があるから。308文字のうち1文字（0.3%）が
/// 実測の損じで、64文字短いもの（長さ違い）は直さない（長さが同じものだけを見る）。
pub const MAX_REPAIR_RATIO: f32 = 0.05;

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

/// モデルが書き写した値を、ユーザーの文の値へ直した記録（承認画面に出す）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repair {
    /// モデルが書いた値。
    pub written: String,
    /// 差し替えたユーザーの値。
    pub user_value: String,
    /// 違っていた文字の数。
    pub differences: usize,
}

/// ツールの入力の中の**書き写した値**を、ユーザーの文の値へ直す（[`substitute`]の後に通す）。
///
/// モデルが書いた長い値（空白を含まない[`MIN_REFERENCE_CHARS`]文字以上）が、ユーザーの文の値と**長さが同じで、
/// 違う文字が[`MAX_REPAIR_RATIO`]以下**なら差し替える。直した記録を返す（承認画面に出すため）。
pub fn repair(input: &Value, values: &[String]) -> (Value, Vec<Repair>) {
    let mut repairs = Vec::new();
    let out = repair_value(input, values, &mut repairs);
    (out, repairs)
}

fn repair_value(input: &Value, values: &[String], repairs: &mut Vec<Repair>) -> Value {
    match input {
        Value::String(text) => Value::String(repair_text(text, values, repairs)),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| repair_value(v, values, repairs))
                .collect(),
        ),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(k, v)| (k.clone(), repair_value(v, values, repairs)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// 1つの文字列の中の長い語を、ユーザーの値へ直す（空白で割って語ごとに見る）。
fn repair_text(text: &str, values: &[String], repairs: &mut Vec<Repair>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        // 空白はそのまま写し、語だけを見る（元の空白の並びを崩さない）。
        let word_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let (word, after) = rest.split_at(word_end);
        match mended(word, values) {
            Some((value, differences)) => {
                repairs.push(Repair {
                    written: word.to_string(),
                    user_value: value.clone(),
                    differences,
                });
                out.push_str(&value);
            }
            None => out.push_str(word),
        }
        let space_end = after
            .find(|c: char| !c.is_whitespace())
            .unwrap_or(after.len());
        out.push_str(&after[..space_end]);
        rest = &after[space_end..];
    }
    out
}

/// `word`が書き写しの損じなら、直した値と違っていた文字の数。直さないなら`None`。
fn mended(word: &str, values: &[String]) -> Option<(String, usize)> {
    let length = word.chars().count();
    if length < MIN_REFERENCE_CHARS {
        return None;
    }
    values
        .iter()
        .filter(|value| value.chars().count() == length && *value != word)
        .map(|value| {
            let differences = value
                .chars()
                .zip(word.chars())
                .filter(|(a, b)| a != b)
                .count();
            (value.clone(), differences)
        })
        .filter(|(_, differences)| (*differences as f32) <= length as f32 * MAX_REPAIR_RATIO)
        .min_by_key(|(_, differences)| *differences)
}

#[cfg(test)]
#[path = "user_reference_tests.rs"]
mod tests;
