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
//! 「ほぼ同じ」は、**文字を足す・消す・書き換える回数の合計**（レーベンシュタイン距離）が
//! [`MAX_REPAIR_RATIO`]以下のときだけである——**書き写しの損じだけを直し、別物を直さない**。
//! 直したことは呼び出し側へ返して承認画面に出す（黙って書き換えない）。
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

/// 書き写しの損じとして直してよい、違いの割合の上限（ユーザーの値の長さに対して）。
///
/// 違いの数え方は**文字を足す・消す・書き換える回数の合計**（レーベンシュタイン距離）で、
/// **長さが変わる損じも数えられる**——実測の損じは308文字のうち「1文字消して1文字書き換えた」（2回、0.6%）だった。
///
/// **これを超える違いは直さない**——モデルが意図して別の値を書いた可能性があるから。実測のもう一方の型
/// （64文字短い＝20%）はここで落ちる。
pub const MAX_REPAIR_RATIO: f32 = 0.05;

/// 直す対象として見る、空白で区切った1語の長さの上限（文字）。
///
/// 探す費用は「語の長さ × 値の長さ」で増えるので、際限なく長い語は見ない。モデルの出力は1回の応答の
/// 上限で頭打ちになるため、**実際にここへ当たることはほぼ無い**（当たった語は直さずそのまま走る）。
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
/// モデルが書いた長い値（空白を含まない[`MIN_REFERENCE_CHARS`]文字以上）が、ユーザーの文の値と
/// **[`MAX_REPAIR_RATIO`]以下の違い**しか無いなら差し替える。直した記録を返す（承認画面に出すため）。
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
            Some((repaired, repair)) => {
                repairs.push(repair);
                out.push_str(&repaired);
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

/// `word`の中でユーザーの値に最も近い部分を差し替えた語と、その記録。直すものが無ければ`None`。
///
/// **語まるごとを比べてはいけない。** モデルは値の前後に自分で飾りを付ける（`payload=`・引用符・
/// `--enc=`）ので、まるごと比べると飾りごと値へ置き換わり、**飾りが消えたコマンドが走る**。
/// 実際に通しの試験が1本これで赤くなった（`payload={{user:1}}`の`payload=`が剥がれた）。
fn mended(word: &str, values: &[String]) -> Option<(String, Repair)> {
    let written: Vec<char> = word.chars().collect();
    if written.len() > MAX_SCANNED_WORD_CHARS {
        return None;
    }
    let mut best: Option<(usize, usize, usize, &String)> = None;
    for value in values {
        let user_value: Vec<char> = value.chars().collect();
        // **上限はユーザーの値の長さで決める。** モデルが短く切り詰めても基準が動かない。
        let limit = (user_value.len() as f32 * MAX_REPAIR_RATIO) as usize;
        if user_value.len() < MIN_REFERENCE_CHARS || written.len() + limit < user_value.len() {
            continue; // 短すぎて入らない
        }
        let Some((differences, start, end)) = closest_region(&written, &user_value, limit) else {
            continue;
        };
        // 違いが0＝値がそのまま入っている。直すものは無い（飾りが付いていてもここで落ちる）。
        if differences > 0 && best.is_none_or(|(d, ..)| differences < d) {
            best = Some((differences, start, end, value));
        }
    }
    let (differences, start, end, value) = best?;
    let mut repaired: String = written[..start].iter().collect();
    repaired.push_str(value);
    repaired.extend(&written[end..]);
    Some((
        repaired,
        Repair {
            written: written[start..end].iter().collect(),
            user_value: value.clone(),
            differences,
        },
    ))
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
