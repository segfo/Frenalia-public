//! 値を番号で指す書き方の**唯一の読み手**（D-113・D-116・D-127）。
//!
//! | 書き方 | 指すもの |
//! |---|---|
//! | `{{val:N}}` | 人が書いた直近の文の置き場の N 番目 |
//! | `{{user:N}}` | 同じ（`{{val:N}}`より前の綴り。文脈に残っているものを無言で落とさないために読み続ける） |
//! | `{{back:K:N}}` | 人が書いた文を新しい方から数えて K 個前（1 が1つ前の文）の置き場の N 番目 |
//!
//! K も N も1始まりで、数字だけで書く。置き場（何番に何が入っているか）は[`crate::value_store`]が持ち、
//! ここは**綴りを読むことだけ**を持つ——差し込み・書き換え・番号の数え上げが同じ読み方をするように、
//! 綴りを読む処理を2つ持たない。
//!
//! # 読めない綴りは、書いたまま残す
//!
//! `{{back:2}}`（N が無い）・`{{back:0:1}}`（0 は使わない）・`{{val:x}}`（数でない）・`{{val:1`（閉じていない）、
//! そして**読めても置き場に無い番号**は、書いた綴りのまま残す。黙って空へ畳むと別のコマンドが静かに走る。
//! 残った綴りは承認画面に見えるので、人は「モデルが指した値が無い」と分かって断れる。

use serde_json::Value;

/// 指す先の値1つ（`{{val:N}}`・`{{back:K:N}}`を読んだもの）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ValueRef {
    /// 人が書いた文を新しい方から数えて何個前か。**0 が直近の文**（`{{val:N}}`）。
    pub back: usize,
    /// その文の置き場の何番目か（1始まり）。
    pub number: usize,
}

impl ValueRef {
    /// 直近の文の`number`番目（`{{val:N}}`）。
    pub fn current(number: usize) -> Self {
        Self { back: 0, number }
    }

    /// 正の綴り。直近の文なら`{{val:N}}`、それより前なら`{{back:K:N}}`。
    pub fn spelling(&self) -> String {
        if self.back == 0 {
            format!("{{{{val:{}}}}}", self.number)
        } else {
            format!("{{{{back:{}:{}}}}}", self.back, self.number)
        }
    }
}

/// モデルへ伝える前の文の書き方の例（システムプロンプトと、ここの読み手が同じ綴りを見る）。
pub const BACK_SYNTAX_EXAMPLE: &str = "{{back:1:1}}";

/// 直近の文を指す綴りの頭（`{{val:`が正、`{{user:`は古い別名）。
const CURRENT_HEADS: [&str; 2] = ["{{val:", "{{user:"];
/// 前の文を指す綴りの頭。
const BACK_HEAD: &str = "{{back:";
const CLOSE: &str = "}}";

/// 文字列を「そのままの部分」と「参照」に割った1切れ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Piece<'a> {
    /// 参照ではない部分（読めない綴りもここに入る）。
    Text(&'a str),
    /// 読めた参照と、書かれていた綴りそのもの。
    Reference {
        reference: ValueRef,
        written: &'a str,
    },
}

/// `text`を前から読み、そのままの部分と参照に割る。連結すれば`text`に戻る。
pub fn pieces(text: &str) -> Vec<Piece<'_>> {
    let mut out = Vec::new();
    let (mut literal_from, mut at) = (0, 0);
    while let Some(found) = text[at..].find("{{") {
        let start = at + found;
        match parse_at(&text[start..]) {
            Some((reference, len)) => {
                if literal_from < start {
                    out.push(Piece::Text(&text[literal_from..start]));
                }
                out.push(Piece::Reference {
                    reference,
                    written: &text[start..start + len],
                });
                at = start + len;
                literal_from = at;
            }
            // 読めない。`{`1文字ぶんだけ進めて探し直す（`{{{val:1}}`の内側は読める）。
            None => at = start + 1,
        }
    }
    if literal_from < text.len() {
        out.push(Piece::Text(&text[literal_from..]));
    }
    out
}

/// `text`の先頭にある参照1つを読む。読めたら`(参照, 綴りの長さ)`。
fn parse_at(text: &str) -> Option<(ValueRef, usize)> {
    let (reference, rest) = if let Some(rest) = CURRENT_HEADS
        .iter()
        .find_map(|head| text.strip_prefix(head))
    {
        let (number, rest) = leading_number(rest)?;
        (ValueRef::current(number), rest)
    } else {
        let rest = text.strip_prefix(BACK_HEAD)?;
        let (back, rest) = leading_number(rest)?;
        let (number, rest) = leading_number(rest.strip_prefix(':')?)?;
        if back == 0 {
            return None; // 0 個前は`{{val:N}}`で書く（2通りの綴りを作らない）
        }
        (ValueRef { back, number }, rest)
    };
    let rest = rest.strip_prefix(CLOSE)?;
    if reference.number == 0 {
        return None; // 番号は1始まり
    }
    Some((reference, text.len() - rest.len()))
}

/// 先頭の数字の並び（1文字以上）を数として読む。桁あふれは読めない扱い。
fn leading_number(text: &str) -> Option<(usize, &str)> {
    let end = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    if end == 0 {
        return None;
    }
    Some((text[..end].parse().ok()?, &text[end..]))
}

/// 1つの文字列の中の参照を、`resolve`が返す中身へ置き換える。`resolve`が`None`を返した参照は
/// **書いた綴りのまま残す**（[モジュールdoc](self)）。
pub fn substitute_text<F>(text: &str, resolve: &mut F) -> String
where
    F: FnMut(ValueRef) -> Option<String>,
{
    let mut out = String::with_capacity(text.len());
    for piece in pieces(text) {
        match piece {
            Piece::Text(t) => out.push_str(t),
            Piece::Reference { reference, written } => match resolve(reference) {
                Some(value) => out.push_str(&value),
                None => out.push_str(written),
            },
        }
    }
    out
}

/// ツールの入力の**すべての文字列**（配列・オブジェクトの中も）に[`substitute_text`]を掛ける。
pub fn substitute<F>(input: &Value, resolve: &mut F) -> Value
where
    F: FnMut(ValueRef) -> Option<String>,
{
    match input {
        Value::String(text) => Value::String(substitute_text(text, resolve)),
        Value::Array(items) => Value::Array(items.iter().map(|v| substitute(v, resolve)).collect()),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(k, v)| (k.clone(), substitute(v, resolve)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// 参照を`k`個前へずらして書き直す——`{{val:N}}`・`{{user:N}}`は`{{back:k:N}}`へ、
/// `{{back:j:N}}`は`{{back:k+j:N}}`へ。読めない綴りはそのまま。
///
/// **用途**: `k`個前の文の返事でモデルが書いたツール呼び出しを、今の文から見た綴りへ読み替える。
/// 会話にはモデルが書いたまま（`{{val:1}}`）残っている（D-113）ので、そのまま見せると**今の文の**
/// 1番目を指してしまう（D-127 の3）。`k`が0なら綴りを正の形（`{{val:N}}`）へ揃えるだけ。
pub fn rewrite_relative(text: &str, k: usize) -> String {
    let mut out = String::with_capacity(text.len());
    for piece in pieces(text) {
        match piece {
            Piece::Text(t) => out.push_str(t),
            Piece::Reference { reference, .. } => out.push_str(
                &ValueRef {
                    back: reference.back + k,
                    number: reference.number,
                }
                .spelling(),
            ),
        }
    }
    out
}

#[cfg(test)]
#[path = "reference_syntax_tests.rs"]
mod tests;
