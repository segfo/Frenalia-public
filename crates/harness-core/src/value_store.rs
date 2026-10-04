//! ハーネスが持っている長い値の置き場。**モデルは中身を書かず、番号で指す。**
//!
//! # 何のためにあるのか
//!
//! モデルは長い値（符号化された塊・ハッシュ・鍵）を**書き写すと間違える**。実測（2026-10-04、
//! ローカルの`qwen3.6-35b`・5回）では308文字の base64 を5回とも書き写し、2回損じた——1回は
//! 1文字消して1文字書き換え、もう1回は2か所まとめて64文字落とした。
//!
//! だから**値そのものをモデルに運ばせない**。中身はハーネスが持ち、モデルが書くのは番号だけにする。
//! これは認知レイヤーの分業（`plans/DESIGN-COGNITION.md` §0。解釈はモデル、事実と制御と記憶はハーネス）を
//! `run_shell`の経路へ当てたものである。
//!
//! ```text
//! ユーザー: pwsh --enc cAB3AHMAaAAg……（308文字）
//! ハーネス: 置き場へ入れて番号を付ける → {{val:1}}
//!           モデルへは「308文字・あなたの文から」とだけ伝える（中身は渡さない）
//! モデル:   run_shell { command: "pwsh --enc {{val:1}}" }
//! ハーネス: 番号を中身へ置き換えて実行する
//! ```
//!
//! # 中身をモデルへ渡さない
//!
//! [`ValueStore::render`]が組む文面には**値の中身が1文字も入らない**。長さ・出どころ・符号化の種類だけである。
//!
//! 理由は2つ。**(1)** 渡せば書き写せてしまい、この仕組みを置いた意味が消える。
//! **(2)** 解読した中身は**攻撃者が書いたかもしれないデータ**で、この文面はシステムプロンプト——
//! モデルが最も信用する位置——に載る。そこへ外から来た文字列を置かない。
//!
//! **限界**: だからモデルは、符号化された中身が何であるかを知らないまま実行を提案する。
//! 危ないかどうかを決めるのは**判定モデルと、承認画面を見る人**である（D-100「要約は補助であって境界ではない」）。
//! 人には承認画面でハーネスが解読した各段が見えている。
//!
//! # ここが守らないもの
//!
//! - **番号はこのターン限り。** 毎ターン作り直すので、前のターンの番号は当てにならない
//!   （文脈の圧縮で古い文が畳まれると、同じ番号が別の値を指してしまうため）
//! - **ユーザーの文に無い値は置けない。** ツールの出力・ファイルの中身は、モデルが書き写すしかない

use crate::Message;

/// 値の中身を文面へ載せるかの上限（文字）。**0である**——[モジュールdoc](self)のとおり、
/// 中身は一切載せない。定数として置いてあるのは、将来ここを動かすときに1か所で済ませるため。
pub const MAX_INLINE_VALUE_CHARS: usize = 0;

/// 置き場にある値1つ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredValue {
    /// 中身。**モデルへは渡らない**（[`ValueStore::render`]は長さしか書かない）。
    pub text: String,
    /// どこから来たか。
    pub origin: Origin,
}

/// 値の出どころ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// ユーザーの文に書かれていた。
    UserMessage,
    /// ハーネスが解読した。
    Decoded {
        /// 元の値の番号（1始まり）。
        from: usize,
        /// 符号化の種類の名前（`base64`等）。
        encoding: String,
    },
}

/// ハーネスが持っている値の一覧。**毎ターン作り直す。**
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValueStore {
    values: Vec<StoredValue>,
}

impl ValueStore {
    /// ユーザーの文から取り出した長い値で組む（[`crate::user_reference::values_in`]の結果）。
    pub fn from_user_values(values: Vec<String>) -> Self {
        Self {
            values: values
                .into_iter()
                .map(|text| StoredValue {
                    text,
                    origin: Origin::UserMessage,
                })
                .collect(),
        }
    }

    /// ハーネスが解読した結果を足し、その番号（1始まり）を返す。
    ///
    /// **同じ中身が既にあるなら足さず、その番号を返す**——同じ値に2つの番号が付くと、モデルが
    /// どちらを指しても同じものが走るのに一覧だけが膨らむ。
    pub fn push_decoded(
        &mut self,
        from: usize,
        encoding: impl Into<String>,
        text: String,
    ) -> usize {
        if let Some(at) = self.values.iter().position(|v| v.text == text) {
            return at + 1;
        }
        self.values.push(StoredValue {
            text,
            origin: Origin::Decoded {
                from,
                encoding: encoding.into(),
            },
        });
        self.values.len()
    }

    /// 差し込み・審査へ渡す中身の列（並びが番号になる。1つ目が`{{val:1}}`）。
    pub fn texts(&self) -> Vec<String> {
        self.values.iter().map(|v| v.text.clone()).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// 1つ引く（番号は1始まり）。
    pub fn get(&self, number: usize) -> Option<&StoredValue> {
        self.values.get(number.checked_sub(1)?)
    }

    /// モデルへ見せる文面。置き場が空なら`None`。
    ///
    /// **中身は1文字も載せない**（[モジュールdoc](self)）。載せるのは番号・長さ・出どころだけである。
    pub fn render(&self) -> Option<String> {
        if self.values.is_empty() {
            return None;
        }
        let mut out = String::from(
            "ハーネスが次の値を持っています。コマンドの中にこれらの値を書き写さず、\
             番号で指してください（ハーネスが中身へ置き換えます）。中身は渡していません——\
             符号化された中身は承認画面で人が見ます。\n",
        );
        for (index, value) in self.values.iter().enumerate() {
            let chars = value.text.chars().count();
            let origin = match &value.origin {
                Origin::UserMessage => "ユーザーの文から".to_string(),
                Origin::Decoded { from, encoding } => {
                    let shape = if reads_as_command_line(&value.text) {
                        "。空白を含むのでコマンド行1本として読める（符号化された塊ではない）"
                    } else {
                        ""
                    };
                    format!("{{{{val:{from}}}}} を {encoding} として解読したもの{shape}")
                }
            };
            out.push_str(&format!(
                "  {{{{val:{}}}}} {chars}文字・{origin}\n",
                index + 1
            ));
        }
        Some(out)
    }
}

/// 解読した中身が**コマンド行として読めるか**（空白を含む1行以上の文字か）。
///
/// **これはモデルが番号の使い方を決めるための手がかりである。** 中身は渡さないので、
/// `{{val:2}}` が「符号化された塊」なのか「コマンド行1本」なのかがモデルに分からない。
/// 実測（2026-10-04）では、`pwsh --enc <塊>` を解読した結果（＝コマンド行1本）をモデルが
/// `--enc` の引数として渡し、**`pwsh --enc pwsh --enc <塊>` という走らない行**を組み立てた。
///
/// **中身は1文字も出さない。** 先頭の語を出せばもっと親切になるが、そこから中身が漏れる
/// （値が「`secretpassword` …」で始まっていたら、その語が一覧に出てしまう）。
/// モデルが要るのは「塊ではない」という1つの事実だけである。
fn reads_as_command_line(text: &str) -> bool {
    text.contains(char::is_whitespace)
}

/// `messages`から置き場を組む（解読の段は呼び出し側が[`ValueStore::push_decoded`]で足す）。
///
/// **毎ターン作り直す。** ここを通らずに番号を振る経路を作らないこと——番号の付け方が2つになると、
/// モデルが指した番号と差し込まれる値が食い違う。
pub fn from_messages(messages: &[Message]) -> ValueStore {
    ValueStore::from_user_values(crate::user_reference::values_in(messages))
}

#[cfg(test)]
#[path = "value_store_tests.rs"]
mod tests;
