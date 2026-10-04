//! 1行のシェルの文字列を、語と区切りへ割る（PowerShell の読み方に寄せる）。
//!
//! 承認画面の解読（[`crate::encoded_command`]）と、システムへの被害の機械判定
//! （[`crate::system_damage`]）が**同じこの割り方**を使う——割り方を2箇所に持つと、
//! 片方だけ直されて静かにずれる（`B-13`。[BUG-222](../../../docs/bugs/BUG-222.md) は
//! 同じ形の一覧を2箇所に持っていた）。
//!
//! `approval_binding`の`shell_tokens`（字面に出るファイルを縛るための割り方）とは別に持つ。
//! あちらは引用符の中まで割る——約束が逆なので1つへ畳まない（[`crate::encoded_command`]のモジュールdoc）。

/// 文の区切りの種類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Separator {
    /// `;`・`&`・`&&`・`||`・改行。ここで文が終わる。
    Statement,
    /// `|`（1つだけ）。前のコマンドの出力を次のコマンドへ渡す。**ここで引数は終わるが、文としては続く**
    /// ——`Get-ChildItem C:\Windows | Remove-Item`の消す先は、パイプの前に書いてある。
    Pipe,
}

/// 行を割った語1つ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Word {
    /// 引用符を剥がした中身。
    pub(crate) text: String,
    /// 引用符で囲まれた部分を含んでいたか（中身をさらに行として読むかの判定に使う）。
    pub(crate) quoted: bool,
    /// 語全体が1組の引用符だけでできていて、展開する部分（二重引用符の中の`$`）を含まないか。
    /// `'abc'`は真、`'ab'+'cd'`・`ab'cd'`・`"$x"`は偽。`FromBase64String`の引数が字面で決まるかに使う。
    pub(crate) literal: bool,
}

/// 語か、文の区切りか、まとまりの記号か。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Token {
    Word(Word),
    /// `;`・`|`・`&`・改行。**ここで PowerShell の引数は終わる**——これを跨いで引数を数えると、
    /// `pwsh -c Get-Date; grep -e foo`の`-e`を PowerShell のスイッチとして読んでしまう。
    Separator(Separator),
    /// `(`・`)`・`{`・`}`・`,`・`=`・`<`・`>`（と`>&`の`&`）。語を切るが、**文は切らない**——
    /// `FromBase64String('…')`の値はこの括弧の向こうにあり、`2>&1`の後ろにも同じ起動の引数が続く。
    Group(char),
}

/// 引用符の種類。PowerShell は U+2018〜U+201B を`'`と、U+201C〜U+201E を`"`と同じに読む
/// （実測: `pwsh ‘-e’ <値>`は子へ`-e`を渡して走った）。開けた文字と閉じる文字は違ってよい。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Quote {
    Single,
    Double,
}

fn quote_of(c: char) -> Option<Quote> {
    match c {
        '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}' => Some(Quote::Single),
        '"' | '\u{201C}' | '\u{201D}' | '\u{201E}' => Some(Quote::Double),
        _ => None,
    }
}

/// 組み立て中の語。
#[derive(Default)]
struct WordBuilder {
    text: String,
    /// 引用符の組の数。
    spans: u32,
    /// 引用符の外の文字があったか。
    bare: bool,
    /// 二重引用符の中に`$`があったか（PowerShell が展開する）。
    expands: bool,
}

impl WordBuilder {
    fn push_bare(&mut self, c: char) {
        self.text.push(c);
        self.bare = true;
    }

    fn finish(&mut self, out: &mut Vec<Token>) {
        let word = std::mem::take(self);
        if !word.text.is_empty() || word.spans > 0 {
            out.push(Token::Word(Word {
                literal: word.spans == 1 && !word.bare && !word.expands,
                quoted: word.spans > 0,
                text: word.text,
            }));
        }
    }
}

/// 行を語と区切りへ割る（PowerShell の読み方に寄せる）。
///
/// - 引用符（`'`・`"`と、同じに読まれる U+2018〜U+201E）の中は割らない。引用符は剥がし、
///   囲まれていたことは[`Word::quoted`]に残す。同じ種類の引用符を2つ重ねたもの（`''`）はその文字自身
/// - バッククォートは次の1文字をそのまま語へ入れる（二重引用符の中でも）。**行末のバッククォートは
///   行の継続**で、文を切らない——切ると`pwsh `⏎`-e …`の`-e`を別の文として読み落とす
/// - `>&`の`&`はリダイレクト（`2>&1`）で、文を切らない
pub(crate) fn tokenize(line: &str) -> Vec<Token> {
    let mut out = Vec::new();
    let mut word = WordBuilder::default();
    let mut in_quote: Option<Quote> = None;
    let mut prev: Option<char> = None;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(q) = in_quote {
            if quote_of(c) == Some(q) {
                match chars.peek().copied().filter(|&n| quote_of(n) == Some(q)) {
                    Some(n) => {
                        chars.next();
                        word.text.push(n);
                    }
                    None => in_quote = None,
                }
            } else if c == '`' && q == Quote::Double {
                if let Some(n) = chars.next() {
                    word.text.push(n);
                }
            } else {
                if c == '$' && q == Quote::Double {
                    word.expands = true;
                }
                word.text.push(c);
            }
            continue;
        }
        match c {
            c if quote_of(c).is_some() => {
                in_quote = quote_of(c);
                word.spans += 1;
            }
            '`' => match chars.next() {
                Some('\n') => word.finish(&mut out),
                Some('\r') => {
                    if chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                    word.finish(&mut out);
                }
                Some(n) => word.push_bare(n),
                None => {}
            },
            '&' if prev == Some('>') => {
                word.finish(&mut out);
                out.push(Token::Group(c));
            }
            // `||`・`&&`は1つの区切り。`|`が1つだけならパイプ（前のコマンドの出力を次へ渡す。文は続く）。
            '|' if chars.peek() != Some(&'|') => {
                word.finish(&mut out);
                out.push(Token::Separator(Separator::Pipe));
            }
            '|' | '&' => {
                if chars.peek() == Some(&c) {
                    chars.next();
                }
                word.finish(&mut out);
                out.push(Token::Separator(Separator::Statement));
            }
            ';' | '\n' | '\r' => {
                word.finish(&mut out);
                out.push(Token::Separator(Separator::Statement));
            }
            '(' | ')' | '{' | '}' | ',' | '=' | '<' | '>' => {
                word.finish(&mut out);
                out.push(Token::Group(c));
            }
            c if c.is_whitespace() => word.finish(&mut out),
            c => word.push_bare(c),
        }
        prev = Some(c);
    }
    word.finish(&mut out);
    out
}

#[cfg(test)]
#[path = "shell_line_tests.rs"]
mod tests;
