use super::*;

/// 語は`W`、文の区切りは`;`、パイプは`|`、まとまりの記号はその文字で並べる。
fn shape(line: &str) -> String {
    tokenize(line)
        .iter()
        .map(|t| match t {
            Token::Word(w) => format!("W({})", w.text),
            Token::Separator(Separator::Statement) => ";".to_string(),
            Token::Separator(Separator::Pipe) => "|".to_string(),
            Token::Group(c) => c.to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// 1つだけの`|`はパイプ（文は続く）。`||`・`&&`・`&`・`;`・改行は文の区切りで、**2文字の区切りは1つ**として返す。
#[test]
fn a_single_pipe_is_a_pipe_and_every_other_separator_ends_the_statement() {
    assert_eq!(shape("a | b"), "W(a) | W(b)");
    assert_eq!(shape("a || b"), "W(a) ; W(b)");
    assert_eq!(shape("a && b"), "W(a) ; W(b)");
    assert_eq!(shape("a & b"), "W(a) ; W(b)");
    assert_eq!(shape("a; b"), "W(a) ; W(b)");
    assert_eq!(shape("a\nb"), "W(a) ; W(b)");
}

/// `2>&1`の`&`は区切りではない（同じ起動の引数が後ろに続く）。引用符の中の区切りは語の一部。
#[test]
fn a_redirect_ampersand_and_quoted_separators_do_not_split() {
    assert_eq!(shape("a 2>&1 | b"), "W(a) W(2) > & W(1) | W(b)");
    assert_eq!(shape("cmd /c 'del x | y'"), "W(cmd) W(/c) W(del x | y)");
}
