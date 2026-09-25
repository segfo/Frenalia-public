//! `run_program` の規則と照合（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` §3）。
//!
//! 規則はプログラムの綴りと引数の**配列**で書く。1本の文字列へ潰して照合しない——潰すと、どこまでが
//! 1つの引数かが分からなくなり、前方一致が別の引数まで食う。
//!
//! 照合は外の世界と話さない純粋な関数である（ファイルの中身で縛る部分は、材料を作る側が
//! 先に計算して渡す）。

use serde::{Deserialize, Serialize};

use crate::{is_interpreter_program, ProgramSubject};

/// 引数1つ分の照合。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArgPattern {
    /// その値と完全一致。
    Exact(String),
    /// 穴——毎回変わってよい引数1個。[`hole_accepts`] が受け付ける値だけが当たる。
    Hole,
}

/// `run_program` の規則1件。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramRule {
    /// 解決前の綴り（モデルが書くもの）。バイト完全一致で照合し、正規化しない。
    pub program: String,
    /// 引数の配列。個数も一致しなければならない（穴が引数の個数を増やせない）。
    pub args: Vec<ArgPattern>,
}

impl ProgramRule {
    /// 承認した呼び出しそのものから、穴の無い規則を作る。
    pub fn exact(subject: &ProgramSubject) -> Self {
        Self {
            program: subject.program.clone(),
            args: subject
                .args
                .iter()
                .cloned()
                .map(ArgPattern::Exact)
                .collect(),
        }
    }

    /// 穴を1つでも持つか。
    pub fn has_hole(&self) -> bool {
        self.args.iter().any(|a| matches!(a, ArgPattern::Hole))
    }

    /// 呼び出しがこの規則に当たるか。
    ///
    /// **インタプリタの規則が穴を持っていたら、何にも当てない**（§4.2）。規則を作る側でも
    /// 拒否するが、台帳のように外から読み込むものがあるので、照合の側でも拒否する。
    pub fn matches(&self, subject: &ProgramSubject) -> bool {
        if self.has_hole() && is_interpreter_program(&self.program) {
            return false;
        }
        subject.program == self.program
            && subject.args.len() == self.args.len()
            && self.args.iter().zip(&subject.args).all(|(p, a)| match p {
                ArgPattern::Exact(v) => a == v,
                ArgPattern::Hole => hole_accepts(a),
            })
    }
}

/// 穴に当たってよい値か（D-97・D-105）。
///
/// 穴が生む危険の主要な形はオプション解釈への注入である（`git <穴>` の穴に `--upload-pack=…`）。
/// 次の値は当たらない。どれもプログラムに依らず判定できる。
///
/// - 空文字列
/// - `-` で始まる（オプション）
/// - Windows では `/` で始まる（古い形式のオプション `/c`。Linux では絶対パスなので拒否しない）
/// - `@` で始まる（コンパイラ等が引数ファイルとして読む）
/// - `"` を含む（独自の規則で引数を割り直すプログラムで、引数を分けられる）
/// - 制御文字・書式文字（ゼロ幅・双方向制御）を含む（画面に見えない）
///
/// **規約であって保証ではない**（§8）。そのプログラムが他の形で値を解釈することは止めない。
pub fn hole_accepts(value: &str) -> bool {
    let Some(first) = value.chars().next() else {
        return false;
    };
    if first == '-' || first == '@' || (cfg!(windows) && first == '/') {
        return false;
    }
    !value
        .chars()
        .any(|c| c == '"' || c.is_control() || is_format_char(c))
}

/// Unicode の書式文字（一般カテゴリ Cf）のうち、表示や解釈を偽装しうるもの。
///
/// ゼロ幅の文字と双方向制御は画面に見えない（または表示の順序を入れ替える）ので、
/// 人が見て承認したものと実際に渡るものが食い違う（Trojan Source、CVE-2021-42574）。
/// 標準ライブラリに Cf の判定は無いので、範囲を列挙する。
pub fn is_format_char(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(program: &str, args: &[&str]) -> ProgramSubject {
        ProgramSubject {
            program: program.to_string(),
            args: args.iter().map(|a| a.to_string()).collect(),
        }
    }

    fn rule(program: &str, args: &[Option<&str>]) -> ProgramRule {
        ProgramRule {
            program: program.to_string(),
            args: args
                .iter()
                .map(|a| match a {
                    Some(v) => ArgPattern::Exact(v.to_string()),
                    None => ArgPattern::Hole,
                })
                .collect(),
        }
    }

    /// 穴は配列の1要素にだけ当たり、個数は増やせない。綴りはバイト完全一致。
    #[test]
    fn a_hole_matches_one_element_and_the_count_must_agree() {
        let r = rule("git", &[Some("log"), Some("-n"), None]);
        assert!(r.matches(&subject("git", &["log", "-n", "5"])));
        assert!(r.matches(&subject("git", &["log", "-n", "main; rm -rf /"])));
        for s in [
            subject("git", &["log", "-n"]),
            subject("git", &["log", "-n", "5", "extra"]),
            subject("git", &["log", "-m", "5"]),
            subject("Git", &["log", "-n", "5"]),
            subject("git.exe", &["log", "-n", "5"]),
        ] {
            assert!(!r.matches(&s), "{s:?}");
        }
    }

    /// 禁止側と許可側を対にする（穴が何も受け付けない実装でも禁止側は緑になるため）。
    #[test]
    fn hole_values_that_could_be_parsed_as_options_or_hidden_are_refused() {
        for bad in [
            "",
            "-x",
            "--upload-pack=evil",
            "@args.rsp",
            "a\"b",
            "line\nbreak",
            "tab\tinside",
            "zero\u{200B}width",
            "bidi\u{202E}txt",
            "bom\u{FEFF}",
        ] {
            assert!(!hole_accepts(bad), "{bad:?} must not fill a hole");
        }
        for good in [
            "5",
            "main",
            "src/lib.rs",
            "日本語",
            "a b c",
            "C:\\work\\x",
            "x=y",
            "a-b",
        ] {
            assert!(hole_accepts(good), "{good:?} must fill a hole");
        }
        // Windows の古い形式のオプションは Windows でだけ拒否する（Linux では絶対パス）。
        assert_eq!(hole_accepts("/c"), !cfg!(windows));
    }

    /// インタプリタの規則は穴を持てない。外から読み込んだ規則が穴を持っていても何にも当てない。
    #[test]
    fn an_interpreter_rule_with_a_hole_matches_nothing() {
        let r = rule("python", &[None]);
        assert!(!r.matches(&subject("python", &["build.py"])));
        let r = rule("python", &[Some("build.py")]);
        assert!(r.matches(&subject("python", &["build.py"])));
    }

    #[test]
    fn exact_rules_are_built_from_the_approved_call() {
        let s = subject("cargo", &["test", "-p", "x"]);
        let r = ProgramRule::exact(&s);
        assert!(!r.has_hole());
        assert!(r.matches(&s));
    }
}
