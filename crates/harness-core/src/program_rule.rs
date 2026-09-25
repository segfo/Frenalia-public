//! `run_program`・`run_shell` の規則と照合（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` §3・§5）。
//!
//! `run_program` の規則はプログラムの綴りと引数の**配列**で書く。1本の文字列へ潰して照合しない——潰すと、
//! どこまでが1つの引数かが分からなくなり、前方一致が別の引数まで食う。
//!
//! 照合は外の世界と話さない純粋な関数である（ファイルの中身で縛る部分は、材料を作る側が
//! 先に計算して渡す）。**毎回、今の中身で計算し直した材料と比べる**——「一度確かめた」を
//! 持ち越さない（`bug-pattern-rules` B-14: 記録が古いまま検証済みとして通さない）。

use serde::{Deserialize, Serialize};

use crate::{is_interpreter_program, BoundFile, CommandSubject, ProgramSubject};

/// パスを照合のために畳む（区切りを`/`へ、末尾の区切りを落とす。Windows では大小も畳む）。
/// ワークスペースルートと解決先の絶対パスの比較に使う。
pub fn fold_path_for_rule(path: &str) -> String {
    let p = path.replace('\\', "/");
    let p = p.trim_end_matches('/');
    if cfg!(windows) {
        p.to_lowercase()
    } else {
        p.to_string()
    }
}

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
    /// 解決した絶対パス（D-103）。`Some`なら、呼び出しの解決先もこれと同じでなければ当たらない
    /// ——承認した`git`が、PATH の先頭に置かれた別の`git.exe`へ解決されても当てない。
    /// コマンドライン・設定の規則は解決先を書かないので`None`（綴りだけで照合する）。
    #[serde(default)]
    pub resolved: Option<String>,
    /// 縛ったファイル（`rel_path`昇順）。コードを走らせる呼び出しでは、今の中身から計算した集合と
    /// **完全に同じ**でなければ当たらない（書き換え・削除・承認後の新規作成で外れる）。
    #[serde(default)]
    pub files: Vec<BoundFile>,
    /// 縛ったワークスペースのルート（[`fold_path_for_rule`]で畳んだもの）。コードを走らせる呼び出しでは
    /// 必須で、別のワークスペースでは当たらない（同じ中身のスクリプトでも、隣に置かれたものが違う）。
    #[serde(default)]
    pub workspace: Option<String>,
}

impl ProgramRule {
    /// 承認した呼び出しそのものから、穴の無い規則を作る。解決先・縛ったファイルもそのまま写し、
    /// コードを走らせる呼び出しならワークスペースに縛る。
    pub fn exact(subject: &ProgramSubject, workspace_root: &str) -> Self {
        Self {
            program: subject.program.clone(),
            args: subject
                .args
                .iter()
                .cloned()
                .map(ArgPattern::Exact)
                .collect(),
            resolved: subject.resolved.clone(),
            files: subject.files.clone(),
            workspace: subject
                .runs_code
                .then(|| fold_path_for_rule(workspace_root)),
        }
    }

    /// 縛るものの無い規則（コマンドライン・設定で書いたもの。解決先・ファイル・ワークスペースは後で決める）。
    pub fn unbound(program: String, args: Vec<ArgPattern>) -> Self {
        Self {
            program,
            args,
            resolved: None,
            files: Vec::new(),
            workspace: None,
        }
    }

    /// 穴を1つでも持つか。
    pub fn has_hole(&self) -> bool {
        self.args.iter().any(|a| matches!(a, ArgPattern::Hole))
    }

    /// 呼び出しがこの規則に当たるか。`workspace_root`は今のワークスペースのルート。
    ///
    /// **コードを走らせる呼び出し（インタプリタ・ワークスペース内の実行ファイル）には、穴を持つ規則を
    /// 当てない**（§4.2）。規則を作る側でも拒否するが、台帳のように外から読み込むものがあるので、
    /// 照合の側でも拒否する。さらに、確かめられない引数を含む呼び出し（`one_shot_only`）には何も当てず、
    /// 縛ったファイルの集合とワークスペースの一致を要求する（D-104）。
    pub fn matches(&self, subject: &ProgramSubject, workspace_root: &str) -> bool {
        let runs_code = subject.runs_code || is_interpreter_program(&self.program);
        if runs_code {
            if self.has_hole() || subject.one_shot_only {
                return false;
            }
            if subject.files != self.files {
                return false;
            }
            match &self.workspace {
                Some(ws) if *ws == fold_path_for_rule(workspace_root) => {}
                _ => return false,
            }
        }
        if let Some(resolved) = &self.resolved {
            match &subject.resolved {
                Some(r) if fold_path_for_rule(r) == fold_path_for_rule(resolved) => {}
                _ => return false,
            }
        }
        subject.program == self.program
            && subject.args.len() == self.args.len()
            && self.args.iter().zip(&subject.args).all(|(p, a)| match p {
                ArgPattern::Exact(v) => a == v,
                ArgPattern::Hole => hole_accepts(a),
            })
    }
}

/// `run_shell` の規則1件（D-102）。人が承認した文字列との完全一致と、字面に出るファイルの中身の一致。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellRule {
    /// 承認した行そのもの。
    pub line: String,
    /// 行に字面で現れたワークスペース内のファイル（`rel_path`昇順）。今の中身から計算した集合と
    /// 完全に同じでなければ当たらない。
    #[serde(default)]
    pub files: Vec<BoundFile>,
    /// 縛ったワークスペースのルート（[`fold_path_for_rule`]で畳んだもの）。
    #[serde(default)]
    pub workspace: Option<String>,
}

impl ShellRule {
    /// 承認した行そのものから作る（ワークスペースに縛る）。
    pub fn exact(subject: &CommandSubject, workspace_root: &str) -> Self {
        Self {
            line: subject.line.clone(),
            files: subject.files.clone(),
            workspace: Some(fold_path_for_rule(workspace_root)),
        }
    }

    /// 行が一致し、縛ったファイルの集合が同じで、ワークスペースが同じか。
    /// **行に確かめられないファイルが出てきた呼び出しには当てない**。
    pub fn matches(&self, subject: &CommandSubject, workspace_root: &str) -> bool {
        if subject.unverifiable || subject.line != self.line || subject.files != self.files {
            return false;
        }
        match &self.workspace {
            Some(ws) => *ws == fold_path_for_rule(workspace_root),
            None => true,
        }
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

/// 画面へ出すために、見えない文字を綴りへ置き換える（D-106）。
///
/// 端末は双方向制御やゼロ幅の文字をそのまま解釈するので、**人が見た並びと実際に渡る並びが違う**
/// ものを承認させられる（Trojan Source）。判定の側で弾く表（[`is_format_char`]・[`hole_accepts`]）と
/// **同じ表を使う**——表が2つあると、片方だけが更新されて「弾かないのに見えない文字」が生まれる。
///
/// 制御文字は改行とタブも含めて潰すので、**行に割ってから1行ずつ渡す**こと。
pub fn escape_for_display(s: &str) -> String {
    if !s.chars().any(|c| c.is_control() || is_format_char(c)) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() || is_format_char(c) {
            out.push_str(&format!("\\u{{{:04X}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const WS: &str = "C:/ws";

    fn subject(program: &str, args: &[&str]) -> ProgramSubject {
        ProgramSubject::plain(program, args.iter().map(|a| a.to_string()).collect())
    }

    fn rule(program: &str, args: &[Option<&str>]) -> ProgramRule {
        ProgramRule::unbound(
            program.to_string(),
            args.iter()
                .map(|a| match a {
                    Some(v) => ArgPattern::Exact(v.to_string()),
                    None => ArgPattern::Hole,
                })
                .collect(),
        )
    }

    fn file(rel: &str, sha: &str) -> BoundFile {
        BoundFile {
            rel_path: rel.to_string(),
            sha256: sha.to_string(),
            dir_listing_sha256: Some("listing".to_string()),
        }
    }

    /// 中身を縛った、インタプリタの呼び出しの材料。
    fn script_call(files: Vec<BoundFile>) -> ProgramSubject {
        ProgramSubject {
            program: "python".into(),
            args: vec!["build.py".into()],
            resolved: Some("C:/Python/python.exe".into()),
            runs_code: true,
            files,
            one_shot_only: false,
            previews: Vec::new(),
            decoded_inline: None,
        }
    }

    /// 穴は配列の1要素にだけ当たり、個数は増やせない。綴りはバイト完全一致。
    #[test]
    fn a_hole_matches_one_element_and_the_count_must_agree() {
        let r = rule("git", &[Some("log"), Some("-n"), None]);
        assert!(r.matches(&subject("git", &["log", "-n", "5"]), WS));
        assert!(r.matches(&subject("git", &["log", "-n", "main; rm -rf /"]), WS));
        for s in [
            subject("git", &["log", "-n"]),
            subject("git", &["log", "-n", "5", "extra"]),
            subject("git", &["log", "-m", "5"]),
            subject("Git", &["log", "-n", "5"]),
            subject("git.exe", &["log", "-n", "5"]),
        ] {
            assert!(!r.matches(&s, WS), "{s:?}");
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
        let mut r = ProgramRule::exact(&script_call(vec![file("build.py", "a")]), WS);
        r.args = vec![ArgPattern::Hole];
        assert!(!r.matches(&script_call(vec![file("build.py", "a")]), WS));
    }

    /// 中身で縛った規則は、中身・隣の名前一覧・ワークスペース・解決先のどれが変わっても当たらない。
    /// 同じなら当たる（対照）。確かめられない引数を含む呼び出しには当たらない。
    #[test]
    fn a_bound_rule_matches_only_the_same_contents_in_the_same_workspace() {
        let approved = script_call(vec![file("build.py", "a")]);
        let r = ProgramRule::exact(&approved, WS);
        assert!(r.matches(&approved, WS));
        // Windows では大小と区切りを畳む。
        if cfg!(windows) {
            assert!(r.matches(&approved, r"c:\WS\"));
        }

        let mut changed = file("build.py", "b");
        assert!(
            !r.matches(&script_call(vec![changed.clone()]), WS),
            "content changed"
        );
        changed = file("build.py", "a");
        changed.dir_listing_sha256 = Some("json.py appeared".into());
        assert!(
            !r.matches(&script_call(vec![changed]), WS),
            "a sibling appeared"
        );
        assert!(!r.matches(&script_call(vec![]), WS), "the file was deleted");
        assert!(
            !r.matches(
                &script_call(vec![file("build.py", "a"), file("x.py", "c")]),
                WS
            ),
            "a file appeared"
        );
        assert!(!r.matches(&approved, "C:/other"), "another workspace");

        let mut moved = approved.clone();
        moved.resolved = Some("C:/ws/.venv/Scripts/python.exe".into());
        assert!(!r.matches(&moved, WS), "resolves elsewhere");

        let mut one_shot = approved.clone();
        one_shot.one_shot_only = true;
        assert!(!r.matches(&one_shot, WS), "an unverifiable argument");
    }

    /// 縛りの無い規則（コマンドライン由来）は、コードを走らせる呼び出しには当たらない。
    #[test]
    fn an_unbound_rule_never_matches_a_call_that_runs_code() {
        let r = rule("python", &[Some("build.py")]);
        assert!(!r.matches(&script_call(vec![file("build.py", "a")]), WS));
        let mut ws_exe = subject("./tool.exe", &[]);
        ws_exe.runs_code = true;
        assert!(!rule("./tool.exe", &[]).matches(&ws_exe, WS));
    }

    #[test]
    fn exact_rules_are_built_from_the_approved_call() {
        let s = subject("cargo", &["test", "-p", "x"]);
        let r = ProgramRule::exact(&s, WS);
        assert!(!r.has_hole());
        assert!(
            r.workspace.is_none(),
            "code-free calls are not tied to a workspace"
        );
        assert!(r.matches(&s, WS));
        assert!(r.matches(&s, "C:/other"));
    }

    /// `run_shell` の規則は行の完全一致と縛ったファイルの一致。確かめられない行には当たらない。
    #[test]
    fn a_shell_rule_matches_the_exact_line_and_the_same_files() {
        let approved = CommandSubject {
            line: "python build.py".into(),
            files: vec![file("build.py", "a")],
            unverifiable: false,
            previews: Vec::new(),
        };
        let r = ShellRule::exact(&approved, WS);
        assert!(r.matches(&approved, WS));

        let mut other = approved.clone();
        other.line = "python build.py ".into();
        assert!(!r.matches(&other, WS));
        let mut other = approved.clone();
        other.files = vec![file("build.py", "b")];
        assert!(!r.matches(&other, WS));
        let mut other = approved.clone();
        other.unverifiable = true;
        assert!(!r.matches(&other, WS));
        assert!(!r.matches(&approved, "C:/other"));
    }

    /// 見えない文字は綴りに置き換え、普通の文字はそのまま出す（D-106）。
    /// **判定が弾く文字と、画面で綴りに変える文字は同じ表**——弾かないのに見えない文字を作らない。
    #[test]
    fn invisible_characters_are_shown_as_their_spelling() {
        assert_eq!(escape_for_display("build.py"), "build.py");
        assert_eq!(escape_for_display("日本語もそのまま"), "日本語もそのまま");
        assert_eq!(escape_for_display("gp\u{202E}yp.exe"), r"gp\u{202E}yp.exe");
        assert_eq!(escape_for_display("a\u{200B}b"), r"a\u{200B}b");
        assert_eq!(escape_for_display("a\tb\nc"), r"a\u{0009}b\u{000A}c");
        // 弾く側と同じ文字が対象になっている（表が2つに割れていない）。
        for c in ['\u{202E}', '\u{200B}', '\u{0007}'] {
            assert!(!hole_accepts(&format!("x{c}")));
            assert_ne!(escape_for_display(&c.to_string()), c.to_string());
        }
    }
}
