//! 引数やファイルの中身を**コードとして実行する**プログラム（インタプリタ）の一覧と判定
//! （`plans/DESIGN-RUNSHELL-ALLOWLIST.md` §4、D-99）。
//!
//! # なぜ要るのか
//!
//! `run_program` はプログラム名と引数の配列を OS へそのまま渡すので、**シェルの層では**
//! 構文が壊れようがない（D-96）。ところが起動したプログラム自身が引数やファイルを
//! コードとして読むなら、その内側で起きることは配列の形からは見えない。
//!
//! ```text
//!  cmd /c "dir & del x"     ← "dir & del x" は cmd が実行するコード
//!  python build.py          ← build.py の中身は python が実行するコード
//! ```
//!
//! だからこれらは別扱いにする——穴を持てず、承認済みの引数との完全一致以外は
//! `accept-all` でも人に聞く。
//!
//! # なぜここ（`harness-core`）に置くのか
//!
//! 判定器（`harness-engine`）と、起動の直前にもう一度確かめる `run_program`
//! （`harness-tools`）が**同じ一覧**を使う。記録とハッシュ（段階2）も同じものを使う。
//! 別々に書くと片方だけ足されて静かにずれる（`bug-pattern-rules` B-05）。
//! 同じ理由で置かれた [`crate::is_config_injection_path`] と同じ置き場である。
//!
//! # 限界（同じ場所で言う）
//!
//! - **一覧は網羅ではない。** 載っていないインタプリタは普通のプログラムとして扱われる。
//!   これは歯止めであって境界ではない（境界は隔離Tier、D-14）
//! - **名前で見る。** 改名したコピー（`cmd.exe` を `foo.exe` へ写したもの）は拾えない
//! - **ビルドツールは載せない。** `cargo`・`npm`・`make` もファイルからコードを走らせるが
//!   （`build.rs`・`package.json` のスクリプト・Makefile）、それは `cargo test` が `build.rs` を
//!   走らせるのと同じ、受容済みの階級である

/// インタプリタとして扱うプログラム名（拡張子なし・小文字）。
///
/// 足すときの基準は1つ——**引数かファイルの中身を、コードとして実行するか**。
pub const INTERPRETER_PROGRAMS: &[&str] = &[
    // シェル
    "cmd",
    "powershell",
    "pwsh",
    "bash",
    "sh",
    "zsh",
    "wsl",
    // スクリプト言語
    "python",
    "python3",
    "py",
    "node",
    "deno",
    "perl",
    "ruby",
    "php",
    // Windows のスクリプトホスト
    "cscript",
    "wscript",
    "mshta",
];

/// `program` がインタプリタか。
///
/// ディレクトリ部分を落とし、ASCII の大小と末尾の `.exe` を除いた名前の**完全一致**で見る。
/// 行全体の部分一致ではないので、`rg "cmd /c" src/` のように引数に綴りが出るだけでは当たらない。
///
/// **畳むのは ASCII の大小と `.exe` だけ**である。Windows は ASCII の大小を区別しないので
/// `CMD.EXE` は `cmd.exe` と同じファイルを開くが、全角の `ｃｍｄ` は別の名前である
/// ——ファイルシステムより多く畳むと、当たらないはずのものに当たる。
pub fn is_interpreter_program(program: &str) -> bool {
    let name = program.rsplit(['\\', '/']).next().unwrap_or(program);
    let lower = name.to_ascii_lowercase();
    let stem = lower.strip_suffix(".exe").unwrap_or(&lower);
    INTERPRETER_PROGRAMS.contains(&stem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_bare_name_and_the_exe_spelling() {
        for program in ["cmd", "cmd.exe", "CMD.EXE", "Cmd", "python", "pwsh.exe"] {
            assert!(is_interpreter_program(program), "{program}");
        }
    }

    #[test]
    fn matches_through_a_directory() {
        assert!(is_interpreter_program(r"C:\Windows\System32\cmd.exe"));
        assert!(is_interpreter_program("/usr/bin/bash"));
    }

    /// 禁止側と対にする（`bug-pattern-rules` B-35）——当たってはいけないものが当たらないこと。
    #[test]
    fn does_not_match_ordinary_programs_or_near_misses() {
        for program in [
            "git",
            "cargo",
            "rg",
            "cmdline",    // 前方一致ではない
            "mycmd",      // 後方一致ではない
            "python.txt", // .exe 以外の拡張子は畳まない
            "ｃｍｄ",     // 全角はファイルシステム上も別の名前
            "",
        ] {
            assert!(!is_interpreter_program(program), "{program}");
        }
    }
}
