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

/// **コードとして読む可能性のあるファイルの拡張子**（小文字・先頭の`.`なし）。
///
/// 使う場所は2つで、**どちらも同じ一覧を見る**。
///
/// 1. `run_shell`の行に字面で出たファイルを縛るとき、隣のフォルダの名前一覧も一緒に縛るか
///    （`harness_tools::approval_binding`）
/// 2. 縛ったファイルの中身へ、機械の被害判定を掛けるか（`harness_engine::approval_risk`）
///
/// **以前はこの2つが別々の定数で、中身がずれていた**（2026-10-04に気づいた）。1にあって2に無いのが
/// `pyw mts cts pm vbe jse hta lua exe dll` の10種で、`deploy.pyw` は中身を読んでハッシュで縛り
/// 判定モデルへも送るのに、**機械の被害判定だけ掛からない**状態だった。このモジュールの冒頭が
/// インタプリタの一覧について言っているのと同じ理由（別々に書くと片方だけ足されて静かにずれる）で、
/// ここへ寄せる。
///
/// `exe`・`dll`も入れている。ワークスペース内の実行ファイルもコードであり、中身を文字として読んで
/// 被害判定を掛けるのは**画面に出すだけ**なので費用が小さい（当たらなければ何も増えない）。
///
/// # 限界（同じ場所で言う）
///
/// **拡張子で見るので、拡張子の無いスクリプトは当たらない**（`#!/bin/sh`で始まるファイル等）。
/// ただし`run_program`でコードを走らせる呼び出しでは**拡張子に関わらず全部**中身を読むので、
/// 当たらないのは`run_shell`の行に字面で出た場合だけである。
pub const SCRIPT_EXTENSIONS: &[&str] = &[
    "py", "pyw", "js", "mjs", "cjs", "ts", "mts", "cts", "ps1", "psm1", "psd1", "sh", "bash",
    "zsh", "rb", "pl", "pm", "php", "bat", "cmd", "vbs", "vbe", "jse", "wsf", "hta", "lua", "exe",
    "dll",
];

/// `path`の拡張子が[`SCRIPT_EXTENSIONS`]のどれかか（大文字小文字は問わない）。
///
/// 区切りは`/`でも`\`でもよい。拡張子の取り出しは`std::path`に任せる——`a.b/c`のような形を
/// 自前で後ろから探すと、フォルダ名の`.`を拡張子として読んでしまう。
pub fn has_script_extension(path: &str) -> bool {
    std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| SCRIPT_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
}

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

    /// **スクリプトの拡張子の一覧は1つだけ。** 承認でファイルを縛る側（`harness-tools`）と、
    /// 中身へ機械の被害判定を掛ける側（`harness-engine`）が同じものを見る。
    ///
    /// 以前は2つあって中身がずれており、`deploy.pyw`のようなファイルは**中身を読んでハッシュで縛り
    /// 判定モデルへも送るのに、機械の被害判定だけ掛からない**状態だった（2026-10-04）。
    /// ずれていた10種をここで名指しして固定する——片方だけ足す直し方へ戻ると、この試験が落ちる。
    #[test]
    fn the_script_extension_table_covers_the_ten_that_used_to_be_missing() {
        for ext in [
            "pyw", "mts", "cts", "pm", "vbe", "jse", "hta", "lua", "exe", "dll",
        ] {
            assert!(
                SCRIPT_EXTENSIONS.contains(&ext),
                "{ext} が一覧から消えている"
            );
            assert!(has_script_extension(&format!("a/b/deploy.{ext}")), "{ext}");
        }
        // もともと両方に在ったものも残っている。
        for ext in [
            "py", "ps1", "bat", "cmd", "sh", "js", "ts", "rb", "pl", "php", "vbs", "wsf",
        ] {
            assert!(SCRIPT_EXTENSIONS.contains(&ext), "{ext}");
        }
    }

    /// 禁止側と対にする（`bug-pattern-rules` B-35）——当たってはいけないものが当たらないこと。
    #[test]
    fn a_path_without_a_script_extension_does_not_match() {
        for path in [
            "notes.txt",
            "README",
            "data.json",
            "a.py/b",   // フォルダ名の`.`を拡張子として読まない
            "archive.", // 拡張子が空
            "",
        ] {
            assert!(!has_script_extension(path), "{path}");
        }
        // 大文字小文字は問わない。区切りは `/` でも `\` でもよい。
        assert!(has_script_extension("Build.PY"));
        assert!(has_script_extension(r"src\tool.Ps1"));
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
