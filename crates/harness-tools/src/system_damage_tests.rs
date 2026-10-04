use super::*;

use DamageAction::{Delete, Modify};
use DamagePlace::{DriveRoot, System, UserData};

/// 行ごとに「期待した組み合わせが見つかったか」を見て、外れた行を全部集める（1行目で止めない）。
fn misses(cases: &[(&str, DamagePlace, DamageAction)]) -> Vec<String> {
    cases
        .iter()
        .filter_map(|(line, place, action)| {
            let found = assess_line(line);
            let hit = found
                .iter()
                .any(|f| f.place == *place && f.action == *action);
            (!hit).then(|| format!("{line} => {found:?}"))
        })
        .collect()
}

/// 何も見つからないはずの行のうち、見つかってしまったもの。
fn false_alarms(lines: &[&str]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|line| {
            let found = assess_line(line);
            (!found.is_empty()).then(|| format!("{line} => {found:?}"))
        })
        .collect()
}

#[test]
fn deleting_the_drive_root_is_found() {
    let cases = [
        ("rm -rf /", DriveRoot, Delete),
        ("rm -rf /*", DriveRoot, Delete),
        (r"del /s /q C:\*", DriveRoot, Delete),
        (r"del /s /q C:\*.*", DriveRoot, Delete),
        (r"Remove-Item C:\ -Recurse -Force", DriveRoot, Delete),
        (r"rd /s /q \", DriveRoot, Delete),
        ("format C:", DriveRoot, Delete),
        (r"Remove-Item $env:SystemDrive\ -Recurse", DriveRoot, Delete),
    ];
    assert_eq!(misses(&cases), Vec::<String>::new());
}

/// ユーザーが挙げた書き方（`%SystemRoot%`・`$Env:SystemRoot`・`%windir%`・`$Env:Windir`）と、
/// 区切り・大小・前置き・`..`の違いを全部同じ場所として読む（`B-20`: 判定する側が自分で揃える）。
#[test]
fn every_way_of_writing_the_windows_folder_is_the_same_place() {
    let cases = [
        (r"Remove-Item C:\Windows\System32\x", System, Delete),
        (r"del %SystemRoot%\System32\x", System, Delete),
        (r"del %windir%\x", System, Delete),
        (r"Remove-Item $Env:SystemRoot\System32\x", System, Delete),
        (r"Remove-Item $Env:Windir\x", System, Delete),
        (r"Remove-Item ${env:windir}\x", System, Delete),
        ("rm -rf C:/Windows/System32", System, Delete),
        (r"Remove-Item \\?\C:\Windows\x", System, Delete),
        (r"Remove-Item \Windows\x", System, Delete),
        (r"Remove-Item C:\Temp\..\WINDOWS\x", System, Delete),
        (
            r#"Remove-Item "C:\Program Files\App" -Recurse"#,
            System,
            Delete,
        ),
        (r"Remove-Item ${env:ProgramFiles(x86)}\App", System, Delete),
        (r"del %ProgramData%\x", System, Delete),
        (r"Remove-Item C:\Users -Recurse", System, Delete),
        ("rm -rf /etc", System, Delete),
        ("sudo rm -rf /usr/lib", System, Delete),
        (
            r"Remove-Item (Join-Path $env:windir 'System32\x')",
            System,
            Delete,
        ),
    ];
    assert_eq!(misses(&cases), Vec::<String>::new());
}

/// システムの場所は、消すだけでなく書き換えても「高」。
#[test]
fn rewriting_system_places_is_found_too() {
    let cases = [
        (r"cp a.txt C:\Windows\", System, Modify),
        (
            r"Copy-Item -Path a -Destination $env:windir",
            System,
            Modify,
        ),
        ("cp -r src /etc", System, Modify),
        (r"Move-Item a.dll C:\Windows\System32\a.dll", System, Modify),
        (r"echo x > C:\Windows\x.txt", System, Modify),
        (
            r"Set-Content -Path $env:SystemRoot\x -Value 1",
            System,
            Modify,
        ),
        (
            r"icacls C:\Windows\System32 /grant Everyone:F",
            System,
            Modify,
        ),
        (r"takeown /f C:\Windows\System32\x", System, Modify),
        (r"Rename-Item C:\Windows\x y", System, Modify),
        (
            r"[IO.File]::WriteAllText('C:\Windows\x', 'data')",
            System,
            Modify,
        ),
    ];
    assert_eq!(misses(&cases), Vec::<String>::new());
    for (line, _, _) in cases {
        assert!(
            assess_line(line).iter().all(DamageFinding::is_high),
            "{line}"
        );
    }
}

/// AppData とプロファイルの根: **消すのは「高」、書き換えるのは見つけるが「高」ではない**。
#[test]
fn user_data_is_high_only_when_it_is_deleted() {
    let deleted = [
        (r"del %AppData%\x", UserData, Delete),
        (
            r"Remove-Item $env:LOCALAPPDATA\Programs -Recurse",
            UserData,
            Delete,
        ),
        (
            r"Remove-Item C:\Users\bob\AppData\Roaming\x",
            UserData,
            Delete,
        ),
        (r"Remove-Item ~\AppData -Recurse", UserData, Delete),
        (r"Remove-Item $HOME\AppData\Local\x", UserData, Delete),
        (r"rd /s /q %USERPROFILE%", UserData, Delete),
        (r"Remove-Item C:\Users\bob -Recurse", UserData, Delete),
    ];
    assert_eq!(misses(&deleted), Vec::<String>::new());
    for (line, _, _) in deleted {
        assert!(
            assess_line(line).iter().any(DamageFinding::is_high),
            "{line}"
        );
    }
    let rewritten = [
        (r"cp a.json %AppData%\app\settings.json", UserData, Modify),
        (
            r"Set-Content $env:LOCALAPPDATA\app\x.txt 1",
            UserData,
            Modify,
        ),
        (r"echo x >> %AppData%\x.log", UserData, Modify),
    ];
    assert_eq!(misses(&rewritten), Vec::<String>::new());
    for (line, _, _) in rewritten {
        assert!(
            !assess_line(line).iter().any(DamageFinding::is_high),
            "{line}: rewriting user data must not be high"
        );
    }
}

/// 消す先がパイプの前・`{ }`の中・別のコマンドの中に書いてある形。
#[test]
fn targets_written_elsewhere_in_the_statement_are_followed() {
    let cases = [
        (
            r"Get-ChildItem C:\Windows\Temp | Remove-Item -Recurse",
            System,
            Delete,
        ),
        (r"gci $env:windir | % { Remove-Item $_ }", System, Delete),
        (r"if ($true) { rm C:\Windows\x }", System, Delete),
        (r"cmd /c del C:\Windows\x", System, Delete),
        (r#"cmd /c "del /q C:\Windows\x""#, System, Delete),
        (
            r"pwsh -NoProfile -c Remove-Item C:\Windows\x",
            System,
            Delete,
        ),
        (
            r#"pwsh -Command "Remove-Item C:\Windows\x""#,
            System,
            Delete,
        ),
        (
            r#"python -c "import shutil; shutil.rmtree('C:/Windows')""#,
            System,
            Delete,
        ),
        ("bash -c 'rm -rf /etc'", System, Delete),
        (
            r"[IO.Directory]::Delete('C:\Windows\x', $true)",
            System,
            Delete,
        ),
        (r"Get-Date; Remove-Item C:\Windows\x", System, Delete),
        (r"robocopy C:\empty C:\Windows /MIR", System, Delete),
    ];
    assert_eq!(misses(&cases), Vec::<String>::new());
}

/// 同じ行の`cd`・`Set-Location`の行き先が、後ろの相対パスの基準になる。
#[test]
fn the_directory_changed_in_the_line_is_the_base_of_relative_paths() {
    let cases = [
        (r"cd C:\Windows; del x", System, Delete),
        (
            r"Set-Location -Path $env:windir; Remove-Item -Recurse System32",
            System,
            Delete,
        ),
        (r"cd C:\; del /s /q *", DriveRoot, Delete),
        (r"cd %AppData%; rd /s /q app", UserData, Delete),
    ];
    assert_eq!(misses(&cases), Vec::<String>::new());
    // スイッチ（`-Recurse`）は、行き先を基準にしても場所として読まない。
    let targets: Vec<String> =
        assess_line(r"Set-Location -Path $env:windir; Remove-Item -Recurse System32")
            .into_iter()
            .map(|f| f.target)
            .collect();
    assert_eq!(targets, vec!["System32".to_string()]);
}

/// 対照（`B-35`）: 読むだけ・普通の場所・コマンドの名前を引数に書いただけの行は、何も見つけない。
/// コピー・移動は書き込み先しか見ない。
#[test]
fn reading_or_touching_ordinary_places_finds_nothing() {
    let lines = [
        "ls",
        "git status",
        r"Get-Content C:\Windows\win.ini",
        r"Select-String -Path C:\Windows\System32\drivers\etc\hosts -Pattern localhost",
        "ls /etc",
        r"cp C:\Windows\win.ini .",
        r"Copy-Item C:\Windows\System32\drivers\etc\hosts -Destination C:\work\hosts",
        r"robocopy C:\Windows\Fonts C:\backup\fonts",
        "echo rm -rf /",
        r"Write-Output 'Remove-Item'",
        "git rm src/old.rs",
        r"Remove-Item .\build -Recurse -Force",
        "rm -rf node_modules target",
        r"del C:\Users\bob\Documents\draft.txt",
        r"Remove-Item C:\work\Windows\x",
        r"cd C:\work; del x",
        "del x",
        r"dir C:\Windows 2>&1 > $null",
        r"echo x > out.txt",
        r"Remove-Item $env:TEMP\x -Recurse",
    ];
    assert_eq!(false_alarms(&lines), Vec::<String>::new());
}

/// `run_program`は引数が既に割れている。同じ判定に通る。
#[test]
fn run_program_arguments_are_judged_the_same_way() {
    let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let found = |p: &str, a: &[&str]| assess_program(p, &args(a));
    assert!(found("cmd", &["/c", "del", r"C:\Windows\x"])
        .iter()
        .any(|f| f.place == System && f.action == Delete));
    assert!(found(
        "pwsh",
        &["-NoProfile", "-Command", r"Remove-Item C:\Windows\x"]
    )
    .iter()
    .any(|f| f.place == System && f.action == Delete));
    assert!(found(
        r"C:\Windows\System32\robocopy.exe",
        &[r"C:\empty", r"C:\Windows", "/MIR"]
    )
    .iter()
    .any(|f| f.place == System && f.action == Delete));
    // 対照: 起動するプログラムが C:\Windows にあっても、それ自体は消す先ではない。
    assert_eq!(
        found(r"C:\Windows\System32\cmd.exe", &["/c", "dir"]),
        Vec::new()
    );
    assert_eq!(found("git", &["status"]), Vec::new());
    assert_eq!(found("python", &["build.py"]), Vec::new());
}

#[test]
fn the_description_names_the_place_the_target_the_action_and_the_command() {
    let found = assess_line(r"Remove-Item C:\Windows\System32\x");
    assert_eq!(
        found
            .iter()
            .map(DamageFinding::describe_ja)
            .collect::<Vec<_>>(),
        vec![r"システムの場所（C:\Windows\System32\x）を消すコマンド（Remove-Item）".to_string()]
    );
}

/// 同じ組み合わせは1回だけ出す（引用符の中を読み直しても重ならない）。
#[test]
fn the_same_finding_is_reported_once() {
    let found = assess_line(r#"cmd /c "del C:\Windows\x" & del C:\Windows\x"#);
    assert_eq!(found.len(), 1, "{found:?}");
}

// --- 複数行のスクリプトの読み方（D-119） ---

/// **コメントに書いただけの危険な処理は拾わない。**
///
/// 読み飛ばさないと、コメントの中の `=` や `{}` で文が切り直されて、コメントの中身をコードとして読む。
/// 実測（2026-10-04）: `# cleanup = os.remove("C:/Windows/x")` の1行だけで「高」が出ていた。
#[test]
fn a_dangerous_line_written_only_in_a_comment_is_not_flagged() {
    let alarms = false_alarms(&[
        // `#`（Python・シェル・PowerShell）。`=` があると、直す前は文が切り直されて拾っていた。
        "# cleanup = os.remove(\"C:/Windows/x\")\nprint(1)\n",
        "# rm -rf /etc\necho hi\n",
        "echo hi  # shutil.rmtree(\"C:/Windows\")\n",
        // `//`（JavaScript・TypeScript）。
        "// fs.rmSync(\"C:/Windows\", {recursive: true})\nconsole.log(1)\n",
        // PowerShell の囲みコメント。
        "<# Remove-Item -Recurse C:/Windows/System32 #>\nWrite-Host hi\n",
        // 閉じない囲みコメントは、そこから先を全部読み飛ばす。
        "<# Remove-Item -Recurse C:/Windows/System32\n",
    ]);
    assert!(alarms.is_empty(), "{alarms:?}");
}

/// **コメントの印は語の途中では始まらない。** 始まるとしてしまうと、`--color=#fff` や `http://x` の
/// 後ろが全部コメントになり、**そこに書かれた危険な処理が見えなくなる**。
#[test]
fn a_comment_mark_inside_a_word_does_not_hide_the_rest_of_the_line() {
    let misses = misses(&[
        ("npm run build --color=#fff; rm -rf /etc", System, Delete),
        ("curl http://x.example/a; rm -rf /etc", System, Delete),
        ("Remove-Item C:/Windows/System32/a#b", System, Delete),
    ]);
    assert!(misses.is_empty(), "{misses:?}");
}

/// **括弧が開いている間は、改行で文を切らない。** 切ると、改行して書いた引数を見落とす。
///
/// 実測（2026-10-04）: `shutil.rmtree(`⏎`  "C:/Windows/System32"`⏎`)` が0件だった。
#[test]
fn a_statement_continued_inside_brackets_is_read_as_one() {
    let misses = misses(&[
        (
            "shutil.rmtree(\n    \"C:/Windows/System32\"\n)\n",
            System,
            Delete,
        ),
        (
            "fs.rmSync(\n  \"C:/Windows\",\n  { recursive: true }\n)\n",
            System,
            Delete,
        ),
        // 入れ子（丸括弧の中の丸括弧・角括弧）でも1つの文として読む。
        (
            "shutil.rmtree(
  os.path.join(
    \"C:/Windows\",
    [\"System32\"][0]
  )
)
",
            System,
            Delete,
        ),
    ]);
    assert!(misses.is_empty(), "{misses:?}");
}

/// **閉じない括弧でテキストの残り全部が1つの文にならない。** 上限の行数で諦めて、普通に切り直す。
#[test]
fn an_unclosed_bracket_gives_up_after_the_line_limit() {
    // `(` を開いたまま、上限を超える行数を置く。最後の行の `cd` が最初の文へ混ざらないこと。
    let filler = "x\n".repeat(crate::shell_line::MAX_CONTINUED_LINES as usize + 5);
    let text = format!("echo (\n{filler}rm -rf /etc\n");
    let found = assess_line(&text);
    // 最後の `rm -rf /etc` は、文として切り直された後でも拾える。
    assert!(
        found
            .iter()
            .any(|f| f.place == System && f.action == Delete),
        "{found:?}"
    );
}

/// **意図して直していないもの（2つ）。** 直すと実際の動きから離れるか、判定を避ける道ができる。
#[test]
fn two_behaviours_are_kept_on_purpose() {
    // (1) `cd` の効きは次の文へ持ち越す——スクリプトでは本当にそう動く。
    let found = assess_line("cd C:/Windows\nrm -rf System32\n");
    assert!(
        found
            .iter()
            .any(|f| f.place == System && f.action == Delete),
        "cd の持ち越しが消えている: {found:?}"
    );

    // (2) 三重引用符の中も、引用符の中として読み直す。読み直さない形にすると、
    //     `exec(\"\"\"…\"\"\")` のように文字列へ入れるだけで判定を避けられる。
    let found = assess_line("exec(\"\"\"\nshutil.rmtree(\"C:/Windows\")\n\"\"\")\n");
    assert!(
        found
            .iter()
            .any(|f| f.place == System && f.action == Delete),
        "三重引用符の中を読まなくなっている: {found:?}"
    );
}

/// **見つけたものが書かれている行を引ける。** 長いスクリプトでは、先頭から順に出しても
/// 当たった行まで届かないので、承認画面がその行を直接見せるために使う。
#[test]
fn a_finding_can_point_at_the_line_it_came_from() {
    let script = "import shutil\nimport sys\n\nif cleanup:\n    shutil.rmtree(\"C:/Windows/Temp\")\nprint(1)\n";
    let found = assess_line(script);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].line_in(script), Some(5));

    // 見つからないときは`None`（嘘の行番号を返さない）。
    assert_eq!(found[0].line_in("print(1)\n"), None);
}
