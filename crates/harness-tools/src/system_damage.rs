//! コマンドの行が**システムへ被害を与える場所**を消す・書き換えるかを、字面で機械的に判定する。
//!
//! # 何のためにあるのか
//!
//! 承認画面は、人が「このコマンドを走らせてよいか」を決めるための道具である。外の判定モデル（Ollaya）が
//! 使えるときはその危険度も出すが、**使えないとき・切っているときにも、明らかに危ないものだけは
//! 「危険度: 高」として見せたい**。ここはそのための、ネットワークを使わずすぐ終わる判定である。
//!
//! 見るのは「どこを」「どうするか」の組み合わせだけである。
//!
//! | 場所 | 消す | 書き換える |
//! |---|---|---|
//! | ドライブの根（`C:\`・`C:\*`・`/`） | 高 | 高 |
//! | システム（`C:\Windows` 以下・`Program Files`・`ProgramData`・`C:\Users` 全体、`/etc`・`/usr` 等） | 高 | 高 |
//! | ユーザーのアプリデータとプロファイルの根（`%AppData%`・`%LocalAppData%`・`C:\Users\<名前>`） | 高 | 要確認 |
//!
//! 場所は、書かれた形（`C:\Windows`・`%SystemRoot%`・`$Env:windir`・`${env:ProgramFiles(x86)}`・`~`）を
//! 揃えてから比べる。**実際の環境変数の値には展開しない**——この判定は、書かれた字面だけで決まる。
//!
//! # 判定の単位
//!
//! 1つの文（`;`・`&&`・`||`・`&`・改行で区切る）の中で、コマンドとその引数を見る。**パイプ（`|`）では
//! 文を切らない**——`Get-ChildItem C:\Windows | Remove-Item`の消す先は、パイプの前に書いてある。
//! コピー・移動は**書き込み先だけ**を見る（読むだけでは被害が出ない）。書き込み先を決められない書き方の
//! ときは、全部の引数を見る。
//!
//! 引用符の中（`cmd /c "del …"`・`python -c "…shutil.rmtree(…)"`）と、PowerShell の`-Command`・
//! cmd の`/c`の後ろは、新しいコマンドとして読み直す。同じ行の中の`cd`・`Set-Location`の行き先は、
//! 後ろの相対パスの基準にする。
//!
//! # 限界（同じ場所で言う）
//!
//! **これは境界ではなく、承認画面に出す表示である。** 聞く／聞かないは変えない（D-100「要約は補助であって
//! 境界ではない」と同じ立場）。見落としても結果は「危険度: 要確認」に戻るだけで、自動承認は広がらない。
//!
//! 字面に出ないものは読めない:
//! - 実行時に組み立てたパス（`$p='C:\Win'+'dows'; rm $p`）・変数に入れたパス
//! - その行で定義した別名・関数（`Set-Alias x Remove-Item; x C:\Windows`）
//! - 8.3 の短い名前（`C:\WINDOW~1`）・シンボリックリンク・ジャンクション・共有経由（`\\localhost\C$\Windows`）
//! - cmd の`^`によるエスケープ（`d^el`）
//! - 書かれていない場所を基準にする相対パス（`cd`を伴わない`..\..\Windows`）
//!
//! 判定の単位にも限界がある。引数の中に書いた別のコマンドの名前（`echo rm C:\Windows`の`rm`）は
//! コマンドとして読まないが、`{ }`や`=`の後ろはコマンドの始まりとして読むので、`if (…) { rm C:\Windows }`は
//! 拾う。

use crate::encoded_command::{is_powershell, rest_of_arguments, Rest};
use crate::shell_line::{tokenize, Separator, Token, Word};

/// 引用符の中を、さらに行として読む深さの上限（[`crate::encoded_command`]と同じ理由で置く）。
const MAX_NESTING: u32 = 16;

/// そのコマンドが場所に何をするか。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DamageAction {
    /// 消す（`Remove-Item`・`del`・`rm`・`rd`・`shutil.rmtree`…）。
    Delete,
    /// 書き換える（コピー・移動の書き込み先・名前の変更・中身の書込・権限や属性の変更）。
    Modify,
}

/// 当たった場所の種類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DamagePlace {
    /// ドライブの根（`C:\`・`C:\*`・`/`）。
    DriveRoot,
    /// OS とアプリの置き場（`C:\Windows` 以下・`Program Files`・`ProgramData`・`C:\Users` 全体・`/etc` 等）。
    System,
    /// ユーザーのアプリデータ（`AppData`）と、プロファイルの根（`C:\Users\<名前>`・`~`）。
    UserData,
}

/// 見つけた組み合わせ1つ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DamageFinding {
    pub action: DamageAction,
    pub place: DamagePlace,
    /// 書かれていたコマンドの名前（書かれたまま。リダイレクトは`>`）。
    pub command: String,
    /// 書かれていた場所（書かれたまま）。
    pub target: String,
}

impl DamageFinding {
    /// 危険度「高」に当たるか。ユーザーのアプリデータを**書き換える**だけのものは当たらない
    /// （消すものは当たる）——設定ファイルを1つ書き換えるのは日常の作業でも起きるから。
    pub fn is_high(&self) -> bool {
        !matches!(
            (self.place, self.action),
            (DamagePlace::UserData, DamageAction::Modify)
        )
    }

    /// 画面に出す一文。例:「システムの場所（C:\Windows\System32\x）を消すコマンド（Remove-Item）」。
    pub fn describe_ja(&self) -> String {
        let place = match self.place {
            DamagePlace::DriveRoot => "ドライブの根",
            DamagePlace::System => "システムの場所",
            DamagePlace::UserData => "ユーザーのアプリデータ・プロファイル",
        };
        let action = match self.action {
            DamageAction::Delete => "消す",
            DamageAction::Modify => "書き換える",
        };
        format!(
            "{place}（{}）を{action}コマンド（{}）",
            self.target, self.command
        )
    }
}

/// `run_shell`の行を判定する。
pub fn assess_line(line: &str) -> Vec<DamageFinding> {
    let mut out = Vec::new();
    let mut cwd = None;
    assess_text(line, &mut cwd, 0, &mut out);
    out
}

/// `run_program`の起動を判定する。引数は既に1要素ずつに割れているので、語として並べてから同じ判定に通す。
pub fn assess_program(program: &str, args: &[String]) -> Vec<DamageFinding> {
    let words: Vec<Word> = std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .map(|text| Word {
            text: text.to_string(),
            quoted: text.chars().any(char::is_whitespace),
            literal: true,
        })
        .collect();
    let mut out = Vec::new();
    let mut cwd = None;
    let refs: Vec<&Word> = words.iter().collect();
    assess_words(&refs, &[], &[], &mut cwd, 0, &mut out);
    out
}

fn assess_text(text: &str, cwd: &mut Option<Path>, nesting: u32, out: &mut Vec<DamageFinding>) {
    if nesting >= MAX_NESTING {
        return;
    }
    let tokens = tokenize(&fold_env_references(text));
    for statement in tokens.split(|t| *t == Token::Separator(Separator::Statement)) {
        assess_statement(statement, cwd, nesting, out);
    }
}

/// 1つの文。パイプで繋いだコマンドを順に見て、前のコマンドの語を「パイプで渡ってくるもの」として後ろへ渡す。
fn assess_statement(
    tokens: &[Token],
    cwd: &mut Option<Path>,
    nesting: u32,
    out: &mut Vec<DamageFinding>,
) {
    let mut piped: Vec<&Word> = Vec::new();
    for segment in tokens.split(|t| *t == Token::Separator(Separator::Pipe)) {
        // `{ }`・`=`の後ろはコマンドの始まり（`if (…) { rm … }`・`$r = Remove-Item …`）。
        for command in segment.split(|t| matches!(t, Token::Group('{' | '}' | '='))) {
            let words: Vec<&Word> = command
                .iter()
                .filter_map(|t| match t {
                    Token::Word(w) => Some(w),
                    _ => None,
                })
                .collect();
            assess_words(&words, command, &piped, cwd, nesting, out);
            piped.extend(words);
        }
    }
}

/// コマンド1つと、その中の引用符で囲んだ文字列（`cmd /c "del …"`・`python -c "…"`・`ssh host '…'`）。
/// 引用符の中は、文字列の中で起こすコマンドとして読み直す。
fn assess_words(
    words: &[&Word],
    tokens: &[Token],
    piped: &[&Word],
    cwd: &mut Option<Path>,
    nesting: u32,
    out: &mut Vec<DamageFinding>,
) {
    assess_command(words, tokens, piped, cwd, nesting, out);
    for w in words {
        if w.quoted && w.text.chars().any(char::is_whitespace) {
            assess_text(&w.text, cwd, nesting + 1, out);
        }
    }
}

/// コマンド1つ。`words[0]`がコマンドの名前。`tokens`はリダイレクト（`>`）を見るための元の並び。
fn assess_command(
    words: &[&Word],
    tokens: &[Token],
    piped: &[&Word],
    cwd: &mut Option<Path>,
    nesting: u32,
    out: &mut Vec<DamageFinding>,
) {
    for target in redirect_targets(tokens) {
        push(out, DamageAction::Modify, ">", target, cwd.as_ref());
    }
    let Some((first, args)) = words.split_first() else {
        return;
    };
    let name = command_name(&first.text);
    // `sudo rm …`: 前置きのコマンドは外して、後ろを同じ判定に通す。
    if PREFIX_COMMANDS.contains(&name.as_str()) {
        assess_command(args, &[], piped, cwd, nesting, out);
        return;
    }
    // PowerShell の`-Command`・cmd の`/c`の後ろは、新しいコマンド。
    if let Some(rest) = rest_as_command(&name, &first.text, args) {
        if nesting + 1 < MAX_NESTING {
            assess_command(rest, &[], &[], cwd, nesting + 1, out);
        }
        return;
    }
    let Some(kind) = verb_kind(&name) else {
        return;
    };
    let action = match kind {
        Verb::Delete => DamageAction::Delete,
        Verb::ChangeDir => {
            *cwd = write_target(args).and_then(|w| Path::parse(&w.text, cwd.as_ref()));
            return;
        }
        Verb::Robocopy if args.iter().any(|w| is_robocopy_purge(&w.text)) => DamageAction::Delete,
        _ => DamageAction::Modify,
    };
    let targets: Vec<&Word> = match kind {
        Verb::Delete => {
            let named: Vec<&Word> = args
                .iter()
                .copied()
                .filter(|w| !is_switch(&w.text))
                .collect();
            if named.is_empty() || named.iter().all(|w| is_pipeline_item(&w.text)) {
                // `Get-ChildItem C:\Windows | Remove-Item`・`… | % { Remove-Item $_ }`
                args.iter().chain(piped.iter()).copied().collect()
            } else {
                args.to_vec()
            }
        }
        Verb::CopyMove => match destination(args) {
            Some(dest) => vec![dest],
            None => args.iter().chain(piped.iter()).copied().collect(),
        },
        Verb::WriteTo => match write_target(args) {
            Some(path) => vec![path],
            None => args.to_vec(),
        },
        Verb::Robocopy => match positional(args).get(1) {
            Some(dest) => vec![*dest],
            None => args.to_vec(),
        },
        Verb::Attributes => args.to_vec(),
        Verb::ChangeDir => unreachable!("handled above"),
    };
    for target in targets {
        push(out, action, &first.text, &target.text, cwd.as_ref());
    }
}

fn push(
    out: &mut Vec<DamageFinding>,
    action: DamageAction,
    command: &str,
    target: &str,
    cwd: Option<&Path>,
) {
    // `-Recurse`はどこにも当たらない。`cd C:\Windows`の後で相対パスとして読むと、システムの場所に見えてしまう。
    if target.starts_with('-') {
        return;
    }
    let Some(place) = Path::parse(target, cwd).and_then(|p| p.place()) else {
        return;
    };
    let finding = DamageFinding {
        action,
        place,
        command: command.to_string(),
        target: target.to_string(),
    };
    if !out.contains(&finding) {
        out.push(finding);
    }
}

/// `>`・`>>`の書き込み先。`2>&1`の`&1`は書き込み先ではない。`$null`・`nul`・`/dev/null`は捨てる先。
fn redirect_targets(tokens: &[Token]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i] == Token::Group('>') {
            let mut j = i + 1;
            while tokens.get(j) == Some(&Token::Group('>')) {
                j += 1;
            }
            match tokens.get(j) {
                Some(Token::Word(w)) if !is_null_device(&w.text) => out.push(w.text.as_str()),
                _ => {}
            }
            i = j;
        }
        i += 1;
    }
    out
}

fn is_null_device(text: &str) -> bool {
    matches!(
        text.to_ascii_lowercase().as_str(),
        "$null" | "nul" | "/dev/null"
    )
}

/// コマンドの名前（ディレクトリ・実行ファイルの拡張子・大小を畳んだもの）。
fn command_name(word: &str) -> String {
    let lower = word.to_ascii_lowercase();
    // `[IO.File]::Delete`・`shutil.rmtree`はそのまま。パスの形（`C:\Windows\System32\cmd.exe`）だけ畳む。
    let name = if lower.starts_with('[') {
        lower.as_str()
    } else {
        lower.rsplit(['\\', '/']).next().unwrap_or(&lower)
    };
    for ext in [".exe", ".com", ".bat", ".cmd"] {
        if let Some(stem) = name.strip_suffix(ext) {
            return stem.to_string();
        }
    }
    name.to_string()
}

/// 前に付けて後ろのコマンドを走らせるだけのもの。
const PREFIX_COMMANDS: &[&str] = &["sudo", "doas", "gsudo", "nohup", "time"];

/// コマンドの種類。表は種類ごとにここだけに持つ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verb {
    /// 引数を消す。
    Delete,
    /// コピー・移動。書き込み先だけを見る。
    CopyMove,
    /// 中身を書き込む。書き込み先（`-Path`か最初の引数）だけを見る。
    WriteTo,
    /// 権限・属性・名前を変える。引数を全部見る。
    Attributes,
    /// `robocopy <元> <先>`。`/MIR`・`/PURGE`・`/MOVE`は消す。
    Robocopy,
    /// 現在の場所を変える（後ろの相対パスの基準）。
    ChangeDir,
}

const DELETE_COMMANDS: &[&str] = &[
    "rm",
    "del",
    "erase",
    "rd",
    "rmdir",
    "ri",
    "remove-item",
    "clear-content",
    "clc",
    "format",
    "shred",
    "unlink",
    "[io.file]::delete",
    "[system.io.file]::delete",
    "[io.directory]::delete",
    "[system.io.directory]::delete",
    "shutil.rmtree",
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "os.removedirs",
    "fs.rmsync",
    "fs.unlinksync",
    "fs.rmdirsync",
];

const COPY_MOVE_COMMANDS: &[&str] = &[
    "cp",
    "copy",
    "cpi",
    "copy-item",
    "xcopy",
    "mv",
    "move",
    "mi",
    "move-item",
    "[io.file]::copy",
    "[system.io.file]::copy",
    "[io.file]::move",
    "[system.io.file]::move",
    "[io.directory]::move",
    "[system.io.directory]::move",
    "shutil.copy",
    "shutil.copy2",
    "shutil.copyfile",
    "shutil.copytree",
    "shutil.move",
    "os.rename",
    "os.replace",
];

const WRITE_TO_COMMANDS: &[&str] = &[
    "set-content",
    "add-content",
    "ac",
    "out-file",
    "tee-object",
    "tee",
    "truncate",
    "[io.file]::writealltext",
    "[system.io.file]::writealltext",
    "[io.file]::writeallbytes",
    "[system.io.file]::writeallbytes",
    "[io.file]::writealllines",
    "[system.io.file]::writealllines",
];

const ATTRIBUTE_COMMANDS: &[&str] = &[
    "icacls",
    "cacls",
    "takeown",
    "attrib",
    "set-acl",
    "chmod",
    "chown",
    "ren",
    "rename",
    "rename-item",
    "rni",
];

const CHANGE_DIR_COMMANDS: &[&str] = &["cd", "chdir", "sl", "set-location", "pushd"];

fn verb_kind(name: &str) -> Option<Verb> {
    let tables: [(&[&str], Verb); 5] = [
        (DELETE_COMMANDS, Verb::Delete),
        (COPY_MOVE_COMMANDS, Verb::CopyMove),
        (WRITE_TO_COMMANDS, Verb::WriteTo),
        (ATTRIBUTE_COMMANDS, Verb::Attributes),
        (CHANGE_DIR_COMMANDS, Verb::ChangeDir),
    ];
    if name == "robocopy" {
        return Some(Verb::Robocopy);
    }
    tables
        .iter()
        .find(|(names, _)| names.contains(&name))
        .map(|(_, verb)| *verb)
}

/// PowerShell の`-Command`・cmd の`/c`・`/k`・`/r`の後ろの語。そこから先は新しいコマンドとして読む。
fn rest_as_command<'a>(name: &str, first: &str, args: &'a [&'a Word]) -> Option<&'a [&'a Word]> {
    let at = if is_powershell(first) {
        args.iter()
            .position(|w| matches!(rest_of_arguments(&w.text), Some(Rest::Code)))?
    } else if name == "cmd" {
        args.iter()
            .position(|w| matches!(w.text.to_ascii_lowercase().as_str(), "/c" | "/k" | "/r"))?
    } else {
        return None;
    };
    Some(&args[at + 1..])
}

/// スイッチの形か。`-Recurse`・`--force`・`/s`・`/MIR`。**`/etc`のような短い POSIX のパスもここに入る**
/// ——そのため、スイッチを除いた引数だけで決める判定（書き込み先）は、決められなければ全部の引数へ戻す。
fn is_switch(text: &str) -> bool {
    if text.starts_with('-') {
        return true;
    }
    match text.strip_prefix('/') {
        Some(rest) => {
            let name = rest.split(':').next().unwrap_or(rest);
            !name.is_empty() && name.len() <= 8 && name.chars().all(|c| c.is_ascii_alphanumeric())
        }
        None => false,
    }
}

/// 値を取らないスイッチ。これ以外の`-名前`の直後の語は、そのスイッチの値として読む（引数の並びに数えない）。
const VALUELESS_SWITCHES: &[&str] = &[
    "-recurse",
    "-force",
    "-confirm",
    "-whatif",
    "-passthru",
    "-container",
    "-verbose",
    "-r",
    "-f",
    "-rf",
    "-fr",
    "-v",
    "-i",
    "-n",
    "-p",
    "-a",
    "-u",
    "-l",
];

/// スイッチとスイッチの値を除いた引数。
fn positional<'a>(args: &[&'a Word]) -> Vec<&'a Word> {
    let mut out = Vec::new();
    let mut skip_value = false;
    for w in args {
        if skip_value {
            skip_value = false;
            continue;
        }
        if is_switch(&w.text) {
            let lower = w.text.to_ascii_lowercase();
            skip_value = lower.starts_with('-')
                && !lower.starts_with("--")
                && !VALUELESS_SWITCHES.contains(&lower.as_str());
            continue;
        }
        out.push(*w);
    }
    out
}

/// 名前付きの値（`-Destination <値>`）。`names`は小文字の完全な名前で、PowerShell の接頭辞の省略
/// （`-Dest`）も受ける。`min`は省略として受ける最短の長さ（`-d`は`-Debug`とぶつかるので受けない）。
fn named_value<'a>(args: &[&'a Word], names: &[&str], min: usize) -> Option<&'a Word> {
    let at = args.iter().position(|w| {
        let lower = w.text.to_ascii_lowercase();
        let name = lower.trim_start_matches('-');
        lower.starts_with('-')
            && name.len() >= min
            && names.iter().any(|full| full.starts_with(name))
    })?;
    args.get(at + 1).copied()
}

/// コピー・移動の書き込み先。`-Destination`か、引数が2つ以上あるときの最後。決められなければ`None`。
fn destination<'a>(args: &[&'a Word]) -> Option<&'a Word> {
    if let Some(dest) = named_value(args, &["destination", "target-directory"], 2) {
        return Some(dest);
    }
    if let Some(dest) = args
        .iter()
        .position(|w| w.text == "-t")
        .and_then(|at| args.get(at + 1))
    {
        return Some(dest);
    }
    let rest = positional(args);
    (rest.len() >= 2).then(|| *rest.last().expect("len >= 2"))
}

/// 中身を書き込む先。`-Path`・`-LiteralPath`・`-FilePath`か、最初の引数。決められなければ`None`。
fn write_target<'a>(args: &[&'a Word]) -> Option<&'a Word> {
    named_value(args, &["path", "literalpath", "filepath"], 1)
        .or_else(|| positional(args).first().copied())
}

fn is_robocopy_purge(text: &str) -> bool {
    matches!(
        text.to_ascii_lowercase().as_str(),
        "/mir" | "/purge" | "/move" | "/mov"
    )
}

/// パイプで渡ってきた1件を指す変数（`$_`・`$PSItem`とその欄）。
fn is_pipeline_item(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower == "$_" || lower.starts_with("$_.") || lower.starts_with("$psitem")
}

/// 揃えた場所。Windows はドライブと要素の並び、POSIX は要素の並び。**すべて小文字**。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Path {
    /// Windows のドライブ（`'c'`）。POSIX のパスなら`None`。
    drive: Option<char>,
    parts: Vec<String>,
}

impl Path {
    /// 書かれた場所を揃える。相対パスは`cwd`が分かっているときだけ繋ぐ。場所として読めなければ`None`。
    fn parse(raw: &str, cwd: Option<&Path>) -> Option<Path> {
        let expanded = expand_env(raw.trim().to_ascii_lowercase().as_str());
        let text = expanded
            .strip_prefix(r"\\?\")
            .or_else(|| expanded.strip_prefix(r"\??\"))
            .or_else(|| expanded.strip_prefix("//?/"))
            .unwrap_or(&expanded);
        if text.is_empty() || text.starts_with(r"\\") || text.starts_with("//") {
            // 共有経由のパスは読まない（モジュールdocの限界）。
            return None;
        }
        let bytes = text.as_bytes();
        let (drive, rest, absolute) =
            if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
                (Some(bytes[0] as char), &text[2..], true)
            } else if let Some(rest) = text.strip_prefix('\\') {
                // ドライブを書かない根（`\Windows`）。今のドライブは分からないので、システムのドライブとして読む。
                (Some('c'), rest, true)
            } else if text.starts_with('/') {
                (None, text, true)
            } else {
                (None, text, false)
            };
        let mut base = if absolute {
            Path {
                drive,
                parts: Vec::new(),
            }
        } else {
            cwd?.clone()
        };
        for part in rest.split(['\\', '/']) {
            match part {
                "" | "." => {}
                ".." => {
                    base.parts.pop();
                }
                p => base.parts.push(p.to_string()),
            }
        }
        Some(base)
    }

    fn place(&self) -> Option<DamagePlace> {
        let parts: Vec<&str> = self.parts.iter().map(String::as_str).collect();
        let is_all = |p: &str| p == "*" || p == "*.*";
        match self.drive {
            Some(_) => match parts.as_slice() {
                [] => Some(DamagePlace::DriveRoot),
                [only] if is_all(only) => Some(DamagePlace::DriveRoot),
                ["windows"
                | "program files"
                | "program files (x86)"
                | "programdata"
                | "boot"
                | "recovery"
                | "system volume information", ..] => Some(DamagePlace::System),
                ["users"] => Some(DamagePlace::System),
                ["users", only] if is_all(only) => Some(DamagePlace::System),
                ["users", _] => Some(DamagePlace::UserData),
                ["users", _, next, ..] if *next == "appdata" || is_all(next) => {
                    Some(DamagePlace::UserData)
                }
                _ => None,
            },
            None => match parts.as_slice() {
                [] => Some(DamagePlace::DriveRoot),
                [only] if is_all(only) => Some(DamagePlace::DriveRoot),
                ["etc" | "usr" | "bin" | "sbin" | "boot" | "lib" | "lib64" | "sys" | "proc", ..] => {
                    Some(DamagePlace::System)
                }
                ["home"] => Some(DamagePlace::System),
                ["home", _] | ["root"] => Some(DamagePlace::UserData),
                _ => None,
            },
        }
    }
}

/// 環境変数の書き方（`%SystemRoot%`・`$env:windir`・`${env:ProgramFiles(x86)}`）と`~`・`$HOME`を、
/// 既定の場所の字面へ置き換える（`text`は小文字）。ユーザー名の分からない所は`<user>`にする
/// （`<`は語の区切りなので、本物のパスには現れない。`*`にすると「全ユーザー」と区別がつかない）。
/// 知らない変数は`*`（どこにも当たらない）にする。
fn expand_env(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    if let Some(after) = rest.strip_prefix('~') {
        if after.is_empty() || after.starts_with(['\\', '/']) {
            out.push_str(r"c:\users\<user>");
            rest = after;
        }
    }
    if let Some(after) = rest.strip_prefix("$home") {
        if after.is_empty() || after.starts_with(['\\', '/']) {
            out.push_str(r"c:\users\<user>");
            rest = after;
        }
    }
    while !rest.is_empty() {
        if let Some((name, after)) = env_reference(rest) {
            out.push_str(env_value(name));
            rest = after;
            continue;
        }
        let c = rest.chars().next().expect("not empty");
        out.push(c);
        rest = &rest[c.len_utf8()..];
    }
    out
}

/// 行を割る前に、環境変数の参照を1語として読める形へ畳む。行の割り方は`{`・`(`で語を切るので、
/// `${env:windir}`・`${env:ProgramFiles(x86)}`・`%ProgramFiles(x86)%`は畳まないと1語にならない。
/// `${env:X}`は`$env:X`へ、名前の中の`(`・`)`は`_`へ置き換える（`ProgramFiles(x86)`→`ProgramFiles_x86_`）。
/// **見つけた場所の表示（[`DamageFinding::target`]）には、畳んだ後の形が出る。**
fn fold_env_references(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < line.len() {
        if lower[i..].starts_with("${env:") {
            if let Some(end) = line[i..].find('}') {
                let name = &line[i + "${env:".len()..i + end];
                out.push_str("$env:");
                out.push_str(&name.replace(['(', ')'], "_"));
                i += end + 1;
                continue;
            }
        }
        if line[i..].starts_with('%') {
            if let Some(end) = line[i + 1..].find('%') {
                let name = &line[i + 1..i + 1 + end];
                if !name.is_empty()
                    && !name.contains(char::is_whitespace)
                    && !name.contains(['\\', '/'])
                {
                    out.push('%');
                    out.push_str(&name.replace(['(', ')'], "_"));
                    out.push('%');
                    i += end + 2;
                    continue;
                }
            }
        }
        let c = line[i..].chars().next().expect("in bounds");
        out.push(c);
        i += c.len_utf8();
    }
    out
}

/// `rest`の先頭が環境変数の参照なら、その名前と残り。
fn env_reference(rest: &str) -> Option<(&str, &str)> {
    if let Some(after) = rest.strip_prefix("${env:") {
        let end = after.find('}')?;
        return Some((&after[..end], &after[end + 1..]));
    }
    if let Some(after) = rest.strip_prefix("$env:") {
        let end = after
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(after.len());
        return (end > 0).then(|| (&after[..end], &after[end..]));
    }
    if let Some(after) = rest.strip_prefix('%') {
        let end = after.find('%')?;
        let name = &after[..end];
        return (!name.is_empty() && !name.contains(['\\', '/', ' ']))
            .then(|| (name, &after[end + 1..]));
    }
    None
}

fn env_value(name: &str) -> &'static str {
    match name {
        "systemroot" | "windir" => r"c:\windows",
        "systemdrive" | "homedrive" => "c:",
        "programfiles" | "programw6432" => r"c:\program files",
        "programfiles(x86)" | "programfiles_x86_" => r"c:\program files (x86)",
        "programdata" | "allusersprofile" => r"c:\programdata",
        "appdata" => r"c:\users\<user>\appdata\roaming",
        "localappdata" => r"c:\users\<user>\appdata\local",
        "userprofile" | "home" => r"c:\users\<user>",
        "homepath" => r"\users\<user>",
        "username" => "<user>",
        _ => "*",
    }
}

#[cfg(test)]
#[path = "system_damage_tests.rs"]
mod tests;
