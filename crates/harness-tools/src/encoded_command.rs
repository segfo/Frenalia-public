//! PowerShell が符号化して受け取るコード（`-EncodedCommand`等）を、**機械的に解読して見せる**
//! （`plans/DESIGN-RUNSHELL-ALLOWLIST.md` §4.4、T-09＝`plans/DESIGN-SANDBOX.md` §6.4）。
//!
//! # 何のためにあるのか
//!
//! 承認を求める画面は「人を輪の中に残す」ための道具である（§0）。ところが
//! `pwsh --enc cwB5AHMAdABlAG0AaQBuAGYAbwA=` のような行は、**人にもモデルにも中身が読めない**。
//! 実際に起きたこと（[BUG-224](../../../docs/bugs/BUG-224.md)）——画面には符号化された塊がそのまま出て、
//! 要約する LLM が自分で解読しようとして**間違えた**（中身は`systeminfo`なのに「`Write-Hello`」と書いた）。
//! 読めないものを承認させているあいだ、承認は形だけになる。
//!
//! だからハーネスが**自分で**解読して、段ごとに並べて出す。解読した中身にさらに符号化された箇所があれば
//! 続けて解読する（2段目・3段目…）。解読できなかったこと・上限で止めたことも1段として残す
//! ——黙って落とすと、見る人には「符号化された中身は無かった」と区別がつかない。
//!
//! # ここが引き受ける2つの仕事
//!
//! 1. **綴りの判定**（[`encoded_switch`]）。PowerShell が `-EncodedCommand` として受け付ける
//!    省略形を1箇所で決める。T-09の検出（`harness-engine`の`looks_like_allowlist_bypass`が呼ぶ
//!    [`line_has_encoded_switch`]）と、承認画面の解読が**同じこの関数**を通る——綴りの一覧を2箇所に
//!    持つと静かにずれる（`B-13`。[BUG-222](../../../docs/bugs/BUG-222.md)）
//! 2. **解読**（[`decode_shell_line`]・[`decode_program_args`]）。段ごとに[`DecodedLayer`]を返す
//!
//! # 照合には使わない
//!
//! 解読した中身は**表示と要約のためだけ**である（[`harness_core::FilePreview`]と同じ立場）。
//! 承認の判定が見るのは行そのものと縛ったファイルのハッシュで、ここが何を返しても自動承認は広がらない。
//! T-09 が使うのは「符号化のスイッチがあるか」の真偽だけで、これも**聞く方向にしか働かない**。
//!
//! # 受け付ける綴り（2026-10-04 に実測した。pwsh 7.6.6・Windows PowerShell 5.1）
//!
//! 子の PowerShell へ argv を直接渡し、符号化したコードが走ったかで見た。
//!
//! | 形 | pwsh | 5.1 |
//! |---|---|---|
//! | `-EncodedCommand`の接頭辞（`-e`・`-en`・`-enc`・`-encoded`…）・大小無視 | 走る | 走る |
//! | `-ec`（頭文字の略。接頭辞ではない） | 走る | 走る |
//! | `/enc`・`/ec`（スラッシュ） | 走る | 走る |
//! | `–enc`（U+2013・U+2014・U+2015 のダッシュ1つ） | 走る | 走る |
//! | **前後に空白の付いた引数**（`' -enc'`・`'-enc '`・タブ） | 走る | 走る |
//! | `--enc`・`--ec`（ハイフン2つ）・`––enc`（同じダッシュ2つ） | 走る | 走らない |
//! | `---enc`・`//enc`・`-–enc`（3つ以上・違う文字を混ぜる） | 走らない | 走らない |
//! | `-enc:<値>`（コロンで繋ぐ）・`-ecx` | 走らない | 走らない |
//! | `-ea`・`-encodeda`…＝`-EncodedArguments`（`/ea`も） | 走る | 走る |
//! | `--ea` | 走る | 走らない |
//! | `-c pwsh -enc <値>`（`-Command`の後ろで2つ目を起こす） | 走る | 走る |
//! | `-NoProfile x.ps1 -e <値>`・`-File x.ps1 -e <値>`（ファイルの後ろ） | 走らない | 走らない |
//!
//! **どちらかが走るものは全部検出する**（片方でしか走らない形でも、走る側で素通りさせない）。
//!
//! 行を読む側（`run_shell`の行を実行する PowerShell）についても実測した: **`‘-e’`・`“-e”`
//! （U+2018〜U+201E の引用符）は普通の引用符として剥がされ**、子には`-e`が渡って走った。
//! `[Diagnostics.Process]::Start('pwsh', '-e <値>')`・`pwsh -c 'pwsh -e <値>'`・`pwsh --% -e <値>`・
//! `pwsh @('-e', '<値>')`も走った。
//!
//! # 行の割り方
//!
//! `approval_binding`の`shell_tokens`（字面に出るファイルを縛るための割り方）とは別に持つ。あちらは
//! 引用符の中まで割る——ファイルの参照を広く拾う方が聞く方向に倒れるからである。ここは逆に、
//! **引用符の中を1語に保たないと`& 'C:\Program Files\PowerShell\7\pwsh.exe' -e …`の起動が読めない**。
//! 約束が逆なので、1つへ畳まない。
//!
//! # 限界（同じ場所で言う）
//!
//! - **字面に出るものしか解読できない。** 変数・連結・実行時に組み立てる式（`$b='c'+'wB5'`・
//!   `pwsh @a`・`-e$x`）は読めない。見落としても結果は「元どおり記録との完全一致」に戻るだけである
//! - **PowerShell の起動を名前で見る**（`pwsh`・`powershell`、`.exe`・パス付き）。8.3 の短い名前
//!   （`POWERS~1.EXE`）・別名を付けた写し・`dotnet pwsh.dll`は見ない
//! - **PowerShell が受け付けない形まで解読して見せることがある**（詰め物`=`を欠く base64 など）。
//!   表示は広い側へ倒す——解読できたものを隠さない
//! - **`run_program`で`powershell`（5.1）へ位置引数でコードを渡すとき、引数を1つずつ読む。**
//!   5.1 は位置引数の残りを空白で繋いでコードにするので、複数の引数にまたがる起動は見落とす
//! - **これは検出であって境界ではない**（§0・D-14）。綴りの網から漏れた形は元の照合に戻るだけである

use harness_core::{DecodeOutcome, DecodedLayer, EncodedSource, TextEncoding};

use crate::shell_line::{tokenize, Token};

/// 解読する段の深さの上限。これより深い段は解読せず、[`DecodeOutcome::DepthLimit`]を残して止める。
pub const MAX_DECODE_DEPTH: u32 = 4;
/// 解読した中身の合計の上限（バイト）。超えたら[`DecodeOutcome::SizeLimit`]を残して止める。
pub const MAX_DECODED_BYTES: usize = 64 * 1024;
/// 残す段の数の上限。超えたら[`DecodeOutcome::CountLimit`]を残して止める。
pub const MAX_DECODED_LAYERS: usize = 16;
/// 引用符の中をさらに行として読む深さの上限。
///
/// **実際の行はこの深さに届かない。** 引用符は2種類しかなく、2段下の同じ種類の引用符は`''`・`""`と
/// 重ねて書くしかないので、入れ子は2段ごとに長さが倍になる（64段には 2^32 バイト級の行が要る）。
/// 届かない上限を置くのは、割り方を直し損ねて再帰が線形に積み上がる形になったときにスタックを守るため。
/// **小さくしない**——以前の版の 8 は数百バイトの行で届き、その下に置いた`pwsh -e`を見落とした。
const MAX_QUOTE_NESTING: u32 = 64;

/// `program`が PowerShell か（ディレクトリ・`.exe`・大小を畳んだ名前の完全一致）。
///
/// `harness_core::is_interpreter_program`より狭い——**符号化の綴りは PowerShell のものだから**、
/// `python`や`cmd`の`-e`を拾わないようにここで絞る。
pub fn is_powershell(program: &str) -> bool {
    let name = program.rsplit(['\\', '/']).next().unwrap_or(program);
    let lower = name.to_ascii_lowercase();
    let stem = lower.strip_suffix(".exe").unwrap_or(&lower);
    stem == "pwsh" || stem == "powershell"
}

/// 1つの引数が、符号化された値を取る PowerShell のスイッチか（モジュールdocの表）。
///
/// **T-09の検出と承認画面の解読が、同じこの関数で綴りを決める**（`B-13`）。
pub fn encoded_switch(arg: &str) -> Option<EncodedSource> {
    let name = switch_name(arg)?;
    // `-ec`・`-ea`は頭文字の略で、接頭辞ではないので名指しする。`-e`は PowerShell が
    // `-ExecutionPolicy`（`-ex`から）より先に`-EncodedCommand`へ解く。
    if name == "ec" || "encodedcommand".starts_with(&name) {
        return Some(EncodedSource::EncodedCommand);
    }
    // `-encoded`までは上で`-EncodedCommand`に取られるので、ここへ来るのは`-encodeda`以上の長さだけ。
    if name == "ea" || "encodedarguments".starts_with(&name) {
        return Some(EncodedSource::EncodedArguments);
    }
    None
}

/// 残りの引数を PowerShell がどう受け取るか（スイッチとしては読まないもの）。
pub(crate) enum Rest {
    /// `-Command`・`-CommandWithArgs`: 残りはコード。
    Code,
    /// `-File`: 残りはスクリプトとその引数。
    Script,
}

/// 残りをコードやファイルとして受け取るスイッチか。ここから先の語は**そのコードの一部**なので、
/// PowerShell の起動のスイッチとしては読まない——読むと`Get-ChildItem -ea Stop`の`-ea`を
/// `-EncodedArguments`と取り違える。逆に、**コードの中で起こした2つ目の PowerShell は読む**
/// （実測: `pwsh -c pwsh -enc <値>`は走る）。
pub(crate) fn rest_of_arguments(arg: &str) -> Option<Rest> {
    let name = switch_name(arg)?;
    // `-c`〜`-command`は`-ConfigurationName`（`-config`から）とぶつからない。実測で`-co`は`-Command`。
    if "command".starts_with(&name) || name == "cwa" || name == "commandwithargs" {
        return Some(Rest::Code);
    }
    if "file".starts_with(&name) {
        return Some(Rest::Script);
    }
    None
}

/// スイッチの名前（前置きを剥がし、小文字にしたもの）。スイッチの形でなければ`None`。
///
/// **PowerShell は引数の前後の空白を削ってから見る**（実測: `' -enc'`でも走る）ので、ここも削る。
fn switch_name(arg: &str) -> Option<String> {
    let name = strip_switch_prefix(arg.trim())?;
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

/// スイッチの前置き（`-`・`--`・`/`・U+2013〜U+2015 のダッシュ1〜2つ）を剥がす。
///
/// **同じ文字の繰り返しだけを認める**（実測: `---enc`・`//enc`・`-–enc`はどちらの PowerShell でも
/// スイッチにならない）。`/`は1つだけ。2つ重ねは pwsh だけが受けるが、検出は広い側に合わせる。
fn strip_switch_prefix(arg: &str) -> Option<&str> {
    let mut chars = arg.chars();
    let first = chars.next()?;
    let max_repeat = match first {
        '-' | '\u{2013}' | '\u{2014}' | '\u{2015}' => 2,
        '/' => 1,
        _ => return None,
    };
    let mut prefix_len = first.len_utf8();
    let mut repeat = 1;
    for c in chars {
        if c == first && repeat < max_repeat {
            repeat += 1;
            prefix_len += c.len_utf8();
        } else {
            break;
        }
    }
    Some(&arg[prefix_len..])
}

/// `run_shell`の行に、PowerShell の符号化スイッチが字面で現れるか（T-09）。
///
/// **聞く方向にしか働かない**（`DESIGN-RUNSHELL-ALLOWLIST.md` §0）。PowerShell の起動に続く引数
/// としてだけ見るので、`grep -e foo`・`git log -e`のような**別のコマンドの`-e`**は拾わない。
/// 引用符の中（`cmd /c "pwsh -e …"`・`pwsh -c 'pwsh -e …'`）も行として読む。
pub fn line_has_encoded_switch(line: &str) -> bool {
    scan_text(line).iter().any(|f| {
        matches!(
            f.source,
            EncodedSource::EncodedCommand | EncodedSource::EncodedArguments
        )
    })
}

/// `run_shell`の行を解読する（段ごと。見つからなければ空）。
pub fn decode_shell_line(line: &str) -> Vec<DecodedLayer> {
    decode_found(scan_text(line))
}

/// `run_program`の引数を解読する（段ごと）。
///
/// `program`が PowerShell なら、引数をそのまま PowerShell の起動のスイッチとして読み、`-Command`の
/// 残りは PowerShell と同じく空白で繋いでコードとして読む。スイッチでない引数（スイッチの値・5.1 の
/// 位置引数のコード）も行として読む——`pwsh -c "…FromBase64String('…')…"`のように、コードそのものを
/// 引数で渡す形があるため。PowerShell でなければ（`cmd /c pwsh -e …`）、引数を空白で繋いだ行として読む。
pub fn decode_program_args(program: &str, args: &[String]) -> Vec<DecodedLayer> {
    let found = match is_powershell(program) {
        true => scan_powershell_args(args),
        false => scan_text(&args.join(" ")),
    };
    decode_found(found)
}

fn decode_found(found: Vec<Found>) -> Vec<DecodedLayer> {
    let mut decoder = Decoder::default();
    decoder.walk(found, 1);
    decoder.layers
}

/// 既に解読した中身`text`の中をさらに読む（`depth`段目から）。LLM が場所を示して解読した中身の2段目以降
/// （[`crate::encoded_payload`]）。`decoded_bytes`はそれまでに解読した量（上限の勘定を引き継ぐ）。
pub(crate) fn decode_nested(text: &str, depth: u32, decoded_bytes: usize) -> Vec<DecodedLayer> {
    let mut decoder = Decoder {
        decoded_bytes,
        ..Decoder::default()
    };
    decoder.walk(scan_text(text), depth);
    decoder.layers
}

/// 解読の進み具合（上限の勘定を1箇所に持つ）。
#[derive(Default)]
struct Decoder {
    layers: Vec<DecodedLayer>,
    decoded_bytes: usize,
    /// 上限で止めた。これ以降は1段も解読しない（止めたことは最後の段に残っている）。
    stopped: bool,
}

impl Decoder {
    /// この段で見つかったものを順に解読し、読めた中身をさらに1段深く読む。
    fn walk(&mut self, found: Vec<Found>, depth: u32) {
        for f in found {
            if self.stopped {
                return;
            }
            if depth > MAX_DECODE_DEPTH {
                self.stop(
                    depth,
                    f.source,
                    DecodeOutcome::DepthLimit {
                        max_depth: MAX_DECODE_DEPTH,
                    },
                );
                return;
            }
            if self.layers.len() >= MAX_DECODED_LAYERS {
                self.stop(
                    depth,
                    f.source,
                    DecodeOutcome::CountLimit {
                        max_layers: MAX_DECODED_LAYERS,
                    },
                );
                return;
            }
            let outcome = self.decode_one(&f);
            let next = match &outcome {
                DecodeOutcome::Text { text, .. } => scan_text(text),
                _ => Vec::new(),
            };
            self.layers.push(DecodedLayer {
                depth,
                source: f.source,
                outcome,
                in_file: None,
            });
            if !next.is_empty() {
                self.walk(next, depth + 1);
            }
        }
    }

    fn stop(&mut self, depth: u32, source: EncodedSource, outcome: DecodeOutcome) {
        self.layers.push(DecodedLayer {
            depth,
            source,
            outcome,
            in_file: None,
        });
        self.stopped = true;
    }

    fn decode_one(&mut self, f: &Found) -> DecodeOutcome {
        let text = match &f.value {
            Value::Missing => return DecodeOutcome::MissingValue,
            Value::NotLiteral => return DecodeOutcome::NotLiteral,
            Value::Text(text) => text,
        };
        let Some(bytes) = base64_decode(text) else {
            return DecodeOutcome::NotBase64;
        };
        if self.decoded_bytes + bytes.len() > MAX_DECODED_BYTES {
            self.stopped = true;
            return DecodeOutcome::SizeLimit {
                max_bytes: MAX_DECODED_BYTES,
            };
        }
        self.decoded_bytes += bytes.len();
        match as_text(&bytes, f.source) {
            Some((encoding, text)) => DecodeOutcome::Text { encoding, text },
            None => DecodeOutcome::NotText,
        }
    }
}

/// 解読したバイト列を文字として読む。読めなければ`None`。
///
/// - **`-EncodedCommand`・`-EncodedArguments`は、PowerShell が必ず UTF-16LE として読む**ので、
///   その読み方のまま出す（読めない符号単位は U+FFFD）。「文字に見えるか」で判定しない——判定すると、
///   制御文字を混ぜるだけで「文字にならない」と表示させて中身を隠せる
/// - **`FromBase64String`の結果は、後ろのコードがどう読むか次第**（UTF-8・UTF-16LE・圧縮・実行ファイル）
///   なので、厳密に読めて文字に見える方のうち、ASCII の割合が高い方を採る。どちらも文字に見えなければ`None`
pub(crate) fn as_text(bytes: &[u8], source: EncodedSource) -> Option<(TextEncoding, String)> {
    match source {
        EncodedSource::EncodedCommand | EncodedSource::EncodedArguments => {
            // **長さが偶数のものだけ**を文字として見せる。UTF-16LE は1文字2バイトなので、
            // 奇数バイトは `-EncodedCommand` の値として成り立たない（PowerShell が書く値は必ず偶数）。
            //
            // これが無いと、綴りの後ろに**たまたま base64 として読める短い語**が続いただけで、
            // 文字化けが解読の結果として画面に出る。実測（2026-10-04）: モデルが
            // `pwsh --enc pwsh --enc <塊>` という行を組み立て、1つ目の `--enc` の引数`pwsh`が
            // 3バイトへ解読されて、意味の無い1文字が「1段目」として出た。
            //
            // **見るのは長さだけで、中身では判断しない。** 「文字に見えない」で落とすと、
            // 制御文字や対にならない代用符号を混ぜるだけで中身を見せずに承認させられる
            // （`control_characters_do_not_hide_an_encoded_command`が固定している）。
            bytes
                .len()
                .is_multiple_of(2)
                .then(|| (TextEncoding::Utf16Le, utf16le_lossy(bytes)))
        }
        // LLM が場所を示した中身・機械で見つけた塊も、後ろのコードがどう読むかは分からないので
        // `FromBase64String`と同じ読み方。
        EncodedSource::FromBase64String
        | EncodedSource::LocatedByModel(_)
        | EncodedSource::BareBase64 => {
            let utf8 = std::str::from_utf8(bytes).ok().map(str::to_string);
            let utf16 = bytes
                .len()
                .is_multiple_of(2)
                .then(|| String::from_utf16(&utf16_units(bytes)).ok())
                .flatten();
            [(TextEncoding::Utf8, utf8), (TextEncoding::Utf16Le, utf16)]
                .into_iter()
                .filter_map(|(encoding, text)| text.map(|t| (encoding, t)))
                .filter(|(_, text)| looks_like_text(text))
                .max_by(|a, b| ascii_ratio(&a.1).total_cmp(&ascii_ratio(&b.1)))
        }
    }
}

fn utf16_units(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

/// PowerShell（`Encoding.Unicode.GetString`）と同じく、読めない符号単位と奇数の最後の1バイトを
/// U+FFFD にして読む。
fn utf16le_lossy(bytes: &[u8]) -> String {
    let mut text = String::from_utf16_lossy(&utf16_units(bytes));
    if !bytes.len().is_multiple_of(2) {
        text.push('\u{FFFD}');
    }
    text
}

/// 文字として見せられるか（空でなく、制御文字が1割以下）。UTF-16LE の ASCII を UTF-8 として読むと
/// 半分が NUL になり、圧縮した中身を UTF-16LE として読むと制御文字が混ざるので、ここで落ちる。
fn looks_like_text(text: &str) -> bool {
    let total = text.chars().count();
    let unreadable = text
        .chars()
        .filter(|&c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
        .count();
    total > 0 && unreadable * 10 <= total
}

/// ASCII の印字可能文字（と改行・タブ）の割合。どちらの読み方かを選ぶのに使う。
fn ascii_ratio(text: &str) -> f32 {
    let total = text.chars().count();
    if total == 0 {
        return 0.0;
    }
    let ascii = text
        .chars()
        .filter(|c| c.is_ascii_graphic() || matches!(c, ' ' | '\t' | '\n' | '\r'))
        .count();
    ascii as f32 / total as f32
}

/// 行の中に見つけた、符号化された中身1つ。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Found {
    source: EncodedSource,
    value: Value,
}

/// 見つけた箇所の値。
#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    /// 綴りの後ろに値が無い。
    Missing,
    /// `FromBase64String`の引数が、字面で決まる文字列ではない（変数・連結・展開する文字列）。
    NotLiteral,
    Text(String),
}

/// 文字列を行として読み、符号化された中身を探す。決まった置き場所（`-EncodedCommand`の値・
/// `FromBase64String('…')`の引数）を読んだうえで、**置き場所を問わず字面に出ている base64 の塊**も探す
/// （[`scan_bare_base64`]）。
fn scan_text(text: &str) -> Vec<Found> {
    let mut found = scan(text, false, 0);
    found.extend(scan_bare_base64(text, &found));
    found
}

/// 機械で探す base64 の塊の、最短の長さ（文字）。これより短い塊は見ない。
const MIN_BARE_BASE64: usize = 16;
/// 機械で探した塊を「読めた」とみなす、解読した中身のASCIIの割合の下限。
///
/// **置き場所が手がかりにならないぶん、中身で絞る。** base64 の文字しか使わない長い語（識別子・ハッシュ）は
/// 偶然このふるいを通ることがあり、通ると承認画面に意味の無い段が1つ増える。走らせるコードはほぼASCIIなので、
/// ここで切る。
const MIN_BARE_ASCII_RATIO: f32 = 0.8;

/// 行の中に**そのまま置かれた base64 の塊**を、場所を問わず探す（`already`に在る値は重ねない）。
///
/// 決まった置き場所の読み取りだけでは、`echo <base64> | ForEach-Object { … FromBase64String($_) }`のように
/// **変数を経由して渡す形**を拾えず、解読が LLM の指し示し（`harness_engine::encoded_span`）頼りになる。
/// ここは同じ中身を機械だけで拾う。
///
/// **読めたものだけを返す**（解読して文字になり、ASCIIが[`MIN_BARE_ASCII_RATIO`]以上）。符号化だと名乗っていない
/// 塊について「解読できなかった」と並べても手がかりにならないからである。
fn scan_bare_base64(text: &str, already: &[Found]) -> Vec<Found> {
    // **詰め物の`=`を外して比べる。** 行を語に割る側は`=`を区切りとして扱うので、決まった置き場所で読んだ値には
    // 詰め物が付かず、ここで拾う塊には付く。そのまま比べると同じ中身が2段に出る。
    let same = |a: &str, b: &str| a.trim_end_matches('=') == b.trim_end_matches('=');
    let seen = |found: &[Found], candidate: &str| {
        found.iter().any(|f| match &f.value {
            Value::Text(text) => same(text, candidate),
            _ => false,
        })
    };
    let mut out = Vec::new();
    for candidate in base64_runs(text) {
        if seen(already, &candidate) || seen(&out, &candidate) {
            continue;
        }
        let readable = base64_decode(&candidate)
            .and_then(|bytes| as_text(&bytes, EncodedSource::BareBase64))
            .is_some_and(|(_, text)| ascii_ratio(&text) >= MIN_BARE_ASCII_RATIO);
        if readable {
            out.push(Found {
                source: EncodedSource::BareBase64,
                value: Value::Text(candidate),
            });
        }
    }
    out
}

/// `text`の中の、base64 として読みうる塊（長さが[`MIN_BARE_BASE64`]以上で4の倍数のもの）。
///
/// **4の倍数だけを見る**——PowerShell も `.NET` も詰め物まで揃った形しか受け付けないし、普通の語を拾う量がここで大きく減る。
fn base64_runs(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut run = String::new();
    let push = |run: &mut String, out: &mut Vec<String>| {
        if run.len() >= MIN_BARE_BASE64 && run.len().is_multiple_of(4) {
            out.push(run.clone());
        }
        run.clear();
    };
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' {
            run.push(c);
        } else {
            push(&mut run, &mut out);
        }
    }
    push(&mut run, &mut out);
    out
}

/// `in_powershell`は、行の頭が既に PowerShell の起動の引数の中か（引用符の中を読み直すとき）。
fn scan(text: &str, in_powershell: bool, nesting: u32) -> Vec<Found> {
    let tokens = tokenize(text);
    let mut out = Vec::new();
    let mut in_powershell = in_powershell;
    let mut i = 0;
    while i < tokens.len() {
        let word = match &tokens[i] {
            Token::Separator(_) => {
                in_powershell = false;
                i += 1;
                continue;
            }
            Token::Group(_) => {
                i += 1;
                continue;
            }
            Token::Word(word) => word,
        };
        // `[Convert]::FromBase64String('…')` は PowerShell の起動と関係なく現れる。
        if is_from_base64_call(&word.text) {
            let (value, next) = call_argument(&tokens, i);
            out.push(Found {
                source: EncodedSource::FromBase64String,
                value,
            });
            i = next;
            continue;
        }
        if in_powershell {
            if let Some(source) = encoded_switch(&word.text) {
                let (value, next) = switch_value(&tokens, i);
                out.push(Found { source, value });
                i = next;
                continue;
            }
            if rest_of_arguments(&word.text).is_some() {
                // 残りはコード（またはスクリプトの引数）。新しい文として読み直す。
                in_powershell = false;
            } else if word.quoted {
                // `Process.Start('pwsh', '-NoProfile -e …')`: 引数の並びを1つの文字列で渡す形。
                // スイッチで始まるときだけ、同じ起動の続きとして読む。
                let continues = strip_switch_prefix(word.text.trim()).is_some();
                out.extend(scan_quoted(&word.text, continues, nesting));
            }
        } else if is_powershell(&word.text) {
            in_powershell = true;
        } else if word.quoted {
            // `cmd /c "pwsh -e …"`・`ssh host 'pwsh -e …'`: 文字列の中で起こす形。
            out.extend(scan_quoted(&word.text, false, nesting));
        }
        i += 1;
    }
    out
}

fn scan_quoted(text: &str, in_powershell: bool, nesting: u32) -> Vec<Found> {
    if nesting >= MAX_QUOTE_NESTING {
        return Vec::new();
    }
    scan(text, in_powershell, nesting + 1)
}

/// `run_program`の PowerShell の引数（既に1要素ずつに割れている）から探す。
fn scan_powershell_args(args: &[String]) -> Vec<Found> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(source) = encoded_switch(arg) {
            let value = args
                .get(i + 1)
                .map_or(Value::Missing, |v| Value::Text(v.clone()));
            out.push(Found { source, value });
            i += 2;
            continue;
        }
        match rest_of_arguments(arg) {
            // PowerShell は`-Command`の残りを空白で繋いで1つのコードにする。
            Some(Rest::Code) => {
                out.extend(scan_text(&args[i + 1..].join(" ")));
                return out;
            }
            Some(Rest::Script) => return out,
            None => {}
        }
        if switch_name(arg).is_none() {
            out.extend(scan_text(arg));
        }
        i += 1;
    }
    out
}

/// `[Convert]::FromBase64String` の呼び出しの綴りか（名前空間の有無・大小を問わない）。
fn is_from_base64_call(word: &str) -> bool {
    word.to_ascii_lowercase().ends_with("frombase64string")
}

/// スイッチの値（括弧は跨ぐが、**文の区切りは跨がない**）と、その次の位置。
fn switch_value(tokens: &[Token], i: usize) -> (Value, usize) {
    for (j, token) in tokens.iter().enumerate().skip(i + 1) {
        match token {
            Token::Group(_) => continue,
            Token::Word(w) => return (Value::Text(w.text.clone()), j + 1),
            Token::Separator(_) => return (Value::Missing, j),
        }
    }
    (Value::Missing, tokens.len())
}

/// `FromBase64String(…)`の引数と、その次の位置。**`('…')`の形のときだけ値になる**——
/// `('ab'+'cd')`・`($s)`・`("$x")`・括弧の無い参照（`$f = [Convert]::FromBase64String`）は
/// 実行時に決まるので、字面を解読すると別物を見せてしまう。
fn call_argument(tokens: &[Token], i: usize) -> (Value, usize) {
    match tokens.get(i + 1..i + 4) {
        Some([Token::Group('('), Token::Word(w), Token::Group(')')]) if w.literal => {
            (Value::Text(w.text.clone()), i + 4)
        }
        _ => (Value::NotLiteral, i + 1),
    }
}

/// 標準の base64（`+/`、`=`の詰め物は任意）。空白は読み飛ばす。読めなければ・空なら`None`。
///
/// **詰め物を欠くものも読む。** PowerShell はそれを断るが、ここは表示のためなので広い側へ倒す
/// （読めたものを隠さない）。
pub(crate) fn base64_decode(text: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for c in text
        .bytes()
        .filter(|c| !c.is_ascii_whitespace() && *c != b'=')
    {
        acc = (acc << 6) | value(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
#[path = "encoded_command_tests.rs"]
mod tests;
