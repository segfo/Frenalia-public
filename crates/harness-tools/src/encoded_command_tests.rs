//! 符号化されたコードの解読の回帰テスト（[BUG-222](../../../docs/bugs/BUG-222.md)・
//! [BUG-224](../../../docs/bugs/BUG-224.md)）。内部の綴りの判定へ触れるため同じクレートに置く
//! （`docs/CODE-STRUCTURE-RULES.md`規則2）。
//!
//! 「走る」「走らない」と書いた綴りは、2026-10-04 に pwsh 7.6.6 と Windows PowerShell 5.1 へ argv を
//! 直接渡して実測したもの（モジュールdocの表）。

use super::*;

/// UTF-16LE の base64（PowerShell の`-EncodedCommand`と同じ作り方）。
fn enc16(code: &str) -> String {
    let bytes: Vec<u8> = code.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    base64_encode(&bytes)
}

fn enc8(code: &str) -> String {
    base64_encode(code.as_bytes())
}

/// 標準の base64（試験でだけ使うので、詰め物まで素直に作る）。
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// 1段だけ解読できたことを確かめる（中身と符号化）。
fn single(layers: &[DecodedLayer]) -> (&EncodedSource, TextEncoding, &str) {
    assert_eq!(layers.len(), 1, "{layers:?}");
    match &layers[0].outcome {
        DecodeOutcome::Text { encoding, text } => (&layers[0].source, *encoding, text.as_str()),
        other => panic!("expected decoded text, got {other:?}"),
    }
}

fn args(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// [BUG-224] ユーザーが実機で見た行（中身は`systeminfo`。要約は`Write-Hello`だと書いた）。
#[test]
fn the_line_the_user_saw_decodes_to_systeminfo() {
    let line = "pwsh --enc cwB5AHMAdABlAG0AaQBuAGYAbwA=";
    let layers = decode_shell_line(line);
    let (source, encoding, text) = single(&layers);
    assert_eq!(*source, EncodedSource::EncodedCommand);
    assert_eq!(encoding, TextEncoding::Utf16Le);
    assert_eq!(text, "systeminfo");
    assert_eq!(layers[0].depth, 1);
    assert!(line_has_encoded_switch(line));
}

/// [BUG-222] PowerShell が受け付ける綴りはどれも検出し、解読する。
#[test]
fn every_spelling_powershell_accepts_is_decoded() {
    let blob = enc16("systeminfo");
    for (program, switch) in [
        ("pwsh", "-EncodedCommand"),
        ("pwsh", "-encodedcommand"),
        ("pwsh", "-eNc"),
        ("pwsh", "-e"),
        ("pwsh", "-en"),
        ("pwsh", "-enco"),
        ("pwsh", "-encoded"),
        ("pwsh", "-ec"),
        ("pwsh", "-EC"),
        ("pwsh", "--enc"),
        ("pwsh", "--ec"),
        ("pwsh", "/enc"),
        ("pwsh", "/ec"),
        ("pwsh", "/EncodedCommand"),
        ("pwsh", "\u{2013}enc"),
        ("pwsh", "\u{2014}e"),
        ("pwsh", "\u{2015}ec"),
        ("pwsh", "\u{2013}\u{2013}enc"),
        // 実測: PowerShell は引数の前後の空白を削ってから見る。
        ("pwsh", "' -enc'"),
        ("pwsh", "\"-enc \""),
        ("pwsh", "'\t-ec'"),
        // 実測: 行を読む PowerShell は U+2018〜U+201E を普通の引用符として剥がす。
        ("pwsh", "\u{2018}-e\u{2019}"),
        ("pwsh", "\u{201C}-enc\u{201D}"),
        ("powershell", "-enc"),
        ("powershell.exe", "-ec"),
        ("PowerShell.EXE", "-e"),
        (
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-enc",
        ),
        ("/usr/bin/pwsh", "-enc"),
    ] {
        let line = format!("{program} -NoProfile {switch} {blob}");
        let layers = decode_shell_line(&line);
        let (_, _, text) = single(&layers);
        assert_eq!(text, "systeminfo", "{line}");
        assert!(line_has_encoded_switch(&line), "{line}");
    }
}

/// [BUG-222] PowerShell を起こす書き方の違い（実測で走ったもの）でも検出する。
#[test]
fn every_way_of_launching_powershell_is_followed() {
    let blob = enc16("systeminfo");
    for line in [
        // 呼び出し演算子と、空白を含むパス
        format!(r"& 'C:\Program Files\PowerShell\7\pwsh.exe' -NoProfile -enc {blob}"),
        // `-Command`の後ろで2つ目の PowerShell を起こす（引用符なし・あり）
        format!("pwsh -NoProfile -c pwsh -NoProfile -enc {blob}"),
        format!("pwsh -NoProfile -co 'pwsh -e {blob}'"),
        // 別のコマンドの文字列の中で起こす
        format!(r#"cmd /c "powershell -e {blob}""#),
        format!("ssh build-host 'pwsh -ec {blob}'"),
        // 引数の並びを1つの文字列で渡す
        format!("[Diagnostics.Process]::Start('pwsh', '-NoProfile -e {blob}').WaitForExit()"),
        // 配列で渡す・解析を止める記号の後ろ
        format!("pwsh -NoProfile @('-e', '{blob}')"),
        format!("pwsh --% -NoProfile -e {blob}"),
        // 代入の右辺・リダイレクトを挟む・行の継続
        format!("$out=pwsh -e {blob}"),
        format!("pwsh -NoProfile 2>&1 -e {blob}"),
        format!("pwsh -NoProfile `\n  -e {blob}"),
        format!("pwsh -NoProfile `\r\n  -e {blob}"),
        // `;`の後ろの別の文
        format!("Get-Date; pwsh -ec {blob}"),
    ] {
        assert!(line_has_encoded_switch(&line), "{line}");
        let layers = decode_shell_line(&line);
        let (_, _, text) = single(&layers);
        assert_eq!(text, "systeminfo", "{line}");
    }
}

/// 対照（`bug-pattern-rules` B-35）: **PowerShell が受け付けない綴りと、別のコマンドの`-e`は拾わない。**
#[test]
fn spellings_powershell_rejects_and_other_commands_are_not_touched() {
    let blob = enc16("systeminfo");
    for line in [
        // 別のコマンドのスイッチ
        "grep -e foo src".to_string(),
        "git log -e".to_string(),
        "git commit -e -m x".to_string(),
        "sed -e s/a/b/ notes.txt".to_string(),
        format!("python -e {blob}"),
        "node -e console.log(1)".to_string(),
        // 文字列の中に`-e`があっても、PowerShell を起こしていなければ拾わない
        r#"git commit -m "fix the -e handling""#.to_string(),
        "echo 'pwsh is great'; grep -e x src".to_string(),
        // PowerShell を起こした後に、区切りを挟んだ別のコマンド
        "pwsh -NoProfile -c Get-Date; grep -e foo src".to_string(),
        "pwsh -File build.ps1 | grep -e x".to_string(),
        // コードの中のコマンドレットの引数（`-ea`は`-ErrorAction`の略で、起動のスイッチではない）
        "pwsh -c Get-ChildItem -ea Stop".to_string(),
        "pwsh -Command Remove-Item x -ea SilentlyContinue".to_string(),
        "pwsh -NoProfile -c \"Get-ChildItem -ea Stop\"".to_string(),
        // スクリプトの引数（実測: `-File`の後ろの`-e`は起動のスイッチにならない）
        format!("pwsh -File build.ps1 -e {blob}"),
        // PowerShell が受け付けない前置き
        format!("pwsh ---enc {blob}"),
        format!("pwsh //enc {blob}"),
        format!("pwsh -\u{2013}enc {blob}"),
        format!("pwsh -enc:{blob}"),
        format!("pwsh -ecx {blob}"),
        format!("pwsh -encodedcommandx {blob}"),
        // 似た語だが別のスイッチ
        "pwsh -ex Bypass -c Get-Date".to_string(),
        "Select-String -Pattern enc -Path notes.txt".to_string(),
    ] {
        // **符号化スイッチとしては読まない。** 行の中に置かれた塊として読むのは構わない（置き場所を問わない
        // 読み取り。`BareBase64`）——確かめたいのは「別のコマンドの`-e`を PowerShell のスイッチと取り違えない」
        // ことである（[BUG-222]の対照）。
        let sources: Vec<EncodedSource> = decode_shell_line(&line)
            .into_iter()
            .map(|l| l.source)
            .collect();
        assert!(
            sources.iter().all(|s| *s == EncodedSource::BareBase64),
            "スイッチとして読んだ: {line} -> {sources:?}"
        );
        assert!(!line_has_encoded_switch(&line), "{line}");
    }
}

/// `-EncodedArguments`（引数の側を符号化する）も同じ扱いで見せる。
#[test]
fn encoded_arguments_are_decoded_too() {
    let blob = enc16("<Objs><S>ARG_OK</S></Objs>");
    for switch in ["-ea", "-encodeda", "-EncodedArguments", "--ea", "/ea"] {
        let line = format!("pwsh -NoProfile {switch} {blob}");
        let layers = decode_shell_line(&line);
        let (source, _, text) = single(&layers);
        assert_eq!(*source, EncodedSource::EncodedArguments, "{line}");
        assert!(text.contains("ARG_OK"), "{text}");
        assert!(line_has_encoded_switch(&line), "{line}");
    }
}

/// 入れ子（`-enc`の中に`-enc`）は段ごとに解読する。
#[test]
fn nesting_is_decoded_one_layer_at_a_time() {
    let inner = enc16("systeminfo");
    let middle = enc16(&format!("pwsh -enc {inner}"));
    let layers = decode_shell_line(&format!("powershell -ec {middle}"));
    assert_eq!(layers.len(), 2, "{layers:?}");
    assert_eq!(layers[0].depth, 1);
    assert_eq!(layers[1].depth, 2);
    match (&layers[0].outcome, &layers[1].outcome) {
        (DecodeOutcome::Text { text: first, .. }, DecodeOutcome::Text { text: second, .. }) => {
            assert!(first.contains("pwsh -enc"), "{first}");
            assert_eq!(second, "systeminfo");
        }
        other => panic!("{other:?}"),
    }
}

/// 書き方の違う段の入れ子（`-enc`の中の`FromBase64String`）も続けて解読する。
#[test]
fn a_from_base64_string_inside_an_encoded_command_is_the_next_layer() {
    let inner = enc8("systeminfo");
    let outer = enc16(&format!(
        "iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{inner}')))"
    ));
    let layers = decode_shell_line(&format!("pwsh -e {outer}"));
    assert_eq!(layers.len(), 2, "{layers:?}");
    assert_eq!(layers[1].depth, 2);
    assert_eq!(layers[1].source, EncodedSource::FromBase64String);
    assert_eq!(
        layers[1].outcome,
        DecodeOutcome::Text {
            encoding: TextEncoding::Utf8,
            text: "systeminfo".to_string()
        }
    );
}

/// `[Convert]::FromBase64String('…')`の文字列リテラルも解読する。UTF-16LE と UTF-8 のどちらでも、
/// 読める方を出す。
#[test]
fn from_base64_string_literals_are_decoded_in_either_encoding() {
    for (blob, expected_encoding) in [
        (enc16("systeminfo"), TextEncoding::Utf16Le),
        (enc8("systeminfo"), TextEncoding::Utf8),
        (enc8("Write-Output 日本語"), TextEncoding::Utf8),
    ] {
        let line = format!(
            "$b=[Convert]::FromBase64String('{blob}'); [Text.Encoding]::Unicode.GetString($b)"
        );
        let layers = decode_shell_line(&line);
        let (source, encoding, _) = single(&layers);
        assert_eq!(*source, EncodedSource::FromBase64String);
        assert_eq!(encoding, expected_encoding, "{line}");
    }
    // 名前空間を付けた綴り・大小の違い・二重引用符・スマート引用符でも同じ。
    for (call, open, close) in [
        ("[System.Convert]::FromBase64String", "'", "'"),
        ("[convert]::frombase64string", "\"", "\""),
        ("[Convert]::FromBase64String", "\u{2018}", "\u{2019}"),
    ] {
        let layers = decode_shell_line(&format!("{call}({open}{}{close})", enc8("systeminfo")));
        let (_, _, text) = single(&layers);
        assert_eq!(text, "systeminfo");
    }
}

/// 実行時に決まるもの（変数・式・連結・展開する文字列）は「解読できなかった」として残す。
/// **黙って落とさない。字面の一部を解読して別物を見せない。**
#[test]
fn material_that_is_not_a_literal_is_reported_as_such() {
    let half = enc8("systeminfo");
    for line in [
        "[Convert]::FromBase64String($payload)".to_string(),
        format!(
            "[Convert]::FromBase64String('{}'+'{}')",
            &half[..8],
            &half[8..]
        ),
        format!("[Convert]::FromBase64String(\"$prefix{half}\")"),
        "$f = [Convert]::FromBase64String; $f".to_string(),
    ] {
        let layers = decode_shell_line(&line);
        assert_eq!(layers.len(), 1, "{line}: {layers:?}");
        assert_eq!(layers[0].outcome, DecodeOutcome::NotLiteral, "{line}");
    }

    let layers = decode_shell_line("pwsh -enc $payload");
    assert_eq!(layers[0].outcome, DecodeOutcome::NotBase64);

    let layers = decode_shell_line("pwsh -enc");
    assert_eq!(layers[0].outcome, DecodeOutcome::MissingValue);

    let layers = decode_shell_line("pwsh -enc; Get-Date");
    assert_eq!(layers[0].outcome, DecodeOutcome::MissingValue);

    let layers = decode_shell_line("pwsh -enc !!!");
    assert_eq!(layers[0].outcome, DecodeOutcome::NotBase64);

    // base64 は読めるが文字にならない（圧縮された中身）。
    let gzip = base64_encode(&[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let layers = decode_shell_line(&format!("[Convert]::FromBase64String('{gzip}')"));
    assert_eq!(layers[0].outcome, DecodeOutcome::NotText);
}

/// 綴りの後ろに**たまたま base64 として読める短い語**が続いただけのときは、文字化けを段として出さない。
///
/// UTF-16LE は1文字2バイトなので、**奇数バイトは `-EncodedCommand` の値として成り立たない**。
/// 実測（2026-10-04）: モデルが `pwsh --enc pwsh --enc <塊>` という行を組み立て、1つ目の `--enc` の
/// 引数 `pwsh` が3バイトへ解読されて、意味の無い1文字が「1段目」として画面に出た。
#[test]
fn a_switch_followed_by_a_short_word_is_not_shown_as_text() {
    // `pwsh` は base64 として読めて3バイトになる（奇数）。
    assert_eq!(base64_decode("pwsh").map(|b| b.len()), Some(3));

    let blob = enc16("systeminfo");
    let layers = decode_shell_line(&format!("pwsh --enc pwsh --enc {blob}"));

    // 1つ目の `--enc` は「文字として成り立たない」。文字化けを出さない。
    assert_eq!(layers[0].outcome, DecodeOutcome::NotText, "{layers:?}");
    // 2つ目はこれまでどおり読める。
    assert!(
        layers.iter().any(
            |l| matches!(&l.outcome, DecodeOutcome::Text { text, .. } if text == "systeminfo")
        ),
        "{layers:?}"
    );
}

/// `-EncodedCommand`は PowerShell が必ず UTF-16LE として読むので、制御文字を混ぜても**その読み方のまま
/// 出す**。「文字に見えない」で隠すと、制御文字を足すだけで中身を見せずに承認させられる。
/// **長さが偶数かどうかしか見ない**のはこのためである（中身では判断しない）。
#[test]
fn control_characters_do_not_hide_an_encoded_command() {
    let code = format!("Write-Output '{}'; systeminfo", "\u{7}".repeat(64));
    let layers = decode_shell_line(&format!("pwsh -e {}", enc16(&code)));
    let (_, encoding, text) = single(&layers);
    assert_eq!(encoding, TextEncoding::Utf16Le);
    assert_eq!(text, code);
}

/// 深さの上限で止めたら、止めたことを段として残す（黙って切らない）。
#[test]
fn stopping_at_the_depth_limit_is_recorded() {
    let mut blob = enc16("systeminfo");
    for _ in 0..MAX_DECODE_DEPTH + 2 {
        blob = enc16(&format!("pwsh -enc {blob}"));
    }
    let layers = decode_shell_line(&format!("pwsh -enc {blob}"));
    assert_eq!(
        layers.len() as u32,
        MAX_DECODE_DEPTH + 1,
        "上限までの段と、止めた1段: {layers:?}"
    );
    assert_eq!(
        layers.last().unwrap().outcome,
        DecodeOutcome::DepthLimit {
            max_depth: MAX_DECODE_DEPTH
        }
    );
    assert_eq!(layers.last().unwrap().depth, MAX_DECODE_DEPTH + 1);
}

/// 大きさの上限で止めたら、止めたことを段として残す。
#[test]
fn stopping_at_the_size_limit_is_recorded() {
    let big = enc16(&"Write-Output x; ".repeat(MAX_DECODED_BYTES / 8));
    let layers = decode_shell_line(&format!("pwsh -enc {big}"));
    assert_eq!(layers.len(), 1, "{:?}", layers[0].outcome);
    assert_eq!(
        layers[0].outcome,
        DecodeOutcome::SizeLimit {
            max_bytes: MAX_DECODED_BYTES
        }
    );
}

/// 段の数の上限で止めたら、止めたことを段として残す。
#[test]
fn stopping_at_the_layer_count_limit_is_recorded() {
    let blob = enc8("systeminfo");
    let mut line = String::new();
    for _ in 0..MAX_DECODED_LAYERS + 3 {
        line.push_str(&format!("[Convert]::FromBase64String('{blob}'); "));
    }
    let layers = decode_shell_line(&line);
    assert_eq!(layers.len(), MAX_DECODED_LAYERS + 1, "{layers:?}");
    assert_eq!(
        layers.last().unwrap().outcome,
        DecodeOutcome::CountLimit {
            max_layers: MAX_DECODED_LAYERS
        }
    );
}

/// 引用符の中で起こした PowerShell は、何段重ねても読む。
///
/// 3段（二重の中の単一の中の二重。内側の`"`は PowerShell の書き方で`""`）と、20段。入れ子は
/// 2段ごとに長さが倍になるので、20段で約4KB——**上限（[`MAX_QUOTE_NESTING`]）を小さくすると、
/// この長さの行の奥に置いた`pwsh -e`を見落とす**（以前の版の上限 8 がそうだった）。
#[test]
fn powershell_launched_inside_nested_quotes_is_read_at_any_depth() {
    let blob = enc16("systeminfo");
    let shallow = format!(r#"cmd /c "ssh host 'cmd /c ""pwsh -e {blob}""'""#);
    let mut deep = format!("pwsh -e {blob}");
    for level in 0..20 {
        deep = match level % 2 {
            0 => format!("ssh host '{}'", deep.replace('\'', "''")),
            _ => format!("cmd /c \"{}\"", deep.replace('"', "\"\"")),
        };
    }
    assert!(deep.len() < 8192, "{}", deep.len());
    for line in [shallow, deep] {
        assert!(line_has_encoded_switch(&line), "{line}");
        let layers = decode_shell_line(&line);
        let (_, _, text) = single(&layers);
        assert_eq!(text, "systeminfo");
    }
}

/// `run_program`の引数からも解読する（program が PowerShell のときだけスイッチを見る）。
#[test]
fn program_arguments_are_decoded_only_for_powershell() {
    let blob = enc16("systeminfo");

    let layers = decode_program_args("pwsh", &args(&["-NoProfile", "-enc", &blob]));
    let (_, _, text) = single(&layers);
    assert_eq!(text, "systeminfo");

    // 前後に空白の付いた要素も、PowerShell と同じく削って読む。
    let layers = decode_program_args("pwsh", &args(&[" -enc ", &blob]));
    let (_, _, text) = single(&layers);
    assert_eq!(text, "systeminfo");

    // 対照: 別のプログラムの`-e`は符号化スイッチとして見ない（引数に置かれた塊としてなら読む）。
    for program in ["grep", "python"] {
        let layers = decode_program_args(program, &args(&["-e", &blob]));
        assert!(
            layers.iter().all(|l| l.source == EncodedSource::BareBase64),
            "{program}: スイッチとして読んだ: {layers:?}"
        );
    }

    // その場のコードの中の`FromBase64String`も見る（引数の中身を行として読む）。
    let code = format!(
        "iex([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{}')))",
        enc8("systeminfo")
    );
    let layers = decode_program_args("pwsh", &args(&["-c", &code]));
    let (source, _, text) = single(&layers);
    assert_eq!(*source, EncodedSource::FromBase64String);
    assert_eq!(text, "systeminfo");

    // `-Command`の残りは空白で繋いでコードとして読む（実測: `pwsh -c pwsh -enc …`は走る）。
    let layers = decode_program_args("pwsh", &args(&["-c", "pwsh", "-enc", &blob]));
    let (_, _, text) = single(&layers);
    assert_eq!(text, "systeminfo");

    // PowerShell でないプログラムが PowerShell を起こす形（`cmd /c pwsh -e …`）。
    let layers = decode_program_args("cmd", &args(&["/c", "pwsh", "-e", &blob]));
    let (_, _, text) = single(&layers);
    assert_eq!(text, "systeminfo");

    // スクリプトの引数はスイッチとして読まない（実測: 走らない）。
    assert!(decode_program_args("pwsh", &args(&["-File", "x.ps1", "-e", &blob])).is_empty());
    assert!(decode_program_args("pwsh", &args(&["-c", "Get-ChildItem", "-ea", "Stop"])).is_empty());

    // スイッチの値そのものは、二重に読まない（`-enc`の値を行としても読まない）。
    let layers = decode_program_args("pwsh", &args(&["-enc", &blob]));
    assert_eq!(layers.len(), 1, "{layers:?}");
}

/// 綴りの判定は1箇所（[`encoded_switch`]）で、T-09 の検出と解読が同じものを見る（`B-05`）。
#[test]
fn the_switch_table_is_shared_by_detection_and_decoding() {
    for (arg, expected) in [
        ("-e", Some(EncodedSource::EncodedCommand)),
        ("-ec", Some(EncodedSource::EncodedCommand)),
        ("-encoded", Some(EncodedSource::EncodedCommand)),
        ("-encodedcommand", Some(EncodedSource::EncodedCommand)),
        ("/EC", Some(EncodedSource::EncodedCommand)),
        (" -enc\t", Some(EncodedSource::EncodedCommand)),
        ("-ea", Some(EncodedSource::EncodedArguments)),
        ("-encodeda", Some(EncodedSource::EncodedArguments)),
        ("--ea", Some(EncodedSource::EncodedArguments)),
        ("-ex", None),
        ("-noprofile", None),
        ("-", None),
        ("", None),
        ("enc", None),
        ("-enc=x", None),
        ("- enc", None),
    ] {
        assert_eq!(encoded_switch(arg), expected, "{arg:?}");
    }
}

/// 試験の入力を作る: 文字列を UTF-16LE の base64 にする（PowerShell の`-EncodedCommand`が受け取る形）。
fn base64_utf16(text: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().fold(0u32, |acc, b| (acc << 8) | *b as u32) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// **置き場所を問わず、行の中に置かれた base64 の塊を機械で読む。**
///
/// 2026-10-04、ユーザーの画面で `echo <base64> | ForEach-Object { … FromBase64String($_) }` が出た——
/// `FromBase64String`の引数が変数なので決まった置き場所の読み取りでは拾えず、解読が LLM の指し示し頼りになっていた。
#[test]
fn a_base64_blob_sitting_anywhere_in_the_line_is_decoded() {
    let inner = base64_utf16("systeminfo");
    let line = format!(
        "echo {inner} | ForEach-Object {{ [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($_)) }}"
    );
    let layers = decode_shell_line(&line);
    assert!(
        layers.iter().any(|l| matches!(
            (&l.source, &l.outcome),
            (EncodedSource::BareBase64, DecodeOutcome::Text { text, .. }) if text == "systeminfo"
        )),
        "{layers:?}"
    );
}

/// 決まった置き場所で読めた塊は、**同じものを2回出さない**（`-EncodedCommand`の値を、置き場所を問わない読み取りが
/// もう1段として重ねない）。
#[test]
fn a_blob_found_at_a_known_place_is_not_reported_twice() {
    let line = format!("pwsh -enc {}", base64_utf16("systeminfo"));
    let layers = decode_shell_line(&line);
    assert_eq!(layers.len(), 1, "{layers:?}");
    assert_eq!(layers[0].source, EncodedSource::EncodedCommand);
}

/// **符号化と名乗っていない塊は、読めたときだけ出す。** 普通のコマンド・長い識別子・読めない塊では1段も出さない
/// （出すと、承認画面が意味の無い段で埋まる）。
#[test]
fn ordinary_lines_do_not_produce_bare_base64_layers() {
    for line in [
        "git status",
        "ls -la C:\\Users\\segfo\\Documents",
        "Get-ChildItem | ForEach-Object { $_.FullName }",
        // base64 の文字だけでできた長い語（4の倍数）。解読しても文字にならないので出さない。
        "Invoke-SomethingVeryLongIdentifierHere",
        // 4の倍数でない塊は見ない。
        "echo cwB5AHMAdABlAG0AaQBuAGYAbwA",
        // 短い塊は見ない。
        "echo cwB5AHMA",
    ] {
        assert!(
            decode_shell_line(line).is_empty(),
            "{line}: {:?}",
            decode_shell_line(line)
        );
    }
}

/// 置き場所を問わない読み取りでも、**解読した中身の中をさらに読む**（段が重なる）。
#[test]
fn a_bare_blob_is_read_again_for_the_next_layer() {
    let inner = base64_utf16("systeminfo");
    let outer = base64_utf16(&format!("pwsh --enc {inner}"));
    let layers = decode_shell_line(&format!("echo {outer} | ForEach-Object {{ $_ }}"));
    let texts: Vec<(u32, String)> = layers
        .iter()
        .filter_map(|l| match &l.outcome {
            DecodeOutcome::Text { text, .. } => Some((l.depth, text.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        texts,
        vec![
            (1, format!("pwsh --enc {inner}")),
            (2, "systeminfo".to_string())
        ],
        "{layers:?}"
    );
}
