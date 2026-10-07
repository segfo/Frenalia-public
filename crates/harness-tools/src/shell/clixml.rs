//! 子の PowerShell が CLIXML で書いた出力を、PowerShell のコンソールが出すのと同じ文字へ戻す
//! （[BUG-238]）。
//!
//! # なぜ要るか
//!
//! `powershell.exe` は `-EncodedCommand` で起動され、標準エラーが端末でないと、エラー・警告・
//! 進行表示・情報の各ストリームを `#< CLIXML` の行で始まる XML（CLIXML。PowerShell が
//! オブジェクトを別のプロセスへ渡すときの直列化形式）にして標準エラーへ書く。呼び出し元も
//! PowerShell で、XML を受け取って元のオブジェクトへ戻す、という前提の形式である。
//! `-Command` で起動すれば平文で、`-OutputFormat Text` を付けても XML のまま（2026-10-07 実測）。
//!
//! モデルが `run_shell` の中で `powershell -Enc …` を撃つと、この XML がそのまま結果欄に入り、
//! **本当のエラーが XML の奥に埋もれた**。TUI の結果欄は先頭400文字しか出さないので、
//! 枠が XML の前置きだけで埋まり、`pwsh` が見つからないというエラーも `[exit code: 1]` も
//! 見えなかった。
//!
//! # 戻し方
//!
//! 区画は「行頭の `#< CLIXML` から `</Objs>` まで」。区画の前後にある普通の出力は触らない。
//!
//! | 要素 | 本文への置き方 |
//! |---|---|
//! | `<S S="Error">` | 文字へ戻してそのまま並べる（1要素が1行の断片で、改行は中身に入っている） |
//! | `<S S="warning">`・`verbose`・`debug` | `WARNING: `・`VERBOSE: `・`DEBUG: ` を前に付けた1行（コンソールと同じ） |
//! | `<Obj S="information">` | `<ToString>` の文字を1行。ただし Tags に `PSHOST` がある記録（`Write-Host`）は置かない |
//! | `<Obj S="progress">` | 本文に置かない。活動名と件数を [`Restored::progress`] へ |
//!
//! `Write-Host` の記録を置かないのは、同じ文字が**標準出力に既に出ている**からである
//! （2026-10-07 実測。置くと同じ行が2回出る）。
//!
//! # 隠さない
//!
//! 読めない要素（上の表に無いもの・壊れた XML・`</Objs>` が来る前に途切れたもの）に当たったら、
//! **そこから区画の終わりまでは元の文字列のまま**残す（`bug-pattern-rules` B-10・B-33:
//! 隠さない側へ倒す）。読み違えて別のストリームとして見せるより、XML のまま見せる方が害が小さい。
//! 進行表示は本文から外すが捨てない（フッタへ件数ごと出す、[`footer_note`]）。
//!
//! # 判定に文言を使わない
//!
//! 区画を見つける手がかりは形式の印（`#< CLIXML` の行と XML の要素名）だけで、メッセージの文言は
//! 見ない（文言は OS の言語で翻訳される。B-33）。同じ理由で、**内側の PowerShell が出した
//! 起動時警告（`InitializeDefaultDrives`）は本文に残る**——外側のシェルの警告（境界印の前に出て
//! `shell-startup-noise` 枠へ行くもの、BUG-086）と文言で突き合わせれば外せるが、それはしない。
//!
//! [BUG-238]: ../../../../docs/bugs/BUG-238.md

const HEADER: &str = "#< CLIXML";
const OBJS_CLOSE: &str = "</Objs>";
/// フッタに名前を出す進行表示の活動の数。これを超えた分は種類の数だけ言う。
const NOTE_MAX_ACTIVITIES: usize = 5;
/// フッタに出す活動名1つの長さ（文字）。
const NOTE_MAX_ACTIVITY_CHARS: usize = 120;

/// 1本のストリームを戻した結果。
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Restored {
    /// 区画を文字へ戻したあとのストリーム。
    pub(crate) text: String,
    /// 本文から外した進行表示の活動名と件数（最初に出た順）。
    pub(crate) progress: Vec<(String, usize)>,
    /// 最後まで文字へ戻した区画の数。
    pub(crate) restored_blocks: usize,
    /// 途中から元の文字列のまま残した区画の数。
    pub(crate) raw_blocks: usize,
}

/// ストリームの中の CLIXML の区画を文字へ戻す。区画が無ければ受け取った文字列をそのまま返す。
pub(crate) fn restore(stream: String) -> Restored {
    if !stream.contains(HEADER) {
        return Restored {
            text: stream,
            ..Default::default()
        };
    }
    let mut restored = Restored::default();
    let mut rest = stream.as_str();
    while let Some(at) = find_header(rest) {
        restored.text.push_str(&rest[..at]);
        rest = restore_block(&rest[at..], &mut restored);
    }
    restored.text.push_str(rest);
    restored
}

/// 戻した区画があれば、そのことを言うフッタの1行。標準出力と標準エラーの両方をまとめて渡す。
pub(crate) fn footer_note(streams: &[&Restored]) -> Option<String> {
    let restored: usize = streams.iter().map(|s| s.restored_blocks).sum();
    let raw: usize = streams.iter().map(|s| s.raw_blocks).sum();
    if restored + raw == 0 {
        return None;
    }
    let mut progress: Vec<(String, usize)> = Vec::new();
    for (activity, count) in streams.iter().flat_map(|s| &s.progress) {
        add_progress(&mut progress, activity, *count);
    }

    let mut note = String::from(
        "[powershell-clixml: 子のPowerShellが -EncodedCommand で起動され、エラー等をXML（CLIXML）で\
         書いていたので、本文では文字へ戻した",
    );
    if raw > 0 {
        note.push_str("。読めない要素があった所から先は、元のXMLのまま残した");
    }
    if !progress.is_empty() {
        note.push_str("。進行表示（本文には置いていない）: ");
        let shown: Vec<String> = progress
            .iter()
            .take(NOTE_MAX_ACTIVITIES)
            .map(|(activity, count)| {
                let activity: String = activity
                    .chars()
                    .take(NOTE_MAX_ACTIVITY_CHARS)
                    .map(|c| if c.is_control() { ' ' } else { c })
                    .collect();
                format!("\"{activity}\" ×{count}")
            })
            .collect();
        note.push_str(&shown.join(", "));
        if progress.len() > NOTE_MAX_ACTIVITIES {
            note.push_str(&format!(" ほか{}種", progress.len() - NOTE_MAX_ACTIVITIES));
        }
    }
    note.push(']');
    Some(note)
}

fn add_progress(progress: &mut Vec<(String, usize)>, activity: &str, count: usize) {
    match progress.iter_mut().find(|(a, _)| a == activity) {
        Some((_, n)) => *n += count,
        None => progress.push((activity.to_string(), count)),
    }
}

/// 行頭にある `#< CLIXML` の位置。行の途中にあるものは区画の始まりと見なさない。
fn find_header(s: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(i) = s[from..].find(HEADER) {
        let at = from + i;
        if at == 0 || s.as_bytes()[at - 1] == b'\n' {
            return Some(at);
        }
        from = at + HEADER.len();
    }
    None
}

/// `#< CLIXML` で始まる `s` から区画を1つ戻して `restored` へ足し、区画の後ろの残りを返す。
fn restore_block<'a>(s: &'a str, restored: &mut Restored) -> &'a str {
    let after_header = &s[HEADER.len()..];
    let body = after_header
        .strip_prefix("\r\n")
        .or_else(|| after_header.strip_prefix('\n'))
        .unwrap_or(after_header);
    // 印の後ろが `<Objs …>` でなければ CLIXML ではない。印ごとそのまま残して先へ進む。
    let Some(open_end) = body.starts_with("<Objs").then(|| body.find('>')).flatten() else {
        restored.text.push_str(HEADER);
        return after_header;
    };
    let mut text = String::new();
    if body[..open_end].ends_with('/') {
        restored.restored_blocks += 1;
        return &body[open_end + 1..];
    }
    let mut cur = &body[open_end + 1..];
    loop {
        let trimmed = cur.trim_start();
        if let Some(after) = trimmed.strip_prefix(OBJS_CLOSE) {
            restored.text.push_str(&text);
            restored.restored_blocks += 1;
            return after;
        }
        let rendered = parse_element(trimmed)
            .and_then(|(element, after)| render(&element, &mut text, restored).then_some(after));
        match rendered {
            Some(after) => cur = after,
            None => {
                // 読めない所から区画の終わりまでは元のまま（隠さない側へ倒す）。
                restored.text.push_str(&text);
                let end = cur
                    .find(OBJS_CLOSE)
                    .map_or(cur.len(), |i| i + OBJS_CLOSE.len());
                restored.text.push_str(&cur[..end]);
                restored.raw_blocks += 1;
                return &cur[end..];
            }
        }
    }
}

/// `<Objs>` の直下にある要素1つ。
enum Element<'a> {
    /// `<S S="kind">text</S>`（エラー・警告・詳細・デバッグ）。
    Stream { kind: &'a str, text: &'a str },
    /// `<Obj S="kind" …>inner</Obj>`（進行表示・情報）。
    Obj { kind: &'a str, inner: &'a str },
}

/// 先頭の要素を1つ読み、要素と、その後ろの残りを返す。読めなければ `None`。
fn parse_element(s: &str) -> Option<(Element<'_>, &str)> {
    if let Some(rest) = s.strip_prefix("<S S=\"") {
        let quote = rest.find('"')?;
        let kind = &rest[..quote];
        let rest = rest[quote + 1..].strip_prefix('>')?;
        let end = rest.find("</S>")?;
        return Some((
            Element::Stream {
                kind,
                text: &rest[..end],
            },
            &rest[end + "</S>".len()..],
        ));
    }
    if s.starts_with("<Obj ") {
        let open_end = s.find('>')?;
        let open = &s[..open_end];
        let kind = attribute(open, "S")?;
        let inner_start = open_end + 1;
        if open.ends_with('/') {
            return Some((Element::Obj { kind, inner: "" }, &s[inner_start..]));
        }
        let close = matching_obj_close(&s[inner_start..])?;
        return Some((
            Element::Obj {
                kind,
                inner: &s[inner_start..inner_start + close],
            },
            &s[inner_start + close + "</Obj>".len()..],
        ));
    }
    None
}

/// 開きタグ `open` の属性 `name="…"` の値。
fn attribute<'a>(open: &'a str, name: &str) -> Option<&'a str> {
    let key = format!(" {name}=\"");
    let start = open.find(&key)? + key.len();
    let len = open[start..].find('"')?;
    Some(&open[start..start + len])
}

/// `<Obj>` の中身 `s` で、対になる `</Obj>` の位置（入れ子の `<Obj>` を数える）。
fn matching_obj_close(s: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = 0;
    while let Some(lt) = s[i..].find('<') {
        let at = i + lt;
        let tag = &s[at..];
        if tag.starts_with("</Obj>") {
            if depth == 0 {
                return Some(at);
            }
            depth -= 1;
            i = at + "</Obj>".len();
        } else if tag.starts_with("<Obj ") || tag.starts_with("<Obj>") {
            let end = tag.find('>')?;
            if !tag[..end].ends_with('/') {
                depth += 1;
            }
            i = at + end + 1;
        } else {
            i = at + 1;
        }
    }
    None
}

/// 要素1つを本文 `text` へ置く（進行表示は `restored.progress` へ）。知らない種類なら `false`。
fn render(element: &Element<'_>, text: &mut String, restored: &mut Restored) -> bool {
    match *element {
        Element::Stream { kind, text: body } => {
            let body = unescape(body);
            let prefix = match kind.to_ascii_lowercase().as_str() {
                "error" => {
                    // 1要素が1行の断片で、改行は中身に入っている。足さずにつなぐ。
                    text.push_str(&body);
                    return true;
                }
                "warning" => "WARNING: ",
                "verbose" => "VERBOSE: ",
                "debug" => "DEBUG: ",
                _ => return false,
            };
            push_line(text, &format!("{prefix}{body}"));
            true
        }
        Element::Obj { kind, inner } => match kind.to_ascii_lowercase().as_str() {
            "progress" => {
                let Some(activity) = between(inner, "<AV>", "</AV>") else {
                    return false;
                };
                add_progress(&mut restored.progress, &unescape(activity), 1);
                true
            }
            "information" => {
                // 中身の文字は `&lt;` 等で包まれるので、この並びが現れるのはタグとしてだけである。
                if inner.contains("<S>PSHOST</S>") {
                    return true;
                }
                let Some(message) = between(inner, "<ToString>", "</ToString>") else {
                    return false;
                };
                push_line(text, &unescape(message));
                true
            }
            _ => false,
        },
    }
}

/// 行頭から始まり改行で終わる1行として足す。
fn push_line(text: &mut String, line: &str) {
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(line);
    if !line.ends_with('\n') {
        text.push('\n');
    }
}

fn between<'a>(s: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = s.find(open)? + open.len();
    let len = s[start..].find(close)?;
    Some(&s[start..start + len])
}

/// XML の実体参照を戻してから、PowerShell の `_xHHHH_`（UTF-16 の符号単位1つ）を戻す。
/// 順序はこの逆にしない——PowerShell が文字列を `_xHHHH_` へ包み、それを XML が包んでいる。
fn unescape(s: &str) -> String {
    decode_powershell_escapes(&decode_xml_entities(s))
}

fn decode_xml_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let candidate = &rest[amp..];
        let decoded = candidate.find(';').and_then(|semi| {
            let c = match &candidate[1..semi] {
                "lt" => '<',
                "gt" => '>',
                "amp" => '&',
                "quot" => '"',
                "apos" => '\'',
                name => {
                    let code = match name.strip_prefix("#x").or_else(|| name.strip_prefix("#X")) {
                        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                        None => name.strip_prefix('#')?.parse().ok()?,
                    };
                    char::from_u32(code)?
                }
            };
            Some((c, semi + 1))
        });
        match decoded {
            Some((c, consumed)) => {
                out.push(c);
                rest = &candidate[consumed..];
            }
            None => {
                out.push('&');
                rest = &candidate[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// `_xHHHH_` を UTF-16 の符号単位へ戻す。サロゲート対は1文字に、片割れは置換文字になる。
fn decode_powershell_escapes(s: &str) -> String {
    if !s.contains("_x") {
        return s.to_string();
    }
    let mut units: Vec<u16> = Vec::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("_x") {
        let (before, candidate) = rest.split_at(i);
        units.extend(before.encode_utf16());
        match powershell_escape(candidate) {
            Some(unit) => {
                units.push(unit);
                rest = &candidate["_xHHHH_".len()..];
            }
            None => {
                units.extend("_x".encode_utf16());
                rest = &candidate[2..];
            }
        }
    }
    units.extend(rest.encode_utf16());
    String::from_utf16_lossy(&units)
}

/// `s` の先頭が `_xHHHH_` なら、その符号単位。
fn powershell_escape(s: &str) -> Option<u16> {
    let bytes = s.as_bytes();
    if bytes.len() < 7 || bytes[6] != b'_' || !bytes[2..6].iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u16::from_str_radix(&s[2..6], 16).ok()
}

#[cfg(test)]
#[path = "clixml_tests.rs"]
mod clixml_tests;
