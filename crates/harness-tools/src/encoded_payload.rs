//! LLM が「ここが符号化された中身」と場所を示した文字列を、**ハーネスが機械的に解読する**。
//!
//! # 何のためにあるのか
//!
//! 承認画面は、符号化された中身を解読して見せる（[`crate::encoded_command`]。`-EncodedCommand`・
//! `FromBase64String`）。ところが文字コードを並べる・16進で書く・圧縮してから base64 にするといった書き方は、
//! 字面の決まった形が無いので機械の解読では拾えない。そこで、判定モデルが「解読が要る」と言ったのに機械の解読が
//! 何も取れなかった行に限って、LLM に**場所と符号化の種類だけ**を答えさせ（`harness_engine::encoded_span`）、
//! 解読はここで行う。
//!
//! # LLM には解読させない
//!
//! [BUG-224](../../../docs/bugs/BUG-224.md) で、要約の LLM が base64 を自分で解いて中身を取り違えた
//! （`systeminfo`を`Write-Hello`と書いた）。LLM の答えはあくまで「どこを・何として読むか」の候補で、
//! **答えた文字列が行の中にそのまま在るものだけ**を解読する。行に無い文字列（LLM が作った・書き換えた）は捨てる。
//!
//! # 限界（同じ場所で言う）
//!
//! - **LLM が場所を示さなかったものは解読しない。** 判定モデルも LLM も、攻撃者が書いたかもしれない行を読むので、
//!   別の場所を指すよう曲げられ得る。そのときは何も解読されないか、無害な部分だけが解読される
//! - 読める書き方は[`PayloadEncoding`]のものだけ。XOR・独自の暗号・実行時に組み立てる文字列は読めない
//! - 解読した中身は**表示と要約・危険度の判定のためだけ**に使い、照合には使わない（[`crate::encoded_command`]と同じ）

use std::io::Read;

use harness_core::{
    DecodeOutcome, DecodedLayer, EncodedSource, LocatedSpan, PayloadEncoding, TextEncoding,
};

use crate::encoded_command::{
    as_text, base64_decode, decode_nested, MAX_DECODED_BYTES, MAX_DECODED_LAYERS,
};

/// LLM が示した箇所のうち、解読する数の上限。
pub const MAX_LOCATED_SPANS: usize = 4;

/// `line`の中で LLM が示した`spans`を解読する。**`line`の中にそのまま在る文字列だけ**を読み、在らないものは捨てる。
/// 読めた中身にさらに機械で読める符号化（`-EncodedCommand`等）があれば、2段目以降として続けて解読する。
///
/// **上限で止めたことも1段として出す**（[`DecodeOutcome::CountLimit`]。行の機械の解読と同じ）。示された箇所が
/// [`MAX_LOCATED_SPANS`]より多い・段の数が上限に達した、のどちらも黙って落とすと、示された箇所を全部解けた行と
/// 区別がつかない（全部解けた行への判定モデルの点数は数えない。D-126）。
pub fn decode_located(line: &str, spans: &[LocatedSpan]) -> Vec<DecodedLayer> {
    let mut layers = Vec::new();
    let mut decoded_bytes = 0usize;
    let in_line = spans
        .iter()
        .filter(|s| !s.text.trim().is_empty() && line.contains(&s.text));
    for (i, span) in in_line.enumerate() {
        let source = EncodedSource::LocatedByModel(span.encoding);
        let cap = if i >= MAX_LOCATED_SPANS {
            Some(MAX_LOCATED_SPANS)
        } else if layers.len() >= MAX_DECODED_LAYERS {
            Some(MAX_DECODED_LAYERS)
        } else {
            None
        };
        if let Some(max_layers) = cap {
            layers.push(DecodedLayer {
                depth: 1,
                source,
                outcome: DecodeOutcome::CountLimit { max_layers },
                in_file: None,
            });
            break;
        }
        let (outcome, used) =
            decode_payload(&span.text, span.encoding, MAX_DECODED_BYTES - decoded_bytes);
        decoded_bytes += used;
        let nested = match &outcome {
            DecodeOutcome::Text { text, .. } => {
                decode_nested(text, 2, decoded_bytes, layers.len() + 1)
            }
            _ => Vec::new(),
        };
        // 入れ子の解読が上限で止めたら（止めた印は最後の段）、ここでも止める。行の機械の解読と同じ。
        let stop = matches!(outcome, DecodeOutcome::SizeLimit { .. })
            || nested.last().is_some_and(|l| {
                matches!(
                    l.outcome,
                    DecodeOutcome::DepthLimit { .. }
                        | DecodeOutcome::SizeLimit { .. }
                        | DecodeOutcome::CountLimit { .. }
                )
            });
        layers.push(DecodedLayer {
            depth: 1,
            source,
            outcome,
            in_file: None,
        });
        layers.extend(nested);
        if stop {
            break;
        }
    }
    layers
}

/// 1つの文字列を`encoding`として解読する。返り値の`usize`は使ったバイト数（上限の勘定）。
fn decode_payload(text: &str, encoding: PayloadEncoding, budget: usize) -> (DecodeOutcome, usize) {
    let source = EncodedSource::LocatedByModel(encoding);
    let bytes = match encoding {
        PayloadEncoding::CharCodes => {
            return match char_codes(text) {
                Some(decoded) if decoded.len() > budget => (
                    DecodeOutcome::SizeLimit {
                        max_bytes: MAX_DECODED_BYTES,
                    },
                    0,
                ),
                Some(decoded) => {
                    let used = decoded.len();
                    (
                        DecodeOutcome::Text {
                            encoding: TextEncoding::CharCodes,
                            text: decoded,
                        },
                        used,
                    )
                }
                None => (DecodeOutcome::Unreadable, 0),
            };
        }
        PayloadEncoding::Base64 => base64_decode(text),
        PayloadEncoding::Base32 => base32_decode(text),
        PayloadEncoding::Hex => hex(text),
        PayloadEncoding::GzipBase64 => base64_decode(text)
            .and_then(|b| inflate(flate2::read::GzDecoder::new(b.as_slice()), budget)),
        PayloadEncoding::DeflateBase64 => base64_decode(text)
            .and_then(|b| inflate(flate2::read::DeflateDecoder::new(b.as_slice()), budget)),
    };
    let Some(bytes) = bytes else {
        return (DecodeOutcome::Unreadable, 0);
    };
    if bytes.len() > budget {
        return (
            DecodeOutcome::SizeLimit {
                max_bytes: MAX_DECODED_BYTES,
            },
            0,
        );
    }
    let used = bytes.len();
    match as_text(&bytes, source) {
        Some((encoding, text)) => (DecodeOutcome::Text { encoding, text }, used),
        None => (DecodeOutcome::NotText, used),
    }
}

/// 圧縮を解く。`budget`を1バイトでも超えたら、超えた分は読まずに返す（呼ぶ側が上限として扱う）。
/// 壊れた圧縮データは`None`。
fn inflate(reader: impl Read, budget: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    reader.take(budget as u64 + 1).read_to_end(&mut out).ok()?;
    (!out.is_empty()).then_some(out)
}

/// RFC 4648 の base32（大小を畳み、詰め物の`=`と空白を読み飛ばす）。読めなければ`None`。
fn base32_decode(text: &str) -> Option<Vec<u8>> {
    const T: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for c in text
        .bytes()
        .filter(|c| !c.is_ascii_whitespace() && *c != b'=')
    {
        let value = T.iter().position(|t| *t == c.to_ascii_uppercase())? as u32;
        acc = (acc << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (!out.is_empty()).then_some(out)
}

/// 16進（`4765742D`・`47 65 74`・`0x47,0x65`・`\x47\x65`）。区切りを除いて偶数桁の16進数字だけなら読む。
fn hex(text: &str) -> Option<Vec<u8>> {
    let cleaned = text.replace("0x", "").replace("0X", "").replace("\\x", "");
    let digits: String = cleaned
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | ',' | '-' | ':' | '\n' | '\r'))
        .collect();
    if digits.is_empty()
        || !digits.len().is_multiple_of(2)
        || !digits.chars().all(|c| c.is_ascii_hexdigit())
    {
        return None;
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).ok())
        .collect()
}

/// 10進の文字コードの並び（`115,121,115`・`[char]105+[char]101`）。数字の並びを全部拾って文字にする。
/// 文字にならない番号（サロゲート・範囲外）が1つでもあれば`None`。
fn char_codes(text: &str) -> Option<String> {
    let mut out = String::new();
    let mut digits = String::new();
    let flush = |digits: &mut String, out: &mut String| -> Option<()> {
        if !digits.is_empty() {
            let code: u32 = digits.parse().ok()?;
            out.push(char::from_u32(code)?);
            digits.clear();
        }
        Some(())
    };
    for c in text.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
        } else {
            flush(&mut digits, &mut out)?;
        }
    }
    flush(&mut digits, &mut out)?;
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
#[path = "encoded_payload_tests.rs"]
mod tests;
