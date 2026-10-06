use std::io::Write;

use super::*;

/// 試験の入力を作るための base64（標準・詰め物あり）。
fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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

fn span(text: &str, encoding: PayloadEncoding) -> LocatedSpan {
    LocatedSpan {
        text: text.to_string(),
        encoding,
    }
}

fn texts(layers: &[DecodedLayer]) -> Vec<(u32, String)> {
    layers
        .iter()
        .filter_map(|l| match &l.outcome {
            DecodeOutcome::Text { text, .. } => Some((l.depth, text.clone())),
            _ => None,
        })
        .collect()
}

/// 5つの書き方を、それぞれ解読する（測定で「解読が要る」と出た書き方から取った形）。
#[test]
fn every_supported_encoding_is_decoded_by_the_harness() {
    let gz = {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b"Get-Date").unwrap();
        b64(&e.finish().unwrap())
    };
    let deflate = {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b"Get-Item x").unwrap();
        b64(&e.finish().unwrap())
    };
    let cases = [
        ("R2V0LURhdGU=", PayloadEncoding::Base64, "Get-Date"),
        // base32（RFC 4648。`Get-Date`を符号化したもの）。大小は畳む。
        ("I5SXILKEMF2GK===", PayloadEncoding::Base32, "Get-Date"),
        ("i5sxilkemf2gk===", PayloadEncoding::Base32, "Get-Date"),
        ("4765742D44617465", PayloadEncoding::Hex, "Get-Date"),
        ("0x47,0x65,0x74", PayloadEncoding::Hex, "Get"),
        (
            "115,121,115,116,101,109,105,110,102,111",
            PayloadEncoding::CharCodes,
            "systeminfo",
        ),
        (
            "[char]105+[char]101+[char]120",
            PayloadEncoding::CharCodes,
            "iex",
        ),
        (gz.as_str(), PayloadEncoding::GzipBase64, "Get-Date"),
        (
            deflate.as_str(),
            PayloadEncoding::DeflateBase64,
            "Get-Item x",
        ),
    ];
    for (text, encoding, expected) in cases {
        let line = format!("iex ({text})");
        let layers = decode_located(&line, &[span(text, encoding)]);
        assert_eq!(
            texts(&layers),
            vec![(1, expected.to_string())],
            "{encoding:?} {text}"
        );
        assert_eq!(layers[0].source, EncodedSource::LocatedByModel(encoding));
    }
}

/// **LLM が答えた文字列が行の中にそのまま無ければ捨てる**（LLM が作った・書き換えた文字列を解読しない）。
/// 対照: 行に在る文字列は解読する。
#[test]
fn a_span_that_is_not_in_the_line_is_dropped() {
    let line = "iex ([char[]](115,121) -join '')";
    let invented = span("R2V0LURhdGU=", PayloadEncoding::Base64);
    let real = span("115,121", PayloadEncoding::CharCodes);
    assert!(decode_located(line, std::slice::from_ref(&invented)).is_empty());
    assert_eq!(
        texts(&decode_located(line, &[invented, real])),
        vec![(1, "sy".to_string())]
    );
    assert!(decode_located(line, &[span("  ", PayloadEncoding::Hex)]).is_empty());
}

/// 示された符号化として読めなければ、その段は「読めなかった」として残す（黙って落とさない）。
#[test]
fn a_span_that_does_not_decode_is_kept_as_unreadable() {
    let line = "x zzz-not-hex y";
    let layers = decode_located(line, &[span("zzz-not-hex", PayloadEncoding::Hex)]);
    assert_eq!(layers.len(), 1);
    assert_eq!(layers[0].outcome, DecodeOutcome::Unreadable);
    let not_gzip = decode_located(
        "a R2V0LURhdGU= b",
        &[span("R2V0LURhdGU=", PayloadEncoding::GzipBase64)],
    );
    assert_eq!(not_gzip[0].outcome, DecodeOutcome::Unreadable);
}

/// 解読した中身の中に、機械で読める符号化（`-EncodedCommand`）があれば2段目として続けて読む。
#[test]
fn decoded_content_is_read_again_for_known_encodings() {
    let inner = "pwsh -enc cwB5AHMAdABlAG0AaQBuAGYAbwA=";
    let outer = b64(inner.as_bytes());
    let line = format!(
        "$x='{outer}'; iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($x)))"
    );
    let layers = decode_located(&line, &[span(&outer, PayloadEncoding::Base64)]);
    assert_eq!(
        texts(&layers),
        vec![(1, inner.to_string()), (2, "systeminfo".to_string())]
    );
}

fn count_limits(layers: &[DecodedLayer]) -> usize {
    layers
        .iter()
        .filter(|l| matches!(l.outcome, DecodeOutcome::CountLimit { .. }))
        .count()
}

/// 示す数には上限がある。**超えた分は黙って落とさず、止めた印の段を残す**（行の機械の解読と同じ）。
/// 対照: 上限ちょうどなら印は無い。行に無い文字列は数に入らない。
#[test]
fn spans_beyond_the_cap_leave_a_count_limit_layer() {
    let line = "1,2 3,4 5,6 7,8 9,10";
    let spans: Vec<_> = ["1,2", "3,4", "5,6", "7,8", "9,10"]
        .iter()
        .map(|t| span(t, PayloadEncoding::CharCodes))
        .collect();
    let layers = decode_located(line, &spans);
    assert_eq!(layers.len(), MAX_LOCATED_SPANS + 1, "{layers:?}");
    assert_eq!(
        layers.last().unwrap(),
        &DecodedLayer {
            depth: 1,
            source: EncodedSource::LocatedByModel(PayloadEncoding::CharCodes),
            outcome: DecodeOutcome::CountLimit {
                max_layers: MAX_LOCATED_SPANS
            },
            in_file: None,
        }
    );

    let exact = decode_located(line, &spans[..MAX_LOCATED_SPANS]);
    assert_eq!(exact.len(), MAX_LOCATED_SPANS);
    assert_eq!(count_limits(&exact), 0, "{exact:?}");
    let mut with_invented = spans[..MAX_LOCATED_SPANS].to_vec();
    with_invented.push(span("R2V0LURhdGU=", PayloadEncoding::Base64));
    assert_eq!(count_limits(&decode_located(line, &with_invented)), 0);
}

/// 段の数の上限に達したら、**止めた印の段を最後に1つだけ残す**。入れ子の解読が先に上限に達した形（以前は
/// 後から切り詰めて、入れ子が残した印ごと落としていた）と、上限ちょうどまで埋まってから次の箇所が来た形の両方。
/// 対照: 上限に届かなければ印は無い。
#[test]
fn the_layer_count_cap_leaves_one_marker_at_the_end() {
    let blob = b64(b"systeminfo");
    let nested = |n: usize| {
        b64(format!("[Convert]::FromBase64String('{blob}'); ")
            .repeat(n)
            .as_bytes())
    };
    let count_limit = DecodeOutcome::CountLimit {
        max_layers: MAX_DECODED_LAYERS,
    };

    // 入れ子が上限を越える。
    let outer = nested(MAX_DECODED_LAYERS + 3);
    let layers = decode_located(
        &format!("x {outer} y"),
        &[span(&outer, PayloadEncoding::Base64)],
    );
    assert_eq!(layers.len(), MAX_DECODED_LAYERS + 1, "{layers:?}");
    assert_eq!(layers.last().unwrap().outcome, count_limit);
    assert_eq!(count_limits(&layers), 1);

    // 上限ちょうどまで埋まり、次の箇所が来る。
    let outer = nested(MAX_DECODED_LAYERS - 1);
    let line = format!("x {outer} y 115,121 z");
    let layers = decode_located(
        &line,
        &[
            span(&outer, PayloadEncoding::Base64),
            span("115,121", PayloadEncoding::CharCodes),
        ],
    );
    assert_eq!(layers.len(), MAX_DECODED_LAYERS + 1, "{layers:?}");
    let last = layers.last().unwrap();
    assert_eq!(last.outcome, count_limit);
    assert_eq!(
        (last.depth, last.source),
        (1, EncodedSource::LocatedByModel(PayloadEncoding::CharCodes))
    );

    let outer = nested(3);
    let layers = decode_located(
        &format!("x {outer} y"),
        &[span(&outer, PayloadEncoding::Base64)],
    );
    assert_eq!(layers.len(), 4, "{layers:?}");
    assert_eq!(count_limits(&layers), 0);
}

/// 解いた中身が大きすぎる圧縮データ（圧縮爆弾）は、上限で止めて「止めた」と残す。
#[test]
fn a_huge_inflated_payload_stops_at_the_size_limit() {
    let bomb = {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(&vec![b'A'; MAX_DECODED_BYTES * 4]).unwrap();
        b64(&e.finish().unwrap())
    };
    let line = format!("x {bomb} y");
    let layers = decode_located(&line, &[span(&bomb, PayloadEncoding::GzipBase64)]);
    assert!(
        matches!(layers[0].outcome, DecodeOutcome::SizeLimit { .. }),
        "{:?}",
        layers[0].outcome
    );
}
