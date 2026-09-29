//! 差分層のオブジェクトの**純粋な判定**（FS も git も触らない）。
//!
//! 差分層の `.git/objects` は子が書ける。置いてよいのは次の2種だけで、それ以外は読まずに捨てる。
//!
//! - ゆるいオブジェクト（`xx/<38桁>`）: 展開して `<種類> <大きさ>\0<中身>` の形と長さを確かめ、
//!   **SHA-1 が名前と一致する**ものだけ（[`verify_loose_object`]）。
//! - pack（`pack/pack-<40桁>.pack`）: 索引は差分層のものを使わず、一時リポジトリの中で
//!   `index-pack` が作り直す（`assemble.rs`）。
//!
//! 捨てるもの（`.idx`・`.rev`・bitmap・midx・commit-graph・`info/*`・`tmp_*`・`.keep` など）は、
//! どれも「git がそれを信じて読むと、オブジェクトの中身とは別の主張を運べる」ものである
//! ——`info/alternates` は別の場所（別ホストを含む。net-spike N8-M1-③）を読ませ、
//! commit-graph は親子関係を、bitmap は到達可能性を、索引は名前と位置の対応を主張する。
//!
//! **最終的な検算は fetch の側の git が行う**（`transfer.fsckObjects`）。ここでの検算は、
//! そこへ渡す前に「形式を検査したオブジェクトだけ」にするため（D-110 (vi)）と、
//! 落とした理由を人へ名指しするためにある。

use std::io::Read;

use flate2::read::ZlibDecoder;
use sha1::{Digest, Sha1};

use super::refs::is_oid_hex;

/// ゆるいオブジェクトを展開したときの大きさの上限（見出しの宣言値もこれで縛る）。
pub(crate) const LOOSE_OBJECT_INFLATED_MAX: u64 = 2 * 1024 * 1024 * 1024;

/// `objects/` からの相対パス（`/` 区切り）を分類した結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ObjectFile {
    Loose { oid: String },
    Pack { stem: String },
    Ignored,
}

pub(crate) fn classify_objects_path(rel: &str) -> ObjectFile {
    let parts: Vec<&str> = rel.split('/').collect();
    match parts.as_slice() {
        [dir, file] if dir.len() == 2 && file.len() == 38 => {
            let oid = format!("{dir}{file}");
            if is_oid_hex(&oid) {
                ObjectFile::Loose { oid }
            } else {
                ObjectFile::Ignored
            }
        }
        ["pack", file] => match file
            .strip_suffix(".pack")
            .and_then(|stem| stem.strip_prefix("pack-").map(|hex| (stem, hex)))
        {
            Some((stem, hex)) if is_oid_hex(hex) => ObjectFile::Pack {
                stem: stem.to_string(),
            },
            _ => ObjectFile::Ignored,
        },
        _ => ObjectFile::Ignored,
    }
}

/// ゆるいオブジェクトを検算する。通れば種類（`commit`・`tree`・`blob`・`tag`）を返す。
///
/// 検算の中身: zlib として最後まで展開できる／見出しが `<種類> <10進の大きさ>\0` の形／
/// 中身の長さが宣言どおり／**入力を余さず使い切る**（末尾の余りを許さない）／
/// `SHA-1(見出し＋中身)` が名前と一致する。展開はストリームで行い、中身をメモリに溜めない。
pub(crate) fn verify_loose_object(oid: &str, compressed: &[u8]) -> Result<&'static str, String> {
    let mut decoder = ZlibDecoder::new(compressed);
    let mut header = Vec::with_capacity(32);
    let mut byte = [0u8; 1];
    loop {
        match decoder.read(&mut byte) {
            Ok(0) => return Err("ends before the header terminator".into()),
            Ok(_) if byte[0] == 0 => break,
            Ok(_) => {
                header.push(byte[0]);
                if header.len() > 32 {
                    return Err("header is too long".into());
                }
            }
            Err(e) => return Err(format!("not a zlib stream: {e}")),
        }
    }
    let header_text = std::str::from_utf8(&header).map_err(|_| "header is not ASCII")?;
    let (kind, size_text) = header_text
        .split_once(' ')
        .ok_or("header is not `<type> <size>`")?;
    let kind: &'static str = match kind {
        "commit" => "commit",
        "tree" => "tree",
        "blob" => "blob",
        "tag" => "tag",
        other => return Err(format!("unknown object type {other:?}")),
    };
    let well_formed_number = !size_text.is_empty()
        && size_text.bytes().all(|b| b.is_ascii_digit())
        && (size_text == "0" || !size_text.starts_with('0'));
    if !well_formed_number {
        return Err(format!("malformed size {size_text:?}"));
    }
    let declared: u64 = size_text.parse().map_err(|_| "size does not fit")?;
    if declared > LOOSE_OBJECT_INFLATED_MAX {
        return Err(format!("declares {declared} bytes, over the limit"));
    }

    let mut hasher = Sha1::new();
    hasher.update(&header);
    hasher.update([0u8]);
    let mut remaining = declared;
    let mut buf = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let want = buf.len().min(remaining as usize);
        let n = decoder
            .read(&mut buf[..want])
            .map_err(|e| format!("zlib stream is broken: {e}"))?;
        if n == 0 {
            return Err(format!("{remaining} bytes shorter than declared"));
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    match decoder.read(&mut byte) {
        Ok(0) => {}
        Ok(_) => return Err("longer than declared".into()),
        Err(e) => return Err(format!("zlib stream is broken: {e}")),
    }
    if decoder.total_in() != compressed.len() as u64 {
        return Err("trailing bytes after the zlib stream".into());
    }
    let actual: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if actual != oid {
        return Err(format!("content hashes to {actual}, not to its name"));
    }
    Ok(kind)
}

#[cfg(test)]
#[path = "objects_tests.rs"]
mod objects_tests;
