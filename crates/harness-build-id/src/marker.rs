//! 刻印（build id）の**バイナリ上の表し方**と、そこから読み戻す走査。
//!
//! # なぜ計算側と同じクレートに居るのか
//!
//! 刻印は「焼く」「配置後に検算する」「実行時にゲートで照合する」の 3 箇所で読まれる。
//! 探すときの目印になる文字列（`HRBUILDID:` の 10 文字）と、その後ろに何が続けば正当と
//! 認めるか（64 桁の小文字 16 進 + NUL）を複数箇所へ書き写すと、**書き写した側が
//! 1 文字ずれただけで何も見つけられなくなる**——見つからないことは「刻印が無い古い DLL」と
//! 区別が付かないので、ゲートが形だけ残って中身が死ぬ。
//!
//! そこで「目印の 10 文字」と「探し方」はこのモジュールだけが持ち、
//! build script（[`crate::x86_deploy`]）と実行時のゲート
//! （`harness-sandbox` の `tier2a::redirector_identity`）は**同じ関数**を呼ぶ。

/// 刻印を DLL のバイト列から探すためのマーカー。この後に 64 桁の 16 進と NUL が続く。
pub const BUILD_ID_MARKER: &str = "HRBUILDID:";

/// 刻印（16 進）の桁数。SHA-256 なので 64。
pub const BUILD_ID_HEX_LEN: usize = 64;

/// バイト列から刻印を取り出すときの失敗。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdError {
    /// マーカーが無い、またはマーカーはあっても後続が正しい形（64 桁の 16 進 + NUL）ではない。
    /// **形が壊れているものから刻印をでっち上げない**——でっち上げると、壊れた DLL が
    /// たまたま期待値と一致して素通りし得る。
    Missing,
    /// **相異なる**刻印が複数入っていた。どれが本物か決められないので通さない。
    /// 「先に見つかった方が勝ち」にすると、選び方次第で判定が変わる。
    Ambiguous(Vec<String>),
}

impl std::fmt::Display for IdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdError::Missing => write!(
                f,
                "no well-formed \"{BUILD_ID_MARKER}<{BUILD_ID_HEX_LEN} hex digits>\\0\" build-id \
                 marker was found"
            ),
            IdError::Ambiguous(ids) => write!(
                f,
                "found {} different build-id markers ({}); cannot decide which one identifies \
                 this file",
                ids.len(),
                ids.join(", ")
            ),
        }
    }
}

impl std::error::Error for IdError {}

/// バイト列を走査して刻印を取り出す。**PE を解析しない**ので、x64 と x86 の両方を同じコードで
/// 扱える（エクスポートテーブルの構造は 32bit と 64bit で違う）。
///
/// マーカーの後ろが「64 桁の小文字 16 進」＋「NUL」になっているものだけを正当とみなす。
/// `HRBUILDID:` の 10 文字がたまたま含まれているだけの場所は、刻印として拾わない。
pub fn extract_build_id(bytes: &[u8]) -> Result<String, IdError> {
    let marker = BUILD_ID_MARKER.as_bytes();
    let payload = BUILD_ID_HEX_LEN;
    let mut found: Vec<String> = Vec::new();

    let mut i = 0usize;
    // 終端の NUL を読むので、その添字（`i + marker.len() + payload`）が範囲内であることを要求する。
    while i + marker.len() + payload < bytes.len() {
        if &bytes[i..i + marker.len()] != marker {
            i += 1;
            continue;
        }
        let start = i + marker.len();
        let hex = &bytes[start..start + payload];
        let terminator = bytes[start + payload];
        let well_formed = terminator == 0
            && hex
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b));
        if well_formed {
            // 走査中に UTF-8 検証を挟まないよう、16 進であることを確かめた後で文字列化する。
            let id = String::from_utf8_lossy(hex).into_owned();
            if !found.contains(&id) {
                found.push(id);
            }
            // 同じマーカーの内側から重ねて探さない。
            i = start + payload + 1;
        } else {
            i += 1;
        }
    }

    match found.len() {
        0 => Err(IdError::Missing),
        1 => Ok(found.remove(0)),
        _ => Err(IdError::Ambiguous(found)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ID_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// マーカー + 刻印 + NUL を、前後に無関係なバイトを挟んで埋め込んだ「DLL もどき」を作る。
    fn blob_with(ids: &[&str]) -> Vec<u8> {
        let mut out: Vec<u8> = b"\x7fELF junk before".to_vec();
        for id in ids {
            out.extend_from_slice(BUILD_ID_MARKER.as_bytes());
            out.extend_from_slice(id.as_bytes());
            out.push(0);
            out.extend_from_slice(b"...unrelated section bytes...");
        }
        out.extend_from_slice(b"junk after");
        out
    }

    // ---- 許可側 ----

    /// **A1**: 正しい刻印が 1 個あれば取り出せる。
    #[test]
    fn a_single_well_formed_marker_is_extracted() {
        assert_eq!(extract_build_id(&blob_with(&[ID_A])), Ok(ID_A.to_string()));
    }

    /// **A2**: 同じ刻印が 2 回現れても曖昧ではない。コード生成の都合で文字列が重複することは
    /// あり、そこで落とすと**正しくビルドした DLL が弾かれる**。
    #[test]
    fn the_same_id_appearing_twice_is_not_ambiguous() {
        assert_eq!(
            extract_build_id(&blob_with(&[ID_A, ID_A])),
            Ok(ID_A.to_string())
        );
    }

    // ---- 拒否側 ----

    /// **D1**: 刻印がまったく無いバイト列。
    #[test]
    fn a_blob_without_any_marker_is_missing() {
        assert_eq!(
            extract_build_id(b"no marker here at all"),
            Err(IdError::Missing)
        );
    }

    /// **D2a**: 16 進が 63 桁しかない（＝マーカーの後ろの形が違う）。
    #[test]
    fn a_marker_with_too_few_hex_digits_is_rejected() {
        let mut blob = BUILD_ID_MARKER.as_bytes().to_vec();
        blob.extend_from_slice(&ID_A.as_bytes()[..63]);
        blob.push(0);
        blob.extend_from_slice(b"trailing bytes to keep the buffer long enough");
        assert_eq!(extract_build_id(&blob), Err(IdError::Missing));
    }

    /// **D2b**: 64 桁あるが NUL で終わっていない。
    #[test]
    fn a_marker_without_the_nul_terminator_is_rejected() {
        let mut blob = BUILD_ID_MARKER.as_bytes().to_vec();
        blob.extend_from_slice(ID_A.as_bytes());
        blob.extend_from_slice(b"XXXX not a terminator");
        assert_eq!(extract_build_id(&blob), Err(IdError::Missing));
    }

    /// **D2c**: 16 進でない文字が混ざる（大文字は不可。1 つの刻印を表す文字の並びを
    /// 1 通りだけに固定する——大小を許すと同じ値が 2 通りで書けてしまう）。
    #[test]
    fn a_marker_with_non_lowercase_hex_is_rejected() {
        let upper = ID_A.to_uppercase();
        assert_eq!(
            extract_build_id(&blob_with(&[&upper])),
            Err(IdError::Missing)
        );
    }

    /// **D3**: 相異なる刻印が 2 つ。どちらが本物か決められないので通さない。
    #[test]
    fn two_different_ids_in_one_file_are_ambiguous() {
        match extract_build_id(&blob_with(&[ID_A, ID_B])) {
            Err(IdError::Ambiguous(ids)) => {
                assert_eq!(ids.len(), 2);
                assert!(ids.contains(&ID_A.to_string()) && ids.contains(&ID_B.to_string()));
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    /// **A3（誤検知側）**: `HRBUILDID:` の 10 文字はあるが、その後ろが刻印の形になっていない。
    /// **刻印をでっち上げない**こと。
    /// でっち上げると、壊れた DLL が偶然期待値と一致して素通りし得る。
    #[test]
    fn the_marker_spelling_alone_does_not_fabricate_an_id() {
        let mut blob = b"some bytes ".to_vec();
        blob.extend_from_slice(BUILD_ID_MARKER.as_bytes());
        blob.extend_from_slice(b" and then completely unrelated text that is not hex at all");
        assert_eq!(extract_build_id(&blob), Err(IdError::Missing));
    }
}
