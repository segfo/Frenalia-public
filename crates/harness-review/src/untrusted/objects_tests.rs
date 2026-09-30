use std::io::Write;

use flate2::write::ZlibEncoder;
use flate2::Compression;

use super::*;

/// `git hash-object --stdin` に `hello\n` を渡したときの名前。
const HELLO_OID: &str = "ce013625030ba8dba906f756967f9e9ca394464a";

fn deflate(raw: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(raw).unwrap();
    e.finish().unwrap()
}

/// 許可側: git が書くゆるいオブジェクトは通り、種類が返る。
#[test]
fn a_well_formed_loose_object_is_accepted() {
    assert_eq!(
        verify_loose_object(HELLO_OID, &deflate(b"blob 6\0hello\n")),
        Ok("blob")
    );
}

/// 禁止側: 名前と中身が違う（偽装）・長さが宣言と違う・形が崩れているものは落とす。
#[test]
fn a_loose_object_that_lies_about_itself_is_rejected() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "forged content under a real name",
            deflate(b"blob 6\0HELLO\n"),
        ),
        ("shorter than declared", deflate(b"blob 7\0hello\n")),
        ("longer than declared", deflate(b"blob 5\0hello\n")),
        ("unknown type", deflate(b"note 6\0hello\n")),
        ("leading zero in size", deflate(b"blob 06\0hello\n")),
        ("no header terminator", deflate(b"blob 6 hello\n")),
        ("not zlib", b"blob 6\0hello\n".to_vec()),
        ("trailing bytes", {
            let mut v = deflate(b"blob 6\0hello\n");
            v.extend_from_slice(b"extra");
            v
        }),
    ];
    for (what, bytes) in cases {
        assert!(verify_loose_object(HELLO_OID, &bytes).is_err(), "{what}");
    }
}

/// 見出しで巨大な大きさを宣言しても、展開を始める前に止まる。
#[test]
fn an_absurd_declared_size_is_rejected_before_inflating() {
    let bytes = deflate(b"blob 99999999999\0x");
    let err = verify_loose_object(HELLO_OID, &bytes).unwrap_err();
    assert!(err.contains("over the limit"), "{err}");
}

#[test]
fn only_loose_objects_and_packs_are_taken_from_the_objects_directory() {
    assert_eq!(
        classify_objects_path("ce/013625030ba8dba906f756967f9e9ca394464a"),
        ObjectFile::Loose {
            oid: HELLO_OID.into()
        }
    );
    assert_eq!(
        classify_objects_path("pack/pack-22f9fc43b2b5c8ce78499bd7a26643018619e11c.pack"),
        ObjectFile::Pack {
            stem: "pack-22f9fc43b2b5c8ce78499bd7a26643018619e11c".into()
        }
    );
    for ignored in [
        "info/alternates",
        "info/commit-graph",
        "info/commit-graphs/commit-graph-chain",
        "info/packs",
        "pack/pack-22f9fc43b2b5c8ce78499bd7a26643018619e11c.idx",
        "pack/pack-22f9fc43b2b5c8ce78499bd7a26643018619e11c.rev",
        "pack/pack-22f9fc43b2b5c8ce78499bd7a26643018619e11c.bitmap",
        "pack/pack-22f9fc43b2b5c8ce78499bd7a26643018619e11c.keep",
        "pack/multi-pack-index",
        "pack/tmp_pack_abc",
        "a7/tmp_obj_aO7KtX",
        "CE/013625030BA8DBA906F756967F9E9CA394464A",
        "ce/013625030ba8dba906f756967f9e9ca394464",
        "pack/pack-XYZ.pack",
    ] {
        assert_eq!(
            classify_objects_path(ignored),
            ObjectFile::Ignored,
            "{ignored}"
        );
    }
}
