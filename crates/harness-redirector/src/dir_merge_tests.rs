//! ディレクトリ一覧の答え（[`answer_dir_query`]）と組み立て（[`merge_dir_entries`]）の試験（BUG-181）。
//!
//! 絞り込みの式は、**Win32が実際にNTへ渡す形**（DOS用の記号へ書き換えた後）で書く。どのパターンが
//! どう届くかと、本物のファイルシステムがどう答えるかは`plans/mac-spike/RESULTS.md` §S78で実測した。
//! 下の期待値はその実測の答え（`.`と`..`を除く）をそのまま写したものである。

use super::*;
use std::collections::HashSet;
use windows::Wdk::Storage::FileSystem::{FileNamesInformation, FILE_NAMES_INFORMATION};

fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// バッファに書かれた`FILE_NAMES_INFORMATION`の並びを名前へ読み戻す。
fn read_names(buf: &[u8], bytes_written: usize) -> Vec<String> {
    let mut out = Vec::new();
    if bytes_written == 0 {
        return out;
    }
    let mut offset = 0usize;
    loop {
        let header = unsafe { &*(buf[offset..].as_ptr() as *const FILE_NAMES_INFORMATION) };
        let name_at = offset + std::mem::offset_of!(FILE_NAMES_INFORMATION, FileName);
        let units: Vec<u16> = buf[name_at..name_at + header.FileNameLength as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        out.push(String::from_utf16_lossy(&units));
        if header.NextEntryOffset == 0 {
            return out;
        }
        offset += header.NextEntryOffset as usize;
    }
}

/// `FindFirstFile`→`FindNextFile`と同じ撃ち方で最後まで一覧を取る——1回目だけ絞り込みを渡して
/// 1件で返させ、2回目からは絞り込み無しで続きを取る（§S78で実測した撃ち方）。
/// 1回目が失敗ならその状態を、最後まで取れたら`STATUS_SUCCESS`を返す。
fn list_like_find_first_file(merged: &[MergedEntry], delivered: &str) -> (NTSTATUS, Vec<String>) {
    let mut state: Option<DirQueryState> = None;
    let mut names = Vec::new();
    let mut first = true;
    loop {
        let mut buf = vec![0u8; 4096];
        let requested = first.then(|| upcase_filter(&w(delivered)));
        let answer = answer_dir_query(
            merged.to_vec(),
            state.as_ref(),
            requested,
            false,
            FileNamesInformation,
            first,
            &mut buf,
        );
        if answer.status != NTSTATUS(0) {
            if first {
                return (answer.status, names);
            }
            assert_eq!(answer.status, STATUS_NO_MORE_FILES, "the end of a listing");
            return (NTSTATUS(0), names);
        }
        names.extend(read_names(&buf, answer.bytes_written));
        state = Some(answer.state);
        first = false;
    }
}

/// §S78の測定と同じ5つのファイルを本物の側に置いた一覧。
fn probe_dir() -> (tempfile::TempDir, tempfile::TempDir, Vec<MergedEntry>) {
    let base = tempfile::tempdir().unwrap();
    let diff_layer = tempfile::tempdir().unwrap();
    for n in ["a.txt", "b.rs", "abc", "x.y.z", "noext"] {
        std::fs::write(base.path().join(n), "x").unwrap();
    }
    let merged = merge_dir_entries(base.path(), diff_layer.path(), &HashSet::new(), "");
    (base, diff_layer, merged)
}

/// 原因1: 絞り込みは1回目の問い合わせでしか届かない。2回目以降も同じ絞り込みで続きを返すこと。
/// 以前は2回目から絞らない一覧の続きを返し、`edited.txt`で絞ったのに別のファイルが並んだ。
#[test]
fn a_name_filter_given_only_on_the_first_query_still_applies_to_the_following_queries() {
    let (_b, _d, merged) = probe_dir();
    assert_eq!(
        list_like_find_first_file(&merged, "a.txt"),
        (NTSTATUS(0), vec!["a.txt".to_string()])
    );
    // 残したいものが残る側: 絞り込みを渡さなければ全部返る。
    let (status, mut all) = list_like_find_first_file(&merged, "*");
    all.sort();
    assert_eq!(status, NTSTATUS(0));
    assert_eq!(all, vec!["a.txt", "abc", "b.rs", "noext", "x.y.z"]);
}

/// 原因2: Win32が書き換えたDOS用の記号（`<`・`>`・`"`）を、本物のファイルシステムと同じ意味で照合する。
/// 左がユーザーの書いたパターン、中がNTへ届いた式、右が本物の答え（§S78）。
#[test]
fn dos_wildcards_match_the_way_the_file_system_answers() {
    let (_b, _d, merged) = probe_dir();
    let cases: &[(&str, &str, &[&str])] = &[
        ("*.txt", "<.txt", &["a.txt"]),
        ("*.*", "*", &["a.txt", "abc", "b.rs", "noext", "x.y.z"]),
        ("a?c", "a>c", &["abc"]),
        ("*.", "<", &["abc", "noext"]),
        ("x.*", "x\"*", &["x.y.z"]),
        ("?.txt", ">.txt", &["a.txt"]),
        ("*.t?t", "<.t>t", &["a.txt"]),
        ("*x*", "*x*", &["a.txt", "noext", "x.y.z"]),
    ];
    for (typed, delivered, expected) in cases {
        let (status, mut got) = list_like_find_first_file(&merged, delivered);
        got.sort();
        assert_eq!(status, NTSTATUS(0), "{typed} ({delivered})");
        assert_eq!(got, *expected, "{typed} was delivered as {delivered}");
    }
}

/// 大小を区別しない（ファイルシステムと同じ）。式は`upcase_filter`が大文字化する。
#[test]
fn filters_ignore_case_like_the_file_system() {
    let base = tempfile::tempdir().unwrap();
    let diff_layer = tempfile::tempdir().unwrap();
    std::fs::write(base.path().join("UPPER.TXT"), "x").unwrap();
    std::fs::write(diff_layer.path().join("lower.txt"), "x").unwrap();
    let merged = merge_dir_entries(base.path(), diff_layer.path(), &HashSet::new(), "");
    // 一覧は大小を無視した名前順で返る（`merge_dir_entries`）。
    assert_eq!(
        list_like_find_first_file(&merged, "<.txt"),
        (NTSTATUS(0), vec!["lower.txt".to_string(), "UPPER.TXT".to_string()])
    );
}

/// 1件も当たらないとき、本物は最初の問い合わせで「該当するファイルが無い」を返す（§S78）。
/// 「もう無い」は読み終えた後だけ。絞り込みの無い空の一覧は従来どおり「もう無い」。
#[test]
fn no_match_is_no_such_file_on_the_first_query_and_no_more_files_otherwise() {
    let (_b, _d, merged) = probe_dir();
    assert_eq!(
        list_like_find_first_file(&merged, "gone.txt").0,
        STATUS_NO_SUCH_FILE
    );
    assert_eq!(
        list_like_find_first_file(&merged, "<.zzz").0,
        STATUS_NO_SUCH_FILE
    );
    let mut buf = vec![0u8; 256];
    let empty = answer_dir_query(
        Vec::new(),
        None,
        None,
        false,
        FileNamesInformation,
        false,
        &mut buf,
    );
    assert_eq!(empty.status, STATUS_NO_MORE_FILES);
}

/// バッファが1件も入らない小ささで断っても、絞り込みは覚えておく——大きいバッファで撃ち直す
/// 続きの問い合わせは`FileName`を渡さない。
#[test]
fn a_buffer_too_small_for_one_entry_keeps_the_filter_for_the_retry() {
    let (_b, _d, merged) = probe_dir();
    let mut tiny = vec![0u8; 4];
    let first = answer_dir_query(
        merged.clone(),
        None,
        Some(upcase_filter(&w("<.txt"))),
        false,
        FileNamesInformation,
        true,
        &mut tiny,
    );
    assert_eq!(first.status, STATUS_BUFFER_OVERFLOW);
    let mut buf = vec![0u8; 4096];
    let retry = answer_dir_query(
        merged,
        Some(&first.state),
        None,
        false,
        FileNamesInformation,
        false,
        &mut buf,
    );
    assert_eq!(retry.status, NTSTATUS(0));
    assert_eq!(read_names(&buf, retry.bytes_written), vec!["a.txt"]);
}

/// やり直す問い合わせは位置を0へ戻す。絞り込みは渡されていれば替え、無ければ前のまま。
/// 続きの問い合わせに渡された`FileName`は見ない。
#[test]
fn restarting_rewinds_and_keeps_the_filter_unless_a_new_one_is_given() {
    let a = Some(w("A"));
    let b = Some(w("B"));
    let prev = DirQueryState {
        next: 3,
        filter: a.clone(),
    };
    assert_eq!(
        next_query_state(Some(&prev), None, true),
        DirQueryState {
            next: 0,
            filter: a.clone()
        }
    );
    assert_eq!(
        next_query_state(Some(&prev), b.clone(), true),
        DirQueryState {
            next: 0,
            filter: b.clone()
        }
    );
    assert_eq!(next_query_state(Some(&prev), b.clone(), false), prev);
    assert_eq!(
        next_query_state(None, None, false),
        DirQueryState {
            next: 0,
            filter: None
        }
    );
}

/// 原因3: 差分層の根に置く帳簿（`.harness-cow-*`）と外の置き場（`_ext`）は、ワークスペースの根の
/// 一覧に出さない。**残したいものが残る側**: 根より下では同じ名前でも中身として一覧に出す。
#[test]
fn the_diff_layer_bookkeeping_is_not_listed_at_the_workspace_root() {
    let base = tempfile::tempdir().unwrap();
    let diff_layer = tempfile::tempdir().unwrap();
    std::fs::create_dir(base.path().join(".harness")).unwrap();
    std::fs::write(base.path().join("keep.txt"), "x").unwrap();
    for f in [
        ".harness-cow-ops.jsonl",
        ".harness-cow-session.json",
        ".harness-cow-debug.log",
        "edited.txt",
    ] {
        std::fs::write(diff_layer.path().join(f), "x").unwrap();
    }
    for d in [".harness-cow-tmp", ".harness-cow-baseline", "_ext"] {
        std::fs::create_dir(diff_layer.path().join(d)).unwrap();
    }
    let merged = merge_dir_entries(base.path(), diff_layer.path(), &HashSet::new(), "");
    let names: Vec<String> = merged
        .iter()
        .map(|e| String::from_utf16_lossy(&e.name))
        .collect();
    assert_eq!(names, vec![".harness", "edited.txt", "keep.txt"]);

    let sub_base = base.path().join("sub");
    let sub_diff = diff_layer.path().join("sub");
    std::fs::create_dir(&sub_base).unwrap();
    std::fs::create_dir(&sub_diff).unwrap();
    std::fs::write(sub_diff.join(".harness-cow-note"), "x").unwrap();
    std::fs::create_dir(sub_diff.join("_ext")).unwrap();
    let merged = merge_dir_entries(&sub_base, &sub_diff, &HashSet::new(), "sub");
    let names: Vec<String> = merged
        .iter()
        .map(|e| String::from_utf16_lossy(&e.name))
        .collect();
    assert_eq!(names, vec![".harness-cow-note", "_ext"]);
}
