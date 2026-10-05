//! 却下印（`dismissed.json`）の読み書きの単体テスト。
//!
//! **端末もWin32の権限も要らない**——試験ごとの一時ディレクトリをワークスペースにして、
//! 実際のファイルを書いて読み直す。

use super::*;

const DOMAIN: &str = "workspace-shell";

fn key(exe: &str, argv: &str) -> CandidateKey {
    CandidateKey {
        from_domain: DOMAIN.to_string(),
        exe: exe.to_string(),
        argv: argv.to_string(),
    }
}

fn keys(items: &[(&str, &str)]) -> BTreeSet<CandidateKey> {
    items.iter().map(|(e, a)| key(e, a)).collect()
}

fn none() -> BTreeSet<CandidateKey> {
    BTreeSet::new()
}

fn write_raw(ws: &Path, text: &str) {
    let path = path(ws);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, text).unwrap();
}

/// 無いのは正常（まだ1件も却下していない）。**警告の対象にしない**——毎回「読めない」と
/// 出すと、本当に壊れたときの警告が埋もれる。
#[test]
fn a_missing_file_reads_as_no_dismissals() {
    let tmp = tempfile::tempdir().unwrap();
    let read = load(tmp.path()).expect("無いファイルを失敗にしている");
    assert!(read.is_empty());
}

/// 書いて読み直すと残っている。**版の欄も書く**（形を変えた日に古い形と区別できるように）。
#[test]
fn a_dismissal_is_written_and_survives_reading_it_back() {
    let tmp = tempfile::tempdir().unwrap();
    let applied = update(
        tmp.path(),
        &keys(&[("C:/git.exe", "git status")]),
        &none(),
        42,
    )
    .expect("書けない");
    assert_eq!(applied.added, 1);
    assert!(applied.wrote);

    let read = load(tmp.path()).expect("読めない");
    assert!(read.contains(DOMAIN, "C:/git.exe", "git status"));
    assert_eq!(read.len(), 1);

    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path(tmp.path())).unwrap()).unwrap();
    assert_eq!(raw["schema_version"], SCHEMA_VERSION);
    assert_eq!(raw["dismissed"][0]["from_domain"], DOMAIN);
    assert_eq!(raw["dismissed"][0]["dismissed_unix_ms"], 42);
}

/// **一時ファイルを残さない**（書いて差し替える形の後始末）。
#[test]
fn writing_leaves_only_the_file_itself() {
    let tmp = tempfile::tempdir().unwrap();
    update(
        tmp.path(),
        &keys(&[("C:/git.exe", "git status")]),
        &none(),
        1,
    )
    .unwrap();
    let names: Vec<String> = std::fs::read_dir(path(tmp.path()).parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec![DISMISSED_FILE.to_string()]);
}

/// 取り消すと**その1件だけ**が消える（**対の側**: 他の印を巻き込まない、`B-35`）。
#[test]
fn undismissing_removes_only_that_mark() {
    let tmp = tempfile::tempdir().unwrap();
    update(
        tmp.path(),
        &keys(&[("C:/git.exe", "git status"), ("C:/cargo.exe", "cargo build")]),
        &none(),
        1,
    )
    .unwrap();

    let applied = update(
        tmp.path(),
        &none(),
        &keys(&[("C:/git.exe", "git status")]),
        2,
    )
    .unwrap();
    assert_eq!(applied.removed, 1);

    let read = load(tmp.path()).unwrap();
    assert!(!read.contains(DOMAIN, "C:/git.exe", "git status"));
    assert!(
        read.contains(DOMAIN, "C:/cargo.exe", "cargo build"),
        "取り消していない印まで消えている"
    );
}

/// **同じ予約を2回当てても書き直さない**（`B-09`: 「足した」と「元からあった」を区別する）。
#[test]
fn the_same_dismissal_twice_is_counted_as_already_there_and_not_rewritten() {
    let tmp = tempfile::tempdir().unwrap();
    let marks = keys(&[("C:/git.exe", "git status")]);
    update(tmp.path(), &marks, &none(), 1).unwrap();

    let second = update(tmp.path(), &marks, &none(), 2).unwrap();
    assert_eq!(second.added, 0);
    assert_eq!(second.already, 1);
    assert!(!second.wrote, "何も変わらないのに書いている");

    let missing = update(
        tmp.path(),
        &none(),
        &keys(&[("C:/never.exe", "x")]),
        3,
    )
    .unwrap();
    assert_eq!(missing.not_found, 1);
    assert!(!missing.wrote);
}

/// **書くのは読み直したファイルへの差分である**——別のエディタが間に書いた印を、
/// こちらの書き戻しで消さない（2つ同時に開いたときの扱い）。
#[test]
fn a_second_writer_does_not_erase_what_the_first_one_wrote() {
    let tmp = tempfile::tempdir().unwrap();
    // エディタA・Bが同じ空の状態を見てから、それぞれ別のものを却下する。
    let seen_by_b = load(tmp.path()).unwrap();
    update(
        tmp.path(),
        &keys(&[("C:/a.exe", "a")]),
        &none(),
        1,
    )
    .unwrap();
    assert!(seen_by_b.is_empty());
    update(
        tmp.path(),
        &keys(&[("C:/b.exe", "b")]),
        &none(),
        2,
    )
    .unwrap();

    let read = load(tmp.path()).unwrap();
    assert!(read.contains(DOMAIN, "C:/a.exe", "a"), "Aの却下が消えている");
    assert!(read.contains(DOMAIN, "C:/b.exe", "b"));
}

/// 照合は**宣言済みの判定と同じ畳み方**（大小・区切り）で行う。対の側として、
/// 引数やドメインが違うものは**別物**であることも確かめる（畳みすぎない）。
#[test]
fn the_match_folds_like_the_judge_but_not_more() {
    let tmp = tempfile::tempdir().unwrap();
    update(
        tmp.path(),
        &keys(&[(r"C:\Git\cmd\git.exe", "git status")]),
        &none(),
        1,
    )
    .unwrap();
    let read = load(tmp.path()).unwrap();

    assert!(read.contains(DOMAIN, "c:/git/CMD/GIT.EXE", "GIT STATUS"));
    assert!(
        !read.contains(DOMAIN, r"C:\Git\cmd\git.exe", "git log"),
        "引数の違う生成まで却下扱いになっている"
    );
    assert!(
        !read.contains("other-domain", r"C:\Git\cmd\git.exe", "git status"),
        "別の遷移元ドメインまで却下扱いになっている"
    );
}

/// 壊れたファイルは**空一覧ではなく理由**として返し、**上書きしない**。
#[test]
fn a_broken_file_is_reported_and_left_as_it_is() {
    let tmp = tempfile::tempdir().unwrap();
    write_raw(tmp.path(), "これはJSONではない");

    let read = load(tmp.path());
    assert!(
        matches!(read, Err(DismissedError::Parse { .. })),
        "壊れたファイルを黙って空にしている: {read:?}"
    );

    let write = update(
        tmp.path(),
        &keys(&[("C:/git.exe", "git status")]),
        &none(),
        1,
    );
    assert!(write.is_err(), "壊れたファイルの上に書いている");
    assert_eq!(
        std::fs::read_to_string(path(tmp.path())).unwrap(),
        "これはJSONではない",
        "壊れた中身が上書きされた"
    );
}

/// 新しい版のエディタが書いたファイルは**読まず、書き戻さない**
/// （古い形で書き戻すと、新しい版の欄が黙って消える）。
#[test]
fn a_file_from_a_newer_editor_is_neither_read_nor_overwritten() {
    let tmp = tempfile::tempdir().unwrap();
    let newer = format!(
        r#"{{"schema_version": {}, "dismissed": [], "future": true}}"#,
        SCHEMA_VERSION + 1
    );
    write_raw(tmp.path(), &newer);

    let read = load(tmp.path());
    assert!(
        matches!(
            read,
            Err(DismissedError::UnsupportedVersion { found, supported, .. })
                if found == SCHEMA_VERSION + 1 && supported == SCHEMA_VERSION
        ),
        "知らない版を読んでいる: {read:?}"
    );
    assert!(update(
        tmp.path(),
        &keys(&[("C:/git.exe", "git status")]),
        &none(),
        1
    )
    .is_err());
    assert_eq!(std::fs::read_to_string(path(tmp.path())).unwrap(), newer);
}
