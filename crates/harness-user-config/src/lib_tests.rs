//! `harness-user-config`の単体テスト。**昇格もWindows依存も無い。**

use super::*;

/// 無いときに既定値のファイルが書かれ、それを読み戻すと既定値と一致する。
///
/// # なぜ往復で測るのか
///
/// 書き出す中身（`DEFAULT_FILE_TEMPLATE`）は**手で書いたTOML**で、構造体のシリアライズではない
/// ——コメントを残すためである。だから「書いた内容と構造体の既定値が同じ」ことは自動では保証されず、
/// フィールドを足してテンプレートを直し忘れると静かにずれる。ここが唯一の歯である。
#[test]
fn a_generated_file_round_trips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(CONFIG_FILE_NAME);

    let first = load_from(&path).expect("a missing file must yield the defaults");
    assert_eq!(first, UserConfig::default());
    assert!(path.exists(), "the default file must be written out");

    let second = load_from(&path).expect("the generated file must parse");
    assert_eq!(
        second,
        UserConfig::default(),
        "the generated file does not round-trip: DEFAULT_FILE_TEMPLATE and the struct defaults \
         have drifted apart"
    );
}

/// 書き出したファイルにはコメントが残る（人が読んで直せる形であること）。
#[test]
fn the_generated_file_explains_each_setting() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(CONFIG_FILE_NAME);
    load_from(&path).expect("defaults");

    let text = std::fs::read_to_string(&path).expect("read back");
    assert!(
        text.contains("refuse_untrusted_links"),
        "the setting is missing from the generated file: {text}"
    );
    assert!(
        text.lines().filter(|l| l.trim_start().starts_with('#')).count() >= 5,
        "the generated file must explain what each setting does: {text}"
    );
}

/// **禁止側**: 壊れているときは`Err`を返し、**元のファイルを1バイトも書き換えない**。
///
/// これが流用元（`libtoolbox`の`config_loader.rs`）との差そのものである。あちらは
/// 既定値で上書きするので、ユーザーが書いた設定が黙って消える。
#[test]
fn a_malformed_file_is_refused_and_left_untouched() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(CONFIG_FILE_NAME);
    let broken = "[security]\nrefuse_untrusted_links = \n";
    std::fs::write(&path, broken).expect("seed a broken file");

    let err = load_from(&path).expect_err("a malformed file must not be accepted");
    assert!(
        matches!(err, UserConfigError::Parse { .. }),
        "unexpected error kind: {err:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&path).expect("read back"),
        broken,
        "**the malformed file was rewritten.** The user's settings would be lost silently"
    );
}

/// 型が合わないときも同じ（真偽値のところに文字列）。
#[test]
fn a_wrongly_typed_value_is_refused_and_left_untouched() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(CONFIG_FILE_NAME);
    let wrong = "[security]\nrefuse_untrusted_links = \"yes\"\n";
    std::fs::write(&path, wrong).expect("seed");

    let err = load_from(&path).expect_err("a wrongly typed value must not be accepted");
    assert_eq!(std::fs::read_to_string(&path).expect("read back"), wrong);
    let text = err.to_string();
    assert!(
        text.contains("boolean") || text.contains("bool"),
        "the message must say what type was expected: {text}"
    );
}

/// 知らないキーは拒否する（`deny_unknown_fields`）。
///
/// 綴りを間違えたキーを黙って無視すると、**設定したのに効いていない**状態になる（`B-32`）。
#[test]
fn an_unknown_key_is_refused_so_a_typo_is_not_silently_ignored() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(CONFIG_FILE_NAME);
    std::fs::write(
        &path,
        "[security]\nrefuse_untrusted_link = true\n", // 末尾の s が無い
    )
    .expect("seed");

    let err = load_from(&path).expect_err("a typo must not be ignored");
    let text = err.to_string();
    assert!(
        text.contains("refuse_untrusted_link"),
        "the message must name the key that was not understood: {text}"
    );
}

/// エラーの文面に**どこが壊れているか**（行）が入る。
#[test]
fn the_error_says_where_the_file_is_broken() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(CONFIG_FILE_NAME);
    // 3行目を壊す。
    std::fs::write(&path, "[security]\n\nrefuse_untrusted_links = = true\n").expect("seed");

    let err = load_from(&path).expect_err("malformed");
    let text = err.to_string();
    assert!(
        text.contains('3') || text.contains("line"),
        "the message must point at the broken line: {text}"
    );
    assert!(
        text.contains(CONFIG_FILE_NAME),
        "the message must name the file: {text}"
    );
}

/// **許可側（対）**: 書かれた値がそのまま読める。既定値を返すだけの実装では緑にならない。
#[test]
fn a_value_written_by_the_user_is_what_comes_back() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(CONFIG_FILE_NAME);
    std::fs::write(&path, "[security]\nrefuse_untrusted_links = false\n").expect("seed");

    let config = load_from(&path).expect("a valid file must parse");
    assert!(
        !config.security.refuse_untrusted_links,
        "the user's value was discarded"
    );
}

/// 節ごと書かれていなくても既定値で埋まる（部分的に書いたファイルが拒否されない）。
#[test]
fn a_file_without_the_section_still_yields_the_defaults() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(CONFIG_FILE_NAME);
    std::fs::write(&path, "# 何も設定していない\n").expect("seed");

    let config = load_from(&path).expect("an empty file is valid");
    assert_eq!(config, UserConfig::default());
}

/// **既定は「守る」側である。** 既定値を緩い側に置くと、ファイルを消しただけで守りが外れる。
#[test]
fn the_default_is_to_refuse_untrusted_links() {
    assert!(UserConfig::default().security.refuse_untrusted_links);
}
