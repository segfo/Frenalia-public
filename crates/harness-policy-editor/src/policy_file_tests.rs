//! `policy_file`のテスト（`docs/CODE-STRUCTURE-RULES.md`の`#[path]`分離）。

use std::path::Path;

use harness_policy::{generalize::SettingsKey, RuleProposal};

use super::*;

fn workspace() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn proposal(id: &str, key: SettingsKey, value: &str) -> RuleProposal {
    RuleProposal {
        id: id.to_string(),
        key,
        value: value.to_string(),
        evidence: Vec::new(),
        warnings: Vec::new(),
    }
}

fn ctx<'a>(domain: &'a str, command: Option<&'a str>) -> ApprovalContext<'a> {
    ApprovalContext {
        domain,
        command,
        cwd: None,
        record_session: Some("sess-1"),
        now_unix_ms: 1_700_000_000_000,
    }
}

/// 書いて読み戻せる（往復）。
#[test]
fn a_policy_file_round_trips_through_disk() {
    let ws = workspace();
    let mut file = PolicyFile::default();
    file.merge_approved(
        &[
            &proposal("fs-1", SettingsKey::FsRead, r"C:\Users\x\.cargo\**"),
            &proposal("net-1", SettingsKey::NetAllowDomains, "crates.io"),
        ],
        &ctx("cargo", Some("cargo build")),
    );

    save(ws.path(), &file).expect("save");
    let read_back = load(ws.path()).expect("load");

    assert_eq!(read_back, file);
    let domain = read_back.domain("cargo").expect("the domain must exist");
    assert_eq!(domain.fs.read, vec![r"C:\Users\x\.cargo\**".to_string()]);
    assert_eq!(domain.net.allow_domains, vec!["crates.io".to_string()]);
    assert_eq!(domain.commands, vec!["cargo build".to_string()]);
    assert_eq!(
        domain.provenance.record_sessions,
        vec!["sess-1".to_string()]
    );
}

/// **存在しないファイルだけ**が空扱い。`load`はそれ以外の理由では空を返さない。
#[test]
fn a_missing_policy_file_reads_as_empty() {
    let ws = workspace();

    let file = load(ws.path()).expect("a missing file is not an error");

    assert!(file.domains.is_empty());
    assert_eq!(file.schema_version, POLICY_SCHEMA_VERSION);
}

/// **壊れたJSONは黙って空にしない。** 空に倒すと、承認済みのルールが消えたまま
/// 「承認できました」と言い続け、穴が開いていない状態でパス2が走る（B-10）。
#[test]
fn a_corrupt_policy_file_is_an_error_rather_than_an_empty_policy() {
    let ws = workspace();
    std::fs::create_dir_all(ws.path().join(".harness")).unwrap();
    std::fs::write(path(ws.path()), b"{ this is not json").unwrap();

    let err = load(ws.path()).expect_err("a corrupt file must not read as empty");

    assert!(
        matches!(err, PolicyFileError::Parse { .. }),
        "unexpected error: {err}"
    );
}

/// 未来のスキーマ版は**解釈しようとしない**（知らないフィールドを落として書き戻すと、
/// 新しい版で足した承認が黙って消える）。
#[test]
fn a_newer_schema_version_is_refused_instead_of_being_reinterpreted() {
    let ws = workspace();
    std::fs::create_dir_all(ws.path().join(".harness")).unwrap();
    std::fs::write(
        path(ws.path()),
        format!(
            r#"{{"schema_version":{},"domains":[]}}"#,
            POLICY_SCHEMA_VERSION + 1
        ),
    )
    .unwrap();

    let err = load(ws.path()).expect_err("a future schema must be refused");

    assert!(
        matches!(err, PolicyFileError::FutureSchema { .. }),
        "unexpected error: {err}"
    );
}

/// 同じ値を2回承認しても**増えない**（和集合マージ＝冪等）。
#[test]
fn approving_the_same_value_twice_does_not_duplicate_it() {
    let mut file = PolicyFile::default();
    let p = proposal("fs-1", SettingsKey::FsRead, r"C:\a\**");

    let first = file.merge_approved(&[&p], &ctx("cargo", Some("cargo build")));
    let second = file.merge_approved(&[&p], &ctx("cargo", Some("cargo build")));

    assert_eq!(first.added.len(), 1);
    assert!(first.created_domain);
    assert!(second.added.is_empty(), "2回目は何も増えない");
    assert!(!second.created_domain);
    assert_eq!(
        second.already_present,
        vec![("fs.read", r"C:\a\**".to_string())]
    );
    assert!(second.is_empty(), "差分が無いことを呼び出し側が判定できる");
    assert_eq!(file.domain("cargo").unwrap().fs.read.len(), 1);
}

/// ドメインは**コマンド単位**（決定7）。別ドメインへの承認は互いに漏れない。
#[test]
fn domains_do_not_leak_rules_into_each_other() {
    let mut file = PolicyFile::default();

    file.merge_approved(
        &[&proposal("fs-1", SettingsKey::FsRead, r"C:\cargo\**")],
        &ctx("cargo", Some("cargo build")),
    );
    file.merge_approved(
        &[&proposal("fs-1", SettingsKey::FsReadWrite, r"C:\npm\**")],
        &ctx("npm", Some("npm install")),
    );

    assert_eq!(
        file.domain("cargo").unwrap().fs.read,
        vec![r"C:\cargo\**".to_string()]
    );
    assert!(
        file.domain("cargo").unwrap().fs.read_write.is_empty(),
        "npmのために開けた穴がcargoへ漏れてはいけない（settings.jsonへ書かない理由そのもの）"
    );
    assert_eq!(
        file.domain("npm").unwrap().fs.read_write,
        vec![r"C:\npm\**".to_string()]
    );
    assert!(file.domain("npm").unwrap().fs.read.is_empty());
}

/// 同じドメインを別のコマンドで承認したら、コマンドは**足される**（ルールも和集合）。
#[test]
fn approving_a_second_command_into_the_same_domain_unions_both() {
    let mut file = PolicyFile::default();

    file.merge_approved(
        &[&proposal("fs-1", SettingsKey::FsRead, r"C:\a\**")],
        &ctx("cargo", Some("cargo build")),
    );
    let report = file.merge_approved(
        &[&proposal("fs-1", SettingsKey::FsRead, r"C:\b\**")],
        &ctx("cargo", Some("cargo test")),
    );

    assert!(report.added_command);
    let domain = file.domain("cargo").unwrap();
    assert_eq!(
        domain.commands,
        vec!["cargo build".to_string(), "cargo test".to_string()]
    );
    assert_eq!(
        domain.fs.read,
        vec![r"C:\a\**".to_string(), r"C:\b\**".to_string()]
    );
}

/// `SettingsKey`の4キーが**それぞれ別のバケツ**へ行く（振り分けを取り違えると、
/// 読み取り許可のつもりが書込許可になる）。
#[test]
fn every_settings_key_lands_in_its_own_bucket() {
    let mut file = PolicyFile::default();

    file.merge_approved(
        &[
            &proposal("fs-1", SettingsKey::FsRead, "r"),
            &proposal("fs-2", SettingsKey::FsReadWrite, "rw"),
            &proposal("fs-3", SettingsKey::FsReadExec, "rx"),
            &proposal("net-1", SettingsKey::NetAllowDomains, "example.com"),
        ],
        &ctx("d", None),
    );

    let domain = file.domain("d").unwrap();
    assert_eq!(domain.fs.read, vec!["r".to_string()]);
    assert_eq!(domain.fs.read_write, vec!["rw".to_string()]);
    assert_eq!(domain.fs.read_exec, vec!["rx".to_string()]);
    assert_eq!(domain.net.allow_domains, vec!["example.com".to_string()]);
}

/// `entries()`はaccess種別を保ったまま平坦化する（パス2が`FsPassthrough`へ変換する材料）。
#[test]
fn fs_entries_keep_their_access_kind_when_flattened() {
    use harness_config::FsAccess;

    let rules = FsRules {
        read: vec!["r".to_string()],
        read_write: vec!["rw".to_string()],
        read_exec: vec!["rx".to_string()],
    };

    assert_eq!(
        rules.entries(),
        vec![
            ("r", FsAccess::Read),
            ("rw", FsAccess::ReadWrite),
            ("rx", FsAccess::ReadExec),
        ]
    );
}

/// 全ドメインを横断した宣言済みパスは重複除去される（同じパスを2ドメインが宣言していても1件）。
#[test]
fn declared_paths_across_domains_are_deduplicated() {
    use harness_config::FsAccess;

    let mut file = PolicyFile::default();
    file.merge_approved(
        &[&proposal("fs-1", SettingsKey::FsRead, "shared")],
        &ctx("a", None),
    );
    file.merge_approved(
        &[&proposal("fs-1", SettingsKey::FsRead, "shared")],
        &ctx("b", None),
    );

    assert_eq!(
        file.all_fs_entries(),
        vec![("shared".to_string(), FsAccess::Read)]
    );
}

/// 置き場は`.harness`配下（P-08の制御ディレクトリ側。記録対象から書き換えられない、かつ
/// 次回の記録の候補に自分自身が混ざらない）。
#[test]
fn the_policy_file_lives_inside_the_control_directory() {
    let p = path(Path::new(r"C:\ws"));

    assert_eq!(p, Path::new(r"C:\ws").join(".harness").join("policy.json"));
    assert!(
        crate::exclusion::is_harness_control_path(&p.to_string_lossy()),
        "policy.json自身が候補として提案されると自己参照ループになる"
    );
}

/// ドメイン名の既定値は先頭トークンのbasenameから拡張子を落としたもの。
/// **CLIとTUIが同じ規則を通る**ことに意味がある（別々に持つと、同じコマンドの記録が
/// 別のドメインへ書き込まれる）。
#[test]
fn the_default_domain_name_is_the_basename_of_the_first_token() {
    assert_eq!(default_domain_name("cargo build --release"), "cargo");
    assert_eq!(default_domain_name(r"C:\tools\gh.exe pr list"), "gh");
    assert_eq!(default_domain_name("/usr/bin/rg foo"), "rg");
}

/// **空白を含む引用符付きパスは正しく切れない**（トークン分割が引用符を解釈しないため、
/// `"C:\Program Files\git\git.exe"` は `C:\Program` で切れて `Program` になる）。
/// これは`main.rs`から移す前からの振る舞いで、移動と同時に変えない（`docs/CODE-STRUCTURE-RULES.md`
/// 規則6）。既定値は識別子の提案でしかなく、CLIは`--domain`、TUIは編集画面の入力欄で
/// 上書きできる——ここを直すなら、ドメイン名だけでなくコマンド行の語彙解析として別途行う。
#[test]
fn a_quoted_path_with_spaces_is_a_known_limitation_of_the_default() {
    assert_eq!(
        default_domain_name(r#""C:\Program Files\git\git.exe" status"#),
        "Program"
    );
}

/// 決められない入力では空を返す（呼び出し側が「--domainを指定してください」と言う）。
/// **勝手に何かへ倒さない**——推測した名前でpolicy.jsonにドメインが増える方が厄介である。
#[test]
fn an_empty_command_yields_an_empty_default_domain_name() {
    assert_eq!(default_domain_name(""), "");
    assert_eq!(default_domain_name("   "), "");
}
