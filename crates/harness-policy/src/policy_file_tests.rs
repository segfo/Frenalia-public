//! `policy_file`のテスト（`docs/CODE-STRUCTURE-RULES.md`の`#[path]`分離）。

use std::path::Path;

use crate::{generalize::SettingsKey, RuleProposal};

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

    // **版だけは往復で変わり得る。** 書くときは内容から決め直すので、遷移を1本も持たない
    // ファイルは「遷移を知らないバイナリでも読める版」を名乗る。
    assert_eq!(read_back.domains, file.domains);
    assert_eq!(read_back.schema_version, file.required_schema_version());
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

// ---------------------------------------------------------------------------
// 遷移の宣言とスキーマ版（段階⑥a）
// ---------------------------------------------------------------------------

fn policy_with_transition(schema_version: u32) -> String {
    format!(
        r#"{{
          "schema_version": {schema_version},
          "domains": [
            {{
              "name": "shell",
              "process": {{
                "transitions": [
                  {{
                    "exe":  {{ "literal": "C:\\Program Files\\Git\\cmd\\git.exe" }},
                    "argv": {{ "any": true }},
                    "to":   "shell"
                  }}
                ]
              }}
            }}
          ]
        }}"#
    )
}

fn write_policy(ws: &Path, text: &str) {
    std::fs::create_dir_all(ws.join(".harness")).unwrap();
    std::fs::write(path(ws), text).unwrap();
}

/// **版が内容に追いついていないファイルは拒否する**（`plans/DESIGN-MAC.md` §5.1(7)）。
///
/// 版1のまま遷移が書かれたファイルは、遷移を知らない古いバイナリが**黙って無視して**読む。
/// 版を正しく上げてあるものは通る（対）。
#[test]
fn a_transition_declared_under_the_old_schema_version_is_refused_but_the_new_one_loads() {
    let ws = workspace();
    write_policy(ws.path(), &policy_with_transition(1));
    let err = load(ws.path()).expect_err("version 1 cannot carry a transition");
    assert!(
        matches!(err, PolicyFileError::UnversionedTransitions { .. }),
        "unexpected error: {err}"
    );

    write_policy(ws.path(), &policy_with_transition(POLICY_SCHEMA_VERSION));
    let file = load(ws.path()).expect("the correctly versioned file loads");
    assert_eq!(file.domains[0].process.transitions.len(), 1);
}

/// 書く側は**内容から版を決める**。足したら上がり、足していなければ上がらない（対）。
#[test]
fn saving_raises_the_schema_version_only_when_a_transition_is_actually_declared() {
    let ws = workspace();

    let mut file = PolicyFile::default();
    file.domains.push(PolicyDomain::new("shell"));
    save(ws.path(), &file).expect("save without transitions");
    let text = std::fs::read_to_string(path(ws.path())).unwrap();
    assert!(
        text.contains("\"schema_version\": 1"),
        "a file without transitions must stay readable by older binaries: {text}"
    );
    assert!(
        !text.contains("\"process\""),
        "an empty process key must not be written at all: {text}"
    );

    file.domains[0].process = serde_json::from_str(
        r#"{"transitions":[{"exe":{"literal":"C:\\x\\git.exe"},"argv":{"any":true},"to":"shell"}]}"#,
    )
    .unwrap();
    save(ws.path(), &file).expect("save with a transition");
    let text = std::fs::read_to_string(path(ws.path())).unwrap();
    assert!(
        text.contains(&format!("\"schema_version\": {POLICY_SCHEMA_VERSION}")),
        "declaring a transition must raise the version: {text}"
    );

    // 書いたものは読み戻せる（書く側と読む側が同じ規則を通っている）。
    let read_back = load(ws.path()).expect("load what we just wrote");
    assert_eq!(read_back.domains[0].process.transitions.len(), 1);
}

/// **編集時検査は`load`に配線されている。** 検査が在ることと呼ばれていることは別の事実で、
/// 後者が抜けるのがこの種の欠陥の本体である（`bug-pattern-rules` B-06）。
#[test]
fn a_hand_written_edge_that_fails_the_checks_is_refused_at_load_time() {
    let ws = workspace();
    write_policy(
        ws.path(),
        &format!(
            r#"{{
              "schema_version": {POLICY_SCHEMA_VERSION},
              "domains": [
                {{
                  "name": "shell",
                  "process": {{
                    "transitions": [
                      {{ "exe": {{ "literal": "git.exe" }}, "argv": {{ "any": true }}, "to": "shell" }}
                    ]
                  }}
                }}
              ]
            }}"#
        ),
    );

    let err = load(ws.path()).expect_err("a leaf-only exe must not load");
    match err {
        PolicyFileError::RejectedTransitions { reason, .. } => {
            assert!(
                reason.contains("is not a full path"),
                "the reason should name what is wrong: {reason}"
            );
        }
        other => panic!("unexpected error: {other}"),
    }
}

/// ワークスペースは`policy.json`に宣言として現れないが、**呼び出し元が書ける場所**である。
/// `load`はそれを判定器へ渡している——渡していなければ、この辺は通ってしまう。
#[test]
fn the_workspace_root_is_handed_to_the_checker_as_a_caller_writable_place() {
    let ws = workspace();
    let script = ws
        .path()
        .join("a.py")
        .to_string_lossy()
        .replace('\\', "\\\\");
    let cwd = ws.path().to_string_lossy().replace('\\', "\\\\");
    write_policy(
        ws.path(),
        &format!(
            r#"{{
              "schema_version": {POLICY_SCHEMA_VERSION},
              "domains": [
                {{
                  "name": "shell",
                  "process": {{
                    "transitions": [
                      {{
                        "exe":  {{ "literal": "C:\\python\\python.exe" }},
                        "argv": {{ "literal": "\"C:\\python\\python.exe\" {script}" }},
                        "cwd":  "{cwd}",
                        "to":   "shell"
                      }}
                    ]
                  }}
                }}
              ]
            }}"#
        ),
    );

    let err = load(ws.path()).expect_err("a fixed value inside the workspace must not load");
    match err {
        PolicyFileError::RejectedTransitions { reason, .. } => assert!(
            reason.contains("which this domain can write"),
            "the reason should say the caller can rewrite it: {reason}"
        ),
        other => panic!("unexpected error: {other}"),
    }
}

/// ワークスペースの**外**にあるプログラムを、引数と作業ディレクトリごと固定した辺を1本書く。
fn write_fixed_edge_outside_the_workspace(ws: &Path) {
    let cwd = ws.to_string_lossy().replace('\\', "\\\\");
    write_policy(
        ws,
        &format!(
            r#"{{
              "schema_version": {POLICY_SCHEMA_VERSION},
              "domains": [
                {{
                  "name": "shell",
                  "process": {{
                    "transitions": [
                      {{
                        "exe":  {{ "literal": "C:\\tools\\gen.exe" }},
                        "argv": {{ "literal": "\"C:\\tools\\gen.exe\" --check" }},
                        "cwd":  "{cwd}",
                        "to":   "shell"
                      }}
                    ]
                  }}
                }}
              ]
            }}"#
        ),
    );
}

/// [残課題 サンドボックス周辺 #65] **`policy.json`の外で書込を許した場所**
/// （`settings.json`の`fs.read_write`・`--fs-allow <path>:rw`）も、呼び出し元が書ける場所である。
/// 固定したプログラムがその下にあれば拒否し、**どの書ける場所に当たったか**を文面に出す
/// ——宣言のどこにも書込が無いので、根を出さないと理由が辿れない。
#[test]
fn a_fixed_value_under_a_place_made_writable_outside_the_policy_is_rejected() {
    let ws = workspace();
    write_fixed_edge_outside_the_workspace(ws.path());

    let err = load_for_session(ws.path(), &[r"C:\tools".to_string()])
        .expect_err("a fixed program under a writable place must not load");
    match err {
        PolicyFileError::RejectedTransitions { reason, .. } => {
            assert!(
                reason.contains("which this domain can write"),
                "the reason should say the caller can rewrite it: {reason}"
            );
            assert!(
                reason.contains("c:/tools"),
                "the reason should name the writable place it lies under: {reason}"
            );
        }
        other => panic!("unexpected error: {other}"),
    }
}

/// 上の対（許可側）。**同じ`policy.json`**が、書ける場所を渡さなければ通り、
/// 別の場所を指す書ける場所を渡しても通る——拒否したのは渡した一覧であって、
/// 辺そのものの形ではないことを固定する（B-35）。
#[test]
fn the_same_fixed_edge_loads_when_no_writable_place_covers_it() {
    let ws = workspace();
    write_fixed_edge_outside_the_workspace(ws.path());

    load(ws.path()).expect("without places writable outside the policy, the edge is fine");
    load_for_session(ws.path(), &[r"C:\other".to_string()])
        .expect("a writable place elsewhere does not cover C:\\tools\\gen.exe");
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

// **「置き場が`.harness`配下で、かつ除外規則がそれを覆っている」を測る対のテストは、
// `harness-policy-editor`の`exclusion_tests.rs`にある**（2026-09-12にこのモジュールを
// 移設した際に移した）。除外規則（`is_harness_control_path`）があちらのクレートにあり、
// **2つが対になっていることに意味がある**ので、片方だけをこちらへ残して分断しない。

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

// ---------------------------------------------------------------------------
// [2026-10-01] `save`は`load`が受け付けないファイルを書かない
// ---------------------------------------------------------------------------

/// 入口から空のドメイン`iso`へ移る辺を1本持つ宣言（遷移先は何も持たないので「狭める」）。
fn entry_with_an_edge_to_an_empty_domain() -> PolicyFile {
    serde_json::from_str(&format!(
        r#"{{
          "schema_version": {POLICY_SCHEMA_VERSION},
          "domains": [
            {{
              "name": "shell",
              "process": {{ "transitions": [
                {{ "exe": {{ "literal": "C:/tools/gen.exe" }}, "argv": {{ "any": true }}, "to": "iso" }}
              ] }}
            }},
            {{ "name": "iso" }}
          ]
        }}"#
    ))
    .expect("parse")
}

/// **許可側**: 遷移先が何も持たない辺（狭める遷移）は書けて、読み戻せる。
#[test]
fn save_writes_a_policy_whose_transitions_pass_the_checks() {
    let ws = workspace();
    save(ws.path(), &entry_with_an_edge_to_an_empty_domain()).expect("a narrowing edge saves");
    load(ws.path()).expect("and loads back");
}

/// **禁止側（対）**: 遷移先へ許可を足して辺が「広げる遷移」に変わったら、**何も書かない**。
///
/// かつては検査せずに書いていたので、ファイル宣言の承認がこの形を作れた——書いた直後から
/// `harness.exe`もエディタも`policy.json`を読めなくなり、手でJSONを直すしか戻す手段が無かった。
/// 元のファイルが残っていること（上書きしていないこと）まで見る。
#[test]
fn save_refuses_a_policy_that_load_would_reject_and_leaves_the_file_alone() {
    let ws = workspace();
    save(ws.path(), &entry_with_an_edge_to_an_empty_domain()).expect("setup");
    let before = std::fs::read_to_string(path(ws.path())).unwrap();

    let mut widened = load(ws.path()).expect("setup loads");
    widened
        .domains
        .iter_mut()
        .find(|d| d.name == "iso")
        .unwrap()
        .fs
        .read
        .push("C:/secrets/**".to_string());

    match save(ws.path(), &widened).expect_err("a widening edge without fixing must not be saved") {
        PolicyFileError::WouldRejectTransitions { reason, .. } => assert!(
            reason.contains("widens"),
            "the reason should be the checker's own words: {reason}"
        ),
        other => panic!("unexpected error: {other}"),
    }
    assert_eq!(
        std::fs::read_to_string(path(ws.path())).unwrap(),
        before,
        "the refused save overwrote policy.json"
    );
    load(ws.path()).expect("the file on disk must still load");
}

/// **直すために読む口（[`load_for_repair`]）は、遷移の検査に落ちる宣言も読み、落ちた理由を返す。**
///
/// [`load`]は同じファイルを断る（`a_hand_written_edge_that_fails_the_checks_is_refused_at_load_time`）ので、
/// それしか無いとエディタは検査に落ちる宣言を一覧にできず、取り消して直す手段も無い（手でJSONを直すしか
/// ない）。宣言画面の遷移タブ（`plans/position-domains/P4.md`のP4.2）がこの口で読む。
///
/// 対の側: 検査に通る宣言では理由が空。**読めないもの（未来の版・版が足りない）は今までどおり断る**——
/// 落とすのは遷移の検査だけで、書く側の[`save`]は同じ検査を掛けたまま。
#[test]
fn load_for_repair_reads_a_policy_that_fails_the_checks_and_says_why() {
    let ws = workspace();
    write_policy(
        ws.path(),
        &format!(
            r#"{{
              "schema_version": {POLICY_SCHEMA_VERSION},
              "domains": [
                {{
                  "name": "shell",
                  "process": {{
                    "transitions": [
                      {{ "exe": {{ "literal": "git.exe" }}, "argv": {{ "any": true }}, "to": "shell" }}
                    ]
                  }}
                }}
              ]
            }}"#
        ),
    );
    let (file, rejections) = load_for_repair(ws.path()).expect("a policy failing the checks reads for repair");
    assert_eq!(file.domains.len(), 1);
    assert_eq!(file.domains[0].process.transitions.len(), 1);
    assert_eq!(rejections.len(), 1, "{rejections:?}");
    assert!(rejections[0].contains("is not a full path"), "{rejections:?}");
    load(ws.path()).expect_err("load itself still refuses it");

    write_policy(ws.path(), &policy_with_transition(POLICY_SCHEMA_VERSION));
    let (_, rejections) = load_for_repair(ws.path()).expect("a valid policy reads");
    assert!(rejections.is_empty(), "{rejections:?}");

    write_policy(ws.path(), &policy_with_transition(SCHEMA_VERSION_WITHOUT_TRANSITIONS));
    assert!(matches!(
        load_for_repair(ws.path()),
        Err(PolicyFileError::UnversionedTransitions { .. })
    ));
    write_policy(
        ws.path(),
        &format!(r#"{{"schema_version":{},"domains":[]}}"#, POLICY_SCHEMA_VERSION + 1),
    );
    assert!(matches!(
        load_for_repair(ws.path()),
        Err(PolicyFileError::FutureSchema { .. })
    ));
}
