//! `approve`のテスト（`docs/CODE-STRUCTURE-RULES.md`の`#[path]`分離）。
//!
//! 中心は**「何も書かない」ことの検証**である。承認は後から効いてくる設定を作る操作なので、
//! 「一部だけ通った」状態が最も危ない（B-35の趣旨で、書ける場合のテストと必ず対にする）。

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

fn request<'a>(
    workspace_root: &'a Path,
    proposals: &'a [RuleProposal],
    accept_ids: &'a [String],
) -> ApproveRequest<'a> {
    ApproveRequest {
        workspace_root,
        proposals,
        accept_ids,
        require_sandbox: RequireSandbox::None,
        domain: "cargo",
        command: Some("cargo build"),
        cwd: None,
        record_session: Some("sess-1"),
        now_unix_ms: 1_700_000_000_000,
    }
}

fn ids(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| v.to_string()).collect()
}

/// 素直な承認: 受理した提案が`policy.json`へ入り、ファイルとして読み戻せる。
#[test]
fn accepting_a_proposal_writes_it_into_the_policy_file() {
    let ws = workspace();
    let proposals = vec![proposal("fs-1", SettingsKey::FsRead, "C:/Users/x/.cargo/**")];
    let accept = ids(&["fs-1"]);

    let plan = plan(&request(ws.path(), &proposals, &accept)).expect("plan");
    commit(ws.path(), &plan).expect("commit");

    let saved = crate::policy_file::load(ws.path()).expect("load");
    assert_eq!(
        saved.domain("cargo").unwrap().fs.read,
        vec!["C:/Users/x/.cargo/**".to_string()]
    );
    assert_eq!(plan.report.added.len(), 1);
}

/// `plan`は**何も書かない**（`commit`を呼ぶまでファイルは生まれない）。
#[test]
fn planning_alone_never_touches_the_disk() {
    let ws = workspace();
    let proposals = vec![proposal("fs-1", SettingsKey::FsRead, "C:/Users/x/.cargo/**")];
    let accept = ids(&["fs-1"]);

    let _plan = plan(&request(ws.path(), &proposals, &accept)).expect("plan");

    assert!(
        !crate::policy_file::path(ws.path()).exists(),
        "確認を取る前に書いてはいけない（D-42）"
    );
}

/// idを1つも指定しなければ拒否する。**全件受理のショートハンドは作らない**（D-42）。
#[test]
fn there_is_no_accept_everything_shorthand() {
    let ws = workspace();
    let proposals = vec![proposal("fs-1", SettingsKey::FsRead, "C:/Users/x/.cargo/**")];
    let accept: Vec<String> = Vec::new();

    let err = plan(&request(ws.path(), &proposals, &accept)).expect_err("must refuse");

    assert!(matches!(err, ApproveError::NoIds), "unexpected: {err}");
}

/// **未知のidが1件でもあれば、他が正しくても何も書かない**（部分適用しない）。
#[test]
fn one_unknown_id_refuses_the_whole_batch() {
    let ws = workspace();
    let proposals = vec![proposal("fs-1", SettingsKey::FsRead, "C:/Users/x/.cargo/**")];
    let accept = ids(&["fs-1", "fs-99"]);

    let err = plan(&request(ws.path(), &proposals, &accept)).expect_err("must refuse");

    assert!(matches!(err, ApproveError::UnknownIds(_)), "unexpected: {err}");
    assert!(
        !crate::policy_file::path(ws.path()).exists(),
        "正しい方のidも書かれてはいけない"
    );
}

/// **広すぎる値（D-47）は1件でも混じれば全体を止める。** 受理1回でマシン全体が開く提案は
/// 実使用で日常的に候補へ並ぶので、机上の懸念ではない。
#[test]
fn one_too_broad_value_refuses_the_whole_batch() {
    let ws = workspace();
    let proposals = vec![
        proposal("fs-1", SettingsKey::FsRead, "C:/Users/x/.cargo/**"),
        proposal("fs-2", SettingsKey::FsRead, "C:/"),
    ];
    let accept = ids(&["fs-1", "fs-2"]);

    let err = plan(&request(ws.path(), &proposals, &accept)).expect_err("must refuse");

    assert!(matches!(err, ApproveError::Refused(_)), "unexpected: {err}");
    assert!(!crate::policy_file::path(ws.path()).exists());
}

/// 対のテスト（B-35）: 同じ形で**広すぎない**値だけなら通る——上のテストが
/// 「常に拒否している」だけで通ってしまわないようにする。
#[test]
fn a_narrow_value_of_the_same_shape_is_accepted() {
    let ws = workspace();
    let proposals = vec![proposal("fs-1", SettingsKey::FsRead, "C:/Users/x/.cargo/**")];
    let accept = ids(&["fs-1"]);

    let plan = plan(&request(ws.path(), &proposals, &accept)).expect("must be accepted");

    assert_eq!(plan.accepted.len(), 1);
}

/// `--require-sandbox`（D-42）と矛盾する提案は、幅の観点では問題なくても止める。
#[test]
fn a_proposal_that_contradicts_require_sandbox_refuses_the_whole_batch() {
    let ws = workspace();
    let proposals = vec![proposal(
        "fs-1",
        SettingsKey::FsReadWrite,
        "C:/Users/x/.cargo/**",
    )];
    let accept = ids(&["fs-1"]);
    let mut req = request(ws.path(), &proposals, &accept);
    req.require_sandbox = RequireSandbox::WriteContainment;

    let err = plan(&req).expect_err("must refuse");

    assert!(matches!(err, ApproveError::Refused(_)), "unexpected: {err}");
    assert!(!crate::policy_file::path(ws.path()).exists());
}

/// 対のテスト（B-35）: 同じ`--require-sandbox`でも読み取りだけなら通る
/// ——「その設定にすると何も承認できない」わけではないことを示す。
#[test]
fn a_read_only_proposal_passes_the_same_require_sandbox() {
    let ws = workspace();
    let proposals = vec![proposal("fs-1", SettingsKey::FsRead, "C:/Users/x/.cargo/**")];
    let accept = ids(&["fs-1"]);
    let mut req = request(ws.path(), &proposals, &accept);
    req.require_sandbox = RequireSandbox::WriteContainment;

    let plan = plan(&req).expect("read-only must pass write-containment");

    assert_eq!(plan.accepted.len(), 1);
}

/// workspace内・外の分類。**外の件数がマシンのACLを実際に変える件数**である。
#[test]
fn paths_are_classified_by_which_side_of_the_workspace_they_are_on() {
    let ws = workspace();
    let root = ws.path().to_string_lossy().replace('\\', "/");
    let proposals = vec![
        proposal("fs-1", SettingsKey::FsRead, &format!("{root}/src/**")),
        proposal("fs-2", SettingsKey::FsRead, "C:/Users/x/.cargo/**"),
        proposal("net-1", SettingsKey::NetAllowDomains, "crates.io"),
    ];
    let accept = ids(&["fs-1", "fs-2", "net-1"]);

    let plan = plan(&request(ws.path(), &proposals, &accept)).expect("plan");

    assert_eq!(
        plan.classes,
        vec![
            PathClass::InsideWorkspace,
            PathClass::OutsideWorkspace,
            PathClass::NotFilesystem,
        ]
    );
    assert_eq!(plan.outside_workspace_count(), 1);
}

/// **接頭辞が一致するだけの別ディレクトリをworkspace内と誤判定しない。**
/// `C:/ws2`は`C:/ws`の配下ではない——ここを間違えると、実際にはACEが要るパスを
/// 「workspaceが覆うので不要」と表示してしまい、パス2が原因不明で落ちる。
#[test]
fn a_sibling_directory_with_a_shared_prefix_is_not_inside_the_workspace() {
    let proposals = vec![
        proposal("fs-1", SettingsKey::FsRead, "C:/ws2/src/**"),
        proposal("fs-2", SettingsKey::FsRead, "C:/ws/src/**"),
    ];
    let accept = ids(&["fs-1", "fs-2"]);
    let workspace_root = Path::new(r"C:\ws");

    let plan = plan(&request(workspace_root, &proposals, &accept)).expect("plan");

    assert_eq!(
        plan.classes,
        vec![PathClass::OutsideWorkspace, PathClass::InsideWorkspace]
    );
}

/// 提案の値が`\`区切り、workspace rootが`/`区切りでも（あるいは逆でも）一致する
/// ——綴りを揃える規則を2つ持たない（B-19）。
#[test]
fn classification_survives_mixed_path_separators_and_case() {
    let proposals = vec![proposal("fs-1", SettingsKey::FsRead, r"C:\WS\Src\**")];
    let accept = ids(&["fs-1"]);

    let plan = plan(&request(Path::new("C:/ws"), &proposals, &accept)).expect("plan");

    assert_eq!(plan.classes, vec![PathClass::InsideWorkspace]);
}

/// 同じidを2回書いても二重に取り込まない。
#[test]
fn repeating_an_id_does_not_accept_it_twice() {
    let ws = workspace();
    let proposals = vec![proposal("fs-1", SettingsKey::FsRead, "C:/Users/x/.cargo/**")];
    let accept = ids(&["fs-1", "fs-1"]);

    let plan = plan(&request(ws.path(), &proposals, &accept)).expect("plan");

    assert_eq!(plan.accepted.len(), 1);
    assert_eq!(plan.report.added.len(), 1);
}

/// ワイルドカードを含む値から、**実際にACEを付けるディレクトリ**を取り出す。
#[test]
fn the_grant_root_is_the_literal_prefix_before_any_wildcard() {
    let ws = Path::new(r"C:\ws");

    assert_eq!(
        grant_root("C:/Users/x/.cargo/**", ws),
        Some(std::path::PathBuf::from("C:/Users/x/.cargo"))
    );
    assert_eq!(
        grant_root("C:/Users/x/.rustup/toolchains/*/bin", ws),
        Some(std::path::PathBuf::from("C:/Users/x/.rustup/toolchains")),
        "`*`を含む要素の1つ手前まで（`*`を含んだままのパスへACEは付けられない）"
    );
    assert_eq!(
        grant_root("C:/Users/x/.cargo/config.toml", ws),
        Some(std::path::PathBuf::from("C:/Users/x/.cargo/config.toml")),
        "ワイルドカードが無ければそのまま"
    );
}

/// **workspace配下は付与対象にしない**（Tier2aのworkspace grantが既に覆っている）。
/// ここを間違えると、26万ノードのツリーへ別主体のACEを重ねて撒くことになる。
#[test]
fn paths_inside_the_workspace_are_not_granted_again() {
    let ws = Path::new(r"C:\ws");

    assert_eq!(grant_root("C:/ws/src/**", ws), None);
    assert_eq!(grant_root(r"C:\ws\target\debug", ws), None);
    assert!(
        grant_root("C:/ws2/src/**", ws).is_some(),
        "接頭辞が一致するだけの別ディレクトリは付与対象（workspaceではない）"
    );
}

/// ドライブ文字だけしか残らない値は付与対象にしない（事実上ドライブ全体への付与になる）。
/// `breadth::check`が承認時に止めているはずだが、**変換側でも受け取らない**。
#[test]
fn a_value_that_reduces_to_a_drive_root_is_not_granted() {
    let ws = Path::new(r"C:\ws");

    assert_eq!(grant_root("C:/*", ws), None);
    assert_eq!(grant_root("C:/", ws), None);
}

/// **壊れた`policy.json`の上に書き足さない。** 読めない状態で承認を続けると、既存の承認を
/// 失ったファイルで上書きすることになる（B-10）。
#[test]
fn approving_on_top_of_a_corrupt_policy_file_fails_instead_of_overwriting_it() {
    let ws = workspace();
    std::fs::create_dir_all(ws.path().join(".harness")).unwrap();
    std::fs::write(crate::policy_file::path(ws.path()), b"{ broken").unwrap();
    let proposals = vec![proposal("fs-1", SettingsKey::FsRead, "C:/Users/x/.cargo/**")];
    let accept = ids(&["fs-1"]);

    let err = plan(&request(ws.path(), &proposals, &accept)).expect_err("must refuse");

    assert!(matches!(err, ApproveError::PolicyFile(_)), "unexpected: {err}");
    assert_eq!(
        std::fs::read(crate::policy_file::path(ws.path())).unwrap(),
        b"{ broken",
        "壊れたファイルを上書きもしない"
    );
}
