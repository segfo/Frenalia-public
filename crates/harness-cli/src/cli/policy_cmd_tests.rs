//! [`crate::cli::policy_cmd`]の単体テスト。
//!
//! `harness-policy`側（正規化・一般化・差分・矛盾チェック）は純粋関数として個別にテスト済みなので、
//! ここが担うのは**CLI層でしか壊れない性質**だけである:
//!
//! - 収集源のパス解決（どのファイルを読みに行くか）
//! - `--source`/`--generalize`の受理と拒否
//! - **提案が自動適用されないこと**（M15.7の完了条件、D-42）
//! - **収集器不在時のfail-open**（同、D-43）

use super::*;

use harness_policy::Source;

/// `--source`は既定で全経路、明示指定なら1経路に絞る。綴りを間違えたら黙って全件にせずエラー。
#[test]
fn source_selection_defaults_to_all_and_rejects_unknown_spellings() {
    assert_eq!(resolve_sources(None).unwrap(), Source::ALL.to_vec());
    assert_eq!(resolve_sources(Some("all")).unwrap(), Source::ALL.to_vec());
    assert_eq!(resolve_sources(Some("etw")).unwrap(), vec![Source::Etw]);
    assert_eq!(
        resolve_sources(Some("network")).unwrap(),
        vec![Source::Network]
    );

    let err = resolve_sources(Some("everything")).unwrap_err();
    assert!(err.contains("everything"), "{err}");
    assert!(
        err.contains("preflight"),
        "the error lists the valid values"
    );
}

/// `--generalize`の既定は`dir`。未知の値は既定へ倒さずエラーにする——「設定したのに効かない」に
/// 気付けない状態を作らないため（`harness-config`のフェーズ名typoと同じ方針）。
#[test]
fn generalization_selection_defaults_to_directory_and_rejects_unknown_spellings() {
    assert_eq!(
        resolve_generalization(None).unwrap(),
        Generalization::Directory
    );
    assert_eq!(
        resolve_generalization(Some("none")).unwrap(),
        Generalization::None
    );
    assert_eq!(
        resolve_generalization(Some("auto")).unwrap(),
        Generalization::Auto
    );

    assert!(resolve_generalization(Some("aggressive")).is_err());
}

/// OS監査の出力先は`net-audit.jsonl`と同じセッションディレクトリ（同じセッションで起きたことを
/// 1箇所へ集める）。`--session`の`session-`接頭辞は有無どちらでも同じ場所を指す。
#[test]
fn fs_audit_path_sits_next_to_the_net_audit_log() {
    let workspace = Path::new(r"C:\workspace");

    let fs_audit = fs_audit_path(workspace, Some("abc123"), None).unwrap();
    let net_audit = net_audit_path(workspace, Some("abc123"), None).unwrap();

    assert_eq!(fs_audit.parent(), net_audit.parent());
    assert_eq!(fs_audit.file_name().unwrap(), "fs-audit.jsonl");
    assert_eq!(
        fs_audit_path(workspace, Some("session-abc123"), None).unwrap(),
        fs_audit
    );
}

#[test]
fn explicit_fs_audit_path_takes_precedence_over_session_resolution() {
    let explicit = Path::new(r"C:\logs\elsewhere.jsonl");

    assert_eq!(
        fs_audit_path(Path::new(r"C:\workspace"), Some("ignored"), Some(explicit)),
        Some(explicit.to_path_buf())
    );
}

/// **D-43 fail-open**: 収集源のファイルが1つも存在しないワークスペースでも、
/// `collect_input`はエラーにならず「読めなかった」というレポートを返す。
#[test]
fn missing_collection_sources_yield_unavailable_reports_not_errors() {
    let dir = tempfile::tempdir().unwrap();

    let input = collect_input(
        dir.path(),
        Some("nonexistent-session"),
        &[Source::Network, Source::Etw],
    );

    assert!(input.candidates().is_empty());
    let unavailable = input.unavailable();
    assert_eq!(unavailable.len(), 2);
    assert!(unavailable.iter().any(|(s, _)| *s == Source::Etw));
    assert!(unavailable.iter().any(|(s, _)| *s == Source::Network));
}

/// 収集器が居なくても、読めた経路の分だけ提案が出る。**「etwが無いから何も提案しない」に
/// してはいけない**——それでは既存3経路の情報が捨てられる。
#[test]
fn proposals_still_come_from_readable_sources_when_the_collector_is_absent() {
    let dir = tempfile::tempdir().unwrap();
    let session_dir = dir
        .path()
        .join(".harness")
        .join("sandbox")
        .join("session-x");
    std::fs::create_dir_all(&session_dir).unwrap();
    std::fs::write(
        session_dir.join("net-audit.jsonl"),
        concat!(
            r#"{"kind":"proxy","allowed":false,"host":"blocked.example","reason":"domain_denied"}"#,
            "\n"
        ),
    )
    .unwrap();
    // fs-audit.jsonl（OS監査）は意図的に作らない。

    let input = collect_input(dir.path(), Some("x"), &[Source::Network, Source::Etw]);
    let proposals = input.proposals(Generalization::Directory);

    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].value, "blocked.example");
    assert!(
        input.unavailable().iter().any(|(s, _)| *s == Source::Etw),
        "the missing collector stays visible in the output"
    );
}

/// 収集不能の告知には、なぜそうなったかと「他の経路だけで動いている」ことの両方が出る。
#[test]
fn unavailable_notice_explains_both_the_cause_and_the_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let input = collect_input(dir.path(), Some("x"), &[Source::Etw]);

    let notice = render_unavailable(&input);

    assert!(notice.contains("'etw'"), "{notice}");
    assert!(notice.contains("best-effort"), "{notice}");
    assert!(
        notice.contains("based only on the sources that were readable"),
        "{notice}"
    );
}

/// **D-42（自動適用しない）の中核**: `suggest`相当の経路を通しても`.harness/settings.json`は
/// 1バイトも変わらない。
#[test]
fn suggesting_never_touches_the_settings_file() {
    let dir = tempfile::tempdir().unwrap();
    let harness_dir = dir.path().join(".harness");
    std::fs::create_dir_all(&harness_dir).unwrap();
    let settings_path = harness_dir.join("settings.json");
    let original = "{\n  \"model\": \"untouched\"\n}\n";
    std::fs::write(&settings_path, original).unwrap();

    let session_dir = harness_dir.join("sandbox").join("session-x");
    std::fs::create_dir_all(&session_dir).unwrap();
    std::fs::write(
        session_dir.join("fs-audit.jsonl"),
        concat!(
            r#"{"kind":"etw","path":"C:/Users/me/.cargo","access":"read","allowed":false,"reason":"STATUS_ACCESS_DENIED","timestamp_unix_ms":1}"#,
            "\n"
        ),
    )
    .unwrap();

    let input = collect_input(dir.path(), Some("x"), &[Source::Etw]);
    let proposals = input.proposals(Generalization::Directory);
    let verdicts = gate::check_all(&proposals, harness_core::RequireSandbox::None);
    let rendered = render_output(&proposals, &verdicts, OutputFormat::Text);

    assert!(!proposals.is_empty(), "there is something to propose");
    assert!(rendered.contains("Nothing above has been applied"));
    assert_eq!(
        std::fs::read_to_string(&settings_path).unwrap(),
        original,
        "suggest must not write to the settings file"
    );
}

/// `apply`は`--accept`が空なら何も書かずに失敗する（「全件適用」の暗黙の既定を持たない）。
#[test]
fn apply_without_accept_writes_nothing_and_fails() {
    let dir = tempfile::tempdir().unwrap();
    let settings_path = dir.path().join(".harness").join("settings.json");

    let code = apply_accepted(
        dir.path(),
        &sample_proposals(),
        &[],
        true,
        harness_core::RequireSandbox::None,
    );

    assert_ne!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    assert!(!settings_path.exists(), "nothing was written");
}

/// 未知のidが1つでもあれば、既知の分も含めて何も書かない（部分適用しない）。
#[test]
fn apply_with_an_unknown_id_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let settings_path = dir.path().join(".harness").join("settings.json");

    let code = apply_accepted(
        dir.path(),
        &sample_proposals(),
        &["fs-1".to_string(), "fs-99".to_string()],
        true,
        harness_core::RequireSandbox::None,
    );

    assert_ne!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    assert!(
        !settings_path.exists(),
        "a single unknown id must not leave a partially applied settings file"
    );
}

/// 受理したidの分**だけ**が書かれ、受理しなかった提案は設定に現れない。
#[test]
fn apply_writes_only_the_accepted_proposals() {
    let dir = tempfile::tempdir().unwrap();

    let code = apply_accepted(
        dir.path(),
        &sample_proposals(),
        &["net-1".to_string()],
        true,
        harness_core::RequireSandbox::None,
    );
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));

    let written: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join(".harness").join("settings.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        written["net"]["allow_domains"],
        serde_json::json!(["blocked.example"])
    );
    assert!(
        written.get("fs").is_none(),
        "the fs proposal was not accepted, so it must not appear"
    );
}

/// **D-42最終文**: `--require-sandbox`と矛盾する提案は、`--yes`が付いていても書かない。
#[test]
fn apply_refuses_proposals_that_contradict_require_sandbox() {
    let dir = tempfile::tempdir().unwrap();
    let settings_path = dir.path().join(".harness").join("settings.json");

    let code = apply_accepted(
        dir.path(),
        &sample_proposals(),
        &["fs-1".to_string()],
        true,
        harness_core::RequireSandbox::WriteContainment,
    );

    assert_ne!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    assert!(!settings_path.exists(), "nothing was written");
}

/// 既存の設定は保持され、対象の配列だけが伸びる。
#[test]
fn apply_preserves_unrelated_settings() {
    let dir = tempfile::tempdir().unwrap();
    let harness_dir = dir.path().join(".harness");
    std::fs::create_dir_all(&harness_dir).unwrap();
    std::fs::write(
        harness_dir.join("settings.json"),
        r#"{"model":"keep-me","net":{"allow_domains":["already.example"]}}"#,
    )
    .unwrap();

    let code = apply_accepted(
        dir.path(),
        &sample_proposals(),
        &["net-1".to_string()],
        true,
        harness_core::RequireSandbox::None,
    );
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));

    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(harness_dir.join("settings.json")).unwrap())
            .unwrap();
    assert_eq!(written["model"], "keep-me");
    assert_eq!(
        written["net"]["allow_domains"],
        serde_json::json!(["already.example", "blocked.example"])
    );
}

/// `--accept`はカンマ区切りでも繰り返し指定でも同じ結果になる。
#[test]
fn accept_ids_can_be_comma_separated_or_repeated() {
    for accept in [
        vec!["fs-1,net-1".to_string()],
        vec!["fs-1".to_string(), "net-1".to_string()],
    ] {
        let dir = tempfile::tempdir().unwrap();
        let code = apply_accepted(
            dir.path(),
            &sample_proposals(),
            &accept,
            true,
            harness_core::RequireSandbox::None,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));

        let written: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join(".harness").join("settings.json")).unwrap(),
        )
        .unwrap();
        assert!(written["fs"]["read_write"].is_array());
        assert!(written["net"]["allow_domains"].is_array());
    }
}

/// 監査一覧は経路・access・対象を並べて出す（提案へ畳む前の材料が読めること）。
#[test]
fn audit_listing_shows_the_source_and_access_of_each_candidate() {
    let input = PolicyInput::new(vec![harness_policy::SourceReport {
        source: Source::Cow,
        available: true,
        candidates: vec![harness_policy::DeniedCandidate::fs(
            Source::Cow,
            "C:/Users/me/.gitconfig",
            harness_config::FsAccess::ReadWrite,
            "write outside the workspace was denied by ACL",
            3,
            0,
        )],
        notes: Vec::new(),
    }]);

    let text = render_candidates(&input, OutputFormat::Text);

    assert!(text.contains("cow"), "{text}");
    assert!(text.contains("read_write"), "{text}");
    assert!(text.contains("C:/Users/me/.gitconfig"), "{text}");
    assert!(text.contains("x3"), "{text}");
}

/// JSON出力はそのまま`jq`で読める形（提案の配列）。
#[test]
fn json_output_is_an_array_of_proposals() {
    let proposals = sample_proposals();

    let json = render_output(&proposals, &[], OutputFormat::Json);

    let parsed: serde_json::Value = serde_json::from_str(json.trim()).unwrap();
    assert!(parsed.is_array());
    assert_eq!(parsed[0]["id"], "fs-1");
}

fn sample_proposals() -> Vec<harness_policy::RuleProposal> {
    let candidates = vec![
        harness_policy::DeniedCandidate::fs(
            Source::Cow,
            "C:/Users/me/out",
            harness_config::FsAccess::ReadWrite,
            "denied",
            1,
            0,
        ),
        harness_policy::DeniedCandidate::net(Source::Network, "blocked.example", "denied", 1, 0),
    ];
    harness_policy::generalize::generalize(&candidates, Generalization::None)
}

/// 提案が空でも`suggest`は成功し、「提案するものが無い」と明示する。
#[test]
fn empty_proposals_render_an_explicit_message() {
    let text = render_output(&[], &[], OutputFormat::Text);

    assert!(text.contains("no denied resources"));
}

/// **§15.1の差分推論がCLI経路で効く。** `.harness/settings.json`が既に`fs.read`で許可している
/// パスで拒否が観測されたら、「readでは足りない」と提案へ載る——「`fs.read`を足したのに
/// まだ失敗する」というユーザー体験上いちばん困る状況を解く。
///
/// **D-46以降は注記だけでなくkeyそのものが昇格する**ことも併せて固定する
/// （注記だけだった頃は`apply`が`(no changes)`で終わっていた。W4）。
#[test]
fn a_denial_under_an_existing_read_grant_is_reported_as_insufficient() {
    let dir = tempfile::tempdir().unwrap();
    let harness_dir = dir.path().join(".harness");
    std::fs::create_dir_all(&harness_dir).unwrap();
    std::fs::write(
        harness_dir.join("settings.json"),
        r#"{"fs":{"read":["C:/tools"]}}"#,
    )
    .unwrap();

    let session_dir = harness_dir.join("sandbox").join("session-x");
    std::fs::create_dir_all(&session_dir).unwrap();
    std::fs::write(
        session_dir.join("fs-audit.jsonl"),
        concat!(
            r#"{"kind":"etw","path":"C:/tools/bin/rustc.exe","access":"read","allowed":false,"reason":"STATUS_ACCESS_DENIED","timestamp_unix_ms":1}"#,
            "\n"
        ),
    )
    .unwrap();

    let input = collect_input(dir.path(), Some("x"), &[Source::Etw]);
    let proposals =
        input.proposals_with_granted(Generalization::None, &granted_paths_from(dir.path(), ""));

    let warning = proposals[0]
        .warnings
        .iter()
        .find(|w| w.contains("ALREADY allowed as fs.read"))
        .expect("the insufficiency must be reported");
    assert!(
        warning.contains("adding fs.read again will not"),
        "it must say that repeating fs.read does not help: {warning}"
    );
    assert!(
        !proposals
            .iter()
            .any(|p| p.key == harness_policy::SettingsKey::FsRead),
        "the proposal that cannot work must be replaced, not merely annotated: {proposals:#?}"
    );
}

/// 許可していないパスの拒否には、この注記は付かない（何が足りないかは分からないため）。
#[test]
fn a_denial_on_an_ungranted_path_carries_no_insufficiency_claim() {
    let dir = tempfile::tempdir().unwrap();
    let harness_dir = dir.path().join(".harness");
    let session_dir = harness_dir.join("sandbox").join("session-x");
    std::fs::create_dir_all(&session_dir).unwrap();
    std::fs::write(
        session_dir.join("fs-audit.jsonl"),
        concat!(
            r#"{"kind":"etw","path":"C:/elsewhere/x.txt","access":"read","allowed":false,"reason":"denied","timestamp_unix_ms":1}"#,
            "\n"
        ),
    )
    .unwrap();

    let input = collect_input(dir.path(), Some("x"), &[Source::Etw]);
    let proposals =
        input.proposals_with_granted(Generalization::None, &granted_paths_from(dir.path(), ""));

    assert!(!proposals[0]
        .warnings
        .iter()
        .any(|w| w.contains("ALREADY allowed")));
}

// ---------------------------------------------------------------------------
// W4: 昇格の梯子がCLI経路で最後まで通ること（D-46）
// ---------------------------------------------------------------------------

/// 拒否1件だけを持つワークスペースを組み立てる。
fn workspace_with_one_denial(settings_json: &str, denied_path: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let harness_dir = dir.path().join(".harness");
    std::fs::create_dir_all(&harness_dir).unwrap();
    std::fs::write(harness_dir.join("settings.json"), settings_json).unwrap();

    let session_dir = harness_dir.join("sandbox").join("session-x");
    std::fs::create_dir_all(&session_dir).unwrap();
    std::fs::write(
        session_dir.join("fs-audit.jsonl"),
        format!(
            r#"{{"kind":"etw","path":"{denied_path}","access":"read","allowed":false,"reason":"STATUS_ACCESS_DENIED","timestamp_unix_ms":1}}{}"#,
            "\n"
        ),
    )
    .unwrap();
    dir
}

/// **W4の回帰の本体。** 「`fs.read`済みのパスで拒否 → 提案 → `apply --accept`」が
/// `(no changes)`で終わらず、設定が実際に変わること。
///
/// これが壊れると、ツールが「効かない」と自分で言う提案を出し、適用しても何も起きない
/// 状態（D-46以前）へ戻る。
#[test]
fn applying_an_escalated_proposal_actually_changes_the_settings() {
    let dir =
        workspace_with_one_denial(r#"{"fs":{"read":["C:/tools"]}}"#, "C:/tools/bin/rustc.exe");
    let settings_path = dir.path().join(".harness").join("settings.json");

    let input = collect_input(dir.path(), Some("x"), &[Source::Etw]);
    let proposals =
        input.proposals_with_granted(Generalization::None, &granted_paths_from(dir.path(), ""));
    let read_write = proposals
        .iter()
        .find(|p| p.key == harness_policy::SettingsKey::FsReadWrite)
        .expect("an fs.read_write escalation must be offered");

    let code = apply_accepted(
        dir.path(),
        &proposals,
        std::slice::from_ref(&read_write.id),
        true,
        harness_core::RequireSandbox::None,
    );
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));

    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings_path).unwrap()).unwrap();
    assert_eq!(
        written["fs"]["read_write"],
        serde_json::json!(["C:/tools/bin/rustc.exe"]),
        "the escalation must reach the settings file; anything else means apply printed \
         (no changes) again"
    );
    assert_eq!(
        written["fs"]["read"],
        serde_json::json!(["C:/tools"]),
        "the existing grant is left alone"
    );
}

/// **F12の解消。** `--fs-allow`だけで開けた穴（`settings.json`には無い）でも、
/// 台帳を根拠に「その許可では足りない」へ到達できる。
///
/// 台帳の`writable: false`は`--fs-allow <path>`の既定＝`read_exec`にあたるので、
/// 昇格先は`fs.read_write`の1件になる。
#[test]
fn a_denial_on_an_fs_allow_only_path_escalates_via_the_ledger() {
    let dir = workspace_with_one_denial("{}", "C:/tools/bin/rustc.exe");
    let ledger = r#"{"entries":[{"path":"C:\\tools","writable":false,"granted_at_unix_secs":1}]}"#;

    let input = collect_input(dir.path(), Some("x"), &[Source::Etw]);
    let proposals = input.proposals_with_granted(
        Generalization::None,
        &granted_paths_from(dir.path(), ledger),
    );

    assert_eq!(proposals.len(), 1, "{proposals:#?}");
    assert_eq!(proposals[0].key, harness_policy::SettingsKey::FsReadWrite);
    assert!(proposals[0]
        .warnings
        .iter()
        .any(|w| w.contains("ALREADY allowed as fs.read_exec")));
}

/// 台帳が読めない/壊れていても提案は止まらない（D-43）。この場合は単に
/// 「許可済みと言える材料が無い」＝従来どおり1件の提案になる。
#[test]
fn a_broken_ledger_degrades_to_no_escalation_instead_of_failing() {
    let dir = workspace_with_one_denial("{}", "C:/tools/bin/rustc.exe");

    let input = collect_input(dir.path(), Some("x"), &[Source::Etw]);
    let proposals = input.proposals_with_granted(
        Generalization::None,
        &granted_paths_from(dir.path(), "{ this is not json"),
    );

    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].key, harness_policy::SettingsKey::FsRead);
}

/// 設定の相対パス指定でも、拒否パス（常に絶対）と突き合わせられる。
/// 絶対化していなかった頃は、相対指定した穴が「覆っていない」と誤判定されていた。
#[test]
fn relative_settings_paths_are_resolved_against_the_workspace_root() {
    let dir = workspace_with_one_denial(r#"{"fs":{"read":["vendor"]}}"#, "PLACEHOLDER");
    // 拒否パスはworkspace_root配下の絶対パスとして書き直す。
    let denied = dir
        .path()
        .join("vendor")
        .join("lib.dll")
        .to_string_lossy()
        .replace('\\', "/");
    let session_dir = dir
        .path()
        .join(".harness")
        .join("sandbox")
        .join("session-x");
    std::fs::write(
        session_dir.join("fs-audit.jsonl"),
        format!(
            r#"{{"kind":"etw","path":"{denied}","access":"read","allowed":false,"reason":"denied","timestamp_unix_ms":1}}{}"#,
            "\n"
        ),
    )
    .unwrap();

    let input = collect_input(dir.path(), Some("x"), &[Source::Etw]);
    let proposals =
        input.proposals_with_granted(Generalization::None, &granted_paths_from(dir.path(), ""));

    assert!(
        proposals
            .iter()
            .all(|p| p.key != harness_policy::SettingsKey::FsRead),
        "the relative grant 'vendor' covers the denial, so fs.read must have escalated: \
         {proposals:#?}"
    );
}

// ---------------------------------------------------------------------------
// W5: 提案の幅ガードがCLI経路で効くこと（D-47）
// ---------------------------------------------------------------------------

/// 祖先チェーンの拒否（`cmd`が祖先をオープンするために出る）から作った提案一式。
fn ancestor_chain_proposals() -> Vec<harness_policy::RuleProposal> {
    harness_policy::generalize::generalize(
        &[
            harness_policy::DeniedCandidate::fs(
                Source::Etw,
                "C:/",
                harness_config::FsAccess::Read,
                "STATUS_ACCESS_DENIED",
                1,
                0,
            ),
            harness_policy::DeniedCandidate::fs(
                Source::Etw,
                "C:/Users/me/.cargo/registry",
                harness_config::FsAccess::Read,
                "STATUS_ACCESS_DENIED",
                1,
                0,
            ),
        ],
        Generalization::None,
    )
}

/// **D-47の本体。** ドライブルートの提案は`--yes`が付いていても書かれない。
#[test]
fn apply_refuses_a_proposal_that_would_open_the_whole_drive() {
    let dir = tempfile::tempdir().unwrap();
    let settings_path = dir.path().join(".harness").join("settings.json");
    let proposals = ancestor_chain_proposals();
    let drive_root = proposals
        .iter()
        .find(|p| p.value == "C:/")
        .expect("the drive-root proposal exists");

    let code = apply_accepted(
        dir.path(),
        &proposals,
        std::slice::from_ref(&drive_root.id),
        true,
        harness_core::RequireSandbox::None,
    );

    assert_ne!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    assert!(!settings_path.exists(), "nothing was written");
}

/// 同じ一覧の中の正当な提案は通る（ガードが全部を巻き込んでいないこと）。
#[test]
fn apply_still_accepts_the_narrow_proposal_from_the_same_listing() {
    let dir = tempfile::tempdir().unwrap();
    let proposals = ancestor_chain_proposals();
    let narrow = proposals
        .iter()
        .find(|p| p.value == "C:/Users/me/.cargo/registry")
        .expect("the narrow proposal exists");

    let code = apply_accepted(
        dir.path(),
        &proposals,
        std::slice::from_ref(&narrow.id),
        true,
        harness_core::RequireSandbox::None,
    );
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));

    let written: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join(".harness").join("settings.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        written["fs"]["read"],
        serde_json::json!(["C:/Users/me/.cargo/registry"])
    );
}

/// **部分適用しない。** 広すぎるものを1件混ぜたら、同時に指定した正当な提案も書かれない。
#[test]
fn apply_writes_nothing_when_one_of_the_accepted_ids_is_too_broad() {
    let dir = tempfile::tempdir().unwrap();
    let settings_path = dir.path().join(".harness").join("settings.json");
    let proposals = ancestor_chain_proposals();
    let all_ids: Vec<String> = proposals.iter().map(|p| p.id.clone()).collect();

    let code = apply_accepted(
        dir.path(),
        &proposals,
        &all_ids,
        true,
        harness_core::RequireSandbox::None,
    );

    assert_ne!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    assert!(
        !settings_path.exists(),
        "a partial apply would leave the user with a configuration they never reviewed as a whole"
    );
}

/// `suggest`の一覧からは**消さない**。印と理由を付けて必ず見せる（D-43）。
#[test]
fn suggest_shows_the_too_broad_proposal_with_a_mark_and_a_reason() {
    let proposals = ancestor_chain_proposals();

    let text = render_output(&proposals, &[], OutputFormat::Text);

    assert!(text.contains("[too-broad]"), "{text}");
    assert!(text.contains("drive root"), "{text}");
    assert!(
        text.contains("C:/Users/me/.cargo/registry"),
        "the narrow proposal is still listed too: {text}"
    );
    assert!(
        !text.contains("[too-broad] fs-2"),
        "the narrow proposal must not be marked: {text}"
    );
}

/// `audit`（生の候補一覧）はガードの影響を受けない——収集器が何を観測したかは常に見せる。
#[test]
fn audit_listing_is_untouched_by_the_breadth_guard() {
    let dir = tempfile::tempdir().unwrap();
    let session_dir = dir
        .path()
        .join(".harness")
        .join("sandbox")
        .join("session-x");
    std::fs::create_dir_all(&session_dir).unwrap();
    std::fs::write(
        session_dir.join("fs-audit.jsonl"),
        concat!(
            r#"{"kind":"etw","path":"C:/","access":"read","allowed":false,"reason":"STATUS_ACCESS_DENIED","timestamp_unix_ms":1}"#,
            "\n"
        ),
    )
    .unwrap();

    let input = collect_input(dir.path(), Some("x"), &[Source::Etw]);
    let text = render_candidates(&input, OutputFormat::Text);

    assert!(
        text.contains("C:/"),
        "the observation itself must stay visible: {text}"
    );
}
