use super::*;

fn value<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
    env.iter()
        .rev()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// 親の環境から来た `GIT_*` は1つも子へ渡らない。渡ると `GIT_DIR` などで git dir の指定
/// そのものを差し替えられる。許可側: `GIT_` で始まらない土台は残り、固定の値は入る。
#[test]
fn inherited_git_variables_are_dropped_and_the_pins_are_added() {
    let base = vec![
        ("GIT_DIR".to_string(), r"C:\agent\.git".to_string()),
        (
            "git_object_directory".to_string(),
            r"C:\agent\objects".to_string(),
        ),
        (
            "GIT_CONFIG_PARAMETERS".to_string(),
            "'core.fsmonitor=evil'".to_string(),
        ),
        ("SYSTEMROOT".to_string(), r"C:\Windows".to_string()),
    ];
    let launcher = GitLauncher::new(PathBuf::from("git"), base, std::env::temp_dir());
    let env = launcher.env();
    assert_eq!(value(env, "GIT_DIR"), None);
    assert_eq!(value(env, "git_object_directory"), None);
    assert_eq!(value(env, "GIT_CONFIG_PARAMETERS"), None);
    assert_eq!(value(env, "SYSTEMROOT"), Some(r"C:\Windows"));
    assert_eq!(value(env, "GIT_CONFIG_KEY_0"), Some("core.hooksPath"));
    assert_eq!(value(env, "GIT_CONFIG_KEY_1"), Some("core.fsmonitor"));
    assert_eq!(value(env, "GIT_NO_REPLACE_OBJECTS"), Some("1"));
    assert_eq!(value(env, "GIT_NO_LAZY_FETCH"), Some("1"));
}

/// 固定した設定が、実際に起動した git から見えている（渡したつもりで渡っていない、を落とす）。
#[test]
fn the_pinned_configuration_reaches_the_git_that_is_started() {
    let cwd = tempfile::tempdir().unwrap();
    let launcher = GitLauncher::from_host(cwd.path().to_path_buf()).expect("git is required");
    for (key, expected) in [
        ("protocol.allow", "never"),
        ("transfer.fsckObjects", "true"),
        (
            "core.hooksPath",
            "harness-empty-git-hooks-dir-does-not-exist",
        ),
        ("core.fsmonitor", "false"),
    ] {
        let out = launcher
            .run_ok(GitAt::Nowhere, &["config", "--get", key], None)
            .unwrap();
        assert_eq!(out.stdout_text().trim(), expected, "{key}");
    }
}

/// 起動の口はこのファイルの1箇所だけ。clippy の `disallowed-methods`（`clippy.toml`）が
/// 他所を止めるが、`#[allow]` を足せば黙らせられるので、許可している箇所の数もここで固定する。
#[test]
fn git_is_spawned_from_exactly_one_place_in_this_crate() {
    let sources = [
        ("launcher.rs", include_str!("launcher.rs")),
        ("lib.rs", include_str!("lib.rs")),
        ("assemble.rs", include_str!("assemble.rs")),
        ("import.rs", include_str!("import.rs")),
        ("worktree.rs", include_str!("worktree.rs")),
        ("lifecycle.rs", include_str!("lifecycle.rs")),
        ("untrusted/mod.rs", include_str!("untrusted/mod.rs")),
        ("untrusted/walk.rs", include_str!("untrusted/walk.rs")),
        ("untrusted/refs.rs", include_str!("untrusted/refs.rs")),
        ("untrusted/objects.rs", include_str!("untrusted/objects.rs")),
    ];
    let needle = concat!("Command", "::new(");
    let allow = concat!("allow(clippy::", "disallowed_methods)");
    let mut spawns = Vec::new();
    let mut allows = Vec::new();
    for (name, text) in sources {
        spawns.extend(std::iter::repeat_n(name, text.matches(needle).count()));
        allows.extend(std::iter::repeat_n(name, text.matches(allow).count()));
    }
    assert_eq!(
        spawns,
        vec!["launcher.rs"],
        "git must be spawned only by GitLauncher::run"
    );
    assert_eq!(allows, vec!["launcher.rs"]);
}
