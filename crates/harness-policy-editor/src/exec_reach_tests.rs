//! [`crate::exec_reach`]の真理値表。**実機も管理者権限も要らない**——判定は宣言と
//! 付与結果だけで決まる純粋関数なので、全状態を網羅できる。
//!
//! ここで固定するのは「拒否される」ことではなく、**画面に出る文言がユーザーの次の操作を
//! 決められること**である（B-32）。実際の事故は「拒否されたが何をすればいいか分からない」
//! であって、「拒否された」ことそのものではなかった。

use super::*;

fn ws() -> PathBuf {
    PathBuf::from("C:/work")
}

fn exe() -> PathBuf {
    PathBuf::from("C:/Users/segfo/.cargo/bin/cargo.exe")
}

/// 今回の事故そのもの: `.cargo/bin`が`fs.read`として承認されている。
#[test]
fn a_read_only_declaration_is_reported_as_missing_the_execute_right() {
    let entries = [("C:/Users/segfo/.cargo/bin", FsAccess::Read)];

    let reach = diagnose(&exe(), &entries, &ws(), &[]);

    assert_eq!(reach.is_reachable(), Some(false));
    let message = reach.message().expect("a warning is required");
    assert!(message.contains("fs.read"), "{message}");
    assert!(message.contains("read_exec"), "{message}");
    assert!(
        message.contains("C:/Users/segfo/.cargo/bin/cargo.exe"),
        "the message must name the value to approve, not just the problem: {message}"
    );
}

/// `fs.read_write`も実行権を含まない（`ReadWrite`に`FILE_GENERIC_EXECUTE`は入っていない）。
#[test]
fn a_read_write_declaration_also_lacks_the_execute_right() {
    let entries = [("C:/Users/segfo/.cargo/bin", FsAccess::ReadWrite)];

    let reach = diagnose(&exe(), &entries, &ws(), &[]);

    assert!(matches!(reach, ExecReach::NoExecRight { .. }));
    assert!(reach.message().unwrap().contains("fs.read_write"));
}

/// **対**（B-35）: 正しく承認されていれば警告は出ない。
/// 拒否側だけを固定すると、「常に警告」でもテストが緑になる。
#[test]
fn a_read_exec_declaration_produces_no_warning() {
    let entries = [("C:/Users/segfo/.cargo/bin", FsAccess::ReadExec)];

    let reach = diagnose(&exe(), &entries, &ws(), &[]);

    assert_eq!(reach.is_reachable(), Some(true));
    assert_eq!(
        reach.message(),
        None,
        "a warning that always fires is noise"
    );
}

/// **`read_write`と`read_exec`が同時に宣言されていたら、実行権のある方を根拠にする。**
/// 「最も広いものを1つ」に畳んでから見ると`read_write`が勝ち、実行できるのに警告が出る。
#[test]
fn an_exec_declaration_wins_over_a_write_declaration_on_the_same_path() {
    let entries = [
        ("C:/Users/segfo/.cargo/bin", FsAccess::ReadWrite),
        ("C:/Users/segfo/.cargo/bin", FsAccess::ReadExec),
    ];

    assert_eq!(
        diagnose(&exe(), &entries, &ws(), &[]).is_reachable(),
        Some(true)
    );
}

/// 宣言が1件も無いとき。
#[test]
fn an_undeclared_executable_is_named_with_the_value_to_approve() {
    let entries = [("C:/Users/segfo/.rustup", FsAccess::ReadExec)];

    let reach = diagnose(&exe(), &entries, &ws(), &[]);

    assert!(matches!(reach, ExecReach::NotDeclared { .. }));
    let message = reach.message().unwrap();
    assert!(message.contains("1件も許可されていません"), "{message}");
    assert!(
        message.contains("C:/Users/segfo/.cargo/bin/cargo.exe"),
        "{message}"
    );
}

/// workspace配下の実行ファイルはworkspace grantが覆う（read/write/execute/delete）。
#[test]
fn an_executable_inside_the_workspace_needs_no_declaration() {
    let reach = diagnose(&PathBuf::from("C:/work/tools/build.exe"), &[], &ws(), &[]);

    assert_eq!(reach.is_reachable(), Some(true));
    assert_eq!(reach.message(), None);
}

/// **宣言はあるがACEが付かなかった**ときは、宣言を直せという指示を出してはいけない
/// （直しても解決しない）。
#[test]
fn a_failed_grant_is_reported_differently_from_a_missing_declaration() {
    let entries = [("C:/Users/segfo/.cargo/bin", FsAccess::ReadExec)];
    let denied = [(
        PathBuf::from("C:/Users/segfo/.cargo/bin"),
        "read_exec".to_string(),
        "access denied".to_string(),
    )];

    let reach = diagnose(&exe(), &entries, &ws(), &denied);

    assert!(matches!(reach, ExecReach::GrantFailed { .. }));
    let message = reach.message().unwrap();
    assert!(message.contains("ACEを付けられませんでした"), "{message}");
    assert!(
        !message.contains("承認してください"),
        "telling the user to approve something they already approved is worse than silence: {message}"
    );
}

/// **コンポーネント境界を跨いだ前方一致で誤判定しない**（`covers`と同じ規則を通している証拠）。
#[test]
fn a_declaration_on_a_sibling_directory_does_not_cover_the_executable() {
    let entries = [("C:/Users/segfo/.cargo/bin-old", FsAccess::ReadExec)];

    assert!(matches!(
        diagnose(&exe(), &entries, &ws(), &[]),
        ExecReach::NotDeclared { .. }
    ));
}

/// ワイルドカード付きの宣言（`generalize`が作る形）でも覆いを判定できる。
#[test]
fn a_wildcard_declaration_is_evaluated_on_its_literal_prefix() {
    let entries = [(
        "C:/Users/segfo/.rustup/toolchains/*/bin",
        FsAccess::ReadExec,
    )];
    let toolchain_exe = PathBuf::from(
        "C:/Users/segfo/.rustup/toolchains/stable-x86_64-pc-windows-msvc/bin/cargo.exe",
    );

    // `*`より前（`.../toolchains`）で覆いを見る。狭すぎる判定にはしない。
    assert_eq!(
        diagnose(&toolchain_exe, &entries, &ws(), &[]).is_reachable(),
        Some(true)
    );
}

/// 大小の違いは無視する（Windowsのパス比較に合わせる）。
#[test]
fn coverage_is_case_insensitive() {
    let entries = [("c:/users/SEGFO/.cargo/BIN", FsAccess::ReadExec)];

    assert_eq!(
        diagnose(&exe(), &entries, &ws(), &[]).is_reachable(),
        Some(true)
    );
}

/// 先頭トークンの取り出し。引用符・パイプ・引数を跨いで**最初のコマンドだけ**を見る。
#[test]
fn the_first_token_of_a_command_line_is_extracted() {
    assert_eq!(first_token("cargo test --all"), Some("cargo".to_string()));
    assert_eq!(first_token("  cargo   "), Some("cargo".to_string()));
    assert_eq!(
        first_token(r#""C:/Program Files/Git/bin/git.exe" status"#),
        Some("C:/Program Files/Git/bin/git.exe".to_string())
    );
    assert_eq!(
        first_token("cargo build | rg error"),
        Some("cargo".to_string())
    );
    assert_eq!(first_token("   "), None);
    assert_eq!(first_token(""), None);
}

/// 解決できないものは**「起動できない」ではなく「測れなかった」**として出す。
/// ここを`Some(false)`に倒すと、シェル関数やエイリアスのたびに嘘の警告が出る。
#[test]
fn an_unresolvable_token_is_reported_as_not_measured() {
    let reach = ExecReach::Unresolved {
        token: "my-function".to_string(),
    };

    assert_eq!(reach.is_reachable(), None);
    let message = reach.message().unwrap();
    assert!(message.contains("特定できませんでした"), "{message}");
    assert!(
        message.contains("シェル関数"),
        "the user must be able to tell 'this is fine' from 'this will fail': {message}"
    );
}

/// **既定で実行できる場所は「宣言が無い」と言ってはいけない**（D-58との整合）。
///
/// 実機E2E（`e2e-policy-editor-pass2`）が捕まえた誤りの回帰テスト。`curl.exe`
/// （`C:/windows/system32`）に対して「1件も許可されていません→read_execで承認してください」と
/// 警告していたが、**コマンドは実際に動いていた**（AppContainerには既定で実行権がある）。
/// しかもその指示に従って承認すると、`preflight`がTrustedInstaller所有ツリーへACEを付けに行く
/// （BUG-015）——`aggregate`が候補に出さないと決めたもの（D-58）を、診断が承認させようとしていた。
#[test]
fn an_executable_under_a_default_exec_root_is_not_reported_as_undeclared() {
    for path in [
        "C:/windows/system32/curl.exe",
        "C:/Windows/System32/cmd.exe",
        "C:/Program Files/WindowsApps/Microsoft.PowerShell_7.6.4.0_x64__8wekyb3d8bbwe/pwsh.exe",
    ] {
        let reach = diagnose(&PathBuf::from(path), &[], &ws(), &[]);

        assert_eq!(
            reach.is_reachable(),
            Some(true),
            "{path} runs without any declaration: {reach:?}"
        );
        assert_eq!(
            reach.message(),
            None,
            "warning about something that already works trains the user to ignore warnings: {path}"
        );
    }
}

/// **対**（B-35）: ユーザーのツールチェーンは宣言が無ければ本当に起動できないので、
/// そちらは黙ってはいけない。両方固定しないと「常に無警告」でも緑になる。
#[test]
fn a_user_owned_executable_without_a_declaration_still_warns() {
    let reach = diagnose(&exe(), &[], &ws(), &[]);

    assert_eq!(reach.is_reachable(), Some(false));
    assert!(reach.message().is_some());
}

/// **候補にすべき実行ファイルを名指しできるのは2状態だけ**（D-57の追記）。
///
/// 7状態を1つずつ通す。`Ok`/`InsideWorkspace`は起動できるので要らず、`DefaultExecutable`は
/// 承認させると害がある（D-58・BUG-015）、`GrantFailed`は宣言が既に`read_exec`なので候補を
/// 足しても直らない、`Unresolved`は測れていないだけである——**「出さない」側を1件ずつ
/// 固定しないと、どれか1つが紛れ込んでも気付けない**（B-35）。
#[test]
fn only_the_two_unreachable_states_name_an_executable_for_the_candidate_list() {
    let exe = PathBuf::from("C:/Users/me/.cargo/bin/cargo.exe");

    let named = [
        ExecReach::NotDeclared { exe: exe.clone() },
        ExecReach::NoExecRight {
            exe: exe.clone(),
            declared: "C:/Users/me/.cargo/bin".to_string(),
            access: FsAccess::Read,
        },
    ];
    for reach in named {
        assert_eq!(
            reach.unreachable_exec_value().as_deref(),
            Some("C:/Users/me/.cargo/bin/cargo.exe"),
            "{reach:?} is exactly the case the candidate list is missing today"
        );
    }

    let silent = [
        ExecReach::Ok {
            exe: exe.clone(),
            declared: "C:/Users/me/.cargo/bin".to_string(),
        },
        ExecReach::InsideWorkspace { exe: exe.clone() },
        ExecReach::DefaultExecutable {
            exe: PathBuf::from("C:/Windows/System32/curl.exe"),
        },
        ExecReach::GrantFailed {
            exe: exe.clone(),
            root: PathBuf::from("C:/Users/me/.cargo/bin"),
            reason: "system-protected".to_string(),
        },
        ExecReach::Unresolved {
            token: "my-function".to_string(),
        },
    ];
    for reach in silent {
        assert_eq!(
            reach.unreachable_exec_value(),
            None,
            "{reach:?} must not add a candidate"
        );
    }
}

/// 名指しする綴りは**設定へそのまま書ける形**（`/`区切り）。ここがずれると、
/// 提案どおりに承認しても`policy.json`の値と実際のパスが一致しない（B-19）。
#[test]
fn the_named_executable_is_spelled_the_way_the_settings_file_wants_it() {
    let reach = ExecReach::NotDeclared {
        exe: PathBuf::from(r"C:\Users\me\.cargo\bin\cargo.exe"),
    };

    assert_eq!(
        reach.unreachable_exec_value().as_deref(),
        Some("C:/Users/me/.cargo/bin/cargo.exe")
    );
}
