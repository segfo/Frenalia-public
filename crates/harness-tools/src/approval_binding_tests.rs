//! `approval_binding`の回帰テスト。内部関数（`is_plain_option`・`shell_tokens`）へ
//! 触れるため`#[cfg(test)]`のまま別ファイルへ分けている（`docs/CODE-STRUCTURE-RULES.md`規則2）。

use super::*;
use harness_core::StagingMode;

fn ws() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("build.py"), "print('build')").unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/lib.rs"), "fn x() {}").unwrap();
    dir
}

fn file_of(b: PathBinding) -> BoundFile {
    match b {
        PathBinding::File(f, _) => f,
        other => panic!("expected a bound file, got {other:?}"),
    }
}

/// 語が指すものの分類。ファイルだけが縛られ、ディレクトリ・不在・外は縛られない。
#[test]
fn bind_path_classifies_what_a_token_points_at() {
    let dir = ws();
    let view = ChildView::real(dir.path()).unwrap();
    let root = dir.path();

    let f = file_of(bind_path(&view, root, "build.py", false));
    assert_eq!(f.rel_path, "build.py");
    assert_eq!(f.sha256, sha256_hex(b"print('build')"));
    assert_eq!(f.dir_listing_sha256, None);

    // 作業ディレクトリからの相対・`./`・`..`で戻る綴り・絶対パスのどれでも同じファイル。
    let sub = root.join("src");
    for token in ["../build.py", "./../build.py"] {
        assert_eq!(
            file_of(bind_path(&view, &sub, token, false)).rel_path,
            "build.py"
        );
    }
    let abs = root.join("build.py");
    assert_eq!(
        file_of(bind_path(&view, &sub, &abs.to_string_lossy(), false)).rel_path,
        "build.py"
    );

    assert!(matches!(
        bind_path(&view, root, "src", false),
        PathBinding::Directory
    ));
    assert!(matches!(
        bind_path(&view, root, ".", false),
        PathBinding::Directory
    ));
    assert!(matches!(
        bind_path(&view, root, "nope.py", false),
        PathBinding::Missing
    ));
    assert!(matches!(
        bind_path(&view, root, "../outside.py", false),
        PathBinding::Outside
    ));
    let elsewhere = tempfile::tempdir().unwrap();
    std::fs::write(elsewhere.path().join("x.py"), "x").unwrap();
    assert!(matches!(
        bind_path(
            &view,
            root,
            &elsewhere.path().join("x.py").to_string_lossy(),
            false
        ),
        PathBinding::Outside
    ));
}

/// 隣の名前一覧は、隣にファイルが増えると変わる（中身が同じでも気づける、D-104）。
#[test]
fn the_sibling_listing_changes_when_a_file_appears_next_to_the_script() {
    let dir = ws();
    let view = ChildView::real(dir.path()).unwrap();
    let before = file_of(bind_path(&view, dir.path(), "build.py", true));
    std::fs::write(dir.path().join("json.py"), "evil").unwrap();
    let after = file_of(bind_path(&view, dir.path(), "build.py", true));
    assert_eq!(
        before.sha256, after.sha256,
        "the script itself did not change"
    );
    assert_ne!(before.dir_listing_sha256, after.dir_listing_sha256);
}

/// `run_shell`の行に字面で現れるファイルを縛る。引用符は剥がし、変数とオプションは見ない。
#[test]
fn a_shell_line_binds_the_files_it_mentions_literally() {
    let dir = ws();
    let view = ChildView::real(dir.path()).unwrap();
    let b = bind_shell_line(
        &view,
        dir.path(),
        r#"python "build.py" --out=dist/x.txt; cat src/lib.rs | Out-File $env:TEMP\y"#,
    );
    let rels: Vec<&str> = b.files.iter().map(|f| f.rel_path.as_str()).collect();
    assert_eq!(rels, ["build.py", "src/lib.rs"]);
    assert!(!b.unverifiable);
    // スクリプトの拡張子なら隣の名前一覧も縛る。そうでなければ縛らない。
    assert!(b.files[0].dir_listing_sha256.is_some());
    assert!(b.files[1].dir_listing_sha256.is_none());
    assert_eq!(b.previews[0].text, "print('build')");

    let long = "x ".repeat(MAX_SHELL_TOKENS + 1);
    assert!(bind_shell_line(&view, dir.path(), &long).unverifiable);
}

/// 行の中の「パスではない語」（`OK:`・`Write-Output`）は無視する——一律に「確かめられない」と
/// すると、行全体が記録と照合されなくなる。**危ないのは代替データストリームで本体が実在するとき**だけ。
#[test]
fn tokens_that_are_not_paths_do_not_make_the_line_unverifiable() {
    let dir = ws();
    let view = ChildView::real(dir.path()).unwrap();
    let line = "$ErrorActionPreference='SilentlyContinue';         try { Get-Content build.py } catch { Write-Output ('READ=OK:' + $r) }";
    let b = bind_shell_line(&view, dir.path(), line);
    assert!(!b.unverifiable, "{b:?}");
    assert_eq!(
        b.files
            .iter()
            .map(|f| f.rel_path.as_str())
            .collect::<Vec<_>>(),
        ["build.py"]
    );

    // 実在するファイルの代替データストリームは、中身を確かめられないので聞く側へ倒す。
    let b = bind_shell_line(&view, dir.path(), "python build.py:hidden");
    assert!(b.unverifiable, "{b:?}");
    // 実在しない名前のストリームは、子も読めないので無視する。
    let b = bind_shell_line(&view, dir.path(), "python nope.py:hidden");
    assert!(!b.unverifiable, "{b:?}");
}

/// ワイルドカードのような「パスにできない語」は無視する。開こうとすると「名前が不正」で失敗し、
/// 「読めない」と区別が付かないので、行全体が照合対象外になっていた（実機のE2Eで踏んだ）。
#[test]
fn tokens_that_cannot_be_file_names_are_ignored() {
    let dir = ws();
    let view = ChildView::real(dir.path()).unwrap();
    let b = bind_shell_line(&view, dir.path(), "git -c safe.directory=* add build.py");
    assert!(!b.unverifiable, "{b:?}");
    assert_eq!(
        b.files
            .iter()
            .map(|f| f.rel_path.as_str())
            .collect::<Vec<_>>(),
        ["build.py"]
    );
    for token in ["*", "a?b", "x<y", "p|q"] {
        assert!(
            matches!(
                bind_path(&view, dir.path(), token, false),
                PathBinding::Missing
            ),
            "{token}"
        );
    }
}

/// コードを走らせる呼び出しの引数は、`-`で始まらないものが全部ファイルでなければ恒久承認できない。
#[test]
fn program_arguments_must_all_be_files_to_be_approved_permanently() {
    let dir = ws();
    std::fs::write(dir.path().join("build.js"), "x").unwrap();
    let view = ChildView::real(dir.path()).unwrap();
    let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();

    let ok = bind_program_args(&view, dir.path(), &args(&["-u", "build.py"]));
    assert!(!ok.one_shot_only);
    assert_eq!(ok.files.len(), 1);
    assert!(ok.files[0].dir_listing_sha256.is_some());

    for bad in [
        &["-c", "print(1)"][..],               // その場のコード
        &["build"][..], // node は build.js を探すが、ハーネスから見て build は無い
        &["-m", "pytest"][..], // モジュール名
        &["src"][..],   // ディレクトリ
        &["--require=./x.js", "build.py"][..], // パスの連結されたオプション
        &["-r./x", "build.py"][..],
        &["../outside.py"][..],
    ] {
        assert!(
            bind_program_args(&view, dir.path(), &args(bad)).one_shot_only,
            "{bad:?} must not be approvable permanently"
        );
    }
}

/// CoW では、子と同じく差分層の中身を読む。実ファイルと中身が違えばハッシュも違う。
#[test]
fn the_cow_view_reads_the_diff_layer_like_the_child() {
    let dir = ws();
    let diff = tempfile::tempdir().unwrap();
    let mut ctx = ToolCtx::new(dir.path().to_path_buf());
    ctx.cow_diff_layer_dir = Some(diff.path().to_path_buf());
    // 差分層へ子が書いたものを置く（Redirector が書くのと同じ置き場）。
    std::fs::write(
        diff.path().join("build.py"),
        "print('changed in the diff layer')",
    )
    .unwrap();

    let cow = ChildView::for_ctx(&ctx).unwrap();
    let f = file_of(bind_path(&cow, dir.path(), "build.py", false));
    assert_eq!(f.sha256, sha256_hex(b"print('changed in the diff layer')"));

    let real = ChildView::real(dir.path()).unwrap();
    assert_ne!(
        file_of(bind_path(&real, dir.path(), "build.py", false)).sha256,
        f.sha256
    );
}

/// `--staged`のステージングは子から見えないので読まない（実ファイルを読む）。
#[test]
fn the_staged_view_reads_the_real_file_because_the_child_does() {
    let dir = ws();
    let mut ctx = ToolCtx::new(dir.path().to_path_buf());
    ctx.staging = StagingConfig {
        mode: StagingMode::Staged,
        sandbox_dir: Some(PathBuf::from(".harness/sandbox/s1")),
    };
    let staged = SandboxFs::open(dir.path(), &ctx.staging).unwrap();
    staged
        .write_string("build.py", "print('staged only')")
        .unwrap();

    let view = ChildView::for_ctx(&ctx).unwrap();
    let f = file_of(bind_path(&view, dir.path(), "build.py", false));
    assert_eq!(f.sha256, sha256_hex(b"print('build')"));
}

#[test]
fn plain_options_have_no_attached_value() {
    for plain in ["-c", "--verbose", "-File", "-u", "--no-cache", "-X_Y"] {
        assert!(is_plain_option(plain), "{plain}");
    }
    for attached in [
        "--require=./x.js",
        "-r./x",
        "-dauto_prepend_file=x.php",
        "---x",
        "-",
        "--",
    ] {
        assert!(!is_plain_option(attached), "{attached}");
    }
}

// --- 入れ子のスクリプトを追う（D-120） ---

/// 符号化された中身を解読して出てきたファイルも縛る。
///
/// 実測（2026-10-04）: `pwsh --enc <塊>` を解読すると3段目が `uv run test.py` になるのに、
/// **`test.py` の中身は読まれておらず、ハッシュでも縛っていなかった**。
#[test]
fn a_file_named_only_inside_a_decoded_layer_is_bound() {
    let dir = ws();
    std::fs::write(dir.path().join("test.py"), "import os\nos.remove('x')\n").unwrap();
    let view = ChildView::real(dir.path()).unwrap();

    // 行そのものには `test.py` が出てこない。
    let line = "pwsh --enc <塊>";
    assert!(bind_shell_line(&view, dir.path(), line).files.is_empty());

    // 解読した段に出てくる。
    let decoded = vec![harness_core::DecodedLayer {
        depth: 1,
        source: harness_core::EncodedSource::EncodedCommand,
        outcome: harness_core::DecodeOutcome::Text {
            encoding: harness_core::TextEncoding::Utf16Le,
            text: "uv run test.py".to_string(),
        },
    }];
    let out = bind_everything(&view, dir.path(), line, &decoded);
    assert_eq!(
        out.files
            .iter()
            .map(|f| f.rel_path.as_str())
            .collect::<Vec<_>>(),
        vec!["test.py"]
    );
    assert!(out.previews[0].text.contains("os.remove"));
    assert!(!out.unverifiable);
}

/// 縛ったファイルの**中身**から、さらに入れ子のスクリプトを追う。**中身を見る回数の上限で止める。**
///
/// `a.py` は行に字面で出ているので第0段。そこから中身を3回見て `b.py` `c.py` `d.py` まで入り、
/// その先の `e.py` は入らない。
#[test]
fn nested_scripts_are_followed_up_to_the_depth_limit() {
    let dir = ws();
    std::fs::write(dir.path().join("a.py"), "run('b.py')").unwrap();
    std::fs::write(dir.path().join("b.py"), "run('c.py')").unwrap();
    std::fs::write(dir.path().join("c.py"), "run('d.py')").unwrap();
    std::fs::write(dir.path().join("d.py"), "run('e.py')").unwrap();
    std::fs::write(dir.path().join("e.py"), "print(1)").unwrap();
    let view = ChildView::real(dir.path()).unwrap();

    let out = bind_everything(&view, dir.path(), "python a.py", &[]);
    let bound: Vec<&str> = out.files.iter().map(|f| f.rel_path.as_str()).collect();
    assert_eq!(MAX_NEST_DEPTH, 3);
    assert_eq!(
        bound,
        vec!["a.py", "b.py", "c.py", "d.py"],
        "中身を見る回数が上限と合っていない"
    );
}

/// 同じファイルを二度追わない（輪になっていても止まる）。
#[test]
fn a_cycle_between_scripts_terminates() {
    let dir = ws();
    std::fs::write(dir.path().join("a.py"), "run('b.py')").unwrap();
    std::fs::write(dir.path().join("b.py"), "run('a.py')").unwrap();
    let view = ChildView::real(dir.path()).unwrap();

    let out = bind_everything(&view, dir.path(), "python a.py", &[]);
    let bound: Vec<&str> = out.files.iter().map(|f| f.rel_path.as_str()).collect();
    assert_eq!(bound, vec!["a.py", "b.py"]);
}

/// **普通の長さのスクリプトを名指ししても「確かめられない」にならない。**
///
/// 第1段から先で全部の語を見ると`MAX_SHELL_TOKENS`（256）を超えて`unverifiable`が立ち、
/// **スクリプトを名指しするコマンドが二度と自動承認されなくなる**。だから拡張子で絞っている。
#[test]
fn an_ordinary_script_does_not_make_the_call_unverifiable() {
    let dir = ws();
    let long: String = (0..400).map(|i| format!("value_{i} = {i}\n")).collect();
    assert!(
        shell_tokens(&long).len() > MAX_SHELL_TOKENS,
        "対照が効いていない: 語が上限を超えていない"
    );
    std::fs::write(dir.path().join("long.py"), &long).unwrap();
    let view = ChildView::real(dir.path()).unwrap();

    let out = bind_everything(&view, dir.path(), "python long.py", &[]);
    assert!(!out.unverifiable, "{out:?}");
    assert_eq!(out.files.len(), 1);
}

/// 第1段から先は**スクリプトの拡張子を持つ語だけ**を見る（メモは追わない）。
#[test]
fn only_script_extensions_are_followed_from_inside_a_file() {
    let dir = ws();
    std::fs::write(dir.path().join("notes.txt"), "hello").unwrap();
    std::fs::write(dir.path().join("helper.ps1"), "Write-Host 1").unwrap();
    std::fs::write(
        dir.path().join("a.py"),
        "open('notes.txt')\nrun('helper.ps1')\n",
    )
    .unwrap();
    let view = ChildView::real(dir.path()).unwrap();

    let out = bind_everything(&view, dir.path(), "python a.py", &[]);
    let bound: Vec<&str> = out.files.iter().map(|f| f.rel_path.as_str()).collect();
    assert_eq!(bound, vec!["a.py", "helper.ps1"], "notes.txt を追っている");
    // 対照: **行に字面で出れば**メモも縛る（第0段は拡張子で絞らない）。
    let out = bind_everything(&view, dir.path(), "cat notes.txt", &[]);
    assert_eq!(
        out.files
            .iter()
            .map(|f| f.rel_path.as_str())
            .collect::<Vec<_>>(),
        vec!["notes.txt"]
    );
}

/// 数の上限を超えたら「確かめられない」を立てる（黙って止めない）。
#[test]
fn passing_the_file_limit_marks_the_call_unverifiable() {
    let dir = ws();
    let names: Vec<String> = (0..MAX_NESTED_FILES + 3)
        .map(|i| format!("s{i}.py"))
        .collect();
    for name in &names {
        std::fs::write(dir.path().join(name), "print(1)").unwrap();
    }
    let calls: String = names.iter().map(|n| format!("run('{n}')\n")).collect();
    std::fs::write(dir.path().join("root.py"), &calls).unwrap();
    let view = ChildView::real(dir.path()).unwrap();

    let out = bind_everything(&view, dir.path(), "python root.py", &[]);
    assert!(out.unverifiable, "{out:?}");
}

/// **縛ると自動承認にも効く。** 入れ子のファイルの中身が変われば、縛った指紋が変わる。
#[test]
fn changing_a_nested_script_changes_the_bound_hashes() {
    let dir = ws();
    std::fs::write(dir.path().join("a.py"), "run('b.py')").unwrap();
    std::fs::write(dir.path().join("b.py"), "print(1)").unwrap();
    let view = ChildView::real(dir.path()).unwrap();

    let before = bind_everything(&view, dir.path(), "python a.py", &[]).files;
    std::fs::write(dir.path().join("b.py"), "print(2)").unwrap();
    let after = bind_everything(&view, dir.path(), "python a.py", &[]).files;

    assert_ne!(before, after, "入れ子のファイルの中身が指紋に効いていない");
    assert_eq!(before[0], after[0], "a.py は変えていない");
}
