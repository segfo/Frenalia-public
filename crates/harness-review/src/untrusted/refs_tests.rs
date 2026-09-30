use super::*;

const A: &str = "0123456789abcdef0123456789abcdef01234567";
const B: &str = "89abcdef0123456789abcdef0123456789abcdef";

/// 許可側: git が書く形は読める。
#[test]
fn a_loose_ref_written_by_git_is_accepted() {
    assert_eq!(parse_loose_ref(format!("{A}\n").as_bytes()).unwrap(), A);
    assert_eq!(parse_loose_ref(A.as_bytes()).unwrap(), A);
}

/// 禁止側: symref・大文字・余計な行・短い名前・空は読まない。
#[test]
fn anything_but_one_object_name_is_rejected_as_a_loose_ref() {
    for bad in [
        "ref: refs/heads/main\n".to_string(),
        A.to_uppercase(),
        format!("{A}\n{B}\n"),
        format!("{A}\n\n"),
        format!(" {A}"),
        A[..39].to_string(),
        String::new(),
    ] {
        assert!(parse_loose_ref(bad.as_bytes()).is_err(), "{bad:?}");
    }
}

#[test]
fn head_is_either_a_branch_or_a_detached_commit() {
    assert_eq!(
        parse_head(b"ref: refs/heads/feature/x\n").unwrap(),
        HeadState::Branch("refs/heads/feature/x".into())
    );
    assert_eq!(
        parse_head(format!("{A}\n").as_bytes()).unwrap(),
        HeadState::Detached(A.into())
    );
    for bad in [
        "ref: refs/remotes/origin/main\n",
        "ref: refs/heads/../x\n",
        "ref:refs/heads/main\n",
        "garbage",
    ] {
        assert!(parse_head(bad.as_bytes()).is_err(), "{bad:?}");
    }
}

#[test]
fn packed_refs_written_by_git_are_read_with_their_peeled_lines_checked() {
    let text = format!(
        "# pack-refs with: peeled fully-peeled sorted \n{A} refs/heads/main\n{B} refs/tags/v1\n^{A}\n"
    );
    let refs = parse_packed_refs(text.as_bytes()).unwrap();
    assert_eq!(
        refs,
        vec![
            ("refs/heads/main".to_string(), A.to_string()),
            ("refs/tags/v1".to_string(), B.to_string()),
        ]
    );
}

/// 1行でも崩れていれば全体を拒否する（一部だけ採らない）。
#[test]
fn one_bad_line_rejects_the_whole_packed_refs() {
    for bad in [
        format!("{A} refs/heads/main\ngarbage\n"),
        format!("^{A}\n{A} refs/heads/main\n"),
        format!("{A} refs/heads/main\n^{A}\n^{A}\n"),
        format!("{A} refs/heads/main\n{B} refs/heads/main\n"),
        format!("{A} refs/heads/a..b\n"),
        format!("{A}  refs/heads/main\n"),
        format!("# not the header\n{A} refs/heads/main\n"),
    ] {
        assert!(parse_packed_refs(bad.as_bytes()).is_err(), "{bad:?}");
    }
}

#[test]
fn ref_names_follow_git_and_windows_rules() {
    for good in [
        "refs/heads/main",
        "refs/heads/feature/x-1_2",
        "refs/tags/v1.2.3",
        "refs/heads/日本語の枝",
    ] {
        assert!(check_ref_name(good).is_ok(), "{good}");
    }
    for bad in [
        "refs/heads/a..b",
        "refs/heads/.hidden",
        "refs/heads/x.lock",
        "refs/heads/x.",
        "refs/heads/x/",
        "refs/heads//x",
        "refs/heads/a b",
        "refs/heads/a~1",
        "refs/heads/a^",
        "refs/heads/a:b",
        "refs/heads/a?",
        "refs/heads/a*",
        "refs/heads/a[",
        "refs/heads/a\\b",
        "refs/heads/a@{1}",
        "refs/heads/a\tb",
        "refs/heads/con",
        "refs/heads/NUL.txt",
        "heads/main",
    ] {
        assert!(check_ref_name(bad).is_err(), "{bad}");
    }
}

/// Windows で同じ場所に落ちる名前は、どちらも取り込まない。関係の無い名前は巻き込まない。
#[test]
fn names_that_collide_on_windows_are_all_reported() {
    let names = [
        "refs/heads/Main",
        "refs/heads/main",
        "refs/heads/a",
        "refs/heads/a/b",
        "refs/heads/a-b",
        "refs/heads/unrelated",
    ];
    assert_eq!(
        find_ambiguous_names(names),
        vec![
            "refs/heads/Main".to_string(),
            "refs/heads/a".to_string(),
            "refs/heads/a/b".to_string(),
            "refs/heads/main".to_string(),
        ]
    );
}
