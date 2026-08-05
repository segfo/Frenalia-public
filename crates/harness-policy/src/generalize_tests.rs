//! [`crate::generalize`]の単体テスト。M15.7の完了条件「ルール一般化の純粋関数の単体テスト」
//! （`docs/INDEX.md`）にあたる。

use super::*;

use crate::normalize::Source;

fn fs(path: &str, access: FsAccess) -> DeniedCandidate {
    DeniedCandidate::fs(Source::Etw, path, access, "STATUS_ACCESS_DENIED", 1, 0)
}

fn net(domain: &str) -> DeniedCandidate {
    DeniedCandidate::net(Source::Network, domain, "domain_denied", 1, 0)
}

/// `None`は畳まない。拒否された対象がそのまま1件1提案になる。
#[test]
fn generalization_none_keeps_every_path_separate() {
    let candidates = vec![
        fs("C:/Users/me/.cargo/registry/a.crate", FsAccess::Read),
        fs("C:/Users/me/.cargo/registry/b.crate", FsAccess::Read),
    ];

    let proposals = generalize(&candidates, Generalization::None);

    assert_eq!(proposals.len(), 2);
    assert_eq!(proposals[0].value, "C:/Users/me/.cargo/registry/a.crate");
    assert_eq!(proposals[1].value, "C:/Users/me/.cargo/registry/b.crate");
    // 畳み込みが起きていないことを直接主張する。「警告が空」を代用にしない
    // ——収集源由来の注記（OS監査の`read`は推定である旨）は畳み込みと無関係に付くため。
    assert!(proposals
        .iter()
        .all(|p| !p.warnings.iter().any(|w| w.contains("generalized from"))));
}

/// `Directory`は同一親配下の2件以上を親1本へ畳み、証拠は全件を引き継ぐ。
#[test]
fn generalization_directory_folds_siblings_into_their_parent() {
    let candidates = vec![
        fs("C:/Users/me/.cargo/registry/a.crate", FsAccess::Read),
        fs("C:/Users/me/.cargo/registry/b.crate", FsAccess::Read),
    ];

    let proposals = generalize(&candidates, Generalization::Directory);

    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].value, "C:/Users/me/.cargo/registry");
    assert_eq!(proposals[0].evidence.len(), 2);
    assert!(proposals[0]
        .warnings
        .iter()
        .any(|w| w.contains("generalized from 2")));
}

/// 兄弟が1件しか無いディレクトリは畳まない。畳むと「1ファイルの拒否でディレクトリ全体を開く」
/// 提案になり、一般化が常に権限を広げる方向にしか働かなくなる。
#[test]
fn generalization_directory_does_not_widen_a_lone_path() {
    let candidates = vec![fs("C:/Users/me/.gitconfig", FsAccess::Read)];

    let proposals = generalize(&candidates, Generalization::Directory);

    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].value, "C:/Users/me/.gitconfig");
    assert!(!proposals[0]
        .warnings
        .iter()
        .any(|w| w.contains("generalized from")));
}

/// ドライブルート直下までは畳まない（`C:/`への一般化はサンドボックスの意味を消す、T-16）。
#[test]
fn generalization_never_folds_up_to_a_drive_root() {
    let candidates = vec![
        fs("C:/toolsA", FsAccess::ReadExec),
        fs("C:/toolsB", FsAccess::ReadExec),
    ];

    let proposals = generalize(&candidates, Generalization::Directory);

    assert_eq!(proposals.len(), 2, "must not collapse into C:/");
    assert!(proposals.iter().all(|p| p.value != "C:" && p.value != "C:/"));
}

/// `Auto`はバージョン番号らしい要素をワイルドカード化し、同値になったものを畳む。
#[test]
fn generalization_auto_wildcards_version_segments_and_merges_them() {
    let candidates = vec![
        fs("C:/Users/me/.rustup/toolchains/1.89.0/bin", FsAccess::ReadExec),
        fs("C:/Users/me/.rustup/toolchains/1.90.0/bin", FsAccess::ReadExec),
    ];

    let proposals = generalize(&candidates, Generalization::Auto);

    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].value, "C:/Users/me/.rustup/toolchains/*/bin");
    assert_eq!(proposals[0].evidence.len(), 2);
    assert!(proposals[0]
        .warnings
        .iter()
        .any(|w| w.contains("wildcard")));
}

/// 16進ハッシュらしい要素もワイルドカード化する。
#[test]
fn generalization_auto_wildcards_hash_segments() {
    let candidates = vec![
        fs("C:/cache/a1b2c3d4e5f6/pkg", FsAccess::Read),
        fs("C:/cache/9f8e7d6c5b4a/pkg", FsAccess::Read),
    ];

    let proposals = generalize(&candidates, Generalization::Auto);

    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].value, "C:/cache/*/pkg");
}

/// 意味のある名前（英字混じり）はワイルドカードで潰さない。潰すと提案が広がりすぎる。
#[test]
fn generalization_auto_leaves_meaningful_segments_alone() {
    let candidates = vec![fs(
        "C:/Users/me/.rustup/toolchains/stable-x86_64-pc-windows-msvc/bin/rustc.exe",
        FsAccess::ReadExec,
    )];

    let proposals = generalize(&candidates, Generalization::Auto);

    assert_eq!(
        proposals[0].value,
        "C:/Users/me/.rustup/toolchains/stable-x86_64-pc-windows-msvc/bin/rustc.exe"
    );
}

/// **P-03**: 同じパスが`read`と`read_write`で拒否されていても、強い方へ寄せて1本にしない。
/// 別々の提案として出し、どちらを受け入れるかをユーザーに選ばせる。
#[test]
fn different_access_levels_never_merge_into_the_stronger_one() {
    let candidates = vec![
        fs("C:/Users/me/.cargo", FsAccess::Read),
        fs("C:/Users/me/.cargo", FsAccess::ReadWrite),
    ];

    let proposals = generalize(&candidates, Generalization::Auto);

    assert_eq!(proposals.len(), 2);
    let keys: Vec<_> = proposals.iter().map(|p| p.key).collect();
    assert!(keys.contains(&SettingsKey::FsRead));
    assert!(keys.contains(&SettingsKey::FsReadWrite));
}

/// `read_write`の提案には必ずwrite-containmentを弱める旨の警告が付く（D-42）。
#[test]
fn read_write_proposals_always_carry_a_write_containment_warning() {
    let proposals = generalize(&[fs("C:/Users/me/out", FsAccess::ReadWrite)], Generalization::None);

    assert!(proposals[0]
        .warnings
        .iter()
        .any(|w| w.contains("write containment")));
}

/// ドメインはFSの畳み込み（親ディレクトリ・ワイルドカード）の対象外で、そのまま1件1提案。
#[test]
fn domains_are_not_subject_to_path_folding() {
    let candidates = vec![net("api.example.com"), net("cdn.example.com")];

    let proposals = generalize(&candidates, Generalization::Auto);

    assert_eq!(proposals.len(), 2);
    assert!(proposals
        .iter()
        .all(|p| p.key == SettingsKey::NetAllowDomains));
    assert_eq!(proposals[0].id, "net-1");
    assert_eq!(proposals[1].id, "net-2");
}

/// idは並びが決定的なので、入力順を変えても同じ提案が同じidになる
/// （`--accept fs-2`が実行のたびに別のものを指すと危険）。
#[test]
fn proposal_ids_are_stable_regardless_of_input_order() {
    let a = fs("C:/z/one", FsAccess::Read);
    let b = fs("C:/a/two", FsAccess::Read);

    let forward = generalize(&[a.clone(), b.clone()], Generalization::Directory);
    let backward = generalize(&[b, a], Generalization::Directory);

    let ids_and_values: Vec<_> = forward
        .iter()
        .map(|p| (p.id.clone(), p.value.clone()))
        .collect();
    let reversed: Vec<_> = backward
        .iter()
        .map(|p| (p.id.clone(), p.value.clone()))
        .collect();
    assert_eq!(ids_and_values, reversed);
    assert_eq!(ids_and_values[0], ("fs-1".to_string(), "C:/a/two".to_string()));
}

/// 複数の収集源から同じ対象が来たら1提案に畳み、`sources()`で両方が見える
/// （提案側で重み付けはしないが、由来は判断材料として残す）。
#[test]
fn evidence_keeps_every_contributing_source() {
    let candidates = vec![
        DeniedCandidate::fs(Source::Preflight, "C:/x", FsAccess::Read, "no path", 1, 0),
        DeniedCandidate::fs(Source::Etw, "C:/x", FsAccess::Read, "denied", 4, 9),
    ];

    let proposals = generalize(&candidates, Generalization::Directory);

    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].sources(), vec![Source::Preflight, Source::Etw]);
    assert_eq!(proposals[0].observed_count(), 5);
}

/// **推定を推定として見せる**（RESULTS.md §12.4/§14.3）。OS監査由来の`read`は
/// 「読み取りだった」ではなく「書込だと判る材料が無かった」を意味するので、
/// 削除・書込が目的なら`read_write`を選ぶよう注記する。
#[test]
fn os_audit_read_proposals_disclose_that_read_is_only_a_guess() {
    let proposals = generalize(
        &[DeniedCandidate::fs(
            Source::Etw,
            "C:/Users/me/notes.txt",
            FsAccess::Read,
            "STATUS_ACCESS_DENIED",
            1,
            0,
        )],
        Generalization::None,
    );

    let warning = proposals[0]
        .warnings
        .iter()
        .find(|w| w.contains("conservative guess"))
        .expect("the inference must be disclosed");
    assert!(warning.contains("fs.read_write"), "it must say what to do instead");
}

/// 他の収集源（preflight・CoW）由来の`read`にはこの注記を付けない——あちらは
/// 要求されたアクセスを実際に知っている（CoWはRedirector DLLが生のマスクを記録する）。
#[test]
fn non_audit_read_proposals_do_not_carry_the_guess_disclosure() {
    for source in [Source::Preflight, Source::Cow] {
        let proposals = generalize(
            &[DeniedCandidate::fs(
                source,
                "C:/Users/me/notes.txt",
                FsAccess::Read,
                "denied",
                1,
                0,
            )],
            Generalization::None,
        );
        assert!(
            !proposals[0]
                .warnings
                .iter()
                .any(|w| w.contains("conservative guess")),
            "{source:?} knows the requested access; it must not be described as a guess"
        );
    }
}
