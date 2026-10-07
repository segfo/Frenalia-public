//! CLI の書込の同意（[`super`]）の試験。**書く・書かないの判定は純粋な関数**（[`auto_refusal`]）なので、権限が広がる
//! 変更を`exposure_view::widening`で実際に作って渡す。バイナリを撃たないのは、`approve`・`unapprove`の書く側が本物の
//! 承認台帳（`%APPDATA%`）に触るため（`tests/show_cli.rs`のモジュールdocと同じ理由）——書く側は各`plan`/`commit`の
//! 単体試験が持ち、CLI はこの関数が真を返したときだけ`commit`を呼ぶ（呼び出し元4つは`confirm_write`の1か所を通る）。

use clap::Parser;
use harness_policy::policy_file::{PolicyDomain, PolicyFile, ENTRY_DOMAIN};
use harness_policy::transition::{editor_edge, AnyMarker, ArgvMatcher};
use harness_policy_editor::exposure_view::{widening, Widening};

use super::*;
use crate::{Cli, Command};

const PEEK: &str = "C:/Users/x/tools/peek.exe";

fn ws() -> std::path::PathBuf {
    std::path::PathBuf::from("C:/ws")
}

fn reading(name: &str, value: &str) -> PolicyDomain {
    let mut domain = PolicyDomain::new(name);
    domain.fs.read.push(value.to_string());
    domain
}

fn file(domains: Vec<PolicyDomain>) -> PolicyFile {
    PolicyFile {
        domains,
        ..PolicyFile::default()
    }
}

/// 入口のドメインから、秘密を読めるドメインへ新しく辺を書く変更（広がる遷移1本）。
fn widening_edge() -> Widening {
    let before = file(vec![
        PolicyDomain::new(ENTRY_DOMAIN),
        reading("secret", "C:/Users/x/secret/**"),
    ]);
    let mut entry = PolicyDomain::new(ENTRY_DOMAIN);
    entry
        .process
        .transitions
        .push(editor_edge(PEEK, ArgvMatcher::Any(AnyMarker), "secret"));
    let after = file(vec![entry, reading("secret", "C:/Users/x/secret/**")]);
    widening(&before, &after, &ws())
}

/// 書く側のドメインが書ける場所を、入口のドメイン（通信できるとみなす）が読むようになる変更（組み合わせ1組だけ）。
fn new_pair_only() -> Widening {
    let mut builder = PolicyDomain::new("builder");
    builder.fs.read_write.push("C:/share/**".to_string());
    let before = file(vec![PolicyDomain::new(ENTRY_DOMAIN), builder.clone()]);
    let after = file(vec![reading(ENTRY_DOMAIN, "C:/share/out.txt"), builder]);
    widening(&before, &after, &ws())
}

/// **`--auto-approve`は、呼び出し元へ新しく権限を渡す変更を書かない**（決定66(8)）——広がる遷移が1本でも、組み合わせが
/// 1組でも、数えられなかったときも断り、理由に`--force-approve`を出す（次の手が分かるように、`B-32`）。
///
/// 対（`B-35`）: 渡すものを増やさない変更（何も無い・版が上がるだけ）は書く。
#[test]
fn auto_approve_is_refused_when_rights_would_be_handed_over() {
    let edge = widening_edge();
    assert_eq!(edge.edges.len(), 1, "試験の前提: 広がる遷移が1本ある");
    let reason =
        auto_refusal(Consent::AutoApprove, &edge).expect("広がる遷移を --auto-approve で書いた");
    assert!(
        reason.contains("--force-approve") && reason.contains("1本"),
        "{reason}"
    );

    let pair = new_pair_only();
    assert!(
        pair.edges.is_empty() && pair.pairs.len() == 1,
        "試験の前提: 組み合わせだけ"
    );
    let reason =
        auto_refusal(Consent::AutoApprove, &pair).expect("組み合わせを --auto-approve で書いた");
    assert!(reason.contains("組み合わせ 1組"), "{reason}");

    let uncounted = Widening {
        uncounted: Some("duplicate domain".to_string()),
        ..Widening::default()
    };
    assert!(
        auto_refusal(Consent::AutoApprove, &uncounted).is_some(),
        "数えられなかった変更を「渡さない」として書いた"
    );

    assert_eq!(
        auto_refusal(Consent::AutoApprove, &Widening::default()),
        None
    );
    let schema_only = Widening {
        schema_raised: Some((2, 3)),
        ..Widening::default()
    };
    assert_eq!(
        auto_refusal(Consent::AutoApprove, &schema_only),
        None,
        "版が上がるだけの変更は渡すものを増やさない"
    );
}

/// **`--force-approve`は、広がる遷移・組み合わせも含めて書く**（読んで受け入れた人の明示の同意）——確認の関数が
/// プロンプトを出さずに真を返し、呼び出し元はそのまま`commit`する。`--auto-approve`の拒否と同じ入力で対にする。
#[test]
fn force_approve_writes_the_widening_edge() {
    for change in [widening_edge(), new_pair_only()] {
        assert_eq!(auto_refusal(Consent::ForceApprove, &change), None);
        assert!(
            confirm_write(Consent::ForceApprove, &change),
            "--force-approve なのに書かない"
        );
        assert!(
            !confirm_write(Consent::AutoApprove, &change),
            "同じ変更を --auto-approve で書いた"
        );
    }
}

fn consent_of(args: &[&str]) -> Result<Consent, clap::Error> {
    let cli =
        Cli::try_parse_from(std::iter::once("harness-policy-editor").chain(args.iter().copied()))?;
    Ok(match cli.command.expect("サブコマンドを指定した") {
        Command::Approve { consent, .. }
        | Command::Unapprove { consent, .. }
        | Command::ApproveDeclared { consent, .. } => consent.consent(),
        other => panic!("同意のフラグを持たないサブコマンド: {other:?}"),
    })
}

/// **`--yes`は`--auto-approve`の別名として残る**（決定66(8)）——書込のある3つのサブコマンドのどれでも同じ同意になり、
/// `--force-approve`と同時には指定できない（「確認済みだが広がりは断る」と「広がりも含めて書く」は両立しない）。
#[test]
fn the_yes_flag_is_auto_approve_under_its_old_name() {
    for sub in [
        vec!["unapprove", "--all"],
        vec!["approve", "--accept", "fs-1"],
        vec![
            "approve-declared",
            "--domain",
            "d",
            "--fs",
            "C:/x",
            "--access",
            "read",
        ],
    ] {
        let with = |flag: &[&str]| -> Result<Consent, clap::Error> {
            consent_of(&sub.iter().chain(flag.iter()).copied().collect::<Vec<_>>())
        };
        assert_eq!(with(&[]).unwrap(), Consent::Ask, "{sub:?}");
        assert_eq!(with(&["--yes"]).unwrap(), Consent::AutoApprove, "{sub:?}");
        assert_eq!(
            with(&["--auto-approve"]).unwrap(),
            Consent::AutoApprove,
            "{sub:?}"
        );
        assert_eq!(
            with(&["--force-approve"]).unwrap(),
            Consent::ForceApprove,
            "{sub:?}"
        );
        assert!(
            with(&["--yes", "--force-approve"]).is_err(),
            "{sub:?}: 両立しない同意を受け付けた"
        );
    }
}
