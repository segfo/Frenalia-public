//! [`crate::breadth`]の単体テスト（D-47）。
//!
//! 入力は`plans/etw-spike/RESULTS.md` §17.6が実測した祖先チェーンそのものを使う——
//! 作り話のパスで閾値を決めると、実際に観測される形と食い違ったまま緑になる。

use super::*;

use crate::generalize::{generalize, Generalization};
use crate::normalize::{DeniedCandidate, Source};
use harness_config::FsAccess;

fn proposal_for(value: &str, access: FsAccess) -> RuleProposal {
    generalize(
        &[DeniedCandidate::fs(Source::Etw, value, access, "denied", 1, 0)],
        Generalization::None,
    )
    .remove(0)
}

fn verdict_for(value: &str) -> BreadthVerdict {
    check(&proposal_for(value, FsAccess::Read))
}

/// §17.6で実際に観測された祖先チェーンのうち、`Temp`を除く全てが止まること。
#[test]
fn the_observed_ancestor_chain_is_refused_up_to_but_not_including_temp() {
    for value in [
        "C:/",
        "C:/Users/",
        "C:/Users/segfo/",
        "C:/Users/segfo/AppData/",
        "C:/Users/segfo/AppData/Local/",
    ] {
        assert!(
            verdict_for(value).is_too_broad(),
            "{value} must be refused; it is one of the ancestors cmd.exe opens on the way to a \
             real target (RESULTS.md 17.6)"
        );
    }

    assert_eq!(
        verdict_for("C:/Users/segfo/AppData/Local/Temp"),
        BreadthVerdict::Acceptable,
        "the chain has to stop somewhere, and %TEMP% is a legitimate thing to allow"
    );
}

/// **通さなければならない側**（§18.5規律3: 全滅は測定不備の合図）。
/// 普通の許可先を巻き込んでいたら、このガードは使い物にならない。
#[test]
fn ordinary_paths_people_actually_need_are_accepted() {
    for value in [
        "C:/Users/segfo/.cargo/registry",
        "C:/Users/segfo/.rustup/toolchains",
        "C:/Program Files/Git/bin",
        "C:/Windows/System32/drivers/etc/hosts",
        "D:/work/project",
        "//fileserver/team/shared/lib",
    ] {
        assert_eq!(
            verdict_for(value),
            BreadthVerdict::Acceptable,
            "{value} is a normal grant target and must not be refused"
        );
    }
}

/// ドライブ直下は、名前を問わず止める（`C:/Windows`も`C:/Anything`も同じ）。
#[test]
fn every_top_level_directory_is_refused_not_just_the_well_known_ones() {
    for value in ["C:/Windows", "C:/Program Files", "C:/ProgramData", "D:/data"] {
        assert!(verdict_for(value).is_too_broad(), "{value}");
    }
}

/// 大文字小文字は区別しない（Windowsのパスは区別しないので、綴りで抜けられては困る）。
#[test]
fn the_guard_is_case_insensitive() {
    assert!(verdict_for("c:/users/segfo").is_too_broad());
    assert!(verdict_for("C:/USERS/segfo/APPDATA").is_too_broad());
}

/// UNCは共有ルートまでを止め、その配下は通す。
#[test]
fn unc_share_roots_are_refused_but_their_contents_are_not() {
    assert!(verdict_for("//fileserver").is_too_broad());
    assert!(verdict_for("//fileserver/team").is_too_broad());
    assert_eq!(
        verdict_for("//fileserver/team/project"),
        BreadthVerdict::Acceptable
    );
}

/// `Generalization::Auto`が作りうる浅いワイルドカードは、同じ範囲を開くので同じ扱い。
#[test]
fn shallow_wildcards_are_refused_because_they_match_almost_everything() {
    assert!(verdict_for("C:/*").is_too_broad());
    assert!(verdict_for("C:/Users/*").is_too_broad());
    assert!(verdict_for("C:/Users/*/AppData").is_too_broad());
    // 深い位置のワイルドカード（ツールチェーンのバージョン等）は本来の用途なので通す。
    assert_eq!(
        verdict_for("C:/Users/segfo/.rustup/toolchains/*/bin"),
        BreadthVerdict::Acceptable
    );
}

/// access種別に関わらず幅で見る——`fs.read`でもドライブ全体が読めれば機密性は同じだけ失われる。
#[test]
fn the_verdict_does_not_depend_on_the_access_kind() {
    for access in [FsAccess::Read, FsAccess::ReadWrite, FsAccess::ReadExec] {
        assert!(check(&proposal_for("C:/", access)).is_too_broad(), "{access:?}");
    }
}

/// ドメインの提案は対象外（別の軸の話）。
#[test]
fn domain_proposals_are_out_of_scope() {
    let proposal = generalize(
        &[DeniedCandidate::net(
            Source::Network,
            "api.example.com",
            "denied",
            1,
            0,
        )],
        Generalization::None,
    )
    .remove(0);

    assert_eq!(check(&proposal), BreadthVerdict::Acceptable);
}

/// 拒否メッセージは、対象の値と「手で編集すればできる」ことの両方を含む
/// ——遮断だけして逃げ道を書かないと、ユーザーは何をすればよいか分からない。
#[test]
fn the_refusal_names_the_value_and_the_manual_escape_hatch() {
    let verdict = verdict_for("C:/");
    let message = verdict.message().expect("carries a reason");

    assert!(message.contains("C:/"));
    assert!(message.contains("drive root"));
    assert!(message.contains("settings.json"));
}

#[test]
fn check_all_pairs_verdicts_with_proposal_ids() {
    let proposals = generalize(
        &[
            DeniedCandidate::fs(Source::Etw, "C:/", FsAccess::Read, "denied", 1, 0),
            DeniedCandidate::fs(
                Source::Etw,
                "C:/Users/segfo/.cargo",
                FsAccess::Read,
                "denied",
                1,
                0,
            ),
        ],
        Generalization::None,
    );

    let verdicts = check_all(&proposals);

    assert_eq!(verdicts.len(), 2);
    let too_broad: Vec<&String> = verdicts
        .iter()
        .filter(|(_, v)| v.is_too_broad())
        .map(|(id, _)| id)
        .collect();
    assert_eq!(too_broad.len(), 1, "{verdicts:#?}");
}
