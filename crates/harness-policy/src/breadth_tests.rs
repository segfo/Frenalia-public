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
        &[DeniedCandidate::fs(
            Source::Etw,
            value,
            access,
            "denied",
            1,
            0,
        )],
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

/// ドライブ直下は**名前で**決める。多者（他ユーザー・全アプリの共有データ）を束ねるものは
/// access種別によらず止める。
#[test]
fn top_level_roots_that_hold_other_principals_data_are_refused() {
    for value in [
        "C:/Users",
        "C:/ProgramData",
        "C:/$Recycle.Bin",
        "C:/System Volume Information",
        "C:/Documents and Settings",
    ] {
        for access in [FsAccess::Read, FsAccess::ReadWrite, FsAccess::ReadExec] {
            assert!(
                check(&proposal_for(value, access)).is_too_broad(),
                "{value} ({access:?}) は他人のものを束ねている"
            );
        }
    }
}

/// **束ねているのが自分自身のものだけなら、ドライブ直下でも通す。**
///
/// 深さで一律に切っていた頃は`C:/.cargo`が巻き添えになり、その配下の候補も畳み込みで
/// 消えていた（実測）。ここが通らないと、この機構はただ不便なだけになる。
#[test]
fn a_top_level_directory_that_only_holds_its_own_tool_data_is_accepted() {
    for value in ["C:/.cargo", "C:/tools", "C:/dev", "D:/data"] {
        assert_eq!(
            verdict_for(value),
            BreadthVerdict::Acceptable,
            "{value} が拒否されると、その配下の候補まで畳み込みで消える"
        );
    }
}

/// マシン全体のインストール先は**書きだけ**止める。
///
/// 読み取り・実行はAppContainerに既定で与えられている範囲なので拒んでも機密性は増えないが、
/// 書ければ全ユーザーが実行するプログラムを差し替えられる。
#[test]
fn machine_wide_install_roots_refuse_writes_but_allow_reads() {
    for value in ["C:/Windows", "C:/Program Files", "C:/Program Files (x86)"] {
        assert!(
            check(&proposal_for(value, FsAccess::ReadWrite)).is_too_broad(),
            "{value} への書込は全ユーザーへのコード実行になる"
        );
        for access in [FsAccess::Read, FsAccess::ReadExec] {
            assert_eq!(
                check(&proposal_for(value, access)),
                BreadthVerdict::Acceptable,
                "{value} ({access:?}) は既定で読める範囲なので、拒んでも機密性は増えない"
            );
        }
    }
}

/// 書込を止めるときは、**代わりに何なら通るか**を書く（直しようがない拒否にしない）。
#[test]
fn the_write_refusal_says_which_access_kind_would_be_accepted() {
    let message = check(&proposal_for("C:/Program Files", FsAccess::ReadWrite))
        .message()
        .expect("拒否される")
        .to_string();

    assert!(message.contains("fs.read"), "{message}");
    assert!(message.contains("fs.read_exec"), "{message}");
}

/// 名指しの判定をワイルドカードで迂回されない（`C:/Us*`が`C:/Users`を覆ってしまう）。
#[test]
fn a_wildcard_cannot_slip_past_the_named_top_level_roots() {
    assert!(verdict_for("C:/Us*").is_too_broad());
    assert!(verdict_for("C:/*/AppData").is_too_broad());
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

/// ドライブルートや祖先チェーンは、access種別に関わらず止める——`fs.read`でもドライブ全体が
/// 読めれば機密性は同じだけ失われる。access種別を見るのはマシン全体のインストール先だけである
/// （`machine_wide_install_roots_refuse_writes_but_allow_reads`）。
#[test]
fn the_verdict_does_not_depend_on_the_access_kind_for_the_ancestor_chain() {
    for value in [
        "C:/",
        "C:/Users",
        "C:/Users/segfo",
        "C:/Users/segfo/AppData",
    ] {
        for access in [FsAccess::Read, FsAccess::ReadWrite, FsAccess::ReadExec] {
            assert!(
                check(&proposal_for(value, access)).is_too_broad(),
                "{value} ({access:?})"
            );
        }
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

/// **既定で実行できる場所の判定**（`is_default_exec_root_path`）。
///
/// 実データ（このリポジトリの記録）で実際に観測された4つの実行像のうち2つがここに当たる
/// ——`C:/Windows/System32/conhost.exe`と`C:/Program Files/WindowsApps/.../pwsh.exe`。
/// この2つを候補に出すと、承認したユーザーは`preflight`にTrustedInstaller所有ツリーへの
/// 付与を試させることになる（BUG-015）。
#[test]
fn machine_wide_install_roots_are_recognized_as_already_executable() {
    for path in [
        "C:/Windows/System32/conhost.exe",
        "C:/windows/system32/cmd.exe",
        "C:/Program Files/WindowsApps/Microsoft.PowerShell_7.6.4.0_x64__8wekyb3d8bbwe/pwsh.exe",
        "C:/Program Files (x86)/Tool/tool.exe",
        "D:/Windows/System32/x.exe",
    ] {
        assert!(
            is_default_exec_root_path(path),
            "{path} is already executable for an AppContainer; proposing it only creates ACL work"
        );
    }
}

/// **対**（B-35）: ユーザーのツールチェーンは既定では実行できないので、候補にしなければならない。
/// 除外側だけを固定すると、「全部除外」でもテストが緑になる。
#[test]
fn user_owned_tool_paths_are_not_treated_as_already_executable() {
    for path in [
        "C:/Users/segfo/.cargo/bin/cargo.exe",
        "C:/Users/segfo/.rustup/toolchains/stable-x86_64-pc-windows-msvc/bin/cargo.exe",
        "C:/tools/rg.exe",
        "D:/dev/bin/node.exe",
        // `Windows`で始まるだけの別ディレクトリを巻き込まない。
        "C:/WindowsApps-mine/tool.exe",
        // ドライブ直下そのもの（第2要素が無い）。
        "C:/",
    ] {
        assert!(
            !is_default_exec_root_path(path),
            "{path} must stay proposable -- excluding it silently removes the only way to run it"
        );
    }
}

/// 「既定で実行できる」と「承認してよい」は**別の問い**である。
/// `fs.read_exec`としては承認できる（`check_value`は通す）が、提案はしない。
#[test]
fn being_already_executable_does_not_mean_the_value_is_refused() {
    let path = "C:/Windows/System32/conhost.exe";

    assert!(is_default_exec_root_path(path));
    assert!(
        !check_value(SettingsKey::FsReadExec, path).is_too_broad(),
        "the user may still write this by hand; we only decline to propose it"
    );
}
