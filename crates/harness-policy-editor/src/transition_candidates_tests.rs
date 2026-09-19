//! [段階⑦] 観測・拒否を候補にするところの単体テスト。
//!
//! **端末もWin32も要らない**（純粋関数なので`cargo test -p harness-policy-editor`に入る）。
//! 画面のキー割り当てと文言は`tui::transition`側が持つ。

use super::*;

use harness_policy::policy_file::{PolicyDomain, ENTRY_DOMAIN};
use harness_policy::transition::AnyMarker;
use harness_sandbox::tier2a::policy_learnd::observed::Spawn;
use harness_sandbox::tier2a::spawnd::transitions::Denial;
use harness_sandbox::tier2a::spawnd::DenyReason;

const WS: &str = "C:/work";

fn edge(exe: ExeMatcher, argv: ArgvMatcher, to: &str) -> TransitionEdge {
    TransitionEdge {
        exe,
        argv,
        cwd: None,
        to: to.to_string(),
        env: None,
    }
}

/// 宣言が`edges`だけの`policy.json`を組む。
fn policy(edges: Vec<TransitionEdge>) -> PolicyFile {
    let mut domain = PolicyDomain::new(ENTRY_DOMAIN);
    domain.process.transitions = edges;
    PolicyFile {
        domains: vec![domain],
        ..PolicyFile::default()
    }
}

fn declared(file: &PolicyFile) -> DeclaredEdges {
    DeclaredEdges::build(file, WS, ENTRY_DOMAIN).expect("宣言が組めない")
}

fn observed(exe: &str, argv: &str) -> ObservedRecord {
    ObservedRecord::ObservedSpawn(Spawn {
        parent_exe: Some("C:/pwsh.exe".to_string()),
        exe: exe.to_string(),
        argv: argv.to_string(),
        count: 1,
        first_ts: 1,
        last_ts: 1,
        argv_truncation: false,
    })
}

fn denial(exe: &str, argv: &str, reason: DenyReason) -> PendingRecord {
    PendingRecord::DeniedByDaemon(Denial {
        from_domain: Some(ENTRY_DOMAIN.to_string()),
        exe: exe.to_string(),
        argv: argv.to_string(),
        cwd: Some(WS.to_string()),
        reason,
        count: 1,
        first_ts: 1,
        last_ts: 1,
        argv_truncation: false,
    })
}

// --- 宣言済みの重ね方 -------------------------------------------------------

/// 宣言が1件も無いなら、観測はすべて承認の対象になる。
#[test]
fn an_unobserved_program_with_no_declaration_is_approvable() {
    let file = policy(Vec::new());
    let candidates = from_observations(&[observed("C:/git.exe", "git status")], &declared(&file));

    assert_eq!(candidates.len(), 1);
    assert!(candidates[0].is_approvable());
    assert!(!candidates[0].is_removable());
}

/// **対の側**（`B-35`）: 同じ綴りを宣言したら、その候補は承認対象から外れて取り消し対象になる。
///
/// これが無いと「常に未宣言と答える」実装でも上のテストは緑になり、**同じ辺を何度でも
/// 二重に承認させる**画面になる。
#[test]
fn a_program_declared_with_this_exact_spelling_becomes_removable() {
    let file = policy(vec![edge(
        ExeMatcher::Literal("C:/git.exe".to_string()),
        ArgvMatcher::Any(AnyMarker),
        ENTRY_DOMAIN,
    )]);
    let candidates = from_observations(&[observed("C:/git.exe", "git status")], &declared(&file));

    assert!(!candidates[0].is_approvable());
    assert!(candidates[0].is_removable());
    match &candidates[0].declared {
        Declared::ByThisEdge {
            argv,
            to_domain,
            runnable_now,
        } => {
            assert_eq!(*argv, crate::transition_approve::ArgvChoice::Any);
            assert_eq!(to_domain, ENTRY_DOMAIN);
            // 自己ループなので今日でも起こせる。
            assert!(*runnable_now);
        }
        other => panic!("この綴りの辺として認識されていない: {other:?}"),
    }
}

/// **遷移先が別ドメインの辺は「いまは起こせない」として出る。**
///
/// 暫定（`plans/DESIGN-MAC-ENFORCEMENT.md` §10.1.2）の可視化であり、
/// **判定の正本は`transition_listing`**である。ここで計算し直していないことを固定する
/// ——§22.9が着地したら`transition_listing`側が`true`を返すようになり、
/// この期待は**そのとき赤くなって**気付ける。
#[test]
fn an_edge_into_another_domain_is_shown_as_not_runnable_today() {
    let mut file = policy(vec![edge(
        ExeMatcher::Literal("C:/git.exe".to_string()),
        ArgvMatcher::Any(AnyMarker),
        "git-domain",
    )]);
    file.domains.push(PolicyDomain::new("git-domain"));
    let candidates = from_observations(&[observed("C:/git.exe", "git status")], &declared(&file));

    match &candidates[0].declared {
        Declared::ByThisEdge { runnable_now, .. } => assert!(
            !runnable_now,
            "別ドメインへの遷移が「いま起こせる」と表示されている\
             （§22.9が着地したならこの期待ごと直すこと）"
        ),
        other => panic!("この綴りの辺として認識されていない: {other:?}"),
    }
}

/// パターンが覆っているだけの候補は、**この行からは外せない**。
///
/// 外すとパターンごと消え、この行に見えていない他のプログラムの許可も一緒に消えるため
/// （FS側の`covering_fs_declaration`と同じ扱い）。
#[test]
fn a_candidate_covered_only_by_a_pattern_is_not_removable_from_this_row() {
    // パターンは**畳んだ形（小文字）**で書く。編集時検査が大文字を落とす
    // ——入力は比較前に小文字化されるので、大文字は永久に一致しないためである。
    let file = policy(vec![edge(
        ExeMatcher::Pattern("c:/tools/.*".to_string()),
        ArgvMatcher::Any(AnyMarker),
        ENTRY_DOMAIN,
    )]);
    let candidates = from_observations(
        &[observed("C:/tools/git.exe", "git status")],
        &declared(&file),
    );

    assert!(
        !candidates[0].is_removable(),
        "パターンを行から外させている"
    );
    assert!(
        !candidates[0].is_approvable(),
        "既に通るものを承認対象にしている（同じ許可が二重になる）"
    );
    assert!(matches!(
        candidates[0].declared,
        Declared::ByAPattern { .. }
    ));
}

// --- 拒否側の絞り込み -------------------------------------------------------

/// 宣言で直る拒否は候補に出る。
#[test]
fn a_denial_that_a_declaration_would_fix_becomes_a_candidate() {
    let file = policy(Vec::new());
    let records = [denial(
        "C:/git.exe",
        "git status",
        DenyReason::Transition {
            denial: TransitionDenial::NoMatchingEdge,
        },
    )];
    let candidates = from_denials(&records, &declared(&file));

    assert_eq!(candidates.len(), 1);
    assert!(candidates[0].is_approvable());
    assert!(matches!(
        candidates[0].source,
        Source::Denied {
            by_kernel: false,
            ..
        }
    ));
}

/// **対の側**（`B-35`）: ポリシーと無関係な拒否は候補に出さない。
///
/// 出すと、直しようのない記録に「宣言を直せ」の顔をさせることになる。
/// これが無いと「全部候補にする」実装でも上のテストは緑になる。
#[test]
fn a_denial_that_is_not_about_policy_is_not_offered_as_a_candidate() {
    let file = policy(Vec::new());
    let records = [denial(
        "C:/git.exe",
        "git status",
        DenyReason::NotRegistered,
    )];

    assert!(
        from_denials(&records, &declared(&file)).is_empty(),
        "宣言をどう書いても変わらない拒否を候補に出している"
    );
}

/// あふれの報告行は候補にならない（種類ではない）。
#[test]
fn an_overflow_report_is_not_a_candidate() {
    let file = policy(Vec::new());
    let observed_records = [ObservedRecord::Overflowed {
        dropped: 3,
        last_ts: 1,
    }];
    let denied_records = [PendingRecord::Overflowed {
        dropped: 3,
        last_ts: 1,
    }];

    assert!(from_observations(&observed_records, &declared(&file)).is_empty());
    assert!(from_denials(&denied_records, &declared(&file)).is_empty());
}

// --- 並び -------------------------------------------------------------------

/// 並びは**入力の順に依存しない**。依存すると、読み直すたびに行が飛び回る。
#[test]
fn the_order_does_not_depend_on_the_order_in_the_file() {
    let file = policy(Vec::new());
    let forward = [
        observed("C:/rustc.exe", "rustc a"),
        observed("C:/cargo.exe", "cargo build"),
        observed("C:/git.exe", "git status"),
    ];
    let mut backward = forward.clone();
    backward.reverse();

    let a = from_observations(&forward, &declared(&file));
    let b = from_observations(&backward, &declared(&file));
    assert_eq!(a, b);
    assert_eq!(
        a.iter().map(|c| c.exe_file_name()).collect::<Vec<_>>(),
        vec!["cargo.exe", "git.exe", "rustc.exe"]
    );
}

// --- 綴りそのものが起こせるか -----------------------------------------------

/// **ストアアプリの綴りは「起こせない」として出る。**
///
/// 実機で触ってもらって見つかった（2026-09-19）。パス1の記録では入口のシェルが
/// `C:\Program Files\WindowsApps\Microsoft.PowerShell_...\pwsh.exe`として観測され、
/// 画面はそれを何の断りもなく「宣言済み」と表示していた。**宣言は書けるが、
/// 遷移の強制を積んだ構成では起こせない**綴りである（実測、`plans/mac-spike/RESULTS.md` §S62）。
///
/// 判定は`harness_sandbox`の`starts_through_the_app_model`——**シェルの候補を選ぶのと
/// 同じ関数**を通す。ここで別に書くと、画面と実際の起動可否がずれる（`B-13`）。
#[test]
fn a_store_app_spelling_is_reported_as_not_startable() {
    let file = policy(Vec::new());
    let store = observed(
        r"C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe\pwsh.exe",
        "pwsh -NoProfile",
    );
    let candidates = from_observations(&[store], &declared(&file));

    assert_eq!(candidates[0].startable, Startable::NotThroughTheAppModel);
    assert!(
        candidates[0].startable.note().is_some(),
        "起こせない理由を画面に出す文面が無い"
    );
    // **宣言そのものは止めない**（書けるが通らないことを見せて、判断はユーザーに残す）。
    assert!(
        candidates[0].is_approvable(),
        "宣言を書けなくしている（なぜ選べないのかが画面から分からなくなる）"
    );
}

/// **対の側**（`B-35`）: 普通の実行ファイルには何も言わない。
///
/// これが無いと「常に起こせないと言う」実装でも上のテストは緑になり、
/// 全部の行に赤い注記が付く画面になる。
#[test]
fn an_ordinary_program_carries_no_startability_note() {
    let file = policy(Vec::new());
    let ordinary = observed(r"C:\Program Files\Git\cmd\git.exe", "git --version");
    let candidates = from_observations(&[ordinary], &declared(&file));

    assert_eq!(candidates[0].startable, Startable::AsFarAsWeKnow);
    assert!(candidates[0].startable.note().is_none());
}

/// 実行エイリアス（`WindowsApps`配下の別の形）も同じ扱いになる。
#[test]
fn the_execution_alias_spelling_is_also_not_startable() {
    assert_eq!(
        Startable::of(r"C:\Users\u\AppData\Local\Microsoft\WindowsApps\pwsh.exe"),
        Startable::NotThroughTheAppModel
    );
    // `C:\Windows`が`C:\WindowsApps`に誤って一致しないこと（成分で見ている証拠）。
    assert_eq!(
        Startable::of(r"C:\Windows\System32\cmd.exe"),
        Startable::AsFarAsWeKnow
    );
}
