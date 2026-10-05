//! 位置の情報がある記録のファイルの候補をドメインごとに作る部品（[`from_session`]）の単体試験（P4.4）。
//!
//! 記録セッションは一時ディレクトリに作り、`process-audit.jsonl`と`fs-audit.jsonl`（通し番号つきの行）を
//! 実際に書いて読ませる。**データのパスは`C:/a`などの架空の場所**にする——`C:/Windows`・`C:/Program Files`は
//! 既定で実行できる場所として候補から外れ（D-58）、ワークスペース（一時ディレクトリ）と`%TEMP%`も外れる。

use harness_config::FsAccess;
use harness_policy::generalize::SettingsKey;
use harness_policy::policy_file::{PolicyFile, ENTRY_DOMAIN};
use harness_policy::{FsAuditEvent, FsAuditKind};

use super::*;
use crate::position_view::position_view_tests::{
    child, root, seed_position_record, user_example, workspace, CMD,
};
use crate::session_dir::RecordSessionDir;

/// `seq`のインスタンス（実行ファイル`image`）が`path`を読んだ行。`seq`が`None`なら通し番号の欄が無い行。
pub(crate) fn fs_event(path: &str, seq: Option<u64>, image: &str) -> FsAuditEvent {
    let mut event = FsAuditEvent::observed(
        FsAuditKind::Etw,
        path,
        FsAccess::Read,
        true,
        "record_all",
        1_700_000_000_000,
    );
    event.process_sequence_number = seq;
    event.process_id = seq.map(|s| s as u32);
    event.image_path = Some(image.to_string());
    event
}

/// `fs-audit.jsonl`を書く（上書き）。
pub(crate) fn write_fs_events(dir: &RecordSessionDir, events: &[FsAuditEvent]) {
    let mut text = String::new();
    for event in events {
        text.push_str(&event.to_jsonl_line().expect("jsonl"));
        text.push('\n');
    }
    std::fs::write(dir.audit_log_path(), text).expect("audit log");
}

/// ユーザーの例の通し番号: cmd=1、pwsh=2と4、calc=3、mspaint=5。
const PWSH_SEQ: u64 = 2;
const CALC_SEQ: u64 = 3;

/// （ドメイン, 値）の組を候補の順に。
fn by_domain(candidates: &SessionCandidates) -> Vec<(Option<String>, String)> {
    candidates
        .proposals
        .iter()
        .zip(&candidates.domains)
        .map(|(p, d)| (d.clone(), p.value.clone()))
        .collect()
}

/// **各ドメインは自分のインスタンスが触った分だけを持つ**（決定65(5)。子の分を親へ足さない）。
/// 対の側: 位置の情報が無い記録（`process-audit.jsonl`が無い）では全部`None`＝1つのドメイン（今までどおり）。
#[test]
fn fs_candidates_are_split_by_position_domain() {
    let ws = workspace();
    let (dir, manifest) = seed_position_record(ws.path(), "s1", &user_example());
    write_fs_events(
        &dir,
        &[
            fs_event("C:/a/x", Some(1), CMD),
            fs_event(
                "C:/b/y",
                Some(PWSH_SEQ),
                "C:/Program Files/PowerShell/7/pwsh.exe",
            ),
            fs_event("C:/c/z", Some(CALC_SEQ), "C:/Windows/System32/calc.exe"),
        ],
    );
    let candidates = from_session(&dir, &manifest, &PolicyFile::default());
    let pairs = by_domain(&candidates);
    assert!(
        pairs.contains(&(Some(ENTRY_DOMAIN.to_string()), "C:/a/x".to_string())),
        "{pairs:?}"
    );
    assert!(
        pairs.contains(&(Some("pwsh".to_string()), "C:/b/y".to_string())),
        "{pairs:?}"
    );
    assert!(
        pairs.contains(&(Some("calc".to_string()), "C:/c/z".to_string())),
        "{pairs:?}"
    );
    assert_eq!(pairs.len(), 3, "子の分が親へ足されていないこと: {pairs:?}");
    assert!(candidates.unattributed.is_some());

    std::fs::remove_file(dir.process_audit_path()).expect("消す");
    let old = from_session(&dir, &manifest, &PolicyFile::default());
    assert_eq!(old.proposals.len(), 3);
    assert!(old.domains.iter().all(Option::is_none), "{:?}", old.domains);
    assert!(old.unattributed.is_none());
}

/// **候補の番号は全体で1列**（CLI の`--accept`が今の番号で指せる）。並びは入口のドメインが先、続いて位置の順。
/// 対の側: 同じパスを2つのドメインが触ると、番号の違う2件になる（畳まない）。
#[test]
fn candidate_ids_are_one_sequence_across_domains() {
    let ws = workspace();
    let (dir, manifest) = seed_position_record(ws.path(), "s1", &user_example());
    write_fs_events(
        &dir,
        &[
            fs_event("C:/c/z", Some(CALC_SEQ), "C:/Windows/System32/calc.exe"),
            fs_event(
                "C:/b/y",
                Some(PWSH_SEQ),
                "C:/Program Files/PowerShell/7/pwsh.exe",
            ),
            fs_event("C:/a/x", Some(1), CMD),
        ],
    );
    let candidates = from_session(&dir, &manifest, &PolicyFile::default());
    let ids: Vec<(&str, &str, Option<&str>)> = candidates
        .proposals
        .iter()
        .zip(&candidates.domains)
        .map(|(p, d)| (p.id.as_str(), p.value.as_str(), d.as_deref()))
        .collect();
    assert_eq!(
        ids,
        vec![
            ("fs-1", "C:/a/x", Some(ENTRY_DOMAIN)),
            ("fs-2", "C:/b/y", Some("pwsh")),
            ("fs-3", "C:/c/z", Some("calc")),
        ]
    );

    write_fs_events(
        &dir,
        &[
            fs_event("C:/shared/s", Some(1), CMD),
            fs_event(
                "C:/shared/s",
                Some(PWSH_SEQ),
                "C:/Program Files/PowerShell/7/pwsh.exe",
            ),
        ],
    );
    let candidates = from_session(&dir, &manifest, &PolicyFile::default());
    let pairs = by_domain(&candidates);
    assert_eq!(
        pairs,
        vec![
            (Some(ENTRY_DOMAIN.to_string()), "C:/shared/s".to_string()),
            (Some("pwsh".to_string()), "C:/shared/s".to_string()),
        ]
    );
    assert_ne!(candidates.proposals[0].id, candidates.proposals[1].id);
}

/// **どのドメインにも引けないファイル操作は件数だけ出して承認できない**（決定65の細目4。入口のドメインへ
/// 寄せない）。対の側: 引けた行は全部候補になる。
#[test]
fn unattributed_fs_events_are_counted_and_not_approvable() {
    let ws = workspace();
    let (dir, manifest) = seed_position_record(ws.path(), "s1", &user_example());
    write_fs_events(
        &dir,
        &[
            fs_event("C:/a/x", Some(1), CMD),
            fs_event(
                "C:/b/y",
                Some(PWSH_SEQ),
                "C:/Program Files/PowerShell/7/pwsh.exe",
            ),
            fs_event("C:/nobody/1", None, CMD),
            fs_event("C:/nobody/2", Some(999), CMD),
        ],
    );
    let candidates = from_session(&dir, &manifest, &PolicyFile::default());
    let values: Vec<&str> = candidates
        .proposals
        .iter()
        .map(|p| p.value.as_str())
        .collect();
    assert_eq!(
        values,
        vec!["C:/a/x", "C:/b/y"],
        "引けない行が候補になっている"
    );
    let unattributed = candidates.unattributed.expect("位置の情報がある記録");
    assert_eq!(unattributed.without_sequence_number, 1);
    assert_eq!(unattributed.unknown_sequence_number, 1);
    let notes = candidates.notes.join("\n");
    assert!(
        notes.contains(
            "どのドメインにも引けなかったファイル操作 2件（承認できません——決定65の細目4）"
        ),
        "{notes}"
    );
}

/// **子の実行ファイル自身の実行権は子のドメインへ**（決定65 Q8。子を起こすとき実行ファイルを開くのは子のトークン）。
/// 子がファイル操作を1件もしなくても、子のドメインに`fs.read_exec`の候補が出る。親のドメインには出ない。
#[test]
fn a_childs_own_executable_goes_to_the_childs_domain() {
    const TOOL: &str = "C:/tools/tool.exe";
    let ws = workspace();
    let (dir, manifest) = seed_position_record(ws.path(), "s1", &[root(1, CMD), child(2, 1, TOOL)]);
    write_fs_events(&dir, &[fs_event("C:/a/x", Some(1), CMD)]);
    let candidates = from_session(&dir, &manifest, &PolicyFile::default());
    let execs: Vec<(Option<&str>, &str)> = candidates
        .proposals
        .iter()
        .zip(&candidates.domains)
        .filter(|(p, _)| p.key == SettingsKey::FsReadExec)
        .map(|(p, d)| (d.as_deref(), p.value.as_str()))
        .collect();
    assert_eq!(
        execs,
        vec![(Some("tool"), TOOL)],
        "{:?}",
        by_domain(&candidates)
    );
}

/// **CLI の`show`は、位置の情報がある記録では候補の行に書く先のドメインを添える**（画面と同じ番号・同じドメイン。
/// `approve --accept fs-N`が画面と同じ候補を指す）。対の側: 位置の情報が無い記録は今までの`aggregate::render`と
/// 1文字も変わらない。
#[test]
fn show_prints_each_candidates_domain_with_the_same_ids() {
    let ws = workspace();
    let (dir, manifest) = seed_position_record(ws.path(), "s1", &user_example());
    write_fs_events(
        &dir,
        &[
            fs_event("C:/a/x", Some(1), CMD),
            fs_event("C:/b/y", Some(PWSH_SEQ), "C:/Program Files/PowerShell/7/pwsh.exe"),
        ],
    );
    let candidates = load(&dir, &manifest, ws.path());
    let text = render(&candidates, 40);
    assert!(text.contains("fs-1     [workspace-shell] fs.read = C:/a/x"), "{text}");
    assert!(text.contains("fs-2     [pwsh] fs.read = C:/b/y"), "{text}");

    std::fs::remove_file(dir.process_audit_path()).expect("消す");
    let old = load(&dir, &manifest, ws.path());
    assert_eq!(render(&old, 40), crate::aggregate::render(&old.fs, 40));
}
