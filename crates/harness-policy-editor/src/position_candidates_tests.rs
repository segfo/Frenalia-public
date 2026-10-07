//! 位置の情報がある記録のファイルの候補をドメインごとに作る部品（[`from_session`]）の単体試験（P4.4）。
//!
//! 記録セッションは一時ディレクトリに作り、`process-audit.jsonl`と`fs-audit.jsonl`（通し番号つきの行）を
//! 実際に書いて読ませる。**データのパスは`C:/a`などの架空の場所**にする——`C:/Windows`・`C:/Program Files`は
//! 既定で実行できる場所として候補から外れ（D-58）、ワークスペース（一時ディレクトリ）と`%TEMP%`も外れる。

use std::path::Path;

use harness_config::FsAccess;
use harness_policy::generalize::SettingsKey;
use harness_policy::policy_file::{PolicyFile, ENTRY_DOMAIN};
use harness_policy::spawn_audit::{SpawnAuditRecord, SPAWN_AUDIT_SCHEMA_VERSION};
use harness_policy::{FsAuditEvent, FsAuditKind};

use super::*;
use crate::position_view::position_view_tests::{
    child, root, seed_position_record, user_example, workspace, CMD,
};
use crate::session_dir::{RecordManifest, RecordSessionDir, RecordStatus};

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
    let candidates = from_session(&dir, &manifest, &PolicyFile::default(), &harness_policy::position_domains::SplitPositions::new());
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
    let old = from_session(&dir, &manifest, &PolicyFile::default(), &harness_policy::position_domains::SplitPositions::new());
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
    let candidates = from_session(&dir, &manifest, &PolicyFile::default(), &harness_policy::position_domains::SplitPositions::new());
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
    let candidates = from_session(&dir, &manifest, &PolicyFile::default(), &harness_policy::position_domains::SplitPositions::new());
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
    let candidates = from_session(&dir, &manifest, &PolicyFile::default(), &harness_policy::position_domains::SplitPositions::new());
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
    let candidates = from_session(&dir, &manifest, &PolicyFile::default(), &harness_policy::position_domains::SplitPositions::new());
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
    let candidates = load(&dir, &manifest, ws.path(), &harness_policy::position_domains::SplitPositions::new());
    let text = render(&candidates, 40);
    assert!(text.contains("fs-1     [workspace-shell] fs.read = C:/a/x"), "{text}");
    assert!(text.contains("fs-2     [pwsh] fs.read = C:/b/y"), "{text}");

    std::fs::remove_file(dir.process_audit_path()).expect("消す");
    let old = load(&dir, &manifest, ws.path(), &harness_policy::position_domains::SplitPositions::new());
    assert_eq!(render(&old, 40), crate::aggregate::render(&old.fs, 40));
}

// ---------------------------------------------------------------------------
// パス2: 許可した生成の記録で拒否をドメインへ振り分ける（P6.6。決定68の前例の(1)(7)）
// ---------------------------------------------------------------------------

/// 入口の子が使う（`C:/Windows`の下なので実行ファイルの候補にはならない）。
pub(crate) const POWERSHELL: &str = "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe";

/// パス2の記録（決定68: 入口のドメインから始めた）を1件作る。`spawn_audit`が`Some`なら許可した生成の記録をその中身で
/// 書く（版の行も呼び出し側が入れる——読めない記録も作れるように）。`None`なら書かない（2026-10-07 より前の記録）。
pub(crate) fn seed_pass2_record(
    ws: &Path,
    id: &str,
    spawn_audit: Option<&str>,
) -> (RecordSessionDir, RecordManifest) {
    let dir = RecordSessionDir::create(ws, id).expect("session dir");
    let mut manifest = RecordManifest::new(id, "powershell -c child", ws, ws, 100);
    manifest.pass = 2;
    manifest.domain = Some(ENTRY_DOMAIN.to_string());
    manifest.status = RecordStatus::Finished;
    manifest.collector_started = true;
    manifest.etw_available = true;
    manifest.exit_code = Some(0);
    dir.write_manifest(&manifest).expect("manifest");
    std::fs::write(dir.audit_log_path(), "").expect("audit log");
    if let Some(text) = spawn_audit {
        std::fs::write(dir.spawn_audit_path(), text).expect("spawn audit");
    }
    (dir, manifest)
}

/// 許可した生成の記録の中身（版の行＋`records`。Daemon が書く形そのもの）。
pub(crate) fn spawn_audit_text(records: &[SpawnAuditRecord]) -> String {
    let mut text = SpawnAuditRecord::Header {
        schema_version: SPAWN_AUDIT_SCHEMA_VERSION,
    }
    .to_jsonl_line()
    .expect("header");
    text.push('\n');
    for record in records {
        text.push_str(&record.to_jsonl_line().expect("record"));
        text.push('\n');
    }
    text
}

/// Daemon が`domain`で起こした子1人（`seq`が`None`なら番号を取れなかった子）。
pub(crate) fn spawned(seq: Option<u64>, domain: &str) -> SpawnAuditRecord {
    SpawnAuditRecord::Spawned {
        ts_unix_ms: 1_700_000_000_000,
        pid: seq.unwrap_or(0) as u32,
        process_sequence_number: seq,
        domain: domain.to_string(),
        exe: POWERSHELL.to_string(),
        top_level: domain == ENTRY_DOMAIN,
    }
}

/// パス2の拒否1件（[`fs_event`]を拒否にしたもの）。
pub(crate) fn denial(path: &str, seq: Option<u64>) -> FsAuditEvent {
    let mut event = fs_event(path, seq, POWERSHELL);
    event.allowed = false;
    event.reason = "deny_only".to_string();
    event
}

/// **許可した生成の記録を持つパス2の記録は、拒否を起こしたドメインごとの候補になる**（決定68の前例の(1)）。並びは入口が先、
/// 残りは名前の順（`p6-child`は名前では入口より前に来る）。番号は全体で1列。引けた拒否だけなら注記は黙る。
#[test]
fn a_pass2_record_with_a_spawn_audit_splits_denials_by_domain() {
    let ws = workspace();
    let audit = spawn_audit_text(&[
        spawned(Some(10), ENTRY_DOMAIN),
        spawned(Some(11), "p6-child"),
        spawned(Some(12), "zeta"),
        spawned(Some(13), "alpha"),
    ]);
    let (dir, manifest) = seed_pass2_record(ws.path(), "p2", Some(&audit));
    write_fs_events(
        &dir,
        &[
            denial("C:/z/zeta.txt", Some(12)),
            denial("C:/b/child.txt", Some(11)),
            denial("C:/a/entry.txt", Some(10)),
            denial("C:/c/alpha.txt", Some(13)),
        ],
    );
    let candidates = load(&dir, &manifest, ws.path(), &harness_policy::position_domains::SplitPositions::new());
    let ids: Vec<(&str, &str, Option<&str>)> = candidates
        .proposals
        .iter()
        .zip(&candidates.domains)
        .map(|(p, d)| (p.id.as_str(), p.value.as_str(), d.as_deref()))
        .collect();
    assert_eq!(
        ids,
        vec![
            ("fs-1", "C:/a/entry.txt", Some(ENTRY_DOMAIN)),
            ("fs-2", "C:/c/alpha.txt", Some("alpha")),
            ("fs-3", "C:/b/child.txt", Some("p6-child")),
            ("fs-4", "C:/z/zeta.txt", Some("zeta")),
        ]
    );
    assert!(candidates.by_position(), "ドメインごとに分けた記録として扱う");
    assert!(candidates.notes.is_empty(), "{:?}", candidates.notes);

    // 分け方の答えは許可した生成の記録が持つので、policy.json が読めなくても分ける（位置の記録は読めないと1つの一覧）。
    std::fs::create_dir_all(harness_policy::policy_file::path(ws.path()).parent().unwrap()).unwrap();
    std::fs::write(harness_policy::policy_file::path(ws.path()), "{ broken").unwrap();
    let candidates = load(&dir, &manifest, ws.path(), &harness_policy::position_domains::SplitPositions::new());
    assert_eq!(candidates.proposals.len(), 4);
    assert!(candidates.by_position(), "{:?}", candidates.notes);
}

/// **許可した生成の記録が無いパス2の記録（2026-10-07 より前）は今までどおり1つの一覧**（ドメインは全部`None`）。
/// 対の側: 同じ拒否でも記録があれば分かれる（上の試験）。
#[test]
fn a_pass2_record_without_a_spawn_audit_stays_one_list() {
    let ws = workspace();
    let (dir, manifest) = seed_pass2_record(ws.path(), "p2", None);
    write_fs_events(
        &dir,
        &[denial("C:/a/entry.txt", Some(10)), denial("C:/b/child.txt", Some(11))],
    );
    let candidates = load(&dir, &manifest, ws.path(), &harness_policy::position_domains::SplitPositions::new());
    assert_eq!(candidates.proposals.len(), 2);
    assert!(candidates.domains.iter().all(Option::is_none), "{:?}", candidates.domains);
    assert!(!candidates.by_position());
    assert!(candidates.notes.is_empty(), "{:?}", candidates.notes);
    assert_eq!(
        render(&candidates, 40),
        crate::aggregate::render(&candidates.fs, 40),
        "古いパス2の記録の見え方は変わらない"
    );
}

/// **読めない許可した生成の記録（版の行が無い）は、1つの一覧にして理由を注記に出す**（黙って分けないままにしない、`B-10`）。
#[test]
fn an_unreadable_spawn_audit_falls_back_to_one_list_and_says_why() {
    let ws = workspace();
    let (dir, manifest) = seed_pass2_record(ws.path(), "p2", Some("{\"kind\":\"spawned\"}\n"));
    write_fs_events(&dir, &[denial("C:/a/entry.txt", Some(10))]);
    let candidates = load(&dir, &manifest, ws.path(), &harness_policy::position_domains::SplitPositions::new());
    assert!(candidates.domains.iter().all(Option::is_none), "{:?}", candidates.domains);
    assert!(!candidates.by_position());
    let notes = candidates.notes.join("\n");
    assert!(notes.contains("許可した生成の記録"), "{notes}");
    assert!(notes.contains("版の行で始まっていません"), "{notes}");
}

/// **どのドメインにも引けないパス2の拒否は件数だけ出して承認できない**（入口へ寄せない。決定68の前例の(7)・決定65の細目4）。
/// 内訳はパス2の言葉で言う（位置の木の「記録の木に無い番号」「割り当てなかった起動」ではない）。番号を取れなかった生成も言う。
/// 対の側: 引けた拒否は候補になる。
#[test]
fn unattributed_pass2_denials_are_counted_not_offered() {
    let ws = workspace();
    let audit = spawn_audit_text(&[spawned(Some(10), ENTRY_DOMAIN), spawned(None, "p6-child")]);
    let (dir, manifest) = seed_pass2_record(ws.path(), "p2", Some(&audit));
    write_fs_events(
        &dir,
        &[
            denial("C:/a/entry.txt", Some(10)),
            denial("C:/nobody/1", None),
            denial("C:/nobody/2", Some(999)),
        ],
    );
    let candidates = load(&dir, &manifest, ws.path(), &harness_policy::position_domains::SplitPositions::new());
    let values: Vec<&str> = candidates.proposals.iter().map(|p| p.value.as_str()).collect();
    assert_eq!(values, vec!["C:/a/entry.txt"], "引けない拒否が候補になっている");
    let unattributed = candidates.unattributed.expect("分けた記録");
    assert_eq!(unattributed.without_sequence_number, 1);
    assert_eq!(unattributed.unknown_sequence_number, 1);
    let notes = candidates.notes.join("\n");
    assert!(
        notes.contains(
            "どのドメインにも引けなかったファイル操作 2件（承認できません——決定65の細目4）: \
             通し番号の欄が無い 1件・許可した生成の記録に無い番号 1件"
        ),
        "{notes}"
    );
    assert!(!notes.contains("記録の木"), "位置の木の言葉が混ざっている: {notes}");
    assert!(notes.contains("通し番号を取れなかった生成 1件"), "{notes}");
}

/// **記録したときの実行前診断と宣言は入口のドメインの候補にだけ合流する**（マニフェストが持つのは入口の宣言。拒否が1件も
/// 無くても入口の候補として出る）。子のドメインの拒否は子のまま。
#[test]
fn the_preflight_diagnosis_of_a_pass2_record_goes_to_the_entry_domain() {
    const TOOL: &str = "C:/tools/tool.exe";
    let ws = workspace();
    let audit = spawn_audit_text(&[spawned(Some(10), ENTRY_DOMAIN), spawned(Some(11), "p6-child")]);
    let (dir, mut manifest) = seed_pass2_record(ws.path(), "p2", Some(&audit));
    manifest.unreachable_exec = Some(TOOL.to_string());
    dir.write_manifest(&manifest).expect("manifest");
    write_fs_events(&dir, &[denial("C:/b/child.txt", Some(11))]);
    let candidates = load(&dir, &manifest, ws.path(), &harness_policy::position_domains::SplitPositions::new());
    let pairs: Vec<(Option<&str>, SettingsKey, &str)> = candidates
        .proposals
        .iter()
        .zip(&candidates.domains)
        .map(|(p, d)| (d.as_deref(), p.key, p.value.as_str()))
        .collect();
    assert_eq!(
        pairs,
        vec![
            (Some(ENTRY_DOMAIN), SettingsKey::FsReadExec, TOOL),
            (Some("p6-child"), SettingsKey::FsRead, "C:/b/child.txt"),
        ]
    );
}

/// **上限を超えて記録できなかった生成と、読めない行を言う**（Daemon が畳むときに書いた`overflow`の行・数えて飛ばした行。`B-10`）。
/// 対の側: どちらも無い記録では黙る（`a_pass2_record_with_a_spawn_audit_splits_denials_by_domain`）。
#[test]
fn a_spawn_audit_that_overflowed_says_so() {
    let ws = workspace();
    let mut audit = spawn_audit_text(&[
        spawned(Some(10), ENTRY_DOMAIN),
        SpawnAuditRecord::Overflow {
            ts_unix_ms: 1_700_000_000_000,
            dropped: 3,
        },
    ]);
    audit.push_str("not json\n");
    let (dir, manifest) = seed_pass2_record(ws.path(), "p2", Some(&audit));
    write_fs_events(&dir, &[denial("C:/a/entry.txt", Some(10))]);
    let candidates = load(&dir, &manifest, ws.path(), &harness_policy::position_domains::SplitPositions::new());
    assert!(candidates.by_position());
    let notes = candidates.notes.join("\n");
    assert!(notes.contains("上限"), "{notes}");
    assert!(notes.contains("3件の生成を記録できませんでした"), "{notes}");
    assert!(notes.contains("読めない行が 1件"), "{notes}");
}
