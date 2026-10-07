//! 記録から位置の木を作る部品（[`load`]・[`verdicts`]・[`position_edges`]）の単体試験。
//!
//! 記録セッションのディレクトリは一時ディレクトリに作り、`process-audit.jsonl`をヘッダ＋インスタンスの行で
//! 実際に書いて読ませる（読む口が収集器の書く場所と同じかまで測る）。**補助は`pub(crate)`**——承認待ちの
//! 位置の行の試験（`tui::transition_positions_tests`）とファイルの候補の試験（`position_candidates_tests`）が
//! 同じ記録を作るのに使う（写すと片方だけ形が変わる、`B-05`）。

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use harness_config::FsAccess;
use harness_policy::policy_file::{PolicyFile, ENTRY_DOMAIN};
use harness_policy::position_domains::PositionSource;
use harness_policy::process_event::{
    ArgvBinding, ArgvTruncation, ParentSeqSource, ProcessAuditRecord, ProcessInstance,
    PROCESS_AUDIT_SCHEMA_VERSION,
};

use super::*;
use crate::session_dir::{self, RecordManifest, RecordSessionDir, RecordStatus};

pub(crate) const CMD: &str = "C:/Windows/System32/cmd.exe";
pub(crate) const PWSH: &str = "C:/Program Files/PowerShell/7/pwsh.exe";
pub(crate) const CALC: &str = "C:/Windows/System32/calc.exe";
pub(crate) const MSPAINT: &str = "C:/Windows/System32/mspaint.exe";
/// 記録に無い親（harness 本体）。
const HARNESS_SEQ: u64 = 9_000;

pub(crate) fn workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(session_dir::sandbox_root(dir.path())).expect("sandbox root");
    dir
}

/// 親の番号を欄から取り、引数が結び付いた子（コマンドラインは実行ファイルを引用符で囲んだだけ）。
pub(crate) fn child(seq: u64, parent: u64, image: &str) -> ProcessInstance {
    ProcessInstance {
        seq,
        parent_seq: Some(parent),
        parent_seq_source: ParentSeqSource::EtwField,
        pid: seq as u32,
        parent_pid: Some(parent as u32),
        image_path: Some(image.to_string()),
        argv: ArgvBinding::Exact {
            command_line: format!("\"{image}\""),
            truncation: ArgvTruncation::None,
        },
        is_scope_root: false,
        timestamp_unix_ms: 1_700_000_000_000 + seq,
    }
}

/// 記録の根（親は harness 本体で、記録に無い）。
pub(crate) fn root(seq: u64, image: &str) -> ProcessInstance {
    ProcessInstance {
        is_scope_root: true,
        ..child(seq, HARNESS_SEQ, image)
    }
}

/// 結び付いたコマンドラインを差し替える。
pub(crate) fn with_command_line(instance: ProcessInstance, line: &str) -> ProcessInstance {
    ProcessInstance {
        argv: ArgvBinding::Exact {
            command_line: line.to_string(),
            truncation: ArgvTruncation::None,
        },
        ..instance
    }
}

/// ユーザーの例（決定65）: cmd→pwsh→calc／cmd→pwsh→mspaint。cmd が記録の根（入口のドメイン）。
pub(crate) fn user_example() -> Vec<ProcessInstance> {
    vec![
        root(1, CMD),
        child(2, 1, PWSH),
        child(3, 2, CALC),
        child(4, 1, PWSH),
        child(5, 4, MSPAINT),
    ]
}

/// パス1の記録セッションを1件作る（`fs-audit.jsonl`は空。`process-audit.jsonl`は書かない＝古い記録）。
pub(crate) fn seed_record(ws: &Path, id: &str) -> (RecordSessionDir, RecordManifest) {
    let dir = RecordSessionDir::create(ws, id).expect("session dir");
    let mut manifest = RecordManifest::new(id, "cmd /c pwsh", ws, ws, 100);
    manifest.status = RecordStatus::Finished;
    manifest.collector_started = true;
    manifest.etw_available = true;
    manifest.exit_code = Some(0);
    dir.write_manifest(&manifest).expect("manifest");
    std::fs::write(dir.audit_log_path(), "").expect("audit log");
    (dir, manifest)
}

/// パス1の記録セッションを1件作り、`process-audit.jsonl`（版の行＋インスタンスの行）を書く。
pub(crate) fn seed_position_record(
    ws: &Path,
    id: &str,
    instances: &[ProcessInstance],
) -> (RecordSessionDir, RecordManifest) {
    let (dir, manifest) = seed_record(ws, id);
    let mut text = ProcessAuditRecord::Header {
        schema_version: PROCESS_AUDIT_SCHEMA_VERSION,
    }
    .to_jsonl_line()
    .expect("header");
    text.push('\n');
    for instance in instances {
        text.push_str(
            &ProcessAuditRecord::Instance(instance.clone())
                .to_jsonl_line()
                .expect("instance"),
        );
        text.push('\n');
    }
    std::fs::write(dir.process_audit_path(), text).expect("process audit");
    (dir, manifest)
}

fn loaded(dir: &RecordSessionDir, manifest: &RecordManifest, policy: &PolicyFile) -> PositionView {
    load(dir, manifest, policy, &harness_policy::position_domains::SplitPositions::new())
        .expect("読めるはず")
        .expect("位置の情報がある記録")
}

/// （字下げ, 実行ファイル, 遷移先）を木の順に。
fn tree_of(view: &PositionView) -> Vec<(usize, String, String)> {
    view.rows
        .iter()
        .map(|row| {
            let position = &view.assignment.positions[row.position];
            (row.depth, position.exe.clone(), position.to_domain.clone())
        })
        .collect()
}

/// **読む口は収集器が書く場所と同じ**（`policy_learnd::process_audit_path`は`fs-audit.jsonl`の隣から導く）。
/// 綴りを写した2か所がずれると、位置の情報がある記録を「古い記録」として黙って平らな一覧で見せる。
#[test]
fn a_session_dir_finds_process_audit_where_the_collector_writes_it() {
    let ws = workspace();
    let (dir, _) = seed_record(ws.path(), "s1");
    assert_eq!(
        dir.process_audit_path(),
        harness_sandbox::tier2a::policy_learnd::process_audit_path(&dir.audit_log_path())
    );
}

/// 行は記録した木の順（親の行の直後に子の行）で、字下げは木の段数。遷移先は割り当ての答え。
#[test]
fn the_rows_follow_the_recorded_tree() {
    let ws = workspace();
    let (dir, manifest) = seed_position_record(ws.path(), "s1", &user_example());
    let view = loaded(&dir, &manifest, &PolicyFile::default());

    assert_eq!(view.session_id, "s1");
    assert_eq!(
        tree_of(&view),
        vec![
            (0, PWSH.to_string(), "pwsh".to_string()),
            (1, CALC.to_string(), "calc".to_string()),
            (1, MSPAINT.to_string(), "mspaint".to_string()),
        ]
    );
    let pwsh = &view.assignment.positions[view.rows[0].position];
    assert_eq!(pwsh.source, PositionSource::Proposed);
    assert_eq!(pwsh.instances.len(), 2, "pwsh は2回起きた");
}

/// 位置の情報が無い記録（`process-audit.jsonl`が無い）と、パス2の記録は`None`（平らな一覧で見せる、決定65 Q6）。
/// 対の側: 同じ記録に`process-audit.jsonl`があれば`Some`。
#[test]
fn an_old_record_or_a_pass_2_record_has_no_positions() {
    let ws = workspace();
    let (old, old_manifest) = seed_record(ws.path(), "old");
    assert!(load(&old, &old_manifest, &PolicyFile::default(), &harness_policy::position_domains::SplitPositions::new())
        .expect("読める")
        .is_none());

    let (dir, mut manifest) = seed_position_record(ws.path(), "p2", &user_example());
    manifest.pass = 2;
    assert!(
        load(&dir, &manifest, &PolicyFile::default(), &harness_policy::position_domains::SplitPositions::new())
            .expect("読める")
            .is_none(),
        "パス2は位置を読まない（パス2は process-audit.jsonl を書かない）"
    );
    manifest.pass = 1;
    assert!(load(&dir, &manifest, &PolicyFile::default(), &harness_policy::position_domains::SplitPositions::new())
        .expect("読める")
        .is_some());
}

/// どの位置にも割り当てなかった起動は、行にせず、理由ごとの件数を注記に出す（§19.3.14）。
#[test]
fn unassigned_instances_are_counted_by_reason_in_the_notes() {
    let ws = workspace();
    let unresolved = ProcessInstance {
        parent_seq: None,
        parent_seq_source: ParentSeqSource::Unresolved,
        ..child(3, 1, CALC)
    };
    let instances = vec![
        root(1, CMD),
        child(2, 1, PWSH),
        unresolved,
        child(4, 777, MSPAINT),
    ];
    let (dir, manifest) = seed_position_record(ws.path(), "s1", &instances);
    let view = loaded(&dir, &manifest, &PolicyFile::default());

    assert_eq!(
        view.rows.len(),
        1,
        "割り当てた位置は pwsh だけ: {:?}",
        tree_of(&view)
    );
    let notes = view.notes.join("\n");
    assert!(notes.contains("親を決められない起動 1件"), "{notes}");
    assert!(notes.contains("親が記録に無い起動 1件"), "{notes}");
}

/// **広げる辺は判定器（`transition::newly_usable`）が答え、エディタは写さない**（`B-13`）。遷移先のドメインに呼び出し元の
/// 持たないファイルを足して聞くと、その辺（とそこへ届く辺）は`Widens`——**書ける**（決定66）で、呼び出し元が子を通して
/// 使えるようになる権限を持ち、文言はそれを言う。対の側: 足さなければ全部`Writable`（新しく提案したドメインは宣言を
/// 持たないので狭める向き）。
///
/// **P4.3 の画面だけでは広げる行は作れない**——位置の遷移先は新しい名前で宣言が無い（既存の名前への付け替えは
/// 断る）。ファイルの候補がドメインごとになる P4.4 で、選んだ候補を`extra_fs`として渡したときに初めて出る
/// （画面の試験は`a_widening_position_can_be_reserved_and_says_what_it_hands_over`）。
#[test]
fn a_widening_position_is_judged_by_the_checker() {
    let ws = workspace();
    let (dir, manifest) = seed_position_record(ws.path(), "s1", &user_example());
    let policy = PolicyFile::default();
    let view = loaded(&dir, &manifest, &policy);
    let edges = position_edges(
        &view.assignment,
        &BTreeMap::new(),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    let index_of = |to: &str| {
        view.assignment
            .positions
            .iter()
            .position(|p| p.to_domain == to)
            .expect("位置がある")
    };

    let plain = verdicts(&policy, ws.path(), &edges, &[], &BTreeSet::new());
    assert!(
        plain.iter().all(|v| *v == EdgeVerdict::Writable),
        "{plain:?}"
    );

    let secret = [(
        "calc".to_string(),
        "C:/secret/**".to_string(),
        FsAccess::Read,
    )];
    let widened = verdicts(&policy, ws.path(), &edges, &secret, &BTreeSet::new());
    let handed = vec![("C:/secret/**".to_string(), "read")];
    assert!(
        matches!(&widened[index_of("calc")], EdgeVerdict::Widens { newly } if newly.fs == handed),
        "{widened:?}"
    );
    assert!(widened[index_of("calc")].is_writable(), "広げる辺は書ける（決定66）");
    let note = widened[index_of("calc")].note().unwrap_or_default();
    assert!(note.contains("広げる") && note.contains("ファイル1件"), "{note}");
    assert!(!note.contains("P5まで"), "{note}");
    // pwsh へ遷移すると calc まで届くので、入口のドメインから pwsh への辺も広げる向きになる（閉包で数える、§19.3.4）。
    assert!(matches!(
        &widened[index_of("pwsh")],
        EdgeVerdict::Widens { newly } if newly.fs == handed
    ));
    assert_eq!(widened[index_of("mspaint")], EdgeVerdict::Writable);
    assert_eq!(
        ENTRY_DOMAIN,
        view.assignment.positions[index_of("pwsh")].from_domain
    );
}

/// [P5.5] **出力を捨てる位置の辺は`"output":"discard"`で書く**（決定66(4)。キー`o`の予約）。形の持ち主は`editor_edge`の
/// まま（`with_output`が出力だけを替える）で、捨てない位置は既定の「返す」。
#[test]
fn a_position_whose_output_is_discarded_becomes_a_discarding_edge() {
    use harness_policy::transition::ChildOutput;
    let ws = workspace();
    let (dir, manifest) = seed_position_record(ws.path(), "s1", &user_example());
    let policy = PolicyFile::default();
    let view = loaded(&dir, &manifest, &policy);
    let calc = view
        .assignment
        .positions
        .iter()
        .find(|p| p.to_domain == "calc")
        .expect("calc の位置");
    let discard: BTreeSet<PositionKey> = [key_of(calc)].into_iter().collect();
    let edges = position_edges(&view.assignment, &BTreeMap::new(), &discard, &BTreeMap::new());
    for add in &edges {
        let expected = if add.edge.to == "calc" {
            ChildOutput::Discard
        } else {
            ChildOutput::Return
        };
        assert_eq!(add.edge.output, expected, "{}", add.edge.to);
    }
}

/// [P5.10.2] 分けた位置（`fixed_command_line`あり）を作る。
fn split_position(exe: &str, line: &str) -> Position {
    Position {
        depth: 1,
        from_domain: ENTRY_DOMAIN.to_string(),
        exe: exe.to_string(),
        to_domain: "x".to_string(),
        source: PositionSource::Proposed,
        instances: vec![2],
        command_lines: vec![line.to_string()],
        fixed_command_line: Some(line.to_string()),
        argv_missing: 0,
        argv_truncated: 0,
    }
}

/// [P5.10.2] **作業ディレクトリの候補**（決定67(3)）: 引数の中の絶対パスのスクリプトのフォルダ。無ければ実行ファイルの
/// フォルダ。相対パスのスクリプトなら実行ファイルのフォルダを「推定」として出す。ドライブ直下は`C:\`の形で根を残す。
#[test]
fn the_cwd_candidate_is_the_script_folder_else_the_program_folder() {
    const PY: &str = "C:/Python312/python.exe";
    let candidate = |exe: &str, line: &str| {
        let c = cwd_candidate(&split_position(exe, line));
        (c.dir, c.estimated)
    };
    assert_eq!(
        candidate(PY, r"python C:\tools\mv.py C:\a\x.txt"),
        (r"C:\tools".to_string(), false)
    );
    assert_eq!(candidate(PY, "python mv.py"), ("C:/Python312".to_string(), true));
    assert_eq!(
        candidate("C:/Windows/System32/hostname.exe", "hostname"),
        ("C:/Windows/System32".to_string(), false)
    );
    assert_eq!(candidate(PY, r"python C:\job.py"), (r"C:\".to_string(), false));
}

/// [P5.10.2] **作業ディレクトリを宣言した辺は、その場所から呼んだものとして行き先を引く**（決定67(4)）——ワークスペースから
/// 引くと、宣言どおりの辺がいつも`CwdMismatch`で「着かない」になり、位置の行も確定も Strict の辺を書けない。
/// 対の側: 宣言の無い同じ起動はワークスペースから引くので、作業ディレクトリを宣言した辺に着かない。
#[test]
fn lands_elsewhere_resolves_a_cwd_edge_from_its_declared_cwd() {
    use harness_policy::policy_file::PolicyDomain;
    const PY: &str = "C:/Python312/python.exe";
    let line = r"python C:\tools\mv.py";
    let edge = editor_edge(PY, ArgvMatcher::Literal(line.to_string()), "t")
        .with_cwd(Some(r"C:\tools".to_string()));
    let mut entry = PolicyDomain::new(ENTRY_DOMAIN);
    entry.process.transitions.push(edge.clone());
    let file = PolicyFile {
        domains: vec![PolicyDomain::new("t"), entry],
        ..PolicyFile::default()
    };
    let graph = TransitionGraph::build(&file.transition_graph_input(Some("C:/ws"), &[]))
        .expect("検査に通る");
    assert_eq!(lands_elsewhere(&graph, ENTRY_DOMAIN, &edge, "C:/ws"), None);
    let undeclared = edge.clone().with_cwd(None);
    assert!(lands_elsewhere(&graph, ENTRY_DOMAIN, &undeclared, "C:/ws").is_some());
}
