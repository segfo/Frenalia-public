//! Tier1（`record_all`、ポリシー定義モード想定）の実現性スパイク。
//!
//! `POLICY-EDITOR-TOMOYO-DIG.md`／`tier1-proxy-luminous-marshmallow.md`（プランファイル）の
//! 設計は、Tier1プロセスツリーのFSアクセスを`ScopeTracker`の`harness_pid`ブートストラップ＋
//! 親子継承（signal 2）だけで正しく相関・帰属できることを前提にしている——Tier1
//! （制限トークン、package SID無し）にはsignal 1（`PackageFullName`）もsignal 3
//! （`TokenIsAppContainer`照会）も使えないため、この前提が崩れていると設計全体が成立しない。
//! 本ファイルはこの前提を実機で検証する。単体テスト（`server.rs`の
//! `flush_batch_record_all_tests`）は`ScopeTracker`へ合成データを与えて配線を確認済みだが、
//! **実際のETWイベント（本物のCreate/OperationEnd、本物のProcessStart）が想定通りの形で
//! 届くか**は実機でしか確かめられない。
//!
//! 実行例（要管理者権限）: `dev-elevated-run.exe spike-etw-tier1-record-all`
//! （`crates/dev-elevated-runner/src/lib.rs`の`KNOWN_TARGETS`にキーを登録済み）。
//!
//! 使い捨てスパイクの位置付け（`docs/CODE-STRUCTURE-RULES.md`規則2）——結論が出たら
//! このファイルは削除し、知見だけをJournal（`docs/phases/**`）へ残す。

use std::time::Duration;

use super::scope::{ScopeTracker, ScopeVerdict};
use super::session::EtwFsSession;
use crate::tier1::win_restricted;

/// セッションを張ってから実際にイベントが流れ始めるまでの待ち。ETWのリアルタイム
/// セッションは即座には配送を始めない（`spike_tests.rs`が実測で確立した値と同じ）。
const WARMUP: Duration = Duration::from_millis(1500);
/// 対象コマンド終了後、バッファ内のイベントが配送され切るまでの待ち（同上）。
const DRAIN: Duration = Duration::from_secs(4);

// **このスパイクが副産物として掘り当てたバグ**（記録）: 最初の実行で
// `set_low_integrity_label`が`ERROR_INVALID_FLAGS`で失敗した。当初は「昇格トークンでは
// `SeSecurityPrivilege`の有効化が要るのでは」と疑ったが、それは誤りで、真因は
// SDDL文字列`"S:(ML;NI;NW;;;LW)"`の`NI`がSDDLの正規ACEフラグトークンではないこと
// （BUG-018の案Aが導入、以来ラベルは一度も付いていなかった）。修正済み
// （docs/bugs/BUG-088.md、`win_restricted.rs`の`SDDL_LOW_LABEL`と回帰テスト3本）。

/// **本命**: package SIDを持たないTier1のプロセスツリー（powershell.exe →孫の`cmd.exe`）で、
/// 孫プロセスが行った`type`（読み取り）のFSアクセスが、`harness_pid`起点の親子継承だけで
/// 正しく「対象」と判定され、record-allとして記録されるか。
///
/// 孫を挟むのは、gen1（harness_pidの直接の子）だけならharness_pidブートストラップ単体でも
/// 説明が付いてしまい、**設計が本当に頼っている「signal 2＝親が対象なら子も対象」が
/// Tier1でも機能するか**を検証できないため。
#[cfg(windows)]
#[test]
#[ignore = "requires administrator token for a real-time ETW session"]
fn tier1_grandchild_process_is_attributed_via_parentage_without_appcontainer_signals() {
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path().to_path_buf();
    win_restricted::set_low_integrity_label(&cwd).expect("set low IL label on cwd");

    let target_file = cwd.join("tier1-spike-marker.txt");
    std::fs::write(&target_file, b"marker").unwrap();

    let session_name = format!("harness-policy-learn-tier1-spike-{}", std::process::id());
    let session = EtwFsSession::start_record_all(&session_name).expect("start ETW session");
    assert!(
        session.kernel_process_enabled(),
        "Kernel-Process must be enabled for ProcessStart-based scoping to work at all"
    );
    // **対象コマンドを起動する前に**配送が始まるのを待つ。ここを省くと、子プロセスの
    // ProcessStartごと取りこぼす（実測: warmup無しだとProcessStartもAccessRecordも0件）。
    std::thread::sleep(WARMUP);

    // gen1 = powershell.exe（このテストプロセス自身の直接の子）。
    // gen2 = cmd.exe（`&`呼び出し演算子でpowershellの子として起動、`type`でファイルを読む）。
    let env = crate::secret_env::build_child_env();
    let command = format!("& cmd.exe /c type \"{}\"", target_file.display());
    let child = win_restricted::spawn(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", &command],
        &cwd,
        &env,
        false,
    )
    .expect("spawn Tier1 powershell");
    let harness_pid = std::process::id();
    let (out, err, code) = child.write_stdin_read_output_and_wait(None).unwrap();
    assert_eq!(
        code, 0,
        "powershell should exit cleanly: out={out:?} err={err:?}"
    );
    assert!(
        out.contains("marker"),
        "the grandchild should have read the marker file: {out:?}"
    );

    // ETWの配送には遅延があるので待ってからドレインする（既存スパイクと同じ作法）。
    std::thread::sleep(DRAIN);

    let mut tracker = ScopeTracker::new("").with_harness_pid(Some(harness_pid));
    let (starts, records) = session.drain_records();
    eprintln!(
        "[spike] observed {} ProcessStart, {} AccessRecord",
        starts.len(),
        records.len()
    );
    for start in &starts {
        eprintln!(
            "[spike] ProcessStart pid={} parent={:?} image={:?}",
            start.pid, start.parent_pid, start.image_name
        );
        tracker.on_process_start_probing(start, |_pid| None);
    }

    let in_scope_pids: std::collections::BTreeSet<u32> = records
        .iter()
        .filter(|r| tracker.classify(r.pid, |_pid| None) == ScopeVerdict::InScope)
        .map(|r| r.pid)
        .collect();
    eprintln!("[spike] in-scope PIDs with at least one record: {in_scope_pids:?}");

    let marker_name = target_file
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let matching: Vec<_> = records
        .iter()
        .filter(|r| r.file_name.contains(&marker_name))
        .collect();
    eprintln!("[spike] records touching the marker file: {matching:?}");

    assert!(
        !matching.is_empty(),
        "expected at least one AccessRecord touching {marker_name}, but none were observed at all \
         (ETW may not have captured the grandchild's Create/OperationEnd)"
    );
    assert!(
        matching
            .iter()
            .any(|r| tracker.classify(r.pid, |_pid| None) == ScopeVerdict::InScope),
        "the record(s) touching {marker_name} were observed but none were attributed as \
         in-scope -- parentage-based scoping did not reach the grandchild: {matching:?}"
    );
    assert!(
        tracker.in_scope_process_count() >= 2,
        "expected at least 2 in-scope processes (powershell.exe gen1 + cmd.exe gen2 grandchild), \
         got {} -- signal 2 (parent inheritance) likely did not fire for the grandchild",
        tracker.in_scope_process_count()
    );

    session.stop();
}
