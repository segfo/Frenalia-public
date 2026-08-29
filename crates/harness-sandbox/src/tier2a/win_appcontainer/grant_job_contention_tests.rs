//! [D-88（`plans/DESIGN-SANDBOX-APPPOLICY.md` §5.1.3の検証4「競合」）] **別プロセスとの交差**を測る。
//!
//! # 問いは1つ
//!
//! > 同じworkspaceを2つの`harness.exe`が同時に準備したとき、**書くのは1つだけで、
//! > しかも取りこぼしが無いか。**
//!
//! writer-leader mutex（`Local\harness-ws-prepare-<畳んだパス>-<mode>`）は実装済みだが、
//! **確かめてあるのは同一プロセス内のスレッド跨ぎまで**である
//! （[`super::grant_job_lane_tests`]の`the_preparation_lock_is_held_by_exactly_one_holder_at_a_time`）。
//! ここが測るのは、その札が**プロセスの境界を越えて**効いているかである。
//!
//! # なぜ要るのか（速さの話ではない）
//!
//! DACLの付与は「読む→足す→書き戻す」なので、交差すると片方の書込が消える。消えるのは
//! こちらが足そうとした**許可**なので普段は拒否側＝安全側へ倒れるが、`.harness/`
//! （制御ディレクトリ）の再保護だけは「読む→**外す**→書き戻す」で、
//! **交差すると外したはずの許可が戻る**——サンドボックスから制御面へ届く形なので、
//! そちらは安全側ではない。だから許可側と`.harness/`側を**対で**見る（`B-35`）。
//!
//! # 「書いたか」を何で判定するか（**付与件数で判定しない**）
//!
//! 全walkレーンでは**`rescue_granted`が0であるのが健全**である——伝播（フェーズ0）が
//! 既存の子孫へ届いていれば、救済walkは1件も書かない（[`super::WorkspaceGrantProgress::rescue_granted`]）。
//! したがって「書いた側」は付与件数では見分けられない。見分けるのは次の2行で、どちらも
//! `HARNESS_PREFLIGHT_TIMING=1`のときだけ子のstderrへ出る**既存の**計器である。
//!
//! | 出る行 | 意味 |
//! |---|---|
//! | `background: rescue walk (N checked, ...)` | このプロセスがツリーを歩いた＝**書いた側** |
//! | `another process prepared this workspace; nothing to do` | 札を取れず、**1バイトも書かずに待った側** |
//!
//! # この測定が答えないこと（**同期区間は札の外側にある**）
//!
//! `plan_workspace_preparation`はrootへのACE付与と`.harness/`の再保護を、**leader選出より前**に
//! 行う（[`super::super::workspace_prepare`]）。つまり「1バイトも書かない」と言えるのは
//! **背景ジョブの区間だけ**で、同期区間は両方のプロセスが通る。ここではその交差を直接は
//! 数えられないので、**結果（`.harness/`の保護が残っているか・全ノードへ届いているか）から
//! 間接的に見る**にとどまる。
//!
//! あわせて、`follow_the_leader`の完了判定は**浅い**（`top_level_child_missing_aces`は直下の
//! 子だけを見る）。だから全ノードの検算と対で見なければ「取りこぼしが無い」とは言えない。
//!
//! # 昇格しない
//!
//! 触るのは`C:\harness-Tier2a-verify-*`（このテストが作る）と、そこへ紐づく台帳エントリだけ。
//! `#[ignore]`が付いているのは**実プロセスを起こし実マシンのACLを変えるから**で、
//! 権限が要るからではない。
//!
//! ```text
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture grant_job_contention
//! ```

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::super::test_support::{
    build_wide_tree, cleanup_workspace, harness_exe, reachability, scopeguard, workspace_grants,
    TestDirGuard,
};

/// 書いた側が出す行（[`super::run_full_walk_lane`]の`timing.mark`）。
const LEADER_MARK: &str = "background: rescue walk (";
/// 待った側が出す行（[`super::follow_the_leader`]の`timing.mark`）。
const FOLLOWER_MARK: &str = "another process prepared this workspace; nothing to do";
/// **交差が起きなかった**ことの印。準備が既に終わっていると背景ジョブ自体が始まらない
/// （`needs_descendant_fix`が偽）ので、待ちも交差も観測できない——引き継ぎ資料が挙げている
/// 罠「準備が終わった後の状態で測ると、待ちも割り込みも観測できない」がこれである。
const READY_WITHOUT_WALK: &str = "reused persistent capability, no tree walk";

/// 測るツリーの大きさ。**leaderが札を握っている時間が、もう1つの`harness.exe`の起動時間より
/// 十分長くなければ交差そのものが起きない。** 既定40,000ノードはこの開発機で数秒。
///
/// 短く回したいときだけ下げること——下げすぎると「交差しなかった」で落ちる（黙って緑には
/// ならないようにしてある）。
fn tree_nodes() -> usize {
    std::env::var("HARNESS_TEST_LAZY_RACE_NODES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(40_000)
}

/// 1つの`harness.exe`の実行結果。**起動時刻と終了時刻を持つ**——marker以前に
/// 「2つが同時に走っていたか」を独立に確かめるためである。
struct ChildRun {
    label: &'static str,
    stdout: String,
    stderr: String,
    code: Option<i32>,
    started: Duration,
    finished: Duration,
}

impl ChildRun {
    fn wrote(&self) -> bool {
        self.stderr.contains(LEADER_MARK)
    }

    fn waited(&self) -> bool {
        self.stderr.contains(FOLLOWER_MARK)
    }

    /// 落ちたときに読む用。**両方まるごと出す**——どちらが何を言ったか分からないと、
    /// 「交差しなかった」と「交差したが両方書いた」を切り分けられない。
    fn dump(&self) -> String {
        format!(
            "--- child {} (exit={:?}, {:.2}s..{:.2}s) ---\nstdout:\n{}\nstderr:\n{}",
            self.label,
            self.code,
            self.started.as_secs_f32(),
            self.finished.as_secs_f32(),
            self.stdout.trim_end(),
            self.stderr.trim_end()
        )
    }
}

/// `harness.exe fs prepare-workspace <ws> --mode rwx`を**2本同時に**起こし、両方の出力を返す。
///
/// **新しい道具を作らない**——このCLIがそのまま「もう1つのharness」になる。同じ札
/// （[`super::prepare_lock_name`]）を取りに行くためである。
///
/// 出力は**別スレッドで並行に読む**。順に`wait_with_output`すると、待っていない側の
/// パイプが埋まって子が止まる（CLIは進捗行をstderrへ出し続ける）。
fn race_two_prepare_workspace(ws: &Path) -> Vec<ChildRun> {
    let exe = harness_exe();
    assert!(
        exe.exists(),
        "harness.exe が {} に無い。先に `cargo build --workspace` を打つこと",
        exe.display()
    );

    let t0 = Instant::now();
    let mut spawned = Vec::new();
    for label in ["A", "B"] {
        let child = Command::new(&exe)
            .arg("fs")
            .arg("prepare-workspace")
            .arg(ws)
            .arg("--mode")
            .arg("rwx")
            // **計器はこれで開く。** 無いと両方とも何も言わずに終わり、
            // 「どちらが書いたか」が観測不能になる。
            .env("HARNESS_PREFLIGHT_TIMING", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn harness.exe fs prepare-workspace");
        spawned.push((label, t0.elapsed(), child));
    }

    std::thread::scope(|scope| {
        let handles: Vec<_> = spawned
            .into_iter()
            .map(|(label, started, child)| {
                scope.spawn(move || {
                    let out = child.wait_with_output().expect("wait for harness.exe");
                    ChildRun {
                        label,
                        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
                        code: out.status.code(),
                        started,
                        finished: t0.elapsed(),
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("the reader thread must not panic"))
            .collect()
    })
}

/// **受入4の1行目**: 2つの`harness.exe`が同じworkspaceを同時に準備したとき、
/// **書くのは1つだけ**で、終わったときツリーに取りこぼしが無い。
#[test]
#[ignore = "spawns two real harness.exe processes and changes real ACLs; run NON-elevated with --test-threads=1"]
fn two_harness_processes_racing_the_same_workspace_leave_exactly_one_writer() {
    let guard = TestDirGuard::create("race");
    let workspace = guard.path().to_path_buf();
    let nodes = tree_nodes();
    let built = build_wide_tree(&workspace, nodes, 200);
    // 制御ディレクトリを置く。**ここは「保護されたまま」が合格**で、許可側とは向きが逆になる。
    let control = workspace.join(".harness");
    std::fs::create_dir_all(&control).expect("create the control dir");
    std::fs::write(control.join("state.json"), b"{}").expect("write control state");

    let canonical_ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.clone());
    // assertが落ちても実マシンへ残さない（ACEを剥がしてから台帳を落とす。台帳は2つある）。
    let _cleanup = scopeguard({
        let canonical_ws = canonical_ws.clone();
        move || cleanup_workspace(&canonical_ws)
    });

    let runs = race_two_prepare_workspace(&workspace);
    for run in &runs {
        eprintln!("{}", run.dump());
    }

    // --- (0) そもそも2つが同時に走ったか（markerより前に、独立に確かめる） ---
    let overlapped = runs[0].started < runs[1].finished && runs[1].started < runs[0].finished;
    assert!(
        overlapped,
        "the two processes did not overlap in time, so nothing was measured: \
         A {:.2}s..{:.2}s / B {:.2}s..{:.2}s",
        runs[0].started.as_secs_f32(),
        runs[0].finished.as_secs_f32(),
        runs[1].started.as_secs_f32(),
        runs[1].finished.as_secs_f32(),
    );

    // --- (1) 両方が正常に終わったか（無言失敗を「交差しなかった」と読まない） ---
    for run in &runs {
        assert_eq!(
            run.code,
            Some(0),
            "harness.exe must succeed for this measurement to mean anything:\n{}",
            run.dump()
        );
    }

    // --- (2) 準備が既に終わっていた（＝交差が起きようがない）状態で測っていないか ---
    for run in &runs {
        assert!(
            !run.stdout.contains(READY_WITHOUT_WALK),
            "the workspace was already prepared, so no preparation raced at all \
             -- the tree ({built} nodes) is too small or was left over from a previous run:\n{}",
            run.dump()
        );
    }

    // --- (3) **書いたのは1つだけか** ---
    let wrote: Vec<&str> = runs.iter().filter(|r| r.wrote()).map(|r| r.label).collect();
    let waited: Vec<&str> = runs.iter().filter(|r| r.waited()).map(|r| r.label).collect();
    let dump = || {
        runs.iter()
            .map(ChildRun::dump)
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(
        wrote.len(),
        1,
        "exactly one process may walk the tree; {} did ({wrote:?}). Two writers means the \
         leader mutex did not cross the process boundary, and a DACL read-modify-write can \
         lose the other side's write:\n{}",
        wrote.len(),
        dump()
    );
    assert_eq!(
        waited.len(),
        1,
        "the other process must report that it wrote nothing and waited; {} did ({waited:?}):\n{}",
        waited.len(),
        dump()
    );
    assert_ne!(
        wrote[0],
        waited[0],
        "the same process cannot be both the writer and the waiter:\n{}",
        dump()
    );

    // --- (4) 取りこぼしが無いか（許可側と`.harness/`側を**対で**見る） ---
    let grants = workspace_grants(&canonical_ws);
    let map = reachability(&canonical_ws, &grants);
    assert!(
        map.len() >= built,
        "the verification must see the whole tree ({} seen, {built} built)",
        map.len()
    );
    let unreached: Vec<&String> = map
        .iter()
        .filter(|(rel, reached)| !*reached && !rel.starts_with(".harness"))
        .map(|(rel, _)| rel)
        .take(10)
        .collect();
    assert!(
        unreached.is_empty(),
        "every node must be reachable after both processes finished; these are not: {unreached:?}"
    );
    for rel in [".harness", ".harness\\state.json"] {
        let entry = map.iter().find(|(candidate, _)| candidate == rel);
        assert_eq!(
            entry.map(|(_, reached)| *reached),
            Some(false),
            "the control directory must stay protected -- this is the direction where a \
             crossing restores permissions that were removed on purpose ({rel})"
        );
    }

    println!(
        "contention: {built} nodes; writer={} waiter={}; A {:.2}s..{:.2}s / B {:.2}s..{:.2}s",
        wrote[0],
        waited[0],
        runs[0].started.as_secs_f32(),
        runs[0].finished.as_secs_f32(),
        runs[1].started.as_secs_f32(),
        runs[1].finished.as_secs_f32(),
    );
}
