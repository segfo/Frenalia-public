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
//! ここが測るのは、そのミューテックスが**プロセスの境界を越えて**効いているかである。
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
//! | `another process prepared this workspace; nothing to do` | ミューテックスを取れず、**1バイトも書かずに待った側** |
//!
//! # この測定が答えないこと（**同期区間はミューテックスの外側にある**）
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

/// 測るツリーの大きさ。**leaderがミューテックスを握っている時間が、もう1つの`harness.exe`の起動時間より
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
/// **新しい道具を作らない**——このCLIがそのまま「もう1つのharness」になる。同じミューテックス
/// （[`super::prepare_lock_name`]）を取りに行くためである。
///
/// 出力は**別スレッドで並行に読む**。順に`wait_with_output`すると、待っていない側の
/// パイプが埋まって子が止まる（CLIは進捗行をstderrへ出し続ける）。
fn race_prepare_workspace(ws: &Path, labels: &[&'static str]) -> Vec<ChildRun> {
    let exe = harness_exe();
    assert!(
        exe.exists(),
        "harness.exe が {} に無い。先に `cargo build --workspace` を打つこと",
        exe.display()
    );

    let t0 = Instant::now();
    let mut spawned = Vec::new();
    for &label in labels {
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

    let runs = race_prepare_workspace(&workspace, &["A", "B"]);
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

// --- 同期区間（ミューテックスの外側）の交差を狙い撃つ ---------------------------------------

/// 1回の標本。**「読めなかった」を「届いていない」へ畳まない**（`B-10`）ので`Option`で持つ。
struct Sample {
    at: Duration,
    /// 見た順に `root` / `.harness` / `.harness\state.json` / 深いファイル。
    reached: [Option<bool>; 4],
    /// `.harness`のDACLに`SE_DACL_PROTECTED`が立っているか。
    ///
    /// **届いてしまう窓の原因を2つに割るために要る**——「保護が最初から立っていない」のか、
    /// 「保護は立っているのに伝播が通り抜けた」のかで、直す場所がまったく変わる。
    control_protected: Option<bool>,
}

/// `pick`が真の標本の**連続した区間**を`(開始秒, 終了秒, 標本数)`で返す。
///
/// 最初と最後だけを見ると、**間に挟まった正常な期間が消える**——「0.0秒から2.4秒まで
/// ずっと開いていた」と「0.0秒に一瞬、2.4秒に一瞬」が同じ表示になる。
fn runs_of(samples: &[Sample], pick: impl Fn(&Sample) -> bool) -> Vec<(f32, f32, usize)> {
    let mut out: Vec<(f32, f32, usize)> = Vec::new();
    for sample in samples {
        let at = sample.at.as_secs_f32();
        if !pick(sample) {
            continue;
        }
        match out.last_mut() {
            // 直前の標本から続いているか（標本間隔2msに対して10msの猶予で判定する）。
            Some(last) if at - last.1 <= 0.010 => {
                last.1 = at;
                last.2 += 1;
            }
            _ => out.push((at, at, 1)),
        }
    }
    out
}

fn format_runs(runs: &[(f32, f32, usize)]) -> String {
    if runs.is_empty() {
        return "-".to_string();
    }
    runs.iter()
        .map(|(a, b, n)| format!("{a:.2}s..{b:.2}s({n})"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `path`がこの主体たち**全員**から届くか。読めなければ`None`。
fn reached_by_all(path: &Path, sids: &[windows::Win32::Security::PSID]) -> Option<bool> {
    super::super::revoke::sid_effective_ace_masks(path, sids)
        .ok()
        .map(|masks| masks.iter().all(Option::is_some))
}

/// **交差の最中に、一瞬だけどう見えるかを外から標本する。**
///
/// # なぜこれを測るのか（上の1本で見つかったことの続き）
///
/// 上の測定で、**同期区間はミューテックスの外側にある**ことが実測で分かった——待つ側も
/// 「rootへの高速付与」を通っている（両方のstderrに`fast (single-object) root grant`が出る）。
/// ミューテックスが守っているのは背景ジョブだけである。
///
/// そこで問うのは「両方が書いたか」ではなく、**その交差が実害を生むか**である。
/// 見るべき向きは2つあり、**意味が正反対**なので分けて測る。
///
/// | 見るもの | 一瞬でも崩れると何が起きるか |
/// |---|---|
/// | **制御ディレクトリ（`.harness/`）が届いてしまう窓** | サンドボックスの中の子が制御面へ書ける。**安全側ではない** |
/// | **workspace root が届かなくなる窓** | 走っている子からツリー全体が消える。拒否側＝安全側だが、コマンドは壊れる |
///
/// 後者は伝播する書込が**書込の直前に主体のACEをrootから外す**ために起きる既知の窓で、
/// [`super::super::acl_dacl_write`]のモジュールdocが
/// 「子プロセスは`wait_until_done`で完了を待つので踏まない」と根拠を書いている。
/// **ここではその窓が実際に何秒開くかを、外から見た値として記録する**（`wait_until_done`が
/// 本当に覆っているかは別の測定で、ここでは判定しない）。
///
/// # **対照を置く**（これが無いと原因を交差のせいにできない）
///
/// 同じ標本を**1プロセスだけ**の腕でも取る。腕の違いは`harness.exe`の本数だけで、
/// ツリーの形も主体も標本器も同じにしてある。**窓が両方の腕で開くなら、それは交差の話ではなく
/// 準備そのものの性質である**——原因の名前が変わると、直す場所も変わる。
///
/// # この標本が答えないこと
///
/// - **標本間隔より短い窓は見えない。** 2ミリ秒ごとなので、それより短い交差は落ちる。
/// - **DACLが「届く」ことと、子が実際に書けたことは別**である。ここはサンドボックスの子を
///   起こしていないので、測っているのは*機会*であって*事実*ではない。
struct WindowReport {
    arm: &'static str,
    samples: usize,
    span: f32,
    /// `.harness` / `.harness\state.json` が**届いてしまった**連続区間。
    control_exposed: [Vec<(f32, f32, usize)>; 2],
    /// `.harness`の保護が**外れていた**連続区間。
    control_unprotected: Vec<(f32, f32, usize)>,
    /// workspace root が**届かなくなった**連続区間。
    root_invisible: Vec<(f32, f32, usize)>,
    root_unreadable: usize,
    deep_visible_at: Option<f32>,
    /// 最初に届いてしまった瞬間の`.harness`のACE一覧（**継承由来かどうかが分かる**）。
    control_aces_when_exposed: Option<Vec<String>>,
}

impl WindowReport {
    fn line(&self) -> String {
        format!(
            "[{}] {} samples over {:.2}s | .harness exposed {} | state.json exposed {} \
             | .harness unprotected {} | root invisible {} | root unreadable {} \
             | deep visible at {:?}",
            self.arm,
            self.samples,
            self.span,
            format_runs(&self.control_exposed[0]),
            format_runs(&self.control_exposed[1]),
            format_runs(&self.control_unprotected),
            format_runs(&self.root_invisible),
            self.root_unreadable,
            self.deep_visible_at,
        )
    }
}

/// 1つの腕を測る。`labels`の本数が`harness.exe`の本数（対照は1本、処置は2本）。
fn sample_one_arm(arm: &'static str, dir_label: &str, labels: &[&'static str]) -> WindowReport {
    let guard = TestDirGuard::create(dir_label);
    let workspace = guard.path().to_path_buf();
    build_wide_tree(&workspace, tree_nodes(), 200);
    let control = workspace.join(".harness");
    std::fs::create_dir_all(&control).expect("create the control dir");
    std::fs::write(control.join("state.json"), b"{}").expect("write control state");
    let deep = workspace.join("d100").join("f000100.txt");
    assert!(
        deep.exists(),
        "the sampled deep file must exist: {}",
        deep.display()
    );

    let canonical_ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.clone());
    let _cleanup = scopeguard({
        let canonical_ws = canonical_ws.clone();
        move || cleanup_workspace(&canonical_ws)
    });

    // **主体を先に発行しておく。** そうしないと標本器が誰を見ればよいか分からない
    // （名前は台帳に載るので、あとから来る子はこれを再利用する＝測る構成は変わらない）。
    for mode in crate::tier2a::workspace_ledger::WorkspaceMode::ALL {
        crate::tier2a::workspace_capability::ensure_capability_name(&canonical_ws, mode.as_str())
            .expect("issue the workspace capability name before sampling");
    }
    let grants = workspace_grants(&canonical_ws);
    let owned_sids: Vec<crate::win_common::OwnedSid> =
        grants.iter().map(|g| g.sid.clone()).collect();

    let stop = std::sync::atomic::AtomicBool::new(false);
    let (samples, control_aces_when_exposed): (Vec<Sample>, Option<Vec<String>>) = std::thread::scope(|scope| {
        let sampler = {
            let stop = &stop;
            let watched = [
                canonical_ws.clone(),
                canonical_ws.join(".harness"),
                canonical_ws.join(".harness").join("state.json"),
                canonical_ws.join("d100").join("f000100.txt"),
            ];
            let owned_sids = &owned_sids;
            scope.spawn(move || {
                let sids: Vec<windows::Win32::Security::PSID> =
                    owned_sids.iter().map(|s| s.as_psid()).collect();
                let t0 = Instant::now();
                let mut out: Vec<Sample> = Vec::new();
                let mut aces_when_exposed = None;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let at = t0.elapsed();
                    let mut reached = [None; 4];
                    for (slot, path) in reached.iter_mut().zip(watched.iter()) {
                        *slot = reached_by_all(path, &sids);
                    }
                    // **届いてしまった最初の1回だけ、現物のACEを控える。**
                    // 件数だけでは「継承で降ってきた」と「誰かが明示的に書いた」を区別できない。
                    if reached[1] == Some(true) && aces_when_exposed.is_none() {
                        aces_when_exposed =
                            super::super::test_support::describe_dacl_aces(&watched[1]).ok();
                    }
                    let control_protected =
                        super::super::revoke::dacl_is_protected(&watched[1]).ok();
                    out.push(Sample {
                        at,
                        reached,
                        control_protected,
                    });
                    std::thread::sleep(Duration::from_millis(2));
                }
                (out, aces_when_exposed)
            })
        };

        let runs = race_prepare_workspace(&workspace, labels);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for run in &runs {
            assert_eq!(
                run.code,
                Some(0),
                "harness.exe must succeed for this measurement to mean anything:\n{}",
                run.dump()
            );
        }
        // **腕が意図どおりの形だったか。** 2本の腕なら書き手はちょうど1つ、
        // 1本の腕ならその1つが書き手である（＝準備が実際に走った）。
        assert_eq!(
            runs.iter().filter(|r| r.wrote()).count(),
            1,
            "[{arm}] exactly one process must have walked the tree:\n{}",
            runs.iter().map(ChildRun::dump).collect::<Vec<_>>().join("\n")
        );
        sampler.join().expect("the sampler thread must not panic")
    });

    assert!(
        samples.len() > 100,
        "[{arm}] the sampler barely ran ({} samples), so nothing was observed",
        samples.len()
    );

    WindowReport {
        arm,
        samples: samples.len(),
        span: samples.last().map(|s| s.at.as_secs_f32()).unwrap_or(0.0),
        control_exposed: [
            runs_of(&samples, |s| s.reached[1] == Some(true)),
            runs_of(&samples, |s| s.reached[2] == Some(true)),
        ],
        control_unprotected: runs_of(&samples, |s| s.control_protected == Some(false)),
        root_invisible: runs_of(&samples, |s| s.reached[0] == Some(false)),
        root_unreadable: samples.iter().filter(|s| s.reached[0].is_none()).count(),
        deep_visible_at: samples
            .iter()
            .find(|s| s.reached[3] == Some(true))
            .map(|s| s.at.as_secs_f32()),
        control_aces_when_exposed,
    }
}

/// **制御ディレクトリが一瞬でも届くようになるか**を、1プロセスと2プロセスで対にして測る。
#[test]
#[ignore = "spawns real harness.exe processes and changes real ACLs; run NON-elevated with --test-threads=1"]
fn the_control_directory_never_becomes_reachable_during_preparation() {
    let alone = sample_one_arm("1 process", "window-alone", &["A"]);
    let crossing = sample_one_arm("2 processes", "window-crossing", &["A", "B"]);
    for report in [&alone, &crossing] {
        println!("{}", report.line());
        if let Some(aces) = &report.control_aces_when_exposed {
            println!("[{}] .harness DACL when first exposed:", report.arm);
            for ace in aces {
                println!("[{}]   {ace}", report.arm);
            }
        }
    }

    for report in [&alone, &crossing] {
        for (index, label) in [(0usize, ".harness"), (1usize, ".harness\\state.json")] {
            let exposed = &report.control_exposed[index];
            assert!(
                exposed.is_empty(),
                "[{}] the control directory ({label}) became reachable from the workspace \
                 capability during preparation ({}). This is the direction that is NOT the safe \
                 side: while that window is open, a sandboxed child can write to the control \
                 plane (D-05/D-09).\n{}\n{}",
                report.arm,
                format_runs(exposed),
                alone.line(),
                crossing.line(),
            );
        }
    }
}

// --- 「機会」を「事実」へ変える -------------------------------------------------

/// 窓の最中にサンドボックスの子が作ろうとするファイル。**制御ディレクトリの中**である。
const BREACH_REL: &str = r".harness\breach.txt";
/// 準備が終わったあとに同じ子が同じことを試す先（**拒否されるはずの対照**）。
const DENIED_REL: &str = r".harness\denied.txt";
/// 子の仕掛けが生きていることの対照（workspace本体なら書けるはず）。
const ALIVE_REL: &str = "ok.txt";

/// サンドボックスの子に`path`を作らせ、**実際に出来たか**を返す。
///
/// **判定はファイルの有無で行う**——`copy`の文言はロケールで変わるので、他人が出した綴りを
/// 根拠にしない（`B-33`）。終了コードは診断として添えるだけ。
fn sandboxed_child_creates(
    workspace: &Path,
    session: &super::super::OwnedContainerSid,
    workspace_cap: windows::Win32::Security::PSID,
    rel: &str,
) -> (bool, i32, String) {
    let target = workspace.join(rel);
    // **`cmd.exe`は使えない。** 起動側は引数を1つずつ引用符で囲むので`cmd.exe "/c" "..."`に
    // なり、`cmd`は引用符付きの`"/c"`をスイッチと認識せず**実行するプログラム名**として扱う
    // （実測: 「ファイル名、ディレクトリ名…の構文が間違っています」）。PowerShellは
    // 引数を通常どおり解釈するので、他の実機テストと同じくこちらを使う。
    let (shell, _) = super::super::resolve_shell();
    let script = format!(
        "New-Item -ItemType File -Force -Path '{}' | Out-Null",
        target.to_string_lossy()
    );
    let child = super::super::spawn_with_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", &script],
        workspace,
        &crate::secret_env::build_child_env(),
        false,
        session.as_psid(),
        super::super::NetworkCapability::Deny,
        super::super::RedirectorInject::default(),
        &[workspace_cap],
        super::super::DomainIdentity::Capability(workspace_cap),
    )
    .expect("spawn the sandboxed child through the production path");
    let (stdout, stderr, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("read the child output");
    (
        target.exists(),
        code,
        format!("{}|{}", stdout.trim(), stderr.trim()),
    )
}

/// **窓の最中に、サンドボックスの子が制御ディレクトリへ書けるか。**
///
/// # なぜ別の測定として要るのか
///
/// 上の標本器が示したのは「DACL上そう見える」ことまでで、それは*機会*であって*事実*ではない。
/// **書けることまで見ないと深刻度が決まらない。**
///
/// # 待ちを意図的に外す（**それがこの測定の要点である**）
///
/// 既定では子は`grant_job::wait_until_done`で準備の完了を待つので、この窓を踏まない。
/// [`super::super::acl_dacl_write`]のモジュールdocも、rootが一瞬見えなくなる窓について
/// 「子は待つので踏まない」を根拠にしている。**しかしD-88はその待ちを外す機構である。**
/// だからここでは待たずに子を起こす——安全性の根拠が「待ち」に置かれているとき、
/// その待ちが無い世界で何が起きるかを測らなければ、根拠が生きているかは分からない。
///
/// # 対で見る（`B-35`）
///
/// 窓の外で同じ子が同じことをして**拒否される**ことと、workspace本体になら**書ける**ことを
/// 並べる。前者が無いと「そもそも境界が無い」を見ているだけかもしれず、後者が無いと
/// 「子が壊れていて何も書けない」を「拒否された」と読む。
#[test]
#[ignore = "spawns a real AppContainer child during the preparation window and changes real ACLs; run NON-elevated with --test-threads=1"]
fn a_sandboxed_child_cannot_write_the_control_plane_during_the_preparation_window() {
    // **全walkレーンを選ぶ。** lazyレーンは伝播を一度も呼ばないので、この窓自体が無い。
    let previous = std::env::var(super::super::lazy_grant::LAZY_LANE_ENV).ok();
    std::env::set_var(super::super::lazy_grant::LAZY_LANE_ENV, "0");
    let _restore = scopeguard(move || match &previous {
        Some(v) => std::env::set_var(super::super::lazy_grant::LAZY_LANE_ENV, v),
        None => std::env::remove_var(super::super::lazy_grant::LAZY_LANE_ENV),
    });
    assert!(
        matches!(
            super::super::lazy_grant::lane(),
            super::PreparationLane::FullWalk
        ),
        "this measurement needs the propagating lane; the lazy lane never propagates"
    );

    let guard = TestDirGuard::create("breach");
    let workspace = guard.path().to_path_buf();
    // 窓の長さは伝播の長さである。子の起動（約0.3秒）が収まるだけの幅を取る。
    build_wide_tree(&workspace, tree_nodes() * 2, 200);
    let control = workspace.join(".harness");
    std::fs::create_dir_all(&control).expect("create the control dir");
    std::fs::write(control.join("state.json"), b"{}").expect("write control state");

    let canonical_ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.clone());
    let _cleanup = scopeguard({
        let canonical_ws = canonical_ws.clone();
        move || cleanup_workspace(&canonical_ws)
    });

    let outcome = super::super::preflight(
        &workspace,
        &[],
        None,
        &super::super::WorkspaceWriteMode::DirectRw,
    )
    .unwrap_or_else(|e| panic!("preflight must succeed before this means anything ({e:?})"));
    for warning in &outcome.warnings {
        eprintln!("preflight warning: {warning}");
    }

    let session =
        super::super::ensure_profile(&crate::tier2a::session_profile::current_profile_name())
            .expect("the session profile must exist after preflight");
    let workspace_cap = super::super::workspace_capability_sid(&canonical_ws, "rwx")
        .expect("the rwx capability must exist after preflight");
    let grants = workspace_grants(&canonical_ws);
    let sids: Vec<windows::Win32::Security::PSID> = grants.iter().map(|g| g.sid.as_psid()).collect();

    // **窓が開くのを待つ。** 「保護が外れている」だけでは足りない——準備が始まる前も
    // 外れているので、そこで撃つと別のものを測る。開いた状態＝**許可が届いている**こと。
    let waiting_since = Instant::now();
    let mut opened_at = None;
    while waiting_since.elapsed() < Duration::from_secs(60) {
        if reached_by_all(&control, &sids) == Some(true) {
            opened_at = Some(waiting_since.elapsed());
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let opened_at = opened_at.expect(
        "the control directory never became reachable during preparation; \
         the sampling measurement says it should (grant_job_contention_tests)",
    );

    let (breached, code, output) =
        sandboxed_child_creates(&workspace, &session, workspace_cap.as_psid(), BREACH_REL);
    let still_open = reached_by_all(&control, &sids);
    println!(
        "breach probe: window opened at {:.2}s; child exit={code} created={breached}; \
         window still open when the child finished: {still_open:?}; output={output}",
        opened_at.as_secs_f32()
    );

    super::super::grant_job::wait_until_done().expect("the preparation must finish");

    // --- 対: 窓の外では拒否される / workspace本体になら書ける ---
    let (denied_created, denied_code, _) =
        sandboxed_child_creates(&workspace, &session, workspace_cap.as_psid(), DENIED_REL);
    let (alive_created, alive_code, alive_out) =
        sandboxed_child_creates(&workspace, &session, workspace_cap.as_psid(), ALIVE_REL);
    println!(
        "controls: after ready -> control plane created={denied_created} (exit={denied_code}); \
         workspace created={alive_created} (exit={alive_code}, {alive_out})"
    );
    assert!(
        alive_created,
        "the child machinery must work at all, otherwise 'denied' proves nothing \
         (exit={alive_code}, {alive_out})"
    );
    assert!(
        !denied_created,
        "once preparation finished, the sandbox must not be able to write the control plane; \
         if it can, the finding is not about the window at all (D-05/D-09)"
    );

    assert!(
        !breached,
        "a sandboxed child created {BREACH_REL} while the preparation window was open \
         (opened at {:.2}s, child exit={code}). The control plane (D-05/D-09) is writable \
         from inside the sandbox for the duration of the propagating write, and the only \
         thing that normally keeps a child out of that window is the very wait that D-88 removes",
        opened_at.as_secs_f32()
    );
}

// --- leaderが生き続けるときに、待っている側は解放されるか -------------------------

/// **準備が終わったら、待っている`harness.exe`は動き出せるか。**
///
/// # なぜ`harness fs prepare-workspace`を2本ぶつけるだけでは足りないのか
///
/// あちらは**leaderがすぐ終了する**。名前付きミューテックスは所有者スレッドが消えた時点で
/// 放棄状態になり、待ち手はそれで解放される——だから**解放が正しく行われたかどうかに関係なく
/// 緑になる**（実測でも待ち手はleaderの終了の0.04〜0.10秒後に終わっていた）。
///
/// 対話セッションのharnessは**終了しない**。だからここでは、**leaderをこのテストプロセスにして
/// 生かしたまま**、準備の完了後に待ち手が動き出すかを測る。
///
/// # このテストが捕まえた欠陥（[BUG-146](../../../../docs/bugs/BUG-146.md)）
///
/// [`super::start`]は名前付きミューテックスを**呼び出し元のスレッド**で取り、背景スレッドで
/// 解放していた。Windowsの名前付きミューテックスは所有権が取得したスレッドに紐づくので、
/// `ReleaseMutex`は`ERROR_NOT_OWNER`で失敗する——**しかも`CloseHandle`は成功するので、
/// 戻り値を見ない限り何も起きていないように見える**。待っている側は1つ目の**プロセスが
/// 終了する**まで動けず、そのworkspaceでコマンドを1本も実行できなくなっていた。
///
/// 修正は取得を背景スレッドへ移し、**取得と解放を同じスレッドへ閉じた**。あわせて
/// `NamedLock`から`Send`を外し、同じ間違いをコンパイラが止めるようにしてある
/// （プリミティブ側の回帰網は`harness-grant-ledger`の
/// `the_lock_guard_cannot_move_between_threads`とその対）。
///
/// **`#[ignore]`は外さない。** 理由は「実`harness.exe`を起こし実マシンのACLを変える」で、
/// このファイルの他の全テストと同じ分類である（赤かったから隠していたのではない）。
#[test]
#[ignore = "spawns a real harness.exe that may block; run NON-elevated with --test-threads=1"]
fn a_waiting_harness_starts_moving_once_the_leader_finishes_preparing() {
    let guard = TestDirGuard::create("leader-alive");
    let workspace = guard.path().to_path_buf();
    // leaderがミューテックスを握っている時間だけあればよいので、小さめでよい。
    build_wide_tree(&workspace, tree_nodes() / 5, 200);
    let control = workspace.join(".harness");
    std::fs::create_dir_all(&control).expect("create the control dir");

    let canonical_ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.clone());
    let _cleanup = scopeguard({
        let canonical_ws = canonical_ws.clone();
        move || cleanup_workspace(&canonical_ws)
    });

    for mode in crate::tier2a::workspace_ledger::WorkspaceMode::ALL {
        crate::tier2a::workspace_capability::ensure_capability_name(&canonical_ws, mode.as_str())
            .expect("issue the workspace capability name");
    }
    let grants = workspace_grants(&canonical_ws);

    // **このプロセスがleaderになる。** 製品の`start`とまったく同じ経路を通す——
    // ミューテックスは`start`が起こす背景スレッドで取られ、同じスレッドで解放される。
    // **このテストプロセスは終了しない**ので、放棄状態による解放は起きない。
    let started = super::start(super::GrantJobRequest {
        root: &canonical_ws,
        ace_grants: grants.clone(),
        protect_sids: Vec::new(),
        skip: vec![canonical_ws.join(".harness")],
        workspace: &canonical_ws,
        mode: "rwx",
        capability_generation: "leader-alive-generation",
        lane: super::PreparationLane::FullWalk,
    });
    assert!(started, "the leader job must start for this to mean anything");

    // 待ち手を1本立てる。**このプロセスは終了しない**ので、放棄状態では解放されない。
    let exe = harness_exe();
    let mut follower = Command::new(&exe)
        .arg("fs")
        .arg("prepare-workspace")
        .arg(&workspace)
        .arg("--mode")
        .arg("rwx")
        .env("HARNESS_PREFLIGHT_TIMING", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the waiting harness.exe");

    super::wait_until_done().expect("the leader preparation must finish");
    let finished_at = Instant::now();

    // 準備は終わった。待ち手はここから動き出せるはずである。
    let mut exited_after = None;
    while finished_at.elapsed() < Duration::from_secs(15) {
        match follower.try_wait().expect("poll the follower") {
            Some(_) => {
                exited_after = Some(finished_at.elapsed());
                break;
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    if exited_after.is_none() {
        // **必ず落とす。** 残すとこのテストバイナリが終わるまで待ち続ける。
        let _ = follower.kill();
    }
    // どちらの道でも刈り取る（`try_wait`が`Some`を返した場合も含めて1箇所で）。
    let _ = follower.wait();
    println!(
        "waiting harness: exited {:?} after the leader finished preparing",
        exited_after
    );

    assert!(
        exited_after.is_some(),
        "the waiting harness.exe was still blocked 15s after the leader finished preparing. \
         The leader is still alive (an interactive session does not exit), so the named mutex \
         was never released -- it is dropped on the background thread, but Windows ties mutex \
         ownership to the acquiring thread. The waiter is freed only when the leader PROCESS \
         exits, and its own wait gives up after 300s and fails the command fail-closed"
    );
}

// --- leaderが途中で死んだとき、待っていた側が引き継ぐか ---------------------------

/// **leaderのプロセスが準備の最中に死んだら、待っていた`harness.exe`が引き継いで完走するか。**
///
/// # なぜ要るのか（[BUG-146](../../../../docs/bugs/BUG-146.md)の「壊してはいけないもの」2番目）
///
/// 準備を1プロセスに絞る仕組みは、**leaderが死んだときに誰も再開できなくなる**という失敗の
/// 仕方を持つ。設計（§5.1.3）はそれを、名前付きミューテックスの**放棄状態**
/// （所有者が解放せずに死ぬとWindowsが次の待ち手へ`WAIT_ABANDONED`で所有権を渡す）で
/// 受け止めると決めている。ここはその引き継ぎを**初めて実測する**——
/// 受入4の残り1行でもあり（`plans/HANDOFF-LAZY-ACE-FAULT-IN.md`の表）、実測は
/// `plans/mac-spike/RESULTS.md` §S29-3にある。
///
/// BUG-146の修正は`with_named_lock`（＝待つ側が通る口）の`WAIT_ABANDONED`の扱いを変えた。
/// 変える前は「取れなかった」と読んで**排他せずに先へ進み、受け取った所有権も解放しないまま
/// ハンドルを閉じて**いた。**振る舞いを変えた経路は測らずに済ませない。**
///
/// # 何を合格とするか（**どちらが歩いたかでは判定しない**）
///
/// leaderがどこまで進んで死んだかで、引き継いだ側が「全walkをやり直す」か
/// 「もう届いていたので何もしない」かが変わる。**どちらも正しい。** だから判定するのは
/// 結果の側——引き継いだ側が成功で終わり、ツリーが全件届き、制御ディレクトリが保護された
/// ままであること——にする。どちらを通ったかは診断として出す。
///
/// # この測定が答えないこと（**2つあり、どちらも実測で確かめた**）
///
/// 1. **待ち手が本当に待ちへ入っていたことは、直接は観測していない。** 「leaderが
///    ミューテックスを握っている」ことと「待ち手がまだ終わっていない」ことの2つから
///    間接的に置いている。
/// 2. **`WAIT_ABANDONED`の扱いが直ったことは、ここでは測れない。** 直す前の
///    `with_named_lock`は放棄状態を「取れなかった」と読んで**排他せずに先へ進んで**いた
///    ——先へ進めば`follow_the_leader`のクロージャは走るので、**引き継ぎ自体は成功する**。
///    実際、修正を戻してもこのテストは緑のままだった（2026-08-30に実測）。失っていたのは
///    引き継ぎの成否ではなく**その間の排他**であり、それを捕まえるのは
///    `harness-grant-ledger`の`a_lock_abandoned_by_a_dead_thread_is_taken_over_and_released`
///    である。**「緑だから直っている」と読まないこと。**
#[test]
#[ignore = "spawns two real harness.exe processes and kills one; changes real ACLs; run NON-elevated with --test-threads=1"]
fn a_second_harness_takes_over_when_the_leader_process_is_killed_mid_preparation() {
    let guard = TestDirGuard::create("leader-killed");
    let workspace = guard.path().to_path_buf();
    // leaderが握っている間に待ち手を立て、さらに殺すまでの時間が要るので大きめにする。
    let built = build_wide_tree(&workspace, tree_nodes(), 200);
    let control = workspace.join(".harness");
    std::fs::create_dir_all(&control).expect("create the control dir");
    std::fs::write(control.join("state.json"), b"{}").expect("write control state");

    let canonical_ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.clone());
    let _cleanup = scopeguard({
        let canonical_ws = canonical_ws.clone();
        move || cleanup_workspace(&canonical_ws)
    });

    let exe = harness_exe();
    assert!(
        exe.exists(),
        "harness.exe が {} に無い。先に `cargo build --workspace` を打つこと",
        exe.display()
    );
    let spawn_one = |label: &str| {
        Command::new(&exe)
            .arg("fs")
            .arg("prepare-workspace")
            .arg(&workspace)
            .arg("--mode")
            .arg("rwx")
            .env("HARNESS_PREFLIGHT_TIMING", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn harness.exe {label}: {e}"))
    };

    let lock_name = super::prepare_lock_name(&canonical_ws, "rwx");
    let mut leader = spawn_one("leader");

    // **leaderがミューテックスを握るまで待つ。** 握る前に待ち手を立てると、待ち手の方が
    // leaderになってしまい、測りたい形にならない。取れてしまったら即座に手放す
    // （握ったままだと今度はこちらがleaderになる）。
    let waiting_since = Instant::now();
    let mut held_at = None;
    while waiting_since.elapsed() < Duration::from_secs(60) {
        match crate::try_acquire_named_lock(&lock_name) {
            Some(taken) => {
                drop(taken);
                std::thread::sleep(Duration::from_millis(20));
            }
            None => {
                held_at = Some(waiting_since.elapsed());
                break;
            }
        }
    }
    let held_at = match held_at {
        Some(at) => at,
        None => {
            let _ = leader.kill();
            let _ = leader.wait();
            panic!("the leader never took the preparation mutex, so nothing was measured");
        }
    };

    // 待ち手を立て、待ちへ入るだけの猶予を与える。
    let mut follower = spawn_one("follower");
    std::thread::sleep(Duration::from_secs(2));
    let follower_still_running = follower
        .try_wait()
        .expect("poll the follower")
        .is_none();

    // **leaderを殺す。** これが放棄状態を作る唯一の方法である（正常終了させると
    // 解放されてしまい、測りたい経路を通らない）。
    let _ = leader.kill();
    let leader_out = leader.wait_with_output().expect("reap the killed leader");
    let killed_at = Instant::now();

    // 引き継いだ側を待つ。**`WAIT_TIMEOUT`（300秒）よりずっと手前で切る**——
    // そこまで待つと「引き継げなかった」と「遅い」の区別が付かなくなる。
    let mut finished_after = None;
    while killed_at.elapsed() < Duration::from_secs(180) {
        match follower.try_wait().expect("poll the follower") {
            Some(_) => {
                finished_after = Some(killed_at.elapsed());
                break;
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    if finished_after.is_none() {
        let _ = follower.kill();
    }
    let follower_out = follower
        .wait_with_output()
        .expect("reap the taking-over harness.exe");
    let follower_stderr = String::from_utf8_lossy(&follower_out.stderr).into_owned();
    let follower_stdout = String::from_utf8_lossy(&follower_out.stdout).into_owned();

    println!(
        "leader-killed: mutex held at {:.2}s (leader exit={:?}); follower finished {:?} after \
         the kill; follower walked={} / reported-nothing-to-do={}",
        held_at.as_secs_f32(),
        leader_out.status.code(),
        finished_after,
        follower_stderr.contains(LEADER_MARK),
        follower_stderr.contains(FOLLOWER_MARK),
    );

    assert!(
        follower_still_running,
        "the second harness.exe had already finished before the leader was killed, so it never \
         waited on the abandoned mutex and nothing was measured:\nstdout:\n{follower_stdout}\n\
         stderr:\n{follower_stderr}"
    );
    assert!(
        finished_after.is_some(),
        "the second harness.exe never finished within 180s after the leader was killed. \
         The preparation mutex was abandoned by the dead leader, and taking it over is the \
         only way this workspace ever becomes usable again (D-88 §5.1.3)\nstdout:\n\
         {follower_stdout}\nstderr:\n{follower_stderr}"
    );
    assert_eq!(
        follower_out.status.code(),
        Some(0),
        "the harness.exe that took over must succeed:\nstdout:\n{follower_stdout}\nstderr:\n\
         {follower_stderr}"
    );

    // --- 結果で判定する（許可側と制御ディレクトリ側を**対で**見る、`B-35`） ---
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
        "every node must be reachable after the survivor took over; these are not: {unreached:?}"
    );
    for rel in [".harness", ".harness\\state.json"] {
        let entry = map.iter().find(|(candidate, _)| candidate == rel);
        assert_eq!(
            entry.map(|(_, reached)| *reached),
            Some(false),
            "the control directory must stay protected through the takeover ({rel})"
        );
    }
}
