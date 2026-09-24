//! [D-88（`plans/DESIGN-SANDBOX-APPPOLICY.md` §5.1.3）検証6「UX」] **昇格の主条件である
//! first-command-outputのp95**を、現行の全walk待機とランダム順で比較して測る。
//!
//! # 何を測るのか（速さの自慢ではなく、昇格条件の検算である）
//!
//! 設計書§5.1.3の「検証と昇格条件」6が主条件を
//! **「first-command-outputのp95」**と定め、**総完了時間は悪化を許容して記録だけ残す**と
//! 決めている。ここで測るのはその主条件で、
//! **`spawn_shell_in_workspace`を呼んでから子が最初の1行を出すまで**を腕ごとに反復する。
//!
//! | 腕 | 何をしているか |
//! |---|---|
//! | `lazy` | 既定。背景の準備を待たずに起こし、要るものは割り込みで実体化する |
//! | `full_walk` | `HARNESS_TIER2A_LAZY_ACE=0`。背景ジョブの完走を待ってから起こす |
//!
//! # **測ったツリーの構成を必ず併記する**（この測定でいちばん壊れやすいところ）
//!
//! §S21が実測したとおり、ビルドが触るのは宣言ツリーの6.8%だが、**その余裕はほぼ`.git`由来**
//! である（`.git`を外すと40.4%、`crates/`だけなら90.6%）。したがって
//! **構成を書かない数字は実リポジトリへ外挿できない**。本測定はツリーごとに
//! ノード数・内訳・バイト数・最大深さを数え、**同じレポートの中**へ入れる
//! （数字と構成が別の場所にあると、片方だけ引用されて外挿が起きる）。
//!
//! 測る構成は3つ。**どれも「1回目の起動」だけを測る**（2回目は背景ジョブ自体が始まらないので
//! 両腕とも同じである、設計書§5.1.3「効くのは1回目だけである」）。
//!
//! | 構成 | 何を代表するか |
//! |---|---|
//! | `t1` 本リポジトリのソース＋`.git` | §S21と同じ構成（死荷重が大半を占める側） |
//! | `t2` 同じものから`.git`を抜いたもの | **lazyが最も不利**な構成 |
//! | `t3` 合成ツリー | §S26が実測した実リポジトリ（24.7万ノード・63秒）に対応する規模 |
//!
//! # ここが測れて**いない**こと（限界を同じ場所に書く）
//!
//! - **製品は出力を流さない。** `run_shell`は`write_stdin_read_output_and_wait`で完走まで
//!   待つ（`harness-tools/src/shell/runner.rs`）ので、ここで採る`first_output_ms`は
//!   **コマンドが動き出した時刻**であって**人が画面で見る時刻ではない**。
//!   短いコマンドで人が見るのは総完了時間の側である。
//! - **`t3`は合成ツリー**なので、実リポジトリより速い（§S26が同規模で2.8倍の差を実測）。
//!   **`t3`の`full_walk`の値をそのまま実リポジトリへ外挿しないこと。**
//! - **撤収してから測り直す形**なので、初回付与ではなく再付与を測っている（§S12-1が
//!   「撤収後の再付与は初回の0.9倍」を実測）。
//! - **単価（検証5-b）は測っていない。** 「1件0.15ミリ秒」は§S13からの外挿値のままである。
//! - **DirectRwだけ**である。CoWは受付パイプを子へ渡さない（`launch.rs`の`lazy_lane_pipe`）ので
//!   対象外で、そちらは検証7の担当である。
//!
//! ```text
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture lazy_ux_latency
//! ```

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::test_support::{
    build_wide_tree, cleanup_workspace, percentile, scopeguard, shuffle_in_place,
};
use super::*;

/// 測定用ツリーの置き場。`TestDirGuard`（`C:\harness-Tier2a-verify-*`、Dropで毎回消す）を
/// **使わない**——25万ノードを試行ごとに作り直すことになるためで、既存の測定と同じ
/// `C:\harness-e2e\`配下に置いて**最後にまとめて消す**。
const TREE_ROOT: &str = r"C:\harness-e2e";

/// 子に読ませる対象は**2つある。走査が最後に来る側を混ぜるためである。**
///
/// # 名前の付け方を間違えると、割り込みを1件も測らずに緑になる（実測で踏んだ）
///
/// 走査器は`pending_dirs.pop()`で進む**スタック**なので、各階層を
/// **逆アルファベット順**に処理する（[`super::lazy_grant::scanner`]）。したがって
/// `zzz-`で始まるディレクトリは**最初に**準備される——初回の20回では、そこを読ませた
/// 子の割り込みが**全試行で0件**だった。「速かった」ことは測れていても、
/// 「割り込みが成立した」ことは測れていない（`B-35`: 対で見ないと読み違える）。
///
/// そこで`aaa-`（走査の**最後**に来る側）を足し、子には**両方**を読ませる。
const PROBE_REL: &str = r"zzz-probe\deep\target.txt";
/// 走査が最後に回ってくる側（上のdocを参照）。**割り込みはここで起きる。**
const LATE_PROBE_REL: &str = r"aaa-probe\deep\target.txt";
const PROBE_MARKER: &str = "lazy-ux-probe-marker";

/// 子が`FIRST`を出したあとに眠る時間。**これは計器の検算のためにある**——
/// 最初の1行が完走の直前にまとめて届いているなら、それは出力が溜められているのであって
/// 「最初の1行の時刻」を測れていない（§S21-0と同じく、測る前に計器を疑う）。
const PROBE_SLEEP: Duration = Duration::from_millis(1_500);
/// 上の眠りが**確かに観測できた**と言える下限。これを下回った標本は`ok=false`にする。
const STREAMING_PROOF: Duration = Duration::from_millis(1_200);

/// 1試行の上限。超えたら子を殺し、`ok=false`の標本として残す（測定全体は止めない）。
const TRIAL_TIMEOUT: Duration = Duration::from_secs(600);

const DEFAULT_REPEATS: usize = 20;
const DEFAULT_SYNTH_NODES: usize = 250_000;
const SYNTH_FANOUT: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum Arm {
    Lazy,
    FullWalk,
}

impl Arm {
    /// **腕の選択は製品と同じ分岐**（`preflight`が`lazy_grant::lane()`を読む）を通す。
    /// ここで環境変数を立て、直後に`lane()`が期待どおり答えることを確かめる——
    /// 確かめないと、両腕が同じ経路を通っていても気付けない（`B-08`）。
    fn arm_the_process(self) -> grant_job::PreparationLane {
        match self {
            Arm::Lazy => std::env::remove_var(lazy_grant::LAZY_LANE_ENV),
            Arm::FullWalk => std::env::set_var(lazy_grant::LAZY_LANE_ENV, "0"),
        }
        let lane = lazy_grant::lane();
        let expected = match self {
            Arm::Lazy => grant_job::PreparationLane::Lazy,
            Arm::FullWalk => grant_job::PreparationLane::FullWalk,
        };
        assert_eq!(
            lane, expected,
            "the {self:?} arm must actually select {expected:?}; if the redirector DLL is \
             missing next to the test binary, the lazy arm silently becomes a second full-walk arm"
        );
        lane
    }
}

/// 測ったツリーの構成。**数字と同じレポートへ入れる**（モジュールdoc）。
#[derive(Debug, Clone, serde::Serialize)]
struct TreeComposition {
    id: String,
    path: String,
    origin: String,
    nodes: usize,
    dirs: usize,
    files: usize,
    bytes: u64,
    max_depth: usize,
    /// 直下の内訳（`.git`が何割を占めるか等がここで見える。§S21の表と同じ読み方をする）。
    top_level: std::collections::BTreeMap<String, usize>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct Sample {
    tree: String,
    repetition: usize,
    order: usize,
    arm: Arm,
    /// 背景ジョブを起こすまで（**この時間は主条件に含めない**——製品では起動時に済んでいる）。
    preflight_ms: u128,
    /// `spawn_shell_in_workspace`が返るまで＝**待たされた時間そのもの**。
    spawn_ms: u128,
    /// **主条件**。spawn呼び出しから子の最初のstdout行まで。
    first_output_ms: Option<u128>,
    /// 総完了時間（§検証6は悪化を許容し記録だけ残すと定めている）。
    total_ms: Option<u128>,
    /// 背景の準備が完走するまで（記録のみ）。
    time_to_ready_ms: Option<u128>,
    /// 受付が開いていたか（`None`＝開いていない）と、割り込みが何件成立したか。
    broker_faults_served: Option<usize>,
    /// この試行がlazyレーンの受付を実際に掴んだか（腕の自己申告ではない証拠）。
    pipe_open: bool,
    exit_code: Option<i32>,
    ok: bool,
    note: Option<String>,
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.trim(), "1" | "true" | "on"))
        .unwrap_or(false)
}

/// このリポジトリの作業コピー（`t1`/`t2`の複製元）。
fn repo_root() -> PathBuf {
    if let Ok(explicit) = std::env::var("HARNESS_TEST_LAZY_UX_SOURCE") {
        return PathBuf::from(explicit);
    }
    // `crates/harness-sandbox` から2段上がる。
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate lives two levels below the repository root")
        .to_path_buf()
}

/// ツリーを数える。**バイト数と最大深さまで採る**——ノード数だけでは、同じ件数でも
/// 「大きく深い実物」と「小さく浅い合成」を取り違える（§S26がまさにその差を測っている）。
fn describe_tree(id: &str, root: &Path, origin: &str) -> TreeComposition {
    let mut dirs = 0usize;
    let mut files = 0usize;
    let mut bytes = 0u64;
    let mut max_depth = 0usize;
    let mut top_level: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    // 直下のどのエントリの配下かを持ったまま歩く（`.git`が何割かを数えるため）。
    let mut pending: Vec<(PathBuf, usize, Option<String>)> = vec![(root.to_path_buf(), 0, None)];
    while let Some((path, depth, bucket)) = pending.pop() {
        max_depth = max_depth.max(depth);
        if let Some(name) = bucket.as_ref() {
            *top_level.entry(name.clone()).or_insert(0) += 1;
        }
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            let child_bucket = match bucket.as_ref() {
                Some(name) => Some(name.clone()),
                None => Some(entry.file_name().to_string_lossy().to_string()),
            };
            if file_type.is_dir() {
                dirs += 1;
                pending.push((entry.path(), depth + 1, child_bucket));
            } else {
                files += 1;
                bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
                if let Some(name) = child_bucket {
                    *top_level.entry(name).or_insert(0) += 1;
                }
            }
        }
    }
    TreeComposition {
        id: id.to_string(),
        path: root.display().to_string(),
        origin: origin.to_string(),
        // rootそのものを1ノードとして数える（`build_wide_tree`の数え方と揃える）。
        nodes: 1 + dirs + files,
        dirs,
        files,
        bytes,
        max_depth,
        top_level,
    }
}

/// `robocopy`で複製する。**戻り値8以上が失敗**（0〜7は「コピーした／するものが無かった」等の
/// 正常系）で、そこを取り違えると壊れた複製の上で測ることになる。
fn robocopy(src: &Path, dst: &Path, exclude_dirs: &[&str]) {
    let mut cmd = std::process::Command::new("robocopy.exe");
    cmd.arg(src).arg(dst).arg("/E").arg("/NJH").arg("/NJS");
    cmd.arg("/NP")
        .arg("/NFL")
        .arg("/NDL")
        .arg("/R:1")
        .arg("/W:1");
    if !exclude_dirs.is_empty() {
        cmd.arg("/XD");
        for dir in exclude_dirs {
            cmd.arg(src.join(dir));
        }
    }
    let status = cmd.status().expect("run robocopy");
    let code = status.code().unwrap_or(-1);
    assert!(
        (0..8).contains(&code),
        "robocopy {} -> {} failed with code {code}",
        src.display(),
        dst.display()
    );
}

/// 測定用ツリーを用意する（**既にあれば作り直さない**——同じ形を測り続けるため）。
fn prepare_tree(id: &str, synth_nodes: usize) -> TreeComposition {
    let root = PathBuf::from(TREE_ROOT).join(format!("lazy-ux-{id}"));
    let probe = root.join(PROBE_REL);
    let origin;
    if !probe.exists() {
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create the measurement tree root");
        match id {
            "t1" => {
                robocopy(&repo_root(), &root, &["target"]);
                origin = format!("robocopy from {} excluding target/", repo_root().display());
            }
            "t2" => {
                robocopy(&repo_root(), &root, &["target", ".git"]);
                origin = format!(
                    "robocopy from {} excluding target/ and .git/",
                    repo_root().display()
                );
            }
            "t3" => {
                let nodes = build_wide_tree(&root, synth_nodes, SYNTH_FANOUT);
                origin = format!("synthetic build_wide_tree(fanout={SYNTH_FANOUT}, {nodes} nodes)");
            }
            other => panic!("unknown tree id {other} (expected t1/t2/t3)"),
        }
        std::fs::create_dir_all(probe.parent().expect("the probe has a parent"))
            .expect("create the probe directory");
        std::fs::write(&probe, PROBE_MARKER).expect("create the probe file");
    } else {
        origin = "reused (already present from an earlier run)".to_string();
    }
    // 走査の最後に来る側は**後から足せる**ようにしておく（既にあるツリーを作り直さずに済む）。
    let late = root.join(LATE_PROBE_REL);
    if !late.exists() {
        std::fs::create_dir_all(late.parent().expect("the late probe has a parent"))
            .expect("create the late probe directory");
        std::fs::write(&late, PROBE_MARKER).expect("create the late probe file");
    }
    describe_tree(id, &root, &origin)
}

/// 子へ流すスクリプト。**2つの対象を読んで即座に1行出し、眠ってから終わる。**
///
/// 読む順は「走査が最後に来る側 → 最初に来る側」である。前者が
/// **割り込みを起こす側**で、後者は「もう届いている側」の対照になる（[`LATE_PROBE_REL`]のdoc）。
/// 眠りは計器の検算用である（[`STREAMING_PROOF`]）。
fn probe_script(workspace: &Path) -> String {
    format!(
        r#"$ErrorActionPreference = 'Stop'
$late = Get-Content -Raw -LiteralPath '{late}'
$early = Get-Content -Raw -LiteralPath '{probe}'
if (($late -match '{marker}') -and ($early -match '{marker}')) {{ Write-Output 'FIRST-OK' }} else {{ Write-Output 'FIRST-NG' }}
[Console]::Out.Flush()
Start-Sleep -Milliseconds {sleep}
Write-Output 'DONE'
"#,
        late = workspace.join(LATE_PROBE_REL).display(),
        probe = workspace.join(PROBE_REL).display(),
        marker = PROBE_MARKER,
        sleep = PROBE_SLEEP.as_millis(),
    )
}

/// 1試行。**撤収して未準備へ戻す → `preflight` → 起動 → 最初の1行 → 完走 → 背景の完走 → 撤収**。
fn measure_once(tree: &TreeComposition, arm: Arm, repetition: usize, order: usize) -> Sample {
    let workspace = PathBuf::from(&tree.path);
    let canonical = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.clone());

    // 前の試行のACEと台帳を落として「未準備」に戻す。**ここが測定の前提そのもの**で、
    // 残っていると2回目の起動（背景ジョブが始まらない側）を測ることになる。
    cleanup_workspace(&canonical);
    arm.arm_the_process();

    let mut note: Option<String> = None;
    let mut ok = true;

    let preflight_started = Instant::now();
    let outcome = preflight(&workspace, &[], None, &WorkspaceWriteMode::DirectRw);
    let preflight_ms = preflight_started.elapsed().as_millis();
    if let Err(e) = &outcome {
        return Sample {
            tree: tree.id.clone(),
            repetition,
            order,
            arm,
            preflight_ms,
            spawn_ms: 0,
            first_output_ms: None,
            total_ms: None,
            time_to_ready_ms: None,
            broker_faults_served: None,
            pipe_open: false,
            exit_code: None,
            ok: false,
            note: Some(format!("preflight failed: {e:?}")),
        };
    }

    // **受付が開いているか**をspawnの直前に見る。これが腕の自己申告ではない証拠になる。
    let pipe_open = grant_job::lazy_broker_pipe_for(&canonical, "rwx").is_some();

    let t0 = Instant::now();
    let request = WorkspaceSpawn {
        image: WorkspaceImage::Shell,
        cwd: workspace.clone(),
        env: crate::secret_env::build_child_env(),
        workspace_root: workspace.clone(),
        cow_diff_layer_dir: None,
        granted_passthrough: Vec::new(),
        net_capability: NetworkCapability::Deny,
        policy_domain: harness_policy::policy_file::ENTRY_DOMAIN.to_string(),
    };
    let spawned = spawn_shell_in_workspace(request);
    let spawn_ms = t0.elapsed().as_millis();
    let Ok((child, _label)) = spawned else {
        let error = spawned.err().expect("the Err arm carries the error");
        return Sample {
            tree: tree.id.clone(),
            repetition,
            order,
            arm,
            preflight_ms,
            spawn_ms,
            first_output_ms: None,
            total_ms: None,
            time_to_ready_ms: None,
            broker_faults_served: grant_job::progress_for(&canonical, "rwx")
                .and_then(|p| p.broker_faults_served),
            pipe_open,
            exit_code: None,
            ok: false,
            note: Some(format!("spawn failed: {error:?}")),
        };
    };

    // **殺す口はストリーミングへ渡す前に取る**（`spawn_streaming`は子を消費する）。
    let kill = child.kill_token().expect("duplicate the child Job handle");
    let script = probe_script(&workspace);
    let mut rx = child.spawn_streaming(Some(script.as_bytes()));

    let mut first_output_ms = None;
    let mut total_ms = None;
    let mut exit_code = None;
    let mut stderr_tail = String::new();
    let deadline = Instant::now() + TRIAL_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            kill.kill();
            ok = false;
            note = Some(format!("trial exceeded {:?}", TRIAL_TIMEOUT));
            break;
        }
        match rx.blocking_recv() {
            Some(crate::win_common::OutputEvent::Stdout(line)) => {
                if first_output_ms.is_none() {
                    first_output_ms = Some(t0.elapsed().as_millis());
                }
                if line.contains("FIRST-NG") {
                    ok = false;
                    note = Some("the child could not read the probe file".to_string());
                }
            }
            Some(crate::win_common::OutputEvent::Stderr(line)) => {
                if stderr_tail.len() < 400 {
                    stderr_tail.push_str(line.trim());
                    stderr_tail.push(' ');
                }
            }
            Some(crate::win_common::OutputEvent::Exited(code)) => {
                total_ms = Some(t0.elapsed().as_millis());
                exit_code = Some(code);
                if code != 0 {
                    ok = false;
                    note = Some(format!("exit={code} stderr={}", stderr_tail.trim()));
                }
            }
            Some(crate::win_common::OutputEvent::OutputClosed) => {}
            None => break,
        }
    }

    if first_output_ms.is_none() {
        ok = false;
        note.get_or_insert_with(|| "the child produced no stdout at all".to_string());
    }
    // **計器の検算**: `FIRST`と完走の間には眠りがあるはずである。差がそれより小さいなら、
    // 出力が完走までまとめて届いている＝「最初の1行の時刻」を測れていない。
    if let (Some(first), Some(total)) = (first_output_ms, total_ms) {
        if total.saturating_sub(first) < STREAMING_PROOF.as_millis() {
            ok = false;
            note.get_or_insert_with(|| {
                format!("output looks buffered: first={first}ms total={total}ms")
            });
        }
    }

    // 背景の完走まで（記録のみ）。**この待ちは主条件の外**である。
    let ready = match grant_job::wait_for_workspace(&canonical, "rwx") {
        Ok(()) => Some(t0.elapsed().as_millis()),
        Err(e) => {
            ok = false;
            note.get_or_insert_with(|| format!("background preparation failed: {e}"));
            None
        }
    };
    let progress = grant_job::progress_for(&canonical, "rwx");

    Sample {
        tree: tree.id.clone(),
        repetition,
        order,
        arm,
        preflight_ms,
        spawn_ms,
        first_output_ms,
        total_ms,
        time_to_ready_ms: ready,
        broker_faults_served: progress.and_then(|p| p.broker_faults_served),
        pipe_open,
        exit_code,
        ok,
        note,
    }
}

/// 腕ごとの要約。**失敗した標本は時間の集計から外し、件数として別に出す**——
/// 混ぜると「速い失敗」が p95 を良く見せる。
fn summarise(samples: &[Sample], tree: &str, arm: Arm) -> serde_json::Value {
    let arm_samples: Vec<&Sample> = samples
        .iter()
        .filter(|s| s.tree == tree && s.arm == arm)
        .collect();
    let good: Vec<&&Sample> = arm_samples.iter().filter(|s| s.ok).collect();
    let metric = |value: fn(&Sample) -> Option<u128>| {
        let values: Vec<u128> = good.iter().filter_map(|s| value(s)).collect();
        if values.is_empty() {
            return serde_json::json!(null);
        }
        serde_json::json!({
            "n": values.len(),
            "min": values.iter().min(),
            "p50": percentile(values.clone(), 50),
            "p95": percentile(values.clone(), 95),
            "max": values.iter().max(),
        })
    };
    serde_json::json!({
        "trials": arm_samples.len(),
        "failures": arm_samples.len() - good.len(),
        "pipe_open": arm_samples.iter().filter(|s| s.pipe_open).count(),
        "receiver_absent": arm_samples
            .iter()
            .filter(|s| s.broker_faults_served.is_none())
            .count(),
        "zero_faults": arm_samples
            .iter()
            .filter(|s| s.broker_faults_served == Some(0))
            .count(),
        "faults_served_total": arm_samples
            .iter()
            .filter_map(|s| s.broker_faults_served)
            .sum::<usize>(),
        "first_output_ms": metric(|s| s.first_output_ms),
        "spawn_ms": metric(|s| Some(s.spawn_ms)),
        "total_ms": metric(|s| s.total_ms),
        "time_to_ready_ms": metric(|s| s.time_to_ready_ms),
    })
}

/// **first-command-outputのp95を、測ったツリーの構成と一緒に出す**（設計書§5.1.3の検証6）。
///
/// 判定はしない——`assert`で落とすのは「測れていない」ときだけである
/// （腕が同じ経路を通った・子が1行も出さなかった等）。**速い遅いの判断は人が読んで行う**。
#[test]
#[ignore = "spawns real AppContainer children and rewrites real ACLs many times; run NON-elevated with --test-threads=1"]
fn lazy_ux_latency_first_command_output() {
    let repeats = env_usize("HARNESS_TEST_LAZY_UX_REPEATS", DEFAULT_REPEATS);
    let synth_nodes = env_usize("HARNESS_TEST_LAZY_UX_SYNTH_NODES", DEFAULT_SYNTH_NODES);
    let keep = env_flag("HARNESS_TEST_LAZY_UX_KEEP");
    let wanted: Vec<String> = std::env::var("HARNESS_TEST_LAZY_UX_TREES")
        .unwrap_or_else(|_| "t1,t2,t3".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // DLLが隣に無ければlazy腕は黙って全walkになる。**測る前に落とす**（fail-closed）。
    assert!(
        matches!(lazy_grant::lane(), grant_job::PreparationLane::Lazy),
        "the lazy lane must be available before measuring; copy target/debug/harness_redirector.dll \
         (and the x86 build) into target/debug/deps/"
    );

    let seed = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos() as u64)
        ^ std::process::id() as u64;
    let mut random_state = seed.max(1);

    let trees: Vec<TreeComposition> = wanted
        .iter()
        .map(|id| prepare_tree(id, synth_nodes))
        .collect();
    for tree in &trees {
        eprintln!("[tree] {}", serde_json::to_string(tree).unwrap());
    }

    // **どう終わっても実マシンを戻す**（パニックしても撤収と削除が走る）。
    let cleanup_paths: Vec<PathBuf> = trees.iter().map(|t| PathBuf::from(&t.path)).collect();
    let _teardown = scopeguard(move || {
        for path in &cleanup_paths {
            let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
            cleanup_workspace(&canonical);
            if !keep {
                let _ = std::fs::remove_dir_all(path);
            }
        }
        std::env::remove_var(lazy_grant::LAZY_LANE_ENV);
    });

    let mut samples: Vec<Sample> = Vec::with_capacity(trees.len() * repeats * 2);
    for tree in &trees {
        for repetition in 0..repeats {
            let mut arms = [Arm::Lazy, Arm::FullWalk];
            shuffle_in_place(&mut arms, &mut random_state);
            for (order, arm) in arms.into_iter().enumerate() {
                let sample = measure_once(tree, arm, repetition, order);
                eprintln!("{}", serde_json::to_string(&sample).unwrap());
                samples.push(sample);
            }
        }
    }

    let summary: serde_json::Value = trees
        .iter()
        .map(|tree| {
            (
                tree.id.clone(),
                serde_json::json!({
                    "lazy": summarise(&samples, &tree.id, Arm::Lazy),
                    "full_walk": summarise(&samples, &tree.id, Arm::FullWalk),
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>()
        .into();
    let report = serde_json::json!({
        "measurement": "D-88 lazy lane UX: first-command-output (design §5.1.3 acceptance 6)",
        "seed": seed,
        "repeats_per_arm": repeats,
        "shell": resolve_shell().1,
        "trees": trees,
        "summary": summary,
        "samples": samples,
    });
    println!("{}", serde_json::to_string_pretty(&report).unwrap());

    // **測れていないときだけ落とす。** 速さの判定はしない（モジュールdoc）。
    for tree in &trees {
        let lazy_pipe_open = samples
            .iter()
            .filter(|s| s.tree == tree.id && s.arm == Arm::Lazy && s.pipe_open)
            .count();
        assert!(
            lazy_pipe_open > 0,
            "[{}] the lazy arm never got a fault receiver, so both arms measured the same thing",
            tree.id
        );
        let full_walk_pipe_open = samples
            .iter()
            .filter(|s| s.tree == tree.id && s.arm == Arm::FullWalk && s.pipe_open)
            .count();
        assert_eq!(
            full_walk_pipe_open, 0,
            "[{}] the full-walk arm must never open a receiver; it did, so the arms are mixed",
            tree.id
        );
        let measured = samples
            .iter()
            .filter(|s| s.tree == tree.id && s.ok && s.first_output_ms.is_some())
            .count();
        assert!(
            measured > 0,
            "[{}] no usable sample; see the notes in the samples above",
            tree.id
        );
    }
}
