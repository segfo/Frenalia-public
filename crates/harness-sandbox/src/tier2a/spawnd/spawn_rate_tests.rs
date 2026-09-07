//! **現実の並列ビルドは毎秒何本のプロセスを起こすか**を測る（`docs/STATUS.md`残課題#43、
//! 記録は`plans/mac-spike/RESULTS.md`）。
//!
//! # なぜこれが要るのか
//!
//! 段階⑤で生成禁止（`CHILD_PROCESS_RESTRICTED`）を積むと、サンドボックスの中の
//! **すべてのプロセス生成**がSpawn Daemonの要求受付パイプを通る。そこが1本しか受付を
//! 開いていないこと自体は測れる（`spawnd_load_tests`）が、**それが問題になるかどうかは
//! 「実際に毎秒何本来るのか」を知らないと決められない**。この測定は到着側の量を出す。
//!
//! # 数えにくさと、その避け方
//!
//! プロセス一覧を繰り返し撮るだけでは、**撮る合間に生まれて死んだものが消える**。
//! しかも消えたことは結果に出ない（数字が小さくなるだけで誰も気付かない）。
//!
//! そこで**2つの計器を同時に回す**。
//!
//! | 計器 | 何を出すか | 取りこぼし |
//! |---|---|---|
//! | Job Objectの累計（`JobObjectBasicAccountingInformation`の`TotalProcesses`） | 本数の正本 | **原理的に無い**（生き死にに関係なく増える累計） |
//! | プロセス一覧のポーリング（Toolhelp） | 誰が親か・いつ生まれたか | ある（短命なものを取り逃す） |
//!
//! **2つの差が、そのまま取りこぼし率である。** 差が大きければ、親の内訳は使わない。
//!
//! # Jobへの入れ方（**この測定プロセス自身を入れる**）
//!
//! 起こしてから入れる形にすると、その隙間に生まれた孫が数から漏れる（`docs/STATUS.md`残課題#41と
//! 同じ窓）。**自分をJobに入れてから起こす**と、子は自動でJobを継承するので窓が無い。
//!
//! **このJobには制限を一切付けない**——とくにkill-on-closeを付けてはいけない。付けると
//! 測定の終わりにハンドルを閉じた瞬間、**自分自身（テストプロセス）が殺される**。
//!
//! # 測っていないもの
//!
//! - **サンドボックスの中**では走らせていない。段階⑤では同じ生成が要求として飛ぶ、という
//!   前提を置いた外挿である
//! - **1要求＝1接続とは限らない**。頼む側が接続を持ち続けるなら、混雑を踏む回数は
//!   プロセス数ではなく**頼む側のプロセス数**で決まる（だから親の内訳を出している）

use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
    JobObjectBasicAccountingInformation, QueryInformationJobObject,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// ポーリング間隔。**Job側の累計は取りこぼさない**ので、この値が効くのは親の内訳だけである。
const POLL: Duration = Duration::from_millis(10);

/// 内側のビルドが使う`target`。**外側の`cargo test`が本体の`target`のロックを握っている**ので、
/// 同じ場所を使うと内側が待たされて測定にならない。
const SCRATCH_TARGET: &str = r"C:\harness-e2e\t1-target";

struct JobGuard(HANDLE);

impl Drop for JobGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// 制限を一切持たないJobを作り、**この測定プロセス自身を**入れる。
fn join_a_counting_job() -> JobGuard {
    unsafe {
        let job = CreateJobObjectW(None, windows::core::PCWSTR::null())
            .expect("計数用のJob Objectを作れなかった");
        AssignProcessToJobObject(job, GetCurrentProcess()).expect(
            "自分自身を計数用Jobへ入れられなかった。既に別のJobに居て入れ子が禁じられている\
             可能性がある（その場合この測定は成立しない）",
        );
        JobGuard(job)
    }
}

/// そのJobで**これまでに何個のプロセスが作られたか**（累計）と、**いま何個生きているか**。
fn job_counts(job: HANDLE) -> (u32, u32) {
    let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    unsafe {
        QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            &mut info as *mut _ as *mut _,
            std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            None,
        )
        .expect("Jobの累計を読めなかった");
    }
    (info.TotalProcesses, info.ActiveProcesses)
}

/// そのプロセスは計数用Jobの中に居るか、そして生成時刻はいつか。
///
/// # 親子の連鎖でたどらない理由（**1回踏んだ**）
///
/// 最初の版は「親PIDが既知の子孫集合に居れば子孫」という数え方だった。これは
/// **PIDの使い回しで壊れる**——死んだ子孫のPIDをWindowsが無関係なプロセスへ割り当てると、
/// その子まで数に入る。実際`cargo test --workspace`の回で、ポーリング側が正本（Jobの累計）より
/// **8.4%多く**数えて検算に引っ掛かった。
///
/// Jobは**プロセスが作られた瞬間から**メンバである（子は自動で継承する）ので、
/// 「Jobの中に居るか」を直接聞けば連鎖をたどる必要が無い。
fn inspect(pid: u32, job: HANDLE) -> Option<u64> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut in_job = windows::Win32::Foundation::BOOL(0);
        let member = IsProcessInJob(handle, job, &mut in_job).is_ok() && in_job.as_bool();
        if !member {
            let _ = CloseHandle(handle);
            return None;
        }
        let mut creation = Default::default();
        let mut exit = Default::default();
        let mut kernel = Default::default();
        let mut user = Default::default();
        let ok = GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user).is_ok();
        let _ = CloseHandle(handle);
        if !ok {
            return None;
        }
        // FILETIMEは1601-01-01からの100ナノ秒。UNIXエポックとの差を引いてミリ秒へ。
        let ticks = ((creation.dwHighDateTime as u64) << 32) | (creation.dwLowDateTime as u64);
        const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;
        ticks
            .checked_sub(EPOCH_DIFF_100NS)
            .map(|since_epoch| since_epoch / 10_000)
    }
}

/// いま生きている全プロセスの`(pid, 親pid, 実行ファイル名)`。
///
/// **名前まで持って帰る。** PIDだけの内訳は誰にも読めない——「上位2つの親が84%」と書いても、
/// その2つが何なのかが分からなければ、接続を持ち続ける形にできるかを判断できない。
fn snapshot_processes() -> Vec<(u32, u32, String)> {
    let mut out = Vec::new();
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return out;
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry
                        .szExeFile
                        .iter()
                        .position(|c| *c == 0)
                        .unwrap_or(entry.szExeFile.len())],
                );
                out.push((entry.th32ProcessID, entry.th32ParentProcessID, name));
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    out
}

/// 1回の測定の結果。
struct Observation {
    label: String,
    /// Jobの累計から出した本数（**正本**）。
    total_processes: u32,
    /// 同時に生きていた最大数。
    peak_active: u32,
    /// 実時間（秒）。
    seconds: f64,
    /// ポーリングで捕まえた子孫の数（正本より少ないのが普通）。
    observed: usize,
    /// 生成時刻が読めた子孫の、1秒窓の最大本数。
    peak_per_second: usize,
    /// 同、100ms窓の最大本数。
    peak_per_100ms: usize,
    /// 親ごとの生成数（PID・実行ファイル名・本数。多い順に数件だけ出す）。
    by_parent: Vec<(u32, String, usize)>,
    /// ビルドの終了コード。
    exit_code: Option<i32>,
}

fn peak_in_window(times_ms: &[u64], window_ms: u64) -> usize {
    if times_ms.is_empty() {
        return 0;
    }
    let mut sorted = times_ms.to_vec();
    sorted.sort_unstable();
    let mut best = 0usize;
    let mut left = 0usize;
    for right in 0..sorted.len() {
        while sorted[right] - sorted[left] >= window_ms {
            left += 1;
        }
        best = best.max(right - left + 1);
    }
    best
}

/// 1本のビルドを、Jobの累計とプロセス一覧のポーリングの両方で見ながら回す。
fn measure(label: &str, job: HANDLE, args: &[&str]) -> Observation {
    let (before_total, _) = job_counts(job);

    let mut command = std::process::Command::new("cargo");
    command
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("CARGO_TARGET_DIR", SCRATCH_TARGET)
        // **色や進捗の出力を切る。** 端末制御が挟まると、内側のcargoが余計な待ちに入ることがある。
        .env("CARGO_TERM_COLOR", "never")
        .env("CARGO_TERM_PROGRESS_WHEN", "never")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let started = Instant::now();
    let mut child = command.spawn().expect("cargoを起こせなかった");
    // **親の内訳を読むときの目印。** 上位に出てくるPIDがこれなら「cargo本体が全部起こしている」、
    // 別のPIDなら「起こしているのは孫（rustcやビルドスクリプト）」と読める。
    eprintln!("[spawn-rate] {label}: build root pid={}", child.id());

    // **一度見たPIDは二度調べない。** 調べ直すと、同じプロセスを何度も数える。
    // 自分自身と、この測定より前から居るものは対象外にする（Jobには自分も入っている）。
    let mut checked: HashSet<u32> = HashSet::new();
    checked.insert(std::process::id());
    let mut seen: BTreeMap<u32, u32> = BTreeMap::new();
    // 名前は**見えたときに控える**。親が先に死ぬと後から名前を引けない。
    let mut names: BTreeMap<u32, String> = BTreeMap::new();
    let mut births: Vec<u64> = Vec::new();
    let mut peak_active = 0u32;

    loop {
        for (pid, ppid, name) in snapshot_processes() {
            names.entry(pid).or_insert(name);
            if checked.insert(pid) {
                if let Some(ms) = inspect(pid, job) {
                    seen.insert(pid, ppid);
                    births.push(ms);
                }
            }
        }
        let (_, active) = job_counts(job);
        peak_active = peak_active.max(active);
        match child.try_wait().expect("try_wait") {
            Some(_) => break,
            None => std::thread::sleep(POLL),
        }
    }
    let status = child.wait().expect("wait");
    let seconds = started.elapsed().as_secs_f64();
    let (after_total, _) = job_counts(job);

    let mut counts: BTreeMap<u32, usize> = BTreeMap::new();
    for ppid in seen.values() {
        *counts.entry(*ppid).or_default() += 1;
    }
    let mut by_parent: Vec<(u32, String, usize)> = counts
        .into_iter()
        .map(|(pid, count)| {
            let name = names
                .get(&pid)
                .cloned()
                // **見えなかったことを「不明」と書く。** 空欄にすると、名前の無い親と
                // 名前を取り逃した親が同じ見た目になる（`P-11`）。
                .unwrap_or_else(|| "(取り逃した)".to_string());
            (pid, name, count)
        })
        .collect();
    by_parent.sort_by_key(|entry| std::cmp::Reverse(entry.2));
    by_parent.truncate(5);

    Observation {
        label: label.to_string(),
        // **自分自身は差し引かない**——`before`と`after`の差なので、この区間で
        // 新しく作られたぶんだけが残る。
        total_processes: after_total.saturating_sub(before_total),
        peak_active,
        seconds,
        observed: seen.len(),
        peak_per_second: peak_in_window(&births, 1_000),
        peak_per_100ms: peak_in_window(&births, 100),
        by_parent,
        exit_code: status.code(),
    }
}

fn report(o: &Observation) {
    let per_sec = if o.seconds > 0.0 {
        (o.total_processes as f64) / o.seconds
    } else {
        0.0
    };
    eprintln!(
        "[spawn-rate] {}: 生成数={} 実時間={:.1}s 平均={:.1}/s 1秒窓の最大={} 100ms窓の最大={} \
         同時最大={} 観測できた子孫={}（取りこぼし={:.1}%） exit={:?}",
        o.label,
        o.total_processes,
        o.seconds,
        per_sec,
        o.peak_per_second,
        o.peak_per_100ms,
        o.peak_active,
        o.observed,
        100.0 - percent(o.observed, o.total_processes as usize),
        o.exit_code
    );
    eprintln!("[spawn-rate] {}: 親ごとの生成数（上位）={:?}", o.label, o.by_parent);
}

fn percent(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        0.0
    } else {
        (part as f64) * 100.0 / (whole as f64)
    }
}

/// **測定**: 現実の並列ビルドが毎秒何本のプロセスを起こすか（3つの的）。
///
/// **昇格は要らない。** `KNOWN_TARGETS`にも入れない——入れると、昇格が要らないものを
/// 昇格側で回すことになる。撃ち方:
///
/// ```text
/// cargo test -p harness-sandbox --lib -- --ignored --nocapture --test-threads=1 \
///     spawnd::spawn_rate_tests
/// ```
#[test]
#[ignore = "runs real cargo builds (minutes); measurement only, no pass/fail"]
fn real_parallel_build_process_creation_rate() {
    let job = join_a_counting_job();
    eprintln!(
        "[spawn-rate] 論理CPU数={} scratch target={SCRATCH_TARGET}",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0)
    );

    // **cold**を最初に撃つ（スクラッチの`target`を空にしてから）。
    let _ = std::fs::remove_dir_all(SCRATCH_TARGET);
    let cold = measure("cold-build", job.0, &["build", "--workspace"]);
    report(&cold);

    // **incremental**: 1ファイルの更新時刻だけを進めて撃ち直す。
    let touched = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    let content = std::fs::read(&touched).expect("触る対象を読めなかった");
    std::fs::write(&touched, &content).expect("触る対象を書き戻せなかった");
    let incremental = measure("incremental-build", job.0, &["build", "--workspace"]);
    report(&incremental);

    // **test**: 同じスクラッチ`target`を使い回すので、ここはビルドより起動が主になる。
    // `--ignored`は付けない——付けると昇格が起きるものが混ざる。
    let tests = measure("cargo-test", job.0, &["test", "--workspace"]);
    report(&tests);

    for o in [&cold, &incremental, &tests] {
        assert!(
            o.total_processes > 0,
            "{}で1本もプロセスが作られなかった。Jobの計数が効いていない\
             （自分がJobへ入れていない／入れ子が禁じられている）",
            o.label
        );
    }
    // **検算**: ポーリング側は正本より多くなり得ない。多いなら、自分と無関係な
    // プロセスを子孫として拾っている（PIDの使い回し等）。
    for o in [&cold, &incremental, &tests] {
        assert!(
            o.observed <= o.total_processes as usize,
            "{}: ポーリングが正本より多く数えた（観測{} > 累計{}）。\
             無関係なプロセスを子孫と誤認している",
            o.label,
            o.observed,
            o.total_processes
        );
    }
}
