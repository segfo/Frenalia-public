//! **argv（コマンドライン）を観測できるかの実現性スパイク**
//! （`plans/PLAN-MAC-RECURSIVE-DESCENDANTS.md` 決定14・未解決#8）。
//!
//! MAC遷移ポリシーのargv軸は、遷移キーを`(遷移元ドメイン, exe, argv) → 遷移先ドメイン`へ
//! 拡張する。これが「ユーザーが手で辺を書く」以上のものになるかは、**観測側でargvを拾えるか**
//! だけに掛かっている——拾えなければステップ4（記録→再現→微調整のループ）が回らない。
//!
//! 本番の収集経路（マニフェスト系統の`Microsoft-Windows-Kernel-Process`）には
//! **コマンドラインのフィールドがどのバージョンにも無い**ことが読み取り専用の調査で確定した
//! （`Get-WinEvent -ListProvider`。全43イベントで0件）。取れる可能性があるのは
//! Classic ETW（MOF）の`Process_V4_TypeGroup1`だけで、こちらは`CommandLine`を持つ。
//! **本ファイルはそれが実機で実際に届くかを測る。**
//!
//! # 何を切り分けるのか（§18.5・§21.4の規律）
//!
//! 「取れなかった」には3つの別の意味がある。全部を区別できる形で出す。
//!
//! 1. **測定が壊れている**（セッションにイベントが1件も来ていない）→ 正の対照
//!    （このテスト自身が起こす`cmd.exe`）で切る
//! 2. **フィールドを持たない版が届いた**（`Process_V2`未満）→ `version`を必ず印字する
//! 3. **フィールドはあるが空**→ `CommandLine`が`None`だった件数を数えて出す
//!
//! さらに**同じプロセスを両系統で同時に観測する**——別々に走らせると「プロセスが動かなかった」と
//! 「フィールドが無い」を区別できない。
//!
//! 実行（要管理者権限。ETWリアルタイムセッション＋private system logger）:
//! ```text
//! dev-elevated-run.exe spike-etw-argv
//! ```
//!
//! 使い捨てスパイクの位置付け（`docs/CODE-STRUCTURE-RULES.md`規則2）——結論が出たら
//! このファイルは削除し、実測値は`plans/etw-spike/RESULTS.md` §22（測定の正本）へ残す。

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use super::mof::{MofFsSession, MofProcessStart};
use super::session::EtwFsSession;

/// 測定M1で使う、`cmd.exe`が起こす短命プロセスの1バッチ分の本数。
const SHORT_LIVED_BATCH: usize = 600;
/// 同・PID再利用を狙って回す時間の上限（超えたら「観測されなかった」と書いて打ち切る）。
const REUSE_HUNT_BUDGET: Duration = Duration::from_secs(120);

/// セッションを張ってから配送が始まるまでの待ち（既存スパイクの実測値と同じ）。
const WARMUP: Duration = Duration::from_millis(1500);
/// 対象コマンド終了後、バッファ内のイベントが配送され切るまでの待ち（同上）。
const DRAIN: Duration = Duration::from_secs(4);

/// 観測したプロセス生成イベントの要約。**`None`の件数とバージョン分布を必ず含める**
/// ——「取れなかった」の3つの意味を読む側が切り分けられるようにするため（モジュールdoc）。
fn summarize(starts: &[MofProcessStart]) -> String {
    let mut by_event_type: BTreeMap<u8, u64> = BTreeMap::new();
    let mut by_version: BTreeMap<u8, u64> = BTreeMap::new();
    let mut with_command_line = 0u64;
    let mut with_package = 0u64;
    for start in starts {
        *by_event_type.entry(start.event_type).or_insert(0) += 1;
        *by_version.entry(start.version).or_insert(0) += 1;
        if start.command_line.is_some() {
            with_command_line += 1;
        }
        if start.package_full_name.is_some() {
            with_package += 1;
        }
    }
    format!(
        "{} process-start event(s); by EventType(1=Start,3=DCStart) {by_event_type:?}; \
         by Version {by_version:?}; with CommandLine {with_command_line}; \
         without CommandLine {}; with PackageFullName {with_package}",
        starts.len(),
        starts.len() as u64 - with_command_line,
    )
}

/// 1件を人が読める形で出す。**`{:?}`で出す**——引用符・バックスラッシュ・`\??\`のような
/// 綴りがそのまま見えないと、決定14(c)の正規化要件を決められない。
fn dump(tag: &str, start: &MofProcessStart) {
    println!(
        "[{tag}] EventType={} Version={} pid={:?} parent={:?} session={:?} key={:?}\n\
         [{tag}]   ImageFileName   = {:?}\n\
         [{tag}]   CommandLine     = {:?}\n\
         [{tag}]   PackageFullName = {:?}",
        start.event_type,
        start.version,
        start.pid,
        start.parent_pid,
        start.session_id,
        start.unique_process_key,
        start.image_file_name,
        start.command_line,
        start.package_full_name,
    );
}

fn pids(starts: &[MofProcessStart]) -> BTreeSet<u32> {
    starts.iter().filter_map(|s| s.pid).collect()
}

fn find_marker<'a>(starts: &'a [MofProcessStart], marker: &str) -> Option<&'a MofProcessStart> {
    starts
        .iter()
        .find(|s| s.command_line.as_deref().is_some_and(|c| c.contains(marker)))
}

/// **本命**: MOF（Classic ETW）の`Process`イベントが`CommandLine`を運ぶか。
/// 運ぶなら、どんな綴りで・どこまで（長いコマンドライン・Tier1の孫まで）運ぶか。
///
/// 同時にマニフェスト系統のセッションも張り、**同じpid**を両方が観測していることを確かめる
/// ——これが無いと「フィールドが無い」と「プロセスを見ていない」を区別できない。
#[cfg(windows)]
#[test]
#[ignore = "requires administrator rights (two ETW sessions); run via dev-elevated-run.exe spike-etw-argv"]
fn mof_process_events_carry_the_command_line_that_manifest_events_lack() {
    use crate::tier1::win_restricted;

    let pid = std::process::id();
    let marker_plain = format!("argvspike-plain-{pid}");
    let marker_long = format!("argvspike-long-{pid}");
    let marker_tier1 = format!("argvspike-tier1-{pid}");

    // cwd相対の引数と空白入りパス（決定14(c)の正規化要件を決めるための材料）。
    let base = tempfile::tempdir().expect("tempdir");
    let cwd = base.path().to_path_buf();
    win_restricted::set_low_integrity_label(&cwd).expect("set low IL label on cwd");
    let spaced = cwd.join("dir with space");
    std::fs::create_dir_all(&spaced).expect("create the spaced dir");
    let rel_leaf = "rel probe.txt";
    std::fs::write(spaced.join(rel_leaf), b"relative-probe").expect("write the relative probe");

    let manifest =
        EtwFsSession::start("harness-argv-spike-manifest").expect("manifest ETW session");
    assert!(
        manifest.kernel_process_enabled(),
        "the manifest session must have Kernel-Process enabled, otherwise the comparison is vacuous"
    );
    let mof = MofFsSession::start_process_only("harness-argv-spike-mof")
        .expect("private system logger (Classic ETW / MOF), PROCESS flag only");
    // 対象を起こす前に配送が始まるのを待つ（省くとProcessStartごと取りこぼす。実測済み）。
    std::thread::sleep(WARMUP);

    // (1) 正の対照。ここが取れなければ結論は「載らない」ではなく「測定が壊れている」。
    let mut plain = std::process::Command::new("cmd.exe")
        .args(["/c", "echo", &marker_plain])
        .spawn()
        .expect("spawn the plain probe");
    let plain_pid = plain.id();
    let _ = plain.wait();

    // (2) 長いコマンドライン。**黙って切り詰められるか**を見る（argvがドメインの選択子に
    //     なる以上、切り詰めは詐称に直結する）。マーカーは末尾に置く。
    let padding = "x".repeat(4000);
    let long_argument = format!("{padding}{marker_long}");
    let mut long = std::process::Command::new("cmd.exe")
        .args(["/c", "echo", &long_argument])
        .spawn()
        .expect("spawn the long-command-line probe");
    let long_pid = long.id();
    let _ = long.wait();
    // 起動側が組み立てた綴りを控えておく（ETWが返す綴りとの差が正規化要件になる）。
    let long_expected_tail_len = long_argument.len();

    // (3) cwd相対の引数＋空白入りパス。
    let mut relative = std::process::Command::new("cmd.exe")
        .args(["/c", "type", rel_leaf])
        .current_dir(&spaced)
        .spawn()
        .expect("spawn the relative-argument probe");
    let relative_pid = relative.id();
    let _ = relative.wait();

    // (4) Tier1連鎖（制限トークン＋低IL）。gen1=powershell.exe / gen2=cmd.exe。
    //     サンドボックス下の子・孫でもコマンドラインが載るかを見る。
    let env = crate::secret_env::build_child_env();
    let command = format!("& cmd.exe /c echo {marker_tier1}");
    let child = win_restricted::spawn(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", &command],
        &cwd,
        &env,
        false,
    )
    .expect("spawn the Tier1 powershell");
    let (out, err, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("wait for the Tier1 chain");
    println!("[tier1] exit={code} out={out:?} err={err:?}");

    std::thread::sleep(DRAIN);
    let mof_outcome = mof.stop();
    let manifest_outcome = manifest.stop();

    let starts = &mof_outcome.process_starts;
    println!(
        "=== MOF (Process class): {} raw event(s), {} dropped by capacity ===",
        mof_outcome.process_events, mof_outcome.process_dropped
    );
    println!("=== MOF summary: {} ===", summarize(starts));
    println!(
        "=== manifest (Kernel-Process): {} ProcessStart, {} events lost, {} rt buffers lost ===",
        manifest_outcome.process_starts.len(),
        manifest_outcome.events_lost,
        manifest_outcome.realtime_buffers_lost
    );

    // --- 4つのプローブそれぞれについて、MOF側で何が見えたか ---
    for (tag, marker) in [
        ("plain", &marker_plain),
        ("long", &marker_long),
        ("tier1-gen2", &marker_tier1),
    ] {
        match find_marker(starts, marker) {
            Some(hit) => dump(tag, hit),
            None => println!("[{tag}] NOT FOUND in any CommandLine (marker {marker})"),
        }
    }
    // 相対引数のプローブはpidで引く（マーカー文字列を持たないため）。
    for start in starts.iter().filter(|s| s.pid == Some(relative_pid)) {
        dump("relative", start);
    }
    // Tier1のgen1（powershell自身）も出す——孫まで届くかが本題なので対で見る。
    for start in starts
        .iter()
        .filter(|s| s.command_line.as_deref().is_some_and(|c| c.contains("argvspike")))
    {
        println!(
            "[chain] pid={:?} parent={:?} image={:?}",
            start.pid, start.parent_pid, start.image_file_name
        );
    }

    // --- 切り詰めの有無 ---
    //
    // **マーカーで探すだけでは足りない**——「イベントが来ていない」と「来たが切り詰められた」を
    // 区別できない（モジュールdocの3分類）。pidで引き当ててから長さを見る。
    let long_events: Vec<&MofProcessStart> =
        starts.iter().filter(|s| s.pid == Some(long_pid)).collect();
    if long_events.is_empty() {
        println!(
            "[long] NO process-start event for pid {long_pid} at all -- the event was lost, \
             not truncated"
        );
    }
    for hit in &long_events {
        let observed = hit.command_line.as_deref().unwrap_or("");
        let observed_len = observed.chars().count();
        let tail: String = observed
            .chars()
            .skip(observed_len.saturating_sub(40))
            .collect();
        println!(
            "[long] pid={long_pid}: the launched argument alone was {long_expected_tail_len} chars; \
             observed CommandLine is {observed_len} chars; contains the tail marker = {}; \
             last 40 chars = {tail:?}",
            observed.contains(&marker_long),
        );
    }

    // --- 両系統が同じpidを見ていること（測定の成立条件） ---
    let mof_pids = pids(starts);
    let manifest_pids: BTreeSet<u32> = manifest_outcome
        .process_starts
        .iter()
        .map(|s| s.pid)
        .collect();
    println!(
        "[pairing] plain probe pid={plain_pid} long={long_pid} relative={relative_pid}; \
         seen by MOF: {} / by manifest: {}",
        mof_pids.contains(&plain_pid),
        manifest_pids.contains(&plain_pid)
    );
    for info in manifest_outcome
        .process_starts
        .iter()
        .filter(|s| s.pid == plain_pid)
    {
        println!(
            "[pairing] manifest ProcessStartInfo for the same pid: image={:?} package={:?} seq={:?} \
             (this struct has no command-line field at all)",
            info.image_name, info.package_full_name, info.process_sequence_number
        );
    }

    assert!(
        mof_pids.contains(&plain_pid) && manifest_pids.contains(&plain_pid),
        "both sessions must have observed the plain probe (pid {plain_pid}); \
         MOF={} manifest={} -- without this, a missing CommandLine cannot be distinguished \
         from a missing process. {}",
        mof_pids.contains(&plain_pid),
        manifest_pids.contains(&plain_pid),
        summarize(starts)
    );
    assert!(
        find_marker(starts, &marker_plain).is_some(),
        "the positive control's command line ({marker_plain}) was not observed. \
         If the summary shows Version < 2, the delivered event class has no CommandLine field; \
         if it shows 0 events, the session never received anything. {}",
        summarize(starts)
    );
    assert!(
        find_marker(starts, &marker_tier1).is_some(),
        "the Tier1 grandchild's command line ({marker_tier1}) was not observed -- argv candidates \
         cannot be generated for sandboxed chains, which is what the policy editor's path 1 needs. {}",
        summarize(starts)
    );
}

/// **測定M1**: MOF側の`UniqueProcessKey`とマニフェスト側の`ProcessSequenceNumber`を、
/// **PID再利用に耐える形で**突き合わせられるか
/// （`plans/PLAN-MAC-ARGV-MEASUREMENTS.md` M1、未解決#1・#5の前提）。
///
/// 分かっているのは「同じ値ではない」ことだけである——[`super::mof::MofProcessStart`]の
/// docは`unique_process_key`を`ProcessSequenceNumber`に**「相当する役割を持つ」**と書いており、
/// *相当する*であって*等しい*ではない。
///
/// # マニフェスト側に[`EtwFsSession`]を使わない理由
///
/// [`super::session::ProviderProbeSession`]は**イベントのタイムスタンプ**を持つ
/// （[`super::session::ProcessStartInfo`]は持たない）。突合が同値で閉じない場合、次の候補は
/// 「pid＋開始時刻の窓」であり、**窓幅を実測するには両側の時刻が要る**。本番構造体へ
/// 時刻を足すと構築点7箇所へ波及するので、測定側でだけ時刻を持てるこちらを使う。
/// セッションの種類（通常のリアルタイムセッション）は`EtwFsSession`と同じである。
///
/// # 何を「再利用に耐える」と見るか
///
/// PID再利用は狙って起こせない（Windowsのpid空間を一周させる必要がある）ので、
/// **起きなかったら起きなかったと書く**。代わりに、この測定では**もっと起きやすい方の危険**を
/// 数える——`UniqueProcessKey`の実体はEPROCESSのポインタであり、**短命プロセスを大量に起こすと
/// 解放されたEPROCESSが再利用される**。同じ鍵が別インスタンスへ付き回るなら、鍵単独では
/// 同一性の根拠にならない。
#[cfg(windows)]
#[test]
#[ignore = "requires administrator rights (two ETW sessions); run via dev-elevated-run.exe spike-etw-argv"]
fn the_two_sessions_correlation_keys_side_by_side() {
    use super::mof::{EVENT_TYPE_PROCESS_DC_START, EVENT_TYPE_PROCESS_START};
    use super::session::{
        ProviderProbeSession, EVENT_ID_PROCESS_START, KERNEL_PROCESS_KEYWORD_PROCESS,
        KERNEL_PROCESS_PROVIDER_GUID,
    };

    let marker = format!("argvspike-corr-{}", std::process::id());

    let manifest = ProviderProbeSession::start(
        "harness-argv-spike-corr-manifest",
        KERNEL_PROCESS_PROVIDER_GUID,
        KERNEL_PROCESS_KEYWORD_PROCESS,
        &[EVENT_ID_PROCESS_START],
        &["ImageName"],
        // **`ProbedEvent.process_id`は使わない**——あれはETWヘッダのpid＝**生成した側**であって、
        // 生まれたプロセスのpidではない（本番の`session.rs`も`ProcessID`プロパティから引いている）。
        &["ProcessID", "ParentProcessID", "ProcessSequenceNumber"],
    )
    .expect("manifest (Kernel-Process) probe session");
    let mof = MofFsSession::start_process_only("harness-argv-spike-corr-mof")
        .expect("private system logger (Classic ETW / MOF), PROCESS flag only");
    std::thread::sleep(WARMUP);

    // (1) 正の対照。両セッションがこれを見ていなければ、結論は「別値」ではなく「測定が壊れている」。
    let mut control = std::process::Command::new("cmd.exe")
        .args(["/c", "echo", &marker])
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn the correlation control probe");
    let control_pid = control.id();
    let _ = control.wait();

    // (2) 短命プロセスを大量に起こす。狙いは2つ——pidの再利用（起きるかは運）と、
    //     EPROCESSの再利用（こちらはほぼ確実に起きる）。
    let hunt_started = std::time::Instant::now();
    let mut launched: Vec<u32> = Vec::new();
    let mut rounds = 0usize;
    loop {
        rounds += 1;
        for _ in 0..SHORT_LIVED_BATCH {
            match std::process::Command::new("cmd.exe")
                .args(["/c", "exit"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                Ok(mut child) => {
                    launched.push(child.id());
                    let _ = child.wait();
                }
                Err(error) => println!("[corr] spawn failed (continuing): {error}"),
            }
        }
        // **起動側の台帳で再利用を判定する**（観測側ではなく自分が知っている事実）。
        let distinct: BTreeSet<u32> = launched.iter().copied().collect();
        let launcher_side_reuse = distinct.len() < launched.len();
        if launcher_side_reuse || hunt_started.elapsed() >= REUSE_HUNT_BUDGET || rounds >= 2 {
            println!(
                "[corr] launched {} short-lived process(es) in {} round(s), {:?}; \
                 launcher-side pid reuse observed = {launcher_side_reuse}",
                launched.len(),
                rounds,
                hunt_started.elapsed(),
            );
            break;
        }
    }

    std::thread::sleep(DRAIN);
    let mof_outcome = mof.stop();
    let manifest_outcome = manifest.stop();

    // --- 生の観測量（「1件も来ていない」と「来たが埋まっていない」を切り分ける） ---
    let all_starts = &mof_outcome.process_starts;
    let live: Vec<&MofProcessStart> = all_starts
        .iter()
        .filter(|s| s.event_type == EVENT_TYPE_PROCESS_START)
        .collect();
    let rundown = all_starts
        .iter()
        .filter(|s| s.event_type == EVENT_TYPE_PROCESS_DC_START)
        .count();
    println!(
        "=== MOF: {} raw Process-class event(s), {} captured, {} dropped; \
         EventType=1 (live start) {} / EventType=3 (rundown) {} ===",
        mof_outcome.process_events,
        all_starts.len(),
        mof_outcome.process_dropped,
        live.len(),
        rundown,
    );
    println!(
        "=== manifest: {} ProcessStart captured, {} event(s) reached the session, \
         {} dropped, {} lost ===",
        manifest_outcome.events.len(),
        manifest_outcome.seen_events,
        manifest_outcome.dropped,
        manifest_outcome.events_lost,
    );
    println!(
        "-> rundown (EventType=3) has no counterpart on the manifest side, so only EventType=1 \
         can be joined; this asymmetry is itself an input to unresolved #5"
    );

    // --- 両側をpidで索引する ---
    let mut mof_by_pid: BTreeMap<u32, Vec<&MofProcessStart>> = BTreeMap::new();
    for start in &live {
        if let Some(pid) = start.pid {
            mof_by_pid.entry(pid).or_default().push(start);
        }
    }
    let mut manifest_by_pid: BTreeMap<u32, Vec<(u64, u64)>> = BTreeMap::new(); // pid -> (seq, ts)
    let mut manifest_missing_seq = 0u64;
    for event in &manifest_outcome.events {
        let Some(pid) = event.numbers.get("ProcessID").map(|v| *v as u32) else {
            continue;
        };
        match event.numbers.get("ProcessSequenceNumber") {
            Some(seq) => manifest_by_pid
                .entry(pid)
                .or_default()
                .push((*seq, event.timestamp_unix_ms)),
            None => manifest_missing_seq += 1,
        }
    }

    // --- 突合の歩留まり（#5の分配規則に直接効く） ---
    let mof_pids: BTreeSet<u32> = mof_by_pid.keys().copied().collect();
    let manifest_pids: BTreeSet<u32> = manifest_by_pid.keys().copied().collect();
    let both: Vec<u32> = mof_pids.intersection(&manifest_pids).copied().collect();
    println!(
        "[join] pids seen by both = {} | MOF only = {} | manifest only = {} \
         (join yield vs MOF = {:.1}%)",
        both.len(),
        mof_pids.difference(&manifest_pids).count(),
        manifest_pids.difference(&mof_pids).count(),
        100.0 * both.len() as f64 / mof_pids.len().max(1) as f64,
    );

    // --- 突合表（先頭30件）と Δt の分布 ---
    println!("pid | UniqueProcessKey (MOF) | ProcessSequenceNumber (manifest) | dt(ms)");
    let mut deltas: Vec<i64> = Vec::new();
    let mut equal_pairs = 0u64;
    let mut shown = 0usize;
    for pid in &both {
        let mof_events = &mof_by_pid[pid];
        let manifest_events = &manifest_by_pid[pid];
        // **1対1で対応する場合だけ**を突合の対象にする（両側に複数あると、どれとどれが
        // 同じインスタンスかは pid だけでは決められない——それがこの測定の問いそのもの）。
        if mof_events.len() != 1 || manifest_events.len() != 1 {
            continue;
        }
        let key = mof_events[0].unique_process_key;
        let (seq, manifest_ts) = manifest_events[0];
        if key == Some(seq) {
            equal_pairs += 1;
        }
        deltas.push(manifest_ts as i64 - mof_events[0].timestamp_unix_ms as i64);
        if shown < 30 {
            println!(
                "{pid:>6} | {:>18} | {seq:>18} | {:>6}",
                key.map(|k| format!("{k:#018x}"))
                    .unwrap_or_else(|| "(none)".into()),
                manifest_ts as i64 - mof_events[0].timestamp_unix_ms as i64,
            );
            shown += 1;
        }
    }
    deltas.sort_unstable();
    println!(
        "[relation] 1:1 pairs = {} | key == seq for {equal_pairs} of them",
        deltas.len()
    );
    if !deltas.is_empty() {
        println!(
            "[window] dt(manifest - MOF) in ms: min={} p50={} max={} \
             (this is the window width if the join has to fall back to pid + start time)",
            deltas[0],
            deltas[deltas.len() / 2],
            deltas[deltas.len() - 1],
        );
    }

    // --- 単調性（別系列かどうか） ---
    let mut manifest_seq_sorted: Vec<(u64, u64)> = manifest_by_pid
        .values()
        .flatten()
        .map(|(seq, ts)| (*ts, *seq))
        .collect();
    manifest_seq_sorted.sort_unstable();
    let seq_monotonic = manifest_seq_sorted.windows(2).all(|w| w[0].1 <= w[1].1);
    let mut mof_key_sorted: Vec<(u64, u64)> = live
        .iter()
        .filter_map(|s| s.unique_process_key.map(|k| (s.timestamp_unix_ms, k)))
        .collect();
    mof_key_sorted.sort_unstable();
    let key_monotonic = mof_key_sorted.windows(2).all(|w| w[0].1 <= w[1].1);
    println!(
        "[monotonic] ProcessSequenceNumber increases with time = {seq_monotonic}; \
         UniqueProcessKey increases with time = {key_monotonic}"
    );
    if let (Some(first), Some(last)) = (manifest_seq_sorted.first(), manifest_seq_sorted.last()) {
        println!(
            "[monotonic] seq range {} .. {} over {} start(s)",
            first.1,
            last.1,
            manifest_seq_sorted.len()
        );
    }

    // --- 一意性: 別インスタンスへ同じ鍵が付き回るか（EPROCESS再利用） ---
    let keys: Vec<u64> = live.iter().filter_map(|s| s.unique_process_key).collect();
    let distinct_keys: BTreeSet<u64> = keys.iter().copied().collect();
    let seqs: Vec<u64> = manifest_by_pid
        .values()
        .flatten()
        .map(|(seq, _)| *seq)
        .collect();
    let distinct_seqs: BTreeSet<u64> = seqs.iter().copied().collect();
    println!(
        "[unique] UniqueProcessKey: {} distinct / {} live starts | \
         ProcessSequenceNumber: {} distinct / {} starts",
        distinct_keys.len(),
        keys.len(),
        distinct_seqs.len(),
        seqs.len(),
    );
    // 同じ鍵が**別のpid**へ付いた例を数える＝鍵単独では同一性の根拠にならない証拠。
    let mut key_to_pids: BTreeMap<u64, BTreeSet<u32>> = BTreeMap::new();
    for start in &live {
        if let (Some(key), Some(pid)) = (start.unique_process_key, start.pid) {
            key_to_pids.entry(key).or_default().insert(pid);
        }
    }
    let shared: Vec<(&u64, &BTreeSet<u32>)> = key_to_pids
        .iter()
        .filter(|(_, pids)| pids.len() > 1)
        .collect();
    println!(
        "[unique] keys that appeared for MORE THAN ONE pid: {} (EPROCESS reuse)",
        shared.len()
    );
    for (key, pids) in shared.iter().take(5) {
        println!("[unique]   key {key:#018x} -> pids {pids:?}");
    }

    // --- PID再利用（観測側） ---
    let reused: Vec<(&u32, &Vec<&MofProcessStart>)> = mof_by_pid
        .iter()
        .filter(|(_, starts)| starts.len() > 1)
        .collect();
    println!(
        "[reuse] pids with 2+ live starts in this trace: {} (0 means PID reuse was NOT exercised \
         -- record it as untested rather than as evidence)",
        reused.len()
    );
    for (pid, starts) in reused.iter().take(5) {
        let keys: Vec<String> = starts
            .iter()
            .map(|s| {
                s.unique_process_key
                    .map(|k| format!("{k:#018x}"))
                    .unwrap_or_else(|| "(none)".into())
            })
            .collect();
        let seqs: Vec<u64> = manifest_by_pid
            .get(pid)
            .map(|v| v.iter().map(|(seq, _)| *seq).collect())
            .unwrap_or_default();
        println!("[reuse]   pid {pid}: keys {keys:?} / seqs {seqs:?}");
    }

    // ---------------- 歯（測定が成立していること） ----------------
    assert!(
        mof_by_pid.contains_key(&control_pid) && manifest_by_pid.contains_key(&control_pid),
        "the positive control (pid {control_pid}, {marker}) was not observed by both sessions \
         (MOF={} manifest={}) -- without it, 'the two keys differ' cannot be distinguished from \
         'one session saw nothing'",
        mof_by_pid.contains_key(&control_pid),
        manifest_by_pid.contains_key(&control_pid),
    );
    assert_eq!(
        manifest_missing_seq, 0,
        "{manifest_missing_seq} manifest ProcessStart event(s) carried no ProcessSequenceNumber; \
         on such an OS the manifest side cannot identify instances at all and the join has to be \
         designed differently"
    );
    let mof_missing_key = live
        .iter()
        .filter(|s| s.unique_process_key.is_none())
        .count();
    assert_eq!(
        mof_missing_key, 0,
        "{mof_missing_key} MOF live-start event(s) carried no UniqueProcessKey"
    );
}

/// **切り詰めの境界を確定する。**
///
/// 4,020文字の1点だけを測って「1024文字で頭打ち」と外挿するのは根拠が足りない
/// （§21.4の「門がどこにあるかを先に確かめる」）。長さを掃引して、
///
/// 1. 上限は**ちょうど1024**か（1023/1024/1025の前後で何が起きるか）
/// 2. 単位は**文字数**か（UTF-16単位＝この掃引はASCIIなので文字数と一致する）
/// 3. **切り詰めを示すフラグがあるか**（`Flags`フィールド。あれば「無言」ではない）
///
/// を確定する。**短い側（切り詰まらないはずの長さ）を必ず混ぜる**——全部が1024になったら、
/// それは切り詰めではなく測定側の欠陥（TDHの読み取り上限等）を疑う合図になる。
/// # 測定M5: 1024の単位はUTF-16単位か文字数か
///
/// §22.3.1は「単位は**UTF-16単位**（読み出しがUTF-16単位で、掃引はASCIIのみ——サロゲートペアを
/// 含む場合に『文字数』と分かれるかは**未測定**）」と明記して残した。決定16(6)は
/// 「観測が1024ちょうどならリテラル辺を作らない」という判定なので、**1024が何の単位かで
/// 判定式が変わる**。ASCIIの掃引を**同じ実行の中に残したまま**（対照）、サロゲートペアだけで
/// 構成した引数を足す。
///
/// 併せて仮説を1つ試す——**切り詰めがサロゲートペアの途中で起きたら、末尾にlone surrogateが
/// 残るはずである**。残るならそれは切り詰めの**検出可能な痕跡**になる。§22.3.1は「`Flags`に
/// 印が無い＝切り詰めは検出できない」と結論したが、それは印が**無い**ことの証明であって、
/// **痕跡が無い**ことの証明ではない。
#[cfg(windows)]
#[test]
#[ignore = "requires administrator rights (ETW system logger); run via dev-elevated-run.exe spike-etw-argv"]
fn where_exactly_is_the_command_line_truncated() {
    /// Rustの`Command`が組み立てる綴りは `"cmd.exe" /c echo <arg>`。前置部分は18 UTF-16単位
    /// （全てASCII）。この前提はASCII側の64単位プローブが逐語一致することで毎回検算される。
    const PREFIX: usize = r#""cmd.exe" /c echo "#.len();
    /// `𠮷`(U+20BB7)。**1文字＝2 UTF-16単位**。単位仮説と文字数仮説を分ける唯一の材料。
    const PAIR: char = '𠮷';
    /// §22.3.1で確定した上限。
    const CAP: usize = 1024;

    struct Probe {
        label: String,
        /// 起動したコマンドライン全体のUTF-16単位数。
        units: usize,
        /// 同・文字数（ASCIIプローブでは`units`と一致する）。
        chars: usize,
        pid: u32,
    }

    let mof = MofFsSession::start_process_only("harness-argv-spike-boundary")
        .expect("private system logger (Classic ETW / MOF), PROCESS flag only");
    std::thread::sleep(WARMUP);

    let launch = |label: String, arg: String| -> Probe {
        let units = PREFIX + arg.encode_utf16().count();
        let chars = PREFIX + arg.chars().count();
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/c", "echo", &arg])
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn the boundary probe");
        let pid = child.id();
        let _ = child.wait();
        Probe {
            label,
            units,
            chars,
            pid,
        }
    };

    let mut probes: Vec<Probe> = Vec::new();

    // (1) ASCII掃引（§22.3.1の再現＝対照）。短い側を必ず含める。
    for total in [64usize, 512, 1023, 1024, 1025, 1100, 2048] {
        probes.push(launch(
            format!("ascii-{total}"),
            "x".repeat(total - PREFIX),
        ));
    }

    // (2) **決定打**: 上限を大きく超える長さをサロゲートペアだけで作る。
    //     単位仮説なら観測は1024単位、文字数仮説なら観測は1024**文字**＝2030単位になる。
    //     予言が2つに割れるので、どちらが当たったかで単位が決まる。
    probes.push(launch(
        "surrogate-decisive".into(),
        PAIR.to_string().repeat(1200),
    ));

    // (3) 境界（対の切れ目がちょうど1024に来る偶数配置）。
    for total_units in [CAP - 2, CAP, CAP + 2] {
        probes.push(launch(
            format!("surrogate-aligned-{total_units}u"),
            PAIR.to_string().repeat((total_units - PREFIX) / 2),
        ));
    }

    // (4) **対の途中で切る**: ASCIIを1文字挟んで奇数境界にすると、前置19単位のあと
    //     高位サロゲートが偶数位置に並ぶ——第1024単位は高位サロゲートになる。
    //     切り詰めが単位数で行われるなら、末尾にlone surrogateが残るはずである。
    probes.push(launch(
        "surrogate-split-pair".into(),
        format!("a{}", PAIR.to_string().repeat(600)),
    ));

    std::thread::sleep(DRAIN);
    let outcome = mof.stop();
    let starts = &outcome.process_starts;

    println!("=== truncation boundary (prefix is {PREFIX} UTF-16 units, all ASCII) ===");
    println!(
        "{:<26} | launched u/ch | observed u/ch | verbatim? | Flags | tail units",
        "probe"
    );
    for probe in &probes {
        match starts.iter().find(|s| s.pid == Some(probe.pid)) {
            Some(hit) => {
                // **生のUTF-16単位で判定する**。`String`へ落ちた後ではlone surrogateが
                // U+FFFDへ置換されて痕跡が消える（`tdh::property_utf16_units`のdoc）。
                let observed_units = hit.command_line_utf16_len.unwrap_or(0);
                let observed_chars = hit
                    .command_line
                    .as_deref()
                    .map(|c| c.chars().count())
                    .unwrap_or(0);
                let tail: Vec<String> = hit
                    .command_line_tail_units
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .map(|u| format!("{u:04X}"))
                    .collect();
                println!(
                    "{:<26} | {:>6}/{:<6} | {:>6}/{:<6} | {:>9} | {:?} | {}",
                    probe.label,
                    probe.units,
                    probe.chars,
                    observed_units,
                    observed_chars,
                    if observed_units == probe.units {
                        "yes"
                    } else {
                        "NO"
                    },
                    hit.flags,
                    tail.join(" "),
                );
            }
            None => println!(
                "{:<26} |  (no process-start event observed for pid {})",
                probe.label, probe.pid
            ),
        }
    }

    let observed_units = |label: &str| -> Option<usize> {
        let probe = probes.iter().find(|p| p.label == label)?;
        starts
            .iter()
            .find(|s| s.pid == Some(probe.pid))?
            .command_line_utf16_len
    };
    let tail_units = |label: &str| -> Option<Vec<u16>> {
        let probe = probes.iter().find(|p| p.label == label)?;
        starts
            .iter()
            .find(|s| s.pid == Some(probe.pid))?
            .command_line_tail_units
            .clone()
    };

    // --- 単位の判定 ---
    let unit_cap_prediction = CAP;
    let char_cap_prediction = PREFIX + 2 * (CAP - PREFIX);
    let decisive = observed_units("surrogate-decisive");
    println!(
        "[M5] decisive probe: observed {decisive:?} UTF-16 unit(s). \
         prediction if the cap counts UTF-16 units = {unit_cap_prediction}; \
         if it counts characters = {char_cap_prediction}"
    );

    // --- 痕跡の判定 ---
    let split_tail = tail_units("surrogate-split-pair");
    let lone_high = split_tail
        .as_deref()
        .and_then(|t| t.last().copied())
        .is_some_and(|u| (0xD800..=0xDBFF).contains(&u));
    println!(
        "[M5] split-pair probe: observed {:?} unit(s), tail = {:?}; \
         ends with a lone high surrogate = {lone_high}",
        observed_units("surrogate-split-pair"),
        split_tail
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|u| format!("{u:04X}"))
            .collect::<Vec<_>>(),
    );
    println!(
        "-> a lone surrogate would be a DETECTABLE trace of truncation (§22.3.1 proved only that \
         no FLAG is set). Even so, decision 16(6) keeps its default: ASCII command lines leave no \
         such trace and they are the majority"
    );

    // ---------------- 歯 ----------------
    //
    // (a) 短い側は完全一致していなければならない。ここがずれるなら、観測しているのは
    //     「カーネルの切り詰め」ではなく測定側の欠陥である。
    let short = probes
        .iter()
        .find(|p| p.label == "ascii-64")
        .expect("the short probe is in the sweep");
    assert_eq!(
        observed_units("ascii-64"),
        Some(short.units),
        "a {}-unit command line must be reported verbatim; if even this is short, the cap is in \
         our reader (TDH), not in the event",
        short.units
    );
    // (b) 決定打の観測値は**2つの予言のどちらか**でなければならない。第3の値なら、
    //     どちらの仮説でもない＝測定側を疑う合図である（1点から外挿しない、§22.3.1）。
    let decisive = decisive.expect("the decisive surrogate probe must be observed");
    assert!(
        decisive == unit_cap_prediction || decisive == char_cap_prediction,
        "the decisive probe observed {decisive} UTF-16 units, which matches neither hypothesis \
         (UTF-16 units -> {unit_cap_prediction}, characters -> {char_cap_prediction}). \
         Something other than the documented 1024 cap is acting here; do not conclude a unit \
         from this run"
    );
}

/// **Tier2a（ポリシーエディタのパス2）**: AppContainer子でも`CommandLine`が載るか。
/// 併せて`PackageFullName`が載るか——`RESULTS.md` §8.4は「MOFには同等フィールドが
/// 見当たらない」と書いているが、`Process_V4_TypeGroup1`の定義には存在する（§22で訂正）。
///
/// # 測定M2: その`PackageFullName`はスコープ判定に使えるか
///
/// §22.6は「別途測る必要がある」と明記して残した。harnessのAppContainer子（`pwsh.exe`）が
/// 運んだ値は`Microsoft.PowerShell_…`＝**pwsh自身のアプリパッケージ**であって、harnessの
/// セッションプロファイル名ではなかった。**pwshはストアアプリなので、自分のパッケージ名が
/// 出ただけかもしれない**——これが「AppContainerのプロファイル名は載らない」なのか
/// 「このプロセスがたまたまパッケージ化されていた」なのかで、収集器の配線が変わる。
///
/// そこで**パッケージ化されていないexe**（`System32\cmd.exe`）を同じTier2aの子として起こし、
/// pwshを正の対照として同じ実行の中に残す。さらに**マニフェスト側も同時に張る**
/// ——同じpidについて両系統の`PackageFullName`を並べないと、「MOFだけで完結できるか」に
/// 答えられない。
#[cfg(windows)]
#[test]
#[ignore = "requires administrator rights (ETW) and creates an AppContainer profile; run via dev-elevated-run.exe spike-etw-argv"]
fn mof_process_events_carry_the_command_line_for_appcontainer_children() {
    use super::session::{
        ProviderProbeSession, EVENT_ID_PROCESS_START, KERNEL_PROCESS_KEYWORD_PROCESS,
        KERNEL_PROCESS_PROVIDER_GUID,
    };
    use crate::shell_tier::WorkspaceWriteMode;
    use crate::tier2a::win_appcontainer::preflight;
    use crate::tier2a::win_appcontainer::test_support::spawn_in_workspace;
    use crate::tier2a::win_appcontainer::NetworkCapability;

    let marker = format!("argvspike-appcontainer-{}", std::process::id());
    let marker_plain_exe = format!("argvspike-ac-cmd-{}", std::process::id());
    let workspace = tempfile::tempdir().expect("workspace tempdir");

    let outcome = preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw)
        .expect("Tier2a preflight");
    for warning in &outcome.warnings {
        println!("preflight warning: {warning}");
    }
    let profile = crate::tier2a::session_profile::current_profile_name();
    let sid = crate::tier2a::win_appcontainer::ensure_profile(&profile).expect("profile SID");
    println!("session profile: {profile}");

    let manifest = ProviderProbeSession::start(
        "harness-argv-spike-ac-manifest",
        KERNEL_PROCESS_PROVIDER_GUID,
        KERNEL_PROCESS_KEYWORD_PROCESS,
        &[EVENT_ID_PROCESS_START],
        &["ImageName", "PackageFullName"],
        &["ProcessID"],
    )
    .expect("manifest (Kernel-Process) probe session");
    let mof = MofFsSession::start_process_only("harness-argv-spike-mof-ac")
        .expect("private system logger (Classic ETW / MOF), PROCESS flag only");
    std::thread::sleep(WARMUP);

    // (1) 正の対照: パッケージ化されたexe（pwsh）。§22.6と同じ値が再現しなければ測定系が壊れている。
    let (shell, _) = crate::tier2a::win_appcontainer::resolve_shell();
    let env = crate::secret_env::build_child_env();
    let command = format!("Write-Output '{marker}'");
    let child = spawn_in_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", &command],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        None,
    )
    .expect("spawn the AppContainer child");
    let child_pid = child.pid();
    println!("AppContainer child pid = {child_pid} (packaged: {shell})");
    let child_output = child.write_stdin_read_output_and_wait(None);
    println!("child finished: {child_output:?}");

    // (2) **本命**: パッケージ化されていないexeを同じTier2aの子として起こす。
    let plain_exe = r"C:\Windows\System32\cmd.exe";
    let plain_child = spawn_in_workspace(
        plain_exe,
        &["/c", "echo", &marker_plain_exe],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        None,
    )
    .expect("spawn the un-packaged AppContainer child");
    let plain_pid = plain_child.pid();
    println!("AppContainer child pid = {plain_pid} (un-packaged: {plain_exe})");
    let plain_output = plain_child.write_stdin_read_output_and_wait(None);
    println!("un-packaged child finished: {plain_output:?}");

    std::thread::sleep(DRAIN);
    let mof_outcome = mof.stop();
    let manifest_outcome = manifest.stop();
    let starts = &mof_outcome.process_starts;
    println!("=== MOF summary: {} ===", summarize(starts));
    println!(
        "=== manifest: {} ProcessStart captured, {} event(s) reached the session ===",
        manifest_outcome.events.len(),
        manifest_outcome.seen_events,
    );

    let by_pid: Vec<&MofProcessStart> = starts.iter().filter(|s| s.pid == Some(child_pid)).collect();
    for start in &by_pid {
        dump("appcontainer", start);
    }
    let plain_by_pid: Vec<&MofProcessStart> =
        starts.iter().filter(|s| s.pid == Some(plain_pid)).collect();
    for start in &plain_by_pid {
        dump("appcontainer-unpackaged", start);
    }

    // --- M2の本体: 両系統の値を同じpidについて並べる ---
    let manifest_package = |pid: u32| -> Option<String> {
        manifest_outcome
            .events
            .iter()
            .find(|e| e.numbers.get("ProcessID") == Some(&(pid as u64)))
            .and_then(|e| e.strings.get("PackageFullName").cloned())
    };
    println!("=== M2: PackageFullName / ApplicationId by side ===");
    println!("[M2] harness session profile name = {profile:?}");
    for (tag, pid, events) in [
        ("packaged (pwsh)", child_pid, &by_pid),
        ("un-packaged (cmd)", plain_pid, &plain_by_pid),
    ] {
        let mof_hit = events.first();
        println!(
            "[M2] {tag} pid={pid}\n\
             [M2]   MOF  PackageFullName   = {:?}\n\
             [M2]   MOF  ApplicationId(U16)= {:?}\n\
             [M2]   MOF  ApplicationId(ANSI)= {:?}\n\
             [M2]   manifest PackageFullName = {:?}",
            mof_hit.and_then(|s| s.package_full_name.clone()),
            mof_hit.and_then(|s| s.application_id_utf16.clone()),
            mof_hit.and_then(|s| s.application_id_ansi.clone()),
            manifest_package(pid),
        );
    }
    println!(
        "-> if the un-packaged child carries neither the harness profile name nor any other \
         AppContainer identity on the MOF side, scope determination keeps using the MANIFEST \
         package_full_name; §8.4's correction (MOF does have the field) stays true, but \
         'therefore MOF alone is enough' does not follow"
    );

    // package付きのイベントを数件出す（AppContainer以外のUWPも混ざる）。
    let packaged: Vec<&MofProcessStart> = starts
        .iter()
        .filter(|s| s.package_full_name.is_some())
        .take(5)
        .collect();
    println!(
        "[appcontainer] {} event(s) carried a PackageFullName; showing up to 5:",
        starts
            .iter()
            .filter(|s| s.package_full_name.is_some())
            .count()
    );
    for start in packaged {
        dump("packaged", start);
    }

    assert!(
        !by_pid.is_empty(),
        "the AppContainer child's process-start event (pid {child_pid}) was not observed at all -- \
         the measurement did not run. {}",
        summarize(starts)
    );
    assert!(
        by_pid
            .iter()
            .any(|s| s.command_line.as_deref().is_some_and(|c| c.contains(&marker))),
        "the AppContainer child's command line ({marker}) was not observed. If this fails, argv \
         candidates cannot be generated for the policy editor's path 2 (Tier2a domain recording), \
         and decision 14's cost section must be rewritten. {}",
        summarize(starts)
    );
    // 対照: pwshは§22.6と同じくpackage付きで観測されなければならない。ここが崩れたら、
    // 非パッケージ側が空だったことに意味を持たせられない（両方空＝フィールドが死んでいる）。
    assert!(
        by_pid.iter().any(|s| s.package_full_name.is_some()),
        "control broken: the PACKAGED child (pwsh, pid {child_pid}) carried no PackageFullName \
         either, so an empty value on the un-packaged side says nothing about AppContainer \
         identity -- §22.6 measured a value here. {}",
        summarize(starts)
    );
    assert!(
        !plain_by_pid.is_empty(),
        "the un-packaged AppContainer child (pid {plain_pid}) was not observed at all -- M2 did \
         not run. {}",
        summarize(starts)
    );
}

/// **副次**: system trace provider（`SystemProcessProviderGuid`）を**通常セッション**で
/// 有効化できるか。できるなら本番は既存のマニフェストセッションへ相乗りでき、
/// private system logger（マシン全体で8本）の枠を消費しない。できないなら決定14の費用に
/// 「ETWセッションもう1本」が乗る。
///
/// **測定の結論（argvが取れるか）は変わらない**——これは費用見積りの入力である。
#[cfg(windows)]
#[test]
#[ignore = "requires administrator rights (ETW); run via dev-elevated-run.exe spike-etw-argv"]
fn can_the_system_process_provider_be_enabled_on_a_normal_session() {
    use super::session::try_enable_provider;
    use windows::Win32::System::Diagnostics::Etw::SystemProcessProviderGuid;

    // 対照群: 通常セッションで有効化できると分かっているプロバイダ。
    let control = try_enable_provider(
        "harness-argv-spike-control",
        super::parse::KERNEL_FILE_PROVIDER_GUID,
    )
    .expect("control session");
    println!("EnableTraceEx2(Kernel-File)             = {control:?}  (control: known to work)");

    let target = try_enable_provider("harness-argv-spike-sysproc", SystemProcessProviderGuid)
        .expect("target session");
    println!("EnableTraceEx2(SystemProcessProvider)   = {target:?}");
    println!(
        "-> if the target failed, process events (and therefore CommandLine) require a session \
         started with EVENT_TRACE_SYSTEM_LOGGER_MODE, i.e. a second session next to the \
         production Kernel-File one."
    );

    assert_eq!(
        control,
        windows::Win32::Foundation::ERROR_SUCCESS,
        "the control provider must be enable-able, otherwise this probe measures nothing"
    );
}
