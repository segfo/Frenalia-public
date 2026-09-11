//! **要求受付パイプの混雑**を測る（`docs/STATUS.md`残課題#43、
//! [`DESIGN-MAC-ENFORCEMENT.md`](../../../../../plans/DESIGN-MAC-ENFORCEMENT.md) §10.1
//! 「同時に繋いでくる子への応答は『拒否』ではない」）。記録は`plans/mac-spike/RESULTS.md`。
//!
//! # 何が問題なのか（測る対象）
//!
//! Daemonの受理ループは「1本受理 → 次のインスタンスを作る」の順で動く。**その窓に当たった子は
//! `ERROR_PIPE_BUSY`(231)を受け取る**。拒否ではない——待って撃ち直せば通る——ので、
//! 残っているのは**待ち時間**だけである。段階⑤で`CHILD_PROCESS_RESTRICTED`を積むと
//! サンドボックスの中の全てのプロセス生成がこの1本を通るので、
//! 「同時に何人来たら何ミリ秒待つのか」を先に知っておきたい。
//!
//! # これは合否の判定ではない
//!
//! **性能の閾値は決めていない**ので、混雑率や待ち時間で赤くならない。赤くなるのは
//! **測定が成立していないとき**だけである（下記）。
//!
//! # 測定が成立していないと判定するもの（ここだけが赤くなる）
//!
//! | 見るもの | 成立していない例 |
//! |---|---|
//! | `last_error` | 5（アクセス拒否）が1件でもあれば、capabilityの積み忘れを混雑と読んでいる |
//! | 応答の理由 | `not_registered`が混じれば、台帳に載っていない子から測っている |
//! | 到着のばらつき | 集合時刻でそろえたはずの1回目が散らばっていれば、それは「同時」ではない |
//! | 対照（N=1） | 1人しか居ないのに混雑するなら、原因は同時接続ではない |
//!
//! # ここで測っていないもの
//!
//! - **本番の非昇格Daemon**ではない（`preflight`が実ACLを触るため昇格側から回す）。
//!   パイプのDACLはユーザーSIDとcapability SID宛で、どちらも昇格で変わらない
//! - **debugビルド**である。絶対値はreleaseと別物になる
//! - **1要求＝1接続**として撃っている。頼む側が接続を持ち続ける綴りなら、混雑を踏むのは
//!   プロセスごとに1回だけになる（段階⑤の未決事項）

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::spawnd_e2e_tests::{domain_spec, setup, spawn_request_payload, wait_and_close};
use super::*;
use crate::tier2a::spawnd::client::TopLevelSpawn;
use crate::tier2a::spawnd::{ChildProcessPolicy, ConsoleNeed, SharedSpawnDaemon};
use crate::win_common::SendHandle;

/// 集合時刻をどれだけ先に置くか。**全レーンの子が起き終わるまでの猶予**である。
///
/// 短すぎると、遅れて起きた子が集合時刻を過ぎてから撃つ（＝同時ではなくなる）。
/// 長すぎると測定が延びるだけなので、**そろったかどうかを毎回検算して**この値の妥当性を見る。
const BARRIER_LEAD: Duration = Duration::from_millis(2_500);

/// 1レーンが繰り返す「接続 → 1往復」の回数。
///
/// **1回では標本が足りない**——混雑は接続のたびに起こる事象なので、
/// `レーン数 × 繰り返し回数`だけの試行が要る。
const REPEAT_PER_LANE: u32 = 20;

/// 同じ条件を何回撃つか。
const ROUNDS: usize = 8;

/// 振る同時接続数。**先頭の1は対照**（1人しか居なければ混雑しないはず）。
const LANE_COUNTS: &[usize] = &[1, 2, 4, 8, 16];

/// 子が1回の「接続 → 1往復」で残した記録（プローブの`attempts`の1要素）。
#[derive(Debug, Clone)]
struct Attempt {
    lane: usize,
    index: u64,
    start_epoch_us: u128,
    end_epoch_us: u128,
    connect_elapsed_us: u128,
    busy_retries: u64,
    busy_wait_us: u128,
    connected: bool,
    last_error: u64,
    reply: String,
}

fn as_u128(v: Option<&serde_json::Value>) -> u128 {
    v.and_then(serde_json::Value::as_u64).unwrap_or(0) as u128
}

fn parse_attempts(lane: usize, stdout: &str) -> Vec<Attempt> {
    let report = super::mac_spike_tests::last_json_line(stdout).unwrap_or_else(|| {
        panic!("レーン{lane}の子がJSONを1行も出さなかった。stdout={stdout:?}")
    });
    let attempts = report
        .get("attempts")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| {
            panic!(
                "レーン{lane}の報告に`attempts`が無い。計器の版が古い\
                 （`--pipe-client-repeat`を持たないプローブが`target\\debug\\deps`に居る）\
                 疑いがある: {report}"
            )
        });
    attempts
        .iter()
        .map(|a| Attempt {
            lane,
            index: a.get("index").and_then(serde_json::Value::as_u64).unwrap_or(0),
            start_epoch_us: as_u128(a.get("start_epoch_us")),
            end_epoch_us: as_u128(a.get("end_epoch_us")),
            connect_elapsed_us: as_u128(a.get("connect_elapsed_us")),
            busy_retries: a
                .get("busy_retries")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            busy_wait_us: as_u128(a.get("busy_wait_us")),
            connected: a
                .get("connected")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            last_error: a
                .get("last_error")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            reply: a
                .get("reply")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
        })
        .collect()
}

fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// 同時に`lanes`人がDaemonへ繋ぎに行く回を1回撃つ。
///
/// **集合時刻でそろえる。** 子を順に起こすと起動順のばらつき（数十ms）が到着に乗り、
/// 「同時接続」ではなく「少しずつずれた到着」を測ることになる。
fn run_round(
    shared: &SharedSpawnDaemon,
    profile: &OwnedContainerSid,
    caps: &[crate::win_common::OwnedSid],
    spawn_cap: &crate::win_common::OwnedSid,
    workspace: &Path,
    lanes: usize,
) -> Vec<Attempt> {
    let spec = domain_spec(profile, caps, Some(spawn_cap));
    let payload = spawn_request_payload();
    let probe = super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();
    let request_pipe = shared.request_pipe().to_string();
    let barrier_ms = (now_epoch_ms() + BARRIER_LEAD.as_millis()).to_string();
    let repeat = REPEAT_PER_LANE.to_string();

    // **ハンドルはこのスレッドで全部作る**（`HANDLE`は`Send`ではないので最小ラッパで渡す。
    // `server.rs`の`accept_loop`と同じ手）。
    let mut prepared = Vec::with_capacity(lanes);
    for _ in 0..lanes {
        let (stdout_read, stdout_write) = appcontainer_pipe(profile.as_psid()).expect("stdout pipe");
        crate::win_common::clear_inherit(stdout_read);
        let (stderr_read, stderr_write) = appcontainer_pipe(profile.as_psid()).expect("stderr pipe");
        crate::win_common::clear_inherit(stderr_read);
        let job = crate::win_common::create_job_object().expect("lineage job");
        prepared.push((
            SendHandle(job),
            SendHandle(stdout_write),
            SendHandle(stderr_write),
            SendHandle(stdout_read),
            SendHandle(stderr_read),
        ));
    }

    std::thread::scope(|scope| {
        let threads: Vec<_> = prepared
            .into_iter()
            .enumerate()
            .map(|(lane, handles)| {
                let shared = shared.clone();
                let spec = spec.clone();
                let workspace = workspace.to_path_buf();
                let probe_str = probe_str.clone();
                let payload = payload.clone();
                let request_pipe = request_pipe.clone();
                let barrier_ms = barrier_ms.clone();
                let repeat = repeat.clone();
                scope.spawn(move || {
                    // まるごと束縛し直す（Rust 2021の部分捕捉で`SendHandle`の意味が消えないように）。
                    let (job, out_w, err_w, out_r, err_r) = handles;
                    let env = crate::secret_env::build_child_env();
                    let child = shared
                        .spawn_top_level(TopLevelSpawn {
                            exe: &probe_str,
                            args: &[
                                "--pipe-client",
                                &request_pipe,
                                "--pipe-payload",
                                &payload,
                                "--pipe-client-repeat",
                                &repeat,
                                "--pipe-client-at",
                                &barrier_ms,
                                "--timeout-secs",
                                "180",
                            ],
                            cwd: &workspace,
                            env: &env,
                            domain: spec,
                            job: job.0,
                            stdout_write: out_w.0,
                            stderr_write: err_w.0,
                            stdin_read: None,
                            redirector: None,
                            console: ConsoleNeed::NotNeeded,
                        })
                        .expect("every lane must spawn through the shared control pipe");
                    let (out, _err) = crate::win_common::read_two_pipes_to_strings(out_r.0, err_r.0);
                    wait_and_close(&child, job.0);
                    parse_attempts(lane, &out)
                })
            })
            .collect();
        threads
            .into_iter()
            .flat_map(|t| t.join().expect("lane thread must not panic"))
            .collect()
    })
}

/// 待ち時間の分布。**平均は出さない**——混雑は「ほとんど0、たまに大きい」形なので、
/// 平均は起きている事を隠す。
struct Stats {
    attempts: usize,
    busy: usize,
    p50_us: u128,
    p90_us: u128,
    max_us: u128,
    max_retries: u64,
    /// **混雑しなかった試行だけ**の接続時間の中央値。
    ///
    /// 待ち時間を読むときの物差しになる——「元々これくらい掛かる」が分かって初めて、
    /// 待たされた分が大きいのか小さいのか言える。
    p50_clean_connect_us: u128,
}

fn percentile(mut v: Vec<u128>, q: usize) -> u128 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    v[((v.len() * q) / 100).min(v.len() - 1)]
}

fn summarize(attempts: &[&Attempt]) -> Stats {
    let waits: Vec<u128> = attempts.iter().map(|a| a.busy_wait_us).collect();
    let clean: Vec<u128> = attempts
        .iter()
        .filter(|a| a.busy_retries == 0)
        .map(|a| a.connect_elapsed_us)
        .collect();
    Stats {
        attempts: attempts.len(),
        busy: attempts.iter().filter(|a| a.busy_retries > 0).count(),
        p50_us: percentile(waits.clone(), 50),
        p90_us: percentile(waits.clone(), 90),
        max_us: percentile(waits, 100),
        max_retries: attempts.iter().map(|a| a.busy_retries).max().unwrap_or(0),
        p50_clean_connect_us: percentile(clean, 50),
    }
}

fn percent(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        0.0
    } else {
        (part as f64) * 100.0 / (whole as f64)
    }
}

/// 全試行が「測れている」ことを確かめる。**ここだけが赤くなる。**
fn assert_measurement_is_valid(lanes: usize, attempts: &[Attempt]) {
    assert!(
        !attempts.is_empty(),
        "N={lanes}で試行が1件も記録されなかった"
    );
    for a in attempts {
        assert!(
            a.connected,
            "N={lanes} lane={} の試行{}が繋がらなかった: last_error={}（5=DACLで拒否／\
             231=撃ち直しの予算切れ／2=パイプ名ごと消えていた）。\
             **どれも「混雑」ではない**ので、この回の数字は待ち時間を測っていない",
            a.lane, a.index, a.last_error
        );
        assert_ne!(
            a.last_error, 5,
            "N={lanes} lane={} の試行{}でアクセス拒否(5)が出た。spawn要求用capabilityの\
             積み忘れを混雑として数えかけている（§10.1の「拒否側の測定は`last_error`まで見る」）",
            a.lane, a.index
        );
        let reason: Option<String> = serde_json::from_str::<serde_json::Value>(&a.reply)
            .ok()
            .and_then(|v| v.get("reason").and_then(|r| r.as_str().map(str::to_string)));
        assert_eq!(
            reason.as_deref(),
            Some("policy_not_implemented"),
            "N={lanes} lane={} の試行{}が想定外の応答を受けた: {:?}。\
             `not_registered`なら、台帳に載っていない子から測っている（測っているのは混雑ではない）",
            a.lane,
            a.index,
            a.reply
        );
    }
}

/// **測定**: 同時接続数を振って、何割が混雑に当たり何ミリ秒待つかを見る。
///
/// 撃ち方:
/// ```text
/// target\debug\dev-elevated-run.exe spawn-daemon-congestion
/// ```
#[test]
#[ignore = "measurement only (no pass/fail); run through spawn-daemon-congestion"]
fn request_pipe_congestion_by_concurrency() {
    let (case, profile, caps) = setup("spawnd-congestion");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let spawn_cap = spawn_request_capability_sid().expect("spawn request capability");

    // **製品と同じ共有接続**を使う（排他は`SharedSpawnDaemon`の側にある）。
    let shared = SharedSpawnDaemon::start(ChildProcessPolicy::Unrestricted).expect("a shared spawn daemon must start");
    eprintln!(
        "[congestion] daemon pid={} request_pipe={} rounds={ROUNDS} repeat/lane={REPEAT_PER_LANE}",
        shared.daemon_pid(),
        shared.request_pipe()
    );

    for &lanes in LANE_COUNTS {
        let mut rounds: Vec<Vec<Attempt>> = Vec::with_capacity(ROUNDS);
        let mut spreads_us: Vec<u128> = Vec::new();
        for round in 0..ROUNDS {
            let attempts = run_round(&shared, &profile, &caps, &spawn_cap, &workspace, lanes);
            assert_measurement_is_valid(lanes, &attempts);

            // **そろったかを毎回検算する**（集合時刻を置いただけでは「同時」の証拠にならない）。
            let firsts: Vec<u128> = attempts
                .iter()
                .filter(|a| a.index == 0)
                .map(|a| a.start_epoch_us)
                .collect();
            let spread = firsts.iter().max().copied().unwrap_or(0)
                - firsts.iter().min().copied().unwrap_or(0);
            spreads_us.push(spread);
            eprintln!(
                "[congestion] N={lanes} round={round}: 到着のばらつき={spread}us, 試行数={}",
                attempts.len()
            );
            rounds.push(attempts);
        }

        let all: Vec<&Attempt> = rounds.iter().flatten().collect();
        let burst: Vec<&Attempt> = all.iter().copied().filter(|a| a.index == 0).collect();
        let sustained: Vec<&Attempt> = all.iter().copied().filter(|a| a.index > 0).collect();
        let b = summarize(&burst);
        let s = summarize(&sustained);

        // 飽和局面の毎秒処理本数（全レーン合計）。
        //
        // **回ごとに出して、そのあと中央値を取る。** 全回をまとめて「最初の開始から最後の終了まで」で
        // 割ると、**回と回のあいだの待ち時間（集合時刻までの猶予・子の起動・後始末）まで分母に入る**
        // ——最初の版がそれで、N=16の値がおよそ5分の1に潰れていた。分母は「実際に撃っていた時間」に限る。
        let mut per_round: Vec<f64> = rounds
            .iter()
            .filter_map(|round| {
                let s: Vec<&Attempt> = round.iter().filter(|a| a.index > 0).collect();
                let start = s.iter().map(|a| a.start_epoch_us).min()?;
                let end = s.iter().map(|a| a.end_epoch_us).max()?;
                let seconds = ((end.saturating_sub(start)) as f64) / 1_000_000.0;
                (seconds > 0.0).then(|| (s.len() as f64) / seconds)
            })
            .collect();
        per_round.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
        let per_sec = per_round.get(per_round.len() / 2).copied().unwrap_or(0.0);

        eprintln!(
            "[congestion] N={lanes} burst    : n={} busy={} ({:.1}%) wait p50={}us p90={}us max={}us \
             max_retries={} clean_connect_p50={}us",
            b.attempts,
            b.busy,
            percent(b.busy, b.attempts),
            b.p50_us,
            b.p90_us,
            b.max_us,
            b.max_retries,
            b.p50_clean_connect_us
        );
        eprintln!(
            "[congestion] N={lanes} sustained: n={} busy={} ({:.1}%) wait p50={}us p90={}us max={}us \
             max_retries={} clean_connect_p50={}us throughput={:.0}/s",
            s.attempts,
            s.busy,
            percent(s.busy, s.attempts),
            s.p50_us,
            s.p90_us,
            s.max_us,
            s.max_retries,
            s.p50_clean_connect_us,
            per_sec
        );
        eprintln!(
            "[congestion] N={lanes} 回ごとの毎秒本数: min={:.0}/s max={:.0}/s（中央値が上の行）",
            per_round.first().copied().unwrap_or(0.0),
            per_round.last().copied().unwrap_or(0.0)
        );
        let spread_max = spreads_us.iter().max().copied().unwrap_or(0);
        eprintln!("[congestion] N={lanes} 到着のばらつき(最大)={spread_max}us");

        // --- 測定が成立しているかの検問 ---
        if lanes == 1 {
            // **対照。** 1人しか居ないのに混雑するなら、原因は同時接続ではない。
            assert_eq!(
                b.busy + s.busy,
                0,
                "1人だけで撃ったのに混雑が{}件出た。別のプロセスが同じパイプへ来ているか、\
                 受理ループが受付を開き直す窓に当たっている——どちらにせよ、\
                 N>1の数字を『同時接続のせい』と読めない",
                b.busy + s.busy
            );
        } else {
            assert!(
                spread_max < 1_000_000,
                "N={lanes}の1回目の到着が{spread_max}us散らばった。集合時刻でそろっていないので、\
                 これは『同時接続』の測定ではない"
            );
        }
    }

    // **最後に畳む。** `Case`のDropがDaemonを止め、workspaceのACEを剥がす。
    drop(case);
}
