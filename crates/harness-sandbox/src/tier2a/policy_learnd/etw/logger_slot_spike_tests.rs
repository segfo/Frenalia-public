//! **測定M4**: private system loggerの枠が埋まっているとき`StartTraceW`は何を返すか
//! （`plans/PLAN-MAC-ARGV-MEASUREMENTS.md` M4）。
//!
//! # なぜ要るのか
//!
//! `plans/etw-spike/RESULTS.md` §22.5のとおり、プロセスイベント（＝argvを運ぶ唯一の経路）は
//! `EVENT_TRACE_SYSTEM_LOGGER_MODE`のセッションでしか取れず、**private system loggerは
//! マシン全体で8本まで**である。EDR・WPRと枠を奪い合う位置に来るので、**枠が取れないときに
//! 何が起きるか**を知らないとfail方針が決められない。識別できないまま失敗すると、決定17(2)が
//! 塞いだ「無言失敗」と同じ形の穴になる。
//!
//! # なぜ単独のファイル・単独のターゲットなのか
//!
//! **実マシンへの影響が最大の測定**である（他ツールと枠を奪い合う）。M1・M2・M5と同じ
//! モジュールへ置くと、`spike-etw-argv`を回すたびに8本張ることになるので分けてある。
//! 実行は`dev-elevated-run.exe spike-etw-logger-slots`（要管理者権限）。
//!
//! # 安全のための取り決め（**これを外すと他ツールの計測を壊す**）
//!
//! - セッション名は[`SLOT_PREFIX`]の接頭辞だけを使う。停止は名前で行われるので、
//!   **自分が張ったもの以外には触れない**
//! - 張る本数には[`MAX_ATTEMPTS`]のハード上限を置く（失敗しなくても回り続けない）
//! - 撤収は`Drop`任せにせず、**最後に`logman query -ets`で0件を実測して`assert`する**
//!   ——外部コマンドの見た目の成功を信用しない
//!
//! 結論が出たらこのファイルは削除する（`docs/CODE-STRUCTURE-RULES.md`規則2）。実測値の正本は
//! `plans/etw-spike/RESULTS.md` §23。

use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_INVALID_PARAMETER, ERROR_SUCCESS,
};

use super::mof::{MofEtwError, MofFsSession};

/// 自分が張ったセッションだけを識別できるようにするための接頭辞。
const SLOT_PREFIX: &str = "harness-slot-probe-";
/// 張り続ける本数のハード上限。**8本で失敗しなくてもここで必ず止まる。**
const MAX_ATTEMPTS: usize = 12;

/// `logman query -ets`の生出力（結果へ貼るためにそのまま返す）。
fn logman_query() -> String {
    match std::process::Command::new("logman")
        .args(["query", "-ets"])
        .output()
    {
        Ok(output) => format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(error) => format!("(failed to run `logman query -ets`: {error})"),
    }
}

/// `logman query -ets`の出力に残っている自分のセッション名。
fn leftover_sessions(query: &str) -> Vec<String> {
    query
        .lines()
        .filter(|line| line.contains(SLOT_PREFIX))
        .map(|line| line.trim().to_string())
        .collect()
}

/// **本命**: 枠が埋まったとき`StartTraceW`が返す値は、他の失敗と区別できるか。
#[cfg(windows)]
#[test]
#[ignore = "requires administrator rights and fills the machine's private system logger slots; run via dev-elevated-run.exe spike-etw-logger-slots"]
fn what_does_starttrace_return_when_the_system_logger_slots_are_full() {
    use super::session::EtwFsSession;

    // --- ベースライン（何本が既に使われている状態で測ったのかを残す） ---
    let baseline = logman_query();
    println!("=== `logman query -ets` BEFORE (baseline) ===\n{baseline}");
    assert!(
        leftover_sessions(&baseline).is_empty(),
        "a previous run left sessions behind: {:?} -- stop them with \
         `logman stop <name> -ets` before measuring, otherwise the slot count is wrong",
        leftover_sessions(&baseline)
    );

    // --- 枠を埋める ---
    //
    // **本番と同じ入口**（`start_process_only`）を使う。`EnableFlags=0`の軽い版を自作すると、
    // 「何が枠を消費するのか」自体を測り損なう恐れがある（§21.4の取り違え）。
    let mut held: Vec<MofFsSession> = Vec::new();
    let mut failure: Option<(usize, windows::Win32::Foundation::WIN32_ERROR)> = None;
    for attempt in 0..MAX_ATTEMPTS {
        let name = format!("{SLOT_PREFIX}{attempt}");
        match MofFsSession::start_process_only(&name) {
            Ok(session) => {
                println!("[slots] #{attempt} {name}: started");
                held.push(session);
            }
            Err(MofEtwError::StartTrace(code)) => {
                println!(
                    "[slots] #{attempt} {name}: StartTraceW FAILED with {code:?} (raw {})",
                    code.0
                );
                failure = Some((attempt, code));
                break;
            }
            Err(other) => {
                println!("[slots] #{attempt} {name}: failed after StartTraceW: {other}");
                failure = None;
                break;
            }
        }
    }
    println!(
        "[slots] {} private system logger(s) started before the first failure (hard cap {MAX_ATTEMPTS})",
        held.len()
    );

    // --- 対照: 枠が埋まった状態でも「通常の」リアルタイムセッションは張れるか ---
    //
    // 張れるなら、失敗はETW資源全般の枯渇ではなく**system logger枠に固有**だと言える。
    let control_name = format!("{SLOT_PREFIX}normal-control");
    let control = EtwFsSession::start(&control_name);
    println!(
        "[control] a NORMAL (non-system-logger) real-time session while the slots are full: {}",
        match &control {
            Ok(_) => "started OK -> the machine is not out of ETW resources in general".to_string(),
            Err(error) => format!("FAILED: {error}"),
        }
    );
    drop(control);

    // --- 撤収（先に畳んでから検証する） ---
    let held_count = held.len();
    drop(held);
    // `ControlTraceW(STOP)`はOSへ反映されるまでに一瞬かかる。
    std::thread::sleep(std::time::Duration::from_millis(500));

    let after = logman_query();
    println!("=== `logman query -ets` AFTER (must contain no {SLOT_PREFIX}* session) ===\n{after}");

    // --- 判定 ---
    match failure {
        Some((attempt, code)) => {
            let distinguishable = code != ERROR_SUCCESS
                && code != ERROR_ALREADY_EXISTS
                && code != ERROR_ACCESS_DENIED
                && code != ERROR_INVALID_PARAMETER;
            println!(
                "[M4] the {}th StartTraceW failed with {code:?} (raw {}). \
                 Distinguishable from the other failures this path can produce \
                 (already-exists / access-denied / invalid-parameter) = {distinguishable}",
                attempt + 1,
                code.0,
            );
            println!(
                "-> if distinguishable, the policy-definition mode can detect 'no slot' at startup \
                 and refuse to begin a recording session (fail-closed with a reason). If not, \
                 a second detector is required (check that events actually arrive after starting)"
            );
        }
        None => println!(
            "[M4] no StartTraceW failure within the hard cap of {MAX_ATTEMPTS} attempts \
             ({held_count} started). The 8-slot limit was NOT reached in this run -- record it as \
             untested rather than as 'the limit does not exist'"
        ),
    }

    // ---------------- 歯: 実マシンに何も残さないこと ----------------
    //
    // ここが本測定で最も危ない部分なので、`Drop`が走ったはずという推定ではなく**実測**で締める。
    let leftovers = leftover_sessions(&after);
    assert!(
        leftovers.is_empty(),
        "{} ETW session(s) with the {SLOT_PREFIX} prefix are still running: {leftovers:?}. \
         Stop each one with `logman stop <name> -ets` (do NOT stop sessions that are not ours)",
        leftovers.len()
    );
}
