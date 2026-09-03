//! **§20項目1の2の実測**: `CHILD_PROCESS_RESTRICTED`によるカーネル拒否を、外から観測できるか
//! （`plans/DESIGN-MAC-POC.md` §20項目1、`plans/mac-spike/RESULTS.md`）。
//!
//! ## なぜ要るのか
//!
//! [§9.2](../../../../../plans/DESIGN-MAC-ENFORCEMENT.md)が名指ししている穴——フックが効かない
//! プログラム（Direct Syscall・独自のアンチフック・注入の失敗）からのプロセス生成は、
//! **Spawn Daemonに要求が1件も届かない**ので、カーネルが拒否した事実が**どこにも残らない**
//! （無言失敗、B-10）。ユーザーには「原因不明の失敗」に見える。
//!
//! これは`plans/PLAN-MAC-RECURSIVE-DESCENDANTS.md`の**未解決#9**（通常運用中のプロセス生成の
//! 監視は誰がやるのか）の中心にある問いでもある。観測できるなら塞げるし、できないなら
//! P-10に従って「この軸は制御していない」と書く——**どちらであるかを測らずに決めない**。
//!
//! ## 測る対象
//!
//! `Microsoft-Windows-Security-Mitigations`（`{fae10392-f0af-4ac0-b8ff-9f4d920c3cdf}`）の
//! `KERNEL_MITIGATION_TASK_PROHIBIT_CHILD_PROCESS_CREATION`。マニフェストの実測では
//! **Id=3（監査）/Id=4（ブロック）**があり、テンプレートは呼び出し元の`ProcessPath`＋
//! `ProcessCommandLine`と、子の`ChildImagePathName`＋`ChildCommandLine`を運ぶ。
//!
//! ## 対照（これが無いと結果を読めない）
//!
//! | 対照 | 何を守るか |
//! |---|---|
//! | **A: 測る世界の同一性** | このテストは**昇格して**走る（ETWセッションに管理者権限が要る）。`mac_spike_tests`のdocが警告するとおり、昇格した親から起こしたAppContainer子は実運用と別の世界になり得る（B-08・BUG-109）。**昇格下でも§S1と同じく直接生成が拒否されること**を確かめ、崩れていたら測定を無効として落とす |
//! | **B: 測定の生存** | mitigationを積まない子では生成が**成功し、かつ拒否イベントが出ない**こと。出るなら別のものを見ている（B-35: 拒否側だけ見ると機構が死んでいる状態と区別できない） |
//!
//! ## 実行
//!
//! ```text
//! cargo build -p tier2a-proc-probe
//! target/debug/dev-elevated-run.exe spike-mac-mitigation-etw
//! ```
//!
//! 判定が出たらこのファイルは消す（`docs/CODE-STRUCTURE-RULES.md`規則2）。実測値の正本は
//! `plans/mac-spike/RESULTS.md`。

use std::collections::BTreeSet;
use std::time::Duration;

use windows::core::GUID;

use super::mac_spike_tests::{
    forget_workspace_capability, last_json_line, probe_exe, workspace_capability_for, SpikeConsole,
    SpikeSpawn,
};
use super::*;
use crate::tier2a::policy_learnd::etw::session::{ProbedEvent, ProviderProbeSession};

/// `Microsoft-Windows-Security-Mitigations`（`Get-WinEvent -ListProvider`で実測）。
const SECURITY_MITIGATIONS_GUID: GUID = GUID::from_u128(0xFAE1_0392_F0AF_4AC0_B8FF_9F4D_920C_3CDF);

/// `KERNEL_MITIGATION_TASK_PROHIBIT_CHILD_PROCESS_CREATION`のevent id。
/// 3=監査（"ブロックされた可能性があります"）/ 4=ブロック（Warning）。
const EVENT_ID_CHILD_PROCESS_AUDIT: u16 = 3;
const EVENT_ID_CHILD_PROCESS_BLOCKED: u16 = 4;

/// セッションを張ってから配送が始まるまでの待ち（`policy_learnd/etw`のスパイクと同じ値）。
const WARMUP: Duration = Duration::from_millis(1500);
/// 対象が終わってからイベントが配送され切るまでの待ち。
const DRAIN: Duration = Duration::from_secs(4);

/// 呼び出し元のコマンドラインを長くするための詰め物。プローブは**未知の引数を黙って無視する**
/// （`tier2a-proc-probe`の`parse_args`の`_ => {}`）ので、これを足しても挙動は変わらない。
/// 目的は`ProcessCommandLine`に**切り詰めがあるか**を見ること——Classic Processクラスの
/// `CommandLine`は1024で頭打ちだった（`plans/etw-spike/RESULTS.md` §22.3.1）ので、
/// このプロバイダが同じ性質を持つかで、argv軸の観測経路の選択が変わる。
const CALLER_CMDLINE_PADDING: usize = 2400;

fn dump(tag: &str, event: &ProbedEvent) {
    println!(
        "[{tag}] Id={} Version={} etw_pid={} numbers={:?}",
        event.event_id, event.version, event.process_id, event.numbers
    );
    for (name, value) in &event.strings {
        println!(
            "[{tag}]   {name} = ({} chars) {value:?}",
            value.chars().count()
        );
    }
}

/// このプローブ実行に由来するイベントだけを拾う（`CallingProcessId`で絞る）。
fn events_for(events: &[ProbedEvent], caller_pid: u32) -> Vec<&ProbedEvent> {
    events
        .iter()
        .filter(|e| e.numbers.get("CallingProcessId") == Some(&(caller_pid as u64)))
        .collect()
}

/// マーカーディレクトリに残ったファイル名の集合（＝実際に起動できた生成経路）。
fn markers(dir: &std::path::Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    e.path()
                        .file_stem()
                        .map(|s| s.to_string_lossy().into_owned())
                })
                .collect()
        })
        .unwrap_or_default()
}

/// **本命**: カーネルが拒否した子プロセス生成が、ETWで観測できるか。
///
/// 1回の実行で次を確定させる。
///
/// 1. 拒否イベント（Id=3または4）が届くか
/// 2. 届くなら**どのフィールドが埋まるか**（特に呼び出し元と子のコマンドライン）
/// 3. 呼び出し元のコマンドラインに**切り詰め**があるか（Classic Processの1024と比較）
/// 4. `WinExec`（§S1で「拒否の理由コードを持たない」唯一の経路）でもイベントが出るか
/// 5. このプロバイダを常時張る場合のイベント量
#[cfg(windows)]
#[test]
#[ignore = "requires administrator rights (ETW real-time session) and spawns AppContainer children; run via dev-elevated-run.exe spike-mac-mitigation-etw"]
fn kernel_denied_child_creation_is_observable_via_security_mitigations() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let _cleanup =
        super::test_support::scopeguard(|| forget_workspace_capability(workspace.path()));

    let sid = ensure_profile(&crate::tier2a::session_profile::current_profile_name())
        .expect("session profile SID");
    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
    grant_job::wait_until_done().expect("background grant job");

    let traverse = traverse_capability_sid().expect("traverse capability");
    let workspace_cap = workspace_capability_for(workspace.path());
    let mut capabilities = vec![traverse.as_psid()];
    if let Some(cap) = &workspace_cap {
        capabilities.push(cap.as_psid());
    }

    let probe = probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();
    let padding = "x".repeat(CALLER_CMDLINE_PADDING);

    let session = ProviderProbeSession::start(
        "harness-mac-mitigation-etw",
        SECURITY_MITIGATIONS_GUID,
        u64::MAX,
        &[EVENT_ID_CHILD_PROCESS_AUDIT, EVENT_ID_CHILD_PROCESS_BLOCKED],
        &[
            "ProcessPath",
            "ProcessCommandLine",
            "ChildImagePathName",
            "ChildCommandLine",
        ],
        &[
            "CallingProcessId",
            "CallingProcessStartKey",
            "CallingThreadId",
        ],
    )
    .expect("start the Security-Mitigations probe session");
    std::thread::sleep(WARMUP);

    // restricted=false（対照B）→ restricted=true（本命＋対照A）の順で回す。
    let mut runs: Vec<(bool, u32, BTreeSet<String>, serde_json::Value)> = Vec::new();
    for restricted in [false, true] {
        let marker_dir = workspace.path().join(if restricted {
            "markers-restricted"
        } else {
            "markers-control"
        });
        std::fs::create_dir_all(&marker_dir).expect("marker dir");
        let marker_dir_str = marker_dir.to_string_lossy().into_owned();

        let mut child = SpikeSpawn {
            exe: &probe_str,
            args: &[
                "--spawn-matrix",
                &marker_dir_str,
                "--timeout-secs",
                "180",
                // 未知の引数（無視される）。呼び出し元のコマンドラインを長くするためだけに置く。
                "--cmdline-padding",
                &padding,
            ],
            cwd: workspace.path(),
            container_sid: sid.as_psid(),
            capabilities: &capabilities,
            child_process_restricted: restricted,
            stdout_override: None,
            extra_inherit: &[],
            process_sddl: None,
            thread_sddl: None,
            token_default_dacl_sddl: None,
            no_appcontainer: false,
            // §S1と同じく両方を`Detached`に揃える（揃えないと比べているのが
            // mitigationの効果ではなくコンソールの有無になる）。
            console: SpikeConsole::Detached,
        }
        .spawn()
        .unwrap_or_else(|e| panic!("spawn probe (restricted={restricted}): {e}"));

        let caller_pid = child.pid();
        let (stdout, stderr, code) = child.wait_and_read();
        println!("[etw] restricted={restricted} caller_pid={caller_pid} exit={code}");
        if !stderr.trim().is_empty() {
            println!("[etw] stderr={stderr}");
        }
        let report = last_json_line(&stdout).unwrap_or_else(|| {
            panic!("probe produced no JSON (restricted={restricted}): {stdout}")
        });
        runs.push((restricted, caller_pid, markers(&marker_dir), report));
    }

    std::thread::sleep(DRAIN);
    let outcome = session.stop();

    let (_, control_pid, control_markers, _) = &runs[0];
    let (_, restricted_pid, restricted_markers, restricted_report) = &runs[1];

    println!(
        "=== Security-Mitigations: {} event(s) reached the session, {} captured (Id 3/4), \
         {} dropped, {} lost ===",
        outcome.seen_events,
        outcome.events.len(),
        outcome.dropped,
        outcome.events_lost
    );
    println!("[etw] control markers    = {control_markers:?}");
    println!("[etw] restricted markers = {restricted_markers:?}");

    let control_events = events_for(&outcome.events, *control_pid);
    let restricted_events = events_for(&outcome.events, *restricted_pid);
    println!(
        "[etw] events attributed to the control caller (pid {control_pid}): {}",
        control_events.len()
    );
    println!(
        "[etw] events attributed to the restricted caller (pid {restricted_pid}): {}",
        restricted_events.len()
    );
    for event in &restricted_events {
        dump("restricted", event);
    }
    for event in &control_events {
        dump("control", event);
    }

    // --- 呼び出し元のコマンドラインの切り詰め（Classic Processの1024と比較する） ---
    let launched_len = restricted_events
        .first()
        .and_then(|e| e.strings.get("ProcessCommandLine"))
        .map(|s| s.chars().count());
    println!(
        "[etw] caller command line: launched with {CALLER_CMDLINE_PADDING} chars of padding; \
         observed ProcessCommandLine length = {launched_len:?} \
         (Classic Process class caps at 1024 -- see etw-spike/RESULTS.md §22.3.1)"
    );

    // --- どのevent idで来たか（監査かブロックか） ---
    let by_id: std::collections::BTreeMap<u16, usize> =
        restricted_events
            .iter()
            .fold(Default::default(), |mut m, e| {
                *m.entry(e.event_id).or_insert(0) += 1;
                m
            });
    println!("[etw] restricted events by id (3=audit, 4=blocked): {by_id:?}");

    // --- どの生成経路が拒否イベントを出したか（`WinExec`が出るかが§S1の残り） ---
    let child_images: BTreeSet<String> = restricted_events
        .iter()
        .filter_map(|e| e.strings.get("ChildImagePathName").cloned())
        .collect();
    let child_cmdlines: Vec<&String> = restricted_events
        .iter()
        .filter_map(|e| e.strings.get("ChildCommandLine"))
        .collect();
    println!("[etw] distinct ChildImagePathName = {child_images:?}");
    println!("[etw] ChildCommandLine samples    = {child_cmdlines:#?}");
    println!("[etw] restricted probe report     = {restricted_report}");

    // ---------------- 対照A: 測る世界の同一性 ----------------
    //
    // 昇格下でも§S1と同じ結論（mitigationありでは直接生成が通らない）が成り立っていること。
    // 崩れていたら、このテストが観測しているのは実運用と別の世界である（B-08）。
    assert!(
        !control_markers.is_empty(),
        "control A broken: even WITHOUT the mitigation no creation path succeeded \
         (markers={control_markers:?}) -- the probe or the elevated context is different from \
         the world §S1 measured; the ETW result below cannot be interpreted"
    );
    assert!(
        restricted_markers.is_empty(),
        "control A broken: the mitigation did not deny every path under elevation \
         (markers={restricted_markers:?}); §S1 measured zero. Fix the world before reading the \
         ETW result"
    );

    // ---------------- 対照B: 測定の生存 ----------------
    //
    // mitigationを積まない側では拒否イベントが出ないこと。出るなら別のものを数えている。
    assert!(
        control_events.is_empty(),
        "control B broken: the un-restricted caller also produced child-process-block events \
         ({} of them) -- the filter is matching something other than the mitigation",
        control_events.len()
    );

    // ---------------- 本命 ----------------
    assert!(
        !restricted_events.is_empty(),
        "no child-process-creation block event was observed for the restricted caller \
         (pid {restricted_pid}), although every creation path was denied. \
         {} event(s) reached the session in total. If this holds, kernel-side denials are \
         invisible to harness and PLAN-MAC-RECURSIVE-DESCENDANTS.md #9 must record that axis \
         as 'not controlled' (P-10)",
        outcome.seen_events
    );
}

/// **測定M3**: `Security-Mitigations`を**既存の`policy_learnd`セッションへ相乗り**できるか
/// （`plans/PLAN-MAC-ARGV-MEASUREMENTS.md` M3。決定17(3)の注記が「未測定」と明記した件）。
///
/// §S1c（上のテスト）は**専用セッション**で測っている。本番の収集器は
/// `Kernel-File`＋`Kernel-Process`の2本を1セッションへ載せているので、そこへ3本目として
/// 載せられるなら**常駐する昇格購読者は増えない**。載せられないなら、昇格した購読者が
/// もう1本常駐する設計になる（プロセス構成と寿命管理が増える）。
///
/// # 測り方の要点
///
/// - **本番の`EtwFsSession`そのもの**へ載せる（等価に組んだ別セッションで測らない。§21.4）
/// - `EnableTraceEx2`の戻り値**だけを見ない**——`ERROR_SUCCESS`でも配送が無いことがあるので、
///   プロバイダ別のヒストグラムで**実際に届いたか**を数える
/// - **既存2プロバイダが相乗り後も届いているか**を同時に確かめる（既存機能を壊していないこと）
#[cfg(windows)]
#[test]
#[ignore = "requires administrator rights (ETW real-time session) and spawns AppContainer children; run via dev-elevated-run.exe spike-mac-mitigation-etw"]
fn security_mitigations_can_ride_on_the_existing_kernel_file_session() {
    use crate::tier2a::policy_learnd::etw::parse::KERNEL_FILE_PROVIDER_GUID;
    use crate::tier2a::policy_learnd::etw::session::{
        EtwFsSession, ExtraProvider, KERNEL_PROCESS_PROVIDER_GUID,
    };

    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let _cleanup =
        super::test_support::scopeguard(|| forget_workspace_capability(workspace.path()));

    let sid = ensure_profile(&crate::tier2a::session_profile::current_profile_name())
        .expect("session profile SID");
    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
    grant_job::wait_until_done().expect("background grant job");

    let traverse = traverse_capability_sid().expect("traverse capability");
    let workspace_cap = workspace_capability_for(workspace.path());
    let mut capabilities = vec![traverse.as_psid()];
    if let Some(cap) = &workspace_cap {
        capabilities.push(cap.as_psid());
    }
    let probe = probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();

    // **本番の入口**で張る。違いは`EnableTraceEx2`がもう1回呼ばれることだけである。
    let session = EtwFsSession::start_with_extra_provider(
        "harness-mac-mitigation-piggyback",
        ExtraProvider {
            provider: SECURITY_MITIGATIONS_GUID,
            keywords: u64::MAX,
            string_props: ["ProcessPath", "ChildImagePathName", "ChildCommandLine"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            u64_props: ["CallingProcessId", "CallingProcessStartKey"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        },
    )
    .expect("start the production-shaped session with a third provider");
    let extra_status = session.extra_provider_status();
    println!(
        "[M3] EnableTraceEx2(Security-Mitigations) on the existing session = {extra_status:?} \
         (raw {}); Kernel-Process enabled on the same session = {}",
        extra_status.0,
        session.kernel_process_enabled(),
    );
    println!(
        "-> the return value alone is not the answer: ETW can accept the registration and still \
         deliver nothing. The per-provider histogram below is what decides it"
    );
    std::thread::sleep(WARMUP);

    // 非制限→制限の順（対照B→本命）。§S1cと同じ形。**制限側は3回**回す
    // ——`CallingProcessStartKey`と`ProcessSequenceNumber`の関係を、1点ではなく複数点で見るため
    // （1点からの外挿はこの系が§22.3.1で一度やり直している）。
    let mut runs: Vec<(bool, u32, BTreeSet<String>)> = Vec::new();
    for (round, restricted) in [false, true, true, true].into_iter().enumerate() {
        let marker_dir = workspace.path().join(if restricted {
            format!("markers-restricted-{round}")
        } else {
            "markers-control".to_string()
        });
        std::fs::create_dir_all(&marker_dir).expect("marker dir");
        let marker_dir_str = marker_dir.to_string_lossy().into_owned();

        let mut child = SpikeSpawn {
            exe: &probe_str,
            args: &["--spawn-matrix", &marker_dir_str, "--timeout-secs", "180"],
            cwd: workspace.path(),
            container_sid: sid.as_psid(),
            capabilities: &capabilities,
            child_process_restricted: restricted,
            stdout_override: None,
            extra_inherit: &[],
            process_sddl: None,
            thread_sddl: None,
            token_default_dacl_sddl: None,
            no_appcontainer: false,
            console: SpikeConsole::Detached,
        }
        .spawn()
        .unwrap_or_else(|e| panic!("spawn probe (restricted={restricted}): {e}"));

        let caller_pid = child.pid();
        let (stdout, stderr, code) = child.wait_and_read();
        println!("[M3] restricted={restricted} caller_pid={caller_pid} exit={code}");
        if !stderr.trim().is_empty() {
            println!("[M3] stderr={stderr}");
        }
        last_json_line(&stdout).unwrap_or_else(|| {
            panic!("probe produced no JSON (restricted={restricted}): {stdout}")
        });
        runs.push((restricted, caller_pid, markers(&marker_dir)));
    }

    std::thread::sleep(DRAIN);
    let outcome = session.stop();

    let (_, control_pid, control_markers) = &runs[0];
    let restricted_runs: Vec<&(bool, u32, BTreeSet<String>)> = runs[1..].iter().collect();
    let (_, restricted_pid, restricted_markers) = restricted_runs[0];
    println!("[M3] control markers    = {control_markers:?}");
    println!(
        "[M3] restricted markers = {:?}",
        restricted_runs
            .iter()
            .map(|(_, _, m)| m.clone())
            .collect::<Vec<_>>()
    );

    // --- プロバイダ別に「実際に届いたか」を数える ---
    let count_for = |guid: windows::core::GUID| -> u64 {
        outcome
            .provider_histogram
            .iter()
            .filter(|((provider, _), _)| *provider == guid.to_u128())
            .map(|(_, count)| *count)
            .sum()
    };
    let kernel_file = count_for(KERNEL_FILE_PROVIDER_GUID);
    let kernel_process = count_for(KERNEL_PROCESS_PROVIDER_GUID);
    let mitigations = count_for(SECURITY_MITIGATIONS_GUID);
    println!(
        "=== events delivered on ONE session: Kernel-File {kernel_file} | \
         Kernel-Process {kernel_process} | Security-Mitigations {mitigations} \
         (total seen {}) ===",
        outcome.seen_events
    );
    println!(
        "[M3] per (provider, event id): {:?}",
        outcome
            .provider_histogram
            .iter()
            .map(|((provider, id), count)| (format!("{provider:032x}"), *id, *count))
            .collect::<Vec<_>>()
    );
    println!(
        "[M3] Kernel-File denials={} observed_paths={} | Kernel-Process starts={}",
        outcome.denials.len(),
        outcome.observed_paths.len(),
        outcome.process_starts.len(),
    );

    // --- 3本目のイベントの中身（§S1cと同じものが取れているか） ---
    let mitigation_events: Vec<&ProbedEvent> = outcome
        .extra_events
        .iter()
        .filter(|e| {
            e.event_id == EVENT_ID_CHILD_PROCESS_AUDIT
                || e.event_id == EVENT_ID_CHILD_PROCESS_BLOCKED
        })
        .collect();
    let for_caller = |pid: u32| -> Vec<&ProbedEvent> {
        mitigation_events
            .iter()
            .copied()
            .filter(|e| e.numbers.get("CallingProcessId") == Some(&(pid as u64)))
            .collect()
    };
    let restricted_events = for_caller(*restricted_pid);
    let control_events = for_caller(*control_pid);
    println!(
        "[M3] child-process-block events: restricted caller {} / control caller {}",
        restricted_events.len(),
        control_events.len()
    );
    for event in restricted_events.iter().take(6) {
        dump("M3-restricted", event);
    }
    println!(
        "[M3] ANSWER: EnableTraceEx2 = {extra_status:?}; mitigation events delivered on the \
         shared session = {mitigations}; block events attributed to the restricted caller = {}. \
         Piggyback works only if BOTH the return value succeeded AND the events arrived",
        restricted_events.len()
    );

    // **測定M1の続き**: mitigation側の`CallingProcessStartKey`と、同じセッションの
    // `Kernel-Process`側の`ProcessSequenceNumber`はどう関係しているか。
    //
    // 生の値としては一致しないが、`ProcessStartKey`は上位にブート識別、下位に開始順の
    // 通し番号を詰めた形である可能性がある。**複数点で検算する**——1点だけ見て関係を
    // 決めるのは§22.3.1で一度やり直した失敗の形である。
    const LOW_48: u64 = (1u64 << 48) - 1;
    println!(
        "caller pid | CallingProcessStartKey | ProcessSequenceNumber | key&(2^48-1) | high 16"
    );
    let mut pairs = 0usize;
    let mut low_bits_match = 0usize;
    let mut high_parts: BTreeSet<u64> = BTreeSet::new();
    for (_, caller_pid, _) in &restricted_runs {
        let start_key = for_caller(*caller_pid)
            .first()
            .and_then(|e| e.numbers.get("CallingProcessStartKey").copied());
        let sequence_number = outcome
            .process_starts
            .iter()
            .find(|s| s.pid == *caller_pid)
            .and_then(|s| s.process_sequence_number);
        match (start_key, sequence_number) {
            (Some(key), Some(seq)) => {
                pairs += 1;
                if key & LOW_48 == seq {
                    low_bits_match += 1;
                }
                high_parts.insert(key >> 48);
                println!(
                    "{caller_pid:>10} | {key:>22} | {seq:>21} | {:>12} | {:>7}",
                    key & LOW_48,
                    key >> 48
                );
            }
            _ => println!(
                "{caller_pid:>10} | {start_key:?} | {sequence_number:?} | (one side missing -- \
                 not a usable pair)"
            ),
        }
    }
    println!(
        "[M3+M1] {low_bits_match} of {pairs} pair(s) satisfy `StartKey & (2^48-1) == \
         ProcessSequenceNumber`; distinct high 16 bits seen = {high_parts:?} \
         (a single constant high part across the run is consistent with a boot identifier)"
    );

    // ---------------- 対照A: 測る世界の同一性 ----------------
    assert!(
        !control_markers.is_empty(),
        "control A broken: even WITHOUT the mitigation no creation path succeeded \
         (markers={control_markers:?}) -- the ETW result cannot be interpreted"
    );
    assert!(
        restricted_markers.is_empty(),
        "control A broken: the mitigation did not deny every path under elevation \
         (markers={restricted_markers:?}); §S1c measured zero"
    );

    // ---------------- 対照B: 測定の生存 ----------------
    assert!(
        control_events.is_empty(),
        "control B broken: the un-restricted caller also produced child-process-block events \
         ({} of them) -- the filter is matching something other than the mitigation",
        control_events.len()
    );

    // ---------------- 歯: 既存2プロバイダを壊していないこと ----------------
    //
    // **ここだけは測定ではなく回帰検査である。** 3本目を載せた結果として既存の収集が死ぬなら、
    // 相乗りは「できる／できない」以前に採ってはならない。
    //
    // 逆に**3本目の可否そのものはassertしない**——載らない／届かないことは設計を変える
    // 立派な答えであって、テストの失敗ではない（`can_the_system_process_provider_be_enabled_on_a_normal_session`と
    // 同じ作法）。判定材料は上の`[M3] ANSWER:`行にすべて出してある。
    assert!(
        kernel_file > 0 && !outcome.observed_paths.is_empty(),
        "regression: no Kernel-File event arrived on the shared session ({kernel_file} events, \
         {} observed paths). Adding a third provider must not stop the production collector",
        outcome.observed_paths.len()
    );
    assert!(
        kernel_process > 0 && !outcome.process_starts.is_empty(),
        "regression: no Kernel-Process event arrived on the shared session \
         ({kernel_process} events, {} ProcessStart). Scope determination depends on these",
        outcome.process_starts.len()
    );
    assert_ne!(
        outcome.seen_events, 0,
        "no event of any kind reached the session -- the measurement did not run"
    );
}
