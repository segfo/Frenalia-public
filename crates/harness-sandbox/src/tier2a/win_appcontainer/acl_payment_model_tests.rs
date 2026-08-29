//! 作成時継承と完成後伝播の end-to-end 費用を、同一ツリー形状・同一DACLで比較する。
//!
//! 「継承はkernel、walkはuserland」のような実装場所のラベルから速度を推定しない。ここで測る
//! 3腕はいずれも実際のWindows APIとNTFSを通し、生成時間、time-to-ready、process CPU、
//! process I/Oをランダム順に反復する。process I/O counterは物理ディスクI/Oそのものではなく、
//! キャッシュを含むプロセス帰属の比較指標であることに注意する。
//!
//! ```text
//! HARNESS_TEST_ACL_PAYMENT_NODES=20000 HARNESS_TEST_ACL_PAYMENT_REPEATS=5 \
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture \
//! acl_payment_model_creation_inheritance_vs_post_propagation
//! ```

use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessIoCounters, GetProcessTimes, IO_COUNTERS,
};

use super::test_support::{build_wide_tree, percentile, TestDirGuard};
use super::*;

const FANOUT: usize = 32;
const DEFAULT_NODES: usize = 20_000;
const DEFAULT_REPEATS: usize = 5;

#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum Arm {
    GenerateWithoutAce,
    InheritWhileCreating,
    PropagateAfterCreating,
}

#[derive(Debug, serde::Serialize)]
struct Sample {
    repetition: usize,
    order: usize,
    arm: Arm,
    nodes: usize,
    generation_ms: u128,
    time_to_ready_ms: u128,
    cpu_ms: u64,
    read_bytes: u64,
    write_bytes: u64,
    other_bytes: u64,
}

#[derive(Clone, Copy)]
struct ProcessCounters {
    cpu_100ns: u64,
    read_bytes: u64,
    write_bytes: u64,
    other_bytes: u64,
}

impl ProcessCounters {
    fn now() -> Self {
        let process = unsafe { GetCurrentProcess() };
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) }
            .expect("GetProcessTimes");
        let mut io = IO_COUNTERS::default();
        unsafe { GetProcessIoCounters(process, &mut io) }.expect("GetProcessIoCounters");
        Self {
            cpu_100ns: filetime(kernel) + filetime(user),
            read_bytes: io.ReadTransferCount,
            write_bytes: io.WriteTransferCount,
            other_bytes: io.OtherTransferCount,
        }
    }

    fn delta(self, before: Self) -> (u64, u64, u64, u64) {
        (
            self.cpu_100ns.saturating_sub(before.cpu_100ns) / 10_000,
            self.read_bytes.saturating_sub(before.read_bytes),
            self.write_bytes.saturating_sub(before.write_bytes),
            self.other_bytes.saturating_sub(before.other_bytes),
        )
    }
}

fn filetime(value: FILETIME) -> u64 {
    ((value.dwHighDateTime as u64) << 32) | value.dwLowDateTime as u64
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn capability(label: &str) -> crate::win_common::OwnedSid {
    super::capability_sid_from_name(&format!(
        "harness-acl-payment-{}-{label}",
        std::process::id()
    ))
    .expect("derive measurement capability")
}

fn verify_every_node(root: &Path, sid: windows::Win32::Security::PSID, required: u32) -> usize {
    let mut pending = vec![root.to_path_buf()];
    let mut checked = 0usize;
    while let Some(path) = pending.pop() {
        let mask = sid_effective_ace_mask(&path, sid)
            .unwrap_or_else(|error| panic!("read effective ACE on {}: {error}", path.display()))
            .unwrap_or(0);
        assert_eq!(
            mask & required,
            required,
            "{} does not carry the complete requested mask",
            path.display()
        );
        checked += 1;
        if path.is_dir() {
            for entry in std::fs::read_dir(&path).expect("read measurement tree") {
                let entry = entry.expect("read measurement entry");
                if !entry
                    .file_type()
                    .expect("measurement file type")
                    .is_symlink()
                {
                    pending.push(entry.path());
                }
            }
        }
    }
    checked
}

fn measure_arm(arm: Arm, repetition: usize, order: usize, files: usize) -> Sample {
    let label = format!("payment-r{repetition}-o{order}");
    let tree = TestDirGuard::create(&label);
    let root = tree.path();
    let sid = capability(&label);
    let mask = workspace_rwx_mask();
    let before = ProcessCounters::now();
    let total_started = Instant::now();

    let (nodes, generation_ms) = match arm {
        Arm::GenerateWithoutAce => {
            let generation_started = Instant::now();
            let nodes = build_wide_tree(root, files, FANOUT);
            (nodes, generation_started.elapsed().as_millis())
        }
        Arm::InheritWhileCreating => {
            grant_workspace_root_rw_fast(root, sid.as_psid()).expect("place inheritable root ACE");
            let generation_started = Instant::now();
            let nodes = build_wide_tree(root, files, FANOUT);
            (nodes, generation_started.elapsed().as_millis())
        }
        Arm::PropagateAfterCreating => {
            let generation_started = Instant::now();
            let nodes = build_wide_tree(root, files, FANOUT);
            let generation_ms = generation_started.elapsed().as_millis();
            grant_workspace_root_rw_fast(root, sid.as_psid()).expect("place root ACE");
            propagate_workspace_root_grant(root, sid.as_psid(), mask)
                .expect("propagate root ACE after creation");
            let rescue = fix_descendants_missing_ace(root, sid.as_psid(), mask, &[], &|_, _| {})
                .expect("verify and rescue descendants");
            assert_eq!(
                rescue.granted, 0,
                "post-propagation must reach all synthetic descendants"
            );
            (nodes, generation_ms)
        }
    };
    let time_to_ready_ms = total_started.elapsed().as_millis();
    let after = ProcessCounters::now();
    let (cpu_ms, read_bytes, write_bytes, other_bytes) = after.delta(before);

    if !matches!(arm, Arm::GenerateWithoutAce) {
        let checked = verify_every_node(root, sid.as_psid(), mask);
        assert_eq!(
            checked, nodes,
            "the correctness scan must see the full tree"
        );
        let revoke = revoke_ace_recursive(root, sid.as_psid()).expect("revoke measurement ACE");
        assert!(
            !revoke.has_blocked(),
            "measurement cleanup left ACEs: {:?}",
            revoke.blocked
        );
    }

    Sample {
        repetition,
        order,
        arm,
        nodes,
        generation_ms,
        time_to_ready_ms,
        cpu_ms,
        read_bytes,
        write_bytes,
        other_bytes,
    }
}

fn shuffled_arms(state: &mut u64) -> [Arm; 3] {
    let mut arms = [
        Arm::GenerateWithoutAce,
        Arm::InheritWhileCreating,
        Arm::PropagateAfterCreating,
    ];
    // 乱数の作り方と百分位の取り方は`lazy_ux_latency_tests`（D-88の受入測定6）と共有する
    // ——**同じ順序の作り方でないと、2つの測定の数字を並べられない**（規則5）。
    super::test_support::shuffle_in_place(&mut arms, state);
    arms
}

#[test]
#[ignore = "実NTFSへ反復してDACLを伝播する費用測定。非昇格・--test-threads=1で実行する"]
fn acl_payment_model_creation_inheritance_vs_post_propagation() {
    let files = env_usize("HARNESS_TEST_ACL_PAYMENT_NODES", DEFAULT_NODES);
    let repeats = env_usize("HARNESS_TEST_ACL_PAYMENT_REPEATS", DEFAULT_REPEATS);
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos() as u64
        ^ std::process::id() as u64;
    let mut random_state = seed.max(1);
    let mut samples = Vec::with_capacity(repeats * 3);

    for repetition in 0..repeats {
        for (order, arm) in shuffled_arms(&mut random_state).into_iter().enumerate() {
            let sample = measure_arm(arm, repetition, order, files);
            eprintln!("{}", serde_json::to_string(&sample).unwrap());
            samples.push(sample);
        }
    }

    let summary_for = |arm: Arm| {
        let arm_samples: Vec<_> = samples
            .iter()
            .filter(|sample| std::mem::discriminant(&sample.arm) == std::mem::discriminant(&arm))
            .collect();
        let metric = |value: fn(&Sample) -> u128| {
            let values: Vec<_> = arm_samples.iter().map(|sample| value(sample)).collect();
            serde_json::json!({
                "p50": percentile(values.clone(), 50),
                "p95": percentile(values, 95),
            })
        };
        serde_json::json!({
            "generation_ms": metric(|sample| sample.generation_ms),
            "time_to_ready_ms": metric(|sample| sample.time_to_ready_ms),
            "cpu_ms": metric(|sample| sample.cpu_ms as u128),
            "process_io_read_bytes": metric(|sample| sample.read_bytes as u128),
            "process_io_write_bytes": metric(|sample| sample.write_bytes as u128),
            "process_io_other_bytes": metric(|sample| sample.other_bytes as u128),
        })
    };
    let report = serde_json::json!({
        "measurement": "workspace ACL payment models",
        "seed": seed,
        "files": files,
        "nodes_per_arm": 1 + FANOUT + files,
        "repeats": repeats,
        "summary": {
            "generate_without_ace": summary_for(Arm::GenerateWithoutAce),
            "inherit_while_creating": summary_for(Arm::InheritWhileCreating),
            "propagate_after_creating": summary_for(Arm::PropagateAfterCreating),
        },
        "samples": samples,
    });
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}
