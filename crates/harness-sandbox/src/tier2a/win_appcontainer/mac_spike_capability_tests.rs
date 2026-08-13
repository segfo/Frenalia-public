//! **MAC/Spawn Daemon設計の実現性スパイク（バッチ1のS3・S4）**。結果の正本は
//! `plans/mac-spike/RESULTS.md`、設計の正本は設計書§22.1（ドメイン＝capability SIDの組）・
//! §22.2.0（群＝宣言1件）・§20項目8・§20項目11である。
//!
//! 測るのは2つ。
//!
//! | # | 問い | 否だったときに崩れるもの |
//! |---|---|---|
//! | S3 | **同一package SID内で**capabilityの差が実効アクセスを変えるか | §22.1そのもの（ドメインの実体がcapabilityの組であること） |
//! | S4 | 1トークンに積めるcapability SIDは実用域（宣言数十件）で足りるか | §22.2.0「群＝宣言1件」（宣言の数だけSIDを積む前提） |
//!
//! **S3の一部は既に測れている**（検問6）。`test_support.rs`のdocが「capabilityを積まないと
//! workspaceが一切見えない」を実測として記録している。**未測定なのは「同一package SID内で
//! 2つのcapabilityの差が出るか」と「片方を外したらその木だけが閉じるか」**なので、そこだけを測る。
//!
//! 実行（**昇格しないこと**、`mac_spike_tests`と同じ理由）:
//!
//! ```text
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture mac_spike_capability_tests
//! ```

use super::mac_spike_tests::{workspace_capability_for, SpikeConsole, SpikeSpawn};
use super::*;

/// capability SIDを名前から導出する。**台帳へは何も書かない**——`workspace_capability_sid`は
/// workspace＋mode単位の秘密を`%APPDATA%`の台帳へ永続化するが、こちらは純粋な導出
/// （`DeriveCapabilitySidsFromName`）なので、スパイクが実マシンへ記録を残さない。
fn spike_capability(label: &str) -> crate::win_common::OwnedSid {
    let name = format!("harness-mac-spike-{}-{label}", std::process::id());
    super::capability_sid_from_name(&name).expect("derive capability sid")
}

/// AppContainer子（PowerShell）に`paths`を読ませ、その出力を返す。
/// **capabilityの組だけを変えて同じことをさせる**のがこのスパイクの測り方。
fn read_from_sandbox(
    container_sid: PSID,
    capabilities: &[PSID],
    paths: &[&std::path::Path],
) -> String {
    let (shell, _) = resolve_shell();
    let reads: Vec<String> = paths
        .iter()
        .map(|p| {
            format!(
                "try {{ Write-Output (Get-Content -Path '{}' -Raw -ErrorAction Stop) }} \
                 catch {{ Write-Output \"DENIED\" }}",
                p.display()
            )
        })
        .collect();
    let command = reads.join("; ");
    // cwdは全パッケージが読める場所にする（workspaceを与えずに測るため）。
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let cwd = std::path::PathBuf::from(format!("{system_root}\\System32"));
    let mut child = SpikeSpawn {
        exe: &shell,
        args: &["-NoProfile", "-NonInteractive", "-Command", &command],
        cwd: &cwd,
        container_sid,
        capabilities,
        child_process_restricted: false,
        stdout_override: None,
        extra_inherit: &[],
        process_sddl: None,
        thread_sddl: None,
        token_default_dacl_sddl: None,
        no_appcontainer: false,
        console: SpikeConsole::NoWindow,
    }
    .spawn()
    .expect("spawn the reader child");
    let (out, err, _code) = child.wait_and_read();
    format!("{out}{err}")
}

/// S3: **同一package SID内で**capabilityの差が実効アクセスを変えるか（§20項目8）。
///
/// 同じ実行ファイル・同じpackage SIDで、積むcapabilityだけを変えた4通りを実I/Oで測る（B-25）。
/// 「ACEを書いた」ではなく「読めた／読めなかった」まで見る。
#[test]
#[ignore = "spawns real AppContainer children and writes ACEs into a tempdir; run NON-elevated with --test-threads=1"]
fn capability_difference_changes_effective_access_within_one_package_sid() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let _cleanup = super::test_support::scopeguard(|| {
        super::mac_spike_tests::forget_workspace_capability(workspace.path())
    });

    let sid = session_sid();
    // `preflight`は祖先のtraverse ACE（D-37）を張る。これが無いとtempdirまで辿り着けない。
    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
    grant_job::wait_until_done().expect("background grant job");

    let traverse = traverse_capability_sid().expect("traverse capability");
    let cap_a = spike_capability("cap-a");
    let cap_b = spike_capability("cap-b");

    let dir_a = workspace.path().join("tree-a");
    let dir_b = workspace.path().join("tree-b");
    std::fs::create_dir_all(&dir_a).expect("tree-a");
    std::fs::create_dir_all(&dir_b).expect("tree-b");
    let secret_a = dir_a.join("secret.txt");
    let secret_b = dir_b.join("secret.txt");
    std::fs::write(&secret_a, "SECRET_TREE_A").expect("seed a");
    std::fs::write(&secret_b, "SECRET_TREE_B").expect("seed b");

    // 各capabilityに「自分の木だけ」を与える。rootには通過権だけ（列挙も読取も与えない）。
    let traverse_mask = FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0;
    let read_mask = FILE_GENERIC_READ.0 | FILE_TRAVERSE.0;
    for cap in [&cap_a, &cap_b] {
        grant_ace_mask_for_test(
            workspace.path(),
            cap.as_psid(),
            traverse_mask,
            windows::Win32::Security::ACE_FLAGS(0),
        )
        .expect("grant traverse on the workspace root");
    }
    for (cap, dir, file) in [(&cap_a, &dir_a, &secret_a), (&cap_b, &dir_b, &secret_b)] {
        grant_ace_mask_for_test(
            dir,
            cap.as_psid(),
            read_mask,
            windows::Win32::Security::ACE_FLAGS(0),
        )
        .expect("grant read on the tree");
        grant_ace_mask_for_test(
            file,
            cap.as_psid(),
            read_mask,
            windows::Win32::Security::ACE_FLAGS(0),
        )
        .expect("grant read on the file");
    }

    let cases: Vec<(&str, Vec<PSID>)> = vec![
        ("none", vec![traverse.as_psid()]),
        ("cap_a", vec![traverse.as_psid(), cap_a.as_psid()]),
        ("cap_b", vec![traverse.as_psid(), cap_b.as_psid()]),
        (
            "both",
            vec![traverse.as_psid(), cap_a.as_psid(), cap_b.as_psid()],
        ),
    ];
    let mut table: Vec<(String, bool, bool)> = Vec::new();
    for (label, caps) in &cases {
        let out = read_from_sandbox(sid.as_psid(), caps, &[&secret_a, &secret_b]);
        let saw_a = out.contains("SECRET_TREE_A");
        let saw_b = out.contains("SECRET_TREE_B");
        eprintln!("[S3] caps={label}: A={saw_a} B={saw_b} out={out:?}");
        table.push(((*label).to_string(), saw_a, saw_b));
    }

    // 後始末は判定より先に（assertで落ちてもtempdirのACEを残さない。ツリーごと消えるが、
    // 秘密の台帳は使っていないので剥がし忘れの孤児ACEは生じない）。
    let get = |label: &str| -> (bool, bool) {
        table
            .iter()
            .find(|(l, _, _)| l == label)
            .map(|(_, a, b)| (*a, *b))
            .expect("case present")
    };

    assert_eq!(
        get("cap_a"),
        (true, false),
        "cap_aだけを積んだ子が、自分の木を読めない／他人の木を読めてしまう。\
         §22.1（ドメイン＝capability SIDの組）が同一package SID内で成立していない。table={table:?}"
    );
    assert_eq!(
        get("cap_b"),
        (false, true),
        "cap_bだけを積んだ子の見え方が逆になっている。table={table:?}"
    );
    assert_eq!(
        get("both"),
        (true, true),
        "両方積んでも両方は読めない（capabilityは加算されるはず）。table={table:?}"
    );
    assert_eq!(
        get("none"),
        (false, false),
        "capabilityを1つも積んでいない子が読めてしまう（既定がdefault-denyになっていない）。\
         table={table:?}"
    );
}

/// S4: 1トークンに積めるcapability SIDの実効上限（§20項目11）。
///
/// §22.2.0が「群＝宣言1件」と決めたので、**宣言の数だけSIDを積む**ことになる。
/// 実用上は問題ないはずだが、「はず」を測らずに設計の前提へ置かない。
///
/// **本数だけでなく「効き続けるか」も測る**（B-25）。大量のSIDの中に本物のACEを持つ
/// capabilityを混ぜ、そのファイルが実際に読めるところまで見る——積めても効かないなら
/// 「積めた」に意味が無い。
#[test]
#[ignore = "spawns real AppContainer children; run NON-elevated with --test-threads=1"]
fn how_many_capability_sids_fit_in_one_token() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let _cleanup = super::test_support::scopeguard(|| {
        super::mac_spike_tests::forget_workspace_capability(workspace.path())
    });

    let sid = session_sid();
    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
    grant_job::wait_until_done().expect("background grant job");
    let traverse = traverse_capability_sid().expect("traverse capability");
    let _workspace_cap = workspace_capability_for(workspace.path());

    // 実効確認用: 最後に積むcapabilityにだけACEを持つファイル。
    let real_cap = spike_capability("bulk-real");
    let secret = workspace.path().join("bulk-secret.txt");
    std::fs::write(&secret, "SECRET_BULK").expect("seed");
    let traverse_mask = FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0;
    let read_mask = FILE_GENERIC_READ.0 | FILE_TRAVERSE.0;
    grant_ace_mask_for_test(
        workspace.path(),
        real_cap.as_psid(),
        traverse_mask,
        windows::Win32::Security::ACE_FLAGS(0),
    )
    .expect("grant traverse");
    grant_ace_mask_for_test(
        &secret,
        real_cap.as_psid(),
        read_mask,
        windows::Win32::Security::ACE_FLAGS(0),
    )
    .expect("grant read");

    // 埋め草のcapability（ACEはどこにも持たない）。
    let filler: Vec<crate::win_common::OwnedSid> = (0..1000)
        .map(|i| spike_capability(&format!("bulk-{i}")))
        .collect();

    // 起動できたかどうかだけを見たいので、**引数の解釈で揺れない**プローブを使う
    // （`cmd.exe`は引数を個別にクォートすると自分の構文解析で落ちるため、
    // 「起動はできたのに exit != 0」という紛らわしい観測になる）。
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let probe = super::mac_spike_tests::probe_exe();
    let probe_str = probe
        .to_str()
        .expect("probe path is valid utf-8")
        .to_string();
    let cwd = std::path::PathBuf::from(format!("{system_root}\\System32"));

    let mut results: Vec<(usize, bool, i32, u128)> = Vec::new();
    for count in [1usize, 10, 50, 100, 500, 1000] {
        let mut caps: Vec<PSID> = vec![traverse.as_psid()];
        caps.extend(
            filler
                .iter()
                .take(count.saturating_sub(1))
                .map(|s| s.as_psid()),
        );
        let started = std::time::Instant::now();
        let spawned = SpikeSpawn {
            exe: &probe_str,
            args: &["--emit", "bulk"],
            cwd: &cwd,
            container_sid: sid.as_psid(),
            capabilities: &caps,
            child_process_restricted: false,
            stdout_override: None,
            extra_inherit: &[],
            process_sddl: None,
            thread_sddl: None,
            token_default_dacl_sddl: None,
            no_appcontainer: false,
            console: SpikeConsole::NoWindow,
        }
        .spawn();
        match spawned {
            Ok(mut child) => {
                let (_, _, code) = child.wait_and_read();
                let elapsed = started.elapsed().as_millis();
                eprintln!("[S4] capabilities={count}: spawn ok exit={code} elapsed_ms={elapsed}");
                results.push((count, true, code, elapsed));
            }
            Err(e) => {
                let elapsed = started.elapsed().as_millis();
                eprintln!("[S4] capabilities={count}: spawn FAILED after {elapsed}ms: {e}");
                results.push((count, false, -1, elapsed));
            }
        }
    }

    // 実効確認: 100本の配列の**最後**に本物を混ぜて、そのファイルが読めるか。
    let mut bulk_caps: Vec<PSID> = vec![traverse.as_psid()];
    bulk_caps.extend(filler.iter().take(98).map(|s| s.as_psid()));
    bulk_caps.push(real_cap.as_psid());
    let out = read_from_sandbox(sid.as_psid(), &bulk_caps, &[&secret]);
    let effective = out.contains("SECRET_BULK");
    eprintln!("[S4] 100本中の最後のcapabilityが実効で効くか: {effective} out={out:?}");

    let ok_at = |n: usize| -> bool {
        results
            .iter()
            .find(|(count, _, _, _)| *count == n)
            .map(|(_, ok, code, _)| *ok && *code == 0)
            .unwrap_or(false)
    };
    assert!(
        ok_at(50),
        "capability SIDを50本積むとプロセスを起動できない。§22.2.0（群＝宣言1件）が\
         実用域で成立しないので、群の単位を設計し直す必要がある。results={results:?}"
    );
    assert!(
        effective,
        "本数を積むと最後のcapabilityが効かなくなる（積めたが実効が失われる）。\
         これは「設定した」と「効く」がずれる形なので、群の本数に上限を設ける必要がある。\
         results={results:?}"
    );
}
