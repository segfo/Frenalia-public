//! **削除の拒否はどの段階で起きるのか**（`plans/etw-spike/RESULTS.md` §12.4の再検証）。
//!
//! 実行:
//! ```text
//! dev-elevated-run.exe etw-delete-denial
//! ```
//!
//! # なぜ測り直すのか
//!
//! §12.4では「削除の拒否はopen段階で起きるので既存の`Create`+`OperationEnd`が捕まえている」と
//! 結論づけた。しかしあのテストは**親ディレクトリの`FILE_DELETE_CHILD`まで拒否していた**——
//! つまり「そもそも開けない」ケースだけを見ていた。
//!
//! §15の真理値表を取り直したとき、**`read+write`許可下で削除が失敗しているのに拒否イベントが
//! 1件も観測されない**という結果が出た。これは§12.4の結論と整合しない。
//!
//! 疑っている筋は、削除が2段階であること:
//!
//! 1. `DELETE`アクセスでopen（`NtCreateFile`）
//! 2. `NtSetInformationFile(FileDispositionInformation)`で削除マーク
//!
//! **後段で弾かれた場合、それは`Create`ではなく`SetInformation`（event 17/18）の失敗**であり、
//! `CREATE|OP_END`しか購読していない収集器からは「相関相手のいない`OperationEnd`」として
//! 捨てられている可能性がある。そうなら、削除の拒否は**取りこぼしている**。
//!
//! # 測ること
//!
//! 許可レベルごとに削除だけを実行し、
//!
//! - `Create`の拒否として観測できるか
//! - event 17/18（SetInformation/SetDelete）・26（DeletePath）が出るか
//! - 相関相手のいない`OperationEnd`が増えるか
//!
//! を見る。マシンの状態は変えない（一時ディレクトリのACLのみ）。

use windows::Win32::Security::NO_INHERITANCE;
use windows::Win32::Storage::FileSystem::{
    DELETE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_TRAVERSE,
};

use crate::shell_tier::WorkspaceWriteMode;
use crate::tier2a::win_appcontainer::{preflight, resolve_shell, spawn, NetworkCapability};

use super::parse::to_settings_path;
use super::session::EtwFsSession;
use super::volumes::drive_letter_map;

const WARMUP: std::time::Duration = std::time::Duration::from_millis(1500);
const DRAIN: std::time::Duration = std::time::Duration::from_secs(5);

/// `FILEIO`(SetInformation等)・`DELETE_PATH`・`RENAME_SETLINK_PATH`も開けて、
/// 削除がどのイベントとして現れるかを網羅的に見る。
const EXTRA_KEYWORDS: u64 = 0x20 | 0x400 | 0x800;

struct Level {
    name: &'static str,
    file_mask: u32,
}

/// `delete`列を足したのが§15との違い——**削除権だけを持たせた段**を用意して、
/// 「開けるが削除できない」と「開けない」を分離する。
const LEVELS: [Level; 4] = [
    Level { name: "none", file_mask: 0 },
    Level { name: "read", file_mask: FILE_GENERIC_READ.0 },
    Level {
        name: "read+write",
        file_mask: FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
    },
    Level {
        name: "read+write+delete",
        file_mask: FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | DELETE.0,
    },
];

#[test]
#[ignore = "requires administrator rights (ETW) and creates an AppContainer profile; run via dev-elevated-run.exe etw-delete-denial"]
fn where_does_a_delete_denial_surface() {
    let workspace = tempfile::tempdir().expect("workspace");
    let outside = tempfile::tempdir().expect("outside");

    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
    let profile = crate::tier2a::session_profile::current_profile_name();
    let sid = crate::tier2a::win_appcontainer::ensure_profile(&profile).expect("package SID");

    let mut probes: Vec<(&'static str, std::path::PathBuf)> = Vec::new();
    for level in &LEVELS {
        let dir = outside.path().join(level.name.replace('+', "_"));
        std::fs::create_dir(&dir).expect("create the level dir");
        // ディレクトリには通過＋子の削除権を与える（**非継承**）。
        // 親側の`FILE_DELETE_CHILD`を許しておくのが§12.4との決定的な違い——
        // あちらは親側も塞いでいたので「open自体が失敗する」ケースしか見ていなかった。
        crate::tier2a::win_appcontainer::grant_ace_mask_for_test(
            &dir,
            sid.as_psid(),
            FILE_TRAVERSE.0 | 0x0080 | 0x0040, // TRAVERSE | READ_ATTRIBUTES | DELETE_CHILD
            NO_INHERITANCE,
        )
        .expect("grant traverse+delete_child on the level dir");

        let data = dir.join("victim.txt");
        std::fs::write(&data, b"payload").expect("create the victim");
        if level.file_mask != 0 {
            crate::tier2a::win_appcontainer::grant_ace_mask_for_test(
                &data,
                sid.as_psid(),
                level.file_mask,
                NO_INHERITANCE,
            )
            .expect("grant the level mask");
        }
        probes.push((level.name, data));
    }

    let session = EtwFsSession::start_with_extra_keywords(
        "harness-policy-learn-delete-denial",
        EXTRA_KEYWORDS,
    )
    .expect("ETW session with SetInformation/DeletePath keywords");
    std::thread::sleep(WARMUP);

    // **削除だけ**を実行する（読み書き実行は混ぜない——混ぜると§15のように事象が絡まる）。
    let mut script = String::from("$ErrorActionPreference='SilentlyContinue';\n");
    for (name, data) in &probes {
        script.push_str(&format!(
            "try {{ Remove-Item -LiteralPath '{d}' -ErrorAction Stop; \
               Write-Output '{n}|delete|OK' }} catch {{ Write-Output '{n}|delete|FAIL' }}\n",
            n = name,
            d = data.display()
        ));
    }

    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    let child = spawn(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", &script],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        None,
    )
    .expect("spawn the AppContainer child");
    let child_pid = child.pid();
    let output = child.write_stdin_read_output_and_wait(None);

    std::thread::sleep(DRAIN);
    let (_starts, denials) = session.drain();
    let outcome = session.stop();

    println!("=== delete results (child pid={child_pid}) ===");
    if let Ok((stdout, _, _)) = &output {
        for line in stdout.lines().filter(|l| l.contains('|')) {
            println!("  {}", line.trim());
        }
    }

    let volumes = drive_letter_map();
    println!("=== Create-stage denials attributed to the child ===");
    for (name, data) in &probes {
        let expected = data.to_string_lossy().replace('\\', "/");
        let matching: Vec<_> = denials
            .iter()
            .filter(|d| {
                d.pid == child_pid
                    && to_settings_path(&d.file_name, &volumes)
                        .is_some_and(|p| p.eq_ignore_ascii_case(&expected))
            })
            .collect();
        println!("  [{name}] {} Create denial(s)", matching.len());
        for d in &matching {
            println!(
                "    CreateOptions={:#010x} disposition={} inferred_access={:?}",
                d.create_options,
                (d.create_options >> 24) & 0xFF,
                d.access
            );
        }
    }

    println!("=== event histogram (extra keywords enabled) ===");
    for (id, name) in [
        (12u16, "Create"),
        (17, "SetInformation"),
        (18, "SetDelete"),
        (19, "Rename"),
        (24, "OperationEnd"),
        (26, "DeletePath"),
        (27, "RenamePath"),
    ] {
        println!(
            "  id={id:<3} ({name:<14}) = {}",
            outcome.event_histogram.get(&id).copied().unwrap_or(0)
        );
    }
    println!(
        "  unmatched OperationEnd = {} (denials that had no Create to correlate with)",
        outcome.correlator_unmatched_operation_ends
    );
    println!("  events={} lost={}", outcome.seen_events, outcome.events_lost);

    println!(
        "HOW TO READ: if a level shows 'delete|FAIL' but ZERO Create denials, the denial did NOT \
         happen at open time -- it happened later (SetInformation), which the collector does not \
         correlate and therefore drops. That would mean delete denials are silently missed \
         whenever the file itself can still be opened, and would contradict the conclusion \
         recorded in RESULTS.md \u{00a7}12.4."
    );

    crate::tier2a::session_profile::end_session(
        &crate::tier2a::win_appcontainer::revoke_session_grant,
    );
    assert!(outcome.seen_events > 0, "no ETW events observed");
}
