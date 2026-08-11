//! **A-3 実現性スパイク（判定ゲート）**: `Microsoft-Windows-Kernel-File`のリアルタイム
//! ETWセッションで、ACLによるアクセス拒否（`STATUS_ACCESS_DENIED`）が実際に観測できるか。
//!
//! M15.7の設計（`plans/DESIGN-SANDBOX-APPPOLICY.md` §11.1）は「実行中にOSが拒否した任意の
//! FSアクセス」を4番目の収集源として要求するが、**それがETWから本当に取れるかは実測しないと
//! 分からない**——Kernel-Fileの`Create`イベントはNTSTATUSを持たず、結果は別イベント
//! （`OperationEnd`）にあり、両者は`Irp`ポインタでしか結び付かない。この設計が成り立つか
//! どうかがM15.7の残りを左右するため、収集器本体を作り込む前にここで確かめる。
//!
//! 実行:
//! ```text
//! dev-elevated-run.exe spike-etw-fs
//! ```
//! （ETWリアルタイムセッションの開始には管理者権限が要る。`#[ignore]`なので通常の
//! `cargo test`では走らない。）
//!
//! **判定が否だった場合、このファイルと`etw/`配下は削除し、結論だけを`docs/STATUS.md`と
//! phase文書へ残す**（`docs/CODE-STRUCTURE-RULES.md`規則2「一回性の調査実験をテストとして残さない」）。

use super::parse::{to_settings_path, STATUS_ACCESS_DENIED};
use super::session::EtwFsSession;
use super::volumes::drive_letter_map;

/// ETWセッションが立ち上がってから最初のイベントが流れてくるまでには猶予が要る。
const WARMUP: std::time::Duration = std::time::Duration::from_millis(1500);
/// 拒否を起こしてからイベントがコールバックへ届くまでの猶予（ETWバッファのフラッシュ待ち）。
const DRAIN: std::time::Duration = std::time::Duration::from_secs(4);

/// 現在のユーザーに対して明示的なDENY ACEを持つファイルを作り、開こうとして拒否させる。
/// 戻り値は作ったファイルのパス（tempdirは呼び出し側が保持する）。
fn create_file_denied_to_self(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("etw-spike-denied.txt");
    std::fs::write(&path, b"secret").expect("create the probe file");

    // `icacls <path> /inheritance:r /deny <user>:(R)` で自分自身の読取を拒否する。
    // ACL操作はこのスパイクの本題ではないので、既に実績のある`icacls`に任せる
    // （`grant_ace_mask`はpackage SID向けのGRANTしか扱わない）。
    let user = std::env::var("USERNAME").expect("USERNAME is set on Windows");
    let output = std::process::Command::new("icacls")
        .arg(&path)
        .arg("/inheritance:r")
        .arg("/deny")
        .arg(format!("{user}:(R)"))
        .output()
        .expect("run icacls");
    assert!(
        output.status.success(),
        "icacls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    path
}

/// **判定ゲート本体。**
///
/// 1. ETWセッションを張る
/// 2. 自分自身に対してDENYされたファイルを開こうとする（確実に`STATUS_ACCESS_DENIED`になる）
/// 3. `Create`+`OperationEnd`の相関で、そのパスの拒否が観測できることを確かめる
///
/// ここが通れば、AppContainer子プロセスの拒否も同じ経路で観測できる——AppContainerのACL拒否も
/// 同じIOマネージャの同じアクセスチェックで、`STATUS_ACCESS_DENIED`として返るため。
/// AppContainer固有なのは「どのプロセスのイベントかを絞る」部分だけで、それはETWの可否では
/// なくトークン照会（`TokenAppContainerSid`）の問題である。
#[test]
#[ignore = "requires administrator rights (ETW real-time session); run via dev-elevated-run.exe spike-etw-fs"]
fn etw_kernel_file_surfaces_access_denied_for_a_denied_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let denied_path = create_file_denied_to_self(dir.path());

    let session = match EtwFsSession::start("harness-policy-learn-spike") {
        Ok(session) => session,
        Err(e) => panic!(
            "could not start the ETW session: {e}\n\
             If this is an access-denied error, the test was not run elevated."
        ),
    };
    std::thread::sleep(WARMUP);

    // 拒否を起こす。成功してしまったらACLの設定が効いていない＝テストの前提が崩れている。
    let attempt = std::fs::read(&denied_path);
    assert!(
        attempt.is_err(),
        "the probe file was readable; the DENY ACE did not take effect, so this run proves nothing"
    );

    std::thread::sleep(DRAIN);
    let outcome = session.stop();

    println!(
        "observed {} Kernel-File events, {} of them access-denied",
        outcome.seen_events,
        outcome.denials.len()
    );
    assert!(
        outcome.seen_events > 0,
        "no Kernel-File events reached the callback at all -- the provider/keywords are wrong, \
         or the session was not actually collecting"
    );

    let volumes = drive_letter_map();
    let expected = denied_path.to_string_lossy().replace('\\', "/");
    let matched = outcome.denials.iter().find(|denial| {
        to_settings_path(&denial.file_name, &volumes)
            .is_some_and(|p| p.eq_ignore_ascii_case(&expected))
    });

    let observed: Vec<String> = outcome
        .denials
        .iter()
        .filter_map(|d| to_settings_path(&d.file_name, &volumes))
        .collect();
    let denial = matched.unwrap_or_else(|| {
        panic!(
            "the denied open was not observed.\n  expected: {expected}\n  \
             observed denials ({}): {observed:#?}\n\
             If seen_events > 0 but no denial matched, Create/OperationEnd correlation is the \
             thing that does not work -- record that in docs/STATUS.md and fall back to the \
             three existing sources.",
            observed.len()
        )
    });

    assert_eq!(denial.status, STATUS_ACCESS_DENIED);
    assert_eq!(
        denial.pid,
        std::process::id(),
        "the event must carry the issuing process id, which is what scoping to the AppContainer \
         children will rely on"
    );
}

/// セッションを止めた後にOSへ残らないこと。リアルタイムETWセッションはプロセスが死んでも
/// OSに残り続ける（`logman query -ets`に出る）ので、撤収が効いていることは明示的に確かめる。
/// 残ると次回の`StartTraceW`が`ERROR_ALREADY_EXISTS`になり、収集が静かに壊れる。
#[test]
#[ignore = "requires administrator rights (ETW real-time session); run via dev-elevated-run.exe spike-etw-fs"]
fn the_session_is_removed_from_the_os_after_stop() {
    const NAME: &str = "harness-policy-learn-spike-teardown";

    let session = EtwFsSession::start(NAME).expect("start the session");
    assert!(logman_lists_session(NAME), "the session should be running");
    let _ = session.stop();

    assert!(
        !logman_lists_session(NAME),
        "the ETW session outlived the process that created it"
    );

    // 同じ名前で作り直せる（前回の残留で`ERROR_ALREADY_EXISTS`にならない）。
    let again = EtwFsSession::start(NAME).expect("the name is reusable after a clean stop");
    let _ = again.stop();
}

fn logman_lists_session(name: &str) -> bool {
    let output = std::process::Command::new("logman")
        .args(["query", "-ets"])
        .output()
        .expect("run logman");
    String::from_utf8_lossy(&output.stdout).contains(name)
}

// ---------------------------------------------------------------------------
// 系統比較スパイク: MOF（Classic）とマニフェスト（Modern）を同時に走らせて突き合わせる
// ---------------------------------------------------------------------------

use super::mof::MofFsSession;

/// `NtCreateFile`を**`RootDirectory`相対**で呼ぶ（`ObjectName`はリーフ名だけ）。
///
/// `cmd.exe`の`>`リダイレクトが使うのと同じ形（[BUG-033](../../../../../docs/bugs/BUG-033.md)）。
/// ETWの各系統がこれを完全パスで報告するのか、リーフ名だけで報告するのかが§6.5の問い。
/// 戻り値はNTSTATUS。
fn open_relative_to_directory(dir: &std::path::Path, leaf: &str) -> i32 {
    use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows::Wdk::Storage::FileSystem::NtCreateFile;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, UNICODE_STRING};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::IO_STATUS_BLOCK;

    // 親ディレクトリのハンドルを取る（`FILE_FLAG_BACKUP_SEMANTICS`が無いとディレクトリを開けない）。
    let dir_w = crate::win_common::wide(&dir.to_string_lossy());
    let dir_handle = unsafe {
        CreateFileW(
            windows::core::PCWSTR(dir_w.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    }
    .expect("open the parent directory handle");

    let mut leaf_w: Vec<u16> = leaf.encode_utf16().collect();
    let mut name = UNICODE_STRING {
        Length: (leaf_w.len() * 2) as u16,
        MaximumLength: (leaf_w.len() * 2) as u16,
        Buffer: windows::core::PWSTR(leaf_w.as_mut_ptr()),
    };
    let attrs = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: dir_handle, // ← ここが肝。ObjectNameはリーフ名だけになる
        ObjectName: &mut name,
        Attributes: 0x40, // OBJ_CASE_INSENSITIVE
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };

    let mut handle = HANDLE::default();
    let mut iosb = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_GENERIC_READ,
            &attrs,
            &mut iosb,
            None,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            windows::Wdk::Storage::FileSystem::FILE_OPEN,
            windows::Wdk::Storage::FileSystem::NTCREATEFILE_CREATE_OPTIONS(0x40), // FILE_NON_DIRECTORY_FILE
            None,
            0,
        )
    };
    unsafe {
        if !handle.is_invalid() {
            let _ = CloseHandle(handle);
        }
        let _ = CloseHandle(dir_handle);
    }
    status.0
}

/// **§6.5 + §7 の判定**: 両系統を同時に走らせ、(a) 絶対パスのopen拒否 (b) RootDirectory相対のopen
/// がそれぞれどう報告されるかを突き合わせる。
///
/// このテストは**assertよりも観測の出力が主目的**である。両系統の差が設計判断
/// （どちらを採るか・FileObject/FileKeyのパス解決が要るか）を決めるため、
/// 数値と実際のパス文字列を`--nocapture`で読めるように出す。
#[test]
#[ignore = "requires administrator rights (two ETW sessions); run via dev-elevated-run.exe spike-etw-fs"]
fn compare_mof_and_manifest_paths_for_absolute_and_relative_opens() {
    let dir = tempfile::tempdir().expect("tempdir");
    let denied_path = create_file_denied_to_self(dir.path());
    let plain_leaf = "etw-spike-relative.txt";
    let plain_path = dir.path().join(plain_leaf);
    std::fs::write(&plain_path, b"plain").expect("create the relative-open probe");

    let manifest = EtwFsSession::start("harness-policy-learn-cmp-manifest")
        .expect("manifest session (Modern ETW)");
    let mof = MofFsSession::start("harness-policy-learn-cmp-mof")
        .expect("system logger session (Classic ETW / MOF)");
    std::thread::sleep(WARMUP);

    // (a) 絶対パスでの拒否
    assert!(
        std::fs::read(&denied_path).is_err(),
        "the DENY ACE must take effect"
    );
    // (b) RootDirectory相対のopen（成功する。ここで見たいのは拒否ではなくパスの報告形式）
    let relative_status = open_relative_to_directory(dir.path(), plain_leaf);

    std::thread::sleep(DRAIN);
    let manifest_outcome = manifest.stop();
    let mof_outcome = mof.stop();

    let volumes = drive_letter_map();
    let expected_denied = denied_path.to_string_lossy().replace('\\', "/");

    println!("=== relative NtCreateFile status = {relative_status:#010X} ===");
    println!(
        "=== manifest (Kernel-File): {} events, {} denials ===",
        manifest_outcome.seen_events,
        manifest_outcome.denials.len()
    );
    println!(
        "=== MOF (FileIo): {} events, {} denials, {} name events ===",
        mof_outcome.seen_events,
        mof_outcome.denials.len(),
        mof_outcome.name_events.len()
    );

    // (a) 両系統とも絶対パスの拒否を捉えられるか
    let manifest_saw_denial = manifest_outcome.denials.iter().any(|d| {
        to_settings_path(&d.file_name, &volumes)
            .is_some_and(|p| p.eq_ignore_ascii_case(&expected_denied))
    });
    let mof_saw_denial = mof_outcome.denials.iter().any(|d| {
        to_settings_path(&d.file_name, &volumes)
            .is_some_and(|p| p.eq_ignore_ascii_case(&expected_denied))
    });
    println!("absolute denial observed -- manifest: {manifest_saw_denial}, mof: {mof_saw_denial}");

    // (b) 相対openを、それぞれどんな文字列で報告したか
    let manifest_relative: Vec<&String> = manifest_outcome
        .observed_paths
        .iter()
        .filter(|p| p.to_lowercase().contains("etw-spike-relative"))
        .collect();
    println!("manifest FileName entries mentioning the relative probe: {manifest_relative:#?}");
    let mof_relative: Vec<&String> = mof_outcome
        .observed_paths
        .iter()
        .filter(|p| p.to_lowercase().contains("etw-spike-relative"))
        .collect();
    println!("MOF OpenPath entries mentioning the relative probe: {mof_relative:#?}");
    let mof_name_events: Vec<&String> = mof_outcome
        .name_events
        .iter()
        .filter(|p| p.to_lowercase().contains("etw-spike-relative"))
        .collect();
    println!("MOF FileIo_Name entries mentioning the relative probe: {mof_name_events:#?}");
    assert!(
        !manifest_relative.is_empty(),
        "the manifest path did not report the relative open at all"
    );

    // 最低限の判定: マニフェスト側は§2.1で確認済みの経路なので拒否を捉えられていること。
    assert!(
        manifest_saw_denial,
        "the manifest path regressed: it no longer observes the absolute denial"
    );
    // MOF側は「捉えられるか」自体が未知なので、falseでも失敗にはしない（観測が目的）。
    // 判明した結果は plans/etw-spike/RESULTS.md へ追記すること。
}

/// **§7.3 / §5-2 / §5-3 の判定**: マニフェスト系統の通常セッションへ`Kernel-Process`を
/// 相乗りさせられるか、`ProcessStart`が`PackageFullName`を運ぶか、取りこぼしはどれだけか。
///
/// この3点がA-4（収集器本体）のスコープ判定方式を決める:
/// - 相乗りできて`PackageFullName`が埋まる → プロセス開始時点で判定でき、`OpenProcess`不要
/// - どちらか駄目 → `OpenProcess`+`TokenAppContainerSid`の事後照会へフォールバック（短命プロセスを取りこぼす）
#[test]
#[ignore = "requires administrator rights (ETW real-time session); run via dev-elevated-run.exe spike-etw-fs"]
fn kernel_process_rides_along_and_reports_package_identity() {
    let session =
        EtwFsSession::start("harness-policy-learn-procscope").expect("start the manifest session");
    println!(
        "Kernel-Process enabled on the same session: {}",
        session.kernel_process_enabled()
    );
    std::thread::sleep(WARMUP);

    // 通常プロセスを1つ起こす（ProcessStartが確実に流れるように）。
    let _ = std::process::Command::new("cmd.exe")
        .args(["/c", "echo etw-spike-procscope"])
        .output()
        .expect("spawn a child process");
    // パッケージ化されたプロセス（AppContainer/UWP）を起こして`PackageFullName`を観測する。
    // 電卓はWindows 11標準のパッケージアプリ。起動できない構成でも失敗にはしない。
    let packaged = std::process::Command::new("cmd.exe")
        .args(["/c", "start", "", "calculator:"])
        .output();
    println!("packaged app launch attempted: {}", packaged.is_ok());

    std::thread::sleep(DRAIN);
    let outcome = session.stop();

    println!(
        "process starts observed: {}, events lost: {}, realtime buffers lost: {}",
        outcome.process_starts.len(),
        outcome.events_lost,
        outcome.realtime_buffers_lost
    );
    let with_package: Vec<_> = outcome
        .process_starts
        .iter()
        .filter(|p| {
            p.package_full_name
                .as_deref()
                .is_some_and(|s| !s.is_empty())
        })
        .collect();
    println!(
        "process starts carrying a non-empty PackageFullName: {}",
        with_package.len()
    );
    for info in with_package.iter().take(5) {
        println!(
            "  pid={} seq={:?} package={:?} image={:?}",
            info.pid, info.process_sequence_number, info.package_full_name, info.image_name
        );
    }
    if let Some(first) = outcome.process_starts.first() {
        println!(
            "  (sample non-packaged) pid={} parent={:?} seq={:?} image={:?}",
            first.pid, first.parent_pid, first.process_sequence_number, first.image_name
        );
    }

    assert!(
        session_enabled_kernel_process(&outcome),
        "no ProcessStart events arrived: Kernel-Process could not be enabled on a normal \
         (non system-logger) real-time session, so scoping must fall back to OpenProcess"
    );
}

fn session_enabled_kernel_process(outcome: &super::session::EtwFsOutcome) -> bool {
    !outcome.process_starts.is_empty()
}

// ---------------------------------------------------------------------------
// A-4d: AppContainer子プロセスでの実測
// ---------------------------------------------------------------------------

/// **A-3の最大の未解決を回収する。** §2.1の拒否はテストプロセス自身（昇格状態）で起こしたもので、
/// 「AppContainerのACL拒否も同じIOマネージャの同じアクセスチェックを通るから同じはず」というのは
/// *論証*であって実測ではなかった。ここで実際にAppContainer子を起こして確かめる。
///
/// 1回のE2Eで4つを確定させる:
/// 1. 子の拒否が`Kernel-File`に出るか
/// 2. `EventHeader.ProcessId`が**子**のPIDになるか（親ではなく）
/// 3. 子の`ProcessStart`に`PackageFullName`が入るか（→スコープ判定のどちらの経路が主になるか）
/// 4. `ScopeTracker`が実際にその子を「対象」と判定できるか
#[test]
#[ignore = "requires administrator rights (ETW) and creates an AppContainer profile; run via dev-elevated-run.exe e2e-policy-learn"]
fn appcontainer_child_denials_are_observable_and_attributable() {
    use crate::shell_tier::WorkspaceWriteMode;
    use crate::tier2a::win_appcontainer::preflight;
    use crate::tier2a::win_appcontainer::test_support::spawn_in_workspace;
    use crate::tier2a::win_appcontainer::NetworkCapability;

    use super::scope::{ScopeTracker, ScopeVerdict};
    use super::session::EtwFsSession;

    // workspace（AppContainerがACEを持つ場所）と、その外の秘密ファイル。
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let outside = tempfile::tempdir().expect("outside tempdir");
    let secret = outside.path().join("etw-e2e-secret.txt");
    std::fs::write(&secret, b"top secret").expect("write the secret file");

    let outcome = preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw)
        .expect("Tier2a preflight");
    for warning in &outcome.warnings {
        println!("preflight warning: {warning}");
    }
    let profile = crate::tier2a::session_profile::current_profile_name();
    println!("session profile: {profile}");
    let sid = crate::tier2a::win_appcontainer::ensure_profile(&profile).expect("profile SID");

    let session = EtwFsSession::start("harness-policy-learn-e2e").expect("ETW session");
    println!(
        "Kernel-Process on the same session: {}",
        session.kernel_process_enabled()
    );
    std::thread::sleep(WARMUP);

    // AppContainer子にworkspace外の秘密ファイルを読ませる（ACLで拒否されるはず）。
    let command = format!(
        "$ErrorActionPreference='SilentlyContinue'; Get-Content -LiteralPath '{}' | Out-Null; \
         Start-Sleep -Seconds 6; Write-Output done",
        secret.display()
    );
    // envは`build_child_env()`で組む。空の環境ブロックを渡すと`CreateProcessW`が
    // `ERROR_ENVVAR_NOT_FOUND`で失敗する（PowerShellの起動にSystemRoot等が要る）。
    // シェルの解決も既存テストと同じ`resolve_shell()`に合わせる。
    let (shell, _) = crate::tier2a::win_appcontainer::resolve_shell();
    let env = crate::secret_env::build_child_env();
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
    println!("AppContainer child pid = {child_pid}");

    // **子が生きている間に**ドレインする（本番の収集器と同じ条件、2秒ごと）。ここで
    // `on_process_start_probing`が効けば、`PackageFullName`が無くても第1世代を識別できる。
    let mut live_tracker = ScopeTracker::new(profile.clone());
    let mut starts: Vec<super::session::ProcessStartInfo> = Vec::new();
    let mut denials: Vec<super::parse::Denial> = Vec::new();
    for _ in 0..4 {
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let (batch_starts, batch_denials) = session.drain();
        for start in &batch_starts {
            live_tracker.on_process_start_probing(
                start,
                crate::tier2a::policy_learnd::server::probe_pid_in_container,
            );
        }
        starts.extend(batch_starts);
        denials.extend(batch_denials);
    }
    let live_verdict = live_tracker.classify(child_pid, |_| None);
    println!(
        "scope verdict while the child was alive (production path): {live_verdict:?}          (package_name_ever_matched={})",
        live_tracker.package_name_ever_matched()
    );

    let child_output = child.write_stdin_read_output_and_wait(None);
    println!("child finished: {child_output:?}");

    std::thread::sleep(DRAIN);
    let (tail_starts, tail_denials) = session.drain();
    starts.extend(tail_starts);
    denials.extend(tail_denials);
    let stats = session.stop();

    println!(
        "observed {} events ({} lost), {} process start(s), {} denial(s)",
        stats.seen_events,
        stats.events_lost,
        starts.len(),
        denials.len()
    );

    // --- (3) 子のProcessStartにPackageFullNameが入るか ---
    let child_start = starts.iter().find(|s| s.pid == child_pid);
    match child_start {
        Some(info) => println!(
            "child ProcessStart: package={:?} seq={:?} parent={:?} image={:?}",
            info.package_full_name, info.process_sequence_number, info.parent_pid, info.image_name
        ),
        None => println!("child ProcessStart was NOT observed"),
    }

    // --- (4) ScopeTrackerが子を対象と判定できるか ---
    let mut tracker = ScopeTracker::new(profile.clone());
    for start in &starts {
        tracker.on_process_start(start);
    }
    let verdict_from_process_start = tracker.classify(child_pid, |_| None);
    println!(
        "scope verdict from ProcessStart alone: {verdict_from_process_start:?} \
         (package_name_ever_matched={})",
        tracker.package_name_ever_matched()
    );

    // --- (1)(2) 子の拒否が出て、PIDが子のものか ---
    let volumes = drive_letter_map();
    let expected = secret.to_string_lossy().replace('\\', "/");
    let matching: Vec<_> = denials
        .iter()
        .filter(|d| {
            to_settings_path(&d.file_name, &volumes)
                .is_some_and(|p| p.eq_ignore_ascii_case(&expected))
        })
        .collect();
    println!("denials matching the secret file: {matching:#?}");

    assert!(
        !matching.is_empty(),
        "the AppContainer child's denied read of {expected} was not observed at all. \
         seen_events={}, total denials={}",
        stats.seen_events,
        denials.len()
    );
    assert_eq!(
        matching[0].status, STATUS_ACCESS_DENIED,
        "the denial must carry STATUS_ACCESS_DENIED"
    );
    // PIDは子（powershell.exe）か、その子孫（PowerShellが内部で起こしたもの）であるはず。
    // 親（このテストプロセス）であってはならない——それだと帰属が壊れている。
    assert_ne!(
        matching[0].pid,
        std::process::id(),
        "the denial was attributed to the test process, not to the AppContainer child"
    );

    // **本番経路の帰属**: `PackageFullName`が無くても、生存中のprobeで対象と判定できること。
    assert_eq!(
        live_verdict,
        ScopeVerdict::InScope,
        "the production scoping path (probe at ProcessStart, while the child is alive) failed to          attribute the AppContainer child to this session"
    );

    // 後始末（プロファイルとACEを撤収する）。
    let _ = crate::tier2a::session_profile::end_session(
        &crate::tier2a::win_appcontainer::revoke_session_grant,
    );
}
