//! AppContainer SIDへのACE付与/失効（fs passthrough・traverse chain・継承ACE）の実機回帰テスト。
//!
//! いずれも実Win32・実AppContainer・実FSのACL変更を伴うため`#[ignore]`。
//! `cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 win_appcontainer` で実行する。
//!
//! **旧称`traverse_diagnostics`**（`docs/bugs/BUG-011.md`等の過去の記録はこの名前で参照している）。
//! 元は`TIER1A-OPEN-ISSUES.md`課題1の調査実験（`experiment_a`〜`o`）と回帰テストが同居する
//! モジュールだった。実験は結論がdocsへ記録済みのため削除し
//! （`docs/refactor/2026-08-03-experiment-tests-removal.md`）、残った回帰テストを実態に合わせて
//! 改名した。
//!
//! `PROBE_COMMAND`/`run_probe`は実FS I/Oを試みる詳細版プローブ。本番の`smoke_test_spawn`
//! （`FS_IO_PROBE_COMMAND`、終了コードのみで判定する軽量版）と同じ合否になることを
//! `parity_production_probe_matches_diagnostic_probe`が突き合わせる
//! （`docs/phases/foundation/M12-shell-isolation-tiers.md`追記3）。

use super::*;

const PROBE_COMMAND: &str = "\
    Set-Location -LiteralPath $env:HARNESS_PROBE_DIR; \
    Write-Output ('CWD=' + (Get-Location).Path); \
    Get-ChildItem | Out-String -Width 200 | Write-Output; \
    New-Item -ItemType File -Path 'probe.txt' -Force | Out-String -Width 200 | Write-Output; \
    Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | Out-String -Width 200 | Write-Output; \
    Get-Volume -ErrorAction SilentlyContinue | Out-String -Width 200 | Write-Output";

/// `dir`をcwdにしてPROBE_COMMANDを実行し、stdout/stderr全文とexit codeをそのまま
/// 標準出力へ焼き付ける（procmon/AccessChkでの裏取りと突き合わせられるよう、テスト自身は
/// 成否をアサートしない。観測が目的であり合否判定はここでは行わない）。
fn run_probe(sid: PSID, dir: &Path) {
    let (shell, label) = resolve_shell();
    println!(
        "=== probe: shell={shell} ({label}), dir={} ===",
        dir.display()
    );
    let mut env = crate::secret_env::build_child_env();
    env.push((
        "HARNESS_PROBE_DIR".to_string(),
        dir.to_string_lossy().into_owned(),
    ));
    let child = spawn(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", PROBE_COMMAND],
        dir,
        &env,
        false,
        sid,
        NetworkCapability::Deny,
    None,
    )
    .expect("spawn should succeed even if the shell command itself fails inside");
    let (out, err, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("pipe I/O should not fail");
    println!("--- exit code: {code} ---");
    println!("--- stdout ---\n{out}");
    println!("--- stderr ---\n{err}");
}








/// PowerShellコマンドをtry/catchで包み、成否を終了コードのみで判定するヘルパー
/// （`$LASTEXITCODE`の文字列パースに頼らない、`smoke_test_spawn`と同じ設計原則）。
/// 失敗時は詳細を`println!`で焼き付ける（観測目的、アサートしない）。
fn run_probe_bool(sid: PSID, dir: &Path, command: &str) -> bool {
    let wrapped =
        format!("try {{ {command} }} catch {{ Write-Output \"CAUGHT: $_\"; exit 1 }}");
    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    let child = spawn(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", &wrapped],
        dir,
        &env,
        false,
        sid,
        NetworkCapability::Deny,
    None,
    )
    .expect("spawn should succeed even if the shell command itself fails inside");
    let (out, err, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("pipe I/O should not fail");
    if code != 0 {
        println!("--- probe failed (exit={code}) ---\nstdout: {out}\nstderr: {err}");
    }
    code == 0
}











/// 未解決事項2: 本番`smoke_test_spawn`（軽量・終了コードのみ判定）と、この診断モジュールの
/// `run_probe`（詳細・stdout全文を観測するリッチ版）が、この機種で**同じ合否判定**になる
/// ことを突き合わせる。両者が食い違う場合、本番プローブの判定精度に疑いが生じるため、
/// `preflight`をこのままTier1自動降格の唯一の判断根拠として使ってよいかを再検討する必要が
/// ある（`docs/phases/foundation/M12-shell-isolation-tiers.md`追記3参照）。
#[test]
#[ignore]
fn parity_production_probe_matches_diagnostic_probe() {
    let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
    let dir = std::path::PathBuf::from(format!(
        "C:\\ProgramData\\harness-sandbox-diag\\{}-parity",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create neutral dir");
    grant_ace_recursive(&dir, sid.as_psid()).expect("grant_ace_recursive on neutral dir");

    let production_result = smoke_test_spawn(sid.as_psid(), &dir, &dir);
    println!("=== production probe (smoke_test_spawn) result: {production_result:?} ===");

    run_probe(sid.as_psid(), &dir);

    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        production_result.is_err(),
        "on this machine (no traverse ACE on drive root, non-admin), the production FS I/O \
         probe is expected to fail just like the diagnostic probe above; if it now succeeds \
         the drive-root traverse constraint may have changed and this assertion (and the \
         M12 追記3 findings) should be revisited"
    );
}

/// Tier2aのpreflightはworkspace全体へAppContainer SIDのRW ACEを付けるが、制御面である
/// `.harness/**` だけは子プロセスから書けてはいけない。preflight内の通常I/O probeと
/// `.harness` write-deny probeを両方通し、この不変条件を実機で確認する。
#[test]
#[ignore]
fn preflight_keeps_harness_control_dir_unwritable_to_appcontainer_child() {
    let workspace = tempfile::tempdir().expect("temp workspace");
    std::fs::create_dir_all(workspace.path().join(".harness")).expect("create .harness");
    std::fs::write(
        workspace.path().join(".harness").join("settings.json"),
        "{}\n",
    )
    .expect("seed settings");

    let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
    let result = preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw);
    if result.is_err() {
        let output = std::process::Command::new("icacls")
            .arg(workspace.path().join(".harness"))
            .output()
            .expect("icacls .harness");
        println!(
            "=== .harness icacls after failed preflight ===\n{}{}",
            crate::decode_console_bytes(&output.stdout),
            crate::decode_console_bytes(&output.stderr)
        );
    }
    result.expect("preflight must protect .harness from AppContainer writes");

    let harness_dir = workspace.path().join(".harness");
    assert_no_sid_ace_recursive(&harness_dir, sid.as_psid())
        .expect(".harness must not carry AppContainer SID ACEs");

    revoke_ace_recursive(workspace.path(), sid.as_psid()).expect("cleanup AppContainer ACEs");
}

/// 特権昇格ヘルパー(D-16)レビュー用の実機検証（`/dig`セッションで検討した「LLMが
/// `run_shell`でharnessを再実行し、`--fs-allow`/`grant-traverse`経由で任意パスへ
/// サンドボックスSID宛のACEを撒かせる」攻撃経路のリンク2: 入れ子のharnessがAppContainer内から
/// `ShellExecuteExW(runas)`（`privhelper.rs::launch_helper_elevated`と同一の呼び出し）で
/// UAC昇格ブローカへ到達できるか）。
///
/// AppContainer内の子プロセス（`tier2a-proc-probe.exe --try-runas <privhelper.exeの絶対パス>`）
/// から`ShellExecuteExW(runas)`を試み、結果をJSONで報告させる。**手動実行時は画面を監視し、
/// UACダイアログが表示された場合は必ずキャンセルすること**（`try_runas`モジュールdocの
/// 安全性の配慮により、仮に誤って「許可」しても実際のACL書込みには到達しないが、
/// 昇格プロセスを残さないため）。
#[test]
#[ignore]
fn appcontainer_child_cannot_reach_uac_elevation_broker() {
    let helper_path = {
        let current = std::env::current_exe().expect("current_exe");
        let dir = current.parent().expect("current_exe has parent").to_path_buf();
        let p = dir.join("harness-privhelper.exe");
        assert!(
            p.exists(),
            "harness-privhelper.exe not found at {} (build with `cargo build -p \
             harness-privhelper` and ensure it sits next to the test binary)",
            p.display()
        );
        p
    };
    let probe_exe = {
        let current = std::env::current_exe().expect("current_exe");
        let dir = current.parent().expect("current_exe has parent").to_path_buf();
        let p = dir.join("tier2a_proc_probe.exe");
        assert!(
            p.exists(),
            "tier2a_proc_probe.exe not found at {} (build with `cargo build -p \
             tier2a-proc-probe`)",
            p.display()
        );
        p
    };

    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw)
        .expect("preflight (direct-rw)");

    let env = crate::secret_env::build_child_env();
    let args = ["--try-runas", &helper_path.to_string_lossy()];
    let child = spawn(
        &probe_exe.to_string_lossy(),
        &args,
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        None,
    )
    .expect("spawn probe inside AppContainer");
    let (stdout, stderr, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("probe should run to completion");
    assert_ne!(
        code, 97,
        "probe watchdog fired (ShellExecuteExW hung, likely awaiting UAC interaction on the \
         interactive desktop), stdout={stdout} stderr={stderr}"
    );

    let report: serde_json::Value = stdout
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str(line).ok())
        .unwrap_or_else(|| panic!("no JSON report line in stdout={stdout} stderr={stderr}"));
    println!("=== try_runas report ===\n{report:#}");

    revoke_ace_recursive(workspace.path(), sid.as_psid()).expect("cleanup AppContainer ACEs");

    // 実機確認済み（2026-08-02）: AppContainer内からの`ShellExecuteExW(runas)`は
    // `ERROR_ACCESS_DENIED`(5)で即座に失敗し（0.5秒程度、UACダイアログは画面に一切
    // 表示されない）、リンク2（入れ子harnessが特権昇格ブローカへ到達する経路）を実機でも
    // 構造的に塞いでいることを目視確認済み。AppContainerトークンはAPI呼び出しの時点で
    // 拒否され、UAC同意ブローカ（consent.exe/AIS）へは一切到達しない。
    //
    // 副次的な発見（`try_runas`モジュールdoc参照）: `SEE_MASK_FLAG_NO_UI`を付けない場合、
    // `ShellExecuteExW`はこの拒否を`ERROR_CANCELLED`(1223、`launch_helper_elevated`が
    // `ElevationDeclined`へ変換するのと同じコード)として返し、加えてシェル自身が
    // 「指定されたデバイス、パス、またはファイルにアクセスできません」という**エラー
    // ダイアログを対話デスクトップへ表示**するまでに約17秒かかっていた（UAC同意画面では
    // なく単なるアクセス拒否通知だが、AppContainerが対話UIを一切出せないわけではないという
    // 事実の記録）。`SEE_MASK_FLAG_NO_UI`を付けるとUI試行自体が起きず、即座に
    // `ERROR_ACCESS_DENIED`で返る。
    //
    // 以下は不変条件が崩れた場合（例: 将来のWindows更新やcapability構成変更でAppContainer
    // からUACに到達できるようになった場合）に検知するための回帰assert。
    assert_eq!(
        report["ok"].as_bool(),
        Some(false),
        "ShellExecuteExW(runas) succeeded from inside AppContainer — this would mean a \
         nested harness process could reach the UAC elevation broker (D-16/D-17's implicit \
         assumption is broken), report={report:#}"
    );
    assert_eq!(
        report["win32_error"].as_u64(),
        Some(5), // ERROR_ACCESS_DENIED
        "expected ShellExecuteExW(runas) to fail with ERROR_ACCESS_DENIED (5) when called \
         from inside AppContainer with SEE_MASK_FLAG_NO_UI; a different error code may \
         indicate a different failure mode worth re-investigating, report={report:#}"
    );
}


/// D-13（fs passthrough allowlist）実機E2E: 中立な外部ディレクトリ（workspace外、`grant_ace_recursive`
/// 済みのworkspaceとは別ルート）へ、まずread-only ACEを付与して子プロセスから読取成功・書込拒否を
/// 確認し、次にread-write ACEへ差し替えて書込成功を確認、最後に`revoke_ace_recursive`で
/// 全ノードから撤収して`assert_no_sid_ace_recursive`が0件（`Ok(())`）を返すことを確認する
/// （D3/D4、`TIER1A-OPEN-ISSUES.md`項目4/6の実証）。`parity_production_probe_matches_diagnostic_probe`
/// と同じく、workspace/外部ルートとも`C:\`直下の浅いパスを使う
/// （`%TEMP%`のような深いパスは`C:\`祖先1本のtraverse ACE付与だけでは足りず、中間の各祖先
/// ディレクトリにも個別のtraverse ACEが要るため、M12追記8の検証条件と揃えるのが目的）。
/// ドライブルートのtraverse ACEが無い機種ではskipする。
#[test]
#[ignore]
fn fs_passthrough_ro_then_rw_then_revoke_cycle() {
    let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");

    // workspace（FS I/Oのgate）とpassthrough対象（中立な外部ルート）は別ディレクトリにする。
    let workspace = std::path::PathBuf::from(format!(
        "C:\\harness-Tier2a-verify-passthrough-ws-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&workspace).expect("create workspace");
    grant_ace_recursive(&workspace, sid.as_psid()).expect("grant_ace_recursive on workspace");
    let probe_dir = workspace
        .join(".harness")
        .join("sandbox")
        .join("Tier2a-tmp");
    std::fs::create_dir_all(&probe_dir).expect("create probe dir");
    if let Err(e) = smoke_test_spawn(sid.as_psid(), &workspace, &probe_dir) {
        eprintln!(
            "skipping fs_passthrough_ro_then_rw_then_revoke_cycle: workspace FS I/O gate \
             failed on this machine ({e:?}); run `harness fs grant-traverse C:\\` as \
             administrator first (D10)"
        );
        let _ = std::fs::remove_dir_all(&workspace);
        return;
    }

    // 外部ルートも`C:\`直下（1階層）にする。`C:\ProgramData\...`のような多階層ネストは
    // 中間の祖先ディレクトリ（`ProgramData`等）にsandbox SID向けtraverse ACEが無く、
    // 別種の未解決問題になり得ることが実機検証で判明した（読取は成功するがrw書込がAccess
    // Deniedになる、`diagnose_unreachable_passthrough`のD9 fallback「cause unknown」経路が
    // 正しく効いた）。M12追記8が検証した「ドライブルート直下1階層」の条件に揃える。
    let external = std::path::PathBuf::from(format!(
        "C:\\harness-Tier2a-verify-passthrough-ext-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&external).expect("create neutral external dir");
    std::fs::write(external.join("existing.txt"), "pre-existing").expect("seed existing file");

    // 1. read-only付与 -> 読取成功・書込拒否。
    grant_ace_recursive_ro(&external, sid.as_psid()).expect("grant_ace_recursive_ro");
    let ro_probe = FsPassthrough {
        path: external.clone(),
        access: FsAccess::ReadExec,
        forced: false,
    };
    let ro_diagnosis = probe_passthrough(sid.as_psid(), &workspace, &ro_probe);
    assert!(
        ro_diagnosis.is_none(),
        "read probe on read-only passthrough should succeed: {ro_diagnosis:?}"
    );
    let rw_probe_against_ro_grant = FsPassthrough {
        path: external.clone(),
        access: FsAccess::ReadWrite,
        forced: false,
    };
    let write_should_fail =
        probe_passthrough(sid.as_psid(), &workspace, &rw_probe_against_ro_grant);
    assert!(
        write_should_fail.is_some(),
        "write probe must fail while only read-only ACE is granted"
    );

    // 2. read-write付与 -> 書込成功。
    grant_ace_recursive(&external, sid.as_psid()).expect("grant_ace_recursive (rw)");
    let rw_probe = FsPassthrough {
        path: external.clone(),
        access: FsAccess::ReadWrite,
        forced: false,
    };
    let rw_diagnosis = probe_passthrough(sid.as_psid(), &workspace, &rw_probe);
    assert!(
        rw_diagnosis.is_none(),
        "write probe on read-write passthrough should succeed: {rw_diagnosis:?}"
    );

    // 3. 撤収 -> 再walkで0件（D4検証パス）。
    revoke_ace_recursive(&external, sid.as_psid()).expect("revoke_ace_recursive");
    let remaining = assert_no_sid_ace_recursive(&external, sid.as_psid());
    assert!(
        remaining.is_ok(),
        "sandbox SID ACE must be fully removed after revoke_ace_recursive: {remaining:?}"
    );

    let _ = std::fs::remove_dir_all(&workspace);
    let _ = std::fs::remove_dir_all(&external);
}

/// `grant_traverse_drive_root`/`revoke_ace`/`assert_no_sid_ace`（いずれも非再帰・単一ノード）の
/// 往復を確認する（D10の巻き戻し、`harness fs revoke-traverse`本体）。実際のドライブルートは
/// 対象にせず、テスト実行ユーザー自身が所有者である`tempfile::tempdir()`を対象にする
/// （所有者は自分のオブジェクトのDACLを自由に変更できるため、`WRITE_DAC`が無い管理者専用の
/// ドライブルートと違い管理者権限が不要。`docs/explanations/Tier2a-non-admin-limitation.md`
/// 「なぜ非管理者ユーザーは自分で直せないのか」の所有者の話と対応する）。
#[test]
#[ignore]
fn grant_traverse_then_revoke_traverse_on_neutral_dir() {
    let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
    let dir = tempfile::tempdir().expect("create neutral tempdir (test-user owned)");
    let path = dir.path().to_path_buf();

    grant_traverse_drive_root(&path, sid.as_psid()).expect("grant_traverse_drive_root");
    let mask = sid_ace_mask(&path, sid.as_psid()).expect("sid_ace_mask after grant");
    assert_eq!(
        mask,
        Some(FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0),
        "granted ACE mask must be exactly FILE_TRAVERSE | FILE_READ_ATTRIBUTES"
    );

    revoke_ace(&path, sid.as_psid()).expect("revoke_ace");
    let verified = assert_no_sid_ace(&path, sid.as_psid());
    assert!(
        verified.is_ok(),
        "sandbox SID ACE must be fully removed after revoke_ace: {verified:?}"
    );
}

/// `grant_traverse_chain`が祖先を浅い方(ドライブルート)から深い方(target自身)へ、
/// 重複なく列挙することを確認する（Win32呼び出しを伴わない純粋なパス演算のみ、
/// クロスプラットフォームで実行可能）。実際のACE付与成否は
/// `grant_traverse_chain_then_revoke_each_node_on_neutral_tree`（ignore-gated）で確認する。
#[test]
fn grant_traverse_chain_orders_ancestors_shallow_to_deep() {
    let target = Path::new(r"C:\Users\example\.cargo");
    let mut chain: Vec<std::path::PathBuf> =
        target.ancestors().map(|p| p.to_path_buf()).collect();
    chain.reverse();
    assert_eq!(
        chain,
        vec![
            std::path::PathBuf::from(r"C:\"),
            std::path::PathBuf::from(r"C:\Users"),
            std::path::PathBuf::from(r"C:\Users\example"),
            std::path::PathBuf::from(r"C:\Users\example\.cargo"),
        ]
    );
}

/// `grant_traverse_chain`が多階層のネストしたディレクトリ全てへ個別にACEを付与し、
/// `revoke_ace`で1件ずつ巻き戻せることを確認する（`TIER1A-OPEN-ISSUES.md`項目6
/// 「多階層祖先traverse ACE不足」の解消の中核）。
///
/// **[BUG-011の教訓、事故から得た設計]** 当初このテストは`tempfile::tempdir()`
/// （`%TEMP%`配下）にネストを作っていたが、`%TEMP%`は実際には
/// `C:\Users\<user>\AppData\Local\Temp\...`という**本物のユーザープロファイルの奥深く**に
/// あるため、`grant_traverse_chain`が`Path::ancestors()`で祖先を辿ると、`C:\Users`・
/// `C:\Users\<user>`（ユーザープロファイル本体）にまで実際のDACL変更が及んでしまい、
/// 実機E2Eで「`C:\Users\<user>`へのDACL変更が数分単位で止まる」という重大インシデントを
/// 起こした（実行中のプロファイルルートへのSetNamedSecurityInfoWは、ローミングプロファイル・
/// インデクサ・AV等の割込みで極端に遅くなりうる。強制終了2回により孤立ACEが
/// `C:\Users`・`C:\Users\<user>`に残置し、`icacls /remove:g`での手動復旧を要した）。
///
/// 修正: 実機診断で使っていた`C:\harness-Tier2a-verify-*-<pid>`
/// パターンを踏襲し、**このテスト専用に新規作成した`C:\`直下のディレクトリ**をネストの
/// 起点にする。これなら`grant_traverse_chain`の祖先チェーンは`C:\`（既存の永続ACE、
/// D10の恒久的な修復として意図的に維持されているためrevokeしない）とこのテスト専用ツリー
/// のみで完結し、実プロファイルツリーには一切触れない。
///
/// `C:\`自体への`WRITE_DAC`が要るため、このテストは`#[ignore]`に加えて**管理者シェルから
/// の実行が必須**（`sudo cargo test -p harness-sandbox -- --ignored
/// grant_traverse_chain_then_revoke_each_node_on_neutral_tree`）。
#[test]
#[ignore]
fn grant_traverse_chain_then_revoke_each_node_on_neutral_tree() {
    let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");
    let test_root = std::path::PathBuf::from(format!(
        "C:\\harness-Tier2a-verify-chain-{}",
        std::process::id()
    ));
    let nested = test_root.join("a").join("b").join("c");
    std::fs::create_dir_all(&nested).expect(
        "create test-owned nested dirs directly under C:\\ (needs admin write on drive root)",
    );

    let (granted, result) = grant_traverse_chain(&nested, sid.as_psid());
    // 掃除は成否に関わらず必ず行う(孤立ACE防止、BUG-011の再発防止そのもの)。
    let cleanup = || {
        // granted[0]はドライブルート(C:\)自身。D10の恒久的な修復として意図的に維持されて
        // いる既存ACEなので、このテストの後始末では**絶対に触らない**。
        for node in granted.iter().skip(1) {
            let _ = revoke_ace(node, sid.as_psid());
        }
        let _ = std::fs::remove_dir_all(&test_root);
    };

    if let Err(e) = &result {
        cleanup();
        panic!("grant_traverse_chain should succeed on a test-owned tree under C:\\: {e:?}");
    }

    // test_root + a + b + c の4ノード(C:\自身は別途、既に前提として存在する)。
    if granted.len() != 5 {
        cleanup();
        panic!("expected 5 granted nodes (C:\\ + test_root + a + b + c), got {granted:?}");
    }
    if granted.last() != Some(&nested) {
        cleanup();
        panic!("last granted node must be the target itself: {granted:?}");
    }

    for node in &granted {
        match sid_ace_mask(node, sid.as_psid()) {
            Ok(mask) if mask == Some(FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0) => {}
            other => {
                cleanup();
                panic!(
                    "node {node:?} must have exactly FILE_TRAVERSE | FILE_READ_ATTRIBUTES, got {other:?}"
                );
            }
        }
    }

    // ドライブルートを除く各ノードでrevoke -> 検証の往復を確認する。
    for node in granted.iter().skip(1) {
        if let Err(e) = revoke_ace(node, sid.as_psid()) {
            cleanup();
            panic!("revoke_ace for {node:?}: {e}");
        }
        if let Err(e) = assert_no_sid_ace(node, sid.as_psid()) {
            cleanup();
            panic!(
                "sandbox SID ACE must be fully removed from {node:?} after revoke_ace: {e:?}"
            );
        }
    }

    let _ = std::fs::remove_dir_all(&test_root);
}





/// `path`のDACLに`PROTECTED_DACL_SECURITY_INFORMATION`を立て、祖先からの継承ACEが
/// このノード配下へ伝播するのを遮断する。**このとき`path`が現在実効的に持つ全ACE
/// （継承由来含む）を`GetExplicitEntriesFromAclW`で吸い出し、明示ACEとして保持し直す**
/// ため、Administrators/自分自身等の既存アクセスは失われない（0 ACEにはしない）。
///
/// 当初の実装は`GetExplicitEntriesFromAclW`で現在のACEを吸い出してから`SetEntriesInAclW`で
/// 組み直す方式だったが、`GetExplicitEntriesFromAclW`は**継承フラグ（`INHERITED_ACE`）が
/// 立ったACEを一切拾わない**（名前どおり「明示」ACEのみが対象）ため、対象ディレクトリの
/// ACEが全て継承由来（新規作成した子ディレクトリの典型）の場合は`count=0`になり、
/// `SetEntriesInAclW(&[], None, ...)`が`new_dacl=NULL`を返してしまう。`SetNamedSecurityInfoW`
/// に`pDacl=NULL`を渡すと「DACLそのものが無い＝誰でもフルコントロール」という最も危険な
/// 状態になり、`grant_ace_ro(root)`自体は成功するのに対象ディレクトリのアクセス制御が
/// 消え去るという事故を招いた（実機の`icacls`出力`"アクセスが設定されていません。すべての
/// ユーザーがフル コントロールを保持しています。"`で発覚）。
///
/// 修正: ACEを個別に吸い出して再構築する必要は無い。`GetNamedSecurityInfoW`が返す
/// `existing_dacl`は、継承由来かどうかを問わず**今この瞬間に有効な全ACEが物理的に
/// 格納された実体**（NTFSは継承ACEを都度計算せず子オブジェクトへ都度複製して保持する）
/// なので、そのポインタをそのまま`PROTECTED_DACL_SECURITY_INFORMATION`付きで書き戻すだけで
/// 「今の実効アクセスを凍結しつつ、以後の祖先からの継承だけを遮断する」が実現できる
/// （`.NET`の`SetAccessRuleProtection(true, true)`が内部で行うのと同じ操作）。
fn protect_dacl_preserve_inherited(path: &Path) -> windows::core::Result<()> {
    use windows::Win32::Security::PROTECTED_DACL_SECURITY_INFORMATION;
    unsafe {
        let path_w = wide(&path.to_string_lossy());
        let mut existing_dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing_dacl),
            None,
            &mut sd,
        )
        .ok()?;

        let result = windows::Win32::Security::Authorization::SetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(existing_dacl as *const _),
            None,
        )
        .ok();

        let _ = LocalFree(HLOCAL(sd.0));
        result
    }
}

/// Phase B-2の本実装（`grant_ace_inheritable_ro`）の実機検証。Experiment L
/// （`docs/phases/foundation/M12-shell-isolation-tiers.md`）は継承ONの
/// 単純ツリー1本しか検証しておらず、「保護DACL（継承を無効にした）子が混在するツリーでも
/// 全ノードへ読取が届くか」は未確認だった。このテストは(1)通常の子孫（継承伝播で届く）と
/// (2)`protect_dacl_preserve_inherited`で継承のみ意図的に遮断した子孫（既存の実効アクセスは
/// 保持したまま、フォールバックの明示付与が要る）を同じツリーに混在させ、
/// `grant_ace_inheritable_ro`が両方を読めるようにし、かつ`revoke_ace_recursive`で完全に
/// 撤収できることを確認する。
#[test]
#[ignore]
fn grant_ace_inheritable_ro_falls_back_for_protected_descendant() {
    let sid = ensure_profile(CONTAINER_NAME).expect("ensure_profile");

    let workspace = std::path::PathBuf::from(format!(
        "C:\\harness-Tier2a-verify-m-ws-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&workspace).expect("create workspace");
    grant_ace_recursive(&workspace, sid.as_psid()).expect("grant_ace_recursive on workspace");
    let probe_dir = workspace
        .join(".harness")
        .join("sandbox")
        .join("Tier2a-tmp");
    std::fs::create_dir_all(&probe_dir).expect("create probe dir");
    if let Err(e) = smoke_test_spawn(sid.as_psid(), &workspace, &probe_dir) {
        eprintln!(
            "skipping grant_ace_inheritable_ro_falls_back_for_protected_descendant: \
             workspace FS I/O gate failed on this machine ({e:?}); run `harness fs \
             grant-traverse C:\\` as administrator first (D10)"
        );
        let _ = std::fs::remove_dir_all(&workspace);
        return;
    }

    let root = std::path::PathBuf::from(format!(
        "C:\\harness-Tier2a-verify-m-{}",
        std::process::id()
    ));

    // 通常branch: root -> normal -> deep -> preexisting.txt（継承伝播で届く想定）。
    let normal_deep = root.join("normal").join("deep");
    std::fs::create_dir_all(&normal_deep).expect("create normal branch");
    let normal_file = normal_deep.join("preexisting.txt");
    std::fs::write(&normal_file, b"reachable via inheritance").expect("seed normal file");

    // 保護branch: root -> protected（既存アクセスは保持したまま継承のみ遮断）-> deep -> blocked.txt。
    let protected_dir = root.join("protected");
    let protected_deep = protected_dir.join("deep");
    std::fs::create_dir_all(&protected_deep).expect("create protected branch");
    let protected_file = protected_deep.join("blocked.txt");
    std::fs::write(&protected_file, b"needs fallback explicit grant")
        .expect("seed protected file");
    protect_dacl_preserve_inherited(&protected_dir)
        .expect("protect_dacl_preserve_inherited on protected dir");

    let grant_result = grant_ace_inheritable_ro(&root, sid.as_psid());
    assert!(
        grant_result.is_ok(),
        "grant_ace_inheritable_ro should succeed on a tree with a protected-DACL child: \
         {grant_result:?}"
    );

    let normal_read_ok = run_probe_bool(
        sid.as_psid(),
        &workspace,
        &format!(
            "Get-Content -LiteralPath '{}' | Out-Null",
            normal_file.display()
        ),
    );
    assert!(
        normal_read_ok,
        "normal branch (reached via inheritance propagation) must be readable"
    );

    let protected_read_ok = run_probe_bool(
        sid.as_psid(),
        &workspace,
        &format!(
            "Get-Content -LiteralPath '{}' | Out-Null",
            protected_file.display()
        ),
    );
    assert!(
        protected_read_ok,
        "protected-DACL branch must be readable via the fallback explicit grant"
    );

    // 完全撤収の確認（D4）。保護フラグ自体は残るが、sid ACEは全ノードから消えるべき。
    revoke_ace_recursive(&root, sid.as_psid()).expect("revoke_ace_recursive");
    let leftover = assert_no_sid_ace_recursive(&root, sid.as_psid());
    assert!(
        leftover.is_ok(),
        "sandbox SID ACE must be fully removed from every node, including the protected \
         branch, after revoke_ace_recursive: {leftover:?}"
    );

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&workspace);
}

/// [S1スパイク] Tier3のSMB使い捨てワークスペース共有（`crates/harness-sandbox/src/
/// smb_share.rs`、未コミット作業中）が使い捨てローカルアカウントへNTFSアクセス権を
/// 付与する手段として`grant_ace_inheritable_rw`/`revoke_ace`を再利用できるかを検証する。
/// AppContainer SID（`ensure_profile`）ではなく、実際に`New-LocalUser`で作る**通常の
/// ローカルアカウント**のSIDに対して同じ関数が機能すること、および往復が体感1秒未満で
/// 終わること（BUG-011の365,903件SetSecurityFile・93秒超という病的な遅さの再発防止、
/// `grant_ace_mask`が単一オブジェクトAPI経由であることの実機確認）を確かめる。
///
/// `grant_ace_inheritable_rw`自体はルートへの書込みは1回だが、既存子孫への読取確認
/// walk（`sid_ace_mask`）はO(n)で残ることがdocに明記されている。ここでは(a)小さいツリー
/// （数ファイル）と(b)実際のワークスペース規模に近いツリー（数百ファイル）の両方を計測し、
/// どちらも実用的な時間で終わることを確認する。
#[test]
#[ignore]
fn grant_and_revoke_inheritable_rw_for_a_real_local_user_account_is_fast() {
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;

    let unique = std::process::id();
    let user = format!("hns3spike{unique}");
    let password = "Sp1ke!Test-Pw-Do-Not-Reuse";

    // 使い捨てローカルアカウントを作成し、SID文字列を取得する
    // （`smb_share.rs::create_ephemeral_share`が実運用でやるのと同じ形、stdin経由で
    // パスワードを渡しコマンドライン上に露出させない）。
    let create_script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$securePassword = ConvertTo-SecureString '{password}' -AsPlainText -Force
New-LocalUser -Name '{user}' -Password $securePassword -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
(Get-LocalUser -Name '{user}').SID.Value
"#
    );
    let sid_string = run_powershell_stdin_for_test(&create_script)
        .expect("New-LocalUser + SID lookup must succeed (run under sudo cargo test)");
    assert!(
        !sid_string.is_empty(),
        "expected a non-empty SID string from Get-LocalUser"
    );

    let cleanup_user = || {
        let _ = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!("Remove-LocalUser -Name '{user}' -ErrorAction SilentlyContinue"),
            ])
            .output();
    };

    let sid_owned = unsafe {
        let sid_w = crate::win_common::wide(&sid_string);
        let mut psid = PSID::default();
        ConvertStringSidToSidW(PCWSTR(sid_w.as_ptr()), &mut psid)
            .expect("ConvertStringSidToSidW must parse Get-LocalUser's SID string");
        psid
    };

    // `C:\`直下は既定でBUILTIN\Usersに読み取りが継承付与されていることが多く（使い捨て
    // ローカルアカウントもUsersグループのメンバー）、そこにツリーを置くと「読めた/読めなく
    // なった」がこちらの明示的な付与/取り消しではなく既定のUsers権限に起因するのか区別
    // できない（`/inheritance:r`で継承ACEを剥がす案も試したが、DACLが空になり自分自身の
    // 書込みまで拒否されて壊れた）。ユーザープロファイル配下（`%TEMP%`）はNTFS既定で
    // 所有者+SYSTEM+Administratorsのみに絞られておりBUILTIN\Usersへの既定付与が無いため、
    // ここにツリーを置くことで「読めるかどうかは完全にこちらの明示的な付与/取り消しに
    // 依存する」検証環境になる。
    let spike_base = std::env::temp_dir().join(format!("harness-tier3-spike-s1-{unique}"));

    // (a) 小さいツリー: ルート + 数階層のネストした既存ファイル数個。
    let small_root = spike_base.join("small");
    std::fs::create_dir_all(small_root.join("a").join("b")).expect("create small tree");
    std::fs::write(small_root.join("a").join("b").join("f.txt"), b"hi").expect("seed file");

    // (b) ワークスペース規模に近いツリー: 数百ファイル。
    let big_root = spike_base.join("big");
    for i in 0..20u32 {
        let dir = big_root.join(format!("dir{i}"));
        std::fs::create_dir_all(&dir).expect("create big tree dir");
        for j in 0..20u32 {
            std::fs::write(dir.join(format!("file{j}.txt")), b"payload")
                .expect("seed big tree file");
        }
    }

    let cleanup_trees = || {
        let _ = std::fs::remove_dir_all(&spike_base);
    };

    // [BUG-020回帰テスト] `small_root/a/b`（ネストしたディレクトリ、必ずしも継承ACEの
    // 直接付与先=rootではない方）のDACLを、grant/revokeサイクルの前後で比較する。
    // 旧実装は`revoke_ace_recursive`が全ノードを`PROTECTED_DACL_SECURITY_INFORMATION`で
    // 恒久的に凍結してしまい、%TEMP%祖先から継承していたSYSTEM/Administrators/所有者の
    // `(I)`フラグが失われた状態のまま戻らなかった（BUG-020）。ここでは`icacls`の生出力
    // （`(I)`フラグの有無を含む）をgrant前とrevoke後で完全一致させることで、この副作用が
    // 再発しないことを機械的に検証する。
    let nested_dir = small_root.join("a").join("b");
    let icacls_output = |path: &Path| -> String {
        std::process::Command::new("icacls")
            .arg(path)
            .output()
            .map(|o| crate::decode_console_bytes(&o.stdout))
            .unwrap_or_default()
    };
    let baseline_icacls = icacls_output(&nested_dir);

    let result = (|| -> Result<(), String> {
        // ベースライン確認: 付与前は読めないこと（プロファイル配下の既定ACLで隔離されて
        // いることの確認、これが崩れていると以降のgrant/revoke確認が無意味になる）。
        let probe_target_pre = small_root.join("a").join("b").join("f.txt");
        let can_read_before_grant = run_as_local_user(
            &user,
            password,
            &format!(
                "try {{ Get-Content -LiteralPath '{}' -ErrorAction Stop | Out-Null; exit 0 }} catch {{ exit 1 }}",
                probe_target_pre.display()
            ),
        );
        if can_read_before_grant {
            return Err(
                "baseline check failed: the ephemeral local user could already read the \
                 file before any grant — %TEMP% is not isolated from BUILTIN\\Users on \
                 this machine, the rest of this test's conclusions would be meaningless"
                    .to_string(),
            );
        }

        let t0 = std::time::Instant::now();
        grant_ace_inheritable_rw(&small_root, sid_owned)
            .map_err(|e| format!("grant on small tree failed: {e:?}"))?;
        let small_grant_elapsed = t0.elapsed();
        println!(
            "=== S1: small tree grant_ace_inheritable_rw took {small_grant_elapsed:?} ==="
        );
        assert!(
            small_grant_elapsed < std::time::Duration::from_secs(2),
            "small-tree grant must finish well under 1-2s, took {small_grant_elapsed:?}"
        );

        let t1 = std::time::Instant::now();
        grant_ace_inheritable_rw(&big_root, sid_owned)
            .map_err(|e| format!("grant on big tree (400 files) failed: {e:?}"))?;
        let big_grant_elapsed = t1.elapsed();
        println!(
            "=== S1: 400-file tree grant_ace_inheritable_rw took {big_grant_elapsed:?} ==="
        );
        assert!(
            big_grant_elapsed < std::time::Duration::from_secs(5),
            "400-file tree grant must not regress toward BUG-011-style pathological slowness, \
             took {big_grant_elapsed:?}"
        );

        // revokeもO(n)（物理コピーされたACEを個別に消す、上記コメント参照）であるため、
        // 400ファイル規模での実測値も取っておく（grant/revoke双方のO(n)係数を見るため）。
        let t_big_revoke = std::time::Instant::now();
        revoke_ace_recursive(&big_root, sid_owned)
            .map_err(|e| format!("revoke_ace_recursive on big tree failed: {e:?}"))?;
        let big_revoke_elapsed = t_big_revoke.elapsed();
        println!("=== S1: 400-file tree revoke_ace_recursive took {big_revoke_elapsed:?} ===");

        // 実際にそのローカルアカウントとしてファイルを読める/書けることを確認する
        // （ACEが付いているというだけでなく、実効アクセスとして機能することの確認）。
        let probe_target = small_root.join("a").join("b").join("f.txt");
        let can_read_after_grant =
            run_as_local_user(&user, password, &format!(
                "try {{ Get-Content -LiteralPath '{}' -ErrorAction Stop | Out-Null; exit 0 }} catch {{ exit 1 }}",
                probe_target.display()
            ));
        assert!(
            can_read_after_grant,
            "the ephemeral local user must be able to read a pre-existing nested file \
             after grant_ace_inheritable_rw (this is the actual SMB-share access scenario, \
             not just ACE presence)"
        );

        let write_target = small_root.join("a").join("b").join("new-from-user.txt");
        let can_write_after_grant =
            run_as_local_user(&user, password, &format!(
                "try {{ 'written' | Set-Content -LiteralPath '{}' -ErrorAction Stop; exit 0 }} catch {{ exit 1 }}",
                write_target.display()
            ));
        assert!(
            can_write_after_grant,
            "the ephemeral local user must be able to write a new file under the \
             inheritable-ACE root after grant_ace_inheritable_rw"
        );

        // [S1発見] `revoke_ace(root)`だけでは不十分だった: NTFSの継承ACEは親への参照
        // ではなく子オブジェクト作成時点で物理的に複製される実体（Phase B-2の知見どおり）
        // であるため、`grant_ace_inheritable_rw`のルート付与は実質的に全既存子孫へ物理コピー
        // を作る（だからこそgrant側はO(1)で済む）。revoke側はこの物理コピーを個別に消す
        // 必要があり、構造的にO(n)にならざるを得ない。`revoke_ace`（非再帰・単一ノード）を
        // 使った初回の実装は、rootのACEは消えても子孫の物理コピーが残るため`f.txt`が読める
        // ままという実機不具合を引き起こした（本テストで実際に検出・修正）。正しくは
        // `revoke_ace_recursive`（既存の再walk版）を使う。
        let t2 = std::time::Instant::now();
        revoke_ace_recursive(&small_root, sid_owned)
            .map_err(|e| format!("revoke_ace_recursive on small tree failed: {e:?}"))?;
        let revoke_elapsed = t2.elapsed();
        println!(
            "=== S1: revoke_ace_recursive (small tree, O(n) walk) took {revoke_elapsed:?} ==="
        );
        assert!(
            revoke_elapsed < std::time::Duration::from_secs(2),
            "revoke_ace_recursive on a small tree must still be fast, took {revoke_elapsed:?}"
        );

        if let Ok(out) = std::process::Command::new("icacls")
            .arg(&probe_target)
            .output()
        {
            println!(
                "=== S1 DEBUG: icacls on {} after revoke_ace_recursive ===\n{}",
                probe_target.display(),
                crate::decode_console_bytes(&out.stdout)
            );
        }

        // [BUG-020回帰assert] grant前後でのDACL完全一致確認（`(I)`フラグの有無を含む）。
        // 一致しなければ、grant/revokeサイクルがこのノードの継承状態を恒久的に変えて
        // しまったことを意味する（`nested_dir`は`grant_ace_inheritable_rw`のroot自身では
        // なく、rootへの付与がNTFSの物理複製で遡及した既存の子孫ノード——BUG-020が
        // 実際に壊していたのはこちら側）。
        let post_revoke_icacls = icacls_output(&nested_dir);
        if post_revoke_icacls != baseline_icacls {
            return Err(format!(
                "BUG-020 regression: DACL of {} does not match its pre-grant baseline after \
                 grant_ace_inheritable_rw + revoke_ace_recursive (inheritance was not fully \
                 restored)\n--- baseline ---\n{baseline_icacls}\n--- after revoke ---\n{post_revoke_icacls}",
                nested_dir.display()
            ));
        }

        let can_read_after_revoke =
            run_as_local_user(&user, password, &format!(
                "try {{ Get-Content -LiteralPath '{}' -ErrorAction Stop | Out-Null; exit 0 }} catch {{ exit 1 }}",
                probe_target.display()
            ));
        assert!(
            !can_read_after_revoke,
            "after revoke_ace, the ephemeral local user must no longer be able to read \
             the file (proves the ACE was actually removed, not just the account deleted)"
        );

        Ok(())
    })();

    cleanup_trees();
    cleanup_user();
    result.expect("S1 spike must succeed end-to-end");
}

/// パスワードをコマンドライン上に晒さずstdin経由でPowerShellへ渡す
/// （`smb_share.rs::run_powershell_stdin`と同じ規律をこのテストモジュールでも守る）。
fn run_powershell_stdin_for_test(script: &str) -> Result<String, String> {
    use std::io::Write;
    let mut child = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", "-"])
        // `vmsandbox::run_powershell`と同じ罠: 常駐管理者pwsh(7)から起動すると継承した
        // `PSModulePath`のせいで`Microsoft.PowerShell.Security`のオートロードが壊れ、
        // `ConvertTo-SecureString`が非終端エラーで静かに失敗する。
        .env_remove("PSModulePath")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn powershell.exe: {e}"))?;
    child
        .stdin
        .take()
        .ok_or("powershell stdin unavailable")?
        .write_all(script.as_bytes())
        .map_err(|e| e.to_string())?;
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "exit={:?} stderr={}",
            output.status.code(),
            crate::decode_console_bytes(&output.stderr)
        ));
    }
    Ok(crate::decode_console_bytes(&output.stdout).trim().to_string())
}

/// `Start-Process -Credential`でSMBの実効アクセスに近い形（実際のログオンセッション、
/// AppContainerのspawnヘルパーとは別経路）で1コマンドを実行し、成功/失敗をbool化する。
/// パスワードはstdin経由ではなく`-Credential`引数化のためこの関数内で組み立てるが、
/// テスト専用の使い捨てパスワードのみを扱う（本番コード`smb_share.rs`はstdin経由を守る）。
fn run_as_local_user(user: &str, password: &str, inner_command: &str) -> bool {
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$securePassword = ConvertTo-SecureString '{password}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('{user}', $securePassword)
$p = Start-Process powershell.exe -Credential $cred -ArgumentList '-NoProfile','-NonInteractive','-Command','{inner}' -WindowStyle Hidden -PassThru -Wait -WorkingDirectory "$env:SystemRoot\Temp"
exit $p.ExitCode
"#,
        inner = inner_command.replace('\'', "''")
    );
    match std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .env_remove("PSModulePath")
        .output()
    {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

/// **workspace封じ込めがセッションを跨いで保たれること**（D-37の受け入れ条件、
/// `docs/STATUS.md`旧Tier2a残課題#9）。
///
/// D-37以前は全セッションが固定名のプロファイル＝同一package SIDで動き、`preflight`が付けた
/// workspace ACEも撤収されなかったため、**あるworkspaceのサンドボックスから、過去にharnessが
/// 開いた別のworkspaceの中身が読めた**（実測済み）。セッションごとに別プロファイルへ分けた
/// 今は、セッションAのSIDにセッションBのworkspaceのACEが無いので構造的に届かない。
#[test]
#[ignore = "spawns a real AppContainer child and grants ACEs to two temp workspaces"]
fn a_sandbox_cannot_reach_another_sessions_workspace() {
    // 2つの**別セッション**を模す（D-37: プロファイル名がセッションごとに変わる）。
    let name_a = crate::tier2a::session_profile::profile_name_for("test-session-a");
    let name_b = crate::tier2a::session_profile::profile_name_for("test-session-b");
    let sid_a = ensure_profile(&name_a).expect("session A profile");
    let sid_b = ensure_profile(&name_b).expect("session B profile");

    // 各セッションは自分のworkspaceにだけACEを持つ。
    let ws_a = tempfile::tempdir().unwrap();
    grant_ace_inheritable_rw(ws_a.path(), sid_a.as_psid()).expect("grant ws_a to session A");
    let ws_b = tempfile::tempdir().unwrap();
    grant_ace_inheritable_rw(ws_b.path(), sid_b.as_psid()).expect("grant ws_b to session B");
    let secret = ws_b.path().join("other-workspace-secret.txt");
    std::fs::write(&secret, "SECRET_FROM_OTHER_WORKSPACE").unwrap();

    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    let command = format!(
        "try {{ Get-Content -Path '{}' -ErrorAction Stop }} catch {{ Write-Output \"DENIED: $_\" }}",
        secret.display()
    );
    // セッションAのSIDで起動した子から、セッションBのworkspaceを読みにいく。
    let child = spawn(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", &command],
        ws_a.path(),
        &env,
        false,
        sid_a.as_psid(),
        NetworkCapability::Deny,
        None,
    )
    .expect("spawn AppContainer child in session A");
    let (stdout, stderr, _code) = child.write_stdin_read_output_and_wait(None).unwrap();
    eprintln!("[probe] セッションAの子から セッションBのworkspace を読んだ結果:
{stdout}{stderr}");

    let leaked = stdout.contains("SECRET_FROM_OTHER_WORKSPACE");
    eprintln!("[probe] 別セッションのworkspaceが読めたか: {leaked}");

    // 後始末（テストが作ったACEとプロファイルを撤収する。順序はACE→プロファイル）。
    let _ = revoke_ace_recursive(ws_a.path(), sid_a.as_psid());
    let _ = revoke_ace_recursive(ws_b.path(), sid_b.as_psid());
    for name in [&name_a, &name_b] {
        unsafe {
            let w = crate::win_common::wide(name);
            let _ = windows::Win32::Security::Isolation::DeleteAppContainerProfile(
                windows::core::PCWSTR(w.as_ptr()),
            );
        }
    }

    assert!(
        !leaked,
        "別セッションのworkspaceの中身がサンドボックスから読めている（D-37が崩れている）"
    );
}
