//! D-30（Tier2a `--cow`）の封じ込め・操作台帳の実機E2E。
//!
//! **旧称`cow_diagnostics`**（`docs/bugs/BUG-033.md`・`BUG-035`・`BUG-037`・`BUG-041`〜`BUG-043`
//! 等の過去の記録と再現コマンドはこの名前で参照している。対応表は
//! `docs/refactor/2026-08-03-experiment-tests-removal.md`）。
//!
//! 実行前に`cargo build -p harness-redirector -p harness-sandbox --tests`を行い、
//! `target/debug/harness_redirector.dll`をテストバイナリと同じディレクトリ（`target/debug/deps/`）
//! へコピーすること（`redirector_dll_path`は`current_exe()`の親を見るため、実運用の
//! `harness.exe`同梱と揃える）。x86 DLLとプローブアプリの配置を含む手順は
//! `docs/DEV-ENVIRONMENT.md`を参照。
//!
//! **`--test-threads=1`で実行すること。** 並列だとAppContainerプロファイル・共有祖先への
//! traverse ACE付与といったマシン全体の共有状態を複数テストが同時に触るため不安定になる。

use super::test_support::{scopeguard, spawn_in_workspace};
use super::*;
use crate::manifest::ManifestOp;
use crate::overlay::{ApplyOptions, ApplyReport, SandboxError, SandboxFs};
use harness_core::{ReadScopeConfig, StagingConfig};

/// CoW一本化（Phase 2）後の`--cow` apply呼び出しヘルパー。`changes::apply_unified_changes`
/// （Phase 2で削除、`SandboxFs`自身が唯一のapply実装になった）の実機E2Eテストからの
/// 呼び出しをこの薄いラッパへ置き換えている。
fn apply_cow(
    upper_dir: &std::path::Path,
    workspace_root: &std::path::Path,
    opts: &ApplyOptions,
) -> Result<ApplyReport, SandboxError> {
    let fs = SandboxFs::open_with_cow(
        workspace_root,
        &StagingConfig::default(),
        &ReadScopeConfig::default(),
        Some(upper_dir),
    )?;
    fs.apply(opts)
}
use std::sync::Mutex;

/// `cow_write_from_wow64_grandchild_process_is_redirected_to_upper`と
/// `cow_wow64_grandchild_without_x86_dll_fails_closed_with_warning`は、テストバイナリの
///隣にある`harness_redirector_x86.dll`という単一の共有ファイルを読む/一時的にリネームする。
/// `cargo test`は既定で`#[test]`関数を並行実行するため、この2つを直列化しないと片方が
/// リネーム中にもう片方が「ファイルが見つからない」で誤って失敗し得る（実機で確認済み）。
static WOW64_DLL_TEST_LOCK: Mutex<()> = Mutex::new(());

const COW_WRITE_PROBE_COMMAND: &str = "\
    $ErrorActionPreference = 'Stop'; \
    try { \
        Set-Content -LiteralPath 'important.txt' -Value 'modified-by-child' -NoNewline; \
        New-Item -ItemType File -Path 'new.txt' -Force | Out-Null; \
        Set-Content -LiteralPath 'new.txt' -Value 'created-by-child' -NoNewline; \
        exit 0 \
    } catch { \
        Write-Output $_.Exception.Message; \
        exit 9 \
    }";

/// 境界（Phase 1）+ 透過（Phase 2）を通しで確認する。workspaceをROで付与し、Redirector DLLを
/// 注入したAppContainer子から`important.txt`を上書き・`new.txt`を新規作成させる。
/// 期待結果: 子は成功（exit 0）、workspace本体は不変、upperへ変更が反映される。
#[test]
#[ignore]
fn cow_write_is_redirected_to_upper_and_workspace_stays_unchanged() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let upper = tempfile::tempdir().expect("upper tempdir");
    std::fs::write(workspace.path().join("important.txt"), "original").expect("seed important.txt");

    let sid = session_sid();
    let write_mode = WorkspaceWriteMode::Cow {
        upper_dir: upper.path().to_path_buf(),
    };
    preflight(workspace.path(), &[], None, &write_mode).expect("preflight (cow)");

    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    let child = spawn_in_workspace(
        &shell,
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            COW_WRITE_PROBE_COMMAND,
        ],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        Some(CowInject {
            workspace_root: workspace.path(),
            upper_dir: upper.path(),
            ext_capture_roots: &[],
        }),
    )
    .expect("spawn with cow injection should succeed");
    let (stdout, stderr, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("child should run to completion");

    assert_eq!(
        code, 0,
        "child write should succeed via redirector (stdout={stdout} stderr={stderr})"
    );

    let workspace_content = std::fs::read_to_string(workspace.path().join("important.txt"))
        .expect("workspace important.txt must still exist");
    assert_eq!(
        workspace_content, "original",
        "workspace body must remain unchanged (boundary=ACL, not the hook)"
    );
    assert!(
        !workspace.path().join("new.txt").exists(),
        "new file must not appear in workspace"
    );

    let upper_content = std::fs::read_to_string(upper.path().join("important.txt"))
        .expect("upper important.txt must exist after copy-up + redirected write");
    assert_eq!(upper_content, "modified-by-child");
    let upper_new_content =
        std::fs::read_to_string(upper.path().join("new.txt")).expect("upper new.txt must exist");
    assert_eq!(upper_new_content, "created-by-child");
}

/// **BUG-066の追加検証（2026-08-06）**: `HARNESS_COW_WORKSPACE`の綴りが揺れても、DLL単体で
/// リダイレクトが成立することを実機で確かめる。
///
/// 2026-08-05の障害では、DLLがworkspace内の絶対パスを**workspace外と判定**して全書込がACL拒否に
/// なっていた。候補だった綴りは4つ（相対パス・大小差・末尾区切り・`\\?\`前置）で、どれだったかは
/// 残存証跡から特定できない。ここでは4つとも**実際にDLLへ届けて**結果を測る。
///
/// **正規化をすり抜けて生の綴りを届ける方法**: `spawn`は呼び出し側の`env`をそのまま子へ渡し、
/// 自分の`HARNESS_COW_WORKSPACE`（`normalize_cow_root`済み）は**後から**push する。
/// `build_env_block`の`sort_by_key`は安定ソートなので、呼び出し側が積んだ同名エントリが前に並び、
/// 環境ブロックの線形探索では前勝ちになる。**この前提は推測しない**——プローブに
/// `$env:HARNESS_COW_WORKSPACE`を印字させ、テスト自身が「生の綴りが届いたこと」を確認してから
/// 結果を解釈する。
#[test]
#[ignore]
fn cow_redirect_survives_every_workspace_root_spelling() {
    // (ラベル, 綴りの作り方, リダイレクトが成立すべきか)
    type Spelling = (&'static str, fn(&std::path::Path) -> String, bool);
    let spellings: &[Spelling] = &[
        (
            "control (as-is)",
            |p| p.to_string_lossy().into_owned(),
            true,
        ),
        ("uppercased", |p| p.to_string_lossy().to_uppercase(), true),
        (
            "trailing separator",
            |p| format!("{}\\", p.to_string_lossy()),
            true,
        ),
        (
            "verbatim prefix",
            |p| format!(r"\\?\{}", p.to_string_lossy()),
            true,
        ),
        // 相対パスだけは判定規則では救えない（絶対パスと照合しようがない）。**黙って壊れる
        // のではなく名乗る**ことがここでの合格条件になる。
        ("relative (--cwd .)", |_| ".".to_string(), false),
    ];

    for (label, make_spelling, expect_redirect) in spellings {
        let workspace = tempfile::tempdir().expect("workspace tempdir");
        let upper = tempfile::tempdir().expect("upper tempdir");
        std::fs::write(workspace.path().join("important.txt"), "original")
            .expect("seed important.txt");

        let sid = session_sid();
        let write_mode = WorkspaceWriteMode::Cow {
            upper_dir: upper.path().to_path_buf(),
        };
        // ACL付与は常に**実パス**で行う（実験対象はDLLが受け取る文字列だけに絞る）。
        preflight(workspace.path(), &[], None, &write_mode).expect("preflight (cow)");

        let raw_spelling = make_spelling(workspace.path());
        // 2026-08-05に実際に失敗した操作の形＝**絶対パス指定の書込**。
        let script = format!(
            "Write-Output \"COWWS=$env:HARNESS_COW_WORKSPACE\"; \
             try {{ Set-Content -LiteralPath '{}' -Value 'modified-by-child' -NoNewline; \
             Write-Output 'ABS=ok' }} catch {{ Write-Output 'ABS=fail' }}",
            workspace.path().join("important.txt").display()
        );

        let (shell, _) = resolve_shell();
        let mut env = crate::secret_env::build_child_env();
        // `spawn`が後から積む正規化済みの値より前に並ぶ（安定ソート）。
        env.insert(
            0,
            ("HARNESS_COW_WORKSPACE".to_string(), raw_spelling.clone()),
        );
        let child = spawn_in_workspace(
            &shell,
            &["-NoProfile", "-NonInteractive", "-Command", &script],
            workspace.path(),
            &env,
            false,
            sid.as_psid(),
            NetworkCapability::Deny,
            Some(CowInject {
                workspace_root: workspace.path(),
                upper_dir: upper.path(),
                ext_capture_roots: &[],
            }),
        )
        .expect("spawn with cow injection should succeed");
        let (stdout, stderr, _code) = child
            .write_stdin_read_output_and_wait(None)
            .expect("child should run to completion");

        // 前提の検証: 生の綴りが本当に子へ届いたか（届いていなければ以降の解釈は無意味）。
        assert!(
            stdout.contains(&format!("COWWS={raw_spelling}")),
            "[{label}] premise not met: the raw spelling did not reach the child. \
             expected COWWS={raw_spelling}, stdout={stdout} stderr={stderr}"
        );

        let upper_file = upper.path().join("important.txt");
        let ops = harness_change_ledger::store::read_ledger_entries(upper.path());
        let denied = harness_change_ledger::store::read_denied_log(upper.path());
        let denied_inside: Vec<&str> = denied
            .iter()
            .filter(|e| {
                harness_change_ledger::path_rules::relative_under_root(
                    &e.path,
                    &workspace.path().to_string_lossy(),
                )
                .is_some()
            })
            .map(|e| e.path.as_str())
            .collect();

        if *expect_redirect {
            assert!(
                stdout.contains("ABS=ok"),
                "[{label}] the write must succeed through the redirector: stdout={stdout}"
            );
            assert_eq!(
                std::fs::read_to_string(&upper_file).ok().as_deref(),
                Some("modified-by-child"),
                "[{label}] the write must land in the upper dir"
            );
            assert!(
                ops.iter().any(|e| e.path == "important.txt"),
                "[{label}] the operations ledger must record it: ops={ops:?}"
            );
            assert!(
                denied_inside.is_empty(),
                "[{label}] no write inside the workspace may be denied: {denied_inside:?}"
            );
        } else {
            // 相対パス: リダイレクトは成立しない（構造的に不可能）。**その代わり名乗る**。
            assert!(
                stdout.contains("ABS=fail"),
                "[{label}] the write is expected to be denied by the read-only ACL: stdout={stdout}"
            );
            assert!(
                !upper_file.exists(),
                "[{label}] nothing may reach the upper dir"
            );
            assert!(
                ops.is_empty(),
                "[{label}] the operations ledger stays empty: ops={ops:?}"
            );
            assert!(
                !denied_inside.is_empty(),
                "[{label}] the denied ledger must record the in-workspace attempt so that \
                 `harness changes` can report it as a lost change (BUG-066のC層): denied={denied:?}"
            );
            // 警告台帳のファイル名はRedirector DLL側（`state.rs`）の定数だが、このクレートは
            // DLLへ依存しないので他の警告系テストと同じくリテラルで書く。
            let warnings =
                std::fs::read_to_string(upper.path().join(".harness-cow-warnings.jsonl"))
                    .unwrap_or_default();
            assert!(
                warnings.contains("config_workspace_not_absolute"),
                "[{label}] the DLL must announce why transparency is gone: warnings={warnings:?}"
            );
        }
        // 実workspace本体は全ケースで不変（境界＝ACLはこの実験の影響を受けない）。
        assert_eq!(
            std::fs::read_to_string(workspace.path().join("important.txt")).unwrap(),
            "original",
            "[{label}] the workspace body must never change (boundary = ACL)"
        );
        println!(
            "MEASUREMENT: workspace_root spelling {label:?} -> redirect={} ops={} denied_inside={}",
            stdout.contains("ABS=ok"),
            ops.len(),
            denied_inside.len()
        );
    }
}

/// Phase 3（設計書§19.8）: `--fs-allow <path>:rw`で実際にACE付与できたworkspace外RW穴
/// （`preflight`の`granted_passthrough`）への子プロセスの書込が、Redirector DLLにより
/// `_ext/<key>`経由でupperへcaptureされ、実ターゲットには一切触れないことを確認する。
#[test]
#[ignore]
fn cow_ext_capture_redirects_fs_allow_rw_write_to_upper_and_leaves_real_target_untouched() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let upper = tempfile::tempdir().expect("upper tempdir");
    // `fs_passthrough_ro_then_rw_then_revoke_cycle`と同じ理由（コメント参照）で
    // `C:\`直下1階層に置く（中間祖先のtraverse ACE不足による未解決rw書込を避ける）。
    let external =
        std::path::PathBuf::from(format!("C:\\harness-Tier2a-cow-ext-{}", std::process::id()));
    std::fs::create_dir_all(&external).expect("create external rw root");

    let sid = session_sid();
    let write_mode = WorkspaceWriteMode::Cow {
        upper_dir: upper.path().to_path_buf(),
    };
    let passthrough = [FsPassthrough {
        path: external.clone(),
        access: FsAccess::ReadWrite,
        forced: false,
    }];
    let outcome = preflight(workspace.path(), &passthrough, None, &write_mode)
        .expect("preflight (cow + fs-allow rw)");

    // D-01/D-30: `--cow`下では`--fs-allow <path>:rw`要求でも実ACLは読取のみに留め、
    // 頼まれていない実行権限も付与しない（境界はACLのまま、DLLの`_ext` captureは
    // あくまで透過性。CoWの本質は「変更のあったファイル単位でレビュー・ロールバック
    // できること」であり、明示的にRO/ReadExecなエントリはそもそも書込の余地が無いので
    // 対象外——ユーザー指摘により追加・訂正、2026-08-02）。
    let actual_mask = sid_ace_mask(&external, sid.as_psid())
        .expect("sid_ace_mask should succeed")
        .expect("package SID must have some ACE on the fs-allow root");
    // `FILE_GENERIC_READ`と`FILE_GENERIC_EXECUTE`はSYNCHRONIZE/READ_CONTROL等の
    // 標準ビットを共有するため、個別ビットのAND判定では正しく切り分けられない
    // （どちらのマスクにも0x120080相当が含まれる）。「`fs_access_mask(FsAccess::Read)`と
    // 完全一致」で判定する方が正確。
    assert_eq!(
        actual_mask,
        fs_access_mask(FsAccess::Read),
        "--cow下ではfs-allow:rwでも実ACLはFsAccess::Read相当ちょうどでなければならない\
         （書込/削除はもちろん、頼まれていない実行権限も含まれてはいけない。境界はACL、\
         _ext captureは透過性のみ）: actual_mask={actual_mask:#x}"
    );

    let ext_capture_roots: Vec<std::path::PathBuf> = outcome
        .granted_passthrough
        .iter()
        .filter(|(_, writable)| *writable)
        .map(|(p, _)| p.clone())
        .collect();
    assert!(
        !ext_capture_roots.is_empty(),
        "fs-allow rw grant should have succeeded: {outcome:?}"
    );

    let probe_path = external.join("probe.txt");
    let script = format!(
        "$ErrorActionPreference = 'Stop'; try {{ \
            Set-Content -LiteralPath '{}' -Value 'ext-write' -NoNewline; exit 0 \
        }} catch {{ Write-Output $_.Exception.Message; exit 9 }}",
        probe_path.display()
    );
    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    let child = spawn_in_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", &script],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        Some(CowInject {
            workspace_root: workspace.path(),
            upper_dir: upper.path(),
            ext_capture_roots: &ext_capture_roots,
        }),
    )
    .expect("spawn with cow+ext injection should succeed");
    let (stdout, stderr, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("child should run to completion");
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");

    assert!(
        !probe_path.exists(),
        "real external target must stay untouched (captured into upper's _ext instead)"
    );
    let original = harness_change_ledger::store::normalize_abs_path(&probe_path.to_string_lossy());
    let key = harness_change_ledger::store::ext_key(&original).expect("ext_key");
    let upper_ext_path = upper.path().join("_ext").join(&key);
    assert_eq!(
        std::fs::read_to_string(&upper_ext_path).expect("upper _ext copy must exist"),
        "ext-write"
    );

    let ledger = crate::tier2a::workspace_ledger::read_cow_ledger(upper.path());
    let entry = ledger
        .iter()
        .find(|c| c.path == original)
        .expect("ledger must record the ext write keyed by the original absolute path");
    assert_eq!(entry.op, ManifestOp::Create);

    let _ = std::fs::remove_dir_all(&external);
}

/// Phase 4（設計書§19.8）: workspace内でも`--fs-allow`のRW穴（ext capture root）でもない
/// 絶対パスへの書込試行は、ACLにより実際に拒否され（`STATUS_ACCESS_DENIED`）、その事実が
/// `.harness-cow-denied.jsonl`へ監査記録される（境界自体はACLが保証し、この台帳は
/// 可視性のみ）。
#[test]
#[ignore]
fn cow_denied_write_outside_workspace_and_ext_roots_is_logged() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let upper = tempfile::tempdir().expect("upper tempdir");
    let outside = std::path::PathBuf::from(format!(
        "C:\\harness-Tier2a-cow-denied-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&outside).expect("create outside dir (no ACE granted)");

    let sid = session_sid();
    let write_mode = WorkspaceWriteMode::Cow {
        upper_dir: upper.path().to_path_buf(),
    };
    preflight(workspace.path(), &[], None, &write_mode).expect("preflight (cow)");

    let probe_path = outside.join("denied.txt");
    let script = format!(
        "$ErrorActionPreference = 'Stop'; try {{ \
            Set-Content -LiteralPath '{}' -Value 'should-not-write' -NoNewline; exit 0 \
        }} catch {{ Write-Output $_.Exception.Message; exit 9 }}",
        probe_path.display()
    );
    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    let child = spawn_in_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", &script],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        Some(CowInject {
            workspace_root: workspace.path(),
            upper_dir: upper.path(),
            ext_capture_roots: &[],
        }),
    )
    .expect("spawn with cow injection should succeed");
    let (stdout, stderr, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("child should run to completion");
    assert_ne!(
        code, 0,
        "write outside workspace/ext roots must fail: stdout={stdout} stderr={stderr}"
    );
    assert!(!probe_path.exists());

    let denied = harness_change_ledger::store::read_denied_log(upper.path());
    let original = harness_change_ledger::store::normalize_abs_path(&probe_path.to_string_lossy());
    assert!(
        denied.iter().any(|e| e.path == original),
        "denied write attempt must be recorded: denied={denied:?} expected={original}"
    );

    let _ = std::fs::remove_dir_all(&outside);
}

/// fail-close確認（Phase 1のみ、DLL注入なし）: workspaceをROで付与した状態で、Redirector DLLを
/// 注入しない（`cow: None`のまま`spawn`する）子から直接書込ませると、フックが存在しなくても
/// ACLだけでACCESS_DENIEDになることを確認する（D-01/D-30「フックは境界ではない」の実証）。
#[test]
#[ignore]
fn workspace_write_fails_closed_without_redirector_injection() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let upper = tempfile::tempdir().expect("upper tempdir");
    std::fs::write(workspace.path().join("important.txt"), "original").expect("seed important.txt");

    let sid = session_sid();
    let write_mode = WorkspaceWriteMode::Cow {
        upper_dir: upper.path().to_path_buf(),
    };
    preflight(workspace.path(), &[], None, &write_mode).expect("preflight (cow)");

    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    // `cow: None` — DLLを注入しない。ACLだけが境界として効くはず。
    let child = spawn_in_workspace(
        &shell,
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            COW_WRITE_PROBE_COMMAND,
        ],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        None,
    )
    .expect("spawn without cow injection should still succeed (process starts)");
    let (stdout, stderr, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("child should run to completion");

    assert_ne!(
        code, 0,
        "workspace write must fail without the redirector (fail-close via ACL, D-01/D-30): \
         stdout={stdout} stderr={stderr}"
    );
    let workspace_content = std::fs::read_to_string(workspace.path().join("important.txt"))
        .expect("workspace important.txt must still exist");
    assert_eq!(workspace_content, "original");
}

/// Phase 4a: Redirector DLLが`run_shell`の直接の子（powershell）だけでなく、その子がさらに
/// 起動する孫プロセス（cmd.exe）にも再注入され、孫からの書込みもupperへ透過リダイレクトされる
/// ことを確認する（設計書§19.2/§22/§32 Phase 4a、`/dig`2026-08-01決定）。
#[test]
#[ignore]
fn cow_write_from_grandchild_process_is_redirected_to_upper() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let upper = tempfile::tempdir().expect("upper tempdir");

    let sid = session_sid();
    let write_mode = WorkspaceWriteMode::Cow {
        upper_dir: upper.path().to_path_buf(),
    };
    preflight(workspace.path(), &[], None, &write_mode).expect("preflight (cow)");

    // cmd.exeは直接の子（powershell）がCreateProcessで起動する孫プロセス。`>`はcmd自身の
    // リダイレクトなので、書込を行うのはcmd.exe自身（孫）——PowerShellの`>`と混同しないよう
    // 二重引用符で1引数にまとめてcmd側の解釈に委ねる。cmdの終了コードには依存せず、
    // 結果は実FSを直接調べて確認する。
    const CMD: &str = "\
        cmd.exe /c \"echo created-by-grandchild>new_by_grandchild.txt\"; \
        exit 0";
    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    let child = spawn_in_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", CMD],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        Some(CowInject {
            workspace_root: workspace.path(),
            upper_dir: upper.path(),
            ext_capture_roots: &[],
        }),
    )
    .expect("spawn with cow injection should succeed");
    let (stdout, stderr, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("child should run to completion");

    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");

    assert!(
        !workspace.path().join("new_by_grandchild.txt").exists(),
        "grandchild's write must not appear in the read-only workspace"
    );
    let upper_content = std::fs::read_to_string(upper.path().join("new_by_grandchild.txt")).expect(
        "upper must contain the grandchild's write \
             (redirector DLL must have been re-injected into the grandchild, Phase 4a)",
    );
    assert!(
        upper_content.trim().contains("created-by-grandchild"),
        "unexpected upper content: {upper_content:?}"
    );

    let warnings_path = upper.path().join(".harness-cow-warnings.jsonl");
    assert!(
        !warnings_path.exists(),
        "grandchild injection should not have failed in this environment: {:?}",
        std::fs::read_to_string(&warnings_path)
    );
}

/// テスト専用: `crates/tier2a-proc-probe`のx64ビルド成果物を、直接の子プロセスとして
/// 起動するための実行ファイルパス（Redirector DLLの通常注入経路＝Phase 1-3を経て、
/// この直接の子自身が`CreateProcessA`/`WinExec`で"ひ孫"を起動する土台に使う）。
fn tier2a_proc_probe_x64_exe() -> PathBuf {
    let current = std::env::current_exe().expect("current_exe");
    let dir = current
        .parent()
        .expect("current_exe has parent")
        .to_path_buf();
    let exe = dir.join("tier2a_proc_probe.exe");
    assert!(
        exe.exists(),
        "tier2a_proc_probe.exe not found at {} (build with `cargo build -p \
         tier2a-proc-probe` and copy next to the test binary per docs/DEV-ENVIRONMENT.md)",
        exe.display()
    );
    exe
}

/// 残課題#5: `CreateProcessA`は`CreateProcessW`を経由せず直接`CreateProcessInternalW`を
/// 呼ぶため、以前は既存フック（`CreateProcessW`/`CreateProcessAsUserW`のみ）を完全に
/// 素通ししていた。`tier2a-proc-probe`（Redirector DLL注入済みの直接の子）が自身の中で
/// `CreateProcessA`を呼んで起動した孫プロセスの書込みも、CoW upperへ透過リダイレクト
/// されることを確認する（`crates/harness-redirector/src/lib.rs`の`hooked_create_process_a`）。
#[test]
#[ignore]
fn cow_write_via_createprocessa_grandchild_is_redirected_to_upper() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let upper = tempfile::tempdir().expect("upper tempdir");

    let sid = session_sid();
    let write_mode = WorkspaceWriteMode::Cow {
        upper_dir: upper.path().to_path_buf(),
    };
    preflight(workspace.path(), &[], None, &write_mode).expect("preflight (cow)");

    let probe = tier2a_proc_probe_x64_exe();
    let env = crate::secret_env::build_child_env();
    let child = spawn_in_workspace(
        probe.to_str().expect("probe path is valid utf-8"),
        &[
            "--spawn-via-createprocessa",
            "cmd.exe /c \"echo created-by-createprocessa>new_by_createprocessa.txt\"",
        ],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        Some(CowInject {
            workspace_root: workspace.path(),
            upper_dir: upper.path(),
            ext_capture_roots: &[],
        }),
    )
    .expect("spawn with cow injection should succeed");
    let (stdout, stderr, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("child should run to completion");
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");

    assert!(
        !workspace.path().join("new_by_createprocessa.txt").exists(),
        "grandchild's write must not appear in the read-only workspace"
    );
    let upper_content = std::fs::read_to_string(upper.path().join("new_by_createprocessa.txt"))
        .expect(
            "upper must contain the grandchild's write (CreateProcessA hook must have \
             re-injected the redirector DLL, residual issue #5)",
        );
    assert!(
        upper_content.trim().contains("created-by-createprocessa"),
        "unexpected upper content: {upper_content:?}"
    );

    let warnings_path = upper.path().join(".harness-cow-warnings.jsonl");
    assert!(
        !warnings_path.exists(),
        "grandchild injection via CreateProcessA should not have failed in this \
         environment: {:?}",
        std::fs::read_to_string(&warnings_path)
    );
}

/// 残課題#5: `WinExec`は`dwCreationFlags`も`lpProcessInformation`も呼び出し元へ公開しない
/// ため、`hooked_win_exec`（`crates/harness-redirector/src/lib.rs`）は本物の`WinExec`を
/// 呼ばず内部で`CreateProcessA`相当の経路へ委譲して注入する設計になっている。その経路が
/// 実際に機能し、`WinExec`で起動した孫プロセスの書込みもCoW upperへ透過リダイレクトされる
/// ことを確認する。
#[test]
#[ignore]
fn cow_write_via_winexec_grandchild_is_redirected_to_upper() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let upper = tempfile::tempdir().expect("upper tempdir");

    let sid = session_sid();
    let write_mode = WorkspaceWriteMode::Cow {
        upper_dir: upper.path().to_path_buf(),
    };
    preflight(workspace.path(), &[], None, &write_mode).expect("preflight (cow)");

    let probe = tier2a_proc_probe_x64_exe();
    let env = crate::secret_env::build_child_env();
    let child = spawn_in_workspace(
        probe.to_str().expect("probe path is valid utf-8"),
        &[
            "--spawn-via-winexec",
            "cmd.exe /c \"echo created-by-winexec>new_by_winexec.txt\"",
        ],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        Some(CowInject {
            workspace_root: workspace.path(),
            upper_dir: upper.path(),
            ext_capture_roots: &[],
        }),
    )
    .expect("spawn with cow injection should succeed");
    let (stdout, stderr, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("child should run to completion");
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");

    assert!(
        !workspace.path().join("new_by_winexec.txt").exists(),
        "grandchild's write must not appear in the read-only workspace"
    );
    let upper_content = std::fs::read_to_string(upper.path().join("new_by_winexec.txt")).expect(
        "upper must contain the grandchild's write (WinExec hook must have re-injected \
             the redirector DLL via its CreateProcessA-based reimplementation, residual \
             issue #5)",
    );
    assert!(
        upper_content.trim().contains("created-by-winexec"),
        "unexpected upper content: {upper_content:?}"
    );

    let warnings_path = upper.path().join(".harness-cow-warnings.jsonl");
    assert!(
        !warnings_path.exists(),
        "grandchild injection via WinExec should not have failed in this environment: {:?}",
        std::fs::read_to_string(&warnings_path)
    );
}

/// Phase 4b: 32bit（WOW64）孫プロセス（`C:\Windows\SysWOW64\cmd.exe`）にもRedirector DLLが
/// 再注入され、書込みがupperへ透過リダイレクトされることを確認する（設計書§32 Phase 4b、
/// `/dig`2026-08-02決定「エントリポイントtrap方式」）。直接の子（powershell、x64）から
/// SysWOW64のcmd.exeを明示パスで起動する（64bitプロセスがSysWOW64を直接指定すればWOW64
/// ファイルシステムリダイレクトの影響を受けない）。x86 Redirector DLL
/// （`harness_redirector_x86.dll`）がこのテストバイナリと同じディレクトリ
/// （`target/debug/deps/`）に存在する前提（`docs/DEV-ENVIRONMENT.md`「Tier2a E2Eテストの
/// 実行方法」参照、x64 DLLの探索規約`redirector_dll_path`と同じ、`crate::wow64`の
/// `x86_sibling_dll_path`参照）。
#[test]
#[ignore]
fn cow_write_from_wow64_grandchild_process_is_redirected_to_upper() {
    let _lock = WOW64_DLL_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let upper = tempfile::tempdir().expect("upper tempdir");

    let sid = session_sid();
    let write_mode = WorkspaceWriteMode::Cow {
        upper_dir: upper.path().to_path_buf(),
    };
    preflight(workspace.path(), &[], None, &write_mode).expect("preflight (cow)");

    const CMD: &str = "\
        C:\\Windows\\SysWOW64\\cmd.exe /c \"echo created-by-wow64-grandchild>new_by_wow64.txt\"; \
        exit 0";
    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    let child = spawn_in_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", CMD],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        Some(CowInject {
            workspace_root: workspace.path(),
            upper_dir: upper.path(),
            ext_capture_roots: &[],
        }),
    )
    .expect("spawn with cow injection should succeed");
    let (stdout, stderr, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("child should run to completion");

    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");

    assert!(
        !workspace.path().join("new_by_wow64.txt").exists(),
        "wow64 grandchild's write must not appear in the read-only workspace"
    );
    let upper_content = std::fs::read_to_string(upper.path().join("new_by_wow64.txt")).expect(
        "upper must contain the wow64 grandchild's write \
             (redirector DLL must have been re-injected via the entry-point trap, Phase 4b)",
    );
    assert!(
        upper_content.trim().contains("created-by-wow64-grandchild"),
        "unexpected upper content: {upper_content:?}"
    );

    let warnings_path = upper.path().join(".harness-cow-warnings.jsonl");
    assert!(
        !warnings_path.exists(),
        "wow64 grandchild injection should not have failed in this environment: {:?}",
        std::fs::read_to_string(&warnings_path)
    );
}

/// Phase 4b失敗系: x86版Redirector DLL（`harness_redirector_x86.dll`）が存在しない場合、
/// WOW64孫プロセスへの注入は失敗するが、孫プロセスの生成自体は拒否されず（Q6）、書込みは
/// workspaceのACLでfail-closeし（transparent性の欠如のみ）、警告台帳に理由が記録されること。
/// このテストは`harness_redirector_x86.dll`を一時的にリネームして実行する。
#[test]
#[ignore]
fn cow_wow64_grandchild_without_x86_dll_fails_closed_with_warning() {
    let _lock = WOW64_DLL_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let upper = tempfile::tempdir().expect("upper tempdir");

    let current = std::env::current_exe().expect("current_exe");
    let dir = current.parent().expect("current_exe has parent");
    let x86_dll = dir.join("harness_redirector_x86.dll");
    let x86_dll_backup = dir.join("harness_redirector_x86.dll.disabled-for-test");
    let had_x86_dll = x86_dll.exists();
    if had_x86_dll {
        std::fs::rename(&x86_dll, &x86_dll_backup).expect("temporarily rename x86 dll");
    }
    // パニックしても必ずリネームを戻す。
    let restore = scopeguard(|| {
        if had_x86_dll {
            let _ = std::fs::rename(&x86_dll_backup, &x86_dll);
        }
    });

    let sid = session_sid();
    let write_mode = WorkspaceWriteMode::Cow {
        upper_dir: upper.path().to_path_buf(),
    };
    preflight(workspace.path(), &[], None, &write_mode).expect("preflight (cow)");

    const CMD: &str = "\
        C:\\Windows\\SysWOW64\\cmd.exe /c \"echo should-not-appear-in-upper>should_not_exist.txt\"; \
        exit 0";
    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    let child = spawn_in_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", CMD],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        Some(CowInject {
            workspace_root: workspace.path(),
            upper_dir: upper.path(),
            ext_capture_roots: &[],
        }),
    )
    .expect("spawn with cow injection should succeed");
    let (stdout, stderr, _code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("child should run to completion");
    let _ = (stdout, stderr);

    drop(restore);

    assert!(
        !workspace.path().join("should_not_exist.txt").exists(),
        "workspace must stay unchanged regardless of injection outcome"
    );
    assert!(
        !upper.path().join("should_not_exist.txt").exists(),
        "without the x86 redirector dll, the write must fail closed (workspace ACL denies \
         it) rather than silently succeed via a stale/mismatched injection"
    );
    let warnings_path = upper.path().join(".harness-cow-warnings.jsonl");
    let warnings = std::fs::read_to_string(&warnings_path).expect(
        "warning ledger must record the injection failure when the x86 redirector dll is \
         missing (Q6: grandchild creation itself must not be refused)",
    );
    assert!(
        warnings.contains("32bit") || warnings.contains("wow64") || warnings.contains("WOW64"),
        "warning entry should mention the wow64/32bit injection path: {warnings}"
    );
}

/// 設計書§21（Memory-mapped file）の実測: 書込可能な`MemoryMappedFile`は`CreateFromFile`の
/// 時点で`FILE_WRITE_DATA`付きの`NtCreateFile`/`NtOpenFile`を要求するため、既存の
/// `is_write_intent`によるopen時リダイレクトだけでカバーできているはず、という仮説を実機で
/// 検証する（`NtCreateSection`自体は未フックのまま）。期待どおりならこのテストが回帰テスト
/// として残り、`NtCreateSection`フックの追加実装は不要と判断する。
#[test]
#[ignore]
fn cow_writable_memory_mapped_file_is_redirected_to_upper() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let upper = tempfile::tempdir().expect("upper tempdir");
    std::fs::write(workspace.path().join("important.txt"), "original").expect("seed important.txt");

    let sid = session_sid();
    let write_mode = WorkspaceWriteMode::Cow {
        upper_dir: upper.path().to_path_buf(),
    };
    preflight(workspace.path(), &[], None, &write_mode).expect("preflight (cow)");

    // 書込可能なview（ReadWrite）を作成し、8バイト全体を書き換える(元の"original"と
    // 同じ長さにして容量周りの複雑さを避ける)。`mapName`に`$null`を渡すと.NET側で
    // 「Map name cannot be an empty string」となる（PowerShellの引数束縛で空文字列化される、
    // 実機確認済み）ため、セッション固有のGUIDを名前として渡す。
    const CMD: &str = "\
        $ErrorActionPreference = 'Stop'; \
        try { \
            $mapName = [guid]::NewGuid().ToString(); \
            $mmf = [System.IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile( \
                'important.txt', [System.IO.FileMode]::Open, $mapName, 0, \
                [System.IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite); \
            $accessor = $mmf.CreateViewAccessor(0, 8, \
                [System.IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite); \
            $bytes = [System.Text.Encoding]::ASCII.GetBytes('mmapwrt!'); \
            $accessor.WriteArray(0, $bytes, 0, $bytes.Length); \
            $accessor.Flush(); \
            $accessor.Dispose(); \
            $mmf.Dispose(); \
            exit 0 \
        } catch { \
            Write-Output $_.Exception.Message; \
            exit 9 \
        }";
    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    let child = spawn_in_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", CMD],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        Some(CowInject {
            workspace_root: workspace.path(),
            upper_dir: upper.path(),
            ext_capture_roots: &[],
        }),
    )
    .expect("spawn with cow injection should succeed");
    let (stdout, stderr, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("child should run to completion");
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");

    let workspace_content = std::fs::read_to_string(workspace.path().join("important.txt"))
        .expect("workspace important.txt must still exist");
    assert_eq!(
        workspace_content, "original",
        "workspace must stay unchanged (mmap write must not bypass the ACL boundary)"
    );

    let upper_content = std::fs::read_to_string(upper.path().join("important.txt")).expect(
        "upper must contain the mmap write (open-time redirection must have copy-up'd the \
         file before the writable view was created)",
    );
    assert_eq!(upper_content, "mmapwrt!");

    let ledger = crate::tier2a::workspace_ledger::read_cow_ledger(upper.path());
    let important = ledger
        .iter()
        .find(|c| c.path == "important.txt")
        .expect("ledger must record important.txt as modified via the mmap write");
    assert_eq!(important.op, ManifestOp::Modify);
}

/// シナリオ1+3: 単発`--cow`セッションで上書き・新規作成を行い、操作台帳（`.harness-cow-ops.jsonl`）
/// の記録内容と、`changes::apply_unified_changes`によるworkspace本体への反映・台帳のprune
/// までを一気通貫で確認する（`plans/AppContainerベース Copy-on-Write ワークスペース設計書.md`
/// §19、Phase 1/2の実機E2E）。
#[test]
#[ignore]
fn cow_ledger_records_single_session_changes_and_applies_cleanly() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let upper = tempfile::tempdir().expect("upper tempdir");
    std::fs::write(workspace.path().join("important.txt"), "original").expect("seed important.txt");

    let sid = session_sid();
    let write_mode = WorkspaceWriteMode::Cow {
        upper_dir: upper.path().to_path_buf(),
    };
    preflight(workspace.path(), &[], None, &write_mode).expect("preflight (cow)");

    const CMD: &str = "\
        $ErrorActionPreference = 'Stop'; \
        try { \
            Set-Content -LiteralPath 'important.txt' -Value 'overwritten-single' -NoNewline; \
            New-Item -ItemType File -Path 'new.txt' -Force | Out-Null; \
            Set-Content -LiteralPath 'new.txt' -Value 'created-single' -NoNewline; \
            exit 0 \
        } catch { \
            Write-Output $_.Exception.Message; \
            exit 9 \
        }";
    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    let child = spawn_in_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", CMD],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        Some(CowInject {
            workspace_root: workspace.path(),
            upper_dir: upper.path(),
            ext_capture_roots: &[],
        }),
    )
    .expect("spawn with cow injection should succeed");
    let (stdout, stderr, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("child should run to completion");
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");

    let ledger = crate::tier2a::workspace_ledger::read_cow_ledger(upper.path());
    let important = ledger
        .iter()
        .find(|c| c.path == "important.txt")
        .expect("ledger must record important.txt");
    assert_eq!(important.op, ManifestOp::Modify);
    assert_eq!(
        important.baseline_hash,
        Some(harness_change_ledger::hash_bytes(b"original"))
    );
    let new = ledger
        .iter()
        .find(|c| c.path == "new.txt")
        .expect("ledger must record new.txt");
    assert_eq!(new.op, ManifestOp::Create);
    assert_eq!(new.baseline_hash, None);

    let report = apply_cow(
        upper.path(),
        workspace.path(),
        &ApplyOptions {
            only_glob: None,
            only_paths: None,
            allow_ext: false,
            adopt_unledgered: false,
        },
    )
    .expect("apply_cow should succeed");
    assert!(
        report.applied.iter().any(|p| p == "important.txt"),
        "applied={:?}",
        report.applied
    );
    assert!(
        report.applied.iter().any(|p| p == "new.txt"),
        "applied={:?}",
        report.applied
    );
    assert!(
        report.conflicts.is_empty(),
        "conflicts={:?}",
        report.conflicts
    );
    assert!(
        report.hard_denied.is_empty(),
        "hard_denied={:?}",
        report.hard_denied
    );

    assert_eq!(
        std::fs::read_to_string(workspace.path().join("important.txt")).unwrap(),
        "overwritten-single"
    );
    assert_eq!(
        std::fs::read_to_string(workspace.path().join("new.txt")).unwrap(),
        "created-single"
    );

    let ledger_after = crate::tier2a::workspace_ledger::read_cow_ledger(upper.path());
    assert!(
        ledger_after.is_empty(),
        "applied entries must be pruned from the ledger: {ledger_after:?}"
    );
}

/// シナリオ2+3: 同一workspaceに対する2つの`--cow`セッション（別々のupper）を並行実行し、
/// 互いのupperが混ざらないこと・workspace本体が両方から不変であることを確認したうえで、
/// 片方を先にapplyしもう片方を後からapplyすると、baseline hash不一致でconflictとして
/// 検知される（TOCTOU防止、`overlay.rs::apply()`と同じ意味論）ことを確認する。
#[test]
#[ignore]
fn cow_ledger_isolates_concurrent_sessions_and_detects_apply_conflicts() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let upper_a = tempfile::tempdir().expect("upper_a tempdir");
    let upper_b = tempfile::tempdir().expect("upper_b tempdir");
    std::fs::write(workspace.path().join("important.txt"), "original").expect("seed important.txt");

    let sid = session_sid();
    // workspace本体へのRO ACEはworkspace単位で共有されるモードのため、同じ"ro"モードの
    // 複数セッションに対して複数回`preflight`を呼んでも（`workspace_ledger::begin_workspace_mode`
    // は他モードとの排他しか見ないため）衝突しない。**ただし各upper_dirへのRW ACEは
    // upper_dirごとに個別に付与される**（`preflight`のCowブランチの`grant_ace_inheritable_rw(upper_dir, ..)`
    // 参照）ため、upper_a・upper_bそれぞれについて`preflight`を呼ぶ必要がある
    // （実機E2Eで発見: 1回しか呼ばないとpreflightされなかった側の子がACCESS_DENIEDで失敗する）。
    preflight(
        workspace.path(),
        &[],
        None,
        &WorkspaceWriteMode::Cow {
            upper_dir: upper_a.path().to_path_buf(),
        },
    )
    .expect("preflight (cow, upper_a)");
    preflight(
        workspace.path(),
        &[],
        None,
        &WorkspaceWriteMode::Cow {
            upper_dir: upper_b.path().to_path_buf(),
        },
    )
    .expect("preflight (cow, upper_b)");

    fn probe_cmd(suffix: &str) -> String {
        format!(
            "$ErrorActionPreference = 'Stop'; \
             try {{ \
                 Set-Content -LiteralPath 'important.txt' -Value 'overwritten-by-{suffix}' -NoNewline; \
                 New-Item -ItemType File -Path 'new.txt' -Force | Out-Null; \
                 Set-Content -LiteralPath 'new.txt' -Value 'created-by-{suffix}' -NoNewline; \
                 exit 0 \
             }} catch {{ \
                 Write-Output $_.Exception.Message; \
                 exit 9 \
             }}"
        )
    }
    let cmd_a = probe_cmd("a");
    let cmd_b = probe_cmd("b");

    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    // 両方を先にspawnしてから待つ（＝両プロセスが実際に同時にOS上で走っている状態を作る）。
    let child_a = spawn_in_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", &cmd_a],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        Some(CowInject {
            workspace_root: workspace.path(),
            upper_dir: upper_a.path(),
            ext_capture_roots: &[],
        }),
    )
    .expect("spawn A with cow injection should succeed");
    let child_b = spawn_in_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", &cmd_b],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        Some(CowInject {
            workspace_root: workspace.path(),
            upper_dir: upper_b.path(),
            ext_capture_roots: &[],
        }),
    )
    .expect("spawn B with cow injection should succeed");

    let (stdout_a, stderr_a, code_a) = child_a
        .write_stdin_read_output_and_wait(None)
        .expect("child A should run to completion");
    assert_eq!(code_a, 0, "stdout={stdout_a} stderr={stderr_a}");
    let (stdout_b, stderr_b, code_b) = child_b
        .write_stdin_read_output_and_wait(None)
        .expect("child B should run to completion");
    assert_eq!(code_b, 0, "stdout={stdout_b} stderr={stderr_b}");

    let ledger_a = crate::tier2a::workspace_ledger::read_cow_ledger(upper_a.path());
    assert_eq!(
        ledger_a
            .iter()
            .find(|c| c.path == "important.txt")
            .unwrap()
            .op,
        ManifestOp::Modify
    );
    assert_eq!(
        std::fs::read_to_string(upper_a.path().join("important.txt")).unwrap(),
        "overwritten-by-a"
    );
    assert_eq!(
        std::fs::read_to_string(upper_a.path().join("new.txt")).unwrap(),
        "created-by-a"
    );
    let ledger_b = crate::tier2a::workspace_ledger::read_cow_ledger(upper_b.path());
    assert_eq!(
        ledger_b
            .iter()
            .find(|c| c.path == "important.txt")
            .unwrap()
            .op,
        ManifestOp::Modify
    );
    assert_eq!(
        std::fs::read_to_string(upper_b.path().join("important.txt")).unwrap(),
        "overwritten-by-b"
    );
    assert_eq!(
        std::fs::read_to_string(upper_b.path().join("new.txt")).unwrap(),
        "created-by-b"
    );

    // workspace本体は両セッションから見て不変のまま（境界＝ACLの再確認）。
    assert_eq!(
        std::fs::read_to_string(workspace.path().join("important.txt")).unwrap(),
        "original"
    );
    assert!(!workspace.path().join("new.txt").exists());

    // セッションAを先に適用する。
    let report_a = apply_cow(
        upper_a.path(),
        workspace.path(),
        &ApplyOptions {
            only_glob: None,
            only_paths: None,
            allow_ext: false,
            adopt_unledgered: false,
        },
    )
    .expect("apply A should succeed");
    assert!(report_a.applied.iter().any(|p| p == "important.txt"));
    assert!(report_a.applied.iter().any(|p| p == "new.txt"));
    assert!(
        report_a.conflicts.is_empty(),
        "conflicts={:?}",
        report_a.conflicts
    );
    assert_eq!(
        std::fs::read_to_string(workspace.path().join("important.txt")).unwrap(),
        "overwritten-by-a"
    );
    assert_eq!(
        std::fs::read_to_string(workspace.path().join("new.txt")).unwrap(),
        "created-by-a"
    );

    // セッションBを後から適用する。workspaceは既にAの内容へ変わっているため、Bのbaseline
    // （important.txt="original"、new.txt=None＝新規作成想定）はどちらも現在値と食い違い、
    // TOCTOU競合として拒否されるはず（`report.applied`は空、両方`conflicts`に入る）。
    let report_b = apply_cow(
        upper_b.path(),
        workspace.path(),
        &ApplyOptions {
            only_glob: None,
            only_paths: None,
            allow_ext: false,
            adopt_unledgered: false,
        },
    )
    .expect("apply B should succeed (as an operation; entries land in conflicts)");
    assert!(
        report_b.applied.is_empty(),
        "B's changes must not be applied over A's: applied={:?}",
        report_b.applied
    );
    assert!(report_b.conflicts.iter().any(|p| p == "important.txt"));
    assert!(report_b.conflicts.iter().any(|p| p == "new.txt"));

    // Bのapply試行後もworkspaceはAの内容のまま変化していないこと。
    assert_eq!(
        std::fs::read_to_string(workspace.path().join("important.txt")).unwrap(),
        "overwritten-by-a"
    );
    assert_eq!(
        std::fs::read_to_string(workspace.path().join("new.txt")).unwrap(),
        "created-by-a"
    );
}

/// リネームE2E: `NtSetInformationFile`の`FileRenameInformation`フック
/// （`rewrite_rename_target`）が実際にWindowsから渡される移動先パスを正しく解釈できるかを
/// 確認する探索的テスト。旧パスの`Delete`＋新パスの`Create`の2レコードに分解されること
/// （設計書§19.4）・upper側で実際にリネームが再現されること・applyでworkspace本体に
/// 反映されることを確認する。
#[test]
#[ignore]
fn cow_ledger_records_rename_as_delete_plus_create_and_applies() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let upper = tempfile::tempdir().expect("upper tempdir");
    std::fs::write(workspace.path().join("old.txt"), "original-content").expect("seed old.txt");

    let sid = session_sid();
    let write_mode = WorkspaceWriteMode::Cow {
        upper_dir: upper.path().to_path_buf(),
    };
    preflight(workspace.path(), &[], None, &write_mode).expect("preflight (cow)");

    const CMD: &str = "\
        $ErrorActionPreference = 'Stop'; \
        try { \
            Rename-Item -LiteralPath 'old.txt' -NewName 'new.txt'; \
            exit 0 \
        } catch { \
            Write-Output $_.Exception.Message; \
            exit 9 \
        }";
    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    let child = spawn_in_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", CMD],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        Some(CowInject {
            workspace_root: workspace.path(),
            upper_dir: upper.path(),
            ext_capture_roots: &[],
        }),
    )
    .expect("spawn with cow injection should succeed");
    let (stdout, stderr, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("child should run to completion");
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");

    let ledger = crate::tier2a::workspace_ledger::read_cow_ledger(upper.path());
    let old_entry = ledger
        .iter()
        .find(|c| c.path == "old.txt")
        .expect("ledger must record old.txt as deleted");
    assert_eq!(old_entry.op, ManifestOp::Delete);
    assert_eq!(
        old_entry.baseline_hash,
        Some(harness_change_ledger::hash_bytes(b"original-content"))
    );
    let new_entry = ledger
        .iter()
        .find(|c| c.path == "new.txt")
        .expect("ledger must record new.txt as created");
    assert_eq!(new_entry.op, ManifestOp::Create);
    assert_eq!(new_entry.baseline_hash, None);

    assert!(!upper.path().join("old.txt").exists());
    assert_eq!(
        std::fs::read_to_string(upper.path().join("new.txt")).unwrap(),
        "original-content"
    );
    assert_eq!(
        std::fs::read_to_string(workspace.path().join("old.txt")).unwrap(),
        "original-content"
    );
    assert!(!workspace.path().join("new.txt").exists());

    let report = apply_cow(
        upper.path(),
        workspace.path(),
        &ApplyOptions {
            only_glob: None,
            only_paths: None,
            allow_ext: false,
            adopt_unledgered: false,
        },
    )
    .expect("apply_cow should succeed");
    assert!(
        report.applied.iter().any(|p| p == "old.txt"),
        "applied={:?}",
        report.applied
    );
    assert!(
        report.applied.iter().any(|p| p == "new.txt"),
        "applied={:?}",
        report.applied
    );

    assert!(!workspace.path().join("old.txt").exists());
    assert_eq!(
        std::fs::read_to_string(workspace.path().join("new.txt")).unwrap(),
        "original-content"
    );
}

/// 削除E2E: `FileDispositionInformation`/`FILE_DELETE_ON_CLOSE`＋`NtClose`フックの組合せと、
/// DLLが`run_shell`呼び出しごとに別プロセスへ再ロードされても台帳ファイルを読み直して
/// 「論理的に削除済み」集合を再構築できること（設計書§19.7）を、実際に2回子プロセスを
/// 起動して確認する。
#[test]
#[ignore]
fn cow_ledger_records_delete_persists_across_processes_and_applies() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let upper = tempfile::tempdir().expect("upper tempdir");
    std::fs::write(workspace.path().join("doomed.txt"), "to-be-deleted").expect("seed doomed.txt");

    let sid = session_sid();
    let write_mode = WorkspaceWriteMode::Cow {
        upper_dir: upper.path().to_path_buf(),
    };
    preflight(workspace.path(), &[], None, &write_mode).expect("preflight (cow)");

    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();

    const DELETE_CMD: &str = "\
        $ErrorActionPreference = 'Stop'; \
        try { \
            Remove-Item -LiteralPath 'doomed.txt' -Force; \
            exit 0 \
        } catch { \
            Write-Output $_.Exception.Message; \
            exit 9 \
        }";
    let child1 = spawn_in_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", DELETE_CMD],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        Some(CowInject {
            workspace_root: workspace.path(),
            upper_dir: upper.path(),
            ext_capture_roots: &[],
        }),
    )
    .expect("spawn (delete) with cow injection should succeed");
    let (stdout1, stderr1, code1) = child1
        .write_stdin_read_output_and_wait(None)
        .expect("child should run to completion");
    assert_eq!(code1, 0, "stdout={stdout1} stderr={stderr1}");

    let ledger = crate::tier2a::workspace_ledger::read_cow_ledger(upper.path());
    let entry = ledger
        .iter()
        .find(|c| c.path == "doomed.txt")
        .expect("ledger must record doomed.txt as deleted");
    assert_eq!(entry.op, ManifestOp::Delete);
    assert_eq!(
        entry.baseline_hash,
        Some(harness_change_ledger::hash_bytes(b"to-be-deleted"))
    );
    assert!(!upper.path().join("doomed.txt").exists());
    assert_eq!(
        std::fs::read_to_string(workspace.path().join("doomed.txt")).unwrap(),
        "to-be-deleted",
        "workspace body must remain unchanged (fail-closed real delete)"
    );

    // 2回目の子プロセス（＝DLLが再ロードされる）で、台帳の再生により論理削除が
    // 引き継がれていることを確認する。
    const CHECK_CMD: &str = "\
        (Test-Path -LiteralPath 'doomed.txt') | Write-Output; \
        exit 0";
    let child2 = spawn_in_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", CHECK_CMD],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        Some(CowInject {
            workspace_root: workspace.path(),
            upper_dir: upper.path(),
            ext_capture_roots: &[],
        }),
    )
    .expect("spawn (check) with cow injection should succeed");
    let (stdout2, stderr2, code2) = child2
        .write_stdin_read_output_and_wait(None)
        .expect("child should run to completion");
    assert_eq!(code2, 0, "stdout={stdout2} stderr={stderr2}");
    assert_eq!(
        stdout2.trim(),
        "False",
        "a freshly-loaded DLL must still treat doomed.txt as deleted (ledger replay, §19.7)"
    );

    let report = apply_cow(
        upper.path(),
        workspace.path(),
        &ApplyOptions {
            only_glob: None,
            only_paths: None,
            allow_ext: false,
            adopt_unledgered: false,
        },
    )
    .expect("apply_cow should succeed");
    assert!(
        report.applied.iter().any(|p| p == "doomed.txt"),
        "applied={:?}",
        report.applied
    );
    assert!(!workspace.path().join("doomed.txt").exists());
}

/// 世代チェーンごとの封じ込め検証本体（`chains`の各要素が1チェーン＝
/// `["x64", "x86", ...]`のようなgen1から数えたビット幅の並び。長さ＝世代数で、**上限は無い**）。
/// `timeout_secs`は各プローブプロセスのwatchdog（世代が深いほど注入待ちが積み上がるため
/// 呼び出し側が調整する）。
///
/// `crates/tier2a-proc-probe`（`tier2a_proc_probe`/
/// `tier2a_proc_probe_x86`、`docs/DEV-ENVIRONMENT.md`「Tier2aプローブアプリのビルド・配置」
/// 参照）を直接Launcherの子（gen1）として起動し、各世代がworkspace内FS操作
/// （create/modify/delete/rename）・workspace外への脱走試行（`C:\Windows`・
/// `%USERPROFILE%`・workspaceの親）・ネットワーク到達性・自身の識別情報（bitness・
/// token integrity level・AppContainer package SID・Redirector DLLロード有無）を検査し、
/// `--chain`の残りに従って次世代を再帰的にspawnしてJSONで報告する。
///
/// 期待値は伝播規則で決まる（設計書§13.2の対応マトリクス）:
/// - Launcher→gen1: gen1がx64のときのみ注入される（`inject_redirector`はx64専用、
///   x86ターゲットでは`spawn()`自体が`Err`を返し起動そのものを拒否する——Q6のfail-open
///   ではなく、Launcher直下はfail-closed拒否）。
/// - gen(i)→gen(i+1): gen(i)が注入済みで、かつ`x86→x64`でない場合のみ成立
///   （x86→x64はHeaven's Gate相当が必要なため対象外、素通し＋警告記録のみ）。
/// - 注入が途切れた世代以降は、プロセス生成自体は拒否されない（Q6）が、CoW透過は
///   一切効かずworkspace ROのACLでfail-closeし続ける（回復しない）。
fn run_containment_chains(chains: &[&[&str]], timeout_secs: u64, sanitize_env: bool) {
    use serde_json::Value;

    fn proc_probe_exe_paths() -> (PathBuf, PathBuf) {
        let current = std::env::current_exe().expect("current_exe");
        let dir = current
            .parent()
            .expect("current_exe has parent")
            .to_path_buf();
        let x64 = dir.join("tier2a_proc_probe.exe");
        let x86 = dir.join("tier2a_proc_probe_x86.exe");
        assert!(
            x64.exists(),
            "tier2a_proc_probe.exe not found at {} (build with `cargo build -p \
             tier2a-proc-probe` and copy next to the test binary per \
             docs/DEV-ENVIRONMENT.md)",
            x64.display()
        );
        assert!(
            x86.exists(),
            "tier2a_proc_probe_x86.exe not found at {} (build with `cargo build -p \
             tier2a-proc-probe --target i686-pc-windows-msvc` and copy next to the test \
             binary per docs/DEV-ENVIRONMENT.md)",
            x86.display()
        );
        (x64, x86)
    }

    /// Launcherの直接注入はx64専用、DLL内の孫再注入は`x86→x64`のみ対象外
    /// （§13.2）という伝播規則から、各世代の注入成否を導く。規則自体に世代数の
    /// 上限が無いため、チェーン長に対して一般のループで畳み込む（再帰性の期待値そのもの）。
    fn expected_injected(chain: &[&str]) -> Vec<bool> {
        let mut injected = vec![false; chain.len()];
        injected[0] = chain[0] == "x64";
        for i in 1..chain.len() {
            let propagate_ok = !(chain[i - 1] == "x86" && chain[i] == "x64");
            injected[i] = injected[i - 1] && propagate_ok;
        }
        injected
    }

    fn gen_tag(gen: usize, arch: &str) -> String {
        format!("gen{}-{arch}", gen + 1)
    }

    fn seed_modify_content(tag: &str) -> String {
        format!("seed-modify-{tag}")
    }
    fn seed_delete_content(tag: &str) -> String {
        format!("seed-delete-{tag}")
    }
    fn seed_rename_content(tag: &str) -> String {
        format!("seed-rename-{tag}")
    }

    fn seed_tag_files(workspace: &Path, tag: &str) {
        std::fs::write(
            workspace.join(format!("{tag}-seed.txt")),
            seed_modify_content(tag),
        )
        .expect("seed -seed.txt");
        std::fs::write(
            workspace.join(format!("{tag}-del.txt")),
            seed_delete_content(tag),
        )
        .expect("seed -del.txt");
        std::fs::write(
            workspace.join(format!("{tag}-ren.txt")),
            seed_rename_content(tag),
        )
        .expect("seed -ren.txt");
    }

    /// workspace本体はCoWの境界（ACL）なので、注入の成否に関わらず常に不変であるはず。
    fn assert_workspace_untouched_for_tag(workspace: &Path, tag: &str) {
        assert!(
            !workspace.join(format!("{tag}-new.txt")).exists(),
            "workspace must never receive a direct write for {tag}"
        );
        assert_eq!(
            std::fs::read_to_string(workspace.join(format!("{tag}-seed.txt"))).unwrap(),
            seed_modify_content(tag),
            "workspace seed file for {tag} must stay unmodified"
        );
        assert_eq!(
            std::fs::read_to_string(workspace.join(format!("{tag}-del.txt"))).unwrap(),
            seed_delete_content(tag),
            "workspace delete-target for {tag} must still exist unmodified"
        );
        assert_eq!(
            std::fs::read_to_string(workspace.join(format!("{tag}-ren.txt"))).unwrap(),
            seed_rename_content(tag),
            "workspace rename-source for {tag} must still exist unmodified"
        );
        assert!(
            !workspace.join(format!("{tag}-ren2.txt")).exists(),
            "workspace must never see the rename target for {tag}"
        );
    }

    fn assert_upper_reflects_tag(upper: &Path, tag: &str, injected: bool) {
        let new_path = upper.join(format!("{tag}-new.txt"));
        let seed_path = upper.join(format!("{tag}-seed.txt"));
        let del_path = upper.join(format!("{tag}-del.txt"));
        let ren_path = upper.join(format!("{tag}-ren.txt"));
        let ren2_path = upper.join(format!("{tag}-ren2.txt"));
        if injected {
            assert_eq!(
                std::fs::read_to_string(&new_path)
                    .unwrap_or_else(|e| panic!("upper must contain {tag}-new.txt: {e}")),
                format!("created-by-{tag}")
            );
            assert_eq!(
                std::fs::read_to_string(&seed_path)
                    .unwrap_or_else(|e| panic!("upper must contain {tag}-seed.txt: {e}")),
                format!("modified-by-{tag}")
            );
            assert!(
                !del_path.exists(),
                "{tag}-del.txt must not be copied up to upper"
            );
            assert!(!ren_path.exists(), "{tag}-ren.txt must not remain in upper");
            assert_eq!(
                std::fs::read_to_string(&ren2_path)
                    .unwrap_or_else(|e| panic!("upper must contain {tag}-ren2.txt: {e}")),
                seed_rename_content(tag)
            );
        } else {
            assert!(
                !new_path.exists(),
                "{tag} was not injected: upper must not see the new file"
            );
            assert!(
                !seed_path.exists(),
                "{tag} was not injected: upper must not see the modified file"
            );
            assert!(
                !ren2_path.exists(),
                "{tag} was not injected: upper must not see the rename target"
            );
        }
    }

    fn assert_ledger_for_tag(
        ledger: &[harness_change_ledger::CowChange],
        tag: &str,
        injected: bool,
    ) {
        let find = |path: &str| ledger.iter().find(|c| c.path == path);
        if injected {
            let new_entry = find(&format!("{tag}-new.txt"))
                .unwrap_or_else(|| panic!("ledger must record {tag}-new.txt"));
            assert_eq!(new_entry.op, ManifestOp::Create);
            let seed_entry = find(&format!("{tag}-seed.txt"))
                .unwrap_or_else(|| panic!("ledger must record {tag}-seed.txt"));
            assert_eq!(seed_entry.op, ManifestOp::Modify);
            assert_eq!(
                seed_entry.baseline_hash,
                Some(harness_change_ledger::hash_bytes(
                    seed_modify_content(tag).as_bytes()
                ))
            );
            let del_entry = find(&format!("{tag}-del.txt"))
                .unwrap_or_else(|| panic!("ledger must record {tag}-del.txt"));
            assert_eq!(del_entry.op, ManifestOp::Delete);
            assert_eq!(
                del_entry.baseline_hash,
                Some(harness_change_ledger::hash_bytes(
                    seed_delete_content(tag).as_bytes()
                ))
            );
            let ren_old = find(&format!("{tag}-ren.txt"))
                .unwrap_or_else(|| panic!("ledger must record {tag}-ren.txt as deleted"));
            assert_eq!(ren_old.op, ManifestOp::Delete);
            let ren_new = find(&format!("{tag}-ren2.txt"))
                .unwrap_or_else(|| panic!("ledger must record {tag}-ren2.txt as created"));
            assert_eq!(ren_new.op, ManifestOp::Create);
        } else {
            for suffix in ["-new.txt", "-seed.txt", "-del.txt", "-ren.txt", "-ren2.txt"] {
                assert!(
                    find(&format!("{tag}{suffix}")).is_none(),
                    "{tag} was not injected: ledger must not record {tag}{suffix}"
                );
            }
        }
    }

    fn nested_reports(top: &Value) -> Vec<Value> {
        let mut out = vec![top.clone()];
        let mut cur = top.clone();
        loop {
            let child = cur
                .get("spawn")
                .and_then(|s| s.get("child"))
                .cloned()
                .filter(|c| !c.is_null());
            match child {
                Some(c) => {
                    out.push(c.clone());
                    cur = c;
                }
                None => break,
            }
        }
        out
    }

    let (x64_exe, x86_exe) = proc_probe_exe_paths();
    let sid = session_sid();

    // D-37: プロセス生成チェーンのプローブexeは`target\debug\deps`にあり、**workspaceの外**である。
    // 旧共有プロファイルの頃はリポジトリrootへの継承ACEがたまたまここまで届いていたが、
    // セッションSIDになった今は誰も付与しない。その結果サンドボックスの子からは
    // `exe.exists()`すらfalseになり、次世代を起動できずに
    // `spawn.error = "probe exe not found"`でチェーンが1世代で切れる。
    // redirector DLLに対して`preflight`のCoW分岐がやっているのと同じ扱いを、
    // **テスト専用のこのexeにも**明示的に与える（製品のサンドボックスがこのexeへ到達できる
    // 必要は無いので、付与はテスト側の責務である）。
    let probe_exes = [x64_exe.clone(), x86_exe.clone()];
    for exe in &probe_exes {
        grant_ace_inheritable_access(exe, sid.as_psid(), FsAccess::ReadExec)
            .expect("grant the chain probe exe to this session (D-37)");
        // 台帳へ載せておけば、テストがパニックしても次回起動のGCが剥がす。
        crate::tier2a::session_profile::record_granted_path(exe);
    }
    let guard_sid = session_sid();
    let guard_exes = probe_exes.clone();
    let _probe_exe_guard = scopeguard(move || {
        for exe in &guard_exes {
            let _ = revoke_ace(exe, guard_sid.as_psid());
        }
    });

    // 読み取り側の脱走試行用: workspace外（ACL未付与）の秘密ファイル。全チェーンで
    // 使い回して構わない（読み取り専用チェックのため、書き換わらない）。
    let outside_dir = tempfile::tempdir().expect("outside tempdir");
    let outside_secret = outside_dir.path().join("outside-secret.txt");
    std::fs::write(&outside_secret, "must-not-be-readable-from-sandbox")
        .expect("seed outside-secret.txt");

    for chain in chains {
        let workspace = tempfile::tempdir().expect("workspace tempdir");
        let upper = tempfile::tempdir().expect("upper tempdir");

        let tags: Vec<String> = (0..chain.len()).map(|i| gen_tag(i, chain[i])).collect();
        for tag in &tags {
            seed_tag_files(workspace.path(), tag);
        }

        let write_mode = WorkspaceWriteMode::Cow {
            upper_dir: upper.path().to_path_buf(),
        };
        preflight(workspace.path(), &[], None, &write_mode).expect("preflight (cow)");

        let injected = expected_injected(chain);
        let gen1_exe = if chain[0] == "x64" {
            &x64_exe
        } else {
            &x86_exe
        };
        let rest_chain = chain[1..].join(",");
        let args: Vec<String> = vec![
            "--gen".to_string(),
            "1".to_string(),
            "--chain".to_string(),
            rest_chain,
            "--x64-exe".to_string(),
            x64_exe.display().to_string(),
            "--x86-exe".to_string(),
            x86_exe.display().to_string(),
            "--outside-read".to_string(),
            outside_secret.display().to_string(),
            "--timeout-secs".to_string(),
            timeout_secs.to_string(),
        ];
        // BUG-045のF2: 各世代が次世代を起動するとき`HARNESS_COW_*`を落とさせる
        // （自前env blockを組み立てる実アプリの模擬）。設定が注入パラメータで
        // 伝わっていれば期待値`injected`は変わらない。
        let mut args = args;
        if sanitize_env {
            args.push("--sanitize-env".to_string());
        }
        let args = args;
        let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();

        let env = crate::secret_env::build_child_env();
        let spawn_result = spawn_in_workspace(
            &gen1_exe.display().to_string(),
            &args_ref,
            workspace.path(),
            &env,
            false,
            sid.as_psid(),
            NetworkCapability::Deny,
            Some(CowInject {
                workspace_root: workspace.path(),
                upper_dir: upper.path(),
                ext_capture_roots: &[],
            }),
        );

        if chain[0] == "x86" {
            // Launcher直下の注入はx64専用。gen1がx86の場合、`spawn()`自体が起動を
            // 拒否する（fail-closed refusal、Q6のfail-openとは異なる）はず。
            assert!(
                spawn_result.is_err(),
                "chain={chain:?}: launcher must refuse to start an x86 gen1 rather than \
                 start it without cow injection"
            );
            for tag in &tags {
                assert_workspace_untouched_for_tag(workspace.path(), tag);
                assert_upper_reflects_tag(upper.path(), tag, false);
            }
            continue;
        }

        let child = spawn_result.expect("spawn with cow injection should succeed (gen1=x64)");
        let (stdout, stderr, code) = child
            .write_stdin_read_output_and_wait(None)
            .expect("child should run to completion");
        assert_ne!(
            code, 97,
            "chain={chain:?}: probe watchdog fired (chain hung), stdout={stdout} \
             stderr={stderr}"
        );

        let top: Value = stdout
            .lines()
            .rev()
            .find_map(|line| serde_json::from_str(line).ok())
            .unwrap_or_else(|| {
                panic!("chain={chain:?}: no JSON report line in stdout={stdout} stderr={stderr}")
            });
        let reports = nested_reports(&top);
        assert_eq!(
            reports.len(),
            chain.len(),
            "chain={chain:?}: expected all {} generations to run and report (Q6: process \
             creation is never refused once gen1 started), got {} reports: {reports:?}",
            chain.len(),
            reports.len()
        );

        for (i, report) in reports.iter().enumerate() {
            let compiled_arch = report["identity"]["compiled_arch"].as_str().unwrap_or("");
            let expected_arch = if chain[i] == "x64" { "x86_64" } else { "x86" };
            assert_eq!(
                compiled_arch,
                expected_arch,
                "chain={chain:?} gen{}: unexpected compiled_arch in report {report:?}",
                i + 1
            );

            let connect_ok = report["net"]["connect"]["ok"].as_bool().unwrap_or(true);
            assert!(
                !connect_ok,
                "chain={chain:?} gen{}: outbound connect must be denied \
                 (NetworkCapability::Deny inherited across all generations): {report:?}",
                i + 1
            );

            for escape_op in [
                "escape-write-windows",
                "escape-write-userprofile",
                "escape-write-parent",
                "escape-read-outside",
            ] {
                let entry = report["escape"]
                    .as_array()
                    .and_then(|arr| arr.iter().find(|e| e["op"] == escape_op));
                if let Some(entry) = entry {
                    let ok = entry["ok"].as_bool().unwrap_or(true);
                    assert!(
                        !ok,
                        "chain={chain:?} gen{}: escape attempt {escape_op} must fail: {entry:?}",
                        i + 1
                    );
                }
            }

            // ベースライン観測（win.ini）: 全8チェーン・全世代で実測した結果、常に
            // `ok:true`（`ALL APPLICATION PACKAGES`への既定read権により、AppContainer
            // からでも読める）と確定的だったため、単なる記録確認ではなく積極的な
            // assertへ格上げする。workspace外の`escape-read-outside`（常にdeny）との
            // 対比で、封じ込め境界が「AppContainerだから何も読めない」ではなく
            // 「ACLが付与されたworkspace/upper以外は読めない」ことを示す対照実験になる。
            let baseline = report["escape"]
                .as_array()
                .and_then(|arr| arr.iter().find(|e| e["op"] == "escape-read-baseline"));
            let baseline_ok = baseline.and_then(|e| e["ok"].as_bool()).unwrap_or(false);
            assert!(
                baseline_ok,
                "chain={chain:?} gen{}: win.ini baseline read must succeed (default \
                 ALL APPLICATION PACKAGES read ACL), got {baseline:?}",
                i + 1
            );
        }

        for (i, tag) in tags.iter().enumerate() {
            assert_workspace_untouched_for_tag(workspace.path(), tag);
            assert_upper_reflects_tag(upper.path(), tag, injected[i]);
        }

        let ledger = crate::tier2a::workspace_ledger::read_cow_ledger(upper.path());
        for (i, tag) in tags.iter().enumerate() {
            assert_ledger_for_tag(&ledger, tag, injected[i]);
        }

        // 伝播が途切れた世代がある場合（`x86→x64`が含まれるチェーン）、警告台帳に
        // 何らかの理由が記録されているはず（Q6、内容までは固定しない）。BUG-045のF1修正で
        // 「注入は成功したがフック設置に失敗した」ケースもここに落ちるようになった。
        if injected.iter().any(|&v| !v) && injected[0] {
            let warnings_path = upper.path().join(".harness-cow-warnings.jsonl");
            let warnings = std::fs::read_to_string(&warnings_path).unwrap_or_default();
            assert!(
                !warnings.trim().is_empty(),
                "chain={chain:?}: injection propagation broke mid-chain but no warning was \
                 recorded"
            );
        }
    }
}

/// 子・孫・ひ孫（3世代）にわたる封じ込めを、全8ビット幅チェーン（3世代 × {x64,x86}）で
/// 確認する。ビット幅の組合せ網羅はこのテストが担当する（深さ方向は
/// [`cow_containment_is_recursive_beyond_three_generations`]）。
#[test]
#[ignore]
fn cow_containment_holds_across_three_generations_all_bitness_chains() {
    run_containment_chains(
        &[
            &["x64", "x64", "x64"],
            &["x64", "x64", "x86"],
            &["x64", "x86", "x64"],
            &["x64", "x86", "x86"],
            &["x86", "x64", "x64"],
            &["x86", "x64", "x86"],
            &["x86", "x86", "x64"],
            &["x86", "x86", "x86"],
        ],
        20,
        false,
    );
}

/// 封じ込めが**世代数に依存しない**ことを実機で示す（玄孫＝gen4以降まで、5世代）。
///
/// 再帰性そのものはコード構造から従う——境界（AppContainerトークン・Job Object）は
/// 子孫へ無条件に継承され、透過性（Redirector DLL）は「注入された世代が自分の
/// `CreateProcessW`/`CreateProcessAsUserW`をフックし次世代へ同じDLLを注入する」という
/// 自己相似構造（`harness-redirector`の`install_create_process_hooks`／
/// `inject_grandchild_and_maybe_resume`）で、どちらにも世代カウンタや深さの上限が無い。
/// このテストはその帰結を実測で裏付けるものなので、ビット幅の全網羅（2^5=32）ではなく
/// 再帰の証明に必要な代表3チェーンだけを回す。
///
/// - 全x64: 5世代を通してリダイレクト・操作台帳記録が続くこと（深さに上限が無い）。
/// - 深い位置でのx64→x86: WOW64再注入（Phase 4b）が孫より深い世代でも成立すること。
/// - 深い位置でのx86→x64: 既知の唯一の断絶点が起きた後、**それ以降の全世代**が
///   非注入のままでもworkspace本体は無傷（fail-close）で、警告台帳に記録が残ること。
#[test]
#[ignore]
fn cow_containment_is_recursive_beyond_three_generations() {
    // 世代ごとに2段階のリモートスレッド注入（WOW64はさらにエントリポイントtrapの
    // ポーリング）が直列に積み上がるため、3世代テストの20秒では足りない。
    run_containment_chains(
        &[
            &["x64", "x64", "x64", "x64", "x64"],
            &["x64", "x64", "x64", "x86", "x86"],
            &["x64", "x64", "x86", "x64", "x64"],
        ],
        60,
        false,
    );
}

/// BUG-045のF2の回帰テスト: **途中の世代が自前のenv blockを組み立てて次世代を起動しても**
/// CoWリダイレクトが途切れないこと。プローブが`--sanitize-env`で`HARNESS_COW_*`を全て
/// 落として子を起動するため、Redirector DLLの設定が環境変数依存のままなら
/// gen2以降は`init()`が設定を取れずフック未設置になり、upper/操作台帳にgen2・gen3の
/// 変更が現れなくなる（＝このテストが落ちる）。設定を`harness_cow_init`の
/// スレッドパラメータで渡す修正が入っているため、期待値は通常チェーンと同じ全世代注入。
#[test]
#[ignore]
fn cow_containment_survives_env_block_sanitized_by_intermediate_generation() {
    run_containment_chains(&[&["x64", "x64", "x64"]], 30, true);
}

/// **BUG-062 / 設計書§17（Reparse Point対策）の実機測定＋受け入れ。**
///
/// 2つのことを1度に確かめます。
///
/// 1. **到達性の実測**: AppContainer子は、書込可能なCoW upper_dir内に junction（mount point）を
///    作れるのか。junctionはsymlinkと違い`SeCreateSymbolicLinkPrivilege`を必要としないため、
///    「作れて当然」と思いがちですが、AppContainerトークン下で実際にどうなるかは測らないと
///    分かりません（`plans/etw-spike/RESULTS.md` §18.5の教訓——推測で結論を書かない）。
///    結果は成否どちらでも標準出力へ残します。
/// 2. **受け入れ**: 上の結果に**関わらず**、`apply`の後にworkspaceへ機密が現れないこと。
///    junctionが作れなければ経路が成立していないという理由で、作れれば`apply`が
///    cap-stdのジェイルで拒む（`PermissionDenied: a path led outside of the filesystem`）
///    という理由で、いずれも同じ不変条件へ帰着します。
///
/// 非昇格側の対になるテストは`overlay::tests::apply_does_not_follow_a_junction_planted_in_the_overlay`
/// （こちらはユーザ権限でjunctionを植えるので、サンドボックス子にできることの上位集合を試します）。
#[test]
#[ignore]
fn cow_apply_does_not_follow_a_junction_that_the_sandboxed_child_plants_in_upper() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let upper = tempfile::tempdir().expect("upper tempdir");
    // 「サンドボックスの外にある機密」の代役。upperの外・workspaceの外に置く。
    let secret_root = tempfile::tempdir().expect("secret tempdir");
    std::fs::write(secret_root.path().join("id_rsa"), "TOP-SECRET-KEY").expect("seed secret");

    let sid = session_sid();
    let write_mode = WorkspaceWriteMode::Cow {
        upper_dir: upper.path().to_path_buf(),
    };
    preflight(workspace.path(), &[], None, &write_mode).expect("preflight (cow)");

    // 子はupper_dir配下へ直接junctionを張ろうとする（upper_dirはRWで付与済み、
    // かつRedirector DLLの`classify`はupper_dir配下をリダイレクト対象外にしている）。
    //
    // **2つの標的で測るのは交絡を切り分けるため**（`plans/etw-spike/RESULTS.md` §18.5）。
    // 「機密ディレクトリ宛のjunctionが作れなかった」だけでは、*junctionが作れない*のか
    // *その標的が見えないだけ*なのかが区別できない。子が確実に読み書きできる標的
    // （upper配下に自分で作ったディレクトリ）でも失敗するなら、原因は標的ではなく
    // junction作成そのものだと確定する。
    let probe = format!(
        "$ErrorActionPreference = 'Stop'; \
         New-Item -ItemType Directory -Path '{reachable}' -Force | Out-Null; \
         try {{ \
             New-Item -ItemType Junction -Path '{link_reachable}' -Target '{reachable}' | Out-Null; \
             Write-Output 'reachable-target: created' \
         }} catch {{ \
             Write-Output ('reachable-target: failed: ' + $_.Exception.Message) \
         }} \
         try {{ \
             New-Item -ItemType Junction -Path '{link_secret}' -Target '{secret}' | Out-Null; \
             Write-Output 'secret-target: created'; \
             exit 0 \
         }} catch {{ \
             Write-Output ('secret-target: failed: ' + $_.Exception.Message); \
             exit 7 \
         }}",
        reachable = upper.path().join("inside").display(),
        link_reachable = upper.path().join("link-inside").display(),
        link_secret = upper.path().join("link").display(),
        secret = secret_root.path().display()
    );

    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    let child = spawn_in_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", &probe],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        Some(CowInject {
            workspace_root: workspace.path(),
            upper_dir: upper.path(),
            ext_capture_roots: &[],
        }),
    )
    .expect("spawn with cow injection should succeed");
    let (stdout, stderr, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("child should run to completion");

    // 到達性の実測結果は成否どちらでも残す（これがこのテストの測定としての産物）。
    println!(
        "MEASUREMENT: AppContainer child planting a junction in the CoW upper dir -> \
         exit={code} stdout={} stderr={}",
        stdout.trim(),
        stderr.trim()
    );
    let junction_created = code == 0 && upper.path().join("link").join("id_rsa").exists();

    // 台帳へ「junction越しのパス」を1件積む。junctionが作れていれば、素の`std::fs::copy`は
    // これを辿ってworkspaceへ機密を落とす（＝BUG-062以前の挙動）。
    harness_change_ledger::store::append_entry(
        upper.path(),
        ManifestOp::Create,
        "link/id_rsa",
        None,
    );

    let report = apply_cow(
        upper.path(),
        workspace.path(),
        &ApplyOptions {
            only_glob: None,
            only_paths: None,
            allow_ext: false,
            adopt_unledgered: false,
        },
    )
    .expect("apply must not fail the whole batch because of one crafted entry");

    let landed = workspace.path().join("link").join("id_rsa");
    assert!(
        !landed.exists(),
        "apply followed a junction out of the CoW upper dir and copied the secret into the \
         workspace (junction_created={junction_created}, report={report:?})"
    );
    assert!(
        report.applied.is_empty(),
        "the junction entry must never be applied (junction_created={junction_created}, \
         report={report:?})"
    );
}
