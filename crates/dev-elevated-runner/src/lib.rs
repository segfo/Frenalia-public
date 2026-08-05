//! `dev-elevated-runner`の共有部分（プロトコル型・入力検証・パイプIPCヘルパー）。
//! IPCヘルパーは`crates/harness-sandbox/src/netfilterd.rs`と同型のパターン（overlapped I/O・
//! タイムアウト付きread/write・現在ユーザSID限定DACL）を複製したもの。ライフサイクルが
//! 異なる（本クレートは多数のクライアント接続を順番に受け続ける、netfilterdは1セッション
//! 2往復で終了）ため、netfilterd.rs自身のdocコメントに倣い汎用化せず複製する。

use serde::{Deserialize, Serialize};

pub const PIPE_NAME_PREFIX: &str = r"\\.\pipe\dev-elevated-runner-";

/// 最終要求からこの時間操作が無ければサーバは自動終了する（タイマーではなく、
/// 「次のクライアント接続を待つ`ConnectNamedPipe`のタイムアウト」として実装する。
/// 退役した%TEMP%キューデーモンの教訓＝生存期間をOSの待機プリミティブに紐付ける、
/// を踏まえたもの。無期限の常駐にはしない）。
pub const IDLE_SHUTDOWN: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// クライアントは自由なコマンドラインを一切送らない。送るのは下表のキー名（記号を含まない
/// 識別子）だけで、実際に実行される`cargo`の引数列はサーバ側にハードコードされた固定値
/// （このテーブル）から引く。クライアント由来の文字列が引数配列へ混入する経路が無いため、
/// 「`&&`/`;`等のシェルメタ文字を拒否する」を個別チェックする必要すらない——キーが完全一致
/// しない時点で拒否される（ユーザー指示: 「どのテストケースを実行するか」だけを送る設計）。
/// 新しいテストターゲットが必要になったら、このテーブルへ1行追加する（コード変更が要る、
/// 実行時の任意入力では増やせない）。
pub const KNOWN_TARGETS: &[(&str, &[&str])] = &[
    (
        "e2e-all",
        &["test", "-p", "harness-cli", "--features", "e2e-mock", "--", "--ignored", "--nocapture"],
    ),
    (
        "e2e-cow-matrix",
        &[
            "test", "-p", "harness-cli", "--features", "e2e-mock", "--", "--ignored", "--nocapture",
            "tier2a_cow_commit_matrix",
        ],
    ),
    (
        "e2e-net-matrix",
        &[
            "test", "-p", "harness-cli", "--features", "e2e-mock", "--", "--ignored", "--nocapture",
            "tier2a_net_policy_matrix",
        ],
    ),
    // フィルタはモジュール名と一致していなければならない。`cow_diagnostics`→
    // `cow_containment_tests`の改名にここが追随しておらず、CoW封じ込めE2E一式が
    // 「0件マッチ＝exit 0」で黙って緑になっていた（`docs/bugs/BUG-056.md`）。
    // 同クラスの再発は`check_tests_actually_ran`が捕まえる。
    (
        "cow-diagnostics",
        &[
            "test", "-p", "harness-sandbox", "--lib", "--", "--ignored", "--test-threads=1",
            "--nocapture", "win_appcontainer::cow_containment_tests",
        ],
    ),
    // ACE付与/撤収（fs passthrough・traverse chain・継承ACE）の実機回帰。BUG-046の修正3で
    // 追加した`traverse_chain_grants_every_ancestor_on_a_test_owned_drive_root`を含む
    // （そちらは`subst`のテスト所有ドライブを使うので単体では昇格不要だが、同モジュールの
    // 他テストが`C:\`直下への書込を伴うためここから回す）。
    (
        "ace-grant-revoke",
        &[
            "test", "-p", "harness-sandbox", "--lib", "--", "--ignored", "--test-threads=1",
            "--nocapture", "win_appcontainer::ace_grant_revoke_tests",
        ],
    ),
    // M15.7 A-3: ETW実現性スパイク（判定ゲート）。`Microsoft-Windows-Kernel-File`の
    // リアルタイムセッションでACL拒否が観測できるかを実機で確かめる。
    // M15.7: Global Object Access Auditing を AppContainer の package SID へ絞れるかの実測。
    // **マシンの監査ポリシーを一時的に変更する**（テスト側のDropガードで撤去）。
    (
        "etw-audit-scope",
        &[
            "test", "-p", "harness-sandbox", "--lib", "--", "--ignored", "--test-threads=1",
            "--nocapture", "can_global_object_access_auditing_be_scoped",
        ],
    ),
    // M15.7: 許可レベル×操作種別の真理値表（拒否から操作種別を推定できるかの実測）。
    // M15.7: 削除の拒否がCreate段階で起きるのか、SetInformation段階なのかの実測。
    (
        "etw-delete-denial",
        &[
            "test", "-p", "harness-sandbox", "--lib", "--", "--ignored", "--test-threads=1",
            "--nocapture", "where_does_a_delete_denial_surface",
        ],
    ),
    // M15.7 / 残課題a-2: 「開けるが操作で落ちる」拒否がどのイベント列として現れるか。
    (
        "etw-operation-denial",
        &[
            "test", "-p", "harness-sandbox", "--lib", "--", "--ignored", "--test-threads=1",
            "--nocapture", "where_does_an_operation_stage_denial_surface",
        ],
    ),
    (
        "etw-access-matrix",
        &[
            "test", "-p", "harness-sandbox", "--lib", "--", "--ignored", "--test-threads=1",
            "--nocapture", "access_denials_by_granted_level_and_operation",
        ],
    ),
    // M15.7: 既知の未検証項目（EventsLost・変換不能パス・相関取りこぼし・短命プロセス帰属率・
    // DELETE_PATHの失敗時発火）の実測。
    (
        "etw-diagnostics",
        &[
            "test", "-p", "harness-sandbox", "--lib", "--", "--ignored", "--test-threads=1",
            "--nocapture", "policy_learnd::etw::diagnostics_tests",
        ],
    ),
    // M15.7 A-4d: AppContainer子プロセスでのETW実測（拒否の観測・PID帰属・PackageFullNameの有無）。
    (
        "e2e-policy-learn",
        &[
            "test", "-p", "harness-sandbox", "--lib", "--", "--ignored", "--test-threads=1",
            "--nocapture", "appcontainer_child_denials",
        ],
    ),
    (
        "spike-etw-fs",
        &[
            "test", "-p", "harness-sandbox", "--lib", "--", "--ignored", "--test-threads=1",
            "--nocapture", "policy_learnd::etw::spike_tests",
        ],
    ),
    (
        "e2e-loopback-exemption",
        &[
            "test", "-p", "harness-sandbox", "--lib", "--", "--ignored", "--test-threads=1",
            "--nocapture", "loopback",
        ],
    ),
    // M15.5: MCPサーバ隔離（D-38）の実機E2E。workspace/`.harness`への到達不可（残課題#4）と、
    // サーバ別の出口allowlist（残課題#3）。`--test-threads=1`はAppContainerプロファイル・
    // WFPというマシン全体の共有状態を触るため（Tier2a残課題#4と同じ理由）。
    (
        "e2e-mcp",
        &[
            "test", "-p", "harness-sandbox", "--lib", "--", "--ignored", "--test-threads=1",
            "--nocapture", "win_appcontainer::mcp_e2e_tests",
        ],
    ),
    (
        "e2e-wfp-multisession",
        &[
            "test", "-p", "harness-sandbox", "--lib", "--", "--ignored", "--test-threads=1",
            "--nocapture", "wfp::tests::e2e_",
        ],
    ),
    (
        "e2e-sandbox-vm-ignored",
        &[
            "test", "-p", "harness-sandbox-vm", "--lib", "--", "--ignored", "--test-threads=1",
            "--nocapture",
        ],
    ),
    // --- `plans/PLAN-M15.7-FOLLOWUP.md` W1/W6/W7 用（テスト本体は各工程で書く） ---
    //
    // **キーの追加はデーモン停止＋再ビルド＋UACを伴うので、テストより先にまとめて登録する。**
    // ここに書いたフィルタ文字列はテスト名に対する契約であり、後から名前を変えると
    // 再びこの往復が要る。テストが存在しない間これら3件は`check_tests_actually_ran`により
    // **非0で失敗する**（「まだ書いていない」を緑と誤認しないため、意図した挙動）。
    //
    // W1: `--fs-allow`の到達性を、祖先が未付与の状態で実測する。
    (
        "etw-fs-allow-reach",
        &[
            "test", "-p", "harness-sandbox", "--lib", "--", "--ignored", "--test-threads=1",
            "--nocapture", "policy_learnd::etw::fs_allow_reach_tests",
        ],
    ),
    // W6: `--fs-allow`を実CLIフラグ経由で通すout-of-process E2E。
    (
        "e2e-fs-allow",
        &[
            "test", "-p", "harness-cli", "--features", "e2e-mock", "--", "--ignored", "--nocapture",
            "tier2a_fs_allow",
        ],
    ),
    // W7: netfilterdからのpolicy-learnd連鎖起動（追加UACなし経路）をassertにする。
    (
        "e2e-chain-launch",
        &[
            "test", "-p", "harness-cli", "--features", "e2e-mock", "--", "--ignored", "--nocapture",
            "tier2a_chain_launch",
        ],
    ),
    // `dev-elevated-runner`自身は除外する。デーモン(`dev-elevated-runnerd.exe`)がこの
    // コマンドを実行している間、自分自身の実行ファイルは起動中でロックされておりリンクし
    // 直せない（実機で`error: failed to remove file ...dev-elevated-runnerd.exe: アクセスが
    // 拒否されました`を確認済み）。本セッションで再ビルドが必要な対象はharness本体側だけ。
    ("workspace-build", &["build", "--workspace", "--exclude", "dev-elevated-runner"]),
    (
        "workspace-clippy",
        &["clippy", "--workspace", "--exclude", "dev-elevated-runner", "--all-targets"],
    ),
    ("workspace-test", &["test", "--workspace", "--exclude", "dev-elevated-runner"]),
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRequest {
    /// `KNOWN_TARGETS`のキーのいずれかと完全一致する必要がある。
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResponse {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// サーバ側が権威的に検証する（クライアント側でも同じ関数を使うが、クライアントを
/// 信用しない——実際にコマンドを起動するのはサーバ側の`resolve_target`であり、
/// そちらも独立に`KNOWN_TARGETS`の完全一致を要求する）。
pub fn validate_target(target: &str) -> Result<(), String> {
    if KNOWN_TARGETS.iter().any(|(name, _)| *name == target) {
        Ok(())
    } else {
        let known: Vec<&str> = KNOWN_TARGETS.iter().map(|(name, _)| *name).collect();
        Err(format!("unknown target {target:?} (known targets: {known:?})"))
    }
}

/// `target`に対応する固定引数列を返す。`validate_target`と同じ完全一致判定を独立に
/// 行うため、こちらを呼ぶだけでも安全（`validate_target`を呼び忘れても任意引数は
/// 実行されない）。
pub fn resolve_target_args(target: &str) -> Option<&'static [&'static str]> {
    KNOWN_TARGETS
        .iter()
        .find(|(name, _)| *name == target)
        .map(|(_, args)| *args)
}

/// `cargo test`のstdoutから、**実際に実行された**テスト件数（passed + failed）を数える。
///
/// テストハーネスはバイナリごとに
/// `test result: ok. 12 passed; 0 failed; 3 ignored; 0 measured; 45 filtered out; ...`
/// を1行印字する。複数のテストバイナリが走る対象（`e2e-all`等）では**合計**を返す
/// ——個々のバイナリが0件になるのは正常（`--ignored`が1つも当たらないターゲットがある）で、
/// 「どれも走らなかった」だけが異常だからである。
///
/// `test result:`行が1つも無ければ`None`。これは「0件走った」とは違う状態
/// （テストハーネスがそもそも起動していない＝ビルド失敗等）なので、呼び出し側が
/// 区別できるようにする。
pub fn executed_test_count(stdout: &str) -> Option<u64> {
    let mut total: Option<u64> = None;
    for line in stdout.lines() {
        let Some(summary) = line.trim_start().strip_prefix("test result:") else {
            continue;
        };
        let passed = count_before(summary, "passed").unwrap_or(0);
        let failed = count_before(summary, "failed").unwrap_or(0);
        total = Some(total.unwrap_or(0) + passed + failed);
    }
    total
}

/// `ok. 12 passed; 0 failed; ...`から`label`直前の数値を取り出す。
///
/// 失敗した実行の要約は`FAILED. 10 passed; 2 failed; ...`という形なので、
/// 小文字の`failed`を探せば見出し語の`FAILED.`とは衝突しない。
fn count_before(summary: &str, label: &str) -> Option<u64> {
    let index = summary.find(label)?;
    summary[..index].split_whitespace().next_back()?.parse().ok()
}

/// テストターゲットなのに1件も走らなかったら、それは「緑」ではなく**壊れたフィルタ**である。
///
/// `cargo test`はフィルタが1件もマッチしなくてもexit 0を返すため、`KNOWN_TARGETS`の
/// フィルタ文字列がモジュール改名に追随しそこねると、E2E一式が黙って走らなくなる
/// （`docs/bugs/BUG-056.md`。CoW封じ込めE2E 17件が実際にこれを踏んだ）。
/// **「テストが走っていない」は「テストが通った」と外形上区別が付かない**ので、
/// ここで明示的に潰す。
///
/// テストを実行しないターゲット（`workspace-build`・`workspace-clippy`）は対象外。
/// 未知のキーも`Ok`にする——入力検証は[`validate_target`]の責務であり、ここを
/// 意味の違う2つ目のゲートにしない。
pub fn check_tests_actually_ran(target: &str, stdout: &str) -> Result<(), String> {
    let Some(args) = resolve_target_args(target) else {
        return Ok(());
    };
    if args.first() != Some(&"test") {
        return Ok(());
    }
    match executed_test_count(stdout) {
        Some(0) => Err(format!(
            "target {target:?} reported success but ran 0 tests. `cargo test` exits 0 when its \
             filter matches nothing, so this is a broken filter, not a pass. Check the filter for \
             {target:?} in KNOWN_TARGETS (crates/dev-elevated-runner/src/lib.rs) against the \
             actual module/test names -- see docs/bugs/BUG-056.md"
        )),
        None => Err(format!(
            "target {target:?} reported success but its output contains no test-harness summary \
             ('test result:' line). The test binaries probably never started"
        )),
        Some(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BUG-056の実物。`cargo test -p harness-sandbox --lib -- --ignored --test-threads=1
    /// --nocapture win_appcontainer::cow_diagnostics`（改名前のフィルタ）が実際に印字した出力。
    /// **捏造せず実機から採る**——このクラスを閉じる関数が、想像した書式ではなく
    /// 本物の書式を相手にしていることを固定するため。
    const ZERO_TESTS: &str = "\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; \
                              0 measured; 252 filtered out; finished in 0.00s\n";

    #[test]
    fn a_normal_run_counts_the_tests_it_executed() {
        let stdout = "running 12 tests\n\ntest result: ok. 12 passed; 0 failed; 3 ignored; \
                      0 measured; 45 filtered out; finished in 1.23s\n";
        assert_eq!(executed_test_count(stdout), Some(12));
        assert!(check_tests_actually_ran("cow-diagnostics", stdout).is_ok());
    }

    /// 実行件数であって成功件数ではない。失敗を含む実行は「走った」に数える
    /// （失敗そのものは終了コードが既に伝えている）。見出し語の`FAILED.`を
    /// `failed`と取り違えないことも、ここで一緒に固定される。
    #[test]
    fn a_failing_run_still_counts_as_having_run() {
        let stdout = "test result: FAILED. 10 passed; 2 failed; 0 ignored; 0 measured; \
                      0 filtered out; finished in 4.00s\n";
        assert_eq!(executed_test_count(stdout), Some(12));
    }

    /// 複数のテストバイナリが走る対象（`e2e-all`）では、0件のバイナリが混ざるのは正常。
    /// 判定は合計で行う。
    #[test]
    fn one_empty_binary_among_several_is_not_a_failure() {
        let stdout = "running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; \
                      0 measured; 7 filtered out; finished in 0.00s\n\nrunning 3 tests\n\n\
                      test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; \
                      0 filtered out; finished in 9.00s\n";
        assert_eq!(executed_test_count(stdout), Some(3));
        assert!(check_tests_actually_ran("e2e-all", stdout).is_ok());
    }

    /// BUG-056そのもの。全バイナリ0件なら、exit 0でも失敗にする。
    #[test]
    fn a_target_that_ran_no_tests_at_all_is_reported_as_broken() {
        assert_eq!(executed_test_count(ZERO_TESTS), Some(0));
        let error = check_tests_actually_ran("cow-diagnostics", ZERO_TESTS)
            .expect_err("0 tests must not be treated as a pass");
        assert!(error.contains("ran 0 tests"), "{error}");
        // 次に踏む人が原因へ最短で行けること（メッセージの中身も契約の一部）。
        assert!(error.contains("KNOWN_TARGETS"), "{error}");
        assert!(error.contains("BUG-056"), "{error}");
    }

    /// テストハーネスが1度も起動しなかった場合は「0件」とは別の失敗として報告する。
    #[test]
    fn output_without_any_harness_summary_is_reported_separately() {
        assert_eq!(executed_test_count("error: could not compile `harness-cli`"), None);
        let error = check_tests_actually_ran("cow-diagnostics", "error: could not compile")
            .expect_err("a missing harness summary must not be treated as a pass");
        assert!(error.contains("no test-harness summary"), "{error}");
    }

    /// テストを実行しないターゲットは対象外（`cargo build`の出力に`test result:`は無い）。
    #[test]
    fn non_test_targets_are_out_of_scope() {
        assert!(check_tests_actually_ran("workspace-build", "    Finished `dev` profile").is_ok());
        assert!(check_tests_actually_ran("workspace-clippy", "").is_ok());
        // 入力検証は`validate_target`の責務なので、未知のキーはここでは判定しない。
        assert!(check_tests_actually_ran("no-such-target", ZERO_TESTS).is_ok());
        assert!(validate_target("no-such-target").is_err());
    }

    /// `KNOWN_TARGETS`の中で`cargo test`を走らせる全ターゲットが、この検知の対象に入ること。
    /// 新しいテストターゲットを足したときに、この検知だけ素通りする形にならないよう固定する。
    #[test]
    fn every_test_target_is_covered_by_the_zero_test_check() {
        for (name, args) in KNOWN_TARGETS {
            if args.first() != Some(&"test") {
                continue;
            }
            assert!(
                check_tests_actually_ran(name, ZERO_TESTS).is_err(),
                "test target {name:?} would silently pass with 0 tests"
            );
        }
    }
}

#[cfg(windows)]
pub mod win {
    use super::*;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL, WAIT_OBJECT_0,
    };
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
        TOKEN_USER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::System::IO::OVERLAPPED;

    #[derive(Debug)]
    pub enum IpcError {
        Ipc(String),
        Win32(String),
    }

    impl std::fmt::Display for IpcError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                IpcError::Ipc(s) => write!(f, "ipc error: {s}"),
                IpcError::Win32(s) => write!(f, "win32 error: {s}"),
            }
        }
    }

    pub fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn current_user_sid_string() -> windows::core::Result<String> {
        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
            let mut ret_len = 0u32;
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut ret_len);
            let mut buf = vec![0u8; ret_len as usize];
            GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr() as *mut _),
                ret_len,
                &mut ret_len,
            )?;
            let _ = CloseHandle(token);
            let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut sid_str = windows::core::PWSTR::null();
            ConvertSidToStringSidW(token_user.User.Sid, &mut sid_str)?;
            let s = sid_str.to_string()?;
            let _ = windows::Win32::Foundation::LocalFree(HLOCAL(sid_str.0 as *mut _));
            Ok(s)
        }
    }

    pub fn pipe_name_for_current_user() -> windows::core::Result<String> {
        Ok(format!("{PIPE_NAME_PREFIX}{}", current_user_sid_string()?))
    }

    pub fn user_only_security_attributes(sid: &str) -> windows::core::Result<SECURITY_ATTRIBUTES> {
        let sddl = format!("D:(A;;GA;;;{sid})");
        unsafe {
            let sddl_w = wide(&sddl);
            let mut sd = PSECURITY_DESCRIPTOR::default();
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl_w.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )?;
            Ok(SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0,
                bInheritHandle: false.into(),
            })
        }
    }

    pub fn run_overlapped<F>(
        handle: HANDLE,
        timeout: std::time::Duration,
        op_name: &str,
        start: F,
    ) -> Result<u32, IpcError>
    where
        F: FnOnce(*mut OVERLAPPED) -> windows::core::Result<()>,
    {
        use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
        use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult};
        unsafe {
            let event = CreateEventW(None, true, false, PCWSTR::null())
                .map_err(|e| IpcError::Ipc(format!("{op_name}: CreateEventW failed: {e}")))?;
            let mut overlapped = OVERLAPPED {
                hEvent: event,
                ..Default::default()
            };
            let pending = match start(&mut overlapped as *mut _) {
                Ok(()) => false,
                Err(e) => {
                    let code = e.code();
                    if code == windows::core::HRESULT::from_win32(ERROR_IO_PENDING.0) {
                        true
                    } else if code == windows::core::HRESULT::from_win32(ERROR_PIPE_CONNECTED.0) {
                        let _ = CloseHandle(event);
                        return Ok(0);
                    } else {
                        let _ = CloseHandle(event);
                        return Err(IpcError::Ipc(format!("{op_name} failed to start: {e}")));
                    }
                }
            };
            if pending {
                let wait =
                    WaitForSingleObject(event, timeout.as_millis().min(u32::MAX as u128) as u32);
                if wait != WAIT_OBJECT_0 {
                    let _ = CancelIoEx(handle, Some(&overlapped as *const _));
                    let mut transferred = 0u32;
                    let _ = GetOverlappedResult(handle, &overlapped, &mut transferred, true);
                    let _ = CloseHandle(event);
                    return Err(IpcError::Ipc(format!("{op_name} timed out after {timeout:?}")));
                }
            }
            let mut transferred = 0u32;
            let result = GetOverlappedResult(handle, &overlapped, &mut transferred, false);
            let _ = CloseHandle(event);
            result.map_err(|e| IpcError::Ipc(format!("{op_name}: GetOverlappedResult failed: {e}")))?;
            Ok(transferred)
        }
    }

    pub fn write_all_timeout(
        handle: HANDLE,
        buf: &[u8],
        timeout: std::time::Duration,
    ) -> Result<(), IpcError> {
        use windows::Win32::Storage::FileSystem::WriteFile;
        let mut offset = 0usize;
        while offset < buf.len() {
            let slice = &buf[offset..];
            let written = run_overlapped(handle, timeout, "WriteFile", |ov| unsafe {
                WriteFile(handle, Some(slice), None, Some(ov))
            })?;
            if written == 0 {
                return Err(IpcError::Ipc("WriteFile wrote 0 bytes".to_string()));
            }
            offset += written as usize;
        }
        Ok(())
    }

    pub fn read_exact_timeout(
        handle: HANDLE,
        buf: &mut [u8],
        timeout: std::time::Duration,
    ) -> Result<(), IpcError> {
        use windows::Win32::Storage::FileSystem::ReadFile;
        let mut offset = 0usize;
        while offset < buf.len() {
            let slice = &mut buf[offset..];
            let read = run_overlapped(handle, timeout, "ReadFile", |ov| unsafe {
                ReadFile(handle, Some(slice), None, Some(ov))
            })?;
            if read == 0 {
                return Err(IpcError::Ipc("ReadFile read 0 bytes (pipe closed?)".to_string()));
            }
            offset += read as usize;
        }
        Ok(())
    }

    pub fn write_framed_timeout(
        handle: HANDLE,
        payload: &[u8],
        timeout: std::time::Duration,
    ) -> Result<(), IpcError> {
        let len = (payload.len() as u32).to_le_bytes();
        write_all_timeout(handle, &len, timeout)?;
        write_all_timeout(handle, payload, timeout)
    }

    pub fn read_framed_timeout(
        handle: HANDLE,
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>, IpcError> {
        let mut len_buf = [0u8; 4];
        read_exact_timeout(handle, &mut len_buf, timeout)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        if len > 0 {
            read_exact_timeout(handle, &mut payload, timeout)?;
        }
        Ok(payload)
    }

    pub fn connect_with_timeout(pipe: HANDLE, timeout: std::time::Duration) -> Result<(), IpcError> {
        use windows::Win32::System::Pipes::ConnectNamedPipe;
        run_overlapped(pipe, timeout, "ConnectNamedPipe", |ov| unsafe {
            ConnectNamedPipe(pipe, Some(ov))
        })?;
        Ok(())
    }
}
