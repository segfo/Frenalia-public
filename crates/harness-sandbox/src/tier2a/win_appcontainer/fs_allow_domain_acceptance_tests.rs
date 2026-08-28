//! **§22.3.0.2（残課題#20の受け入れ条件）の実機測定**。
//!
//! `--fs-allow`で開けた穴の主体は、セッションのpackage SIDから**宣言ごとのcapability SID**へ
//! 移った。移行が成立したと言える条件は「拒否ACEを書いたか」ではなく
//! **許可を持たないドメインが存在するか**である（capability SID宛に`FILE_EXECUTE`のDENYを
//! 置いても素通りすることが実測されている。`plans/mac-spike/RESULTS.md` §S8）。
//!
//! ここで測るのは、**同じセッション（同じpackage SID）の中で、宣言capabilityを積んだ子と
//! 積まない子で到達可否が割れる**ことの2つである。
//!
//! | # | 条件 | このファイルのテスト |
//! |---|---|---|
//! | 1 | インタプリタ経由の実行が止まる | `only_the_declaring_domain_can_run_the_declared_script_through_an_interpreter` |
//! | 2 | 宣言したドメインだけがパスを見る | `only_the_declaring_domain_reaches_the_declared_path` |
//!
//! # 何を測っているか（測る対象を一文で書く）
//!
//! **壊れた状態＝「宣言していないドメインの子が、宣言されたパスへ届く」**である。
//! したがって見るのはACEの有無（台帳でも実DACLでもない）ではなく、
//! **子プロセスから見た実I/Oの成否**——付与が正しくてもトークンへcapabilityを積み忘れれば
//! 届かず、逆にpackage SID宛ACEが1本でも残っていれば積まなくても届く。ACLだけを見る
//! 単体テスト（`ace_grant_revoke_tests`）ではその両方が見えない。
//!
//! # 対で測る（`B-35`）
//!
//! 禁止側（宣言していないドメインが届かない）だけを見るテストは、**機構が効きすぎて
//! 全部拒否になっているときも緑になる**。だから許可側（宣言したドメインは届く）を必ず
//! 同じテストの中で測る。2つの子は**capabilityの集合だけが違い、他は同じ**にしてある。
//!
//! 加えて、禁止側では**子が起動したこと自体を印で確かめる**（`B-33`）。「印が出ない」は
//! 「拒否された」ではなく「そもそも走らなかった」でも起きるので、両者を区別できないと
//! 拒否側は常に緑になる。
//!
//! # 実行（**昇格しないこと**）
//!
//! ```text
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture fs_allow_domain_acceptance
//! ```
//!
//! 昇格すると子のトークンが実運用とずれる（`B-08`）。対象を`C:\`直下に置いてあるのは、
//! 祖先が`C:\`だけで済み、**既にtraverse台帳にあるACEで足りる＝新しい昇格が要らない**ため
//! （`%TEMP%`を使うと`preflight`がプロファイル全階層へ恒久的にtraverse ACEを付ける。
//! `docs/DEV-ENVIRONMENT.md`）。

use super::test_support::{scopeguard, TestDirGuard};
use super::*;

/// 子が「起動して、コマンドを解釈するところまでは進んだ」ことの印（`B-33`: 他人の出力を
/// 印にしない。自分で出したこの文字列だけを根拠にする）。
const CHILD_ALIVE_MARKER: &str = "HARNESS-ACCEPT-CHILD-ALIVE";
/// 宣言したパスにあるスクリプトが**実際に走った**ことの印。
const PAYLOAD_RAN_MARKER: &str = "HARNESS-ACCEPT-PAYLOAD-RAN";
/// インタプリタがスクリプトへ到達できず、例外を捕まえたことの印。
const DENIED_MARKER: &str = "HARNESS-ACCEPT-DENIED";

/// このテスト群が使う宣言（`--fs-allow <path>:read`と同じ形）。
fn read_declaration(path: &std::path::Path) -> FsPassthrough {
    FsPassthrough {
        path: path.to_path_buf(),
        access: FsAccess::Read,
        forced: false,
        scope: GrantScope::Recursive,
    }
}

/// `preflight`を通して宣言capabilityを発行・付与し、`(セッションSID, workspace capability,
/// 宣言capability)`を返す。
///
/// **失敗したら`panic!`する。** ここを「環境が整っていないので飛ばす」にすると、
/// 受け入れ条件を1度も測らないまま緑になる（`B-12`と同じ形の穴で、実際に
/// CoW封じ込めE2E 17件が0件マッチのまま緑だった前例がある）。
fn grant_and_collect_subjects(
    workspace: &std::path::Path,
    declared: &std::path::Path,
) -> (OwnedContainerSid, crate::win_common::OwnedSid, crate::win_common::OwnedSid) {
    let declaration = read_declaration(declared);
    let outcome = preflight(
        workspace,
        std::slice::from_ref(&declaration),
        None,
        &WorkspaceWriteMode::DirectRw,
    )
    .unwrap_or_else(|e| {
        panic!(
            "preflight must succeed before this measurement means anything ({e:?}); \
             if the ancestor traverse is missing, run `harness fs grant-traverse C:\\` \
             as administrator once (D10) and re-run"
        )
    });
    grant_job::wait_until_done().expect("the background grant job must finish before we spawn");

    for warning in &outcome.warnings {
        eprintln!("preflight warning: {warning}");
    }
    // **まず「測れる状態になったか」を確かめる。** 付与できていなければ、この後の
    // 「届かない」は移行が効いた証拠ではなく、ただの未付与である。
    assert!(
        outcome
            .granted_passthrough
            .iter()
            .any(|(p, _)| p == declared),
        "the declared path must be reported as granted before we measure reachability: {:?}",
        outcome.granted_passthrough
    );

    let canonical_ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.to_path_buf());
    let ws_cap = workspace_capability_sid(&canonical_ws, "rwx")
        .expect("the workspace capability must exist after preflight (D-54)");

    // 宣言の主体は**台帳の索引から引く**（本番の`launch.rs`と同じ引き方。ここで
    // `fs_allow_capability_sid`を呼ぶと発行側の口を通ってしまい、「preflightが実際に
    // 発行したもの」ではなく「このテストが今作ったもの」を測ることになる）。
    let mut decl_caps = fs_allow_capability_sids(declared, Some(&canonical_ws));
    assert_eq!(
        decl_caps.len(),
        1,
        "this workspace must have exactly one declaration subject for the path; \
         found {} (a leftover from an earlier run makes the measurement ambiguous)",
        decl_caps.len()
    );
    let decl_cap = decl_caps.pop().expect("checked above");

    (session_sid(), ws_cap, decl_cap)
}

/// 実マシンに残るもの（宣言capability宛のACEと台帳エントリ）を、**assertが落ちても**戻す
/// （`型F`。`TestDirGuard`はディレクトリしか戻さない）。
///
/// 順序は**ACEを剥がしてから台帳を落とす**。逆にすると主体を引けなくなり、撤収経路の無い
/// ACEが残る（`workspace_capability::forget_capability`のdocが定める不変条件）。
fn cleanup_declaration(workspace: std::path::PathBuf, declared: std::path::PathBuf) -> impl Drop {
    scopeguard(move || {
        let canonical_ws = workspace
            .canonicalize()
            .unwrap_or_else(|_| workspace.clone());
        if declared.exists() {
            match revoke_declaration_capabilities(&declared, Some(&canonical_ws), &|_, _| {}) {
                Ok(report) => eprintln!("cleanup: declaration ACEs revoked: {report:?}"),
                Err(e) => eprintln!("cleanup: could not revoke the declaration ACEs: {e}"),
            }
        }
        let dropped = crate::tier2a::workspace_capability::forget_capability(&canonical_ws, "");
        eprintln!("cleanup: dropped {} capability ledger entries", dropped.len());
        // `preflight`成功のたびに`workspace-grant-ledger.json`へ1行積まれる。使い捨ての
        // ワークスペースなので、消さないと**実在しないパスの記録**が溜まり続ける
        // （実測で1,043件まで育った前例があり、掃除は`harness fs prune`頼みになっていた）。
        crate::tier2a::workspace_ledger::remove_workspace_entry(&canonical_ws);
    })
}

/// 同じpackage SIDのまま、`domain_caps`だけを変えて子を起こし、標準出力を返す。
///
/// **2つのドメインの違いをこの引数1つに閉じ込める**のがこのヘルパーの目的である。
/// 起動の仕方が少しでも違うと、割れた結果を「capabilityのせい」と言えなくなる。
fn run_in_domain(
    session: &OwnedContainerSid,
    workspace: &std::path::Path,
    domain_caps: &[windows::Win32::Security::PSID],
    command: &str,
) -> String {
    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    let identity = domain_caps
        .first()
        .copied()
        .map(DomainIdentity::Capability)
        .unwrap_or(DomainIdentity::OwnPackage);
    let child = spawn_with_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", command],
        workspace,
        &env,
        false,
        session.as_psid(),
        NetworkCapability::Deny,
        None,
        domain_caps,
        identity,
    )
    .expect("spawn the domain child through the production path");
    let (stdout, stderr, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("read the child output");
    eprintln!("[domain child] exit={code}\nstdout={stdout}\nstderr={stderr}");
    stdout
}

/// **受け入れ条件2**: 宣言したドメインだけがパスを見る。
///
/// 到達性は本番のプローブ（`probe_passthrough`）で測る。主体を明示的に渡せるので、
/// 「この主体では届く／この主体では届かない」を**同じ器で**1件ずつ測れる
/// （`test_support::spawn_in_workspace`は宣言capabilityを積まないので、この測定には使えない
/// ——同ヘルパーのdocがそう名指ししている）。
#[test]
#[ignore = "spawns real AppContainer children and changes real ACLs; run NON-elevated with --test-threads=1"]
fn only_the_declaring_domain_reaches_the_declared_path() {
    let workspace_guard = TestDirGuard::create("fsallow-accept-ws");
    let declared_guard = TestDirGuard::create("fsallow-accept-declared");
    let workspace = workspace_guard.path().to_path_buf();
    let declared = declared_guard.path().to_path_buf();
    std::fs::write(declared.join("secret.txt"), b"declared-content").expect("seed the declared dir");

    let _cleanup = cleanup_declaration(workspace.clone(), declared.clone());
    let (session, ws_cap, decl_cap) = grant_and_collect_subjects(&workspace, &declared);
    let traverse = traverse_capability_sid().expect("traverse capability SID");
    let declaration = read_declaration(&declared);

    // --- 許可側: 宣言capabilityを積んだドメインは届く ---
    //
    // **この対が無いと、機構が丸ごと死んでいても禁止側だけは緑になる。**
    let reachable = probe_passthrough(
        session.as_psid(),
        traverse.as_psid(),
        Some(ws_cap.as_psid()),
        &[decl_cap.as_psid()],
        &workspace,
        &declaration,
    );
    assert!(
        reachable.is_none(),
        "the declaring domain must reach its own declaration: {reachable:?}"
    );

    // --- 禁止側: 同じセッション・同じpackage SIDでも、積まないドメインは届かない ---
    let denied = probe_passthrough(
        session.as_psid(),
        traverse.as_psid(),
        Some(ws_cap.as_psid()),
        &[],
        &workspace,
        &declaration,
    )
    .expect(
        "a domain that did not declare the path must not reach it -- if this is None, the hole \
         is still open to every domain in the session (a package-SID ACE may have survived)",
    );
    // 「届かなかった」が**別の理由**（プローブを起こせなかった）でないことを確かめる
    // ——許可側が通っている以上プローブ自体は動くが、ここを見ないと将来の回帰で
    // 「起動失敗＝拒否」と読み替わる（問4）。
    assert!(
        !denied.contains("probe failed"),
        "the denial must come from the access check, not from a failure to start the probe: {denied}"
    );
    eprintln!("the non-declaring domain was denied as expected: {denied}");
}

/// **受け入れ条件1**: インタプリタ経由の実行が止まる。
///
/// 宣言したパスにスクリプトを置き、**同じコマンド**を2つのドメインで走らせる。
/// 宣言capabilityを積んだ側だけがスクリプトを読めて実行でき、積まない側は
/// インタプリタがファイルへ到達できずに例外になる。
///
/// これが閉じるのは、`D-79`（パスベースの実行制御）が**不採用で決着した後に残っていた
/// 唯一の道**である——`--sandbox tier2a`はワークスペース内の実行を止めないが、
/// 主体を宣言ごとに割れば「読めないから走らせられない」が成立する。
///
/// **実行ポリシーは測定から外す。** 子の中で`Set-ExecutionPolicy -Scope Process Bypass`を
/// 先に撃つのは、測りたいのがACLであってPowerShellの署名ポリシーではないためである
/// （ポリシーが理由で落ちると、拒否側が「capabilityが無いから」に見えてしまう）。
#[test]
#[ignore = "spawns real AppContainer children and changes real ACLs; run NON-elevated with --test-threads=1"]
fn only_the_declaring_domain_can_run_the_declared_script_through_an_interpreter() {
    let workspace_guard = TestDirGuard::create("fsallow-accept-exec-ws");
    let declared_guard = TestDirGuard::create("fsallow-accept-exec-declared");
    let workspace = workspace_guard.path().to_path_buf();
    let declared = declared_guard.path().to_path_buf();
    let payload = declared.join("payload.ps1");
    std::fs::write(&payload, format!("Write-Output '{PAYLOAD_RAN_MARKER}'\n"))
        .expect("seed the payload script");

    let _cleanup = cleanup_declaration(workspace.clone(), declared.clone());
    let (session, ws_cap, decl_cap) = grant_and_collect_subjects(&workspace, &declared);

    // 2つのドメインへ**同じ文字列**を渡す（違いはcapabilityの集合だけにする）。
    let command = format!(
        "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; \
         Write-Output '{CHILD_ALIVE_MARKER}'; \
         try {{ & '{}' }} catch {{ Write-Output ('{DENIED_MARKER}: ' + $_.Exception.Message) }}",
        payload.display()
    );

    // --- 許可側 ---
    let declaring = run_in_domain(
        &session,
        &workspace,
        &[ws_cap.as_psid(), decl_cap.as_psid()],
        &command,
    );
    assert!(
        declaring.contains(CHILD_ALIVE_MARKER),
        "the declaring domain's child did not even start: {declaring}"
    );
    assert!(
        declaring.contains(PAYLOAD_RAN_MARKER),
        "the declaring domain must be able to run the script it declared: {declaring}"
    );

    // --- 禁止側 ---
    let non_declaring = run_in_domain(&session, &workspace, &[ws_cap.as_psid()], &command);
    assert!(
        non_declaring.contains(CHILD_ALIVE_MARKER),
        "the non-declaring domain's child never ran -- 'the payload did not run' would then say \
         nothing about the access check: {non_declaring}"
    );
    assert!(
        !non_declaring.contains(PAYLOAD_RAN_MARKER),
        "a domain that did not declare the path ran the script anyway -- the hole is still open \
         to the whole session: {non_declaring}"
    );
    assert!(
        non_declaring.contains(DENIED_MARKER),
        "the interpreter must fail on the script (and be caught), not silently produce nothing: \
         {non_declaring}"
    );
}
