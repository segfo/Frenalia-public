//! **§22.3.0.2（残課題#20の受け入れ条件）の実機測定**。
//!
//! `--fs-allow`で開けた穴の宛先SIDは、セッションのpackage SIDから**宣言ごとのcapability SID**へ
//! 移った。移行が成立したと言える条件は「拒否ACEを書いたか」ではなく
//! **許可を持たないドメインが存在するか**である（capability SID宛に`FILE_EXECUTE`のDENYを
//! 置いても素通りすることが実測されている。`plans/mac-spike/RESULTS.md` §S8）。
//!
//! ここで測るのは、**同じセッション（同じpackage SID）の中で、宣言capabilityを積んだ子と
//! 積まない子で到達可否が割れる**ことと、**子へ運ばれる宛先SIDが宣言と1対1である**ことである。
//!
//! | # | 条件 | このファイルのテスト |
//! |---|---|---|
//! | 1 | インタプリタ経由の実行が止まる | `only_the_declaring_domain_can_run_the_declared_script_through_an_interpreter` |
//! | 2 | 宣言したドメインだけがパスを見る | `only_the_declaring_domain_reaches_the_declared_path` |
//! | 3 | 運ばれる宛先SIDは**いま宣言した級**の1件だけ（分流N1） | `only_the_declared_access_class_is_carried_to_the_child` |
//! | 4 | **CoWのRO降格を通しても**、運ばれるのは実際に書いた級（測定1） | `the_cow_read_only_downgrade_carries_the_class_that_was_actually_written` |
//!
//! 3と4は同じ「宣言と1対1」を**別の作られ方**で測る（`test-logic-rules`型C）。3は同じパスへ
//! 2つの級を発行した状態から、4は`--sandbox tier2a-cow`が級を降格した状態から始める。
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
use crate::tier2a::workspace_ledger::WorkspaceMode;

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

/// `--fs-allow <path>:rw`と同じ形。**`--sandbox tier2a-cow`ではこれが`read`へ降格して書かれる**
/// （`preflight`のD-30分岐）。降格を通った後の姿を測るテストが使う。
fn read_write_declaration(path: &std::path::Path) -> FsPassthrough {
    FsPassthrough {
        path: path.to_path_buf(),
        access: FsAccess::ReadWrite,
        forced: false,
        scope: GrantScope::Recursive,
    }
}

/// `preflight`を通して宣言capabilityを発行・付与し、`(セッションSID, workspace capability,
/// 宣言capability, 運ばれた宣言エントリ)`を返す。
///
/// # 宣言と書込モードを引数で受ける理由
///
/// `--sandbox tier2a-cow`は`:rw`の宣言を`read`へ降格して書くので、**降格を通った後に何が
/// 運ばれるか**を測るには同じ器へCoWを流せなければならない。器を2つ書くと、片方だけが
/// 仕様変更に追随しない（`docs/CODE-STRUCTURE-RULES.md`規則5）。
///
/// **`GrantedPassthrough`をそのまま返す**のは、宛先SID以外の欄（`writable`）も測る対象だから
/// である——1つの構造体の中で`writable`は**要求した級**、`subject_sid`は**実際に書いた級**を
/// 表しており、CoWの降格はその2つを意図的に食い違わせる。片方だけ返すと、その食い違いが
/// 意図どおりかを確かめる手段がテストから消える。
///
/// **失敗したら`panic!`する。** ここを「環境が整っていないので飛ばす」にすると、
/// 受け入れ条件を1度も測らないまま緑になる（`B-12`と同じ形の穴で、実際に
/// CoW封じ込めE2E 17件が0件マッチのまま緑だった前例がある）。
fn grant_and_collect_subjects(
    workspace: &std::path::Path,
    declaration: &FsPassthrough,
    write_mode: &WorkspaceWriteMode,
) -> (
    OwnedContainerSid,
    crate::win_common::OwnedSid,
    crate::win_common::OwnedSid,
    harness_core::GrantedPassthrough,
) {
    let declared = declaration.path.clone();
    let outcome = preflight(
        workspace,
        std::slice::from_ref(declaration),
        None,
        write_mode,
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
    let granted = outcome
        .granted_passthrough
        .iter()
        .find(|g| g.path == declared)
        .unwrap_or_else(|| {
            panic!(
                "the declared path must be reported as granted before we measure reachability: {:?}",
                outcome.granted_passthrough
            )
        })
        .clone();

    let canonical_ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.to_path_buf());
    // workspace本体の宛先SIDのモードは**書込モードが決める**。この対応は`preflight`の
    // 同じ`match`（`WorkspaceWriteMode` → `WorkspaceMode`）と一致していなければならず、
    // ずれるとCoWで`rwx`のcapabilityを積んで「テストだけが書ける」形になる。
    // **`match`は`..`無しの全分岐に保つ**（バリアントを足したらここで落とす）。
    let ws_mode = match write_mode {
        WorkspaceWriteMode::DirectRw => WorkspaceMode::Rwx,
        WorkspaceWriteMode::Cow { .. } => WorkspaceMode::Ro,
    };
    let ws_cap = workspace_capability_sid(&canonical_ws, ws_mode.as_str())
        .expect("the workspace capability must exist after preflight (D-54)");

    // [分流N1] 宣言の宛先SIDは**`preflight`が運んできた値**を使う（本番の`launch.rs`と
    // 同じ入手経路）。かつてここは台帳の索引（`fs_allow_capability_sids`）を引いていたが、
    // **本番がそれをやめた**ので、引き続き台帳を引くと「本番が積むもの」ではなく
    // 「台帳に在るもの」を測ることになる。台帳の索引が宣言より広いこと自体は
    // `only_the_declared_access_class_is_carried_to_the_child`が別に測る。
    let decl_cap = crate::win_common::sid_from_string(&granted.subject_sid)
        .expect("preflight must hand back a usable capability SID for the declaration");

    (session_sid(), ws_cap, decl_cap, granted)
}

/// 実マシンに残るもの（宣言capability宛のACEと台帳エントリ）を、**assertが落ちても**戻す
/// （`型F`。`TestDirGuard`はディレクトリしか戻さない）。
///
/// 順序は**ACEを剥がしてから台帳を落とす**。逆にすると宛先SIDを引けなくなり、撤収経路の無い
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
/// 到達性は本番のプローブ（`probe_passthrough`）で測る。宛先SIDを明示的に渡せるので、
/// 「この宛先SIDでは届く／この宛先SIDでは届かない」を**同じ器で**1件ずつ測れる
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
    let declaration = read_declaration(&declared);
    let (session, ws_cap, decl_cap, _granted) =
        grant_and_collect_subjects(&workspace, &declaration, &WorkspaceWriteMode::DirectRw);
    let traverse = traverse_capability_sid().expect("traverse capability SID");

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
/// 宛先SIDを宣言ごとに割れば「読めないから走らせられない」が成立する。
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
    let (session, ws_cap, decl_cap, _granted) = grant_and_collect_subjects(
        &workspace,
        &read_declaration(&declared),
        &WorkspaceWriteMode::DirectRw,
    );

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

/// **受け入れ条件（分流N1）**: 子へ運ばれるcapability SIDは、**いま宣言した級のものだけ**である。
///
/// # 壊れた状態を一文で
///
/// **同じパスへ過去に別のアクセス級で発行したcapability SIDまで、子のトークンへ載る。**
/// 宛先SIDは`(秘密, 畳み込み済みパス, access級)`から決まるので、同じパスでも級が違えば
/// 別のSIDになり、それぞれ別のACEが載る。`read`だけを宣言した子に`read_write`用の
/// capability SIDまで積むと、その子は**宣言していない書込の許可へ手が届く**。
///
/// # なぜ2回`preflight`を通すのか
///
/// 「同じパスに複数の級のcapability SIDが在る」状態を作るためである。実運用では
/// `--fs-allow C:\x:rw`で1回起動し、次に`:read`で起動すれば自然にこうなる
/// （`--sandbox tier2a-cow`でも起きる——RW宣言が`read`へ降格するので、同じ宣言のまま
/// モードを変えるだけで2つ目の級が発行される）。
///
/// # 何を根拠に「1対1になった」と言うか（**対で測る**、`B-35`）
///
/// - **広い側が実在すること**を先に測る——台帳の索引（`fs_allow_capability_sids`）が
///   このパスに対して**2件**返すこと。ここが1件なら、この後の「1件だった」は
///   絞り込みが効いた証拠ではなく、**そもそも2件目が作られていない**だけである。
/// - そのうえで、`preflight`が運ぶ宛先SIDが**ちょうど1件**で、しかも
///   **いま宣言した級のもの**であること。本番の`launch.rs`はこの値をそのまま積むので、
///   これが子のトークンに載る集合そのものである。
#[test]
#[ignore = "changes real ACLs and the real capability ledger; run NON-elevated with --test-threads=1"]
fn only_the_declared_access_class_is_carried_to_the_child() {
    let workspace_guard = TestDirGuard::create("fsallow-n1-ws");
    let declared_guard = TestDirGuard::create("fsallow-n1-declared");
    let workspace = workspace_guard.path().to_path_buf();
    let declared = declared_guard.path().to_path_buf();
    std::fs::write(declared.join("seed.txt"), b"seed").expect("seed the declared dir");

    let _cleanup = cleanup_declaration(workspace.clone(), declared.clone());
    let canonical_ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.clone());

    // --- 1回目: `read_write`で宣言する（2つ目の級を先に作っておく） ---
    let rw_declaration = FsPassthrough {
        path: declared.clone(),
        access: FsAccess::ReadWrite,
        forced: false,
        scope: GrantScope::Recursive,
    };
    preflight(
        &workspace,
        std::slice::from_ref(&rw_declaration),
        None,
        &WorkspaceWriteMode::DirectRw,
    )
    .expect("the read_write declaration must be granted first");
    grant_job::wait_until_done().expect("the background grant job must finish");

    // --- 2回目: 同じパスを`read`で宣言する（本番の測定対象） ---
    let read_decl = read_declaration(&declared);
    let outcome = preflight(
        &workspace,
        std::slice::from_ref(&read_decl),
        None,
        &WorkspaceWriteMode::DirectRw,
    )
    .expect("the read declaration must be granted");
    grant_job::wait_until_done().expect("the background grant job must finish");

    // --- 広い側が実在することを先に測る（歯の確認） ---
    let ledger_subjects = fs_allow_capability_sids(&declared, Some(&canonical_ws));
    assert_eq!(
        ledger_subjects.len(),
        2,
        "this measurement is only meaningful if the ledger really holds two access classes for \
         the path; found {} (if this is 1, the second class was never issued and 'exactly one \
         was carried' proves nothing)",
        ledger_subjects.len()
    );

    // --- 狭い側: 運ばれるのはちょうど1件 ---
    let carried: Vec<&harness_core::GrantedPassthrough> = outcome
        .granted_passthrough
        .iter()
        .filter(|g| g.path == declared)
        .collect();
    assert_eq!(
        carried.len(),
        1,
        "exactly one subject must be carried for the declared path, got {:?}",
        carried
    );

    // --- しかも「いま宣言した級」のものであること ---
    //
    // 級から宛先SIDを引き直して突き合わせる。**ここで`read`側と一致し、`read_write`側と
    // 一致しないこと**が、「宣言と1対1」の中身である。
    let read_cap = fs_allow_capability_sid(&canonical_ws, &declared, FsAccess::Read)
        .expect("the read capability must exist after the second preflight");
    let rw_cap = fs_allow_capability_sid(&canonical_ws, &declared, FsAccess::ReadWrite)
        .expect("the read_write capability must exist from the first preflight");
    let read_sid = crate::win_common::sid_to_string(read_cap.as_psid()).expect("render read SID");
    let rw_sid = crate::win_common::sid_to_string(rw_cap.as_psid()).expect("render read_write SID");
    assert_ne!(
        read_sid, rw_sid,
        "the two access classes must derive different SIDs, otherwise this test cannot tell them \
         apart (the derivation would not include the access class)"
    );
    assert_eq!(
        carried[0].subject_sid, read_sid,
        "the carried subject must be the one for the access class declared in this run"
    );
    assert_ne!(
        carried[0].subject_sid, rw_sid,
        "the read_write subject from the earlier run must not be carried into this child"
    );
}

/// **受け入れ条件（測定1、`plans/HANDOFF-ISSUE-20-SUBJECT-MIGRATION.md`）**:
/// `--sandbox tier2a-cow`のRO降格を通しても、運ばれる宛先SIDは**実際にACEを書いた級**のものである。
///
/// # 壊れた状態を一文で
///
/// **CoWで`:rw`を宣言したとき、ACEは`read`級のcapability SID宛に書かれるのに、子のトークンへ
/// 運ばれるのは`read_write`級のcapability SIDになっている。**
///
/// `--sandbox tier2a-cow`はworkspace本体を読取専用にして書込を差分層へ逃がすモードで、
/// `--fs-allow <path>:rw`の要求もOSへ書くときは`read`へ降格する（D-30。書込はRedirector DLLの
/// フックを通す経路だけに絞るため）。宛先SIDは`(秘密, 畳み込み済みパス, access級)`から決まるので、
/// **級が1つ違えばまったく別のSID**になる。したがって「ユーザーが要求した級」から導出すると、
/// ACEを書いた先と積む先がずれる。
///
/// **この壊れ方は成功に見える**——ACEは正しく付き、台帳にも記録が残る。壊れるのは
/// 子のトークンへ積む先（`launch.rs`はこの値をそのまま積む）と、撤収側が探しに行く先である。
///
/// # 何を根拠に「実際に書いた級」と言うか（**対で測る**、`B-35`）
///
/// - **台帳側**: このパスへ発行された宣言capabilityが**`read`の1件だけ**であること
///   （`read_write`は1度も発行されていない）。ここが2件なら降格前の級でも発行している
/// - **DACL側**: 運ばれた宛先SID宛のACEが**実在し**、そのマスクが`read`級であること。
///   台帳ではなく実物を読む——台帳は「付けたつもり」を記録しているだけである
/// - **到達側**: 運ばれた宛先SIDを積んだ子は届き、積まない子は届かない
///
/// # このテストの歯がどこにあるか（`B-27`。**2つの壊れ方を別々に測って確かめた**）
///
/// **壊れ方が2つあり、捕まえる assert が違う。** 片方だけ試すと「歯がある」と誤解する。
///
/// | 壊れ方 | 作り方（実測） | 赤くなる assert | 緑のままの assert |
/// |---|---|---|---|
/// | `preflight`が**要求した級**から導出する | `preflight`の導出を`fp.access`→`requested.access`へ | **台帳側だけ**（`read`が未発行・`read_write`が発行済み） | DACL側・`writable`・package SID・**到達側の許可/禁止とも** |
/// | 運ぶ側が級を**導出し直す** | 運ばれた宛先SIDを`read_write`級のSIDへ差し替え | **DACL側**（その宛先SIDのACEが無い） | 台帳側 |
///
/// **到達側には、1つ目の壊れ方に対する歯が無い**（実測）。導出が要求した級に変わっても、
/// ACEも運ぶ値も同じ`entry_cap`から出るので**両方まとめてずれ、子は普通に読める**——
/// 級が違うだけで整合してしまう。だから台帳側の assert を落とせない。
/// 到達側が担当しているのは「機構が丸ごと死んでいる／全ドメインへ開いている」の側である。
///
/// 2つ目の壊れ方では**DACL側が先に落ちる**ので、到達側がそれも捕まえるかどうかは
/// このテストからは言えない（**測っていない**）。
///
/// # 実行（**昇格しないこと**）
///
/// workspace・差分層・宣言先を**3つとも`C:\`直下**に置く。差分層を入れ子にすると`preflight`が
/// 中間ディレクトリのtraverseを求めて昇格を起こす（`cow_diff_layer_subject_tests`が一度踏んだ）。
#[test]
#[ignore = "real machine: creates directories under C:\\, writes DACLs, and spawns AppContainer children; run NON-elevated with --test-threads=1"]
fn the_cow_read_only_downgrade_carries_the_class_that_was_actually_written() {
    let workspace_guard = TestDirGuard::create("fsallow-cow-ws");
    let diff_guard = TestDirGuard::create("fsallow-cow-diff");
    let declared_guard = TestDirGuard::create("fsallow-cow-declared");
    let workspace = workspace_guard.path().to_path_buf();
    let diff_layer = diff_guard.path().to_path_buf();
    let declared = declared_guard.path().to_path_buf();
    std::fs::write(declared.join("seed.txt"), b"declared-content").expect("seed the declared dir");

    let canonical_ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.clone());
    let _cleanup = cleanup_declaration(workspace.clone(), declared.clone());

    // **要求は`:rw`。** 降格させるのがこの測定の全てなので、ここを`read`にすると何も測らない。
    let requested = read_write_declaration(&declared);
    let (session, ws_cap, decl_cap, granted) = grant_and_collect_subjects(
        &workspace,
        &requested,
        &WorkspaceWriteMode::Cow {
            diff_layer_dir: diff_layer.clone(),
        },
    );

    // 差分層のACEは、台帳から名前を引ける**うちに**剥がす。`cleanup_declaration`の
    // `forget_capability`が台帳を落とすと宛先SIDを引けなくなり、撤収経路の無いACEが残る。
    // **この束縛は`_cleanup`より後**なので、Dropは先に走る（宣言の順と逆順に落ちる）。
    let diff_cap = lookup_cow_diff_layer_capability_sid(&canonical_ws, &diff_layer);
    let _diff_cleanup = scopeguard({
        let diff_layer = diff_layer.clone();
        move || {
            if let Some(cap) = &diff_cap {
                let _ = revoke_ace_recursive(&diff_layer, cap.as_psid());
            }
        }
    });

    // --- 台帳側: 発行されたのは`read`の1件だけ ---
    //
    // **広い側が作られていないことを直接見る。** ここで`read_write`が`Some`なら、降格前の級で
    // 発行しているということで、たとえ運ぶ値が正しくても撤収側は2つの索引を持つことになる。
    let read_name = crate::tier2a::workspace_capability::lookup_declaration_capability_name(
        &canonical_ws,
        &declared,
        FsAccess::Read.label(),
    )
    .expect(
        "the CoW downgrade must issue the capability for the class it actually writes (read); \
         if this is None, the subject was derived from the class the user requested",
    );
    assert_eq!(
        crate::tier2a::workspace_capability::lookup_declaration_capability_name(
            &canonical_ws,
            &declared,
            FsAccess::ReadWrite.label(),
        ),
        None,
        "the read_write class must never be issued under --sandbox tier2a-cow: the ACE that is \
         actually written is a read-class ACE, so a read_write capability would be a subject with \
         no ACE behind it (and a second index for revocation to disagree about)"
    );
    let ledger_subjects = fs_allow_capability_sids(&declared, Some(&canonical_ws));
    assert_eq!(
        ledger_subjects.len(),
        1,
        "exactly one declaration capability must exist for this path after a CoW run, found {}",
        ledger_subjects.len()
    );

    // --- 運ばれた値: ちょうど1件で、`read`級のSIDである ---
    let read_sid_from_ledger = crate::win_common::sid_to_string(
        capability_sid_from_name(&read_name)
            .expect("the recorded read capability name must render to a SID")
            .as_psid(),
    )
    .expect("render the read-class SID");
    assert_eq!(
        granted.subject_sid, read_sid_from_ledger,
        "the carried subject must be the capability of the class that was actually written (read)"
    );

    // **`writable`は要求した級のまま残る。** ここが`false`へ落ちると、CoWのRedirector DLLが
    // どのルートの書込を横取りすべきか（`ext_capture_roots`）を見失う——降格するのは
    // **ACLの級**であって、ユーザーが何を要求したかの記録ではない。
    assert!(
        granted.writable,
        "the CoW downgrade must not erase the fact that the user asked for :rw; \
         ext_capture_roots reads this field to decide which roots the redirector captures"
    );

    // --- DACL側: 運ばれたSID宛のACEが実在し、そのマスクが`read`級である ---
    //
    // **台帳ではなく実物を読む。** 台帳は「付けたつもり」を記録しているだけで、付与側の
    // 思い込みがそのまま両辺に乗る。
    let carried_mask = sid_ace_mask(&declared, decl_cap.as_psid())
        .expect("the declared path DACL must be readable")
        .expect(
            "the carried subject must be the SID that actually holds an ACE on the declared path; \
             if this is None, the ACE was written for a different class than the one being carried \
             (symptom: the ACL looks correct but the child cannot read a single byte)",
        );
    let read_mask = required_passthrough_mask(FsAccess::Read);
    assert_eq!(
        carried_mask & read_mask,
        read_mask,
        "the ACE behind the carried subject must satisfy the read-class mask \
         (got {carried_mask:#x}, need {read_mask:#x})"
    );
    let rw_mask = required_passthrough_mask(FsAccess::ReadWrite);
    assert_ne!(
        carried_mask & rw_mask,
        rw_mask,
        "the ACE must NOT satisfy the read_write mask: the whole point of --sandbox tier2a-cow is \
         that writes go through the redirector into the diff layer, not straight to the real path \
         (got {carried_mask:#x})"
    );

    // --- 移行後の不変条件（§22.3.0）: セッションpackage SID宛のACEは0本 ---
    assert_eq!(
        sid_ace_mask(&declared, session.as_psid()).expect("the declared path DACL must be readable"),
        None,
        "the session package SID must have no ACE on the declared path: it is shared by every \
         process in this AppContainer, so one such ACE re-opens the path to every domain \
         (DACL cannot express 'package SID AND capability SID' -- parallel ALLOW entries are OR)"
    );

    // --- 到達側 ---
    //
    // **降格後の級でプローブを撃つ。** 要求した`:rw`の形で撃つと書込を試して落ち、
    // 「宛先SIDが間違っている」と区別の付かない**偽の到達不能**になる
    // （本番の`preflight`も降格後の宣言でプローブしている）。
    let effective = read_declaration(&declared);
    let traverse = traverse_capability_sid().expect("traverse capability SID");

    // 許可側: 運ばれた宛先SIDを積んだ子は届く。**この対が無いと、機構が丸ごと死んでいても
    // 禁止側だけは緑になる。**
    let reachable = probe_passthrough(
        session.as_psid(),
        traverse.as_psid(),
        Some(ws_cap.as_psid()),
        &[decl_cap.as_psid()],
        &workspace,
        &effective,
    );
    assert!(
        reachable.is_none(),
        "a child carrying the subject that preflight handed back must reach the declaration \
         even after the CoW read-only downgrade: {reachable:?}"
    );

    // 禁止側: 同じセッション・同じpackage SIDでも、積まない子は届かない。
    let denied = probe_passthrough(
        session.as_psid(),
        traverse.as_psid(),
        Some(ws_cap.as_psid()),
        &[],
        &workspace,
        &effective,
    )
    .expect(
        "a domain that did not declare the path must not reach it -- if this is None, the hole is \
         still open to every domain in the session (a package-SID ACE may have survived)",
    );
    assert!(
        !denied.contains("probe failed"),
        "the denial must come from the access check, not from a failure to start the probe: {denied}"
    );
    eprintln!("the non-declaring domain was denied as expected: {denied}");
}
