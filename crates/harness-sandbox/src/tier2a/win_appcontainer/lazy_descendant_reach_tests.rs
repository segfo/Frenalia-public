//! [D-88（`plans/DESIGN-SANDBOX-APPPOLICY.md` §5.1.3）検証3「子孫到達」] **注入したフックが
//! 子・孫まで届き、そこでもfault-inが効くか**を、実際に多段のプロセスを起こして測る。
//!
//! # なぜ`cargo build`で測らないのか
//!
//! 本節の設計は`cargo`→`rustc`を例に挙げているが、**この機構だけでは測れない**——
//! ツールチェーン（`~/.cargo`・rustup・MSVCのlink.exe）はワークスペースの**外**にあり、
//! そこへ届くにはfs passthroughの宣言が要る。その宣言を作るポリシーエディタはまだ
//! 仕上がっていないので、`cargo build`を測ろうとすると**測っているのがlazyレーンなのか
//! 宣言の不足なのか区別できない**。
//!
//! そこで**ワークスペースの中とOS標準のものだけで完結する代用**にする。測りたいのは
//! 「フックが子孫へ届くか」であって「cargoが動くか」ではないので、**多段でプロセスを起こし、
//! それぞれが未準備のファイルを開く**形なら同じことが測れる。
//!
//! # 何を測るか（4段）
//!
//! | 段 | 起こすもの | 測るもの |
//! |---|---|---|
//! | 1 | 親のPowerShell自身 | 大量の属性照会と読取でfault-inが回るか |
//! | 2 | 子（`cmd.exe`） | `CreateProcess`フック経由で設定が伝わるか |
//! | 3 | 孫（`cmd` → `powershell`） | 2段先まで伝わるか |
//! | 4 | 32bitの孫（`SysWOW64\cmd.exe`） | x86 DLLの再注入経路が生きているか |
//!
//! **4段目が落ちても、それは「透過性が届かない」であって境界の穴ではない**（D-01）。
//! ACLが拒否する側は変わらない。
//!
//! ```text
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 lazy_descendant_reach
//! ```

use std::sync::atomic::Ordering;

use super::test_support::{
    cleanup_workspace, make_unreachable, scopeguard, workspace_grants, TestDirGuard,
};
use super::*;

/// 未準備にしておくファイルを置く場所。**深い位置に置く**ので、祖先も含めて割り込みで
/// 付与される経路を通る。
const PROBES: [&str; 4] = [
    r"late\p1\parent.txt",
    r"late\p2\child.txt",
    r"late\p3\grandchild.txt",
    r"late\p4\wow64.txt",
];
const MARKER: &str = "lazy-descendant-reach-marker";

/// 段6（量のある工程）で**未準備のまま**にしておくファイル数。
///
/// 1件ずつの割り込みが連続して成立するかを見るためのもので、**数が多いほど良いわけではない**
/// ——ここで測りたいのは「連続しても崩れないか」であって速さではない。150件で
/// 「1件だけたまたま通った」との区別は十分に付く。
const BULK_COUNT: usize = 150;

/// 4段ぶんを1回の子プロセスで走らせるスクリプト。
///
/// **各段が別々のファイルを読む**ので、どの段が落ちたかが出力から分かる
/// （まとめて1ファイルにすると、1段目が通った時点で残りが「もう届いている」になり、
/// 2段目以降を測ったことにならない）。
///
/// 32bitの段は**この機に無ければ飛ばす**——`SysWOW64`が無い環境で落としても、
/// 測れなかったことと壊れていることの区別が付かなくなる（`B-12`）。
fn probe_script(workspace: &std::path::Path) -> String {
    let ws = workspace.display();
    format!(
        r#"$ErrorActionPreference = 'SilentlyContinue'
# 段0: ツリー全体の属性照会。増分ビルドが最初にやることで、fault-inの引き金のうち
# `NtQuery*AttributesFile` を通す。
$seen = (Get-ChildItem -LiteralPath '{ws}' -Recurse -File).Count
Write-Output "enumerated=$seen"

# 段1: 親自身が未準備のファイルを読む。
$p1 = Get-Content -Raw -LiteralPath '{ws}\{p1}'
if ($p1 -match '{marker}') {{ Write-Output 'stage1-parent=ok' }} else {{ Write-Output 'stage1-parent=NG' }}

# 段2: 子（cmd.exe）。CreateProcessフック経由で設定が伝わっているか。
$p2 = & cmd.exe /c "type ""{ws}\{p2}"""
if ("$p2" -match '{marker}') {{ Write-Output 'stage2-child=ok' }} else {{ Write-Output 'stage2-child=NG' }}

# 段3: 孫（cmd -> powershell）。2段先まで伝わるか。
$p3 = & cmd.exe /c "powershell -NoProfile -NonInteractive -Command ""Get-Content -Raw -LiteralPath '{ws}\{p3}'"""
if ("$p3" -match '{marker}') {{ Write-Output 'stage3-grandchild=ok' }} else {{ Write-Output 'stage3-grandchild=NG' }}

# 段4: 32bitの孫（WOW64）。x86 DLLの再注入経路。**無い機では測らない。**
$wow = "$env:SystemRoot\SysWOW64\cmd.exe"
if (Test-Path -LiteralPath $wow) {{
  $p4 = & $wow /c "type ""{ws}\{p4}"""
  if ("$p4" -match '{marker}') {{ Write-Output 'stage4-wow64=ok' }} else {{ Write-Output 'stage4-wow64=NG' }}
}} else {{
  Write-Output 'stage4-wow64=skipped'
}}

# 段5: 書込も通ること（読取だけ測ると、書ける側が壊れていても緑になる）。
Set-Content -LiteralPath '{ws}\late\written-by-probe.txt' -Value '{marker}'
if ((Get-Content -Raw -LiteralPath '{ws}\late\written-by-probe.txt') -match '{marker}') {{
  Write-Output 'stage5-write=ok'
}} else {{ Write-Output 'stage5-write=NG' }}

# 段6: **量のある工程**。ネイティブの検索ツール（findstr）で再帰的に全件読ませる。
# ビルドの入力走査に近い形——PowerShell経由ではなく実行ファイルが直接I/Oを回すので、
# 1件ずつの割り込みが{bulk}件連続で成立するかを見る。
Set-Location -LiteralPath '{ws}'
$found = (& cmd.exe /c "findstr /s /m /c:{marker} bulk\*.txt" | Measure-Object -Line).Lines
Write-Output "stage6-bulk=$found"
"#,
        ws = ws,
        p1 = PROBES[0],
        p2 = PROBES[1],
        p3 = PROBES[2],
        p4 = PROBES[3],
        marker = MARKER,
        bulk = BULK_COUNT,
    )
}

/// **フックは子・孫まで届き、そこでもfault-inが効く。**
///
/// 落ちた段が分かる形で出す——`stage2-child=NG`なら「子へ設定が伝わっていない」、
/// `stage4-wow64=NG`なら「32bitの再注入だけが届いていない」と読める。
/// **どれが落ちても境界の穴ではない**（ACLの拒否は変わらない、D-01）が、
/// 既定へ上げてよいかの判断はここで決まる。
#[test]
#[ignore = "spawns real AppContainer children (and grandchildren) and changes real ACLs; run NON-elevated with --test-threads=1"]
fn the_hooks_reach_children_and_grandchildren_and_fault_in_still_works() {
    std::env::set_var(lazy_grant::LAZY_LANE_ENV, "1");
    assert!(
        matches!(lazy_grant::lane(), grant_job::PreparationLane::Lazy),
        "the probe must select the lazy lane (is the redirector DLL next to the test binary?)"
    );

    let guard = TestDirGuard::create("lazy-reach");
    let workspace = guard.path().to_path_buf();
    for probe in PROBES {
        let path = workspace.join(probe);
        std::fs::create_dir_all(path.parent().expect("probe has a parent"))
            .expect("create probe dirs");
        std::fs::write(&path, MARKER).expect("create probe file");
    }
    // 属性照会の段に意味を持たせるだけの厚み。
    for i in 0..300 {
        std::fs::write(workspace.join(format!("f{i:03}.txt")), b"x").expect("fill the tree");
    }
    // 段6（量のある工程）用。**全件が未準備のまま**になる。
    std::fs::create_dir_all(workspace.join("bulk")).expect("create the bulk dir");
    for i in 0..BULK_COUNT {
        std::fs::write(workspace.join(format!("bulk\\b{i:04}.txt")), MARKER)
            .expect("create a bulk file");
    }

    let outcome = preflight(&workspace, &[], None, &WorkspaceWriteMode::DirectRw)
        .unwrap_or_else(|e| panic!("preflight must succeed ({e:?})"));
    for warning in &outcome.warnings {
        eprintln!("preflight warning: {warning}");
    }
    grant_job::wait_until_done().expect("the initial preparation must finish");

    let canonical_ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.clone());
    let _cleanup = scopeguard({
        let canonical_ws = canonical_ws.clone();
        move || cleanup_workspace(&canonical_ws)
    });
    let grants = workspace_grants(&canonical_ws);
    let session = ensure_profile(&crate::tier2a::session_profile::current_profile_name())
        .expect("the session profile must exist");
    let workspace_cap = workspace_capability_sid(&canonical_ws, "rwx")
        .expect("the rwx capability must exist");

    // **4つとも未準備にする。** 1つだけだと、最初の段が付与した時点で残りが
    // 「もう届いている」になり、2段目以降を測ったことにならない。
    for probe in PROBES {
        make_unreachable(&workspace.join(probe), &grants);
    }
    // 段6のぶんも全件未準備にする。**ここを飛ばすと、findstrは最初から届いている
    // ファイルを読むだけになり「量のある割り込み」を測ったことにならない。**
    for i in 0..BULK_COUNT {
        make_unreachable(&workspace.join(format!("bulk\\b{i:04}.txt")), &grants);
    }

    let mut writer = lazy_grant::writer::AclWriter::start(canonical_ws.clone(), grants.clone());
    let capabilities: Vec<String> = grants
        .iter()
        .filter_map(|g| crate::win_common::sid_to_string(g.sid.as_psid()).ok())
        .collect();
    let mut broker = lazy_grant::broker::Broker::start(
        lazy_grant::broker::FaultPolicy {
            canonical_workspace: canonical_ws.clone(),
            skip: vec![canonical_ws.join(".harness")],
            mode: "rwx".to_string(),
        },
        writer.handle(),
        &capabilities,
    )
    .expect("the fault receiver must open");
    let pipe = broker.pipe_name().to_string();

    let (shell, _) = resolve_shell();
    let script = probe_script(&workspace);
    let child = spawn_with_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", &script],
        &workspace,
        &crate::secret_env::build_child_env(),
        false,
        session.as_psid(),
        NetworkCapability::Deny,
        RedirectorInject::lazy(&canonical_ws, &pipe),
        &[workspace_cap.as_psid()],
        DomainIdentity::Capability(workspace_cap.as_psid()),
    )
    .expect("spawn the multi-generation probe");
    let (stdout, stderr, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("read the probe output");

    let broker_stats = broker.stop();
    let writer_stats = writer.stop_at_safe_point();
    eprintln!("[descendant reach] exit={code}\n{stdout}\n--- stderr ---\n{stderr}");
    eprintln!("[descendant reach] broker={broker_stats:?} writer={writer_stats:?}");

    // **1段目は必ず通ること。** ここが落ちているなら測っているのは子孫到達ではない。
    assert!(
        stdout.contains("stage1-parent=ok"),
        "the injected parent itself must fault in its own file; \
         everything below is meaningless otherwise (exit={code})\n{stdout}\n{stderr}"
    );
    // **割り込みが実際に成立していること**（読めただけでは「最初から届いていた」と区別できない）。
    assert!(
        broker_stats.served >= 1,
        "the receiver must have served interrupts: {broker_stats:?}"
    );

    // 残りの段は**落ちても止めずに数える**——どこまで届いたかが成果物なので、
    // 最初のNGでpanicすると残りが測れない。
    let stages = [
        ("stage2-child", "子（cmd.exe）"),
        ("stage3-grandchild", "孫（cmd → powershell）"),
        ("stage4-wow64", "32bitの孫（WOW64）"),
        ("stage5-write", "書込"),
    ];
    let mut failed = Vec::new();
    for (key, label) in stages {
        if stdout.contains(&format!("{key}=ok")) || stdout.contains(&format!("{key}=skipped")) {
            continue;
        }
        failed.push(format!("{label}（{key}）"));
    }
    assert!(
        failed.is_empty(),
        "the hooks did not reach: {}\n--- probe output ---\n{stdout}\n--- stderr ---\n{stderr}",
        failed.join(" / ")
    );

    // 段6は**件数で見る**。「1件でも読めた」ではなく「全件読めた」でないと、
    // 連続した割り込みが途中で崩れていないと言えない。
    assert!(
        stdout.contains(&format!("stage6-bulk={BULK_COUNT}")),
        "the native recursive search must reach all {BULK_COUNT} unprepared files \
         (a smaller number means the interrupts stopped working part-way through)\
         \n--- probe output ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    // 割り込みの総数も対で見る（`B-35`）——読めた件数だけでは、
    // 「実は途中から届いていた」と「全件割り込んだ」を区別できない。
    assert!(
        broker_stats.served >= BULK_COUNT,
        "every unprepared file must have gone through the receiver: {broker_stats:?}"
    );
    let _ = Ordering::Relaxed;
}
