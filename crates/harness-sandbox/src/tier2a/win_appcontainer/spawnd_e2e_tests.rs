//! 段階5（Spawn Daemon本体）の実機受け入れテスト。実ACLを変更するため昇格ランナーから
//! 直列実行する（`dev-elevated-run.exe spawn-daemon`）。
//!
//! # 何を合格条件にしているのか
//!
//! 解説の1枚もの（`docs/guide/11a-mac-enforcement-map.md`§3）が段階③に課しているのは
//! **対で2本を2組**である。片方だけだと、「全部拒否する」実装でも「全部届かない」実装でも
//! 緑になってしまう（`B-35`）。
//!
//! | 組 | 通るはず | 通らないはず |
//! |---|---|---|
//! | 到達性 | spawn要求用capabilityを積んだ子 → **要求受付パイプ** | 同じ子 → **制御パイプ**／capabilityを積まない子 → 要求受付パイプ |
//! | 台帳 | Daemonが起こした子 → **「台帳に無い」ではない**理由で断られる | harnessが直接起こした子 → **「台帳に無い」** |
//!
//! **2組目が肝である。** 「拒否された」だけを見ると、Daemonが常に拒否していても合格する。
//! 拒否の**理由**が変わることを見て初めて、台帳の判定が生きていると言える。
//!
//! # ここで測っていないもの
//!
//! - **遷移が許可されること**。段階5にポリシー評価は無く、答えは常に拒否である
//!   （段階Eが入るまでは`unknown_source_domain`が正しい応答）
//! - **`CHILD_PROCESS_RESTRICTED`下での動作**。積むのは段階⑤
//!
//! # 測っている世界が本番と1つだけ違う（**limitation**）
//!
//! これらは昇格ランナーから走るので、**テストの中のDaemonは昇格したトークンで動く**。
//! 本番のDaemonは非昇格である（`client::launch_daemon`は`runas`を使わない）。
//!
//! **ここで見ている事実は、その差に依存しない**——パイプのDACLはユーザーSIDと
//! capability SID宛で、どちらも昇格で変わらないからである。**依存し得るのは
//! 子の整合性レベル**で、昇格して測った回と非昇格の回で挙動が違った前例がある
//! （§S47。pwshの起動時警告）。**この4本はそこを判定に使っていない。**
//!
//! 昇格が要るのはDaemonのためではなく、workspaceの実ACLを触る`preflight`のためである。

use std::time::Duration;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};

use super::test_support::{cleanup_workspace, TestDirGuard};
use super::*;
use crate::cancel_descendants::{
    assert_cancel_completes, prepare_descendant, DescendantOutput, DescendantProbe,
};
// `super::*`は`win_appcontainer`の再エクスポートを持ち込むが、Daemon側の型はそこには載らない。
use crate::tier2a::spawnd::client::{SpawnDaemonHandle, SpawnedChild, TopLevelSpawn};
use crate::tier2a::spawnd::SharedSpawnDaemon;
use crate::tier2a::spawnd::{ChildProcessPolicy, ConsoleNeed, DomainIdentitySpec, DomainSpec};
use crate::win_common::SendHandle;

/// 1ケース分の実マシン資源。**失敗した経路でも同じ順で畳む**（`test-logic-rules`型F）。
pub(super) struct Case {
    pub(super) daemon: Option<SpawnDaemonHandle>,
    canonical_workspace: std::path::PathBuf,
    pub(super) dir: Option<TestDirGuard>,
}

impl Drop for Case {
    fn drop(&mut self) {
        // Daemonを先に畳む。畳む前にACEを剥がすと、生きている子がworkspaceを
        // 触れなくなって「機構の失敗」に見える。
        drop(self.daemon.take());
        cleanup_workspace(&self.canonical_workspace);
        drop(self.dir.take());
    }
}

/// [段階⑤] 段階⑤（子プロセス生成の禁止）の受け入れ。**ファイルを分けてあるが
/// モジュールは`spawnd_e2e_tests`の下にある**——昇格の的`spawn-daemon`のフィルタが
/// `win_appcontainer::spawnd_e2e_tests`なので、外へ出すと0件マッチで黙って走らなくなる
/// （BUG-056）。分けた理由は1ファイルの行数上限（`docs/CODE-STRUCTURE-RULES.md`）である。
mod child_process_restricted_tests;

/// [段階6b] 遷移ポリシーの受け入れ（対で3本）。**同じ理由でここに置いてある**——
/// 昇格の的`spawn-daemon`のフィルタが`win_appcontainer::spawnd_e2e_tests`なので、
/// 外へ出すと0件マッチで黙って走らなくなる（BUG-056）。
mod transition_acceptance_tests;

/// [段階6c] 拒否の待ち行列の受け入れ（対で4本）。**同じ理由でここに置いてある**——
/// 昇格の的`spawn-daemon`のフィルタが`win_appcontainer::spawnd_e2e_tests`なので、
/// 外へ出すと0件マッチで黙って走らなくなる（BUG-056）。
mod transition_queue_tests;

/// [段階6b] このファイルのテストが名乗る**遷移元ドメイン名**。
///
/// **`DomainSpec::name`（プロファイル名の側）とわざと別の綴りにしてある。**
/// 同じにすると、遷移元キーに`name`を使ってしまう実装でも緑のまま通る（`B-35`の形）。
pub(super) const E2E_POLICY_DOMAIN: &str = "spawnd-e2e-policy-domain";

/// workspaceを1つ用意し、preflightを通し、Daemonを起こす。**生成禁止は積まない。**
///
/// [段階6b] 遷移の宣言は**空**である。宣言を渡すのは
/// [`setup_with_policy_and_transitions`]で、そちらは遷移の受け入れテストだけが使う。
pub(super) fn setup(label: &str) -> (Case, OwnedContainerSid, Vec<crate::win_common::OwnedSid>) {
    setup_with_policy(label, ChildProcessPolicy::Unrestricted)
}

/// [段階⑤] 生成禁止の姿勢を選んで同じ土台を作る。
///
/// **対で測るための入口である**——同じワークスペース・同じドメインで、積んだ回と
/// 積まない回を並べないと、「全部拒否する」実装でも緑になる（`B-35`）。
pub(super) fn setup_with_policy(
    label: &str,
    child_process_policy: ChildProcessPolicy,
) -> (Case, OwnedContainerSid, Vec<crate::win_common::OwnedSid>) {
    setup_with_policy_and_transitions(label, child_process_policy, |_| {
        harness_policy::policy_file::PolicyFile::default()
    })
}

/// [段階6b] 遷移の宣言を渡して同じ土台を作る。
///
/// `declare`はワークスペースルートを受け取って`policy.json`の中身を組む
/// ——宣言の中に**そのワークスペースの実パス**が要る（実行ファイルのフルパス等）ため、
/// ディレクトリが決まった後でないと組めない。
pub(super) fn setup_with_policy_and_transitions(
    label: &str,
    child_process_policy: ChildProcessPolicy,
    declare: impl FnOnce(&std::path::Path) -> harness_policy::policy_file::PolicyFile,
) -> (Case, OwnedContainerSid, Vec<crate::win_common::OwnedSid>) {
    let guard = TestDirGuard::create(label);
    let workspace = guard.path().to_path_buf();
    let outcome = preflight(&workspace, &[], None, &WorkspaceWriteMode::DirectRw)
        .unwrap_or_else(|e| panic!("preflight must succeed: {e:?}"));
    for warning in &outcome.warnings {
        eprintln!("preflight warning: {warning}");
    }
    grant_job::wait_until_done().expect("workspace preparation must finish");
    let canonical = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.clone());
    let profile = ensure_profile(&crate::tier2a::session_profile::current_profile_name())
        .expect("session profile must exist");

    // 子が本番と同じ範囲へ到達できるようにする**このドメイン固有のもの**だけを返す。
    //
    // **traverse capabilityはここに入れない。** `spawn_with_workspace`（harnessが直接
    // 起こす経路）はD-37に従って**自分で**先頭へ積むので、ここでも積むと同じSIDが2つ並ぶ
    // ——`CreateProcessW`が`ERROR_INVALID_PARAMETER`(0x80070057)で落ちる。
    // Daemon経由の経路は自動で積まないので、そちらは[`domain_spec`]が明示的に足す。
    let mut caps: Vec<crate::win_common::OwnedSid> = Vec::new();
    if let Some(cap) = super::mac_spike_tests::workspace_capability_for(&workspace) {
        caps.push(cap);
    }

    let daemon = SpawnDaemonHandle::start(
        crate::tier2a::spawnd::TransitionPolicy {
            policy: declare(&canonical),
            workspace_root: canonical.to_string_lossy().into_owned(),
        },
        child_process_policy,
    )
    .expect("the spawn daemon must start");
    eprintln!(
        "[spawnd] daemon pid={} request_pipe={} policy={}",
        daemon.daemon_pid(),
        daemon.request_pipe(),
        child_process_policy.as_arg()
    );

    (
        Case {
            daemon: Some(daemon),
            canonical_workspace: canonical,
            dir: Some(guard),
        },
        profile,
        caps,
    )
}

/// テスト用のドメイン記述。**package SIDそのものをドメインにする**
/// （このセッションのプロファイルは1ドメインに対応する。§22.1.1の`OwnPackage`）。
///
/// **traverse capabilityをここで足す。** Daemonは受け取った一覧をそのまま積むだけで、
/// D-37の「全Tier2a子が共通で携える」を自分では知らない——`spawn_with_workspace`が
/// 自動で積むぶんを、Daemon経由では呼び出し側が明示する形になる。
pub(super) fn domain_spec(
    profile: &OwnedContainerSid,
    caps: &[crate::win_common::OwnedSid],
    extra: Option<&crate::win_common::OwnedSid>,
) -> DomainSpec {
    let traverse = traverse_capability_sid().expect("traverse capability");
    let mut capability_sids: Vec<String> = std::iter::once(&traverse)
        .chain(caps.iter())
        .map(|c| crate::win_common::sid_to_string(c.as_psid()).expect("capability sid to string"))
        .collect();
    if let Some(extra) = extra {
        capability_sids
            .push(crate::win_common::sid_to_string(extra.as_psid()).expect("extra sid to string"));
    }
    DomainSpec {
        name: "spawnd-e2e".to_string(),
        // [段階6b] **わざと`name`と違う綴りにしてある**（[`E2E_POLICY_DOMAIN`]のdoc）。
        policy_domain: E2E_POLICY_DOMAIN.to_string(),
        container_sid: crate::win_common::sid_to_string(profile.as_psid())
            .expect("container sid to string"),
        capability_sids,
        identity: DomainIdentitySpec::OwnPackage,
    }
}

/// Daemonに子を起こしてもらい、**その子のstdout/stderrと終了コード**を返す。
///
/// パイプとJobを作るのはこちら（harness役）である（§10.1「子のstdioパイプを作るプロセス」）。
fn spawn_via_daemon(
    daemon: &SpawnDaemonHandle,
    profile: &OwnedContainerSid,
    workspace: &std::path::Path,
    domain: DomainSpec,
    args: &[&str],
) -> (SpawnedChild, HANDLE, String, String) {
    let probe = super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();

    let (stdout_read, stdout_write) =
        appcontainer_pipe(profile.as_psid()).expect("stdout pipe for the daemon-spawned child");
    crate::win_common::clear_inherit(stdout_read);
    let (stderr_read, stderr_write) =
        appcontainer_pipe(profile.as_psid()).expect("stderr pipe for the daemon-spawned child");
    crate::win_common::clear_inherit(stderr_read);
    // 系統Jobを作るのは**harness**である（§10.1.1）。Daemonへは複製が渡り、
    // こちらの原本はキャンセル用に持ち続ける。
    let job = crate::win_common::create_job_object().expect("lineage job");

    let child = daemon
        .spawn_top_level(TopLevelSpawn {
            exe: &probe_str,
            args,
            cwd: workspace,
            env: &crate::secret_env::build_child_env(),
            domain,
            job,
            stdout_write,
            stderr_write,
            stdin_read: None,
            redirector: None,
            console: ConsoleNeed::NotNeeded,
        })
        .expect("the daemon must spawn the top-level child");

    let (out, err) = crate::win_common::read_two_pipes_to_strings(stdout_read, stderr_read);
    (child, job, out, err)
}

/// 子の応答JSON（`--pipe-client`が最後の行に出す）から1つの欄を読む。
pub(super) fn report_field(stdout: &str, field: &str) -> Option<serde_json::Value> {
    super::mac_spike_tests::last_json_line(stdout).and_then(|v| v.get(field).cloned())
}

/// 要求受付パイプへ送る本物の要求電文（`SpawnRequest::Spawn`）。
pub(super) fn spawn_request_payload() -> String {
    serde_json::to_string(&crate::tier2a::spawnd::SpawnRequest::Spawn {
        exe: "git.exe".to_string(),
        args: vec!["status".to_string()],
        cwd: "C:/".to_string(),
    })
    .expect("serialize the spawn request")
}

/// 子が受け取った応答（`SpawnResponse`）を取り出す。
pub(super) fn reply_json(stdout: &str) -> Option<serde_json::Value> {
    let reply = report_field(stdout, "reply")?;
    serde_json::from_str(reply.as_str()?).ok()
}

/// 応答の種別（`"spawned"` か `"denied"`）。
pub(super) fn reply_kind(stdout: &str) -> Option<String> {
    reply_json(stdout)?
        .get("kind")?
        .as_str()
        .map(|s| s.to_string())
}

/// 子が返した拒否理由を、**いちばん具体的な綴り**で取り出す。
///
/// [段階6b] `reason`は文字列ではなく`{"kind":...}`のオブジェクトになった。さらに
/// 遷移ポリシーが断ったときは、外側が`"transition"`で**中身の`denial.kind`のほうが
/// 知りたい値**である（「宣言が無い」のか「ドメインを知らない」のか）。
/// ここで1段掘っておかないと、呼び出し側のテストが全部`"transition"`としか言えなくなる。
pub(super) fn deny_reason(stdout: &str) -> Option<String> {
    let reason = reply_json(stdout)?.get("reason")?.clone();
    let kind = reason.get("kind")?.as_str()?;
    if kind == "transition" {
        return reason
            .get("denial")?
            .get("kind")?
            .as_str()
            .map(|s| s.to_string());
    }
    Some(kind.to_string())
}

// ---------------------------------------------------------------------------
// 組1: 到達性（要求受付パイプへは届く／制御パイプへは届かない）
// ---------------------------------------------------------------------------

/// **P1・P5**: spawn要求用capabilityを積んだ子が要求受付パイプへ**届き**、
/// Daemonが起こした子なので**「台帳に無い」ではない**理由で断られる。
///
/// この1本が組1の許可側と組2の許可側を兼ねる——同じ子で同じ1往復を見るので、
/// 「届いた」と「台帳に居た」が**別々の測定で食い違う**ことがない（型7の逆向き）。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_daemon_spawned_child_reaches_the_request_pipe_and_is_denied_by_policy_not_by_the_table() {
    let (case, profile, caps) = setup("spawnd-p1");
    let daemon = case.daemon.as_ref().expect("case owns the daemon");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let spawn_cap = spawn_request_capability_sid().expect("spawn request capability");
    let payload = spawn_request_payload();

    let (child, job, out, err) = spawn_via_daemon(
        daemon,
        &profile,
        &workspace,
        domain_spec(&profile, &caps, Some(&spawn_cap)),
        &[
            "--pipe-client",
            daemon.request_pipe(),
            "--pipe-payload",
            &payload,
            "--timeout-secs",
            "60",
        ],
    );
    eprintln!("[spawnd P1] stdout={out}\nstderr={err}");
    wait_and_close(&child, job);

    assert_eq!(
        report_field(&out, "connected").and_then(|v| v.as_bool()),
        Some(true),
        "spawn要求用capabilityを積んだ子が要求受付パイプへ接続できない。\
         §10.1のDACL設計が成立しない: {out}"
    );
    assert_eq!(
        report_field(&out, "reply_ok").and_then(|v| v.as_bool()),
        Some(true),
        "応答を読めていない（1往復が成立していない）: {out}"
    );
    assert_eq!(
        deny_reason(&out).as_deref(),
        Some("unknown_source_domain"),
        "Daemonが起こした子なのに「台帳に無い」で断られている。\
         §12のProcess Table登録がResumeより前に効いていない（BUG-116の形）: {out}"
    );
    drop(case);
}

/// **P2**（組1の拒否側）: 同じcapabilityを積んだ子でも、**制御パイプへは届かない**。
///
/// 制御パイプはユーザーSID専有DACLのままである（§10.1）。AppContainerのアクセスチェックは
/// ユーザーの許可と package/capability の許可の**交差**なので、package SIDにも
/// capabilityにも宛てていないこのパイプへは到達できない。**ここが破れると、
/// サンドボックスがharnessと同じ特権クライアントとして振る舞える。**
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn the_control_pipe_stays_unreachable_from_inside_the_sandbox() {
    let (case, profile, caps) = setup("spawnd-p2");
    let daemon = case.daemon.as_ref().expect("case owns the daemon");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let spawn_cap = spawn_request_capability_sid().expect("spawn request capability");
    let control = daemon.control_pipe_name().to_string();

    let (child, job, out, err) = spawn_via_daemon(
        daemon,
        &profile,
        &workspace,
        domain_spec(&profile, &caps, Some(&spawn_cap)),
        &["--pipe-client", &control, "--timeout-secs", "60"],
    );
    eprintln!("[spawnd P2] stdout={out}\nstderr={err}");
    wait_and_close(&child, job);

    assert_eq!(
        report_field(&out, "connected").and_then(|v| v.as_bool()),
        Some(false),
        "サンドボックスの中から制御パイプへ到達できた。\
         「特権クライアントとサンドボックスの区別をDACLで引く」（§10.1・P-01）が破れている: {out}"
    );
    // P3と同じ理由で、**理由まで見る**（`connected:false`は混雑でも成立する）。
    // 制御パイプはインスタンス1本なので、混雑と拒否の取り違えはここが最も起きやすい。
    assert_eq!(
        report_field(&out, "last_error").and_then(|v| v.as_u64()),
        Some(5),
        "到達できなかった理由がアクセス拒否(5)ではない。\
         231ならパイプが混雑していただけで、ユーザーSID専有DACLの効果を測れていない: {out}"
    );
    drop(case);
}

/// **P3**（組1の拒否側その2）: spawn要求用capabilityを**積まない**子は、
/// 要求受付パイプにも届かない。
///
/// これが成立して初めて、§22.2.2の`process: deny`が「パイプに到達すらできない」という
/// 二重のdenyになる——capabilityを積むかどうかが、そのままドメイン単位のスイッチである。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_child_without_the_spawn_capability_cannot_reach_the_request_pipe() {
    let (case, profile, caps) = setup("spawnd-p3");
    let daemon = case.daemon.as_ref().expect("case owns the daemon");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let payload = spawn_request_payload();

    let (child, job, out, err) = spawn_via_daemon(
        daemon,
        &profile,
        &workspace,
        // **`spawn_cap`を積まない**のがこの測定の全部である。
        domain_spec(&profile, &caps, None),
        &[
            "--pipe-client",
            daemon.request_pipe(),
            "--pipe-payload",
            &payload,
            "--timeout-secs",
            "60",
        ],
    );
    eprintln!("[spawnd P3] stdout={out}\nstderr={err}");
    wait_and_close(&child, job);

    assert_eq!(
        report_field(&out, "connected").and_then(|v| v.as_bool()),
        Some(false),
        "spawn要求用capabilityを積んでいない子が要求受付パイプへ到達できた。\
         capabilityがドメイン単位のスイッチになっていない（§10.1）: {out}"
    );
    // **「届かなかった」だけでは足りない。理由まで見る。**
    //
    // 名前付きパイプは、サーバが次の受付インスタンスを作る前の窓に当たると
    // `ERROR_PIPE_BUSY`(231)を返す。それも`connected:false`になるので、
    // **この測定はDACLと無関係な理由で緑になり得る**——実際、同じ窓を
    // `concurrent_requests_...`が踏んで発覚した。
    // 測りたいのは`ERROR_ACCESS_DENIED`(5)、つまり**DACLが拒んだこと**である。
    assert_eq!(
        report_field(&out, "last_error").and_then(|v| v.as_u64()),
        Some(5),
        "到達できなかった理由がアクセス拒否(5)ではない。\
         231ならパイプが混雑していただけで、capabilityの効果を測れていない: {out}"
    );
    drop(case);
}

// ---------------------------------------------------------------------------
// 組2: 台帳（在るPIDと無いPIDで拒否の理由が変わる）
// ---------------------------------------------------------------------------

/// **P4**（組2の拒否側）: **Daemonを通さずに**起こした子は、capabilityを積んでいても
/// 「台帳に無い」で断られる。
///
/// P1と対になる——同じcapability・同じ電文で、**違うのは誰が起こしたかだけ**である。
/// この差が理由に出なければ、Daemonは「常に同じ返事をしている」ことになる（`B-35`）。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer child; run through spawn-daemon"]
fn a_child_the_daemon_did_not_spawn_is_denied_as_not_registered() {
    let (case, profile, caps) = setup("spawnd-p4");
    let daemon = case.daemon.as_ref().expect("case owns the daemon");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let spawn_cap = spawn_request_capability_sid().expect("spawn request capability");
    let payload = spawn_request_payload();

    let probe = super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();
    let mut domain_caps: Vec<PSID> = caps.iter().map(|c| c.as_psid()).collect();
    domain_caps.push(spawn_cap.as_psid());

    // **harnessが直接起こす**（Daemonを通らないのでProcess Tableに載らない）。
    let child = spawn_with_workspace(
        &probe_str,
        &[
            "--pipe-client",
            daemon.request_pipe(),
            "--pipe-payload",
            &payload,
            "--timeout-secs",
            "60",
        ],
        &workspace,
        &crate::secret_env::build_child_env(),
        false,
        profile.as_psid(),
        NetworkCapability::Deny,
        None,
        &domain_caps,
        DomainIdentity::OwnPackage,
    )
    .expect("spawn the unregistered child directly");
    let (out, err, _) = child
        .write_stdin_read_output_and_wait(None)
        .expect("read the unregistered child output");
    eprintln!("[spawnd P4] stdout={out}\nstderr={err}");

    assert_eq!(
        report_field(&out, "connected").and_then(|v| v.as_bool()),
        Some(true),
        "対照の前提が崩れている——capabilityを積んだ子は到達できるはず（P1と同じ条件）: {out}"
    );
    assert_eq!(
        deny_reason(&out).as_deref(),
        Some("not_registered"),
        "Daemonが起こしていない子が「台帳に無い」以外の理由で断られている。\
         §12の既定拒否が効いていないか、拒否理由が1つに丸まっている: {out}"
    );
    drop(case);
}

// ---------------------------------------------------------------------------
// ②が作った不変条件を、③が壊していないか
// ---------------------------------------------------------------------------

/// **P6**: Daemonが起こした子は**harnessが作った系統Job**に入っており、
/// harnessからのキャンセルで**孫まで死ぬ**。
///
/// **③で最も壊れやすいのがここである。** Daemonが系統Jobの複製を1本持つので、
/// ②より前の実装（最後の取っ手を閉じるとOSが中身を始末する形）なら、
/// キャンセルは**例外もエラーも出さずに**効かなくなっていた。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer descendant; run through spawn-daemon"]
fn cancelling_a_daemon_spawned_lineage_still_kills_the_grandchild() {
    let (case, profile, caps) = setup("spawnd-p6");
    let daemon = case.daemon.as_ref().expect("case owns the daemon");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();

    let (script, pid_file) =
        prepare_descendant(&workspace, DescendantOutput::RedirectedToFile, true);
    let shell = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string();

    let (stdout_read, stdout_write) = appcontainer_pipe(profile.as_psid()).expect("stdout pipe");
    crate::win_common::clear_inherit(stdout_read);
    let (stderr_read, stderr_write) = appcontainer_pipe(profile.as_psid()).expect("stderr pipe");
    crate::win_common::clear_inherit(stderr_read);
    let job = crate::win_common::create_job_object().expect("lineage job");

    let child = daemon
        .spawn_top_level(TopLevelSpawn {
            exe: &shell,
            args: &["-NoProfile", "-NonInteractive", "-Command", &script],
            cwd: &workspace,
            env: &crate::secret_env::build_child_env(),
            domain: domain_spec(&profile, &caps, None),
            job,
            stdout_write,
            stderr_write,
            stdin_read: None,
            redirector: None,
            console: ConsoleNeed::Required,
        })
        .expect("the daemon must spawn the shell");

    let descendant = DescendantProbe::wait_for_pid_file(&pid_file);
    // **キャンセル前に孫が確かに生きていたことを、同じテストでassertする**——
    // これが無いと「孫がそもそも起動していない」実装でも緑になる。
    descendant.assert_alive();

    let kill = crate::win_common::KillToken::duplicate(job).expect("duplicate the lineage job");
    // `HANDLE`は`Send`ではないので、専用スレッドへ渡す前に最小ラッパで包む
    // （`win_common::SendHandle`。読み手はEOFまで読むだけなのでスレッド越しでも安全）。
    let out_pipe = crate::win_common::SendHandle(stdout_read);
    let err_pipe = crate::win_common::SendHandle(stderr_read);
    assert_cancel_completes("daemon-spawned lineage cancellation", move || {
        let (out_pipe, err_pipe) = (out_pipe, err_pipe);
        kill.kill();
        let _ = crate::win_common::read_two_pipes_to_strings(out_pipe.0, err_pipe.0);
    });
    descendant.assert_exited_after_cancel();

    unsafe {
        let _ = CloseHandle(child.process);
        let _ = CloseHandle(job);
    }
    drop(case);
}

/// **P7**: 制御パイプを閉じるとDaemonが終わる（§10.1「寿命は親が保持するハンドルに紐付ける」）。
///
/// **タイマーにも完了メッセージにも依存しない**ことがこの節の決定なので、
/// `Shutdown`を送らずに落として測る。
#[test]
#[ignore = "starts a real spawn daemon; run through spawn-daemon"]
fn dropping_the_handle_ends_the_daemon() {
    let daemon = SpawnDaemonHandle::start(
        crate::tier2a::spawnd::TransitionPolicy::empty(""),
        ChildProcessPolicy::Unrestricted,
    )
        .expect("the spawn daemon must start");
    let pid = daemon.daemon_pid();
    assert!(pid != 0, "DaemonのPIDが返っていない（Readyが届いていない）");

    // **落とす前に生きていたことを、同じテストで確かめる**（`B-35`）。
    // これが無いと、Daemonが**そもそも起動していない**実装でも下のassertが通る
    // ——`wait_for_process_exit`は開けないPIDを「もう居ない」として真を返すからである。
    assert!(
        !crate::win_common::wait_for_process_exit(pid, 0),
        "ハンドルを落とす前にDaemon（pid={pid}）が既に居ない。\
         測定の前提が崩れている（下の「終わった」が何も意味しなくなる）"
    );

    drop(daemon);

    // ハンドルは既に閉じたので、PIDから開き直して終了を待つ。
    assert!(
        crate::win_common::wait_for_process_exit(pid, 10_000),
        "制御パイプを閉じてもDaemon（pid={pid}）が終わらない。\
         寿命がパイプに紐付いていない（§10.1）"
    );
}

/// **P8**: Daemonが落ちた後の生成要求は、**識別可能なエラー**になる（§10.1）。
///
/// この節は「回復手段は用意しない／失敗は識別可能なエラーにしてログへ出す」と決めている。
/// **測っているのは「無言で成功しないこと」と「返ってくること」**である——
/// ハングすれば`run_shell`はタイムアウトまで返らず、静かに成功すれば
/// 呼び出し側は起きてもいない子を待つ。
///
/// **どの段で落ちるかまでは固定しない。** Daemonのプロセスが消えた瞬間に、
/// ハンドルの複製も制御パイプの書込も等しく失敗する——どちらで落ちても
/// 「識別可能なエラーが返る」という約束は満たされる。段を固定すると、
/// 実装の内部順序を変えただけでこのテストが赤くなる。
#[test]
#[ignore = "starts a real spawn daemon; run through spawn-daemon"]
fn a_spawn_request_after_the_daemon_died_fails_loudly() {
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    let daemon = SharedSpawnDaemon::start(
        crate::tier2a::spawnd::TransitionPolicy::empty(""),
        ChildProcessPolicy::Unrestricted,
    )
        .expect("the spawn daemon must start");
    let pid = daemon.daemon_pid();

    // Daemonを外から落とす（クラッシュの模擬）。
    unsafe {
        let handle =
            OpenProcess(PROCESS_TERMINATE, false, pid).expect("open the daemon to kill it");
        let _ = TerminateProcess(handle, 1);
        let _ = CloseHandle(handle);
    }
    assert!(
        crate::win_common::wait_for_process_exit(pid, 10_000),
        "落としたはずのDaemon（pid={pid}）がまだ生きている。測定の前提が崩れている"
    );

    // AppContainerは要らない（Daemonが死んでいるので、そこまで到達しない）。
    let job = crate::win_common::create_job_object().expect("job");
    let (stdout_read, stdout_write) =
        crate::win_common::create_inheritable_pipe().expect("stdout pipe");
    let (stderr_read, stderr_write) =
        crate::win_common::create_inheritable_pipe().expect("stderr pipe");

    let result = daemon.spawn_top_level(TopLevelSpawn {
        exe: r"C:\Windows\System32\cmd.exe",
        args: &["/c", "exit", "0"],
        cwd: std::path::Path::new(r"C:\"),
        env: &[],
        domain: DomainSpec {
            name: "dead-daemon".to_string(),
            policy_domain: E2E_POLICY_DOMAIN.to_string(),
            container_sid: "S-1-15-2-1-2-3".to_string(),
            capability_sids: Vec::new(),
            identity: DomainIdentitySpec::OwnPackage,
        },
        job,
        stdout_write,
        stderr_write,
        stdin_read: None,
        redirector: None,
        console: ConsoleNeed::NotNeeded,
    });

    let message = match result {
        Ok(child) => {
            unsafe {
                let _ = CloseHandle(child.process);
            }
            panic!(
                "Daemonが死んでいるのに生成が成功したと報告された。\
                 呼び出し側は起きてもいない子を待つことになる（`B-10`）"
            );
        }
        Err(e) => e.to_string(),
    };
    eprintln!("[spawnd P8] error={message}");
    assert!(
        !message.trim().is_empty(),
        "エラーが空文字である。**理由の分からない失敗は無言失敗と同じ**（§10.1）"
    );

    unsafe {
        let _ = CloseHandle(stdout_read);
        let _ = CloseHandle(stderr_read);
        let _ = CloseHandle(job);
    }

    // 同じ共有接続で再度要求しても、新しいDaemonを起こさず直ちに拒否する。
    let second_job = crate::win_common::create_job_object().expect("second job");
    let (second_stdout_read, second_stdout_write) =
        crate::win_common::create_inheritable_pipe().expect("second stdout pipe");
    let (second_stderr_read, second_stderr_write) =
        crate::win_common::create_inheritable_pipe().expect("second stderr pipe");
    let second = daemon.spawn_top_level(TopLevelSpawn {
        exe: r"C:\Windows\System32\cmd.exe",
        args: &["/c", "exit", "0"],
        cwd: std::path::Path::new(r"C:\"),
        env: &[],
        domain: DomainSpec {
            name: "dead-daemon-second-attempt".to_string(),
            policy_domain: E2E_POLICY_DOMAIN.to_string(),
            container_sid: "S-1-15-2-1-2-3".to_string(),
            capability_sids: Vec::new(),
            identity: DomainIdentitySpec::OwnPackage,
        },
        job: second_job,
        stdout_write: second_stdout_write,
        stderr_write: second_stderr_write,
        stdin_read: None,
        redirector: None,
        console: ConsoleNeed::NotNeeded,
    });
    assert!(
        second
            .expect_err("a broken shared connection must never restart")
            .to_string()
            .contains("will not be restarted"),
        "2回目は保存済みのbroken状態から拒否しなければならない"
    );
    assert_eq!(daemon.daemon_pid(), pid, "Daemon PIDを差し替えてはならない");
    unsafe {
        let _ = CloseHandle(second_stdout_read);
        let _ = CloseHandle(second_stderr_read);
        let _ = CloseHandle(second_job);
    }
}

/// 子の終了を待ち、harness側のハンドルを閉じる。
/// **P9**: 1本の制御パイプを共有したまま、複数のスレッドが同時に生成を頼んでも
/// 要求と応答が1組ずつ噛み合う（§12「単一制御パイプの直列化」）。
///
/// **この1本が、要求受付パイプ側の混雑も同時に暴いた。** 書いた初日に3割ほど落ち、
/// 原因は制御パイプではなく**要求受付パイプ**だった——4人が同時に繋ぐと、
/// サーバが次の受付インスタンスを作る前の窓に当たった子が`ERROR_PIPE_BUSY`(231)を受け取る。
/// **プローブが再試行していなかったので、それが「到達できなかった」に化けていた**
/// （P2・P3の拒否側が別の理由で緑になり得た形。どちらも`last_error`まで見るよう直した）。
///
/// # ここが壊れると何が起きるか
///
/// 制御パイプは**要求と応答が交互に並ぶ1本のバイト列**である。排他が無いと、
/// スレッドAの要求とスレッドBの要求が混ざって書かれ、**Aの応答をBが読む**。
/// 症状は「たまに起動に失敗する」「たまに別の子のハンドルが返る」で、
/// **どちらも再現しないので原因に辿り着けない。**
///
/// 測るのは3つ: 全レーンが起動できたこと、**PIDが全部違うこと**（同じ応答を
/// 複数レーンが読んでいない）、各レーンの子がProcess Tableに載っていること
/// （`unknown_source_domain`であって`not_registered`ではない）。
///
/// **3つめが要る。** PIDが違うだけなら、登録がどれか1つだけ成功していても通る。
#[test]
#[ignore = "starts a real spawn daemon and several AppContainer children; run through spawn-daemon"]
fn concurrent_requests_share_one_control_pipe_without_interleaving() {
    let (case, profile, caps) = setup("spawnd-p8");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let spawn_cap = spawn_request_capability_sid().expect("spawn request capability");
    let spec = domain_spec(&profile, &caps, Some(&spawn_cap));
    let payload = spawn_request_payload();
    let probe = super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();

    // **製品と同じ共有接続**を使う。`setup`が持つのは素の`SpawnDaemonHandle`で、
    // 排他はそれを包む`SharedSpawnDaemon`の側にある——測りたいのはそちらである。
    let shared = SharedSpawnDaemon::start(
        crate::tier2a::spawnd::TransitionPolicy::empty(""),
        ChildProcessPolicy::Unrestricted,
    )
        .expect("a shared spawn daemon must start");
    let request_pipe = shared.request_pipe().to_string();
    eprintln!("[spawnd P9] shared daemon pid={}", shared.daemon_pid());

    const LANES: usize = 4;
    // **ハンドルはこのスレッドで全部作る**（`HANDLE`は`Send`ではないので、
    // 最小ラッパで1回だけ渡す。`server.rs`の`accept_loop`と同じ手）。
    let mut prepared = Vec::with_capacity(LANES);
    for _ in 0..LANES {
        let (stdout_read, stdout_write) =
            appcontainer_pipe(profile.as_psid()).expect("stdout pipe");
        crate::win_common::clear_inherit(stdout_read);
        let (stderr_read, stderr_write) =
            appcontainer_pipe(profile.as_psid()).expect("stderr pipe");
        crate::win_common::clear_inherit(stderr_read);
        let job = crate::win_common::create_job_object().expect("lineage job");
        prepared.push((
            SendHandle(job),
            SendHandle(stdout_write),
            SendHandle(stderr_write),
            SendHandle(stdout_read),
            SendHandle(stderr_read),
        ));
    }

    let outcomes: Vec<(u32, String)> = std::thread::scope(|scope| {
        let lanes: Vec<_> = prepared
            .into_iter()
            .map(|lane| {
                let shared = shared.clone();
                let spec = spec.clone();
                let workspace = workspace.clone();
                let probe_str = probe_str.clone();
                let payload = payload.clone();
                let request_pipe = request_pipe.clone();
                scope.spawn(move || {
                    // まるごと束縛し直す（Rust 2021の部分捕捉で`SendHandle`の意味が消えないように）。
                    let (job, out_w, err_w, out_r, err_r) = lane;
                    let env = crate::secret_env::build_child_env();
                    let child = shared
                        .spawn_top_level(TopLevelSpawn {
                            exe: &probe_str,
                            args: &[
                                "--pipe-client",
                                &request_pipe,
                                "--pipe-payload",
                                &payload,
                                "--timeout-secs",
                                "60",
                            ],
                            cwd: &workspace,
                            env: &env,
                            domain: spec,
                            job: job.0,
                            stdout_write: out_w.0,
                            stderr_write: err_w.0,
                            stdin_read: None,
                            redirector: None,
                            console: ConsoleNeed::NotNeeded,
                        })
                        .expect("every lane must spawn through the shared control pipe");
                    let (out, _err) =
                        crate::win_common::read_two_pipes_to_strings(out_r.0, err_r.0);
                    let pid = child.pid;
                    wait_and_close(&child, job.0);
                    (pid, out)
                })
            })
            .collect();
        lanes
            .into_iter()
            .map(|lane| lane.join().expect("lane thread must not panic"))
            .collect()
    });

    let pids: std::collections::BTreeSet<u32> = outcomes.iter().map(|(pid, _)| *pid).collect();
    assert_eq!(
        pids.len(),
        LANES,
        "同時に頼んだ{LANES}件のうちPIDが重複した。制御パイプ上で応答が入れ替わっている\
         （別レーンの応答を読んでいる）: {pids:?}"
    );
    for (pid, out) in &outcomes {
        assert_eq!(
            deny_reason(out).as_deref(),
            Some("unknown_source_domain"),
            "pid={pid}の子が「台帳に無い」で断られている。同時要求のどれかが\
             Process Tableへ登録されないまま起きている（§12・BUG-116）: {out}"
        );
    }
    drop(case);
}

/// **観測**: 直接生成とDaemon経由で、トップレベルを起こすのに掛かる時間を同条件で比べる。
///
/// # これは合否の判定ではない
///
/// **性能の閾値は決めていない**ので、赤くなる条件を持たない。ここが返すのは
/// 「④の配線で1回の起動がどれだけ延びたか」という**後続の判断のための観測値**である。
///
/// # 何を揃えてあるか（揃っていないものは下に書く）
///
/// - **同じ実行ファイル・同じ引数・同じworkspace・同じプロファイル**で撃つ
/// - **交互に撃つ**（直接→Daemon→直接→…）。片方を先にまとめて撃つと、ACLキャッシュや
///   ディスクの暖まりが片方だけに乗る
/// - **Daemonは暖めてから測る**（起動とハンドシェイクは測定の外。1回捨て撃ちする）
///
/// **揃っていないもの＝この数字が答えないこと。**
///
/// - **debugビルドである。** releaseの絶対値は別物になる。**比較できるのは2本の差だけ**である
/// - **昇格して走っている**（`preflight`が実ACLを触るため）。本番のDaemonは非昇格である
/// - **1並列でしか撃っていない。** 同時に何本も頼んだときの待ち時間は測っていない（残課題#43）
/// - **注入を伴う構成（CoW・lazy）は撃っていない。** あちらはsuspended窓での注入と
///   初期化待ちが載るので、支配的な項が違う
#[test]
#[ignore = "measurement only (no pass/fail); run through spawn-daemon-latency"]
fn top_level_spawn_latency_direct_versus_daemon() {
    const TRIALS: usize = 12;
    const EXE: &str = r"C:\Windows\System32\cmd.exe";
    let args = ["/c", "exit", "0"];

    let (case, profile, caps) = setup("spawnd-latency");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let spawn_cap = spawn_request_capability_sid().expect("spawn request capability");
    let domain_caps: Vec<PSID> = caps.iter().map(|c| c.as_psid()).collect();
    let env = crate::secret_env::build_child_env();
    let shared = SharedSpawnDaemon::start(
        crate::tier2a::spawnd::TransitionPolicy::empty(""),
        ChildProcessPolicy::Unrestricted,
    )
        .expect("a shared spawn daemon must start");
    let _ = &spawn_cap;

    let direct = |workspace: &std::path::Path| {
        spawn_with_workspace(
            EXE,
            &args,
            workspace,
            &env,
            false,
            profile.as_psid(),
            NetworkCapability::Deny,
            None,
            &domain_caps,
            DomainIdentity::OwnPackage,
        )
    };
    let via_daemon = |workspace: &std::path::Path| {
        spawn_with_workspace_via_daemon(
            &shared,
            "spawnd-latency",
            E2E_POLICY_DOMAIN,
            EXE,
            &args,
            workspace,
            &env,
            false,
            profile.as_psid(),
            NetworkCapability::Deny,
            None,
            &domain_caps,
            DomainIdentity::OwnPackage,
            SpawnRequestAccess::Grant,
            ConsoleNeed::NotNeeded,
        )
    };

    // 暖機（測定に含めない）。Daemonの起動・ハンドシェイク・初回のACL照会をここで済ませる。
    for _ in 0..2 {
        drop(direct(&workspace).expect("warm-up direct spawn"));
        drop(via_daemon(&workspace).expect("warm-up daemon spawn"));
    }

    let mut direct_us: Vec<u128> = Vec::with_capacity(TRIALS);
    let mut daemon_us: Vec<u128> = Vec::with_capacity(TRIALS);
    for _ in 0..TRIALS {
        let t = std::time::Instant::now();
        let child = direct(&workspace).expect("direct spawn");
        direct_us.push(t.elapsed().as_micros());
        drop(child);

        let t = std::time::Instant::now();
        let child = via_daemon(&workspace).expect("daemon spawn");
        daemon_us.push(t.elapsed().as_micros());
        drop(child);
    }

    let summarize = |label: &str, mut v: Vec<u128>| {
        v.sort_unstable();
        let median = v[v.len() / 2];
        let p90 = v[(v.len() * 9) / 10];
        eprintln!(
            "[latency] {label}: n={} median={median}us p90={p90}us min={}us max={}us",
            v.len(),
            v[0],
            v[v.len() - 1]
        );
        median
    };
    let d = summarize("direct  ", direct_us);
    let s = summarize("daemon  ", daemon_us);
    eprintln!(
        "[latency] median delta = {}us (daemon - direct); build=debug, elevated, 1 at a time",
        s as i128 - d as i128
    );
    drop(case);
}

/// **観測**: Redirector DLLの注入が、トップレベル1回の起動へ上乗せする時間
/// （[`DESIGN-MAC-POC.md`](../../../../plans/DESIGN-MAC-POC.md) §20項目13）。
///
/// # これは合否の判定ではない
///
/// **閾値を決めていない**ので赤くなる条件を持たない。赤くなるのは
/// **測定が成立していないとき**だけである（下記「計器を先に疑う」）。
///
/// # 何の費用か——ファイルフックの費用**ではない**
///
/// 段階5bで常時注入へ変えたが、CoWの誘導もfault受付も無い構成では
/// **ファイル系7フックを1本も置かない**（`harness-redirector`の`init`）。したがってここで
/// 測るのは`NtCreateFile`等1回あたりの上乗せではなく、**1回の起動に載る一時費用**である
/// ——`LoadLibraryW`のリモートスレッド・プロセス生成フック4本の設置・準備完了の往復。
///
/// **1オープンあたりの上乗せは`lazy_hook_overhead_tests`が別に測っている。**
/// あちらの数字をこちらへ持ってこないこと（載っているフックの本数が違う）。
///
/// # 計器を先に疑う（数字を読む前に落ちる検算）
///
/// 「注入したつもりで注入していなかった」回の差はほぼ0になり、**注入は無料だ**という
/// 誤った結論になる。だから時間を測る前に、**各腕の子が自分のenvを印字して**
/// 注入の指示が届いたかどうかを見る。腕と印字が食い違ったらそこで落とす。
///
/// # 揃えてあるもの／揃っていないもの
///
/// - **同じ実行ファイル・同じ引数・同じworkspace・同じプロファイル・同じDaemon**
/// - **腕を交互に撃つ**（片方を先にまとめて撃つとキャッシュの暖まりが片方に乗る）
/// - **暖機を測定の外に置く**（Daemonの起動とハンドシェイク、DLLの初回ロード）
///
/// 揃っていないもの＝**この数字が答えないこと**:
///
/// - **debugビルドである。** 読めるのは腕どうしの差だけで、絶対値は別物になる
/// - **昇格して走っている**（`preflight`が実ACLを触るため）。本番のDaemonは非昇格である
/// - **1並列でしか撃っていない。** 同時に何本も頼んだときは測っていない（残課題#43）
/// - **CoW・lazyの構成は撃っていない。** あちらはファイルフック7本の設置が別に載る
/// - **x86の子は撃っていない。** WOW64の孫への再注入は別の費用である
#[test]
#[ignore = "measurement only (no pass/fail); run through spawn-daemon-latency"]
fn top_level_spawn_latency_injection_cost() {
    const TRIALS: usize = 12;
    const EXE: &str = r"C:\Windows\System32\cmd.exe";
    /// 注入の指示が子へ届いたことを、子の環境変数として見る印（計器の検算用）。
    const ENV_MARK: &str = "HARNESS_REDIRECTOR_PROCESS_HOOKS";

    let (case, profile, caps) = setup("spawnd-inject-cost");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let canonical = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.clone());
    let domain_caps: Vec<PSID> = caps.iter().map(|c| c.as_psid()).collect();
    let env = crate::secret_env::build_child_env();
    let shared = SharedSpawnDaemon::start(
        crate::tier2a::spawnd::TransitionPolicy::empty(""),
        ChildProcessPolicy::Unrestricted,
    )
        .expect("a shared spawn daemon must start");

    let spawn = |exe: &str, inject: super::RedirectorInject<'_>, args: &[&str]| {
        spawn_with_workspace_via_daemon(
            &shared,
            "spawnd-inject-cost",
            E2E_POLICY_DOMAIN,
            exe,
            args,
            &workspace,
            &env,
            false,
            profile.as_psid(),
            NetworkCapability::Deny,
            inject,
            &domain_caps,
            DomainIdentity::OwnPackage,
            SpawnRequestAccess::Grant,
            ConsoleNeed::NotNeeded,
        )
    };

    /// 1腕の作り方。ワークスペースのパスを受け取って注入の指定を返す。
    type MakeInject = fn(&std::path::Path) -> super::RedirectorInject<'_>;

    // **腕は3本。** 2本目と3本目は「同じ費用のはず」なので、揃わなければ
    // どちらかの理解が間違っている（別の計器で同じ量を出す＝突き合わせ）。
    let arms: [(&str, MakeInject); 3] = [
        ("no-inject     ", |_| super::RedirectorInject::default()),
        ("hooks-only    ", |_| {
            super::RedirectorInject::for_tier2a(None, None, None)
        }),
        ("hooks+workspace", |ws| {
            super::RedirectorInject::for_tier2a(Some(ws), None, None)
        }),
    ];

    // ---- 数字より前の検算: 注入の指示が実際に届いたか ----
    //
    // **`cmd`の組み込みコマンドは使えない。** 生成側は**全ての引数を無条件で引用する**ので
    // （`spawn.rs`のコマンドライン組み立て）、`cmd /c "set" ...`の`"set"`を`cmd`が
    // 実行ファイル名として解決しようとして落ちる。**この形で2回落ちた**——落ちたのが
    // 計器の側だと分かるのは、対象を測る前にここを通しているからである。
    // PowerShellは`-Command`に引用された1つの文字列を受け取る形なので、この罠に掛からない。
    //
    // 見るのは標準出力ではなく**終了コード**である。出力を見る形にすると、
    // 変数名そのものが出力に混ざる経路（エラー文言など）と区別が付かない。
    let (shell, _shell_label) = super::resolve_shell();
    for (label, make) in &arms {
        let child = spawn(
            &shell,
            make(&canonical),
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!("if (Test-Path env:{ENV_MARK}) {{ exit 0 }} else {{ exit 1 }}"),
            ],
        )
        .unwrap_or_else(|e| panic!("[{label}] instrument spawn failed: {e:?}"));
        let (stdout, stderr, code) = child
            .write_stdin_read_output_and_wait(None)
            .unwrap_or_else(|e| panic!("[{label}] could not run the instrument child: {e:?}"));
        assert!(
            code == 0 || code == 1,
            "[{label}] the instrument child did not reach the exit statement (exit={code}). \
             Nothing was measured. stdout={stdout:?} stderr={stderr:?}"
        );
        let injected = code == 0;
        eprintln!("[inject-cost] {label}: {ENV_MARK} present in child env = {injected}");
        let expected = *label != "no-inject     ";
        assert_eq!(
            injected, expected,
            "[{label}] the arm did not do what its name says. Timing it would compare two \
             identical worlds and report that injection is free. stdout={stdout:?} \
             stderr={stderr:?}"
        );
    }

    // ---- 暖機（測定に含めない）----
    for _ in 0..2 {
        for (label, make) in &arms {
            drop(
                spawn(EXE, make(&canonical), &["/c", "exit", "0"])
                    .unwrap_or_else(|e| panic!("[{label}] warm-up spawn failed: {e:?}")),
            );
        }
    }

    // ---- 本測定（腕を交互に撃つ）----
    let mut samples: Vec<Vec<u128>> = vec![Vec::with_capacity(TRIALS); arms.len()];
    for _ in 0..TRIALS {
        for (index, (label, make)) in arms.iter().enumerate() {
            let t = std::time::Instant::now();
            let child = spawn(EXE, make(&canonical), &["/c", "exit", "0"])
                .unwrap_or_else(|e| panic!("[{label}] spawn failed: {e:?}"));
            samples[index].push(t.elapsed().as_micros());
            drop(child);
        }
    }

    let mut medians: Vec<u128> = Vec::with_capacity(arms.len());
    for (index, (label, _)) in arms.iter().enumerate() {
        let mut v = std::mem::take(&mut samples[index]);
        v.sort_unstable();
        let median = v[v.len() / 2];
        eprintln!(
            "[inject-cost] {label}: n={} median={median}us p90={}us min={}us max={}us",
            v.len(),
            v[(v.len() * 9) / 10],
            v[0],
            v[v.len() - 1]
        );
        medians.push(median);
    }
    eprintln!(
        "[inject-cost] median delta (hooks-only - no-inject) = {}us",
        medians[1] as i128 - medians[0] as i128
    );
    eprintln!(
        "[inject-cost] median delta (hooks+workspace - no-inject) = {}us",
        medians[2] as i128 - medians[0] as i128
    );
    eprintln!(
        "[inject-cost] config: build=debug, elevated, 1 at a time, trials={TRIALS}, exe={EXE}, \
         no CoW diff layer, no fault broker (so no file hooks are installed)"
    );
    drop(case);
}

pub(super) fn wait_and_close(child: &SpawnedChild, job: HANDLE) {
    unsafe {
        let _ = WaitForSingleObject(child.process, 60_000);
        let mut code = 0u32;
        let _ = GetExitCodeProcess(child.process, &mut code);
        eprintln!("[spawnd] child pid={} exit={code}", child.pid);
        let _ = CloseHandle(child.process);
        let _ = CloseHandle(job);
    }
    // 実マシンの後始末に少しだけ猶予を与える（Jobのkill-on-closeが走る）。
    std::thread::sleep(Duration::from_millis(200));
}
