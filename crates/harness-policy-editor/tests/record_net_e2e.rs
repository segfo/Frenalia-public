//! パス2（Tier2aでのドメイン記録）の実機E2E。**管理者権限が要る**
//! （WFPの出口強制daemonと、fs-allowのACE付与のため）。
//!
//! 実行: `dev-elevated-run.exe e2e-policy-editor-pass2`
//! （`crates/dev-elevated-runner/src/lib.rs`の`KNOWN_TARGETS`にキーを登録済み）。
//!
//! # 何を確かめるか（B-27: 歯のあるテストにする）
//!
//! 1. **Tier2aへ着地した**こと（降格していたら記録の意味が無いので失敗にする）
//! 2. `record_all`が効いて、**許可ドメインを1つも宣言していないのに**外部ドメインへ到達できた
//! 3. そのドメインが`net-audit.jsonl`に載り、候補として出てくる
//! 4. **対のテスト**: 環境変数を読まない生ソケットは**WFPに落とされる**
//!    ——2番が「単に何も強制していない」から通ったのではないことを示す（B-35）
//! 5. マニフェストが`pass=2`・`finished`で閉じ、撤収まで通っている
//! 6. **1プロセスで2回走らせると、2回目はdaemonを再利用する**（D-56）——かつ
//!    **再利用したdaemonでも強制は本物のまま**（生ソケットは落ちる）。
//!    「2回目が速かったのは強制が消えたからではない」ことを区別する対（B-35）
//! 7. **承認したFS宣言が実DACLへ届き、その宛先SIDがcapability SIDである**（残課題#20の
//!    移行の不変条件＝package SID宛が0本）。**取り消したあとに何が残るか**も同じ実行で測る
//!    ——[`an_executable_that_cannot_be_started_becomes_a_read_exec_candidate_and_then_runs`]
//!
//! # このテストが触らないもの（正直に書く）
//!
//! ネットワーク側の3本は`policy.json`の`fs`を**空**にしてある。workspace外のFSルールを
//! 入れるとこのマシンの実ACLと`fs-passthrough-ledger.json`を書き換えることになり、
//! ネットワークを測るテストの副作用としては重すぎる。**FS側を測るのは7番の1本だけ**で、
//! そちらは`%TEMP%`配下の一時ディレクトリに閉じている（`--fs-allow`経由の同じ機構は
//! CLI側の既存E2Eが別に通している）。

#![cfg(windows)]

use std::path::Path;
use std::process::Command;

fn editor_exe() -> &'static str {
    env!("CARGO_BIN_EXE_harness-policy-editor")
}

/// 記録対象にするドメイン。外部への到達性が要るので、安定していて用途上問題の無いものを使う。
const TARGET_DOMAIN: &str = "example.com";

fn write_policy(workspace_root: &Path, domain: &str, command: &str) {
    let policy = serde_json::json!({
        "schema_version": 1,
        "domains": [{
            "name": domain,
            "commands": [command],
            "cwd": workspace_root,
            // 意図的に空（モジュールdocの「触らないもの」参照）。
            "fs": { "read": [], "read_write": [], "read_exec": [] },
            // **1つも宣言しない。** それでも到達できることがrecord_allの効き目の証明になる。
            "net": { "allow_domains": [] },
            "provenance": { "record_sessions": [], "updated_unix_ms": 0 }
        }]
    });
    let dir = workspace_root.join(".harness");
    std::fs::create_dir_all(dir.join("sandbox")).unwrap();
    std::fs::write(
        dir.join("policy.json"),
        serde_json::to_string_pretty(&policy).unwrap(),
    )
    .unwrap();
}

fn run_record_net(workspace_root: &Path, domain: &str, command: &str) -> std::process::Output {
    Command::new(editor_exe())
        .args([
            "record-net",
            "--domain",
            domain,
            "--workspace",
            &workspace_root.to_string_lossy(),
            "--cwd",
            &workspace_root.to_string_lossy(),
            "--limit",
            "0",
            "--timeout",
            "120",
            "--",
            command,
        ])
        // 開発ビルド（`target/debug`）は必ずユーザー書込可なので、D-44の逃がし弁が要る。
        .env("HARNESS_ALLOW_USER_WRITABLE_ELEVATED_HELPERS", "1")
        .output()
        .expect("the policy editor binary should run")
}

fn manifest_of_latest_session(workspace_root: &Path) -> serde_json::Value {
    let sandbox = workspace_root.join(".harness").join("sandbox");
    let mut manifests: Vec<serde_json::Value> = std::fs::read_dir(&sandbox)
        .expect("sandbox dir")
        .flatten()
        .filter_map(|entry| {
            let text = std::fs::read_to_string(entry.path().join("record-session.json")).ok()?;
            serde_json::from_str(&text).ok()
        })
        .collect();
    assert_eq!(
        manifests.len(),
        1,
        "expected exactly one recording session under {}",
        sandbox.display()
    );
    manifests.remove(0)
}

/// いちばん新しい記録のマニフェスト（[`manifest_of_latest_session`]と違い**複数あってよい**）。
///
/// 承認をはさんで2回記録するテストのために分けてある——「ちょうど1件」を主張する側は、
/// 記録が1回で終わることそのものを固定しているので緩めない。
fn latest_manifest(workspace_root: &Path) -> serde_json::Value {
    let sandbox = workspace_root.join(".harness").join("sandbox");
    let mut manifests: Vec<serde_json::Value> = std::fs::read_dir(&sandbox)
        .expect("sandbox dir")
        .flatten()
        .filter_map(|entry| {
            let text = std::fs::read_to_string(entry.path().join("record-session.json")).ok()?;
            serde_json::from_str(&text).ok()
        })
        .collect();
    manifests.sort_by_key(|m| m["started_unix_ms"].as_u64().unwrap_or(0));
    manifests
        .pop()
        .unwrap_or_else(|| panic!("no recording session under {}", sandbox.display()))
}

/// `show`（既定＝最新のセッション）の標準出力。提案idはここからしか取れない
/// ——`approve`が受け取るidは`show`が振ったものと同じでなければならない。
fn run_show(workspace_root: &Path) -> String {
    let output = Command::new(editor_exe())
        .args([
            "show",
            "--workspace",
            &workspace_root.to_string_lossy(),
            "--limit",
            "0",
        ])
        .output()
        .expect("show should run");
    assert!(
        output.status.success(),
        "show failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// 対象パスのDACLをSDDL（セキュリティ記述子の文字列表現）で読む。
///
/// # なぜharnessの関数で数えないのか
///
/// ACEを**付ける**のも**数える**のも同じ関数だと、その関数が同じ向きに間違えていても
/// 緑になる。ここは「実マシンに何が残ったか」を測るところなので、**別の道具**（`Get-Acl`）で
/// 読み直す。同じ形の裏取りをD-84の実装でも行っている。
///
/// **限界**: SDDLは継承ACEと明示ACEを1つの文字列に並べる。ここで測る対象は
/// **新しく作った一時ディレクトリの中のファイル**で、capability SID（`S-1-15-3-`）や
/// AppContainerのpackage SID（`S-1-15-2-`）が最初から載っていることは無いため、
/// **測定前後の差**を見れば継承分と混ざらない。だから基準線を必ず先に取る。
fn acl_sddl(path: &Path) -> String {
    let script = format!(
        "(Get-Acl -LiteralPath '{}').Sddl",
        path.display().to_string().replace('\'', "''")
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .expect("powershell.exe should run");
    assert!(
        output.status.success(),
        "Get-Acl failed for {}: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// SDDLの中に現れる、指定した接頭辞を持つSIDの件数。
///
/// `S-1-15-3-`＝capability SID（宣言ごとの宛先SID、残課題#20の移行先）、
/// `S-1-15-2-`＝AppContainerのpackage SID（移行元。**移行後は0本でなければならない**）。
fn count_sid_prefix(sddl: &str, prefix: &str) -> usize {
    sddl.match_indices(prefix).count()
}

/// 実行像の診断に使うexeの置き場（**`%TEMP%`の外**）。
///
/// # なぜ`tempfile::tempdir()`を使えないのか（**これで1本壊れていた**）
///
/// 候補除外の規則（[BUG-103](../../../docs/bugs/BUG-103.md)）は**`%TEMP%`配下を候補にしない**
/// ——刹那的なパスの巣であり、一時ディレクトリ全体への継承つきRWDはP-01違反だからである。
/// `tempfile::tempdir()`はその`%TEMP%`の下に作る。したがって、そこへ置いたexeは
/// **診断では名指しされるのに候補一覧には出てこない**。
///
/// この食い違いのせいで、下のテストは2026-08-11に除外規則が入った時点から
/// 「候補が見つからない」で落ちるようになっていた。**`#[ignore]`が付いているため
/// `cargo test --workspace`では一度も現れず、昇格して撃つまで分からなかった。**
///
/// 置き場は他のE2Eと同じ`C:\harness-e2e\`配下にする（workspaceの外・`%TEMP%`の外・
/// `C:/Windows`と`C:/Program Files`の外、という3条件を全部満たす）。
struct ProbeDir(std::path::PathBuf);

impl ProbeDir {
    fn new() -> Self {
        let dir = std::path::PathBuf::from(r"C:\harness-e2e")
            .join(format!("exec-ace-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| {
            panic!(
                "could not create the probe directory {} ({e}). This test needs a place \
                    outside %TEMP% because %TEMP% is excluded from candidates.",
                dir.display()
            )
        });
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ProbeDir {
    /// **後片付けはここが持つ。** `tempfile`と違って自動では消えないので、
    /// パニックで抜けても消えるように`Drop`へ置く（測定は`Drop`より前に済んでいる）。
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.0) {
            eprintln!(
                "warning: could not remove the probe directory {} ({e}); remove it by hand",
                self.0.display()
            );
        }
    }
}

fn net_audit_of_latest_session(workspace_root: &Path) -> String {
    let sandbox = workspace_root.join(".harness").join("sandbox");
    std::fs::read_dir(&sandbox)
        .expect("sandbox dir")
        .flatten()
        .find_map(|entry| std::fs::read_to_string(entry.path().join("net-audit.jsonl")).ok())
        .unwrap_or_default()
}

/// 1・2・3・5番: 許可ドメインを1つも宣言していないのに到達でき、そのドメインが記録される。
#[test]
#[ignore = "requires administrator rights (WFP netfilterd) and outbound network access"]
fn pass2_records_the_domain_a_command_reached_without_declaring_any_allowlist() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let workspace_root = workspace.path();
    // Windows標準の`curl.exe`はプロキシ環境変数を読む（AppContainerからも起動できる）。
    let command = format!("curl.exe -sS -o NUL -w '%{{http_code}}' https://{TARGET_DOMAIN}/");
    write_policy(workspace_root, "e2e", &command);

    let output = run_record_net(workspace_root, "e2e", &command);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}");

    assert!(
        output.status.success(),
        "record-net should succeed: {stdout}\n{stderr}"
    );

    // 1. Tier2aへ着地している（降格していたらそもそもここへ来ない——`record_net`が
    //    `NotTier2a`で失敗するため——が、表示でも確かめる）。
    assert!(
        stderr.contains("Tier2aへ着地しました"),
        "the recording must land on Tier2a: {stderr}"
    );
    assert!(
        stderr.contains("WFPのdefault-denyを張りました"),
        "WFP egress enforcement must be up before the command runs: {stderr}"
    );

    // 2/3. record_allが効いて、宣言ゼロのまま到達したドメインが記録されている。
    let audit = net_audit_of_latest_session(workspace_root);
    assert!(
        audit.contains(TARGET_DOMAIN),
        "the domain the command reached must appear in net-audit.jsonl: {audit}"
    );
    assert!(
        audit.contains("record_all"),
        "the allow decision must be recorded as record_all (not an allowlist hit): {audit}"
    );
    assert!(
        stdout.contains(TARGET_DOMAIN),
        "the domain must appear among the candidates: {stdout}"
    );

    // 5. マニフェストがパス2として閉じている。
    let manifest = manifest_of_latest_session(workspace_root);
    assert_eq!(manifest["pass"], 2, "manifest: {manifest}");
    assert_eq!(manifest["status"], "finished", "manifest: {manifest}");
    assert_eq!(manifest["domain"], "e2e", "manifest: {manifest}");
    assert_eq!(
        manifest["exit_code"], 0,
        "the command must have succeeded (a non-zero exit means the recording is incomplete): {manifest}"
    );

    // 撤収まで通っている（ここが抜けるとプロファイルとACEがマシンに残る）。
    assert!(
        stderr.contains("撤収: AppContainerプロファイルとACE"),
        "the session profile teardown must run: {stderr}"
    );
}

/// 4番（対のテスト、B-35）: **プロキシを経由しない生ソケットはWFPに落とされる。**
///
/// 上のテストが通るのは「何も強制していないから素通しできた」のではなく、
/// **Proxy経由の通信だけが通っている**ことを示す。これが成り立たないなら、パス2の記録は
/// 「観測できたドメインの一覧」でしかなく、「このドメインだけ使う」とは読めない。
#[test]
#[ignore = "requires administrator rights (WFP netfilterd) and outbound network access"]
fn a_raw_socket_that_bypasses_the_proxy_is_dropped_by_wfp() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let workspace_root = workspace.path();
    // 環境変数を一切読まない生のTCP接続。WFPが立っていれば失敗する。
    // 失敗を**明示的な終了コード**にして、「たまたま何か別の理由で落ちた」と区別する。
    let command = "try { $c = New-Object System.Net.Sockets.TcpClient; \
                   $c.Connect('93.184.215.14', 443); \
                   Write-Output 'RAW-SOCKET-CONNECTED'; exit 9 } \
                   catch { Write-Output 'RAW-SOCKET-BLOCKED'; exit 0 }";
    write_policy(workspace_root, "e2e-raw", command);

    let output = run_record_net(workspace_root, "e2e-raw", command);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}");

    assert!(
        stderr.contains("WFPのdefault-denyを張りました"),
        "this test is meaningless unless WFP actually came up: {stderr}"
    );
    assert!(
        stdout.contains("RAW-SOCKET-BLOCKED"),
        "a raw socket must not reach the internet while WFP default-deny is up \
         (if this says CONNECTED, the enforcement is not working and pass 2's records \
         cannot be read as 'only these domains'): {stdout}"
    );
    let manifest = manifest_of_latest_session(workspace_root);
    assert_eq!(
        manifest["exit_code"], 0,
        "the guard command reports blocked with exit 0: {manifest}"
    );
}

/// 6番（D-56）: **1プロセスで`record_net`を2回呼び、2回目がdaemonを再利用すること**と、
/// **再利用したdaemンでも強制が本物のままであること**を同時に固定する。
///
/// # なぜ上の2本と違って`record_net`を直接呼ぶのか
///
/// 再利用は「同じプロセスで2回走らせる」ときにしか起きない。CLIの`record-net`は1回の起動で
/// 1回しか記録しないので、サブプロセスを2回起こす形（上の2本）では**測れるものが何も無い**。
/// 繰り返しが起きるのはTUIだが、TUIを自動で叩くのは経路が長すぎるため、その中身である
/// ライブラリ関数を同じ持ち方（`SharedNetfilter`をプロセス寿命で持つ）で2回呼ぶ。
///
/// # 「2回目にUACが出ない」をどう測るか
///
/// 出ないことは目視でしか確かめられない——ように見えるが、`ShellExecuteExW(runas)`を通るのは
/// `NetfilterHandle::start`だけであり、そこを通ったかどうかは`Applied { reused }`が答える。
/// したがって **`reused == true` は「UACが出ていない」と同値**である。同じ置き換えを
/// `tier2a_chain_launch_*`（`docs/STATUS.md`の未検証項目a）が既に採っている。
///
/// # 対（B-35）
///
/// 2回目は**生ソケットのガードコマンド**を走らせる。再利用したdaemonの下でも生ソケットが
/// 落ちることを見ないと、「2回目はUACが出ずに速かった」は「2回目は何も強制されていない」と
/// 区別できない。deny側だけのテストは機構が死んでいるときも通るので、1回目で
/// 「プロキシ経由なら到達できる」ことも併せて確かめる。
#[test]
#[ignore = "requires administrator rights (WFP netfilterd) and outbound network access"]
fn a_second_pass2_in_the_same_process_reuses_the_daemon_and_still_enforces() {
    use harness_policy_editor::record_net::{
        record_net, NetRecordEvent, RecordNetRequest, SessionGrants, SharedNetfilter,
    };

    place_netfilterd_next_to_the_test_binary();
    // 開発ビルド（`target/debug`）は必ずユーザー書込可なので、D-44の逃がし弁が要る。
    // 上の2本はサブプロセスの`.env()`で渡しているが、ここは同一プロセスなので自分で立てる。
    std::env::set_var("HARNESS_ALLOW_USER_WRITABLE_ELEVATED_HELPERS", "1");

    let workspace = tempfile::tempdir().expect("tempdir");
    let workspace_root = workspace.path();
    let reach = format!("curl.exe -sS -o NUL -w '%{{http_code}}' https://{TARGET_DOMAIN}/");
    let guard = "try { $c = New-Object System.Net.Sockets.TcpClient; \
                 $c.Connect('93.184.215.14', 443); \
                 Write-Output 'RAW-SOCKET-CONNECTED'; exit 9 } \
                 catch { Write-Output 'RAW-SOCKET-BLOCKED'; exit 0 }";
    write_policy(workspace_root, "e2e-reuse", &reach);

    // **宣言順が撤収順を決める**（D-56）。`SessionGrants`より後に`SharedNetfilter`を作ることで、
    // netfilterdの`Teardown`がAppContainerプロファイルの削除より先に走る。
    let _grants = SessionGrants::hold();
    let wfp = SharedNetfilter::hold();
    // 収集器も同じ順序で持つ（D-56 段階2）。このE2Eが測るのはWFPの再利用だが、
    // 収集器を渡さないと**そもそもパス2が組み立てられない**ので、製品と同じ形で持つ。
    let collector = harness_policy_editor::record::SharedCollector::hold();
    let spawn_daemon = harness_policy_editor::record_net::SharedSpawnDaemon::hold();

    let policy =
        harness_policy_editor::policy_file::load(workspace_root).expect("load policy.json");
    let domain = policy
        .domain("e2e-reuse")
        .expect("domain e2e-reuse")
        .clone();
    let never_cancel = || false;

    // 1回の実行を回して「WFPが立ったか・再利用だったか」と標準出力を集める小さなヘルパー。
    let run = |command: &str| -> (Option<bool>, String) {
        let request = RecordNetRequest {
            domain: &domain,
            command,
            cwd: workspace_root,
            workspace_root,
            timeout: Some(std::time::Duration::from_secs(120)),
            cancel: &never_cancel,
            wfp: &wfp,
            collector: &collector,
            spawn_daemon: &spawn_daemon,
        };
        let mut reused: Option<bool> = None;
        let mut stdout = String::new();
        let mut on_event = |event: NetRecordEvent| match event {
            NetRecordEvent::WfpEnforced { reused: r } => reused = Some(r),
            NetRecordEvent::Stdout(line) => stdout.push_str(&line),
            NetRecordEvent::Warning(message) => eprintln!("[warn] {message}"),
            _ => {}
        };
        let outcome = record_net(&request, &mut on_event).expect("record_net should succeed");
        eprintln!(
            "[e2e] exit={:?} reused={reused:?} stdout={stdout:?}",
            outcome.exit_code
        );
        (reused, stdout)
    };

    // 1回目: daemonを起こす（UACが1回出る）。プロキシ経由なら外部へ到達できる。
    let (reused_first, stdout_first) = run(&reach);
    assert_eq!(
        reused_first,
        Some(false),
        "the first run has to start the daemon (if this says true, some earlier run leaked a \
         daemon into this process and the second-run assertion below proves nothing)"
    );
    assert!(
        stdout_first.contains("200"),
        "the first run must actually reach {TARGET_DOMAIN} through the proxy; otherwise the \
         'still enforcing' assertion below cannot be told apart from 'nothing works at all': \
         {stdout_first:?}"
    );

    // 2回目: **daemonを再利用する＝UACが出ない**。しかも強制は本物のまま。
    let (reused_second, stdout_second) = run(guard);
    assert_eq!(
        reused_second,
        Some(true),
        "the second run must reuse the running daemon -- this is the same statement as \
         'no UAC prompt appeared on the second recording'"
    );
    assert!(
        stdout_second.contains("RAW-SOCKET-BLOCKED"),
        "a raw socket must still be dropped by the reused daemon's filters. If this says \
         CONNECTED, the reuse silently dropped the enforcement and pass 2's records can no \
         longer be read as 'only these domains': {stdout_second:?}"
    );
}

/// 7番: **起動できなかった実行ファイルが候補になり、承認すると本当に走る**（D-57の追記）。
///
/// # なぜこれを実機で見るのか
///
/// 純粋関数のテストは「診断が名指しした値が候補になる」までしか固定できない。実際に必要なのは
/// その先——**承認した`fs.read_exec`でACEが付き、AppContainerからそのexeを起動できる**こと。
/// ここが繋がっていなければ、画面の指示どおりに操作しても`Access is denied`のままである
/// （これはE2Eでしか測れない。`plans/PLAN-POLICY-EDITOR-EXEC-DENIAL.md`が段階4の
/// 未確認事項として残していたもの）。
///
/// # 判定に終了コードを使わない
///
/// [BUG-095](../../docs/bugs/BUG-095.md): **起動に失敗したコマンドが`exit 0`で返る**。
/// したがって「走ったこと」は標準出力の中身（`MARKER`）で見る。1回目に`MARKER`が出ないこと・
/// 2回目に出ることの**両方**を固定する（B-35: 片方だけだと、機構が死んでいても通る）。
///
/// # 置き場
///
/// workspace外・かつ`C:/Windows`と`C:/Program Files`の外（＝AppContainerに既定の実行権が
/// 無い場所、D-58）でなければ、そもそも診断が「起動できない」と言わない。**さらに`%TEMP%`の
/// 外**である必要がある（あそこは候補除外の対象。[`ProbeDir`]のdoc）。
/// **このテストが実マシンへ残す変更はここへのACE1件**で、`ProbeDir`のDropごと消える。
///
/// # 後半で測るもの（残課題#20の受け入れ条件と、エディタの後片付け）
///
/// 承認して起動できるようになった時点で、**実マシンのDACLを別の道具で読み返す**。
/// 見るのは3つで、どれも「付与後 → 撤収後」の対で測る（片側だけ緑にしない、B-35）。
///
/// 1. **capability SID（`S-1-15-3-`）宛のACEが付いている**——承認が実ACLへ届いた証拠。
/// 2. **package SID（`S-1-15-2-`）宛のACEが0本**——残課題#20の移行の不変条件そのもの。
///    1本でも残っていると同一セッションの全ドメインが素通りし、**しかも成功に見える**。
///    この不変条件を**実機で**測るのはここが初めてである。
/// 3. **宣言を取り消して次のパス2を回したあとに何本残るか**——エディタの後片付けが
///    どこまで効くか。`reconcile_undeclared_roots`が担当する経路で、**実機で1度も
///    通っていない**。値はまず観測して記録する（期待値を先に決め打たない）。
#[test]
#[ignore = "requires administrator rights (WFP netfilterd, ACE grant via privhelper)"]
fn an_executable_that_cannot_be_started_becomes_a_read_exec_candidate_and_then_runs() {
    const MARKER: &str = "POLICY-EDITOR-EXEC-REACH-OK";

    let workspace = tempfile::tempdir().expect("tempdir");
    let workspace_root = workspace.path();
    // **workspaceの外**に置く（中に置くとworkspace grantが覆ってしまい、診断は何も言わない）。
    // **かつ`%TEMP%`の外**（あそこは候補除外の対象。[`ProbeDir`]のdocを読むこと）。
    let toolbox = ProbeDir::new();
    let probe = toolbox.path().join("e2e-exec-probe.exe");
    std::fs::copy(r"C:\Windows\System32\cmd.exe", &probe).expect("copy the probe executable");
    // 引用符を付けない（付けるとPowerShellが文字列として評価する。パスに空白が無いことは
    // tempdirの形から保証される）。
    let command = format!("{} /c echo {MARKER}", probe.display());
    let declared = probe.display().to_string().replace('\\', "/");

    // 基準線。**ここを取らないと、あとで数えた本数が「元から在った分」と区別できない。**
    let baseline = acl_sddl(&probe);
    assert_eq!(
        count_sid_prefix(&baseline, "S-1-15-3-"),
        0,
        "precondition: a freshly copied probe must not carry any capability SID ACE: {baseline}"
    );
    assert_eq!(
        count_sid_prefix(&baseline, "S-1-15-2-"),
        0,
        "precondition: a freshly copied probe must not carry any package SID ACE: {baseline}"
    );

    write_policy(workspace_root, "e2e-exec", &command);

    // --- 1回目: 宣言が無いので起動できない。診断が名指しし、候補として出る -----------
    let first = run_record_net(workspace_root, "e2e-exec", &command);
    let first_stdout = String::from_utf8_lossy(&first.stdout).to_string();
    let first_stderr = String::from_utf8_lossy(&first.stderr).to_string();
    eprintln!("--- 1st stdout ---\n{first_stdout}\n--- 1st stderr ---\n{first_stderr}");

    assert!(
        first_stderr.contains("Tier2aへ着地しました"),
        "this test is meaningless unless the enforcement is actually up: {first_stderr}"
    );
    assert!(
        !first_stdout.contains(MARKER),
        "precondition: the executable must NOT be startable before it is approved \
         (if it already runs, this run proves nothing): {first_stdout}"
    );

    let manifest = latest_manifest(workspace_root);
    assert_eq!(
        manifest["unreachable_exec"].as_str(),
        Some(declared.as_str()),
        "the pre-run diagnosis must name the executable in the manifest: {manifest}"
    );

    // 候補一覧（`show`）に`fs.read_exec`として並ぶこと。**ここがこの変更の本体**である。
    let show = run_show(workspace_root);
    // **候補表の行だけを見る。** 「fs.read_exec と対象パスを両方含む行」で拾うと、
    // 診断の説明行（`候補に足した: …`）が先に当たり、その行頭の語をidとして`approve`へ
    // 渡してしまう（実機で `知らない提案id: 候補に足した:` として出た）。
    // 候補表の行は必ず`fs-<番号>`で始まるので、そこまで含めて絞る。
    let id = show
        .lines()
        .map(str::trim_start)
        .find(|line| {
            line.starts_with("fs-") && line.contains("fs.read_exec") && line.contains(&declared)
        })
        .and_then(|line| line.split_whitespace().next())
        .unwrap_or_else(|| {
            panic!("the diagnosed executable must appear as an fs.read_exec candidate:\n{show}")
        })
        .to_string();

    // --- 承認して2回目: 今度は実際に起動する -----------------------------------------
    let approve = Command::new(editor_exe())
        .args([
            "approve",
            "--workspace",
            &workspace_root.to_string_lossy(),
            "--domain",
            "e2e-exec",
            "--accept",
            &id,
            "--yes",
        ])
        .output()
        .expect("approve should run");
    assert!(
        approve.status.success(),
        "approve failed: {}\n{}",
        String::from_utf8_lossy(&approve.stdout),
        String::from_utf8_lossy(&approve.stderr)
    );
    let policy = std::fs::read_to_string(workspace_root.join(".harness").join("policy.json"))
        .expect("policy.json");
    assert!(
        policy.contains(&declared),
        "the approved value must land in policy.json: {policy}"
    );

    let second = run_record_net(workspace_root, "e2e-exec", &command);
    let second_stdout = String::from_utf8_lossy(&second.stdout).to_string();
    let second_stderr = String::from_utf8_lossy(&second.stderr).to_string();
    eprintln!("--- 2nd stdout ---\n{second_stdout}\n--- 2nd stderr ---\n{second_stderr}");

    assert!(
        second_stdout.contains(MARKER),
        "after approving fs.read_exec the sandbox must be able to start it \
         (this is the whole point: the candidate list told the user what to approve, \
          and doing it has to actually work): {second_stdout}\n{second_stderr}"
    );

    // --- 付与後の実DACL: 宛先SIDは移ったか（残課題#20の受け入れ条件） --------------------
    let after_grant = acl_sddl(&probe);
    eprintln!("--- SDDL after grant ---\n{after_grant}");
    assert!(
        count_sid_prefix(&after_grant, "S-1-15-3-") >= 1,
        "the approved fs.read_exec must land as a capability SID ACE on the real DACL \
         (if this is 0 the exe ran for some other reason and the assertion above proves \
          nothing): {after_grant}"
    );
    assert_eq!(
        count_sid_prefix(&after_grant, "S-1-15-2-"),
        0,
        "[#20] the migration invariant: no session package SID ACE may remain on a declared \
         path. A single one lets every domain in the session through, and it looks like \
         success: {after_grant}"
    );

    // --- 宣言を取り消して次のパス2を回す: 後片付けはどこまで効くか --------------------
    let unapprove = Command::new(editor_exe())
        .args([
            "unapprove",
            "--workspace",
            &workspace_root.to_string_lossy(),
            "--domain",
            "e2e-exec",
            "--all",
            "--yes",
        ])
        .output()
        .expect("unapprove should run");
    assert!(
        unapprove.status.success(),
        "unapprove failed: {}\n{}",
        String::from_utf8_lossy(&unapprove.stdout),
        String::from_utf8_lossy(&unapprove.stderr)
    );
    let policy_after_unapprove =
        std::fs::read_to_string(workspace_root.join(".harness").join("policy.json"))
            .expect("policy.json");
    assert!(
        !policy_after_unapprove.contains(&declared),
        "precondition for the cleanup measurement: the declaration must be gone from \
         policy.json, otherwise nothing is expected to be revoked: {policy_after_unapprove}"
    );

    let third = run_record_net(workspace_root, "e2e-exec", &command);
    eprintln!(
        "--- 3rd stderr ---\n{}",
        String::from_utf8_lossy(&third.stderr)
    );

    let after_unapprove = acl_sddl(&probe);
    let capability_left = count_sid_prefix(&after_unapprove, "S-1-15-3-");
    eprintln!(
        "MEASURED: capability SID ACEs left after unapprove + next pass2 = {capability_left}\n\
         --- SDDL after unapprove ---\n{after_unapprove}"
    );
    // [BUG-142] **0本を要求する。** 撤収の条件は「もう誰も宣言していないこと」であり
    // （`plans/DESIGN-MAC-DOMAIN.md` §22.2.1）、宣言を全部取り消した以上ここは0でなければ
    // ならない。**初回の測定ではここが1だった**——撤収の索引がプロセス内の変数で、
    // CLIの流れ（付与→`unapprove`→再実行）は別プロセスなので常に空集合との差分になり、
    // 何も剥がさないまま無言で終わっていた。索引を台帳へ移した修正の回帰テストである。
    assert_eq!(
        capability_left, 0,
        "the declaration was withdrawn, so no declaration capability ACE may remain. \
         If this is 1, the revoke ran against an empty index again (BUG-142): {after_unapprove}"
    );
    // package SID宛は、宣言を外した後も0本のままでなければならない（撤収が宛先SIDを
    // **取り違えて**古い形で付け直していないこと）。
    assert_eq!(
        count_sid_prefix(&after_unapprove, "S-1-15-2-"),
        0,
        "[#20] a package SID ACE appeared during the revoke path: {after_unapprove}"
    );
}

/// `NetfilterHandle::start`は`current_exe().parent()`の隣から`harness-netfilterd.exe`を探すが、
/// **統合テストのバイナリが置かれる`target/debug/deps/`にそれは無い**（cargoが実行ファイルを
/// 置くのは`target/debug/`）。上の2本はビルド済みCLIをサブプロセスとして起こすので影響を
/// 受けないが、ライブラリを直接呼ぶこのテストは自分で置く必要がある。
///
/// 実装は`harness-sandbox`側の`ensure_daemon_next_to_test_binary`と同型だが、あちらは
/// `#[cfg(test)]`のクレート内部関数なので参照できない（テスト専用の関数を製品APIとして
/// 公開する方が悪い）。**同じ理由で同じことをしている**ことをここに書いておく。
fn place_netfilterd_next_to_the_test_binary() {
    const NAME: &str = "harness-netfilterd.exe";
    let current = std::env::current_exe().expect("current_exe");
    let deps = current.parent().expect("deps dir");
    let target = deps.join(NAME);
    let source = deps.parent().expect("target/debug").join(NAME);
    assert!(
        source.exists(),
        "{} is missing; run `cargo build --workspace` first",
        source.display()
    );
    let same = (|| -> Option<bool> {
        let (a, b) = (
            std::fs::metadata(&source).ok()?,
            std::fs::metadata(&target).ok()?,
        );
        Some(a.len() == b.len() && a.modified().ok()? == b.modified().ok()?)
    })()
    .unwrap_or(false);
    if !same {
        std::fs::copy(&source, &target).unwrap_or_else(|e| {
            panic!(
                "failed to place a fresh {NAME} next to the test binary ({e}). If a previous \
                 harness-netfilterd.exe is still running, stop it and re-run."
            )
        });
    }
}
