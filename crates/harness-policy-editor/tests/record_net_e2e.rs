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
//!
//! # このテストが触らないもの（正直に書く）
//!
//! `policy.json`の`fs`は**空**にしてある。workspace外のFSルールを入れるとこのマシンの実ACLと
//! `fs-passthrough-ledger.json`を書き換えることになり、テストの副作用としては重すぎる
//! （その経路は`--fs-allow`側の既存E2Eが通している）。ここで確かめるのはネットワーク側と、
//! 「Tier2aへ着地してWFPが立った」という土台の部分である。

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
