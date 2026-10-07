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
//! 6. **1プロセスで2回走らせると、2回目はWFPのdaemonを再利用し**（D-56）、**Spawn Daemonは起こし直す**
//!    （決定68 の前例の(3)）——かつ**再利用したdaemonでも強制は本物のまま**（生ソケットは落ちる）。
//!    「2回目が速かったのは強制が消えたからではない」ことを区別する対（B-35）
//! 7. **承認したFS宣言が実DACLへ届き、その宛先SIDがcapability SIDである**（残課題#20の
//!    移行の不変条件＝package SID宛が0本）。**取り消したあとに何が残るか**も同じ実行で測る
//!    ——[`an_executable_that_cannot_be_started_becomes_a_read_exec_candidate_and_then_runs`]
//! 8. **強制モード（`--enforce-net`、決定64）は宣言した通信先だけを通し、宣言の外を断る**
//!    ——同じ実行で許可側と禁止側を両方測り、候補が断られた宛先だけになることを確かめる
//!    （[`enforcing_pass2_allows_only_the_declared_domain_and_proposes_the_refused_one`]）
//! 9. **同じワークスペースの`harness.exe`の許可がパス2で消えない**（BUG-184）——子モジュール[`harness_grants`]
//!
//! # [決定68] パス2は入口から・生成禁止つきで走る
//!
//! パス2は入口のドメイン`workspace-shell`から始め、Spawn Daemon を生成禁止（`Restricted`）つきで起こす。
//! シェルが起こす子（`curl.exe`・`e2e-exec-probe.exe`）は**入口の辺に当たらないと Daemon が断る**ので、
//! 子を起こす試験は`policy.json`にその実行ファイルの辺を**入口から入口へ**（自己ループ。Daemon は表を引かず
//! 呼び出し元の実体で起こす）書く（[`write_policy`]）。宣言も入口のドメインに置き、`--domain`は渡さない。
//!
//! # このテストが触らないもの（正直に書く）
//!
//! ネットワーク側の3本は`policy.json`の`fs`を**空**にしてある。workspace外のFSルールを
//! 入れるとこのマシンの実ACLと`fs-passthrough-ledger.json`を書き換えることになり、
//! ネットワークを測るテストの副作用としては重すぎる。**FS側を測るのは7番と9番だけ**で、
//! 7番は`%TEMP%`配下の一時ディレクトリに閉じている（`--fs-allow`経由の同じ機構は
//! CLI側の既存E2Eが別に通している）。9番が実マシンへ書くものと撃ち方は子モジュールのdocが持つ。

#![cfg(windows)]

#[path = "record_net_e2e/harness_grants.rs"] // 1,000行に近いので子モジュールへ置く（規則1）
mod harness_grants;

mod common;

use std::path::Path;
use std::process::Command;

// 子モジュール（`harness_grants`）も`super::`越しに使う。
use common::{acl_sddl, count_sid_prefix, editor_exe, place_netfilterd_next_to_the_test_binary};

/// 記録対象にするドメイン。外部への到達性が要るので、安定していて用途上問題の無いものを使う。
const TARGET_DOMAIN: &str = "example.com";

/// 入口のドメインの名前（`harness_policy::policy_file::ENTRY_DOMAIN`）。
const ENTRY: &str = harness_policy_editor::policy_file::ENTRY_DOMAIN;

/// Windows 標準の`curl.exe`（PowerShell が`curl.exe`を引いて起こす実行ファイル。入口の辺に書く綴り）。
fn curl_exe() -> String {
    common::system32("curl.exe")
}

/// [決定68(2)] 宣言は**入口のドメイン**（`workspace-shell`）に置く——パス2は常に入口から始め、通信の宣言も入口のものを使う。
/// `children`はコマンドが起こす子の実行ファイル（絶対パス）で、**入口から入口への辺**（引数は任意）として書く
/// ——パス2は生成禁止を積むので、辺の無い子は Daemon が`no_matching_edge`で断る（決定68(1)）。
fn write_policy(workspace_root: &Path, command: &str, children: &[&str]) {
    // **1つも宣言しない。** それでも到達できることがrecord_allの効き目の証明になる。
    write_policy_declaring(workspace_root, command, &[], children);
}

/// [`write_policy`]の、通信先を宣言する版（強制モードの試験が使う）。手書きの JSON にせず製品の型で組み、
/// 製品の`save`で書く（型が変わった日に試験だけが古い綴りで残らない。`save`は読み込みと同じ遷移の検査を掛ける）。
fn write_policy_declaring(
    workspace_root: &Path,
    command: &str,
    allow_domains: &[&str],
    children: &[&str],
) {
    use harness_policy::transition::{editor_edge, AnyMarker, ArgvMatcher};
    let mut entry = harness_policy::policy_file::PolicyDomain::new(ENTRY);
    entry.commands.push(command.to_string());
    entry.cwd = Some(workspace_root.to_path_buf());
    // `fs`は意図的に空（モジュールdocの「触らないもの」参照）。
    entry.net.allow_domains = allow_domains.iter().map(|d| d.to_string()).collect();
    for exe in children {
        entry
            .process
            .transitions
            .push(editor_edge(exe, ArgvMatcher::Any(AnyMarker), ENTRY));
    }
    let mut file = harness_policy::policy_file::PolicyFile::default();
    file.domains.push(entry);
    std::fs::create_dir_all(workspace_root.join(".harness").join("sandbox")).unwrap();
    harness_policy::policy_file::save(workspace_root, &file)
        .unwrap_or_else(|e| panic!("policy.jsonを書けない: {e}"));
}

fn run_record_net(workspace_root: &Path, command: &str) -> std::process::Output {
    run_record_net_with(workspace_root, command, &[])
}

/// [`run_record_net`]に`record-net`のフラグ（`--enforce-net`等）を足して走らせる版（撃ち方の正本は
/// [`common::record_net_cli`]）。[決定68(2)] `--domain`は無い（パス2は常に入口から始める）。
fn run_record_net_with(workspace_root: &Path, command: &str, flags: &[&str]) -> std::process::Output {
    common::record_net_cli(workspace_root, command, flags, &[]).0
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
    // [決定68(1)] 入口から入口への`curl.exe`の辺が無いと、Daemon が生成を断る（モジュールdoc）。
    let command = format!("curl.exe -sS -o NUL -w '%{{http_code}}' https://{TARGET_DOMAIN}/");
    write_policy(workspace_root, &command, &[&curl_exe()]);

    let output = run_record_net(workspace_root, &command);
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
    // [決定68(2)] パス2は入口から始めたとマニフェストに書く。
    assert_eq!(manifest["domain"], ENTRY, "manifest: {manifest}");
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

/// 8番（決定64）: **強制モードは宣言した通信先だけを通し、宣言の外を断る。断った宛先だけが候補になる。**
///
/// 1本のコマンドで、宣言した宛先（`example.com`）と宣言していない宛先（`example.org`）へ
/// 1回ずつ繋ぐ。許可側と禁止側を同じ実行に置くので、「何も通さない」でも「全部通す」でも落ちる
/// （B-35）。断る側は中継プロキシが接続の前に断るので、`example.org`へ実際に届く必要は無い。
#[test]
#[ignore = "requires administrator rights (WFP netfilterd) and outbound network access"]
fn enforcing_pass2_allows_only_the_declared_domain_and_proposes_the_refused_one() {
    const UNDECLARED: &str = "example.org";
    let workspace = tempfile::tempdir().expect("tempdir");
    let workspace_root = workspace.path();
    let command = format!(
        "curl.exe -sS -o NUL -w '%{{http_code}}' https://{TARGET_DOMAIN}/; \
         curl.exe -sS -o NUL -w '%{{http_code}}' https://{UNDECLARED}/"
    );
    write_policy_declaring(workspace_root, &command, &[TARGET_DOMAIN], &[&curl_exe()]);

    let output = run_record_net_with(workspace_root, &command, &["--enforce-net"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}");

    assert!(
        output.status.success(),
        "record-net should succeed even if the command itself fails: {stdout}\n{stderr}"
    );
    assert!(
        stderr.contains("Tier2aへ着地しました"),
        "the run must land on Tier2a: {stderr}"
    );
    assert!(
        stderr.contains("宣言した通信先 1件だけを許し"),
        "the proxy must start with the declared allowlist, not record_all: {stderr}"
    );

    // 許可側: 宣言した宛先は許可リストに一致して通った（record_allで通ったのではない）。
    let audit = net_audit_of_latest_session(workspace_root);
    // 監査の生の行も残す。ホスト名を持たないWFPのdropが何件・どの宛先かは、合否と別に
    // 読み返したくなる（一時ワークスペースは試験の終わりに消える）。
    eprintln!("--- net-audit.jsonl ---\n{audit}");
    let events: Vec<serde_json::Value> = audit
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    let host_of = |event: &serde_json::Value| {
        event["host"]
            .as_str()
            .or_else(|| event["remote_host"].as_str())
            .map(str::to_string)
    };
    assert!(
        events.iter().any(|e| host_of(e).as_deref() == Some(TARGET_DOMAIN)
            && e["allowed"] == true
            && e["reason"] == "domain_allowed"),
        "the declared domain must pass as an allowlist hit: {audit}"
    );
    assert!(
        !audit.contains("record_all"),
        "nothing may pass as record_all in the enforcing mode: {audit}"
    );
    // 禁止側: 宣言していない宛先は断られた。
    assert!(
        events.iter().any(|e| host_of(e).as_deref() == Some(UNDECLARED)
            && e["allowed"] == false),
        "the undeclared domain must be refused: {audit}"
    );

    // 候補は断られた宛先だけ（宣言済みの宛先を候補へ戻さない）。
    assert!(
        stdout.contains(&format!("net.allow_domains = {UNDECLARED}")),
        "the refused domain must be proposed: {stdout}"
    );
    assert!(
        !stdout.contains(&format!("net.allow_domains = {TARGET_DOMAIN}")),
        "an already-declared domain must not be proposed again: {stdout}"
    );

    // マニフェストがモードを残しており、`show`で開き直しても同じ候補になる。
    let manifest = manifest_of_latest_session(workspace_root);
    assert_eq!(manifest["net_mode"], "declared", "manifest: {manifest}");
    assert_eq!(manifest["status"], "finished", "manifest: {manifest}");
    let shown = run_show(workspace_root);
    assert!(
        shown.contains(&format!("net.allow_domains = {UNDECLARED}"))
            && !shown.contains(&format!("net.allow_domains = {TARGET_DOMAIN}")),
        "show must read the record back with the mode it was run with: {shown}"
    );

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
    // 子を起こさない（PowerShell の中だけで完結する）ので辺は要らない。
    write_policy(workspace_root, command, &[]);

    let output = run_record_net(workspace_root, command);
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

/// 6番（D-56）: **1プロセスで`record_net`を2回呼び、2回目がWFPのdaemonを再利用すること**と、
/// **再利用したdaemonでも強制が本物のままであること**を同時に固定する。あわせて
/// **Spawn Daemon は使い回さず、2回目に起こし直す**ことを見る（決定68 の前例の(3)）。
///
/// # 2つの daemon は逆の持ち方をする
///
/// WFPのdaemon（`harness-netfilterd`）は昇格して起きるので、使い回すことで2回目のUACを消す（D-56）。
/// Spawn Daemon は昇格しないので UAC は増えず、宣言と遷移先の表を Hello の後で差し替える口が無いので、
/// 使い回すと承認した辺がその回に効かない（決定68の困りごと2）——だから毎回起こし直す。どちらかだけを見ると、
/// 「全部使い回す」「全部起こし直す」の取り違えがもう片方で緑になるので、同じ2回で両方を見る。
/// Spawn Daemon の取り替えは**プロセスIDが変わったこと**を、エディタの持ち主（非公開）ではなく
/// `Get-CimInstance`（[`common::spawn_daemons_started_by_this_process`]）で数える。
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
fn a_second_pass2_in_the_same_process_reuses_the_wfp_daemon_restarts_the_spawn_daemon_and_still_enforces()
{
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
    write_policy(workspace_root, &reach, &[&curl_exe()]);
    let daemons_before = common::spawn_daemons_started_by_this_process();
    assert!(
        daemons_before.is_empty(),
        "前提: この試験のプロセスがまだ Spawn Daemon を起こしていない（前の試験の残りが居ると、下の取り替えの判定が読めない）: {daemons_before:?}"
    );

    // **宣言順が撤収順を決める**（D-56）。`SessionGrants`より後に`SharedNetfilter`を作ることで、
    // netfilterdの`Teardown`がAppContainerプロファイルの削除より先に走る。
    let _grants = SessionGrants::hold();
    let wfp = SharedNetfilter::hold();
    // 収集器も同じ順序で持つ（D-56 段階2）。このE2Eが測るのはWFPの再利用だが、
    // 収集器を渡さないと**そもそもパス2が組み立てられない**ので、製品と同じ形で持つ。
    let collector = harness_policy_editor::record::SharedCollector::hold();
    let spawn_daemon = harness_policy_editor::record_net::SharedSpawnDaemon::hold();

    let never_cancel = || false;

    // 1回の実行を回して「WFPが立ったか・再利用だったか」と標準出力を集める小さなヘルパー。
    let run = |command: &str| -> (Option<bool>, String) {
        // [決定68(2)] 要求はドメインを持たない（`record_net`が`policy.json`を読み、入口から始める）。
        let request = RecordNetRequest {
            command,
            cwd: workspace_root,
            workspace_root,
            timeout: Some(std::time::Duration::from_secs(120)),
            cancel: &never_cancel,
            wfp: &wfp,
            collector: &collector,
            spawn_daemon: &spawn_daemon,
            net_mode: harness_policy_editor::record_net::NetMode::RecordAll,
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
    // 1回目の Spawn Daemon は、次のパス2が畳むまで生きている（持ち主がプロセスの寿命で持つ）。
    let daemons_first = common::spawn_daemons_started_by_this_process();
    eprintln!("[e2e] 1回目の後の Spawn Daemon: {daemons_first:?}");
    assert_eq!(
        daemons_first.len(),
        1,
        "1回目のパス2の後に、この試験が起こした Spawn Daemon がちょうど1つ居ない: {daemons_first:?}"
    );

    // 2回目: **WFPのdaemonを再利用する＝UACが出ない**。しかも強制は本物のまま。
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
    // **Spawn Daemon は起こし直す**（決定68 の前例の(3)）——1回目の個体は畳まれ、別のプロセスIDの1つだけが居る。
    let daemons_second = common::spawn_daemons_started_by_this_process();
    eprintln!("[e2e] 2回目の後の Spawn Daemon: {daemons_second:?}");
    assert!(
        daemons_second.len() == 1 && daemons_second.is_disjoint(&daemons_first),
        "2回目のパス2は Spawn Daemon を起こし直す（1回目 {daemons_first:?} を畳み、別の1つを起こす）はずが、\
         2回目の後は {daemons_second:?}。同じプロセスIDなら使い回している（承認した辺がその回に効かない、決定68の困りごと2）、\
         2つ以上なら前の個体を畳んでいない"
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

    // [決定68(1)] 入口から入口への辺（Daemon が呼び出し元の実体で起こす）。辺はファイルの許可ではないので、1回目に
    // 起動できないことは変わらない——起動できない理由が「辺が無い」ではなく「実行権が無い」であることを、辺を書いて
    // 揃える。綴りは`\`の形（下の`policy.json`の`/`の値の照合に、辺の綴りが当たらないようにする）。
    write_policy(workspace_root, &command, &[&probe.display().to_string()]);

    // --- 1回目: 宣言が無いので起動できない。診断が名指しし、候補として出る -----------
    let first = run_record_net(workspace_root, &command);
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
    let line = show
        .lines()
        .map(str::trim_start)
        .find(|line| {
            line.starts_with("fs-") && line.contains("fs.read_exec") && line.contains(&declared)
        })
        .unwrap_or_else(|| {
            panic!("the diagnosed executable must appear as an fs.read_exec candidate:\n{show}")
        });
    // [決定68] 実行前診断は入口で起こすコマンドを診るので、候補は入口のドメインの見出しに出る（P6.6）。
    assert!(
        line.contains(&format!("[{ENTRY}]")),
        "the diagnosed executable must be offered to the entry domain: {line}"
    );
    let id = line
        .split_whitespace()
        .next()
        .expect("a candidate line starts with its id")
        .to_string();

    // --- 承認して2回目: 今度は実際に起動する -----------------------------------------
    // [決定68 の前例の(1)(7)] パス2の記録は許可した生成の記録を持つので候補がドメインごとに分かれ、`approve`は
    // `--domain`を断る（実行前診断の候補は入口の候補に出るので、書く先は入口）。
    let approve = Command::new(editor_exe())
        .args([
            "approve",
            "--workspace",
            &workspace_root.to_string_lossy(),
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

    let second = run_record_net(workspace_root, &command);
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
            ENTRY,
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

    let third = run_record_net(workspace_root, &command);
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

/// **サンドボックスの中のシェルから、Spawn Daemonの要求受付パイプへ1往復する**
/// PowerShellスクリプト（`plans/DESIGN-MAC-PROTOCOL.md` §12）。
///
/// 子の環境変数`HARNESS_SPAWN_REQUEST_PIPE`から窓口の名前を取り、
/// `[4バイトのリトルエンディアン長][本体]`のフレームで1往復して`REPLY:<json>`を1行印字する。
///
/// # **同じ綴りが`crates/harness-tools/src/shell/shell_tests.rs`の(e)にもある**
///
/// あちらは`run_shell`の、こちらはポリシーエディタのパス2の**同じ測定**である。
/// 1箇所へ畳めないのは、あちらが`#[cfg(test)]`のクレート内部にあり、ここから参照するには
/// **テストでしか使わない文字列を製品クレートの公開面へ載せる**ことになるためで、
/// このファイルの`place_netfilterd_next_to_the_test_binary`が同じ理由で採ったのと同じ判断である。
///
/// **写しである以上、片方だけ直ると気付けない。** 直すときは必ず両方を直すこと
/// （向こう側にも同じ注記がある）。
const SPAWN_REQUEST_ROUNDTRIP: &str = r#"
$raw = $env:HARNESS_SPAWN_REQUEST_PIPE
if (-not $raw) { Write-Output 'NO_PIPE_ENV'; exit 0 }
$name = $raw -replace '^\\\\\.\\pipe\\', ''
$c = New-Object System.IO.Pipes.NamedPipeClientStream('.', $name, 'InOut')
try { $c.Connect(5000) } catch { Write-Output ('CONNECT_FAILED:' + $_.Exception.Message); exit 0 }
$body = [Text.Encoding]::UTF8.GetBytes('{"kind":"spawn","image":"C:\\Windows\\System32\\cmd.exe","command_line":"\"cmd.exe\" /c exit 0","cwd":"C:/"}')
$c.Write([BitConverter]::GetBytes([int]$body.Length), 0, 4)
$c.Write($body, 0, $body.Length)
$c.Flush()
$hdr = New-Object byte[] 4
if ($c.Read($hdr, 0, 4) -ne 4) { Write-Output 'NO_REPLY_HEADER'; exit 0 }
$n = [BitConverter]::ToInt32($hdr, 0)
$buf = New-Object byte[] $n
$got = 0
while ($got -lt $n) { $r = $c.Read($buf, $got, $n - $got); if ($r -le 0) { break }; $got += $r }
Write-Output ('REPLY:' + [Text.Encoding]::UTF8.GetString($buf, 0, $got))
"#;

/// 手書きのJSONを、**受け手の型で読めることだけ**確かめる（2026-09-17に追加）。
///
/// # なぜ要るのか——**コンパイラがここを見張っていない**
///
/// 電文の形を変えたとき、Rustで組んでいる呼び出し元は全部ビルドが落ちて気付ける。
/// ところが上の2つの写しは**PowerShellの中の文字列**なので、古い綴りのまま残っても
/// 何も起きない——**気付くのは昇格のE2Eを60秒回した後**である（段階6f-1で実際に踏んだ）。
///
/// ここは昇格も実機も要らない。**壊れていれば1秒で分かる。**
#[test]
fn the_hand_written_spawn_request_still_parses() {
    let json = SPAWN_REQUEST_ROUNDTRIP
        .split_once("GetBytes('")
        .and_then(|(_, rest)| rest.split_once("')"))
        .map(|(json, _)| json)
        .expect("the script must contain a GetBytes('...') payload");
    // PowerShellの単一引用符の中なので、JSONの`\\`はそのままの2文字である。
    serde_json::from_str::<harness_sandbox::tier2a::spawnd::SpawnRequest>(json).unwrap_or_else(
        |e| {
            panic!(
                "要求受付パイプへ手書きで送っているJSONが、受け手の型で読めない: {e}\n{json}\n\
                 **この写しは`crates/harness-tools/src/shell/shell_tests.rs`にもある。両方直すこと。**"
            )
        },
    );
}

/// 8番: **パス2で起こした子は要求受付パイプへ届き、`no_matching_edge`で断られる**
/// （`plans/DESIGN-MAC-PROTOCOL.md` §12の経路表で「積む」と決めた側）。
///
/// # なぜ`run_shell`側のテストでは足りないのか
///
/// パス2は入口の関数（`spawn_shell_in_workspace_via_daemon`）を`run_shell`と共有するが、
/// **そこへ辿り着くまでの配線は別物**である——`record_net`が自前で`SharedSpawnDaemon`を
/// 遅延起動し、`SessionGrants`・`SharedNetfilter`と並ぶ寿命で持つ。共通部分だけを測って
/// 呼び出し側の1本が取り残される形は、このリポジトリで実際に起きている（BUG-032）。
///
/// # 見るのは「断られたこと」ではなく**断る理由**である
///
/// `no_matching_edge`は「あなたが誰かも、どのドメインに居るかも分かった。
/// **ただしそのドメインは`git.exe`を起こす辺を宣言していない**」である
/// （このE2Eは`fs`も`process`も空の`policy.json`を書く）。`not_registered`は
/// 「登録が効いていない」（BUG-116の形）。**同じ値へ丸めると、常に拒否する実装でも通る**（`B-35`）。
///
/// # [段階6b] この1本が、遷移元ドメインの配線まで測っている
///
/// `unknown_source_domain`ではなく`no_matching_edge`が返ることは、
/// **Daemonがこの子の遷移元を入口のドメイン（`workspace-shell`）として引けている**ことを意味する
/// （決定68(2)。以前は「記録中のドメイン」だった。宣言を入口へ置いたので、入口の名前が`policy.json`に在る）。
/// 子が受け取った理由の文字列だけでなく、Daemon の待ち行列（`pending.jsonl`）の行の遷移元・実行ファイル・理由も見る
/// ——子の印字は子が組み立てた文字列で、遷移元の名前までは載らない。
///
/// # 対の相手
///
/// 拒否側は`harness-mcp`の`transport_stdio_e2e_tests`が持つ（MCPの子は**そもそも届かない**）。
/// 2本で「経路ごとに向きが逆である」を固定している。
///
/// # 歯があることの確かめ方
///
/// `crates/harness-sandbox/src/tier2a/win_appcontainer/launch.rs`の
/// `SpawnRequestAccess::Grant`を`Withhold`へ倒すと接続が拒否され、このテストは赤くなる
/// （倒したら必ず戻すこと）。
///
/// # ここが測っていないもの
///
/// - **外部への到達性は要らない**（窓口はローカルの名前付きパイプ）。それでも昇格が要るのは
///   `record_net`がWFPのdaemonを起こすためで、パイプのためではない
/// - `policy.json`の`fs`は他の3本と同じく**空**にしてある（実ACLと台帳を触らない、モジュールdoc）
#[test]
#[ignore = "requires administrator rights (WFP netfilterd) and starts a real spawn daemon"]
fn pass2_reaches_the_request_pipe_and_is_denied_by_policy_not_by_the_table() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let workspace_root = workspace.path();
    // 辺は書かない——`cmd.exe`を起こす辺が無いことが、この試験の断られる理由そのものである。
    write_policy(workspace_root, SPAWN_REQUEST_ROUNDTRIP, &[]);

    let output = run_record_net(workspace_root, SPAWN_REQUEST_ROUNDTRIP);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    eprintln!("--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}");

    // 着地していなければ、以下は何も測っていない（Tier1にはSpawn Daemonが居ない）。
    assert!(
        stderr.contains("Tier2aへ着地しました"),
        "this test is meaningless unless the recording actually lands on Tier2a: {stderr}"
    );

    // 窓口の名前が子へ届いていない＝Daemon経由になっていないか、envの受け渡しが落ちている。
    //
    // **部分一致で見ない。行そのものと比べる。** この目印は`SPAWN_REQUEST_ROUNDTRIP`の
    // 本文にも（`Write-Output 'NO_PIPE_ENV'`という**まだ実行されていない行**として）現れる。
    // 進行表示はいまその本文をstderrへ echo しているので今日は当たらないが、
    // **表示先が変わった日に、機構は健全なままこのテストだけが赤くなる**。
    // 子が実際に印字した行は`NO_PIPE_ENV`単独なので、行として比べれば取り違えようがない。
    let printed_lines: Vec<&str> = stdout.lines().map(str::trim).collect();
    assert!(
        !printed_lines.contains(&"NO_PIPE_ENV"),
        "パス2の子に要求受付パイプの名前が届いていない。Daemon経由になっていないか、\
         環境変数の受け渡しが落ちている: {stdout}"
    );
    assert!(
        stdout.contains("no_matching_edge"),
        "パス2の子が要求受付パイプで `no_matching_edge` を受け取れていない。\
         `unknown_source_domain` なら遷移元ドメインの配線が違う（パス2は入口のドメインの固定名を\
         渡すはずで、それ以外の名前を渡していると`policy.json`に無いのでこうなる。決定68）、\
         `not_registered` なら Process Table への登録が Resume より前に効いていない（BUG-116の形）、\
         `CONNECT_FAILED` なら spawn要求用capability を積んでいない: {stdout}"
    );
    assert!(
        !stdout.contains("not_registered"),
        "Daemonが起こした子なのに「台帳に無い」で断られている（§12・BUG-116）: {stdout}"
    );
    // [決定68(2)] Daemon が断った記録の遷移元は入口のドメイン（ちょうど1種類。要求は1往復だけ送る）。
    let denials = common::daemon_denials(workspace_root, "pass2-spawn-reach");
    eprintln!("[e2e] 待ち行列の拒否: {denials:?}");
    let expected = (
        Some(ENTRY.to_string()),
        "cmd.exe".to_string(),
        harness_sandbox::tier2a::spawnd::DenyReason::Transition {
            denial: harness_policy::transition::TransitionDenial::NoMatchingEdge,
        },
    );
    assert_eq!(
        denials,
        vec![expected],
        "Daemon の待ち行列に（入口 {ENTRY}, cmd.exe, no_matching_edge）がちょうど1件ない"
    );

    // 撤収まで通っている（ここが抜けるとプロファイルとACEがマシンに残る）。
    let manifest = manifest_of_latest_session(workspace_root);
    assert_eq!(manifest["pass"], 2, "manifest: {manifest}");
    assert_eq!(manifest["status"], "finished", "manifest: {manifest}");
}
