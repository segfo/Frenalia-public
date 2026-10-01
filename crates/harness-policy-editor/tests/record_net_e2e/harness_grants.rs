//! [#71の4点目・BUG-184] **エディタの試験実行（パス2、`record-net`）を、`harness.exe`が動いているのと
//! 同じワークスペースで回しても、`harness.exe`が付けた許可は取り消されずに残る。**
//!
//! # 何を確かめるのか
//!
//! パス2は開始時に「もう宣言されていない許可」を取り消す（`record_net.rs`の
//! `reconcile_undeclared_roots`）。取り消し候補はそのワークスペースが宛先SIDを発行したパスの全部
//! （capability台帳）で、残す集合は`policy.json`の全ドメインの承認済み宣言＋`settings.json`の`fs.*`である。
//! [BUG-184](../../../../docs/bugs/BUG-184.md)の修正はこの2つを入れた——残す集合をワークスペースの
//! ファイル宣言の全部にしたことと、**発行元のワークスペースが実行中なら取り消さない**ことである。
//! 単体試験（`stale_roots_tests`）はどちらも判定までしか測らず、実機を通した姿はこの試験だけが見る。
//!
//! 置くものは3つ（どれもワークスペースの外、`C:\`直下）。
//!
//! | 置き場 | `harness.exe`が付ける経路 | 実行中のパス2 | 終了後のパス2 |
//! |---|---|---|---|
//! | `declared`（A） | 入口ドメインの承認済み宣言 | **残る**（残す集合） | **残る**（残す集合）← 許可側 |
//! | `fsallow`（F） | `--fs-allow` | **残る**（実行中なので見送り） | 取り消される（BUG-184の限界(1)） |
//! | `stale`（S） | 起動時は承認済み宣言。**動いている間に`unapprove`で宣言と承認を外す** | 残る（見送り。見送った件数に入る） | **取り消される**（どこからも外れた宣言）← 禁止側 |
//!
//! **終了後の回が対照である**（`B-35`）。実行中の回だけだと、「残った」が取り消し処理が死んでいる
//! からなのか、生存判定が効いたからなのかを区別できない。終了後に同じ操作でSが消え、Aが残れば、
//! 取り消し処理は生きていて、残す集合も効いている。実行中の回は、見送った件数（SとFの2件）が
//! 警告に出ることで、取り消し処理がSとFを候補として見たうえで見送ったことを確かめる。
//!
//! # 2つのキーに分けてある（撃つ順序が要る）
//!
//! - `e2e-policy-editor-keeps-harness-grants`（`keep_`）: `harness.exe`を動かしたまま
//!   パス2を回し、3つとも残ることを確かめる。**3つのACEと承認を残して終わる**（`harness.exe`は
//!   試験の中で終了させる）
//! - `e2e-policy-editor-revokes-stale-grants`（`revoke_`）: 動いていない状態でパス2を回し、Sが消えてAが
//!   残ることを確かめ、残りを製品の取り消し（`unapprove`と`harness fs revoke`）で片付ける
//!
//! 2つのキーの間で、人が3つの置き場のACLを見られる（`(Get-Acl <置き場>).Access`）。
//! `e2e-policy-editor-pass2`（`record_net_e2e`の全件）からは`--skip harness_grants::`で外してある。
//!
//! # 撃つ前に要るもの
//!
//! - **`e2e-mock`付きの`harness.exe`**（`--provider mock`の台本で`harness.exe`を待たせる）。この試験の
//!   バイナリは`harness-cli`をビルドしないので、エディタの実行ファイルの隣の`harness.exe`を使う。
//!   `cargo build --workspace`の**後に**`cargo build -p harness-cli --features e2e-mock`を撃っておく
//!   （逆順だと`e2e-mock`無しで上書きされる）。無ければ試験が手順付きで落ちる
//! - `harness-netfilterd.exe`等の補助（`cargo build --workspace`。パス2のほかの試験と同じ）
//!
//! # 測っていないもの
//!
//! - **画面版のエディタ**（1プロセスで試験実行を繰り返すと、2回目以降は自分の印で「実行中」と判定して
//!   見送る。BUG-184の限界(2)）。ここはCLIの`record-net`だけを撃つ
//! - `settings.json`の`fs.*`の宣言（残す集合に入る経路の1つ）と、CoWの差分層
//! - **この試験自体の歯**: 2026-10-01に付与側→撤収側を1回ずつ撃って緑だった（`docs/STATUS.md`
//!   サンドボックス周辺 #71）。製品の側を壊して赤くなることは確かめていない（`B-27`）

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use harness_core::{BlockKind, StopReason, StreamEvent, Usage};
use harness_policy::policy_file::{PolicyDomain, PolicyFile, ENTRY_DOMAIN};
use harness_sandbox::tier2a::policy_approval::{DeclarationRef, PolicyApprovalStore};

/// `keep_`を撃つ`KNOWN_TARGETS`のキー。
const KEEP_KEY: &str = "e2e-policy-editor-keeps-harness-grants";
/// `revoke_`を撃つキー。
const REVOKE_KEY: &str = "e2e-policy-editor-revokes-stale-grants";

/// ワークスペース。`%TEMP%`を使わない（`harness.exe`のTier2aがプロファイルの祖先へtraverseを付ける。
/// `crates/harness-cli/tests/tier2a_e2e.rs`の冒頭と同じ理由）。
const WORKSPACE: &str = r"C:\harness-e2e\editor-keeps-harness";
/// スクラッチ（台本・`harness.exe`の出力）。ワークスペースの外に置く。
const SCRATCH: &str = r"C:\harness-e2e\_scratch";
/// パス2で記録するドメイン（ファイル宣言を持たない＝パス2自身は何も付けない）。
const RECORDED_DOMAIN: &str = "e2e-keep";
/// パス2で撃つコマンド。走ったことを標準出力の印で見る。
const PASS2_MARKER: &str = "EDITOR_PASS2_RAN";

/// 3つの置き場。**付与の試験と撤収の試験が同じ値を読む**（綴りを2箇所に書かない、`B-05`）。
const DECLARED: &str = r"C:\harness-e2e-keep-declared";
const FS_ALLOW: &str = r"C:\harness-e2e-keep-fsallow";
const STALE: &str = r"C:\harness-e2e-keep-stale";

/// 実行中の回で、パス2が見送るはずの件数（SとF）。
const DEFERRED_WHILE_RUNNING: usize = 2;

fn harness_exe() -> PathBuf {
    Path::new(super::editor_exe()).with_file_name("harness.exe")
}

fn workspace() -> PathBuf {
    PathBuf::from(WORKSPACE)
}

/// `policy.json`に書く値（ポリシーエディタが書く`/`区切りの綴り）。承認台帳はこの綴りで照合する。
fn declared_value(dir: &str) -> String {
    format!("{}/**", harness_policy::normalize::normalize_path(dir))
}

fn entry_declaration(value: &str) -> DeclarationRef<'_> {
    DeclarationRef {
        domain: ENTRY_DOMAIN,
        value,
        access: harness_config::FsAccess::ReadExec,
    }
}

/// `path`のDACLに載っているcapability SID（`S-1-15-3-`）宛のACEの本数（親の`acl_sddl`で読む。
/// 置き場は試験が作り直した`C:\`直下のディレクトリなので、継承分は混ざらない）。
fn capability_aces(path: &str) -> usize {
    super::count_sid_prefix(&super::acl_sddl(Path::new(path)), "S-1-15-3-")
}

/// capability台帳に、このワークスペースが`path`宛に発行した宣言の宛先が何件あるか。
fn minted_for(path: &str) -> usize {
    let ws = workspace().canonicalize().unwrap_or_else(|_| workspace());
    harness_sandbox::tier2a::workspace_capability::declaration_capability_names(
        Path::new(path),
        Some(&ws),
    )
    .len()
}

fn require_elevated(key: &str) {
    assert!(
        harness_sandbox::tier2a::privhelper::is_elevated(),
        "この試験は管理者権限で走らせること（`harness.exe`とパス2がACEを書き、WFPのdaemonを起こす）。\
         素の`cargo test`ではなく`dev-elevated-run.exe {key}`から撃つ"
    );
}

/// エディタのサブコマンドを1回撃つ（`approve-declared`・`unapprove`）。**失敗を返す**。
fn editor(args: &[&str]) -> Result<String, String> {
    let output = Command::new(super::editor_exe())
        .args(args)
        .output()
        .map_err(|e| format!("エディタを起動できない: {e}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        Ok(text)
    } else {
        Err(format!(
            "`harness-policy-editor {}`が失敗した: {text}",
            args.join(" ")
        ))
    }
}

/// `harness fs revoke <path>`（名前の付いた扉）。**結果は返すだけで判定しない**——準備と後片付けで
/// 使い、「剥がすものが無かった」（非0で返る）も起こり得るので、呼ぶ側が出力を見せる。
fn harness_fs_revoke(path: &str) -> String {
    match Command::new(harness_exe())
        .args(["fs", "revoke", path])
        .output()
    {
        Ok(out) => format!(
            "`harness fs revoke {path}` -> {}\n{}{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
        Err(e) => format!("`harness fs revoke {path}`を起動できない: {e}"),
    }
}

/// パス2を1回撃つ（親の`run_record_net_with`）。標準出力と標準エラーをつないで返す。
fn run_pass2() -> (bool, String, String) {
    let command = format!("Write-Output '{PASS2_MARKER}'");
    let out = super::run_record_net_with(&workspace(), RECORDED_DOMAIN, &command, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    eprintln!("--- パス2 stdout ---\n{stdout}\n--- パス2 stderr ---\n{stderr}");
    (out.status.success(), stdout, stderr)
}

/// パス2が「使用中なので見送った」と言った件数（`record_net.rs`の警告。言っていなければ`None`）。
fn deferred_count(stderr: &str) -> Option<usize> {
    stderr.lines().find_map(|line| {
        if !line.contains("このワークスペースは使用中なので") {
            return None;
        }
        let rest = line.split("もう宣言されていない許可が").nth(1)?;
        rest.split('件').next()?.trim().parse().ok()
    })
}

/// パス2の撤収の行（`  撤収 i/n: <パス>`）に、`dir`の名前が出たか。
fn pass2_revoked(stderr: &str, dir: &str) -> bool {
    let name = Path::new(dir)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    stderr
        .lines()
        .filter(|l| l.trim_start().starts_with("撤収 "))
        .any(|l| l.to_ascii_lowercase().contains(&name))
}

/// 試験の中で動かしておく`harness.exe`。**`Drop`で必ず手放す**——試験が途中で落ちても、
/// 待たせたままの`harness.exe`がワークスペースの印を持ち続けないようにする（台本の側にも10分の期限がある）。
struct RunningHarness {
    child: Option<Child>,
    release_flag: PathBuf,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl RunningHarness {
    /// 手放して、終了を待つ。戻り値は（成功したか, 標準出力, 標準エラー）。
    fn release_and_wait(&mut self, limit: Duration) -> (bool, String, String) {
        let _ = std::fs::write(&self.release_flag, "go");
        let mut success = false;
        if let Some(mut child) = self.child.take() {
            let started = Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        success = status.success();
                        break;
                    }
                    Ok(None) if started.elapsed() < limit => {
                        std::thread::sleep(Duration::from_millis(250))
                    }
                    _ => {
                        let _ = child.kill();
                        let _ = child.wait();
                        eprintln!("[harness-grants] harness.exeが期限内に終わらなかったので止めた");
                        break;
                    }
                }
            }
        }
        (
            success,
            std::fs::read_to_string(&self.stdout_path).unwrap_or_default(),
            std::fs::read_to_string(&self.stderr_path).unwrap_or_default(),
        )
    }
}

impl Drop for RunningHarness {
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = self.release_and_wait(Duration::from_secs(60));
        }
    }
}

/// ワークスペースの中に印のファイルを書いてから、手放しの印が置かれるまで待つ台本。
fn waiting_script(ready: &Path, release: &Path) -> String {
    let ready = ready.display();
    let release = release.display();
    format!(
        "Set-Content -LiteralPath '{ready}' -Value 'ready'; \
         $deadline = (Get-Date).AddMinutes(10); \
         while ((-not (Test-Path -LiteralPath '{release}')) -and ((Get-Date) -lt $deadline)) \
         {{ Start-Sleep -Milliseconds 250 }}; \
         if (Test-Path -LiteralPath '{release}') {{ Write-Output 'WAITING_SCRIPT_RELEASED' }} \
         else {{ Write-Output 'WAITING_SCRIPT_TIMED_OUT' }}"
    )
}

/// `--provider mock`の台本（`run_shell`を1回呼んで終わる）。形は`harness_core`の型で組む
/// ——手書きのJSONにすると、型が変わった日に台本だけが古い形で残る。
fn mock_turns(script: &str) -> Vec<Vec<StreamEvent>> {
    let input = serde_json::json!({ "command": script, "timeout_ms": 660_000 });
    vec![
        vec![
            StreamEvent::BlockStart {
                index: 0,
                kind: BlockKind::ToolUse {
                    id: "call_1".to_string(),
                    name: "run_shell".to_string(),
                },
            },
            StreamEvent::ToolInputDelta {
                index: 0,
                json_fragment: input.to_string(),
            },
            StreamEvent::BlockStop { index: 0 },
            StreamEvent::Done {
                stop_reason: StopReason::ToolUse,
                usage: Usage::default(),
            },
        ],
        vec![
            StreamEvent::BlockStart {
                index: 0,
                kind: BlockKind::Text,
            },
            StreamEvent::TextDelta {
                index: 0,
                text: "done".to_string(),
            },
            StreamEvent::BlockStop { index: 0 },
            StreamEvent::Done {
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            },
        ],
    ]
}

/// `harness.exe`を`--fs-allow F`つきのTier2aで起こし、台本の子がワークスペースへ印を書くまで待つ。
fn start_waiting_harness() -> Result<RunningHarness, String> {
    let exe = harness_exe();
    // **`e2e-mock`付きでビルドされているか**を先に見る（無いと`--mock-turns`が引数エラーで落ち、
    // 「harnessが起動しなかった」としか読めない）。
    let help = Command::new(&exe)
        .arg("--help")
        .output()
        .map_err(|e| format!("{}を起動できない: {e}", exe.display()))?;
    if !String::from_utf8_lossy(&help.stdout).contains("--mock-turns") {
        return Err(format!(
            "{}が`e2e-mock`無しでビルドされている（`--mock-turns`が無い）。同じリポジトリで\
             `cargo build --workspace`の後に`cargo build -p harness-cli --features e2e-mock`を撃ってから、\
             もう一度`dev-elevated-run.exe {KEEP_KEY}`を撃つこと",
            exe.display()
        ));
    }

    let ws = workspace();
    let ready = ws.join("harness-ready.flag");
    let release = ws.join("harness-release.flag");
    let scratch = PathBuf::from(SCRATCH);
    std::fs::create_dir_all(&scratch).map_err(|e| format!("スクラッチを作れない: {e}"))?;
    let turns_path = scratch.join("editor-keeps-harness-turns.json");
    let stdout_path = scratch.join("editor-keeps-harness-stdout.json");
    let stderr_path = scratch.join("editor-keeps-harness-stderr.txt");
    let script = waiting_script(&ready, &release);
    std::fs::write(
        &turns_path,
        serde_json::to_string(&mock_turns(&script)).expect("serialize the mock turns"),
    )
    .map_err(|e| format!("台本を書けない: {e}"))?;
    let stdout_file =
        std::fs::File::create(&stdout_path).map_err(|e| format!("出力先を作れない: {e}"))?;
    let stderr_file =
        std::fs::File::create(&stderr_path).map_err(|e| format!("出力先を作れない: {e}"))?;

    let fs_allow = format!(r"{FS_ALLOW}\**");
    let rule = format!("run_shell:{script}");
    let child = Command::new(&exe)
        .args([
            "--provider",
            "mock",
            "--mock-turns",
            &turns_path.to_string_lossy(),
            "--cwd",
            WORKSPACE,
            "--permission-mode",
            "accept-all",
            "--dangerously-allow",
            "--output-format",
            "json",
            "-p",
            "(scripted; prompt text is ignored by the mock provider)",
            "--allow",
            &rule,
            "--sandbox",
            "tier2a",
            "--fs-allow",
            &fs_allow,
        ])
        // 開発ビルドの昇格ヘルパーの逃がし弁（D-44）と、記憶の置き場の逃がし口（`e2e-mock`のときだけ効く）。
        .env("HARNESS_ALLOW_USER_WRITABLE_ELEVATED_HELPERS", "1")
        .env(
            "HARNESS_TEST_RECALL_DATA_ROOT",
            scratch.join("editor-keeps-harness-recall"),
        )
        .stdin(Stdio::null())
        .stdout(stdout_file)
        .stderr(stderr_file)
        .spawn()
        .map_err(|e| format!("{}を起動できない: {e}", exe.display()))?;
    let mut running = RunningHarness {
        child: Some(child),
        release_flag: release,
        stdout_path,
        stderr_path,
    };

    let started = Instant::now();
    while !ready.exists() {
        let exited = running
            .child
            .as_mut()
            .and_then(|c| c.try_wait().ok().flatten())
            .is_some();
        if exited || started.elapsed() > Duration::from_secs(300) {
            let (_, out, err) = running.release_and_wait(Duration::from_secs(5));
            return Err(format!(
                "harness.exeの台本の子が待ち状態に入らなかった（{}）。stdout:\n{out}\nstderr:\n{err}",
                if exited { "先に終了した" } else { "300秒待っても印が無い" }
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Ok(running)
}

/// 前の回の残りを**製品の取り消し**で消す（承認台帳の`revoke`と`harness fs revoke`）。
///
/// `harness fs revoke`は**置き場が在るうちに**撃つ——在ればACEが無いことを実DACLで確かめてから
/// capability台帳の記録を落とすが、無いと「消えた」と言えずに記録を残す
/// （`forget_revoked_declarations`）。残ると、次のパス2が取り消し候補として数え、見送った件数がずれる。
fn reset_leftovers(ws: &Path) {
    let values = [declared_value(DECLARED), declared_value(STALE)];
    let left = PolicyApprovalStore::in_config_dir().revoke(
        ws,
        &[entry_declaration(&values[0]), entry_declaration(&values[1])],
    );
    assert!(
        left.is_empty(),
        "前の回の承認を承認台帳から消せなかった: {left:?}"
    );
    for dir in [DECLARED, FS_ALLOW, STALE] {
        let _ = std::fs::create_dir_all(dir);
        eprintln!(
            "[harness-grants] 前の回の残りの掃除: {}",
            harness_fs_revoke(dir)
        );
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap_or_else(|e| panic!("置き場を作れない（{dir}）: {e}"));
        std::fs::write(Path::new(dir).join("f.txt"), "x")
            .unwrap_or_else(|e| panic!("置き場へ書けない（{dir}）: {e}"));
    }
}

/// `policy.json`を書く: 入口ドメインにAとSの宣言、パス2で記録するドメイン（ファイル宣言なし）。
fn write_policy(ws: &Path) {
    let mut file = PolicyFile::default();
    let mut entry = PolicyDomain::new(ENTRY_DOMAIN);
    entry.fs.read_exec.push(declared_value(DECLARED));
    entry.fs.read_exec.push(declared_value(STALE));
    file.domains.push(entry);
    let mut recorded = PolicyDomain::new(RECORDED_DOMAIN);
    recorded
        .commands
        .push(format!("Write-Output '{PASS2_MARKER}'"));
    recorded.cwd = Some(ws.to_path_buf());
    file.domains.push(recorded);
    harness_policy::policy_file::save(ws, &file)
        .unwrap_or_else(|e| panic!("policy.jsonを書けない: {e}"));
    harness_policy::policy_file::load(ws)
        .unwrap_or_else(|e| panic!("書いたpolicy.jsonが読み込みで拒否された: {e}"));
}

/// [4点目・付与側] **`harness.exe`が動いている間のパス2は、`harness.exe`が付けた許可を1つも取り消さない。**
///
/// 手順: 承認（`approve-declared`）→ `harness.exe`を待たせる → 3つの置き場にACEが付いたことを確かめる →
/// **動いている間に**Sの宣言と承認を外す（`unapprove`）→ パス2 → 3つとも残ることと、見送った件数が
/// 2（SとF）であることを確かめる → `harness.exe`を手放す。ACEと承認は残して終わる（撤収のキーが使う）。
#[test]
#[ignore = "starts harness.exe (e2e-mock build) and a pass-2 recording in the same workspace; run through dev-elevated-run e2e-policy-editor-keeps-harness-grants"]
fn keep_harness_grants_while_harness_runs_in_the_same_workspace() {
    require_elevated(KEEP_KEY);
    let ws = workspace();
    let _ = std::fs::remove_dir_all(&ws);
    std::fs::create_dir_all(&ws).expect("create the workspace");
    reset_leftovers(&ws);
    for dir in [DECLARED, FS_ALLOW, STALE] {
        assert_eq!(
            capability_aces(dir),
            0,
            "前提: 作り直した{dir}にcapability SID宛のACEが載っている"
        );
    }
    write_policy(&ws);
    let ws_arg = ws.to_string_lossy().to_string();
    let approved = editor(&[
        "approve-declared",
        "--domain",
        ENTRY_DOMAIN,
        "--workspace",
        &ws_arg,
        "--fs",
        &declared_value(DECLARED),
        "--fs",
        &declared_value(STALE),
        "--access",
        "read_exec",
        "--yes",
    ])
    .unwrap_or_else(|e| panic!("{e}"));
    eprintln!("[harness-grants] approve-declared:\n{approved}");

    let mut failures: Vec<String> = Vec::new();
    let mut harness = start_waiting_harness().unwrap_or_else(|e| panic!("{e}"));

    // --- harness.exeが付けたもの（前提） ---
    for dir in [DECLARED, FS_ALLOW, STALE] {
        let n = capability_aces(dir);
        if n != 1 {
            failures.push(format!(
                "前提: harness.exeの起動後に{dir}のcapability SID宛のACEが{n}本（1本のはず）。\
                 harness.exeが付けていないなら、この後の「残った」は何の証拠にもならない"
            ));
        }
    }

    // --- 動いている間に、Sをどこからも外す（製品の取り消し） ---
    let unapproved = editor(&[
        "unapprove",
        "--domain",
        ENTRY_DOMAIN,
        "--workspace",
        &ws_arg,
        "--fs",
        &declared_value(STALE),
        "--access",
        "read_exec",
        "--yes",
    ]);
    match &unapproved {
        Ok(text) => eprintln!("[harness-grants] unapprove:\n{text}"),
        Err(e) => failures.push(e.clone()),
    }
    let policy =
        std::fs::read_to_string(harness_policy::policy_file::path(&ws)).unwrap_or_default();
    if policy.contains(&declared_value(STALE)) {
        failures.push(format!(
            "前提: `unapprove`の後も`policy.json`にSの宣言が残っている: {policy}"
        ));
    }
    if PolicyApprovalStore::in_config_dir()
        .load()
        .is_approved(&ws, entry_declaration(&declared_value(STALE)))
    {
        failures.push("前提: `unapprove`の後も承認台帳にSの承認が残っている".to_string());
    }

    // --- harness.exeが動いている間のパス2 ---
    let (ok, stdout, stderr) = run_pass2();
    if !ok {
        failures.push("パス2が失敗した（上の出力）".to_string());
    }
    if !stderr.contains("Tier2aへ着地しました") || !stdout.contains(PASS2_MARKER) {
        failures.push("パス2がTier2aでコマンドを走らせていない（上の出力）".to_string());
    }
    // 取り消し候補の母集団（このワークスペースが宛先を発行したパスの全部）を、件数の照合の材料として残す。
    let held = harness_sandbox::tier2a::workspace_capability::declared_paths_for_workspace(
        &ws.canonicalize().unwrap_or_else(|_| ws.clone()),
    );
    eprintln!("[harness-grants] このワークスペースが宛先を発行したパス: {held:?}");
    match deferred_count(&stderr) {
        Some(DEFERRED_WHILE_RUNNING) => {}
        Some(n) => failures.push(format!(
            "パス2が見送った件数が{n}件（SとFの{DEFERRED_WHILE_RUNNING}件のはず）。Aを数えているなら残す集合が効いていない、\
             少ないならSかFを取り消し候補として見ていない。宛先を発行したパス: {held:?}"
        )),
        None => failures.push(
            "パス2が「使用中なので取り消しを見送った」と言っていない——harness.exeが動いているのに\
             生存判定が効いていないか、取り消し候補が空だった"
                .to_string(),
        ),
    }
    for dir in [DECLARED, FS_ALLOW, STALE] {
        let n = capability_aces(dir);
        if n != 1 {
            failures.push(format!(
                "**harness.exeが動いている間のパス2で、{dir}のACEが{n}本になった**（1本のまま残るはず。BUG-184）"
            ));
        }
    }

    // --- harness.exeを手放す（台本の子が最後まで走ったことも見る） ---
    let (exited_ok, harness_out, harness_err) = harness.release_and_wait(Duration::from_secs(120));
    let result = serde_json::from_str::<serde_json::Value>(harness_out.trim())
        .ok()
        .and_then(|v| v["tool_calls"][0]["result"].as_str().map(str::to_string))
        .unwrap_or_default();
    if !exited_ok || !result.contains("WAITING_SCRIPT_RELEASED") {
        failures.push(format!(
            "harness.exeが正常に終わっていない、または台本の子が手放しの印を見ていない\
             （終了={exited_ok}、子の結果={result:?}）。stderr:\n{harness_err}"
        ));
    }

    assert!(
        failures.is_empty(),
        "{}件の問題:\n- {}",
        failures.len(),
        failures.join("\n- ")
    );
    eprintln!(
        "[harness-grants] **状態を残した**: {DECLARED}・{FS_ALLOW}・{STALE}のACE、Aの承認、ワークスペース{WORKSPACE}。\
         確認: (Get-Acl <置き場>).Access | ? IdentityReference -like 'S-1-15-3-*'／\
         続き: dev-elevated-run.exe {REVOKE_KEY}"
    );
}

/// [4点目・撤収側] **`harness.exe`が動いていないときのパス2は、どこからも外れた宣言（S）だけを取り消し、
/// 承認済みの宣言（A）は残す。**
///
/// Fは取り消される——`--fs-allow`の許可はエディタが出どころを区別できないので残す集合に入らない
/// （BUG-184の限界(1)）。**ここは見張りとして書いてある**: 限界が直れば赤くなるので、そのときは
/// assertを「残る」へ反転させ、BUG-184とSTATUS #71の限界の記述を直すこと。
///
/// 前提（付与側が残したもの）を先に確かめる——無いまま撃つと、どの置き場も「0本」で緑になる（`B-09`）。
#[test]
#[ignore = "runs pass 2 after e2e-policy-editor-keeps-harness-grants and cleans up with the product's revoke; run through dev-elevated-run e2e-policy-editor-revokes-stale-grants"]
fn revoke_only_the_undeclared_grants_once_harness_has_exited() {
    require_elevated(REVOKE_KEY);
    let ws = workspace();
    let ws_canon = ws.canonicalize().unwrap_or_else(|_| ws.clone());

    // --- 前提 ---
    let mut missing: Vec<String> = Vec::new();
    let policy =
        std::fs::read_to_string(harness_policy::policy_file::path(&ws)).unwrap_or_default();
    if !policy.contains(&declared_value(DECLARED)) || policy.contains(&declared_value(STALE)) {
        missing.push(format!(
            "`policy.json`がAを宣言しSを宣言しない形になっていない: {policy}"
        ));
    }
    let approvals = PolicyApprovalStore::in_config_dir().load();
    if !approvals.is_approved(&ws, entry_declaration(&declared_value(DECLARED))) {
        missing.push("Aの承認が無い".to_string());
    }
    if approvals.is_approved(&ws, entry_declaration(&declared_value(STALE))) {
        missing.push("Sの承認が残っている".to_string());
    }
    for dir in [DECLARED, FS_ALLOW, STALE] {
        if !Path::new(dir).is_dir() || capability_aces(dir) != 1 {
            missing.push(format!(
                "{dir}にcapability SID宛のACEがちょうど1本載っていない"
            ));
        }
    }
    let live = harness_sandbox::tier2a::workspace_ledger::live_modes(&ws_canon);
    if !live.is_empty() {
        missing.push(format!(
            "ワークスペースがまだ使用中（モード: {}）——harness.exeかエディタが動いている",
            live.join(", ")
        ));
    }
    assert!(
        missing.is_empty(),
        "撤収側の前提が無い——**先に`dev-elevated-run.exe {KEEP_KEY}`を撃ち、緑を確かめてから**撃つこと:\n- {}",
        missing.join("\n- ")
    );

    // --- harness.exeが動いていないときのパス2 ---
    let (ok, stdout, stderr) = run_pass2();
    let mut failures: Vec<String> = Vec::new();
    if !ok || !stderr.contains("Tier2aへ着地しました") || !stdout.contains(PASS2_MARKER) {
        failures.push("パス2がTier2aでコマンドを走らせていない（上の出力）".to_string());
    }
    if let Some(n) = deferred_count(&stderr) {
        failures.push(format!(
            "誰も動いていないのに、パス2が「使用中なので{n}件見送った」と言っている"
        ));
    }
    // 禁止側: Sは取り消される（実DACL・パス2の撤収の行・capability台帳の3つで見る）。
    if capability_aces(STALE) != 0 {
        failures.push(format!(
            "**どこからも外れた宣言（{STALE}）のACEが残っている**——開始時の取り消しが効いていない"
        ));
    }
    if !pass2_revoked(&stderr, STALE) {
        failures.push(format!("パス2の撤収の行に{STALE}が出ていない"));
    }
    if minted_for(STALE) != 0 {
        failures.push(format!(
            "capability台帳に{STALE}宛の宣言の宛先が残っている（ACEは消えたのに索引が残る、BUG-142の形）"
        ));
    }
    // 許可側: Aは残る（残す集合＝承認済みの宣言）。
    if capability_aces(DECLARED) != 1 {
        failures.push(format!(
            "**承認済みの宣言（{DECLARED}）のACEが取り消された**——残す集合が`policy.json`の承認済み宣言を\
             数えていない（BUG-184の層2）"
        ));
    }
    if pass2_revoked(&stderr, DECLARED) {
        failures.push(format!("パス2の撤収の行に{DECLARED}が出ている"));
    }
    // 見張り: Fは今は取り消される（BUG-184の限界(1)）。
    if capability_aces(FS_ALLOW) != 0 {
        failures.push(format!(
            "{FS_ALLOW}（`--fs-allow`）のACEが残っている。**BUG-184の限界(1)が直った合図かもしれない**——\
             直したのなら、このassertを「残る」へ反転させ、docs/bugs/BUG-184.mdとdocs/STATUS.md #71の\
             限界の記述を直すこと。直していないなら、パス2の取り消しが`--fs-allow`の宛先を候補に入れていない"
        ));
    }

    if failures.is_empty() {
        // 後片付けは**製品の取り消し**で行う（`B-27`）: Aの宣言と承認を外し、3つとも名前の付いた扉で剥がす。
        let ws_arg = ws.to_string_lossy().to_string();
        if let Err(e) = editor(&[
            "unapprove",
            "--domain",
            ENTRY_DOMAIN,
            "--workspace",
            &ws_arg,
            "--fs",
            &declared_value(DECLARED),
            "--access",
            "read_exec",
            "--yes",
        ]) {
            eprintln!("[harness-grants] 後片付け: {e}");
        }
        for dir in [DECLARED, FS_ALLOW, STALE] {
            eprintln!("[harness-grants] 後片付け: {}", harness_fs_revoke(dir));
        }
        let leftover: Vec<&str> = [DECLARED, FS_ALLOW, STALE]
            .into_iter()
            .filter(|dir| capability_aces(dir) != 0)
            .collect();
        if leftover.is_empty() {
            for dir in [DECLARED, FS_ALLOW, STALE] {
                let _ = std::fs::remove_dir_all(dir);
            }
            let _ = std::fs::remove_dir_all(&ws);
            let scratch = PathBuf::from(SCRATCH);
            for name in [
                "editor-keeps-harness-turns.json",
                "editor-keeps-harness-stdout.json",
                "editor-keeps-harness-stderr.txt",
            ] {
                let _ = std::fs::remove_file(scratch.join(name));
            }
            let _ = std::fs::remove_dir_all(scratch.join("editor-keeps-harness-recall"));
        } else {
            failures.push(format!(
                "後片付け: `harness fs revoke`の後もcapability SID宛のACEが残っている: {leftover:?}"
            ));
        }
    } else {
        eprintln!(
            "[harness-grants] 失敗したので状態を残した。手で消すなら（昇格して）`harness fs revoke`を\
             {DECLARED}・{FS_ALLOW}・{STALE}へ撃ち、`harness-policy-editor unapprove --domain {ENTRY_DOMAIN} \
             --workspace {WORKSPACE} --all --yes`で承認を外す"
        );
    }
    assert!(
        failures.is_empty(),
        "{}件の問題:\n- {}",
        failures.len(),
        failures.join("\n- ")
    );
}
