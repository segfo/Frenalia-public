//! [決定69] ドメインごとの通信の昇格E2E。**`policy.json`の承認済みの`net`宣言が、そのドメインの子だけに
//! 効くか**を本番の経路（`harness.exe --sandbox tier2a --enforce-transitions`）で確かめる
//! （`plans/position-domains/P7.md`の Task P7.8）。**管理者権限が要る**（WFP の出口強制と Tier2a の準備）。
//!
//! 実行: `dev-elevated-run.exe e2e-policy-editor-domain-net`。事前に`cargo build --workspace`と
//! `cargo build -p harness-cli --features e2e-mock`（部品は[`common`]）。**外部への到達性が要る**
//! （`example.com`の HTTP と`github.com`の22番）。届かなければ判定不能として落ちる。
//!
//! # 何を測るのか
//!
//! 決定69 で、通信を宣言したドメインには**専用の中継プロキシ・`internetClient`・WFP の項目**が付くように
//! なった。効いているなら、次が**同時に**成り立つ——(1) そのドメインの子は**自分の**宛先へ届く、
//! (2) 同じ子は**他のドメインの**宛先へ届かない、(3) 宣言していないドメインの子は宛先を1つも知らず届かない、
//! (4) あるドメインの子は**他のドメインのプロキシのポート**へ届かない（WFP の既定拒否が層として効いている）。
//!
//! # 腕（`B-35`: 通る側と断る側、測りたい差だけを変えた対照を同じ回で）
//!
//! | 腕 | 行 | 期待 |
//! |---|---|---|
//! | ① 外の対照 | 試験のプロセスから`example.com`の HTTP と`github.com:22` | 届く（届かなければ以降は判定不能） |
//! | ② 子が自分の宛先へ／他のドメインの宛先へ | 入口 → powershell が`example.com`と`other.example.net`を順に取る | 前者は 200、後者は失敗。子の`HTTP_PROXY`は**入口と違うポート** |
//! | ③ 入口の対照 | 入口が`example.com`を取る（`--net-allow-domain example.com`） | 200（入口の出口は別の宛先で動いている） |
//! | ④ 他のドメインのプロキシへ直に | 入口が自分のポートを引数で渡し、powershell がそこへ TCP で繋ぐ | 繋がらない（WFP の既定拒否。`e2e-mcp`の`other=False`の写し） |
//! | ⑤ 宣言しないドメイン | 入口 → cmd が`%HTTP_PROXY%`を出し、`example.com`を取る | 宛先は**空**・取得は失敗 |
//! | ⑥ ssh | 入口 → ssh →`connect.exe`（`net`に`github.com`）で`ssh -T git@github.com` | 22番へ届いた証拠（`Permission denied (publickey)`）と、監査に`github.com:22`の許可の行 |
//! | ⑦ 層の切り分け | 監査（`net-audit.jsonl`）の行の**ドメインの印** | ②の許可と拒否、⑥の許可が**それぞれのドメインの印**で出る |
//!
//! # 宣言はこの試験が直接書く（限界）
//!
//! `policy.json`は製品の型と`save`で書き、承認は製品の台帳（D-112・決定69(2)）へ直接記録する——
//! **測りたいのは強制の振る舞い**で、エディタの画面から承認する経路は`widening_transitions_e2e.rs`と
//! 単体試験が見ている。後始末で承認を消す（`B-01`の対）。
//!
//! # 言えないこと
//!
//! - **ポートでは絞っていない**（中継プロキシは CONNECT の宛先のホスト名だけを見る）。`github.com`を許した
//!   ドメインは`github.com`のどのポートへも CONNECT できる。
//! - 生のソケット（プロキシを通らない接続）は④でしか測っていない（`8.8.8.8:53`のような外部の直接接続は
//!   `e2e-mcp`が測っている）。
//! - ssh の鍵は使わない（公開鍵の認証は通らなくてよい。**22番へ届いたこと**が測りたいものである）。
//!
//! # ワークスペースの置き場
//!
//! `C:\harness-e2e\policy-editor-domain-net`（`%TEMP%`の外。`%TEMP%`配下は候補にしない規則＝BUG-103）。
//! 緑なら消し、赤なら調査のため残す。

#![cfg(windows)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use harness_policy::policy_file::{self, PolicyDomain, PolicyFile, ENTRY_DOMAIN};
use harness_policy::transition::{editor_edge, AnyMarker, ArgvMatcher};

use common::{
    case_dir, file_name, harness_exe, middle_shell, run_arm_with, scratch_dir, system32,
    Arm, MiddleShell, Script,
};

const CASE: &str = "policy-editor-domain-net";
/// 子のドメインが宣言する宛先（②の許可側）。
const CHILD_HOST: &str = "example.com";
/// **別のドメインだけが宣言する宛先**（②の禁止側。子のプロキシは許可に持たない）。
const OTHER_HOST: &str = "other.example.net";
/// ssh のドメインが宣言する宛先（⑥）。
const SSH_HOST: &str = "github.com";
/// 出力を捨てる子と同じく葉として使う`cmd.exe`（⑤。通信を宣言しないドメイン）。
const CMD_EXE: &str = "cmd.exe";
const CMD_DOMAIN: &str = "cmd";
/// ssh とその`ProxyCommand`のドメインの名前（位置の鍵は（親のドメイン, 実行ファイル）なので葉名になる）。
const SSH_DOMAIN: &str = "ssh";
const CONNECT_DOMAIN: &str = "connect";
/// 入口が自分の中継プロキシのポートを子へ渡す環境変数（`harness`が所有する名前ではないので届く）。
const ENTRY_PORT_ENV: &str = "HARNESS_TEST_ENTRY_PROXY_PORT";

fn ssh_exe() -> String {
    format!("{}\\System32\\OpenSSH\\ssh.exe", common::system_root())
}

/// Git for Windows 付属の中継の道具（`HTTP_PROXY`を読んで CONNECT する）。
fn connect_exe() -> PathBuf {
    PathBuf::from(r"C:\Program Files\Git\mingw64\bin\connect.exe")
}


#[test]
#[ignore = "requires administrator rights (WFP netfilterd) and outbound network access (example.com, github.com:22); run through dev-elevated-run"]
fn each_domain_reaches_only_its_own_destinations_through_its_own_proxy() {
    let harness = harness_exe();
    let shell = middle_shell();
    let ws = case_dir(CASE);
    std::fs::create_dir_all(ws.join(".harness").join("sandbox")).unwrap();
    let mut failures: Vec<String> = Vec::new();

    // ① 外の対照。ここが届かないと、以降の「届かない」が何のせいか言えない。
    if let Err(reason) = http_reachable(CHILD_HOST) {
        panic!("判定不能: サンドボックスの外から {CHILD_HOST} へ届かない（{reason}）");
    }
    let ssh_outside = ssh_probe_outside();
    eprintln!("[domain-net] ① 外から ssh -T git@{SSH_HOST}: {ssh_outside:?}");

    write_policy(&ws, &shell);
    let approved = approve_net(&ws);
    assert!(
        approved,
        "通信の宣言を台帳へ記録できない（この試験は強制を測れない）"
    );

    // ② 子は自分の宛先へ届き、他のドメインの宛先へは届かない（許可側と禁止側を同じ回で）。
    let own_and_other = Script {
        name: "2-child-own-and-other",
        line: format!(
            "{}; {}",
            net_probe("ENTRY", CHILD_HOST),
            common::ps_run(
                &shell,
                &format!(
                    "{}; {}",
                    net_probe("CHILD", CHILD_HOST),
                    net_probe("CHILDOTHER", OTHER_HOST)
                )
            )
        ),
    };
    let arm = run_arm_with(
        &harness,
        &ws,
        CASE,
        &own_and_other,
        &["--net-allow-domain", CHILD_HOST],
    );
    arm.print(own_and_other.name);
    // ③ 入口の対照（同じ回・同じ書き方）。
    if !arm.result.contains("ENTRY:NET_OK 200") {
        failures.push(format!(
            "{}: 判定不能——入口のシェルが同じ回に {CHILD_HOST} へ届いていない。本文:\n{}",
            own_and_other.name, arm.result
        ));
    }
    if !arm.result.contains("CHILD:NET_OK 200") {
        failures.push(format!(
            "{}: **子（{}）が自分のドメインの宛先 {CHILD_HOST} へ届いていない。** 専用の中継プロキシか \
             internetClient か WFP の項目のどれかが付いていない。本文:\n{}",
            own_and_other.name, shell.domain, arm.result
        ));
    }
    if arm.result.contains("CHILDOTHER:NET_OK") {
        failures.push(format!(
            "{}: **子が他のドメインだけが宣言した宛先 {OTHER_HOST} へ届いた。** 宛先を絞ったつもりで \
             絞れていない。本文:\n{}",
            own_and_other.name, arm.result
        ));
    }
    let (entry_proxy, child_proxy) = (proxy_of(&arm, "ENTRY"), proxy_of(&arm, "CHILD"));
    eprintln!("[domain-net] 入口の HTTP_PROXY={entry_proxy:?}／子の HTTP_PROXY={child_proxy:?}");
    match (&entry_proxy, &child_proxy) {
        (Some(entry), Some(child)) if !entry.is_empty() && !child.is_empty() && entry != child => {}
        _ => failures.push(format!(
            "{}: 子が**自分のドメインの**中継プロキシを渡されていない（入口 {entry_proxy:?}／子 \
             {child_proxy:?}）——同じなら入口の出口を使っている",
            own_and_other.name
        )),
    }

    // ④ 子から入口のプロキシのポートへ直に繋ぐ（WFP の既定拒否が層として効いているか）。
    // 入口が自分のプロキシのポートを**環境変数へ入れて**子へ渡す（`harness`が所有する名前ではないので
    // 子へそのまま届く）。1回目の実測では`$args`で渡そうとして届かず、**ポート0へ繋いでいた**
    // ——「繋がらなかった」ではなく「測れていなかった」（計器の失敗）。
    let child_probe = format!(
        "Write-Output ('CHILDSEES=' + $env:{ENTRY_PORT_ENV}); \
         try {{ $c = [Net.Sockets.TcpClient]::new(); \
         $c.Connect('127.0.0.1', [int]$env:{ENTRY_PORT_ENV}); $c.Close(); \
         Write-Output ('PORT_' + 'OK') }} \
         catch {{ Write-Output ('PORT_' + 'FAIL ' + $_.Exception.Message) }}"
    );
    let other_port = Script {
        name: "4-child-to-the-entry-proxy-port",
        line: format!(
            "$env:{ENTRY_PORT_ENV} = ($env:HTTP_PROXY -split ':')[-1]; \
             Write-Output ('ENTRYPORT=' + $env:{ENTRY_PORT_ENV}); {}",
            common::ps_run(&shell, &child_probe)
        ),
    };
    let arm = run_arm_with(
        &harness,
        &ws,
        CASE,
        &other_port,
        &["--net-allow-domain", CHILD_HOST],
    );
    arm.print(other_port.name);
    if arm.result.contains("PORT_OK") {
        failures.push(format!(
            "{}: **子が入口の中継プロキシのポートへ直に繋げた。** WFP の既定拒否がそのドメインに効いて \
             いない（`e2e-mcp`の other=False が崩れた形）。本文:\n{}",
            other_port.name, arm.result
        ));
    }
    if !arm.result.contains("PORT_FAIL") {
        failures.push(format!(
            "{}: 子が接続を試した印が無い（子が走っていない）。本文:\n{}",
            other_port.name, arm.result
        ));
    }
    // **計器の確認**: 子が入口のポートを受け取っていなければ、何へ繋いだのかが言えない
    // （1回目の実測ではポート0へ繋いでいた）。
    let entry_port = line_after(&arm, "ENTRYPORT=");
    let child_sees = line_after(&arm, "CHILDSEES=");
    match (&entry_port, &child_sees) {
        (Some(entry), Some(child)) if !entry.is_empty() && entry == child => {}
        _ => failures.push(format!(
            "{}: 判定不能——子が入口のプロキシのポートを受け取っていない（入口 {entry_port:?}／子 \
             {child_sees:?}）。繋がらなかったのが「そのポートへ繋げない」からだと言えない",
            other_port.name
        )),
    }

    // ⑤ 通信を宣言しないドメイン（cmd）は宛先を1つも知らず、届かない。
    let quiet = Script {
        name: "5-domain-without-declarations",
        line: format!(
            "& '{}' /d /c \"echo PROXY=[%HTTP_PROXY%] & curl.exe -sS -o NUL -w CURL=%%{{http_code}} http://{CHILD_HOST}/ 2>&1\"",
            system32(CMD_EXE)
        ),
    };
    let arm = run_arm_with(&harness, &ws, CASE, &quiet, &["--net-allow-domain", CHILD_HOST]);
    arm.print(quiet.name);
    // **`cmd.exe`は未定義の変数を展開せず、`%HTTP_PROXY%`という綴りのまま印字する**
    // （空文字になるのではない）。1回目の実測でここを`PROXY=[]`と期待して赤くなった——
    // 計器の読み方の誤りで、**綴りが残っていることが「定義されていない」の証拠**である。
    if !arm.result.contains("PROXY=[%HTTP_PROXY%]") {
        failures.push(format!(
            "{}: **通信を宣言しないドメインの子が中継プロキシの宛先を知っている**（決定69 の前例の(6)で \
             消すはず）。本文:\n{}",
            quiet.name, arm.result
        ));
    }
    if arm.result.contains("CURL=200") {
        failures.push(format!(
            "{}: **通信を宣言しないドメインの子が外へ届いた。** 本文:\n{}",
            quiet.name, arm.result
        ));
    }

    // ⑥ 自分のドメインのプロキシが**22番への`CONNECT`**を通すか（決定69(3)）。
    //
    // **ssh 自身をサンドボックスの中で走らせることは今できない**（下の観測）。だから
    // ssh が`ProxyCommand`の道具にさせることと同じこと——中継プロキシへ`CONNECT <host>:22`を送り、
    // 返ってきたトンネルの向こうから SSH の名乗り（`SSH-2.0-...`）を読む——を子に直接やらせる。
    // **読んでいるのは「そのドメインのプロキシがホスト名で22番を通した」ことだけ**で、
    // **改行は`[char]13`/`[char]10`で組む**——PowerShell の単一引用符の中では`` `r`n ``が
    // 文字どおりのバッククォートになり、要求が終端しない（1回目の実測ではここで
    // プロキシが応答を返さず、読み取りが時間切れになった＝計器の失敗）。
    // **応答の頭は空行までまとめて捨てる**（`date`のような欄が付くので行数を決め打ちできない。
    // 2回目の実測では2行目を捨てて空行を名乗りとして読んでいた）。
    // **読み取りは30秒待つ**——中継プロキシは TLS の名乗りを5秒覗いてから中継を始めるので、
    // ssh のように**サーバが先に話す**プロトコルでは最初の1行がその分だけ遅れて来る。
    let connect_probe = format!(
        "$crlf = [string][char]13 + [string][char]10; \
         $p = ($env:HTTP_PROXY -split ':')[-1]; \
         try {{ $c = [Net.Sockets.TcpClient]::new('127.0.0.1', [int]$p); \
         $s = $c.GetStream(); $s.ReadTimeout = 30000; \
         $head = 'CONNECT {SSH_HOST}:22 HTTP/1.1' + $crlf + 'Host: {SSH_HOST}:22' + $crlf + $crlf; \
         $req = [Text.Encoding]::ASCII.GetBytes($head); \
         $s.Write($req, 0, $req.Length); $s.Flush(); \
         $r = [IO.StreamReader]::new($s); \
         Write-Output ('CONNECT=' + $r.ReadLine()); \
         while ($r.ReadLine() -ne [string]::Empty) {{ }} \
         Write-Output ('BANNER=' + $r.ReadLine()); $c.Close() }} \
         catch {{ Write-Output ('CONNECT=FAIL ' + $_.Exception.Message) }}"
    );
    let port22 = Script {
        name: "6-connect-to-port-22-through-its-own-proxy",
        line: common::ps_run(&shell, &connect_probe),
    };
    let arm = run_arm_with(&harness, &ws, CASE, &port22, &[]);
    arm.print(port22.name);
    let connect_line = line_after(&arm, "CONNECT=");
    let banner = line_after(&arm, "BANNER=");
    if !connect_line.as_deref().is_some_and(|l| l.contains("200")) {
        failures.push(format!(
            "{}: 自分のドメインのプロキシが {SSH_HOST} の22番への CONNECT を通さなかった（{connect_line:?}）。\
             外から同じ宛先へ ssh を撃った結果は {ssh_outside:?}。本文:\n{}",
            port22.name, arm.result
        ));
    }
    // **トンネルの向こうが本物の22番であること**の証拠（プロキシが 200 を返しただけでは、
    // 繋がった先が22番だとは言えない）。
    if !banner.as_deref().is_some_and(|b| b.contains("SSH-")) {
        failures.push(format!(
            "{}: CONNECT は通ったが、向こうから SSH の名乗りが来ない（{banner:?}）——22番へ繋がったと言えない",
            port22.name
        ));
    }

    // ⑥の観測（判定には使わない）: ssh 自身を中で走らせる。
    //
    // **2026-10-07 の実測では走らない**——`ssh.exe`は`ProxyCommand`と話すための無名パイプを
    // 作れずに `Could not create pipes to communicate with the proxy: Permission denied` で
    // 止まる（遷移の強制の下では子を自分で起こせないため）。**中継プロキシの側が22番を
    // 通せることは⑥で測れている**ので、ここは「ssh をそのまま使えるか」の観測として残す。
    if connect_exe().is_file() {
        let ssh = Script {
            name: "6-observation-ssh-itself",
            line: ssh_line(),
        };
        let arm = run_arm_with(&harness, &ws, CASE, &ssh, &[]);
        arm.print(ssh.name);
        let reached = arm.result.contains("Permission denied (publickey)");
        eprintln!(
            "[domain-net] ⑥の観測: サンドボックスの中の ssh は {}（外から撃った結果は {ssh_outside:?}）",
            if reached {
                "22番へ届いた"
            } else {
                "届かなかった——判定には使わない"
            }
        );
    } else {
        eprintln!(
            "[domain-net] ⑥の観測を撃っていない: 中継の道具が無い（{}）",
            connect_exe().display()
        );
    }

    // ⑦ 層の切り分け（監査の行のドメインの印）。
    let audit = all_net_audit(&ws);
    eprintln!("[domain-net] --- net-audit.jsonl（末尾40行）---");
    for line in audit.lines().rev().take(40).collect::<Vec<_>>().into_iter().rev() {
        eprintln!("{line}");
    }
    let events: Vec<serde_json::Value> = audit
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    let has = |domain: &str, host: &str, allowed: bool| {
        events.iter().any(|e| {
            e.get("domain").and_then(|v| v.as_str()) == Some(domain)
                && e.get("host").and_then(|v| v.as_str()) == Some(host)
                && e.get("allowed").and_then(|v| v.as_bool()) == Some(allowed)
        })
    };
    if !has(&shell.domain, CHILD_HOST, true) {
        failures.push(format!(
            "監査に「ドメイン {} が {CHILD_HOST} へ許可された」行が無い——どのプロキシが通したのか言えない",
            shell.domain
        ));
    }
    if !has(&shell.domain, OTHER_HOST, false) {
        failures.push(format!(
            "監査に「ドメイン {} が {OTHER_HOST} を断られた」行が無い——断ったのがそのドメインのプロキシだと言えない",
            shell.domain
        ));
    }
    if !has(&shell.domain, SSH_HOST, true) {
        failures.push(format!(
            "監査に「ドメイン {} が {SSH_HOST} へ許可された」行が無い——22番へ通したのがそのドメインの \
             プロキシだと言えない",
            shell.domain
        ));
    }

    // 後始末（製品の経路で承認を消す。`B-01`の対）。
    revoke_net(&ws);

    assert!(
        failures.is_empty(),
        "ドメインごとの通信の強制で{}件の問題（ワークスペース {} を調査のため残す）:\n- {}",
        failures.len(),
        ws.display(),
        failures.join("\n- ")
    );
    let _ = std::fs::remove_dir_all(&ws);
    let _ = std::fs::remove_dir_all(scratch_dir(CASE));
}

/// この試験の`policy.json`（辺とドメインごとの通信の宣言）。
fn write_policy(ws: &Path, shell: &MiddleShell) {
    let mut entry = PolicyDomain::new(ENTRY_DOMAIN);
    for exe in [shell.path.clone(), system32(CMD_EXE), ssh_exe()] {
        let to = match file_name(&exe).as_str() {
            CMD_EXE => CMD_DOMAIN.to_string(),
            name if name.eq_ignore_ascii_case("ssh.exe") => SSH_DOMAIN.to_string(),
            _ => shell.domain.clone(),
        };
        entry
            .process
            .transitions
            .push(editor_edge(&exe, ArgvMatcher::Any(AnyMarker), &to));
    }
    // 子のドメイン: 通信を宣言する（②の許可側）。
    let mut child = PolicyDomain::new(&shell.domain);
    // 22番の宛先もこのドメインが宣言する（⑥ の`CONNECT`を測るのはこのドメインのプロキシ）。
    child.net.allow_domains = vec![CHILD_HOST.to_string(), SSH_HOST.to_string()];
    // 通信を宣言しないドメイン（⑤）。
    let quiet = PolicyDomain::new(CMD_DOMAIN);
    // 別のドメインだけが宣言する宛先（②の禁止側の根拠）——このドメインへは誰も遷移しない。
    let mut other = PolicyDomain::new("other-net");
    other.net.allow_domains = vec![OTHER_HOST.to_string()];
    // ssh のドメイン: 自分は通信を宣言せず、`ProxyCommand`の道具へ遷移する（⑥）。
    let mut ssh = PolicyDomain::new(SSH_DOMAIN);
    ssh.process.transitions.push(editor_edge(
        &connect_exe().to_string_lossy(),
        ArgvMatcher::Any(AnyMarker),
        CONNECT_DOMAIN,
    ));
    let mut connect = PolicyDomain::new(CONNECT_DOMAIN);
    connect.net.allow_domains = vec![SSH_HOST.to_string()];

    let file = PolicyFile {
        domains: vec![entry, child, quiet, other, ssh, connect],
        ..PolicyFile::default()
    };
    policy_file::save(ws, &file).unwrap_or_else(|e| panic!("policy.json を書けない: {e}"));
}

/// この試験が書いた通信の宣言（ドメイン, 宛先）。
fn net_declarations(shell_domain: &str) -> Vec<(String, &'static str)> {
    vec![
        (shell_domain.to_string(), CHILD_HOST),
        (shell_domain.to_string(), SSH_HOST),
        ("other-net".to_string(), OTHER_HOST),
        (CONNECT_DOMAIN.to_string(), SSH_HOST),
    ]
}

/// 台帳への記録そのものは[`common::net_approval_in_ledger`]が持つ（`record_net_e2e`と同じ1か所）。
fn approve_net(ws: &Path) -> bool {
    net_approval(ws, /* approve */ true).is_empty()
}

/// 承認を台帳から消す（**付与と撤収の対**。`B-01`）。
fn revoke_net(ws: &Path) {
    let left = net_approval(ws, /* approve */ false);
    assert!(left.is_empty(), "承認を台帳から消せない: {left:?}");
}

fn net_approval(ws: &Path, approve: bool) -> Vec<String> {
    let shell = middle_shell();
    let declarations = net_declarations(&shell.domain);
    let pairs: Vec<(&str, &str)> = declarations
        .iter()
        .map(|(domain, value)| (domain.as_str(), *value))
        .collect();
    common::net_approval_in_ledger(ws, &pairs, approve)
}

/// `<tag>:PROXY=…`と`<tag>:NET_OK <状態>`／`<tag>:NET_FAIL <理由>`を印字する PowerShell の1行。
///
/// **進捗表示を切る**（`$ProgressPreference`）——Windows PowerShell 5.1 の`Invoke-WebRequest`は進捗バーを
/// コンソールの画面バッファへ書こうとし、サンドボックスの中では「Access is denied 0x5」で落ちる
/// （`widening_transitions_e2e.rs`の同じ関数の実測）。
fn net_probe(tag: &str, host: &str) -> String {
    format!(
        "$ProgressPreference = 'SilentlyContinue'; \
         Write-Output ('{tag}:PRO' + 'XY=' + $env:HTTP_PROXY); \
         try {{ $r = Invoke-WebRequest -Uri 'http://{host}/' -Proxy $env:HTTP_PROXY -UseBasicParsing -TimeoutSec 20; \
         Write-Output ('{tag}:NET_' + 'OK ' + $r.StatusCode) }} \
         catch {{ Write-Output ('{tag}:NET_' + 'FAIL ' + $_.Exception.Message) }}"
    )
}

/// 行の`prefix`の後ろ（印字が無ければ`None`）。
fn line_after(arm: &Arm, prefix: &str) -> Option<String> {
    arm.result
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix).map(str::to_string))
}

/// `<tag>:PROXY=`の値（印字が無ければ`None`）。
fn proxy_of(arm: &Arm, tag: &str) -> Option<String> {
    let prefix = format!("{tag}:PROXY=");
    arm.result
        .lines()
        .find_map(|line| line.trim().strip_prefix(&prefix).map(str::to_string))
}

/// ⑥の行。`ProxyCommand`に**ポートを書かない**——`connect.exe -h`が`HTTP_PROXY`を読むので、
/// Spawn Daemon が差し替えたそのドメインの宛先がそのまま効く（決定69 の前例の(15)）。
fn ssh_line() -> String {
    format!(
        "& '{}' -T -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL \
         -o 'ProxyCommand=\"{}\" -h %h %p' git@{SSH_HOST} 2>&1",
        ssh_exe(),
        connect_exe().display()
    )
}

/// サンドボックスの外から HTTP で届くか（届かなければ判定不能）。
fn http_reachable(host: &str) -> Result<(), String> {
    let script = format!(
        "$ProgressPreference = 'SilentlyContinue'; \
         try {{ $r = Invoke-WebRequest -Uri 'http://{host}/' -UseBasicParsing -TimeoutSec 20; \
         Write-Output ('NET_' + 'OK ' + $r.StatusCode) }} \
         catch {{ Write-Output ('NET_' + 'FAIL ' + $_.Exception.Message) }}"
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|e| format!("powershell.exe を起こせない: {e}"))?;
    let text = String::from_utf8_lossy(&output.stdout);
    if text.contains("NET_OK 200") {
        Ok(())
    } else {
        Err(text.trim().to_string())
    }
}

/// サンドボックスの外から`ssh -T git@github.com`を1回（比べる相手。22番へ届けば鍵が無くても
/// `Permission denied (publickey)`が返る）。
fn ssh_probe_outside() -> String {
    let output = Command::new(ssh_exe())
        .args([
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=NUL",
            "-o",
            "ConnectTimeout=15",
            &format!("git@{SSH_HOST}"),
        ])
        .output()
        .unwrap_or_else(|e| panic!("ssh.exe を起こせない: {e}"));
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .trim()
    .to_string()
}

/// このワークスペースの**全部の**`net-audit.jsonl`をつないだもの。
///
/// **1本だけ読むと前の腕の行が見えない**——`harness.exe`は起動ごとに別のセッションの置き場
/// （`.harness/sandbox/audit-<セッションid>/`）へ書くので、腕を1本撃つたびにファイルが増える。
/// 1回目の実測では「いちばん新しい1本」を読んでいて、最後に撃った腕の行しか見えなかった（計器の失敗）。
fn all_net_audit(ws: &Path) -> String {
    let sandbox = ws.join(".harness").join("sandbox");
    let Ok(entries) = std::fs::read_dir(&sandbox) else {
        return String::new();
    };
    let mut out = String::new();
    for entry in entries.flatten() {
        if let Ok(text) = std::fs::read_to_string(entry.path().join("net-audit.jsonl")) {
            out.push_str(&text);
            if !out.ends_with('\n') {
                out.push('\n');
            }
        }
    }
    out
}

