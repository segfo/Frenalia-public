//! **N8 論点③の対策候補B: AppContainerトークンからSMB（UNC）共有へ届くか**
//! （`plans/net-spike/RESULTS.md` `N8-M1-③`）。
//!
//! **何を決めるためのものか。** force-push判定に要る「判定用の履歴データ」を取り出すとき、
//! ブローカーは子のオブジェクトDBを読む。ところが子は自分の`objects/info/alternates`へ
//! **UNCパスを書ける**——実測では、子のodbしか指していないブローカーが引きずられて
//! **リモートのSMB共有からオブジェクトを取り込んだ**。ブローカーはサンドボックスの外にいるので
//! Tier2aのネットワーク統制（WFP）が掛からず、**子が自力で出られない先へブローカー経由で出られる**。
//!
//! 対策候補Bは「子のodbを読む側（`upload-pack`）だけを**子と同じ権限**で走らせれば、
//! ブローカーの到達範囲が子を超えない」というもの。本テストはその前提——
//! **AppContainerトークンでUNCへ届くのか**——だけを測る。gitは介さない（トークンの性質の話）。
//!
//! **capabilityを1つずつ変える**（B-29: 一度に1変数）。`NetworkCapability`の2択ではなく
//! [`SpikeSpawn`]を使うのは、**SMBは`internetClient`ではなく`privateNetworkClientServer`の
//! 側だと予想される**ためで、2択では「どちらでも塞がった」の理由が確定しない。
//!
//! **共有パスは環境依存なので`N8_UNC_PROBE`で渡す**（リポジトリへ他人のホスト名を埋めない）。
//!
//! **§18.5の規律**: 対照C1（コンテナ**外**から読める）が落ちたらテストごと落とす。
//! 「共有が落ちていた」を「AppContainerが塞いだ」と読み違えるのが一番ありそうな失敗だからである。
//! 対照C2（コンテナ**内**でローカルのファイルは読める）も要る——UNCだけが失敗したのか、
//! コンテナの中で何も読めていないのかが区別できない。
//!
//! **判定が出たら削除する**（`docs/CODE-STRUCTURE-RULES.md`規則2: 一回性の調査実験を残さない）。

use std::path::{Path, PathBuf};

use windows::Win32::Security::PSID;

use super::mac_spike_tests::{SpikeConsole, SpikeSpawn};
#[allow(unused_imports)]
use super::resolve_shell;

const MARKER: &str = "N8-UNC-REACH-MARKER";

/// AppContainerのネットワークcapability（well-known SID）。
const CAP_INTERNET_CLIENT: &str = "S-1-15-3-1";
const CAP_INTERNET_CLIENT_SERVER: &str = "S-1-15-3-2";
const CAP_PRIVATE_NETWORK: &str = "S-1-15-3-3";

fn sid_from_string(s: &str) -> crate::win_common::OwnedSid {
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
    let w: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let mut psid = PSID::default();
    unsafe {
        ConvertStringSidToSidW(windows::core::PCWSTR(w.as_ptr()), &mut psid)
            .unwrap_or_else(|e| panic!("ConvertStringSidToSidW({s}): {e}"));
        let owned = crate::win_common::OwnedSid::copy_from(psid).expect("copy sid");
        let _ = windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(psid.0));
        owned
    }
}

/// UNC上のマーカーを読ませる1行スクリプト。**成否と理由の両方**を出す
/// （`EXISTS=False`だけだと「拒否された」のか「無い」のかが分からない）。
fn probe_script(unc_file: &str) -> String {
    format!(
        "Write-Output ('EXISTS=' + (Test-Path -LiteralPath '{unc_file}')); \
         try {{ Write-Output ('CONTENT=' + (Get-Content -LiteralPath '{unc_file}' -Raw -ErrorAction Stop).Trim()) }} \
         catch {{ Write-Output ('ERR=' + ($_.Exception.Message -replace '\\s+',' ')) }}; \
         Write-Output ('LOCALFILE=' + (Test-Path -LiteralPath 'C:\\Windows\\System32\\kernel32.dll'))"
    )
}

/// **③-C: 遮断の「理由」を切り分けるプローブ。**
///
/// `N8-③-B`は「AppContainerの子はSMB共有へ届かない」までしか言えていない。理由が
/// (a) capability/WFPによるネットワーク遮断なのか (b) AppContainerトークンが
/// ユーザーの認証済みSMBセッションを引き継がないためなのかで、**塞がる範囲が変わる**
/// ——(b)なら**認証を要求しない共有（匿名/ゲスト）には届き得る**ので、子が
/// 「認証不要のSMBホスト」を`alternates`に書けば対策1を素通りできる。
///
/// **匿名共有を立てずに分離する。** 2つの仮説はネットワーク層について別の予測をするからである。
///
/// | 仮説 | TCP 445 | UNCのWin32エラー |
/// |---|---|---|
/// | (a) capability | **繋がらない**（AppContainerのソケット拒否は`WSAEACCES`=10013） | ネットワーク系 |
/// | (b) 認証 | **繋がる**（落ちるのはSMBのセッション確立） | `ERROR_LOGON_FAILURE`(1326)・`ERROR_ACCESS_DENIED`(5)系 |
///
/// **IPと名前の両方へ撃つ**——名前解決の失敗を「ネットワーク遮断」と読み違えないため。
/// エラーは文字列ではなく**HRESULT（`0x8007xxxx`の下位16bitがWin32コード）**で採る。
fn reason_probe_script(unc_file: &str, ip: &str, host: &str) -> String {
    format!(
        "Write-Output ('LOCALFILE=' + (Test-Path -LiteralPath 'C:\\Windows\\System32\\kernel32.dll')); \
         try {{ Write-Output ('CONTENT=' + ([System.IO.File]::ReadAllText('{unc_file}')).Trim()) }} \
         catch {{ $e=$_.Exception; while($e.InnerException){{$e=$e.InnerException}}; \
                 Write-Output ('UNCHR=0x' + ('{{0:X8}}' -f $e.HResult)); \
                 Write-Output ('UNCERR=' + ($e.Message -replace '\\s+',' ')) }}; \
         function T($h,$p) {{ $c=New-Object System.Net.Sockets.TcpClient; \
             try {{ $t=$c.ConnectAsync($h,$p); if($t.Wait(5000)) {{ 'OK' }} else {{ 'TIMEOUT' }} }} \
             catch {{ $x=$_.Exception; while($x.InnerException){{$x=$x.InnerException}}; \
                     if($x -is [System.Net.Sockets.SocketException]) \
                        {{ 'ERR:' + $x.SocketErrorCode + ':' + $x.NativeErrorCode }} \
                     else {{ 'ERR:' + $x.GetType().Name }} }} \
             finally {{ $c.Close() }} }}; \
         Write-Output ('TCPIP=' + (T '{ip}' 445)); \
         Write-Output ('TCPNAME=' + (T '{host}' 445)); \
         function U($p) {{ try {{ [void][System.IO.File]::ReadAllText($p); 'READ' }} \
             catch {{ $y=$_.Exception; while($y.InnerException){{$y=$y.InnerException}}; \
                     '0x' + ('{{0:X8}}' -f $y.HResult) }} }}; \
         Write-Output ('UNCIP=' + (U '\\\\{ip}\\share\\test\\n8-unc-probe\\marker.txt')); \
         Write-Output ('UNCBAD=' + (U '\\\\192.0.2.1\\share\\marker.txt'))"
    )
}

fn kv(out: &str, key: &str) -> Option<String> {
    out.lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
        .map(|v| v.trim_end().to_string())
}

fn run_outside(script: &str) -> String {
    let shell = shell_path();
    let out = std::process::Command::new(&shell)
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .expect("run powershell outside the container");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// **シェルは実体パスへ固定する。**
///
/// `resolve_shell()`は`preflight`が選んだ`SELECTED_SHELL`を先に見る。`preflight`を通さない
/// このスパイクでは未設定なので候補の先頭（`WindowsApps`配下の**実行エイリアス**＝
/// 長さ0の再解析ポイント）が返り得る。AppContainerからエイリアスを起動すると
/// `CreateProcessW`が`ERROR_INVALID_PARAMETER`で落ちる——**測りたいUNC到達性の手前で
/// 起動が失敗するので、そのままだと「AppContainerが塞いだ」と読み違える。**
fn shell_path() -> String {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    format!(r"{system_root}\System32\WindowsPowerShell\v1.0\powershell.exe")
}

fn run_in_container(container_sid: PSID, capabilities: &[PSID], script: &str) -> String {
    let shell = shell_path();
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let cwd = PathBuf::from(format!(r"{system_root}\System32"));
    let mut child = SpikeSpawn {
        exe: &shell,
        args: &["-NoProfile", "-NonInteractive", "-Command", script],
        cwd: &cwd,
        container_sid,
        capabilities,
        child_process_restricted: false,
        stdout_override: None,
        extra_inherit: &[],
        process_sddl: None,
        thread_sddl: None,
        token_default_dacl_sddl: None,
        no_appcontainer: false,
        console: SpikeConsole::NoWindow,
    }
    .spawn()
    .expect("spawn the probe child inside the AppContainer");
    let (out, err, _code) = child.wait_and_read();
    format!("{out}{err}")
}

fn row(label: &str, out: &str) {
    eprintln!(
        "[N8-③-B] {label:<34} EXISTS={:<6} LOCALFILE={:<6} CONTENT={:?} ERR={:?}",
        kv(out, "EXISTS").unwrap_or_else(|| "-".into()),
        kv(out, "LOCALFILE").unwrap_or_else(|| "-".into()),
        kv(out, "CONTENT").unwrap_or_else(|| "-".into()),
        kv(out, "ERR").unwrap_or_else(|| "-".into()),
    );
}

fn reached(out: &str) -> bool {
    kv(out, "CONTENT").as_deref() == Some(MARKER)
}

fn row_reason(label: &str, out: &str) {
    eprintln!(
        "[N8-③-C] {label:<32} TCPIP={:<26} UNCHR={:<12} UNCIP={:<12} UNCBAD={:<12} LOCAL={:<5} TCPNAME={}",
        kv(out, "TCPIP").unwrap_or_else(|| "-".into()),
        kv(out, "UNCHR").unwrap_or_else(|| "-".into()),
        kv(out, "UNCIP").unwrap_or_else(|| "-".into()),
        kv(out, "UNCBAD").unwrap_or_else(|| "-".into()),
        kv(out, "LOCALFILE").unwrap_or_else(|| "-".into()),
        kv(out, "TCPNAME").unwrap_or_else(|| "-".into()),
    );
}

/// `\\host\share\...` からホスト名を取る。
fn unc_host(unc: &str) -> String {
    unc.trim_start_matches('\\')
        .split('\\')
        .next()
        .unwrap_or_default()
        .to_string()
}

/// **③-C**: `N8-③-B`が残した「遮断の理由」を切り分ける。
///
/// `N8-③-B`とは**別のテストとして足す**——同じ関数へ足すと、既に成立した結果
/// （capability 4通りで届かない）を測り直すことになるため。ここが見るのは
/// **なぜ届かないか**だけである。
#[test]
#[ignore = "実AppContainerと実SMB共有を使う。**非昇格**・--test-threads=1・N8_UNC_PROBE必須"]
fn n8_why_cant_an_appcontainer_child_reach_an_smb_share() {
    let base = std::env::var("N8_UNC_PROBE").expect("N8_UNC_PROBE に検証用UNCディレクトリを渡すこと");
    let unc_file = format!(r"{base}\marker.txt");
    let host = unc_host(&base);
    assert!(!host.is_empty(), "UNCからホスト名を取れない: {base}");

    // **IPはコンテナ外で解決する。** コンテナ内で名前解決に失敗したものを
    // 「ネットワークが遮断された」と読み違えないため（IP直指定なら解決は要らない）。
    let ip = {
        use std::net::ToSocketAddrs;
        let addr = format!("{host}:445")
            .to_socket_addrs()
            .unwrap_or_else(|e| panic!("ホスト名を解決できない: {host} ({e})"))
            .next()
            .unwrap_or_else(|| panic!("{host} に解決結果が無い"));
        addr.ip().to_string()
    };
    eprintln!("[N8-③-C] host={host} ip={ip} probe={base}");

    std::fs::create_dir_all(&base).unwrap_or_else(|e| panic!("共有へ書けない: {base} ({e})"));
    std::fs::write(&unc_file, MARKER).unwrap_or_else(|e| panic!("マーカーを置けない: {e}"));

    let sid = super::session_sid();
    let script = reason_probe_script(&unc_file, &ip, &host);

    // --- C1: コンテナ外（対照。ここが落ちたら以降は無意味） ---
    let c1 = run_outside(&script);
    row_reason("C1 outside", &c1);
    assert!(
        reached(&c1),
        "対照C1が落ちた＝共有が読めていない。以降の結果は無意味。out={c1:?}"
    );
    assert_eq!(
        kv(&c1, "TCPIP").as_deref(),
        Some("OK"),
        "対照C1でTCP445へ繋がらない＝**計器かホストの問題**。\
         コンテナ内のTCP失敗をcapabilityの効果と読んではいけない。out={c1:?}"
    );

    // --- C0（計器の対照）: コンテナが起動できるか ---
    let filler0 = super::capability_sid_from_name(&format!("harness-n8c-c0-{}", std::process::id()))
        .expect("derive filler capability");
    let c0 = run_in_container(sid.as_psid(), &[filler0.as_psid()], "Write-Output 'C0=OK'");
    assert!(
        c0.contains("C0=OK"),
        "計器の対照C0が落ちた＝コンテナで何も実行できていない。out={c0:?}"
    );

    let ic = sid_from_string(CAP_INTERNET_CLIENT);
    let ics = sid_from_string(CAP_INTERNET_CLIENT_SERVER);
    let pn = sid_from_string(CAP_PRIVATE_NETWORK);
    let filler = super::capability_sid_from_name(&format!("harness-n8c-fill-{}", std::process::id()))
        .expect("derive filler capability");

    let none_out = run_in_container(sid.as_psid(), &[filler.as_psid()], &script);
    row_reason("C3 in-container: network cap無し", &none_out);
    assert_eq!(
        kv(&none_out, "LOCALFILE").as_deref(),
        Some("True"),
        "対照C2が落ちた＝コンテナ内でローカルのファイルすら読めていない。out={none_out:?}"
    );

    let ic_out = run_in_container(sid.as_psid(), &[ic.as_psid()], &script);
    row_reason("C4 in-container: internetClient", &ic_out);
    let pn_out = run_in_container(sid.as_psid(), &[pn.as_psid()], &script);
    row_reason("C5 in-container: privateNetwork", &pn_out);
    let all_out = run_in_container(
        sid.as_psid(),
        &[ic.as_psid(), ics.as_psid(), pn.as_psid()],
        &script,
    );
    row_reason("C6 in-container: network cap全部", &all_out);

    let _ = std::fs::remove_file(&unc_file);
    let _ = std::fs::remove_dir(&base);
    eprintln!(
        "[N8-③-C] 共有側の残骸: marker={} dir={}",
        Path::new(&unc_file).exists(),
        Path::new(&base).exists()
    );

    // **判定は人間が読む。** ここでassertしないのは、(a)(b)どちらでも「テストとしては成功」で
    // あり、決めたいのは真偽ではなく**どちらか**だからである（B-33: 測定の出力を成否へ潰さない）。
    eprintln!(
        "[N8-③-C] 読み方: 全capabilityでTCPIPが ERR:AccessDenied:10013 → **(a) capabilityが塞いでいる**。\
         TCPIPがOKでUNCHRが0x8007052E/0x80070005 → **(b) 認証セッション**（匿名共有には届き得る）。\
         TCPIP=OKでUNCHRがネットワーク系（0x80070035等）→ どちらでもない第3の理由"
    );
}

/// 対照 → capabilityを1つずつ変えた4通り、を1本で回す。
///
/// 分けないのは、共有の到達性・コンテナの生死・capabilityの3つが**同じ実行の中で**
/// 揃っていないと失敗の原因を1つに絞れないためである（B-29）。
#[test]
#[ignore = "実AppContainerと実SMB共有を使う。**非昇格**・--test-threads=1・N8_UNC_PROBE必須"]
fn n8_can_an_appcontainer_child_reach_an_smb_share() {
    let base = std::env::var("N8_UNC_PROBE").expect(
        "N8_UNC_PROBE に検証用UNCディレクトリを渡すこと。\
         リポジトリへホスト名を埋めないため必須にしてある",
    );
    let unc_file = format!(r"{base}\marker.txt");

    std::fs::create_dir_all(&base).unwrap_or_else(|e| panic!("共有へ書けない: {base} ({e})"));
    std::fs::write(&unc_file, MARKER).unwrap_or_else(|e| panic!("マーカーを置けない: {e}"));

    // **本番のセッションプロファイル（D-37）を使う。** 手製のスパイクプロファイルでは
    // `CreateProcessW`が`ERROR_INVALID_PARAMETER`で落ちた（動いている他のスパイクは
    // どれも`session_sid()`を使っている）。測りたいのは「子と同じ権限」なので、
    // 本番の識別子の方が測定対象としても正しい。
    let sid = super::session_sid();
    // PowerShellの単一引用符文字列ではバックスラッシュは素通しなので、エスケープは要らない。
    let script = probe_script(&unc_file);

    // --- C1: コンテナ外（**必ず成功するはず**の対照） ---
    let c1 = run_outside(&script);
    row("C1 outside", &c1);
    assert!(
        reached(&c1),
        "対照C1が落ちた＝共有が読めていない。**以降の結果は無意味**\
         （「AppContainerが塞いだ」と読み違える）。out={c1:?}"
    );

    // --- C3〜C6: コンテナ内。capabilityを1つずつ足す ---
    let ic = sid_from_string(CAP_INTERNET_CLIENT);
    let ics = sid_from_string(CAP_INTERNET_CLIENT_SERVER);
    let pn = sid_from_string(CAP_PRIVATE_NETWORK);

    // --- C0（**計器の対照**）: 中身の無いスクリプトでコンテナが起動できるか ---
    // ここが落ちたら、以降の失敗は「AppContainerがUNCを塞いだ」ではなく**起動できていない**。
    // 起動の失敗と到達の失敗は、区別しないと正反対の結論になる。
    let filler0 =
        super::capability_sid_from_name(&format!("harness-n8-c0-{}", std::process::id()))
            .expect("derive filler capability");
    let c0 = run_in_container(sid.as_psid(), &[filler0.as_psid()], "Write-Output 'C0=OK'");
    eprintln!("[N8-③-B] C0 instrument: {c0:?}");
    assert!(
        c0.contains("C0=OK"),
        "計器の対照C0が落ちた＝コンテナで**何も実行できていない**。out={c0:?}"
    );

    // **capability配列を空にすると`CreateProcessW`が`ERROR_INVALID_PARAMETER`で落ちる**
    // （production側も`NetworkCapability::Deny`のときtraverse capabilityを必ず積むので、
    // 「本当に0本」は通らない経路である）。したがって「ネットワークcapabilityが無い」を
    // 測るための埋め草として、**ネットワークと無関係な導出capabilityを1本だけ**積む。
    // 台帳へは何も書かない純粋な導出なので、実マシンに記録は残らない。
    let filler = super::capability_sid_from_name(&format!("harness-n8-filler-{}", std::process::id()))
        .expect("derive filler capability");
    let none_out = run_in_container(sid.as_psid(), &[filler.as_psid()], &script);
    row("C3 in-container: network cap無し", &none_out);

    // --- C2: コンテナが生きていることの対照（**UNCの失敗を読む前に**確認する） ---
    assert_eq!(
        kv(&none_out, "LOCALFILE").as_deref(),
        Some("True"),
        "対照C2が落ちた＝コンテナの中で**ローカルのファイルすら**読めていない。\
         UNCの失敗をcapabilityの効果と読んではいけない。out={none_out:?}"
    );

    let ic_out = run_in_container(sid.as_psid(), &[ic.as_psid()], &script);
    row("C4 in-container: internetClient", &ic_out);

    let pn_out = run_in_container(sid.as_psid(), &[pn.as_psid()], &script);
    row("C5 in-container: privateNetwork", &pn_out);

    let all_out = run_in_container(
        sid.as_psid(),
        &[ic.as_psid(), ics.as_psid(), pn.as_psid()],
        &script,
    );
    row("C6 in-container: network capability全部", &all_out);

    // --- 後片付け（B-01: 付与と撤収を対で持つ） ---
    // セッションプロファイルは本番の資源なので**消さない**（作ったのはこのテストではない）。
    // 消すのは共有側に置いたマーカーだけ。
    let _ = std::fs::remove_file(&unc_file);
    let _ = std::fs::remove_dir(&base);
    eprintln!(
        "[N8-③-B] 共有側の残骸: marker={} dir={}",
        Path::new(&unc_file).exists(),
        Path::new(&base).exists()
    );
    eprintln!(
        "[N8-③-B] 結論: 到達 capability無し={} / internetClient={} / privateNetwork={} / 全部={}",
        reached(&none_out),
        reached(&ic_out),
        reached(&pn_out),
        reached(&all_out)
    );
}
