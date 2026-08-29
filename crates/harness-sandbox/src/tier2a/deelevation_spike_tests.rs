//! **測定専用スパイク（判定が出たら削除する。`docs/CODE-STRUCTURE-RULES.md`規則2）**:
//! 昇格した`dev-elevated-runner`配下から、**非昇格（[`super::privhelper::is_elevated`]が偽）の
//! 子プロセス**を起こせるか。
//!
//! # 何のために測るのか
//!
//! [BUG-111](../../../../docs/bugs/BUG-111.md)の残り1点は「シナリオ(A)——privhelperが連鎖起動した
//! `harness-netfilterd`とのハンドシェイクだけが失敗する経路——を通すE2Eが無い」ことである。
//! この経路へ入る条件は
//! [`win_appcontainer::preflight`](win_appcontainer/preflight.rs)の分岐
//! （`if crate::tier2a::privhelper::is_elevated() { ...直接付与... } else { ...privhelper委譲... }`）
//! が**偽**になることで、つまり**harness本体が非昇格**でなければならない。現在のTier2a E2Eは
//! `dev-elevated-runner`経由で昇格して走るため、この分岐に構造的に入らない。
//!
//! したがって、E2Eを書き始める前にここだけを確かめる——
//! **昇格したテストプロセスから、非昇格の子を起こす手段はあるか。**
//!
//! # 測り方（`plans/etw-spike/RESULTS.md` §18.5・§21.4の規律）
//!
//! **計器は製品コードそのもの**にする。`harness.exe`は起動直後
//! （[`stage_parse_args`](../../../harness-cli/src/cli/startup/parse_args.rs)、`Cli::parse`より前）に
//! `is_elevated()`を呼び、真なら[`ELEVATED_MARKER`]を含む警告をstderrへ出す。つまり
//! **この警告の有無＝シナリオ(A)の分岐が見るのと同じ判定**である。IL（integrity level）や
//! Administrators所属を代理指標にすると「ILは下がったが`TokenIsElevated`は真」のような
//! 取り違えが起き得るので、代理ではなく門そのものを読む。
//!
//! - **正の対照（M0）**: 素の子。**警告が出なければ計器が壊れている**ので、テストごと落とす。
//!   「警告が無い＝非昇格」を信じてよいのは、同じ計器で「警告が出る」を見た後だけである。
//! - **無言失敗の排除**: 子が起動に失敗してもstderrに警告は出ない。だから
//!   「警告が無いこと」だけでなく**「子が正常に走ったこと」**（終了コードと
//!   stdoutの[`HELP_MARKER`]）を対で見る。これが無いと、単に壊れた子を
//!   「非昇格化に成功した」と読む（§18.5が3回踏んだ交絡と同じ形）。
//! - **測定対象を取り違えない**（§21.4）: 測るのは**昇格デーモンが起こしたプロセスの子**である。
//!   対話シェルから起こした子は最初から非昇格なので必ず成功して見える。だから
//!   このテストは冒頭で**自分が昇格しているか**を確かめ、していなければ測定不成立として落とす。
//!   `dev-elevated-run.exe spike-deelevation`で走らせること。
//!
//! # 何を残すか
//!
//! `C:\harness-e2e\deelevation-spike\`配下に手法ごとのディレクトリを作り、子の出力をそこへ
//! 書かせる（`runas`・`explorer`は子のstdioを親へ繋げないため、ファイル経由で受け取る）。
//! **全手法で同じラッパー`.cmd`を通す**——手法ごとに起動の形を変えると、差が
//! 「非昇格化できたか」ではなく「起動の形」から来ている可能性が残る。正常終了時は削除する。

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// 手法ごとの作業ディレクトリの親。**パスに空白を含めない**——`runas`へは
/// 「プログラムとその引数」を1つの引用符付き文字列で渡すため、空白があると引用が入れ子になる。
const SPIKE_ROOT: &str = r"C:\harness-e2e\deelevation-spike";

/// 子が**正常に走った**ことの印（stdout）。`harness.exe --help`はclapのusageを出して0で終わる。
const HELP_MARKER: &str = "Usage: harness.exe";

/// 子が**昇格していた**ことの印（stderr）。`parse_args.rs`の`is_elevated()`分岐が出す唯一の文言で、
/// ここを変えるとこのスパイクは黙って「常に非昇格」と読むようになる。
const ELEVATED_MARKER: &str = "running with an elevated (administrator) token";

/// ラッパーが完了印（`rc.txt`）を書くまでの待ち上限。`runas`・`explorer`は起動しただけで
/// 戻るので、子の完了はファイルの出現でしか観測できない。
const CHILD_TIMEOUT: Duration = Duration::from_secs(120);

/// `target/debug/deps/harness_sandbox-<hash>.exe` → `target/debug/harness.exe`。
///
/// **実体は`win_appcontainer::test_support`が持つ**——D-88の受入4「競合」が同じ解決を要り、
/// このファイルは判定が出たら消えるスパイクなので、**消えても残る場所**へ移した（規則5）。
fn harness_exe() -> PathBuf {
    crate::tier2a::win_appcontainer::test_support::harness_exe()
}

fn windir() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string())
}

fn system32(exe: &str) -> String {
    format!(r"{}\System32\{exe}", windir())
}

/// 子の素性と結末を、**書いた順**にファイルへ残すラッパー。
///
/// 順序に意味がある。`groups.txt`（トークンの素性）を最初に書くので、
/// 「1つも出来ていない＝ラッパー自体が走っていない／このディレクトリへ書けない」と
/// 「`groups.txt`はあるが`rc.txt`が無い＝`harness.exe`が終わっていない」を切り分けられる。
fn write_wrapper(dir: &Path, harness: &Path) -> PathBuf {
    let wrapper = dir.join("run.cmd");
    let d = dir.display();
    let body = format!(
        "@echo off\r\n\
         \"{whoami}\" /groups /fo csv > \"{d}\\groups.txt\" 2>&1\r\n\
         \"{harness}\" --help > \"{d}\\out.txt\" 2>\"{d}\\err.txt\"\r\n\
         echo %ERRORLEVEL% > \"{d}\\rc.txt\"\r\n",
        whoami = system32("whoami.exe"),
        harness = harness.display(),
    );
    std::fs::write(&wrapper, body).expect("write the wrapper .cmd");
    wrapper
}

/// `whoami`はコンソールのコードページ（この機ではCP932）で書くので、UTF-8として読むと
/// 日本語が化けて**「読めない」と「出ていない」の区別が付かなくなる**。
/// 既存の`decode_console_bytes`（BUG-051で入れたもの）を通す。
fn read_trimmed(path: &Path) -> Option<String> {
    std::fs::read(path)
        .ok()
        .map(|b| crate::win_common::decode_console_bytes(&b).trim().to_string())
}

fn wait_for(path: &Path, timeout: Duration) -> bool {
    let start = Instant::now();
    loop {
        if path.exists() {
            return true;
        }
        if start.elapsed() >= timeout {
            return false;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// `whoami /groups /fo csv`の出力から**SIDで**integrity levelを読む。
///
/// 名前（`Mandatory Label\High Mandatory Level`）ではなくSIDを見るのは、表示名がロケール依存の
/// ためである。「表示名が英語だろう」という前提は、測定の答えではなくこの開発機の設定に依存する。
fn integrity_from_groups(groups: &str) -> String {
    let mut found: Vec<String> = Vec::new();
    let mut rest = groups;
    while let Some(i) = rest.find("S-1-16-") {
        let tail = &rest[i + "S-1-16-".len()..];
        let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
        rest = &tail[digits.len()..];
        if !digits.is_empty() && !found.contains(&digits) {
            found.push(digits);
        }
    }
    if found.is_empty() {
        return "unknown (no S-1-16-* in the whoami output)".to_string();
    }
    found
        .iter()
        .map(|rid| match rid.as_str() {
            "0" => "Untrusted(0)".to_string(),
            "4096" => "Low(4096)".to_string(),
            "8192" => "Medium(8192)".to_string(),
            "8448" => "MediumPlus(8448)".to_string(),
            "12288" => "High(12288)".to_string(),
            "16384" => "System(16384)".to_string(),
            other => format!("S-1-16-{other}"),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// `BUILTIN\Administrators`（S-1-5-32-544）の行。属性欄まで丸ごと出す——
/// 「載っているが deny-only」と「そもそも載っていない」は別の状態であり、
/// 非昇格化の手法によってどちらになるかが変わる。
fn admins_from_groups(groups: &str) -> String {
    groups
        .lines()
        .find(|l| l.contains("S-1-5-32-544"))
        .map(|l| l.trim().to_string())
        .unwrap_or_else(|| r"absent (BUILTIN\Administrators is not in the token at all)".to_string())
}

/// ラッパーが残したファイルから読んだ、子1つ分の事実。
#[derive(Debug)]
struct ChildFacts {
    /// `harness.exe --help`の終了コード（文字列のまま。読めない値も残す）。
    rc: String,
    /// **子が正常に走ったか**（stdoutに[`HELP_MARKER`]）。無言失敗を「非昇格化成功」と
    /// 読まないための対。
    ran_ok: bool,
    /// **子が昇格していたか**（stderrに[`ELEVATED_MARKER`]）。これが測りたい門そのもの。
    elevated: bool,
    integrity: String,
    admins: String,
    stderr: String,
    /// `whoami`の生出力。ILもAdministrators行も読めなかったときに**何が書かれていたのか**を
    /// 出すため——「トークンにラベルが無い」と「`whoami`自体が動かなかった」は別の事実で、
    /// 区別せずに片方だと決めるのが§18.5の交絡そのものである。
    groups_raw: String,
}

fn collect(dir: &Path) -> Result<ChildFacts, String> {
    let groups = read_trimmed(&dir.join("groups.txt"));
    let rc = read_trimmed(&dir.join("rc.txt"));
    let Some(rc) = rc else {
        return Err(match groups {
            None => "the wrapper produced nothing: it never ran, or it could not write into the \
                     spike directory"
                .to_string(),
            Some(_) => "groups.txt is present but rc.txt never appeared: the wrapper started but \
                        harness.exe did not finish"
                .to_string(),
        });
    };
    let groups = groups.unwrap_or_default();
    let stdout = read_trimmed(&dir.join("out.txt")).unwrap_or_default();
    let stderr = read_trimmed(&dir.join("err.txt")).unwrap_or_default();
    Ok(ChildFacts {
        rc,
        ran_ok: stdout.contains(HELP_MARKER),
        elevated: stderr.contains(ELEVATED_MARKER),
        integrity: integrity_from_groups(&groups),
        admins: admins_from_groups(&groups),
        stderr,
        groups_raw: groups,
    })
}

/// 手法1つ分の結果。**起動器の失敗と子の失敗を型で分ける**——
/// 「`runas`が起動できなかった」と「子は起きたが昇格していた」を同じ欄に混ぜると、
/// 次に何を試すべきかが読めなくなる。
#[derive(Debug)]
enum Probe {
    /// 起動器そのものが失敗した（`runas`のエラー、Win32エラー等）。
    LauncherFailed(String),
    /// 起動器は戻ったが、ラッパーの結果が読めなかった。
    NoResult(String),
    Ran(ChildFacts),
}

impl Probe {
    /// **非昇格の子を「使える形で」起こせた**と言えるか。
    /// `ran_ok`との対にしてあるのは、壊れた子のstderrにも警告は出ないためである。
    fn is_usable_non_elevated(&self) -> bool {
        matches!(self, Probe::Ran(f) if f.ran_ok && !f.elevated)
    }
}

fn report(method: &str, launcher: &str, probe: &Probe) {
    println!("---- {method} ----");
    println!("  launcher : {launcher}");
    match probe {
        Probe::LauncherFailed(e) => println!("  result   : LAUNCHER FAILED: {e}"),
        Probe::NoResult(e) => println!("  result   : NO RESULT: {e}"),
        Probe::Ran(f) => {
            println!(
                "  result   : child ran (harness --help rc={}), ran_ok={}, ELEVATED={}",
                f.rc, f.ran_ok, f.elevated
            );
            println!("  integrity: {}", f.integrity);
            println!("  admins   : {}", f.admins);
            if f.integrity.starts_with("unknown") {
                println!(
                    "  whoami   : (raw, {} bytes) {}",
                    f.groups_raw.len(),
                    f.groups_raw.replace('\n', "\n             ")
                );
            }
            if !f.stderr.is_empty() {
                println!("  stderr   : {}", f.stderr.replace('\n', "\n             "));
            }
        }
    }
}

/// 手法0（**正の対照**）: 昇格したテストプロセスから素直に子を起こす。
fn probe_plain(dir: &Path, wrapper: &Path) -> (String, Probe) {
    let out = Command::new(system32("cmd.exe"))
        .arg("/c")
        .arg(wrapper)
        .output();
    let launcher = match &out {
        Ok(o) => format!("cmd /c -> exit {:?}", o.status.code()),
        Err(e) => format!("cmd /c -> {e}"),
    };
    if let Err(e) = out {
        return (launcher, Probe::LauncherFailed(e.to_string()));
    }
    (launcher, finish(dir))
}

/// 手法1: `runas /trustlevel:0x20000`（SAFER の NormalUser レベル）。
/// 引き継ぎ資料が「最初に打つもの」として名指ししている手法。
fn probe_runas(dir: &Path, wrapper: &Path) -> (String, Probe) {
    let out = Command::new(system32("runas.exe"))
        .arg("/trustlevel:0x20000")
        .arg(format!("{} /c {}", system32("cmd.exe"), wrapper.display()))
        .output();
    let launcher = match &out {
        Ok(o) => format!(
            "runas -> exit {:?} | stdout={:?} | stderr={:?}",
            o.status.code(),
            String::from_utf8_lossy(&o.stdout).trim(),
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!("runas -> {e}"),
    };
    if let Err(e) = out {
        return (launcher, Probe::LauncherFailed(e.to_string()));
    }
    (launcher, finish(dir))
}

/// 手法2: 対話ユーザーの`explorer.exe`に開かせる（explorerは中ILの非昇格プロセスなので、
/// その子も非昇格になる）。**対話セッションのexplorerが動いていることが前提**で、
/// 無人実行では成立しない可能性がある——それ自体も測る対象。
fn probe_explorer(dir: &Path, wrapper: &Path) -> (String, Probe) {
    // `explorer.exe`は`System32`ではなく**Windowsディレクトリ直下**にある
    // （最初の実行で`os error 2`を出したのはこの取り違え）。
    let out = Command::new(format!(r"{}\explorer.exe", windir()))
        .arg(wrapper)
        .output();
    let launcher = match &out {
        // explorerは委譲して即座に戻る（終了コードは意味を持たない）。
        Ok(o) => format!("explorer -> exit {:?} (delegated, not meaningful)", o.status.code()),
        Err(e) => format!("explorer -> {e}"),
    };
    if let Err(e) = out {
        return (launcher, Probe::LauncherFailed(e.to_string()));
    }
    (launcher, finish(dir))
}

/// 手法3: 自分の昇格トークンの**linked token**（UACの分割トークンの、絞られた方）を取り出し、
/// `CreateProcessWithTokenW`で子を起こす。手法1/2と違い、
/// **子は自分のプロセスの子のまま**（E2Eで待ち合わせ・kill・stdio取得ができる形）。
fn probe_linked_token(dir: &Path, wrapper: &Path) -> (String, Probe) {
    let cmdline = format!("{} /c {}", system32("cmd.exe"), wrapper.display());
    match unsafe { spawn_with_linked_token(&cmdline) } {
        Err(e) => ("CreateProcessWithTokenW".to_string(), Probe::LauncherFailed(e)),
        Ok(pid) => (
            format!("CreateProcessWithTokenW -> pid {pid}"),
            finish(dir),
        ),
    }
}

/// 手法4: **対話ユーザーのシェル（`explorer.exe`）のトークンを複製して**子を起こす。
/// M3が使えないのは「自分のlinked tokenを*primaryとして*取り出すには`SeTcbPrivilege`が要る」
/// という制限のためだが、**他プロセスのトークンなら`TOKEN_DUPLICATE`で開けば済む**。
/// 昇格した管理者は中ILの自プロセスを開けるので、この非対称が効く。
fn probe_shell_token(dir: &Path, wrapper: &Path) -> (String, Probe) {
    let cmdline = format!("{} /c {}", system32("cmd.exe"), wrapper.display());
    match unsafe { spawn_with_shell_token(&cmdline) } {
        Err(e) => ("shell token".to_string(), Probe::LauncherFailed(e)),
        Ok(pid) => (format!("shell token -> pid {pid}"), finish(dir)),
    }
}

/// 手法5: **UACの絞られたトークンを自前で組み立てる**。自分のトークンを複製し、
/// `CreateRestrictedToken`でAdministratorsをdeny-onlyにして特権を落とし、
/// さらに**integrity levelをMediumへ下げて**から`CreateProcessAsUserW`で起こす。
///
/// M1（`runas /trustlevel`）が非昇格にならなかったのは**ILがHighのまま**だったからで、
/// ここはその1点だけを変えた対照でもある（B-29: 一度に1変数）。
///
/// `CreateProcessAsUserW`は通常`SeAssignPrimaryTokenPrivilege`を要求するが、
/// **呼び出し元自身のトークンから作った制限トークン**の場合は不要である（`SeIncreaseQuotaPrivilege`
/// だけで足り、そちらは管理者が持つ）。
fn probe_filtered_token(dir: &Path, wrapper: &Path) -> (String, Probe) {
    let cmdline = format!("{} /c {}", system32("cmd.exe"), wrapper.display());
    match unsafe { spawn_with_filtered_token(&cmdline) } {
        Err(e) => ("filtered token".to_string(), Probe::LauncherFailed(e)),
        Ok((pid, api)) => (format!("filtered token via {api} -> pid {pid}"), finish(dir)),
    }
}

/// 起動後の共通処理: 完了印を待ってから事実を読む。
fn finish(dir: &Path) -> Probe {
    let rc = dir.join("rc.txt");
    if !wait_for(&rc, CHILD_TIMEOUT) {
        // タイムアウトでも`collect`を通す——`groups.txt`の有無で理由が分かれるため。
        return match collect(dir) {
            Ok(facts) => Probe::Ran(facts),
            Err(e) => Probe::NoResult(format!("timed out after {CHILD_TIMEOUT:?}: {e}")),
        };
    }
    // `rc.txt`が見えた直後は`out.txt`/`err.txt`の書き込みが完了している（ラッパーは
    // その2つを書き終えてから`rc.txt`を書く）。
    match collect(dir) {
        Ok(facts) => Probe::Ran(facts),
        Err(e) => Probe::NoResult(e),
    }
}

/// 自プロセスの昇格トークンからlinked token（＝UACに絞られた方）を取り、primaryへ複製して
/// `CreateProcessWithTokenW`する。成功したら子のPIDを返す。
///
/// `CreateProcessWithTokenW`は`SeImpersonatePrivilege`を要求する（昇格した管理者は持つ）。
/// `CreateProcessAsUserW`ではないのは、あちらが要求する`SeAssignPrimaryTokenPrivilege`を
/// 管理者トークンが既定で持たないためである。
unsafe fn spawn_with_linked_token(cmdline: &str) -> Result<u32, String> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, DuplicateTokenEx, SecurityImpersonation, TokenLinkedToken,
        TokenPrimary, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_LINKED_TOKEN, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{
        CreateProcessWithTokenW, GetCurrentProcess, OpenProcessToken,
        CREATE_PROCESS_LOGON_FLAGS, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
    };

    let mut token = HANDLE::default();
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut token)
        .map_err(|e| format!("OpenProcessToken: {e}"))?;

    let mut linked = TOKEN_LINKED_TOKEN::default();
    let mut len = 0u32;
    let queried = GetTokenInformation(
        token,
        TokenLinkedToken,
        Some(&mut linked as *mut _ as *mut _),
        std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32,
        &mut len,
    );
    let _ = CloseHandle(token);
    queried.map_err(|e| {
        format!("GetTokenInformation(TokenLinkedToken): {e} -- this token has no linked (filtered) token")
    })?;

    let mut primary = HANDLE::default();
    let dup = DuplicateTokenEx(
        linked.LinkedToken,
        TOKEN_ALL_ACCESS,
        None,
        SecurityImpersonation,
        TokenPrimary,
        &mut primary,
    );
    let _ = CloseHandle(linked.LinkedToken);
    dup.map_err(|e| format!("DuplicateTokenEx: {e}"))?;

    let mut wide: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();
    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    let created = CreateProcessWithTokenW(
        primary,
        CREATE_PROCESS_LOGON_FLAGS(0),
        None,
        windows::core::PWSTR(wide.as_mut_ptr()),
        CREATE_UNICODE_ENVIRONMENT,
        None,
        None,
        &si,
        &mut pi,
    );
    let _ = CloseHandle(primary);
    created.map_err(|e| format!("CreateProcessWithTokenW: {e}"))?;
    let pid = pi.dwProcessId;
    let _ = CloseHandle(pi.hThread);
    let _ = CloseHandle(pi.hProcess);
    Ok(pid)
}

/// 対話デスクトップのシェル（`explorer.exe`）のトークンを複製してprimary化し、
/// `CreateProcessWithTokenW`で起こす。PIDは`GetShellWindow`のウィンドウ所有者から取る
/// （プロセス列挙のためだけに`ToolHelp`を有効化しない）。
unsafe fn spawn_with_shell_token(cmdline: &str) -> Result<u32, String> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        DuplicateTokenEx, SecurityImpersonation, TokenPrimary, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE,
        TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{
        CreateProcessWithTokenW, OpenProcess, OpenProcessToken, CREATE_PROCESS_LOGON_FLAGS,
        PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION, STARTUPINFOW,
    };
    use windows::Win32::UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId};

    let hwnd = GetShellWindow();
    if hwnd.0.is_null() {
        return Err("GetShellWindow returned NULL: no interactive shell on this desktop".to_string());
    }
    let mut pid = 0u32;
    GetWindowThreadProcessId(hwnd, Some(&mut pid));
    if pid == 0 {
        return Err("GetWindowThreadProcessId returned pid 0".to_string());
    }

    let process = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)
        .map_err(|e| format!("OpenProcess(shell pid {pid}): {e}"))?;
    let mut token = HANDLE::default();
    let opened = OpenProcessToken(process, TOKEN_DUPLICATE | TOKEN_QUERY, &mut token);
    let _ = CloseHandle(process);
    opened.map_err(|e| format!("OpenProcessToken(shell pid {pid}): {e}"))?;

    let mut primary = HANDLE::default();
    let dup = DuplicateTokenEx(
        token,
        TOKEN_ALL_ACCESS,
        None,
        SecurityImpersonation,
        TokenPrimary,
        &mut primary,
    );
    let _ = CloseHandle(token);
    dup.map_err(|e| format!("DuplicateTokenEx(shell token): {e}"))?;

    let mut wide: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();
    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    let created = CreateProcessWithTokenW(
        primary,
        CREATE_PROCESS_LOGON_FLAGS(0),
        None,
        windows::core::PWSTR(wide.as_mut_ptr()),
        PROCESS_CREATION_FLAGS(0),
        None,
        None,
        &si,
        &mut pi,
    );
    let _ = CloseHandle(primary);
    created.map_err(|e| format!("CreateProcessWithTokenW(shell token): {e}"))?;
    let child = pi.dwProcessId;
    let _ = CloseHandle(pi.hThread);
    let _ = CloseHandle(pi.hProcess);
    Ok(child)
}

/// 自分のトークンから「UACに絞られたトークン」を組み立てて子を起こす。
/// 戻り値には**どのAPIで起きたか**も含める（`CreateProcessAsUserW`が通ったのか、
/// 退避先の`CreateProcessWithTokenW`だったのかで、E2Eで使える形が変わる）。
unsafe fn spawn_with_filtered_token(cmdline: &str) -> Result<(u32, &'static str), String> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows::Win32::Security::{
        CreateRestrictedToken, SetTokenInformation, TokenIntegrityLevel, DISABLE_MAX_PRIVILEGE,
        PSID, SID_AND_ATTRIBUTES, TOKEN_MANDATORY_LABEL,
    };
    use windows::Win32::System::SystemServices::SE_GROUP_INTEGRITY;
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, CreateProcessWithTokenW, GetCurrentProcess, OpenProcessToken,
        CREATE_PROCESS_LOGON_FLAGS, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
    };
    use windows::Win32::Security::{TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY};

    let mut token = HANDLE::default();
    OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
        &mut token,
    )
    .map_err(|e| format!("OpenProcessToken(self): {e}"))?;

    // Administrators（S-1-5-32-544）をdeny-onlyへ落とし、併せて全特権を外す。
    let admins_w: Vec<u16> = "S-1-5-32-544"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut admins = PSID::default();
    ConvertStringSidToSidW(windows::core::PCWSTR(admins_w.as_ptr()), &mut admins)
        .map_err(|e| format!("ConvertStringSidToSidW(Administrators): {e}"))?;
    let disable = [SID_AND_ATTRIBUTES {
        Sid: admins,
        Attributes: 0,
    }];
    let mut restricted = HANDLE::default();
    let made = CreateRestrictedToken(
        token,
        DISABLE_MAX_PRIVILEGE,
        Some(&disable),
        None,
        None,
        &mut restricted,
    );
    let _ = CloseHandle(token);
    if let Err(e) = made {
        let _ = LocalFree(HLOCAL(admins.0));
        return Err(format!("CreateRestrictedToken: {e}"));
    }

    // **ILを下げるのがM1との唯一の差**。ここを飛ばすとHighのままで、実測どおり
    // `TokenIsElevated`は真を返し続ける。
    let medium_w: Vec<u16> = "S-1-16-8192"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut medium = PSID::default();
    let converted = ConvertStringSidToSidW(windows::core::PCWSTR(medium_w.as_ptr()), &mut medium);
    let _ = LocalFree(HLOCAL(admins.0));
    converted.map_err(|e| format!("ConvertStringSidToSidW(medium IL): {e}"))?;
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: medium,
            Attributes: SE_GROUP_INTEGRITY as u32,
        },
    };
    let labeled = SetTokenInformation(
        restricted,
        TokenIntegrityLevel,
        &label as *const _ as *const _,
        std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32,
    );
    let _ = LocalFree(HLOCAL(medium.0));
    if let Err(e) = labeled {
        let _ = CloseHandle(restricted);
        return Err(format!("SetTokenInformation(TokenIntegrityLevel=Medium): {e}"));
    }

    let mut wide: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();
    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    let as_user = CreateProcessAsUserW(
        restricted,
        None,
        windows::core::PWSTR(wide.as_mut_ptr()),
        None,
        None,
        false,
        PROCESS_CREATION_FLAGS(0),
        None,
        None,
        &si,
        &mut pi,
    );
    let api = match as_user {
        Ok(()) => "CreateProcessAsUserW",
        Err(as_user_err) => {
            // 退避先。`CreateProcessAsUserW`が特権不足で落ちた場合でも
            // `CreateProcessWithTokenW`（`SeImpersonatePrivilege`）なら通ることがある。
            let mut wide2: Vec<u16> =
                cmdline.encode_utf16().chain(std::iter::once(0)).collect();
            let with_token = CreateProcessWithTokenW(
                restricted,
                CREATE_PROCESS_LOGON_FLAGS(0),
                None,
                windows::core::PWSTR(wide2.as_mut_ptr()),
                PROCESS_CREATION_FLAGS(0),
                None,
                None,
                &si,
                &mut pi,
            );
            if let Err(with_token_err) = with_token {
                let _ = CloseHandle(restricted);
                return Err(format!(
                    "CreateProcessAsUserW: {as_user_err} / CreateProcessWithTokenW: {with_token_err}"
                ));
            }
            "CreateProcessWithTokenW (CreateProcessAsUserW failed)"
        }
    };
    let _ = CloseHandle(restricted);
    let child = pi.dwProcessId;
    let _ = CloseHandle(pi.hThread);
    let _ = CloseHandle(pi.hProcess);
    Ok((child, api))
}

#[test]
#[ignore = "実機測定。dev-elevated-run.exe spike-deelevation で昇格して走らせる"]
fn can_the_elevated_runner_start_a_non_elevated_child() {
    let harness = harness_exe();
    assert!(
        harness.is_file(),
        "harness.exe が {} に無い。先に `dev-elevated-run.exe workspace-build` を打つこと",
        harness.display()
    );

    // §21.4: **測定対象を取り違えないこと。** 非昇格のシェルから走らせると、どの手法も
    // 「非昇格の子ができた」と報告するが、それは何も測っていない。
    assert!(
        super::privhelper::is_elevated(),
        "このテストプロセスが昇格していない。測っているのは『昇格したプロセスから非昇格の子を \
         起こせるか』なので、非昇格で走らせた結果には意味が無い（plans/etw-spike/RESULTS.md \
         §21.4）。`dev-elevated-run.exe spike-deelevation` で実行すること"
    );
    println!("test process: is_elevated()=true (measurement is meaningful)");
    println!("harness.exe : {}", harness.display());
    println!("spike root  : {SPIKE_ROOT}");

    assert!(
        !SPIKE_ROOT.contains(' '),
        "SPIKE_ROOT に空白があると runas への引用が入れ子になる: {SPIKE_ROOT}"
    );

    let root = PathBuf::from(SPIKE_ROOT);
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create the spike root");

    type ProbeFn = fn(&Path, &Path) -> (String, Probe);
    let methods: &[(&str, ProbeFn)] = &[
        ("M0 plain child (POSITIVE CONTROL)", probe_plain),
        ("M1 runas /trustlevel:0x20000", probe_runas),
        ("M2 explorer.exe delegation", probe_explorer),
        ("M3 linked token + CreateProcessWithTokenW", probe_linked_token),
        ("M4 shell (explorer) token + CreateProcessWithTokenW", probe_shell_token),
        ("M5 self-built filtered token (deny-only admins + medium IL)", probe_filtered_token),
    ];

    let mut results: Vec<(&str, Probe)> = Vec::new();
    for (name, f) in methods {
        let dir = root.join(name.split_whitespace().next().expect("method id"));
        std::fs::create_dir_all(&dir).expect("create the method directory");
        let wrapper = write_wrapper(&dir, &harness);
        let (launcher, probe) = f(&dir, &wrapper);
        report(name, &launcher, &probe);
        results.push((name, probe));
    }

    // 型B（件数で測る）: 手法を足したのに測らずに素通りする形を作らない。
    assert_eq!(
        results.len(),
        methods.len(),
        "全手法を測っていない（フィルタや早期returnで抜けた手法がある）"
    );

    // **計器の検証**（§18.5の対照）。素の子で警告が出ないなら、以降の
    // 「警告が無い＝非昇格」は一切信用できない。
    let (_, control) = &results[0];
    match control {
        Probe::Ran(f) => {
            assert!(
                f.ran_ok,
                "正の対照の子が正常に走っていない（rc={}）。計器（harness --help）が壊れている",
                f.rc
            );
            assert!(
                f.elevated,
                "正の対照（昇格プロセスの素の子）に昇格警告が出なかった。\
                 `{ELEVATED_MARKER}` を出す経路が消えたか文言が変わっている。\
                 この状態では『警告が無い＝非昇格』と読めないので、測定は不成立"
            );
        }
        other => panic!("正の対照が走らなかった: {other:?}。測定不成立"),
    }

    println!("======== VERDICT ========");
    let winners: Vec<&str> = results
        .iter()
        .skip(1)
        .filter(|(_, p)| p.is_usable_non_elevated())
        .map(|(name, _)| *name)
        .collect();
    if winners.is_empty() {
        println!(
            "NO METHOD produced a usable non-elevated child from the elevated runner. \
             シナリオ(A)のE2Eは、この形（昇格した dev-elevated-runner の下で harness を \
             非昇格で起こす）では成立しない。"
        );
    } else {
        println!("usable non-elevated child via: {}", winners.join(" | "));
    }

    // 型F: 実機に何も残さない。パニックした場合だけ、調査のために残る。
    let _ = std::fs::remove_dir_all(&root);
}
