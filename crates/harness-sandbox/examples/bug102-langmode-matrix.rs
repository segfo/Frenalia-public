//! BUG-102の切り分け用の1差分測定（B-29）。**製品コードではなく測定器である。**
//!
//! Tier1経由のPowerShellだけがConstrainedLanguageに落ちる原因が
//! 「低IL」なのか「`CreateRestrictedToken`による特権剥奪」なのかを、
//! 2つのノブを1つずつ動かして確定する。
//!
//! | 条件 | トークン | 低IL |
//! |---|---|---|
//! | A  | 細工なし（`std::process::Command`） | – |
//! | A' | `CreateRestrictedToken`（フラグ0＝何も制限しない派生） | – |
//! | B  | 同上 | ✓ |
//! | C  | `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` | – |
//! | D  | 同上 | ✓ ＝ Tier1と同じ組み合わせ |
//! | D-prod | **製品の`win_restricted::spawn`をそのまま呼ぶ** | ✓ |
//!
//! `D`（この測定器が自前で組んだトークン）と`D-prod`（製品経路）が食い違ったら、
//! 引き金はトークンではなくその周辺（envブロック・Job Object・パイプ）にある。
//!
//! 子は`$ExecutionContext.SessionState.LanguageMode`を**終了コード**（10=Full・20=Constrained・
//! 99=その他）と**ファイル**の両方へ出す。ConstrainedLanguageでは標準出力へ出す前に
//! 落ちる構文があり得るため、コマンドの成否に依存しない終了コードを一次チャネルにする。
//!
//! 実行: `cargo run -p harness-sandbox --example bug102-langmode-matrix`

#[cfg(not(windows))]
fn main() {
    eprintln!("this probe is Windows-only (BUG-102 is a Windows WDAC/PowerShell issue)");
}

#[cfg(windows)]
fn main() {
    win::run();
}

#[cfg(windows)]
mod win {
    use std::path::{Path, PathBuf};

    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows::Win32::Security::{
        CreateRestrictedToken, SetTokenInformation, TokenIntegrityLevel,
        CREATE_RESTRICTED_TOKEN_FLAGS, DISABLE_MAX_PRIVILEGE, PSID, SID_AND_ATTRIBUTES,
        TOKEN_ACCESS_MASK, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_GROUPS, TOKEN_ADJUST_PRIVILEGES,
        TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL,
        TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken,
        WaitForSingleObject, CREATE_NO_WINDOW, INFINITE, PROCESS_INFORMATION, STARTUPINFOW,
    };

    /// 子で走らせるプローブ。**二重引用符を含めない**（コマンドラインの引用を単純に保つため）。
    const PROBE: &str = "$m = [string]$ExecutionContext.SessionState.LanguageMode; \
         $o = $env:HARNESS_LANGMODE_OUT; \
         if ($o) { Set-Content -LiteralPath $o -Value $m -Encoding ascii }; \
         if ($m -eq 'FullLanguage') { exit 10 } \
         elseif ($m -eq 'ConstrainedLanguage') { exit 20 } else { exit 99 }";

    const OUT_ENV: &str = "HARNESS_LANGMODE_OUT";
    const LOW_IL_SDDL: &str = "S-1-16-4096";
    const MEDIUM_IL_SDDL: &str = "S-1-16-8192";

    pub fn run() {
        let cwd = std::env::current_dir().expect("cwd");
        // 第2の使い方: 任意のスクリプトをTier1と同じトークンで走らせて素の出力を見る。
        // 起動スクリプトの書き換え候補が ConstrainedLanguage を通るかを1文ずつ測るのに使う。
        let args: Vec<String> = std::env::args().skip(1).collect();
        if let Some(script) = args.first() {
            run_script_under_tier1_token(script, &cwd);
            return;
        }
        let out_dir = std::env::temp_dir().join("harness-bug102-langmode");
        let _ = std::fs::create_dir_all(&out_dir);
        // 低ILの子でも書けるように、**製品と同じ関数**でラベルを付ける。
        if let Err(e) = harness_sandbox::tier1::win_restricted::set_low_integrity_label(&out_dir) {
            eprintln!("warn: low IL label on {} failed: {e}", out_dir.display());
        }
        println!("probe out dir: {}", out_dir.display());
        println!();
        println!("cond    restricted  lowIL  exit  file");
        println!("------  ----------  -----  ----  ----------------------");

        row("A", "-", "-", plain("pwsh", &out_dir, "a"));
        row(
            "A'",
            "-",
            "-",
            token_probe(false, None, "pwsh", &cwd, &out_dir, "aa"),
        );
        row(
            "B",
            "-",
            "low",
            token_probe(false, Some(LOW_IL_SDDL), "pwsh", &cwd, &out_dir, "b"),
        );
        row(
            "C",
            "yes",
            "-",
            token_probe(true, None, "pwsh", &cwd, &out_dir, "c"),
        );
        row(
            "D",
            "yes",
            "low",
            token_probe(true, Some(LOW_IL_SDDL), "pwsh", &cwd, &out_dir, "d"),
        );
        row("D-prod", "yes", "low", prod(&cwd, &out_dir, "dprod"));

        println!();
        println!("追加の対照（ILの値そのものが効いているか・5.1でも同じか）");
        // E: ラベルを**明示的にMedium**で書く。SetTokenInformationの呼び出し自体ではなく
        //    「値がLowであること」が引き金だと言うための対照（B-35: 消えた側だけでなく残る側も見る）。
        row(
            "E",
            "yes",
            "med",
            token_probe(true, Some(MEDIUM_IL_SDDL), "pwsh", &cwd, &out_dir, "e"),
        );
        // F: Windows PowerShell 5.1。Tier1のフォールバック先が生きているかどうか。
        row("F", "-", "-", plain("powershell", &out_dir, "f"));
        row(
            "G",
            "yes",
            "low",
            token_probe(true, Some(LOW_IL_SDDL), "powershell", &cwd, &out_dir, "g"),
        );
    }

    /// 与えられたスクリプトを**製品の`win_restricted::spawn`**（＝Tier1と同じ制限トークン+低IL）で
    /// 走らせ、stdout/stderr/終了コードをそのまま出す。`-Command -`ではなく`-Command <script>`で
    /// 渡すので、起動スクリプトの禁止構文に巻き込まれずに1文だけを測れる。
    fn run_script_under_tier1_token(script: &str, cwd: &Path) {
        let env: Vec<(String, String)> = std::env::vars().collect();
        let args = ["-NoProfile", "-NonInteractive", "-Command", script];
        match harness_sandbox::tier1::win_restricted::spawn("pwsh", &args, cwd, &env, false) {
            Ok(child) => match child.write_stdin_read_output_and_wait(None) {
                Ok((o, e, code)) => {
                    println!("--- exit: {code}");
                    println!("--- stdout:\n{o}");
                    println!("--- stderr:\n{e}");
                }
                Err(e) => println!("wait failed: {e}"),
            },
            Err(e) => println!("spawn failed: {e}"),
        }
    }

    fn row(cond: &str, restricted: &str, low_il: &str, r: (i32, String)) {
        println!(
            "{cond:<6}  {restricted:<10}  {low_il:<5}  {:<4}  {}",
            r.0, r.1
        );
    }

    fn out_path(dir: &Path, tag: &str) -> PathBuf {
        dir.join(format!("{tag}.txt"))
    }

    fn take_result(out: &Path, code: i32) -> (i32, String) {
        let text = std::fs::read_to_string(out)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|e| format!("<no file: {e}>"));
        (code, text)
    }

    /// A: トークン細工なし。この測定器自身が正しく測れていることの対照。
    fn plain(exe: &str, dir: &Path, tag: &str) -> (i32, String) {
        let out = out_path(dir, tag);
        let _ = std::fs::remove_file(&out);
        let status = std::process::Command::new(exe)
            .args(["-NoProfile", "-NonInteractive", "-Command", PROBE])
            .env(OUT_ENV, &out)
            .status();
        let code = match status {
            Ok(s) => s.code().unwrap_or(-1),
            Err(e) => {
                eprintln!("spawn failed: {e}");
                -1
            }
        };
        take_result(&out, code)
    }

    /// D-prod: 製品の`win_restricted::spawn`をそのまま呼ぶ（トークン・Job・パイプすべて製品実装）。
    fn prod(cwd: &Path, dir: &Path, tag: &str) -> (i32, String) {
        let out = out_path(dir, tag);
        let _ = std::fs::remove_file(&out);
        // 同名キーを2つ積むと環境ブロックの先勝ちで前の条件の出力先を拾ってしまうため、
        // 親から継承する分を先に落としてから足す。
        let mut env: Vec<(String, String)> =
            std::env::vars().filter(|(k, _)| k != OUT_ENV).collect();
        env.push((OUT_ENV.to_string(), out.display().to_string()));
        let args = ["-NoProfile", "-NonInteractive", "-Command", PROBE];
        match harness_sandbox::tier1::win_restricted::spawn("pwsh", &args, cwd, &env, false) {
            Ok(child) => match child.write_stdin_read_output_and_wait(None) {
                Ok((o, e, code)) => {
                    if !o.trim().is_empty() {
                        println!("  [D-prod stdout] {}", o.trim());
                    }
                    if !e.trim().is_empty() {
                        println!("  [D-prod stderr] {}", e.trim());
                    }
                    take_result(&out, code)
                }
                Err(e) => (-1, format!("<wait failed: {e}>")),
            },
            Err(e) => (-1, format!("<spawn failed: {e}>")),
        }
    }

    /// A'/B/C/D: ノブ2つを1つずつ動かす。envは親から継承させる（`lpEnvironment`=NULL）ので、
    /// 出力先だけ`set_var`で親へ入れてから起動する。
    fn token_probe(
        restricted: bool,
        il_sddl: Option<&str>,
        exe: &str,
        cwd: &Path,
        dir: &Path,
        tag: &str,
    ) -> (i32, String) {
        let out = out_path(dir, tag);
        let _ = std::fs::remove_file(&out);
        std::env::set_var(OUT_ENV, &out);

        let token = match build_token(restricted, il_sddl) {
            Ok(t) => t,
            Err(e) => return (-1, format!("<token failed: {e}>")),
        };

        let cmdline = format!(
            "\"{exe}\" \"-NoProfile\" \"-NonInteractive\" \"-Command\" \"{}\"",
            PROBE.replace('"', "\\\"")
        );
        let mut cmdline_w = wide(&cmdline);
        let cwd_w = wide(&cwd.to_string_lossy());
        let startup_info = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();

        let code = unsafe {
            let spawned = CreateProcessAsUserW(
                token,
                PCWSTR::null(),
                PWSTR(cmdline_w.as_mut_ptr()),
                None,
                None,
                false,
                CREATE_NO_WINDOW,
                None,
                PCWSTR(cwd_w.as_ptr()),
                &startup_info,
                &mut pi,
            );
            let _ = CloseHandle(token);
            match spawned {
                Ok(()) => {
                    WaitForSingleObject(pi.hProcess, INFINITE);
                    let mut c: u32 = 0;
                    let _ = GetExitCodeProcess(pi.hProcess, &mut c);
                    let _ = CloseHandle(pi.hProcess);
                    let _ = CloseHandle(pi.hThread);
                    c as i32
                }
                Err(e) => {
                    eprintln!("  CreateProcessAsUserW failed: {e}");
                    -1
                }
            }
        };
        take_result(&out, code)
    }

    /// `win_restricted::build_restricted_token`の2つのノブを独立に外せるようにしたもの。
    /// **製品の実装をここへ写した箇所である**（測定器なのでprivateを開けるより写す方を採る）。
    fn build_token(restricted: bool, il_sddl: Option<&str>) -> windows::core::Result<HANDLE> {
        unsafe {
            let mut process_token = HANDLE::default();
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ACCESS_MASK(
                    TOKEN_DUPLICATE.0
                        | TOKEN_QUERY.0
                        | TOKEN_ASSIGN_PRIMARY.0
                        | TOKEN_ADJUST_DEFAULT.0
                        | TOKEN_ADJUST_SESSIONID.0
                        | TOKEN_ADJUST_GROUPS.0
                        | TOKEN_ADJUST_PRIVILEGES.0,
                ),
                &mut process_token,
            )?;

            // 「自トークン由来の制限トークン」であることが`CreateProcessAsUserW`の特権免除の
            // 条件なので、特権剥奪しない条件でも`CreateRestrictedToken`自体は必ず通す
            // （フラグを0にするだけ）。ここを`DuplicateTokenEx`に替えると由来が切れて
            // 別物の測定になる（BUG-003）。
            let flags = if restricted {
                DISABLE_MAX_PRIVILEGE
            } else {
                CREATE_RESTRICTED_TOKEN_FLAGS(0)
            };
            let mut token = HANDLE::default();
            CreateRestrictedToken(process_token, flags, None, None, None, &mut token)?;
            let _ = CloseHandle(process_token);

            if let Some(sddl) = il_sddl {
                let low_sid_str = wide(sddl);
                let mut low_sid = PSID::default();
                ConvertStringSidToSidW(PCWSTR(low_sid_str.as_ptr()), &mut low_sid)?;
                let label = TOKEN_MANDATORY_LABEL {
                    Label: SID_AND_ATTRIBUTES {
                        Sid: low_sid,
                        Attributes: 0x2000_0000, // SE_GROUP_INTEGRITY
                    },
                };
                let result = SetTokenInformation(
                    token,
                    TokenIntegrityLevel,
                    &label as *const _ as *const _,
                    std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32,
                );
                let _ = LocalFree(HLOCAL(low_sid.0));
                result?;
            }

            Ok(token)
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
}
