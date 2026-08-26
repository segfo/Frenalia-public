//! **制限SID（`SidsToRestrict`）を指定したトークンで、非管理者のまま子を起こせるか**
//! （[`plans/HANDOFF-FS-BOUNDARY-STATIC-ACE.md`](../../../../../plans/HANDOFF-FS-BOUNDARY-STATIC-ACE.md)
//! の「次に測ること」5番＝案A-3の前提）。
//!
//! # なぜ先にこれを測るのか
//!
//! [BUG-003](../../../../docs/bugs/BUG-003.md)が実機で確かめたのは、
//! 「`OpenProcessToken`で得たプライマリトークンへ**直接**`CreateRestrictedToken`を適用した
//! 制限トークンなら、`CreateProcessAsUserW`が`SeAssignPrimaryTokenPrivilege`を要求しない」
//! という特例である。**その実測は制限SIDが`None`のときのもの**で、実際Tier1の実装は
//! `CreateRestrictedToken(token, DISABLE_MAX_PRIVILEGE, None, None, None, ...)`と
//! **SID制限機能を1つも使っていない**（[`crate::tier1::win_restricted`]のコメント）。
//!
//! **制限SIDを非空にしても同じ特例が効くかは測っていない。効かなければ案A-3は成立しない**
//! ——非管理者のharnessでは子が起動できないからである。
//!
//! # 何を測るか（**対照を必ず含める**、`bug-pattern-rules` B-35）
//!
//! | 腕 | トークンの作り方 | これで分かること |
//! |---|---|---|
//! | **A（対照）** | `DISABLE_MAX_PRIVILEGE`のみ・制限SID無し＝**今のTier1と同じ** | 計器が生きているか。ここが落ちたら他の腕は読めない |
//! | **B** | 制限SIDあり・フラグ無し | 制限SIDそのものが起動を壊すか |
//! | **C** | 制限SIDあり・`WRITE_RESTRICTED` | **A-3が使いたい形** |
//!
//! 起動できた腕については、続けて**書込の真理値表**を取る——読取は素通りし、書込は
//! 制限SIDを許可した場所にだけ落ちる、という`WRITE_RESTRICTED`の期待挙動が
//! **実際にそうなっているか**を見る。期待を書いて終わりにしない。
//!
//! # 置き場所について
//!
//! 主題はトークンの形（Tier1側の話）だが、**必要な部品（capability SIDの導出・ACE付与）が
//! ここに揃っている**ので、`t4_privhelper_pipe_reach_tests`（主題はパイプ）と同じ理由で
//! この階層へ置く。
//!
//! # 実行
//!
//! **昇格しない。** 昇格して回すと`SeAssignPrimaryTokenPrivilege`を持ってしまい、
//! **特例が効いたのか特権で通ったのかが区別できなくなる**（`bug-pattern-rules` B-08）。
//!
//! ```text
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture restricted_sid_probe
//! ```
//!
//! **判定が出たら本ファイルは削除する**（`docs/CODE-STRUCTURE-RULES.md`規則2）。

use std::path::Path;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Security::{
    CreateRestrictedToken, GetTokenInformation, TokenGroups, CREATE_RESTRICTED_TOKEN_FLAGS,
    DISABLE_MAX_PRIVILEGE, SID_AND_ATTRIBUTES, TOKEN_ACCESS_MASK, TOKEN_ADJUST_DEFAULT,
    TOKEN_ADJUST_GROUPS, TOKEN_ADJUST_PRIVILEGES, TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DUPLICATE, TOKEN_GROUPS, TOKEN_QUERY, WRITE_RESTRICTED,
};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken,
    WaitForSingleObject, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, INFINITE,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};

use super::test_support::TestDirGuard;
use super::*;
use crate::win_common::{
    build_env_block, clear_inherit, create_pipe_with_sddl, read_two_pipes_to_strings, wide,
};

/// `SE_GROUP_LOGON_ID`。ログオンSIDを見分けるための属性ビット。
const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;

/// `NT AUTHORITY\WRITE RESTRICTED`。`WRITE_RESTRICTED`トークンの書込判定で
/// **Windowsが暗黙に見る**とされる主体。**本当にそうかを本プローブで確かめる**
/// （期待を書いて終わりにしない）。
const WRITE_RESTRICTED_SID: &str = "S-1-5-33";

/// `NT AUTHORITY\RESTRICTED`。制限トークンの2周目判定でChromiumが使う古典的な主体。
/// **capability SIDが制限SIDとして拒否される**（実測）ため、A-3が使えるのはこちらになる。
const RESTRICTED_SID: &str = "S-1-5-12";

/// 自プロセスのプライマリトークンを、Tier1と**同じアクセスマスク**で開く。
/// マスクが違うと`CreateRestrictedToken`や`CreateProcessAsUserW`の可否が変わり得るので揃える。
fn open_own_primary_token() -> HANDLE {
    let mut token = HANDLE::default();
    unsafe {
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
            &mut token,
        )
        .expect("open own primary token");
    }
    token
}

/// トークンからログオンSIDを取り出す。
///
/// **なぜ要るか**: 制限トークンはウィンドウステーション／デスクトップへのアクセスも
/// 2周目の判定に掛ける。それらのDACLが許可しているのは**ログオンSID**なので、
/// 制限SIDに入れておかないと、FSとは無関係な理由で起動が落ちうる
/// （Chromiumのサンドボックスが同じことをしている確立された作法）。
/// **入れないと「制限SIDだから落ちた」と誤読する。**
fn logon_sid(token: HANDLE) -> Option<crate::win_common::OwnedSid> {
    unsafe {
        let mut needed: u32 = 0;
        let _ = GetTokenInformation(token, TokenGroups, None, 0, &mut needed);
        if needed == 0 {
            return None;
        }
        let mut buf = vec![0u8; needed as usize];
        GetTokenInformation(
            token,
            TokenGroups,
            Some(buf.as_mut_ptr() as *mut _),
            needed,
            &mut needed,
        )
        .ok()?;
        let groups = &*(buf.as_ptr() as *const TOKEN_GROUPS);
        let count = groups.GroupCount as usize;
        let entries = std::slice::from_raw_parts(groups.Groups.as_ptr(), count);
        for entry in entries {
            if entry.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID {
                return crate::win_common::OwnedSid::copy_from(entry.Sid).ok();
            }
        }
        None
    }
}

/// SDDL文字列からSIDを作る。
fn sid_from_string(sddl: &str) -> crate::win_common::OwnedSid {
    let s = wide(sddl);
    let mut psid = windows::Win32::Security::PSID::default();
    unsafe {
        windows::Win32::Security::Authorization::ConvertStringSidToSidW(
            PCWSTR(s.as_ptr()),
            &mut psid,
        )
        .unwrap_or_else(|e| panic!("convert {sddl}: {e}"));
    }
    let owned = unsafe { crate::win_common::OwnedSid::copy_from(psid) }.expect("copy sid");
    unsafe {
        let _ = windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(psid.0));
    }
    owned
}

/// 1つの腕の起動結果。**エラーは握り潰さず、Win32のコードごと持ち帰る**（B-10）。
#[derive(Debug)]
struct SpawnOutcome {
    spawned: bool,
    error: Option<String>,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// 指定の作り方でトークンを組み、`script`（`.cmd`ファイル）を`cmd.exe`で走らせる。
///
/// **`.cmd`ファイル経由にしてある**のは、コマンドラインの引用符の扱いで結果が変わるのを
/// 避けるため（`cmd.exe /c`の再トークン化は独特で、`win_restricted`のテストも
/// この罠を避けてPowerShellを選んでいる。ここでは引数を1つにして罠ごと消す）。
///
/// **パイプのDACLは制限SIDから組み立てる。** stdoutへ書くのは書込アクセスなので2周目の判定に
/// 掛かり、許可しないと出力が空になって「スクリプトが動かなかった」と誤読する。
/// 呼び出し側が別途SDDLを渡す形にすると、腕ごとに書き忘れて**全部Falseに見える**ので、
/// ここで一括して作る（`B-05`: コンパイラが守らない対応関係を作らない）。
fn spawn_with(
    flags: CREATE_RESTRICTED_TOKEN_FLAGS,
    restrict: &[windows::Win32::Security::PSID],
    script: &Path,
    cwd: &Path,
) -> SpawnOutcome {
    let mut pipe_sddl = String::from("D:(A;;GA;;;WD)");
    for sid in restrict {
        if let Ok(s) = crate::win_common::sid_to_string(*sid) {
            pipe_sddl.push_str(&format!("(A;;GA;;;{s})"));
        }
    }
    let pipe_sddl = pipe_sddl.as_str();
    let base = open_own_primary_token();
    let entries: Vec<SID_AND_ATTRIBUTES> = restrict
        .iter()
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: *sid,
            Attributes: 0,
        })
        .collect();

    let mut token = HANDLE::default();
    let create = unsafe {
        CreateRestrictedToken(
            base,
            flags,
            None,
            None,
            if entries.is_empty() {
                None
            } else {
                Some(entries.as_slice())
            },
            &mut token,
        )
    };
    unsafe {
        let _ = CloseHandle(base);
    }
    if let Err(e) = create {
        return SpawnOutcome {
            spawned: false,
            error: Some(format!("CreateRestrictedToken failed: {e}")),
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
        };
    }

    // **パイプにも制限SIDを許可する。** stdoutへ書くのは書込アクセスなので、
    // `WRITE_RESTRICTED`では2周目の判定に掛かる。許可しないと出力が空になり、
    // 「スクリプトが動かなかった」と誤読する（この罠を踏むと真理値表が全部Falseに見える）。
    let (stdout_read, stdout_write) = create_pipe_with_sddl(pipe_sddl).expect("stdout pipe");
    clear_inherit(stdout_read);
    let (stderr_read, stderr_write) = create_pipe_with_sddl(pipe_sddl).expect("stderr pipe");
    clear_inherit(stderr_read);

    let mut cmdline = wide(&format!("\"cmd.exe\" /c \"{}\"", script.display()));
    let cwd_w = wide(&cwd.to_string_lossy());
    let mut env_block = build_env_block(&crate::secret_env::build_child_env());

    let startup_info = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        hStdOutput: stdout_write,
        hStdError: stderr_write,
        hStdInput: INVALID_HANDLE_VALUE,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();

    let result = unsafe {
        CreateProcessAsUserW(
            token,
            PCWSTR::null(),
            PWSTR(cmdline.as_mut_ptr()),
            None,
            None,
            true,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            Some(env_block.as_mut_ptr() as *mut _),
            PCWSTR(cwd_w.as_ptr()),
            &startup_info,
            &mut pi,
        )
    };

    unsafe {
        let _ = CloseHandle(stdout_write);
        let _ = CloseHandle(stderr_write);
        let _ = CloseHandle(token);
    }

    if let Err(e) = result {
        unsafe {
            let _ = CloseHandle(stdout_read);
            let _ = CloseHandle(stderr_read);
        }
        return SpawnOutcome {
            spawned: false,
            error: Some(format!("CreateProcessAsUserW failed: {e}")),
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
        };
    }

    let (out, err) = read_two_pipes_to_strings(stdout_read, stderr_read);
    let code = unsafe {
        WaitForSingleObject(pi.hProcess, INFINITE);
        let mut c: u32 = 0;
        let _ = GetExitCodeProcess(pi.hProcess, &mut c);
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
        c as i32
    };

    SpawnOutcome {
        spawned: true,
        error: None,
        exit_code: Some(code),
        stdout: out,
        stderr: err,
    }
}

/// 起動できるかだけを見る最小のスクリプト。**依存を極小にする**——
/// PowerShell等の大きなプロセスを使うと、起動失敗が「トークンのせい」なのか
/// 「そのプログラムが制限下で動けないせい」なのかを分離できない。
fn write_minimal_script(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("spawn-probe.cmd");
    std::fs::write(&path, "@echo off\r\necho SPAWNED\r\nexit /b 7\r\n").expect("write script");
    path
}

/// 書込の真理値表を取るスクリプト。**読取の対照を必ず含める**（B-35）——
/// 全部Falseになったときに「制限が効いた」のか「そもそも走っていない」のかを分ける。
fn write_truth_table_script(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("write-probe.cmd");
    // **`>nul`・`2>nul`を使わない。** `NUL`はデバイスオブジェクトで、そこへ書くのも
    // 書込アクセスである——`WRITE_RESTRICTED`では2周目の判定に掛かる。最初の版は
    // 読取の対照を`type ... >nul`と書いたため、**読めなかったのか`NUL`へ書けなかったのか
    // 区別できず、対照が偽になった**（実測。stderrに拒否が4件出ていた）。
    // 読めたことは**内容がstdoutに出たか**で判定する。
    let body = format!(
        "@echo off\r\n\
         echo MARKER=alive\r\n\
         type \"{read_src}\"\r\n\
         echo.\r\n\
         echo x> \"{plain}\\a.txt\"\r\n\
         if exist \"{plain}\\a.txt\" (echo WRITE_PLAIN=True) else (echo WRITE_PLAIN=False)\r\n\
         echo x> \"{cap}\\a.txt\"\r\n\
         if exist \"{cap}\\a.txt\" (echo WRITE_CAP=True) else (echo WRITE_CAP=False)\r\n\
         echo x> \"{wr}\\a.txt\"\r\n\
         if exist \"{wr}\\a.txt\" (echo WRITE_WRSID=True) else (echo WRITE_WRSID=False)\r\n\
         echo x> \"{usr}\\a.txt\"\r\n\
         if exist \"{usr}\\a.txt\" (echo WRITE_USER=True) else (echo WRITE_USER=False)\r\n\
         exit /b 0\r\n",
        read_src = dir.join("readable.txt").display(),
        plain = dir.join("plain").display(),
        cap = dir.join("cap").display(),
        wr = dir.join("wrsid").display(),
        usr = dir.join("usrsid").display(),
    );
    std::fs::write(&path, body).expect("write script");
    path
}

fn says(out: &str, key: &str) -> Option<bool> {
    for line in out.lines() {
        if let Some(rest) = line.trim().strip_prefix(&format!("{key}=")) {
            return match rest.trim() {
                "True" => Some(true),
                "False" => Some(false),
                _ => None,
            };
        }
    }
    None
}

/// トークンのユーザーSIDを取り出す。
fn token_user_sid(token: HANDLE) -> Option<crate::win_common::OwnedSid> {
    use windows::Win32::Security::{TokenUser, TOKEN_USER};
    unsafe {
        let mut needed: u32 = 0;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        if needed == 0 {
            return None;
        }
        let mut buf = vec![0u8; needed as usize];
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            needed,
            &mut needed,
        )
        .ok()?;
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        crate::win_common::OwnedSid::copy_from(user.User.Sid).ok()
    }
}

/// **どのSIDなら制限SIDとして受け付けられるのか**を総当たりで割る。
///
/// # なぜこれが要るのか
///
/// 最初の測定は、capability SID（`S-1-15-3-…`）とログオンSIDを組で渡して
/// `CreateRestrictedToken`が`ERROR_INVALID_PARAMETER`で落ちた。**そこから
/// 「制限SIDは使えない」と結論してはいけない**——APIのシグネチャは実コードで照合して
/// 正しかったので、残る容疑は**渡したSIDの種類**である。
///
/// 1本ずつ渡して、通る種類と通らない種類を分ける。**トークンを作るだけで子は起こさない**ので
/// 実マシンには何も残らない。
#[test]
#[ignore = "creates restricted tokens only (no child processes); run NON-elevated"]
fn restricted_sid_probe_which_sid_kinds_are_accepted() {
    let base = open_own_primary_token();
    let logon = logon_sid(base);
    let user = token_user_sid(base);
    unsafe {
        let _ = CloseHandle(base);
    }
    let cap = super::capability_sid_from_name("harness-restricted-sid-probe")
        .expect("derive capability sid");

    let mut candidates: Vec<(&str, crate::win_common::OwnedSid)> = Vec::new();
    if let Some(u) = user {
        candidates.push(("token user SID", u));
    }
    if let Some(l) = logon {
        candidates.push(("logon SID", l));
    }
    for (label, sddl) in [
        ("RESTRICTED (S-1-5-12)", "S-1-5-12"),
        ("WRITE RESTRICTED (S-1-5-33)", WRITE_RESTRICTED_SID),
        ("Everyone (S-1-1-0)", "S-1-1-0"),
        ("Users (S-1-5-32-545)", "S-1-5-32-545"),
        ("NULL SID (S-1-0-0)", "S-1-0-0"),
    ] {
        candidates.push((label, sid_from_string(sddl)));
    }
    candidates.push(("capability SID (S-1-15-3-…)", cap));

    let mut rows = Vec::new();
    for (label, sid) in &candidates {
        for (flag_label, flags) in [
            ("none", CREATE_RESTRICTED_TOKEN_FLAGS(0)),
            ("WRITE_RESTRICTED", WRITE_RESTRICTED),
        ] {
            let entries = [SID_AND_ATTRIBUTES {
                Sid: sid.as_psid(),
                Attributes: 0,
            }];
            let token_in = open_own_primary_token();
            let mut out = HANDLE::default();
            let r = unsafe {
                CreateRestrictedToken(token_in, flags, None, None, Some(&entries), &mut out)
            };
            unsafe {
                let _ = CloseHandle(token_in);
            }
            let ok = r.is_ok();
            if ok {
                unsafe {
                    let _ = CloseHandle(out);
                }
            }
            rows.push(serde_json::json!({
                "sid": label,
                "sid_value": crate::win_common::sid_to_string(sid.as_psid()).unwrap_or_default(),
                "flags": flag_label,
                "accepted": ok,
                "error": r.err().map(|e| e.to_string()),
            }));
        }
    }

    println!(
        "{}",
        serde_json::json!({
            "measurement": "which SID kinds does CreateRestrictedToken accept as restricting SIDs",
            "rows": rows,
        })
    );

    // **1つも通らなかったら、それはSIDの種類の話ではなく呼び出しの話である。**
    // どれか1つでも通れば「種類による」と言えるので、その区別をここで固定する。
    assert!(
        rows.iter().any(|r| r["accepted"] == serde_json::json!(true)),
        "if no SID kind at all is accepted, the parameters themselves are wrong — do not read \
         this table as a statement about SID kinds: {rows:?}"
    );
}

/// **A-3の前提を1点で決める。** 判定に使うのは「起動できたか」だけで、時間は測らない。
#[test]
#[ignore = "spawns child processes with restricted tokens; run NON-elevated"]
fn restricted_sid_probe_can_a_restricted_sid_token_still_spawn() {
    let dir = TestDirGuard::create("restricted-sid");
    let root = dir.path();
    let script = write_minimal_script(root);

    let base = open_own_primary_token();
    let logon = logon_sid(base);
    unsafe {
        let _ = CloseHandle(base);
    }
    let logon = logon.expect("the token must carry a logon SID");
    let base = open_own_primary_token();
    let user = token_user_sid(base).expect("the token must carry a user SID");
    unsafe {
        let _ = CloseHandle(base);
    }
    // **capability SIDは制限SIDとして受け付けられない**（`restricted_sid_probe_which_sid_kinds_are_accepted`
    // の実測——`S-1-15-3-…`だけが`ERROR_INVALID_PARAMETER`で、他は全部通る）。
    let restricted = sid_from_string(RESTRICTED_SID);
    let wr = sid_from_string(WRITE_RESTRICTED_SID);

    // **制限SIDの集合を振る。** 最初の測定は`{RESTRICTED, ログオン}`だけで、起動はしたが
    // 子が`0xC0000142`（DLL初期化失敗）で即死した。**そこから「制限トークンでは動かない」と
    // 結論してはいけない**——プロセス起動時に触るオブジェクト（システムDLL・KnownDlls・
    // CSRSSのポート・デスクトップ）が、どの主体を許可しているかで決まるからである。
    // だから**集合を振って、どこから動き出すか**を見る。
    let configs: Vec<(&str, CREATE_RESTRICTED_TOKEN_FLAGS, Vec<windows::Win32::Security::PSID>)> = vec![
        (
            "control: DISABLE_MAX_PRIVILEGE only (today's Tier1)",
            DISABLE_MAX_PRIVILEGE,
            vec![],
        ),
        (
            "no flags; restrict={RESTRICTED, logon}",
            CREATE_RESTRICTED_TOKEN_FLAGS(0),
            vec![restricted.as_psid(), logon.as_psid()],
        ),
        (
            "no flags; restrict={user, logon} (A-2 baseline: no narrowing expected)",
            CREATE_RESTRICTED_TOKEN_FLAGS(0),
            vec![user.as_psid(), logon.as_psid()],
        ),
        (
            "WRITE_RESTRICTED; restrict={RESTRICTED, logon}",
            WRITE_RESTRICTED,
            vec![restricted.as_psid(), logon.as_psid()],
        ),
        (
            "WRITE_RESTRICTED; restrict={WRITE RESTRICTED, logon}",
            WRITE_RESTRICTED,
            vec![wr.as_psid(), logon.as_psid()],
        ),
        (
            "WRITE_RESTRICTED; restrict={WRITE RESTRICTED, RESTRICTED, logon}",
            WRITE_RESTRICTED,
            vec![wr.as_psid(), restricted.as_psid(), logon.as_psid()],
        ),
        (
            "WRITE_RESTRICTED; restrict={user, logon} (A-2 write-restricted)",
            WRITE_RESTRICTED,
            vec![user.as_psid(), logon.as_psid()],
        ),
    ];

    let mut rows = Vec::new();
    let mut control_ok = false;
    for (label, flags, restrict) in &configs {
        let outcome = spawn_with(*flags, restrict, &script, root);
        if label.starts_with("control") {
            control_ok = outcome.spawned
                && outcome.exit_code == Some(7)
                && outcome.stdout.contains("SPAWNED");
        }
        rows.push(serde_json::json!({
            "config": label,
            "create_token_ok": outcome.error.is_none(),
            "spawned": outcome.spawned,
            "error": outcome.error,
            // 7 = スクリプトが最後まで走った印。0xC0000142 (-1073741502) = DLL初期化失敗。
            "exit_code": outcome.exit_code,
            "exit_code_hex": outcome.exit_code.map(|c| format!("{:#010x}", c as u32)),
            "ran_the_script": outcome.stdout.contains("SPAWNED"),
            "stderr": outcome.stderr,
        }));
    }

    println!(
        "{}",
        serde_json::json!({
            "measurement": "which restricting-SID sets let a normal process actually start",
            "rows": rows,
        })
    );

    // **対照が生きているかを先に見る。** ここが落ちたら他の腕の結果は読めない。
    assert!(
        control_ok,
        "control arm (today's Tier1 shape) must spawn, run the script and reach exit 7: {rows:?}"
    );
}

/// **`WRITE_RESTRICTED`が実際に「読取は素通し・書込は制限SIDのある所だけ」になるか。**
///
/// 上のプローブが起動できることを示した場合にだけ意味を持つ。**期待を書いて終わりにしない**
/// ——読取の対照（`READ_OUTSIDE`）を必ず含め、全部Falseのときに
/// 「制限が効いた」と「走っていない」を分ける。
#[test]
#[ignore = "spawns child processes with restricted tokens; run NON-elevated"]
fn restricted_sid_probe_write_restricted_truth_table() {
    let dir = TestDirGuard::create("restricted-sid-table");
    let root = dir.path();

    std::fs::write(root.join("readable.txt"), b"hello").expect("seed a readable file");
    for name in ["plain", "cap", "wrsid", "usrsid"] {
        std::fs::create_dir_all(root.join(name)).expect("seed dirs");
    }

    let base = open_own_primary_token();
    let logon = logon_sid(base);
    unsafe {
        let _ = CloseHandle(base);
    }
    let logon = logon.expect("the token must carry a logon SID");
    let restricted = sid_from_string(RESTRICTED_SID);
    let wr = sid_from_string(WRITE_RESTRICTED_SID);
    let mask = fs_access_mask(FsAccess::ReadWrite);

    // 片方の腕にだけ`RESTRICTED`（＝制限SIDに入れた主体）、もう片方にだけ`WRITE RESTRICTED`を許可する。
    // **どちらのSIDが書込判定を満たすのか**を、推測ではなく出力で決めるための対である
    // （`WRITE_RESTRICTED`が`S-1-5-33`を暗黙に見る、という説の真偽もここで決まる）。
    super::grant_ace_mask_for_test(
        &root.join("cap"),
        restricted.as_psid(),
        mask,
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
    )
    .expect("grant RESTRICTED sid on cap/");
    super::grant_ace_mask_for_test(
        &root.join("wrsid"),
        wr.as_psid(),
        mask,
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
    )
    .expect("grant WRITE RESTRICTED sid on wrsid/");

    let script = write_truth_table_script(root);
    // **実際にプロセスが起動できる唯一の構成で測る**（上のプローブの実測）。
    // `{RESTRICTED, ログオン}`や`{WRITE RESTRICTED, ログオン}`は`0xC0000142`で即死するので、
    // そちらで表を取っても「制限が効いた」ではなく「起動していない」を測ることになる。
    let base2 = open_own_primary_token();
    let user = token_user_sid(base2).expect("token user sid");
    unsafe {
        let _ = CloseHandle(base2);
    }
    // **書込側の陽性対照**（B-35）。制限SIDに入れた主体（ユーザーSID）を直接許可した場所。
    // ここが書けなければ「制限が効いた」ではなく「そもそも書けない」を測っている。
    super::grant_ace_mask_for_test(
        &root.join("usrsid"),
        user.as_psid(),
        mask,
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
    )
    .expect("grant the user sid on usrsid/");
    let outcome = spawn_with(
        WRITE_RESTRICTED,
        &[user.as_psid(), logon.as_psid()],
        &script,
        root,
    );

    println!(
        "{}",
        serde_json::json!({
            "measurement": "does WRITE_RESTRICTED let reads through and confine writes to the restricting SID",
            "spawned": outcome.spawned,
            "error": outcome.error,
            "exit_code": outcome.exit_code,
            // 読取の対照は**内容が出たか**で見る（`>nul`を挟むと書込の可否と混ざる）。
            "read_outside": outcome.stdout.contains("hello"),
            "write_plain_no_extra_ace": says(&outcome.stdout, "WRITE_PLAIN"),
            "write_dir_granting_capability_sid": says(&outcome.stdout, "WRITE_CAP"),
            "write_dir_granting_write_restricted_sid": says(&outcome.stdout, "WRITE_WRSID"),
            "write_dir_granting_the_restricting_user_sid_POSITIVE_CONTROL":
                says(&outcome.stdout, "WRITE_USER"),
            "stdout": outcome.stdout,
            "stderr": outcome.stderr,
        })
    );

    // 撤収（付与と撤収は対、B-01）。ツリーは`TestDirGuard`がDropで消す。
    for (name, sid) in [("cap", restricted.as_psid()), ("wrsid", wr.as_psid()), ("usrsid", user.as_psid())] {
        let _ = revoke_ace_recursive(&root.join(name), sid);
    }

    // **結論を書く前に「走ったこと」を確かめる**（B-35）。ここが偽なら真理値表は読めない。
    assert!(
        outcome.spawned,
        "this table only means something if the child actually started: {outcome:?}"
    );
    assert!(
        outcome.stdout.contains("MARKER=alive"),
        "the child's stdout must reach us before any False can be read as a denial: {outcome:?}"
    );
}
