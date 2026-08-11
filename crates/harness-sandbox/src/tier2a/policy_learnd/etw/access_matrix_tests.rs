//! **許可レベル × 操作種別の真理値表**を実機で埋める（`docs/STATUS.md`の項目`b`の追試）。
//!
//! 実行:
//! ```text
//! dev-elevated-run.exe etw-access-matrix
//! ```
//!
//! # 何を確かめたいのか
//!
//! ETWの`Create`は`DesiredAccess`を運ばない（RESULTS.md §3.1）。§12.4では同じファイルへの
//! **読み取りと削除の拒否がイベント上まったく同じ形**（`CreateDisposition=FILE_OPEN`）で
//! 現れ、区別できなかった。
//!
//! しかし**「何を許可済みか」と突き合わせれば**話が変わる。Windowsのアクセスチェックは
//! `DesiredAccess ⊆ granted`で成否が決まるので、拒否された＝「許可していないビットが
//! 要求に含まれていた」が確定する。
//!
//! | 許可済み | 拒否から言えること |
//! |---|---|
//! | なし | 何も分からない（どの操作でも拒否される） |
//! | read | 要求は`FILE_GENERIC_READ`の外を含む → 書込・削除・実行のいずれか |
//! | read+write | 要求は両者の外 → 実行（`FILE_EXECUTE`）かDACL書換系 |
//!
//! これが成立すれば、**4656に頼らずに提案の精度を上げられる**——特に
//! 「`fs.read`を足したのにまだ失敗する」というユーザー体験上いちばん困る状況で、
//! 「readでは足りない」と言えるようになる。
//!
//! # 2026-08-04の改訂: なぜ測り直すのか
//!
//! §15.2は拒否時の`CreateOptions`を表にしたが、**read/writeの行がどの許可レベルでの
//! 観測なのかを記録していなかった**（execだけ「read許可下」と明記されている）。
//! 内訳が無いと次の問いに答えられない。
//!
//! > 権限ゼロのとき、read/write/delete/execの拒否は**本当に全部同じ値**(`0x01200000`)になるのか。
//! > つまり「読取権すら無ければ、何を狙っても同じ形で潰れる」と言えるのか。
//!
//! 内訳が取れなかったのは**測り方の問題**だった。旧版はread/write/deleteが同じ`data.txt`を
//! 共有していたので、`[level/data]`に3操作の拒否が混ざって出ていた。本版では
//! **操作ごとに別ファイル**を用意し、`[level/op]`で厳密に対応付ける。
//!
//! # もう1つの軸: 同じ操作を別の呼び出し側で
//!
//! §15.2は「`CreateDisposition`は呼び出し側がどう開いたかであって要求したアクセス権ではない」
//! と述べたが、**それ自体は実測していない**。そこで同じ論理操作を2通りの呼び出し側で行う。
//!
//! - read: `Get-Content`（.NET `FileStream`）と `cmd.exe /c type`（Win32 `CreateFileW`）
//! - write: `Add-Content`（.NET追記）と `cmd.exe /c echo >`（Win32 `CREATE_ALWAYS`）
//!
//! **同じ操作・同じ許可レベルで値が割れたら、値から操作種別を導く方式は成立しない**
//! ——呼び出し側を選べるのは我々ではなくモデルが動かすプログラムだからである。
//! 割れなければ、逆に値は操作種別の信号として使える可能性が残る。
//!
//! マシンの状態は変えない（一時ディレクトリのACLのみ）。

use windows::Win32::Security::NO_INHERITANCE;
use windows::Win32::Storage::FileSystem::{
    DELETE, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_TRAVERSE,
};

use crate::shell_tier::WorkspaceWriteMode;
use crate::tier2a::win_appcontainer::test_support::spawn_in_workspace;
use crate::tier2a::win_appcontainer::{preflight, resolve_shell, NetworkCapability};

use super::parse::to_settings_path;
use super::session::EtwFsSession;
use super::volumes::drive_letter_map;

const WARMUP: std::time::Duration = std::time::Duration::from_millis(1500);
const DRAIN: std::time::Duration = std::time::Duration::from_secs(5);

/// 許可レベル3種。**ディレクトリには通過権だけを非継承で与え、ファイルへは個別に付与する**
/// ——`FILE_TRAVERSE`は`FILE_EXECUTE`と同じビット(0x20)なので、継承させると実行テストが
/// 汚染される（「何も許可していないファイル」のはずが実行可能になってしまう）。
struct Level {
    name: &'static str,
    file_mask: u32,
}

const LEVELS: [Level; 3] = [
    Level {
        name: "none",
        file_mask: 0,
    },
    Level {
        name: "read",
        file_mask: FILE_GENERIC_READ.0,
    },
    Level {
        name: "read+write",
        file_mask: FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
    },
];

/// 1操作＝1ファイル。**旧版がread/write/deleteで`data.txt`を共有していたのが内訳を
/// 潰していた原因**なので、ここは必ず分ける。
///
/// `exe`はコピーした`cmd.exe`、それ以外はテキストファイル。
struct Op {
    /// `[level/op]`の表示名。
    name: &'static str,
    /// 対象ファイル名。
    file: &'static str,
    /// 子で実行するPowerShell断片。`@P@`が対象パス、`@OK@`/`@NG@`が結果出力に置き換わる。
    /// **トークンを`@`で挟むのは誤置換を防ぐため**（素の`OK`だとパス中の文字列まで壊れる）。
    script: &'static str,
}

const OPS: [Op; 6] = [
    Op {
        name: "read_dotnet",
        file: "read_dotnet.txt",
        script: "try { Get-Content -LiteralPath '@P@' -ErrorAction Stop | Out-Null; @OK@ } catch { @NG@ }",
    },
    // 同じ「読む」を別の読み手で。`Get-Content`はPowerShellのプロバイダ層を通るが、
    // こちらは`FileStream`を直に開く。**同じ操作で値が割れるかが焦点**。
    //
    // ここは当初`cmd.exe /c type`で測るつもりだったが**成立しなかった**。`cmd`は祖先
    // ディレクトリを「通過」ではなく**オープン**するため、`C:/`・`C:/Users/`…の段階で
    // 拒否され、対象ファイルに到達しない（capability SIDの祖先grantは
    // `FILE_TRAVERSE|FILE_READ_ATTRIBUTES`のみ）。許可レベルを何にしても失敗し、
    // しかもファイルパスで絞る限り拒否は0件に見える。`write_cmd`が動くのは
    // リダイレクト先を開くだけで祖先を辿り直さないため。
    Op {
        name: "read_netfx",
        file: "read_netfx.txt",
        script: "try { [System.IO.File]::ReadAllBytes('@P@') | Out-Null; @OK@ } catch { @NG@ }",
    },
    Op {
        name: "write_dotnet",
        file: "write_dotnet.txt",
        script: "try { Add-Content -LiteralPath '@P@' -Value 'x' -ErrorAction Stop; @OK@ } catch { @NG@ }",
    },
    // cmdのリダイレクトは`CREATE_ALWAYS`＝`FILE_OVERWRITE_IF`(5)になるはず。
    // .NETの追記(`FILE_OPEN_IF`=3)と割れたら、dispositionは呼び出し側の都合だと確定する。
    Op {
        name: "write_cmd",
        file: "write_cmd.txt",
        script: "& cmd.exe /c \"echo x> @P@\"; if ($LASTEXITCODE -eq 0) { @OK@ } else { @NG@ }",
    },
    Op {
        name: "delete",
        file: "delete.txt",
        script: "try { Remove-Item -LiteralPath '@P@' -ErrorAction Stop; @OK@ } catch { @NG@ }",
    },
    Op {
        name: "exec",
        file: "exec.exe",
        script: "try { & '@P@' /c exit 2>&1 | Out-Null; if ($LASTEXITCODE -eq 0) { @OK@ } else { @NG@ } } catch { @NG@ }",
    },
];

/// `CreateOptions`の下位24bitを名前付きで展開する。
///
/// **手でビットを剥がす作業を出力側へ寄せる**ためのもの。§15.2の値（`0x01200000`等）は
/// 生のまま表に載っていたので、`FILE_OPEN_REPARSE_POINT`単独なのか
/// `FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT`なのかが読み取れなかった。
fn describe_create_options(create_options: u32) -> String {
    const FLAGS: [(u32, &str); 23] = [
        (0x0000_0001, "DIRECTORY_FILE"),
        (0x0000_0002, "WRITE_THROUGH"),
        (0x0000_0004, "SEQUENTIAL_ONLY"),
        (0x0000_0008, "NO_INTERMEDIATE_BUFFERING"),
        (0x0000_0010, "SYNCHRONOUS_IO_ALERT"),
        (0x0000_0020, "SYNCHRONOUS_IO_NONALERT"),
        (0x0000_0040, "NON_DIRECTORY_FILE"),
        (0x0000_0080, "CREATE_TREE_CONNECTION"),
        (0x0000_0100, "COMPLETE_IF_OPLOCKED"),
        (0x0000_0200, "NO_EA_KNOWLEDGE"),
        (0x0000_0400, "OPEN_REMOTE_INSTANCE"),
        (0x0000_0800, "RANDOM_ACCESS"),
        (0x0000_1000, "DELETE_ON_CLOSE"),
        (0x0000_2000, "OPEN_BY_FILE_ID"),
        (0x0000_4000, "OPEN_FOR_BACKUP_INTENT"),
        (0x0000_8000, "NO_COMPRESSION"),
        (0x0001_0000, "OPEN_REQUIRING_OPLOCK"),
        (0x0002_0000, "DISALLOW_EXCLUSIVE"),
        (0x0004_0000, "SESSION_AWARE"),
        (0x0010_0000, "RESERVE_OPFILTER"),
        (0x0020_0000, "OPEN_REPARSE_POINT"),
        (0x0040_0000, "OPEN_NO_RECALL"),
        (0x0080_0000, "OPEN_FOR_FREE_SPACE_QUERY"),
    ];
    let opts = create_options & 0x00FF_FFFF;
    let named: Vec<&str> = FLAGS
        .iter()
        .filter(|(bit, _)| opts & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if named.is_empty() {
        "(none)".to_string()
    } else {
        named.join("|")
    }
}

fn disposition_name(disposition: u32) -> &'static str {
    match disposition {
        0 => "SUPERSEDE/unset",
        1 => "OPEN",
        2 => "CREATE",
        3 => "OPEN_IF",
        4 => "OVERWRITE",
        5 => "OVERWRITE_IF",
        _ => "?",
    }
}

#[test]
#[ignore = "requires administrator rights (ETW) and creates an AppContainer profile; run via dev-elevated-run.exe etw-access-matrix"]
fn access_denials_by_granted_level_and_operation() {
    let workspace = tempfile::tempdir().expect("workspace");
    let outside = tempfile::tempdir().expect("outside");

    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
    let profile = crate::tier2a::session_profile::current_profile_name();
    let sid = crate::tier2a::win_appcontainer::ensure_profile(&profile).expect("package SID");

    // --- 各(レベル, 操作)のファイルを用意する ---
    let mut probes: Vec<(&'static str, &'static Op, std::path::PathBuf)> = Vec::new();
    for level in &LEVELS {
        let dir = outside.path().join(level.name.replace('+', "_"));
        std::fs::create_dir(&dir).expect("create the level dir");

        // ディレクトリ: 通過・属性読み・**列挙**・**子の削除**（**非継承**。中のファイルへは伝えない）。
        //
        // ここで与える権利は「測りたい対象（ファイル自身のACL）以外の理由で失敗しない」ための
        // 下地であり、**測定の交絡を潰すためにある**。実際に2つ踏んだ。
        //
        // - `FILE_DELETE_CHILD`が無いと、親側で削除が弾かれて「そもそも開けない」ケースしか
        //   見られない（§16がこれを踏んで§12.4の誤った結論を生んだ）
        // - `FILE_LIST_DIRECTORY`が無いと、`cmd /c type`が**ファイルではなくディレクトリで**
        //   拒否される（`type`はワイルドカードを取るのでパスを列挙して展開する）。
        //   この状態では許可レベルを何にしても失敗し、しかもファイルパスで絞る限り
        //   イベントは1件も見えない——「拒否0件なのに失敗する」という紛らわしい形になる
        crate::tier2a::win_appcontainer::grant_ace_mask_for_test(
            &dir,
            sid.as_psid(),
            // TRAVERSE | READ_ATTRIBUTES | DELETE_CHILD | LIST_DIRECTORY
            FILE_TRAVERSE.0 | 0x0080 | 0x0040 | 0x0001,
            NO_INHERITANCE,
        )
        .expect("grant traverse+list+delete_child on the level dir");

        for op in &OPS {
            let path = dir.join(op.file);
            if op.file.ends_with(".exe") {
                std::fs::copy(r"C:\Windows\System32\cmd.exe", &path).expect("copy the probe exe");
            } else {
                std::fs::write(&path, b"payload").expect("create the probe file");
            }
            if level.file_mask != 0 {
                crate::tier2a::win_appcontainer::grant_ace_mask_for_test(
                    &path,
                    sid.as_psid(),
                    level.file_mask,
                    NO_INHERITANCE,
                )
                .expect("grant the level mask on the file");
            }
            probes.push((level.name, op, path));
        }
    }

    let session = EtwFsSession::start("harness-policy-learn-access-matrix").expect("ETW session");
    std::thread::sleep(WARMUP);

    // --- AppContainer子から各(レベル, 操作)を1回ずつ試す ---
    let mut script = String::from("$ErrorActionPreference='SilentlyContinue';\n");
    for (level, op, path) in &probes {
        // 失敗時は`$LASTEXITCODE`も出す——`cmd`経由の操作が「アクセス拒否で落ちた」のか
        // 「そもそもコマンドラインが壊れていた」のかを結果だけで切り分けられるようにする。
        let body = op
            .script
            .replace("@OK@", &format!("Write-Output '{level}|{}|OK'", op.name))
            .replace(
                "@NG@",
                &format!(
                    "Write-Output ('{level}|{}|FAIL last=' + $LASTEXITCODE)",
                    op.name
                ),
            )
            .replace("@P@", &path.display().to_string());
        script.push_str(&body);
        script.push('\n');
    }

    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    let child = spawn_in_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", &script],
        workspace.path(),
        &env,
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        None,
    )
    .expect("spawn the AppContainer child");
    let child_pid = child.pid();
    let output = child.write_stdin_read_output_and_wait(None);

    std::thread::sleep(DRAIN);
    let (starts, denials) = session.drain();
    let outcome = session.stop();

    // **孫プロセスも対象に入れる。** `cmd.exe`経由の操作は子(PowerShell)ではなく孫のPIDで
    // 拒否が出るので、`pid == child_pid`で絞ると「拒否0件」に見えてしまう。
    // 本番の収集器が持つ「親が対象なら子も対象」（T-15）と同じ閉包をここでも作る。
    let mut family: std::collections::HashSet<u32> = std::collections::HashSet::new();
    family.insert(child_pid);
    loop {
        let before = family.len();
        for s in &starts {
            if s.parent_pid.is_some_and(|p| family.contains(&p)) {
                family.insert(s.pid);
            }
        }
        if family.len() == before {
            break;
        }
    }
    println!("=== process family (child pid={child_pid}) ===");
    for s in starts.iter().filter(|s| family.contains(&s.pid)) {
        println!(
            "  pid={} parent={:?} image={}",
            s.pid,
            s.parent_pid,
            s.image_name.as_deref().unwrap_or("?")
        );
    }

    // --- 1. 操作の成否（差分推論の前提） ---
    println!("=== operation results (as seen by the child, pid={child_pid}) ===");
    match &output {
        Ok((stdout, stderr, code)) => {
            for line in stdout.lines().filter(|l| l.contains('|')) {
                println!("  {}", line.trim());
            }
            if !stderr.trim().is_empty() {
                println!("  (stderr) {}", stderr.trim());
            }
            println!("  (exit code {code})");
        }
        Err(e) => println!("  child failed: {e}"),
    }

    // --- 2. (レベル, 操作)ごとの拒否イベント ---
    let volumes = drive_letter_map();
    println!(
        "=== Create-stage denials attributed to the child ({} total across all paths) ===",
        denials.len()
    );
    // **パス一致だけで拾う**（PIDでは絞らない）。プローブファイルは使い捨ての一時ディレクトリに
    // あり我々のプロセス以外は触らないので、これで取りこぼしも混入も無い。
    // どのPIDが開いたかは行ごとに表示して、家族の外から来ていないかを目で確かめられるようにする。
    for (level, op, path) in &probes {
        let expected = path.to_string_lossy().replace('\\', "/");
        let matching: Vec<_> = denials
            .iter()
            .filter(|d| {
                to_settings_path(&d.file_name, &volumes)
                    .is_some_and(|p| p.eq_ignore_ascii_case(&expected))
            })
            .collect();
        println!("  [{level}/{}] {} denial event(s)", op.name, matching.len());
        for d in &matching {
            let disposition = (d.create_options >> 24) & 0xFF;
            let who = if d.pid == child_pid {
                "child"
            } else if family.contains(&d.pid) {
                "descendant"
            } else {
                "OUTSIDE-FAMILY"
            };
            println!(
                "    CreateOptions={:#010x} disposition={disposition}({}) options={} inferred={:?} pid={}({who})",
                d.create_options,
                disposition_name(disposition),
                describe_create_options(d.create_options),
                d.access,
                d.pid
            );
        }
    }
    // プローブファイル以外で家族が食らった拒否。**「操作は失敗したのに対象ファイルの
    // 拒否が0件」という行の正体を突き止めるため**にある（別のパスで落ちている可能性）。
    let probe_paths: std::collections::HashSet<String> = probes
        .iter()
        .map(|(_, _, p)| p.to_string_lossy().replace('\\', "/").to_lowercase())
        .collect();
    println!("=== other denials hit by the family (not on a probe file) ===");
    let mut other: Vec<(u32, String)> = denials
        .iter()
        .filter(|d| family.contains(&d.pid))
        .filter_map(|d| {
            let p = to_settings_path(&d.file_name, &volumes)?;
            (!probe_paths.contains(&p.to_lowercase())).then_some((d.pid, p))
        })
        .collect();
    other.sort();
    other.dedup();
    for (pid, path) in &other {
        println!("  pid={pid} {path}");
    }
    if other.is_empty() {
        println!("  (none)");
    }

    println!(
        "=== events={} lost={} ===",
        outcome.seen_events, outcome.events_lost
    );
    println!(
        "HOW TO READ (1): compare read_dotnet vs read_cmd, and write_dotnet vs write_cmd, at the \
         SAME level. If the same logical operation yields DIFFERENT CreateOptions depending on who \
         opened the file, then CreateOptions cannot identify the operation -- the caller picks it, \
         and we do not control the caller."
    );
    println!(
        "HOW TO READ (2): look at the 'none' rows. If every operation denies with the SAME value, \
         that value means 'could not even probe the path' rather than any specific operation, and \
         the ladder is in the caller's open sequence rather than in the kernel."
    );

    let _ = crate::tier2a::session_profile::end_session(
        &crate::tier2a::win_appcontainer::revoke_session_grant,
    );
    assert!(outcome.seen_events > 0, "no ETW events observed");
}

/// 参考: 実行に要るビットが読取に含まれないことを、マスクの定義から確認する
/// （差分推論「read許可下で失敗＝実行か書込」の論理的な根拠）。
#[test]
fn generic_read_does_not_include_the_execute_bit() {
    assert_eq!(
        FILE_GENERIC_READ.0 & FILE_GENERIC_EXECUTE.0 & 0x20,
        0,
        "FILE_EXECUTE (0x20) must not be part of FILE_GENERIC_READ"
    );
    assert_ne!(FILE_GENERIC_EXECUTE.0 & 0x20, 0);
    // DELETE も同様に読取・書込のどちらにも含まれない。
    assert_eq!((FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0) & DELETE.0, 0);
}

/// `0x01200000`は「reparse pointを開くだけの、ファイルともディレクトリとも決めていないopen」
/// ——つまり**データopenではなくプローブ**である、という読みを固定する。
#[test]
fn the_probe_open_is_distinguishable_from_a_plain_data_open() {
    assert_eq!(describe_create_options(0x0120_0000), "OPEN_REPARSE_POINT");
    assert_eq!(
        describe_create_options(0x0100_0060),
        "SYNCHRONOUS_IO_NONALERT|NON_DIRECTORY_FILE"
    );
    assert_eq!(
        describe_create_options(0x0340_0060),
        "SYNCHRONOUS_IO_NONALERT|NON_DIRECTORY_FILE|OPEN_NO_RECALL"
    );
}

/// `FILE_DELETE_ON_CLOSE`だけは呼び出し側の好みではなく**`DELETE`アクセスの含意**
/// （`NtCreateFile`の仕様上、立てるなら`DesiredAccess`に`DELETE`が必須）。
/// 出力で見落とさないよう名前付きで出ることを固定する。
#[test]
fn delete_on_close_is_named_in_the_description() {
    assert_eq!(describe_create_options(0x0100_1060).split('|').count(), 3);
    assert!(describe_create_options(0x0100_1060).contains("DELETE_ON_CLOSE"));
}
