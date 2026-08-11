//! **ACLによる拒否は本当に`Create`段でしか起きないのか**の実測（残課題a-2の決着）。
//!
//! 実行:
//! ```text
//! dev-elevated-run.exe etw-operation-denial
//! ```
//!
//! # 結論（`plans/etw-spike/RESULTS.md` §18）
//!
//! **起きない。5ケースすべてで、拒否は`Create`(12)にしか現れなかった。**
//! `SetInformation`(17)/`SetDelete`(18)/`Rename`(19)/`Write`(16)由来の拒否は0件で、
//! パスは全件イベント自身の`FileName`で解決でき、`FileObject`/`FileKey`の表は一度も
//! 引かれなかった。§16の「削除の拒否を取りこぼしている」は測定の交絡だった。
//!
//! 構造的な理由: Windowsのアクセスチェックは**openの時点で`DesiredAccess`に対して**行われ、
//! 開いた後の操作はハンドルが持つ許可済みアクセスと照合されるのであってACLを引き直さない。
//! しかも仮にopen後に拒否されたとしても、それは呼び出し側がopen時にその権限を要求しなかった
//! ということなので、**ACLを緩めても直らない＝提案の材料にならない**。
//!
//! # このテストを残す理由
//!
//! 「`SetInformation`を購読すべきではないか」は今後も繰り返し出てくる問いなので、
//! **否という答えを実測として固定しておく**。同時に、`FILEIO`/`FILENAME`/`READ`/`WRITE`を
//! 開けたときのイベント量（約2倍）も出るので、コスト側の根拠も同じ場所で確認できる。
//!
//! # 測り方（3回踏んだ交絡への対処）
//!
//! `Remove-Item`/`Rename-Item`/`Move-Item`は祖先ディレクトリを「通過」ではなく**オープン**する。
//! そのため祖先の権利が1ビットでも欠けると、**対象へ到達する前に落ちる**——それを
//! 「削除が拒否された」と読むと結論を誤る（§16・§17.6・本テストの初回測定で3回踏んだ）。
//!
//! - ディレクトリの権利は**ビットを手で選ばず**`FILE_GENERIC_READ | FILE_TRAVERSE`で与える
//! - 拒否は対象ファイルだけでなく**一時ツリー配下すべて**について出す
//! - **成功するはずのケースを必ず混ぜる**（`delete_allowed`）。全部失敗したら、対象の性質では
//!   なく測定の不備を疑う合図になる
//!
//! マシンの状態は変えない（一時ディレクトリのACLのみ）。

use windows::Win32::Security::NO_INHERITANCE;
use windows::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_TRAVERSE};

use crate::shell_tier::WorkspaceWriteMode;
use crate::tier2a::win_appcontainer::test_support::spawn_in_workspace;
use crate::tier2a::win_appcontainer::{preflight, resolve_shell, NetworkCapability};

use super::parse::{to_settings_path, STATUS_ACCESS_DENIED};
use super::session::{
    EtwFsSession, RawFsEvent, KERNEL_FILE_KEYWORD_FILEIO, KERNEL_FILE_KEYWORD_FILENAME,
    KERNEL_FILE_KEYWORD_READ, KERNEL_FILE_KEYWORD_WRITE,
};
use super::volumes::drive_letter_map;

const WARMUP: std::time::Duration = std::time::Duration::from_millis(1500);
const DRAIN: std::time::Duration = std::time::Duration::from_secs(5);

const EVENT_ID_CREATE: u16 = 12;
const EVENT_ID_OPERATION_END: u16 = 24;
/// Id=10/11 は`FileKey`→`FileName`の対応を配るイベント（`KERNEL_FILE_KEYWORD_FILENAME`）。
const EVENT_ID_NAME: [u16; 2] = [10, 11];

fn event_name(id: u16) -> &'static str {
    match id {
        10 | 11 => "Name",
        12 => "Create",
        13 => "Cleanup",
        14 => "Close",
        15 => "Read",
        16 => "Write",
        17 => "SetInformation",
        18 => "SetDelete",
        19 => "Rename",
        20 => "DirEnum",
        22 => "QueryInformation",
        24 => "OperationEnd",
        26 => "DeletePath",
        27 => "RenamePath",
        30 => "CreateNewFile",
        _ => "?",
    }
}

/// `FILE_INFORMATION_CLASS`のうち、書込・削除・リネームを意味するもの。
/// **どれが実際に飛んでくるかが問い1**なので、判定に使う前にまず観測する。
fn info_class_name(class: u64) -> &'static str {
    match class {
        4 => "FileBasicInformation(attrs/timestamps)",
        10 => "FileRenameInformation",
        11 => "FileLinkInformation",
        13 => "FileDispositionInformation(delete)",
        19 => "FileAllocationInformation",
        20 => "FileEndOfFileInformation(truncate)",
        64 => "FileDispositionInformationEx(delete)",
        65 => "FileRenameInformationEx",
        _ => "other",
    }
}

struct Case {
    name: &'static str,
    /// 親ディレクトリへ与えるマスク。`FILE_DELETE_CHILD`(0x40)の有無が
    /// 「開ける／開けない」を分ける。
    dir_mask: u32,
    /// `Some`なら移動先ディレクトリを別に作り、このマスクを与える（`@T@`で参照）。
    dest_mask: Option<u32>,
    /// 子で実行するPowerShell断片（`@P@`が対象パス、`@T@`が移動先パス）。
    script: &'static str,
}

/// ディレクトリを**開ける**だけの権利一式。
///
/// `FILE_GENERIC_READ`には`SYNCHRONIZE`・`FILE_LIST_DIRECTORY`・`FILE_READ_ATTRIBUTES`が
/// 入っており、`FILE_TRAVERSE`だけを別に足す（`FILE_TRAVERSE`は`FILE_EXECUTE`と同じビット
/// で、`FILE_GENERIC_READ`には含まれない）。
///
/// **ビットを手で選ばないのが要点**。`Remove-Item`/`Rename-Item`は祖先ディレクトリを
/// 「通過」ではなく**オープン**するため、`SYNCHRONIZE`や`FILE_LIST_DIRECTORY`が1つ欠けるだけで
/// 対象ファイルへ到達する前に落ちる。そうなると「削除が拒否された」ように見えて、実際に
/// 拒否されているのは祖先である——§16はこの交絡を踏んだ疑いが濃い（§17.6の`cmd`と同型）。
const DIR_OPENABLE: u32 = FILE_GENERIC_READ.0 | FILE_TRAVERSE.0;
const FILE_DELETE_CHILD: u32 = 0x0040;

const CASES: [Case; 5] = [
    // 親が削除を許す＋列挙も許す。**ここは成功するはず**——成功することの確認自体が、
    // 他の段の「なぜ失敗したのか」を切り分ける基準になる。
    Case {
        name: "delete_allowed",
        dir_mask: DIR_OPENABLE | FILE_DELETE_CHILD,
        dest_mask: None,
        script: "try { Remove-Item -LiteralPath '@P@' -ErrorAction Stop; @OK@ } catch { @NG@ }",
    },
    // **理屈上、`Create`段を通り越しうる唯一の経路**。別ディレクトリへの移動は
    // `NtSetInformationFile(FileRenameInformation)`で行われ、**移動先ディレクトリへの
    // 書込権はハンドルの許可済みアクセスではなくrename IRPの時点で検査される**。
    // 元ファイル側は全部許可しておき、移動先だけ書けなくする。
    // ここで拒否が17/19に出るならa-2は実在し、`Create`に出るなら現行経路で足りる。
    Case {
        name: "move_to_unwritable_dir",
        dir_mask: DIR_OPENABLE | FILE_DELETE_CHILD,
        dest_mask: Some(DIR_OPENABLE),
        script: "try { Move-Item -LiteralPath '@P@' -Destination '@T@' -ErrorAction Stop; @OK@ } catch { @NG@ }",
    },
    // 対照: 親が子の削除を許さない＝`Create`段で落ちるはず（現行の収集器でも見えている側）。
    Case {
        name: "delete_no_delete_child",
        dir_mask: DIR_OPENABLE,
        dest_mask: None,
        script: "try { Remove-Item -LiteralPath '@P@' -ErrorAction Stop; @OK@ } catch { @NG@ }",
    },
    // **§16のテストと同じACL**（`FILE_LIST_DIRECTORY`を与えない）。§16はここで
    // 「削除は失敗するが`Create`拒否は0件」を観測し、`SetInformation`段の取りこぼしと結論づけた。
    // §17.6で`read_cmd`が同じ交絡（親を列挙できずディレクトリ側で落ちる）を踏んだため、
    // **その結論が交絡ではなかったかをここで確かめる**。拒否がファイルではなく
    // ディレクトリに出ていれば、a-2の根拠は作り直しになる。
    Case {
        name: "delete_no_list_like_s16",
        dir_mask: FILE_TRAVERSE.0 | 0x0080 | FILE_DELETE_CHILD,
        dest_mask: None,
        script: "try { Remove-Item -LiteralPath '@P@' -ErrorAction Stop; @OK@ } catch { @NG@ }",
    },
    // リネームもa-2の対象（`docs/STATUS.md`）。親に子の削除を許さない状態で試す。
    Case {
        name: "rename_no_delete_child",
        dir_mask: DIR_OPENABLE,
        dest_mask: None,
        script: "try { Rename-Item -LiteralPath '@P@' -NewName 'renamed.txt' -ErrorAction Stop; @OK@ } catch { @NG@ }",
    },
];

#[test]
#[ignore = "requires administrator rights (ETW) and creates an AppContainer profile; run via dev-elevated-run.exe etw-operation-denial"]
fn where_does_an_operation_stage_denial_surface() {
    let workspace = tempfile::tempdir().expect("workspace");
    let outside = tempfile::tempdir().expect("outside");

    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
    let profile = crate::tier2a::session_profile::current_profile_name();
    let sid = crate::tier2a::win_appcontainer::ensure_profile(&profile).expect("package SID");

    // **一時ツリーのルート自身にも開ける権利を与える。** 最初の測定ではこれが無く、
    // 4ケースすべてがルートへの`Create`拒否で止まっていた（ケースディレクトリにも
    // ファイルにも到達していなかった）。祖先で落ちている限り、測りたい段には永遠に届かない。
    crate::tier2a::win_appcontainer::grant_ace_mask_for_test(
        outside.path(),
        sid.as_psid(),
        DIR_OPENABLE,
        NO_INHERITANCE,
    )
    .expect("grant openable on the probe tree root");

    let mut probes: Vec<(&'static str, std::path::PathBuf)> = Vec::new();
    let mut dests: Vec<Option<std::path::PathBuf>> = Vec::new();
    for case in &CASES {
        let dir = outside.path().join(case.name);
        std::fs::create_dir(&dir).expect("create the case dir");
        crate::tier2a::win_appcontainer::grant_ace_mask_for_test(
            &dir,
            sid.as_psid(),
            case.dir_mask,
            NO_INHERITANCE,
        )
        .expect("grant the case dir mask");

        let path = dir.join("victim.txt");
        std::fs::write(&path, b"payload").expect("create the victim");
        // ファイルは読み書きできる。**開ける状態を作るのが目的**なので、ここは常に与える。
        crate::tier2a::win_appcontainer::grant_ace_mask_for_test(
            &path,
            sid.as_psid(),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            NO_INHERITANCE,
        )
        .expect("grant read+write on the victim");

        // 移動先ディレクトリ（`dest_mask`があるケースのみ）。**元ファイル側は全部許可し、
        // ここだけ書けなくする**ことで、拒否がrename段でしか起こり得ない状況を作る。
        let dest = case.dest_mask.map(|mask| {
            let dest_dir = outside.path().join(format!("{}__dest", case.name));
            std::fs::create_dir(&dest_dir).expect("create the destination dir");
            crate::tier2a::win_appcontainer::grant_ace_mask_for_test(
                &dest_dir,
                sid.as_psid(),
                mask,
                NO_INHERITANCE,
            )
            .expect("grant the destination dir mask");
            dest_dir.join("moved.txt")
        });

        probes.push((case.name, path));
        dests.push(dest);
    }

    let session = EtwFsSession::start_with_raw_capture(
        "harness-policy-learn-operation-denial",
        KERNEL_FILE_KEYWORD_FILEIO
            | KERNEL_FILE_KEYWORD_FILENAME
            | KERNEL_FILE_KEYWORD_READ
            | KERNEL_FILE_KEYWORD_WRITE,
    )
    .expect("ETW session with FILEIO/FILENAME/READ/WRITE keywords");
    std::thread::sleep(WARMUP);

    let mut script = String::from("$ErrorActionPreference='SilentlyContinue';\n");
    for ((case, (_, path)), dest) in CASES.iter().zip(&probes).zip(&dests) {
        script.push_str(
            &case
                .script
                .replace("@OK@", &format!("Write-Output '{}|OK'", case.name))
                .replace("@NG@", &format!("Write-Output '{}|FAIL'", case.name))
                .replace("@P@", &path.display().to_string())
                .replace(
                    "@T@",
                    &dest
                        .as_ref()
                        .map(|d| d.display().to_string())
                        .unwrap_or_default(),
                ),
        );
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
    let (raw, raw_dropped) = session.raw_events();
    let (starts, _denials) = session.drain();
    let outcome = session.stop();

    // 孫まで含めた家族（`cmd`等が挟まる場合に備える。§17.2で踏んだ落とし穴）。
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

    let volumes = drive_letter_map();
    // **プローブファイルだけを見ない。** §17.6で踏んだ通り、拒否は対象ファイルではなく
    // 親ディレクトリや祖先チェーンに出ることがある。ここでは一時ツリー配下の拒否を
    // まるごと拾い、パスをそのまま出す。
    let outside_root = outside
        .path()
        .to_string_lossy()
        .replace('\\', "/")
        .to_lowercase();

    // --- 実装が使う予定の解決アルゴリズムを、そのままここで回す ---
    //
    // 1. `Create`(12)とName(10/11)から `FileObject`→パス / `FileKey`→パス を作る
    // 2. `Irp`で「開始イベント」を保持し、`OperationEnd`(24)で引き当てる（現行のCorrelatorと同型）
    // 3. 拒否だったものについて、開始イベントの`FileName`（Createなら持っている）か、
    //    無ければ`FileObject`/`FileKey`から引く
    let mut by_file_object: std::collections::HashMap<u64, String> =
        std::collections::HashMap::new();
    let mut by_file_key: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
    let mut pending: std::collections::HashMap<u64, RawFsEvent> = std::collections::HashMap::new();

    #[derive(Debug)]
    struct Resolved {
        path: String,
        event_id: u16,
        info_class: Option<u64>,
        /// パスをどう引き当てたか。**`FILENAME`キーワードが要るかの答えがここに出る**。
        via: &'static str,
        pid: u32,
        in_family: bool,
    }
    let mut resolved: Vec<Resolved> = Vec::new();
    let mut denials_without_path = 0u64;
    let mut denied_operation_ends = 0u64;

    for event in &raw {
        if let Some(name) = event.file_name.as_deref() {
            if let Some(path) = to_settings_path(name, &volumes) {
                if event.event_id == EVENT_ID_CREATE {
                    if let Some(fo) = event.file_object {
                        by_file_object.insert(fo, path.clone());
                    }
                }
                if EVENT_ID_NAME.contains(&event.event_id) {
                    if let Some(fk) = event.file_key {
                        by_file_key.insert(fk, path.clone());
                    }
                }
                // `Create`も`FileKey`を運ぶ版があるかもしれないので、あれば入れる。
                if let Some(fk) = event.file_key {
                    by_file_key.entry(fk).or_insert(path);
                }
            }
        }

        if event.event_id == EVENT_ID_OPERATION_END {
            let Some(irp) = event.irp else { continue };
            let Some(start) = pending.remove(&irp) else {
                continue;
            };
            if event.status != Some(STATUS_ACCESS_DENIED as u64) {
                continue;
            }
            denied_operation_ends += 1;
            let (path, via) = start
                .file_name
                .as_deref()
                .and_then(|n| to_settings_path(n, &volumes))
                .map(|p| (Some(p), "event's own FileName"))
                .or_else(|| {
                    start
                        .file_object
                        .and_then(|fo| by_file_object.get(&fo).cloned())
                        .map(|p| (Some(p), "FileObject table (from Create)"))
                })
                .or_else(|| {
                    start
                        .file_key
                        .and_then(|fk| by_file_key.get(&fk).cloned())
                        .map(|p| (Some(p), "FileKey table (needs FILENAME keyword)"))
                })
                .unwrap_or((None, "unresolved"));

            match path {
                Some(path) if path.to_lowercase().starts_with(&outside_root) => {
                    resolved.push(Resolved {
                        path,
                        event_id: start.event_id,
                        info_class: start.info_class,
                        via,
                        pid: start.pid,
                        in_family: family.contains(&start.pid),
                    });
                }
                Some(_) => {}
                None => denials_without_path += 1,
            }
        } else if let Some(irp) = event.irp {
            pending.insert(irp, event.clone());
        }
    }

    // --- 出力 ---
    println!(
        "=== operation results (child pid={child_pid}, family {} pids) ===",
        family.len()
    );
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

    println!(
        "=== raw capture: {} events (dropped {raw_dropped}) ===",
        raw.len()
    );
    println!("=== event histogram (whole machine) ===");
    for (id, count) in &outcome.event_histogram {
        println!("  id={id:<3} ({:<22}) = {count}", event_name(*id));
    }

    println!(
        "=== access-denied OperationEnds correlated to a start event: {denied_operation_ends} \
         (of which {} landed under the probe tree) ===",
        resolved.len()
    );
    // **ファイルだけでなくディレクトリの拒否も出す**。どちらで落ちたかがa-2の成否そのもの。
    resolved.sort_by(|a, b| a.path.cmp(&b.path).then(a.event_id.cmp(&b.event_id)));
    for hit in &resolved {
        println!(
            "  {} <- id={} ({}) info_class={} via={} pid={}{}",
            hit.path,
            hit.event_id,
            event_name(hit.event_id),
            hit.info_class
                .map(|c| format!("{c} {}", info_class_name(c)))
                .unwrap_or_else(|| "-".to_string()),
            hit.via,
            hit.pid,
            if hit.in_family {
                ""
            } else {
                " (OUTSIDE-FAMILY)"
            }
        );
    }
    if resolved.is_empty() {
        println!("  (none)");
    }
    println!(
        "  access-denied OperationEnds whose path could not be resolved: {denials_without_path}"
    );
    println!(
        "=== tables built: FileObject->path {} entries, FileKey->path {} entries ===",
        by_file_object.len(),
        by_file_key.len()
    );
    println!(
        "=== events={} lost={} ===",
        outcome.seen_events, outcome.events_lost
    );
    println!(
        "HOW TO READ: every denial should list 'id=12 (Create)' as its originating event and \
         'via=event's own FileName' as how the path was recovered. If any denial ever originates \
         from id=17/18/19 (SetInformation/SetDelete/Rename) or id=16 (Write), then ACL denials are \
         NOT confined to open time after all and the collector's Create-only view has a hole. \
         [delete_allowed] must succeed -- if it fails, the ancestors are not openable and the \
         measurement is testing the wrong thing (this confound was hit three times, see \
         RESULTS.md \u{00a7}18.5)."
    );

    let _ = crate::tier2a::session_profile::end_session(
        &crate::tier2a::win_appcontainer::revoke_session_grant,
    );

    // --- 結論を固定する ---
    assert!(outcome.seen_events > 0, "no ETW events observed");

    // 交絡検知。これが落ちたら測定が成立していないので、以降のassertは意味を持たない。
    let stdout = output.map(|(o, _, _)| o).unwrap_or_default();
    assert!(
        stdout.contains("delete_allowed|OK"),
        "the control case must succeed; if it fails the ancestors are not openable and this test \
         is measuring the ancestor chain instead of the target (RESULTS.md §18.5). stdout:\n{stdout}"
    );

    // 本題: ACL起因の拒否はopen段にしか出ない。
    let post_open: Vec<&Resolved> = resolved
        .iter()
        .filter(|r| r.event_id != EVENT_ID_CREATE)
        .collect();
    assert!(
        post_open.is_empty(),
        "an ACL denial surfaced after open, which contradicts RESULTS.md §18: {post_open:#?}"
    );

    // `FILENAME`キーワード（Id=10/11）が要らないことの根拠。`Create`が`FileName`を運ぶので、
    // `FileObject`/`FileKey`からの解決に落ちる拒否は無い。
    let needed_tables: Vec<&Resolved> = resolved
        .iter()
        .filter(|r| r.via != "event's own FileName")
        .collect();
    assert!(
        needed_tables.is_empty(),
        "a denial needed the FileObject/FileKey table to recover its path, which would mean the \
         FILENAME keyword is required after all: {needed_tables:#?}"
    );
}
