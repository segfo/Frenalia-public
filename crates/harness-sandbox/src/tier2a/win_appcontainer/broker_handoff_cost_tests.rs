//! **T-5: ブローカーが「開いたハンドル」を手渡す形はいくらか**
//! （分流の指示と結果の正本は`plans/handoff/fs-boundary-cost/T-5.md`）。
//!
//! # なぜ測るのか
//!
//! いまのFS境界は「許可したい各オブジェクトのDACLへ、サンドボックス主体宛のACEを書く」。
//! 26万ノードで初回22.5秒・撤収18.7秒・一巡61.4秒である（`plans/mac-spike/RESULTS.md` §S12）。
//!
//! Microsoft自身がAppContainerへ広い範囲を与えるときに使っているのはACLの書き換えではなく
//! **ブローカー**である。そこで、フックが親へ頼む内容を「このファイルにACEを書いて」から
//! **「このファイルを開いて、開いたハンドルをください」**へ替える案がある。
//! DACL書込（§S13の支配項123.5 µs）と**撤収18.7秒・マシンに残る痕跡がまるごと消える**代わりに、
//! **1オープンごとに払う**ことになる。だから1件あたりを測る。
//!
//! # §S13との関係——**あちらは同一プロセス内のスレッド間で測っており、過小評価である**
//!
//! §S13は「子が要求を出して親がACEを書く」形を1件162.8 µsと出したが、その往復は
//! **同じプロセスの2スレッド間**だった。本モジュールは**AppContainerの子から親へ**という
//! 本物のプロセス境界で同じものを測り直し、そのうえでハンドル手渡しと並べる。
//! **したがってここには「§S13の腕Bと腕Cを跨ぎで測り直したもの」が含まれる**
//! （HANDOFFの「次に測ること」4番）。
//!
//! | 腕 | 親がやること | 何が分かるか |
//! |---|---|---|
//! | `rtt` | 何もしない | **プロセス跨ぎの往復の値段**（§S13腕B＝16.4 µsの跨ぎ版） |
//! | `open` | `CreateFileW`＋`CloseHandle` | ブローカーが払うオープンの値段 |
//! | `handoff` | `CreateFileW`＋`DuplicateHandle`で子へ複製 | **本命。ハンドル手渡しの1件** |
//! | `dacl` | 非継承ACEを1本書く | **§S13腕C＝162.8 µsの跨ぎ版**（同じ判定線の相手側） |
//!
//! 腕は**4本とも同じ計器**（`win_pipe_ipc`の長さプレフィックス・フレーム、
//! `run_overlapped`のI/O）で回すので、差だけを読めば良い。
//!
//! # 「渡した」と「使える」は別の事実
//!
//! 最後に`verify`の腕で、**子が自力で同じパスを開けないこと**を先に記録してから
//! （B-35: 対で測らないと、ハンドルが効いたのか元から開けたのかが区別できない）、
//! 渡されたハンドルで読取と追記を行わせる。**追記が実際に効いたかは親が読み返して判定する**
//! ——子の自己申告を根拠にしない（B-25）。
//!
//! # 計器そのものが測定対象を汚していないか（§S13-0の罠）
//!
//! §S13-0では、付与記録の計装（`grant_audit::note_low_level_grant`）がプロセス内の一覧を
//! 毎回線形走査し、1件あたりが9.6倍に膨らんだ。**`dacl`の腕は同じ罠を踏む**ので、
//! 製品の一括経路と同じく`note_root_grant`のガードを**サーバスレッドで**張る
//! （ガードはスレッドローカルなので、張る場所を間違えると効かない）。
//!
//! 他の3腕はACEを書かないので同じ罠は無いが、次を確かめてある。
//!
//! - 子は**パス一覧をループ前に読み込み**、時刻採取はループ内で1回だけ、統計はループ後。
//! - `handoff`の腕は**受け取ったハンドルを毎回閉じる**（閉じないと子のハンドル表が
//!   単調に伸び、1件あたりが件数に依存してしまう）。
//! - 腕ごとに**別のツリー**を使う（同じファイルを2度触ってキャッシュ効果を混ぜない）。
//!
//! # 実行（**昇格しないこと**）
//!
//! ```text
//! cargo build -p tier2a-proc-probe
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture broker_handoff_cost
//! ```
//!
//! 昇格したテストからAppContainerの子を起こすと親トークンが管理者のものになり、測っている
//! 世界が実運用（非昇格のharness）とずれる（B-08、BUG-109と同型）。ACEを書くのは
//! **テスト自身が作ったツリー**だけなので所有者権限で足りる。
//!
//! 主体は`capability_sid_from_name`（純粋導出）とこのセッションのpackage SIDだけで、
//! **`workspace_capability_sid`は呼ばない**（あちらは`%APPDATA%`の台帳へ秘密を永続化する）。
//!
//! # 判定が出たらこのファイルは削除する
//!
//! `docs/CODE-STRUCTURE-RULES.md`規則2（一回性の調査実験をテストとして残さない）。

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, GENERIC_READ,
    GENERIC_WRITE, HANDLE, HLOCAL, LocalFree,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows::Win32::System::Threading::GetCurrentProcess;

use super::mac_spike_tests::{last_json_line, probe_exe, SpikeConsole, SpikeSpawn};
use super::test_support::{build_wide_tree, TestDirGuard};
use super::*;
use crate::win_common::wide;
use crate::win_pipe_ipc::{
    connect_with_timeout, current_user_sid_string, read_framed_timeout, unique_pipe_name,
    write_framed_timeout,
};

/// §S9・§S10・§S12・§S13と同じfanout。**形が違うと数字を並べられない。**
const FANOUT: usize = 32;

/// 既定の件数。分流の指示は「N は 2,000 程度」。
const DEFAULT_ITEMS: usize = 2_000;

/// 助走。パイプ・スレッド・ページの初回費用を本measurementへ混ぜないためだけのもの。
const WARMUP_ITEMS: usize = 200;

/// **§S13の腕C**（同一プロセス内スレッド間での「往復＋DACL書込」）。判定線そのもの。
/// **この定数は測定値の転記である。** §S13を測り直したらここも直すこと。
const S13_COMBINED_US: f64 = 162.8;

/// **§S13の腕B**（同一プロセス内スレッド間での往復だけ）。跨ぎとの差を出すために引く。
const S13_RTT_US: f64 = 16.4;

/// **§S13の腕A**（DACL書込だけ、パイプ抜き、10,000件）。本モジュールの`local`の腕と
/// 同じ仕事なので、**マシンの状態が§S13の日とどれだけ違うか**を測る物差しに使う。
const S13_ARM_A_US: f64 = 123.5;

/// 事前配布の1ノードあたり（§S12-1、26万ノードで22,484 ms ÷ 260,033ノード）。
const EAGER_US_PER_NODE: f64 = 86.5;

/// パイプI/Oのタイムアウト。**測っているのはµs単位の往復**なので、ここへ引っ掛かるのは
/// 「遅い」ではなく「壊れている」である。
const PIPE_TIMEOUT: Duration = Duration::from_secs(60);

/// 実マシンは1つしかないので、**時間を測る区間だけ**は他の分流と直列化する。
const LOCK_DIR: &str = r"C:\harness-e2e\_measure-lock";
const LOCK_NAME: &str = "T-5";

/// `verify`の腕で読み書きする本文。**子の申告ではなく親の読み返し**で判定する。
const VERIFY_BODY: &str = "T5-VERIFY-BODY";
const VERIFY_APPEND: &str = "T5-CHILD-WROTE";

fn item_count() -> usize {
    std::env::var("HARNESS_T5_ITEMS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_ITEMS)
}

/// 測定用のcapability SIDを**名前から導出**する（`workspace_capability_sid`は使わない）。
fn measure_capability_name(label: &str) -> String {
    format!("harness-t5-{}-{label}", std::process::id())
}

fn measure_capability(label: &str) -> crate::win_common::OwnedSid {
    super::capability_sid_from_name(&measure_capability_name(label)).expect("derive capability sid")
}

/// 時間を測っている間だけ握るロック。**失敗しても必ず外れる**ようにDropで消す（B-01）。
struct MeasureLock {
    path: PathBuf,
}

impl MeasureLock {
    /// 他の名前のファイルが消えるまで10秒間隔で待つ。30分取れなければ`None`。
    fn acquire() -> Option<Self> {
        let dir = PathBuf::from(LOCK_DIR);
        std::fs::create_dir_all(&dir).ok()?;
        let mine = dir.join(LOCK_NAME);
        let deadline = Instant::now() + Duration::from_secs(30 * 60);
        loop {
            // 先に自分の札を置いてから他人を見る（見てから置くと、2本が同時に「空だ」と
            // 判断して両方置ける）。他人が居たら自分の札を引っ込めて待ち直す。
            let placed = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&mine)
                .is_ok()
                || mine.exists();
            let others: Vec<String> = std::fs::read_dir(&dir)
                .ok()?
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n != LOCK_NAME)
                .collect();
            if placed && others.is_empty() {
                return Some(Self { path: mine });
            }
            let _ = std::fs::remove_file(&mine);
            if Instant::now() >= deadline {
                eprintln!("[T5] 測定ロックが30分取れなかった。待っていた相手: {others:?}");
                return None;
            }
            eprintln!("[T5] 測定ロック待ち（相手: {others:?}）");
            std::thread::sleep(Duration::from_secs(10));
        }
    }
}

impl Drop for MeasureLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// 撤収し、**残っていないことを実測してから**先へ進む（B-25: `revoke`の戻り値は根拠にしない。
/// 「撤収したと報告されたのにACEが減っていなかった」実例がBUG-101）。
///
/// `acl_baseline_cost_tests`に同名のprivate関数があるが、**あちらは所要時間を返す測定用**で、
/// 本モジュールが要るのは後始末だけである。共有の置き場（`test_support`）へ上げないのは、
/// 同じファイルを他の分流が同時に触っているためで、**この2つは判定が出たらどちらも消える**
/// （`docs/CODE-STRUCTURE-RULES.md`規則2）。
fn revoke_and_verify(root: &Path, sid: PSID) {
    let report = revoke_ace_recursive(root, sid).expect("revoke the measurement ACEs");
    eprintln!("[T5] revoke {}: {report:?}", root.display());
    if let Err(leftovers) = assert_no_sid_ace_recursive(root, sid) {
        panic!(
            "撤収後もACEが{}件残っている: {:?}",
            leftovers.len(),
            leftovers.iter().take(5).collect::<Vec<_>>()
        );
    }
}

/// `root`配下のファイルだけを列挙する（JITが配る相手＝開こうとしたオブジェクトに揃える）。
fn collect_files(root: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    super::acl_grant::collect_dirs_and_files(root, &mut dirs, &mut files, OnVanished::Abort)
        .expect("enumerate the measurement tree");
    files.sort();
    files
}

/// 腕1本ぶんのツリーを作り、パスの一覧を返す。ラベルは**全部同じ長さ**にしてある——
/// パス長が腕ごとに変わると、フレームのバイト数まで一緒に動いてしまう。
fn build_arm_tree(label: &str, count: usize) -> (TestDirGuard, Vec<PathBuf>) {
    let dir = TestDirGuard::create(label);
    build_wide_tree(dir.path(), count, FANOUT);
    let files = collect_files(dir.path());
    assert!(
        files.len() >= count,
        "{label}: ツリーに測る対象が揃っていない（{}件）",
        files.len()
    );
    (dir, files)
}

/// サーバ側が1件の要求に対して行う仕事。腕の名前で切り替える。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ServerWork {
    /// 何もしない（往復だけ）。
    Nothing,
    /// 開いて即閉じる。
    Open,
    /// 開いて子へ複製し、ハンドル値を返す。
    Handoff,
    /// 非継承ACEを1本書く（§S13腕Cと同じ仕事）。
    Dacl,
}

fn work_for(arm: &str) -> ServerWork {
    match arm {
        "open" => ServerWork::Open,
        "handoff" | "verify" => ServerWork::Handoff,
        "dacl" => ServerWork::Dacl,
        _ => ServerWork::Nothing,
    }
}

/// サーバ（親＝ブローカー役）の走行記録。**「何も撃っていない」を成功に見せない**ため、
/// 受けた件数と腕の並びと失敗をそのまま持ち帰る（B-10）。
#[derive(Debug, Default)]
struct ServeReport {
    arms_seen: Vec<String>,
    requests: usize,
    handed: usize,
    granted: usize,
    errors: Vec<String>,
}

/// 要求受付側。`ARM:<名前>`で腕を切り替え、それ以外のフレームはパスとして扱う。
///
/// **付与記録のガードをこのスレッドで張る**（`grant_audit::note_root_grant`）。
/// ガードはスレッドローカルなので、呼び出し側で張っても効かない（§S13-0）。
fn serve(
    pipe_raw: isize,
    child_process_raw: isize,
    grant_capability_name: String,
    grant_root: PathBuf,
    grant_mask: u32,
) -> ServeReport {
    let pipe = HANDLE(pipe_raw as *mut core::ffi::c_void);
    let child = HANDLE(child_process_raw as *mut core::ffi::c_void);
    let mut report = ServeReport::default();

    if let Err(e) = connect_with_timeout(pipe, PIPE_TIMEOUT) {
        report.errors.push(format!("ConnectNamedPipe: {e}"));
        unsafe {
            let _ = CloseHandle(pipe);
        }
        return report;
    }

    let sid = super::capability_sid_from_name(&grant_capability_name)
        .expect("server: derive the measurement capability sid");
    // §S13-0の罠。**製品の一括経路と同じガードを、書く側のスレッドで張る。**
    let _audit = crate::tier2a::grant_audit::note_root_grant(&grant_root, sid.as_psid());

    let mut work = ServerWork::Nothing;
    loop {
        let frame = match read_framed_timeout(pipe, PIPE_TIMEOUT) {
            Ok(f) => f,
            Err(e) => {
                report.errors.push(format!("read: {e}"));
                break;
            }
        };
        let text = String::from_utf8_lossy(&frame).into_owned();
        if let Some(arm) = text.strip_prefix("ARM:") {
            report.arms_seen.push(arm.to_string());
            work = work_for(arm);
            if write_framed_timeout(pipe, b"ok", PIPE_TIMEOUT).is_err() {
                report.errors.push("write(arm ack)".to_string());
                break;
            }
            if arm == "done" {
                break;
            }
            continue;
        }

        report.requests += 1;
        let path = PathBuf::from(&text);
        let reply: String = match work {
            ServerWork::Nothing => "0".to_string(),
            ServerWork::Open => match open_for_broker(&path) {
                Ok(h) => {
                    unsafe {
                        let _ = CloseHandle(h);
                    }
                    "0".to_string()
                }
                Err(code) => {
                    report.errors.push(format!("open {}: {code:#x}", path.display()));
                    format!("E{code}")
                }
            },
            ServerWork::Handoff => match open_for_broker(&path) {
                Ok(h) => match duplicate_into(h, child) {
                    Some(raw) => {
                        report.handed += 1;
                        raw.to_string()
                    }
                    None => {
                        // `DUPLICATE_CLOSE_SOURCE`は失敗時に元を閉じないので自分で閉じる。
                        unsafe {
                            let _ = CloseHandle(h);
                        }
                        report
                            .errors
                            .push(format!("duplicate {}", path.display()));
                        "E0".to_string()
                    }
                },
                Err(code) => {
                    report.errors.push(format!("open {}: {code:#x}", path.display()));
                    format!("E{code}")
                }
            },
            ServerWork::Dacl => {
                match super::grant_ace_mask_for_test(
                    &path,
                    sid.as_psid(),
                    grant_mask,
                    NO_INHERITANCE,
                ) {
                    Ok(()) => {
                        report.granted += 1;
                        "0".to_string()
                    }
                    Err(e) => {
                        report.errors.push(format!("grant {}: {e}", path.display()));
                        "E0".to_string()
                    }
                }
            }
        };
        if write_framed_timeout(pipe, reply.as_bytes(), PIPE_TIMEOUT).is_err() {
            report.errors.push("write(reply)".to_string());
            break;
        }
    }

    unsafe {
        let _ = CloseHandle(pipe);
    }
    report
}

/// ブローカーが要求に応えて開くときの形。読み書きの両方を握り、共有は全部許す
/// （握ったまま親が読み返せないと、後段の検算ができない）。
fn open_for_broker(path: &Path) -> Result<HANDLE, u32> {
    let w = wide(&path.to_string_lossy());
    unsafe {
        CreateFileW(
            PCWSTR(w.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| e.code().0 as u32)
    }
}

/// 子のハンドル表へ複製する。`DUPLICATE_CLOSE_SOURCE`で親側の元ハンドルも同時に手放す
/// ——ブローカーが素直に書くとこの形になる（別に`CloseHandle`を撃つと1呼び出し増える）。
fn duplicate_into(src: HANDLE, child: HANDLE) -> Option<usize> {
    let mut out = HANDLE::default();
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            src,
            child,
            &mut out,
            0,
            false,
            DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE,
        )
    };
    if ok.is_ok() {
        Some(out.0 as usize)
    } else {
        None
    }
}

/// 要求受付パイプ（設計§10.1）を作る。**ユーザー専有DACLではサンドボックスの子は届かない**
/// ことが実測済みなので（`t4_privhelper_pipe_reach_tests`）、capability SID宛のACEを足す。
///
/// マスクから`FILE_CREATE_PIPE_INSTANCE`(0x4)を外すのも§10.1のとおり（含めると子が同名の
/// 追加インスタンスを作って後続クライアントを横取りできる）。**S7が実測で通した形と同じ**。
fn create_request_pipe(name: &str, capability: PSID) -> (HANDLE, PSECURITY_DESCRIPTOR) {
    const READ_WRITE_WITHOUT_CREATE_INSTANCE: u32 = 0x0012_019B;
    let cap = crate::win_common::sid_to_string(capability).expect("capability sid string");
    let user = current_user_sid_string().expect("current user sid");
    let sddl = format!(
        "D:(A;;GA;;;{user})(A;;0x{:x};;;{cap})",
        READ_WRITE_WITHOUT_CREATE_INSTANCE
    );
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide(&sddl).as_ptr()),
            windows::Win32::Security::Authorization::SDDL_REVISION_1,
            &mut sd,
            None,
        )
    }
    .expect("convert the request-pipe SDDL");
    let sa = windows::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };
    let name_w = wide(name);
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(name_w.as_ptr()),
            // **オーバーラップドにする**——`win_pipe_ipc`のフレーム関数（§S13が使った計器）が
            // `run_overlapped`前提だからで、ここを変えると§S13と数字を並べられない。
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            64 * 1024,
            64 * 1024,
            0,
            Some(&sa as *const _),
        )
    };
    assert!(!handle.is_invalid(), "要求受付パイプを作れなかった: {sddl}");
    (handle, sd)
}

/// 腕1本ぶんの結果を、子が出したJSONから引く。
fn arm_of<'a>(report: &'a Value, name: &str) -> Option<&'a Value> {
    report
        .get("arms")?
        .as_array()?
        .iter()
        .find(|a| a.get("arm").and_then(|n| n.as_str()) == Some(name))
}

fn us_of(report: &Value, name: &str) -> f64 {
    arm_of(report, name)
        .and_then(|a| a.get("us_per_item"))
        .and_then(|v| v.as_f64())
        .unwrap_or(f64::NAN)
}

/// **ハンドル手渡しの1件あたりを、プロセス境界を跨いで測る。**
///
/// assertするのは揺れない構造の側（腕が全部走ったか・ハンドルが本当に使えたか・
/// 撤収できたか）だけで、**時間は判定に使わず値として出す**。時間を読むのは人間の仕事である。
#[test]
#[ignore = "spawns a real AppContainer child, creates thousands of files and writes DACLs; run NON-elevated"]
fn broker_handoff_cost_per_open() {
    let count = item_count();
    let mask = fs_access_mask(FsAccess::Read);
    let container = session_sid();
    let traverse = traverse_capability_sid().expect("traverse capability");

    // --- 子が実行できる場所を1つだけ作る（ここだけpackage SIDへ読取+実行を許す） ---
    //
    // 既存のスパイクは`preflight`でこれを済ませているが、あちらは`workspace_capability_sid`を
    // 呼んで`%APPDATA%`の台帳へ秘密を書く。**この測定は台帳に何も残さない**約束なので、
    // 使い捨てのディレクトリへプローブを写して、そこへだけACEを付ける（対で撤収する）。
    let bin_dir = TestDirGuard::create("t5x");
    let probe_src = probe_exe();
    let probe_dst = bin_dir.path().join("tier2a_proc_probe.exe");
    std::fs::copy(&probe_src, &probe_dst).expect("copy the probe next to a reachable directory");

    // --- 腕ごとに別のツリー（ラベルは同じ長さ＝パス長を動かさない） ---
    let (dir_rtt, files_rtt) = build_arm_tree("t5a", count);
    let (dir_open, files_open) = build_arm_tree("t5b", count);
    let (dir_hand, files_hand) = build_arm_tree("t5c", count);
    let (dir_dacl, files_dacl) = build_arm_tree("t5d", count);
    // **対照**: パイプを一切通さず、この場（親プロセス）でACEを1件ずつ書く。§S13の腕A
    // （123.5 µs）と同じ仕事で、**今日のこのマシンでの値**を同じ実行の中に持つための腕。
    // これが無いと、跨ぎの`dacl`が高かったときに「境界のせい」なのか
    // 「このマシンのDACL書込が§S13の日より遅いだけ」なのかを言い分けられない（B-29）。
    let (dir_local, files_local) = build_arm_tree("t5e", count);

    // `verify`の的は**ハンドル手渡しの腕と同じツリー**（package SID宛ACEが1本も無い場所）。
    let verify_path = dir_hand.path().join("verify.txt");
    std::fs::write(&verify_path, VERIFY_BODY).expect("write the verify target");

    let to_s = |v: &[PathBuf]| -> Vec<String> {
        v.iter().map(|p| p.to_string_lossy().into_owned()).collect()
    };
    let plan = json!({
        "arms": [
            {"name": "warmup",  "paths": to_s(&files_rtt[..WARMUP_ITEMS.min(files_rtt.len())])},
            {"name": "rtt",     "paths": to_s(&files_rtt)},
            {"name": "open",    "paths": to_s(&files_open)},
            {"name": "handoff", "paths": to_s(&files_hand)},
            {"name": "dacl",    "paths": to_s(&files_dacl)},
        ],
        "verify": {"path": verify_path.to_string_lossy(), "append": VERIFY_APPEND},
    });
    let plan_path = bin_dir.path().join("plan.json");
    std::fs::write(&plan_path, serde_json::to_vec(&plan).unwrap()).expect("write the plan");

    // プローブと計画を子から読めるようにする（**この1本だけがマシンへ残る痕跡で、対で撤収する**）。
    grant_ace_mask_with(
        bin_dir.path(),
        container.as_psid(),
        fs_access_mask(FsAccess::ReadExec),
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
        DaclWrite::Propagate,
    )
    .expect("grant read+exec on the probe directory");

    // --- 要求受付パイプ（§10.1） ---
    let request_cap = measure_capability("reqpipe");
    let pipe_name = unique_pipe_name("t5-broker");
    let (server_pipe, sd) = create_request_pipe(&pipe_name, request_cap.as_psid());

    // --- ここから時間を測るので、他の分流と直列化する ---
    let Some(_lock) = MeasureLock::acquire() else {
        unsafe {
            let _ = CloseHandle(server_pipe);
            let _ = LocalFree(HLOCAL(sd.0));
        }
        revoke_and_verify(bin_dir.path(), container.as_psid());
        panic!("測定ロックが取れなかったので測っていない（外挿で数字を作らないこと）");
    };

    let capabilities: Vec<PSID> = vec![traverse.as_psid(), request_cap.as_psid()];
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let cwd = PathBuf::from(format!("{system_root}\\System32"));
    let probe_str = probe_dst.to_string_lossy().into_owned();
    let plan_str = plan_path.to_string_lossy().into_owned();
    let mut child = SpikeSpawn {
        exe: &probe_str,
        args: &[
            "--broker-bench",
            &pipe_name,
            "--broker-plan",
            &plan_str,
            "--timeout-secs",
            "600",
        ],
        cwd: &cwd,
        container_sid: container.as_psid(),
        capabilities: &capabilities,
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
    .expect("spawn the AppContainer requester");

    let server_thread = {
        let pipe_raw = server_pipe.0 as isize;
        let child_raw = child.process().0 as isize;
        let cap_name = measure_capability_name("dacl");
        let grant_root = dir_dacl.path().to_path_buf();
        std::thread::spawn(move || serve(pipe_raw, child_raw, cap_name, grant_root, mask))
    };

    // --- 対照（in-process、§S13腕A相当）。子が回っている**前**に済ませると子の起動と
    // 重なるので、子を待ち切ってから撃つ。ロックはまだ握っている。
    let (stdout, stderr, code) = child.wait_and_read();
    let serve_report = server_thread.join().expect("server thread");

    let local_sid = measure_capability("local");
    let local_ms = {
        let _audit = crate::tier2a::grant_audit::note_root_grant(dir_local.path(), local_sid.as_psid());
        let t = Instant::now();
        for f in &files_local {
            super::grant_ace_mask_for_test(f, local_sid.as_psid(), mask, NO_INHERITANCE)
                .unwrap_or_else(|e| panic!("local arm: grant on {}: {e}", f.display()));
        }
        t.elapsed().as_millis()
    };
    let local_us = (local_ms as f64) * 1000.0 / (files_local.len() as f64);
    unsafe {
        let _ = LocalFree(HLOCAL(sd.0));
    }
    drop(_lock);

    eprintln!("[T5] child exit={code}\nstderr={stderr}");
    eprintln!("[T5] server={serve_report:?}");
    let report = last_json_line(&stdout)
        .unwrap_or_else(|| panic!("子がJSONを出さなかった。stdout={stdout}"));
    eprintln!("[T5] child report={report}");

    // --- 「使える」の裏取りは親が行う（子の申告を根拠にしない、B-25） ---
    let after = std::fs::read_to_string(&verify_path).unwrap_or_default();
    let dacl_sid = measure_capability("dacl");
    let sample = &files_dacl[files_dacl.len() / 2];
    let effective = sid_effective_ace_mask(sample, dacl_sid.as_psid()).expect("read effective mask");

    let rtt = us_of(&report, "rtt");
    let open = us_of(&report, "open");
    let handoff = us_of(&report, "handoff");
    let dacl = us_of(&report, "dacl");

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "measurement": "T-5 broker handle handoff vs ACE write, ACROSS a real process boundary",
            "items_per_arm": count,
            "fanout": FANOUT,
            "arms": report.get("arms"),
            "arm_local_dacl_in_process": {
                "total_ms": local_ms,
                "us_per_item": local_us,
                "note": "§S13腕A（123.5 µs）と同じ仕事を、今日のこのマシンで、パイプ抜きで",
            },
            "verify": report.get("verify"),
            "parent_reread_contains_child_append": after.contains(VERIFY_APPEND),
            "server": {
                "arms_seen": serve_report.arms_seen,
                "requests": serve_report.requests,
                "handed": serve_report.handed,
                "granted": serve_report.granted,
                "errors": serve_report.errors.iter().take(5).collect::<Vec<_>>(),
                "error_count": serve_report.errors.len(),
            },
            "derived": {
                "handoff_us": handoff,
                "dacl_us_cross_process": dacl,
                "local_dacl_us_in_process": local_us,
                "S13_arm_a_dacl_only_us": S13_ARM_A_US,
                "machine_drift_vs_S13_arm_a": local_us / S13_ARM_A_US,
                "S13_combined_us_same_process": S13_COMBINED_US,
                "S13_rtt_us_same_process": S13_RTT_US,
                "cross_process_rtt_us": rtt,
                "rtt_cross_over_same": rtt / S13_RTT_US,
                "open_minus_rtt_us": open - rtt,
                "handoff_minus_open_us": handoff - open,
                "handoff_vs_S13_line": handoff / S13_COMBINED_US,
                "handoff_vs_dacl_cross": handoff / dacl,
                "eager_us_per_node_from_S12": EAGER_US_PER_NODE,
                "break_even_touch_ratio_handoff": EAGER_US_PER_NODE / handoff,
                "break_even_touch_ratio_dacl_cross": EAGER_US_PER_NODE / dacl,
            },
        }))
        .unwrap()
    );

    // --- 撤収（付与と撤収は対、B-01）。**残っていないことを実測してから**消す ---
    revoke_and_verify(dir_dacl.path(), dacl_sid.as_psid());
    revoke_and_verify(dir_local.path(), local_sid.as_psid());
    revoke_and_verify(bin_dir.path(), container.as_psid());
    // ハンドル手渡しの腕は**何も書いていない**はずなので、それも確かめる（本案の売りそのもの）。
    for (label, dir) in [
        ("rtt", dir_rtt.path()),
        ("open", dir_open.path()),
        ("handoff", dir_hand.path()),
    ] {
        if let Err(leftovers) = assert_no_sid_ace_recursive(dir, dacl_sid.as_psid()) {
            panic!("{label}の腕がACEを残している（{}件）", leftovers.len());
        }
    }

    // --- ここから判定 ---
    assert!(
        report.get("ok").and_then(|v| v.as_bool()) == Some(true),
        "子が途中で倒れている。腕ごとの数字は読めない: {report}"
    );
    assert_eq!(
        serve_report.arms_seen,
        vec!["warmup", "rtt", "open", "handoff", "dacl", "verify", "done"],
        "腕が全部走っていない（走らなかった腕の数字は「速い」ではなく「無い」）"
    );
    assert!(
        serve_report.errors.is_empty(),
        "サーバ側に失敗がある。1件でもあると平均が「拒否の速さ」を含む: {:?}",
        serve_report.errors.iter().take(5).collect::<Vec<_>>()
    );
    assert_eq!(
        serve_report.handed,
        count + 1,
        "手渡した件数が合わない（+1は`verify`の1件）"
    );
    assert_eq!(
        serve_report.granted, count,
        "ACEを書いた件数が合わない。`dacl`の腕が§S13腕Cと同じ仕事をしていない"
    );

    // 腕Cと同じ仕事をしたことを、時間ではなく実効マスクで確かめる（§S13と同じ検算）。
    assert_eq!(
        effective,
        Some(mask),
        "`dacl`の腕が実際にはACEを書いていない。この腕の数字は往復だけを測っていることになる: {}",
        sample.display()
    );

    // 「渡した」と「使える」を分ける（B-35: 対で見ないと機構の手柄か分からない）。
    let verify = report.get("verify").cloned().unwrap_or(Value::Null);
    assert_eq!(
        verify.get("child_own_open_ok").and_then(|v| v.as_bool()),
        Some(false),
        "**子が自力で同じパスを開けている**。手渡しが効いたのか元から開けたのかを区別できない: {verify}"
    );
    assert_eq!(
        verify.get("read_ok").and_then(|v| v.as_bool()),
        Some(true),
        "渡したハンドルで読めていない（「渡した」だけで「使える」になっていない）: {verify}"
    );
    assert!(
        verify
            .get("read_text")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .contains(VERIFY_BODY),
        "渡したハンドルから読めた内容が違う: {verify}"
    );
    assert_eq!(
        verify.get("write_ok").and_then(|v| v.as_bool()),
        Some(true),
        "渡したハンドルで書けていない: {verify}"
    );
    assert!(
        after.contains(VERIFY_APPEND),
        "子は「書けた」と言っているが、親が読み返すと入っていない（無言の失敗）: {after:?}"
    );

    assert!(
        handoff.is_finite() && dacl.is_finite() && rtt.is_finite() && open.is_finite(),
        "腕のどれかが数字を出していない: {report}"
    );
}
