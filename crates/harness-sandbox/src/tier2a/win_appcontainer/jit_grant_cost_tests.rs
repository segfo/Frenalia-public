//! **遅延実体化（JIT）でACEを1件ずつ配るときの、1件あたりの費用**
//! （[`plans/HANDOFF-FS-BOUNDARY-STATIC-ACE.md`](../../../../../plans/HANDOFF-FS-BOUNDARY-STATIC-ACE.md)
//! の「次に測ること」1番）。
//!
//! # なぜ測るのか
//!
//! いまのFS境界は、許可したいツリー全体へ**事前に**ACEを配る。26万ノードで初回22.5秒、
//! 撤収を挟む一巡で61.4秒である（`plans/mac-spike/RESULTS.md` §S12）。
//!
//! 「初回アクセス時に、そのオブジェクトへだけ配る」形にすれば、費用は**宣言したツリーの
//! 大きさ**から**実際に触った件数**へ変わる。**ただし1件あたりが高ければ、触る件数が
//! 多いワークロード（ビルド等）では事前配布より遅くなる。** どちらが速いかは
//! 「1件あたりの費用」と「触る割合」の2つでしか決まらないので、**まず前者を測る**。
//!
//! # 3つに分けて測る理由
//!
//! JITの1件は「子が要求を送る → 親がポリシーを見てACEを書く → 子へ返す」であり、
//! **費用の出所が2つある**。合算だけを測ると、高かったときにどちらを削ればよいか分からない。
//!
//! | 腕 | 測るもの | これだけで分かること |
//! |---|---|---|
//! | A | **DACL書込だけ**（1ファイルへ非継承ACEを1本、1件ずつ） | 通信を無料にしても消えない下限 |
//! | A' | 同じ書込を**ACEが既に載った状態**で（冪等スキップ） | 読取だけの床。AとA'の差が書込そのものの値段 |
//! | B | **パイプ往復だけ**（サーバは何もしない） | 通信の値段 |
//! | C | **合算**（サーバが受け取ったパスへ実際にACEを書く） | 実際のJIT 1件 |
//!
//! # この測定が言わないこと（**外挿しないこと**）
//!
//! - **同一プロセス内のスレッド間**でパイプを張っている。実物は**サンドボックスの子から
//!   親へ**の**プロセス跨ぎ**なので、スケジューリングのぶん腕BとCは**過小評価**である。
//! - **フック自体の費用を含まない**（`NtCreateFile`を横取りして分類する処理）。
//! - **失敗したopenをやり直す費用を含まない**（実物は拒否→要求→再open）。
//! - ファイルは測定用に作りたてで、**DACLが小さい**。実リポジトリのファイルは継承ACEを
//!   複数持つので、読み書きするDACLはこれより大きい。
//! - 触る割合（損益分岐の相手側）は**本モジュールでは測っていない**。
//!
//! # 実行
//!
//! **昇格しない。** ACEを書くのはテスト自身が作ったツリーだけで、主体は
//! `capability_sid_from_name`（純粋導出）＝**台帳にもプロファイルにも何も残さない**。
//!
//! ```text
//! HARNESS_TEST_JIT_COST_NODES=10000 cargo test -p harness-sandbox --lib -- \
//!     --ignored --test-threads=1 --nocapture jit_grant_cost
//! ```
//!
//! **判定が出たら本ファイルは削除する**（`docs/CODE-STRUCTURE-RULES.md`規則2）。

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, LocalFree, HLOCAL};
use windows::Win32::Security::NO_INHERITANCE;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_SHARE_MODE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};

use super::test_support::{build_wide_tree, TestDirGuard};
use super::*;
use crate::win_common::wide;
use crate::win_pipe_ipc::{
    connect_with_timeout, current_user_sid_string, read_framed_timeout, unique_pipe_name,
    user_only_security_attributes, write_framed_timeout,
};

/// §S9・§S10・§S12と同じfanout。**形が違うと数字を並べられない。**
const FANOUT: usize = 32;

/// 既定のファイル数。腕AとCで別々のツリーを作るので、26万は使わない
/// （1件ずつ書く形なので、傾きを見るには1万で足りる）。
const DEFAULT_FILE_COUNT: usize = 10_000;

/// **事前配布の1ノードあたり費用**（`plans/mac-spike/RESULTS.md` §S12-1の実測、
/// 26万ノードで22,484 ms ÷ 260,033ノード）。損益分岐の相手側として使う。
///
/// **この定数は測定値の転記である。** §S12を測り直したらここも直すこと。
const EAGER_US_PER_NODE: f64 = 86.5;

/// パイプI/Oのタイムアウト。**測っているのはµs単位の往復**なので、ここに引っ掛かるのは
/// 「速いか遅いか」ではなく「壊れている」である。
const PIPE_TIMEOUT: Duration = Duration::from_secs(30);

/// 罠の対照（腕A-naive）で回す件数の上限。**O(n²)なので上限が要る**——
/// 2,000件で既に1件あたり約1.2 msに達している（`GRANT_AUDIT_NOTE`）。
const NAIVE_ARM_CAP: usize = 2_000;

fn file_count() -> usize {
    std::env::var("HARNESS_TEST_JIT_COST_NODES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_FILE_COUNT)
}

/// 測定用のcapability SIDを**名前から導出**する（`workspace_capability_sid`は使わない
/// ——あちらは`%APPDATA%`の台帳へ秘密を永続化する）。
fn measure_capability_name(label: &str) -> String {
    format!("harness-jit-cost-{}-{label}", std::process::id())
}

fn measure_capability(label: &str) -> crate::win_common::OwnedSid {
    super::capability_sid_from_name(&measure_capability_name(label)).expect("derive capability sid")
}

/// `root`配下のファイルだけを列挙する（ディレクトリは除く）。JITが配る相手は
/// **開こうとしたオブジェクト**なので、測る対象もファイルに揃える。
fn collect_files(root: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    super::acl_grant::collect_dirs_and_files(root, &mut dirs, &mut files, OnVanished::Abort)
        .expect("enumerate the measurement tree");
    files
}

/// 1ファイルへ非継承ACEを1本書く——**JITが1件でやることそのもの**。
fn grant_one(path: &Path, sid: PSID, mask: u32) {
    super::grant_ace_mask_for_test(path, sid, mask, NO_INHERITANCE)
        .unwrap_or_else(|e| panic!("grant one ACE on {}: {e}", path.display()));
}

/// 要求受付側（親役）。`n`件ぶん「1フレーム読む → `grant`が真ならそのパスへACEを書く →
/// 1フレーム返す」を回す。**ACEを書く主体は名前から導出し直す**——`PSID`はスレッドを
/// またげないので、共有ではなく再導出で渡す。
///
/// **付与記録のガードをこのスレッドで張る**（`grant_root`）。ガードはスレッドローカルなので、
/// 呼び出し側で張っても効かない。理由は[`GRANT_AUDIT_NOTE`]を参照。
fn serve_requests(pipe_raw: isize, n: usize, grant: Option<(String, u32)>, grant_root: PathBuf) {
    let pipe = HANDLE(pipe_raw as *mut core::ffi::c_void);
    connect_with_timeout(pipe, PIPE_TIMEOUT).expect("server: wait for the client to connect");

    let sid = grant.as_ref().map(|(name, _)| {
        super::capability_sid_from_name(name).expect("server: derive capability sid")
    });
    let _audit = sid
        .as_ref()
        .map(|s| crate::tier2a::grant_audit::note_root_grant(&grant_root, s.as_psid()));

    for i in 0..n {
        let request = read_framed_timeout(pipe, PIPE_TIMEOUT)
            .unwrap_or_else(|e| panic!("server: read #{i}: {e}"));
        if let (Some(sid), Some((_, mask))) = (sid.as_ref(), grant.as_ref()) {
            let path = PathBuf::from(String::from_utf8(request).expect("server: request is a path"));
            grant_one(&path, sid.as_psid(), *mask);
        }
        write_framed_timeout(pipe, b"ok", PIPE_TIMEOUT)
            .unwrap_or_else(|e| panic!("server: write #{i}: {e}"));
    }
}

/// **最初の測定が測っていたのは、ACLではなく計装だった**（2026-08-26）。
///
/// `grant_ace_mask`は入口で`grant_audit::note_low_level_grant`を呼ぶ。これは
/// 「台帳に無いACEが載っていないか」を後で突き合わせるための**自己検証の計装**で、
/// **既定でON**である（`HARNESS_GRANT_AUDIT`未設定は`Report`。綴り間違いで黙って無効に
/// ならないよう、知らない値もONへ倒してある）。
///
/// その記録は`note_attempt`が**プロセス内の一覧を毎回線形走査して重複を弾く**——しかも
/// 比較はパス正規化つきである。**1件ずつ配る形では O(n²) になり、2,000件で1件あたり
/// 約1.2 msに達した**（うち約1.0 msが走査で、DACLの読み書きは約0.15 ms）。
///
/// **製品の一括経路はここを踏まない。** `fix_descendants_missing_ace`は先頭で
/// `note_root_grant`のガードを張り、子孫ぶんの記録を抑止する（26万ノードで全件が
/// 偽の「記録漏れ」になるため）。**JITの実装も同じ形になる**——root（宣言されたパス）を
/// 1回記録し、そこから materialize する個々のオブジェクトは記録しない。
///
/// **したがって本測定はガードを張った状態を主として測り、張らない場合を対照として残す。**
/// 対照を消さないのは、**素朴に`grant_ace_mask`をJITの口へ繋ぐと実際にこの罠を踏む**からで、
/// その事実自体が設計へ持ち帰るべき値である。
///
/// **ガードはスレッドローカルである**（`IN_ROOT_GRANT.with(...)`）。合算の腕はサーバ
/// スレッドが書くので、**そちらのスレッドで張らないと効かない**。
#[allow(dead_code)]
const GRANT_AUDIT_NOTE: () = ();

/// 要求受付用のパイプをサーバ側で作る。**呼び出しユーザー専有のDACL**
/// （`user_only_security_attributes`）で、privhelperのパイプと同じ形にしてある。
///
/// **実物のJIT要求路はこれでは足りない**——サンドボックスの子は本人専有のパイプを開けない
/// ことが実測済みで（`t4_privhelper_pipe_reach_tests`）、package SID宛のACEが要る。
/// **本測定が測っているのはパイプI/Oの値段であって、そのDACLの違いは費用に効かない。**
fn create_request_pipe(name: &str) -> HANDLE {
    let sid = current_user_sid_string().expect("current user sid");
    let mut sa = user_only_security_attributes(&sid).expect("pipe security attributes");
    unsafe {
        let name_w = wide(name);
        let handle = CreateNamedPipeW(
            PCWSTR(name_w.as_ptr()),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            4096,
            4096,
            0,
            Some(&mut sa as *mut _),
        );
        let _ = LocalFree(HLOCAL(sa.lpSecurityDescriptor));
        assert!(!handle.is_invalid(), "CreateNamedPipeW failed");
        handle
    }
}

/// 要求側（子役）としてパイプを開く。サーバスレッドがまだ`CreateNamedPipeW`を終えていない
/// 可能性があるので、**短い間隔で再試行する**（判定には関与しない起動同期）。
fn open_request_pipe(name: &str) -> HANDLE {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let handle = unsafe {
            let name_w = wide(name);
            CreateFileW(
                PCWSTR(name_w.as_ptr()),
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                None,
            )
        };
        match handle {
            Ok(h) => return h,
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "client: could not open the request pipe within 10 s: {e}"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

/// **JIT 1件あたりの費用を、書込・通信・合算の3つに割って測る。**
///
/// assertするのは揺れない構造の側だけで、**時間は判定に使わず値として出す**
/// （マシンの状態で揺れるため）。時間を読むのは人間の仕事である。
#[test]
#[ignore = "creates thousands of files and writes DACLs one at a time; run NON-elevated"]
fn jit_grant_cost_per_miss() {
    let count = file_count();
    let mask = fs_access_mask(FsAccess::Read);

    // ---------- 腕A: DACL書込だけ（**製品の一括経路と同じく、付与記録のガードを張る**） ----------
    let dir_a = TestDirGuard::create("jitcost-write");
    let nodes_a = build_wide_tree(dir_a.path(), count, FANOUT);
    let files_a = collect_files(dir_a.path());
    let sid_a = measure_capability("write");

    let write_ms;
    let skip_ms;
    {
        let _audit = crate::tier2a::grant_audit::note_root_grant(dir_a.path(), sid_a.as_psid());

        let t = Instant::now();
        for f in &files_a {
            grant_one(f, sid_a.as_psid(), mask);
        }
        write_ms = t.elapsed().as_millis();

        // 腕A': 同じ呼び出しを、ACEが既に載った状態で（冪等スキップ＝読取だけの床）。
        let t = Instant::now();
        for f in &files_a {
            grant_one(f, sid_a.as_psid(), mask);
        }
        skip_ms = t.elapsed().as_millis();
    }

    // ---------- 腕A-naive: ガードを張らない場合（**罠の対照**、`GRANT_AUDIT_NOTE`） ----------
    // O(n²)なので件数を絞る。**絞ったこと自体が結論**である——絞らないと終わらない。
    let naive_count = files_a.len().min(NAIVE_ARM_CAP);
    let dir_naive = TestDirGuard::create("jitcost-naive");
    build_wide_tree(dir_naive.path(), naive_count, FANOUT);
    let files_naive = collect_files(dir_naive.path());
    let sid_naive = measure_capability("naive");
    let naive_n = files_naive.len().min(naive_count);
    let t = Instant::now();
    for f in files_naive.iter().take(naive_n) {
        grant_one(f, sid_naive.as_psid(), mask);
    }
    let naive_ms = t.elapsed().as_millis();

    // ---------- 腕B: パイプ往復だけ ----------
    let pipe_name_b = unique_pipe_name("jitcost-rtt");
    let server_pipe_b = create_request_pipe(&pipe_name_b);
    let raw_b = server_pipe_b.0 as isize;
    let n_b = files_a.len();
    let server_b = std::thread::spawn(move || serve_requests(raw_b, n_b, None, PathBuf::new()));
    let client_b = open_request_pipe(&pipe_name_b);

    let t = Instant::now();
    for f in &files_a {
        let payload = f.to_string_lossy().into_owned();
        write_framed_timeout(client_b, payload.as_bytes(), PIPE_TIMEOUT).expect("client: write");
        let reply = read_framed_timeout(client_b, PIPE_TIMEOUT).expect("client: read");
        assert_eq!(reply, b"ok", "the server must answer every request");
    }
    let rtt_ms = t.elapsed().as_millis();
    unsafe {
        let _ = CloseHandle(client_b);
    }
    server_b.join().expect("server thread (rtt arm)");
    unsafe {
        let _ = CloseHandle(server_pipe_b);
    }

    // ---------- 腕C: 合算（サーバが受け取ったパスへ実際に書く） ----------
    let dir_c = TestDirGuard::create("jitcost-combined");
    let nodes_c = build_wide_tree(dir_c.path(), count, FANOUT);
    let files_c = collect_files(dir_c.path());
    let sid_c = measure_capability("combined");

    let pipe_name_c = unique_pipe_name("jitcost-full");
    let server_pipe_c = create_request_pipe(&pipe_name_c);
    let raw_c = server_pipe_c.0 as isize;
    let n_c = files_c.len();
    let grant_spec = Some((measure_capability_name("combined"), mask));
    let grant_root_c = dir_c.path().to_path_buf();
    let server_c = std::thread::spawn(move || serve_requests(raw_c, n_c, grant_spec, grant_root_c));
    let client_c = open_request_pipe(&pipe_name_c);

    let t = Instant::now();
    for f in &files_c {
        let payload = f.to_string_lossy().into_owned();
        write_framed_timeout(client_c, payload.as_bytes(), PIPE_TIMEOUT).expect("client: write");
        let reply = read_framed_timeout(client_c, PIPE_TIMEOUT).expect("client: read");
        assert_eq!(reply, b"ok", "the server must answer every request");
    }
    let combined_ms = t.elapsed().as_millis();
    unsafe {
        let _ = CloseHandle(client_c);
    }
    server_c.join().expect("server thread (combined arm)");
    unsafe {
        let _ = CloseHandle(server_pipe_c);
    }

    // ---------- 実効の確認（B-25: 「呼んだ」ではなく「載った」を見る） ----------
    let sample = &files_c[files_c.len() / 2];
    let effective = sid_effective_ace_mask(sample, sid_c.as_psid()).expect("read effective mask");

    let per = |ms: u128| (ms as f64) * 1000.0 / (files_a.len() as f64);
    let combined_us = per(combined_ms);
    // 損益分岐: JITが事前配布より安いのは「触る割合 < 事前配布の1件 ÷ JITの1件」のとき。
    let break_even_touch_ratio = EAGER_US_PER_NODE / combined_us;

    println!(
        "{}",
        serde_json::json!({
            "measurement": "JIT per-miss cost (single-object DACL write + one pipe round trip)",
            "file_count": count,
            "files_measured": files_a.len(),
            "nodes_tree_a": nodes_a,
            "nodes_tree_c": nodes_c,
            "fanout": FANOUT,
            "arm_a_dacl_write_only": { "total_ms": write_ms, "us_per_item": per(write_ms) },
            "arm_a_prime_idempotent_skip": { "total_ms": skip_ms, "us_per_item": per(skip_ms) },
            "arm_a_naive_without_audit_guard": {
                "items": naive_n,
                "total_ms": naive_ms,
                "us_per_item": (naive_ms as f64) * 1000.0 / (naive_n as f64),
                "note": "O(n^2) grant-audit scan; the product's bulk path suppresses this",
            },
            "arm_b_pipe_round_trip_only": { "total_ms": rtt_ms, "us_per_item": per(rtt_ms) },
            "arm_c_combined": { "total_ms": combined_ms, "us_per_item": combined_us },
            "eager_us_per_node_from_S12": EAGER_US_PER_NODE,
            "jit_over_eager": combined_us / EAGER_US_PER_NODE,
            "break_even_touch_ratio": break_even_touch_ratio,
        })
    );

    // 撤収（付与と撤収は対、B-01）。**残っていないことを実測してから**ツリーを消す。
    for (root, sid) in [
        (dir_a.path(), sid_a.as_psid()),
        (dir_c.path(), sid_c.as_psid()),
        (dir_naive.path(), sid_naive.as_psid()),
    ] {
        let report = revoke_ace_recursive(root, sid).expect("revoke the measurement ACEs");
        println!("  revoke {}: {report:?}", root.display());
        if let Err(leftovers) = assert_no_sid_ace_recursive(root, sid) {
            panic!(
                "the measurement SID still has ACEs on {} node(s) after revoke; first few: {:?}",
                leftovers.len(),
                leftovers.iter().take(5).collect::<Vec<_>>()
            );
        }
    }

    assert!(
        files_a.len() >= count,
        "the tree must actually contain the files being measured (got {})",
        files_a.len()
    );
    assert_eq!(
        files_a.len(),
        files_c.len(),
        "the two trees must be the same size, otherwise the per-item numbers are not comparable"
    );
    // **腕Cが本当に書いたことを、時間ではなく実効マスクで確かめる**——ここが`None`なら
    // 腕Cは「パイプ往復だけ」を測っていたことになり、合算という主張が崩れる。
    assert_eq!(
        effective,
        Some(mask),
        "the combined arm must have left the requested mask on {}; if this is None the server \
         never wrote anything and the 'combined' number is really just arm B",
        sample.display()
    );
}
