//! [残課題#52] **プローブがどこでヒープを壊しているか**を、Page Heap(Full)とVEHで出す測定。
//!
//! # 何を測っているのか
//!
//! `--spawn-matrix`のプローブはAppContainerの中で**ときどき最後に落ちる**
//! （`0xC0000374`＝ヒープ破壊）。段階6f-2はこれを「計器の元からの不具合」として積んだが、
//! **根本原因は追っていない**。追えなかったのは道具が無かったからである。
//!
//! ```text
//!   素のまま         : どこかで破壊 → 後の確保/解放で検知 → fail-fast（VEHを飛び越えて即死）
//!   Page Heap(Full)  : 破壊した瞬間に番兵ページを踏む → ただのアクセス違反 → VEHが記録できる
//! ```
//!
//! `fail-fast`は「誰にも捕まえさせず即死させる」Windowsの仕組みで、例外ハンドラを飛び越える。
//! だから**VEH（例外を横取りするハンドラ）だけでは捕まらない**。Page Heap(Full)が
//! 「捕まえられない即死」を「正確な場所での、捕まえられるアクセス違反」へ変えて初めて、
//! プローブ側の`fault_log`が場所を記録できる。**2つとも要るのはこの噛み合わせのためである。**
//!
//! # なぜ受け入れ（`spawn-daemon`）と別の的なのか
//!
//! Page Heapはレジストリで**実行ファイル名に対して機械全体に効く**。受け入れの中で載せると、
//! 同じプローブを使う他の測定まで「デバッグ用アロケータの下の挙動」を測ることになる。
//! **受け入れが測るのは製品の挙動**なので、計器で測定対象を変えてはいけない。
//!
//! だから`spawn-daemon`はこの1本を`--skip`で外し、`spawn-daemon-pageheap`が名前で拾う
//! ——`spawn-daemon-latency`とまったく同じ置き方である。**本体をこのモジュールに置いてある**
//! ので、時期が来て一本化するときは`--skip`の行と専用ターゲットの項を消すだけでよい
//! （引っ越しは起きない）。
//!
//! # この的は「破壊が起きたか」では赤くしない
//!
//! 破壊は**出ないこともある**——Page Heapはヒープの配置を変えるので、配置に依存するバグは
//! 消える。赤くするのは**測定が成立していないとき**だけである。
//!
//! | 赤くする条件 | なぜ |
//! |---|---|
//! | Page Heapが**効いていない** | 「破壊が出ない＝きれい」という**偽の合格**になる。いちばん危ない |
//! | VEHの**受け皿が繋がっていない** | 落ちても記録が残らず、やはり偽の合格になる |
//! | 生成禁止を積まない腕で**マーカーが1つも生まれない** | プローブが8経路を撃てていない＝そもそも測っていない |
//! | **撤収に失敗した** | Page Heapがレジストリに載りっぱなしになる |
//!
//! 上2つは**同じ1回の測定で見る**（`--fault-self overflow`）——Page Heapが効いていれば
//! そこで落ち、受け皿が繋がっていればその落下が記録される。
//!
//! # ここで測っていないもの（**limitation**）
//!
//! - **`fail-fast`のままなら1回も記録されない。** 番兵ページを踏む前にアロケータが先に
//!   気づく形だと、VEHは呼ばれない。そのときこの測定は**空振り**である（赤にはならない）
//! - **隔離は規約であって機構ではない。** `spawn-daemon`と同時に回せばIFEOは機械全体に
//!   効くので巻き込む。順に回す前提である
//! - **場所が分かっても直らない。** これは診断であって修正ではない

use super::super::page_heap;
use super::super::test_support::scopeguard;
use super::*;

/// プローブ側のVEHの受け皿（`tier2a-proc-probe`の`fault_log::FAULT_LOG_ENV`と**対の綴り**）。
///
/// プローブはバイナリクレートなので定数を共有できず、**両端に同じ文字列を持つ**
/// ——ズレてもコンパイラは教えてくれない（`B-05`）。だから綴りが合っていることを
/// `--fault-self overflow`の腕が**実測で**見張る（受け皿が繋がっていなければ記録が生まれない）。
const PROBE_FAULT_LOG_ENV: &str = "HARNESS_TEST_PROBE_FAULT_LOG";

/// 未処理のアクセス違反でプロセスが終わるときの終了コード。
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;

/// プローブを1本起こして、標準出力・標準エラー・終了コードを取る。
///
/// [`super::start_top_level`]に**VEHの受け皿だけ**を足した呼び方である。
fn run_probe(
    case: &Case,
    profile: &OwnedContainerSid,
    caps: &[crate::win_common::OwnedSid],
    args: &[&str],
    fault_log: &std::path::Path,
) -> (String, String, u32) {
    let daemon = case.daemon.as_ref().expect("case owns the daemon");
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();
    let probe = super::super::mac_spike_tests::probe_exe();
    let probe_str = probe.to_str().expect("probe path is utf-8").to_string();

    let (child, job, out, err) = super::start_top_level(
        daemon,
        profile,
        &workspace,
        super::TopLevelArm {
            exe: &probe_str,
            args,
            domain: super::domain_spec(profile, caps, None),
            console: ConsoleNeed::NotNeeded,
            // **注入しない。** 測っているのはプローブ自身のヒープであって、
            // フックの挙動ではない（注入すると測定対象にDLLが1つ増える）。
            redirector: None,
            extra_env: vec![(
                PROBE_FAULT_LOG_ENV.to_string(),
                fault_log.to_string_lossy().into_owned(),
            )],
        },
    );
    let code = super::wait_and_close_with_code(&child, job);
    (out, err, code)
}

/// 記録が在れば標準エラーへ丸ごと写す。**在っても赤くしない**——記録が出ることが
/// この測定の成果であって、合否ではない。
fn dump_fault_log(tag: &str, path: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    if text.trim().is_empty() {
        return None;
    }
    eprintln!("[pageheap {tag}] ---- fault record ----\n{text}");
    Some(text)
}

/// Page Heap(Full)の下で`--spawn-matrix`を走らせ、落ちたなら**どこで落ちたか**を記録する。
///
/// **`spawn-daemon`からは`--skip`で外れている**（モジュールdoc）。撃つのは
/// `dev-elevated-run.exe spawn-daemon-pageheap`である。
#[test]
#[ignore = "loads Page Heap into the registry and starts real AppContainer children; run through spawn-daemon-pageheap"]
fn the_spawn_matrix_under_page_heap_records_where_it_faults() {
    let probe = super::super::mac_spike_tests::probe_exe();
    let image = probe
        .file_name()
        .and_then(|n| n.to_str())
        .expect("probe file name is utf-8")
        .to_string();

    page_heap::enable_full(&image).expect("Page Heapを載せる（昇格が要る）");
    // **落ちても外す。** 撤収は冪等なので、末尾の明示的な撤収と二重で呼ばれてよい。
    let _restore = scopeguard({
        let image = image.clone();
        move || {
            let _ = page_heap::disable(&image);
        }
    });
    assert!(
        page_heap::is_enabled(&image),
        "載せた直後に載っていない＝レジストリへ書けていない"
    );

    let mut engaged_anywhere = false;
    for policy in [
        ChildProcessPolicy::Unrestricted,
        ChildProcessPolicy::Restricted,
    ] {
        let arm = policy.as_arg();
        let label = format!("spawnd-pageheap-{arm}");
        let (case, profile, caps) = super::setup_with_policy(&label, policy);
        let workspace = case
            .dir
            .as_ref()
            .expect("case owns the dir")
            .path()
            .to_path_buf();

        // --- (1) Page Heapが本当に効いているか＋受け皿が繋がっているか。
        // `--fault-self overflow`は**Page Heapが効いているときだけ**落ちる的である
        // （効いていなければヒープの遊びに収まって黙って通る）。
        let engaged_log = workspace.join("fault-engaged.log");
        let (out, err, code) = run_probe(
            &case,
            &profile,
            &caps,
            &["--fault-self", "overflow"],
            &engaged_log,
        );
        eprintln!("[pageheap {arm}] fault-self exit={code:#010x} stdout={out} stderr={err}");
        assert_eq!(
            code, STATUS_ACCESS_VIOLATION,
            "AppContainerの中でPage Heapが効いていない（はみ出しが黙って通った）。\
             効いていないまま先へ進むと『破壊が出ない＝きれい』という偽の合格になる"
        );
        assert!(
            dump_fault_log(arm, &engaged_log).is_some(),
            "落ちたのに記録が無い＝VEHの受け皿({PROBE_FAULT_LOG_ENV})が繋がっていない"
        );
        engaged_anywhere = true;

        // --- (2) 本番の測定。8経路を撃たせ、落ちたなら場所を記録させる。
        let marker_dir = workspace.join("spawn-markers");
        std::fs::create_dir_all(&marker_dir).expect("marker dir");
        let marker_str = marker_dir.to_string_lossy().into_owned();
        let matrix_log = workspace.join("fault-matrix.log");
        let (out, err, code) = run_probe(
            &case,
            &profile,
            &caps,
            &["--spawn-matrix", &marker_str, "--timeout-secs", "60"],
            &matrix_log,
        );
        eprintln!("[pageheap {arm}] spawn-matrix exit={code:#010x}\nstdout={out}\nstderr={err}");
        dump_fault_log(arm, &matrix_log);

        let mut markers: Vec<String> = std::fs::read_dir(&marker_dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        markers.sort();
        eprintln!("[pageheap {arm}] markers={markers:?}");

        // **測定が成立しているかだけを見る。** 生成禁止を積まない腕で1つも生まれないなら、
        // プローブは8経路を撃てていない（＝そもそも測っていない）。積んだ腕で0本なのは
        // 正しい結果なので、ここでは条件にしない。
        if policy == ChildProcessPolicy::Unrestricted {
            assert!(
                !markers.is_empty(),
                "生成禁止を積まない腕で1つも子が生まれていない＝プローブが経路を撃てていない"
            );
        }

        drop(case);
    }
    assert!(engaged_anywhere, "腕が1本も走っていない");

    page_heap::disable(&image).expect("Page Heapを外す");
    assert!(
        !page_heap::is_enabled(&image),
        "撤収したのにキーが残っている＝機械に載りっぱなしになる"
    );
}
