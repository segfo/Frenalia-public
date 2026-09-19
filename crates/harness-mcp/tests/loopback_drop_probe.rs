//! **ループバックの接続要求を誰が捨てているのかを名指しさせるための計測**（残課題#53）。
//!
//! ## なぜテストの形をしているのか
//!
//! ここに居るのはテストではなく**測定の操作**である。それでもテストとして書いてあるのは、
//! このリポジトリで昇格が要る操作を撃つ唯一の経路が`dev-elevated-runner`であり、
//! そこは**固定表`KNOWN_TARGETS`のキーと完全一致するcargoの呼び出し**しか実行しないためである
//! （無検証の文字列を管理者権限で実行させる口を作らない、という設計）。したがって
//! 「単発の管理者コマンド」は操作の側をテストにして表へ足す（`CLAUDE.md`「開発コマンド」）。
//!
//! ## なぜ開始・報告・停止が別のテストなのか
//!
//! **昇格側のプロセスへ呼び出し元の環境変数が引き継がれる保証が無い。** 1つのテストに
//! 「向き」を引数や環境変数で渡すと、引き継がれなかったときに**停止したつもりで開始していた**
//! という無言の取り違えになる（`n2-loopback-exemption-add`／`-remove`が分かれているのと同じ理由）。
//!
//! ## 何を残すか
//!
//! 監視セッションとキャプチャフィルタは**実マシンに残る共有状態**である。だから
//! [`stop_the_loopback_drop_monitor`]が対の撤収で、**掛ける前の状態（フィルタ0件）を
//! 開始側が記録し、停止側が戻ったことを実測して残す**。出力は全部
//! `C:\harness-e2e\tls-flake-lane-c\pktmon-*.txt`へ書く（判定はその場で、証拠は後から読める形で）。
//!
//! ## この版の綴り
//!
//! `pktmon`の下位コマンドと旗は版で変わる。**この機械（Windows 11 build 26200）で
//! `pktmon help`／`pktmon start help`／`pktmon counters help`／`pktmon filter add help`を
//! 読んで確かめた綴り**だけを使っている。別の機械へ持っていくときは読み直すこと。

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// 出力の置き場。測定のログと同じところへ置く（後から同じ時計で突き合わせるため）。
fn output_dir() -> PathBuf {
    PathBuf::from(r"C:\harness-e2e\tls-flake-lane-c")
}

/// ループバックのTCPだけを報告対象にするフィルタの名前。
const FILTER_NAME: &str = "laneC-loopback-tcp";

/// `pktmon`を1回撃ち、標準出力と標準エラーを**バイトのまま**ファイルへ残す。
///
/// 出力は日本語（CP932）なので、文字列にしてから書くと化ける。判定に使う分だけ
/// `from_utf8_lossy`で見る。
fn pktmon(args: &[&str], label: &str) -> (bool, String) {
    let out = Command::new("pktmon")
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("could not run `pktmon {}`: {e}", args.join(" ")));

    let path = output_dir().join(format!("pktmon-{label}.txt"));
    let mut blob = format!("$ pktmon {}\n", args.join(" ")).into_bytes();
    blob.extend_from_slice(&out.stdout);
    blob.extend_from_slice(b"\n--- stderr ---\n");
    blob.extend_from_slice(&out.stderr);
    std::fs::create_dir_all(output_dir()).ok();
    std::fs::write(&path, &blob).unwrap_or_else(|e| panic!("could not write {path:?}: {e}"));

    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    println!("=== pktmon {} (ok={}) -> {}", args.join(" "), out.status.success(), path.display());
    println!("{text}");
    (out.status.success(), text)
}

fn print_file(path: &Path) {
    if let Ok(bytes) = std::fs::read(path) {
        println!("--- {} ({} bytes) ---", path.display(), bytes.len());
    }
}

/// **開始側**。掛ける前の状態を記録してから、ループバックTCPだけに絞って計数を始める。
///
/// `--counters-only`（＝`--capture --flags 0`）を使う: **どの部品で何件落ちたかを数えるだけ**で、
/// パケットを1本も記録しない。層が分かれば重いキャプチャは要らない、という順序のため。
#[test]
#[ignore = "実マシンに監視セッションを作る。dev-elevated-run の pktmon-drop-start から撃つ"]
fn start_the_loopback_drop_monitor() {
    std::fs::create_dir_all(output_dir()).expect("output dir");

    // **掛ける前の状態を残す。** 撤収したことを後から言うには、元が何だったかが要る。
    pktmon(&["status"], "before-status");
    pktmon(&["filter", "list"], "before-filter-list");

    // ループバックのTCPだけを報告対象にする（雑音を減らす）。
    let (ok, text) = pktmon(
        &["filter", "add", FILTER_NAME, "-i", "127.0.0.1", "-t", "TCP"],
        "filter-add",
    );
    assert!(ok, "could not add the loopback tcp filter: {text}");

    let (ok, text) = pktmon(&["start", "--capture", "--counters-only"], "start");
    assert!(ok, "could not start counters-only monitoring: {text}");

    // **開始したことを問い合わせで確かめる。** 「撃ったから動いているはず」にしない。
    let (ok, status) = pktmon(&["status"], "after-start-status");
    assert!(ok, "could not query the monitor status");
    assert!(
        !status.trim().is_empty(),
        "the status query must say something once monitoring started"
    );
}

/// **報告側**。落ちた数と、**その部品での直近の理由**を出す。
///
/// `--drop-reason`がこの測定の中心である——件数だけでは「どこで落ちたか」しか分からず、
/// 「なぜ落ちたか」が出ない。`--json`はこの版では`-i`(非表示の部品も)と`-r`(理由)を含む。
#[test]
#[ignore = "dev-elevated-run の pktmon-drop-report から撃つ"]
fn report_the_loopback_drops() {
    let (ok, _) = pktmon(&["status"], "report-status");
    assert!(ok, "the monitor must still be running when the report is taken");

    pktmon(&["counters", "--type", "drop", "--drop-reason"], "counters-drop");
    pktmon(&["counters", "--type", "drop", "--json"], "counters-drop-json");
    pktmon(&["counters", "--type", "all"], "counters-all");

    // **計器が対象を見ているかを、対象と別に確かめる。** 最初の試行では`--type all`まで
    // ゼロだった——ループバックのTCPが1本も無かったのではなく、**この計器にその経路が
    // 見えていない**可能性がある。区別するには「どの部品を監視できているか」と
    // 「ゼロの部品も含めた全カウンター」を並べるしかない。
    pktmon(&["list", "--all", "--include-hidden"], "list-all");
    pktmon(
        &["counters", "--type", "all", "--include-hidden", "--zero"],
        "counters-all-zero",
    );

    for label in [
        "counters-drop",
        "counters-drop-json",
        "counters-all",
        "list-all",
        "counters-all-zero",
    ] {
        print_file(&output_dir().join(format!("pktmon-{label}.txt")));
    }
}

/// ETLの置き場。停止側が`etl2txt`で読める形へ変換する。
fn etl_path() -> PathBuf {
    output_dir().join("laneC-tcpip.etl")
}

/// **もう一つの開始側**——パケットではなく**TCPIPのイベント**を集める。
///
/// **なぜ分けたか**: 最初に撃った`--capture`（パケットの計数）は、`--type all`まで
/// ゼロだった。`pktmon list`が挙げる監視対象は**NDISの層の部品だけ**（vSwitch・NIC・
/// フィルタドライバ）で、Windowsの`127.0.0.1`はそこを通らずTCP/IPスタックの中で折り返す。
/// **つまりあの計器にはこの経路が原理的に見えていない**——「落ちていない」ではなく
/// 「見ていない」である。だから層を1つ上げて、TCPIPプロバイダのイベントを直接集める。
///
/// 綴りは`pktmon start help`の例4そのもの（`--trace -p <provider>`）。
#[test]
#[ignore = "実マシンにETWセッションを作る。dev-elevated-run の pktmon-trace-start から撃つ"]
fn start_the_tcpip_event_trace() {
    std::fs::create_dir_all(output_dir()).expect("output dir");

    // 直前のセッションが残っていても開始できるよう、先に止める（止まっていれば無害）。
    pktmon(&["stop"], "trace-pre-stop");
    pktmon(&["filter", "remove"], "trace-pre-filter-remove");
    let _ = std::fs::remove_file(etl_path());

    let etl = etl_path();
    let etl = etl.to_str().expect("utf-8 path");
    // **上限を置く。** TCPIPプロバイダは饒舌なので、置かないと機械の空きを食い潰す。
    let (ok, text) = pktmon(
        &[
            "start",
            "--trace",
            "-p",
            "Microsoft-Windows-TCPIP",
            "--file-name",
            etl,
            "--file-size",
            "512",
        ],
        "trace-start",
    );
    assert!(ok, "could not start the tcpip event trace: {text}");

    let (ok, status) = pktmon(&["status"], "trace-after-start-status");
    assert!(ok, "could not query the monitor status");
    assert!(!status.trim().is_empty(), "the status query must say something");
}

/// **停止側（撤収）**。セッションを止め、掛けたフィルタを外し、**戻ったことを実測する**。
///
/// 片方だけ残すと次の測定の交絡になるので、停止とフィルタ削除を**両方**撃ってから
/// 問い合わせる。`pktmon stop`が「動いていない」で非0を返す場合もあるため、
/// **成否ではなく問い合わせの結果で判定する**。
#[test]
#[ignore = "dev-elevated-run の pktmon-drop-stop から撃つ"]
fn stop_the_loopback_drop_monitor() {
    pktmon(&["stop"], "stop");
    pktmon(&["filter", "remove"], "filter-remove");

    // **どちらの開始側で始めていても、この1本で片付く形にしてある。** 停止のキーを
    // 2つに割ると「どちらを撃てばよいか」を撃つ側が判断することになり、判断を外した回に
    // セッションが残る。ETLが在れば読める形へ変換し、無ければ何もしない。
    let etl = etl_path();
    if etl.exists() {
        let bytes = std::fs::metadata(&etl).map(|m| m.len()).unwrap_or(0);
        println!("etl: {} ({bytes} bytes)", etl.display());
        let txt = output_dir().join("laneC-tcpip.txt");
        pktmon(
            &[
                "etl2txt",
                etl.to_str().expect("utf-8"),
                "--out",
                txt.to_str().expect("utf-8"),
                "--timestamp",
            ],
            "etl2txt",
        );
        print_file(&txt);
    }

    let (_, status) = pktmon(&["status"], "after-stop-status");
    let (_, filters) = pktmon(&["filter", "list"], "after-stop-filter-list");

    // 掛けた名前が残っていないことだけは機械で判定する（文面は版で変わるので名前で見る）。
    assert!(
        !filters.contains(FILTER_NAME),
        "the loopback filter must be gone after the stop target: {filters}"
    );
    println!("status after stop:\n{status}");
}
