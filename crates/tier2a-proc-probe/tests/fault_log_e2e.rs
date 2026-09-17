//! [残課題#52] **記録の受け皿（VEH）が本当に書くか**を、プローブを実際に落として確かめる。
//!
//! # なぜ実プロセスで撃つのか
//!
//! VEH（例外を横取りするハンドラ）は**プロセスが実際に落ちる経路**でしか検算できない。
//! 単体テストの中で故意にアクセス違反を起こすと、テストプロセスごと落ちて
//! 「1本赤」ではなく「全部道連れ」になる。だから子プロセスとして撃ち、
//! **残った記録ファイル**を親が読む。
//!
//! # `overflow`と`null`を取り違えないための対
//!
//! | mode | 落ちる条件 | 何の検算か |
//! |---|---|---|
//! | `null` | **常に** | **VEHが記録するか**（ここで撃てる） |
//! | `overflow` | **Page Heap(Full)が効いているときだけ** | Page Heapが効いているか（昇格側の的が撃つ） |
//!
//! **兼ねられない。** `overflow`はPage Heapが無ければ落ちないのでVEHの検算にならず、
//! `null`は常に落ちるのでPage Heapの検算にならない。ここには両方の「Page Heapが無い側」を
//! 置いてあり、`overflow`が**黙って通る**ことを固定する——これが昇格側の
//! 「効いていれば落ちる」と対になって、Page Heapの有無を判定できるようにする。

use std::path::PathBuf;
use std::process::Command;

/// テスト用の記録先。**テストごとに別名**にする（並列で走っても混ざらないように）。
fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "harness-probe-fault-{tag}-{}-{nanos}.log",
        std::process::id()
    ))
}

fn probe() -> &'static str {
    env!("CARGO_BIN_EXE_tier2a_proc_probe")
}

/// 受け皿を張って**必ず落ちる的**を撃つと、落ちた場所が記録される。
///
/// **記録の中身まで見る**——ファイルが在るだけでは「空のファイルを作っただけ」と
/// 区別できない（`B-10`: 失敗を黙らせない）。
#[test]
#[cfg(windows)]
fn a_deliberate_fault_is_recorded_when_the_receiver_is_set() {
    let log = scratch("null");
    let status = Command::new(probe())
        .args(["--fault-self", "null"])
        .env("HARNESS_TEST_PROBE_FAULT_LOG", &log)
        .output()
        .expect("the probe must start");

    // 記録しても**握りつぶさない**ので、プロセスはアクセス違反で落ちる。
    assert_eq!(
        status.status.code(),
        Some(0xC000_0005u32 as i32),
        "記録した後は既定の死に方へ渡すこと（続行すると壊れたヒープの上を走る）"
    );

    let text = std::fs::read_to_string(&log).expect("記録が生まれていない");
    let _ = std::fs::remove_file(&log);

    assert!(
        text.contains("code=0xc0000005"),
        "例外コードが読めない（符号拡張していないか）: {text}"
    );
    assert!(
        text.contains("access=write") && text.contains("target=0x0"),
        "読み書きの別と触ったアドレスが要る: {text}"
    );
    assert!(
        text.contains("tier2a_proc_probe.exe+0x"),
        "アドレスがモジュール名+オフセットに解けていない（『こちらのコードか\
         システムのDLLか』が分からなくなる）: {text}"
    );
    assert!(
        text.contains("frame "),
        "戻りアドレス列が1本も無い: {text}"
    );
}

/// **受け皿を張ったときだけハンドラを登録する**（対で見る）。
///
/// # 記録ファイルの有無では検算にならない
///
/// 「張らなければ登録しない」を**自分が指定した場所にファイルが無いこと**で測ると、
/// **書き先が違うだけの実装**が素通りする——実際に変異テスト（張られていなくても
/// 既定の置き場へ書く）が緑のまま通った。だからプローブ本人に`veh_installed`を
/// 名乗らせ、そこを的にする。
///
/// これが無いと「常に登録する」実装が通り、同じプローブを使う他の的
/// （`cow-diagnostics`等）の挙動を黙って変える。
#[test]
#[cfg(windows)]
fn the_receiver_decides_whether_the_handler_is_installed_at_all() {
    let log = scratch("installed");
    let with = Command::new(probe())
        .args(["--fault-self", "none"])
        .env("HARNESS_TEST_PROBE_FAULT_LOG", &log)
        .output()
        .expect("the probe must start");
    let _ = std::fs::remove_file(&log);
    assert!(
        String::from_utf8_lossy(&with.stdout).contains("\"veh_installed\":true"),
        "張ったのに登録していない: {}",
        String::from_utf8_lossy(&with.stdout)
    );

    let without = Command::new(probe())
        .args(["--fault-self", "none"])
        .env_remove("HARNESS_TEST_PROBE_FAULT_LOG")
        .output()
        .expect("the probe must start");
    assert!(
        String::from_utf8_lossy(&without.stdout).contains("\"veh_installed\":false"),
        "張っていないのに登録している＝opt-inになっていない: {}",
        String::from_utf8_lossy(&without.stdout)
    );
}

/// 張っていないときは、**落ちても記録が生まれない**。
///
/// 上のテストが「登録したか」を見るのに対し、こちらは**実際に落として**
/// 書き出しまで起きないことを見る（登録の有無と書き出しの有無は別の事実である）。
#[test]
#[cfg(windows)]
fn nothing_is_recorded_when_the_receiver_is_not_set() {
    let log = scratch("unset");
    let status = Command::new(probe())
        .args(["--fault-self", "null"])
        .env_remove("HARNESS_TEST_PROBE_FAULT_LOG")
        .output()
        .expect("the probe must start");

    assert_eq!(
        status.status.code(),
        Some(0xC000_0005u32 as i32),
        "張っていなくても落ち方は同じ（変わるのは記録の有無だけ）"
    );
    assert!(
        !log.exists(),
        "張っていないのに記録が生まれている＝opt-inになっていない"
    );
}

/// **1バイトのはみ出しは、Page Heapが無ければ黙って通る。**
///
/// この事実が「`--fault-self overflow`はPage Heapが効いているかの判定になる」の根拠である
/// ——ここが落ちるようになったら、昇格側の的の判定は意味を失う（Page Heapの有無に
/// 関わらず落ちるので、区別できなくなる）。
#[test]
#[cfg(windows)]
fn a_one_byte_overflow_survives_without_page_heap() {
    let log = scratch("overflow");
    let out = Command::new(probe())
        .args(["--fault-self", "overflow"])
        .env("HARNESS_TEST_PROBE_FAULT_LOG", &log)
        .output()
        .expect("the probe must start");
    let _ = std::fs::remove_file(&log);

    assert_eq!(
        out.status.code(),
        Some(0),
        "Page Heapが無ければヒープの遊びに収まって通るはず: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("\"survived\":true"),
        "通ったことを自分で名乗ること: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}
