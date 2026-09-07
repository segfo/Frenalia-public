//! 計器の校正（`plans/mac-spike/RESULTS.md` §S54、`docs/STATUS.md`残課題#43）。
//!
//! # なぜ校正が要るのか
//!
//! この計器が答えるのは「**混雑でどれだけ待たされたか**」である。ところが実機の測定では
//! 混雑がそもそも再現しないことがあり——残課題#43が「再試行は一度も発火していない
//! （`busy_retries`が全て0）」と書いている——**その状態では、時間の欄が動くことを
//! 誰も確認できない**。0が返ってきたとき、それが「待っていない」なのか「測れていない」なのかを
//! 区別する手段が無い。
//!
//! そこで**混雑を意図的に作る**。1接続を受けたら決まった時間だけ次の受付を開かない
//! パイプのサーバを立て、そこへ2人続けて撃つ。
//!
//! # 対の両側を見る（`B-35`）
//!
//! | 撃つ順 | サーバの状態 | 期待 |
//! |---|---|---|
//! | 1人目 | 受付中 | `busy_retries == 0` かつ `busy_wait_us == 0` |
//! | 2人目 | 受付を閉じて眠っている | `busy_retries >= 1` かつ `busy_wait_us >= 眠り時間の半分` |
//!
//! **片側だけでは足りない。** 混雑側だけを見ると、`busy_wait_us`へ経過時間を丸ごと入れる
//! （＝混雑していなくても数字が出る）実装でも緑になる。空いている側で0が出ることまで
//! 見て初めて、この欄が「混雑で待った分」を指していると言える。
//!
//! **昇格は要らない**（自分のユーザーのパイプを1本立てるだけ）ので、`#[ignore]`を付けない
//! ——通常の`cargo test`で回り続ける。

use std::sync::mpsc;
use std::time::Duration;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
};
use windows::Win32::Storage::FileSystem::{
    FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

/// 次の受付を開くまで意図的に待つ時間。
///
/// **`Sleep`の分解能（既定15.6ms）より十分大きく取る。** 同じ桁にすると、
/// 「待たされた」と「眠りの粒度」が区別できない。
const REARM_DELAY: Duration = Duration::from_millis(400);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// **わざと遅い**名前付きパイプのサーバを1本立てる。
///
/// `clients`人ぶんを順に受け、1人捌くごとに[`REARM_DELAY`]だけ次の受付を開かない。
/// この「開いていない窓」が、Spawn Daemonの受理ループが持つ窓（§10.1）の模型である
/// ——あちらは`create_request_pipe`が返るまでの数十マイクロ秒だが、**計器を校正するには
/// 窓が測定誤差より十分に広い必要がある**ので、ここでは意図的に広げてある。
///
/// ハンドルはすべてこのスレッドの中で作って閉じる（`HANDLE`は`Send`ではない）。
fn spawn_slow_server(
    name: String,
    clients: usize,
) -> (mpsc::Receiver<()>, std::thread::JoinHandle<()>) {
    let (ready_tx, ready_rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let name_w = wide(&name);
        // **捌き終えたインスタンスを閉じずに持ち続ける。**
        //
        // ここが最初の版の誤りだった——1人目を捌いた直後に閉じたら、インスタンスが
        // 0本になって**名前ごと消え**、2人目は`ERROR_PIPE_BUSY`(231)ではなく
        // `ERROR_FILE_NOT_FOUND`(2)を受け取った。それは「混雑」ではなく「そんなパイプは無い」で、
        // 測りたい窓ではない。**Spawn Daemonの窓は「繋がったインスタンスが残っている間に
        // 次の受付がまだ開いていない」**なので、模型もその形にする。
        let mut served: Vec<HANDLE> = Vec::with_capacity(clients);
        for index in 0..clients {
            if index > 0 {
                // **次を開く前に眠る。** 順序を逆にすると眠っている間も受付が開いたままで、窓が消える。
                std::thread::sleep(REARM_DELAY);
            }
            let mut open_mode = PIPE_ACCESS_DUPLEX;
            if index == 0 {
                open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
            }
            let pipe = unsafe {
                CreateNamedPipeW(
                    PCWSTR(name_w.as_ptr()),
                    open_mode,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    PIPE_UNLIMITED_INSTANCES,
                    4096,
                    4096,
                    0,
                    None,
                )
            };
            assert!(
                pipe != INVALID_HANDLE_VALUE,
                "校正用サーバのパイプを作れなかった: {}",
                windows::core::Error::from_win32()
            );
            if index == 0 {
                // **作り終えてから合図する。** 先に合図すると、クライアントが
                // 「まだ存在しないパイプ」へ撃って`ERROR_FILE_NOT_FOUND`で即死し、
                // 混雑を測るはずの試行が別の理由で失敗する。
                let _ = ready_tx.send(());
            }
            serve_one(pipe);
            served.push(pipe);
        }
        for pipe in served {
            unsafe {
                let _ = DisconnectNamedPipe(pipe);
                let _ = CloseHandle(pipe);
            }
        }
    });
    (ready_rx, handle)
}

/// 1接続ぶんを捌く（4バイト長＋本体を読み、同じ形式で返す）。**ハンドルは閉じない**
/// （閉じる責任は呼び出し側にある。上記の「名前ごと消える」を避けるため）。
fn serve_one(pipe: HANDLE) {
    unsafe {
        let connected = ConnectNamedPipe(pipe, None);
        // 既に繋がっていれば`ERROR_PIPE_CONNECTED`。**成功として扱う**のが作法である。
        if connected.is_err() && GetLastError().0 != ERROR_PIPE_CONNECTED.0 {
            return;
        }

        let mut len_buf = [0u8; 4];
        let mut read = 0u32;
        if ReadFile(pipe, Some(&mut len_buf), Some(&mut read), None).is_ok() && read == 4 {
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut body = vec![0u8; len.min(4096)];
            let _ = ReadFile(pipe, Some(&mut body), Some(&mut read), None);

            let reply = b"calibration-reply";
            let mut frame = (reply.len() as u32).to_le_bytes().to_vec();
            frame.extend_from_slice(reply);
            let mut written = 0u32;
            let _ = WriteFile(pipe, Some(&frame), Some(&mut written), None);
            let _ = FlushFileBuffers(pipe);
        }
    }
}

fn probe_once(pipe: &str) -> super::Attempt {
    let spec = super::Spec {
        pipe_name: pipe,
        payload_override: Some("calibration"),
        report_file: None,
        repeat: 1,
        start_at_epoch_ms: None,
    };
    super::one_round_trip(&spec, 0)
}

/// **校正**: 空いているサーバへ撃った回は0、塞がっているサーバへ撃った回は実時間が出る。
///
/// 2つを**同じテストの中で順に**撃つ。別々のテストに分けると、片方だけが走った状態
/// （フィルタ・並列実行）で「対で見た」と言えなくなる。
#[test]
fn the_busy_wait_field_moves_only_when_the_pipe_is_actually_busy() {
    let name = format!(
        r"\\.\pipe\harness-t1-calibration-{}-{}",
        std::process::id(),
        super::epoch_us()
    );
    let (ready, server) = spawn_slow_server(name.clone(), 2);
    ready
        .recv_timeout(Duration::from_secs(5))
        .expect("校正用サーバが5秒以内に受付を開かなかった");

    // --- 対の「空いている」側 ---
    let idle = probe_once(&name);
    assert!(
        idle.connected,
        "空いているサーバへ繋がらなかった。last_error={} error={:?}",
        idle.last_error, idle.error
    );
    assert_eq!(
        idle.busy_retries, 0,
        "受付が開いているのに撃ち直しが起きた。混雑の判定が別の失敗を拾っている"
    );
    assert_eq!(
        idle.busy_wait_us, 0,
        "混雑していないのに待ち時間が入っている。busy_wait_usが\
         『混雑で待った分』ではなく経過時間そのものを測っている疑い"
    );
    assert!(
        idle.first_busy_at_us.is_none(),
        "混雑していないのに最初の混雑時刻が入っている: {:?}",
        idle.first_busy_at_us
    );

    // --- 対の「塞がっている」側 ---
    // 1人目を捌いたサーバは`REARM_DELAY`のあいだ次の受付を開かない。**その窓へ撃つ。**
    let busy = probe_once(&name);
    assert!(
        busy.connected,
        "撃ち直しの予算内に繋がらなかった。混雑は拒否ではないので、待てば通るはずである。\
         last_error={} error={:?}",
        busy.last_error, busy.error
    );
    assert!(
        busy.busy_retries >= 1,
        "受付が閉じている窓へ撃ったのに撃ち直しが0回だった。\
         ERROR_PIPE_BUSY(231)を混雑として数えられていない"
    );
    // **下限だけを見る。** 上限を置くと、負荷の高いマシンで偽の赤になる。
    let floor_us = (REARM_DELAY.as_micros()) / 2;
    assert!(
        busy.busy_wait_us >= floor_us,
        "混雑で待ったはずの時間が短すぎる: busy_wait_us={} < {}us。\
         回数（busy_retries={}）は出ているのに時間が出ていないなら、\
         それは校正前の計器と同じで『待ち時間の問題』を測れていない",
        busy.busy_wait_us,
        floor_us,
        busy.busy_retries
    );
    assert!(
        busy.first_busy_at_us.is_some(),
        "混雑したのに最初の混雑時刻が空のままである"
    );
    assert!(
        busy.connect_elapsed_us >= busy.busy_wait_us,
        "接続全体の時間({})が混雑で待った時間({})より短い。2つの時計が別のものを指している",
        busy.connect_elapsed_us,
        busy.busy_wait_us
    );

    server.join().expect("校正用サーバのスレッドが落ちた");
}
