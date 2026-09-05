//! **同じコンソールに繋がったプロセス同士が、互いの画面バッファを読めるか・互いを落とせるか**を
//! 測る短絡モード（`plans/mac-spike/RESULTS.md` §S48、設計書§7.1.1の測定3）。
//!
//! # なぜ要るか
//!
//! §7.1.1は、`CHILD_PROCESS_RESTRICTED`を積んだシェルを走らせるために
//! **コンソール保持プロセス**を1本立て、Daemonがその瞬間だけコンソールを借りる形を採った。
//! そのとき残る問いが「**保持プロセスを何本持つか**」である。
//!
//! 1本を全ドメインで共有すると、ファイル・ネットワーク・プロセスのどれもドメインごとに
//! 分けてあるのに、**コンソールだけが横断チャネルになる**。同じコンソールに繋がった
//! シェル同士が互いの出力を読めたり、互いへCtrl+Breakを撃てたりするなら、
//! 保持プロセスはドメインごとに要る（その費用は§22.9の表に載る）。
//!
//! **逆向きにも効く。** サンドボックスの中から画面バッファへ**そもそも触れない**なら、
//! 横断する通り道が存在しないので、保持プロセスを共有できる余地が出る＝費用が減る。
//! **どちらに転んでも設計に返る**ので、憶測ではなく実測で決める。
//!
//! # 測るもの
//!
//! | 引数 | 何をするか |
//! |---|---|
//! | `--console-write <text>` | `CONOUT$`を開き、画面バッファの原点へ`text`を書く |
//! | `--console-read` | `CONOUT$`を開き、画面バッファの原点から読み返す |
//! | `--console-ctrl-break` | 同じコンソールの全プロセスへ`CTRL_BREAK_EVENT`を撃つ |
//! | `--console-ctrl-c` | 同じコンソールの全プロセスへ`CTRL_C_EVENT`を撃つ |
//! | `--console-ctrl-receipt <path>` | 制御イベントを受け取ったら種類を`<path>`へ書き切って終わる（受け取る側） |
//! | `--console-ctrl-cleanup <path>` | 上記の後始末で書き切る先。待っている間はバッファに残す |
//! | `--console-ctrl-accept` | `CTRL_C_EVENT`を受け取る側へ戻す（上流から受け継いだ「無視する」属性を自分だけ外す） |
//! | `--console-ctrl-ignore` | 逆に自分で「無視する」側にする（親が立てていない環境で、立っていたらどうなるかを測る） |
//! | `--console-watch-input` | 待っている間、押されたキーそのものを読んで同じ記録へ積む（「押せているか」を割る） |
//! | `--console-idle-secs <n>` | 上記の後、`n`秒生き続ける（撃たれる側になる腕で使う） |
//!
//! **制御イベントを2種類撃てるようにしてあるのは、§7.1.1の測定7のためである**——
//! 保持プロセスがハンドラで自分を守れたとして、**守りが片方の種類にしか効かない**なら
//! 「サンドボックスから届く経路が塞がった」とは書けない。
//!
//! # 受け取る側を測る（測定8、`--console-ctrl-receipt`）
//!
//! 測定7では`CTRL_C_EVENT`について**何も言えなかった**——撃つのは成功するのに、
//! 守っていない相手すら落ちなかったので、「届いていない」と「届いたが既定の反応が終了ではない」
//! が潰れたままだった（[§S49](../../../plans/mac-spike/RESULTS.md)）。
//!
//! **死ぬかどうかで測るのをやめ、受け取ったかどうかを直接記録すれば割れる。**
//! `--console-ctrl-receipt`を付けた腕は、制御イベントを受け取ると
//! (1) 種類をファイルへ書き切り、(2) 待っている間バッファに残していた印を書き切って閉じ、
//! (3) [`CTRL_HANDLED_EXIT_CODE`]で終わる。**記録が残れば、死ななくても届いたと言える。**
//!
//! **`--console-write`と`--console-read`は同時に指定できる。** ただし実測（§S48）では
//! **サンドボックスの中からは書けるが読めない**（読みは`ERROR_ACCESS_DENIED`）ので、
//! 「書いた本人が読み返す」は検算にならない。**書けたことの検算は、AppContainerでない腕が
//! 同じ画面バッファを読めることで取る。**
//!
//! # 出力の形は`object_reach`に合わせる
//!
//! 1行のJSONで、試行1件ごとに`kind`/`ok`/`last_error`を持つ。読む側
//! （`mac_spike_daemon_tests`）は`reach_attempt_ok`と同じ形で引ける。
//! **同じ量を2つの綴りで出さない。**

use serde_json::{json, Value};

/// 画面バッファから読み返す文字数。**行の折り返しに依存させない**ため、
/// 原点から1行ぶんより多め・全部より十分少なめの固定長を読む。
#[cfg(windows)]
const READ_CHARS: u32 = 256;

pub struct Spec {
    /// 画面バッファへ書く文字列。
    pub write: Option<String>,
    /// 画面バッファから読み返すか。
    pub read: bool,
    /// 同じコンソールの全プロセスへ`CTRL_BREAK_EVENT`を撃つか。
    pub ctrl_break: bool,
    /// 同じコンソールの全プロセスへ`CTRL_C_EVENT`を撃つか。
    pub ctrl_c: bool,
    /// 受け取った制御イベントを書き切る先（指定すると「受け取る側」の仕掛けが入る）。
    pub ctrl_receipt: Option<String>,
    /// 後始末で書き切る先（待っている間はバッファに残したままにする）。
    pub ctrl_cleanup: Option<String>,
    /// 待っている間、**コンソールの入力そのもの**も読んで同じ記録へ積むか
    /// （[`watch_console_input`]）。「押したのに何も起きない」を割るための腕。
    pub watch_input: bool,
    /// `CTRL_C_EVENT`の扱いをどうしたか（[`apply_ctrl_c_mode`]の戻り値をそのまま持つ）。
    /// **レポートへ出すためだけに持ち回る**——適用そのものは`main`が最初に済ませている。
    pub ctrl_c_mode: &'static str,
    /// 上記を済ませた後、生き続ける秒数（0なら即終了）。
    pub idle_secs: u64,
}

#[cfg(windows)]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `CTRL_BREAK_EVENT`を「処理した」と答えて既定の終了を止めるハンドラ。
///
/// **入れる相手は2つある。** 撃つ側（これが無いと、撃った本人がプロセスグループの巻き添えで
/// `STATUS_CONTROL_C_EXIT`（`0xC000013A`）で死に、レポートを出し切る前に消える）と、
/// **撃たれる側**（設計書§7.1.1の測定7＝保持プロセスがこの手で自分を守れるか）である。
#[cfg(windows)]
unsafe extern "system" fn ignore_ctrl_event(_ctrl_type: u32) -> windows::Win32::Foundation::BOOL {
    windows::Win32::Foundation::BOOL(1)
}

/// 自分に届く`CTRL_C_EVENT`/`CTRL_BREAK_EVENT`を握り潰す（掛かったら`true`）。
///
/// **`console_share`モード以外からも使う**——`--console-guard-ctrl`を付けた待機モードの
/// プロセス（＝保持プロセス役）が、撃たれても生き残るかを測るため（§7.1.1の測定7）。
/// **同じハンドラを2箇所で書かない**（`docs/CODE-STRUCTURE-RULES.md`§5.0）。
#[cfg(windows)]
pub fn guard_self_from_ctrl_events() -> bool {
    unsafe {
        windows::Win32::System::Console::SetConsoleCtrlHandler(Some(ignore_ctrl_event), true)
    }
    .is_ok()
}

#[cfg(not(windows))]
pub fn guard_self_from_ctrl_events() -> bool {
    false
}

/// `CTRL_C_EVENT`の扱いを、走り出す前にどうするか。
///
/// **3つに割れている理由は、既定が「親から受け継いだまま」だからである。** 受け継いだ状態を
/// 知らないまま「外す／立てる」だけを用意すると、比較の基準が消える。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CtrlCMode {
    /// 何もしない。**親から受け継いだまま**で、比較の基準になる。
    Inherit,
    /// 受け取る側へ戻す（`SetConsoleCtrlHandler(NULL, FALSE)`）。
    Accept,
    /// 自分で無視する側にする（`SetConsoleCtrlHandler(NULL, TRUE)`）。
    /// **親が立てていない環境で「立っていたらどうなるか」を測るための腕。**
    Ignore,
}

/// **`CTRL_C_EVENT`の扱いを走り出す前に決める。**
///
/// Microsoftの文書は「`SetConsoleCtrlHandler`は**継承される属性**を立てられ、それが
/// 立っているプロセスへ`GenerateConsoleCtrlEvent`が`CTRL_C_EVENT`を送っても
/// **ハンドラは呼ばれない**。`CTRL_BREAK_EVENT`は常にハンドラを呼ぶ」と書いている
/// （`GenerateConsoleCtrlEvent`のRemarks）。**この属性はどのプロセスも自分について
/// 付け外しできる**ので、外して撃てば「上流から受け継いだ属性のせいか」が割れる。
///
/// **どのモードよりも先に、`main`が1回だけ呼ぶ。** 受け取る側の腕でも保持プロセス役でも
/// 使うので、モードごとに書くと片方だけ直る事故になる。
#[cfg(windows)]
pub fn apply_ctrl_c_mode(mode: CtrlCMode) -> &'static str {
    let ignore = match mode {
        CtrlCMode::Inherit => return "inherit",
        CtrlCMode::Accept => false,
        CtrlCMode::Ignore => true,
    };
    let ok =
        unsafe { windows::Win32::System::Console::SetConsoleCtrlHandler(None, ignore) }.is_ok();
    match (mode, ok) {
        (CtrlCMode::Accept, true) => "accept",
        (CtrlCMode::Accept, false) => "accept-failed",
        (CtrlCMode::Ignore, true) => "ignore",
        (CtrlCMode::Ignore, false) => "ignore-failed",
        (CtrlCMode::Inherit, _) => unreachable!("Inheritは上で返している"),
    }
}

#[cfg(not(windows))]
pub fn apply_ctrl_c_mode(_mode: CtrlCMode) -> &'static str {
    "unsupported"
}

/// 制御イベントを受け取ったハンドラが、後始末まで済ませたときの終了コード。
///
/// **37（シェルの完走印）・97（見張りタイマー）と衝突しない値を選んである。**
/// これがあると、「ハンドラを通って終わった」と「OSの既定で終わらされた」
/// （`STATUS_CONTROL_C_EXIT` = `0xC000013A`）が終了コードだけで割れる。
/// 読む側は`mac_spike_daemon_tests`で、**同じ値を両方に書いてある**ので片方だけ変えないこと。
pub const CTRL_HANDLED_EXIT_CODE: i32 = 43;

/// 後始末で書き切る印。**待っている間はバッファの中にあり、ディスクには無い。**
pub const CLEANUP_MARKER: &str = "HARNESS-CTRL-CLEANUP-COMPLETE";

/// 受け取る側の仕掛けの置き場。
///
/// **プロセス全体で1つ持つ必要がある。** 制御イベントのハンドラはOSが起こす**別のスレッド**で
/// 走るので、待っている側のローカル変数には触れない。
#[cfg(windows)]
static CTRL_RECEIPT: std::sync::OnceLock<CtrlReceipt> = std::sync::OnceLock::new();

/// 制御イベントを受け取ったときに書き残すもの一式（設計書§7.1.1の測定8）。
#[cfg(windows)]
struct CtrlReceipt {
    /// 受け取った事実を書き切る先。**1行1 JSON**で、仕掛けた時点の1行と、
    /// 受け取るたびの1行が積まれる。**手で撃った回の記録もこの1ファイルで完結する。**
    receipt: std::path::PathBuf,
    /// 待っている間ずっと「書いたがディスクへ出していない」状態で持つ書き手。
    /// ハンドラがこれを書き切って閉じることが、**後始末が最後まで走った証拠**になる。
    cleanup: std::sync::Mutex<Option<std::io::BufWriter<std::fs::File>>>,
}

#[cfg(windows)]
impl CtrlReceipt {
    /// 1件を**追記して即座に書き切る**。
    ///
    /// バッファに残すと、この直後にプロセスが消えたときに一緒に消える——
    /// それでは「受け取った」の証拠にならない。
    ///
    /// **時刻を必ず付ける。** 手で撃った回は、押した順序と記録の順序を後から
    /// 突き合わせられないと何も言えない。
    fn append(&self, mut entry: Value) {
        use std::io::Write;
        if let Some(map) = entry.as_object_mut() {
            map.insert("at_unix_ms".into(), json!(unix_millis()));
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.receipt)
        {
            let _ = f.write_all(format!("{entry}\n").as_bytes());
            let _ = f.flush();
        }
    }

    /// バッファに残していた印を書き切って閉じる（＝後始末）。
    ///
    /// **3つの結果を1語ずつに分ける。** 「対象が無かった」を「失敗した」と同じ語で書くと、
    /// 後から記録を読む人が**構成の違いを不具合と読む**（実際に踏んだ——後始末の対象を
    /// 指定しない回で`failed`と出た）。
    fn finish_cleanup(&self) -> &'static str {
        use std::io::Write;
        let Ok(mut slot) = self.cleanup.lock() else {
            return "lock-failed";
        };
        let Some(mut writer) = slot.take() else {
            return "skipped";
        };
        if writer.flush().is_ok() {
            "ok"
        } else {
            "failed"
        }
        // `writer`はここで落ち、ファイルが閉じる。
    }
}

/// 記録に付ける時刻（1970年からのミリ秒）。**新しい依存を足さないための最小の形**である。
fn unix_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[cfg(windows)]
fn ctrl_event_name(ctrl_type: u32) -> &'static str {
    match ctrl_type {
        0 => "CTRL_C_EVENT",
        1 => "CTRL_BREAK_EVENT",
        2 => "CTRL_CLOSE_EVENT",
        5 => "CTRL_LOGOFF_EVENT",
        6 => "CTRL_SHUTDOWN_EVENT",
        _ => "UNKNOWN",
    }
}

/// 押されたキーの番号を、よく使うものだけ名前にする。
///
/// **`Ctrl`+`Break`は`VK_CANCEL`（3）として届く。** これが記録に出れば「キーは届いているが
/// 信号になっていない」、1件も出なければ「そもそも端末が送っていない」と読み分けられる。
#[cfg(windows)]
fn virtual_key_name(vk: u16) -> &'static str {
    match vk {
        0x03 => "VK_CANCEL(Ctrl+Break)",
        0x08 => "VK_BACK",
        0x0D => "VK_RETURN",
        0x11 => "VK_CONTROL",
        0x12 => "VK_MENU(Alt)",
        0x13 => "VK_PAUSE",
        0x10 => "VK_SHIFT",
        0x1B => "VK_ESCAPE",
        0x20 => "VK_SPACE",
        0x43 => "C",
        0x91 => "VK_SCROLL",
        _ => "",
    }
}

/// **キーが本当に届いているかを見る**（`--console-watch-input`）。
///
/// # なぜ要るか
///
/// 「押したのに何も起きない」は2つの意味に割れる——**端末がそのキーを送っていない**のか、
/// **送られたが信号にならなかった**のか。制御イベントのハンドラは後者しか見ないので、
/// 前者と区別が付かない。そこで**コンソールの入力そのもの**を読んで、同じ記録へ積む。
///
/// # 読み方
///
/// | 記録に出るもの | 意味 |
/// |---|---|
/// | `key`の行が出て、`received`も出る | キーが届き、信号にもなった |
/// | `key`の行だけ出る | **キーは届いているが信号になっていない** |
/// | どちらも出ない | **端末がそのキーを送っていない**（キーの組み合わせが違う等） |
///
/// **`Ctrl`+`C`はここには出ないのが正常である**——`ENABLE_PROCESSED_INPUT`が立っていると、
/// コンソールがキー入力ではなく信号として扱うためである。だから開始時のモードも記録する。
///
/// **入力を読むと消費する。** この腕を撃っている間、同じコンソールの他のプロセスは
/// その入力を受け取れない。測定専用の腕であって、常用するものではない。
#[cfg(windows)]
pub fn watch_console_input(seconds: u64) {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_MODE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Console::{
        GetConsoleMode, GetNumberOfConsoleInputEvents, ReadConsoleInputW, CONSOLE_MODE,
        INPUT_RECORD, KEY_EVENT,
    };
    use windows::Win32::System::Threading::WaitForSingleObject;

    let Some(state) = CTRL_RECEIPT.get() else {
        // 記録の置き場が無ければ、見ても残せない。**黙って待たない**（`B-10`）。
        return;
    };

    let name = wide("CONIN$");
    let conin = unsafe {
        CreateFileW(
            PCWSTR(name.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0),
            None,
            OPEN_EXISTING,
            Default::default(),
            None,
        )
    };
    let conin = match conin {
        Ok(h) => h,
        Err(e) => {
            state.append(json!({ "kind": "input-watch", "ok": false, "error": e.to_string() }));
            std::thread::sleep(std::time::Duration::from_secs(seconds));
            return;
        }
    };

    // **開始時のモードを残す。** `ENABLE_PROCESSED_INPUT`（1）が立っていれば、
    // `Ctrl`+`C`はキー入力ではなく信号になる——出てこないのが正常だと読める。
    let mut mode = CONSOLE_MODE(0);
    let mode_ok = unsafe { GetConsoleMode(conin, &mut mode) }.is_ok();
    state.append(json!({
        "kind": "input-watch",
        "ok": true,
        "mode_ok": mode_ok,
        "mode": mode.0,
        "processed_input": mode.0 & 0x0001 != 0,
        "watch_secs": seconds,
    }));

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    let mut other_events: u32 = 0;
    while std::time::Instant::now() < deadline {
        // 待てる相手なので回し続けない。100ミリ秒ごとに起きて、無ければまた待つ。
        if unsafe { WaitForSingleObject(conin, 100) } != WAIT_OBJECT_0 {
            continue;
        }
        let mut pending: u32 = 0;
        if unsafe { GetNumberOfConsoleInputEvents(conin, &mut pending) }.is_err() || pending == 0 {
            continue;
        }
        let mut records = vec![INPUT_RECORD::default(); pending.min(64) as usize];
        let mut read: u32 = 0;
        if unsafe { ReadConsoleInputW(conin, &mut records, &mut read) }.is_err() {
            continue;
        }
        for record in records.iter().take(read as usize) {
            if record.EventType != KEY_EVENT as u16 {
                other_events += 1;
                continue;
            }
            let key = unsafe { record.Event.KeyEvent };
            let unicode = unsafe { key.uChar.UnicodeChar };
            state.append(json!({
                "kind": "key",
                "down": key.bKeyDown.as_bool(),
                "vk": key.wVirtualKeyCode,
                "vk_name": virtual_key_name(key.wVirtualKeyCode),
                "scan": key.wVirtualScanCode,
                "char_code": unicode,
                "ctrl_state": key.dwControlKeyState,
                // 左右どちらのCtrlでも立つ。押しながらかどうかがこれで分かる。
                "ctrl_held": key.dwControlKeyState & 0x000C != 0,
            }));
        }
    }
    state.append(json!({ "kind": "input-watch-end", "other_events": other_events }));
    unsafe {
        let _ = CloseHandle(conin);
    }
}

#[cfg(not(windows))]
pub fn watch_console_input(seconds: u64) {
    std::thread::sleep(std::time::Duration::from_secs(seconds));
}

/// 受け取った事実と後始末を書き残してから終わるハンドラ。
///
/// **順序が証拠の強さを決める。** 受け取った事実を先に書き切ってから後始末へ進む——
/// 逆にすると、後始末で詰まった回が「届いていない」と読めてしまう。
#[cfg(windows)]
unsafe extern "system" fn record_and_exit_ctrl_event(
    ctrl_type: u32,
) -> windows::Win32::Foundation::BOOL {
    if let Some(state) = CTRL_RECEIPT.get() {
        state.append(json!({
            "kind": "received",
            "event": ctrl_type,
            "name": ctrl_event_name(ctrl_type),
        }));
        state.append(json!({
            "kind": "cleanup",
            "result": state.finish_cleanup(),
        }));
    }
    std::process::exit(CTRL_HANDLED_EXIT_CODE);
}

/// 受け取る側の仕掛けを作る（`--console-ctrl-receipt`）。
///
/// **待ちに入る前に呼ぶ。** レポートが見えた時点で仕掛けが済んでいないと、
/// 読む側は「撃ってよい時点」を判定できない（仕掛かる前に撃つと、測っているのは
/// 届くかどうかではなく競走になる）。
///
/// 返すJSONは**この腕が自分の構成を名乗る**ためのもので、読む側はこれを照合してから
/// 結果を読む（引数が届いていない回を「届かなかった回」と取り違えないため）。
#[cfg(windows)]
pub fn arm_ctrl_receipt(receipt: &str, cleanup: Option<&str>, ctrl_c_mode: &str) -> Value {
    use std::io::Write;

    // 後始末の対象を先に開く。**開いた時点でファイルは空で存在する**ので、
    // 読む側は「空で在る＝仕掛かった」「中身が在る＝ハンドラが走った」と読み分けられる。
    let (cleanup_open, writer) = match cleanup {
        Some(path) => match std::fs::File::create(path) {
            Ok(file) => {
                let mut w = std::io::BufWriter::new(file);
                // **ここでは書き切らない。** バッファに残すのが目的で、
                // ディスクへ出してしまうと「後始末が走った」の証拠にならなくなる。
                let _ = w.write_all(CLEANUP_MARKER.as_bytes());
                (true, Some(w))
            }
            Err(_) => (false, None),
        },
        None => (false, None),
    };

    let armed = CTRL_RECEIPT
        .set(CtrlReceipt {
            receipt: std::path::PathBuf::from(receipt),
            cleanup: std::sync::Mutex::new(writer),
        })
        .is_ok();

    let handler = armed
        && unsafe {
            windows::Win32::System::Console::SetConsoleCtrlHandler(
                Some(record_and_exit_ctrl_event),
                true,
            )
        }
        .is_ok();

    let summary = json!({
        "receipt": receipt,
        "cleanup": cleanup,
        "cleanup_open": cleanup_open,
        "handler": handler,
        "ctrl_c_mode": ctrl_c_mode,
    });

    // **仕掛けた時点も記録へ残す。** 手で撃った回は、この1ファイルだけを見れば
    // 「どういう構成で待っていて、いつ何を受け取ったか」が揃う。
    if let Some(state) = CTRL_RECEIPT.get() {
        let mut armed_line = summary.clone();
        if let Some(map) = armed_line.as_object_mut() {
            map.insert("kind".into(), json!("armed"));
            map.insert("pid".into(), json!(std::process::id()));
            map.insert("membership".into(), console_membership());
        }
        state.append(armed_line);
    }

    summary
}

#[cfg(not(windows))]
pub fn arm_ctrl_receipt(receipt: &str, cleanup: Option<&str>, ctrl_c_mode: &str) -> Value {
    json!({
        "receipt": receipt,
        "cleanup": cleanup,
        "cleanup_open": false,
        "handler": false,
        "ctrl_c_mode": ctrl_c_mode,
    })
}

/// このプロセスがどのコンソールに属しているか（**腕ごとの検算**）。
///
/// 属していない腕が「読めなかった」と言っても、それはコンソールのせいではない。
/// **どの腕でも必ず出す。**
#[cfg(windows)]
fn console_membership() -> Value {
    use windows::Win32::System::Console::GetConsoleProcessList;
    let mut ids = [0u32; 16];
    let count = unsafe { GetConsoleProcessList(&mut ids) } as usize;
    if count == 0 || count > ids.len() {
        return json!({ "attached": false, "count": count, "members": [] });
    }
    json!({
        "attached": ids[..count].contains(&std::process::id()),
        "count": count,
        "members": ids[..count].to_vec(),
    })
}

#[cfg(windows)]
pub fn run(spec: &Spec) -> Value {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_MODE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Console::{
        GenerateConsoleCtrlEvent, ReadConsoleOutputCharacterW, WriteConsoleOutputCharacterW, COORD,
        CTRL_BREAK_EVENT, CTRL_C_EVENT,
    };

    let mut attempts: Vec<Value> = Vec::new();
    let membership = console_membership();

    // **いちばん先に仕掛ける。** この関数を抜けた後にレポートが書かれ、それを見た読む側が
    // 撃つので、ここで済ませておかないと「撃ってよい時点」が保証できない。
    let ctrl_receipt = spec.ctrl_receipt.as_deref().map(|receipt| {
        arm_ctrl_receipt(receipt, spec.ctrl_cleanup.as_deref(), spec.ctrl_c_mode)
    });

    // `CONOUT$`は「自分が属しているコンソールのアクティブな画面バッファ」を指す特別な名前である。
    // **属していなければここで失敗する**——その失敗は「コンソールに参加していない」の印であって、
    // 権限の話ではない。区別できるように`last_error`を必ず出す。
    let name = wide("CONOUT$");
    let conout: Option<HANDLE> = unsafe {
        match CreateFileW(
            PCWSTR(name.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0),
            None,
            OPEN_EXISTING,
            Default::default(),
            None,
        ) {
            Ok(h) => {
                attempts.push(json!({
                    "kind": "conout-open", "ok": true, "last_error": 0u32,
                }));
                Some(h)
            }
            Err(_) => {
                attempts.push(json!({
                    "kind": "conout-open", "ok": false, "last_error": GetLastError().0,
                }));
                None
            }
        }
    };

    let origin = COORD { X: 0, Y: 0 };

    if let Some(text) = &spec.write {
        match conout {
            Some(h) => {
                let buf: Vec<u16> = text.encode_utf16().collect();
                let mut written: u32 = 0;
                let ok = unsafe { WriteConsoleOutputCharacterW(h, &buf, origin, &mut written) };
                attempts.push(json!({
                    "kind": "console-write",
                    "ok": ok.is_ok(),
                    "written": written,
                    "requested": buf.len(),
                    "last_error": if ok.is_ok() { 0 } else { unsafe { GetLastError() }.0 },
                }));
            }
            // 開けていないのに「書けなかった」と記録すると、原因が2つに割れたまま残る。
            None => attempts.push(json!({
                "kind": "console-write", "ok": false, "skipped": "conout-not-open",
            })),
        }
    }

    if spec.read {
        match conout {
            Some(h) => {
                let mut buf = vec![0u16; READ_CHARS as usize];
                let mut read: u32 = 0;
                let ok = unsafe { ReadConsoleOutputCharacterW(h, &mut buf, origin, &mut read) };
                let text = String::from_utf16_lossy(&buf[..read as usize]);
                attempts.push(json!({
                    "kind": "console-read",
                    "ok": ok.is_ok(),
                    "read": read,
                    // **中身をそのまま出す。** 「含んでいたか」を子の側で判定すると、
                    // 探した文字列が違ったときに「読めなかった」と区別できなくなる。
                    "text": text,
                    "last_error": if ok.is_ok() { 0 } else { unsafe { GetLastError() }.0 },
                }));
            }
            None => attempts.push(json!({
                "kind": "console-read", "ok": false, "skipped": "conout-not-open",
            })),
        }
    }

    // **撃つ前に自分を守る。** プロセスグループ0は「このコンソールに繋がった全プロセス」
    // ——**自分を含む**ので、守らないと撃った本人が`STATUS_CONTROL_C_EXIT`で死ぬ。
    // 死ぬと標準出力がドレインされる前にプロセスが消え、**レポートが1行も残らない**
    // （実際に踏んだ: 出力が残る回と残らない回が混ざった）。
    //
    // これは**計器を守るだけで、測っている対象は変えない**——的の側にハンドラは無いので、
    // 「別ドメインから撃たれて落ちるか」はそのまま測れる。
    // 副産物として「ハンドラを入れれば自分だけは守れる」という事実も記録に残る。
    let mut guarded: Option<bool> = None;
    for (requested, event, kind) in [
        (spec.ctrl_break, CTRL_BREAK_EVENT, "console-ctrl-break"),
        (spec.ctrl_c, CTRL_C_EVENT, "console-ctrl-c"),
    ] {
        if !requested {
            continue;
        }
        // 守りは**プロセスに1回**掛かれば足りる（2種類撃つ腕でも二重に掛けない）。
        let self_guarded = *guarded.get_or_insert_with(guard_self_from_ctrl_events);
        let ok = unsafe { GenerateConsoleCtrlEvent(event, 0) };
        attempts.push(json!({
            "kind": kind,
            "ok": ok.is_ok(),
            "self_guarded": self_guarded,
            "last_error": if ok.is_ok() { 0 } else { unsafe { GetLastError() }.0 },
        }));
    }

    if let Some(h) = conout {
        unsafe {
            let _ = CloseHandle(h);
        }
    }

    json!({
        "mode": "console-share",
        "pid": std::process::id(),
        "membership": membership,
        "attempts": attempts,
        // **腕は自分で名乗る。** 引数が届いていない回を「届かなかった回」と
        // 取り違えないための照合先である（`null`は「頼まれていない」）。
        "ctrl_receipt": ctrl_receipt,
    })
}

/// レポートを出し終えてから待つ（`--console-idle-secs`）。
///
/// **待つのは呼び出し側の仕事にしてある。** ここで待ってから出力すると、
/// 待っている間にCtrl+Breakで落とされたときに**1行も残らない**——
/// 「落とされた」と「そもそも動かなかった」が区別できなくなる。
pub fn idle(spec: &Spec) {
    if spec.idle_secs == 0 {
        return;
    }
    if spec.watch_input {
        // 待ち方を差し替えるだけで、待つ長さは同じ。**押されたキーを記録しながら待つ。**
        watch_console_input(spec.idle_secs);
        return;
    }
    std::thread::sleep(std::time::Duration::from_secs(spec.idle_secs));
}

#[cfg(not(windows))]
pub fn run(_spec: &Spec) -> Value {
    json!({"mode": "console-share", "error": "windows-only"})
}
