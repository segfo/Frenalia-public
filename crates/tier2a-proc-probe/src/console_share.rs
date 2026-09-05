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
//! | `--console-idle-secs <n>` | 上記の後、`n`秒生き続ける（Ctrl+Breakの**的**になる腕で使う） |
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
    /// 上記を済ませた後、生き続ける秒数（0なら即終了）。
    pub idle_secs: u64,
}

#[cfg(windows)]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `CTRL_BREAK_EVENT`を「処理した」と答えて既定の終了を止めるハンドラ。
///
/// **撃つ側だけが入れる。** これが無いと、撃った本人がプロセスグループの巻き添えで
/// `STATUS_CONTROL_C_EXIT`（`0xC000013A`）で死に、レポートを出し切る前に消える。
#[cfg(windows)]
unsafe extern "system" fn ignore_ctrl_event(_ctrl_type: u32) -> windows::Win32::Foundation::BOOL {
    windows::Win32::Foundation::BOOL(1)
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
        GenerateConsoleCtrlEvent, ReadConsoleOutputCharacterW, SetConsoleCtrlHandler,
        WriteConsoleOutputCharacterW, COORD, CTRL_BREAK_EVENT,
    };

    let mut attempts: Vec<Value> = Vec::new();
    let membership = console_membership();

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

    if spec.ctrl_break {
        // **撃つ前に自分を守る。** プロセスグループ0は「このコンソールに繋がった全プロセス」
        // ——**自分を含む**ので、守らないと撃った本人が`STATUS_CONTROL_C_EXIT`で死ぬ。
        // 死ぬと標準出力がドレインされる前にプロセスが消え、**レポートが1行も残らない**
        // （実際に踏んだ: 出力が残る回と残らない回が混ざった）。
        //
        // これは**計器を守るだけで、測っている対象は変えない**——的の側にハンドラは無いので、
        // 「別ドメインから撃たれて落ちるか」はそのまま測れる。
        // 副産物として「ハンドラを入れれば自分だけは守れる」という事実も記録に残る。
        let guarded = unsafe { SetConsoleCtrlHandler(Some(ignore_ctrl_event), true) };
        let ok = unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0) };
        attempts.push(json!({
            "kind": "console-ctrl-break",
            "ok": ok.is_ok(),
            "self_guarded": guarded.is_ok(),
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
    })
}

/// レポートを出し終えてから待つ（`--console-idle-secs`）。
///
/// **待つのは呼び出し側の仕事にしてある。** ここで待ってから出力すると、
/// 待っている間にCtrl+Breakで落とされたときに**1行も残らない**——
/// 「落とされた」と「そもそも動かなかった」が区別できなくなる。
pub fn idle(spec: &Spec) {
    if spec.idle_secs > 0 {
        std::thread::sleep(std::time::Duration::from_secs(spec.idle_secs));
    }
}

#[cfg(not(windows))]
pub fn run(_spec: &Spec) -> Value {
    json!({"mode": "console-share", "error": "windows-only"})
}
