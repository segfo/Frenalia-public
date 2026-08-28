//! **Redirector DLLのフックが、成功するopen 1回へ上乗せする時間**を測る短絡モード
//! （`plans/mac-spike/RESULTS.md` §S25、Lazy ACE fault-in＝D-88の着手条件）。
//!
//! # なぜ要るか
//!
//! Lazy ACE fault-inは、いまフックの無いTier2a（DirectRw）へフックを新設する。
//! **払うのはfaultした回数ではなく、成功も含めた全openの回数である。**
//! §S21が実ワークロードを実測しており、1セッションのオープン総回数は**144,967〜218,841回**、
//! 一方でfaultする対象は**503ノード**しかない。したがって
//!
//! - fault側の総額 ≒ 503 × 約153 µs ＝ **0.08秒**（§S13の単価＋§S20の跨ぎ往復）
//! - フック側の総額 ＝ 145,000〜219,000 × **1オープンあたりの上乗せ**
//!
//! となり、**上乗せが1 µsなら0.15秒、20 µsなら2.9秒**である。前者なら誤差、後者なら
//! 「初回の待ちを消すために毎回2.9秒を払う」ことになる。**この1つの数字で向きが決まる。**
//!
//! # 測り方（同じプロセス内で前後を撮る）
//!
//! 2つのプロセスを比べると、キャッシュ・ページ・スケジューリングの差が上乗せに混ざる。
//! **同一プロセスで「載せる前 → 載せた後」を撮り**、差を上乗せとして読む。DLLを渡さない
//! ときも同じ2区間を撮る——これが**ドリフトの対照**になる（2区間目が勝手に速く／遅くなる量）。
//!
//! 腕は3つで、いずれも**成功する**操作である（fault経路の費用は別問題で、上記のとおり小さい）。
//!
//! | 腕 | 何を測るか | なぜ要るか |
//! |---|---|---|
//! | `open_inside` | workspace内のファイルを開いて閉じる | フックが分類して素通しする主経路 |
//! | `open_outside` | workspace外のファイルを開いて閉じる | 実行時間の大半を占める（system32のDLL等）。ここが重いと全部が重い |
//! | `attrs_inside` | workspace内へ`GetFileAttributesW` | `NtQuery*AttributesFile`もフック済みなので、属性照会にも上乗せが乗る |
//!
//! # この測定が言わないこと
//!
//! - **CoWの分類ロジックを測っている。** fault-in専用のフックは差分層への書き換えを
//!   行わないぶん**これより軽い**はずなので、得られる値は**上限**である。
//! - AppContainerの中では回していない（フックの費用はトークンに依らない）。
//! - 実ビルドの壁時計ではない。§S21が測った回数を掛けて見積もるための**単価**である。

use serde_json::{json, Value};

pub struct Spec {
    /// workspace内の既存ファイル。
    pub inside: String,
    /// workspace外の既存ファイル。
    pub outside: Option<String>,
    /// 1腕あたりの反復回数。
    pub iters: usize,
    /// 与えられたらこのDLLを`LoadLibraryW`し、`harness_cow_init(NULL)`を呼んでから2区間目を撮る。
    /// 設定は環境変数（`HARNESS_COW_WORKSPACE`・`HARNESS_COW_DIFF_LAYER`）で渡す。
    pub dll: Option<String>,
}

#[cfg(windows)]
pub fn run(spec: &Spec) -> Value {
    use std::time::Instant;
    use windows::core::{PCSTR, PCWSTR};
    use windows::Win32::Foundation::{CloseHandle, GetLastError, GENERIC_READ};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, GetFileAttributesW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, INVALID_FILE_ATTRIBUTES, OPEN_EXISTING,
    };
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// 1回開いて閉じる。**成功数を数える**——0件成功のまま「速い」と読むのを防ぐ（B-25）。
    fn time_opens(path: &str, iters: usize) -> Value {
        let w = wide(path);
        let mut ok = 0usize;
        let mut last_error = 0u32;
        let t = Instant::now();
        for _ in 0..iters {
            let h = unsafe {
                CreateFileW(
                    PCWSTR(w.as_ptr()),
                    GENERIC_READ.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                )
            };
            match h {
                Ok(h) => {
                    ok += 1;
                    unsafe {
                        let _ = CloseHandle(h);
                    }
                }
                Err(_) => last_error = unsafe { GetLastError() }.0,
            }
        }
        let us = t.elapsed().as_secs_f64() * 1e6 / (iters as f64);
        json!({ "us_per_op": us, "ok": ok, "iters": iters, "last_error": last_error })
    }

    fn time_attrs(path: &str, iters: usize) -> Value {
        let w = wide(path);
        let mut ok = 0usize;
        let t = Instant::now();
        for _ in 0..iters {
            let a = unsafe { GetFileAttributesW(PCWSTR(w.as_ptr())) };
            if a != INVALID_FILE_ATTRIBUTES {
                ok += 1;
            }
        }
        let us = t.elapsed().as_secs_f64() * 1e6 / (iters as f64);
        json!({ "us_per_op": us, "ok": ok, "iters": iters })
    }

    let sweep = |label: &str| -> Value {
        json!({
            "phase": label,
            "open_inside": time_opens(&spec.inside, spec.iters),
            "open_outside": spec.outside.as_ref().map(|p| time_opens(p, spec.iters)),
            "attrs_inside": time_attrs(&spec.inside, spec.iters),
        })
    };

    // ウォームアップ（ページキャッシュとローダの初回費用を1区間目へ入れない）。
    let _ = time_opens(&spec.inside, spec.iters.min(500));

    let before = sweep("before");

    let mut loaded = json!(null);
    if let Some(dll) = &spec.dll {
        let w = wide(dll);
        let module = unsafe { LoadLibraryW(PCWSTR(w.as_ptr())) };
        match module {
            Ok(m) => {
                // `harness_cow_init(NULL)`はenv（`HARNESS_COW_*`）から設定を読む。
                let init =
                    unsafe { GetProcAddress(m, PCSTR(c"harness_cow_init".as_ptr() as *const u8)) };
                let rc = match init {
                    Some(p) => {
                        let f: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 =
                            unsafe { core::mem::transmute(p) };
                        Some(unsafe { f(core::ptr::null_mut()) })
                    }
                    None => None,
                };
                loaded =
                    json!({ "load_ok": true, "init_export_found": rc.is_some(), "init_rc": rc });
            }
            Err(e) => {
                loaded = json!({
                    "load_ok": false,
                    "last_error": unsafe { GetLastError() }.0,
                    "error": e.to_string(),
                });
            }
        }
    }

    let after = sweep("after");

    let delta = |a: &Value, b: &Value, key: &str| -> Value {
        let get = |v: &Value| {
            v.get(key)
                .and_then(|x| x.get("us_per_op"))
                .and_then(|x| x.as_f64())
        };
        match (get(a), get(b)) {
            (Some(x), Some(y)) => json!({ "before_us": x, "after_us": y, "delta_us": y - x }),
            _ => json!(null),
        }
    };

    json!({
        "mode": "open-bench",
        "inside": spec.inside,
        "outside": spec.outside,
        "iters": spec.iters,
        "dll": spec.dll,
        "redirector": loaded,
        "before": before,
        "after": after,
        "delta": {
            "open_inside": delta(&before, &after, "open_inside"),
            "open_outside": delta(&before, &after, "open_outside"),
            "attrs_inside": delta(&before, &after, "attrs_inside"),
        },
    })
}

#[cfg(not(windows))]
pub fn run(_spec: &Spec) -> Value {
    json!({"mode": "open-bench", "error": "windows-only"})
}
