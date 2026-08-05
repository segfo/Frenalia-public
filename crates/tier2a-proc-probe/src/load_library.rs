//! `LoadLibraryW`をAppContainer内から直接呼び、成否と`GetLastError`を報告する。
//!
//! **なぜ専用モードが要るか**: `docs/STATUS.md` Tier2a残課題#7の症状は
//! 「`LoadLibraryW returned NULL in target process`」だが、これは`spawn.rs`の
//! `inject_redirector`が`CreateRemoteThread(kernel32!LoadLibraryW)`の**スレッド終了コード**を
//! 見ているだけで、`GetLastError`は取れていない（リモートスレッドが終了した時点で、その
//! スレッドのlast errorは消えている）。したがって現状の観測からは「ロードできなかった」以上の
//! ことが一切分からず、何度実行しても情報が増えない。
//!
//! このモードは**注入機構を通さずに**「このAppContainerはこのDLLをロードできるのか」だけを
//! 測る。切り分けは次のとおり:
//!
//! | 結果 | 意味 |
//! |---|---|
//! | 成功 | DLL自体はAppContainerでロードできる → 原因は注入機構の側（タイミング等） |
//! | `5` ERROR_ACCESS_DENIED | ACL/権利の不足（ファイル読取が通ってもセクション生成に要る権利は別） |
//! | `126` ERROR_MOD_NOT_FOUND | 依存DLLへ到達できない |
//! | `193` ERROR_BAD_EXE_FORMAT | ビット数の取り違え |
//! | `1114` ERROR_DLL_INIT_FAILED | 静的初期化・TLSコールバックの失敗 |
//!
//! `DllMain`が`FALSE`を返す経路は`harness-redirector`には無い（常に`1`を返し、フック設置は
//! 別スレッドへ委譲している）ので、`1114`が出たらそれ自体が新しい発見になる。

use serde_json::{json, Value};

#[cfg(windows)]
pub fn run(path: &str) -> Value {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::GetLastError;
    use windows::Win32::System::LibraryLoader::LoadLibraryW;

    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let exists = std::path::Path::new(path).exists();
    // 読取だけなら通るのか（`ReadAllBytes`相当）も同時に測る。「読めるがロードできない」なら
    // 原因はACLではなくローダ側にある、と1回の実行で切り分けられる。
    let read_bytes = std::fs::read(path).map(|b| b.len());

    unsafe {
        match LoadLibraryW(PCWSTR(wide.as_ptr())) {
            // **`FreeLibrary`しない。** `harness_redirector.dll`の`DllMain`は初期化スレッドを
            // 起動して即座に戻る（Loader Lock回避）ため、ロード直後にアンロードすると
            // 走行中のスレッドごとDLLが剥がれてクラッシュする（実測: segfault）。
            // このプロセスは報告を出したら終了するので、アンロードする必要も無い。
            Ok(_module) => {
                json!({
                    "load_library": {
                        "path": path,
                        "exists": exists,
                        "read_ok": read_bytes.is_ok(),
                        "read_len": read_bytes.ok(),
                        "ok": true,
                        "last_error": 0,
                        "message": "",
                    }
                })
            }
            Err(e) => {
                let last = GetLastError().0;
                json!({
                    "load_library": {
                        "path": path,
                        "exists": exists,
                        "read_ok": read_bytes.is_ok(),
                        "read_len": read_bytes.as_ref().ok(),
                        "ok": false,
                        "last_error": last,
                        "message": e.message(),
                    }
                })
            }
        }
    }
}

#[cfg(not(windows))]
pub fn run(path: &str) -> Value {
    json!({"load_library": {"path": path, "ok": false, "message": "windows only"}})
}
