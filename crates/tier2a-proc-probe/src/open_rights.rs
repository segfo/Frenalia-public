//! 指定した権利を要求してファイル・ディレクトリを**開くだけ**のモード（`--open-rights <権利>:<パス>`、繰り返し可）。
//!
//! **なぜ要るのか**: Spawn Daemonは固定辺の起動直前に、呼び出し元のトークンで`AccessCheck`を掛けて
//! 「固定したファイルを書き換えられるか」を判定する（`harness-sandbox`の`spawnd::fixed_inputs`）。
//! その答えが**実際に開ける権利**と一致するかを、同じAppContainerの子で突き合わせるための計器である。
//!
//! **何も書かない。** 開いて閉じるだけなので、`C:\Windows\System32\cmd.exe`のような対象でも
//! 中身は1バイトも変わらない（書込権を要求して開けても、書かずに閉じる）。
//!
//! 報告の`last_error`の読み方: `0`＝開けた、`5`＝アクセス拒否、`32`＝共有違反（**アクセス判定は
//! 通った後**に共有の判定で断られた。実行中のイメージを書込で開いたとき等）。

use serde_json::{json, Value};

/// 名前→アクセスマスク。`AccessCheck`の答えと1ビットずつ比べられるよう、単独の権利だけを並べる。
pub fn right_mask(name: &str) -> Option<u32> {
    Some(match name {
        // ディレクトリでは FILE_ADD_FILE と同じビット
        "write_data" => 0x0000_0002,
        // ディレクトリでは FILE_ADD_SUBDIRECTORY と同じビット
        "append_data" => 0x0000_0004,
        "delete_child" => 0x0000_0040,
        "write_attributes" => 0x0000_0100,
        "delete" => 0x0001_0000,
        "write_dac" => 0x0004_0000,
        "write_owner" => 0x0008_0000,
        _ => return None,
    })
}

#[cfg(windows)]
pub fn run(specs: &[String]) -> Value {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GetLastError};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let mut attempts = Vec::new();
    for spec in specs {
        let Some((right, path)) = spec.split_once(':') else {
            attempts.push(json!({ "spec": spec, "error": "expected <right>:<path>" }));
            continue;
        };
        let Some(mask) = right_mask(right) else {
            attempts.push(json!({ "spec": spec, "error": "unknown right" }));
            continue;
        };
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let (ok, last_error) = unsafe {
            match CreateFileW(
                PCWSTR(wide.as_ptr()),
                mask,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                // ディレクトリも同じ呼び方で開くために要る。
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            ) {
                Ok(handle) => {
                    let _ = CloseHandle(handle);
                    (true, 0u32)
                }
                Err(_) => (false, GetLastError().0),
            }
        };
        attempts.push(json!({
            "right": right,
            "path": path,
            "mask": mask,
            "ok": ok,
            "last_error": last_error,
        }));
    }
    json!({ "open_rights": attempts })
}

#[cfg(not(windows))]
pub fn run(_specs: &[String]) -> Value {
    json!({ "open_rights": [], "error": "windows only" })
}
