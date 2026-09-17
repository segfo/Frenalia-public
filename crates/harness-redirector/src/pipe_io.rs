//! 名前付きパイプへ**1フレーム書いて1フレーム読む**ところだけ。
//!
//! # なぜ独立したモジュールなのか（2026-09-17、段階6f-2）
//!
//! このDLLからパイプで話す相手が**2人**になった。
//!
//! | 相手 | 何を頼むか | 呼ぶ側 |
//! |---|---|---|
//! | 受付（broker） | 拒否されたopenをやり直してよいか | [`crate::fault_in`] |
//! | Spawn Daemon | 子プロセスを代わりに起こしてほしい | [`crate::spawn_broker`] |
//!
//! **枠組み（4バイトのリトルエンディアンの長さ＋本文）は同じ**で、`harness-sandbox`側の
//! `win_pipe_ipc::write_framed_timeout`/`read_framed_timeout`と一致している必要がある。
//! 2人目が来たときに写すと、**片方だけ直された枠組み**が生まれる
//! （`docs/CODE-STRUCTURE-RULES.md` §5.0）。
//!
//! # ここに無いもの
//!
//! **接続の持ち方は呼ぶ側が決める。** 受付は1本を張りっぱなしにし（1 openごとに繋ぎ直すと
//! 往復29.2 µsに接続の費用が毎回乗る、`plans/mac-spike/RESULTS.md` §S20）、生成要求は
//! **1回ごとに開いて閉じる**（頻度が桁違いに低く、張りっぱなしにすると窓口の受付インスタンスを
//! 1つ占有し続ける。`docs/STATUS.md`残課題#43）。
//!
//! # 再入
//!
//! ここが使う`CreateFileW`/`ReadFile`/`WriteFile`は`NtCreateFile`へ降りて自分のフックに戻る。
//! **呼ぶ側が`ReentryGuard`を握っていること**——握らずに呼ぶと、要求のためのopenが
//! 自分自身の要求を生む。

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_IO_PENDING, HANDLE, WAIT_OBJECT_0};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_MODE, OPEN_EXISTING,
};
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

/// 1フレームで受け取る上限。**壊れた長さで巨大な確保をしない**ための安全弁で、
/// どちらの相手の応答も短い（受付は数十バイト、Daemonは最大でも数百バイト）。
const MAX_REPLY_BYTES: usize = 64 * 1024;

/// パイプへ繋ぐ。`None`は「居ない・開けない」。
pub(crate) fn connect(pipe_name: &str) -> Option<HANDLE> {
    unsafe {
        // NUL終端のUTF-16へ（`ledger.rs`の`nt_path_wide`と同じ作り方）。
        let name_w: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
        CreateFileW(
            PCWSTR(name_w.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            None,
        )
        .ok()
    }
}

/// 1フレーム書いて1フレーム読む。`None`は「この接続はもう使えない」。
pub(crate) fn roundtrip(pipe: HANDLE, payload: &[u8], timeout_ms: u32) -> Option<Vec<u8>> {
    let len = (payload.len() as u32).to_le_bytes();
    write_all(pipe, &len, timeout_ms)?;
    write_all(pipe, payload, timeout_ms)?;
    let mut len_buf = [0u8; 4];
    read_exact(pipe, &mut len_buf, timeout_ms)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_REPLY_BYTES {
        return None;
    }
    let mut reply = vec![0u8; len];
    if len > 0 {
        read_exact(pipe, &mut reply, timeout_ms)?;
    }
    Some(reply)
}

fn write_all(pipe: HANDLE, buf: &[u8], timeout_ms: u32) -> Option<()> {
    let mut done = 0usize;
    while done < buf.len() {
        let chunk = &buf[done..];
        let n = overlapped(pipe, timeout_ms, |ov| unsafe {
            WriteFile(pipe, Some(chunk), None, Some(ov))
        })?;
        if n == 0 {
            return None;
        }
        done += n as usize;
    }
    Some(())
}

fn read_exact(pipe: HANDLE, buf: &mut [u8], timeout_ms: u32) -> Option<()> {
    let mut done = 0usize;
    while done < buf.len() {
        let chunk = &mut buf[done..];
        let n = overlapped(pipe, timeout_ms, |ov| unsafe {
            ReadFile(pipe, Some(chunk), None, Some(ov))
        })?;
        if n == 0 {
            return None;
        }
        done += n as usize;
    }
    Some(())
}

/// オーバーラップドI/Oを`timeout_ms`付きで回す。
///
/// タイムアウトしたら`CancelIoEx`で取り消し、**取り消しの完了まで待ってから**返る
/// （`bWait=true`）——待たずに返ると、この関数のスタックにある`OVERLAPPED`をカーネルが
/// まだ見ている状態でスタックが巻き戻る。`harness-sandbox`の`run_overlapped`が
/// 同じ理由で同じことをしている。
fn overlapped<F>(pipe: HANDLE, timeout_ms: u32, start: F) -> Option<u32>
where
    F: FnOnce(*mut OVERLAPPED) -> windows::core::Result<()>,
{
    unsafe {
        let event = CreateEventW(None, true, false, None).ok()?;
        let mut ov = OVERLAPPED {
            hEvent: event,
            ..Default::default()
        };
        let started = start(&mut ov as *mut _);
        let pending = match started {
            Ok(()) => false,
            Err(e) if e.code() == ERROR_IO_PENDING.to_hresult() => true,
            Err(_) => {
                let _ = CloseHandle(event);
                return None;
            }
        };
        if pending && WaitForSingleObject(event, timeout_ms) != WAIT_OBJECT_0 {
            let _ = CancelIoEx(pipe, Some(&ov as *const _));
            let mut discarded = 0u32;
            let _ = GetOverlappedResult(pipe, &ov, &mut discarded, true);
            let _ = CloseHandle(event);
            return None;
        }
        let mut transferred = 0u32;
        let ok = GetOverlappedResult(pipe, &ov, &mut transferred, true).is_ok();
        let _ = CloseHandle(event);
        ok.then_some(transferred)
    }
}
