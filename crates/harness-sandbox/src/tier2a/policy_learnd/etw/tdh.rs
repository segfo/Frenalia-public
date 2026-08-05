//! TDH（Trace Data Helper）でETWイベントのプロパティを名前で引く（M15.7）。
//!
//! マニフェストベースのプロバイダ（`Microsoft-Windows-Kernel-File`）のイベント本体は、
//! バージョンごとにレイアウトが変わりうる可変長のバイト列である。**オフセット決め打ちで
//! 読まない**——TDHにマニフェストを解決させ、プロパティ名で引く。Windowsの更新で
//! フィールドが増減しても静かに壊れないようにするため。
//!
//! 引けなかったプロパティは`None`を返し、呼び出し側はそのイベントを捨てる（D-43）。

use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Diagnostics::Etw::{
    TdhGetProperty, TdhGetPropertySize, EVENT_RECORD, PROPERTY_DATA_DESCRIPTOR,
};

use crate::win_common::wide;

fn descriptor(name_w: &[u16]) -> PROPERTY_DATA_DESCRIPTOR {
    PROPERTY_DATA_DESCRIPTOR {
        PropertyName: name_w.as_ptr() as u64,
        ArrayIndex: 0,
        Reserved: 0,
    }
}

/// 名前で引いた生バイト列。
///
/// # Safety
/// `record`はETWコールバックが渡した有効な`EVENT_RECORD`でなければならない。
unsafe fn property_bytes(record: &EVENT_RECORD, name: &str) -> Option<Vec<u8>> {
    let name_w = wide(name);
    let descriptors = [descriptor(&name_w)];

    let mut size: u32 = 0;
    let status = TdhGetPropertySize(record, None, &descriptors, &mut size);
    if status != ERROR_SUCCESS.0 || size == 0 {
        return None;
    }

    let mut buffer = vec![0u8; size as usize];
    let status = TdhGetProperty(record, None, &descriptors, &mut buffer);
    if status != ERROR_SUCCESS.0 {
        return None;
    }
    Some(buffer)
}

/// 整数プロパティ（`uint32`・`pointer`）を`u64`として引く。
///
/// ポインタ型の幅は**イベントを生成したプロセスのビット幅**で決まる（WOW64の子なら4バイト）
/// ため、サイズを見てから解釈する。固定で8バイトとして読むと32bitプロセス由来のイベントで
/// ずれる——CoW台帳で同種の幅依存バグを踏んだ前例がある（[BUG-042]）。
///
/// [BUG-042]: ../../../../../docs/bugs/BUG-042.md
///
/// # Safety
/// `record`はETWコールバックが渡した有効な`EVENT_RECORD`でなければならない。
pub unsafe fn property_u64(record: &EVENT_RECORD, name: &str) -> Option<u64> {
    let bytes = property_bytes(record, name)?;
    match bytes.len() {
        1 => Some(bytes[0] as u64),
        2 => Some(u16::from_le_bytes([bytes[0], bytes[1]]) as u64),
        4 => Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64),
        8 => Some(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])),
        _ => None,
    }
}

/// UTF-16文字列プロパティを引く。末尾のNUL以降は落とす。
///
/// # Safety
/// `record`はETWコールバックが渡した有効な`EVENT_RECORD`でなければならない。
pub unsafe fn property_string(record: &EVENT_RECORD, name: &str) -> Option<String> {
    let bytes = property_bytes(record, name)?;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let end = units.iter().position(|u| *u == 0).unwrap_or(units.len());
    if end == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&units[..end]))
}
