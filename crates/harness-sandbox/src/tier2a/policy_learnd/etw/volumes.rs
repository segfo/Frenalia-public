//! `\Device\HarddiskVolumeN` → `C:` の対応表（M15.7）。
//!
//! ETWのKernel-Fileが報告する`FileName`は多くの場合NTデバイスパス形式で、そのままでは
//! `.harness/settings.json`の`fs.read`へ書けない。ドライブ文字への変換表を1度だけ作り、
//! [`super::parse::to_settings_path`]へ渡す。
//!
//! 変換できないパス（ネットワークリダイレクタ・名前付きパイプ・マウント解除済みボリューム）は
//! 候補にしない。設定へ書けないものを提案しても適用できないため。

use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

use crate::win_common::wide;

/// `A:`〜`Z:`のうち実在するものについて`(NTデバイスパス, ドライブ文字)`を返す。
///
/// 1つのドライブ文字が複数のターゲットを持つ場合（`QueryDosDeviceW`はNUL区切りで複数返す）は
/// **先頭だけ**を採る。先頭が現在有効な解決先で、以降は履歴だから。
pub fn drive_letter_map() -> Vec<(String, String)> {
    let mut map = Vec::new();
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let drive_w = wide(&drive);
        let mut buffer = vec![0u16; 1024];
        let len = unsafe { QueryDosDeviceW(PCWSTR(drive_w.as_ptr()), Some(&mut buffer)) };
        if len == 0 {
            continue;
        }
        let end = buffer.iter().position(|u| *u == 0).unwrap_or(buffer.len());
        if end == 0 {
            continue;
        }
        let target = String::from_utf16_lossy(&buffer[..end]);
        if target.starts_with(r"\Device\") {
            map.push((target, drive));
        }
    }
    // 長いデバイス名を先に置く。`\Device\HarddiskVolume3`が`\Device\HarddiskVolume30`の
    // 前に一致して誤変換するのを防ぐ（前方一致で引くため順序が意味を持つ）。
    map.sort_by_key(|(device, _)| std::cmp::Reverse(device.len()));
    map
}

#[cfg(all(windows, test))]
mod tests {
    use super::*;

    /// この開発機には必ず`C:`がある。NTデバイスパスへ解決できること。
    #[test]
    fn the_system_drive_resolves_to_an_nt_device_path() {
        let map = drive_letter_map();

        let system_drive = map
            .iter()
            .find(|(_, drive)| drive == "C:")
            .expect("C: must be present");
        assert!(
            system_drive.0.starts_with(r"\Device\"),
            "unexpected target: {}",
            system_drive.0
        );
    }

    /// 長いデバイス名が先に来る（前方一致の誤爆防止）。
    #[test]
    fn longer_device_names_sort_first() {
        let map = drive_letter_map();

        for pair in map.windows(2) {
            assert!(
                pair[0].0.len() >= pair[1].0.len(),
                "the map must be sorted longest-first"
            );
        }
    }
}
