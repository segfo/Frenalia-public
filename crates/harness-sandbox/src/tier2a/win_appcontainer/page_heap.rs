//! [残課題#52] **1つの実行ファイルにだけPage Heap(Full)を載せる／外す**（テスト専用）。
//!
//! # 何のためにあるのか
//!
//! プローブが`0xC0000374`（ヒープ破壊）で落ちる件の根本原因を出すための道具である。
//! 素のままだと破壊は**後の確保/解放で気づかれて`fail-fast`**（誰にも捕まえさせず即死させる
//! Windowsの仕組み）で落ちるので、**どこで壊したのかが残らない**。
//!
//! Page Heap(Full)は確保ごとに1ページへ隔離し、直後に**番兵ページ**（踏むと即アクセス違反に
//! なるページ）を置く。これで「壊した瞬間そのアドレスでアクセス違反」に変わり、
//! プローブ側のVEH（`tier2a-proc-probe`の`fault_log`）が場所を記録できるようになる。
//!
//! # どこに書くのか——**バイナリ名で引かれるレジストリのキー**
//!
//! `HKLM\...\Image File Execution Options\<実行ファイル名>` に2つの値を置く。
//! **キーは実行ファイルの"名前"で引かれる**ので、
//!
//! - **自分たちのテスト用バイナリだけ**を狙える（他人の設定が紛れ込む余地が無い）
//! - **キーの有無がそのまま状態**である。だから別に台帳を持たない——
//!   落ちて残っても**レジストリを読めば見え、同じ削除で消える**
//!
//! # 撤収は「消す」でよい（**共有システムバイナリなら駄目**）
//!
//! [`disable`]はキーを**丸ごと消す**。消す前の値を保存しないのは、対象が
//! **自分たちがビルドしたテスト用バイナリ**で、他に誰もそこへIFEOを書かないからである。
//! `cmd.exe`のような共有システムバイナリへ載せるなら、削除ではなく保存/復元が要る
//! ——そのときはこのモジュールをそのまま使ってはいけない。
//!
//! # 効いているかは**仮定せず測る**
//!
//! 値を書けたことと、Page Heapが実際に効いていることは**別の事実**である。
//! とくにAppContainerの中の子プロセスがこのキーを読めるかは自明でない。
//! 読めなければPage Heapは**黙って効かず**、「破壊が出ない＝きれい」という偽の合格になる。
//! だから有効化の直後に`--fault-self overflow`（Page Heapが効いているときだけ落ちる的）で
//! 確かめる（`tier2a-proc-probe`の`fault_log::run`の表）。

use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegGetValueW, RegSetValueExW, HKEY,
    HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_DWORD, REG_OPTION_NON_VOLATILE, RRF_RT_REG_DWORD,
};

/// IFEO（実行ファイルごとの起動時フラグをレジストリに置く仕組み）の親キー。
const IFEO_ROOT: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

/// `FLG_HEAP_PAGE_ALLOCS`。**ローダへの親スイッチ**で、これが無いと`PageHeapFlags`は読まれない。
const FLG_HEAP_PAGE_ALLOCS: u32 = 0x0200_0000;

/// Page Heapの細目。`0x1`＝有効化、`0x2`＝**full**（確保の直後に番兵ページを置く）。
///
/// **`0x1`だけでは番兵ページが立たない**（軽い側の検査になる）ので、はみ出しは捕まらない。
const PAGE_HEAP_FULL: u32 = 0x3;

/// 対象の実行ファイル名から、置き場のキーのパスを組む。
///
/// **フルパスを受け取らない。** IFEOは実行ファイルの**葉の名前**で引かれるので、
/// `C:\...\probe.exe`を渡すとキーが入れ子になり、**1つも効かないのに書けてしまう**
/// （黙って効かない形を作らない）。
pub(super) fn key_path(image_name: &str) -> Result<String, String> {
    if image_name.is_empty() {
        return Err("image name must not be empty".to_string());
    }
    if image_name.contains('\\') || image_name.contains('/') {
        return Err(format!(
            "image name must be the bare file name, not a path: {image_name:?}"
        ));
    }
    Ok(format!("{IFEO_ROOT}\\{image_name}"))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Page Heap(Full)を1つの実行ファイルへ載せる。**既に載っていれば上書きする**（冪等）。
pub(super) fn enable_full(image_name: &str) -> Result<(), String> {
    let path = wide(&key_path(image_name)?);
    let mut key = HKEY::default();
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path.as_ptr()),
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut key,
            None,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(format!(
            "RegCreateKeyExW({}) failed: {:?} (昇格しているか確認)",
            key_path(image_name)?,
            status
        ));
    }
    let write = set_dword(key, "GlobalFlag", FLG_HEAP_PAGE_ALLOCS)
        .and_then(|()| set_dword(key, "PageHeapFlags", PAGE_HEAP_FULL));
    unsafe {
        let _ = RegCloseKey(key);
    }
    write
}

fn set_dword(key: HKEY, name: &str, value: u32) -> Result<(), String> {
    let name_w = wide(name);
    let bytes = value.to_le_bytes();
    let status = unsafe {
        RegSetValueExW(
            key,
            PCWSTR(name_w.as_ptr()),
            0,
            REG_DWORD,
            Some(bytes.as_slice()),
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!("RegSetValueExW({name}) failed: {status:?}"))
    }
}

/// Page Heapを外す。**キーごと消す**（モジュールdocの「撤収は消すでよい」）。
///
/// **冪等**である——載っていない状態で呼んでも成功を返す。撤収は落ちた後にも
/// 撃たれるものなので、「もう無い」を失敗にすると本当の失敗と見分けが付かなくなる。
pub(super) fn disable(image_name: &str) -> Result<(), String> {
    let path = wide(&key_path(image_name)?);
    let status = unsafe { RegDeleteKeyW(HKEY_LOCAL_MACHINE, PCWSTR(path.as_ptr())) };
    if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(format!(
            "RegDeleteKeyW({}) failed: {status:?}",
            key_path(image_name)?
        ))
    }
}

/// いまPage Heapが載っているか。**回収のための目**でもある——テストごと殺されて
/// キーが残っても、これで見えて[`disable`]で消せる（台帳を持たない理由）。
pub(super) fn is_enabled(image_name: &str) -> bool {
    read_dword(image_name, "GlobalFlag").is_some_and(|v| v & FLG_HEAP_PAGE_ALLOCS != 0)
        && read_dword(image_name, "PageHeapFlags").is_some_and(|v| v & 0x1 != 0)
}

fn read_dword(image_name: &str, name: &str) -> Option<u32> {
    let path = wide(&key_path(image_name).ok()?);
    let name_w = wide(name);
    let mut value = 0u32;
    let mut size = std::mem::size_of::<u32>() as u32;
    let status: WIN32_ERROR = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path.as_ptr()),
            PCWSTR(name_w.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut value as *mut u32 as *mut std::ffi::c_void),
            Some(&mut size),
        )
    };
    (status == ERROR_SUCCESS).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 葉の名前なら組めて、**パスなら断る**。対で置く——断る側だけだと
    /// 「何も組めない」実装でも緑になる。
    #[test]
    fn the_key_is_keyed_by_the_bare_file_name_and_a_path_is_refused() {
        let ok = key_path("tier2a_proc_probe.exe").expect("a bare name must be accepted");
        assert!(
            ok.ends_with(r"Image File Execution Options\tier2a_proc_probe.exe"),
            "{ok}"
        );

        for rejected in [
            r"C:\work\tier2a_proc_probe.exe",
            "sub/tier2a_proc_probe.exe",
            "",
        ] {
            assert!(
                key_path(rejected).is_err(),
                "a path or empty name must be refused: {rejected:?}"
            );
        }
    }

    /// **fullは`0x1`では立たない。** `PageHeapFlags`から`0x2`を落とすと番兵ページが
    /// 立たず、はみ出しは捕まらない——値を取り違えたまま「効いている」と読む形を止める。
    #[test]
    fn full_page_heap_needs_both_the_master_switch_and_the_full_bit() {
        assert_eq!(FLG_HEAP_PAGE_ALLOCS, 0x0200_0000);
        assert_eq!(PAGE_HEAP_FULL & 0x1, 0x1, "有効化のビットが要る");
        assert_eq!(
            PAGE_HEAP_FULL & 0x2,
            0x2,
            "fullのビットが要る（番兵ページ）"
        );
    }

    /// **載っていない実行ファイルは「載っていない」と答える。** ここが常に`true`を返すと、
    /// 撤収の検証（キーが消えたか）が意味を失う。
    #[test]
    fn an_image_nobody_touched_is_reported_as_not_enabled() {
        assert!(!is_enabled("harness-page-heap-nobody-writes-this.exe"));
    }

    /// **撤収は冪等**——無いキーを消しても成功する（昇格が要らない経路で確かめる:
    /// 存在しないキーの削除は`ERROR_FILE_NOT_FOUND`で返り、書込権限を要求しない）。
    #[test]
    fn disabling_something_that_was_never_enabled_succeeds() {
        disable("harness-page-heap-nobody-writes-this.exe")
            .expect("撤収は『もう無い』を失敗にしない");
    }
}
