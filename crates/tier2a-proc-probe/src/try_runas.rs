//! 特権昇格ヘルパー(D-16)レビュー用の実機検証プローブ。
//!
//! `crates/harness-sandbox/src/privhelper.rs`の`launch_helper_elevated`とほぼ同一のWin32呼び出し
//! （`ShellExecuteExW`、`lpVerb="runas"`、`SEE_MASK_NOCLOSEPROCESS`、`nShow=SW_HIDE`）を、
//! AppContainer内の子プロセスから実行してみて、UAC昇格ブローカへ到達できるかを確認する。
//! 本体との差分は`SEE_MASK_FLAG_NO_UI`を追加している点だけで、その理由と影響は下記
//! 「副次的な発見」に記す。
//!
//! 「LLMが`run_shell`で`harness.exe`を再実行し、特権昇格ヘルパー経由で任意パスへ
//! サンドボックスSID宛のACEを撒かせる」という攻撃経路（`/dig`セッションで検討）の
//! 成立性を判定するための実験——AppContainer/低ILトークンはUAC昇格ブローカ(AIS)へ
//! 到達できず即座に失敗する、というのが一般的なWindowsの挙動だが、この特定の
//! AppContainerプロファイル（capability構成・no-console等）での実機確認は無かった。
//!
//! **実機確認済み（2026-08-02）**: `SEE_MASK_FLAG_NO_UI`を付けた現行プローブでは、
//! `ShellExecuteExW(runas)`は`ERROR_ACCESS_DENIED`(5)で即座に失敗し、UAC同意ダイアログ
//! （「このアプリがデバイスに変更を加えることを許可しますか？」）は画面に一切表示されない
//! ことを目視確認した。AppContainerトークンはAPI呼び出しの時点でシェルに拒否され、UAC同意
//! ブローカ（consent.exe/AIS）へは一切到達しない。リンク2（入れ子harnessが特権昇格ブローカへ
//! 到達する経路）は実機でも構造的に閉じている。この`ERROR_ACCESS_DENIED`(5)は、
//! `crates/harness-sandbox/src/win_appcontainer.rs`の回帰テスト
//! `traverse_diagnostics::appcontainer_child_cannot_reach_uac_elevation_broker`が固定assert
//! している値でもある。
//!
//! **副次的な発見**: 初回検証時は`SEE_MASK_FLAG_NO_UI`を付けていなかった。このとき同じ拒否は
//! `ERROR_CANCELLED`(1223、`launch_helper_elevated`が`ElevationDeclined`へ変換するのと同じ
//! コード)として返り、さらに`ShellExecuteExW`が戻るまでに約17秒かかっていた。その間、シェル
//! 自身が「指定されたデバイス、パス、またはファイルにアクセスできません」というエラー
//! ダイアログを対話デスクトップ上に表示する（UAC同意画面ではなく、単なるアクセス拒否の通知）。
//! つまり返るエラーコードと所要時間は`SEE_MASK_FLAG_NO_UI`の有無で変わるが、
//! 「特権昇格には至らない」という結論はどちらでも同じである。AppContainerの「対話UIを持たない」という
//! 想定は絶対ではなく、シェルのエラーUIのような経路では可視化され得る——今回のセキュリティ結論
//! （特権付与は起きない）には影響しないが、サンドボックス化された子プロセスが対話デスクトップへ
//! 予期しないダイアログを出しうるという事実は覚えておく価値がある。以降の再実行で毎回ダイアログを
//! 手動で閉じずに済むよう、このプローブでは`SEE_MASK_FLAG_NO_UI`を追加している
//! （`launch_helper_elevated`本体は非サンドボックスの本体プロセスから呼ばれる想定で、
//! 失敗時にユーザーへエラーUIを見せることに実害が無いため、本体側は変更していない）。
//!
//! **安全性の配慮**: 昇格対象には`harness-privhelper.exe`自身を使うが、第2引数
//! （パイプ名）には実在しないパイプ名を渡す。`serve()`は`CreateFileW(OPEN_EXISTING)`で
//! そのパイプへ接続しようとして即座に失敗し、実際のACL書込み処理（`dispatch()`）へは
//! 一切到達せず終了する。したがって仮にUACが表示され誤って「許可」されても、
//! 実際に特権操作が行われることは無い。加えて`ShellExecuteExW`が成功して`hProcess`が
//! 有効だった場合は、直後に`TerminateProcess`して後始末する（二重の保険）。

use serde_json::{json, Value};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{GetLastError, CloseHandle, ERROR_CANCELLED};
use windows::Win32::System::Threading::TerminateProcess;
use windows::Win32::UI::Shell::{
    ShellExecuteExW, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `helper_path`（通常は`harness-privhelper.exe`の絶対パス）へ、実在しないパイプ名を
/// 引数に付けて`runas`昇格を試みる。戻り値はJSONレポート
/// （`{"target", "ok", "win32_error", "elevation_declined"}`）。
pub fn try_runas(helper_path: &str) -> Value {
    // 実在しないパイプ名（安全性の配慮、モジュールdoc参照）。
    let fake_pipe = format!(
        r"\\.\pipe\harness-privhelper-verify-nonexistent-{}",
        std::process::id()
    );

    let verb_w = wide("runas");
    let file_w = wide(helper_path);
    let params_w = wide(&fake_pipe);

    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        // SEE_MASK_FLAG_NO_UI: 失敗時にシェル自身がエラーダイアログを対話デスクトップへ
        // 出さないようにする（モジュールdoc「副次的な発見」参照。戻り値・GetLastError()の
        // 意味には影響しない、UI抑制のみ）。
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI,
        lpVerb: PCWSTR(verb_w.as_ptr()),
        lpFile: PCWSTR(file_w.as_ptr()),
        lpParameters: PCWSTR(params_w.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };

    let ok = unsafe { ShellExecuteExW(&mut info) };
    if ok.is_err() {
        let err = unsafe { GetLastError() };
        return json!({
            "target": helper_path,
            "fake_pipe_arg": fake_pipe,
            "ok": false,
            "win32_error": err.0,
            "elevation_declined": err == ERROR_CANCELLED,
        });
    }

    // 成功した場合（hProcessが有効）は直後に後始末する（モジュールdoc「安全性の配慮」参照）。
    let hprocess_valid = !info.hProcess.is_invalid();
    if hprocess_valid {
        unsafe {
            let _ = TerminateProcess(info.hProcess, 1);
            let _ = CloseHandle(info.hProcess);
        }
    }

    json!({
        "target": helper_path,
        "fake_pipe_arg": fake_pipe,
        "ok": true,
        "win32_error": Value::Null,
        "elevation_declined": false,
        "hprocess_valid": hprocess_valid,
    })
}
