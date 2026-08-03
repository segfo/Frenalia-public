//! Windows Tier1（`win_restricted`）とTier2a（`win_appcontainer`）が共有する低レベル
//! 補助関数（ワイド文字列変換・パイプ・env変換・HANDLE読み書き・Job Object）。
//!
//! いずれもWin32のパイプ継承・HANDLE操作というOSレベル挙動そのものに起因するロジックで、
//! 起動方式（制限トークン vs AppContainer属性）に依存しない。`win_restricted.rs`からの
//! 機械的な移設であり、ロジックは変更していない（BUG-004で発見した継承フラグの扱いも含む）。

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    LocalFree, SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT, HLOCAL,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::JobObjects::{
    CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Pipes::CreatePipe;

/// `harness-sandbox-vm`（`smb_share`・`vmsandboxd`）から参照されるため`pub`
/// （`docs/CODE-STRUCTURE-RULES.md`規則4）。
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// パスをそのまま`wide`へ渡すと、Win32 ACL API（`GetNamedSecurityInfoW`/`SetNamedSecurityInfoW`
/// 等）は`MAX_PATH`（260文字）を超えるパスを`ERROR_INVALID_NAME`（0x8007007B）で拒否する
/// （BUG-028）。`\\?\`ロングパス接頭辞（既に付いている場合・UNCパスの場合は付け直さない）を
/// 付与し、この制約を回避する。ACLを扱う全経路（`win_appcontainer.rs`のgrant/revoke系）は
/// パスの文字列化に必ずこれを使うこと（生の`wide(&path.to_string_lossy())`を直接呼ばない）。
pub(crate) fn long_path_wide(path: &std::path::Path) -> Vec<u16> {
    let s = path.to_string_lossy();
    if s.starts_with(r"\\?\") {
        return wide(&s);
    }
    if let Some(unc) = s.strip_prefix(r"\\") {
        return wide(&format!(r"\\?\UNC\{unc}"));
    }
    wide(&format!(r"\\?\{s}"))
}

/// NUL終端のUTF-16文字列（`PWSTR`）をRustの`String`へ変換する（`ConvertSidToStringSidW`等、
/// Win32が呼び出し側に所有権を渡す出力バッファを読み取る用途、`privhelper`から使う）。
pub(crate) fn pwstr_to_string(p: windows::core::PWSTR) -> String {
    unsafe { p.to_string().unwrap_or_default() }
}

/// `CreatePipe`の`bInheritHandle=TRUE`は両端を継承可能にする。子へ渡さない側（親が保持し続ける側）
/// を継承不可へ戻さないと、子が余分な複製ハンドルを継承してしまい、親が閉じてもEOFにならず
/// 子が永久にハングする（BUG-004、MSDN「Creating a Child Process with Redirected Input and
/// Output」記載の既知の落とし穴。実機でこれによる子プロセスのハングを確認した）。
pub(crate) fn clear_inherit(handle: HANDLE) {
    unsafe {
        let _ = SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0));
    }
}

/// 環境変数をCreateProcess系API用のnull区切り環境ブロック（UTF-16、末尾ダブルNUL）へ変換する。
pub(crate) fn build_env_block(env: &[(String, String)]) -> Vec<u16> {
    let mut entries: Vec<&(String, String)> = env.iter().collect();
    entries.sort_by_key(|a| a.0.to_ascii_uppercase());
    let mut block: Vec<u16> = Vec::new();
    for (k, v) in entries {
        block.extend(format!("{k}={v}").encode_utf16());
        block.push(0);
    }
    block.push(0);
    block
}

pub(crate) fn write_all(handle: HANDLE, mut buf: &[u8]) {
    unsafe {
        while !buf.is_empty() {
            let mut written = 0u32;
            let ok = WriteFile(handle, Some(buf), Some(&mut written), None);
            if ok.is_err() || written == 0 {
                break;
            }
            buf = &buf[written as usize..];
        }
    }
}

pub(crate) fn read_to_string(handle: HANDLE) -> String {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    unsafe {
        loop {
            let mut read = 0u32;
            let ok = ReadFile(handle, Some(&mut buf), Some(&mut read), None);
            if ok.is_err() || read == 0 {
                break;
            }
            out.extend_from_slice(&buf[..read as usize]);
        }
    }
    decode_console_bytes(&out)
}

/// BUG-051: 子プロセスのコンソール出力を復号する。まず全体をUTF-8として試し、それで
/// 妥当ならそのまま返す（正常系のほぼ全ケースはここで完了し、追加コストは無い）。
///
/// 失敗した場合のみ`\n`で行に分割し、行ごとに「UTF-8として妥当ならUTF-8、そうでなければ
/// ANSIコードページ（`GetACP()`）」として復号する。この分割はマルチバイト文字を分断しない
/// ——CP932の妥当な2バイト列（先行`0x81-0x9F`/`0xE0-0xFC`、後続`0x40-0x7E`/`0x80-0xFC`）を
/// 全探索した結果、`0x0A`を含むものは0件と確認済み。
///
/// **なぜ1本のストリーム内で混在し得るか**: PowerShellは起動直後、
/// `[Console]::OutputEncoding`をUTF-8へ切り替えるブートストラップが実行される**前**に
/// メッセージ（`InitializeDefaultDrives`失敗等）をstderrへ書くことがあり、これはANSI
/// コードページのバイト列で届く。以降の出力（ブートストラップ適用後）はUTF-8になるため、
/// 同一ストリーム内で前半ANSI・後半UTF-8という構成になり得る（実機Tier2aで確認、BUG-051）。
/// これはBUG-049/BUG-050（コマンド**入力**側のエンコーディング）とは別の**出力**側の欠陥。
#[cfg(windows)]
pub fn decode_console_bytes(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    let mut out = String::with_capacity(bytes.len());
    for (i, line) in bytes.split(|&b| b == b'\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        match std::str::from_utf8(line) {
            Ok(s) => out.push_str(s),
            Err(_) => out.push_str(&decode_ansi_lossy(line)),
        }
    }
    out
}

/// `bytes`をANSIコードページ（`GetACP()`）としてベストエフォートで復号する。
/// `decode_console_bytes`の非UTF-8行専用のフォールバック——復号方向にはBUG-050の
/// ベストフィット問題（符号化方向のみ）は存在しない。`MultiByteToWideChar`自体が失敗した
/// 場合（未知のコードページ等、通常起き得ない）は`from_utf8_lossy`へ更に退避する。
#[cfg(windows)]
fn decode_ansi_lossy(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let cp = unsafe { windows::Win32::Globalization::GetACP() };
    let needed = unsafe {
        windows::Win32::Globalization::MultiByteToWideChar(
            cp,
            windows::Win32::Globalization::MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0),
            bytes,
            None,
        )
    };
    if needed <= 0 {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let mut wide = vec![0u16; needed as usize];
    let written = unsafe {
        windows::Win32::Globalization::MultiByteToWideChar(
            cp,
            windows::Win32::Globalization::MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0),
            bytes,
            Some(&mut wide),
        )
    };
    if written <= 0 {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    wide.truncate(written as usize);
    String::from_utf16_lossy(&wide)
}

/// `HANDLE`は`windows`クレートで`Send`を実装しない（生ポインタ相当のため）。
/// `read_two_pipes_to_strings`がスレッド間で1回だけ受け渡すための最小限のラッパ
/// （`win_appcontainer::KillToken`と同じ「単純な数値ハンドルなので実際には安全」という判断）。
struct SendHandle(HANDLE);
unsafe impl Send for SendHandle {}

/// stdout/stderrを2スレッドで並行に読み切る（Phase5-E、`run_shell`不安定性調査）。
///
/// 従来は`read_to_string(stdout)`→`read_to_string(stderr)`の逐次読みだった。子プロセスが
/// stderrへパイプバッファ（既定64KB、匿名パイプの既定サイズ）を超えて書き込むと、読み手が
/// 現れないstderr側のパイプが満杯になり子プロセスの書込みがブロックする。逐次読みは
/// stdoutを読み切るまでstderrに手を付けないため、子はstdoutも吐けないままデッドロックし、
/// `run_shell`のタイムアウトまで応答が返らない（Tier2a/Tier1の`write_stdin_read_output_and_wait`
/// が踏んでいた欠陥。ビルドログ等stderr出力の多いコマンドで再現する）。
pub(crate) fn read_two_pipes_to_strings(stdout: HANDLE, stderr: HANDLE) -> (String, String) {
    let stdout_handle = SendHandle(stdout);
    let stdout_thread = std::thread::spawn(move || {
        let h = stdout_handle;
        read_to_string(h.0)
    });
    let err = read_to_string(stderr);
    let out = stdout_thread.join().unwrap_or_default();
    (out, err)
}

/// 指定したSDDL文字列のセキュリティ記述子を持つ匿名パイプを作る（両端とも継承可能で返る）。
/// 呼び出し側が用途に応じて`clear_inherit`で片端を継承不可へ戻す（`win_restricted`の
/// 低ILラベル付きパイプ・`win_appcontainer`のpackage SID付きパイプ、いずれもこの関数を土台にする）。
pub(crate) fn create_pipe_with_sddl(sddl: &str) -> windows::core::Result<(HANDLE, HANDLE)> {
    let mut read = HANDLE::default();
    let mut write = HANDLE::default();
    unsafe {
        let sddl_w = wide(sddl);
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: true.into(),
        };
        let result = CreatePipe(&mut read, &mut write, Some(&sa), 0);
        let _ = LocalFree(HLOCAL(sd.0));
        result?;
    }
    Ok((read, write))
}

/// kill-on-close付きJob Objectを作る（breakaway許可フラグは立てないため既定拒否）。
/// Tier1/Tier2aどちらの起動シーケンスでも同一ロジックを使う（T-13対策）。
pub(crate) fn create_job_object() -> windows::core::Result<HANDLE> {
    unsafe {
        let job = CreateJobObjectW(None, PCWSTR::null())?;
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )?;
        Ok(job)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// BUG-051回帰: 妥当なUTF-8（絵文字・非BMP文字含む）はバイト単位で無変更に通ること。
    #[test]
    fn decode_console_bytes_keeps_valid_utf8_unchanged() {
        let s = "ASCII + 日本語 + 🚀 + 𠮷野家\r\n2行目\n";
        assert_eq!(decode_console_bytes(s.as_bytes()), s);
    }

    /// BUG-051回帰: 起動直後のANSIコードページ由来の行と、ブートストラップ適用後のUTF-8の行が
    /// 同一ストリーム内に混在しても、両方とも正しく復元されること。ANSIコードページに依存しない
    /// 検証にするため、`GetACP()`で符号化した行を使う（このマシンのコードページがCP932でも
    /// UTF-8(65001)でも成立する）。
    #[test]
    fn decode_console_bytes_recovers_mixed_utf8_and_ansi_lines() {
        let ansi_line = "起動直後のANSI行";
        let utf8_line = "ブートストラップ後のUTF-8行 🚀";
        let ansi_bytes = encode_ansi_for_test(ansi_line);

        let mut mixed = Vec::new();
        mixed.extend_from_slice(&ansi_bytes);
        mixed.push(b'\n');
        mixed.extend_from_slice(utf8_line.as_bytes());
        mixed.push(b'\n');

        let cp = unsafe { windows::Win32::Globalization::GetACP() };
        if cp == 65001 {
            // このマシンのANSI CPがUTF-8の場合、ansi_bytes自体がUTF-8になるため
            // 全体が最初のUTF-8一括デコードで通る（分岐は踏まないが結果は正しい）。
            assert_eq!(
                decode_console_bytes(&mixed),
                format!("{ansi_line}\n{utf8_line}\n")
            );
            return;
        }
        // 全体を一括UTF-8デコードすると失敗する入力であることを前提として確認する
        // （さもないと本テストは行単位フォールバック経路を検証できていない）。
        assert!(std::str::from_utf8(&mixed).is_err());
        assert_eq!(
            decode_console_bytes(&mixed),
            format!("{ansi_line}\n{utf8_line}\n")
        );
    }

    /// CRLF・末尾に改行が無い場合の両方で内容が保持されること。
    #[test]
    fn decode_console_bytes_preserves_crlf_and_missing_trailing_newline() {
        let ansi_line = "日本語のみの1行（末尾改行なし）";
        let bytes = encode_ansi_for_test(ansi_line);
        let cp = unsafe { windows::Win32::Globalization::GetACP() };
        if cp == 65001 {
            assert_eq!(decode_console_bytes(&bytes), ansi_line);
            return;
        }
        assert_eq!(decode_console_bytes(&bytes), ansi_line);

        let crlf = "行1\r\n行2\r\n".to_string().into_bytes();
        assert_eq!(decode_console_bytes(&crlf), "行1\r\n行2\r\n");
    }

    /// UTF-8としてもANSIコードページとしても復号できない極端なバイト列でpanicせず、
    /// `U+FFFD`を含む文字列へ安全に退避すること。
    #[test]
    fn decode_console_bytes_does_not_panic_on_undecodable_bytes() {
        let bytes = vec![0xFFu8, 0xFE, 0x00, 0x01, 0x0A, 0x80, 0x81];
        let out = decode_console_bytes(&bytes);
        assert!(!out.is_empty() || bytes.is_empty());
    }

    #[test]
    fn decode_console_bytes_handles_empty_input() {
        assert_eq!(decode_console_bytes(&[]), "");
    }

    /// テスト専用: `str`を現在のANSIコードページ（`GetACP()`）でエンコードする
    /// （`encode_console_bytes`の逆写像に相当するが、対称性検証のためテストだけに持つ）。
    fn encode_ansi_for_test(s: &str) -> Vec<u8> {
        let cp = unsafe { windows::Win32::Globalization::GetACP() };
        let utf16: Vec<u16> = s.encode_utf16().collect();
        let needed = unsafe {
            windows::Win32::Globalization::WideCharToMultiByte(
                cp,
                windows::Win32::Globalization::WC_NO_BEST_FIT_CHARS,
                &utf16,
                None,
                windows::core::PCSTR::null(),
                None,
            )
        };
        assert!(needed > 0, "WideCharToMultiByte(needed) failed for {s:?}");
        let mut buf = vec![0u8; needed as usize];
        let written = unsafe {
            windows::Win32::Globalization::WideCharToMultiByte(
                cp,
                windows::Win32::Globalization::WC_NO_BEST_FIT_CHARS,
                &utf16,
                Some(&mut buf),
                windows::core::PCSTR::null(),
                None,
            )
        };
        assert!(written > 0, "WideCharToMultiByte(write) failed for {s:?}");
        buf.truncate(written as usize);
        buf
    }
}
