//! Windows Tier1b（`win_restricted`）とTier1a（`win_appcontainer`）が共有する低レベル
//! 補助関数（ワイド文字列変換・パイプ・env変換・HANDLE読み書き・Job Object）。
//!
//! いずれもWin32のパイプ継承・HANDLE操作というOSレベル挙動そのものに起因するロジックで、
//! 起動方式（制限トークン vs AppContainer属性）に依存しない。`win_restricted.rs`からの
//! 機械的な移設であり、ロジックは変更していない（BUG-004で発見した継承フラグの扱いも含む）。

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT, HLOCAL, LocalFree, SetHandleInformation,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows::Win32::System::Pipes::CreatePipe;

pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
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
    String::from_utf8_lossy(&out).into_owned()
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
/// Tier1b/Tier1aどちらの起動シーケンスでも同一ロジックを使う（T-13対策）。
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
