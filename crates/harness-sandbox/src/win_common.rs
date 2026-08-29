//! Windows Tier1（`win_restricted`）とTier2a（`win_appcontainer`）が共有する低レベル
//! 補助関数（ワイド文字列変換・パイプ・env変換・HANDLE読み書き・Job Object）。
//!
//! いずれもWin32のパイプ継承・HANDLE操作というOSレベル挙動そのものに起因するロジックで、
//! 起動方式（制限トークン vs AppContainer属性）に依存しない。`win_restricted.rs`からの
//! 機械的な移設であり、ロジックは変更していない（BUG-004で発見した継承フラグの扱いも含む）。

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT, HLOCAL,
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
use windows::Win32::System::Threading::{
    GetExitCodeProcess, TerminateProcess, WaitForSingleObject, INFINITE,
};

/// `harness-sandbox-vm`（`smb_share`・`vmsandboxd`）から参照されるため`pub`
/// （`docs/CODE-STRUCTURE-RULES.md`規則4）。
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 指定PIDのプロセスが終了するまで待つ。既に終了していれば即座に`true`、時間切れなら`false`。
///
/// **PIDではなくプロセスハンドルの生存で判定する**（`bug-pattern-rules` B-17）。PIDは再利用
/// され得るが、`OpenProcess`で得たハンドルはそのプロセス自身を指し続ける。開けなかった場合は
/// 「もう居ない」＝`true`として扱う（`ERROR_INVALID_PARAMETER`は消滅済みの正常系）。
///
/// `harness-cli`が`/workspace`の再起動で使う（`startup::relaunch`）。あちらは`windows`クレートに
/// 依存していないのでここへ置く。
pub fn wait_for_process_exit(pid: u32, timeout_ms: u32) -> bool {
    use windows::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::{
        OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE,
    };
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_SYNCHRONIZE, false, pid) else {
            return true;
        };
        let status = WaitForSingleObject(handle, timeout_ms);
        let _ = CloseHandle(handle);
        status != WAIT_TIMEOUT
    }
}

/// ディレクトリ**そのもの**（パスではなく実体）を一意に指す識別子。
/// `<ボリュームシリアル>-<ファイルID>`の16進表現。
///
/// **なぜ要るか**（[BUG-110](../../docs/bugs/BUG-110.md)）: 台帳が持つ「このツリーについて
/// 〜を済ませた」という記録は、**その時点のツリー**についての事実である。同じパスでも
/// 削除して作り直せば別のオブジェクトで、前の記録は当てはまらない。パスだけを鍵にした
/// 記録は、その瞬間から嘘になる。
///
/// **作成時刻では代用できない。** Windowsのfile tunnelingは、同じ名前で15秒以内に
/// 作り直したファイル/ディレクトリへ元の作成時刻（と8.3短縮名）を引き継がせる。
/// 一方`nFileIndex`はMFTレコード番号＋シーケンス番号なので、作り直せば必ず変わる。
///
/// 開くのは`FILE_READ_ATTRIBUTES`のみ（内容は読まない）で、共有は全許可
/// ——ここで対象を掴んだまま他の書込を止めると、呼び出し元の意図しない排他になる。
pub(crate) fn directory_identity(path: &std::path::Path) -> windows::core::Result<String> {
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    let path_w = long_path_wide(path);
    unsafe {
        // `FILE_FLAG_BACKUP_SEMANTICS`が無いとディレクトリは開けない（ファイル用の
        // `CreateFileW`はディレクトリに対して`ERROR_ACCESS_DENIED`を返す）。
        let handle = CreateFileW(
            PCWSTR(path_w.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )?;
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        let result = GetFileInformationByHandle(handle, &mut info);
        let _ = CloseHandle(handle);
        result?;
        let file_id = ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64;
        Ok(format!(
            "{:08x}-{:016x}",
            info.dwVolumeSerialNumber, file_id
        ))
    }
}

/// パスをそのまま`wide`へ渡すと、Win32 ACL API（`GetNamedSecurityInfoW`/`SetNamedSecurityInfoW`
/// 等）は`MAX_PATH`（260文字）を超えるパスを`ERROR_INVALID_NAME`（0x8007007B）で拒否する
/// （BUG-028）。`\\?\`ロングパス接頭辞（既に付いている場合・UNCパスの場合は付け直さない）を
/// 付与し、この制約を回避する。ACLを扱う全経路（`win_appcontainer.rs`のgrant/revoke系）は
/// パスの文字列化に必ずこれを使うこと（生の`wide(&path.to_string_lossy())`を直接呼ばない）。
pub(crate) fn long_path_wide(path: &std::path::Path) -> Vec<u16> {
    // `\\?\`を付けた時点でそのパスは**verbatim**になり、Win32はもう正規化してくれない
    // ——区切りは`\`でなければならず、`/`のままだとACL APIが`ERROR_FILE_NOT_FOUND`
    // （0x80070002）で失敗する。`workspace_root.join(..)`由来のパスは元から`\`なのでこれまで
    // 露呈しなかったが、**ユーザーが設定ファイルへ直接書いたパス**（MCP宣言の`command`、
    // `fs.allow`等）は`C:/foo/bar`の形で来る。ここは全ACL経路が通る一点なので、
    // 呼び出し側ごとに正規化を撒くのではなくここで吸収する（規則5: 同じ欠陥を複数箇所に
    // 作らない）。実測: `harness mcp`の宣言に`c:/...`と書いた起動でACE付与が失敗していた。
    let s = path.to_string_lossy().replace('/', "\\");
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

/// SIDのバイト列コピー。Win32が返すSIDは呼び出し側で解放規則が異なる（`FreeSid`/`LocalFree`/
/// 配列ごと解放）ため、**中身をコピーして所有権を単純化する**。`loopback_exemption`（exemption
/// 一覧から読み出したSID）と`win_appcontainer`（capability SID）が共有する（規則5）。
///
/// `pub`なのは、`traverse_capability_sid`の戻り値としてクレート外（`harness-cli`の
/// `harness fs grant-traverse`）まで届くため（`docs/CODE-STRUCTURE-RULES.md`規則4）。
#[derive(Debug, Clone)]
pub struct OwnedSid {
    bytes: Vec<u8>,
}

impl OwnedSid {
    /// # Safety
    /// `sid`は有効なSIDを指していること。
    pub unsafe fn copy_from(sid: windows::Win32::Security::PSID) -> windows::core::Result<Self> {
        use windows::Win32::Security::{CopySid, GetLengthSid, PSID};
        let len = GetLengthSid(sid);
        if len == 0 {
            return Err(windows::core::Error::from_win32());
        }
        let mut bytes = vec![0u8; len as usize];
        CopySid(len, PSID(bytes.as_mut_ptr() as *mut _), sid)?;
        Ok(Self { bytes })
    }

    pub fn as_psid(&self) -> windows::Win32::Security::PSID {
        windows::Win32::Security::PSID(self.bytes.as_ptr() as *mut _)
    }
}

/// SIDを文字列表現（`S-1-5-21-...`）へ変換する。`win_pipe_ipc`（パイプDACL用のユーザSID）と
/// `tier2a::loopback_exemption`（台帳の鍵にするpackage SID）が共有する。
pub(crate) fn sid_to_string(sid: windows::Win32::Security::PSID) -> windows::core::Result<String> {
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    unsafe {
        let mut sid_str_ptr = windows::core::PWSTR::null();
        ConvertSidToStringSidW(sid, &mut sid_str_ptr)?;
        let sid_str = pwstr_to_string(sid_str_ptr);
        let _ = LocalFree(HLOCAL(sid_str_ptr.0 as *mut _));
        Ok(sid_str)
    }
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
///
/// `CREATE_UNICODE_ENVIRONMENT`が要求する終端は、変数ゼロ件の場合も含めて**常に二重NUL**
/// （`\0\0`）である——各変数は単一NULで終わり、ブロック全体の終わりにもう1つNULが要る。
/// 変数が1件以上あればループの各`push(0)`＋関数末尾の`push(0)`で自然に二重になるが、
/// **0件のときはループが1回も回らず`push(0)`が1回しか効かない**ため、単一NULのまま
/// `CreateProcessAsUserW`へ渡ると`ERROR_INVALID_PARAMETER`になる（実機で確認済み——
/// 本番経路は`build_child_env()`が常に非空を返すため露見しなかった潜在バグ）。
pub(crate) fn build_env_block(env: &[(String, String)]) -> Vec<u16> {
    let mut entries: Vec<&(String, String)> = env.iter().collect();
    entries.sort_by_key(|a| a.0.to_ascii_uppercase());
    let mut block: Vec<u16> = Vec::new();
    for (k, v) in entries {
        block.extend(format!("{k}={v}").encode_utf16());
        block.push(0);
    }
    block.push(0);
    if env.is_empty() {
        block.push(0);
    }
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
pub(crate) fn decode_ansi_lossy(bytes: &[u8]) -> String {
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
/// スレッド間で受け渡すための最小限のラッパ（`win_appcontainer::KillToken`と同じ
/// 「単純な数値ハンドルなので実際には安全」という判断）。
///
/// **`docs/CODE-STRUCTURE-RULES.md`規則5により写しを作らない。** 使うのは
/// [`read_two_pipes_to_strings`]（stdout/stderrを2スレッドで読む）と、
/// `tier2a::win_appcontainer::lazy_grant::broker`（接続ごとのハンドラスレッドへ
/// パイプを渡す、D-88）の2箇所である。
pub(crate) struct SendHandle(pub(crate) HANDLE);
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

/// ストリーミング出力の1件（[`stream_child_output`]が流す）。
///
/// **`Exited`と`OutputClosed`は独立したイベントである。** 孫プロセスがstdout/stderrを
/// 継承したまま握り続けると、直接の子が終了しても`OutputClosed`はすぐには来ない。
/// 受け手は`Exited`を見た時点でタイムアウト判断などへ進んでよく、`OutputClosed`だけを
/// 待ってハングする設計にしないこと。
#[derive(Debug, Clone)]
pub enum OutputEvent {
    Stdout(String),
    Stderr(String),
    /// stdout/stderrの両方がEOFに達した。**プロセスの終了（`Exited`）とは独立**。
    OutputClosed,
    /// プロセスの終了コード。
    Exited(i32),
}

/// spawn済みの子プロセスから、出力を行単位で流しつつ終了を別イベントで通知する。
///
/// Tier1（`win_restricted::RestrictedChild`）とTier2a（`win_appcontainer::AppContainerChild`）は
/// **HANDLEの構成が同形**（process / job / stdin_write / stdout_read / stderr_read）なので、
/// ストリーミングの実装はここ1つだけを持つ（`docs/CODE-STRUCTURE-RULES.md`規則5）。
/// 呼び出し側は自分のDropを`mem::forget`で無効化してからハンドルを渡すこと——以降の後始末は
/// 本関数が起こす各スレッドが自分の担当分だけ行う（`wfp.rs`の`WfpSession::teardown`と同じ
/// 「所有権をここで断つ」パターン）。
///
/// `write_stdin_read_output_and_wait`と違い呼び出し側で`spawn_blocking`する必要はない
/// ——OSスレッド4本（stdout読取・stderr読取・両者のjoin・プロセス待機）を内部で起こし、
/// receiverだけを返す。
pub(crate) fn stream_child_output(
    process: HANDLE,
    job: HANDLE,
    stdin_write: Option<HANDLE>,
    stdout_read: HANDLE,
    stderr_read: HANDLE,
    stdin_payload: Option<&[u8]>,
) -> tokio::sync::mpsc::UnboundedReceiver<OutputEvent> {
    if let Some(stdin) = stdin_write {
        if let Some(payload) = stdin_payload {
            write_all(stdin, payload);
        }
        unsafe {
            let _ = CloseHandle(stdin);
        }
    }

    let stdout = SendHandle(stdout_read);
    let stderr = SendHandle(stderr_read);
    let process = SendHandle(process);
    let job = SendHandle(job);

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

    // stdout/stderrの読み取りとプロセス待機は**完全に独立したスレッド**で走らせる。
    // 片方をもう片方の後始末（join）にぶら下げると、その依存の向きだけ`Exited`が
    // `OutputClosed`を待つ形になってしまい、「孫プロセスがパイプを握っていても
    // `Exited`は先に届く」という設計意図（[`OutputEvent`]のdoc）を満たせない。
    let tx_out = tx.clone();
    let out_thread = std::thread::spawn(move || {
        // RFC 2229の部分キャプチャが`stdout.0`だけを捉えて`SendHandle`のSend実装を
        // 素通りしないよう、変数全体を明示的に再束縛してから使う。
        let stdout = stdout;
        stream_pipe_lines(stdout.0, |line| {
            let _ = tx_out.send(OutputEvent::Stdout(line));
        });
        unsafe {
            let _ = CloseHandle(stdout.0);
        }
    });
    let tx_err = tx.clone();
    let err_thread = std::thread::spawn(move || {
        let stderr = stderr;
        stream_pipe_lines(stderr.0, |line| {
            let _ = tx_err.send(OutputEvent::Stderr(line));
        });
        unsafe {
            let _ = CloseHandle(stderr.0);
        }
    });
    let tx_closed = tx.clone();
    std::thread::spawn(move || {
        let _ = out_thread.join();
        let _ = err_thread.join();
        let _ = tx_closed.send(OutputEvent::OutputClosed);
    });

    std::thread::spawn(move || unsafe {
        let process = process;
        let job = job;
        WaitForSingleObject(process.0, INFINITE);
        let mut code: u32 = 0;
        let _ = GetExitCodeProcess(process.0, &mut code);
        let _ = tx.send(OutputEvent::Exited(code as i32));
        // ジョブを閉じる＝kill-on-closeで、居残っている子孫（stdout/stderrを握ったまま
        // 孤児化した孫プロセス）を巻き取って終了させる。これによりreader側の`ReadFile`が
        // EOFで返り、`OutputClosed`が来ないまま無期限にブロックする事態を避ける。
        let _ = CloseHandle(job.0);
        let _ = CloseHandle(process.0);
    });

    rx
}

/// パイプから行単位で読み、`\n`ごとにコールバックへ渡す（`decode_console_bytes`をBUG-051と
/// 同じ方針で1行分のバイト列に適用する）。EOF時に残った未改行の断片も最後に1回だけ渡す。
/// ブロッキング（呼び出し側が専用スレッドで回す）。
fn stream_pipe_lines(handle: HANDLE, mut on_line: impl FnMut(String)) {
    let mut pending = Vec::new();
    let mut buf = [0u8; 8192];
    unsafe {
        loop {
            let mut read = 0u32;
            let ok = ReadFile(handle, Some(&mut buf), Some(&mut read), None);
            if ok.is_err() || read == 0 {
                break;
            }
            pending.extend_from_slice(&buf[..read as usize]);
            while let Some(pos) = pending.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = pending.drain(..=pos).collect();
                on_line(decode_console_bytes(&line));
            }
        }
    }
    if !pending.is_empty() {
        on_line(decode_console_bytes(&pending));
    }
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

/// 既定のセキュリティ記述子で継承可能な匿名パイプを作る（Tier0の起動シーケンス用）。
///
/// Tier1/Tier2aが[`create_pipe_with_sddl`]で明示ラベル・package SIDを付けるのは、
/// **低ILやAppContainerの子がMedium ILのパイプへ書けない**（No-Write-Up）ために
/// stdout/stderrが消えるという実害があるからで、パイプ一般の要件ではない。
/// Tier0の子は親と同じMedium ILで走るので、既定の記述子で届く。
/// 消えた理由が分からなくなると「念のため」で低ILラベルが復活しかねないので明記しておく。
pub(crate) fn create_inheritable_pipe() -> windows::core::Result<(HANDLE, HANDLE)> {
    let mut read = HANDLE::default();
    let mut write = HANDLE::default();
    unsafe {
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: true.into(),
        };
        CreatePipe(&mut read, &mut write, Some(&sa), 0)?;
    }
    Ok((read, write))
}

/// 子プロセスの本体が`spawn_blocking`や別スレッドへ移動した後も、timeout・キャンセルから
/// 終了させられる軽量ハンドル。**Tier1（`tier1::win_restricted`）とTier0（`tier0::win_plain`）が
/// 共有する**——`kill`の意味はトークンの種類に依存しないので、Tierごとに書き直すと
/// 片方だけ直る事故になる（`docs/CODE-STRUCTURE-RULES.md`§5.0）。
#[derive(Clone, Copy)]
pub struct KillToken(pub(crate) HANDLE);

// HANDLEはカーネルオブジェクトへのポインタ値で、別スレッドからの`TerminateProcess`は
// OSレベルで安全（`RestrictedChild`のSend実装と同じ理由）。
unsafe impl Send for KillToken {}

impl KillToken {
    pub fn kill(&self) {
        unsafe {
            let _ = TerminateProcess(self.0, 1);
        }
    }
}

/// kill-on-close付きJob Objectを作る（breakaway許可フラグは立てないため既定拒否）。
/// Tier0/Tier1/Tier2aどの起動シーケンスでも同一ロジックを使う（T-13対策）。
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

// --- 名前付きmutexによる「そのプロセスはまだ生きているか」の表明・確認 ---
//
// プロセスIDを記録して自分でliveness確認する方式ではなく、名前付きmutexを使う。作成した
// プロセスが（正常終了でもクラッシュでも）いなくなるとWindows自身がオブジェクトを破棄する
// ため、`OpenMutexW`で聞くだけで生存確認ができる。`workspace_ledger`（workspaceモード/CoW
// セッションの生存）と`loopback_exemption`（exemptionの所有者の生存）が共有する
// （`docs/CODE-STRUCTURE-RULES.md`規則5）。

/// `name`という名前付きmutexが現在誰かに保持されているか（＝生きたプロセスが存在するか）。
pub(crate) fn mutex_exists(name: &str) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenMutexW, SYNCHRONIZATION_SYNCHRONIZE};
    let wide = wide(name);
    unsafe {
        match OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, false, PCWSTR(wide.as_ptr())) {
            Ok(h) => {
                let _ = CloseHandle(h);
                true
            }
            Err(_) => false,
        }
    }
}

/// `name`という名前付きmutexを作成（既に存在すれば単にハンドルを開くだけ）し、
/// **意図的に`CloseHandle`しない**。生のWin32 `HANDLE`はDropで自動closeされないため、
/// この関数を抜けた後もハンドルはプロセスが終了するまで有効なまま残る。プロセスが
/// 正常終了・クラッシュのいずれで消えても、Windowsがこのハンドルを自動的に閉じ、
/// 参照が0になったオブジェクト自体も破棄される——それが「このモード/セッション/所有者は
/// もう生きていない」という合図になる。
pub(crate) fn hold_mutex_for_process_lifetime(name: &str) -> windows::core::Result<()> {
    use windows::Win32::System::Threading::CreateMutexW;
    let wide = wide(name);
    unsafe {
        CreateMutexW(None, false, PCWSTR(wide.as_ptr()))?;
    }
    Ok(())
}

// --- ボリュームの素性（どのボリュームに載っているか・ACLを保持できるか） ---
//
// CoWの差分層はワークスペースと同じボリュームへ置く（D-81）ので「このパスはどのボリュームか」
// が要り、CoWの境界はACL（ワークスペースを読取専用にする）なので「そのボリュームはACLを
// 保持できるか」が要る。どちらもWin32の生の問い合わせなのでここに置き、**規則の側は
// `session_scope`が持つ**（採取と判定を分ける）。

/// `path`が載っているボリュームのマウントポイント（`D:\`、あるいは
/// `C:\mnt\data\`のようなドライブ文字を持たないマウント先）を返す。
///
/// **先頭2文字を切り出す方式にしない。** ボリュームはドライブ文字を持たずに
/// ディレクトリへマウントできるので、`C:\mnt\data\proj`の実体が`C:`とは別ボリュームである
/// ことがある。そこを取り違えると「同じボリュームのつもりで別ボリューム」になり、
/// D-81が消しに行く相手（媒体ごと消える差分層）が成立しなくなる。
///
/// `path`は存在しなくてよい（`GetVolumePathNameW`は綴りだけで解決する）が、
/// 解決できなければ`None`を返す。**呼び出し側は`None`を「同じボリューム」と読まないこと。**
pub fn volume_mount_point_of(path: &std::path::Path) -> Option<std::path::PathBuf> {
    use windows::Win32::Storage::FileSystem::GetVolumePathNameW;
    // `subst`のドライブ文字は**ボリュームではなくディレクトリへの別名**なので、先に実体へ
    // 直す（下記）。直さないと`GetVolumePathNameW`が壊れた答えを返す。
    let path = resolve_subst_drive(path);
    let path = path.as_path();
    let wide_path = wide(&path.to_string_lossy());
    // MAX_PATHで足りない長いパスもあるので、NTの上限に合わせて広めに取る。
    let mut buf = vec![0u16; 32768];
    unsafe { GetVolumePathNameW(PCWSTR(wide_path.as_ptr()), &mut buf).ok()? };
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    if len == 0 {
        return None;
    }
    Some(std::path::PathBuf::from(String::from_utf16_lossy(
        &buf[..len],
    )))
}

/// `mount_point`（[`volume_mount_point_of`]の戻り値）が、CoWの境界を張れるボリュームかを
/// 判定するための素の事実を集める。
///
/// **2つを一度に採るのが要点である。** 「ACLを保持できるか」だけでは足りない——
/// ネットワーク共有（SMB）はサーバ側がNTFSなら`FILE_PERSISTENT_ACLS`を**立てて返す**が、
/// AppContainerのpackage SIDは**ローカルの主体**なので共有越しには意味を持たない。
/// ACLの有無だけを見ると「張れる」と誤読する。
///
/// 問い合わせ自体に失敗したら`None`。**`None`を「使える」と読まないこと**——
/// 判定できないなら境界を張れるか分からないのだから、拒否側へ倒すのが安全である。
pub fn volume_capability(
    mount_point: &std::path::Path,
) -> Option<crate::session_scope::VolumeCapability> {
    use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetVolumeInformationW};
    use windows::Win32::System::SystemServices::FILE_PERSISTENT_ACLS;
    use windows::Win32::System::WindowsProgramming::DRIVE_REMOTE;
    // `GetVolumeInformationW`/`GetDriveTypeW`はルートパスに末尾の区切りを要求する。
    let mut root = mount_point.to_string_lossy().into_owned();
    if !root.ends_with('\\') {
        root.push('\\');
    }
    let wide_root = wide(&root);
    let mut fs_name = vec![0u16; 256];
    let mut flags = 0u32;
    unsafe {
        GetVolumeInformationW(
            PCWSTR(wide_root.as_ptr()),
            None,
            None,
            None,
            Some(&mut flags),
            Some(&mut fs_name),
        )
        .ok()?
    };
    let len = fs_name.iter().position(|&c| c == 0).unwrap_or(fs_name.len());
    let drive_type = unsafe { GetDriveTypeW(PCWSTR(wide_root.as_ptr())) };
    Some(crate::session_scope::VolumeCapability {
        persistent_acls: flags & FILE_PERSISTENT_ACLS != 0,
        filesystem: String::from_utf16_lossy(&fs_name[..len]),
        is_remote: drive_type == DRIVE_REMOTE,
    })
}

/// `subst`で作ったドライブ文字を、指している実体のパスへ直す（`subst`でなければそのまま返す）。
///
/// # なぜ要るのか
///
/// `subst X: C:\some\dir` はボリュームを作らない——**ディレクトリへの別名**をDOSデバイス名前空間
/// に置くだけである。ところが`GetVolumePathNameW`はこれを普通のボリュームのように扱おうとして
/// 壊れた答えを返す（実測: `N:\proj` に対して `N:\proj\` 自身を「マウント先」として返し、
/// 続く`GetVolumeInformationW`が`ERROR_DIRECTORY_NOT_SUPPORTED`で失敗する。`N:\`を直接聞くと
/// それも失敗する）。その結果、ボリュームの素性が「判定不能」になり、CoWの関所は
/// **拒否側へ倒れて起動できなくなる**。
///
/// **これは実際に踏む配置である。** `preflight`のワークスペース長チェックは、パスが長すぎる
/// ときの回避策として`subst`を**自分から勧めている**——勧めたとおりにすると CoW が起動できない、
/// という噛み合わせになっていた。実体（多くはNTFSのC:）では境界を張れるので、拒否は過剰である。
///
/// 判定は`QueryDosDeviceW`が返す文字列で行う。`subst`のときだけ`\??\`＋実パスの形になり、
/// 本物のボリュームは`\Device\HarddiskVolume3`・`\Device\Volume{GUID}`、ネットワークドライブは
/// `\Device\LanmanRedirector\...`になる（この機で全ドライブを実測して確認した）。
fn resolve_subst_drive(path: &std::path::Path) -> std::path::PathBuf {
    use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

    let text = path.to_string_lossy().into_owned();
    // `X:`で始まるものだけが対象（UNCパスやverbatimは`subst`ではない）。
    let bytes = text.as_bytes();
    if bytes.len() < 2 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
        return path.to_path_buf();
    }
    let drive = &text[..2];
    let wide_drive = wide(drive);
    let mut buffer = vec![0u16; 4096];
    let len = unsafe { QueryDosDeviceW(PCWSTR(wide_drive.as_ptr()), Some(&mut buffer)) };
    if len == 0 {
        return path.to_path_buf();
    }
    let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    let target = String::from_utf16_lossy(&buffer[..end]);
    match apply_dos_device_target(&text, &target) {
        Some(resolved) => std::path::PathBuf::from(resolved),
        None => path.to_path_buf(),
    }
}

/// [`resolve_subst_drive`]の**規則だけ**（純関数。Win32を触らないので`cargo test`で検算できる）。
///
/// `device_target`は`QueryDosDeviceW`の戻り値。`subst`のときだけ`\??\`＋実パスの形になり、
/// そのときだけ`Some`を返す。本物のボリューム（`\Device\HarddiskVolume3`・
/// `\Device\Volume{GUID}`）とネットワークドライブ（`\Device\LanmanRedirector\...`）は
/// `None`＝そのまま扱う。
fn apply_dos_device_target(path_text: &str, device_target: &str) -> Option<String> {
    let real = device_target.strip_prefix(r"\??\")?;
    // 残り（`X:`を除いた部分）を実体へ継ぎ足す。`X:`だけならその実体そのもの。
    Some(format!("{real}{}", &path_text[2..]))
}

/// `path`のDACL（アクセス権の一覧）を**実際に書けるか**を、副作用なしで確かめる。
///
/// # なぜ申告を信じないのか
///
/// `FILE_PERSISTENT_ACLS`は「このファイルシステムはACLを永続化できます」という**申告**であって、
/// 書けることの保証ではない。この開発機の`E:`（第三者製の暗号化ファイルシステム`cryptoFs`）は
/// **申告を立てて返すのに、DACLの書込を一律で拒否する**（実測、2026-08-24）——
/// しかも`WRITE_DAC`付きのハンドルは普通に開けるので、**開けるかどうかでは見抜けない**。
/// 拒否されるのは書き込む瞬間だけである。
///
/// # なぜ「同じ内容を書き戻す」のか
///
/// 読んだDACLをそのまま書き戻すので、**成功しても対象は1ビットも変わらない**。
/// 権限を試しに足して消す形にすると、途中で落ちたときに足したものが残る（B-01の非対称）。
/// 測りたいのは「この対象へDACLを書く操作が通るか」だけなので、恒等な書込で足りる。
pub fn can_write_dacl(path: &std::path::Path) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{
        GetKernelObjectSecurity, SetKernelObjectSecurity, DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
    };

    let wide_path = wide(&path.to_string_lossy());
    unsafe {
        let Ok(handle) = CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            READ_CONTROL.0 | WRITE_DAC.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            // ディレクトリも同じ関数で開くために要る。
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        ) else {
            return false;
        };
        let mut needed = 0u32;
        // 1回目は必要な大きさを聞くだけ（必ず失敗する）。
        let _ = GetKernelObjectSecurity(
            handle,
            DACL_SECURITY_INFORMATION.0,
            PSECURITY_DESCRIPTOR::default(),
            0,
            &mut needed,
        );
        let mut buffer = vec![0u8; needed.max(4096) as usize];
        let descriptor = PSECURITY_DESCRIPTOR(buffer.as_mut_ptr().cast());
        let read = GetKernelObjectSecurity(
            handle,
            DACL_SECURITY_INFORMATION.0,
            descriptor,
            buffer.len() as u32,
            &mut needed,
        )
        .is_ok();
        // **読めた内容をそのまま書き戻す。** 成功しても対象は変わらない。
        let written =
            read && SetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION, descriptor).is_ok();
        let _ = CloseHandle(handle);
        written
    }
}

/// いま到達できるドライブ文字のルート（`C:\`・`D:\`…）を列挙する。
///
/// CoWの差分層がボリュームごとに散る（D-81）ため、棚卸し（`harness cow list`/`gc`）は
/// 1つの根ではなく**全ボリュームの根**を掃く必要がある。
pub fn logical_drive_roots() -> Vec<std::path::PathBuf> {
    use windows::Win32::Storage::FileSystem::GetLogicalDrives;
    let mask = unsafe { GetLogicalDrives() };
    (0..26u32)
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| std::path::PathBuf::from(format!("{}:\\", (b'A' + i as u8) as char)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `CREATE_UNICODE_ENVIRONMENT`は変数0件でも二重NUL終端を要求する。ループが1回も
    /// 回らない0件の場合に単一NULのままにならないことを固定する（実機で
    /// `CreateProcessAsUserW`が`ERROR_INVALID_PARAMETER`を返すことで発覚したバグの回帰）。
    #[test]
    fn empty_env_block_is_double_null_terminated() {
        assert_eq!(build_env_block(&[]), vec![0u16, 0u16]);
    }

    /// 変数1件以上の場合は既存通り、各変数の後ろのNULと末尾のNULで自然に二重終端になる。
    #[test]
    fn non_empty_env_block_ends_with_two_nulls_after_the_last_entry() {
        let block = build_env_block(&[("A".to_string(), "1".to_string())]);
        assert_eq!(block, "A=1\0\0".encode_utf16().collect::<Vec<u16>>());
    }

    /// エントリはキー名（大文字化して比較）でソートされる。
    #[test]
    fn env_block_entries_are_sorted_by_uppercased_key() {
        let block = build_env_block(&[
            ("b".to_string(), "2".to_string()),
            ("A".to_string(), "1".to_string()),
        ]);
        let joined = String::from_utf16(&block[..block.len() - 1]).unwrap();
        assert_eq!(joined, "A=1\0b=2\0");
    }

    fn long_path_string(path: &str) -> String {
        let wide = long_path_wide(std::path::Path::new(path));
        String::from_utf16_lossy(&wide[..wide.len() - 1])
    }

    /// `\\?\`はverbatimなので区切りが`\`でなければならない。設定ファイルへ`C:/foo`と書かれた
    /// パス（MCP宣言の`command`・`fs.allow`等）でACL付与が`ERROR_FILE_NOT_FOUND`にならないこと。
    #[test]
    fn forward_slashes_are_normalised_before_the_verbatim_prefix_is_added() {
        assert_eq!(
            long_path_string("C:/Users/me/tools/server.exe"),
            r"\\?\C:\Users\me\tools\server.exe"
        );
        assert_eq!(long_path_string(r"C:\Users\me"), r"\\?\C:\Users\me");
    }

    /// 既に`\\?\`が付いているパスは二重に付けない（`std::fs::canonicalize`の戻り値が来る経路）。
    #[test]
    fn an_already_verbatim_path_is_left_alone() {
        assert_eq!(long_path_string(r"\\?\C:\Users\me"), r"\\?\C:\Users\me");
        assert_eq!(
            long_path_string(r"\\?\C:/Users/me"),
            r"\\?\C:\Users\me",
            "a verbatim prefix with forward slashes is still broken; normalise it too"
        );
    }

    /// UNCパスは`\\?\UNC\`形式へ変換する（既存挙動の固定）。
    #[test]
    fn unc_paths_use_the_unc_verbatim_form() {
        assert_eq!(
            long_path_string(r"\\server\share\dir"),
            r"\\?\UNC\server\share\dir"
        );
    }

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

#[cfg(test)]
mod subst_resolution_tests {
    use super::apply_dos_device_target;

    /// `subst`で作った別名は、指している実体へ直す。**直さないと`GetVolumePathNameW`が
    /// 壊れた答えを返し、ボリュームの素性が判定不能になってCoWが起動できない**——
    /// しかも`preflight`は長いパスの回避策として`subst`を自分から勧めている。
    #[test]
    fn a_subst_drive_is_rewritten_onto_its_target() {
        assert_eq!(
            apply_dos_device_target(r"N:\proj\src", r"\??\C:\work\area").as_deref(),
            Some(r"C:\work\area\proj\src")
        );
        // ドライブ文字だけのときは実体そのもの。
        assert_eq!(
            apply_dos_device_target("N:", r"\??\C:\work\area").as_deref(),
            Some(r"C:\work\area")
        );
    }

    /// **本物のボリュームは書き換えない**（許可側と拒否側を対で測る）。ここが`Some`を返すと、
    /// 実在しないパスを作ってしまい、まともなドライブまで判定不能になる。
    #[test]
    fn real_volumes_and_network_drives_are_left_alone() {
        for device in [
            r"\Device\HarddiskVolume3",
            r"\Device\Volume{1d778159-9d29-11f1-8838-acf23c3508a0}",
            r"\Device\LanmanRedirector\;X:000000000004107c\server\share",
        ] {
            assert_eq!(
                apply_dos_device_target(r"X:\proj", device),
                None,
                "本物のボリュームを書き換えてはいけない: {device}"
            );
        }
    }
}
