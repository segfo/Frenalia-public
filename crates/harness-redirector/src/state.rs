//! フックの関数シグネチャ型・`Config`・プロセス内グローバル状態。
//!
//! Redirector DLLは注入先プロセス内で動くため、状態はプロセスごとの`static`として持つ。
//! ハンドル→パス対応表・削除保留集合・ディレクトリ列挙カーソル等はいずれもフック本体から
//! 参照されるため、ここに集約している。

use super::*;

/// `retour`が要求する生のNt関数シグネチャ。`windows`クレートの`Wdk`ラッパは実体が
/// `windows_targets::link!`経由のIAT呼び出しであり、ここでフックする対象（`ntdll.dll`の
/// エクスポート本体、`GetProcAddress`で取得したアドレス）とは別物。ABIが一致する生の
/// 関数ポインタ型として定義し直し、`GetProcAddress`のアドレスをこの型へtransmuteして使う。
pub(crate) type NtCreateFileFn = unsafe extern "system" fn(
    *mut HANDLE,
    FILE_ACCESS_RIGHTS,
    *const OBJECT_ATTRIBUTES,
    *mut IO_STATUS_BLOCK,
    *const i64,
    FILE_FLAGS_AND_ATTRIBUTES,
    FILE_SHARE_MODE,
    NTCREATEFILE_CREATE_DISPOSITION,
    NTCREATEFILE_CREATE_OPTIONS,
    *const c_void,
    u32,
) -> NTSTATUS;

pub(crate) type NtOpenFileFn = unsafe extern "system" fn(
    *mut HANDLE,
    u32,
    *const OBJECT_ATTRIBUTES,
    *mut IO_STATUS_BLOCK,
    u32,
    u32,
) -> NTSTATUS;

pub(crate) type NtSetInformationFileFn = unsafe extern "system" fn(
    HANDLE,
    *mut IO_STATUS_BLOCK,
    *const c_void,
    u32,
    FILE_INFORMATION_CLASS,
) -> NTSTATUS;

pub(crate) type NtCloseFn = unsafe extern "system" fn(HANDLE) -> NTSTATUS;

/// `GetFileAttributesExW`（ひいては.NETの`File.Exists`/`Directory.Exists`、PowerShellの
/// `Test-Path`）が使う、ハンドルを開かない属性照会。`NtCreateFile`/`NtOpenFile`とは別経路の
/// ため、これをフックしないと論理削除済みパスの`Test-Path`が実workspace側の実体を見て
/// `True`を返してしまう（実機E2Eで発見、設計書§19.7の読み取り時判定を完全にするための追加）。
pub(crate) type NtQueryFullAttributesFileFn = unsafe extern "system" fn(
    *const OBJECT_ATTRIBUTES,
    *mut windows::Wdk::Storage::FileSystem::FILE_NETWORK_OPEN_INFORMATION,
) -> NTSTATUS;

/// `GetFileAttributesW`（`NtQueryFullAttributesFile`より軽量な照会）が使う経路。`windows`クレートは
/// 安全ラッパを提供していないため、他のNt関数と同様`GetProcAddress`のアドレスを手動定義した
/// 関数ポインタ型へtransmuteして使う。
pub(crate) type NtQueryAttributesFileFn = unsafe extern "system" fn(
    *const OBJECT_ATTRIBUTES,
    *mut windows::Wdk::Storage::FileSystem::FILE_BASIC_INFORMATION,
) -> NTSTATUS;

/// ディレクトリ列挙（`FindFirstFile`/`FindNextFile`、.NETの`Directory.EnumerateFileSystemEntries`、
/// PowerShellの`Remove-Item`/`Test-Path`のパス解決層が最終的にたどり着く経路）。BUG-047:
/// このAPIだけ未フックだったため、セッション中に差分層側だけへ新規作成されたファイルが
/// ディレクトリ列挙結果に現れず、`Remove-Item`等が「存在しない」と誤判定していた
/// （個別パス指定の`NtCreateFile`/`NtQueryAttributesFile`等は元々正しく差分層優先だった）。
pub(crate) type NtQueryDirectoryFileFn = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    windows::Win32::System::IO::PIO_APC_ROUTINE,
    *const c_void,
    *mut IO_STATUS_BLOCK,
    *mut c_void,
    u32,
    FILE_INFORMATION_CLASS,
    windows::Win32::Foundation::BOOLEAN,
    *const windows::Win32::Foundation::UNICODE_STRING,
    windows::Win32::Foundation::BOOLEAN,
) -> NTSTATUS;

/// BUG-048（F3）: Windows 10 1709以降、`FindFirstFileEx`系の実際の経路は`NtQueryDirectoryFile`
/// ではなく`NtQueryDirectoryFileEx`（`RestartScan`/`ReturnSingleEntry`の2つのBOOLEAN引数の
/// 代わりに`QueryFlags: u32`を取る、`SL_RESTART_SCAN`/`SL_RETURN_SINGLE_ENTRY`ビット）。
pub(crate) type NtQueryDirectoryFileExFn = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    windows::Win32::System::IO::PIO_APC_ROUTINE,
    *const c_void,
    *mut IO_STATUS_BLOCK,
    *mut c_void,
    u32,
    FILE_INFORMATION_CLASS,
    u32,
    *const windows::Win32::Foundation::UNICODE_STRING,
) -> NTSTATUS;

/// Phase 4a（BUG-041修正後）: `kernel32!CreateProcessW`。`lpStartupInfo`
/// （`STARTUPINFOW`または`STARTUPINFOEXW`、レイアウトが呼び出し元次第で変わる）・
/// `lpProcessAttributes`/`lpThreadAttributes`/`lpEnvironment`は中身を一切解釈せず不透明
/// ポインタとしてそのままオリジナル関数へ渡す。唯一操作するのは独立したu32引数の
/// `dwCreationFlags`（`CREATE_SUSPENDED_FLAG`ビット）のみ（モジュールdoc参照）。
/// `lpProcessInformation`だけは戻り値読み取りのため`PROCESS_INFORMATION`として解釈する
/// （呼び出し元が非NULLを渡す前提はWin32 API仕様上保証されている）。
pub(crate) type CreateProcessWFn = unsafe extern "system" fn(
    PCWSTR,
    PWSTR,
    *const c_void,
    *const c_void,
    BOOL,
    u32,
    *const c_void,
    PCWSTR,
    *const c_void,
    *mut c_void,
) -> BOOL;

/// Phase 4a（BUG-041修正後）: `kernel32!CreateProcessAsUserW`。`CreateProcessWFn`と同型で、
/// 第1引数に`hToken`が追加されるだけ。
pub(crate) type CreateProcessAsUserWFn = unsafe extern "system" fn(
    HANDLE,
    PCWSTR,
    PWSTR,
    *const c_void,
    *const c_void,
    BOOL,
    u32,
    *const c_void,
    PCWSTR,
    *const c_void,
    *mut c_void,
) -> BOOL;

/// 残課題#5（Phase 4a以降）: `kernel32!CreateProcessA`。`CreateProcessWFn`と同じ引数個数・
/// 意味だが、文字列引数がANSI（`PCSTR`/`PSTR`）になる。`CreateProcessA`は内部で
/// `CreateProcessW`を経由せず直接`CreateProcessInternalW`（より下位の共通API）を呼ぶため
/// （一般的なWindows内部実装のknown-how、実装側のコードコメントとも符合）、既存の
/// `CreateProcessW`/`CreateProcessAsUserW`フックは`CreateProcessA`呼び出しを完全に素通しして
/// いた。同じ「オリジナルが完全に返った後に注入する」安全なタイミング（BUG-041の教訓）を
/// そのまま適用する。
pub(crate) type CreateProcessAFn = unsafe extern "system" fn(
    PCSTR,
    PSTR,
    *const c_void,
    *const c_void,
    BOOL,
    u32,
    *const c_void,
    PCSTR,
    *const c_void,
    *mut c_void,
) -> BOOL;

/// 残課題#5: `kernel32!WinExec`。`UINT WinExec(LPCSTR lpCmdLine, UINT uCmdShow)`。
/// `CreateProcessA`/`W`と違い`dwCreationFlags`も`lpProcessInformation`も呼び出し元へ一切
/// 公開しないため、この関数自身のシグネチャ経由では「suspendedで起動して孫へ注入してから
/// resumeする」ことができない。そのため`hooked_win_exec`は本物の`WinExec`を呼ばず、
/// 代わりに（フック済みの）`CreateProcessA`相当のロジック（`hooked_create_process_a`関数を
/// 直接呼ぶ、`GenericDetour::call`＝オリジナル関数呼び出しではない点に注意）を自前で実行し、
/// 得られた`PROCESS_INFORMATION`を注入に使ってから、WinExecの戻り値規約（成功時は32より
/// 大きい値、失敗時はエラーコード相当の32以下の値）に変換する。
pub(crate) type WinExecFn = unsafe extern "system" fn(PCSTR, u32) -> u32;

/// Win32 `PROCESS_CREATION_FLAGS`の`CREATE_SUSPENDED`ビット（`windows`クレートの
/// `windows::Win32::System::Threading::CREATE_SUSPENDED`と同値だが、フック関数の引数型が
/// 生の`u32`のためリテラルとして持つ）。
pub(crate) const CREATE_SUSPENDED_FLAG: u32 = 0x0000_0004;

pub(crate) struct Config {
    /// ワークスペースのルート。**空のことがある**——[`Config::process_hooks`]だけを理由に
    /// 注入された相手（MCPサーバ）にはワークスペースが無い。空のときは
    /// **ファイル系フックを1つも設置しない**（何がworkspace内かを判定できないまま
    /// 分類すると、`docs/bugs/BUG-066.md`と同じ「全部の照合が外れる」状態になる）。
    pub(crate) workspace_root: PathBuf,
    /// CoWの差分層。**`cow_enabled`が偽のときは空**（[D-88（`DESIGN-SANDBOX-APPPOLICY.md`）]の
    /// DirectRwレーンには差分層が無い）。空のまま誘導へ使わないよう、参照する箇所は
    /// すべて`cow_enabled`の内側に置くこと。
    pub(crate) diff_layer_dir: PathBuf,
    /// CoWの誘導（書込のcopy-up・読取のread-through・ディレクトリのマージ）を行うか。
    ///
    /// **偽のとき、フックは成功経路で何も判定しない。** これは費用の要求である
    /// （`plans/mac-spike/RESULTS.md` §S25の実測: 差分層の有無を見に行く分類を
    /// openの前に置くと1回あたり+28.3 µs、後ろに置けば+1.4 µs。§S21の回数を掛けると
    /// **毎セッション4〜6秒 対 0.2〜0.3秒**で、消せるのは初回の待ちだけなので
    /// 前者だと数セッションで元本を割る）。**CoWの分類をDirectRwへ持ち込まないこと。**
    pub(crate) cow_enabled: bool,
    /// [D-88] fault要求の受付パイプ名。`Some`のとき、`ACCESS_DENIED`で返ったopenを
    /// **1回だけ**やり直す（`fault_in`）。`None`なら何もしない（今日と同じ挙動）。
    ///
    /// **名前は秘密ではない**（子から`\\.\pipe\`の一覧は取れる）。守るのはパイプのDACLで、
    /// これを知っていても capability SID を積んでいない子は接続すらできない。
    pub(crate) broker_pipe: Option<String>,
    /// Phase 3（設計書§19.8）: `--fs-allow <path>:rw`で実際にACE付与できたworkspace外RW穴の
    /// ルート一覧（DOS形式、正規化前）。ここに含まれるパスへの書込は、workspace内と同じ
    /// `_ext/<key>`経由の操作台帳captureの対象になる（境界＝ACLはfs-allowが既に張っている、
    /// ここはあくまで透過性・変更の可視化のためのcaptureであってACL自体を変えない）。
    pub(crate) ext_capture_roots: Vec<PathBuf>,
    /// **プロセス生成フックを置くこと自体が目的である**（段階5b、
    /// `plans/DESIGN-MAC-ENFORCEMENT.md` §8.1）。
    ///
    /// # なぜ「何も誘導しないのに注入する」が要るのか
    ///
    /// 段階⑤で`CHILD_PROCESS_RESTRICTED`（OSが子プロセス生成そのものを拒否する緩和策）を
    /// 積むと、サンドボックスの中のプログラムは自力で子を作れなくなる。代わりに
    /// Spawn Daemonへ頼む形になり、**その頼み方へ変換するのがこのフックである**。
    /// したがって**フックが入っていないプロセスが1つでも居る状態で⑤を積むことはできない**
    /// ——そのプロセスは子を作ることも頼むこともできなくなる。
    ///
    /// # 真のとき、CoWの誘導もfault受付も無ければファイル系フックは設置しない
    ///
    /// あの7本は`NtCreateFile`等の呼び出しすべてを経由させる。誘導も受付も無ければ
    /// **素通りするだけの回り道**なので、置けば費用だけが残る。
    ///
    /// # 真であること「だけ」が注入の理由なら、フックの設置失敗は致命である
    ///
    /// 他に何もしないDLLが「入ったが何もしていない」状態で成功を返すと、
    /// ⑤を積んだ日に**そのプロセスだけが静かに子を作れなくなる**
    /// （`.claude/skills/bug-pattern-rules`の方式4が招く型そのもの）。
    pub(crate) process_hooks: bool,
}

/// 孫プロセスへの再注入が失敗した/初期化未完了だった場合の警告台帳ファイル名
/// （`<diff_layer_dir>/.harness-cow-warnings.jsonl`、Q6）。操作台帳（`COW_OPS_LEDGER_FILENAME`）とは
/// 別ファイルにする——こちらは「透過性が欠けている」という注意喚起であり、`ChangeOp`の
/// 型を汚さないため。
pub(crate) const COW_WARNINGS_LEDGER_FILENAME: &str = ".harness-cow-warnings.jsonl";

#[derive(serde::Serialize)]
pub(crate) struct CowWarningEntry<'a> {
    pub(crate) kind: &'a str,
    pub(crate) message: &'a str,
    pub(crate) ts_unix_millis: u128,
}

pub(crate) static CONFIG: OnceLock<Config> = OnceLock::new();
pub(crate) static CREATE_FILE_HOOK: OnceLock<GenericDetour<NtCreateFileFn>> = OnceLock::new();
pub(crate) static OPEN_FILE_HOOK: OnceLock<GenericDetour<NtOpenFileFn>> = OnceLock::new();
pub(crate) static SET_INFO_HOOK: OnceLock<GenericDetour<NtSetInformationFileFn>> = OnceLock::new();
pub(crate) static CLOSE_HOOK: OnceLock<GenericDetour<NtCloseFn>> = OnceLock::new();
pub(crate) static QUERY_FULL_ATTR_HOOK: OnceLock<GenericDetour<NtQueryFullAttributesFileFn>> =
    OnceLock::new();
pub(crate) static QUERY_ATTR_HOOK: OnceLock<GenericDetour<NtQueryAttributesFileFn>> =
    OnceLock::new();
pub(crate) static QUERY_DIR_HOOK: OnceLock<GenericDetour<NtQueryDirectoryFileFn>> = OnceLock::new();
pub(crate) static QUERY_DIR_EX_HOOK: OnceLock<GenericDetour<NtQueryDirectoryFileExFn>> =
    OnceLock::new();
pub(crate) static CREATE_PROCESS_W_HOOK: OnceLock<GenericDetour<CreateProcessWFn>> =
    OnceLock::new();
pub(crate) static CREATE_PROCESS_AS_USER_W_HOOK: OnceLock<GenericDetour<CreateProcessAsUserWFn>> =
    OnceLock::new();
pub(crate) static CREATE_PROCESS_A_HOOK: OnceLock<GenericDetour<CreateProcessAFn>> =
    OnceLock::new();
pub(crate) static WIN_EXEC_HOOK: OnceLock<GenericDetour<WinExecFn>> = OnceLock::new();

/// このDLL自身がロードされているモジュールベースアドレス（`DllMain`の`hinst`引数、数値上は
/// そのプロセスにおけるロードベースアドレスと一致する——Windowsの仕様）。孫プロセス内での
/// 自DLLの相対オフセット（RVA）を、自プロセスの`GetProcAddress`結果から逆算するために使う
/// （Phase 4a、`inject_grandchild`参照）。
pub(crate) static SELF_MODULE: OnceLock<usize> = OnceLock::new();

/// `init()`の同時実行を防ぐ。孫プロセスでは`DllMain`の`DLL_PROCESS_ATTACH`が自動的に起動する
/// 内部初期化スレッドと、Launcher役の親プロセス側から`CreateRemoteThread`で明示的に呼ばれる
/// `harness_cow_init`エクスポートの2経路が同一プロセス内で競合し得るため直列化する
/// （Phase 4a、モジュールdoc参照）。
///
/// BUG-045: 以前は`std::sync::Once`だったが、**失敗した初期化まで確定させてしまう**ため
/// `Mutex`+[`INIT_SUCCEEDED`]へ置き換えた。`DllMain`側のスレッド（設定を環境変数からしか
/// 取れない）が先に走って失敗しても、後から来る`harness_cow_init`（注入パラメータで設定を
/// 直接受け取れる、F2）が再試行できる必要がある。成功は冪等に一度だけ確定する。
pub(crate) static INIT_LOCK: Mutex<()> = Mutex::new(());

/// `init()`が最後まで成功（6つのファイルフック設置完了）したか。`harness_cow_init`の戻り値
/// そのものであり、注入側（`inject_grandchild`／`wow64::remote_call_init`）が
/// `GetExitCodeThread`で読む唯一の成否シグナルになる（BUG-045のF1）。
pub(crate) static INIT_SUCCEEDED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// ハンドル値→workspace相対パス（`/`区切り）。`NtClose`で確実に取り除く（際限なく膨らまない
/// ようにする、設計書§19.6）。
pub(crate) fn handle_paths() -> &'static Mutex<HashMap<isize, String>> {
    static M: OnceLock<Mutex<HashMap<isize, String>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 削除予定（`FileDispositionInformation`のDeleteFile=TRUE、または`FILE_DELETE_ON_CLOSE`）の
/// ハンドル集合。フラグが後から取り消されれば除去する（設計書§19.6）。
pub(crate) fn delete_pending() -> &'static Mutex<HashSet<isize>> {
    static S: OnceLock<Mutex<HashSet<isize>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashSet::new()))
}

/// ディレクトリハンドル値→マージ済み列挙の再開カーソル（BUG-047）。`NtQueryDirectoryFile`は
/// 同一ハンドルに対し`RestartScan=FALSE`で繰り返し呼ばれてページングするため、次に返す
/// マージ済みエントリの先頭インデックスをハンドルごとに覚えておく必要がある
/// （`handle_paths`と同じくハンドル値をキーにする一時マップ、`NtClose`で確実に取り除く）。
/// マージ結果自体は毎回`std::fs::read_dir`から再計算するため、呼び出しの合間にディレクトリの
/// 中身が変化すると位置がずれ得るが、これは許容する既知の簡略化とする（同期的な単一セッション
/// 内での列挙という想定スコープでは実害が薄い）。
pub(crate) fn dir_query_cursor() -> &'static Mutex<HashMap<isize, usize>> {
    static C: OnceLock<Mutex<HashMap<isize, usize>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// パスごとの「このセッションで最初に触った瞬間の実workspace側ハッシュ」キャッシュ
/// （`None`＝新規作成）。baselineは「セッションが触る前の姿」を意味するため、2回目以降の
/// 操作では初回に記録した値をそのまま複製する（設計書§19.5）。
pub(crate) fn baseline_cache() -> &'static Mutex<HashMap<String, Option<String>>> {
    static C: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 現在「論理的に削除済み」のworkspace相対パス集合（設計書§19.7）。DLL初期化時に既存の
/// 台帳を再生して組み立て、以降はこのDLLがフックした操作でその都度更新する。
///
/// Phase 4a（孫プロセスへの再注入）により、同じ台帳へ複数プロセス（兄弟）が並行して追記し得る
/// ようになったため、自プロセスが起こしていない削除（兄弟プロセスが起こした削除）もここへ
/// 反映する必要がある。`refresh_deleted_set`が増分tail再読込でこれを行う（設計書§19.2）。
pub(crate) fn deleted_paths_state() -> &'static Mutex<HashSet<String>> {
    static D: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    D.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Phase 4: 既にこのプロセスで`.harness-cow-denied.jsonl`へ記録済みのパス集合（同一パスへの
/// 繰り返し拒否試行で台帳が肥大しないようにする、プロセス内のみのdedup——別プロセス/セッションで
/// 再度記録され得るが実害は無い）。
pub(crate) fn denied_paths_state() -> &'static Mutex<HashSet<String>> {
    static D: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    D.get_or_init(|| Mutex::new(HashSet::new()))
}

/// ACLで実際に拒否された（`STATUS_ACCESS_DENIED`）workspace外書込試行を
/// `<diff_layer_dir>/.harness-cow-denied.jsonl`へ1行追記する（Phase 4、設計書§19.8）。
/// 同一パスは初回のみ記録する。追記の実体は`store::append_denied_entry`
/// （`harness cow audit`の読み側と型を共有、host側で拒否を検知する経路が将来できても
/// 同じ形式で書けるようにするため）。
pub(crate) fn record_denied_attempt(cfg: &Config, path: &Path, access_mask: u32) {
    let path_str = path.to_string_lossy().replace('\\', "/");
    {
        let mut g = denied_paths_state().lock().unwrap();
        if !g.insert(path_str.clone()) {
            return;
        }
    }
    let pid = unsafe { GetCurrentProcessId() };
    store::append_denied_entry(&cfg.diff_layer_dir, &path_str, access_mask, pid);
}

/// BUG-066: 差分層配下の実体へ直接書かれたパスのうち、既にこのプロセスが台帳へ記録済みの集合
/// （`record_diff_layer_alias_write`の冪等化。`copy_up`の`diff_layer_path.exists()`と同じ役割を果たす）。
pub(crate) fn diff_layer_alias_first_touch(rel: &str) -> bool {
    static S: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .unwrap()
        .insert(rel.to_string())
}

/// `deleted_paths_state`を最後に同期した時点での台帳ファイルの読み込み済みバイトオフセット。
pub(crate) fn ledger_read_offset() -> &'static Mutex<u64> {
    static O: OnceLock<Mutex<u64>> = OnceLock::new();
    O.get_or_init(|| Mutex::new(0))
}
