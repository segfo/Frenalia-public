//! **E2E専用**: 昇格した`dev-elevated-runnerd`から`harness-privhelper.exe`を起こすブローカー。
//!
//! # なぜ在るか
//!
//! `harness.exe`の起動シーケンスは「自分が昇格しているか」で二手に分かれ、**本番が通るのは
//! 非昇格の枝**である——preflightがprivhelperへ委譲し、privhelperが`harness-netfilterd`を
//! 連鎖起動する（シナリオ(A)）。従来のE2Eは`dev-elevated-runnerd`配下で走るのでharness本体まで
//! 昇格が継承され、構造的にもう一方の枝（本体が自分でnetfilterdを起こす＝シナリオ(B)）しか
//! 通らない。BUG-111で見つかった「WFPが立たなかったときの説明が実挙動の逆」だった文言が
//! シナリオ(A)側にあり、誰にも当たらないまま残っていたのはこのためである。
//!
//! テストとharnessを**非昇格のまま**走らせ、**privhelperの昇格だけ**をこのブローカーへ
//! 肩代わりさせれば、E2E中のUACを0回に保ったまま本番と同じ枝を通せる
//! （`plans/PLAN-NONELEVATED-E2E.md`）。
//!
//! # 縛り（3つ揃って初めて起動する）
//!
//! | 縛り | 何を防ぐか | 実装 |
//! |---|---|---|
//! | ディレクトリは`C:\harness-e2e\`の**配下**のみ。ファイル名は固定でクライアントは選べない | 任意パスの管理者実行 | [`resolve_launcher_dir`]・[`candidate_exe_path`] |
//! | 中身が`target\debug\harness-privhelper.exe`と**バイト一致** | `C:\harness-e2e\`はAuthenticated Users書込可なので、名前だけ借りた別のバイナリが管理者で走る | [`launch`] |
//! | パイプ名は`unique_pipe_name("privhelper")`が作る形だけ | 昇格プロセスが任意の名前を`CreateFileW`で開く（`is_harness_pipe_name`と同じ理由、P-01） | [`validate_pipe_name`] |
//!
//! **配置DACLの検査（D-44、`harness_sandbox::elevated_launch::verify_elevation_target`）は
//! ここでは使えない**——`C:\harness-e2e\`はユーザー書込可なので必ず拒否になる。代わりに置いたのが
//! バイト一致で、これは「いま開発者がビルドしたprivhelperと同じものか」を見る。
//!
//! # 検証は受信側（＝ここ）で行う
//!
//! 要求を組み立てるのは非昇格のharness側で、そちらは攻撃者と同じ権限で動きうる（P-01）。
//! クライアントが同じ関数を呼んでいるかどうかに関わらず、**起動する側が独立に全部を検査する**
//! （`validate_target`と`resolve_target_args`が同じ完全一致を二重に行っているのと同じ理由）。
//!
//! # 逃がし弁の注入を落とすと、E2Eは緑のまま何も測らなくなる
//!
//! privhelperはモックのnetfilterdを連鎖起動する前に配置DACLを検査する（D-44）ので、
//! `C:\harness-e2e\`からの連鎖起動は必ず引っ掛かる。この検査が見るのは**検査する側の
//! プロセスの環境変数**なので、ここでprivhelperの環境へ
//! [`ALLOW_USER_WRITABLE_HELPERS_ENV`](harness_sandbox::elevated_launch::ALLOW_USER_WRITABLE_HELPERS_ENV)
//! を渡さないと連鎖起動が拒否され、`netfilterd_chain_attempted`が偽になり、E2Eは
//! **シナリオ(B)へ落ちたまま緑になる**（＝何も測っていないのに成功に見える、B-09）。
//! 注入は[`privhelper_command`]が持ち、単体テストが名指しで固定している。
//!
//! # D-60の緩和ではない
//!
//! D-60（`plans/DESIGN-SANDBOX-PRIVSEP.md`）は「連鎖起動の対象は固定名のみ・親から任意パスを
//! 受け取らない・D-44の配置検査は落とさない」と定めるが、それが掛かるのは**製品コード**
//! （`harness-privhelper`が`harness-netfilterd`を起こす経路）である。ここは
//! `dev-elevated-runner`という**開発専用ツール**で、しかもこのデーモンは既に「repo rootで
//! `cargo`を昇格実行する」＝リポジトリへ書ける者へ管理者コード実行を与えている。
//! 前提条件の種類が変わらないのでD-60は変わらない。
//! **本モジュールをD-60緩和の前例として読まないこと。**

use crate::PrivhelperLaunchRequest;
use std::path::{Path, PathBuf};

/// 起動を許すディレクトリの根。**この配下だけ**（根そのものは対象外）。
///
/// 綴りはE2E側の`CASE_ROOT`（`crates/harness-cli/tests/tier2a_e2e.rs`）と同じ場所を指すが、
/// あちらはテストのワークスペース置き場、こちらは**起動を許す範囲**という別の役割なので
/// 定数を共有しない（同じ文字列でも意味が違うものを1つにすると、片方の都合で動かせなくなる）。
pub const LAUNCH_ROOT: &str = r"C:\harness-e2e";

/// 起動する実行ファイルの名前。**クライアントは名前を選べない**（送れるのはディレクトリだけ）。
/// 綴りの正本は`harness-sandbox`側にあり、ここでは複製しない（B-05）。
pub const PRIVHELPER_EXE_NAME: &str = harness_sandbox::tier2a::privhelper::HELPER_EXE_NAME;

/// 受理するパイプ名の接頭辞。`harness-sandbox`の接頭辞に、privhelperの部品名を足したもの。
///
/// `unique_pipe_name("privhelper")`が作る形と一致することは単体テストが固定する
/// （両者が同じ規則を見ていることを、綴りではなく**実際に生成させて**確かめる）。
pub fn privhelper_pipe_prefix() -> String {
    format!(
        "{}privhelper-",
        harness_sandbox::win_pipe_ipc::HARNESS_PIPE_PREFIX
    )
}

/// パイプ名の形を検証する（縛り3）。
///
/// 起こされたprivhelperはこの名前を`CreateFileW`で開いて応答を書き込むので、任意の名前を
/// 通すと「昇格プロセスが呼び出し側の選んだ先へ書き込む」プリミティブになる。**名前付きパイプに
/// 見えない普通のファイルパスも`CreateFileW`は開ける**（`is_harness_pipe_name`のdoc参照）。
pub fn validate_pipe_name(name: &str) -> Result<(), String> {
    // 形の下限（接頭辞・区切り文字・印字可能ASCII・長さ）は`harness-sandbox`の判定を
    // そのまま使う。同じ規則を2つ持たない（B-05）。
    if !harness_sandbox::win_pipe_ipc::is_harness_pipe_name(name) {
        return Err(format!(
            "refusing to launch the privilege-separation helper: {name:?} is not a harness pipe \
             name (expected {}<component>-...)",
            harness_sandbox::win_pipe_ipc::HARNESS_PIPE_PREFIX
        ));
    }
    let prefix = privhelper_pipe_prefix();
    if !name.starts_with(&prefix) {
        return Err(format!(
            "refusing to launch the privilege-separation helper: {name:?} is a harness pipe but \
             not a privhelper pipe (expected a name starting with {prefix:?})"
        ));
    }
    Ok(())
}

/// パス文字列を「小文字化した構成要素の並び」へ落とす。
///
/// **受理する形を絞るための正規化**であって、一般のWindowsパスを扱う関数ではない。
/// 受け付けるのは`X:\...`（`canonicalize`が返すverbatim形`\\?\X:\...`を含む）だけで、
/// UNC・ドライブ相対（`C:foo`）・`.`・`..`・予約文字を含む要素は**すべて拒否**する。
/// `Path::components`を使わず自前で分解しているのは、この判定が
/// 「Windowsのパス解釈」ではなく「通す形の許可リスト」だからである（非Windowsでも同じ結果になる）。
fn path_elements(path: &Path) -> Result<Vec<String>, String> {
    let raw = path.to_string_lossy();
    let raw: &str = raw.strip_prefix(r"\\?\").unwrap_or(raw.as_ref());
    let bytes = raw.as_bytes();
    let absolute_on_a_local_drive = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/');
    if !absolute_on_a_local_drive {
        return Err(format!(
            "{raw:?} is not an absolute path on a local drive (expected something like \
             {LAUNCH_ROOT}\\<dir>)"
        ));
    }
    let mut elements = vec![raw[..2].to_ascii_lowercase()];
    for part in raw[3..].split(['\\', '/']) {
        if part.is_empty() {
            continue; // 区切りの重なり・末尾の`\`
        }
        if part == "." || part == ".." {
            return Err(format!("{raw:?} contains a relative element ({part:?})"));
        }
        if part.contains([':', '*', '?', '"', '<', '>', '|']) {
            return Err(format!(
                "{raw:?} contains a component with a reserved character ({part:?})"
            ));
        }
        elements.push(part.to_ascii_lowercase());
    }
    Ok(elements)
}

/// `child`が`root`の**厳密な配下**か（根そのものは配下ではない）。
///
/// 構成要素の並びで比べるので、`C:\harness-e2e-evil`が`C:\harness-e2e`の配下に見える
/// 前方一致の事故は起きない（BUG-066型の取り違えを構造で排除する）。
fn is_strictly_under(child: &[String], root: &[String]) -> bool {
    child.len() > root.len() && child[..root.len()] == *root
}

/// **純粋な形の検査**（縛り1の前半）: `C:\harness-e2e\`の配下を指す絶対パスか。
///
/// ファイルシステムを一切見ないので、存在しないパス・偽装されたパスもここで落ちる。
/// 実体の解決（reparse point）は[`resolve_launcher_dir`]が続けて行う。
pub fn validate_launcher_dir_shape(dir: &Path) -> Result<(), String> {
    let root =
        path_elements(Path::new(LAUNCH_ROOT)).expect("LAUNCH_ROOT is a well-formed absolute path");
    let elements = path_elements(dir).map_err(|reason| {
        format!("refusing to launch the privilege-separation helper: {reason}")
    })?;
    if !is_strictly_under(&elements, &root) {
        return Err(format!(
            "refusing to launch the privilege-separation helper from {}: the launcher directory \
             must be strictly under {LAUNCH_ROOT}",
            dir.display()
        ));
    }
    Ok(())
}

/// 形を検査し、実体（junction/symlinkの解決後）でももう一度検査して、解決済みのパスを返す
/// （縛り1）。
///
/// 解決後にもう一度見るのは、`C:\harness-e2e\`が**ユーザー書込可**だからである——
/// そこへ`C:\Windows\System32`を指すjunctionを作れば、形の検査だけなら通ってしまう。
/// 根自身がjunctionである場合に備えて、根も解決してから比べる。
pub fn resolve_launcher_dir(dir: &Path) -> Result<PathBuf, String> {
    validate_launcher_dir_shape(dir)?;

    let resolved = dir.canonicalize().map_err(|e| {
        format!(
            "refusing to launch the privilege-separation helper from {}: the launcher directory \
             could not be resolved ({e})",
            dir.display()
        )
    })?;
    if !resolved.is_dir() {
        return Err(format!(
            "refusing to launch the privilege-separation helper from {}: it is not a directory",
            dir.display()
        ));
    }
    let resolved_root = Path::new(LAUNCH_ROOT).canonicalize().map_err(|e| {
        format!("refusing to launch the privilege-separation helper: {LAUNCH_ROOT} could not be resolved ({e})")
    })?;

    let elements = path_elements(&resolved)?;
    let root_elements = path_elements(&resolved_root)?;
    if !is_strictly_under(&elements, &root_elements) {
        return Err(format!(
            "refusing to launch the privilege-separation helper from {}: it resolves to {}, which \
             is outside {LAUNCH_ROOT}",
            dir.display(),
            resolved.display()
        ));
    }
    Ok(resolved)
}

/// 起動する実行ファイルのパス。**名前は固定**（縛り1の後半）。
pub fn candidate_exe_path(launcher_dir: &Path) -> PathBuf {
    launcher_dir.join(PRIVHELPER_EXE_NAME)
}

/// バイト一致の相手（縛り2）。デーモンが自分のrepo rootから引くので、クライアントは指せない。
pub fn reference_exe_path(repo_root: &Path) -> PathBuf {
    repo_root
        .join("target")
        .join("debug")
        .join(PRIVHELPER_EXE_NAME)
}

/// privhelperを起こすコマンドを組み立てる（**起動はしない**——単体テストが中身を検査できるように、
/// 組み立てと実行を分ける）。
///
/// 逃がし弁の注入がここに在る。落とすと連鎖起動がD-44のゲートで拒否され、E2Eは
/// シナリオ(B)へ落ちたまま緑になる（モジュールdoc参照）。
pub fn privhelper_command(exe: &Path, pipe_name: &str) -> std::process::Command {
    let mut command = std::process::Command::new(exe);
    command.arg(pipe_name);
    command.env(
        harness_sandbox::elevated_launch::ALLOW_USER_WRITABLE_HELPERS_ENV,
        "1",
    );
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // 既に昇格しているデーモンからの通常の起動なので、トークンはそのまま子へ継承される
        // （UACは出ない）。コンソール窓を出さないのは、E2Eの最中に窓が瞬くのを防ぐため
        // （`launch_netfilterd_chained`の`SW_HIDE`と同じ意図）。
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

/// 書込・削除・改名を**他のプロセスへ許さずに**開く。
///
/// 共有モードから`FILE_SHARE_WRITE`と`FILE_SHARE_DELETE`を落とすと、このハンドルを持っている
/// 間は誰もその実行ファイルを書き換えられず、消すことも改名することもできない。
/// **バイト一致の検査（縛り2）は、これが無いと検査と起動の間の差し替えで無意味になる**
/// （`C:\harness-e2e\`は誰でも書けるので、この隙間は机上の話ではない）。
///
/// 掴んだまま`CreateProcess`できるのは、共有規則が実行を**読み取り扱い**にするためである
/// ——`FILE_SHARE_READ`だけ許していれば、イメージのマップは通る。この前提は
/// `a_locked_executable_can_still_be_started_but_not_overwritten`が実機で確かめている。
#[cfg(windows)]
fn open_without_write_sharing(path: &Path) -> Result<std::fs::File, String> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x0000_0001;

    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|e| {
            format!(
                "refusing to launch the privilege-separation helper: {} could not be opened ({e})",
                path.display()
            )
        })
}

/// 起動対象を掴んだうえで、その中身が`reference`と**バイト一致**することを確かめる（縛り2）。
///
/// 成功したら**掴んだままのハンドル**を返す。呼び出し側はこれを起動が済むまで持ち続ける
/// ——検査した実体と起動する実体が同じであることは、このハンドルだけが保証している。
#[cfg(windows)]
fn open_verified_copy(candidate: &Path, reference: &Path) -> Result<std::fs::File, String> {
    use std::io::Read;

    // **掴んでから比べる**（比べてから掴むと、その間に差し替えられる）。
    let mut handle = open_without_write_sharing(candidate)?;
    let mut candidate_bytes = Vec::new();
    handle.read_to_end(&mut candidate_bytes).map_err(|e| {
        format!(
            "refusing to launch the privilege-separation helper: {} could not be read ({e})",
            candidate.display()
        )
    })?;
    let reference_bytes = std::fs::read(reference).map_err(|e| {
        format!(
            "refusing to launch {}: the reference build {} could not be read ({e}). Build it first \
             with `cargo build -p harness-privhelper`",
            candidate.display(),
            reference.display()
        )
    })?;
    if candidate_bytes != reference_bytes {
        return Err(format!(
            "refusing to launch {}: its contents do not match {} ({} vs {} bytes). {LAUNCH_ROOT} \
             is writable by any authenticated user, so only a byte-for-byte copy of the build \
             tree's helper is accepted -- copy it again after rebuilding",
            candidate.display(),
            reference.display(),
            candidate_bytes.len(),
            reference_bytes.len()
        ));
    }
    Ok(handle)
}

/// 要求を検査して`harness-privhelper.exe`を昇格したまま起こし、そのPIDを返す。
///
/// **終了を待たない。** privhelperは「親（＝非昇格のharness本体）から要求を受信する」ことを
/// 待っており、親はこのブローカーの応答を受け取ってから要求を送る。ここで終了を待つと
/// 「ブローカーはprivhelper待ち・privhelperは親待ち・親はブローカー待ち」の循環になる
/// （同じ形の実機デッドロックが`run_privileged_raw`のコメントに記録されている）。
#[cfg(windows)]
pub fn launch(request: &PrivhelperLaunchRequest, repo_root: &Path) -> Result<u32, String> {
    validate_pipe_name(&request.pipe_name)?;
    let launcher_dir = resolve_launcher_dir(&request.launcher_dir)?;
    let candidate = candidate_exe_path(&launcher_dir);
    let reference = reference_exe_path(repo_root);
    let handle = open_verified_copy(&candidate, &reference)?;

    let child = privhelper_command(&candidate, &request.pipe_name)
        .spawn()
        .map_err(|e| {
            format!(
                "failed to launch the privilege-separation helper {}: {e}",
                candidate.display()
            )
        })?;
    let pid = child.id();
    // 起動が済んだら掴みを解く（差し替えを防ぎたい区間は「検査〜起動」だけ）。
    drop(handle);
    // `Child`を落としてもプロセスは走り続ける（Windowsのstdは`Drop`でkillしない）。
    // 終了は親とのIPCが終わったときにprivhelper自身が行う。
    drop(child);
    Ok(pid)
}

/// **非昇格側から**このブローカーへ1件だけ要求を送る（`ChainLauncher`の実体になる側）。
///
/// デーモンが居なければ即座に`Err`を返す——**自分では起こさない**。起こす設計にすると、
/// これを使うE2EがUACを誘発し得るテストになり、背景実行できなくなる
/// （`plans/PLAN-NONELEVATED-E2E.md`段階3）。`Err`を受けた呼び出し側は、既存の
/// 「連鎖起動できなければ`runas`へ落ちる」経路（D-60）へそのまま進む。
///
/// 宛先は`\\.\pipe\dev-elevated-runner-<現在ユーザーのSID>`という決定的な名前なので、
/// 環境変数もフラグも要らない。
#[cfg(windows)]
pub fn request_privhelper_launch(pipe_name: &str, launcher_dir: &Path) -> Result<(), String> {
    use crate::win::{pipe_name_for_current_user, read_framed_timeout, wide, write_framed_timeout};
    use crate::{RunRequest, RunResponse};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_MODE, OPEN_EXISTING,
    };

    const REQUEST_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    // ブローカーがやるのは検査と`spawn`だけなので、`cargo`を回す既存の要求と違って短くてよい。
    const RESPONSE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

    let daemon_pipe = pipe_name_for_current_user()
        .map_err(|e| format!("failed to resolve the dev-elevated-runnerd pipe name: {e}"))?;
    let daemon_pipe_w = wide(&daemon_pipe);
    // 接続できない＝デーモンが居ない、または別の要求を処理中（このパイプは同時1接続）。
    let pipe = unsafe {
        CreateFileW(
            PCWSTR(daemon_pipe_w.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            Default::default(),
            None,
        )
    }
    .map_err(|e| {
        format!(
            "could not connect to dev-elevated-runnerd ({daemon_pipe}): {e}. Start it once with \
             `dev-elevated-run.exe <target>` (one UAC prompt), or expect the caller to fall back \
             to its own elevation"
        )
    })?;

    let request = RunRequest::LaunchPrivhelper(PrivhelperLaunchRequest {
        pipe_name: pipe_name.to_string(),
        launcher_dir: launcher_dir.to_path_buf(),
    });
    let exchange = (|| -> Result<RunResponse, String> {
        let request_bytes = serde_json::to_vec(&request)
            .map_err(|e| format!("failed to serialize the launch request: {e}"))?;
        write_framed_timeout(pipe, &request_bytes, REQUEST_WRITE_TIMEOUT)
            .map_err(|e| format!("failed to send the launch request: {e}"))?;
        let response_bytes = read_framed_timeout(pipe, RESPONSE_READ_TIMEOUT).map_err(|e| {
            format!(
                "failed to read the launch response: {e} (a dev-elevated-runnerd from an older \
                 build does not understand this request -- stop it and rebuild)"
            )
        })?;
        serde_json::from_slice(&response_bytes)
            .map_err(|e| format!("failed to parse the launch response: {e}"))
    })();
    unsafe {
        let _ = CloseHandle(pipe);
    }

    let response = exchange?;
    if response.exit_code != 0 {
        return Err(response.stderr.trim().to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 実際に`unique_pipe_name`が作る名前が通ること（**許可側**）。綴りを写して比べるのではなく
    /// 生成させて確かめる——写した綴りは、生成側が変わったときに一緒に変わらない（B-05）。
    #[test]
    fn a_pipe_name_produced_by_the_helper_is_accepted() {
        let name = harness_sandbox::win_pipe_ipc::unique_pipe_name("privhelper");
        validate_pipe_name(&name).unwrap_or_else(|e| panic!("{name} must be accepted: {e}"));
    }

    /// 他の形は通さない（**禁止側**）。とくに「harnessのパイプではあるが別の部品のもの」は、
    /// 接頭辞だけの検査では素通りする。
    #[test]
    fn pipe_names_of_any_other_shape_are_rejected() {
        for name in [
            harness_sandbox::win_pipe_ipc::unique_pipe_name("netfilterd"), // 別の部品
            r"\\.\pipe\harness-".to_string(),                              // 接頭辞だけ
            r"\\.\pipe\privhelper-1".to_string(),                          // 接頭辞が違う
            r"C:\Windows\System32\evil.txt".to_string(),                   // ただのファイル
            r"\\.\pipe\harness-privhelper-..\..\evil".to_string(),         // 区切り文字入り
            r"\\evil-host\pipe\harness-privhelper-1".to_string(),          // 別ホスト
            String::new(),
        ] {
            assert!(
                validate_pipe_name(&name).is_err(),
                "{name:?} must be rejected"
            );
        }
    }

    /// `C:\harness-e2e\`の配下は通る（**許可側**、形の検査のみ）。
    #[test]
    fn a_directory_under_the_launch_root_is_accepted_by_shape() {
        for dir in [
            r"C:\harness-e2e\scenarioA",
            r"C:\harness-e2e\scenarioA\12345",
            r"c:\HARNESS-E2E\ScenarioA",     // 大小は区別しない
            r"C:/harness-e2e/scenarioA",     // 区切りの揺れ
            r"C:\harness-e2e\scenarioA\",    // 末尾の区切り
            r"\\?\C:\harness-e2e\scenarioA", // canonicalizeが返す形
        ] {
            validate_launcher_dir_shape(Path::new(dir))
                .unwrap_or_else(|e| panic!("{dir} must be accepted: {e}"));
        }
    }

    /// 配下でないものは通さない（**禁止側**）。根そのもの・隣接する名前・相対要素・UNCを含む。
    #[test]
    fn anything_that_is_not_strictly_under_the_launch_root_is_rejected() {
        for dir in [
            r"C:\Windows\System32",          // まったく別の場所
            r"C:\harness-e2e",               // 根そのもの（配下ではない）
            r"C:\harness-e2e\",              // 同上（末尾の区切り違い）
            r"C:\harness-e2e-evil\payload",  // 前方一致だが別ディレクトリ
            r"C:\harness-e2e\..\Windows",    // `..`で外へ出る
            r"C:\harness-e2e\.\x",           // `.`
            r"harness-e2e\scenarioA",        // 相対
            r"C:harness-e2e\scenarioA",      // ドライブ相対（絶対ではない）
            r"\\server\share\harness-e2e\x", // UNC
            r"D:\harness-e2e\scenarioA",     // 別ドライブ
            r"C:\harness-e2e\a:b",           // 代替データストリーム
            "",
        ] {
            assert!(
                validate_launcher_dir_shape(Path::new(dir)).is_err(),
                "{dir:?} must be rejected"
            );
        }
    }

    /// 起動する実行ファイル名はクライアントが選べない——要求はディレクトリしか運ばない。
    #[test]
    fn the_executable_name_is_fixed_and_not_client_controlled() {
        let path = candidate_exe_path(Path::new(r"C:\harness-e2e\scenarioA"));
        assert_eq!(path.file_name().unwrap(), PRIVHELPER_EXE_NAME);
        assert_eq!(PRIVHELPER_EXE_NAME, "harness-privhelper.exe");
    }

    /// バイト一致の相手はデーモンのrepo rootから引く（クライアントは指せない）。
    #[test]
    fn the_reference_build_is_taken_from_the_daemons_own_repo_root() {
        let reference = reference_exe_path(Path::new(r"C:\repo"));
        assert_eq!(
            reference,
            Path::new(r"C:\repo")
                .join("target")
                .join("debug")
                .join(PRIVHELPER_EXE_NAME)
        );
    }

    /// **逃がし弁の注入が在ること**を名指しで固定する。これを落とすと、privhelperの
    /// 連鎖起動がD-44のゲートで拒否され、E2Eは緑のままシナリオ(B)へ落ちる（B-09）。
    #[test]
    fn the_command_carries_the_escape_hatch_and_only_the_pipe_name() {
        let command = privhelper_command(
            Path::new(r"C:\harness-e2e\scenarioA\harness-privhelper.exe"),
            r"\\.\pipe\harness-privhelper-1-0-1",
        );

        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args, [r"\\.\pipe\harness-privhelper-1-0-1"]);

        let escape_hatch = command
            .get_envs()
            .find(|(key, _)| {
                *key == std::ffi::OsStr::new(
                    harness_sandbox::elevated_launch::ALLOW_USER_WRITABLE_HELPERS_ENV,
                )
            })
            .map(|(_, value)| value)
            .expect("the D-44 escape hatch must be injected into the helper's environment");
        assert_eq!(escape_hatch, Some(std::ffi::OsStr::new("1")));
    }
}

/// 実マシンのファイルシステムを触るもの（形の検査だけでは確かめられない部分）。
#[cfg(all(windows, test))]
mod fs_tests {
    use super::*;

    /// このテストが作った作業ディレクトリ。**後始末はテスト自身が行う**（実マシンの共有場所に
    /// 残骸を積まない）。`C:\harness-e2e\`は既存のE2Eが使っている置き場で、無ければ作る。
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir =
                Path::new(LAUNCH_ROOT).join(format!("_broker-test-{name}-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            assert!(
                dir.is_dir(),
                "could not create {} -- this test needs {LAUNCH_ROOT} to be writable",
                dir.display()
            );
            Self(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// 実在する`C:\harness-e2e\`配下は解決まで通る（**許可側**）。
    #[test]
    fn a_real_directory_under_the_launch_root_resolves() {
        let scratch = Scratch::new("resolve");

        let resolved = resolve_launcher_dir(scratch.path()).expect("must be accepted");

        // `canonicalize`はverbatim形（`\\?\C:\...`）を返す。構成要素で比べれば同じ場所を指す。
        assert!(
            path_elements(&resolved).unwrap().ends_with(&[scratch
                .path()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_ascii_lowercase()]),
            "{}",
            resolved.display()
        );
    }

    /// 実在しても`C:\harness-e2e\`の外なら拒否する（**禁止側**）。
    #[test]
    fn a_real_directory_outside_the_launch_root_is_rejected() {
        let outside = tempfile::tempdir().expect("tempdir");

        let error = resolve_launcher_dir(outside.path()).expect_err("must be rejected");

        assert!(error.contains("strictly under"), "{error}");
    }

    /// **junctionで外へ出る経路を塞ぐ**（禁止側）。`C:\harness-e2e\`はユーザー書込可なので、
    /// そこへ別の場所を指すjunctionを作るのは非管理者でもできる——形の検査だけなら通ってしまう
    /// ので、解決後にもう一度見る必要がある。この検査を外すとこのテストだけが赤くなる。
    #[test]
    fn a_junction_that_leaves_the_launch_root_is_rejected() {
        let scratch = Scratch::new("junction");
        let outside = tempfile::tempdir().expect("tempdir");
        let junction = scratch.path().join("escape");
        let created = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &junction.to_string_lossy(),
                &outside.path().to_string_lossy(),
            ])
            .output()
            .expect("mklink");
        assert!(
            created.status.success(),
            "could not create a junction: {}",
            String::from_utf8_lossy(&created.stderr)
        );

        let error = resolve_launcher_dir(&junction).expect_err("must be rejected");

        // 後始末: junction自体を消す（リンク先は消さない）。
        let _ = std::fs::remove_dir(&junction);
        assert!(error.contains("which is outside"), "{error}");
    }

    /// **`launch`が縛りを実際に通っていること**を、入口から確かめる。検査関数が在っても
    /// 呼ばれていなければ意味が無い（B-06）。どのケースも`spawn`へ到達する前に落ちるので、
    /// このテストはprivhelperを1つも起こさない。
    #[test]
    fn launch_refuses_before_spawning_when_any_constraint_fails() {
        let scratch = Scratch::new("launch-refuse");
        let good_pipe = harness_sandbox::win_pipe_ipc::unique_pipe_name("privhelper");
        // 参照ビルドはここに無い。**そこへ到達する前に落ちる**のが正しい振る舞いである。
        let repo_root = scratch.path();

        // 縛り3: パイプ名の形
        let bad_pipe = launch(
            &PrivhelperLaunchRequest {
                pipe_name: r"C:\Windows\System32\evil.txt".to_string(),
                launcher_dir: scratch.path().to_path_buf(),
            },
            repo_root,
        )
        .expect_err("a malformed pipe name must be refused");
        assert!(bad_pipe.contains("not a harness pipe"), "{bad_pipe}");

        // 縛り1: 置き場
        let outside = tempfile::tempdir().expect("tempdir");
        let bad_dir = launch(
            &PrivhelperLaunchRequest {
                pipe_name: good_pipe.clone(),
                launcher_dir: outside.path().to_path_buf(),
            },
            repo_root,
        )
        .expect_err("a launcher directory outside the launch root must be refused");
        assert!(bad_dir.contains("strictly under"), "{bad_dir}");

        // 置き場は正しいが、そこに`harness-privhelper.exe`が無い
        let missing = launch(
            &PrivhelperLaunchRequest {
                pipe_name: good_pipe,
                launcher_dir: scratch.path().to_path_buf(),
            },
            repo_root,
        )
        .expect_err("a missing helper must be refused");
        assert!(missing.contains("could not be opened"), "{missing}");
    }

    /// 形は通るが実在しないディレクトリは、「安全だった」ではなく解決の失敗として落とす。
    #[test]
    fn a_well_formed_but_missing_directory_is_rejected() {
        let missing = Path::new(LAUNCH_ROOT).join("_broker-test-does-not-exist");

        let error = resolve_launcher_dir(&missing).expect_err("must be rejected");

        assert!(error.contains("could not be resolved"), "{error}");
    }

    /// **掴んだ実行ファイルは起動できるが、上書きはできない。** バイト一致の検査（縛り2）が
    /// 検査と起動の間の差し替えで無意味にならないことの根拠であり、同時に「掴んだせいで
    /// 起動できない」という取り違えが起きていないことの確認でもある（対で見る）。
    ///
    /// 起動対象は`where.exe`（OSに必ず在り、`/?`で使い方を印字して即終了する）。
    /// privhelper自身を使わないのは、このテストが確かめているのが**共有規則というOSの性質**
    /// であって、privhelperの挙動ではないためである。
    #[test]
    fn a_locked_executable_can_still_be_started_but_not_overwritten() {
        let scratch = Scratch::new("lock");
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let source = Path::new(&system_root).join("System32").join("where.exe");
        let copy = scratch.path().join("where.exe");
        std::fs::copy(&source, &copy).expect("copy where.exe");

        let handle = open_without_write_sharing(&copy).expect("open");

        // (1) 掴んでいる間は上書きできない。
        let write_while_locked = std::fs::OpenOptions::new().write(true).open(&copy);
        assert!(
            write_while_locked.is_err(),
            "the lock must keep others from replacing the executable"
        );
        // (2) それでも起動はできる（実行は共有規則上「読み取り」扱い）。
        let output = std::process::Command::new(&copy)
            .arg("/?")
            .output()
            .expect("a locked executable must still be startable");
        assert!(output.status.success(), "{:?}", output.status);

        // (3) 掴みを解けば上書きできる＝(1)を拒んでいたのはこのハンドルであって、
        //     ACLや他の理由ではない（歯があることの確認、B-27）。
        drop(handle);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&copy)
            .expect("after dropping the handle the file must be writable again");
    }

    /// バイト一致の検査そのもの（**許可側**）。`launch`を丸ごと呼ぶと本物のprivhelperが
    /// 起きてしまうので、`launch`が通すのと同じ関数を直接呼ぶ。
    #[test]
    fn a_byte_for_byte_copy_of_the_reference_is_accepted() {
        let scratch = Scratch::new("bytes-ok");
        let reference = scratch.path().join("reference.bin");
        let candidate = scratch.path().join("candidate.bin");
        std::fs::write(&reference, b"privhelper-image").unwrap();
        std::fs::write(&candidate, b"privhelper-image").unwrap();

        open_verified_copy(&candidate, &reference).expect("an identical copy must be accepted");
    }

    /// 1バイトでも違えば落ちる（**禁止側**）。長さ違い・空も同じく落ちる。
    #[test]
    fn anything_that_is_not_the_reference_build_is_rejected() {
        let scratch = Scratch::new("bytes-ng");
        let reference = scratch.path().join("reference.bin");
        std::fs::write(&reference, b"privhelper-image").unwrap();

        for content in [
            b"privhelper-imagE".as_slice(), // 同じ長さ・1バイト違い
            b"privhelper-image-plus".as_slice(),
            b"".as_slice(),
        ] {
            let candidate = scratch.path().join("candidate.bin");
            std::fs::write(&candidate, content).unwrap();

            let error = open_verified_copy(&candidate, &reference)
                .expect_err("only the reference build may be launched");

            assert!(error.contains("do not match"), "{error}");
        }
    }

    /// 起動対象が無い／参照が無いは、それぞれ別の失敗として報告する
    /// （「検査したら安全だった」と混ぜない。参照が無いのはビルドし忘れで、直し方が違う）。
    #[test]
    fn a_missing_candidate_and_a_missing_reference_are_reported_differently() {
        let scratch = Scratch::new("bytes-missing");
        let reference = scratch.path().join("reference.bin");
        let candidate = scratch.path().join("candidate.bin");
        std::fs::write(&reference, b"privhelper-image").unwrap();

        let missing_candidate = open_verified_copy(&scratch.path().join("nope.bin"), &reference)
            .expect_err("a missing candidate must be rejected");
        assert!(
            missing_candidate.contains("could not be opened"),
            "{missing_candidate}"
        );

        std::fs::write(&candidate, b"privhelper-image").unwrap();
        let missing_reference =
            open_verified_copy(&candidate, &scratch.path().join("nope-reference.bin"))
                .expect_err("a missing reference build must be rejected");
        assert!(
            missing_reference.contains("cargo build -p harness-privhelper"),
            "{missing_reference}"
        );
    }
}
