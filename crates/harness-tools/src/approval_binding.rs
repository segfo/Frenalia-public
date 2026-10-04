//! 承認を中身に縛る（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` §4.3・§5、D-102・D-104）。
//!
//! 引数や行に出てくるワークスペース内のファイルを、**子プロセスが実際に読むのと同じ見え方で**読み、
//! 中身の SHA-256 と、スクリプトなら同じフォルダの名前一覧の SHA-256 を取る。承認の記録はこれを持ち、
//! 次の呼び出しで今の中身から計算し直した値と比べる——書き換え・削除・承認後の新規作成・
//! 隣への`json.py`の追加のどれでも一致しなくなり、人に聞く側へ倒れる。
//!
//! # 読む先
//!
//! - Tier2a の CoW: 差分層を先に、無ければ実ファイル（Redirector と同じ順）
//! - Tier3 の CIFS 共有（`shell_sees_staged_writes`）: ステージングを先に
//! - それ以外: 実ファイル。**`--staged`のステージングは子から見えないので読まない**
//!
//! # 限界（§8）
//!
//! 縛るのは入口のファイルと隣の名前までで、既にある隣のモジュールの書き換え・サブフォルダ・
//! `node_modules`は拾えない。承認の再計算から子がファイルを開くまでの窓も残る。

use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use harness_core::{BoundFile, FilePreview, ReadScopeConfig, StagingConfig, ToolCtx};
use harness_sandbox::SandboxFs;
use sha2::{Digest, Sha256};

/// 縛れるファイルの大きさの上限。超えるものは「確かめられない」として扱う（恒久承認しない）。
pub const MAX_BOUND_FILE_BYTES: u64 = 16 * 1024 * 1024;
/// 承認画面に見せる中身の上限。
pub const MAX_PREVIEW_BYTES: usize = 256 * 1024;
/// `run_shell`の1行から縛る語の数の上限。超える行は「確かめられない」として扱う。
const MAX_SHELL_TOKENS: usize = 256;

/// 子プロセスが実際に読むのと同じ見え方でワークスペースを読む口。
pub struct ChildView {
    fs: SandboxFs,
    workspace_root: PathBuf,
}

impl ChildView {
    /// ツール呼び出しの文脈から開く（モジュールdoc「読む先」）。
    pub fn for_ctx(ctx: &ToolCtx) -> Result<Self, String> {
        let fs = match (&ctx.cow_diff_layer_dir, ctx.shell_sees_staged_writes) {
            (Some(dir), _) => SandboxFs::open_with_cow(
                &ctx.workspace_root,
                &StagingConfig::default(),
                &ReadScopeConfig::default(),
                Some(dir),
            ),
            (None, true) => SandboxFs::open_with_cow(
                &ctx.workspace_root,
                &ctx.staging,
                &ReadScopeConfig::default(),
                None,
            ),
            (None, false) => SandboxFs::open(&ctx.workspace_root, &StagingConfig::default()),
        }
        .map_err(|e| e.to_string())?;
        Ok(Self {
            fs,
            workspace_root: ctx.workspace_root.clone(),
        })
    }

    /// 実ファイルだけを読む（コマンドライン・設定の規則を起動時の中身で縛るとき、D-104）。
    pub fn real(workspace_root: &Path) -> Result<Self, String> {
        let fs = SandboxFs::open(workspace_root, &StagingConfig::default())
            .map_err(|e| e.to_string())?;
        Ok(Self {
            fs,
            workspace_root: workspace_root.to_path_buf(),
        })
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }
}

/// 1つの語（引数・行の中の語）が指すものの縛り方。
#[derive(Debug)]
pub enum PathBinding {
    /// ワークスペース内の通常ファイル。中身で縛った。
    File(BoundFile, FilePreview),
    /// ディレクトリ（ワークスペースのルートを含む）。
    Directory,
    /// 見え方の中に存在しない。
    Missing,
    /// ワークスペースの外（`..`で外へ出る綴りを含む）。
    Outside,
    /// 存在するのに中身を確かめられない（読めない・通常ファイルでない・大きすぎる・形の不正な綴り）。
    Unverifiable,
}

/// `token`を`cwd`からのパスとして引き、縛る。`with_listing`なら同じフォルダの名前一覧も縛る。
pub fn bind_path(view: &ChildView, cwd: &Path, token: &str, with_listing: bool) -> PathBinding {
    // ファイル名に使えない文字を含む語は、そもそもパスではない（`*`・`?` のようなワイルドカードや、
    // 行の中の記号）。開こうとすると「名前が不正」で失敗するので、**開ける／開けないでは
    // 区別できない**——ここで落とさないと、行に `*` が1つあるだけで行全体が照合対象外になる。
    // **落とすのは「縛らない」であって「許す」ではない**（照合は行の完全一致が受ける）。
    if token.chars().any(is_invalid_path_char) {
        return PathBinding::Missing;
    }
    let joined = if Path::new(token).is_absolute() {
        PathBuf::from(token)
    } else {
        cwd.join(token)
    };
    let Some(normalized) = lexically_normalize(&joined) else {
        return PathBinding::Outside;
    };
    let Some(rel) = harness_change_ledger::path_rules::relative_under_root(
        &normalized.to_string_lossy(),
        &view.workspace_root.to_string_lossy(),
    ) else {
        return PathBinding::Outside;
    };
    let rel = rel.replace('\\', "/");
    let rel = rel.trim_matches('/');
    if rel.is_empty() {
        return PathBinding::Directory;
    }
    if harness_change_ledger::validate_relative_path(rel).is_err() {
        // パスとして通らない綴り。**そのほとんどはパスですらない**（`OK:`・`Write-Output` のような
        // 行の中の普通の語）ので、一律に「確かめられない」とすると行全体が照合対象外になる。
        //
        // 危ないのは1つだけ——代替データストリーム（`build.py:evil`。ファイル本体とは別に中身を持てる）で、
        // **本体が実在するとき**だけである。そのときは中身を確かめられないので聞く側へ倒す。
        // 本体が無ければ、子もそのストリームを読めないので無視してよい。
        return match alternate_stream_base(rel) {
            Some(base) if view.fs.is_dir(base) || view.fs.open_file_for_read(base).is_ok() => {
                PathBinding::Unverifiable
            }
            _ => PathBinding::Missing,
        };
    }
    if view.fs.is_dir(rel) {
        return PathBinding::Directory;
    }
    let file = match view.fs.open_file_for_read(rel) {
        Ok(f) => f,
        Err(harness_sandbox::SandboxError::NotFound(_)) => return PathBinding::Missing,
        // 「無い」と「読めない」を分ける。**無いものは縛らなくてよい**（子も読めない）。
        // 読めないもの（権限・共有違反・別のプロセスが握っている）は、中身を確かめられないので聞く側へ。
        Err(harness_sandbox::SandboxError::Jail(harness_sandbox::JailError::Io(e)))
            if is_absent(&e) =>
        {
            return PathBinding::Missing;
        }
        Err(harness_sandbox::SandboxError::Io(e)) if is_absent(&e) => return PathBinding::Missing,
        Err(_) => return PathBinding::Unverifiable,
    };
    // 開いたハンドルで確かめる（名前で確かめてから開くと、その間に差し替えられる）。
    match file.metadata() {
        Ok(m) if m.is_file() && m.len() <= MAX_BOUND_FILE_BYTES => {}
        Ok(m) if m.is_dir() => return PathBinding::Directory,
        _ => return PathBinding::Unverifiable,
    }
    let mut bytes = Vec::new();
    if file
        .take(MAX_BOUND_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > MAX_BOUND_FILE_BYTES
    {
        return PathBinding::Unverifiable;
    }
    let dir_listing_sha256 = if with_listing {
        let parent = rel.rsplit_once('/').map_or("", |(p, _)| p);
        match view.fs.list_dir_names(parent) {
            Ok(names) => Some(sha256_hex(
                names.into_iter().collect::<Vec<_>>().join("\n").as_bytes(),
            )),
            Err(_) => return PathBinding::Unverifiable,
        }
    } else {
        None
    };
    let truncated = bytes.len() > MAX_PREVIEW_BYTES;
    let preview = FilePreview {
        rel_path: rel.to_string(),
        text: String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_PREVIEW_BYTES)]).into_owned(),
        truncated,
    };
    PathBinding::File(
        BoundFile {
            rel_path: rel.to_string(),
            sha256: sha256_hex(&bytes),
            dir_listing_sha256,
        },
        preview,
    )
}

/// `run_shell`の1行を縛った結果。
#[derive(Debug, Default)]
pub struct ShellBinding {
    pub files: Vec<BoundFile>,
    pub previews: Vec<FilePreview>,
    pub unverifiable: bool,
}

/// `run_shell`の行に**字面で**現れる語のうち、ワークスペース内の通常ファイルを指すものを縛る（D-102）。
///
/// 行を空白と`;|&(){}<>,=`で割り、引用符とバッククォートを剥がした語を、`cwd`からのパスとして引く。
/// **これは検出だが、聞く方向にしか働かない**——変数・連結・ワイルドカードで書かれた参照は見落とすが、
/// 見落としても結果は「行の完全一致」に戻るだけで、自動承認は広がらない。
/// ディレクトリとワークスペース外は縛らない。存在するのに確かめられないファイルが1つでもあれば
/// `unverifiable`（記録と照合しない）。
pub fn bind_shell_line(view: &ChildView, cwd: &Path, line: &str) -> ShellBinding {
    let tokens = shell_tokens(line);
    let mut out = ShellBinding::default();
    if tokens.len() > MAX_SHELL_TOKENS {
        out.unverifiable = true;
        return out;
    }
    for token in tokens {
        match bind_path(
            view,
            cwd,
            &token,
            harness_core::has_script_extension(&token),
        ) {
            PathBinding::File(f, p) => push_unique(&mut out.files, &mut out.previews, f, p),
            PathBinding::Unverifiable => out.unverifiable = true,
            PathBinding::Directory | PathBinding::Missing | PathBinding::Outside => {}
        }
    }
    out
}

/// `run_program`の引数を縛った結果（コードを走らせる呼び出しだけ）。
#[derive(Debug, Default)]
pub struct ProgramBinding {
    pub files: Vec<BoundFile>,
    pub previews: Vec<FilePreview>,
    pub one_shot_only: bool,
}

/// コードを走らせる`run_program`の引数を縛る（D-104）。
///
/// `-`で始まらない引数は**全部**、ワークスペース内に実在する通常ファイルでなければならない
/// （隣の名前一覧も縛る）。1つでもそうでない——実在しない名前・ディレクトリ・ワークスペース外・
/// その場のコード・モジュール名——なら`one_shot_only`（恒久承認できない）。判定する側（ハーネスが
/// その綴りを開く）と実行する側（インタプリタが自分の規則でファイルを探す。`node build`は`build.js`を
/// 探す）が別のものを見ると、縛ったつもりのものが縛れていないため、確かめられないものは聞く側へ倒す。
/// `-`で始まる引数にパスが連結されている形（`--require=./x.js`・`-r./x`）も同じ理由で`one_shot_only`。
pub fn bind_program_args(view: &ChildView, cwd: &Path, args: &[String]) -> ProgramBinding {
    let mut out = ProgramBinding::default();
    for arg in args {
        if arg.starts_with('-') {
            if !is_plain_option(arg) {
                out.one_shot_only = true;
            }
            continue;
        }
        match bind_path(view, cwd, arg, true) {
            PathBinding::File(f, p) => push_unique(&mut out.files, &mut out.previews, f, p),
            _ => out.one_shot_only = true,
        }
    }
    out
}

/// 解決先がワークスペース内の実行ファイルなら、その実体を縛る（D-103。隣の名前一覧も——
/// Windows は実行ファイルと同じフォルダの DLL を先に読む）。ワークスペース外なら`None`。
pub fn bind_executable(view: &ChildView, resolved: &Path) -> Option<PathBinding> {
    harness_change_ledger::path_rules::relative_under_root(
        &resolved.to_string_lossy(),
        &view.workspace_root.to_string_lossy(),
    )?;
    Some(bind_path(
        view,
        &view.workspace_root,
        &resolved.to_string_lossy(),
        true,
    ))
}

/// `resolved`がワークスペース内か。
pub fn is_inside_workspace(workspace_root: &Path, resolved: &Path) -> bool {
    harness_change_ledger::path_rules::relative_under_root(
        &resolved.to_string_lossy(),
        &workspace_root.to_string_lossy(),
    )
    .is_some()
}

/// 値の付いていないオプションか（`-c`・`--verbose`・`-File`）。`=`や`/`・`.`が付いたもの
/// （`--require=./x.js`・`-r./x`・`-dauto_prepend_file=x.php`）は偽。
fn is_plain_option(arg: &str) -> bool {
    let name = arg.trim_start_matches('-');
    !name.is_empty()
        && arg.len() - name.len() <= 2
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// ファイル名に使えない文字（Windows の規則。Linux でも、これらを含む語は行の中の記号とみなす）。
fn is_invalid_path_char(c: char) -> bool {
    matches!(c, '*' | '?' | '"' | '<' | '>' | '|')
}

/// その誤りは「そこに何も無い」を意味するか。
fn is_absent(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    if matches!(e.kind(), ErrorKind::NotFound) {
        return true;
    }
    // Windows: ERROR_PATH_NOT_FOUND(3)・ERROR_INVALID_NAME(123)・ERROR_BAD_PATHNAME(161)・
    // ERROR_FILENAME_EXCED_RANGE(206)。`ErrorKind`へ畳まれない番号があるので生の値でも見る。
    matches!(e.raw_os_error(), Some(2 | 3 | 123 | 161 | 206))
}

/// 代替データストリームの綴り（`build.py:evil`）なら、その本体（`build.py`）。
/// 最後の要素にコロンがあるものだけを見る（`C:/…` のようなドライブ文字は絶対パスとして先に処理される）。
fn alternate_stream_base(rel: &str) -> Option<&str> {
    let (dir, last) = rel.rsplit_once('/').unwrap_or(("", rel));
    let (base, _stream) = last.split_once(':')?;
    if base.is_empty() {
        return None;
    }
    Some(if dir.is_empty() {
        base
    } else {
        // `dir/base` を指す部分文字列（`rel`の先頭から`base`の末尾まで）。
        &rel[..dir.len() + 1 + base.len()]
    })
}

/// 行を語へ割る（[`bind_shell_line`]のdoc）。
fn shell_tokens(line: &str) -> Vec<String> {
    line.split(|c: char| c.is_whitespace() || ";|&(){}<>,=".contains(c))
        .map(|t| t.trim_matches(|c| c == '"' || c == '\'' || c == '`'))
        .filter(|t| !t.is_empty() && !t.starts_with('-') && !t.starts_with('$'))
        .map(str::to_string)
        .collect()
}

/// 同じファイルを2度縛らない。`rel_path`昇順に保つ（照合は集合の完全一致で比べる）。
fn push_unique(
    files: &mut Vec<BoundFile>,
    previews: &mut Vec<FilePreview>,
    file: BoundFile,
    preview: FilePreview,
) {
    if let Err(pos) = files.binary_search_by(|f| f.rel_path.cmp(&file.rel_path)) {
        files.insert(pos, file);
        previews.insert(pos, preview);
    }
}

/// `..`と`.`を字面で畳む。ルートより上へ出たら`None`（ワークスペース外）。
fn lexically_normalize(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Prefix(_) | Component::RootDir => out.push(c.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() || out.as_os_str().is_empty() {
                    return None;
                }
            }
            Component::Normal(n) => out.push(n),
        }
    }
    Some(out)
}

/// 中身のハッシュ（小文字16進）。承認の台帳が写しの照合に使うので公開する。
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
#[path = "approval_binding_tests.rs"]
mod tests;
