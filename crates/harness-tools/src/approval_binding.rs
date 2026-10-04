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

/// 縛ったファイルの**中身を見る回数**の上限（D-120）。
///
/// 第0段（モデルが書いた行と、ハーネスが解読した各段）はここに数えない。3なら、
/// 第0段で縛ったファイルの中身 → そこで見つけたファイルの中身 → さらにその中身、までを見る。
/// `python a.py` で `a.py → b.py → c.py → d.py` と名指しが続くなら `d.py` までが入り、
/// その先の `e.py` は入らない。
pub const MAX_NEST_DEPTH: u32 = 3;

/// 第1段から先で新しく縛るファイルの数の上限（D-120）。超えたら「確かめられない」として扱う。
pub const MAX_NESTED_FILES: usize = 10;

/// 解読した段のうち、ファイルを探す段の数の上限（D-120）。
pub const MAX_LAYERS_TO_BIND: usize = 8;

/// 縛ったファイルの中身から解読する段の数の上限（全ファイル合わせて。D-122）。
pub const MAX_FILE_LAYERS: usize = 16;

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

impl ShellBinding {
    /// 別の縛り結果を取り込む（同じファイルは1つに、「確かめられない」は片方でも真なら真）。
    ///
    /// **重複なしの差し込みはこの1か所を通す。** 以前は`push_unique`と`shell/program.rs`の中へ
    /// 同じ処理が写されていた（`B-05`——写すと片方だけ直されて静かにずれる）。
    pub fn absorb(&mut self, other: ShellBinding) {
        self.unverifiable |= other.unverifiable;
        for (file, preview) in other.files.into_iter().zip(other.previews) {
            push_unique(&mut self.files, &mut self.previews, file, preview);
        }
    }
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
        bind_token_into(&mut out, view, cwd, &token);
    }
    out
}

/// 1つの語を、ワークスペース内の通常ファイルを指すものなら縛る。`bind_shell_line`（`run_shell`）と
/// `bind_program_file_args`（`run_program`）が**同じ1判定を通す**ための共通部品。
///
/// 片方だけ直されて静かにずれるのを防ぐ（`B-05`）。縛る方向にしか働かない——ディレクトリ・
/// ワークスペース外・存在しない語は黙って飛ばし、**存在するのに読めない語だけ**`unverifiable`。
fn bind_token_into(out: &mut ShellBinding, view: &ChildView, cwd: &Path, token: &str) {
    match bind_path(view, cwd, token, harness_core::has_script_extension(token)) {
        PathBinding::File(f, p) => push_unique(&mut out.files, &mut out.previews, f, p),
        PathBinding::Unverifiable => out.unverifiable = true,
        PathBinding::Directory | PathBinding::Missing | PathBinding::Outside => {}
    }
}

/// `run_program`の引数のうち、ワークスペース内の通常ファイルを指すものを縛る（D-123）。
///
/// `run_shell`の[`bind_shell_line`]と**同じ寛容さ**——`-`で始まる語（オプション）は飛ばし、
/// ファイルでない語（`uv run`の`run`のようなサブコマンド）は咎めない。字面に出た実在ファイルだけ縛る。
///
/// インタプリタ用の厳格な[`bind_program_args`]とは**別物**である。あちらはハーネスが「走るコードを
/// 全部縛った」と主張する呼び出し用で、ファイルでない引数があると恒久承認できなくする（D-104。
/// `node build`が`build.js`を自分の規則で探すため、縛ったつもりのものが縛れていない）。
/// こちらは「字面に名指しされたファイルだけ」を縛るので、サブコマンドは咎めない。
pub fn bind_program_file_args(view: &ChildView, cwd: &Path, args: &[String]) -> ShellBinding {
    let mut out = ShellBinding::default();
    if args.len() > MAX_SHELL_TOKENS {
        out.unverifiable = true;
        return out;
    }
    for arg in args {
        if arg.starts_with('-') {
            continue;
        }
        bind_token_into(&mut out, view, cwd, arg);
    }
    out
}

/// 行・解読した各段・入れ子のスクリプトを**全部**縛る（D-120）。承認材料を組む2つの入口
/// （`run_shell`・`run_program`）がどちらもここを通る。
///
/// ```text
/// 第0段  モデルが書いた行     → 全部の語を見る
///        解読した各段の中身   → 全部の語を見る（`MAX_LAYERS_TO_BIND`段まで）
/// 第1段〜 縛ったファイルの中身 → スクリプトの拡張子を持つ語だけ（[`bind_nested`]。[`MAX_NEST_DEPTH`]回まで）
/// ```
pub fn bind_everything(
    view: &ChildView,
    cwd: &Path,
    line: &str,
    decoded: &[harness_core::DecodedLayer],
) -> ShellBinding {
    let mut out = bind_shell_line(view, cwd, line);
    out.absorb(bind_decoded(view, cwd, decoded));
    let nested = bind_nested(view, cwd, &out);
    out.absorb(nested);
    out
}

/// 縛ったファイルの**中身に入っている符号化された塊**を解読する（D-122）。
///
/// # 何のためにあるのか
///
/// 行を解読してファイルを縛れるようにした（D-120）が、**そのファイルの中に符号化された塊が
/// 書いてあると、そこから先は見えない**。実測（2026-10-04）: `uv run test.py` の `test.py` が
///
/// ```text
/// import os
/// print("hello")
/// os.remove("pwsh --enc <塊>")
/// ```
///
/// で、**その塊を2段解くと `rm C:\Windows\System32\calc.exe` だった**。
/// 機械の被害判定は `os.remove` の引数を見るが、引数は符号化された文字列そのものなので
/// システムの場所には当たらない——**判定は正しく、解読が1段足りなかった**。
///
/// 解読に使うのは行と同じ関数（[`crate::encoded_command::decode_shell_line`]）で、
/// 承認画面に出る段と同じ解き方である。見つけた段には**どのファイルの中で見つけたか**を書いておく
/// （`DecodedLayer::in_file`）ので、画面も危険度の理由も「test.py の中」と言える。
///
/// # ここが守らないもの
///
/// - 見るのは`code_only`が真なら**スクリプトの拡張子を持つファイルだけ**（`run_shell`）。
///   偽ならすべて（`run_program`でコードを走らせるとき）
/// - 全部合わせて[`MAX_FILE_LAYERS`]段まで。超えた分は見ない
pub fn decode_in_files(
    previews: &[FilePreview],
    code_only: bool,
) -> Vec<harness_core::DecodedLayer> {
    let mut out = Vec::new();
    for preview in previews {
        if code_only && !harness_core::has_script_extension(&preview.rel_path) {
            continue;
        }
        for mut layer in crate::encoded_command::decode_shell_line(&preview.text) {
            if out.len() >= MAX_FILE_LAYERS {
                return out;
            }
            layer.in_file = Some(preview.rel_path.clone());
            out.push(layer);
        }
    }
    out
}

/// 解読した各段の中身からもファイルを縛る（第0段の一部。深さを消費しない）。
///
/// 解読そのものの深さは別の上限が持っている（`MAX_DECODE_DEPTH`＝4・`MAX_DECODED_LAYERS`＝16）ので、
/// ここでは**見る段の数**だけを[`MAX_LAYERS_TO_BIND`]で抑える。
pub fn bind_decoded(
    view: &ChildView,
    cwd: &Path,
    decoded: &[harness_core::DecodedLayer],
) -> ShellBinding {
    let mut out = ShellBinding::default();
    for layer in decoded.iter().take(MAX_LAYERS_TO_BIND) {
        if let harness_core::DecodeOutcome::Text { text, .. } = &layer.outcome {
            out.absorb(bind_shell_line(view, cwd, text));
        }
    }
    out
}

/// 縛ったファイルの**中身**から、さらに入れ子のスクリプトを縛る（D-120）。
///
/// # 何のためにあるのか
///
/// 承認材料にファイルが入るのは「モデルが書いた行に字面で出た語」を見るときだけだった。だから
/// `pwsh --enc <塊>` を解読して出てきた `uv run test.py` の `test.py` は、**画面には見えているのに
/// 中身を読んでおらず、ハッシュでも縛っていなかった**（実測: 2026-10-04）。
///
/// ```text
/// 第0段  モデルが書いた行 ＋ ハーネスが解読した各段 → 全部の語を見る（`bind_shell_line`）
/// 第1段  第0段で縛ったファイルの中身               → スクリプトの拡張子を持つ語だけ
/// 第2段  第1段で縛ったファイルの中身               → 同上
/// 第3段  第2段で縛ったファイルの中身               → 同上。ここで止める（`MAX_NEST_DEPTH`）
/// ```
///
/// # 第1段から先で拡張子を見る理由
///
/// ファイルの中身は語が多い。全部の語を`bind_shell_line`へ通すと[`MAX_SHELL_TOKENS`]（256）を
/// 超えて`unverifiable`が立ち、**スクリプトを名指しするコマンドが二度と自動承認されなくなる**
/// （普通の100行のPythonファイルでも語は256を超える）。追いたいのは入れ子のスクリプトなので、
/// 拡張子（`harness_core::has_script_extension`。D-118の一覧）で絞れば目的に足りる。
///
/// # 縛ると自動承認にも効く
///
/// ここで縛ったファイルは`CommandSubject.files`へ入り、承認の記録へそのまま写される。照合は
/// 中身のハッシュの完全一致なので、**`test.py`の中身が1バイト変われば自動承認が外れて承認画面が出る**。
///
/// # ここが守らないもの
///
/// - **LLMが場所を示して解読した分は縛れない。** その解読は承認の分類が終わった後で走るので、
///   `files`へ入れても照合には届かない（機械の解読の分だけが縛りに効く）
/// - **第1段から先は拡張子で絞る**ので、拡張子の無いスクリプト（`#!/bin/sh`で始まるファイル等）は追えない
/// - **変数に入れたファイル名は追えない**（`p = "x.ps1"`の後の`run(p)`）。字面に出ているものだけ
/// - **上限で止めたら`unverifiable`を立てる**（黙って止めない）。確かめ切れていないので自動承認はしない
pub fn bind_nested(view: &ChildView, cwd: &Path, seed: &ShellBinding) -> ShellBinding {
    let mut out = ShellBinding::default();
    // 次の段で中身を見るファイルの本文。最初は第0段で縛ったもの。
    let mut frontier: Vec<String> = seed.previews.iter().map(|p| p.text.clone()).collect();
    let mut seen: Vec<String> = seed.files.iter().map(|f| f.rel_path.clone()).collect();

    for _ in 0..MAX_NEST_DEPTH {
        if frontier.is_empty() {
            break;
        }
        let mut next = Vec::new();
        for text in std::mem::take(&mut frontier) {
            for token in script_tokens(&text) {
                if out.files.len() >= MAX_NESTED_FILES {
                    // 確かめ切れていない。自動承認はしない。
                    out.unverifiable = true;
                    return out;
                }
                match bind_path(view, cwd, &token, true) {
                    PathBinding::File(f, p) => {
                        if seen.contains(&f.rel_path) {
                            continue; // 同じファイルを二度追わない（循環も止まる）
                        }
                        seen.push(f.rel_path.clone());
                        next.push(p.text.clone());
                        push_unique(&mut out.files, &mut out.previews, f, p);
                    }
                    PathBinding::Unverifiable => out.unverifiable = true,
                    PathBinding::Directory | PathBinding::Missing | PathBinding::Outside => {}
                }
            }
        }
        frontier = next;
    }
    out
}

/// テキストの中の、**スクリプトの拡張子を持つ語**だけ（第1段から先で使う）。
///
/// 割り方は[`shell_tokens`]と同じにして、ここで拡張子で絞る——割り方を別に持つと、片方だけ直されて
/// 静かにずれる（`B-05`）。
fn script_tokens(text: &str) -> Vec<String> {
    shell_tokens(text)
        .into_iter()
        .filter(|t| harness_core::has_script_extension(t))
        .collect()
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
