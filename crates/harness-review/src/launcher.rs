//! レビュー経路の**安全な git 起動器**（D-110 (vi)）。このクレートで git を起動する唯一の口。
//!
//! # 守る不変条件
//!
//! **ホストの git は、エージェントが書いた config・hooks・alternates・commit-graph・midx・
//! bitmap・shallow・grafts・`info/*` を読まない。**
//!
//! 環境変数や `-c` では守れない——git にはリポジトリ自身の `.git/config` を無効にする手段が無い
//! （BUG-150 で実測）。だから守り方は構造である: **差分層の `.git` を git dir として渡す口を
//! 作らない**。git dir は [`GitAt`] の3種（本物のリポジトリ・ハーネスが組んだ一時リポジトリ・
//! レビュー用 worktree）でしか指定できず、どれもこのクレートの中でしか作れない。
//!
//! # 環境と固定する設定
//!
//! 起動の型は `harness-sandbox` の `resolve.rs`（`git merge-file`）と同じ——`which` で解決した
//! 絶対パス・`env_clear`・許可リストの環境（`build_child_env`）・`hardening_env`（hooks・
//! fsmonitor・pager の無効化）。そのうえで、このクレートの操作に要る設定を `-c` で固定する
//! （[`PINNED_CONFIG`]）。**`-C` は使わない**——指した先に `.git` が無いと上の階層を探しに行き、
//! 無関係なリポジトリを拾い得る。git dir は必ず `--git-dir` で明示し、作業ディレクトリは
//! 呼び出し側が渡すハーネスの一時ディレクトリにする。
//!
//! # この機構の限界
//!
//! - **ローカル fetch の相手側（一時リポジトリで動く upload-pack）には、`-c` も `GIT_CONFIG_*` も
//!   `GIT_NO_REPLACE_OBJECTS` も届かない**（git が `local_repo_env` を消してから起動する）。
//!   相手側が読むのは一時リポジトリの設定と利用者のグローバル設定だけなので、そこは
//!   「一時リポジトリの中身をハーネスが全部決める」ことで守っている（`assemble.rs`）。
//! - 利用者のグローバル設定（`~/.gitconfig`）は読む。利用者のものであってエージェントのもの
//!   ではないので不変条件の外である。
//! - `GIT_CONFIG_NOSYSTEM=1`（`hardening_env`）により、Git for Windows の既定の
//!   `core.autocrlf=true` が効かない。レビュー用 worktree のファイルは改行が LF のまま
//!   書き出され得る（利用者の普段の checkout とは違う見え方になる）。

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::ReviewError;

/// 空の tree のオブジェクト名。git はこれを常に「在る」ものとして扱う。
///
/// レビュー用 worktree での checkout・status は `--attr-source=<空の tree>` で回す——
/// `.gitattributes` は skip-worktree でディスクへ出さなくても **index から読まれ**、
/// 利用者のグローバル設定にあるフィルタ（`git lfs install` が書く `filter.lfs.*` 等）を
/// エージェントの属性が選べてしまう。属性の読み元を空にすればフィルタ・改行変換は選ばれない。
pub(crate) const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

/// すべての起動で `-c` として固定する設定。
///
/// | 設定 | なぜ |
/// |---|---|
/// | `protocol.allow=never`・`protocol.file.allow=always` | ネットワークへ出ない。利用者の `url.<x>.insteadOf` がローカルのパスを URL へ書き換えても通信しない |
/// | `transfer.fsckObjects`・`fetch.fsckObjects` | 取り込むオブジェクトを形式検査する（D-110 (vi)） |
/// | `fetch.prune(Tags)=false` | 本物の ref を消さない |
/// | `gc.auto=0`・`maintenance.auto=false`・`fetch.writeCommitGraph=false` | 利用者のリポジトリで保守処理を走らせない |
/// | `submodule.recurse`・`fetch.recurseSubmodules` | サブモジュールへ辿らない（エージェントの `.gitmodules` が指す先へ行かない） |
/// | `core.symlinks=false` | worktree へシンボリックリンクを作らない（中身を文字として書く） |
/// | `core.longpaths=true` | レビューの置き場のぶんパスが長くなる |
/// | `core.protectNTFS=true` | `.git` の 8.3 短縮名などの別名を checkout しない |
pub(crate) const PINNED_CONFIG: &[(&str, &str)] = &[
    ("protocol.allow", "never"),
    ("protocol.file.allow", "always"),
    ("transfer.fsckObjects", "true"),
    ("fetch.fsckObjects", "true"),
    ("fetch.prune", "false"),
    ("fetch.pruneTags", "false"),
    ("gc.auto", "0"),
    ("maintenance.auto", "false"),
    ("fetch.writeCommitGraph", "false"),
    ("submodule.recurse", "false"),
    ("fetch.recurseSubmodules", "false"),
    ("core.symlinks", "false"),
    ("core.longpaths", "true"),
    ("core.protectNTFS", "true"),
];

/// `hardening_env` に足して固定する環境変数。
const PINNED_ENV: &[(&str, &str)] = &[
    // エージェントが `refs/replace/*` を運んでも、ハーネス自身の読み取りを差し替えさせない。
    ("GIT_NO_REPLACE_OBJECTS", "1"),
    ("GIT_TERMINAL_PROMPT", "0"),
    // 部分クローンの本物で、足りないオブジェクトを取りにネットワークへ出ない。
    ("GIT_NO_LAZY_FETCH", "1"),
    // 出力を解析するので、文言を英語に固定する。
    ("LC_ALL", "C"),
];

/// 本物のリポジトリ（ワークスペースのルートの `.git`）。利用者のものなので、git に読ませてよい。
///
/// 作れるのは [`crate::lifecycle`] の検査を通ったときだけ（`pub(crate)`）。
#[derive(Debug, Clone)]
pub struct RealRepo {
    pub(crate) work_tree: PathBuf,
    pub(crate) git_dir: PathBuf,
}

impl RealRepo {
    pub(crate) fn new_unchecked(work_tree: PathBuf, git_dir: PathBuf) -> Self {
        Self { work_tree, git_dir }
    }

    /// ワークスペースのルート。
    pub fn work_tree(&self) -> &Path {
        &self.work_tree
    }

    /// 本物の `objects` ディレクトリ（一時リポジトリの alternates が指す唯一の先）。
    pub(crate) fn objects_dir(&self) -> PathBuf {
        self.git_dir.join("objects")
    }
}

/// レビュー用 worktree。`worktree.rs` が作ったものだけを表す。
#[derive(Debug, Clone)]
pub struct ReviewWorktree {
    pub(crate) path: PathBuf,
}

impl ReviewWorktree {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// ハーネスが組んだ一時リポジトリ。`assemble.rs` が `init --bare` した直後にだけ作る。
#[derive(Debug)]
pub(crate) struct SourceRepo {
    pub(crate) git_dir: PathBuf,
}

impl SourceRepo {
    /// `git_dir` は**このクレートが今作った** bare リポジトリであること。差分層の中の
    /// パスを渡すと不変条件が崩れるので、呼ぶのは `assemble.rs` の1箇所だけにする。
    pub(crate) fn assembled_at(git_dir: PathBuf) -> Self {
        Self { git_dir }
    }
}

/// git を**どこで**走らせるか。任意のパスを git dir として受け取る口はここに無い。
pub(crate) enum GitAt<'a> {
    /// 本物のリポジトリ。
    Real(&'a RealRepo),
    /// ハーネスが組んだ一時リポジトリ（中身は全部ハーネスが決めた）。
    Source(&'a SourceRepo),
    /// レビュー用 worktree。属性の読み元は空の tree に固定する（[`EMPTY_TREE`]）。
    Worktree(&'a ReviewWorktree),
    /// リポジトリの外（`init` と `--version` だけが使う）。
    Nowhere,
}

/// 1回の起動の結果。
pub(crate) struct GitOutput {
    pub(crate) success: bool,
    pub(crate) code: Option<i32>,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

impl GitOutput {
    pub(crate) fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub(crate) fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).trim().to_string()
    }
}

/// 安全な git 起動器。
#[derive(Debug, Clone)]
pub struct GitLauncher {
    exe: PathBuf,
    env: Vec<(String, String)>,
    neutral_cwd: PathBuf,
}

impl GitLauncher {
    /// 本番の起動器。`git` を `PATH` から絶対パスへ解決し、環境は許可リストから組む。
    ///
    /// `neutral_cwd` は git の作業ディレクトリにするハーネスの一時ディレクトリ
    /// （本物のリポジトリの中や差分層の中を渡さないこと）。
    pub fn from_host(neutral_cwd: PathBuf) -> Result<Self, ReviewError> {
        let exe = which::which("git")
            .map_err(|e| ReviewError::GitUnavailable(format!("git was not found on PATH: {e}")))?;
        Ok(Self::new(
            exe,
            harness_sandbox::build_child_env(),
            neutral_cwd,
        ))
    }

    /// 起動器を明示的に組む。`base_env` は子へ渡す環境の土台で、`GIT_` で始まるものは
    /// 捨てる（`GIT_DIR`・`GIT_OBJECT_DIRECTORY`・`GIT_CONFIG_PARAMETERS` などが漏れると、
    /// git dir の指定そのものを差し替えられる）。テストは `HOME` を一時ディレクトリへ向けた
    /// 環境を渡す。
    pub fn new(exe: PathBuf, base_env: Vec<(String, String)>, neutral_cwd: PathBuf) -> Self {
        let mut env: Vec<(String, String)> = base_env
            .into_iter()
            .filter(|(k, _)| !k.to_ascii_uppercase().starts_with("GIT_"))
            .collect();
        env.extend(harness_core::git::hardening_env());
        env.extend(
            PINNED_ENV
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string())),
        );
        Self {
            exe,
            env,
            neutral_cwd,
        }
    }

    /// 子へ渡す環境（テストが中身を検算するため）。
    pub fn env(&self) -> &[(String, String)] {
        &self.env
    }

    /// git を1回起動する。失敗（終了コード非0）も `Ok` で返す——呼び出し側が意味を決める。
    pub(crate) fn run<S: AsRef<OsStr>>(
        &self,
        at: GitAt<'_>,
        args: &[S],
        stdin: Option<&[u8]>,
    ) -> Result<GitOutput, ReviewError> {
        let mut argv: Vec<OsString> = Vec::new();
        for (key, value) in PINNED_CONFIG {
            argv.push("-c".into());
            argv.push(format!("{key}={value}").into());
        }
        let cwd = match &at {
            GitAt::Real(repo) => {
                argv.push(git_dir_arg(&repo.git_dir));
                &self.neutral_cwd
            }
            GitAt::Source(source) => {
                argv.push(git_dir_arg(&source.git_dir));
                &self.neutral_cwd
            }
            GitAt::Worktree(wt) => {
                argv.push(git_dir_arg(&wt.path.join(".git")));
                let mut work_tree = OsString::from("--work-tree=");
                work_tree.push(wt.path.as_os_str());
                argv.push(work_tree);
                argv.push(format!("--attr-source={EMPTY_TREE}").into());
                &wt.path
            }
            GitAt::Nowhere => &self.neutral_cwd,
        };
        argv.extend(args.iter().map(|a| a.as_ref().to_os_string()));

        #[allow(clippy::disallowed_methods)] // このクレートで git を起動する唯一の場所
        let mut command = Command::new(&self.exe);
        command
            .args(&argv)
            .current_dir(cwd)
            .env_clear()
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            });
        let describe = || describe_args(args);
        let mut child = command.spawn().map_err(|e| {
            ReviewError::GitUnavailable(format!(
                "could not start {} ({}): {e}",
                self.exe.display(),
                describe()
            ))
        })?;
        // 書き込み側は別スレッドにする——大きな入力で stdout のパイプが詰まると互いに待つ。
        let writer = stdin.map(|input| {
            let mut pipe = child.stdin.take().expect("stdin was requested as piped");
            let input = input.to_vec();
            std::thread::spawn(move || pipe.write_all(&input))
        });
        let io_error = |e| ReviewError::Io {
            path: self.exe.clone(),
            source: e,
        };
        let output = child.wait_with_output().map_err(io_error)?;
        if let Some(writer) = writer {
            writer
                .join()
                .map_err(|_| ReviewError::GitUnavailable("stdin writer panicked".into()))?
                .map_err(io_error)?;
        }
        Ok(GitOutput {
            success: output.status.success(),
            code: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    /// 成功（終了コード0）を要求する版。失敗は [`ReviewError::GitFailed`] にする。
    pub(crate) fn run_ok<S: AsRef<OsStr>>(
        &self,
        at: GitAt<'_>,
        args: &[S],
        stdin: Option<&[u8]>,
    ) -> Result<GitOutput, ReviewError> {
        let out = self.run(at, args, stdin)?;
        if out.success {
            Ok(out)
        } else {
            Err(ReviewError::GitFailed {
                command: describe_args(args),
                code: out.code,
                stderr: out.stderr_text(),
            })
        }
    }
}

fn git_dir_arg(dir: &Path) -> OsString {
    let mut arg = OsString::from("--git-dir=");
    arg.push(dir.as_os_str());
    arg
}

fn describe_args<S: AsRef<OsStr>>(args: &[S]) -> String {
    let mut s = String::from("git");
    for a in args.iter().take(3) {
        s.push(' ');
        s.push_str(&a.as_ref().to_string_lossy());
    }
    s
}

#[cfg(test)]
#[path = "launcher_tests.rs"]
mod launcher_tests;
