//! harness-sandbox: ワークスペースjail + オーバーレイFS。`plans/DESIGN.md`
//! §ファイルサンドボックス・ステージング・シェル隔離、および §ツールシステム
//! 「fsジェイル（cap-std を主ゲート）」参照。
//!
//! M4時点のスコープは「層1: ワークスペースjail＝モード非依存の不変条件」のみだった。
//! M10で `overlay`（`SandboxFs`: 書込リダイレクト・read-through・変更マニフェスト・
//! 論理削除tombstone・`--live`/`--staged`/`--workspace_commit`3モード・apply/discard）を
//! 追加した。読取スコープ（whitelist/blacklist反転モード）・シェル隔離Tierは引き続き
//! M11/M12のスコープで本クレートには未実装。
//!
//! **主ゲートはcap-std**: 起動時（実際にはツール呼び出しごと。§実装ノート参照）に開いた
//! `cap_std::fs::Dir` ハンドルからの相対openに統一し、絶対パス再解決を経由したTOCTOU
//! （検査後に対象を差し替える攻撃）をopenat相当の型で封じる。文字列としての`..`検査・
//! Windows予約デバイス名/ADS/UNC前置の拒否は、cap-stdによる主ゲートを補強する**早期リジェクト**
//! （設計書「path-clean+dunce::canonicalize+starts_withは補助ログに降格」と同じ位置付け）であり、
//! これ単体を安全性の根拠にはしない。
//!
//! `SandboxFs`のオーバーレイ実体（`tree/`・`_ext/`・`manifest.jsonl`）は常にworkspace内
//! （`StagingConfig.sandbox_dir`はworkspace_rootからの相対パス）に置くため、この`WorkspaceJail`
//! 1つだけで実FS・オーバーレイの両方を仲介できる（新たなambient authorityを増やさない）。

pub mod git;
pub mod manifest;
pub mod overlay;

pub use manifest::{ManifestOp, ManifestTarget};
pub use overlay::{ApplyOptions, ApplyReport, ChangeEntry, SandboxError, SandboxFs};

use std::path::{Component, Path, PathBuf};

use cap_std::fs::{Dir, File};
use cap_std::time::SystemTime;

#[derive(Debug, thiserror::Error)]
pub enum JailError {
    #[error("path escapes the workspace: {0}")]
    Escape(String),
    #[error("unsafe path form: {0}")]
    UnsafePath(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// ワークスペースルート配下への相対アクセスに閉じ込める。
/// `cap_std::fs::Dir::open_ambient_dir` はプロセスのambient authority（OSが与える無制限の
/// ファイルアクセス能力）を使う唯一の箇所であり、以降の`open`/`read_to_string`はこの
/// `Dir`ハンドルからの相対open（openat相当）に閉じているため、絶対パスへの再解決が起きない。
pub struct WorkspaceJail {
    dir: Dir,
}

impl WorkspaceJail {
    pub fn open(root: &Path) -> Result<Self, JailError> {
        let dir = Dir::open_ambient_dir(root, cap_std::ambient_authority())?;
        Ok(Self { dir })
    }

    pub fn read_to_string(&self, rel_path: &str) -> Result<String, JailError> {
        let rel = check_relative_path(rel_path)?;
        Ok(self.dir.read_to_string(&rel)?)
    }

    /// ジェイル内へ書き込む（`write_file`/`edit_file`用）。親ディレクトリは
    /// jailを開いた`Dir`ハンドルからの相対`create_dir_all`（openat相当）で作る
    /// （§ツールシステム`write_file`「親ディレクトリ作成」）。
    pub fn write_string(&self, rel_path: &str, content: &str) -> Result<(), JailError> {
        use std::io::Write as _;

        let rel = check_relative_path(rel_path)?;
        if let Some(parent) = rel.parent() {
            if !parent.as_os_str().is_empty() {
                self.dir.create_dir_all(parent)?;
            }
        }
        let mut file = self.dir.create(&rel)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }

    /// jailルート配下の全ファイルを相対パスで列挙する（`grep`/`glob`用）。
    /// **【T3】`ignore::WalkBuilder`はstdのパスベースopenで自走査しcap-stdの`Dir`ハンドルを
    /// 経由できないため、走査本体はここで組む自前walker（`Dir::entries`＝openat相当）に統一し、
    /// `ignore`/`globset`はgitignore・globのマッチング判定にのみ使う**
    /// （§ツールシステム fsジェイル）。シンボリックリンクは辿らない（jail脱出防止）。
    pub fn walk_files(&self) -> Result<Vec<PathBuf>, JailError> {
        let mut out = Vec::new();
        Self::walk_dir(&self.dir, PathBuf::new(), &mut out)?;
        Ok(out)
    }

    /// ジェイル内のファイルを読取専用で開く（`grep`用、cap-stdの相対open＝openat相当）。
    pub fn open_file(&self, rel_path: &str) -> Result<File, JailError> {
        let rel = check_relative_path(rel_path)?;
        Ok(self.dir.open(&rel)?)
    }

    /// ジェイル内ファイルの最終更新時刻（`glob`のmtime順ソート用）。
    pub fn modified(&self, rel_path: &str) -> Result<SystemTime, JailError> {
        let rel = check_relative_path(rel_path)?;
        Ok(self.dir.metadata(&rel)?.modified()?)
    }

    /// ジェイル内のファイルを物理削除する（`SandboxFs::apply`のtombstone適用用）。
    pub fn remove_file(&self, rel_path: &str) -> Result<(), JailError> {
        let rel = check_relative_path(rel_path)?;
        Ok(self.dir.remove_file(&rel)?)
    }

    /// ジェイル内のディレクトリを再帰的に削除する（`SandboxFs::discard`用）。
    /// 存在しない場合は無視する（`discard`の冪等性のため）。
    pub fn remove_dir_all(&self, rel_path: &str) -> Result<(), JailError> {
        let rel = check_relative_path(rel_path)?;
        match self.dir.open_dir(&rel) {
            Ok(sub) => {
                Self::remove_dir_contents(&sub)?;
                // Windowsは開いたままのディレクトリハンドルを削除できないため、
                // `remove_dir`の前に明示的にドロップする（NLLは値のDropタイミングまでは
                // 早めない。値のスコープ終端まで開いたままになる）。
                drop(sub);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        Ok(self.dir.remove_dir(&rel)?)
    }

    fn remove_dir_contents(dir: &Dir) -> Result<(), JailError> {
        for entry in dir.entries()? {
            let entry = entry?;
            let name = entry.file_name();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                let sub = entry.open_dir()?;
                Self::remove_dir_contents(&sub)?;
                drop(sub);
                dir.remove_dir(&name)?;
            } else {
                dir.remove_file(&name)?;
            }
        }
        Ok(())
    }

    fn walk_dir(dir: &Dir, prefix: PathBuf, out: &mut Vec<PathBuf>) -> Result<(), JailError> {
        for entry in dir.entries()? {
            let entry = entry?;
            let name = entry.file_name();
            if name == ".git" || name == ".harness" {
                continue;
            }
            let rel = prefix.join(&name);
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            } else if file_type.is_dir() {
                let sub = entry.open_dir()?;
                Self::walk_dir(&sub, rel, out)?;
            } else if file_type.is_file() {
                out.push(rel);
            }
        }
        Ok(())
    }
}

/// jailを開かずに文字列としての形だけを検査する下位互換チェック。
/// `run_shell`の`cwd`のように、子プロセスへ渡すだけでcap-std経由のopenをしない値
/// （設計書「これらはrun_shell子プロセスには効かない＝子の実FSアクセスを止めるのは
/// OS隔離Tierだけ」§ツールシステム fsジェイル）に対して、最低限の形の妥当性だけ確認する用途。
pub fn check_relative_path(path: &str) -> Result<PathBuf, JailError> {
    let rel = Path::new(path);
    if rel.is_absolute() {
        return Err(JailError::Escape(path.to_string()));
    }
    if path.starts_with("\\\\") || path.starts_with("//") {
        return Err(JailError::UnsafePath(format!("UNC path is not allowed: {path}")));
    }
    for c in rel.components() {
        match c {
            Component::ParentDir => {
                return Err(JailError::Escape(path.to_string()));
            }
            Component::Normal(part) => {
                let s = part.to_string_lossy();
                if s.contains(':') {
                    return Err(JailError::UnsafePath(format!(
                        "alternate data stream syntax is not allowed: {s}"
                    )));
                }
                if is_reserved_windows_name(&s) {
                    return Err(JailError::UnsafePath(format!(
                        "reserved device name is not allowed: {s}"
                    )));
                }
            }
            _ => {}
        }
    }
    Ok(rel.to_path_buf())
}

/// Windowsの予約デバイス名（大小・拡張子を無視、`NUL.txt`も対象）。
/// §ツールシステム fsジェイル「予約デバイス名basename（大小・拡張子無視）」。
fn is_reserved_windows_name(name: &str) -> bool {
    let base = name.split('.').next().unwrap_or(name);
    matches!(
        base.to_ascii_uppercase().as_str(),
        "CON" | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_absolute_path() {
        let dir = tempfile::tempdir().unwrap();
        let jail = WorkspaceJail::open(dir.path()).unwrap();
        #[cfg(windows)]
        let abs = "C:\\Windows\\System32\\drivers\\etc\\hosts";
        #[cfg(not(windows))]
        let abs = "/etc/passwd";
        let err = jail.read_to_string(abs).unwrap_err();
        assert!(matches!(err, JailError::Escape(_)));
    }

    #[test]
    fn rejects_parent_dir_escape() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().parent().unwrap().join("outside.txt"), "secret").unwrap();
        let jail = WorkspaceJail::open(dir.path()).unwrap();
        let err = jail.read_to_string("../outside.txt").unwrap_err();
        assert!(matches!(err, JailError::Escape(_)));
    }

    #[test]
    fn write_string_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let jail = WorkspaceJail::open(dir.path()).unwrap();
        jail.write_string("sub/dir/a.txt", "hello").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("sub/dir/a.txt")).unwrap(),
            "hello"
        );
    }

    #[test]
    fn write_string_rejects_path_escape() {
        let dir = tempfile::tempdir().unwrap();
        let jail = WorkspaceJail::open(dir.path()).unwrap();
        let err = jail.write_string("../outside.txt", "x").unwrap_err();
        assert!(matches!(err, JailError::Escape(_)));
    }

    #[test]
    fn walk_files_lists_nested_files_and_skips_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("a.txt"), "1").unwrap();
        std::fs::write(dir.path().join("sub/b.txt"), "2").unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".git/HEAD"), "ref: refs/heads/main").unwrap();

        let jail = WorkspaceJail::open(dir.path()).unwrap();
        let mut files: Vec<String> = jail
            .walk_files()
            .unwrap()
            .into_iter()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .collect();
        files.sort();
        assert_eq!(files, vec!["a.txt".to_string(), "sub/b.txt".to_string()]);
    }

    #[test]
    fn allows_file_within_workspace() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "hello").unwrap();
        let jail = WorkspaceJail::open(dir.path()).unwrap();
        assert_eq!(jail.read_to_string("a.txt").unwrap(), "hello");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.txt"), "top secret").unwrap();
        symlink(outside.path(), workspace.path().join("escape")).unwrap();

        let jail = WorkspaceJail::open(workspace.path()).unwrap();
        // cap-std はシンボリックリンクを辿った先が Dir の外に出る場合、openat相当の
        // 経路で拒否する（TOCTOUを型で封じる、というcap-stdの中核の保証）。
        let err = jail.read_to_string("escape/secret.txt").unwrap_err();
        assert!(matches!(err, JailError::Io(_)));
    }

    #[cfg(windows)]
    #[test]
    fn rejects_reserved_device_name() {
        let dir = tempfile::tempdir().unwrap();
        let jail = WorkspaceJail::open(dir.path()).unwrap();
        let err = jail.read_to_string("NUL.txt").unwrap_err();
        assert!(matches!(err, JailError::UnsafePath(_)));
    }

    #[cfg(windows)]
    #[test]
    fn rejects_alternate_data_stream_syntax() {
        let dir = tempfile::tempdir().unwrap();
        let jail = WorkspaceJail::open(dir.path()).unwrap();
        let err = jail.read_to_string("a.txt:hidden").unwrap_err();
        assert!(matches!(err, JailError::UnsafePath(_)));
    }
}
