//! harness-sandbox: ワークスペースjail。`plans/DESIGN.md` §ファイルサンドボックス・
//! ステージング・シェル隔離、および §ツールシステム「fsジェイル（cap-std を主ゲート）」参照。
//!
//! M4時点のスコープは「層1: ワークスペースjail＝モード非依存の不変条件」のみである。
//! オーバーレイFS・書込ステージング3モード・シェル隔離Tier・読取スコープ（whitelist/blacklist
//! 反転モード）はいずれもM10/M11/M12のスコープで、本クレートには未実装。
//!
//! **主ゲートはcap-std**: 起動時（実際にはツール呼び出しごと。§実装ノート参照）に開いた
//! `cap_std::fs::Dir` ハンドルからの相対openに統一し、絶対パス再解決を経由したTOCTOU
//! （検査後に対象を差し替える攻撃）をopenat相当の型で封じる。文字列としての`..`検査・
//! Windows予約デバイス名/ADS/UNC前置の拒否は、cap-stdによる主ゲートを補強する**早期リジェクト**
//! （設計書「path-clean+dunce::canonicalize+starts_withは補助ログに降格」と同じ位置付け）であり、
//! これ単体を安全性の根拠にはしない。

use std::path::{Component, Path, PathBuf};

use cap_std::fs::Dir;

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
