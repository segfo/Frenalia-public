//! 読取スコープ + capability FS（M11）。`plans/DESIGN-SANDBOX.md` §5 参照。
//!
//! `WorkspaceJail`（workspace内）とは別に、`read.allow`/`read.allow_descend`で明示された
//! 外部ルートごとに`cap_std::fs::Dir`を1枚開き、以降は openat 相対アクセスのみに限定する
//! （ambient authorityを使うのは各ルートの`open_ambient_dir`の一点のみ、TOCTOUを型で封じる
//! 原則を維持）。`read.mode`（whitelist既定/blacklist）の反転、`read.deny`/`read.deny_descend`
//! による除外・掘り下げ禁止を実装する。

use std::path::{Path, PathBuf};

use cap_std::fs::Dir;
use harness_core::{ReadMode, ReadScopeConfig};

use crate::{check_relative_path, JailError};

#[derive(Debug, thiserror::Error)]
pub enum ReadScopeError {
    #[error("path is not within an allowed read root: {0}")]
    NotAllowed(String),
    #[error("path is denied by read scope config: {0}")]
    Denied(String),
    #[error(transparent)]
    Jail(#[from] JailError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

struct ExternalRoot {
    root: PathBuf,
    dir: Dir,
    /// `true`なら`read.allow_descend`（再帰読取可）、`false`なら`read.allow`（直下のみ）。
    descend: bool,
}

/// 外部絶対パスの読取スコープ判定。workspace内の走査filterには`is_denied_rel`/
/// `should_skip_descend`を使い、`WorkspaceJail::walk_files_filtered`と組み合わせる。
pub struct ReadScope {
    mode: ReadMode,
    roots: Vec<ExternalRoot>,
    deny: Vec<String>,
    deny_descend: Vec<String>,
}

impl ReadScope {
    /// 設定に基づき外部ルートを開く。個々のルートが存在しない/開けない場合はそのルートを
    /// 静かにスキップする（設定ファイルの記述ミスで起動全体を止めない、`harness-config`と
    /// 同じ「fail-fastはシークレット欠落時のみ」の原則）。
    pub fn open(config: &ReadScopeConfig) -> Self {
        let mut roots = Vec::new();
        for root in &config.allow {
            if let Ok(dir) = Dir::open_ambient_dir(root, cap_std::ambient_authority()) {
                roots.push(ExternalRoot {
                    root: root.clone(),
                    dir,
                    descend: false,
                });
            }
        }
        for root in &config.allow_descend {
            if let Ok(dir) = Dir::open_ambient_dir(root, cap_std::ambient_authority()) {
                roots.push(ExternalRoot {
                    root: root.clone(),
                    dir,
                    descend: true,
                });
            }
        }
        Self {
            mode: config.mode,
            roots,
            deny: config.deny.clone(),
            deny_descend: config.deny_descend.clone(),
        }
    }

    /// このディレクトリ名は掘り下げ禁止か（`read.deny_descend`、whitelist/blacklist共通）。
    pub fn should_skip_descend(&self, dir_name: &str) -> bool {
        self.deny_descend.iter().any(|d| d == dir_name)
    }

    /// `WorkspaceJail::walk_files_filtered`にそのまま渡せる掘り下げ禁止名の一覧。
    pub fn deny_descend_names(&self) -> Vec<String> {
        self.deny_descend.clone()
    }

    /// workspace相対パスの各階層いずれかが`read.deny`/`read.deny_descend`の名前に一致すれば
    /// 除外する（grep/glob結果からの事後フィルタ用）。
    pub fn is_denied_rel(&self, rel: &Path) -> bool {
        rel.components().any(|c| {
            if let std::path::Component::Normal(part) = c {
                let s = part.to_string_lossy();
                self.deny.iter().any(|d| d == s.as_ref())
                    || self.deny_descend.iter().any(|d| d == s.as_ref())
            } else {
                false
            }
        })
    }

    /// 外部絶対パス`abs_path`を読む（openat相当、cap-std `Dir`経由）。
    pub fn read_external_to_string(&self, abs_path: &Path) -> Result<String, ReadScopeError> {
        match self.mode {
            ReadMode::Whitelist => {
                let (root, rel) = self.find_allow_root(abs_path)?;
                Ok(root.dir.read_to_string(&rel)?)
            }
            ReadMode::Blacklist => {
                if self.is_denied_abs(abs_path) {
                    return Err(ReadScopeError::Denied(abs_path.display().to_string()));
                }
                let parent = abs_path
                    .parent()
                    .ok_or_else(|| ReadScopeError::NotAllowed(abs_path.display().to_string()))?;
                let file_name = abs_path
                    .file_name()
                    .ok_or_else(|| ReadScopeError::NotAllowed(abs_path.display().to_string()))?;
                let dir = Dir::open_ambient_dir(parent, cap_std::ambient_authority())
                    .map_err(|_| ReadScopeError::NotAllowed(abs_path.display().to_string()))?;
                let rel = check_relative_path(&file_name.to_string_lossy())?;
                Ok(dir.read_to_string(&rel)?)
            }
        }
    }

    fn find_allow_root(&self, abs_path: &Path) -> Result<(&ExternalRoot, PathBuf), ReadScopeError> {
        let mut best: Option<(&ExternalRoot, PathBuf)> = None;
        for root in &self.roots {
            let Ok(rel) = abs_path.strip_prefix(&root.root) else {
                continue;
            };
            if rel.as_os_str().is_empty() {
                continue; // ルート自体はファイルではない
            }
            if !root.descend && rel.components().count() != 1 {
                // read.allow（直下のみ）: ネストしたパスは拒否
                continue;
            }
            let candidate_len = root.root.as_os_str().len();
            let better = best
                .as_ref()
                .map(|(r, _)| r.root.as_os_str().len() < candidate_len)
                .unwrap_or(true);
            if better {
                best = Some((root, rel.to_path_buf()));
            }
        }
        best.ok_or_else(|| ReadScopeError::NotAllowed(abs_path.display().to_string()))
    }

    fn is_denied_abs(&self, abs_path: &Path) -> bool {
        let normalized = abs_path.to_string_lossy().replace('\\', "/");
        let by_prefix = self.deny.iter().any(|d| {
            let dn = d.replace('\\', "/");
            normalized == dn || normalized.starts_with(&format!("{dn}/"))
        });
        by_prefix || self.is_denied_rel(abs_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harness_core::ReadScopeConfig;

    fn config(mode: ReadMode) -> ReadScopeConfig {
        ReadScopeConfig {
            mode,
            ..Default::default()
        }
    }

    #[test]
    fn whitelist_denies_external_path_without_configured_root() {
        let external = tempfile::tempdir().unwrap();
        std::fs::write(external.path().join("secret.txt"), "top secret").unwrap();

        let scope = ReadScope::open(&config(ReadMode::Whitelist));
        let err = scope
            .read_external_to_string(&external.path().join("secret.txt"))
            .unwrap_err();
        assert!(matches!(err, ReadScopeError::NotAllowed(_)));
    }

    #[test]
    fn whitelist_allow_root_reads_direct_child_only() {
        let external = tempfile::tempdir().unwrap();
        std::fs::write(external.path().join("a.txt"), "direct").unwrap();
        std::fs::create_dir_all(external.path().join("sub")).unwrap();
        std::fs::write(external.path().join("sub/b.txt"), "nested").unwrap();

        let scope = ReadScope::open(&ReadScopeConfig {
            mode: ReadMode::Whitelist,
            allow: vec![external.path().to_path_buf()],
            ..Default::default()
        });

        assert_eq!(
            scope
                .read_external_to_string(&external.path().join("a.txt"))
                .unwrap(),
            "direct"
        );
        let err = scope
            .read_external_to_string(&external.path().join("sub/b.txt"))
            .unwrap_err();
        assert!(matches!(err, ReadScopeError::NotAllowed(_)));
    }

    #[test]
    fn whitelist_allow_descend_root_reads_nested_files() {
        let external = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(external.path().join("sub")).unwrap();
        std::fs::write(external.path().join("sub/b.txt"), "nested").unwrap();

        let scope = ReadScope::open(&ReadScopeConfig {
            mode: ReadMode::Whitelist,
            allow_descend: vec![external.path().to_path_buf()],
            ..Default::default()
        });

        assert_eq!(
            scope
                .read_external_to_string(&external.path().join("sub/b.txt"))
                .unwrap(),
            "nested"
        );
    }

    #[test]
    fn blacklist_allows_external_path_by_default() {
        let external = tempfile::tempdir().unwrap();
        std::fs::write(external.path().join("a.txt"), "content").unwrap();

        let scope = ReadScope::open(&config(ReadMode::Blacklist));
        assert_eq!(
            scope
                .read_external_to_string(&external.path().join("a.txt"))
                .unwrap(),
            "content"
        );
    }

    #[test]
    fn blacklist_denies_configured_path() {
        let external = tempfile::tempdir().unwrap();
        std::fs::write(external.path().join("secret.txt"), "top secret").unwrap();
        let target = external.path().join("secret.txt");

        let scope = ReadScope::open(&ReadScopeConfig {
            mode: ReadMode::Blacklist,
            deny: vec![target.to_string_lossy().replace('\\', "/")],
            ..Default::default()
        });

        let err = scope.read_external_to_string(&target).unwrap_err();
        assert!(matches!(err, ReadScopeError::Denied(_)));
    }

    #[test]
    fn deny_descend_matches_workspace_relative_component() {
        let scope = ReadScope::open(&ReadScopeConfig {
            deny_descend: vec!["node_modules".to_string()],
            ..Default::default()
        });
        assert!(scope.should_skip_descend("node_modules"));
        assert!(scope.is_denied_rel(Path::new("node_modules/pkg/index.js")));
        assert!(!scope.is_denied_rel(Path::new("src/main.rs")));
    }
}
