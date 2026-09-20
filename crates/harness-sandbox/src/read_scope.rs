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

/// 照合の前に綴りの揺れを畳む。**設定の側も対象の側も、必ずこれを通してから比べる。**
///
/// 畳むのは3つ——区切りを`/`へ揃える・末尾の区切りを落とす・大小を潰す。
/// 大小を潰す理由は[`ReadScope::is_denied_rel`]のdocにある。
fn normalize_for_match(s: &str) -> String {
    let unified = s.replace('\\', "/");
    unified.trim_end_matches('/').to_lowercase()
}

/// 正規化済みの`path`が、正規化済みの`needle`そのものか、その配下か。
///
/// **単純な`starts_with`にしない**——`src/secret`が`src/secrets.txt`に当たってしまう
/// （`config_injection.rs`が同じ誤検知を同じ形で避けている）。
fn path_hits(path: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    path == needle || path.starts_with(&format!("{needle}/"))
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
    ///
    /// **ここは名前しか受け取らない**ので、パス形式（`src/generated`）の設定は当たらない。
    /// それで漏れないのは、走査の枝刈りが**速くするためのもの**で、保証は
    /// [`Self::is_denied_rel`]による事後フィルタが持っているためである
    /// （`overlay.rs`の`walk_files`は枝刈りのあとに必ず同じ判定を通す）。
    pub fn should_skip_descend(&self, dir_name: &str) -> bool {
        let name = normalize_for_match(dir_name);
        self.deny_descend
            .iter()
            .any(|d| normalize_for_match(d) == name)
    }

    /// `WorkspaceJail::walk_files_filtered`にそのまま渡せる掘り下げ禁止名の一覧。
    pub fn deny_descend_names(&self) -> Vec<String> {
        self.deny_descend.clone()
    }

    /// workspace相対パスが`read.deny`/`read.deny_descend`に当たるか
    /// （grep/glob結果からの事後フィルタ用・`read_to_string`のworkspace相対経路用）。
    ///
    /// # 2つの書き方を両方受ける（[BUG-124]）
    ///
    /// | 設定の綴り | 意味 |
    /// |---|---|
    /// | `secret.txt`（区切りを含まない） | **どの階層の**その名前にも当たる |
    /// | `src/secret.txt`（区切りを含む） | ワークスペースルートからの**その位置**（配下も含む） |
    ///
    /// **以前は名前の完全一致しか見ていなかった。** `Component::Normal`が区切りを含むことは
    /// 無いので、`src/secret.txt`と書いた設定は**構造上どの成分とも一致せず**、
    /// エラーにも警告にもならないまま素通りしていた（`B-10`: 無言の失敗）。
    ///
    /// # 大小を区別しない
    ///
    /// NTFS・APFSは既定で区別しないので、区別する判定にすると`.SSH`と書いた設定が
    /// 実体の`.ssh`に当たらない。Linuxでは本当に別物なので**過剰に拒否する側**へ倒れるが、
    /// deny listでは安全な向きである（`P-05`）。`config_injection.rs`が同じ理由で
    /// 同じ選択をしている。
    ///
    /// [BUG-124]: ../../../docs/bugs/BUG-124.md
    pub fn is_denied_rel(&self, rel: &Path) -> bool {
        let whole = normalize_for_match(&rel.to_string_lossy());
        let by_name = rel.components().any(|c| {
            if let std::path::Component::Normal(part) = c {
                let s = normalize_for_match(&part.to_string_lossy());
                self.denied_names().any(|d| d == s)
            } else {
                false
            }
        });
        by_name
            || self
                .denied_names()
                .any(|d| d.contains('/') && path_hits(&whole, &d))
    }

    /// `deny`と`deny_descend`を正規化して1本の列にする。**同じ判定を2度書かない**（`B-05`）。
    fn denied_names(&self) -> impl Iterator<Item = String> + '_ {
        self.deny
            .iter()
            .chain(self.deny_descend.iter())
            .map(|d| normalize_for_match(d))
    }

    /// 外部絶対パス`abs_path`を読む（openat相当、cap-std `Dir`経由）。
    pub fn read_external_to_string(&self, abs_path: &Path) -> Result<String, ReadScopeError> {
        // [BUG-124] **モードに依らず除外を先に通す。** 以前はWhitelist分岐が
        // `find_allow_root`を呼ぶだけで、`read.deny`が判定に一度も参加しなかった
        // ——`allow_descend`で開いた枝を`deny`で閉じ直せず、しかも
        // **効かない側が「安全既定」と呼ばれているwhitelist**だった。
        // 拒否が増える方向なので、既定を薄める変更ではない。
        if self.is_denied_abs(abs_path) {
            return Err(ReadScopeError::Denied(abs_path.display().to_string()));
        }
        match self.mode {
            ReadMode::Whitelist => {
                let (root, rel) = self.find_allow_root(abs_path)?;
                Ok(root.dir.read_to_string(&rel)?)
            }
            ReadMode::Blacklist => {
                // 除外判定は上の1箇所で済ませた（同じ判定を2度書かない、`B-05`）。
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
        let normalized = normalize_for_match(&abs_path.to_string_lossy());
        let by_prefix = self
            .deny
            .iter()
            .any(|d| path_hits(&normalized, &normalize_for_match(d)));
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

    // -----------------------------------------------------------------------
    // [BUG-124] `read.deny`の意味を1つに揃えた分。**許可側と禁止側を対で置く**（`B-35`）
    // -----------------------------------------------------------------------

    /// 許可側——区切りを含む綴りは、ワークスペースルートからの位置として当たる。
    ///
    /// **以前はここが無言で外れていた。** `Component::Normal`は区切りを含まないので、
    /// `src/secret.txt`はどの成分とも一致せず、警告も出ないまま読めていた。
    #[test]
    fn a_path_shaped_deny_entry_now_matches_that_position() {
        let scope = ReadScope::open(&ReadScopeConfig {
            deny: vec!["src/secret.txt".to_string()],
            ..config(ReadMode::Whitelist)
        });
        assert!(scope.is_denied_rel(Path::new("src/secret.txt")));
        assert!(
            scope.is_denied_rel(Path::new("src\\secret.txt")),
            "Windowsの区切りで綴られた対象にも当たること"
        );
    }

    /// 禁止側——位置が違えば当たらない。**「区切りを含めば何にでも当たる」実装でも
    /// 上のテストだけは通る**ので、こちらが要る。
    #[test]
    fn a_path_shaped_deny_entry_does_not_match_a_different_position() {
        let scope = ReadScope::open(&ReadScopeConfig {
            deny: vec!["src/secret.txt".to_string()],
            ..config(ReadMode::Whitelist)
        });
        assert!(!scope.is_denied_rel(Path::new("docs/src/secret.txt")));
        assert!(!scope.is_denied_rel(Path::new("src/secret.txt.bak")));
        assert!(!scope.is_denied_rel(Path::new("src/other.txt")));
    }

    /// 区切りを含まない綴りは、従来どおり**どの階層でも**当たる（既存の意味を壊していない）。
    #[test]
    fn a_name_shaped_deny_entry_still_matches_at_any_depth() {
        let scope = ReadScope::open(&ReadScopeConfig {
            deny: vec!["secret.txt".to_string()],
            ..config(ReadMode::Whitelist)
        });
        assert!(scope.is_denied_rel(Path::new("secret.txt")));
        assert!(scope.is_denied_rel(Path::new("a/b/secret.txt")));
        assert!(!scope.is_denied_rel(Path::new("a/secret.txt.bak")));
    }

    /// 大小を区別しない。Windowsでは`.SSH`と書いた設定が実体の`.ssh`に当たらないと、
    /// **設定した本人は閉じたつもりで開いている**。
    #[test]
    fn deny_matching_ignores_case() {
        let scope = ReadScope::open(&ReadScopeConfig {
            deny: vec![".SSH".to_string()],
            ..config(ReadMode::Whitelist)
        });
        assert!(scope.is_denied_rel(Path::new("home/.ssh/id_rsa")));
    }

    /// 許可側——既定モード（whitelist）でも、`allow_descend`で開いた枝を`deny`で閉じ直せる。
    /// **これが症状Aそのものである。**
    #[test]
    fn whitelist_now_applies_deny_inside_an_allowed_external_root() {
        let external = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(external.path().join(".ssh")).unwrap();
        std::fs::write(external.path().join(".ssh/id_rsa"), "private key").unwrap();

        let scope = ReadScope::open(&ReadScopeConfig {
            allow_descend: vec![external.path().to_path_buf()],
            deny: vec![".ssh".to_string()],
            ..config(ReadMode::Whitelist)
        });
        let err = scope
            .read_external_to_string(&external.path().join(".ssh/id_rsa"))
            .unwrap_err();
        assert!(
            matches!(err, ReadScopeError::Denied(_)),
            "whitelistでもdenyが効くこと。得たもの: {err:?}"
        );
    }

    /// 禁止側——除外に当たらないものは、同じ設定のまま読める。
    /// **これが無いと「whitelistで全部拒否する」実装でも上のテストが通る。**
    #[test]
    fn whitelist_still_reads_what_deny_does_not_cover() {
        let external = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(external.path().join(".ssh")).unwrap();
        std::fs::write(external.path().join("notes.txt"), "ordinary").unwrap();

        let scope = ReadScope::open(&ReadScopeConfig {
            allow_descend: vec![external.path().to_path_buf()],
            deny: vec![".ssh".to_string()],
            ..config(ReadMode::Whitelist)
        });
        let text = scope
            .read_external_to_string(&external.path().join("notes.txt"))
            .expect("除外に当たらないものは読めること");
        assert_eq!(text, "ordinary");
    }

    /// 正規化と前方一致の検算。**`starts_with`だけの実装は`src/secrets.txt`を誤検知する。**
    #[test]
    fn path_hits_requires_a_separator_at_the_boundary() {
        assert!(path_hits("src/secret", "src/secret"));
        assert!(path_hits("src/secret/a.txt", "src/secret"));
        assert!(!path_hits("src/secrets.txt", "src/secret"));
        assert!(!path_hits("src/secret", ""));
        assert_eq!(normalize_for_match("Src\\Secret\\"), "src/secret");
    }
}
