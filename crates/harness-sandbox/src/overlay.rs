//! `SandboxFs`: 書込リダイレクト・read-through・変更マニフェスト・論理削除（tombstone）。
//! `plans/DESIGN.md` §オーバーレイFS・§書込ステージング3モード 参照（M10）。
//!
//! パーミッション層（`RiskClass`/`PermissionArbiter`）とは直交する: `SandboxFs`は
//! 「許可された書込の実FS効果をどこへ落とすか」だけを決め、実行してよいかどうかは
//! 一切判定しない（そちらは`harness-engine::PermissionArbiter`が唯一の強制点として担う）。
//!
//! オーバーレイの実体（`tree/`・`_ext/`・`manifest.jsonl`）は常に`StagingConfig.sandbox_dir`
//! （workspace_rootからの相対パス）配下、すなわちworkspace内に置く。これにより`WorkspaceJail`
//! （cap-std主ゲート）1つだけで実FS・オーバーレイの両方を仲介でき、新たなambient authorityを
//! 増やさずに済む。workspace外の絶対パス（例 `C:\Windows\probe.txt`）だけは、オーバーレイ
//! 実体こそworkspace内（`_ext/c/Windows/probe.txt`）に置きつつ、`apply`時に実際へ書く際は
//! `std::fs`でその絶対パスへ直接触れる（jailの外なので、そこだけ意図的なambient access）。

use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use cap_std::fs::File;
use cap_std::time::SystemTime;
use harness_core::{ReadScopeConfig, StagingConfig, StagingMode};

use crate::manifest::{self, ManifestEntry, ManifestOp, ManifestTarget};
use crate::read_scope::ReadScope;
use crate::{check_relative_path, git, JailError, WorkspaceJail};

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error(transparent)]
    Jail(#[from] JailError),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    ReadScope(#[from] crate::read_scope::ReadScopeError),
}

fn hash_content(content: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    content.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn normalize_str(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// `C:\Windows\probe.txt` → `c/Windows/probe.txt`、`/etc/passwd` → `etc/passwd` のように、
/// workspace外の絶対パスをオーバーレイ内の一意な相対キーへ写像する。UNC前置・予約デバイス名・
/// ADS構文は`check_relative_path`（既存のjail主ゲート補助チェック）にそのまま委譲して拒否する
/// （§ツールシステム fsジェイル「Windowsパスの罠を明示拒否」と同じ判定を再利用）。
fn ext_key(path: &str) -> Result<String, JailError> {
    let normalized = path.replace('\\', "/");
    if normalized.starts_with("//") {
        return Err(JailError::UnsafePath(format!(
            "UNC path is not allowed: {path}"
        )));
    }
    let bytes = normalized.as_bytes();
    if bytes.len() > 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/' {
        let drive = (bytes[0] as char).to_ascii_lowercase();
        let rest = &normalized[3..];
        check_relative_path(rest)?;
        return Ok(format!("{drive}/{rest}"));
    }
    if let Some(rest) = normalized.strip_prefix('/') {
        check_relative_path(rest)?;
        return Ok(rest.to_string());
    }
    Err(JailError::Escape(path.to_string()))
}

/// `pattern`に単一`*`（複数可）を含む素朴なglobマッチ。`AllowlistRule`と同系統の簡易実装
/// （M10のスコープでは`--only`の絞り込みに足りれば十分、`globset`級の完全なglob文法は不要）。
fn simple_glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == text;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0usize;
    let last = parts.len() - 1;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !text[pos..].starts_with(part) {
                return false;
            }
            pos += part.len();
        } else if i == last {
            return text[pos..].ends_with(part);
        } else {
            match text[pos..].find(part) {
                Some(idx) => pos += idx + part.len(),
                None => return false,
            }
        }
    }
    true
}

enum Target {
    /// 実FSへ直接（liveモード実効時）。
    Live { rel: PathBuf },
    /// workspace内・オーバーレイ経由。
    Tree { rel: PathBuf },
    /// workspace外・オーバーレイ経由（`_ext/`）。
    Ext { key: String, original: String },
}

/// `changes()`が返す1件（レビュー対象、`apply`/`discard`の単位）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChangeEntry {
    pub op: ManifestOp,
    pub target: ManifestTarget,
    pub path: String,
    pub overlay_path: String,
    pub baseline_hash: Option<String>,
    pub new_hash: Option<String>,
}

pub struct ApplyOptions<'a> {
    /// 選択適用フィルタ（`AllowlistRule`同様の`*`ワイルドカード）。`None`なら全件対象。
    /// CLIの`--only <glob>`向け。
    pub only_glob: Option<&'a str>,
    /// 選択適用フィルタ（完全一致のパス集合）。TUI変更パネルのファイル毎accept/reject向け
    /// （globでは非連続な複数ファイルの選択を表現しづらいため）。`only_glob`と併用時はAND。
    pub only_paths: Option<&'a [String]>,
    /// `_ext/`（workspace外ターゲット）を実際に適用してよいか（`--dangerously-allow`相当）。
    pub allow_ext: bool,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ApplyReport {
    pub applied: Vec<String>,
    /// baseline照合の相違により拒否されたパス（DESIGN「相違なら適用拒否→再レビュー要求」）。
    pub conflicts: Vec<String>,
    /// `_ext`ターゲットだが`allow_ext`が無かったため拒否されたパス。
    pub ext_blocked: Vec<String>,
    /// D-09（`plans/DESIGN-SANDBOX.md` §7）: 設定注入パス（`.git/config`・`.harness/**`等）への
    /// 変更のため層3 hard-denyで拒否されたパス。overlay経由の`.git/config`/`.harness/**`
    /// コミットを、実行前ゲート（`permission.rs::classify()`）をバイパスされた場合でも
    /// apply時に再度塞ぐ（T-11対策）。
    pub hard_denied: Vec<String>,
}

/// 書込リダイレクト・read-through・マニフェスト・tombstoneを仲介するオーバーレイFS。
/// `ToolCtx.staging.sandbox_dir`が`None`（`StagingConfig::default()`）なら、内部の
/// `WorkspaceJail`をそのまま素通しする純live実装として振る舞う（M9までの既存挙動と等価）。
pub struct SandboxFs {
    jail: WorkspaceJail,
    workspace_root: PathBuf,
    sandbox_dir: Option<PathBuf>,
    mode: StagingMode,
    explicit: bool,
    read_scope: ReadScope,
}

impl SandboxFs {
    pub fn open(workspace_root: &Path, staging: &StagingConfig) -> Result<Self, SandboxError> {
        Self::open_with_read_scope(workspace_root, staging, &ReadScopeConfig::default())
    }

    /// `read.allow`/`read.allow_descend`/`read.deny`/`read.deny_descend`（M11）を
    /// 反映した`SandboxFs`を開く。
    pub fn open_with_read_scope(
        workspace_root: &Path,
        staging: &StagingConfig,
        read_scope_config: &ReadScopeConfig,
    ) -> Result<Self, SandboxError> {
        let jail = WorkspaceJail::open(workspace_root)?;
        Ok(Self {
            jail,
            workspace_root: workspace_root.to_path_buf(),
            sandbox_dir: staging.sandbox_dir.clone(),
            mode: staging.mode,
            explicit: staging.explicit,
            read_scope: ReadScope::open(read_scope_config),
        })
    }

    fn manifest_path(&self) -> Option<PathBuf> {
        self.sandbox_dir.as_ref().map(|d| d.join("manifest.jsonl"))
    }

    fn tree_overlay_rel(&self, rel: &Path) -> PathBuf {
        self.sandbox_dir
            .as_ref()
            .expect("sandbox_dir present")
            .join("tree")
            .join(rel)
    }

    fn ext_overlay_rel(&self, key: &str) -> PathBuf {
        self.sandbox_dir
            .as_ref()
            .expect("sandbox_dir present")
            .join("_ext")
            .join(key)
    }

    /// git認識型の既定判定（`explicit`時はそのまま`self.mode`）。
    fn effective_mode(&self, rel: &Path) -> StagingMode {
        if self.explicit {
            return self.mode;
        }
        if git::is_clean_tracked(&self.workspace_root, rel) {
            StagingMode::Live
        } else {
            self.mode
        }
    }

    fn classify_for_write(&self, path: &str) -> Result<Target, SandboxError> {
        let p = Path::new(path);
        if p.is_absolute() {
            if self.sandbox_dir.is_none() || self.mode == StagingMode::Live {
                // liveモード（またはオーバーレイ無効）はworkspace外書込を一切許さない
                // （§ツールシステム fsジェイル、既存のWorkspaceJailと同じくEscapeで拒否）。
                return Err(SandboxError::Jail(JailError::Escape(path.to_string())));
            }
            let key = ext_key(path)?;
            return Ok(Target::Ext {
                key,
                original: path.replace('\\', "/"),
            });
        }
        let rel = check_relative_path(path)?;
        if self.sandbox_dir.is_none() {
            return Ok(Target::Live { rel });
        }
        match self.effective_mode(&rel) {
            StagingMode::Live => Ok(Target::Live { rel }),
            StagingMode::Staged | StagingMode::WorkspaceCommit => Ok(Target::Tree { rel }),
        }
    }

    fn append_entry(&self, entry: ManifestEntry) -> Result<(), SandboxError> {
        let Some(manifest_rel) = self.manifest_path() else {
            return Ok(());
        };
        let existing = self
            .jail
            .read_to_string(&normalize_str(&manifest_rel))
            .unwrap_or_default();
        let mut updated = existing;
        if !updated.is_empty() && !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str(
            &serde_json::to_string(&entry)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
        );
        updated.push('\n');
        self.jail.write_string(&normalize_str(&manifest_rel), &updated)?;
        Ok(())
    }

    fn log_live_audit(&self, rel: &Path, content: &str) {
        if self.sandbox_dir.is_none() {
            return;
        }
        let _ = self.append_entry(ManifestEntry {
            op: ManifestOp::Modify,
            target: ManifestTarget::Live,
            path: normalize_str(rel),
            overlay_path: String::new(),
            baseline_hash: None,
            new_hash: Some(hash_content(content)),
            ts_unix_millis: manifest::now_millis(),
        });
    }

    fn folded_entries(&self) -> Result<Vec<ManifestEntry>, SandboxError> {
        let Some(manifest_rel) = self.manifest_path() else {
            return Ok(Vec::new());
        };
        let raw = match self.jail.read_to_string(&normalize_str(&manifest_rel)) {
            Ok(s) => s,
            Err(JailError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Vec::new())
            }
            Err(e) => return Err(e.into()),
        };
        let mut latest: std::collections::HashMap<(ManifestTarget, String), ManifestEntry> =
            Default::default();
        for line in raw.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: ManifestEntry = serde_json::from_str(line)
                .map_err(|e| SandboxError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
            latest.insert((entry.target, entry.path.clone()), entry);
        }
        Ok(latest.into_values().collect())
    }

    fn latest_tree_entry(&self, rel: &Path) -> Result<Option<ManifestEntry>, SandboxError> {
        let rel_str = normalize_str(rel);
        Ok(self
            .folded_entries()?
            .into_iter()
            .find(|e| e.target == ManifestTarget::Tree && e.path == rel_str))
    }

    /// レビュー対象の変更一覧（`Live`監査エントリは除く、§オーバーレイFS「レビュー＆コミット」）。
    pub fn change_set(&self) -> Result<Vec<ChangeEntry>, SandboxError> {
        Ok(self
            .folded_entries()?
            .into_iter()
            .filter(|e| e.target != ManifestTarget::Live)
            .map(|e| ChangeEntry {
                op: e.op,
                target: e.target,
                path: e.path,
                overlay_path: e.overlay_path,
                baseline_hash: e.baseline_hash,
                new_hash: e.new_hash,
            })
            .collect())
    }

    /// ワークスペース内へ書き込む。`path`が絶対パスなら`_ext/`へ、相対パスは実効モードに
    /// 応じて実FS直書き（live）かオーバーレイ（tree）かへ振り分ける。
    pub fn write_string(&self, path: &str, content: &str) -> Result<(), SandboxError> {
        match self.classify_for_write(path)? {
            Target::Live { rel } => {
                self.jail.write_string(&normalize_str(&rel), content)?;
                self.log_live_audit(&rel, content);
                Ok(())
            }
            Target::Tree { rel } => {
                let overlay_rel = self.tree_overlay_rel(&rel);
                let baseline_hash = self
                    .jail
                    .read_to_string(&normalize_str(&rel))
                    .ok()
                    .map(|s| hash_content(&s));
                self.jail.write_string(&normalize_str(&overlay_rel), content)?;
                let op = if baseline_hash.is_none() {
                    ManifestOp::Create
                } else {
                    ManifestOp::Modify
                };
                self.append_entry(ManifestEntry {
                    op,
                    target: ManifestTarget::Tree,
                    path: normalize_str(&rel),
                    overlay_path: normalize_str(&overlay_rel),
                    baseline_hash,
                    new_hash: Some(hash_content(content)),
                    ts_unix_millis: manifest::now_millis(),
                })
            }
            Target::Ext { key, original } => {
                let overlay_rel = self.ext_overlay_rel(&key);
                let baseline_hash = std::fs::read_to_string(Path::new(&original))
                    .ok()
                    .map(|s| hash_content(&s));
                self.jail.write_string(&normalize_str(&overlay_rel), content)?;
                let op = if baseline_hash.is_none() {
                    ManifestOp::Create
                } else {
                    ManifestOp::Modify
                };
                self.append_entry(ManifestEntry {
                    op,
                    target: ManifestTarget::Ext,
                    path: original,
                    overlay_path: normalize_str(&overlay_rel),
                    baseline_hash,
                    new_hash: Some(hash_content(content)),
                    ts_unix_millis: manifest::now_millis(),
                })
            }
        }
    }

    /// read-through: オーバーレイに版があればそれ、無ければ実FS。tombstone済みは`NotFound`。
    /// 絶対パスは`read.allow`/`read.allow_descend`（whitelist）または`read.deny`未該当
    /// （blacklist）の場合のみ`ReadScope`経由で読める（M11、`plans/DESIGN-SANDBOX.md` §5）。
    /// オーバーレイ（`_ext`）は書込のみが対象（読取は常に実FSを直接見る）。
    pub fn read_to_string(&self, path: &str) -> Result<String, SandboxError> {
        if Path::new(path).is_absolute() {
            return Ok(self.read_scope.read_external_to_string(Path::new(path))?);
        }
        let rel = check_relative_path(path)?;
        if self.read_scope.is_denied_rel(&rel) {
            return Err(SandboxError::NotFound(path.to_string()));
        }
        if self.sandbox_dir.is_none() {
            return Ok(self.jail.read_to_string(path)?);
        }
        match self.latest_tree_entry(&rel)? {
            Some(entry) if entry.op == ManifestOp::Delete => {
                Err(SandboxError::NotFound(path.to_string()))
            }
            Some(entry) => Ok(self.jail.read_to_string(&entry.overlay_path)?),
            None => Ok(self.jail.read_to_string(path)?),
        }
    }

    /// 論理削除（tombstone）。M10時点でこれを発火する組み込みツールは無く、`SandboxFs`単体の
    /// 契約として提供する（§オーバーレイFS「論理削除（tombstone）」）。
    pub fn remove(&self, path: &str) -> Result<(), SandboxError> {
        if self.sandbox_dir.is_none() {
            return Err(SandboxError::NotFound(
                "staging is not enabled for this ToolCtx (live-only)".to_string(),
            ));
        }
        let rel = check_relative_path(path)?;
        let baseline_hash = self.read_to_string(path).ok().map(|s| hash_content(&s));
        self.append_entry(ManifestEntry {
            op: ManifestOp::Delete,
            target: ManifestTarget::Tree,
            path: normalize_str(&rel),
            overlay_path: String::new(),
            baseline_hash,
            new_hash: None,
            ts_unix_millis: manifest::now_millis(),
        })
    }

    /// grep/glob用: 実FSファイルとオーバーレイ(tree)ファイルの和集合（tombstone除外）を、
    /// workspace_rootからの相対パスで返す。`read.deny_descend`配下は掘り下げず、
    /// `read.deny`/`read.deny_descend`に一致するパスは結果からも除外する（M11）。
    pub fn walk_files(&self) -> Result<Vec<PathBuf>, SandboxError> {
        let skip_dirs = self.read_scope.deny_descend_names();
        let mut set: BTreeSet<String> = self
            .jail
            .walk_files_filtered(&skip_dirs)?
            .into_iter()
            .map(|p| normalize_str(&p))
            .collect();
        if self.sandbox_dir.is_some() {
            for c in self.change_set()? {
                if c.target != ManifestTarget::Tree {
                    continue;
                }
                if c.op == ManifestOp::Delete {
                    set.remove(&c.path);
                } else {
                    set.insert(c.path);
                }
            }
        }
        set.retain(|p| !self.read_scope.is_denied_rel(Path::new(p)));
        Ok(set.into_iter().map(PathBuf::from).collect())
    }

    /// grep用: read-throughで実効内容を持つファイルハンドルを開く。
    pub fn open_file_for_read(&self, path: &str) -> Result<File, SandboxError> {
        let rel = check_relative_path(path)?;
        if self.sandbox_dir.is_some() {
            if let Some(entry) = self.latest_tree_entry(&rel)? {
                if entry.op == ManifestOp::Delete {
                    return Err(SandboxError::NotFound(path.to_string()));
                }
                return Ok(self.jail.open_file(&entry.overlay_path)?);
            }
        }
        Ok(self.jail.open_file(path)?)
    }

    /// glob用: read-throughで実効mtimeを返す。
    pub fn modified(&self, path: &str) -> Result<SystemTime, SandboxError> {
        let rel = check_relative_path(path)?;
        if self.sandbox_dir.is_some() {
            if let Some(entry) = self.latest_tree_entry(&rel)? {
                if entry.op != ManifestOp::Delete {
                    return Ok(self.jail.modified(&entry.overlay_path)?);
                }
            }
        }
        Ok(self.jail.modified(path)?)
    }

    /// ステージ済み変更を実FSへ選択適用する。in-workspace分は`WorkspaceJail`
    /// （cap-std＋予約名/ADS検査）を必ず通し、`_ext`（workspace外）は`opts.allow_ext`が
    /// 無ければ拒否する（§オーバーレイFS「apply は live 書込と同一の…ゲートを必ず通す」）。
    pub fn apply(&self, opts: &ApplyOptions) -> Result<ApplyReport, SandboxError> {
        let mut report = ApplyReport::default();
        let entries = self.change_set()?;
        let mut applied_keys: Vec<(ManifestTarget, String)> = Vec::new();

        for e in &entries {
            if let Some(glob) = opts.only_glob {
                if !simple_glob_match(glob, &e.path) {
                    continue;
                }
            }
            if let Some(paths) = opts.only_paths {
                if !paths.iter().any(|p| p == &e.path) {
                    continue;
                }
            }
            if e.target == ManifestTarget::Ext && !opts.allow_ext {
                report.ext_blocked.push(e.path.clone());
                continue;
            }
            if harness_core::is_config_injection_path(&e.path) {
                report.hard_denied.push(e.path.clone());
                continue;
            }

            let current_hash = match e.target {
                ManifestTarget::Tree => self.jail.read_to_string(&e.path).ok().map(|s| hash_content(&s)),
                ManifestTarget::Ext => std::fs::read_to_string(Path::new(&e.path))
                    .ok()
                    .map(|s| hash_content(&s)),
                ManifestTarget::Live => None,
            };
            if current_hash != e.baseline_hash {
                // baseline照合の相違（サイレントなlost update / TOCTOU防止）。
                // §オーバーレイFS「相違なら適用拒否→再レビュー要求」。
                report.conflicts.push(e.path.clone());
                continue;
            }

            let result: Result<(), SandboxError> = match (e.target, e.op) {
                (ManifestTarget::Tree, ManifestOp::Delete) => {
                    self.jail.remove_file(&e.path).map_err(Into::into)
                }
                (ManifestTarget::Tree, _) => {
                    let content = self.jail.read_to_string(&e.overlay_path)?;
                    self.jail.write_string(&e.path, &content).map_err(Into::into)
                }
                (ManifestTarget::Ext, ManifestOp::Delete) => {
                    std::fs::remove_file(Path::new(&e.path)).map_err(Into::into)
                }
                (ManifestTarget::Ext, _) => {
                    let content = self.jail.read_to_string(&e.overlay_path)?;
                    let target_path = Path::new(&e.path);
                    if let Some(parent) = target_path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(target_path, content).map_err(Into::into)
                }
                (ManifestTarget::Live, _) => Ok(()),
            };
            result?;
            report.applied.push(e.path.clone());
            applied_keys.push((e.target, e.path.clone()));
        }

        if !applied_keys.is_empty() {
            self.prune_manifest(&applied_keys)?;
        }
        Ok(report)
    }

    /// 適用済みエントリをマニフェストから除去する（再適用/永続的な"pending"表示を防ぐ）。
    fn prune_manifest(&self, applied: &[(ManifestTarget, String)]) -> Result<(), SandboxError> {
        let Some(manifest_rel) = self.manifest_path() else {
            return Ok(());
        };
        let raw = self
            .jail
            .read_to_string(&normalize_str(&manifest_rel))
            .unwrap_or_default();
        let mut out = String::new();
        for line in raw.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: ManifestEntry = serde_json::from_str(line)
                .map_err(|e| SandboxError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
            if applied
                .iter()
                .any(|(t, p)| *t == entry.target && p == &entry.path)
            {
                continue;
            }
            out.push_str(&serde_json::to_string(&entry).expect("ManifestEntry serializes"));
            out.push('\n');
        }
        self.jail.write_string(&normalize_str(&manifest_rel), &out)?;
        Ok(())
    }

    /// ステージ済み変更を全て破棄する（sandbox_dir自体を削除、§オーバーレイFS「discard」）。
    pub fn discard(&self) -> Result<(), SandboxError> {
        let Some(dir) = &self.sandbox_dir else {
            return Ok(());
        };
        Ok(self.jail.remove_dir_all(&normalize_str(dir))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harness_core::StagingConfig;

    fn staged_config(sandbox_dir: &str) -> StagingConfig {
        StagingConfig {
            mode: StagingMode::Staged,
            explicit: true,
            sandbox_dir: Some(PathBuf::from(sandbox_dir)),
        }
    }

    #[test]
    fn live_default_behaves_like_bare_jail() {
        let dir = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(dir.path(), &StagingConfig::default()).unwrap();
        fs.write_string("a.txt", "hello").unwrap();
        assert_eq!(std::fs::read_to_string(dir.path().join("a.txt")).unwrap(), "hello");
        assert_eq!(fs.read_to_string("a.txt").unwrap(), "hello");
        assert!(fs.change_set().unwrap().is_empty());
    }

    #[test]
    fn staged_in_workspace_write_does_not_touch_real_fs_and_reads_through() {
        let dir = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();

        fs.write_string("newfile.txt", "staged content").unwrap();

        assert!(!dir.path().join("newfile.txt").exists(), "real FS must stay untouched");
        assert_eq!(fs.read_to_string("newfile.txt").unwrap(), "staged content");
        let changes = fs.change_set().unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].target, ManifestTarget::Tree);
        assert_eq!(changes[0].op, ManifestOp::Create);
        assert_eq!(changes[0].path, "newfile.txt");
    }

    #[cfg(windows)]
    #[test]
    fn staged_absolute_windows_path_redirects_to_ext_without_touching_real_fs() {
        let dir = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();
        let target = r"C:\Windows\harness_m10_probe.txt";

        fs.write_string(target, "probe").unwrap();

        assert!(!Path::new(target).exists(), "real C:\\Windows must stay untouched");
        let changes = fs.change_set().unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].target, ManifestTarget::Ext);
        assert_eq!(changes[0].path, "C:/Windows/harness_m10_probe.txt");
        let overlay_abs = dir.path().join(&changes[0].overlay_path);
        assert!(overlay_abs.exists());
        assert_eq!(std::fs::read_to_string(overlay_abs).unwrap(), "probe");
    }

    #[test]
    fn live_mode_rejects_absolute_path_writes() {
        let dir = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(
            dir.path(),
            &StagingConfig {
                mode: StagingMode::Live,
                explicit: true,
                sandbox_dir: Some(PathBuf::from(".harness/sandbox/s1")),
            },
        )
        .unwrap();
        #[cfg(windows)]
        let abs = r"C:\Windows\x";
        #[cfg(not(windows))]
        let abs = "/etc/passwd";
        let err = fs.write_string(abs, "x").unwrap_err();
        assert!(matches!(err, SandboxError::Jail(JailError::Escape(_))));
    }

    #[test]
    fn tombstone_marks_deleted_and_read_returns_not_found() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("existing.txt"), "orig").unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();

        fs.remove("existing.txt").unwrap();

        assert!(dir.path().join("existing.txt").exists(), "tombstone must not physically delete");
        let err = fs.read_to_string("existing.txt").unwrap_err();
        assert!(matches!(err, SandboxError::NotFound(_)));
        let changes = fs.change_set().unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].op, ManifestOp::Delete);
    }

    #[test]
    fn apply_only_selected_file_reflects_to_real_fs_and_prunes_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();
        fs.write_string("keep.txt", "keep-content").unwrap();
        fs.write_string("skip.txt", "skip-content").unwrap();

        let report = fs
            .apply(&ApplyOptions {
                only_glob: Some("keep.txt"),
                only_paths: None,
                allow_ext: false,
            })
            .unwrap();

        assert_eq!(report.applied, vec!["keep.txt".to_string()]);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("keep.txt")).unwrap(),
            "keep-content"
        );
        assert!(!dir.path().join("skip.txt").exists());

        let remaining = fs.change_set().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].path, "skip.txt");
    }

    #[test]
    fn apply_rejects_ext_target_without_allow_ext() {
        let dir = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();
        #[cfg(windows)]
        let abs = r"C:\Windows\harness_m10_apply_probe.txt";
        #[cfg(not(windows))]
        let abs = "/tmp/harness_m10_apply_probe.txt";
        fs.write_string(abs, "x").unwrap();

        let report = fs
            .apply(&ApplyOptions {
                only_glob: None,
                only_paths: None,
                allow_ext: false,
            })
            .unwrap();

        assert!(report.applied.is_empty());
        assert_eq!(report.ext_blocked.len(), 1);
        assert!(!Path::new(abs).exists());
    }

    #[test]
    fn apply_hard_denies_staged_git_config_write() {
        let dir = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();
        fs.write_string(".git/config", "[core]\n\thooksPath = /tmp/evil\n").unwrap();

        let report = fs
            .apply(&ApplyOptions {
                only_glob: None,
                only_paths: None,
                allow_ext: false,
            })
            .unwrap();

        assert!(report.applied.is_empty());
        assert_eq!(report.hard_denied, vec![".git/config".to_string()]);
        assert!(!dir.path().join(".git/config").exists());
    }

    #[test]
    fn apply_hard_denies_staged_harness_settings_write() {
        let dir = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();
        fs.write_string(
            ".harness/settings.json",
            "{\"allowlist\":[{\"tool\":\"run_shell\",\"pattern\":\"*\"}]}",
        )
        .unwrap();

        let report = fs
            .apply(&ApplyOptions {
                only_glob: None,
                only_paths: None,
                allow_ext: false,
            })
            .unwrap();

        assert!(report.applied.is_empty());
        assert_eq!(
            report.hard_denied,
            vec![".harness/settings.json".to_string()]
        );
    }

    #[test]
    fn apply_allows_normal_file_alongside_hard_denied_config_write() {
        let dir = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();
        fs.write_string("src/main.rs", "fn main() {}").unwrap();
        fs.write_string(".gitattributes", "* text=auto").unwrap();

        let report = fs
            .apply(&ApplyOptions {
                only_glob: None,
                only_paths: None,
                allow_ext: false,
            })
            .unwrap();

        assert_eq!(report.applied, vec!["src/main.rs".to_string()]);
        assert_eq!(report.hard_denied, vec![".gitattributes".to_string()]);
        assert!(dir.path().join("src/main.rs").exists());
        assert!(!dir.path().join(".gitattributes").exists());
    }

    #[test]
    fn apply_detects_conflict_when_real_file_changed_since_baseline() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("shared.txt"), "original").unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();
        fs.write_string("shared.txt", "staged-edit").unwrap();

        // apply前に「外部」から実FSを直接変更（同時編集・レース状況を模す）。
        std::fs::write(dir.path().join("shared.txt"), "changed-by-someone-else").unwrap();

        let report = fs
            .apply(&ApplyOptions {
                only_glob: None,
                only_paths: None,
                allow_ext: false,
            })
            .unwrap();

        assert!(report.applied.is_empty());
        assert_eq!(report.conflicts, vec!["shared.txt".to_string()]);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("shared.txt")).unwrap(),
            "changed-by-someone-else",
            "conflicting apply must not overwrite"
        );
    }

    #[test]
    fn discard_removes_all_staged_changes() {
        let dir = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();
        fs.write_string("a.txt", "x").unwrap();
        assert!(!fs.change_set().unwrap().is_empty());

        fs.discard().unwrap();

        assert!(!dir.path().join(".harness/sandbox/s1").exists());
        assert!(fs.change_set().unwrap().is_empty());
    }

    #[test]
    fn walk_files_includes_staged_new_file_and_excludes_tombstoned() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("real.txt"), "r").unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();
        fs.write_string("staged_new.txt", "n").unwrap();
        fs.remove("real.txt").unwrap();

        let mut files: Vec<String> = fs
            .walk_files()
            .unwrap()
            .into_iter()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .collect();
        files.sort();

        assert_eq!(files, vec!["staged_new.txt".to_string()]);
    }

    /// M11受入テスト: `read.deny_descend`配下はwalkできない（grep/globが中身を返さない）。
    #[test]
    fn walk_files_skips_deny_descend_directories() {
        use harness_core::ReadScopeConfig;

        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules/pkg")).unwrap();
        std::fs::write(dir.path().join("node_modules/pkg/index.js"), "x").unwrap();
        std::fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

        let fs = SandboxFs::open_with_read_scope(
            dir.path(),
            &StagingConfig::default(),
            &ReadScopeConfig {
                deny_descend: vec!["node_modules".to_string()],
                ..Default::default()
            },
        )
        .unwrap();

        let files: Vec<String> = fs
            .walk_files()
            .unwrap()
            .into_iter()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .collect();
        assert_eq!(files, vec!["main.rs".to_string()]);
    }

    /// M11受入テスト: `..`による外部脱出はread/writeいずれの経路でも不可（回帰確認）。
    #[test]
    fn read_and_write_reject_parent_dir_escape_regardless_of_read_scope() {
        use harness_core::{ReadMode, ReadScopeConfig};

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().parent().unwrap().join("m11_outside.txt"),
            "secret",
        )
        .unwrap();

        let fs = SandboxFs::open_with_read_scope(
            dir.path(),
            &StagingConfig::default(),
            &ReadScopeConfig {
                mode: ReadMode::Blacklist,
                ..Default::default()
            },
        )
        .unwrap();

        let err = fs.read_to_string("../m11_outside.txt").unwrap_err();
        assert!(matches!(err, SandboxError::Jail(JailError::Escape(_))));
        let err = fs.write_string("../m11_outside.txt", "x").unwrap_err();
        assert!(matches!(err, SandboxError::Jail(JailError::Escape(_))));
    }
}
