//! `SandboxFs`: 書込リダイレクト・read-through・変更台帳・論理削除（tombstone）。
//! `plans/DESIGN.md` §オーバーレイFS・§書込ステージング3モード 参照（M10）。
//!
//! パーミッション層（`RiskClass`/`PermissionArbiter`）とは直交する: `SandboxFs`は
//! 「許可された書込の実FS効果をどこへ落とすか」だけを決め、実行してよいかどうかは
//! 一切判定しない（そちらは`harness-engine::PermissionArbiter`が唯一の強制点として担う）。
//!
//! **CoW一本化（Phase 2、`plans/AppContainerベース Copy-on-Write ワークスペース設計書.md`
//! §19）**: `--staged`/`--workspace-commit`（オーバーレイあり・強制力なし・レビュー用）と
//! `--cow`（オーバーレイあり・workspace本体RO ACLで強制・Tier2a限定）は、以前は別々の
//! 保存形式（`tree/`・`_ext/`・`manifest.jsonl` vs `.harness-cow-ops.jsonl`操作台帳）を
//! 持っていたが、今は**単一のオーバーレイディレクトリ + 操作台帳
//! （`harness_change_ledger::store`、Redirector DLLと共有）**という同じ表現に統一されている。
//! 違いは「オーバーレイディレクトリがworkspace内（`--staged`）かworkspace外（`--cow`）か」と
//! 「ACLによる強制があるか（Tier2a `--cow`のみ）」だけであり、`SandboxFs`自身はその区別を
//! 一切気にしない——両モードとも`overlay: Option<OverlayBackend>`という同じフィールドで
//! 表現され、書込・読取・削除・列挙・commit（apply）・破棄（discard）は完全に同一のコードで
//! 処理される。
//!
//! オーバーレイの実体アクセスは、`overlay.dir`（workspace内外どちらもありうる絶対パス）に対して
//! 開いた専用の`WorkspaceJail`（cap-std主ゲート、openat相当）に統一する。操作台帳・baseline
//! ミラーの読み書き自体は`harness_change_ledger::store`が`std::fs`で直接行う（DLLが生の
//! Win32/NT APIで同じファイルを触るため、host側だけcap-stdに閉じ込めても対称性がなく、
//! 台帳形式を完全に共有する既定路線と矛盾するため）。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use cap_std::fs::File;
use cap_std::time::SystemTime;
use harness_change_ledger::{store, ChangeOp};
use harness_core::{ReadScopeConfig, StagingConfig, StagingMode};

use crate::read_scope::ReadScope;
use crate::{check_relative_path, JailError, WorkspaceJail};

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

fn normalize_str(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// `pattern`に単一`*`（複数可）を含む素朴なglobマッチ。`AllowlistRule`と同系統の簡易実装
/// （M10のスコープでは`--only`の絞り込みに足りれば十分、`globset`級の完全なglob文法は不要）。
pub(crate) fn simple_glob_match(pattern: &str, text: &str) -> bool {
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

/// `--staged`/`--cow`いずれかが有効なときの唯一のオーバーレイ実体。`dir`は絶対パス
/// （`--staged`ならworkspace内`<workspace_root>/<sandbox_dir>`、`--cow`ならworkspace外の
/// CoW upperディレクトリ）。
struct OverlayBackend {
    dir: PathBuf,
    jail: WorkspaceJail,
}

/// `changes()`が返す1件（レビュー対象、`apply`/`discard`の単位）。stagedもCoWも同じ形。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChangeEntry {
    pub op: ChangeOp,
    pub path: String,
    pub baseline_hash: Option<String>,
    /// 台帳の`path`が相対パスとして受け付けられない場合の理由（[BUG-062](../../docs/bugs/BUG-062.md)）。
    ///
    /// `Some`のエントリを`apply`は必ず拒否する。**それでも一覧からは消さない**——見た目が
    /// 普通の相対パスに見える値（`x/../.git/config`）を黙って隠すと、ユーザは「何も無かった」と
    /// 解釈してしまう。理由を添えて見せるのは`harness policy suggest`の`[too-broad]`と同じ扱いで、
    /// D-43「失敗を隠さない」に従う。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected: Option<String>,
}

pub struct ApplyOptions<'a> {
    /// 選択適用フィルタ（`AllowlistRule`同様の`*`ワイルドカード）。`None`なら全件対象。
    /// CLIの`--only <glob>`向け。
    pub only_glob: Option<&'a str>,
    /// 選択適用フィルタ（完全一致のパス集合）。TUI変更パネルのファイル毎accept/reject向け
    /// （globでは非連続な複数ファイルの選択を表現しづらいため）。`only_glob`と併用時はAND。
    pub only_paths: Option<&'a [String]>,
    /// workspace外ターゲットを実際に適用してよいか（`--dangerously-allow`相当）。Phase 2時点では
    /// workspace外書込自体を`write_string`が受け付けないため常に無効（Phase 3で復活予定）。
    pub allow_ext: bool,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ApplyReport {
    pub applied: Vec<String>,
    /// baseline照合の相違により拒否されたパス（DESIGN「相違なら適用拒否→再レビュー要求」）。
    pub conflicts: Vec<String>,
    /// workspace外ターゲットだが`allow_ext`が無かったため拒否されたパス。Phase 2時点では
    /// workspace外書込自体が無いため常に空（Phase 3で復活予定）。
    pub ext_blocked: Vec<String>,
    /// D-09（`plans/DESIGN-SANDBOX.md` §7）: 設定注入パス（`.git/config`・`.harness/**`等）への
    /// 変更のため層3 hard-denyで拒否されたパス。overlay経由の`.git/config`/`.harness/**`
    /// コミットを、実行前ゲート（`permission.rs::classify()`）をバイパスされた場合でも
    /// apply時に再度塞ぐ（T-11対策）。
    pub hard_denied: Vec<String>,
    /// 台帳の`path`が相対パスとして受け付けられない形だったため拒否したエントリと、その理由
    /// （[BUG-062](../../docs/bugs/BUG-062.md)）。`hard_denied`と分けているのは**原因が違う**
    /// ため——あちらは「形としては正しいパスだが書いてはいけない場所」、こちらは
    /// 「パスの形そのものが不正＝台帳が改竄されたか壊れている」である。運用上の対処も違う
    /// （前者はレビューして諦める、後者は台帳を疑う）。
    pub rejected: Vec<(String, String)>,
}

/// 書込リダイレクト・read-through・操作台帳・tombstoneを仲介するオーバーレイFS。
/// `overlay`が`None`（純live、`StagingConfig::default()`かつ`cow_upper_dir=None`）なら、
/// 内部の`WorkspaceJail`をそのまま素通しする（M9までの既存挙動と等価）。
pub struct SandboxFs {
    jail: WorkspaceJail,
    workspace_root: PathBuf,
    overlay: Option<OverlayBackend>,
    read_scope: ReadScope,
}

impl SandboxFs {
    pub fn open(workspace_root: &Path, staging: &StagingConfig) -> Result<Self, SandboxError> {
        Self::open_with_read_scope(workspace_root, staging, &ReadScopeConfig::default())
    }

    /// `read.allow`/`read.allow_descend`/`read.deny`/`read.deny_descend`（M11）を
    /// 反映した`SandboxFs`を開く。`--cow`のCoWオーバーレイは使わない（`cow_upper_dir=None`
    /// 相当）、`ToolCtx.cow_upper_dir`を運べる呼び出し元は`open_with_cow`を使うこと。
    pub fn open_with_read_scope(
        workspace_root: &Path,
        staging: &StagingConfig,
        read_scope_config: &ReadScopeConfig,
    ) -> Result<Self, SandboxError> {
        Self::open_with_cow(workspace_root, staging, read_scope_config, None)
    }

    /// `ToolCtx.cow_upper_dir`をそのまま渡して`SandboxFs`を開く（host内蔵ツール
    /// write_file/edit_file/read_file/grep/glob向け）。`Some`なら、workspace内相対パスへの
    /// 書込/読取/削除/列挙はRedirector DLLと同じupperディレクトリ・同じ操作台帳
    /// （`.harness-cow-ops.jsonl`）を経由する。`None`かつ`staging.mode`が`Staged`/
    /// `WorkspaceCommit`なら、`staging.sandbox_dir`（workspace相対）をworkspace内オーバーレイ
    /// として同じ経路で使う（`--cow`と`--staged`はCLI起動時に排他化されているため、両方
    /// 有効になることは実運用上ない、Phase 0の`conflicts_with_all`）。
    pub fn open_with_cow(
        workspace_root: &Path,
        staging: &StagingConfig,
        read_scope_config: &ReadScopeConfig,
        cow_upper_dir: Option<&Path>,
    ) -> Result<Self, SandboxError> {
        let jail = WorkspaceJail::open(workspace_root)?;
        let overlay_dir: Option<PathBuf> = match cow_upper_dir {
            Some(dir) => Some(dir.to_path_buf()),
            None => match staging.mode {
                StagingMode::Live => None,
                StagingMode::Staged | StagingMode::WorkspaceCommit => staging
                    .sandbox_dir
                    .as_ref()
                    .map(|rel| workspace_root.join(rel)),
            },
        };
        let overlay = match overlay_dir {
            Some(dir) => {
                std::fs::create_dir_all(&dir)?;
                Some(OverlayBackend {
                    jail: WorkspaceJail::open(&dir)?,
                    dir,
                })
            }
            None => None,
        };
        Ok(Self {
            jail,
            workspace_root: workspace_root.to_path_buf(),
            overlay,
            read_scope: ReadScope::open(read_scope_config),
        })
    }

    /// レビュー対象の変更一覧（`--staged`/`--cow`いずれも同じ形。オーバーレイ無効なら空）。
    pub fn change_set(&self) -> Result<Vec<ChangeEntry>, SandboxError> {
        let Some(overlay) = &self.overlay else {
            return Ok(Vec::new());
        };
        Ok(store::replay_ledger(&overlay.dir)
            .into_iter()
            .map(|c| {
                // `_ext`（絶対パス）は`store::ext_key`が別途検証する経路なので、ここでの
                // 相対パス判定にはかけない（かけると全件が「不正」になる）。
                let rejected = if Path::new(&c.path).is_absolute() {
                    store::ext_key(&c.path).err()
                } else {
                    ledger_path_rejection(&c.path).err()
                };
                ChangeEntry {
                    op: c.op,
                    path: c.path,
                    baseline_hash: c.baseline_hash,
                    rejected,
                }
            })
            .collect())
    }

    /// ワークスペース内へ書き込む。オーバーレイ無効ならworkspace実体へ直書き、有効なら
    /// オーバーレイディレクトリ・操作台帳へ記録する。workspace外の絶対パスはオーバーレイ有効時
    /// のみ`_ext/<key>`（`store::ext_key`）へ記録する（Phase 3）。オーバーレイ無効（純live）
    /// なら既存のLive挙動どおり拒否する。
    pub fn write_string(&self, path: &str, content: &str) -> Result<(), SandboxError> {
        if Path::new(path).is_absolute() {
            let Some(overlay) = &self.overlay else {
                return Err(SandboxError::Jail(JailError::Escape(path.to_string())));
            };
            let original = store::normalize_abs_path(path);
            let key = store::ext_key(&original)
                .map_err(|e| SandboxError::Jail(JailError::UnsafePath(e)))?;
            let baseline_hash = store::baseline_hash_and_mirror_ext(&overlay.dir, &original, &key);
            overlay.jail.write_string(&format!("_ext/{key}"), content)?;
            let op = if baseline_hash.is_none() {
                ChangeOp::Create
            } else {
                ChangeOp::Modify
            };
            store::append_entry(&overlay.dir, op, &original, baseline_hash);
            return Ok(());
        }
        let rel = check_relative_path(path)?;
        match &self.overlay {
            None => Ok(self.jail.write_string(&normalize_str(&rel), content)?),
            Some(overlay) => {
                let rel_str = normalize_str(&rel);
                let baseline_hash =
                    store::baseline_hash_and_mirror(&overlay.dir, &self.workspace_root, &rel_str);
                overlay.jail.write_string(&rel_str, content)?;
                let op = if baseline_hash.is_none() {
                    ChangeOp::Create
                } else {
                    ChangeOp::Modify
                };
                store::append_entry(&overlay.dir, op, &rel_str, baseline_hash);
                Ok(())
            }
        }
    }

    /// read-through: オーバーレイに版があればそれ、無ければ実FS。tombstone済みは`NotFound`。
    /// 絶対パスは`read.allow`/`read.allow_descend`（whitelist）または`read.deny`未該当
    /// （blacklist）の場合のみ`ReadScope`経由で読める（M11、`plans/DESIGN-SANDBOX.md` §5）。
    pub fn read_to_string(&self, path: &str) -> Result<String, SandboxError> {
        if Path::new(path).is_absolute() {
            if let Some(overlay) = &self.overlay {
                let original = store::normalize_abs_path(path);
                if let Ok(key) = store::ext_key(&original) {
                    if store::deleted_set(&overlay.dir).contains(&original) {
                        return Err(SandboxError::NotFound(path.to_string()));
                    }
                    match overlay.jail.read_to_string(&format!("_ext/{key}")) {
                        Ok(s) => return Ok(s),
                        Err(JailError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            return Ok(self.read_scope.read_external_to_string(Path::new(path))?);
        }
        let rel = check_relative_path(path)?;
        if self.read_scope.is_denied_rel(&rel) {
            return Err(SandboxError::NotFound(path.to_string()));
        }
        let Some(overlay) = &self.overlay else {
            return Ok(self.jail.read_to_string(path)?);
        };
        let rel_str = normalize_str(&rel);
        if store::deleted_set(&overlay.dir).contains(&rel_str) {
            return Err(SandboxError::NotFound(path.to_string()));
        }
        match overlay.jail.read_to_string(&rel_str) {
            Ok(s) => Ok(s),
            Err(JailError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(self.jail.read_to_string(path)?)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// 論理削除（tombstone）。オーバーレイが無効な純live構成では使えない
    /// （`SandboxFs`単体の契約として提供、§オーバーレイFS「論理削除（tombstone）」）。
    pub fn remove(&self, path: &str) -> Result<(), SandboxError> {
        let Some(overlay) = &self.overlay else {
            return Err(SandboxError::NotFound(
                "staging is not enabled for this ToolCtx (live-only)".to_string(),
            ));
        };
        if Path::new(path).is_absolute() {
            let original = store::normalize_abs_path(path);
            let key = store::ext_key(&original)
                .map_err(|e| SandboxError::Jail(JailError::UnsafePath(e)))?;
            let baseline_hash = store::baseline_hash_and_mirror_ext(&overlay.dir, &original, &key);
            store::append_entry(&overlay.dir, ChangeOp::Delete, &original, baseline_hash);
            return Ok(());
        }
        let rel = check_relative_path(path)?;
        let rel_str = normalize_str(&rel);
        let baseline_hash =
            store::baseline_hash_and_mirror(&overlay.dir, &self.workspace_root, &rel_str);
        store::append_entry(&overlay.dir, ChangeOp::Delete, &rel_str, baseline_hash);
        Ok(())
    }

    /// grep/glob用: 実FSファイルとオーバーレイファイルの和集合（tombstone除外）を、
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
        if let Some(overlay) = &self.overlay {
            for c in store::replay_ledger(&overlay.dir) {
                // `_ext`（workspace外絶対パス）エントリはworkspace相対のファイル一覧に含めない
                // （grep/globはworkspace内を対象とする）。
                if Path::new(&c.path).is_absolute() {
                    continue;
                }
                if c.op == ChangeOp::Delete {
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
        let Some(overlay) = &self.overlay else {
            return Ok(self.jail.open_file(path)?);
        };
        let rel_str = normalize_str(&rel);
        if store::deleted_set(&overlay.dir).contains(&rel_str) {
            return Err(SandboxError::NotFound(path.to_string()));
        }
        match overlay.jail.open_file(&rel_str) {
            Ok(f) => Ok(f),
            Err(JailError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(self.jail.open_file(path)?)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// glob用: read-throughで実効mtimeを返す。
    pub fn modified(&self, path: &str) -> Result<SystemTime, SandboxError> {
        let rel = check_relative_path(path)?;
        let Some(overlay) = &self.overlay else {
            return Ok(self.jail.modified(path)?);
        };
        let rel_str = normalize_str(&rel);
        if store::deleted_set(&overlay.dir).contains(&rel_str) {
            return Ok(self.jail.modified(path)?);
        }
        match overlay.jail.modified(&rel_str) {
            Ok(t) => Ok(t),
            Err(JailError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(self.jail.modified(path)?)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// オーバーレイ済み変更を実FSへ選択適用する（`--staged`/`--cow`共通、
    /// §オーバーレイFS「apply は live 書込と同一の…ゲートを必ず通す」）。
    pub fn apply(&self, opts: &ApplyOptions) -> Result<ApplyReport, SandboxError> {
        let Some(overlay) = &self.overlay else {
            return Ok(ApplyReport::default());
        };
        apply_overlay_changes(&self.jail, overlay, opts)
    }

    /// オーバーレイ側の現在内容を読む（`resolve`の`mine`側材料）。
    pub fn overlay_content(&self, path: &str) -> Option<String> {
        let overlay = self.overlay.as_ref()?;
        store::read_overlay_content(&overlay.dir, path)
    }

    /// baselineミラーがあれば読む（`resolve`の`base`側材料。無ければ`None`）。
    pub fn baseline_mirror_content(&self, path: &str) -> Option<String> {
        let overlay = self.overlay.as_ref()?;
        store::read_baseline_mirror(&overlay.dir, path)
    }

    /// 実workspace側の現在内容（`resolve`の`theirs`側材料）。
    pub fn real_content(&self, path: &str) -> Option<String> {
        self.jail.read_to_string(path).ok()
    }

    /// `resolve`が3-way mergeの結果を確定させる: 実workspaceへ書き、オーバーレイ実体・
    /// 台帳エントリを除去する（`apply()`の該当ステップを単一エントリに適用したもの）。
    pub fn finalize_resolved(&self, path: &str, content: &str) -> Result<(), SandboxError> {
        self.jail.write_string(path, content)?;
        if let Some(overlay) = &self.overlay {
            let overlay_abs = store::upper_path_for(&overlay.dir, path);
            let _ = std::fs::remove_file(&overlay_abs);
            store::prune_ledger(&overlay.dir, std::slice::from_ref(&path.to_string()));
        }
        Ok(())
    }

    /// オーバーレイ済み変更を全て破棄する（オーバーレイディレクトリ自体を削除、
    /// §オーバーレイFS「discard」）。`self`を消費する——`overlay.jail`はオーバーレイ
    /// ディレクトリ自身に対して開いた`cap_std::fs::Dir`ハンドルを保持しており、
    /// Windowsでは開いたハンドルを持つディレクトリを削除できない
    /// （`ERROR_SHARING_VIOLATION`）ため、削除前に明示的にハンドルを閉じる必要がある。
    pub fn discard(mut self) -> Result<(), SandboxError> {
        let Some(overlay) = self.overlay.take() else {
            return Ok(());
        };
        drop(overlay.jail);
        std::fs::remove_dir_all(&overlay.dir)?;
        Ok(())
    }
}

/// `apply()`の実体。`--staged`/`--cow`で別々に実装していたロジック（旧`SandboxFs::apply`・
/// `changes.rs::apply_cow_changes`）をここへ一本化した（Phase 2）。
///
/// **workspace側・overlay側とも、必ず`WorkspaceJail`（cap-stdの`Dir`からの相対open＝
/// openat相当）を経由する。** 生の`std::fs`とパス結合でこれを行っていたのが
/// [BUG-062](../../docs/bugs/BUG-062.md)——操作台帳`.harness-cow-ops.jsonl`はupper_dir配下に
/// あってサンドボックス子へ書込可能なので、`c.path`は**敵対者が任意に決められる文字列**である。
/// 検証せずに`workspace_root.join(&c.path)`すると、`..`ひとつでworkspace外へユーザ権限で
/// 書けてしまい、`is_config_injection_path`（前置詞一致）も`x/../.git/config`で素通りした。
///
/// jail経由にすることで、パスの形（`..`・UNC・ADS・予約デバイス名）と、reparse pointを
/// 辿ってjail外へ出る経路（設計書§17）の両方が同じ1つの機構で閉じる。
fn apply_overlay_changes(
    jail: &WorkspaceJail,
    overlay: &OverlayBackend,
    opts: &ApplyOptions,
) -> Result<ApplyReport, SandboxError> {
    let mut report = ApplyReport::default();
    let changes = store::replay_ledger(&overlay.dir);
    let mut applied_paths: Vec<String> = Vec::new();

    for c in &changes {
        if let Some(glob) = opts.only_glob {
            if !simple_glob_match(glob, &c.path) {
                continue;
            }
        }
        if let Some(paths) = opts.only_paths {
            if !paths.iter().any(|p| p == &c.path) {
                continue;
            }
        }
        let is_ext = Path::new(&c.path).is_absolute();
        if is_ext && !opts.allow_ext {
            report.ext_blocked.push(c.path.clone());
            continue;
        }

        // 台帳の値が相対パスとして受け付けられる形かを、実FSへ触る前に確かめる。
        // ここを通ってはじめて、後段の`is_config_injection_path`（正規化前の前置詞一致）が
        // 「正規化済みの相対パスしか来ない」という前提を持てる（BUG-062の層2）。
        if !is_ext {
            if let Err(reason) = ledger_path_rejection(&c.path) {
                report.rejected.push((c.path.clone(), reason));
                continue;
            }
        }
        if harness_core::is_config_injection_path(&c.path) {
            report.hard_denied.push(c.path.clone());
            continue;
        }

        // baseline照合（サイレントなlost update / TOCTOU防止、§オーバーレイFS
        // 「相違なら適用拒否→再レビュー要求」）。workspace側の読取もjail経由。
        let current_hash = if is_ext {
            std::fs::read(&c.path)
                .ok()
                .map(|b| harness_change_ledger::hash_bytes(&b))
        } else {
            jail.read_bytes(&c.path)
                .ok()
                .map(|b| harness_change_ledger::hash_bytes(&b))
        };
        if current_hash != c.baseline_hash {
            report.conflicts.push(c.path.clone());
            continue;
        }

        let outcome = if is_ext {
            apply_ext_entry(overlay, c)
        } else {
            apply_workspace_entry(jail, overlay, c)
        };
        match outcome {
            Ok(()) => {
                report.applied.push(c.path.clone());
                applied_paths.push(c.path.clone());
            }
            // ジェイルが拒んだ1件は、バッチ全体を止めずにそのエントリの結果として記録する。
            // ここに来る代表例が**overlay内に仕込まれたreparse point**で、cap-stdは
            // `PermissionDenied("a path led outside of the filesystem")`で拒む（実測）。
            // 1件の細工で正当な変更のcommitまで巻き添えにすると、攻撃者に「applyを永久に
            // 妨害する」手段を与えることになる（可用性側の劣化）。
            //
            // 他のI/Oエラー（`_ext`分岐の生の`std::fs`等）は従来どおり致命として伝播させる
            // ——そちらは「この1件が悪い」という判断材料が無い。
            Err(SandboxError::Jail(e)) => {
                report.rejected.push((c.path.clone(), e.to_string()));
            }
            Err(other) => return Err(other),
        }
    }

    if !applied_paths.is_empty() {
        store::prune_ledger(&overlay.dir, &applied_paths);
    }
    Ok(report)
}

/// 台帳の相対パスが受け付けられない理由（`None`相当＝`Ok`なら受け付ける）。
/// 判定の実体は`harness_change_ledger::validate_relative_path`が持つ（`check_relative_path`と
/// 同じ関数。2箇所へ別々に書かない、`docs/CODE-STRUCTURE-RULES.md`規則5）。
fn ledger_path_rejection(path: &str) -> Result<(), String> {
    match harness_change_ledger::validate_relative_path(path) {
        Ok(_) => Ok(()),
        Err(harness_change_ledger::PathRejection::Escape) => {
            Err("path escapes the workspace root".to_string())
        }
        Err(harness_change_ledger::PathRejection::Unsafe(reason)) => Err(reason),
    }
}

/// workspace内エントリ1件の適用。読み書きとも`WorkspaceJail`（openat相当）に閉じる。
fn apply_workspace_entry(
    jail: &WorkspaceJail,
    overlay: &OverlayBackend,
    c: &harness_change_ledger::CowChange,
) -> Result<(), SandboxError> {
    match c.op {
        ChangeOp::Delete => {
            if jail.exists(&c.path) {
                jail.remove_file(&c.path)?;
            }
            Ok(())
        }
        ChangeOp::Create | ChangeOp::Modify => {
            if overlay.jail.is_dir(&c.path) {
                // ディレクトリ作成そのものの記録（例`mkdir sub`が台帳へCreateとして残る）。
                // 実体化するだけでよく、配下の個別ファイルエントリが引き続き同じ
                // overlayを参照するため、ここではoverlay側を消さない。
                jail.create_dir_all(&c.path)?;
                return Ok(());
            }
            let content = overlay.jail.read_bytes(&c.path)?;
            jail.write_bytes(&c.path, &content)?;
            // overlay側の実体を消しておかないと、Redirectorのcopy_upが「既にupperにある＝
            // このセッションで一度触った」と誤認して、次の変更を台帳へ記録しなくなる
            // （BUG-034）。ベストエフォート、失敗してもcommit自体は成功扱いにする。
            let _ = overlay.jail.remove_file(&c.path);
            Ok(())
        }
    }
}

/// workspace外絶対パス（`_ext`、Phase 3）エントリ1件の適用。
///
/// **宛先が意図的にworkspaceの外**なので、ここだけはjailに閉じられない（`allow_ext`＝
/// `--dangerously-allow`という別の門を通っている）。ただし**読取元はoverlayのjail経由**で、
/// パスは`store::ext_key`（`..`とUNCを拒否する）が導く`_ext/<key>`だけに限る。
fn apply_ext_entry(
    overlay: &OverlayBackend,
    c: &harness_change_ledger::CowChange,
) -> Result<(), SandboxError> {
    let key = store::ext_key(&c.path).map_err(|e| {
        SandboxError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
    })?;
    let rel = format!("_ext/{key}");
    let target = Path::new(&c.path);
    match c.op {
        ChangeOp::Delete => {
            if target.exists() {
                std::fs::remove_file(target)?;
            }
            Ok(())
        }
        ChangeOp::Create | ChangeOp::Modify => {
            if overlay.jail.is_dir(&rel) {
                std::fs::create_dir_all(target)?;
                return Ok(());
            }
            let content = overlay.jail.read_bytes(&rel)?;
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(target, &content)?;
            let _ = overlay.jail.remove_file(&rel);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harness_core::StagingConfig;

    fn staged_config(sandbox_dir: &str) -> StagingConfig {
        StagingConfig {
            mode: StagingMode::Staged,
            sandbox_dir: Some(PathBuf::from(sandbox_dir)),
        }
    }

    #[test]
    fn live_default_behaves_like_bare_jail() {
        let dir = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(dir.path(), &StagingConfig::default()).unwrap();
        fs.write_string("a.txt", "hello").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
            "hello"
        );
        assert_eq!(fs.read_to_string("a.txt").unwrap(), "hello");
        assert!(fs.change_set().unwrap().is_empty());
    }

    #[test]
    fn staged_in_workspace_write_does_not_touch_real_fs_and_reads_through() {
        let dir = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();

        fs.write_string("newfile.txt", "staged content").unwrap();

        assert!(
            !dir.path().join("newfile.txt").exists(),
            "real FS must stay untouched"
        );
        assert_eq!(fs.read_to_string("newfile.txt").unwrap(), "staged content");
        let changes = fs.change_set().unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].op, ChangeOp::Create);
        assert_eq!(changes[0].path, "newfile.txt");
    }

    #[test]
    fn staged_modify_writes_baseline_mirror_of_pre_edit_content() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "original").unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();

        fs.write_string("a.txt", "edited").unwrap();

        let baseline_abs = dir
            .path()
            .join(".harness/sandbox/s1/.harness-cow-baseline/a.txt");
        assert_eq!(std::fs::read_to_string(&baseline_abs).unwrap(), "original");
        // real workspace must stay untouched by staged writes.
        assert_eq!(std::fs::read_to_string(dir.path().join("a.txt")).unwrap(), "original");
    }

    #[test]
    fn staged_create_of_new_path_writes_no_baseline_mirror() {
        let dir = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();

        fs.write_string("newfile.txt", "staged content").unwrap();

        assert!(!dir
            .path()
            .join(".harness/sandbox/s1/.harness-cow-baseline/newfile.txt")
            .exists());
    }

    #[test]
    fn live_mode_rejects_absolute_path_writes() {
        let dir = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(
            dir.path(),
            &StagingConfig {
                mode: StagingMode::Live,
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

    #[cfg(windows)]
    fn ext_probe_path() -> (PathBuf, String) {
        // 実際に存在する一時ディレクトリ配下の絶対パスをプローブに使う（baselineハッシュの
        // 「実在するファイルの内容を読む」経路も一緒に検証するため）。
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("probe.txt");
        std::mem::forget(outside); // このテストの間だけ存在すればよいので、tempdirは意図的にリークする。
        (target.clone(), target.to_string_lossy().to_string())
    }
    #[cfg(not(windows))]
    fn ext_probe_path() -> (PathBuf, String) {
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("probe.txt");
        std::mem::forget(outside);
        (target.clone(), target.to_string_lossy().to_string())
    }

    /// Phase 3: `--staged`でもworkspace外絶対パスへの書込は`_ext/<key>`へ記録され、実FSには
    /// 触れない（`--cow`の`_ext`扱いと同じ経路、設計書§19.8）。
    #[test]
    fn staged_mode_redirects_absolute_path_writes_to_ext() {
        let dir = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();
        let (target, abs) = ext_probe_path();

        fs.write_string(&abs, "probe-content").unwrap();

        assert!(!target.exists(), "real target must stay untouched");
        assert_eq!(fs.read_to_string(&abs).unwrap(), "probe-content");
        let changes = fs.change_set().unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].op, ChangeOp::Create);
        assert_eq!(changes[0].path, harness_change_ledger::store::normalize_abs_path(&abs));
    }

    /// `apply`はworkspace外エントリを`allow_ext`無しでは`ext_blocked`へ回し、実際には書かない。
    #[test]
    fn apply_blocks_ext_entries_without_allow_ext() {
        let dir = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();
        let (target, abs) = ext_probe_path();
        fs.write_string(&abs, "probe-content").unwrap();

        let report = fs
            .apply(&ApplyOptions {
                only_glob: None,
                only_paths: None,
                allow_ext: false,
            })
            .unwrap();

        assert!(report.applied.is_empty());
        assert_eq!(report.ext_blocked.len(), 1);
        assert!(!target.exists());
    }

    /// `apply`が`allow_ext: true`のとき、実際にworkspace外の実ファイルへ書き込む。
    #[test]
    fn apply_writes_ext_entries_when_allow_ext_is_set() {
        let dir = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();
        let (target, abs) = ext_probe_path();
        fs.write_string(&abs, "probe-content").unwrap();

        let report = fs
            .apply(&ApplyOptions {
                only_glob: None,
                only_paths: None,
                allow_ext: true,
            })
            .unwrap();

        assert_eq!(
            report.applied,
            vec![harness_change_ledger::store::normalize_abs_path(&abs)]
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "probe-content");
    }

    #[test]
    fn tombstone_marks_deleted_and_read_returns_not_found() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("existing.txt"), "orig").unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();

        fs.remove("existing.txt").unwrap();

        assert!(
            dir.path().join("existing.txt").exists(),
            "tombstone must not physically delete"
        );
        let err = fs.read_to_string("existing.txt").unwrap_err();
        assert!(matches!(err, SandboxError::NotFound(_)));
        let changes = fs.change_set().unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].op, ChangeOp::Delete);
    }

    #[test]
    fn apply_only_selected_file_reflects_to_real_fs_and_prunes_ledger() {
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

        // 適用済み(`keep.txt`)のオーバーレイ実体は`apply`後に削除される一方、
        // 未適用のまま残る`skip.txt`のオーバーレイ実体はまだ削除されない
        // （次回applyやdiscardまで、レビュー対象としてオーバーレイディレクトリ配下に残る）。
        assert!(!dir.path().join(".harness/sandbox/s1/keep.txt").exists());
        assert!(dir.path().join(".harness/sandbox/s1/skip.txt").exists());
    }

    #[test]
    fn apply_hard_denies_staged_git_config_write() {
        let dir = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();
        fs.write_string(".git/config", "[core]\n\thooksPath = /tmp/evil\n")
            .unwrap();

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

    /// BUG-062の再現用: 「サンドボックス子が`<upper>/.harness-cow-ops.jsonl`へ直接書いた」
    /// 状況を作る。upper_dirはAppContainer子へ`grant_ace_inheritable_rw`で渡っているので
    /// （`win_appcontainer/preflight.rs`）、台帳の内容はP-01上ハーネスが信用してよい入力ではない。
    ///
    /// workspace_rootを`<tempdir>/root`に置くのは、`..`による脱出先を**同じtempdir内**に
    /// 収めるため（%TEMP%直下へ書き出すテストにしない）。
    fn tampered_ledger_fixture() -> (tempfile::TempDir, tempfile::TempDir, PathBuf, PathBuf) {
        let ws = tempfile::tempdir().unwrap();
        let upper_tmp = tempfile::tempdir().unwrap();
        let workspace_root = ws.path().join("root");
        let upper_dir = upper_tmp.path().join("upper");
        std::fs::create_dir_all(&workspace_root).unwrap();
        std::fs::create_dir_all(&upper_dir).unwrap();
        (ws, upper_tmp, workspace_root, upper_dir)
    }

    /// **BUG-062 (a)**: 台帳の相対パスに`..`が入っていると、`apply`がworkspace_rootの外へ
    /// ユーザ権限で書ける。`apply`はworkspaceの主ゲート（cap-stdの`WorkspaceJail`）を
    /// 通らなければならない。
    #[test]
    fn apply_refuses_ledger_paths_that_escape_the_workspace_root() {
        let (ws, upper_tmp, workspace_root, upper_dir) = tampered_ledger_fixture();
        // 敵対者がupper側に置いた実体。`upper_dir.join("../escape.txt")`がこれを指す。
        std::fs::write(upper_tmp.path().join("escape.txt"), "pwned").unwrap();
        store::append_entry(&upper_dir, ChangeOp::Create, "../escape.txt", None);

        let fs = SandboxFs::open_with_cow(
            &workspace_root,
            &StagingConfig::default(),
            &ReadScopeConfig::default(),
            Some(&upper_dir),
        )
        .unwrap();
        let report = fs
            .apply(&ApplyOptions {
                only_glob: None,
                only_paths: None,
                allow_ext: false,
            })
            .unwrap();

        assert!(
            report.applied.is_empty(),
            "an escaping ledger path must never be applied: {report:?}"
        );
        assert!(
            !ws.path().join("escape.txt").exists(),
            "apply wrote outside the workspace root (BUG-062)"
        );
    }

    /// **BUG-062 (b)**: D-09/P-08の層3 hard-denyは`is_config_injection_path`の前置詞一致で
    /// 判定しているため、`x/../.git/config`のように**正規化前は別の前置詞に見える**値で
    /// 素通りする。実FS上は`.git/config`へ着地するので、設定注入がapply経路から通る。
    #[test]
    fn apply_hard_deny_is_not_bypassable_by_a_parent_dir_segment() {
        let (_ws, _upper_tmp, workspace_root, upper_dir) = tampered_ledger_fixture();
        // `upper_dir.join("x/../.git/config")`＝`<upper>/.git/config`。
        std::fs::create_dir_all(upper_dir.join(".git")).unwrap();
        std::fs::write(
            upper_dir.join(".git/config"),
            "[core]\n\thooksPath = /tmp/evil\n",
        )
        .unwrap();
        store::append_entry(&upper_dir, ChangeOp::Create, "x/../.git/config", None);

        let fs = SandboxFs::open_with_cow(
            &workspace_root,
            &StagingConfig::default(),
            &ReadScopeConfig::default(),
            Some(&upper_dir),
        )
        .unwrap();
        let report = fs
            .apply(&ApplyOptions {
                only_glob: None,
                only_paths: None,
                allow_ext: false,
            })
            .unwrap();

        assert!(
            report.applied.is_empty(),
            "a config-injection path must never be applied: {report:?}"
        );
        assert!(
            !workspace_root.join(".git/config").exists(),
            "apply wrote .git/config through a `..` segment (BUG-062, D-09 bypass)"
        );
    }

    /// **BUG-062 (c) / 設計書§17（Reparse Point対策）**: upper側に置かれたjunctionを
    /// `apply`が辿ってはいけない。辿ると、ユーザ権限で走る信頼側が**upperの外の任意の
    /// ファイル**を読み、その内容をworkspace（＝サンドボックスから読める場所）へ落とす。
    ///
    /// junctionの作成には管理者権限もdeveloper modeも要らない（symlinkと違い
    /// `SeCreateSymbolicLinkPrivilege`を必要としない）ので、**このテストは通常の
    /// `cargo test`で走る**。
    #[cfg(windows)]
    #[test]
    fn apply_does_not_follow_a_junction_planted_in_the_overlay() {
        let (_ws, upper_tmp, workspace_root, upper_dir) = tampered_ledger_fixture();
        let secret_dir = upper_tmp.path().join("secrets");
        std::fs::create_dir_all(&secret_dir).unwrap();
        std::fs::write(secret_dir.join("id_rsa"), "TOP-SECRET-KEY").unwrap();

        // upper_dir/link -> upper_tmp/secrets（upperの外）へのjunction。
        let link = upper_dir.join("link");
        let status = std::process::Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                &link.to_string_lossy(),
                &secret_dir.to_string_lossy(),
            ])
            .output()
            .expect("run mklink");
        if !status.status.success() {
            // junctionが作れない環境ではこのテストは何も主張できない。黙って緑にせず、
            // 作れなかったという事実を出して飛ばす（推測で「対策済み」と書かないため）。
            eprintln!(
                "skipping: mklink /J failed on this machine: {}",
                String::from_utf8_lossy(&status.stderr)
            );
            return;
        }
        assert!(
            link.join("id_rsa").exists(),
            "the junction itself must resolve, otherwise this test proves nothing"
        );

        store::append_entry(&upper_dir, ChangeOp::Create, "link/id_rsa", None);

        let fs = SandboxFs::open_with_cow(
            &workspace_root,
            &StagingConfig::default(),
            &ReadScopeConfig::default(),
            Some(&upper_dir),
        )
        .unwrap();
        let report = fs
            .apply(&ApplyOptions {
                only_glob: None,
                only_paths: None,
                allow_ext: false,
            })
            .unwrap();

        let landed = workspace_root.join("link/id_rsa");
        assert!(
            !landed.exists(),
            "apply followed a junction out of the overlay and copied the secret into the \
             workspace (BUG-062 / 設計書§17). report={report:?}"
        );
        assert!(
            report.applied.is_empty(),
            "the junction entry must not count as applied: {report:?}"
        );
        // 1件の細工でバッチ全体が落ちるのではなく、そのエントリの結果として記録される。
        assert_eq!(
            report.rejected.len(),
            1,
            "the junction entry must be reported, not silently dropped: {report:?}"
        );
        assert_eq!(report.rejected[0].0, "link/id_rsa");
    }

    /// W1-4: applyが拒否する形のエントリは、一覧（`harness changes`・TUI変更パネル）から
    /// **消えてはいけない**。理由付きで見せる（D-43「失敗を隠さない」）。
    #[test]
    fn change_set_marks_malformed_paths_instead_of_hiding_them() {
        let (_ws, _upper_tmp, workspace_root, upper_dir) = tampered_ledger_fixture();
        store::append_entry(&upper_dir, ChangeOp::Create, "../escape.txt", None);
        store::append_entry(&upper_dir, ChangeOp::Create, "ok.txt", None);

        let fs = SandboxFs::open_with_cow(
            &workspace_root,
            &StagingConfig::default(),
            &ReadScopeConfig::default(),
            Some(&upper_dir),
        )
        .unwrap();
        let changes = fs.change_set().unwrap();

        assert_eq!(changes.len(), 2, "the entry must stay visible: {changes:?}");
        let escaping = changes
            .iter()
            .find(|c| c.path == "../escape.txt")
            .expect("escaping entry must still be listed");
        assert!(
            escaping.rejected.is_some(),
            "the escaping entry must carry a reason"
        );
        let ok = changes.iter().find(|c| c.path == "ok.txt").unwrap();
        assert!(ok.rejected.is_none(), "a normal path must not be flagged");
    }

    #[test]
    fn discard_removes_all_staged_changes() {
        let dir = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();
        fs.write_string("a.txt", "x").unwrap();
        assert!(!fs.change_set().unwrap().is_empty());

        fs.discard().unwrap();

        assert!(!dir.path().join(".harness/sandbox/s1").exists());
    }

    fn cow_fs(workspace_root: &Path, upper_dir: &Path) -> SandboxFs {
        SandboxFs::open_with_cow(
            workspace_root,
            &StagingConfig::default(),
            &ReadScopeConfig::default(),
            Some(upper_dir),
        )
        .unwrap()
    }

    /// CoW一本化の核心（Phase 1/2）: `write_string`はworkspace本体へ一切触れず、upper側の
    /// 実体・Redirector DLLと共有する操作台帳の両方へ記録される。
    #[test]
    fn cow_write_redirects_to_upper_and_leaves_workspace_untouched() {
        let ws = tempfile::tempdir().unwrap();
        let upper = tempfile::tempdir().unwrap();
        let fs = cow_fs(ws.path(), upper.path());

        fs.write_string("notes.txt", "hello").unwrap();

        assert!(!ws.path().join("notes.txt").exists());
        assert_eq!(
            std::fs::read_to_string(upper.path().join("notes.txt")).unwrap(),
            "hello"
        );
        let changes = store::replay_ledger(upper.path());
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "notes.txt");
        assert_eq!(changes[0].op, ChangeOp::Create);
    }

    /// `write_file`→`read_file`のread-through整合: run_shellが書いた（＝upperに載った）
    /// 内容も含め、CoW時の`read_to_string`は「upper優先、無ければworkspace」の順で読める。
    #[test]
    fn cow_read_prefers_upper_over_workspace() {
        let ws = tempfile::tempdir().unwrap();
        let upper = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("a.txt"), "workspace-content").unwrap();
        let fs = cow_fs(ws.path(), upper.path());

        assert_eq!(fs.read_to_string("a.txt").unwrap(), "workspace-content");

        fs.write_string("a.txt", "upper-content").unwrap();
        assert_eq!(fs.read_to_string("a.txt").unwrap(), "upper-content");
    }

    /// 論理削除（`remove`）は台帳へDeleteを記録するだけで、`read_to_string`はNotFoundを返す
    /// （設計書§19.7「削除済み＞upper＞workspace」）。
    #[test]
    fn cow_remove_marks_deleted_and_read_returns_not_found() {
        let ws = tempfile::tempdir().unwrap();
        let upper = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("existing.txt"), "orig").unwrap();
        let fs = cow_fs(ws.path(), upper.path());

        fs.remove("existing.txt").unwrap();

        assert!(
            ws.path().join("existing.txt").exists(),
            "論理削除は実workspaceを物理削除しない"
        );
        let err = fs.read_to_string("existing.txt").unwrap_err();
        assert!(matches!(err, SandboxError::NotFound(_)));
    }

    /// `walk_files`はupper側の新規作成・削除を実workspaceの一覧へ反映する（grep/glob用）。
    #[test]
    fn cow_walk_files_reflects_upper_changes() {
        let ws = tempfile::tempdir().unwrap();
        let upper = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("real.txt"), "r").unwrap();
        let fs = cow_fs(ws.path(), upper.path());
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

    /// baselineハッシュは台帳に既存エントリがあればそれを権威として複製する
    /// （`harness_change_ledger::store`をDLLと共有するため、2回目の書込でbaselineが
    /// 再計算されて食い違うことはない）。
    #[test]
    fn cow_second_write_reuses_recorded_baseline_not_current_workspace_content() {
        let ws = tempfile::tempdir().unwrap();
        let upper = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("a.txt"), "original").unwrap();
        let fs = cow_fs(ws.path(), upper.path());

        fs.write_string("a.txt", "first-edit").unwrap();
        fs.write_string("a.txt", "second-edit").unwrap();

        let changes = store::replay_ledger(upper.path());
        assert_eq!(changes.len(), 1);
        assert_eq!(
            changes[0].baseline_hash,
            Some(harness_change_ledger::hash_bytes(b"original"))
        );
        assert_eq!(changes[0].op, ChangeOp::Modify);
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
