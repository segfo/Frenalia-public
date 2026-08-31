//! `SandboxFs`: 書込リダイレクト・read-through・変更台帳・論理削除（tombstone）。
//! `plans/DESIGN.md` §オーバーレイFS・§書込ステージング3モード 参照（M10）。
//!
//! パーミッション層（`RiskClass`/`PermissionArbiter`）とは直交する: `SandboxFs`は
//! 「許可された書込の実FS効果をどこへ落とすか」だけを決め、実行してよいかどうかは
//! 一切判定しない（そちらは`harness-engine::PermissionArbiter`が唯一の強制点として担う）。
//!
//! **CoW一本化（Phase 2、`plans/AppContainerベース Copy-on-Write ワークスペース設計書.md`
//! §19）**: `--staged`/`--workspace-commit`（オーバーレイあり・強制力なし・レビュー用）と
//! `--sandbox tier2a-cow`（オーバーレイあり・workspace本体RO ACLで強制・Tier2a限定）は、以前は別々の
//! 保存形式（`tree/`・`_ext/`・`manifest.jsonl` vs `.harness-cow-ops.jsonl`操作台帳）を
//! 持っていたが、今は**単一のオーバーレイディレクトリ + 操作台帳
//! （`harness_change_ledger::store`、Redirector DLLと共有）**という同じ表現に統一されている。
//! 違いは「オーバーレイディレクトリがworkspace内（`--staged`）かworkspace外（`--sandbox tier2a-cow`）か」と
//! 「ACLによる強制があるか（Tier2a `--sandbox tier2a-cow`のみ）」だけであり、`SandboxFs`自身はその区別を
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

/// `--staged`/`--sandbox tier2a-cow`いずれかが有効なときの唯一のオーバーレイ実体。`dir`は絶対パス
/// （`--staged`ならworkspace内`<workspace_root>/<sandbox_dir>`、`--sandbox tier2a-cow`ならworkspace外の
/// CoW 差分層ディレクトリ）。
pub(crate) struct OverlayBackend {
    pub(crate) dir: PathBuf,
    pub(crate) jail: WorkspaceJail,
    /// 台帳に無い実体がオーバーレイに現れ得るか（[`effective_changes`]が走査するか）。
    ///
    /// `true`になるのは**オーバーレイがworkspaceの外にある場合＝`--sandbox tier2a-cow`の差分層**だけである。
    /// そこはサンドボックス子へRW付与されていて、しかもworkspaceのビューからは見えないので、
    /// 子が直接置いたファイルを取りこぼすと黙って失われる（[BUG-066](../../docs/bugs/BUG-066.md)）。
    ///
    /// `--staged`のオーバーレイはworkspace内（`<workspace_root>/<sandbox_dir>`）にあり、
    /// **harness自身が同じディレクトリを監査ログの置き場として使う**（`net-audit.jsonl`・
    /// `fs-audit.jsonl`、`cli/startup/sandbox.rs`）。ここを走査すると、その監査ログが
    /// 「台帳に無い変更」として一覧に出て`apply`でworkspaceルートへコピーされてしまう。
    /// またstagedではオーバーレイ外の書込はそのまま実workspaceへ落ちる（＝失われない）ので、
    /// 走査が守るべきものが無い。
    scan_for_unledgered: bool,
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
    /// **オーバーレイに実体はあるが操作台帳に記録が無い**エントリ
    /// （[BUG-066](../../docs/bugs/BUG-066.md)）。
    ///
    /// CoW 差分層ディレクトリはサンドボックス子へRW付与されているので、子は台帳を経由せずに
    /// 直接ファイルを置ける（実際モデルが`run_shell`から`Set-Content <差分層>\merge-demo.txt`と
    /// 書いた）。台帳だけを見ていると**差分層に存在する変更が`changes`から消え、`discard`で
    /// 黙って失われる**ため、実体の走査結果と突き合わせてここに立てる。
    ///
    /// `baseline_hash`は`op`が`Modify`のとき**不明**である（セッション開始時点の姿を記録した
    /// ものが無い）。捏造すると第三者による同時編集の上書き検知が壊れるので`None`のままにし、
    /// `apply`は既定でこの種のエントリを適用しない（`ApplyOptions::adopt_unledgered`）。
    pub unledgered: bool,
}

pub struct ApplyOptions<'a> {
    /// 選択適用フィルタ（`AllowlistRule`同様の`*`ワイルドカード）。`None`なら全件対象。
    /// CLIの`--only <glob>`向け。
    pub only_glob: Option<&'a str>,
    /// 選択適用フィルタ（完全一致のパス集合）。TUI変更パネルのファイル毎accept/reject向け
    /// （globでは非連続な複数ファイルの選択を表現しづらいため）。`only_glob`と併用時はAND。
    pub only_paths: Option<&'a [String]>,
    /// workspace外ターゲットを実際に適用してよいか（`harness apply --dangerously-allow`相当）。
    ///
    /// **`false`が既定で、`true`はワークスペース外の実FSへ書く唯一の経路を開ける。**
    /// 絶対パスの書込は`write_string`が`_ext/<key>`へ記録するので（同ファイルの該当分岐）、
    /// `apply`まで実FSは無傷のまま溜まる。ここを`true`にすると`apply_ext_entry`が
    /// `std::fs::write`まで進む。
    ///
    /// **本番で`true`になるのはCLIの`apply`だけ**である——TUIの変更パネルと`harness resolve`は
    /// `false`を直書きしており、ハンク単位の適用は`canonical_ledger_path`が絶対パスを弾く。
    pub allow_ext: bool,
    /// 台帳に記録が無いオーバーレイ実体（[`ChangeEntry::unledgered`]）のうち、**実workspace側に
    /// 既に別内容のファイルがあるもの**を適用してよいか（CLIの`--adopt-unledgered`）。
    ///
    /// 既定は`false`。この種のエントリはセッション開始時点の姿（baseline）が分からないため、
    /// 適用すると「セッション中に人が実workspaceを編集していた」場合の上書きを検知できない。
    /// workspace側に実体が無いもの（純粋な新規作成）は失うものが無いので、このフラグに関係なく
    /// 適用する（[BUG-066](../../docs/bugs/BUG-066.md)）。
    pub adopt_unledgered: bool,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ApplyReport {
    pub applied: Vec<String>,
    /// baseline照合の相違により拒否されたパス（DESIGN「相違なら適用拒否→再レビュー要求」）。
    pub conflicts: Vec<String>,
    /// workspace外ターゲットだが`allow_ext`が無かったため拒否されたパス。
    ///
    /// **空でないことは普通に起こる**——モデルが絶対パスへ書けば`_ext/<key>`として溜まり、
    /// `allow_ext`無しの`apply`はここへ回す。空かどうかは「外向きの書込が溜まっているか」の
    /// 指標であって、機構が無効である証拠ではない。
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
    /// オーバーレイに実体はあるが台帳に記録が無く（[`ChangeEntry::unledgered`]）、かつ実
    /// workspace側に別内容のファイルがあるため適用を見送ったパス（[BUG-066](../../docs/bugs/BUG-066.md)）。
    /// baselineが不明なので、適用すると人の同時編集を黙って上書きし得る。
    /// `ApplyOptions::adopt_unledgered`で明示的に取り込める。
    pub unledgered: Vec<String>,
}

impl ApplyReport {
    /// 別の`apply`呼び出しの結果を取り込む。1回のコミット操作が「ファイル単位の`apply`」と
    /// 「ハンク単位の`apply_hunks`（ファイルごとに1回）」へ分かれるため、UIへ出す前に
    /// 1つの報告へまとめる（`harness-tui::push_apply_report`は1件しか受け取らない）。
    pub fn merge(&mut self, other: ApplyReport) {
        self.applied.extend(other.applied);
        self.conflicts.extend(other.conflicts);
        self.ext_blocked.extend(other.ext_blocked);
        self.hard_denied.extend(other.hard_denied);
        self.rejected.extend(other.rejected);
        self.unledgered.extend(other.unledgered);
    }
}

/// 書込リダイレクト・read-through・操作台帳・tombstoneを仲介するオーバーレイFS。
/// `overlay`が`None`（純live、`StagingConfig::default()`かつ`cow_diff_layer_dir=None`）なら、
/// 内部の`WorkspaceJail`をそのまま素通しする（M9までの既存挙動と等価）。
pub struct SandboxFs {
    pub(crate) jail: WorkspaceJail,
    workspace_root: PathBuf,
    pub(crate) overlay: Option<OverlayBackend>,
    read_scope: ReadScope,
}

impl SandboxFs {
    pub fn open(workspace_root: &Path, staging: &StagingConfig) -> Result<Self, SandboxError> {
        Self::open_with_read_scope(workspace_root, staging, &ReadScopeConfig::default())
    }

    /// `read.allow`/`read.allow_descend`/`read.deny`/`read.deny_descend`（M11）を
    /// 反映した`SandboxFs`を開く。`--sandbox tier2a-cow`のCoWオーバーレイは使わない（`cow_diff_layer_dir=None`
    /// 相当）、`ToolCtx.cow_diff_layer_dir`を運べる呼び出し元は`open_with_cow`を使うこと。
    pub fn open_with_read_scope(
        workspace_root: &Path,
        staging: &StagingConfig,
        read_scope_config: &ReadScopeConfig,
    ) -> Result<Self, SandboxError> {
        Self::open_with_cow(workspace_root, staging, read_scope_config, None)
    }

    /// `ToolCtx.cow_diff_layer_dir`をそのまま渡して`SandboxFs`を開く（host内蔵ツール
    /// write_file/edit_file/read_file/grep/glob向け）。`Some`なら、workspace内相対パスへの
    /// 書込/読取/削除/列挙はRedirector DLLと同じ差分層ディレクトリ・同じ操作台帳
    /// （`.harness-cow-ops.jsonl`）を経由する。`None`かつ`staging.mode`が`Staged`/
    /// `WorkspaceCommit`なら、`staging.sandbox_dir`（workspace相対）をworkspace内オーバーレイ
    /// として同じ経路で使う（`--sandbox tier2a-cow`と`--staged`はCLI起動時に排他化されているため、両方
    /// 有効になることは実運用上ない。**排他はclapの宣言ではなく**`harness-cli`の
    /// `setup::resolve_staging_mode_checked`が実行時に拒否する形で成立している）。
    pub fn open_with_cow(
        workspace_root: &Path,
        staging: &StagingConfig,
        read_scope_config: &ReadScopeConfig,
        cow_diff_layer_dir: Option<&Path>,
    ) -> Result<Self, SandboxError> {
        let jail = WorkspaceJail::open(workspace_root)?;
        let overlay_dir: Option<PathBuf> = match cow_diff_layer_dir {
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
                let scan_for_unledgered = harness_change_ledger::path_rules::relative_under_root(
                    &dir.to_string_lossy(),
                    &workspace_root.to_string_lossy(),
                )
                .is_none();
                Some(OverlayBackend {
                    jail: WorkspaceJail::open(&dir)?,
                    dir,
                    scan_for_unledgered,
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

    /// レビュー対象の変更一覧（`--staged`/`--sandbox tier2a-cow`いずれも同じ形。オーバーレイ無効なら空）。
    pub fn change_set(&self) -> Result<Vec<ChangeEntry>, SandboxError> {
        let Some(overlay) = &self.overlay else {
            return Ok(Vec::new());
        };
        Ok(effective_changes(&self.jail, overlay)
            .into_iter()
            .map(|e| {
                // `_ext`（絶対パス）は`store::ext_key`が別途検証する経路なので、ここでの
                // 相対パス判定にはかけない（かけると全件が「不正」になる）。
                let rejected = if Path::new(&e.change.path).is_absolute() {
                    store::ext_key(&e.change.path).err()
                } else {
                    canonical_ledger_path(&e.change.path).err()
                };
                ChangeEntry {
                    op: e.change.op,
                    path: e.change.path,
                    baseline_hash: e.change.baseline_hash,
                    rejected,
                    unledgered: e.unledgered,
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
            // 台帳に載っていないオーバーレイ実体もここへ含める（BUG-066）。`read_to_string`は
            // 元々「差分層に実体があればそちら」を返すので、列挙にだけ出てこないと
            // 「grepでは見つからないのにread_fileでは読める」というちぐはぐが残る。
            for e in effective_changes(&self.jail, overlay) {
                let c = e.change;
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

    /// オーバーレイ済み変更を実FSへ選択適用する（`--staged`/`--sandbox tier2a-cow`共通、
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
            let overlay_abs = store::diff_layer_path_for(&overlay.dir, path);
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
        // 削除の実行点は`session_scope`が1つだけ持つ（GCも同じ関数を通る）。
        crate::session_scope::remove_overlay_dir(&overlay.dir)?;
        Ok(())
    }
}

/// このセッションに何があるかの1件（台帳由来か、オーバーレイ実体の走査由来か）。
struct EffectiveChange {
    change: harness_change_ledger::CowChange,
    /// 走査でしか見つからなかった＝台帳に記録が無い（[`ChangeEntry::unledgered`]）。
    unledgered: bool,
}

/// **このセッションに何があるか**を計算する唯一の場所。`change_set`（見せる）・
/// `apply_overlay_changes`（反映する）・`walk_files`（列挙する）が同じ答えを使う。
///
/// 内訳は「操作台帳の再生」∪「オーバーレイ実体の走査のうち台帳に無いもの」である
/// （走査するのは`--sandbox tier2a-cow`の差分層だけ。理由は[`OverlayBackend::scan_for_unledgered`]）。
/// **なぜ台帳だけでは足りないか**（[BUG-066](../../docs/bugs/BUG-066.md)）: オーバーレイ
/// ディレクトリはサンドボックス子へRW付与されているので、子は`copy_up`もフックも経由せず
/// 直接ファイルを置ける。台帳だけを正本にすると、そうして置かれたファイルは
/// `read_file`からは読めるのに`changes`には出ず、`apply`もせず、`discard`で消える
/// ——**作業が黙って失われる**。Redirector DLLは境界ではない（D-01）ので、可視性を
/// 「書く側が台帳に記録してくれること」へ依存させない。
///
/// 走査由来エントリの`op`は実workspace側の現在の姿から決める:
///
/// | 実workspace側 | 判定 |
/// |---|---|
/// | 実体が無い | `Create`（baseline `None`＝新規作成。適用しても失うものが無い） |
/// | 実体があり内容が同じ | **変更ではない**ので列挙しない |
/// | 実体があり内容が違う | `Modify`だが**baselineは不明**（`None`のまま。捏造しない） |
fn effective_changes(jail: &WorkspaceJail, overlay: &OverlayBackend) -> Vec<EffectiveChange> {
    let ledger = store::replay_ledger(&overlay.dir);
    let known: BTreeSet<String> = ledger
        .iter()
        .map(|c| store::ledger_key_match_form(&c.path))
        .collect();
    let mut out: Vec<EffectiveChange> = ledger
        .into_iter()
        .map(|change| EffectiveChange {
            change,
            unledgered: false,
        })
        .collect();
    if !overlay.scan_for_unledgered {
        return out;
    }

    for key in store::scan_diff_layer_content_files(&overlay.dir) {
        if known.contains(&store::ledger_key_match_form(&key)) {
            continue;
        }
        let is_ext = Path::new(&key).is_absolute();
        let overlay_rel = if is_ext {
            match store::ext_key(&key) {
                Ok(k) => format!("_ext/{k}"),
                Err(_) => continue,
            }
        } else {
            key.clone()
        };
        let Ok(overlay_bytes) = overlay.jail.read_bytes(&overlay_rel) else {
            continue;
        };
        let workspace_bytes = if is_ext {
            std::fs::read(&key).ok()
        } else {
            canonical_ledger_path(&key)
                .ok()
                .and_then(|rel| jail.read_bytes(&rel).ok())
        };
        let op = match workspace_bytes {
            None => ChangeOp::Create,
            Some(current) if current == overlay_bytes => continue,
            Some(_) => ChangeOp::Modify,
        };
        out.push(EffectiveChange {
            change: harness_change_ledger::CowChange {
                path: key,
                op,
                baseline_hash: None,
            },
            unledgered: true,
        });
    }
    out
}

/// `apply()`の実体。`--staged`/`--sandbox tier2a-cow`で別々に実装していたロジック（旧`SandboxFs::apply`・
/// `changes.rs::apply_cow_changes`）をここへ一本化した（Phase 2）。
///
/// **workspace側・overlay側とも、必ず`WorkspaceJail`（cap-stdの`Dir`からの相対open＝
/// openat相当）を経由する。** 生の`std::fs`とパス結合でこれを行っていたのが
/// [BUG-062](../../docs/bugs/BUG-062.md)——操作台帳`.harness-cow-ops.jsonl`はdiff_layer_dir配下に
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
    let changes = effective_changes(jail, overlay);
    let mut applied_paths: Vec<String> = Vec::new();

    for entry in &changes {
        let c = &entry.change;
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
        // ここを通ってはじめて、後段の`is_config_injection_path`（前置詞一致）が
        // 「正規形の相対パスしか来ない」という前提を持てる（BUG-062の層2）。
        //
        // **以降は`canonical`（`.`成分を除いた正規形）だけを使う。** 元の`c.path`を判定や
        // FS操作に使うと、`././.git/config`のような表記でhard-denyを取りこぼす
        // （`is_config_injection_path`は`./`を1回しか剥がさない。実測で確認した迂回）。
        // `c.path`を使ってよいのは**台帳の照合と報告**だけ——台帳に載っているのはその文字列
        // なので、`prune_ledger`は元の綴りで引く必要がある。
        let canonical = if is_ext {
            c.path.clone()
        } else {
            match canonical_ledger_path(&c.path) {
                Ok(p) => p,
                Err(reason) => {
                    report.rejected.push((c.path.clone(), reason));
                    continue;
                }
            }
        };
        if harness_core::is_config_injection_path(&canonical) {
            report.hard_denied.push(c.path.clone());
            continue;
        }

        // baseline照合（サイレントなlost update / TOCTOU防止、§オーバーレイFS
        // 「相違なら適用拒否→再レビュー要求」）。workspace側の読取もjail経由。
        //
        // 台帳に無いエントリ（BUG-066）はbaselineが**不明**なのでこの照合が成立しない。
        // `op`が`Create`＝実workspace側に実体が無い場合だけは失うものが無いので適用し、
        // 実体があって内容が違う場合（`Modify`）は既定で見送る——ここで現在のハッシュを
        // baselineとして採ってしまうと、セッション中に人が編集していた場合の上書きを
        // 「検知できた上で無視した」のと同じことになる。取り込みは`adopt_unledgered`で
        // 明示的に選ばせる。
        if entry.unledgered {
            if c.op == ChangeOp::Modify && !opts.adopt_unledgered {
                report.unledgered.push(c.path.clone());
                continue;
            }
        } else {
            let current_hash = if is_ext {
                std::fs::read(&c.path)
                    .ok()
                    .map(|b| harness_change_ledger::hash_bytes(&b))
            } else {
                jail.read_bytes(&canonical)
                    .ok()
                    .map(|b| harness_change_ledger::hash_bytes(&b))
            };
            if current_hash != c.baseline_hash {
                report.conflicts.push(c.path.clone());
                continue;
            }
        }

        let outcome = if is_ext {
            apply_ext_entry(overlay, c)
        } else {
            apply_workspace_entry(jail, overlay, &canonical, c.op)
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

/// 台帳の相対パスを検査し、**正規形**（`.`成分を除き`/`区切りに揃えたもの）を返す。
/// 判定の実体は`harness_change_ledger::validate_relative_path`が持つ（`check_relative_path`と
/// 同じ関数。2箇所へ別々に書かない、`docs/CODE-STRUCTURE-RULES.md`規則5）。
pub(crate) fn canonical_ledger_path(path: &str) -> Result<String, String> {
    match harness_change_ledger::validate_relative_path(path) {
        Ok(canonical) => Ok(normalize_str(&canonical)),
        Err(harness_change_ledger::PathRejection::Escape) => {
            Err("path escapes the workspace root".to_string())
        }
        Err(harness_change_ledger::PathRejection::Unsafe(reason)) => Err(reason),
    }
}

/// workspace内エントリ1件の適用。読み書きとも`WorkspaceJail`（openat相当）に閉じる。
///
/// `rel`は[`canonical_ledger_path`]を通した正規形であること——台帳の生の綴りを渡すと、
/// hard-denyの判定と実際に触る場所がずれる余地が戻ってしまう。
fn apply_workspace_entry(
    jail: &WorkspaceJail,
    overlay: &OverlayBackend,
    rel: &str,
    op: ChangeOp,
) -> Result<(), SandboxError> {
    match op {
        ChangeOp::Delete => {
            if jail.exists(rel) {
                jail.remove_file(rel)?;
            }
            Ok(())
        }
        ChangeOp::Create | ChangeOp::Modify => {
            if overlay.jail.is_dir(rel) {
                // ディレクトリ作成そのものの記録（例`mkdir sub`が台帳へCreateとして残る）。
                // 実体化するだけでよく、配下の個別ファイルエントリが引き続き同じ
                // overlayを参照するため、ここではoverlay側を消さない。
                jail.create_dir_all(rel)?;
                return Ok(());
            }
            let content = overlay.jail.read_bytes(rel)?;
            jail.write_bytes(rel, &content)?;
            // overlay側の実体を消しておかないと、Redirectorのcopy_upが「既に差分層にある＝
            // このセッションで一度触った」と誤認して、次の変更を台帳へ記録しなくなる
            // （BUG-034）。ベストエフォート、失敗してもcommit自体は成功扱いにする。
            let _ = overlay.jail.remove_file(rel);
            Ok(())
        }
    }
}

/// workspace外絶対パス（`_ext`、Phase 3）エントリ1件の適用。
///
/// **宛先が意図的にworkspaceの外**なので、ここだけはjailに閉じられない（`allow_ext`＝
/// `--dangerously-allow`という別のゲートを通っている）。ただし**読取元はoverlayのjail経由**で、
/// パスは`store::ext_key`（`..`とUNCを拒否する）が導く`_ext/<key>`だけに限る。
fn apply_ext_entry(
    overlay: &OverlayBackend,
    c: &harness_change_ledger::CowChange,
) -> Result<(), SandboxError> {
    let key = store::ext_key(&c.path)
        .map_err(|e| SandboxError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;
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
        assert_eq!(
            std::fs::read_to_string(dir.path().join("a.txt")).unwrap(),
            "original"
        );
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
    /// 触れない（`--sandbox tier2a-cow`の`_ext`扱いと同じ経路、設計書§19.8）。
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
        assert_eq!(
            changes[0].path,
            harness_change_ledger::store::normalize_abs_path(&abs)
        );
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
                adopt_unledgered: false,
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
                adopt_unledgered: false,
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
                adopt_unledgered: false,
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
                adopt_unledgered: false,
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
                adopt_unledgered: false,
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
                adopt_unledgered: false,
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
                adopt_unledgered: false,
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

    /// BUG-062の再現用: 「サンドボックス子が`<差分層>/.harness-cow-ops.jsonl`へ直接書いた」
    /// 状況を作る。diff_layer_dirはAppContainer子へ`grant_ace_inheritable_rw`で渡っているので
    /// （`win_appcontainer/preflight.rs`）、台帳の内容はP-01上ハーネスが信用してよい入力ではない。
    ///
    /// workspace_rootを`<tempdir>/root`に置くのは、`..`による脱出先を**同じtempdir内**に
    /// 収めるため（%TEMP%直下へ書き出すテストにしない）。
    fn tampered_ledger_fixture() -> (tempfile::TempDir, tempfile::TempDir, PathBuf, PathBuf) {
        let ws = tempfile::tempdir().unwrap();
        let diff_layer_tmp = tempfile::tempdir().unwrap();
        let workspace_root = ws.path().join("root");
        let diff_layer_dir = diff_layer_tmp.path().join("diff_layer");
        std::fs::create_dir_all(&workspace_root).unwrap();
        std::fs::create_dir_all(&diff_layer_dir).unwrap();
        (ws, diff_layer_tmp, workspace_root, diff_layer_dir)
    }

    /// **BUG-062 (a)**: 台帳の相対パスに`..`が入っていると、`apply`がworkspace_rootの外へ
    /// ユーザ権限で書ける。`apply`はworkspaceの主ゲート（cap-stdの`WorkspaceJail`）を
    /// 通らなければならない。
    #[test]
    fn apply_refuses_ledger_paths_that_escape_the_workspace_root() {
        let (ws, diff_layer_tmp, workspace_root, diff_layer_dir) = tampered_ledger_fixture();
        // 敵対者が差分層側に置いた実体。`diff_layer_dir.join("../escape.txt")`がこれを指す。
        std::fs::write(diff_layer_tmp.path().join("escape.txt"), "pwned").unwrap();
        store::append_entry(&diff_layer_dir, ChangeOp::Create, "../escape.txt", None);

        let fs = SandboxFs::open_with_cow(
            &workspace_root,
            &StagingConfig::default(),
            &ReadScopeConfig::default(),
            Some(&diff_layer_dir),
        )
        .unwrap();
        let report = fs
            .apply(&ApplyOptions {
                only_glob: None,
                only_paths: None,
                allow_ext: false,
                adopt_unledgered: false,
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
        let (_ws, _diff_layer_tmp, workspace_root, diff_layer_dir) = tampered_ledger_fixture();
        // `diff_layer_dir.join("x/../.git/config")`＝`<diff_layer>/.git/config`。
        std::fs::create_dir_all(diff_layer_dir.join(".git")).unwrap();
        std::fs::write(
            diff_layer_dir.join(".git/config"),
            "[core]\n\thooksPath = /tmp/evil\n",
        )
        .unwrap();
        store::append_entry(&diff_layer_dir, ChangeOp::Create, "x/../.git/config", None);

        let fs = SandboxFs::open_with_cow(
            &workspace_root,
            &StagingConfig::default(),
            &ReadScopeConfig::default(),
            Some(&diff_layer_dir),
        )
        .unwrap();
        let report = fs
            .apply(&ApplyOptions {
                only_glob: None,
                only_paths: None,
                allow_ext: false,
                adopt_unledgered: false,
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

    /// **BUG-062 (c) / 設計書§17（Reparse Point対策）**: 差分層側に置かれたjunctionを
    /// `apply`が辿ってはいけない。辿ると、ユーザ権限で走る信頼側が**差分層の外の任意の
    /// ファイル**を読み、その内容をworkspace（＝サンドボックスから読める場所）へ落とす。
    ///
    /// junctionの作成には管理者権限もdeveloper modeも要らない（symlinkと違い
    /// `SeCreateSymbolicLinkPrivilege`を必要としない）ので、**このテストは通常の
    /// `cargo test`で走る**。
    #[cfg(windows)]
    #[test]
    fn apply_does_not_follow_a_junction_planted_in_the_overlay() {
        let (_ws, diff_layer_tmp, workspace_root, diff_layer_dir) = tampered_ledger_fixture();
        let secret_dir = diff_layer_tmp.path().join("secrets");
        std::fs::create_dir_all(&secret_dir).unwrap();
        std::fs::write(secret_dir.join("id_rsa"), "TOP-SECRET-KEY").unwrap();

        // diff_layer_dir/link -> diff_layer_tmp/secrets（差分層の外）へのjunction。
        let link = diff_layer_dir.join("link");
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

        store::append_entry(&diff_layer_dir, ChangeOp::Create, "link/id_rsa", None);

        let fs = SandboxFs::open_with_cow(
            &workspace_root,
            &StagingConfig::default(),
            &ReadScopeConfig::default(),
            Some(&diff_layer_dir),
        )
        .unwrap();
        let report = fs
            .apply(&ApplyOptions {
                only_glob: None,
                only_paths: None,
                allow_ext: false,
                adopt_unledgered: false,
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

    /// **CoW設計書§32 Phase 5「例外的なパス形式」の実測＋受け入れ**（BUG-062の直系の続き）。
    ///
    /// D-09のhard-deny（`is_config_injection_path`）は**正規化前の文字列に対する前置詞一致**
    /// なので、「文字列としては別物だが、実FS上は同じ場所へ着地する」表記があれば同じ形の
    /// 迂回が成立する。BUG-062で見つかった`x/../.git/config`はその一例にすぎない。
    ///
    /// ここで試すのはWindowsのパス正規化に由来する表記ゆれである。
    ///
    /// | 表記 | 疑い |
    /// |---|---|
    /// | `././.git/config` | `strip_prefix("./")`が**1回しか**剥がさない |
    /// | `.GIT/config` | 前置詞一致が**大小を区別する**のにNTFSは区別しない |
    /// | `.git./config` | Win32が成分末尾のドットを落とす |
    /// | `.git /config` | Win32が成分末尾のスペースを落とす |
    ///
    /// **どれか1つでも`.git/config`へ着地したらこのテストは落ちる。**
    #[test]
    fn apply_hard_deny_is_not_bypassable_by_exotic_path_spellings() {
        let forms = [
            "././.git/config",
            ".GIT/config",
            ".git./config",
            ".git /config",
        ];
        let mut landed: Vec<(&str, String)> = Vec::new();

        for form in forms {
            let (_ws, _diff_layer_tmp, workspace_root, diff_layer_dir) = tampered_ledger_fixture();
            // 差分層側に実体を置く。置けない表記（OSが受け付けない名前）はその時点で
            // 迂回にならないので、作れなかったことを記録して次へ進む。
            let src = diff_layer_dir.join(form);
            if let Some(parent) = src.parent() {
                if std::fs::create_dir_all(parent).is_err() {
                    println!("MEASUREMENT: {form:<20} -> could not create the overlay source");
                    continue;
                }
            }
            if std::fs::write(&src, "[core]\n\thooksPath = /tmp/evil\n").is_err() {
                println!("MEASUREMENT: {form:<20} -> could not write the overlay source");
                continue;
            }
            store::append_entry(&diff_layer_dir, ChangeOp::Create, form, None);

            let fs = SandboxFs::open_with_cow(
                &workspace_root,
                &StagingConfig::default(),
                &ReadScopeConfig::default(),
                Some(&diff_layer_dir),
            )
            .unwrap();
            let report = fs
                .apply(&ApplyOptions {
                    only_glob: None,
                    only_paths: None,
                    allow_ext: false,
                    adopt_unledgered: false,
                })
                .unwrap();

            let target = workspace_root.join(".git").join("config");
            let hit = target.exists();
            println!(
                "MEASUREMENT: {form:<20} -> applied={:?} hard_denied={:?} rejected={:?} \
                 landed_on_.git/config={hit}",
                report.applied, report.hard_denied, report.rejected
            );
            if hit {
                landed.push((form, format!("{report:?}")));
            }
        }

        assert!(
            landed.is_empty(),
            "these spellings reached .git/config even though D-09 must hard-deny it: {landed:#?}"
        );
    }

    /// **`plans/PLAN-COW-AS-DEFAULT.md`検証タスクの本体（判定層だけを切り出した版）**。
    ///
    /// 問い: 追跡ファイル（`.github/workflows/x.yml`）を「ワークツリー実体」ではなく
    /// 「コミット・オブジェクト＋ブランチ移動」として運ぶと、apply の層3 hard-deny
    /// （`is_config_injection_path`の前置詞一致）を迂回できるか。
    ///
    /// **なぜ透過層を切り離すのか（2026-08-23の実機測定）**: 生の git は CoW の透過層
    /// （Redirector DLL）で完走しない——`resolve_relative_object_attributes_path`
    /// （`crates/harness-redirector/src/ntpath.rs:71`）が git のハンドル相対 open を解決できず
    /// `.git/objects/pack: Function not implemented` となり、git はオブジェクトを1つも書けない
    /// （`dev-elevated-run e2e-cow-git-injection` の観測）。よって「生 git で迂回」は
    /// **透過層で先に落ちて** end-to-end では観測できない。ここでは透過層を外し、
    /// **判定層（apply）だけ**を測る: git が書いたであろうオブジェクト＋ref移動を**本物の git**で
    /// 作って台帳へ載せ、apply の非対称——オブジェクト/refは通し、同内容のワークツリー実体は
    /// hard-deny する——を確かめる（1差分×1ケース `B-29` / 許可側と拒否側の対 `B-35`）。
    ///
    /// **成立の定義**（plan「何が『成立』か」）: apply 後、サンドボックス外の
    /// `git checkout HEAD -- .github/workflows/x.yml` で拒否対象ファイルが実体化する
    /// → 現在の hard-deny は追跡ファイル経由の設定注入を止めていない。
    ///
    /// 昇格は不要（AppContainer も Redirector も使わない）。外部の`git`に依存し実FS I/Oを行う
    /// ため`#[ignore]`とし、`cargo test -p harness-sandbox --lib -- --ignored <name>`で回す。
    #[test]
    #[ignore]
    fn apply_hard_deny_is_bypassed_by_git_objects_carrying_a_config_injection_file() {
        const INJECTED: &str = "name: evil-injected-via-git";

        // ハードニングなしの素の git（テスト足場。サンドボックス内でモデルが起動する git とは別）。
        fn git(dir: &std::path::Path, args: &[&str]) -> String {
            let out = std::process::Command::new("git")
                .current_dir(dir)
                .args([
                    "-c",
                    "safe.directory=*",
                    "-c",
                    "user.name=e2e",
                    "-c",
                    "user.email=e2e@example.com",
                ])
                .args(args)
                .output()
                .unwrap_or_else(|e| panic!("git {args:?}: {e} (is git installed and on PATH?)"));
            assert!(
                out.status.success(),
                "git {args:?} failed: stdout={} stderr={}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        // `.git/objects/xx/<rest>` のルース・オブジェクト集合（`xx/rest`形で返す。pack/infoは除く）。
        fn loose_objects(objects_dir: &std::path::Path) -> std::collections::HashSet<String> {
            let mut set = std::collections::HashSet::new();
            let Ok(top) = std::fs::read_dir(objects_dir) else {
                return set;
            };
            for e in top.flatten() {
                let fan = e.file_name();
                let fan = fan.to_string_lossy().to_string();
                if fan.len() == 2 && fan.chars().all(|c| c.is_ascii_hexdigit()) {
                    if let Ok(inner) = std::fs::read_dir(e.path()) {
                        for f in inner.flatten() {
                            set.insert(format!("{fan}/{}", f.file_name().to_string_lossy()));
                        }
                    }
                }
            }
            set
        }

        fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) {
            std::fs::create_dir_all(dst).unwrap();
            for entry in std::fs::read_dir(src).unwrap().flatten() {
                let from = entry.path();
                let to = dst.join(entry.file_name());
                if entry.file_type().unwrap().is_dir() {
                    copy_dir_all(&from, &to);
                } else {
                    std::fs::copy(&from, &to).unwrap();
                }
            }
        }

        let (_ws_tmp, diff_layer_tmp, workspace_root, diff_layer_dir) = tampered_ledger_fixture();

        // 1) 実workspaceに正当なリポジトリ（master@c0＝READMEのみ）を種付け。
        std::fs::write(workspace_root.join("README.md"), "seed\n").unwrap();
        git(&workspace_root, &["init", "-q"]);
        git(&workspace_root, &["add", "README.md"]);
        git(&workspace_root, &["commit", "-q", "-m", "seed"]);
        let master_ref = workspace_root.join(".git").join("refs").join("heads").join("master");
        assert!(
            master_ref.exists(),
            "seed must leave a loose master ref (not packed); found none at {master_ref:?}"
        );
        let c0_ref_bytes = std::fs::read(&master_ref).unwrap();
        let loose_before = loose_objects(&workspace_root.join(".git").join("objects"));

        // 2) workspaceのコピー側で注入コミットを作る（本物の git、サンドボックス外）。
        //    実workspaceの`.git`は一切触らない——迂回ペイロードは「外から台帳経由で運ぶ」。
        let build = diff_layer_tmp.path().join("build");
        copy_dir_all(&workspace_root, &build);
        std::fs::create_dir_all(build.join(".github").join("workflows")).unwrap();
        std::fs::write(build.join(".github").join("workflows").join("x.yml"), INJECTED).unwrap();
        git(&build, &["add", ".github/workflows/x.yml"]);
        git(&build, &["commit", "-q", "-m", "inject ci workflow via tracked object"]);
        let c1 = git(&build, &["rev-parse", "HEAD"]);
        let build_ref_bytes =
            std::fs::read(build.join(".git").join("refs").join("heads").join("master")).unwrap();

        // 3) 差分オブジェクト＋ref移動＋ワークツリー実体を 差分層 へ置き、台帳へ載せる
        //    （Redirector の copy-up が記録したであろう形を、本物のオブジェクトで再現する）。
        let loose_after = loose_objects(&build.join(".git").join("objects"));
        let new_objects: Vec<String> =
            loose_after.difference(&loose_before).cloned().collect();
        assert!(
            !new_objects.is_empty(),
            "the injected commit must create new loose objects (blob/tree/commit)"
        );
        for rel in &new_objects {
            let src = build.join(".git").join("objects").join(rel);
            let dst = diff_layer_dir.join(".git").join("objects").join(rel);
            std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
            std::fs::copy(&src, &dst).unwrap();
            store::append_entry(&diff_layer_dir, ChangeOp::Create, &format!(".git/objects/{rel}"), None);
        }
        // ブランチ移動（Modify。baseline＝実workspaceの現在の master 内容＝c0）。
        std::fs::create_dir_all(diff_layer_dir.join(".git").join("refs").join("heads")).unwrap();
        std::fs::write(
            diff_layer_dir.join(".git").join("refs").join("heads").join("master"),
            &build_ref_bytes,
        )
        .unwrap();
        store::append_entry(
            &diff_layer_dir,
            ChangeOp::Modify,
            ".git/refs/heads/master",
            Some(harness_change_ledger::hash_bytes(&c0_ref_bytes)),
        );
        // ワークツリー実体（Create。これが拒否側の対照——apply で hard-deny されねばならない）。
        std::fs::create_dir_all(diff_layer_dir.join(".github").join("workflows")).unwrap();
        std::fs::write(
            diff_layer_dir.join(".github").join("workflows").join("x.yml"),
            INJECTED,
        )
        .unwrap();
        store::append_entry(&diff_layer_dir, ChangeOp::Create, ".github/workflows/x.yml", None);

        // 4) apply。
        let fs = SandboxFs::open_with_cow(
            &workspace_root,
            &StagingConfig::default(),
            &ReadScopeConfig::default(),
            Some(&diff_layer_dir),
        )
        .unwrap();
        let report = fs
            .apply(&ApplyOptions {
                only_glob: None,
                only_paths: None,
                allow_ext: false,
                adopt_unledgered: false,
            })
            .unwrap();
        let applied: Vec<String> = report.applied.iter().map(|p| p.replace('\\', "/")).collect();
        let hard_denied: Vec<String> =
            report.hard_denied.iter().map(|p| p.replace('\\', "/")).collect();

        // 拒否側（機構が生きている証拠）: ワークツリーの設定注入パスは hard_denied。
        assert!(
            hard_denied.iter().any(|p| p == ".github/workflows/x.yml"),
            "control: the working-tree config-injection path must be hard-denied, otherwise this \
             test cannot distinguish a live deny mechanism from a dead one (B-35). report={report:?}"
        );
        // 許可側（迂回）: オブジェクトは全件 applied、hard_denied されていない。
        let objects_applied = applied.iter().filter(|p| p.starts_with(".git/objects/")).count();
        assert_eq!(
            objects_applied,
            new_objects.len(),
            "every injected git object must be applied (they carry the payload): report={report:?}"
        );
        assert!(
            !hard_denied.iter().any(|p| p.starts_with(".git/objects/")),
            "git objects must NOT be hard-denied — their content-hash paths carry no config-\
             injection signal: report={report:?}"
        );
        assert!(
            applied.iter().any(|p| p == ".git/refs/heads/master"),
            "the moved branch ref must be applied: report={report:?}"
        );

        // 実FS: apply 直後はワークツリー実体はまだ無い（hard_denied されたので）。
        let wt = workspace_root.join(".github").join("workflows").join("x.yml");
        assert!(
            !wt.exists(),
            "the working-tree file must NOT be materialized by apply itself (it was hard-denied)"
        );

        // 5) サンドボックス外で checkout → 迂回で運んだオブジェクトから拒否対象が実体化する。
        git(&workspace_root, &["checkout", "HEAD", "--", ".github/workflows/x.yml"]);
        assert!(
            wt.exists(),
            "BYPASS成立: サンドボックス外の`git checkout`が、密輸したオブジェクトから hard-deny \
             対象ファイルを実体化させた"
        );
        assert_eq!(
            std::fs::read_to_string(&wt).unwrap(),
            INJECTED,
            "materialized content must be the injected payload"
        );
        assert_eq!(
            git(&workspace_root, &["rev-parse", "HEAD"]),
            c1,
            "実HEADが注入コミットを指していること（refも運ばれた）"
        );
    }

    /// W1-4: applyが拒否する形のエントリは、一覧（`harness changes`・TUI変更パネル）から
    /// **消えてはいけない**。理由付きで見せる（D-43「失敗を隠さない」）。
    #[test]
    fn change_set_marks_malformed_paths_instead_of_hiding_them() {
        let (_ws, _diff_layer_tmp, workspace_root, diff_layer_dir) = tampered_ledger_fixture();
        store::append_entry(&diff_layer_dir, ChangeOp::Create, "../escape.txt", None);
        store::append_entry(&diff_layer_dir, ChangeOp::Create, "ok.txt", None);

        let fs = SandboxFs::open_with_cow(
            &workspace_root,
            &StagingConfig::default(),
            &ReadScopeConfig::default(),
            Some(&diff_layer_dir),
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

    fn cow_fs(workspace_root: &Path, diff_layer_dir: &Path) -> SandboxFs {
        SandboxFs::open_with_cow(
            workspace_root,
            &StagingConfig::default(),
            &ReadScopeConfig::default(),
            Some(diff_layer_dir),
        )
        .unwrap()
    }

    // ---- BUG-066: 操作台帳を経由せず差分層へ直接置かれたファイル ----
    //
    // 実機ではサンドボックス子プロセスが`Set-Content <差分層>\x.txt`で作る状況（モデルが実際に
    // やったのがこれ）。ここでは「台帳を通らずに差分層へ実体が現れた」という**結果だけ**を
    // `std::fs::write`で再現する——Redirector DLLが注入されていようが回避されていようが、
    // **host側の突き合わせだけで成立する**ことを固定したいため。

    fn write_directly_into_diff_layer(diff_layer: &Path, rel: &str, content: &str) {
        let target = diff_layer.join(rel);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(target, content).unwrap();
    }

    /// 台帳に記録が無い差分層実体も`changes`に現れる（`unledgered`印付き）。これが無いと、
    /// 差分層には在るのに「変更なし」と表示され`discard`で黙って消える。
    #[test]
    fn unledgered_diff_layer_files_show_up_in_the_change_set() {
        let ws = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        let fs = cow_fs(ws.path(), diff_layer.path());
        write_directly_into_diff_layer(diff_layer.path(), "sub/direct.txt", "by the agent");

        let changes = fs.change_set().unwrap();

        assert_eq!(changes.len(), 1, "{changes:?}");
        assert_eq!(changes[0].path, "sub/direct.txt");
        assert_eq!(changes[0].op, ChangeOp::Create);
        assert!(changes[0].unledgered);
        // 列挙（glob/grep）からも見えること＝「read_fileでは読めるのに一覧に出ない」を作らない。
        assert!(fs
            .walk_files()
            .unwrap()
            .contains(&PathBuf::from("sub/direct.txt")));
    }

    /// 実workspace側に実体が無い（＝純粋な新規作成）なら、失うものが無いので既定で適用する。
    #[test]
    fn unledgered_new_file_is_applied_without_an_extra_flag() {
        let ws = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        let fs = cow_fs(ws.path(), diff_layer.path());
        write_directly_into_diff_layer(diff_layer.path(), "direct.txt", "by the agent");

        let report = fs
            .apply(&ApplyOptions {
                only_glob: None,
                only_paths: None,
                allow_ext: false,
                adopt_unledgered: false,
            })
            .unwrap();

        assert_eq!(report.applied, vec!["direct.txt".to_string()]);
        assert!(report.unledgered.is_empty());
        assert_eq!(
            std::fs::read_to_string(ws.path().join("direct.txt")).unwrap(),
            "by the agent"
        );
    }

    /// 実workspace側に別内容の実体がある場合はbaselineが不明なので**適用しない**
    /// （人の同時編集を検知できないまま上書きするのを避ける）。明示フラグでのみ取り込む。
    #[test]
    fn unledgered_modification_needs_adopt_because_its_baseline_is_unknown() {
        let ws = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("notes.txt"), "original").unwrap();
        let fs = cow_fs(ws.path(), diff_layer.path());
        write_directly_into_diff_layer(diff_layer.path(), "notes.txt", "edited by the agent");

        let report = fs
            .apply(&ApplyOptions {
                only_glob: None,
                only_paths: None,
                allow_ext: false,
                adopt_unledgered: false,
            })
            .unwrap();
        assert!(report.applied.is_empty());
        assert_eq!(report.unledgered, vec!["notes.txt".to_string()]);
        assert_eq!(
            std::fs::read_to_string(ws.path().join("notes.txt")).unwrap(),
            "original",
            "the workspace file must stay untouched until the user opts in"
        );

        let report = fs
            .apply(&ApplyOptions {
                only_glob: None,
                only_paths: None,
                allow_ext: false,
                adopt_unledgered: true,
            })
            .unwrap();
        assert_eq!(report.applied, vec!["notes.txt".to_string()]);
        assert_eq!(
            std::fs::read_to_string(ws.path().join("notes.txt")).unwrap(),
            "edited by the agent"
        );
    }

    /// 内容が実workspace側と同じなら変更ではない（`apply`で書き戻す意味も無い）。
    #[test]
    fn unledgered_file_identical_to_the_workspace_is_not_a_change() {
        let ws = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("same.txt"), "same bytes").unwrap();
        let fs = cow_fs(ws.path(), diff_layer.path());
        write_directly_into_diff_layer(diff_layer.path(), "same.txt", "same bytes");

        assert!(fs.change_set().unwrap().is_empty());
    }

    /// 台帳に載っているパスは走査で二重に数えない（綴りの大小差があっても同一視する）。
    #[test]
    fn a_ledgered_path_is_not_reported_twice_by_the_diff_layer_scan() {
        let ws = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        let fs = cow_fs(ws.path(), diff_layer.path());

        fs.write_string("Ledgered.txt", "written through the tool")
            .unwrap();

        let changes = fs.change_set().unwrap();
        assert_eq!(changes.len(), 1, "{changes:?}");
        assert!(!changes[0].unledgered);
    }

    /// 台帳を経由しなくてもD-09のhard-denyは効く（`.git/config`を差分層へ直接置いてもapplyは
    /// 拒否する）。走査由来のエントリが台帳由来と同じゲートを通ることの確認。
    #[test]
    fn unledgered_config_injection_paths_are_still_hard_denied() {
        let ws = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        let fs = cow_fs(ws.path(), diff_layer.path());
        write_directly_into_diff_layer(diff_layer.path(), ".git/config", "[core]\n");

        let report = fs
            .apply(&ApplyOptions {
                only_glob: None,
                only_paths: None,
                allow_ext: false,
                adopt_unledgered: true,
            })
            .unwrap();

        assert_eq!(report.hard_denied, vec![".git/config".to_string()]);
        assert!(report.applied.is_empty());
        assert!(!ws.path().join(".git/config").exists());
    }

    /// **`--staged`のオーバーレイは走査しない。** そこはworkspace内にあり、harness自身が
    /// `net-audit.jsonl`等の監査ログ置き場として使っている（`cli/startup/sandbox.rs`）。
    /// 走査すると監査ログが「台帳に無い変更」として一覧に出て、`apply`がworkspaceルートへ
    /// コピーしてしまう。stagedではオーバーレイ外の書込は実workspaceへ直接落ちる（失われない）
    /// ので、走査が守るべきものも無い。
    #[test]
    fn staged_overlay_is_not_scanned_so_harness_own_audit_logs_do_not_become_changes() {
        let ws = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(ws.path(), &staged_config(".harness/sandbox/s1")).unwrap();
        let audit = ws.path().join(".harness/sandbox/s1/net-audit.jsonl");
        std::fs::create_dir_all(audit.parent().unwrap()).unwrap();
        std::fs::write(&audit, "{\"event\":\"connect\"}\n").unwrap();

        assert!(fs.change_set().unwrap().is_empty());
    }

    /// CoW一本化の核心（Phase 1/2）: `write_string`はworkspace本体へ一切触れず、差分層側の
    /// 実体・Redirector DLLと共有する操作台帳の両方へ記録される。
    #[test]
    fn cow_write_redirects_to_diff_layer_and_leaves_workspace_untouched() {
        let ws = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        let fs = cow_fs(ws.path(), diff_layer.path());

        fs.write_string("notes.txt", "hello").unwrap();

        assert!(!ws.path().join("notes.txt").exists());
        assert_eq!(
            std::fs::read_to_string(diff_layer.path().join("notes.txt")).unwrap(),
            "hello"
        );
        let changes = store::replay_ledger(diff_layer.path());
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "notes.txt");
        assert_eq!(changes[0].op, ChangeOp::Create);
    }

    /// `write_file`→`read_file`のread-through整合: run_shellが書いた（＝差分層に載った）
    /// 内容も含め、CoW時の`read_to_string`は「差分層優先、無ければworkspace」の順で読める。
    #[test]
    fn cow_read_prefers_diff_layer_over_workspace() {
        let ws = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("a.txt"), "workspace-content").unwrap();
        let fs = cow_fs(ws.path(), diff_layer.path());

        assert_eq!(fs.read_to_string("a.txt").unwrap(), "workspace-content");

        fs.write_string("a.txt", "diff-layer-content").unwrap();
        assert_eq!(fs.read_to_string("a.txt").unwrap(), "diff-layer-content");
    }

    /// 論理削除（`remove`）は台帳へDeleteを記録するだけで、`read_to_string`はNotFoundを返す
    /// （設計書§19.7「削除済み＞差分層＞workspace」）。
    #[test]
    fn cow_remove_marks_deleted_and_read_returns_not_found() {
        let ws = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("existing.txt"), "orig").unwrap();
        let fs = cow_fs(ws.path(), diff_layer.path());

        fs.remove("existing.txt").unwrap();

        assert!(
            ws.path().join("existing.txt").exists(),
            "論理削除は実workspaceを物理削除しない"
        );
        let err = fs.read_to_string("existing.txt").unwrap_err();
        assert!(matches!(err, SandboxError::NotFound(_)));
    }

    /// `walk_files`は差分層側の新規作成・削除を実workspaceの一覧へ反映する（grep/glob用）。
    #[test]
    fn cow_walk_files_reflects_diff_layer_changes() {
        let ws = tempfile::tempdir().unwrap();
        let diff_layer = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("real.txt"), "r").unwrap();
        let fs = cow_fs(ws.path(), diff_layer.path());
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
        let diff_layer = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("a.txt"), "original").unwrap();
        let fs = cow_fs(ws.path(), diff_layer.path());

        fs.write_string("a.txt", "first-edit").unwrap();
        fs.write_string("a.txt", "second-edit").unwrap();

        let changes = store::replay_ledger(diff_layer.path());
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
