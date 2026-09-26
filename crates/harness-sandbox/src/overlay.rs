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
    /// 設定注入パス（`.git/config`・`.harness/**`等）への書込。判定器に加えて書込口でも拒否する
    /// （`plans/DESIGN-RUNSHELL-ALLOWLIST.md` §6.1・D-101）。
    #[error("refusing to write a config-injection path: {0}")]
    ConfigInjection(String),
    /// **[D-110 (v)]** `.git`成分を持つパスを実ワークスペースへ書こうとした。git済みの内容が
    /// 本物へ入る入口は、D-80が作るgit-fetchの段だけにする。
    ///
    /// **`ConfigInjection`と分けているのは意味が違うため**——あちらは「書いてはいけない場所」、
    /// こちらは「ここでは書かない（経路が別）」である。文面も「保留」と読める形にする。
    #[error("withholding a git-internal path from the plain apply path (it is reviewed through git, not as a file): {0}")]
    GitInternalWithheld(String),
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
    /// このエントリを**どう扱うか**の分類。表示側がパスの綴りから自分で判定し直さないために
    /// ここへ持たせる（判定を2つ持つと、一覧と`apply`の扱いがずれる。`B-13`）。
    pub category: ChangeCategory,
}

/// [`ChangeEntry`]の扱いの分類。**`apply`が実際に何をするか**で分ける。
///
/// 表示側はこれを見て畳むかどうかを決める。**綴りから判定し直さないこと**——
/// 判定器は`harness-core`側の1組（`is_config_injection_path`・`is_git_internal_path`）だけが持つ。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeCategory {
    /// 普通の変更。`apply`が実ワークスペースへ書く。
    SideEffect,
    /// **[D-110 (v)]** `.git`成分を持つので`apply`は反映を保留する
    /// （`harness_core::is_git_internal_path`）。git済みの内容が本物へ入る入口は
    /// D-80のgit-fetchの段だけ。**人が見る一覧では件数へ畳む**（合格基準P1）。
    GitInternal,
    /// 設定注入パスなので`apply`が層3 hard-denyで拒否する（D-05）。
    /// **`GitInternal`と重なるものは、こちらが勝つ**（攻撃の合図を保留に混ぜない）。
    ConfigInjection,
    /// ワークスペース外への書込（`_ext/<key>`）。`--dangerously-allow`が要る。
    Ext,
}

/// 1件の変更を[`ChangeCategory`]へ割り当てる。
///
/// **順序が`apply_overlay_changes`のゲートの順序と一致していることが要点である。**
/// 一覧が「保留」と言ったものを`apply`が拒否した（またはその逆）という食い違いを作らないため、
/// 判定は同じ関数・同じ順番で行う。ずれると、画面で見た扱いと実際の扱いが違うことになる。
fn classify_change(path: &str, workspace_root: &Path) -> ChangeCategory {
    // `_ext`（絶対パス）は最初に分ける——workspace外なので下の2つの判定はどちらも
    // 「担当外」として`false`を返し、普通の変更と区別が付かなくなる。
    if Path::new(path).is_absolute() {
        return ChangeCategory::Ext;
    }
    if harness_core::is_config_injection_path(path, workspace_root) {
        return ChangeCategory::ConfigInjection;
    }
    if harness_core::is_git_internal_path(path, workspace_root) {
        return ChangeCategory::GitInternal;
    }
    ChangeCategory::SideEffect
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
    /// **[D-110 (v)]** `.git`成分を持つため反映を**保留**したパス
    /// （[`harness_core::is_git_internal_path`]）。git済みの内容が実ワークスペースへ入る入口は、
    /// D-80が作るgit-fetchの段だけにする。
    ///
    /// **`hard_denied`と分けているのは意味が違うため。** あちらは「書いてはいけない場所」＝
    /// 攻撃の合図で、運用上の対処は「レビューして諦める」。こちらは「ここでは反映しない」＝
    /// 経路の振り分けで、対処は「gitのレビュー経路を通す」である。混ぜると、
    /// 設定注入の試みが正常なgit内容の山に埋もれる。
    ///
    /// **失敗ではないので終了コード4には数えない**が、**「完全に適用し切った」には数える**
    /// ——数えないと、保留した内容を抱えた差分層がD-82の回収で畳まれてコミットが消える。
    pub git_withheld: Vec<String>,
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
        self.git_withheld.extend(other.git_withheld);
    }
}

/// 書込リダイレクト・read-through・操作台帳・tombstoneを仲介するオーバーレイFS。
/// `overlay`が`None`（純live、`StagingConfig::default()`かつ`cow_diff_layer_dir=None`）なら、
/// 内部の`WorkspaceJail`をそのまま素通しする（M9までの既存挙動と等価）。
pub struct SandboxFs {
    pub(crate) jail: WorkspaceJail,
    /// `overlay_hunks`も層3 hard-denyを掛けるため`pub(crate)`にしてある
    /// （[BUG-126](../../../docs/bugs/BUG-126.md)。判定器が絶対パスを畳むのに根が要る）。
    pub(crate) workspace_root: PathBuf,
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
                let category = classify_change(&e.change.path, &self.workspace_root);
                ChangeEntry {
                    op: e.change.op,
                    path: e.change.path,
                    baseline_hash: e.change.baseline_hash,
                    rejected,
                    unledgered: e.unledgered,
                    category,
                }
            })
            .collect())
    }

    /// ワークスペース内へ書き込む。オーバーレイ無効ならworkspace実体へ直書き、有効なら
    /// オーバーレイディレクトリ・操作台帳へ記録する。workspace外の絶対パスはオーバーレイ有効時
    /// のみ`_ext/<key>`（`store::ext_key`）へ記録する（Phase 3）。オーバーレイ無効（純live）
    /// なら既存のLive挙動どおり拒否する。
    ///
    /// **設定注入パスへの書込はここでも拒否する**（D-101）。判定器（`PermissionArbiter`）が主ゲートだが、
    /// 判定に渡す値の選び方が破れると（BUG-164）、差分層の無い直接書くモードでは実ファイルまで届いた。
    /// 差分層を使うかどうかで防御の有無が変わらないよう、`write_file`・`edit_file`の2経路が通る
    /// 唯一の書込口に同じ判定を置く。
    ///
    /// **`.git`成分の保留（D-110 (v)・[`harness_core::is_git_internal_path`]）は、ここには
    /// 意図的に掛けない。** 保留が効くのは**差分層から実ワークスペースへ反映する段**だけである。
    /// ここへ掛けると差分層への書込そのものが止まり、サンドボックスの中の`git commit`が
    /// 壊れる（`crates/harness-cli/tests/tier2a_e2e.rs`の
    /// `tier2a_cow_git_commit_writes_objects_under_the_redirector`がgitの完走を固定している）。
    /// **エージェントがgitを使えること自体は壊さず、その結果が本物へ入る入口だけを絞る**のが
    /// D-110 (v)の形である。同じ理由で層1（`harness-engine::permission::classify`）にも掛けない。
    pub fn write_string(&self, path: &str, content: &str) -> Result<(), SandboxError> {
        // 形の崩れた相対パス（`..`で外へ出る等）は、従来どおり形の誤りとして先に返す
        // （設定注入パスの判定は`..`を拒否側へ倒すので、順序を逆にすると誤りの種類が変わる）。
        if !Path::new(path).is_absolute() {
            check_relative_path(path)?;
        }
        if harness_core::is_config_injection_path(path, &self.workspace_root) {
            return Err(SandboxError::ConfigInjection(path.to_string()));
        }
        self.write_string_unchecked(path, content)
    }

    /// テスト専用: 書込口を通らない子プロセスの書込を模して差分層（またはステージング）へ置く。
    #[cfg(test)]
    pub(crate) fn stage_like_a_child_for_test(
        &self,
        path: &str,
        content: &str,
    ) -> Result<(), SandboxError> {
        self.write_string_unchecked(path, content)
    }

    /// [`Self::write_string`]から設定注入パスの拒否だけを除いたもの。
    ///
    /// 本番で呼ぶのは`write_string`だけ。テストは、**書込口を通らない子プロセスの書込**
    /// （CoW で Redirector が差分層へ流すもの）を模すためにこれを使う——反映の段（`apply`）の
    /// 設定注入パスの再検査は、その経路のために残っている。
    fn write_string_unchecked(&self, path: &str, content: &str) -> Result<(), SandboxError> {
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

    /// `rel_dir`（空文字列ならワークスペースのルート）の直下にある名前の一覧。
    /// 実ファイルの名前に、差分層の実効の変更（台帳に載っていない実体を含む）を重ね、削除の記録を引く。
    ///
    /// 承認に「スクリプトの隣の名前一覧」を縛るために使う（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` D-104）。
    /// 差分層の中に新しく作られたサブディレクトリも、その最初の名前として現れる
    /// （`json/__init__.py`が増えれば`json`が増える）。**子の見え方の上位集合**になるよう作ってあり、
    /// 名前の増加を見落とさない側に倒れている。
    pub fn list_dir_names(&self, rel_dir: &str) -> Result<BTreeSet<String>, SandboxError> {
        let dir = rel_dir.trim_matches('/');
        let mut names = self.jail.list_dir_names(dir)?;
        let Some(overlay) = &self.overlay else {
            return Ok(names);
        };
        let prefix = if dir.is_empty() {
            String::new()
        } else {
            format!("{dir}/")
        };
        for e in effective_changes(&self.jail, overlay) {
            let c = e.change;
            if Path::new(&c.path).is_absolute() {
                continue;
            }
            let Some(rest) = c.path.strip_prefix(&prefix) else {
                continue;
            };
            match rest.split_once('/') {
                // 直下のファイル。削除の記録なら名前を引く。
                None => {
                    if c.op == ChangeOp::Delete {
                        names.remove(rest);
                    } else {
                        names.insert(rest.to_string());
                    }
                }
                // もっと深い変更は、直下のサブディレクトリの名前として現れる。
                Some((first, _)) => {
                    if c.op != ChangeOp::Delete {
                        names.insert(first.to_string());
                    }
                }
            }
        }
        Ok(names)
    }

    /// `rel_path`がディレクトリとして見えるか（実ファイルか、差分層に作られたディレクトリ）。
    pub fn is_dir(&self, rel_path: &str) -> bool {
        if self.jail.is_dir(rel_path) {
            return true;
        }
        self.overlay
            .as_ref()
            .is_some_and(|o| o.jail.is_dir(rel_path.trim_matches('/')))
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
        apply_overlay_changes(&self.jail, overlay, opts, &self.workspace_root)
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
    ///
    /// **実ワークスペースへ書く3つめの口なので、`apply`と同じ2つのゲートを掛ける。**
    /// 今日ここへ設定注入パスや`.git`が届かないのは、**それらが`report.conflicts`へ
    /// 一度も入らないから**という**間接的な理由**にすぎない（`apply`が先に弾く）。
    /// 分類が1つ増えるたびにその理屈は崩れるので、口の側に置く（`B-37`: 不変条件の根拠を
    /// 別の機構の副作用へ相乗りさせない）。
    pub fn finalize_resolved(&self, path: &str, content: &str) -> Result<(), SandboxError> {
        if harness_core::is_config_injection_path(path, &self.workspace_root) {
            return Err(SandboxError::ConfigInjection(path.to_string()));
        }
        // **[D-110 (v)]** hard-denyを先に評価する（順序の理由は`apply_overlay_changes`側に書いた）。
        if harness_core::is_git_internal_path(path, &self.workspace_root) {
            return Err(SandboxError::GitInternalWithheld(path.to_string()));
        }
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
    workspace_root: &Path,
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
        if harness_core::is_config_injection_path(&canonical, workspace_root) {
            report.hard_denied.push(c.path.clone());
            continue;
        }
        // **[D-110 (v)] `.git`成分を持つ変更はここでは反映しない（「保留」）。**
        //
        // **順序が意味を持つ。** 上のhard-denyを**先に**評価する——`.git/config`・`.git/hooks`・
        // `.git/info/exclude`は両方に当たるが、あちらは「設定注入の試み」という攻撃の合図なので、
        // 正常なgit内容と同じ分類へ混ぜない（2026-09-26のユーザー判断）。
        //
        // **なぜ前のゲートだけでは足りないのか**: gitは内容のハッシュを名前にしたオブジェクトと
        // refの移動でファイルを運べるので、`.git/objects/ab/cdef…`というパスには中身の情報が
        // 1ビットも無い。実測で、拒否対象の追跡ファイルをこの形で運ぶと
        // **サンドボックス外の普通の`git checkout`で実体化した**（`docs/bugs/BUG-167.md`）。
        // **危険な実行はharnessのgitではなく、そのあと人やエディタが打つgitである**ので、
        // 反映してしまえばharnessは経路に居ない——入口で止めるしかない。
        if harness_core::is_git_internal_path(&canonical, workspace_root) {
            report.git_withheld.push(c.path.clone());
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

    /// **[BUG-126] 層3。** 絶対パスで綴った設定注入パスは`_ext`分岐へ入り、
    /// `canonical`が絶対のまま判定器へ渡るので前方一致しなかった。
    ///
    /// **`--dangerously-allow`（`allow_ext: true`）を通しても hard-deny が掛かること**を測る
    /// ——`--dangerously-allow`は「ワークスペースの外を触るな」を守る**別目的のゲート**であって、
    /// 「設定注入パスを触るな」を守るゲートではない。片方で代用できると読むと、
    /// `.git/hooks/pre-commit`が実FSへ着地する。
    #[test]
    fn apply_hard_denies_an_absolute_path_that_points_back_into_the_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();
        let target = dir.path().join(".git").join("hooks").join("pre-commit");
        let abs = target.to_string_lossy().replace('\\', "/");
        fs.stage_like_a_child_for_test(&abs, "#!/bin/sh\necho pwned\n")
            .unwrap();

        let report = fs
            .apply(&ApplyOptions {
                only_glob: None,
                only_paths: None,
                allow_ext: true,
                adopt_unledgered: false,
            })
            .unwrap();

        assert!(report.applied.is_empty(), "{report:?}");
        assert_eq!(report.hard_denied.len(), 1, "{report:?}");
        assert!(
            !target.exists(),
            "the hook landed on the real filesystem: {}",
            target.display()
        );
    }

    /// **[BUG-126] 対（過剰拒否側）。** ワークスペース外の絶対パスは従来どおり
    /// `allow_ext`だけがゲートで、hard-denyの対象ではない。
    /// **これが無いと「絶対パスなら全部hard-deny」でも上のテストが通る**——
    /// それは`_ext`経路そのものを殺す（T-11と`ApplyOptions::allow_ext`の存在意義が消える）。
    #[test]
    fn apply_still_writes_an_ordinary_absolute_path_outside_the_workspace() {
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

        assert!(report.hard_denied.is_empty(), "{report:?}");
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

    /// 名前一覧は、実ファイルに差分層の実効の変更を重ねて削除の記録を引いたもの（D-104）。
    /// 差分層で増えたファイル・増えたサブディレクトリ・台帳に載らずに子が直接置いた実体の
    /// どれでも名前が増え、削除の記録で名前が消える。差分層の無い直接書くモードでは実ファイルだけ。
    #[test]
    fn list_dir_names_merges_the_diff_layer_over_the_workspace() {
        let ws = tempfile::tempdir().unwrap();
        let diff = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("build.py"), "print(1)").unwrap();
        std::fs::write(ws.path().join("README"), "r").unwrap();
        std::fs::create_dir_all(ws.path().join("lib")).unwrap();
        std::fs::write(ws.path().join("lib/util.py"), "u").unwrap();

        let live = SandboxFs::open(ws.path(), &StagingConfig::default()).unwrap();
        let names: Vec<String> = live.list_dir_names("").unwrap().into_iter().collect();
        assert_eq!(names, ["README", "build.py", "lib"]);

        let fs = SandboxFs::open_with_cow(
            ws.path(),
            &StagingConfig::default(),
            &ReadScopeConfig::default(),
            Some(diff.path()),
        )
        .unwrap();
        fs.stage_like_a_child_for_test("json.py", "evil").unwrap();
        fs.stage_like_a_child_for_test("pkg/__init__.py", "evil")
            .unwrap();
        fs.remove("README").unwrap();
        // 台帳に載らずに差分層へ直接置かれた実体（BUG-066 の形）。
        std::fs::write(diff.path().join("stray.py"), "x").unwrap();

        let names: Vec<String> = fs.list_dir_names("").unwrap().into_iter().collect();
        assert!(names.contains(&"json.py".to_string()), "{names:?}");
        assert!(names.contains(&"pkg".to_string()), "{names:?}");
        assert!(names.contains(&"stray.py".to_string()), "{names:?}");
        assert!(names.contains(&"build.py".to_string()), "{names:?}");
        assert!(!names.contains(&"README".to_string()), "{names:?}");

        let lib: Vec<String> = fs.list_dir_names("lib").unwrap().into_iter().collect();
        assert_eq!(lib, ["util.py"]);
        assert!(fs.list_dir_names("no-such-dir").unwrap().is_empty());
        assert!(
            fs.is_dir("pkg"),
            "a directory created in the diff layer is a directory"
        );
    }

    /// 書込口は設定注入パスを拒否する（D-101）。直接書くモード（オーバーレイ無し）と
    /// ステージング（オーバーレイ有り）の両方で、綴りの揺れも含めて拒否し、実ファイルは変わらない。
    /// 対照として、同じ書込口で普通のファイルは書ける。
    #[test]
    fn write_string_refuses_config_injection_paths_in_both_live_and_staged_modes() {
        for staged in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(dir.path().join(".git")).unwrap();
            std::fs::write(dir.path().join(".git/config"), "original").unwrap();
            let config = if staged {
                staged_config(".harness/sandbox/s1")
            } else {
                StagingConfig::default()
            };
            let fs = SandboxFs::open(dir.path(), &config).unwrap();

            for spelling in [
                ".git/config",
                ".GIT/config",
                "././.git/config",
                ".harness/settings.json",
            ] {
                let err = fs.write_string(spelling, "evil").unwrap_err();
                assert!(
                    matches!(err, SandboxError::ConfigInjection(_)),
                    "staged={staged} {spelling}: {err:?}"
                );
            }
            assert_eq!(
                std::fs::read_to_string(dir.path().join(".git/config")).unwrap(),
                "original",
                "staged={staged}"
            );

            fs.write_string("src/main.rs", "fn main() {}").unwrap();
            assert_eq!(
                fs.read_to_string("src/main.rs").unwrap(),
                "fn main() {}",
                "staged={staged}: a normal file must still be writable"
            );
        }
    }

    /// `.git`のような成分に対してOSが自動生成する8.3短縮名（この機では`GIT~1`）を、
    /// 実際にOSへ聞いて返す。8.3が無効なボリュームでは長い名前がそのまま返るので`None`。
    ///
    /// **綴りを推測しない。** 別名は衝突順で決まる（`~1`とは限らない）ので、
    /// テストが自分で組み立てると「この機では別名が違うので迂回が再現しなかった」ことと
    /// 「迂回が塞がっている」ことが区別できなくなる。
    #[cfg(windows)]
    fn os_short_name_of(path: &Path) -> Option<String> {
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::GetShortPathNameW;
        let wide = crate::win_common::wide(&path.to_string_lossy());
        let mut buf = vec![0u16; 32768];
        let len = unsafe { GetShortPathNameW(PCWSTR(wide.as_ptr()), Some(&mut buf)) } as usize;
        if len == 0 || len > buf.len() {
            return None;
        }
        let shortened = String::from_utf16_lossy(&buf[..len]);
        let last = Path::new(&shortened)
            .file_name()?
            .to_string_lossy()
            .into_owned();
        // 8.3が無効なら長い名前がそのまま返る。その場合は別名が存在しない。
        let long = path.file_name()?.to_string_lossy().into_owned();
        if last.eq_ignore_ascii_case(&long) {
            None
        } else {
            Some(last)
        }
    }

    /// **8.3短縮名の別名で、書込口（D-101）と`apply`（層3）の両方を迂回できるか。**
    ///
    /// NTFSは`.git`のような成分に短い別名を自動生成し、**OSはそれを実体へ解決する**。
    /// 判定器（`is_config_injection_path`）は綴りの前方一致で見るので、別名は素通りし得る
    /// ——`.GIT/config`（大小）や`.git./config`（末尾ドット）と同じクラスである。
    ///
    /// **別名はOSに聞く**（上の`os_short_name_of`）。8.3が無効なボリュームでは
    /// 別名が存在しないので、**測れなかったことを出力に明記してから**その部分だけ飛ばす
    /// ——黙って緑にすると「塞がっている」と読めてしまう（`B-12`）。
    ///
    /// 拒否側と許可側を対にする（`B-35`）: 別名経由の書込が拒否され、
    /// 同じ書込口で普通のファイルは書けること。
    #[cfg(windows)]
    #[test]
    fn hard_deny_is_not_bypassable_by_an_8dot3_short_name_alias() {
        // (1) 書込口（D-101）。直接書くモードとステージングの両方。
        // **反復ごとに置き場を作り直す**——共有すると、前の反復が作った実体を
        // 次の反復の着地として読んでしまう（実際に一度そう出た）。
        // **観測を全部出してから判定する**——「拒否されたか」と「実体へ着地したか」は
        // 別の事実で、前者で止めると後者が記録に残らない。
        let mut observations = Vec::new();
        let mut alias_seen = None;
        for staged in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            // 別名を生成させるために実体を先に作る（存在しないパスには別名が付かない）。
            std::fs::create_dir_all(dir.path().join(".git/hooks")).unwrap();
            let Some(alias) = os_short_name_of(&dir.path().join(".git")) else {
                println!(
                    "MEASUREMENT: 8.3 short names are disabled on this volume, so the alias \
                     bypass could NOT be measured here (this is not evidence that it is closed)"
                );
                return;
            };
            let via_alias = format!("{alias}/hooks/pre-commit");
            let real = dir.path().join(".git/hooks/pre-commit");
            alias_seen = Some(alias.clone());

            let config = if staged {
                staged_config(".harness/sandbox/s1")
            } else {
                StagingConfig::default()
            };
            let fs = SandboxFs::open(dir.path(), &config).unwrap();
            let result = fs.write_string(&via_alias, "#!/bin/sh\nevil\n");
            let landed = real.exists();
            println!(
                "MEASUREMENT: alias=[{alias}] write_string(staged={staged}) -> {result:?} \
                 landed_on_real_.git/hooks/pre-commit={landed}"
            );
            observations.push((
                staged,
                matches!(result, Err(SandboxError::ConfigInjection(_))),
                landed,
                format!("{result:?}"),
            ));
            // 対照: 同じ書込口で普通のファイルは書ける。
            fs.write_string("src/main.rs", "fn main() {}").unwrap();
        }
        for (staged, refused, landed, shown) in &observations {
            assert!(
                refused,
                "staged={staged}: the alias spelling must be refused at the write entry point, \
                 got {shown}"
            );
            assert!(
                !landed,
                "staged={staged}: the write landed on the real .git/hooks/pre-commit \
                 through the alias"
            );
        }
        let alias = alias_seen.expect("at least one iteration ran");
        let via_alias = format!("{alias}/hooks/pre-commit");

        // (2) `apply`（層3）。差分層に実体を置き、台帳へ別名の綴りで載せる。
        let (_ws, _diff_layer_tmp, workspace_root, diff_layer_dir) = tampered_ledger_fixture();
        std::fs::create_dir_all(workspace_root.join(".git/hooks")).unwrap();
        let staged_src = diff_layer_dir.join(&via_alias);
        std::fs::create_dir_all(staged_src.parent().unwrap()).unwrap();
        std::fs::write(&staged_src, "#!/bin/sh\nevil\n").unwrap();
        store::append_entry(&diff_layer_dir, ChangeOp::Create, &via_alias, None);

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
        println!(
            "MEASUREMENT: apply -> applied={:?} hard_denied={:?} rejected={:?}",
            report.applied, report.hard_denied, report.rejected
        );
        assert!(
            !workspace_root.join(".git/hooks/pre-commit").exists(),
            "apply wrote the real .git/hooks/pre-commit through the alias spelling"
        );
        assert_eq!(
            report.hard_denied,
            vec![via_alias.clone()],
            "the alias spelling must be reported as hard-denied, not silently skipped"
        );
    }

    #[test]
    fn apply_hard_denies_staged_git_config_write() {
        let dir = tempfile::tempdir().unwrap();
        let fs = SandboxFs::open(dir.path(), &staged_config(".harness/sandbox/s1")).unwrap();
        fs.stage_like_a_child_for_test(".git/config", "[core]\n\thooksPath = /tmp/evil\n")
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
        fs.stage_like_a_child_for_test(
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
        fs.stage_like_a_child_for_test(".gitattributes", "* text=auto")
            .unwrap();

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

    /// **[D-110 (v)] コミットに包んだ設定注入ファイルが、普通の`apply`では実体化しないこと。**
    ///
    /// **このテストは2026-09-26に意味が反転した。** 元は「迂回が成立する」ことを実証する
    /// 測定で（`apply_hard_deny_is_bypassed_by_git_objects_carrying_a_config_injection_file`、
    /// `#[ignore]`付き）、実際に成立していた。その穴を`git_withheld`で塞いだので、
    /// 同じ手順で**塞がっていること**を固定する側へ書き換えてある。経緯は
    /// `docs/bugs/BUG-167.md`。
    ///
    /// 問い: 追跡ファイル（`.github/workflows/x.yml`）を「ワークツリー実体」ではなく
    /// **「コミット・オブジェクト＋ブランチ移動」として運ぶ**と、実ワークスペースへ届くか。
    /// パスの前置詞一致（`is_config_injection_path`）では止まらない——
    /// `.git/objects/ab/cdef…`というパスには中身の情報が1ビットも無いからである。
    ///
    /// **なぜ透過層を切り離すのか（2026-08-23の実機測定）**: 生の git は当時 CoW の透過層
    /// （Redirector DLL）で完走しなかった（BUG-128で修正済み）。ここでは透過層を外し、
    /// **判定層（apply）だけ**を測る: git が書いたであろうオブジェクト＋ref移動を**本物の git**で
    /// 作って台帳へ載せ、`apply`がそれを保留することを確かめる。
    ///
    /// **拒否側と許可側の対**（`B-35`）:
    /// - 拒否側: apply 後にサンドボックス外で`git checkout`しても、拒否対象ファイルは**出てこない**。
    /// - 許可側: 同じ台帳に載せた普通のファイルは**反映される**（機構が死んでいれば両方止まる）。
    ///
    /// 昇格は不要（AppContainer も Redirector も使わない）。**`#[ignore]`は外した**——
    /// 塞いだ穴の回帰テストなので、明示的に撃たない限り走らない形では守りにならない
    /// （`B-12`: 走っていないことと通ったことが外形上区別できない）。外部の`git`に依存するが、
    /// **無ければスキップせず失敗させる**。
    #[test]
    fn apply_withholds_git_internals_so_an_object_carried_injection_never_materializes() {
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
        let master_ref = workspace_root
            .join(".git")
            .join("refs")
            .join("heads")
            .join("master");
        assert!(
            master_ref.exists(),
            "seed must leave a loose master ref (not packed); found none at {master_ref:?}"
        );
        let c0_ref_bytes = std::fs::read(&master_ref).unwrap();
        // 注入前のHEAD。**保留が効いていれば apply 後もここから動かない。**
        let c0 = git(&workspace_root, &["rev-parse", "HEAD"]);
        let loose_before = loose_objects(&workspace_root.join(".git").join("objects"));

        // 2) workspaceのコピー側で注入コミットを作る（本物の git、サンドボックス外）。
        //    実workspaceの`.git`は一切触らない——迂回ペイロードは「外から台帳経由で運ぶ」。
        let build = diff_layer_tmp.path().join("build");
        copy_dir_all(&workspace_root, &build);
        std::fs::create_dir_all(build.join(".github").join("workflows")).unwrap();
        std::fs::write(
            build.join(".github").join("workflows").join("x.yml"),
            INJECTED,
        )
        .unwrap();
        git(&build, &["add", ".github/workflows/x.yml"]);
        git(
            &build,
            &[
                "commit",
                "-q",
                "-m",
                "inject ci workflow via tracked object",
            ],
        );
        let c1 = git(&build, &["rev-parse", "HEAD"]);
        let build_ref_bytes =
            std::fs::read(build.join(".git").join("refs").join("heads").join("master")).unwrap();

        // 3) 差分オブジェクト＋ref移動＋ワークツリー実体を 差分層 へ置き、台帳へ載せる
        //    （Redirector の copy-up が記録したであろう形を、本物のオブジェクトで再現する）。
        let loose_after = loose_objects(&build.join(".git").join("objects"));
        let new_objects: Vec<String> = loose_after.difference(&loose_before).cloned().collect();
        assert!(
            !new_objects.is_empty(),
            "the injected commit must create new loose objects (blob/tree/commit)"
        );
        for rel in &new_objects {
            let src = build.join(".git").join("objects").join(rel);
            let dst = diff_layer_dir.join(".git").join("objects").join(rel);
            std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
            std::fs::copy(&src, &dst).unwrap();
            store::append_entry(
                &diff_layer_dir,
                ChangeOp::Create,
                &format!(".git/objects/{rel}"),
                None,
            );
        }
        // ブランチ移動（Modify。baseline＝実workspaceの現在の master 内容＝c0）。
        std::fs::create_dir_all(diff_layer_dir.join(".git").join("refs").join("heads")).unwrap();
        std::fs::write(
            diff_layer_dir
                .join(".git")
                .join("refs")
                .join("heads")
                .join("master"),
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
            diff_layer_dir
                .join(".github")
                .join("workflows")
                .join("x.yml"),
            INJECTED,
        )
        .unwrap();
        store::append_entry(
            &diff_layer_dir,
            ChangeOp::Create,
            ".github/workflows/x.yml",
            None,
        );
        // 許可側の対照（`B-35`）: **同じ台帳に載せた普通のファイル**。
        // これが反映されないなら、止まった理由は「保留が効いた」ではなく「applyが死んでいる」。
        const ORDINARY: &str = "fn main() {}";
        std::fs::create_dir_all(diff_layer_dir.join("src")).unwrap();
        std::fs::write(diff_layer_dir.join("src").join("main.rs"), ORDINARY).unwrap();
        store::append_entry(&diff_layer_dir, ChangeOp::Create, "src/main.rs", None);

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
        let applied: Vec<String> = report
            .applied
            .iter()
            .map(|p| p.replace('\\', "/"))
            .collect();
        let hard_denied: Vec<String> = report
            .hard_denied
            .iter()
            .map(|p| p.replace('\\', "/"))
            .collect();

        let git_withheld: Vec<String> = report
            .git_withheld
            .iter()
            .map(|p| p.replace('\\', "/"))
            .collect();

        // 対照その1（機構が生きている証拠）: ワークツリーの設定注入パスは hard_denied のまま。
        // **`git_withheld`へ移っていないこと**も見る——D-110 (v)は「拒否が勝つ」と定めており、
        // 攻撃の合図を保留に混ぜない（混ざると`.git/objects`の山に埋もれる）。
        assert!(
            hard_denied.iter().any(|p| p == ".github/workflows/x.yml"),
            "control: the working-tree config-injection path must stay hard-denied (not merely \
             withheld), otherwise this test cannot distinguish a live deny mechanism from a dead \
             one (B-35). report={report:?}"
        );
        assert!(
            !git_withheld.iter().any(|p| p == ".github/workflows/x.yml"),
            "hard-deny must win over withholding for config-injection paths (D-110 (v)): \
             report={report:?}"
        );
        // 対照その2（許可側）: 同じ台帳の普通のファイルは反映される。
        assert!(
            applied.iter().any(|p| p == "src/main.rs"),
            "an ordinary file in the same ledger must still be applied, otherwise apply is simply \
             dead (B-35): report={report:?}"
        );
        assert_eq!(
            std::fs::read_to_string(workspace_root.join("src").join("main.rs")).unwrap(),
            ORDINARY
        );

        // 本題（拒否側）: オブジェクトと ref は **1件も反映されず、全件が保留**になる。
        assert!(
            !applied.iter().any(|p| p.starts_with(".git/")),
            "no path under .git may be applied as a plain file (D-110 (v)): report={report:?}"
        );
        let objects_withheld = git_withheld
            .iter()
            .filter(|p| p.starts_with(".git/objects/"))
            .count();
        assert_eq!(
            objects_withheld,
            new_objects.len(),
            "every injected git object must be withheld: report={report:?}"
        );
        assert!(
            git_withheld.iter().any(|p| p == ".git/refs/heads/master"),
            "the moved branch ref must be withheld too — withholding only the objects would still \
             let a later `git checkout` see the new tip: report={report:?}"
        );

        // 実FS: ワークツリー実体も、gitの内部ファイルも、1つも実ワークスペースへ現れない。
        let wt = workspace_root
            .join(".github")
            .join("workflows")
            .join("x.yml");
        assert!(
            !wt.exists(),
            "the working-tree file must NOT be materialized by apply itself (it was hard-denied)"
        );
        let real_objects = loose_objects(&workspace_root.join(".git").join("objects"));
        assert!(
            new_objects.iter().all(|o| !real_objects.contains(o)),
            "none of the injected objects may reach the real object store: \
             real={real_objects:?} injected={new_objects:?}"
        );

        // 5) **穴が塞がったことの本体**: サンドボックス外で checkout しても、
        //    運べなかったオブジェクトからは何も出てこない。実HEADも動いていない。
        assert_eq!(
            git(&workspace_root, &["rev-parse", "HEAD"]),
            c0,
            "the real HEAD must still point at the pre-existing commit (the ref was withheld)"
        );
        let out = std::process::Command::new("git")
            .current_dir(&workspace_root)
            .args(["-c", "safe.directory=*"])
            .args(["checkout", "HEAD", "--", ".github/workflows/x.yml"])
            .output()
            .unwrap_or_else(|e| panic!("git checkout: {e} (is git installed and on PATH?)"));
        assert!(
            !out.status.success(),
            "`git checkout` must fail because the injected path is not in the real HEAD; \
             it succeeded, which means the bypass is open again"
        );
        assert!(
            !wt.exists(),
            "BYPASSが再び開いている: サンドボックス外の`git checkout`が、密輸した\
             オブジェクトから hard-deny 対象ファイルを実体化させた"
        );
        // `c1`（注入コミット）は差分層の中にだけ在り、実リポジトリには無い。
        let rev_parse_c1 = std::process::Command::new("git")
            .current_dir(&workspace_root)
            .args(["-c", "safe.directory=*"])
            .args(["cat-file", "-e", &c1])
            .output()
            .unwrap();
        assert!(
            !rev_parse_c1.status.success(),
            "the injected commit object {c1} must not exist in the real repository"
        );
    }

    /// **[D-110 (v)]** 前置詞一致の拒否リストでは止まらない形が、成分単位の保留で止まること。
    ///
    /// ここに並べたものは**どれも`CONFIG_INJECTION_PREFIXES`に載っていない**
    /// （載っているのは`.git/config`・`.git/hooks`・`.git/info/exclude`の3つだけ）。
    /// つまり保留が無ければ全件が普通のファイルとして実ワークスペースへ書かれる。
    ///
    /// **入れ子の`.git`が入っているのが要点である**——前置詞一致は先頭しか見ないので、
    /// `vendor/x/.git/config`は原理的に当たらない。
    #[test]
    fn apply_withholds_git_internals_that_the_prefix_list_cannot_see() {
        let withheld_forms = [
            ".git/objects/ab/cdef1234567890",
            ".git/refs/heads/topic",
            ".git/HEAD",
            ".git/packed-refs",
            ".git/objects/info/alternates",
            ".git/refs/replace/deadbeef",
            ".git/logs/HEAD",
            ".git/shallow",
            ".git/info/grafts",
            ".git/config.worktree",
            ".git/modules/sub/config",
            // 入れ子のリポジトリ（前置詞一致では絶対に当たらない）
            "vendor/x/.git/config",
            "vendor/x/.git/objects/ab/cdef",
        ];
        let (_ws, _diff_layer_tmp, workspace_root, diff_layer_dir) = tampered_ledger_fixture();
        for form in withheld_forms {
            let src = diff_layer_dir.join(form);
            std::fs::create_dir_all(src.parent().unwrap()).unwrap();
            std::fs::write(&src, "payload").unwrap();
            store::append_entry(&diff_layer_dir, ChangeOp::Create, form, None);
        }
        // 許可側の対照（`B-35`）: `.git`成分を持たない、名前が似ているだけのもの。
        // **これらは保留ではなく hard-deny が受け持つ**（分担がずれていないことを見る）。
        for form in [".gitattributes", ".gitlab-ci.yml"] {
            std::fs::write(diff_layer_dir.join(form), "payload").unwrap();
            store::append_entry(&diff_layer_dir, ChangeOp::Create, form, None);
        }
        // 許可側の対照その2: 普通のファイルは反映される。
        std::fs::create_dir_all(diff_layer_dir.join("src")).unwrap();
        std::fs::write(diff_layer_dir.join("src").join("lib.rs"), "ok").unwrap();
        store::append_entry(&diff_layer_dir, ChangeOp::Create, "src/lib.rs", None);

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
        let norm = |v: &Vec<String>| -> Vec<String> {
            v.iter().map(|p| p.replace('\\', "/")).collect()
        };
        let withheld = norm(&report.git_withheld);
        let denied = norm(&report.hard_denied);
        let applied = norm(&report.applied);

        for form in withheld_forms {
            assert!(
                withheld.iter().any(|p| p == form),
                "{form} must be withheld (the prefix list cannot see it): report={report:?}"
            );
            assert!(
                !workspace_root.join(form).exists(),
                "{form} must not reach the real workspace"
            );
        }
        for form in [".gitattributes", ".gitlab-ci.yml"] {
            assert!(
                denied.iter().any(|p| p == form),
                "{form} is not a `.git` component — the prefix list must keep hard-denying it: \
                 report={report:?}"
            );
        }
        assert_eq!(
            applied,
            vec!["src/lib.rs".to_string()],
            "exactly the ordinary file must be applied: report={report:?}"
        );
    }

    /// **[D-110 (v)]** ハンク単位の口（`apply_hunks`）にも同じ保留が掛かること。
    ///
    /// ここを抜くと「ファイル全体は保留されるが、一部だけ選べば通る」という形で同じ穴が残る。
    #[test]
    fn applying_hunks_withholds_git_internals_too() {
        let (_ws, _diff_layer_tmp, workspace_root, diff_layer_dir) = tampered_ledger_fixture();
        std::fs::create_dir_all(workspace_root.join(".git")).unwrap();
        std::fs::write(workspace_root.join(".git/HEAD"), "ref: refs/heads/master\n").unwrap();
        std::fs::create_dir_all(diff_layer_dir.join(".git")).unwrap();
        std::fs::write(diff_layer_dir.join(".git/HEAD"), "ref: refs/heads/evil\n").unwrap();
        store::append_entry(&diff_layer_dir, ChangeOp::Modify, ".git/HEAD", None);

        let fs = SandboxFs::open_with_cow(
            &workspace_root,
            &StagingConfig::default(),
            &ReadScopeConfig::default(),
            Some(&diff_layer_dir),
        )
        .unwrap();
        let report = fs
            .apply_hunks(&crate::overlay_hunks::HunkSelection {
                path: ".git/HEAD",
                // ハッシュの中身は問わない——**保留はハッシュ照合より前に掛かる**
                // （掛からなければ、ここが不一致でも`conflicts`として素通りしてしまう）。
                workspace_hash: String::new(),
                overlay_hash: String::new(),
                accepted: &[0],
            })
            .unwrap();
        assert_eq!(
            report.git_withheld.len(),
            1,
            "the hunk-level mouth must withhold it too: report={report:?}"
        );
        assert!(report.applied.is_empty());
        assert_eq!(
            std::fs::read_to_string(workspace_root.join(".git/HEAD")).unwrap(),
            "ref: refs/heads/master\n",
            "the real .git/HEAD must be untouched"
        );
    }

    /// **[D-110 (v)]** `finalize_resolved`（実ワークスペースへ書く3つめの口）も保留すること。
    ///
    /// 今日ここへ`.git`が届かないのは「保留されたものは`conflicts`へ入らない」という
    /// **間接的な理由**にすぎない。分類が1つ増えるたびにその理屈は崩れるので、口の側で見る
    /// （`B-37`: 不変条件の根拠を別の機構の副作用へ相乗りさせない）。
    #[test]
    fn finalizing_a_resolved_merge_refuses_git_internals_and_config_injection() {
        let (_ws, _diff_layer_tmp, workspace_root, diff_layer_dir) = tampered_ledger_fixture();
        let fs = SandboxFs::open_with_cow(
            &workspace_root,
            &StagingConfig::default(),
            &ReadScopeConfig::default(),
            Some(&diff_layer_dir),
        )
        .unwrap();
        let err = fs
            .finalize_resolved(".git/refs/heads/master", "deadbeef\n")
            .unwrap_err();
        assert!(
            matches!(err, SandboxError::GitInternalWithheld(_)),
            "expected a withholding error, got {err:?}"
        );
        let err = fs.finalize_resolved(".git/config", "[core]\n").unwrap_err();
        assert!(
            matches!(err, SandboxError::ConfigInjection(_)),
            "hard-deny must win for config-injection paths, got {err:?}"
        );
        // 許可側（`B-35`）: 普通のパスは書ける。
        fs.finalize_resolved("src/main.rs", "fn main() {}").unwrap();
        assert_eq!(
            std::fs::read_to_string(workspace_root.join("src").join("main.rs")).unwrap(),
            "fn main() {}"
        );
    }

    /// **[D-110 (v)]** 一覧の分類が、`apply`の実際の扱いと一致すること。
    ///
    /// 表示側は`ChangeEntry::category`を見て畳むので、**ここがずれると画面で見た扱いと
    /// 実際の扱いが違う**ことになる。
    #[test]
    fn change_entries_are_categorized_the_same_way_apply_treats_them() {
        let (_ws, _diff_layer_tmp, workspace_root, diff_layer_dir) = tampered_ledger_fixture();
        for form in [".git/objects/ab/cdef", ".git/config", "src/main.rs"] {
            let src = diff_layer_dir.join(form);
            std::fs::create_dir_all(src.parent().unwrap()).unwrap();
            std::fs::write(&src, "x").unwrap();
            store::append_entry(&diff_layer_dir, ChangeOp::Create, form, None);
        }
        let fs = SandboxFs::open_with_cow(
            &workspace_root,
            &StagingConfig::default(),
            &ReadScopeConfig::default(),
            Some(&diff_layer_dir),
        )
        .unwrap();
        let by_path: std::collections::HashMap<String, ChangeCategory> = fs
            .change_set()
            .unwrap()
            .into_iter()
            .map(|e| (e.path.replace('\\', "/"), e.category))
            .collect();
        assert_eq!(
            by_path.get(".git/objects/ab/cdef"),
            Some(&ChangeCategory::GitInternal)
        );
        assert_eq!(
            by_path.get(".git/config"),
            Some(&ChangeCategory::ConfigInjection),
            "hard-deny wins over withholding, and the listing must say the same thing"
        );
        assert_eq!(
            by_path.get("src/main.rs"),
            Some(&ChangeCategory::SideEffect)
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
