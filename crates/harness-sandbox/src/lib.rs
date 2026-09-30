//! harness-sandbox: ワークスペースjail + オーバーレイFS。`plans/DESIGN.md`
//! §ファイルサンドボックス・ステージング・シェル隔離、および §ツールシステム
//! 「fsジェイル（cap-std を主ゲート）」参照。
//!
//! 本クレートは次の3層を持つ。
//!
//! 1. **ワークスペースjail**（本ファイルの`WorkspaceJail`）— モード非依存の不変条件。
//! 2. **Tier非依存の機構** — `overlay`（`SandboxFs`: 書込リダイレクト・read-through・
//!    変更マニフェスト・論理削除tombstone・`--live`/`--staged`/`--workspace_commit`の3モード・
//!    apply/discard）、`read_scope`（whitelist/blacklist反転モード）、`resolve`、`secret_env`、
//!    `manifest`。
//! 3. **シェル隔離Tierごとの実装** — `tier1`（Windows制限トークン+低IL）・`tier2a`
//!    （Windows AppContainer、既定）・`tier2b`（Linux bubblewrap）。Tier3（Hyper-V VM +
//!    Incusコンテナ）は`harness-sandbox-vm`クレートが持つ（本クレートの**上**に載る、
//!    `plans/DESIGN.md` §ワークスペース構成参照）。どのTierを選ぶかの判定は`shell_tier`が
//!    持つ（Tier横断のためどのtierモジュールにも属さない）。
//!
//! Tierごとのモジュールは`tierN`のファサード越しにのみ公開する。そこに現れていない
//! モジュール（`tier2a::wfp`等）はそのTier内部の実装詳細である。
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

// --- Tier非依存 ---

/// 昇格ヘルパーの起動側・受信側に共通するガード（T-21/D-44、監査シンクのパス検証）。
/// **windows専用ではない**（パス検証は純粋で全プラットフォームでテストできる）。
pub mod elevated_launch;
// `manifest`・`overlay`・`overlay_hunks`・`read_scope`は、外部がルートの`pub use`（下）
// 経由でしか使わないのでモジュール自体は公開しない（`docs/CODE-STRUCTURE-RULES.md`規則4）。
pub(crate) mod manifest;
pub(crate) mod overlay;
/// オーバーレイ変更のハンク単位レビュー（材料の計算）と部分適用。`overlay`本体から分けた
/// のは1ファイル1,000行の上限（`docs/CODE-STRUCTURE-RULES.md`規則1）と、
/// 「1エントリ全体を適用する」既存経路と「ハンクを選んで合成する」経路が別の責務のため。
pub(crate) mod overlay_hunks;
pub(crate) mod read_scope;
pub mod resolve;
pub mod secret_env;
/// セッションID → オーバーレイの置き場、の写像。起動時（`harness-cli`）とセッション切替時
/// （`harness-tui`）の両方から引かれるため、どちらからも依存できるここに置く。
pub mod session_scope;
/// レビュー面の差分エンジン（表示側と適用側で共有する唯一のハンク計算）。
pub mod textdiff;

/// どのシェル隔離Tierを選ぶかの判定。Tier横断のためどの`tierN`にも属さない。
pub mod shell_tier;

/// `harness-sandbox-vm`（Tier3）がACL/コンソール出力の共通ヘルパーとして参照するため`pub`
/// （`docs/CODE-STRUCTURE-RULES.md`規則4、外部利用が実測されたため公開面へ昇格した）。
#[cfg(windows)]
pub mod win_common;

#[cfg(all(test, windows))]
mod cancel_descendants;

/// 名前付きパイプIPCの下回り（DACL・オーバーラップドI/O・長さプレフィックス・フレーミング）。
/// `tier2a::privhelper`・`tier2a::netfilterd`・`harness-sandbox-vm`の`vmsandboxd`が共有する
/// ため、どの`tierN`にも属さずここに置く。`harness-sandbox-vm`から参照されるため`pub`
/// （`docs/CODE-STRUCTURE-RULES.md`規則4）。
#[cfg(windows)]
pub mod win_pipe_ipc;

/// BUG-051: 子プロセスのコンソール出力（起動直後のANSIコードページ由来のメッセージと、
/// ブートストラップ適用後のUTF-8が同一ストリーム内で混在し得る）を復号するために使う。
/// `run_shell`（Tier0/1/2a）に限らず、Windowsコマンドの出力をエラーメッセージへ載せる
/// 全ての箇所（`win_appcontainer`・`smb_share`・`vmsandbox`）が共通で通す唯一の入口。
#[cfg(windows)]
pub use win_common::decode_console_bytes;

// --- シェル隔離Tierごとの実装 ---
//
// 各`tierN`の`mod.rs`がそのTierのファサード。外部へ見せるモジュールと、Tier内部の
// 実装詳細（`pub(crate)`）の区別はそこで宣言する。

/// Tier0は「保護なし」の起動経路で、ポリシーエディタのパス1（記録）が使う。
/// 隔離Tierの一員ではなく、**あえて隔離しない**入口である（`tier0`のモジュールdoc参照）。
#[cfg(windows)]
pub mod tier0;

#[cfg(windows)]
pub mod tier1;

/// Tier2a本体はwindows専用だが、`tier2a::traverse_ledger`だけは全プラットフォームで
/// コンパイルする（`harness fs list`が非Windowsでも空台帳を表示できるようにするため、
/// 移設前からの挙動）。そのため本モジュール自体には`#[cfg(windows)]`を付けない。
pub mod tier2a;

#[cfg(target_os = "linux")]
pub mod tier2b;

pub use manifest::ManifestOp;
pub use overlay::{
    ApplyOptions, ApplyReport, ChangeCategory, ChangeEntry, SandboxError, SandboxFs,
};
pub use overlay_hunks::{FileReview, HunkBlock, HunkSelection};
pub use read_scope::{ReadScope, ReadScopeError};
pub use secret_env::{build_child_env, git_hardening_env};
pub use shell_tier::{select_tier, FsAccess, FsPassthrough, TierError, WorkspaceWriteMode};
pub use textdiff::{DiffHunk, DiffKind, DiffLine};

use std::path::{Path, PathBuf};

use cap_std::fs::{Dir, File};
use cap_std::time::SystemTime;

/// 名前付きOSミューテックスで`f`を直列化する汎用ヘルパー。
///
/// 実体は[`harness_grant_ledger::with_named_lock`]（台帳のread-modify-writeを複数
/// `harness.exe`同時起動下で直列化するのが元々の用途）。`harness-cli`と
/// `workspace_ledger::begin_workspace_mode`が既にこのパスで参照しているため、
/// 呼び出し側を書き換えずに済むよう再エクスポートする。
pub use harness_grant_ledger::with_named_lock;

/// [D-88] 待たずに取る版と、そのガード。**取れたかどうかで進路を変えたいとき**に使う
/// （workspace準備の leader 選出）。実体は同じクレートにある。
pub use harness_grant_ledger::{try_acquire_named_lock, NamedLock};

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
        self.write_bytes(rel_path, content.as_bytes())
    }

    /// [`Self::write_string`]のバイト列版。CoWのapplyは任意のバイナリ（画像・実行ファイル等）を
    /// 差分層からworkspaceへ移すため、`&str`では表せない（`write_string`はこれを呼ぶ）。
    pub fn write_bytes(&self, rel_path: &str, content: &[u8]) -> Result<(), JailError> {
        use std::io::Write as _;

        let rel = check_relative_path(rel_path)?;
        if let Some(parent) = rel.parent() {
            if !parent.as_os_str().is_empty() {
                self.dir.create_dir_all(parent)?;
            }
        }
        let mut file = self.dir.create(&rel)?;
        file.write_all(content)?;
        Ok(())
    }

    /// ジェイル内のファイルをバイト列として読む（applyのbaseline照合・差分層側実体の読み出し用。
    /// テキストとは限らないので[`Self::read_to_string`]では代用できない）。
    pub fn read_bytes(&self, rel_path: &str) -> Result<Vec<u8>, JailError> {
        use std::io::Read as _;

        let rel = check_relative_path(rel_path)?;
        let mut file = self.dir.open(&rel)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        Ok(buf)
    }

    /// ジェイル内のファイルの長さ（バイト）。無い・読めない・ファイルでないなら`None`。
    ///
    /// **中身を読む前の篩に使う**——「差分層の実体が実workspace側とバイト一致するか」の判定は
    /// 一覧（`harness changes`）のたびに走るので、長さが違うだけで分かる場合に全部を読まない
    /// （[BUG-174](../../docs/bugs/BUG-174.md)）。
    pub fn file_len(&self, rel_path: &str) -> Option<u64> {
        let rel = check_relative_path(rel_path).ok()?;
        let meta = self.dir.metadata(&rel).ok()?;
        meta.is_file().then(|| meta.len())
    }

    /// ジェイル内にディレクトリを（親ごと）作る。
    pub fn create_dir_all(&self, rel_path: &str) -> Result<(), JailError> {
        let rel = check_relative_path(rel_path)?;
        Ok(self.dir.create_dir_all(&rel)?)
    }

    /// ジェイル内の`rel_path`がディレクトリか。**形が不正なパスは`false`**
    /// （呼び出し側は先に`check_relative_path`で弾いている前提。ここで`Result`を返しても
    /// 判断材料が増えない）。
    pub fn is_dir(&self, rel_path: &str) -> bool {
        let Ok(rel) = check_relative_path(rel_path) else {
            return false;
        };
        self.dir.metadata(&rel).map(|m| m.is_dir()).unwrap_or(false)
    }

    /// `rel_dir`（空文字列ならジェイルのルート）の**直下**にある名前（ファイル・ディレクトリの両方）。
    /// ディレクトリが存在しなければ空。承認に「スクリプトの隣の名前一覧」を縛るために使う
    /// （`plans/DESIGN-RUNSHELL-ALLOWLIST.md` D-104）。
    pub fn list_dir_names(
        &self,
        rel_dir: &str,
    ) -> Result<std::collections::BTreeSet<String>, JailError> {
        let collect = |entries: cap_std::fs::ReadDir| -> Result<_, JailError> {
            let mut names = std::collections::BTreeSet::new();
            for entry in entries {
                names.insert(entry?.file_name().to_string_lossy().into_owned());
            }
            Ok(names)
        };
        if rel_dir.is_empty() {
            return collect(self.dir.entries()?);
        }
        let rel = check_relative_path(rel_dir)?;
        match self.dir.open_dir(&rel) {
            Ok(sub) => collect(sub.entries()?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Default::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// ジェイル内に`rel_path`が存在するか（[`Self::is_dir`]と同じく形が不正なら`false`）。
    pub fn exists(&self, rel_path: &str) -> bool {
        let Ok(rel) = check_relative_path(rel_path) else {
            return false;
        };
        self.dir.metadata(&rel).is_ok()
    }

    /// jailルート配下の全ファイルを相対パスで列挙する（`grep`/`glob`用）。
    /// **【T3】`ignore::WalkBuilder`はstdのパスベースopenで自走査しcap-stdの`Dir`ハンドルを
    /// 経由できないため、走査本体はここで組む自前walker（`Dir::entries`＝openat相当）に統一し、
    /// `ignore`/`globset`はgitignore・globのマッチング判定にのみ使う**
    /// （§ツールシステム fsジェイル）。シンボリックリンクは辿らない（jail脱出防止）。
    pub fn walk_files(&self) -> Result<Vec<PathBuf>, JailError> {
        self.walk_files_filtered(&[])
    }

    /// `walk_files`の拡張版（M11）。`skip_dirs`に名前が一致するディレクトリは掘り下げない
    /// （`read.deny_descend`、`plans/DESIGN-SANDBOX.md` §5）。`.git`/`.harness`は常に
    /// 掘り下げ対象外（既存の不変条件、設定に関わらず適用）。
    pub fn walk_files_filtered(&self, skip_dirs: &[String]) -> Result<Vec<PathBuf>, JailError> {
        let mut out = Vec::new();
        Self::walk_dir(&self.dir, PathBuf::new(), &mut out, skip_dirs)?;
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

    fn walk_dir(
        dir: &Dir,
        prefix: PathBuf,
        out: &mut Vec<PathBuf>,
        skip_dirs: &[String],
    ) -> Result<(), JailError> {
        for entry in dir.entries()? {
            let entry = entry?;
            let name = entry.file_name();
            if name == ".git" || name == ".harness" {
                continue;
            }
            let name_str = name.to_string_lossy();
            if skip_dirs.iter().any(|d| d == name_str.as_ref()) {
                continue;
            }
            let rel = prefix.join(&name);
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            } else if file_type.is_dir() {
                let sub = entry.open_dir()?;
                Self::walk_dir(&sub, rel, out, skip_dirs)?;
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
///
/// **判定の実体は[`harness_change_ledger::validate_relative_path`]が持つ**（本関数は
/// エラー型を`JailError`へ写すだけの薄い層）。同じ判定が`SandboxFs::apply`——つまり
/// **サンドボックス子が書ける操作台帳を信頼側が読む地点**——でも要るためで、
/// 2箇所へ別々に書くと片方だけ古くなる（`docs/CODE-STRUCTURE-RULES.md`規則5、
/// [BUG-062](../../docs/bugs/BUG-062.md)）。台帳クレート側に置くのは依存の向きの都合
/// （あちらはRedirector DLLも参照するので`harness-sandbox`へ依存できない）。
pub fn check_relative_path(path: &str) -> Result<PathBuf, JailError> {
    harness_change_ledger::validate_relative_path(path).map_err(|rejection| match rejection {
        harness_change_ledger::PathRejection::Escape => JailError::Escape(path.to_string()),
        harness_change_ledger::PathRejection::Unsafe(reason) => JailError::UnsafePath(reason),
    })
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
