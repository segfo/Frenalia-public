//! `win_appcontainer`配下の実機テストが共有する後始末ユーティリティ（テスト専用）。
//!
//! ここに集めているのはいずれも「**パニックしても実マシンに何も残さない**」ための道具である。
//! テスト末尾の`let _ = std::fs::remove_dir_all(...)`は正常終了時にしか走らず、assertが落ちた
//! 瞬間に残留物が生まれる——実際に`C:\harness-Tier2a-verify-*`が16件残っていたのが
//! [BUG-046](../../../../docs/bugs/BUG-046.md)の修正4である。RAIIなら`panic!`でも巻き戻る。
//!
//! `docs/CODE-STRUCTURE-RULES.md`規則5により、同じ`ScopeGuard`を各テストファイルへ複製せず
//! ここ1箇所に置く（元は`cow_containment_tests.rs`のprivate定義だった）。

/// パニック時にも確実にクロージャを実行する簡易scopeguard（`scopeguard`クレート依存を
/// 避けるための最小実装。テストコード専用）。
pub(super) struct ScopeGuard<F: FnMut()>(F);

impl<F: FnMut()> Drop for ScopeGuard<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}

pub(super) fn scopeguard<F: FnMut()>(f: F) -> ScopeGuard<F> {
    ScopeGuard(f)
}

/// `C:\harness-Tier2a-verify-<label>-<pid>`を作り、Dropで必ず再帰削除するガード。
///
/// **なぜ`tempfile::tempdir()`ではなく`C:\`直下なのか**: `%TEMP%`は実際には
/// `C:\Users\<user>\AppData\Local\Temp\…`という本物のユーザープロファイルの奥にあり、
/// `grant_traverse_chain`が`Path::ancestors()`で祖先を辿ると`C:\Users`・`C:\Users\<user>`まで
/// DACL変更が及ぶ（実行中プロファイルルートへの`SetNamedSecurityInfoW`が数分止まった
/// [BUG-011](../../../../docs/bugs/BUG-011.md)の直接の原因）。ドライブルート直下なら祖先は
/// `C:\`だけで済む。
pub(super) struct TestDirGuard {
    path: std::path::PathBuf,
}

impl TestDirGuard {
    /// 作成に失敗したらpanicする（テストの前提が崩れているので続行しても意味が無い）。
    pub(super) fn create(label: &str) -> Self {
        let path = std::path::PathBuf::from(format!(
            "C:\\harness-Tier2a-verify-{label}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path)
            .unwrap_or_else(|e| panic!("create test dir {}: {e}", path.display()));
        Self { path }
    }

    pub(super) fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TestDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// `subst`で作る**テストが所有する仮想ドライブ**。Dropで`subst /D`と実体の削除まで行う。
///
/// traverse機構の検証に要るのは「まだ誰もACEを付けていないドライブルート」である。`C:\`実体で
/// 剥奪→再付与を試すと、その間にテストが落ちたときマシン全体のTier2a FS I/Oが壊れる
/// （[BUG-046](../../../../docs/bugs/BUG-046.md)そのもの、[BUG-012](../../../../docs/bugs/BUG-012.md)と同型）。
/// `subst`のルートは実体がテスト所有のディレクトリなので、**所有者権限だけで`WRITE_DAC`が
/// 通り管理者権限が要らない**という利点もある。
pub(super) struct SubstDrive {
    letter: char,
    backing: std::path::PathBuf,
}

impl SubstDrive {
    /// 空きドライブレターを`Z`から降順に探して割り当てる。空きが無ければ`None`
    /// （呼び出し側はskipする）。
    pub(super) fn create() -> Option<Self> {
        let backing = std::env::temp_dir().join(format!("harness-subst-root-{}", std::process::id()));
        std::fs::create_dir_all(&backing).ok()?;

        for letter in ('D'..='Z').rev() {
            if std::path::Path::new(&format!("{letter}:\\")).exists() {
                continue;
            }
            let status = std::process::Command::new("subst")
                .arg(format!("{letter}:"))
                .arg(&backing)
                .status();
            if matches!(status, Ok(s) if s.success()) {
                return Some(Self { letter, backing });
            }
        }
        let _ = std::fs::remove_dir_all(&backing);
        None
    }

    /// 仮想ドライブのルート（`X:\`）。`Path::ancestors()`の終端になる。
    pub(super) fn root(&self) -> std::path::PathBuf {
        std::path::PathBuf::from(format!("{}:\\", self.letter))
    }
}

impl Drop for SubstDrive {
    fn drop(&mut self) {
        let _ = std::process::Command::new("subst")
            .arg(format!("{}:", self.letter))
            .arg("/D")
            .status();
        let _ = std::fs::remove_dir_all(&self.backing);
    }
}
