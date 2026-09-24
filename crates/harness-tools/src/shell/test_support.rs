//! `run_shell`と`run_program`のテストが共有する部品。
//!
//! **実マシンの共有状態（台帳・ACE）を触る後始末を、1箇所にだけ置く**ために分けてある。
//! 2つのテストファイルに写すと、撤収の順序のような約束が片方だけ直って静かにずれる
//! （`bug-pattern-rules` B-05。このリポジトリの「テストが実マシンの共有状態を触る」方式が招く型）。

#[cfg(windows)]
use std::path::PathBuf;

/// 実preflightを走らせるテスト用の使い捨てワークスペース。**製品の実台帳へ残る記録を
/// 持ち帰る。**
///
/// preflightは成功のたびにworkspace台帳へ1件、capability台帳へモード数ぶんの記録を残す。
/// 使い捨てディレクトリで走らせると、それは**指す先が消えた記録**として積もり続ける
/// （`workspace_ledger`のdocが「実測で1,043件・155KB」と書いているのがこの形である）。
/// 実測でも、素の`cargo test -p harness-tools --lib`1回につきworkspace台帳へ2件・
/// capability台帳へ4件が増えていた。
///
/// # 撤収の順序を型で固定する
///
/// `Drop`は**先にツリーを消し、そのあとで台帳から名前を落とす**。逆にすると、ACEが載った
/// ままの木に対して撤収経路の名前だけが先に消える——`forget_capability`のdocが名指しで
/// 禁じている順序であり、BUG-017/BUG-059が繰り返し踏んだ孤立ACEの形そのものである。
/// `Drop`に置いたのは、テストが途中でpanicしても撤収が走るようにするため。
#[cfg(windows)]
pub(crate) struct Tier2aScratchWorkspace {
    dir: Option<tempfile::TempDir>,
    /// preflightが台帳へ書いたのと同じ綴り（`\\?\`付き）。`remove_workspace_entry`が
    /// 使う`same_ledger_path`はverbatim前置を畳まないので、素のパスでは一致しない。
    canonical: PathBuf,
}

#[cfg(windows)]
impl Tier2aScratchWorkspace {
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().canonicalize().unwrap();
        Self {
            dir: Some(dir),
            canonical,
        }
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        self.dir.as_ref().expect("still alive").path()
    }
}

#[cfg(windows)]
impl Drop for Tier2aScratchWorkspace {
    fn drop(&mut self) {
        drop(self.dir.take());
        harness_sandbox::tier2a::workspace_ledger::remove_workspace_entry(&self.canonical);
        let _ =
            harness_sandbox::tier2a::workspace_capability::forget_capability(&self.canonical, "");
    }
}
