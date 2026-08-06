//! 台帳から「実在しないパスを指すエントリ」を落とすときの判定（D-53）。
//!
//! 台帳は`preflight`が起動のたびに追記する一方、**誰も消さない**ため記録が積もる
//! （実測で`workspace-grant-ledger.json`が1,043件・155KBまで膨らんでいた）。掃除する機能が
//! `harness fs prune`で、本モジュールはその**判定だけ**を持つ。実際に台帳を書き換えるのは
//! 各台帳の所有モジュール（`Ledger::update`でロックしたうえで削る）。
//!
//! ## 「存在しない」は「消えた」ではない
//!
//! この判定の核心は、[`std::path::Path::exists`]がfalseを返す理由が2つあることである。
//!
//! 1. **オブジェクトが本当に消えた**。NTFSのACLはオブジェクトに乗っているので、
//!    オブジェクトが消えればACEも道連れになる。台帳の記録はもう何も指していない＝消してよい。
//! 2. **ボリューム自体へ到達できない**（未マウントのリムーバブル、オフラインのネットワーク
//!    ドライブ）。オブジェクトもACEも媒体/サーバ側で**生きている**。ここで台帳だけ消すと、
//!    実マシン（あるいは共有先）に**追跡不能なACE**を作る——台帳は`harness fs revoke-*`が
//!    撤収対象を列挙する唯一の一覧なので、記録を失うと剥がす手段ごと失われる。
//!
//! そこで**ボリュームルートが到達可能なときだけ「消えた」と確定する**。2つを区別できない
//! ときは常に残す側へ倒す（`docs/SECURITY-PRINCIPLES.md` P-03）。
//!
//! ## ルートは対象にしない
//!
//! ドライブルート（`C:\`）やUNC共有ルート（`\\server\share`）は、そもそも消えないうえ、
//! 万一消したときの影響が個別のエントリではなくマシン全体に及ぶ（traverse台帳の`C:\`は
//! 全AppContainerセッションのFS I/Oを支えている）。「ルートを消す」という判断自体を
//! 持たせないため、観測結果に関わらず[`PruneVerdict::Root`]で残す。

use std::path::Path;

/// 台帳に載った1パスをFS側から観測した結果。**3つのブールだけ**に落としてあるので、
/// [`classify`]はFSに触れずに単体テストできる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathObservation {
    /// ドライブルート（`C:\`）またはUNC共有ルート（`\\server\share`）そのものか。
    pub is_root: bool,
    /// そのパスが載っているボリュームのルートへ到達できるか。
    pub volume_reachable: bool,
    /// そのパス自身のディレクトリエントリが存在するか。**リンクを辿らない**
    /// （`symlink_metadata`）ので、リンク切れのシンボリックリンク自身もtrueになる。
    pub entry_exists: bool,
}

/// 台帳エントリを落としてよいかの判定結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PruneVerdict {
    /// 実在する。台帳の記録は正しいので残す。
    Alive,
    /// 消えたと確定できる（ボリュームは到達可能で、その上に無い）。落としてよい。
    Gone,
    /// 判定不能。ボリューム自体へ到達できないので、実体が生きている可能性がある。残す。
    Unreachable,
    /// ドライブ/共有のルート自体。常に残す（モジュールdoc参照）。
    Root,
}

impl PruneVerdict {
    /// この判定でエントリを落とすか。**`Gone`だけがtrue**。
    pub fn should_remove(self) -> bool {
        matches!(self, PruneVerdict::Gone)
    }
}

/// 観測結果から判定する純粋関数。FSにもクロックにも触れない。
///
/// 優先順位は `Root` > `Alive` > `Unreachable` > `Gone`。`Gone`は「ルートでなく、実在せず、
/// かつボリュームが到達可能」という3条件が**すべて**揃ったときにだけ出る。
pub fn classify(o: PathObservation) -> PruneVerdict {
    if o.is_root {
        return PruneVerdict::Root;
    }
    if o.entry_exists {
        return PruneVerdict::Alive;
    }
    if !o.volume_reachable {
        return PruneVerdict::Unreachable;
    }
    PruneVerdict::Gone
}

/// 実FSを観測する。[`classify`]と分けてあるのは、判定側をFSから切り離して網羅的に
/// テストするため（`docs/CODE-STRUCTURE-RULES.md`規則3）。
pub fn observe(path: &Path) -> PathObservation {
    // `ancestors()`の最後は必ずルート（`C:\`・`\\server\share`・`/`）になる。
    let root = path.ancestors().last().unwrap_or(path);
    PathObservation {
        is_root: root == path,
        volume_reachable: std::fs::symlink_metadata(root).is_ok(),
        // `exists()`ではなく`symlink_metadata`を使う。リンク切れのシンボリックリンクは
        // `exists()`がfalseになるが、**エントリ自体は残っていてACEも乗りうる**ため。
        entry_exists: std::fs::symlink_metadata(path).is_ok(),
    }
}

/// 台帳に載っているパス文字列を判定する（[`observe`]＋[`classify`]）。
pub fn verdict_for(path: &Path) -> PruneVerdict {
    classify(observe(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(is_root: bool, volume_reachable: bool, entry_exists: bool) -> PathObservation {
        PathObservation {
            is_root,
            volume_reachable,
            entry_exists,
        }
    }

    /// 3ブール＝8通りを全網羅する。`Gone`が出るのは1通りだけであることを表で固定する。
    #[test]
    fn the_full_truth_table_yields_gone_in_exactly_one_case() {
        let cases = [
            //  root,  reachable, exists  -> 期待
            ((true, true, true), PruneVerdict::Root),
            ((true, true, false), PruneVerdict::Root),
            ((true, false, true), PruneVerdict::Root),
            ((true, false, false), PruneVerdict::Root),
            ((false, true, true), PruneVerdict::Alive),
            ((false, false, true), PruneVerdict::Alive),
            ((false, false, false), PruneVerdict::Unreachable),
            ((false, true, false), PruneVerdict::Gone),
        ];
        let mut gone = 0;
        for ((is_root, reachable, exists), expected) in cases {
            let got = classify(obs(is_root, reachable, exists));
            assert_eq!(
                got, expected,
                "classify(root={is_root}, reachable={reachable}, exists={exists})"
            );
            if got.should_remove() {
                gone += 1;
            }
        }
        assert_eq!(gone, 1, "`Gone` must come from exactly one combination");
    }

    /// ルートは観測が何であれ落とさない。`C:\`のtraverse ACEは全AppContainerセッションの
    /// FS I/Oを支えているので、「ルートを消す」判断自体をコードに持たせない。
    #[test]
    fn a_root_is_never_removed_whatever_the_observation_says() {
        for reachable in [true, false] {
            for exists in [true, false] {
                let v = classify(obs(true, reachable, exists));
                assert_eq!(v, PruneVerdict::Root);
                assert!(!v.should_remove());
            }
        }
    }

    /// ボリュームへ到達できないなら、実在しなく見えても残す（未マウントのリムーバブル・
    /// オフラインのネットワークドライブ。実体とACEは生きている）。
    #[test]
    fn an_unreachable_volume_is_never_treated_as_gone() {
        let v = classify(obs(false, false, false));
        assert_eq!(v, PruneVerdict::Unreachable);
        assert!(!v.should_remove());
    }

    #[test]
    fn observe_reports_an_existing_directory_as_alive() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let o = observe(dir.path());
        assert!(o.entry_exists);
        assert!(o.volume_reachable);
        assert!(!o.is_root);
        assert_eq!(classify(o), PruneVerdict::Alive);
    }

    #[test]
    fn observe_reports_a_deleted_directory_as_gone() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().to_path_buf();
        drop(dir);
        let o = observe(&path);
        assert!(!o.entry_exists);
        assert!(
            o.volume_reachable,
            "the temp dir's volume must still be reachable"
        );
        assert_eq!(classify(o), PruneVerdict::Gone);
    }

    /// 実在するパスのルートは、そのパス自身とは別物として観測される（`is_root`が
    /// leafで立たないこと＝ルート判定がパス末端に誤爆しないことの確認）。
    #[test]
    fn observe_marks_only_the_volume_root_as_root() {
        let dir = tempfile::tempdir().expect("create temp dir");
        assert!(!observe(dir.path()).is_root);

        let root = dir.path().ancestors().last().expect("a root exists");
        let o = observe(root);
        assert!(o.is_root, "{} should be observed as a root", root.display());
        assert_eq!(classify(o), PruneVerdict::Root);
    }
}
