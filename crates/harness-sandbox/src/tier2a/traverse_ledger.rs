//! traverse台帳（D10の巻き戻し用、`fs-passthrough-ledger.json`とは別ファイル）。
//!
//! 元々`crates/harness-cli/src/main.rs`にあったが、`win_appcontainer::preflight`が
//! traverse ACE不足を自動検知してprivhelper経由で付与するようになったため（`preflight`は
//! このcrate内にある）、harness-cli→harness-sandboxの依存方向を逆流させないためここへ移動した。
//! `harness fs grant-traverse`/`revoke-traverse`（harness-cli側）はこのモジュールの関数を呼ぶ。
//!
//! ファイル入出力（誤削除防止の2層・fail-open）は`harness-grant-ledger`の`Ledger<T>`が持つ。
//! 本モジュールはこの台帳固有の「何を記録するか」だけを持つ。

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use harness_grant_ledger::Ledger;

/// traverse台帳の1エントリ。`grant-traverse`は`writable`という概念を持たない（付与する
/// アクセス権は常に`FILE_TRAVERSE | FILE_READ_ATTRIBUTES`固定）ため、fs-passthrough-ledgerの
/// エントリ型とは別の小さな型にする。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TraverseLedgerEntry {
    pub path: String,
    pub granted_at_unix_secs: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TraverseLedger {
    pub entries: Vec<TraverseLedgerEntry>,
}

/// `fs-passthrough-ledger.json`と意味が異なる記録（ドライブルート/祖先ディレクトリへの
/// traverse付与）を混在させないため、別ファイルにする。
///
/// この台帳はD10の巻き戻し（`harness fs revoke-traverse`）の対象一覧のため、複数
/// `harness.exe`同時起動下でのロストアップデートは付与済みtraverse ACEが追跡不能な
/// まま実マシンに残ることを意味する。`Local\harness-traverse-grant-ledger`で
/// read-modify-writeを直列化する（`fs-passthrough-ledger.json`/`tier3-vm-ledger.json`と
/// 同じ方針、R-01）。
fn ledger() -> &'static Ledger<TraverseLedger> {
    static LEDGER: OnceLock<Ledger<TraverseLedger>> = OnceLock::new();
    LEDGER.get_or_init(|| {
        Ledger::in_config_dir(
            "traverse-grant-ledger.json",
            Some("Local\\harness-traverse-grant-ledger"),
        )
    })
}

/// 台帳ファイルのパス（`%APPDATA%\harness\config\traverse-grant-ledger.json`）。
pub fn traverse_ledger_path() -> Option<PathBuf> {
    ledger().path().map(Path::to_path_buf)
}

pub fn load_traverse_ledger() -> TraverseLedger {
    ledger().load()
}

pub fn save_traverse_ledger(ledger_value: &TraverseLedger) {
    ledger().save(ledger_value);
}

/// `grant-traverse`が実際にACE付与を試みたパスをtraverse台帳へ記録する（D10の巻き戻し用）。
/// 同一パスは上書き（冪等）。
pub fn record_traverse_grant(path: &Path) {
    let path_str = path.to_string_lossy().into_owned();
    let granted_at = harness_grant_ledger::now_unix_secs();
    ledger().update(|l| {
        if let Some(entry) = l
            .entries
            .iter_mut()
            .find(|e| harness_grant_ledger::same_ledger_path(&e.path, &path_str))
        {
            entry.granted_at_unix_secs = granted_at;
        } else {
            l.entries.push(TraverseLedgerEntry {
                path: path_str,
                granted_at_unix_secs: granted_at,
            });
        }
    });
}

pub fn remove_traverse_grant(path: &Path) {
    let path_str = path.to_string_lossy().into_owned();
    ledger().update(|l| {
        l.entries
            .retain(|e| !harness_grant_ledger::same_ledger_path(&e.path, &path_str))
    });
}

/// `should_remove`がtrueを返したパスのエントリを落とす（`harness fs prune`、D-53）。
/// 返り値は実際に落としたパスの一覧。
///
/// **判定は呼び出し側が持ち、本関数はロックと永続化だけを持つ。** 台帳ファイルを所有するのは
/// このモジュールなので、CLI側で`load`→`save`する形にはしない（複数`harness.exe`同時起動下の
/// lost updateを避ける、R-01）。
///
/// **D-48との関係**: この台帳に載っていることが`revoke_ace`のガードの発火条件なので、エントリを
/// 落とすとその祖先ノードのガードが解除される。呼び出し側は`harness_grant_ledger::prune`の
/// 判定を通すこと——`Gone`は「オブジェクトが存在しない」ことを意味し、存在しないオブジェクトに
/// ACEは載っていないので、ガードが守るべきものがそもそも無い。
pub fn prune_traverse_entries(should_remove: impl Fn(&Path) -> bool) -> Vec<String> {
    ledger().update(|l| {
        let mut removed = Vec::new();
        l.entries.retain(|e| {
            if should_remove(Path::new(&e.path)) {
                removed.push(e.path.clone());
                false
            } else {
                true
            }
        });
        removed
    })
}

/// 台帳のパス文字列とクエリのパスを突き合わせるための正規化。
///
/// 区切りの`/`→`\`置換は`win_common::long_path_wide`（全ACL経路が通る一点で`C:/foo`のような
/// ユーザー入力を吸収している）と同じ方針に揃える。ここが揃っていないと、`grant`は
/// `C:/x`で通ったのに台帳照合だけ`C:\x`で外れる、という食い違いが生まれる。
/// 末尾の区切りを落とすのは`C:\Users`と`C:\Users\`を同一視するため。Windowsのパスは
/// 大文字小文字を区別しないのでASCII小文字化する（パス要素に非ASCIIが来ても、
/// この関数は「一致するか」しか判定しないので取りこぼす方向にしか働かない）。
fn normalize_ledger_path(s: &str) -> String {
    let replaced = s.replace('/', "\\");
    let trimmed = replaced.trim_end_matches('\\');
    // `C:\`のようなドライブルートは末尾を落とすと`C:`になる。これは`C:`（カレント
    // ディレクトリ相対）と別物だが、**両辺に同じ正規化をかけて一致だけを見る**用途では
    // 区別する必要が無い（`C:`単独が台帳へ載ることはない）。
    trimmed.to_ascii_lowercase()
}

/// `path`がこの台帳に「traverse ACEを付与済み」として載っているか（純粋関数）。
///
/// D-48（`plans/DESIGN-SANDBOX-PRIVSEP.md`）の判定本体。台帳に載っているノードのACEは
/// **harnessが実マシンへ意図的に維持している永続的な修復**であり、汎用の撤収APIから
/// 巻き添えで剥がされてはいけない（[BUG-046](../../../../docs/bugs/BUG-046.md)）。
pub fn is_recorded(path: &Path, ledger: &TraverseLedger) -> bool {
    let target = normalize_ledger_path(&path.to_string_lossy());
    ledger
        .entries
        .iter()
        .any(|e| normalize_ledger_path(&e.path) == target)
}

/// [`is_recorded`]の台帳読み込み版。ファイルI/Oを伴うため、呼び出し側は
/// 「撤収しようとしている宛先SIDが本当にtraverse ACEの持ち主（capability SID）か」を
/// 先に判定してから呼ぶこと（`revoke_ace`が全ノードでこれを読むのを避けるため）。
pub fn is_recorded_traverse_node(path: &Path) -> bool {
    is_recorded(path, &load_traverse_ledger())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger_with(paths: &[&str]) -> TraverseLedger {
        TraverseLedger {
            entries: paths
                .iter()
                .map(|p| TraverseLedgerEntry {
                    path: (*p).to_string(),
                    granted_at_unix_secs: 0,
                })
                .collect(),
        }
    }

    /// 台帳は`C:\`という表記で持つが、照合しに来るパスは`C:/`や`c:\`のこともある。
    /// ここが外れると「台帳には載っているのに守られない」＝BUG-046の再来になる。
    #[test]
    fn a_drive_root_matches_regardless_of_separator_and_case() {
        let ledger = ledger_with(&["C:\\"]);
        for probe in ["C:\\", "C:/", "c:\\", "c:/"] {
            assert!(
                is_recorded(Path::new(probe), &ledger),
                "{probe} must match the recorded C:\\ entry"
            );
        }
    }

    #[test]
    fn a_trailing_separator_does_not_change_the_verdict() {
        let ledger = ledger_with(&["C:\\Users"]);
        assert!(is_recorded(Path::new("C:\\Users"), &ledger));
        assert!(is_recorded(Path::new("C:\\Users\\"), &ledger));
        assert!(is_recorded(Path::new("c:/users/"), &ledger));
    }

    /// 前方一致で判定してはいけない（`C:\Users`の登録が`C:\UsersOther`まで守ると、
    /// 今度は本来剥がせるべきACEが剥がせなくなる）。
    #[test]
    fn a_sibling_with_a_shared_prefix_is_not_recorded() {
        let ledger = ledger_with(&["C:\\Users"]);
        assert!(!is_recorded(Path::new("C:\\UsersOther"), &ledger));
        assert!(!is_recorded(Path::new("C:\\Users\\segfo"), &ledger));
    }

    #[test]
    fn an_empty_ledger_records_nothing() {
        let ledger = TraverseLedger::default();
        assert!(!is_recorded(Path::new("C:\\"), &ledger));
    }
}
