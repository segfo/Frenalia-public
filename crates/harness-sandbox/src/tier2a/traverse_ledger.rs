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
    /// ACEを書き込む前の事前記録なら`true`。畳み直し（[`settle_pending_traverse_grants`]）が
    /// 実DACLと照合し、ACEが在れば確定、無ければこの記録だけを落とす。
    #[serde(default)]
    pub pending: bool,
    /// この予定を書いたプロセスの生存マーカー名（`pending`のときだけ意味を持つ）。
    ///
    /// **これが要るのは、畳み直しが他プロセスの飛行中の予定を消し得るからである。** 予定を
    /// 書いてからACEを書き終えるまでの間に別の`harness.exe`が畳み直すと、実DACLにはまだ
    /// ACEが無いので「書込前に止まった予定」と読めてしまい、**まだ生きている相手の回収名を
    /// 奪う**。以前はトランザクション全体を名前付きmutexで直列化してこれを防いでいたが、
    /// その区間にはUACの応答待ちが含まれており（待ちは`INFINITE`）、2つ目の`harness.exe`が
    /// 無言で止まった。持ち主を記録すれば、直列化はこの台帳のread-modify-writeだけで足りる。
    ///
    /// `None`は「持ち主不明」＝実DACLだけで判定する（旧台帳との後方互換であり、マーカーの
    /// 作成に失敗した回もここへ倒れる）。
    #[serde(default)]
    pub pending_owner: Option<String>,
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
    record_traverse_grants(&[path.to_path_buf()]);
}

/// 実際に付与できたtraverse ACEを、チェーン単位で確定する。
///
/// `record_traverse_grant`をノードごとに呼ぶと、台帳全文のread-modify-writeをノード数ぶん
/// 行う。事前記録と確定のどちらも、付与チェーン1本につき1回だけ永続化する。
pub fn record_traverse_grants(paths: &[PathBuf]) {
    record_traverse_grants_in(ledger(), paths);
}

/// 実際に付与できたtraverse ACEを、指定した台帳へチェーン単位で確定する。
///
/// 通常運用では[`record_traverse_grants`]だけがこの入口を使う。`Ledger::at_path`を渡す
/// のは、通常の`%APPDATA%`台帳を触らない強制終了E2Eだけである。
fn record_traverse_grants_in(ledger: &Ledger<TraverseLedger>, paths: &[PathBuf]) {
    if paths.is_empty() {
        return;
    }
    let granted_at = harness_grant_ledger::now_unix_secs();
    ledger.update(|l| {
        for path in paths {
            let path_str = path.to_string_lossy();
            if let Some(entry) = l
                .entries
                .iter_mut()
                .find(|e| harness_grant_ledger::same_ledger_path(&e.path, &path_str))
            {
                entry.granted_at_unix_secs = granted_at;
                entry.pending = false;
                entry.pending_owner = None;
            } else {
                l.entries.push(TraverseLedgerEntry {
                    path: path_str.into_owned(),
                    granted_at_unix_secs: granted_at,
                    pending: false,
                    pending_owner: None,
                });
            }
        }
    });
}

/// traverse ACEを書き始める**前**に、予定する祖先チェーン全体を記録する。
///
/// 付与と台帳記録の間にプロセスが強制終了しても、撤収に必要なパスを失わないようにする
/// traverse ACEを書き始める前に、指定した台帳へ予定を永続化する。
///
/// `pending`は「付与済み」の意味ではないため、既存の確定記録を未確定へ戻さない。
/// 分けている理由は、強制終了E2Eが実機DACLだけを共有し、通常台帳を一切触らずに
/// 同じ順序を通すためである。
///
/// `owner`は自プロセスの生存マーカー名（[`TraverseLedgerEntry::pending_owner`]）。**マーカーは
/// この関数を呼ぶ前に握っておくこと**——先に予定を書くと、その予定は「持ち主を名乗っているが
/// 持ち主が存在しない」瞬間を持ち、他プロセスの畳み直しから見て死んだ持ち主と区別できない
/// （`B-18`: 確認と作成の間に窓を作らない）。
fn begin_traverse_grants_in(
    ledger: &Ledger<TraverseLedger>,
    paths: &[PathBuf],
    owner: Option<&str>,
) {
    if paths.is_empty() {
        return;
    }
    let granted_at = harness_grant_ledger::now_unix_secs();
    ledger.update(|l| {
        for path in paths {
            let path_str = path.to_string_lossy();
            if l.entries
                .iter()
                .any(|e| harness_grant_ledger::same_ledger_path(&e.path, &path_str))
            {
                continue;
            }
            l.entries.push(TraverseLedgerEntry {
                path: path_str.into_owned(),
                granted_at_unix_secs: granted_at,
                pending: true,
                pending_owner: owner.map(str::to_owned),
            });
        }
    });
}

/// 畳み直しが1回で何をしたか。**黙って畳まない**ための値（`B-11`: 保険は発火件数を出す）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PendingSettleOutcome {
    /// 実ACEが在ったので確定へ昇格した件数。
    pub confirmed: usize,
    /// 実ACEが無かったので予定だけを落とした件数。
    pub dropped: usize,
    /// DACLを読めなかったので未確定のまま残した件数（安全側）。
    pub kept_unreadable: usize,
    /// 持ち主がまだ生きているので触らなかった件数。
    pub kept_in_flight: usize,
}

impl PendingSettleOutcome {
    pub fn is_empty(self) -> bool {
        self == Self::default()
    }
}

/// 未確定の事前記録を、**持ち主の生存**と実DACLで突き合わせる。
///
/// 見る順序は「持ち主 → 実DACL」である。持ち主が生きているなら、その予定はいま飛行中で
/// あり、実DACLは**これから**変わる——先にDACLを見ると「まだ書かれていない」を「書かれない
/// まま終わった」と読み違え、生きている相手の回収名を奪う。
///
/// 持ち主が死んでいる（または不明な）予定だけが実DACLの判定へ進む。`Ok(true)`はACEが在るので
/// 確定、`Ok(false)`は書込前に止まったので記録を除去、`Err`は判定不能なので安全側に未確定の
/// まま残す。判定対象はpendingだけなので、`pending`が1件も無ければDACLを1本も読まない。
fn settle_pending_traverse_grants_in(
    value: &mut TraverseLedger,
    is_owner_live: impl Fn(&str) -> bool,
    has_ace: impl Fn(&Path) -> Result<bool, ()>,
) -> PendingSettleOutcome {
    let mut outcome = PendingSettleOutcome::default();
    let mut settled_at = None;
    value.entries.retain_mut(|entry| {
        if !entry.pending {
            return true;
        }
        if entry.pending_owner.as_deref().is_some_and(&is_owner_live) {
            outcome.kept_in_flight += 1;
            return true;
        }
        match has_ace(Path::new(&entry.path)) {
            Ok(true) => {
                entry.pending = false;
                entry.pending_owner = None;
                entry.granted_at_unix_secs =
                    *settled_at.get_or_insert_with(harness_grant_ledger::now_unix_secs);
                outcome.confirmed += 1;
                true
            }
            Ok(false) => {
                outcome.dropped += 1;
                false
            }
            Err(()) => {
                outcome.kept_unreadable += 1;
                true
            }
        }
    });
    outcome
}

/// 自プロセスが「traverseの予定を書いている最中である」ことを表明する生存マーカーの名前。
///
/// トークンは`session_profile::session_token()`（`<pid>-<unix秒>`、プロセス内で不変）を
/// 流用する。ここで採番し直すと、同じ「このプロセス」を指す識別子が2つになる。
#[cfg(windows)]
fn pending_owner_marker_name(token: &str) -> String {
    format!(r"Local\harness-traverse-pending-{token}")
}

/// 自プロセスの生存マーカーを握り、その名前を返す。**握れなければ`None`**。
///
/// マーカーはプロセスが消えるとOSが破棄する（正常終了・強制終了を問わない）。だから
/// 「持ち主が生きているか」は`mutex_exists`で聞くだけで済み、PIDの再利用を心配しなくてよい。
/// 握るのは1プロセスにつき1回で、ハンドルはプロセス終了まで意図的に手放さない。
///
/// **`None`へ倒れたときは持ち主を名乗らない**——名乗れない持ち主を書くと、他プロセスからは
/// 「死んだ持ち主」と区別できず、飛行中の予定が消され得る。名乗らなければ実DACLだけで
/// 判定される（この変更が入る前と同じ振る舞い）。
#[cfg(windows)]
fn hold_pending_owner_marker() -> Option<&'static str> {
    static OWNER: OnceLock<Option<String>> = OnceLock::new();
    OWNER
        .get_or_init(|| {
            let name = pending_owner_marker_name(crate::tier2a::session_profile::session_token());
            match crate::win_common::hold_mutex_for_process_lifetime(&name) {
                Ok(()) => Some(name),
                Err(_) => None,
            }
        })
        .as_deref()
}

/// 指定台帳に残った`pending`を、持ち主の生存と実DACLで照合して畳む。
///
/// ここを通常台帳固定にすると、強制終了E2Eは回復処理だけを別実装で写すしかなくなる。
/// 同じ実装へ隔離台帳を渡せば、`pending`を残した子と次回起動に相当する親の両方が製品と
/// 同じ照合を通る。
#[cfg(windows)]
fn settle_pending_traverse_grants_in_ledger(
    ledger: &Ledger<TraverseLedger>,
) -> PendingSettleOutcome {
    let pending = ledger.load().entries.iter().any(|e| e.pending);
    if !pending {
        return PendingSettleOutcome::default();
    }
    let sid = match crate::tier2a::win_appcontainer::traverse_capability_sid() {
        Ok(sid) => sid,
        // 宛先SIDを導けないなら「ACEが無い」と読んではいけない（測る相手が無いだけである）。
        // 1件も畳まずに戻る＝次の機会へ送る。
        Err(_) => return PendingSettleOutcome::default(),
    };
    ledger.update(|value| {
        settle_pending_traverse_grants_in(value, crate::win_common::mutex_exists, |path| {
            crate::tier2a::win_appcontainer::sid_ace_mask(path, sid.as_psid())
                .map(|mask| mask.is_some())
                .map_err(|_| ())
        })
    })
}

/// **前回までに残った未確定の予定を畳む。** 起動と`harness fs`の入口が呼ぶ。
///
/// # なぜ付与の経路だけでは足りないのか
///
/// 畳み直しを「次のtraverse付与のとき」に置くと、**付与が二度と起きない場合に一度も走らない**。
/// `preflight`が付与へ進むのは祖先traverseが不足しているときだけなので、実ACEを書き終えた
/// 直後に落ちた回は、以後ずっと`pending`のまま残る。UACを断った回に至っては、ACEが1本も
/// 無いのに予定だけが残り、D-48のガード（`is_recorded`）と`harness fs list`がそれを
/// 「載っている」と数え続ける。
///
/// `pending`が1件も無ければ台帳を1回読んで戻るだけである（実DACLは1本も読まない）。
#[cfg(windows)]
pub fn settle_pending_traverse_grants() {
    let outcome = settle_pending_traverse_grants_in_ledger(ledger());
    if outcome.is_empty() {
        return;
    }
    eprintln!(
        "harness: settled {} pending traverse grant record(s) left by an earlier run \
         (confirmed={}, dropped={}, unreadable={}, still in flight={}; see docs/bugs/BUG-112.md)",
        outcome.confirmed + outcome.dropped + outcome.kept_unreadable + outcome.kept_in_flight,
        outcome.confirmed,
        outcome.dropped,
        outcome.kept_unreadable,
        outcome.kept_in_flight
    );
}

#[cfg(not(windows))]
pub fn settle_pending_traverse_grants() {}

/// traverse ACE付与を、事前記録から確定まで1つのトランザクションとして実行する。
///
/// 特権ヘルパーは別プロセスなので、実DACLへ書く処理そのものは`work`へ委ねる。一方で台帳は
/// 非昇格側が所有するため、ここで「予定を記録 → ヘルパー/直接付与 → 成功分を確定」を囲む。
///
/// # ここでロックを握らない（2026-09-03）
///
/// 以前はこの区間全体を名前付きmutexで直列化していた。しかし`work`にはUACの応答待ちが
/// 含まれ、待ちは`INFINITE`である——**2つ目の`harness.exe`が、1つ目のUACダイアログが
/// 閉じるまで無言で止まった**。直列化が要ったのは「並走した片方が相手の飛行中の予定を
/// 消す」ためだったので、予定の側に持ち主を書いてそれを防ぐ
/// （[`TraverseLedgerEntry::pending_owner`]）。残る直列化は台帳自身の
/// read-modify-write だけで、UACを跨がない。
#[cfg(windows)]
pub fn with_recorded_traverse_grants<R>(
    targets: &[PathBuf],
    work: impl FnOnce() -> (Vec<PathBuf>, R),
) -> (Vec<PathBuf>, R) {
    with_recorded_traverse_grants_in(ledger(), targets, || {}, work, || {})
}

/// traverseのwrite-ahead transaction本体。
///
/// `before_work`と`after_work`は通常運用ではno-opである。テストだけがここを停止位置にして
/// 子プロセスを強制終了するため、付与前後の窓を時間待ちではなく順序そのもので作れる。
#[cfg(windows)]
fn with_recorded_traverse_grants_in<R>(
    ledger: &Ledger<TraverseLedger>,
    targets: &[PathBuf],
    before_work: impl FnOnce(),
    work: impl FnOnce() -> (Vec<PathBuf>, R),
    after_work: impl FnOnce(),
) -> (Vec<PathBuf>, R) {
    // 順序は固定である: ①マーカーを握る → ②予定を書く → ③ACEを付ける → ④成功分を確定。
    // ①を②より後ろへ動かすと、その間の予定は「持ち主を名乗るが持ち主が居ない」状態になり、
    // 他プロセスの畳み直しから死んだ持ち主と区別できない（`B-18`）。
    let owner = hold_pending_owner_marker();
    settle_pending_traverse_grants_in_ledger(ledger);
    let paths: Vec<PathBuf> = targets
        .iter()
        .flat_map(|target| target.ancestors().map(Path::to_path_buf))
        .collect();
    begin_traverse_grants_in(ledger, &paths, owner);
    before_work();
    let (granted, result) = work();
    after_work();
    record_traverse_grants_in(ledger, &granted);
    (granted, result)
}

/// 強制終了E2Eが通常台帳を汚さず、製品と同じトランザクションを通すためのテスト専用入口。
#[cfg(all(windows, test))]
pub(crate) fn with_recorded_traverse_grants_for_test<R>(
    ledger: &Ledger<TraverseLedger>,
    targets: &[PathBuf],
    before_work: impl FnOnce(),
    work: impl FnOnce() -> (Vec<PathBuf>, R),
    after_work: impl FnOnce(),
) -> (Vec<PathBuf>, R) {
    with_recorded_traverse_grants_in(ledger, targets, before_work, work, after_work)
}

/// 隔離台帳に対して製品と同じ畳み直しを撃つ、テスト専用入口。
#[cfg(all(windows, test))]
pub(crate) fn settle_pending_traverse_grants_for_test(
    ledger: &Ledger<TraverseLedger>,
) -> PendingSettleOutcome {
    settle_pending_traverse_grants_in_ledger(ledger)
}

#[cfg(not(windows))]
pub fn with_recorded_traverse_grants<R>(
    _targets: &[PathBuf],
    work: impl FnOnce() -> (Vec<PathBuf>, R),
) -> (Vec<PathBuf>, R) {
    work()
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

/// `path`がこの台帳に「traverse ACEを付与済み」として載っているか（純粋関数）。
///
/// D-48（`plans/DESIGN-SANDBOX-PRIVSEP.md`）の判定本体。台帳に載っているノードのACEは
/// **harnessが実マシンへ意図的に維持している永続的な修復**であり、汎用の撤収APIから
/// 巻き添えで剥がされてはいけない（[BUG-046](../../../../docs/bugs/BUG-046.md)）。
///
/// # `pending`も「載っている」と数える
///
/// 未確定の予定はまだACEが在るとは限らないが、**安全側はガードを効かせる方**である
/// ——ACEが実際に在るのに守らない側へ倒すと、それがBUG-046そのものになる。実体が無い予定は
/// [`settle_pending_traverse_grants`]が畳んで落とすので、この過剰な保護は次の起動までしか
/// 続かない。
///
/// 突き合わせは`harness_grant_ledger::same_ledger_path`（区切りと大小と末尾の区切りを
/// 吸収する共通判定）を通す。**この判定をこの台帳へ写さない**——同じ判定が2つあると
/// 片方だけ直って静かにずれる（同関数のdoc、`B-19`）。
pub fn is_recorded(path: &Path, ledger: &TraverseLedger) -> bool {
    let target = path.to_string_lossy();
    ledger
        .entries
        .iter()
        .any(|e| harness_grant_ledger::same_ledger_path(&e.path, &target))
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
                    pending: false,
                    pending_owner: None,
                })
                .collect(),
        }
    }

    fn pending_entry(path: &str, owner: Option<&str>) -> TraverseLedgerEntry {
        TraverseLedgerEntry {
            path: path.to_string(),
            granted_at_unix_secs: 1,
            pending: true,
            pending_owner: owner.map(str::to_owned),
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

    #[test]
    fn a_pending_entry_is_settled_only_when_the_real_ace_can_be_read() {
        let mut value = TraverseLedger {
            entries: vec![
                pending_entry("C:\\has-ace", None),
                pending_entry("C:\\was-never-written", None),
                pending_entry("C:\\cannot-read", None),
            ],
        };
        let outcome = settle_pending_traverse_grants_in(
            &mut value,
            |_owner| panic!("no entry names an owner, so liveness must never be asked"),
            |path| match path.to_string_lossy().as_ref() {
                "C:\\has-ace" => Ok(true),
                "C:\\was-never-written" => Ok(false),
                "C:\\cannot-read" => Err(()),
                other => panic!("unexpected path {other}"),
            },
        );

        assert_eq!(
            value.entries.len(),
            2,
            "only a proven-absent ACE is forgotten"
        );
        assert!(
            value
                .entries
                .iter()
                .any(|e| e.path == "C:\\has-ace" && !e.pending),
            "a real ACE must become a confirmed recovery entry"
        );
        assert!(
            value
                .entries
                .iter()
                .any(|e| e.path == "C:\\cannot-read" && e.pending),
            "an unreadable DACL must not erase the only recovery name"
        );
        assert_eq!(
            outcome,
            PendingSettleOutcome {
                confirmed: 1,
                dropped: 1,
                kept_unreadable: 1,
                kept_in_flight: 0,
            },
            "the settle must be able to say what it did (B-11)"
        );
    }

    /// **禁止側と許可側を対で見る**（`B-35`）。死んだ持ち主の予定は畳まれ、生きている持ち主の
    /// 予定は**実DACLを見に行くことすらせず**残る。
    ///
    /// 許可側が壊れると、並走した`harness.exe`が相手の飛行中の予定を消す——ACEを書いた直後に
    /// その相手が落ちれば、回収名を失ったACEが実マシンへ残る（BUG-112そのもの）。
    #[test]
    fn a_pending_entry_owned_by_a_live_process_is_left_alone() {
        let mut value = TraverseLedger {
            entries: vec![
                pending_entry("C:\\in-flight", Some("Local\\owner-alive")),
                pending_entry("C:\\owner-died", Some("Local\\owner-gone")),
            ],
        };
        let outcome = settle_pending_traverse_grants_in(
            &mut value,
            |owner| owner == "Local\\owner-alive",
            |path| {
                assert_eq!(
                    path.to_string_lossy(),
                    "C:\\owner-died",
                    "a live owner's entry must not even be probed: its DACL is about to change"
                );
                Ok(false)
            },
        );

        assert_eq!(
            value.entries.len(),
            1,
            "the live owner's plan must survive and the dead owner's must go"
        );
        assert_eq!(value.entries[0].path, "C:\\in-flight");
        assert!(value.entries[0].pending);
        assert_eq!(
            outcome,
            PendingSettleOutcome {
                confirmed: 0,
                dropped: 1,
                kept_unreadable: 0,
                kept_in_flight: 1,
            }
        );
    }

    /// 確定へ昇格したら持ち主の名前は落とす（`pending`でないエントリが持ち主を名乗っていると、
    /// 次に読む人が「まだ飛行中かもしれない」と読める）。
    #[test]
    fn confirming_an_entry_clears_its_owner() {
        let mut value = TraverseLedger {
            entries: vec![pending_entry("C:\\has-ace", Some("Local\\owner-gone"))],
        };
        settle_pending_traverse_grants_in(&mut value, |_| false, |_| Ok(true));
        assert!(!value.entries[0].pending);
        assert_eq!(value.entries[0].pending_owner, None);
    }

    /// D-48のガードは未確定の予定も守る（安全側。実体が無いものは畳み直しが落とす）。
    #[test]
    fn a_pending_entry_still_counts_as_recorded_for_the_revoke_guard() {
        let value = TraverseLedger {
            entries: vec![pending_entry("C:\\Users", None)],
        };
        assert!(is_recorded(Path::new("c:/users/"), &value));
    }
}
