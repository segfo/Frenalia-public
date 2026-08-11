//! 「どのSIDのACEを剥がすか」の判定の真理値表（[BUG-101](../../../../docs/bugs/BUG-101.md)欠陥②）。
//!
//! 分類は純粋関数なので、実AppContainerもレジストリも要らずに全数を固定できる。
//! **禁止側（剥がしてはいけないもの）と許可側（剥がすべきもの）を必ず対で持つ**（B-35）
//! ——片方だけだと、判定が「全部拒否」に退化しても緑のままになる。撤収機構の場合、
//! それは「1件も剥がさないのに成功と報告する」＝このバグそのものである。

use super::*;

const LEGACY: &str = "harness.shell.sandbox";
const DEAD_SESSION: &str = "harness.shell.sandbox.1234-5678";
const LIVE_SESSION: &str = "harness.shell.sandbox.4321-8765";

const SID_LEGACY: &str = "S-1-15-2-1111111111-1-1-1-1-1-1";
const SID_DEAD: &str = "S-1-15-2-2222222222-2-2-2-2-2-2";
const SID_LIVE: &str = "S-1-15-2-3333333333-3-3-3-3-3-3";
const SID_FOREIGN: &str = "S-1-15-2-4444444444-4-4-4-4-4-4";
const SID_ORPHAN: &str = "S-1-15-2-5555555555-5-5-5-5-5-5";

fn registry() -> BTreeMap<String, String> {
    BTreeMap::from([
        (SID_LEGACY.to_string(), LEGACY.to_string()),
        (SID_DEAD.to_string(), DEAD_SESSION.to_string()),
        (SID_LIVE.to_string(), LIVE_SESSION.to_string()),
        // このマシンの実測どおり、登録簿の大半はStoreアプリである。
        (
            SID_FOREIGN.to_string(),
            "microsoft.windowsnotepad_8wekyb3d8bbwe".to_string(),
        ),
    ])
}

/// harnessが実際に書くマスク（`read_write`）。
fn harness_rw_mask() -> u32 {
    fs_access_mask(FsAccess::ReadWrite)
}

struct Fixture {
    registry: BTreeMap<String, String>,
    live: Vec<String>,
    ledger: Vec<String>,
    masks: Vec<u32>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            registry: registry(),
            live: vec![LIVE_SESSION.to_string()],
            ledger: Vec::new(),
            masks: harness_package_sid_masks(),
        }
    }

    fn classify(&self, sid: &str, mask: u32, has_deny: bool) -> SubjectKind {
        SubjectClassifier {
            registered: Some(&self.registry),
            live_profiles: &self.live,
            ledger_sids: &self.ledger,
            harness_masks: &self.masks,
        }
        .classify(sid, mask, has_deny)
    }
}

// --- 許可側: 剥がすべきものが対象になる ---

/// 規則2。**旧共有プロファイルも対象**——`is_session_profile_name`は接尾辞が無い
/// `harness.shell.sandbox`を拒否するので、そこだけに頼ると旧共有ぶんが永久に剥がせない。
#[test]
fn a_dead_harness_profile_is_revocable_including_the_legacy_shared_one() {
    let f = Fixture::new();
    assert!(f
        .classify(SID_DEAD, harness_rw_mask(), false)
        .is_revocable());
    assert!(f
        .classify(SID_LEGACY, harness_rw_mask(), false)
        .is_revocable());
}

/// 規則4。**これがBUG-101で手作業の`icacls`が要った経路**——プロファイルが削除済みで
/// 名前へ逆引きできないSID。マスクがharnessの値と完全一致するものだけを名乗る。
#[test]
fn an_unregistered_sid_carrying_a_mask_harness_grants_is_revocable() {
    let f = Fixture::new();
    for access in FsAccess::ALL {
        assert_eq!(
            f.classify(SID_ORPHAN, fs_access_mask(access), false),
            SubjectKind::UnregisteredHarnessMask,
            "{access:?} is a mask harness writes, so an unregistered SID carrying it is ours"
        );
    }
}

/// 規則3。台帳の記録は登録簿より後に見るが、マスクの指紋よりは強い
/// ——記録は推論ではないので、形が違っても剥がせる。
#[test]
fn a_sid_recorded_in_the_ledger_is_revocable_even_with_an_unfamiliar_mask() {
    let mut f = Fixture::new();
    f.ledger = vec![SID_ORPHAN.to_string()];
    assert_eq!(
        f.classify(SID_ORPHAN, 0x1234, false),
        SubjectKind::LedgerRecorded
    );
}

// --- 禁止側: 剥がしてはいけないものが対象にならない ---

/// **規則0が規則3に勝つ**（`docs/SECURITY-PRINCIPLES.md` P-01）。台帳ファイルは
/// [BUG-103](../../../../docs/bugs/BUG-103.md)(d)でサンドボックスから書ける状態だった。
/// 台帳を無条件に信じると、サンドボックス内から他アプリのACEを剥がさせる経路になる。
#[test]
fn a_registered_foreign_sid_is_never_revocable_even_if_the_ledger_names_it() {
    let mut f = Fixture::new();
    f.ledger = vec![SID_FOREIGN.to_string()];
    let kind = f.classify(SID_FOREIGN, harness_rw_mask(), false);
    assert!(!kind.is_revocable(), "{kind:?}");
    assert!(matches!(kind, SubjectKind::ForeignRegistered { .. }));
}

/// 実行中の他セッションから権限を奪わない（BUG-053）。**台帳エントリも残す**
/// ——ACEは実在するので、記録を消すとharnessが把握しない穴になる。
#[test]
fn a_live_harness_session_is_not_revocable_and_holds_the_ledger_entry() {
    let mut f = Fixture::new();
    f.ledger = vec![SID_LIVE.to_string()];
    let kind = f.classify(SID_LIVE, harness_rw_mask(), false);
    assert!(!kind.is_revocable(), "{kind:?}");
    assert!(matches!(kind, SubjectKind::LiveHarness { .. }));
}

/// マスクは**完全一致**で判定する。上位集合・部分集合を「harnessのもの」と読むと、
/// 無関係なアプリのACEまで拾う（B-25: 複合マスクのAND判定をしない）。
///
/// なお`fs_access_mask(ReadWrite) | FILE_GENERIC_EXECUTE`は**`ReadWriteExec`と同値**なので
/// 上位集合の例には使えない（このテストを書いたとき実際にそれで踏んだ）。
#[test]
fn an_unregistered_sid_whose_mask_is_not_exactly_one_of_ours_is_not_claimed() {
    use windows::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_GENERIC_WRITE, WRITE_DAC};
    let f = Fixture::new();
    let cases = [
        // 上位集合: harnessは`WRITE_DAC`を渡さない。
        ("superset", fs_access_mask(FsAccess::ReadWriteExec) | WRITE_DAC.0),
        // 部分集合: `DELETE`を含まない読み書き（harnessの`ReadWrite`は`DELETE`を含む）。
        ("subset", FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0),
    ];
    for (label, mask) in cases {
        assert!(!f.masks.contains(&mask), "test premise for {label}");
        assert_eq!(
            f.classify(SID_ORPHAN, mask, false),
            SubjectKind::Unidentified { classified: true },
            "{label} mask {mask:#x} must not be claimed"
        );
    }
}

/// 祖先traverseのマスクは指紋に入れない。`C:\`のような共有ノードのtraverse ACEを純減させると
/// マシン全体のTier2a FS I/Oが壊れる（[BUG-046](../../../../docs/bugs/BUG-046.md)）。
/// 巻き戻したいときは`harness fs revoke-traverse`という名前の付いた扉を通る。
#[test]
fn the_ancestor_traverse_mask_is_not_part_of_the_fingerprint() {
    use windows::Win32::Storage::FileSystem::{FILE_READ_ATTRIBUTES, FILE_TRAVERSE};
    let f = Fixture::new();
    let traverse = FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0;
    assert_eq!(
        f.classify(SID_ORPHAN, traverse, false),
        SubjectKind::Unidentified { classified: true }
    );
}

/// 拒否ACEを持つSIDは指紋で名乗らない（harnessのfs passthrough付与は許可ACEしか書かない）。
/// **記録がある場合は別**——下のテストが対で押さえる。
#[test]
fn an_unregistered_sid_with_a_deny_ace_is_not_claimed_by_the_fingerprint() {
    let f = Fixture::new();
    assert_eq!(
        f.classify(SID_ORPHAN, harness_rw_mask(), true),
        SubjectKind::Unidentified { classified: true }
    );
}

/// 拒否ACEがあっても、台帳が付与先として記録しているなら撤収対象である
/// （記録は指紋より強い＝上のテストの対）。
#[test]
fn a_recorded_sid_is_still_revocable_when_it_also_carries_a_deny_ace() {
    let mut f = Fixture::new();
    f.ledger = vec![SID_ORPHAN.to_string()];
    assert_eq!(
        f.classify(SID_ORPHAN, harness_rw_mask(), true),
        SubjectKind::LedgerRecorded
    );
}

/// **登録簿を読めなかったことを「登録が無い」と読み替えない**（B-10）。
/// 読み替えると、他アプリのSIDが一斉に孤児と判定されて破壊側へ倒れる。
#[test]
fn a_registry_read_failure_classifies_nothing_as_revocable() {
    let masks = harness_package_sid_masks();
    let ledger = vec![SID_ORPHAN.to_string()];
    let classifier = SubjectClassifier {
        registered: None,
        live_profiles: &[],
        ledger_sids: &ledger,
        harness_masks: &masks,
    };
    for sid in [SID_LEGACY, SID_DEAD, SID_LIVE, SID_FOREIGN, SID_ORPHAN] {
        let kind = classifier.classify(sid, harness_rw_mask(), false);
        assert_eq!(
            kind,
            SubjectKind::Unidentified { classified: false },
            "{sid} must not be claimed when the profile registry could not be read"
        );
        assert!(!kind.is_revocable());
    }
}

// --- 台帳エントリを落としてよいかの判定 ---

fn outcome(sid: &str, kind: SubjectKind, still_on_root: bool) -> SubjectOutcome {
    SubjectOutcome {
        sid: sid.to_string(),
        kind,
        still_on_root,
    }
}

fn report(subjects: Vec<SubjectOutcome>) -> HarnessRevokeReport {
    HarnessRevokeReport {
        subjects,
        walk: RevokeReport::default(),
        root_missing: false,
        classification_error: None,
        cleared_elsewhere: 0,
    }
}

/// **BUG-101の中核**: 剥がせなかったのに台帳エントリを消すと、それまで「台帳に載った
/// 剥がせるACE」だったものが「harnessがもう存在すら記録していない孤立ACE」になる
/// ——実行前より状態が悪化する。名前を捨てる操作は最後に置く（B-01）。
#[test]
fn the_ledger_entry_is_kept_when_a_target_ace_survived_on_the_root() {
    let r = report(vec![outcome(
        SID_DEAD,
        SubjectKind::DeadHarness {
            profile: DEAD_SESSION.to_string(),
        },
        true,
    )]);
    assert_eq!(r.targeted(), 1);
    assert_eq!(r.unfinished(), vec![SID_DEAD]);
    assert!(!r.may_remove_ledger_entry());
}

/// 対になる許可側——全部剥がせたなら台帳から落とす。
#[test]
fn the_ledger_entry_is_removed_once_every_target_is_gone() {
    let r = report(vec![
        outcome(
            SID_DEAD,
            SubjectKind::DeadHarness {
                profile: DEAD_SESSION.to_string(),
            },
            false,
        ),
        outcome(
            SID_FOREIGN,
            SubjectKind::ForeignRegistered {
                moniker: "microsoft.windowsnotepad_8wekyb3d8bbwe".to_string(),
            },
            false,
        ),
    ]);
    assert_eq!(r.targeted(), 1);
    assert!(r.unfinished().is_empty());
    // 他アプリのSIDが残っていることは、harnessの記録を残す理由にはならない。
    assert!(r.may_remove_ledger_entry());
    assert_eq!(r.left_alone().len(), 1);
}

/// 生きているセッションのACEが載っている間は、剥がさないし記録も消さない。
#[test]
fn the_ledger_entry_is_kept_while_a_live_session_still_holds_an_ace() {
    let r = report(vec![outcome(
        SID_LIVE,
        SubjectKind::LiveHarness {
            profile: LIVE_SESSION.to_string(),
        },
        false,
    )]);
    assert_eq!(r.targeted(), 0);
    assert!(!r.may_remove_ledger_entry());
}

/// 「対象が0件だった」と「対象は在ったが剥がせなかった」を混ぜない（B-09）。
/// 前者は台帳の掃除だけを行ってよく、後者は失敗として扱う。
#[test]
fn zero_targets_is_distinguishable_from_a_failed_revoke() {
    let nothing = report(Vec::new());
    assert_eq!(nothing.targeted(), 0);
    assert_eq!(nothing.rewritten(), 0);
    assert!(nothing.may_remove_ledger_entry());

    let failed = report(vec![outcome(
        SID_DEAD,
        SubjectKind::DeadHarness {
            profile: DEAD_SESSION.to_string(),
        },
        true,
    )]);
    assert_eq!(failed.targeted(), 1);
    assert_eq!(failed.rewritten(), 0);
    assert!(!failed.may_remove_ledger_entry());
}

/// 触らなかった主体は**SIDと理由**で出す。件数だけでは`icacls`で追えず、名前を失ったSIDは
/// それ以外に到達手段が無い（B-09）。
#[test]
fn subjects_left_alone_are_reported_with_their_sid_and_a_reason() {
    let r = report(vec![outcome(
        SID_ORPHAN,
        SubjectKind::Unidentified { classified: true },
        false,
    )]);
    let left = r.left_alone();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].0, SID_ORPHAN);
    assert!(!left[0].1.is_empty());
}

/// 登録簿は実マシンで読める（この機の実測: 218件。うちharness由来は`Moniker`が
/// `harness.shell.sandbox`で始まる）。**読めることそのもの**が分類の前提なので固定する
/// ——読めなくなれば全主体が「判別不能」へ落ち、`fs revoke`は何も剥がさなくなる。
#[test]
fn the_appcontainer_registry_is_readable_on_this_machine() {
    let map = registered_appcontainer_monikers().expect("HKCU AppContainer Mappings must be readable");
    assert!(
        !map.is_empty(),
        "the machine has AppContainer profiles registered; an empty map means the key moved"
    );
    for sid in map.keys() {
        assert!(
            sid.starts_with("S-1-15-2-"),
            "subkey names under Mappings are package SIDs, got {sid}"
        );
    }
}
