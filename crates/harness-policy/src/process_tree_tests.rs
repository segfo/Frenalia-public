//! 木の辿り方（[`walk`]）の単体試験。**鍵は`u64`**（通し番号の木）で測る——pid の木は
//! エディタの`aggregate_tests`が`u32`で測っている（同じ関数を2つの鍵で通す）。

use super::*;

fn keys(entries: &[TreeEntry<u64>]) -> Vec<u64> {
    entries.iter().map(|entry| entry.key).collect()
}

fn depths(entries: &[TreeEntry<u64>]) -> Vec<usize> {
    entries.iter().map(|entry| entry.depth).collect()
}

/// 子は親の直後に深さ優先で並び、兄弟は**入力の順**（30 が 20 より前）。
#[test]
fn children_follow_their_parents_in_input_order() {
    let entries = walk(&[(10, None), (30, Some(10)), (20, Some(10)), (40, Some(30))]);
    assert_eq!(keys(&entries), vec![10, 30, 40, 20]);
    assert_eq!(depths(&entries), vec![0, 1, 2, 1]);
}

/// 根はなぜ根なのかを言う。子の行は`root == None`。
///
/// **親が分からないものを別の親へ繋がない**——3つとも根として出る。
#[test]
fn roots_say_why_they_are_roots() {
    let entries = walk(&[(1, None), (2, Some(99)), (3, Some(3)), (4, Some(1))]);
    let by_key = |key: u64| {
        *entries
            .iter()
            .find(|entry| entry.key == key)
            .expect("1件も落とさない")
    };
    assert_eq!(by_key(1).root, Some(RootKind::NoParent));
    assert_eq!(by_key(2).root, Some(RootKind::ParentAbsent));
    assert_eq!(by_key(3).root, Some(RootKind::OwnParent));
    assert_eq!(by_key(4).root, None);
    assert_eq!(by_key(4).depth, 1);
}

/// 親子が閉路になっても止まり、**1件も落とさない**。根が1つも無いので素朴な走査では
/// 全件が消える（`B-09`の黙った取りこぼし）。拾い直した最初の節は`InCycle`の根になる。
#[test]
fn a_cycle_is_walked_without_hanging_or_dropping() {
    let entries = walk(&[(1, Some(2)), (2, Some(1)), (3, Some(2))]);
    assert_eq!(keys(&entries), vec![1, 2, 3]);
    assert_eq!(depths(&entries), vec![0, 1, 2]);
    assert_eq!(entries[0].root, Some(RootKind::InCycle));
    assert_eq!(entries[1].root, None);
}

/// 同じ鍵が2回あっても1回だけ出る（訪問済みで止まる）。
#[test]
fn a_repeated_key_is_listed_once() {
    let entries = walk(&[(1, None), (1, None), (2, Some(1))]);
    assert_eq!(keys(&entries), vec![1, 2]);
}
