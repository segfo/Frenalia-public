//! 親子の鍵で組んだ森を、**閉路があっても止まって1件も落とさずに**、親→子の順へ並べる。
//!
//! # 何のためにあるのか
//!
//! 記録したプロセスを木として見せる・木の位置ごとに何かを決める、という処理が2つある——
//! ポリシーエディタの古い記録の表示（pid の親子で組む。`harness-policy-editor`の
//! `Aggregate::process_tree`）と、位置ごとのドメインの割り当て（通し番号の親子で組む。
//! `plans/position-domains/P3.md` Task 4）。**辿り方を2つ書くと片方だけ直る**
//! （`bug-pattern-rules` B-13）ので、鍵の型に依らない1つの関数にした（2026-10-05、P3a。
//! 元はエディタの`Aggregate::process_tree`の本体）。
//!
//! # どちらの鍵で組むかは呼び出し側が選ぶ
//!
//! この関数は鍵の意味を知らない。**pid で組んだ木は、pid の使い回しの下で誤った親子を描く**
//! （`plans/POLICY-EDITOR-TOMOYO-DIG.md`の「決定65の追記」(3)。後から引く pid の表は 600組中32組で
//! 別の親を指した）。位置の割り当ては通し番号で組み、pid の木は位置の情報が無い古い記録の表示にだけ使う。
//!
//! # 親が分からないものを別の親へ繋がない
//!
//! 親の鍵が無い・親が入力に無い・親が自分自身の節は、**根として扱う**。嘘の親子関係を描くくらいなら、
//! 根が複数ある方が正直である。なぜ根なのかは[`RootKind`]で返す——呼び出し側が「親が記録に無い」を
//! もう一度自分で判定しなくて済むように（判定を2つ持たない）。
//!
//! # 閉路でも1件も落とさない
//!
//! 親子が閉路になると、閉路の中の節はどの根からも辿れなくなる。走査の最後に入力の順で拾い直し、
//! [`RootKind::InCycle`]の根として出す（表示から黙って消えるより、親が変に見える方がまだ調べようがある、
//! `B-09`）。

use std::collections::{BTreeMap, BTreeSet};

/// 木の1行。[`walk`]は親→子の順（深さ優先の行きがけ）で並べる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeEntry<K> {
    /// 根からの段数（根は0）。
    pub depth: usize,
    pub key: K,
    /// 根なら、なぜ根なのか（`depth == 0`のときだけ`Some`）。
    pub root: Option<RootKind>,
}

/// 節が根になった理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootKind {
    /// 親の鍵が無い。
    NoParent,
    /// 親の鍵はあるが、その鍵の節が入力に無い（記録の外の親）。
    ParentAbsent,
    /// 親の鍵が自分自身。
    OwnParent,
    /// 閉路の中にいて、どの根からも辿れなかった（走査の最後に拾い直した）。
    InCycle,
}

/// `nodes`の各要素は（自分の鍵, 親の鍵）。根は入力の順、兄弟も入力の順で並ぶ。
///
/// 同じ鍵が2回あれば2回目は出さない。**1件も落とさない・閉路でも止まる**（モジュールdoc）。
pub fn walk<K: Ord + Copy>(nodes: &[(K, Option<K>)]) -> Vec<TreeEntry<K>> {
    let present: BTreeSet<K> = nodes.iter().map(|(key, _)| *key).collect();
    let mut children: BTreeMap<K, Vec<K>> = BTreeMap::new();
    let mut roots: Vec<(K, RootKind)> = Vec::new();
    for (key, parent) in nodes {
        match parent {
            None => roots.push((*key, RootKind::NoParent)),
            Some(parent) if parent == key => roots.push((*key, RootKind::OwnParent)),
            Some(parent) if !present.contains(parent) => roots.push((*key, RootKind::ParentAbsent)),
            Some(parent) => children.entry(*parent).or_default().push(*key),
        }
    }

    let mut out = Vec::new();
    let mut visited = BTreeSet::new();
    for (root, kind) in roots {
        walk_from(root, kind, &children, &mut visited, &mut out);
    }
    // 閉路の中に居て根から辿れなかった節を拾い直す（1件も落とさない）。
    for (key, _) in nodes {
        if !visited.contains(key) {
            walk_from(*key, RootKind::InCycle, &children, &mut visited, &mut out);
        }
    }
    out
}

/// `start`を根として、その下を深さ優先の行きがけで`out`へ足す。
fn walk_from<K: Ord + Copy>(
    start: K,
    kind: RootKind,
    children: &BTreeMap<K, Vec<K>>,
    visited: &mut BTreeSet<K>,
    out: &mut Vec<TreeEntry<K>>,
) {
    let mut stack = vec![(0usize, start)];
    while let Some((depth, key)) = stack.pop() {
        // 閉路を踏んでも止まる（同じ節を2度出さない）。
        if !visited.insert(key) {
            continue;
        }
        out.push(TreeEntry {
            depth,
            key,
            root: (depth == 0).then_some(kind),
        });
        if let Some(kids) = children.get(&key) {
            // 逆順に積むので、取り出す順＝入力の順になる。
            for kid in kids.iter().rev() {
                stack.push((depth + 1, *kid));
            }
        }
    }
}

#[cfg(test)]
#[path = "process_tree_tests.rs"]
mod process_tree_tests;
