//! 遷移で**呼び出し元が子を通して新しく使えるようになる権限**と、ポリシーの書き方で生じる
//! **組み合わせの対**（Limit 1）を計算する（2026-10-06、`plans/position-domains/P5.md` の P5.2）。
//!
//! # 何のためにあるのか
//!
//! 決定66（`plans/POLICY-EDITOR-TOMOYO-DIG.md`）で、権限が広がる子への遷移を**入力を固定せずに**書けるようにした
//! （普通のモード）。守る線は子のドメインの権限（OSが強制する）だが、その代わり**呼び出し元は子を通して、
//! 子のドメインの権限を全部使える**。だから承認のときに、その辺で何が呼び出し元の手に渡るのかと、
//! 宣言の組み合わせで生まれる持ち出しの経路（あるドメインが書いた場所を、外部と通信できる別のドメインが
//! 読む／実行する）を人へ見せる。**断らずに人が判断する**（決定66(9)）。本モジュールはその材料を計算するだけで、
//! 見せるのはポリシーエディタ（P5.3・P5.6）である。
//!
//! # 新しく使える権限の数え方（決定66の「表示用の向きの定義」）
//!
//! **遷移先の届く範囲（到達閉包。§19.3.4）の権限 − 遷移元が自分で宣言している権限**。空でなければ「広げる」。
//!
//! - 遷移先の側を閉包にするのは、子がさらに先へ遷移して届く権限も、呼び出し元が子を通して使えるからである
//! - 遷移元の側を**自分の宣言だけ**にするのは、決定65(5)（親は自分が触った分だけを持つ）に沿うためである。
//!   閉包から当の辺だけを除いて数える方式（[`super::Direction`]の今の数え方）を採らないのは、同じ遷移先への辺が
//!   2本あると**互いを正当化して**「どちらも広げない」と出てしまうためである
//! - 自己ループ辺は何も渡さない（子は呼び出し元と同じドメインで、子が辿れる辺は呼び出し元も自分で辿れる。
//!   [`super::Direction::Same`]と同じ扱い）
//! - **Strict の印が付いたドメインへ入る辺は何も渡さない**（決定66の追記。入力が固定されていて、呼び出し元は子に
//!   決めた操作しかさせられない）。遷移先の先にある Strict の辺も、閉包が辿らないので数えない（§19.3.4 の付け替え）。
//!   **向き（[`super::Direction`]）はこの除外を通さない**——子のドメインが広いことは変わらず、規則(g)（実行ファイルの
//!   パターンは広げる辺で断る。決定66(7)）は Strict の辺にも掛かるためである。除外の持ち主は
//!   [`GraphFacts::usable_through`]の1か所
//!
//! # ここで計算しないもの（判定を2つ持たない。`B-13`）
//!
//! - **到達閉包と権限の和**は[`super::GraphFacts`]の`reachable_from`・`rights_of`を呼ぶだけ——向きの判定・
//!   [`super::rights_summary`]と同じもの。閉包が辿る辺の条件（Strict の辺を辿らない。P5.3 で「書き方の形」から
//!   付け替えた）が変われば、ここも同時に従う
//! - **覆うか**は判定器の包含[`super::fs_covers`]、**場所が重なるか**は覆うかの唯一の規則
//!   [`crate::insufficient::covers`]と、宣言値が開く範囲（[`crate::normalize::literal_prefix`]・
//!   [`crate::normalize::declared_scope`]。付与層と同じ境目）を組むだけ
//! - **外部と通信できるか**は呼び出し側が渡す関数で決める（今は[`provisional_net_capable`]を渡す。
//!   決定66(9)の寿命どおり、通信をドメインごとに分ける P7 で差し替える）
//!
//! # 限界（同じ場所に書く）
//!
//! - **宣言されていない遷移先には空を返す**（[`super::rights_summary`]と同じ）。向きの判定に使うときは、
//!   未宣言を「証明できない」へ倒す判定（[`super::GraphFacts::direction`]の先頭）を先に通すこと
//! - **組み合わせの書く側は、ドメインの宣言（`read_write`）と、宣言の外で書ける場所**
//!   （[`super::GraphInput::caller_writable_roots`]＝ワークスペース・`policy.json`の外で書込を許した場所。P5.4a）。
//!   後者は**入口のドメインが書く**として数える（`--fs-allow`の穴を持つのは入口だけ）。遷移先のドメインも土台として
//!   ワークスペースを書ける（`domain_provision`の共通の土台）が、それは数えていない——読む側も宣言だけを見るので、
//!   宣言せずに土台で読むワークスペースの組は出ない（少なめに出る側）
//! - 組み合わせは**ドメインの宣言どうし**で見る。そのドメインへ実際に遷移で届くかは問わない（届かない組も出る
//!   ＝多めに出す側）
//! - 外部と通信できるかの判定は暫定（上）。P7 までは強制で効くのは入口のドメインの通信宣言だけである（決定66の限界）

use std::collections::BTreeSet;

use harness_change_ledger::path_rules::fold_for_pattern_comparison;
use harness_config::FsAccess;

use super::{fs_covers, DomainView, GraphError, GraphFacts, GraphInput, Rights};
use crate::policy_file::ENTRY_DOMAIN;

/// 辺1本で、呼び出し元が子を通して新しく使えるようになる権限（[`exposure_delta`]の答えの1行）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeExposure {
    pub from: String,
    /// `from`の`transitions`配列の添字（**変更後**の宣言での位置）。辺の内容ではなく位置で指す
    /// （`Rejection::edge_index`と同じ）。
    pub edge_index: usize,
    pub to: String,
    /// 変更で**増えた**分。新しい辺なら[`newly_usable`]の全部、前からあった辺なら前に渡していた分との差。
    pub newly_usable: crate::transition_listing::Rights,
}

/// 組み合わせの対で、読む側がその場所をどう使えるか。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PairUse {
    /// 読める（`read`・`read_write`）。書かれたデータが外へ出る。
    Read,
    /// 実行できる（`read_exec`）。書かれたものが、通信できるドメインで**走る**。
    Execute,
}

/// 組み合わせの対1つ（Limit 1）: `writer`が書ける場所を、外部と通信できる別のドメイン`reader`が読む／実行する。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CombinationPair {
    pub writer: String,
    /// 書く側の宣言値（`read_write`）。書かれた綴りのまま。
    pub writer_place: String,
    pub reader: String,
    /// 読む側の宣言値。書かれた綴りのまま。`writer_place`と範囲が重なる。
    pub reader_place: String,
    pub use_: PairUse,
}

/// [P5.6] Strict のドメインへ入る辺1本（入力を固定するので、呼び出し元は子を操れない。決定66の追記）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictEdge {
    pub from: String,
    /// `from`の`transitions`配列の添字（**変更後**の宣言での位置。[`EdgeExposure::edge_index`]と同じ）。
    pub edge_index: usize,
    pub to: String,
}

/// 変更（`before` → `after`）で増えたもの（[`exposure_delta`]の答え）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExposureDelta {
    /// 渡す権限が増えた辺（変更後の宣言の順）。増えていない辺は入らない。
    pub edges: Vec<EdgeExposure>,
    /// 変更で生まれた組み合わせの対（欄の順）。前からあった対は入らない。
    pub pairs: Vec<CombinationPair>,
    /// [P5.6] 変更で**新しく** Strict のドメインへ入るようになった辺（変更後の宣言の順）。何も渡さないので[`Self::edges`]
    /// には入らないが、明細は辺のモード（普通か Strict か）を示すためにこれを出す。前から Strict だった辺は入らない。
    pub strict_edges: Vec<StrictEdge>,
}

/// `from`から`to`へ遷移すると、呼び出し元が子を通して新しく使えるようになる権限
/// （＝`to`の届く範囲の権限 − `from`が自分で宣言している権限。モジュールdoc）。
///
/// **検査に落ちる宣言でも答える**（[`super::rights_summary`]と同じく`GraphFacts::new`だけを通す）。
/// 落ちるのは同じ名前のドメインが2つあるとき（[`GraphError::DuplicateDomain`]）だけ。
pub fn newly_usable(
    input: &GraphInput<'_>,
    from: &str,
    to: &str,
) -> Result<crate::transition_listing::Rights, GraphError> {
    let facts = GraphFacts::new(input)?;
    Ok(facts.usable_through(from, to).listed())
}

/// 変更（`before` → `after`）で、辺ごとに増えた「呼び出し元が子を通して使える権限」と、新しく生まれた
/// 組み合わせの対。
///
/// - **辺**: 変更後の各辺について、前から**同じ内容の辺**が同じ遷移元にあったなら、前に渡していた分を引いた差
///   （辺はそのままでも、遷移先のファイルの宣言が増えれば渡る権限は増える）。無かったなら全部。
///   同じ遷移先への辺が前からあっても、内容の違う新しい辺は全部を出す——並行する辺は互いを正当化しない
/// - **対**: 変更後の対のうち、変更前に無かったもの。外部と通信できるかは`net_capable`だけで決める
///   （今は[`provisional_net_capable`]を渡す）
pub fn exposure_delta<F>(
    before: &GraphInput<'_>,
    after: &GraphInput<'_>,
    net_capable: F,
) -> Result<ExposureDelta, GraphError>
where
    F: Fn(&DomainView<'_>) -> bool,
{
    let before_facts = GraphFacts::new(before)?;
    let after_facts = GraphFacts::new(after)?;

    let mut edges = Vec::new();
    let mut strict_edges = Vec::new();
    for view in &after.domains {
        let before_view = before_facts.by_name.get(view.name);
        for (edge_index, edge) in view.process.transitions.iter().enumerate() {
            // Strict の辺の鍵は`enters_strict`の1か所（`usable_through`が数えないのと同じ判定。`B-13`）。
            let was_strict = before_view
                .is_some_and(|b| b.process.transitions.contains(edge))
                && before_facts.enters_strict(view.name, &edge.to);
            if after_facts.enters_strict(view.name, &edge.to) && !was_strict {
                strict_edges.push(StrictEdge {
                    from: view.name.to_string(),
                    edge_index,
                    to: edge.to.clone(),
                });
            }
            let now = after_facts.usable_through(view.name, &edge.to);
            let added = match before_view {
                Some(before_view) if before_view.process.transitions.contains(edge) => {
                    subtract(now, &before_facts.usable_through(view.name, &edge.to))
                }
                _ => now,
            };
            if !added.is_empty() {
                edges.push(EdgeExposure {
                    from: view.name.to_string(),
                    edge_index,
                    to: edge.to.clone(),
                    newly_usable: added.listed(),
                });
            }
        }
    }

    let existed = combination_pairs(before, &net_capable);
    let pairs = combination_pairs(after, &net_capable)
        .into_iter()
        .filter(|pair| !existed.contains(pair))
        .collect();
    Ok(ExposureDelta {
        edges,
        pairs,
        strict_edges,
    })
}

/// 外部と通信できるかの**暫定**の判定（決定66(9)）: 入口のドメイン（[`ENTRY_DOMAIN`]）は常に通信できる、
/// 他は通信先（`net`）を1つでも宣言していれば通信できる、とみなす。
///
/// **暫定である理由**: いまはドメインごとの通信の分離が無く（P7）、強制で効くのは入口のドメインの通信宣言だけ
/// である（決定64・決定66の限界）。P7 で通信をドメインごとに分けたら、実際の可否を返す関数に差し替える。
/// **呼び出し側は自分で閉包を書かずにこれを渡す**——暫定の規則の持ち主を1か所にして、差し替えを1か所で済ませる
/// （`B-05`）。
pub fn provisional_net_capable(domain: &DomainView<'_>) -> bool {
    domain.name == ENTRY_DOMAIN || !domain.net.is_empty()
}

impl<'a> GraphFacts<'a> {
    /// 遷移先の届く範囲の権限 − 遷移元が自分で宣言している権限（モジュールdoc）。**向きの判定**
    /// （[`GraphFacts::direction`]）と[`GraphFacts::usable_through`]がこれを呼ぶ——数え方を2つ持たない（`B-13`）。
    /// 当の辺が Strict のドメインへ入るかは見ない（見るのは[`GraphFacts::usable_through`]）。
    pub(super) fn newly_usable_rights(&self, from: &str, to: &str) -> Rights<'a> {
        if from == to {
            return Rights::default();
        }
        let reachable = self.rights_of(self.reachable_from(to));
        let own = self.rights_of(
            self.by_name
                .get_key_value(from)
                .map(|(name, _)| *name)
                .into_iter()
                .collect(),
        );
        subtract(reachable, &own)
    }

    /// [`newly_usable`]・[`exposure_delta`]の本体: `from`から`to`へ入る辺で、**呼び出し元が子を通して**新しく使える
    /// 権限。Strict の印が付いたドメインへ入る辺は空（決定66の追記。印の判定は[`GraphFacts::enters_strict`]の1か所）。
    fn usable_through(&self, from: &str, to: &str) -> Rights<'a> {
        if self.enters_strict(from, to) {
            return Rights::default();
        }
        self.newly_usable_rights(from, to)
    }
}

impl Rights<'_> {
    /// 何も無いか（向きの判定〔[`super::GraphFacts::direction`]〕もこれで「狭める」を決める）。
    pub(super) fn is_empty(&self) -> bool {
        self.fs.is_empty() && self.net.is_empty()
    }
}

/// `minuend`のうち、`subtrahend`に**覆われない**ものだけを残す。
///
/// 覆うかは判定器と同じ[`fs_covers`]・通信先の一致（`rights_of`が小文字へ畳んだ綴り）で見る。
/// 「狭める」（[`super::Direction::Narrower`]）は「この差が空か」である（包含を別に書かない）。
fn subtract<'a>(minuend: Rights<'a>, subtrahend: &Rights<'_>) -> Rights<'a> {
    Rights {
        fs: minuend
            .fs
            .into_iter()
            .filter(|needed| {
                !subtrahend
                    .fs
                    .iter()
                    .any(|granted| fs_covers(granted, needed))
            })
            .collect(),
        net: minuend
            .net
            .into_iter()
            .filter(|domain| !subtrahend.net.contains(domain))
            .collect(),
    }
}

/// 組み合わせの対を全部。書く側は各ドメインの`read_write`宣言と、宣言の外で書ける場所
/// （[`GraphInput::caller_writable_roots`]。**入口のドメイン**が書く。P5.4a）。読む側はドメインの宣言だけを見る
/// （モジュールdocの限界）。
fn combination_pairs<F>(input: &GraphInput<'_>, net_capable: &F) -> BTreeSet<CombinationPair>
where
    F: Fn(&DomainView<'_>) -> bool,
{
    // (書く側のドメイン, 見せる綴り, 重なりを見る綴り)。宣言はそのまま、根は配下全部を書ける場所として
    // `**`を付けて見る（規則(i)の`caller_writable_roots`が根を配下ごとに数えるのと揃える）。
    let mut writes: Vec<(&str, &str, String)> = Vec::new();
    for writer in &input.domains {
        for (place, access) in &writer.fs {
            if *access == FsAccess::ReadWrite {
                writes.push((writer.name, place, place.to_string()));
            }
        }
    }
    for root in &input.caller_writable_roots {
        let span = format!("{}/**", root.trim_end_matches(['/', '\\']));
        writes.push((ENTRY_DOMAIN, root, span));
    }

    let mut pairs = BTreeSet::new();
    for (writer, writer_place, span) in &writes {
        for reader in &input.domains {
            if reader.name == *writer || !net_capable(reader) {
                continue;
            }
            for (reader_place, access) in &reader.fs {
                if !places_overlap(span, reader_place) {
                    continue;
                }
                pairs.insert(CombinationPair {
                    writer: writer.to_string(),
                    writer_place: writer_place.to_string(),
                    reader: reader.name.to_string(),
                    reader_place: reader_place.to_string(),
                    use_: match access {
                        FsAccess::ReadExec => PairUse::Execute,
                        FsAccess::Read | FsAccess::ReadWrite => PairUse::Read,
                    },
                });
            }
        }
    }
    pairs
}

/// 2つの宣言値が開く範囲が重なるか。
///
/// 宣言値が開く範囲は[`crate::normalize::literal_prefix`]（ACEが付く場所）と
/// [`crate::normalize::declared_scope`]（その場所だけか、配下もか）で決まる（付与層と同じ境目。D-63）。
/// 片方の場所が、もう片方の範囲の中にあれば重なる。覆うかの規則は[`crate::insufficient::covers`]だけを使う。
///
/// 付与層が受け付けない形（`**`以外のワイルドカード。[`crate::normalize::has_unsupported_wildcard`]）は
/// ACEが1本も付かず何も開かないので、重ならない。
fn places_overlap(a: &str, b: &str) -> bool {
    use crate::normalize::{declared_scope, has_unsupported_wildcard, literal_prefix};
    if has_unsupported_wildcard(a) || has_unsupported_wildcard(b) {
        return false;
    }
    let root = |value: &str| {
        fold_for_pattern_comparison(literal_prefix(value))
            .trim_end_matches('/')
            .to_string()
    };
    let (a_root, b_root) = (root(a), root(b));
    a_root == b_root
        || (declared_scope(a).is_recursive() && crate::insufficient::covers(&a_root, &b_root))
        || (declared_scope(b).is_recursive() && crate::insufficient::covers(&b_root, &a_root))
}

#[cfg(test)]
#[path = "transition_exposure_tests.rs"]
mod transition_exposure_tests;
