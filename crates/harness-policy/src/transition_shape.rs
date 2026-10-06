//! 1つのドメインから見た**遷移の形**——届く範囲の権限・起動で届くドメイン・最長の連鎖——と、
//! 自己ループ辺の一覧（2026-10-05、`plans/position-domains/P3.md` Task 3）。
//!
//! # 何のためにあるのか
//!
//! ポリシーエディタの宣言画面の遷移タブ（`plans/PLAN-POLICY-EDITOR-POSITION-DOMAINS.md` の P4.2）は、
//! ドメインごとに「そこへ遷移すると何ができるようになるか」「起動でどのドメインへ届くか」
//! 「連鎖が最長で何段になるか（閉路があれば上限なし）」「手で書いた自己ループ辺」を見せる。
//! 記録した木の位置ごとにドメインを分けると（決定65(1)）ドメインの数が増えるので、
//! 宣言を1本ずつ読んで頭の中で辿らせない。
//!
//! # ここで計算しないもの（判定を2つ持たない）
//!
//! - **権限の要約は[`super::rights_summary`]を呼ぶだけ**——モデル向けのツール（`transition_listing::rows`）と
//!   同じ値である。2つ作るとモデルとユーザーで見えるものがずれる（§19.3.8、`bug-pattern-rules` B-13）
//! - **到達閉包は[`super::GraphFacts`]の`reachable_from`を呼ぶだけ**——向きの判定が使っているものと同じ
//!
//! # 検査に落ちる宣言でも答える
//!
//! [`super::TransitionGraph::build`]を通さず、[`super::GraphFacts::new`]だけを通す（`rights_summary`・
//! `edge_direction`と同じ）。エディタは**直す前の宣言**を見せる必要があり、検査に落ちたら何も見えない、
//! では直しようがない。落ちるのは同じ名前のドメインが2つあるとき（`GraphError::DuplicateDomain`）だけ。
//!
//! # 最長の連鎖は全部の辺を数える
//!
//! Strict の辺（Strict の印が付いたドメインへ入る、argv・cwd を全部固定した辺。決定66の追記）は到達閉包から外れる
//! （§19.3.4 を「書き方の形」から付け替えた）——**権限が呼び出し元へ渡らない**からである。起こせないからではない。
//! 印の無いドメインへの辺は、固定してあっても閉包に入る。連鎖の段数が問うのは「何回続けて起こせるか」なので、Strict の辺も、
//! 宣言されていない遷移先への辺も1段に数える。閉路は禁じていない（§19.3.1 の限定詞。§19.3.2 の
//! collapse＝自己ループ辺は閉路そのもの）ので、起点から閉路へ届けば**上限なし**と答え、その閉路を返す。
//!
//! # 限界
//!
//! - 「起動で届くドメイン」は到達閉包そのもの（権限を数えた範囲と同じ集合）なので、**Strict の辺の先と、
//!   宣言されていない遷移先は入らない**。それらは最長の連鎖の経路には現れる
//! - 段数はドメインの段数である。同じドメインの中で何本のプロセスが走るか（資源）は範囲外（§19.3.6）

use std::collections::BTreeMap;

use super::{rights_summary, GraphError, GraphFacts, GraphInput};

/// 1つのドメインから見た遷移の形（[`shape`]の答え）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionShape {
    /// 届く範囲の権限。**[`super::rights_summary`]と同じ値**（モデル向けのツールと同じ）。
    /// Strict の辺の先は入らない（§19.3.4）。
    pub rights: crate::transition_listing::Rights,
    /// 起動で届くドメイン（自分を除く・名前の順）。**到達閉包そのもの**で、権限を数えた範囲と同じ集合。
    /// Strict の辺の先と、宣言されていない遷移先は入らない（モジュールdocの限界）。
    pub reachable: Vec<String>,
    pub longest_chain: LongestChain,
}

/// 起点から続けて起こせる遷移の段数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LongestChain {
    /// 起点から閉路へ届かない。`path[0]`が起点で`path.len() == steps + 1`。**Strict の辺も数える**。
    /// 同じ段数の経路が2つ以上あれば、宣言の順で先の辺を採る。
    Finite { steps: usize, path: Vec<String> },
    /// 起点から閉路へ届く（自己ループ辺を含む）。`cycle`はその閉路のドメインを順に並べたもの
    /// （`[A, B]`は A→B→A、自己ループは`[A]`）。
    Unbounded { cycle: Vec<String> },
}

/// 遷移先が遷移元と同じ辺（自己ループ辺。§19.3.2 の collapse）1本。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfLoop {
    pub domain: String,
    /// そのドメインの`transitions`配列の添字。**辺の内容ではなく位置で指す**（`Rejection::edge_index`と同じ）。
    pub edge_index: usize,
}

/// `from`から見た遷移の形。**検査に落ちる宣言でも答える**（モジュールdoc）。
///
/// 宣言されていない`from`には、空の権限・空の到達先・0段の連鎖を返す（`rights_summary`と同じく
/// `Err`にしない）。
pub fn shape(input: &GraphInput<'_>, from: &str) -> Result<TransitionShape, GraphError> {
    let facts = GraphFacts::new(input)?;
    let rights = rights_summary(input, from)?;
    let reachable = facts
        .reachable_from(from)
        .into_iter()
        .filter(|name| *name != from)
        .map(str::to_string)
        .collect();
    Ok(TransitionShape {
        rights,
        reachable,
        longest_chain: longest_chain(&facts, from),
    })
}

/// 自己ループ辺の一覧（宣言の順）。エディタは自己ループ辺を書かない（決定65(3)。凍結中）ので、
/// ここに出るのは手で書いたものか、凍結の前にエディタが書いたものである。失敗しない。
pub fn self_loops(input: &GraphInput<'_>) -> Vec<SelfLoop> {
    let mut out = Vec::new();
    for view in &input.domains {
        for (edge_index, edge) in view.process.transitions.iter().enumerate() {
            if edge.to == view.name {
                out.push(SelfLoop {
                    domain: view.name.to_string(),
                    edge_index,
                });
            }
        }
    }
    out
}

/// 起点から辺を辿る深さ優先の帰りがけで、各ドメインから先の最長の段数を決める。
/// 経路の途中にいるドメインへ戻る辺を見つけたら、その時点で閉路として答える。
fn longest_chain(facts: &GraphFacts<'_>, from: &str) -> LongestChain {
    enum Mark {
        /// いま辿っている経路の上にいる（ここへ戻る辺は閉路）。
        OnPath,
        /// 辿り終えた。ここから先の最長の段数と、その次のドメイン。
        Done { steps: usize, next: Option<String> },
    }
    struct Frame {
        name: String,
        successors: Vec<String>,
        cursor: usize,
    }
    // 遷移先を宣言の順で、重複を除いて。**Strict の辺も数える**（モジュールdoc）。
    // 宣言されていないドメインは辺を持たない。
    let successors = |name: &str| -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if let Some(view) = facts.by_name.get(name) {
            for edge in &view.process.transitions {
                if !out.contains(&edge.to) {
                    out.push(edge.to.clone());
                }
            }
        }
        out
    };

    let mut marks: BTreeMap<String, Mark> = BTreeMap::new();
    marks.insert(from.to_string(), Mark::OnPath);
    let mut stack = vec![Frame {
        name: from.to_string(),
        successors: successors(from),
        cursor: 0,
    }];
    while let Some(frame) = stack.last_mut() {
        let next = frame.successors.get(frame.cursor).cloned();
        frame.cursor += 1;
        let Some(next) = next else {
            // 辿り終えた。最も長く続く遷移先を採る（同じ長さなら宣言の順で先のもの）。
            let frame = stack.pop().expect("the loop saw a frame on the stack");
            let mut best: Option<(usize, String)> = None;
            for successor in frame.successors {
                if let Some(Mark::Done { steps, .. }) = marks.get(&successor) {
                    let candidate = steps + 1;
                    if best
                        .as_ref()
                        .is_none_or(|(longest, _)| candidate > *longest)
                    {
                        best = Some((candidate, successor));
                    }
                }
            }
            let mark = match best {
                Some((steps, next)) => Mark::Done {
                    steps,
                    next: Some(next),
                },
                None => Mark::Done {
                    steps: 0,
                    next: None,
                },
            };
            marks.insert(frame.name, mark);
            continue;
        };
        match marks.get(&next) {
            Some(Mark::OnPath) => {
                let start = stack
                    .iter()
                    .position(|frame| frame.name == next)
                    .expect("a domain marked on-path is on the stack");
                return LongestChain::Unbounded {
                    cycle: stack[start..]
                        .iter()
                        .map(|frame| frame.name.clone())
                        .collect(),
                };
            }
            Some(Mark::Done { .. }) => {}
            None => {
                marks.insert(next.clone(), Mark::OnPath);
                let next_successors = successors(&next);
                stack.push(Frame {
                    name: next,
                    successors: next_successors,
                    cursor: 0,
                });
            }
        }
    }

    let steps = match marks.get(from) {
        Some(Mark::Done { steps, .. }) => *steps,
        _ => 0,
    };
    let mut path = vec![from.to_string()];
    let mut cursor = from.to_string();
    while let Some(Mark::Done {
        next: Some(next), ..
    }) = marks.get(&cursor)
    {
        path.push(next.clone());
        cursor = next.clone();
    }
    LongestChain::Finite { steps, path }
}

#[cfg(test)]
#[path = "transition_shape_tests.rs"]
mod transition_shape_tests;
