//! 確定の明細に**広がる遷移**を出す（`plans/POLICY-EDITOR-TOMOYO-DIG.md` 決定66。手順は
//! `plans/position-domains/P5.md`の P5.3）。
//!
//! # 何のためにあるのか
//!
//! 決定66で、権限が広がる子への遷移（広げる遷移）を**入力を固定せずに**書けるようにした（普通のモード）。守る線は
//! 子のドメインの権限（OSが強制する）だが、その代わり**呼び出し元は子を通して、子のドメインの権限を使える**。
//! だから`policy.json`を書く前に、その変更で「どの遷移が・呼び出し元へ新しく何を渡すようになるか」を確認の画面に出し、
//! **断らずに人が判断する**。数えるのは`harness_policy::transition::exposure_delta`（到達閉包・Strict の辺の除外・
//! 前から渡していた分との差）で、ここは結果を並べるだけ（判定を2つ持たない、`B-13`）。
//!
//! # どの経路に出すか（`policy.json`を書く経路6つのうち4つ）
//!
//! `policy.json`を保存する関数は6つある。**広がり得る4つ**——位置ごとのドメインの確定（`position_approve`）・
//! ファイル宣言の承認（`approve`）・付け替え（`reassign`）・取り消し（`unapprove`）——は、`plan`が
//! [`Widening`]を作り、その確認を出す画面と CLI がすべて[`lines`]を並べる（TUI の承認待ち・宣言画面と、CLI の
//! `approve`・`unapprove`）。宣言の承認・付け替えは遷移先の権限を増やし、取り消しは遷移元の宣言を減らすので、
//! 辺に触らなくても辺が渡す権限は増え得る。**対象外の2つ**:
//!
//! - `transition_approve::commit_removals`（宣言画面の遷移タブの取り消し）——辺を消すだけで、到達閉包は縮む
//!   だけなので広がらない
//! - `transition_approve::commit`（辺を足すが、画面と CLI からは呼ばれない。試験の入口として残る。
//!   承認待ちの遷移タブの確定は`position_approve`を通る）
//!
//! # 限界
//!
//! - **組み合わせの対**（Limit 1。あるドメインが書ける場所を、外部と通信できる別のドメインが読む／実行する）は
//!   まだ出さない（P5.6）
//! - **子の出力の行は出さない**——この段では、固定していない広げる辺の子へ Daemon は呼び出し元の標準入出力を
//!   渡さない（`harness_policy::transition::Allowed::inherit_handles`の式を据え置いた）。出力を返す既定が入る
//!   P5.4b で「子が読めるものは出力で呼び出し元へ渡る」を足す（入る前に言うと嘘になる、`B-32`）
//! - 1つの確認に2つの`plan`が並ぶ画面（承認待ちの「承認＋チェックを外した取り消し」、宣言画面の
//!   「付け替え＋取り消し」）は、`plan`ごとに「いまの`policy.json`からの差」を出す。**2つを重ねて初めて広がる辺**
//!   （片方が足した値を、もう片方が遷移元から外す）は数えない
//! - `policy.json`の外で書込を許した場所（`--fs-allow`）はエディタが知らないので数えない（`check_added`と同じ）

use std::path::Path;

use harness_policy::policy_file::PolicyFile;
use harness_policy::transition::{self, ExeMatcher};
use harness_policy::transition_listing::Rights;

/// 変更で広がる遷移（[`widening`]の答え）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Widening {
    /// 渡す権限が増えた辺（変更後の宣言の順）。
    pub edges: Vec<WidenedEdge>,
    /// 数えられなかった理由（同じ名前のドメインが2つある等）。**黙って「広がらない」と言わない**（`B-10`）。
    pub uncounted: Option<String>,
}

impl Widening {
    /// 確認に出すものが無い（広がる辺が無く、数えられなかったことも無い）。
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty() && self.uncounted.is_none()
    }
}

/// 広がる辺1本。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WidenedEdge {
    pub from: String,
    /// 辺の実行ファイル（書かれた綴り。パターンならパターンそのもの）。
    pub exe: String,
    pub to: String,
    /// この変更で増えた、呼び出し元が子を通して使えるようになる権限。
    pub newly_usable: Rights,
}

/// `before` → `after`の変更で広がる遷移。`after`は書く予定の内容、`before`は読み込んだ`policy.json`。
pub fn widening(before: &PolicyFile, after: &PolicyFile, workspace_root: &Path) -> Widening {
    let workspace = workspace_root.to_string_lossy();
    let delta = transition::exposure_delta(
        &before.transition_graph_input(Some(workspace.as_ref()), &[]),
        &after.transition_graph_input(Some(workspace.as_ref()), &[]),
        transition::provisional_net_capable,
    );
    match delta {
        Ok(delta) => Widening {
            edges: delta
                .edges
                .into_iter()
                .map(|edge| WidenedEdge {
                    exe: after
                        .domain(&edge.from)
                        .and_then(|d| d.process.transitions.get(edge.edge_index))
                        .map(|e| match &e.exe {
                            ExeMatcher::Literal(exe) | ExeMatcher::Pattern(exe) => exe.clone(),
                        })
                        .unwrap_or_default(),
                    from: edge.from,
                    to: edge.to,
                    newly_usable: edge.newly_usable,
                })
                .collect(),
            uncounted: None,
        },
        Err(e) => Widening {
            edges: Vec::new(),
            uncounted: Some(e.to_string()),
        },
    }
}

/// 確認の画面・CLI に並べる行（出すものが無ければ空）。先頭に空行を1つ置く（前の節と分ける）。
pub fn lines(widening: &Widening) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(reason) = &widening.uncounted {
        lines.push(String::new());
        lines.push(format!(
            "広がる遷移を数えられません（{reason}）——書くと呼び出し元が子を通して何を使えるようになるかは、\
             この画面では確かめていません"
        ));
    }
    if widening.edges.is_empty() {
        return lines;
    }
    lines.push(String::new());
    lines.push(format!(
        "広がる遷移 {}本——書くと、呼び出し元は子を通して次の権限を使えるようになります\
         （守るのは子のドメインの権限。決定66）:",
        widening.edges.len()
    ));
    for edge in &widening.edges {
        lines.push(format!("  {} → {}（{}）", edge.from, edge.to, edge.exe));
        lines.extend(rights_lines(&edge.newly_usable, "      "));
    }
    lines
}

/// 権限を1件1行で（`fs.<種別> <値>`・`net.allow_domains <宛先>`）。位置の木の説明欄も同じ綴りで出す。
pub fn rights_lines(rights: &Rights, indent: &str) -> Vec<String> {
    rights
        .fs
        .iter()
        .map(|(value, key)| format!("{indent}fs.{key}  {value}"))
        .chain(
            rights
                .net
                .iter()
                .map(|host| format!("{indent}net.allow_domains  {host}")),
        )
        .collect()
}

/// 権限の件数の要約（`ファイル2件・通信1件`）。行の短い注記に使う。
pub fn rights_count(rights: &Rights) -> String {
    format!("ファイル{}件・通信{}件", rights.fs.len(), rights.net.len())
}

#[cfg(test)]
#[path = "exposure_view_tests.rs"]
mod exposure_view_tests;
