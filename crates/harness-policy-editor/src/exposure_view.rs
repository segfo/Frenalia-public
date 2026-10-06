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
//! # どの経路に出すか（`policy.json`を書く経路6つのうち5つ）
//!
//! `policy.json`を保存する関数は6つある。**広がり得る5つ**——位置ごとのドメインの確定（`position_approve`）・
//! ファイル宣言の承認（`approve`）・付け替え（`reassign`）・取り消し（`unapprove`）・宣言画面の遷移タブの確定
//! （`transition_approve::commit_removals`。P5.5 で Strict の印の付け外しが乗った）——は、`plan`が[`Widening`]を作り、
//! その確認を出す画面と CLI がすべて[`lines`]を並べる（TUI の承認待ち・宣言画面の両タブと、CLI の`approve`・
//! `unapprove`）。宣言の承認・付け替えは遷移先の権限を増やし、取り消しは遷移元の宣言を減らし、**Strict の印を外すと
//! 入る辺が閉包に入る**ので、辺に触らなくても辺が渡す権限は増え得る。**対象外の1つ**:
//!
//! - `transition_approve::commit`（辺を足すが、画面と CLI からは呼ばれない。試験の入口として残る。
//!   承認待ちの遷移タブの確定は`position_approve`を通る）
//!
//! [P5.5] [`Widening`]は**スキーマ版の上がり**（出力を捨てる辺か Strict の印を初めて書くと3へ。古い`harness.exe`は
//! 読込で断る）も運ぶ——確定の明細を出す経路がすべてこの構造体を並べるので、案内の配線を1つにした。
//!
//! # 限界
//!
//! - **組み合わせの対**（Limit 1。あるドメインが書ける場所を、外部と通信できる別のドメインが読む／実行する）は
//!   **断らずに並べるだけ**（P5.6、決定66(9)）。「外部と通信できるか」は暫定の見立て（`provisional_net_capable`。P7 で
//!   差し替え）で、変更の前から在った対は出さない。CLI の`--auto-approve`は対が1組でもあれば書かない（`cli_consent`）
//! - **子の出力の行は、広がる辺にだけ出す**（P5.4b。Daemon が出力を返すようになった段で足した——P5.3 は返して
//!   いなかったので、入る前に言うと嘘になった、`B-32`）。広がらない辺の出力の設定は、辺の綴りに添える
//!   [`output_suffix`]が出す（P5.5。確認の明細・宣言画面の遷移タブ）
//! - 1つの確認に2つの`plan`が並ぶ画面（承認待ちの「承認＋チェックを外した取り消し」、宣言画面の
//!   「付け替え＋取り消し」）は、`plan`ごとに「いまの`policy.json`からの差」を出す。**2つを重ねて初めて広がる辺**
//!   （片方が足した値を、もう片方が遷移元から外す）は数えない
//! - `policy.json`の外で書込を許した場所（`--fs-allow`）はエディタが知らないので数えない（`check_added`と同じ）

use std::path::Path;

use harness_policy::policy_file::{PolicyFile, POLICY_SCHEMA_VERSION};
use harness_policy::transition::{self, ChildOutput, CombinationPair, ExeMatcher, PairUse, TransitionEdge};
use harness_policy::transition_listing::Rights;

/// 変更で広がる遷移（[`widening`]の答え）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Widening {
    /// 渡す権限が増えた辺（変更後の宣言の順）。
    pub edges: Vec<WidenedEdge>,
    /// 数えられなかった理由（同じ名前のドメインが2つある等）。**黙って「広がらない」と言わない**（`B-10`）。
    pub uncounted: Option<String>,
    /// [P5.5] この変更で`policy.json`のスキーマ版が上がるとき（変更前, 変更後）。出力を捨てる辺か Strict の印を初めて
    /// 書くと3へ上がり、版2までしか読めない古い`harness.exe`は読込で断る——書く前に知らせる。広がりではないが、
    /// 確定の明細を出す全経路がこの構造体を並べるので、ここに持たせて配線を1つにした（`B-06`）。
    pub schema_raised: Option<(u32, u32)>,
    /// [P5.6] 変更で生まれた組み合わせの対（決定66(9)・Limit 1。あるドメインが書ける場所を、外部と通信できる別のドメインが
    /// 読む／実行する）。**断らずに見せる**——ポリシーの書き方の責任で、人が判断する。
    pub pairs: Vec<CombinationPair>,
    /// [P5.6] 変更で新しく Strict のドメインへ入るようになった辺。何も渡さないので[`Self::edges`]には入らないが、明細は
    /// 辺のモード（普通か Strict か）を示すためにこれを出す（`harness_policy::transition::ExposureDelta::strict_edges`）。
    pub strict_edges: Vec<StrictEdgeView>,
}

impl Widening {
    /// 確認に出すものが無い（広がる辺・組み合わせ・新しい Strict の辺が無く、数えられなかったことも、版が上がることも無い）。
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
            && self.uncounted.is_none()
            && self.schema_raised.is_none()
            && self.pairs.is_empty()
            && self.strict_edges.is_empty()
    }

    /// [P5.6] **呼び出し元へ新しく権限を渡し得る変更か**——広がる辺・新しい組み合わせが1件でもある、または数えられ
    /// なかった（確かめていないものを「渡さない」と言わない、`B-10`）。CLI の`--auto-approve`はこれが真なら書かない
    /// （決定66(8)）。版の上がりと新しい Strict の辺は渡すものを増やさないので数えない。
    pub fn hands_over_rights(&self) -> bool {
        !self.edges.is_empty() || !self.pairs.is_empty() || self.uncounted.is_some()
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
    /// 辺の出力の設定（[`harness_policy::transition::ChildOutput`]。P5.4b）。返す辺なら、子が読めるものは出力で
    /// 呼び出し元へ渡る——明細はそれを言う。
    pub output: ChildOutput,
}

/// [P5.6] 新しく Strict になった辺1本（明細の表示用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictEdgeView {
    pub from: String,
    /// 辺の実行ファイル（書かれた綴り）。
    pub exe: String,
    pub to: String,
}

/// `before` → `after`の変更で広がる遷移。`after`は書く予定の内容、`before`は読み込んだ`policy.json`。
pub fn widening(before: &PolicyFile, after: &PolicyFile, workspace_root: &Path) -> Widening {
    // 版は内容から決まる（`PolicyFile::required_schema_version`）。版1→2（初めての遷移）は P5 より前から言っていない。
    let (was, will_be) = (
        before.required_schema_version(),
        after.required_schema_version(),
    );
    let schema_raised = (will_be == POLICY_SCHEMA_VERSION && was < will_be).then_some((was, will_be));
    let workspace = workspace_root.to_string_lossy();
    let delta = transition::exposure_delta(
        &before.transition_graph_input(Some(workspace.as_ref()), &[]),
        &after.transition_graph_input(Some(workspace.as_ref()), &[]),
        transition::provisional_net_capable,
    );
    // 辺は変更後の宣言での位置で指される。見つからないことは無い（見つからなければ空の綴り・既定の出力）。
    let written = |from: &str, index: usize| -> Option<&TransitionEdge> {
        after.domain(from).and_then(|d| d.process.transitions.get(index))
    };
    let exe_of = |edge: Option<&TransitionEdge>| {
        edge.map(|e| match &e.exe {
            ExeMatcher::Literal(exe) | ExeMatcher::Pattern(exe) => exe.clone(),
        })
        .unwrap_or_default()
    };
    match delta {
        Ok(delta) => Widening {
            edges: delta
                .edges
                .into_iter()
                .map(|edge| {
                    let found = written(&edge.from, edge.edge_index);
                    WidenedEdge {
                        exe: exe_of(found),
                        // 見つからなければ既定の「返す」——渡る側へ倒して言う（言わないより言い過ぎる側）。
                        output: found.map(|e| e.output).unwrap_or_default(),
                        from: edge.from,
                        to: edge.to,
                        newly_usable: edge.newly_usable,
                    }
                })
                .collect(),
            uncounted: None,
            schema_raised,
            pairs: delta.pairs,
            strict_edges: delta
                .strict_edges
                .into_iter()
                .map(|edge| StrictEdgeView {
                    exe: exe_of(written(&edge.from, edge.edge_index)),
                    from: edge.from,
                    to: edge.to,
                })
                .collect(),
        },
        Err(e) => Widening {
            uncounted: Some(e.to_string()),
            schema_raised,
            ..Widening::default()
        },
    }
}

/// 確認の画面・CLI に並べる行（出すものが無ければ空）。節ごとに先頭へ空行を1つ置く（前の節と分ける）。
pub fn lines(widening: &Widening) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some((was, will_be)) = widening.schema_raised {
        lines.push(String::new());
        lines.push(format!(
            "policy.json のスキーマ版が {was}→{will_be} に上がります（子の出力を捨てる辺か Strict の印を書くため）。\
             版{will_be}を知らない古い harness.exe・ポリシーエディタは、この policy.json を読込で断ります\
             （印を黙って無視して読むことはありません）。このワークスペースを古い harness.exe で使うなら先に更新してください"
        ));
    }
    if let Some(reason) = &widening.uncounted {
        lines.push(String::new());
        lines.push(format!(
            "広がる遷移を数えられません（{reason}）——書くと呼び出し元が子を通して何を使えるようになるかは、\
             この画面では確かめていません"
        ));
    }
    if !widening.edges.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "広がる遷移 {}本——書くと、呼び出し元は子を通して次の権限を使えるようになります\
             （守るのは子のドメインの権限。決定66）:",
            widening.edges.len()
        ));
        for edge in &widening.edges {
            // [P5.6] 辺のモード。広がる辺は定義から普通のモード（Strict の辺は何も渡さないので広がらない）。
            lines.push(format!("  {} → {}（{}）［普通］", edge.from, edge.to, edge.exe));
            lines.extend(rights_lines(&edge.newly_usable, "      "));
            // [P5.4b] 出力の行き先（決定66(4)）。返す辺は、子が読めるものが出力を通って呼び出し元へ渡る
            // ——いちばん太い持ち出しの経路なので明細で言う。捨てても子が書いたファイルは残るので「渡らない」とは言わない。
            lines.push(match edge.output {
                ChildOutput::Return => {
                    "      出力を返すので、子が読めるものは呼び出し元へ渡ります".to_string()
                }
                ChildOutput::Discard => "      子の出力は捨てる設定です".to_string(),
            });
        }
    }
    if !widening.strict_edges.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "新しく Strict になる辺 {}本——入力を固定するので、呼び出し元は子を操れません（広がる遷移に数えていません）:",
            widening.strict_edges.len()
        ));
        for edge in &widening.strict_edges {
            lines.push(format!("  {} → {}（{}）［Strict］", edge.from, edge.to, edge.exe));
        }
    }
    if !widening.pairs.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "組み合わせ {}組——あるドメインが書ける場所を、外部と通信できる別のドメインが読む／実行します。\
             断らずに見せます（決定66(9)。書いたものが外へ出る・通信できるドメインで走る経路になり得ます）:",
            widening.pairs.len()
        ));
        for pair in &widening.pairs {
            let use_ = match pair.use_ {
                PairUse::Read => "読める",
                PairUse::Execute => "実行できる",
            };
            lines.push(format!(
                "  {} が書ける {} を、{} が{use_}（{}）",
                pair.writer, pair.writer_place, pair.reader, pair.reader_place
            ));
        }
        lines.push(
            "  外部と通信できるかは暫定の見立てです（入口のドメインと、通信先を宣言したドメイン。P7 で差し替え）"
                .to_string(),
        );
    }
    lines
}

/// [P5.5] 辺の綴りに添える出力の設定（捨てる辺だけ。既定の「返す」は何も添えない）。確認の明細・宣言画面の遷移タブ・
/// 位置の木の行が同じこれを通す（文言を写さない、`B-05`）。
pub fn output_suffix(output: ChildOutput) -> &'static str {
    match output {
        ChildOutput::Return => "",
        ChildOutput::Discard => "（子の出力を捨てる）",
    }
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
