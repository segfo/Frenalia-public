//! [段階⑦] 選んだ候補を**遷移の宣言として`policy.json`へ書く**／消す
//! （`plans/POLICY-EDITOR-TOMOYO-DIG.md` 決定63「辺の追加」「辺の取り消し」）。
//!
//! # ここではACEを付けない（というより、付ける対象が無い）
//!
//! FSの宣言と違い、**遷移の宣言は付与の対象を持たない**（`plans/DESIGN-MAC-ENFORCEMENT.md` §10.2）。
//! 承認しても実マシンのACLは1ビットも変わらない。**その旨を画面に出すこと**
//! ——[`ACE_NOTICE`]がその文言の持ち主である（`crate::unapprove::ACE_NOTICE`と同じ作法）。
//!
//! # 「決める」と「書く」を分ける
//!
//! [`plan`]は何も書かずに結果を返し、[`commit`]がそれを書く。`crate::approve`・
//! `crate::unapprove`と同じ2段で、CLIは差分を見せ、TUIはモーダルで確認を取る。
//!
//! # 部分適用しない
//!
//! 編集時検査に1件でも落ちたら**何も書かずに失敗する**（`crate::approve`と同じ判断）。
//! 「一部だけ通った」状態は、ユーザーが受け入れたつもりの構成と実際の構成をずらす。
//!
//! # 足すのと消すのを同じ場所に置く
//!
//! 承認だけ作ると、**間違えて承認した辺を手でJSONを編集しないと消せない**（`B-01`:
//! 対の片方だけ実装しない）。FS側が`approve`と`unapprove`を対で持っているのと同じ形を、
//! 遷移では1モジュールの中に置く——指す対象（[`EdgeRef`]）が同じだからである。
//!
//! # 遷移先は呼び出し側が選ぶ（2026-10-01）
//!
//! かつては遷移先を必ず呼び出し元と同じドメインに倒していた（`provisional_destination`。
//! `harness.exe`が別ドメインを用意できるかをエディタが知る手段が無かったため）。#30（D-112）で
//! 用意できるかが`policy.json`と承認台帳から決まるようになったので外し、[`TransitionRequest::to_domain`]で
//! 受ける。**書く前に断るのは3つ**——遷移元と同じ遷移先（自己ループ辺。凍結中、
//! `plans/POLICY-EDITOR-TOMOYO-DIG.md` 決定65(3)）、入れ物の名前にできない名前
//! （[`harness_sandbox::tier2a::domain_profile_name_problem`]）、編集時検査に落ちる宣言。
//! 「宣言の上では用意されない」遷移先（通信を宣言している・許可が付かない宣言がある）は**断らずに書く**
//! ——警告は画面が[`crate::transition_destination::Outlook`]で出す（`Startable`と同じ姿勢。
//! 書けるが通らないことを見えるところへ出し、判断はユーザーに残す）。

use std::path::Path;

use harness_change_ledger::path_rules::fold_for_pattern_comparison;
use harness_policy::policy_file::{self, PolicyDomain, PolicyFile, PolicyFileError};
use harness_policy::transition::{self, AnyMarker, ArgvMatcher, ExeMatcher, TransitionEdge};

/// 承認・取り消しがACLに何をするのかの説明。**この文言の持ち主はここだけ**（CLIもTUIもこれを出す）。
///
/// FS宣言の承認と見た目が同じなので、**いま何も起きないことを言わないと**「ACLが変わった」と
/// 読まれる（決定18: ACEを付ける経路は`preflight`ただ1つ）。
///
/// **2行目は2026-10-01に足した。** 別ドメインへの遷移を書けるようになり、遷移先になったドメインの
/// 承認済みファイル宣言には、`harness.exe`が遷移の強制を有効にした起動で許可を付ける（D-112の
/// 「付与する範囲」——遷移先になっていることが条件の1つ）。「変わるのは起こしてよいかだけ」と
/// 言い切ると、その帰結が見えない。
pub const ACE_NOTICE: &str = concat!(
    "注: 遷移の宣言を書いても、いま実マシンのACLは変わりません（変わるのは「起こしてよいか」）。\n",
    "    別ドメイン行きは、遷移を強制する起動でそのドメインの承認済み宣言へ許可が付く理由になります。"
);

/// 辺1本の指し方。**承認と取り消しで同じ型を使う。**
///
/// # なぜ提案idで指さないのか
///
/// idは候補の顔ぶれで振り直されるので、「どの宣言か」を表す識別子にならない
/// （`crate::unapprove::UnapproveTarget`が同じ理由で`(ドメイン, キー, 値)`で指している）。
/// 遷移で一意なのは**遷移元ドメインと`(exe, argv)`の組**である
/// （`plans/DESIGN-MAC.md` §4）。遷移元は画面が1つ持つので、ここは残り2つを持つ。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EdgeRef {
    /// 実行ファイルのフルパス。**観測された綴りそのまま**（畳んだ値を書かない）。
    pub exe: String,
    pub argv: ArgvChoice,
}

/// argvをどう照合するか。**省略できる形にしない**——`any`と書くか値を書くかを常に選ばせる
/// （`plans/DESIGN-MAC.md` §5.1）。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArgvChoice {
    /// 任意の引数を許す（`{"any": true}`）。
    Any,
    /// この綴りのコマンドラインだけを許す。
    Literal(String),
}

impl ArgvChoice {
    /// 画面と確認ダイアログに出す綴り。`Any`は[`harness_policy::transition_listing::ANY_ARGV`]。
    pub fn display(&self) -> &str {
        match self {
            ArgvChoice::Any => harness_policy::transition_listing::ANY_ARGV,
            ArgvChoice::Literal(value) => value,
        }
    }

    fn matcher(&self) -> ArgvMatcher {
        match self {
            ArgvChoice::Any => ArgvMatcher::Any(AnyMarker),
            ArgvChoice::Literal(value) => ArgvMatcher::Literal(value.clone()),
        }
    }

    fn matches_declared(&self, declared: &ArgvMatcher) -> bool {
        match (self, declared) {
            (ArgvChoice::Any, ArgvMatcher::Any(_)) => true,
            (ArgvChoice::Literal(mine), ArgvMatcher::Literal(theirs)) => {
                fold_for_pattern_comparison(mine) == fold_for_pattern_comparison(theirs)
            }
            _ => false,
        }
    }
}

/// 辺を1本組み立てる。**遷移先は引数で受ける**（[`TransitionRequest::to_domain`]）。
///
/// 形（リテラルの exe・**cwdは宣言しない**・環境変数の差分も書かない）は[`transition::editor_edge`]の
/// 1か所が持つ——位置ごとの割り当て（`harness_policy::position_domains`）が作る辺と同じ形にするため（`B-05`）。
fn edge_for(edge: &EdgeRef, to_domain: &str) -> TransitionEdge {
    transition::editor_edge(&edge.exe, edge.argv.matcher(), to_domain)
}

impl EdgeRef {
    /// この指し方で`to_domain`へ移る辺（形は[`edge_for`]）。位置ごとのドメインの確定（`tui::position_commit`）が、
    /// 拒否からの承認の予約を辺にするのに使う。
    pub(crate) fn edge_to(&self, to_domain: &str) -> TransitionEdge {
        edge_for(self, to_domain)
    }

    /// 辺そのものから指し方を作る（リテラルの exe で、引数が任意かリテラルの辺だけ）。パターンを含む辺は
    /// [`EdgeRef`]で指せないので`None`。**「同じ辺か」の比べ方を[`refers_to`]の1つにする**ために使う。
    fn of_edge(edge: &TransitionEdge) -> Option<EdgeRef> {
        let ExeMatcher::Literal(exe) = &edge.exe else {
            return None;
        };
        let argv = match &edge.argv {
            ArgvMatcher::Any(_) => ArgvChoice::Any,
            ArgvMatcher::Literal(value) => ArgvChoice::Literal(value.clone()),
            ArgvMatcher::Pattern(_) => return None,
        };
        Some(EdgeRef {
            exe: exe.clone(),
            argv,
        })
    }
}

/// 承認・取り消しの要求。
pub struct TransitionRequest<'a> {
    pub workspace_root: &'a Path,
    /// 遷移元ドメイン。**画面が1つ持つ**（辺の3つ組のうち1つ目）。
    pub from_domain: &'a str,
    /// 足す辺の遷移先ドメイン（1回の確定で1つ）。**`from_domain`と同じ値は断る**
    /// （[`TransitionApproveError::SelfLoopFrozen`]）。
    ///
    /// **既定値を持たせない**——呼び出し側が選んだ値を必ず渡す（かつての暫定は、ここを
    /// 遷移元で埋めていた）。`policy.json`に無い名前なら、宣言の無いドメインとして作る。
    /// 取り消し（`remove`）には効かない（消す辺は`(exe, argv)`で指す）。
    pub to_domain: &'a str,
    /// 足す辺。
    pub approve: &'a [EdgeRef],
    /// 消す辺。**`policy.json`に書かれている綴りで指すこと。**
    pub remove: &'a [EdgeRef],
    pub record_session: Option<&'a str>,
    pub now_unix_ms: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum TransitionApproveError {
    #[error("承認も取り消しも1件も指定されていません（policy.jsonは変えていません）")]
    NothingSelected,
    #[error("この宣言では書けません（何も書いていません）:\n{0}")]
    Rejected(String),
    /// 遷移先が遷移元と同じ（自己ループ辺）。**凍結中で書かない**——自己ループ辺は深さを区別しなくなる
    /// 書き方で、ユーザーの明示操作として設計するまで書かない（`plans/POLICY-EDITOR-TOMOYO-DIG.md`
    /// 決定65(3)）。手で書いた自己ループ辺の取り消しは止めない（`B-01`）。
    #[error(
        "遷移先が遷移元と同じドメイン「{domain}」です。自己ループ辺（深さを区別しない書き方）は凍結中のため\
         書けません（何も書いていません）。遷移先の欄に別のドメイン名を入れてください"
    )]
    SelfLoopFrozen { domain: String },
    /// 遷移先の名前が、`harness.exe`の入れ物（AppContainerプロファイル）の名前にできない。
    #[error("遷移先ドメイン「{to_domain}」には書けません（何も書いていません）: {reason}")]
    DestinationName { to_domain: String, reason: String },
    /// 足そうとした辺が「広げる遷移」で、固定（引数と作業ディレクトリ）が無いので検査に落ちた。
    ///
    /// **検査の理由をそのまま出すだけでは足りない**——検査は「argvをリテラルにしcwdを宣言せよ」と
    /// 言うが、このエディタは作業ディレクトリを宣言しない（[`edge_for`]）ので、その直し方は取れない。
    #[error(
        "遷移先「{to_domain}」は、呼び出し元より広い権限に届く（または狭いと証明できない）ので、\
         引数と作業ディレクトリを固定した遷移としてしか宣言できません。このエディタは作業ディレクトリを\
         宣言しないので書けません（何も書いていません）。\n\
         遷移先と、そこから辿れるドメインのファイル・通信の宣言を呼び出し元の宣言の範囲に収めるか、\
         宣言を持たないドメインを遷移先にしてください。\n検査の理由:\n{detail}"
    )]
    WidensWithoutFixing { to_domain: String, detail: String },
    #[error(transparent)]
    PolicyFile(#[from] PolicyFileError),
}

/// 書く前に決まったこと一式。
///
/// **「足した」と「元からあった」、「消した」と「元から無かった」を区別する**（`B-09`）
/// ——区別しないと、綴りを間違えた指定が「承認しました」として通る。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionPlan {
    /// 書き込む予定の内容（[`commit`]がそのまま保存する）。
    pub file: PolicyFile,
    pub added: Vec<EdgeRef>,
    /// 足そうとしたが、同じ`(exe, argv)`の辺が既にあった。
    ///
    /// **同じ綴りを2本書かない。** 重複した辺は編集時検査を通らず、`policy.json`が
    /// まるごと効かなくなる（症状は「宣言したのに断られる」で、宣言側を疑いにくい）。
    pub already_declared: Vec<EdgeRef>,
    pub removed: Vec<EdgeRef>,
    /// 消そうとしたが`policy.json`に無かった。
    pub not_found: Vec<EdgeRef>,
    /// 足す辺の遷移先（[`TransitionRequest::to_domain`]そのもの）。
    pub to_domain: String,
    /// 遷移先が`policy.json`に無かったので、**宣言の無いドメインとして作る**。
    ///
    /// 確認ダイアログが言うためにある——黙って作ると、宣言画面（F3）に見覚えの無い空のドメインが
    /// 現れる（`B-09`: 足したものを足したと言う）。
    pub created_to_domain: bool,
}

impl TransitionPlan {
    /// 書く必要が無い（足すものも消すものも無い）。
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// 何を書くかを決める（**何も書かない**）。
///
/// # 検査は`harness-policy`のものをそのまま通す
///
/// [`transition::check_all`]は`policy_file::load`が読むたびに掛けている検査そのものである。
/// ここで先に掛けるのは、**書いてから落ちる**のを避けるためで、規則を写しているのではない
/// ——[`policy_file::save`]も同じ検査を掛ける（BUG-188）が、ここで先に掛けるのは、
/// 確認ダイアログに理由を出してから何も書かずに止めるためである。
pub fn plan(req: &TransitionRequest<'_>) -> Result<TransitionPlan, TransitionApproveError> {
    if req.approve.is_empty() && req.remove.is_empty() {
        return Err(TransitionApproveError::NothingSelected);
    }
    let to_domain = req.to_domain.to_string();
    // **自己ループ辺は書かない**（決定65(3)。凍結中）。取り消しだけの確定は遷移先を使わないので通す
    // ——手で書いた自己ループ辺を外す操作まで止めない（`B-01`）。
    if !req.approve.is_empty() && to_domain == req.from_domain {
        return Err(TransitionApproveError::SelfLoopFrozen {
            domain: req.from_domain.to_string(),
        });
    }
    // **入れ物の名前にできない遷移先は書く前に断る**（決定63「自動生成名の検証を『あれば良い』に
    // 落とさない」と同じ理由。編集時検査は通るのに、`harness.exe`が起動時に用意できない）。
    // 取り消しだけの確定は見ない（遷移先を使わない）。
    if !req.approve.is_empty() {
        if let Some(reason) = harness_sandbox::tier2a::domain_profile_name_problem(&to_domain) {
            return Err(TransitionApproveError::DestinationName { to_domain, reason });
        }
    }
    let mut file = policy_file::load(req.workspace_root)?;
    let add: Vec<TransitionEdge> = req
        .approve
        .iter()
        .map(|target| edge_for(target, &to_domain))
        .collect();
    let report = apply_edge_changes(
        &mut file,
        &EdgeChanges {
            from_domain: req.from_domain,
            add: &add,
            remove: req.remove,
            record_session: req.record_session,
            now_unix_ms: req.now_unix_ms,
        },
    );
    let (mut added, mut already_declared) = (Vec::new(), Vec::new());
    for (index, target) in req.approve.iter().enumerate() {
        if report.already_declared.contains(&index) {
            already_declared.push(target.clone());
        } else {
            added.push(target.clone());
        }
    }
    let added_at: Vec<(String, usize)> = report
        .added
        .iter()
        .map(|index| (req.from_domain.to_string(), *index))
        .collect();
    check_added(&file, req.workspace_root, &added_at)?;

    Ok(TransitionPlan {
        created_to_domain: report.created_domains.contains(&to_domain),
        file,
        added,
        already_declared,
        removed: report.removed,
        not_found: report.not_found,
        to_domain,
    })
}

/// 1つの遷移元へ足す辺・消す辺（[`apply_edge_changes`]の入力。2026-10-05、`plans/position-domains/P4.md`のP4.3）。
pub struct EdgeChanges<'a> {
    pub from_domain: &'a str,
    /// 足す辺（形は[`transition::editor_edge`]で作ったもの）。**遷移先は辺ごとに違ってよい**
    /// ——位置ごとのドメイン（決定65）では、1つの遷移元から別々の遷移先へ辺が出る。
    pub add: &'a [TransitionEdge],
    /// 消す辺。**`policy.json`に書かれている綴りで指すこと。**
    pub remove: &'a [EdgeRef],
    pub record_session: Option<&'a str>,
    pub now_unix_ms: u64,
}

/// [`apply_edge_changes`]が何をしたか。**「足した」と「元からあった」、「消した」と「元から無かった」を
/// 区別する**（`B-09`。[`TransitionPlan`]と同じ理由）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EdgeChangeReport {
    /// 足した辺の、遷移元の`transitions`への添字（[`EdgeChanges::add`]の順）。[`check_added`]へ渡す。
    pub added: Vec<usize>,
    /// 足そうとしたが同じ`(exe, argv)`の辺が既にあった（[`EdgeChanges::add`]への添字）。
    pub already_declared: Vec<usize>,
    pub removed: Vec<EdgeRef>,
    pub not_found: Vec<EdgeRef>,
    /// 足した辺の遷移先で、`policy.json`に無かったので宣言の無いドメインとして作ったもの（名前の順）。
    /// **遷移元を作ったことは入れない**——遷移元に届く辺があるとは限らない。
    pub created_domains: Vec<String>,
}

/// 読み込んだ`file`へ、1つの遷移元の辺を足す・消す（**入出力なし・検査なし**）。書いた後の検査は
/// [`check_added`]、保存は呼び出し側。[`plan`]と、位置ごとのドメインの確定（P4.5）・承認待ちの位置の行の
/// 判定（`crate::position_view::verdicts`）が同じこれを通る（`docs/CODE-STRUCTURE-RULES.md` §5.0）。
///
/// 遷移元が`policy.json`に無ければ作る。
pub fn apply_edge_changes(file: &mut PolicyFile, changes: &EdgeChanges<'_>) -> EdgeChangeReport {
    if file.domain(changes.from_domain).is_none() {
        file.domains.push(PolicyDomain::new(changes.from_domain));
        file.domains.sort_by(|a, b| a.name.cmp(&b.name));
    }
    let mut report = EdgeChangeReport::default();
    let mut destinations: Vec<String> = Vec::new();
    {
        let entry = file
            .domains
            .iter_mut()
            .find(|d| d.name == changes.from_domain)
            .expect("just inserted or already present");

        // **消す方を先にやる。** 同じ`(exe, argv)`を「消してから違う形で足し直す」が
        // 1回の確定でできる——逆順にすると、足したものをその場で消すことになる。
        let (removed, not_found) = remove_edges(entry, changes.remove);
        report.removed = removed;
        report.not_found = not_found;

        for (index, edge) in changes.add.iter().enumerate() {
            // 同じ辺か の比べ方は[`refers_to`]の1つ（リテラルの exe を畳んで比べ、引数の照合方法も見る）。
            let declared = EdgeRef::of_edge(edge).is_some_and(|target| {
                entry
                    .process
                    .transitions
                    .iter()
                    .any(|existing| refers_to(&target, existing))
            });
            if declared {
                report.already_declared.push(index);
                continue;
            }
            entry.process.transitions.push(edge.clone());
            report.added.push(entry.process.transitions.len() - 1);
            destinations.push(edge.to.clone());
        }

        if !report.added.is_empty() || !report.removed.is_empty() {
            if let Some(session) = changes.record_session {
                if !entry
                    .provenance
                    .record_sessions
                    .iter()
                    .any(|s| s == session)
                {
                    entry.provenance.record_sessions.push(session.to_string());
                }
            }
            entry.provenance.updated_unix_ms = changes.now_unix_ms;
        }
    }

    // **遷移先が無ければ、宣言の無いドメインとして作る。** 編集時検査は「宣言されていない
    // ドメインへの遷移」を断る（打ち間違いが空の＝常に狭い権限で黙って通るのを止めるため）ので、
    // 作らないと書けない。作るのは**足した辺の遷移先だけ**（取り消しだけ・既にある辺だけの確定で
    // 見覚えの無いドメインを増やさない）。
    for to in destinations {
        if file.domain(&to).is_none() {
            file.domains.push(PolicyDomain::new(to.as_str()));
            report.created_domains.push(to);
        }
    }
    if !report.created_domains.is_empty() {
        file.domains.sort_by(|a, b| a.name.cmp(&b.name));
        report.created_domains.sort();
    }
    report
}

/// 足した辺を書いた後の`file`を検査する（**書く前に検査する**——ここで落ちれば`policy.json`は元のままである）。
///
/// [`transition::check_all`]（`policy_file::load`が読むたびに掛けている検査そのもの）に落ちたら、
/// `added`（`(遷移元, transitions への添字)`）のうち広げる向きの辺があれば
/// [`TransitionApproveError::WidensWithoutFixing`]（このエディタで取れる直し方を言い直す）、無ければ
/// [`TransitionApproveError::Rejected`]。**向きの規則はここで書かない**——[`transition::edge_direction`]に聞く（`B-13`）。
///
/// **`policy.json`の外で書込を許した場所は空で渡す**——エディタはそれを知らない
/// （`--fs-allow`はharnessの起動ごとの指定で、書く時点では原理的に分からない）。
/// したがって固定した遷移は、ここを通っても`harness.exe`の起動時に初めて拒否されることがある
/// （残課題 サンドボックス周辺 #65。`policy_file::load_for_session`のdoc）。
/// **このエディタが書く辺は固定した遷移にならない**（`cwd`を宣言しない。[`edge_for`]）ので、
/// 足した辺がそれで落ちることは無い（試験`an_edge_this_editor_writes_survives_the_writable_places_harness_adds`）。
pub fn check_added(
    file: &PolicyFile,
    workspace_root: &Path,
    added: &[(String, usize)],
) -> Result<(), TransitionApproveError> {
    let workspace = workspace_root.to_string_lossy();
    let input = file.transition_graph_input(Some(workspace.as_ref()), &[]);
    let rejected = match transition::check_all(&input) {
        Ok(rejections) => rejections.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
        Err(e) => vec![e.to_string()],
    };
    if rejected.is_empty() {
        return Ok(());
    }
    let detail = rejected.join("\n");
    // 足した辺が「広げる遷移」だったなら、このエディタで取れる直し方を言い直す（変種のdoc）。
    let widening = added.iter().find(|(from, index)| {
        matches!(
            transition::edge_direction(&input, from, *index),
            Ok(Some(transition::Direction::WiderOrUnknown))
        )
    });
    Err(match widening {
        Some((from, index)) => TransitionApproveError::WidensWithoutFixing {
            to_domain: file
                .domain(from)
                .and_then(|domain| domain.process.transitions.get(*index))
                .map(|edge| edge.to.clone())
                .unwrap_or_default(),
            detail,
        },
        None => TransitionApproveError::Rejected(detail),
    })
}

/// 決まった内容を書く。**`false`は「書く必要が無かった」**（`B-09`）。
pub fn commit(
    workspace_root: &Path,
    plan: &TransitionPlan,
) -> Result<bool, TransitionApproveError> {
    if plan.is_empty() {
        return Ok(false);
    }
    policy_file::save(workspace_root, &plan.file)?;
    Ok(true)
}

/// `domain`から、`remove`の各指定が指す辺を取り除く。返すのは（消した指定, 宣言に無かった指定）。
fn remove_edges(domain: &mut PolicyDomain, remove: &[EdgeRef]) -> (Vec<EdgeRef>, Vec<EdgeRef>) {
    let mut removed = Vec::new();
    let mut not_found = Vec::new();
    for target in remove {
        let before = domain.process.transitions.len();
        domain
            .process
            .transitions
            .retain(|edge| !refers_to(target, edge));
        if domain.process.transitions.len() == before {
            not_found.push(target.clone());
        } else {
            removed.push(target.clone());
        }
    }
    (removed, not_found)
}

/// 宣言画面（`F3`）の遷移タブの取り消し（2026-10-05、`plans/position-domains/P4.md`のP4.2）。
///
/// [`plan`]の取り消しと違い、**遷移元ごとに、書かれている辺そのもの**（`(遷移元, TransitionEdge)`）で指す。
/// 手で書いた辺にはパターン・作業ディレクトリ・環境変数の差分があり、[`EdgeRef`]（リテラルの exe と引数）では
/// 指せないからである。位置（`transitions`の添字）では指さない——ダイアログを見ている間に別の経路で
/// 書き換わると、添字は別の辺を指す。
/// 遷移元のドメイン名と、そこに書かれている辺そのもの（[`RemovalPlan`]の指し方）。
pub type DomainEdge = (String, TransitionEdge);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalPlan {
    /// 書き込む予定の内容（[`commit_removals`]がそのまま保存する）。
    pub file: PolicyFile,
    pub removed: Vec<DomainEdge>,
    /// 消そうとしたが`policy.json`に無かった（別の経路で消えていた）。**黙って落とさない**（`B-09`）。
    pub not_found: Vec<DomainEdge>,
}

/// 取り消しの内容を決める（**何も書かない**）。遷移元が違う辺も**1つの`PolicyFile`**に当てる——保存は
/// [`commit_removals`]の1回だけで、片方の遷移元だけ消えた状態を作らない。
///
/// 読むのは[`policy_file::load_for_repair`]——**遷移の検査に落ちる宣言も直せるように**するためである
/// （検査に落ちる辺を取り消せば、書いた後のファイルは検査に通る）。ここでは検査を掛けない。取り消しは
/// 権限を減らす向きで、取り消した後もまだ検査に落ちるなら[`policy_file::save`]自身が断る。
pub fn plan_removals(
    workspace_root: &Path,
    removals: &[DomainEdge],
    now_unix_ms: u64,
) -> Result<RemovalPlan, TransitionApproveError> {
    if removals.is_empty() {
        return Err(TransitionApproveError::NothingSelected);
    }
    let (mut file, _rejections) = policy_file::load_for_repair(workspace_root)?;
    let (removed, not_found) = apply_removals(&mut file, removals, now_unix_ms);
    Ok(RemovalPlan {
        file,
        removed,
        not_found,
    })
}

/// `removals`の各辺を、その遷移元のドメインから取り除く（**入出力なし・検査なし**）。等しい辺（`==`）が2本
/// 書かれていれば両方消す——画面は同じ中身の辺を1つの予約で指すので、片方だけ残すと「取り消します」と出た行が残る。
/// 消した遷移元のドメインは`provenance.updated_unix_ms`を進める。返すのは（消したもの, 宣言に無かったもの）。
pub(crate) fn apply_removals(
    file: &mut PolicyFile,
    removals: &[DomainEdge],
    now_unix_ms: u64,
) -> (Vec<DomainEdge>, Vec<DomainEdge>) {
    let mut removed = Vec::new();
    let mut not_found = Vec::new();
    for (from, edge) in removals {
        let Some(domain) = file.domains.iter_mut().find(|d| d.name == *from) else {
            not_found.push((from.clone(), edge.clone()));
            continue;
        };
        let before = domain.process.transitions.len();
        domain.process.transitions.retain(|declared| declared != edge);
        if domain.process.transitions.len() == before {
            not_found.push((from.clone(), edge.clone()));
        } else {
            domain.provenance.updated_unix_ms = now_unix_ms;
            removed.push((from.clone(), edge.clone()));
        }
    }
    (removed, not_found)
}

/// 取り消しを書く。**保存は1回**（遷移元が何個でも）。`false`は「消せる辺が無かった」（`B-09`）。
pub fn commit_removals(
    workspace_root: &Path,
    plan: &RemovalPlan,
) -> Result<bool, TransitionApproveError> {
    if plan.removed.is_empty() {
        return Ok(false);
    }
    policy_file::save(workspace_root, &plan.file)?;
    Ok(true)
}

/// この指定は、その辺のことを言っているか。
///
/// **リテラルの辺だけが対象である。** パターンの辺は「この綴りそのもの」ではないので、
/// ここからは消せない（外すと、この行に見えていない他のプログラムの許可も消えるため。
/// `crate::transition_candidates::Declared::ByAPattern`のdoc）。
fn refers_to(target: &EdgeRef, edge: &TransitionEdge) -> bool {
    let ExeMatcher::Literal(declared_exe) = &edge.exe else {
        return false;
    };
    fold_for_pattern_comparison(declared_exe) == fold_for_pattern_comparison(&target.exe)
        && target.argv.matches_declared(&edge.argv)
}

#[cfg(test)]
#[path = "transition_approve_tests.rs"]
mod transition_approve_tests;
