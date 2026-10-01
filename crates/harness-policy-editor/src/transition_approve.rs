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
//! 受ける。**書く前に断るのは2つだけ**——入れ物の名前にできない名前
//! （[`crate::transition_destination::profile_name_problem`]）と、編集時検査に落ちる宣言。
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
fn edge_for(edge: &EdgeRef, to_domain: &str) -> TransitionEdge {
    TransitionEdge {
        exe: ExeMatcher::Literal(edge.exe.clone()),
        argv: edge.argv.matcher(),
        // **cwdは宣言しない。** 観測にcwdは無く（§10.3）、拒否側のcwdは呼び出し元の実cwdで
        // あって「ここでしか起こしてはいけない」という意思ではない。意思でないものを宣言へ
        // 書くと、次に別の場所から走らせたときに理由の分からない拒否になる。
        cwd: None,
        to: to_domain.to_string(),
        // 環境変数の差分も宣言しない（既定はセッションのbase env。§19.1）。
        env: None,
    }
}

/// 承認・取り消しの要求。
pub struct TransitionRequest<'a> {
    pub workspace_root: &'a Path,
    /// 遷移元ドメイン。**画面が1つ持つ**（辺の3つ組のうち1つ目）。
    pub from_domain: &'a str,
    /// 足す辺の遷移先ドメイン（1回の確定で1つ）。`from_domain`と同じなら自己ループ。
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
/// ——[`policy_file::save`]自身は検査しないので、書いた後に読めないファイルを作れてしまう。
pub fn plan(req: &TransitionRequest<'_>) -> Result<TransitionPlan, TransitionApproveError> {
    if req.approve.is_empty() && req.remove.is_empty() {
        return Err(TransitionApproveError::NothingSelected);
    }
    let to_domain = req.to_domain.to_string();
    // **入れ物の名前にできない遷移先は書く前に断る**（決定63「自動生成名の検証を『あれば良い』に
    // 落とさない」と同じ理由。編集時検査は通るのに、`harness.exe`が起動時に用意できない）。
    // 自己ループは入れ物を作らないので見ない。取り消しだけの確定も見ない（遷移先を使わない）。
    if !req.approve.is_empty() && to_domain != req.from_domain {
        if let Some(reason) = crate::transition_destination::profile_name_problem(&to_domain) {
            return Err(TransitionApproveError::DestinationName { to_domain, reason });
        }
    }
    let mut file = policy_file::load(req.workspace_root)?;
    if file.domain(req.from_domain).is_none() {
        file.domains.push(PolicyDomain::new(req.from_domain));
        file.domains.sort_by(|a, b| a.name.cmp(&b.name));
    }

    let mut plan = TransitionPlan {
        file: PolicyFile::default(),
        added: Vec::new(),
        already_declared: Vec::new(),
        removed: Vec::new(),
        not_found: Vec::new(),
        to_domain: to_domain.clone(),
        created_to_domain: false,
    };
    // 足した辺の添字（検査に落ちたとき、どれが「広げる遷移」かを向きの判定器に聞くため）。
    let mut added_indices: Vec<usize> = Vec::new();

    {
        let entry = file
            .domains
            .iter_mut()
            .find(|d| d.name == req.from_domain)
            .expect("just inserted or already present");

        // **消す方を先にやる。** 同じ`(exe, argv)`を「消してから違う形で足し直す」が
        // 1回の確定でできる——逆順にすると、足したものをその場で消すことになる。
        for target in req.remove {
            let before = entry.process.transitions.len();
            entry
                .process
                .transitions
                .retain(|edge| !refers_to(target, edge));
            if entry.process.transitions.len() == before {
                plan.not_found.push(target.clone());
            } else {
                plan.removed.push(target.clone());
            }
        }

        for target in req.approve {
            if entry
                .process
                .transitions
                .iter()
                .any(|edge| refers_to(target, edge))
            {
                plan.already_declared.push(target.clone());
                continue;
            }
            entry.process.transitions.push(edge_for(target, &to_domain));
            added_indices.push(entry.process.transitions.len() - 1);
            plan.added.push(target.clone());
        }

        if !plan.added.is_empty() || !plan.removed.is_empty() {
            if let Some(session) = req.record_session {
                if !entry
                    .provenance
                    .record_sessions
                    .iter()
                    .any(|s| s == session)
                {
                    entry.provenance.record_sessions.push(session.to_string());
                }
            }
            entry.provenance.updated_unix_ms = req.now_unix_ms;
        }
    }

    // **遷移先が無ければ、宣言の無いドメインとして作る。** 編集時検査は「宣言されていない
    // ドメインへの遷移」を断る（打ち間違いが空の＝常に狭い権限で黙って通るのを止めるため）ので、
    // 作らないと書けない。作るのは**足す辺があるときだけ**（取り消しだけ・既にある辺だけの確定で
    // 見覚えの無いドメインを増やさない）。
    if !plan.added.is_empty() && file.domain(&to_domain).is_none() {
        file.domains.push(PolicyDomain::new(to_domain.as_str()));
        file.domains.sort_by(|a, b| a.name.cmp(&b.name));
        plan.created_to_domain = true;
    }

    // **書く前に検査する。** ここで落ちれば`policy.json`は元のままである。
    //
    // **`policy.json`の外で書込を許した場所は空で渡す**——エディタはそれを知らない
    // （`--fs-allow`はharnessの起動ごとの指定で、書く時点では原理的に分からない）。
    // したがって固定した遷移は、ここを通っても`harness.exe`の起動時に初めて拒否されることがある
    // （残課題 サンドボックス周辺 #65。`policy_file::load_for_session`のdoc）。
    // **このエディタが書く辺は固定した遷移にならない**（`cwd`を宣言しない。[`edge_for`]）ので、
    // 足した辺がそれで落ちることは無い（試験`an_edge_this_editor_writes_survives_the_writable_places_harness_adds`）。
    let workspace = req.workspace_root.to_string_lossy();
    let input = file.transition_graph_input(Some(workspace.as_ref()), &[]);
    let rejected = match transition::check_all(&input) {
        Ok(rejections) => rejections.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
        Err(e) => vec![e.to_string()],
    };
    if !rejected.is_empty() {
        let detail = rejected.join("\n");
        // 足した辺が「広げる遷移」だったなら、このエディタで取れる直し方を言い直す（変種のdoc）。
        let widens = added_indices.iter().any(|index| {
            matches!(
                transition::edge_direction(&input, req.from_domain, *index),
                Ok(Some(transition::Direction::WiderOrUnknown))
            )
        });
        return Err(if widens {
            TransitionApproveError::WidensWithoutFixing { to_domain, detail }
        } else {
            TransitionApproveError::Rejected(detail)
        });
    }

    plan.file = file;
    Ok(plan)
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
