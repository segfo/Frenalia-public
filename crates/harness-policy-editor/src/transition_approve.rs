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

use std::path::Path;

use harness_change_ledger::path_rules::fold_for_pattern_comparison;
use harness_policy::policy_file::{self, PolicyDomain, PolicyFile, PolicyFileError};
use harness_policy::transition::{self, AnyMarker, ArgvMatcher, ExeMatcher, TransitionEdge};

/// 取り消しがACLに何をするのかの説明。**この文言の持ち主はここだけ**（CLIもTUIもこれを出す）。
///
/// FS宣言の承認と見た目が同じなので、**何も起きないことを言わないと**「ACLが変わった」と
/// 読まれる（決定18: ACEを付ける経路は`preflight`ただ1つ）。
pub const ACE_NOTICE: &str = concat!(
    "注: 遷移の宣言はファイルやネットワークの許可とは別物で、実マシンのACLは変わりません。\n",
    "    変わるのは「このプログラムを起こしてよいか」だけです。"
);

/// 自己ループにしか宣言できないことの説明。**暫定**（下記[`provisional_destination`]）。
///
/// # いつ消えるか
///
/// §22.9（ドメインごとのプロファイル発行器）が着地した日。
/// この定数を消すと、参照している画面がコンパイルできなくなる。
pub const SELF_LOOP_NOTICE: &str = concat!(
    "注: いまは「同じドメインの中で起こす」宣言しか書けません（暫定）。\n",
    "    代償が3つあります——(1) 以降の深さを区別できなくなる (2) 同じドメインのプロセスは\n",
    "    互いにコードを注入できる (3) 連鎖の深さに上限が無くなる（止められるのは取り消しと\n",
    "    時間切れだけ）。別ドメインへ分ける宣言は、その実体を作る機構が入ってから書けます。"
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

/// **【暫定】この辺の遷移先。いまは必ず呼び出し元と同じドメイン（自己ループ）である。**
///
/// # なぜ選べないのか
///
/// 別のドメインで起こすには、そのドメインの`(package SID, capability SIDの組)`が要る。
/// 今日プロファイルを作る機構はセッション単位とMCPサーバ単位の2つだけで、
/// **ドメインを鍵にした発行器が無い**（`plans/DESIGN-MAC-BROKER.md` §22.9）。
/// だから別ドメイン宛の辺は宣言できても**Daemonが`TargetDomainNotProvisioned`で断る**
/// ——「書けるのに一度も通らない辺」を作らせないために、ここで自己ループへ倒す。
///
/// # いつ・どうやって消すのか
///
/// §22.9が着地した日に**この関数ごと**消す。
/// `plans/DESIGN-MAC-ENFORCEMENT.md` §10.1.2の「まとめて消す」一覧の**6つ目**に載せてある。
///
/// **消す作業は小さい。** 辺を組む[`edge_for`]は遷移先を**引数で**受けるので、
/// この関数を消して呼び出し元（1箇所）が選んだ値を渡すだけになる。
/// あわせて[`SELF_LOOP_NOTICE`]と、それを固定している試験
/// `only_self_loop_edges_are_written_today`を消すこと。
fn provisional_destination(from_domain: &str) -> String {
    from_domain.to_string()
}

/// 辺を1本組み立てる。**遷移先は引数で受ける**（暫定を埋め込まない。上記）。
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
    /// 足す辺の遷移先。**【暫定】いまは遷移元と同じ**（[`provisional_destination`]）。
    pub to_domain: String,
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
    let mut file = policy_file::load(req.workspace_root)?;
    if file.domain(req.from_domain).is_none() {
        file.domains.push(PolicyDomain::new(req.from_domain));
        file.domains.sort_by(|a, b| a.name.cmp(&b.name));
    }
    let to_domain = provisional_destination(req.from_domain);

    let mut plan = TransitionPlan {
        file: PolicyFile::default(),
        added: Vec::new(),
        already_declared: Vec::new(),
        removed: Vec::new(),
        not_found: Vec::new(),
        to_domain: to_domain.clone(),
    };

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

    // **書く前に検査する。** ここで落ちれば`policy.json`は元のままである。
    //
    // **`policy.json`の外で書込を許した場所は空で渡す**——エディタはそれを知らない
    // （`--fs-allow`はharnessの起動ごとの指定で、書く時点では原理的に分からない）。
    // したがって固定した遷移は、ここを通っても`harness.exe`の起動時に初めて拒否されることがある
    // （残課題 サンドボックス周辺 #65。`policy_file::load_for_session`のdoc）。
    let workspace = req.workspace_root.to_string_lossy();
    let input = file.transition_graph_input(Some(workspace.as_ref()), &[]);
    let rejected = match transition::check_all(&input) {
        Ok(rejections) => rejections.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
        Err(e) => vec![e.to_string()],
    };
    if !rejected.is_empty() {
        return Err(TransitionApproveError::Rejected(rejected.join("\n")));
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
