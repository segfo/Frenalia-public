//! 位置ごとのドメインの記録を**1回の確定で書く**（`plans/POLICY-EDITOR-TOMOYO-DIG.md` 決定65、手順は
//! `plans/position-domains/P4.md`の P4.5）。
//!
//! # 何のためにあるのか
//!
//! 位置ごとのドメインの記録を承認すると、書くものは「ドメインごとのファイルの宣言」（承認待ちの FS/ネットのタブ）と
//! 「位置ごとの遷移の辺」（観測のタブ）と、場合によって「エディタが前に書いた自己ループ辺の置き換え」になる。
//! 今までの書く経路は2つ（[`crate::approve::commit`]＝1ドメインのファイルの宣言、[`crate::transition_approve::commit`]＝
//! 1つの遷移元の辺）で、それぞれが`policy.json`を1回ずつ保存する。別々に書くと、片方だけ書けた状態（辺は書けたが
//! ファイルの宣言は断られた、など）が残る。ここは全部を1つの`PolicyFile`に足してから、最後に1回だけ検査・保存する。
//!
//! # 部分適用しない
//!
//! 1件でも書けなければ何も書かない（`crate::approve`・`crate::transition_approve`と同じ判断）。**広がる辺は書ける**
//! （決定66。守る線は子のドメインの権限）——決定65(6) の暫定「広がる辺が1本でもあれば全体を断る」は P5.3 で外した。
//! 代わりに確認の明細に「広がる遷移」と、呼び出し元が子を通して使えるようになる権限を出す（[`PositionPlan::widening`]）。
//! いま書けない辺を作るのは Strict の印（入る辺は引数のリテラルと作業ディレクトリを固定し、それらを呼び出し元が書けない
//! 場所に置く。決定67で位置の木の`s`がその形の辺と印を書くようになった）や相対パスの引数（作業ディレクトリが要る）などで、
//! それが1本でもあれば全体を断る。
//!
//! # 判定は写さない（`B-13`）
//!
//! - ファイルの宣言の検査: [`approve::validate`]（`gate`・`breadth`）をドメインごとに通す
//! - 辺を足す・消す: [`transition_approve::apply_edge_changes`]、書いた後の検査: [`transition_approve::check_added`]
//! - 自己ループ辺の取り除き: [`take_self_loops`]、書いた後の行き先: [`lands_elsewhere`]（承認待ちの位置の行の判定と同じ部品）
//! - 宣言の取り消し: [`crate::unapprove::remove_value`]
//!
//! # 承認台帳は保存の後
//!
//! このマシンでの承認（D-112）は、`policy.json`を保存した**後**に、承認した宣言を全ドメイン分まとめて1回で記録し、
//! 取り消した宣言の承認を消す（`crate::approve::commit`・`crate::unapprove::commit`と同じ順。先に記録して保存が
//! 落ちると、無い宣言の承認が残る）。
//!
//! # 限界
//!
//! - CLI（[`cli_plan`]）はファイルの宣言だけを書き、辺を書かない（CLI に遷移の承認は無い。辺とファイルの宣言を
//!   1つの確認で見せられないので、辺が要るドメインの候補は断る。`plans/position-domains/P4.md`の前例の表の12）。
//! - 台帳への記録は`policy.json`の保存と不可分ではない。保存の後に台帳を書けなければ
//!   [`PositionApproveError::ApprovalNotRecorded`]・[`PositionApproveError::ApprovalNotRevoked`]で言う（成功と言わない）。
//! - **windows専用**: 自己ループ辺の取り除きと行き先の引き直しが[`crate::position_view`]（windows専用）の部品だからである。

use std::collections::BTreeSet;
use std::path::Path;

use harness_change_ledger::path_rules::fold_for_pattern_comparison;
use harness_core::RequireSandbox;
use harness_policy::generalize::SettingsKey;
use harness_policy::policy_file::{
    self, ApprovalContext, MergeReport, PolicyFile, PolicyFileError, ENTRY_DOMAIN,
};
use harness_policy::transition::{ArgvMatcher, ExeMatcher, TransitionEdge, TransitionGraph};
use harness_policy::RuleProposal;
use harness_sandbox::tier2a::policy_approval::DeclarationRef;

use crate::approve::{self, ApproveError, PathClass};
use crate::position_candidates::SessionCandidates;
use crate::position_view::{lands_elsewhere, take_self_loops};
use crate::session_dir::RecordManifest;
use crate::transition_approve::{
    self, apply_edge_changes, check_added, EdgeChanges, EdgeRef, SourcedEdgeRef,
    TransitionApproveError,
};
use crate::transition_candidates::Startable;
use crate::unapprove::{remove_value, UnapproveTarget};

/// 1つのドメインへ書くファイルの宣言（`accept_ids`が`proposals`から選ぶ。[`approve::validate`]へそのまま渡す）。
#[derive(Debug, Clone)]
pub struct DomainSelection {
    pub domain: String,
    pub proposals: Vec<RuleProposal>,
    pub accept_ids: Vec<String>,
}

/// （ドメイン, 提案）の組を、ドメインごとの選択にまとめる（全部を承認する。並びはドメインに初めて出る順）。
/// 画面の確定と CLI が同じこれを通す。
pub fn group_by_domain(
    items: impl IntoIterator<Item = (String, RuleProposal)>,
) -> Vec<DomainSelection> {
    let mut out: Vec<DomainSelection> = Vec::new();
    for (domain, proposal) in items {
        let index = match out.iter().position(|s| s.domain == domain) {
            Some(index) => index,
            None => {
                out.push(DomainSelection {
                    domain,
                    proposals: Vec::new(),
                    accept_ids: Vec::new(),
                });
                out.len() - 1
            }
        };
        out[index].accept_ids.push(proposal.id.clone());
        out[index].proposals.push(proposal);
    }
    out
}

/// 足す辺1本（形は[`harness_policy::transition::editor_edge`]で作ったもの）。
#[derive(Debug, Clone)]
pub struct EdgeWrite {
    pub from_domain: String,
    pub edge: TransitionEdge,
    /// 遷移元の自己ループ辺（リテラルの exe が同じもの）を取り除いてから足す
    /// （`harness_policy::position_domains::PositionSource::ReplacesSelfLoop`）。
    pub replaces_self_loop: bool,
    /// 遷移先のドメインに Strict の印を付ける（決定67。位置の木の`s`の行）。辺は引数のリテラルと作業ディレクトリを
    /// 持つ形で来る——満たさなければ書いた後の検査（規則(e)(i)）が全体を断る。
    pub strict: bool,
}

/// 1回の確定の要求。
pub struct PositionRequest<'a> {
    pub workspace_root: &'a Path,
    pub require_sandbox: RequireSandbox,
    /// 記録したコマンド・作業ディレクトリ・記録セッション（ファイルの宣言を書く各ドメインの由来に残す）。
    pub command: Option<&'a str>,
    pub cwd: Option<&'a Path>,
    pub record_session: Option<&'a str>,
    pub now_unix_ms: u64,
    pub fs: Vec<DomainSelection>,
    pub edges: Vec<EdgeWrite>,
    /// 消す辺（遷移元, [`EdgeRef`]）。承認待ちの遷移タブの取り消しの予約と同じ指し方（`policy.json`に書かれている
    /// 綴りを畳んで比べる）。
    pub remove_edges: Vec<SourcedEdgeRef>,
    /// 取り消すファイル・通信の宣言（チェックを外したもの）。
    pub unapprove: Vec<UnapproveTarget>,
    /// 確定のダイアログで自己ループ辺の置き換えを見せ、ユーザーが`y`を押したときだけ`true`（決定65 Q7・D-42）。
    pub replace_self_loops: bool,
}

/// 受理したファイルの宣言1件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedFs {
    pub id: String,
    pub key: SettingsKey,
    pub value: String,
    pub class: PathClass,
}

/// 1つのドメインへ書くファイルの宣言の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainFs {
    pub domain: String,
    pub report: MergeReport,
    pub accepted: Vec<AcceptedFs>,
}

/// 書く前に決まったこと一式。**「足した」と「元からあった」、「消した」と「元から無かった」を区別する**（`B-09`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PositionPlan {
    /// 書き込む予定の内容（[`commit`]がそのまま保存する）。
    pub file: PolicyFile,
    pub fs: Vec<DomainFs>,
    /// 拒否ではないが読んでおくべきこと（`[<ドメイン>]`を頭に付ける）。
    pub warnings: Vec<String>,
    pub edges_added: Vec<(String, TransitionEdge)>,
    /// 足そうとしたが同じ辺が既にあった。
    pub already_declared: Vec<(String, TransitionEdge)>,
    pub self_loops_replaced: Vec<(String, TransitionEdge)>,
    pub edges_removed: Vec<SourcedEdgeRef>,
    pub edges_not_found: Vec<SourcedEdgeRef>,
    pub unapproved: Vec<UnapproveTarget>,
    pub unapprove_not_found: Vec<UnapproveTarget>,
    /// `policy.json`に無かったので宣言の無いドメインとして作るもの（名前の順）。
    pub created_domains: Vec<String>,
    /// Strict の印を付けるドメイン（名前の順。決定67）。
    pub strict_marked: Vec<String>,
    /// この確定で広がる遷移（足す辺と、ファイルの宣言の承認・取り消しで渡す権限が増える既存の辺。決定66）。
    /// [`confirmation_lines`]が[`crate::exposure_view::lines`]で並べる。
    pub widening: crate::exposure_view::Widening,
}

impl PositionPlan {
    /// 書く必要が無い（`policy.json`が1つも変わらない）。
    pub fn is_empty(&self) -> bool {
        self.fs.iter().all(|d| d.report.is_empty())
            && self.edges_added.is_empty()
            && self.self_loops_replaced.is_empty()
            && self.edges_removed.is_empty()
            && self.unapproved.is_empty()
            && self.strict_marked.is_empty()
    }

    /// 保存の後に承認台帳へ記録するファイルの宣言（受理した値をドメインごとに。通信の宣言は台帳の対象外）。
    pub fn declarations(&self) -> Vec<DeclarationRef<'_>> {
        self.fs
            .iter()
            .flat_map(|d| {
                d.accepted.iter().filter_map(move |a| {
                    a.key.fs_access().map(|access| DeclarationRef {
                        domain: &d.domain,
                        value: &a.value,
                        access,
                    })
                })
            })
            .collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PositionApproveError {
    #[error(transparent)]
    Approve(#[from] ApproveError),
    #[error(transparent)]
    Transition(#[from] TransitionApproveError),
    #[error(
        "遷移元「{from}」の自己ループ辺を置き換える確定です。確認の画面で置き換えを読んでから y を押してください\
         （何も書いていません）"
    )]
    SelfLoopNeedsConfirmation { from: String },
    #[error(
        "遷移元「{from}」の自己ループ辺はパターンなので、置き換えるとこの記録に無いプログラムも起こせなくなります。\
         宣言画面（F3）の遷移タブで直してください（何も書いていません）"
    )]
    PatternSelfLoop { from: String },
    /// 書いた後の宣言で、足した辺の起動が辺の遷移先に着かない（既にあるパターンの辺と重なる等）。
    #[error("{from} から {exe} を起こす辺: {actual}。何も書いていません")]
    ResolvesElsewhere {
        from: String,
        exe: String,
        actual: String,
    },
    #[error(
        "ドメイン「{domain}」へ届く辺がこの確定にも policy.json にも無いので、ファイルの宣言を書けません\
         （何も書いていません）"
    )]
    MissingEdgeForDomain { domain: String },
    #[error(
        "位置ごとのドメインの記録は、候補ごとに書く先のドメインが決まっています。--domain は付けないでください\
         （何も書いていません）"
    )]
    DomainFlagWithPositions,
    #[error(
        "次の候補のドメインはまだ policy.json に無く、そこへ届く遷移の辺も要ります。CLI は遷移の辺を書かないので、\
         TUI（F2）で遷移と一緒に承認してください（何も書いていません）: {candidates}"
    )]
    NeedsTransition { candidates: String },
    #[error(transparent)]
    PolicyFile(#[from] PolicyFileError),
    /// `policy.json`は書けたが、このマシンでの承認（D-112）を台帳へ記録できなかった。**成功と言わない。**
    #[error(
        "policy.json には書きましたが、このマシンでの承認を台帳へ記録できませんでした: {0}\n\
         これらの宣言は、承認し直すまで許可が付きません（台帳: %APPDATA%\\harness\\config\\policy-approval-ledger.json）"
    )]
    ApprovalNotRecorded(String),
    /// `policy.json`からは消したが、このマシンでの承認を台帳から消せなかった。
    #[error(
        "policy.json からは消しましたが、このマシンでの承認を台帳から消せませんでした: {0}\n\
         同じ値が後で policy.json に戻ると承認済みとして扱われます（台帳: %APPDATA%\\harness\\config\\policy-approval-ledger.json）"
    )]
    ApprovalNotRevoked(String),
}

/// 何を書くかを決める（**何も書かない**）。手順は`plans/position-domains/P4.md`の P4.5 Step 2 の順。
pub fn plan(req: &PositionRequest<'_>) -> Result<PositionPlan, PositionApproveError> {
    let selects_fs = req.fs.iter().any(|s| !s.accept_ids.is_empty());
    if !selects_fs
        && req.edges.is_empty()
        && req.remove_edges.is_empty()
        && req.unapprove.is_empty()
    {
        return Err(TransitionApproveError::NothingSelected.into());
    }
    // (1) 足す辺の、自己ループ辺（凍結中、決定65(3)）と入れ物の名前にできない遷移先は書く前に断る
    // （`transition_approve::plan`の事前の検査と同じ変種・同じ関数）。
    for write in &req.edges {
        if write.edge.to == write.from_domain {
            return Err(TransitionApproveError::SelfLoopFrozen {
                domain: write.from_domain.clone(),
            }
            .into());
        }
        if let Some(reason) = harness_sandbox::tier2a::domain_profile_name_problem(&write.edge.to) {
            return Err(TransitionApproveError::DestinationName {
                to_domain: write.edge.to.clone(),
                reason,
            }
            .into());
        }
    }
    // (2) ドメインごとのファイルの宣言の検査（何も読まない）。
    let mut validated = Vec::new();
    for selection in req.fs.iter().filter(|s| !s.accept_ids.is_empty()) {
        let checked = approve::validate(
            &selection.proposals,
            &selection.accept_ids,
            req.require_sandbox,
            req.workspace_root,
        )?;
        validated.push((selection, checked));
    }
    // 自己ループ辺の置き換えは、ユーザーが確認の画面で読んだときだけ（決定65 Q7）。
    if let Some(write) = req.edges.iter().find(|w| w.replaces_self_loop) {
        if !req.replace_self_loops {
            return Err(PositionApproveError::SelfLoopNeedsConfirmation {
                from: write.from_domain.clone(),
            });
        }
    }

    // (3) 読むのは1回。
    let mut file = policy_file::load(req.workspace_root)?;
    let before = file.clone();
    let known_before: BTreeSet<String> = file.domains.iter().map(|d| d.name.clone()).collect();

    // (4) 取り消し（遷移元ごと。足すより先——同じ辺を消してから違う形で足し直せる）。
    let (mut edges_removed, mut edges_not_found) = (Vec::new(), Vec::new());
    for from in distinct(req.remove_edges.iter().map(|(from, _)| from.as_str())) {
        let refs: Vec<EdgeRef> = req
            .remove_edges
            .iter()
            .filter(|(f, _)| f == from)
            .map(|(_, r)| r.clone())
            .collect();
        // 無い遷移元のために空のドメインを作らない（`apply_edge_changes`は遷移元を作る）。
        if file.domain(from).is_none() {
            edges_not_found.extend(refs.into_iter().map(|r| (from.to_string(), r)));
            continue;
        }
        let report = apply_edge_changes(
            &mut file,
            &EdgeChanges {
                from_domain: from,
                add: &[],
                remove: &refs,
                record_session: req.record_session,
                now_unix_ms: req.now_unix_ms,
            },
        );
        edges_removed.extend(report.removed.into_iter().map(|r| (from.to_string(), r)));
        edges_not_found.extend(report.not_found.into_iter().map(|r| (from.to_string(), r)));
    }

    // (5) 置き換える自己ループ辺を取り除く（取り除かないと同じ実行ファイルに2本当たる。P3b の注意1）。
    let mut self_loops_replaced = Vec::new();
    let mut taken: BTreeSet<(String, String)> = BTreeSet::new();
    for write in req.edges.iter().filter(|w| w.replaces_self_loop) {
        let exe = matcher_text(&write.edge.exe);
        if !taken.insert((write.from_domain.clone(), fold_for_pattern_comparison(exe))) {
            continue;
        }
        let removed = take_self_loops(&mut file, &write.from_domain, exe);
        if removed.is_empty() {
            // リテラルの自己ループ辺が無い。パターンの自己ループ辺が残っているなら置き換えない（取り除くと記録に無い
            // プログラムも起こせなくなる）。どちらも無いなら（ダイアログを見ている間に消えた等）、普通に足すだけ。
            if has_pattern_self_loop(&file, &write.from_domain) {
                return Err(PositionApproveError::PatternSelfLoop {
                    from: write.from_domain.clone(),
                });
            }
            continue;
        }
        self_loops_replaced.extend(removed.into_iter().map(|e| (write.from_domain.clone(), e)));
    }

    // (6) 辺を遷移元ごとに足す。
    let (mut edges_added, mut already_declared) = (Vec::new(), Vec::new());
    let mut created_domains: Vec<String> = Vec::new();
    for from in distinct(req.edges.iter().map(|w| w.from_domain.as_str())) {
        let add: Vec<TransitionEdge> = req
            .edges
            .iter()
            .filter(|w| w.from_domain == from)
            .map(|w| w.edge.clone())
            .collect();
        let report = apply_edge_changes(
            &mut file,
            &EdgeChanges {
                from_domain: from,
                add: &add,
                remove: &[],
                record_session: req.record_session,
                now_unix_ms: req.now_unix_ms,
            },
        );
        for (j, edge) in add.into_iter().enumerate() {
            if report.already_declared.contains(&j) {
                already_declared.push((from.to_string(), edge));
            } else {
                edges_added.push((from.to_string(), edge));
            }
        }
        created_domains.extend(report.created_domains);
    }
    // (6b) Strict の印（決定67。位置の木の`s`）。遷移先のドメインは辺を足したときに作られるので、その後で付ける。
    // 印の付いたドメインへ入る辺の検査（規則(e)(i)）は (9) の1回の検査が掛ける。
    let mut strict_marked: Vec<String> = Vec::new();
    for write in req.edges.iter().filter(|w| w.strict) {
        if let Some(domain) = file.domains.iter_mut().find(|d| d.name == write.edge.to) {
            if !domain.strict {
                domain.strict = true;
                strict_marked.push(domain.name.clone());
            }
        }
    }
    strict_marked.sort();

    // (7) ファイルの宣言をドメインごとに。**届く辺の無いドメインには書かない**——入口のドメイン・元からあるドメイン・
    // この確定の後に辺の遷移先になっているドメインだけ。
    let mut fs = Vec::new();
    let mut warnings = Vec::new();
    for (selection, checked) in &validated {
        let domain = selection.domain.as_str();
        let reachable = domain == ENTRY_DOMAIN
            || known_before.contains(domain)
            || file
                .domains
                .iter()
                .any(|d| d.process.transitions.iter().any(|e| e.to == domain));
        if !reachable {
            return Err(PositionApproveError::MissingEdgeForDomain {
                domain: domain.to_string(),
            });
        }
        let report = file.merge_approved(
            &checked.accepted,
            &ApprovalContext {
                domain,
                command: req.command,
                cwd: req.cwd,
                record_session: req.record_session,
                now_unix_ms: req.now_unix_ms,
            },
        );
        if report.created_domain {
            created_domains.push(domain.to_string());
        }
        warnings.extend(checked.warnings.iter().map(|w| format!("[{domain}] {w}")));
        warnings.extend(
            approve::grant_root_warnings(&file, domain, req.workspace_root, &checked.accepted)
                .into_iter()
                .map(|w| format!("[{domain}] {w}")),
        );
        fs.push(DomainFs {
            domain: domain.to_string(),
            report,
            accepted: checked
                .accepted
                .iter()
                .zip(&checked.classes)
                .map(|(p, class)| AcceptedFs {
                    id: p.id.clone(),
                    key: p.key,
                    value: p.value.clone(),
                    class: *class,
                })
                .collect(),
        });
    }

    // (8) 宣言の取り消し（承認の後——逆順だと、今回外したものを承認が書き戻しうる。`tui::edit_commit`と同じ順）。
    let (mut unapproved, mut unapprove_not_found) = (Vec::new(), Vec::new());
    for target in &req.unapprove {
        let removed = file
            .domains
            .iter_mut()
            .find(|d| d.name == target.domain)
            .is_some_and(|d| remove_value(d, target.key, &target.value));
        if removed {
            unapproved.push(target.clone());
        } else {
            unapprove_not_found.push(target.clone());
        }
    }

    // (9) 全部を足した後で1回だけ検査する。書けない辺（Strict のドメインへ入る辺など）が1本でもあれば全体を断る。
    // 広がる辺は書ける（決定66）ので、ここでは断らずに明細の材料（`widening`）にする。
    check_added(&file, req.workspace_root)?;

    // (10) 書いた後の判定器で、足した辺の起動が辺の遷移先に着くかを引き直す（P3b の注意2）。
    if !edges_added.is_empty() {
        let workspace = req.workspace_root.to_string_lossy();
        let input = file.transition_graph_input(Some(workspace.as_ref()), &[]);
        let graph = TransitionGraph::build(&input)
            .map_err(|e| TransitionApproveError::Rejected(e.to_string()))?;
        for (from, edge) in &edges_added {
            if let Some(actual) = lands_elsewhere(&graph, from, edge, &workspace) {
                return Err(PositionApproveError::ResolvesElsewhere {
                    from: from.clone(),
                    exe: matcher_text(&edge.exe).to_string(),
                    actual,
                });
            }
        }
    }

    created_domains.sort();
    created_domains.dedup();
    let widening = crate::exposure_view::widening(&before, &file, req.workspace_root);
    Ok(PositionPlan {
        widening,
        file,
        fs,
        warnings,
        edges_added,
        already_declared,
        self_loops_replaced,
        edges_removed,
        edges_not_found,
        unapproved,
        unapprove_not_found,
        created_domains,
        strict_marked,
    })
}

/// 決まった内容を書く。**`save`を呼ぶのは1回だけ**（遷移元・ドメインが何個でも）。`false`は「書く必要が無かった」（`B-09`）。
///
/// `save`は本番では[`policy_file::save`]（書く前に遷移の検査を掛ける）。試験は呼ばれた回数を数える
/// （`plans/position-domains/P4.md`の前例の表の11）。台帳はその後に1回ずつ（承認・取り消し）。
pub fn commit(
    workspace_root: &Path,
    plan: &PositionPlan,
    save: &dyn Fn(&Path, &PolicyFile) -> Result<(), PolicyFileError>,
) -> Result<bool, PositionApproveError> {
    if plan.is_empty() {
        return Ok(false);
    }
    save(workspace_root, &plan.file)?;
    let store = crate::approval_store::approval_store();
    let declarations = plan.declarations();
    let not_recorded = if declarations.is_empty() {
        Vec::new()
    } else {
        store.approve(workspace_root, &declarations)
    };
    let revoked: Vec<DeclarationRef<'_>> = plan
        .unapproved
        .iter()
        .filter_map(UnapproveTarget::declaration)
        .collect();
    let left = if revoked.is_empty() {
        Vec::new()
    } else {
        store.revoke(workspace_root, &revoked)
    };
    if !not_recorded.is_empty() {
        return Err(PositionApproveError::ApprovalNotRecorded(describe(
            &not_recorded,
        )));
    }
    if !left.is_empty() {
        return Err(PositionApproveError::ApprovalNotRevoked(describe(&left)));
    }
    Ok(true)
}

/// CLI の`approve`（位置の情報がある記録）。候補ごとのドメインへ**ファイルの宣言だけ**を書く確定を作る
/// （辺は書かない。`plans/position-domains/P4.md`の前例の表の12）。`--domain`（`domain_flag`）は断る——1つのドメインへ
/// 全部書くと、位置ごとに分けた意味が黙って消える。`policy.json`にまだ無いドメイン（辺が要る）の候補も断る。
#[allow(clippy::too_many_arguments)]
pub fn cli_plan(
    workspace_root: &Path,
    manifest: &RecordManifest,
    candidates: &SessionCandidates,
    accept_ids: &[String],
    domain_flag: Option<&str>,
    require_sandbox: RequireSandbox,
    now_unix_ms: u64,
) -> Result<PositionPlan, PositionApproveError> {
    if domain_flag.is_some() {
        return Err(PositionApproveError::DomainFlagWithPositions);
    }
    if accept_ids.is_empty() {
        return Err(ApproveError::NoIds.into());
    }
    let policy = policy_file::load(workspace_root)?;
    let (mut chosen, mut unknown, mut needs) = (Vec::new(), Vec::new(), Vec::new());
    for id in accept_ids {
        let found = candidates
            .proposals
            .iter()
            .zip(&candidates.domains)
            .find(|(p, _)| &p.id == id);
        let Some((proposal, Some(domain))) = found else {
            unknown.push(id.as_str());
            continue;
        };
        if domain != ENTRY_DOMAIN && policy.domain(domain).is_none() {
            needs.push(format!("{id} [{domain}]"));
            continue;
        }
        chosen.push((domain.clone(), proposal.clone()));
    }
    if !unknown.is_empty() {
        return Err(ApproveError::UnknownIds(unknown.join(", ")).into());
    }
    if !needs.is_empty() {
        return Err(PositionApproveError::NeedsTransition {
            candidates: needs.join(", "),
        });
    }
    plan(&PositionRequest {
        workspace_root,
        require_sandbox,
        command: Some(&manifest.command),
        cwd: Some(&manifest.cwd),
        record_session: Some(&manifest.id),
        now_unix_ms,
        fs: group_by_domain(chosen),
        edges: Vec::new(),
        remove_edges: Vec::new(),
        unapprove: Vec::new(),
        replace_self_loops: false,
    })
}

/// 確認の明細（画面のダイアログと CLI が同じこれを出す）。**判断材料を先に、明細を後に**——マシンに残る変更 → 作る
/// ドメイン → 置き換える自己ループ辺 → ドメインごとのファイルの宣言 → 遷移元ごとの辺 → 取り消し → ACL の注記
/// （`tui::edit_commit`の`request_approval`と同じ作法）。`hand_changed`は手で access を変えた候補の id。
pub fn confirmation_lines(
    workspace_root: &Path,
    plan: &PositionPlan,
    hand_changed: &BTreeSet<String>,
) -> Vec<String> {
    let mut lines = vec![format!("{}:", policy_file::path(workspace_root).display())];
    let accepted: Vec<(&str, &AcceptedFs)> = plan
        .fs
        .iter()
        .flat_map(|d| d.accepted.iter().map(move |a| (d.domain.as_str(), a)))
        .collect();
    if !accepted.is_empty() {
        // **承認の実質的な判断材料**: 実際にマシンのACLを変えるのはworkspace外の分だけ。
        let outside: Vec<&(&str, &AcceptedFs)> = accepted
            .iter()
            .filter(|(_, a)| a.class == PathClass::OutsideWorkspace)
            .collect();
        let inside = accepted
            .iter()
            .filter(|(_, a)| a.class == PathClass::InsideWorkspace)
            .count();
        lines.push(String::new());
        if inside > 0 {
            lines.push(format!(
                "  workspace配下 {inside}件: Tier2aのworkspace許可が既に覆うため、ACEの追加は要りません"
            ));
        }
        if outside.is_empty() {
            lines.push("  workspace外: なし（このマシンのACLは変わりません）".to_string());
        } else {
            lines.push(format!(
                "  workspace外 {}件: パス2がこのルートへ実際にACEを付けます——**マシンに残る変更**です",
                outside.len()
            ));
            for (domain, a) in &outside {
                lines.push(format!("    [{domain}] {}", a.value));
            }
        }
        let changed: Vec<&(&str, &AcceptedFs)> = accepted
            .iter()
            .filter(|(_, a)| hand_changed.contains(&a.id))
            .collect();
        if !changed.is_empty() {
            lines.push(format!(
                "  手で access を変えた候補 {}件（観測ではなくあなたの判断です）:",
                changed.len()
            ));
            for (domain, a) in &changed {
                lines.push(format!("    [{domain}] {}", a.value));
            }
        }
    }
    for warning in &plan.warnings {
        lines.push(format!("  ! {warning}"));
    }
    // **広がる遷移は判断材料**（書くと呼び出し元の手に何が渡るか）なので、明細より先に出す。
    lines.extend(crate::exposure_view::lines(&plan.widening));
    if !plan.created_domains.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "作るドメイン {}個（policy.json に無いので、宣言の無いドメインとして作ります）: {}",
            plan.created_domains.len(),
            plan.created_domains.join(", ")
        ));
    }
    if !plan.strict_marked.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "Strict の印を付けるドメイン {}個（入る辺は引数・作業ディレクトリを固定し、標準入力を断ち、環境変数は harness の\
             基準の値から始めます——決定66の追記）: {}",
            plan.strict_marked.len(),
            plan.strict_marked.join(", ")
        ));
    }
    if !plan.self_loops_replaced.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "置き換える自己ループ辺 {}本（エディタが前に書いたもの。確定すると消え、位置の辺に置き換わります——決定65）:",
            plan.self_loops_replaced.len()
        ));
        for (from, edge) in &plan.self_loops_replaced {
            lines.push(format!("  - {from} の {}", edge_label(edge)));
        }
    }
    for d in plan.fs.iter().filter(|d| !d.report.added.is_empty()) {
        lines.push(String::new());
        lines.push(format!(
            "ファイルの宣言: ドメイン {}{}",
            d.domain,
            if plan.created_domains.contains(&d.domain) {
                "（新規）"
            } else {
                ""
            }
        ));
        lines.extend(approve::group_by_key(
            &d.report.added,
            &d.report.already_present,
        ));
    }
    for from in distinct(plan.edges_added.iter().map(|(from, _)| from.as_str())) {
        lines.push(String::new());
        lines.push(format!("遷移元ドメイン {from}:"));
        for (_, edge) in plan.edges_added.iter().filter(|(f, _)| f == from) {
            lines.push(format!("  + {}", edge_label(edge)));
            // **書く直前に、その綴りが起こせないことを言う**（取り消しの効かない操作の直前）。
            if let Some(note) = Startable::of(matcher_text(&edge.exe)).note() {
                lines.push(format!("      ⚠ {note}"));
            }
            // [P5.10.2] 作業ディレクトリを宣言した辺は、呼び出し元がその場所から呼ばないと断られる（決定67(4)）。
            if let Some(cwd) = &edge.cwd {
                lines.push(format!("      {}", cwd_notice(cwd)));
            }
        }
    }
    if !plan.edges_removed.is_empty() {
        lines.push(String::new());
        lines.push(format!("取り消す遷移 {}件:", plan.edges_removed.len()));
        for (from, target) in &plan.edges_removed {
            lines.push(format!(
                "  - [{from}] {} {}",
                target.exe,
                target.argv.display()
            ));
        }
    }
    if !plan.unapproved.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "取り消す宣言 {}件（チェックを外した分）:",
            plan.unapproved.len()
        ));
        for target in &plan.unapproved {
            lines.push(format!(
                "    - [{}] {} {}",
                target.domain,
                target.key.dotted(),
                target.value
            ));
        }
    }
    let unchanged_edges = plan.already_declared.len();
    let not_found = plan.edges_not_found.len() + plan.unapprove_not_found.len();
    if unchanged_edges > 0 || not_found > 0 {
        lines.push(String::new());
    }
    if unchanged_edges > 0 {
        lines.push(format!(
            "既に宣言されていて増えない遷移: {unchanged_edges}件"
        ));
    }
    if not_found > 0 {
        lines.push(format!("宣言に無くて消えないもの: {not_found}件"));
    }
    let edges_change = !plan.edges_added.is_empty()
        || !plan.edges_removed.is_empty()
        || !plan.self_loops_replaced.is_empty();
    if edges_change {
        lines.push(String::new());
        lines.extend(transition_approve::ACE_NOTICE.lines().map(str::to_string));
    }
    if !plan.unapproved.is_empty() {
        lines.push(String::new());
        lines.extend(crate::unapprove::ACE_NOTICE.lines().map(str::to_string));
    }
    lines
}

/// 作業ディレクトリを宣言した辺の注意（確認の明細。決定67(4)・`plans/DESIGN-MAC-ENFORCEMENT.md` §8.3）。
pub(crate) fn cwd_notice(cwd: &str) -> String {
    format!(
        "作業ディレクトリ {cwd} を宣言します——呼び出し元はこの場所へ移ってから呼ぶ必要があります\
         （違う場所からの呼び出しは cwd_mismatch で断られます）"
    )
}

/// 辺1本の綴り（`<exe> <引数> → <遷移先>`）。
fn edge_label(edge: &TransitionEdge) -> String {
    let argv = match &edge.argv {
        ArgvMatcher::Any(_) => harness_policy::transition_listing::ANY_ARGV,
        ArgvMatcher::Literal(value) | ArgvMatcher::Pattern(value) => value.as_str(),
    };
    format!(
        "{} {argv} → {}{}",
        matcher_text(&edge.exe),
        edge.to,
        crate::exposure_view::output_suffix(edge.output)
    )
}

fn matcher_text(exe: &ExeMatcher) -> &str {
    match exe {
        ExeMatcher::Literal(value) | ExeMatcher::Pattern(value) => value,
    }
}

/// `from`にパターンの自己ループ辺があるか。
fn has_pattern_self_loop(file: &PolicyFile, from: &str) -> bool {
    file.domain(from).is_some_and(|d| {
        d.process
            .transitions
            .iter()
            .any(|e| e.to == from && matches!(e.exe, ExeMatcher::Pattern(_)))
    })
}

/// 初めて出る順に重複を除く。
fn distinct<'a>(names: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    let mut out: Vec<&str> = Vec::new();
    for name in names {
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// 台帳へ書けなかった宣言の綴り（`crate::approve::commit`と同じ形）。
fn describe(declarations: &[DeclarationRef<'_>]) -> String {
    declarations
        .iter()
        .map(|d| format!("{} ({}) in {}", d.value, d.access.settings_key(), d.domain))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
#[path = "position_approve_tests.rs"]
mod position_approve_tests;
