//! 記録したプロセスの木（`process-audit.jsonl`）から、承認待ち（`F2`）の「遷移・観測から」に出す**位置の木**を作る
//! （`plans/POLICY-EDITOR-TOMOYO-DIG.md` 決定65、手順は`plans/position-domains/P4.md`の P4.3）。
//!
//! # 何のためにあるのか
//!
//! P4.8 まであった平らな観測の一覧は（親の exe, 子の exe, 引数）でまとめるだけで深さが無く、どの位置に
//! どのドメインを割り当てるかを見せられなかった（決定65の困りごと2）。パス1の記録は記録セッションのディレクトリに
//! プロセスの木を持つので、位置ごとの遷移先（`harness_policy::position_domains::assign_domains`の答え）を
//! 木の形に並べ、各位置の辺を書けるかを判定器に聞いておく。画面（`tui::transition_positions`）は並べて
//! 予約を持つだけにする。
//!
//! # 判定はしない（`B-13`）
//!
//! - 位置の割り当て: [`assign_domains`]（Spawn Daemon と同じ判定器で既にある辺を引く）
//! - 書けるか: [`transition::check_all`]・[`transition::edge_direction`]・[`TransitionGraph::resolve`]に聞く
//!   （[`verdicts`]）。相対パスの引数・広げる向きをここで判定し直さない
//! - 辺を足す: [`crate::transition_approve::apply_edge_changes`]（遷移タブの承認と同じ部品）
//!
//! # 限界
//!
//! - [`verdicts`]は**表示のための見込み**である。最後に書けるかを決めるのは確定（P4.5 の`position_approve`）で、
//!   そこでは選んだものだけを足して検査し直す。
//! - 位置の情報が無い記録（パス2・2026-10-05より前の記録）は`None`を返す——画面は平らな一覧で見せる（決定65の細目6）。
//! - `#[cfg(windows)]`の下にある: 行ごとの[`Startable`]（ストアアプリの仕組みを通る綴りか）が
//!   `crate::transition_candidates`の型だからである（P4.md は付けないと書いていたが、型の置き場に合わせた）。

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use harness_change_ledger::path_rules::fold_for_pattern_comparison;
use harness_config::FsAccess;
use harness_policy::policy_file::{PolicyDomain, PolicyFile, ENTRY_DOMAIN};
use harness_policy::position_domains::{
    assign_domains, AssignError, Assignment, EdgeToAdd, Position, PositionSource, Unassigned,
};
use harness_policy::process_event::{parse_process_audit, ProcessAuditError};
use harness_policy::process_tree::walk;
use harness_policy::transition::{
    self, editor_edge, AnyMarker, ArgvMatcher, Direction, ExeMatcher, Resolution, SpawnAttempt,
    TransitionGraph,
};

use crate::session_dir::{RecordManifest, RecordSessionDir};
use crate::transition_approve::{apply_edge_changes, EdgeChanges};
use crate::transition_candidates::Startable;

/// 1つの記録の位置の木。
#[derive(Debug, Clone)]
pub struct PositionView {
    /// どの記録から作ったか（見出しに出す。記録を替えたら予約を捨てる目印にもなる）。
    pub session_id: String,
    pub assignment: Assignment,
    /// 画面の行（記録した木の順）。
    pub rows: Vec<PositionRow>,
    /// 割り当てなかった起動の理由ごとの件数・読めなかった行・収集器の記録。**黙らせない**（`B-10`）。
    pub notes: Vec<String>,
}

/// 画面の1行＝位置1つ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PositionRow {
    /// [`Assignment::positions`]への添字。
    pub position: usize,
    /// 木の段数（根の子の位置が0）。
    pub depth: usize,
    /// この綴りを遷移の強制を積んだ構成で起こせるか（[`Startable::of`]）。
    pub startable: Startable,
}

/// 位置の同一性＝（割り当てたときの遷移元, 畳んだ exe）。画面の予約（承認する・引数を絞る）はこれで持つ
/// ——遷移先の名前を変えても、指している行は同じだからである。
pub type PositionKey = (String, String);

pub fn key_of(position: &Position) -> PositionKey {
    (
        position.from_domain.clone(),
        fold_for_pattern_comparison(&position.exe),
    )
}

/// 位置の辺を書いたと仮定したときの判定（[`verdicts`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeVerdict {
    /// `policy.json`に既にある辺（書かない）。
    AlreadyDeclared,
    /// 書ける見込み。
    Writable,
    /// 広げる向き（遷移先の権限が呼び出し元より広い、または狭いと証明できない）なので検査に落ちる。
    /// **このエディタは入力（引数と作業ディレクトリ）を固定した辺を書かないので、P5 まで書けない**（決定65(6)）。
    Widens { detail: String },
    /// 広げる以外の理由で書けない（相対パスの引数・書いた後に別の辺に当たる・パターンの自己ループ辺）。
    Rejected { detail: String },
}

impl EdgeVerdict {
    pub fn is_writable(&self) -> bool {
        matches!(self, EdgeVerdict::Writable)
    }

    /// 行と状態の文言に出す一言（書ける・宣言済みなら`None`——宣言済みは出どころの欄が言う）。
    ///
    /// **「P5まで書けません」は暫定の文言**（決定65の寿命）。入力を絞った遷移が入った日に、この文言と
    /// `transition_approve::TransitionApproveError::WidensWithoutFixing`を外す（変種そのものは残る）。
    pub fn note(&self) -> Option<String> {
        match self {
            EdgeVerdict::AlreadyDeclared | EdgeVerdict::Writable => None,
            EdgeVerdict::Widens { .. } => {
                Some("P5まで書けません（遷移先の権限が呼び出し元より広い——決定65(6)）".to_string())
            }
            EdgeVerdict::Rejected { detail } => Some(format!(
                "書けません: {}",
                detail.lines().next().unwrap_or_default()
            )),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PositionViewError {
    #[error("process-audit.jsonl を読めませんでした: {0}")]
    Unreadable(std::io::Error),
    #[error(transparent)]
    Unparsable(ProcessAuditError),
    #[error(transparent)]
    Assign(AssignError),
}

/// 記録の位置の木を作る。**位置の情報が無い記録**（`process-audit.jsonl`が無い——2026-10-05より前のパス1）と
/// **パス2の記録**（パス2は`process-audit.jsonl`を書かない。`record_net`の`capture_argv: false`）は`Ok(None)`。
///
/// 割り当てに渡す作業ディレクトリは記録のワークスペース（記録は作業ディレクトリを観測していない）。
pub fn load(
    dir: &RecordSessionDir,
    manifest: &RecordManifest,
    policy: &PolicyFile,
) -> Result<Option<PositionView>, PositionViewError> {
    if manifest.pass == 2 {
        return Ok(None);
    }
    let text = match std::fs::read_to_string(dir.process_audit_path()) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(PositionViewError::Unreadable(e)),
    };
    let log = parse_process_audit(&text).map_err(PositionViewError::Unparsable)?;
    let assignment = assign_domains(
        &log,
        policy,
        &manifest.workspace_root,
        &harness_sandbox::tier2a::domain_profile_name_problem,
    )
    .map_err(PositionViewError::Assign)?;

    let mut notes = unassigned_notes(&assignment);
    if log.skipped_lines > 0 {
        notes.push(format!(
            "process-audit.jsonl: 読めなかった行が{}行あります（その起動は木に出ていません）",
            log.skipped_lines
        ));
    }
    for reason in &log.controls {
        notes.push(format!("プロセスの木の収集器の記録: {reason}"));
    }
    Ok(Some(PositionView {
        session_id: dir.id().to_string(),
        rows: tree_rows(&assignment),
        assignment,
        notes,
    }))
}

/// 行の順と字下げ。親は「`to_domain`がこの位置の`from_domain`で、1段浅い最初の位置」、遷移元が入口のドメインなら
/// 親なし。**順は[`walk`]が決める**（閉路でも止まり、1件も落とさない）。
fn tree_rows(assignment: &Assignment) -> Vec<PositionRow> {
    let positions = &assignment.positions;
    let nodes: Vec<(usize, Option<usize>)> = positions
        .iter()
        .enumerate()
        .map(|(index, position)| {
            let parent = (position.from_domain != ENTRY_DOMAIN)
                .then(|| {
                    positions.iter().position(|parent| {
                        parent.to_domain == position.from_domain
                            && parent.depth + 1 == position.depth
                    })
                })
                .flatten();
            (index, parent)
        })
        .collect();
    walk(&nodes)
        .into_iter()
        .map(|entry| PositionRow {
            position: entry.key,
            depth: entry.depth,
            startable: Startable::of(&positions[entry.key].exe),
        })
        .collect()
}

/// 割り当てなかった起動を理由ごとに数えて注記にする（§19.3.14「理由別に件数を数えて出す」）。
fn unassigned_notes(assignment: &Assignment) -> Vec<String> {
    let mut counts: BTreeMap<&'static str, (&'static str, usize)> = BTreeMap::new();
    for instance in &assignment.unassigned {
        let entry = counts
            .entry(instance.reason.label())
            .or_insert((unassigned_text(&instance.reason), 0));
        entry.1 += 1;
    }
    counts
        .into_values()
        .map(|(text, count)| format!("{text} {count}件（どの位置にも割り当てていません）"))
        .collect()
}

/// 割り当てなかった理由の日本語。**この表はここ1か所**で、`_`を書かない——[`Unassigned`]に変種が増えたら
/// ここでビルドが落ちる（`B-06`）。
fn unassigned_text(reason: &Unassigned) -> &'static str {
    match reason {
        Unassigned::ParentUnresolved => "親を決められない起動",
        Unassigned::ParentNotRecorded { .. } => "親が記録に無い起動",
        Unassigned::ParentUnassigned => "親を割り当てなかった起動",
        Unassigned::InCycle => "親子の番号が輪になっている起動（記録が壊れている）",
        Unassigned::NoImagePath => "実行ファイルのパスが無い起動",
        Unassigned::NameRefused { .. } => "提案する名前が入れ物の名前の検査を通らない起動",
        Unassigned::ExistingEdgeUnresolvable(_) => "既にある辺と食い違う起動",
        Unassigned::DuplicateSequenceNumber => "同じ通し番号の2つ目",
    }
}

/// `renamed`を当てたドメイン名（無ければそのまま）。
pub fn renamed_name<'a>(renamed: &'a BTreeMap<String, String>, name: &'a str) -> &'a str {
    renamed.get(name).map(String::as_str).unwrap_or(name)
}

/// この位置を記録どおりのコマンドラインに絞れるか: 記録したコマンドラインが**ちょうど1通り**で、引数が結び付かな
/// かった起動も切り詰められた疑いのある起動も無いとき（`plans/DESIGN-MAC.md` §5.1(6)、決定65 Q2）。
pub fn can_narrow(position: &Position) -> bool {
    position.command_lines.len() == 1 && position.argv_missing == 0 && position.argv_truncated == 0
}

/// 位置ごとの辺（[`Assignment::positions`]と同じ並び。既にある辺の位置も出どころつきで入れる）。
///
/// 遷移元・遷移先の名前は`renamed`で置き換える（**名前ごと**——遷移先の名前を変えると、その位置から起きる子の
/// 遷移元も一緒に変わる）。`narrow`に入っていて[`can_narrow`]な位置は記録したコマンドラインに絞り、他は任意の引数。
/// 形は[`editor_edge`]の1か所（`B-05`）。
pub fn position_edges(
    assignment: &Assignment,
    renamed: &BTreeMap<String, String>,
    narrow: &BTreeSet<PositionKey>,
) -> Vec<EdgeToAdd> {
    assignment
        .positions
        .iter()
        .map(|position| {
            let argv = match position.command_lines.first() {
                Some(line) if can_narrow(position) && narrow.contains(&key_of(position)) => {
                    ArgvMatcher::Literal(line.clone())
                }
                _ => ArgvMatcher::Any(AnyMarker),
            };
            EdgeToAdd {
                from_domain: renamed_name(renamed, &position.from_domain).to_string(),
                edge: editor_edge(
                    &position.exe,
                    argv,
                    renamed_name(renamed, &position.to_domain),
                ),
                source: position.source,
            }
        })
        .collect()
}

/// 自己ループ辺の置き換え（[`PositionSource::ReplacesSelfLoop`]）で取り除く辺: `from`の自己ループ辺のうち、
/// リテラルの exe が（判定器と同じ畳み方で）`exe`と等しいもの。取り除いた辺を返す——**空なら、当たっていたのは
/// パターンの自己ループ辺**で、置き換えるとこの記録に無いプログラムも起こせなくなるので書かない（決定65 Q7）。
pub(crate) fn take_self_loops(
    file: &mut PolicyFile,
    from: &str,
    exe: &str,
) -> Vec<transition::TransitionEdge> {
    let Some(domain) = file.domains.iter_mut().find(|d| d.name == from) else {
        return Vec::new();
    };
    let folded = fold_for_pattern_comparison(exe);
    let mut taken = Vec::new();
    domain.process.transitions.retain(|edge| {
        let hit = edge.to == from
            && matches!(&edge.exe, ExeMatcher::Literal(e) if fold_for_pattern_comparison(e) == folded);
        if hit {
            taken.push(edge.clone());
        }
        !hit
    });
    taken
}

/// パターンの自己ループ辺に当たった位置の文言（[`take_self_loops`]が何も取り除けなかったとき）。
pub(crate) const PATTERN_SELF_LOOP: &str = "遷移元の自己ループ辺がパターンなので、置き換えるとこの記録に無いプログラムも起こせなくなります。\
     宣言画面（F3）の遷移タブで直してください";

/// `edges`を全部書いたと仮定した`PolicyFile`で、各辺を判定器に聞く（`edges`と同じ並びで返す）。
///
/// - 出どころが[`PositionSource::ExistingEdge`]の辺は足さずに[`EdgeVerdict::AlreadyDeclared`]
/// - [`PositionSource::ReplacesSelfLoop`]の辺は、遷移元の自己ループ辺を取り除いてから足す（取り除かないと同じ実行
///   ファイルに2本当たる。P3b の注意1）。パターンの自己ループ辺なら[`EdgeVerdict::Rejected`]
/// - `extra_fs`（`(ドメイン, 値, access)`）は各ドメインの宣言へ足してから聞く（ファイルの候補がドメインごとになる
///   P4.4 で、選んだ候補を渡す）
/// - [`transition::check_all`]に落ちた辺は、[`transition::edge_direction`]が広げる向きと答えれば
///   [`EdgeVerdict::Widens`]、そうでなければ[`EdgeVerdict::Rejected`]
/// - 全体が検査に通れば、判定器を組んで各辺の起動を引き直し、**書いた辺の遷移先に着かない**（既にあるパターンの辺と
///   重なる等。P3b の注意2）なら[`EdgeVerdict::Rejected`]。他の辺が検査に落ちる間は判定器を組めないので引き直さない
///
/// **全部を一度に足す**——予約の有無で他の行の判定が動くと、何を選べば何が書けるのかが追えない。選んだものだけで
/// 検査し直すのは確定（P4.5）である。
pub fn verdicts(
    policy: &PolicyFile,
    workspace_root: &Path,
    edges: &[EdgeToAdd],
    extra_fs: &[(String, String, FsAccess)],
) -> Vec<EdgeVerdict> {
    let mut file = policy.clone();
    for (domain, value, access) in extra_fs {
        let entry = domain_mut(&mut file, domain);
        let bucket = match access {
            FsAccess::Read => &mut entry.fs.read,
            FsAccess::ReadWrite => &mut entry.fs.read_write,
            FsAccess::ReadExec => &mut entry.fs.read_exec,
        };
        if !bucket.contains(value) {
            bucket.push(value.clone());
        }
    }

    let mut verdicts: Vec<Option<EdgeVerdict>> = vec![None; edges.len()];
    let mut by_from: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (index, add) in edges.iter().enumerate() {
        match add.source {
            PositionSource::ExistingEdge => verdicts[index] = Some(EdgeVerdict::AlreadyDeclared),
            PositionSource::ReplacesSelfLoop => {
                let exe = match &add.edge.exe {
                    ExeMatcher::Literal(exe) | ExeMatcher::Pattern(exe) => exe.as_str(),
                };
                if take_self_loops(&mut file, &add.from_domain, exe).is_empty() {
                    verdicts[index] = Some(EdgeVerdict::Rejected {
                        detail: PATTERN_SELF_LOOP.to_string(),
                    });
                } else {
                    by_from
                        .entry(add.from_domain.as_str())
                        .or_default()
                        .push(index);
                }
            }
            PositionSource::Proposed => by_from
                .entry(add.from_domain.as_str())
                .or_default()
                .push(index),
        }
    }

    // 足した辺が着いた場所（遷移元, transitions への添字）。
    let mut placed: Vec<Option<(String, usize)>> = vec![None; edges.len()];
    for (from, indices) in &by_from {
        let add: Vec<transition::TransitionEdge> =
            indices.iter().map(|i| edges[*i].edge.clone()).collect();
        let report = apply_edge_changes(
            &mut file,
            &EdgeChanges {
                from_domain: from,
                add: &add,
                remove: &[],
                record_session: None,
                now_unix_ms: 0,
            },
        );
        let mut added = report.added.iter();
        for (j, index) in indices.iter().enumerate() {
            if report.already_declared.contains(&j) {
                verdicts[*index] = Some(EdgeVerdict::AlreadyDeclared);
            } else if let Some(at) = added.next() {
                placed[*index] = Some((from.to_string(), *at));
            }
        }
    }

    let workspace = workspace_root.to_string_lossy();
    let input = file.transition_graph_input(Some(workspace.as_ref()), &[]);
    let rejections = match transition::check_all(&input) {
        Ok(rejections) => rejections,
        // 同じ名前のドメインが2つある（宣言の外形が壊れている）。どの辺も判定できない。
        Err(e) => {
            return verdicts
                .into_iter()
                .map(|v| {
                    v.unwrap_or_else(|| EdgeVerdict::Rejected {
                        detail: e.to_string(),
                    })
                })
                .collect()
        }
    };
    for (index, at) in placed.iter().enumerate() {
        let Some((from, at)) = at else { continue };
        let reasons: Vec<&str> = rejections
            .iter()
            .filter(|r| r.domain == *from && r.edge_index == *at)
            .map(|r| r.reason.as_str())
            .collect();
        if reasons.is_empty() {
            continue;
        }
        let detail = reasons.join("\n");
        verdicts[index] = Some(match transition::edge_direction(&input, from, *at) {
            Ok(Some(Direction::WiderOrUnknown)) => EdgeVerdict::Widens { detail },
            _ => EdgeVerdict::Rejected { detail },
        });
    }

    if rejections.is_empty() {
        if let Ok(graph) = TransitionGraph::build(&input) {
            for (index, at) in placed.iter().enumerate() {
                if at.is_none() || verdicts[index].is_some() {
                    continue;
                }
                let add = &edges[index];
                if let Some(detail) = lands_elsewhere(&graph, &add.from_domain, &add.edge, &workspace) {
                    verdicts[index] = Some(EdgeVerdict::Rejected { detail });
                }
            }
        }
    }

    verdicts
        .into_iter()
        .map(|v| v.unwrap_or(EdgeVerdict::Writable))
        .collect()
}

/// 書いた後の判定器で、`from`から辺`edge`の起動（引数はリテラルならその綴り、任意なら空）が辺の遷移先に着くか。
/// 着かなければ理由（`None`は着く）。位置の行の判定（[`verdicts`]）と確定（`crate::position_approve`）が同じこれを
/// 通す（P3b の注意2。`B-05`）。
pub(crate) fn lands_elsewhere(
    graph: &TransitionGraph,
    from: &str,
    edge: &transition::TransitionEdge,
    workspace: &str,
) -> Option<String> {
    let ExeMatcher::Literal(exe) = &edge.exe else {
        return None;
    };
    let command_line = match &edge.argv {
        ArgvMatcher::Literal(line) => line.as_str(),
        _ => "",
    };
    match graph.resolve(SpawnAttempt {
        from_domain: from,
        exe,
        command_line,
        cwd: workspace,
    }) {
        Resolution::Allowed(allowed) if allowed.to == edge.to => None,
        Resolution::Allowed(allowed) => Some(format!(
            "書いた後の宣言では {} へ遷移します（既にある辺と重なる）",
            allowed.to
        )),
        Resolution::Denied(denial) => Some(format!(
            "書いた後の宣言で断られます（既にある辺と重なる）: {}",
            denial.as_str()
        )),
    }
}

/// `name`のドメイン（無ければ宣言の無いドメインとして作る）。
fn domain_mut<'f>(file: &'f mut PolicyFile, name: &str) -> &'f mut PolicyDomain {
    if file.domain(name).is_none() {
        file.domains.push(PolicyDomain::new(name));
        file.domains.sort_by(|a, b| a.name.cmp(&b.name));
    }
    file.domains
        .iter_mut()
        .find(|d| d.name == name)
        .expect("just inserted or already present")
}

#[cfg(test)]
#[path = "position_view_tests.rs"]
pub(crate) mod position_view_tests;
