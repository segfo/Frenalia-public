//! 位置の情報がある記録の**ファイルの候補をドメインごとに**作る（`plans/POLICY-EDITOR-TOMOYO-DIG.md` 決定65(5)・
//! Q4・Q8、手順は`plans/position-domains/P4.md`の P4.4）。
//!
//! # 何のためにあるのか
//!
//! 今までの候補は記録の全部のファイル操作から1つの一覧を作り（[`crate::aggregate::from_session`]）、ドメイン欄の
//! 1つの名前へ書いていた。位置ごとのドメイン（決定65）では、各ドメインが**自分のインスタンスが触った分だけ**を持つ
//! ——入口のシェルはモデルが書いたコマンドを実行するので、子孫の権限の和を持たせると、いちばん守りたい場面を
//! 守れない（決定65(5)）。そこでファイル操作を通し番号で位置のドメインへ振り分け
//! （`harness_policy::position_domains::partition_fs`）、ドメインごとに候補を作る。
//!
//! # 番号は全体で1列
//!
//! ドメインごとに`generalize`を呼ぶと、それぞれが`fs-1`から振る。CLI の`--accept fs-N`と画面が同じ番号で同じ
//! 候補を指すように、連結してから振り直す（[`renumber`]）。並びは入口のドメインが先、続いて位置に初めて出る順。
//!
//! # 位置の情報が無い記録は今までどおり
//!
//! パス2・2026-10-05より前のパス1は1つの一覧（ドメインは全部`None`）。読む口は[`crate::position_view::load`]の
//! 1つで、パス2を読まない判定もそこにある。
//!
//! # 限界
//!
//! - どのドメインにも引けなかったファイル操作は件数だけ出す（承認できない、決定65の細目4）。
//! - 注記・プロセスツリー・件数は記録全体の集計（[`SessionCandidates::fs`]）から出す。ドメインごとの集計の
//!   除外の件数は数えない（同じ除外が全体の集計に1回ずつ数えてある）。
//! - 画面（FS/ネットのタブ）と CLI（`show`・`approve`）は同じ[`load`]を通るので、同じ記録の候補番号が同じになる
//!   （P4.5 で揃えた。それまでは CLI が記録全体を1つのドメインで番号付けしていた）。

use std::collections::BTreeSet;
use std::path::Path;

use harness_policy::policy_file::{PolicyFile, ENTRY_DOMAIN};
use harness_policy::position_domains::{partition_fs, SplitPositions, Unattributed};
use harness_policy::RuleProposal;

use crate::aggregate::Aggregate;
use crate::session_dir::{RecordManifest, RecordSessionDir};

/// 1つの記録の候補。
pub struct SessionCandidates {
    /// 記録全体の集計（注記・プロセスツリー・件数のため。今までの候補と同じもの）。
    pub fs: Aggregate,
    /// 位置の情報がある記録はドメインごとに作って**全体で1列に振り直した**`fs-1..N`。無い記録は今までの候補。
    pub proposals: Vec<RuleProposal>,
    /// `proposals`と同じ並び。位置の情報が無い記録は全部`None`。
    pub domains: Vec<Option<String>>,
    /// どのドメインにも引けなかったファイル操作の件数（位置の情報がある記録だけ`Some`）。
    pub unattributed: Option<Unattributed>,
    /// 引けなかった件数・位置の木を作れなかった理由。**黙らせない**（`B-10`）。
    pub notes: Vec<String>,
}

impl SessionCandidates {
    /// 位置ごとのドメインに分けた記録か。
    pub fn by_position(&self) -> bool {
        self.unattributed.is_some()
    }
}

/// 記録の候補を、`policy.json`を読んでから作る（[`from_session`]）。**画面の FS/ネットのタブと CLI の`show`・`approve`が
/// 同じこれを通る**——同じ記録の候補番号が画面と CLI で同じになる（`B-13`）。`policy.json`が読めなければ位置を
/// 割り当てられないので、今までどおりの1つの一覧にして理由を注記に出す（`B-10`）。
///
/// `split`はコマンドラインごとに分ける位置（決定67）。画面は位置の木と**同じ集合**を渡す（`crate::position_view::load`の
/// doc）。CLI は分けない（空の集合）——CLI は辺を書かないので分けた位置を作れない。画面が分けて書いた後は、既にある
/// リテラルの辺を判定器で引くので、CLI も分けたドメインの候補を出す。
pub fn load(
    dir: &RecordSessionDir,
    manifest: &RecordManifest,
    workspace_root: &Path,
    split: &SplitPositions,
) -> SessionCandidates {
    match harness_policy::policy_file::load(workspace_root) {
        Ok(file) => from_session(dir, manifest, &file, split),
        Err(e) => whole(
            dir,
            manifest,
            Some(format!(
                "policy.json を読めないので、位置ごとのドメインに分けずに見せています: {e}"
            )),
        ),
    }
}

/// CLI の`show`に出す注記と候補一覧。位置ごとのドメインの記録は各行に`[<ドメイン>]`を添える（今までの記録は
/// `aggregate::render`と同じ綴り）。
pub fn render(candidates: &SessionCandidates, limit: usize) -> String {
    let mut out = crate::aggregate::render_notes(&candidates.fs);
    for note in &candidates.notes {
        out.push_str(note);
        out.push('\n');
    }
    crate::aggregate::render_candidates(&mut out, &candidates.proposals, &candidates.domains, limit);
    out
}

/// 記録の候補を作る。位置の情報があれば（[`crate::position_view::load`]が`Some`）ドメインごと、無ければ今までどおり。
/// 位置の木を作れなかったら今までどおりの1つの一覧にして、理由を注記に出す。
pub fn from_session(
    dir: &RecordSessionDir,
    manifest: &RecordManifest,
    policy: &PolicyFile,
    split: &SplitPositions,
) -> SessionCandidates {
    let view = match crate::position_view::load(dir, manifest, policy, split) {
        Ok(Some(view)) => view,
        Ok(None) => return whole(dir, manifest, None),
        Err(e) => {
            return whole(
                dir,
                manifest,
                Some(format!(
                    "位置の木を作れないので、ファイルの候補を位置ごとのドメインに分けずに見せています: {e}"
                )),
            )
        }
    };

    let fs = crate::aggregate::from_session(dir, manifest);
    let mut tail = crate::audit_tail::AuditTail::new(dir.audit_log_path());
    let (events, _skipped) = tail.poll_fs_events();
    let partition = partition_fs(&events, &view.assignment);
    let rules = crate::exclusion::ExclusionRules::for_session(&manifest.workspace_root);

    let mut proposals = Vec::new();
    let mut domains = Vec::new();
    for domain in domain_order(&view.assignment, partition.by_domain.keys()) {
        let Some(share) = partition.by_domain.get(&domain) else {
            continue;
        };
        let mut aggregate = Aggregate::from_events(&share.events, rules.clone());
        // 子の実行ファイル自身の実行権は子のドメインへ（決定65 Q8）。ファイル操作をした起動の実行ファイルは
        // `add_event`が既に足しているので、まだ候補に無いものだけ足す（観測の回数を二重に数えない）。
        for image in &share.exec_images {
            if !aggregate.has_exec_candidate(image) {
                aggregate.add_exec_image(image, manifest.started_unix_ms);
            }
        }
        for proposal in aggregate.proposals() {
            proposals.push(proposal);
            domains.push(Some(domain.clone()));
        }
    }
    renumber(&mut proposals);

    // 割り当てなかった起動の理由ごとの件数は、遷移・観測からのタブの位置の木が出す（`position_view`の注記）。
    let unattributed = partition.unattributed;
    SessionCandidates {
        fs,
        proposals,
        domains,
        unattributed: Some(unattributed),
        notes: view_notes(&unattributed),
    }
}

/// 位置ごとのドメインに分けない候補（今までの1つの一覧。ドメインは全部`None`）。`policy.json`を読めないときにも使う。
pub fn whole(
    dir: &RecordSessionDir,
    manifest: &RecordManifest,
    note: Option<String>,
) -> SessionCandidates {
    let fs = crate::aggregate::from_session(dir, manifest);
    let proposals = fs.proposals();
    SessionCandidates {
        domains: vec![None; proposals.len()],
        proposals,
        fs,
        unattributed: None,
        notes: note.into_iter().collect(),
    }
}

/// ドメインの並び: 入口のドメイン → 位置に初めて出る順（[`Assignment::positions`]の順）→ 残り（名前の順）。
///
/// [`Assignment::positions`]: harness_policy::position_domains::Assignment::positions
fn domain_order<'a>(
    assignment: &harness_policy::position_domains::Assignment,
    present: impl Iterator<Item = &'a String>,
) -> Vec<String> {
    let mut order: Vec<String> = vec![ENTRY_DOMAIN.to_string()];
    for position in &assignment.positions {
        if !order.contains(&position.to_domain) {
            order.push(position.to_domain.clone());
        }
    }
    let known: BTreeSet<String> = order.iter().cloned().collect();
    order.extend(present.filter(|name| !known.contains(*name)).cloned());
    order
}

/// 連結した候補の番号を全体で1列に振り直す（`fs-1..N`）。パス1の候補に通信（`net-`）は無い。
pub fn renumber(proposals: &mut [RuleProposal]) {
    for (index, proposal) in proposals.iter_mut().enumerate() {
        debug_assert_ne!(
            proposal.key,
            harness_policy::generalize::SettingsKey::NetAllowDomains,
            "パス1の候補に通信は無い"
        );
        proposal.id = format!("fs-{}", index + 1);
    }
}

/// 引けなかったファイル操作の注記（0件なら何も言わない）。
fn view_notes(unattributed: &Unattributed) -> Vec<String> {
    let total = unattributed.without_sequence_number
        + unattributed.unknown_sequence_number
        + unattributed.unassigned_instance;
    if total == 0 {
        return Vec::new();
    }
    vec![format!(
        "どのドメインにも引けなかったファイル操作 {total}件（承認できません——決定65の細目4）: \
         通し番号の欄が無い {}件・記録の木に無い番号 {}件・割り当てなかった起動 {}件",
        unattributed.without_sequence_number,
        unattributed.unknown_sequence_number,
        unattributed.unassigned_instance
    )]
}

#[cfg(test)]
#[path = "position_candidates_tests.rs"]
pub(crate) mod position_candidates_tests;
