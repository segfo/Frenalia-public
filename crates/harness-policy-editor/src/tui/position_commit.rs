//! 承認待ち画面（`F2`）の**位置ごとのドメインの記録の確定**——FS/ネットのタブで選んだドメインごとのファイルの宣言、
//! 観測のタブで選んだ位置の辺、拒否からの予約、取り消し、却下印を1つの確認ダイアログにまとめ、`y`で`policy.json`を
//! **1回だけ**保存する（`plans/POLICY-EDITOR-TOMOYO-DIG.md` 決定65、`plans/position-domains/P4.md`の P4.5）。
//!
//! # いつここを通るか
//!
//! 選んでいる記録が位置の情報を持つとき（[`App::is_position_record`]）、承認待ちの**どのタブの`a`も**ここへ来る。
//! タブごとに別々に書くと、片方だけ書けた状態（辺は書けたがファイルの宣言は断られた）や、別のタブの予約が黙って
//! 残る状態を作る（`B-32`）。位置の情報が無い記録（パス2・古い記録）は今までどおり`tui::edit_commit`と
//! `tui::transition_commit`を通る。
//!
//! # 書く順序
//!
//! (1) 却下印が読めるかを確かめる → (2) `policy.json`（[`position_approve::commit`]。台帳はその中で保存の後）→
//! (3) 却下印。`tui::transition_commit`の`commit_transition`と同じ理由（落ちやすい方を先に確かめる）。
//!
//! # 限界
//!
//! - 拒否からの予約の遷移元は入口のドメインに決め打ちしている（P4.6 で行の遷移元にする）。
//! - 記録を替えた後の古い位置の予約は使わない（[`App::current_positions`]）。

use std::collections::BTreeSet;
use std::path::PathBuf;

use harness_policy::policy_file::{self, ENTRY_DOMAIN};
use harness_policy::position_domains::PositionSource;

use crate::position_approve::{self, DomainSelection, EdgeWrite, PositionRequest};
use crate::position_view::{key_of, position_edges, renamed_name};
use crate::transition_approve::EdgeRef;
use crate::tui::state::{App, Confirm, Modal};
use crate::tui::transition::CandidateKey;
use crate::tui::transition_dismissed;
use crate::tui::transition_positions::PositionsState;
use crate::unapprove::UnapproveTarget;

/// 確定の入力（予約から組み立てたもの）。`a`（ダイアログを出す）と`y`（書く）が同じ[`App::position_inputs`]で作る。
struct Inputs {
    fs: Vec<DomainSelection>,
    edges: Vec<EdgeWrite>,
    remove_edges: Vec<(String, EdgeRef)>,
    unapprove: Vec<UnapproveTarget>,
    /// 拒否からの承認の予約の遷移先（平らな一覧の遷移先の欄。予約が無ければ`None`）。
    flat_destination: Option<String>,
    dismiss: BTreeSet<CandidateKey>,
    undismiss: BTreeSet<CandidateKey>,
    /// 由来（記録したコマンド・作業ディレクトリ・記録セッション）。
    command: String,
    cwd: PathBuf,
    session: String,
}

impl Inputs {
    fn writes_policy(&self) -> bool {
        !self.fs.is_empty()
            || !self.edges.is_empty()
            || !self.remove_edges.is_empty()
            || !self.unapprove.is_empty()
    }

    fn has_dismissals(&self) -> bool {
        !self.dismiss.is_empty() || !self.undismiss.is_empty()
    }

    /// **`replace_self_loops`は`true`**——置き換える自己ループ辺はダイアログに出し、`y`はその同意を兼ねる（決定65 Q7）。
    fn request<'a>(&'a self, app: &'a App) -> PositionRequest<'a> {
        PositionRequest {
            workspace_root: &app.workspace_root,
            require_sandbox: app.require_sandbox,
            command: Some(&self.command),
            cwd: Some(&self.cwd),
            record_session: Some(&self.session),
            now_unix_ms: crate::session_dir::now_unix_ms(),
            fs: self.fs.clone(),
            edges: self.edges.clone(),
            remove_edges: self.remove_edges.clone(),
            unapprove: self.unapprove.clone(),
            replace_self_loops: true,
        }
    }
}

impl App {
    /// 選んでいる記録が位置の情報を持つか（候補がドメインごとに分かれている、または観測のタブが位置の木を出している）。
    pub fn is_position_record(&self) -> bool {
        self.view.as_ref().is_some_and(|view| view.by_position())
            || self.current_positions().is_some()
    }

    /// 選んでいる記録の位置の行（**記録を替えた後の古い状態は返さない**——位置の鍵と付け替えは記録ごとに作り直すので、
    /// 別の記録の行を指しうる）。
    pub(crate) fn current_positions(&self) -> Option<&PositionsState> {
        let id = self.selected_session()?.manifest.id.as_str();
        self.pending
            .positions
            .as_ref()
            .filter(|positions| positions.view.session_id == id)
    }

    /// 確定の内容を組み立てて確認ダイアログを出す（**まだ書かない**）。書けないならその理由のダイアログ。
    pub(crate) fn request_position_commit(&mut self) {
        let Some(inputs) = self.position_inputs() else {
            return;
        };
        if inputs.has_dismissals() {
            if let Err(e) = transition_dismissed::load(&self.workspace_root) {
                self.modal = Some(Modal {
                    title: "却下印を書けません（何も書いていません）".to_string(),
                    lines: vec![
                        e.to_string(),
                        String::new(),
                        "壊れたファイルは上書きしません。直すか消すと保存できます。".to_string(),
                        "承認・取り消しだけを書くなら、x で却下の予約を外してください。"
                            .to_string(),
                    ],
                    confirm: Confirm::ReadOnly,
                });
                return;
            }
        }
        let mut lines = Vec::new();
        if inputs.writes_policy() {
            let plan = match position_approve::plan(&inputs.request(self)) {
                Ok(plan) => plan,
                Err(e) => {
                    // 部分適用はしない——1件でも通らなければ何も書かずに理由だけ出す。
                    self.modal = Some(Modal {
                        title: "書けません（何も書いていません）".to_string(),
                        lines: e.to_string().lines().map(str::to_string).collect(),
                        confirm: Confirm::ReadOnly,
                    });
                    return;
                }
            };
            if plan.is_empty() && !inputs.has_dismissals() {
                self.modal = Some(Modal {
                    title: "変化なし".to_string(),
                    lines: vec!["（承認済みの内容に変化はありません。何も書きません）".to_string()],
                    confirm: Confirm::ReadOnly,
                });
                return;
            }
            lines = position_approve::confirmation_lines(
                &self.workspace_root,
                &plan,
                &self.hand_changed,
            );
            // 拒否からの予約の遷移先を`harness.exe`が用意する見込み（平らな一覧の確定と同じ説明）。
            if let Some(to) = inputs.flat_destination.as_deref() {
                lines.push(String::new());
                lines.extend(self.outlook_notice_lines(to));
            }
        }
        if inputs.has_dismissals() {
            if !lines.is_empty() {
                lines.push(String::new());
            }
            lines.extend(transition_dismissed::confirmation_lines(
                &self.workspace_root,
                ENTRY_DOMAIN,
                &inputs.dismiss,
                &inputs.undismiss,
            ));
        }
        self.modal = Some(Modal {
            title: "位置ごとのドメインの確定（policy.json は1回の保存で書きます）".to_string(),
            lines,
            confirm: Confirm::Position,
        });
        self.modal_scroll = 0;
    }

    /// 確認後に実際に書く。**入力も`plan`も作り直す**——ダイアログを見ている間に`policy.json`が別の経路で変わっていた
    /// 場合に、古い読み込み結果で上書きしないため（`tui::transition_commit`の`commit_transition`と同じ作法）。
    pub(crate) fn commit_position(&mut self) {
        let Some(inputs) = self.position_inputs() else {
            return;
        };
        if inputs.has_dismissals() {
            if let Err(e) = transition_dismissed::load(&self.workspace_root) {
                self.status = format!("却下印を書けませんでした（何も書いていません）: {e}");
                return;
            }
        }
        let mut done: Vec<String> = Vec::new();
        if inputs.writes_policy() {
            let plan = match position_approve::plan(&inputs.request(self)) {
                Ok(plan) => plan,
                Err(e) => {
                    self.status = format!("書けませんでした（何も書いていません）: {e}");
                    return;
                }
            };
            match position_approve::commit(&self.workspace_root, &plan, &policy_file::save) {
                Ok(true) => done.push(format!(
                    "書きました: {}（ファイルの宣言 {}件・遷移の辺 {}本・取り消し {}件。ACLはいま変わりません）",
                    policy_file::path(&self.workspace_root).display(),
                    plan.fs.iter().map(|d| d.report.added.len()).sum::<usize>(),
                    plan.edges_added.len(),
                    plan.edges_removed.len() + plan.unapproved.len()
                )),
                Ok(false) => {
                    done.push("変わるものがありませんでした（policy.jsonは書いていません）".to_string())
                }
                Err(e) => {
                    self.status = e.to_string();
                    return;
                }
            }
            self.clear_position_reservations();
        }
        if inputs.has_dismissals() {
            match transition_dismissed::update(
                &self.workspace_root,
                ENTRY_DOMAIN,
                &inputs.dismiss,
                &inputs.undismiss,
                super::transition_commit::now_unix_ms(),
            ) {
                Ok(applied) => {
                    done.push(format!(
                        "却下 {}件 / 却下の取り消し {}件を保存しました（表示だけの印です）",
                        applied.added, applied.removed
                    ));
                    self.pending.dismiss.clear();
                    self.pending.undismiss.clear();
                }
                // **予約は残す**——もう一度 a を押せば同じものを書きに行ける。
                Err(e) => done.push(format!(
                    "却下印は書けませんでした（却下の予約は残してあります）: {e}"
                )),
            }
        }
        self.status = done.join("。");
        // 宣言が変わったので重ね（`[x]`）と遷移の候補を作り直す。
        self.refresh_declared_overlay();
        self.reload_transitions();
    }

    /// 書いた予約を空にする（ファイル・通信の選択、`R`、外したチェック、位置の予約と付け替え、拒否からの予約）。
    fn clear_position_reservations(&mut self) {
        self.accepted.clear();
        self.recursive.clear();
        self.unapproved.clear();
        if let Some(positions) = self.pending.positions.as_mut() {
            positions.approve.clear();
            positions.narrow.clear();
            positions.renamed.clear();
        }
        self.pending.approve.clear();
        self.pending.narrow.clear();
        self.pending.remove.clear();
    }

    /// 予約から確定の入力を組み立てる。**`a`と`y`が同じこれを通る**（片方だけ予約の種類を落とさない。`B-06`）。
    /// 組み立てられない（書く先のドメインが決まらない候補・遷移先が空・何も選んでいない）ときは理由を状態の行に出して`None`。
    fn position_inputs(&mut self) -> Option<Inputs> {
        let Some(entry) = self.selected_session() else {
            self.status = "開いている記録がありません".to_string();
            return None;
        };
        let (command, cwd, session) = (
            entry.manifest.command.clone(),
            entry.manifest.cwd.clone(),
            entry.manifest.id.clone(),
        );
        // 位置の辺（観測のタブで選んだ位置）と付け替え。
        let (renamed, mut edges) = match self.current_positions() {
            Some(positions) => (
                positions.renamed.clone(),
                selected_position_edges(positions),
            ),
            None => Default::default(),
        };

        // ファイルの宣言: 選んだ候補と`R`の合成提案を、候補ごとのドメイン（付け替えを当てた名前）へ。
        let mut chosen = Vec::new();
        let mut without_domain = Vec::new();
        if let Some(view) = self.view.as_ref() {
            for (proposal, domain) in view.proposals.iter().zip(&view.domains) {
                if !self.accepted.contains(&proposal.id) {
                    continue;
                }
                match domain {
                    Some(domain) => {
                        chosen.push((renamed_name(&renamed, domain).to_string(), proposal.clone()))
                    }
                    None => without_domain.push(proposal.id.clone()),
                }
            }
        }
        for (domain, proposal) in self.recursive_proposals() {
            match domain {
                Some(domain) => {
                    chosen.push((renamed_name(&renamed, &domain).to_string(), proposal))
                }
                None => without_domain.push(proposal.value),
            }
        }
        if !without_domain.is_empty() {
            // **黙って入口のドメインへ寄せない**——位置ごとに分けた意味が消える（`B-09`）。
            self.status = format!(
                "書く先のドメインが決まらない候補があります（何も書いていません）: {}",
                without_domain.join(", ")
            );
            return None;
        }

        // 拒否からの予約（平らな一覧。遷移元は入口のドメイン——P4.6 で行の遷移元にする）。
        let (approve_refs, remove_refs) = self.reserved_edges();
        let flat_destination = if approve_refs.is_empty() {
            None
        } else {
            let to = self.destination_for_commit(true)?;
            edges.extend(approve_refs.iter().map(|target| EdgeWrite {
                from_domain: ENTRY_DOMAIN.to_string(),
                edge: target.edge_to(&to),
                replaces_self_loop: false,
            }));
            Some(to)
        };
        let remove_edges = remove_refs
            .into_iter()
            .map(|target| (ENTRY_DOMAIN.to_string(), target))
            .collect();
        let (dismiss, undismiss) = self.reserved_dismissals();

        let inputs = Inputs {
            fs: position_approve::group_by_domain(chosen),
            edges,
            remove_edges,
            unapprove: self.unapproved.iter().cloned().collect(),
            flat_destination,
            dismiss,
            undismiss,
            command,
            cwd,
            session,
        };
        if !inputs.writes_policy() && !inputs.has_dismissals() {
            self.status = "選んだものが1件もありません（FS/ネットのタブで候補を、観測のタブで位置を Space で選んでから a）"
                .to_string();
            return None;
        }
        Some(inputs)
    }
}

/// 位置の行で選んだ位置の辺（付け替え・絞り方を当てたもの。形は[`position_edges`]の1か所）。
fn selected_position_edges(positions: &PositionsState) -> Vec<EdgeWrite> {
    let assignment = &positions.view.assignment;
    position_edges(assignment, &positions.renamed, &positions.narrow)
        .into_iter()
        .zip(&assignment.positions)
        .filter(|(_, position)| positions.approve.contains(&key_of(position)))
        .map(|(add, _)| EdgeWrite {
            replaces_self_loop: add.source == PositionSource::ReplacesSelfLoop,
            from_domain: add.from_domain,
            edge: add.edge,
        })
        .collect()
}
