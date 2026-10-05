//! 承認待ち画面（`F2`）のFS/ネットのタブの**確定**——選んだ候補（と外したチェック）から確認ダイアログを
//! 組み立て、`y`で`policy.json`へ書く（[`crate::tui::state::App`]の続き）。
//!
//! 候補を開く・選ぶ操作は[`super::edit`]が持つ。2026-10-05に`edit.rs`から**そのまま**移した
//! （本体が1,000行を超えていたため。`plans/position-domains/P4.md`のP4.0。振る舞いは変えていない）。
//!
//! # 承認は「決める」と「書く」の2段のまま使う
//!
//! [`crate::approve`]は`plan`（何も書かずに差分を返す）と`commit`（それを書く）に分かれており、
//! CLIはその間で確認プロンプトを出す。TUIも**同じ2段**をモーダルで使う。`y`を押した時点で
//! `plan`をもう一度作り直すのは、差分を見せている間に`policy.json`が別の経路で変わっていた
//! 場合に、古い読み込み結果で上書きしないため（承認は和集合マージなので作り直しても安全）。

use crate::approve::{self, ApproveRequest, PathClass};
use crate::policy_file;
use crate::session_dir::NetMode;
use crate::tui::state::{App, Confirm, EditField, Modal, Pass, RecordField, Screen};

impl App {
    /// 承認へ渡す`(提案一覧, 受理するid)`を組み立てる。**`a`（差分を見せる）と`y`（実際に書く）が
    /// 同じ関数を通る。**
    ///
    /// [D-63] 再帰の宣言を合成で足すようになったとき、`request_approval`にだけ足して
    /// `commit_approval`に足し忘れ、**確認は出るのに何も書かれない**という形にした（B-06）。
    /// 組み立てを1箇所に寄せて、次に選択の種類が増えても片方だけになりようがないようにする。
    fn approval_inputs(&self) -> (Vec<harness_policy::RuleProposal>, Vec<String>) {
        let mut proposals = self
            .view
            .as_ref()
            .map(|v| v.proposals.clone())
            .unwrap_or_default();
        let recursive = self.recursive_proposals();
        proposals.extend(recursive.iter().cloned());
        let mut accept_ids: Vec<String> = self.accepted.iter().cloned().collect();
        accept_ids.extend(recursive.iter().map(|p| p.id.clone()));
        (proposals, accept_ids)
    }

    /// 承認の差分を作ってモーダルで見せる。**ここでは何も書かない。**
    pub(super) fn request_approval(&mut self) {
        if self.view.is_none() {
            self.status = "開いている記録がありません".to_string();
            return;
        }
        // **取り消しだけの確定も通す。** チェックを外す操作は`accepted`を増やさないので、
        // ここで`accepted`の空だけを見て弾くと「外したのに確定できない」になる。
        // [D-63] `recursive`も「選んだもの」に数える。数え忘れると、再帰だけを指定した確定が
        // 「何も選んでいない」として弾かれる（選ぶ手段を増やしたら、選択の有無を見る場所も
        // 全部数える——B-06）。
        if self.accepted.is_empty() && self.unapproved.is_empty() && self.recursive.is_empty() {
            self.status =
                "承認する候補をスペースで選んでください（全件受理のショートハンドはありません）"
                    .to_string();
            return;
        }
        let Some(entry) = self.sessions.get(self.selected_session) else {
            return;
        };
        let domain = self.domain.text().trim().to_string();
        if domain.is_empty() {
            self.status = "ドメイン名を入力してください（Tabで入力欄へ移動）".to_string();
            self.edit_focus = EditField::Domain;
            return;
        }

        // [D-63] `R`で印を付けた再帰の宣言も合成して同じ経路へ流す（組み立ては`approval_inputs`）。
        let (proposals, accept_ids) = self.approval_inputs();
        // **承認が0件でも進む。** チェックを外しただけの確定（取り消しのみ）では`accepted`が
        // 空で、`approve::plan`は`NoIds`を返す——これをエラーとして扱うと「外したのに確定
        // できない」になる。承認の段はここでは**任意**である。
        let plan = if accept_ids.is_empty() {
            None
        } else {
            let request = ApproveRequest {
                workspace_root: &self.workspace_root,
                proposals: &proposals,
                accept_ids: &accept_ids,
                require_sandbox: self.require_sandbox,
                domain: &domain,
                command: Some(&entry.manifest.command),
                cwd: Some(&entry.manifest.cwd),
                record_session: Some(&entry.manifest.id),
                now_unix_ms: crate::session_dir::now_unix_ms(),
            };
            match approve::plan(&request) {
                Ok(plan) => Some(plan),
                Err(e) => {
                    // 部分適用はしない——1件でも通らなければ何も書かずに理由だけ出す。
                    self.modal = Some(Modal {
                        title: "承認できません（何も書いていません）".to_string(),
                        lines: e.to_string().lines().map(str::to_string).collect(),
                        confirm: Confirm::ReadOnly,
                    });
                    return;
                }
            }
        };

        // **判断材料を先に、明細を後に置く。** 687件の明細が先だと、マシンに何が残るのか
        // （＝承認するかどうかを決める唯一の材料）を読むのに延々と送ることになる。
        let mut lines = vec![format!(
            "{}:",
            policy_file::path(&self.workspace_root).display()
        )];
        lines.push(format!(
            "  ドメイン: {domain}{}",
            if plan.as_ref().is_some_and(|p| p.report.created_domain) {
                "（新規）"
            } else {
                ""
            }
        ));

        // 承認する分の判断材料は、承認が1件でもあるときだけ出す（取り消しのみの確定では
        // 「workspace外: なし」のような無関係な行を並べない）。
        if let Some(plan) = plan.as_ref() {
            // **承認の実質的な判断材料**: 実際にマシンのACLを変えるのはworkspace外の分だけ。
            let outside: Vec<&str> = plan
                .accepted
                .iter()
                .zip(&plan.classes)
                .filter(|(_, class)| **class == PathClass::OutsideWorkspace)
                .map(|(p, _)| p.value.as_str())
                .collect();
            let inside = plan
                .classes
                .iter()
                .filter(|c| **c == PathClass::InsideWorkspace)
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
                for value in &outside {
                    lines.push(format!("    {value}"));
                }
            }
            // **観測が言ったことと、ユーザーが判断したことを分けて見せる。** `c`でaccessを変えた
            // 候補は「そう観測された」わけではないので、書く前に件数と内訳を出す（D-42・B-09）。
            let hand_changed: Vec<&str> = plan
                .accepted
                .iter()
                .filter(|p| self.hand_changed.contains(&p.id))
                .map(|p| p.value.as_str())
                .collect();
            if !hand_changed.is_empty() {
                lines.push(String::new());
                lines.push(format!(
                    "  手で access を変えた候補 {}件（観測ではなくあなたの判断です）:",
                    hand_changed.len()
                ));
                for value in &hand_changed {
                    lines.push(format!("    {value}"));
                }
            }

            for warning in &plan.warnings {
                lines.push(format!("  ! {warning}"));
            }

            lines.extend(group_by_key(
                &plan.report.added,
                &plan.report.already_present,
            ));
        }

        // **外したチェック（＝取り消す宣言）を、足す側と同じ確認画面に出す。** 別の画面で
        // 聞くと、1回の`a`で2種類のことが起きるのに片方しか読まずに`y`を押せてしまう。
        let unapprove_plan = if self.unapproved.is_empty() {
            None
        } else {
            let targets: Vec<crate::unapprove::UnapproveTarget> =
                self.unapproved.iter().cloned().collect();
            match crate::unapprove::plan(&self.workspace_root, &targets) {
                Ok(plan) => Some(plan),
                Err(e) => {
                    self.modal = Some(Modal {
                        title: "取り消せません（何も書いていません）".to_string(),
                        lines: e.to_string().lines().map(str::to_string).collect(),
                        confirm: Confirm::ReadOnly,
                    });
                    return;
                }
            }
        };
        let removing = unapprove_plan.as_ref().map_or(0, |p| p.removed.len());
        if let Some(plan) = unapprove_plan.as_ref() {
            lines.push(String::new());
            lines.push(format!(
                "取り消す宣言 {}件（チェックを外した分）:",
                removing
            ));
            for target in &plan.removed {
                lines.push(format!("    - {} {}", target.key.dotted(), target.value));
            }
            lines.push(String::new());
            lines.extend(crate::unapprove::ACE_NOTICE.lines().map(str::to_string));
        }

        // 「承認で増えるものが無い」かどうか（承認自体をしていない場合も含む）。
        let adds_nothing = plan.as_ref().is_none_or(|p| p.report.is_empty());
        if adds_nothing && removing == 0 {
            lines.push(String::new());
            lines.push("（承認済みの内容に変化はありません。何も書きません）".to_string());
            self.modal = Some(Modal {
                title: "変化なし".to_string(),
                lines,
                confirm: Confirm::ReadOnly,
            });
            return;
        }

        self.modal = Some(Modal {
            // **何が起きるのかをタイトルで出す。** 取り消しが混ざる確定を「承認の確認」とだけ
            // 書くと、消える宣言があることが本文を読むまで分からない。
            title: if removing > 0 && adds_nothing {
                format!("{removing}件の宣言を取り消します")
            } else if removing > 0 {
                format!("承認と、{removing}件の宣言の取り消し")
            } else {
                "承認の確認".to_string()
            },
            lines,
            confirm: Confirm::Approval,
        });
        self.modal_scroll = 0;
    }

    /// モーダルで`y`が押されたときに実際に書く。**planを作り直してから**書く（モジュールdoc）。
    pub(crate) fn commit_approval(&mut self) {
        if self.view.is_none() {
            return;
        }
        let Some(entry) = self.sessions.get(self.selected_session) else {
            return;
        };
        let domain = self.domain.text().trim().to_string();
        // [D-63] `request_approval`とまったく同じ組み立てを通す（片方だけ再帰を落とさない）。
        let (proposals, accept_ids) = self.approval_inputs();
        let pass_of_record = entry.manifest.pass;
        let command = entry.manifest.command.clone();
        let cwd = entry.manifest.cwd.clone();

        // **承認が0件でも取り消しは書く。** `accepted`が空だと`approve::plan`は`NoIds`を返すので、
        // ここで一律にエラー扱いすると**取り消しだけの確定が黙って落ちる**
        // （`request_approval`が確認を出したのに何も起きない、という形になる）。
        if !accept_ids.is_empty() {
            let request = ApproveRequest {
                workspace_root: &self.workspace_root,
                proposals: &proposals,
                accept_ids: &accept_ids,
                require_sandbox: self.require_sandbox,
                domain: &domain,
                command: Some(&entry.manifest.command),
                cwd: Some(&entry.manifest.cwd),
                record_session: Some(&entry.manifest.id),
                now_unix_ms: crate::session_dir::now_unix_ms(),
            };
            let plan = match approve::plan(&request) {
                Ok(plan) => plan,
                Err(e) => {
                    self.status = e.to_string();
                    return;
                }
            };
            if let Err(e) = approve::commit(&self.workspace_root, &plan) {
                self.status = e.to_string();
                return;
            }
        }

        // **外したチェック（＝宣言の取り消し）も同じ確定で書く。** 片方だけ書くと、画面上は
        // 外れているのに`policy.json`には残る（B-01: 対の片方だけ実装しない）。
        // 承認を先に書いてから取り消す順序にしてあるのは、`approve`が和集合マージなので
        // 逆順だと「今回外したものを承認が書き戻す」ことが起こり得るためである。
        let mut unapproved_note = String::new();
        if !self.unapproved.is_empty() {
            let targets: Vec<crate::unapprove::UnapproveTarget> =
                self.unapproved.iter().cloned().collect();
            match crate::unapprove::plan(&self.workspace_root, &targets).and_then(|plan| {
                let removed = plan.removed.len();
                crate::unapprove::commit(&self.workspace_root, &plan).map(|_| removed)
            }) {
                Ok(removed) => {
                    self.unapproved.clear();
                    if removed > 0 {
                        unapproved_note = format!(
                            "／宣言 {removed}件を取り消しました（ACEは次のパス2開始時に撤収）"
                        );
                    }
                }
                // **書けなかったことを黙らない。** 承認だけ通って取り消しが落ちた状態は、
                // 画面の見た目と`policy.json`がずれている状態そのものである。
                Err(e) => unapproved_note = format!("／**取り消しは失敗しました**: {e}"),
            }
        }
        // 宣言が変わったので重ねを作り直す（作り直さないと外した行が`[x]`のまま残る）。
        self.refresh_declared_overlay();

        let written = policy_file::path(&self.workspace_root)
            .display()
            .to_string();
        // ガイド: 次の1回を記録画面に用意する（Enterで開始。「パス」欄で変えられる）。
        //  - パス1の候補を承認した → パス2（記録）。ここで初めてACEが付き、通信先を集める。
        //  - パス2の候補を承認した → パス2（強制）。宣言した通信先だけで動くか、宣言の外で
        //    断られる宛先が無いかを確かめる（決定64）。
        let next_mode = if pass_of_record == 2 {
            NetMode::Declared
        } else {
            NetMode::RecordAll
        };
        self.pass = Pass::Two;
        self.net_mode = next_mode;
        self.run_domain.set_text(domain.clone());
        self.command.set_text(command);
        self.cwd.set_text(cwd.display().to_string());
        self.screen = Screen::Record;
        self.record_focus = RecordField::Command;
        self.status = match next_mode {
            NetMode::RecordAll => format!(
                "書きました: {written}{unapproved_note}。次はパス2（ドメイン {domain}）——\
                 **ここで初めてACEが付きます**。Enterで開始"
            ),
            NetMode::Declared => format!(
                "書きました: {written}{unapproved_note}。次はパス2の強制（ドメイン {domain}）——\
                 宣言した通信先だけを許して走らせ、断られる宛先が無いかを確かめます。Enterで開始"
            ),
        };
    }
}

/// 差分を**access種別ごとにまとめて**並べる。
///
/// `+ fs.read = <パス>`を1行ずつ出すと、687件では同じ`fs.read =`が687回並び、
/// 「どの種別を何件許すのか」という一番知りたいことが読み取れない。種別を見出しにして
/// パスをぶら下げる。
///
/// **既にある分は件数だけ**にする——変更ではないので明細を出しても判断は変わらず、
/// これから増える分（＝承認の対象）が埋もれる。中身が知りたければ`policy.json`そのものを読む。
fn group_by_key(
    added: &[(&'static str, String)],
    already_present: &[(&'static str, String)],
) -> Vec<String> {
    // 表示順は`SettingsKey`の並び（read → read_write → read_exec → net）に合わせて固定する
    // ——実行のたびに順序が変わると差分を見比べられない。
    const ORDER: &[&str] = &[
        "fs.read",
        "fs.read_write",
        "fs.read_exec",
        "net.allow_domains",
    ];
    let mut lines = Vec::new();

    for key in ORDER {
        let values: Vec<&str> = added
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect();
        if values.is_empty() {
            continue;
        }
        lines.push(String::new());
        lines.push(format!("  {key}  ＋{}件", values.len()));
        for value in values {
            lines.push(format!("      {value}"));
        }
    }

    let mut present_lines = Vec::new();
    for key in ORDER {
        let count = already_present.iter().filter(|(k, _)| k == key).count();
        if count > 0 {
            present_lines.push(format!("  {key}  {count}件は既にあります（変更なし）"));
        }
    }
    if !present_lines.is_empty() {
        lines.push(String::new());
        lines.extend(present_lines);
    }

    lines
}
