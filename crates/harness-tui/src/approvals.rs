//! 承認の台帳への書込と、前回の写しの読み出し（D-107）。
//!
//! **判定器とファイルの間に線を引く場所である。** 判定器（`PermissionArbiter`）は規則を作って
//! 自分の中へ入れるところまでしかやらず、台帳という**マシン全体で1つの共有物**への書込は
//! この描画ループの側が引き受ける。理由は2つ——判定器のロックの中でファイル操作をしない
//! （進行中のツール判定を待たせない）ことと、**書けなかったことを画面に出す**ためである。
//!
//! 書込が失敗しても、その呼び出しは**このセッション中は自動承認のまま**である
//! （ゲートが既に判定器へ入れている）。食い違いを黙らせず、そう画面に書く。

use std::sync::Arc;

use harness_core::{PermissionSubject, ProgramRule, ShellRule};
use harness_engine::approval_ledger::{ApprovalStore, RecordedRule};
use harness_engine::Remembered;
use tokio::sync::mpsc::UnboundedSender;

use crate::app::{AppState, PreviousCopy, TranscriptItem};
use crate::engine::EngineHandle;

/// 描画ループの外でやった仕事の結果。
#[derive(Debug)]
pub(crate) enum BackgroundEvent {
    /// 台帳への書込が終わった。`Ok`は記録した内容、`Err`は理由。
    ApprovalRecorded(Result<String, String>),
}

impl BackgroundEvent {
    /// 画面へ積む。
    pub(crate) fn apply(self, app: &mut AppState) {
        match self {
            BackgroundEvent::ApprovalRecorded(Ok(what)) => app
                .transcript
                .push(TranscriptItem::Info(format!("承認を記録した: {what}"))),
            BackgroundEvent::ApprovalRecorded(Err(reason)) => {
                app.transcript.push(TranscriptItem::Error(reason))
            }
        }
    }
}

/// 「恒久的に承認」を確定する。判定器への登録はゲートが同期で終えているので、ここは
/// **台帳へ書くだけ**である。書込はファイル操作（名前付きミューテックス・読取専用属性の付け外し・
/// 写しの書き出し）なので`spawn_blocking`へ出し、結果は[`BackgroundEvent`]で戻す。
pub(crate) fn record_approval(
    engine: &EngineHandle,
    store: &Arc<ApprovalStore>,
    background: &UnboundedSender<BackgroundEvent>,
    app: &mut AppState,
    id: &str,
    holes: &[usize],
) {
    let outcome = engine.gate.respond_remember(id, holes);
    match outcome.remembered {
        Some(Remembered::Recorded(rule)) => {
            let described = rule.describe();
            let store = store.clone();
            let previews = outcome.previews;
            let background = background.clone();
            tokio::task::spawn_blocking(move || {
                let result = match store.record(rule, &previews) {
                    Ok(()) => Ok(described),
                    Err(reason) => Err(format!(
                        "承認を台帳へ書けなかった（{reason}）。{described} は\
                         **このセッション中だけ**自動で通る。`harness approvals list` には出ない。"
                    )),
                };
                let _ = background.send(BackgroundEvent::ApprovalRecorded(result));
            });
        }
        Some(Remembered::SessionOnly) => app.transcript.push(TranscriptItem::Info(
            "このセッション中は許可する（台帳に残る形の無いツールなので、次の起動では聞かれる）"
                .to_string(),
        )),
        Some(Remembered::Refused) => app.transcript.push(TranscriptItem::Error(
            "この呼び出しは恒久的に承認できないので、一度だけ許可した\
             （確かめられないファイルを指しているか、引数をコードとして走らせる呼び出し）"
                .to_string(),
        )),
        // 応答先が既に無い（二重応答・ターンの取り消し）。何も起きていないので黙る。
        None => {}
    }
}

/// 承認待ちの呼び出しについて、前回の承認で残した写しを読む（差分表示用）。
pub(crate) fn previous_copies(store: &ApprovalStore, app: &AppState) -> Vec<PreviousCopy> {
    let Some(view) = &app.pending_permission else {
        return Vec::new();
    };
    let Some(rule) = candidate_rule(&view.subject, &app.workspace_root) else {
        return Vec::new();
    };
    view.bound_files()
        .iter()
        .filter_map(|f| {
            store
                .previous_snapshot(&rule, &f.rel_path)
                .map(|text| PreviousCopy {
                    rel_path: f.rel_path.clone(),
                    text,
                })
        })
        .collect()
}

/// いま聞かれている呼び出しを、**もし恒久承認したら**どういう記録になるかの形にする。
/// 写しを引くのに使うだけで、判定には使わない（[`ApprovalStore::previous_snapshot`]は
/// 「同じ呼び出しか」を program・引数・解決先・ワークスペースで見る）。
fn candidate_rule(subject: &PermissionSubject, workspace_root: &str) -> Option<RecordedRule> {
    match subject {
        PermissionSubject::Command(c) => {
            Some(RecordedRule::RunShell(ShellRule::exact(c, workspace_root)))
        }
        PermissionSubject::Program(p) => Some(RecordedRule::RunProgram(ProgramRule::exact(
            p,
            workspace_root,
        ))),
        _ => None,
    }
}
