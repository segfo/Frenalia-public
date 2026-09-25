//! 承認の台帳への書込と、前回の写しの読み出し（D-107）。
//!
//! **判定器とファイルの間に線を引く場所である。** 判定器（`PermissionArbiter`）は規則を作って
//! 自分の中へ入れるところまでしかやらず、台帳という**マシン全体で1つの共有物**への書込は
//! この描画ループの側が引き受ける。理由は2つ——判定器のロックの中でファイル操作をしない
//! （進行中のツール判定を待たせない）ことと、**書けなかったことを画面に出す**ためである。
//!
//! 書込が失敗しても、その呼び出しは**このセッション中は自動承認のまま**である
//! （ゲートが既に判定器へ入れている）。食い違いを黙らせず、そう画面に書く。

use std::collections::HashMap;
use std::sync::Arc;

use harness_core::{LlmProvider, PermissionSubject, ProgramRule, ShellRule};
use harness_engine::approval_ledger::{ApprovalStore, RecordedRule};
use harness_engine::approval_summary::{summarize_for_approval, SummaryPiece};
use harness_engine::Remembered;
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;

use crate::app::{AppState, PreviousCopy, SummaryState, TranscriptItem};
use crate::engine::EngineHandle;

/// 承認画面の要約（D-100）をどこで作るか。`harness-cli`が起動時に決める。
pub struct ApprovalSummary {
    /// 要約に使うプロバイダ。会話と同じものを共有していることもある。
    pub provider: Arc<dyn LlmProvider>,
    pub model: String,
    /// 画面に出す出どころ（「どこへ中身が出たか」が後から分かるように）。
    pub label: String,
}

/// 同じ中身を2回要約しない（セッション中だけ覚える）。鍵は縛ったファイルのハッシュと行そのもの。
pub(crate) type SummaryCache = HashMap<String, String>;

/// 描画ループの外でやった仕事の結果。
#[derive(Debug)]
pub(crate) enum BackgroundEvent {
    /// 台帳への書込が終わった。`Ok`は記録した内容、`Err`は理由。
    ApprovalRecorded(Result<String, String>),
    /// 要約ができた。`request`は承認要求のid、`key`は使い回しの鍵。
    SummaryReady {
        request: String,
        key: String,
        result: Result<String, String>,
    },
}

/// 背景の結果を画面へ反映する。
pub(crate) fn on_background(event: BackgroundEvent, app: &mut AppState, cache: &mut SummaryCache) {
    match event {
        BackgroundEvent::ApprovalRecorded(Ok(what)) => app
            .transcript
            .push(TranscriptItem::Info(format!("承認を記録した: {what}"))),
        BackgroundEvent::ApprovalRecorded(Err(reason)) => {
            app.transcript.push(TranscriptItem::Error(reason))
        }
        BackgroundEvent::SummaryReady {
            request,
            key,
            result,
        } => {
            if let Ok(text) = &result {
                cache.insert(key, text.clone());
            }
            // **別の承認要求へ移っていたら捨てる。** 前の中身の要約を、いま聞かれている
            // 呼び出しの説明として出さない。
            let Some(view) = app.pending_permission.as_mut() else {
                return;
            };
            if view.id != request {
                return;
            }
            view.summary = match result {
                Ok(text) => SummaryState::Done(text),
                Err(reason) => SummaryState::Failed(reason),
            };
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

/// 要約に回す材料を組み立てる（D-100）。
///
/// **読取スコープで拒否される中身は送らない。** 承認のために中身を読むときは、子と同じ見え方を
/// するため読取スコープを通していない（`approval_binding`）。ここは人へ見せるためではなく
/// **外のプロバイダへ送る**ので、ユーザーが「読ませない」と書いた場所は落とす。
pub(crate) fn summary_pieces(
    app: &AppState,
    read_scope: &harness_sandbox::ReadScope,
) -> Vec<SummaryPiece> {
    let Some(view) = &app.pending_permission else {
        return Vec::new();
    };
    let mut pieces = Vec::new();
    match &view.subject {
        PermissionSubject::Command(c) => {
            pieces.push(SummaryPiece {
                label: "the shell line".to_string(),
                text: c.line.clone(),
            });
            pieces.extend(file_pieces(&c.previews, read_scope));
        }
        PermissionSubject::Program(p) => {
            pieces.extend(file_pieces(&p.previews, read_scope));
            if let Some(decoded) = &p.decoded_inline {
                pieces.push(SummaryPiece {
                    label: "the decoded -EncodedCommand".to_string(),
                    text: decoded.clone(),
                });
            } else if p.runs_code && p.files.is_empty() && !p.args.is_empty() {
                // ファイルに縛れない＝引数そのものがコードである（`pwsh -c "…"`）。
                pieces.push(SummaryPiece {
                    label: "the arguments, which run as code".to_string(),
                    text: p.args.join("\n"),
                });
            }
        }
        _ => {}
    }
    pieces
}

fn file_pieces(
    previews: &[harness_core::FilePreview],
    read_scope: &harness_sandbox::ReadScope,
) -> Vec<SummaryPiece> {
    previews
        .iter()
        .filter(|p| !read_scope.is_denied_rel(std::path::Path::new(&p.rel_path)))
        .map(|p| SummaryPiece {
            label: p.rel_path.clone(),
            text: p.text.clone(),
        })
        .collect()
}

/// 同じ中身を2回要約しないための鍵。
pub(crate) fn summary_key(pieces: &[SummaryPiece]) -> String {
    pieces
        .iter()
        .map(|p| format!("{}\u{1}{}", p.label, p.text.len()))
        .collect::<Vec<_>>()
        .join("\u{2}")
}

/// 承認要求1件につき1本だけ要約を起こす（B-23 の二重起動の防止）。
/// 返り値は**この要求のためのキャンセルトークン**で、モーダルが差し替わったら落とす。
pub(crate) fn start_summary(
    summary: &ApprovalSummary,
    background: &UnboundedSender<BackgroundEvent>,
    app: &mut AppState,
    cache: &SummaryCache,
    read_scope: &harness_sandbox::ReadScope,
    redact_host_paths: bool,
) -> Option<CancellationToken> {
    let pieces = summary_pieces(app, read_scope);
    if pieces.is_empty() {
        return None;
    }
    let key = summary_key(&pieces);
    let view = app.pending_permission.as_mut()?;
    if let Some(done) = cache.get(&key) {
        view.summary_source = Some(format!("{} / {}", summary.label, summary.model));
        view.summary = SummaryState::Done(done.clone());
        return None;
    }
    // **開始を即座に画面へ出す**（B-23）。無言で待たせない。
    // 出どころも一緒に出す——中身がどこへ出たのかを後から見て分かるようにする（D-100）。
    view.summary_source = Some(format!("{} / {}", summary.label, summary.model));
    view.summary = SummaryState::Running;
    let request = view.id.clone();

    let cancel = CancellationToken::new();
    let token = cancel.clone();
    let provider = summary.provider.clone();
    let model = summary.model.clone();
    let background = background.clone();
    tokio::spawn(async move {
        let result = match summarize_for_approval(
            provider.as_ref(),
            &model,
            &pieces,
            redact_host_paths,
            &token,
        )
        .await
        {
            // キャンセルされたときは何も送らない（モーダルはもう別のものを見ている）。
            Ok(None) => return,
            Ok(Some(text)) if text.is_empty() => Err("モデルが空の要約を返した".to_string()),
            Ok(Some(text)) => Ok(text),
            Err(e) => Err(e.to_string()),
        };
        let _ = background.send(BackgroundEvent::SummaryReady {
            request,
            key,
            result,
        });
    });
    Some(cancel)
}

#[cfg(test)]
#[path = "approvals_tests.rs"]
mod approvals_tests;
