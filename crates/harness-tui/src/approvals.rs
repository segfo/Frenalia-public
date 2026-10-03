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
use std::time::Instant;

use harness_core::{
    DecodeOutcome, DecodedLayer, EncodedSource, LlmProvider, PermissionSubject, ProgramRule,
    ShellRule,
};
use harness_engine::approval_ledger::{ApprovalStore, RecordedRule};
use harness_engine::approval_summary::{summarize_for_approval, SummaryLanguage, SummaryPiece};
use harness_engine::Remembered;
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;

use crate::app::{AppState, PreviousCopy, SummaryState, SummaryWait, TranscriptItem};
use crate::engine::EngineHandle;

/// 承認画面の要約（D-100）をどこで作るか。`harness-cli`が起動時に決める。
pub struct ApprovalSummary {
    /// 要約に使うプロバイダ。会話と同じものを共有していることもある。
    pub provider: Arc<dyn LlmProvider>,
    pub model: String,
    /// 画面に出す出どころ（「どこへ中身が出たか」が後から分かるように）。
    pub label: String,
}

/// 同じ中身を2回要約しない（セッション中だけ覚える）。鍵は送った中身そのものと要約の言語（[`summary_key`]）。
pub(crate) type SummaryCache = HashMap<String, String>;

/// 描画ループの外でやった仕事の結果。
#[derive(Debug)]
pub(crate) enum BackgroundEvent {
    /// 台帳への書込が終わった。`Ok`は記録した内容、`Err`は理由。
    ApprovalRecorded(Result<String, String>),
    /// 要約の途中経過。`output_chars`はそれまでに受けた出力（考える過程と本文）の文字数の累計。
    /// 待ちの行の「考えた量」に使う。
    SummaryProgress {
        request: String,
        output_chars: usize,
    },
    /// 要約ができた。`request`は承認要求のid、`key`は使い回しの鍵。
    SummaryReady {
        request: String,
        key: String,
        result: Result<String, String>,
    },
}

/// 背景の結果を画面へ反映する。`now`は受け取った時刻（要約を待った時間を測る。試験は作って渡す）。
pub(crate) fn on_background(
    event: BackgroundEvent,
    app: &mut AppState,
    cache: &mut SummaryCache,
    now: Instant,
) {
    match event {
        BackgroundEvent::ApprovalRecorded(Ok(what)) => app
            .transcript
            .push(TranscriptItem::Info(format!("承認を記録した: {what}"))),
        BackgroundEvent::ApprovalRecorded(Err(reason)) => {
            app.transcript.push(TranscriptItem::Error(reason))
        }
        BackgroundEvent::SummaryProgress {
            request,
            output_chars,
        } => {
            // **いま待っている要約のものだけを入れる。** 別の承認要求へ移った後・できた後に遅れて届いたもの
            // （キャンセルの前に送られて溝に残っていたもの）は捨てる。累計なので小さい値では戻さない。
            if let Some(SummaryState::Running(wait)) = waiting_summary_for(app, &request) {
                wait.output_chars = wait.output_chars.max(output_chars);
            }
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
            let Some(summary) = waiting_summary_for(app, &request) else {
                return;
            };
            // 待った時間を残す（会話の「(thought for Ns)」と同じ）。待っていなかったなら残さない。
            let took = match summary {
                SummaryState::Running(wait) => Some(now.saturating_duration_since(wait.started)),
                _ => None,
            };
            *summary = match result {
                Ok(text) => SummaryState::Done { text, took },
                Err(reason) => SummaryState::Failed { reason, took },
            };
        }
    }
}

/// いま開いている承認ダイアログが`request`のものなら、その要約の状態。別の要求・閉じていれば`None`。
fn waiting_summary_for<'a>(app: &'a mut AppState, request: &str) -> Option<&'a mut SummaryState> {
    app.pending_permission
        .as_mut()
        .filter(|view| view.id == request)
        .map(|view| &mut view.summary)
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
            pieces.extend(decoded_pieces(&c.decoded));
        }
        PermissionSubject::Program(p) => {
            pieces.extend(file_pieces(&p.previews, read_scope));
            // ファイルに縛れない＝引数そのものがコードである（`pwsh -c "…"`）。ただし`-EncodedCommand`の値を
            // 解読できたなら、走るコードはその中身で、引数は符号化された塊とスイッチだけなので回さない
            // （塊を渡すと、要約が自分で解読しようとする）。`FromBase64String`だけなら、それを戻して何をするか
            // （`iex`等）は引数の側にあるので回す。
            let args_are_the_code = !p.decoded.iter().any(|l| {
                l.depth == 1
                    && l.source == EncodedSource::EncodedCommand
                    && matches!(l.outcome, DecodeOutcome::Text { .. })
            });
            if args_are_the_code && p.runs_code && p.files.is_empty() && !p.args.is_empty() {
                pieces.push(SummaryPiece {
                    label: "the arguments, which run as code".to_string(),
                    text: p.args.join("\n"),
                });
            }
            pieces.extend(decoded_pieces(&p.decoded));
        }
        _ => {}
    }
    pieces
}

/// 解読した段を要約の材料にする（[BUG-224]）。**要約する LLM に自分で解読させない**——
/// 実際に、符号化された塊を渡したら自分で解いて中身を取り違えた（`systeminfo`を`Write-Hello`と
/// 書いた）。解読はハーネスの仕事で、要約は読んで説明する仕事である（D-100「要約は補助」）。
///
/// 解読できなかった段も材料に入れる。符号化された箇所があること自体が、人が知るべき事実だからである。
/// 文言は画面の`decoded_layer_lines`（`app/approval.rs`）と同じく網羅の`match`で組む。
fn decoded_pieces(decoded: &[DecodedLayer]) -> Vec<SummaryPiece> {
    decoded
        .iter()
        .map(|layer| {
            let place = match layer.source {
                EncodedSource::EncodedCommand | EncodedSource::EncodedArguments => "value",
                EncodedSource::FromBase64String => "argument",
            };
            let head = format!(
                "encoded payload, layer {} (the {place} of {})",
                layer.depth,
                layer.source.spelling()
            );
            let not_decoded = |why: String| SummaryPiece {
                label: format!("{head}, which the harness did not decode"),
                text: why,
            };
            match &layer.outcome {
                DecodeOutcome::Text { encoding, text } => SummaryPiece {
                    label: format!("{head}, decoded by the harness from {}", encoding.name()),
                    text: text.clone(),
                },
                DecodeOutcome::MissingValue => not_decoded("No value follows it.".to_string()),
                DecodeOutcome::NotBase64 => not_decoded(
                    "The value is not base64 (a variable or expression decided at run time)."
                        .to_string(),
                ),
                DecodeOutcome::NotText => not_decoded(
                    "The base64 decodes to bytes that are not text (possibly compressed or encrypted)."
                        .to_string(),
                ),
                DecodeOutcome::NotLiteral => not_decoded(
                    "The argument is not a plain string literal (decided at run time).".to_string(),
                ),
                DecodeOutcome::DepthLimit { max_depth } => not_decoded(format!(
                    "Nested more than {max_depth} layers deep; the harness stopped decoding here."
                )),
                DecodeOutcome::SizeLimit { max_bytes } => not_decoded(format!(
                    "Decoded material exceeded {max_bytes} bytes; the harness stopped decoding here."
                )),
                DecodeOutcome::CountLimit { max_layers } => not_decoded(format!(
                    "More than {max_layers} encoded payloads; the harness stopped decoding here."
                )),
            }
        })
        .collect()
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

/// 同じ中身を2回要約しないための鍵。**送る中身そのもの**（見出しと本文）と要約の言語で作る。
///
/// [BUG-220] 以前は見出しと**本文の長さ**だけで作っており、同じ長さの別の中身（`ls -la /tmp/x`と
/// `rm -rf /tmp/x`）に前の要約が出た。各欄は長さを前に付けて並べる——区切りの文字だけで並べると、
/// 中身に区切りの文字を書けば別の組と同じ鍵を作れる。言語を含めないと、言語が変わっても前の言語の要約が出る。
pub(crate) fn summary_key(pieces: &[SummaryPiece], language: Option<SummaryLanguage>) -> String {
    let mut key = format!("{};", language.map_or("", SummaryLanguage::english_name));
    for p in pieces {
        key.push_str(&format!(
            "{}:{}{}:{}",
            p.label.len(),
            p.label,
            p.text.len(),
            p.text
        ));
    }
    key
}

/// ユーザーが最後に入力した文（画面の transcript の最後の`User`）。要約の言語を決めるのに使う
/// （**文そのものは要約の呼び出しへ渡さない**。渡るのは[`SummaryLanguage`]の名前だけ）。
fn last_user_input(app: &AppState) -> Option<&str> {
    app.transcript.iter().rev().find_map(|item| match item {
        TranscriptItem::User(text) => Some(text.as_str()),
        _ => None,
    })
}

/// 承認要求1件につき1本だけ要約を起こす（B-23 の二重起動の防止）。
/// 返り値は**この要求のためのキャンセルトークン**で、モーダルが差し替わったら落とす。
///
/// `display_language`は Windows の表示言語（起動時に1回読む。試験は作って渡す）。要約の言語は、
/// ユーザーが最後に入力した文とこれから決める（[`SummaryLanguage::for_user`]）。
pub(crate) fn start_summary(
    summary: &ApprovalSummary,
    background: &UnboundedSender<BackgroundEvent>,
    app: &mut AppState,
    cache: &SummaryCache,
    read_scope: &harness_sandbox::ReadScope,
    redact_host_paths: bool,
    display_language: Option<SummaryLanguage>,
) -> Option<CancellationToken> {
    let pieces = summary_pieces(app, read_scope);
    if pieces.is_empty() {
        return None;
    }
    let language = SummaryLanguage::for_user(last_user_input(app), display_language);
    let key = summary_key(&pieces, language);
    let view = app.pending_permission.as_mut()?;
    if let Some(done) = cache.get(&key) {
        view.summary_source = Some(format!("{} / {}", summary.label, summary.model));
        view.summary = SummaryState::Done {
            text: done.clone(),
            took: None,
        };
        return None;
    }
    // **開始を即座に画面へ出す**（B-23）。無言で待たせない。
    // 出どころも一緒に出す——中身がどこへ出たのかを後から見て分かるようにする（D-100）。
    view.summary_source = Some(format!("{} / {}", summary.label, summary.model));
    view.summary = SummaryState::Running(SummaryWait::new(Instant::now()));
    let request = view.id.clone();

    let cancel = CancellationToken::new();
    let token = cancel.clone();
    let provider = summary.provider.clone();
    let model = summary.model.clone();
    let background = background.clone();
    // 途中経過（考えた量）を描画ループへ送る。届いた先で、いま待っている要求のものかを照合する（`on_background`）。
    let progress = background.clone();
    let progress_request = request.clone();
    let mut report = move |output_chars| {
        let _ = progress.send(BackgroundEvent::SummaryProgress {
            request: progress_request.clone(),
            output_chars,
        });
    };
    tokio::spawn(async move {
        let result = match summarize_for_approval(
            provider.as_ref(),
            &model,
            &pieces,
            redact_host_paths,
            language,
            &token,
            &mut report,
        )
        .await
        {
            // キャンセルされたときは何も送らない（モーダルはもう別のものを見ている）。
            Ok(None) => return,
            // 本文が空なら engine が`Err`で返す（BUG-214）。ここで空かどうかを見直さない——
            // 見直すと「なぜ空か」を持たない固定の文に戻ってしまう。
            Ok(Some(text)) => Ok(text),
            // 本文が空のときは「出力の上限で止まった・考える過程が何文字あった」まで文になる。
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
