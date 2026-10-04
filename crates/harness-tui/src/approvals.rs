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
use std::time::{Duration, Instant};

use harness_core::{
    DecisionModel, DecodeOutcome, DecodedLayer, EncodedSource, LlmProvider, PermissionSubject,
    ProgramRule, RiskLevel, ShellRule,
};
use harness_engine::approval_ledger::{ApprovalStore, RecordedRule};
use harness_engine::approval_risk::{self, RiskOutcome};
use harness_engine::approval_summary::{summarize_for_approval, SummaryLanguage, SummaryPiece};
use harness_engine::encoded_span::SpanLocator;
use harness_engine::Remembered;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::app::{AppState, PreviousCopy, RiskView, SummaryState, SummaryWait, TranscriptItem};
use crate::engine::EngineHandle;

/// 承認画面の要約（D-100）をどこで作るか。`harness-cli`が起動時に決める。
pub struct ApprovalSummary {
    /// 要約に使うプロバイダ。会話と同じものを共有していることもある。
    pub provider: Arc<dyn LlmProvider>,
    pub model: String,
    /// 画面に出す出どころ（「どこへ中身が出たか」が後から分かるように）。
    pub label: String,
}

/// 承認画面の危険度判定に使う判定モデル（Ollaya。`harness_core::decision`）をどこへ聞くか。`harness-cli`が起動時に決める。
/// **これが無ければ（設定で切った・作れなかった）、危険度は機械の判定だけで出す**（`harness_engine::approval_risk`）。
pub struct ApprovalRisk {
    pub check: Arc<dyn DecisionModel>,
    /// 画面に出す出どころ（サーバ／モデル）。コマンドがどこへ出たのかが分かるように。
    pub label: String,
    /// 解読する箇所を選ばせる LLM（`harness_engine::encoded_span`）。**要約と同じプロバイダとモデル**で、
    /// 起動時に要約の設定から組む（`harness_tui::run`）。要約を作らない設定なら`None`（選ばせない）。
    pub locator: Option<Arc<dyn SpanLocator>>,
}

/// 要約を起こす前に、危険度の判定を待つ上限。**判定モデルを使うときは、危険度を先に出してから要約する**
/// （ユーザーの指示。要約に危険の一言を入れるため）。**超えても失敗にはしない**——要約は危険度なしで起こし、
/// 判定はその後に届いても承認画面の色と見出しには反映する（要約に一言が入らないだけ）。
///
/// 判定は2回の問い合わせ（約3秒）＋解読した段（1段約1秒）＋縛ったファイル（4,000字で約12秒）で、
/// 多いと10秒を超える（`plans/risk-judge-spike/RESULTS.md` §1）。判定モデルの初回の読み込みにも約10秒かかる。
pub(crate) const RISK_WAIT_FOR_SUMMARY: Duration = Duration::from_secs(30);

/// 判定モデルを温めておく間隔の下限。同じ間隔の中では2度呼ばない。
const RISK_WARM_EVERY: Duration = Duration::from_secs(60);

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
    /// 判定モデルまで使った危険度が届いた。`request`は承認要求のid、`key`は判定に使った材料の鍵
    /// （同じ材料を2回判定しないために覚える。`approval_risk::cache_key`）。
    RiskReady {
        request: String,
        key: String,
        outcome: RiskOutcome,
    },
    /// 判定モデルを使えなかった（`reason`は記録へ1回だけ書く。危険度は機械の判定だけで出している）。
    RiskUnavailable { reason: String },
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
        BackgroundEvent::RiskReady {
            request,
            key,
            outcome,
        } => {
            // 同じ材料は2回判定しない。承認要求が移っていても覚える（次に同じ材料が来たとき即座に使える）。
            // **判定モデルが答えなかった回は覚えない**——覚えると、判定モデルが戻っても聞き直さない。
            if outcome.model_error().is_none() {
                app.risk_seen.insert(key, outcome.clone());
            }
            if let Some(assessment) = app
                .pending_permission
                .as_mut()
                .filter(|view| view.id == request)
                .and_then(|view| view.assessment.as_mut())
            {
                assessment.outcome = outcome;
                assessment.waiting = None;
            }
        }
        BackgroundEvent::RiskUnavailable { reason } => {
            // 危険度は機械の判定だけで出していて、書くのは会話の記録にセッションにつき1回だけ。
            // **毎回の承認で繰り返さない**（判定モデルを止めている間、承認のたびに出るのを避ける）。
            if !app.risk_unavailable_noted {
                app.risk_unavailable_noted = true;
                app.transcript.push(TranscriptItem::Info(format!(
                    "承認画面の判定モデルを使えなかった（{reason}）。危険度は機械の判定だけで出す。\
                     このセッションでは以後知らせない"
                )));
            }
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
            let head = match layer.source {
                EncodedSource::EncodedCommand | EncodedSource::EncodedArguments => format!(
                    "encoded payload, layer {} (the value of {})",
                    layer.depth,
                    layer.source.spelling()
                ),
                EncodedSource::FromBase64String => format!(
                    "encoded payload, layer {} (the argument of {})",
                    layer.depth,
                    layer.source.spelling()
                ),
                EncodedSource::BareBase64 => format!(
                    "encoded payload, layer {} (a base64 string sitting in the command line)",
                    layer.depth
                ),
                EncodedSource::LocatedByModel(encoding) => format!(
                    "encoded payload, layer {} (a {} string that a model pointed at)",
                    layer.depth,
                    encoding.name()
                ),
            };
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
                DecodeOutcome::Unreadable => not_decoded(
                    "It does not decode as the encoding the model named.".to_string(),
                ),
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
pub(crate) fn summary_key(
    pieces: &[SummaryPiece],
    language: Option<SummaryLanguage>,
    risk: Option<RiskLevel>,
) -> String {
    let mut key = format!(
        "{};{};",
        language.map_or("", SummaryLanguage::english_name),
        risk_key(risk)
    );
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

/// 要約の鍵に入れる危険度の綴り。**要約へ一言を渡す段階（危険）だけを区別する**——低い・判定なしは
/// 今までと同じ要求なので、同じ鍵（空）になる。
fn risk_key(risk: Option<RiskLevel>) -> &'static str {
    match risk {
        Some(RiskLevel::Danger) => "danger",
        Some(RiskLevel::Low) | None => "",
    }
}

/// 危険度の判定の、要約を起こす側から見た状態。
pub(crate) enum RiskGate {
    /// 決まっている（機械の判定だけの設定・前に同じ材料を判定していた）。
    Ready(RiskOutcome),
    /// 判定モデルまで使う判定を背景で走らせている。届けば受け取れ、届かずに終われば（キャンセル）送り手が落ちる。
    Pending(oneshot::Receiver<RiskOutcome>),
}

/// 判定を待った結果。
enum GateOutcome {
    /// 待っている間に承認要求が移った（要約を起こさず降りる）。
    Cancelled,
    /// 判定が間に合った。
    Verdict(RiskOutcome),
    /// 間に合わなかった（要約は危険度なしで起こす）。
    Missing,
}

/// 判定を`wait`まで待つ。**待つ上限を超えても失敗にしない**（要約は危険度なしで進む）。
async fn wait_for_verdict(
    gate: RiskGate,
    wait: Duration,
    cancel: &CancellationToken,
) -> GateOutcome {
    match gate {
        RiskGate::Ready(outcome) => GateOutcome::Verdict(outcome),
        RiskGate::Pending(rx) => tokio::select! {
            biased;
            _ = cancel.cancelled() => GateOutcome::Cancelled,
            result = tokio::time::timeout(wait, rx) => match result {
                Ok(Ok(outcome)) => GateOutcome::Verdict(outcome),
                // 時間切れ・送り手が落ちた（判定の失敗）。
                _ => GateOutcome::Missing,
            },
        },
    }
}

/// 危険度の判定を起こす（D-100 の追記。組み立ては`harness_engine::approval_risk`）。対象は`run_shell`の行と
/// `run_program`の起動で、書込先・その他の材料は判定しない（`None`）。
///
/// **開いた時点で機械の判定を画面へ出す**（すぐ終わる）。`risk`（判定モデル）があれば背景で全部を判定し、届いたら
/// 置き換える。返り値の`RiskGate`は要約を起こす側が受け取る。`cancel`は承認要求が移る・閉じるときに落とす。
///
/// **流れ（このプロセスで実際に走ったコマンド）は引数で受けず、`app.command_history`から自分で読む**——呼ぶ側に
/// 渡し忘れる余地を残さない（`bug-pattern-rules` B-06 の「選ぶ自由を奪う」）。
pub(crate) fn start_risk(
    risk: Option<&ApprovalRisk>,
    background: &UnboundedSender<BackgroundEvent>,
    app: &mut AppState,
    cancel: &CancellationToken,
) -> Option<RiskGate> {
    let history = app.command_history.entries();
    let history = history.as_slice();
    let view = app.pending_permission.as_ref()?;
    let machine = approval_risk::machine(&view.subject)?;
    let Some(risk) = risk else {
        // 判定モデルを使わない設定。機械の判定で決まり（待つものは無い）。
        let view = app.pending_permission.as_mut()?;
        view.assessment = Some(RiskView::done(machine.clone(), None));
        return Some(RiskGate::Ready(machine));
    };
    let key = approval_risk::cache_key(&view.subject, history)?;
    if let Some(known) = app.risk_seen.get(&key).cloned() {
        // 同じ材料を前に判定していた。聞き直さず、すぐ画面へ出す。
        let view = app.pending_permission.as_mut()?;
        view.assessment = Some(RiskView::done(known.clone(), Some(risk.label.clone())));
        return Some(RiskGate::Ready(known));
    }
    let view = app.pending_permission.as_mut()?;
    view.assessment = Some(RiskView::waiting(
        machine,
        risk.label.clone(),
        Instant::now(),
    ));
    let subject = view.subject.clone();
    let request = view.id.clone();
    let history = history.to_vec();
    let (tx, rx) = oneshot::channel();
    let check = risk.check.clone();
    let locator = risk.locator.clone();
    let background = background.clone();
    let token = cancel.clone();
    tokio::spawn(async move {
        let outcome = tokio::select! {
            biased;
            // キャンセルされたときは何も送らない（承認画面はもう別のものを見ている）。
            _ = token.cancelled() => return,
            outcome = approval_risk::assess(&subject, &history, Some(&*check), locator.as_deref()) => outcome,
        };
        let Some(outcome) = outcome else {
            return;
        };
        if let Some(reason) = outcome.model_error() {
            // 画面へはセッションにつき1回だけ知らせる（危険度は機械の判定だけで出ている）。
            let _ = background.send(BackgroundEvent::RiskUnavailable {
                reason: reason.to_string(),
            });
        }
        // 要約を待たせている側へ（間に合えば要約にも入る）、画面へ（いつ届いても色になる）。
        let _ = tx.send(outcome.clone());
        let _ = background.send(BackgroundEvent::RiskReady {
            request,
            key,
            outcome,
        });
    });
    Some(RiskGate::Pending(rx))
}

/// 判定モデルを温めておく。判定モデルは放置すると解放され、次の呼び出しで読み込み直す（約10秒。実測）ので、
/// **ユーザーが依頼を送った時点**で無害な固定の1行を投げておき、承認が出る頃には読み込み済みにする。
/// 結果は捨てる——**失敗も知らせない**（承認で判定を使うときに、使えなければ1回だけ知らせる）。
pub(crate) struct RiskWarmUp {
    last: Option<Instant>,
}

impl RiskWarmUp {
    pub(crate) fn new() -> Self {
        Self { last: None }
    }

    /// 前回から[`RISK_WARM_EVERY`]以上空いていれば、温める呼び出しを背景で1回起こす。
    pub(crate) fn nudge(&mut self, risk: &ApprovalRisk, now: Instant) -> bool {
        if self
            .last
            .is_some_and(|last| now.saturating_duration_since(last) < RISK_WARM_EVERY)
        {
            return false;
        }
        self.last = Some(now);
        let check = risk.check.clone();
        tokio::spawn(async move {
            // 固定の無害な1行。**ユーザーの入力もコマンドも送らない。**
            let _ = harness_core::assess_command_risk(&*check, "echo").await;
        });
        true
    }
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
#[allow(clippy::too_many_arguments)] // 呼び出し元は`lib.rs`の1箇所で、引数は承認ごとに違う部品そのもの
pub(crate) fn start_summary(
    summary: &ApprovalSummary,
    background: &UnboundedSender<BackgroundEvent>,
    app: &mut AppState,
    cache: &SummaryCache,
    read_scope: &harness_sandbox::ReadScope,
    redact_host_paths: bool,
    display_language: Option<SummaryLanguage>,
    risk: Option<RiskGate>,
) -> Option<CancellationToken> {
    let mut pieces = summary_pieces(app, read_scope);
    // 判定が決まっていれば、LLM が場所を示してハーネスが解読した段も材料に入れる（待っているなら届いてから足す）。
    let extra_added = match &risk {
        Some(RiskGate::Ready(outcome)) => {
            pieces.extend(decoded_pieces(&outcome.extra_decoded));
            true
        }
        _ => false,
    };
    if pieces.is_empty() {
        return None;
    }
    let language = SummaryLanguage::for_user(last_user_input(app), display_language);
    // 判定済み（前に同じ行を判定していた）か、判定を使わない構成なら、その段階を鍵に入れて今すぐ使い回しを見る。
    let pending = matches!(risk, Some(RiskGate::Pending(_)));
    let known = match &risk {
        Some(RiskGate::Ready(outcome)) => outcome.severity().summary_hint(),
        _ => None,
    };
    let key = summary_key(&pieces, language, known);
    // **判定を待っているときは、使い回しをこの時点で確定させない。** 判定が危険と出たら、危険度なしで
    // 作った前の要約（危険と言っていない要約）を出してはいけない。段階ごとの候補だけ先に引いておき、
    // 判定が決まってから選ぶ（間に合わなければ「危険度なし」の候補＝今までと同じ使い回しになる）。
    let candidates: Vec<(String, String)> = match pending {
        true => [None, Some(RiskLevel::Danger)]
            .into_iter()
            .filter_map(|hint| {
                let candidate_key = summary_key(&pieces, language, hint);
                cache
                    .get(&candidate_key)
                    .map(|t| (candidate_key, t.clone()))
            })
            .collect(),
        false => Vec::new(),
    };
    let view = app.pending_permission.as_mut()?;
    if !pending {
        if let Some(done) = cache.get(&key) {
            view.summary_source = Some(format!("{} / {}", summary.label, summary.model));
            view.summary = SummaryState::Done {
                text: done.clone(),
                took: None,
            };
            return None;
        }
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
        let mut pieces = pieces;
        // 判定を待つ（上限あり）。間に合えば要約へ危険度の一言と、LLM が場所を示して解読した段を足し、
        // 間に合わなければ今までと同じ要求で起こす。
        let hint = match risk {
            None => None,
            Some(gate) => match wait_for_verdict(gate, RISK_WAIT_FOR_SUMMARY, &token).await {
                GateOutcome::Cancelled => return,
                GateOutcome::Verdict(outcome) => {
                    if !extra_added {
                        pieces.extend(decoded_pieces(&outcome.extra_decoded));
                    }
                    outcome.severity().summary_hint()
                }
                GateOutcome::Missing => None,
            },
        };
        // 送る中身が決まったので、使い回しの鍵もここで決める（判定が間に合った場合は段階が入る）。
        let key = summary_key(&pieces, language, hint);
        // 判定を待っていた間に引いておいた候補に、決まった段階の要約があれば、それを使う（LLMを呼ばない）。
        if let Some((_, text)) = candidates.iter().find(|(candidate, _)| *candidate == key) {
            let _ = background.send(BackgroundEvent::SummaryReady {
                request,
                key,
                result: Ok(text.clone()),
            });
            return;
        }
        let result = match summarize_for_approval(
            provider.as_ref(),
            &model,
            &pieces,
            redact_host_paths,
            language,
            hint,
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

#[cfg(test)]
#[path = "approvals_risk_tests.rs"]
mod approvals_risk_tests;
