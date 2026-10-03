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
    LlmProvider, PermissionSubject, ProgramRule, RiskCheck, RiskLevel, RiskVerdict, ShellRule,
};
use harness_engine::approval_ledger::{ApprovalStore, RecordedRule};
use harness_engine::approval_summary::{summarize_for_approval, SummaryLanguage, SummaryPiece};
use harness_engine::Remembered;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;
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

/// 承認画面の危険度判定（外の判定モデル。`harness_core::risk_check`）をどこへ聞くか。`harness-cli`が起動時に決める。
/// **これが無ければ（設定で切った・作れなかった）、承認画面も要約も今までと同じ**である。
pub struct ApprovalRisk {
    pub check: Arc<dyn RiskCheck>,
    /// 画面に出す出どころ（サーバ／モデル）。コマンドがどこへ出たのかが分かるように。
    pub label: String,
}

/// 要約を起こす前に、危険度の判定を待つ上限。**超えても失敗にはしない**——要約は危険度なしで先に起こし、
/// 判定はその後に届いても承認画面の色と見出しには反映する（要約に一言が入らないだけ）。
/// 判定モデルの初回の読み込みに約10秒かかる実測があり、その場合はここを超える。
pub(crate) const RISK_WAIT_FOR_SUMMARY: Duration = Duration::from_secs(5);

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
    /// 危険度の判定が届いた。`request`は承認要求のid、`line`は判定したコマンド行（同じ行を2回判定しないために覚える）。
    RiskReady {
        request: String,
        line: String,
        verdict: RiskVerdict,
    },
    /// 危険度の判定を得られなかった（`reason`は記録へ1回だけ書く。承認画面は今までどおり）。
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
            line,
            verdict,
        } => {
            // 同じ行は2回判定しない。承認要求が移っていても覚える（次に同じ行が来たとき即座に使える）。
            app.risk_seen.insert(line, verdict);
            if let Some(view) = app
                .pending_permission
                .as_mut()
                .filter(|view| view.id == request)
            {
                view.verdict = Some(verdict);
            }
        }
        BackgroundEvent::RiskUnavailable { reason } => {
            // 承認画面は今までどおりで、書くのは会話の記録にセッションにつき1回だけ。
            // **毎回の承認で繰り返さない**（判定モデルを止めている間、承認のたびに出るのを避ける）。
            if !app.risk_unavailable_noted {
                app.risk_unavailable_noted = true;
                app.transcript.push(TranscriptItem::Info(format!(
                    "承認画面の危険度判定を使えなかった（{reason}）。承認画面はこれまでどおり。\
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

/// 要約の鍵に入れる危険度の綴り。**要約へ一言を渡す段階（注意以上）だけを区別する**——低い・判定なしは
/// 今までと同じ要求なので、同じ鍵（空）になる。
fn risk_key(risk: Option<RiskLevel>) -> &'static str {
    match risk {
        Some(RiskLevel::Caution) => "caution",
        Some(RiskLevel::Danger) => "danger",
        Some(RiskLevel::Low) | None => "",
    }
}

/// 要約へ危険度を渡す段階。注意以上だけ（低いは渡さない。[`RiskLevel::summary_instruction`]）。
fn summary_hint(verdict: RiskVerdict) -> Option<RiskLevel> {
    verdict.level.is_elevated().then_some(verdict.level)
}

/// 危険度の判定の、要約を起こす側から見た状態。
pub(crate) enum RiskGate {
    /// 判定済み（同じ行を前に判定していた）。
    Ready(RiskVerdict),
    /// 判定を背景で走らせている。届けば受け取れ、届かずに終われば（失敗・キャンセル）送り手が落ちる。
    Pending(oneshot::Receiver<RiskVerdict>),
}

/// 判定を待った結果。
enum GateOutcome {
    /// 待っている間に承認要求が移った（要約を起こさず降りる）。
    Cancelled,
    /// 判定が間に合った。
    Verdict(RiskVerdict),
    /// 間に合わなかった・失敗した（要約は危険度なしで起こす＝今までと同じ）。
    Missing,
}

/// 判定を`wait`まで待つ。**待つ上限を超えても失敗にしない**（要約は危険度なしで進む）。
async fn wait_for_verdict(
    gate: RiskGate,
    wait: Duration,
    cancel: &CancellationToken,
) -> GateOutcome {
    match gate {
        RiskGate::Ready(verdict) => GateOutcome::Verdict(verdict),
        RiskGate::Pending(rx) => tokio::select! {
            biased;
            _ = cancel.cancelled() => GateOutcome::Cancelled,
            result = tokio::time::timeout(wait, rx) => match result {
                Ok(Ok(verdict)) => GateOutcome::Verdict(verdict),
                // 時間切れ・送り手が落ちた（判定の失敗）。
                _ => GateOutcome::Missing,
            },
        },
    }
}

/// 危険度の判定を起こす。対象は`run_shell`のコマンド行だけ（ほかの材料は判定しない）。
///
/// **判定が無い・遅い・落ちているときの承認画面は今までと同じ**——ここは画面へ足すだけで、
/// 何も待たせず、何も止めない。返り値の`RiskGate`は要約を起こす側が受け取る。
/// `cancel`は承認要求が移る・閉じるときに落とす。
pub(crate) fn start_risk(
    risk: &ApprovalRisk,
    background: &UnboundedSender<BackgroundEvent>,
    app: &mut AppState,
    cancel: &CancellationToken,
) -> Option<RiskGate> {
    let view = app.pending_permission.as_mut()?;
    let PermissionSubject::Command(command) = &view.subject else {
        return None;
    };
    let line = command.line.clone();
    let request = view.id.clone();
    view.verdict_source = Some(risk.label.clone());
    if let Some(known) = app.risk_seen.get(&line).copied() {
        // 同じ行を前に判定していた。聞き直さず、すぐ画面へ出す。
        if let Some(view) = app.pending_permission.as_mut() {
            view.verdict = Some(known);
        }
        return Some(RiskGate::Ready(known));
    }
    let (tx, rx) = oneshot::channel();
    let check = risk.check.clone();
    let background = background.clone();
    let token = cancel.clone();
    tokio::spawn(async move {
        let result = tokio::select! {
            biased;
            // キャンセルされたときは何も送らない（承認画面はもう別のものを見ている）。
            _ = token.cancelled() => return,
            result = check.assess(&line) => result,
        };
        match result {
            Ok(verdict) => {
                // 要約を待たせている側へ（間に合えば要約にも入る）、画面へ（いつ届いても色になる）。
                let _ = tx.send(verdict);
                let _ = background.send(BackgroundEvent::RiskReady {
                    request,
                    line,
                    verdict,
                });
            }
            Err(e) => {
                // `tx`を落とす（待っている要約が「判定なし」で進む）。画面へはセッションにつき1回だけ知らせる。
                drop(tx);
                let _ = background.send(BackgroundEvent::RiskUnavailable {
                    reason: e.to_string(),
                });
            }
        }
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
            let _ = check.assess("echo").await;
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
    let pieces = summary_pieces(app, read_scope);
    if pieces.is_empty() {
        return None;
    }
    let language = SummaryLanguage::for_user(last_user_input(app), display_language);
    // 判定済み（前に同じ行を判定していた）か、判定を使わない構成なら、その段階を鍵に入れて今すぐ使い回しを見る。
    let pending = matches!(risk, Some(RiskGate::Pending(_)));
    let known = match &risk {
        Some(RiskGate::Ready(verdict)) => summary_hint(*verdict),
        _ => None,
    };
    let key = summary_key(&pieces, language, known);
    // **判定を待っているときは、使い回しをこの時点で確定させない。** 判定が危険と出たら、危険度なしで
    // 作った前の要約（危険と言っていない要約）を出してはいけない。段階ごとの候補だけ先に引いておき、
    // 判定が決まってから選ぶ（間に合わなければ「危険度なし」の候補＝今までと同じ使い回しになる）。
    let candidates: Vec<(String, String)> = match pending {
        true => [None, Some(RiskLevel::Caution), Some(RiskLevel::Danger)]
            .into_iter()
            .filter_map(|hint| {
                let candidate_key = summary_key(&pieces, language, hint);
                cache.get(&candidate_key).map(|t| (candidate_key, t.clone()))
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
        // 判定を待つ（上限あり）。間に合えば要約へ危険度の一言を足し、間に合わなければ今までと同じ要求で起こす。
        let hint = match risk {
            None => None,
            Some(gate) => match wait_for_verdict(gate, RISK_WAIT_FOR_SUMMARY, &token).await {
                GateOutcome::Cancelled => return,
                GateOutcome::Verdict(verdict) => summary_hint(verdict),
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
