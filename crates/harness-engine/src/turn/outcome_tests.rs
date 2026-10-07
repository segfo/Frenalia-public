use super::*;

/// ディスパッチが実際に書く文（綴りはリテラルで書く——定数どうしを比べると、文言が変わっても緑のまま）。
#[test]
fn each_synthesized_result_is_told_apart() {
    let cases = [
        (
            "permission denied by policy: run_shell (Exec) — no rule matched this call",
            RecordedOutcome::Denied,
        ),
        (
            "invalid tool input for write_file: unknown field `command`",
            RecordedOutcome::InvalidInput,
        ),
        ("cancelled by user", RecordedOutcome::Cancelled),
        ("exit code 1\nstderr: nope", RecordedOutcome::RanWithError),
        ("unknown tool: nope", RecordedOutcome::RanWithError),
    ];
    for (content, expected) in cases {
        assert_eq!(RecordedOutcome::of(content, true), expected, "{content}");
    }
}

/// 書き写しを断った文は、断る文を組む関数そのもの（`Transcription::refusal_ja`）から作って見分ける。
#[test]
fn a_transcription_refusal_is_told_apart() {
    let t = harness_core::user_reference::Transcription {
        back: 0,
        number: 1,
        written_chars: 63,
        value_chars: 64,
        differences: 1,
    };
    let content = t.refusal_ja("  {{val:1}} 64文字・ユーザーの文から\n");
    assert_eq!(
        RecordedOutcome::of(&content, true),
        RecordedOutcome::RefusedTranscription
    );
}

/// 対: エラーでない結果は、頭が何であっても「実行した」。成功した出力（ファイルの中身等）が
/// 拒否の文で始まっていても、拒否とは読まない。
#[test]
fn a_successful_result_is_ran_whatever_it_starts_with() {
    for content in [
        "permission denied by policy: (this is just file content)",
        "cancelled by user",
        "hello",
    ] {
        assert_eq!(
            RecordedOutcome::of(content, false),
            RecordedOutcome::Ran,
            "{content}"
        );
    }
}
