//! 承認の台帳と要約の配線の回帰テスト（D-100・D-107）。内部関数（`summary_pieces`・
//! `summary_key`・`on_background`）へ触れるため`#[cfg(test)]`のまま別ファイルへ分けている
//! （`docs/CODE-STRUCTURE-RULES.md`規則2）。

use super::*;
use harness_core::ReadScopeConfig;
use harness_core::{CommandSubject, FilePreview, ProgramSubject, RiskClass};
use harness_sandbox::ReadScope;
use std::time::{Duration, Instant};

fn preview(rel: &str, text: &str) -> FilePreview {
    FilePreview {
        rel_path: rel.to_string(),
        text: text.to_string(),
        truncated: false,
    }
}

/// 縛ったファイル（中身は要らないので、ハッシュは形だけ合わせる）。
fn bound(rel: &str) -> harness_core::BoundFile {
    harness_core::BoundFile {
        rel_path: rel.to_string(),
        sha256: "a".repeat(64),
        dir_listing_sha256: None,
    }
}

pub(super) fn app_with(subject: PermissionSubject) -> AppState {
    let mut app = AppState::new("mock".into(), "m".into());
    app.workspace_root = "C:/ws".into();
    app.pending_permission = Some(crate::app::PermissionView::new(
        "perm-0".into(),
        "run_program".into(),
        RiskClass::Exec,
        subject,
        "{}".into(),
        None,
        "C:/ws".into(),
    ));
    app
}

pub(super) fn open_scope(cfg: ReadScopeConfig) -> ReadScope {
    ReadScope::open(&cfg)
}

/// 縛ったファイルの中身と、その場のコードが要約へ回る。
#[test]
fn the_material_is_the_bound_files_and_any_inline_code() {
    let mut p = ProgramSubject::plain("python", vec!["build.py".into()]);
    p.files = vec![bound("build.py")];
    p.one_shot_only = false;
    p.previews = vec![preview("build.py", "print('hi')")];
    let app = app_with(PermissionSubject::Program(p));
    let pieces = summary_pieces(&app, &open_scope(ReadScopeConfig::default()));
    assert_eq!(pieces.len(), 1, "縛れたのでコードそのものは回さない");
    assert_eq!(pieces[0].label, "build.py");
    assert_eq!(pieces[0].text, "print('hi')");

    // ファイルに縛れない＝引数そのものがコード。
    let p = ProgramSubject::plain("pwsh", vec!["-c".into(), "Get-Date".into()]);
    let app = app_with(PermissionSubject::Program(p));
    let pieces = summary_pieces(&app, &open_scope(ReadScopeConfig::default()));
    assert_eq!(pieces.len(), 1);
    assert!(pieces[0].text.contains("Get-Date"));

    // 解読した`-EncodedCommand`があればそちらを出す。
    let mut p = ProgramSubject::plain("pwsh", vec!["-enc".into(), "RwBl".into()]);
    p.decoded_inline = Some("Get-Date".into());
    let app = app_with(PermissionSubject::Program(p));
    let pieces = summary_pieces(&app, &open_scope(ReadScopeConfig::default()));
    assert_eq!(pieces[0].label, "the decoded -EncodedCommand");

    // `run_shell`は行そのものも回す。
    let mut c = CommandSubject::line_only("python build.py");
    c.previews = vec![preview("build.py", "print('hi')")];
    let app = app_with(PermissionSubject::Command(c));
    let pieces = summary_pieces(&app, &open_scope(ReadScopeConfig::default()));
    assert_eq!(pieces.len(), 2);
    assert_eq!(pieces[0].label, "the shell line");
}

/// **読取スコープで拒否される中身は送らない**（D-100）。承認のために読むときは子と同じ見え方を
/// するので読取スコープを通していないが、外のプロバイダへ出すのは別の話である。
#[test]
fn material_the_user_said_not_to_read_is_never_sent() {
    let mut p = ProgramSubject::plain("python", vec!["build.py".into()]);
    p.files = vec![bound("build.py"), bound(".env")];
    p.one_shot_only = false;
    p.previews = vec![preview("build.py", "print"), preview(".env", "TOKEN=x")];
    let app = app_with(PermissionSubject::Program(p));

    let allowed = summary_pieces(&app, &open_scope(ReadScopeConfig::default()));
    assert_eq!(allowed.len(), 2, "対照: 既定では両方送る");

    let denied = summary_pieces(
        &app,
        &open_scope(ReadScopeConfig {
            deny: vec![".env".to_string()],
            ..Default::default()
        }),
    );
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0].label, "build.py");
}

/// 中身が違えば鍵も違う（使い回しで別の中身の要約を出さない）。
#[test]
fn the_reuse_key_changes_with_the_material() {
    let a = vec![SummaryPiece {
        label: "a".into(),
        text: "one".into(),
    }];
    let b = vec![SummaryPiece {
        label: "a".into(),
        text: "three".into(),
    }];
    assert_ne!(summary_key(&a, None, None), summary_key(&b, None, None));
    assert_eq!(
        summary_key(&a, None, None),
        summary_key(&a.clone(), None, None)
    );
}

/// **長さが同じでも、中身が違えば鍵は違う**（[BUG-220](../../../docs/bugs/BUG-220.md)）。以前の鍵は
/// 見出しと**中身の長さ**だけで作っており、同じ長さの別の行・別の中身に、前に作った要約がそのまま出た。
/// 変わったことにハッシュが気づいて聞き直したまさにその場面で、変わる前の説明を見せることになる。
#[test]
fn material_of_the_same_length_does_not_share_a_key() {
    let line = |text: &str| {
        vec![SummaryPiece {
            label: "the shell line".into(),
            text: text.into(),
        }]
    };
    let listed = line("ls -la /tmp/x");
    let removed = line("rm -rf /tmp/x");
    assert_eq!(
        listed[0].text.len(),
        removed[0].text.len(),
        "前提: 長さが同じ"
    );
    assert_ne!(
        summary_key(&listed, None, None),
        summary_key(&removed, None, None)
    );

    // 区切りの文字を中身に混ぜても、別の組と同じ鍵にはならない（見出しと中身の境目を偽れない）。
    let one = vec![SummaryPiece {
        label: "a".into(),
        text: "x\u{2}b\u{1}y".into(),
    }];
    let two = vec![
        SummaryPiece {
            label: "a".into(),
            text: "x".into(),
        },
        SummaryPiece {
            label: "b".into(),
            text: "y".into(),
        },
    ];
    assert_ne!(summary_key(&one, None, None), summary_key(&two, None, None));
}

/// **別の承認要求へ移っていたら、遅れて届いた要約は捨てる。** 前の中身の説明を、
/// いま聞かれている呼び出しの説明として出さない。
#[test]
fn a_summary_that_arrives_after_the_modal_changed_is_discarded() {
    let mut app = app_with(PermissionSubject::Command(CommandSubject::line_only("a")));
    let mut cache = SummaryCache::new();

    on_background(
        BackgroundEvent::SummaryReady {
            request: "perm-9".into(),
            key: "k".into(),
            result: Ok("古い要約".into()),
        },
        &mut app,
        &mut cache,
        Instant::now(),
    );
    assert_eq!(
        app.pending_permission.as_ref().unwrap().summary,
        crate::app::SummaryState::Off
    );
    // 使い回しの表には入る（同じ中身をもう一度要約しないため）。
    assert_eq!(cache.get("k").map(String::as_str), Some("古い要約"));

    on_background(
        BackgroundEvent::SummaryReady {
            request: "perm-0".into(),
            key: "k2".into(),
            result: Ok("いまの要約".into()),
        },
        &mut app,
        &mut cache,
        Instant::now(),
    );
    assert_eq!(
        app.pending_permission.as_ref().unwrap().summary,
        crate::app::SummaryState::Done {
            text: "いまの要約".into(),
            took: None
        }
    );
}

/// 台帳への書込の結果は、成功なら通知、失敗ならエラーとして画面に出る。
#[test]
fn the_ledger_write_result_is_visible() {
    let mut app = app_with(PermissionSubject::Command(CommandSubject::line_only("a")));
    let mut cache = SummaryCache::new();
    on_background(
        BackgroundEvent::ApprovalRecorded(Err("書けなかった".into())),
        &mut app,
        &mut cache,
        Instant::now(),
    );
    assert!(matches!(
        app.transcript.last(),
        Some(TranscriptItem::Error(m)) if m == "書けなかった"
    ));
}

/// 要約に回すものが無ければ起こさない／同じ中身なら使い回す（B-23 の二重起動の防止）。
/// どちらも**プロバイダを1度も呼ばない**ので、ここでは起動しないことだけを見る。
#[tokio::test]
async fn a_summary_is_not_started_twice_for_the_same_material() {
    struct Never;
    #[async_trait::async_trait]
    impl harness_core::LlmProvider for Never {
        fn id(&self) -> &str {
            "never"
        }
        async fn stream(
            &self,
            _req: harness_core::CompletionRequest,
        ) -> Result<
            futures::stream::BoxStream<
                'static,
                Result<harness_core::StreamEvent, harness_core::ProviderError>,
            >,
            harness_core::ProviderError,
        > {
            panic!("the summariser must not be called here");
        }
    }

    let summary = ApprovalSummary {
        provider: Arc::new(Never),
        model: "m".into(),
        label: "mock / ".into(),
    };
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let scope = open_scope(ReadScopeConfig::default());

    // 回すものが無い（書込先パスの承認）。
    let mut app = app_with(PermissionSubject::WritePath("a.txt".into()));
    assert!(start_summary(
        &summary,
        &tx,
        &mut app,
        &SummaryCache::new(),
        &scope,
        false,
        None,
        None
    )
    .is_none());

    // 同じ中身は使い回す。
    let mut c = CommandSubject::line_only("cargo test");
    c.previews = vec![];
    let mut app = app_with(PermissionSubject::Command(c));
    let key = summary_key(&summary_pieces(&app, &scope), None, None);
    let mut cache = SummaryCache::new();
    cache.insert(key, "前に作った要約".into());
    assert!(start_summary(&summary, &tx, &mut app, &cache, &scope, false, None, None).is_none());
    assert_eq!(
        app.pending_permission.as_ref().unwrap().summary,
        crate::app::SummaryState::Done {
            text: "前に作った要約".into(),
            took: None
        }
    );
}

/// **考える過程だけで出力の上限に達し、本文が空のまま止まったら、そう画面に出す**（BUG-214）。
/// 以前は「モデルが空の要約を返した」という固定の文しか出ず、原因（上限で止まった・考える過程で
/// 使い切った）が画面から読めなかった。実機で見た形（`reasoning_content`だけで
/// `finish_reason: "length"`）を、製品の入口`start_summary`から流して確かめる。
#[tokio::test]
async fn a_summary_cut_off_while_thinking_says_so_on_screen() {
    use harness_core::{BlockKind, StopReason, StreamEvent, Usage};

    struct ThinksPastTheLimit;
    #[async_trait::async_trait]
    impl harness_core::LlmProvider for ThinksPastTheLimit {
        fn id(&self) -> &str {
            "thinks-past-the-limit"
        }
        async fn stream(
            &self,
            _req: harness_core::CompletionRequest,
        ) -> Result<
            futures::stream::BoxStream<'static, Result<StreamEvent, harness_core::ProviderError>>,
            harness_core::ProviderError,
        > {
            let events = vec![
                StreamEvent::BlockStart {
                    index: usize::MAX,
                    kind: BlockKind::Thinking,
                },
                StreamEvent::ThinkingDelta {
                    index: usize::MAX,
                    text: "The user wants a summary of (ls).name. ".repeat(40),
                },
                StreamEvent::BlockStop { index: usize::MAX },
                StreamEvent::Done {
                    stop_reason: StopReason::MaxTokens,
                    usage: Usage::default(),
                },
            ];
            Ok(Box::pin(futures::stream::iter(events.into_iter().map(Ok))))
        }
    }

    let summary = ApprovalSummary {
        provider: Arc::new(ThinksPastTheLimit),
        model: "m".into(),
        label: "mock / ".into(),
    };
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let scope = open_scope(ReadScopeConfig::default());
    let mut app = app_with(PermissionSubject::Command(CommandSubject::line_only(
        "powershell.exe -Command (ls).name",
    )));
    let mut cache = SummaryCache::new();

    assert!(start_summary(&summary, &tx, &mut app, &cache, &scope, false, None, None).is_some());
    apply_until_ready(&mut rx, &mut app, &mut cache).await;

    let crate::app::SummaryState::Failed { reason, .. } =
        &app.pending_permission.as_ref().unwrap().summary
    else {
        panic!(
            "失敗として出ていない: {:?}",
            app.pending_permission.as_ref().unwrap().summary
        );
    };
    assert!(
        reason.contains("出力の上限"),
        "上限で止まったと言っていない: {reason}"
    );
    assert!(
        reason.contains("考える過程"),
        "考える過程に触れていない: {reason}"
    );
    assert!(cache.is_empty(), "失敗を使い回しの表へ入れない");
}

/// 背景から届くもの（途中経過と結果）を、結果が届くまで画面へ反映する。
pub(super) async fn apply_until_ready(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<BackgroundEvent>,
    app: &mut AppState,
    cache: &mut SummaryCache,
) {
    loop {
        let event = rx.recv().await.expect("要約の結果が届かない");
        let ready = matches!(event, BackgroundEvent::SummaryReady { .. });
        on_background(event, app, cache, Instant::now());
        if ready {
            return;
        }
    }
}

/// 送られた要求を控え、本文1行を返すプロバイダ（何が要約の呼び出しへ渡ったかを見る）。
#[derive(Default)]
pub(super) struct Capturing {
    pub(super) seen: std::sync::Mutex<Vec<harness_core::CompletionRequest>>,
}

#[async_trait::async_trait]
impl harness_core::LlmProvider for Capturing {
    fn id(&self) -> &str {
        "capturing"
    }
    async fn stream(
        &self,
        req: harness_core::CompletionRequest,
    ) -> Result<
        futures::stream::BoxStream<
            'static,
            Result<harness_core::StreamEvent, harness_core::ProviderError>,
        >,
        harness_core::ProviderError,
    > {
        self.seen.lock().unwrap().push(req);
        let events = vec![
            harness_core::StreamEvent::TextDelta {
                index: 0,
                text: "ファイルを消す。".to_string(),
            },
            harness_core::StreamEvent::Done {
                stop_reason: harness_core::StopReason::EndTurn,
                usage: Default::default(),
            },
        ];
        Ok(Box::pin(futures::stream::iter(events.into_iter().map(Ok))))
    }
}

/// 製品の入口`start_summary`から要約を1本起こし、結果を画面へ反映するまで待つ。送った要求を返す。
async fn summarize_through_the_screen(
    app: &mut AppState,
    display_language: Option<SummaryLanguage>,
) -> harness_core::CompletionRequest {
    let provider = Arc::new(Capturing::default());
    let summary = ApprovalSummary {
        provider: provider.clone(),
        model: "m".into(),
        label: "mock / ".into(),
    };
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let scope = open_scope(ReadScopeConfig::default());
    let mut cache = SummaryCache::new();
    assert!(
        start_summary(
            &summary,
            &tx,
            app,
            &cache,
            &scope,
            false,
            display_language,
            None
        )
        .is_some(),
        "要約が起きなかった"
    );
    apply_until_ready(&mut rx, app, &mut cache).await;
    let seen = provider.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    seen[0].clone()
}

/// **ユーザーが日本語で書いていれば、要約を日本語で書かせる。ユーザーの文そのものは要求のどこにも載らない**
/// （D-100「要約の言語」）。要約は会話と別のプロバイダへ送れるので、渡すのは言語の名前だけである。
#[tokio::test]
async fn the_summary_is_asked_for_in_the_users_language_without_sending_the_users_words() {
    let mut app = app_with(PermissionSubject::Command(CommandSubject::line_only(
        "rm -rf build",
    )));
    let words = "ビルドの成果物を消しておいて（秘密の合言葉 ZEBRA-42）";
    app.push_user_prompt(words.to_string());

    // 表示言語は英語にしておく（文から決まったことを見るため）。
    let req = summarize_through_the_screen(&mut app, Some(SummaryLanguage::English)).await;

    assert!(
        req.system[0]
            .text
            .ends_with("\n- Write the summary in Japanese."),
        "{}",
        req.system[0].text
    );
    let everything = format!("{req:?}");
    assert!(
        !everything.contains("ZEBRA-42"),
        "ユーザーの文が要求に載っている"
    );
    assert!(
        !everything.contains("成果物"),
        "ユーザーの文が要求に載っている"
    );
    assert!(
        matches!(
            &app.pending_permission.as_ref().unwrap().summary,
            crate::app::SummaryState::Done { text, .. } if text == "ファイルを消す。"
        ),
        "{:?}",
        app.pending_permission.as_ref().unwrap().summary
    );
}

/// **ラテン文字だけの入力・入力がまだ無いときは表示言語、それも無ければ言語を足さない**（今までの要求）。
#[tokio::test]
async fn without_a_deciding_script_the_display_language_is_used() {
    let mut app = app_with(PermissionSubject::Command(CommandSubject::line_only("ls")));
    app.push_user_prompt("list the files".to_string());
    let req = summarize_through_the_screen(&mut app, Some(SummaryLanguage::German)).await;
    assert!(req.system[0]
        .text
        .ends_with("\n- Write the summary in German."));

    let mut app = app_with(PermissionSubject::Command(CommandSubject::line_only("ls")));
    let req = summarize_through_the_screen(&mut app, Some(SummaryLanguage::Japanese)).await;
    assert!(req.system[0]
        .text
        .ends_with("\n- Write the summary in Japanese."));

    let mut app = app_with(PermissionSubject::Command(CommandSubject::line_only("ls")));
    let req = summarize_through_the_screen(&mut app, None).await;
    assert!(
        !req.system[0].text.contains("Write the summary in"),
        "言語が決まらないのに言語を足した"
    );
}

/// **言語が違えば鍵も違う。** 含めないと、言語が変わっても前の言語の要約が使い回される。
#[test]
fn the_reuse_key_changes_with_the_language() {
    let pieces = vec![SummaryPiece {
        label: "the shell line".into(),
        text: "ls".into(),
    }];
    let none = summary_key(&pieces, None, None);
    let ja = summary_key(&pieces, Some(SummaryLanguage::Japanese), None);
    let en = summary_key(&pieces, Some(SummaryLanguage::English), None);
    assert_ne!(none, ja);
    assert_ne!(ja, en);
    assert_eq!(
        ja,
        summary_key(&pieces.clone(), Some(SummaryLanguage::Japanese), None)
    );
}

/// **使い回すのは、中身も言語も同じときだけ**（製品の入口から）。[BUG-220] 以前は同じ長さの別の行に、
/// 前の行の要約がそのまま出た。言語が変わったときも前の言語の要約を出さない。
#[tokio::test]
async fn a_cached_summary_is_reused_only_for_the_same_material_and_language() {
    let summary = ApprovalSummary {
        provider: Arc::new(Capturing::default()),
        model: "m".into(),
        label: "mock / ".into(),
    };
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let scope = open_scope(ReadScopeConfig::default());
    let ja = Some(SummaryLanguage::Japanese);

    // `ls -la /tmp/x`の要約を日本語で作ってあるとする。
    let listed = || {
        app_with(PermissionSubject::Command(CommandSubject::line_only(
            "ls -la /tmp/x",
        )))
    };
    let mut cache = SummaryCache::new();
    cache.insert(
        summary_key(&summary_pieces(&listed(), &scope), ja, None),
        "一覧を出すだけ。".into(),
    );

    // 同じ中身・同じ言語なら使い回す（対照）。
    let mut again = listed();
    assert!(start_summary(&summary, &tx, &mut again, &cache, &scope, false, ja, None).is_none());
    assert_eq!(
        again.pending_permission.as_ref().unwrap().summary,
        crate::app::SummaryState::Done {
            text: "一覧を出すだけ。".into(),
            took: None
        }
    );

    // 長さが同じ別の行には使い回さない。
    let mut removed = app_with(PermissionSubject::Command(CommandSubject::line_only(
        "rm -rf /tmp/x",
    )));
    let token = start_summary(&summary, &tx, &mut removed, &cache, &scope, false, ja, None)
        .expect("別の中身なのに要約を起こさなかった");
    token.cancel();
    assert!(matches!(
        removed.pending_permission.as_ref().unwrap().summary,
        crate::app::SummaryState::Running(_)
    ));

    // 同じ行でも、言語が違えば使い回さない。
    let mut english = listed();
    let token = start_summary(
        &summary,
        &tx,
        &mut english,
        &cache,
        &scope,
        false,
        Some(SummaryLanguage::English),
        None,
    )
    .expect("言語が違うのに前の要約を使い回した");
    token.cancel();
    assert!(matches!(
        english.pending_permission.as_ref().unwrap().summary,
        crate::app::SummaryState::Running(_)
    ));
}

/// 待っている承認ダイアログ（`perm-0`）。要約は`started`に起こした。
fn waiting_app(started: Instant) -> AppState {
    let mut app = app_with(PermissionSubject::Command(CommandSubject::line_only("ls")));
    app.pending_permission.as_mut().unwrap().summary =
        crate::app::SummaryState::Running(crate::app::SummaryWait::new(started));
    app
}

fn output_chars(app: &AppState) -> Option<usize> {
    match &app.pending_permission.as_ref()?.summary {
        crate::app::SummaryState::Running(wait) => Some(wait.output_chars),
        _ => None,
    }
}

fn progress(request: &str, output_chars: usize) -> BackgroundEvent {
    BackgroundEvent::SummaryProgress {
        request: request.into(),
        output_chars,
    }
}

/// **途中経過が届くと、待ちの行の「考えた量」が増える。** 累計なので、小さい値では戻さない。
#[test]
fn progress_raises_the_amount_on_the_waiting_line() {
    let now = Instant::now();
    let mut app = waiting_app(now);
    let mut cache = SummaryCache::new();
    assert_eq!(output_chars(&app), Some(0));

    on_background(progress("perm-0", 40), &mut app, &mut cache, now);
    assert_eq!(output_chars(&app), Some(40));
    on_background(progress("perm-0", 100), &mut app, &mut cache, now);
    assert_eq!(output_chars(&app), Some(100));
    on_background(progress("perm-0", 60), &mut app, &mut cache, now);
    assert_eq!(output_chars(&app), Some(100), "累計が戻った");
}

/// **別の承認要求の途中経過・終わった後に遅れて届いた途中経過は捨てる。** キャンセルの前に送られて溝に残って
/// いたものが、いま聞かれている呼び出しの待ちの行や、出来上がった要約を書き換えない。
#[test]
fn progress_for_another_request_or_after_the_end_is_discarded() {
    let now = Instant::now();
    let mut app = waiting_app(now);
    let mut cache = SummaryCache::new();

    on_background(progress("perm-9", 400), &mut app, &mut cache, now);
    assert_eq!(output_chars(&app), Some(0), "別の要求の量が入った");

    on_background(
        BackgroundEvent::SummaryReady {
            request: "perm-0".into(),
            key: "k".into(),
            result: Ok("一覧を出す。".into()),
        },
        &mut app,
        &mut cache,
        now,
    );
    let done = app.pending_permission.as_ref().unwrap().summary.clone();
    on_background(progress("perm-0", 999), &mut app, &mut cache, now);
    assert_eq!(
        app.pending_permission.as_ref().unwrap().summary,
        done,
        "終わった後の途中経過で状態が変わった"
    );

    // ダイアログが閉じた後に届いても何も起きない。
    app.pending_permission = None;
    on_background(progress("perm-0", 1), &mut app, &mut cache, now);
    assert!(app.pending_permission.is_none());
}

/// **終わったら待ちの行は消え、待った時間が残る**（会話の「(thought for Ns)」と同じ）。作れなかったときも同じ。
#[test]
fn the_wait_ends_with_the_time_it_took() {
    let started = Instant::now();
    let finished = started + Duration::from_millis(9_100);
    let mut cache = SummaryCache::new();

    let mut app = waiting_app(started);
    on_background(
        BackgroundEvent::SummaryReady {
            request: "perm-0".into(),
            key: "k".into(),
            result: Ok("一覧を出す。".into()),
        },
        &mut app,
        &mut cache,
        finished,
    );
    assert_eq!(
        app.pending_permission.as_ref().unwrap().summary,
        crate::app::SummaryState::Done {
            text: "一覧を出す。".into(),
            took: Some(Duration::from_millis(9_100)),
        }
    );

    let mut app = waiting_app(started);
    on_background(
        BackgroundEvent::SummaryReady {
            request: "perm-0".into(),
            key: "k2".into(),
            result: Err("接続できない".into()),
        },
        &mut app,
        &mut cache,
        finished,
    );
    assert_eq!(
        app.pending_permission.as_ref().unwrap().summary,
        crate::app::SummaryState::Failed {
            reason: "接続できない".into(),
            took: Some(Duration::from_millis(9_100)),
        }
    );
}

/// **製品の入口から**: 要約が考える過程と本文を流す間、背景から途中経過が届き、待ちの行の量が増えてから
/// 要約に置き換わる。
#[tokio::test]
async fn progress_flows_from_the_summary_to_the_waiting_line() {
    use harness_core::{BlockKind, StopReason, StreamEvent, Usage};

    struct ThinksThenAnswers;
    #[async_trait::async_trait]
    impl harness_core::LlmProvider for ThinksThenAnswers {
        fn id(&self) -> &str {
            "thinks-then-answers"
        }
        async fn stream(
            &self,
            _req: harness_core::CompletionRequest,
        ) -> Result<
            futures::stream::BoxStream<'static, Result<StreamEvent, harness_core::ProviderError>>,
            harness_core::ProviderError,
        > {
            let events = vec![
                StreamEvent::BlockStart {
                    index: usize::MAX,
                    kind: BlockKind::Thinking,
                },
                StreamEvent::ThinkingDelta {
                    index: usize::MAX,
                    text: "let me look".to_string(), // 11 文字
                },
                StreamEvent::BlockStop { index: usize::MAX },
                StreamEvent::TextDelta {
                    index: 0,
                    text: "一覧を出す。".to_string(), // 6 文字
                },
                StreamEvent::Done {
                    stop_reason: StopReason::EndTurn,
                    usage: Usage::default(),
                },
            ];
            Ok(Box::pin(futures::stream::iter(events.into_iter().map(Ok))))
        }
    }

    let summary = ApprovalSummary {
        provider: Arc::new(ThinksThenAnswers),
        model: "m".into(),
        label: "mock / ".into(),
    };
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let scope = open_scope(ReadScopeConfig::default());
    let mut app = app_with(PermissionSubject::Command(CommandSubject::line_only("ls")));
    let mut cache = SummaryCache::new();
    assert!(start_summary(&summary, &tx, &mut app, &cache, &scope, false, None, None).is_some());
    assert_eq!(
        output_chars(&app),
        Some(0),
        "起こした直後は待ちの行が出ている"
    );

    let mut seen = Vec::new();
    loop {
        let event = rx.recv().await.expect("要約の結果が届かない");
        let ready = matches!(event, BackgroundEvent::SummaryReady { .. });
        on_background(event, &mut app, &mut cache, Instant::now());
        if ready {
            break;
        }
        seen.push(output_chars(&app));
    }
    assert_eq!(
        seen,
        vec![Some(11), Some(17)],
        "途中経過が待ちの行に入っていない"
    );
    assert!(
        matches!(
            &app.pending_permission.as_ref().unwrap().summary,
            crate::app::SummaryState::Done { text, took: Some(_) } if text == "一覧を出す。"
        ),
        "{:?}",
        app.pending_permission.as_ref().unwrap().summary
    );
}
