//! 承認の台帳と要約の配線の回帰テスト（D-100・D-107）。内部関数（`summary_pieces`・
//! `summary_key`・`on_background`）へ触れるため`#[cfg(test)]`のまま別ファイルへ分けている
//! （`docs/CODE-STRUCTURE-RULES.md`規則2）。

use super::*;
use harness_core::ReadScopeConfig;
use harness_core::{CommandSubject, FilePreview, ProgramSubject, RiskClass};
use harness_sandbox::ReadScope;

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

fn app_with(subject: PermissionSubject) -> AppState {
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

fn open_scope(cfg: ReadScopeConfig) -> ReadScope {
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
    assert_ne!(summary_key(&a), summary_key(&b));
    assert_eq!(summary_key(&a), summary_key(&a.clone()));
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
    );
    assert_eq!(
        app.pending_permission.as_ref().unwrap().summary,
        crate::app::SummaryState::Done("いまの要約".into())
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
    assert!(start_summary(&summary, &tx, &mut app, &SummaryCache::new(), &scope, false).is_none());

    // 同じ中身は使い回す。
    let mut c = CommandSubject::line_only("cargo test");
    c.previews = vec![];
    let mut app = app_with(PermissionSubject::Command(c));
    let key = summary_key(&summary_pieces(&app, &scope));
    let mut cache = SummaryCache::new();
    cache.insert(key, "前に作った要約".into());
    assert!(start_summary(&summary, &tx, &mut app, &cache, &scope, false).is_none());
    assert_eq!(
        app.pending_permission.as_ref().unwrap().summary,
        crate::app::SummaryState::Done("前に作った要約".into())
    );
}
