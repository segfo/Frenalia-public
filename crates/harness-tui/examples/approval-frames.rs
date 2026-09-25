//! 承認画面を**文字に起こして**標準出力へ流す（D-106）。
//!
//! # 何のためにあるのか
//!
//! 承認画面は自動テストで測れないものを持っている——枠に収まるか、選択肢が切れないか、
//! 見えない文字が綴りで出るか。単体テストが見ているのは「どの行を作るか」までで、
//! **組み上がった画面**は見ていない。ここはそれを文字で出す。
//!
//! ```powershell
//! cargo run -p harness-tui --example approval-frames
//! cargo run -p harness-tui --example approval-frames -- 70   # 端末幅を変えて見る
//! ```
//!
//! # 限界（ここで確かめられないこと）
//!
//! **これは ratatui が組んだ結果であって、実端末が描いた結果ではない。** 全角の幅・IME の
//! 変換候補・端末ごとの色や合字はここには映らない。実端末での確認は
//! `docs/DEV-ENVIRONMENT.md` の「承認画面の手動確認」が引き続き要る。

use std::time::{Duration, Instant};

use harness_core::{
    BoundFile, CommandSubject, FilePreview, PermissionSubject, ProgramSubject, RiskClass,
};
use harness_tui::{ApprovalStage, PermissionView, PreviousCopy, SummaryState};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

fn main() {
    let width: u16 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(100);
    let height: u16 = 30;

    for (title, view) in scenes() {
        println!("\n### {title}  （{width}×{height}）");
        println!("{}", render(&view, width, height));
    }
    println!(
        "\n（これは ratatui が組んだ結果です。実端末の全角幅・IME・色はここには映りません。\n\
         実端末での確認は docs/DEV-ENVIRONMENT.md の「承認画面の手動確認」を使ってください。）"
    );
}

fn render(view: &PermissionView, width: u16, height: u16) -> String {
    let mut term = Terminal::new(TestBackend::new(width, height)).unwrap();
    term.draw(|f| {
        harness_tui::render_approval_modal_for_example(f, f.area(), view);
    })
    .unwrap();
    let buffer = term.backend().buffer().clone();
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
                .trim_end()
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn aged(mut view: PermissionView) -> PermissionView {
    // 入力を捨てる窓（300ms）を過ぎた状態で描く。
    view.opened_at = Instant::now() - Duration::from_secs(1);
    view
}

fn view(tool: &str, subject: PermissionSubject) -> PermissionView {
    aged(PermissionView::new(
        "perm-0".to_string(),
        tool.to_string(),
        RiskClass::Exec,
        subject,
        "{}".to_string(),
        None,
        r"C:\Users\me\project".to_string(),
    ))
}

fn bound(rel: &str, listing: bool) -> BoundFile {
    BoundFile {
        rel_path: rel.to_string(),
        sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".to_string(),
        dir_listing_sha256: listing.then(|| "c".repeat(64)),
    }
}

fn script_subject() -> ProgramSubject {
    let mut p = ProgramSubject::plain("python", vec!["build.py".to_string()]);
    p.resolved = Some(r"C:\Python\python.exe".to_string());
    p.files = vec![bound("build.py", true)];
    p.one_shot_only = false;
    p.previews = vec![FilePreview {
        rel_path: "build.py".to_string(),
        text: "import subprocess\nsubprocess.run(['cargo', 'build'])\nprint('done')".to_string(),
        truncated: false,
    }];
    p
}

fn scenes() -> Vec<(&'static str, PermissionView)> {
    let mut out = Vec::new();

    out.push((
        "1. 素のプログラム（縛るファイルなし）",
        view(
            "run_program",
            PermissionSubject::Program(ProgramSubject::plain(
                "git",
                vec!["log".into(), "-n".into(), "5".into()],
            )),
        ),
    ));

    out.push((
        "2. インタプリタ＋縛ったファイル",
        view("run_program", PermissionSubject::Program(script_subject())),
    ));

    let mut confirm = view(
        "run_program",
        PermissionSubject::Program(ProgramSubject::plain(
            "git",
            vec!["log".into(), "-n".into(), "5".into()],
        )),
    );
    confirm.stage = ApprovalStage::Confirm;
    out.push(("3. 確認の一段（穴を選ぶ）", confirm));

    out.push((
        "4. 双方向制御を含む引数",
        view(
            "run_program",
            PermissionSubject::Program(ProgramSubject::plain(
                "pwsh",
                vec!["gp\u{202E}yp.exe".into(), "a\u{200B}b".into()],
            )),
        ),
    ));

    let mut content = view("run_program", PermissionSubject::Program(script_subject()));
    content.on_key(key('v'));
    out.push(("5. 中身の枠（[v]）", content));

    let mut with_diff = view(
        "run_shell",
        PermissionSubject::Command(CommandSubject {
            line: "python build.py --release".to_string(),
            files: vec![bound("build.py", true)],
            unverifiable: false,
            previews: vec![FilePreview {
                rel_path: "build.py".to_string(),
                text: "import subprocess\nsubprocess.run(['cargo', 'build', '--release'])\n"
                    .to_string(),
                truncated: false,
            }],
        }),
    );
    with_diff.previous = Some(vec![PreviousCopy {
        rel_path: "build.py".to_string(),
        text: Ok("import subprocess\nsubprocess.run(['cargo', 'build'])\n".to_string()),
    }]);
    with_diff.summary_source = Some("lmstudio / qwen3-8b".to_string());
    with_diff.summary = SummaryState::Done(
        "cargo build を --release で実行します。ネットワークへは出ません。".to_string(),
    );
    with_diff.on_key(key('f'));
    out.push(("6. 差分の枠（[f]）と要約", with_diff));

    out
}

fn key(c: char) -> crossterm::event::KeyEvent {
    crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char(c),
        crossterm::event::KeyModifiers::NONE,
    )
}
