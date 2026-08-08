//! `harness-policy-editor`: TOMOYO風ポリシーエディタの起動点。
//!
//! 設計は`harness_policy_editor`のlib.rs（記録2パス・3状態UI）を参照。
//!
//! # サブコマンドは互いに独立している
//!
//! `record`（記録する）と`show`/`sessions`（見る）は別々のコマンドで、間の状態は
//! ワークスペース上のファイルが持つ。**記録→編集の順序を強制しない**ため
//! ——記録し直す・過去の記録を別の一般化度合いで見直す、をいつでも行える。
//!
//! 現状の到達点はパス1（Tier1でのrecord-all記録）まで。TUIの3画面と、パス2
//! （Tier2aでのドメイン記録）はこれから実装する。
//!
//! # 出力の使い分け（B-24）
//!
//! 記録結果・候補一覧は**標準出力**、進行状況・警告・診断は**標準エラー**へ出す。
//! 標準出力を機械可読の契約として扱えるようにするため（`harness policy suggest`の
//! `--output-format`と同じ判断）。

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// 提案の既定の表示件数。0で全件。
const DEFAULT_LIMIT: usize = 40;

#[derive(Parser, Debug)]
#[command(
    name = "harness-policy-editor",
    about = "TOMOYO風ポリシーエディタ（記録→編集⇄テスト）。harness本体とは独立して動く。",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// コマンドをTier1で実行し、触ったファイルを全部記録する（パス1）。
    Record {
        /// 作業ディレクトリ（既定: カレントディレクトリ）。低ILラベルを付ける唯一の場所。
        #[arg(long)]
        cwd: Option<PathBuf>,
        /// workspaceルート（既定: カレントディレクトリ）。記録の置き場の基準。
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// 一般化の度合い（none/dir/auto、既定: dir）。
        #[arg(long)]
        generalize: Option<String>,
        /// この秒数を過ぎたら対象コマンドを打ち切る。
        #[arg(long)]
        timeout: Option<u64>,
        /// 表示する提案の件数（0で全件）。
        #[arg(long)]
        limit: Option<usize>,
        /// 記録するコマンド（`--`のあと）。
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// 記録済みのセッションを読み直して候補を表示する（記録し直さない）。
    Show {
        /// セッションid（既定: 最新）。
        session: Option<String>,
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long)]
        generalize: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
        /// 観測したプロセスツリーも表示する。
        #[arg(long)]
        tree: bool,
    },
    /// 記録セッションの一覧（新しい順）。
    Sessions {
        #[arg(long)]
        workspace: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Record {
            cwd,
            workspace,
            generalize,
            timeout,
            limit,
            command,
        }) => run_record(cwd, workspace, generalize, timeout, limit, &command),
        Some(Command::Show {
            session,
            workspace,
            generalize,
            limit,
            tree,
        }) => run_show(session.as_deref(), workspace, generalize, limit, tree),
        Some(Command::Sessions { workspace }) => run_sessions(workspace),
        None => {
            print_overview();
            ExitCode::SUCCESS
        }
    }
}

#[cfg(windows)]
fn run_record(
    cwd: Option<PathBuf>,
    workspace: Option<PathBuf>,
    generalize: Option<String>,
    timeout: Option<u64>,
    limit: Option<usize>,
    command: &[String],
) -> ExitCode {
    use harness_policy_editor::record::{AbortReason, RecordEvent, RecordRequest};

    let workspace_root = resolve_workspace(workspace);
    let cwd = cwd
        .map(|p| harness_sandbox::session_scope::normalize_workspace_root(&p))
        .unwrap_or_else(|| workspace_root.clone());
    let Some(generalization) = resolve_generalization(&generalize) else {
        return ExitCode::FAILURE;
    };
    let limit = resolve_limit(limit);
    let command = command.join(" ");

    eprintln!("記録するコマンド: {command}");
    eprintln!("作業ディレクトリ: {}", cwd.display());
    eprintln!(
        "隔離: Tier1（制限トークン＋低IL）。ETW収集器の起動でUACが1回出ます。\n\
         収集器が張るETWセッションは管理者権限を要するためです。"
    );

    // キャンセルはまだ配線していない（CLIにはUIイベントが無い）。**「押せば止まる」ように
    // 見せない**——Ctrl-Cで本プロセスが終われば、ジョブのkill-on-closeでTier1ツリーが
    // 畳まれ、パイプ切断で収集器も自発終了する（寿命がOSハンドルに紐付いている）。
    let never_cancel = || false;
    let request = RecordRequest {
        command: &command,
        cwd: &cwd,
        workspace_root: &workspace_root,
        timeout: timeout.map(std::time::Duration::from_secs),
        cancel: &never_cancel,
    };

    let mut access_count = 0u64;
    let mut on_event = |event: RecordEvent| match event {
        RecordEvent::CollectorStarted { etw_available } => {
            eprintln!(
                "収集器を起動しました（ETWセッション: {}）",
                if etw_available { "有効" } else { "**張れず**" }
            );
        }
        RecordEvent::CollectorUnavailable(reason) => {
            eprintln!("収集器を起動できませんでした: {reason}");
        }
        RecordEvent::WarmingUp(duration) => {
            eprintln!(
                "ETWの配送が始まるのを待っています（{}ms）… ここを省くとProcessStartごと\
                 取りこぼします",
                duration.as_millis()
            );
        }
        RecordEvent::ChildStarted => eprintln!("--- コマンドを開始しました ---"),
        RecordEvent::StartupNoise(line) => {
            eprint!("[シェル起動時ノイズ] {line}");
        }
        RecordEvent::Stdout(line) => print!("{line}"),
        RecordEvent::Stderr(line) => eprint!("{line}"),
        RecordEvent::Access(_) => {
            access_count += 1;
            if access_count.is_multiple_of(500) {
                eprintln!("… {access_count}件のFSアクセスを記録しました");
            }
        }
        RecordEvent::Exited(code) => eprintln!("--- コマンドが終了しました（exit {code}）---"),
        RecordEvent::Aborted(reason) => match reason {
            AbortReason::Canceled => eprintln!("記録を中断しました（キャンセル）"),
            AbortReason::TimedOut => eprintln!("記録を中断しました（タイムアウト）"),
        },
        RecordEvent::Draining(duration) => {
            eprintln!(
                "ETWの残りのイベントが届くのを待っています（{}秒）…",
                duration.as_secs()
            );
        }
        RecordEvent::CollectorStopped { written } => {
            eprintln!("収集器が撤収しました（{written}件を記録）");
        }
        RecordEvent::Warning(message) => eprintln!("警告: {message}"),
    };

    let outcome = match harness_policy_editor::record(&request, &mut on_event) {
        Ok(outcome) => outcome,
        Err(e) => {
            eprintln!("記録できませんでした: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!();
    print!(
        "{}",
        harness_policy_editor::aggregate::render(&outcome.aggregate, generalization, limit)
    );
    println!();
    println!("記録セッション: {}", outcome.session_id);
    println!("監査ログ: {}", outcome.audit_log_path.display());
    println!(
        "この記録を見直す: harness-policy-editor show {} --generalize <none|dir|auto>",
        outcome.session_id
    );
    println!(
        "まだ実装していない: 候補の承認とACE付与（中間ステップ）、Tier2aでのドメイン記録（パス2）。\n\
         今の出力は「何を許せばよさそうか」の材料までです（適用はユーザーの明示操作、D-42）。"
    );

    ExitCode::SUCCESS
}

#[cfg(not(windows))]
fn run_record(
    _cwd: Option<PathBuf>,
    _workspace: Option<PathBuf>,
    _generalize: Option<String>,
    _timeout: Option<u64>,
    _limit: Option<usize>,
    _command: &[String],
) -> ExitCode {
    eprintln!("{}", NOT_WINDOWS_MESSAGE);
    ExitCode::FAILURE
}

fn run_show(
    session: Option<&str>,
    workspace: Option<PathBuf>,
    generalize: Option<String>,
    limit: Option<usize>,
    tree: bool,
) -> ExitCode {
    use harness_policy_editor::session_dir;

    let workspace_root = resolve_workspace(workspace);
    let Some(generalization) = resolve_generalization(&generalize) else {
        return ExitCode::FAILURE;
    };
    let limit = resolve_limit(limit);

    let found = match session {
        Some(id) => session_dir::RecordSessionDir::open(&workspace_root, id)
            .and_then(|dir| dir.read_manifest().map(|m| (dir, m))),
        None => session_dir::latest_session(&workspace_root),
    };
    let Some((dir, manifest)) = found else {
        eprintln!(
            "記録セッションが見つかりません（{}）。先に `harness-policy-editor record -- <コマンド>` を実行してください。",
            session_dir::sandbox_root(&workspace_root).display()
        );
        return ExitCode::FAILURE;
    };

    eprintln!("記録セッション: {} （{}）", manifest.id, manifest.status.label());
    eprintln!("コマンド: {}", manifest.command);
    eprintln!("作業ディレクトリ: {}", manifest.cwd.display());
    if let Some(code) = manifest.exit_code {
        eprintln!("終了コード: {code}");
    }
    if !manifest.collector_started {
        eprintln!("警告: この記録では収集器が起動していません（FSアクセスは記録されていません）");
    } else if !manifest.etw_available {
        eprintln!("警告: この記録ではETWセッションが張れていません（何も観測できていません）");
    }
    for warning in &manifest.warnings {
        eprintln!("記録時の警告: {warning}");
    }

    let aggregate = harness_policy_editor::aggregate::from_log(&dir.audit_log_path());
    print!(
        "{}",
        harness_policy_editor::aggregate::render(&aggregate, generalization, limit)
    );
    if tree {
        println!();
        print!(
            "{}",
            harness_policy_editor::aggregate::render_process_tree(&aggregate)
        );
    }
    ExitCode::SUCCESS
}

fn run_sessions(workspace: Option<PathBuf>) -> ExitCode {
    use harness_policy_editor::session_dir;

    let workspace_root = resolve_workspace(workspace);
    let sessions = session_dir::list_sessions(&workspace_root);
    if sessions.is_empty() {
        eprintln!(
            "記録セッションはまだありません（{}）",
            session_dir::sandbox_root(&workspace_root).display()
        );
        return ExitCode::SUCCESS;
    }
    for (_, manifest) in sessions {
        println!(
            "{:<24} {:<40} {}",
            manifest.id,
            truncate(&manifest.command, 40),
            manifest.status.label()
        );
    }
    ExitCode::SUCCESS
}

fn truncate(text: &str, max_chars: usize) -> String {
    let mut out: String = text.chars().take(max_chars).collect();
    if text.chars().count() > max_chars {
        out.push('…');
    }
    out
}

fn resolve_workspace(workspace: Option<PathBuf>) -> PathBuf {
    let raw = workspace.unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    // 綴りを揃えるのは**境界で1度だけ**（B-19）。harness本体の`--cwd`と同じ関数を通す
    // ——規則を2つ持つとBUG-066/BUG-068と同型の穴になる。
    harness_sandbox::session_scope::normalize_workspace_root(&raw)
}

fn resolve_generalization(raw: &Option<String>) -> Option<harness_policy::Generalization> {
    match raw {
        None => Some(harness_policy::Generalization::Directory),
        Some(value) => match harness_policy::Generalization::parse(value) {
            Some(mode) => Some(mode),
            None => {
                eprintln!("--generalize は none / dir / auto のいずれかです（指定: {value}）");
                None
            }
        },
    }
}

/// `0`は「全件」の意味。表示件数の上限として`usize::MAX`へ読み替える。
fn resolve_limit(limit: Option<usize>) -> usize {
    match limit {
        Some(0) => usize::MAX,
        Some(n) => n,
        None => DEFAULT_LIMIT,
    }
}

#[cfg(not(windows))]
const NOT_WINDOWS_MESSAGE: &str = "harness-policy-editor の記録モードはWindows専用です\
     （Tier1の制限トークン・Tier2aのAppContainer・ETW・WFPに依存しているため）。";

fn print_overview() {
    println!("harness-policy-editor — LLMを介さずに「このコマンドに何を許すか」を決める道具");
    println!();
    println!("記録は2パスで行います（FSのpermissiveさとネットワーク強制は同一トークンでは");
    println!("両立しないため、同時にではなく順番に使います）:");
    println!("  パス1  Tier1（制限トークン＋低IL）で触ったファイルを全部記録    ← 実装済み");
    println!("  中間   FS候補をユーザーが承認して付与                          ← 未実装");
    println!("  パス2  Tier2a（AppContainer）で接続したドメインを記録          ← 未実装");
    println!();
    println!("使えるコマンド:");
    println!("  record -- <コマンド>   Tier1で実行し、触ったファイルを記録する（UACが1回出ます）");
    println!("  sessions               記録セッションの一覧");
    println!("  show [<id>]            記録を読み直して候補を表示する（記録し直さない）");
    println!();
    println!("記録と閲覧は独立したコマンドです。記録し終えてから編集へ進む一方通行ではなく、");
    println!("いつでも記録し直す・別の一般化度合いで見直すことができます。");
    println!();
    println!("これから実装する部分: 記録／編集／テストの3画面（TUI）、中間ステップとパス2の配線。");
}
