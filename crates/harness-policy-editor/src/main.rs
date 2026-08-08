//! `harness-policy-editor`: TOMOYO風ポリシーエディタの起動点。
//!
//! 設計は`harness_policy_editor`のlib.rs（記録2パス・3状態UI）を参照。
//!
//! # サブコマンドは互いに独立している
//!
//! `record`（パス1）・`approve`（承認）・`record-net`（パス2）・`show`/`sessions`（見る）は
//! 別々のコマンドで、間の状態はワークスペース上のファイル（`fs-audit.jsonl`・
//! `net-audit.jsonl`・`record-session.json`・`policy.json`）が持つ。
//! **順序を強制しない**ため——記録し直す・過去の記録を別の一般化度合いで見直す、を
//! いつでも行える。
//!
//! 現状の到達点は2パス記録の端から端まで（パス1→承認→パス2）。TUIの3画面は未実装。
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
    /// 承認済みのドメインをTier2a（AppContainer＋WFP＋Proxy）で実行し、
    /// 接続したドメインを記録する（パス2）。
    ///
    /// **ここで初めてACEが付く**（`preflight`経由）。Tier2aへ着地しない場合とWFPが立たない
    /// 場合は中止する——強制の無い観測を「記録できた」と言わないため。
    #[command(name = "record-net")]
    RecordNet {
        /// 承認済みのドメイン名（`approve --domain`で使ったもの）。
        #[arg(long)]
        domain: String,
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// 作業ディレクトリ（既定: policy.jsonに記録されたcwd、無ければworkspace）。
        #[arg(long)]
        cwd: Option<PathBuf>,
        #[arg(long)]
        generalize: Option<String>,
        /// この秒数を過ぎたら対象コマンドを打ち切る。
        #[arg(long)]
        timeout: Option<u64>,
        #[arg(long)]
        limit: Option<usize>,
        /// 実行するコマンド（`--`のあと）。省略時はドメインが1件だけ持つコマンドを使う。
        #[arg(last = true)]
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
        /// パス2の記録（接続したドメイン）を表示する。
        #[arg(long)]
        net: bool,
    },
    /// 記録した候補のうち指定したものを承認し、`.harness/policy.json`へ書く（中間ステップ）。
    ///
    /// **ACEはここでは付けない**——実際の付与はパス2（`record-net`）が`preflight`経由で行う。
    /// 付与経路を1つに保つための意図的な分担で、承認は「次のパス2でこの穴を開ける」宣言である。
    Approve {
        /// セッションid（既定: 最新）。
        session: Option<String>,
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// ドメイン名（「このコマンドに何を許すか」の単位、既定: コマンドの先頭トークン）。
        #[arg(long)]
        domain: Option<String>,
        /// 承認する提案id（カンマ区切り可）。**全件受理のショートハンドは無い**（D-42）。
        #[arg(long)]
        accept: Vec<String>,
        /// `show`に渡したのと同じ値を指定すること（idは一般化の度合いで変わる）。
        #[arg(long)]
        generalize: Option<String>,
        /// 承認を`--require-sandbox`の宣言と突き合わせる（none/write-containment/confidential）。
        #[arg(long)]
        require_sandbox: Option<String>,
        /// 差分を確認済みとして書き込む（非対話では必須）。
        #[arg(long)]
        yes: bool,
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
        Some(Command::RecordNet {
            domain,
            workspace,
            cwd,
            generalize,
            timeout,
            limit,
            command,
        }) => run_record_net(&domain, workspace, cwd, generalize, timeout, limit, &command),
        Some(Command::Show {
            session,
            workspace,
            generalize,
            limit,
            tree,
            net,
        }) => run_show(session.as_deref(), workspace, generalize, limit, tree, net),
        Some(Command::Approve {
            session,
            workspace,
            domain,
            accept,
            generalize,
            require_sandbox,
            yes,
        }) => run_approve(
            session.as_deref(),
            workspace,
            domain.as_deref(),
            &accept,
            generalize,
            require_sandbox.as_deref(),
            yes,
        ),
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

#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn run_record_net(
    domain_name: &str,
    workspace: Option<PathBuf>,
    cwd: Option<PathBuf>,
    generalize: Option<String>,
    timeout: Option<u64>,
    limit: Option<usize>,
    command: &[String],
) -> ExitCode {
    use harness_policy_editor::record_net::{NetRecordEvent, RecordNetRequest};

    let workspace_root = resolve_workspace(workspace);
    let Some(generalization) = resolve_generalization(&generalize) else {
        return ExitCode::FAILURE;
    };
    let limit = resolve_limit(limit);

    let policy = match harness_policy_editor::policy_file::load(&workspace_root) {
        Ok(policy) => policy,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let Some(domain) = policy.domain(domain_name) else {
        eprintln!(
            "ドメイン `{domain_name}` は {} にありません。先に \
             `harness-policy-editor approve --domain {domain_name} --accept <id>...` を実行してください。",
            harness_policy_editor::policy_file::path(&workspace_root).display()
        );
        if !policy.domains.is_empty() {
            eprintln!(
                "定義済みのドメイン: {}",
                policy
                    .domains
                    .iter()
                    .map(|d| d.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        return ExitCode::FAILURE;
    };

    // コマンドは明示指定が優先。省略時は**1件だけ**のときに限りそれを使う
    // ——複数あるなら黙って1つ選ばず、どれかを言わせる。
    let command = if command.is_empty() {
        match domain.commands.as_slice() {
            [only] => only.clone(),
            [] => {
                eprintln!(
                    "ドメイン `{domain_name}` にはコマンドが記録されていません。\
                     `-- <コマンド>` で明示してください。"
                );
                return ExitCode::FAILURE;
            }
            many => {
                eprintln!(
                    "ドメイン `{domain_name}` には複数のコマンドがあります。`-- <コマンド>` で\
                     どれを走らせるか明示してください:"
                );
                for c in many {
                    eprintln!("  {c}");
                }
                return ExitCode::FAILURE;
            }
        }
    } else {
        command.join(" ")
    };

    let cwd = cwd
        .map(|p| harness_sandbox::session_scope::normalize_workspace_root(&p))
        .or_else(|| domain.cwd.clone())
        .unwrap_or_else(|| workspace_root.clone());

    eprintln!("パス2（Tier2aでのドメイン記録）");
    eprintln!("ドメイン: {domain_name}");
    eprintln!("コマンド: {command}");
    eprintln!("作業ディレクトリ: {}", cwd.display());

    // キャンセルはまだ配線していない（CLIにはUIイベントが無い）。**「押せば止まる」ように
    // 見せない**——Ctrl-Cで本プロセスが終われば、ジョブのkill-on-closeでTier2aツリーが
    // 畳まれ、パイプ切断でnetfilterdも自発終了する（寿命がOSハンドルに紐付いている）。
    let never_cancel = || false;
    let request = RecordNetRequest {
        domain,
        command: &command,
        cwd: &cwd,
        workspace_root: &workspace_root,
        timeout: timeout.map(std::time::Duration::from_secs),
        cancel: &never_cancel,
    };

    let mut net_count = 0u64;
    let mut on_event = |event: NetRecordEvent| match event {
        NetRecordEvent::ElevationExpected { max_prompts } => {
            eprintln!(
                "隔離: Tier2a（AppContainer＋WFP＋Local Proxy）。UACが最大{max_prompts}回出ます\n\
                 （ACEの付与と、WFPの出口強制daemonの起動が管理者権限を要するためです）。"
            );
        }
        NetRecordEvent::GrantingPassthrough { outside_count } => {
            if outside_count == 0 {
                eprintln!("workspace外の穴はありません（このマシンのACLは変わりません）");
            } else {
                eprintln!("workspace外の穴 {outside_count}件へACEを付けます…");
            }
        }
        NetRecordEvent::PassthroughGranted { path, writable } => {
            eprintln!(
                "  付与: {} ({})",
                path.display(),
                if writable { "rw" } else { "ro" }
            );
        }
        NetRecordEvent::PassthroughDenied {
            path,
            access,
            reason,
        } => {
            eprintln!(
                "  **付与できませんでした**: {} ({access}): {reason}\n\
                 この穴が要るコマンドは、この後の実行で失敗します。",
                path.display()
            );
        }
        NetRecordEvent::Tier2aReady => eprintln!("Tier2aへ着地しました"),
        NetRecordEvent::ProxyStarted(addr) => eprintln!("Local Proxy: {addr}（全許可・記録用）"),
        NetRecordEvent::FakeDnsStarted(addr) => eprintln!("Fake DNS: {addr}"),
        NetRecordEvent::WfpEnforced => {
            eprintln!("WFPのdefault-denyを張りました（loopbackの穴は上の2つのポートだけ）");
        }
        NetRecordEvent::ChildStarted => eprintln!("--- コマンドを開始しました ---"),
        NetRecordEvent::StartupNoise(line) => eprint!("[シェル起動時ノイズ] {line}"),
        NetRecordEvent::Stdout(line) => print!("{line}"),
        NetRecordEvent::Stderr(line) => eprint!("{line}"),
        NetRecordEvent::NetAccess(_) => {
            net_count += 1;
            if net_count.is_multiple_of(50) {
                eprintln!("… {net_count}件のネットワークイベントを記録しました");
            }
        }
        NetRecordEvent::Exited(code) => eprintln!("--- コマンドが終了しました（exit {code}）---"),
        NetRecordEvent::Aborted(reason) => match reason {
            harness_policy_editor::record_net::AbortReason::Canceled => {
                eprintln!("記録を中断しました（キャンセル）")
            }
            harness_policy_editor::record_net::AbortReason::TimedOut => {
                eprintln!("記録を中断しました（タイムアウト）")
            }
        },
        NetRecordEvent::Draining(d) => {
            eprintln!("監査ログが書き切られるのを待っています（{}ms）…", d.as_millis());
        }
        NetRecordEvent::TearingDown(what) => eprintln!("撤収: {what}"),
        NetRecordEvent::Warning(message) => eprintln!("警告: {message}"),
    };

    let outcome = match harness_policy_editor::record_net(&request, &mut on_event) {
        Ok(outcome) => outcome,
        Err(e) => {
            eprintln!("記録できませんでした: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!();
    print!(
        "{}",
        harness_policy_editor::net_aggregate::render(&outcome.aggregate, generalization, limit)
    );
    println!();
    println!("記録セッション: {}", outcome.session_id);
    println!("監査ログ: {}", outcome.net_audit_log_path.display());
    if let Some(code) = outcome.exit_code {
        if code != 0 {
            println!(
                "**コマンドは異常終了しています（exit {code}）。** 記録した候補は不完全な可能性が\n\
                 あります——FSの穴が足りない、またはWFPが必要な通信を落としたことが原因かもしれません。"
            );
        }
    }
    println!(
        "この記録を見直す: harness-policy-editor show {} --net --generalize <none|dir|auto>",
        outcome.session_id
    );
    println!(
        "候補を承認する: harness-policy-editor approve {} --domain {domain_name} --accept <id>...",
        outcome.session_id
    );
    ExitCode::SUCCESS
}

#[cfg(not(windows))]
#[allow(clippy::too_many_arguments)]
fn run_record_net(
    _domain_name: &str,
    _workspace: Option<PathBuf>,
    _cwd: Option<PathBuf>,
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
    net: bool,
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

    eprintln!(
        "記録セッション: {} （パス{}・{}）",
        manifest.id,
        manifest.pass,
        manifest.status.label()
    );
    eprintln!("コマンド: {}", manifest.command);
    eprintln!("作業ディレクトリ: {}", manifest.cwd.display());
    if let Some(domain) = &manifest.domain {
        eprintln!("ドメイン: {domain}");
    }
    if let Some(code) = manifest.exit_code {
        eprintln!("終了コード: {code}");
    }
    for warning in &manifest.warnings {
        eprintln!("記録時の警告: {warning}");
    }

    // `--net`が無くても、パス2の記録を開いたなら**そちらを見せる**——`fs-audit.jsonl`が
    // 無いセッションでFSの候補一覧（0件）を出しても、何も伝わらない。
    let show_net = net || manifest.pass == 2;
    if show_net {
        let aggregate = harness_policy_editor::net_aggregate::from_log(&dir.net_audit_log_path());
        print!(
            "{}",
            harness_policy_editor::net_aggregate::render(&aggregate, generalization, limit)
        );
        return ExitCode::SUCCESS;
    }

    if !manifest.collector_started {
        eprintln!("警告: この記録では収集器が起動していません（FSアクセスは記録されていません）");
    } else if !manifest.etw_available {
        eprintln!("警告: この記録ではETWセッションが張れていません（何も観測できていません）");
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

#[allow(clippy::too_many_arguments)]
fn run_approve(
    session: Option<&str>,
    workspace: Option<PathBuf>,
    domain: Option<&str>,
    accept: &[String],
    generalize: Option<String>,
    require_sandbox: Option<&str>,
    yes: bool,
) -> ExitCode {
    use harness_policy_editor::approve::{self, ApproveRequest, PathClass};
    use harness_policy_editor::session_dir;

    let workspace_root = resolve_workspace(workspace);
    let Some(generalization) = resolve_generalization(&generalize) else {
        return ExitCode::FAILURE;
    };
    let Some(require_sandbox) = resolve_require_sandbox(require_sandbox) else {
        return ExitCode::FAILURE;
    };

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

    // idは`--generalize`に依存するので、`show`とまったく同じ経路で作り直す。
    let aggregate = harness_policy_editor::aggregate::from_log(&dir.audit_log_path());
    let proposals = aggregate.proposals(generalization);

    // ドメイン名の既定はコマンドの先頭トークン（`cargo build` → `cargo`）。
    let domain = domain
        .map(|d| d.to_string())
        .unwrap_or_else(|| default_domain_name(&manifest.command));
    if domain.is_empty() {
        eprintln!("ドメイン名を決められませんでした。--domain <name> を指定してください。");
        return ExitCode::FAILURE;
    }

    // カンマ区切りを展開する（`--accept fs-1,fs-2`と`--accept fs-1 --accept fs-2`の両方を許す）。
    let accept_ids: Vec<String> = accept
        .iter()
        .flat_map(|arg| arg.split(','))
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .collect();

    let request = ApproveRequest {
        workspace_root: &workspace_root,
        proposals: &proposals,
        accept_ids: &accept_ids,
        require_sandbox,
        domain: &domain,
        command: Some(&manifest.command),
        cwd: Some(&manifest.cwd),
        record_session: Some(&manifest.id),
        now_unix_ms: harness_policy_editor::session_dir::now_unix_ms(),
    };
    let plan = match approve::plan(&request) {
        Ok(plan) => plan,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    println!("{}:", harness_policy_editor::policy_file::path(&workspace_root).display());
    println!("  ドメイン: {domain}{}", if plan.report.created_domain { "（新規）" } else { "" });
    for (key, value) in &plan.report.added {
        println!("  + {key} = {value}");
    }
    for (key, value) in &plan.report.already_present {
        println!("  = {key} = {value}  （既にあります）");
    }
    for warning in &plan.warnings {
        println!("  ! {warning}");
    }

    // **承認の実質的な判断材料**: 実際にマシンのACLを変えるのはworkspace外の分だけである。
    let outside: Vec<&str> = plan
        .accepted
        .iter()
        .zip(&plan.classes)
        .filter(|(_, class)| **class == PathClass::OutsideWorkspace)
        .map(|(p, _)| p.value.as_str())
        .collect();
    let inside = plan
        .classes
        .iter()
        .filter(|c| **c == PathClass::InsideWorkspace)
        .count();
    println!();
    if inside > 0 {
        println!(
            "  workspace配下 {inside}件: Tier2aのworkspace許可が既に覆うため、ACEの追加は要りません"
        );
    }
    if outside.is_empty() {
        println!("  workspace外: なし（このマシンのACLは変わりません）");
    } else {
        println!(
            "  workspace外 {}件: パス2（record-net）がこのルートへ実際にACEを付けます\
             ——**マシンに残る変更**です",
            outside.len()
        );
        for value in &outside {
            println!("    {value}");
        }
    }

    if plan.report.is_empty() {
        println!();
        println!("（承認済みの内容に変化はありません。何も書きませんでした）");
        return ExitCode::SUCCESS;
    }

    if !confirm_write(yes) {
        eprintln!("中止しました。何も書いていません。");
        return ExitCode::FAILURE;
    }
    if let Err(e) = approve::commit(&workspace_root, &plan) {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }

    println!();
    println!(
        "書きました: {}",
        harness_policy_editor::policy_file::path(&workspace_root).display()
    );
    println!(
        "次: harness-policy-editor record-net --domain {domain}\n\
         （Tier2aで実行し、接続したドメインを記録します。ここで初めてACEが付きます）"
    );
    ExitCode::SUCCESS
}

/// ドメイン名の既定値——コマンドの先頭トークンのbasename（`cargo build` → `cargo`、
/// `C:\tools\gh.exe pr list` → `gh`）。**実行時マッチャではなく識別子**なので、
/// 衝突したら`--domain`で明示させる。
fn default_domain_name(command: &str) -> String {
    let token = command.split_whitespace().next().unwrap_or("");
    let token = token.trim_matches(['"', '\'']);
    let name = token.rsplit(['\\', '/']).next().unwrap_or(token);
    name.rsplit_once('.').map(|(s, _)| s).unwrap_or(name).to_string()
}

fn resolve_require_sandbox(raw: Option<&str>) -> Option<harness_core::RequireSandbox> {
    match raw {
        None | Some("none") => Some(harness_core::RequireSandbox::None),
        Some("write-containment") => Some(harness_core::RequireSandbox::WriteContainment),
        Some("confidential") => Some(harness_core::RequireSandbox::Confidential),
        Some(other) => {
            eprintln!(
                "--require-sandbox は none / write-containment / confidential のいずれかです\
                 （指定: {other}）"
            );
            None
        }
    }
}

/// 書込前の確認。非対話（パイプ・リダイレクト）では`--yes`を必須にする——ヘッドレスは
/// 対話プロンプトを一切出さない原則に従い、「答えが返ってこないまま既定で進む」形を作らない
/// （`harness policy apply`と同じ作法）。
fn confirm_write(yes: bool) -> bool {
    use std::io::IsTerminal;

    if yes {
        return true;
    }
    if !std::io::stdin().is_terminal() {
        eprintln!(
            "確認なしには書きません: 標準入力が端末ではないためプロンプトを出せません。\
             上の差分を確認したうえで --yes を付けて実行してください。"
        );
        return false;
    }
    eprint!("この内容を .harness/policy.json へ書きますか？ [y/N] ");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim(), "y" | "Y" | "yes" | "YES")
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
            "{:<24} pass{} {:<40} {}",
            manifest.id,
            manifest.pass,
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
    println!("  パス1  Tier1（制限トークン＋低IL）で触ったファイルを全部記録");
    println!("  中間   FS候補をユーザーが承認して policy.json へ書く");
    println!("  パス2  Tier2a（AppContainer＋WFP＋Proxy）で接続したドメインを記録");
    println!();
    println!("使えるコマンド:");
    println!("  record -- <コマンド>        Tier1で実行し、触ったファイルを記録する（UAC 1回）");
    println!("  approve --domain <name> --accept <id>...");
    println!("                              候補を承認して .harness/policy.json へ書く");
    println!("  record-net --domain <name>  Tier2aで実行し、接続したドメインを記録する（UAC 最大2回）");
    println!("  sessions                    記録セッションの一覧");
    println!("  show [<id>] [--net]         記録を読み直して候補を表示する（記録し直さない）");
    println!();
    println!("記録と閲覧は独立したコマンドです。記録し終えてから編集へ進む一方通行ではなく、");
    println!("いつでも記録し直す・別の一般化度合いで見直すことができます。");
    println!();
    println!("ACEが実際に付くのは record-net（パス2）だけです。approve は「次のパス2でこの穴を");
    println!("開ける」という宣言を書くだけで、このマシンには何も残しません。");
    println!();
    println!("これから実装する部分: 記録／編集／テストの3画面（TUI）。");
}
