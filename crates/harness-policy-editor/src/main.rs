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
//! いつでも行える。TUI（`harness_policy_editor::tui`）も同じファイルの上に載るだけで、
//! 記録の手順を画面ごとに書き直さない。
//!
//! # サブコマンド無しの起動はTUI
//!
//! 標準入出力が端末なら記録・編集の2画面のTUIを開き、そうでなければ（パイプ・リダイレクト）
//! 概要を表示する。端末でない相手に端末制御を始めない。
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

#[cfg(test)]
#[path = "cli_strings_tests.rs"]
mod cli_strings_tests;

/// `show`・`approve`（記録の候補を見せる・承認する）。2026-10-05にこのファイルから**そのまま**移した
/// （本体が1,000行を超えているため。`plans/position-domains/P4.md`のP4.5の準備）。
mod cli_candidates;
use cli_candidates::{run_approve, run_show};

#[derive(Parser, Debug)]
#[command(
    name = "harness-policy-editor",
    about = "TOMOYO風ポリシーエディタ（記録→編集⇄テスト）。harness本体とは独立して動く。",
    long_about = None
)]
struct Cli {
    /// TUI（サブコマンド無しで起動したとき）が対象にするworkspaceルート。
    /// サブコマンド側にも同名の引数があるので、こちらは`global`にしない
    /// （同じ名前を2つの階層で有効にすると、どちらが効いたのか分からなくなる）。
    #[arg(long)]
    workspace: Option<PathBuf>,
    /// 承認を`--require-sandbox`の宣言と突き合わせる（none/write-containment/confidential）。
    ///
    /// **TUI（サブコマンド無しの既定経路）用**。`approve`サブコマンド側にも同名の引数があるが、
    /// `global`にはしない——`workspace`と同じ理由（同じ名前を2階層で有効にすると、
    /// どちらが効いたのか分からなくなる）。
    ///
    /// **これが無かったのが[BUG-127](../../docs/bugs/BUG-127.md)である。**
    /// 宣言の口が`approve`サブコマンドにしか無く、TUIは`RequireSandbox::None`を定数で
    /// 渡していたため、D-42の突き合わせが主経路で1件も効いていなかった。
    #[arg(long)]
    require_sandbox: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// コマンドを隔離せず（Tier0）に実行し、触ったファイルを全部記録する（パス1）。
    Record {
        /// 作業ディレクトリ（既定: カレントディレクトリ）。低ILラベルを付ける唯一の場所。
        #[arg(long)]
        cwd: Option<PathBuf>,
        /// workspaceルート（既定: カレントディレクトリ）。記録の置き場の基準。
        #[arg(long)]
        workspace: Option<PathBuf>,
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
    ///
    /// 既定は通信先を全部許して記録する。`--enforce-net`を付けると、`policy.json`の
    /// `net.allow_domains`に一致する通信先だけを許し、ほかは断る（決定64）。
    #[command(name = "record-net")]
    RecordNet {
        /// 承認済みのドメイン名（`approve --domain`で使ったもの）。
        #[arg(long)]
        domain: String,
        /// 通信を宣言どおりに強制する（`policy.json`の`net.allow_domains`だけを許し、ほかは断る）。
        /// 候補には断られた宛先だけが出る。省略時は通信先を全部許して記録する。
        #[arg(long)]
        enforce_net: bool,
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// 作業ディレクトリ（既定: policy.jsonに記録されたcwd、無ければworkspace）。
        #[arg(long)]
        cwd: Option<PathBuf>,
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
        /// 表示する提案の件数（0で全件）。
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
    /// `.harness/policy.json`の承認済み宣言を取り消す（`approve`の対）。
    ///
    /// **ACEはここでは剥がさない**——付与がパス2の開始時なのと対称で、撤収も
    /// 次のパス2の開始時（と、このプロセスの終了時）に走る。名前を`revoke`にしないのは
    /// そのため（消すのは宣言であって、ACLの変更はこのコマンドの中では起きない）。
    Unapprove {
        /// 取り消す宣言があるドメイン名。`--all`と併用すると、そのドメインの宣言を全部消す。
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// 取り消すFS宣言の値（`policy.json`に書かれている綴り）。`--access`と対で指定する。
        #[arg(long)]
        fs: Vec<String>,
        /// `--fs`のaccess種別（`read`/`read_write`/`read_exec`）。
        #[arg(long)]
        access: Option<String>,
        /// 取り消すネットワーク宣言（`net.allow_domains`の値）。
        #[arg(long)]
        net: Vec<String>,
        /// 宣言を全部取り消す（`--domain`があればそのドメインだけ、無ければ全ドメイン）。
        ///
        /// **一括承認のショートハンドが無いのに一括取り消しがあるのは意図的**（D-42）。
        /// 禁じているのは読まずに権限を「与える」ことで、こちらは権限を「減らす」向きである。
        #[arg(long)]
        all: bool,
        /// [BUG-103] **いまの規則なら候補にしなかったFS宣言**を取り消す
        /// （`.harness`・harness自身のサンドボックスプロファイル・`C:/Windows`等・
        /// このworkspace配下・`%TEMP%`配下）。
        ///
        /// 候補側を直しても既存の宣言は消えないので、その掃除に使う。判定は候補側と
        /// **同じ関数**を通る（`exclusion::ExclusionRules`）。
        #[arg(long)]
        excluded: bool,
        /// 差分を確認済みとして書き込む（非対話では必須）。
        #[arg(long)]
        yes: bool,
    },
    /// [D-112] **既に`policy.json`にあるファイル宣言を、このマシンで承認する。**
    ///
    /// リポジトリに同梱されていた宣言・手で書いた宣言・承認台帳ができる前に承認した宣言は、
    /// このマシンで承認するまで許可が付かない（`harness.exe`でも、`record-net`でも）。
    /// 承認する宣言は1件ずつ名指しする——**全件を承認するショートハンドは無い**（決定51）。
    /// 候補の承認と同じ検査（`--require-sandbox`との矛盾・広すぎる値・候補にしない規則）を通す。
    #[command(name = "approve-declared")]
    ApproveDeclared {
        /// 宣言があるドメイン名。
        #[arg(long)]
        domain: String,
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// 承認するFS宣言の値（`policy.json`に書かれている綴り）。繰り返して複数指定できる。
        #[arg(long, required = true)]
        fs: Vec<String>,
        /// `--fs`のaccess種別（`read`/`read_write`/`read_exec`）。
        #[arg(long)]
        access: String,
        /// 承認を`--require-sandbox`の宣言と突き合わせる（none/write-containment/confidential）。
        #[arg(long)]
        require_sandbox: Option<String>,
        /// 確認済みとして書き込む（非対話では必須）。
        #[arg(long)]
        yes: bool,
    },
}

fn main() -> ExitCode {
    // [残課題#68] **このプロセスも補助プロセス（netfilterd・policy-learnd）を起こす。**
    // 起こす箇所は`harness-sandbox`側で共通だが、**掛けるかどうかを解決するのは起こす側の
    // プロセス**なので、ここでも置く必要がある——`harness.exe`にだけ書いた版を実機で撃つと、
    // こちら経由の起動では設定が効いていなかった（`B-06`: 同じ状態を作り得る経路を全部数える）。
    //
    // **エディタはコマンドラインのフラグを持たない**ので、設定ファイルの値をそのまま使う。
    // 読めなければ掛ける側に倒れる（`harness_user_config::load`が失敗したときの既定）。
    #[cfg(windows)]
    harness_sandbox::process_hardening::set_link_mitigation(
        harness_user_config::load()
            .map(|c| c.security.refuse_untrusted_links)
            .unwrap_or(true),
    );

    let cli = Cli::parse();
    match cli.command {
        Some(Command::Record {
            cwd,
            workspace,
            timeout,
            limit,
            command,
        }) => run_record(cwd, workspace, timeout, limit, &command),
        Some(Command::RecordNet {
            domain,
            enforce_net,
            workspace,
            cwd,
            timeout,
            limit,
            command,
        }) => run_record_net(&domain, enforce_net, workspace, cwd, timeout, limit, &command),
        Some(Command::Show {
            session,
            workspace,
            limit,
            tree,
            net,
        }) => run_show(session.as_deref(), workspace, limit, tree, net),
        Some(Command::Approve {
            session,
            workspace,
            domain,
            accept,
            require_sandbox,
            yes,
        }) => run_approve(
            session.as_deref(),
            workspace,
            domain.as_deref(),
            &accept,
            require_sandbox.as_deref(),
            yes,
        ),
        Some(Command::Sessions { workspace }) => run_sessions(workspace),
        Some(Command::ApproveDeclared {
            domain,
            workspace,
            fs,
            access,
            require_sandbox,
            yes,
        }) => run_approve_declared(
            &domain,
            workspace,
            &fs,
            &access,
            require_sandbox.as_deref(),
            yes,
        ),
        Some(Command::Unapprove {
            domain,
            workspace,
            fs,
            access,
            net,
            all,
            excluded,
            yes,
        }) => run_unapprove(
            UnapproveSelector {
                domain: domain.as_deref(),
                fs: &fs,
                access: access.as_deref(),
                net: &net,
                all,
                excluded,
            },
            workspace,
            yes,
        ),
        None => run_tui(cli.workspace, cli.require_sandbox.as_deref()),
    }
}

/// サブコマンド無しの起動。**端末なら記録・編集の2画面のTUI**、そうでなければ従来の概要表示。
///
/// パイプ・リダイレクト越しに呼ばれたときに端末制御（raw mode・オルタネートスクリーン）を
/// 始めると、相手の出力を壊すうえ操作もできない。`is_terminal`で分けるのは`confirm_write`と
/// 同じ作法である。
#[cfg(windows)]
fn run_tui(workspace: Option<PathBuf>, require_sandbox: Option<&str>) -> ExitCode {
    use std::io::IsTerminal;

    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        print_overview();
        return ExitCode::SUCCESS;
    }
    // **解決点は`resolve_require_sandbox`ただ1つ**（CLI経路の`run_approve`と同じ関数を通す）。
    // 綴りの検査もここで済ませる——不正な値で黙って`None`へ倒すと、
    // 「宣言したのに効いていない」が観測できない形になる（[BUG-127](../../docs/bugs/BUG-127.md)）。
    let Some(require_sandbox) = resolve_require_sandbox(require_sandbox) else {
        return ExitCode::FAILURE;
    };
    let workspace_root = resolve_workspace(workspace);
    match harness_policy_editor::tui::run(workspace_root, require_sandbox) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("TUIを起動できませんでした: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn run_tui(_workspace: Option<PathBuf>, _require_sandbox: Option<&str>) -> ExitCode {
    // 記録がWindows専用（Tier2aのAppContainer・ETW・WFP）なので、TUIもWindowsだけ。
    print_overview();
    ExitCode::SUCCESS
}

#[cfg(windows)]
fn run_record(
    cwd: Option<PathBuf>,
    workspace: Option<PathBuf>,
    timeout: Option<u64>,
    limit: Option<usize>,
    command: &[String],
) -> ExitCode {
    use harness_policy_editor::record::{AbortReason, RecordEvent, RecordRequest};

    let workspace_root = resolve_workspace(workspace);
    let cwd = cwd
        .map(|p| harness_sandbox::session_scope::normalize_workspace_root(&p))
        .unwrap_or_else(|| workspace_root.clone());
    let limit = resolve_limit(limit);
    let command = command.join(" ");

    eprintln!("記録するコマンド: {command}");
    eprintln!("作業ディレクトリ: {}", cwd.display());
    eprintln!("{}", harness_policy_editor::record::ELEVATION_NOTICE);

    // キャンセルはまだ配線していない（CLIにはUIイベントが無い）。**「押せば止まる」ように
    // 見せない**——Ctrl-Cで本プロセスが終われば、ジョブのkill-on-closeで記録対象のツリーが
    // 畳まれ、パイプ切断で収集器も自発終了する（寿命がOSハンドルに紐付いている）。
    let never_cancel = || false;
    // 収集器はこの1回の記録で使い切る（CLIは1プロセス1記録）。**プロセス終了で`Teardown`が
    // 走る**——TUIと同じ`SharedCollector`を通すことで、寿命の扱いを1つにしている。
    let collector = harness_policy_editor::record::SharedCollector::hold();
    let request = RecordRequest {
        command: &command,
        cwd: &cwd,
        workspace_root: &workspace_root,
        timeout: timeout.map(std::time::Duration::from_secs),
        cancel: &never_cancel,
        collector: &collector,
        // CLIは1コマンド1プロセスなので、常駐netfilterdの恩恵は受けられない
        // （前回のCLI呼び出しのdaemonはプロセス終了とともに撤収している）。
        wfp: None,
    };

    let mut access_count = 0u64;
    let mut on_event = |event: RecordEvent| match event {
        // 文言は実行側（`record`）が1つだけ持つ（規則5）。
        RecordEvent::CollectorStarted {
            etw_available,
            reused,
        } => {
            eprintln!(
                "{}",
                harness_policy_editor::record::collector_started_line(etw_available, reused)
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
        harness_policy_editor::aggregate::render(&outcome.aggregate, limit)
    );
    println!();
    println!("記録セッション: {}", outcome.session_id);
    println!("監査ログ: {}", outcome.audit_log_path.display());
    println!(
        "この記録を見直す: harness-policy-editor show {}",
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
    enforce_net: bool,
    workspace: Option<PathBuf>,
    cwd: Option<PathBuf>,
    timeout: Option<u64>,
    limit: Option<usize>,
    command: &[String],
) -> ExitCode {
    use harness_policy_editor::record_net::{
        NetMode, NetRecordEvent, RecordNetRequest, SessionGrants, SharedNetfilter,
        SharedSpawnDaemon,
    };
    let net_mode = if enforce_net {
        NetMode::Declared
    } else {
        NetMode::RecordAll
    };

    // パス2が開けた穴の寿命は**このプロセスの寿命**（D-37）。早期returnの各点でも必ず撤収が
    // 走るよう、値として持つ（`Drop`）。
    let _grants = SessionGrants::hold();
    // **`_grants`より後**に宣言する（D-56、`SharedNetfilter`のdoc「宣言順」）。CLIは1回の
    // 起動につき1回しか記録しないので再利用は起きないが、`record_net`が要求する形は同じで、
    // ここだけ別の持ち方をすると経路ごとに撤収順が違うことになる。
    let wfp = SharedNetfilter::hold();
    // 収集器も同じ理由・同じ順序で持つ（`_grants`より後＝`Teardown`がプロファイル削除より先）。
    let collector = harness_policy_editor::record::SharedCollector::hold();
    let spawn_daemon = SharedSpawnDaemon::hold();
    let workspace_root = resolve_workspace(workspace);
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
    eprintln!("通信の扱い: {}", net_mode.label());
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
        wfp: &wfp,
        collector: &collector,
        spawn_daemon: &spawn_daemon,
        net_mode,
    };

    let mut net_count = 0u64;
    let mut on_event = |event: NetRecordEvent| match event {
        NetRecordEvent::ElevationExpected { max_prompts } => {
            eprintln!(
                "{}",
                harness_policy_editor::record_net::elevation_notice(max_prompts)
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
        NetRecordEvent::RevokingUndeclared { total } => {
            eprintln!("取り消された宣言 {total}件のACEを撤収します（宣言を外した分の後始末）…");
        }
        NetRecordEvent::UndeclaredRevoked { path, done, total } => {
            eprintln!("  撤収 {done}/{total}: {}", path.display());
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
        // 文言は`ExecReach`が持つ（表示側で書き写さない、規則5）。問題が無ければ黙る。
        NetRecordEvent::ExecReachability(reach) => {
            if let Some(message) = reach.message() {
                eprintln!("警告: {message}");
            }
        }
        NetRecordEvent::CollectorStarted {
            etw_available,
            reused,
        } => eprintln!(
            "{}",
            harness_policy_editor::record::collector_started_line(etw_available, reused)
        ),
        NetRecordEvent::WarmingUp(duration) => eprintln!(
            "ETWの配送が始まるのを待っています（{}ms）",
            duration.as_millis()
        ),
        // **拒否だけを出す。** 許可まで流すと、強制下の観測（＝知りたいこと）が埋もれる。
        NetRecordEvent::FsAccess(event) => {
            if !event.allowed {
                if let Some(path) = event.path.as_deref() {
                    eprintln!("FS拒否: {path}");
                }
            }
        }
        NetRecordEvent::CollectorStopped { written } => {
            eprintln!("収集器が畳みました（書込 {written}件）")
        }
        NetRecordEvent::ProxyStarted {
            addr,
            mode,
            allowed,
        } => eprintln!(
            "{}",
            harness_policy_editor::record_net::proxy_started_line(addr, mode, allowed)
        ),
        NetRecordEvent::FakeDnsStarted(addr) => eprintln!("Fake DNS: {addr}"),
        NetRecordEvent::WfpEnforced { reused } => {
            eprintln!(
                "{}",
                harness_policy_editor::record_net::wfp_enforced_line(reused)
            );
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
            eprintln!(
                "監査ログが書き切られるのを待っています（{}ms）…",
                d.as_millis()
            );
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
        harness_policy_editor::net_aggregate::render(&outcome.aggregate, limit)
    );
    // **FSの拒否欄はネットワーク候補とは別枠**（スキーマも意味も違う）。文言は実行側が持つ。
    print!(
        "{}",
        harness_policy_editor::record_net::render_fs_denials(
            &outcome.fs_aggregate,
            outcome.collector_started,
            outcome.etw_available,
            outcome.net_mode,
        )
    );
    println!();
    println!("記録セッション: {}", outcome.session_id);
    println!(
        "監査ログ（ネットワーク）: {}",
        outcome.net_audit_log_path.display()
    );
    println!("監査ログ（FS）: {}", outcome.audit_log_path.display());
    if let Some(code) = outcome.exit_code {
        if code != 0 {
            println!(
                "**コマンドは異常終了しています（exit {code}）。** 記録した候補は不完全な可能性が\n\
                 あります——FSの穴が足りない、またはWFPが必要な通信を落としたことが原因かもしれません。"
            );
            if outcome.net_mode == NetMode::Declared {
                println!(
                    "強制モードなので、宣言の外の通信先を中継プロキシか名前解決が断ったことも原因になり得ます\n\
                     （断られた宛先は上の通信の候補一覧に出ています）。"
                );
            }
        }
    }
    println!(
        "この記録を見直す: harness-policy-editor show {} --net",
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
    _enforce_net: bool,
    _workspace: Option<PathBuf>,
    _cwd: Option<PathBuf>,
    _timeout: Option<u64>,
    _limit: Option<usize>,
    _command: &[String],
) -> ExitCode {
    eprintln!("{}", NOT_WINDOWS_MESSAGE);
    ExitCode::FAILURE
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
/// `harness-policy-editor unapprove` — 承認済み宣言を取り消す。
///
/// 表示の作法は`approve`と同じ2段（差分を見せる→確認→書く）。**消える件数と「元から無かった」
/// 件数を分けて出す**——分けないと、綴りを間違えた指定が「取り消しました」として通る（B-09）。
/// `unapprove`の「何を対象にするか」の指定一式。
///
/// 選択子は5通り（`--fs`＋`--access` / `--net` / `--all` / `--excluded`）あり、互いに排他である。
/// 束ねて1つの型で運ぶのは、**組み合わせの検査を1箇所（[`collect_unapprove_targets`]）に
/// 閉じ込める**ため——引数を平らに並べると、呼び出し側が増えるたびに検査を書き写すことになる。
struct UnapproveSelector<'a> {
    domain: Option<&'a str>,
    fs: &'a [String],
    access: Option<&'a str>,
    net: &'a [String],
    all: bool,
    excluded: bool,
}

fn run_unapprove(
    selector: UnapproveSelector<'_>,
    workspace: Option<PathBuf>,
    yes: bool,
) -> ExitCode {
    use harness_policy_editor::unapprove;

    let workspace_root = resolve_workspace(workspace);
    let file = match harness_policy_editor::policy_file::load(&workspace_root) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    let targets = match collect_unapprove_targets(&file, &selector, &workspace_root) {
        Ok(targets) => targets,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::FAILURE;
        }
    };
    if targets.is_empty() {
        println!("取り消す宣言がありません（policy.jsonは変更していません）");
        return ExitCode::SUCCESS;
    }

    let plan = match unapprove::plan(&workspace_root, &targets) {
        Ok(plan) => plan,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "{}:",
        harness_policy_editor::policy_file::path(&workspace_root).display()
    );
    if plan.removed.is_empty() {
        println!("  取り消せる宣言はありませんでした");
    } else {
        println!("  取り消す宣言 {}件:", plan.removed.len());
        for target in &plan.removed {
            println!(
                "    - [{}] {} {}",
                target.domain,
                target.key.dotted(),
                target.value
            );
        }
    }
    if !plan.not_found.is_empty() {
        // **「無かった」を黙って成功にしない。** 指定の綴り間違いはここでしか気付けない。
        println!("  policy.jsonに無かった指定 {}件:", plan.not_found.len());
        for target in &plan.not_found {
            println!(
                "    ? [{}] {} {}",
                target.domain,
                target.key.dotted(),
                target.value
            );
        }
    }
    if !plan.emptied_domains.is_empty() {
        println!(
            "  宣言が空になるドメイン: {}（ドメイン自体は残します——宣言なしでパス2を走らせて\
             拒否されることを確かめられるようにするため）",
            plan.emptied_domains.join(", ")
        );
    }
    println!();
    println!("{}", harness_policy_editor::unapprove::ACE_NOTICE);

    if plan.is_empty() {
        return if plan.not_found.is_empty() {
            ExitCode::SUCCESS
        } else {
            // 1件も消せず、しかも指定が全部見つからなかった＝ユーザーの意図は果たせていない。
            ExitCode::FAILURE
        };
    }
    if !confirm_write(yes) {
        println!("何も書いていません");
        return ExitCode::FAILURE;
    }
    match unapprove::commit(&workspace_root, &plan) {
        Ok(true) => {
            println!(
                "policy.jsonを更新しました（{}件を取り消し）",
                plan.removed.len()
            );
            ExitCode::SUCCESS
        }
        Ok(false) => {
            println!("変更はありませんでした");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// [D-112] `approve-declared`: 既に`policy.json`にあるファイル宣言を、このマシンで承認する。
fn run_approve_declared(
    domain: &str,
    workspace: Option<PathBuf>,
    values: &[String],
    access: &str,
    require_sandbox: Option<&str>,
    yes: bool,
) -> ExitCode {
    use harness_policy::generalize::SettingsKey;
    use harness_policy_editor::approve_declared;
    use harness_policy_editor::unapprove::UnapproveTarget;

    let Some(require_sandbox) = resolve_require_sandbox(require_sandbox) else {
        return ExitCode::FAILURE;
    };
    // 語彙は`unapprove --access`と同じ（新しい綴りを作らない）。
    let key = match access {
        "read" => SettingsKey::FsRead,
        "read_write" => SettingsKey::FsReadWrite,
        "read_exec" => SettingsKey::FsReadExec,
        other => {
            eprintln!("--access は read / read_write / read_exec のいずれかです（指定: {other}）");
            return ExitCode::FAILURE;
        }
    };
    let workspace_root = resolve_workspace(workspace);
    let targets: Vec<UnapproveTarget> = values
        .iter()
        .map(|value| UnapproveTarget {
            domain: domain.to_string(),
            key,
            value: value.clone(),
        })
        .collect();
    let plan = match approve_declared::plan(&workspace_root, &targets, require_sandbox) {
        Ok(plan) => plan,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "{}:",
        harness_policy_editor::policy_file::path(&workspace_root).display()
    );
    if !plan.approve.is_empty() {
        println!("  このマシンで承認する宣言 {}件:", plan.approve.len());
        for target in &plan.approve {
            println!("    + [{}] {} {}", target.domain, target.key.dotted(), target.value);
        }
    }
    for target in &plan.already {
        println!(
            "  = [{}] {} {}（承認済みでした）",
            target.domain,
            target.key.dotted(),
            target.value
        );
    }
    // **断った宣言と無かった指定を黙らない**（B-09）。「承認しました」だけを見せると、
    // 綴りの間違いや検査で止まった宣言に許可が付くと思い込む。
    for (target, reason) in &plan.refused {
        println!(
            "  ✗ [{}] {} {}: {reason}",
            target.domain,
            target.key.dotted(),
            target.value
        );
    }
    for target in &plan.not_found {
        println!(
            "  ? [{}] {} {}（policy.jsonにありません）",
            target.domain,
            target.key.dotted(),
            target.value
        );
    }
    // **部分適用しない**（`approve`と同じ判断）。名指しした宣言の1件でも断る・無いなら何も書かない
    // ——指定の誤りを直してから撃ち直す方が、一部だけ通った状態より読み違えにくい。
    if !plan.refused.is_empty() || !plan.not_found.is_empty() {
        eprintln!("承認できない指定があるので、何も書いていません");
        return ExitCode::FAILURE;
    }
    if plan.is_empty() {
        return ExitCode::SUCCESS;
    }
    println!();
    println!(
        "承認すると、次の record-net と harness.exe の起動でこの宣言に許可（ACE）が付きます。"
    );
    if !confirm_write(yes) {
        println!("何も書いていません");
        return ExitCode::FAILURE;
    }
    match approve_declared::commit(&workspace_root, &plan) {
        Ok(count) => {
            println!("このマシンで{count}件を承認しました");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// CLIの引数から取り消し対象を組み立てる。組み立てに失敗した理由は文字列で返す。
fn collect_unapprove_targets(
    file: &harness_policy_editor::PolicyFile,
    selector: &UnapproveSelector<'_>,
    workspace_root: &std::path::Path,
) -> Result<Vec<harness_policy_editor::unapprove::UnapproveTarget>, String> {
    use harness_policy::generalize::SettingsKey;
    use harness_policy_editor::unapprove::{self, UnapproveTarget};

    let UnapproveSelector {
        domain,
        fs,
        access,
        net,
        all,
        excluded,
    } = *selector;

    // [BUG-103] いまの規則なら候補にしなかった宣言だけを掃除する。
    if excluded {
        if all || !fs.is_empty() || !net.is_empty() {
            return Err(
                "--excluded は --all / --fs / --net と同時に指定できません（何を対象に\
                 するのかをはっきりさせてください）"
                    .to_string(),
            );
        }
        let rules = harness_policy_editor::exclusion::ExclusionRules::for_session(workspace_root);
        let mut found = unapprove::excluded_targets(file, &rules);
        if let Some(name) = domain {
            found.retain(|(target, _)| target.domain == name);
        }
        // **理由の内訳を出す**（B-09/B-32）。「1,644件消します」だけでは、消えるものが
        // 意図した種類なのかをユーザーが確かめようがない。
        let mut by_reason: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for (_, reason) in &found {
            *by_reason.entry(format!("{reason:?}")).or_default() += 1;
        }
        if !by_reason.is_empty() {
            println!("いまの規則なら候補にしなかった宣言の内訳:");
            for (reason, count) in &by_reason {
                println!("  {reason}: {count}件");
            }
            println!();
        }
        return Ok(found.into_iter().map(|(target, _)| target).collect());
    }

    if all {
        if !fs.is_empty() || !net.is_empty() {
            return Err(
                "--all と --fs/--net は同時に指定できません（全部消すのか個別に消すのかを\
                 はっきりさせてください）"
                    .to_string(),
            );
        }
        return match domain {
            Some(name) => match file.domain(name) {
                Some(d) => Ok(unapprove::domain_targets(d)),
                None => Err(format!("ドメイン {name} は policy.json にありません")),
            },
            None => Ok(unapprove::all_targets(file)),
        };
    }

    if fs.is_empty() && net.is_empty() {
        return Err(
            "取り消す対象を指定してください（--fs <値> --access <種別> / --net <ドメイン> / --all）"
                .to_string(),
        );
    }
    let Some(domain) = domain else {
        return Err("--domain <name> を指定してください".to_string());
    };

    let mut targets = Vec::new();
    if !fs.is_empty() {
        let Some(access) = access else {
            return Err(
                "--fs には --access <read|read_write|read_exec> を付けてください\
                 （同じパスが別のaccessでも宣言され得るため、どちらを消すのかが決まりません）"
                    .to_string(),
            );
        };
        // 語彙は`SettingsKey`と1:1（新しい綴りを作らない）。
        let key = match access {
            "read" => SettingsKey::FsRead,
            "read_write" => SettingsKey::FsReadWrite,
            "read_exec" => SettingsKey::FsReadExec,
            other => {
                return Err(format!(
                    "--access は read / read_write / read_exec のいずれかです（指定: {other}）"
                ))
            }
        };
        for value in fs {
            targets.push(UnapproveTarget {
                domain: domain.to_string(),
                key,
                value: value.clone(),
            });
        }
    }
    for value in net {
        targets.push(UnapproveTarget {
            domain: domain.to_string(),
            key: SettingsKey::NetAllowDomains,
            value: value.clone(),
        });
    }
    Ok(targets)
}

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
        // 失敗した行にだけ理由を添える。一覧なので**1行目だけ**——全文は`show`で読める
        // （出さないと、この一覧から「どれを追えばいいか」が決められない）。
        if let Some(note) = manifest.failure_note() {
            println!(
                "  {}",
                truncate(note.lines().next().unwrap_or_default(), 100)
            );
        }
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
     （Tier2aのAppContainer・ETW・WFPに依存しているため）。";

fn print_overview() {
    println!("harness-policy-editor — LLMを介さずに「このコマンドに何を許すか」を決める道具");
    println!();
    println!("記録は2パスで行います（FSのpermissiveさとネットワーク強制は同一トークンでは");
    println!("両立しないため、同時にではなく順番に使います）:");
    println!("  パス1  隔離なし（Tier0）で触ったファイルを全部記録");
    println!("  中間   FS候補をユーザーが承認して policy.json へ書く");
    println!("  パス2  Tier2a（AppContainer＋WFP＋Proxy）で接続したドメインを記録");
    println!();
    println!("端末から引数なしで起動すると、記録・編集の2画面のTUIが開きます");
    println!("（いま概要が出ているのは、標準入出力が端末ではないためです）。");
    println!();
    println!("使えるコマンド:");
    println!("  record -- <コマンド>        隔離せずに実行し、触ったファイルを記録する（UAC 1回）");
    println!("  approve --domain <name> --accept <id>...");
    println!("                              候補を承認して .harness/policy.json へ書く");
    println!(
        "  record-net --domain <name>  Tier2aで実行し、接続したドメインを記録する（UAC 最大2回）"
    );
    println!("             [--enforce-net]  通信をpolicy.jsonのnet.allow_domainsだけに絞り、ほかは断る");
    println!("  sessions                    記録セッションの一覧");
    println!("  show [<id>] [--net]         記録を読み直して候補を表示する（記録し直さない）");
    println!("  unapprove --domain <name> --fs <値> --access <種別> | --net <ドメイン> | --all");
    println!("                              承認済み宣言を取り消す（ACLは次のパス2開始時に撤収）");
    println!("  approve-declared --domain <name> --fs <値> --access <種別>");
    println!("                              policy.jsonにある宣言をこのマシンで承認する");
    println!();
    println!("記録と閲覧は独立したコマンドです。記録し終えてから編集へ進む一方通行ではなく、");
    println!("いつでも記録し直す・別の一般化度合いで見直すことができます。");
    println!();
    println!("approve は policy.json へ宣言を書き、このマシンの承認台帳へ承認を記録するだけで、");
    println!("ACLは触りません。ACEが付くのは、承認済みのファイル宣言を record-net（パス2）か");
    println!("harness.exe の起動が読んだときです。");
    println!();
    println!("宣言どおりに走らせて確かめるのは record-net --enforce-net です。強制で効くのは");
    println!("この試験実行の中だけで、harness.exe本体はまだpolicy.jsonのnet.allow_domainsで");
    println!("通信を許しません（本体ではsettings.jsonのnet.allow_domainsが効きます）。");
    println!();
    println!("宣言を直すには: 取り消しは unapprove か TUI の宣言画面の Space、ファイル宣言の");
    println!("種類と ** の付け替えは TUI の宣言画面の c・R です。");
    println!("まだ無いもの: policy.json のパスそのものの書き換えと、付け替えのコマンド。");
}
