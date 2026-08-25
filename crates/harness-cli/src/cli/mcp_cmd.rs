//! `harness mcp`サブコマンド（M15.5、D-39）と、起動時の承認プロンプト。
//!
//! 承認の経路は2つある。**どちらも同じ台帳・同じハッシュを使う**（`harness_mcp::ApprovalStore`）。
//!
//! 1. `harness mcp approve <id>` — 落ち着いて宣言を読んでから承認する帯域外の経路。
//!    CI・スクリプト・複数ワークスペースの棚卸しではこちらしか使えない
//! 2. 起動時プロンプト — 対話起動で未承認の宣言に出会ったとき、その場で内容を見て判断する
//!
//! **ヘッドレス（`-p`/`--print`）では2は行わず自動拒否する。** `plans/DESIGN.md` §パーミッションの
//! 「ヘッドレス時はプロンプトになるものを既定で自動拒否」と同じ規則で、宣言の承認も例外にしない。

use std::io::{IsTerminal, Write};
use std::path::Path;

use harness_mcp::{ApprovalStore, McpServerDecl};

use super::*;

/// `harness mcp`サブコマンドの各操作。
#[derive(Subcommand)]
pub(crate) enum McpAction {
    /// このワークスペースの宣言と承認状態を一覧表示する。
    List {
        #[arg(long = "output-format", value_enum, default_value_t = OutputFormat::Text)]
        output_format: OutputFormat,
    },
    /// 宣言内容を表示して承認する（承認台帳へ宣言のハッシュを記録する）。
    Approve {
        /// 承認するサーバのid。
        id: String,
        /// 確認プロンプトを出さずに承認する（スクリプト用）。
        #[arg(long = "yes", default_value_t = false)]
        yes: bool,
    },
    /// 承認を取り消す（次回起動からそのサーバは起動されない）。
    Revoke {
        /// 取り消すサーバのid。
        id: String,
    },
}

/// 設定から宣言を読む。**このコマンド群は起動パイプラインを通らない**ので、ここで直接読む。
fn load_decls(workspace_root: &Path) -> Result<Vec<McpServerDecl>, String> {
    let settings = harness_config::Settings::load(workspace_root);
    harness_mcp::parse_mcp_settings(settings.mcp.as_ref())
}

/// ユーザ層のStreamable HTTPゲート（D-49）。`Settings::load`がプロジェクト層の分を
/// 既に剥がしているので、ここで読めるのはユーザ層の値だけである。
///
/// **CLIフラグ（`--allow-mcp-http`等）はここには効かない**——それらは起動時のフラグで、
/// `harness mcp`サブコマンドの対象外。表示にはその旨を添える。
fn load_http_gates(workspace_root: &Path) -> harness_mcp::McpHttpSettings {
    let settings = harness_config::Settings::load(workspace_root);
    harness_mcp::parse_mcp_http_gates(settings.mcp.as_ref()).unwrap_or_default()
}

pub(crate) fn run_mcp(action: McpAction, workspace_root: &Path) -> ExitCode {
    let decls = match load_decls(workspace_root) {
        Ok(decls) => decls,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let store = ApprovalStore::in_config_dir();

    match action {
        McpAction::List { output_format } => list(
            &decls,
            &store,
            &load_http_gates(workspace_root),
            output_format,
        ),
        McpAction::Approve { id, yes } => approve(&decls, &store, &id, yes),
        McpAction::Revoke { id } => revoke(&store, &id),
    }
}

/// 一覧に出す状態。承認だけでなく**セッションゲート**（D-49）も見る——「承認済みなのに
/// 起動しない」の理由が一覧から読めないと、ユーザーは次に何をすべきか分からない。
fn status_of(
    decl: &McpServerDecl,
    ledger: &harness_mcp::McpApprovalLedger,
    gates: &harness_mcp::McpHttpSettings,
) -> &'static str {
    if decl.transport == harness_mcp::McpTransportKind::StreamableHttp
        && !gates.allow_streamable_http
    {
        return "http-not-enabled";
    }
    if ledger.is_approved(decl) {
        "approved"
    } else if ledger.approval_for_id(&decl.id).is_some() {
        "changed-since-approval"
    } else {
        "not-approved"
    }
}

fn list(
    decls: &[McpServerDecl],
    store: &ApprovalStore,
    gates: &harness_mcp::McpHttpSettings,
    output_format: OutputFormat,
) -> ExitCode {
    let ledger = store.load();
    let rows: Vec<serde_json::Value> = decls
        .iter()
        .map(|decl| {
            serde_json::json!({
                "id": decl.id,
                "status": status_of(decl, &ledger, gates),
                "transport": decl.transport.label(),
                "command": decl.command,
                "args": decl.args,
                "url": decl.url,
                "network": decl.network.allow_domains,
                "workspace": format!("{:?}", decl.workspace).to_lowercase(),
                "declared_tools": decl.tools.len(),
                "valid": decl.validate().is_ok(),
            })
        })
        .collect();

    match output_format {
        OutputFormat::Json => {
            let out = serde_json::json!({
                "ledger_path": store.path().map(|p| p.display().to_string()),
                "streamable_http_enabled": gates.allow_streamable_http,
                "streamable_http_allow_domains": gates.http_allow_domains,
                "servers": rows,
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        }
        // **1行1サーバ。** [BUG-133](../../../../docs/bugs/BUG-133.md): ここは`Json`と同じ
        // アームに畳まれていて`to_string_pretty`（＝**複数行**）を出しており、1行1JSONという
        // JSONLの約束を最初から満たしていなかった。
        //
        // セッション全体にかかる値（承認台帳の場所・Streamable HTTPのゲート）はここには
        // 載らない——JSONLの行は同じ形のレコードの並びで、そこへ性質の違う1行を混ぜると
        // 読む側が行ごとに種別を判定する羽目になる。**その3つが要るときは`json`を使う**
        // （`status`が`http-not-enabled`になる形で、ゲートの効き自体は各行に現れる）。
        OutputFormat::Jsonl => {
            for row in &rows {
                if let Ok(s) = serde_json::to_string(row) {
                    println!("{s}");
                }
            }
        }
        OutputFormat::Text => {
            if decls.is_empty() {
                println!(
                    "no mcp servers are declared in this workspace (add them under the \"mcp\" \
                     key of .harness/settings.json)"
                );
                return ExitCode::SUCCESS;
            }
            for (decl, row) in decls.iter().zip(&rows) {
                println!(
                    "{:<24} {}",
                    decl.id,
                    row["status"].as_str().unwrap_or_default()
                );
                print!("{}", decl.describe());
                if let Err(e) = decl.validate() {
                    println!("  INVALID: {e}");
                }
                println!();
            }
            if let Some(path) = store.path() {
                println!("approval ledger: {}", path.display());
            }
            if decls
                .iter()
                .any(|d| d.transport == harness_mcp::McpTransportKind::StreamableHttp)
            {
                print_http_gate_status(gates);
            }
        }
    }
    ExitCode::SUCCESS
}

/// HTTP宣言がある場合だけ、そのゲートの現状と開け方を出す（D-49）。
fn print_http_gate_status(gates: &harness_mcp::McpHttpSettings) {
    if gates.allow_streamable_http {
        println!(
            "streamable http: enabled; allowed domains: {}",
            if gates.http_allow_domains.is_empty() {
                "(none -- no remote endpoint will be contacted; loopback is exempt)".to_string()
            } else {
                gates.http_allow_domains.join(", ")
            }
        );
    } else {
        println!(
            "streamable http: DISABLED. Servers using it will not start even once approved. \
             Enable it in your *user* settings.json with \"mcp\": {{ \"allow_streamable_http\": \
             true, \"http_allow_domains\": [\"...\"] }}, or pass --allow-mcp-http (plus \
             --allow-mcp-http-domain) for a single run. A project's .harness/settings.json cannot \
             enable it."
        );
    }
}

fn approve(
    decls: &[McpServerDecl],
    store: &ApprovalStore,
    id: &str,
    skip_prompt: bool,
) -> ExitCode {
    let Some(decl) = decls.iter().find(|d| d.id == id) else {
        eprintln!(
            "error: no mcp server with id {id:?} is declared in this workspace. `harness mcp \
             list` shows what is declared here."
        );
        return ExitCode::FAILURE;
    };
    // 起動できない宣言を承認させない（承認したのに動かない状態を作らない）。
    if let Err(e) = decl.validate() {
        eprintln!("error: refusing to approve an invalid declaration: {e}");
        return ExitCode::FAILURE;
    }
    if store.load().is_approved(decl) {
        println!("mcp server {id:?} is already approved with exactly this declaration.");
        return ExitCode::SUCCESS;
    }

    println!("About to approve this mcp server declaration:\n");
    print!("{}", decl.describe());
    match decl.transport {
        harness_mcp::McpTransportKind::Stdio => println!(
            "\nharness will start this program and expose its tools to the model. The server runs \
             in its own AppContainer sandbox, but it is third-party code: treat approval as \"I am \
             willing to run this\", not \"this is safe\".\n"
        ),
        // D-41「有効化した時点でこの経路がharnessの出口制御の外にあることを明示する」。
        harness_mcp::McpTransportKind::StreamableHttp => println!(
            "\nharness itself will connect to the url above and expose that server's tools to the \
             model. Unlike a stdio server there is no sandbox here: harness sends the declared \
             headers from its own process, over its own network position. Approval means \"I trust \
             whoever operates this endpoint\". Approving is not enough on its own -- the transport \
             must also be enabled and the host allowlisted (`harness mcp list` shows both).\n"
        ),
    }
    if decl.transport == harness_mcp::McpTransportKind::StreamableHttp
        && decl.url.starts_with("http://")
    {
        println!(
            "WARNING: this url is plaintext http. Unless it is loopback, the declared headers \
             (including any credentials) travel unencrypted, and harness will refuse to connect \
             without --allow-mcp-http-plaintext.\n"
        );
    }
    if decl.transport == harness_mcp::McpTransportKind::StreamableHttp {
        print_presented_certificate(decl);
    }
    if let Some(existing) = store.load().approval_for_id(id) {
        println!(
            "NOTE: this id was approved before, but the declaration has changed since \
             (approval recorded at unix {}). Approving now replaces that record.\n",
            existing.approved_at_unix_secs
        );
    }

    if !skip_prompt && !confirm("Approve this declaration?") {
        println!("not approved.");
        return ExitCode::FAILURE;
    }

    store.approve(decl);
    println!("approved {id:?}.");
    ExitCode::SUCCESS
}

/// **承認の前に、サーバが実際に提示する証明書を見せる**（D-52）。
///
/// `tls_pin`は64桁の16進なので、それだけでは何を承認しようとしているのか判断できない。
/// TLSハンドシェイクだけ行って（**HTTPリクエストは送らない**＝宣言されたヘッダも
/// 認証トークンもまだ渡らない）、発行元・サブジェクト・SAN・有効期限・指紋を並べ、
/// 宣言のピンと一致するかまで出す。
///
/// **繋がらなくても承認は妨げない。** ネットワークの都合でサーバが見えないことはあり、
/// 「今つながらないから承認できない」はユーザーの作業を止めるだけで安全性を上げない
/// （承認はあくまで宣言に対する記録で、実接続時の検証は別に効く）。
fn print_presented_certificate(decl: &McpServerDecl) {
    // 下見は`Endpoint`（D-49のゲートを通った証）ではなく`ParsedUrl`で行う——ゲートは
    // 「接続して喋ってよいか」の判断で、ここは一言も喋らない（`cert_probe`のdoc参照）。
    let Ok(endpoint) = harness_mcp::http_wire::parse_endpoint_url(&decl.url) else {
        return;
    };
    if !endpoint.is_tls() {
        return;
    }

    println!("Looking at the certificate this server presents (no request is sent yet)...");
    match harness_mcp::cert_probe::probe(&endpoint) {
        Ok(Some(presented)) => {
            print!("{}", presented.describe());
            match &decl.tls_pin {
                Some(declared) => {
                    let matches = harness_mcp::http_wire::parse_cert_pin(declared)
                        .map(|pin| pin == presented.pin)
                        .unwrap_or(false);
                    if matches {
                        println!("    -> MATCHES the tls_pin in the declaration.\n");
                    } else {
                        println!(
                            "    -> DOES NOT MATCH the tls_pin in the declaration. Either the \
                             server changed its certificate, or you are not talking to the \
                             server you think you are. Do not approve until you have resolved \
                             this with whoever runs it.\n"
                        );
                    }
                }
                None => println!(
                    "    -> the declaration has no tls_pin, so this certificate must validate \
                     against the OS certificate store (or \"mcp.http_ca_bundle\"). To pin this \
                     exact certificate instead, add:\n         \"tls_pin\": \"{}\"\n",
                    presented.pin.to_declaration_string()
                ),
            }
        }
        Ok(None) => {}
        Err(e) => println!(
            "    (could not reach the server to look at its certificate: {e})\n     You can still \
             approve the declaration; the certificate is checked again on every connection.\n"
        ),
    }
}

fn revoke(store: &ApprovalStore, id: &str) -> ExitCode {
    match store.revoke(id) {
        0 => {
            println!("no approval recorded for {id:?}; nothing to revoke.");
            ExitCode::SUCCESS
        }
        n => {
            println!("revoked {n} approval(s) for {id:?}.");
            ExitCode::SUCCESS
        }
    }
}

/// y/N の確認を取る。**TTYが無ければ常に`false`**（非対話で黙って承認しない）。
pub(crate) fn confirm(question: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        eprintln!("{question} [y/N] -- stdin is not a terminal; treating this as \"no\"");
        return false;
    }
    print!("{question} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// 起動時に未承認の宣言へ出会ったときの対話プロンプト（承認経路2、モジュールdoc参照）。
///
/// 承認された宣言は`plan.approved`へ移し、台帳へも記録する（次回からは無音で起動する）。
/// **ヘッドレスではこの関数を呼ばない**——呼び出し側（`stage_run_agent`）が対話かどうかで
/// 分岐する。TTYが無い場合も[`confirm`]が常に`false`を返すので二重に守られている。
pub(crate) fn prompt_for_unapproved(
    plan: &mut harness_mcp::McpStartupPlan,
    decls: &[McpServerDecl],
    store: &ApprovalStore,
) {
    use harness_mcp::SkipReason;

    let mut still_skipped = Vec::new();
    for skipped in std::mem::take(&mut plan.skipped) {
        // 承認以外の理由（宣言が不正・OS非対応等）は、聞いても解決しないのでそのまま落とす。
        if !matches!(skipped.reason, SkipReason::NotApproved { .. }) {
            still_skipped.push(skipped);
            continue;
        }
        let Some(decl) = decls.iter().find(|d| d.id == skipped.id) else {
            still_skipped.push(skipped);
            continue;
        };

        println!("\n{}\n", skipped.message());
        print!("{}", decl.describe());
        println!(
            "\nharness will start this program and expose its tools to the model. It runs in its \
             own AppContainer sandbox, but it is third-party code.\n"
        );
        if confirm("Approve this declaration and start the server now?") {
            store.approve(decl);
            plan.approved.push(decl.clone());
        } else {
            still_skipped.push(skipped);
        }
    }
    plan.skipped = still_skipped;
}
