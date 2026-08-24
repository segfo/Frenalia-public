//! `harness policy`サブコマンド（M15.7、ポリシー学習ヘルパーのユーザー側入口）。
//!
//! 設計正本は`plans/DESIGN-SANDBOX-APPPOLICY.md` §11。判断ロジック（正規化・一般化・差分計算・
//! 矛盾チェック）は純粋クレート`harness-policy`が持ち、**このファイルはファイルI/Oと表示だけ**を担う。
//! 分けているのは、提案の質そのものである一般化ロジックを実機・管理者権限なしに全数テストできる
//! 形に保つため（`docs/CODE-STRUCTURE-RULES.md`規則3）。
//!
//! # D-42（自動適用しない）がここでどう形になっているか
//!
//! - [`PolicyAction::Suggest`]は**1バイトも書かない**。差分を表示するだけで終わる。
//! - [`PolicyAction::Apply`]は`--accept <id>`で明示された提案**だけ**を書く。全件適用の
//!   ショートハンド（`--all`等）は用意しない——「触れば通る」経路を1つも作らないため、
//!   受理は常に個別の意思表示にする。
//! - 書込前に2つのチェックを通し、1件でも引っ掛かれば**何も書かずに**失敗する（部分適用しない）。
//!   `--require-sandbox`との矛盾（`harness_policy::gate`、D-42）と、
//!   値が広すぎないか（`harness_policy::breadth`、D-47）。後者に`--force`のような
//!   抜け道は用意しない——回避したいユーザーは`.harness/settings.json`を手で編集する。
//!   どちらのチェックも[`PolicyAction::Audit`]には掛けない（D-43「失敗を隠さない」）。

use std::io::IsTerminal;

use harness_policy::{
    diff, gate, normalize, GateVerdict, PolicyInput, RuleProposal, Source, SourceReport,
};

use super::*;

/// 収集源の選択（`--source`）。
fn resolve_sources(spec: Option<&str>) -> Result<Vec<Source>, String> {
    match spec {
        None | Some("all") => Ok(Source::ALL.to_vec()),
        Some(other) => Source::parse(other).map(|s| vec![s]).ok_or_else(|| {
            format!("unknown --source {other:?} (expected all|preflight|net|cow|etw)")
        }),
    }
}

/// 4経路をそれぞれ読み、[`PolicyInput`]へ束ねる。
///
/// **読めなかった経路もレポートとして残す**（D-43）。ファイルが無いことと拒否が0件だったことは
/// 別の事実であり、後者だけを表示すると「もう許可すべきものは無い」と誤読される。
fn collect_input(workspace_root: &Path, session: Option<&str>, sources: &[Source]) -> PolicyInput {
    let mut reports = Vec::new();

    for source in sources {
        let report = match source {
            Source::Preflight => collect_preflight(),
            Source::Network => collect_jsonl(
                Source::Network,
                net_audit_path(workspace_root, session, None),
            ),
            Source::Cow => collect_jsonl(Source::Cow, cow_denied_path(session)),
            Source::Etw => collect_jsonl(Source::Etw, fs_audit_path(workspace_root, session, None)),
        };
        reports.push(report);
    }

    PolicyInput::new(reports)
}

fn collect_preflight() -> SourceReport {
    let ledger = crate::fs_grants::fs_ledger();
    let Some(path) = ledger.path() else {
        return SourceReport::unavailable(
            Source::Preflight,
            "the fs passthrough ledger location could not be resolved on this platform",
        );
    };
    match std::fs::read_to_string(path) {
        Ok(text) => normalize::normalize_preflight(&text),
        Err(e) => SourceReport::unavailable(
            Source::Preflight,
            format!("{} could not be read: {e}", path.display()),
        ),
    }
}

/// JSONLの収集源（net / cow / etw）を共通の手順で読む。パス解決に失敗した場合と、読めなかった
/// 場合を同じ`unavailable`へ寄せる——利用者から見ればどちらも「その経路の情報が無い」である。
fn collect_jsonl(source: Source, path: Option<PathBuf>) -> SourceReport {
    let Some(path) = path else {
        return SourceReport::unavailable(
            source,
            format!(
                "no {} audit log location could be resolved for this session",
                source.label()
            ),
        );
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) => {
            return SourceReport::unavailable(
                source,
                format!("{} could not be read: {e}", path.display()),
            )
        }
    };
    match source {
        Source::Network => normalize::normalize_net_audit(&text),
        Source::Cow => normalize::normalize_cow_denied(&text),
        Source::Etw => normalize::normalize_fs_audit(&text),
        Source::Preflight => unreachable!("preflight is read as JSON, not JSONL"),
    }
}

/// OS監査収集器（M15.7、`harness-policy-learnd`）の出力先。`net-audit.jsonl`と同じ
/// セッションディレクトリに置く——同じセッションで起きたことを1箇所に集める。
pub(crate) fn fs_audit_path(
    workspace_root: &Path,
    session: Option<&str>,
    explicit_path: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(path) = explicit_path {
        return Some(path.to_path_buf());
    }
    resolve_sandbox_dir(workspace_root, session)
        .map(|dir| workspace_root.join(dir).join("fs-audit.jsonl"))
}

#[cfg(windows)]
fn cow_denied_path(session: Option<&str>) -> Option<PathBuf> {
    resolve_cow_diff_layer_dir(session)
        .map(|dir| dir.join(harness_change_ledger::COW_DENIED_LEDGER_FILENAME))
}

#[cfg(not(windows))]
fn cow_denied_path(_session: Option<&str>) -> Option<PathBuf> {
    None
}

/// `.harness/settings.json`のパス（`harness policy apply`の書込先）。
fn project_settings_path(workspace_root: &Path) -> PathBuf {
    workspace_root.join(".harness").join("settings.json")
}

/// 既に許可されているFSパスを読む（§15.1の差分推論の入力）。
///
/// **既に許可済みなのに拒否された**＝その許可では足りない、が確定するので、提案そのものを
/// 昇格候補へ差し替える（D-46、`harness_policy::generalize`）。読むのはここ（CLI層）で、
/// 判定は純粋クレート側が行う。
///
/// 収集源は2つある。**片方だけでは足りない**——
///
/// | 収集源 | 何を捉えるか |
/// |---|---|
/// | `.harness/settings.json`の`fs.*` | 設定ファイルで宣言した穴。access種別が正確 |
/// | `fs-passthrough-ledger.json`の`entries` | **実際にACE付与が確認できた**ルート。`--fs-allow`由来を含む |
///
/// 台帳を混ぜる前は、`--fs-allow`だけで穴を開けたユーザーが「その許可では足りない」に
/// 永遠に到達できなかった（`plans/PLAN-M15.7-FOLLOWUP.md` W4）。
fn granted_paths(workspace_root: &Path) -> harness_policy::GrantedPaths {
    let ledger_json = crate::fs_grants::fs_ledger()
        .path()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .unwrap_or_default();
    granted_paths_from(workspace_root, &ledger_json)
}

/// [`granted_paths`]の判断部分。台帳の中身を引数で受けるのは**テストをこの開発機の実台帳から
/// 切り離すため**——`fs-passthrough-ledger.json`はマシン全体で1つしか無く、差し替えられない。
fn granted_paths_from(workspace_root: &Path, ledger_json: &str) -> harness_policy::GrantedPaths {
    let settings = harness_config::Settings::load(workspace_root);
    // 設定の相対パスは`workspace_root`基準で絶対化する（`fs_passthrough`を組み立てる
    // `startup::sandbox`と同じ扱い）。生のまま比較すると、相対指定した穴が拒否パス
    // （常に絶対パス）と一致せず、覆っていないと誤判定する。
    let from_settings: Vec<(String, harness_config::FsAccess)> = settings
        .fs
        .unwrap_or_default()
        .to_fs_passthrough()
        .into_iter()
        .map(|(path, access)| {
            (
                workspace_root
                    .join(&path)
                    .to_string_lossy()
                    .replace('\\', "/"),
                access,
            )
        })
        .collect();

    harness_policy::GrantedPaths::merged(
        from_settings,
        harness_policy::normalize::granted_from_ledger(ledger_json),
    )
}

fn read_settings_value(workspace_root: &Path) -> serde_json::Value {
    let path = project_settings_path(workspace_root);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or(serde_json::Value::Null)
}

// ---------------------------------------------------------------------------
// 表示
// ---------------------------------------------------------------------------

fn render_unavailable(input: &PolicyInput) -> String {
    let unavailable = input.unavailable();
    if unavailable.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for (source, note) in unavailable {
        out.push_str(&format!(
            "note: no data from the '{}' source -- {note}\n",
            source.label()
        ));
    }
    out.push_str(
        "note: collection is best-effort and never blocks harness (D-43); the proposals below \
         are based only on the sources that were readable.\n",
    );
    out
}

fn render_proposals_text(proposals: &[RuleProposal], verdicts: &[(String, GateVerdict)]) -> String {
    if proposals.is_empty() {
        return "(no denied resources to propose rules for)\n".to_string();
    }
    let mut out = String::new();
    for proposal in proposals {
        let verdict = verdicts
            .iter()
            .find(|(id, _)| id == &proposal.id)
            .map(|(_, v)| v);
        let blocked = verdict.is_some_and(|v| v.is_rejected());
        // D-47: 幅のガードは`--require-sandbox`とは別軸なので、印も別にする。
        // **一覧からは消さない**（D-43「失敗を隠さない」）。
        let breadth = harness_policy::breadth::check(proposal);
        let mut marks = String::new();
        if blocked {
            marks.push_str("[blocked] ");
        }
        if breadth.is_too_broad() {
            marks.push_str("[too-broad] ");
        }
        out.push_str(&format!(
            "{}{}  {} = {:?}   (observed {}x via {})\n",
            marks,
            proposal.id,
            proposal.key.dotted(),
            proposal.value,
            proposal.observed_count(),
            proposal
                .sources()
                .iter()
                .map(|s| s.label())
                .collect::<Vec<_>>()
                .join("+"),
        ));
        for warning in &proposal.warnings {
            out.push_str(&format!("    warning: {warning}\n"));
        }
        if let Some(message) = verdict.and_then(|v| v.message()) {
            let label = if blocked { "refused" } else { "warning" };
            out.push_str(&format!("    {label}: {message}\n"));
        }
        if let Some(message) = breadth.message() {
            out.push_str(&format!("    refused: {message}\n"));
        }
    }
    out.push_str(
        "\nNothing above has been applied. Review the entries, then run \
         `harness policy apply --accept <id>[,<id>...]` to write the ones you want into \
         .harness/settings.json (changes take effect on the next start).\n",
    );
    out
}

fn render_output(
    proposals: &[RuleProposal],
    verdicts: &[(String, GateVerdict)],
    output_format: OutputFormat,
) -> String {
    match output_format {
        OutputFormat::Json => {
            serde_json::to_string(proposals).unwrap_or_else(|_| "[]".to_string()) + "\n"
        }
        OutputFormat::Jsonl => {
            let mut out = String::new();
            for proposal in proposals {
                if let Ok(line) = serde_json::to_string(proposal) {
                    out.push_str(&line);
                    out.push('\n');
                }
            }
            out
        }
        OutputFormat::Text => render_proposals_text(proposals, verdicts),
    }
}

fn render_candidates(input: &PolicyInput, output_format: OutputFormat) -> String {
    let candidates = input.candidates();
    match output_format {
        OutputFormat::Json => {
            serde_json::to_string(&candidates).unwrap_or_else(|_| "[]".to_string()) + "\n"
        }
        OutputFormat::Jsonl => {
            let mut out = String::new();
            for candidate in &candidates {
                if let Ok(line) = serde_json::to_string(candidate) {
                    out.push_str(&line);
                    out.push('\n');
                }
            }
            out
        }
        OutputFormat::Text => {
            if candidates.is_empty() {
                return "(no denied resources recorded)\n".to_string();
            }
            let mut out = String::new();
            for candidate in &candidates {
                let (target, access) = match &candidate.requested {
                    harness_policy::Requested::Fs { path, access } => {
                        (path.clone(), access.settings_key())
                    }
                    harness_policy::Requested::Net { domain } => (domain.clone(), "domain"),
                };
                out.push_str(&format!(
                    "{:<9} {:<11} {:<60} x{:<5} {}\n",
                    candidate.source.label(),
                    access,
                    target,
                    candidate.count,
                    candidate.reason
                ));
            }
            out
        }
    }
}

// ---------------------------------------------------------------------------
// サブコマンド本体
// ---------------------------------------------------------------------------

pub(crate) fn run_policy_subcommand(
    action: PolicyAction,
    workspace_root: &Path,
    cli: &Cli,
) -> ExitCode {
    let require_sandbox = parse_require_sandbox(cli.require_sandbox.as_deref());

    match action {
        PolicyAction::Audit {
            session,
            source,
            output_format,
        } => {
            let sources = match resolve_sources(source.as_deref()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
            };
            let input = collect_input(workspace_root, session.as_deref(), &sources);
            if output_format == OutputFormat::Text {
                eprint!("{}", render_unavailable(&input));
            }
            print!("{}", render_candidates(&input, output_format));
            ExitCode::SUCCESS
        }

        PolicyAction::Suggest {
            session,
            source,
            output_format,
        } => {
            let sources = match resolve_sources(source.as_deref()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
            };
            let input = collect_input(workspace_root, session.as_deref(), &sources);
            let proposals = input.proposals_with_granted(&granted_paths(workspace_root));
            let verdicts = gate::check_all(&proposals, require_sandbox);
            if output_format == OutputFormat::Text {
                eprint!("{}", render_unavailable(&input));
            }
            print!("{}", render_output(&proposals, &verdicts, output_format));
            ExitCode::SUCCESS
        }

        PolicyAction::Learn {
            duration,
            session,
            output_format,
        } => run_learn(
            workspace_root,
            session.as_deref(),
            duration,
            require_sandbox,
            output_format,
        ),

        PolicyAction::Apply {
            session,
            source,
            accept,
            yes,
        } => {
            let sources = match resolve_sources(source.as_deref()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
            };
            let input = collect_input(workspace_root, session.as_deref(), &sources);
            let proposals = input.proposals_with_granted(&granted_paths(workspace_root));
            apply_accepted(workspace_root, &proposals, &accept, yes, require_sandbox)
        }
    }
}

/// `harness policy learn`: 収集器を単体で起動し、一定時間集めてから提案を表示する。
///
/// **収集器が起動できなくても失敗にしない**（D-43 fail-open）。起動できなかった理由を
/// 明示したうえで、既存3経路の記録だけで提案する——収集は境界ではないので（P-07）、
/// 張れないことを理由に「何を許せばよいか」を answering できなくする理由が無い。
#[cfg(windows)]
fn run_learn(
    workspace_root: &Path,
    session: Option<&str>,
    duration_secs: u64,
    require_sandbox: harness_core::RequireSandbox,
    output_format: OutputFormat,
) -> ExitCode {
    use harness_sandbox::tier2a::policy_learnd;

    let Some(sink) = fs_audit_path(workspace_root, session, None) else {
        eprintln!(
            "no sandbox session directory found under .harness/sandbox/. Start a harness session \
             first (the collector writes into that session's directory)."
        );
        return ExitCode::FAILURE;
    };
    let session_profile = harness_sandbox::tier2a::session_profile::current_profile_name();

    eprintln!(
        "starting the OS audit collector for {duration_secs}s (a UAC prompt will appear once; \
         an ETW real-time session requires administrator rights)"
    );
    let handle = match policy_learnd::client::start(policy_learnd::LearnPolicy {
        session_profile,
        workspace_root: workspace_root.to_path_buf(),
        fs_audit_log_path: sink,
        harness_pid: Some(std::process::id()),
        record_all: false,
    }) {
        Ok(handle) => Some(handle),
        Err(e) => {
            // fail-open: 集められないだけで、提案そのものは残り3経路でできる。
            eprintln!(
                "warning: the OS audit collector did not start ({e}); proposals will be based on \
                 the already-recorded sources only (preflight / network / CoW)"
            );
            None
        }
    };
    if let Some(handle) = handle.as_ref() {
        if !handle.etw_available() {
            eprintln!(
                "warning: the collector started but could not open an ETW session; nothing will \
                 be collected this run (the reason is recorded in fs-audit.jsonl)"
            );
        }
    }

    if handle.is_some() {
        eprintln!("collecting... (run the commands you want to learn from in another window)");
        std::thread::sleep(std::time::Duration::from_secs(duration_secs));
    }

    if let Some(handle) = handle {
        match handle.stop() {
            Ok(written) => eprintln!("collector stopped; {written} denial(s) recorded"),
            Err(e) => eprintln!("warning: the collector did not shut down cleanly: {e}"),
        }
    }

    let input = collect_input(workspace_root, session, &Source::ALL);
    let proposals = input.proposals_with_granted(&granted_paths(workspace_root));
    let verdicts = gate::check_all(&proposals, require_sandbox);
    if output_format == OutputFormat::Text {
        eprint!("{}", render_unavailable(&input));
    }
    print!("{}", render_output(&proposals, &verdicts, output_format));
    ExitCode::SUCCESS
}

#[cfg(not(windows))]
fn run_learn(
    _workspace_root: &Path,
    _session: Option<&str>,
    _duration_secs: u64,
    _require_sandbox: harness_core::RequireSandbox,
    _output_format: OutputFormat,
) -> ExitCode {
    eprintln!(
        "error: harness policy learn is Windows-only (the OS audit collector uses ETW). \
         `harness policy suggest` works on every platform with the already-recorded sources."
    );
    ExitCode::FAILURE
}

/// `--accept`で指定されたidを解決し、矛盾チェックを通してから書き込む。
///
/// **部分適用しない**: 1件でも未知のidがある、または1件でも`--require-sandbox`と矛盾する場合、
/// 何も書かずに失敗する。「一部だけ通った」状態は、ユーザーが受け入れたつもりの構成と
/// 実際の構成がずれるため、設定という「後から効いてくる」対象では特に避ける。
fn apply_accepted(
    workspace_root: &Path,
    proposals: &[RuleProposal],
    accept: &[String],
    yes: bool,
    require_sandbox: harness_core::RequireSandbox,
) -> ExitCode {
    let requested_ids: Vec<String> = accept
        .iter()
        .flat_map(|arg| arg.split(','))
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .collect();

    if requested_ids.is_empty() {
        eprintln!(
            "harness policy apply requires --accept <id>[,<id>...]. Run `harness policy suggest` \
             first to see the ids. There is deliberately no \"accept everything\" shorthand \
             (plans/DESIGN-SANDBOX-APPPOLICY.md D-42)."
        );
        return ExitCode::FAILURE;
    }

    let mut accepted: Vec<&RuleProposal> = Vec::new();
    let mut unknown: Vec<&str> = Vec::new();
    for id in &requested_ids {
        match proposals.iter().find(|p| &p.id == id) {
            Some(proposal) => {
                if !accepted.iter().any(|p| p.id == proposal.id) {
                    accepted.push(proposal);
                }
            }
            None => unknown.push(id),
        }
    }
    if !unknown.is_empty() {
        eprintln!(
            "unknown proposal id(s): {}. Ids come from `harness policy suggest` and depend on \
             --source, so pass the same options to both commands.",
            unknown.join(", ")
        );
        return ExitCode::FAILURE;
    }

    // 2軸の拒否を1箇所へ集める。どちらも**部分適用しない**（1件でも該当なら何も書かない）。
    //
    // - D-42: `read_write`への昇格等が`--require-sandbox`の宣言と矛盾していないか
    // - D-47: 受理1回でマシン全体が開くような広すぎる値でないか
    //
    // 軸を分けたまま両方を通すのは、拒否された理由がユーザーから見て別物だからである
    // （前者は自分の宣言との矛盾、後者は値そのものの広さ）。
    let mut refused = Vec::new();
    for proposal in &accepted {
        if let GateVerdict::Rejected(message) = gate::check_proposal(proposal, require_sandbox) {
            refused.push(format!("{}: {message}", proposal.id));
        }
        if let Some(message) = harness_policy::breadth::check(proposal).message() {
            refused.push(format!("{}: {message}", proposal.id));
        }
    }
    if !refused.is_empty() {
        eprintln!("refusing to apply (nothing was written):");
        for message in refused {
            eprintln!("  {message}");
        }
        return ExitCode::FAILURE;
    }

    let existing = read_settings_value(workspace_root);
    let settings_diff = diff::compute_diff(&existing, &accepted);
    if settings_diff.is_empty() {
        println!("(every accepted proposal is already present in .harness/settings.json)");
        return ExitCode::SUCCESS;
    }

    let path = project_settings_path(workspace_root);
    println!("{}:", path.display());
    print!("{}", settings_diff.render_text());
    for proposal in &accepted {
        if let Some(message) = gate::check_proposal(proposal, require_sandbox).message() {
            println!("  warning ({}): {message}", proposal.id);
        }
    }

    if !confirm_write(yes) {
        eprintln!("aborted; nothing was written");
        return ExitCode::FAILURE;
    }

    let updated = diff::apply_to_settings(&existing, &settings_diff);
    let mut text = match serde_json::to_string_pretty(&updated) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("failed to serialize the updated settings: {e}");
            return ExitCode::FAILURE;
        }
    };
    text.push('\n');
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("failed to create {}: {e}", parent.display());
            return ExitCode::FAILURE;
        }
    }
    if let Err(e) = std::fs::write(&path, text) {
        eprintln!("failed to write {}: {e}", path.display());
        return ExitCode::FAILURE;
    }

    println!(
        "wrote {}. The change takes effect on the next harness start -- harness never reloads \
         its own configuration at runtime (plans/DESIGN.md, tool system).",
        path.display()
    );
    ExitCode::SUCCESS
}

/// 書込前の確認。非対話（パイプ・リダイレクト）では`--yes`を必須にする——ヘッドレスは
/// 対話プロンプトを一切出さない原則（`plans/DESIGN.md`§非対話モード）に従い、
/// 「答えが返ってこないまま既定で進む」形を作らない。
fn confirm_write(yes: bool) -> bool {
    if yes {
        return true;
    }
    if !std::io::stdin().is_terminal() {
        eprintln!(
            "refusing to write without confirmation: stdin is not a terminal, so no prompt can \
             be shown. Re-run with --yes if you have reviewed the diff above."
        );
        return false;
    }
    eprint!("apply these changes to .harness/settings.json? [y/N] ");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim(), "y" | "Y" | "yes" | "Yes")
}

#[cfg(test)]
#[path = "policy_cmd_tests.rs"]
mod policy_cmd_tests;
