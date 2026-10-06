//! `show`・`approve`サブコマンド——記録した候補を見せる・承認して`policy.json`へ書く（[`super`]のCLIの続き）。
//!
//! 2026-10-05に`main.rs`から**そのまま**移した（`main.rs`は本体1,000行を超えているので、P4.5 で位置ごとの
//! ドメインの記録を扱う前に置き場を分けた。`plans/position-domains/P4.md`）。引数の解決・確認のプロンプトは
//! `main.rs`の関数をそのまま使う。
//!
//! # 位置の情報がある記録（P4.5）
//!
//! 候補は画面（承認待ちの FS/ネットのタブ）と同じ`position_candidates::load`で作るので、同じ記録の`fs-N`が画面と
//! 同じ候補を指す。`show`は各行に書く先のドメインを添え、`approve`は候補ごとのドメインへファイルの宣言だけを書く
//! （辺は書かない。辺が要る候補と`--domain`は断る——`position_approve::cli_plan`）。位置の情報は windows 専用の
//! 部品から読むので、非windowsでは今までの1つの一覧のまま。

use std::path::PathBuf;
use std::process::ExitCode;

use super::{confirm_write, resolve_limit, resolve_require_sandbox, resolve_workspace};

pub(super) fn run_show(
    session: Option<&str>,
    workspace: Option<PathBuf>,
    limit: Option<usize>,
    tree: bool,
    net: bool,
) -> ExitCode {
    use harness_policy_editor::session_dir;

    let workspace_root = resolve_workspace(workspace);
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
    // **失敗した記録は、まず理由を出す。** 文言はマニフェスト側が1つだけ持つ（規則5）。
    if let Some(note) = manifest.failure_note() {
        eprintln!("{note}");
    }
    for warning in &manifest.warnings {
        eprintln!("記録時の警告: {warning}");
    }

    // パス2の記録は**ネットワークとFSの両方**を見せる（`--net`はネットワークだけに絞る指定）。
    //
    // 以前はパス2ならネットワークだけを出して`return`していた（当時のパス2は
    // `fs-audit.jsonl`を書かなかったので、FS側は常に0件だった）。段階4でdeny-only収集器を
    // 配線してからは、**「なぜコマンドが失敗したか」の答えはFS側にある**——
    // ここで打ち切ると、`Access is denied`で落ちたユーザーが次に何を許可すればよいかを
    // 見る場所が1つも無くなる（TUIの編集画面も同じ理由で両方を出す）。
    let show_net = net || manifest.pass == 2;
    if show_net {
        // 候補の取り込み口はその記録を走らせたモードで決まる（決定64）。欄が無い古い記録は記録モード。
        let aggregate = harness_policy_editor::net_aggregate::from_log(
            &dir.net_audit_log_path(),
            manifest.net_mode(),
        );
        print!(
            "{}",
            harness_policy_editor::net_aggregate::render(&aggregate, limit)
        );
        // `--net`は「ネットワークだけ」の意思表示なので、FS側は出さない。
        if net {
            return ExitCode::SUCCESS;
        }
        let fs = harness_policy_editor::aggregate::from_session(&dir, &manifest);
        // **収集器が起きなかったときこそ出す。** 「観測していません」と「拒否は0件でした」は
        // 別の事実で、区別できなければfail-openは単なる隠蔽になる（D-43）。
        // `collector_started`で囲むと、起きなかったときだけ何も出ない正反対の挙動になる
        // ——TUIの編集画面で実際にそうなっていた（BUG-093）。
        print!(
            "{}",
            harness_policy_editor::record_net::render_fs_denials(
                &fs,
                manifest.collector_started,
                manifest.etw_available,
                manifest.net_mode(),
            )
        );
        // **候補一覧は収集器の生死で隠さない。** かつては`collector_started`で囲っていたが、
        // FS候補は観測だけから作られるものではない——実行前診断が名指しした実行ファイルは
        // 収集器がまったく起きなくても候補になる（`aggregate`のモジュールdoc）。囲んだままだと
        // **起動できなかった当のexeが、いちばん知りたい場面でだけ画面から消える**。
        // 何も観測できていないことは`render_notes`が別に言う（D-43）。
        print!("{}", harness_policy_editor::aggregate::render(&fs, limit));
        if tree {
            print!(
                "{}",
                harness_policy_editor::aggregate::render_process_tree(&fs)
            );
        }
        return ExitCode::SUCCESS;
    }

    if !manifest.collector_started {
        eprintln!("警告: この記録では収集器が起動していません（FSアクセスは記録されていません）");
    } else if !manifest.etw_available {
        eprintln!("警告: この記録ではETWセッションが張れていません（何も観測できていません）");
    }

    // 位置の情報がある記録は候補をドメインごとに作る（画面と同じ入口・同じ番号。P4.5）。
    #[cfg(windows)]
    {
        let candidates =
            harness_policy_editor::position_candidates::load(&dir, &manifest, &workspace_root);
        print!(
            "{}",
            harness_policy_editor::position_candidates::render(&candidates, limit)
        );
        if tree {
            println!();
            print!(
                "{}",
                harness_policy_editor::aggregate::render_process_tree(&candidates.fs)
            );
        }
    }
    #[cfg(not(windows))]
    {
        let aggregate = harness_policy_editor::aggregate::from_session(&dir, &manifest);
        print!(
            "{}",
            harness_policy_editor::aggregate::render(&aggregate, limit)
        );
        if tree {
            println!();
            print!(
                "{}",
                harness_policy_editor::aggregate::render_process_tree(&aggregate)
            );
        }
    }
    ExitCode::SUCCESS
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run_approve(
    session: Option<&str>,
    workspace: Option<PathBuf>,
    domain: Option<&str>,
    accept: &[String],
    require_sandbox: Option<&str>,
    yes: bool,
) -> ExitCode {
    use harness_policy_editor::approve::{self, ApproveRequest, PathClass};
    use harness_policy_editor::session_dir;

    let workspace_root = resolve_workspace(workspace);
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

    // カンマ区切りを展開する（`--accept fs-1,fs-2`と`--accept fs-1 --accept fs-2`の両方を許す）。
    let accept_ids: Vec<String> = accept
        .iter()
        .flat_map(|arg| arg.split(','))
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .collect();

    // idは候補の並びから決まるので、`show`とまったく同じ経路で作り直す。位置の情報がある記録は候補ごとのドメインへ
    // 書く別の経路（P4.5）。
    #[cfg(windows)]
    let proposals = {
        let candidates =
            harness_policy_editor::position_candidates::load(&dir, &manifest, &workspace_root);
        if candidates.by_position() {
            return approve_by_position(
                &workspace_root,
                &manifest,
                &candidates,
                domain,
                &accept_ids,
                require_sandbox,
                yes,
            );
        }
        candidates.proposals
    };
    #[cfg(not(windows))]
    let proposals = harness_policy_editor::aggregate::from_session(&dir, &manifest).proposals();

    // ドメイン名の既定はコマンドの先頭トークン（`cargo build` → `cargo`）。
    let domain = domain.map(|d| d.to_string()).unwrap_or_else(|| {
        harness_policy_editor::policy_file::default_domain_name(&manifest.command)
    });
    if domain.is_empty() {
        eprintln!("ドメイン名を決められませんでした。--domain <name> を指定してください。");
        return ExitCode::FAILURE;
    }

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

    println!(
        "{}:",
        harness_policy_editor::policy_file::path(&workspace_root).display()
    );
    println!(
        "  ドメイン: {domain}{}",
        if plan.report.created_domain {
            "（新規）"
        } else {
            ""
        }
    );
    for (key, value) in &plan.report.added {
        println!("  + {key} = {value}");
    }
    for (key, value) in &plan.report.already_present {
        println!("  = {key} = {value}  （既にあります）");
    }
    for warning in &plan.warnings {
        println!("  ! {warning}");
    }
    // 遷移先のドメインへ足すと、そこへの辺が呼び出し元へ渡す権限が増える（決定66。TUI の確認と同じ部品）。
    for line in harness_policy_editor::exposure_view::lines(&plan.widening) {
        println!("{line}");
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

/// `approve`の、位置の情報がある記録の経路（P4.5）。候補ごとのドメインへ**ファイルの宣言だけ**を書く。明細は画面の
/// 確認ダイアログと同じ（`position_approve::confirmation_lines`）。保存は1回、承認台帳はその後。
#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn approve_by_position(
    workspace_root: &std::path::Path,
    manifest: &harness_policy_editor::RecordManifest,
    candidates: &harness_policy_editor::position_candidates::SessionCandidates,
    domain_flag: Option<&str>,
    accept_ids: &[String],
    require_sandbox: harness_core::RequireSandbox,
    yes: bool,
) -> ExitCode {
    use harness_policy_editor::position_approve;

    let plan = match position_approve::cli_plan(
        workspace_root,
        manifest,
        candidates,
        accept_ids,
        domain_flag,
        require_sandbox,
        harness_policy_editor::session_dir::now_unix_ms(),
    ) {
        Ok(plan) => plan,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    for line in
        position_approve::confirmation_lines(workspace_root, &plan, &std::collections::BTreeSet::new())
    {
        println!("{line}");
    }
    if plan.is_empty() {
        println!();
        println!("（承認済みの内容に変化はありません。何も書きませんでした）");
        return ExitCode::SUCCESS;
    }
    if !confirm_write(yes) {
        eprintln!("中止しました。何も書いていません。");
        return ExitCode::FAILURE;
    }
    if let Err(e) =
        position_approve::commit(workspace_root, &plan, &harness_policy_editor::policy_file::save)
    {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }
    println!();
    println!(
        "書きました: {}",
        harness_policy_editor::policy_file::path(workspace_root).display()
    );
    println!(
        "次: 新しい位置のドメインと遷移の辺は TUI（F2 の「遷移・観測から」）で承認します（CLI は辺を書きません）"
    );
    ExitCode::SUCCESS
}
