//! 起動パイプライン Stage1: 引数parse・早期dispatch。
//!
//! 昇格チェック警告・`.env`読込・`Cli::parse`・`workspace_root`解決・資格情報不要な
//! サブコマンドの早期dispatch・`--resume`の妥当性検査までを担う。

use super::*;

/// `--cwd`（省略時は`current_dir()`）で受け取ったworkspaceルートを、**完全修飾された
/// 非verbatimパス**へ揃える（[BUG-067](../../../../docs/bugs/BUG-067.md)）。
///
/// この値は`ToolCtx.workspace_root`として全機構へ配られ、その多くが「完全修飾された絶対パス」を
/// 暗黙の前提にしている。前提が破れると**起動できない**ことが実測で分かった:
///
/// * `--cwd .`（相対）→ `win_common::long_path_string`が`\\?\.`という不正なverbatimパスを作り、
///   AppContainerへのACE付与が`0x80070002`（ファイルが見つかりません）で失敗する。
/// * `--cwd \\?\C:\ws`（verbatim）→ `.harness`書込拒否プローブのPowerShellが`Join-Path`で
///   verbatimパスを扱えず例外になり、preflightが「想定外の終了コード」で止まる。
///
/// **`canonicalize`は使わない。** あれはFSを触ってシンボリックリンク・ジャンクションを解決する
/// ため、ACEを付ける対象がリンク自身からリンク先へすり替わる（境界の意味が変わる）。
/// ここで欲しいのは綴りを揃えることだけなので、FSを一切触らない`std::path::absolute`
/// （`GetFullPathNameW`相当。`.`/`..`は字句的に畳むがリンクは辿らない）を使う。verbatim前置は
/// `absolute`が素通しする仕様なので、共有ヘルパで先に落とす。
fn normalize_workspace_root(raw: &Path) -> PathBuf {
    // 実体は`harness_sandbox::session_scope`（TUIの`/workspace`も同じ関数を通す。
    // 綴りの規則を2つ持つとBUG-066/BUG-068と同型の穴になる）。
    harness_sandbox::session_scope::normalize_workspace_root(raw)
}

/// [`stage_parse_args`]の出力。Stage2（`stage_configure`）以降が必要とする値だけを運ぶ。
pub(super) struct ParsedArgs {
    pub(super) cli: Cli,
    pub(super) workspace_root: PathBuf,
    pub(super) resume_id: Option<String>,
    pub(super) resume_wants_picker: bool,
}

/// 昇格チェック警告・`.env`・`Cli::parse`・`workspace_root`解決・資格情報不要な
/// サブコマンドの早期dispatch・`--resume`の妥当性検査。
///
/// `Err(ExitCode)`は「エラー」に限らない――早期dispatch・`--list-sessions`のように、
/// 正常終了として即座に返すべき`ExitCode`もここに含む（[`run`]側は`Ok`/`Err`を区別せず
/// そのまま返す）。
pub(super) fn stage_parse_args() -> Result<ParsedArgs, ExitCode> {
    // 本体プロセスが管理者権限で起動されていないかを確認する（D-16、
    // `plans/DESIGN-SANDBOX-PRIVSEP.md` §5.3）。harness本体は常に非管理者トークンで動作する
    // 設計であり、ヘルパー機構が無い間は実害が無いが（WFP/VHDX自体を使わないため）、
    // 「本体が管理者ならヘルパー経由でない直接呼び出しに倒れていないか」を明示的に確認する
    // 材料として警告ログを残す。拒否はしない。
    #[cfg(windows)]
    if harness_sandbox::tier2a::privhelper::is_elevated() {
        eprintln!(
            "warning: harness is running with an elevated (administrator) token. harness is \
             designed to always run as a non-administrator process; privileged operations \
             (e.g. `harness fs grant-traverse`) should go through the privilege-separation \
             helper (D-16, plans/DESIGN-SANDBOX-PRIVSEP.md §5.3), not this elevated \
             process directly."
        );
    }

    // カレントディレクトリの`.env`があれば読み込み、プロセスのenvへ反映する（既存の環境変数は
    // 上書きしない、§設定とシークレット「ユーザ/プロジェクト設定」相当の簡易版）。無ければ無視する。
    let _ = dotenvy::dotenv();

    let mut cli = Cli::parse();

    let workspace_root = match cli.cwd.clone() {
        Some(dir) => dir,
        None => match std::env::current_dir() {
            Ok(dir) => dir,
            Err(e) => {
                eprintln!("failed to resolve current directory: {e}");
                return Err(ExitCode::FAILURE);
            }
        },
    };
    let workspace_root = normalize_workspace_root(&workspace_root);
    harness_config::ensure_project_settings_file(&workspace_root);

    // `apply`/`changes`/`discard`サブコマンドはプロバイダ資格情報を一切必要としないため、
    // 他のあらゆる検証より前に処理して即終了する（§非対話モード、プロンプトは一切送らない）。
    // `.take()`（`mem::replace`でNoneに戻す）を使うのは、`Commands::Prompt`分岐で`&cli`を
    // 丸ごと借用したいため。単純な`cli.command`のムーブだと`cli.command`フィールドだけが
    // 部分ムーブされ、以降`&cli`が取れなくなる。
    if let Some(cmd) = cli.command.take() {
        return Err(match cmd {
            Commands::Fs { action } => crate::fs_grants::run_fs_subcommand(action),
            Commands::Tier2a { action } => run_tier2a_subcommand(action),
            Commands::Tier3 { action } => run_tier3_subcommand(action),
            Commands::Cow { action } => run_cow_subcommand(action),
            Commands::Net { action } => run_net_subcommand(action, &workspace_root),
            // `memory`は記憶ディレクトリ（workspace外・データディレクトリ配下）とこの
            // ワークスペースのパスしか触らず、sandboxもプロバイダ資格情報も要らない
            // （`net`/`policy`と同じ位置づけ）。
            Commands::Memory { action } => run_memory_subcommand(action, &workspace_root),
            // `policy`はワークスペースの監査ログ・ユーザグローバル台帳・`.harness/settings.json`
            // しか触らず、sandboxもプロバイダ資格情報も要らない（`net`と同じ位置づけ）。
            // `--require-sandbox`の矛盾チェック（D-42）のため`&cli`も渡す。
            Commands::Policy { action } => run_policy_subcommand(action, &workspace_root, &cli),
            // `mcp`は`.harness/settings.json`の宣言とユーザグローバルの承認台帳しか触らず、
            // sandboxもプロバイダ資格情報も要らない（`net`/`policy`と同じ位置づけ）。
            Commands::Mcp { action } => run_mcp(action, &workspace_root),
            Commands::Prompt => run_prompt_subcommand(&cli, &workspace_root),
            other => run_sandbox_subcommand(other, &workspace_root),
        });
    }

    // `--list-sessions`はプロバイダ資格情報を一切必要としないため、他のあらゆる検証より前に
    // 処理して即終了する（§非対話モード、プロンプトは一切送らない）。
    if cli.list_sessions {
        let sessions_dir = workspace_root.join(".harness").join("sessions");
        return Err(match harness_engine::SessionStore::list(&sessions_dir) {
            Ok(summaries) => {
                print_session_list(&summaries, cli.output_format);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("failed to list sessions in {}: {e}", sessions_dir.display());
                ExitCode::FAILURE
            }
        });
    }

    // 引数なし`--resume`（値省略、空文字列扱い）はヘッドレスでは非対話原則により拒否する。
    // ピッカーはTTYが要る対話TUIでのみ意味を持つ（§非対話モード「ヘッドレスモードは対話
    // プロンプトを一切出さない」）。
    let resume_wants_picker = cli.resume.as_deref() == Some("");
    if resume_wants_picker && cli.print.is_some() {
        eprintln!("--resume without a value opens an interactive picker and is not supported with -p/--print; pass --resume <id> explicitly");
        return Err(ExitCode::FAILURE);
    }
    let resume_id = cli.resume.clone().filter(|s| !s.is_empty());

    if cli.fork_session && resume_id.is_none() && !cli.continue_session {
        eprintln!("--fork-session requires --resume <id> or --continue");
        return Err(ExitCode::FAILURE);
    }
    if cli.fork_session && resume_wants_picker {
        eprintln!("--fork-session cannot be combined with a bare --resume (use the picker's 'f' key instead)");
        return Err(ExitCode::FAILURE);
    }

    Ok(ParsedArgs {
        cli,
        workspace_root,
        resume_id,
        resume_wants_picker,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **BUG-067の回帰テスト**: `--cwd`の綴りが揺れても、以降の全機構が受け取るのは
    /// 完全修飾された非verbatimパスであること。実測で分かった起動不能の2形
    /// （相対パス・`\\?\`前置）が、ここで揃うことで解消する。
    #[test]
    fn workspace_root_is_normalized_to_a_fully_qualified_non_verbatim_path() {
        let cwd = std::env::current_dir().expect("current_dir");
        let expected = std::path::absolute(&cwd).expect("absolute(cwd)");

        // 相対パス（`--cwd .`）はプロセスのcwd基準で完全修飾される。
        assert_eq!(normalize_workspace_root(Path::new(".")), expected);
        // verbatim前置は落ちる（`long_path_string`が二重の`\\?\`を作らないように）。
        let verbatim = PathBuf::from(format!(r"\\?\{}", cwd.display()));
        assert_eq!(normalize_workspace_root(&verbatim), expected);
        // 末尾の区切りも落ちる。
        let trailing = PathBuf::from(format!(r"{}\", cwd.display()));
        assert_eq!(normalize_workspace_root(&trailing), expected);
        // 既に正規形なら何も変えない（冪等）。
        assert_eq!(normalize_workspace_root(&expected), expected);
    }

    /// **大小差は潰さない。** `canonicalize`ではなく`std::path::absolute`を使っているため
    /// FSを触らず、綴りの大小はユーザーが打ったまま残る（Windowsのパス比較は大小を区別せず、
    /// 判定側は`path_rules::relative_under_root`が吸収するので、ここで潰す必要が無い）。
    /// シンボリックリンク・ジャンクションを解決しないこと（＝ACEを付ける対象がすり替わらない）
    /// も同じ性質から従う。
    #[test]
    fn normalization_does_not_touch_the_filesystem_so_case_and_links_are_preserved() {
        let diff_layer = PathBuf::from(r"C:\WS\Sub");
        assert_eq!(
            normalize_workspace_root(&diff_layer),
            PathBuf::from(r"C:\WS\Sub")
        );
    }
}
