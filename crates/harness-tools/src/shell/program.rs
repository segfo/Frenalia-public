//! `run_program`——プログラム名と引数の配列を、**シェルを通さずに**起こす
//! （`plans/DESIGN-RUNSHELL-ALLOWLIST.md` §2、D-96・D-98）。
//!
//! # なぜ`run_shell`と別のツールなのか
//!
//! 自由記述のコマンド行は、シェルが解釈するまで何個のコマンドになるか決まらない。
//! `git log | rm …` のように、許可したつもりの無いコマンドが同じ行に紛れ込む。
//! ここでは**解釈する層そのものを通らない**。配列は OS へ argv としてそのまま届くので、
//! 引数に `;` や `|` を書いても文字として届くだけで、コマンドは増えない。
//!
//! # `run_shell`と共有するもの・しないもの
//!
//! 隔離の部品（Job・制限トークン・AppContainer・Redirector・bwrap）、子へ渡す環境、
//! 出力のフッタは`run_shell`と同じものを使う（[`super::prepare_run`]・[`super::push_run_footer`]）。
//! 違うのは「何を起こすか」だけで、それは[`super::runner::Launch`]が持つ。
//!
//! # 限界（同じ場所で言う）
//!
//! - **起動したプログラム自身が引数やファイルをコードとして読むと、その中身は見えない**
//!   （`cmd /c …`・`python build.py`）。それらはインタプリタとして別扱いにする
//!   （[`harness_core::is_interpreter_program`]、D-99）
//! - **Tier3 では使えない**（[`super::runner::TIER3_PROGRAM_UNSUPPORTED`]）
//! - **解決した実行ファイルが指す実体の差し替えは防がない**。担保は隔離Tier（D-14）

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use tokio::time::Duration;

use harness_core::{is_interpreter_program, RiskClass, Tool, ToolCtx, ToolError, ToolOutput};
use harness_core::{parse_tool_input, PermissionSubject, ProgramSubject};

use super::net_decision::classify_net_program;
use super::runner::Launch;
use super::{
    join_output, prepare_run, push_run_footer, resolve_cwd, run_in_tier, DEFAULT_TIMEOUT_MS,
};
#[cfg(windows)]
use super::{transition_denial_note, transition_queue_cursor};

/// ツール名。判定器（`harness-engine`）がインタプリタの判定を掛ける相手を名指すのに使う
/// ——**綴りを複製しない**（`bug-pattern-rules` B-05）。
pub const RUN_PROGRAM_TOOL: &str = "run_program";

/// **知らない項目を拒否する。** 設計（`plans/DESIGN.md` §ツールシステム）が全ツールに約束しているのに
/// 既存のツールに無かったため、余分な項目で判定を騙して素通りする穴があった（BUG-164）。
/// 新しいツールでは最初から作らない。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunProgramInput {
    program: String,
    args: Option<Vec<String>>,
    timeout_ms: Option<u64>,
    cwd: Option<String>,
}

const RUN_PROGRAM_DESCRIPTION: &str =
    "シェルを通さず、プログラムを直接起動して stdout+stderr+終了コードを返す。\
     program は実行ファイルの名前かパス、args は引数の配列で、各要素はそのまま1つの引数として\
     届く（空白・;・|・引用符を含んでよく、シェルに解釈されない）。\
     パイプ・リダイレクト・シェルの組み込み機能は使えない——それらが要るときは run_shell を使う。\
     素の名前は PATH からだけ探し、作業ディレクトリは探さない。";

/// `run_program`の実体。
///
/// **`Default`は「Spawn Daemon の接続なし」を意味する**——`run_shell`（[`super::RunShellTool`]）と
/// 同じ理由で、Tier2aの呼び出しは直接生成へ降格せず内部エラーで断る。
#[derive(Default)]
pub struct RunProgramTool {
    #[cfg(windows)]
    spawn_daemon: Option<harness_sandbox::tier2a::spawnd::SharedSpawnDaemon>,
    /// 拒否された遷移を出力末尾へ注記するか。`run_shell`と同じ値を配る
    /// （[`super::RunShellTool`]の同名の欄のdoc）。
    #[cfg(windows)]
    report_transition_denials: bool,
}

impl RunProgramTool {
    /// Tier2aのセッションが持つSpawn Daemon接続を注入する。**本番のTier2a経路は必ずこちら**。
    /// `report_transition_denials`は呼び出し元が必ず選ぶ（既定値を持たせない）。
    #[cfg(windows)]
    pub fn with_spawn_daemon(
        spawn_daemon: harness_sandbox::tier2a::spawnd::SharedSpawnDaemon,
        report_transition_denials: bool,
    ) -> Self {
        Self {
            spawn_daemon: Some(spawn_daemon),
            report_transition_denials,
        }
    }
}

fn run_program_input_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "program": {
                "type": "string",
                "description": "起動するプログラム。実行ファイルの名前（例: git）かパス"
            },
            "args": {
                "type": "array",
                "items": { "type": "string" },
                "description": "引数の配列。各要素がそのまま1つの引数になる（省略時は引数なし）"
            },
            "timeout_ms": { "type": "integer", "description": "タイムアウト（ミリ秒、省略時120000）" },
            "cwd": { "type": "string", "description": "ワークスペースルートからの相対作業ディレクトリ" }
        },
        "required": ["program"],
        "additionalProperties": false
    })
}

#[async_trait]
impl Tool for RunProgramTool {
    fn name(&self) -> &str {
        RUN_PROGRAM_TOOL
    }

    fn description(&self) -> &str {
        RUN_PROGRAM_DESCRIPTION
    }

    fn input_schema(&self) -> serde_json::Value {
        run_program_input_schema()
    }

    fn spec_for_ctx(&self, _ctx: &ToolCtx) -> harness_core::ToolSpec {
        harness_core::ToolSpec {
            name: self.name().to_string(),
            description: RUN_PROGRAM_DESCRIPTION.to_string(),
            input_schema: self.input_schema(),
        }
    }

    fn risk(&self, _input: &serde_json::Value) -> RiskClass {
        RiskClass::Exec
    }

    /// 判定の材料（D-101）。解決先（D-103）と、コードを走らせる呼び出しなら縛ったファイル（D-104）を含む。
    /// ファイルを読むので`spawn_blocking`で走らせる（B-31）。**副作用を持たない**——名前の解決には
    /// 子へ渡す環境だけを使い、プロキシや偽DNSを立てる準備処理（`prepare_run`）は呼ばない。
    async fn permission_subject(
        &self,
        input: &serde_json::Value,
        ctx: &ToolCtx,
    ) -> Result<PermissionSubject, ToolError> {
        let input: RunProgramInput = parse_tool_input(input)?;
        let cwd = resolve_cwd(input.cwd.as_deref(), ctx)?;
        let args = input.args.unwrap_or_default();
        let program = input.program;
        let ctx = ctx.clone();
        tokio::task::spawn_blocking(move || {
            PermissionSubject::Program(program_subject(program, args, &cwd, &ctx))
        })
        .await
        .map_err(|e| ToolError::ExecutionFailed(format!("permission subject task failed: {e}")))
    }

    async fn call(&self, input: serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let input: RunProgramInput = parse_tool_input(&input)?;
        let args = input.args.unwrap_or_default();
        let cwd = resolve_cwd(input.cwd.as_deref(), ctx)?;
        let dur = Duration::from_millis(input.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS));

        let prepared = prepare_run(ctx).await;

        // Tier3（D-108）: **プログラムの解決はコンテナの中で起きる。** ホストのPATHで解けば
        // Windows の絶対パスが argv[0] になり、Linux のコンテナでは必ず失敗する。名前のまま渡す。
        // 偽装インタプリタの拒否（短い名前・リンク）もホストで子を起こすときの検査なので通さない。
        let exe = match ctx.shell_tier.tier == harness_core::ShellTier::Tier3 {
            true => std::path::PathBuf::from(&input.program),
            false => {
                let exe = resolve_program(&input.program, &cwd, &prepared.env)?;
                refuse_disguised_interpreter(&input.program, &exe)?;
                exe
            }
        };
        let exe_str = exe.to_str().ok_or_else(|| {
            ToolError::InvalidInput(format!(
                "the resolved program path is not valid Unicode: {}",
                exe.display()
            ))
        })?;
        // 判定は**起動する実体**の名前で行う（`bug-pattern-rules` B-21）。
        let net_decision = classify_net_program(exe_str, &ctx.net_app.allow_apps);

        // コマンドを走らせる前に、断られた遷移の待ち行列のどこまでが既読かを控える（`run_shell`と同じ）。
        #[cfg(windows)]
        let transition_cursor =
            transition_queue_cursor(self.report_transition_denials, &ctx.workspace_root);

        let super::runner::IsolatedRun {
            out,
            err,
            code,
            setup_warning,
            ..
        } = run_in_tier(
            Launch::Program {
                exe: exe_str,
                args: &args,
            },
            &cwd,
            dur,
            net_decision,
            ctx,
            &prepared,
            #[cfg(windows)]
            self.spawn_daemon.as_ref(),
        )
        .await?;

        let code = code.unwrap_or(-1);
        let mut content = join_output(out, err);
        content.push_str(&format!(
            "\n[exit code: {code}]\n[program: {}]",
            exe.display()
        ));
        #[cfg(windows)]
        let transition_note = transition_denial_note(
            self.spawn_daemon.as_ref(),
            &ctx.workspace_root,
            transition_cursor,
        );
        #[cfg(not(windows))]
        let transition_note = None;
        push_run_footer(
            &mut content,
            ctx,
            net_decision,
            setup_warning,
            transition_note,
            &prepared,
        );

        Ok(ToolOutput {
            content,
            is_error: code != 0,
        })
    }
}

/// `run_program`の判定の材料を計算する（[`RunProgramTool::permission_subject`]）。
fn program_subject(
    program: String,
    args: Vec<String>,
    cwd: &Path,
    ctx: &ToolCtx,
) -> ProgramSubject {
    use crate::approval_binding::{self, ChildView, PathBinding};

    let mut env = harness_sandbox::build_child_env();
    super::env::append_path_extra(&mut env, &ctx.run_shell_path_extra);
    // Tier3 では解決はコンテナの中で起きるので、ホストのPATHで解かない（D-108）。
    // 解いてしまうと、記録は**走りもしない Windows の絶対パス**に縛られる。
    let resolved = match ctx.shell_tier.tier == harness_core::ShellTier::Tier3 {
        true => None,
        false => resolve_program(&program, cwd, &env).ok(),
    };
    let in_workspace = resolved
        .as_deref()
        .is_some_and(|r| approval_binding::is_inside_workspace(&ctx.workspace_root, r));
    // 名前でインタプリタでなくても、実体がそうなら同じ扱い（起動の直前にも断るが、判定もそれに揃える）。
    let disguised = resolved.as_deref().is_some_and(|r| {
        let real = std::fs::canonicalize(r).unwrap_or_else(|_| r.to_path_buf());
        real.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(is_interpreter_program)
    });
    let runs_code = is_interpreter_program(&program) || in_workspace || disguised;

    let mut subject = ProgramSubject {
        resolved: resolved.as_ref().map(|r| r.to_string_lossy().into_owned()),
        runs_code,
        // 符号化された中身は、ハーネスが機械的に解読して承認画面と要約へ渡す（§4.4）。
        // **照合には使わない**——`same_for_approval`も記録もこの欄を見ない。
        decoded: crate::encoded_command::decode_program_args(&program, &args),
        ..ProgramSubject::plain(program, args)
    };
    subject.one_shot_only = false;
    if !runs_code {
        return subject;
    }
    let Ok(view) = ChildView::for_ctx(ctx) else {
        subject.one_shot_only = true;
        return subject;
    };
    let args_binding = approval_binding::bind_program_args(&view, cwd, &subject.args);
    subject.one_shot_only = args_binding.one_shot_only;
    let mut binding = approval_binding::ShellBinding {
        files: args_binding.files,
        previews: args_binding.previews,
        unverifiable: false,
    };
    if in_workspace {
        // ワークスペース内の実行ファイルは、実体そのものも縛る（D-103）。
        match resolved
            .as_deref()
            .and_then(|r| approval_binding::bind_executable(&view, r))
        {
            Some(PathBinding::File(f, p)) => binding.absorb(approval_binding::ShellBinding {
                files: vec![f],
                previews: vec![p],
                unverifiable: false,
            }),
            _ => subject.one_shot_only = true,
        }
    }
    // 解読した各段と、縛ったファイルの中身からも入れ子のスクリプトを縛る（D-120）。
    // `run_shell`と**同じ関数**を通す——片方だけ直されて静かにずれるのを防ぐ（B-05）。
    binding.absorb(approval_binding::bind_decoded(&view, cwd, &subject.decoded));
    let nested = approval_binding::bind_nested(&view, cwd, &binding);
    binding.absorb(nested);
    // ここで確かめ切れなかったものは、恒久承認しない（`run_program`は`one_shot_only`が同じ役）。
    subject.one_shot_only |= binding.unverifiable;
    // 縛ったファイルの中身に入っている符号化された塊も解読する（D-122）。コードを走らせる
    // 呼び出しなので、拡張子で絞らず全部見る。
    subject
        .decoded
        .extend(approval_binding::decode_in_files(&binding.previews, false));
    subject.files = binding.files;
    subject.previews = binding.previews;
    subject
}

/// `program`を、起動する実行ファイルのパスへ解決する（D-98）。
///
/// - **素の名前**は、子へ渡すPATHの**絶対パスの項目だけ**から探す（Windowsは PATHEXT の拡張子も）。
///   **作業ディレクトリは探さない**——ワークスペースへ置かれた同名のファイルに乗っ取られないため。
///   PATHの相対の項目（`.` 等）を落とすのは、`which`がそれをハーネス自身のカレントディレクトリ
///   からの相対として探すためである（`which` 7.0.3 `finder.rs`）
/// - **パス区切りを含む**なら、`cwd`からの相対（または絶対パス）として解決する
/// - Windows で解決先が**バッチファイル**（`.bat`/`.cmd`）なら断る（[`refuse_batch_file`]）
pub(crate) fn resolve_program(
    program: &str,
    cwd: &Path,
    child_env: &[(String, String)],
) -> Result<PathBuf, ToolError> {
    if program.trim().is_empty() {
        return Err(ToolError::InvalidInput(
            "program must not be empty".to_string(),
        ));
    }
    let path_list = absolute_path_entries(child_env);
    let found = which::which_in(program, Some(path_list), cwd).map_err(|_| {
        ToolError::InvalidInput(format!(
            "program not found: {program} (a bare name is looked up only in the child's PATH, \
             never in the working directory; use a relative path such as ./{program} to run a \
             file from the working directory)"
        ))
    })?;
    refuse_batch_file(&found)?;
    Ok(found)
}

/// 子へ渡すPATHのうち、絶対パスの項目だけを残す。
fn absolute_path_entries(child_env: &[(String, String)]) -> std::ffi::OsString {
    let path = child_env
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("PATH"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let dirs = std::env::split_paths(path).filter(|dir| dir.is_absolute());
    std::env::join_paths(dirs).unwrap_or_default()
}

/// Windows では、バッチファイルを起こすと OS が cmd.exe を挟み、**argv を cmd の規則で
/// 解釈し直す**。「配列はそのまま届く」という前提（D-96）がそこで崩れるので起こさない。
#[cfg(windows)]
fn refuse_batch_file(found: &Path) -> Result<(), ToolError> {
    let ext = found
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    if matches!(ext.as_deref(), Some("bat") | Some("cmd")) {
        return Err(ToolError::InvalidInput(format!(
            "{} is a batch file: Windows runs it through cmd.exe, which re-parses the \
             arguments, so the argument array would not arrive as given. Use run_shell instead.",
            found.display()
        )));
    }
    Ok(())
}

#[cfg(not(windows))]
fn refuse_batch_file(_found: &Path) -> Result<(), ToolError> {
    Ok(())
}

/// **判定と実行が別物を見ていないか**を、起動の直前にもう一度確かめる（`bug-pattern-rules` B-21）。
///
/// 判定器（`harness-engine`）がインタプリタかどうかを見るのは、モデルが書いた`program`の
/// **名前**である。起動するのは解決した実体なので、名前と実体が食い違うと判定をすり抜ける。
///
/// ```text
///  program: "POWERS~1.EXE"   ← 短い名前（8.3 形式）。名前ではインタプリタに見えない
///  実体:    powershell.exe
/// ```
///
/// 実体の名前は`canonicalize`で得る（短い名前を正式名へ・シンボリックリンクを実体へ）。
/// **起動には正規化したパスを使わない**——`\\?\`付きのパスを渡すと、自分の置き場所を
/// そのパスから探すプログラムが混乱しうるため。
///
/// **限界**: ハードリンクや、改名したコピー（`cmd.exe`を`foo.exe`へ写したもの）は拾えない。
fn refuse_disguised_interpreter(requested: &str, found: &Path) -> Result<(), ToolError> {
    if is_interpreter_program(requested) {
        return Ok(()); // 名前の時点で判定器が見ている
    }
    let real = std::fs::canonicalize(found).unwrap_or_else(|_| found.to_path_buf());
    let real_name = real.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if is_interpreter_program(real_name) {
        return Err(ToolError::InvalidInput(format!(
            "{requested} resolves to {} , which runs its arguments or files as code. \
             Request it by its real name ({real_name}) so that the approval check sees it.",
            real.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
#[path = "program_tests.rs"]
mod program_tests;
