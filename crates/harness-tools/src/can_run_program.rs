//! [段階6e] `can_run_program`——モデルが「いま何を起こせるか」を引くための読み取り専用ツール
//! （`plans/DESIGN-MAC-TRANSITION-POLICY.md` §19.3.8）。
//!
//! # 何のためにあるのか
//!
//! 遷移MAC（どのプログラムがどのプログラムを起こしてよいかをOSに強制させる機構）が効いていると、
//! **宣言外のプロセス生成は拒否される**。ところがその宣言の中身は起こす側からは見えないので、
//! モデルは`git`を起こせるのかどうかを**撃って拒否されるまで知れない**。
//!
//! 一覧をシステムプロンプトへ載せる手もあるが、**それをすると宣言の増加がそのまま
//! プロンプトの肥大になる**（§19.3.8）。だから「要るときに引く」形にし、その受け口がこれである。
//!
//! # 持たせないもの
//!
//! - **書き込み口**。ポリシーの変更は常にユーザーの明示操作である（D-42）
//! - **LLMの呼び出し**。並べ替えは決定的な関数だけで行う（§19.3.8の理由2つ）
//! - **同義語の辞書**。`svn`≈`git`という知識は消費者であるモデルが既に持っている
//!
//! # 判定・整形・並べ替えはここに書かない
//!
//! [`harness_policy::transition_listing`]が持つ。**段階⑦のポリシーエディタの画面も同じものを
//! 使う**ので、ここへ写すとモデルに見えるものとユーザーに見えるものがずれる。

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

use harness_core::{RiskClass, RunnableProgramFact, Tool, ToolCtx, ToolError, ToolOutput};
use harness_policy::transition_listing::{match_rank, Rank};

/// 1回に返す行数の既定。**モデルの文脈を焼き切らない値**にしておき、足りなければ
/// `offset`で続きを引かせる（一度に全部返すと、宣言が増えたときに1回の応答が破裂する）。
const DEFAULT_LIMIT: usize = 20;
/// 呼び出し側が`limit`で要求できる上限。
const MAX_LIMIT: usize = 100;

#[derive(Deserialize)]
struct CanRunProgramInput {
    /// 探したいプログラム名（部分一致）。省略すると一覧になる。
    #[serde(default)]
    program: Option<String>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    limit: Option<usize>,
}

/// このツールの名前。
///
/// **定数にしてあるのは、[段階6f-3]の拒否の注記が同じ名前を書くためである**
/// ——注記は「このツールを引け」とモデルへ言うので、綴りがずれると
/// **存在しないツールを指す案内**になる（`B-05`: 別々に持つ綴りはコンパイラが守らない）。
pub const CAN_RUN_PROGRAM_TOOL: &str = "can_run_program";

pub struct CanRunProgramTool;

#[async_trait]
impl Tool for CanRunProgramTool {
    fn name(&self) -> &str {
        CAN_RUN_PROGRAM_TOOL
    }

    fn description(&self) -> &str {
        "このシェルから起こせるプログラムを調べる（読み取りのみ）。プログラム名を渡すとその名前で\
         起こせるかどうかが分かり、省略すると起こせるものの一覧になる。プロセス生成が拒否されたとき、\
         または外部コマンドを使う計画を立てる前に引くこと。"
    }

    fn input_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "program": {
                    "type": "string",
                    "description": "調べたいプログラム名（`git`のような名前でも、フルパスの一部でもよい）。省略すると起こせるものを一覧する"
                },
                "offset": { "type": "integer", "description": "一覧の何件目から返すか（省略時0）" },
                "limit": { "type": "integer", "description": "一度に返す件数（省略時20、最大100）" }
            },
            "additionalProperties": false
        })
    }

    fn risk(&self, _input: &serde_json::Value) -> RiskClass {
        // 宣言を読むだけで、マシンの状態を1ビットも変えない。
        RiskClass::ReadOnly
    }

    async fn call(&self, input: serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let input: CanRunProgramInput =
            serde_json::from_value(input).map_err(|e| ToolError::InvalidInput(e.to_string()))?;

        // **黙って空を返さない**（`B-10`）。「起こせるものが無い」と「そもそも強制が
        // 効いていない」は別の事実で、混ぜるとモデルは存在しない制約に合わせて動く。
        let Some(facts) = ctx.transition_facts.as_deref() else {
            return Ok(ToolOutput {
                content: "この構成ではプロセス生成の制限は有効になっていません（宣言の有無に\
                          関わらず、シェルから起こせるプログラムは制限されていません）。"
                    .to_string(),
                is_error: false,
            });
        };

        let query = input.program.unwrap_or_default();
        let limit = input.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
        let offset = input.offset.unwrap_or(0);

        let matched = rank(&facts.programs, &query);
        Ok(ToolOutput {
            content: render(&matched, &query, offset, limit),
            is_error: false,
        })
    }
}

/// 問い合わせで絞り、近い順に並べる。**同じ近さの行は宣言順のまま**（安定ソート）。
///
/// 近さの規則は[`harness_policy::transition_listing::match_rank`]が唯一の実装で、
/// **ここには規則を書かない**——エディタの画面と並び順が食い違わないようにするため。
fn rank<'a>(programs: &'a [RunnableProgramFact], query: &str) -> Vec<&'a RunnableProgramFact> {
    let mut ranked: Vec<(Rank, &RunnableProgramFact)> = programs
        .iter()
        .filter_map(|program| {
            let row = harness_policy::transition_listing::Row {
                exe: program.exe.clone(),
                exe_is_pattern: program.exe_is_pattern,
                argv: program.argv.clone(),
                argv_is_pattern: program.argv_is_pattern,
                to_domain: program.to_domain.clone(),
                rights: Default::default(),
                runnable_now: program.runnable_now,
            };
            match_rank(query, &row).map(|rank| (rank, program))
        })
        .collect();
    ranked.sort_by_key(|(rank, _)| *rank);
    ranked.into_iter().map(|(_, program)| program).collect()
}

fn render(
    matched: &[&RunnableProgramFact],
    query: &str,
    offset: usize,
    limit: usize,
) -> String {
    if matched.is_empty() {
        return if query.trim().is_empty() {
            "このシェルから起こせると宣言されているプログラムはありません。".to_string()
        } else {
            format!(
                "`{query}`に一致するものはありません。引数なしで呼ぶと、起こせるものを一覧できます。"
            )
        };
    }

    let mut out = String::new();
    let page = matched.iter().skip(offset).take(limit);
    for program in page {
        out.push_str(&render_row(program));
        out.push('\n');
    }

    let shown = offset + limit.min(matched.len().saturating_sub(offset));
    if shown < matched.len() {
        // 既存のツールと同じ作法（`search.rs`）。**残りがあることを黙らせない。**
        out.push_str(&format!(
            "[output truncated] 全{}件のうち{}件目までを表示しました。続きは offset={} で引けます。\n",
            matched.len(),
            shown,
            shown
        ));
    }
    out
}

fn render_row(program: &RunnableProgramFact) -> String {
    let mut line = String::new();
    if program.exe_is_pattern {
        // **そのまま打てる名前ではない**ことを先に言う（パターンを実行ファイル名と誤読させない）。
        line.push_str(&format!("パターン {} に一致する実行ファイル", program.exe));
    } else {
        line.push_str(&program.exe);
    }
    if program.argv_is_pattern {
        line.push_str(&format!("（引数がパターン {} に一致するとき）", program.argv));
    } else if program.argv != harness_policy::transition_listing::ANY_ARGV {
        line.push_str(&format!("（引数が {} のときだけ）", program.argv));
    }

    if !program.runnable_now {
        // **暫定**（`plans/DESIGN-MAC-ENFORCEMENT.md` §10.1.2の撤去一覧5点目）。
        // 宣言は正しいがharness側が未実装なので、いま撃つと拒否される。
        // **これを黙ると、一覧に出したものが拒否されるという最も分かりにくい形になる。**
        line.push_str(
            " — **いまは起こせません**（宣言は有効ですが、別の権限の組へ移す機構がharness側に\
             まだありません）",
        );
        return line;
    }

    let rights = render_rights(program);
    if !rights.is_empty() {
        line.push_str(&format!(" — 起こした先で使えるもの: {rights}"));
    }
    line
}

/// 遷移先から**到達できる範囲**の権限（§19.3.4の到達閉包で計算済みの値を並べるだけ）。
fn render_rights(program: &RunnableProgramFact) -> String {
    let mut parts = Vec::new();
    if !program.rights_fs.is_empty() {
        let fs: Vec<String> = program
            .rights_fs
            .iter()
            .map(|(path, access)| format!("{path}({access})"))
            .collect();
        parts.push(format!("ファイル {}", fs.join("、")));
    }
    if !program.rights_net.is_empty() {
        parts.push(format!("通信先 {}", program.rights_net.join("、")));
    }
    parts.join(" / ")
}

#[cfg(test)]
#[path = "can_run_program_tests.rs"]
mod can_run_program_tests;
