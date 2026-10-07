//! 前の人の文と、その返事で呼んだツールを**読むだけ**の道具 `past_requests`（D-127 の3）。
//!
//! # 何のためにあるのか
//!
//! ユーザーが「さっきのをもう一度」と頼んだとき、モデルは前の文の値を指す必要がある。値は
//! `{{back:K:N}}`（K 個前の人の文の N 番目）で指せるが、**どの文が K 個前か・その文の何番に何が入っているか**は
//! システムプロンプトに並べていない（遠くまで遡ると一覧が伸び、選び間違える余地も増えるため）。
//! そこで、モデルが要るときに引く道具を置く。
//!
//! ```text
//! モデル: past_requests {}           → 人の文の一覧（K・冒頭・その返事で呼んだツールと結果の種類）
//! モデル: past_requests {"back": 1}  → 1つ前の文と、そのとき呼んだツール（値は番号に置き換え済み）
//! モデル: run_shell { command: "pwsh --enc {{back:1:1}}" }
//! ```
//!
//! # 値の中身は出さない
//!
//! 一覧にも詳細にも、長い値の中身は1文字も出さない（D-116「中身は渡さない」と同じ理由——渡せば書き写せてしまう）。
//! 置き場にある値はその番号の綴りへ（`{{val:N}}`／`{{back:K:N}}`）、置き場に無い値の形の連なり
//! （[`harness_core::user_reference::looks_like_payload`]）は`[N文字の値・番号なし]`へ置き換える（`mask`）。
//!
//! # 昔のツール呼び出しの番号は書き換えて返す
//!
//! 会話にはモデルが書いたまま（`{{val:1}}`）残っている（D-113）。その`{{val:1}}`は**当時の直近の文**＝K 個前の文の
//! 値を指していたので、そのまま見せると今の文の1番目に置き換わる。だから
//! [`harness_core::reference_syntax::rewrite_relative`]で`{{back:K:1}}`へ読み替えて**から**伏せる。
//! ツールの結果の冒頭も同じく読み替える——この道具自身の結果が会話に残り、後で読まれるため（D-127 の検問4）。
//!
//! # ここが守らないもの
//!
//! - **会話を読めない経路では使えない。** 会話が渡るのは置き場が本物の会話から組まれたときだけ
//!   （`crate::References::conversation`）で、認知レイヤーの経路では「使えない」と返す（D-127「認知レイヤーの経路は未決」）
//! - **畳まれた文は数えられない**（要約に置き換えられた文は会話から消えている。`harness_core::human_turns`）
//! - **伏せるのは40文字以上の値だけ。** 解読した段のうち40文字に満たないものは、ツールの入力・結果に現れても伏せない
//!   （短い文字列を全部置き換えると、無関係な文まで書き換わる）
//! - **いま実行中の返事の、この呼び出しは載らない。** 渡る会話はこの1ステップを始める前のもの
//! - Tier3 では、道具の出力は他の道具と同じく実行の後で伏字化される（`crate::turn`のディスパッチが全道具に掛ける）

use async_trait::async_trait;
use serde::Deserialize;

use harness_core::human_turns::{human_turns, PAST_REQUESTS_TOOL};
use harness_core::reference_syntax::{rewrite_relative, ValueRef};
use harness_core::user_reference::{looks_like_payload, MIN_REFERENCE_CHARS};
use harness_core::{
    parse_tool_input, ContentBlock, Message, PermissionSubject, RiskClass, Role, Tool, ToolCtx,
    ToolError, ToolOutput, ValueStore,
};

use crate::references::store_for_text;
use crate::RecordedOutcome;

/// 一覧に載せる人の文の数（新しい方から）。
const MAX_LISTED: usize = 20;
/// 一覧の各行に載せる文の冒頭（文字）。
const LIST_HEAD_CHARS: usize = 200;
/// 一覧の各行に載せるツール呼び出しの数（新しい方から）。
const MAX_CALLS_PER_LINE: usize = 8;
/// 詳細に載せる文の長さ（文字）。
const DETAIL_TEXT_CHARS: usize = 4_000;
/// 詳細に載せるツール呼び出しの数（新しい方から）。
const MAX_CALLS_IN_DETAIL: usize = 20;
/// 詳細に載せるツールの入力の長さ（文字）。
const INPUT_CHARS: usize = 600;
/// 詳細に載せるツールの結果の冒頭（文字）。
const RESULT_HEAD_CHARS: usize = 300;

/// 会話が渡らない経路（認知レイヤー）で返す文。**同じ呼び出しを繰り返させない**ために、繰り返しても変わらないと言う。
const UNAVAILABLE_WITHOUT_CONVERSATION: &str =
    "この経路（認知レイヤー）では past_requests はまだ使えません。ここには会話そのものが渡されないので、\
     ユーザーの前の文を数えられません。同じ呼び出しを繰り返しても結果は変わりません。\
     前の文の値が要るときは、ユーザーに値をもう一度貼ってもらってください。";

/// `past_requests`の入力。**知らない項目は拒否する**（BUG-164・D-101）。
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PastRequestsInput {
    /// 詳しく見る人の文が何個前か（0 がいまの文）。省くと一覧。
    #[serde(default)]
    back: Option<usize>,
}

/// 前の人の文と、その返事で呼んだツールを読む道具（[モジュールdoc](self)）。
pub struct PastRequestsTool;

#[async_trait]
impl Tool for PastRequestsTool {
    fn name(&self) -> &str {
        PAST_REQUESTS_TOOL
    }

    fn description(&self) -> &str {
        "ユーザーの前の文と、その返事で呼んだツールを読む（読むだけ。承認は要らない）。\
         ユーザーが前の文を指して頼んだとき（「さっきのをもう一度」「前に貼ったものを使って」等）に使う。\
         back を省くと、人の文を新しい順に最大20個（K・文の冒頭・その返事で呼んだツールと結果の種類）。\
         back に K を渡すと、その文・値の一覧・その返事で呼んだツールの入力と結果の冒頭。\
         K は何個前の文か（0 がいまの文、1 が1つ前）。長い値は中身を出さず番号だけで示す\
         （K=0 の文の値は {{val:N}}、それより前の文の値は {{back:K:N}}）。\
         コマンドの中ではその番号をそのまま書けば、ハーネスが中身へ置き換える。"
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "back": {
                    "type": "integer",
                    "description": "詳しく見る人の文が何個前か（0 がいまの文、1 が1つ前）。省くと一覧"
                }
            },
            "additionalProperties": false
        })
    }

    fn risk(&self, _input: &serde_json::Value) -> RiskClass {
        // 渡された会話を読んで文字列を返すだけで、マシンの状態も会話も変えない。
        RiskClass::ReadOnly
    }

    /// 判定の材料（D-101）は「一覧か、何個前の詳細か」。
    async fn permission_subject(
        &self,
        input: &serde_json::Value,
        _ctx: &ToolCtx,
    ) -> Result<PermissionSubject, ToolError> {
        let input: PastRequestsInput = parse_tool_input(input)?;
        Ok(PermissionSubject::Text(match input.back {
            None => PAST_REQUESTS_TOOL.to_string(),
            Some(k) => format!("{PAST_REQUESTS_TOOL} back:{k}"),
        }))
    }

    /// 会話を渡さない呼び方では読めない（エンジンは常に[`Tool::call_in_conversation`]で呼ぶ）。
    async fn call(
        &self,
        input: serde_json::Value,
        _ctx: &ToolCtx,
    ) -> Result<ToolOutput, ToolError> {
        let _: PastRequestsInput = parse_tool_input(&input)?;
        Err(ToolError::ExecutionFailed(format!(
            "{PAST_REQUESTS_TOOL} は会話を読む道具で、会話を渡す呼び出し（call_in_conversation）からしか使えません"
        )))
    }

    async fn call_in_conversation(
        &self,
        input: serde_json::Value,
        _ctx: &ToolCtx,
        conversation: Option<&[Message]>,
    ) -> Result<ToolOutput, ToolError> {
        let input: PastRequestsInput = parse_tool_input(&input)?;
        let Some(messages) = conversation else {
            return Ok(error(UNAVAILABLE_WITHOUT_CONVERSATION.to_string()));
        };
        let turns = collect_turns(messages);
        Ok(match input.back {
            None => ToolOutput {
                content: render_listing(&turns),
                is_error: false,
            },
            Some(k) if k < turns.len() => ToolOutput {
                content: render_detail(&turns, k),
                is_error: false,
            },
            Some(k) => error(out_of_range(k, turns.len())),
        })
    }
}

fn error(content: String) -> ToolOutput {
    ToolOutput {
        content,
        is_error: true,
    }
}

fn out_of_range(k: usize, count: usize) -> String {
    match count {
        0 => format!("K={k} の文はありません。人が書いた文がまだありません。"),
        n => format!(
            "K={k} の文はありません。指せるのは 0〜{}（人が書いた文は{n}個。0 がいまの文）です。",
            n - 1
        ),
    }
}

/// 人の文1つと、その返事で呼んだツール。
struct Turn<'a> {
    text: &'a str,
    /// この文の置き場（`{{val:N}}`・`{{back:K:N}}`が指すものと同じ組み方。`crate::references::store_for_text`）。
    store: ValueStore,
    calls: Vec<Call<'a>>,
}

/// その返事で呼んだツール1件。
struct Call<'a> {
    name: &'a str,
    input: &'a serde_json::Value,
    /// 結果の文と`is_error`。会話に結果が無ければ`None`。
    result: Option<(&'a str, bool)>,
}

/// 会話から人の文を**新しい順に**集める（`turns[k]`が K 個前の文）。
///
/// 「その返事」は、その人の文から次の人の文までの間にあるモデルの`ToolUse`である。ツールの結果を運ぶ文と
/// 畳んだ要約の文は人の文に数えない（`harness_core::human_turns`）。
fn collect_turns(messages: &[Message]) -> Vec<Turn<'_>> {
    let humans = human_turns(messages);
    let mut turns: Vec<Turn<'_>> = humans
        .iter()
        .enumerate()
        .map(|(i, human)| {
            let end = humans.get(i + 1).map_or(messages.len(), |next| next.index);
            Turn {
                text: human.text,
                store: store_for_text(human.text),
                calls: calls_in(&messages[human.index + 1..end]),
            }
        })
        .collect();
    turns.reverse();
    turns
}

fn calls_in(reply: &[Message]) -> Vec<Call<'_>> {
    let mut calls = Vec::new();
    for message in reply.iter().filter(|m| m.role == Role::Assistant) {
        for block in &message.content {
            if let ContentBlock::ToolUse { id, name, input } = block {
                calls.push(Call {
                    name,
                    input,
                    result: result_of(reply, id),
                });
            }
        }
    }
    calls
}

fn result_of<'a>(reply: &'a [Message], id: &str) -> Option<(&'a str, bool)> {
    reply.iter().flat_map(|m| &m.content).find_map(|b| match b {
        ContentBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
        } if tool_use_id == id => Some((content.as_str(), *is_error)),
        _ => None,
    })
}

/// 伏せるときに番号へ置き換える値の一覧（中身, 綴り）。**`k`個前の文の値を先に**、残りの文の値を新しい順に並べ、
/// 同じ中身は先のものだけ残す。置き換えは長いものから（短い値が長い値の一部だったときに、長い方を割らない）。
fn known_values(turns: &[Turn<'_>], k: usize) -> Vec<(String, String)> {
    let order = std::iter::once(k).chain((0..turns.len()).filter(|&j| j != k));
    let mut known: Vec<(String, String)> = Vec::new();
    for back in order {
        for (index, text) in turns[back].store.texts().into_iter().enumerate() {
            if text.chars().count() < MIN_REFERENCE_CHARS || known.iter().any(|(t, _)| *t == text) {
                continue;
            }
            let spelling = ValueRef {
                back,
                number: index + 1,
            }
            .spelling();
            known.push((text, spelling));
        }
    }
    known.sort_by_key(|(text, _)| std::cmp::Reverse(text.chars().count()));
    known
}

/// 長い値を伏せる（[モジュールdoc](self)）。置き場にある値はその番号の綴りへ、置き場に無い値の形の連なりは
/// `[N文字の値・番号なし]`へ。**切り詰める前に掛ける**——先に切ると、途中で切れた値が値の形に見えずに残る。
fn mask(text: &str, known: &[(String, String)]) -> String {
    let mut out = text.to_string();
    for (value, spelling) in known {
        if out.contains(value.as_str()) {
            out = out.replace(value.as_str(), spelling);
        }
    }
    mask_unnumbered(&out)
}

/// 値に使われる文字（base64 の文字。16進の文字はこれに含まれる）。
fn is_value_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')
}

/// 値に使われる文字の連なりを1つずつ見て、値の形（[`looks_like_payload`]）なら伏せる。
///
/// 空白で区切った語ではなく**連なり**で見るのは、ツールの入力の JSON（`"command":"echo <値>"}`）では値の前後に
/// 引用符が付き、語のままでは値の形に見えないため。
fn mask_unnumbered(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut run_start: Option<usize> = None;
    let flush = |out: &mut String, run: &str| {
        if looks_like_payload(run) {
            out.push_str(&format!("[{}文字の値・番号なし]", run.chars().count()));
        } else {
            out.push_str(run);
        }
    };
    for (at, c) in text.char_indices() {
        match (is_value_char(c), run_start) {
            (true, None) => run_start = Some(at),
            (true, Some(_)) => {}
            (false, start) => {
                if let Some(start) = start {
                    flush(&mut out, &text[start..at]);
                    run_start = None;
                }
                out.push(c);
            }
        }
    }
    if let Some(start) = run_start {
        flush(&mut out, &text[start..]);
    }
    out
}

/// 先頭`max_chars`文字。切ったら残りの文字数を添える。
fn head(text: &str, max_chars: usize) -> String {
    let total = text.chars().count();
    if total <= max_chars {
        return text.to_string();
    }
    let kept: String = text.chars().take(max_chars).collect();
    format!("{kept}…（あと{}文字）", total - max_chars)
}

/// 1行に収める（改行・タブを空白へ）。
fn one_line(text: &str) -> String {
    text.replace(['\r', '\n', '\t'], " ")
}

fn outcome_label(call: &Call<'_>) -> &'static str {
    match call.result {
        Some((content, is_error)) => RecordedOutcome::of(content, is_error).label_ja(),
        None => "結果が会話に無い",
    }
}

/// 引数なし: 人の文を新しい順に最大[`MAX_LISTED`]個。
fn render_listing(turns: &[Turn<'_>]) -> String {
    if turns.is_empty() {
        return "人が書いた文がまだありません。".to_string();
    }
    let mut out = format!(
        "人が書いた文（新しい順。全部で{}個のうち最大{MAX_LISTED}個。K は何個前か——0 がいまの文）:\n",
        turns.len()
    );
    for (k, turn) in turns.iter().enumerate().take(MAX_LISTED) {
        let text = head(
            &one_line(&mask(turn.text, &known_values(turns, k))),
            LIST_HEAD_CHARS,
        );
        let values = match turn.store.len() {
            0 => "値なし".to_string(),
            n => format!("指せる値{n}個"),
        };
        out.push_str(&format!("K={k}: 「{text}」 {values}"));
        if !turn.calls.is_empty() {
            let skipped = turn.calls.len().saturating_sub(MAX_CALLS_PER_LINE);
            let shown: Vec<String> = turn.calls[skipped..]
                .iter()
                .map(|c| format!("{}（{}）", c.name, outcome_label(c)))
                .collect();
            let more = match skipped {
                0 => String::new(),
                n => format!("ほか前に{n}件, "),
            };
            out.push_str(&format!(
                " / 返事で呼んだツール: {more}{}",
                shown.join(", ")
            ));
        }
        out.push('\n');
    }
    out.push_str(
        "詳しく見るには {\"back\": K} を渡してください。値は中身を出さず番号だけで示します——\
         いまの文（K=0）の値は {{val:N}}、それより前の文の値は {{back:K:N}} で、\
         コマンドの中にそのまま書けばハーネスが中身へ置き換えます。\n",
    );
    out
}

/// `back: K`: その文・値の一覧・その返事のツール呼び出し（入力と結果の冒頭）。
fn render_detail(turns: &[Turn<'_>], k: usize) -> String {
    let turn = &turns[k];
    let known = known_values(turns, k);
    let which = match k {
        0 => "いまの文".to_string(),
        k => format!("{k}つ前の文"),
    };
    let mut out = format!(
        "K={k}（{which}）:\n{}\n\n",
        head(&mask(turn.text, &known), DETAIL_TEXT_CHARS)
    );
    match turn.store.is_empty() {
        true => out.push_str("この文に長い値はありません。\n"),
        false => out.push_str(&format!(
            "この文の値（中身は出しません。コマンドの中ではこの番号で指してください）:\n{}",
            turn.store.entry_lines(k)
        )),
    }
    if turn.calls.is_empty() {
        out.push_str("\nこの文への返事ではツールを呼んでいません。\n");
        return out;
    }
    let skipped = turn.calls.len().saturating_sub(MAX_CALLS_IN_DETAIL);
    out.push_str(&format!(
        "\nこの文への返事で呼んだツール（{}件{}）:\n",
        turn.calls.len(),
        match skipped {
            0 => String::new(),
            n => format!("。古い{n}件は省略"),
        }
    ));
    for (i, call) in turn.calls.iter().enumerate().skip(skipped) {
        // 会話には当時の書き方（`{{val:1}}`＝当時の直近の文＝K 個前の文）で残っている。**今の綴りへ読み替えてから**
        // 伏せる——そのまま見せると、今の文の1番目を指してしまう（D-127 の3）。
        let input = mask(&rewrite_relative(&call.input.to_string(), k), &known);
        out.push_str(&format!(
            "{}. {} — {}\n   入力: {}\n",
            i + 1,
            call.name,
            outcome_label(call),
            head(&input, INPUT_CHARS)
        ));
        if let Some((content, _)) = call.result {
            let result = mask(&rewrite_relative(content, k), &known);
            out.push_str(&format!(
                "   結果の冒頭: {}\n",
                head(&one_line(&result), RESULT_HEAD_CHARS)
            ));
        }
    }
    out
}

#[cfg(test)]
#[path = "past_requests_tests.rs"]
mod tests;
