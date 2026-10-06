//! 1ステップ（`RawTurn`）= **1回のスコープ付きLLMコール + そのターンのツール実行**。
//! `plans/DESIGN-COGNITION.md` §1「`harness-engine` ← 「1回のスコープ付きLLMコール + ツール実行」」。
//!
//! [`crate::run_agent_loop`]（素朴ループ）はこのプリミティブを`ToolUse`が出なくなるまで
//! 繰り返すだけの薄い層になり、認知レイヤー（`harness-cognition`、M14以降）は
//! `ConversationState`の代わりに自前の作業記憶から組んだ最小コンテキストを渡して
//! **1ステップだけ**回す。どちらも入口はこの[`TurnExecutor`]1つ。
//!
//! | ファイル | 責務 |
//! |---|---|
//! | 本ファイル | 型・[`Executor`]・回復の梯子のドライバ・ツール実行 |
//! | [`stream`] | 1回のストリーム受信・ブロック組み立て・縮退検知器への供給 |
//! | [`references`] | ツール呼び出し1件の入力への、書き写しの審査と値の差し込み |
//! | [`outcome`] | 会話に残ったツールの結果の顛末の見分け（結果の文の頭の綴りはここにだけ置く） |
//!
//! # なぜツール実行までこの中に置くか
//!
//! ツール実行を呼び出し側へ出すと、認知レイヤーが`PermissionGate`を通さずに
//! `Tool::call`を直接叩く経路が作れてしまう。ここに閉じ込めることで、
//! 「パーミッションの強制点は1箇所」（`plans/DESIGN.md` §パーミッション、
//! `docs/SECURITY-PRINCIPLES.md`）が**構造的に**保たれる —— 認知層は
//! [`Executor`]越しにしかツールへ触れられず、迂回路が型として存在しない。
//!
//! # 責務の境界（呼び出し側に残すもの）
//!
//! ここは**会話履歴を持たない**。`ConversationState`への追記・ターン予算・
//! コンテキスト圧縮・ターン境界のイベント（`TurnStarted`/`TurnCompleted`/`Cancelled`/`Error`）は
//! すべて呼び出し側の責務。ここが発行するのは1ステップ内部の
//! `TextDelta`/`ThinkingDelta`/`ToolCallProposed`/`ToolStarted`/`ToolFinished`と、
//! 縮退で捨てた回の`TurnDiscarded`だけ。

mod outcome;
mod references;
mod stream;
mod text_tool_call;

pub use outcome::{
    RecordedOutcome, CANCELLED_BEFORE_START, DENIAL_PREFIX, INVALID_TOOL_INPUT_PREFIX,
};

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use harness_core::{
    discarded_marker, AgentEvent, CompletionRequest, ContentBlock, DegenerateKind, LlmProvider,
    ProviderError, StopReason, ToolCtx, ToolOutput, Usage, CANCELLED_REASON,
};
use harness_tools::ToolRegistry;

use crate::degeneracy::{ladder, CallWatch, DegeneracyDetector, Degenerate};
use crate::permission::PermissionGate;
use crate::{emit, sanitize, EventSink};
use harness_core::text::truncate_head_tail;
use stream::{Attempt, MalformedToolInput};

/// ツール出力がこれを超える文字数なら頭尾切詰めする（M9、DESIGN.md L349「大出力 head+tail
/// 切詰め」）。会話履歴に積む前に適用するため、モデルへ送るコンテキスト自体を圧迫しない。
const MAX_TOOL_OUTPUT_CHARS: usize = 8_000;

/// このターンのassistantテキストが**ユーザ向けの応答**なのか、**認知レイヤー内部の機構**なのか。
///
/// 認知レイヤーの各フェーズ（`plans/DESIGN-COGNITION.md` §3.3）はスキーマ強制された
/// JSONを返させる解釈コールで、その中身はユーザへ見せる文章ではない。`Internal`のターンで
/// `TextDelta`/`ThinkingDelta`を流すと、TUIのトランスクリプトとヘッドレスのtext出力へ
/// 生JSONが垂れ流される。**どのターンの本文が最終回答かを知っているのは認知層だけ**なので、
/// 判断をここで受け取り、発行するかどうかをこの1箇所で決める。
///
/// ツール関連イベント（`ToolCallProposed`/`ToolStarted`/`ToolFinished`）は`Internal`でも
/// 発行する——実際にワークスペースを触る操作はフェーズの内外を問わずユーザに見えるべきで、
/// TUIの承認モーダル・ヘッドレスJSONの`tool_calls`集計もこれを前提にしている。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TurnVisibility {
    /// 本文をそのままユーザへ見せる（素朴ループの全ターン）。
    #[default]
    UserFacing,
    /// 本文は認知レイヤーが解釈する構造化出力。デルタを一切流さない。
    Internal,
}

/// 1ステップの入力。認知レイヤー（M14以降）は`ContextAssembler`が組んだ最小コンテキストを、
/// 素朴ループは`ConversationState`全体を、それぞれここへ載せる。
///
/// `plans/DESIGN-COGNITION.md` §1のスケッチにある`allowed: ToolGate`（フェーズ毎の許可ツール
/// 制限、§7.3）は`ContextAssembler`が渡すツールspecを絞ることで実現しており（M14）、
/// ここには持たない。`budget: TokenBudget`（§6）も同様に`max_tokens`と組立側の縮約へ
/// 落ちているため、常に全許可の値を運ぶだけのフィールドは置いていない。
pub struct RawTurnRequest {
    pub req: CompletionRequest,
    pub visibility: TurnVisibility,
    /// 値の置き場（`{{val:N}}`・`{{back:K:N}}`が指すもの。D-127）。**`None`なら`req.messages`から組む**
    /// （素朴ループ。送る文がそのまま会話なので、それで正しい）。
    ///
    /// 送る文が会話そのものでない呼び出し側（認知レイヤーは1つの文に組み直して送る）は、会話から組んだ
    /// 置き場を[`RawTurnRequest::with_references`]で渡す——送る文から組むと、ツールの出力に出てきた値まで
    /// 番号を取ってしまう（BUG-235）。`Arc`なのは、同じ発話の中の何回ものコールで使い回すため。
    pub references: Option<std::sync::Arc<crate::References>>,
    /// `req.messages`が**会話そのもの**か。決めるのは作る関数（[`RawTurnRequest::user_facing`]は`true`、
    /// [`RawTurnRequest::internal`]は`false`）だけで、外からは書けない。
    ///
    /// `references`が`None`のとき、これが`true`なら置き場を会話として組み（[`crate::References::from_conversation`]）、
    /// 会話を読む道具（`Tool::call_in_conversation`）へ会話を渡す。`false`なら送る文から組むだけで、道具には
    /// 会話を渡さない——組み直した文を会話として読ませると、ツールの出力の中の文まで「人の文」に見える
    /// （D-127「認知レイヤーの経路は未決」）。
    request_is_conversation: bool,
}

impl RawTurnRequest {
    /// 素朴ループのターン（本文をユーザへ流す）。
    pub fn user_facing(req: CompletionRequest) -> Self {
        Self {
            req,
            visibility: TurnVisibility::UserFacing,
            references: None,
            // 素朴ループは`ConversationState`をそのまま写して送る（`crate::build_request`）。
            request_is_conversation: true,
        }
    }

    /// 認知レイヤーのフェーズコール（本文は構造化出力なので流さない）。
    pub fn internal(req: CompletionRequest) -> Self {
        Self {
            req,
            visibility: TurnVisibility::Internal,
            references: None,
            // 認知レイヤーは作業記憶から1つの文に組み直して送る。会話ではない。
            request_is_conversation: false,
        }
    }

    /// 値の置き場を、送る文からではなく呼び出し側が組んだもので渡す（[`RawTurnRequest::references`]）。
    /// 道具へ会話を渡すかは、渡した置き場が会話から組まれたか（[`crate::References::conversation`]）で決まる。
    pub fn with_references(mut self, references: std::sync::Arc<crate::References>) -> Self {
        self.references = Some(references);
        self
    }
}

/// 「対話なら聞いていた」拒否に足す一言（[`harness_engine::Decision::DenyWouldPrompt`]）。
///
/// **直し方が違うものを同じ文言で返さない。** モードや設定注入パスによる拒否は設定を変えるしか
/// 無いが、こちらは規則を1本書けば通る——どちらなのかが分からないと、モデルも人も次の手を選べない。
pub const WOULD_HAVE_PROMPTED_HINT: &str =
    " — no rule matched this call, so an interactive session would have asked. Headless runs deny \
     instead of asking. Pass --allow with an exact rule for this call, or run interactively.";

/// そのツール呼び出しが**実際に実行されたか**、されなかったなら何故か。
///
/// `Executed`以外はいずれも「`Tool::call`を呼んでいない」ことを意味し、`output`には
/// モデルへ差し戻す説明文が入る（モデルに自己修正させるため、ターン自体は落とさない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolCallDecision {
    Executed,
    /// `PermissionGate`が拒否した。
    DeniedByPolicy,
    /// `ToolRegistry`に無い名前だった。
    UnknownTool,
    /// 引数JSONの連結結果がパースできなかった。
    MalformedInput,
    /// JSONとしては読めたが、ツールの入力として読めなかった（知らない項目・型の違い等）。
    /// 判定の材料が作れないので、**判定にも実行にも進んでいない**（D-101）。
    InvalidInput,
    /// 先行するツールの実行中にキャンセルされ、この呼び出しには手を付けていない。
    CancelledBeforeStart,
    /// ユーザーの文の長い値を**損じたまま書き写していた**（D-115）。判定にも実行にも進んでいない
    /// ——壊れた写しは別のものを実行する命令なので、承認を聞く前に断る。
    TranscribedValue,
}

/// 1件のツール呼び出しと、その顛末。`output`は**履歴へ積むそのもの**
/// （Tier3伏字化・頭尾切詰め適用済み）。
#[derive(Debug, Clone)]
pub struct CompletedToolCall {
    pub id: String,
    pub name: String,
    pub input: serde_json::Value,
    pub output: ToolOutput,
    pub decision: ToolCallDecision,
    /// 判定器が見た材料（D-101）。実行まで進まなかった呼び出しは`None`。
    ///
    /// **入力のキーを探す代わりに、これを見る。** 「入力に`command`があればそれ」という選び方は、
    /// 入力を作るモデルに材料を選ばせる形であり、BUG-164 そのものである。認知層の出典
    /// （`harness_cognition::hiv::evidence`）が最後の利用者だった。
    pub subject: Option<harness_core::PermissionSubject>,
}

impl CompletedToolCall {
    /// 会話履歴へ積む`tool_result`ブロックへ変換する。`tool_use`との1対1対応を保つのは
    /// 呼び出し側の責務（`plans/DESIGN.md` §エージェントループ「続行で400にならない」）。
    pub fn to_tool_result(&self) -> ContentBlock {
        ContentBlock::ToolResult {
            tool_use_id: self.id.clone(),
            content: self.output.content.clone(),
            is_error: self.output.is_error,
        }
    }
}

/// 完走した1ステップの結果。
#[derive(Debug, Clone)]
pub struct RawTurn {
    /// assistantメッセージの中身（Tier3伏字化済み）。
    pub content: Vec<ContentBlock>,
    /// `content`中の`Text`ブロックの連結。
    pub text: String,
    /// `content`中の`ToolUse`ブロックと1対1で対応する（順序も同じ）。
    pub tool_calls: Vec<CompletedToolCall>,
    pub stop_reason: StopReason,
    pub usage: Usage,
    /// ツール実行の途中でキャンセルされた。`tool_calls`自体は`tool_use`と対応が取れた
    /// 状態で埋まっているので、呼び出し側は**通常どおり履歴へ積んでから**終了すること。
    pub cancelled_mid_tool: bool,
}

/// 1ステップの結果。「部分的にしか届かなかった応答は会話履歴を一切触ってはならない」という
/// 整合性の不変条件（`plans/DESIGN.md` §エージェントループ「ストリーム途中は部分assistant破棄」・
/// `plans/DESIGN-COGNITION.md` §11.4）を、見落とし得るフラグではなく**型**で強制する。
///
/// 破棄の理由は2つあり（キャンセルと縮退）、後始末は同一（部分assistantを一切積まない）だが
/// 呼び出し側の畳み方が違うため、別バリアントにしてある。
#[derive(Debug, Clone)]
pub enum RawTurnResult {
    Completed(RawTurn),
    /// 部分的に蓄積していたassistantブロックは破棄済み。呼び出し側は履歴へ何も積まない。
    CancelledMidStream,
    /// 回復の梯子（`plans/DESIGN-COGNITION.md` §11.3）を使い切ってなお縮退した。
    /// 部分assistantは破棄済みで、**ツールは1つも実行されていない**。
    /// 呼び出し側は履歴へ何も積まない。
    Discarded {
        kind: DegenerateKind,
    },
}

/// 1ステップの失敗。**ストリーム開始前**（プロバイダ呼び出し自体の失敗）と**開始後**
/// （受信中の失敗）を区別する。`run_agent_loop`のコンテキスト圧縮リトライは前者にだけ
/// 効く仕様で、これまでこの非対称性はコードの配置に暗黙的に埋まっていた。
#[derive(Debug)]
pub enum EngineError {
    Call(ProviderError),
    Stream(ProviderError),
}

impl EngineError {
    pub fn into_provider_error(self) -> ProviderError {
        match self {
            EngineError::Call(e) | EngineError::Stream(e) => e,
        }
    }
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Call(e) | EngineError::Stream(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for EngineError {}

/// 認知レイヤーがLLM／ツールへ触れる唯一の口（`plans/DESIGN-COGNITION.md` §1
/// 「認知層は provider を知らず、RawTurn 経由でのみ LLM/ツールに触れる」）。
#[async_trait]
pub trait Executor: Send + Sync {
    async fn raw_turn(&self, r: RawTurnRequest) -> Result<RawTurnResult, EngineError>;
}

/// [`Executor`]の実装。1ステップに必要な参照だけを束ねた、状態を持たない実行器。
///
/// 縮退ガードの移動統計はセッション全体を寿命とするため、`degeneracy`だけは
/// 呼び出し側が所有する[`DegeneracyDetector`]を借りる形にしてある（中身は`Arc`）。
/// `None`ならガードは完全に無効で、M21以前と同じ経路になる。
/// 損じた写しの拒否をこの回数まで続けたら、次の呼び出しはカウンタを0に戻して素通りさせる。
///
/// **用途**: モデルが番号参照（`{{val:N}}`）で書き直せない形で写し間違いを繰り返す経路の無限ループ対策。
/// 典型例はファイル編集ツールの`old_string`——ファイルの中身から切り出した語がユーザー文の長い値と
/// 似ているとき、番号参照を使っても別の文字列になるのでモデルは少し変えた写しで撃ち直し続ける。
///
/// **下流の防御がある前提で選んだ値**: 3回で素通りに倒す。本当に別物が走る写しなら、コマンドの構文失敗・
/// 承認画面・ファイル照合失敗のいずれかが受ける。レビューで値を上げたくなった場合は`turn/mod.rs`の
/// 試験の`refused_streak_bypasses_after_threshold`も合わせて更新する。
pub const TRANSCRIPTION_REFUSAL_BYPASS_THRESHOLD: u32 = 3;

pub struct TurnExecutor<'a> {
    provider: &'a dyn LlmProvider,
    tools: &'a ToolRegistry,
    ctx: &'a ToolCtx,
    gate: &'a dyn PermissionGate,
    events: Option<&'a EventSink>,
    cancel: Option<&'a CancellationToken>,
    degeneracy: Option<&'a DegeneracyDetector>,
    /// 損じた写しを拒否した連続回数。`TRANSCRIPTION_REFUSAL_BYPASS_THRESHOLD`に達したら
    /// 次を素通りさせてカウンタを0に戻す。`Executed`な決定が1つでも通ったら0に戻す。
    ///
    /// **ターンまたぎでは引き継がない**（`TurnExecutor`はターンごとに作り直されるため、新しいターンは
    /// 0から始まる）。無限ループは1ターン内で起きる現象なので、これで足りる。
    ///
    /// `Executor` trait が`Sync`を要求するので`AtomicU32`で持つ（`Cell`は`Sync`でない）。
    transcription_refusal_streak: std::sync::atomic::AtomicU32,
}

impl<'a> TurnExecutor<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: &'a dyn LlmProvider,
        tools: &'a ToolRegistry,
        ctx: &'a ToolCtx,
        gate: &'a dyn PermissionGate,
        events: Option<&'a EventSink>,
        cancel: Option<&'a CancellationToken>,
        degeneracy: Option<&'a DegeneracyDetector>,
    ) -> Self {
        Self {
            provider,
            tools,
            ctx,
            gate,
            events,
            cancel,
            degeneracy,
            transcription_refusal_streak: std::sync::atomic::AtomicU32::new(0),
        }
    }

    fn is_tier3(&self) -> bool {
        self.ctx.shell_tier.tier == harness_core::ShellTier::Tier3
    }

    /// [`Executor::raw_turn`]の本体。`on_text_delta`はヘッドレスのtext出力
    /// （`harness-cli`が`&mut W`をキャプチャする＝`Send`でないクロージャ）専用の経路で、
    /// trait側は`&dyn Executor`にするためジェネリクスを持てない。そのため
    /// **inherentメソッドを本体、trait実装をno-op委譲**の2段構えにしている。
    /// 認知レイヤーは`AgentEvent`を消費するのでこのコールバックを必要としない。
    ///
    /// # 回復の梯子
    ///
    /// 縮退を検知したらここでリクエストを作り直して再送する（§11.3）。**外へ
    /// [`RawTurnResult::Discarded`]を返すのは梯子を使い切ったときだけ**。梯子の各段は
    /// 毎回**元のリクエストから**組み直す（前段の書き換えを積み重ねない）。
    /// `TurnExecutor`は会話履歴を持たないので、触るのは`req`のコピーだけで履歴は汚れない。
    pub async fn raw_turn_with_deltas<F>(
        &self,
        request: RawTurnRequest,
        on_text_delta: &mut F,
    ) -> Result<RawTurnResult, EngineError>
    where
        F: FnMut(&str),
    {
        let RawTurnRequest {
            req: mut base_req,
            visibility,
            references,
            request_is_conversation,
        } = request;
        let visible = visibility == TurnVisibility::UserFacing;
        // 呼び出し側が伏字化済みのリクエストを渡してくる経路（`run_agent_loop`）もあるが、
        // ここを choke point にするため無条件に適用する（[`crate::sanitize`]は冪等）。
        if self.is_tier3() {
            sanitize::completion_request(&mut base_req);
        }

        // ハーネスが持っている値（モデルに書き写させず、番号で指させる。`harness_core::value_store`）。
        // **この回の会話の文から1回だけ組む**——ツール呼び出しごとに数え直すと、途中で番号の意味が変わる。
        // 組み立ては`References::from_messages`の1か所だけを通す。ここと`build_request`（モデルへ一覧を
        // 見せる段）が同じ関数を同じ`messages`で呼ぶので、**モデルが見た番号と差し込まれる値が食い違わない**。
        // 呼び出し側が組んだ置き場を渡したなら、そちらを使う（`RawTurnRequest::references`）。
        // 送る文が会話そのものなら、会話として組む——会話を読む道具へ渡るのはこの場合と、呼び出し側が
        // 会話から組んで渡した場合だけである（`Tool::call_in_conversation`）。
        let references = references.unwrap_or_else(|| {
            std::sync::Arc::new(match request_is_conversation {
                true => crate::References::from_conversation(&base_req.messages),
                false => crate::References::from_messages(&base_req.messages),
            })
        });

        let mut ladder: Option<ladder::Ladder> = None;
        // 現在の段。`None`は「素の1回目」（梯子はまだ登っていない）。
        let mut rung: Option<ladder::Rung> = None;
        let mut retries = 0u32;
        // BUG-079: 本文へツール呼び出しを書いたので通知付きで再送する、という状態。
        // **1ターンにつき1回だけ**——2回目も同じなら、それは説明としてそう書いているのだと見て
        // 本文をそのまま受け入れる（誤検出で答えを失わないため）。
        let mut text_tool_call_retried = false;

        loop {
            let mut req = base_req.clone();
            if let Some(r) = rung {
                ladder::apply(&mut req, r, retries);
            }
            if text_tool_call_retried {
                ladder::append_notice(&mut req, text_tool_call::NOTICE);
            }
            if (rung.is_some() || text_tool_call_retried) && self.is_tier3() {
                sanitize::completion_request(&mut req);
            }

            let mut watch = self.degeneracy.map(|d| d.watch(&req.model, req.max_tokens));
            let stream::StreamOutcome {
                attempt,
                emitted_bytes,
            } = self
                .stream_once(&req, on_text_delta, watch.as_mut(), visible)
                .await?;

            match attempt {
                Attempt::Cancelled => {
                    // キャンセルも意味論は「直前の部分assistantは捨てられた」なので、
                    // 縮退と同じ区切りマーカーを出す（§11.4「既存の同型の穴も同時に塞ぐ」）。
                    self.emit_marker(on_text_delta, CANCELLED_REASON, emitted_bytes, visible);
                    return Ok(RawTurnResult::CancelledMidStream);
                }
                Attempt::Completed {
                    content,
                    malformed,
                    stop_reason,
                    usage,
                } => {
                    // BUG-079: ツール呼び出しが本文テキストとして出ていたら、この試行は捨てて
                    // 通知付きで1回だけ再送する。**本文からツール名も引数も取らない**——
                    // ここで使うのは「やり直させるか」の真偽値だけ（`text_tool_call`のdoc）。
                    if let Some(marker) = text_tool_call::detect(&content) {
                        let retrying = !text_tool_call_retried;
                        self.report_text_tool_call(
                            on_text_delta,
                            marker,
                            emitted_bytes,
                            retrying,
                            visible,
                            &req,
                        );
                        if retrying {
                            // 捨てた試行は母集団へ入れない（使えなかったコールなので）。
                            // `TurnExecutor`は会話履歴を持たないため、履歴は汚れていない。
                            text_tool_call_retried = true;
                            continue;
                        }
                    }
                    // 縮退しなかったコールだけが母集団へ入る（§11.2の自己敗北的フィードバック回避）。
                    if let Some(w) = watch {
                        w.record_clean();
                    }
                    return self
                        .complete(content, malformed, stop_reason, usage, &references)
                        .await
                        .map(RawTurnResult::Completed);
                }
                Attempt::Degenerate(hit) => {
                    let Some(w) = watch.as_ref() else {
                        // 検知器が無ければ`Degenerate`は返らない（到達しない）。
                        unreachable!("degeneracy detected without a detector");
                    };
                    let next = self.advance_ladder(&mut ladder, w, &base_req.model).await;
                    self.report_discard(on_text_delta, &hit, emitted_bytes, next, visible, &req);
                    if next == ladder::Rung::Exhausted {
                        return Ok(RawTurnResult::Discarded { kind: hit.kind });
                    }
                    rung = Some(next);
                    retries += 1;
                }
            }
        }
    }

    /// 梯子を1段進める。(d) 段が選ばれたらここで実際にモデルを再ロードし、
    /// **失敗したら段を`Exhausted`へ落とす**（対応しないプロバイダはその段を飛ばす、§11.5）。
    async fn advance_ladder(
        &self,
        ladder: &mut Option<ladder::Ladder>,
        watch: &CallWatch<'_>,
        model: &str,
    ) -> ladder::Rung {
        let l = ladder.get_or_insert_with(|| {
            ladder::Ladder::new(watch.recovery_budget(), watch.recycle_enabled())
        });
        let mut next = l.advance(watch.elapsed());
        if next == ladder::Rung::Recycle && !matches!(self.provider.recycle(model).await, Ok(true))
        {
            next = ladder::Rung::Exhausted;
        }
        next
    }

    /// 破棄をイベント・text区切りマーカー・wire logの3経路へ出す。
    ///
    /// イベントとマーカーの両方を無条件に出してよいのは、実際に届くのが常に片方だけだから——
    /// TUI・headless json/jsonl では`on_text_delta`がno-opクロージャ、headless text では
    /// `events`が`None`になる。
    #[allow(clippy::too_many_arguments)]
    fn report_discard<F>(
        &self,
        on_text_delta: &mut F,
        hit: &Degenerate,
        emitted_bytes: u64,
        next: ladder::Rung,
        visible: bool,
        req: &CompletionRequest,
    ) where
        F: FnMut(&str),
    {
        // 捨てた本文と発火理由を残す（§11.6「捨てた本文の保全」）。誤検知だったのかを事後に
        // 確かめられるようにするためで、新しい保存経路は作らず既存のwire logを再利用する。
        harness_core::wire_log::record(|| {
            serde_json::json!({
                "kind": "turn_discarded",
                "degenerate_kind": hit.kind.as_str(),
                "reason": hit.reason,
                "next_rung": next.as_str(),
                "model": req.model,
                "max_tokens": req.max_tokens,
                "discarded_bytes": emitted_bytes,
            })
        });
        emit(
            self.events,
            AgentEvent::TurnDiscarded {
                kind: hit.kind,
                reason: hit.reason.clone(),
                discarded_bytes: emitted_bytes,
                next_rung: (next != ladder::Rung::Exhausted).then(|| next.as_str().to_string()),
            },
        );
        self.emit_marker(on_text_delta, hit.kind.as_str(), emitted_bytes, visible);
    }

    /// 本文へ書かれたツール呼び出しを、イベント・text区切りマーカー・wire logの3経路へ出す
    /// （[`TurnExecutor::report_discard`]と同じ理由で3つとも無条件に出す）。
    ///
    /// `retrying`が`false`なら**本文は捨てない**ので区切りマーカーも出さない——下流に
    /// 切り詰めさせると、そのまま答えとして採用するテキストが消える。
    fn report_text_tool_call<F>(
        &self,
        on_text_delta: &mut F,
        marker: &str,
        emitted_bytes: u64,
        retrying: bool,
        visible: bool,
        req: &CompletionRequest,
    ) where
        F: FnMut(&str),
    {
        harness_core::wire_log::record(|| {
            serde_json::json!({
                "kind": "tool_call_written_as_text",
                "marker": marker,
                "retrying": retrying,
                "model": req.model,
                "discarded_bytes": emitted_bytes,
            })
        });
        emit(
            self.events,
            AgentEvent::ToolCallWrittenAsText {
                marker: marker.to_string(),
                discarded_bytes: emitted_bytes,
                retrying,
            },
        );
        if retrying {
            self.emit_marker(
                on_text_delta,
                "tool_call_written_as_text",
                emitted_bytes,
                visible,
            );
        }
    }

    /// text形式の区切りマーカーを流す。**`Internal`のターンでは出さない**——そもそも本文を
    /// 1バイトも流していないので、下流に切り詰める対象が無い（出すとかえって偽の区切りになる）。
    fn emit_marker<F>(&self, on_text_delta: &mut F, reason: &str, bytes: u64, visible: bool)
    where
        F: FnMut(&str),
    {
        if visible {
            on_text_delta(&discarded_marker(reason, bytes));
        }
    }

    /// 完走したストリームを`RawTurn`へ仕上げる（伏字化 → 本文の連結 → ツール実行）。
    async fn complete(
        &self,
        mut content: Vec<ContentBlock>,
        malformed: std::collections::HashMap<String, MalformedToolInput>,
        stop_reason: StopReason,
        usage: Usage,
        references: &crate::References,
    ) -> Result<RawTurn, EngineError> {
        if self.is_tier3() {
            sanitize::content_blocks(&mut content);
        }

        let text = content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("");

        let (tool_calls, cancelled_mid_tool) = self
            .execute_tool_calls(&content, &malformed, references)
            .await;

        Ok(RawTurn {
            content,
            text,
            tool_calls,
            stop_reason,
            usage,
            cancelled_mid_tool,
        })
    }

    /// `content`中の`ToolUse`を順に処理する。戻り値の`Vec`は`ToolUse`ブロックと1対1で対応する
    /// （拒否・未知ツール・引数不正・キャンセルでも必ず1件返す＝`tool_result`の欠落を防ぐ）。
    async fn execute_tool_calls(
        &self,
        content: &[ContentBlock],
        malformed: &std::collections::HashMap<String, MalformedToolInput>,
        references: &crate::References,
    ) -> (Vec<CompletedToolCall>, bool) {
        let mut tool_calls = Vec::new();
        let mut cancelled_mid_tool = false;

        for block in content {
            let ContentBlock::ToolUse { id, name, input } = block else {
                continue;
            };
            if !cancelled_mid_tool && self.cancel.is_some_and(|c| c.is_cancelled()) {
                cancelled_mid_tool = true;
            }
            if cancelled_mid_tool {
                // 残り全てへcancelledな結果を合成する（実際にツールは呼ばない）。
                // ここでは`AgentEvent`を一切発行しない —— 実行されていない呼び出しが
                // フロントエンドの集計へ混じらないようにするため。
                tool_calls.push(CompletedToolCall {
                    id: id.clone(),
                    name: name.clone(),
                    input: input.clone(),
                    output: ToolOutput {
                        content: CANCELLED_BEFORE_START.to_string(),
                        is_error: true,
                    },
                    decision: ToolCallDecision::CancelledBeforeStart,
                    subject: None,
                });
                continue;
            }

            // 書き写しの審査 → 断るか素通りか → 差し込み（D-113・D-115。`references`モジュール）。
            let input = match self.screen_references(id, name, input, references) {
                references::Screened::Refused(call) => {
                    tool_calls.push(*call);
                    continue;
                }
                references::Screened::Proceed(input) => input,
            };
            let input = &input;

            emit(
                self.events,
                AgentEvent::ToolCallProposed {
                    id: id.clone(),
                    name: name.clone(),
                    input: input.clone(),
                },
            );

            let (output, decision, subject) = self
                .dispatch_one(id, name, input, malformed, references.conversation())
                .await;

            // ツールが実際に走ったら、拒否連続カウンタを0に戻す（別のユーザー値の写しが来たときに
            // 直前の無関係な拒否が引き継がれないようにする）。
            if decision == ToolCallDecision::Executed {
                self.transcription_refusal_streak
                    .store(0, std::sync::atomic::Ordering::Relaxed);
            }

            let mut output = output;
            if self.is_tier3() {
                sanitize::tool_output(&mut output);
            }
            let output = ToolOutput {
                content: truncate_head_tail(&output.content, MAX_TOOL_OUTPUT_CHARS),
                is_error: output.is_error,
            };
            emit(
                self.events,
                AgentEvent::ToolFinished {
                    id: id.clone(),
                    output: output.clone(),
                },
            );
            tool_calls.push(CompletedToolCall {
                id: id.clone(),
                name: name.clone(),
                input: input.clone(),
                output,
                decision,
                subject,
            });
        }

        (tool_calls, cancelled_mid_tool)
    }

    /// 1件のツール呼び出しをディスパッチする。**`PermissionGate`を通す唯一の場所**。
    ///
    /// `conversation`は判定を通った後で道具へ渡すだけ（`Tool::call_in_conversation`）。判定には使わない。
    async fn dispatch_one(
        &self,
        id: &str,
        name: &str,
        input: &serde_json::Value,
        malformed: &std::collections::HashMap<String, MalformedToolInput>,
        conversation: Option<&[harness_core::Message]>,
    ) -> (
        ToolOutput,
        ToolCallDecision,
        Option<harness_core::PermissionSubject>,
    ) {
        if let Some(m) = malformed.get(id) {
            // 引数JSONが壊れていた`tool_use`。ツールは呼ばず、モデルへ差し戻して自己修正させる
            // （`unknown tool`と同じ「エラーの説明を`tool_result`として返す」パターン）。
            return (
                ToolOutput {
                    content: format!(
                        "malformed tool_use input for {name}: arguments did not parse as JSON \
                         (raw: {})",
                        truncate_head_tail(&m.raw, 500)
                    ),
                    is_error: true,
                },
                ToolCallDecision::MalformedInput,
                None,
            );
        }

        let Some(tool) = self.tools.get(name) else {
            return (
                ToolOutput {
                    content: format!("unknown tool: {name}"),
                    is_error: true,
                },
                ToolCallDecision::UnknownTool,
                None,
            );
        };

        let risk = tool.risk(input);
        // 判定の材料はツールが自分の型で解釈して返す（D-101）。判定器は入力を見ない——入力のキーで
        // 材料を選ぶと、入力を作るモデルが判定の材料を選べる（BUG-164）。材料を作れない入力は、
        // 判定にも実行にも進めずにモデルへ差し戻す（`call`も同じ型で読むので、どのみち失敗する）。
        let subject = match tool.permission_subject(input, self.ctx).await {
            Ok(subject) => subject,
            Err(e) => {
                return (
                    ToolOutput {
                        content: format!("{INVALID_TOOL_INPUT_PREFIX} for {name}: {e}"),
                        is_error: true,
                    },
                    ToolCallDecision::InvalidInput,
                    None,
                );
            }
        };
        let verdict = self.gate.resolve(name, risk, &subject, input).await;
        if !verdict.is_allow() {
            // 「聞くはずだった」拒否には直し方を足す。**接頭辞は変えない**——ヘッドレスのJSONは
            // この接頭辞で`"denied"`を決めており、文言の先頭を変えると分類が壊れる。
            let hint = match verdict.would_have_prompted() {
                true => WOULD_HAVE_PROMPTED_HINT,
                false => "",
            };
            return (
                ToolOutput {
                    content: format!("{DENIAL_PREFIX}: {name} ({risk:?}){hint}"),
                    is_error: true,
                },
                ToolCallDecision::DeniedByPolicy,
                None,
            );
        }
        // D-106: ファイルの中身や名前の解決先に依存する材料は、**承認の直後に計算し直して比べる**。
        // 承認画面で待っている間に書き換えられた中身を、承認済みとして走らせない。
        // （この再計算から子がファイルを開くまでの窓は残る——§8。）
        if subject.depends_on_files() {
            let unchanged = match tool.permission_subject(input, self.ctx).await {
                Ok(again) => again.same_for_approval(&subject),
                Err(_) => false,
            };
            if !unchanged {
                return (
                    ToolOutput {
                        content: format!(
                            "{DENIAL_PREFIX}: {name} ({risk:?}) — the files it depends \
                             on or the program it resolves to changed while it was being approved, \
                             so it was not run"
                        ),
                        is_error: true,
                    },
                    ToolCallDecision::DeniedByPolicy,
                    None,
                );
            }
        }

        emit(
            self.events,
            AgentEvent::ToolStarted {
                id: id.to_string(),
                name: name.to_string(),
                subject: Some(subject.clone()),
            },
        );
        let output = self
            .call_with_wait_reasons(id, tool, input, conversation)
            .await;
        (output, ToolCallDecision::Executed, Some(subject))
    }

    /// [BUG-082フォローアップ] `tool.call(...)`を待つ間、`WaitReason`（D-54のworkspace ACL
    /// 伝播ジョブ等）を定期的に問い合わせ、変化があれば`AgentEvent::ToolProgress`として
    /// ツールカードへ流す。
    ///
    /// **このメソッドはどの背景条件が存在するかを一切知らない**——`harness_tools::wait_reasons`
    /// が返す集合を素通しでポーリングするだけなので、新しい待機理由が増えてもここは変更不要
    /// （`WaitReason`のdoc参照）。ポーリング間隔（300ms）はツールカードの更新として十分な
    /// 頻度で、かつ通常（待たされない）ツール呼び出しには実質コストを足さない——
    /// `tokio::select!`は`tool.call(...)`が先に終わればそちらを即座に返す。
    ///
    /// 道具は**常に`Tool::call_in_conversation`で呼ぶ**（既定は`Tool::call`へそのまま渡す）。名前で
    /// 道具を見分けて呼び分けない——会話を渡すかは`conversation`の有無だけで決まる。
    async fn call_with_wait_reasons(
        &self,
        id: &str,
        tool: &std::sync::Arc<dyn harness_core::Tool>,
        input: &serde_json::Value,
        conversation: Option<&[harness_core::Message]>,
    ) -> ToolOutput {
        let call_future = tool.call_in_conversation(input.clone(), self.ctx, conversation);
        tokio::pin!(call_future);
        let wait_reasons = harness_tools::wait_reasons::known_wait_reasons();
        let mut last_reason: Option<String> = None;
        loop {
            tokio::select! {
                result = &mut call_future => {
                    return result.unwrap_or_else(|e| ToolOutput {
                        content: e.to_string(),
                        is_error: true,
                    });
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(300)) => {
                    let reason = wait_reasons.describe_active();
                    if reason != last_reason {
                        // 空文字列は「待機理由が無くなった」の合図（TUI側で`wait_reason`を
                        // クリアする）。`None`のまま黙って戻すと、ツールカードは直前の
                        // （もう終わった）待機理由を実際の実行終了まで表示し続けてしまう。
                        emit(
                            self.events,
                            AgentEvent::ToolProgress {
                                id: id.to_string(),
                                message: reason.clone().unwrap_or_default(),
                            },
                        );
                        last_reason = reason;
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Executor for TurnExecutor<'_> {
    async fn raw_turn(&self, r: RawTurnRequest) -> Result<RawTurnResult, EngineError> {
        self.raw_turn_with_deltas(r, &mut |_: &str| {}).await
    }
}
