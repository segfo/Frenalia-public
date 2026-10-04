//! harness-config: 設定階層のマージ。`plans/DESIGN.md` §設定とシークレット参照。
//!
//! 既定（空）→ユーザ（`directories`の設定ディレクトリ配下`settings.json`）→プロジェクト
//! （`<project_root>/.harness/settings.json`）の順に`serde_json::Value`をディープマージしてから
//! `Settings`へデシリアライズする。CLIフラグとのマージ（最優先）は`harness-cli`側の責務
//! （フラグが`Some`ならそちらを使う、という素朴な上書きで足りるため、ここには含めない）。
//!
//! シークレット（APIキー等）は設計書の原則通りここでは一切扱わない（env優先、
//! `harness-cli`の`main()`が直接環境変数から読む）。設定ファイルが存在しない/パースできない
//! 場合はエラーにせず警告をstderrへ出して無視する（fail-fastはシークレット欠落時のみ）。

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    pub provider: Option<String>,
    pub model: Option<String>,
    pub permission_mode: Option<String>,
    /// 承認の許可リスト（`tool:pattern`）。**ユーザー層の値だけが入る**——プロジェクト層の
    /// `.harness/settings.json` の `allow` は読み込み時に捨てる（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` D-95、
    /// [`clamp_project_allow`]）。捨てた件数は [`Settings::ignored_project_allow`]。
    pub allow: Option<Vec<String>>,
    /// プロジェクト層の `allow` から捨てた規則の件数（D-95）。起動時に告知するために運ぶ。
    /// 設定ファイルには書かれない（読み込みの結果であって、設定の値ではない）。
    #[serde(skip)]
    pub ignored_project_allow: usize,
    pub max_tokens: Option<u32>,
    pub max_turns: Option<usize>,
    pub output_format: Option<String>,
    /// `true`ならTUI入力欄でEnterが送信（後方互換モード）。既定（`None`/`false`）では
    /// Alt+EnterまたはShift+Enterが送信、素のEnterは改行を挿入する（§リッチTUI「入力ボックス」）。
    pub enter_submits: Option<bool>,
    /// 読取スコープ設定（M11、`plans/DESIGN-SANDBOX.md` §5）。省略時は
    /// `ReadSettings::default()`（whitelist・外部ルート無し＝M10までと等価）。
    pub read: Option<ReadSettings>,
    /// 協調プロキシ設定（M12補遺、`plans/DESIGN-SANDBOX-PRIVSEP.md` §3.1 D-15）。省略時は
    /// `NetSettings::default()`（`allow_domains`空＝全拒否ポリシーを監査付きで起動）。
    pub net: Option<NetSettings>,
    /// Tier2a fs passthrough設定（D-13、`plans/DESIGN-SANDBOX-APPPOLICY.md`補遺）。省略時は
    /// `FsSettings::default()`（`allow`空＝追加ルート無し＝M12までと等価）。
    pub fs: Option<FsSettings>,
    /// `run_shell`子プロセス向けの非シークレット設定。省略時は
    /// `RunShellSettings::default()`（追加PATH無し＝従来通り）。
    pub run_shell: Option<RunShellSettings>,
    /// 承認画面の設定（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` D-100）。省略時は
    /// `ApprovalSettings::default()`（要約を作る・会話と同じプロバイダとモデル）。
    /// **プロジェクト層からは設定できない**（[`clamp_project_approval`]）。
    pub approval: Option<ApprovalSettings>,
    /// 認知レイヤー設定（M13〜、`plans/DESIGN-COGNITION.md` §2.3）。省略時は
    /// `CognitionSettings::default()`（`default_level`未指定＝`CognitionLevel`の既定）。
    pub cognition: Option<CognitionSettings>,
    /// コンテキスト縮約設定（`plans/PLAN-COMPACTION.md`）。省略時はプロバイダの
    /// `ProviderCapabilities`から解決した既定（ローカル`0.5`/`0.3`、クラウド`0.85`/`0.6`）。
    pub compaction: Option<CompactionSettings>,
    /// 縮退ガード設定（`plans/DESIGN-COGNITION.md` §11.6、M21）。省略時は
    /// `DegeneracySettings::default()`（有効・`auto_recycle`は無効）。
    pub degeneracy: Option<DegeneracySettings>,
    /// MCPサーバ宣言（M15.5、`plans/DESIGN-MCP.md` §4.1）。**ここだけ型を付けずに生の
    /// `Value`で運ぶ。**
    ///
    /// 宣言の型（`harness_mcp::McpServerDecl`）は承認ハッシュ（D-39）と一体で、ハッシュ対象の
    /// 完全性をコンパイル時に担保する構造を持つため`harness-mcp`から動かせない。一方で
    /// `harness-config`が`harness-mcp`へ依存すると、`harness-config`に依存する`harness-policy`
    /// （M15.7、意図的に純粋クレートとして保たれている）まで`harness-sandbox`とWin32を
    /// 引きずり込むことになる。
    ///
    /// そのため**この階層はマージだけを担当し、解釈は`harness_mcp::parse_mcp_settings`が行う**。
    /// 設定階層のディープマージ（ユーザ→プロジェクト）はこの`Value`に対して正しく効く。
    pub mcp: Option<serde_json::Value>,
    /// ポリシー学習ヘルパー設定（M15.7、`plans/DESIGN-SANDBOX-APPPOLICY.md` §11）。省略時は
    /// `PolicySettings::default()`（収集は無効）。
    pub policy: Option<PolicySettings>,
}

/// `settings.json`の`approval`キー（D-100）。**ユーザ層だけが決める**
/// （[`clamp_project_approval`]。中身をどこへ送るかをリポジトリに決めさせない）。
///
/// ```jsonc
/// "approval": {
///   "summarize": true,
///   "summary_provider": "lmstudio",
///   "summary_model": "qwen3-8b",
///   "use_judge_model": true,
///   "judge_model_url": "http://127.0.0.1:11435",
///   "judge_model": "winnow:e4b"
/// }
/// ```
///
/// 判定モデルの3つの欄は、以前の名前（`risk_check`・`risk_base_url`・`risk_model`）でも読む（`serde(alias)`）。
/// **この節は知らない項目を黙って捨てる**ので、名前だけ変えると、以前の名前で書いた設定が知らせも無く効かなくなる。
/// 同じ欄を新旧両方の名前で書くと、読み込みのエラーになる（どちらかを黙って選ばない）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ApprovalSettings {
    /// 承認画面で LLM に中身を要約させるか。省略時は真。
    pub summarize: Option<bool>,
    /// 要約に使うプロバイダ（`anthropic`・`openai`・`lmstudio`）。省略時は会話と同じ。
    pub summary_provider: Option<String>,
    /// 要約に使うプロバイダのエンドポイント。省略時はそのプロバイダの既定。
    pub summary_base_url: Option<String>,
    /// 要約に使うモデル。省略時は会話と同じ。
    pub summary_model: Option<String>,
    /// 承認画面の危険度の判定に、外の判定モデル（Ollaya）も使うか（`harness_engine::approval_risk`）。
    /// **省略時は偽**——偽でも機械の被害判定は動き、承認画面には「危険度: 要確認／高」が出る。
    /// 使うと、`judge_model_url`へ出るのは: `run_shell`の行・`run_program`のプログラムと引数・このセッションで走った
    /// コマンドの流れ（20件まで）・ハーネスが解読した中身・コードとして読まれる縛ったファイルの先頭4,000字。
    /// 判定は補助で、通す・止めるは決めない。以前の名前は`risk_check`。
    #[serde(alias = "risk_check")]
    pub use_judge_model: Option<bool>,
    /// 判定モデルのサーバ。省略時は`http://127.0.0.1:11435`。以前の名前は`risk_base_url`。
    #[serde(alias = "risk_base_url")]
    pub judge_model_url: Option<String>,
    /// 判定モデル。省略時は`winnow:e4b`。以前の名前は`risk_model`。
    #[serde(alias = "risk_model")]
    pub judge_model: Option<String>,
}

/// `.harness/settings.json`の`policy`キー（M15.7）。
///
/// ```jsonc
/// "policy": { "learn": false }
/// ```
///
/// **`learn`は収集の有効化だけを表し、提案の適用には一切関与しない**（D-42）。
/// 設定ファイルから許可ルールが自動で増える経路は、この機構のどこにも存在しない。
///
/// # 消したキー: `generalize`（D-62）
///
/// 一般化そのものを廃止したので消した。**このキーは在った頃から一度も読まれていなかった**
/// ——`rg`で確認したところ参照は0件で、CLIの`resolve_generalization`は設定を見ずに既定へ
/// 倒していた。docコメントだけが「CLIの`--generalize`が優先」と書いており、設定した人は
/// 効いていると読むしかなかった（B-32: 設定したのに効かない状態を作らない、の違反）。
/// 古い`settings.json`に残っていても、serdeは未知のキーを無視するので害は無い。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PolicySettings {
    /// セッション中にOS監査収集器を起動するか（CLIの`--policy-learn`が優先）。
    /// **有効にするとUACが1回出る**（収集器はETWセッションのため昇格が要る）。
    pub learn: Option<bool>,
}

impl PolicySettings {
    /// セッション中の収集が有効か（既定は無効＝オプトイン）。
    pub fn learn_enabled(&self) -> bool {
        self.learn.unwrap_or(false)
    }
}

/// `.harness/settings.json`の`cognition`キー。
///
/// `plans/DESIGN-COGNITION.md` §8のデルタ表は`model_tiers`も挙げるが、読む側（ModelRouter）が
/// 実装されるM17で追加する。設定だけ先に受け付けても黙って無視されるだけで、誤解を招くため。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CognitionSettings {
    /// `off` | `auto` | `always`。CLIの`--cognition`が指定されていればそちらが優先。
    pub default_level: Option<harness_core::CognitionLevel>,
    /// フェーズ別トークン予算の上書き（`plans/DESIGN-COGNITION.md` §3.3の表・§6.1）。
    /// 書かなかったフェーズは既定値のまま（`harness_cognition::PhaseBudgets`が部分上書きする）。
    ///
    /// ```jsonc
    /// "cognition": { "budgets": { "distill": { "max_in": 6000, "max_out": 800 } } }
    /// ```
    pub budgets: Option<std::collections::BTreeMap<harness_core::Phase, harness_core::TokenBudget>>,
    /// 情報源カタログ（M16、`plans/DESIGN-COGNITION.md` §4.2・§7.5）。内蔵ツール・MCP・webを
    /// **用途と信頼度で横並びに**宣言する。書かなかった情報源は種別の既定値で扱われる。
    ///
    /// ```jsonc
    /// "cognition": {
    ///   "sources": [
    ///     { "id": "mcp/company-docs", "kind": "mcp", "use_for": ["社内仕様"],
    ///       "trust": "high", "freshness": "authoritative" },
    ///     { "id": "web_fetch", "kind": "web", "use_for": ["一般調査"], "trust": "medium" }
    ///   ]
    /// }
    /// ```
    ///
    /// **どのMCPサーバを起動してよいかの宣言とは別のキーである**（§4.2）——あちらは
    /// 「起動してよいか」（`plans/DESIGN-MCP.md` §4）、こちらは「起動できるもののうち、
    /// どれをどの用途の情報源としてモデルへ見せるか」。per-tool `RiskClass`宣言（D-40）も
    /// ここには置かない。あれはMCP機構が所有し、認知層は`Tool::risk()`の結果に従うだけ。
    pub sources: Option<Vec<SourceSetting>>,
    /// `Recall`（ゴールを横断する永続記憶、`plans/PLAN-RECALL-MEMORY.md`）の設定。
    pub recall: Option<RecallSettings>,
}

/// `.harness/settings.json`の`cognition.recall`キー。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RecallSettings {
    /// 自動チェックポイント生成・自動読出し注入の有効化（既定true）。
    pub enabled: Option<bool>,
    /// gitが無い環境で履歴なし書込みを許すか（既定false）。**ユーザー層設定でのみ有効**
    /// （[`clamp_project_recall_allow_unversioned`]）——cloneしたリポジトリの
    /// `.harness/settings.json`だけで履歴無し書込みを有効化できてしまうと、
    /// 「このワークスペースだけ事後レビューの手段を封じる」毒入れ経路になる。
    pub allow_unversioned: Option<bool>,
    /// bigram検索の上位K件（既定5）。
    pub top_k: Option<usize>,
    /// Recallのダイジェスト照合が`Stale`と判定した記憶に、機械的な再検証項目を積むか
    /// （既定false、オプトイン）。**プロジェクト層からは有効化できるが無効化できない**
    /// （[`clamp_project_recall_stale_reverification_floor`]）——`true`は「古い記憶を無警告で
    /// 使わせない」という安全側の設定なので、`TrustLevel`の【T5】（引き下げは許すが
    /// 引き上げは許さない）とは逆方向の非対称クランプになる。
    pub stale_reverification: Option<bool>,
}

/// `cognition.sources[]`の1エントリ（`plans/DESIGN-COGNITION.md` §4.2）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceSetting {
    /// 内蔵ツール名（`read_file`等）、MCPサーバid（`mcp/company-docs`）、
    /// またはMCPツールの完全名（`mcp/company-docs/search_docs`）。
    pub id: Option<String>,
    /// `file` | `shell` | `web` | `mcp` | `memory`。省略時は`id`から推測する。
    pub kind: Option<String>,
    /// 用途タグ。Investigateへ渡すカタログに出る唯一の説明文。
    pub use_for: Option<Vec<String>>,
    /// `high` | `medium` | `low`。【T5】プロジェクト設定からは**引き下げのみ**可能
    /// （[`clamp_project_source_trust`]）。
    pub trust: Option<String>,
    /// `authoritative` | `fresh` | `stale` | `unknown`。
    pub freshness: Option<String>,
}

/// 【T5】`cognition.sources[].trust`は**上限**として解釈する（`plans/DESIGN-COGNITION.md` §4.2）。
///
/// プロジェクト同梱の`.harness/settings.json`はリポジトリをcloneしただけで存在し得るので、
/// そこから妥当性の重み付けを**引き上げられる**と、悪意あるリポジトリが自分の情報源を
/// 「信頼度high」と自称できてしまう。引き下げは安全側なので許す。
///
/// `Settings::load`はJSON層をディープマージしてからデシリアライズするため、マージ後には
/// どの層の値かが分からない。したがってこのクランプは**マージの過程で**掛ける必要がある。
/// `user`はユーザ層（マージ前）、`merged`はプロジェクト層まで載せた結果。
///
/// ユーザ層に宣言の無いidの上限は`medium`とする——プロジェクト設定だけで`high`を名乗れる道を
/// 残さないため。ユーザが明示的に`high`と書いた情報源だけが`high`になる。
pub fn clamp_project_source_trust(user: &serde_json::Value, merged: &mut serde_json::Value) {
    let ceilings: std::collections::HashMap<String, u8> = source_entries(user)
        .filter_map(|e| {
            let id = e.get("id")?.as_str()?.to_string();
            Some((id, trust_rank(e.get("trust").and_then(|v| v.as_str()))))
        })
        .collect();

    let Some(entries) = merged
        .get_mut("cognition")
        .and_then(|c| c.get_mut("sources"))
        .and_then(|s| s.as_array_mut())
    else {
        return;
    };
    for entry in entries {
        let Some(obj) = entry.as_object_mut() else {
            continue;
        };
        let id = obj.get("id").and_then(|v| v.as_str()).unwrap_or_default();
        // ユーザ層に宣言が無ければ上限は`medium`（rank 1）。
        let ceiling = ceilings.get(id).copied().unwrap_or(1);
        let declared = trust_rank(obj.get("trust").and_then(|v| v.as_str()));
        if declared > ceiling {
            obj.insert(
                "trust".to_string(),
                serde_json::Value::String(trust_name(ceiling).to_string()),
            );
        }
    }
}

/// `mcp`キーのうち、**ユーザ層でしか効かない**もの（`plans/DESIGN-MCP.md` D-49）。
///
/// 宣言（`mcp.servers[]`）はプロジェクト設定からも受け付ける（D-39）。リポジトリ同梱の宣言は
/// 承認台帳で止めるという設計であり、そこは変わらない。**変えられては困るのは、その宣言を
/// 「起動してよい」と決める側**である——Streamable HTTPはharness本体が喋る経路で、
/// AppContainerもWFPも協調プロキシも掛からない（§6.2）。有効化・宛先allowlist・信頼するCAまで
/// プロジェクト設定から動かせると、リポジトリが自分で自分を許可できてしまう。
const USER_ONLY_MCP_KEYS: &[&str] = &[
    "allow_streamable_http",
    "http_allow_domains",
    "http_ca_bundle",
];

/// D-49のクランプ。[`clamp_project_source_trust`]と同じく**マージの過程で**掛ける
/// （マージ後にはどの層の値かが分からなくなる）。
///
/// これらのキーについては、**マージ結果をユーザ層の値そのものへ戻す**。捨てて既定値に
/// するのではない——プロジェクト層が`http_allow_domains`を書いただけでユーザ自身の
/// allowlistが消えると、リポジトリが「権限を広げる」代わりに「ユーザの設定を壊す」
/// ことができてしまう。安全側ではあるが、プロジェクト層の影響をゼロにするのが本来の意図。
///
/// 上書きを無視したことは警告として出す——黙って無視すると「設定したのに効かない」に
/// 気付けない（[`parse_mcp_settings`](harness_mcp)と同じ方針）。
pub fn clamp_project_mcp_http_gates(user: &serde_json::Value, merged: &mut serde_json::Value) {
    let user_mcp = user.get("mcp").cloned();
    let Some(mcp) = merged.get_mut("mcp").and_then(|m| m.as_object_mut()) else {
        return;
    };
    for key in USER_ONLY_MCP_KEYS {
        let user_value = user_mcp.as_ref().and_then(|m| m.get(*key));
        // マージ結果がユーザ層の値と同じなら、プロジェクト層は触っていない。
        if mcp.get(*key) == user_value {
            continue;
        }
        eprintln!(
            "warning: ignoring \"mcp.{key}\" from the project settings. Streamable HTTP runs \
             outside the sandbox, so it can only be set in your user settings.json or on the \
             command line (see DESIGN-MCP.md D-49)."
        );
        match user_value {
            Some(value) => {
                mcp.insert((*key).to_string(), value.clone());
            }
            None => {
                mcp.remove(*key);
            }
        }
    }
}

/// `cognition.recall.allow_unversioned`は**ユーザー層設定でのみ**有効化できる
/// （`plans/PLAN-RECALL-MEMORY.md`）。[`clamp_project_mcp_http_gates`]と同じ形の
/// クランプ——マージ結果をユーザ層の値へ戻す（プロジェクト層が`false`→`true`にできない）。
///
/// cloneしたリポジトリの`.harness/settings.json`だけでgit不在時の履歴なし書込みを
/// 有効化できると、「このワークスペースの記憶だけ事後レビュー（`harness memory review`＋
/// git履歴）の手段を封じる」毒入れ経路になる。読出しには影響しない
/// （`allow_unversioned`は書込みの可否だけを制御する）。
pub fn clamp_project_recall_allow_unversioned(
    user: &serde_json::Value,
    merged: &mut serde_json::Value,
) {
    let user_value = user
        .get("cognition")
        .and_then(|c| c.get("recall"))
        .and_then(|r| r.get("allow_unversioned"));

    let Some(recall) = merged
        .get_mut("cognition")
        .and_then(|c| c.get_mut("recall"))
        .and_then(|r| r.as_object_mut())
    else {
        return;
    };
    if recall.get("allow_unversioned") == user_value {
        return;
    }
    eprintln!(
        "warning: ignoring \"cognition.recall.allow_unversioned\" from the project settings. \
         It can only be set in your user settings.json (see plans/PLAN-RECALL-MEMORY.md)."
    );
    match user_value {
        Some(value) => {
            recall.insert("allow_unversioned".to_string(), value.clone());
        }
        None => {
            recall.remove("allow_unversioned");
        }
    }
}

/// `cognition.recall.stale_reverification`は**プロジェクト層から有効化はできるが無効化はできない**
/// （`plans/PLAN-RECALL-MEMORY.md`、`docs/STATUS.md`認知レイヤー残課題#16）。
///
/// [`clamp_project_recall_allow_unversioned`]・[`clamp_project_source_trust`]（【T5】）と形は
/// 同じ「マージ結果をユーザ層の値へ戻す」クランプだが、**方向が逆**——`allow_unversioned`は
/// ユーザー層限定（プロジェクトは一切動かせない）、`source_trust`は引き下げのみ許可
/// （プロジェクトは安全側にしか動かせない）だが、`stale_reverification`は`true`＝安全側なので
/// **プロジェクトは引き上げる方向（`true`）にしか動かせない**。ユーザー層が`true`にしていれば、
/// プロジェクト層が`false`と書いてもユーザーの値が勝つ。ユーザー層が`true`にしていなければ、
/// プロジェクト層は自由に`true`/`false`を書ける（安全側への変更を妨げないため）。
pub fn clamp_project_recall_stale_reverification_floor(
    user: &serde_json::Value,
    merged: &mut serde_json::Value,
) {
    let user_floor = user
        .get("cognition")
        .and_then(|c| c.get("recall"))
        .and_then(|r| r.get("stale_reverification"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !user_floor {
        // フロアが立っていない（ユーザー層がtrueにしていない）ので、プロジェクト層の値を
        // そのまま通す。
        return;
    }

    let Some(recall) = merged
        .get_mut("cognition")
        .and_then(|c| c.get_mut("recall"))
        .and_then(|r| r.as_object_mut())
    else {
        return;
    };
    let merged_true = recall
        .get("stale_reverification")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if merged_true {
        return;
    }
    eprintln!(
        "warning: ignoring an attempt to disable \"cognition.recall.stale_reverification\" from \
         the project settings. Once enabled in your user settings.json it cannot be turned off by \
         a project (see plans/PLAN-RECALL-MEMORY.md)."
    );
    recall.insert(
        "stale_reverification".to_string(),
        serde_json::Value::Bool(true),
    );
}

fn source_entries(root: &serde_json::Value) -> impl Iterator<Item = &serde_json::Value> {
    root.get("cognition")
        .and_then(|c| c.get("sources"))
        .and_then(|s| s.as_array())
        .map(|a| a.as_slice())
        .unwrap_or(&[])
        .iter()
}

/// 未知の綴り・未指定は`medium`（rank 1）へ倒す。未知の値を`high`扱いしない。
fn trust_rank(trust: Option<&str>) -> u8 {
    match trust {
        Some("high") => 2,
        Some("low") => 0,
        _ => 1,
    }
}

fn trust_name(rank: u8) -> &'static str {
    match rank {
        2 => "high",
        0 => "low",
        _ => "medium",
    }
}

/// `.harness/settings.json`の`compaction`キー（`plans/PLAN-COMPACTION.md`「設定」）。
///
/// いずれも省略可で、省略時はプロバイダの`ProviderCapabilities`から解決した既定へ落ちる
/// （`local`なら`0.5`/`0.3`、クラウドなら`0.85`/`0.6`）。
///
/// ```jsonc
/// "compaction": { "context_window": 8192, "trigger_ratio": 0.5, "target_ratio": 0.3 }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CompactionSettings {
    /// 使用率判定の分母の上書き。**通常は省略でよい。**
    ///
    /// 解決順は CLIの`--context-window` → このキー → **推論サーバへの問い合わせ**
    /// （`LlmProvider::detect_context_window`。LM Studioは`GET /api/v1/models`の
    /// `loaded_instances[].config.context_length`＝実`n_ctx`を返す） →
    /// `ProviderCapabilities.context_window`。
    ///
    /// 書くのは、検出値が実態と違うとき（LM Studioの`parallel`スロットの扱い等）や、
    /// **宣言された窓より狭い予算で運用したい**ときだけである。比率だけを書けば足りる。
    pub context_window: Option<u32>,
    /// 使用率がこれを超えたら縮約する。
    pub trigger_ratio: Option<f32>,
    /// 縮約後に目指す水準。`trigger_ratio`より小さくないと毎ターン再発火して振動する
    /// （逆転していれば起動時にエラーで止める。黙って直さない）。
    pub target_ratio: Option<f32>,
}

/// `.harness/settings.json`の`degeneracy`キー（`plans/DESIGN-COGNITION.md` §11.6）。
///
/// ```jsonc
/// "degeneracy": {
///   "enabled": true,                 // 既定 true。この機構全体の無効化スイッチ
///   "auto_recycle": false,           // 既定 false。(d)段。LMStudio系統でのみ意味を持つ
///   "gate_multiplier": 3.0,          // 平常中央値の何倍で「疑い」状態へ入るか
///   "recovery_multiplier": 3.0,      // 回復に使ってよい壁時計時間 = 中央値 × これ
///   "short_period":  { "window": 512,  "max_period": 32, "min_repeats": 8 },
///   "ngram":         {
///     "window": 1024, "n": 32, "seen_ratio_max": 0.80,
///     "min_hot_sections": 6, "min_hot_sections_suspect": 3
///   },
///   "reasoning_only_ratio": 0.6      // max_tokens の何割を thinking だけで食ったら kill
/// }
/// ```
///
/// **`enabled`という単一の無効化スイッチを置く**のは、この機構が本来正常な動作を阻害し得る
/// 唯一のクラスの機能だからである（他の機構は「拒否する」方向で、これは「捨ててやり直す」方向）。
/// 想定外の誤検知に当たった人が、ハーネス全体を使えなくなる前に切れる口を1つ確保する。
///
/// `auto_recycle`は**booleanだけ**であり、実行内容（エンドポイントと手順）は完全にコード側にある。
/// 設定ファイルは宣言のみを持ちコード実行ベクタにならない——`docs/SECURITY-PRINCIPLES.md` P-08 と
/// 脅威モデル T-08（`.harness/settings.json`自己追記）の前提を変えない。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DegeneracySettings {
    pub enabled: Option<bool>,
    pub auto_recycle: Option<bool>,
    pub gate_multiplier: Option<f32>,
    pub recovery_multiplier: Option<f32>,
    pub short_period: Option<ShortPeriodSettings>,
    pub ngram: Option<NgramSettings>,
    pub reasoning_only_ratio: Option<f32>,
}

/// `degeneracy.short_period`（①短周期反復の窓・周期上限・最小反復回数）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct ShortPeriodSettings {
    pub window: Option<usize>,
    pub max_period: Option<usize>,
    pub min_repeats: Option<usize>,
}

/// `degeneracy.ngram`（②新規性率の窓・n-gram長・既出率の上限・連続区間数）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct NgramSettings {
    pub window: Option<usize>,
    pub n: Option<usize>,
    pub seen_ratio_max: Option<f64>,
    /// 平常時（異常ゲート閉）に必要な連続ホット区間数。
    pub min_hot_sections: Option<usize>,
    /// 疑い状態（異常ゲート開）に必要な連続ホット区間数。
    pub min_hot_sections_suspect: Option<usize>,
}

impl DegeneracySettings {
    /// この機構全体が有効か（既定`true`）。
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }
}

/// `.harness/settings.json`の`run_shell`キー。シークレットenvの転送は禁止し、PATH追加だけを扱う。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RunShellSettings {
    /// clean envで継承したPATHへ追記するディレクトリ。例: `C:\\Users\\me\\.local\\bin`。
    pub path_extra: Option<Vec<String>>,
}

impl RunShellSettings {
    pub fn path_extra(&self) -> Vec<String> {
        self.path_extra.clone().unwrap_or_default()
    }
}

/// `.harness/settings.json`の`fs`キー（D-13、Tier2a fs passthrough allowlist）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FsSettings {
    /// 追加で許可するルート。各要素は`"<path>"`（read-only既定）または`"<path>:rw"`
    /// （書込も許可、明示opt-in）。CLIの`--fs-allow`と和集合でマージされる
    /// （`net.allow_apps`と同じ役割分担、絶対パス化は`harness-cli`側）。
    pub allow: Option<Vec<String>>,
    /// 読取だけを許可するルート。
    pub read: Option<Vec<String>>,
    /// 読取・書込を許可するルート。
    pub read_write: Option<Vec<String>>,
    /// 読取・実行を許可するルート。
    pub read_exec: Option<Vec<String>>,
}

/// serde表現（`read`/`read_write`/`read_exec`）は`fs.{read,read_write,read_exec}`の設定キー名と
/// 一致させる。`harness-policy`の提案・`fs-audit.jsonl`のイベントがこの綴りをそのまま運ぶため
/// （`plans/DESIGN-SANDBOX-APPPOLICY.md` §11.1「`access`は設定スキーマと同じ語彙へ寄せる」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsAccess {
    Read,
    ReadWrite,
    ReadExec,
}

impl FsAccess {
    /// `fs.{read,read_write,read_exec}`の設定キー名。
    pub fn settings_key(self) -> &'static str {
        match self {
            FsAccess::Read => "read",
            FsAccess::ReadWrite => "read_write",
            FsAccess::ReadExec => "read_exec",
        }
    }
}

impl FsSettings {
    /// `fs.{read,read_write,read_exec}`と旧`fs.allow`を`(パス文字列, access)`へ変換する。
    /// 旧`fs.allow`は互換のため、`:rw`ならread_write、サフィックス無しなら従来の
    /// read+execute相当（read_exec）として扱う。
    ///
    /// # 同じパスが複数のバケツにあったときは、ここでは畳まない
    ///
    /// かつては[`merge_fs_access`]で1件へ畳んでいたが、その規則は`ReadWrite`と`ReadExec`を
    /// `ReadWrite`へ寄せる（＝**実行権を黙って落とす**）ものだった。`fs.read_write`と
    /// `fs.read_exec`の両方に同じパスを書いたユーザーは、実行できない理由が設定から読み取れない
    /// 状態になる。和を表せるのは付与層（`harness_sandbox::FsAccess::ReadWriteExec`）だけなので、
    /// **畳み込みはそちらへ寄せた**——この関数は宣言をそのままの粒度で返す。
    /// 同じパスが2回現れ得るので、呼び出し側は`harness_sandbox::FsAccess::wider`で合成すること。
    pub fn to_fs_passthrough(&self) -> Vec<(String, FsAccess)> {
        let mut out = Vec::new();
        for path in self.read.clone().unwrap_or_default() {
            push_fs_entry(&mut out, path, FsAccess::Read);
        }
        for path in self.read_write.clone().unwrap_or_default() {
            push_fs_entry(&mut out, path, FsAccess::ReadWrite);
        }
        for path in self.read_exec.clone().unwrap_or_default() {
            push_fs_entry(&mut out, path, FsAccess::ReadExec);
        }
        for entry in self.allow.clone().unwrap_or_default() {
            match entry.strip_suffix(":rw") {
                Some(path) => push_fs_entry(&mut out, path.to_string(), FsAccess::ReadWrite),
                None => push_fs_entry(&mut out, entry, FsAccess::ReadExec),
            }
        }
        out
    }
}

/// 宣言を1件足す。**同じパス・同じaccessの重複だけ**を落とす（`fs.read`に同じ行が2度書かれた等）。
///
/// access種別が違う重複は**畳まずに両方残す**——ここで畳むと、和を表せない語彙（3値）へ
/// 落とし込むことになり、必ずどちらかの権限が消える（[`FsSettings::to_fs_passthrough`]のdoc）。
fn push_fs_entry(out: &mut Vec<(String, FsAccess)>, path: String, access: FsAccess) {
    if out.iter().any(|(p, a)| p == &path && *a == access) {
        return;
    }
    out.push((path, access));
}

/// `.harness/settings.json`の`net`キー（M12補遺、D-15/D-10）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetSettings {
    /// 協調プロキシの許可ドメイン（`*.example.com`形式のサフィックスワイルドカード対応）。
    pub allow_domains: Option<Vec<String>>,
    /// アプリ単位network制御（軸1、D-10/D-11）の信頼アプリ名リスト（Tier2aで`internetClient`を
    /// 付与する先頭exe名。basename・拡張子除去・小文字で照合）。
    pub allow_apps: Option<Vec<String>>,
}

impl NetSettings {
    /// `harness_core::NetProxyConfig`へ変換する。
    pub fn to_net_proxy_config(&self) -> harness_core::NetProxyConfig {
        harness_core::NetProxyConfig {
            allow_domains: self.allow_domains.clone().unwrap_or_default(),
            domain_policy_enabled: true,
            enforced_by_wfp: false,
            audit_log_path: None,
            proxy_addr: None,
            fake_dns_addr: None,
            ..Default::default()
        }
    }

    /// `harness_core::NetAppPolicy`へ変換する（軸1、D-10/D-11）。
    pub fn to_net_app_policy(&self) -> harness_core::NetAppPolicy {
        harness_core::NetAppPolicy {
            allow_apps: self.allow_apps.clone().unwrap_or_default(),
        }
    }
}

/// `.harness/settings.json`の`read`キー（M11）。`harness_core::ReadScopeConfig`へ変換する前の
/// 生の設定値（パス文字列のまま、`~`展開等は行わない）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ReadSettings {
    /// `"whitelist"`（既定）/`"blacklist"`。未知の値・省略時はwhitelist扱い。
    pub mode: Option<String>,
    pub allow: Option<Vec<String>>,
    pub allow_descend: Option<Vec<String>>,
    pub deny: Option<Vec<String>>,
    pub deny_descend: Option<Vec<String>>,
}

impl ReadSettings {
    /// `harness_core::ReadScopeConfig`へ変換する（`allow`/`allow_descend`はパスとして解釈）。
    pub fn to_read_scope_config(&self) -> harness_core::ReadScopeConfig {
        let mode = match self.mode.as_deref() {
            Some("blacklist") => harness_core::ReadMode::Blacklist,
            _ => harness_core::ReadMode::Whitelist,
        };
        harness_core::ReadScopeConfig {
            mode,
            allow: self
                .allow
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(std::path::PathBuf::from)
                .collect(),
            allow_descend: self
                .allow_descend
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(std::path::PathBuf::from)
                .collect(),
            deny: self.deny.clone().unwrap_or_default(),
            deny_descend: self.deny_descend.clone().unwrap_or_default(),
        }
    }
}

/// `<project_root>/.harness/settings.json`（呼び出し側は`project_root`に作業ディレクトリを渡す）。
fn project_settings_path(project_root: &Path) -> std::path::PathBuf {
    project_root.join(".harness").join("settings.json")
}

const DEFAULT_PROJECT_SETTINGS: &str = r#"{
  "run_shell": {
    "path_extra": []
  },
  "net": {
    "allow_domains": [],
    "allow_apps": []
  },
  "fs": {
    "read": [],
    "read_write": [],
    "read_exec": []
  }
}
"#;

/// ユーザ層の`settings.json`の雛形（無ければ起動時に書く。[`ensure_user_settings_file`]）。
///
/// **書いても動きが変わらない値だけ**を置く——どれも省略時と同じ値（要約は作る・判定モデルは使わない）。
/// 開いた人が「どこに何を書けばよいか」を見つけられるようにするためのもので、既定を変えるためのものではない。
/// **送り先やモデル名は書かない**——書くと、ハーネス側の既定が変わっても、このファイルの古い値に縛られる。
const DEFAULT_USER_SETTINGS: &str = r#"{
  "approval": {
    "summarize": true,
    "use_judge_model": false
  }
}
"#;

/// `directories::ProjectDirs`の設定ディレクトリ配下`settings.json`（Windowsは`%APPDATA%`、
/// mac/LinuxはXDG準拠、§設定とシークレット「ユーザ（`directories`: Windows `%APPDATA%`／
/// mac/Linux XDG）」）。
fn user_settings_path() -> Option<std::path::PathBuf> {
    directories::ProjectDirs::from("", "", "harness").map(|d| d.config_dir().join("settings.json"))
}

/// CoW差分層の自動回収（D-82）で「これは消さない」を宣言する設定。
///
/// # なぜ[`Settings`]のフィールドにしないのか
///
/// **プロジェクト層（`.harness/settings.json`）から触れる場所に置かないためである。**
/// これは「何を削除してよいか」を決める設定で、リポジトリに同梱された設定が
/// 「消してよい」と言えると、**リポジトリが他のセッションの未適用の作業を消させられる**。
/// ユーザ層でしか効かないキーを[`Settings`]へ載せてクランプで守る方法もある
/// （`mcp`のHTTPゲートがそれ、[`clamp_project_mcp_http_gates`]）が、こちらは
/// **そもそも載せない**——プロジェクト層に現れる余地が無ければ、クランプを掛け忘れる経路も無い。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CowGcSettings {
    /// ネットワーク上のボリュームにある差分層を自動回収から外す。**既定は`true`（外す）。**
    ///
    /// 差分層の置き場を全ボリューム走査で棚卸しする都合上、割り当て済みのネットワークドライブ
    /// も対象に入る。そこにあるものは**他のマシンが作った可能性がある**うえ、常時接続が普通なので
    /// 「到達できない＝判定不能」という安全網も働かない。既定で消さない側へ倒す。
    pub protect_network_volumes: Option<bool>,
}

impl Default for CowGcSettings {
    fn default() -> Self {
        Self {
            protect_network_volumes: Some(true),
        }
    }
}

impl CowGcSettings {
    pub fn protect_network_volumes(&self) -> bool {
        self.protect_network_volumes.unwrap_or(true)
    }
}

/// ユーザ層の`settings.json`だけを読んで[`CowGcSettings`]を返す（プロジェクト層は**見ない**）。
///
/// 読めない・書かれていない場合は既定（ネットワーク上は保護する）。
/// **設定ファイルが壊れていても保護が外れないこと**が要点で、`unwrap_or_default`が
/// 常に安全側を返す。
pub fn user_cow_gc_settings() -> CowGcSettings {
    let Some(path) = user_settings_path() else {
        return CowGcSettings::default();
    };
    let Some(value) = read_json(&path) else {
        return CowGcSettings::default();
    };
    value
        .get("cow")
        .and_then(|c| c.get("gc"))
        .and_then(|gc| serde_json::from_value::<CowGcSettings>(gc.clone()).ok())
        .unwrap_or_default()
}

/// ファイルを読みJSONとしてパースする。存在しない場合は`Ok(None)`、存在するが読めない/
/// パースできない場合は警告をstderrへ出し`Ok(None)`として扱う（設定ファイルの欠如・破損で
/// 起動自体を止めない）。
fn read_json(path: &Path) -> Option<serde_json::Value> {
    if !path.exists() {
        return None;
    }
    match std::fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str(&text) {
            Ok(v) => Some(v),
            Err(e) => {
                eprintln!(
                    "warning: ignoring malformed settings file {}: {e}",
                    path.display()
                );
                None
            }
        },
        Err(e) => {
            eprintln!(
                "warning: could not read settings file {}: {e}",
                path.display()
            );
            None
        }
    }
}

pub fn ensure_project_settings_file(project_root: &Path) {
    ensure_settings_file_at(&project_settings_path(project_root), DEFAULT_PROJECT_SETTINGS);
}

/// ユーザ層の`settings.json`（Windowsは`%APPDATA%\harness\config\settings.json`）が無ければ、雛形
/// （[`DEFAULT_USER_SETTINGS`]）を書く。**既にあれば触らない。** 作れなくても起動は止めない（警告だけ）。
///
/// **起動の処理（`harness-cli`）からだけ呼ぶ。** [`Settings::load`]からは呼ばない——読む関数は試験からも呼ばれ、
/// そこに入れると試験のたびにこのマシンの本物の設定の置き場へ書いてしまう。
pub fn ensure_user_settings_file() {
    if let Some(path) = user_settings_path() {
        ensure_settings_file_at(&path, DEFAULT_USER_SETTINGS);
    }
}

/// `path`が無ければ`template`を書く。**既にあれば何もしない。**
///
/// 「在るか確かめてから書く」と、その間に別のプロセス（同時に起動した2つ目のハーネス）が書いた中身を上書きし得る。
/// だから**既にあれば失敗する開き方**（`create_new`）で作り、在ったら黙って降りる（`B-18`: 確認と作成を不可分に）。
fn ensure_settings_file_at(path: &Path, template: &str) {
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!(
                "warning: could not create settings directory {}: {e}",
                parent.display()
            );
            return;
        }
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path);
    let mut file = match file {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return,
        Err(e) => {
            eprintln!(
                "warning: could not create default settings file {}: {e}",
                path.display()
            );
            return;
        }
    };
    if let Err(e) = std::io::Write::write_all(&mut file, template.as_bytes()) {
        eprintln!(
            "warning: could not write default settings file {}: {e}",
            path.display()
        );
    }
}

/// `overlay`のキーで`base`を上書きするディープマージ。オブジェクト同士は再帰的にマージし、
/// それ以外（スカラー/配列）は`overlay`の値で丸ごと置き換える。
fn deep_merge(base: &mut serde_json::Value, overlay: serde_json::Value) {
    match (base, overlay) {
        (serde_json::Value::Object(base_map), serde_json::Value::Object(overlay_map)) => {
            for (k, v) in overlay_map {
                match base_map.get_mut(&k) {
                    Some(existing) => deep_merge(existing, v),
                    None => {
                        base_map.insert(k, v);
                    }
                }
            }
        }
        (base_slot, overlay_value) => {
            *base_slot = overlay_value;
        }
    }
}

/// 層の JSON が持つ `allow` の件数。
fn count_allow_rules(layer: &serde_json::Value) -> usize {
    layer
        .get("allow")
        .and_then(|v| v.as_array())
        .map_or(0, Vec::len)
}

/// 【D-95】プロジェクト層の `allow` を捨て、ユーザー層の値へ戻す
/// （`plans/DESIGN-RUNSHELL-ALLOWLIST.md` D-95）。
///
/// プロジェクト層の設定はワークスペースの中にあり、`run_shell` から書け、クローンしたリポジトリに
/// 同梱されていることもある——**敵対者が用意し得る入力**なので、自動承認の根拠にしない。
/// 他のクランプと違い「上限へ抑える」のではなく**丸ごと捨てる**。
///
/// **マージに頼らずユーザー層の値を明示的に戻す。** 深いマージは配列を丸ごと置き換えるので
/// （[`deep_merge`]）、マージ後の `allow` はプロジェクト層の配列そのものになっている——
/// 以前はこれでユーザー層の規則が**消えて**、プロジェクト層の規則に**置き換わって**いた。
/// 【T5】承認画面の設定は**ユーザ層だけ**が決める（D-100）。
///
/// **要約はワークスペースのファイルの中身をプロバイダへ送る。** プロジェクト層
/// （`.harness/settings.json`＝クローンしたリポジトリが同梱できる）から送り先を書けると、
/// リポジトリを開いただけで中身が任意のエンドポイントへ出る。要約を**有効にする**側も同じで、
/// ユーザーが切っているものをリポジトリが戻せてはいけない。だから節ごと捨てる。
pub fn clamp_project_approval(user: &serde_json::Value, merged: &mut serde_json::Value) {
    let Some(obj) = merged.as_object_mut() else {
        return;
    };
    match user.get("approval") {
        Some(v) => {
            obj.insert("approval".to_string(), v.clone());
        }
        None => {
            obj.remove("approval");
        }
    }
}

pub fn clamp_project_allow(user: &serde_json::Value, merged: &mut serde_json::Value) {
    let Some(obj) = merged.as_object_mut() else {
        return;
    };
    match user.get("allow") {
        Some(user_allow) => {
            obj.insert("allow".to_string(), user_allow.clone());
        }
        None => {
            obj.remove("allow");
        }
    }
}

impl Settings {
    /// 既定（空）→ユーザ→プロジェクトの順にマージする。`project_root`はワークスペースルート
    /// （`--cwd`解決後のディレクトリ）を渡す。
    pub fn load(project_root: &Path) -> Settings {
        let mut merged = serde_json::Value::Object(Default::default());
        ensure_project_settings_file(project_root);

        if let Some(user_path) = user_settings_path() {
            if let Some(user_json) = read_json(&user_path) {
                deep_merge(&mut merged, user_json);
            }
        }
        // 【T5】のクランプに要るので、プロジェクト層を載せる前のユーザ層を控えておく
        // （マージ後はどの層の値かが分からなくなる）。
        let user_layer = merged.clone();
        let project_json = read_json(&project_settings_path(project_root));
        let ignored_project_allow = project_json.as_ref().map_or(0, count_allow_rules);
        if let Some(project_json) = project_json {
            deep_merge(&mut merged, project_json);
        }
        clamp_project_source_trust(&user_layer, &mut merged);
        clamp_project_mcp_http_gates(&user_layer, &mut merged);
        clamp_project_recall_allow_unversioned(&user_layer, &mut merged);
        clamp_project_recall_stale_reverification_floor(&user_layer, &mut merged);
        clamp_project_allow(&user_layer, &mut merged);
        clamp_project_approval(&user_layer, &mut merged);

        let mut settings: Settings = serde_json::from_value(merged).unwrap_or_default();
        settings.ignored_project_allow = ignored_project_allow;
        settings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_settings_override_user_settings_which_override_default() {
        let dir = tempfile::tempdir().unwrap();
        // このテストは`directories::ProjectDirs`のユーザ設定パス（テスト実行環境依存で
        // 触れられない）は使わず、`deep_merge`単体でマージ優先順位のみを検証する。
        let mut merged = serde_json::json!({ "model": "user-model", "max_turns": 10 });
        let project_override = serde_json::json!({ "model": "project-model" });
        deep_merge(&mut merged, project_override);

        let settings: Settings = serde_json::from_value(merged).unwrap();
        assert_eq!(settings.model.as_deref(), Some("project-model"));
        assert_eq!(settings.max_turns, Some(10));
        let _ = dir; // ディレクトリ自体は使わないが構造を保つため保持
    }

    /// `compaction`は3項目とも独立に省略でき、書いたものだけが`Some`になる
    /// （省略値の解決＝プロバイダ既定へのフォールバックは`harness-engine`側の責務で、
    /// ここは「書かれたことだけを運ぶ」）。
    #[test]
    fn parses_partial_compaction_settings() {
        let settings: Settings =
            serde_json::from_value(serde_json::json!({ "compaction": { "context_window": 8192 } }))
                .unwrap();
        let c = settings.compaction.unwrap();
        assert_eq!(c.context_window, Some(8192));
        assert_eq!(c.trigger_ratio, None);
        assert_eq!(c.target_ratio, None);

        let full: Settings = serde_json::from_value(serde_json::json!({
            "compaction": { "context_window": 32768, "trigger_ratio": 0.5, "target_ratio": 0.3 }
        }))
        .unwrap();
        let c = full.compaction.unwrap();
        assert_eq!(c.context_window, Some(32_768));
        assert_eq!(c.trigger_ratio, Some(0.5));
        assert_eq!(c.target_ratio, Some(0.3));

        let empty: Settings = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(empty.compaction.is_none());
    }

    /// `cognition.default_level`は`CognitionLevel`のsnake_case表現をそのまま書ける
    /// （CLIの`--cognition`と同じ綴り）。キー自体が無ければ`None`のまま。
    #[test]
    fn parses_cognition_default_level() {
        let settings: Settings = serde_json::from_value(
            serde_json::json!({ "cognition": { "default_level": "always" } }),
        )
        .unwrap();
        assert_eq!(
            settings.cognition.unwrap().default_level,
            Some(harness_core::CognitionLevel::Always)
        );

        let empty: Settings = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(empty.cognition.is_none());
    }

    /// `cognition.budgets`はフェーズ名をキーに部分指定できる（書かなかったフェーズは
    /// `harness_cognition::PhaseBudgets`の既定表のまま）。
    #[test]
    fn parses_partial_cognition_budgets() {
        let settings: Settings = serde_json::from_value(serde_json::json!({
            "cognition": { "budgets": { "distill": { "max_in": 6000, "max_out": 800 } } }
        }))
        .unwrap();

        let budgets = settings.cognition.unwrap().budgets.unwrap();
        assert_eq!(budgets.len(), 1);
        assert_eq!(
            budgets[&harness_core::Phase::Distill],
            harness_core::TokenBudget {
                max_in: 6000,
                max_out: 800
            }
        );
    }

    /// `cognition.sources`は各フィールドを独立に省略できる（書いたものだけが`Some`）。
    #[test]
    fn parses_partial_cognition_sources() {
        let settings: Settings = serde_json::from_value(serde_json::json!({
            "cognition": { "sources": [
                { "id": "mcp/company-docs", "kind": "mcp", "use_for": ["社内仕様"],
                  "trust": "high", "freshness": "authoritative" },
                { "id": "web_fetch" }
            ] }
        }))
        .unwrap();

        let sources = settings.cognition.unwrap().sources.unwrap();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].trust.as_deref(), Some("high"));
        assert_eq!(
            sources[0].use_for.as_deref(),
            Some(&["社内仕様".to_string()][..])
        );
        assert_eq!(sources[1].id.as_deref(), Some("web_fetch"));
        assert_eq!(
            sources[1].trust, None,
            "省略は種別既定へ落とす（読む側の責務）"
        );
    }

    /// `cognition.recall`は各フィールドを独立に省略できる。
    #[test]
    fn parses_partial_cognition_recall_settings() {
        let settings: Settings = serde_json::from_value(serde_json::json!({
            "cognition": { "recall": { "enabled": false, "top_k": 3 } }
        }))
        .unwrap();
        let recall = settings.cognition.unwrap().recall.unwrap();
        assert_eq!(recall.enabled, Some(false));
        assert_eq!(recall.top_k, Some(3));
        assert_eq!(recall.allow_unversioned, None);
        assert_eq!(recall.stale_reverification, None);
    }

    // --- `cognition.recall.allow_unversioned`はユーザー層限定 ---

    fn merged_recall(user: &serde_json::Value, project: serde_json::Value) -> serde_json::Value {
        let mut merged = user.clone();
        deep_merge(&mut merged, project);
        clamp_project_recall_allow_unversioned(user, &mut merged);
        merged
            .get("cognition")
            .and_then(|c| c.get("recall"))
            .cloned()
            .unwrap_or_default()
    }

    /// プロジェクト層は`allow_unversioned`を独力で有効化できない（未決事項の確定に伴う
    /// 設計判断）。
    #[test]
    fn a_project_cannot_enable_recall_allow_unversioned_on_its_own() {
        let user = serde_json::json!({});
        let recall = merged_recall(
            &user,
            serde_json::json!({ "cognition": { "recall": { "allow_unversioned": true } } }),
        );
        assert_eq!(recall.get("allow_unversioned"), None);
    }

    /// ユーザー層が明示的に`true`にしていれば、プロジェクト層に`false`と書かれていても
    /// ユーザーの値が勝つ（マージ結果をユーザ層へ戻す、D-49と同じ形）。
    #[test]
    fn a_user_enabled_allow_unversioned_survives_a_conflicting_project_value() {
        let user = serde_json::json!({ "cognition": { "recall": { "allow_unversioned": true } } });
        let recall = merged_recall(
            &user,
            serde_json::json!({ "cognition": { "recall": { "allow_unversioned": false } } }),
        );
        assert_eq!(
            recall.get("allow_unversioned"),
            Some(&serde_json::json!(true))
        );
    }

    // --- `cognition.recall.stale_reverification`はプロジェクト層から有効化はできるが
    //     無効化はできない（`allow_unversioned`・【T5】と方向が逆の非対称クランプ） ---

    fn merged_recall_stale_reverification(
        user: &serde_json::Value,
        project: serde_json::Value,
    ) -> serde_json::Value {
        let mut merged = user.clone();
        deep_merge(&mut merged, project);
        clamp_project_recall_stale_reverification_floor(user, &mut merged);
        merged
            .get("cognition")
            .and_then(|c| c.get("recall"))
            .cloned()
            .unwrap_or_default()
    }

    /// ユーザー層が未設定（フロアが立っていない）なら、プロジェクト層は自由に有効化できる
    /// ——`true`は安全側の変更であり、それを妨げる理由が無い（`allow_unversioned`とは逆方向）。
    #[test]
    fn a_project_can_freely_enable_stale_reverification_when_the_user_has_not_set_a_floor() {
        let user = serde_json::json!({});
        let recall = merged_recall_stale_reverification(
            &user,
            serde_json::json!({ "cognition": { "recall": { "stale_reverification": true } } }),
        );
        assert_eq!(
            recall.get("stale_reverification"),
            Some(&serde_json::json!(true))
        );
    }

    /// ユーザー層が`true`にしていれば、プロジェクト層が`false`と書いてもユーザーの値が勝つ
    /// （プロジェクトは無効化できない）。
    #[test]
    fn a_project_cannot_disable_stale_reverification_once_the_user_enabled_it() {
        let user =
            serde_json::json!({ "cognition": { "recall": { "stale_reverification": true } } });
        let recall = merged_recall_stale_reverification(
            &user,
            serde_json::json!({ "cognition": { "recall": { "stale_reverification": false } } }),
        );
        assert_eq!(
            recall.get("stale_reverification"),
            Some(&serde_json::json!(true))
        );
    }

    /// ユーザー層が`false`（明示）でも、プロジェクト層は制約なく`true`にできる
    /// （フロアは「ユーザーがtrueにしたか」でだけ立つ）。
    #[test]
    fn a_project_can_enable_stale_reverification_even_if_the_user_explicitly_disabled_it() {
        let user =
            serde_json::json!({ "cognition": { "recall": { "stale_reverification": false } } });
        let recall = merged_recall_stale_reverification(
            &user,
            serde_json::json!({ "cognition": { "recall": { "stale_reverification": true } } }),
        );
        assert_eq!(
            recall.get("stale_reverification"),
            Some(&serde_json::json!(true))
        );
    }

    /// **【T5】**: プロジェクト同梱設定はtrustを**引き下げられるが引き上げられない**。
    /// cloneしただけで存在し得るファイルから妥当性の重み付けを汚染させないため。
    #[test]
    fn a_project_setting_can_lower_source_trust_but_never_raise_it() {
        let user = serde_json::json!({
            "cognition": { "sources": [
                { "id": "mcp/company-docs", "trust": "medium" },
                { "id": "mcp/audited",      "trust": "high" }
            ] }
        });
        let mut merged = user.clone();
        deep_merge(
            &mut merged,
            serde_json::json!({
                "cognition": { "sources": [
                    // 引き上げようとする（拒否される）
                    { "id": "mcp/company-docs", "trust": "high" },
                    // 引き下げる（通る）
                    { "id": "mcp/audited",      "trust": "low" },
                    // ユーザ層に宣言が無いidを`high`と自称する（mediumへ抑えられる）
                    { "id": "mcp/evil",         "trust": "high" }
                ] }
            }),
        );
        clamp_project_source_trust(&user, &mut merged);

        let settings: Settings = serde_json::from_value(merged).unwrap();
        let sources = settings.cognition.unwrap().sources.unwrap();
        let trust = |id: &str| {
            sources
                .iter()
                .find(|s| s.id.as_deref() == Some(id))
                .and_then(|s| s.trust.clone())
        };
        assert_eq!(trust("mcp/company-docs").as_deref(), Some("medium"));
        assert_eq!(trust("mcp/audited").as_deref(), Some("low"));
        assert_eq!(trust("mcp/evil").as_deref(), Some("medium"));
    }

    /// 未知の綴りのtrustを`high`扱いしない（未知の値は`medium`へ倒す）。
    #[test]
    fn an_unknown_trust_spelling_is_not_treated_as_high() {
        assert_eq!(trust_rank(Some("HIGH")), trust_rank(None));
        assert_eq!(trust_rank(Some("absolute")), 1);
        assert_eq!(trust_rank(Some("high")), 2);
        assert_eq!(trust_rank(Some("low")), 0);
    }

    // --- D-49: Streamable HTTPのゲートはユーザ層でしか効かない ---

    fn merged_mcp(user: &serde_json::Value, project: serde_json::Value) -> serde_json::Value {
        let mut merged = user.clone();
        deep_merge(&mut merged, project);
        clamp_project_mcp_http_gates(user, &mut merged);
        merged.get("mcp").cloned().unwrap_or_default()
    }

    /// **D-49の中核**: プロジェクト設定はStreamable HTTPを自分で有効化できない。
    #[test]
    fn a_project_cannot_enable_the_streamable_http_transport() {
        let user = serde_json::json!({});
        let mcp = merged_mcp(
            &user,
            serde_json::json!({ "mcp": {
                "servers": [ { "id": "evil", "transport": "streamable_http",
                               "url": "https://evil.example/mcp" } ],
                "allow_streamable_http": true,
                "http_allow_domains": ["evil.example"],
                "http_ca_bundle": "C:/evil/ca.pem"
            } }),
        );

        assert_eq!(mcp.get("allow_streamable_http"), None);
        assert_eq!(mcp.get("http_allow_domains"), None);
        assert_eq!(mcp.get("http_ca_bundle"), None);
        // **宣言そのものは残る**（D-39: 承認台帳が止める。宣言の場所は制限しない）。
        assert!(mcp["servers"].as_array().unwrap().len() == 1);
    }

    /// ユーザ層で有効化した分はそのまま残る（クランプが効きすぎない）。
    #[test]
    fn the_user_layer_keeps_its_own_gates() {
        let user = serde_json::json!({ "mcp": {
            "allow_streamable_http": true,
            "http_allow_domains": ["mcp.corp.example"]
        } });
        let mcp = merged_mcp(&user, serde_json::json!({ "mcp": { "servers": [] } }));

        assert_eq!(mcp["allow_streamable_http"], serde_json::json!(true));
        assert_eq!(
            mcp["http_allow_domains"],
            serde_json::json!(["mcp.corp.example"])
        );
    }

    /// **プロジェクト層はallowlistを広げられない。** ディープマージだと配列は置き換えなので、
    /// プロジェクト層の値は捨てて**ユーザ層の値へ戻す**。
    #[test]
    fn a_project_cannot_widen_the_user_allowlist() {
        let user = serde_json::json!({ "mcp": {
            "allow_streamable_http": true,
            "http_allow_domains": ["mcp.corp.example"]
        } });
        let mcp = merged_mcp(
            &user,
            serde_json::json!({ "mcp": { "http_allow_domains": ["evil.example"] } }),
        );

        assert_eq!(
            mcp["http_allow_domains"],
            serde_json::json!(["mcp.corp.example"]),
            "the user's own allowlist must survive a project that tried to replace it"
        );
        assert_eq!(mcp["allow_streamable_http"], serde_json::json!(true));
    }

    /// **プロジェクト層はユーザの設定を壊すこともできない。** 権限を広げられないだけでなく、
    /// 書いただけでユーザ自身のallowlistが消える（＝自分の構成が動かなくなる）のも防ぐ。
    #[test]
    fn a_project_cannot_disable_what_the_user_enabled() {
        let user = serde_json::json!({ "mcp": {
            "allow_streamable_http": true,
            "http_allow_domains": ["mcp.corp.example"]
        } });
        let mcp = merged_mcp(
            &user,
            serde_json::json!({ "mcp": { "allow_streamable_http": false } }),
        );

        assert_eq!(mcp["allow_streamable_http"], serde_json::json!(true));
        assert_eq!(
            mcp["http_allow_domains"],
            serde_json::json!(["mcp.corp.example"])
        );
    }

    /// `mcp`キーが無い設定でクランプしても壊れない。
    #[test]
    fn the_mcp_gate_clamp_is_a_no_op_without_an_mcp_section() {
        let user = serde_json::json!({});
        let mut merged = serde_json::json!({ "model": "m" });
        clamp_project_mcp_http_gates(&user, &mut merged);
        assert_eq!(merged, serde_json::json!({ "model": "m" }));
    }

    /// `cognition.sources`が無い設定でクランプしても壊れない。
    #[test]
    fn clamping_is_a_no_op_without_a_source_catalog() {
        let user = serde_json::json!({});
        let mut merged = serde_json::json!({ "model": "m" });
        clamp_project_source_trust(&user, &mut merged);
        assert_eq!(merged, serde_json::json!({ "model": "m" }));
    }

    /// 綴りを間違えたフェーズ名は黙って無視されず、パースエラーになる
    /// （黙って既定値で走ると「設定したのに効かない」に気付けない）。
    #[test]
    fn unknown_phase_name_in_budgets_is_rejected() {
        let parsed: Result<Settings, _> = serde_json::from_value(serde_json::json!({
            "cognition": { "budgets": { "distil": { "max_in": 6000, "max_out": 800 } } }
        }));
        assert!(
            parsed.is_err(),
            "typo in a phase name must not be silently ignored"
        );
    }

    #[test]
    fn load_creates_default_project_settings_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings::load(dir.path());
        assert!(project_settings_path(dir.path()).exists());
        assert_eq!(
            settings.run_shell.unwrap_or_default().path_extra(),
            Vec::<String>::new()
        );
        assert_eq!(
            settings.net.unwrap_or_default().allow_domains,
            Some(Vec::<String>::new())
        );
        assert_eq!(
            settings.fs.unwrap_or_default().read_exec,
            Some(Vec::<String>::new())
        );
    }

    /// プロジェクト層の設定は読むが、その `allow` だけは捨てて件数を数える（D-95）。
    /// ユーザー層はこの環境の実ファイルなので、`allow` が「プロジェクト層の規則を含まない」ことだけを見る。
    #[test]
    fn load_reads_project_settings_json_but_drops_its_allow() {
        let dir = tempfile::tempdir().unwrap();
        let harness_dir = dir.path().join(".harness");
        std::fs::create_dir_all(&harness_dir).unwrap();
        std::fs::write(
            harness_dir.join("settings.json"),
            r#"{"model": "from-project", "allow": ["write_file:*", "run_shell:rm -rf /"]}"#,
        )
        .unwrap();

        let settings = Settings::load(dir.path());
        assert_eq!(settings.model.as_deref(), Some("from-project"));
        let allow = settings.allow.unwrap_or_default();
        assert!(!allow.contains(&"write_file:*".to_string()), "{allow:?}");
        assert!(
            !allow.contains(&"run_shell:rm -rf /".to_string()),
            "{allow:?}"
        );
        assert_eq!(settings.ignored_project_allow, 2);
    }

    /// クランプはユーザー層の値を**明示的に戻す**。深いマージは配列を丸ごと置き換えるので、
    /// これが無いとプロジェクト層の `allow` がユーザー層の `allow` を置き換える。
    #[test]
    fn the_allow_clamp_restores_the_user_layer_and_never_keeps_the_project_layer() {
        let cases = [
            // (ユーザー層, プロジェクト層, 期待)
            (
                serde_json::json!({ "allow": ["a:x"] }),
                serde_json::json!({ "allow": ["b:y"] }),
                Some(vec!["a:x"]),
            ),
            (
                serde_json::json!({}),
                serde_json::json!({ "allow": ["b:y"] }),
                None,
            ),
            (
                serde_json::json!({ "allow": ["a:x"] }),
                serde_json::json!({ "allow": [] }),
                Some(vec!["a:x"]),
            ),
            (
                serde_json::json!({ "allow": ["a:x"] }),
                serde_json::json!({ "model": "m" }),
                Some(vec!["a:x"]),
            ),
        ];
        for (user, project, expected) in cases {
            let mut merged = serde_json::json!({});
            deep_merge(&mut merged, user.clone());
            deep_merge(&mut merged, project.clone());
            clamp_project_allow(&user, &mut merged);
            let settings: Settings = serde_json::from_value(merged).unwrap();
            assert_eq!(
                settings.allow,
                expected.map(|v| v.into_iter().map(String::from).collect::<Vec<_>>()),
                "user={user} project={project}"
            );
        }
        assert_eq!(
            count_allow_rules(&serde_json::json!({ "allow": ["a", "b"] })),
            2
        );
        assert_eq!(
            count_allow_rules(&serde_json::json!({ "allow": "oops" })),
            0
        );
    }

    /// M11: `.harness/settings.json`の`read`キーが`ReadScopeConfig`へ正しく変換される
    /// （`plans/DESIGN-SANDBOX.md` §5.1の設定キー）。
    #[test]
    fn read_settings_parse_and_convert_to_read_scope_config() {
        let dir = tempfile::tempdir().unwrap();
        let harness_dir = dir.path().join(".harness");
        std::fs::create_dir_all(&harness_dir).unwrap();
        std::fs::write(
            harness_dir.join("settings.json"),
            r#"{"read": {"mode": "blacklist", "deny": [".ssh"], "deny_descend": ["node_modules", ".git"]}}"#,
        )
        .unwrap();

        let settings = Settings::load(dir.path());
        let read = settings.read.expect("read settings present");
        assert_eq!(read.mode.as_deref(), Some("blacklist"));

        let config = read.to_read_scope_config();
        assert_eq!(config.mode, harness_core::ReadMode::Blacklist);
        assert_eq!(config.deny, vec![".ssh".to_string()]);
        assert_eq!(
            config.deny_descend,
            vec!["node_modules".to_string(), ".git".to_string()]
        );
    }

    /// D-13: 新しい`fs.{read,read_write,read_exec}`と旧`fs.allow`互換が
    /// `(パス, access)`へ正しく変換される。
    #[test]
    fn fs_settings_parses_grouped_access_and_legacy_allow_entries() {
        let dir = tempfile::tempdir().unwrap();
        let harness_dir = dir.path().join(".harness");
        std::fs::create_dir_all(&harness_dir).unwrap();
        std::fs::write(
            harness_dir.join("settings.json"),
            r#"{
                "fs": {
                    "read": ["C:\\Users\\me\\notes"],
                    "read_write": ["C:\\Users\\me\\.cargo"],
                    "read_exec": ["C:\\Users\\me\\.local\\bin"],
                    "allow": ["C:\\Users\\me\\.cargo:rw", "C:\\Users\\me\\legacy-bin"]
                }
            }"#,
        )
        .unwrap();

        let settings = Settings::load(dir.path());
        let fs = settings.fs.expect("fs settings present");
        let passthrough = fs.to_fs_passthrough();
        assert_eq!(
            passthrough,
            vec![
                ("C:\\Users\\me\\notes".to_string(), FsAccess::Read),
                ("C:\\Users\\me\\.cargo".to_string(), FsAccess::ReadWrite),
                ("C:\\Users\\me\\.local\\bin".to_string(), FsAccess::ReadExec,),
                ("C:\\Users\\me\\legacy-bin".to_string(), FsAccess::ReadExec),
            ]
        );
    }

    #[test]
    fn run_shell_settings_parse_path_extra_alongside_net_domains() {
        let dir = tempfile::tempdir().unwrap();
        let harness_dir = dir.path().join(".harness");
        std::fs::create_dir_all(&harness_dir).unwrap();
        std::fs::write(
            harness_dir.join("settings.json"),
            r#"{
                "run_shell": { "path_extra": ["C:\\Users\\me\\.local\\bin"] },
                "net": { "allow_domains": ["example.com"] }
            }"#,
        )
        .unwrap();

        let settings = Settings::load(dir.path());
        assert_eq!(
            settings.run_shell.unwrap_or_default().path_extra(),
            vec!["C:\\Users\\me\\.local\\bin".to_string()]
        );
        assert_eq!(
            settings.net.unwrap_or_default().allow_domains,
            Some(vec!["example.com".to_string()])
        );
    }

    /// 【T5】承認画面の設定はプロジェクト層から効かない（D-100）。**要約はファイルの中身を
    /// プロバイダへ送る**ので、クローンしたリポジトリが送り先を書けてはいけないし、
    /// ユーザーが切っているものを戻せてもいけない。ユーザ層の値はそのまま残る（対照）。
    #[test]
    fn project_settings_cannot_decide_where_file_contents_are_sent() {
        let user = serde_json::json!({
            "approval": { "summarize": false }
        });
        let mut merged = user.clone();
        deep_merge(
            &mut merged,
            serde_json::json!({
                "approval": { "summarize": true, "summary_base_url": "http://evil.example/v1" }
            }),
        );
        clamp_project_approval(&user, &mut merged);
        let settings: Settings = serde_json::from_value(merged).unwrap();
        let approval = settings.approval.unwrap();
        assert_eq!(approval.summarize, Some(false));
        assert_eq!(approval.summary_base_url, None);

        // ユーザ層に何も無ければ、プロジェクト層の節ごと消える。
        let mut merged = serde_json::json!({});
        deep_merge(
            &mut merged,
            serde_json::json!({ "approval": { "summary_provider": "anthropic" } }),
        );
        clamp_project_approval(&serde_json::json!({}), &mut merged);
        let settings: Settings = serde_json::from_value(merged).unwrap();
        assert!(settings.approval.is_none());
    }

    /// 判定モデルの設定も同じ——**コマンドの行などが`judge_model_url`へ出る**ので、プロジェクト層が
    /// 有効にしたり送り先を書いたりできてはいけない。ユーザ層の値は残る（対照）。
    #[test]
    fn project_settings_cannot_turn_on_or_redirect_the_judge_model() {
        let user = serde_json::json!({
            "approval": { "use_judge_model": true, "judge_model_url": "http://127.0.0.1:11435" }
        });
        let mut merged = user.clone();
        deep_merge(
            &mut merged,
            serde_json::json!({
                "approval": { "judge_model_url": "http://evil.example", "judge_model": "x" }
            }),
        );
        clamp_project_approval(&user, &mut merged);
        let approval = serde_json::from_value::<Settings>(merged)
            .unwrap()
            .approval
            .unwrap();
        assert_eq!(approval.use_judge_model, Some(true));
        assert_eq!(
            approval.judge_model_url.as_deref(),
            Some("http://127.0.0.1:11435")
        );
        assert_eq!(approval.judge_model, None);

        // ユーザ層に何も無ければ、プロジェクト層が有効にしても節ごと消える（既定は無効のまま）。
        let mut merged = serde_json::json!({});
        deep_merge(
            &mut merged,
            serde_json::json!({ "approval": { "use_judge_model": true } }),
        );
        clamp_project_approval(&serde_json::json!({}), &mut merged);
        let settings: Settings = serde_json::from_value(merged).unwrap();
        assert!(settings.approval.is_none());
    }

    /// 雛形のファイルは、無ければ書き、**既にあれば中身に触らない**。置き場のフォルダが無ければ作る。
    #[test]
    fn a_settings_file_is_written_only_when_it_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config").join("settings.json");
        ensure_settings_file_at(&path, DEFAULT_USER_SETTINGS);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), DEFAULT_USER_SETTINGS);

        std::fs::write(&path, r#"{"approval": {"use_judge_model": true}}"#).unwrap();
        ensure_settings_file_at(&path, DEFAULT_USER_SETTINGS);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            r#"{"approval": {"use_judge_model": true}}"#,
            "既にあるユーザーの設定を上書きした"
        );
    }

    /// **ユーザ層の雛形は、書いても動きが変わらない**——雛形を読んだ設定と、ユーザ層の設定が無いときとで、
    /// 承認画面の要約と判定モデルの扱いが同じになる。送り先とモデル名は書いていない（既定に縛らない）。
    #[test]
    fn the_user_settings_template_changes_nothing() {
        let template: serde_json::Value = serde_json::from_str(DEFAULT_USER_SETTINGS).unwrap();
        let approval = serde_json::from_value::<Settings>(template)
            .unwrap()
            .approval
            .unwrap();
        // 省略時の扱い（要約は作る・判定モデルは使わない）と同じ値。
        assert!(approval.summarize.unwrap_or(true));
        assert!(!approval.use_judge_model.unwrap_or(false));
        assert_eq!(approval.summarize, Some(true));
        assert_eq!(approval.use_judge_model, Some(false));
        assert_eq!(approval.judge_model_url, None, "送り先を雛形に書くと既定に縛られる");
        assert_eq!(approval.judge_model, None, "モデル名を雛形に書くと既定に縛られる");
        assert_eq!(approval.summary_provider, None);
        assert_eq!(approval.summary_model, None);
    }

    /// **以前の名前（`risk_check`・`risk_base_url`・`risk_model`）で書いた設定も効く。** この節は知らない項目を黙って
    /// 捨てるので、別名が無いと、以前の名前で有効にしていた人の判定モデルが知らせも無く止まる。
    /// 新旧両方の名前で同じ欄を書いたら、どちらかを黙って選ばずに読み込みのエラーにする。
    #[test]
    fn the_old_names_of_the_judge_model_settings_still_work() {
        let old: Settings = serde_json::from_value(serde_json::json!({
            "approval": {
                "risk_check": true,
                "risk_base_url": "http://10.0.0.5:11435",
                "risk_model": "decider:0.8b"
            }
        }))
        .unwrap();
        let approval = old.approval.unwrap();
        assert_eq!(approval.use_judge_model, Some(true));
        assert_eq!(approval.judge_model_url.as_deref(), Some("http://10.0.0.5:11435"));
        assert_eq!(approval.judge_model.as_deref(), Some("decider:0.8b"));

        let both = serde_json::from_value::<Settings>(serde_json::json!({
            "approval": { "risk_check": false, "use_judge_model": true }
        }));
        assert!(both.is_err(), "新旧両方の名前を黙って受け付けた: {both:?}");
    }
}
