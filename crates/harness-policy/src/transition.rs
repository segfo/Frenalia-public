//! 遷移MACの宣言の形と、その宣言を読んで「この遷移を許すか」を答える判定器（段階⑥a）。
//!
//! # 何のためにあるのか
//!
//! サンドボックスの中のプログラムは、遷移MACが立つと**自分で子プロセスを起こせなくなる**。
//! 代わりに起こすのは信頼された常駐プロセス（Spawn Daemon）で、そのとき
//! 「**この呼び出し元が、この実行ファイルを、この引数で起こしてよいか**」を答える必要がある。
//! 本モジュールはその問いを答える純粋関数と、答えの材料になる宣言の形だけを持つ。
//!
//! 設計の正本は`plans/DESIGN-MAC.md` §4・§5.1・§19.1と
//! `plans/DESIGN-MAC-TRANSITION-POLICY.md` §19.3。
//!
//! # ここが持たないもの（限界を同じ場所に書く）
//!
//! - **強制しない。** 拒否を実際に返せるのはSpawn DaemonとOSカーネルだけで、本モジュールは
//!   その2つが読む答えを計算するだけである（`plans/DESIGN-MAC-PROTOCOL.md` §13:
//!   観測を判定の根拠にしない、と同じ分け方）
//! - **ファイルを読まない。** 入力は常に読み込み済みの値で受け取る（クレートのlib.rsの契約）。
//!   したがって「この固定値が指すファイルは本当に存在するか」は答えない
//! - **プロセスを起こさない。** 許可の答えが持つ`cwd`・env・ハンドル継承の指示を実行するのは
//!   Daemonの仕事である（段階6b）
//!
//! # 判定と編集時検査が同じ構築関数を通る
//!
//! [`TransitionGraph::build`]を通らなければ[`TransitionGraph`]は作れず、`build`は
//! 編集時検査（[`check_all`]と同じ規則）を必ず掛ける。**検査を通っていない宣言で
//! 判定できる経路が存在しない**——検査の呼び忘れを規律ではなく型で止めるためである
//! （`bug-pattern-rules` B-06の「数え上げなくてよくする機構へ倒す」）。

use std::collections::{BTreeMap, BTreeSet};

use harness_change_ledger::path_rules::fold_for_pattern_comparison;
use harness_config::FsAccess;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// 遷移先ドメイン名の長さ上限（`plans/DESIGN-MAC-TRANSITION-POLICY.md` §19.3.14）。
///
/// ドメイン名はAppContainerプロファイル名の接尾辞に入る。名前全体が64文字、接頭辞が12文字なので
/// 接尾辞は50文字である（`harness-sandbox`の`tier2a::mcp_profile`の`MAX_SUFFIX_LEN`が同じ値を持つ）。
///
/// **これは上限であって予算ではない。** 実際の接尾辞にはセッションを識別する部分も載るので、
/// **使える文字数はこれより少ない**。ここで50を見ているのは「確実に長すぎるもの」を
/// 編集時に落とすためで、通ったからといってプロファイルが作れる保証にはならない（P-11）。
pub const MAX_DOMAIN_NAME_LEN: usize = 50;

// ---------------------------------------------------------------------------
// 宣言の形（`policy.json`の`process`キー）
// ---------------------------------------------------------------------------

/// ドメイン1件の遷移宣言。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionRules {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transitions: Vec<TransitionEdge>,
}

impl TransitionRules {
    pub fn is_empty(&self) -> bool {
        self.transitions.is_empty()
    }
}

/// 辺1本。`(遷移元ドメイン, 実行ファイル, argv) → 遷移先ドメイン`の対応である（§4）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionEdge {
    pub exe: ExeMatcher,
    /// **省略できる形にしない。** `any`と書くか値を書くかを常に選ばせる（§5.1）。
    pub argv: ArgvMatcher,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// 遷移先ドメイン名。
    pub to: String,
    /// 環境変数の**差分**（§19.1）。既定値はセッションのbase envで、ここには差分だけ書く。
    ///
    /// **呼び出し元のenvを通す指定は書けない。** 名前単位の素通し一覧を作ると、
    /// §19.1が塞いだ穴が名前ごとに開き直る。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<EnvOverride>,
}

/// 実行ファイルの照合方法。`{"literal": …}` または `{"pattern": …}`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExeMatcher {
    Literal(String),
    Pattern(String),
}

/// argvの照合方法。`{"literal": …}` / `{"pattern": …}` / `{"any": true}`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgvMatcher {
    Literal(String),
    Pattern(String),
    /// 任意のargvを許す。**綴りは`{"any": true}`ただ1つ**（§5.1）。
    Any(AnyMarker),
}

/// `{"any": true}`の`true`だけを受ける印。
///
/// # なぜ`bool`そのものにしないのか
///
/// `{"any": false}`という**意味を持たない2つ目の綴り**が書けてしまうためである。
/// 同じ意味に2つの綴りがあると、片方だけを扱う経路が生まれる（§5.1(2)が`.*`を
/// 禁じたのと同じ理屈）。ここでは**読み込みの時点で落とす**ので、
/// 「後で検査する」を忘れる余地が無い。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnyMarker;

impl Serialize for AnyMarker {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for AnyMarker {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if bool::deserialize(deserializer)? {
            Ok(AnyMarker)
        } else {
            Err(serde::de::Error::custom(
                "\"any\" must be true; to declare that no argv matches, remove the edge instead",
            ))
        }
    }
}

/// 辺ごとの環境変数の差分。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvOverride {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub set: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unset: Vec<String>,
}

impl EnvOverride {
    pub fn is_empty(&self) -> bool {
        self.set.is_empty() && self.unset.is_empty()
    }
}

/// ポリシーエディタが書く辺の形: `exe`はリテラル（観測した綴りそのまま）、`cwd`と`env`は書かない。
///
/// **この形の持ち主はここ1か所である**（`B-05`）。エディタの遷移の承認（`harness_policy_editor`の
/// `transition_approve`）と位置ごとの割り当て（[`crate::position_domains::Assignment::edges_to_add`]）が
/// 両方これを呼ぶ——写すと、片方だけ`cwd`を書き始めたときに「同じ位置の辺なのに経路で形が違う」が起きる。
/// `cwd`を書かない理由は、観測に作業ディレクトリが無く、拒否側の作業ディレクトリは「ここでしか起こしては
/// いけない」という意思ではないためである（意思でないものを宣言へ書くと、別の場所から走らせたときに
/// 理由の分からない拒否になる）。環境変数の差分も書かない（既定はセッションのbase env、§19.1）。
pub fn editor_edge(exe: &str, argv: ArgvMatcher, to: &str) -> TransitionEdge {
    TransitionEdge {
        exe: ExeMatcher::Literal(exe.to_string()),
        argv,
        cwd: None,
        to: to.to_string(),
        env: None,
    }
}

// ---------------------------------------------------------------------------
// 判定器への入力
// ---------------------------------------------------------------------------

/// ドメイン1件の「見え方」。
///
/// # なぜ`PolicyFile`をそのまま受けないのか
///
/// `policy.json`の型は`harness-policy-editor`にあり、そのクレートは`harness-sandbox`に
/// 依存している。判定器は**Spawn Daemon（`harness-sandbox`側）からも呼ばれる**ので、
/// あちらの型をここで受けると依存が循環する。見え方だけを受けることで、
/// 同じ判定器を編集側とDaemon側の両方が通れる（判定を2つ書かない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainView<'a> {
    pub name: &'a str,
    /// このドメインが宣言しているFSの`(値, access)`。
    pub fs: Vec<(&'a str, FsAccess)>,
    /// このドメインが宣言している通信先。
    pub net: Vec<&'a str>,
    pub process: &'a TransitionRules,
}

/// 検査・構築の入力一式。
#[derive(Debug, Clone, Default)]
pub struct GraphInput<'a> {
    pub domains: Vec<DomainView<'a>>,
    /// **呼び出し元が書ける場所**として、宣言の外から分かっているもの。
    ///
    /// §19.1の「固定値が指すファイルが呼び出し元から書けない場所にあること」を検査するのに使う。
    /// 宣言だけを見ると**ワークスペース**と、**`policy.json`の外で書込を許した場所**
    /// （`settings.json`の`fs.read_write`・`--fs-allow <path>:rw`）が抜けるので、
    /// 呼び出し側が明示的に渡す。組み立ては`PolicyFile::transition_graph_input`が持つ。
    /// 渡さなければその範囲は検査されない（P-11: 見ていないものは見ていないと書く）。
    ///
    /// **全ドメインへ一律に効く。** `--fs-allow`の穴を持つのは入口のドメインだけだが、
    /// 入口のコードが書き換えたファイルを別ドメインの固定した遷移が読むので、
    /// 呼び出し元がどのドメインかで分けない。
    pub caller_writable_roots: Vec<&'a str>,
}

// ---------------------------------------------------------------------------
// 検査の結果
// ---------------------------------------------------------------------------

/// 編集時検査で落ちた辺1本。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub domain: String,
    /// そのドメインの`transitions`配列の添字。**辺の内容ではなく位置で指す**——
    /// 同じ内容の辺が2本あっても、どちらを直せばよいかが分かるようにするため。
    pub edge_index: usize,
    pub reason: String,
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "domain {:?} transition #{}: {}",
            self.domain, self.edge_index, self.reason
        )
    }
}

/// 宣言の外形（グラフを組む前に分かること）が壊れている。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    /// 同じ名前のドメインが2件以上ある。
    DuplicateDomain(String),
    /// 1本以上の辺が編集時検査で落ちた。
    RejectedEdges(Vec<Rejection>),
}

impl std::fmt::Display for GraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GraphError::DuplicateDomain(name) => {
                write!(f, "domain {name:?} is declared more than once")
            }
            GraphError::RejectedEdges(rejections) => {
                let joined: Vec<String> = rejections.iter().map(|r| r.to_string()).collect();
                write!(f, "{}", joined.join("; "))
            }
        }
    }
}

impl std::error::Error for GraphError {}

// ---------------------------------------------------------------------------
// 向きと、固定されているか
// ---------------------------------------------------------------------------

/// 遷移の向き（§19.1）。
///
/// # 比べるのは「その辺が無かったとしたら」である
///
/// 有効権限は到達閉包で数える（§19.3.4）が、**判定する当の辺を含んだまま比べてはならない**。
/// 含めると遷移元の閉包が遷移先の閉包を必ず飲み込むので、**どんな辺も「狭める」に見える**
/// ——検査が常に通る、つまり何も検査していないのと同じになる。
///
/// したがって遷移元の側は**その辺を取り除いたグラフ**で数える。問いは
/// 「**この辺を足すと、遷移元は新しく何かへ手が届くようになるか**」である。
/// §19.1が挙げる中継ドメインの罠（FSは狭いが広いドメインへの辺を持つドメインを1枚挟む）は、
/// この数え方で落ちる——中継の閉包には広い権限が入っているからである。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// 遷移先＝遷移元。**既定でそのまま許可してよい**（§19.1の1行目）。
    Same,
    /// 遷移先の有効権限が遷移元の有効権限に含まれることを**証明できた**。
    Narrower,
    /// 広げる、または**証明できなかった**。§19.1の3行目はこの2つを同じ扱いにしている
    /// ——判定できないものを「広げない」側へ倒すと、実装時に無言のfail-openになるためである。
    WiderOrUnknown,
}

/// Daemonが子へ渡すenvの決め方（§19.1の表）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvPolicy {
    /// 呼び出し元のenvをそのまま通す（`argv: any`かつ狭める／同値の辺だけ）。
    PassThrough,
    /// セッションのbase envへ、この辺の差分を当てたものを渡す。
    ///
    /// **呼び出し元のenvは1つも載らない。** 差分が空でも意味は変わらない
    /// （「base envそのもの」である）。
    Fixed(EnvOverride),
}

// ---------------------------------------------------------------------------
// 判定の答え
// ---------------------------------------------------------------------------

/// 許可したときに、Daemonが従うべき指示一式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowed<'a> {
    pub to: &'a str,
    /// `lpCurrentDirectory`へ渡す値。`None`なら呼び出し元の実cwdをそのまま渡す
    /// （§8.3。cwd宣言が要らない辺は定義から「狭める／同値」で、詐称して得られる権限が無い）。
    pub cwd: Option<&'a str>,
    pub env: &'a EnvPolicy,
    /// 呼び出し元のハンドル（stdioを含む）を引き継がせてよいか。
    ///
    /// **`false`なら、Daemonは自分で作ったもの以外を1つも渡してはならない**（§19.1）。
    /// stdinも同様に断つ——固定argvのシェルは、stdinが端末でなければそこからコマンドを読む。
    ///
    /// # 誰が従うのか（**2026-09-20まで誰も従っていなかった**）
    ///
    /// `harness_sandbox::tier2a::spawnd::server::serve_spawn_request`が唯一の読み手で、
    /// `false`なら`CallerHandles::default()`へ差し替えてから子を起こす。
    ///
    /// **この欄は2026-09-17に入ったが、読み手は2026-09-20まで存在しなかった**
    /// （[BUG-161](../../../docs/bugs/BUG-161.md)）。計算されていることと効いていることは
    /// 別の事実で、**判定器側のテストはどちらも緑にする**。再発を止めているのは読み手側の
    /// 完全分解（`..`を書かない）で、欄が増えるとあちらがコンパイルできなくなる。
    pub inherit_handles: bool,
    pub direction: Direction,
    /// **固定辺か**（argvがリテラルで、cwdが宣言されている。`is_fully_fixed`）。
    ///
    /// 真なら、Daemonは起こす直前に「固定したファイルを呼び出し元が書き換えられないか」を
    /// 呼び出し元のトークンでOSに聞く（`plans/DESIGN-MAC.md` §19.1）。読み込み時の検査は
    /// 綴りで比べるので別名（8.3形式の短い名前・リンク・ハードリンク）に弱く、それを実体の側で補う。
    ///
    /// # なぜ`inherit_handles`から読み取らせないのか
    ///
    /// 今は「`inherit_handles == false` ⇔ 固定辺」が成り立つが、それは編集時検査が
    /// 「広げる辺は固定必須」を課している**結果**であって、型が保証していない。
    /// 読み手が裏の事情に頼ると、検査の規則が変わった日に黙って外れる。
    pub fixed: bool,
}

/// 拒否の理由。**「拒否された」だけでは、宣言が無いのか曖昧なのかが区別できない。**
///
/// # なぜserdeが要るのか（2026-09-12、段階6b）
///
/// この値は**Spawn Daemonから要求元のサンドボックスへ、要求受付パイプで返る**
/// （`harness_sandbox::tier2a::spawnd::DenyReason::Transition`）。拒否の語彙を電文側に
/// もう1つ作ると、判定器が増やした理由が電文側へ届かないまま片方だけ古くなる（`B-13`）。
/// **判定器の答えをそのまま運ぶ。**
///
/// # 要求元へ何を見せているか
///
/// [`TransitionDenial::CwdMismatch`]だけが宣言の中身（宣言された`cwd`）を含む。
/// **これは要求元自身のドメインの辺に書かれた値**なので、他のドメインの宣言は漏れない
/// ——`policy.json`そのものはサンドボックスから読めない（P-08）が、
/// 「自分がどう宣言されているか」は、拒否の理由として返らないと直しようがない。
/// # `Hash`を導出している理由（2026-09-12、段階6c）
///
/// 拒否の待ち行列（`plans/DESIGN-MAC-ENFORCEMENT.md` §10.2）は「拒否1件に1行」ではなく
/// **種類ごとに1行**へ畳む。その種類の鍵に理由そのものが入るので、理由が
/// `HashMap`の鍵になれる必要がある。**畳む単位を文字列にしない**のは、
/// 文字列へ潰した瞬間に「宣言が無いのか、cwdが違うのか」が鍵の中で見分けられなくなり、
/// 別々の直し方を要する拒否が1行にまとまってしまうからである。
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TransitionDenial {
    /// 呼び出し元のドメインがグラフに無い。
    UnknownSourceDomain,
    /// 一致する辺が無い（未宣言＝DENY）。
    NoMatchingEdge,
    /// パターンの辺が2本以上一致した（§19.3.9の規則2。どちらの権限を与えるか決められない）。
    AmbiguousPattern { matched: usize },
    /// 辺は一致したが、呼び出し元の実cwdが宣言と違う（§8.3の2番目）。
    CwdMismatch { declared: String, actual: String },
}

impl TransitionDenial {
    /// 診断用の短い説明。**ユーザーへ出す文面ではない**（画面の文言は呼び出し側が持つ）。
    pub fn as_str(&self) -> &'static str {
        match self {
            TransitionDenial::UnknownSourceDomain => "caller domain is not declared",
            TransitionDenial::NoMatchingEdge => "no declared transition matches",
            TransitionDenial::AmbiguousPattern { .. } => "more than one pattern edge matches",
            TransitionDenial::CwdMismatch { .. } => "caller cwd differs from the declared cwd",
        }
    }
}

/// [`TransitionGraph::resolve`]の答え。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution<'a> {
    Allowed(Allowed<'a>),
    Denied(TransitionDenial),
}

impl Resolution<'_> {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Resolution::Allowed(_))
    }
}

/// 1回の遷移要求（Daemonが受け取った要求を畳み込む前の形）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpawnAttempt<'a> {
    pub from_domain: &'a str,
    /// 実行ファイルのフルパス。
    pub exe: &'a str,
    /// **`CreateProcess`へ渡す生のコマンドライン文字列**（§5.1(3)）。
    /// パス解決はしない——Windowsに`argv`という実体は無く、Daemonが持つのも単一の文字列である。
    pub command_line: &'a str,
    /// 呼び出し元の実cwd。
    pub cwd: &'a str,
}

// ---------------------------------------------------------------------------
// 畳んだグラフ
// ---------------------------------------------------------------------------

/// 検査を通った宣言から組んだ、判定できる形のグラフ。
#[derive(Debug)]
pub struct TransitionGraph {
    domains: BTreeMap<String, CompiledDomain>,
}

#[derive(Debug)]
struct CompiledDomain {
    edges: Vec<CompiledEdge>,
}

#[derive(Debug)]
struct CompiledEdge {
    exe: CompiledMatcher,
    argv: CompiledMatcher,
    cwd: Option<String>,
    to: String,
    env: EnvPolicy,
    direction: Direction,
    inherit_handles: bool,
    fixed: bool,
}

#[derive(Debug)]
enum CompiledMatcher {
    /// 畳み込み済みの綴り。
    Literal(String),
    Pattern(Regex),
    Any,
}

impl CompiledMatcher {
    fn matches(&self, folded_input: &str) -> bool {
        match self {
            CompiledMatcher::Literal(value) => value == folded_input,
            CompiledMatcher::Pattern(re) => re.is_match(folded_input),
            CompiledMatcher::Any => true,
        }
    }

    fn is_literal(&self) -> bool {
        matches!(self, CompiledMatcher::Literal(_))
    }
}

impl TransitionGraph {
    /// 宣言を検査し、通ったら判定できる形へ畳む。
    ///
    /// **落ちた辺が1本でもあれば、グラフは作られない**（部分的に有効なグラフを返さない）。
    /// 一部だけ有効にすると、「拒否されたはずの辺が効いていない」状態と
    /// 「そもそも宣言していない」状態が区別できなくなる。
    pub fn build(input: &GraphInput<'_>) -> Result<Self, GraphError> {
        let facts = GraphFacts::new(input)?;
        let rejections = facts.check_all();
        if !rejections.is_empty() {
            return Err(GraphError::RejectedEdges(rejections));
        }

        let mut domains = BTreeMap::new();
        for view in &input.domains {
            let mut edges = Vec::with_capacity(view.process.transitions.len());
            for (edge_index, edge) in view.process.transitions.iter().enumerate() {
                let direction = facts.direction(view.name, edge_index, &edge.to);
                let fixed = is_fully_fixed(edge);
                edges.push(CompiledEdge {
                    // `compile_matcher`は検査が通った後にしか呼ばれないので、
                    // ここでの失敗は起こり得ない（起きたら検査とコンパイルがずれている）。
                    exe: compile_exe(&edge.exe).expect("checked above"),
                    argv: compile_argv(&edge.argv).expect("checked above"),
                    cwd: edge.cwd.as_ref().map(|c| fold_for_pattern_comparison(c)),
                    to: edge.to.clone(),
                    env: env_policy(edge),
                    direction,
                    inherit_handles: !fixed && direction != Direction::WiderOrUnknown,
                    fixed,
                });
            }
            domains.insert(view.name.to_string(), CompiledDomain { edges });
        }
        Ok(Self { domains })
    }

    /// この要求を許すか（§19.3.9の2段の解決規則）。
    ///
    /// 1. リテラル完全一致の辺があればそれを使う（定義から1本に定まる）
    /// 2. 無ければパターンの辺。**2本以上一致したら拒否する**（どちらの権限を与えるべきか
    ///    決められないため。fail-closed）
    /// 3. 一致が無ければ拒否（未宣言＝DENY）
    ///
    /// **入力の畳み込みはこの関数が行う**（B-20: 判定関数が自分で正規化する）。
    /// 呼び出し側で畳んでから渡す形にすると、畳まずに呼ぶ経路がいつか生える。
    pub fn resolve(&self, attempt: SpawnAttempt<'_>) -> Resolution<'_> {
        let Some(domain) = self.domains.get(attempt.from_domain) else {
            return Resolution::Denied(TransitionDenial::UnknownSourceDomain);
        };
        let exe = fold_for_pattern_comparison(attempt.exe);
        let command_line = fold_for_pattern_comparison(attempt.command_line);

        let matched: Vec<&CompiledEdge> = domain
            .edges
            .iter()
            .filter(|edge| edge.exe.matches(&exe) && edge.argv.matches(&command_line))
            .collect();

        // 段1: リテラル完全一致（exe・argvとも）が在ればそれ。
        let literal: Vec<&&CompiledEdge> = matched
            .iter()
            .filter(|edge| edge.exe.is_literal() && edge.argv.is_literal())
            .collect();
        let chosen = match literal.len() {
            1 => literal[0],
            // 同一のリテラル辺が2本ある形は`check_all`が落とすので、ここへは来ない。
            // 来たら曖昧として扱う——`expect`で落とさないのは、Daemonの中で走るためである
            // （判定器のpanicは、拒否ではなく生成の窓口ごと失われることを意味する）。
            0 => match matched.len() {
                0 => return Resolution::Denied(TransitionDenial::NoMatchingEdge),
                1 => matched[0],
                n => return Resolution::Denied(TransitionDenial::AmbiguousPattern { matched: n }),
            },
            n => return Resolution::Denied(TransitionDenial::AmbiguousPattern { matched: n }),
        };

        // §8.3の2番目: 宣言した`cwd`と呼び出し元の実cwdが違えば拒否する。
        // **渡すだけでは足りない**——無言で別のcwdへすり替えると「頼んだのと違うものが走った」
        // になる（成功に見える失敗を作らない）。
        if let Some(declared) = &chosen.cwd {
            let actual = fold_for_pattern_comparison(attempt.cwd);
            if declared != &actual {
                return Resolution::Denied(TransitionDenial::CwdMismatch {
                    declared: declared.clone(),
                    actual,
                });
            }
        }

        Resolution::Allowed(Allowed {
            to: &chosen.to,
            cwd: chosen.cwd.as_deref(),
            env: &chosen.env,
            inherit_handles: chosen.inherit_handles,
            direction: chosen.direction,
            fixed: chosen.fixed,
        })
    }

    /// 宣言されているドメイン名（診断・表示用）。
    pub fn domain_names(&self) -> impl Iterator<Item = &str> + '_ {
        self.domains.keys().map(|s| s.as_str())
    }
}

// ---------------------------------------------------------------------------
// 編集時検査
// ---------------------------------------------------------------------------

/// 宣言を検査する（グラフを組まずに、落ちた辺の一覧だけが欲しいとき）。
///
/// **[`TransitionGraph::build`]と同じ規則を通る**——`build`がこの関数を内部で呼ぶので、
/// 2つの規則が分かれることがない（`bug-pattern-rules` B-05）。
pub fn check_all(input: &GraphInput<'_>) -> Result<Vec<Rejection>, GraphError> {
    Ok(GraphFacts::new(input)?.check_all())
}

/// `from`の`edge_index`番目の辺の向き（§19.1・§19.3.4）。**検査に落ちる宣言でも答える**
/// （[`TransitionGraph::build`]を通さない）。辺が無ければ`None`。
///
/// 検査に落ちた理由を**人へ説明し直す**ために使う——ポリシーエディタは作業ディレクトリを宣言しない
/// ので、「広げる遷移は固定が要る」と言われても直しようが無く、別の言い方が要る。
/// **向きの規則はここで書かない。** [`GraphFacts::direction`]ただ1つを呼ぶ（`B-13`）。
pub fn edge_direction(
    input: &GraphInput<'_>,
    from: &str,
    edge_index: usize,
) -> Result<Option<Direction>, GraphError> {
    let facts = GraphFacts::new(input)?;
    let Some(edge) = input
        .domains
        .iter()
        .find(|d| d.name == from)
        .and_then(|view| view.process.transitions.get(edge_index))
    else {
        return Ok(None);
    };
    Ok(Some(facts.direction(from, edge_index, &edge.to)))
}

/// 固定辺で**固定したファイル**（起こす実行ファイルと、`argv[0]`以降の絶対パスらしいトークン）を、
/// 書かれた綴りのまま返す。
///
/// Daemonは固定辺の子を起こす直前に、これらを**実際に`CreateProcessW`へ渡す値**
/// （要求された実行ファイルとコマンドライン）から取り、呼び出し元のトークンで
/// 書き換えられないかをOSに聞く（[`Allowed::fixed`]）。読み込み時の検査も同じ関数で
/// 候補を集めるので、2層の検査が別のファイルを見ることはない。
pub fn fixed_file_paths(image: &str, command_line: &str) -> Vec<String> {
    transition_check::fixed_file_paths(image, command_line)
}

/// [段階6e] `domain`から**到達できる範囲**の権限（§19.3.4の到達閉包）。
///
/// # なぜ直接の宣言では足りないのか
///
/// 問いが「このドメインへ遷移すると何ができるようになるか」だからである。
/// そのドメインが宣言しているものだけを見ると、**そこから先へ渡っていける範囲が抜ける**
/// ——中継を1枚挟んで広い権限へ届く形が、まさに§19.3.4が閉包で数えると決めた理由である。
///
/// **閉包の計算はここで書かない。** 向きの判定（[`GraphFacts::direction`]）が使っているものを
/// そのまま呼ぶ——2つ書くと、片方だけ直したときに「編集時に落ちる辺」と
/// 「モデルへ見せる要約」が食い違う（`B-13`）。
///
/// 宣言されていないドメイン名には**空の権限**を返す（`Err`にしない）。到達先が未宣言でも
/// 一覧そのものは作れる必要があり、その行の要約が空であることは正しい事実である。
pub fn rights_summary(
    input: &GraphInput<'_>,
    domain: &str,
) -> Result<crate::transition_listing::Rights, GraphError> {
    let facts = GraphFacts::new(input)?;
    Ok(facts.rights_of(facts.reachable_from(domain, None)).listed())
}

/// 検査と向きの判定が共有する、グラフから導かれる事実。
struct GraphFacts<'a> {
    input: &'a GraphInput<'a>,
    by_name: BTreeMap<&'a str, &'a DomainView<'a>>,
}

/// 有効権限。**辺ごとではなく、到達可能な全ドメインの権限の和**である（§19.3.4）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Rights<'a> {
    fs: BTreeSet<(&'a str, FsAccess)>,
    net: BTreeSet<String>,
}

impl Rights<'_> {
    /// 表示とモデル向けの形（[`crate::transition_listing::Rights`]）へ。**並べ方はここ1か所**
    /// ——[`rights_summary`]と[`newly_usable`]が同じ綴り（設定キー名）・同じ順で並べる。
    fn listed(self) -> crate::transition_listing::Rights {
        crate::transition_listing::Rights {
            fs: self
                .fs
                .into_iter()
                .map(|(value, access)| (value.to_string(), access.settings_key()))
                .collect(),
            net: self.net.into_iter().collect(),
        }
    }
}

impl<'a> GraphFacts<'a> {
    fn new(input: &'a GraphInput<'a>) -> Result<Self, GraphError> {
        let mut by_name: BTreeMap<&str, &DomainView<'_>> = BTreeMap::new();
        for view in &input.domains {
            if by_name.insert(view.name, view).is_some() {
                return Err(GraphError::DuplicateDomain(view.name.to_string()));
            }
        }
        Ok(Self { input, by_name })
    }

    /// `from`の`edge_index`番目の辺が向いている向き（§19.1・§19.3.4）。
    ///
    /// 遷移元の側は**その辺を取り除いて**数える（[`Direction`]のdoc）。
    fn direction(&self, from: &str, edge_index: usize, to: &str) -> Direction {
        if from == to {
            return Direction::Same;
        }
        if !self.by_name.contains_key(from) || !self.by_name.contains_key(to) {
            // 片方が宣言されていないなら証明できない。**保守側へ倒す**（§19.1の3行目）。
            return Direction::WiderOrUnknown;
        }
        let from_rights = self.rights_of(self.reachable_from(from, Some((from, edge_index))));
        let to_rights = self.rights_of(self.reachable_from(to, None));
        if rights_contained(&to_rights, &from_rights) {
            Direction::Narrower
        } else {
            Direction::WiderOrUnknown
        }
    }

    /// `start`から辿れるドメインの集合（自分自身を含む）。
    ///
    /// **固定辺は辿らない**（[`is_fully_fixed`]のdoc）。**閉路があっても止まる**——
    /// 訪問済みを持つ素朴な深さ優先探索なので、§19.3.2のcollapse（自己ループ辺）を
    /// 禁じる必要が無い（§19.3.1の限定詞）。
    ///
    /// `skip`は「この辺だけ無かったことにする」指定で、向きの判定に使う。
    fn reachable_from(&self, start: &str, skip: Option<(&str, usize)>) -> BTreeSet<&'a str> {
        let mut seen: BTreeSet<&'a str> = BTreeSet::new();
        let mut stack: Vec<&'a str> = Vec::new();
        if let Some((name, _)) = self.by_name.get_key_value(start) {
            stack.push(name);
        }
        while let Some(current) = stack.pop() {
            if !seen.insert(current) {
                continue;
            }
            let Some(view) = self.by_name.get(current) else {
                continue;
            };
            for (index, edge) in view.process.transitions.iter().enumerate() {
                if skip == Some((current, index)) || is_fully_fixed(edge) {
                    continue;
                }
                if let Some((target, _)) = self.by_name.get_key_value(edge.to.as_str()) {
                    stack.push(target);
                }
            }
        }
        seen
    }

    /// ドメイン集合が持つ権限の和（§19.3.4「到達可能な全ドメインの権限の和」）。
    fn rights_of(&self, members: BTreeSet<&'a str>) -> Rights<'a> {
        let mut rights = Rights::default();
        for member in members {
            let Some(view) = self.by_name.get(member) else {
                continue;
            };
            for (value, access) in &view.fs {
                rights.fs.insert((*value, *access));
            }
            for domain in &view.net {
                rights.net.insert(domain.to_ascii_lowercase());
            }
        }
        rights
    }
}

/// `inner ⊆ outer` を**証明できたか**。証明できないときは`false`（§19.1の3行目）。
fn rights_contained(inner: &Rights<'_>, outer: &Rights<'_>) -> bool {
    inner.net.iter().all(|d| outer.net.contains(d))
        && inner
            .fs
            .iter()
            .all(|needed| outer.fs.iter().any(|granted| fs_covers(granted, needed)))
}

/// `granted`が`needed`を覆うか。**覆うと証明できるときだけ`true`**。
fn fs_covers(granted: &(&str, FsAccess), needed: &(&str, FsAccess)) -> bool {
    if !access_at_least(granted.1, needed.1) {
        return false;
    }
    let granted_value = fold_for_pattern_comparison(granted.0);
    let needed_value = fold_for_pattern_comparison(needed.0);
    if granted_value == needed_value {
        return true;
    }
    // 再帰宣言（`**`）だけが部分木を覆う。それ以外のワイルドカードは、
    // 覆う範囲を機械的に決められないので**覆っていない扱い**にする（保守側へ倒す）。
    if !crate::normalize::declared_scope(granted.0).is_recursive() {
        return false;
    }
    if needed_value.contains('*') {
        // 覆われる側にワイルドカードが残っていると、前方一致だけでは包含を示せない。
        return false;
    }
    path_covered_by(
        &fold_for_pattern_comparison(crate::normalize::literal_prefix(granted.0)),
        &needed_value,
    )
}

/// アクセスの強さ。`read < read_exec` / `read < read_write`で、後2者は互いに比較不能である
/// （`insufficient::wider`が同じ順序を持つ。**そちらが正本**）。
fn access_at_least(granted: FsAccess, needed: FsAccess) -> bool {
    match needed {
        FsAccess::Read => true,
        FsAccess::ReadExec => granted == FsAccess::ReadExec,
        FsAccess::ReadWrite => granted == FsAccess::ReadWrite,
    }
}

/// 畳み込み済みの`root`が、畳み込み済みの`path`を覆うか。
///
/// 覆うかどうかの規則は[`crate::insufficient::covers`]が唯一の正本である（B-05）。
fn path_covered_by(root: &str, path: &str) -> bool {
    crate::insufficient::covers(root, path)
}

// ---------------------------------------------------------------------------
// 辺そのものの性質
// ---------------------------------------------------------------------------

/// 呼び出し元支配の入力が**全部**固定されている辺か。
///
/// # なぜ構文だけで決めるのか
///
/// §19.1は「広げる遷移は固定を必須にする」と定め、§19.3.4は「固定辺は到達閉包から除外する」と
/// 定めている。**この2つを素直に読むと循環する**——向きを知るには閉包が要り、閉包を計算するには
/// どの辺が固定かを知る必要がある。
///
/// **循環を断つために、固定は構文だけで決める**（argvがリテラルで、cwdが宣言されている）。
/// そのうえで、**この条件を満たす辺は向きに関わらずstdinと継承ハンドルも断つ**
/// （[`Allowed::inherit_handles`]が`false`になる）。
///
/// **断たないと閉包の除外が不健全になる**——呼び出し元がstdinでコードを渡せるなら、
/// その辺は権限を受け渡しているので数えなければならない。
///
/// **代償**: 狭める辺でもリテラルargvを書いた瞬間にstdioの引き継ぎが消える。
/// 逃げ道は`argv: any`の辺で、粒度と引き継ぎのどちらを取るかをユーザーが選べる
/// （§19.1が「逃げ道は`argv: any`の辺」と書いているのと同じ形）。
fn is_fully_fixed(edge: &TransitionEdge) -> bool {
    matches!(edge.argv, ArgvMatcher::Literal(_)) && edge.cwd.is_some()
}

/// この辺でDaemonが子へ渡すenvの決め方（§19.1の表）。
fn env_policy(edge: &TransitionEdge) -> EnvPolicy {
    // argvを選択子に使う辺では、向きを問わずenvもポリシー側の値にする——argvだけ照合して
    // envを通すと、同じargvのまま別のコードが走る（`PYTHONSTARTUP`等）。
    match edge.argv {
        ArgvMatcher::Any(_) => EnvPolicy::PassThrough,
        ArgvMatcher::Literal(_) | ArgvMatcher::Pattern(_) => {
            EnvPolicy::Fixed(edge.env.clone().unwrap_or_default())
        }
    }
}

// ---------------------------------------------------------------------------
// パターンのコンパイル
// ---------------------------------------------------------------------------

/// 完全一致に固定してからコンパイルする（§22.5）。
///
/// `regex`の既定は部分一致なので、`c:/x`が`z:/evil/c:/x`に当たってしまう。
/// **非捕獲グループで包む**ので、書き手が`^`や`$`を書いていても壊れない。
fn build_anchored(pattern: &str) -> Result<Regex, regex::Error> {
    Regex::new(&format!("^(?:{pattern})$"))
}

fn compile_exe(matcher: &ExeMatcher) -> Result<CompiledMatcher, regex::Error> {
    Ok(match matcher {
        ExeMatcher::Literal(value) => CompiledMatcher::Literal(fold_for_pattern_comparison(value)),
        ExeMatcher::Pattern(pattern) => CompiledMatcher::Pattern(build_anchored(pattern)?),
    })
}

fn compile_argv(matcher: &ArgvMatcher) -> Result<CompiledMatcher, regex::Error> {
    Ok(match matcher {
        ArgvMatcher::Literal(value) => CompiledMatcher::Literal(fold_for_pattern_comparison(value)),
        ArgvMatcher::Pattern(pattern) => CompiledMatcher::Pattern(build_anchored(pattern)?),
        ArgvMatcher::Any(_) => CompiledMatcher::Any,
    })
}

/// 編集時検査（[`check_all`]の本体と、綴りを見る関数群）。
#[path = "transition_check.rs"]
mod transition_check;

/// 1つのドメインから見た遷移の形（届く範囲の権限・起動で届くドメイン・最長の連鎖）と、自己ループ辺の一覧
/// （ポリシーエディタの宣言画面の遷移タブ、`plans/PLAN-POLICY-EDITOR-POSITION-DOMAINS.md` の P4.2）。
/// **検査に落ちる宣言でも答える**（[`rights_summary`]・[`edge_direction`]と同じ）。
#[path = "transition_shape.rs"]
mod transition_shape;
pub use transition_shape::{self_loops, shape, LongestChain, SelfLoop, TransitionShape};

/// 遷移で呼び出し元が子を通して新しく使えるようになる権限と、ポリシーの書き方で生じる組み合わせの対
/// （決定66。`plans/position-domains/P5.md` の P5.2）。**検査に落ちる宣言でも答える**（[`shape`]と同じ）。
#[path = "transition_exposure.rs"]
mod transition_exposure;
pub use transition_exposure::{
    exposure_delta, newly_usable, provisional_net_capable, CombinationPair, EdgeExposure,
    ExposureDelta, PairUse,
};

#[cfg(test)]
#[path = "transition_tests.rs"]
mod transition_tests;
