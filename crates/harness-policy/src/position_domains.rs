//! 記録したプロセスの木（`process-audit.jsonl`）の**位置ごとに遷移先のドメインを割り当て**、
//! ファイル操作（`fs-audit.jsonl`）をドメインへ振り分ける（`plans/POLICY-EDITOR-TOMOYO-DIG.md` 決定65(1)、
//! 分配の規則は`plans/DESIGN-MAC-TRANSITION-POLICY.md` §19.3.14。手順は`plans/position-domains/P3.md` Task 4）。
//!
//! # 何のためにあるのか
//!
//! ユーザーが示したルール（決定65）は、記録した連鎖だけを通し、記録に無い連鎖を断ることである。
//!
//! ```text
//! 記録:   cmd(入口のドメイン) → pwsh(ドメイン2) → calc(ドメイン3)
//!         cmd(入口のドメイン) → pwsh(ドメイン2) → mspaint(ドメイン4)
//! 通る:   cmd→pwsh→calc / cmd→pwsh→mspaint
//! 断る:   cmd→cmd→calc / cmd→pwsh→pwsh / cmd→cmd→notepad
//! ```
//!
//! そのためには、木の位置（どのドメインから、どの実行ファイルを起こしたか）ごとに別の遷移先を持たせ、
//! 辺を「（遷移元のドメイン, 実行ファイル）→ 遷移先」で書けばよい。本モジュールはその割り当てを計算する
//! （[`assign_domains`]）。あわせて、各ドメインが**自分のインスタンスが触った分だけ**を持つように
//! ファイル操作を分ける（[`partition_fs`]。決定65(5)、子孫の分を親へ足さない）。
//!
//! # 書かない（D-42）
//!
//! 答えは値で返すだけで、辺を`policy.json`へ書くのはポリシーエディタ（P4.5）である。監査の記録が
//! 権限の付与を自動で動かすと、記録の正しさがそのまま境界の正しさになる（クレートの`lib.rs`のdoc）。
//! エディタが書く形は[`Assignment::edges_to_add`]・[`Assignment::domains_to_add`]が作る。
//!
//! # 判定はSpawn Daemonと同じ判定器だけを通る（`B-13`）
//!
//! 既にある辺は[`TransitionGraph::resolve`]で引き、その遷移先をそのまま使う。**照合を自前で書かない**
//! ——書くと、エディタが「既にある」と言った辺がDaemonでは当たらない（またはその逆）が起きる。
//! `policy.json`が検査に落ちるなら判定器を組めないので、割り当てずに[`AssignError::PolicyRejected`]を返す。
//! 実行ファイルの比較（位置をまとめる鍵）も判定器と同じ畳み方（`fold_for_pattern_comparison`）で行う。
//!
//! # 名前の検査を引数で受ける理由
//!
//! 提案する名前は`harness.exe`の入れ物（AppContainerプロファイル）の名前に入るので、書く前に
//! `harness_sandbox::tier2a::domain_profile_name_problem`で確かめる。ところが`harness-sandbox`が
//! このクレートに依存しているので、ここからは呼べない（循環する）。そこでクロージャで受け、
//! エディタが本物を渡す（`docs/CODE-STRUCTURE-RULES.md` §5.2 の手段2）。
//!
//! # 決定65の細目との対応
//!
//! | 細目 | ここで |
//! |---|---|
//! | (1) 位置ごとに別のドメイン | 位置の鍵＝（親のドメイン, 畳んだ exe）。親を先に解くため深さの順に解く |
//! | Q1 引数では分けない | 鍵に引数を入れない。引数は[`Position::command_lines`]に載せるだけ。**決定67で「引数が任意の位置では」へ限定した**（下） |
//! | Q2 引数の既定は「任意」 | [`Assignment::edges_to_add`]が`argv: any`で辺を作る。引数が使えない起動は数える |
//! | 決定67(1)(2) 引数を固定した位置は分ける | [`SplitPositions`]に入った位置は、全部の起動のコマンドラインが使えるときだけ鍵にコマンドラインを足す。使えなければ分けずに[`SplitRefused`] |
//! | 決定67の名前 | `<葉名>-<スクリプトの語幹>`（[`script_argument`]）／`<葉名>`・`<葉名>-N`。語幹の形が名前の検査に落ちたら切らずに葉名の形へ倒す |
//! | Q4 引けないファイル操作は数えるだけ | [`Unattributed`]。入口のドメインへ寄せない |
//! | Q7 自己ループ辺に吸わせない | [`PositionSource::ReplacesSelfLoop`]で新しい名前を提案する |
//! | Q8 子の実行ファイルの実行権は子へ | [`DomainShare::exec_images`] |
//! | Q9 `<葉名>`／`<葉名>-N`・名前の検査 | 葉名を`[a-z0-9-]`へ寄せ、名前の検査に落ちたら短く切らずに断る |
//! | 追記(2)(3) 親は番号で引く | 親は`parent_seq`だけで引く（pid を使わない、`B-17`）。引けない子は数える |
//!
//! # 限界
//!
//! - 引数が結び付かなかった起動は、空のコマンドラインで判定器に聞く。引数で分けた既存のリテラルの辺には
//!   当たらず、`argv: any`の辺にだけ当たる——結果は「任意の引数」の新しい提案になる（§19.3.11 の粗い側）。
//! - 既存の**パターン**の辺と同じ実行ファイルに`argv: any`の辺を提案すると、エディタが書いた後に両方が当たって
//!   判定器が`AmbiguousPattern`で断りうる。ここは書かないので検出しない（書く前の検査はエディタが掛ける）。
//! - 提案の名前は「この記録と今の`policy.json`」で決まる。承認しなかった提案は次の記録で別の名前になりうる
//!   （承認すれば既にある辺として固定され、次からは[`PositionSource::ExistingEdge`]で出る）。
//! - 作業ディレクトリは観測していない（`process_event`のモジュールdoc）。判定器にはワークスペースを渡し、
//!   作業ディレクトリを宣言した辺（Strict の辺・相対パスの引数を固定した辺）だけが当たって`CwdMismatch`になったら、
//!   **宣言の場所で起きたものとみなして引き直す**（決定67。エディタが書いたその辺を、同じ記録の読み直しで既にある辺として
//!   引くため）。記録の起動が実際にどこで走ったかは確かめていない——強制は Spawn Daemon が実際の作業ディレクトリで判定する。
//! - 分けるかは**段ごと**に決める。同じ（遷移元, 実行ファイル）が既にある辺の閉路で別の段にも現れると、段ごとに
//!   分ける・分けないが違いうる（その段の起動だけで決めるため）。
//! - 同じ通し番号が2回あれば1つ目だけを使う。ファイル操作は番号で引くので、その番号の行は1つ目の
//!   インスタンスのドメインへ入る。

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use harness_change_ledger::path_rules::fold_for_pattern_comparison;

use crate::event::{FsAuditEvent, FsAuditKind};
use crate::policy_file::{file_stem, PolicyFile, ENTRY_DOMAIN};
use crate::process_event::{
    ArgvBinding, ArgvTruncation, ParentSeqSource, ProcessAuditLog, ProcessInstance,
};
use crate::process_tree::{walk, RootKind};
use crate::transition::{
    editor_edge, is_absolute_path, split_command_line, AnyMarker, ArgvMatcher, GraphError,
    Resolution, SpawnAttempt, TransitionDenial, TransitionEdge, TransitionGraph,
};

// ---------------------------------------------------------------------------
// 答えの形
// ---------------------------------------------------------------------------

/// [`assign_domains`]の答え。**書かない**——辺を`policy.json`へ書くのはエディタ（D-42）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    /// 割り当てた位置。順序は（深さ, 遷移元, 葉名, 畳んだ exe, 遷移先）——通し番号に依らない。
    pub positions: Vec<Position>,
    /// 記録の根のインスタンス（`is_scope_root`）。ドメインは常に[`ENTRY_DOMAIN`]で、根の辺は観測から
    /// 作らない（§19.3.12）。seq の昇順。
    pub roots: Vec<RootInstance>,
    /// どの位置にも割り当てなかったインスタンス。seq の昇順。
    pub unassigned: Vec<UnassignedInstance>,
    /// 分ける集合（[`SplitPositions`]）に入っていたが、コマンドラインの欠け・切り詰めの疑いがあって分けなかった位置
    /// （決定67(2)）。（遷移元, 畳んだ exe）の順。**黙って分けないままにしない**（`B-09`）。
    pub split_refused: Vec<SplitRefused>,
}

/// 分ける位置の集合（決定67(1)）。鍵は**分ける前の**位置の（遷移元のドメイン, 判定器と同じ畳み方の exe）
/// ——[`split_key`]が作る。遷移元は割り当ての名前（エディタの付け替えを当てる前）で書く。
pub type SplitPositions = BTreeSet<(String, String)>;

/// 位置を分けるときの鍵（[`SplitPositions`]の要素）。分けた後の位置で呼ぶと、その位置を戻す鍵になる。
pub fn split_key(position: &Position) -> (String, String) {
    (
        position.from_domain.clone(),
        fold_for_pattern_comparison(&position.exe),
    )
}

/// 分ける集合に入っていたが分けなかった位置（[`Assignment::split_refused`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitRefused {
    pub from_domain: String,
    /// 実行ファイル（その段で seq が最も小さい起動の綴り）。
    pub exe: String,
    /// 引数が結び付かなかった起動の件数。
    pub argv_missing: usize,
    /// 引数が切り詰められた疑い・確定の起動の件数。
    pub argv_truncated: usize,
}

/// 1つの位置＝辺1本（`from_domain`から`exe`を起こすと`to_domain`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Position {
    /// 子の段数（根の子が1）。深さの違うインスタンスが同じ位置に入ったら最も浅いもの。
    pub depth: usize,
    pub from_domain: String,
    /// 実行ファイルのフルパス。**観測した綴り**（この位置で seq が最も小さいインスタンスの`image_path`）。
    /// 辺の`exe.literal`にそのまま書く。
    pub exe: String,
    pub to_domain: String,
    pub source: PositionSource,
    /// この位置のインスタンスの seq（昇順）。エディタの木の描画とファイル操作の振り分けが引く。
    pub instances: Vec<u64>,
    /// 結び付いたコマンドライン（生の綴り。切り詰めの疑い・確定のものは入れない。重複を除いて昇順）。
    /// エディタの説明欄と、分けられるか（[`Position::can_split`]）の材料。
    pub command_lines: Vec<String>,
    /// **分けた位置だけ`Some`**（決定67(1)）: この位置の辺が固定するコマンドライン（seq が最も小さい起動の生の綴り）。
    /// [`Assignment::edges_to_add`]がこれをリテラルの引数にする。分けていない位置・既にある辺の位置は`None`。
    pub fixed_command_line: Option<String>,
    /// 引数が結び付かなかった起動（`ArgvBinding::Missing`）の件数。
    pub argv_missing: usize,
    /// 引数が切り詰められた疑い・確定の起動の件数（リテラルの辺の候補にしない。`plans/DESIGN-MAC.md` §5.1(6)）。
    pub argv_truncated: usize,
}

impl Position {
    /// コマンドラインごとに分けられるか（決定67(2)）: 全部の起動のコマンドラインが結び付き、切り詰めの疑いも無い。
    /// エディタの`u`はこれで断り、割り当ても同じ条件（起動ごとの[`argv_use`]）で分けるかを決める。
    pub fn can_split(&self) -> bool {
        self.argv_missing == 0 && self.argv_truncated == 0 && !self.command_lines.is_empty()
    }
}

/// 位置の遷移先がどこから来たか。
///
/// **宣言の順に意味がある**——同じ位置に出どころの違うインスタンスが混ざったら、後ろのもの（大きい方）を
/// その位置の出どころにする（自己ループ辺に当たったインスタンスが1つでもあれば`ReplacesSelfLoop`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PositionSource {
    /// `policy.json`に既にある辺が判定器で引けた（遷移先はその辺のもの）。エディタは書かない。
    ExistingEdge,
    /// 新しく提案した名前。エディタが辺と（無ければ）宣言の無いドメインを書く。
    Proposed,
    /// 既にある自己ループ辺に当たったが吸わせず、新しい名前を提案した（決定65 Q7）。
    /// 置き換えはエディタのダイアログでユーザーが確定したときだけ（D-42）。
    ReplacesSelfLoop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootInstance {
    pub seq: u64,
    pub image_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnassignedInstance {
    pub seq: u64,
    pub reason: Unassigned,
}

/// 割り当てなかった理由（§19.3.14「理由別に件数を数えて出す」）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unassigned {
    /// 親の番号が無い、または出どころが`unresolved`（決定65の追記(2)。番号が書いてあっても使わない）。
    ParentUnresolved,
    /// 親の番号はあるが、その親のインスタンスが記録に無い（同(2)）。
    ParentNotRecorded { parent_seq: u64 },
    /// 親（かその祖先）を割り当てなかった。
    ParentUnassigned,
    /// 親子の番号が閉路になっている（記録が壊れている）。閉路の中で根として拾い直した1つがこれになり、
    /// その下は[`Unassigned::ParentUnassigned`]になる。
    InCycle,
    /// 実行ファイルのパスが無い（設定の綴りへ寄せられなかった）。辺の`exe`を書けない。
    NoImagePath,
    /// 提案する名前が名前の検査を通らない（27文字を超える等。理由は検査の文面）。
    NameRefused { proposed: String, reason: String },
    /// 既にある辺に当たったが、判定器が許可を答えなかった（`AmbiguousPattern`・`CwdMismatch`）。
    /// 新しい辺を足すと既にある辺と食い違うので提案もしない。
    ExistingEdgeUnresolvable(TransitionDenial),
    /// 同じ seq が2回あった（2つ目以降）。
    DuplicateSequenceNumber,
}

impl Unassigned {
    /// 件数を数える鍵（画面の文面ではない）。
    pub fn label(&self) -> &'static str {
        match self {
            Unassigned::ParentUnresolved => "parent_unresolved",
            Unassigned::ParentNotRecorded { .. } => "parent_not_recorded",
            Unassigned::ParentUnassigned => "parent_unassigned",
            Unassigned::InCycle => "in_cycle",
            Unassigned::NoImagePath => "no_image_path",
            Unassigned::NameRefused { .. } => "name_refused",
            Unassigned::ExistingEdgeUnresolvable(_) => "existing_edge_unresolvable",
            Unassigned::DuplicateSequenceNumber => "duplicate_sequence_number",
        }
    }
}

/// エディタが書く辺1本（[`Assignment::edges_to_add`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeToAdd {
    pub from_domain: String,
    /// `exe`はリテラル（観測した綴り）・`argv`は任意・`cwd`と`env`は書かない
    /// ——エディタの遷移の承認と同じ形（どちらも[`editor_edge`]で作る）。
    pub edge: TransitionEdge,
    /// [`PositionSource::Proposed`]か[`PositionSource::ReplacesSelfLoop`]。**後者は遷移元の自己ループ辺を
    /// 取り除かないと書けない**——同じ実行ファイルに「任意の引数」の辺が2本当たり、判定器が
    /// `AmbiguousPattern`で断る。どの辺を取り除くかはユーザーが確定する（決定65 Q7）。
    pub source: PositionSource,
}

impl Assignment {
    /// そのインスタンスのドメイン。根は[`ENTRY_DOMAIN`]、割り当てなかったものは`None`。
    pub fn domain_of(&self, seq: u64) -> Option<&str> {
        self.instance_domains()
            .find(|(instance, _)| *instance == seq)
            .map(|(_, domain)| domain)
    }

    /// 割り当てなかった理由ごとの件数（[`Assignment::unassigned`]から数える。別に持たない、`B-13`）。
    pub fn unassigned_counts(&self) -> BTreeMap<&'static str, usize> {
        let mut counts = BTreeMap::new();
        for instance in &self.unassigned {
            *counts.entry(instance.reason.label()).or_insert(0) += 1;
        }
        counts
    }

    /// 書く辺の一覧（既にある辺の位置は除く。[`Assignment::positions`]の順）。
    pub fn edges_to_add(&self) -> Vec<EdgeToAdd> {
        self.positions
            .iter()
            .filter(|position| position.source != PositionSource::ExistingEdge)
            .map(|position| EdgeToAdd {
                from_domain: position.from_domain.clone(),
                // 辺の形はエディタの遷移の承認と同じ1か所（`editor_edge`）で決める（`B-05`）。分けた位置は
                // コマンドラインのリテラル（決定67(1)）。作業ディレクトリは決めない（記録に無い。エディタが足す）。
                edge: editor_edge(
                    &position.exe,
                    match &position.fixed_command_line {
                        Some(line) => ArgvMatcher::Literal(line.clone()),
                        None => ArgvMatcher::Any(AnyMarker),
                    },
                    &position.to_domain,
                ),
                source: position.source,
            })
            .collect()
    }

    /// [`Assignment::edges_to_add`]の遷移元・遷移先のうち、`policy`に宣言の無いドメイン（名前の順）。
    /// エディタは宣言の無いドメインとして作る（入口のドメインが未宣言なら、それも入る）。
    pub fn domains_to_add(&self, policy: &PolicyFile) -> Vec<String> {
        let mut names = BTreeSet::new();
        for add in self.edges_to_add() {
            for name in [add.from_domain, add.edge.to] {
                if policy.domain(&name).is_none() {
                    names.insert(name);
                }
            }
        }
        names.into_iter().collect()
    }

    /// （seq, ドメイン）の組。**`domain_of`と`partition_fs`が同じものを引く**（`B-13`）。
    fn instance_domains(&self) -> impl Iterator<Item = (u64, &str)> + '_ {
        let roots = self.roots.iter().map(|root| (root.seq, ENTRY_DOMAIN));
        let placed = self.positions.iter().flat_map(|position| {
            position
                .instances
                .iter()
                .map(move |seq| (*seq, position.to_domain.as_str()))
        });
        roots.chain(placed)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AssignError {
    /// `policy.json`が遷移の検査に落ちる。既にある辺を判定器で引けないので割り当てない
    /// （判定を自前で書き直さない。エディタの遷移の承認も同じ`policy.json`では書けない）。
    #[error("policy.json の遷移の宣言が検査に落ちるので、既にある辺を引けません: {0}")]
    PolicyRejected(GraphError),
}

// ---------------------------------------------------------------------------
// 割り当て
// ---------------------------------------------------------------------------

/// 記録したプロセスの木の位置ごとに遷移先のドメインを割り当てる。
///
/// - `workspace_root`: [`PolicyFile::transition_graph_input`]へ渡す（エディタの遷移の承認と同じく、
///   `policy.json`の外で書込を許した場所は空）。判定器へ渡す作業ディレクトリにも使う
///   （記録は作業ディレクトリを観測していない）
/// - `name_problem`: 名前の検査。エディタは`&harness_sandbox::tier2a::domain_profile_name_problem`を渡す
/// - `split`: コマンドラインごとに分ける位置（決定67。空なら今までどおり、引数では分けない）
pub fn assign_domains(
    log: &ProcessAuditLog,
    policy: &PolicyFile,
    workspace_root: &Path,
    name_problem: &dyn Fn(&str) -> Option<String>,
    split: &SplitPositions,
) -> Result<Assignment, AssignError> {
    let workspace = workspace_root.to_string_lossy();
    let input = policy.transition_graph_input(Some(workspace.as_ref()), &[]);
    let graph = TransitionGraph::build(&input).map_err(AssignError::PolicyRejected)?;

    let mut roots: Vec<RootInstance> = Vec::new();
    let mut unassigned: Vec<UnassignedInstance> = Vec::new();
    let mut split_refused: Vec<SplitRefused> = Vec::new();

    // 番号で引ける表。同じ番号の2つ目以降は割り当てない。
    let mut by_seq: BTreeMap<u64, &ProcessInstance> = BTreeMap::new();
    let mut nodes: Vec<(u64, Option<u64>)> = Vec::new();
    for instance in &log.instances {
        if by_seq.contains_key(&instance.seq) {
            unassigned.push(UnassignedInstance {
                seq: instance.seq,
                reason: Unassigned::DuplicateSequenceNumber,
            });
            continue;
        }
        by_seq.insert(instance.seq, instance);
        nodes.push((instance.seq, parent_key(instance)));
    }

    // 深さごとに解く（親が必ず先に解ける）。
    let mut by_depth: BTreeMap<usize, Vec<(u64, Option<RootKind>)>> = BTreeMap::new();
    for entry in walk(&nodes) {
        by_depth
            .entry(entry.depth)
            .or_default()
            .push((entry.key, entry.root));
    }

    let mut naming = Naming::new(policy, name_problem);
    let mut domain_by_seq: BTreeMap<u64, String> = BTreeMap::new();
    let mut placed: Vec<Placed<'_>> = Vec::new();
    for (depth, entries) in by_depth {
        let mut needs_name: Vec<(&ProcessInstance, String, PositionSource)> = Vec::new();
        for (seq, root) in entries {
            let instance = by_seq[&seq];
            if let Some(kind) = root {
                match root_reason(instance, kind) {
                    None => {
                        domain_by_seq.insert(seq, ENTRY_DOMAIN.to_string());
                        roots.push(RootInstance {
                            seq,
                            image_path: instance.image_path.clone(),
                        });
                    }
                    Some(reason) => unassigned.push(UnassignedInstance { seq, reason }),
                }
                continue;
            }
            match place(&graph, instance, &domain_by_seq, &workspace) {
                Step::Unassigned(reason) => unassigned.push(UnassignedInstance { seq, reason }),
                Step::Existing { from, to } => {
                    domain_by_seq.insert(seq, to.clone());
                    placed.push(Placed::new(
                        instance,
                        depth,
                        from,
                        to,
                        PositionSource::ExistingEdge,
                        None,
                    ));
                }
                Step::NeedsName { from, source } => needs_name.push((instance, from, source)),
            }
        }

        // 分ける位置（決定67）: 分ける集合に入っていて、この段の全部の起動のコマンドラインが使えるものだけ。
        let split_here = splittable(&needs_name, split, &mut split_refused);
        let keyed: Vec<(&ProcessInstance, String, PositionSource, NameKey)> = needs_name
            .into_iter()
            .map(|(instance, from, source)| {
                let key = NameKey::of(instance, &from, &split_here);
                (instance, from, source, key)
            })
            .collect();
        // この段で名前の要る鍵に名前を付ける。**順序は通し番号に依らない**（Naming::name_all）。
        naming.name_all(keyed.iter().map(|(_, _, _, key)| key.clone()));
        for (instance, from, source, key) in keyed {
            match naming.verdict(&key) {
                Ok(name) => {
                    domain_by_seq.insert(instance.seq, name.clone());
                    // 分けた位置の辺が固定する綴りは生のまま（判定器が畳んで比べる）。
                    let fixed = key
                        .command_line
                        .is_some()
                        .then(|| usable_command_line(instance).map(str::to_string))
                        .flatten();
                    placed.push(Placed::new(instance, depth, from, name, source, fixed));
                }
                Err(reason) => unassigned.push(UnassignedInstance {
                    seq: instance.seq,
                    reason,
                }),
            }
        }
    }

    roots.sort_by_key(|root| root.seq);
    unassigned.sort_by_key(|instance| instance.seq);
    split_refused.sort_by_cached_key(|r| (r.from_domain.clone(), fold_for_pattern_comparison(&r.exe)));
    Ok(Assignment {
        positions: positions_from(placed),
        roots,
        unassigned,
        split_refused,
    })
}

/// 起動のコマンドラインが使えるか（[`Position::command_lines`]・`argv_missing`・`argv_truncated`の数え方と、分けるかの判定が
/// 同じこれを通す。`B-13`）。
enum ArgvUse<'i> {
    Usable(&'i str),
    Missing,
    Truncated,
}

fn argv_use(instance: &ProcessInstance) -> ArgvUse<'_> {
    match &instance.argv {
        ArgvBinding::Exact {
            command_line,
            truncation: ArgvTruncation::None,
        } => ArgvUse::Usable(command_line),
        ArgvBinding::Exact { .. } => ArgvUse::Truncated,
        ArgvBinding::Missing { .. } => ArgvUse::Missing,
    }
}

fn usable_command_line(instance: &ProcessInstance) -> Option<&str> {
    match argv_use(instance) {
        ArgvUse::Usable(line) => Some(line),
        ArgvUse::Missing | ArgvUse::Truncated => None,
    }
}

/// この段で分ける（遷移元, 畳んだ exe）——`split`に入っていて、名前の要る全部の起動のコマンドラインが使えるもの
/// （決定67(2)）。使えない起動があれば分けず、件数を`refused`へ積む。
fn splittable(
    needs_name: &[(&ProcessInstance, String, PositionSource)],
    split: &SplitPositions,
    refused: &mut Vec<SplitRefused>,
) -> BTreeSet<(String, String)> {
    let mut groups: BTreeMap<(String, String), Vec<&ProcessInstance>> = BTreeMap::new();
    for (instance, from, _) in needs_name {
        let key = (from.clone(), exe_of(instance));
        if split.contains(&key) {
            groups.entry(key).or_default().push(instance);
        }
    }
    let mut out = BTreeSet::new();
    for (key, mut members) in groups {
        let (mut missing, mut truncated) = (0, 0);
        for member in &members {
            match argv_use(member) {
                ArgvUse::Usable(_) => {}
                ArgvUse::Missing => missing += 1,
                ArgvUse::Truncated => truncated += 1,
            }
        }
        if missing == 0 && truncated == 0 {
            out.insert(key);
            continue;
        }
        members.sort_by_key(|member| member.seq);
        refused.push(SplitRefused {
            from_domain: key.0,
            exe: members[0].image_path.clone().unwrap_or_default(),
            argv_missing: missing,
            argv_truncated: truncated,
        });
    }
    out
}

/// `walk`へ渡す親の鍵。**根（`is_scope_root`）は親を見ない**——根の親は harness 本体か Spawn Daemon で、
/// 記録に無い。**出どころが`unresolved`なら番号を使わない**（決定65の追記(2): 親を決めない）。
fn parent_key(instance: &ProcessInstance) -> Option<u64> {
    if instance.is_scope_root || instance.parent_seq_source == ParentSeqSource::Unresolved {
        return None;
    }
    instance.parent_seq
}

/// 木の根になったインスタンスを割り当てない理由（記録の根なら`None`）。
/// なぜ根なのかは`walk`が答える——ここで「親が記録に在るか」を判定し直さない（`B-13`）。
fn root_reason(instance: &ProcessInstance, kind: RootKind) -> Option<Unassigned> {
    if instance.is_scope_root {
        return None;
    }
    Some(match kind {
        RootKind::NoParent => Unassigned::ParentUnresolved,
        RootKind::ParentAbsent => match instance.parent_seq {
            Some(parent_seq) => Unassigned::ParentNotRecorded { parent_seq },
            None => Unassigned::ParentUnresolved,
        },
        RootKind::OwnParent | RootKind::InCycle => Unassigned::InCycle,
    })
}

/// 子1つを判定器に聞いた結果。
enum Step {
    Unassigned(Unassigned),
    /// 既にある辺（自己ループでない）。
    Existing {
        from: String,
        to: String,
    },
    /// 新しい名前が要る（`Proposed`か`ReplacesSelfLoop`）。
    NeedsName {
        from: String,
        source: PositionSource,
    },
}

fn place(
    graph: &TransitionGraph,
    instance: &ProcessInstance,
    domain_by_seq: &BTreeMap<u64, String>,
    workspace: &str,
) -> Step {
    // walk が子として置いたので親の番号は記録にある。その親を割り当てていなければ子も割り当てない。
    let Some(from) = instance.parent_seq.and_then(|p| domain_by_seq.get(&p)) else {
        return Step::Unassigned(Unassigned::ParentUnassigned);
    };
    let Some(exe) = instance.image_path.as_deref() else {
        return Step::Unassigned(Unassigned::NoImagePath);
    };
    // 引数が結び付かなかった起動は空のコマンドラインで聞く（`argv: any`の辺にだけ当たる。モジュールdocの限界）。
    let command_line = match &instance.argv {
        ArgvBinding::Exact { command_line, .. } => command_line.as_str(),
        ArgvBinding::Missing { .. } => "",
    };
    let attempt = SpawnAttempt {
        from_domain: from,
        exe,
        command_line,
        cwd: workspace,
    };
    let resolution = match graph.resolve(attempt) {
        // 記録は作業ディレクトリを持たない。作業ディレクトリを宣言した辺だけが実行ファイルと引数で当たったなら、
        // その場所で起きたものとみなして引き直す（決定67。モジュールdocの限界）。
        Resolution::Denied(TransitionDenial::CwdMismatch { declared, .. }) => {
            graph.resolve(SpawnAttempt {
                cwd: &declared,
                ..attempt
            })
        }
        other => other,
    };
    let from = from.clone();
    match resolution {
        Resolution::Allowed(allowed) if allowed.to != from => Step::Existing {
            to: allowed.to.to_string(),
            from,
        },
        // 自己ループ辺に当たった。吸わせない（決定65 Q7）。
        Resolution::Allowed(_) => Step::NeedsName {
            from,
            source: PositionSource::ReplacesSelfLoop,
        },
        // 遷移元が未宣言（今回の提案のドメインもこれ）か、当たる辺が無い。
        Resolution::Denied(
            TransitionDenial::UnknownSourceDomain | TransitionDenial::NoMatchingEdge,
        ) => Step::NeedsName {
            from,
            source: PositionSource::Proposed,
        },
        Resolution::Denied(denial) => {
            Step::Unassigned(Unassigned::ExistingEdgeUnresolvable(denial))
        }
    }
}

/// 位置をまとめる鍵の実行ファイル（判定器と同じ畳み方）。
fn exe_of(instance: &ProcessInstance) -> String {
    fold_for_pattern_comparison(instance.image_path.as_deref().unwrap_or(""))
}

/// 提案する名前の葉名（決定65 Q9）: basename の最後の拡張子を除き（[`file_stem`]）、ASCII小文字にし、
/// `[a-z0-9-]`以外を`-`にし、`-`の連続を1つにし、両端の`-`を落とす。空なら`process`。
fn leaf_name(image_path: &str) -> String {
    let mut out = String::new();
    for c in file_stem(image_path).chars() {
        let c = c.to_ascii_lowercase();
        let c = if c.is_ascii_lowercase() || c.is_ascii_digit() {
            c
        } else {
            '-'
        };
        if c == '-' && (out.is_empty() || out.ends_with('-')) {
            continue;
        }
        out.push(c);
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "process".to_string()
    } else {
        out
    }
}

/// コマンドラインの中のスクリプト（[`script_argument`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptArgument {
    /// 書かれた綴り（引用符を外したもの）。
    pub token: String,
    /// 絶対パスか（判定器の規則(d)と同じ見分け）。
    pub absolute: bool,
}

/// コマンドラインの中のスクリプト: `argv[0]`の後ろで、拡張子が`harness_core::SCRIPT_EXTENSIONS`のどれかである最初の語
/// （決定67）。分けた位置の名前（`<葉名>-<語幹>`）と、エディタの作業ディレクトリの候補が同じこれを通す。語の割り方は
/// 判定器の編集時検査と同じ（写さない）。`argv[0]`は呼び出し元が書いた綴りそのもので数えない。
pub fn script_argument(command_line: &str) -> Option<ScriptArgument> {
    split_command_line(command_line)
        .into_iter()
        .skip(1)
        .find(|token| harness_core::has_script_extension(token))
        .map(|token| ScriptArgument {
            absolute: is_absolute_path(&fold_for_pattern_comparison(&token)),
            token,
        })
}

/// 名前を付ける鍵: （遷移元のドメイン, 畳んだ exe）と、**分けた位置だけ**畳んだコマンドライン（決定67）。
/// 判定器と同じ畳み方で束ねるので、大小・区切りだけ違う綴りは同じ辺（同じ名前）になる。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NameKey {
    from: String,
    folded_exe: String,
    command_line: Option<String>,
}

impl NameKey {
    fn of(instance: &ProcessInstance, from: &str, split_here: &BTreeSet<(String, String)>) -> Self {
        let folded_exe = exe_of(instance);
        let command_line = split_here
            .contains(&(from.to_string(), folded_exe.clone()))
            .then(|| usable_command_line(instance).map(fold_for_pattern_comparison))
            .flatten();
        Self {
            from: from.to_string(),
            folded_exe,
            command_line,
        }
    }

    /// 名前の元（決定67の「分けた位置のドメイン名」）: 分けた位置でスクリプトの語があれば`<葉名>-<語幹>`、他は葉名。
    fn base(&self) -> String {
        let leaf = leaf_name(&self.folded_exe);
        match self.command_line.as_deref().and_then(script_argument) {
            Some(script) => format!("{leaf}-{}", leaf_name(&script.token)),
            None => leaf,
        }
    }
}

/// 提案する名前の割り当て。鍵は[`NameKey`]（遷移元のドメイン, 畳んだ exe, 分けた位置ならコマンドライン）。
struct Naming<'n> {
    /// 使えない名前（**小文字で比べる**——大小だけ違う名前のドメインを作らない）:
    /// `policy.json`のドメイン名・入口のドメイン・この割り当てで既に決めた名前。
    taken: BTreeSet<String>,
    decided: BTreeMap<NameKey, Result<String, Unassigned>>,
    name_problem: &'n dyn Fn(&str) -> Option<String>,
}

impl<'n> Naming<'n> {
    fn new(policy: &PolicyFile, name_problem: &'n dyn Fn(&str) -> Option<String>) -> Self {
        let taken = policy
            .domains
            .iter()
            .map(|domain| domain.name.as_str())
            .chain([ENTRY_DOMAIN])
            .map(str::to_ascii_lowercase)
            .collect();
        Self {
            taken,
            decided: BTreeMap::new(),
            name_problem,
        }
    }

    /// まだ名前の無い鍵に名前を付ける。**（遷移元, 名前の元, 畳んだ exe, 畳んだコマンドライン）の順**に決める——
    /// 通し番号にも入力の順にも依らないので、2回目の記録で番号が変わっても同じ名前になる。
    /// 名前の検査に落ちた鍵は断ったと覚える（深い段で同じ鍵が出ても同じ理由で断る）。
    /// **短く切って通さない**（決定65 Q9 は「断る」）。分けた位置の`<葉名>-<語幹>`が落ちたときだけ、切らずに
    /// 葉名の形へ倒す（決定67——スクリプト名が長いだけで分けられなくしない）。
    fn name_all(&mut self, keys: impl Iterator<Item = NameKey>) {
        let mut pending: BTreeSet<(String, String, NameKey)> = BTreeSet::new();
        for key in keys {
            if !self.decided.contains_key(&key) {
                pending.insert((key.from.clone(), key.base(), key));
            }
        }
        for (_, base, key) in pending {
            let leaf = leaf_name(&key.folded_exe);
            let mut name = self.free_name(&base);
            let mut problem = (self.name_problem)(&name);
            if problem.is_some() && base != leaf {
                name = self.free_name(&leaf);
                problem = (self.name_problem)(&name);
            }
            self.taken.insert(name.clone());
            let verdict = match problem {
                None => Ok(name),
                Some(reason) => Err(Unassigned::NameRefused {
                    proposed: name,
                    reason,
                }),
            };
            self.decided.insert(key, verdict);
        }
    }

    fn free_name(&self, leaf: &str) -> String {
        if !self.taken.contains(leaf) {
            return leaf.to_string();
        }
        (2..)
            .map(|n| format!("{leaf}-{n}"))
            .find(|candidate| !self.taken.contains(candidate))
            .expect("the suffixes are unbounded")
    }

    fn verdict(&self, key: &NameKey) -> Result<String, Unassigned> {
        self.decided
            .get(key)
            .cloned()
            .expect("name_all named every key of this depth")
    }
}

/// 割り当てたインスタンス1つ。
struct Placed<'l> {
    instance: &'l ProcessInstance,
    depth: usize,
    from: String,
    to: String,
    source: PositionSource,
    /// 分けた位置の起動だけ`Some`（その起動のコマンドラインの生の綴り。決定67）。
    fixed_command_line: Option<String>,
}

impl<'l> Placed<'l> {
    fn new(
        instance: &'l ProcessInstance,
        depth: usize,
        from: String,
        to: String,
        source: PositionSource,
        fixed_command_line: Option<String>,
    ) -> Self {
        Self {
            instance,
            depth,
            from,
            to,
            source,
            fixed_command_line,
        }
    }
}

/// 割り当てたインスタンスを（遷移元, 畳んだ exe, 遷移先）でまとめて位置にする。
fn positions_from(placed: Vec<Placed<'_>>) -> Vec<Position> {
    let mut groups: BTreeMap<(String, String, String), Vec<Placed<'_>>> = BTreeMap::new();
    for one in placed {
        let key = (one.from.clone(), exe_of(one.instance), one.to.clone());
        groups.entry(key).or_default().push(one);
    }
    let mut positions: Vec<Position> = groups
        .into_values()
        .map(|mut members| {
            members.sort_by_key(|one| one.instance.seq);
            let first = &members[0];
            let mut command_lines = BTreeSet::new();
            let (mut argv_missing, mut argv_truncated) = (0, 0);
            for one in &members {
                match argv_use(one.instance) {
                    ArgvUse::Usable(command_line) => {
                        command_lines.insert(command_line.to_string());
                    }
                    ArgvUse::Truncated => argv_truncated += 1,
                    ArgvUse::Missing => argv_missing += 1,
                }
            }
            Position {
                depth: members
                    .iter()
                    .map(|one| one.depth)
                    .min()
                    .unwrap_or(first.depth),
                from_domain: first.from.clone(),
                exe: first.instance.image_path.clone().unwrap_or_default(),
                to_domain: first.to.clone(),
                source: members
                    .iter()
                    .map(|one| one.source)
                    .max()
                    .unwrap_or(first.source),
                instances: members.iter().map(|one| one.instance.seq).collect(),
                command_lines: command_lines.into_iter().collect(),
                // 同じ位置の起動は同じ（畳んだ）コマンドラインなので、seq が最も小さいものの綴り。
                fixed_command_line: first.fixed_command_line.clone(),
                argv_missing,
                argv_truncated,
            }
        })
        .collect();
    positions.sort_by_cached_key(|p| {
        (
            p.depth,
            p.from_domain.clone(),
            leaf_name(&p.exe),
            fold_for_pattern_comparison(&p.exe),
            p.to_domain.clone(),
        )
    });
    positions
}

// ---------------------------------------------------------------------------
// ファイル操作の振り分け
// ---------------------------------------------------------------------------

/// ファイル操作をドメインへ振り分けた結果。
#[derive(Debug, Clone, Default)]
pub struct Partition<'e> {
    /// ドメイン名 → そのドメインのインスタンスが触った分（決定65(5)。子孫の分を親へ足さない）。
    /// ファイル操作が無くても、実行ファイルのあるドメインは載る。
    pub by_domain: BTreeMap<String, DomainShare<'e>>,
    pub unattributed: Unattributed,
}

#[derive(Debug, Clone, Default)]
pub struct DomainShare<'e> {
    /// このドメインのインスタンスのファイル操作（入力の順）。
    pub events: Vec<&'e FsAuditEvent>,
    /// このドメインのインスタンスの実行ファイル（決定65 Q8: 子を起こすとき実行ファイルを開くのは子のトークン
    /// なので、子の実行ファイル自身の実行権は子のドメインへ）。根の実行ファイルは入口のドメインへ。
    pub exec_images: BTreeSet<String>,
}

/// どのドメインにも引けなかったファイル操作の件数（決定65 Q4。入口のドメインへ寄せない——入口は
/// モデルが動かす根なので、寄せると最も危ない所の権限が増える）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Unattributed {
    /// 通し番号の欄が無い（古い行・番号を引けなかった行）。
    pub without_sequence_number: usize,
    /// 番号が記録の木に無い。
    pub unknown_sequence_number: usize,
    /// 番号は木にあるが、そのインスタンスを割り当てなかった。
    pub unassigned_instance: usize,
}

/// ファイル操作をドメインへ振り分ける。制御の行（[`FsAuditKind::Control`]）は振り分けない
/// （数えもしない。エディタは今までどおり全体の注記として出す）。
pub fn partition_fs<'e>(events: &'e [FsAuditEvent], assignment: &Assignment) -> Partition<'e> {
    let domains: BTreeMap<u64, &str> = assignment.instance_domains().collect();
    let unassigned: BTreeSet<u64> = assignment.unassigned.iter().map(|u| u.seq).collect();

    let mut partition = Partition::default();
    for root in &assignment.roots {
        let share = partition
            .by_domain
            .entry(ENTRY_DOMAIN.to_string())
            .or_default();
        if let Some(image) = &root.image_path {
            share.exec_images.insert(image.clone());
        }
    }
    for position in &assignment.positions {
        partition
            .by_domain
            .entry(position.to_domain.clone())
            .or_default()
            .exec_images
            .insert(position.exe.clone());
    }

    for event in events {
        if event.kind == FsAuditKind::Control {
            continue;
        }
        let Some(seq) = event.process_sequence_number else {
            partition.unattributed.without_sequence_number += 1;
            continue;
        };
        match domains.get(&seq) {
            Some(domain) => partition
                .by_domain
                .entry((*domain).to_string())
                .or_default()
                .events
                .push(event),
            None if unassigned.contains(&seq) => partition.unattributed.unassigned_instance += 1,
            None => partition.unattributed.unknown_sequence_number += 1,
        }
    }
    partition
}

#[cfg(test)]
#[path = "position_domains_tests.rs"]
mod position_domains_tests;
