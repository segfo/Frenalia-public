//! 拒否候補を許可ルールの候補へ一般化する（`plans/DESIGN-SANDBOX-APPPOLICY.md` §11.3）。
//!
//! # 意図的にしないこと
//!
//! - **パスを畳まない（D-62）。** 観測された値をそのまま1件1提案にする。かつては
//!   `Generalization`（`none`/`dir`/`auto`）で畳み方を選べ、`dir`が既定だった。**廃止した。**
//!   提案の値がディレクトリやワイルドカードになると、付与は継承ACE（`(OI)(CI)`）に、
//!   ワイルドカードは`grant_root`が最初の`*`の手前で切るため**その親ディレクトリ全体**になる。
//!   どちらも観測していない兄弟ファイルと将来作られるファイルまで覆うのに、ユーザーには
//!   「観測された数件をまとめた1行」にしか見えなかった。畳み込みは
//!   「ETWが対象exeのアクセスを網羅している」という**成り立たない前提**に依存している。
//!   件数が多くて読めない問題は、値ではなく**表示**で解く——`policy-editor`の`ProposalTree`が
//!   パスの木にまとめ、親行のチェックで配下をまとめて選べる（値を書き換えないので広がらない）。
//! - **access種別をまたいで畳まない。** 同じパスが`read`と`read_write`の両方で拒否されていても、
//!   1本の`read_write`にまとめない。強い方へ寄せるのは「要求された権限を超えて与えない」
//!   （P-03）に反する——`read`しか要らなかった経路まで書込可になる。別々の提案として出し、
//!   どちらを受け入れるかをユーザーに選ばせる。
//! - **収集源をまたいで信頼度を変えない。** preflight由来（ユーザーが既に設定に書いた穴）も
//!   ETW由来（子プロセスが勝手に触った先）も同じ重みで提案する。両者の差を提案側で
//!   吸収すると、「触れば通る」経路を作りかけることになる（D-42）。証拠は
//!   [`RuleProposal::evidence`]に残るので、判断材料としては失われない。

use serde::{Deserialize, Serialize};

use harness_config::FsAccess;

use crate::normalize::{DeniedCandidate, Requested, Source};

/// 提案の出力先。`.harness/settings.json`のキーそのもの（§11.3「出力先は設定スキーマの語彙に一致させる」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingsKey {
    FsRead,
    FsReadWrite,
    FsReadExec,
    NetAllowDomains,
}

impl SettingsKey {
    /// 設定ファイル上のドット区切りパス（表示用）。
    pub fn dotted(self) -> &'static str {
        match self {
            SettingsKey::FsRead => "fs.read",
            SettingsKey::FsReadWrite => "fs.read_write",
            SettingsKey::FsReadExec => "fs.read_exec",
            SettingsKey::NetAllowDomains => "net.allow_domains",
        }
    }

    /// `(トップレベルキー, 配列キー)`。[`crate::diff`]がJSONを組み立てるのに使う。
    pub fn json_path(self) -> (&'static str, &'static str) {
        match self {
            SettingsKey::FsRead => ("fs", "read"),
            SettingsKey::FsReadWrite => ("fs", "read_write"),
            SettingsKey::FsReadExec => ("fs", "read_exec"),
            SettingsKey::NetAllowDomains => ("net", "allow_domains"),
        }
    }

    pub fn from_access(access: FsAccess) -> SettingsKey {
        match access {
            FsAccess::Read => SettingsKey::FsRead,
            FsAccess::ReadWrite => SettingsKey::FsReadWrite,
            FsAccess::ReadExec => SettingsKey::FsReadExec,
        }
    }

    /// [`Self::from_access`]の逆。`net.allow_domains`はFSではないので`None`。
    pub fn fs_access(self) -> Option<FsAccess> {
        match self {
            SettingsKey::FsRead => Some(FsAccess::Read),
            SettingsKey::FsReadWrite => Some(FsAccess::ReadWrite),
            SettingsKey::FsReadExec => Some(FsAccess::ReadExec),
            SettingsKey::NetAllowDomains => None,
        }
    }

    /// FSの3値を巡回する（`read → read_write → read_exec → read`）。
    ///
    /// 順番の正本をここに置くのは、ユーザーが押すキー（ポリシーエディタの編集画面）と
    /// 設定スキーマの語彙が同じ列挙だからである。表示側で並びを書くと、キーが増えたときに
    /// 片方だけ変わる（B-05）。`net.allow_domains`には次が無い（`None`）。
    pub fn next_fs_access(self) -> Option<SettingsKey> {
        match self {
            SettingsKey::FsRead => Some(SettingsKey::FsReadWrite),
            SettingsKey::FsReadWrite => Some(SettingsKey::FsReadExec),
            SettingsKey::FsReadExec => Some(SettingsKey::FsRead),
            SettingsKey::NetAllowDomains => None,
        }
    }
}

/// 許可ルールの候補1件。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleProposal {
    /// `harness policy apply --accept <id>`で参照する安定した識別子（`fs-1`・`net-2`）。
    /// 同じ入力なら常に同じidになる（並びが決定的なため）。
    pub id: String,
    pub key: SettingsKey,
    /// 設定へ書く値（パスまたはドメインパターン）。
    pub value: String,
    /// この提案の根拠になった拒否候補。**提案を狭めるためにユーザーが読む材料**であり、
    /// 一般化でまとめた分だけここが増える。
    pub evidence: Vec<DeniedCandidate>,
    /// 受け入れる前に読むべき注意。空でないことは「危険」を意味しない（一般化の広さの説明も入る）。
    pub warnings: Vec<String>,
}

impl RuleProposal {
    /// この提案が何件の拒否を説明するか。
    pub fn observed_count(&self) -> u64 {
        self.evidence.iter().map(|c| c.count).sum()
    }

    /// 根拠になった収集源（重複除去・安定順）。
    pub fn sources(&self) -> Vec<Source> {
        let mut sources: Vec<Source> = self.evidence.iter().map(|c| c.source).collect();
        sources.sort_unstable();
        sources.dedup();
        sources
    }
}

/// 候補列を提案列へ変換する。
///
/// 出力の並びは決定的（キー → 値の辞書順）で、idはその並びから振る。入力の順序に依存しないため、
/// 同じ台帳に対して何度実行しても`--accept fs-2`が同じものを指す。
pub fn generalize(candidates: &[DeniedCandidate]) -> Vec<RuleProposal> {
    generalize_with_granted(candidates, &crate::insufficient::GrantedPaths::default())
}

/// [`generalize`]に「既に設定で許可済みのパス」を教える版。
///
/// **既に許可済みなのに拒否された＝その許可では足りない**が確定するので、提案へその旨を載せる
/// （`plans/etw-spike/RESULTS.md` §15、実機の真理値表で前提を確認済み）。これは4656に頼らずに
/// 精度を上げられる唯一の経路で、根拠は推測ではなくWindowsのアクセスチェックの性質
/// （`DesiredAccess ⊆ granted`）そのものである。
pub fn generalize_with_granted(
    candidates: &[DeniedCandidate],
    granted: &crate::insufficient::GrantedPaths,
) -> Vec<RuleProposal> {
    let mut groups: Vec<Group> = Vec::new();

    for candidate in candidates {
        match &candidate.requested {
            Requested::Fs { path, access } => {
                let key = SettingsKey::from_access(*access);
                push_into_group(&mut groups, key, path.clone(), candidate.clone());
            }
            Requested::Net { domain } => {
                push_into_group(
                    &mut groups,
                    SettingsKey::NetAllowDomains,
                    domain.clone(),
                    candidate.clone(),
                );
            }
        }
    }

    // **観測された値をそのまま出す。畳み込みもワイルドカード化もしない**（D-62）。
    // かつては`Generalization::Directory`が既定で、同一ディレクトリ配下に2件以上の拒否が
    // あればその親1本へ畳んでいた。だが提案の値がディレクトリになると、付与は
    // `grant_ace_inheritable_access`の継承ACE（`(OI)(CI)`）になり、**観測していない兄弟ファイルと
    // 将来そこに作られるファイルまで覆う**。ユーザーから見えるのは「観測された2件をまとめた1行」
    // なのに、実際に開くのはサブツリー全体だった。
    //
    // 同じ理由が本モジュールの「意図的にしないこと」に既にある——access種別を強い方へ寄せないのは
    // 「要求された権限を超えて与えない」（P-03）ためである。**パスの軸でも同じ原則が要る。**
    // 表示上のまとまりは`policy-editor`の`ProposalTree`が担当する（そちらは値を書き換えないので
    // 一括選択しても広がらない）。
    //
    // 同一(key, value)は`push_into_group`が既に1グループへ束ねているので、ここで畳む処理は要らない。

    // グループ → 提案は 1:N である（[`escalate`]が昇格候補を並べるため）。**展開してから
    // 並べ替え、その後にidを振る**——先にグループを並べてから展開すると、昇格で生まれた提案の
    // idが挿入順に依存し、`--accept fs-2`が実行ごとに別のものを指しかねない。
    let mut expanded: Vec<Expanded> = Vec::new();
    for group in groups {
        expanded.extend(expand(group, granted));
    }
    expanded.sort_by(|a, b| a.key.cmp(&b.key).then_with(|| a.value.cmp(&b.value)));
    let expanded = merge_same_key_and_value(expanded);

    let mut fs_seq = 0usize;
    let mut net_seq = 0usize;
    expanded
        .into_iter()
        .map(|item| {
            let id = if item.key == SettingsKey::NetAllowDomains {
                net_seq += 1;
                format!("net-{net_seq}")
            } else {
                fs_seq += 1;
                format!("fs-{fs_seq}")
            };
            RuleProposal {
                id,
                key: item.key,
                value: item.value,
                evidence: item.evidence,
                warnings: item.warnings,
            }
        })
        .collect()
}

/// idを振る前の提案。1つの[`Group`]から1件以上生まれる。
struct Expanded {
    key: SettingsKey,
    value: String,
    evidence: Vec<DeniedCandidate>,
    warnings: Vec<String>,
}

/// 展開後に同じ`(key, value)`になったものを1件へ畳む（**採番の前**）。
///
/// # なぜ[`push_into_group`]の束ねだけでは足りないのか
///
/// あちらは観測時点の`(key, value)`で`Group`を束ねる。ところが同じ`(key, value)`は
/// **別々のGroupからも生まれる**——
///
/// - `fs.read`のGroupが[`expand`]の昇格で`fs.read_exec`になったもの
/// - 最初から`fs.read_exec`として観測／導出されたGroup（ポリシーエディタの実行像・実行前診断）
///
/// 畳まずに並べると、**同じ設定値の提案がidだけ違う形で2行並び、観測回数も割れる**。
/// 片方を承認しても、もう片方が未承認のまま一覧に残って見える。
///
/// **これはパスの一般化（D-62で廃止）とは別物**である。ここで畳むのは`(key, value)`が
/// 完全一致するものだけで、覆う範囲は1ミリも広がらない。
///
/// 証拠は連結し、警告は**順序を保ったまま重複を除く**（同じ文が2回並ぶと、行ごとの警告が
/// 共通警告として畳まれる`SessionView`側の判定も濁る）。
fn merge_same_key_and_value(expanded: Vec<Expanded>) -> Vec<Expanded> {
    let mut out: Vec<Expanded> = Vec::new();
    for item in expanded {
        match out
            .iter_mut()
            .find(|e| e.key == item.key && e.value.eq_ignore_ascii_case(&item.value))
        {
            Some(existing) => {
                existing.evidence.extend(item.evidence);
                for warning in item.warnings {
                    if !existing.warnings.contains(&warning) {
                        existing.warnings.push(warning);
                    }
                }
            }
            None => out.push(item),
        }
    }
    out
}

/// 提案のaccessを言い換える（`value`と`evidence`はそのまま、`key`だけ差し替える）。
///
/// ポリシーエディタの編集画面が使う——観測は`fs.read`でも、ユーザーが「これは実行だ」と
/// 判断できることがある（ETWは読取と実行を区別できない。RESULTS.md §17）。
///
/// **警告を作り直すのはこの関数の責任である。** `key`に依存する警告（`fs.read_write`の
/// 書込封じ込め注意・OS監査由来の`fs.read`は推測である旨）を表示側で足し引きすると、
/// 同じ提案がCLIとTUIで別の注意書きを持つ（B-05）。`key`に依存しない警告
/// （一般化の広さ・ワイルドカード）はそのまま残す。
///
/// idは変えない——選び直しを強いないため。**手で選ばれたことは警告として残す**
/// （何を書くのかを読んでから承認できるように、D-42）。
pub fn restate_access(proposal: &RuleProposal, key: SettingsKey) -> RuleProposal {
    let previous = key_dependent_warnings(proposal.key, &proposal.evidence);
    let mut warnings: Vec<String> = proposal
        .warnings
        .iter()
        .filter(|warning| !previous.contains(warning))
        .cloned()
        .collect();
    for warning in key_dependent_warnings(key, &proposal.evidence) {
        if !warnings.contains(&warning) {
            warnings.push(warning);
        }
    }
    warnings.push(format!(
        "the access of this candidate was chosen by hand; what was recorded is {}",
        proposal.key.dotted()
    ));

    RuleProposal {
        id: proposal.id.clone(),
        key,
        value: proposal.value.clone(),
        evidence: proposal.evidence.clone(),
        warnings,
    }
}

/// 1グループを提案（1件以上）へ展開する。
///
/// # なぜ昇格が要るのか（D-46）
///
/// 「既に`fs.read`で許可済みのパスで拒否が観測された」とき、旧実装は**同じ`fs.read`を提案し直し、
/// 警告として「もう一度fs.readを足しても直らない」と書いていた**。`key`も`value`も変わらないので
/// `harness policy apply`は`(no changes)`を印字して終わり——ツールが効かないと自分で言う提案を出し、
/// 適用しても何も起きない状態だった。CLIから`fs.read_write`へ到達する経路が存在しなかった。
///
/// そこで、その提案を**昇格候補で置き換える**。判定の入力は`value`そのもの（evidenceの一員では
/// なく）にする——`value`が既に覆われている＝**設定へ足しても意味が無いことが確定している**ので、
/// 置き換えるべき条件と`(no changes)`になる条件がちょうど一致する。畳み込みで生まれた親を
/// 子の1件だけを根拠に昇格させると、書込が要らない範囲まで広げてしまう。
fn expand(group: Group, granted: &crate::insufficient::GrantedPaths) -> Vec<Expanded> {
    let base_warnings = warnings_for(&group);

    // **昇格してよいのは、その提案を足しても何も増えないときだけ。**
    //
    // 判定に`value`の被覆だけを使うと、`fs.read`許可下の`fs.read_exec`提案まで置き換えてしまう
    // ——それは`apply`が`(no changes)`になる提案ではなく、**実行権を得る唯一の正解**である。
    // 置き換えれば、頼まれてもいない`fs.read_write`が並び（P-03の逆）、正解は2件のうちの1件へ
    // 薄まる。本decisionが宣言している「置き換えるべき条件と`(no changes)`になる条件が
    // ちょうど一致する」を成立させるには、**提案自身のkeyまで覆われているか**を見る必要がある。
    let covering = match group.key.fs_access() {
        // `net.allow_domains`にこの梯子は無い（FSのaccess種別の話である）。
        None => None,
        Some(requested) => granted
            .covering(&group.value)
            .filter(|granted| crate::insufficient::includes(*granted, requested)),
    };
    let Some(insufficient) = crate::insufficient::diagnose(covering) else {
        // 昇格しない場合でも、証拠の**一員**が許可済みなら注記だけは載せる（旧来の挙動）。
        // 親へ畳んだ提案そのものは広げないが、「この配下には既に許可済みで、なお拒否された
        // ものがある」は判断材料として残す価値がある。
        let mut warnings = base_warnings;
        if !granted.is_empty() {
            let from_evidence =
                group
                    .evidence
                    .iter()
                    .find_map(|candidate| match &candidate.requested {
                        Requested::Fs { path, .. } => {
                            crate::insufficient::diagnose(granted.covering(path))
                        }
                        Requested::Net { .. } => None,
                    });
            if let Some(from_evidence) = from_evidence {
                warnings.push(from_evidence.explain().to_string());
            }
        }
        return vec![Expanded {
            key: group.key,
            value: group.value,
            evidence: group.evidence,
            warnings,
        }];
    };

    // **昇格先を1つに決め打たない。** `read`許可下の拒否から言えるのは「書込・削除・実行の
    // いずれか」までで、どれかは決まらない（`FILE_EXECUTE`も`DELETE`も`FILE_GENERIC_READ`/
    // `FILE_GENERIC_WRITE`のどちらにも含まれない）。片方へ自動で寄せると、実行が目的だった
    // 場合に頼まれていない書込穴を提案することになり P-03 に反する。両方を並べて選ばせる
    // （D-42: 適用は常にユーザーの明示操作）。
    escalation_targets(&insufficient)
        .into_iter()
        .map(|(key, why)| {
            let mut warnings = base_warnings.clone();
            warnings.push(insufficient.explain().to_string());
            warnings.push(why.to_string());
            Expanded {
                key,
                value: group.value.clone(),
                evidence: group.evidence.clone(),
                warnings,
            }
        })
        .collect()
}

/// 「その許可では足りない」から導ける昇格先と、それを選ぶべき場面の説明。
fn escalation_targets(
    insufficient: &crate::insufficient::Insufficient,
) -> Vec<(SettingsKey, &'static str)> {
    use crate::insufficient::Insufficient;
    match insufficient {
        Insufficient::ReadWasNotEnough => vec![
            (
                SettingsKey::FsReadWrite,
                "accept this one if the failing operation writes, deletes or renames",
            ),
            (
                SettingsKey::FsReadExec,
                "accept this one instead if the failing operation runs a program from that path",
            ),
        ],
        Insufficient::ReadExecWasNotEnough => vec![(
            SettingsKey::FsReadWrite,
            "execute is already allowed here, so what is missing is write or delete",
        )],
        Insufficient::ReadWriteWasNotEnough => vec![(
            SettingsKey::FsReadExec,
            "write is already allowed here, so the failing operation is either running a program \
             or asking for a right this mechanism does not grant at all (taking ownership, \
             changing the ACL) -- in the latter case no settings change will help",
        )],
    }
}

/// 同じ`(key, value)`の観測をまとめたバケツ。**値は観測されたものそのまま**（D-62）。
struct Group {
    key: SettingsKey,
    value: String,
    evidence: Vec<DeniedCandidate>,
}

fn push_into_group(
    groups: &mut Vec<Group>,
    key: SettingsKey,
    value: String,
    candidate: DeniedCandidate,
) {
    if let Some(existing) = groups
        .iter_mut()
        .find(|g| g.key == key && g.value.eq_ignore_ascii_case(&value))
    {
        existing.evidence.push(candidate);
    } else {
        groups.push(Group {
            key,
            value,
            evidence: vec![candidate],
        });
    }
}

/// `key`を変えたら**必ず作り直さなければならない**警告だけを返す。
///
/// [`warnings_for`]と[`restate_access`]が共有する（片方だけが新しい注意書きを知っている状態を
/// 作らない、B-05）。ここに無い警告（一般化の広さ・ワイルドカード）はkeyに依存しない。
fn key_dependent_warnings(key: SettingsKey, evidence: &[DeniedCandidate]) -> Vec<String> {
    let mut warnings = Vec::new();

    if key == SettingsKey::FsReadWrite {
        warnings.push(
            "grants write access outside the workspace, which weakens write containment; \
             prefer fs.read unless a write was actually required"
                .to_string(),
        );
    }
    // **推定を推定として見せる**（`plans/etw-spike/RESULTS.md` §12.4 / §14.3）。
    //
    // OS監査（ETW）由来の`read`は「本当に読み取りだった」ではなく「**書込だと判る材料が
    // 無かった**」を意味する。ETWの`Create`は`DesiredAccess`を運ばず、`CreateDisposition`が
    // `FILE_OPEN`のときは読取・書込・削除の区別が付かないので、P-03に従って狭い側へ倒している。
    //
    // その結果、**削除できなくて困っている人に`fs.read`が提示される**ことが起こりうる。
    // 狭い側に外しているので安全だが、黙っていると「提案どおりにしたのに直らない」になる。
    // 正確な`AccessMask`はSecurity Audit 4656が持つが、購読経路も監査範囲も折り合わず
    // 採用しないと決めた（§14.3）。**精度の不足は注記で埋める。**
    if key == SettingsKey::FsRead
        && evidence
            .iter()
            .any(|candidate| candidate.source == Source::Etw)
    {
        warnings.push(
            "this came from OS auditing, which cannot tell read from write/delete when the \
             request only opened an existing file -- 'read' is the conservative guess, not an \
             observation. If what you are trying to allow is a write, a delete or a rename, \
             accept fs.read_write instead"
                .to_string(),
        );
    }

    warnings
}

fn warnings_for(group: &Group) -> Vec<String> {
    let mut warnings = key_dependent_warnings(group.key, &group.evidence);

    // 値にワイルドカードが入りうるのは、**ユーザーが手で書いた宣言**がpreflight由来の候補として
    // 戻ってくる経路だけである（D-62で一般化を廃止したので、harnessが`*`を作ることはない）。
    // `approve::grant_root`は最初の`*`の手前で切るため、ACEはその親ディレクトリ全体に付く。
    if group.value.contains('*') {
        warnings.push("contains a wildcard; review how wide it is before accepting".to_string());
    }

    warnings
}

#[cfg(test)]
#[path = "generalize_tests.rs"]
mod generalize_tests;
