//! 拒否候補を許可ルールの候補へ一般化する（`plans/DESIGN-SANDBOX-APPPOLICY.md` §11.3）。
//!
//! 具体パスを1件ずつ並べても人は判断できない。同じディレクトリ配下への多数の拒否は1本の
//! プレフィックスルールへ、バージョン番号やハッシュを含むパスはワイルドカードへ畳む。
//! 一般化の度合いは[`Generalization`]で選べる——広げるほど楽になるが、その分だけ
//! 頼んでいない場所まで開くので、**選ぶのはユーザーである**。
//!
//! # 意図的にしないこと
//!
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

/// 一般化の度合い。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Generalization {
    /// 畳まない。拒否された対象をそのまま1件1提案にする。最も狭く、最も安全。
    None,
    /// 同一ディレクトリ配下に2件以上の拒否があれば、その親ディレクトリ1本へ畳む。
    #[default]
    Directory,
    /// [`Generalization::Directory`]に加えて、バージョン番号・ハッシュらしきパス要素を
    /// `*`へ置き換える。ツールチェーン（`.rustup/toolchains/<version>/`等）のように
    /// 更新のたびにパスが変わる置き場を1本で書けるようにする。
    Auto,
}

impl Generalization {
    pub fn parse(s: &str) -> Option<Generalization> {
        match s {
            "none" => Some(Generalization::None),
            "dir" | "directory" => Some(Generalization::Directory),
            "auto" => Some(Generalization::Auto),
            _ => None,
        }
    }
}

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
    /// 同じ入力・同じ[`Generalization`]なら常に同じidになる（並びが決定的なため）。
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
pub fn generalize(candidates: &[DeniedCandidate], mode: Generalization) -> Vec<RuleProposal> {
    generalize_with_granted(
        candidates,
        mode,
        &crate::insufficient::GrantedPaths::default(),
    )
}

/// [`generalize`]に「既に設定で許可済みのパス」を教える版。
///
/// **既に許可済みなのに拒否された＝その許可では足りない**が確定するので、提案へその旨を載せる
/// （`plans/etw-spike/RESULTS.md` §15、実機の真理値表で前提を確認済み）。これは4656に頼らずに
/// 精度を上げられる唯一の経路で、根拠は推測ではなくWindowsのアクセスチェックの性質
/// （`DesiredAccess ⊆ granted`）そのものである。
pub fn generalize_with_granted(
    candidates: &[DeniedCandidate],
    mode: Generalization,
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

    if mode != Generalization::None {
        groups = fold_fs_groups_by_directory(groups);
    }
    if mode == Generalization::Auto {
        groups = wildcard_volatile_segments(groups);
    }

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
/// # なぜ展開前の[`merge_same_value`]では足りないのか
///
/// あちらは`Group`（＝観測されたaccessごとのバケツ）を畳む。ところが同じ`(key, value)`は
/// **別々のGroupからも生まれる**——
///
/// - `fs.read`のGroupが[`expand`]の昇格で`fs.read_exec`になったもの
/// - 最初から`fs.read_exec`として観測／導出されたGroup（ポリシーエディタの実行像・実行前診断）
///
/// 畳まずに並べると、`merge_same_value`のdocが警告しているのと同じ状態
/// （**同じ設定値の提案がidだけ違う形で2行並び、観測回数も割れる**）が展開後に再現する。
/// 片方を承認しても、もう片方が未承認のまま一覧に残って見える。
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

struct Group {
    key: SettingsKey,
    value: String,
    evidence: Vec<DeniedCandidate>,
    /// 一般化で畳んだ結果か（`warnings`の文言と、畳み込みの再適用を分けるために持つ）。
    generalized_from: Vec<String>,
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
            generalized_from: Vec::new(),
        });
    }
}

/// 同一キー・同一親ディレクトリに**2件以上**の異なるパスがあれば親ディレクトリ1本へ畳む。
/// 1件しか無いディレクトリを畳まないのは、それをやると「1つのファイルが拒否されただけで
/// ディレクトリ全体を開く提案」になり、一般化が常に権限を広げる方向にしか働かなくなるため。
fn fold_fs_groups_by_directory(groups: Vec<Group>) -> Vec<Group> {
    let mut out: Vec<Group> = Vec::new();
    let mut by_parent: Vec<(SettingsKey, String, Vec<Group>)> = Vec::new();

    for group in groups {
        if group.key == SettingsKey::NetAllowDomains {
            out.push(group);
            continue;
        }
        let parent = parent_dir(&group.value);
        match parent {
            Some(parent) => {
                if let Some(slot) = by_parent
                    .iter_mut()
                    .find(|(k, p, _)| *k == group.key && p.eq_ignore_ascii_case(&parent))
                {
                    slot.2.push(group);
                } else {
                    by_parent.push((group.key, parent, vec![group]));
                }
            }
            None => out.push(group),
        }
    }

    for (key, parent, members) in by_parent {
        if members.len() < 2 {
            out.extend(members);
            continue;
        }
        // **畳み込みで作ってよい値かを`breadth`に聞く。** `C:/Program Files/Git`と
        // `C:/Program Files/GitHub CLI`を親へ畳むと`C:/Program Files`になるが、
        // 「Gitとgh に触った」から**推論で**マシン規模のディレクトリへ広げるのは一般化の役目では
        // ない。しかも畳むと**畳まれた子（それぞれは承認できる値）が一覧から消える**ので、
        // 選べる候補が1件も残らなくなる。判定は最も厳しいaccessで見る
        // （ユーザーが自分で`fs.read = C:/Program Files`を選ぶ道は残る——直接観測されれば
        // 候補として出るし、そちらは`breadth`が読みを許す）。
        if crate::breadth::is_too_broad_for_any_access(&parent) {
            out.extend(members);
            continue;
        }
        let mut evidence = Vec::new();
        let mut generalized_from = Vec::new();
        for member in members {
            generalized_from.push(member.value);
            evidence.extend(member.evidence);
        }
        generalized_from.sort();
        out.push(Group {
            key,
            value: parent,
            evidence,
            generalized_from,
        });
    }

    // **畳んだ先と同じ値のグループが既に居ることがある。** ディレクトリ自身への観測
    // （`C:/.cargo`を直接開いた）は`C:/`をキーにした別のバケツへ入るので、その配下を
    // 畳んで出来た`C:/.cargo`とは合流しない。設定値としては同一なので、ここで1つへ畳む。
    merge_same_value(out)
}

/// 同じ`(key, value)`のグループを1つへ畳む。
///
/// 分かれたまま残すと、**同じ設定値の提案がidだけ違う形で2行並び、観測回数も割れて**
/// どちらも実数より小さく見える（片方を承認しても、もう片方が未承認のまま残って見える）。
/// 畳み込み（親への集約）とワイルドカード化の**両方**が同じ値を作り得るので、1箇所に持つ。
fn merge_same_value(groups: Vec<Group>) -> Vec<Group> {
    let mut out: Vec<Group> = Vec::new();
    for group in groups {
        match out
            .iter_mut()
            .find(|g| g.key == group.key && g.value.eq_ignore_ascii_case(&group.value))
        {
            Some(existing) => {
                existing.evidence.extend(group.evidence);
                existing.generalized_from.extend(group.generalized_from);
            }
            None => out.push(group),
        }
    }
    for group in &mut out {
        group.generalized_from.sort();
        group.generalized_from.dedup();
    }
    out
}

/// バージョン番号・ハッシュらしきパス要素を`*`へ置換する。置換後に同じ値になったグループは畳む。
fn wildcard_volatile_segments(groups: Vec<Group>) -> Vec<Group> {
    let mut out: Vec<Group> = Vec::new();

    for mut group in groups {
        if group.key == SettingsKey::NetAllowDomains {
            out.push(group);
            continue;
        }
        let wildcarded = wildcard_path(&group.value);
        if wildcarded != group.value {
            group.generalized_from.push(group.value.clone());
            group.value = wildcarded;
        }
        out.push(group);
    }

    // 置換後に同じ値になったグループを畳む（畳み込み側と同じ関数を通す）。
    merge_same_value(out)
}

/// パスの親ディレクトリ（`/`区切り前提。正規化は[`crate::normalize`]が済ませている）。
/// ドライブルート（`C:/`）とその直下は畳まない——`C:/`まで一般化する提案は、
/// サンドボックスの意味そのものを消す（T-16）ので出さない。
fn parent_dir(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches('/');
    let idx = trimmed.rfind('/')?;
    let parent = &trimmed[..idx];
    // `C:` / 空 / `/` / UNCのホスト部分（`//host`）は親として採らない。
    if parent.is_empty() || parent.ends_with(':') || parent == "/" {
        return None;
    }
    if parent.starts_with("//") && parent[2..].find('/').is_none() {
        return None;
    }
    Some(parent.to_string())
}

/// バージョン番号らしい要素（`1.2.3`・`v2`・`stable-x86_64-pc-windows-msvc`は除く）か、
/// 16進ハッシュらしい要素（8文字以上の`[0-9a-f]`）を`*`にする。
fn wildcard_path(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            if is_volatile_segment(segment) {
                "*"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn is_volatile_segment(segment: &str) -> bool {
    if segment.len() < 2 {
        return false;
    }
    if is_hex_hash(segment) {
        return true;
    }
    is_version_like(segment)
}

/// 8文字以上・全て16進数字・数字を1文字以上含む（`deadbeef`のような英字のみの単語も
/// 16進として成立するが、`cabbage`等の実在する語を巻き込みたくないので数字を必須にする）。
fn is_hex_hash(segment: &str) -> bool {
    segment.len() >= 8
        && segment.chars().all(|c| c.is_ascii_hexdigit())
        && segment.chars().any(|c| c.is_ascii_digit())
}

/// `1.2.3` / `v1.2` / `2024-01` のような、数字とごく一部の区切りだけで構成された要素。
/// 英字を含む要素（`stable-x86_64-pc-windows-msvc`・`node_modules`）は対象外——
/// 意味のある名前をワイルドカードで潰すと、提案が一気に広がりすぎる。
fn is_version_like(segment: &str) -> bool {
    let body = segment.strip_prefix('v').unwrap_or(segment);
    if body.is_empty() {
        return false;
    }
    let mut has_digit = false;
    for c in body.chars() {
        if c.is_ascii_digit() {
            has_digit = true;
        } else if c != '.' && c != '-' && c != '_' {
            return false;
        }
    }
    has_digit
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

    if !group.generalized_from.is_empty() {
        warnings.push(format!(
            "generalized from {} observed path(s): {}",
            group.generalized_from.len(),
            group.generalized_from.join(", ")
        ));
    }
    if group.value.contains('*') {
        warnings.push("contains a wildcard; review how wide it is before accepting".to_string());
    }

    warnings
}

#[cfg(test)]
#[path = "generalize_tests.rs"]
mod generalize_tests;
