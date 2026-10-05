//! 中間ステップ——記録した候補のうちどれを許すかをユーザーが**明示的に**選び、
//! [`crate::policy_file`]（`policy.json`）へ書く（D-42: 反映は常にユーザーの明示操作）。
//!
//! # ここではACEを付けない
//!
//! 付与経路は`win_appcontainer::preflight`ただ1つに保つ。承認が独自にACEを付けると
//! **付与経路が2つになり**、片方だけが台帳へ記録する／片方だけが撤収できる、という形の
//! 事故になる（BUG-017の孤立ACEと同型）。承認は「次のパス2でこの穴を開ける」という宣言で、
//! 実際の付与と台帳への記録は[`crate::record_net`]がpreflight経由で行う。
//!
//! # 部分適用しない
//!
//! 未知のidが1件でもある、`--require-sandbox`と矛盾する提案が1件でもある、広すぎる値が
//! 1件でもある——いずれの場合も**何も書かずに失敗する**。設定は「後から効いてくる」対象で、
//! 「一部だけ通った」状態はユーザーが受け入れたつもりの構成と実際の構成をずらす
//! （`harness policy apply`と同じ判断）。
//!
//! # 判定は既存の純粋関数をそのまま使う
//!
//! - [`harness_policy::gate::check_proposal`]（D-42、`--require-sandbox`との矛盾）
//! - [`harness_policy::breadth::check`]（D-47、`C:/`のような広すぎる値）
//!
//! 承認の経路を別に作るからといって判定を書き直さない——書き直すと片方だけが緩む。
//!
//! # 「決める」と「書く」を分ける
//!
//! [`plan`]は何も書かずに結果（受理した提案・書き込む予定の内容・差分・パスの分類）を返し、
//! [`commit`]がそれを書く。CLIは間で差分を見せて確認を取り、TUIは同じ2段を別のUIで使う。

use std::path::Path;

use harness_core::RequireSandbox;
use harness_policy::{breadth, gate, generalize::SettingsKey, GateVerdict, RuleProposal};

use crate::policy_file::{self, ApprovalContext, MergeReport, PolicyFile};

/// 承認の要求。
pub struct ApproveRequest<'a> {
    pub workspace_root: &'a Path,
    /// `show`が出したのと**同じ**提案一覧（同じ畳み込みで作ったもの）。
    pub proposals: &'a [RuleProposal],
    /// `--accept`で指定されたid（カンマ区切りは呼び出し側で展開済み）。
    pub accept_ids: &'a [String],
    pub require_sandbox: RequireSandbox,
    pub domain: &'a str,
    pub command: Option<&'a str>,
    pub cwd: Option<&'a Path>,
    pub record_session: Option<&'a str>,
    pub now_unix_ms: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ApproveError {
    #[error(
        "承認するidを1つ以上指定してください（--accept <id>[,<id>...]）。idは `show` の出力に\
         あります。**全件受理のショートハンドは意図的に用意していません**（D-42）"
    )]
    NoIds,
    #[error("知らない提案id: {0}。idは `show` の出力から取ってください")]
    UnknownIds(String),
    #[error("承認できません（何も書いていません）:\n{0}")]
    Refused(String),
    #[error(transparent)]
    PolicyFile(#[from] policy_file::PolicyFileError),
    /// `policy.json`は書けたが、このマシンでの承認（D-112）を台帳へ記録できなかった。
    ///
    /// **成功と言わない。** 記録できなかった宣言は未承認のままなので、次の試験実行でも
    /// `harness.exe`でも許可が付かない——「承認したのに効かない」の原因がここで出ないと辿れない。
    #[error(
        "policy.json には書きましたが、このマシンでの承認を台帳へ記録できませんでした: {0}\n\
         これらの宣言は、承認し直すまで許可が付きません（台帳: %APPDATA%\\harness\\config\\policy-approval-ledger.json）"
    )]
    ApprovalNotRecorded(String),
}

/// 受理した提案のうち、その値がworkspaceのどちら側にあるか。
///
/// **承認の実質的な判断材料**である。Tier2aはworkspaceツリーへは既にACEを付けているので、
/// workspace内のパスに新しく穴を開ける必要は無い。実際にマシンのACLを変えるのは
/// workspace**外**の分だけである。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathClass {
    /// workspace配下。Tier2aのworkspace grantが既に覆う（ACEの追加は不要）。
    InsideWorkspace,
    /// workspace外。パス2でこのルートへ実際にACEを付ける（マシンに残る変更）。
    OutsideWorkspace,
    /// パスではない（`net.allow_domains`）。
    NotFilesystem,
}

/// 書く前に決まったこと一式。
#[derive(Debug)]
pub struct ApprovePlan<'a> {
    pub accepted: Vec<&'a RuleProposal>,
    /// 承認するドメイン（[`commit`]が承認台帳へ記録する鍵の1つ）。
    pub domain: &'a str,
    /// 書き込む予定の内容（[`commit`]がそのまま保存する）。
    pub file: PolicyFile,
    pub report: MergeReport,
    /// 受理した提案ごとの分類（`accepted`と同じ並び）。
    pub classes: Vec<PathClass>,
    /// 拒否ではないが読んでおくべきこと（`gate`の警告）。
    pub warnings: Vec<String>,
}

impl ApprovePlan<'_> {
    /// マシンのACLを実際に変えることになる提案の件数（workspace外）。
    pub fn outside_workspace_count(&self) -> usize {
        self.classes
            .iter()
            .filter(|c| **c == PathClass::OutsideWorkspace)
            .count()
    }
}

/// 受理するidを解決し、検査を通し、`policy.json`へのマージ結果まで作る。**何も書かない。**
///
/// 中身は[`validate`]（idの照合と2軸の検査）→ `policy_file::load` → `merge_approved` → [`grant_root_warnings`]の
/// 包みである（2026-10-05、`plans/position-domains/P4.md`のP4.5の準備。位置ごとのドメインの確定が
/// 同じ部品をドメインごとに通すため）。
pub fn plan<'a>(req: &ApproveRequest<'a>) -> Result<ApprovePlan<'a>, ApproveError> {
    let Validated {
        accepted,
        classes,
        mut warnings,
    } = validate(
        req.proposals,
        req.accept_ids,
        req.require_sandbox,
        req.workspace_root,
    )?;

    let mut file = policy_file::load(req.workspace_root)?;
    let report = file.merge_approved(
        &accepted,
        &ApprovalContext {
            domain: req.domain,
            command: req.command,
            cwd: req.cwd,
            record_session: req.record_session,
            now_unix_ms: req.now_unix_ms,
        },
    );
    warnings.extend(grant_root_warnings(
        &file,
        req.domain,
        req.workspace_root,
        &accepted,
    ));

    Ok(ApprovePlan {
        accepted,
        domain: req.domain,
        file,
        report,
        classes,
        warnings,
    })
}

/// [`validate`]が通したもの。
pub(crate) struct Validated<'a> {
    /// 受理した提案（指定の順、重複は1つ）。
    pub accepted: Vec<&'a RuleProposal>,
    /// 受理した提案ごとの分類（`accepted`と同じ並び）。
    pub classes: Vec<PathClass>,
    /// 拒否ではないが読んでおくべきこと（`gate`の警告）。
    pub warnings: Vec<String>,
}

/// 受理するidを解決し、`gate`（`--require-sandbox`との矛盾）と`breadth`（広すぎる値）の2軸の検査を通す
/// （**何も読まない・書かない**）。1件でも通らなければ何も受理しない（部分適用しない、モジュールdoc）。
pub(crate) fn validate<'a>(
    proposals: &'a [RuleProposal],
    accept_ids: &[String],
    require_sandbox: RequireSandbox,
    workspace_root: &Path,
) -> Result<Validated<'a>, ApproveError> {
    if accept_ids.is_empty() {
        return Err(ApproveError::NoIds);
    }

    let mut accepted: Vec<&RuleProposal> = Vec::new();
    let mut unknown: Vec<&str> = Vec::new();
    for id in accept_ids {
        match proposals.iter().find(|p| &p.id == id) {
            Some(proposal) => {
                if !accepted.iter().any(|p| p.id == proposal.id) {
                    accepted.push(proposal);
                }
            }
            None => unknown.push(id.as_str()),
        }
    }
    if !unknown.is_empty() {
        return Err(ApproveError::UnknownIds(unknown.join(", ")));
    }

    // 2軸の拒否を1箇所へ集める。どちらも**部分適用しない**（1件でも該当なら何も書かない）。
    // 軸を分けたまま両方を通すのは、拒否された理由がユーザーから見て別物だからである
    // （前者は自分の宣言との矛盾、後者は値そのものの広さ）。
    let mut refused = Vec::new();
    let mut warnings = Vec::new();
    for proposal in &accepted {
        match gate::check_proposal(proposal, require_sandbox) {
            GateVerdict::Rejected(message) => refused.push(format!("{}: {message}", proposal.id)),
            GateVerdict::AllowedWithWarning(message) => {
                warnings.push(format!("{}: {message}", proposal.id))
            }
            GateVerdict::Allowed => {}
        }
        if let Some(message) = breadth::check(proposal).message() {
            refused.push(format!("{}: {message}", proposal.id));
        }
    }
    if !refused.is_empty() {
        return Err(ApproveError::Refused(
            refused
                .iter()
                .map(|line| format!("  {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
        ));
    }

    let classes = accepted
        .iter()
        .map(|p| classify(p, workspace_root))
        .collect();

    Ok(Validated {
        accepted,
        classes,
        warnings,
    })
}

/// 承認した後にこのドメインのworkspace外のルートが多くなるなら、その警告（多くなければ空）。**何も書かない。**
///
/// `file`はマージした**後**の`policy.json`、`accepted`はいま承認する提案（[`validate`]が通したもの）。
pub(crate) fn grant_root_warnings(
    file: &PolicyFile,
    domain: &str,
    workspace_root: &Path,
    accepted: &[&RuleProposal],
) -> Vec<String> {
    // **承認の結果が次のパス2の待ち時間になる、ということをこの瞬間に見せる。**
    // `preflight`はworkspace外のルートを1件ずつ処理するので、準備時間はこの件数にほぼ比例する。
    // 件数はマージ**後**のドメイン全体で数える（この承認で足した分だけでなく、次のパス2が
    // 実際に処理する数そのもの）。一般化して畳めば減らせる、という行動もここで伝える
    // ——数だけ出して「どうすればいいか」を書かないのは、警告として半分しか役に立たない（B-32）。
    // 件数の定義は付与の一覧を作る関数（`harness.exe`とパス2が共有する）が唯一持つ（B-05）。
    // [D-112] 数えるのは**この承認の後に許可が付くもの**——既に承認済みの宣言と、いま承認する値。
    let approvals = crate::approval_store::approval_store().load();
    let workspace_key =
        harness_sandbox::tier2a::policy_approval::approval_workspace_key(workspace_root);
    let approved_after_commit = |d: harness_sandbox::tier2a::policy_approval::DeclarationRef<'_>| {
        approvals.is_approved_for_key(&workspace_key, d)
            || (d.domain == domain
                && accepted
                    .iter()
                    .any(|p| p.value == d.value && p.key.fs_access() == Some(d.access)))
    };
    let grant_roots = file
        .domain(domain)
        .map(|entry| {
            harness_sandbox::tier2a::policy_grants::GrantContext::for_workspace(workspace_root)
                .domain_grants(entry, &approved_after_commit)
                .passthrough
                .len()
        })
        .unwrap_or(0);
    if grant_roots < MANY_GRANT_ROOTS {
        return Vec::new();
    }
    vec![format!(
        "このドメインのworkspace外のルートは{grant_roots}件になります。パス2はこれを1件ずつ\
         処理するので、準備に時間がかかります（承認前に一般化の度合いを上げて畳むと減ります）"
    )]
}

/// 「workspace外のルートが多い」と警告し始める件数。
///
/// 根拠は`preflight`の実測——1件あたりのACL読取・付与・台帳更新は数ms程度だが、件数に比例して
/// 積み上がる。数十件までは体感できないので、**数百件のオーダーに入るところ**で線を引く。
/// 正確な閾値そのものに意味は無く、「気付かないうちに桁が変わっていた」ことを知らせるのが目的。
const MANY_GRANT_ROOTS: usize = 100;

/// [`plan`]の結果を実際に書き込む。
///
/// # [D-112] このマシンでの承認を記録するのは、**今回受け入れた値だけ**
///
/// `policy.json`全体を記録すると、候補を1件承認しただけで、同じファイルにある**同梱の
/// 未承認の宣言まで承認したことになる**（一括承認の抜け道。決定51が禁じている形）。
/// 記録は`policy.json`を書いた**後**に行う——先に記録して保存が落ちると、無い宣言の承認が残る。
pub fn commit(workspace_root: &Path, plan: &ApprovePlan<'_>) -> Result<(), ApproveError> {
    policy_file::save(workspace_root, &plan.file)?;
    let declarations = accepted_declarations(plan);
    if declarations.is_empty() {
        return Ok(());
    }
    let not_recorded =
        crate::approval_store::approval_store().approve(workspace_root, &declarations);
    if !not_recorded.is_empty() {
        return Err(ApproveError::ApprovalNotRecorded(
            not_recorded
                .iter()
                .map(|d| format!("{} ({}) in {}", d.value, d.access.settings_key(), d.domain))
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    Ok(())
}

/// 今回受け入れた提案のうち、ファイル宣言のもの（承認台帳の鍵の形）。
///
/// 値は提案の値そのまま——`merge_approved`は値を書き換えずに`policy.json`へ書くので、
/// ここで記録する値と`policy.json`に書かれる値は同じ文字列になる（`R`で付けた`/**`も、
/// 提案の側に合成済みで来る）。
fn accepted_declarations<'p>(
    plan: &'p ApprovePlan<'_>,
) -> Vec<harness_sandbox::tier2a::policy_approval::DeclarationRef<'p>> {
    plan.accepted
        .iter()
        .filter_map(|proposal| {
            proposal.key.fs_access().map(|access| {
                harness_sandbox::tier2a::policy_approval::DeclarationRef {
                    domain: plan.domain,
                    value: &proposal.value,
                    access,
                }
            })
        })
        .collect()
}

/// 差分を**access種別ごとにまとめて**並べる。
///
/// `+ fs.read = <パス>`を1行ずつ出すと、687件では同じ`fs.read =`が687回並び、
/// 「どの種別を何件許すのか」という一番知りたいことが読み取れない。種別を見出しにして
/// パスをぶら下げる。
///
/// **既にある分は件数だけ**にする——変更ではないので明細を出しても判断は変わらず、
/// これから増える分（＝承認の対象）が埋もれる。中身が知りたければ`policy.json`そのものを読む。
///
/// 承認待ちの確認ダイアログ（`tui::edit_commit`）と、位置ごとのドメインの確定の明細（`crate::position_approve`。
/// 画面と CLI）が同じこれを通す。2026-10-05に`tui::edit_commit`から**そのまま**移した（P4.5 の準備）。
pub(crate) fn group_by_key(
    added: &[(&'static str, String)],
    already_present: &[(&'static str, String)],
) -> Vec<String> {
    // 表示順は`SettingsKey`の並び（read → read_write → read_exec → net）に合わせて固定する
    // ——実行のたびに順序が変わると差分を見比べられない。
    const ORDER: &[&str] = &[
        "fs.read",
        "fs.read_write",
        "fs.read_exec",
        "net.allow_domains",
    ];
    let mut lines = Vec::new();

    for key in ORDER {
        let values: Vec<&str> = added
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect();
        if values.is_empty() {
            continue;
        }
        lines.push(String::new());
        lines.push(format!("  {key}  ＋{}件", values.len()));
        for value in values {
            lines.push(format!("      {value}"));
        }
    }

    let mut present_lines = Vec::new();
    for key in ORDER {
        let count = already_present.iter().filter(|(k, _)| k == key).count();
        if count > 0 {
            present_lines.push(format!("  {key}  {count}件は既にあります（変更なし）"));
        }
    }
    if !present_lines.is_empty() {
        lines.push(String::new());
        lines.extend(present_lines);
    }

    lines
}

/// 提案の値がworkspaceのどちら側にあるかを判定する。配下判定の実体は
/// [`harness_sandbox::tier2a::policy_grants::is_under`]（付与の一覧を作る側と同じ規則を通す）。
fn classify(proposal: &RuleProposal, workspace_root: &Path) -> PathClass {
    if proposal.key == SettingsKey::NetAllowDomains {
        return PathClass::NotFilesystem;
    }
    if harness_sandbox::tier2a::policy_grants::is_under(&proposal.value, workspace_root) {
        PathClass::InsideWorkspace
    } else {
        PathClass::OutsideWorkspace
    }
}

#[cfg(test)]
#[path = "approve_tests.rs"]
mod approve_tests;

#[cfg(test)]
#[path = "approve_grant_roots_tests.rs"]
mod approve_grant_roots_tests;
