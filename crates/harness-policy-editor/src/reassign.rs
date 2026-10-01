//! 宣言の付け替え（宣言画面の`c`・`R`）——`policy.json`にある**ファイル宣言1件の種類（access）と
//! `**`の有無**を変える。
//!
//! # 何のためにあるのか
//!
//! 取り消し（[`crate::unapprove`]）ができてからも、「`fs.read`で承認したが実行ファイルだった」
//! 「`**`で広げすぎた」を直すには、宣言を取り消してから記録を開き直し、候補を承認し直すしかなかった。
//! 付け替えはその2手を1手にする。
//!
//! **変えられるのは種類と`**`だけ**で、パスの文字列を打ち替える編集は作らない——候補画面の`c`・`R`
//! （決定47・D-63）と同じ範囲に揃える。パスを自由に打てると、観測に基づかない値が`policy.json`へ入る
//! （D-62: 値は観測されたとおりに書き、広げる意思は`**`と書くことでしか表さない）。
//!
//! # 承認の状態は引き継ぐ（D-112）
//!
//! 付け替えた後の値は、**元の宣言がこのマシンで承認済みだったときだけ**承認済みとして台帳へ記録し、
//! 元の値の承認は消す。未承認の宣言を付け替えても、付け替えた後の値は未承認のまま（`y`で承認する）。
//! 付け替えで承認が**生まれる**ことは無いので、一括承認の抜け道にならない（決定51）。
//!
//! 広がる向き（`read`→`read_write`、素のパス→`**`）も承認を引き継ぐ。候補画面の`c`で手で変えた値を
//! 同じ確定の中で承認するのと同じ判断である（決定47）——1行ずつ押させ、確認の画面に
//! 「広がる」と別建てで出してから書く。
//!
//! # 承認と同じ幅の検査を通す
//!
//! 付け替えた後の値は[`crate::approve_declared::ApprovalChecks`]（候補にしない規則・許可を付けない値・
//! `--require-sandbox`との矛盾・広すぎる値）を通す。**元の宣言が未承認でも掛ける**——この経路が
//! 書く値は、`y`で承認できる値に限る（`y`が断る値を付け替えで作らない）。
//!
//! # ACEはここでは触らない（[`ACE_NOTICE`]）
//!
//! 取り消しと同じ理由（付与がパス2の開始時と`harness.exe`の起動時なので、変化も同じ点で効かせる。
//! 決定48）で、ここが書くのは`policy.json`と承認台帳だけである。**ただし付け替えでは前の値のACEが
//! 撤収されない**——撤収は「もう宣言されていないパス」単位（`record_net::stale_roots`）で、付け替えは
//! パスを変えないからである。効き目が無くなるかどうかは、何を変えたかで分かれる:
//!
//! | 変えたもの | 前の値のACE | 根拠 |
//! |---|---|---|
//! | 種類 | パスに残るが効かない | 宛先SIDは`(ワークスペース, パス, 種類)`ごとに導出され（`workspace_capability::ensure_declaration_capability_in`）、子へ積むのは付与処理がいま返した宛先SIDだけ（`launch::declaration_caps`） |
//! | `**`を付けた | 付与処理が継承ACEへ書き直す | `preflight`は継承フラグまで見て足りるかを判定する（`ExplicitAce::satisfies`） |
//! | `**`を外した（種類は同じ） | **配下へ付いた継承ACEが残り、効き続ける** | `preflight`は狭めない（既に配下へ降りたコピーは消えないため）。警告を出し、`harness fs revoke <パス>`を案内する |
//!
//! # 「決める」と「書く」を分ける
//!
//! [`plan`]は何も書かずに結果を返し、[`commit`]が書く（`approve`・`unapprove`・`approve_declared`と同じ2段）。

use std::path::Path;

use harness_core::RequireSandbox;
use harness_policy::generalize::SettingsKey;
use harness_policy::normalize::{declared_scope, has_unsupported_wildcard};
use harness_policy::RuleProposal;
use harness_sandbox::tier2a::policy_approval::{approval_workspace_key, DeclarationRef};

use crate::approve_declared::{stored_spelling, ApprovalChecks};
use crate::policy_file::{self, ApprovalContext, PolicyFile, PolicyFileError};
use crate::unapprove::UnapproveTarget;

/// 付け替えがACEに何をするのかの説明。**この文言の持ち主はここだけ**（確認の画面がこれを出す）。
///
/// 中身の根拠はモジュールdocの表。
pub const ACE_NOTICE: &str = concat!(
    "注: 付け替えは policy.json と承認台帳を書くだけで、ACLはまだ変わりません。付け替えた後の値の\n",
    "    許可は、次にパス2（record-net）を開始したとき、または harness.exe を起動したときに付きます。\n",
    "    種類を変えた場合、前の種類のACEはパスに残りますが、その宛先SIDはもう子へ渡らないので効きません。\n",
    "    ** を外した場合、種類が同じなら配下へ付いた継承ACEは残って効き続けます\n",
    "    （閉じるには harness fs revoke <パス> を実行してください）。"
);

/// 付け替え1件の指定。**ドメインは変えられない**（`from`のドメインのまま）——ドメインは承認台帳の
/// 鍵の1つで、別ドメインへ移すのは「別の子へ許可を渡す」ことだからである（D-112の「1件の鍵」）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reassignment {
    /// `policy.json`の行（付け替える前）。
    pub from: UnapproveTarget,
    /// 付け替えた後の種類。
    pub key: SettingsKey,
    /// 付け替えた後の値。
    pub value: String,
}

impl Reassignment {
    /// 付け替えた後の宣言。
    pub fn to(&self) -> UnapproveTarget {
        UnapproveTarget {
            domain: self.from.domain.clone(),
            key: self.key,
            value: self.value.clone(),
        }
    }
}

/// 書く予定の付け替え1件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedReassignment {
    /// 元の宣言（`policy.json`に書いてあるとおりの綴り）。
    pub from: UnapproveTarget,
    pub to: UnapproveTarget,
    /// 元の宣言より権限が広がるか（[`widens`]）。確認の画面で別建てにするためだけに持つ。
    pub widens: bool,
    /// 元の宣言がこのマシンで承認済みで、付け替えた後の値へ承認を引き継ぐか。
    pub carries_approval: bool,
}

/// 1回の付け替えで何が起きるか。**「付け替える」「断った」「無かった」を必ず分ける**（B-09）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReassignPlan {
    /// 書き込む予定の`policy.json`（[`commit`]がこれを保存する）。
    pub file: PolicyFile,
    pub changes: Vec<PlannedReassignment>,
    /// 付け替えない指定と、その理由。
    pub refused: Vec<(Reassignment, String)>,
    /// 元の宣言が`policy.json`に無かった指定。
    pub not_found: Vec<Reassignment>,
}

#[derive(Debug, thiserror::Error)]
pub enum ReassignError {
    #[error(transparent)]
    PolicyFile(#[from] PolicyFileError),
    /// `policy.json`は書けたが、承認台帳を更新しきれなかった。
    ///
    /// **成功と言わない。** 記録できなかった承認は「付け替えたのに許可が付かない」、消せなかった
    /// 承認は「同じ値が後で`policy.json`に戻ると承認済みとして付く」になる。
    #[error(
        "policy.json には書きましたが、このマシンでの承認台帳を更新しきれませんでした: {0}\n\
         （台帳: %APPDATA%\\harness\\config\\policy-approval-ledger.json）"
    )]
    LedgerIncomplete(String),
}

/// 付け替えの内容を決める（**何も書かない**）。
///
/// `approved_in_same_commit`は、**同じ確定で先に承認する宣言**（宣言画面の`y`で予約した分）。
/// 確認の画面を出す時点ではまだ台帳に無いので、それを渡さないと「承認してから付け替える」の
/// 結果を「未承認のまま」と見せてしまう（`approve::plan`の件数の警告が「今回承認する値も
/// 承認済みとみなす」のと同じ形）。書く時点では承認が先に台帳へ入っているので空でよい。
pub fn plan(
    workspace_root: &Path,
    reassignments: &[Reassignment],
    require_sandbox: RequireSandbox,
    approved_in_same_commit: &[UnapproveTarget],
) -> Result<ReassignPlan, ReassignError> {
    let original = policy_file::load(workspace_root)?;
    let mut file = original.clone();
    let approvals = crate::approval_store::approval_store().load();
    let workspace_key = approval_workspace_key(workspace_root);
    let checks = ApprovalChecks::for_workspace(workspace_root, require_sandbox);
    // 衝突を見る相手。**元の宣言は消えた後も残しておく**——付け替えた後の値が別の付け替えの
    // 元の値と同じになる（入れ替え）と、書く順で結果が変わるので断る側に倒す。
    let mut existing = crate::unapprove::all_targets(&original);
    let mut seen: Vec<UnapproveTarget> = Vec::new();
    let now_unix_ms = crate::session_dir::now_unix_ms();

    let mut out = ReassignPlan::default();
    for reassignment in reassignments {
        let Some(from) = stored_spelling(&original, &reassignment.from) else {
            out.not_found.push(reassignment.clone());
            continue;
        };
        if seen.contains(&from) {
            out.refused.push((
                reassignment.clone(),
                "同じ宣言を2回付け替えようとしています".to_string(),
            ));
            continue;
        }
        if let Some(reason) = refusal(
            &checks,
            &existing,
            &from,
            reassignment.key,
            &reassignment.value,
        ) {
            out.refused.push((reassignment.clone(), reason));
            continue;
        }
        let to = UnapproveTarget {
            domain: from.domain.clone(),
            key: reassignment.key,
            value: reassignment.value.clone(),
        };
        let carries_approval = from.declaration().is_some_and(|declaration| {
            approvals.is_approved_for_key(&workspace_key, declaration)
        }) || approved_in_same_commit
            .iter()
            .any(|approved| same_declaration(approved, &from));

        // 元の値を消す規則は取り消しと同じ関数、足す規則は承認と同じ関数を通す（規則5.0）。
        let Some(domain) = file.domains.iter_mut().find(|d| d.name == from.domain) else {
            out.not_found.push(reassignment.clone());
            continue;
        };
        crate::unapprove::remove_value(domain, from.key, &from.value);
        let proposal = RuleProposal {
            id: String::new(),
            key: to.key,
            value: to.value.clone(),
            evidence: Vec::new(),
            warnings: Vec::new(),
        };
        file.merge_approved(
            &[&proposal],
            &ApprovalContext {
                domain: &to.domain,
                command: None,
                cwd: None,
                record_session: None,
                now_unix_ms,
            },
        );

        existing.push(to.clone());
        seen.push(from.clone());
        out.changes.push(PlannedReassignment {
            widens: widens(&from, to.key, &to.value),
            from,
            to,
            carries_approval,
        });
    }
    out.file = file;
    Ok(out)
}

/// [`plan`]の結果を書く。**付け替えるものが無いときは書かない**（B-09）。付け替えた件数を返す。
///
/// 順序は「`policy.json` → 付け替えた後の値の承認 → 元の値の承認を消す」。台帳を`policy.json`の
/// **後**に書くのは`approve::commit`と同じ理由（先に記録して保存が落ちると、無い宣言の承認が残る）。
/// 承認を先・消すのを後にするのは、宣言画面の確定（承認を先に、取り消しを後に）と同じく、
/// 途中で落ちたときに権限を黙って失う側へ倒さないため。
pub fn commit(workspace_root: &Path, plan: &ReassignPlan) -> Result<usize, ReassignError> {
    if plan.changes.is_empty() {
        return Ok(0);
    }
    policy_file::save(workspace_root, &plan.file)?;
    let store = crate::approval_store::approval_store();

    let carried: Vec<DeclarationRef<'_>> = plan
        .changes
        .iter()
        .filter(|change| change.carries_approval)
        .filter_map(|change| change.to.declaration())
        .collect();
    let not_recorded = if carried.is_empty() {
        Vec::new()
    } else {
        store.approve(workspace_root, &carried)
    };
    // 元の値の承認は**引き継いだかどうかに関係なく**消す（取り消しと同じ。残すと、同じ値が後で
    // `policy.json`へ戻ったとき承認済みとして付く）。
    let previous: Vec<DeclarationRef<'_>> = plan
        .changes
        .iter()
        .filter_map(|change| change.from.declaration())
        .collect();
    let not_revoked = store.revoke(workspace_root, &previous);

    if not_recorded.is_empty() && not_revoked.is_empty() {
        return Ok(plan.changes.len());
    }
    let describe = |declarations: &[DeclarationRef<'_>]| {
        declarations
            .iter()
            .map(|d| format!("{} ({}) in {}", d.value, d.access.settings_key(), d.domain))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut parts = Vec::new();
    if !not_recorded.is_empty() {
        parts.push(format!(
            "記録できなかった承認（これらには許可が付きません）: {}",
            describe(&not_recorded)
        ));
    }
    if !not_revoked.is_empty() {
        parts.push(format!(
            "消せなかった前の値の承認: {}",
            describe(&not_revoked)
        ));
    }
    Err(ReassignError::LedgerIncomplete(parts.join("／")))
}

/// 付け替えを受け付けない理由（受け付けるなら`None`）。
///
/// **確定（[`plan`]）と、宣言画面で`c`・`R`を押した瞬間の両方がこれを通す**——押した時点で断れば、
/// 選び直しが要ることにその場で気付ける（候補画面の`R`が広すぎる値を印の段階で止めるのと同じ作法）。
/// `existing`は衝突を見る相手（同じドメインに同じ種類・同じ値の宣言があれば断る）。
pub(crate) fn refusal(
    checks: &ApprovalChecks,
    existing: &[UnapproveTarget],
    from: &UnapproveTarget,
    key: SettingsKey,
    value: &str,
) -> Option<String> {
    if from.key.fs_access().is_none() {
        return Some(
            "ネットワークの宣言は付け替えの対象外です（種類と ** を持たない）".to_string(),
        );
    }
    if key.fs_access().is_none() {
        return Some("ファイルの宣言はネットワークの宣言へ付け替えられません".to_string());
    }
    if key == from.key && value.eq_ignore_ascii_case(&from.value) {
        return Some("元の宣言と同じです（変えるものがありません）".to_string());
    }
    let to = UnapproveTarget {
        domain: from.domain.clone(),
        key,
        value: value.to_string(),
    };
    // 同じ設定値の宣言を2行に割らない（候補画面の`c`が同じ値に移動先の種類が既にあると作らないのと同じ）。
    if let Some(present) = existing
        .iter()
        .find(|t| *t != from && same_declaration(t, &to))
    {
        return Some(format!(
            "同じ宣言が既にあります（[{}] {} {}）",
            present.domain,
            present.key.dotted(),
            present.value
        ));
    }
    checks.refusal(&to)
}

/// 付け替えが元の宣言より**権限を広げる**か——種類が増える（`read`→`read_write`等。`read_write`と
/// `read_exec`は互いを含まないので、その間の付け替えも広げる側に数える）、または素のパスが`**`になる。
///
/// 包含の規則は[`harness_policy::insufficient::includes`]が唯一の正本（B-20: 別の問いに同じ関数を
/// 使わない——付与層の和`FsAccess::wider`とは別の問い）。
pub fn widens(from: &UnapproveTarget, key: SettingsKey, value: &str) -> bool {
    let adds_access = match (from.key.fs_access(), key.fs_access()) {
        (Some(before), Some(after)) => !harness_policy::insufficient::includes(before, after),
        _ => false,
    };
    let adds_scope =
        !declared_scope(&from.value).is_recursive() && declared_scope(value).is_recursive();
    adds_access || adds_scope
}

/// 値の`**`を付け外しした値。**付け外しの仕方が決まらない形は`None`**。
///
/// - `<path>/**` → `<path>`（そのオブジェクト1つだけ、D-63）
/// - `<path>` → `<path>/**`（配下すべてと今後作られるもの）
///
/// 途中にワイルドカードを含む値（`C:/x/*/bin`）と、`**`が要素の途中にある値（`C:/x/a**`）は
/// `None`——前者は付与層が受け付けない形で（`policy_grants::SkipReason::MiddleWildcard`）、後者は
/// 外した後の値が決まらない。範囲の判定そのものは[`declared_scope`]が持つ（B-05）。
pub fn toggle_recursive(value: &str) -> Option<String> {
    if has_unsupported_wildcard(value) {
        return None;
    }
    let trimmed = value.trim_end_matches(['/', '\\']);
    if declared_scope(value).is_recursive() {
        let head = trimmed.strip_suffix("**")?;
        if !head.ends_with(['/', '\\']) {
            return None;
        }
        let base = head.trim_end_matches(['/', '\\']);
        return (!base.is_empty()).then(|| base.to_string());
    }
    if trimmed.is_empty() || trimmed.contains('*') {
        return None;
    }
    // 区切りは値が使っている方に合わせる（エディタが書く値は`/`。手で`\`だけで書いた値に`/`を混ぜない）。
    let separator = if trimmed.contains('\\') && !trimmed.contains('/') {
        '\\'
    } else {
        '/'
    };
    Some(format!("{trimmed}{separator}**"))
}

/// 同じ宣言か（ドメインと種類は完全一致、値は大文字小文字を無視——`unapprove`が消す範囲と同じ）。
fn same_declaration(a: &UnapproveTarget, b: &UnapproveTarget) -> bool {
    a.domain == b.domain && a.key == b.key && a.value.eq_ignore_ascii_case(&b.value)
}

#[cfg(test)]
#[path = "reassign_tests.rs"]
mod reassign_tests;
