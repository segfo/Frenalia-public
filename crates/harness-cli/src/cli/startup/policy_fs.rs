//! [#30] `harness.exe`が`policy.json`のファイル宣言から**どの許可を付け、付いた結果をどの子へ渡すか**を決める。
//!
//! # 何のためにあるのか
//!
//! ポリシーエディタで承認したファイル宣言は、以前はエディタ自身の試験実行（パス2）の中でしか
//! 許可にならず、`harness.exe`では手書きの`settings.json`の`fs.*`と`--fs-allow`だけが効いていた
//! （D-42の注記が言う「原則と補足が入れ替わっている」状態）。ここが、その宣言を起動時の付与処理へ流し込む。
//!
//! # 一覧は3つに分けて持つ
//!
//! | 一覧 | 何を入れるか | 誰のトークンへ載るか |
//! |---|---|---|
//! | 入口 | 手書きの一覧（`settings.json`・`--fs-allow`）＋入口ドメイン`workspace-shell`の承認済み宣言 | モデルのシェル（入口の子） |
//! | ドメインごと | 遷移先ドメインの承認済み宣言（下の「付与する範囲」を満たすものだけ） | そのドメインの子だけ |
//! | 自動撤収の宣言集合 | 全ドメインの承認済み宣言のルート | 誰にも載らない（撤収の判定にだけ使う） |
//!
//! 宛先SIDは宣言ごと（ワークスペース, パス, 級）なので、ドメインの宣言にACEを書いても、その
//! SIDを持たない入口の子は広がらない。**広がりを止めているのは「どのトークンへどのSIDを積むか」**で、
//! それを決めるのが[`granted_for`]（付与の結果を一覧ごとに振り分ける）である。
//!
//! # 付与する範囲（他のドメイン）
//!
//! 遷移先ドメインの宣言は、そのドメインの子が実際に起こされ得るときだけ付ける。条件は3つ——
//! 遷移先になっている（ドメインの用意と同じ`PolicyFile::transition_target_domains`）、
//! 通信を宣言していない（していれば用意を断るので付けても使われない）、遷移の強制が有効
//! （`--enforce-transitions`。無効だと子は自分で生成でき、Daemon経由の遷移が起きない）。
//! 使われないドメインまで毎回付けると、`.cargo`だけで実測142.6秒の付与とUACが起動に乗る。
//!
//! # この関数が守らないもの
//!
//! - **承認の判定はしない**——渡された`approved`をそのまま使う（承認台帳はD-112、
//!   `harness_sandbox::tier2a::policy_approval`）。
//! - **同じパス・同じ級を別のドメインが素のパスと`**`で宣言すると、宛先SIDが1つなので両方が
//!   配下すべてを得る**（宛先の鍵に範囲が入っていない既存の設計。STATUSの残課題）。

use std::collections::BTreeMap;

use harness_core::GrantedPassthrough;
use harness_policy::policy_file::{PolicyFile, ENTRY_DOMAIN};
use harness_sandbox::tier2a::policy_approval::DeclarationRef;
use harness_sandbox::tier2a::policy_grants::{GrantContext, SkippedDeclaration};
use harness_sandbox::tier2a::workspace_capability::declaration_key;
use harness_sandbox::{FsPassthrough, WorkspaceWriteMode};

/// 遷移先ドメインごとの、このセッションで付いた許可（`Ok`）か、付けなかった理由（`Err`）。
/// ドメインの用意（`domain_provision::provision_target_domains`）がこれを読む——台帳を引き直さない
/// （BUG-185）。
pub(crate) type DomainFsGrants = BTreeMap<String, Result<Vec<GrantedPassthrough>, String>>;

/// `policy.json`から決めた、付与処理へ渡すもの。
#[derive(Debug, Default)]
pub(super) struct PolicyFsPlan {
    /// 入口ドメイン`workspace-shell`の承認済み宣言（手書きの一覧へ[`merge_into`]で合流させる）。
    pub(super) entry: Vec<FsPassthrough>,
    /// 付与する範囲に入った遷移先ドメインの承認済み宣言。
    pub(super) domains: Vec<(String, Vec<FsPassthrough>)>,
    /// 付与する範囲に入らなかった遷移先ドメインと、その理由。
    pub(super) not_granted_domains: Vec<(String, String)>,
    /// 全ドメインの承認済み宣言のルート（自動撤収の宣言集合へ足す）。
    pub(super) declared_roots: Vec<String>,
    /// 入口ドメインで付けなかった宣言（人へ見せる）。
    pub(super) entry_skipped: Vec<SkippedDeclaration>,
}

/// 宣言から、付ける一覧を決める（**何も書かない**。純粋関数）。
pub(super) fn plan(
    policy: &PolicyFile,
    ctx: &GrantContext,
    approved: &dyn Fn(DeclarationRef<'_>) -> bool,
    transitions_enforced: bool,
) -> PolicyFsPlan {
    let mut out = PolicyFsPlan::default();

    // 自動撤収の宣言集合は**全ドメイン**の承認済み宣言から作る。付与する範囲の条件で付けなかった
    // 回に「もう宣言されていない」と数えると、強制を有効にした次の回に付け直しになる。
    for domain in &policy.domains {
        for fp in ctx.domain_grants(domain, approved).passthrough {
            out.declared_roots
                .push(fp.path.to_string_lossy().into_owned());
        }
    }

    if let Some(entry) = policy.domain(ENTRY_DOMAIN) {
        let grants = ctx.domain_grants(entry, approved);
        out.entry = grants.passthrough;
        out.entry_skipped = grants.skipped;
    }

    for name in policy.transition_target_domains() {
        let Some(domain) = policy.domain(&name) else {
            // 定義が無いことはドメインの用意が理由ごと報告する（ここで二重に出さない）。
            continue;
        };
        if !domain.net.allow_domains.is_empty() {
            out.not_granted_domains.push((
                name,
                "it declares network access, and per-domain egress control does not exist yet, \
                 so the domain is not prepared and its file declarations are not granted"
                    .to_string(),
            ));
            continue;
        }
        let grants = ctx.domain_grants(domain, approved);
        // **1件でも付けない宣言があるドメインは用意しない**（fail-closed。§22.9の骨格と同じ判断）。
        // 付けられる分だけで用意すると、エディタで確かめたより狭い権限で黙って動く。
        if !grants.skipped.is_empty() {
            out.not_granted_domains.push((
                name,
                format!(
                    "{} of its file declarations cannot be granted: {}",
                    grants.skipped.len(),
                    grants
                        .skipped
                        .iter()
                        .map(|s| format!("{} ({}): {}", s.value, s.access.settings_key(), s.reason.describe()))
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            ));
            continue;
        }
        // **付ける宣言が無いドメインは、強制の有無に関係なく今までどおり用意できる**（土台だけで動く）。
        // 下の「強制が無効なら付けない」は、払う費用（付与とUAC）があるときだけの判断である。
        if grants.passthrough.is_empty() {
            out.domains.push((name, Vec::new()));
            continue;
        }
        if !transitions_enforced {
            out.not_granted_domains.push((
                name,
                "transitions are not enforced (--enforce-transitions), so no child runs in this \
                 domain and its file declarations are not granted"
                    .to_string(),
            ));
            continue;
        }
        out.domains.push((name, grants.passthrough));
    }
    out
}

/// 入口ドメインの宣言を手書きの一覧へ合流させる。**同じルートは1本に畳む**（和を取り、範囲は再帰が勝つ）
/// ——手書きの一覧の作り方（`sandbox.rs`の畳み込み）と同じ規則である。比較は宛先SIDの鍵と同じ畳み方
/// （`declaration_key`）で行う（`C:\x`と`c:/X`を別のルートとして2本にしない）。
pub(super) fn merge_into(manual: &mut Vec<FsPassthrough>, entry: &[FsPassthrough]) {
    for fp in entry {
        let key = declaration_key(&fp.path);
        match manual.iter_mut().find(|m| declaration_key(&m.path) == key) {
            Some(existing) => {
                existing.access = existing.access.wider(fp.access);
                if fp.scope.is_recursive() {
                    existing.scope = fp.scope;
                }
            }
            None => manual.push(fp.clone()),
        }
    }
}

/// 付与処理の結果から、**この一覧の宣言に対応する分**を取り出す。
///
/// 付与処理は入口とドメインの一覧をまとめて受け取り、CoWでの降格後の（パス, 級）で重複を除いて
/// 付ける（`preflight`の`dedupe_resolved`）。結果の`writable`はまとめた行の和になっているので、
/// **そのまま渡すと、読取しか宣言していない一覧へ別の一覧の書込の印が移る**（CoWでは書込誘導の
/// 対象になる）。だから一覧ごとに、**その一覧が要求した書込の印で組み直す**。
///
/// 照合は（宛先SIDの鍵と同じ畳み方のパス, 実際に書いた級）。級は`shell_tier::effective_access`で
/// 決める——付与処理と同じ関数を通さないと、降格後の級で付いた結果を探し当てられない（B-05）。
///
/// 戻り値は（見つかった分, 見つからなかった宣言のパス）。見つからないのは、付与処理が付けられなかった
/// （パスが無い・昇格を断られた等。理由は付与処理の警告が持つ）ときである。
pub(super) fn granted_for(
    requested: &[FsPassthrough],
    granted: &[GrantedPassthrough],
    write_mode: &WorkspaceWriteMode,
) -> (Vec<GrantedPassthrough>, Vec<std::path::PathBuf>) {
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for fp in requested {
        let key = declaration_key(&fp.path);
        let access = harness_sandbox::shell_tier::effective_access(fp.access, write_mode);
        match granted
            .iter()
            .find(|g| g.granted_access == access.label() && declaration_key(&g.path) == key)
        {
            Some(g) => found.push(GrantedPassthrough {
                writable: fp.access.is_read_write(),
                ..g.clone()
            }),
            None => missing.push(fp.path.clone()),
        }
    }
    (found, missing)
}

/// 遷移先ドメインごとの付与の結果（[`DomainFsGrants`]）を組み立てる。
pub(super) fn domain_fs_grants(
    plan: &PolicyFsPlan,
    granted: &[GrantedPassthrough],
    write_mode: &WorkspaceWriteMode,
) -> DomainFsGrants {
    let mut out = DomainFsGrants::new();
    for (name, reason) in &plan.not_granted_domains {
        out.insert(name.clone(), Err(reason.clone()));
    }
    for (name, requested) in &plan.domains {
        let (found, missing) = granted_for(requested, granted, write_mode);
        let result = if missing.is_empty() {
            Ok(found)
        } else {
            Err(format!(
                "{} of its declarations could not be granted in this session ({}); see the \
                 fs-allow warnings above",
                missing.len(),
                missing
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        };
        out.insert(name.clone(), result);
    }
    out
}

/// モデルへ見せる遷移の一覧の権限欄に載せてよい`(値, 級)`——**どれかのドメインで承認済み**のもの。
///
/// 権限欄は到達できる全ドメインの和で、どのドメインの宣言かを持たない
/// （`harness_policy::transition::rights_summary`）。だから「どれかのドメインで承認済み」で絞る。
/// 未承認の宣言を載せると、付いていない許可をモデルへ伝えることになる。
pub(super) fn approved_fs_values(
    policy: &PolicyFile,
    approved: &dyn Fn(DeclarationRef<'_>) -> bool,
) -> std::collections::BTreeSet<(String, &'static str)> {
    let mut out = std::collections::BTreeSet::new();
    for domain in &policy.domains {
        for (value, access) in domain.fs.entries() {
            if approved(DeclarationRef {
                domain: &domain.name,
                value,
                access,
            }) {
                out.insert((value.to_string(), access.settings_key()));
            }
        }
    }
    out
}

#[cfg(test)]
#[path = "policy_fs_tests.rs"]
mod policy_fs_tests;
