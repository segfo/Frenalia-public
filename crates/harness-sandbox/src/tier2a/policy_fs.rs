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
//! 遷移先ドメインの宣言は、そのドメインの子が実際に起こされ得るときだけ付ける。条件は2つ——
//! 遷移先になっている（ドメインの用意と同じ`PolicyFile::transition_target_domains`）、遷移の強制が有効
//! （`--enforce-transitions`。無効だと子は自分で生成でき、Daemon経由の遷移が起きない）。
//! 使われないドメインまで毎回付けると、`.cargo`だけで実測142.6秒の付与とUACが起動に乗る。
//! **「通信を宣言していない」という3つ目の条件は決定69（P7）で外した**——通信を宣言するドメインには
//! 専用の中継プロキシ・`internetClient`・WFPの項目を与えるので、用意を断る理由ではなくなった。
//!
//! # 通信の宣言（決定69）
//!
//! ファイルと同じく**このマシンで承認した宣言だけ**を使う（[`domain_net`]）。承認済みの宛先は
//! [`PolicyFsPlan::entry_net`]（入口）と[`PolicyFsPlan::domains_net`]（用意する遷移先）に載り、
//! 呼び出し側（`harness.exe`の起動・ポリシーエディタのパス2）がそこから出口を組み立てる。
//!
//! # この関数が守らないもの
//!
//! - **承認の判定はしない**——渡された`approved`をそのまま使う（承認台帳はD-112、
//!   `crate::tier2a::policy_approval`）。
//! - **同じパス・同じ級を別のドメインが素のパスと`**`で宣言すると、宛先SIDが1つなので両方が
//!   配下すべてを得る**（宛先の鍵に範囲が入っていない既存の設計。STATUSの残課題）。

use std::collections::BTreeMap;

use harness_core::GrantedPassthrough;
use harness_policy::policy_file::{PolicyDomain, PolicyFile, ENTRY_DOMAIN};
use crate::tier2a::policy_approval::DeclarationRef;
use crate::tier2a::policy_grants::{GrantContext, SkippedDeclaration};
use crate::tier2a::workspace_capability::declaration_key;
use crate::{FsPassthrough, WorkspaceWriteMode};

/// 遷移先ドメインごとの、このセッションで付いた許可（`Ok`）か、付けなかった理由（`Err`）。
/// ドメインの用意（`domain_provision::provision_target_domains`）がこれを読む——台帳を引き直さない
/// （BUG-185）。
pub type DomainFsGrants = BTreeMap<String, Result<Vec<GrantedPassthrough>, String>>;

/// `policy.json`から決めた、付与処理へ渡すもの。
#[derive(Debug, Default)]
pub struct PolicyFsPlan {
    /// 入口ドメイン`workspace-shell`の承認済み宣言（手書きの一覧へ[`merge_into`]で合流させる）。
    pub entry: Vec<FsPassthrough>,
    /// 付与する範囲に入った遷移先ドメインの承認済み宣言。
    pub domains: Vec<(String, Vec<FsPassthrough>)>,
    /// 付与する範囲に入らなかった遷移先ドメインと、その理由。
    pub not_granted_domains: Vec<(String, String)>,
    /// 全ドメインの承認済み宣言のルート（自動撤収の宣言集合へ足す）。
    pub declared_roots: Vec<String>,
    /// 入口ドメインで付けなかった宣言（人へ見せる）。
    pub entry_skipped: Vec<SkippedDeclaration>,
    /// [決定69(1)] 入口ドメインの通信（承認済みの宛先と、使えなかった宣言の理由）。
    /// セッションの中継プロキシへ渡す宛先はこれと`--net-allow-domain`の和である。
    pub entry_net: DomainNet,
    /// [決定69(1)] 用意する範囲に入った遷移先ドメインの通信（ドメインごとの中継プロキシの材料）。
    /// **用意しないドメインは入らない**——出口を作っても使う子が居ない。
    pub domains_net: Vec<(String, DomainNet)>,
}

/// [決定69(1)(2)] ドメインが使える通信の宛先と、使えなかった宣言の理由。
///
/// **値は`policy.json`の綴りのまま**で、正規化（`harness_core::normalize_domain_pattern`）は中継プロキシへ
/// 渡す直前に1回だけ通す（`harness.exe`とパス2が同じ`net_policy_plan`を通る）。ここで正規化しないのは、
/// 承認台帳の鍵が**書いてあるとおりの綴り**だからである（綴りを変えた値は未承認＝付けない側へ倒れる）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainNet {
    /// このマシンで承認済みの宛先（宣言の順）。
    pub allow_domains: Vec<String>,
    /// 使えなかった宣言（**呼び出し側は必ず出すこと**。`B-10`）。
    pub skipped: Vec<SkippedNetDeclaration>,
}

impl DomainNet {
    /// 出口（専用の中継プロキシ・`internetClient`・WFPの項目）が要るか。
    pub fn wants_egress(&self) -> bool {
        !self.allow_domains.is_empty()
    }
}

/// 使えなかった通信の宣言1件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedNetDeclaration {
    pub value: String,
    pub reason: NetSkipReason,
}

/// 通信の宣言に許可を付けない理由。**`_`を書かない網羅`match`で文面を作る**（理由を足したらビルドが落ちる）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetSkipReason {
    /// このマシンで承認されていない（D-112・決定69(2)）。
    NotApprovedOnThisMachine,
    /// 宛先の綴りを解釈できない（`harness_core::normalize_domain_pattern`が断った）。
    Unparsable(String),
}

impl NetSkipReason {
    /// 人へ見せる理由。
    pub fn describe(&self) -> String {
        match self {
            NetSkipReason::NotApprovedOnThisMachine => {
                "not approved on this machine (a policy.json shipped with a repository is not \
                 trusted until you approve each declaration in harness-policy-editor)"
                    .to_string()
            }
            NetSkipReason::Unparsable(detail) => {
                format!("the destination cannot be interpreted: {detail}")
            }
        }
    }
}

/// ドメインの`net`宣言から、**このマシンで承認済みで、綴りを解釈できる宛先だけ**を取る（決定69(1)(2)）。
///
/// 承認の照合は`harness.exe`・パス2・エディタの見込みが同じこれを通る（`B-05`: 判定を写さない）。
/// 解釈の検査もここで掛ける——未承認と解釈できないは**別の理由**なので、まとめて「使えない」にしない（`B-10`）。
pub fn domain_net(
    domain: &PolicyDomain,
    approved: &dyn Fn(DeclarationRef<'_>) -> bool,
) -> DomainNet {
    let mut out = DomainNet::default();
    for value in &domain.net.allow_domains {
        let declaration = DeclarationRef {
            domain: &domain.name,
            value,
            key: harness_policy::generalize::SettingsKey::NetAllowDomains,
        };
        if !approved(declaration) {
            out.skipped.push(SkippedNetDeclaration {
                value: value.clone(),
                reason: NetSkipReason::NotApprovedOnThisMachine,
            });
            continue;
        }
        if let Err(detail) = harness_core::normalize_domain_pattern(value) {
            out.skipped.push(SkippedNetDeclaration {
                value: value.clone(),
                reason: NetSkipReason::Unparsable(detail),
            });
            continue;
        }
        if !out.allow_domains.contains(value) {
            out.allow_domains.push(value.clone());
        }
    }
    out
}

/// 遷移先のドメイン1つを、`harness.exe`が用意できるか。
#[derive(Debug, Clone)]
pub enum DomainReadiness {
    /// 許可が付かないファイル宣言がある。**1件でもあればドメインごと用意しない**（fail-closed）。
    NotGranted { skipped: Vec<SkippedDeclaration> },
    /// 用意できる。付けるファイルの一覧（空なら共通の土台だけで用意される）と、使える通信の宛先。
    Ready {
        passthrough: Vec<FsPassthrough>,
        /// [決定69] 承認済みの通信の宛先（出口はここから作る。`net.allow_domains`を宣言していても
        /// **用意そのものは断らない**——決定65の暫定(b) は P7 で外した）。
        net: DomainNet,
    },
}

/// 遷移先のドメイン1つを用意できるかを決める。`harness.exe`の付与の一覧（[`plan`]）とポリシーエディタの見込み
/// （`transition_destination::outlook`）が**同じこれを通る**（決定68の前例の(9)）。
///
/// 判定順は「付かないファイル宣言 → 用意できる」。**通信の宣言は用意を断る理由ではない**（決定69）——
/// 承認済みの宛先は[`DomainReadiness::Ready`]に載り、呼び出し側がそこから専用の中継プロキシとWFPの項目を作る。
/// `grants`は宣言から付ける一覧を作る関数で、製品では`GrantContext::domain_grants`に承認台帳を渡したもの。
pub fn domain_readiness(
    domain: &PolicyDomain,
    approved: &dyn Fn(DeclarationRef<'_>) -> bool,
    grants: impl FnOnce(&PolicyDomain) -> crate::tier2a::policy_grants::DomainGrants,
) -> DomainReadiness {
    let granted = grants(domain);
    if !granted.skipped.is_empty() {
        return DomainReadiness::NotGranted { skipped: granted.skipped };
    }
    DomainReadiness::Ready {
        passthrough: granted.passthrough,
        net: domain_net(domain, approved),
    }
}

/// 宣言から、付ける一覧を決める（**何も書かない**。純粋関数）。
pub fn plan(
    policy: &PolicyFile,
    ctx: &GrantContext,
    approved: &dyn Fn(DeclarationRef<'_>) -> bool,
    transitions_enforced: bool,
) -> PolicyFsPlan {
    // 自動撤収の宣言集合は**全ドメイン**の承認済み宣言から作る。付与する範囲の条件で付けなかった
    // 回に「もう宣言されていない」と数えると、強制を有効にした次の回に付け直しになる。
    // 数え方はポリシーエディタの開始時の取り消し（BUG-184）と同じ関数を通す。
    let mut out = PolicyFsPlan {
        declared_roots: ctx.declared_roots(policy, approved),
        ..Default::default()
    };

    if let Some(entry) = policy.domain(ENTRY_DOMAIN) {
        let grants = ctx.domain_grants(entry, approved);
        out.entry = grants.passthrough;
        out.entry_skipped = grants.skipped;
        // [決定69(1)] 入口の通信も同じ1回の`plan`で決める——`harness.exe`が`policy.json`を読むのは
        // `stage_prepare_sandbox`の1回だけで、ここで取らないと読み直すことになる（`B-13`）。
        out.entry_net = domain_net(entry, approved);
    }

    for name in policy.transition_target_domains() {
        let Some(domain) = policy.domain(&name) else {
            // 定義が無いことはドメインの用意が理由ごと報告する（ここで二重に出さない）。
            continue;
        };
        // 判定は[`domain_readiness`]の1つ（エディタの見込みと`domain_provision`も同じ判定を通る。決定68の前例の(9)）。
        let (passthrough, net) = match domain_readiness(domain, approved, |d| {
            ctx.domain_grants(d, approved)
        }) {
            // **1件でも付けない宣言があるドメインは用意しない**（fail-closed。§22.9の骨格と同じ判断）。
            // 付けられる分だけで用意すると、エディタで確かめたより狭い権限で黙って動く。
            DomainReadiness::NotGranted { skipped } => {
                out.not_granted_domains.push((
                    name,
                    format!(
                        "{} of its file declarations cannot be granted: {}",
                        skipped.len(),
                        skipped
                            .iter()
                            .map(|s| format!("{} ({}): {}", s.value, s.access.settings_key(), s.reason.describe()))
                            .collect::<Vec<_>>()
                            .join("; ")
                    ),
                ));
                continue;
            }
            DomainReadiness::Ready { passthrough, net } => (passthrough, net),
        };
        // **付ける宣言が無いドメインは、強制の有無に関係なく今までどおり用意できる**（土台だけで動く）。
        // 下の「強制が無効なら付けない」は、払う費用（付与とUAC）があるときだけの判断である。
        if passthrough.is_empty() {
            out.domains_net.push((name.clone(), net));
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
        out.domains_net.push((name.clone(), net));
        out.domains.push((name, passthrough));
    }
    out
}

/// 入口ドメインの宣言を手書きの一覧へ合流させる。**同じルートは1本に畳む**（和を取り、範囲は再帰が勝つ）
/// ——手書きの一覧の作り方（`sandbox.rs`の畳み込み）と同じ規則である。比較は宛先SIDの鍵と同じ畳み方
/// （`declaration_key`）で行う（`C:\x`と`c:/X`を別のルートとして2本にしない）。
pub fn merge_into(manual: &mut Vec<FsPassthrough>, entry: &[FsPassthrough]) {
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
pub fn granted_for(
    requested: &[FsPassthrough],
    granted: &[GrantedPassthrough],
    write_mode: &WorkspaceWriteMode,
) -> (Vec<GrantedPassthrough>, Vec<std::path::PathBuf>) {
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for fp in requested {
        let key = declaration_key(&fp.path);
        let access = crate::shell_tier::effective_access(fp.access, write_mode);
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
pub fn domain_fs_grants(
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
pub fn approved_fs_values(
    policy: &PolicyFile,
    approved: &dyn Fn(DeclarationRef<'_>) -> bool,
) -> std::collections::BTreeSet<(String, &'static str)> {
    let mut out = std::collections::BTreeSet::new();
    for domain in &policy.domains {
        for (value, access) in domain.fs.entries() {
            if approved(DeclarationRef {
                domain: &domain.name,
                value,
                key: harness_policy::generalize::SettingsKey::from_access(access),
            }) {
                out.insert((value.to_string(), access.settings_key()));
            }
        }
    }
    out
}

/// [決定69(1)] モデルへ見せる遷移の一覧の権限欄に載せてよい通信の宛先——**どれかのドメインで承認済み**のもの。
///
/// ファイルの[`approved_fs_values`]と同じ理由で要る：権限欄は到達できる全ドメインの和で、どのドメインの
/// 宣言かを持たない（`harness_policy::transition::rights_summary`）。未承認の宛先を載せると、
/// **出口に入っていない宛先をモデルへ伝える**ことになる。
pub fn approved_net_values(
    policy: &PolicyFile,
    approved: &dyn Fn(DeclarationRef<'_>) -> bool,
) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    for domain in &policy.domains {
        for value in domain_net(domain, approved).allow_domains {
            // 権限欄は小文字へ畳んだ綴りで比べる（`rights_summary`と同じ）。
            out.insert(value.to_ascii_lowercase());
        }
    }
    out
}

/// [残課題 サンドボックス周辺 #65] **`policy.json`の外で書込を許した場所**の一覧。
/// 遷移の編集時検査が「呼び出し元から書ける場所」として数える
/// （`harness_policy::policy_file::load_for_session`のdoc）。
///
/// 入力は`settings.json`の`fs.*`と`--fs-allow`を合成済みの一覧で、書込を含むもの
/// （`FsAccess::is_read_write`＝`ReadWrite`/`ReadWriteExec`）の付与ルートを返す。
///
/// # 付与した結果ではなく、宣言から取る
///
/// 付与に失敗した穴も数える——検査は厳しい側に倒す。**CoWモードでも数える**:
/// CoWでは`:rw`の実ACEが読取へ降格され書込は差分層へ向かうが、既存の検査は
/// ワークスペースもCoWに関係なく「書ける」と数えているので、それに揃える。
///
/// # `policy.json`の宣言は入れない（#30）
///
/// この一覧に入るのは`settings.json`と`--fs-allow`由来だけである。`harness.exe`は#30から
/// `policy.json`の`fs`も付与の一覧へ流し込むが、**この関数は合流させる前の手書きの一覧で呼ぶ**
/// （`stage_prepare_sandbox`）——宣言は宣言として既に検査の視野にあり、ここへ入れると遷移先ドメインの
/// 書込宣言まで「入口から書ける」と数えられ、正当な辺が拒否される。
pub fn writable_outside_policy(
    fs_passthrough: &[crate::FsPassthrough],
) -> Vec<String> {
    fs_passthrough
        .iter()
        .filter(|fp| fp.access.is_read_write())
        .map(|fp| fp.path.to_string_lossy().into_owned())
        .collect()
}

/// 付与の結果から、付与台帳（`fs-passthrough-ledger.json`）へ書く記録を組む（`harness-cli`の`run_agent.rs`から
/// そのまま移した。P6.2。`harness.exe`とポリシーエディタのパス2が同じこれを通る——決定68の前例の(11)）。
///
/// # 同じパスは記録の前に1行へ畳む
///
/// 付与台帳はパスごとに1行で、後から書いた行が`forced`/`writable`/`scope`を上書きする（`upsert_grant`）。
/// 一覧ごと（入口・遷移先ドメイン）に同じパスがあると、後の行（`forced=false`）が前の行の特権の使用を消し、
/// 撤収が`SeRestorePrivilege`を使わなくなる（BUG-119の逆行）。`forced`・`writable`は和、範囲は再帰が勝つ。
/// 比べる綴りは宛先SIDの鍵と同じ畳み方（`declaration_key`）。
///
/// # `forced`は宣言からではなく、そのパスで特権を使ったかから
///
/// [BUG-119] `--force-system-acl`はセッション全域のスイッチで、そのパスで特権を使ったかという事実ではない。
/// 宣言（`declared`）から引くのは**範囲だけ**である。組み立ては`FsPassthroughGrantRecord::from_granted`が唯一の定義を持つ。
///
/// # 承認済みの宣言のルートなら、ワークスペースを参照に載せる
///
/// 「ファイルで宣言された」（＝自動撤収の対象。D-27）かは、台帳と同じ比べ方（`same_ledger_path`）で
/// `file_declared_roots`と比べる。文字列の完全一致では`C:\x`と`C:/x`が別物になり、毎起動で印が外れて撤収される。
pub fn grant_records<'a>(
    granted: impl IntoIterator<Item = &'a GrantedPassthrough>,
    declared: &[FsPassthrough],
    file_declared_roots: &[String],
    workspace_root: &std::path::Path,
) -> Vec<crate::tier2a::fs_passthrough_ledger::FsPassthroughGrantRecord> {
    let mut by_path: Vec<GrantedPassthrough> = Vec::new();
    for granted in granted {
        let key = declaration_key(&granted.path);
        match by_path
            .iter_mut()
            .find(|seen| declaration_key(&seen.path) == key)
        {
            Some(seen) => {
                seen.writable |= granted.writable;
                seen.used_restore_privilege |= granted.used_restore_privilege;
            }
            None => by_path.push(granted.clone()),
        }
    }
    by_path
        .iter()
        .map(|granted| {
            let key = declaration_key(&granted.path);
            let declared = declared
                .iter()
                .filter(|fp| declaration_key(&fp.path) == key)
                .max_by_key(|fp| fp.scope.is_recursive());
            let path_str = granted.path.to_string_lossy();
            let file_declared = file_declared_roots
                .iter()
                .any(|root| harness_grant_ledger::same_ledger_path(root, &path_str));
            crate::tier2a::fs_passthrough_ledger::FsPassthroughGrantRecord::from_granted(
                granted,
                declared,
                file_declared.then(|| workspace_root.to_string_lossy().into_owned()),
            )
        })
        .collect()
}

#[cfg(test)]
#[path = "policy_fs_tests.rs"]
mod policy_fs_tests;
