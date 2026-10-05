//! [段階⑦] 遷移先ドメインを`harness.exe`が**用意する見込み**と、遷移先の名前の検査
//! （`plans/POLICY-EDITOR-TOMOYO-DIG.md`「別ドメインへの遷移を書けるようにした（2026-10-01）」）。
//!
//! # 何のためにあるのか
//!
//! 別のドメインへ移す遷移は、**遷移先ドメインの実体（package SIDとcapabilityの組）を`harness.exe`が
//! 起動時に用意できたときだけ**通る——Spawn Daemonは用意された表に無い遷移先を
//! `TargetDomainNotProvisioned`で断る（`plans/DESIGN-MAC-ENFORCEMENT.md` §10.1.2）。
//! 用意できるかは`policy.json`と承認台帳から決まる（D-112、#30）ので、エディタも書く前に
//! 「宣言の上では用意されない」ことを言える。ここがその見込みを作る。
//!
//! # 判定の材料は`harness.exe`と同じ関数を通す。写しているのは組み立て順だけ
//!
//! - **宣言ごとに許可が付くか**: `policy_grants::GrantContext::domain_grants`——`harness.exe`の
//!   付与の一覧（`harness-cli`の`startup::policy_fs::plan`）が呼ぶのと**同じ関数・同じ承認台帳**。
//! - **組み立て順**（通信を宣言している→付かない宣言が1件でもある→宣言が無い）は、`policy_fs::plan`と
//!   `harness-sandbox`の`domain_provision::capability_sids_for`の**写し**である。`harness-cli`は
//!   バイナリのクレートでここから呼べない。**ずれたときに外れるのはこの画面の見込みだけ**で、
//!   実際に起こせるかは`harness.exe`が決め、モデルへ見せる一覧も`harness.exe`が実際に用意した表から
//!   作る（`transition_tool::facts_from_policy`）。
//!
//! # 見込みが言わないもの（限界）
//!
//! - **実行時の失敗**——パスが無い・昇格を断られた・入れ物を作れない。`harness.exe`の起動時の警告が持つ
//! - **遷移の強制が無効な起動**——そもそも遷移が起きない。ファイル宣言を持つ遷移先は、強制を有効にした
//!   起動でしか許可が付かない（付与の費用を使われない起動に払わないため。D-112）が、その起動では
//!   遷移も起きないので、見込みは「強制を有効にした起動なら」の1通りだけを答える
//! - **いま用意されているか**——エディタは`harness.exe`とは別プロセスで、どのセッションが何を用意したかを
//!   知らない。答えるのは「次に起動したら用意されるはずか」である

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use harness_policy::policy_file::{PolicyDomain, PolicyFile};
use harness_sandbox::tier2a::policy_grants::{DomainGrants, SkipReason, SkippedDeclaration};

/// 遷移先ドメインを`harness.exe`が用意する見込み。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outlook {
    /// 遷移先が呼び出し元と同じドメイン（自己ループ辺）。**凍結中で、エディタからは書けない**
    /// （決定65(3)）。この変種が出るのは、遷移先の欄に呼び出し元の名前が入ったときと、手で書いた
    /// 自己ループ辺の見込みを引いたときである。Daemonは表を引かず、呼び出し元の実体のまま起こす
    /// （`spawnd::server::serve_spawn_request`）。
    SameDomain,
    /// 宣言の上では用意される。
    Provisioned {
        /// 遷移先のファイル宣言の件数。0なら共通の土台（ワークスペース等）だけで用意される。
        /// 1以上なら、`harness.exe`が起動時にそれらへ許可を付けてから用意する。
        declarations: usize,
    },
    /// 宣言の上で、用意されないことが分かっている。**この遷移は断られ続ける。**
    NotProvisioned(Blocker),
}

/// 用意されない理由。**`harness.exe`の起動時の警告と同じ分け方**（`domain_provision`の`skipped`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocker {
    /// 通信を宣言している。**【暫定】**ドメインごとの通信の出口制御（専用プロキシ＋WFPの欄）が
    /// まだ無いので、`harness.exe`は通信を宣言するドメインを用意しない（`domain_provision`のdoc）。
    ///
    /// # いつ消えるか
    ///
    /// ドメインごとの出口制御が入り、`harness.exe`が通信を宣言するドメインを用意するようになった日
    /// （`plans/HANDOFF-POLICY-EDITOR.md`の「前提を待つもの」D、`docs/INDEX.md`の未実装機能
    /// サンドボックス周辺 #55）。**この変種を消すと、文言を組む`match`がコンパイルできなくなる**。
    DeclaresNetwork { count: usize },
    /// 許可が付かないファイル宣言がある。**1件でもあればドメインごと用意されない**（fail-closed。
    /// 付いた分だけで用意すると、エディタで確かめたより狭い権限で黙って動く。D-112）。
    DeclarationsNotGranted { skipped: Vec<SkippedDeclaration> },
}

impl Outlook {
    /// この遷移先への辺は、宣言の上では起こせるか。
    pub fn is_provisioned(&self) -> bool {
        !matches!(self, Outlook::NotProvisioned(_))
    }

    /// 遷移先の欄と一覧の行末に出す一言。
    pub fn short_label(&self) -> String {
        match self {
            Outlook::SameDomain => {
                "呼び出し元と同じドメイン（自己ループ辺は凍結中で書けない）".to_string()
            }
            Outlook::Provisioned { declarations: 0 } => {
                "用意される見込み（ファイル宣言なし・共通の土台だけ）".to_string()
            }
            Outlook::Provisioned { declarations } => {
                format!("用意される見込み（承認済みのファイル宣言 {declarations}件に許可が付く）")
            }
            Outlook::NotProvisioned(Blocker::DeclaresNetwork { count }) => {
                format!("用意されない: 通信を宣言している（{count}件）")
            }
            Outlook::NotProvisioned(Blocker::DeclarationsNotGranted { skipped }) => {
                let unapproved = unapproved_count(skipped);
                if unapproved == skipped.len() {
                    format!("用意されない: このマシンで未承認のファイル宣言 {unapproved}件")
                } else {
                    format!(
                        "用意されない: 許可が付かないファイル宣言 {}件（うち未承認 {unapproved}件）",
                        skipped.len()
                    )
                }
            }
        }
    }

    /// 確定の直前に出す説明。**取り消しの効かない操作の直前なので、何が起きるかを全部言う。**
    pub fn notice_lines(&self, to_domain: &str) -> Vec<String> {
        match self {
            Outlook::SameDomain => vec![
                format!("遷移先が呼び出し元と同じドメイン（{to_domain}）です。"),
                "  自己ループ辺は凍結中のため書けません（決定65）。".to_string(),
                "  Tab で遷移先の欄へ移って、別のドメイン名を入れてから確定してください。".to_string(),
            ],
            Outlook::Provisioned { declarations: 0 } => vec![
                format!("遷移先 {to_domain} はファイル宣言を持たないので、harness.exe は"),
                "  共通の土台（ワークスペース・祖先の通り抜け・生成の依頼口）だけでこのドメインを用意します。"
                    .to_string(),
            ],
            Outlook::Provisioned { declarations } => vec![
                format!(
                    "遷移先 {to_domain} の承認済みのファイル宣言 {declarations}件に、harness.exe が起動時に"
                ),
                "  許可を付けてからこのドメインを用意します（遷移の強制を有効にした起動だけ）。"
                    .to_string(),
                "  付与に失敗するとそのドメインは用意されず、遷移は断られます（起動時に警告が出ます）。"
                    .to_string(),
            ],
            Outlook::NotProvisioned(Blocker::DeclaresNetwork { count }) => vec![
                format!("⚠ 遷移先 {to_domain} は通信を {count}件宣言しています。"),
                "  ドメインごとの通信の出口制御がまだ無いので、harness.exe はこのドメインを用意せず、"
                    .to_string(),
                "  この遷移は断られ続けます（書くことはできます。通信の宣言を外せば用意されます）。"
                    .to_string(),
            ],
            Outlook::NotProvisioned(Blocker::DeclarationsNotGranted { skipped }) => {
                let mut lines = vec![
                    format!(
                        "⚠ 遷移先 {to_domain} のファイル宣言のうち {}件に許可が付きません。",
                        skipped.len()
                    ),
                    "  1件でも付かないドメインは用意されず、この遷移は断られ続けます（書くことはできます）。"
                        .to_string(),
                ];
                if unapproved_count(skipped) > 0 {
                    lines.push(
                        "  未承認の宣言は、宣言画面（F3）の y で「このマシンで承認」すると付きます。"
                            .to_string(),
                    );
                }
                for skip in skipped.iter().take(SKIPPED_SHOWN) {
                    lines.push(format!(
                        "    - {} ({}): {}",
                        skip.value,
                        skip.access.settings_key(),
                        skip.reason.describe()
                    ));
                }
                if skipped.len() > SKIPPED_SHOWN {
                    lines.push(format!(
                        "    …ほか {}件（宣言画面 F3 で全部見られます）",
                        skipped.len() - SKIPPED_SHOWN
                    ));
                }
                lines
            }
        }
    }
}

/// 確認ダイアログに名指しする付かない宣言の上限（残りは件数で言う）。
const SKIPPED_SHOWN: usize = 5;

fn unapproved_count(skipped: &[SkippedDeclaration]) -> usize {
    skipped
        .iter()
        .filter(|s| s.reason == SkipReason::NotApprovedOnThisMachine)
        .count()
}

/// 遷移先`to_domain`を`harness.exe`が用意する見込み。
///
/// `grants`はドメインの宣言から付ける一覧を作る関数で、製品では[`grants_on_this_machine`]を渡す
/// （試験では承認台帳を介さずに渡せるよう、引数で受ける）。
///
/// **`policy.json`に無い名前は「宣言が空のドメイン」として答える**——確定すると
/// [`crate::transition_approve::plan`]が宣言の無いドメインとして作るからである。
pub fn outlook(
    file: &PolicyFile,
    from_domain: &str,
    to_domain: &str,
    grants: &dyn Fn(&PolicyDomain) -> DomainGrants,
) -> Outlook {
    if to_domain == from_domain {
        return Outlook::SameDomain;
    }
    let Some(domain) = file.domain(to_domain) else {
        return Outlook::Provisioned { declarations: 0 };
    };
    // 順序は`policy_fs::plan`と同じ（モジュールdoc）。通信の宣言が先——付与の一覧を作る前に断る。
    if !domain.net.allow_domains.is_empty() {
        return Outlook::NotProvisioned(Blocker::DeclaresNetwork {
            count: domain.net.allow_domains.len(),
        });
    }
    let granted = grants(domain);
    if !granted.skipped.is_empty() {
        return Outlook::NotProvisioned(Blocker::DeclarationsNotGranted {
            skipped: granted.skipped,
        });
    }
    Outlook::Provisioned {
        declarations: domain.fs.entries().len(),
    }
}

/// `policy.json`の全ドメインについての見込み（遷移先の欄と一覧の行が引く表）。
pub fn outlooks(
    file: &PolicyFile,
    from_domain: &str,
    grants: &dyn Fn(&PolicyDomain) -> DomainGrants,
) -> BTreeMap<String, Outlook> {
    file.domains
        .iter()
        .map(|d| (d.name.clone(), outlook(file, from_domain, &d.name, grants)))
        .collect()
}

/// 用意される見込みのドメイン名（[`harness_policy::transition_listing::rows`]へ渡す表）。
///
/// `harness.exe`は実際に用意できた表を渡すが、エディタはそれを知らないので見込みを渡す（モジュールdoc）。
/// 自己ループは表を引かないので、ここに入れなくても「起こせる」と出る。
pub fn provisioned_names(outlooks: &BTreeMap<String, Outlook>) -> BTreeSet<String> {
    outlooks
        .iter()
        .filter(|(_, o)| matches!(o, Outlook::Provisioned { .. }))
        .map(|(name, _)| name.clone())
        .collect()
}

/// このマシンの承認台帳（D-112）で、ドメインの宣言から付ける一覧を作る。
///
/// **`harness.exe`と同じ関数・同じ台帳**（`policy_grants`・`approval_store`）を通す。
/// 台帳は呼ぶたびに1回読む（呼び出し側は表を作り直すときに1回呼ぶこと）。
pub fn grants_on_this_machine(workspace_root: &Path) -> impl Fn(&PolicyDomain) -> DomainGrants {
    let approvals = crate::approval_store::approval_store().load();
    let workspace_key =
        harness_sandbox::tier2a::policy_approval::approval_workspace_key(workspace_root);
    let context = harness_sandbox::tier2a::policy_grants::GrantContext::for_workspace(workspace_root);
    move |domain: &PolicyDomain| {
        context.domain_grants(domain, &|d| approvals.is_approved_for_key(&workspace_key, d))
    }
}

// ---------------------------------------------------------------------------
// 遷移先の名前
// ---------------------------------------------------------------------------

/// 遷移先ドメインの入れ物（AppContainerプロファイル）の名前の接頭辞。
///
/// `harness-sandbox`の`domain_profile::DOMAIN_PROFILE_PREFIX`の写し（あちらはクレート外へ公開していない）。
/// **変えられない値である**——GCがこの接頭辞だけを頼りに孤児を列挙するので、変えると以前のセッションの
/// 入れ物を回収できなくなる（同定数のdoc）。それでも変わった日は、下の名前の検査が**全部の名前を断る**
/// 側へ外れ、許可側の試験（`a_short_plain_name_can_be_a_destination`）が赤くなる。
const DOMAIN_PROFILE_PREFIX: &str = "harness.domain";

/// `harness.exe`のセッションの印（`<pid>-<unix秒>`）が**最も長くなる形**。pidは`u32`の最大桁。
///
/// 印の形の正本は`harness_sandbox::tier2a::session_profile::session_token`で、
/// 試験`the_longest_session_token_still_has_the_shape_of_a_real_one`がこのプロセスの本物の印と
/// 形を突き合わせる（形が変わったらその試験が赤くなる）。
const LONGEST_SESSION_TOKEN: &str = "4294967295-9999999999";

/// 遷移先`to_domain`が、`harness.exe`の入れ物の名前として**どのセッションでも使えるか**。
/// 使えなければ理由を返す。
///
/// # 判定は`harness-sandbox`の持ち主の判定そのものに聞く
///
/// 最も長いセッションの印で入れ物の名前を組み、`session_profile::token_of_profile`（GCと
/// 「生きている他セッション」の名簿が使う唯一の入口）が**同じ印を読み戻せるか**を見る。
/// 読み戻せないのは、名前に使えない文字がある・長すぎる（入れ物の名前は64文字まで。
/// `harness.exe`は起動時にその遷移先を用意できない）ときである。
///
/// `.`はかつて暫定で断っていた——持ち主の判定が名前の**最後の**`.`で印を切っていたので、
/// `a.b`の`a`を印の一部と読み違えたためである。2026-10-01に判定が最初の`.`で切るよう直った
/// （[BUG-189](../../../docs/bugs/BUG-189.md)）ので、**この関数は何も変えずに通すようになった**
/// （判定を写さずに聞いているため）。
///
/// 編集時検査（`harness_policy::transition`の`check_domain_name`）は50文字で通すので、
/// 長さはそれより厳しい。**決定63が「自動生成名の検証を『あれば良い』に落とさない——検証が無いと
/// 承認は通るのにプロファイル生成が実行時に落ちる」と決めた**のと同じ理由で、書く前に断る。
pub fn profile_name_problem(to_domain: &str) -> Option<String> {
    if name_round_trips(to_domain) {
        return None;
    }
    Some(format!(
        "harness.exe の入れ物（AppContainerプロファイル）の名前にできません——\
         使えるのは英数字と「-」「.」だけで、長さは {}文字までです",
        longest_accepted_name_len()
    ))
}

fn name_round_trips(to_domain: &str) -> bool {
    let name = format!("{DOMAIN_PROFILE_PREFIX}.{LONGEST_SESSION_TOKEN}.{to_domain}");
    harness_sandbox::tier2a::session_profile::token_of_profile(&name)
        == Some(LONGEST_SESSION_TOKEN)
}

/// どのセッションでも入れ物の名前にできる最長の名前の長さ（**持ち主の判定に聞いて数える**。
/// 上限の値をここへ写さない）。
fn longest_accepted_name_len() -> usize {
    (1..=64)
        .take_while(|n| name_round_trips(&"x".repeat(*n)))
        .last()
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "transition_destination_tests.rs"]
mod transition_destination_tests;
