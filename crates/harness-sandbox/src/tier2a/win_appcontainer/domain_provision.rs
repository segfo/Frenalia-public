//! [#55] **遷移先ドメインの実体を用意する**（`plans/DESIGN-MAC-BROKER.md` §22.9）。
//!
//! # 何のためにあるのか
//!
//! 遷移の判定器は「このプログラムはドメインDで動かしてよい」まで答えを出すが、
//! **Dで実際に起こすにはDの実体——`(package SID, capability SIDの組)`——が要る**（§22.1）。
//! それは`policy.json`に書かれておらず、**このセッションで作るもの**である。ここがその発行器で、
//! 作った表をSpawn Daemonへ渡す（`spawnd::ControlRequest::Hello::domains`）。
//!
//! # 起動時にまとめて用意する
//!
//! 遷移が起きた瞬間に作る形は**採れない**——許可を配る操作が任意の時点で起き、
//! 昇格が要る場面ではそこでUACが出る。起動あたりのUACを1回に抑える設計と衝突する。
//! 費用は測ってある（`plans/mac-spike/RESULTS.md` §S72）——1ドメインあたり17〜19msで線形、
//! 実測された現実的な数（11本）で211ms。
//!
//! # **新しい許可は1本も付けない**（骨格の定義）
//!
//! ここは`lookup`しかしない。**発行も付与もしない**——`preflight`が既に許可した宣言の
//! 宛先SIDを引くだけである。引けなければ**そのドメインは用意しない**（fail-closed）。
//!
//! そうしている理由は2つある。
//!
//! 1. **ACLを書く経路を増やさない。** 書く経路が増えるほど、片方だけが台帳へ記録する／
//!    片方だけが撤収できる、という形の事故が起きる（BUG-017の孤立ACEと同型）
//! 2. **`harness.exe`が`policy.json`の`fs`を使い始めるのは別の決定である**
//!    （残課題#30）。骨格でそこへ踏み込むと、2つの変更の切り分けができなくなる
//!
//! # 採らなかった逃げ方
//!
//! **呼び出し元のcapabilityのまま名前だけ遷移先にする**形は採らない（§10.1.2）。
//! 宣言では狭めたつもりの遷移が1ビットも狭まらず、しかも**その食い違いは症状として出ない**
//! ——「分けたつもり」で全部が同じ権限のまま動き続ける。

use std::path::Path;

use harness_policy::policy_file::{PolicyFile, ENTRY_DOMAIN};

use super::AppContainerError;
use crate::tier2a::spawnd::{DomainIdentitySpec, DomainSpec};

/// 1ドメインを用意した結果。
///
/// **用意できなかったことも値で返す**（`B-10`）。黙って表から落とすと、
/// 「宣言したのに断られる」の原因が画面のどこにも出ない。
#[derive(Debug)]
pub struct Provisioned {
    /// Daemonへ渡す表（用意できたものだけ）。
    pub domains: Vec<DomainSpec>,
    /// 用意できなかったドメインと、その理由。**呼び出し側は必ず出すこと。**
    pub skipped: Vec<(String, String)>,
}

/// 宣言から、**入口ドメイン以外の遷移先**を重複なく拾う。
///
/// 入口ドメインを除くのは、そこが呼び出し元自身だからである（自己ループは表を引かない）。
fn target_domain_names(policy: &PolicyFile) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for domain in &policy.domains {
        for edge in &domain.process.transitions {
            if edge.to == ENTRY_DOMAIN || names.iter().any(|n| n == &edge.to) {
                continue;
            }
            names.push(edge.to.clone());
        }
    }
    names
}

/// ドメイン`name`のcapability SIDの組を、**既に許可済みの宣言から引く**。
///
/// **発行しない。** 1件でも引けなければ`Err`——そのドメインは用意しない。
fn capability_sids_for(
    policy: &PolicyFile,
    canonical_workspace: &Path,
    workspace_mode: &str,
    name: &str,
) -> Result<Vec<String>, String> {
    let Some(domain) = policy.domain(name) else {
        return Err(format!(
            "policy.jsonに`{name}`というドメインの定義が無い（遷移先として名指しされているだけ）"
        ));
    };
    // **通信を宣言するドメインは用意しない。** 通信はcapabilityとWFPの両方で閉じており、
    // 片方だけ用意すると**素通しになる**（`internetClient`を持ったまま既定拒否だけを失う形は
    // 既知の欠陥として`tier2a::wfp`のdocが書いている）。WFPの欄とドメイン専用プロキシは
    // この回の範囲外なので、**断る側へ倒す**。
    if !domain.net.allow_domains.is_empty() {
        return Err(format!(
            "`{name}`は通信を宣言している（{}件）。ドメインごとの出口制御はまだ無いので用意しない\
             ——capabilityだけ与えると既定拒否が効かず素通しになる",
            domain.net.allow_domains.len()
        ));
    }

    // このセッションの**どのドメインの子も共通で携えるもの**を先に積む。
    //
    // # なぜ「呼び出し元のcapabilityをそのまま渡す」ことにならないのか
    //
    // §10.1.2が却下したのは**呼び出し元の組をまるごと渡す**形である。ここで積むのは
    // 「そのセッションの全Tier2a子が持つ共通の土台」だけで、**宣言ごとの穴
    // （`--fs-allow`）は積まない**——そこが狭まる軸である。土台を外すと、
    // 用意したドメインは**何も読めず何も起こせない**ので、分けた意味の前に動かなくなる。
    //
    // | 何 | なぜ全ドメインが要るのか |
    // |---|---|
    // | 祖先traverse（D-37） | これが無いとどのパスへも辿り着けない |
    // | spawn要求用 | 無いと孫を頼めず、鎖がそのドメインで必ず止まる |
    // | workspace（D-54） | 子のcwdはワークスペースの中で、そこが見えないと何も動かない |
    // | Redirector DLL | 注入の失敗は生成ごと落とす（BUG-116）。無いと必ず起動に失敗する |
    //
    // **narrowingはワークスペースの外に対して効く**——それがこの骨格の射程である。
    //
    // **[BUG-180] CoWの差分層は、意図してここへ入れない。** CoWではワークスペースの書ける側が
    // 差分層なので、遷移先の子にも差分層のSIDが要る（無いと変更前の中身を黙って読む）。
    // だが差分層は`/sessions`・`/fork`で作り直され、宛先SIDも変わる——起動時に1回だけ作る
    // この表へ入れると、古い差分層のSIDを持ち続ける。差分層のSIDはharnessがトップレベルを
    // 起こすたびに注入設定と一緒に送り、Daemonの`spawnd/child_plan.rs`が積む。
    let traverse = super::traverse_capability_sid()
        .map_err(|e| format!("traverse capabilityを導出できない: {e}"))?;
    let spawn_request = super::spawn_request_capability_sid()
        .map_err(|e| format!("spawn要求用capabilityを導出できない: {e}"))?;
    let workspace_cap = super::workspace_capability_sid(canonical_workspace, workspace_mode)
        .map_err(|e| format!("workspace capabilityを導出できない: {e}"))?;
    let mut sids = vec![
        crate::win_common::sid_to_string(traverse.as_psid())
            .map_err(|e| format!("sid_to_string(traverse): {e}"))?,
        crate::win_common::sid_to_string(spawn_request.as_psid())
            .map_err(|e| format!("sid_to_string(spawn request): {e}"))?,
        crate::win_common::sid_to_string(workspace_cap.as_psid())
            .map_err(|e| format!("sid_to_string(workspace): {e}"))?,
    ];
    // Redirector DLLの宛先（§22.9の前提で宣言宛へ移したもの）。**引くだけで発行しない。**
    for dll_cap in super::redirector_dll_capability_sids() {
        sids.push(
            crate::win_common::sid_to_string(dll_cap.as_psid())
                .map_err(|e| format!("sid_to_string(redirector dll): {e}"))?,
        );
    }

    for (declared, access) in domain.fs.entries() {
        // 宣言値から**ACEが載るオブジェクト**を出す（`C:/x/**`なら`C:/x`）。
        // 変換の定義は1つだけである（D-63）。
        let object = harness_policy::normalize::literal_prefix(declared);
        // 設定の語彙から**許可を書く側の語彙**へ移す。`settings_key()`が同じ綴りを返すからと
        // いってそちらを使わない——同じ文字列を2つの型が別々に持つと、片方に級が増えた日に
        // 静かにずれる（`B-05`）。級は宛先SIDの鍵そのものなので、ずれると
        // 「ACEは正しいのに子から一切読めない」形になる。
        let access = crate::shell_tier::FsAccess::from_settings(access);
        let Some(capability_name) =
            crate::tier2a::workspace_capability::lookup_declaration_capability_name(
                canonical_workspace,
                Path::new(object),
                access.label(),
            )
        else {
            return Err(format!(
                "`{name}`が宣言している `{declared}`（{}）が、このセッションでは許可されていない\
                 ——骨格では新しい許可を付けないので用意しない。\
                 同じパスを`--fs-allow`か設定でも宣言すると用意できる",
                access.label()
            ));
        };
        sids.push(
            crate::win_common::sid_to_string(
                super::capability_sid_from_name(&capability_name)
                    .map_err(|e| format!("capability SIDを導出できない（{capability_name}）: {e}"))?
                    .as_psid(),
            )
            .map_err(|e| format!("sid_to_string(capability): {e}"))?,
        );
    }
    Ok(sids)
}

/// 宣言に現れる遷移先ドメインを**用意できるものだけ**用意する。
///
/// `canonical_workspace`は`canonicalize`済みを渡すこと（許可を引く鍵の一部である）。
///
/// # 入れ物を作る前に台帳へ記録する
///
/// 逆順だと、作成直後に落ちた場合に「実在するが台帳に無い入れ物」が残る
/// （`session_profile::record_domain_profile`のdocと同じ順序の不変条件）。
pub fn provision_target_domains(
    policy: &PolicyFile,
    canonical_workspace: &Path,
    // workspaceのアクセスモード（`"rwx"`/`"ro"`）。**`preflight`が付与したのと同じ語彙**で
    // なければ別のcapability SIDを導出し、ワークスペースが一切見えない子ができる。
    workspace_mode: &str,
) -> Provisioned {
    let mut domains = Vec::new();
    let mut skipped = Vec::new();

    for name in target_domain_names(policy) {
        let capability_sids =
            match capability_sids_for(policy, canonical_workspace, workspace_mode, &name) {
                Ok(sids) => sids,
                Err(reason) => {
                    skipped.push((name, reason));
                    continue;
                }
            };

        // **記録してから作る**（上記）。
        let profile_name = crate::tier2a::session_profile::record_domain_profile(&name);
        let container = match super::ensure_profile(&profile_name) {
            Ok(sid) => sid,
            Err(e) => {
                skipped.push((name, format!("入れ物を作れなかった（{profile_name}）: {e}")));
                continue;
            }
        };
        let container_sid = match crate::win_common::sid_to_string(container.as_psid()) {
            Ok(text) => text,
            Err(e) => {
                skipped.push((name, format!("package SIDを文字列にできない: {e}")));
                continue;
            }
        };

        domains.push(DomainSpec {
            name: profile_name,
            policy_domain: name,
            container_sid,
            capability_sids,
            // **このドメインは自分専用のpackage SIDを持つ**ので、身分はpackage SIDそのものである
            // （§22.1.1の`OwnPackage`）。呼び出し元のcapabilityを身分に流用しない。
            identity: DomainIdentitySpec::OwnPackage,
        });
    }

    Provisioned { domains, skipped }
}

/// 用意したドメインのpackage SIDを、制御面（`.harness/`）の保護へ渡すための一覧。
///
/// **保護の一覧へ入れる責任は呼び出し側にある**——ここは文字列を配るだけで、
/// どのノードをどう守るかは`revoke::protect_harness_control_dir_from_appcontainer`が持つ。
pub fn container_sids(provisioned: &Provisioned) -> Result<Vec<String>, AppContainerError> {
    Ok(provisioned
        .domains
        .iter()
        .map(|d| d.container_sid.clone())
        .collect())
}

#[cfg(test)]
#[path = "domain_provision_tests.rs"]
mod domain_provision_tests;
