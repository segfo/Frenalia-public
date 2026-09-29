//! Daemonが起こす子1人ぶんの**持ち物**——トークンへ積むcapabilityと、注入するRedirectorの
//! 設定——を1か所で決める。
//!
//! # 何のためにあるのか
//!
//! Daemonが子のトークンを組む場所は2つある（トップレベル＝`server::spawn_top_level`、
//! 入れ子＝`server::spawn_nested`）。それぞれが自分で組むと、片方にだけ足した規則が
//! もう片方に届かない——BUG-169は「同じ一覧を2か所で組み立てて、片方に1種類足りない」形で
//! 実機テスト18本が7日間赤のままだった。
//!
//! そこで**トークンの材料になる[`ResolvedDomain`]は[`ChildPlan::resolve`]からしか作れない**
//! ようにしてある。2か所とも必ずここを通るので、規則を足す場所は1つで済む。
//!
//! # Win32をほとんど呼ばない
//!
//! 呼ぶのは`sid_from_string`（文字列→SIDの変換）だけで、昇格も実機も要らない。
//! 判定の全体を`cargo test`で固定できる（`child_plan_tests.rs`）。

use windows::Win32::Security::{PSID, SID_AND_ATTRIBUTES};

use crate::tier2a::win_appcontainer::DomainIdentity;
use crate::win_common::{sid_from_string, OwnedSid};

use super::table::Caller;
use super::{DomainIdentitySpec, DomainSpec, RedirectorSpec};

/// `SECURITY_CAPABILITIES`へ積むときの属性（`spawn_with_workspace`と同じ値）。
const SE_GROUP_ENABLED: u32 = 0x0000_0004;

/// 子1人ぶんの持ち物の計画。
///
/// **プロセス表へ載せるドメイン（[`ChildPlan::domain`]）と、トークンへ積むcapability
/// （[`ChildPlan::capability_sids`]）は別の値である。** 前者は`Hello`の表／電文の値そのもので、
/// 後者はそこへ計画が足したものを含み得る。表へ載せる側を書き換えないのは、
/// 同じ事実の正本を2つ持たないためである（`B-13`）。
pub(super) struct ChildPlan<'a> {
    domain: &'a DomainSpec,
    capability_sids: Vec<String>,
    redirector: Option<RedirectorSpec>,
    crosses_domains: bool,
}

impl<'a> ChildPlan<'a> {
    /// harnessが頼んだトップレベルの子。ドメインもRedirectorの設定も電文の値である。
    ///
    /// トップレベルは呼び出し元を持たないので、**ドメインを跨ぐことは無い**。
    pub(super) fn top_level(domain: &'a DomainSpec, redirector: Option<&RedirectorSpec>) -> Self {
        Self::build(domain, redirector.cloned(), false)
    }

    /// サンドボックスの中から頼まれた入れ子の子。
    ///
    /// ドメインは判定が選んだ遷移先（自己ループなら呼び出し元と同じ値、別ドメインなら
    /// `Hello`の表の値）、Redirectorの設定は呼び出し元のもの。
    pub(super) fn nested(caller: &Caller, target_domain: &'a DomainSpec) -> Self {
        // [#49] **ドメインを跨ぐか。** 値が1ビットでも違えば跨いだ扱いにする（fail-closed）。
        // ここで1回だけ決める——同じ判断を2か所に置くと、片方だけ直る。
        let crosses_domains = target_domain != &caller.domain;
        Self::build(target_domain, caller.redirector.clone(), crosses_domains)
    }

    fn build(
        domain: &'a DomainSpec,
        redirector: Option<RedirectorSpec>,
        crosses_domains: bool,
    ) -> Self {
        Self {
            domain,
            capability_sids: domain.capability_sids.clone(),
            redirector,
            crosses_domains,
        }
    }

    /// プロセス表へ載せるドメイン。**この子が次に何かを頼んだときの`from`になる。**
    pub(super) fn domain(&self) -> &'a DomainSpec {
        self.domain
    }

    /// この子へ注入するRedirectorの設定。`None`は注入しない。
    pub(super) fn redirector(&self) -> Option<&RedirectorSpec> {
        self.redirector.as_ref()
    }

    /// 呼び出し元とドメインを跨ぐか（[#49] 返すハンドルの権限を絞る判断に使う）。
    pub(super) fn crosses_domains(&self) -> bool {
        self.crosses_domains
    }

    /// 文字列のSIDを、`CreateProcessW`へ渡せる形へ戻す。
    ///
    /// **[`ResolvedDomain`]を作る口はここだけである**（モジュールdocの理由）。
    pub(super) fn resolve(&self) -> Result<ResolvedDomain, String> {
        let container = sid_from_string(&self.domain.container_sid).map_err(|e| {
            format!(
                "sid_from_string(container {}): {e}",
                self.domain.container_sid
            )
        })?;
        let mut capabilities = Vec::with_capacity(self.capability_sids.len());
        for sid in &self.capability_sids {
            capabilities.push(
                sid_from_string(sid)
                    .map_err(|e| format!("sid_from_string(capability {sid}): {e}"))?,
            );
        }
        let identity = match &self.domain.identity {
            DomainIdentitySpec::OwnPackage => None,
            DomainIdentitySpec::Capability { sid } => Some(
                sid_from_string(sid)
                    .map_err(|e| format!("sid_from_string(domain identity {sid}): {e}"))?,
            ),
        };
        Ok(ResolvedDomain {
            container,
            capabilities,
            identity,
        })
    }
}

/// ワイヤ上のドメイン（文字列のSID）を、`CreateProcessW`へ渡せる形へ戻したもの。
///
/// **`OwnedSid`を持ち続けることに意味がある。** `PSID`は生ポインタなので、
/// 元の所有者が落ちた瞬間に宙を指す——`CreateProcessW`が終わるまでこの構造体を生かす。
pub(super) struct ResolvedDomain {
    container: OwnedSid,
    capabilities: Vec<OwnedSid>,
    /// `None`＝package SIDそのものがドメイン（[`DomainIdentitySpec::OwnPackage`]）。
    ///
    /// **capability列とは別に持つ。** ここへ混ぜると、ドメインの宛先として指定しただけの
    /// SIDが**トークンへ積まれる**（＝黙って権限が1つ増える）。宛先に使うことと
    /// 名乗ることは別の決定である。
    identity: Option<OwnedSid>,
}

impl ResolvedDomain {
    /// package SID。
    pub(super) fn container_psid(&self) -> PSID {
        self.container.as_psid()
    }

    /// トークンへ積むcapability（**`identity`は含めない**。上記）。
    pub(super) fn capability_attributes(&self) -> Vec<SID_AND_ATTRIBUTES> {
        self.capabilities
            .iter()
            .map(|sid| SID_AND_ATTRIBUTES {
                Sid: sid.as_psid(),
                Attributes: SE_GROUP_ENABLED,
            })
            .collect()
    }

    pub(super) fn domain_identity(&self) -> DomainIdentity {
        match &self.identity {
            Some(sid) => DomainIdentity::Capability(sid.as_psid()),
            None => DomainIdentity::OwnPackage,
        }
    }
}

#[cfg(test)]
#[path = "child_plan_tests.rs"]
mod child_plan_tests;
