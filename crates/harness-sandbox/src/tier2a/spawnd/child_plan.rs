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
//! # いまここが持つ規則
//!
//! **注入するRedirectorが要る宛先SIDを、トークンへ必ず積む**（[`required_capability`]）。
//! CoWの注入設定なら差分層の宛先SIDである。
//!
//! これが無かったのがBUG-180である。別ドメインへの遷移では、トークンの材料が
//! `Hello`の表（起動時に用意した遷移先ドメインの実体）から来る。表には差分層のSIDが無い
//! ——差分層はセッションごとに作り直されるので、起動時の表には入れられない。
//! 一方でRedirectorは呼び出し元と同じCoWの設定で注入されていたので、
//! **子は差分層へ書けず、読むと変更前の中身が黙って返っていた。**
//!
//! 差分層のSIDは、トップレベルを起こすたびにharnessが注入設定と一緒に送ってくる
//! （[`RedirectorSpec::Cow`]の`diff_layer_capability_sid`）。**注入設定と対で運ぶ**ので、
//! その設定で注入する子には必ず同じSIDが積まれる。
//!
//! **別ドメインへ移る子からは、ワークスペース外への誘導を外す**（[`redirector_for_nested`]）。
//! 差分層の許可を渡すだけだと、遷移先が持たない`--fs-allow`の書込先へ、その子が
//! 変更を承認待ちとして置けてしまうためである。
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
    /// `Hello`の表の値）。Redirectorの設定は呼び出し元へ注入したものから始め、
    /// **ドメインを跨ぐならワークスペース外への誘導を外す**（[`redirector_for_nested`]）。
    pub(super) fn nested(caller: &Caller, target_domain: &'a DomainSpec) -> Self {
        // [#49] **ドメインを跨ぐか。** 値が1ビットでも違えば跨いだ扱いにする（fail-closed）。
        // ここで1回だけ決める——同じ判断を2か所に置くと、片方だけ直る。
        let crosses_domains = target_domain != &caller.domain;
        let redirector = redirector_for_nested(caller.redirector.as_ref(), crosses_domains);
        Self::build(target_domain, redirector, crosses_domains)
    }

    fn build(
        domain: &'a DomainSpec,
        redirector: Option<RedirectorSpec>,
        crosses_domains: bool,
    ) -> Self {
        Self {
            domain,
            capability_sids: capabilities_for(domain, redirector.as_ref()),
            redirector,
            crosses_domains,
        }
    }

    /// プロセス表へ載せるドメイン。**この子が次に何かを頼んだときの`from`になる。**
    ///
    /// トークンへ積むもの（[`Self::capability_sids`]）と違って、計画が足したSIDを含まない
    /// ——差分層のSIDは系統の注入設定が持つ事実で、ドメインの事実ではない。
    pub(super) fn domain(&self) -> &'a DomainSpec {
        self.domain
    }

    /// トークンへ積むcapability SID（文字列）。ドメインのものに、注入設定が要るものを足した値。
    ///
    /// 製品の経路は[`Self::resolve`]がこの値を直接読む。テストが同じ値を文字列のまま見るための口である。
    #[cfg(test)]
    pub(super) fn capability_sids(&self) -> &[String] {
        &self.capability_sids
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

/// [BUG-180] **この注入設定で動くRedirectorが、子のトークンに要求する宛先SID。**
///
/// **`_`を書かない。** 注入設定の種類を足した日に、ここがコンパイルできなくなる——
/// 新しい種類が何かへ届く必要があるかを、足す人に必ず答えさせるためである。
fn required_capability(spec: &RedirectorSpec) -> Option<&str> {
    match spec {
        RedirectorSpec::Cow {
            diff_layer_capability_sid,
            ..
        } => Some(diff_layer_capability_sid.as_str()),
        // lazyの受付はパイプ経由で、Redirectorが自分で開く場所を持たない。
        RedirectorSpec::Lazy { .. } => None,
        // プロセス生成フックだけで、ファイル系フックは差分層を持たない。
        RedirectorSpec::ProcessHooks { .. } => None,
    }
}

/// トークンへ積むcapability SIDの一覧。ドメインのものに、注入設定が要るものを足す。
///
/// **既に在れば足さない（重複を必ず除く）。** トップレベルの電文のドメインには、
/// harnessが差分層のSIDを既に入れている（`win_appcontainer/launch.rs`）。同じSIDが
/// `SECURITY_CAPABILITIES`に2つ並ぶと`CreateProcessW`が`ERROR_INVALID_PARAMETER`で落ちる
/// （`spawnd_e2e_tests.rs`の`setup_with_transitions_and_domains`に同じ注記がある）。
fn capabilities_for(domain: &DomainSpec, redirector: Option<&RedirectorSpec>) -> Vec<String> {
    let mut sids = domain.capability_sids.clone();
    if let Some(required) = redirector.and_then(required_capability) {
        if !sids.iter().any(|sid| sid.eq_ignore_ascii_case(required)) {
            sids.push(required.to_string());
        }
    }
    sids
}

/// [BUG-180] 入れ子の子へ注入する設定。**別ドメインへ移る子からは、ワークスペース外への
/// 書込を差分層へ向ける設定（`ext_capture_roots`）を外す**（ユーザー判断、2026-09-29）。
///
/// 自己ループなら呼び出し元へ注入した設定をそのまま使う。
///
/// # なぜ外すのか
///
/// `ext_capture_roots`は`--fs-allow <path>:rw`で開けたワークスペース外の書込先で、
/// **呼び出し元の宣言ごとの穴**である。遷移先ドメインはこの穴を引き継がない——
/// 狭めるのはワークスペースの外に対して、が§22.9の決定である。ところが差分層の許可を
/// 持った子（BUG-180の修正で積むようになった）がこの設定のまま動くと、**許可を持たない
/// ワークスペース外のパスへ新しいファイルを承認待ちとして置ける**。承認
/// （`harness apply --dangerously-allow`）のときには、呼び出し元の変更と見分けられない。
///
/// 外すと、その子のワークスペース外への書込は本物のパスへ向かい、ACLで拒否される
/// （CoWを使わない構成と同じ結果になる）。
///
/// # 外した後も残るもの（限界）
///
/// - **Redirectorは境界ではない**（D-01）。差分層のSIDは差分層全体（`_ext`を含む）に効くので、
///   `_ext`のパスを直接指定するプログラムは読み書きできる。ここで止まるのは、普通のツールが
///   自動でワークスペース外の変更を積む経路と、変更後の中身を見せる経路だけである
///   （塞ぐには`_ext`を別のディレクトリ・別の宛先SIDに分ける。`docs/STATUS.md`の残課題）
/// - 呼び出し元が差分層で変えたワークスペース外のファイルをこの子が読むと、**変更前の中身**が
///   見える（その読取を遷移先ドメインが宣言している場合だけ。宣言していなければ読めない）
/// - lazyの受付・プロセス生成フックの設定は跨いでもそのまま渡している。別ドメインで
///   それが適切かは今回見ていない
///
/// **外した子の子孫も外れたまま**である——Daemonはこの値をその子のエントリへ登録し
/// （`table`の`Entry::redirector`）、孫の計画はそこから始まる。
fn redirector_for_nested(
    inherited: Option<&RedirectorSpec>,
    crosses_domains: bool,
) -> Option<RedirectorSpec> {
    let spec = inherited?;
    Some(match spec {
        // **`..`を書かない。** 欄を足した日に、ここで「跨ぐ子へ渡してよいか」を答えさせる。
        RedirectorSpec::Cow {
            workspace_root,
            diff_layer_dir,
            ext_capture_roots,
            diff_layer_capability_sid,
        } => RedirectorSpec::Cow {
            workspace_root: workspace_root.clone(),
            diff_layer_dir: diff_layer_dir.clone(),
            ext_capture_roots: if crosses_domains {
                Vec::new()
            } else {
                ext_capture_roots.clone()
            },
            diff_layer_capability_sid: diff_layer_capability_sid.clone(),
        },
        RedirectorSpec::Lazy { .. } | RedirectorSpec::ProcessHooks { .. } => spec.clone(),
    })
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
