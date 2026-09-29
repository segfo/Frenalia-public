//! [`ChildPlan`]の単体テスト。**昇格も実プロセスも要らない**——呼ぶWin32は
//! `sid_from_string`（文字列→SID）だけで、呼び出し元は[`ProcessTable`]から実物の形で作る。

use super::*;
use crate::tier2a::spawnd::table::ProcessTable;

/// ハンドル値は台帳の中ではただの整数である（`table_tests.rs`と同じ）。
const JOB: u64 = 0x1000;
const PROC_TOP: u64 = 0x11;

/// 呼び出し元（入口ドメイン）の実体。`ConvertStringSidToSidW`が受け付ければ値は何でもよい。
fn entry_domain() -> DomainSpec {
    DomainSpec {
        name: "entry-profile".to_string(),
        // **`name`と別の綴りにしておく**——同じにすると、2つの欄を取り違えた実装でも
        // 自己ループの判定が通ってしまう。
        policy_domain: "entry".to_string(),
        container_sid: "S-1-15-2-1-2-3".to_string(),
        capability_sids: vec!["S-1-15-3-1024-1".to_string()],
        identity: DomainIdentitySpec::OwnPackage,
    }
}

/// `Hello`の表に載っている遷移先ドメインの実体。
fn target_domain() -> DomainSpec {
    DomainSpec {
        name: "d0-profile".to_string(),
        policy_domain: "d0".to_string(),
        container_sid: "S-1-15-2-4-5-6".to_string(),
        capability_sids: vec!["S-1-15-3-1024-2".to_string()],
        identity: DomainIdentitySpec::OwnPackage,
    }
}

/// 台帳へトップレベルを1人載せ、その人を要求元として引いたもの。
fn caller_with(redirector: Option<RedirectorSpec>) -> Caller {
    let mut table = ProcessTable::new();
    table
        .register_top_level(4200, PROC_TOP, JOB, entry_domain(), Vec::new(), redirector)
        .expect("register the top-level process");
    table.resolve(4200, |_| true).expect("resolve the caller")
}

fn lazy_spec() -> RedirectorSpec {
    RedirectorSpec::Lazy {
        workspace_root: r"C:\ws".to_string(),
        broker_pipe: r"\\.\pipe\harness-broker-x".to_string(),
    }
}

// --- ドメインの宛先とトークンの振り分け（server.rsから移したもの） ---

fn spec(identity: DomainIdentitySpec) -> DomainSpec {
    DomainSpec {
        identity,
        ..entry_domain()
    }
}

/// **ドメインの宛先に指定したSIDが、トークンへ積まれてはいけない。**
///
/// 宛先に使うこと（誰がこの子を開けるか）と名乗ること（この子が何を持っているか）は
/// 別の決定である。混ぜると、**宛先を指定しただけで権限が1つ増える**——しかも
/// 増えたことはどこにも出ない（`B-10`）。
#[test]
fn the_domain_identity_sid_is_not_added_to_the_token_capabilities() {
    let domain = spec(DomainIdentitySpec::Capability {
        sid: "S-1-15-3-1024-9".to_string(),
    });
    let resolved = ChildPlan::top_level(&domain, None)
        .resolve()
        .expect("resolve");

    assert_eq!(
        resolved.capability_attributes().len(),
        1,
        "宣言していないcapabilityがトークンへ積まれている。\
         ドメインの宛先SIDを指定しただけで権限が1つ増える形になっている"
    );
    assert!(
        matches!(resolved.domain_identity(), DomainIdentity::Capability(_)),
        "宛先が capability として渡っていない"
    );
}

/// **対の側**（`B-35`）: package SIDそのものがドメインなら、宛先SIDは持たない。
///
/// 片方だけだと、`identity`を常に`None`にする実装でも上のテストが通る。
#[test]
fn own_package_carries_no_extra_identity_sid() {
    let domain = spec(DomainIdentitySpec::OwnPackage);
    let resolved = ChildPlan::top_level(&domain, None)
        .resolve()
        .expect("resolve");
    assert_eq!(resolved.capability_attributes().len(), 1);
    assert!(
        matches!(resolved.domain_identity(), DomainIdentity::OwnPackage),
        "package SIDをドメインにする指定が capability に化けている"
    );
}

// --- 計画の骨格 ---

/// トップレベルは**電文の値をそのまま**使い、ドメインを跨がない。
#[test]
fn a_top_level_plan_takes_the_request_as_is() {
    let domain = entry_domain();
    let spec = lazy_spec();
    let plan = ChildPlan::top_level(&domain, Some(&spec));

    assert_eq!(plan.domain(), &domain);
    assert_eq!(plan.redirector(), Some(&spec));
    assert!(!plan.crosses_domains(), "トップレベルに呼び出し元は居ない");
}

/// 自己ループは**跨がない**、別ドメインは**跨ぐ**（対。`B-35`）。
///
/// 片方だけだと、常に同じ答えを返す実装でも通る。跨ぐかどうかは、呼び出し元へ返す
/// ハンドルの権限を絞るかを決める（#49）。
#[test]
fn a_self_loop_does_not_cross_domains_but_a_transition_to_another_domain_does() {
    let caller = caller_with(None);

    let self_loop = ChildPlan::nested(&caller, &caller.domain);
    assert!(!self_loop.crosses_domains());
    assert_eq!(self_loop.domain(), &caller.domain);

    let target = target_domain();
    let transition = ChildPlan::nested(&caller, &target);
    assert!(transition.crosses_domains());
    assert_eq!(
        transition.domain(),
        &target,
        "プロセス表へ載せるのは遷移先の実体でなければならない（呼び出し元のドメインを載せると、\
         狭めたはずの子が呼び出し元の遷移権で判定される）"
    );
}

/// 注入設定を持たない系統の子には、何も注入しない。
#[test]
fn a_lineage_without_a_redirector_injects_nothing() {
    let caller = caller_with(None);
    let target = target_domain();
    assert_eq!(ChildPlan::nested(&caller, &target).redirector(), None);
    assert_eq!(
        ChildPlan::nested(&caller, &caller.domain).redirector(),
        None
    );
}
