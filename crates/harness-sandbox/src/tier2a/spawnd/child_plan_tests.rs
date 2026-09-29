//! [`ChildPlan`]の単体テスト。**昇格も実プロセスも要らない**——呼ぶWin32は
//! `sid_from_string`（文字列→SID）だけで、呼び出し元は[`ProcessTable`]から実物の形で作る。
//!
//! # 何が壊れたときに、ここが赤くなるのか
//!
//! | 壊れ方 | 被害 |
//! |---|---|
//! | 注入設定が要るSIDをトークンへ積まない | 別ドメインへ移った子が差分層へ届かず、変更前の中身を黙って読む（BUG-180） |
//! | 同じSIDを2回積む | `CreateProcessW`が`ERROR_INVALID_PARAMETER`で落ち、CoWのトップレベルが1つも起きない |
//! | 呼び出し元の宣言ごとの穴まで遷移先へ渡す | 遷移で狭めたつもりが1ビットも狭まらない（§10.1.2が却下した形） |

use super::*;
use crate::tier2a::spawnd::table::ProcessTable;

/// ハンドル値は台帳の中ではただの整数である（`table_tests.rs`と同じ）。
const JOB: u64 = 0x1000;
const PROC_TOP: u64 = 0x11;
const PROC_NESTED: u64 = 0x22;

// 子のトークンへ積む宛先を、**種類が見分けられる値**で置く（`win_appcontainer.rs`の
// `DomainCapabilities`のdocが挙げる4種類＋全Tier2a子が共通で持つ2つ）。
// `ConvertStringSidToSidW`が受け付ければ値は何でもよい。
const TRAVERSE: &str = "S-1-15-3-1024-100";
const SPAWN_REQUEST: &str = "S-1-15-3-1024-101";
const WORKSPACE: &str = "S-1-15-3-1024-102";
const FS_ALLOW: &str = "S-1-15-3-1024-103";
const DIFF_LAYER: &str = "S-1-15-3-1024-104";
const REDIRECTOR_DLL: &str = "S-1-15-3-1024-105";

fn sids(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// 呼び出し元（入口ドメイン）の実体。**製品のトップレベルと同じ中身**である——
/// `launch.rs`はworkspace・`--fs-allow`の穴・差分層・Redirector DLLを積み、
/// `spawn_with_workspace_via_daemon`がtraverseとspawn要求用を足す。
fn entry_domain() -> DomainSpec {
    DomainSpec {
        name: "entry-profile".to_string(),
        // **`name`と別の綴りにしておく**——同じにすると、2つの欄を取り違えた実装でも
        // 自己ループの判定が通ってしまう。
        policy_domain: "entry".to_string(),
        container_sid: "S-1-15-2-1-2-3".to_string(),
        capability_sids: sids(&[
            TRAVERSE,
            SPAWN_REQUEST,
            WORKSPACE,
            FS_ALLOW,
            DIFF_LAYER,
            REDIRECTOR_DLL,
        ]),
        identity: DomainIdentitySpec::OwnPackage,
    }
}

/// `Hello`の表に載っている遷移先ドメインの実体。**`domain_provision`が積む土台だけ**で、
/// 宣言ごとの穴（`--fs-allow`）も差分層も無い。
fn target_domain() -> DomainSpec {
    DomainSpec {
        name: "d0-profile".to_string(),
        policy_domain: "d0".to_string(),
        container_sid: "S-1-15-2-4-5-6".to_string(),
        capability_sids: sids(&[TRAVERSE, SPAWN_REQUEST, WORKSPACE, REDIRECTOR_DLL]),
        identity: DomainIdentitySpec::OwnPackage,
    }
}

fn cow_spec() -> RedirectorSpec {
    RedirectorSpec::Cow {
        workspace_root: r"C:\ws".to_string(),
        diff_layer_dir: r"C:\cow\s1".to_string(),
        ext_capture_roots: vec![r"C:\outside".to_string()],
        diff_layer_capability_sid: DIFF_LAYER.to_string(),
    }
}

fn lazy_spec() -> RedirectorSpec {
    RedirectorSpec::Lazy {
        workspace_root: r"C:\ws".to_string(),
        broker_pipe: r"\\.\pipe\harness-broker-x".to_string(),
    }
}

fn process_hooks_spec() -> RedirectorSpec {
    RedirectorSpec::ProcessHooks {
        workspace_root: Some(r"C:\ws".to_string()),
    }
}

/// 注入設定の全種類と「注入しない」。**`match`に`_`を書かない**——種類を足した日に
/// ここがコンパイルできなくなり、下の網羅テストへ加えることを強制する。
fn every_redirector() -> Vec<Option<RedirectorSpec>> {
    let all = vec![cow_spec(), lazy_spec(), process_hooks_spec()];
    for spec in &all {
        match spec {
            RedirectorSpec::Cow { .. }
            | RedirectorSpec::Lazy { .. }
            | RedirectorSpec::ProcessHooks { .. } => {}
        }
    }
    std::iter::once(None)
        .chain(all.into_iter().map(Some))
        .collect()
}

/// 台帳へトップレベルを1人載せ、その人を要求元として引いたもの。
fn caller_with(redirector: Option<RedirectorSpec>) -> Caller {
    let mut table = ProcessTable::new();
    table
        .register_top_level(4200, PROC_TOP, JOB, entry_domain(), Vec::new(), redirector)
        .expect("register the top-level process");
    table.resolve(4200, |_| true).expect("resolve the caller")
}

/// 別ドメインへ移った子（孫を頼む側）。**Daemonが実際にするのと同じ手順で台帳へ載せる**
/// ——計画を立て、計画のドメインで登録し、引き直す。
fn cross_domain_child_with(redirector: Option<RedirectorSpec>, target: &DomainSpec) -> Caller {
    let mut table = ProcessTable::new();
    let lineage = table
        .register_top_level(4200, PROC_TOP, JOB, entry_domain(), Vec::new(), redirector)
        .expect("register the top-level process");
    let top = table
        .resolve(4200, |_| true)
        .expect("resolve the top-level");
    let plan = ChildPlan::nested(&top, target);
    table
        .register_in_lineage(
            4201,
            PROC_NESTED,
            lineage,
            plan.domain().clone(),
            plan.redirector().cloned(),
        )
        .expect("register the nested child");
    table
        .resolve(4201, |_| true)
        .expect("resolve the nested child")
}

fn count(sids: &[String], sid: &str) -> usize {
    sids.iter().filter(|s| s.eq_ignore_ascii_case(sid)).count()
}

// --- ドメインの宛先とトークンの振り分け（server.rsから移したもの） ---

fn spec(identity: DomainIdentitySpec) -> DomainSpec {
    DomainSpec {
        capability_sids: sids(&[WORKSPACE]),
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

// --- [BUG-180] 注入設定が要るSIDは、必ずトークンへ積まれる ---

/// **本体。** CoWの系統から別ドメインへ移った子は、差分層のSIDを**ちょうど1本**持つ。
///
/// 修正前は`Hello`の表の値（差分層を含まない）がそのままトークンになっていたので、
/// この子は差分層へ届かず、変更前の中身を黙って読んでいた。
#[test]
fn a_cross_domain_child_of_a_cow_lineage_carries_the_diff_layer_capability() {
    let caller = caller_with(Some(cow_spec()));
    let target = target_domain();
    assert_eq!(
        count(&target.capability_sids, DIFF_LAYER),
        0,
        "前提: 表の遷移先ドメインは差分層のSIDを持たない"
    );

    let plan = ChildPlan::nested(&caller, &target);
    assert!(plan.crosses_domains());
    assert_eq!(
        count(plan.capability_sids(), DIFF_LAYER),
        1,
        "別ドメインへ移ったCoWの子のトークンに差分層のSIDが無い（BUG-180）: {:?}",
        plan.capability_sids()
    );
    // **プロセス表へ載せるドメインは表の値のまま**（差分層は注入設定の事実で、
    // ドメインの事実ではない。`B-13`）。
    assert_eq!(plan.domain(), &target);
    // `resolve`まで通しても数が合う（文字列の一覧と実際にトークンへ積む一覧を分けない）。
    let resolved = plan.resolve().expect("resolve");
    assert_eq!(
        resolved.capability_attributes().len(),
        target.capability_sids.len() + 1
    );
}

/// **重複を除く側の歯。** トップレベルの電文のドメインには差分層のSIDが既に入っている。
/// もう1本足すと`CreateProcessW`が`ERROR_INVALID_PARAMETER`で落ち、CoWのシェルが起きない。
///
/// 大文字小文字だけ違う綴りでも同じSIDとして扱う（SIDの文字列表現は`S-1-…`で、
/// 比較する側が綴りに頼らないこと）。
#[test]
fn a_top_level_cow_child_carries_the_diff_layer_capability_exactly_once() {
    let domain = entry_domain();
    let plan = ChildPlan::top_level(&domain, Some(&cow_spec()));
    assert_eq!(count(plan.capability_sids(), DIFF_LAYER), 1);
    assert_eq!(plan.capability_sids(), domain.capability_sids.as_slice());

    let mut lower = cow_spec();
    if let RedirectorSpec::Cow {
        diff_layer_capability_sid,
        ..
    } = &mut lower
    {
        *diff_layer_capability_sid = DIFF_LAYER.to_ascii_lowercase();
    }
    let plan = ChildPlan::top_level(&domain, Some(&lower));
    assert_eq!(
        count(plan.capability_sids(), DIFF_LAYER),
        1,
        "綴りの大小だけで同じSIDが2本積まれている"
    );
}

/// 自己ループの子も差分層のSIDを1本だけ持つ（呼び出し元のドメインに既に入っている）。
#[test]
fn a_self_loop_child_of_a_cow_lineage_carries_the_diff_layer_capability_once() {
    let caller = caller_with(Some(cow_spec()));
    let plan = ChildPlan::nested(&caller, &caller.domain);
    assert_eq!(count(plan.capability_sids(), DIFF_LAYER), 1);
    assert_eq!(
        plan.capability_sids(),
        caller.domain.capability_sids.as_slice()
    );
}

/// **対の側**（`B-35`）: CoWでない注入設定は何も足さない。
///
/// 片方だけだと、「いつも何かを足す」実装でも上のテストが通る。
#[test]
fn non_cow_redirectors_add_nothing_to_the_token() {
    let target = target_domain();
    for redirector in [None, Some(lazy_spec()), Some(process_hooks_spec())] {
        let caller = caller_with(redirector.clone());
        let plan = ChildPlan::nested(&caller, &target);
        assert_eq!(
            plan.capability_sids(),
            target.capability_sids.as_slice(),
            "{redirector:?} で注入する子に、表に無いSIDが積まれた"
        );
    }
}

/// **この型の穴を構造で止める本体。** 注入設定の全種類 × 子の起こされ方の全部で、
/// 「注入する設定が要るSIDはトークンに在る」と「同じSIDが2本無い」が成り立つ。
///
/// BUG-169・BUG-180はどちらも「トークンを組む場所が複数あり、片方に1種類足りない」形だった。
/// 起こされ方を1つ足した日にここへ加えれば、足りない組み合わせが`cargo test`で赤くなる。
#[test]
fn every_injected_child_carries_what_its_redirector_needs() {
    let target = target_domain();
    for redirector in every_redirector() {
        let caller = caller_with(redirector.clone());
        let cross_child = cross_domain_child_with(redirector.clone(), &target);
        let entry = entry_domain();

        let cases: Vec<(&str, ChildPlan<'_>)> = vec![
            (
                "top-level",
                ChildPlan::top_level(&entry, redirector.as_ref()),
            ),
            ("self-loop", ChildPlan::nested(&caller, &caller.domain)),
            ("cross-domain", ChildPlan::nested(&caller, &target)),
            (
                "self-loop inside the target domain",
                ChildPlan::nested(&cross_child, &cross_child.domain),
            ),
        ];
        for (how, plan) in cases {
            if let Some(required) = plan.redirector().and_then(required_capability) {
                assert_eq!(
                    count(plan.capability_sids(), required),
                    1,
                    "{how} / {redirector:?}: 注入する設定が要るSID {required} がトークンに無い"
                );
            }
            for sid in plan.capability_sids() {
                assert_eq!(
                    count(plan.capability_sids(), sid),
                    1,
                    "{how} / {redirector:?}: 同じSIDが2本積まれている（CreateProcessWが落ちる）: {sid}"
                );
            }
        }
    }
}

/// 別ドメインへ移ったCoWの子のトークンを、**4種類の出どころ**で固定する
/// （`DomainCapabilities`のdocの表と、`plans/DESIGN-MAC-BROKER.md` §22.9）。
///
/// | 種類 | 在るか | 出どころ |
/// |---|---|---|
/// | ワークスペース本体 | 在る | `Hello`の表（土台） |
/// | `--fs-allow`の穴 | **無い** | 遷移で狭める軸（§10.1.2） |
/// | CoWの差分層 | 在る | 系統の注入設定（BUG-180） |
/// | Redirector DLL | 在る | `Hello`の表（土台） |
#[test]
fn each_of_the_four_capability_kinds_has_a_source_on_the_cross_domain_path() {
    let caller = caller_with(Some(cow_spec()));
    let target = target_domain();
    let plan = ChildPlan::nested(&caller, &target);
    let caps = plan.capability_sids();

    assert_eq!(
        count(caps, WORKSPACE),
        1,
        "ワークスペース本体が無い: {caps:?}"
    );
    assert_eq!(
        count(caps, FS_ALLOW),
        0,
        "呼び出し元の`--fs-allow`の穴が遷移先へ渡っている——遷移で狭まらない: {caps:?}"
    );
    assert_eq!(
        count(caps, DIFF_LAYER),
        1,
        "差分層が無い（BUG-180）: {caps:?}"
    );
    assert_eq!(
        count(caps, REDIRECTOR_DLL),
        1,
        "Redirector DLLが無い: {caps:?}"
    );
}

// --- [BUG-180・ユーザー判断] 別ドメインへ移る子からは、ワークスペース外への誘導を外す ---

fn ext_roots_of(spec: Option<&RedirectorSpec>) -> Option<Vec<String>> {
    match spec {
        Some(RedirectorSpec::Cow {
            ext_capture_roots, ..
        }) => Some(ext_capture_roots.clone()),
        _ => None,
    }
}

/// **本体。** 別ドメインへ移るCoWの子は、ワークスペース外への誘導を持たない。
/// **それ以外の欄は呼び出し元と同じ**——差分層・ワークスペース・宛先SIDまで落とすと、
/// その子はワークスペースの変更も見えなくなる（BUG-180へ逆戻りする）。
#[test]
fn a_cross_domain_child_loses_ext_capture_but_keeps_everything_else() {
    let caller = caller_with(Some(cow_spec()));
    let target = target_domain();
    let plan = ChildPlan::nested(&caller, &target);

    match plan.redirector() {
        Some(RedirectorSpec::Cow {
            workspace_root,
            diff_layer_dir,
            ext_capture_roots,
            diff_layer_capability_sid,
        }) => {
            assert!(
                ext_capture_roots.is_empty(),
                "別ドメインへ移る子にワークスペース外への誘導が残っている: {ext_capture_roots:?}"
            );
            let RedirectorSpec::Cow {
                workspace_root: w,
                diff_layer_dir: d,
                diff_layer_capability_sid: s,
                ..
            } = cow_spec()
            else {
                unreachable!()
            };
            assert_eq!(workspace_root, &w);
            assert_eq!(diff_layer_dir, &d);
            assert_eq!(diff_layer_capability_sid, &s);
        }
        other => panic!("CoWの注入設定になっていない: {other:?}"),
    }
}

/// **対の側**（`B-35`）: 自己ループの子は、呼び出し元の誘導をそのまま持つ。
///
/// 片方だけだと、「いつも外す」実装でも上のテストが通る——そうなると、同じドメインの
/// 子まで`--fs-allow`で開けた書込先へ書けなくなる。
#[test]
fn a_self_loop_child_keeps_the_callers_ext_capture() {
    let caller = caller_with(Some(cow_spec()));
    let plan = ChildPlan::nested(&caller, &caller.domain);
    assert_eq!(plan.redirector(), Some(&cow_spec()));
}

/// **外した子の子孫も外れたまま**である。台帳が系統のトップレベルの設定を返していた頃は、
/// 孫の計画がトップレベルの設定から始まり、外した誘導が1世代で戻った。
///
/// あわせて、その子を**台帳へ載せたドメインが`Hello`の表の値のまま**であることも見る
/// （差分層のSIDはドメインの事実ではない。`B-13`）。
#[test]
fn a_stripped_child_stays_stripped_in_its_own_self_loop() {
    let target = target_domain();
    let child = cross_domain_child_with(Some(cow_spec()), &target);
    assert_eq!(
        child.domain, target,
        "別ドメインへ移った子を台帳へ載せたドメインが、表の値から変わっている"
    );
    assert_eq!(
        ext_roots_of(child.redirector.as_ref()),
        Some(Vec::new()),
        "台帳が、その子へ注入した設定ではなく系統のトップレベルの設定を返している"
    );

    let grandchild = ChildPlan::nested(&child, &child.domain);
    assert!(!grandchild.crosses_domains());
    assert_eq!(
        ext_roots_of(grandchild.redirector()),
        Some(Vec::new()),
        "外したワークスペース外への誘導が孫の代で戻っている"
    );
    assert_eq!(count(grandchild.capability_sids(), DIFF_LAYER), 1);
}

/// CoWでない注入設定は、跨いでも跨がなくてもそのまま渡す（今回の判断の射程外）。
#[test]
fn non_cow_redirectors_cross_domains_unchanged() {
    let target = target_domain();
    for spec in [lazy_spec(), process_hooks_spec()] {
        let caller = caller_with(Some(spec.clone()));
        assert_eq!(
            ChildPlan::nested(&caller, &target).redirector(),
            Some(&spec)
        );
    }
}
