//! panicを受け止める範囲（[`contain_panic`]）と、panicのフックが端末を戻すかの試験。
//!
//! 本物の端末は使わない。フックの「端末を戻す」の代わりに**戻した回数を数える**ものを差し込む（[`counting_hook`]）
//! ——製品のフック（`install_panic_hook`）と違うのは戻す動作だけで、受け止める範囲の中かを見る判定（`on_panic`）と、
//! 元のフックへつなぐ形（`chain_panic_hook`）は製品と同じものを通る。
//!
//! 受け止める範囲の中（戻さない）と外（戻す。ポリシーエディタと、ふつうのpanic）を対で確かめる。

use std::cell::Cell;
use std::sync::Once;

use super::*;

thread_local! {
    /// このスレッドで起きたpanicのうち、フックが端末を戻した回数（[`counting_hook`]）。
    static RESTORED: Cell<usize> = const { Cell::new(0) };
}

/// 端末を戻す代わりに、このスレッドの[`RESTORED`]を1つ増やすフックを差し込む（プロセスで1回だけ。試験は並んで
/// 走るので、数えるのはpanicしたスレッドの分だけにする）。元のフック（既定のもの）へもつなぐので、panicの文面は
/// 今までどおり試験の出力へ出る。
fn counting_hook() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| chain_panic_hook(|| RESTORED.with(|n| n.set(n.get() + 1))));
}

/// このスレッドで、これまでにフックが端末を戻した回数。
fn restored() -> usize {
    RESTORED.with(Cell::get)
}

/// panicの中身の文字列（`panic!("…")`の文面）。
fn message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("")
}

/// **受け止める範囲の中のpanicは、端末を戻さずに`Err`で返る**（TUIは画面を握ったまま続けられる）。
#[test]
fn a_panic_inside_contain_panic_comes_back_as_an_error_without_restoring_the_terminal() {
    counting_hook();
    let before = restored();
    let caught = contain_panic(|| -> u8 { panic!("解析器が落ちた") });
    let payload = caught.expect_err("受け止めたpanicが`Err`で返らない");
    assert_eq!(message(payload.as_ref()), "解析器が落ちた");
    assert_eq!(
        restored(),
        before,
        "受け止める範囲の中のpanicで端末を戻した"
    );
}

/// **範囲の外のpanicは、今までどおり端末を戻す**（ポリシーエディタは範囲を作らない。ふつうのpanicも同じ）。
/// `catch_unwind`で受けても戻す——受け止めるかどうかではなく、範囲の中かで決まる。
#[test]
fn a_panic_outside_contain_panic_still_restores_the_terminal() {
    counting_hook();
    let before = restored();
    let caught = std::panic::catch_unwind(|| panic!("範囲の外"));
    assert!(caught.is_err());
    assert_eq!(
        restored(),
        before + 1,
        "範囲の外のpanicで端末を戻さなかった"
    );
}

/// **範囲を出たら、印は必ず倒れている**——中でpanicしても、しなくても。出た後のpanicは端末を戻す。
#[test]
fn leaving_the_scope_always_clears_the_mark_even_after_a_panic() {
    counting_hook();
    assert!(!panic_is_contained(), "範囲の外なのに中と答えた");
    assert_eq!(
        contain_panic(|| 5).ok(),
        Some(5),
        "戻り値がそのまま返らない"
    );
    assert!(!panic_is_contained(), "panicせずに出たのに印が残った");
    assert!(contain_panic(|| panic!("中")).is_err());
    assert!(!panic_is_contained(), "panicして出たのに印が残った");

    let before = restored();
    assert!(std::panic::catch_unwind(|| panic!("出た後")).is_err());
    assert_eq!(
        restored(),
        before + 1,
        "範囲を出た後のpanicで端末を戻さない"
    );
}

/// **入れ子にできる**——内側の範囲を出ても、外側の範囲の中にいる間は端末を戻さない。
#[test]
fn nested_scopes_keep_the_outer_one_contained() {
    counting_hook();
    let before = restored();
    let outer = contain_panic(|| {
        assert!(panic_is_contained());
        let inner = contain_panic(|| panic!("内側"));
        assert!(inner.is_err());
        assert!(
            panic_is_contained(),
            "内側の範囲を出たら、外側の中なのに印が倒れた"
        );
        panic!("外側");
    });
    assert_eq!(message(outer.expect_err("外側").as_ref()), "外側");
    assert_eq!(restored(), before, "入れ子の範囲の中のpanicで端末を戻した");
    assert!(!panic_is_contained());
}

/// **受け止める範囲の中でも、panicの報告（元のフック。既定では標準エラーへの文面）は呼ぶ**——止めるのは端末を戻す
/// ことだけ。範囲の外では、端末を戻してから報告する（戻す前に書くと、文面がオルタネートスクリーンの上に出て消える）。
#[test]
fn the_report_is_made_inside_and_outside_but_the_restore_only_outside() {
    let calls = std::cell::RefCell::new(Vec::new());
    let run = || {
        on_panic(
            || calls.borrow_mut().push("restore"),
            || calls.borrow_mut().push("report"),
        )
    };
    run();
    assert_eq!(*calls.borrow(), ["restore", "report"], "範囲の外");
    calls.borrow_mut().clear();
    contain_panic(run).expect("panicしていない");
    assert_eq!(*calls.borrow(), ["report"], "範囲の中");
}
