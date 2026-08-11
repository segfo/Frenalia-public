//! [`super`]のテスト。**両方の画面が通る共通部分**なので、ここが壊れると承認と取り消しの
//! 両方が同時に壊れる（＝それだけ固定する価値がある）。

use super::*;

#[test]
fn the_mark_distinguishes_all_from_partial_from_none() {
    assert_eq!(Mark::of(3, 3), Mark::All);
    assert_eq!(Mark::of(3, 1), Mark::Partial);
    assert_eq!(Mark::of(3, 0), Mark::None);
}

/// **操作できるものが無い**のは「未選択」とは別の状態。同じ`[ ]`にすると、
/// Spaceを押しても何も起きない行が「押せば選べる」ように見える（B-32）。
#[test]
fn nothing_selectable_is_not_the_same_as_nothing_selected() {
    assert_eq!(Mark::of(0, 0), Mark::NotApplicable);
    assert_ne!(Mark::of(0, 0).glyph(), Mark::of(3, 0).glyph());
}

#[test]
fn every_mark_has_its_own_glyph() {
    let glyphs = [
        Mark::All.glyph(),
        Mark::Partial.glyph(),
        Mark::None.glyph(),
        Mark::NotApplicable.glyph(),
    ];
    let unique: std::collections::BTreeSet<&str> = glyphs.iter().copied().collect();
    assert_eq!(unique.len(), glyphs.len(), "記号が重なると状態が読めない");
}

#[test]
fn moving_the_selection_stops_at_both_ends() {
    let mut row = 0;
    move_row(&mut row, 3, -1);
    assert_eq!(row, 0, "先頭より上へは行かない");
    move_row(&mut row, 3, 10);
    assert_eq!(row, 2, "末尾より下へは行かない");
}

/// 行が1つも無い状態で動かしても壊れない（記録が0件・宣言が0件のときに通る）。
#[test]
fn moving_the_selection_with_no_rows_is_safe() {
    let mut row = 5;
    move_row(&mut row, 0, 1);
    assert_eq!(row, 0);
}

#[test]
fn clamping_pulls_the_selection_back_when_rows_shrink() {
    let mut row = 9;
    clamp_row(&mut row, 3);
    assert_eq!(row, 2);
    clamp_row(&mut row, 0);
    assert_eq!(row, 0);
}
