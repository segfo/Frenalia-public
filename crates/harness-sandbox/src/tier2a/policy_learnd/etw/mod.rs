//! OS監査によるFSアクセス拒否の収集（M15.7、`plans/DESIGN-SANDBOX-APPPOLICY.md` §11.1の
//! 4番目の収集源）。
//!
//! | モジュール | 役割 | 検証手段 |
//! |---|---|---|
//! | [`parse`] | `Create`↔`OperationEnd`の相関・access種別の推定・NTパス変換 | 単体テスト（純粋関数） |
//! | [`tdh`] | イベントプロパティを名前で引く（マニフェスト解決） | 実機（TDHはETWレコードを要求する） |
//! | [`session`] | **本番経路**。マニフェストベース(Modern ETW)のセッションのライフサイクル | 実機E2E（`#[ignore]`） |
//! | [`mof`] | Classic ETW(MOF / System Logger系)のセッション。**本番では使わないが対照群として意図的に残す**（規則2の例外、モジュールdoc参照） | 実機E2E（`#[ignore]`） |
//! | [`scope`] | 「このイベントは自分のサンドボックス配下か」の3段構え判定 | 単体テスト（純粋関数＋probe注入） |
//! | [`volumes`] | `\Device\HarddiskVolumeN` → `C:` の対応表 | 実機 |
//!
//! 判断（相関・分類）と副作用（Win32）を分けているのは、提案の質そのものである前者を
//! 管理者権限なしに全数テストできる形に保つためである（`docs/CODE-STRUCTURE-RULES.md`規則3）。

/// Classic ETW（MOF / System Logger系）。**本番経路ではない**——マニフェスト側が捉えきれない
/// 事象に当たったときに対比するための対照群として意図的に残している（モジュールdocに理由、
/// 実測比較は`plans/etw-spike/RESULTS.md` §8）。
pub mod mof;
pub mod parse;
pub mod scope;
pub mod session;
pub mod tdh;
pub mod volumes;

#[cfg(all(windows, test))]
#[path = "spike_tests.rs"]
mod spike_tests;

/// `docs/STATUS.md`「既知の未検証項目」#1〜#5を実測する。**assertより観測値の出力が主目的**。
#[cfg(all(windows, test))]
#[path = "diagnostics_tests.rs"]
mod diagnostics_tests;

/// `auditpol /resourceSACL`をAppContainerのpackage SIDへ絞れるかの実測（項目`c`）。
/// **マシンの監査ポリシーを一時的に変更する**（Dropガードで撤去）。
#[cfg(all(windows, test))]
#[path = "audit_scope_tests.rs"]
mod audit_scope_tests;

/// 許可レベル×操作種別の真理値表を実機で埋める（項目`b`の追試）。
#[cfg(all(windows, test))]
#[path = "access_matrix_tests.rs"]
mod access_matrix_tests;

/// 削除の拒否がどの段階で現れるか（§12.4の再検証）。**その結論（§16）は§18で撤回された**
/// ——残す理由はモジュールdoc参照（規則2の明示的例外）。
#[cfg(all(windows, test))]
#[path = "delete_denial_tests.rs"]
mod delete_denial_tests;

/// 「開けるが操作で落ちる」拒否は起きるのか（残課題a-2の決着、§18）。**起きない**——
/// ACL起因の拒否は必ず`Create`段に出る。
#[cfg(all(windows, test))]
#[path = "operation_denial_tests.rs"]
mod operation_denial_tests;

/// `--fs-allow`で許可したパスへ、祖先が未付与の状態で到達できるかの実測
/// （`plans/PLAN-M15.7-FOLLOWUP.md` W1、§19）。CoW redirector DLLの到達性
/// （`docs/STATUS.md` Tier2a残課題#7）も同じ軸で測る。
///
/// **モジュール名は`KNOWN_TARGETS`の`etw-fs-allow-reach`のフィルタ文字列と一致していなければ
/// ならない**（改名するとBUG-056と同じ「0件マッチ」が再発する）。
#[cfg(all(windows, test))]
#[path = "fs_allow_reach_tests.rs"]
mod fs_allow_reach_tests;

/// [`parse::access_from_create_options`]が寄りかかっている前提——「disposition 2/4/5は
/// 呼び出し側が書込を要求した証拠になる」——を`NtCreateFile`の戻り値で実測する（W3、D-46）。
/// **ETWも管理者権限も要らないので`#[ignore]`を付けない**。前提が崩れた日に赤くなるべきもの。
#[cfg(all(windows, test))]
#[path = "disposition_semantics_tests.rs"]
mod disposition_semantics_tests;
