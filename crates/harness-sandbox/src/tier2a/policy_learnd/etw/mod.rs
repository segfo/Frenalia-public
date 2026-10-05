//! OS監査によるFSアクセス拒否の収集（M15.7、`plans/DESIGN-SANDBOX-APPPOLICY.md` §11.1の
//! 4番目の収集源）。
//!
//! | モジュール | 役割 | 検証手段 |
//! |---|---|---|
//! | [`parse`] | `Create`↔`OperationEnd`の相関・access種別の推定・NTパス変換 | 単体テスト（純粋関数） |
//! | [`tdh`] | イベントプロパティを名前で引く（マニフェスト解決） | 実機（TDHはETWレコードを要求する） |
//! | [`session`] | **本番経路**。マニフェストベース(Modern ETW)のセッションのライフサイクル | 実機E2E（`#[ignore]`） |
//! | `kernel_process` | 本番セッションへ`Kernel-Process`を載せ、`ProcessStart`を解読する（名前は[`session`]から再公開） | 実機E2E（`#[ignore]`） |
//! | [`mof`] | Classic ETW(MOF / System Logger系)のセッション。**本番では使わないが対照群として意図的に残す**（規則2の例外、モジュールdoc参照） | 実機E2E（`#[ignore]`） |
//! | [`scope`] | 「このイベントは自分のサンドボックス配下か」の3段構え判定 | 単体テスト（純粋関数＋probe注入） |
//! | [`volumes`] | `\Device\HarddiskVolumeN` → `C:` の対応表 | 実機 |
//!
//! 判断（相関・分類）と副作用（Win32）を分けているのは、提案の質そのものである前者を
//! 管理者権限なしに全数テストできる形に保つためである（`docs/CODE-STRUCTURE-RULES.md`規則3）。

/// `Kernel-Process`の有効化と`ProcessStart`の解読（2026-10-05に`session.rs`からそのまま移した）。
/// **非公開**——外からは`session`が再公開する名前（`session::ProcessStartInfo`等）で引く。
mod kernel_process;
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

// **削除済み（2026-09-30）**: ネットワーク可視化（`Kernel-Network`/`DNS-Client`）の実現性スパイク
// `network_spike_tests`（判定は是。確定した事実は`plans/POLICY-EDITOR-TOMOYO-DIG.md`「実機スパイクで
// 確定した事実」、削除の判断は`docs/refactor/2026-08-19-spike-test-inventory.md`）。昇格キー
// `spike-etw-net`も同時に外した。復元が要るならこのコミットの親から取る。

/// OS監査収集器（M15.7）の未検証項目#1〜#5を実測する（項目の一覧と結果は
/// `plans/etw-spike/RESULTS.md` §12。以前は`docs/STATUS.md`が一覧を持っていた）。
/// **assertより観測値の出力が主目的**。
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

/// Tier1（`record_all`、ポリシー定義モード想定）の実現性スパイク。`harness_pid`起点の
/// 親子継承だけでプロセスツリーを正しく相関・帰属できるかを実機で確かめる
/// （`plans/POLICY-EDITOR-TOMOYO-DIG.md`）。
#[cfg(all(windows, test))]
#[path = "tier1_record_all_spike_tests.rs"]
mod tier1_record_all_spike_tests;

/// argv（コマンドライン）を観測できるかの実現性スパイク
/// （`plans/PLAN-MAC-RECURSIVE-DESCENDANTS.md`決定14・未解決#8）。マニフェスト側には
/// コマンドラインのフィールドが無いので、MOF側の`Process`クラスで測る。
///
/// **専用の昇格キーは`KNOWN_TARGETS`に登録していない。** 撃つときにキーを足すなら、
/// フィルタ文字列をこのモジュール名と一致させる（ずれるとBUG-056と同じ「0件マッチ」になる）。
#[cfg(all(windows, test))]
#[path = "argv_capture_spike_tests.rs"]
mod argv_capture_spike_tests;

/// private system loggerの枠（マシン全体で8本）が埋まったときの`StartTraceW`の挙動
/// （`plans/PLAN-MAC-ARGV-MEASUREMENTS.md` M4）。**実マシンへの影響が最大の測定**なので、
/// argvスパイクと同居させず単独のターゲットで回す。
///
/// **専用の昇格キーは`KNOWN_TARGETS`に登録していない。** 撃つときにキーを足すなら、
/// フィルタ文字列をこのモジュール名と一致させる（ずれるとBUG-056と同じ「0件マッチ」になる）。
#[cfg(all(windows, test))]
#[path = "logger_slot_spike_tests.rs"]
mod logger_slot_spike_tests;

/// 親の通し番号（`ParentProcessSequenceNumber`）が親自身の`ProcessSequenceNumber`を指すかの実測
/// （ポリシーエディタの決定65、`plans/PLAN-POLICY-EDITOR-POSITION-DOMAINS.md` P1b。結果は
/// `plans/etw-spike/RESULTS.md` §24）。
///
/// **モジュール名は`KNOWN_TARGETS`の`spike-etw-process-lineage`のフィルタ文字列と一致していなければ
/// ならない**（改名するとBUG-056と同じ「0件マッチ」が再発する）。P2fでキーと一緒に消す。
#[cfg(all(windows, test))]
#[path = "process_lineage_spike_tests.rs"]
mod process_lineage_spike_tests;
