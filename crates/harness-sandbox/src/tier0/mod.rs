//! Tier0（Windows）: 隔離なしの素の子プロセス起動 + Job Object。
//!
//! **これは「保護がある」Tierではない。** 制限トークンも低ILラベルもAppContainerも使わず、
//! 親と同じMedium ILで子を起こす。Job Objectだけは付ける——これは隔離ではなく
//! kill-on-closeで子孫を取り逃さないための資源管理（T-13対策）で、Tier0/Tier1/Tier2aに共通する。
//!
//! # なぜ隔離しない起動経路をわざわざ持つのか
//!
//! ポリシーエディタの**パス1（record-all＝FSアクセスの観測）**のために要る。
//! 記録の目的は「このワークロードが何に触るか」を観測して許可を組むことなので、
//! 観測を制限下で行うと**サンドボックスの実装都合による拒否が候補一覧に混ざる**。
//! Tier1で記録していた頃は、低ILラベルがcwd 1個にしか付かないことに起因する拒否が
//! 候補へ流れ込んでいた（`docs/STATUS.md`の「Tier1での拒否をTier2aで要る許可と
//! 読み替えないこと」はこの汚染の警告）。パス1を回すのはTier2aを使う人＝どちらにせよ
//! ローカル管理者権限を持つ人なので、Tier0にしても要求が増えることはない。
//! 経緯は`plans/PLAN-POLICY-EDITOR-EXEC-DENIAL.md`「第11セッション」節。
//!
//! `run_shell`のTier0経路は別物である（`harness-tools`の`shell::runner::run_tier0`が
//! tokioの`Command`で起こす）。ここはETW観測とライブ表示のために
//! `OutputEvent`ストリームと`KillToken`を必要とするパス1専用の入口で、
//! Tier1/Tier2aと同じ`win_common::stream_child_output`を共有する。

#[cfg(windows)]
pub mod win_plain;
