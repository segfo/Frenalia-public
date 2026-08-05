//! ポリシー学習ヘルパー（M15.7、`plans/DESIGN-SANDBOX-APPPOLICY.md` §11）。
//!
//! **`harness-netfilterd`とは別の昇格プロセス**（`harness-policy-learnd.exe`）として動く。
//! netfilterdへ相乗りしない理由は、あちらが「Tier2a＋ドメインポリシー有効＋ローカルプロキシ
//! 起動済み」のときしか起動せず、**FS学習だけが欲しい場面には居ない**ためである。分離により
//! オンデマンドな学習（`harness policy learn`の単体実行）が可能になり、信頼境界が
//! ファイル境界に一致する（D-35）。
//!
//! | モジュール | 信頼境界 |
//! |---|---|
//! | 本ファイル | 両岸が共有するワイヤ形式（IPCのメッセージ型） |
//! | [`client`] | **非特権側**。パイプを作り、昇格ヘルパーを起こし、生存を握る |
//! | [`server`] | **昇格側**。ETWを張り、拒否を`fs-audit.jsonl`へ書く |
//! | [`etw`] | 昇格側から使うETWの下回り |
//!
//! # 生存期間はOSハンドルに紐付ける
//!
//! 収集器は`Teardown`を受け取るまで常駐するが、**親がクラッシュしてもパイプ切断で自発終了する**
//! （2回目の`ReadFile`が`ERROR_BROKEN_PIPE`になる）。タイマーやファイルポーリングで寿命を
//! 決めない——グローバル`CLAUDE.md`が禁じる「`%TEMP%`のキューを監視する常駐昇格プロセス」は
//! 認証なしのローカル特権昇格になるため、そのパターンは踏まない。

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub mod client;
pub mod etw;
pub mod server;

/// 収集器へ渡すポリシー一式（`StartCollect`のペイロード）。
///
/// **SIDではなくプロファイル名を運ぶ**（`NetfilterPolicy`と同じ方針、D-37）。昇格側は
/// `session_profile::is_session_profile_name`で形を検証してから使うので、
/// 任意のAppContainerを対象にさせることはできない。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LearnPolicy {
    /// 収集対象を絞るためのセッションプロファイル名（`harness.shell.sandbox.<token>`）。
    pub session_profile: String,
    /// workspaceルート。`fs_audit_log_path`の検証基準になる
    /// （`crate::elevated_launch::validate_audit_sink_path`）。
    pub workspace_root: PathBuf,
    /// `fs-audit.jsonl`の書込先。**昇格側が受信時に検証する**——非昇格の親が指定した任意パスへ
    /// 管理者権限で書くのは任意パス追記プリミティブそのものだから。
    pub fs_audit_log_path: PathBuf,
    /// harness本体のPID。**極端に短命な第1世代を取りこぼさないための補助**（実測#1）。
    ///
    /// `ProcessStart`は届くのにトークン照会が間に合わない場合、親が harness 本体であることを
    /// 手掛かりに対象とみなす。`runas`で起こす昇格ヘルパーの親はAppInfoサービスになるため、
    /// harnessの直接の子は実質`run_shell`のAppContainer子だけである。
    ///
    /// **これは推定であり確証ではない**。誤って含めても影響は「提案候補が1つ増える」ことに留まり、
    /// 権限が自動で広がることはない（D-42: 適用は常にユーザーの明示操作）。
    #[serde(default)]
    pub harness_pid: Option<u32>,
}

/// 親→収集器。1セッションで`StartCollect`→`Teardown`の順に2回送る。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LearnRequest {
    StartCollect(LearnPolicy),
    Teardown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LearnResponse {
    /// 収集を開始した。`etw_available`が`false`なら、セッションは張れなかったが
    /// **harnessは止めない**（D-43 fail-open）——その事実は`fs-audit.jsonl`の制御レコードにも残る。
    Started { etw_available: bool },
    /// 撤収完了。観測できた拒否の件数を返す（呼び出し側の表示用）。
    TornDown { denials_written: u64 },
    Err(String),
}

#[derive(Debug, thiserror::Error)]
pub enum LearnError {
    #[error("elevation was declined or failed (UAC canceled?): {0}")]
    ElevationDeclined(String),
    #[error("ipc error: {0}")]
    Ipc(String),
    #[error("the collector rejected the request: {0}")]
    Rejected(String),
    #[error("win32 call failed: {0}")]
    Win32(String),
    #[error("refusing to launch the collector: {0}")]
    UnsafeLaunchTarget(String),
}

impl From<windows::core::Error> for LearnError {
    fn from(e: windows::core::Error) -> Self {
        LearnError::Win32(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **D-34（ワイヤ形式はバイト列で固定する）**: `harness-policy-learnd.exe`は別プロセスとして
    /// このJSONを読むので、表現が変わると無言で通信不能になる。往復テストとは別に、
    /// バイト列そのものを固定する。
    #[test]
    fn start_collect_request_json_wire_format_is_stable() {
        let request = LearnRequest::StartCollect(LearnPolicy {
            session_profile: "harness.shell.sandbox.1-2".to_string(),
            workspace_root: PathBuf::from("C:/work"),
            fs_audit_log_path: PathBuf::from("C:/work/.harness/sandbox/session-x/fs-audit.jsonl"),
            harness_pid: None,
        });

        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"StartCollect":{"session_profile":"harness.shell.sandbox.1-2","workspace_root":"C:/work","fs_audit_log_path":"C:/work/.harness/sandbox/session-x/fs-audit.jsonl","harness_pid":null}}"#
        );
    }

    #[test]
    fn teardown_and_responses_have_a_stable_wire_format() {
        assert_eq!(
            serde_json::to_string(&LearnRequest::Teardown).unwrap(),
            r#""Teardown""#
        );
        assert_eq!(
            serde_json::to_string(&LearnResponse::Started {
                etw_available: true
            })
            .unwrap(),
            r#"{"Started":{"etw_available":true}}"#
        );
        assert_eq!(
            serde_json::to_string(&LearnResponse::TornDown {
                denials_written: 7
            })
            .unwrap(),
            r#"{"TornDown":{"denials_written":7}}"#
        );
    }
}
