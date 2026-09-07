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

/// D-56 段階2（要求の連続を捌くプロトコル）のテスト。実daemonを非昇格で起動して検出する
/// ものを含む——`cargo test -p harness-sandbox`は別パッケージのdaemonをリビルドしないので、
/// 「古いビルドを黙って測る」ことの検出器が要る。
#[cfg(all(windows, test))]
mod reuse_tests;

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
    /// トップレベル子の親になるSpawn Daemon。`None`は従来のパス1/Tier1経路。
    #[serde(default)]
    pub spawn_daemon_pid: Option<u32>,
    /// ポリシーエディタの記録モード（Tier1、`plans/POLICY-EDITOR-TOMOYO-DIG.md`）専用。
    /// `true`なら拒否だけでなく全アクセス（成功も含む）を記録する（record-all）。
    ///
    /// このフラグはスコープ判定の方式も切り替える——Tier1（制限トークン）にはAppContainerの
    /// package SIDが無いため、signal 1（`PackageFullName`一致）は元々空振りし、signal 3
    /// （`TokenIsAppContainer`照会）は**誤って`Some(false)`を返し対象を永久に除外してしまう**
    /// （Tier1プロセスは有効なトークンを持つが単にAppContainerではないだけなので、
    /// `probe_pid_in_container`は生存中でも確定的に「違う」と答えてしまう）。そのため
    /// `record_all=true`のときはprobeを使わず、`harness_pid`起点の親子継承（signal 2＋
    /// フォールバック）だけでスコープを決める。
    #[serde(default)]
    pub record_all: bool,
}

/// 親→収集器。**`Teardown`までの要求の連続**（D-56 段階2）。
///
/// ```text
///   StartCollect → StopCollect → StartCollect → … → Teardown
/// ```
///
/// かつては`StartCollect`→`Teardown`の1往復固定で、記録を走らせるたびにdaemonを起こし直して
/// いた＝**そのたびUACが出ていた**。ポリシーエディタは1回の起動で記録を何度も走らせる道具
/// なので、これが実運用の主要な摩擦になっていた。1往復はこのループの特殊形なので、
/// harness本体（`run_agent.rs`の2経路）は無変更で通る。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LearnRequest {
    StartCollect(LearnPolicy),
    /// 現世代の収集を止める（**daemonは待機を続ける**）。
    ///
    /// **「空の`StartCollect`」では代用できない**——次の`StartCollect`が来るまで
    /// ETWセッションを張ったままにすると、記録していない時間帯のイベントが次の記録へ混ざる。
    StopCollect,
    Teardown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LearnResponse {
    /// 収集を開始した。`etw_available`が`false`なら、セッションは張れなかったが
    /// **harnessは止めない**（D-43 fail-open）——その事実は`fs-audit.jsonl`の制御レコードにも残る。
    Started {
        etw_available: bool,
        /// 受理した値をechoし、古い収集器が新しい欄を無視していないことを確認する。
        ///
        /// **`default`が要る。** 収集器はプロセスをまたいで生き残る常駐で（D-56 段階2。
        /// 起動のたびに立て直すとそのたびUACが出るため）、**前のビルドのものが動いている
        /// ことがある**。`default`が無いと、古い収集器の応答は欄が無いという理由で
        /// 電文の解釈そのものに失敗し、「malformed response」になる——止まること自体は
        /// 正しいが、**版ずれだと読めない**（`B-10`: 失敗の理由を潰さない）。
        /// `default`を置くと`None`として解釈が通り、下の照合が
        /// 「要求した値をechoしていない」という本来の文面で断る。
        #[serde(default)]
        spawn_daemon_pid: Option<u32>,
    },
    /// 現世代を畳んだ。**この世代で**書けた件数を返す（累積ではない——累積にすると
    /// UIが「今回の記録で観測した件数」として出す数と食い違う）。
    Stopped {
        written: u64,
    },
    /// 撤収完了。観測できた拒否の件数を返す（呼び出し側の表示用）。
    TornDown {
        denials_written: u64,
    },
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
            spawn_daemon_pid: None,
            record_all: false,
        });

        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"StartCollect":{"session_profile":"harness.shell.sandbox.1-2","workspace_root":"C:/work","fs_audit_log_path":"C:/work/.harness/sandbox/session-x/fs-audit.jsonl","harness_pid":null,"spawn_daemon_pid":null,"record_all":false}}"#
        );
    }

    /// 旧バージョン（`record_all`フィールドを持たない）が書いたJSONも、
    /// `#[serde(default)]`により`record_all: false`として読める（後方互換）。
    #[test]
    fn start_collect_request_without_record_all_defaults_to_false() {
        let old_wire = r#"{"StartCollect":{"session_profile":"harness.shell.sandbox.1-2","workspace_root":"C:/work","fs_audit_log_path":"C:/work/.harness/sandbox/session-x/fs-audit.jsonl","harness_pid":null}}"#;

        let request: LearnRequest = serde_json::from_str(old_wire).unwrap();
        match request {
            LearnRequest::StartCollect(policy) => assert!(!policy.record_all),
            _ => panic!("expected StartCollect"),
        }
    }

    /// `record_all: true`のワイヤ形式も固定する（Tier1記録モードが実際に送る形）。
    ///
    /// **`session_profile`はrecord-allでもプロファイル名の形でなければならない。**
    /// スコープ判定には使われない（Tier1にpackage SIDが無いため）が、昇格側の
    /// `validate_request`が`is_session_profile_name`で形を検証しており、通らない名前を
    /// 送ると収集がまったく始まらない。ここで独自の名前（`harness.policy-mode`等）を
    /// 例示すると、それを写した実装が無言で拒否される——同じ主張を
    /// `server.rs`の`the_profile_name_the_record_mode_sends_passes_the_elevated_side_validation`
    /// が実際の検証関数に対して固定している。
    #[test]
    fn start_collect_request_with_record_all_true_wire_format_is_stable() {
        let profile = "harness.shell.sandbox.4242-1700000000";
        assert!(
            crate::tier2a::session_profile::is_session_profile_name(profile),
            "the example must be a name the elevated side actually accepts"
        );
        let request = LearnRequest::StartCollect(LearnPolicy {
            session_profile: profile.to_string(),
            workspace_root: PathBuf::from("C:/work"),
            fs_audit_log_path: PathBuf::from("C:/work/.harness/sandbox/session-x/fs-audit.jsonl"),
            harness_pid: Some(4242),
            spawn_daemon_pid: None,
            record_all: true,
        });

        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"StartCollect":{"session_profile":"harness.shell.sandbox.4242-1700000000","workspace_root":"C:/work","fs_audit_log_path":"C:/work/.harness/sandbox/session-x/fs-audit.jsonl","harness_pid":4242,"spawn_daemon_pid":null,"record_all":true}}"#
        );
    }

    /// **D-56段階2で足した2値のワイヤ形式。** 別プロセスが読むので、綴りが変わると
    /// 無言で通信不能になる（`StopCollect`が読めなければ、収集器は要求を`malformed`として
    /// 拒否し、呼び出し側は「畳めたか分からないdaemon」を抱えたまま次の記録へ進む）。
    #[test]
    fn stop_collect_and_stopped_have_a_stable_wire_format() {
        assert_eq!(
            serde_json::to_string(&LearnRequest::StopCollect).unwrap(),
            r#""StopCollect""#
        );
        assert_eq!(
            serde_json::to_string(&LearnResponse::Stopped { written: 7 }).unwrap(),
            r#"{"Stopped":{"written":7}}"#
        );
        // 旧バージョンが書いた形（`StopCollect`を知らない側）も読めることを確認する。
        assert!(matches!(
            serde_json::from_str::<LearnRequest>(r#""Teardown""#),
            Ok(LearnRequest::Teardown)
        ));
    }

    #[test]
    fn teardown_and_responses_have_a_stable_wire_format() {
        assert_eq!(
            serde_json::to_string(&LearnRequest::Teardown).unwrap(),
            r#""Teardown""#
        );
        assert_eq!(
            serde_json::to_string(&LearnResponse::Started {
                etw_available: true,
                spawn_daemon_pid: Some(77),
            })
            .unwrap(),
            r#"{"Started":{"etw_available":true,"spawn_daemon_pid":77}}"#
        );
        assert_eq!(
            serde_json::to_string(&LearnResponse::TornDown { denials_written: 7 }).unwrap(),
            r#"{"TornDown":{"denials_written":7}}"#
        );
    }

    /// **生き残っている古い収集器の応答が「読める」こと**を固定する。
    ///
    /// 収集器はプロセスをまたいで常駐する（D-56 段階2）ので、**前のビルドのものが
    /// 動いていることがある**。それが返す`Started`には`spawn_daemon_pid`が無い。
    /// ここが読めないと、断り方が「版がずれている」ではなく
    /// 「電文が壊れている」になり、原因が消える（`B-10`）。
    ///
    /// **読めたうえで断るのは`client`の照合の仕事である**（対の側は下のテスト）。
    #[test]
    fn a_started_from_an_older_collector_parses_as_no_daemon_pid() {
        let parsed: LearnResponse =
            serde_json::from_str(r#"{"Started":{"etw_available":true}}"#).expect(
                "古い収集器の応答が読めない。版ずれが「電文が壊れている」に化けて原因が消える",
            );
        assert!(matches!(
            parsed,
            LearnResponse::Started {
                etw_available: true,
                spawn_daemon_pid: None,
            }
        ));
    }

    /// **対の側**（`B-35`）: Daemon PIDを要求したのにechoが返らなければ、それは版ずれである。
    ///
    /// 上のテストだけだと「読めた」で終わり、**読めたあと素通りする実装でも緑になる。**
    /// ここで測るのは`client`が使うのと同じ比較（要求した値とechoした値の一致）である。
    #[test]
    fn a_missing_echo_is_distinguishable_from_a_matching_one() {
        let older: LearnResponse =
            serde_json::from_str(r#"{"Started":{"etw_available":true}}"#).expect("parse");
        let current: LearnResponse =
            serde_json::from_str(r#"{"Started":{"etw_available":true,"spawn_daemon_pid":77}}"#)
                .expect("parse");
        let echoed = |response: &LearnResponse| match response {
            LearnResponse::Started {
                spawn_daemon_pid, ..
            } => *spawn_daemon_pid,
            _ => unreachable!("Startedを読ませている"),
        };

        let requested = Some(77u32);
        assert_ne!(
            echoed(&older),
            requested,
            "古い収集器の応答が「要求どおりecho した」と読めてしまう。\
             Daemonが親になった子をETWのスコープ判定が拾えないまま記録が進む"
        );
        assert_eq!(
            echoed(&current),
            requested,
            "現行の収集器の応答が一致と読めない。全セッションが版ずれ扱いで止まる"
        );

        // パス1・Tier1経路（Daemon PIDを要求しない）では、古い収集器で構わない。
        assert_eq!(echoed(&older), None, "要求していない側は一致として通る");
    }
}
