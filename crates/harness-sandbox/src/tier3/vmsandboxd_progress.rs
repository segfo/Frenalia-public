//! Tier3セットアップ（`vmsandboxd::VmSandboxHandle::start`）待機中に見せる、経過時間ベースの
//! 合成進捗（本ラウンドの意図的な範囲）。
//!
//! **重要な注意**: ここで送られる[`SandboxPrepEvent`]は、daemon（`vmsandboxd`）が実際に
//! どのフェーズを実行しているかを示す**実測値ではない**。`vmsandboxd`のIPCプロトコル
//! （`VmRequest`/`VmResponse`）にはフェーズ完了通知が一切無く（`serve_inner`は
//! `StartSession`→`Ready`/`Err`の単発応答のみ）、クライアント側は処理完了までdaemon内部の
//! 進行状況を一切観測できない。本モジュールは`vm_host.rs`の待機タイムアウト定数
//! （`COLD_BOOT_GUEST_WAIT`/`WARM_RESTORE_GUEST_WAIT`）や実測値（コールド起動約212秒・
//! ウォーム再利用約19.6〜17.7秒、`plans/vm-spike/RESULTS.md`§3.15）から**較正した閾値表**に
//! 沿って、経過時間だけを根拠にラベルを推測して切り替えているに過ぎない。実際の内部処理が
//! ここで示すフェーズと異なるタイミングで進んでいても検知できない。
//!
//! 将来daemon側のIPCプロトコルへ実フェーズ通知（`VmResponse`への非終端Progressフレーム追加等）
//! を追加する際は、この「合成データである」という前提をUI/表示側（`harness-tui::sandbox_prep`・
//! `harness-cli`の非対話ヘルパー）へ埋め込まないこと——両者は[`SandboxPrepEvent`]という
//! 値の並びだけに依存させてあるため、送信元をここから実測ベースの送信元に差し替えるだけで
//! 移行できる設計にしてある。設計文書側の記録は`plans/DESIGN-SANDBOX-VMISOLATION.md`参照。

use std::time::Duration;

use tokio::sync::mpsc::UnboundedSender;

/// 進捗表示イベント。`done_hint`は本ラウンドでは常に`None`で送る——合成データから
/// 完了率（パーセンテージ/ETA）を主張すると、実際の所要時間とずれた場合に誤った期待を
/// 与えるため。将来の実測ベース送信元だけがここに実値を入れてよい。
#[derive(Debug, Clone)]
pub struct SandboxPrepEvent {
    pub elapsed: Duration,
    pub label: String,
    pub done_hint: Option<f32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    ConnectingDaemon,
    BootingVm,
    WaitingGuestOs,
    EstablishingTrust,
    CreatingContainer,
    ConfiguringWorkspace,
}

impl Phase {
    fn label_ja(self) -> &'static str {
        match self {
            Phase::ConnectingDaemon => "デーモンに接続中…（初回はUAC許可が必要な場合があります）",
            Phase::BootingVm => "VMを起動中…",
            Phase::WaitingGuestOs => "ゲストOSの起動を待っています…",
            Phase::EstablishingTrust => "コンテナ基盤(Incus)の信頼確立を待っています…",
            Phase::CreatingContainer => "コンテナを作成・起動中…",
            Phase::ConfiguringWorkspace => "ワークスペース共有を設定中…",
        }
    }

    /// `warm_hint`（`--tier3-warm`指定の有無）に応じて較正済みの閾値表を切り替える。
    /// warm想定時間（約25秒）を超えても終わらない場合は、実際にはコールドへフォールバック
    /// している可能性が高いため、以降はコールド表を同じ経過秒で評価し直す（なだらかに
    /// 合流させることで、推測が外れても表示が破綻しないようにする）。
    fn from_elapsed(elapsed: Duration, warm_hint: bool) -> Self {
        let secs = elapsed.as_secs();
        if warm_hint && secs < 25 {
            return match secs {
                0..=2 => Phase::ConnectingDaemon,
                3..=7 => Phase::BootingVm,
                8..=15 => Phase::WaitingGuestOs,
                16..=19 => Phase::EstablishingTrust,
                _ => Phase::CreatingContainer,
            };
        }
        match secs {
            0..=4 => Phase::ConnectingDaemon,
            5..=24 => Phase::BootingVm,
            25..=194 => Phase::WaitingGuestOs,
            195..=214 => Phase::EstablishingTrust,
            215..=224 => Phase::CreatingContainer,
            _ => Phase::ConfiguringWorkspace,
        }
    }
}

/// `tx`が破棄される（=呼び出し元が受信を打ち切る）まで250ms間隔で[`SandboxPrepEvent`]を
/// 送り続ける。呼び出し側は`VmSandboxHandle::start`を`spawn_blocking`した`JoinHandle`と
/// `tokio::select!`で競わせ、完了したらこの関数を包む`tokio::spawn`タスクを`abort()`する
/// （本関数自体には終了条件が`tx.send`の失敗以外に無いため）。
pub async fn run_synthetic_ticker(tx: UnboundedSender<SandboxPrepEvent>, warm_hint: bool) {
    let start = std::time::Instant::now();
    let mut interval = tokio::time::interval(Duration::from_millis(250));
    loop {
        interval.tick().await;
        let elapsed = start.elapsed();
        let phase = Phase::from_elapsed(elapsed, warm_hint);
        let ev = SandboxPrepEvent {
            elapsed,
            label: phase.label_ja().to_string(),
            done_hint: None,
        };
        if tx.send(ev).is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_thresholds_progress_monotonically_through_all_phases() {
        let mut last = Phase::ConnectingDaemon;
        for secs in [0, 4, 5, 24, 25, 194, 195, 214, 215, 224, 225, 400] {
            let phase = Phase::from_elapsed(Duration::from_secs(secs), false);
            assert!(
                phase as u8 >= last as u8,
                "phase regressed at {secs}s: {phase:?} < {last:?}"
            );
            last = phase;
        }
        assert_eq!(
            Phase::from_elapsed(Duration::from_secs(400), false),
            Phase::ConfiguringWorkspace
        );
    }

    #[test]
    fn warm_hint_falls_back_to_cold_table_past_warm_window() {
        assert_eq!(
            Phase::from_elapsed(Duration::from_secs(1), true),
            Phase::ConnectingDaemon
        );
        assert_eq!(
            Phase::from_elapsed(Duration::from_secs(10), true),
            Phase::WaitingGuestOs
        );
        // warm想定(25秒)を超えたら、同じ経過秒をコールド表で評価し直す。
        assert_eq!(
            Phase::from_elapsed(Duration::from_secs(30), true),
            Phase::from_elapsed(Duration::from_secs(30), false)
        );
    }
}
