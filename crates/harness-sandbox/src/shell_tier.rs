//! シェル隔離Tier検知・選択（M12）。`plans/DESIGN-SANDBOX.md` §6/§7 D-02/D-03参照。
//!
//! 起動時にOS能力をプローブし最上位Tierを選択する。不可なら自動降格+警告
//! （`ShellTierSelection.downgraded_from`/`reason`、値そのものは`harness_core`が定義する
//! 「`ToolCtx`が運ぶ値」。ここは選択ロジックの実体のみ）。`--require-sandbox[=confidential]`
//! 指定時は降格せず`TierError`で実行拒否する（§8-2の判定表）。
//!
//! Windows/Linux以外（macOS等）はTier0固定（Seatbelt枠は本フェーズの対象外、
//! `plans/DESIGN-SANDBOX.md` §6.6は将来拡張として明記のみ）。

use std::path::PathBuf;

use harness_core::{RequireSandbox, ShellTier, ShellTierSelection};

#[derive(Debug, Clone, thiserror::Error)]
pub enum TierError {
    #[error(
        "selected shell isolation tier {selected} does not satisfy --require-sandbox={required} (see plans/DESIGN-SANDBOX.md §8-2)"
    )]
    Insufficient {
        selected: &'static str,
        required: &'static str,
    },
}

/// §8-2の判定表: 選択Tierが`require`を満たすかどうか。
fn satisfies(tier: ShellTier, require: RequireSandbox) -> bool {
    match require {
        RequireSandbox::None => true,
        RequireSandbox::WriteContainment => matches!(tier, ShellTier::Tier2 | ShellTier::Tier1b),
        RequireSandbox::Confidential => matches!(tier, ShellTier::Tier2),
    }
}

fn require_label(require: RequireSandbox) -> &'static str {
    match require {
        RequireSandbox::None => "none",
        RequireSandbox::WriteContainment => "write-containment",
        RequireSandbox::Confidential => "confidential",
    }
}

/// OS能力プローブ結果。テストから注入できるようにフィールドを公開する。
#[derive(Debug, Clone, Default)]
pub struct Probes {
    /// LinuxでのみTier2候補にする。`bwrap`バイナリのパスが見つかったか。
    pub bwrap_path: Option<PathBuf>,
    /// `/proc/sys/kernel/unprivileged_userns_clone`の値（`Some(false)`なら明示的に無効）。
    /// 読めない/存在しない場合は`None`（多くのディストロは既定で有効なので許可側に倒す）。
    pub unprivileged_userns_enabled: Option<bool>,
}

impl Probes {
    #[cfg(target_os = "linux")]
    pub fn detect() -> Self {
        let bwrap_path = which::which("bwrap").ok();
        let unprivileged_userns_enabled =
            std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
                .ok()
                .map(|s| s.trim() != "0");
        Self {
            bwrap_path,
            unprivileged_userns_enabled,
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn detect() -> Self {
        Self::default()
    }

    #[cfg(target_os = "linux")]
    fn linux_tier2_available(&self) -> bool {
        self.bwrap_path.is_some() && self.unprivileged_userns_enabled.unwrap_or(true)
    }
}

/// 現在のOSでの最上位Tierを選択する（`require`違反時は降格せず`TierError`）。
pub fn select_tier(require: RequireSandbox) -> Result<ShellTierSelection, TierError> {
    select_tier_with_probes(require, &Probes::detect())
}

/// テスト用: プローブ結果を注入して選択ロジックのみを検証する。
pub fn select_tier_with_probes(
    require: RequireSandbox,
    probes: &Probes,
) -> Result<ShellTierSelection, TierError> {
    let selection = best_effort_tier(probes);
    if satisfies(selection.tier, require) {
        Ok(selection)
    } else {
        Err(TierError::Insufficient {
            selected: selection.tier.label(),
            required: require_label(require),
        })
    }
}

#[cfg(target_os = "windows")]
fn best_effort_tier(_probes: &Probes) -> ShellTierSelection {
    // Restricted Token構築はほぼ全ての非管理者環境で可能と仮定する（§6.3）。
    // 実際の構築失敗はrun_shell呼び出し時にTier0へ実行時降格させる
    // （harness-tools::shell側の責務、`plans/DESIGN-SANDBOX.md` §6.1「不可なら自動降格+警告」）。
    ShellTierSelection::direct(ShellTier::Tier1b)
}

#[cfg(target_os = "linux")]
fn best_effort_tier(probes: &Probes) -> ShellTierSelection {
    if probes.linux_tier2_available() {
        ShellTierSelection::direct(ShellTier::Tier2)
    } else {
        let reason = if probes.bwrap_path.is_none() {
            "bwrap not found on PATH".to_string()
        } else {
            "unprivileged user namespaces are disabled (/proc/sys/kernel/unprivileged_userns_clone=0)"
                .to_string()
        };
        ShellTierSelection::downgraded(ShellTier::Tier2, ShellTier::Tier0, reason)
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn best_effort_tier(_probes: &Probes) -> ShellTierSelection {
    ShellTierSelection::downgraded(
        ShellTier::Tier2,
        ShellTier::Tier0,
        "no native shell isolation tier implemented for this OS (macOS Seatbelt is future work, see plans/DESIGN-SANDBOX.md §6.6)",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_defaults_to_tier1b() {
        let selection = select_tier_with_probes(RequireSandbox::None, &Probes::default()).unwrap();
        assert_eq!(selection.tier, ShellTier::Tier1b);
        assert!(selection.downgraded_from.is_none());
        assert!(!selection.is_unisolated());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_require_confidential_rejects_tier1b() {
        let err = select_tier_with_probes(RequireSandbox::Confidential, &Probes::default())
            .unwrap_err();
        assert!(matches!(err, TierError::Insufficient { .. }));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_require_write_containment_passes_tier1b() {
        let selection =
            select_tier_with_probes(RequireSandbox::WriteContainment, &Probes::default()).unwrap();
        assert_eq!(selection.tier, ShellTier::Tier1b);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_selects_tier2_when_bwrap_present_and_userns_enabled() {
        let probes = Probes {
            bwrap_path: Some(PathBuf::from("/usr/bin/bwrap")),
            unprivileged_userns_enabled: Some(true),
        };
        let selection = select_tier_with_probes(RequireSandbox::None, &probes).unwrap();
        assert_eq!(selection.tier, ShellTier::Tier2);
        assert!(selection.downgraded_from.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_downgrades_to_tier0_when_bwrap_missing() {
        let probes = Probes {
            bwrap_path: None,
            unprivileged_userns_enabled: Some(true),
        };
        let selection = select_tier_with_probes(RequireSandbox::None, &probes).unwrap();
        assert_eq!(selection.tier, ShellTier::Tier0);
        assert_eq!(selection.downgraded_from, Some(ShellTier::Tier2));
        assert!(selection.is_unisolated());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_downgrades_to_tier0_when_userns_disabled() {
        let probes = Probes {
            bwrap_path: Some(PathBuf::from("/usr/bin/bwrap")),
            unprivileged_userns_enabled: Some(false),
        };
        let selection = select_tier_with_probes(RequireSandbox::None, &probes).unwrap();
        assert_eq!(selection.tier, ShellTier::Tier0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_require_sandbox_rejects_tier0_downgrade() {
        let probes = Probes {
            bwrap_path: None,
            unprivileged_userns_enabled: None,
        };
        let err =
            select_tier_with_probes(RequireSandbox::WriteContainment, &probes).unwrap_err();
        assert!(matches!(err, TierError::Insufficient { .. }));
    }
}
