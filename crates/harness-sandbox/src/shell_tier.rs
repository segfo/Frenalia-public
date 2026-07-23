//! シェル隔離Tier検知・選択（M12）。`plans/DESIGN-SANDBOX.md` §6/§7 D-02/D-03参照。
//!
//! 起動時にOS能力をプローブし最上位Tierを選択する。不可なら自動降格+警告
//! （`ShellTierSelection.downgraded_from`/`reason`、値そのものは`harness_core`が定義する
//! 「`ToolCtx`が運ぶ値」。ここは選択ロジックの実体のみ）。`--require-sandbox[=confidential]`
//! 指定時は降格せず`TierError`で実行拒否する（§8-2の判定表）。
//!
//! Windows/Linux以外（macOS等）はTier0固定（Seatbelt枠は本フェーズの対象外、
//! `plans/DESIGN-SANDBOX.md` §6.6は将来拡張として明記のみ）。

use std::path::{Path, PathBuf};

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
        RequireSandbox::WriteContainment => {
            matches!(tier, ShellTier::Tier2 | ShellTier::Tier1a | ShellTier::Tier1b)
        }
        RequireSandbox::Confidential => matches!(tier, ShellTier::Tier2 | ShellTier::Tier1a),
    }
}

fn require_label(require: RequireSandbox) -> &'static str {
    match require {
        RequireSandbox::None => "none",
        RequireSandbox::WriteContainment => "write-containment",
        RequireSandbox::Confidential => "confidential",
    }
}

/// Tier1a向けfs passthrough記述子（D-13、`plans/DESIGN-SANDBOX-APPPOLICY.md` §5.1）。
/// package SIDへ追加ルート（`workspace_root`外）の許可ACEを付与する対象を表す。
/// `writable=false`が既定（read-only、書込は明示`:rw`指定時のみ`true`）。
/// Windows以外では値を運ぶだけで`best_effort_tier`のLinux/other分岐からは無視される
/// （`harness-core`へは出さずこのクレート内に閉じる、network側の`NetAppPolicy`とは
/// 役割分担が異なる: FSアクセス制御は実FSのACLで完結するため`ToolCtx`を経由しない）。
#[derive(Debug, Clone)]
pub struct FsPassthrough {
    pub path: PathBuf,
    pub writable: bool,
    /// `--force-system-acl`（D-19）: `NT SERVICE\TrustedInstaller`所有等で`WRITE_DAC`不可の
    /// システム保護パスへ、特権分離ヘルパーが`SeRestorePrivilege`を有効化して強制付与する。
    /// 既定false。`is_force_grant_forbidden`のゲートを通過したもののみ実際に強制付与される。
    pub forced: bool,
}

/// OS能力プローブ結果。テストから注入できるようにフィールドを公開する。
#[derive(Debug, Clone, Default)]
pub struct Probes {
    /// LinuxでのみTier2候補にする。`bwrap`バイナリのパスが見つかったか。
    pub bwrap_path: Option<PathBuf>,
    /// `/proc/sys/kernel/unprivileged_userns_clone`の値（`Some(false)`なら明示的に無効）。
    /// 読めない/存在しない場合は`None`（多くのディストロは既定で有効なので許可側に倒す）。
    pub unprivileged_userns_enabled: Option<bool>,
    /// Windows Tier1a（AppContainer）のプリフライト結果をテストから注入する
    /// （`None`なら本番同様に実際の`win_appcontainer::preflight`を呼ぶ、`Some(..)`なら
    /// テストが結果を固定する）。プロファイル作成+実FS再帰ACL書込という副作用ありの重い
    /// 処理なので、単体テストで実Win32を呼ばずに分岐ロジックだけを検証するために使う。
    pub tier1a_preflight_override: Option<Result<(), String>>,
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
/// `opt_in_tier1a`はD-02「既定にせずフラグでオプトイン」の実装（`--experimental-tier1a`）。
/// 無効時はWindows上でも常にTier1bを選択し、既存コストは増分ゼロ。
pub fn select_tier(
    require: RequireSandbox,
    workspace_root: &Path,
    opt_in_tier1a: bool,
    passthrough: &[FsPassthrough],
) -> Result<ShellTierSelection, TierError> {
    select_tier_with_probes(
        require,
        workspace_root,
        opt_in_tier1a,
        passthrough,
        &Probes::detect(),
    )
}

/// テスト用: プローブ結果を注入して選択ロジックのみを検証する。
pub fn select_tier_with_probes(
    require: RequireSandbox,
    workspace_root: &Path,
    opt_in_tier1a: bool,
    passthrough: &[FsPassthrough],
    probes: &Probes,
) -> Result<ShellTierSelection, TierError> {
    let selection = best_effort_tier(workspace_root, opt_in_tier1a, passthrough, probes);
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
fn best_effort_tier(
    workspace_root: &Path,
    opt_in_tier1a: bool,
    passthrough: &[FsPassthrough],
    probes: &Probes,
) -> ShellTierSelection {
    // Restricted Token構築はほぼ全ての非管理者環境で可能と仮定する（§6.3）。
    // 実際の構築失敗はrun_shell呼び出し時にTier0へ実行時降格させる
    // （harness-tools::shell側の責務、`plans/DESIGN-SANDBOX.md` §6.1「不可なら自動降格+警告」）。
    if !opt_in_tier1a {
        return ShellTierSelection::direct(ShellTier::Tier1b);
    }
    match &probes.tier1a_preflight_override {
        Some(Ok(())) => ShellTierSelection::direct(ShellTier::Tier1a),
        Some(Err(reason)) => {
            ShellTierSelection::downgraded(ShellTier::Tier1a, ShellTier::Tier1b, reason.clone())
        }
        // テスト注入が無い場合のみ実際のWin32 preflightを呼ぶ（副作用ありの重い処理を
        // 単体テストでは避ける、既存の分岐と同じ考え方）。D8: passthroughの到達不能は
        // Tier選択自体を左右せず`passthrough_warnings`として運ぶだけ。
        None => match crate::win_appcontainer::preflight(workspace_root, passthrough) {
            Ok(outcome) => ShellTierSelection::direct(ShellTier::Tier1a)
                .with_passthrough_warnings(outcome.warnings)
                .with_granted_passthrough(outcome.granted_passthrough),
            Err(e) => ShellTierSelection::downgraded(ShellTier::Tier1a, ShellTier::Tier1b, e.to_string()),
        },
    }
}

#[cfg(target_os = "linux")]
fn best_effort_tier(
    _workspace_root: &Path,
    _opt_in_tier1a: bool,
    _passthrough: &[FsPassthrough],
    probes: &Probes,
) -> ShellTierSelection {
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
fn best_effort_tier(
    _workspace_root: &Path,
    _opt_in_tier1a: bool,
    _passthrough: &[FsPassthrough],
    _probes: &Probes,
) -> ShellTierSelection {
    ShellTierSelection::downgraded(
        ShellTier::Tier2,
        ShellTier::Tier0,
        "no native shell isolation tier implemented for this OS (macOS Seatbelt is future work, see plans/DESIGN-SANDBOX.md §6.6)",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_root() -> PathBuf {
        std::env::temp_dir()
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_defaults_to_tier1b() {
        let selection = select_tier_with_probes(
            RequireSandbox::None,
            &empty_root(),
            false,
            &[],
            &Probes::default(),
        )
        .unwrap();
        assert_eq!(selection.tier, ShellTier::Tier1b);
        assert!(selection.downgraded_from.is_none());
        assert!(!selection.is_unisolated());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_require_confidential_rejects_tier1b() {
        let err = select_tier_with_probes(
            RequireSandbox::Confidential,
            &empty_root(),
            false,
            &[],
            &Probes::default(),
        )
        .unwrap_err();
        assert!(matches!(err, TierError::Insufficient { .. }));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_require_write_containment_passes_tier1b() {
        let selection = select_tier_with_probes(
            RequireSandbox::WriteContainment,
            &empty_root(),
            false,
            &[],
            &Probes::default(),
        )
        .unwrap();
        assert_eq!(selection.tier, ShellTier::Tier1b);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_without_opt_in_never_selects_tier1a() {
        // フラグ無し（opt_in_tier1a=false）は、たとえpreflightが成功する状況を注入しても
        // 絶対にTier1aへ行かない（D-02「既定にせずフラグでオプトイン」の型レベルの保証）。
        let probes = Probes {
            tier1a_preflight_override: Some(Ok(())),
            ..Default::default()
        };
        let selection =
            select_tier_with_probes(RequireSandbox::None, &empty_root(), false, &[], &probes)
                .unwrap();
        assert_eq!(selection.tier, ShellTier::Tier1b);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_opt_in_with_successful_preflight_selects_tier1a() {
        let probes = Probes {
            tier1a_preflight_override: Some(Ok(())),
            ..Default::default()
        };
        let selection =
            select_tier_with_probes(RequireSandbox::None, &empty_root(), true, &[], &probes)
                .unwrap();
        assert_eq!(selection.tier, ShellTier::Tier1a);
        assert!(selection.downgraded_from.is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_opt_in_with_failed_preflight_downgrades_to_tier1b() {
        let probes = Probes {
            tier1a_preflight_override: Some(Err("acl grant failed".to_string())),
            ..Default::default()
        };
        let selection =
            select_tier_with_probes(RequireSandbox::None, &empty_root(), true, &[], &probes)
                .unwrap();
        assert_eq!(selection.tier, ShellTier::Tier1b);
        assert_eq!(selection.downgraded_from, Some(ShellTier::Tier1a));
        assert!(selection.reason.is_some());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_opt_in_tier1a_satisfies_confidential() {
        let probes = Probes {
            tier1a_preflight_override: Some(Ok(())),
            ..Default::default()
        };
        let selection = select_tier_with_probes(
            RequireSandbox::Confidential,
            &empty_root(),
            true,
            &[],
            &probes,
        )
        .unwrap();
        assert_eq!(selection.tier, ShellTier::Tier1a);
    }

    /// B1-B3の回帰: passthrough引数追加後もTier1a preflightの既存分岐（成功/失敗）は不変。
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_passthrough_argument_does_not_affect_override_branches() {
        let probes = Probes {
            tier1a_preflight_override: Some(Ok(())),
            ..Default::default()
        };
        let passthrough = vec![FsPassthrough {
            path: PathBuf::from("C:\\dummy"),
            writable: false,
            forced: false,
        }];
        let selection =
            select_tier_with_probes(RequireSandbox::None, &empty_root(), true, &passthrough, &probes)
                .unwrap();
        // オーバーライドが刺さっている限り、実際のpreflightは呼ばれず
        // passthrough_warningsも実プローブ由来では埋まらない（空のまま）。
        assert_eq!(selection.tier, ShellTier::Tier1a);
        assert!(selection.passthrough_warnings.is_empty());
    }

    /// 未解決事項2 決定5の回帰テスト: FSプローブ失敗（この機種のtraverse ACE欠如を模す）で
    /// Tier1aがTier1bへ丸ごと降格すると、`confidential`はTier1bを満たさないため、黙って
    /// Tier1bで起動するのではなく`TierError`で起動前に拒否されなければならない
    /// （`docs/phases/foundation/M12-shell-isolation-tiers.md`追記3参照）。
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_opt_in_tier1a_with_failed_preflight_rejects_confidential() {
        let probes = Probes {
            tier1a_preflight_override: Some(Err(
                "workspace FS I/O denied inside AppContainer".to_string(),
            )),
            ..Default::default()
        };
        let err = select_tier_with_probes(
            RequireSandbox::Confidential,
            &empty_root(),
            true,
            &[],
            &probes,
        )
        .unwrap_err();
        assert!(matches!(err, TierError::Insufficient { .. }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_selects_tier2_when_bwrap_present_and_userns_enabled() {
        let probes = Probes {
            bwrap_path: Some(PathBuf::from("/usr/bin/bwrap")),
            unprivileged_userns_enabled: Some(true),
            ..Default::default()
        };
        let selection =
            select_tier_with_probes(RequireSandbox::None, &empty_root(), false, &[], &probes)
                .unwrap();
        assert_eq!(selection.tier, ShellTier::Tier2);
        assert!(selection.downgraded_from.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_downgrades_to_tier0_when_bwrap_missing() {
        let probes = Probes {
            bwrap_path: None,
            unprivileged_userns_enabled: Some(true),
            ..Default::default()
        };
        let selection =
            select_tier_with_probes(RequireSandbox::None, &empty_root(), false, &[], &probes)
                .unwrap();
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
            ..Default::default()
        };
        let selection =
            select_tier_with_probes(RequireSandbox::None, &empty_root(), false, &[], &probes)
                .unwrap();
        assert_eq!(selection.tier, ShellTier::Tier0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_require_sandbox_rejects_tier0_downgrade() {
        let probes = Probes {
            bwrap_path: None,
            unprivileged_userns_enabled: None,
            ..Default::default()
        };
        let err = select_tier_with_probes(
            RequireSandbox::WriteContainment,
            &empty_root(),
            false,
            &[],
            &probes,
        )
        .unwrap_err();
        assert!(matches!(err, TierError::Insufficient { .. }));
    }
}
