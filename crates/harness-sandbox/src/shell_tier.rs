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
    #[error(
        "{attempted} is unavailable: {reason}. Use --tier1 to explicitly opt in to Windows Tier1 fallback."
    )]
    Unavailable {
        attempted: &'static str,
        reason: String,
    },
}

/// §8-2の判定表: 選択Tierが`require`を満たすかどうか。
fn satisfies(tier: ShellTier, require: RequireSandbox) -> bool {
    match require {
        RequireSandbox::None => true,
        RequireSandbox::WriteContainment => matches!(
            tier,
            ShellTier::Tier3 | ShellTier::Tier2b | ShellTier::Tier2a | ShellTier::Tier1
        ),
        RequireSandbox::Confidential => {
            matches!(
                tier,
                ShellTier::Tier3 | ShellTier::Tier2b | ShellTier::Tier2a
            )
        }
    }
}

fn require_label(require: RequireSandbox) -> &'static str {
    match require {
        RequireSandbox::None => "none",
        RequireSandbox::WriteContainment => "write-containment",
        RequireSandbox::Confidential => "confidential",
    }
}

/// Tier2a向けfs passthroughアクセス権。設定上は`fs.read`/`fs.read_write`/`fs.read_exec`に対応する。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsAccess {
    /// 読取のみ。
    Read,
    /// 読取・書込。
    ReadWrite,
    /// 読取・実行。
    ReadExec,
}

impl FsAccess {
    pub fn is_read_write(self) -> bool {
        self == FsAccess::ReadWrite
    }

    pub fn label(self) -> &'static str {
        match self {
            FsAccess::Read => "read",
            FsAccess::ReadWrite => "read_write",
            FsAccess::ReadExec => "read_exec",
        }
    }
}

/// Tier2a向けfs passthrough記述子（D-13、`plans/DESIGN-SANDBOX-APPPOLICY.md` §5.1）。
/// package SIDへ追加ルート（`workspace_root`外）の許可ACEを付与する対象を表す。
/// Windows以外では値を運ぶだけで`best_effort_tier`のLinux/other分岐からは無視される
/// （`harness-core`へは出さずこのクレート内に閉じる、network側の`NetAppPolicy`とは
/// 役割分担が異なる: FSアクセス制御は実FSのACLで完結するため`ToolCtx`を経由しない）。
#[derive(Debug, Clone)]
pub struct FsPassthrough {
    pub path: PathBuf,
    pub access: FsAccess,
    /// `--force-system-acl`（D-19）: `NT SERVICE\TrustedInstaller`所有等で`WRITE_DAC`不可の
    /// システム保護パスへ、特権分離ヘルパーが`SeRestorePrivilege`を有効化して強制付与する。
    /// 既定false。`is_force_grant_forbidden`のゲートを通過したもののみ実際に強制付与される。
    pub forced: bool,
}

/// OS能力プローブ結果。テストから注入できるようにフィールドを公開する。
#[derive(Debug, Clone, Default)]
pub struct Probes {
    /// LinuxでのみTier2b候補にする。`bwrap`バイナリのパスが見つかったか。
    pub bwrap_path: Option<PathBuf>,
    /// `/proc/sys/kernel/unprivileged_userns_clone`の値（`Some(false)`なら明示的に無効）。
    /// 読めない/存在しない場合は`None`（多くのディストロは既定で有効なので許可側に倒す）。
    pub unprivileged_userns_enabled: Option<bool>,
    /// Windows Tier2a（AppContainer）のプリフライト結果をテストから注入する
    /// （`None`なら本番同様に実際の`win_appcontainer::preflight`を呼ぶ、`Some(..)`なら
    /// テストが結果を固定する）。プロファイル作成+実FS再帰ACL書込という副作用ありの重い
    /// 処理なので、単体テストで実Win32を呼ばずに分岐ロジックだけを検証するために使う。
    pub tier2a_preflight_override: Option<Result<(), String>>,
    /// Windows Tier3（Hyper-V外層VM + Incusコンテナ）の可否をテストから注入する
    /// （`None`なら本番同様にゴールデン像VHDXの存在チェックのみ行う——VM起動自体は`run_shell`
    /// 呼び出し時に`harness-cli`が`VmSandboxHandle::start`で行うため、Tier選択時点では
    /// 「試す価値があるか」の軽量チェックに留める、Phase 1のスコープ）。
    pub tier3_available_override: Option<Result<(), String>>,
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
    fn linux_tier2b_available(&self) -> bool {
        self.bwrap_path.is_some() && self.unprivileged_userns_enabled.unwrap_or(true)
    }
}

/// 現在のOSでの最上位Tierを選択する（`require`違反時は降格せず`TierError`）。
/// Windowsではフラグ無しでもTier2aを常時プローブする（Linuxのbwrapプローブと同じ
/// 「フラグなし常時プローブ」構造）。Tier2aが使えない場合は、`opt_in_tier1`が
/// 指定されているときだけTier1へ降格する。`opt_in_tier3`は`--vm-sandbox`の実装。
pub fn select_tier(
    require: RequireSandbox,
    workspace_root: &Path,
    opt_in_tier3: bool,
    opt_in_tier1: bool,
    passthrough: &[FsPassthrough],
    wfp_chain_pipe: Option<String>,
) -> Result<ShellTierSelection, TierError> {
    select_tier_with_probes(
        require,
        workspace_root,
        opt_in_tier3,
        opt_in_tier1,
        passthrough,
        wfp_chain_pipe,
        &Probes::detect(),
    )
}

/// テスト用: プローブ結果を注入して選択ロジックのみを検証する。
pub fn select_tier_with_probes(
    require: RequireSandbox,
    workspace_root: &Path,
    opt_in_tier3: bool,
    opt_in_tier1: bool,
    passthrough: &[FsPassthrough],
    wfp_chain_pipe: Option<String>,
    probes: &Probes,
) -> Result<ShellTierSelection, TierError> {
    let selection = best_effort_tier(
        workspace_root,
        opt_in_tier3,
        opt_in_tier1,
        passthrough,
        wfp_chain_pipe,
        probes,
    )?;
    if satisfies(selection.tier, require) {
        Ok(selection)
    } else {
        Err(TierError::Insufficient {
            selected: selection.tier.label(),
            required: require_label(require),
        })
    }
}

/// Tier3の軽量可用性チェック（ゴールデン像VHDXの存在のみ確認、実際のVM起動はしない）。
/// `plans/DESIGN-SANDBOX-VMISOLATION.md`の固定運用規約と同じパスを見る
/// （`harness_sandbox::vmsandbox::VmSandboxConfig::default().golden_vhdx`と同一値、
/// 循環依存を避けるためここでは値を直接埋め込む——両者が乖離したら単体テストで検知できないが、
/// Phase 1では許容する）。
#[cfg(windows)]
fn probe_tier3_available() -> Result<(), String> {
    let golden = Path::new(r"C:\ProgramData\harness\golden-images\almalinux-golden.vhdx");
    if !golden.exists() {
        return Err(format!(
            "golden image not found at {} (Tier3 requires a pre-built AlmaLinux golden VHDX, \
             see plans/vm-spike/RESULTS.md)",
            golden.display()
        ));
    }
    Ok(())
}

/// Tier2aのプローブ本体（成功ならTier2a直接選択のための`ShellTierSelection`、失敗なら理由文字列）。
/// `best_effort_tier`の2箇所（フラグなしの既定パス、Tier3失敗時のカスケード先）から共有する。
#[cfg(target_os = "windows")]
fn try_tier2a(
    workspace_root: &Path,
    passthrough: &[FsPassthrough],
    wfp_chain_pipe: Option<String>,
    probes: &Probes,
) -> Result<ShellTierSelection, String> {
    match &probes.tier2a_preflight_override {
        Some(Ok(())) => Ok(ShellTierSelection::direct(ShellTier::Tier2a)),
        Some(Err(reason)) => Err(reason.clone()),
        // テスト注入が無い場合のみ実際のWin32 preflightを呼ぶ（副作用ありの重い処理を
        // 単体テストでは避ける、既存の分岐と同じ考え方）。D8: passthroughの到達不能は
        // Tier選択自体を左右せず`passthrough_warnings`として運ぶだけ。
        None => {
            match crate::win_appcontainer::preflight(workspace_root, passthrough, wfp_chain_pipe) {
                Ok(outcome) => Ok(ShellTierSelection::direct(ShellTier::Tier2a)
                    .with_passthrough_warnings(outcome.warnings)
                    .with_denied_passthrough(outcome.denied_passthrough)
                    .with_granted_passthrough(outcome.granted_passthrough)
                    .with_netfilterd_chain_attempted(outcome.netfilterd_chain_attempted)),
                Err(e) => Err(e.to_string()),
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn best_effort_tier(
    workspace_root: &Path,
    opt_in_tier3: bool,
    opt_in_tier1: bool,
    passthrough: &[FsPassthrough],
    wfp_chain_pipe: Option<String>,
    probes: &Probes,
) -> Result<ShellTierSelection, TierError> {
    if opt_in_tier1 {
        return Ok(ShellTierSelection::direct(ShellTier::Tier1));
    }

    // Tier3はTier2a/Tier1とは独立のオプトイン（`--vm-sandbox`）。指定時は
    // 最優先で試す（Tier3が唯一vNIC単位で出口を強制できるTierのため、成立するなら常に最良）。
    // 不成立の場合はTier2aへカスケードする。Tier2aも不成立なら、暗黙にはTier1へ降格しない。
    if opt_in_tier3 {
        let probe_result = match &probes.tier3_available_override {
            Some(r) => r.clone(),
            None => probe_tier3_available(),
        };
        return match probe_result {
            Ok(()) => Ok(ShellTierSelection::direct(ShellTier::Tier3)),
            Err(tier3_reason) => match try_tier2a(workspace_root, passthrough, wfp_chain_pipe, probes) {
                Ok(tier2a_selection) => {
                    // Tier2aへ実際に着地するので、「なぜTier3ではないか」を理由として持たせる
                    // （既存の単発降格の形をそのまま踏襲、Tier2a到達自体は成功のため
                    // `tier2a_selection`が運ぶpassthrough_warnings等のビルダ値は保持する）。
                    Ok(ShellTierSelection {
                        downgraded_from: Some(ShellTier::Tier3),
                        reason: Some(tier3_reason),
                        ..tier2a_selection
                    })
                }
                Err(tier2a_reason) => Err(TierError::Unavailable {
                    attempted: ShellTier::Tier2a.label(),
                    reason: format!(
                        "Tier3 unavailable ({tier3_reason}); Tier2a preflight also failed ({tier2a_reason})"
                    ),
                }),
            },
        };
    }

    // フラグなしの既定パス: Tier2aを無条件にプローブする（Linuxのbwrapプローブと同じ
    // 「フラグなし常時プローブ」構造）。失敗時はTier1へ暗黙降格せず、起動時エラーにする。
    match try_tier2a(workspace_root, passthrough, wfp_chain_pipe, probes) {
        Ok(selection) => Ok(selection),
        Err(reason) => Err(TierError::Unavailable {
            attempted: ShellTier::Tier2a.label(),
            reason,
        }),
    }
}

#[cfg(target_os = "linux")]
fn best_effort_tier(
    _workspace_root: &Path,
    _opt_in_tier3: bool,
    _opt_in_tier1: bool,
    _passthrough: &[FsPassthrough],
    _wfp_chain_pipe: Option<String>,
    probes: &Probes,
) -> Result<ShellTierSelection, TierError> {
    if probes.linux_tier2b_available() {
        Ok(ShellTierSelection::direct(ShellTier::Tier2b))
    } else {
        let reason = if probes.bwrap_path.is_none() {
            "bwrap not found on PATH".to_string()
        } else {
            "unprivileged user namespaces are disabled (/proc/sys/kernel/unprivileged_userns_clone=0)"
                .to_string()
        };
        Ok(ShellTierSelection::downgraded(
            ShellTier::Tier2b,
            ShellTier::Tier0,
            reason,
        ))
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn best_effort_tier(
    _workspace_root: &Path,
    _opt_in_tier3: bool,
    _opt_in_tier1: bool,
    _passthrough: &[FsPassthrough],
    _wfp_chain_pipe: Option<String>,
    _probes: &Probes,
) -> Result<ShellTierSelection, TierError> {
    Ok(ShellTierSelection::downgraded(
        ShellTier::Tier2b,
        ShellTier::Tier0,
        "no native shell isolation tier implemented for this OS (macOS Seatbelt is future work, see plans/DESIGN-SANDBOX.md §6.6)",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_root() -> PathBuf {
        std::env::temp_dir()
    }

    /// Windowsはフラグ無しでもTier2aを常時プローブする（Linuxのbwrapプローブと
    /// 対称的な構造）。preflight成功時はTier2aへ直接着地する。
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_default_selects_tier2a_when_preflight_succeeds() {
        let probes = Probes {
            tier2a_preflight_override: Some(Ok(())),
            ..Default::default()
        };
        let selection = select_tier_with_probes(
            RequireSandbox::None,
            &empty_root(),
            false,
            false,
            &[],
            None,
            &probes,
        )
        .unwrap();
        assert_eq!(selection.tier, ShellTier::Tier2a);
        assert!(selection.downgraded_from.is_none());
        assert!(!selection.is_unisolated());
    }

    /// 既定パスではTier2a preflightが失敗してもTier1へ暗黙降格しない。
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_default_errors_when_tier2a_preflight_fails() {
        let probes = Probes {
            tier2a_preflight_override: Some(Err("acl grant failed".to_string())),
            ..Default::default()
        };
        let err = select_tier_with_probes(
            RequireSandbox::None,
            &empty_root(),
            false,
            false,
            &[],
            None,
            &probes,
        )
        .unwrap_err();
        assert!(matches!(err, TierError::Unavailable { .. }));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_tier1_opt_in_selects_tier1_directly() {
        let probes = Probes {
            tier2a_preflight_override: Some(Err("acl grant failed".to_string())),
            ..Default::default()
        };
        let selection = select_tier_with_probes(
            RequireSandbox::None,
            &empty_root(),
            false,
            true,
            &[],
            None,
            &probes,
        )
        .unwrap();
        assert_eq!(selection.tier, ShellTier::Tier1);
        assert_eq!(selection.downgraded_from, None);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_require_confidential_rejects_tier1() {
        let probes = Probes {
            tier2a_preflight_override: Some(Err("not available on this test host".to_string())),
            ..Default::default()
        };
        let err = select_tier_with_probes(
            RequireSandbox::Confidential,
            &empty_root(),
            false,
            true,
            &[],
            None,
            &probes,
        )
        .unwrap_err();
        assert!(matches!(err, TierError::Insufficient { .. }));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_require_write_containment_passes_tier1() {
        let probes = Probes {
            tier2a_preflight_override: Some(Err("not available on this test host".to_string())),
            ..Default::default()
        };
        let selection = select_tier_with_probes(
            RequireSandbox::WriteContainment,
            &empty_root(),
            false,
            true,
            &[],
            None,
            &probes,
        )
        .unwrap();
        assert_eq!(selection.tier, ShellTier::Tier1);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_default_tier2a_satisfies_confidential() {
        let probes = Probes {
            tier2a_preflight_override: Some(Ok(())),
            ..Default::default()
        };
        let selection = select_tier_with_probes(
            RequireSandbox::Confidential,
            &empty_root(),
            false,
            false,
            &[],
            None,
            &probes,
        )
        .unwrap();
        assert_eq!(selection.tier, ShellTier::Tier2a);
    }

    /// B1-B3の回帰: passthrough引数追加後もTier2a preflightの既存分岐（成功/失敗）は不変。
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_passthrough_argument_does_not_affect_override_branches() {
        let probes = Probes {
            tier2a_preflight_override: Some(Ok(())),
            ..Default::default()
        };
        let passthrough = vec![FsPassthrough {
            path: PathBuf::from("C:\\dummy"),
            access: FsAccess::ReadExec,
            forced: false,
        }];
        let selection = select_tier_with_probes(
            RequireSandbox::None,
            &empty_root(),
            false,
            false,
            &passthrough,
            None,
            &probes,
        )
        .unwrap();
        // オーバーライドが刺さっている限り、実際のpreflightは呼ばれず
        // passthrough_warningsも実プローブ由来では埋まらない（空のまま）。
        assert_eq!(selection.tier, ShellTier::Tier2a);
        assert!(selection.passthrough_warnings.is_empty());
    }

    /// FSプローブ失敗（この機種のtraverse ACE欠如を模す）では、既定の時点で
    /// 起動前に拒否されなければならない。
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_tier2a_failure_rejects_confidential() {
        let probes = Probes {
            tier2a_preflight_override: Some(Err(
                "workspace FS I/O denied inside AppContainer".to_string()
            )),
            ..Default::default()
        };
        let err = select_tier_with_probes(
            RequireSandbox::Confidential,
            &empty_root(),
            false,
            false,
            &[],
            None,
            &probes,
        )
        .unwrap_err();
        assert!(matches!(err, TierError::Unavailable { .. }));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_opt_in_tier3_with_available_golden_image_selects_tier3() {
        let probes = Probes {
            tier3_available_override: Some(Ok(())),
            ..Default::default()
        };
        let selection = select_tier_with_probes(
            RequireSandbox::None,
            &empty_root(),
            true,
            false,
            &[],
            None,
            &probes,
        )
        .unwrap();
        assert_eq!(selection.tier, ShellTier::Tier3);
        assert!(selection.downgraded_from.is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_opt_in_tier3_satisfies_confidential() {
        let probes = Probes {
            tier3_available_override: Some(Ok(())),
            ..Default::default()
        };
        let selection = select_tier_with_probes(
            RequireSandbox::Confidential,
            &empty_root(),
            true,
            false,
            &[],
            None,
            &probes,
        )
        .unwrap();
        assert_eq!(selection.tier, ShellTier::Tier3);
    }

    /// `--vm-sandbox`でTier3が不成立でもTier2aへカスケードする。Tier2a preflightが
    /// 成功する状況を注入し、Tier2aへ着地すること・`downgraded_from`がTier3のままであることを確認する。
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_opt_in_tier3_unavailable_cascades_to_tier2a() {
        let probes = Probes {
            tier3_available_override: Some(Err("golden image not found".to_string())),
            tier2a_preflight_override: Some(Ok(())),
            ..Default::default()
        };
        let selection = select_tier_with_probes(
            RequireSandbox::None,
            &empty_root(),
            true,
            false,
            &[],
            None,
            &probes,
        )
        .unwrap();
        assert_eq!(selection.tier, ShellTier::Tier2a);
        assert_eq!(selection.downgraded_from, Some(ShellTier::Tier3));
        assert!(selection.reason.is_some());
    }

    /// Tier3・Tier2aの両方が不成立の場合は、Tier1へ暗黙降格せず起動時エラーにする。
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_opt_in_tier3_and_tier2a_both_unavailable_errors() {
        let probes = Probes {
            tier3_available_override: Some(Err("golden image not found".to_string())),
            tier2a_preflight_override: Some(Err("acl grant failed".to_string())),
            ..Default::default()
        };
        let err = select_tier_with_probes(
            RequireSandbox::None,
            &empty_root(),
            true,
            false,
            &[],
            None,
            &probes,
        )
        .unwrap_err();
        let TierError::Unavailable { reason, .. } = err else {
            panic!("expected unavailable error");
        };
        assert!(reason.contains("golden image not found"));
        assert!(reason.contains("acl grant failed"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_without_opt_in_never_selects_tier3() {
        // `opt_in_tier3=false`なら、たとえTier3の可用性チェックが成功する状況を注入しても
        // 絶対にTier3へ行かない（既定パスはTier2aプローブへ入る）。
        let probes = Probes {
            tier3_available_override: Some(Ok(())),
            tier2a_preflight_override: Some(Err("not tested here".to_string())),
            ..Default::default()
        };
        let err = select_tier_with_probes(
            RequireSandbox::None,
            &empty_root(),
            false,
            false,
            &[],
            None,
            &probes,
        )
        .unwrap_err();
        assert!(matches!(err, TierError::Unavailable { .. }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_selects_Tier2b_when_bwrap_present_and_userns_enabled() {
        let probes = Probes {
            bwrap_path: Some(PathBuf::from("/usr/bin/bwrap")),
            unprivileged_userns_enabled: Some(true),
            ..Default::default()
        };
        let selection = select_tier_with_probes(
            RequireSandbox::None,
            &empty_root(),
            false,
            false,
            &[],
            None,
            &probes,
        )
        .unwrap();
        assert_eq!(selection.tier, ShellTier::Tier2b);
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
        let selection = select_tier_with_probes(
            RequireSandbox::None,
            &empty_root(),
            false,
            false,
            &[],
            None,
            &probes,
        )
        .unwrap();
        assert_eq!(selection.tier, ShellTier::Tier0);
        assert_eq!(selection.downgraded_from, Some(ShellTier::Tier2b));
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
        let selection = select_tier_with_probes(
            RequireSandbox::None,
            &empty_root(),
            false,
            false,
            &[],
            None,
            &probes,
        )
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
            false,
            &[],
            None,
            &probes,
        )
        .unwrap_err();
        assert!(matches!(err, TierError::Insufficient { .. }));
    }
}
