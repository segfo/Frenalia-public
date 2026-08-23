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

use harness_core::{RequireSandbox, SandboxChoice, ShellTier, ShellTierSelection};
// [D-63] 付与範囲の語彙は`harness-policy`が持つ（宣言を読む側と付ける側で1つにする、B-05）。
pub use harness_policy::normalize::{declared_scope, GrantScope};

#[derive(Debug, Clone, thiserror::Error)]
pub enum TierError {
    #[error(
        "selected shell isolation tier {selected} does not satisfy --require-sandbox={required} (see plans/DESIGN-SANDBOX.md §8-2)"
    )]
    Insufficient {
        selected: &'static str,
        required: &'static str,
    },
    // **`--sandbox tier1`を勧めない。** Tier1では低ILラベルがcwd 1個にしか付かないため、
    // ビルド・テスト・`git commit`のいずれも通らない（`tier1::win_restricted`のdocの表）。
    // 「代替Tierがある」かのような案内は、試して失敗するまでの時間を無駄にさせる（B-32）。
    //
    // [BUG-109] **「UACを断ったのだろう」と断定しない。** かつてここは
    // 「昇格できるのに今回失敗したのだから、たぶん断られたUACだ。受け入れて再実行せよ」と
    // 書いていたが、その推測が外れる経路が実在した——制御面のノードを昇格した収集器が作り、
    // 非昇格のharnessがそのDACLを書けない場合で、**UACは一度も提示されない**（進捗表示は
    // 「UACが最大0回出ます」と正しく出していた）。再実行しても同じ場所で永久に止まる。
    // 原因は`reason`が既に名指ししているので、案内は**それを読ませる**側へ倒す（B-32）。
    #[error(
        "{attempted} is unavailable: {reason}. Read that reason first -- if it names a path, that \
         path is the thing to fix. If a UAC prompt appeared and was declined, accept it and retry. \
         (--sandbox tier1 exists but cannot run builds, tests or git commits, so it is not a \
         substitute.)"
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

/// Tier2a向けfs passthroughアクセス権（＝**実際に付与するACEマスクの記述**）。
///
/// # 設定語彙より1つ多い
///
/// 設定ファイルの語彙（[`harness_config::FsAccess`]・`fs.read`/`fs.read_write`/`fs.read_exec`）は
/// 3値だが、こちらには[`FsAccess::ReadWriteExec`]がある。**同じパスに`fs.read_write`と
/// `fs.read_exec`の両方が宣言され得る**のに、1つのオブジェクトのDACLへ同じSID宛のACEを
/// 2本持つことはできない（[`crate::tier2a::win_appcontainer`]の付与は`SetEntriesInAclW`で
/// 1本にまとまる）ため、**和を表せる値**が要る。
///
/// 和が無かった頃は、畳み込みが先に入った方を残して**もう片方の権限が黙って消えていた**
/// ——`read_exec`と`read_write`が同じルートに立つと、どちらを採っても片方が失われる
/// （`ReadWrite`に`FILE_GENERIC_EXECUTE`は入っていない）。
///
/// **`fs.read_write_exec`という設定キーは作らない。** 提案の語彙（`harness_policy::SettingsKey`）と
/// 設定スキーマの1:1を崩さないため、和はこの層（付与）にだけ存在する。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsAccess {
    /// 読取のみ。
    Read,
    /// 読取・書込。
    ReadWrite,
    /// 読取・実行。
    ReadExec,
    /// 読取・書込・実行。**設定語彙には無い**——同じパスへの`fs.read_write`と`fs.read_exec`の
    /// 宣言を1本のACEへ畳んだときにだけ現れる（[`FsAccess::wider`]）。
    ReadWriteExec,
}

impl FsAccess {
    /// **全variantの列挙。** 「harnessがパッケージSID宛に書き得るACEマスクの集合」を
    /// `ALL.map(fs_access_mask)`として**導出**するために要る（撤収側が、名前を失った孤児SIDの
    /// ACEをharnessのものと見分ける指紋に使う。[BUG-101](../../../docs/bugs/BUG-101.md)欠陥②）。
    ///
    /// **手書きのリストを別の場所に作らないこと**（B-05）。variantを足したときの追従漏れは
    /// 下の[`FsAccess::index_in_all`]がコンパイルエラーにする——「剥がせるはずのACEを
    /// 剥がし損ねる」形の無言失敗は、この配列がずれた瞬間に発生する。
    pub const ALL: [FsAccess; 4] = [
        FsAccess::Read,
        FsAccess::ReadWrite,
        FsAccess::ReadExec,
        FsAccess::ReadWriteExec,
    ];

    /// [`FsAccess::ALL`]の網羅性を**コンパイル時に**強制するためだけの写像。
    ///
    /// `_`を持たない`match`なので、variantを1つ足すとここが非網羅でビルドが落ちる。
    /// 併せて`ALL`の配列長も合わなくなるので、2段で気付ける（`prompt.rs`の
    /// `EnvironmentFacts`が使っている2段ゲートと同じ考え方）。
    ///
    /// 下の`const _`ブロックが`ALL`の各要素を自分の添字と突き合わせるので、**順序を
    /// 間違えた／同じ値を2回書いた**場合もコンパイルが通らない。
    const fn index_in_all(self) -> usize {
        match self {
            FsAccess::Read => 0,
            FsAccess::ReadWrite => 1,
            FsAccess::ReadExec => 2,
            FsAccess::ReadWriteExec => 3,
        }
    }

    /// 書込を含むか。**`ReadWriteExec`も真**——ここが偽だと、和を取った途端に
    /// 台帳の`writable`が落ち、到達性プローブがread側で測り、`--sandbox tier2a-cow`のcaptureも外れる
    /// （この1つの述語が3箇所の分岐を決めている）。
    pub fn is_read_write(self) -> bool {
        matches!(self, FsAccess::ReadWrite | FsAccess::ReadWriteExec)
    }

    /// 実行を含むか（`CreateProcess`できるか）。
    pub fn is_exec(self) -> bool {
        matches!(self, FsAccess::ReadExec | FsAccess::ReadWriteExec)
    }

    pub fn label(self) -> &'static str {
        match self {
            FsAccess::Read => "read",
            FsAccess::ReadWrite => "read_write",
            FsAccess::ReadExec => "read_exec",
            FsAccess::ReadWriteExec => "read_write_exec",
        }
    }

    /// 設定語彙（3値）から付与層の値へ。
    pub fn from_settings(access: harness_config::FsAccess) -> Self {
        match access {
            harness_config::FsAccess::Read => FsAccess::Read,
            harness_config::FsAccess::ReadWrite => FsAccess::ReadWrite,
            harness_config::FsAccess::ReadExec => FsAccess::ReadExec,
        }
    }

    /// **同じパスに複数の宣言があるときの合成規則（唯一の定義）。**
    ///
    /// 「広い方を採る」ではなく**和を取る**。`ReadWrite`と`ReadExec`は互いに包含しないので、
    /// どちらかを選ぶ規則では必ず片方の権限が消える——消えた側は実行時に
    /// `Access is denied`として現れるが、宣言は残っているので画面上は許可されて見える。
    ///
    /// 呼び出し側は「何をキーに重複と見なすか」（パス文字列／`PathBuf`のルート）が違うので
    /// 畳み込みのループ自体は各自が持つが、**合成の規則はここだけにある**（B-05）。
    pub fn wider(self, other: FsAccess) -> FsAccess {
        let write = self.is_read_write() || other.is_read_write();
        let exec = self.is_exec() || other.is_exec();
        match (write, exec) {
            (true, true) => FsAccess::ReadWriteExec,
            (true, false) => FsAccess::ReadWrite,
            (false, true) => FsAccess::ReadExec,
            (false, false) => FsAccess::Read,
        }
    }
}

/// [`FsAccess::ALL`]が全variantを過不足なく1回ずつ持つことの**コンパイル時**検算。
///
/// テストではなくここに置くのは、`cargo build`の時点で落としたいため——`ALL`がずれると
/// 「harnessが書いたACEをharnessが自分のものと認識できない」＝
/// [BUG-101](../../../docs/bugs/BUG-101.md)欠陥②の再発になり、症状は**無言**である
/// （`fs revoke`が成功を報告しながら剥がさない）。
const _: () = {
    let mut i = 0;
    while i < FsAccess::ALL.len() {
        assert!(FsAccess::ALL[i].index_in_all() == i);
        i += 1;
    }
};

/// Tier2a向けfs passthrough記述子（D-13、`plans/DESIGN-SANDBOX-APPPOLICY.md` §5.1）。
/// package SIDへ追加ルート（`workspace_root`外）の許可ACEを付与する対象を表す。
/// Windows以外では値を運ぶだけで`best_effort_tier`のLinux/other分岐からは無視される
/// （`harness-core`へは出さずこのクレート内に閉じる、network側の`NetAppPolicy`とは
/// 役割分担が異なる: FSアクセス制御は実FSのACLで完結するため`ToolCtx`を経由しない）。
#[derive(Debug, Clone)]
pub struct FsPassthrough {
    /// **ACEを付ける対象そのもの**（ワイルドカードは含まない）。宣言値が`C:/x/**`なら`C:/x`。
    /// 変換は`harness_policy::normalize::literal_prefix`が唯一の定義を持つ（D-63）。
    pub path: PathBuf,
    pub access: FsAccess,
    /// `--force-system-acl`（D-19）: `NT SERVICE\TrustedInstaller`所有等で`WRITE_DAC`不可の
    /// システム保護パスへ、特権分離ヘルパーが`SeRestorePrivilege`を有効化して強制付与する。
    /// 既定false。`is_force_grant_forbidden`のゲートを通過したもののみ実際に強制付与される。
    pub forced: bool,
    /// [D-63] どこまで開くか。**宣言値の書き方**が決める（`declared_scope`）。
    ///
    /// `path`と対で初めて付与が定まる——`path`が「どのオブジェクトへ」、これが「そのオブジェクト
    /// だけか、配下もか」。ここを付与層で推測してはいけない（宣言と付与が食い違う、B-05）。
    pub scope: GrantScope,
}

/// Tier2aがworkspaceへ付与するACLの種別（D-30、`plans/DESIGN-SANDBOX.md` §7）。
/// `select_tier`から`preflight`まで貫通させる唯一のパラメータとし、`match`の全分岐
/// （`..`無し）でACL付与関数の選択を強制する（`WorkspaceWriteMode`のバリアントを増やした
/// 場合、ACL決定を書き忘れるとコンパイルエラーになる——`harness-core::ToolCtx`/
/// `EnvironmentFacts`の2段ゲートと同じ思想）。Windows以外では値を運ぶだけで無視される
/// （`FsPassthrough`と同じ扱い）。
#[derive(Debug, Clone)]
pub enum WorkspaceWriteMode {
    /// 既定（D-29）。workspaceへ`grant_ace_inheritable_rw`でRead/Write/Execute/Deleteを
    /// 直接付与する。CoW upperは存在しない。
    DirectRw,
    /// `--sandbox tier2a-cow`（D-30）。workspaceへは`grant_ace_inheritable_ro`でRead/Execute/Traverseのみ
    /// 付与し、`upper_dir`（workspace外、`--sandbox tier2a-cow`時に確保される）へ`grant_ace_inheritable_rw`を
    /// 付与する。透過的なリダイレクトはRedirector DLL（Phase 2）が担い、フックが無効・回避・
    /// 未対応APIで通過された場合もworkspace本体への書込はACLにより`ACCESS_DENIED`で
    /// fail-closeする（フックは境界にしない、D-01/D-30）。
    Cow { upper_dir: PathBuf },
}

impl WorkspaceWriteMode {
    pub fn upper_dir(&self) -> Option<&Path> {
        match self {
            WorkspaceWriteMode::DirectRw => None,
            WorkspaceWriteMode::Cow { upper_dir } => Some(upper_dir),
        }
    }
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
    /// Windowsで**このユーザーがそもそも昇格できるか**をテストから注入する
    /// （`None`なら本番同様に`privhelper::can_elevate()`を呼ぶ）。
    ///
    /// Tier2aはtraverse ACE付与・netfilterd・ETWのいずれでも昇格を要求するので、
    /// 昇格できないユーザーはTier2aへ到達できない。その人たちに残る選択肢は実質Tier0だけで、
    /// **Tier1はビルドもテストも`git commit`も通せない**（`tier1::win_restricted`の
    /// モジュールdocの表）ため代替にならない。
    ///
    /// **「昇格できない」と「今回UACを断った」を分けるためのプローブである。**
    /// 後者で降格させると、押し間違い1回で保護が黙って外れる。
    pub can_elevate_override: Option<bool>,
}

impl Probes {
    #[cfg(target_os = "linux")]
    pub fn detect() -> Self {
        let bwrap_path = which::which("bwrap").ok();
        let unprivileged_userns_enabled =
            std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
                .ok()
                .map(|s| s.trim() != "0");
        // テスト注入用のフィールド（`*_override`）は既定のままにする。**`..Self::default()`を
        // 落とすと、注入フィールドが増えるたびにLinuxビルドだけが`E0063`で落ちる**——
        // 実際にそうなっており、Windowsでしかコンパイルしていなかったので誰も気づかなかった。
        Self {
            bwrap_path,
            unprivileged_userns_enabled,
            ..Self::default()
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
///
/// **どのTierを狙うかは[`SandboxChoice`]の1引数だけが決める**（`--sandbox`のCLI表面と1:1）。
/// かつては`opt_in_tier3: bool`と`opt_in_tier1: bool`の2引数で、「両方真」という
/// 到達不能であるべき状態を分岐の順序だけが防いでいた。
///
/// | `choice` | 挙動 |
/// |---|---|
/// | [`SandboxChoice::Auto`] | Tier2aを常時プローブする（Linuxのbwrapプローブと同じ「フラグなし常時プローブ」構造）。失敗し、かつ**昇格できない**アカウントのときだけTier0へ宣言付きで降格する |
/// | [`SandboxChoice::Tier1`] | preflightを通さずTier1へ固定する |
/// | [`SandboxChoice::Tier2a`] / [`SandboxChoice::Tier2aCow`] | Tier2aをプローブし、**届かなければ拒否する**（Tier0へ降格しない） |
/// | [`SandboxChoice::Tier3`] | Tier3を優先し、不成立ならTier2aへカスケードする。それも駄目なら拒否 |
#[allow(clippy::too_many_arguments)]
pub fn select_tier(
    require: RequireSandbox,
    workspace_root: &Path,
    choice: SandboxChoice,
    passthrough: &[FsPassthrough],
    wfp_chain_pipe: Option<String>,
    write_mode: &WorkspaceWriteMode,
    // D-60: 常駐している昇格プロセスから`privhelper`を起こす手段（`None`なら`runas`＝UAC 1回）。
    // **「後から必要になった昇格」をUAC 0回で通す唯一の入口**。harness本体は起動時に1回しか
    // ここを通らず、そのとき連鎖元となるdaemonはまだ居ないので`None`を渡す。
    privhelper_launcher: Option<crate::tier2a::ChainLauncher<'_>>,
) -> Result<ShellTierSelection, TierError> {
    select_tier_with_probes(
        require,
        workspace_root,
        choice,
        passthrough,
        wfp_chain_pipe,
        write_mode,
        privhelper_launcher,
        &Probes::detect(),
    )
}

/// テスト用: プローブ結果を注入して選択ロジックのみを検証する。
#[allow(clippy::too_many_arguments)]
pub fn select_tier_with_probes(
    require: RequireSandbox,
    workspace_root: &Path,
    choice: SandboxChoice,
    passthrough: &[FsPassthrough],
    wfp_chain_pipe: Option<String>,
    write_mode: &WorkspaceWriteMode,
    privhelper_launcher: Option<crate::tier2a::ChainLauncher<'_>>,
    probes: &Probes,
) -> Result<ShellTierSelection, TierError> {
    let selection = best_effort_tier(
        workspace_root,
        choice,
        passthrough,
        wfp_chain_pipe,
        write_mode,
        privhelper_launcher,
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
/// （`harness_sandbox_vm::vmsandbox::VmSandboxConfig::default().golden_vhdx`と同一値、
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
#[allow(clippy::too_many_arguments)]
fn try_tier2a(
    workspace_root: &Path,
    passthrough: &[FsPassthrough],
    wfp_chain_pipe: Option<String>,
    write_mode: &WorkspaceWriteMode,
    privhelper_launcher: Option<crate::tier2a::ChainLauncher<'_>>,
    probes: &Probes,
) -> Result<ShellTierSelection, String> {
    match &probes.tier2a_preflight_override {
        Some(Ok(())) => Ok(ShellTierSelection::direct(ShellTier::Tier2a)),
        Some(Err(reason)) => Err(reason.clone()),
        // テスト注入が無い場合のみ実際のWin32 preflightを呼ぶ（副作用ありの重い処理を
        // 単体テストでは避ける、既存の分岐と同じ考え方）。D8: passthroughの到達不能は
        // Tier選択自体を左右せず`passthrough_warnings`として運ぶだけ。
        None => {
            match crate::tier2a::win_appcontainer::preflight_with_privhelper_launcher(
                workspace_root,
                passthrough,
                wfp_chain_pipe,
                write_mode,
                privhelper_launcher,
            ) {
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
#[allow(clippy::too_many_arguments)]
fn best_effort_tier(
    workspace_root: &Path,
    choice: SandboxChoice,
    passthrough: &[FsPassthrough],
    wfp_chain_pipe: Option<String>,
    write_mode: &WorkspaceWriteMode,
    privhelper_launcher: Option<crate::tier2a::ChainLauncher<'_>>,
    probes: &Probes,
) -> Result<ShellTierSelection, TierError> {
    match choice {
        // preflightを通さない逃がし弁。Tier2aが壊れている機械でも起動だけはできる。
        SandboxChoice::Tier1 => Ok(ShellTierSelection::direct(ShellTier::Tier1)),

        // Tier3は指定時に最優先で試す（Tier3が唯一vNIC単位で出口を強制できるTierのため、
        // 成立するなら常に最良）。不成立の場合はTier2aへカスケードする。Tier2aも不成立なら、
        // 暗黙にはTier1へ降格しない。
        SandboxChoice::Tier3 => {
            let probe_result = match &probes.tier3_available_override {
                Some(r) => r.clone(),
                None => probe_tier3_available(),
            };
            match probe_result {
                Ok(()) => Ok(ShellTierSelection::direct(ShellTier::Tier3)),
                Err(tier3_reason) => match try_tier2a(
                    workspace_root,
                    passthrough,
                    wfp_chain_pipe,
                    write_mode,
                    privhelper_launcher,
                    probes,
                ) {
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
            }
        }

        // **Tier2aを「要求」した場合は、届かなければ拒否する。**
        //
        // `Auto`との唯一の差はここで、下の`can_elevate()`による Tier0 降格を**通さない**。
        // 降格を通すと、`--sandbox tier2a-cow`を指定したのにTier0で走り、ACLを一度も
        // 触らないまま「workspaceはread-only」と宣言する——それがBUG-113そのものである。
        // 「隔離が要る」と明示した人には、黙って弱い形で走るより起動を止める方が正しい
        // （`--require-sandbox`のfail-fastと同じ思想）。
        SandboxChoice::Tier2a | SandboxChoice::Tier2aCow => match try_tier2a(
            workspace_root,
            passthrough,
            wfp_chain_pipe,
            write_mode,
            privhelper_launcher,
            probes,
        ) {
            Ok(selection) => Ok(selection),
            Err(reason) => Err(TierError::Unavailable {
                attempted: ShellTier::Tier2a.label(),
                reason: format!(
                    // **CLIフラグの綴りをここへ書かない。** この関数はライブラリの入口で、
                    // `harness-policy-editor`の記録経路のように**ユーザーが`--sandbox`を
                    // 一度も打っていない**呼び出し元がある。「指定を外せ」と案内すると、
                    // 存在しない操作を勧めることになる（`bug-pattern-rules` B-32）。
                    "{reason} (the requested isolation '{}' requires Tier2a, and a requested \
                     tier never falls back to a weaker one)",
                    choice.value_label()
                ),
            }),
        },

        // 既定パス: Tier2aを無条件にプローブする（Linuxのbwrapプローブと同じ
        // 「フラグなし常時プローブ」構造）。
        SandboxChoice::Auto => match try_tier2a(
            workspace_root,
            passthrough,
            wfp_chain_pipe,
            write_mode,
            privhelper_launcher,
            probes,
        ) {
            Ok(selection) => Ok(selection),
            // **失敗の理由を2つに分ける。**
            //
            // Tier2aはtraverse ACE付与・netfilterd・ETWのどれでも昇格を要求するので、
            // 昇格**できない**ユーザーはこの先どうやってもTier2aへ到達しない。その人に
            // 起動時エラーを返し続けるのは「harnessが使えない」と同義で、Tier1も代替に
            // ならない（ビルド・テスト・`git commit`が通らない）。Linuxが`bwrap`不在時に
            // Tier0へ**宣言付きで**降格するのと同じ形へ揃える。
            //
            // 一方、昇格**できる**のに今回失敗した（UACをキャンセルした・privhelperが
            // エラーを返した）場合は、これまでどおり起動時エラーにする。ここを降格に
            // すると、UACの押し間違い1回で保護が黙って外れる——BUG-093では実際に
            // UACのキャンセルを別の失敗と読み違えており、同じ取り違えをTier選択で
            // 繰り返さないための分岐である。
            //
            // **この降格は`Auto`にしか無い。** 明示的にTier2aを要求した指定
            // （`tier2a`/`tier2a-cow`）は上の分岐で拒否済みで、ここへは来ない。
            //
            // なお降格しても`--require-sandbox`は素通りしない（`satisfies`がTier0を
            // `write-containment`・`confidential`のどちらでも拒む）。「黙って降格しない」
            // 原則も守られている——`downgraded_from`と`reason`が`prompt.rs`経由で
            // モデルへ必ず出る。
            Err(reason) => {
                let can_elevate = probes
                    .can_elevate_override
                    .unwrap_or_else(crate::tier2a::privhelper::can_elevate);
                if can_elevate {
                    Err(TierError::Unavailable {
                        attempted: ShellTier::Tier2a.label(),
                        reason,
                    })
                } else {
                    Ok(ShellTierSelection::downgraded(
                        ShellTier::Tier2a,
                        ShellTier::Tier0,
                        format!(
                            "{reason} (this account cannot elevate, so Tier2a is out of reach; \
                             Tier1 is not a substitute because it cannot run builds, tests or git commits)"
                        ),
                    ))
                }
            }
        },
    }
}

/// Linux版。`choice`は運ぶだけで使わない——Tier1/Tier2a/Tier3はいずれもWindows専用機構で、
/// このOSにはbubblewrap（Tier2b）しか無い。**引数の形はWindows版と揃える**（揃っていないと
/// `select_tier_with_probes`が渡す引数の数が合わず、Windows以外でビルドが通らなくなる。
/// 実際に`privhelper_launcher`を受けていない期間があり、現HEADはWindows以外で
/// コンパイルできなかった）。
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn best_effort_tier(
    _workspace_root: &Path,
    _choice: SandboxChoice,
    _passthrough: &[FsPassthrough],
    _wfp_chain_pipe: Option<String>,
    _write_mode: &WorkspaceWriteMode,
    _privhelper_launcher: Option<crate::tier2a::ChainLauncher<'_>>,
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

/// その他のOS（macOS等）版。Linux版と同じ理由で、引数の形をWindows版へ揃えてある。
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
#[allow(clippy::too_many_arguments)]
fn best_effort_tier(
    _workspace_root: &Path,
    _choice: SandboxChoice,
    _passthrough: &[FsPassthrough],
    _wfp_chain_pipe: Option<String>,
    _write_mode: &WorkspaceWriteMode,
    _privhelper_launcher: Option<crate::tier2a::ChainLauncher<'_>>,
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

    /// [`FsAccess::wider`]の真理値表。**和であって「広い方を選ぶ」ではない。**
    ///
    /// `ReadWrite`と`ReadExec`は互いに包含しないので、どちらかを選ぶ規則では必ず片方の
    /// 権限が落ちる。落ちた側は実行時の`Access is denied`としてしか現れない。
    #[test]
    fn wider_takes_the_union_and_is_commutative() {
        use FsAccess::*;
        let table = [
            (Read, Read, Read),
            (Read, ReadWrite, ReadWrite),
            (Read, ReadExec, ReadExec),
            (Read, ReadWriteExec, ReadWriteExec),
            (ReadWrite, ReadExec, ReadWriteExec),
            (ReadWrite, ReadWriteExec, ReadWriteExec),
            (ReadExec, ReadWriteExec, ReadWriteExec),
            (ReadWrite, ReadWrite, ReadWrite),
            (ReadExec, ReadExec, ReadExec),
            (ReadWriteExec, ReadWriteExec, ReadWriteExec),
        ];
        for (a, b, expected) in table {
            assert_eq!(a.wider(b), expected, "{a:?}.wider({b:?})");
            assert_eq!(b.wider(a), expected, "{b:?}.wider({a:?}) must be the same");
        }
    }

    /// 述語は和の値でも成り立つ。`is_read_write`は台帳の`writable`・到達性プローブのモード・
    /// `--sandbox tier2a-cow`のcapture判定という**3つの分岐**を決めているので、ここが偽だと和を取った途端に
    /// 書込の扱いが静かに変わる。
    #[test]
    fn the_combined_value_reports_both_write_and_exec() {
        assert!(FsAccess::ReadWriteExec.is_read_write());
        assert!(FsAccess::ReadWriteExec.is_exec());
        assert!(FsAccess::ReadWrite.is_read_write());
        assert!(!FsAccess::ReadWrite.is_exec());
        assert!(FsAccess::ReadExec.is_exec());
        assert!(!FsAccess::ReadExec.is_read_write());
        assert!(!FsAccess::Read.is_read_write());
        assert!(!FsAccess::Read.is_exec());
    }

    /// 設定語彙（3値）からの変換は全単射的で、和の値は**設定からは作られない**
    /// （`fs.read_write_exec`という設定キーは無い）。
    #[test]
    fn settings_vocabulary_never_produces_the_combined_value() {
        for access in [
            harness_config::FsAccess::Read,
            harness_config::FsAccess::ReadWrite,
            harness_config::FsAccess::ReadExec,
        ] {
            assert_ne!(
                FsAccess::from_settings(access),
                FsAccess::ReadWriteExec,
                "the union may only come from combining two declarations"
            );
        }
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
            SandboxChoice::Auto,
            &[],
            None,
            &WorkspaceWriteMode::DirectRw,
            None,
            &probes,
        )
        .unwrap();
        assert_eq!(selection.tier, ShellTier::Tier2a);
        assert!(selection.downgraded_from.is_none());
        assert!(!selection.is_unisolated());
    }

    /// 既定パスでTier2a preflightが失敗し、かつ**このユーザーは昇格できる**とき
    /// （＝UACを断った・privhelperが失敗した等の一時的な失敗）は、起動時エラーにする。
    /// ここを降格にすると、UACの押し間違い1回で保護が黙って外れる。
    ///
    /// `can_elevate_override`を明示するのは、**テストの結果を実行ホストの権限に
    /// 依存させないため**である。省略すると開発機（管理者）では通り、非管理者の
    /// CIでは別の分岐に入る、という環境依存のテストになる（B-08）。
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_default_errors_when_tier2a_fails_but_the_user_could_have_elevated() {
        let probes = Probes {
            tier2a_preflight_override: Some(Err("acl grant failed".to_string())),
            can_elevate_override: Some(true),
            ..Default::default()
        };
        let err = select_tier_with_probes(
            RequireSandbox::None,
            &empty_root(),
            SandboxChoice::Auto,
            &[],
            None,
            &WorkspaceWriteMode::DirectRw,
            None,
            &probes,
        )
        .unwrap_err();
        assert!(matches!(err, TierError::Unavailable { .. }));
    }

    /// **昇格できないユーザーは、宣言付きでTier0へ降格する。**
    ///
    /// Tier2aはtraverse ACE付与・netfilterd・ETWのいずれでも昇格を要求するので、
    /// 昇格できない人はどうやってもTier2aへ到達しない。Tier1も代替にならない
    /// （ビルド・テスト・`git commit`が通らない）ため、起動時エラーを返し続けるのは
    /// 「使えない」と同義になる。Linuxが`bwrap`不在時にTier0へ降格するのと同じ形。
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_downgrades_to_tier0_when_the_user_cannot_elevate_at_all() {
        let probes = Probes {
            tier2a_preflight_override: Some(Err("acl grant failed".to_string())),
            can_elevate_override: Some(false),
            ..Default::default()
        };
        let selection = select_tier_with_probes(
            RequireSandbox::None,
            &empty_root(),
            SandboxChoice::Auto,
            &[],
            None,
            &WorkspaceWriteMode::DirectRw,
            None,
            &probes,
        )
        .expect("a non-elevatable account must still be able to start");

        assert_eq!(selection.tier, ShellTier::Tier0);
        // **降格は必ず宣言する。** `downgraded_from`と`reason`は`prompt.rs`が
        // 「本来Tier2aを試したがTier0へ降格した」としてモデルへ出す唯一の材料で、
        // どちらかが欠けると「黙って保護が外れた」のと区別が付かない（B-11）。
        assert_eq!(selection.downgraded_from, Some(ShellTier::Tier2a));
        let reason = selection
            .reason
            .as_deref()
            .expect("a downgrade without a reason is a silent downgrade");
        assert!(
            reason.contains("acl grant failed"),
            "the original preflight failure must survive into the reason: {reason}"
        );
        assert!(
            reason.contains("cannot elevate"),
            "the reason must say why we stopped trying, not just what failed: {reason}"
        );
    }

    /// 降格しても`--require-sandbox`は素通りしない。Tier0は`write-containment`を
    /// 満たさないので、隔離を要求した起動は依然として失敗する（`satisfies`）。
    /// **「既定を緩めた」と「要求を無視するようになった」は別**で、後者になっていないことを固定する。
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_tier0_downgrade_still_fails_require_sandbox() {
        let probes = Probes {
            tier2a_preflight_override: Some(Err("acl grant failed".to_string())),
            can_elevate_override: Some(false),
            ..Default::default()
        };
        let err = select_tier_with_probes(
            RequireSandbox::WriteContainment,
            &empty_root(),
            SandboxChoice::Auto,
            &[],
            None,
            &WorkspaceWriteMode::DirectRw,
            None,
            &probes,
        )
        .unwrap_err();
        assert!(
            matches!(err, TierError::Insufficient { .. }),
            "an explicit sandbox requirement must not be silently downgraded away: {err:?}"
        );
    }

    /// 昇格できないユーザーでも、**Tier2aが成功するなら降格しない**。
    /// 新しい分岐は失敗経路にだけ効くもので、成功経路を触っていないことを固定する
    /// （B-06: 変更が届く範囲を「効かせたい所だけ」に限定できているか）。
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_does_not_downgrade_when_tier2a_succeeds_even_if_elevation_is_unavailable() {
        let probes = Probes {
            tier2a_preflight_override: Some(Ok(())),
            can_elevate_override: Some(false),
            ..Default::default()
        };
        let selection = select_tier_with_probes(
            RequireSandbox::None,
            &empty_root(),
            SandboxChoice::Auto,
            &[],
            None,
            &WorkspaceWriteMode::DirectRw,
            None,
            &probes,
        )
        .unwrap();
        assert_eq!(selection.tier, ShellTier::Tier2a);
        assert_eq!(selection.downgraded_from, None);
    }

    /// **`tier2a`/`tier2a-cow`は、昇格できないアカウントでもTier0へ降格しない。**
    ///
    /// この2値の存在理由がここである。`Auto`は「昇格できないなら仕方ない」とTier0へ
    /// 宣言付きで降ろすが、Tier2aを**明示的に要求した**人にその逃げ道を通すと、
    /// `--sandbox tier2a-cow`と打ったのにACLを一度も触らないまま
    /// 「workspaceはread-only」とモデルへ宣言することになる（BUG-113）。
    ///
    /// `can_elevate_override: Some(false)`を明示して**`Auto`が降格する条件をそのまま**
    /// 与えているのが肝で、これを`true`にすると`Auto`でも`Err`になるので何も測れない。
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_required_tier2a_refuses_instead_of_downgrading_when_elevation_is_impossible() {
        for choice in [SandboxChoice::Tier2a, SandboxChoice::Tier2aCow] {
            let probes = Probes {
                tier2a_preflight_override: Some(Err("acl grant failed".to_string())),
                // **`Auto`ならTier0へ降格する条件**（下の対照テストがそれを固定している）。
                can_elevate_override: Some(false),
                ..Default::default()
            };
            let err = select_tier_with_probes(
                RequireSandbox::None,
                &empty_root(),
                choice,
                &[],
                None,
                &WorkspaceWriteMode::DirectRw,
                None,
                &probes,
            )
            .unwrap_err();
            let TierError::Unavailable { attempted, reason } = err else {
                panic!(
                    "--sandbox {} must refuse to start, not downgrade",
                    choice.value_label()
                );
            };
            assert_eq!(attempted, ShellTier::Tier2a.label());
            assert!(
                reason.contains("acl grant failed"),
                "the original preflight failure must survive into the reason: {reason}"
            );
            // **何を指定したせいで降格しなかったのかを名指しする。** ここが無いと、
            // 同じ状況で`Auto`なら起動できることに気付けない（B-32: 理由を読ませる）。
            assert!(
                reason.contains(choice.value_label()),
                "the reason must name the --sandbox value that forbade the fallback: {reason}"
            );
        }
    }

    /// 上の対照。**同じプローブ**（preflight失敗＋昇格不可）で`Auto`はTier0へ降格する
    /// ——差が`choice`だけであることを固定しないと、上のテストは「preflightが失敗すれば
    /// 常に`Err`」でも緑になる（`test-logic-rules`: 禁止側と許可側を対にする）。
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_auto_still_downgrades_under_the_very_probes_that_make_tier2a_refuse() {
        let probes = Probes {
            tier2a_preflight_override: Some(Err("acl grant failed".to_string())),
            can_elevate_override: Some(false),
            ..Default::default()
        };
        let selection = select_tier_with_probes(
            RequireSandbox::None,
            &empty_root(),
            SandboxChoice::Auto,
            &[],
            None,
            &WorkspaceWriteMode::DirectRw,
            None,
            &probes,
        )
        .expect("auto must keep the Tier0 escape hatch for accounts that cannot elevate");
        assert_eq!(selection.tier, ShellTier::Tier0);
        assert_eq!(selection.downgraded_from, Some(ShellTier::Tier2a));
    }

    /// 許可側: preflightが通るなら`tier2a`/`tier2a-cow`はTier2aへそのまま着地する
    /// （新しい拒否分岐が成功経路を巻き込んでいないこと、B-06）。
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_required_tier2a_lands_on_tier2a_when_preflight_succeeds() {
        for choice in [SandboxChoice::Tier2a, SandboxChoice::Tier2aCow] {
            let probes = Probes {
                tier2a_preflight_override: Some(Ok(())),
                can_elevate_override: Some(false),
                ..Default::default()
            };
            let selection = select_tier_with_probes(
                RequireSandbox::None,
                &empty_root(),
                choice,
                &[],
                None,
                &WorkspaceWriteMode::DirectRw,
                None,
                &probes,
            )
            .unwrap_or_else(|e| panic!("--sandbox {} must start: {e}", choice.value_label()));
            assert_eq!(selection.tier, ShellTier::Tier2a);
            assert_eq!(selection.downgraded_from, None);
        }
    }

    /// **`tier2a`を要求してもTier3へは行かない。** Tier3の可用性チェックが成功する状況を
    /// 注入しても、選んだのはTier2aなのでTier2aへ着地する（`Tier3`だけがTier3を狙う、
    /// 既存の`windows_without_opt_in_never_selects_tier3`と対称）。
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_required_tier2a_never_selects_tier3() {
        let probes = Probes {
            tier3_available_override: Some(Ok(())),
            tier2a_preflight_override: Some(Ok(())),
            ..Default::default()
        };
        let selection = select_tier_with_probes(
            RequireSandbox::None,
            &empty_root(),
            SandboxChoice::Tier2a,
            &[],
            None,
            &WorkspaceWriteMode::DirectRw,
            None,
            &probes,
        )
        .unwrap();
        assert_eq!(selection.tier, ShellTier::Tier2a);
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
            SandboxChoice::Tier1,
            &[],
            None,
            &WorkspaceWriteMode::DirectRw,
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
            SandboxChoice::Tier1,
            &[],
            None,
            &WorkspaceWriteMode::DirectRw,
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
            SandboxChoice::Tier1,
            &[],
            None,
            &WorkspaceWriteMode::DirectRw,
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
            SandboxChoice::Auto,
            &[],
            None,
            &WorkspaceWriteMode::DirectRw,
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
            scope: GrantScope::Recursive,
        }];
        let selection = select_tier_with_probes(
            RequireSandbox::None,
            &empty_root(),
            SandboxChoice::Auto,
            &passthrough,
            None,
            &WorkspaceWriteMode::DirectRw,
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
            // 昇格できるユーザーを固定する（できない場合はTier0へ降格し、`satisfies`が
            // `Insufficient`で弾く——それは別のテストが見ている）。
            can_elevate_override: Some(true),
            ..Default::default()
        };
        let err = select_tier_with_probes(
            RequireSandbox::Confidential,
            &empty_root(),
            SandboxChoice::Auto,
            &[],
            None,
            &WorkspaceWriteMode::DirectRw,
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
            SandboxChoice::Tier3,
            &[],
            None,
            &WorkspaceWriteMode::DirectRw,
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
            SandboxChoice::Tier3,
            &[],
            None,
            &WorkspaceWriteMode::DirectRw,
            None,
            &probes,
        )
        .unwrap();
        assert_eq!(selection.tier, ShellTier::Tier3);
    }

    /// `--sandbox tier3`でTier3が不成立でもTier2aへカスケードする。Tier2a preflightが
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
            SandboxChoice::Tier3,
            &[],
            None,
            &WorkspaceWriteMode::DirectRw,
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
            SandboxChoice::Tier3,
            &[],
            None,
            &WorkspaceWriteMode::DirectRw,
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
            can_elevate_override: Some(true),
            ..Default::default()
        };
        let err = select_tier_with_probes(
            RequireSandbox::None,
            &empty_root(),
            SandboxChoice::Auto,
            &[],
            None,
            &WorkspaceWriteMode::DirectRw,
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
            SandboxChoice::Auto,
            &[],
            None,
            &WorkspaceWriteMode::DirectRw,
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
            SandboxChoice::Auto,
            &[],
            None,
            &WorkspaceWriteMode::DirectRw,
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
            SandboxChoice::Auto,
            &[],
            None,
            &WorkspaceWriteMode::DirectRw,
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
            SandboxChoice::Auto,
            &[],
            None,
            &WorkspaceWriteMode::DirectRw,
            None,
            &probes,
        )
        .unwrap_err();
        assert!(matches!(err, TierError::Insufficient { .. }));
    }
}
