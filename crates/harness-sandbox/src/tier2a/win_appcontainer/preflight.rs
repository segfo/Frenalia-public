//! Tier2a起動前の実機プローブ（`preflight`）。
//!
//! ワークスペース・fs passthrough・`.harness/**`制御面のそれぞれについて、実際に
//! AppContainer子を起動してFS I/Oを試し、Tier2aを選んでよいかを判定する。判定材料の
//! 収集が責務であり、ACLの付与/撤収そのものは`acl_grant`/`revoke`に委ねる。

use super::*;

/// FS I/Oプローブ失敗を表す固有の終了コード（`spawn`自体の失敗や、シェル解決の失敗と
/// 区別するためのマーカー。`smoke_test_spawn`と`preflight`の理由文字列組立の両方で使う）。
const FS_PROBE_DENIED_EXIT_CODE: i32 = 3;

/// `probe_dir`（preflightが事前に作成・ACL付与済みのワークスペース内一時ディレクトリ）へ
/// 実際に一時ファイルを作成・読取・削除するPowerShellコマンド。`exit 0`だけを試す旧実装は
/// FileSystemプロバイダの初期化失敗があってもプロセス自体は正常終了してしまい偽陽性となる
/// （`docs/phases/foundation/M12-shell-isolation-tiers.md`追記3参照）ため、実FS I/Oまで
/// 一括で試し、成否を終了コードに反映させる。
const FS_IO_PROBE_COMMAND: &str = "\
    $ErrorActionPreference = 'Stop'; \
    try { \
        $p = Join-Path $env:HARNESS_PROBE_DIR ([Guid]::NewGuid().ToString() + '.tmp'); \
        New-Item -ItemType File -Path $p -Force | Out-Null; \
        Get-Content -LiteralPath $p | Out-Null; \
        Remove-Item -LiteralPath $p -Force; \
        exit 0 \
    } catch { \
        exit 3 \
    }";

const CONTROL_DIR_WRITE_DENY_PROBE_COMMAND: &str = "\
    $ErrorActionPreference = 'Stop'; \
    $p = Join-Path $env:HARNESS_CONTROL_DIR ([Guid]::NewGuid().ToString() + '.tmp'); \
    try { \
        New-Item -ItemType File -Path $p -Force | Out-Null; \
        Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue; \
        exit 4 \
    } catch { \
        exit 0 \
    }";

/// `workspace_cap`は、workspaceツリーのACEの主体になったcapability SID（D-54）。本番の
/// `run_shell`と**同じcapability構成**で起動しないとプローブの意味が無いので、`preflight`は
/// ここへ必ず`Some`を渡す（`None`は自前でpackage SID宛のACEを付ける実機テスト専用）。
pub(crate) fn smoke_test_spawn(
    sid: PSID,
    workspace_cap: Option<PSID>,
    workspace_root: &Path,
    probe_dir: &Path,
) -> Result<(), AppContainerError> {
    // 本番run_shellと同じシェル解決を使い、そのシェルがゼロcapabilityのAppContainer内で
    // 実際に起動でき、かつワークスペース内のファイルI/Oまで通ることを確認する
    // （エイリアス回避は`resolve_shell`の責務）。
    let (shell, _) = resolve_shell();
    let mut env = crate::secret_env::build_child_env();
    env.push((
        "HARNESS_PROBE_DIR".to_string(),
        probe_dir.to_string_lossy().into_owned(),
    ));
    let child = spawn_with_workspace(
        &shell,
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            FS_IO_PROBE_COMMAND,
        ],
        workspace_root,
        &env,
        false,
        sid,
        NetworkCapability::Deny,
        None,
        workspace_cap,
    )
    .map_err(|e| AppContainerError::Preflight(format!("shell could not start: {e}")))?;
    let (_, _, code) = child
        .write_stdin_read_output_and_wait(None)
        .map_err(|e| AppContainerError::Preflight(format!("shell could not start: {e}")))?;
    if code == FS_PROBE_DENIED_EXIT_CODE {
        return Err(AppContainerError::Preflight(
            "workspace FS I/O denied inside AppContainer (likely missing traverse ACE on \
             drive root; non-admin cannot grant; see \
             docs/phases/foundation/M12-shell-isolation-tiers.md 追記2/3)"
                .to_string(),
        ));
    }
    if code != 0 {
        return Err(AppContainerError::Preflight(format!(
            "smoke test command exited with unexpected code {code}"
        )));
    }
    Ok(())
}

fn smoke_test_harness_control_write_denied(
    sid: PSID,
    workspace_cap: Option<PSID>,
    workspace_root: &Path,
) -> Result<(), AppContainerError> {
    let control_dir = workspace_root.join(".harness");
    if !control_dir.exists() {
        return Ok(());
    }

    let (shell, _) = resolve_shell();
    let mut env = crate::secret_env::build_child_env();
    env.push((
        "HARNESS_CONTROL_DIR".to_string(),
        control_dir.to_string_lossy().into_owned(),
    ));
    // D-54: workspace capabilityを積んだ状態で試す。積まずに拒否されても
    // 「`.harness/`の保護が効いた」ことの証明にならない（workspaceごと届いていないだけ）。
    let child = spawn_with_workspace(
        &shell,
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            CONTROL_DIR_WRITE_DENY_PROBE_COMMAND,
        ],
        workspace_root,
        &env,
        false,
        sid,
        NetworkCapability::Deny,
        None,
        workspace_cap,
    )
    .map_err(|e| {
        AppContainerError::Preflight(format!(
            ".harness write-deny probe shell could not start: {e}"
        ))
    })?;
    let (_, _, code) = child.write_stdin_read_output_and_wait(None).map_err(|e| {
        AppContainerError::Preflight(format!(
            ".harness write-deny probe shell could not start: {e}"
        ))
    })?;
    if code == 0 {
        return Ok(());
    }
    if code == 4 {
        return Err(AppContainerError::Preflight(
            ".harness remained writable inside AppContainer after control-plane ACL protection"
                .to_string(),
        ));
    }
    Err(AppContainerError::Preflight(format!(
        ".harness write-deny probe exited with unexpected code {code}"
    )))
}

/// fs passthrough（D-13）の到達性プローブ用コマンド。`FS_IO_PROBE_COMMAND`と同じ
/// 「実I/Oを試し終了コードで判定する」設計だが、catchブロックで例外メッセージをstdoutへ
/// 出す点が異なる（D9: 到達不能時に生エラーを呼び出し元へ返すため）。
const FS_PASSTHROUGH_RO_PROBE_COMMAND: &str = "\
    $ErrorActionPreference = 'Stop'; \
    try { \
        Get-ChildItem -LiteralPath $env:HARNESS_PASSTHROUGH_DIR -ErrorAction Stop | Out-Null; \
        exit 0 \
    } catch { \
        Write-Output $_.Exception.Message; \
        exit 3 \
    }";

/// ro版と同じ設計のrw版（一時ファイルの作成→読取→削除まで試す）。
const FS_PASSTHROUGH_RW_PROBE_COMMAND: &str = "\
    $ErrorActionPreference = 'Stop'; \
    try { \
        $p = Join-Path $env:HARNESS_PASSTHROUGH_DIR ([Guid]::NewGuid().ToString() + '.harness-probe.tmp'); \
        New-Item -ItemType File -Path $p -Force | Out-Null; \
        Get-Content -LiteralPath $p | Out-Null; \
        Remove-Item -LiteralPath $p -Force; \
        exit 0 \
    } catch { \
        Write-Output $_.Exception.Message; \
        exit 3 \
    }";

/// D9診断の材料。**Win32の読み取り結果をここへ写してから判定へ渡す**ことで、判定側
/// （[`describe_passthrough_chain`]）を実機・管理者権限なしに全数テストできる形に保つ
/// （`docs/CODE-STRUCTURE-RULES.md`規則3、先行例は`session_profile::plan_reclaim`）。
///
/// **`leaf`と`ancestors`でSIDの系統が違う**のが本型の存在理由である（D-37、BUG-058）。
pub(crate) struct PassthroughChainFacts {
    /// leaf（fs-allowで許可したパス自身）が**セッションpackage SID**から見て持つマスク。
    pub(crate) leaf_mask: Option<u32>,
    /// leafに必要なマスク（[`required_passthrough_mask`]）。
    pub(crate) required_leaf_mask: u32,
    /// leafの親からドライブルートまでの祖先が、**capability SID**から見て持つマスク
    /// （浅い方から深い方の順、`grant_traverse_chain`と同じ列挙順）。
    pub(crate) ancestors: Vec<(std::path::PathBuf, Option<u32>)>,
}

const TRAVERSE_REQUIRED_MASK: u32 = FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0;

/// D9の診断文を組み立てる（純粋関数）。
///
/// **祖先とleafは別の主体が別のACEで賄っている**（D-37）。祖先の通過権は全セッションで
/// 共有する永続capability SID（`traverse_capability_sid`）が持ち、leafへの読み書きは
/// そのセッション限りのpackage SIDが持つ。したがって診断も2系統に分けなければならない
/// ——BUG-058以前は両方をセッションSIDで見ていたため、traverseが正常でも全祖先を
/// 「ACEが無い」と報告していた。
pub(crate) fn describe_passthrough_chain(
    path: &Path,
    raw_message: &str,
    facts: &PassthroughChainFacts,
) -> String {
    let missing_ancestors: Vec<String> = facts
        .ancestors
        .iter()
        .filter(|(_, mask)| !mask.is_some_and(|m| m & TRAVERSE_REQUIRED_MASK == TRAVERSE_REQUIRED_MASK))
        .map(|(node, mask)| match mask {
            Some(_) => format!(
                "{} (has a traverse-capability ACE but missing FILE_TRAVERSE|FILE_READ_ATTRIBUTES)",
                node.display()
            ),
            None => format!(
                "{} (no ACE for the traverse capability SID)",
                node.display()
            ),
        })
        .collect();

    let leaf_problem = match facts.leaf_mask {
        Some(mask) if mask & facts.required_leaf_mask == facts.required_leaf_mask => None,
        Some(mask) => Some(format!(
            "the target itself carries a session SID ACE with mask {mask:#010x}, which does not \
             cover the requested {:#010x}",
            facts.required_leaf_mask
        )),
        None => Some("the target itself carries no ACE for this session's package SID".to_string()),
    };

    let mut diagnosis = Vec::new();
    if !missing_ancestors.is_empty() {
        diagnosis.push(format!(
            "missing traverse ACE (traverse capability SID) on {} ancestor node(s): {} -- fix \
             (admin, one-time, grants the whole chain in one UAC prompt): \
             harness fs grant-traverse {}",
            missing_ancestors.len(),
            missing_ancestors.join(", "),
            path.display()
        ));
    }
    if let Some(leaf) = leaf_problem {
        diagnosis.push(leaf);
    }

    if diagnosis.is_empty() {
        return format!(
            "fs-allow {} : unreachable inside AppContainer (probe error: {raw_message}); \
             the target's own session SID ACE and all ancestor traverse ACEs (up to the drive \
             root) look fine, cause unknown (path may not exist, or a read-only file attribute \
             is blocking a :rw request)",
            path.display()
        );
    }
    format!(
        "fs-allow {} : unreachable inside AppContainer (probe error: {raw_message}) -- \
         diagnosis: {} (see docs/phases/foundation/M12-shell-isolation-tiers.md 追記10・追記13, \
         and docs/bugs/BUG-058.md for why the two SIDs are checked separately)",
        path.display(),
        diagnosis.join("; ")
    )
}

/// D9: passthroughルートが到達不能だったときの原因診断。生エラーメッセージに加え、
/// **leafの親からドライブルートまでの全祖先**（`grant_traverse_chain`と同じ列挙順）の
/// traverse ACE有無と、**leaf自身**のアクセス権を実地チェックし、欠けている方を名指しする。
/// 従来はドライブルート1箇所しか見ていなかったが、`C:\Users\<user>\.cargo`のように中間の
/// 祖先（`C:\Users`・`C:\Users\<user>`）が欠けているケースを診断できなかった
/// （`docs/phases/foundation/M12-shell-isolation-tiers.md`追記10で判明）。
///
/// **`session_sid`と`traverse_sid`を分けて受ける**のはD-37以降の必然である（BUG-058）。
/// Win32の読み取りだけをここで行い、判定は[`describe_passthrough_chain`]へ委ねる。
fn diagnose_unreachable_passthrough(
    session_sid: PSID,
    traverse_sid: PSID,
    path: &Path,
    access: FsAccess,
    raw_message: &str,
) -> String {
    // leaf自身は列挙から外す（`ancestors()`の先頭は`path`自身）。leafが持つべきなのは
    // traverse ACEではなくセッションSIDのアクセス権なので、同じ基準で見てはいけない。
    let mut ancestors: Vec<std::path::PathBuf> = path
        .parent()
        .into_iter()
        .flat_map(|parent| parent.ancestors().map(|p| p.to_path_buf()))
        .collect();
    ancestors.reverse();

    let facts = PassthroughChainFacts {
        leaf_mask: sid_ace_mask(path, session_sid).unwrap_or(None),
        required_leaf_mask: required_passthrough_mask(access),
        ancestors: ancestors
            .into_iter()
            .map(|node| {
                let mask = sid_ace_mask(&node, traverse_sid).unwrap_or(None);
                (node, mask)
            })
            .collect(),
    };
    describe_passthrough_chain(path, raw_message, &facts)
}

/// D8: passthroughルート1件へコンテナ内から実I/Oプローブ（疎通テスト）を行う。到達可なら
/// `None`、到達不能なら診断メッセージ（D9）を返す。全体のTier選択には影響しない
/// （`preflight`が結果を警告一覧として集約するだけで、壊れた穴以外は継続する）。
///
/// `sid`は子プロセスを起動するセッションpackage SID、`traverse_sid`は祖先チェーンの
/// 通過権を持つcapability SID。**両方を受けるのはD9診断が2系統を区別するため**（BUG-058）。
pub(crate) fn probe_passthrough(
    sid: PSID,
    traverse_sid: PSID,
    workspace_cap: Option<PSID>,
    workspace_root: &Path,
    fp: &FsPassthrough,
) -> Option<String> {
    let (shell, _) = resolve_shell();
    let mut env = crate::secret_env::build_child_env();
    env.push((
        "HARNESS_PASSTHROUGH_DIR".to_string(),
        fp.path.to_string_lossy().into_owned(),
    ));
    let command = if fp.access.is_read_write() {
        FS_PASSTHROUGH_RW_PROBE_COMMAND
    } else {
        FS_PASSTHROUGH_RO_PROBE_COMMAND
    };
    // 子のcwdは`workspace_root`なので、workspace capability（D-54）が無いと**プローブ対象の
    // 手前で**起動に失敗する。穴そのものの到達性を測るために、本番と同じ構成で起動する。
    let child = match spawn_with_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", command],
        workspace_root,
        &env,
        false,
        sid,
        NetworkCapability::Deny,
        None,
        workspace_cap,
    ) {
        Ok(child) => child,
        Err(e) => {
            return Some(format!(
                "fs-allow {} : probe could not start: {e}",
                fp.path.display()
            ));
        }
    };
    match child.write_stdin_read_output_and_wait(None) {
        Ok((_, _, 0)) => None,
        Ok((stdout, _, _code)) => Some(diagnose_unreachable_passthrough(
            sid,
            traverse_sid,
            &fp.path,
            fp.access,
            stdout.trim(),
        )),
        Err(e) => Some(format!(
            "fs-allow {} : probe failed: {e}",
            fp.path.display()
        )),
    }
}

/// harness起動時に1回だけ呼ぶ。プロファイル作成→ACL付与→起動smokeテストの一連を行い、
/// いずれか失敗したら理由文字列を返す（`shell_tier::best_effort_tier`がTier1への降格理由
/// としてそのまま使う）。判断は実行前に完結させ、`run_shell`個々の呼び出し中には降格ロジックを
/// 一切持たせない（非冪等コマンドの二重実行を避けるための意図的判断）。
///
/// `passthrough`（D-13、fs passthrough allowlist）は各ルートへACEを付与したうえで到達性を
/// プローブする（D8）。到達不能な穴は`preflight`全体を失敗させず、戻り値の警告一覧に
/// 診断メッセージ（D9）を積むだけに留める（壊れた穴があってもworkspaceと他の穴は動き続ける）。
/// `preflight`の戻り値。`warnings`はD8の到達不能診断（従来どおり）、`granted_passthrough`は
/// **実際にACEが付与された（既存で十分だった場合・部分的にしか適用できなかった場合を含む）**
/// passthroughルートの一覧（`(path, writable)`）。呼び出し側（`harness-cli`の台帳記録）は
/// この一覧だけを台帳へ書くことで、「幻の台帳エントリ」（実際には`ACCESS_DENIED`で失敗した
/// のに記録だけ残る）を防ぐ。逆に、rootへのACE付与自体は成功したが子孫の一部
/// （TrustedInstaller所有等）で失敗した「部分適用」ケースは、`sid_ace_mask`でrootを権威的に
/// プローブして`Ok`/`Err`によらず記録する（BUG-017: 記録漏れが「撤収経路の無い孤立ACE」を
/// 生むため、幻の台帳エントリより孤立ACEの方を重く見て記録側に倒す）。
#[derive(Debug)]
pub struct PreflightOutcome {
    pub warnings: Vec<String>,
    pub denied_passthrough: Vec<(std::path::PathBuf, String, String)>,
    pub granted_passthrough: Vec<(std::path::PathBuf, bool)>,
    /// `preflight`が特権分離ヘルパーへ`GrantFsAllow`を委譲する経路を実際に通り、その際
    /// `wfp_chain_pipe`が`Some`だったため「処理完了後に`harness-netfilterd`を連鎖起動してほしい」
    /// という指示を実際に添えたかどうか（`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`付録D
    /// シナリオ(A)）。連鎖起動の**成否**までは追跡しない（ヘルパー側はベストエフォートでログのみ、
    /// `privhelper.rs`の`serve()`参照）——呼び出し元は、この値が`true`ならnetfilterdとの
    /// ハンドシェイクを試み、タイムアウトすれば「今回は使えなかった」として扱えばよい。
    /// `false`の場合（`needs_elevation`が空だった、または本体が既に管理者で直接付与した等）は
    /// 連鎖起動を試みていないため、呼び出し元はシナリオ(B)（`NetfilterHandle::start`直接起動）へ
    /// フォールバックする必要がある。
    pub netfilterd_chain_attempted: bool,
}

/// `fp`が要求するアクセスのうち、`preflight`が「既に十分」と判定するために必要な最小マスク
/// （`grant_ace`/`grant_ace_ro`が実際に付与するマスクと同じ論理和。継承フラグの相違までは
/// 見ない、`grant_ace_mask`の冪等スキップと同じ考え方）。
fn required_passthrough_mask(access: FsAccess) -> u32 {
    fs_access_mask(access)
}

/// `preflight`のfs-allow昇格結果（`granted`パス一覧、`(path, reason)`失敗一覧）。
type FsAllowElevationOutcome = (Vec<std::path::PathBuf>, Vec<(std::path::PathBuf, String)>);

/// BUG-059の回収: redirector DLLに残った、**生存していないセッション**宛のACEを剥がす。
///
/// 付与側（下記CoW分岐）に保険を入れて新規発生は止めたが、記録漏れの間に積み上がったACEは
/// 台帳に無いため`gc_dead_sessions`の撤収対象に入らない（実機に4件残留していた）。DLLは
/// harness自身の実行ファイルの隣という**既知の固定パス**なので、そこだけを直接掃く。
///
/// 失敗しても起動は止めない——これは後始末であって境界ではなく、ここで`Err`を返すと
/// 「掃除できないマシンではTier2aが起動できない」という筋の悪い依存を作る。
fn sweep_stale_redirector_dll_aces() {
    let live = crate::tier2a::session_profile::live_profile_names();
    for dll in redirector_dll_paths() {
        match revoke_stale_appcontainer_aces(&dll, &live) {
            Ok(removed) if !removed.is_empty() => {
                eprintln!(
                    "harness: removed {} stale AppContainer ACE(s) left on {} by sessions that are \
                     no longer running (see docs/bugs/BUG-059.md)",
                    removed.len(),
                    dll.display()
                );
            }
            Ok(_) => {}
            Err(e) => eprintln!(
                "harness: could not sweep stale AppContainer ACEs on {}: {e}",
                dll.display()
            ),
        }
    }
}

/// プロセスのカレントディレクトリにできるパスの実測上限（文字数）。
///
/// **`CreateProcessW`が新しいプロセスへ与えるカレントディレクトリは`MAX_PATH`から逃げられません。**
/// 末尾の区切りとNUL終端の分を含めて260に収まる必要がある＝ディレクトリ自体は258文字まで。
///
/// この開発機での実測（`LongPathsEnabled=1`、2026-08-06。[BUG-068](../../../../docs/bugs/BUG-068.md)）:
///
/// | 操作 | `longPathAware`マニフェスト無し | 有り |
/// |---|---|---|
/// | `SetCurrentDirectoryW`（自プロセス、295文字） | `ERROR_FILENAME_EXCED_RANGE`(206) | **成功** |
/// | `CreateProcessW`＋`lpCurrentDirectory`（295文字） | `ERROR_DIRECTORY`(267) | `ERROR_DIRECTORY`(267) |
/// | `CreateProcessW`＋継承（親のcwdが295文字） | （前提不成立） | `ERROR_INVALID_PARAMETER`(87) |
///
/// つまり**マニフェストのオプトインは自プロセスのcwdしか解放しません**（Microsoftの
/// 「最大ファイルパスの制限」ページが挙げる対象一覧にも`SetCurrentDirectoryW`はあるが
/// `CreateProcessW`は無い）。明示的に渡しても親から継承させても、子プロセスへ260超のcwdは
/// 与えられないので、harness側にマニフェストを足しても**この制限は変わりません**（実測済み。
/// 再検討する前にこの表を見ること）。境界は258文字で、259文字から失敗します。
///
/// `\\?\`前置も解決になりません。285文字のverbatim形も同じ267で失敗し、短いパスですら
/// verbatim形のcwdは`cmd.exe`が「UNCパスはサポートされません」としてWindowsディレクトリへ
/// 黙って切り替えます（＝verbatimをcwdに使ってはいけない）。
const MAX_CHILD_CWD_LEN: usize = 258;

/// workspaceを子プロセスのカレントディレクトリにできるか（[BUG-068](../../../../docs/bugs/BUG-068.md)の
/// 追加検証で判明した、harnessではなくWindows側の限界）。
///
/// 超えている場合、`smoke_test_spawn`が`CreateProcessW: ディレクトリ名が無効です (0x8007010B)`で
/// 落ちます——**存在する正しいディレクトリなのに「無効」と言われる**ので、原因に辿り着くのが
/// 難しい。ACEを付ける前にここで止め、理由と回避策を名指しします。
fn check_workspace_usable_as_child_cwd(workspace_root: &Path) -> Result<(), AppContainerError> {
    let len = workspace_root.to_string_lossy().encode_utf16().count();
    if len <= MAX_CHILD_CWD_LEN {
        return Ok(());
    }
    Err(AppContainerError::Preflight(format!(
        "the workspace path is {len} characters long; Windows cannot use a directory longer than \
         {MAX_CHILD_CWD_LEN} characters as a process working directory (the limit is MAX_PATH \
         including a trailing separator and the NUL terminator, and it is lifted by neither \
         LongPathsEnabled nor a \\\\?\\ prefix). Every shell isolation tier hits this at spawn \
         time, so `--tier1`/`--tier0` will not help either. Move the workspace somewhere shorter, \
         or map it to a drive letter (`subst X: \"<workspace>\"`). Read-only commands \
         (`harness changes`/`apply`) are unaffected: {}",
        workspace_root.display()
    )))
}

pub fn preflight(
    workspace_root: &Path,
    passthrough: &[FsPassthrough],
    wfp_chain_pipe: Option<String>,
    write_mode: &WorkspaceWriteMode,
) -> Result<PreflightOutcome, AppContainerError> {
    let mut timing = PhaseTiming::start();
    // ACEを1本も付ける前に、そもそもこのworkspaceで子プロセスを起動できるかを確かめる。
    check_workspace_usable_as_child_cwd(workspace_root)?;
    timing.mark("check_workspace_usable_as_child_cwd");
    // D-37: プロファイルはセッション単位。共有package SIDをやめ、workspace・CoW upper_dir・
    // fs-allowの穴はこのセッションのSIDにだけ紐付ける（別セッション・別workspaceから到達
    // できないようにする）。祖先のtraverseだけはharness共通のcapability SIDが持つ（下記）。
    //
    // 起動のたびに、死んだセッションが残した資源をここで回収する（台帳＋生存マーカー、
    // 台帳が失われていても接頭辞付きプロファイルの列挙で回収できる）。
    crate::tier2a::session_profile::gc_dead_sessions(&revoke_session_grant);
    timing.mark("gc_dead_sessions");
    let profile_name = crate::tier2a::session_profile::begin_session()
        .map_err(AppContainerError::Preflight)?;
    let sid = ensure_profile(&profile_name)?;
    timing.mark("begin_session + ensure_profile");
    sweep_stale_redirector_dll_aces();
    timing.mark("sweep_stale_redirector_dll_aces");
    // 祖先traverseの付与先（D-37）。package SIDと違いセッションを跨いで永続する。
    let traverse_sid = traverse_capability_sid()?;

    // workspaceのアクセスモード（通常起動=RWX / `--cow`=RO、将来`--cow_exec`=RXを追加予定）は
    // 同じworkspaceに対して混在させてはいけない——ACEはファイルに1つしか付けられないため、
    // モードが違うセッションが同時に動くと片方の前提を裏切る（例: ROのはずが後から来た
    // RWXセッションのせいで書けてしまう）。ACE付与の前に、名前付きmutexで他モードが
    // 使用中でないか確認し、自モードの生存マーカーを確保する
    // （`crate::tier2a::workspace_ledger::begin_workspace_mode`のdoc参照、モード衝突チェックと
    // マーカー作成は内部で`with_named_lock`により直列化されるため、2プロセスがほぼ同時に
    // 別モードで起動しても早い者勝ちの事故にはならない）。
    let workspace_mode = match write_mode {
        WorkspaceWriteMode::DirectRw => "rwx",
        WorkspaceWriteMode::Cow { .. } => "ro",
    };
    let canonical_workspace_root = workspace_root.canonicalize().map_err(|e| {
        AppContainerError::Preflight(format!(
            "failed to canonicalize workspace root {}: {e}",
            workspace_root.display()
        ))
    })?;
    crate::tier2a::workspace_ledger::begin_workspace_mode(&canonical_workspace_root, workspace_mode)
        .map_err(AppContainerError::Preflight)?;
    crate::tier2a::workspace_ledger::record_workspace_grant(&canonical_workspace_root, workspace_mode);

    // D-54: workspaceツリーへ付けるACEの主体。**セッションのpackage SIDではなく、この
    // workspace＋モードに固有のcapability SID**へ付ける。付与の形（どのツリーへ何を許すか）は
    // workspaceとモードで決まるものであって、セッションの属性ではない——主体をその形に
    // 合わせることで、26万ノードへの継承ACEの伝播を**ワークスペースにつき一度きり**にする
    // （毎起動で払っていた実測60秒が消える、BUG-081）。名前はワークスペースごとのランダム
    // 秘密から導出され、サンドボックスから読めない台帳にだけ存在する
    // （`crate::tier2a::workspace_capability`のdoc）。
    let workspace_cap = workspace_capability_sid(&canonical_workspace_root, workspace_mode)?;
    let workspace_cap_psid = Some(workspace_cap.as_psid());

    // D-30: `write_mode`がACL付与方針を唯一決める。`match`を全分岐（`..`無し）にすることで、
    // `WorkspaceWriteMode`へバリアントを追加した際にACL決定漏れをコンパイルエラーにする。
    //
    // **workspace本体は`record_granted_path`しない**（D-54）。あれは「このセッションが撤収
    // 責任を負う」という表明で、記録すると`end_session`/`gc_dead_sessions`がツリー全体の
    // `revoke_ace_recursive`（実測30.8秒）を回してしまう。capability宛のACEはセッションより
    // 長生きするのが仕様であり、撤収は`harness fs revoke-workspace`が明示的に行う。
    let workspace_mask = match write_mode {
        WorkspaceWriteMode::DirectRw => {
            // 既定（D-29）。[BUG-082 Part B] rootへ継承ACEを1件、**伝播なし**で付けるだけ
            // （`grant_workspace_root_rw_fast`のdoc）——既存子孫への伝播は`grant_job`の
            // 背景フェーズへ委ねる。2回目以降の起動は冪等スキップでWin32書込0回。
            grant_workspace_root_rw_fast(workspace_root, workspace_cap.as_psid())?;
            timing.mark("grant_workspace_root_rw_fast(workspace_root)");
            workspace_rwx_mask()
        }
        WorkspaceWriteMode::Cow { upper_dir } => {
            // `--cow`（D-30）。workspaceはRead/Execute/Traverseのみ（D-13と同じ関数）。
            // Redirector DLLが無効・回避されても、この時点でACLがROである限り
            // workspace本体への書込は`ACCESS_DENIED`でfail-closeする。
            grant_workspace_root_ro_fast(workspace_root, workspace_cap.as_psid())?;
            // upper_dirは**セッション専有**（他セッションと共有しない）なので、主体は
            // 従来どおりセッションのpackage SIDのままにする。D-54が置き換えるのは
            // 「ワークスペースにつき一度きりで済むはずの付与」だけで、こちらは該当しない。
            std::fs::create_dir_all(upper_dir)
                .map_err(|e| AppContainerError::Preflight(e.to_string()))?;
            grant_ace_inheritable_rw(upper_dir, sid.as_psid())?;
            crate::tier2a::session_profile::record_granted_path(upper_dir);
            // `harness cow status`/`apply`/`list`がworkspace_rootを引けるよう、upper_dir自身に
            // 由来を記録する（`workspace_ledger::write_cow_session_meta`のdoc参照）。
            crate::tier2a::workspace_ledger::write_cow_session_meta(
                upper_dir,
                &canonical_workspace_root,
                upper_dir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown-session"),
            );
            // CoWのupper_dirはセッション専有（他セッションと共有しない）なので、他モードとの
            // 衝突チェックは不要。セッションID（upper_dirの最終パス要素、
            // `cow_upper_dir_for_session`参照）で名前を付けた生存マーカーだけを確保し、
            // `harness cow discard`等が「まだこのセッションが動いているか」を判定できるように
            // する（`plans/AppContainerベース Copy-on-Write ワークスペース設計書.md`Phase 6の
            // 前段）。
            let session_id = upper_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown-session");
            crate::tier2a::workspace_ledger::hold_cow_session_marker(session_id).map_err(|e| {
                AppContainerError::Preflight(format!(
                    "failed to create CoW session marker for {session_id}: {e}"
                ))
            })?;
            fs_access_mask(FsAccess::ReadExec)
        }
    };
    // D-05/D-09の層3。剥がす主体は**capability SID（今の継承元）とpackage SID（D-37時代の
    // 残骸）の両方**——片方だけだと剥がし残した側から制御面が書ける（`revoke.rs`のdoc参照）。
    let protected_nodes = protect_harness_control_dir_from_appcontainer(
        workspace_root,
        &[workspace_cap.as_psid(), sid.as_psid()],
    )?;
    // [BUG-084] 件数を出す。層3のhard-denyは「1件も掛かっていない」が症状として現れない
    // （BUG-083はそれが恒常的に起きていた）ので、`HARNESS_PREFLIGHT_TIMING=1`で事後確認
    // できる形にしておく。
    timing.mark(&format!(
        "protect_harness_control_dir_from_appcontainer ({protected_nodes} nodes)"
    ));

    // 保護DACL（BUG-020の残存損害等）で継承が届かなかった既存子孫の救済が要るか。
    // **ワークスペースにつき一度きり**で、実行は`preflight`の最後（他のACL作業を全て終えた後）に
    // 背景スレッドへ委ねる（`grant_job`のdoc「DACL書込の競合を避けるための約束」）。
    let needs_descendant_fix = !crate::tier2a::workspace_capability::tree_is_verified(
        &canonical_workspace_root,
        workspace_mode,
    );

    // workspace_root（Cow時はupper_dirも）の祖先traverseチェーンが不足していないか事前に判定する
    // （読み取り専用、UAC無し）。不足分は下のfs-allow昇格要求と合流させ、1回のprivhelper呼び出し
    // （起動あたりUAC最大1回）で解消する。以前はtraverse不足を`smoke_test_spawn`（下記）が
    // リアクティブに検知してTier1bへ静かに降格するだけだったが、privhelper経由で自動付与できる
    // 経路（`GrantWorkspaceAccess`）が整ったため、ここで先回りして解消する
    // （`plans/DESIGN-SANDBOX-PRIVSEP.md` D-16「特権昇格デーモンを使う際の注意点」参照）。
    // D-37: 見るのは**祖先だけ**。workspace_root/upper_dir自身への到達権はセッション固有の
    // package SID宛の継承ACE（すぐ上で付与済み）が与えるので、共通capability SIDのACEを
    // そこへ要求してはいけない。ここでleafまで含めると、セッションのたびに新しいworkspaceで
    // 「capability SIDのACEが無い」と判定され、毎回昇格を要求してしまう。
    let mut traverse_targets: Vec<std::path::PathBuf> =
        workspace_root.parent().map(|p| p.to_path_buf()).into_iter().collect();
    if let WorkspaceWriteMode::Cow { upper_dir } = write_mode {
        if let Some(parent) = upper_dir.parent() {
            traverse_targets.push(parent.to_path_buf());
        }
    }
    // D-45（W1の実測から確定、`plans/etw-spike/RESULTS.md` §19）: `--fs-allow`で許可した
    // パスの**親**もここへ入れる。対象自身への継承ACEだけでは、削除（`Remove-Item`）と
    // 移動（`Move-Item`）が失敗する——この2つは祖先ディレクトリを「通過」ではなく
    // **オープン**するため、対象へ到達する前に祖先で拒否される（拒否は対象ファイルではなく
    // 祖先に出るので、対象パスだけを見ていると「失敗しているのに拒否0件」に見える）。
    // 読取・書込・実行・`cmd /c type`はフルパスのファイルopenなので祖先未付与でも通る。
    //
    // マスクは現行の`FILE_TRAVERSE|FILE_READ_ATTRIBUTES`のままでよい（§19.2で7操作すべてが
    // これで通ることを実測した）。`SYNCHRONIZE`・`FILE_LIST_DIRECTORY`まで広げると
    // `C:\`・`C:\Users`が列挙可能になり機密性の実害が出るので広げない。
    //
    // **親を入れる（leafは入れない）**。leafへの到達権はこのセッション固有のpackage SIDが
    // 継承ACEで与える（上のfs-allowループ）。ここでcapability SIDのACEをleafへ要求すると、
    // 新しいパスを指定するたびに「capability SIDのACEが無い」と判定され毎回昇格を求めてしまう。
    //
    // 存在しないパスは入れない——後段のループが`path does not exist, skipped`として弾く
    // ものへ、先回りしてマシンのACLを書き換える理由が無い。
    for requested in passthrough {
        if !requested.path.exists() {
            continue;
        }
        let Some(parent) = requested.path.parent() else {
            continue;
        };
        let parent = parent.to_path_buf();
        if !traverse_targets.contains(&parent) {
            traverse_targets.push(parent);
        }
    }
    let missing_traverse: Vec<std::path::PathBuf> = traverse_targets
        .into_iter()
        .filter(|target| !traverse_chain_sufficient(target, traverse_sid.as_psid()))
        .collect();

    let mut warnings = Vec::new();

    // D-37: Redirector DLL（`--cow`の透過性）はworkspaceの外＝harness.exeの隣にあるため、
    // workspaceへの継承ACEでは覆えない。共有package SIDだった頃はリポジトリrootへの継承ACEが
    // たまたま`target/debug/*.dll`まで届いていたが、セッションごとにSIDが変わる今は明示的に
    // 読取+実行を与える必要がある（無ければ注入が失敗し、境界＝ACLは効いたまま透過性だけが失われる）。
    if matches!(write_mode, WorkspaceWriteMode::Cow { .. }) {
        for dll in redirector_dll_paths() {
            match grant_ace_inheritable_access(&dll, sid.as_psid(), FsAccess::ReadExec) {
                Ok(()) => crate::tier2a::session_profile::record_granted_path(&dll),
                // BUG-059 / BUG-017と同じ保険: `Err`は「何も起きなかった」を意味しない。
                // 副作用を伴う関数が途中で失敗したとき、ACEが既に載っているかは呼び出し側からは
                // 分からない。載っているのに記録しないと**撤収経路の無い孤立ACE**になる
                // （実機に4件残留していた）。rootを権威的にプローブして実在すれば記録する。
                // `grant_ace_inheritable_access`側のファイル分岐（層1）を直した後も、この保険は
                // 残す——記録漏れの代償（孤立ACE）は、幻の台帳エントリより重い。
                Err(e) => {
                    if matches!(sid_ace_mask(&dll, sid.as_psid()), Ok(Some(_))) {
                        crate::tier2a::session_profile::record_granted_path(&dll);
                        warnings.push(format!(
                            "cow: granting the redirector DLL to this session reported an error \
                             ({}): {e} -- but the ACE is present on the file, so it was recorded \
                             in the session ledger and will be revoked at session end",
                            dll.display()
                        ));
                    } else {
                        warnings.push(format!(
                            "cow: failed to grant the redirector DLL to this session ({}): {e}",
                            dll.display()
                        ));
                    }
                }
            }
        }
    }
    let mut denied_passthrough: Vec<(std::path::PathBuf, String, String)> = Vec::new();
    let mut granted_passthrough: Vec<(std::path::PathBuf, bool)> = Vec::new();
    // 本体プロセス内（非管理者）でACCESS_DENIEDになったエントリ（システム保護パス等）だけを
    // ここへ集め、後段で1回の特権分離ヘルパー要求へまとめる（起動あたりUAC最大1回、
    // `TIER1A-PRIVHELPER-HANG.md`「引き継ぎTODO」の決定）。
    let mut needs_elevation: Vec<crate::tier2a::privhelper::FsAllowGrant> = Vec::new();
    let mut netfilterd_chain_attempted = false;

    for requested in passthrough {
        if !requested.path.exists() {
            let reason = "path does not exist, skipped".to_string();
            warnings.push(format!("fs-allow {} : {reason}", requested.path.display()));
            denied_passthrough.push((
                requested.path.clone(),
                requested.access.label().to_string(),
                reason,
            ));
            continue;
        }

        // D-30（`--cow`）: fs-allowの`:rw`要求は、実際にOSへ付与するACLではRead止まりにする
        // （実行権限は与えない、`FsAccess::Read`。`FsAccess::ReadExec`ではない点に注意）。
        // `--cow`が存在する理由は「変更のあったファイルだけを単位としてレビュー・ロールバック
        // できること」（CoW＝ファイル単位の巻き戻し可能性が本質、スナップショット全体コピー
        // 方式ではない）であり、明示的にRO/ReadExecなfs-allowエントリはそもそも書込の余地が
        // 無いので対象外——ここで動的にRWをRO化しているのは、あくまで「元々RWだったものへ
        // 強制的にRedirector DLLのフックを通す書込経路」を作るための道具であって、頼まれても
        // いない実行権限まで付与する理由は無い（ユーザー指摘により`ReadExec`から`Read`へ訂正、
        // 2026-08-02）。workspace本体が`--cow`下で`grant_ace_inheritable_ro`
        // （`FsAccess::ReadExec`）を使うのは、workspace内のツール・スクリプトを実行できる
        // 必要があるというworkspace固有の事情であり、任意の外部fs-allowパスには適用されない。
        // 書込境界はACLであり、Redirector DLLの`_ext` captureはあくまで透過性のための利便性
        // （D-01「フックは境界にしない」）。ここで実RWを付与してしまうと、DLL注入失敗・バグ・
        // 迂回時にfail-closeせず実ファイルへ直接書けてしまい、workspace本体との一貫性が崩れる
        // （BUG-043発見時の実機検証を経てユーザー指摘により追加、2026-08-02）。`requested`
        // （ユーザーが本来要求したアクセス）は`granted_passthrough`の記録に使い、
        // `ext_capture_roots`（`crates/harness-tools/src/shell.rs`）の判定材料として残す。
        let downgrade_to_ro =
            matches!(write_mode, WorkspaceWriteMode::Cow { .. }) && requested.access.is_read_write();
        let effective_access = if downgrade_to_ro {
            FsAccess::Read
        } else {
            requested.access
        };
        let fp = FsPassthrough {
            path: requested.path.clone(),
            access: effective_access,
            forced: requested.forced,
        };
        let fp = &fp;
        let requested_rw = requested.access.is_read_write();

        // 事前チェック（決定1）: 既にsid宛のACEが要求マスクの上位集合を持っていれば、
        // 本体内のwalkもprivhelperのUACも一切スキップする（ユーザ所有パスの再実行はUAC無し）。
        let required = required_passthrough_mask(fp.access);
        let already_sufficient = matches!(sid_ace_mask(&fp.path, sid.as_psid()), Ok(Some(existing)) if existing & required == required);
        if already_sufficient {
            granted_passthrough.push((fp.path.clone(), requested_rw));
            // BUG-057: 付与を**スキップした**場合もsession ledgerへ記録する。ACEを実際に
            // 書いたのが前のセッションだったとしても、載っているのは**このセッションのSID宛**
            // であり（D-37でSIDはセッション固有）、撤収責任はこのセッションにある。
            // 記録しないと`end_session`の撤収対象から漏れ、「fs passthroughはセッション終了で
            // 失効する」（D-37の仕様）が破れる。
            crate::tier2a::session_profile::record_granted_path(&fp.path);
            if let Some(diagnosis) =
                probe_passthrough(
                    sid.as_psid(),
                    traverse_sid.as_psid(),
                    workspace_cap_psid,
                    workspace_root,
                    fp,
                )
            {
                denied_passthrough.push((
                    fp.path.clone(),
                    fp.access.label().to_string(),
                    diagnosis.clone(),
                ));
                warnings.push(diagnosis);
            }
            continue;
        }

        let grant_result = grant_ace_inheritable_access(&fp.path, sid.as_psid(), fp.access);
        match grant_result {
            Ok(()) => {
                granted_passthrough.push((fp.path.clone(), requested_rw));
                crate::tier2a::session_profile::record_granted_path(&fp.path);
                if let Some(diagnosis) =
                    probe_passthrough(
                    sid.as_psid(),
                    traverse_sid.as_psid(),
                    workspace_cap_psid,
                    workspace_root,
                    fp,
                )
                {
                    denied_passthrough.push((
                        fp.path.clone(),
                        fp.access.label().to_string(),
                        diagnosis.clone(),
                    ));
                    warnings.push(diagnosis);
                }
            }
            Err(_) => {
                // forced（--force-system-acl, D-19）は host パスの絶対拒否ゲートを**UACの前に**
                // 通す（禁止パスなら昇格させずここで警告に落とす。無駄なUACを出さない二重化）。
                if fp.forced {
                    if let Some(reason) = is_force_grant_forbidden(&fp.path) {
                        denied_passthrough.push((
                            fp.path.clone(),
                            fp.access.label().to_string(),
                            format!("forced system-ACL grant refused: {reason}"),
                        ));
                        warnings.push(format!(
                            "fs-allow {} : forced system-ACL grant refused: {reason}",
                            fp.path.display()
                        ));
                        continue;
                    }
                }
                // 本体（非管理者）内では書けなかった。システム保護パス（所有者がSYSTEM/
                // TrustedInstaller等）の可能性があるため、即座に警告へ落とさず後段の
                // 特権分離ヘルパー経路へ回す。
                needs_elevation.push(crate::tier2a::privhelper::FsAllowGrant {
                    path: fp.path.clone(),
                    access: fp.access,
                    forced: fp.forced,
                });
            }
        }
    }

    if !missing_traverse.is_empty() || !needs_elevation.is_empty() {
        let elevated: Result<FsAllowElevationOutcome, String> = if crate::tier2a::privhelper::is_elevated() {
            // 本体が既に管理者（§5.3、grant-traverseの`*_direct`と同じ考え方）:
            // ヘルパーを経由せずその場で直接付与する。traverseが不足していれば先に解消する
            // （workspace_root/upper_dirへ到達できなければfs-allow付与自体が無意味なため）。
            for target in &missing_traverse {
                let (granted_nodes, result) = grant_traverse_chain(target, traverse_sid.as_psid());
                for node in &granted_nodes {
                    crate::tier2a::traverse_ledger::record_traverse_grant(node);
                }
                if let Err(e) = result {
                    return Err(AppContainerError::Preflight(format!(
                        "failed to grant traverse ACE (admin, direct) for {}: {e}",
                        target.display()
                    )));
                }
            }
            let mut granted = Vec::new();
            let mut failures = Vec::new();
            for entry in &needs_elevation {
                // forcedは書込前に絶対拒否ゲートを通し、通過分のみ`SeRestorePrivilege`下で付与する
                // （dispatch側と同じ防壁。本体が既に管理者の経路でも同一の不変条件を保つ）。
                if entry.forced {
                    if let Some(reason) = is_force_grant_forbidden(&entry.path) {
                        failures.push((entry.path.clone(), reason));
                        continue;
                    }
                }
                let do_grant =
                    || grant_ace_inheritable_access(&entry.path, sid.as_psid(), entry.access);
                let result = if entry.forced {
                    with_restore_privilege(do_grant)
                } else {
                    do_grant()
                };
                match result {
                    Ok(()) => granted.push(entry.path.clone()),
                    Err(e) => failures.push((entry.path.clone(), e.to_string())),
                }
            }
            Ok((granted, failures))
        } else {
            netfilterd_chain_attempted = wfp_chain_pipe.is_some();
            match crate::tier2a::privhelper::run_privileged_workspace_access(
                missing_traverse.clone(),
                needs_elevation.clone(),
                wfp_chain_pipe.clone(),
            ) {
                Ok((traverse_granted, traverse_error, granted, failures)) => {
                    for node in &traverse_granted {
                        crate::tier2a::traverse_ledger::record_traverse_grant(node);
                    }
                    if let Some(reason) = traverse_error {
                        if !missing_traverse.is_empty() {
                            return Err(AppContainerError::Preflight(format!(
                                "failed to grant traverse ACE via privilege-separation helper: \
                                 {reason}"
                            )));
                        }
                    }
                    Ok((granted, failures))
                }
                Err(e) => {
                    // traverseが不足していて、それがprivhelper経由でも解消できなかった場合は
                    // Tier2a自体が成立しない（fail-close、workspace FS I/Oが動かない）ため即座に
                    // 打ち切る。UAC拒否（`ElevationDeclined`）もここに含まれる。
                    if !missing_traverse.is_empty() {
                        return Err(AppContainerError::Preflight(format!(
                            "traverse ACE grant via privilege-separation helper failed (UAC \
                             declined or helper error?): {e}"
                        )));
                    }
                    Err(e.to_string())
                }
            }
        };

        match elevated {
            Ok((granted, failures)) => {
                for path in &granted {
                    let writable = needs_elevation
                        .iter()
                        .find(|e| &e.path == path)
                        .map(|e| e.access.is_read_write())
                        .unwrap_or(false);
                    granted_passthrough.push((path.clone(), writable));
                    // BUG-057: 昇格経由（privhelper / 本体が既に管理者の直接付与、どちらも
                    // この`granted`へ合流する）の付与もsession ledgerへ記録する。ここが
                    // 抜けていたため、`fs-passthrough-ledger.json`（`harness fs revoke`が見る）
                    // には載るのに`end_session`の自動撤収からは漏れていた。
                    crate::tier2a::session_profile::record_granted_path(path);
                    if let Some(fp) = passthrough.iter().find(|fp| &fp.path == path) {
                        if let Some(diagnosis) = probe_passthrough(
                            sid.as_psid(),
                            traverse_sid.as_psid(),
                            workspace_cap_psid,
                            workspace_root,
                            fp,
                        ) {
                            denied_passthrough.push((
                                fp.path.clone(),
                                fp.access.label().to_string(),
                                diagnosis.clone(),
                            ));
                            warnings.push(diagnosis);
                        }
                    }
                }
                for (path, reason) in &failures {
                    let access = needs_elevation
                        .iter()
                        .find(|e| &e.path == path)
                        .map(|e| e.access)
                        .unwrap_or(FsAccess::ReadExec);
                    let writable = access.is_read_write();
                    // BUG-017: grant_ace_recursive/grant_ace_inheritable_roはroot(先頭ノード)から
                    // 順に付与するため、途中の子孫(TrustedInstaller所有等)で失敗しても、rootには
                    // 既にACEが載っている場合がある。「失敗」扱いで台帳へ記録しないと、実FS上には
                    // ACEが残るのに撤収経路が無い孤立ACEになる。rootを権威的にプローブし、ACEが
                    // 実在すれば台帳へ記録して`fs revoke`で後から掃除できるようにする。
                    if matches!(sid_ace_mask(path, sid.as_psid()), Ok(Some(_))) {
                        granted_passthrough.push((path.clone(), writable));
                        // BUG-057: 部分適用でACEが実在するなら、`end_session`の撤収対象にも入れる
                        // （`fs revoke`だけでなく自動撤収からも漏らさない）。
                        crate::tier2a::session_profile::record_granted_path(path);
                        warnings.push(format!(
                            "fs-allow {} : partially applied via privilege-separation helper \
                             (D-16) -- some descendant failed ({reason}), but the root itself now \
                             carries the sandbox ACE; recorded in the ledger so `harness fs revoke \
                             {}` can clean it up",
                            path.display(),
                            path.display()
                        ));
                    } else {
                        denied_passthrough.push((
                            path.clone(),
                            access.label().to_string(),
                            format!("ACE grant failed (via privilege-separation helper, D-16): {reason}"),
                        ));
                        warnings.push(format!(
                            "fs-allow {} : ACE grant failed (via privilege-separation helper, \
                             D-16): {reason}",
                            path.display()
                        ));
                    }
                }
            }
            Err(reason) => {
                for entry in &needs_elevation {
                    if matches!(sid_ace_mask(&entry.path, sid.as_psid()), Ok(Some(_))) {
                        granted_passthrough
                            .push((entry.path.clone(), entry.access.is_read_write()));
                        // BUG-057: 上と同じ（ヘルパーが完走できなかった場合の部分適用）。
                        crate::tier2a::session_profile::record_granted_path(&entry.path);
                        warnings.push(format!(
                            "fs-allow {} : partially applied -- the privilege-separation helper \
                             (D-16) could not fully complete ({reason}), but the root itself now \
                             carries the sandbox ACE; recorded in the ledger so `harness fs revoke \
                             {}` can clean it up",
                            entry.path.display(),
                            entry.path.display()
                        ));
                    } else {
                        denied_passthrough.push((
                            entry.path.clone(),
                            entry.access.label().to_string(),
                            format!(
                                "ACE grant failed: access denied in-process, and the privilege-separation helper (D-16) could not complete either: {reason}"
                            ),
                        ));
                        warnings.push(format!(
                            "fs-allow {} : ACE grant failed: access denied in-process, and the \
                             privilege-separation helper (D-16) could not complete either: {reason}",
                            entry.path.display()
                        ));
                    }
                }
            }
        }
    }

    // D-30: `FS_IO_PROBE_COMMAND`はprobe_dirへの書込を試みる。Cowモードではworkspace自体が
    // 意図的にROなので、probe_dirをworkspace配下に置くと「workspaceが書けない」という
    // Cowモードの正しい挙動を誤ってtraverse ACE不足として誤診断してしまう。probe_dirは
    // 書込可能であるべき場所（DirectRw時はworkspace、Cow時はupper_dir）に置く。上のtraverse
    // 自動付与を経た後の保険として、未知の原因によるFS I/O拒否をここで最終確認する。
    let probe_base = match write_mode {
        WorkspaceWriteMode::DirectRw => workspace_root,
        WorkspaceWriteMode::Cow { upper_dir } => upper_dir.as_path(),
    };
    let tmp_dir = probe_base.join(format!(".harness-tier2a-probe-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir).map_err(|e| AppContainerError::Preflight(e.to_string()))?;
    timing.mark("traverse/fs-allow/elevation");
    let smoke_result = smoke_test_spawn(sid.as_psid(), workspace_cap_psid, workspace_root, &tmp_dir);
    let _ = std::fs::remove_dir_all(&tmp_dir);
    smoke_result?;
    smoke_test_harness_control_write_denied(sid.as_psid(), workspace_cap_psid, workspace_root)?;
    timing.mark("smoke tests");

    // D-54: 救済walkはここで初めて起動する——**`preflight`のACL作業を全て終えた後**である
    // ことが、DACL書込の競合を避ける条件になっている（`grant_job`のdoc）。rootへの継承付与は
    // 既に同期で終わっているので、workspaceの大半はこの時点で到達可能であり、残りは
    // 保護DACL配下だけである。子プロセスを起動する経路は`grant_job::wait_until_done`で
    // 完了を待つ（待たずに走らせると、モデルには「そのファイルは無い」と見える）。
    if needs_descendant_fix {
        // [BUG-082 Part B] 背景フェーズが行う伝播はrootへの継承ACE伝播である。BUG-083の修正で
        // `.harness/`の保護が実際に効くようになり、この伝播はOS側で`.harness/`の手前で止まるが、
        // 保護が止められるのは**継承経由の伝播だけ**なので、保護前から物理コピーとして乗っていた
        // ACEやD-37時代のpackage SID残骸に備えて背景側でも剥がし直す（第2の防御）。ここで渡す
        // `.harness/`再保護用のSIDは、上の
        // 同期`protect_harness_control_dir_from_appcontainer`呼び出しと**同じ集合**
        // （workspace capability＋セッションSID）にする——片方だけだと剥がし残した側から
        // 制御面が書けるのは同期区間と同じ理屈（`revoke.rs`のdoc参照）。`workspace_cap`は
        // このすぐ後で`grant_job::start`へ移動するため、先にコピーを取っておく。
        let session_sid_copy = unsafe { crate::win_common::OwnedSid::copy_from(sid.as_psid()) }
            .map_err(|e| {
                AppContainerError::Preflight(format!(
                    "failed to copy the session SID for background .harness re-protection: {e}"
                ))
            })?;
        let harness_protect_sids = vec![workspace_cap.clone(), session_sid_copy];

        // 戻り値の`false`は「このプロセスでは既に別のジョブが走っている」＝`preflight`が2回
        // 呼ばれた場合だけで、製品では起こらない（実機テストが同居するときだけ）。
        let started = grant_job::start(
            workspace_root,
            workspace_cap,
            workspace_mask,
            harness_protect_sids,
            vec![workspace_root.join(".harness")],
            &canonical_workspace_root,
            workspace_mode,
        );
        timing.mark(&format!(
            "grant_job::start (background propagate + descendant fix-up, started={started})"
        ));
    }

    Ok(PreflightOutcome {
        warnings,
        denied_passthrough,
        granted_passthrough,
        netfilterd_chain_attempted,
    })
}
