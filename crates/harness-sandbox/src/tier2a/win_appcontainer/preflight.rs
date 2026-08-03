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

pub(crate) fn smoke_test_spawn(
    sid: PSID,
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
    let child = spawn(
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
    let child = spawn(
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

/// D9: passthroughルートが到達不能だったときの原因診断。生エラーメッセージに加え、
/// **`path`自身からドライブルートまでの全祖先**（`grant_traverse_chain`と同じ列挙順）の
/// traverse ACE有無を実地チェックし、欠けているノードを名指しする。従来はドライブルート
/// 1箇所しか見ていなかったが、`C:\Users\<user>\.cargo`のように中間の祖先（`C:\Users`・
/// `C:\Users\<user>`）が欠けているケースを診断できなかった
/// （`docs/phases/foundation/M12-shell-isolation-tiers.md`追記10で判明）。
/// 修復手順は`harness fs grant-traverse <path>`（連鎖化済み、追記13）を1回提示するだけでよい。
fn diagnose_unreachable_passthrough(sid: PSID, path: &Path, raw_message: &str) -> String {
    let mut chain: Vec<std::path::PathBuf> = path.ancestors().map(|p| p.to_path_buf()).collect();
    chain.reverse();

    let mut missing = Vec::new();
    for node in &chain {
        match sid_ace_mask(node, sid) {
            Ok(Some(mask)) if mask & FILE_TRAVERSE.0 != 0 && mask & FILE_READ_ATTRIBUTES.0 != 0 => {
            }
            Ok(Some(_)) => missing.push(format!(
                "{} (has a sandbox SID ACE but missing FILE_TRAVERSE|FILE_READ_ATTRIBUTES)",
                node.display()
            )),
            Ok(None) | Err(_) => missing.push(format!(
                "{} (no traverse ACE for the sandbox SID)",
                node.display()
            )),
        }
    }

    if missing.is_empty() {
        return format!(
            "fs-allow {} : unreachable inside AppContainer (probe error: {raw_message}); \
             all ancestor traverse ACEs (up to the drive root) look fine, cause unknown \
             (path may not exist, or a read-only file attribute is blocking a :rw request)",
            path.display()
        );
    }
    format!(
        "fs-allow {} : unreachable inside AppContainer (probe error: {raw_message}) -- \
         diagnosis: missing traverse ACE on {} ancestor node(s): {} (see \
         docs/phases/foundation/M12-shell-isolation-tiers.md 追記10・追記13). \
         fix (admin, one-time, grants the whole chain in one UAC prompt): \
         harness fs grant-traverse {}",
        path.display(),
        missing.len(),
        missing.join(", "),
        path.display()
    )
}

/// D8: passthroughルート1件へコンテナ内から実I/Oプローブ（疎通テスト）を行う。到達可なら
/// `None`、到達不能なら診断メッセージ（D9）を返す。全体のTier選択には影響しない
/// （`preflight`が結果を警告一覧として集約するだけで、壊れた穴以外は継続する）。
pub(crate) fn probe_passthrough(sid: PSID, workspace_root: &Path, fp: &FsPassthrough) -> Option<String> {
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
    let child = match spawn(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", command],
        workspace_root,
        &env,
        false,
        sid,
        NetworkCapability::Deny,
        None,
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
            &fp.path,
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

pub fn preflight(
    workspace_root: &Path,
    passthrough: &[FsPassthrough],
    wfp_chain_pipe: Option<String>,
    write_mode: &WorkspaceWriteMode,
) -> Result<PreflightOutcome, AppContainerError> {
    let sid = ensure_profile(CONTAINER_NAME)?;

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

    // D-30: `write_mode`がACL付与方針を唯一決める。`match`を全分岐（`..`無し）にすることで、
    // `WorkspaceWriteMode`へバリアントを追加した際にACL決定漏れをコンパイルエラーにする。
    match write_mode {
        WorkspaceWriteMode::DirectRw => {
            // 既定（D-29）。Tier2aが既定でプローブされるため、起動のたびにワークスペース全体へ
            // 個別書込を試みる`grant_ace_recursive`ではなく、高速化版（root継承ACE1件+
            // フォールバック確認walk、`grant_ace_inheritable_rw`のdoc参照）を使う。
            grant_ace_inheritable_rw(workspace_root, sid.as_psid())?;
        }
        WorkspaceWriteMode::Cow { upper_dir } => {
            // `--cow`（D-30）。workspaceはRead/Execute/Traverseのみ（D-13と同じ関数）。
            // Redirector DLLが無効・回避されても、この時点でACLがROである限り
            // workspace本体への書込は`ACCESS_DENIED`でfail-closeする。
            grant_ace_inheritable_ro(workspace_root, sid.as_psid())?;
            std::fs::create_dir_all(upper_dir)
                .map_err(|e| AppContainerError::Preflight(e.to_string()))?;
            grant_ace_inheritable_rw(upper_dir, sid.as_psid())?;
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
        }
    }
    protect_harness_control_dir_from_appcontainer(workspace_root, sid.as_psid())?;

    // workspace_root（Cow時はupper_dirも）の祖先traverseチェーンが不足していないか事前に判定する
    // （読み取り専用、UAC無し）。不足分は下のfs-allow昇格要求と合流させ、1回のprivhelper呼び出し
    // （起動あたりUAC最大1回）で解消する。以前はtraverse不足を`smoke_test_spawn`（下記）が
    // リアクティブに検知してTier1bへ静かに降格するだけだったが、privhelper経由で自動付与できる
    // 経路（`GrantWorkspaceAccess`）が整ったため、ここで先回りして解消する
    // （`plans/DESIGN-SANDBOX-PRIVSEP.md` D-16「特権昇格デーモンを使う際の注意点」参照）。
    let mut traverse_targets: Vec<std::path::PathBuf> = vec![workspace_root.to_path_buf()];
    if let WorkspaceWriteMode::Cow { upper_dir } = write_mode {
        traverse_targets.push(upper_dir.clone());
    }
    let missing_traverse: Vec<std::path::PathBuf> = traverse_targets
        .into_iter()
        .filter(|target| !traverse_chain_sufficient(target, sid.as_psid()))
        .collect();

    let mut warnings = Vec::new();
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
            if let Some(diagnosis) = probe_passthrough(sid.as_psid(), workspace_root, fp) {
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
                if let Some(diagnosis) = probe_passthrough(sid.as_psid(), workspace_root, fp) {
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
                let (granted_nodes, result) = grant_traverse_chain(target, sid.as_psid());
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
                    if let Some(fp) = passthrough.iter().find(|fp| &fp.path == path) {
                        if let Some(diagnosis) =
                            probe_passthrough(sid.as_psid(), workspace_root, fp)
                        {
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
    let smoke_result = smoke_test_spawn(sid.as_psid(), workspace_root, &tmp_dir);
    let _ = std::fs::remove_dir_all(&tmp_dir);
    smoke_result?;
    smoke_test_harness_control_write_denied(sid.as_psid(), workspace_root)?;

    Ok(PreflightOutcome {
        warnings,
        denied_passthrough,
        granted_passthrough,
        netfilterd_chain_attempted,
    })
}
