//! `preflight`が実行する**実機プローブ**——実際にAppContainer子を起動してFS I/Oを試し、
//! 結果を判定材料として返す層。
//!
//! `docs/CODE-STRUCTURE-RULES.md`規則1（本体1,000行）を`preflight.rs`が超えたため、規則3の
//! 軸1（どの外部システムと話すか）で切り出した。**ここは子プロセスとFSだけを触る**——
//! ACEの付与/撤収は`acl_grant`/`revoke`、どのプローブをどの順で打つかの決定は`preflight`が持つ。
//!
//! プローブは「拒否されること」も測る（`smoke_test_harness_control_write_denied`）。
//! 許可側だけを見るプローブは、機構が完全に死んでいるときも通ってしまう（B-35）。

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

pub(crate) fn smoke_test_harness_control_write_denied(
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
/// `fp`が要求するアクセスのうち、`preflight`が「既に十分」と判定するために必要な最小マスク
/// （`grant_ace`/`grant_ace_ro`が実際に付与するマスクと同じ論理和。継承フラグの相違までは
/// 見ない、`grant_ace_mask`の冪等スキップと同じ考え方）。
pub(crate) fn required_passthrough_mask(access: FsAccess) -> u32 {
    fs_access_mask(access)
}
