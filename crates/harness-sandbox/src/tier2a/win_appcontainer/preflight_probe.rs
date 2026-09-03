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

/// プローブ子プロセスのドメイン識別（§22.1.1）。**4本のプローブが共有する**——
/// 綴りを4箇所に書き分けると、片方だけが仕様変更に追随しない（B-05）。
///
/// workspace capabilityを渡された場合はそれがドメインで、`None`（package SID宛ACEを自前で
/// 付ける実機テスト専用の経路）ではプロファイルそのものがドメインになる。
fn probe_domain(workspace_cap: Option<PSID>) -> DomainIdentity {
    match workspace_cap {
        Some(sid) => DomainIdentity::Capability(sid),
        None => DomainIdentity::OwnPackage,
    }
}

/// [§22.3] プローブ子のトークンへ積むcapabilityの集合（workspace本体＋`--fs-allow`の宣言）。
///
/// **`--fs-allow`の穴は宣言ごとのcapability SID宛になった**ので、その宛先SIDを積まない子からは
/// 到達できない。積み忘れると、付与は正しく効いているのに到達性プローブが**全件を
/// 「到達不能」と報告する**——`preflight`から見ると穴が全部壊れているように見えるが、
/// 実際には測る側が権限を持っていないだけである。
///
/// 4本のプローブが同じ組み立てを通るように、綴りはここ1箇所に置く（`probe_domain`と同じ理由）。
/// プローブの子へ積むcapabilityの集合。
///
/// **本番の子と同じ集合でなければ、プローブは別の世界を測る**（`B-08`）。`workspace_cap`を
/// 独立の引数にしてあるのは、それが[`probe_domain`]（ドメインの識別子）も決めるからで、
/// 意味の違いであって重要度の違いではない。
///
/// [§22.3.2] `extra_domain_caps`は「このドメインがFSへ届くために要る、workspace本体以外の
/// capability」である——`--fs-allow`の宣言ぶんと、**CoWの差分層**。かつてこの引数は
/// `fs_allow_caps`という名前だったが、差分層の宛先SIDがcapabilityへ移った時点でその名前は
/// 実態より狭くなった（`preflight`のCoW分岐は`probe_dir`を**差分層の中**に作るので、
/// 積まないとプローブの書込が拒否され、`preflight`が「workspace FS I/Oが拒否された」と
/// **誤診断して起動を拒否する**——実際にこの移行で1度踏んだ）。
fn probe_capabilities(workspace_cap: Option<PSID>, extra_domain_caps: &[PSID]) -> Vec<PSID> {
    workspace_cap
        .into_iter()
        .chain(extra_domain_caps.iter().copied())
        .collect()
}

/// **シェルが実際にスクリプトを走らせた**ことだけを示す印。プローブの1文目で出す。
///
/// # なぜ終了コードだけでは足りないか（実測、2026-08-13）
///
/// PowerShellは**コンソールの与え方によっては、何一つ実行しないまま`exit 0`で終わる**
/// （`plans/mac-spike/RESULTS.md` §S1・§S1b。5.1・7とも、`DETACHED_PROCESS`で再現。
/// この性質はAppContainer固有ですらない）。終了コードしか見ないプローブは、この
/// 「無言のシェル」を**合格として通す**——`exit 0`だからである（B-09/B-10）。
/// 印を先頭で出させ、印が無い実行を不合格にすることで、その口を塞ぐ。
///
/// 印の綴りは**この定数から`format!`でコマンド文字列へ埋め込む**（判定側と2箇所に
/// 書き分けない、B-05）。
const PROBE_RAN_MARKER: &str = "HARNESS-PROBE-RAN";

/// プローブの結果を「シェルが走ったか」の軸だけで分類したもの。**終了コードの意味は
/// プローブごとに違う**ので、その解釈は呼び出し元に残す。
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProbeOutcome {
    /// 印があった＝スクリプトは走った。`code`の意味は各プローブが解釈する。
    Ran { code: i32 },
    /// 印が無い＝1行も走っていない（無言のシェル）。終了コードは信用できない。
    SilentShell { code: i32 },
}

/// プローブのstdoutと終了コードから[`ProbeOutcome`]を決める（純粋関数）。
pub(crate) fn judge_probe(marker: &str, stdout: &str, code: i32) -> ProbeOutcome {
    if stdout.contains(marker) {
        ProbeOutcome::Ran { code }
    } else {
        ProbeOutcome::SilentShell { code }
    }
}

/// `probe_dir`（preflightが事前に作成・ACL付与済みのワークスペース内一時ディレクトリ）へ
/// 実際に一時ファイルを作成・読取・削除するPowerShellコマンド。`exit 0`だけを試す旧実装は
/// FileSystemプロバイダの初期化失敗があってもプロセス自体は正常終了してしまい偽陽性となる
/// （`docs/phases/foundation/M12-shell-isolation-tiers.md`追記3参照）ため、実FS I/Oまで
/// 一括で試し、成否を終了コードに反映させる。
///
/// **印は1文目で出す**（[`PROBE_RAN_MARKER`]）。FSの成否より前に出すことで、
/// 「シェルが走ったか」と「FSが通ったか」を別々に読めるようにする。
fn fs_io_probe_command() -> String {
    format!(
        "Write-Output '{PROBE_RAN_MARKER}'; \
         $ErrorActionPreference = 'Stop'; \
         try {{ \
             $p = Join-Path $env:HARNESS_PROBE_DIR ([Guid]::NewGuid().ToString() + '.tmp'); \
             New-Item -ItemType File -Path $p -Force | Out-Null; \
             Get-Content -LiteralPath $p | Out-Null; \
             Remove-Item -LiteralPath $p -Force; \
             exit 0 \
         }} catch {{ \
             exit {FS_PROBE_DENIED_EXIT_CODE} \
         }}"
    )
}

fn control_dir_write_deny_probe_command() -> String {
    format!(
        "Write-Output '{PROBE_RAN_MARKER}'; \
         $ErrorActionPreference = 'Stop'; \
         $p = Join-Path $env:HARNESS_CONTROL_DIR ([Guid]::NewGuid().ToString() + '.tmp'); \
         try {{ \
             New-Item -ItemType File -Path $p -Force | Out-Null; \
             Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue; \
             exit 4 \
         }} catch {{ \
             exit 0 \
         }}"
    )
}

/// シェル選択プローブがstdinへ流すスクリプト——**そのシェルがAppContainer内で実際に走るか**
/// だけを見る最小のもの。FS I/Oを含めない（含めると、traverse ACE不足のような環境側の失敗を
/// 「このシェルは使えない」と読んでしまう）。
///
/// **本番`run_shell`と同じ渡し方（`-Command -`＝stdin経由）で測る。** 他の2プローブは
/// `-Command <script>`だが、選ばれたシェルが最も多く通るのは`run_shell`の形なので、
/// 選択の判定はそちらに合わせる（`harness-tools`の`platform_shell_command`・
/// `run_windows_tier2a`。ブートストラップ本体は依存の向き上ここからは参照できないので、
/// 形だけを合わせた最小のスクリプトを使う）。
fn shell_selection_probe_stdin() -> Vec<u8> {
    format!("Write-Output '{PROBE_RAN_MARKER}'\r\n").into_bytes()
}

/// このプロセスで使うTier2aシェルを、**実際にAppContainer内で起こして**決める。
/// 戻り値は警告（第1候補で決まったときは空）。
///
/// # 呼ぶ位置（変えるときは必ず読むこと）
///
/// **`preflight`がシェルを起こす3つのプローブ（`probe_passthrough_batch` →
/// `smoke_test_spawn` → `smoke_test_harness_control_write_denied`）より前**で呼ぶ。
/// 後ろに置くと、最初に走る`probe_passthrough_batch`が未選択のシェルで実行され、
/// そこで起動に失敗すると**passthroughを一律「到達不能」と誤診断する**。
/// 呼ぶのは全ACE付与が終わった後——シェルはworkspaceをcwdにして起こすので、
/// traverse/workspaceのACEが揃う前に測ると環境の問題をシェルの問題として読む。
///
/// # 落ち方
///
/// 候補が全滅しても**ここではpreflightを止めない**。Tier2aが成立するかの判定は
/// 後続の`smoke_test_spawn`が持っており、判定点を2つに増やすと「どちらが理由を出すのか」が
/// ぶれる。ここは最も保守的な候補（PowerShell 5.1）を選んで理由を`warnings`へ残すだけにする。
pub(crate) fn select_shell_by_probe(
    sid: PSID,
    workspace_cap: Option<PSID>,
    workspace_root: &Path,
) -> Vec<String> {
    let candidates = shell_candidates();
    // 候補が1本しか無い機（pwshが入っていない）では、測る意味が無いのでプロセスを起こさない。
    if candidates.len() <= 1 {
        if let Some(only) = candidates.into_iter().next() {
            remember_selected_shell(only);
        }
        return Vec::new();
    }

    let env = crate::secret_env::build_child_env();
    let stdin_payload = shell_selection_probe_stdin();
    let mut warnings: Vec<String> = Vec::new();
    let last_index = candidates.len() - 1;

    for (index, candidate) in candidates.iter().enumerate() {
        let (shell, label) = candidate;
        // 最後の候補は測らずに採る——落ちる先が他に無いので、測って落ちても結論は同じであり、
        // 起動を1回ぶん余計に払うだけになる。成否は後続のsmoke testが本来の理由付きで出す。
        if index == last_index {
            break;
        }
        let reason = match spawn_with_workspace(
            shell,
            &["-NoProfile", "-NonInteractive", "-Command", "-"],
            workspace_root,
            &env,
            // `-Command -`はstdinからスクリプトを読むので、stdinの口を開けて渡す
            // （`want_stdin: false`だと子は空を読んで何もせずに終わり、印が出ない）。
            true,
            sid,
            NetworkCapability::Deny,
            None,
            // [§22.3] シェルを選ぶだけのプローブなので`--fs-allow`の宛先SIDは積まない
            // ——測っているのは「このシェルはAppContainerで起動して1行走るか」だけで、
            // 宣言したパスへ届くかは後段の`probe_passthrough_batch`が測る。
            &probe_capabilities(workspace_cap, &[]),
            probe_domain(workspace_cap),
        ) {
            Err(e) => format!("could not start it ({e})"),
            Ok(child) => match child.write_stdin_read_output_and_wait(Some(&stdin_payload)) {
                Err(e) => format!("its output could not be read ({e})"),
                Ok((stdout, _, code)) => match judge_probe(PROBE_RAN_MARKER, &stdout, code) {
                    ProbeOutcome::Ran { code: 0 } => {
                        remember_selected_shell(candidate.clone());
                        return warnings;
                    }
                    ProbeOutcome::Ran { code } => {
                        format!("it ran the probe but exited with code {code}")
                    }
                    // §S1b の「無言のシェル」。**ここを合格にすると本番で1行も走らない**。
                    ProbeOutcome::SilentShell { code } => format!(
                        "it exited with code {code} without running anything \
                         (no '{PROBE_RAN_MARKER}' on stdout)"
                    ),
                },
            },
        };
        warnings.push(format!(
            "Tier2a shell: {label} ({shell}) is not usable on this machine — {reason}. \
             Falling back to the next candidate."
        ));
    }

    if let Some(last) = candidates.into_iter().next_back() {
        remember_selected_shell(last);
    }
    warnings
}

/// `workspace_cap`は、workspaceツリーのACEの宛先SIDになったcapability SID（D-54）。本番の
/// `run_shell`と**同じcapability構成**で起動しないとプローブの意味が無いので、`preflight`は
/// ここへ必ず`Some`を渡す（`None`は自前でpackage SID宛のACEを付ける実機テスト専用）。
pub(crate) fn smoke_test_spawn(
    sid: PSID,
    workspace_cap: Option<PSID>,
    extra_domain_caps: &[PSID],
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
            &fs_io_probe_command(),
        ],
        workspace_root,
        &env,
        false,
        sid,
        NetworkCapability::Deny,
        None,
        &probe_capabilities(workspace_cap, extra_domain_caps),
        probe_domain(workspace_cap),
    )
    .map_err(|e| AppContainerError::Preflight(format!("shell could not start: {e}")))?;
    let (stdout, _, code) = child
        .write_stdin_read_output_and_wait(None)
        .map_err(|e| AppContainerError::Preflight(format!("shell could not start: {e}")))?;
    // **印が無い実行は、終了コードが0でも合格にしない**（無言のシェル。`PROBE_RAN_MARKER`のdoc）。
    if let ProbeOutcome::SilentShell { code } = judge_probe(PROBE_RAN_MARKER, &stdout, code) {
        return Err(AppContainerError::Preflight(format!(
            "the shell ({shell}) exited with code {code} without running the probe script at all \
             (no '{PROBE_RAN_MARKER}' on stdout); its exit code says nothing about workspace FS I/O"
        )));
    }
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
    extra_domain_caps: &[PSID],
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
            &control_dir_write_deny_probe_command(),
        ],
        workspace_root,
        &env,
        false,
        sid,
        NetworkCapability::Deny,
        None,
        // [§22.3] **拒否側のプローブこそ、実際の子が持つcapability SIDを全部積んで試す。**
        // 積まずに拒否されても「`.harness/`の保護が効いた」ことの証明にならないのは
        // workspace capabilityと同じ理屈で、宣言capabilityにもそのまま当てはまる
        // （`--fs-allow`が`.harness/`を覆う宣言をしていれば、それは実際に穴である）。
        &probe_capabilities(workspace_cap, extra_domain_caps),
        probe_domain(workspace_cap),
    )
    .map_err(|e| {
        AppContainerError::Preflight(format!(
            ".harness write-deny probe shell could not start: {e}"
        ))
    })?;
    let (stdout, _, code) = child.write_stdin_read_output_and_wait(None).map_err(|e| {
        AppContainerError::Preflight(format!(
            ".harness write-deny probe shell could not start: {e}"
        ))
    })?;
    // **拒否側のプローブこそ印が要る。** このプローブは「書けなかった＝catch枝＝`exit 0`」で
    // 合格にするので、印が無いと**1行も走らなかったシェル**が最も確実に合格する（B-35の裏返し）。
    if let ProbeOutcome::SilentShell { code } = judge_probe(PROBE_RAN_MARKER, &stdout, code) {
        return Err(AppContainerError::Preflight(format!(
            ".harness write-deny probe: the shell ({shell}) exited with code {code} without \
             running the probe script at all (no '{PROBE_RAN_MARKER}' on stdout); this is not \
             evidence that .harness is protected"
        )));
    }
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

/// fs passthrough（D-13）の到達性プローブ用コマンド。**全エントリを1プロセスで測る。**
///
/// # なぜ1プロセスなのか（実測に基づく）
///
/// 以前はエントリ1件につきAppContainer内でPowerShellを1プロセス起こしていた。素の
/// PowerShell 5.1の起動だけで**182ms/回**（この機での実測。AppContainer生成・Job Object・
/// パイプ・実I/Oを含まない下限）なので、ポリシーエディタのように**workspace外の穴が
/// 数百件**あるドメインでは、それだけで数分の無反応になる（実例: `cargo`ドメインの668件で
/// 下限2分）。しかも「既に十分」で付与をスキップした2回目以降の実行でも同じ時間を払っていた
/// ——UACを消しても待ち時間がそのまま残る形だった。
///
/// **診断の情報量は落としていない。** 判定は依然として「AppContainerの中から実I/Oを試す」
/// ことで行い（D8）、失敗したエントリだけが`diagnose_unreachable_passthrough`（D9、
/// 祖先チェーンのACL読取のみでプロセスを起こさない）へ回る。減ったのはプロセス起動の回数だけ。
///
/// # 入出力の形
///
/// - 標準入力: 1行1エントリ、`<mode>\t<path>`（`mode`は`ro`または`rw`）。
///   **envではなくstdinで渡す**——環境変数ブロックには実用上の長さ上限があり、
///   数百パスは載らない。
/// - 標準出力: 1行1結果、`<index>\tOK` または `<index>\tERR\t<message>`。
///   `index`は入力の**空でない行**の0起点連番。メッセージ中の空白は1つへ潰して1行に収める。
///
/// 制御文字は`` `t ``のようなバッククォート表記ではなく`[char]9`で書く——この文字列は
/// Rustのリテラル→コマンドライン→PowerShellパーサと3層を通るので、層ごとの引用規則に
/// 依存しない書き方にしておく。
///
/// # `rw`は対象がファイルかディレクトリかで手段を変える
///
/// `Test-Path -PathType Leaf`で判定する。ディレクトリは配下に一時ファイルを作って書込を試す
/// （元の実装）。**単一の実行ファイル自体へ`fs.read_write`/`fs.read_exec`を宣言できるように
/// なった**（ポリシーエディタ段階9、D-59のマスクの和）ことで、`granted`がファイルパスそのもの
/// のケースが実機で初めて出た——`Join-Path <file> <uuid>.tmp`は`<file>`をディレクトリとして
/// 扱うので「パスの一部が見つかりません」で必ず失敗する。ファイルの場合は
/// `File.Open(..., FileAccess.ReadWrite, FileShare.ReadWrite)`で開いて即閉じるだけにする
/// （内容は変更しない。共有モードを緩めるのは、対象が同時に他プロセスから読まれていても
/// このプローブ自体の目的＝書込アクセス権の有無の確認には影響しないため）。
///
/// # [D-63] `rw1`——オブジェクト単体で許可されたディレクトリ
///
/// **プローブは宣言された範囲を測る。** 範囲を知らずに測ると、正しく動いている構成を
/// 「到達不能」と報告する（B-10の裏返し——測り方が対象と食い違うと、緑も赤も意味を失う）。
///
/// `rw`（従来）は`New-Item`で作った一時ファイルを**開き直して**から消す。ディレクトリ自身にしか
/// ACEが無い場合、作成は通るが**開き直しと削除は拒否される**——新しいファイルは親から継承する
/// ACEを持たないためである。結果は「偽の到達不能」＋**消せない`.harness-probe.tmp`が残る**。
///
/// `rw1`は`File.Create(..., FileOptions.DeleteOnClose)`で作成ハンドル1つだけを使い、閉じた
/// 時点でOSに消させる。作成時のアクセス検査は親の`FILE_ADD_FILE`に対して行われ、要求した
/// アクセス権はそのハンドルに与えられるので、開き直しは発生しない。
pub(crate) const PROBE_MODE_RW_OBJECT: &str = "rw1";
// `[Console]::In.ReadToEnd()` は Constrained Language Mode では許可型でなく、実 I/O の前に
// 落ちる。PowerShell の組込み`$input`なら、標準入力を同じく行単位で受け取れる。
const FS_PASSTHROUGH_BATCH_PROBE_COMMAND: &str = "\
    $ErrorActionPreference = 'Stop'; \
    $i = -1; \
    foreach ($raw in $input) { \
        $line = $raw.TrimEnd([char]13); \
        if ($line.Length -eq 0) { continue }; \
        $i++; \
        $t = $line.IndexOf([char]9); \
        $mode = $line.Substring(0, $t); \
        $p = $line.Substring($t + 1); \
        try { \
            $isLeaf = Test-Path -LiteralPath $p -PathType Leaf; \
            if ($mode -eq 'rw' -or $mode -eq 'rw1') { \
                if ($isLeaf) { \
                    $stream = [System.IO.File]::Open($p, [System.IO.FileMode]::Open, \
                        [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite); \
                    $stream.Close() \
                } elseif ($mode -eq 'rw1') { \
                    $tmp = Join-Path $p ([Guid]::NewGuid().ToString() + '.harness-probe.tmp'); \
                    $stream = [System.IO.File]::Create($tmp, 4096, \
                        [System.IO.FileOptions]::DeleteOnClose); \
                    $stream.Close() \
                } else { \
                    $tmp = Join-Path $p ([Guid]::NewGuid().ToString() + '.harness-probe.tmp'); \
                    New-Item -ItemType File -Path $tmp -Force | Out-Null; \
                    Get-Content -LiteralPath $tmp | Out-Null; \
                    Remove-Item -LiteralPath $tmp -Force \
                } \
            } else { \
                if ($isLeaf) { \
                    Get-Item -LiteralPath $p -ErrorAction Stop | Out-Null \
                } else { \
                    Get-ChildItem -LiteralPath $p -ErrorAction Stop | Out-Null \
                } \
            }; \
            Write-Output ([string]$i + [char]9 + 'OK') \
        } catch { \
            Write-Output ([string]$i + [char]9 + 'ERR' + [char]9 + \
                ($_.Exception.Message -replace '\\s+', ' ')) \
        } \
    }";

/// [`probe_passthrough_batch`]の結果。
///
/// **「測れなかった」を「到達可」と混ぜない**（B-10）。プローブを起こせなかったときに
/// 全件`None`（到達可）を返すと、穴が壊れていても黙って通る。逆に全件へ同じ失敗文言を
/// 詰めると、数百件の同一警告でユーザーの目を潰す（B-09/B-32）——1つの事実は1回だけ言う。
pub(crate) enum BatchProbeOutcome {
    /// プローブを実行できた。入力と**同じ順・同じ件数**の結果（`None`＝到達可）。
    Measured(Vec<Option<String>>),
    /// プローブ自体を起こせなかった。全件が未測定である、という1つの事実。
    NotRun(String),
}

/// 入力行を組み立てる（純粋関数。実機・AppContainerなしで形を固定できる）。
pub(crate) fn batch_probe_stdin(entries: &[FsPassthrough]) -> String {
    let mut payload = String::new();
    for fp in entries {
        // [D-63] **宣言された範囲で測る。** オブジェクト単体で許可したディレクトリを従来の`rw`で
        // 測ると、配下に作った一時ファイルを開き直せず「偽の到達不能」になり、消せない
        // `.harness-probe.tmp`まで残る（[`PROBE_MODE_RW_OBJECT`]のdoc）。
        let mode = match (fp.access.is_read_write(), fp.scope) {
            (false, _) => "ro",
            (true, GrantScope::Recursive) => "rw",
            (true, GrantScope::Object) => PROBE_MODE_RW_OBJECT,
        };
        payload.push_str(mode);
        payload.push('\t');
        // パスに改行が入ることは通常ありえないが、入ったら行の対応がずれる。
        // 潰さずに**空白へ置換**して、少なくとも件数のずれは起こさない。
        payload.push_str(&fp.path.to_string_lossy().replace(['\r', '\n'], " "));
        payload.push('\n');
    }
    payload
}

/// プローブのstdoutを、入力件数ぶんの結果へ写す（純粋関数）。
///
/// 行が欠けているエントリは**`None`（到達可）にしない**——測れなかったことをそう言う。
pub(crate) fn parse_batch_probe_output(stdout: &str, count: usize) -> Vec<Option<String>> {
    let mut seen: Vec<Option<Option<String>>> = vec![None; count];
    for line in stdout.lines() {
        let mut parts = line.split('\t');
        let Some(index) = parts.next().and_then(|i| i.trim().parse::<usize>().ok()) else {
            continue;
        };
        if index >= count {
            continue;
        }
        seen[index] = Some(match parts.next() {
            Some("OK") => None,
            Some("ERR") => Some(parts.next().unwrap_or("(no message)").trim().to_string()),
            _ => Some("probe returned an unrecognized result line".to_string()),
        });
    }
    seen.into_iter()
        .map(|result| {
            result.unwrap_or(Some(
                "the reachability probe produced no result for this path".to_string(),
            ))
        })
        .collect()
}

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
/// **祖先とleafは別の宛先SIDが別のACEで賄っている**（D-37）。祖先の通過権は全セッションで
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
        .filter(|(_, mask)| {
            !mask.is_some_and(|m| m & TRAVERSE_REQUIRED_MASK == TRAVERSE_REQUIRED_MASK)
        })
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

/// 1件だけ測る版（実機E2Eが「この穴が到達可か」を単体で確かめるために使う）。
///
/// **実装は[`probe_passthrough_batch`]ただ1つ**——判定を2つ持つと、片方だけが仕様変更に
/// 追随しない（`docs/CODE-STRUCTURE-RULES.md`規則5）。本番の`preflight`はこちらを使わない。
#[cfg(test)]
pub(crate) fn probe_passthrough(
    sid: PSID,
    traverse_sid: PSID,
    workspace_cap: Option<PSID>,
    extra_domain_caps: &[PSID],
    workspace_root: &Path,
    fp: &FsPassthrough,
) -> Option<String> {
    match probe_passthrough_batch(
        sid,
        traverse_sid,
        workspace_cap,
        extra_domain_caps,
        workspace_root,
        std::slice::from_ref(fp),
    ) {
        BatchProbeOutcome::Measured(mut results) => results.pop().flatten(),
        BatchProbeOutcome::NotRun(reason) => {
            Some(format!("fs-allow {} : {reason}", fp.path.display()))
        }
    }
}

/// D8: passthroughルート**全件**へ、コンテナ内から実I/Oプローブ（疎通テスト）を行う。
/// 到達可なら`None`、到達不能なら診断メッセージ（D9）を、入力と同じ順で返す。
/// 全体のTier選択には影響しない（`preflight`が結果を警告一覧として集約するだけで、
/// 壊れた穴以外は継続する）。
///
/// **プロセスは1つしか起こさない**（[`FS_PASSTHROUGH_BATCH_PROBE_COMMAND`]のdoc参照）。
///
/// `sid`は子プロセスを起動するセッションpackage SID、`traverse_sid`は祖先チェーンの
/// 通過権を持つcapability SID。**両方を受けるのはD9診断が2系統を区別するため**（BUG-058）。
///
/// **呼ぶのは全ての付与が終わってから**にすること。昇格ヘルパー経由で祖先のtraverseが
/// 直る場合があるので、付与の途中で測ると「直る前の状態」を到達不能として報告してしまう。
pub(crate) fn probe_passthrough_batch(
    sid: PSID,
    traverse_sid: PSID,
    workspace_cap: Option<PSID>,
    extra_domain_caps: &[PSID],
    workspace_root: &Path,
    entries: &[FsPassthrough],
) -> BatchProbeOutcome {
    if entries.is_empty() {
        return BatchProbeOutcome::Measured(Vec::new());
    }
    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    // 子のcwdは`workspace_root`なので、workspace capability（D-54）が無いと**プローブ対象の
    // 手前で**起動に失敗する。穴そのものの到達性を測るために、本番と同じ構成で起動する。
    let child = match spawn_with_workspace(
        &shell,
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            FS_PASSTHROUGH_BATCH_PROBE_COMMAND,
        ],
        workspace_root,
        &env,
        // **`want_stdin: true`が要る。** 対象パスの一覧はstdinで渡すので、ここが`false`だと
        // 子は`[Console]::In.ReadToEnd()`で空文字を読み、`foreach`が1周も回らず**出力が0行**に
        // なる。他のプローブ（`smoke_test_spawn`等）はstdinを使わないので`false`で、
        // それを写して1度踏んだ。
        true,
        sid,
        NetworkCapability::Deny,
        None,
        // [§22.3] **穴の宛先SIDを積まないと、この測定は全件「到達不能」になる。**
        // 付与が正しく効いていても、測る側がcapabilityを持っていなければ届かない。
        &probe_capabilities(workspace_cap, extra_domain_caps),
        probe_domain(workspace_cap),
    ) {
        Ok(child) => child,
        Err(e) => return BatchProbeOutcome::NotRun(format!("probe could not start: {e}")),
    };
    let payload = batch_probe_stdin(entries);
    let (stdout, stderr, exit_code) =
        match child.write_stdin_read_output_and_wait(Some(payload.as_bytes())) {
            // 終了コードは見ない——**個々の結果は行で返る**ので、プロセス全体の成否は
            // 「行が返ったか」でしか意味を持たない（欠けた行は`parse_batch_probe_output`が拾う）。
            Ok(output) => output,
            Err(e) => return BatchProbeOutcome::NotRun(format!("probe failed: {e}")),
        };

    let raw = parse_batch_probe_output(&stdout, entries.len());
    // 1行も返らないのは、個別パスの拒否ではなくプローブ自体の異常である。ここを各パスの
    // `cause unknown`に畳むと、シェル引数・stdin・PowerShell初期化のどれが壊れたかを
    // 利用者が区別できない。標準出力・標準エラーと終了コードを一度だけ残し、全件を
    // 「未測定」として扱う（B-09/B-10）。
    let returned_any_result_row = stdout.lines().any(|line| {
        line.split('\t')
            .next()
            .and_then(|index| index.trim().parse::<usize>().ok())
            .is_some_and(|index| index < entries.len())
    });
    if !returned_any_result_row {
        return BatchProbeOutcome::NotRun(format!(
            "probe returned no result rows (exit code {exit_code}; stdout={stdout:?}; stderr={stderr:?})"
        ));
    }
    // 失敗したエントリだけをD9診断へ回す（祖先チェーンのACL読取のみ。プロセスは起こさない）。
    BatchProbeOutcome::Measured(
        entries
            .iter()
            .zip(raw)
            .map(|(fp, message)| {
                message.map(|message| {
                    diagnose_unreachable_passthrough(
                        sid,
                        traverse_sid,
                        &fp.path,
                        fp.access,
                        message.trim(),
                    )
                })
            })
            .collect(),
    )
}
/// `fp`が要求するアクセスのうち、`preflight`が「既に十分」と判定するために必要な最小マスク
/// （`grant_ace`/`grant_ace_ro`が実際に付与するマスクと同じ論理和）。
pub(crate) fn required_passthrough_mask(access: FsAccess) -> u32 {
    fs_access_mask(access)
}

/// [D-63] `scope`が要求する継承フラグ。マスクと対で「既に十分か」を決める
/// （[`super::ExplicitAce::satisfies`]）。
///
/// **`Object`は0を返す**——「継承していないこと」までは要求しない。既にある継承ACEを
/// 不十分と見なすと、`preflight`が毎回付与し直しに行くだけで**何も狭まらない**
/// （狭めるにはツリー全体から降りたコピーを剥がす必要があり、それは撤収の仕事である）。
pub(crate) fn required_inherit_flags(scope: GrantScope) -> u8 {
    match scope {
        GrantScope::Object => 0,
        GrantScope::Recursive => (OBJECT_INHERIT_ACE.0 | CONTAINER_INHERIT_ACE.0) as u8,
    }
}

#[cfg(test)]
mod probe_verdict_tests {
    use super::*;

    /// 印があれば走った——終了コードの意味はプローブごとに違うので、そのまま運ぶ。
    #[test]
    fn a_marked_run_is_reported_with_its_exit_code() {
        assert_eq!(
            judge_probe(PROBE_RAN_MARKER, &format!("{PROBE_RAN_MARKER}\r\n"), 0),
            ProbeOutcome::Ran { code: 0 }
        );
        // FS I/Oプローブの「シェルは走ったがFSが拒否された」（exit 3）は**シェルの不合格ではない**。
        // ここを`SilentShell`と混ぜると、環境の問題でシェルを取り替えることになる。
        assert_eq!(
            judge_probe(
                PROBE_RAN_MARKER,
                &format!("{PROBE_RAN_MARKER}\r\n"),
                FS_PROBE_DENIED_EXIT_CODE
            ),
            ProbeOutcome::Ran {
                code: FS_PROBE_DENIED_EXIT_CODE
            }
        );
    }

    /// **この判定が本題**（§S1b）。何も実行せずに`exit 0`したシェルは、終了コードだけを
    /// 見れば合格に見える。印が無い以上、その0は「拒否されなかった」ことすら意味しない。
    #[test]
    fn a_shell_that_exits_zero_without_running_anything_is_not_a_pass() {
        assert_eq!(
            judge_probe(PROBE_RAN_MARKER, "", 0),
            ProbeOutcome::SilentShell { code: 0 }
        );
        // 起動時ノイズだけを吐いて終わった場合も同じ（他人の出力は印にならない、B-33）。
        assert_eq!(
            judge_probe(
                PROBE_RAN_MARKER,
                "Attempting to perform the InitializeDefaultDrives operation\r\n",
                0
            ),
            ProbeOutcome::SilentShell { code: 0 }
        );
    }

    /// 印が無ければ、終了コードが何であっても不合格側へ倒す（0以外でも同じ扱い）。
    #[test]
    fn a_nonzero_exit_without_the_marker_is_also_a_silent_shell() {
        assert_eq!(
            judge_probe(PROBE_RAN_MARKER, "some error text", 1),
            ProbeOutcome::SilentShell { code: 1 }
        );
    }

    /// 印は**プローブのコマンド文字列そのもの**へ埋め込まれていること（B-05: 綴りを
    /// 2箇所に書き分けない）。ここが外れると、判定は永遠に`SilentShell`を返す。
    #[test]
    fn every_probe_command_emits_the_marker_it_is_judged_by() {
        for command in [
            fs_io_probe_command(),
            control_dir_write_deny_probe_command(),
            String::from_utf8(shell_selection_probe_stdin()).expect("probe stdin is utf-8"),
        ] {
            assert!(
                command.contains(PROBE_RAN_MARKER),
                "プローブのコマンドが印を出していない: {command}"
            );
        }
        // FS I/Oプローブの拒否コードも、コマンド側とRust側で同じ値でなければならない。
        assert!(
            fs_io_probe_command().contains(&format!("exit {FS_PROBE_DENIED_EXIT_CODE}")),
            "拒否コードの綴りがコマンドと定数でずれている"
        );
    }
}

#[cfg(test)]
mod batch_probe_tests {
    use super::*;

    /// 既定は`Recursive`（D-63以前の全エントリの意味）。スコープを変える検証は
    /// [`scoped_entry`]を使う。
    fn entry(path: &str, access: FsAccess) -> FsPassthrough {
        scoped_entry(path, access, GrantScope::Recursive)
    }

    fn scoped_entry(path: &str, access: FsAccess, scope: GrantScope) -> FsPassthrough {
        FsPassthrough {
            path: std::path::PathBuf::from(path),
            access,
            forced: false,
            scope,
        }
    }

    /// [D-63] **オブジェクト単体で許可した書込可ディレクトリは別モードで測る。**
    ///
    /// 従来の`rw`は配下に作った一時ファイルを開き直すので、ディレクトリ自身にしかACEが無い
    /// 構成では必ず失敗する（偽の到達不能＋消えない`.harness-probe.tmp`）。
    /// **ファイルは`Object`でもモードが変わらない**——ファイルに配下は無く、`rw`の分岐は
    /// 対象がファイルなら開いて閉じるだけだからである。
    #[test]
    fn an_object_scoped_writable_entry_uses_the_single_handle_probe_mode() {
        let payload = batch_probe_stdin(&[
            scoped_entry(r"C:\dir", FsAccess::ReadWrite, GrantScope::Object),
            scoped_entry(r"C:\tree", FsAccess::ReadWrite, GrantScope::Recursive),
            scoped_entry(r"C:\ro", FsAccess::Read, GrantScope::Object),
        ]);
        assert_eq!(payload, "rw1\tC:\\dir\nrw\tC:\\tree\nro\tC:\\ro\n");
    }

    /// 入力の形（1行1エントリ、`<mode>\t<path>`）を固定する。プローブ側のPowerShellが
    /// この形を前提に`IndexOf([char]9)`で割るので、片方だけ変えると**全件が測れなくなる**
    /// （しかも「測れなかった」は下の`parse`側で警告に落ちるので、静かには壊れない）。
    #[test]
    fn stdin_carries_one_line_per_entry_with_the_mode_first() {
        let payload = batch_probe_stdin(&[
            entry(r"C:\a", FsAccess::Read),
            entry(r"C:\b", FsAccess::ReadWrite),
            entry(r"C:\c", FsAccess::ReadExec),
        ]);
        assert_eq!(payload, "ro\tC:\\a\nrw\tC:\\b\nro\tC:\\c\n");
    }

    /// 改行を含むパスが来ても**行数はずれない**（ずれると結果が別のパスへ付く）。
    #[test]
    fn newlines_in_a_path_do_not_shift_the_line_numbering() {
        let payload = batch_probe_stdin(&[
            entry("C:\\a\nb", FsAccess::Read),
            entry(r"C:\c", FsAccess::Read),
        ]);
        assert_eq!(payload.lines().count(), 2);
        assert!(payload.starts_with("ro\tC:\\a b\n"));
    }

    #[test]
    fn ok_and_err_lines_map_back_to_their_entries_in_order() {
        let stdout = "0\tOK\n1\tERR\tAccess to the path is denied.\n2\tOK\n";
        assert_eq!(
            parse_batch_probe_output(stdout, 3),
            vec![
                None,
                Some("Access to the path is denied.".to_string()),
                None
            ]
        );
    }

    /// 出力の順序に依存しない（PowerShell側は順に出すが、それを前提にしない）。
    #[test]
    fn results_are_matched_by_index_not_by_position() {
        let stdout = "2\tOK\n0\tERR\tboom\n1\tOK\n";
        let results = parse_batch_probe_output(stdout, 3);
        assert_eq!(results[0], Some("boom".to_string()));
        assert_eq!(results[1], None);
        assert_eq!(results[2], None);
    }

    /// **行が欠けたエントリを「到達可」にしない**（B-10: 測れなかったことをそう言う）。
    /// ここが`None`になると、壊れた穴が黙って通る。
    #[test]
    fn a_missing_result_line_is_reported_not_treated_as_reachable() {
        let results = parse_batch_probe_output("0\tOK\n", 3);
        assert_eq!(results[0], None);
        for missing in &results[1..] {
            assert!(
                missing.as_deref().is_some_and(|m| m.contains("no result")),
                "a path the probe never answered for must not be reported as reachable: \
                 {missing:?}"
            );
        }
    }

    /// 範囲外の添字・壊れた行は無視する（プローブの出力は昇格していない子プロセス由来なので、
    /// 形が崩れていてもパニックしない）。欠けた分は上のルールで「測れなかった」になる。
    #[test]
    fn out_of_range_and_garbage_lines_do_not_panic() {
        let results = parse_batch_probe_output("9\tOK\ngarbage\n\n0\tWAT\n", 1);
        assert!(results[0]
            .as_deref()
            .is_some_and(|m| m.contains("unrecognized")));
    }
}

#[cfg(test)]
mod shell_selection_real_machine_tests {
    use super::*;

    /// **実機**: この機のTier2aシェルが、実際にAppContainer内で走るものに決まること。
    ///
    /// 単体テストでは「候補の並び」と「判定」しか測れない（どちらもプロセスを起こさない）。
    /// 決めているのは実プローブなので、選択が実際に成立することはここでしか測れない。
    ///
    /// **昇格して走らせないこと**——昇格したテストからAppContainer子を起こすと親トークンが
    /// 管理者のものになり、実運用とは別の世界を測る（B-08、BUG-109と同型）。
    ///
    /// ```text
    /// cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture \
    ///     shell_selection_real_machine_tests
    /// ```
    #[test]
    #[ignore = "spawns real AppContainer children; run NON-elevated with --test-threads=1"]
    fn the_selected_shell_is_pwsh7_when_this_machine_has_one() {
        let workspace = tempfile::tempdir().expect("workspace tempdir");
        preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
        grant_job::wait_until_done().expect("background grant job");

        let (shell, label) = resolve_shell();
        println!("[shell selection] selected {label} ({shell})");

        // **対で見る**（B-35）——pwshがある機では選ばれ、無い機では5.1が選ばれる。
        // 片側だけを固定すると、選択機構が死んでいても（常に5.1でも）緑になる。
        match which::which("pwsh") {
            Ok(pwsh) => assert_eq!(
                label,
                PWSH_LABEL,
                "pwshが{}に在るのに5.1へ落ちた。preflightのwarningsに理由が出ているはず",
                pwsh.display()
            ),
            Err(_) => assert_eq!(
                label, POWERSHELL51_LABEL,
                "pwshが無い機では5.1が選ばれなければならない"
            ),
        }

        // 選ばれたシェルが**実際にworkspaceのFS I/Oまで通る**こと（preflight本体と同じ判定を、
        // 選択後の状態でもう一度当てる。ここが通れば`run_shell`も同じexeで走る）。
        let sid = ensure_profile(&crate::tier2a::session_profile::current_profile_name())
            .expect("session profile");
        let workspace_cap = super::super::workspace_capability_sid(
            &workspace.path().canonicalize().unwrap_or_default(),
            "rwx",
        )
        .expect("workspace capability");
        let probe_dir = workspace.path().join(".harness-shell-selection-probe");
        std::fs::create_dir_all(&probe_dir).expect("probe dir");
        let result = smoke_test_spawn(
            sid.as_psid(),
            Some(workspace_cap.as_psid()),
            &[],
            workspace.path(),
            &probe_dir,
        );
        let _ = std::fs::remove_dir_all(&probe_dir);
        result.expect("the selected shell must pass the same FS I/O probe preflight uses");
    }
}
