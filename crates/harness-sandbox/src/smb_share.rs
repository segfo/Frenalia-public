//! Tier3ワークスペースのCIFSライブ共有（`plans/DESIGN-SANDBOX-VMISOLATION.md`§2.4の
//! ライブ共有方式）で、Windowsホスト側に作る使い捨てSMB共有・使い捨てローカルアカウントの
//! ライフサイクル管理。
//!
//! **設計判断（`harness-vmsandboxd`は既にD-21でUAC昇格済みデーモンであるため）**: ここで
//! `New-SmbShare`/`New-LocalUser`/`New-NetFirewallRule`を叩くのに新規の特権昇格経路は
//! 要らない。`vmsandbox::run_powershell`と同じPowerShell shell-outパターンをそのまま使う。
//!
//! セッションごとに使い捨てのローカルアカウント＋パスワード（Incusペアリングの「使い捨て
//! トークン」と同じ思想）を発行し、そのアカウントだけに共有への`FullAccess`を与える
//! （`New-SmbShare`はACLパラメータを省略すると既定で`Everyone: Read`を付与してしまうため、
//! 必ず明示する）。
//!
//! **実機検証済み（S1スパイク、2026-07-27）**: `grant_ace_inheritable_rw`によるNTFS付与・
//! `revoke_ace_recursive`による取り消し・実際のSMBマウント経由read/write許可/拒否の一連は
//! `smb_mount_access_is_granted_then_actually_revoked`（本ファイル末尾、`#[ignore]`）で
//! 実機確認済み。`vmsandbox::VmSession::attach_to_guest`への統合（CIFSライブ共有の
//! 作成・再利用・修復判定）も完了している（`docs/bugs/BUG-026.md`参照）。

use std::path::Path;
use std::process::Stdio;

use rand::Rng;

use crate::vmsandbox::VmError;
use crate::win_appcontainer::{grant_ace_inheritable_rw, revoke_ace_recursive};

/// `New-LocalUser`のアカウント名。Windowsローカルアカウント名の20文字制限に収まるよう、
/// `workspace_id`（`short_id(canonicalized workspace_root)`、`vmsandbox::compute_workspace_id`
/// 参照）から短縮識別子だけを使う。**【2026-07-27・Phase B】キーを`session_id`から
/// `workspace_id`へ変更した**（`DESIGN-SANDBOX-VMISOLATION.md`項目6-a資源仕分け表: SMB共有・
/// 使い捨てアカウント・NTFS ACEは「ワークスペース単位・参照カウント共有」であり、
/// 「セッション単位」ではない。同一ワークスペースを複数セッションが共有する場合、2セッション目
/// 以降はこの名前を新規作成せず既存のものを再利用する——呼び出し側（`vmsandbox.rs`の
/// `VmSession::start`）が`vm_ledger::record_workspace_resource`の参照カウントを見て
/// 判断する）。
pub fn ephemeral_user_name(workspace_id: &str) -> String {
    format!("hns3-{}", short_id(workspace_id))
}

/// `New-SmbShare`の共有名。[`ephemeral_user_name`]と同じく`workspace_id`キー。
pub fn ephemeral_share_name(workspace_id: &str) -> String {
    format!("harness-ws-{}", short_id(workspace_id))
}

/// `workspace_root`から`workspace_id`（`short_id(canonicalized workspace_root)`、
/// `DESIGN-SANDBOX-VMISOLATION.md`項目6-a）を計算する。呼び出し側は`workspace_root`を
/// 正規化済みであることを前提としない（`std::fs::canonicalize`をここで行う）——ただし
/// `vmsandboxd.rs`の`authorize_workspace_root`が`StartSession`受理時に既に一度
/// canonicalizeしているため、実運用上は二重canonicalizeになる（副作用はなく、単なる
/// 冪等な再計算）。
pub fn compute_workspace_id(workspace_root: &Path) -> String {
    let canonical = std::fs::canonicalize(workspace_root)
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    short_id(&canonical.to_string_lossy())
}

/// 任意の文字列キーから衝突しにくい短い識別子を作る（アカウント名/共有名の文字数制限のため、
/// キー全体ではなくこれを使う）。暗号論的な一意性は不要だが、念のためFNV-1aハッシュの
/// 16進8桁を使う。**B-4**: 衝突自体は稀だが起き得るため、`create_ephemeral_share`側で
/// `New-LocalUser`の失敗を衝突として検知し別suffixでリトライする（同関数のdoc参照）。
fn short_id(key: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in key.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{:08x}", (hash & 0xffff_ffff) as u32)
}

/// セッション使い捨てのSMBアカウントパスワードを生成する（OSのCSPRNG経由、
/// `unique_session_id`のPID+タイムスタンプとは異なり実際に秘密として使うため）。
fn generate_password() -> String {
    const CHARSET: &[u8] =
        b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%^&*-_=+";
    let mut rng = rand::rng();
    (0..32)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// `script`をargv経由ではなくstdin経由でPowerShellへ渡す（`-Command -`はコマンドを
/// 標準入力から読む指示）。パスワード等の機密情報をコマンドラインへ一切載せないための
/// `vmsandbox::run_powershell`の亜種（既存`ssh_push_file`が確立した「機密情報はstdin経由」
/// という規律の横展開）。**同一マシン上の他プロセスが`tasklist /v`等でコマンドラインを
/// 観測してもパスワードが見えない**ことがこの関数を新設する理由。
fn run_powershell_stdin(script: &str) -> Result<String, VmError> {
    let mut child = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", "-"])
        // `vmsandbox::run_powershell`と同じ罠（実機で再現・特定済み、同関数のdoc参照）:
        // 常駐管理者pwsh(7)セッションから起動すると継承した`PSModulePath`のせいで
        // `Microsoft.PowerShell.Security`のオートロードが壊れ、`ConvertTo-SecureString`が
        // 非終端エラーで静かに失敗し`$securePassword`が`$null`のまま`New-LocalUser`へ渡る。
        .env_remove("PSModulePath")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| VmError::PowerShell(format!("failed to spawn powershell.exe: {e}")))?;
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .ok_or_else(|| VmError::PowerShell("powershell stdin unavailable".to_string()))?
            .write_all(script.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(VmError::PowerShell(format!(
            "exit={:?} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// PowerShellの文字列リテラル内で安全に埋め込めるよう、シングルクォートを`''`へ
/// エスケープする（`New-LocalUser -Description`等、ユーザー由来ではない固定文字列にしか
/// 使わないが、念のため一般化しておく）。
fn ps_quote(s: &str) -> String {
    s.replace('\'', "''")
}

/// セッション使い捨てのSMB共有とローカルアカウントを作成する。戻り値は
/// `(share_name, user_name, password)`。呼び出し側はこの直後に
/// `crate::vm_ledger::record_smb_share`で台帳へ追記し、`password`をSSH経由でゲストへ
/// credentials fileとして配布する（このモジュールはSSH配布自体は行わない）。
///
/// **NTFSアクセス権の付与（S1スパイクで実機検証済み）**: `New-SmbShare -FullAccess`は
/// SMB共有レベルの権限のみで、`workspace_root`自体のNTFS DACLへは何もしない。使い捨て
/// ローカルアカウントが実際にファイル読み書きできるかは`workspace_root`の既存NTFS ACLに
/// 依存してしまうため、`win_appcontainer::grant_ace_inheritable_rw`（単一オブジェクトAPI、
/// 子孫を一切走査しない）でルート1件へ継承ACEを付与する。実機計測で数百ファイル規模でも
/// 数十ms・体感1秒未満で完了することを確認済み（`plans/vm-spike/RESULTS.md`関連の教訓、
/// BUG-011のような素朴な再帰付与の病的な遅さとは無縁）。
/// [`create_ephemeral_share`]が実行するPowerShellスクリプトの構築部分だけを切り出したもの
/// （単体テストで実際に`New-LocalUser`/`New-SmbShare`を実行せずにエスケープ漏れを検証する
/// ため）。`user`/`share`/`password`/`path`のすべてを`ps_quote`でエスケープすることが
/// このモジュールの規律（S-2段階7、`path`だけ漏れていたのが実際のバグだった）。
fn build_create_share_script(
    user: &str,
    share: &str,
    password: &str,
    workspace_root: &Path,
    computer: &str,
) -> String {
    format!(
        r#"
$ErrorActionPreference = 'Stop'
$securePassword = ConvertTo-SecureString '{password}' -AsPlainText -Force
New-LocalUser -Name '{user}' -Password $securePassword -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -Description 'harness tier3 ephemeral ({user})' | Out-Null
New-SmbShare -Name '{share}' -Path '{path}' -FullAccess '{computer}\{user}' -CachingMode None | Out-Null
(Get-LocalUser -Name '{user}').SID.Value
"#,
        password = ps_quote(password),
        user = ps_quote(user),
        share = ps_quote(share),
        path = ps_quote(&workspace_root.to_string_lossy()),
        computer = computer,
    )
}

/// ワークスペース単位（`workspace_id`キー、`DESIGN-SANDBOX-VMISOLATION.md`項目6-a）の
/// 使い捨てSMB共有＋ローカルアカウントを新規作成する。**呼び出し側（`vmsandbox.rs`の
/// `VmSession::start`）は、同一`workspace_id`の資源が既に存在する（参照カウント>0、
/// `vm_ledger::record_workspace_resource`）場合はこの関数を呼ばず既存の共有・アカウントを
/// 再利用する**——本関数は「新規作成」の一択のみを扱う。
///
/// 戻り値は`(share_name, user_name, password, user_sid)`。`user_sid`は`vm_ledger`へ記録して
/// おくことで、daemon死亡後のGCでアカウント名からSIDを解決できなくなっていても
/// （`Remove-LocalUser`済み等）NTFS ACEを取り消せるようにする（A-5）。
///
/// **B-4**: `New-LocalUser`は同名アカウントが既に存在すると失敗する。`workspace_id`の
/// `short_id`（FNV-1a 32bit）衝突は稀だが、衝突時にセッション開始自体が失敗するのは
/// 避けたいため、失敗時は別suffixを付けて最大4回までリトライする。
pub fn create_ephemeral_share(workspace_id: &str, workspace_root: &Path) -> Result<(String, String, String, String), VmError> {
    let password = generate_password();
    let computer = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "localhost".to_string());

    let mut last_err = None;
    for attempt in 0..4u8 {
        let suffixed_key = if attempt == 0 {
            workspace_id.to_string()
        } else {
            format!("{workspace_id}-{attempt}")
        };
        let user = ephemeral_user_name(&suffixed_key);
        let share = ephemeral_share_name(&suffixed_key);

        // パスワードを含むためstdin経由（argv上に露出させない）。SIDは直後のNTFS付与に使うため
        // 最後の行で出力する（`run_powershell_stdin`はstdoutをtrimして1文字列として返す）。
        let script = build_create_share_script(&user, &share, &password, workspace_root, &computer);
        match run_powershell_stdin(&script) {
            Ok(sid_string) => {
                let sid_owned = unsafe {
                    let sid_w = crate::win_common::wide(&sid_string);
                    let mut psid = windows::Win32::Security::PSID::default();
                    windows::Win32::Security::Authorization::ConvertStringSidToSidW(
                        windows::core::PCWSTR(sid_w.as_ptr()),
                        &mut psid,
                    )
                    .map_err(|e| VmError::PowerShell(format!("failed to parse SID '{sid_string}': {e}")))?;
                    psid
                };
                if let Err(e) = grant_ace_inheritable_rw(workspace_root, sid_owned) {
                    // [BUG-028] `run_powershell_stdin`は既に共有・使い捨てアカウントを実際に
                    // 作成済みの状態でしか`Ok`を返さない。ここでNTFS付与が失敗した場合、
                    // それらを孤児化させないその場でbest-effortに削除する
                    // （`destroy_ephemeral_share`はNTFS取消も含めbest-effort、失敗しても無視）。
                    destroy_ephemeral_share(&share, &user, Some(workspace_root));
                    return Err(VmError::PowerShell(format!(
                        "failed to grant NTFS access to {user}: {e:?}"
                    )));
                }
                return Ok((share, user, password, sid_string));
            }
            Err(e) => {
                // `New-LocalUser`の名前衝突かどうかを区別せず、単純に次のsuffixへ進む
                // （衝突以外の失敗——PowerShellそのものの不調等——でも同じ扱いで問題ない。
                // 4回とも失敗すれば最後のエラーをそのまま返す）。
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        VmError::PowerShell("create_ephemeral_share: exhausted retries".to_string())
    }))
}

/// `create_ephemeral_share`が作った共有・アカウント・NTFS付与を破棄する。**呼び出し側は
/// `workspace_id`の参照カウントが0になった最後の1セッションのteardownでのみこの関数を
/// 呼ぶこと**（`vm_ledger::release_workspace_resource`が`Some`を返した場合のみ）。共有を
/// 先に外してからアカウントを削除する（逆順だと一瞬孤児共有が残る）。NTFS ACEの取り消し
/// （`revoke_ace_recursive`、S1スパイクで継承ACEの取り消し漏れを修正済み）は、アカウントを
/// 消す**前**に行う必要がある（消した後だとSIDはもう解決できないが、ACE自体はDACLに
/// 解決不能なSIDとして残り続けるため）。個別の失敗はbest-effortで無視し可能な範囲を試みる
/// （`gc_orphan_sessions`からの再試行に任せる、`teardown_vm`と同じ方針）。
///
/// `workspace_root`が`None`の場合（呼び出し側が`workspace_root`を保持していない経路専用）は
/// NTFS revokeをスキップし、共有・アカウントの削除のみ行う。**Phase B以降、GC経路
/// （`gc_orphan_sessions`）は`vm_ledger::WorkspaceResourceEntry::workspace_root`を記録済み
/// なので`Some`を渡せるようになった（A-5解消）**——`None`はこの構造上もう到達し得ないはずだが、
/// 呼び出し側の実装ミスに対する防御的なフォールバックとして残す。
pub fn destroy_ephemeral_share(share_name: &str, user_name: &str, workspace_root: Option<&Path>) {
    if let Some(workspace_root) = workspace_root {
        if let Ok(sid_string) = crate::vmsandbox::run_powershell(&format!(
            "(Get-LocalUser -Name '{user_name}' -ErrorAction Stop).SID.Value"
        )) {
            let sid_result = unsafe {
                let sid_w = crate::win_common::wide(&sid_string);
                let mut psid = windows::Win32::Security::PSID::default();
                windows::Win32::Security::Authorization::ConvertStringSidToSidW(
                    windows::core::PCWSTR(sid_w.as_ptr()),
                    &mut psid,
                )
                .map(|_| psid)
            };
            if let Ok(sid_owned) = sid_result {
                let _ = revoke_ace_recursive(workspace_root, sid_owned);
            }
        }
    }

    let _ = crate::vmsandbox::run_powershell(&format!(
        "Remove-SmbShare -Name '{share_name}' -Force -ErrorAction SilentlyContinue"
    ));
    let _ = crate::vmsandbox::run_powershell(&format!(
        "Remove-LocalUser -Name '{user_name}' -ErrorAction SilentlyContinue"
    ));
}

/// BUG-026の修復（状態S4/S6、`docs/bugs/BUG-026.md`）向け: 台帳エントリはあるがゲスト側
/// マウントが不健全な場合に、既存のSMB共有・NTFS ACEはそのまま流用し、使い捨てアカウントの
/// パスワードだけをローテーションする。共有・NTFS付与を作り直すコストを避けるため
/// （実リポジトリ規模では revoke 約11秒+grant 約4秒かかる、`RESULTS.md`参照）。
///
/// アカウント自体が既に存在しない場合（状態S4/S5、`Set-LocalUser`が対象無しで失敗する）は
/// `Err`を返す。呼び出し側はこれを「作り直しが必要」の合図として扱い、
/// `destroy_ephemeral_share`→`create_ephemeral_share`のフルリカバリへフォールバックする。
pub fn rotate_share_password(user: &str) -> Result<String, VmError> {
    let password = generate_password();
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$securePassword = ConvertTo-SecureString '{password}' -AsPlainText -Force
Set-LocalUser -Name '{user}' -Password $securePassword -ErrorAction Stop
"#,
        password = ps_quote(&password),
        user = ps_quote(user),
    );
    run_powershell_stdin(&script)?;
    Ok(password)
}

/// BUG-026 F4（GCの回収）向け: 台帳に載っていないWindows側実体（状態S2/S3、
/// `docs/bugs/BUG-026.md`の状態表参照）を実際に列挙する。`record_workspace_resource`の
/// 呼び出し前に失敗した場合（`New-LocalUser`名前衝突後の別suffixでの作り直し等）、
/// 台帳からは不可視のまま共有・アカウント・NTFS ACEが残り続けるため、
/// `Get-SmbShare`/`Get-LocalUser`で命名規則（`harness-ws-*`/`hns3-*`）に基づき実体側から
/// 直接走査する。共有の`Path`プロパティから`workspace_root`が取れるため、
/// `destroy_ephemeral_share`によるNTFS ACE取り消しまで行える。
///
/// 戻り値は`(share_name, user_name, workspace_root)`のリスト。台帳との突合（どれが本当に
/// 孤児か）は呼び出し側（`gc_orphan_sessions`）が行う。
pub fn enumerate_windows_workspace_shares() -> Vec<(String, String, std::path::PathBuf)> {
    let script = r#"
Get-SmbShare -Name 'harness-ws-*' -ErrorAction SilentlyContinue |
    ForEach-Object { "$($_.Name)`t$($_.Path)" }
"#;
    let Ok(stdout) = crate::vmsandbox::run_powershell(script) else {
        return Vec::new();
    };
    parse_workspace_share_listing(&stdout)
}

/// [`enumerate_windows_workspace_shares`]のPowerShell出力パース部分だけを切り出したもの
/// （単体テストで実際に`Get-SmbShare`を実行せずに検証するため、`build_create_share_script`と
/// 同じ分離の方針）。
fn parse_workspace_share_listing(stdout: &str) -> Vec<(String, String, std::path::PathBuf)> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(2, '\t');
            let share = parts.next()?.trim();
            let path = parts.next()?.trim();
            if share.is_empty() || path.is_empty() {
                return None;
            }
            // 共有名からアカウント名を導出する（`ephemeral_user_name`/`ephemeral_share_name`は
            // 同じ`short_id`サフィックスを共有する命名規則、本ファイル冒頭参照）。
            let suffix = share.strip_prefix("harness-ws-")?;
            Some((
                share.to_string(),
                format!("hns3-{suffix}"),
                std::path::PathBuf::from(path),
            ))
        })
        .collect()
}

/// 内部vSwitch（`switch_name`）に対応するホストのvEthernetアダプタだけへSMB(445)の受信を
/// 許可するファイアウォールルールを、daemon起動時に1回だけ冪等に作成する
/// （`plans/vm-spike/05-network-acl-enforce.ps1:38-40`と同じホストNIC探索パターン）。
/// 既定の「ファイルとプリンターの共有(SMB-受信)」ルールは無効化せず、`subnet_cidr`で
/// スコープを絞るに留める（他の正当なSMB利用を壊さないため、ユーザー確認済みの方針）。
pub fn ensure_smb_firewall_rule(switch_name: &str, subnet_cidr: &str) -> Result<(), VmError> {
    let rule_name = "harness-tier3-smb-inbound";
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
if (-not (Get-NetFirewallRule -Name '{rule_name}' -ErrorAction SilentlyContinue)) {{
    $adapter = Get-NetAdapter | Where-Object {{ $_.Name -match [regex]::Escape('{switch_name}') }}
    if (-not $adapter) {{
        throw "internal vSwitch host adapter not found: {switch_name}"
    }}
    New-NetFirewallRule -Name '{rule_name}' -DisplayName 'Harness Tier3 SMB (internal vSwitch only)' `
        -Direction Inbound -Protocol TCP -LocalPort 445 -InterfaceAlias $adapter.Name -Action Allow | Out-Null
}}
Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction SilentlyContinue |
    Get-NetFirewallAddressFilter | Where-Object {{ $_.RemoteAddress -notcontains '{subnet_cidr}' }} |
    ForEach-Object {{ Set-NetFirewallAddressFilter -InputObject $_ -RemoteAddress '{subnet_cidr}' }}
"#,
        rule_name = rule_name,
        switch_name = ps_quote(switch_name),
        subnet_cidr = subnet_cidr,
    );
    crate::vmsandbox::run_powershell(&script)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_id_is_deterministic_and_fixed_length() {
        let a = short_id("harness-tier3-1234-5678");
        let b = short_id("harness-tier3-1234-5678");
        assert_eq!(a, b);
        assert_eq!(a.len(), 8);
    }

    #[test]
    fn ephemeral_names_stay_within_windows_username_length_limit() {
        let session_id = "harness-tier3-999999-1234567890123";
        let user = ephemeral_user_name(session_id);
        // Windowsローカルアカウント名は20文字まで。
        assert!(user.len() <= 20, "user name too long: {user}");
    }

    #[test]
    fn generate_password_produces_sufficient_length_and_varies() {
        let a = generate_password();
        let b = generate_password();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
    }

    /// S-2段階7の回帰テスト: `workspace_root`にシングルクォートを含む場合でも、
    /// 生成スクリプトの`New-SmbShare -Path '...'`行がクォートで正しく閉じること
    /// （修正前は`path`だけ`ps_quote`が漏れており、ここでスクリプトが壊れていた）。
    #[test]
    fn build_create_share_script_escapes_single_quote_in_workspace_root() {
        let path = Path::new(r"C:\work\it's a repo");
        let script = build_create_share_script("hns3-aaaaaaaa", "harness-ws-aaaaaaaa", "pw", path, "HOST");
        assert!(
            script.contains(r"-Path 'C:\work\it''s a repo'"),
            "expected the path to be escaped in the generated script, got: {script}"
        );
        // エスケープ漏れの症状（生の`'`がそのまま出力へ紛れ込む）が無いことも直接確認する。
        assert!(!script.contains(r"-Path 'C:\work\it's a repo'"));
    }

    #[test]
    fn ps_quote_escapes_single_quotes() {
        assert_eq!(ps_quote("it's"), "it''s");
    }

    /// BUG-026 F4回帰: `Get-SmbShare`の出力パースが共有名からアカウント名を正しく導出し、
    /// タブ区切り・空行・命名規則に合わない行を適切に無視することを検証する。
    #[test]
    fn parse_workspace_share_listing_extracts_share_user_and_path() {
        let stdout = "harness-ws-62d45a6b\tC:\\work\\project\nharness-ws-abcd1234\tC:\\other\\repo\n";
        let parsed = parse_workspace_share_listing(stdout);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "harness-ws-62d45a6b");
        assert_eq!(parsed[0].1, "hns3-62d45a6b");
        assert_eq!(parsed[0].2, std::path::PathBuf::from("C:\\work\\project"));
        assert_eq!(parsed[1].0, "harness-ws-abcd1234");
        assert_eq!(parsed[1].1, "hns3-abcd1234");
    }

    #[test]
    fn parse_workspace_share_listing_ignores_malformed_or_empty_lines() {
        let stdout = "\nnot-a-harness-share\tC:\\x\n\tC:\\missing-name\nharness-ws-only-name\n";
        assert!(parse_workspace_share_listing(stdout).is_empty());
    }

    #[test]
    fn parse_workspace_share_listing_handles_empty_input() {
        assert!(parse_workspace_share_listing("").is_empty());
    }

    /// [SMBマウント検証スパイク] `create_ephemeral_share`/`destroy_ephemeral_share`が実際に
    /// SMB経由（`\\localhost\<share>`、実際のネットワーク認証・共有権限・NTFS権限を全て通る
    /// 経路）でread/writeを許可/拒否できることを実機検証する。対象はharnessリポジトリ全体では
    /// なく、リポジトリ配下の使い捨てスクラッチディレクトリ（`plans/vm-spike/smb-spike-tmp`）に
    /// 限定する（ユーザー確認済みの方針。revoke側にS1で発見したバグの再発が万一あった場合でも、
    /// リポジトリ全体のACLへ影響が及ぶリスクを避けるため）。
    ///
    /// 検証の要点: NTFS ACE取り消し（`revoke_ace_recursive`）**だけ**を先に単独実行し、共有・
    /// アカウント自体はまだ生きている状態でSMBアクセスが拒否されることを確認する。これにより
    /// 「アクセスできなくなったのは共有/アカウントが消えたからではなく、NTFS権限が正しく
    /// 取り消されたから」であることを、共有レベル権限とは独立に証明できる。
    #[test]
    #[ignore]
    fn smb_mount_access_is_granted_then_actually_revoked() {
        let unique = std::process::id();
        let session_id = format!("smbspike{unique}");
        let repo_root =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../plans/vm-spike");
        let scratch = repo_root
            .canonicalize()
            .expect("plans/vm-spike must exist")
            .join(format!("smb-spike-tmp-{unique}"));
        std::fs::create_dir_all(&scratch).expect("create scratch dir");
        std::fs::write(scratch.join("preexisting.txt"), b"hello from host")
            .expect("seed preexisting file");

        let cleanup = || {
            let _ = std::fs::remove_dir_all(&scratch);
        };

        let result = (|| -> Result<(), String> {
            let (share, user, password, _sid) = create_ephemeral_share(&session_id, &scratch)
                .map_err(|e| format!("create_ephemeral_share failed: {e:?}"))?;

            let unc = format!(r"\\localhost\{share}");

            // (1) 共有・アカウント・NTFS付与すべて生きている状態で、実際にSMB経由の
            // read/writeが機能することを確認する。
            let connect_script = format!(
                r#"
$ErrorActionPreference = 'Stop'
net use '{unc}' /user:localhost\{user} '{password}' | Out-Null
if ($LASTEXITCODE -ne 0) {{ throw "net use failed with exit $LASTEXITCODE" }}
"#
            );
            run_ps(&connect_script)
                .map_err(|e| format!("net use (initial connect) failed: {e}"))?;

            let read_ok = run_ps_bool(&format!(
                "Get-Content -LiteralPath '{unc}\\preexisting.txt' -ErrorAction Stop | Out-Null"
            ));
            let write_ok = run_ps_bool(&format!(
                "'written over smb' | Set-Content -LiteralPath '{unc}\\from-smb.txt' -ErrorAction Stop"
            ));
            let _ = run_ps(&format!("net use '{unc}' /delete /y"));

            if !read_ok {
                return Err("expected to be able to read preexisting.txt over SMB after grant".to_string());
            }
            if !write_ok {
                return Err("expected to be able to write a new file over SMB after grant".to_string());
            }

            // (2) NTFS ACE取り消しだけを単独実行する（共有・アカウントはまだ生かしたまま）。
            let sid_string = run_ps_capture(&format!(
                "(Get-LocalUser -Name '{user}').SID.Value"
            ))
            .map_err(|e| format!("failed to look up SID before revoke: {e}"))?;
            let sid_owned = unsafe {
                let sid_w = crate::win_common::wide(&sid_string);
                let mut psid = windows::Win32::Security::PSID::default();
                windows::Win32::Security::Authorization::ConvertStringSidToSidW(
                    windows::core::PCWSTR(sid_w.as_ptr()),
                    &mut psid,
                )
                .map_err(|e| format!("ConvertStringSidToSidW failed: {e}"))?;
                psid
            };
            revoke_ace_recursive(&scratch, sid_owned)
                .map_err(|e| format!("revoke_ace_recursive failed: {e:?}"))?;

            // (3) 共有・アカウントはまだ存在するので再接続自体は成功するはずだが、NTFS権限が
            // 無くなっているためread/writeは拒否されるはず。
            run_ps(&connect_script)
                .map_err(|e| format!("net use (post-revoke reconnect) failed: {e}"))?;
            let read_after_revoke = run_ps_bool(&format!(
                "Get-Content -LiteralPath '{unc}\\preexisting.txt' -ErrorAction Stop | Out-Null"
            ));
            let _ = run_ps(&format!("net use '{unc}' /delete /y"));

            if read_after_revoke {
                return Err(
                    "after revoke_ace_recursive, SMB read must be denied (share/account still \
                     exist at this point, only the NTFS ACE was removed) — proves the NTFS \
                     revoke, not account/share teardown, is what enforces access"
                        .to_string(),
                );
            }

            destroy_ephemeral_share(&share, &user, Some(&scratch));
            Ok(())
        })();

        cleanup();
        result.expect("SMB mount verification spike must succeed end-to-end");
    }

    /// PowerShellを`-Command`経由で実行し成否だけ見る（`net use`等、副作用のみに関心がある
    /// 呼び出し用）。
    fn run_ps(script: &str) -> Result<(), String> {
        let output = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .env_remove("PSModulePath")
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(format!(
                "exit={:?} stdout={} stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(())
    }

    /// PowerShellスクリプトを実行し、成功/失敗をboolへ潰す（read/writeの許可・拒否確認用、
    /// `run_ps`と異なりエラー内容は捨てる——許可/拒否の2値だけが関心事のため）。
    fn run_ps_bool(script: &str) -> bool {
        run_ps(script).is_ok()
    }

    /// PowerShellスクリプトの標準出力を1文字列として取得する（SID文字列取得用）。
    fn run_ps_capture(script: &str) -> Result<String, String> {
        let output = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .env_remove("PSModulePath")
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(format!(
                "exit={:?} stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// [実リポジトリ本体での検証] ユーザー指示による5段階検証のうち、最終段（このharness
    /// リポジトリのルート自体、`target/`込みの実規模＝約57,000ファイル、14GB）への実適用。
    /// スクラッチディレクトリでの検証（`smb_mount_access_is_granted_then_actually_revoked`）は
    /// 数百ファイル規模だったが、Tier1aの`grant_ace_inheritable_ro`/`_rw`が実運用で処理する
    /// のはこの規模（MSVCツールチェーン等）であり、「Tier1aと同等」を主張するならこの規模で
    /// 実際に速いことを示す必要がある、というのがこのテストの動機。
    ///
    /// **安全策**: `assert!`ではなくすべて`Err`返却にして、途中で条件を満たさなくても
    /// パニックで巻き戻し処理を飛ばさないようにする（実リポジトリへの変更のため、
    /// revoke/共有削除を確実に実行してから最後に成否を確定させる）。事前に`icacls`で
    /// ルートのベースラインDACLを記録し（本テストのassert対象ではなく、テスト実行者が
    /// 目視で比較できるようログへ出力するのみ）、事後に同じユーザーのACEが残っていないかも
    /// 確認する。
    #[test]
    #[ignore]
    fn real_repo_root_smb_grant_revoke_at_full_scale() {
        let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repo root must resolve");
        println!("=== repo root under test: {} ===", repo_root.display());

        let baseline_acl = run_ps_capture(&format!(
            "icacls '{}'",
            repo_root.display()
        ))
        .unwrap_or_else(|e| format!("<failed to capture baseline: {e}>"));
        println!("=== baseline ACL (before grant) ===\n{baseline_acl}");

        let unique = std::process::id();
        let session_id = format!("reporoot{unique}");

        let result = (|| -> Result<(), String> {
            let t_grant = std::time::Instant::now();
            let (share, user, password, _sid) = create_ephemeral_share(&session_id, &repo_root)
                .map_err(|e| format!("create_ephemeral_share (grant included) failed: {e:?}"))?;
            let grant_elapsed = t_grant.elapsed();
            println!("=== real repo root (~57k files incl. target/) create_ephemeral_share (incl. grant_ace_inheritable_rw) took {grant_elapsed:?} ===");

            let unc = format!(r"\\localhost\{share}");
            let connect_script = format!(
                r#"
$ErrorActionPreference = 'Stop'
net use '{unc}' /user:localhost\{user} '{password}' | Out-Null
if ($LASTEXITCODE -ne 0) {{ throw "net use failed with exit $LASTEXITCODE" }}
"#
            );
            run_ps(&connect_script).map_err(|e| format!("net use (connect) failed: {e}"))?;

            let read_ok = run_ps_bool(&format!(
                "Get-Content -LiteralPath '{unc}\\CLAUDE.md' -TotalCount 1 -ErrorAction Stop | Out-Null"
            ));
            let _ = run_ps(&format!("net use '{unc}' /delete /y"));
            if !read_ok {
                return Err("expected to read CLAUDE.md over SMB after grant on real repo root".to_string());
            }

            let sid_string = run_ps_capture(&format!("(Get-LocalUser -Name '{user}').SID.Value"))
                .map_err(|e| format!("SID lookup before revoke failed: {e}"))?;
            let sid_owned = unsafe {
                let sid_w = crate::win_common::wide(&sid_string);
                let mut psid = windows::Win32::Security::PSID::default();
                windows::Win32::Security::Authorization::ConvertStringSidToSidW(
                    windows::core::PCWSTR(sid_w.as_ptr()),
                    &mut psid,
                )
                .map_err(|e| format!("ConvertStringSidToSidW failed: {e}"))?;
                psid
            };

            let t_revoke = std::time::Instant::now();
            revoke_ace_recursive(&repo_root, sid_owned)
                .map_err(|e| format!("revoke_ace_recursive on real repo root failed: {e:?}"))?;
            let revoke_elapsed = t_revoke.elapsed();
            println!("=== real repo root (~57k files incl. target/) revoke_ace_recursive took {revoke_elapsed:?} ===");

            run_ps(&connect_script)
                .map_err(|e| format!("net use (post-revoke reconnect) failed: {e}"))?;
            let read_after_revoke = run_ps_bool(&format!(
                "Get-Content -LiteralPath '{unc}\\CLAUDE.md' -TotalCount 1 -ErrorAction Stop | Out-Null"
            ));
            let _ = run_ps(&format!("net use '{unc}' /delete /y"));

            destroy_ephemeral_share(&share, &user, Some(&repo_root));

            if read_after_revoke {
                return Err(
                    "after revoke_ace_recursive, SMB read of the real repo must be denied"
                        .to_string(),
                );
            }
            Ok(())
        })();

        let after_acl = run_ps_capture(&format!("icacls '{}'", repo_root.display()))
            .unwrap_or_else(|e| format!("<failed to capture post-test ACL: {e}>"));
        println!("=== ACL after test (should match baseline, modulo ordering) ===\n{after_acl}");

        result.expect("real repo root SMB grant/revoke verification must succeed end-to-end");
    }
}
