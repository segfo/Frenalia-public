//! **N1: AppContainerごとの証明書ストアはどこまで効くか**の実現性スパイク。
//! 結果の正本は`plans/net-spike/RESULTS.md`（Journal）、決定の正本は
//! `plans/AppContainerを用いたドメインベース通信制御アーキテクチャ設計書.md` §10.3のD-65である。
//!
//! ## 何を測るのか（**測定であって実装ではない**）
//!
//! D-65は「TLS終端に要るharnessのCAを、ユーザーのRootストアへは入れず**AppContainerごとの
//! 証明書ストア**（層1）へ入れる」と決めた。層1の構造がWindowsに実在することは実測済みだが
//! （`plans/net-spike/RESULTS.md` §1）、**harnessが作るlegacy AppContainer**
//! （`CreateAppContainerProfile`。パッケージ済みアプリではない）で成立するかは未測定である。
//!
//! | # | 問い | ここでの測り方 |
//! |---|---|---|
//! | a | legacy AppContainerでも同じ**リダイレクト**が掛かるか | コンテナの中からHKCU／証明書ストアへ書き、**物理的にどこへ落ちたか**を外から見る |
//! | b | チェーン構築（Schannelが使う`CertGetCertificateChain`）が**そこを読む**か | コンテナの中で`X509Chain.Build`（`SslStream`＝Schannelと同じ信頼判断の実体） |
//! | c | コンテナの**外から**書いたものを中が自分のストアとして見るか | 外から物理パスへ書いて中で列挙 |
//!
//! 問cが本命である——実運用で書く主体は**AppContainerの外**（harness本体）だからである。
//!
//! ## 測る順序（B-35: 禁止側だけを測らない）
//!
//! 1. **対照A**: CAをどこにも置かない状態で、中のチェーン構築が**失敗する**ことを確認する
//! 2. **本命**: 外からコンテナ専用ストアへ書いて、中から見えるか・信頼されるか
//! 3. **対照B**: 同じCAをユーザーのRootストアへ入れたとき中から見えるか
//!    （*切り分けの基準線*——ここも見えないなら証明書側の不備であって層1の話ではない。
//!    同時に「コンテナの視界がユーザーのストアへ落ちるか」も分かる）
//!
//! ## 実行（**昇格しないこと**）
//!
//! ```text
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture cert_store_spike_tests
//! ```
//!
//! `dev-elevated-run.exe`から回さない。理由は`mac_spike_tests`と同じで、昇格したテストから
//! AppContainer子を起こすと親トークンが管理者のものになり、測っている世界が実運用
//! （非昇格のharness）と変わる（`bug-pattern-rules` B-08）。**このスパイクは昇格を一切要さない**
//! ——書込先はHKCU配下、プロファイル作成も非昇格でできる。
//!
//! ## 走っている他セッションへ影響させない
//!
//! - プロファイルは**このスパイク専用の使い捨て名**（`harness.n1cert.<pid>`）を作り、必ず消す。
//!   共有の`harness.shell.sandbox*`（走行中のTier2aセッションのもの）には触らない。
//! - **loopback exemptionには触らない**。あれはマシン全体で1本のリストを全harnessセッションが
//!   共有しており（`tier2a::loopback_exemption`のdoc、BUG-053）、ここから足し引きすると
//!   走行中セッションの通信が黙って壊れる。そのため実クライアント（`curl.exe`・
//!   `Invoke-WebRequest`）でのTCP接続は**このスパイクでは撃たない**——信頼判断の実体である
//!   チェーン構築（`X509Chain`＝`CertGetCertificateChain`）を中で直接測る。
//!
//! ## 実マシンに残すもの（全てRAIIで撤収する）
//!
//! 使い捨てCAとリーフ（`Cert:\CurrentUser\My`、有効期間1日）・スパイク用プロファイル・
//! `HKCU:\Software\HarnessSpikeN1`・コンテナのStorageキー・作業用の一時ディレクトリ。
//! **対照Bで一時的にユーザーのRootストアへ入れるCAも、同じガードで必ず消す**
//! （D-65が恒久的な導入を名指しで禁じている）。
//!
//! ## 判定が出たらこのファイルは消す
//!
//! `docs/CODE-STRUCTURE-RULES.md`規則2（一回性の調査実験をテストとして残さない）。
//! 層1を採用するなら、そのときの回帰テストは**本番機構の側に**書き直す。

use std::path::Path;

use super::{ensure_profile_for_test, resolve_shell, spawn, DomainIdentity, NetworkCapability};

/// AppContainerごとのレジストリ領域（`plans/net-spike/RESULTS.md` §1で実在を確認した場所）。
const STORAGE_ROOT: &str = r"HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage";

/// 問aの「素のHKCU書込」の的。証明書ストアと違い、CryptoAPIの都合が混ざらない対照になる。
const PLAIN_HKCU_KEY: &str = r"HKCU:\Software\HarnessSpikeN1";

/// 外からCAを一時的に置く作業用ストア（CryptoAPIに`Blob`値を正しく組ませるための足場）。
const SCRATCH_STORE: &str = r"HKCU:\Software\Microsoft\SystemCertificates\HarnessN1Scratch";

/// このスパイクが作る使い捨てプロファイル名。**`session_profile::PROFILE_PREFIX`とは別系統**に
/// してあるので、走行中の他セッションのGC（`plan_reclaim`）の候補にならない。
fn spike_profile_name() -> String {
    format!("harness.n1cert.{}", std::process::id())
}

/// コンテナの中から**新しく作らせる**ストアの名前（フェーズごとに別名にして着地点を見分ける）。
/// 撤収は`HarnessN1In*`のワイルドカードで一括して行う。
fn custom_store_name(phase: &str) -> String {
    format!(
        "HarnessN1In{}",
        phase
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
    )
}

// ---------------------------------------------------------------------------
// PowerShellを動かすための最小の道具
// ---------------------------------------------------------------------------

/// `-EncodedCommand`用のbase64（UTF-16LE）。
///
/// スクリプトを`-Command`へ生で渡すと、`CreateProcessW`のコマンドライン整形（`spawn_impl`）と
/// PowerShellのパーサの二重引用符解釈が噛み合わず、**引用符を含むスクリプトが黙って別物になる**。
/// `base64`クレートを足さないのは、依存を1本増やすとworkspace全体の再ビルドが走り、
/// 並行して動いている他セッションの`cargo`まで巻き込むためである。
fn encoded_command(script: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bytes: Vec<u8> = Vec::new();
    for unit in script.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// **AppContainerの外**（通常トークン）でPowerShellを回す。
fn ps_outside(script: &str) -> (String, String, i32) {
    let (shell, _) = resolve_shell();
    let out = std::process::Command::new(&shell)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            &encoded_command(script),
        ])
        .output()
        .expect("run powershell outside the container");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

/// 子へ渡す環境変数。`spawn`は環境ブロックを**明示的に組む**（`build_env_block`）ので、
/// 空で渡すと子は環境変数を1つも持たない。
///
/// **本番と同じ`secret_env::build_child_env`（allowlist＋秘密除外）を使う。** 最初は
/// `SystemRoot`/`PATH`等だけを手で写していたが、`CreateProcessW`が
/// `ERROR_ENVVAR_NOT_FOUND`(0x800700CB)で落ちた——PowerShellの起動に要る変数の集合を
/// スパイク側で当て直す作業に意味は無く、`mac_spike_tests`の`SpikeSpawn`も同じ関数を使っている。
fn child_env() -> Vec<(String, String)> {
    crate::secret_env::build_child_env()
}

/// **AppContainerの中**でPowerShellを回す。`spawn`（本番と同じ経路）を使う。
///
/// cwdは`C:\Windows\System32`にしてある——ALL APPLICATION PACKAGESに読取実行が既定で
/// 付いており、workspaceのACE付与（`preflight`）を一切要さないためである。このスパイクは
/// 入力も出力もargvとstdoutだけで運ぶので、コンテナはファイルシステムへ触れる必要が無い。
fn ps_in_container(
    container_sid: windows::Win32::Security::PSID,
    script: &str,
) -> (String, String, i32) {
    ps_in_container_with_net(container_sid, script, NetworkCapability::Deny)
}

fn ps_in_container_with_net(
    container_sid: windows::Win32::Security::PSID,
    script: &str,
    net: NetworkCapability,
) -> (String, String, i32) {
    let (shell, _) = resolve_shell();
    let encoded = encoded_command(script);
    let child = spawn(
        &shell,
        &["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded],
        Path::new(r"C:\Windows\System32"),
        &child_env(),
        false,
        container_sid,
        net,
        super::RedirectorInject::default(),
        DomainIdentity::OwnPackage,
    )
    .expect("spawn powershell inside the spike AppContainer");
    child
        .write_stdin_read_output_and_wait(None)
        .expect("read the container child's output")
}

/// `KEY=VALUE`形式の出力から1件引く。
fn kv(out: &str, key: &str) -> Option<String> {
    out.lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
        .map(|v| v.trim_end().to_string())
}

/// 引けなければテストを落とす（測定そのものが成立していない）。
fn kv_req(out: &str, key: &str) -> String {
    kv(out, key).unwrap_or_else(|| panic!("出力に{key}=が無い。測定が成立していない:\n{out}"))
}

// ---------------------------------------------------------------------------
// 使い捨ての証明書
// ---------------------------------------------------------------------------

struct SpikeCerts {
    ca_der_b64: String,
    ca_thumb: String,
    leaf_der_b64: String,
    leaf_thumb: String,
}

/// 有効期間1日の使い捨てCAと、それが署名したリーフを`Cert:\CurrentUser\My`へ作る。
/// **Rootストアには入れない**（対照Bだけが、測る瞬間だけ入れる）。
///
/// 撤収は呼び出し側の`scopeguard`が`Remove-Item -DeleteKey`で行う（秘密鍵ごと消す）。
/// 1日で失効するのは、撤収がpanic等で飛んだ場合の被害を時間で頭打ちにするためである。
fn create_spike_certs() -> SpikeCerts {
    let script = r#"
$ErrorActionPreference = 'Stop'
$ca = New-SelfSignedCertificate -Type Custom -Subject 'CN=harness-n1-spike-ca' `
    -KeyUsage CertSign,CRLSign,DigitalSignature -KeyExportPolicy Exportable `
    -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1) `
    -TextExtension @('2.5.29.19={text}CA=1&pathlength=0')
$leaf = New-SelfSignedCertificate -Type Custom -Subject 'CN=harness-n1-spike-leaf' `
    -DnsName 'harness-n1-spike.invalid' -Signer $ca -KeyExportPolicy Exportable `
    -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1) `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1')
Write-Output ("CA_THUMB=" + $ca.Thumbprint)
Write-Output ("CA_DER_B64=" + [Convert]::ToBase64String($ca.GetRawCertData()))
Write-Output ("LEAF_THUMB=" + $leaf.Thumbprint)
Write-Output ("LEAF_DER_B64=" + [Convert]::ToBase64String($leaf.GetRawCertData()))
"#;
    let (out, err, code) = ps_outside(script);
    assert_eq!(
        code, 0,
        "使い捨て証明書の生成に失敗した: out={out} err={err}"
    );
    SpikeCerts {
        ca_thumb: kv_req(&out, "CA_THUMB"),
        ca_der_b64: kv_req(&out, "CA_DER_B64"),
        leaf_thumb: kv_req(&out, "LEAF_THUMB"),
        leaf_der_b64: kv_req(&out, "LEAF_DER_B64"),
    }
}

/// 測定が残し得る痕跡を全部剥がす。**assertで落ちても走る**ようにガードから呼ぶ。
fn cleanup_all(certs: &(String, String), profile: &str) {
    let (ca_thumb, leaf_thumb) = certs;
    let script = TEMPLATE_CLEANUP
        .replace("%%CA_THUMB%%", ca_thumb)
        .replace("%%LEAF_THUMB%%", leaf_thumb)
        .replace("%%PLAIN%%", PLAIN_HKCU_KEY)
        .replace("%%SCRATCH%%", SCRATCH_STORE)
        .replace("%%STORAGE%%", STORAGE_ROOT)
        .replace("%%PROFILE%%", profile);
    let (out, err, _) = ps_outside(&script);
    eprintln!("[N1] cleanup: out={out:?} err={err:?}");
    // **黙って残さない**。`Drop`の中なので既にpanicしている最中かもしれず、二重panicで
    // プロセスが即死すると原因が読めなくなる——`panicking()`のときは大きく警告して残す。
    if kv(&out, "RESIDUE_CERTS").as_deref() != Some("0") {
        let msg = format!(
            "後始末が終わっていない: スパイクの証明書がユーザーのストアに残っている（{out}）。\
             `Cert:\\CurrentUser\\Root`等から手で消すこと"
        );
        if std::thread::panicking() {
            eprintln!("[N1][!!] {msg}");
        } else {
            panic!("{msg}");
        }
    }
    unsafe {
        let w = crate::win_common::wide(profile);
        let _ = windows::Win32::Security::Isolation::DeleteAppContainerProfile(
            windows::core::PCWSTR(w.as_ptr()),
        );
    }
}

const TEMPLATE_CLEANUP: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
# 1. 使い捨て証明書を、置き得た全ての場所から消す（Rootは対照Bが一時的に入れる場所）。
#
#    **`Remove-Item -DeleteKey`だけに頼らない。** 秘密鍵を持たない複製（対照Bが入れた
#    Rootのものが該当する）に対して`-DeleteKey`は失敗し、`SilentlyContinue`と相まって
#    **黙って消えないまま完了する**——実際にこれで、ユーザーのRootストアへスパイクのCAが
#    4件残っていた（D-65が名指しで禁じている状態）。`X509Store.Remove`は鍵の有無に
#    関わらず消せるので、そちらを主にして`-DeleteKey`は鍵の後始末専用にする。
foreach ($name in 'My','Root','CA','TrustedPeople','Disallowed') {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($name,'CurrentUser')
    try { $store.Open('ReadWrite') } catch { continue }
    foreach ($c in @($store.Certificates | Where-Object {
        $_.Thumbprint -eq '%%CA_THUMB%%' -or $_.Thumbprint -eq '%%LEAF_THUMB%%' })) {
        $store.Remove($c)
    }
    $store.Close()
}
# 秘密鍵（`My`にだけ在る）はここで消す。
foreach ($thumb in '%%CA_THUMB%%','%%LEAF_THUMB%%') {
    Remove-Item -Path ("Cert:\CurrentUser\My\" + $thumb) -DeleteKey -Force
}
# 2. 素のHKCU書込の的と、Blob生成用の作業ストアと、中から作らせた実験用ストア。
Remove-Item -Path '%%PLAIN%%' -Recurse -Force
Remove-Item -Path '%%SCRATCH%%' -Recurse -Force
Remove-Item -Path 'HKCU:\Software\Microsoft\SystemCertificates\HarnessN1In*' -Recurse -Force
# 3. コンテナのStorageキーとプロファイルフォルダ（このスパイク専用のものだけ）。
#    `DeleteAppContainerProfile`もフォルダを消すが、**S_OKを返しながら何も消さないことがある**
#    （`session_profile.rs`の実測コメント）ので、こちらでも明示的に消す。
Remove-Item -Path '%%STORAGE%%\%%PROFILE%%' -Recurse -Force
Remove-Item -Path (Join-Path $env:LOCALAPPDATA 'Packages\%%PROFILE%%') -Recurse -Force

# 4. **消えたことを数え直す**（撤収の成功を戻り値ではなく状態で確かめる）。
$left = 0
foreach ($name in 'My','Root','CA','TrustedPeople','Disallowed') {
    $left += @(Get-ChildItem ("Cert:\CurrentUser\" + $name) -EA SilentlyContinue |
        Where-Object { $_.Thumbprint -eq '%%CA_THUMB%%' -or $_.Thumbprint -eq '%%LEAF_THUMB%%' }).Count
}
Write-Output ("RESIDUE_CERTS=" + $left)
Write-Output 'CLEANUP=done'
"#;

// ---------------------------------------------------------------------------
// コンテナの中で走らせる観測スクリプト
// ---------------------------------------------------------------------------

/// 中から見た世界を`KEY=VALUE`で報告する。**例外は握り潰さず本文を出す**
/// ——最初の版は`$ErrorActionPreference='SilentlyContinue'`で失敗理由ごと消してしまい、
/// 「書けなかった」のか「書いたが別の場所へ落ちた」のか区別できなかった。
const TEMPLATE_PROBE: &str = r#"
$ErrorActionPreference = 'Continue'
$doWrites = %%DO_WRITES%%
function Say($k, $v) { Write-Output ("$k=" + (($v -as [string]) -replace '\s+', ' ')) }
function Try1($k, $block) {
    try { Say $k (& $block) } catch { Say $k ("EXCEPTION:" + $_.Exception.Message) }
}

Say 'PHASE' '%%PHASE%%'
Say 'TOKEN_USER' ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
# **本当にAppContainerの中で走っているか**の独立確認（B-29: 測っている世界を取り違えない）。
# .NETの`WindowsIdentity.Groups`はpackage SIDを載せないので、トークンを直接読む`whoami`で見る。
Try1 'APPCONTAINER_SIDS' { (@(& whoami.exe /groups /nh) -match 'S-1-15-2-').Count }
# **envが原因ではないことの確認**（B-29）: ユーザーストアの実体は`%APPDATA%\Microsoft\
# SystemCertificates`にあり、この変数が落ちていればcrypt32は同じ`ERROR_FILE_NOT_FOUND`を返し得る。
# 子のenvは`secret_env::build_child_env`のallowlist経由なので、実際に届いているかを見る。
Say 'ENV_APPDATA' $env:APPDATA
Say 'ENV_USERPROFILE' $env:USERPROFILE
Try1 'APPDATA_STORE_DIR' {
    (Get-Item (Join-Path $env:APPDATA 'Microsoft\SystemCertificates') -EA Stop).Name
}

# --- HKCUそのものへ手が届くか（証明書とは無関係の対照） -------------------------
Try1 'HKCU_SOFTWARE_READ' { (Get-Item 'HKCU:\Software' -EA Stop).SubKeyCount }
if ($doWrites) {
    Try1 'HKCU_WRITE' {
        New-Item -Path '%%PLAIN%%' -Force -EA Stop | Out-Null
        Set-ItemProperty -Path '%%PLAIN%%' -Name probe -Value 'from-container' -EA Stop
        (Get-ItemProperty -Path '%%PLAIN%%' -Name probe -EA Stop).probe
    }
}

# --- 中から見た証明書ストア -----------------------------------------------------
$caDer = [Convert]::FromBase64String('%%CA_B64%%')
$ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$caDer)
$leafDer = [Convert]::FromBase64String('%%LEAF_B64%%')
$leaf = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$leafDer)

Try1 'ROOT_RO_COUNT' {
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser')
    $s.Open('ReadOnly'); $n = $s.Certificates.Count; $s.Close(); $n
}
Try1 'ROOT_RO_HAS_CA' {
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser')
    $s.Open('ReadOnly')
    $n = @($s.Certificates | Where-Object { $_.Thumbprint -eq $ca.Thumbprint }).Count
    $s.Close(); $n
}
Try1 'ROOT_LM_COUNT' {
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine')
    $s.Open('ReadOnly'); $n = $s.Certificates.Count; $s.Close(); $n
}
Try1 'MY_RO_COUNT' {
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('My','CurrentUser')
    $s.Open('ReadOnly'); $n = $s.Certificates.Count; $s.Close(); $n
}
# crypt32自身の言い分（.NETの例外文言では errorコードが分からない）。
Try1 'CERTUTIL_ROOT' { ((& certutil.exe -user -store Root 2>&1) | Select-Object -Last 2) -join ' / ' }
if ($doWrites) {
    Try1 'ROOT_ADD_FROM_CONTAINER' {
        $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser')
        $s.Open('ReadWrite'); $s.Add($ca); $s.Close(); 'OK'
    }
    # **問aの直接の的**: 中から`CurrentUser`の**新しい**ストアを作らせ、
    # それが物理的にどこへ落ちるかを外から見る（既存ストア名の都合を排した対照）。
    Try1 'CUSTOM_STORE_RW' {
        $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('%%CUSTOM%%','CurrentUser')
        $s.Open('ReadWrite'); $s.Add($ca); $n = $s.Certificates.Count; $s.Close(); "added/$n"
    }
}

# --- 物理パスを直接見る（リダイレクトが掛かっているかの直接証拠） ---------------
# `Test-Path`はアクセス不能なキーに対しても`True`を返すことがある（実測: コンテナ内で
# 存在しないキーに`True`が出た）ので、**必ず`Get-Item -EA Stop`で開いて**判定する。
Try1 'REG_REAL_ROOT_COUNT' {
    (Get-Item 'HKCU:\Software\Microsoft\SystemCertificates\Root\Certificates' -EA Stop).SubKeyCount
}
Try1 'REG_REAL_ROOT_HAS_CA' {
    $null = Get-Item ('HKCU:\Software\Microsoft\SystemCertificates\Root\Certificates\' + $ca.Thumbprint) -EA Stop
    'yes'
}
Try1 'REG_REDIR_ROOT_COUNT' {
    (Get-Item '%%STORAGE%%\%%PROFILE%%\Software\Microsoft\SystemCertificates\Root\Certificates' -EA Stop).SubKeyCount
}

# --- **信頼判断の実体**: crypt32のチェーン構築（.NETを経由しない） ---------------
# `curl.exe`（schannel）も`Invoke-WebRequest`も、最後はここ（`CertGetCertificateChain`）で
# 信頼を決める。出力は日本語化されるが**エラーの記号名とHRESULTは英数字のまま**なので、
# `CERT_`と`0x8`を含む行だけを拾えば言語に依存せず読める。
Try1 'VERIFY_LEAF' {
    (((& certutil.exe -user -verify (Join-Path '%%AC%%' 'Temp\n1-leaf.cer') 2>&1) |
        Select-String -Pattern 'CERT_|0x8|Untrusted' | Select-Object -First 6) -join ' | ')
}
# **対照**: マシンのRootストアに実在する証明書。ここが「信頼できる」と出るなら、
# チェーン構築そのものは中でも動いており、落ちているのは「その根が無い」だけと言える。
Try1 'VERIFY_MACHINE_ANCHOR' {
    (((& certutil.exe -user -verify (Join-Path '%%AC%%' 'Temp\n1-anchor.cer') 2>&1) |
        Select-String -Pattern 'CERT_|0x8|Untrusted' | Select-Object -First 6) -join ' | ')
}

# --- 信頼判断の実体（Schannelが使うのと同じチェーン構築） ------------------------
# `X509Chain`は既定で**ユーザーのチェーンエンジン**（`HCCE_CURRENT_USER`）を使い、
# `X509Chain($true)`が**マシンのエンジン**（`HCCE_LOCAL_MACHINE`）になる。中で
# CurrentUserストアが開けないなら、この2つは別の結果になるはずなので分けて測る。
Try1 'CHAIN_USER' {
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = 'NoCheck'
    $chain.ChainPolicy.ExtraStore.Add($ca) | Out-Null
    $ok = $chain.Build($leaf)
    $status = ($chain.ChainStatus | ForEach-Object { $_.Status }) -join '+'
    if ($status -eq '') { $status = 'NoError' }
    "$ok/$status"
}
Try1 'CHAIN_MACHINE' {
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain($true)
    $chain.ChainPolicy.RevocationMode = 'NoCheck'
    $chain.ChainPolicy.ExtraStore.Add($ca) | Out-Null
    $ok = $chain.Build($leaf)
    $status = ($chain.ChainStatus | ForEach-Object { $_.Status }) -join '+'
    if ($status -eq '') { $status = 'NoError' }
    "$ok/$status"
}
# **エンジンそのものが動くかの対照**（B-29）: マシンのRootストアに実在する証明書で組む。
# これが通るなら「チェーン構築が壊れている」のではなく「その信頼の根が無い」だけと言える。
Try1 'CHAIN_MACHINE_ANCHOR' {
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine')
    $s.Open('ReadOnly')
    $anchor = @($s.Certificates | Where-Object { $_.NotAfter -gt (Get-Date) })[0]
    $s.Close()
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain($true)
    $chain.ChainPolicy.RevocationMode = 'NoCheck'
    $ok = $chain.Build($anchor)
    $status = ($chain.ChainStatus | ForEach-Object { $_.Status }) -join '+'
    if ($status -eq '') { $status = 'NoError' }
    "$ok/$status"
}
Say 'DONE' '1'
"#;

/// `do_writes`は**コンテナの中でだけ真**にする。外（通常トークン）で同じスクリプトを回すと、
/// 対照のつもりの実行がユーザーのRootストアへCAを入れてしまい、測定対象を汚す。
fn probe_script(phase: &str, certs: &SpikeCerts, profile: &str, do_writes: bool) -> String {
    let ac = format!(
        r"{}\Packages\{profile}\AC",
        std::env::var("LOCALAPPDATA").expect("LOCALAPPDATA")
    );
    TEMPLATE_PROBE
        .replace("%%DO_WRITES%%", if do_writes { "$true" } else { "$false" })
        .replace("%%CUSTOM%%", &custom_store_name(phase))
        .replace("%%AC%%", &ac)
        .replace("%%PHASE%%", phase)
        .replace("%%PLAIN%%", PLAIN_HKCU_KEY)
        .replace("%%CA_B64%%", &certs.ca_der_b64)
        .replace("%%LEAF_B64%%", &certs.leaf_der_b64)
        .replace("%%STORAGE%%", STORAGE_ROOT)
        .replace("%%PROFILE%%", profile)
}

/// 外から見た着地点（問a・cの判定材料）。
const TEMPLATE_OUTSIDE_VIEW: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$p = '%%STORAGE%%\%%PROFILE%%'
Write-Output ("REAL_PLAIN=" + (Test-Path '%%PLAIN%%'))
Write-Output ("REDIR_PLAIN=" + (Test-Path ($p + '\Software\HarnessSpikeN1')))
Write-Output ("REAL_ROOT_HAS_CA=" + (Test-Path 'HKCU:\Software\Microsoft\SystemCertificates\Root\Certificates\%%CA_THUMB%%'))
Write-Output ("REDIR_ROOT_HAS_CA=" + (Test-Path ($p + '\Software\Microsoft\SystemCertificates\Root\Certificates\%%CA_THUMB%%')))
# 中から作らせたストアがどちらへ落ちたか（問aの直接の的）。
Write-Output ("REAL_CUSTOM=" + ((Get-ChildItem 'HKCU:\Software\Microsoft\SystemCertificates' -EA SilentlyContinue |
    Where-Object { $_.PSChildName -like 'HarnessN1In*' } | ForEach-Object { $_.PSChildName }) -join ','))
Write-Output ("REDIR_CUSTOM=" + ((Get-ChildItem ($p + '\Software\Microsoft\SystemCertificates') -EA SilentlyContinue |
    Where-Object { $_.PSChildName -like 'HarnessN1In*' } | ForEach-Object { $_.PSChildName }) -join ','))
Write-Output ("STORAGE_TREE=" + (((Get-ChildItem $p -Recurse -EA SilentlyContinue).Name -replace '.*\\Storage\\','') -join ';'))
"#;

fn outside_view(certs: &SpikeCerts, profile: &str) -> String {
    let script = TEMPLATE_OUTSIDE_VIEW
        .replace("%%STORAGE%%", STORAGE_ROOT)
        .replace("%%PROFILE%%", profile)
        .replace("%%PLAIN%%", PLAIN_HKCU_KEY)
        .replace("%%CA_THUMB%%", &certs.ca_thumb);
    let (out, err, _) = ps_outside(&script);
    if !err.trim().is_empty() {
        eprintln!("[N1] outside_view stderr={err}");
    }
    out
}

/// **問cの本命の書込**: AppContainerの外から、コンテナ専用ストアの物理パスへCAを置く。
///
/// `Blob`値は生のDERではなく**シリアライズされたストア要素**（プロパティ列＋証明書）なので、
/// 手で組まずCryptoAPIに作らせる——作業用ストア（`SCRATCH_STORE`）へ`certutil -addstore`し、
/// できた`Blob`のバイト列をそのままコピーする。
///
/// あわせて、作ったキーへ**そのコンテナのpackage SID宛の許可ACE**を付ける。パッケージ済み
/// アプリではOSが登録時にこれを行うが、`CreateAppContainerProfile`のlegacy AppContainerでは
/// キー自体が存在しないため、外から作る側が主体を明示する必要がある。
const TEMPLATE_SEED_CONTAINER_STORE: &str = r#"
$ErrorActionPreference = 'Stop'
# CryptoAPIに`Blob`を組ませるための足場（作業ストア）。`X509Store`は
# `OpenExistingOnly`を指定しなければ存在しないストアを作るので、外部プロセスは要らない。
$ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
    ,[Convert]::FromBase64String('%%CA_B64%%'))
$scratch = New-Object System.Security.Cryptography.X509Certificates.X509Store('HarnessN1Scratch','CurrentUser')
$scratch.Open('ReadWrite')
$scratch.Add($ca)
$scratch.Close()
$blob = (Get-ItemProperty -Path '%%SCRATCH%%\Certificates\%%CA_THUMB%%' -Name Blob).Blob
Write-Output ("BLOB_LEN=" + $blob.Length)

# **論理ストアの構造をそのまま作る**。実マシンの`Root`は`Certificates`・`CRLs`・`CTLs`の
# 3本を持ち（パッケージ済みアプリのStorage配下も同じ形）、`Certificates`だけを作った版では
# 中からのストアopenが`ERROR_FILE_NOT_FOUND`のままだった。構造の不足を候補から外すために揃える。
$store = '%%STORAGE%%\%%PROFILE%%\Software\Microsoft\SystemCertificates\Root'
foreach ($sub in 'Certificates', 'CRLs', 'CTLs') {
    New-Item -Path ($store + '\' + $sub) -Force | Out-Null
}
$dst = $store + '\Certificates\%%CA_THUMB%%'
New-Item -Path $dst -Force | Out-Null
Set-ItemProperty -Path $dst -Name Blob -Value $blob -Type Binary
Write-Output ("SEEDED=" + (Test-Path $dst))
Remove-Item -Path '%%SCRATCH%%' -Recurse -Force
"#;

/// 上で作ったキー群へ、**そのコンテナのpackage SID宛の許可ACE**を付ける。
///
/// パッケージ済みアプリではOSが登録時にこれを行うが、`CreateAppContainerProfile`の
/// legacy AppContainerではキー自体が存在しない（実測: プロファイル作成直後は
/// `Storage\<moniker>`が無い）ため、外から作る側が主体を明示する必要がある。
/// **ACEの有無を別フェーズに割ってある**——本番実装が何をしなければならないかは、
/// 「ACE無しでも見えるか」を測らないと決められない（B-29）。
///
/// 権限（`%%RIGHTS%%`）を引数にしてあるのは、③の測定が
/// 「`FullControl`でなく`ReadKey`で足りるか」まで見るためである（呼び出しは[`grant_storage_ace`]）。
const TEMPLATE_GRANT_PACKAGE_SID: &str = r#"
$ErrorActionPreference = 'Stop'
$sid = New-Object System.Security.Principal.SecurityIdentifier('%%PKG_SID%%')
$root = '%%STORAGE%%\%%PROFILE%%'
$keys = @(Get-Item $root) + @(Get-ChildItem $root -Recurse)
foreach ($k in $keys) {
    $acl = Get-Acl -Path $k.PSPath
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
        $sid, '%%RIGHTS%%', 'ContainerInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -Path $k.PSPath -AclObject $acl
}
Write-Output ("GRANTED_KEYS=" + $keys.Count)
Write-Output ("ACL=" + (((Get-Acl -Path $root).Access |
    Where-Object { $_.IdentityReference -like 'S-1-15-2-*' } |
    ForEach-Object { $_.RegistryRights }) -join ','))
"#;

/// `Storage\<moniker>`配下へpackage SID宛のACEを付ける（[`TEMPLATE_GRANT_PACKAGE_SID`]の唯一の口）。
///
/// `rights`は`RegistryRights`の名前（`FullControl`・`ReadKey`等）。
fn grant_storage_ace(pkg_sid: &str, profile: &str, rights: &str) -> (String, String, i32) {
    ps_outside(
        &TEMPLATE_GRANT_PACKAGE_SID
            .replace("%%PKG_SID%%", pkg_sid)
            .replace("%%RIGHTS%%", rights)
            .replace("%%STORAGE%%", STORAGE_ROOT)
            .replace("%%PROFILE%%", profile),
    )
}

/// **ファイル側の置き場**にCAを置く。
///
/// パッケージ済みアプリのAppContainerプロファイルには
/// `%LOCALAPPDATA%\Packages\<moniker>\AC\Microsoft\SystemCertificates\<論理ストア>\{Certificates,CRLs,CTLs}`
/// という**ファイルベースの証明書ストア**が実在した（実測: `Microsoft.WindowsStore_8wekyb3d8bbwe`に
/// `My`がある）。これは実ユーザー側の`%APPDATA%\Microsoft\SystemCertificates\My\…`と同じ形である。
/// レジストリ側（Storage）だけを置いても中からストアが開かなかったので、こちらも撃つ。
///
/// **`AC`フォルダはそのAppContainerの専用領域**で、`CreateAppContainerProfile`が
/// package SID宛のACEを付けて作る。外から作った子フォルダはそれを継承する。
const TEMPLATE_SEED_AC_FILE_STORE: &str = r#"
$ErrorActionPreference = 'Stop'
$ac = Join-Path $env:LOCALAPPDATA 'Packages\%%PROFILE%%\AC'
Write-Output ("AC_EXISTS=" + (Test-Path $ac))
$store = Join-Path $ac 'Microsoft\SystemCertificates\Root'
foreach ($sub in 'Certificates', 'CRLs', 'CTLs') {
    New-Item -ItemType Directory -Path (Join-Path $store $sub) -Force | Out-Null
}
Write-Output ("STORE_DIR=" + (Test-Path $store))
Write-Output ("AC_ACL=" + (((Get-Acl $ac).Access |
    Where-Object { $_.IdentityReference -like 'S-1-15-2-*' } |
    ForEach-Object { $_.IdentityReference.Value + ':' + $_.FileSystemRights }) -join ' | '))

if ('%%WITH_BLOB%%' -eq 'yes') {
    # 作業ストアでCryptoAPIに`Blob`を組ませ、そのバイト列をファイルとして置く
    # （実ユーザー側の`%APPDATA%\…\Certificates\<thumbprint>`と同じ形）。
    $ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        ,[Convert]::FromBase64String('%%CA_B64%%'))
    $scratch = New-Object System.Security.Cryptography.X509Certificates.X509Store('HarnessN1Scratch','CurrentUser')
    $scratch.Open('ReadWrite'); $scratch.Add($ca); $scratch.Close()
    $blob = (Get-ItemProperty -Path '%%SCRATCH%%\Certificates\%%CA_THUMB%%' -Name Blob).Blob
    Remove-Item -Path '%%SCRATCH%%' -Recurse -Force
    [IO.File]::WriteAllBytes((Join-Path $store ('Certificates\%%CA_THUMB%%')), $blob)
    Write-Output ("BLOB_FILE=" + (Test-Path (Join-Path $store 'Certificates\%%CA_THUMB%%')))
}
"#;

// **対照B（ユーザーのRootストアへ一時的に入れる）は撤去した。**
//
// 理由は2つあり、どちらも実測で分かった。
//
// 1. **GUIの確認ダイアログ（「ルート証明書ストア」）が出て、テストが無人では終わらない。**
//    実際に測定中10分以上そこで止まった。`X509Store.Add`は`CurrentUser\Root`に対しては
//    UIを出す（それ自体は、ユーザーRootへの追加が黙って通らないという良い性質である）。
// 2. **押し間違いの被害がD-65の禁止事項そのもの**——ユーザーのRootストアに恒久的にCAが残る。
//    実際にこのスパイクは撤収の無言失敗で4件残しており、同じ場所を二度触る理由が無い。
//
// この対照が担っていた「証明書材料が正しいことの基準線」は、より安全な2つで置き換えてある。
// (a) AppContainerにしない対照（`n1_does_a_capability_unlock_the_current_user_certificate_store`の
// 最後の変数）でユーザーストアが正常に開くこと、(b) `Mappings`登録後にコンテナ内で
// `X509Chain.Build`が`NoError`を返すこと（＝材料が正しくなければ通らない）。

// ---------------------------------------------------------------------------
// 測定本体
// ---------------------------------------------------------------------------

/// 観測結果を1行にまとめて出す（フェーズ間の差分を目で追えるようにするため）。
fn row(label: &str, out: &str) {
    eprintln!(
        "[N1][まとめ] {label}\n    APPDATA={} / そこのSystemCertificates={}\n    \
         AppContainer判定={} / CurrentUser\\Root件数={} / \
         そこにCA={} / CurrentUser\\My件数={} / LocalMachine\\Root件数={}\n    \
         中からのRoot追加={} / 中から新規ストア作成={} / certutil={}\n    \
         実HKCUのRoot件数={} / リダイレクト先のRoot件数={}\n    \
         crypt32のverify（このCAのリーフ）={}\n    crypt32のverify（マシンRootの証明書）={}\n    \
         .NETチェーン（ユーザーエンジン）={} / .NETチェーン（マシンエンジン）={} / \
         .NETチェーン（マシンRootの証明書）={}",
        kv(out, "ENV_APPDATA").unwrap_or_default(),
        kv(out, "APPDATA_STORE_DIR").unwrap_or_default(),
        kv(out, "APPCONTAINER_SIDS").unwrap_or_default(),
        kv(out, "ROOT_RO_COUNT").unwrap_or_default(),
        kv(out, "ROOT_RO_HAS_CA").unwrap_or_default(),
        kv(out, "MY_RO_COUNT").unwrap_or_default(),
        kv(out, "ROOT_LM_COUNT").unwrap_or_default(),
        kv(out, "ROOT_ADD_FROM_CONTAINER").unwrap_or_default(),
        kv(out, "CUSTOM_STORE_RW").unwrap_or_default(),
        kv(out, "CERTUTIL_ROOT").unwrap_or_default(),
        kv(out, "REG_REAL_ROOT_COUNT").unwrap_or_default(),
        kv(out, "REG_REDIR_ROOT_COUNT").unwrap_or_default(),
        kv(out, "VERIFY_LEAF").unwrap_or_default(),
        kv(out, "VERIFY_MACHINE_ANCHOR").unwrap_or_default(),
        kv(out, "CHAIN_USER").unwrap_or_default(),
        kv(out, "CHAIN_MACHINE").unwrap_or_default(),
        kv(out, "CHAIN_MACHINE_ANCHOR").unwrap_or_default(),
    );
}

/// 問a・b・cを1本の流れで測る（対照A → 本命 → 対照B）。
///
/// 3フェーズを別テストへ割らないのは、同じプロファイル・同じCAで**状態を1つずつ足しながら**
/// 見ないと「見えた／見えない」の原因が特定できないためである（B-29: 一度に1変数だけ動かす）。
#[test]
#[ignore = "実AppContainerと実レジストリを使う。**非昇格**で、--test-threads=1で走らせること"]
fn n1_appcontainer_certificate_store_redirect_and_chain_building() {
    let profile = spike_profile_name();
    let certs = create_spike_certs();
    // 後始末は測定より先に登録する（assertで落ちてもマシンに残さない）。
    let cleanup_thumbs = (certs.ca_thumb.clone(), certs.leaf_thumb.clone());
    let cleanup_profile = profile.clone();
    let _guard = super::test_support::scopeguard(move || {
        cleanup_all(&cleanup_thumbs, &cleanup_profile);
    });

    let sid = ensure_profile_for_test(&profile).expect("create the spike AppContainer profile");
    let pkg_sid = crate::win_common::sid_to_string(sid.as_psid()).expect("package SID string");
    eprintln!(
        "[N1] profile={profile} package_sid={pkg_sid} ca={} leaf={}",
        certs.ca_thumb, certs.leaf_thumb
    );

    // `certutil -verify`に食わせる証明書を、コンテナが読める唯一の場所（専用の`AC`フォルダ）へ置く。
    let (ac_out, ac_err, ac_code) = ps_outside(
        &TEMPLATE_SEED_AC_TEMP
            .replace("%%PROFILE%%", &profile)
            .replace("%%LEAF_B64%%", &certs.leaf_der_b64)
            .replace("%%CA_B64%%", &certs.ca_der_b64),
    );
    eprintln!("[N1][AC\\Tempへ配置] exit={ac_code}\n{ac_out}{ac_err}");
    assert_eq!(ac_code, 0, "ACフォルダへの証明書配置が失敗した");

    // --- フェーズ0: 外（通常トークン）の基準線 -------------------------------
    // 「中で見えない」が層1の性質なのか証明書材料の不備なのかを切り分ける基準線
    // （B-29: 変数を1つずつ動かす）。**書込プローブは撃たない**（外を汚さない）。
    let (base, base_err, _) = ps_outside(&probe_script("outside", &certs, &profile, false));
    eprintln!("[N1][外・CA未投入] \n{base}\n--- stderr ---\n{base_err}");

    // --- フェーズ1: 対照A（CAはどこにも無い） --------------------------------
    let (phase_a, err_a, code_a) =
        ps_in_container(sid.as_psid(), &probe_script("A", &certs, &profile, true));
    eprintln!("[N1][対照A] exit={code_a}\n{phase_a}\n--- stderr ---\n{err_a}");
    eprintln!(
        "[N1][対照A] 外から見た着地点:\n{}",
        outside_view(&certs, &profile)
    );

    // --- フェーズ2: 外からコンテナ専用ストアへCAを置く（問c、ACEはまだ付けない） ---
    let seed = TEMPLATE_SEED_CONTAINER_STORE
        .replace("%%CA_B64%%", &certs.ca_der_b64)
        .replace("%%CA_THUMB%%", &certs.ca_thumb)
        .replace("%%SCRATCH%%", SCRATCH_STORE)
        .replace("%%STORAGE%%", STORAGE_ROOT)
        .replace("%%PROFILE%%", &profile);
    let (seed_out, seed_err, seed_code) = ps_outside(&seed);
    eprintln!("[N1][種まき] exit={seed_code}\n{seed_out}\n--- stderr ---\n{seed_err}");
    assert_eq!(
        seed_code, 0,
        "コンテナ専用ストアへの書込（外から）が失敗した。問cの測定が成立していない"
    );

    let (phase_c1, err_c1, code_c1) =
        ps_in_container(sid.as_psid(), &probe_script("C1", &certs, &profile, true));
    eprintln!("[N1][問c・ACE無し] exit={code_c1}\n{phase_c1}\n--- stderr ---\n{err_c1}");

    // --- フェーズ3: package SID宛のACEを付けてから、もう一度見る -------------
    let (grant_out, grant_err, grant_code) = grant_storage_ace(&pkg_sid, &profile, "FullControl");
    eprintln!("[N1][ACE付与] exit={grant_code}\n{grant_out}\n--- stderr ---\n{grant_err}");
    assert_eq!(grant_code, 0, "package SID宛ACEの付与が失敗した");

    let (phase_c2, err_c2, code_c2) =
        ps_in_container(sid.as_psid(), &probe_script("C2", &certs, &profile, true));
    eprintln!("[N1][問c・ACE有り] exit={code_c2}\n{phase_c2}\n--- stderr ---\n{err_c2}");
    eprintln!(
        "[N1][問c・ACE有り] 外から見た着地点:\n{}",
        outside_view(&certs, &profile)
    );

    // --- フェーズ3.5: ファイル側の置き場（AC配下）を作って、もう一度見る -----
    let seed_ac = |with_blob: bool| {
        let script = TEMPLATE_SEED_AC_FILE_STORE
            .replace("%%PROFILE%%", &profile)
            .replace("%%WITH_BLOB%%", if with_blob { "yes" } else { "no" })
            .replace("%%CA_B64%%", &certs.ca_der_b64)
            .replace("%%CA_THUMB%%", &certs.ca_thumb)
            .replace("%%SCRATCH%%", SCRATCH_STORE);
        let (out, err, code) = ps_outside(&script);
        eprintln!("[N1][ACファイルストア with_blob={with_blob}] exit={code}\n{out}\n--- stderr ---\n{err}");
        assert_eq!(code, 0, "AC配下のファイルストア作成が失敗した");
    };
    seed_ac(false);
    let (phase_d1, _, _) =
        ps_in_container(sid.as_psid(), &probe_script("D1", &certs, &profile, true));
    eprintln!("[N1][ACストア・骨組みのみ]\n{phase_d1}");
    seed_ac(true);
    let (phase_d2, _, _) =
        ps_in_container(sid.as_psid(), &probe_script("D2", &certs, &profile, true));
    eprintln!("[N1][ACストア・CA配置済み]\n{phase_d2}");

    // フェーズ4（対照B＝ユーザーのRootストアへ一時投入）は**撤去した**。理由は
    // `TEMPLATE_SEED_USER_ROOT`があった場所のコメント参照（GUIダイアログで無人実行が止まる／
    // 押し間違いの被害がD-65の禁止事項そのもの）。

    // --- まとめ（判定はこの表を見て人間が書く。ここでは崩れた前提だけを落とす） ---
    row("外・CA未投入（基準線）", &base);
    row("中・対照A（CAどこにも無し）", &phase_a);
    row("中・問c（コンテナ専用ストア、ACE無し）", &phase_c1);
    row("中・問c（コンテナ専用ストア、ACE有り）", &phase_c2);
    row("中・ACファイルストア（骨組みのみ）", &phase_d1);
    row("中・ACファイルストア（CA配置済み）", &phase_d2);

    for (label, out) in [
        ("外・基準線", &base),
        ("A", &phase_a),
        ("C1", &phase_c1),
        ("C2", &phase_c2),
    ] {
        assert_eq!(
            kv(out, "DONE").as_deref(),
            Some("1"),
            "フェーズ{label}の観測スクリプトが最後まで走っていない:\n{out}"
        );
    }
}

// ---------------------------------------------------------------------------
// 実クライアント（.NET経由でないSchannel）はコンテナの中でTLSを検証できるのか
// ---------------------------------------------------------------------------

/// **測っている対象を取り違えていないかの確認**（`test-logic-rules`の4問）。
///
/// 本測定は`X509Store`/`X509Chain`（.NET）で見たが、そこで起きた
/// 「CurrentUserストアが`ERROR_FILE_NOT_FOUND`」「チェーン構築が例外」は、
/// **.NET固有の経路の話かもしれない**。D-64/D-65が相手にするのは
/// `curl.exe`（Windows同梱・schannel）や`Invoke-WebRequest`といった実クライアントなので、
/// そちらが同じ世界でどう振る舞うかを直接見る。
///
/// - `certutil -verify`は.NETを経由しない**crypt32のチェーン構築そのもの**である
/// - `curl.exe`/`Invoke-WebRequest`は**公開のTLSサーバ**（`https://example.com`）へ1回GETする。
///   loopback exemption（マシン全体で1本、走行中セッションと共有）に触らずにSchannelの
///   実挙動を見るための最短経路。**送るのはリクエストだけで、こちらの情報は載せない**
const TEMPLATE_REAL_CLIENT_PROBE: &str = r#"
$ErrorActionPreference = 'Continue'
function Say($k, $v) { Write-Output ("$k=" + (($v -as [string]) -replace '\s+', ' ')) }
function Try1($k, $block) {
    try { Say $k (& $block) } catch { Say $k ("EXCEPTION:" + $_.Exception.Message) }
}
$ac = '%%AC%%'

# 1. crypt32のチェーン構築（.NETを経由しない）。既知の公開CAで終わる証明書ではなく、
#    このスパイクのCAで署名したリーフなので「UntrustedRoot」が正しい答え。
Try1 'CERTUTIL_VERIFY_LEAF' {
    ((& certutil.exe -verify (Join-Path $ac 'Temp\n1-leaf.cer') 2>&1) | Select-Object -Last 3) -join ' / '
}
# 2. 実クライアント（schannel）。公開サーバへの1回のGET。
Try1 'CURL_PUBLIC' {
    (& "$env:SystemRoot\System32\curl.exe" -sS -m 20 -o NUL -w 'http=%{http_code}' https://example.com 2>&1) -join ' '
}
Try1 'IWR_PUBLIC' {
    (Invoke-WebRequest -Uri 'https://example.com' -UseBasicParsing -TimeoutSec 20).StatusCode
}
Say 'DONE' '1'
"#;

/// 実クライアントの測定に要るファイル（リーフ証明書）を、**コンテナが読める唯一の場所**
/// ——そのAppContainer専用の`AC`フォルダ——へ置く。
const TEMPLATE_SEED_AC_TEMP: &str = r#"
$ErrorActionPreference = 'Stop'
$temp = Join-Path $env:LOCALAPPDATA 'Packages\%%PROFILE%%\AC\Temp'
New-Item -ItemType Directory -Path $temp -Force | Out-Null
[IO.File]::WriteAllBytes((Join-Path $temp 'n1-leaf.cer'), [Convert]::FromBase64String('%%LEAF_B64%%'))
[IO.File]::WriteAllBytes((Join-Path $temp 'n1-ca.cer'), [Convert]::FromBase64String('%%CA_B64%%'))
# 対照用: **マシンのRootストアに実在する**証明書を1枚置く（自己署名＝それ自身が根）。
$s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine')
$s.Open('ReadOnly')
$anchor = @($s.Certificates | Where-Object {
    $_.NotAfter -gt (Get-Date) -and $_.Subject -eq $_.Issuer })[0]
$s.Close()
[IO.File]::WriteAllBytes((Join-Path $temp 'n1-anchor.cer'), $anchor.GetRawCertData())
Write-Output ("ANCHOR=" + $anchor.Subject)
Write-Output ("AC_TEMP=" + $temp)
"#;

/// 実クライアント（`curl.exe`・`Invoke-WebRequest`）と`certutil -verify`が、
/// legacy AppContainerの中でTLSの信頼判断をできるのかを測る。
///
/// **外でも同じスクリプトを回して対照にする**——外で通って中で落ちるなら
/// コンテナの性質、両方落ちるならこの機の性質である（B-29）。
#[test]
#[ignore = "実AppContainerを使い、**公開サーバへ1回HTTPS GETする**。非昇格で走らせること"]
fn n1_do_real_schannel_clients_work_inside_a_legacy_appcontainer() {
    let profile = format!("harness.n1net.{}", std::process::id());
    let certs = create_spike_certs();
    let cleanup_thumbs = (certs.ca_thumb.clone(), certs.leaf_thumb.clone());
    let cleanup_profile = profile.clone();
    let _guard = super::test_support::scopeguard(move || {
        cleanup_all(&cleanup_thumbs, &cleanup_profile);
    });

    let sid = ensure_profile_for_test(&profile).expect("create the spike AppContainer profile");
    let (seed_out, seed_err, seed_code) = ps_outside(
        &TEMPLATE_SEED_AC_TEMP
            .replace("%%PROFILE%%", &profile)
            .replace("%%LEAF_B64%%", &certs.leaf_der_b64)
            .replace("%%CA_B64%%", &certs.ca_der_b64),
    );
    eprintln!("[N1-net][配置] exit={seed_code} {seed_out} {seed_err}");
    assert_eq!(seed_code, 0, "ACフォルダへの証明書配置が失敗した");
    let ac = kv(&seed_out, "AC_TEMP")
        .expect("AC_TEMP")
        .trim_end_matches("\\Temp")
        .to_string();

    let script = TEMPLATE_REAL_CLIENT_PROBE.replace("%%AC%%", &ac);
    let (outside, _, _) = ps_outside(&script);
    eprintln!("[N1-net][外（通常トークン）]\n{outside}");

    let (inside, inside_err, inside_code) =
        ps_in_container_with_net(sid.as_psid(), &script, NetworkCapability::InternetClient);
    eprintln!(
        "[N1-net][中（AppContainer）] exit={inside_code}\n{inside}\n--- stderr ---\n{inside_err}"
    );

    for (label, out) in [("外", &outside), ("中", &inside)] {
        eprintln!(
            "[N1-net][まとめ] {label}: certutil -verify={} / curl(schannel)={} / Invoke-WebRequest={}",
            kv(out, "CERTUTIL_VERIFY_LEAF").unwrap_or_default(),
            kv(out, "CURL_PUBLIC").unwrap_or_default(),
            kv(out, "IWR_PUBLIC").unwrap_or_default(),
        );
    }
    assert_eq!(
        kv(&inside, "DONE").as_deref(),
        Some("1"),
        "コンテナ内の観測スクリプトが最後まで走っていない:\n{inside}"
    );
}

// ---------------------------------------------------------------------------
// ユーザーストアの実体（%APPDATA%側）へ手が届いたら、中は何を見るのか
// ---------------------------------------------------------------------------

/// どこでアクセスが止まるかを1段ずつ見る。
const TEMPLATE_ANCESTOR_PROBE: &str = r#"
$ErrorActionPreference = 'Continue'
function Say($k, $v) { Write-Output ("$k=" + (($v -as [string]) -replace '\s+', ' ')) }
function Try1($k, $block) {
    try { Say $k (& $block) } catch { Say $k ("DENIED:" + $_.Exception.Message) }
}
$p = $env:APPDATA
foreach ($step in @('C:\Users', ('C:\Users\' + $env:USERNAME), (Split-Path $p -Parent), $p,
                    (Join-Path $p 'Microsoft'), (Join-Path $p 'Microsoft\SystemCertificates'),
                    (Join-Path $p 'Microsoft\SystemCertificates\Root'))) {
    Try1 ('DIR:' + $step) { (Get-Item $step -EA Stop).Name }
}
Try1 'ROOT_RO_COUNT' {
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser')
    $s.Open('ReadOnly'); $n = $s.Certificates.Count; $s.Close(); $n
}
Try1 'ROOT_RO_HAS_CA' {
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser')
    $s.Open('ReadOnly')
    $n = @($s.Certificates | Where-Object { $_.Thumbprint -eq '%%CA_THUMB%%' }).Count
    $s.Close(); $n
}
Say 'DONE' '1'
"#;

/// `%APPDATA%\Microsoft\SystemCertificates`（＝ユーザーストアのファイル側の実体）へ
/// **そのコンテナのpackage SIDだけ**に読取を許す／剥がす。
///
/// 継承は付けない（`None`）——`My\Keys`配下にはユーザーの秘密鍵があり、測定のために
/// そこまで開ける理由が無い。剥がしは`RemoveAccessRuleAll`で同じ主体のACEを全部落とし、
/// **剥がれたことを再取得して確かめる**（`feedback-security-self-verification`）。
const TEMPLATE_GRANT_USER_STORE_DIR: &str = r#"
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:APPDATA 'Microsoft\SystemCertificates'
$sid = New-Object System.Security.Principal.SecurityIdentifier('%%PKG_SID%%')
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'ReadAndExecute', 'None', 'None', 'Allow')
$acl = Get-Acl $dir
if ('%%MODE%%' -eq 'grant') { $acl.AddAccessRule($rule) } else { $acl.RemoveAccessRuleAll($rule) }
Set-Acl -Path $dir -AclObject $acl
$now = @((Get-Acl $dir).Access | Where-Object { $_.IdentityReference.Value -eq '%%PKG_SID%%' })
Write-Output ("ACE_PRESENT=" + $now.Count)
"#;

/// **問b・cの取り違えを潰すための追加測定。**
///
/// 本測定では「コンテナ専用ストアへ外から置いても中から見えない」と出たが、そのとき
/// **ストアのopen自体が別の理由で失敗していた**（`%APPDATA%\Microsoft\SystemCertificates`が
/// AppContainerから拒否される）。2つの原因が重なった状態で「見えない」と結論するのは
/// 変数を1つに絞れていない（B-29）。
///
/// そこで、そのディレクトリだけを開けてストアが開くようにしてから、**中が見ているのが
/// ユーザーのストアなのか、リダイレクトされたコンテナ専用ストアなのか**を確かめる。
/// 前者なら層1は成立しない（見えているのはユーザーの信頼設定そのもの）。
#[test]
#[ignore = "実AppContainerを使い、%APPDATA%配下のACEを一時的に足して必ず剥がす。非昇格で走らせること"]
fn n1_when_the_user_store_directory_is_reachable_what_does_the_container_see() {
    let profile = format!("harness.n1dir.{}", std::process::id());
    let certs = create_spike_certs();
    let cleanup_thumbs = (certs.ca_thumb.clone(), certs.leaf_thumb.clone());
    let cleanup_profile = profile.clone();
    let _guard = super::test_support::scopeguard(move || {
        cleanup_all(&cleanup_thumbs, &cleanup_profile);
    });

    let sid = ensure_profile_for_test(&profile).expect("create the spike AppContainer profile");
    let pkg_sid = crate::win_common::sid_to_string(sid.as_psid()).expect("package SID string");

    // ACEの撤収は付与より先に登録する（B-01: 付与と撤収を対で、しかも撤収を先に置く）。
    let revoke_sid = pkg_sid.clone();
    let _ace_guard = super::test_support::scopeguard(move || {
        let (out, err, code) = ps_outside(
            &TEMPLATE_GRANT_USER_STORE_DIR
                .replace("%%PKG_SID%%", &revoke_sid)
                .replace("%%MODE%%", "revoke"),
        );
        eprintln!("[N1-dir][ACE撤収] exit={code} {out} {err}");
        assert_eq!(
            kv(&out, "ACE_PRESENT").as_deref(),
            Some("0"),
            "%APPDATA%配下へ足したACEが剥がれていない（実マシンに残る）"
        );
    });

    let script = TEMPLATE_ANCESTOR_PROBE.replace("%%CA_THUMB%%", &certs.ca_thumb);

    let (before, _, _) = ps_in_container(sid.as_psid(), &script);
    eprintln!("[N1-dir][ACE付与前]\n{before}");

    // コンテナ専用ストア（レジストリ側）へCAを置き、package SID宛のACEも付けておく。
    let seed = TEMPLATE_SEED_CONTAINER_STORE
        .replace("%%CA_B64%%", &certs.ca_der_b64)
        .replace("%%CA_THUMB%%", &certs.ca_thumb)
        .replace("%%SCRATCH%%", SCRATCH_STORE)
        .replace("%%STORAGE%%", STORAGE_ROOT)
        .replace("%%PROFILE%%", &profile);
    let (_, _, seed_code) = ps_outside(&seed);
    assert_eq!(seed_code, 0, "コンテナ専用ストアへの書込が失敗した");
    let (_, _, grant_code) = grant_storage_ace(&pkg_sid, &profile, "FullControl");
    assert_eq!(grant_code, 0, "package SID宛ACEの付与が失敗した");

    let (grant_out, grant_err, grant_code) = ps_outside(
        &TEMPLATE_GRANT_USER_STORE_DIR
            .replace("%%PKG_SID%%", &pkg_sid)
            .replace("%%MODE%%", "grant"),
    );
    eprintln!("[N1-dir][ACE付与] exit={grant_code} {grant_out} {grant_err}");
    assert_eq!(grant_code, 0, "%APPDATA%配下へのACE付与が失敗した");

    let (after, _, _) = ps_in_container(sid.as_psid(), &script);
    eprintln!("[N1-dir][ACE付与後]\n{after}");

    eprintln!(
        "[N1-dir][まとめ] ストアのopen: 付与前={} → 付与後={} / \
         コンテナ専用ストアへ置いたCAが見えるか: 付与前={} → 付与後={}",
        kv(&before, "ROOT_RO_COUNT").unwrap_or_default(),
        kv(&after, "ROOT_RO_COUNT").unwrap_or_default(),
        kv(&before, "ROOT_RO_HAS_CA").unwrap_or_default(),
        kv(&after, "ROOT_RO_HAS_CA").unwrap_or_default(),
    );
    assert_eq!(kv(&after, "DONE").as_deref(), Some("1"));
}

// ---------------------------------------------------------------------------
// capabilityを積めば`CurrentUser`ストアが開くのか
// ---------------------------------------------------------------------------

/// `sharedUserCertificates`（**ユーザー／マシンの証明書ストアへのアクセス**を与える、
/// 既知の番号付きcapability）。`internetClient`が`S-1-15-3-1`であるのと同じ系列。
const SHARED_USER_CERTIFICATES_SID: &str = "S-1-15-3-9";

/// パッケージ済みアプリの`…\AppContainer\Storage\<pkg>`のDACLに、`ReadKey`で載っていた
/// capability SID（この機で実測。2パッケージとも同一の値）。名前は不明だが、
/// **OSがその領域へ読取を許している主体**なので変数として撃つ価値がある。
const STORAGE_READER_CAP_SID: &str = "S-1-15-3-1024-3635283841-2530182609-996808640-1887759898-3848208603-3313616867-983405619-2501854204";

/// 文字列SIDを`PSID`にする（`LocalFree`は呼び出し側の`SidBuf::drop`が行う）。
struct SidBuf(windows::Win32::Security::PSID);

impl SidBuf {
    fn parse(s: &str) -> Self {
        use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
        unsafe {
            let mut psid = windows::Win32::Security::PSID::default();
            let w = crate::win_common::wide(s);
            ConvertStringSidToSidW(windows::core::PCWSTR(w.as_ptr()), &mut psid)
                .unwrap_or_else(|e| panic!("ConvertStringSidToSidW({s}): {e}"));
            Self(psid)
        }
    }
}

impl Drop for SidBuf {
    fn drop(&mut self) {
        unsafe {
            use windows::Win32::Foundation::{LocalFree, HLOCAL};
            let _ = LocalFree(HLOCAL(self.0 .0));
        }
    }
}

/// **`CurrentUser`ストアが開けないのはcapabilityが足りないだけなのか**を測る。
///
/// 本測定（[`n1_appcontainer_certificate_store_redirect_and_chain_building`]）で、
/// legacy AppContainerの中では`Root`も`My`も**新規の名前のストアも**、例外なく
/// `ERROR_FILE_NOT_FOUND`で開けなかった。「置き場が無い」のか「開く権利が無い」のかは
/// これだけでは決まらないので、トークンへ積むcapabilityだけを変えて同じ観測を撃つ。
///
/// 任意のcapabilityを積むために、本番の`spawn`ではなく`mac_spike_tests`の[`SpikeSpawn`]を
/// 使う（`capabilities`を引数で受け取るのはあちらだけ。スパイク同士の共有は
/// `docs/CODE-STRUCTURE-RULES.md`規則5＝写しを作らない、に従う）。
#[test]
#[ignore = "実AppContainerを使う。**非昇格**で、--test-threads=1で走らせること"]
fn n1_does_a_capability_unlock_the_current_user_certificate_store() {
    use super::mac_spike_tests::{SpikeConsole, SpikeSpawn};

    let profile = format!("harness.n1caps.{}", std::process::id());
    let certs = create_spike_certs();
    let cleanup_thumbs = (certs.ca_thumb.clone(), certs.leaf_thumb.clone());
    let cleanup_profile = profile.clone();
    let _guard = super::test_support::scopeguard(move || {
        cleanup_all(&cleanup_thumbs, &cleanup_profile);
    });

    let sid = ensure_profile_for_test(&profile).expect("create the spike AppContainer profile");
    // `certutil -verify`用の証明書を、このプロファイルの`AC\Temp`へ置く（本測定と同じ形）。
    let (_, _, seed_code) = ps_outside(
        &TEMPLATE_SEED_AC_TEMP
            .replace("%%PROFILE%%", &profile)
            .replace("%%LEAF_B64%%", &certs.leaf_der_b64)
            .replace("%%CA_B64%%", &certs.ca_der_b64),
    );
    assert_eq!(seed_code, 0, "ACフォルダへの証明書配置が失敗した");
    let traverse = super::traverse_capability_sid().expect("traverse capability");
    let shared_certs = SidBuf::parse(SHARED_USER_CERTIFICATES_SID);
    let storage_reader = SidBuf::parse(STORAGE_READER_CAP_SID);
    let (shell, _) = resolve_shell();

    // 最後の1件は**AppContainerにしない**対照である（`no_appcontainer`）。同じ`spawn`経路・
    // 同じenv（allowlist済み）・同じスクリプトで、**AppContainerかどうかだけ**を動かす。
    // これが通れば「CurrentUserストアが開かない」はAppContainer固有の性質だと言えるし、
    // ここも落ちるなら原因はこちらの起動側にある（B-29: 変数を1つだけ動かす）。
    let variants: [(&str, Vec<windows::Win32::Security::PSID>, bool); 5] = [
        (
            "capability無し（本番のspawnと同じ）",
            vec![traverse.as_psid()],
            false,
        ),
        (
            "＋sharedUserCertificates",
            vec![traverse.as_psid(), shared_certs.0],
            false,
        ),
        (
            "＋Storageに載っていたcapability",
            vec![traverse.as_psid(), storage_reader.0],
            false,
        ),
        (
            "＋両方",
            vec![traverse.as_psid(), shared_certs.0, storage_reader.0],
            false,
        ),
        ("**対照**: AppContainerにしない", vec![], true),
    ];

    for (label, caps, no_appcontainer) in &variants {
        let script = probe_script(label, &certs, &profile, false);
        let encoded = encoded_command(&script);
        let mut child = SpikeSpawn {
            exe: &shell,
            args: &["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded],
            cwd: Path::new(r"C:\Windows\System32"),
            container_sid: sid.as_psid(),
            capabilities: caps,
            child_process_restricted: false,
            stdout_override: None,
            extra_inherit: &[],
            process_sddl: None,
            thread_sddl: None,
            token_default_dacl_sddl: None,
            no_appcontainer: *no_appcontainer,
            console: SpikeConsole::NoWindow,
        }
        .spawn()
        .unwrap_or_else(|e| panic!("spawn（{label}）: {e}"));
        let (out, err, code) = child.wait_and_read();
        eprintln!("[N1-caps] {label} exit={code}\n{out}\n--- stderr ---\n{err}");
        row(&format!("中・{label}"), &out);
        assert_eq!(
            kv(&out, "DONE").as_deref(),
            Some("1"),
            "観測スクリプトが最後まで走っていない（{label}）:\n{out}"
        );
    }
}

// ---------------------------------------------------------------------------
// procmonで一次原因を見るための最小プローブ
// ---------------------------------------------------------------------------

/// **procmonでキャプチャする用の最小プローブ。**
///
/// N1の測定は「どこへ置いても中からストアが開かない」で止まっており、**なぜ
/// `ERROR_FILE_NOT_FOUND`なのか**（CryptoAPIが実際にどのパスを引いて失敗しているか）は
/// 測れていない。それを見るにはprocmonで実際のI/Oを覗くしかない。
///
/// # 使い方（procmonは**ユーザーがGUIから操作する**、`docs/DEV-ENVIRONMENT.md`）
///
/// 1. procmonを起動し、キャプチャを開始する
/// 2. このテストを回す。**コンテナ子プロセスのPIDを標準エラーへ出す**ので、それで絞り込む
/// 3. キャプチャを止め、CSVへ保存する
///
/// # 何を最小にしてあるか
///
/// キャプチャ窓に入る雑音を減らすため、**証明書の生成もストアへの種まきもしない**。
/// コンテナの中で`X509Store('Root','CurrentUser')`を開こうとして失敗する、それだけを撃つ。
/// 対照として**同じ子プロセスの中で**`LocalMachine`側も開く——成功する側のI/Oが並ぶので、
/// 「失敗した側だけが引いているパス」を差分で読める（B-29）。
#[test]
#[ignore = "procmonでのキャプチャ専用。非昇格で単体実行し、出力されたPIDで絞り込むこと"]
fn n1_procmon_minimal_store_open_probe() {
    let profile = format!("harness.n1pm.{}", std::process::id());
    let cleanup_profile = profile.clone();
    let _guard = super::test_support::scopeguard(move || unsafe {
        let w = crate::win_common::wide(&cleanup_profile);
        let _ = windows::Win32::Security::Isolation::DeleteAppContainerProfile(
            windows::core::PCWSTR(w.as_ptr()),
        );
    });
    let sid = ensure_profile_for_test(&profile).expect("create the spike AppContainer profile");

    let script = r#"
$ErrorActionPreference = 'Continue'
Write-Output ("CHILD_PID=" + $PID)
# ここが本題。失敗する側。
try {
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser')
    $s.Open('ReadOnly')
    Write-Output ("USER_ROOT=" + $s.Certificates.Count)
    $s.Close()
} catch { Write-Output ("USER_ROOT=EXCEPTION:" + $_.Exception.Message) }
# 対照。成功する側（同じプロセスの同じAPIで、コンテキストだけが違う）。
try {
    $m = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine')
    $m.Open('ReadOnly')
    Write-Output ("MACHINE_ROOT=" + $m.Certificates.Count)
    $m.Close()
} catch { Write-Output ("MACHINE_ROOT=EXCEPTION:" + $_.Exception.Message) }
Write-Output 'DONE=1'
"#;

    let (shell, _) = resolve_shell();
    let encoded = encoded_command(script);
    let child = spawn(
        &shell,
        &["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded],
        Path::new(r"C:\Windows\System32"),
        &child_env(),
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        super::RedirectorInject::default(),
        DomainIdentity::OwnPackage,
    )
    .expect("spawn powershell inside the spike AppContainer");
    let pid = child.pid();
    eprintln!("[N1-procmon] ========================================");
    eprintln!("[N1-procmon] コンテナ子プロセスのPID = {pid}");
    eprintln!("[N1-procmon] procmonではこのPIDで絞り込むこと");
    eprintln!("[N1-procmon] ========================================");
    let (out, err, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("read the container child's output");
    eprintln!("[N1-procmon] exit={code}\n{out}\n--- stderr ---\n{err}");
    eprintln!(
        "[N1-procmon] （再掲）PID = {pid} / 子が自称したPID = {:?}",
        kv(&out, "CHILD_PID")
    );
    assert_eq!(kv(&out, "DONE").as_deref(), Some("1"));
}

/// procmonが指した`AppContainer\Mappings\<package SID>`が、**存在しない**のか
/// **中から見えない**のかを切り分ける。
///
/// procmonの実測（2026-08-16）で、コンテナ内のCryptoAPIは`CurrentUser`のストアを開く前に
/// `HKCU\Software\Classes\Local Settings\…\AppContainer\Mappings\<package SID>`を引き、
/// `NAME NOT FOUND`を受けて`ERROR_FILE_NOT_FOUND`で返っていた。**ストアの物理パスには
/// 一度も触っていない**——だから`Storage`配下へ何を置いても効かなかった。
///
/// 一方、外から見ると`Mappings`には`harness.shell.sandbox`系が登録されている
/// （`CreateAppContainerProfile`が作る）。**外にあるのに中で`NAME NOT FOUND`になる**なら、
/// AppContainerのレジストリリダイレクト（`REPARSE`）で別の場所を見ていることになる。
#[test]
#[ignore = "実AppContainerを使う。非昇格で走らせること"]
fn n1_is_the_appcontainer_mapping_key_missing_or_just_invisible() {
    let profile = format!("harness.n1map.{}", std::process::id());
    let cleanup_profile = profile.clone();
    let _guard = super::test_support::scopeguard(move || unsafe {
        let w = crate::win_common::wide(&cleanup_profile);
        let _ = windows::Win32::Security::Isolation::DeleteAppContainerProfile(
            windows::core::PCWSTR(w.as_ptr()),
        );
    });
    let sid = ensure_profile_for_test(&profile).expect("create the spike AppContainer profile");
    let pkg_sid = crate::win_common::sid_to_string(sid.as_psid()).expect("package SID string");
    eprintln!("[N1-map] profile={profile} package_sid={pkg_sid}");

    let mappings = format!(
        r"HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\{pkg_sid}"
    );
    let script = format!(
        r#"
$ErrorActionPreference = 'Continue'
function Say($k, $v) {{ Write-Output ("$k=" + (($v -as [string]) -replace '\s+', ' ')) }}
function Try1($k, $b) {{ try {{ Say $k (& $b) }} catch {{ Say $k ("EXCEPTION:" + $_.Exception.Message) }} }}
Try1 'MAPPING_OPEN' {{ (Get-Item '{mappings}' -EA Stop).PSChildName }}
Try1 'MAPPING_MONIKER' {{ (Get-ItemProperty '{mappings}' -EA Stop).Moniker }}
Try1 'MAPPINGS_PARENT_COUNT' {{
    (Get-ChildItem 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings' -EA Stop).Count
}}
Say 'DONE' '1'
"#
    );

    let (outside, _, _) = ps_outside(&script);
    eprintln!("[N1-map][外]\n{outside}");
    let (inside, _, _) = ps_in_container(sid.as_psid(), &script);
    eprintln!("[N1-map][中]\n{inside}");

    eprintln!(
        "[N1-map][まとめ] Mappingsキー: 外={} / 中={} ｜ Moniker: 外={} / 中={} ｜ Mappings配下の件数: 外={} / 中={}",
        kv(&outside, "MAPPING_OPEN").unwrap_or_default(),
        kv(&inside, "MAPPING_OPEN").unwrap_or_default(),
        kv(&outside, "MAPPING_MONIKER").unwrap_or_default(),
        kv(&inside, "MAPPING_MONIKER").unwrap_or_default(),
        kv(&outside, "MAPPINGS_PARENT_COUNT").unwrap_or_default(),
        kv(&inside, "MAPPINGS_PARENT_COUNT").unwrap_or_default(),
    );
    assert_eq!(kv(&inside, "DONE").as_deref(), Some("1"));
}

/// **結論を覆し得る最後の一手**: `AppContainer\Mappings\<package SID>`を外から作れば、
/// コンテナ専用の証明書ストアが生き返るか。
///
/// procmonが示したのは「crypt32は`Mappings\<SID>`でモニカを引き、無いので即失敗する」だった
/// （ストアの物理パスには一度も触っていない）。この登録はHKCU配下＝**昇格不要**で作れる。
/// 作った上でストアを置いたとき中から見えるなら、D-65の層1は成立する。
#[test]
#[ignore = "実AppContainerとHKCUへの書込を使う。非昇格で、--test-threads=1で走らせること"]
fn n1_does_creating_the_appcontainer_mapping_revive_the_per_container_store() {
    let profile = format!("harness.n1rev.{}", std::process::id());
    let certs = create_spike_certs();
    let cleanup_thumbs = (certs.ca_thumb.clone(), certs.leaf_thumb.clone());
    let cleanup_profile = profile.clone();
    let _guard = super::test_support::scopeguard(move || {
        cleanup_all(&cleanup_thumbs, &cleanup_profile);
    });

    let sid = ensure_profile_for_test(&profile).expect("create the spike AppContainer profile");
    let pkg_sid = crate::win_common::sid_to_string(sid.as_psid()).expect("package SID string");
    eprintln!("[N1-rev] profile={profile} package_sid={pkg_sid}");
    // `certutil -user -verify`に食わせる証明書を、コンテナが読める`AC\Temp`へ置く。
    let (_, _, ac_code) = ps_outside(
        &TEMPLATE_SEED_AC_TEMP
            .replace("%%PROFILE%%", &profile)
            .replace("%%LEAF_B64%%", &certs.leaf_der_b64)
            .replace("%%CA_B64%%", &certs.ca_der_b64),
    );
    assert_eq!(ac_code, 0, "ACフォルダへの証明書配置が失敗した");

    // Mappingsエントリの撤収を、作る前に登録する（B-01）。
    let revoke_sid = pkg_sid.clone();
    let _map_guard = super::test_support::scopeguard(move || {
        let script = format!(
            r#"$ErrorActionPreference='SilentlyContinue'
Remove-Item -Path 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\{revoke_sid}' -Recurse -Force
Write-Output ("MAPPING_LEFT=" + (Test-Path 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\{revoke_sid}'))"#
        );
        let (out, _, _) = ps_outside(&script);
        eprintln!("[N1-rev][Mappings撤収] {out}");
        assert_eq!(
            kv(&out, "MAPPING_LEFT").as_deref(),
            Some("False"),
            "作ったMappingsエントリが残っている"
        );
    });

    // 1. 既存エントリ（`harness.shell.sandbox`）と同じ形で登録を作る。
    let seed_map = format!(
        r#"
$ErrorActionPreference = 'Stop'
$base = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings'
$key = Join-Path $base '{pkg_sid}'
New-Item -Path $key -Force | Out-Null
New-Item -Path (Join-Path $key 'Children') -Force | Out-Null
Set-ItemProperty -Path $key -Name Moniker -Value '{profile}'
Set-ItemProperty -Path $key -Name DisplayName -Value 'Harness N1 Spike'
# コンテナ自身が読めるようにする（既存エントリと同じくpackage SIDへ許可）。
$sid = New-Object System.Security.Principal.SecurityIdentifier('{pkg_sid}')
foreach ($k in @($key, (Join-Path $key 'Children'))) {{
    $acl = Get-Acl $k
    $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
        $sid, 'ReadKey', 'ContainerInherit', 'None', 'Allow')))
    Set-Acl -Path $k -AclObject $acl
}}
Write-Output ("MAPPING_MADE=" + (Get-ItemProperty $key).Moniker)
"#
    );
    let (map_out, map_err, map_code) = ps_outside(&seed_map);
    eprintln!("[N1-rev][Mappings作成] exit={map_code} {map_out} {map_err}");
    assert_eq!(map_code, 0, "Mappingsエントリの作成に失敗した");

    // 2. コンテナ専用ストア（Storage側）にCAを置き、package SID宛のACEも付ける。
    let seed = TEMPLATE_SEED_CONTAINER_STORE
        .replace("%%CA_B64%%", &certs.ca_der_b64)
        .replace("%%CA_THUMB%%", &certs.ca_thumb)
        .replace("%%SCRATCH%%", SCRATCH_STORE)
        .replace("%%STORAGE%%", STORAGE_ROOT)
        .replace("%%PROFILE%%", &profile);
    let (_, _, seed_code) = ps_outside(&seed);
    assert_eq!(seed_code, 0, "コンテナ専用ストアへの書込が失敗した");
    let (_, _, grant_code) = grant_storage_ace(&pkg_sid, &profile, "FullControl");
    assert_eq!(grant_code, 0, "package SID宛ACEの付与が失敗した");

    // 3. 中から見る。
    let (inside, inside_err, _) = ps_in_container(
        sid.as_psid(),
        &probe_script("REVIVE", &certs, &profile, true),
    );
    eprintln!("[N1-rev][中]\n{inside}\n--- stderr ---\n{inside_err}");
    row("中・Mappings登録あり＋コンテナ専用ストアにCA", &inside);
    eprintln!(
        r"[N1-rev][**判定**] CurrentUser\Rootが開いたか={} / そこに置いたCAが見えるか={}",
        kv(&inside, "ROOT_RO_COUNT").unwrap_or_default(),
        kv(&inside, "ROOT_RO_HAS_CA").unwrap_or_default(),
    );
    assert_eq!(kv(&inside, "DONE").as_deref(), Some("1"));
}

/// 層1を成立させるために**実マシンへ書く必要がある最小セット**を絞る。
///
/// [`n1_does_creating_the_appcontainer_mapping_revive_the_per_container_store`]は
/// `Moniker`＋`DisplayName`＋`Children`＋package SID宛ACEを全部書いた。実装が残す副作用は
/// 小さいほどよい（D-65の表の「実マシンへの副作用」列がそのまま変わる）ので、
/// **`Moniker`だけ・ACE無し**で成立するかを見る。
#[test]
#[ignore = "実AppContainerとHKCUへの書込を使う。非昇格で、--test-threads=1で走らせること"]
fn n1_minimal_write_set_for_the_per_container_store() {
    let profile = format!("harness.n1min.{}", std::process::id());
    let certs = create_spike_certs();
    let cleanup_thumbs = (certs.ca_thumb.clone(), certs.leaf_thumb.clone());
    let cleanup_profile = profile.clone();
    let _guard = super::test_support::scopeguard(move || {
        cleanup_all(&cleanup_thumbs, &cleanup_profile);
    });

    let sid = ensure_profile_for_test(&profile).expect("create the spike AppContainer profile");
    let pkg_sid = crate::win_common::sid_to_string(sid.as_psid()).expect("package SID string");
    let revoke_sid = pkg_sid.clone();
    let _map_guard = super::test_support::scopeguard(move || {
        let script = format!(
            r#"$ErrorActionPreference='SilentlyContinue'
Remove-Item -Path 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\{revoke_sid}' -Recurse -Force
Write-Output ("MAPPING_LEFT=" + (Test-Path 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\{revoke_sid}'))"#
        );
        let (out, _, _) = ps_outside(&script);
        eprintln!("[N1-min][Mappings撤収] {out}");
        assert_eq!(kv(&out, "MAPPING_LEFT").as_deref(), Some("False"));
    });

    // **`Moniker`だけ**。`DisplayName`も`Children`もACEも書かない。
    let seed_map = format!(
        r#"
$ErrorActionPreference = 'Stop'
$key = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings\{pkg_sid}'
New-Item -Path $key -Force | Out-Null
Set-ItemProperty -Path $key -Name Moniker -Value '{profile}'
Write-Output ("MAPPING_MADE=" + (Get-ItemProperty $key).Moniker)
"#
    );
    let (map_out, _, map_code) = ps_outside(&seed_map);
    eprintln!("[N1-min][Mappings作成（Monikerのみ）] exit={map_code} {map_out}");
    assert_eq!(map_code, 0, "Mappingsエントリの作成に失敗した");

    // ストア側も**ACE無し**で置く（`Blob`と論理ストアの骨組みだけ）。
    let seed = TEMPLATE_SEED_CONTAINER_STORE
        .replace("%%CA_B64%%", &certs.ca_der_b64)
        .replace("%%CA_THUMB%%", &certs.ca_thumb)
        .replace("%%SCRATCH%%", SCRATCH_STORE)
        .replace("%%STORAGE%%", STORAGE_ROOT)
        .replace("%%PROFILE%%", &profile);
    let (_, _, seed_code) = ps_outside(&seed);
    assert_eq!(seed_code, 0, "コンテナ専用ストアへの書込が失敗した");

    let (inside, _, _) =
        ps_in_container(sid.as_psid(), &probe_script("MIN", &certs, &profile, false));
    eprintln!("[N1-min][中]\n{inside}");
    eprintln!(
        "[N1-min][**判定**] Monikerのみ・ACE無しで: ストアが開いたか={} / CAが見えるか={} / チェーン={}",
        kv(&inside, "ROOT_RO_COUNT").unwrap_or_default(),
        kv(&inside, "ROOT_RO_HAS_CA").unwrap_or_default(),
        kv(&inside, "CHAIN_USER").unwrap_or_default(),
    );
    assert_eq!(kv(&inside, "DONE").as_deref(), Some("1"));
}

// ---------------------------------------------------------------------------
// ③ `Mappings`側と`Storage`側の、どちらのACEが必須か（2×2の残り2象限）
// ---------------------------------------------------------------------------

/// `…\AppContainer\Mappings`（`STORAGE_ROOT`と兄弟。モニカ解決に使われる方）。
const MAPPINGS_ROOT: &str = r"HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings";

/// `Mappings\<package SID>`を`Moniker`だけで作り、**package SID宛のACEの有無だけ**を切り替える。
///
/// 最後に**読み返して**、意図した構成が実際に載ったかを報告する（見た目の成功を信じない。
/// `feedback-security-self-verification`）。`MAPPING_PKG_ACE`が期待と違えば、その象限は
/// 「測ったつもりの構成」を測っていないので呼び出し側が落とす。
const TEMPLATE_SEED_MAPPING_VARIANT: &str = r#"
$ErrorActionPreference = 'Stop'
$key = '%%MAPPINGS%%\%%PKG_SID%%'
New-Item -Path $key -Force | Out-Null
Set-ItemProperty -Path $key -Name Moniker -Value '%%PROFILE%%'
if ('%%WITH_ACE%%' -eq 'yes') {
    $sid = New-Object System.Security.Principal.SecurityIdentifier('%%PKG_SID%%')
    $acl = Get-Acl $key
    $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
        $sid, 'ReadKey', 'ContainerInherit', 'None', 'Allow')))
    Set-Acl -Path $key -AclObject $acl
}
Write-Output ("MONIKER=" + (Get-ItemProperty $key).Moniker)
Write-Output ("MAPPING_PKG_ACE=" + @((Get-Acl $key).Access |
    Where-Object { $_.IdentityReference.Value -eq '%%PKG_SID%%' }).Count)
"#;

/// 象限ごとに「外から見て、実際にどういう構成になっているか」を1画面に出す。
///
/// **`ALL APPLICATION PACKAGES`（`S-1-15-2-1`）が継承で載っていないか**を必ず見る——載っていれば
/// 「ACEを付けていない」つもりの象限が実は許可されており、2×2が2×2になっていない（B-29）。
/// `IdentityReference`は既定で名前へ解決されるので、SIDへ**戻してから**前方一致を見る。
const TEMPLATE_QUADRANT_FACTS: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$m = '%%MAPPINGS%%\%%PKG_SID%%'
$s = '%%STORAGE%%\%%PROFILE%%'
function Dump($path) {
    $o = @()
    foreach ($a in (Get-Acl $path).Access) {
        $id = $a.IdentityReference.Value
        try { $id = $a.IdentityReference.Translate(
            [System.Security.Principal.SecurityIdentifier]).Value } catch { }
        if ($id -like 'S-1-15-*') { $o += ($id + ':' + $a.RegistryRights) }
    }
    ($o -join ' | ')
}
Write-Output ("F_MONIKER=" + (Get-ItemProperty $m).Moniker)
Write-Output ("F_MAPPING_APPX_ACE=" + (Dump $m))
Write-Output ("F_STORAGE_APPX_ACE=" + (Dump $s))
Write-Output ("F_BLOB=" + (Test-Path (
    $s + '\Software\Microsoft\SystemCertificates\Root\Certificates\%%CA_THUMB%%')))
"#;

/// コンテナの中から、**どの段で止まるか**を1段ずつ見る。
///
/// 判定の勘所は`ROOT_OPEN`の失敗時の**HRESULT**である——`0x80070002`（`FILE_NOT_FOUND`）なら
/// モニカ解決の失敗、`0x80070005`（`ACCESS_DENIED`）ならACE不足。`.Message`はこの機では
/// 日本語化されるので指標にしない（言語に依存しない数値で判定する）。PowerShellは.NETの例外を
/// `MethodInvocationException`で包むため、**最内側まで辿ってから**`HResult`を読む。
/// レジストリプロバイダ（`Get-Item`）経由はどちらも`0x8013150A`等の.NET側HRESULTになるので、
/// **例外の型名**（`SecurityException`＝拒否／`ItemNotFoundException`＝不在）も併せて出す。
const TEMPLATE_ACE_MATRIX_PROBE: &str = r#"
$ErrorActionPreference = 'Continue'
function Say($k, $v) { Write-Output ("$k=" + (($v -as [string]) -replace '\s+', ' ')) }
function Try1($k, $block) {
    try { Say $k (& $block) }
    catch {
        $x = $_.Exception
        while ($x.InnerException) { $x = $x.InnerException }
        Say $k ("EXC:" + $x.GetType().Name + ":" + ("0x{0:X8}" -f $x.HResult) + ":" + $x.Message)
    }
}
# 「本当にAppContainerの中で走っているか」の診断（**判定には使わない**）。
#
# ここで素直に見えそうな2つは、この機では**どちらも中で0を返す**ことが実測で分かった——
# `whoami.exe /groups /nh`は1行も返さず（LSAへの名前解決に届かないためと見られる）、
# `WindowsIdentity.GetCurrent().Groups`も`S-1-15-2-1`を載せない。つまり
# **「0件＝コンテナの外」と読めてしまう**ので、これらを生死判定に使ってはいけない。
# 実際の判定は呼び出し側が`MY_COUNT`（ユーザー自身のストアが見えていないこと）で行う。
Try1 'GROUPS_COUNT' { @([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups).Count }
Try1 'GROUPS_S1_15' {
    (@([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups |
        ForEach-Object { $_.Value } | Where-Object { $_ -like 'S-1-15-*' }) -join ',')
}
Try1 'WHOAMI_GROUPS' { (@(& whoami.exe /groups /nh 2>&1).Count) }
# 1. モニカ解決の入口。ここが読めないなら`Mappings`側のACEが要る。
Try1 'MAPPING_MONIKER' { (Get-ItemProperty '%%MAPPINGS_KEY%%' -EA Stop).Moniker }
# 2. ストアの物理キー（絶対パスで直接）。ここが読めないなら`Storage`側のACEが要る。
Try1 'STORAGE_CERT_COUNT' { (Get-Item '%%STORAGE_CERTS%%' -EA Stop).SubKeyCount }
# 3. リダイレクト後の論理パス（中から見た`HKCU`）。2と3の差がリダイレクトの働き。
Try1 'REDIR_ROOT_COUNT' {
    (Get-Item 'HKCU:\Software\Microsoft\SystemCertificates\Root\Certificates' -EA Stop).SubKeyCount
}
# 4. **判定の本体**。
Try1 'ROOT_OPEN' {
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser')
    $s.Open('ReadOnly'); $n = $s.Certificates.Count; $s.Close(); $n
}
Try1 'ROOT_HAS_CA' {
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser')
    $s.Open('ReadOnly')
    $n = @($s.Certificates | Where-Object { $_.Thumbprint -eq '%%CA_THUMB%%' }).Count
    $s.Close(); $n
}
# 5. **隔離が壊れていないこと**（許可側だけを見て「通った」と言わないための対**照**。
#    ユーザーの`My`が見えたら、見ているのはコンテナのストアではなくユーザーのストアである）。
Try1 'MY_COUNT' {
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('My','CurrentUser')
    $s.Open('ReadOnly'); $n = $s.Certificates.Count; $s.Close(); $n
}
# 6. 信頼判断の実体。`ExtraStore`で**チェーン構築の材料**は常に与えるので、
#    `NoError`と`UntrustedRoot`の差は「その根が信頼された置き場に在るか」だけになる。
Try1 'CHAIN_USER' {
    $ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        ,[Convert]::FromBase64String('%%CA_B64%%'))
    $leaf = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        ,[Convert]::FromBase64String('%%LEAF_B64%%'))
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = 'NoCheck'
    $chain.ChainPolicy.ExtraStore.Add($ca) | Out-Null
    $ok = $chain.Build($leaf)
    $st = ($chain.ChainStatus | ForEach-Object { $_.Status }) -join '+'
    if ($st -eq '') { $st = 'NoError' }
    "$ok/$st"
}
Say 'DONE' '1'
"#;

/// 象限1つ分の痕跡（`Mappings`エントリ・`Storage`キー・プロファイル）を剥がす。
const TEMPLATE_CLEANUP_QUADRANT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
Remove-Item -Path '%%MAPPINGS%%\%%PKG_SID%%' -Recurse -Force
Remove-Item -Path '%%STORAGE%%\%%PROFILE%%' -Recurse -Force
Remove-Item -Path (Join-Path $env:LOCALAPPDATA 'Packages\%%PROFILE%%') -Recurse -Force
Write-Output ("MAPPING_LEFT=" + (Test-Path '%%MAPPINGS%%\%%PKG_SID%%'))
Write-Output ("STORAGE_LEFT=" + (Test-Path '%%STORAGE%%\%%PROFILE%%'))
"#;

/// 撤収は**戻り値ではなく状態で**確かめる（型F: ロールバックまでが設計）。
fn cleanup_quadrant(profile: &str, pkg_sid: &str) {
    let (out, err, _) = ps_outside(
        &TEMPLATE_CLEANUP_QUADRANT
            .replace("%%MAPPINGS%%", MAPPINGS_ROOT)
            .replace("%%PKG_SID%%", pkg_sid)
            .replace("%%STORAGE%%", STORAGE_ROOT)
            .replace("%%PROFILE%%", profile),
    );
    eprintln!("[N1-ace][撤収 {profile}] {out} {err}");
    unsafe {
        let w = crate::win_common::wide(profile);
        let _ = windows::Win32::Security::Isolation::DeleteAppContainerProfile(
            windows::core::PCWSTR(w.as_ptr()),
        );
    }
    for key in ["MAPPING_LEFT", "STORAGE_LEFT"] {
        if kv(&out, key).as_deref() != Some("False") {
            // `Drop`の中なので、既にpanicしている最中の二重panicは避ける（原因が読めなくなる）。
            let msg = format!("{key}が撤収できていない（profile={profile}）:\n{out}");
            if std::thread::panicking() {
                eprintln!("[N1-ace][!!] {msg}");
            } else {
                panic!("{msg}");
            }
        }
    }
}

/// 1象限分の観測（この5つで表の1行になる）。
struct Quadrant {
    label: &'static str,
    root_open: String,
    has_ca: String,
    chain: String,
    my_count: String,
    moniker: String,
    storage_key: String,
}

/// **③: `Mappings`側と`Storage`側の、どちらのpackage SID宛ACEが必須か。**
///
/// これまで測ったのは「両方付ける（成功）」と「両方付けない（`ACCESS_DENIED`）」の2点だけで、
/// 実装が**どちらを書かねばならないか**は決まっていない（`plans/net-spike/RESULTS.md`
/// N1（訂正）の「まだ測っていないこと」3）。2変数の2×2へ広げて残る2象限を撃つ。
///
/// # 象限を別プロファイルへ割る理由
///
/// ACEを足したり剥がしたりして1つのプロファイルを使い回すと、剥がし漏れが次の象限の結果に
/// 化けて出る（順序効果）。package SIDはプロファイル名から決まるので、**象限ごとに新しい名前**に
/// すれば各象限は互いに独立になる（B-29: 一度に1変数だけ動かす）。
///
/// # 何をもって「測定が成立した」とするか
///
/// 禁止側（ACEを欠いた象限が失敗すること）だけでは、機構が**まるごと死んでいる**場合も緑になる
/// （B-35）。そこで**許可側の対照**——「両方＋`FullControl`」でストアが開くこと——を同じ実行に
/// 含め、そこが開かなければ測定全体を無効として落とす。
///
/// # 5行目（`ReadKey`）は最小権限の下限探り
///
/// 2×2そのものではないが、`Storage`側が読取だけで足りるなら実装が実マシンへ残す権限が下がる
/// （P-01）。「両方＋`FullControl`」からの1変数変更なので、同じ表に並べて読める。
#[test]
#[ignore = "実AppContainerとHKCUへの書込を使う。**非昇格**で、--test-threads=1で走らせること"]
fn n1_which_ace_is_required_mappings_or_storage() {
    let pid = std::process::id();
    let certs = create_spike_certs();

    // 証明書と作業ストアの後始末。**象限ごとの痕跡は各象限のガードが先に落とす**ので、
    // ここへ渡すプロファイル名（象限0）に対する操作は既に空振りになっている——
    // この呼び出しが担うのは`Cert:\CurrentUser\*`の残数確認と`HarnessN1*`の掃除である。
    let cleanup_thumbs = (certs.ca_thumb.clone(), certs.leaf_thumb.clone());
    let cleanup_profile = format!("harness.n1ace0.{pid}");
    let _cert_guard = super::test_support::scopeguard(move || {
        cleanup_all(&cleanup_thumbs, &cleanup_profile);
    });

    // (ラベル, `Mappings`側のACE, `Storage`側のACEと権限)
    let plan: [(&str, bool, Option<&str>); 5] = [
        ("① 両方付けない（既知: ACCESS_DENIED）", false, None),
        ("② Mappings側だけ", true, None),
        ("③ Storage側だけ", false, Some("FullControl")),
        (
            "④ 両方（既知: 成功。**許可側の対照**）",
            true,
            Some("FullControl"),
        ),
        (
            "⑤ 両方だがStorage側はReadKey（最小権限の下限）",
            true,
            Some("ReadKey"),
        ),
    ];

    // **「中で走っている」ことの基準線**（B-29: 測っている世界を取り違えない）。
    // 中の`My`がこの値と一致したら、それはコンテナのストアではなく**ユーザーのストア**である
    // ＝AppContainerになっていない。中で0や拒否になるのが正常。
    let (my_out, _, _) = ps_outside(
        r#"$s = New-Object System.Security.Cryptography.X509Certificates.X509Store('My','CurrentUser')
$s.Open('ReadOnly'); Write-Output ("USER_MY=" + $s.Certificates.Count); $s.Close()"#,
    );
    let user_my = kv_req(&my_out, "USER_MY");
    eprintln!("[N1-ace] ユーザー自身のCurrentUser\\My = {user_my}件（中でこの値が出たら測定は無効）");

    let mut rows: Vec<Quadrant> = Vec::new();

    for (i, (label, map_ace, storage_ace)) in plan.iter().enumerate() {
        eprintln!("\n[N1-ace] ================ {label} ================");
        let profile = format!("harness.n1ace{i}.{pid}");
        let sid = ensure_profile_for_test(&profile).expect("create the spike AppContainer profile");
        let pkg_sid = crate::win_common::sid_to_string(sid.as_psid()).expect("package SID string");

        // 撤収を、作る前に登録する（B-01: 対で、しかも撤収を先に置く）。
        let g_profile = profile.clone();
        let g_sid = pkg_sid.clone();
        let _quadrant_guard = super::test_support::scopeguard(move || {
            cleanup_quadrant(&g_profile, &g_sid);
        });

        // --- 1. Mappingsエントリ（Monikerのみ。ACEだけを象限で切り替える） -----
        let (m_out, m_err, m_code) = ps_outside(
            &TEMPLATE_SEED_MAPPING_VARIANT
                .replace("%%MAPPINGS%%", MAPPINGS_ROOT)
                .replace("%%PKG_SID%%", &pkg_sid)
                .replace("%%PROFILE%%", &profile)
                .replace("%%WITH_ACE%%", if *map_ace { "yes" } else { "no" }),
        );
        assert_eq!(
            m_code, 0,
            "[{label}] Mappingsエントリの作成に失敗した: {m_out}{m_err}"
        );
        assert_eq!(
            kv(&m_out, "MAPPING_PKG_ACE").as_deref(),
            Some(if *map_ace { "1" } else { "0" }),
            "[{label}] Mappings側ACEの有無が意図と違う。この象限は測るつもりの構成になっていない:\n{m_out}"
        );

        // --- 2. Storage側（Blobは常に置き、ACEだけを象限で切り替える） ---------
        let (s_out, s_err, s_code) = ps_outside(
            &TEMPLATE_SEED_CONTAINER_STORE
                .replace("%%CA_B64%%", &certs.ca_der_b64)
                .replace("%%CA_THUMB%%", &certs.ca_thumb)
                .replace("%%SCRATCH%%", SCRATCH_STORE)
                .replace("%%STORAGE%%", STORAGE_ROOT)
                .replace("%%PROFILE%%", &profile),
        );
        assert_eq!(
            s_code, 0,
            "[{label}] コンテナ専用ストアへの書込が失敗した: {s_out}{s_err}"
        );
        if let Some(rights) = storage_ace {
            let (g_out, g_err, g_code) = grant_storage_ace(&pkg_sid, &profile, rights);
            assert_eq!(
                g_code, 0,
                "[{label}] Storage側ACE（{rights}）の付与が失敗した: {g_out}{g_err}"
            );
            eprintln!("[N1-ace][Storage側ACE={rights}] {g_out}");
        }

        // --- 3. 外から見た構成の自己検証（型A: 設定値ではなく実際に載ったもの） -
        let (facts, _, _) = ps_outside(
            &TEMPLATE_QUADRANT_FACTS
                .replace("%%MAPPINGS%%", MAPPINGS_ROOT)
                .replace("%%PKG_SID%%", &pkg_sid)
                .replace("%%STORAGE%%", STORAGE_ROOT)
                .replace("%%PROFILE%%", &profile)
                .replace("%%CA_THUMB%%", &certs.ca_thumb),
        );
        eprintln!("[N1-ace][外から見た構成]\n{facts}");
        assert_eq!(
            kv(&facts, "F_BLOB").as_deref(),
            Some("True"),
            "[{label}] CAのBlobが置けていない。中で見えなくても当たり前になる:\n{facts}"
        );

        // --- 4. 中から測る -----------------------------------------------------
        let script = TEMPLATE_ACE_MATRIX_PROBE
            .replace(
                "%%MAPPINGS_KEY%%",
                &format!("{MAPPINGS_ROOT}\\{pkg_sid}"),
            )
            .replace(
                "%%STORAGE_CERTS%%",
                &format!(
                    r"{STORAGE_ROOT}\{profile}\Software\Microsoft\SystemCertificates\Root\Certificates"
                ),
            )
            .replace("%%CA_THUMB%%", &certs.ca_thumb)
            .replace("%%CA_B64%%", &certs.ca_der_b64)
            .replace("%%LEAF_B64%%", &certs.leaf_der_b64);
        let (inside, inside_err, code) = ps_in_container(sid.as_psid(), &script);
        eprintln!("[N1-ace][中] exit={code}\n{inside}\n--- stderr ---\n{inside_err}");
        assert_eq!(
            kv(&inside, "DONE").as_deref(),
            Some("1"),
            "[{label}] 観測スクリプトが最後まで走っていない:\n{inside}"
        );
        assert_ne!(
            kv(&inside, "MY_COUNT").as_deref(),
            Some(user_my.as_str()),
            "[{label}] 中の`My`がユーザー自身の{user_my}件と一致した。\
             子がAppContainerの中で走っていない＝測っている世界が違う:\n{inside}"
        );

        rows.push(Quadrant {
            label,
            root_open: kv(&inside, "ROOT_OPEN").unwrap_or_default(),
            has_ca: kv(&inside, "ROOT_HAS_CA").unwrap_or_default(),
            chain: kv(&inside, "CHAIN_USER").unwrap_or_default(),
            my_count: kv(&inside, "MY_COUNT").unwrap_or_default(),
            moniker: kv(&inside, "MAPPING_MONIKER").unwrap_or_default(),
            storage_key: kv(&inside, "STORAGE_CERT_COUNT").unwrap_or_default(),
        });
    }

    eprintln!("\n[N1-ace][**まとめ**] 中から見た結果（HRESULT: 0x80070002=FILE_NOT_FOUND / 0x80070005=ACCESS_DENIED）");
    for r in &rows {
        eprintln!(
            "  {}\n      Mappings\\<SID>のMoniker読取 = {}\n      Storage\\…\\Certificates読取 = {}\n      \
             CurrentUser\\Rootのopen  = {}\n      そこに我々のCA         = {} / チェーン = {}\n      \
             ユーザーのMyが見えるか = {}（0であること＝隔離が効いている）",
            r.label, r.moniker, r.storage_key, r.root_open, r.has_ca, r.chain, r.my_count,
        );
    }

    // **許可側の対照が成立していなければ、禁止側の結果は読めない**（B-35 / 問2）。
    let both = &rows[3];
    let opened = both.root_open.parse::<u32>().unwrap_or(0);
    assert!(
        opened > 0,
        "許可側の対照（{}）でストアが開いていない。この実行の測定は無効:\n{:?}",
        both.label,
        both.root_open
    );
    assert_eq!(
        both.has_ca, "1",
        "許可側の対照で我々のCAが見えていない。この実行の測定は無効"
    );
}

// ---------------------------------------------------------------------------
// ② `Mappings`エントリを**何が作るのか**
// ---------------------------------------------------------------------------

/// loopback exemptionを**足して → 見て → 外して → 見る**（**このプロセスが昇格しているときだけ**）。
///
/// `CheckNetIsolation LoopbackExempt`は`NetworkIsolationSetAppContainerConfig`の
/// OS付属フロントエンドで、**SID→モニカの対応を要するAPI**である（＝`Mappings`を作る候補）。
/// 足しっぱなしで落ちるとマシン全体で1本のリストに残る（BUG-053）ので、
/// **同じスクリプトの中で必ず外す**——テストの後片付けに預けない。
///
/// `-a`と`-d`は**単体のOS付属コマンド**であり、リスト全体を`Set`で上書きしない
/// （BUG-053がまさにそれ）。
const TEMPLATE_EXEMPTION_STEP: &str = r#"
$ErrorActionPreference = 'Continue'
$key = '%%MAPPINGS%%\%%PKG_SID%%'
function State($tag) {
    Write-Output ($tag + '_EXISTS=' + (Test-Path $key))
    if (Test-Path $key) {
        $p = Get-ItemProperty $key
        Write-Output ($tag + '_MONIKER=' + $p.Moniker)
        Write-Output ($tag + '_DISPLAY=' + $p.DisplayName)
    }
}
State 'BEFORE'
$add = (& CheckNetIsolation.exe LoopbackExempt -a "-p=%%PKG_SID%%" 2>&1) -join ' / '
Write-Output ('ADD_OUT=' + $add)
# **「成功しました」を信用しない。** リストに実際に載ったかを読み返す（型A: 実効で測る）——
# ここを確かめずに`AFTER_ADD_EXISTS=False`を「exemptionではMappingsは生えない」と読むと、
# 実は`-a`が何もしていなかった場合に**偽の否定**を掴む。
$list = (& CheckNetIsolation.exe LoopbackExempt -s 2>&1) -join ' '
Write-Output ('EXEMPT_LISTED=' + ($list -match [regex]::Escape('%%PKG_SID%%')))
State 'AFTER_ADD'
$del = (& CheckNetIsolation.exe LoopbackExempt -d "-p=%%PKG_SID%%" 2>&1) -join ' / '
Write-Output ('DEL_OUT=' + $del)
$list2 = (& CheckNetIsolation.exe LoopbackExempt -s 2>&1) -join ' '
Write-Output ('EXEMPT_LISTED_AFTER_DEL=' + ($list2 -match [regex]::Escape('%%PKG_SID%%')))
State 'AFTER_DEL'
Write-Output 'EXEMPT_DONE=1'
"#;

/// **preflightのACE付与に相当する候補**: package SID宛のACEを実ディレクトリへ付ける。
///
/// 自分の持ち物へ付けるだけなので**昇格は要らない**（本番で昇格するのは、workspaceの
/// 祖先traverse ACEのように他人の持ち物へ触るときだけ）。ACE付与そのものはSID→モニカの
/// 解決を要さないはずだが、候補として明示的に潰しておく。
const TEMPLATE_ACE_ON_DIR_STEP: &str = r#"
$ErrorActionPreference = 'Continue'
$dir = Join-Path $env:LOCALAPPDATA ('Temp\n1map2-' + $PID)
New-Item -ItemType Directory -Path $dir -Force | Out-Null
try {
    $sid = New-Object System.Security.Principal.SecurityIdentifier('%%PKG_SID%%')
    $acl = Get-Acl $dir
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $sid, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    Set-Acl -Path $dir -AclObject $acl
    Write-Output ('ACE_APPLIED=' + @((Get-Acl $dir).Access |
        Where-Object { $_.IdentityReference.Value -eq '%%PKG_SID%%' }).Count)
} catch { Write-Output ('ACE_APPLIED=EXC:' + $_.Exception.Message) }
Remove-Item -Path $dir -Recurse -Force -EA SilentlyContinue
Write-Output ('ACE_DIR_LEFT=' + (Test-Path $dir))
Write-Output 'ACE_DONE=1'
"#;

/// コンテナの中から**自分のHKCUへ書く**。
///
/// AppContainerのHKCU書込はそのコンテナ専用領域（`Storage\<moniker>`）へリダイレクトされる。
/// この経路はCryptoAPIと同じく**「このコンテナは何者か」の解決を要する**ので、
/// `Mappings`エントリを作る主体の候補になる。本番のセッションは実際のシェル作業
/// （PowerShellプロファイル・COM・cargo等）でHKCUに触るが、`Write-Output $PID`だけの
/// 子は触らない——**そこが本番と違っていたために「子を起こしても生えない」と読めていた**可能性がある。
const TEMPLATE_CHILD_TOUCHES_OWN_HIVE: &str = r#"
$ErrorActionPreference = 'Continue'
function Say($k, $v) { Write-Output ("$k=" + (($v -as [string]) -replace '\s+', ' ')) }
function Try1($k, $b) {
    try { Say $k (& $b) }
    catch {
        $x = $_.Exception
        while ($x.InnerException) { $x = $x.InnerException }
        Say $k ("EXC:" + $x.GetType().Name + ":" + $x.Message)
    }
}
Try1 'HKCU_READ' { (Get-Item 'HKCU:\Software' -EA Stop).SubKeyCount }
Try1 'HKCU_WRITE' {
    New-Item -Path '%%PLAIN%%' -Force -EA Stop | Out-Null
    Set-ItemProperty -Path '%%PLAIN%%' -Name probe -Value 'from-container' -EA Stop
    (Get-ItemProperty -Path '%%PLAIN%%' -Name probe -EA Stop).probe
}
# 自分のプロファイルフォルダ（`AC`）へ書く——ファイル側の経路も同じ解決を要するかもしれない。
Try1 'AC_FILE_WRITE' {
    $p = Join-Path $env:USERPROFILE 'x'
    [IO.File]::WriteAllText((Join-Path $env:TEMP 'n1map2.txt'), 'x')
    'ok'
}
Say 'DONE' '1'
"#;

/// **②: `…\AppContainer\Mappings\<package SID>`を作っているのは何か。**
///
/// `CreateAppContainerProfile`は作らない（実測。[`n1_is_the_appcontainer_mapping_key_missing_or_just_invisible`]）。
/// にもかかわらず本番の`harness.shell.sandbox*`には在り、しかも
/// `DisplayName`が`ensure_profile_locked`の渡す`"Harness Shell Sandbox"`と一致する
/// ——**プロファイル作成の引数を知っている何かが、後から作っている**。
///
/// 第一候補はloopback exemption（`NetworkIsolationSetAppContainerConfig`）である。
/// 状況証拠として、この機では**exemptionリストが空なのにMappingsエントリだけが残っている**
/// ——「`-a`で生えて`-d`では消えない」なら説明が付く。ここではそれを直接確かめる。
///
/// # なぜ`Mappings`が在るのに実装が自分で作らねばならないか
///
/// **在ることを前提にすると、それを作る操作が起きない構成で黙って層1が死ぬ**
/// （例: ネットワークを使わないセッションではexemptionを足さない）。
/// D-65は**冪等に自分で作る**と決めている。本測定はその根拠を固めるためのもので、
/// 結果がどちらでも「自分で作る」は変わらない。
///
/// # 昇格の扱い（**このテストは両方の世界で回す**）
///
/// 候補のうち`CheckNetIsolation`だけが昇格を要する。そこで本テストは
/// **自分が昇格しているかを見て、昇格している時だけその段を実行する**。
///
/// ```text
/// cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture n1_what_creates
/// target\debug\dev-elevated-run.exe n1-mapping-creator   # 昇格側（KNOWN_TARGETSに登録済み）
/// ```
///
/// **2つの実行の差そのものが測定である**——`CreateAppContainerProfile`が`Mappings`を作るか否かが
/// 昇格の有無で変わるなら、本番の`harness.shell.sandbox*`に在って新規プロファイルに無い理由が
/// それで説明できる（昇格した`netfilterd`/`privhelper`が過去に作っていた、等）。
/// 通常のスパイクで昇格を避ける理由（B-08: 測る世界が変わる）は、ここでは
/// **その「変わること」自体が変数**なので当てはまらない。
#[test]
#[ignore = "実AppContainerとHKCUを使う。**非昇格で1回**、`dev-elevated-run n1-mapping-creator`で**昇格でも1回**回す"]
fn n1_what_creates_the_appcontainer_mapping_entry() {
    let profile = format!("harness.n1map2.{}", std::process::id());
    let sid = ensure_profile_for_test(&profile).expect("create the spike AppContainer profile");
    let pkg_sid = crate::win_common::sid_to_string(sid.as_psid()).expect("package SID string");
    eprintln!("[N1-②] profile={profile} package_sid={pkg_sid}");

    // 撤収を先に登録する（B-01）。`Mappings`が生えた場合も必ず剥がす。
    let g_profile = profile.clone();
    let g_sid = pkg_sid.clone();
    let _guard = super::test_support::scopeguard(move || {
        cleanup_quadrant(&g_profile, &g_sid);
        // **マシン全体で1本のリスト**に残っていないかを、非昇格の読み取りで確かめる（BUG-053）。
        let (out, _, _) = ps_outside(
            r#"$o = (& CheckNetIsolation.exe LoopbackExempt -s 2>&1) -join "`n"
Write-Output ("EXEMPT_DUMP=" + ($o -replace '\s+',' '))"#,
        );
        let dump = kv(&out, "EXEMPT_DUMP").unwrap_or_default();
        if dump.contains(&g_sid) {
            eprintln!(
                "[N1-②][!!] loopback exemptionが残っている（マシン全体で1本のリスト）。\
                 手で消すこと: sudo CheckNetIsolation LoopbackExempt -d -p={g_sid}\n{dump}"
            );
        } else {
            eprintln!("[N1-②][撤収確認] exemptionリストに自分のSIDは無い");
        }
    });

    let observe = |tag: &str| -> String {
        let script = format!(
            r#"$key = '{MAPPINGS_ROOT}\{pkg_sid}'
Write-Output ("EXISTS=" + (Test-Path $key))
if (Test-Path $key) {{
    $p = Get-ItemProperty $key
    Write-Output ("MONIKER=" + $p.Moniker)
    Write-Output ("DISPLAY=" + $p.DisplayName)
}}
Write-Output ("TOTAL=" + @(Get-ChildItem '{MAPPINGS_ROOT}' -EA SilentlyContinue).Count)"#
        );
        let (out, _, _) = ps_outside(&script);
        eprintln!("[N1-②][{tag}]\n{out}");
        kv(&out, "EXISTS").unwrap_or_default()
    };

    // --- 段0: プロファイル生成直後（基準線） --------------------------------
    let s0 = observe("段0: CreateAppContainerProfile直後");
    assert_eq!(
        s0, "False",
        "基準線が崩れている（生成直後に既にMappingsが在る）。この測定は成立しない"
    );

    // --- 段1: 子プロセスを実際に起こす（既知: 生えない、の再確認） ----------
    let (child_out, _, _) = ps_in_container(
        sid.as_psid(),
        "Write-Output ('CHILD=' + $PID); Write-Output 'DONE=1'",
    );
    eprintln!("[N1-②] 子プロセス: {}", child_out.replace('\n', " "));
    let s1 = observe("段1: AppContainer子プロセスを起こした後");

    // --- 段1b: 子が**自分のHKCUへ書く**（本番のシェル作業に相当） ------------
    let (touch_out, touch_err, _) = ps_in_container(
        sid.as_psid(),
        &TEMPLATE_CHILD_TOUCHES_OWN_HIVE.replace("%%PLAIN%%", PLAIN_HKCU_KEY),
    );
    eprintln!("[N1-②][子がHKCUへ書く]\n{touch_out}\n--- stderr ---\n{touch_err}");
    let s1b = observe("段1b: 子が自分のHKCUへ書いた後");
    // 書けたのに`Storage`が生えないのか、そもそも書けていないのかを分ける（B-29）。
    let (stor_out, _, _) = ps_outside(&format!(
        r#"Write-Output ("STORAGE_EXISTS=" + (Test-Path '{STORAGE_ROOT}\{profile}'))
Write-Output ("STORAGE_TREE=" + (((Get-ChildItem '{STORAGE_ROOT}\{profile}' -Recurse -EA SilentlyContinue).Name -replace '.*\\Storage\\','') -join ';'))"#
    ));
    eprintln!("[N1-②][Storage側]\n{stor_out}");

    // --- 段1c: package SID宛のACEを実ディレクトリへ付ける（preflight相当） --
    let (ace_out, _, _) = ps_outside(&TEMPLATE_ACE_ON_DIR_STEP.replace("%%PKG_SID%%", &pkg_sid));
    eprintln!("[N1-②][ACE付与]\n{ace_out}");
    assert_eq!(
        kv(&ace_out, "ACE_APPLIED").as_deref(),
        Some("1"),
        "ACEが実際に載っていない。段1cは何も測れていない:\n{ace_out}"
    );
    let s1c = observe("段1c: package SID宛ACEを付けた後");

    // --- 段2/3: loopback exemption（**昇格しているときだけ**） ---------------
    let el_out = if crate::tier2a::privhelper::is_elevated() {
        let (out, err, _) = ps_outside(
            &TEMPLATE_EXEMPTION_STEP
                .replace("%%MAPPINGS%%", MAPPINGS_ROOT)
                .replace("%%PKG_SID%%", &pkg_sid),
        );
        eprintln!("[N1-②][exemption]\n{out}\n--- stderr ---\n{err}");
        assert_eq!(
            kv(&out, "EXEMPT_DONE").as_deref(),
            Some("1"),
            "exemptionの段が最後まで走っていない:\n{out}{err}"
        );
        // 段2の否定は、**exemptionが実際に載った**ときだけ有効（型A）。
        assert_eq!(
            kv(&out, "EXEMPT_LISTED").as_deref(),
            Some("True"),
            "`-a`が「成功しました」と言ったのにリストへ載っていない。\
             この段の結果は「exemptionでは生えない」の根拠にならない:\n{out}"
        );
        out
    } else {
        eprintln!(
            "[N1-②] 非昇格なのでexemptionの段は飛ばす（`dev-elevated-run n1-mapping-creator`で回すこと）"
        );
        String::new()
    };

    // --- 段4: 全部終わった後をもう一度見る ----------------------------------
    let s4 = observe("段4: 全候補を撃った後");

    let skipped = if el_out.is_empty() { "（非昇格のため未実行）" } else { "" };
    eprintln!(
        "\n[N1-②][**まとめ**] このプロセスは昇格しているか = {}\n  \
         Mappings\\<SID>の有無:\n    \
         段0  CreateAppContainerProfile直後 = {s0}\n    \
         段1  子プロセス起動後              = {s1}\n    \
         段1b 子がHKCUへ書いた後            = {s1b}\n    \
         段1c package SID宛ACEを付けた後    = {s1c}\n    \
         段2  exemption -a の直後           = {}{skipped}\n    \
         段3  exemption -d の直後           = {}{skipped}\n    \
         段4  全部終わった後                = {s4}\n  \
         exemptionが実際にリストへ載ったか = {}（Falseなら段2の否定は無効）\n  \
         -d の後もリストに載っているか     = {}",
        crate::tier2a::privhelper::is_elevated(),
        kv(&el_out, "AFTER_ADD_EXISTS").unwrap_or_default(),
        kv(&el_out, "AFTER_DEL_EXISTS").unwrap_or_default(),
        kv(&el_out, "EXEMPT_LISTED").unwrap_or_default(),
        kv(&el_out, "EXEMPT_LISTED_AFTER_DEL").unwrap_or_default(),
    );
}

// ---------------------------------------------------------------------------
// N2. 層1へ置いたCAを、**実クライアントがTLSハンドシェイクで**信頼するか
// ---------------------------------------------------------------------------
//
// ここまでのN1が測ったのは信頼判断の実体（`CertGetCertificateChain`）までで、
// **ハンドシェイクは1本も通していない**（`HANDOFF-N1-CERT-STORE-REDIRECT.md` ①）。
// N2の表の「層1」列も同じ理由で空いている（`plans/net-spike/RESULTS.md` N2節）。
// この2つは同じ測定なので、ここで一度に埋める。
//
// **`gh`（Go）が本命である。** N2はGoが層2のCA束環境変数を1つも見ないことを実測しており、
// 一方でシステムストアは見た。したがってGoの可否は層1だけで決まる。ただしN1が
// 「読む」を確認したのは.NETの`X509Chain`であって、**Goが同じ経路を通る保証はない**
// ——Goは`crypto/x509`が独自にストアを引くため、ここを測らずに✓とは書けない。

/// このN2の測定だけが使う固定プロファイル名。
///
/// **pidで変えない。** loopback exemptionは*package SID*を指定して外から足す必要があり
/// （要管理者・`CheckNetIsolation`）、pidで名前が変わるとSIDも変わって毎回足し直しになる。
/// SIDはプロファイル名から決定的に導出されるので、名前を固定すればプロファイルを作り直しても
/// 同じSIDになり、exemptionを1回足せば測定を何度でも回せる。
const N2_PROFILE: &str = "harness.n2tls";

/// コンテナの中で、3種のクライアントを**本命チェーンと対照チェーンの両方**へ撃つ。
///
/// 対照を「同じサーバでCAを消した状態」ではなく**別のCAで署名された別サーバ**にしてあるのは、
/// 同一チェーンで「置く前／置いた後」を続けて測ると、Windowsのチェーン／失効キャッシュが
/// 前の結果を持ち越して**偽陰性**（層1が効いているのに効かないと読む）を作るためである
/// （`plans/net-spike/RESULTS.md` N2節の罠C。実際に一度誤読しかけた）。
///
/// 各行は**そのクライアントの生の出力**を返す。`http=200`かどうかではなく
/// **エラーの種類が変わったか**で読む——`SEC_E_UNTRUSTED_ROOT`／`x509: certificate signed by
/// unknown authority`が出れば信頼していない、消えれば信頼している。
const TEMPLATE_N2_RUNTIME_PROBE: &str = r#"
$ErrorActionPreference = 'Continue'
function Say($k, $v) { Write-Output ("$k=" + (($v -as [string]) -replace '\s+', ' ')) }
function Try1($k, $block) {
    try { Say $k (& $block) } catch { Say $k ("EXCEPTION:" + $_.Exception.Message) }
}

# --- 前提の自己確認: 層1が中から見えているか -------------------------------
# ここが偽なら以下のクライアントの結果は「層1の可否」を意味しない（測定が成立していない）。
Try1 'STORE_COUNT' {
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser')
    $s.Open('ReadOnly'); $n = $s.Certificates.Count; $s.Close(); $n
}
Try1 'STORE_HAS_CA' {
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser')
    $s.Open('ReadOnly')
    $hit = @($s.Certificates | Where-Object { $_.Thumbprint -eq '%%CA_THUMB%%' }).Count
    $s.Close(); $hit
}

# --- 本命: CAをコンテナ専用ストアへ置いたチェーン ---------------------------
Try1 'CURL_TRUSTED' {
    (& "$env:SystemRoot\System32\curl.exe" -sS -m 20 -o NUL -w 'http=%{http_code}' '%%URL%%' 2>&1) -join ' '
}
Try1 'IWR_TRUSTED' {
    (Invoke-WebRequest -Uri '%%URL%%' -UseBasicParsing -TimeoutSec 20).StatusCode
}
Try1 'GH_TRUSTED' {
    # `gh`は起動時に設定ファイルを読む。既定の`%APPDATA%\GitHub CLI`はAppContainerから
    # 読めず（実測: `Access is denied`）、**TLSを測る前に落ちる**。コンテナが書ける
    # AC配下へ逃がして、測定対象がTLSだけになるようにする。
    $env:GH_CONFIG_DIR = '%%GHCFG%%'
    $env:GH_TOKEN = 'dummy'; $env:GH_HOST = '%%HOSTPORT%%'
    ((& '%%GH%%' api rate_limit 2>&1) | Select-Object -First 1) -join ' '
}

# --- 切り分け: 同じcurlに、同じCAを**ファイルで**渡したらどうなるか ---------
# 層1（ストア）を読まないのか、それともサーバ／証明書の側に問題があるのかを分ける。
# ここが通れば「curlは層1を読まないだけ」＝層2（`.curlrc`）で救える、と言い切れる。
# `--ssl-no-revoke`が要るのは、Schannelが失効確認をCAの信頼とは別に要求するためである
# （`plans/net-spike/RESULTS.md` N2節の罠B）。
Try1 'CURL_CACERT_FILE' {
    (& "$env:SystemRoot\System32\curl.exe" -sS -m 20 --ssl-no-revoke --cacert '%%CAFILE%%' `
        -o NUL -w 'http=%{http_code}' '%%URL%%' 2>&1) -join ' '
}

# --- N7-d: 同じCAファイルで、**`--ssl-no-revoke`を外して**同じ往復をする -------
# N7-bは「loopbackのHTTPでCRLを配れば失効確認が通る」を**コンテナの外で**実測した。
# 中でも通るかは別問題である——CRLの取得は、curlが張るTLS接続とは**別のloopback接続**を
# CryptoAPIがこのプロセス内から張るので、AppContainerのネットワーク制限
# （capability＋loopback exemption）の対象になる。ここが通れば問dが成立する。
Try1 'CURL_NO_REVOKE_FLAG' {
    (& "$env:SystemRoot\System32\curl.exe" -sS -m 30 --cacert '%%CAFILE%%' `
        -o NUL -w 'http=%{http_code}' '%%URL%%' 2>&1) -join ' '
}
# **切り分けの直接証拠**: そもそもコンテナからCRL配布サーバへ素のHTTPで届くのか。
# ここが通るのに上が落ちるなら、CryptoAPIの取得経路がcurlのそれと違う（B-29）。
Try1 'CURL_CRL_DIRECT' {
    (& "$env:SystemRoot\System32\curl.exe" -sS -m 20 -o NUL -w 'http=%{http_code}' '%%CRLURL%%' 2>&1) -join ' '
}

# --- 対照: 別CAで署名された別サーバ（CAはどこにも置いていない） -------------
Try1 'CURL_CONTROL' {
    (& "$env:SystemRoot\System32\curl.exe" -sS -m 20 -o NUL -w 'http=%{http_code}' '%%URL_CTRL%%' 2>&1) -join ' '
}
Try1 'IWR_CONTROL' {
    (Invoke-WebRequest -Uri '%%URL_CTRL%%' -UseBasicParsing -TimeoutSec 20).StatusCode
}
Try1 'GH_CONTROL' {
    $env:GH_CONFIG_DIR = '%%GHCFG%%'
    $env:GH_TOKEN = 'dummy'; $env:GH_HOST = '%%HOSTPORT_CTRL%%'
    ((& '%%GH%%' api rate_limit 2>&1) | Select-Object -First 1) -join ' '
}
Say 'DONE' '1'
"#;

/// N2が実マシンへ残し得るものを剥がし、**消えたことを数え直す**。
///
/// 数え直しまでを撤収に含めるのは、このセッションで実際に踏んだためである——
/// 「撤収コードを呼んだ」だけを完了と見なした結果、`Cert:\CurrentUser\Root`に
/// テストCAが残っていた（`plans/net-spike/RESULTS.md` N2節の追記・B-01）。
fn n2_cleanup(profile: &str, pkg_sid: &str) {
    let script = format!(
        r#"$ErrorActionPreference = 'SilentlyContinue'
$map = '{MAPPINGS_ROOT}\{pkg_sid}'
$sto = '{STORAGE_ROOT}\{profile}'
Remove-Item -Path $map -Recurse -Force
Remove-Item -Path $sto -Recurse -Force
Remove-Item -Path '{SCRATCH_STORE}' -Recurse -Force
# `gh`用に外から作った設定ディレクトリ（AC配下）。プロファイル削除でも消えるが、
# 削除が失敗した経路でも残さないように明示的に消す。
Remove-Item -Path ($env:LOCALAPPDATA + '\Packages\{profile}\AC\Temp\ghcfg') -Recurse -Force
Write-Output ("LEFT_MAPPING=" + (Test-Path $map))
Write-Output ("LEFT_STORAGE=" + (Test-Path $sto))
Write-Output ("LEFT_SCRATCH=" + (Test-Path '{SCRATCH_STORE}'))
# このN2はユーザーの証明書ストアへ一切書かないので、**書いていないことを確かめる**側で数える。
$n = 0
foreach ($s in 'Root','CA','My','TrustedPeople','Disallowed') {{
    $n += @(Get-ChildItem ("Cert:\CurrentUser\" + $s) |
        Where-Object {{ $_.Subject -like '*harness-n2*' }}).Count
}}
Write-Output ("RESIDUE_USER_STORE=" + $n)
"#
    );
    let (out, err, _) = ps_outside(&script);
    eprintln!("[N2-L1][撤収] out={out:?} err={err:?}");
    unsafe {
        let w = crate::win_common::wide(profile);
        let _ = windows::Win32::Security::Isolation::DeleteAppContainerProfile(
            windows::core::PCWSTR(w.as_ptr()),
        );
    }
    for key in ["LEFT_MAPPING", "LEFT_STORAGE", "LEFT_SCRATCH"] {
        if kv(&out, key).as_deref() != Some("False") {
            let msg = format!("撤収が終わっていない: {key} が残っている（{out}）");
            if std::thread::panicking() {
                eprintln!("[N2-L1][!!] {msg}");
            } else {
                panic!("{msg}");
            }
        }
    }
    if kv(&out, "RESIDUE_USER_STORE").as_deref() != Some("0") {
        let msg = format!(
            "ユーザーの証明書ストアにN2の証明書が居る（{out}）。\
             このスパイクは1枚も置かないはずなので、置き場を取り違えている"
        );
        if std::thread::panicking() {
            eprintln!("[N2-L1][!!] {msg}");
        } else {
            panic!("{msg}");
        }
    }
}

/// N2の測定に要る**loopback exemptionの付与と撤収**。測定そのものはここではしない。
///
/// ## なぜテストとして書くのか（`sudo`で直接撃たない理由）
///
/// `CLAUDE.md`が「実行中に昇格が起きるものは`dev-elevated-runner`経由で実行する」と定めており、
/// `CheckNetIsolation`は**要管理者**である。`dev-elevated-runner`は任意コマンドを昇格実行できない
/// （`validate_target`が`KNOWN_TARGETS`との完全一致を要求する。これは
/// 「無検証のまま管理者権限で実行させられる」経路を作らないための設計で、
/// グローバル`CLAUDE.md`が常駐昇格キューを禁じたのと同じ理由である）。
/// **だから昇格が要る操作の側をテストにして、既知ターゲットとして登録する。**
///
/// ## 測定本体（[`n2_do_real_runtimes_trust_the_per_container_store`]）とは分ける
///
/// 昇格したテストからAppContainer子を起こすと親トークンが管理者のものになり、
/// 測っている世界が実運用（非昇格のharness）と変わる（B-08）。
/// **付与／撤収だけを昇格で回し、測定は非昇格で回す。**
///
/// ## 使い方
///
/// ```text
/// target\debug\dev-elevated-run.exe n2-loopback-exemption-add
/// target\debug\dev-elevated-run.exe n2-loopback-exemption-remove
/// ```
///
/// 付与と撤収を**環境変数ではなく別のテストに分けてある**のは、`dev-elevated-run`が
/// 昇格側プロセスへ呼び出し元の環境変数を引き継ぐ保証が無いためである。
/// 引き継がれなければ「撤収したつもりで付与していた」という無言の取り違えになる。
fn n2_loopback_exemption(remove: bool) {
    // SIDはプロファイル名から決定的に導出される。撤収時は既にプロファイルが消えているので、
    // 一度作ってSIDを引き、用が済んだら消す（作り直しても同じSIDになる）。
    let sid = ensure_profile_for_test(N2_PROFILE).expect("create/open the N2 profile");
    let pkg_sid = crate::win_common::sid_to_string(sid.as_psid()).expect("package SID string");
    let flag = if remove { "-d" } else { "-a" };
    let out = std::process::Command::new("CheckNetIsolation")
        .args(["LoopbackExempt", flag, &format!("-p={pkg_sid}")])
        .output()
        .expect("run CheckNetIsolation");
    eprintln!(
        "[N2-exempt] {flag} sid={pkg_sid} status={} stdout={}",
        out.status,
        String::from_utf8_lossy(&out.stdout).trim()
    );

    // **見た目の成功を信じない**——リストを読み返して、意図した状態になったかを確かめる
    // （`feedback-security-self-verification`。`icacls`と同じで、この種のコマンドは
    // 「成功しました」と言いながら何もしていないことがある）。
    let listed = std::process::Command::new("CheckNetIsolation")
        .args(["LoopbackExempt", "-s"])
        .output()
        .expect("list loopback exemptions");
    let listed = String::from_utf8_lossy(&listed.stdout).to_string();
    let present = listed.contains(&pkg_sid);
    eprintln!("[N2-exempt] リストに載っているか={present}（remove={remove}）");
    if remove {
        // 撤収時はプロファイルも消す（測定側のガードが落ちた場合の取りこぼしを拾う）。
        unsafe {
            let w = crate::win_common::wide(N2_PROFILE);
            let _ = windows::Win32::Security::Isolation::DeleteAppContainerProfile(
                windows::core::PCWSTR(w.as_ptr()),
            );
        }
        assert!(
            !present,
            "exemptionが消えていない。`CheckNetIsolation LoopbackExempt -s`に残っている:\n{listed}"
        );
    } else {
        assert!(
            present,
            "`-a`が成功と言ったのにリストへ載っていない。この状態で測定しても\
             「繋がらない」の理由がexemption不在なのか層1なのか分けられない:\n{listed}"
        );
    }
}

#[test]
#[ignore = "要管理者。`dev-elevated-run.exe n2-loopback-exemption-add`から回すこと"]
fn n2_loopback_exemption_add() {
    n2_loopback_exemption(false);
}

#[test]
#[ignore = "要管理者。`dev-elevated-run.exe n2-loopback-exemption-remove`から回すこと"]
fn n2_loopback_exemption_remove() {
    n2_loopback_exemption(true);
}

/// **層1へ置いたCAを、実クライアント（Schannel系2種＋Go）がハンドシェイクで信頼するか。**
///
/// ## 外から与えるもの（このテストは証明書もサーバも作らない）
///
/// | 環境変数 | 中身 |
/// |---|---|
/// | `HARNESS_TEST_N2_CA_B64` | 本命CAのDER（base64）。コンテナ専用ストアへ置く |
/// | `HARNESS_TEST_N2_CA_THUMB` | 同CAのSHA1拇印（区切り無し） |
/// | `HARNESS_TEST_N2_URL` | 本命サーバのURL（そのCAで署名した証明書を出す） |
/// | `HARNESS_TEST_N2_URL_CONTROL` | 対照サーバのURL（**別CA**で署名した証明書を出す） |
///
/// 証明書生成とTLSサーバを外へ出したのは、`New-SelfSignedCertificate`のリーフでは
/// `SAN=IP:127.0.0.1`のサーバ証明書を作る手間が測定の本筋から外れるためである
/// （`openssl s_server`で足りる）。
///
/// ## loopback exemptionが要る
///
/// AppContainerは自マシン宛の接続を既定で落とすので、`CheckNetIsolation LoopbackExempt -a`が
/// 要る（**要管理者**）。テストからは撃たない——昇格したテストからAppContainer子を起こすと
/// 親トークンが管理者になり、測っている世界が実運用と変わる（B-08）。
/// **`dev-elevated-run n2-loopback-exemption-add`／`-remove`で付与・撤収する**——
/// 条件は「テストか」でも「自分が`sudo`を打つか」でもなく**「昇格が起きるか」**である（`CLAUDE.md`）。
/// `CheckNetIsolation`を`sudo`で直に撃つと、**何を変えたかがコードに残らず撤収の対も書かれない**。
/// （この行の旧版は`HANDOFF-N1-CERT-STORE-REDIRECT.md` ①案Bを引いて「単体で`sudo`」と書いており、
/// それは`CLAUDE.md`が2026-08-16の事故として名指ししている記述そのものだった。）
/// リスト全体を`Set`しないこと（他セッションのexemptionを消す＝BUG-053）。
#[test]
#[ignore = "実AppContainer＋loopback exemption＋外で立てたTLSサーバが要る。非昇格・--test-threads=1で走らせること"]
fn n2_do_real_runtimes_trust_the_per_container_store() {
    let ca_b64 = std::env::var("HARNESS_TEST_N2_CA_B64").expect("HARNESS_TEST_N2_CA_B64（本命CAのDER base64）");
    let ca_thumb = std::env::var("HARNESS_TEST_N2_CA_THUMB")
        .expect("HARNESS_TEST_N2_CA_THUMB")
        .trim()
        .to_uppercase();
    let url = std::env::var("HARNESS_TEST_N2_URL").expect("HARNESS_TEST_N2_URL");
    let url_ctrl = std::env::var("HARNESS_TEST_N2_URL_CONTROL").expect("HARNESS_TEST_N2_URL_CONTROL");
    let hostport = |u: &str| {
        u.trim_start_matches("https://")
            .trim_end_matches('/')
            .to_string()
    };

    let sid = ensure_profile_for_test(N2_PROFILE).expect("create the N2 AppContainer profile");
    let pkg_sid = crate::win_common::sid_to_string(sid.as_psid()).expect("package SID string");
    eprintln!("[N2-L1] profile={N2_PROFILE} package_sid={pkg_sid}");
    eprintln!(
        "[N2-L1] loopback exemptionが要る（package_sid={pkg_sid}）。未設定なら次で付与すること:\n  \
         target\\debug\\dev-elevated-run.exe n2-loopback-exemption-add\n  \
         （測定後は必ず `... n2-loopback-exemption-remove`。マシン全体で1本の共有リスト＝BUG-053）"
    );

    // 撤収を、作る前に登録する（B-01）。
    let cleanup_sid = pkg_sid.clone();
    let _guard = super::test_support::scopeguard(move || {
        n2_cleanup(N2_PROFILE, &cleanup_sid);
    });

    // --- 層1を組む: Mappings（モニカ解決）＋ Storage（置き場）の2つが直列に要る -----
    // どちらが欠けても中のストアは開かない（N1-③で両方必須と確定済み）。
    let seed_map = TEMPLATE_SEED_MAPPING_VARIANT
        .replace("%%MAPPINGS%%", MAPPINGS_ROOT)
        .replace("%%PKG_SID%%", &pkg_sid)
        .replace("%%PROFILE%%", N2_PROFILE)
        .replace("%%WITH_ACE%%", "yes");
    let (map_out, map_err, map_code) = ps_outside(&seed_map);
    eprintln!("[N2-L1][Mappings] exit={map_code} {map_out} {map_err}");
    assert_eq!(map_code, 0, "Mappingsエントリの作成に失敗した");
    assert_eq!(
        kv(&map_out, "MAPPING_PKG_ACE").as_deref(),
        Some("1"),
        "package SID宛ACEが載っていない。この構成では層1は開かない:\n{map_out}"
    );

    let seed_store = TEMPLATE_SEED_CONTAINER_STORE
        .replace("%%CA_B64%%", &ca_b64)
        .replace("%%CA_THUMB%%", &ca_thumb)
        .replace("%%SCRATCH%%", SCRATCH_STORE)
        .replace("%%STORAGE%%", STORAGE_ROOT)
        .replace("%%PROFILE%%", N2_PROFILE);
    let (store_out, store_err, store_code) = ps_outside(&seed_store);
    eprintln!("[N2-L1][Storage] exit={store_code} {store_out} {store_err}");
    assert_eq!(store_code, 0, "コンテナ専用ストアへの書込が失敗した");
    assert_eq!(
        kv(&store_out, "SEEDED").as_deref(),
        Some("True"),
        "CAのBlobが置けていない:\n{store_out}"
    );
    // N1-③で`ReadKey`で足りると確定している。実装が残す副作用は小さいほどよい。
    let (grant_out, _, grant_code) = grant_storage_ace(&pkg_sid, N2_PROFILE, "ReadKey");
    eprintln!("[N2-L1][ACE] exit={grant_code} {grant_out}");
    assert_eq!(grant_code, 0, "package SID宛ACEの付与が失敗した");

    // `gh`用の設定ディレクトリを、コンテナが書けるAC配下へ**外から**作る。
    // これを渡さないと`gh`は既定の`%APPDATA%\GitHub CLI`を読みに行って`Access is denied`で
    // 落ち、**TLSを1バイトも喋らないまま「失敗」に見える**（実測）。
    let ghcfg = format!(
        r"{}\Packages\{N2_PROFILE}\AC\Temp\ghcfg",
        std::env::var("LOCALAPPDATA").expect("LOCALAPPDATA")
    );
    // 同じAC配下へ、切り分け用のCAファイル（PEM）も置く。`curl --cacert`へ渡して
    // 「層1（ストア）を読まないだけなのか、証明書／サーバ側の問題なのか」を分ける。
    let cafile = format!(
        r"{}\Packages\{N2_PROFILE}\AC\Temp\n2-ca.pem",
        std::env::var("LOCALAPPDATA").expect("LOCALAPPDATA")
    );
    let (ghcfg_out, _, ghcfg_code) = ps_outside(&format!(
        r#"$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Path '{ghcfg}' -Force | Out-Null
$der = [Convert]::FromBase64String('{ca_b64}')
$pem = "-----BEGIN CERTIFICATE-----`n" +
    [Convert]::ToBase64String($der, 'InsertLineBreaks') + "`n-----END CERTIFICATE-----`n"
[IO.File]::WriteAllText('{cafile}', $pem)
Write-Output ("GHCFG=" + (Test-Path '{ghcfg}'))
Write-Output ("CAFILE=" + (Test-Path '{cafile}'))"#
    ));
    assert_eq!(ghcfg_code, 0, "gh用設定ディレクトリ／CAファイルの配置に失敗した: {ghcfg_out}");
    assert_eq!(
        kv(&ghcfg_out, "CAFILE").as_deref(),
        Some("True"),
        "切り分け用のCAファイルが置けていない:\n{ghcfg_out}"
    );

    // --- コンテナの中から実クライアントを撃つ ---------------------------------
    // N7-dのCRL配布URL。未設定でも測定が成立するよう、**置換だけは必ず行う**
    // ——未置換のまま`%%CRLURL%%`が子へ届くと、curlが意味不明なURLで落ちて
    // 「コンテナからCRLサーバへ届かない」と読めてしまう（無言の取り違え）。
    let crl_url = std::env::var("HARNESS_TEST_N2_CRL_URL").unwrap_or_default();
    let crl_probe_url = if crl_url.is_empty() {
        "http://127.0.0.1:1/none".to_string() // 明示的に届かない先＝「未設定」と読める
    } else {
        crl_url.clone()
    };
    let script = TEMPLATE_N2_RUNTIME_PROBE
        .replace("%%GHCFG%%", &ghcfg)
        .replace("%%CAFILE%%", &cafile)
        .replace("%%CA_THUMB%%", &ca_thumb)
        .replace("%%URL%%", &url)
        .replace("%%URL_CTRL%%", &url_ctrl)
        .replace("%%CRLURL%%", &crl_probe_url)
        .replace("%%HOSTPORT%%", &hostport(&url))
        .replace("%%HOSTPORT_CTRL%%", &hostport(&url_ctrl))
        .replace("%%GH%%", r"C:\Program Files\GitHub CLI\gh.exe");

    // 外でも同じスクリプトを回して対照にする（外で通って中で落ちるならコンテナの性質、
    // 両方落ちるならこの機の性質である。B-29）。**外はCAをどこにも持たない**ので、
    // 本命側も失敗するのが正しい——外の結果は「サーバが生きている」ことの確認に使う。
    let (outside, _, _) = ps_outside(&script);
    eprintln!("[N2-L1][外（通常トークン・CA無し）]\n{outside}");

    let (inside, inside_err, inside_code) =
        ps_in_container_with_net(sid.as_psid(), &script, NetworkCapability::InternetClient);
    eprintln!("[N2-L1][中（AppContainer）] exit={inside_code}\n{inside}\n--- stderr ---\n{inside_err}");

    assert_eq!(
        kv(&inside, "DONE").as_deref(),
        Some("1"),
        "コンテナ内の観測スクリプトが最後まで走っていない:\n{inside}"
    );
    eprintln!(
        "\n[N2-L1][**判定**]\n  \
         層1が中から見えているか: ストア件数={} / 置いたCAが在るか={}\n  \
         本命（層1にCAあり）      curl={} | IWR={} | gh={}\n  \
         対照（別CA・置いていない） curl={} | IWR={} | gh={}\n  \
         **N7-d（失効確認）** CRL配布URL={}\n    \
         `--ssl-no-revoke`無しのcurl = {}\n    \
         コンテナからCRLサーバへ素のHTTP = {}",
        kv(&inside, "STORE_COUNT").unwrap_or_default(),
        kv(&inside, "STORE_HAS_CA").unwrap_or_default(),
        kv(&inside, "CURL_TRUSTED").unwrap_or_default(),
        kv(&inside, "IWR_TRUSTED").unwrap_or_default(),
        kv(&inside, "GH_TRUSTED").unwrap_or_default(),
        kv(&inside, "CURL_CONTROL").unwrap_or_default(),
        kv(&inside, "IWR_CONTROL").unwrap_or_default(),
        kv(&inside, "GH_CONTROL").unwrap_or_default(),
        if crl_url.is_empty() {
            "(HARNESS_TEST_N2_CRL_URL 未設定——下2行はN7-dの結果として読まないこと)"
        } else {
            &crl_url
        },
        kv(&inside, "CURL_NO_REVOKE_FLAG").unwrap_or_default(),
        kv(&inside, "CURL_CRL_DIRECT").unwrap_or_default(),
    );
    // 測定が成立していること（層1が見えていること）だけをここで固定する。
    // 各ランタイムの可否は上の出力を人が読んで表へ写す——`http=200`以外にも
    // 「TLSは通ったがアプリ層で落ちた」形があり、機械的な合否に潰すと情報が消える。
    assert_eq!(
        kv(&inside, "STORE_HAS_CA").as_deref(),
        Some("1"),
        "層1が中から見えていない。この実行の結果は各ランタイムの可否を意味しない:\n{inside}"
    );
}

// ---------------------------------------------------------------------------
// N6. 層1の**撤収**——開けた信頼を、閉じられるか
// ---------------------------------------------------------------------------
//
// N1・N2が測ったのは**付与**（CAを置くと中から信頼される）だけで、**撤収は1度も
// 測っていない**（`plans/HANDOFF-N6-CERT-STORE-TEARDOWN.md`）。D-65は実装が書く3点
// （`Mappings`登録・`Blob`・双方へのpackage SID宛ACE）に対して**撤収の対**を要求しており
// （B-01）、バグ88件の横断分析で最頻の再発パターンが「対の片方だけ実装する」である。
//
// ## ここで使う「信頼」の物差しと、その限界（**先に宣言する**）
//
// 測るのは**コンテナ内の`X509Store`／`X509Chain`**（＝`CertGetCertificateChain`）であって、
// TLSハンドシェイクではない。これは弱い代理指標ではなく**層1の射程そのもの**である
// ——N2-層1が実測したとおり、層1を読むのは`CertGetCertificateChain`をプロセス内で呼ぶ
// クライアントだけで（`Invoke-WebRequest`✓／`curl.exe`✗／`gh`✗）、**その1点が消えれば
// 層1で救えていた相手は全員救えなくなる**。
//
// この選択で**測れないもの**を明示する（D-43: 測っていないことを測ったように書かない）。
//
// - TLSセッション再開・Schannelの資格情報キャッシュに由来する持ち越し。撤収後も
//   **既存のTLSセッションが生き続ける**可能性はここでは否定できない
// - 失効確認（`CryptnetUrlCache`）の持ち越し
//
// loopback exemptionとTLSサーバを要さないぶん、**マシン全体で1本のリスト**（BUG-053）に
// 触らずに済み、他セッションと衝突しない。問eの測定（`n2_*`）とは独立に回せる。

/// N6の各測定が張る層1の最小構成（N1-③の⑤＝`Mappings`に`ReadKey`・`Storage`に`ReadKey`）。
///
/// **`FullControl`ではなく`ReadKey`**にしてあるのは、これがD-65が実装すると決めた構成であり、
/// **撤収は実装する構成に対して測らなければ意味が無い**ためである（`FullControl`で測って
/// 「撤収できた」と言っても、実装は別の構成で走る）。
fn n6_setup_layer1(profile: &str, pkg_sid: &str, ca_der_b64: &str, ca_thumb: &str) {
    let (m_out, m_err, m_code) = ps_outside(
        &TEMPLATE_SEED_MAPPING_VARIANT
            .replace("%%MAPPINGS%%", MAPPINGS_ROOT)
            .replace("%%PKG_SID%%", pkg_sid)
            .replace("%%PROFILE%%", profile)
            .replace("%%WITH_ACE%%", "yes"),
    );
    assert_eq!(
        m_code, 0,
        "[{profile}] Mappingsエントリの作成に失敗した: {m_out}{m_err}"
    );
    assert_eq!(
        kv(&m_out, "MAPPING_PKG_ACE").as_deref(),
        Some("1"),
        "[{profile}] Mappings側のpackage SID宛ACEが載っていない。層1が開かない構成である:\n{m_out}"
    );

    let (s_out, s_err, s_code) = ps_outside(
        &TEMPLATE_SEED_CONTAINER_STORE
            .replace("%%CA_B64%%", ca_der_b64)
            .replace("%%CA_THUMB%%", ca_thumb)
            .replace("%%SCRATCH%%", SCRATCH_STORE)
            .replace("%%STORAGE%%", STORAGE_ROOT)
            .replace("%%PROFILE%%", profile),
    );
    assert_eq!(
        s_code, 0,
        "[{profile}] コンテナ専用ストアへの書込が失敗した: {s_out}{s_err}"
    );
    assert_eq!(
        kv(&s_out, "SEEDED").as_deref(),
        Some("True"),
        "[{profile}] CAのBlobが置けていない:\n{s_out}"
    );

    let (g_out, g_err, g_code) = grant_storage_ace(pkg_sid, profile, "ReadKey");
    assert_eq!(
        g_code, 0,
        "[{profile}] Storage側ACE（ReadKey）の付与が失敗した: {g_out}{g_err}"
    );
}

/// `Storage`配下の`Blob`（＝`Certificates\<thumbprint>`キー）の物理パス。
fn n6_blob_key(profile: &str, ca_thumb: &str) -> String {
    format!(
        r"{STORAGE_ROOT}\{profile}\Software\Microsoft\SystemCertificates\Root\Certificates\{ca_thumb}"
    )
}

/// 中から1回観測する（[`TEMPLATE_ACE_MATRIX_PROBE`]をそのまま使う。**器を作り直さない**）。
///
/// 返るのは`KEY=VALUE`の生出力。判定に使う鍵は`ROOT_OPEN`（ストアが開いたか・件数）・
/// `ROOT_HAS_CA`（置いたCAが見えるか）・`CHAIN_USER`（信頼判断の実体）・
/// `MY_COUNT`（**隔離が壊れていないことの対照**）である。
fn n6_probe_once(
    sid: windows::Win32::Security::PSID,
    profile: &str,
    pkg_sid: &str,
    certs: &SpikeCerts,
) -> String {
    let script = TEMPLATE_ACE_MATRIX_PROBE
        .replace("%%MAPPINGS_KEY%%", &format!("{MAPPINGS_ROOT}\\{pkg_sid}"))
        .replace(
            "%%STORAGE_CERTS%%",
            &format!(
                r"{STORAGE_ROOT}\{profile}\Software\Microsoft\SystemCertificates\Root\Certificates"
            ),
        )
        .replace("%%CA_THUMB%%", &certs.ca_thumb)
        .replace("%%CA_B64%%", &certs.ca_der_b64)
        .replace("%%LEAF_B64%%", &certs.leaf_der_b64);
    let (out, err, code) = ps_in_container(sid, &script);
    if code != 0 || kv(&out, "DONE").as_deref() != Some("1") {
        eprintln!("[N6][中の観測が完走していない] exit={code}\n{out}\n--- stderr ---\n{err}");
    }
    out
}

/// 1回の観測を1行にまとめる。
fn n6_row(label: &str, out: &str) -> String {
    format!(
        "{label:<28} Rootのopen={:<12} CAが見えるか={:<10} チェーン={:<28} Myの件数={} / Moniker={} / Storageキー={}",
        kv(out, "ROOT_OPEN").unwrap_or_default(),
        kv(out, "ROOT_HAS_CA").unwrap_or_default(),
        kv(out, "CHAIN_USER").unwrap_or_default(),
        kv(out, "MY_COUNT").unwrap_or_default(),
        kv(out, "MAPPING_MONIKER").unwrap_or_default(),
        kv(out, "STORAGE_CERT_COUNT").unwrap_or_default(),
    )
}

/// **その観測が「層1が効いている」状態か**を1つの真偽へ落とす。
///
/// `ROOT_HAS_CA=1`（置いたCAがストアから見える）**かつ**`CHAIN_USER`が`True/NoError`
/// （信頼判断が通る）のときだけ真。片方だけで判定しないのは、撤収が
/// 「ストアからは消えたのにチェーンは通り続ける」形（＝キャッシュ）を取り得るためで、
/// **その差こそが問bの答え**だからである。
fn n6_trusted(out: &str) -> bool {
    kv(out, "ROOT_HAS_CA").as_deref() == Some("1")
        && kv(out, "CHAIN_USER").as_deref() == Some("True/NoError")
}

/// N6が実マシンへ残し得るものを全部剥がし、**消えたことを数え直す**。
///
/// 証明書の残骸は**subject名で横断して**数える——`cleanup_all`の`RESIDUE_CERTS`は
/// *その実行で作ったthumbprint*しか見ないので、**撤収が走らずに落ちた過去の実行の残骸を
/// 構造上いつでも0と報告する**（N1とN2が独立に2回踏んだ穴。`net-spike/RESULTS.md` N2節の追記）。
fn n6_cleanup(profiles: &[(String, String)]) {
    for (profile, pkg_sid) in profiles {
        cleanup_quadrant(profile, pkg_sid);
    }
    let script = r#"
$ErrorActionPreference = 'SilentlyContinue'
# 1. 使い捨て証明書を**subject名で横断して**消す（thumbprint指定にしない）。
foreach ($name in 'My','Root','CA','TrustedPeople','Disallowed') {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($name,'CurrentUser')
    try { $store.Open('ReadWrite') } catch { continue }
    foreach ($c in @($store.Certificates | Where-Object {
        $_.Subject -like '*harness-n1-spike*' -or $_.Subject -like '*harness-n6*' })) {
        $store.Remove($c)
    }
    $store.Close()
}
# 秘密鍵（`My`にだけ在る）はここで消す。
foreach ($c in @(Get-ChildItem 'Cert:\CurrentUser\My' | Where-Object {
    $_.Subject -like '*harness-n1-spike*' -or $_.Subject -like '*harness-n6*' })) {
    Remove-Item -Path ("Cert:\CurrentUser\My\" + $c.Thumbprint) -DeleteKey -Force
}
# 2. Blob生成用の作業ストアと、同期用ディレクトリの親（プロファイル削除で消えているはず）。
Remove-Item -Path '%%SCRATCH%%' -Recurse -Force
# 3. **数え直す**（撤収の成功を戻り値ではなく状態で確かめる）。
$left = 0
foreach ($name in 'My','Root','CA','TrustedPeople','Disallowed') {
    $left += @(Get-ChildItem ("Cert:\CurrentUser\" + $name) -EA SilentlyContinue |
        Where-Object { $_.Subject -like '*harness-n1-spike*' -or $_.Subject -like '*harness-n6*' }).Count
}
Write-Output ("RESIDUE_BY_SUBJECT=" + $left)
Write-Output ("LEFT_SCRATCH=" + (Test-Path '%%SCRATCH%%'))
"#
    .replace("%%SCRATCH%%", SCRATCH_STORE);
    let (out, err, _) = ps_outside(&script);
    eprintln!("[N6][撤収] {out} {err}");
    for (key, want) in [("RESIDUE_BY_SUBJECT", "0"), ("LEFT_SCRATCH", "False")] {
        if kv(&out, key).as_deref() != Some(want) {
            let msg = format!("後始末が終わっていない（{key}）。実マシンに残っている:\n{out}");
            if std::thread::panicking() {
                eprintln!("[N6][!!] {msg}");
            } else {
                panic!("{msg}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 問a・b: `Blob`を消したら、新規プロセス／既存プロセスで信頼が失われるか
// ---------------------------------------------------------------------------

/// **長命プロセス**の中で、外からの合図に合わせて何度も観測する（問b）。
///
/// # なぜファイルで同期するのか
///
/// 問bは「**プロセスが生きたまま**`Blob`が消えたとき、そのプロセスは信頼を失うか」である。
/// つまり削除は**子の実行中に外から**起きなければならない。既存の`ps_in_container`は
/// 一問一答（起動→出力を全部読む→終了）なので往復できない。
///
/// stdinで往復させる手もあるが（`AppContainerSession`）、PowerShellを`-Command -`の
/// REPLとして駆動する必要があり、プロンプト文字列の混入と行バッファリングという
/// **測定と無関係な不確実さ**が増える。コンテナ専用の`AC`フォルダは中からも外からも
/// 書けることが既に分かっている（`gh`の設定ディレクトリで実証済み）ので、
/// そこにフラグファイルを置き合う方が読み解ける。
///
/// # 各段で何を測るか
///
/// `<段>_STORE`は`件数/CAの有無`、`<段>_CHAIN`は`Build()/ChainStatus`である。
/// **2つを分けて出すのが要点**——「ストアからは消えたのにチェーンは通り続ける」形が
/// あり得て、それはキャッシュの存在を意味する（そのまま`_AT`の時刻で寿命が読める）。
const TEMPLATE_N6_LONGLIVED_PROBE: &str = r#"
$ErrorActionPreference = 'Continue'
function Say($k, $v) { Write-Output ("$k=" + (($v -as [string]) -replace '\s+', ' ')) }
function Try1($k, $block) {
    try { Say $k (& $block) }
    catch {
        $x = $_.Exception
        while ($x.InnerException) { $x = $x.InnerException }
        Say $k ("EXC:" + $x.GetType().Name + ":" + ("0x{0:X8}" -f $x.HResult))
    }
}
$sync = '%%SYNC%%'
Say 'CHILD_PID' $PID
$ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
    ,[Convert]::FromBase64String('%%CA_B64%%'))
$leaf = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
    ,[Convert]::FromBase64String('%%LEAF_B64%%'))

function Measure1($tag) {
    Try1 ($tag + '_STORE') {
        $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser')
        $s.Open('ReadOnly')
        $n = $s.Certificates.Count
        $hit = @($s.Certificates | Where-Object { $_.Thumbprint -eq '%%CA_THUMB%%' }).Count
        $s.Close()
        "$n/$hit"
    }
    Try1 ($tag + '_CHAIN') {
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = 'NoCheck'
        $chain.ChainPolicy.ExtraStore.Add($ca) | Out-Null
        $ok = $chain.Build($leaf)
        $st = ($chain.ChainStatus | ForEach-Object { $_.Status }) -join '+'
        if ($st -eq '') { $st = 'NoError' }
        "$ok/$st"
    }
    Say ($tag + '_AT') ((Get-Date).ToString('HH:mm:ss'))
}

# 外が「合図ファイル」を置くまで待つ。**待ちには必ず上限を置く**——外が落ちたときに
# コンテナ子が永遠に居座ると、テストが終わってもプロセスが残る。
function WaitFor($name) {
    $p = Join-Path $sync $name
    $i = 0
    while (-not (Test-Path $p)) {
        Start-Sleep -Milliseconds 200
        $i++
        if ($i -gt %%LIMIT_TICKS%%) { Say ('TIMEOUT_' + $name) '1'; return $false }
    }
    return $true
}

# 段0: **`Blob`が在る状態**の基準線（ここが通らなければ以降は読めない）。
Measure1 'T0'
[IO.File]::WriteAllText((Join-Path $sync 'p0.done'), 'x')

foreach ($step in %%STEPS%%) {
    if (-not (WaitFor ('go-' + $step))) { break }
    Measure1 ('T' + $step)
    [IO.File]::WriteAllText((Join-Path $sync ('done-' + $step)), 'x')
}
Say 'DONE' '1'
"#;

/// 同期ディレクトリにフラグが現れるまで待つ（外側）。
fn n6_wait_for_flag(sync: &Path, name: &str, limit: std::time::Duration) -> bool {
    let target = sync.join(name);
    let start = std::time::Instant::now();
    while start.elapsed() < limit {
        if target.exists() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}

fn n6_set_flag(sync: &Path, name: &str) {
    std::fs::write(sync.join(name), b"x").unwrap_or_else(|e| {
        panic!("同期フラグ{name}を置けない（{}）: {e}", sync.display())
    });
}

/// **問a・b: `Blob`を消したら信頼は失われるか。新規プロセスと既存プロセスで別々に。**
///
/// # 測る順序（B-35: 禁止側だけを測らない）
///
/// 1. **対照**（消す前）: 新規プロセスでも長命プロセスでも信頼が効いていることを確認する。
///    これが無いと、後の「信頼されない」を「元から通っていなかった」と区別できない
/// 2. `Blob`（＝`Certificates\<thumbprint>`キー）**だけ**を消す。`Mappings`もACEも残す
///    ——**1度に1変数**（B-29）。ACEも同時に剥がすと、どちらが効いたのか決まらない
/// 3. **新規プロセス**で測る（問a）
/// 4. **段0を既に通した長命プロセス**で、時間を空けながら繰り返し測る（問b）
///
/// # 時間差の刻み
///
/// 既定は「直後・+30秒・+120秒」。`HARNESS_TEST_N6_WAITS`（カンマ区切りの秒数）で上書きできる
/// ——**設計判断に要るのは「即座に失効するか否か」の二値**で、そこは直後の1点で決まる。
/// 寿命の上限を詰めたくなったときに、器を書き換えずに刻みだけ延ばせるようにしてある。
#[test]
#[ignore = "実AppContainerとHKCUへの書込を使う。**非昇格**で、--test-threads=1で走らせること"]
fn n6_does_deleting_the_blob_revoke_trust() {
    let profile = format!("harness.n6blob.{}", std::process::id());
    let certs = create_spike_certs();
    let sid = ensure_profile_for_test(&profile).expect("create the spike AppContainer profile");
    let pkg_sid = crate::win_common::sid_to_string(sid.as_psid()).expect("package SID string");
    eprintln!("[N6-a/b] profile={profile} package_sid={pkg_sid} ca={}", certs.ca_thumb);

    // 撤収を、作る前に登録する（B-01: 対で、しかも撤収を先に置く）。
    let g = vec![(profile.clone(), pkg_sid.clone())];
    let _guard = super::test_support::scopeguard(move || n6_cleanup(&g));

    n6_setup_layer1(&profile, &pkg_sid, &certs.ca_der_b64, &certs.ca_thumb);

    // --- 対照1: 消す前・新規プロセス -----------------------------------------
    let before = n6_probe_once(sid.as_psid(), &profile, &pkg_sid, &certs);
    eprintln!("[N6-a/b] {}", n6_row("対照（消す前・新規プロセス）", &before));
    assert!(
        n6_trusted(&before),
        "**対照が成立していない**——`Blob`を置いた状態で信頼されていない。\
         この実行の「信頼が失われた」は撤収の効果を意味しない:\n{before}"
    );

    // --- 長命プロセスを起こす（段0で基準線を取ってから待たせる） --------------
    let sync_dir = std::path::PathBuf::from(format!(
        r"{}\Packages\{profile}\AC\Temp\n6sync",
        std::env::var("LOCALAPPDATA").expect("LOCALAPPDATA")
    ));
    std::fs::create_dir_all(&sync_dir).expect("create the sync directory under AC\\Temp");

    let waits: Vec<u64> = std::env::var("HARNESS_TEST_N6_WAITS")
        .unwrap_or_else(|_| "0,30,120".to_string())
        .split(',')
        .filter_map(|s| s.trim().parse::<u64>().ok())
        .collect();
    assert!(!waits.is_empty(), "HARNESS_TEST_N6_WAITSが空。刻みが1つも無い");
    let steps: Vec<String> = (0..waits.len()).map(|i| format!("s{i}")).collect();
    let steps_ps = format!(
        "@({})",
        steps
            .iter()
            .map(|s| format!("'{s}'"))
            .collect::<Vec<_>>()
            .join(",")
    );
    // 待ちの上限は「全刻みの合計＋余裕5分」。外が落ちても子が居座らない。
    let limit_ticks = (waits.iter().sum::<u64>() + 300) * 5;

    let script = TEMPLATE_N6_LONGLIVED_PROBE
        .replace("%%SYNC%%", &sync_dir.to_string_lossy())
        .replace("%%CA_B64%%", &certs.ca_der_b64)
        .replace("%%LEAF_B64%%", &certs.leaf_der_b64)
        .replace("%%CA_THUMB%%", &certs.ca_thumb)
        .replace("%%STEPS%%", &steps_ps)
        .replace("%%LIMIT_TICKS%%", &limit_ticks.to_string());

    let (shell, _) = resolve_shell();
    let encoded = encoded_command(&script);
    let child = spawn(
        &shell,
        &["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded],
        Path::new(r"C:\Windows\System32"),
        &child_env(),
        false,
        sid.as_psid(),
        NetworkCapability::Deny,
        super::RedirectorInject::default(),
        DomainIdentity::OwnPackage,
    )
    .expect("spawn the long-lived probe inside the spike AppContainer");
    let long_pid = child.pid();
    eprintln!("[N6-b] 長命プロセスのPID={long_pid}");

    // 出力はEOFまで読み切る形でしか取れないので、**別スレッドへ預けて**本体は外側の
    // 操作（削除・待機）を進める。`AppContainerChild`は`Send`である。
    let (tx, rx) = std::sync::mpsc::channel();
    let joiner = std::thread::spawn(move || {
        let r = child.write_stdin_read_output_and_wait(None);
        let _ = tx.send(r);
    });

    // 段0（`Blob`が在る状態）の完了を待つ。ここで待ち切れなければ測定は不成立。
    assert!(
        n6_wait_for_flag(&sync_dir, "p0.done", std::time::Duration::from_secs(180)),
        "長命プロセスが段0（基準線）を終えなかった。同期ディレクトリ={}",
        sync_dir.display()
    );

    // --- `Blob`だけを消す（`Mappings`もACEも残す。1度に1変数） ---------------
    let blob_key = n6_blob_key(&profile, &certs.ca_thumb);
    let certs_key = format!(
        r"{STORAGE_ROOT}\{profile}\Software\Microsoft\SystemCertificates\Root\Certificates"
    );
    let (del_out, del_err, del_code) = ps_outside(&format!(
        r#"$ErrorActionPreference = 'Stop'
Write-Output ("BLOB_BEFORE=" + (Test-Path '{blob_key}'))
Remove-Item -Path '{blob_key}' -Recurse -Force
Write-Output ("BLOB_AFTER=" + (Test-Path '{blob_key}'))
Write-Output ("CERTS_LEFT=" + (Get-Item '{certs_key}').SubKeyCount)
# **消したのは`Blob`だけ**であることを読み返す（他の変数を動かしていない証拠）。
Write-Output ("MAPPING_STILL=" + (Test-Path '{MAPPINGS_ROOT}\{pkg_sid}'))
Write-Output ("STORAGE_ACE_STILL=" + @((Get-Acl '{STORAGE_ROOT}\{profile}').Access |
    Where-Object {{ $_.IdentityReference.Value -eq '{pkg_sid}' }}).Count)"#
    ));
    eprintln!("[N6-a/b][Blob削除] exit={del_code}\n{del_out}{del_err}");
    assert_eq!(del_code, 0, "Blobの削除が失敗した: {del_out}{del_err}");
    assert_eq!(
        kv(&del_out, "BLOB_BEFORE").as_deref(),
        Some("True"),
        "消す前にBlobが無い。測定が成立していない:\n{del_out}"
    );
    assert_eq!(
        kv(&del_out, "BLOB_AFTER").as_deref(),
        Some("False"),
        "**Blobが消えていない**。「信頼が残った」の原因が撤収の失敗なのか\
         キャッシュなのか分けられない:\n{del_out}"
    );
    assert_eq!(
        kv(&del_out, "MAPPING_STILL").as_deref(),
        Some("True"),
        "Mappings登録まで消えている。1度に2変数動かしている:\n{del_out}"
    );

    // --- 問a: **新規プロセス** ------------------------------------------------
    let after_new = n6_probe_once(sid.as_psid(), &profile, &pkg_sid, &certs);
    eprintln!(
        "[N6-a] {}",
        n6_row("問a（Blob削除後・新規プロセス）", &after_new)
    );

    // --- 問b: **長命プロセス**を刻みながら叩く --------------------------------
    for (i, wait) in waits.iter().enumerate() {
        if *wait > 0 {
            eprintln!("[N6-b] {wait}秒待つ…");
            std::thread::sleep(std::time::Duration::from_secs(*wait));
        }
        n6_set_flag(&sync_dir, &format!("go-{}", steps[i]));
        assert!(
            n6_wait_for_flag(
                &sync_dir,
                &format!("done-{}", steps[i]),
                std::time::Duration::from_secs(120)
            ),
            "長命プロセスが刻み{}（+{wait}秒）に応答しなかった",
            steps[i]
        );
    }

    let long_out = rx
        .recv_timeout(std::time::Duration::from_secs(180))
        .expect("長命プロセスの出力を受け取れなかった")
        .expect("長命プロセスの読み取りに失敗した");
    let _ = joiner.join();
    eprintln!("[N6-b][長命プロセスの出力]\n{}", long_out.0);
    assert_eq!(
        kv(&long_out.0, "DONE").as_deref(),
        Some("1"),
        "長命プロセスの観測スクリプトが最後まで走っていない:\n{}",
        long_out.0
    );

    // --- まとめ（判定はこの表を人が読んで書く） -------------------------------
    eprintln!("\n[N6][**まとめ: 問a・b**] 物差しは`X509Store`（ストアに在るか）と`X509Chain`（信頼判断）");
    eprintln!("  {}", n6_row("① 対照・消す前・新規プロセス", &before));
    eprintln!("  {}", n6_row("② 問a・消した後・新規プロセス", &after_new));
    eprintln!("  ③ 問b・長命プロセス（同一プロセス内で繰り返し）:");
    let mut elapsed = 0u64;
    eprintln!(
        "      段0（Blobが在る・基準線）  ストア={} / チェーン={} / 時刻={}",
        kv(&long_out.0, "T0_STORE").unwrap_or_default(),
        kv(&long_out.0, "T0_CHAIN").unwrap_or_default(),
        kv(&long_out.0, "T0_AT").unwrap_or_default(),
    );
    for (i, wait) in waits.iter().enumerate() {
        elapsed += wait;
        eprintln!(
            "      削除から+{elapsed:>4}秒            ストア={} / チェーン={} / 時刻={}",
            kv(&long_out.0, &format!("T{}_STORE", steps[i])).unwrap_or_default(),
            kv(&long_out.0, &format!("T{}_CHAIN", steps[i])).unwrap_or_default(),
            kv(&long_out.0, &format!("T{}_AT", steps[i])).unwrap_or_default(),
        );
    }
    eprintln!(
        "\n  → 問a（新規プロセスで信頼が失われたか） = {}",
        if n6_trusted(&after_new) { "**失われていない**" } else { "失われた" }
    );

    // **隔離が壊れていないこと**（B-35の対照）。ユーザーの`My`が見えていたら、
    // 見ているのはコンテナのストアではなくユーザーのストアである＝測る世界が違う。
    for (label, out) in [("対照", &before), ("問a", &after_new)] {
        assert_eq!(
            kv(out, "DONE").as_deref(),
            Some("1"),
            "[{label}] 観測スクリプトが最後まで走っていない:\n{out}"
        );
    }
}

// ---------------------------------------------------------------------------
// 問c: `Blob`を消さずに**ACEだけ**を剥がすのは、有効な撤収か
// ---------------------------------------------------------------------------

/// package SID宛のACEを、指定したキー群から**再帰的に**剥がし、**剥がれたことを数え直す**。
///
/// `RemoveAccessRuleAll`は同じ主体・同じ`AccessControlType`のルールを権限に関わらず全部落とす。
/// 継承ACEは`Set-Acl`で直接は落とせないが、**親の明示ACEを落とせば子の継承分も一緒に消える**
/// ので、親から順に処理すれば足りる（`Get-Item` → `Get-ChildItem -Recurse`の順がそれ）。
///
/// 数え直しは`(Get-Acl).Access`（継承分を含む）で行う——`ACE_LEFT=0`が
/// 「その主体からはもう1本も効いていない」の意味になる（`feedback-security-self-verification`）。
const TEMPLATE_N6_REVOKE_ACE: &str = r#"
$ErrorActionPreference = 'Stop'
$sid = New-Object System.Security.Principal.SecurityIdentifier('%%PKG_SID%%')
$targets = %%TARGETS%%
foreach ($root in $targets) {
    if (-not (Test-Path $root)) { continue }
    $keys = @(Get-Item $root) + @(Get-ChildItem $root -Recurse)
    foreach ($k in $keys) {
        $acl = Get-Acl -Path $k.PSPath
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $sid, 'ReadKey', 'ContainerInherit', 'None', 'Allow')
        $null = $acl.RemoveAccessRuleAll($rule)
        Set-Acl -Path $k.PSPath -AclObject $acl
    }
}
# **剥がれたことを、付与とは独立に数え直す**（継承分も含めて0であること）。
$left = 0
foreach ($root in $targets) {
    if (-not (Test-Path $root)) { continue }
    foreach ($k in (@(Get-Item $root) + @(Get-ChildItem $root -Recurse))) {
        $left += @((Get-Acl -Path $k.PSPath).Access | Where-Object {
            $id = $_.IdentityReference.Value
            try { $id = $_.IdentityReference.Translate(
                [System.Security.Principal.SecurityIdentifier]).Value } catch { }
            $id -eq '%%PKG_SID%%' }).Count
    }
}
Write-Output ("ACE_LEFT=" + $left)
# **`Blob`は消していない**ことの読み返し（問cはACEだけを動かす測定である）。
Write-Output ("BLOB_STILL=" + (Test-Path '%%BLOB%%'))
"#;

/// **問c: `Blob`を残したままACEだけを剥がしたら、信頼は失われるか。**
///
/// # なぜ象限ごとに別プロファイルなのか
///
/// N1-③と同じ理由に加えて、こちらには**順序効果**という固有の危険がある——1つの
/// プロファイルでACEを剥がしては戻すと、剥がし漏れ・戻し漏れが次の象限の結果に化けて出る。
/// package SIDはプロファイル名から決まるので、名前を変えれば各象限は互いに独立になる。
///
/// # N1-③との違い（**同じ表に見えるが別の問い**）
///
/// N1-③は「**最初からACEを付けない**」を測った。ここで測るのは「**一度付けて動いた後に
/// 剥がす**」であり、**撤収が効くか**という別の問いである。前者が真でも、ハンドルや
/// キャッシュが生きていて後者が偽になり得る——それが撤収を実測しなければならない理由である。
#[test]
#[ignore = "実AppContainerとHKCUへの書込を使う。**非昇格**で、--test-threads=1で走らせること"]
fn n6_does_revoking_the_ace_revoke_trust() {
    let pid = std::process::id();
    let certs = create_spike_certs();

    // (ラベル, `Mappings`側を剥がすか, `Storage`側を剥がすか)
    let plan: [(&str, bool, bool); 3] = [
        ("① Mappings側のACEだけ剥がす", true, false),
        ("② Storage側のACEだけ剥がす", false, true),
        ("③ 両方剥がす（ACEによる完全撤収）", true, true),
    ];

    let mut made: Vec<(String, String)> = Vec::new();
    for i in 0..plan.len() {
        made.push((format!("harness.n6ace{i}.{pid}"), String::new()));
    }
    // 撤収を、作る前に登録する。SIDは作った後に埋まるので`Mutex`で共有する。
    let registry = std::sync::Arc::new(std::sync::Mutex::new(made));
    let g = registry.clone();
    let _guard = super::test_support::scopeguard(move || {
        let snapshot: Vec<(String, String)> = g
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, sid)| !sid.is_empty())
            .collect();
        n6_cleanup(&snapshot);
    });

    let mut rows: Vec<(String, String, String)> = Vec::new();
    for (i, (label, revoke_map, revoke_storage)) in plan.iter().enumerate() {
        eprintln!("\n[N6-c] ================ {label} ================");
        let profile = format!("harness.n6ace{i}.{pid}");
        let sid = ensure_profile_for_test(&profile).expect("create the spike AppContainer profile");
        let pkg_sid = crate::win_common::sid_to_string(sid.as_psid()).expect("package SID string");
        if let Ok(mut v) = registry.lock() {
            v[i].1 = pkg_sid.clone();
        }

        n6_setup_layer1(&profile, &pkg_sid, &certs.ca_der_b64, &certs.ca_thumb);

        // --- 対照: 剥がす前は信頼が効いていること -----------------------------
        let before = n6_probe_once(sid.as_psid(), &profile, &pkg_sid, &certs);
        eprintln!("[N6-c] {}", n6_row("  剥がす前（対照）", &before));
        assert!(
            n6_trusted(&before),
            "[{label}] **対照が成立していない**——剥がす前から信頼されていない。\
             この象限の結果は撤収の効果を意味しない:\n{before}"
        );

        // --- ACEだけを剥がす（`Blob`は残す） ----------------------------------
        let mut targets: Vec<String> = Vec::new();
        if *revoke_map {
            targets.push(format!("{MAPPINGS_ROOT}\\{pkg_sid}"));
        }
        if *revoke_storage {
            targets.push(format!("{STORAGE_ROOT}\\{profile}"));
        }
        let targets_ps = format!(
            "@({})",
            targets
                .iter()
                .map(|t| format!("'{t}'"))
                .collect::<Vec<_>>()
                .join(",")
        );
        let (rev_out, rev_err, rev_code) = ps_outside(
            &TEMPLATE_N6_REVOKE_ACE
                .replace("%%PKG_SID%%", &pkg_sid)
                .replace("%%TARGETS%%", &targets_ps)
                .replace("%%BLOB%%", &n6_blob_key(&profile, &certs.ca_thumb)),
        );
        eprintln!("[N6-c][ACE剥がし] exit={rev_code} {rev_out} {rev_err}");
        assert_eq!(rev_code, 0, "[{label}] ACEの剥がしが失敗した: {rev_out}{rev_err}");
        assert_eq!(
            kv(&rev_out, "ACE_LEFT").as_deref(),
            Some("0"),
            "[{label}] **ACEが剥がれていない**。「信頼が残った」の原因が撤収の失敗である\
             可能性を排除できない:\n{rev_out}"
        );
        assert_eq!(
            kv(&rev_out, "BLOB_STILL").as_deref(),
            Some("True"),
            "[{label}] `Blob`まで消えている。問cは**ACEだけ**を動かす測定である:\n{rev_out}"
        );

        // --- 剥がした後・**新規プロセス** ------------------------------------
        let after = n6_probe_once(sid.as_psid(), &profile, &pkg_sid, &certs);
        eprintln!("[N6-c] {}", n6_row("  剥がした後（新規プロセス）", &after));
        assert_eq!(
            kv(&after, "DONE").as_deref(),
            Some("1"),
            "[{label}] 観測スクリプトが最後まで走っていない:\n{after}"
        );

        rows.push((
            label.to_string(),
            n6_row("剥がす前", &before),
            format!(
                "{}   → 信頼は{}",
                n6_row("剥がした後", &after),
                if n6_trusted(&after) { "**残った**" } else { "失われた" }
            ),
        ));
    }

    eprintln!("\n[N6][**まとめ: 問c**] `Blob`は残したまま、ACEだけを剥がした");
    for (label, before, after) in &rows {
        eprintln!("  {label}\n      {before}\n      {after}");
    }
}

// ---------------------------------------------------------------------------
// 問d: `DeleteAppContainerProfile`は、層1が書いたものを消すか
// ---------------------------------------------------------------------------

/// **問d: プロファイルを消したら、`Storage`キー・`Mappings`エントリ・`Blob`は消えるか。**
///
/// # なぜこれを測るのか
///
/// 消えるなら、層1の撤収は**プロファイルの寿命に相乗り**できる（D-37の
/// 「セッション＝プロセスの寿命」と同じ形。既存の`gc_dead_sessions`が拾える）。
/// 消えないなら、実装は撤収を**明示的に書かねばならない**——そして書き忘れれば
/// 「セッションが終わったのにそのコンテナ名の信頼が残り続ける」状態がマシンに堆積する。
///
/// # `DeleteAppContainerProfile`は嘘をつくことがある
///
/// `S_OK`を返しながら何も消さないことがある（`session_profile.rs`の実測コメント、
/// このファイルの`TEMPLATE_CLEANUP`もそれを前提に明示削除を重ねている）。したがって
/// **戻り値ではなく状態を数える**（型F: ロールバックまでが設計）。
#[test]
#[ignore = "実AppContainerとHKCUへの書込を使う。**非昇格**で、--test-threads=1で走らせること"]
fn n6_what_does_delete_appcontainer_profile_actually_remove() {
    let profile = format!("harness.n6del.{}", std::process::id());
    let certs = create_spike_certs();
    let sid = ensure_profile_for_test(&profile).expect("create the spike AppContainer profile");
    let pkg_sid = crate::win_common::sid_to_string(sid.as_psid()).expect("package SID string");
    eprintln!("[N6-d] profile={profile} package_sid={pkg_sid}");

    let g = vec![(profile.clone(), pkg_sid.clone())];
    let _guard = super::test_support::scopeguard(move || n6_cleanup(&g));

    n6_setup_layer1(&profile, &pkg_sid, &certs.ca_der_b64, &certs.ca_thumb);

    // --- 対照: 消す前は信頼が効いていること -----------------------------------
    let before = n6_probe_once(sid.as_psid(), &profile, &pkg_sid, &certs);
    eprintln!("[N6-d] {}", n6_row("対照（プロファイル削除前）", &before));
    assert!(
        n6_trusted(&before),
        "**対照が成立していない**——削除前から信頼されていない:\n{before}"
    );

    let census = |tag: &str| -> String {
        let script = format!(
            r#"$ErrorActionPreference = 'SilentlyContinue'
Write-Output ("MAPPING=" + (Test-Path '{MAPPINGS_ROOT}\{pkg_sid}'))
Write-Output ("STORAGE=" + (Test-Path '{STORAGE_ROOT}\{profile}'))
Write-Output ("BLOB=" + (Test-Path '{}'))
Write-Output ("PROFILE_DIR=" + (Test-Path (Join-Path $env:LOCALAPPDATA 'Packages\{profile}')))
Write-Output ("STORAGE_TREE=" + (((Get-ChildItem '{STORAGE_ROOT}\{profile}' -Recurse -EA SilentlyContinue).Name -replace '.*\\Storage\\','') -join ';'))"#,
            n6_blob_key(&profile, &certs.ca_thumb)
        );
        let (out, _, _) = ps_outside(&script);
        eprintln!("[N6-d][{tag}]\n{out}");
        out
    };

    let pre = census("削除前");
    assert_eq!(
        kv(&pre, "BLOB").as_deref(),
        Some("True"),
        "削除前にBlobが無い。測定が成立していない:\n{pre}"
    );

    // --- `DeleteAppContainerProfile`を撃つ（**これだけ**。手で消さない） ------
    let hr = unsafe {
        let w = crate::win_common::wide(&profile);
        windows::Win32::Security::Isolation::DeleteAppContainerProfile(windows::core::PCWSTR(
            w.as_ptr(),
        ))
    };
    eprintln!("[N6-d] DeleteAppContainerProfileの戻り値 = {hr:?}");

    let post = census("削除後");

    // --- 残ったものが**まだ生きているか**（残骸なのか、無害な抜け殻なのか） ---
    // プロファイルを消しても、package SIDは名前から決定的に導出されるので同じ名前を
    // 作り直せば同じSIDになる。**次のセッションが同じ名前を使ったら信頼を引き継ぐのか**を測る。
    let sid2 = ensure_profile_for_test(&profile).expect("re-create the profile with the same name");
    let pkg_sid2 = crate::win_common::sid_to_string(sid2.as_psid()).expect("package SID string");
    assert_eq!(
        pkg_sid2, pkg_sid,
        "同じ名前で作り直したのにpackage SIDが変わった。この測定の前提が崩れている"
    );
    let after = n6_probe_once(sid2.as_psid(), &profile, &pkg_sid, &certs);
    eprintln!(
        "[N6-d] {}",
        n6_row("作り直した後（同じ名前・同じSID）", &after)
    );

    eprintln!("\n[N6][**まとめ: 問d**] `DeleteAppContainerProfile`が何を消したか");
    for key in ["MAPPING", "STORAGE", "BLOB", "PROFILE_DIR"] {
        eprintln!(
            "  {key:<12} 削除前={:<6} → 削除後={}",
            kv(&pre, key).unwrap_or_default(),
            kv(&post, key).unwrap_or_default(),
        );
    }
    eprintln!(
        "  削除後のStorage配下 = {:?}",
        kv(&post, "STORAGE_TREE").unwrap_or_default()
    );
    eprintln!(
        "\n  → 同じ名前で作り直したコンテナは、消す前のCAを{}",
        if n6_trusted(&after) {
            "**まだ信頼している**（＝撤収になっていない）"
        } else {
            "信頼していない"
        }
    );
    assert_eq!(kv(&after, "DONE").as_deref(), Some("1"));
}

// ---------------------------------------------------------------------------
// 問e（前段）: そもそも、その6ランタイムはAppContainerの中で起動できるのか
// ---------------------------------------------------------------------------

/// **問eの測定を組む前に潰しておく前提**。
///
/// N2-層1が踏んだ罠Aは「`gh`はTLSを喋る前に設定ファイルの読取で落ちる。これを
/// 『Goが層1を読まない』と読み違えると、1つの否定を2回数えることになる」だった。
/// 6ランタイムのうち`cargo`・`python`・`uv`は**`%USERPROFILE%`配下**に居り、
/// AppContainerからはそもそも**exeが読めない**可能性が高い——その状態で「層1を読まない」と
/// 記録すれば、罠Aをそっくり繰り返すことになる。
///
/// そこでまず`--version`だけを撃ち、**どのランタイムが中で起動できるか**を確定させる。
/// ここで起動できないものは、問eの表では「✗」ではなく**「測定不能」**として扱い、
/// 到達させる手段（package SID宛ACE等）を別途決める。
#[test]
#[ignore = "実AppContainerを使う。**非昇格**で走らせること。問eの前段（起動可否だけを見る）"]
fn n6_which_runtimes_can_even_start_inside_the_container() {
    let profile = format!("harness.n6run.{}", std::process::id());
    let cleanup_profile = profile.clone();
    let _guard = super::test_support::scopeguard(move || unsafe {
        let w = crate::win_common::wide(&cleanup_profile);
        let _ = windows::Win32::Security::Isolation::DeleteAppContainerProfile(
            windows::core::PCWSTR(w.as_ptr()),
        );
    });
    let sid = ensure_profile_for_test(&profile).expect("create the spike AppContainer profile");

    // 実パスは外で解決して埋め込む（中では`where.exe`もPATHも当てにならない）。
    let home = std::env::var("USERPROFILE").expect("USERPROFILE");
    let local = std::env::var("LOCALAPPDATA").expect("LOCALAPPDATA");
    let runtimes: Vec<(&str, String, &str)> = vec![
        ("cargo", format!(r"{home}\.cargo\bin\cargo.exe"), "--version"),
        ("git", r"C:\Program Files\Git\cmd\git.exe".to_string(), "--version"),
        ("node", r"C:\Program Files\nodejs\node.exe".to_string(), "--version"),
        (
            "python",
            format!(r"{local}\Programs\Python\Python313\python.exe"),
            "--version",
        ),
        ("uv", format!(r"{home}\.local\bin\uv.exe"), "--version"),
        (
            "mingw64-curl",
            r"C:\Program Files\Git\mingw64\bin\curl.exe".to_string(),
            "--version",
        ),
        // 既知の2件を**同じ実行に並べる**（B-35の許可側の対照）。この2つが中で動かないなら、
        // 落ちているのはランタイム個別の事情ではなく起動側である。
        (
            "（対照）System32 curl",
            r"C:\Windows\System32\curl.exe".to_string(),
            "--version",
        ),
        (
            "（対照）gh",
            r"C:\Program Files\GitHub CLI\gh.exe".to_string(),
            "--version",
        ),
    ];

    let mut script = String::from(
        r#"$ErrorActionPreference = 'Continue'
function Say($k, $v) { Write-Output ("$k=" + (($v -as [string]) -replace '\s+', ' ')) }
"#,
    );
    for (name, exe, arg) in &runtimes {
        // **exeの存在と、起動できるかを分けて出す**——「ファイルが見えない」と
        // 「起動したが落ちた」は別の症状であり、要る手当てが違う（B-29）。
        script.push_str(&format!(
            r#"
Say 'EXISTS:{name}' (Test-Path '{exe}')
try {{ Say 'RUN:{name}' ((& '{exe}' {arg} 2>&1) | Select-Object -First 1) }}
catch {{ Say 'RUN:{name}' ("EXC:" + $_.Exception.Message) }}
"#
        ));
    }
    script.push_str("Say 'DONE' '1'\n");

    let (outside, _, _) = ps_outside(&script);
    eprintln!("[N6-e前段][外（通常トークン）]\n{outside}");
    let (inside, inside_err, code) = ps_in_container(sid.as_psid(), &script);
    eprintln!("[N6-e前段][中（AppContainer）] exit={code}\n{inside}\n--- stderr ---\n{inside_err}");

    eprintln!("\n[N6][**まとめ: 問eの前段**] 中で起動できるか（外＝対照）");
    for (name, exe, _) in &runtimes {
        eprintln!(
            "  {name:<22} exeが見えるか 外={:<6} 中={:<6} | 起動 外={} | 中={}",
            kv(&outside, &format!("EXISTS:{name}")).unwrap_or_default(),
            kv(&inside, &format!("EXISTS:{name}")).unwrap_or_default(),
            kv(&outside, &format!("RUN:{name}")).unwrap_or_default(),
            kv(&inside, &format!("RUN:{name}")).unwrap_or_default(),
        );
        let _ = exe;
    }
    assert_eq!(
        kv(&inside, "DONE").as_deref(),
        Some("1"),
        "中の観測スクリプトが最後まで走っていない:\n{inside}"
    );
}

// ---------------------------------------------------------------------------
// 問e: 層1で未測定の6ランタイム
// ---------------------------------------------------------------------------
//
// N2-層1が層1で実測したのは**3つだけ**（`Invoke-WebRequest`✓／`curl.exe`✗／`gh`✗）で、
// `cargo`・`git`・`node`・`python`・`uv`・mingw64 `curl`の6つは空欄のまま残った。
// N2自身が検問で「層1で救えるのは.NET系だけ、と一般化しかけた」と記録しており
// （D-43: 測っていないものを測ったように書かない）、ここはその空欄を実測で埋める。
//
// ## 到達性の壁——**`--version`すら通らないランタイムが4つある**（実測）
//
// `n6_which_runtimes_can_even_start_inside_the_container`で先に測ったところ、
// AppContainerの中から起動できたのは`git`とmingw64 `curl`だけだった
// （どちらも`C:\Program Files\Git`配下で、そこには`ALL APPLICATION PACKAGES`のACEが既にある）。
// `cargo`・`node`・`python`・`uv`は**exeのファイル読取が拒否**される
// （`Access to the path '…' is denied`）。
//
// **これを測らずに走らせると、N2-層1の罠Aをそのまま繰り返す**——あちらは`gh`が
// 設定ファイルの読取で落ちるのをTLSの結果と読み違えかけた（「1つの否定を2回数える」）。
// exeが開けない状態の失敗は「層1を読まない」ではなく**測定不能**である。
//
// ## 到達させる手段に**コピー**を選んだ理由
//
// | 案 | 却下/採用の理由 |
// |---|---|
// | 実ディレクトリへpackage SID宛ACEを付ける | `C:\Program Files\nodejs`は**要管理者**（B-08: 昇格するとスパイクが測る世界が変わる）。ユーザー所有の`Python313`は8,843ファイルで、剥がし漏れれば実インストールにACEが残る |
// | **そのコンテナ専用の`AC`フォルダへexeをコピーする（採用）** | 昇格が要らず、実マシンのACLを1つも変えず、残骸はプロファイル配下だけ（既存の撤収がそのまま消す） |
//
// **コピーで測定対象がずれないこと**——問eが問うのは「そのランタイムのTLS実装が
// *どの信頼ストアを見るか*」であり、これは**バイナリの性質**であってexeの置き場所とは
// 独立である。置き場所が効くのは設定ファイル・sysrootの探索だけで、そちらは
// `CARGO_HOME`等を`AC`配下へ向けて別に解決する。
//
// ## 判定の読み方（`http=200`かどうかでは読まない）
//
// N2節と同じ規準を使う——**エラーの種類が変わるか**で読む。アプリ層のエラー
// （`expected value at line 1 column 1`・`is this a git repository?`・`No solution found`）は
// **TLS通過**である。対照（別CAのサーバ）では必ず証明書検証エラーになるので、
// 「対照が証明書エラー／本命がそれ以外」なら層1を読んだ、と言える。

/// `%LOCALAPPDATA%\Packages\<profile>\AC\Temp`配下に作る作業領域。
///
/// **`AC`フォルダはそのAppContainerの専用領域**で、`CreateAppContainerProfile`が
/// package SID宛のACEを付けて作る。外から作った子フォルダはそれを継承するので、
/// 中からは読み書き実行でき、外（通常トークン）からも普通に触れる。
fn n6_ac_dir(profile: &str, leaf: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!(
        r"{}\Packages\{profile}\AC\Temp\{leaf}",
        std::env::var("LOCALAPPDATA").expect("LOCALAPPDATA")
    ))
}

/// 1ランタイム分の撃ち方。
struct N6Runtime {
    /// 表の行名。
    name: &'static str,
    /// コンテナの中から見たexeの絶対パス（コピーしたものはAC配下）。
    exe_in: String,
    /// **外の対照**で使う、実インストールのexeパス。
    ///
    /// 中と外で別々に持つのは、コピーしたexeが**外からは読めない**ためである
    /// （`AC`フォルダのDACLはpackage SID向けで、通常トークンのユーザーは弾かれる。
    /// 実測: 外の`python`が`probe.py`を`[Errno 13] Permission denied`で開けなかった）。
    /// 外の対照は「そのコマンドがそもそもTLSまで届くか」を見るためのものなので、
    /// **実体のexeと外から読める作業ディレクトリ**で撃たないと意味が無い。
    exe_out: String,
    /// `%%URL%%`・`%%HOME%%`・`%%EXE%%`・`%%PY%%`・`%%RT%%`・`%%EXTRA%%`を埋めるPowerShell式。
    command: &'static str,
    /// 変種 (表示名, **出力キーに使うASCII識別子**, `%%EXTRA%%`へ入れる値)。
    ///
    /// **識別子をASCIIにしてあるのは事故の再発防止である。** 最初は表示名をそのまま
    /// `RT:<name>:<変種>:<main|ctrl>`のキーへ使っていたが、PowerShellの標準出力は
    /// コンソールのコードページで返るのに対しRust側はUTF-8として読むため、
    /// **日本語を含むキーが文字化けして`kv()`が1件も引けず、表が全部空欄になった**
    /// （実測。値の側の文字化けは読めば分かるが、キーの側は「測れていない」と
    /// 見分けが付かない＝無言の失敗になる。B-10）。
    ///
    /// **失効確認を切った版**を並べる理由（N2節の罠B）——Schannelは失効確認をCAの信頼とは
    /// 別に要求するので、**CAを信頼させても**`CRYPT_E_NO_REVOCATION_CHECK`で落ちる。
    /// これを「層1を読まない」と読むと、通っているものを✗と書くことになる。
    /// `uv`の`UV_NATIVE_TLS`・`node`の`--use-system-ca`も同じ枠で撃つ——どちらも
    /// 「既定では自前のCA束を見る／これを立てるとOSのストアを見る」という切り替えで、
    /// **どちらの状態の話なのかを混ぜない**ために必ず両方を並べる。
    variants: &'static [(&'static str, &'static str, &'static str)],
    /// 出力を何行残すか。**足りないと本当の原因が切り落とされる**——最初の測定では
    /// `cargo`が`failed to update registry`、`uv`が`Request failed after 3 retries`までしか
    /// 見えず、その下にあるTLSの理由が読めなかった。
    lines: usize,
}

/// 中と外で違うのはこの4つだけ（exeは[`N6Runtime`]が持つ）。
struct N6Paths {
    /// `probe.js`/`probe.py`を置いたディレクトリ。
    rt: String,
    /// cwd兼、各ランタイムのキャッシュ・設定の置き場。**書ける場所であること。**
    home: String,
    /// `uv --python`へ渡すPython。
    py: String,
}

/// Python/Nodeの一行スクリプトは、PowerShellの引用符とWin32のコマンドライン整形を
/// 二重に通すと**黙って別物になる**（`encoded_command`のdocと同じ理由）。
/// スクリプトはファイルとして外から置き、コンテナはパスだけを受け取る。
const N6_PROBE_JS: &str = r#"
const https = require('https');
const url = process.argv[2];
const req = https.get(url, (res) => { console.log('STATUS=' + res.statusCode); process.exit(0); });
req.on('error', (e) => { console.log('ERR=' + e.message); process.exit(0); });
req.setTimeout(20000, () => { console.log('ERR=timeout'); process.exit(0); });
"#;

const N6_PROBE_PY: &str = r#"
import sys, urllib.request
try:
    with urllib.request.urlopen(sys.argv[1], timeout=20) as r:
        print('STATUS=' + str(r.status))
except Exception as e:
    print('ERR=' + type(e).__name__ + ':' + str(e))
"#;

/// **`python`が✗だったときに、それが「層1を読まない」なのかを確かめる直接の証拠。**
///
/// CPythonの`SSLContext.load_default_certs`はWindowsでは`ssl.enum_certificates("ROOT")`と
/// `("CA")`を引いてそこから信頼ルートを積む。つまり**そこに我々のCAが現れるかどうか**が
/// 分岐点であり、`CERTIFICATE_VERIFY_FAILED`だけでは「ストアを見ていない」のか
/// 「見たが載っていない」のか区別できない（B-29: 症状を性質と読まない）。
///
/// あわせて`ssl`が持ち込む既定の信頼束の件数も出す——`enum_certificates`が
/// **0件や例外**を返しているなら、それは層1の話ではなくこの持ち込みPythonの不備である。
const N6_PROBE_PY_STORE: &str = r#"
import sys, ssl, hashlib
want = sys.argv[1].lower()
for name in ('ROOT', 'CA'):
    try:
        certs = ssl.enum_certificates(name)
        hit = sum(1 for c, enc, trust in certs if hashlib.sha1(c).hexdigest().lower() == want)
        print('%s=%d/hit=%d' % (name, len(certs), hit))
    except Exception as e:
        print('%s=ERR:%r' % (name, e))
"#;

/// **問e: 層1で未測定の6ランタイムは、コンテナ専用ストアに置いたCAを信頼するか。**
///
/// # 外から与えるもの（N2の測定と**同じ契約**。器を作り直さない＝検問7）
///
/// | 環境変数 | 中身 |
/// |---|---|
/// | `HARNESS_TEST_N2_CA_B64` | 本命CAのDER（base64）。コンテナ専用ストアへ置く |
/// | `HARNESS_TEST_N2_CA_THUMB` | 同CAのSHA1拇印（区切り無し） |
/// | `HARNESS_TEST_N2_URL` | 本命サーバのURL（そのCAで署名した証明書を出す） |
/// | `HARNESS_TEST_N2_URL_CONTROL` | 対照サーバのURL（**別CA**で署名した証明書を出す） |
///
/// プロファイル名も[`N2_PROFILE`]をそのまま使う——loopback exemptionは*package SID*に対して
/// 足すもので、SIDはプロファイル名から決定的に導出される。名前を変えると
/// `dev-elevated-run n2-loopback-exemption-add`を撃ち直す羽目になる。
///
/// # loopback exemptionが要る（**要管理者**。測定本体は非昇格）
///
/// ```text
/// target\debug\dev-elevated-run.exe n2-loopback-exemption-add
/// （ここで本テストを非昇格で回す）
/// target\debug\dev-elevated-run.exe n2-loopback-exemption-remove
/// ```
#[test]
#[ignore = "実AppContainer＋loopback exemption＋外で立てたTLSサーバが要る。非昇格・--test-threads=1で走らせること"]
fn n6_do_the_remaining_six_runtimes_trust_the_per_container_store() {
    let ca_b64 = std::env::var("HARNESS_TEST_N2_CA_B64").expect("HARNESS_TEST_N2_CA_B64（本命CAのDER base64）");
    let ca_thumb = std::env::var("HARNESS_TEST_N2_CA_THUMB")
        .expect("HARNESS_TEST_N2_CA_THUMB")
        .trim()
        .to_uppercase();
    let url = std::env::var("HARNESS_TEST_N2_URL").expect("HARNESS_TEST_N2_URL");
    let url_ctrl = std::env::var("HARNESS_TEST_N2_URL_CONTROL").expect("HARNESS_TEST_N2_URL_CONTROL");

    let sid = ensure_profile_for_test(N2_PROFILE).expect("create the N2 AppContainer profile");
    let pkg_sid = crate::win_common::sid_to_string(sid.as_psid()).expect("package SID string");
    eprintln!("[N6-e] profile={N2_PROFILE} package_sid={pkg_sid}");

    // 撤収を、作る前に登録する（B-01）。プロファイル配下（コピーしたexeを含む）は
    // ディレクトリごと消す——`DeleteAppContainerProfile`は`S_OK`を返しながら
    // 何も消さないことがある（`session_profile.rs`の実測）ので、明示的に重ねる。
    let cleanup_sid = pkg_sid.clone();
    let _guard = super::test_support::scopeguard(move || {
        let pkg_dir = format!(
            r"{}\Packages\{N2_PROFILE}",
            std::env::var("LOCALAPPDATA").unwrap_or_default()
        );
        let (out, _, _) = ps_outside(&format!(
            r#"$ErrorActionPreference='SilentlyContinue'
Remove-Item -Path '{pkg_dir}' -Recurse -Force
Write-Output ("LEFT_PKGDIR=" + (Test-Path '{pkg_dir}'))"#
        ));
        eprintln!("[N6-e][プロファイル配下の削除] {out}");
        n2_cleanup(N2_PROFILE, &cleanup_sid);
    });

    // --- 層1を組む（N1-③の最小セット: 双方に`ReadKey`） ----------------------
    n6_setup_layer1(N2_PROFILE, &pkg_sid, &ca_b64, &ca_thumb);

    // --- ランタイムをコンテナが届く場所へ運ぶ ---------------------------------
    let rt = n6_ac_dir(N2_PROFILE, "rt");
    let home = n6_ac_dir(N2_PROFILE, "home");
    std::fs::create_dir_all(&rt).expect("create the AC-side runtime directory");
    std::fs::create_dir_all(&home).expect("create the AC-side home directory");

    // **コンテナに、自分のプロファイルディレクトリを辿らせる。**
    //
    // `CreateAppContainerProfile`がpackage SID宛のACEを付けるのは`AC`配下だけで、
    // その親（`…\Packages\<moniker>`）と`…\Packages`自身には無い。絶対パスでの
    // ファイルopenは（祖先のtraverse capabilityで）通るのに、`Set-Location`は
    // `Access to the path '…\Packages\harness.n2tls' is denied`で落ちる（実測）。
    //
    // **cwdが無いとTLSへ届く前に落ちるランタイムがある**——`git`は`getcwd`で
    // `Unable to read current working directory: Permission denied`、`node`は起動時の
    // `fs.realpathSync`で落ちた。これを「層1を読まない」と記録すればN2-層1の罠Aの再演になる。
    //
    // 付けるのは**非継承のtraverse 1本ずつ**（配下へ配らない）。実マシンに残るのは
    // `…\Packages`の1本だけで、それは下のガードが剥がして数え直す（B-01）。
    let packages_root = std::path::PathBuf::from(format!(
        r"{}\Packages",
        std::env::var("LOCALAPPDATA").expect("LOCALAPPDATA")
    ));
    let profile_dir = packages_root.join(N2_PROFILE);
    const TRAVERSE_MASK: u32 = windows::Win32::Storage::FileSystem::FILE_TRAVERSE.0
        | windows::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES.0;
    let revoke_from = packages_root.clone();
    let revoke_sid = pkg_sid.clone();
    let _traverse_guard = super::test_support::scopeguard(move || {
        // プロファイルディレクトリ側はディレクトリごと消えるので、残るのはここだけ。
        let sid = SidBuf::parse(&revoke_sid);
        match super::revoke_ace(&revoke_from, sid.0) {
            Ok(()) => eprintln!("[N6-e][traverse撤収] {} から剥がした", revoke_from.display()),
            Err(e) => {
                let msg = format!(
                    "traverse ACEが剥がせていない（{} / {revoke_sid}）: {e}。実マシンに残る",
                    revoke_from.display()
                );
                if std::thread::panicking() {
                    eprintln!("[N6-e][!!] {msg}");
                } else {
                    panic!("{msg}");
                }
            }
        }
    });
    for dir in [&packages_root, &profile_dir] {
        super::grant_ace_mask_for_test(
            dir,
            sid.as_psid(),
            TRAVERSE_MASK,
            windows::Win32::Security::NO_INHERITANCE,
        )
        .unwrap_or_else(|e| panic!("{} へのtraverse付与が失敗した: {e}", dir.display()));
    }

    let user = std::env::var("USERPROFILE").expect("USERPROFILE");
    let local = std::env::var("LOCALAPPDATA").expect("LOCALAPPDATA");
    // rustupの**実体**を撃つ（`~/.cargo/bin/cargo.exe`はrustupのプロキシで、
    // `~/.rustup`配下へ辿り着けないコンテナの中では起動できない）。
    let real_cargo = format!(r"{user}\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin\cargo.exe");
    let py_src = format!(r"{local}\Programs\Python\Python313");

    for (src, dst) in [
        (r"C:\Program Files\nodejs\node.exe".to_string(), "node.exe"),
        (format!(r"{user}\.local\bin\uv.exe"), "uv.exe"),
        (real_cargo.clone(), "cargo.exe"),
    ] {
        assert!(
            Path::new(&src).exists(),
            "コピー元が無い: {src}（この機の構成が測定の前提と違う）"
        );
        std::fs::copy(&src, rt.join(dst))
            .unwrap_or_else(|e| panic!("{src} を {} へコピーできない: {e}", rt.display()));
    }

    // Pythonだけは単体exeでは動かない（`python313.dll`・`Lib`・`DLLs`が要る）。
    // **`Lib\site-packages`（158MB）と`Lib\test`は写さない**——`urllib.request`と`ssl`に
    // 要らず、写す量が1桁変わる。
    let py_dst = rt.join("py");
    std::fs::create_dir_all(&py_dst).expect("create the AC-side python directory");
    let (rc_out, rc_err, _) = ps_outside(&format!(
        r#"$ErrorActionPreference = 'Continue'
$src = '{py_src}'
$dst = '{}'
& robocopy.exe $src $dst python.exe pythonw.exe python313.dll python3.dll vcruntime140.dll vcruntime140_1.dll /NJH /NJS /NP /NFL /NDL | Out-Null
& robocopy.exe (Join-Path $src 'DLLs') (Join-Path $dst 'DLLs') /E /NJH /NJS /NP /NFL /NDL | Out-Null
& robocopy.exe (Join-Path $src 'Lib') (Join-Path $dst 'Lib') /E /XD site-packages test idlelib tkinter /NJH /NJS /NP /NFL /NDL | Out-Null
Write-Output ("PY_EXE=" + (Test-Path (Join-Path $dst 'python.exe')))
Write-Output ("PY_SSL=" + (Test-Path (Join-Path $dst 'Lib\ssl.py')))
Write-Output ("PY_SSLPYD=" + (Test-Path (Join-Path $dst 'DLLs\_ssl.pyd')))"#,
        py_dst.display()
    ));
    eprintln!("[N6-e][pythonの持ち込み]\n{rc_out}{rc_err}");
    for key in ["PY_EXE", "PY_SSL", "PY_SSLPYD"] {
        assert_eq!(
            kv(&rc_out, key).as_deref(),
            Some("True"),
            "pythonの持ち込みが不完全（{key}）。この状態の失敗は層1の可否を意味しない:\n{rc_out}"
        );
    }

    // 外の対照用の作業領域（**`AC`配下は外から読めない**ので別に要る。[`N6Runtime::exe_out`]）。
    let out_rt = std::env::temp_dir().join(format!("n6-outside-{}", std::process::id()));
    std::fs::create_dir_all(&out_rt).expect("create the outside-control directory");
    let out_rt_guard = out_rt.clone();
    let _out_guard = super::test_support::scopeguard(move || {
        let _ = std::fs::remove_dir_all(&out_rt_guard);
    });
    for dir in [&rt, &out_rt] {
        std::fs::write(dir.join("probe.js"), N6_PROBE_JS).expect("write probe.js");
        std::fs::write(dir.join("probe.py"), N6_PROBE_PY).expect("write probe.py");
        std::fs::write(dir.join("probe_store.py"), N6_PROBE_PY_STORE)
            .expect("write probe_store.py");
    }

    let py_exe = py_dst.join("python.exe").to_string_lossy().into_owned();
    let py_real = format!(r"{py_src}\python.exe");
    // 変種を持たないランタイムでも、表の形を揃えるために既定の1件だけは置く。
    const PLAIN: &[(&str, &str, &str)] = &[("既定", "default", "")];
    let runtimes: Vec<N6Runtime> = vec![
        N6Runtime {
            name: "cargo",
            exe_in: rt.join("cargo.exe").to_string_lossy().into_owned(),
            exe_out: real_cargo.clone(),
            command: r#"
$env:CARGO_HOME = '%%HOME%%\cargo'
$env:CARGO_HTTP_CHECK_REVOKE = '%%EXTRA%%'
$env:CARGO_REGISTRIES_N6_INDEX = 'sparse+%%URL%%/index/'
(& '%%EXE%%' search hello --registry n6 2>&1)
"#,
            variants: &[
                ("失効確認あり", "revoke-on", "true"),
                ("失効確認オフ", "revoke-off", "false"),
            ],
            lines: 14,
        },
        N6Runtime {
            name: "git",
            exe_in: r"C:\Program Files\Git\cmd\git.exe".to_string(),
            exe_out: r"C:\Program Files\Git\cmd\git.exe".to_string(),
            // **cwdを変種にしてある。** `git`はコンテナの中では`getcwd`が
            // `Unable to read current working directory: Permission denied`で落ち、
            // **TLSへ1バイトも届かない**（`C:\Windows\System32`でもAC配下でも同じだった）。
            // Git for Windowsの`mingw_getcwd`はcwdのディレクトリハンドルを開いて
            // `GetFinalPathNameByHandleW`まで通すので、単なる実行権限では足りない。
            // どのcwdなら通るのかを**測って**決める——通るものが1つも無ければ、
            // `git`の行は「✗」ではなく**測定不能**である（N2-層1の罠A）。
            command: r#"
$env:HOME = '%%HOME%%'
$env:GIT_TERMINAL_PROMPT = '0'
Set-Location '%%EXTRA%%'
(& '%%EXE%%' ls-remote '%%URL%%/x.git' 2>&1)
"#,
            variants: &[
                ("cwd=AC配下", "cwd-ac", "%%HOME%%"),
                ("cwd=System32", "cwd-sys32", r"C:\Windows\System32"),
                ("cwd=Gitの配布先", "cwd-git", r"C:\Program Files\Git"),
            ],
            lines: 3,
        },
        N6Runtime {
            name: "node",
            exe_in: rt.join("node.exe").to_string_lossy().into_owned(),
            exe_out: r"C:\Program Files\nodejs\node.exe".to_string(),
            command: r#"
(& '%%EXE%%' %%EXTRA%% '%%RT%%\probe.js' '%%URL%%' 2>&1)
"#,
            // Node 25は既定で**同梱のCA束**を見る（実測: 既定の失敗メッセージ自身が
            // `try running Node.js with --use-system-ca`と言う）。`uv`の`UV_NATIVE_TLS`と
            // 同じ形なので、**既定とOSストア併用の両方**を並べる。
            variants: &[
                ("既定(同梱CA束)", "default", ""),
                ("--use-system-ca", "system-ca", "--use-system-ca"),
            ],
            lines: 3,
        },
        N6Runtime {
            name: "python",
            exe_in: py_exe.clone(),
            exe_out: py_real.clone(),
            command: r#"
(& '%%EXE%%' '%%RT%%\probe.py' '%%URL%%' 2>&1)
"#,
            variants: PLAIN,
            lines: 3,
        },
        N6Runtime {
            // **`python`が✗のとき用の直接証拠**（[`N6_PROBE_PY_STORE`]）。URLは使わないので
            // 本命／対照で同じ結果になるのが正しい——ここで見たいのは
            // 「Pythonのストア列挙に我々のCAが現れるか」だけである。
            name: "python-store",
            exe_in: py_exe.clone(),
            exe_out: py_real.clone(),
            command: r#"
(& '%%EXE%%' '%%RT%%\probe_store.py' '%%CA_THUMB%%' 2>&1)
"#,
            variants: PLAIN,
            lines: 3,
        },
        N6Runtime {
            name: "uv",
            exe_in: rt.join("uv.exe").to_string_lossy().into_owned(),
            exe_out: format!(r"{user}\.local\bin\uv.exe"),
            command: r#"
$env:UV_CACHE_DIR = '%%HOME%%\uvcache'
$env:UV_NATIVE_TLS = '%%EXTRA%%'
(& '%%EXE%%' pip install --dry-run --python '%%PY%%' --index-url '%%URL%%/simple' harness-n6-absent 2>&1)
"#,
            // N2節: `uv`の既定の信頼ルートはバイナリ同梱の`webpki-roots`で、
            // `UV_NATIVE_TLS=true`で初めてシステムストアを見る。**どちらの話かを混ぜない。**
            variants: &[
                ("既定(webpki-roots)", "webpki", "false"),
                ("UV_NATIVE_TLS=true", "native-tls", "true"),
            ],
            lines: 8,
        },
        N6Runtime {
            name: "mingw64-curl",
            exe_in: r"C:\Program Files\Git\mingw64\bin\curl.exe".to_string(),
            exe_out: r"C:\Program Files\Git\mingw64\bin\curl.exe".to_string(),
            command: r#"
(& '%%EXE%%' -sS -m 20 %%EXTRA%% -o NUL -w 'http=%{http_code}' '%%URL%%' 2>&1)
"#,
            variants: &[
                ("失効確認あり", "revoke-on", ""),
                ("失効確認オフ", "revoke-off", "--ssl-no-revoke"),
            ],
            lines: 3,
        },
        N6Runtime {
            // **許可側の対照**（B-35）。6行が全部✗で終わったとき、それが「層1を読まない
            // 6つ」なのか「この実行ではサーバも証明書もexemptionも壊れていた」のかは、
            // 禁止側だけを見ていては決められない。**層1を読むと分かっている唯一の相手**
            // （N2-層1で実測: `Invoke-WebRequest`＝.NET）を同じコンテナ・同じサーバへ
            // 同じ実行の中で撃ち、ここが`200`にならなければ実行全体を無効として落とす。
            //
            // **失敗したときに理由まで出す。** `Invoke-WebRequest`は
            // `The SSL connection could not be established, see inner exception.`しか出さず、
            // それだけでは「CAが信頼されていない」のか「失効確認で落ちた」のか
            // 「そもそも繋がっていない」のか分けられない（B-29）。そこで
            // (1) 内側の例外を最後まで辿り、(2) `SslStream`を自前で張って
            // **検証コールバックが受け取る`SslPolicyErrors`と`ChainStatus`**を覗く。
            // コールバックは常に`$true`を返す——ここで見たいのは可否ではなく**理由**である。
            name: "iwr-control",
            exe_in: String::new(),
            exe_out: String::new(),
            command: r#"
$u = [Uri]'%%URL%%'
$out = @()
try { $out += 'IWR=' + (Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 20).StatusCode }
catch {
    $x = $_.Exception; $m = @()
    while ($x) { $m += ($x.GetType().Name + ':' + $x.Message); $x = $x.InnerException }
    $out += 'IWR=' + ($m -join ' <- ')
}
$script:seen = 'callback-not-invoked'
try {
    $tcp = New-Object System.Net.Sockets.TcpClient($u.Host, $u.Port)
    $cb = [System.Net.Security.RemoteCertificateValidationCallback] {
        param($snd, $cert, $chain, $errors)
        $st = ($chain.ChainStatus | ForEach-Object { $_.Status }) -join '+'
        if ($st -eq '') { $st = 'NoError' }
        $script:seen = "policyErrors=$errors chainStatus=$st subject=" + $cert.Subject
        return $true
    }
    $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $cb)
    $ssl.AuthenticateAsClient($u.Host)
    $out += 'SSLSTREAM=ok'
    $ssl.Dispose(); $tcp.Close()
} catch { $out += 'SSLSTREAM=EXC:' + $_.Exception.Message }
$out += 'VERDICT=' + $script:seen
$out -join ' | '
"#,
            variants: PLAIN,
            lines: 2,
        },
    ];

    // --- 中／外で撃つスクリプトを組む -----------------------------------------
    //
    // **前提の自己確認を先頭に置く**——層1が中から見えていなければ、以下の結果は
    // 「層1の可否」を意味しない（測定が成立していない）。
    //
    // **`Set-Location`を必ず打つ**。既定のcwdは`C:\Windows\System32`で、そこは
    // AppContainerから*実行*はできても`getcwd`相当が通らない——最初の測定では
    // `git`が`Unable to read current working directory: Permission denied`、
    // `node`が`fs.lstat`でTLSへ届く前に落ちていた。**これをそのまま「層1を読まない」と
    // 記録すれば、N2-層1の罠A（1つの否定を2回数える）をそっくり繰り返すことになる。**
    let build_script = |p: &N6Paths, exe_of: &dyn Fn(&N6Runtime) -> String| -> String {
        let mut s = format!(
            r#"$ErrorActionPreference = 'Continue'
function Say($k, $v) {{ Write-Output ("$k=" + (($v -as [string]) -replace '\s+', ' ')) }}
function Try1($k, $block) {{ try {{ Say $k (& $block) }} catch {{ Say $k ("EXCEPTION:" + $_.Exception.Message) }} }}
Try1 'CWD' {{ Set-Location '{home}'; (Get-Location).Path }}
Try1 'STORE_COUNT' {{
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser')
    $s.Open('ReadOnly'); $n = $s.Certificates.Count; $s.Close(); $n
}}
Try1 'STORE_HAS_CA' {{
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser')
    $s.Open('ReadOnly')
    $hit = @($s.Certificates | Where-Object {{ $_.Thumbprint -eq '%%CA_THUMB%%' }}).Count
    $s.Close(); $hit
}}
"#,
            home = p.home
        );
        for r in &runtimes {
            for (_vlabel, vid, extra) in r.variants {
                // **対照（別CAのサーバ）を同じ実行に必ず含める**——対照が証明書エラーに
                // ならなければ、本命の結果は「層1を読んだ」の証拠にならない（B-35）。
                for (which, url_ph) in [("main", "%%URL_MAIN%%"), ("ctrl", "%%URL_CTRL%%")] {
                    // **`%%EXTRA%%`を最初に埋める。** 変種の値そのものが`%%HOME%%`のような
                    // 別のプレースホルダを含むことがある（`git`のcwd変種）ので、
                    // 後続の置換に拾わせる必要がある。
                    let body = r
                        .command
                        .replace("%%EXTRA%%", extra)
                        .replace("%%EXE%%", &exe_of(r))
                        .replace("%%URL%%", url_ph)
                        .replace("%%RT%%", &p.rt)
                        .replace("%%PY%%", &p.py)
                        .replace("%%HOME%%", &p.home);
                    // **`$( )`であって`( )`ではない。** 丸括弧のグルーピングは
                    // パイプライン1本しか取れないので、環境変数の設定行を前に持つ
                    // `cargo`・`git`・`uv`の本体を入れると構文エラーになり、
                    // **スクリプトが1行も出力しないまま終わる**（実測）。
                    s.push_str(&format!(
                        "Try1 'RT:{}:{vid}:{which}' {{ ($({body}) | Select-Object -First {}) -join ' | ' }}\n",
                        r.name, r.lines
                    ));
                }
            }
        }
        s.push_str("Say 'DONE' '1'\n");
        s.replace("%%URL_MAIN%%", &url)
            .replace("%%URL_CTRL%%", &url_ctrl)
            .replace("%%CA_THUMB%%", &ca_thumb)
    };

    let inside_script = build_script(
        &N6Paths {
            rt: rt.to_string_lossy().into_owned(),
            home: home.to_string_lossy().into_owned(),
            py: py_exe.clone(),
        },
        &|r| r.exe_in.clone(),
    );
    let outside_script = build_script(
        &N6Paths {
            rt: out_rt.to_string_lossy().into_owned(),
            home: out_rt.to_string_lossy().into_owned(),
            py: py_real.clone(),
        },
        &|r| r.exe_out.clone(),
    );

    // --- 外でも同じことを回して対照にする（B-29） -----------------------------
    // **外はCAをどこにも持たない**ので本命側も失敗するのが正しい。外の役目は
    // 「サーバが生きている・そのコマンドがそもそもTLSまで届く」ことの確認である。
    let (outside, _, _) = ps_outside(&outside_script);
    eprintln!("[N6-e][外（通常トークン・CA無し）]\n{outside}");

    let (inside, inside_err, inside_code) =
        ps_in_container_with_net(sid.as_psid(), &inside_script, NetworkCapability::InternetClient);
    eprintln!("[N6-e][中（AppContainer）] exit={inside_code}\n{inside}\n--- stderr ---\n{inside_err}");

    eprintln!("\n[N6][**まとめ: 問e**] 層1にCAを置いたコンテナの中から");
    eprintln!(
        "  前提: 中のCurrentUser\\Root={} 件 / そこに置いたCAが在るか={} / cwd={}",
        kv(&inside, "STORE_COUNT").unwrap_or_default(),
        kv(&inside, "STORE_HAS_CA").unwrap_or_default(),
        kv(&inside, "CWD").unwrap_or_default(),
    );
    for r in &runtimes {
        eprintln!("  ── {} ──", r.name);
        for (vlabel, vid, _) in r.variants {
            for (which, label) in [
                ("main", "本命（層1にCAあり）      "),
                ("ctrl", "対照（別CA・置いていない）"),
            ] {
                let key = format!("RT:{}:{vid}:{which}", r.name);
                eprintln!("      [{vlabel}] {label} 中= {}", kv(&inside, &key).unwrap_or_default());
                eprintln!(
                    "      [{vlabel}] {label} 外= {}",
                    kv(&outside, &key).unwrap_or_default()
                );
            }
        }
    }

    assert_eq!(
        kv(&inside, "DONE").as_deref(),
        Some("1"),
        "コンテナ内の観測スクリプトが最後まで走っていない:\n{inside}"
    );
    // 測定が成立していることだけをここで固定する。各ランタイムの可否は上の出力を人が
    // 読んで表へ写す——`http=200`以外にも「TLSは通ったがアプリ層で落ちた」形があり、
    // 機械的な合否に潰すと情報が消える（N2節と同じ規準）。
    assert_eq!(
        kv(&inside, "STORE_HAS_CA").as_deref(),
        Some("1"),
        "層1が中から見えていない。この実行の結果は各ランタイムの可否を意味しない:\n{inside}"
    );
    // **許可側の対照**（B-35）。ここが200でなければ、6行の✗は「層1を読まない」ではなく
    // 「この実行のサーバ／証明書／exemptionが壊れていた」かもしれない。
    //
    // 値は`IWR=200 | SSLSTREAM=ok | VERDICT=…`という診断付きの1行なので**部分一致で見る**
    // （完全一致にすると、診断を足した瞬間に対照が「壊れた」ことになる）。
    let iwr_main = kv(&inside, "RT:iwr-control:default:main").unwrap_or_default();
    let iwr_ctrl = kv(&inside, "RT:iwr-control:default:ctrl").unwrap_or_default();
    assert!(
        iwr_main.contains("IWR=200"),
        "許可側の対照（Invoke-WebRequest）が200を返していない。層1を読むと分かっている\
         唯一の相手が通らないなら、この実行の測定は無効である:\n  main={iwr_main}\n{inside}"
    );
    assert!(
        !iwr_ctrl.contains("IWR=200"),
        "**対照サーバ（別CA・置いていない）まで200になっている。** 何かが無条件に信頼\
         されており、本命の200は層1の証拠にならない:\n  ctrl={iwr_ctrl}\n{inside}"
    );
}
