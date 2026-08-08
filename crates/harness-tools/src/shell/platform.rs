//! プラットフォームのシェルそのものと話す層——どの実行ファイルを起動するか、stdinへ何を流すか、
//! 子が返したバイト列をどう文字へ戻すか、そしてシェル自身が出したノイズをどこで切るか。
//!
//! `docs/CODE-STRUCTURE-RULES.md`規則3の軸1（どの外部システムと話すか）で`shell.rs`から
//! 切り出した。Tierごとの隔離機構は`super::runner`が扱い、ここは**Tierに依らずシェル共通**の
//! ものだけを持つ——だからこそ Tier0/Tier1/Tier2a とポリシーエディタの記録モード2つ
//! （パス1＝Tier1でのFS記録、パス2＝Tier2aでのドメイン記録）の**5経路**がこの1箇所を
//! 共有できる（個別に実装して綴りが食い違うことを防ぐ、B-05）。

use tokio::process::Command;

/// 起動する子プロセスコマンドと、記録用のシェルラベル・stdin経由で渡すブートストラップ・
/// 追加env（Windowsのみ使用）をまとめたもの。
pub(crate) struct ShellInvocation {
    pub(crate) cmd: Command,
    pub(crate) stdin_payload: Option<Vec<u8>>,
    pub(crate) shell_label: &'static str,
    /// BUG-050: コマンド本体を運ぶ追加env（Windowsのみ）。呼び出し元が`env`へ追加してから
    /// spawnする（`git_hardening_env()`と同じ、既存の`env`可変配列に足すだけのパターン）。
    pub(crate) extra_env: Option<(&'static str, String)>,
}

/// Unixは`sh -c <command>`（argvの1要素として渡るためWindowsの`-Command`文字列補間問題は無い）。
#[cfg(not(windows))]
pub(crate) fn platform_shell_command(command: &str) -> ShellInvocation {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(command);
    ShellInvocation {
        cmd,
        stdin_payload: None,
        shell_label: "sh",
        extra_env: None,
    }
}

/// Windowsはpwsh7優先→Windows PowerShell 5.1フォールバック。コマンド文字列はargvへも
/// stdinスクリプトへも埋め込まず、**env経由**で渡す（BUG-050、§ツールシステム run_shell
/// 「シェル選択」）。stdinへ書くのは`RUN_SHELL_BOOTSTRAP_SCRIPT`という固定の純ASCII文字列
/// だけで、コマンドの中身に一切依存しない。
#[cfg(windows)]
pub(crate) fn platform_shell_command(command: &str) -> ShellInvocation {
    let (bin, shell_label) = if which::which("pwsh").is_ok() {
        ("pwsh", "pwsh")
    } else {
        ("powershell", "powershell5.1")
    };
    let mut cmd = Command::new(bin);
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", "-"]);
    ShellInvocation {
        cmd,
        stdin_payload: Some(run_shell_bootstrap_stdin()),
        shell_label,
        extra_env: Some((RUN_SHELL_COMMAND_ENV_VAR, command.to_string())),
    }
}

/// BUG-050: コマンド本体を運ぶenv変数名。`CreateProcessW`の環境ブロック（UTF-16、
/// `win_common::build_env_block`）を経由するため、CP932等のANSIコードページでは表現できない
/// 文字（絵文字・ハングル・非BMP等）も無損失で子へ渡る。読み取り後は
/// `RUN_SHELL_BOOTSTRAP_SCRIPT`内で`Remove-Item Env:`により孫プロセスへの継承を絶つ。
///
/// **`pub`である理由**: ポリシーエディタの記録モード（`harness-policy-editor`）が
/// Tier1でコマンドを走らせる4番目の経路になるため。複製すると綴りが静かにずれる（B-05）。
#[cfg(windows)]
pub const RUN_SHELL_COMMAND_ENV_VAR: &str = "HARNESS_RUN_SHELL_COMMAND";

/// BUG-049/BUG-050: `-Command -`（stdin経由）で流すブートストラップ。**内容はコマンドに
/// 依存しない固定の純ASCII文字列**であり、これがstdinの符号化問題（BUG-049修正が
/// `WideCharToMultiByte`のベストフィット変換で持ち込んだ検査回避＝BUG-050の根本原因）を
/// 完全に消し去る——stdinへ非ASCIIバイトが一切乗らないため、コードページ変換自体が
/// 不要になる。
///
/// コマンド本体は`RUN_SHELL_COMMAND_ENV_VAR`からenv経由で読み、`[scriptblock]::Create`で
/// 実行する。**判定用の元コマンドは一切変更しない**: `classify_net_app`等の危険構文検査は
/// 呼び出し元で元の`command`文字列に対して行い（`super::net_decision::classify_net_app`・
/// `harness-engine::permission::looks_like_allowlist_bypass`）、このブートストラップは
/// 検査結果とは独立に常に同じ内容で送られる。
///
/// 実測（Windows PowerShell 5.1・pwsh 7.6.4、`CREATE_NO_WINDOW`下）:
/// 絵文字・非BMP文字（`𠮷`）・複合文字（`が`）を含むコマンド、日本語ファイル名の作成・削除、
/// いずれもバイト完全一致で往復する。ベストフィット変換の検体（`¦`→`|`）も`¦`のまま保たれる。
///
/// また、`-Command -`（stdin経由）実行の終了コードはPowerShellプロセス自身の終了コードで
/// あり、スクリプトが明示的に`exit`しない限り**最後の文（statement）の成否からブール化
/// （0/1）されるだけ**で、ネイティブコマンドの実際の終了コード（例: `7`）は失われる
/// （Phase5-H実測）。末尾の`$LASTEXITCODE`/`$?`判定で、bashの`sh -c`と同じ「最後のコマンドの
/// 終了状態」意味論に揃える。
///
/// Tier0（本関数の呼び出し元`platform_shell_command`）・Tier2a（`run_windows_tier2a`）・
/// Tier1（`run_windows_tier1`）・ポリシーエディタのパス1
/// （`harness_policy_editor::record`、Tier1で対象コマンドを走らせる）・同パス2
/// （`harness_policy_editor::record_net`、Tier2aで走らせる）の**5経路全て**が
/// この1関数を通す（Tier横断で1箇所に集約し、個別に実装して食い違うことを防ぐ）。
#[cfg(windows)]
pub(crate) const RUN_SHELL_BOOTSTRAP_SCRIPT: &str = "\
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; \
$OutputEncoding = [System.Text.Encoding]::UTF8; \
Write-Output '<<<harness-run-shell-begin>>>'; \
[Console]::Error.WriteLine('<<<harness-run-shell-begin>>>'); \
$__harness_cmd = $env:HARNESS_RUN_SHELL_COMMAND; \
Remove-Item Env:HARNESS_RUN_SHELL_COMMAND -ErrorAction SilentlyContinue; \
. ([scriptblock]::Create($__harness_cmd)); \
if ($LASTEXITCODE) { exit $LASTEXITCODE } elseif (-not $?) { exit 1 }
";

/// シェル自身が**コマンドを走らせる前に**吐いた出力と、コマンドの出力を分ける境界印。
///
/// # なぜ要るか
///
/// PowerShellは起動時にプロファイル読込・プロバイダ初期化を行い、そこで出た警告が
/// コマンドの出力と同じストリームに混ざる。混ざると、標準出力を持たないコマンド
/// （`echo hoge > test.txt` のようなリダイレクト）では**シェルの警告だけが唯一の出力**になり、
/// コマンドが失敗したように見える（モデルは実際にリトライループへ入った）。
///
/// 実例: このマシンにはSMBマップドライブ（`X:`/`Z:`）があり、AppContainerの子で
/// PowerShellの`FileSystemProvider.InitializeDefaultDrives()`がそれを解決しようとして
/// `\PIPE\wkssvc`・`\PIPE\DAV RPC SERVICE`を開き、両パイプのDACLにapp-package系ACEが
/// 無いため`ACCESS_DENIED`になる。ドライブを外すと消えることを1差分実験で確認済み。
/// **コマンド自体は成功している**——この警告は起動時ノイズでしかない。
///
/// # なぜ文字列マッチではなく境界印か
///
/// 上のメッセージは**OSのロケールで翻訳される**（この機では日本語）。既知の文言を
/// マッチして消す実装は英語環境で素通りし、逆に別の言語では健全な出力を巻き込み得る
/// （`bug-pattern-rules` B-05: 型で守れない複製、B-21: 検査と実体の乖離）。境界印なら
/// ロケールにも文言にも依存せず、**このノイズだけでなくプロファイル由来の出力等にも効く**。
///
/// # 消さない
///
/// 印より前の出力は捨てず、`[shell-startup-noise: ...]`として別枠で見せる。サンドボックスが
/// 何を拒否したかは診断の材料であり、黙って落とすと将来の調査不能地帯になる（B-10）。
///
/// 印が見つからない場合（Unix・Tier3・シェルが印に到達する前に死んだ場合）は
/// **全部をコマンドの出力として扱う**——安全側（隠さない側）へ倒す。
///
/// **`pub`である理由**: ポリシーエディタの記録モードは出力を**行単位でストリーミング**
/// するため、`split_shell_startup_noise`（全文が揃ってから切る）をそのままは使えない。
/// 印そのものを共有して、切り方だけを各自の形に合わせる（B-05: 印の綴りは複製しない）。
#[cfg(windows)]
pub const RUN_SHELL_OUTPUT_SENTINEL: &str = "<<<harness-run-shell-begin>>>";

/// 境界印で「シェル起動時ノイズ」と「コマンドの出力」に分ける。戻り値は`(noise, output)`。
///
/// 印は**最初の1つ**で切る。コマンドが同じ文字列を出力しても、それは印より後なので
/// 分割位置は動かない（＝コマンド側から分割位置を操作できない）。
#[cfg(windows)]
pub(crate) fn split_shell_startup_noise(text: &str) -> (String, String) {
    let Some(start) = text.find(RUN_SHELL_OUTPUT_SENTINEL) else {
        return (String::new(), text.to_string());
    };
    let noise = text[..start].trim().to_string();
    let rest = &text[start + RUN_SHELL_OUTPUT_SENTINEL.len()..];
    (noise, rest.trim_start_matches(['\r', '\n']).to_string())
}

#[cfg(not(windows))]
pub(crate) fn split_shell_startup_noise(text: &str) -> (String, String) {
    (String::new(), text.to_string())
}

/// stdout側とstderr側のノイズを1つにまとめる（どちらも空なら`None`＝フッター行を出さない）。
///
/// PowerShellのプロバイダ初期化エラーがどちらのストリームへ出るかはホストの実装依存で、
/// 実測でも両方あり得る。**同じ文言が両方に出たら1回だけ見せる**——2回出すと、
/// 起きたことが2つあるように読める。
pub(crate) fn merge_startup_noise(out_noise: &str, err_noise: &str) -> Option<String> {
    match (out_noise.trim(), err_noise.trim()) {
        ("", "") => None,
        ("", e) => Some(e.to_string()),
        (o, "") => Some(o.to_string()),
        (o, e) if o == e => Some(o.to_string()),
        (o, e) => Some(format!("{o}\n{e}")),
    }
}

/// ブートストラップをstdinへ流すためのバイト列。**Tier横断の4経路が共有する**
/// （このdocの上にある`RUN_SHELL_BOOTSTRAP_SCRIPT`の最終段落を参照）。
#[cfg(windows)]
pub fn run_shell_bootstrap_stdin() -> Vec<u8> {
    debug_assert!(
        RUN_SHELL_BOOTSTRAP_SCRIPT.is_ascii(),
        "BUG-050: bootstrap must stay pure ASCII so no code-page conversion is ever needed"
    );
    RUN_SHELL_BOOTSTRAP_SCRIPT.as_bytes().to_vec()
}

/// BUG-051: Tier0（本関数）・Tier1・Tier2aが共通で使う出力デコーダ。Windowsでは
/// `harness_sandbox::decode_console_bytes`（起動直後のANSIコードページ由来のメッセージと
/// ブートストラップ適用後のUTF-8が同一ストリーム内で混在し得ることへの対処、`win_common`の
/// doc参照）を通す。Unix（`sh -c`）にはこの種の混在は無いため`from_utf8_lossy`のまま。
pub(crate) fn decode_console_output(bytes: &[u8]) -> String {
    #[cfg(windows)]
    {
        harness_sandbox::decode_console_bytes(bytes)
    }
    #[cfg(not(windows))]
    {
        String::from_utf8_lossy(bytes).into_owned()
    }
}
