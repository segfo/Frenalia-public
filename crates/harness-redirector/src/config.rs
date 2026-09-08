//! 親プロセスから渡される`Config`のシリアライズ/デシリアライズと、デバッグログ。
//!
//! 設定は`CreateRemoteThread`の引数として注入先プロセスのメモリへ書き込まれた
//! テキストblobとして届く（`inject`参照）。

use super::*;

pub(crate) fn get_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

/// 注入パラメータ（`harness_cow_init`の引数）で運ぶ設定のバイト列上限。実際の中身は
/// 3行のパス文字列なので通常は数百バイトで、この上限は「NUL終端が壊れていた場合に
/// 無限に読み進めない」ための安全弁。
pub(crate) const CONFIG_BLOB_MAX_LEN: usize = 64 * 1024;

/// [段階5b] **プロセス生成フックを置くこと自体を目的に注入した**ことを子へ伝える環境変数。
///
/// 直接の子はこの env からしか設定を受け取れない（[`super::init::init`]のdoc:
/// `inject_redirector`は`LoadLibraryW`しか呼ばず、設定blobを渡すのは孫への再注入だけ）。
/// **`HARNESS_COW_WORKSPACE`では代用できない**——MCPサーバにはワークスペースが無い。
pub(crate) const PROCESS_HOOKS_ENV: &str = "HARNESS_REDIRECTOR_PROCESS_HOOKS";

/// [`PROCESS_HOOKS_ENV`]の値を読む。**無効を意味する綴りだけを見る**のではなく、
/// **有効を意味する綴りだけを見る**——この変数は「立てたら真」であって、
/// 未設定が既定（偽）だからである（`lazy_grant::lane()`とは向きが逆で、
/// あちらは既定が有効なので無効側の綴りを見る）。
pub(crate) fn process_hooks_from_env() -> bool {
    get_env(PROCESS_HOOKS_ENV).is_some_and(|v| !matches!(v.trim(), "0" | "false" | "off"))
}

/// 注入パラメータで運ぶ設定のシリアライズ（BUG-045のF2）。`\n`区切り5行・NUL終端のUTF-8:
///
/// ```text
/// <workspace_root>\n<diff_layer_dir>\n<ext_capture_roots を ';' で連結>\n<broker_pipe>\n<process_hooks>\0
/// ```
///
/// 環境変数（`HARNESS_COW_*`・`HARNESS_LAZY_BROKER_PIPE`）と等価な情報を、
/// **子孫プロセスのenv blockに依存せずに**渡すための唯一の形式。途中の世代が自前の
/// env blockを組み立てて子を起動しても設定が途切れないようにする
/// （モジュールdoc「設定の伝播」参照）。
///
/// # `cow_enabled`を載せない理由
///
/// **`diff_layer_dir`が空かどうかで決まる**ので、独立した値として運ぶと**2つの真実**に
/// なる（`B-13`）。片方だけ書き換わった blob は「CoWを名乗るのに差分層が無い」という
/// 復元不能な状態になり得るので、導出できるものは導出する。
///
/// # 行を足したときの後方互換
///
/// 足りない行は空として読む。4行目（fault受付）が無ければfault-in無し、5行目
/// （プロセス生成フック）が無ければ**そのフックのためだけの注入ではない**と読む。
/// **壊れるのではなく、機能が1つ無いだけ**に倒してある。
pub(crate) fn serialize_config_blob(cfg: &Config) -> Vec<u8> {
    let ext = cfg
        .ext_capture_roots
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(";");
    let mut bytes = format!(
        "{}\n{}\n{}\n{}\n{}",
        cfg.workspace_root.to_string_lossy(),
        cfg.diff_layer_dir.to_string_lossy(),
        ext,
        cfg.broker_pipe.as_deref().unwrap_or(""),
        if cfg.process_hooks { "1" } else { "" }
    )
    .into_bytes();
    bytes.push(0);
    bytes
}

/// [`serialize_config_blob`]の逆。自プロセス内のNUL終端バイト列を指すポインタから設定を復元する。
///
/// # Safety
/// `param`はNULLか、自プロセスで読み取り可能なNUL終端バイト列の先頭でなければならない
/// （注入側が`VirtualAllocEx`+`WriteProcessMemory`で書き込んだ領域）。
pub(crate) unsafe fn deserialize_config_blob(param: *const u8) -> Option<Config> {
    if param.is_null() {
        return None;
    }
    let mut len = 0usize;
    while len < CONFIG_BLOB_MAX_LEN {
        if unsafe { *param.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    if len == 0 || len >= CONFIG_BLOB_MAX_LEN {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(param, len) };
    parse_config_blob(&String::from_utf8_lossy(bytes))
}

/// 復元のうち文字列解析だけを切り出した部分（単体テスト可能にするため）。
pub(crate) fn parse_config_blob(text: &str) -> Option<Config> {
    let mut lines = text.split('\n');
    // [段階5b] **ワークスペースは空でもよくなった**（MCPサーバには無い）。ただし
    // 空を許すのはプロセス生成フックだけを理由に注入したときで、CoWの誘導とfault受付は
    // どちらも「workspace内か」の判定を要るので、下の検査で弾く。
    let workspace_root = lines.next().unwrap_or("");
    // [D-88] **差分層は空でもよい**（DirectRwのlazyレーンには差分層が無い）。
    // 空なら`cow_enabled`が偽になり、誘導の枝は1つも通らない。
    let diff_layer_dir = lines.next().unwrap_or("");
    let ext_capture_roots = lines
        .next()
        .unwrap_or("")
        .split(';')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect();
    let broker_pipe = lines.next().unwrap_or("").trim_end_matches('\0');
    // [段階5b] 5行目。古い世代のblobには無いので、空＝偽として読む。
    let process_hooks = !lines.next().unwrap_or("").trim_end_matches('\0').is_empty();
    let cow_enabled = !diff_layer_dir.is_empty();
    // CoWでもなく受付もフックの要求も無いなら、このDLLがやることは1つも無い。
    // **成功したことにしない**——何もしないフックが設置された状態は、
    // 原因のたどりにくい遅さとして残る。
    if !cow_enabled && broker_pipe.is_empty() && !process_hooks {
        return None;
    }
    // 誘導も受付も「workspace内か」を判定するので、**ワークスペースが分からないまま
    // その2つを名乗るblobは受け取らない**（BUG-066: 判定が全部外れると、
    // 「workspace外への書込が拒否された」ように見える形で全部が壊れる）。
    if workspace_root.is_empty() && (cow_enabled || !broker_pipe.is_empty()) {
        return None;
    }
    Some(Config {
        workspace_root: PathBuf::from(workspace_root),
        diff_layer_dir: PathBuf::from(diff_layer_dir),
        cow_enabled,
        broker_pipe: (!broker_pipe.is_empty()).then(|| broker_pipe.to_string()),
        ext_capture_roots,
        process_hooks,
    })
}

/// BUG-033調査用の診断計装（`docs/bugs/BUG-033.md`参照、再発時の再調査用に残置）。
/// releaseビルドでは`cfg!(debug_assertions)`により本体が定数畳み込みで消えるため、配布
/// バイナリには影響しない。
///
/// BUG-041調査で判明: AppContainer子/孫プロセスに付与しているACLはworkspace（RO）とdiff_layer_dir（RW）
/// のみで、`%TEMP%`直下への書込権は無い。そのため`%TEMP%`へ書く実装は**サンドボックス内から
/// 常に無音**だった（BUG-033で「ログが生成されなかった＝該当パスを通っていない」と解釈した
/// 箇所は、この理由で不成立だった可能性が高い——同ファイルに追記済み）。`CONFIG`が既に設定済み
/// なら`diff_layer_dir`（子・孫とも書込可能、`append_ledger_entry`/`append_warning_entry`と同じ場所）
/// へ書き、未設定（`init()`より前、または`CONFIG`取得に失敗する異常系）なら従来通り`%TEMP%`へ
/// フォールバックする。`--sandbox tier2a-cow`のフック呼び出し頻度は対話セッションのシェルコマンド数程度で
/// 済むため、ログ肥大やI/O再入（`copy_up`同様に自分自身のフックへ戻ってくる可能性はあるが、
/// いずれの出力先も`workspace_relative`が`None`を返す経路なので無限ループにはならない）の
/// 実害は無い想定。
pub(crate) fn debug_log(msg: &str) {
    if !cfg!(debug_assertions) {
        return;
    }
    // [D-88] **差分層が空のときは`%TEMP%`へ落とす。**
    //
    // `PathBuf::new().join("x")`は`"x"`——つまり**相対パス**になり、子のカレント
    // ディレクトリ（＝ワークスペースのroot）へログが落ちる。DirectRwのlazyレーンには
    // 差分層が無いので、この分岐が無いと**利用者のリポジトリに`.harness-cow-debug.log`が
    // 生える**（実際に生やした）。デバッグビルドだけとはいえ、フックが自分の作業物を
    // 相手の作業場へ置くのは筋が悪い。
    let path = match CONFIG.get() {
        Some(cfg) if !cfg.diff_layer_dir.as_os_str().is_empty() => {
            cfg.diff_layer_dir.join(".harness-cow-debug.log")
        }
        _ => std::env::temp_dir().join("harness-cow-debug.log"),
    };
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "[{}] {msg}", now_millis());
    }
}
