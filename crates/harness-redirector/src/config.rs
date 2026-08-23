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

/// 注入パラメータで運ぶ設定のシリアライズ（BUG-045のF2）。`\n`区切り3行・NUL終端のUTF-8:
///
/// ```text
/// <workspace_root>\n<upper_dir>\n<ext_capture_roots を ';' で連結>\0
/// ```
///
/// 環境変数（`HARNESS_COW_*`）と等価な情報を、**子孫プロセスのenv blockに依存せずに**
/// 渡すための唯一の形式。途中の世代が自前のenv blockを組み立てて子を起動しても設定が
/// 途切れないようにする（モジュールdoc「設定の伝播」参照）。
pub(crate) fn serialize_config_blob(cfg: &Config) -> Vec<u8> {
    let ext = cfg
        .ext_capture_roots
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(";");
    let mut bytes = format!(
        "{}\n{}\n{}",
        cfg.workspace_root.to_string_lossy(),
        cfg.upper_dir.to_string_lossy(),
        ext
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
    let workspace_root = lines.next().filter(|s| !s.is_empty())?;
    let upper_dir = lines.next().filter(|s| !s.is_empty())?;
    let ext_capture_roots = lines
        .next()
        .unwrap_or("")
        .split(';')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect();
    Some(Config {
        workspace_root: PathBuf::from(workspace_root),
        upper_dir: PathBuf::from(upper_dir),
        ext_capture_roots,
    })
}

/// BUG-033調査用の診断計装（`docs/bugs/BUG-033.md`参照、再発時の再調査用に残置）。
/// releaseビルドでは`cfg!(debug_assertions)`により本体が定数畳み込みで消えるため、配布
/// バイナリには影響しない。
///
/// BUG-041調査で判明: AppContainer子/孫プロセスに付与しているACLはworkspace（RO）とupper_dir（RW）
/// のみで、`%TEMP%`直下への書込権は無い。そのため`%TEMP%`へ書く実装は**サンドボックス内から
/// 常に無音**だった（BUG-033で「ログが生成されなかった＝該当パスを通っていない」と解釈した
/// 箇所は、この理由で不成立だった可能性が高い——同ファイルに追記済み）。`CONFIG`が既に設定済み
/// なら`upper_dir`（子・孫とも書込可能、`append_ledger_entry`/`append_warning_entry`と同じ場所）
/// へ書き、未設定（`init()`より前、または`CONFIG`取得に失敗する異常系）なら従来通り`%TEMP%`へ
/// フォールバックする。`--sandbox tier2a-cow`のフック呼び出し頻度は対話セッションのシェルコマンド数程度で
/// 済むため、ログ肥大やI/O再入（`copy_up`同様に自分自身のフックへ戻ってくる可能性はあるが、
/// いずれの出力先も`workspace_relative`が`None`を返す経路なので無限ループにはならない）の
/// 実害は無い想定。
pub(crate) fn debug_log(msg: &str) {
    if !cfg!(debug_assertions) {
        return;
    }
    let path = match CONFIG.get() {
        Some(cfg) => cfg.upper_dir.join(".harness-cow-debug.log"),
        None => std::env::temp_dir().join("harness-cow-debug.log"),
    };
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "[{}] {msg}", now_millis());
    }
}
