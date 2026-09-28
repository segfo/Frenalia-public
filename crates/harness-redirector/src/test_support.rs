//! 単体テストが共有する組み立て（`#[cfg(test)]`のときだけコンパイルされる）。

use super::*;

/// 一時的なworkspaceと差分層で、CoWが有効な設定を作る（2つの一時ディレクトリは返り値が持つ）。
pub(crate) fn cow_fixture() -> (tempfile::TempDir, tempfile::TempDir, Config) {
    let ws = tempfile::tempdir().unwrap();
    let diff_layer = tempfile::tempdir().unwrap();
    let cfg = Config {
        workspace_root: ws.path().to_path_buf(),
        diff_layer_dir: diff_layer.path().to_path_buf(),
        cow_enabled: true,
        broker_pipe: None,
        ext_capture_roots: Vec::new(),
        process_hooks: false,
    };
    (ws, diff_layer, cfg)
}

/// 台帳に`rel`について書かれた行の`op`を、書かれた順に返す。
pub(crate) fn ledger_ops(cfg: &Config, rel: &str) -> Vec<ChangeOp> {
    let text = std::fs::read_to_string(cfg.diff_layer_dir.join(COW_OPS_LEDGER_FILENAME))
        .unwrap_or_default();
    parse_ledger(&text)
        .into_iter()
        .filter(|e| e.path == rel)
        .map(|e| e.op)
        .collect()
}
