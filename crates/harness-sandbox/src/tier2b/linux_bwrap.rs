//! Linux Tier2b: bubblewrap（user+mount+network namespace + OverlayFS）。
//! `plans/DESIGN-SANDBOX.md` §6.2参照。
//!
//! **本セッションでは実機未検証**（この作業環境はWindows専用でLinux実機が無い）。
//! WSL2等で別途再検証が必要（`docs/phases/foundation/M12-*.md`に明記）。
//!
//! bwrap自体が特権プリミティブ（user/mount/network namespace + OverlayFS）を握るため、
//! harness側は`bwrap`を通常の子プロセスとして起動するだけでよく（`tokio::process::Command`を
//! そのまま流用できる、Windows Tier1のような独自FFIが不要）、既存の非同期I/O構造を変えずに
//! 済む。
//!
//! 【T1】読み取り専用で見せる範囲を実FS全体にしない: workspace + ツールチェーン必須パスのみ
//! `--ro-bind`し、`$HOME`は`--tmpfs`でマスクする（機密パスを空に見せる）。workspace自体は
//! `--overlay-src`でCoWの**本体層**にし、書込は**差分層**が受ける（`SandboxFs`のsandbox_dir
//! 配下に`diff-layer`/`work`を置き、`overlay.rs`のapply経路と合流できる置き場所にする）。
//! **ツールチェーンの`--ro-bind`は重ね合わせに参加しないので本体層ではない**（D-83）。

use std::path::{Path, PathBuf};

/// bwrap起動引数を組み立てる。`command`はハードニング済みの`sh -c <command>`実行を想定
/// （呼び出し側=`harness-tools::shell`が`sh -c`分を付与する）。
pub struct BwrapConfig {
    /// 重ね合わせの**本体層**（読み取り専用の元）。`--overlay-src`でbwrapへ渡す。
    pub workspace_root: PathBuf,
    /// **差分層**の置き場所（`<workspace>/.harness/sandbox/tier2b/diff-layer`。`runner.rs`が作る）。
    pub diff_layer_dir: PathBuf,
    /// bwrapの作業用ディレクトリ（OverlayFSのworkdir、差分層と同階層に置く）。
    pub work_dir: PathBuf,
}

/// `bwrap`へ渡す引数列を構築する（`bwrap <args...> -- sh -c <command>`の`<args...>`部分）。
pub fn build_args(config: &BwrapConfig) -> Vec<String> {
    let mut args = vec![
        "--die-with-parent".to_string(),
        "--unshare-user".to_string(),
        "--unshare-pid".to_string(),
        "--unshare-net".to_string(),
    ];

    // ツールチェーン必須パスはread-onlyでbindする（存在しないパスはbwrapが起動時に失敗する
    // ため、実在するもののみ追加する）。
    for ro in [
        "/usr",
        "/bin",
        "/lib",
        "/lib64",
        "/etc/alternatives",
        "/tmp",
    ] {
        if Path::new(ro).exists() {
            args.push("--ro-bind".to_string());
            args.push(ro.to_string());
            args.push(ro.to_string());
        }
    }
    for env_dir in ["CARGO_HOME", "RUSTUP_HOME"] {
        if let Ok(path) = std::env::var(env_dir) {
            if Path::new(&path).exists() {
                args.push("--ro-bind".to_string());
                args.push(path.clone());
                args.push(path);
            }
        }
    }

    // $HOMEは機密パス（~/.ssh等）を含み得るため実体を見せずtmpfsでマスクする（【T1】）。
    if let Ok(home) = std::env::var("HOME") {
        args.push("--tmpfs".to_string());
        args.push(home);
    }

    // workspaceを本体層にし、書込は差分層が受ける（D-08: 子から見た直前の書込の可視性を
    // OverlayFSで自動充足）。
    let ws = config.workspace_root.to_string_lossy().into_owned();
    args.push("--overlay-src".to_string());
    args.push(ws.clone());
    args.push("--overlay".to_string());
    args.push(config.diff_layer_dir.to_string_lossy().into_owned());
    args.push(config.work_dir.to_string_lossy().into_owned());
    args.push(ws.clone());

    args.push("--chdir".to_string());
    args.push(ws);

    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_args_includes_overlay_and_namespace_flags() {
        let config = BwrapConfig {
            workspace_root: PathBuf::from("/home/u/project"),
            diff_layer_dir: PathBuf::from("/home/u/project/.harness/sandbox/tier2b/diff-layer"),
            work_dir: PathBuf::from("/home/u/project/.harness/sandbox/tier2b/work"),
        };
        let args = build_args(&config);
        assert!(args.contains(&"--unshare-net".to_string()));
        assert!(args.contains(&"--unshare-user".to_string()));
        assert!(args.contains(&"--overlay-src".to_string()));
        assert!(args.contains(&"/home/u/project".to_string()));
    }
}
