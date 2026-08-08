//! Tier2a子プロセスを起こすまでの**前口上**——`preflight`が付けたのと同じ主体を導出し、
//! 背景のACL walkの完了を待ってから`spawn_with_workspace`を呼ぶ、という一連の手順。
//!
//! # なぜ1箇所に集めるのか
//!
//! この手順は`preflight`（ACEを付ける側）と**主体の導出規則を共有していなければならない**。
//! `docs/CODE-STRUCTURE-RULES.md`規則5の一般論としてではなく、実害として:
//!
//! - workspaceツリーのACEは**workspace＋モード単位のcapability SID**宛に付いている（D-54）。
//!   モードの語彙（`"rwx"` / `"ro"`）が`preflight`とずれると別のcapabilityを導出し、
//!   **付与されていない主体で起動して全アクセスが拒否される**。
//! - 子は**そのセッションのプロファイル**で起動しなければならない（D-37）。固定名や別名で
//!   導出すると、ACEを付けたSIDと違う主体になりworkspaceが一切見えない。
//! - 初回起動では保護DACL配下を救済する背景walkが走っている。終わる前にコマンドを走らせると、
//!   その配下が「存在しない/読めない」ように見え原因不明の失敗になる（D-54、[`grant_job`]）。
//!
//! 手順を経路ごとに書き直すと、この3つのどれかが片方だけ直る／片方だけ忘れられる。
//! 呼び出し元は`run_shell`のTier2a経路（`harness-tools`）と、ポリシーエディタのパス2
//! （`plans/POLICY-EDITOR-TOMOYO-DIG.md`）の2つである。
//!
//! # ここが持たないもの
//!
//! - **network capabilityを付けるかどうかの判断**。`net_capability`は引数で受け取る。
//!   判定（`should_grant_tier2a_network_capability`）は`harness-tools`側の純粋関数で、
//!   judgementとenforcementを同じ場所に置かない方針（`shell::net_decision`のdoc）に従う。
//! - **コマンド本体をenvへ載せること**。`RUN_SHELL_COMMAND_ENV_VAR`（BUG-050）は
//!   `harness-tools`の定数で、依存の向き上ここからは見えない。呼び出し元が`env`へ積んでから渡す
//!   （Tier1の記録モードも同じ形で積んでいる）。
//!
//! # 呼び出しはブロッキングである
//!
//! [`grant_job::wait_until_done`]は`std::thread::sleep`で実待ちする同期関数で、初回は20秒を
//! 超えることがある。**async文脈からは`spawn_blocking`等でワーカースレッドの外へ逃がすこと**
//! （BUG-082フォローアップ: `.await`無しでasync fnの中から呼ぶと、tokioのワーカーを待ち時間ぶん
//! 専有し、並行して動くはずの進捗表示が更新されなくなる）。待ちを関数の中に入れてあるのは、
//! **呼び出し元が忘れられないようにするため**である。

use std::path::PathBuf;

use super::{
    ensure_profile, grant_job, resolve_shell, spawn_with_workspace, AppContainerChild,
    AppContainerError, CowInject, NetworkCapability,
};

/// Tier2aでシェルを起こすための入力一式。
///
/// 全て所有値なのは、呼び出し元がまるごと`spawn_blocking`へ`move`できるようにするため。
pub struct WorkspaceSpawn {
    /// 子のカレントディレクトリ。存在しなければ作られる。
    pub cwd: PathBuf,
    /// 子へ渡す環境変数一式（**コマンド本体を載せた後のもの**、モジュールdoc参照）。
    pub env: Vec<(String, String)>,
    /// workspaceルート。ACEを付けた主体（capability SID）の導出に使う。
    pub workspace_root: PathBuf,
    /// `--cow`（D-30）のupper_dir。`Some`のときだけRedirector DLLを注入し、
    /// workspaceモードは`"ro"`になる。
    pub cow_upper_dir: Option<PathBuf>,
    /// `preflight`が**実際にACEを付けられた**passthroughルート（`(path, writable)`）。
    /// `--cow`時、このうち書込可のものがRedirector DLLのext capture対象になる（設計書§19.8）。
    /// 境界＝ACLはfs-allowが既に張っているので、ここは変更の可視化のためのcaptureである。
    pub granted_passthrough: Vec<(PathBuf, bool)>,
    /// 子へ与えるnetwork capability。**判断は呼び出し元が行う**（モジュールdoc参照）。
    pub net_capability: NetworkCapability,
}

impl WorkspaceSpawn {
    /// workspaceのアクセスモード。`preflight`の`workspace_mode`と**同じ語彙**でなければならない
    /// ——ずれると別のcapability SIDを導出する（モジュールdoc）。
    fn workspace_mode(&self) -> &'static str {
        if self.cow_upper_dir.is_some() {
            "ro"
        } else {
            "rwx"
        }
    }
}

/// Tier2aでシェルを起こす。戻り値は`(子プロセス, シェルのラベル)`。
///
/// **ブロッキング**（モジュールdocの「呼び出しはブロッキングである」参照）。
pub fn spawn_shell_in_workspace(
    req: WorkspaceSpawn,
) -> Result<(AppContainerChild, &'static str), AppContainerError> {
    let _ = std::fs::create_dir_all(&req.cwd);

    // D-37: 子プロセスはこの**セッションのプロファイル**で起動する。`preflight`がACEを付けたのも
    // 同じSIDなので、固定名（＝別のプロファイル）で導出すると workspace へ書けなくなる。
    let sid = ensure_profile(&crate::tier2a::session_profile::current_profile_name())?;

    // preflightのsmoke testと同一のシェル解決を使う（pwshのストアアプリ実行エイリアスは
    // AppContainerで起動不可＝`resolve_shell`が実在のpowershell.exeへフォールバックする）。
    let (bin, shell_label) = resolve_shell();
    let args = ["-NoProfile", "-NonInteractive", "-Command", "-"];

    let ext_capture_roots: Vec<PathBuf> = req
        .granted_passthrough
        .iter()
        .filter(|(_, writable)| *writable)
        .map(|(path, _)| path.clone())
        .collect();
    let cow = req
        .cow_upper_dir
        .as_ref()
        .map(|upper_dir| CowInject {
            workspace_root: &req.workspace_root,
            upper_dir,
            ext_capture_roots: ext_capture_roots.as_slice(),
        });

    // D-54: workspaceツリーのACEはworkspace＋モード単位のcapability SID宛に付いている。
    // `preflight`が付与したのと同じ主体をこの子のトークンへ積まないと、workspaceが一切
    // 見えない（package SIDだけでは届かない）。
    let canonical_workspace = req
        .workspace_root
        .canonicalize()
        .unwrap_or_else(|_| req.workspace_root.clone());
    let workspace_cap = super::workspace_capability_sid(&canonical_workspace, req.workspace_mode())?;

    // D-54: 初回起動では、保護DACL配下を救済するwalkが背景で走っていることがある。終わる前に
    // コマンドを走らせると、その配下がモデルには「存在しない/読めない」と見え、原因不明の
    // 失敗になる。完了を待ち、walkが失敗していたら断る（fail-closed、`grant_job`のdoc）。
    // 走っていなければ即座に返るので、2回目以降の起動では何のコストも無い。
    grant_job::wait_until_done().map_err(AppContainerError::Preflight)?;

    let child = spawn_with_workspace(
        &bin,
        &args,
        &req.cwd,
        &req.env,
        true,
        sid.as_psid(),
        req.net_capability,
        cow,
        Some(workspace_cap.as_psid()),
    )?;
    Ok((child, shell_label))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **`preflight`が使うのと同じ語彙**であることを固定する。ここがずれると別のcapability SIDを
    /// 導出し、付与されていない主体で起動して全アクセスが拒否される（D-54、モジュールdoc）。
    /// `preflight`側の対応する`match`は`WorkspaceWriteMode`を`..`無しで分解しているので、
    /// バリアントが増えれば向こうはコンパイルエラーになる。こちらは`Option`なのでその保護が
    /// 効かない——だからテストで固定する。
    #[test]
    fn the_workspace_mode_vocabulary_matches_preflight() {
        let base = WorkspaceSpawn {
            cwd: PathBuf::from(r"C:\ws"),
            env: Vec::new(),
            workspace_root: PathBuf::from(r"C:\ws"),
            cow_upper_dir: None,
            granted_passthrough: Vec::new(),
            net_capability: NetworkCapability::Deny,
        };
        assert_eq!(base.workspace_mode(), "rwx", "通常起動 = WorkspaceWriteMode::DirectRw");

        let cow = WorkspaceSpawn {
            cow_upper_dir: Some(PathBuf::from(r"C:\ws\.harness\upper")),
            ..base
        };
        assert_eq!(cow.workspace_mode(), "ro", "--cow = WorkspaceWriteMode::Cow");
    }

    /// ext captureの対象は**書込可の穴だけ**（読み取り専用の穴はCoWの記録対象ではない）。
    #[test]
    fn only_writable_passthrough_roots_become_ext_capture_roots() {
        let req = WorkspaceSpawn {
            cwd: PathBuf::from(r"C:\ws"),
            env: Vec::new(),
            workspace_root: PathBuf::from(r"C:\ws"),
            cow_upper_dir: None,
            granted_passthrough: vec![
                (PathBuf::from(r"C:\ro"), false),
                (PathBuf::from(r"C:\rw"), true),
            ],
            net_capability: NetworkCapability::Deny,
        };

        let roots: Vec<PathBuf> = req
            .granted_passthrough
            .iter()
            .filter(|(_, writable)| *writable)
            .map(|(path, _)| path.clone())
            .collect();

        assert_eq!(roots, vec![PathBuf::from(r"C:\rw")]);
    }
}
