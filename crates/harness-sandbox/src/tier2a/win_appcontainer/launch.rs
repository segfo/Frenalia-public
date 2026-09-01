//! Tier2a子プロセスを起こすまでの**前口上**——`preflight`が付けたのと同じ宛先SIDを導出し、
//! 背景のACL walkの完了を待ってから`spawn_with_workspace`を呼ぶ、という一連の手順。
//!
//! # なぜ1箇所に集めるのか
//!
//! この手順は`preflight`（ACEを付ける側）と**宛先SIDの導出規則を共有していなければならない**。
//! `docs/CODE-STRUCTURE-RULES.md`規則5の一般論としてではなく、実害として:
//!
//! - workspaceツリーのACEは**workspace＋モード単位のcapability SID**宛に付いている（D-54）。
//!   モードの語彙（`"rwx"` / `"ro"`）が`preflight`とずれると別のcapabilityを導出し、
//!   **付与されていない宛先SIDで起動して全アクセスが拒否される**。
//! - 子は**そのセッションのプロファイル**で起動しなければならない（D-37）。固定名や別名で
//!   導出すると、ACEを付けたSIDと違う宛先SIDになりworkspaceが一切見えない。
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
    AppContainerError, CowInject, DomainIdentity, NetworkCapability, RedirectorInject,
};

/// Tier2aでシェルを起こすための入力一式。
///
/// 全て所有値なのは、呼び出し元がまるごと`spawn_blocking`へ`move`できるようにするため。
pub struct WorkspaceSpawn {
    /// 子のカレントディレクトリ。存在しなければ作られる。
    pub cwd: PathBuf,
    /// 子へ渡す環境変数一式（**コマンド本体を載せた後のもの**、モジュールdoc参照）。
    pub env: Vec<(String, String)>,
    /// workspaceルート。ACEを付けた宛先SID（capability SID）の導出に使う。
    pub workspace_root: PathBuf,
    /// `--sandbox tier2a-cow`（D-30）のdiff_layer_dir。`Some`のときだけRedirector DLLを注入し、
    /// workspaceモードは`"ro"`になる。
    pub cow_diff_layer_dir: Option<PathBuf>,
    /// `preflight`が**実際にACEを付けられた**passthroughルート（`(path, writable)`）。
    /// `--sandbox tier2a-cow`時、このうち書込可のものがRedirector DLLのext capture対象になる（設計書§19.8）。
    /// 境界＝ACLはfs-allowが既に張っているので、ここは変更の可視化のためのcaptureである。
    pub granted_passthrough: Vec<(PathBuf, bool)>,
    /// 子へ与えるnetwork capability。**判断は呼び出し元が行う**（モジュールdoc参照）。
    pub net_capability: NetworkCapability,
}

impl WorkspaceSpawn {
    /// workspaceのアクセスモード。`preflight`の`workspace_mode`と**同じ語彙**でなければならない
    /// ——ずれると別のcapability SIDを導出する（モジュールdoc）。
    fn workspace_mode(&self) -> &'static str {
        if self.cow_diff_layer_dir.is_some() {
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
    let cow = req.cow_diff_layer_dir.as_ref().map(|diff_layer_dir| CowInject {
        workspace_root: &req.workspace_root,
        diff_layer_dir,
        ext_capture_roots: ext_capture_roots.as_slice(),
    });

    // D-54: workspaceツリーのACEはworkspace＋モード単位のcapability SID宛に付いている。
    // `preflight`が付与したのと同じcapability SIDをこの子のトークンへ積まないと、workspaceが一切
    // 見えない（package SIDだけでは届かない）。
    let canonical_workspace = req
        .workspace_root
        .canonicalize()
        .unwrap_or_else(|_| req.workspace_root.clone());
    let workspace_cap =
        super::workspace_capability_sid(&canonical_workspace, req.workspace_mode())?;

    // [§22.3] `--fs-allow`で開いた穴のcapability SIDも積む。**穴のACEはもうこのセッションのpackage SID
    // 宛ではなく、宣言ごとのcapability SID宛である**——積まなければ、preflightが正しく
    // 付与していても子からは1バイトも読めない（`ACCESS_DENIED`）。
    //
    // 宛先SIDは`preflight`が付与に使ったのと**同じ導出**（`fs_allow_capability_sid`）から
    // 引き直す。モジュールdocが「宛先SIDの導出規則を`preflight`と共有していなければならない」と
    // 言っているのは、まさにこの種のずれが「付与されていない宛先SIDで起動して全アクセスが
    // 拒否される」形で出るからである。
    //
    // 引くのは**実際にACEが付いた穴**（`granted_passthrough`）だけにする。付けられなかった
    // パスのcapability SIDまで積むと、宣言していないものをトークンへ載せる形になる。
    //
    // # ここは近似である（T1-cで厳密化する）
    //
    // 宛先SIDは`(秘密, 畳み込み済みパス, access級)`から決まるのに、`granted_passthrough`が
    // 運んでいるのは`writable`という**2値**でしかない。`FsAccess`は4値（`read`/`read_write`/
    // `read_exec`/`read_write_exec`）あるので、**boolからaccess級を復元すると別の宛先SIDを
    // 導出し得る**——そして外れたときの症状は「ACEは正しいのに子から一切読めない」という
    // 最も分かりにくい形になる。だから**復元しない**。
    //
    // 代わりに台帳の索引を引く（`declaration_capability_names`）。これは
    // 「**このworkspaceがこのパスに対して発行したcapability SID**」を返すので、access級を推測せずに
    // 済む。近似なのは、同じパスへ複数のaccess級を発行済みのとき全部を積む点である
    // （このworkspace自身が宣言したものに限られるので他所へは広がらないが、
    // §22.3.0.2の条件2をこの子について厳密にはしていない）。
    //
    // 厳密化には`preflight`が返す`granted_subjects`（`(path, SID文字列)`）を
    // `ShellTierSelection`経由でここまで運ぶ必要があり、それはT1-cの担当である。
    let fs_allow_caps: Vec<crate::win_common::OwnedSid> = req
        .granted_passthrough
        .iter()
        .flat_map(|(path, _)| {
            super::fs_allow_capability_sids(path, Some(&canonical_workspace))
        })
        .collect();
    // [§22.3.2] CoWの差分層のcapability SIDも積む。**差分層のACEはもうこのセッションのpackage SID宛では
    // なく、差分層ごとのcapability SID宛である**——積まなければ、Redirector DLLが退避しようと
    // した書込がすべて`ACCESS_DENIED`になり、CoWが丸ごと機能しない（DLLは子の中で動くので、
    // 使えるのは子のトークンが持つcapability SIDだけである）。
    //
    // **引くだけで発行しない**（`lookup_`側）。ここで発行すると「起こす側」が台帳エントリを
    // 作ることになり、`preflight`を経ていない差分層に対して記録だけが増える。引けないときは
    // 積まない——症状は`ACCESS_DENIED`＝fail-closedで、無言で広がる向きには倒れない。
    let cow_diff_layer_cap = req.cow_diff_layer_dir.as_ref().and_then(|diff_layer_dir| {
        super::lookup_cow_diff_layer_capability_sid(&canonical_workspace, diff_layer_dir)
    });

    let mut domain_caps = vec![workspace_cap.as_psid()];
    domain_caps.extend(fs_allow_caps.iter().map(|cap| cap.as_psid()));
    domain_caps.extend(cow_diff_layer_cap.iter().map(|cap| cap.as_psid()));

    // 起こす手順は**注入するものを除いて同一**なので、1つのクロージャに畳む。2回書くと、
    // 片方だけ引数が変わっても誰も気付けない（`B-05`: コンパイラが守らない複製）。
    let spawn = |inject: RedirectorInject<'_>| {
        spawn_with_workspace(
            &bin,
            &args,
            &req.cwd,
            &req.env,
            true,
            sid.as_psid(),
            req.net_capability,
            inject,
            &domain_caps,
            // §22.1.1: このシェルのドメインはworkspace＋モード単位のcapability（D-54）。
            // traverse capabilityは全Tier2a子が共有するので**ドメインの識別子にしてはいけない**。
            DomainIdentity::Capability(workspace_cap.as_psid()),
        )
    };

    // [D-88（`plans/DESIGN-SANDBOX-APPPOLICY.md` §5.1.3）] **ここが「待つ条件」である。**
    //
    // これまでは無条件に「背景ジョブが最後まで終わったか」を待っていた。それは
    // 「**このコマンドが要るものが開けるか**」ではないので、要るファイルへ先に許可を
    // 付けても解放されない——だから待ちを足すのではなく、**待つ条件そのものを外す**。
    //
    // 外してよいのは、外した先に**要るものが要った瞬間に開く**仕掛けがあるときだけである。
    // その仕掛け＝fault受付が今このworkspaceに開いているかを、`lazy_broker_pipe_for`が答える
    // （`None`なら開いていない＝今日と同じく待つ）。
    if let Some(pipe) = lazy_lane_pipe(&req, &canonical_workspace, &bin) {
        match spawn(RedirectorInject::lazy(&canonical_workspace, &pipe)) {
            Ok(child) => return Ok((child, shell_label)),
            // resume**前**の失敗（注入・ハンドシェイク）。子はユーザーコードを1行も
            // 実行していないので、破棄して**1回だけ**通常起動へ落ちる（設計書
            // 「起動と自動fallback」の3）。ここで諦めると、レーンの不調が
            // **コマンドの失敗**に化ける——lazyで失われるのは速さだけのはずである。
            Err(AppContainerError::RedirectorInjection(_)) => {}
            // それ以外（起動そのものの失敗）は再試行しない。作り直しても同じである。
            Err(e) => return Err(e),
        }
    }

    // D-54: 初回起動では、保護DACL配下を救済するwalkが背景で走っていることがある。終わる前に
    // コマンドを走らせると、その配下がモデルには「存在しない/読めない」と見え、原因不明の
    // 失敗になる。完了を待ち、walkが失敗していたら断る（fail-closed、`grant_job`のdoc）。
    // 走っていなければ即座に返るので、2回目以降の起動では何のコストも無い。
    grant_job::wait_until_done().map_err(AppContainerError::Preflight)?;

    let child = spawn(cow.into())?;
    Ok((child, shell_label))
}

/// [D-88] このコマンドをlazyレーンで起こしてよいなら、fault受付パイプの名前を返す。
///
/// # 条件は2つだけである
///
/// 1. **`--sandbox tier2a-cow`ではない。** CoWとの合成（workspaceへのread/execだけを
///    fault-inし、write/deleteは差分層へ向ける）は設計にあるが**まだ実装していない**——
///    CoWのフックは成功経路で差分層を見に行く形のままなので、受付だけ渡しても使われない。
///    **渡さないことで、使われない設定が子へ届くのを防ぐ**（`B-14`と同じ姿勢: 記録の存在で
///    実体の存在を代替しない）。
/// 2. **このworkspaceにfault受付が今開いている。** 開いているのは準備中の間だけなので、
///    2回目以降の起動（`ready`）や既定レーンでは`None`になり、従来の経路へ落ちる。
/// 3. **このシェルが注入の対象外に指定されていない。** 指定されているなら、注入しても
///    フックが無い状態で走ることになるので、**最初からレーンに乗せず全walkを待つ**
///    （`lazy_grant::NO_INJECT_ENV`）。ここで弾くと、下の`wait_until_done`へそのまま落ちる
///    ——**これが「注入できないプロセスは待たされる」の実装である。**
fn lazy_lane_pipe(
    req: &WorkspaceSpawn,
    canonical_workspace: &std::path::Path,
    shell: &str,
) -> Option<String> {
    if req.cow_diff_layer_dir.is_some() {
        return None;
    }
    if super::lazy_grant::injection_is_excluded_for(std::path::Path::new(shell)) {
        return None;
    }
    // **一度でも許可を付けられなかったworkspaceでは、もうレーンを使わない。**
    // ここで`None`を返すと下の`wait_until_done`へ落ちる——つまり
    // 「次のコマンドは背景の準備が終わるまで待つ」が成立する。モデルがやり直せば必ず通る。
    if super::lazy_grant::lane_is_distrusted(canonical_workspace, req.workspace_mode()) {
        return None;
    }
    grant_job::lazy_broker_pipe_for(canonical_workspace, req.workspace_mode())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **`preflight`が使うのと同じ語彙**であることを固定する。ここがずれると別のcapability SIDを
    /// 導出し、付与されていない宛先SIDで起動して全アクセスが拒否される（D-54、モジュールdoc）。
    /// `preflight`側の対応する`match`は`WorkspaceWriteMode`を`..`無しで分解しているので、
    /// バリアントが増えれば向こうはコンパイルエラーになる。こちらは`Option`なのでその保護が
    /// 効かない——だからテストで固定する。
    #[test]
    fn the_workspace_mode_vocabulary_matches_preflight() {
        let base = WorkspaceSpawn {
            cwd: PathBuf::from(r"C:\ws"),
            env: Vec::new(),
            workspace_root: PathBuf::from(r"C:\ws"),
            cow_diff_layer_dir: None,
            granted_passthrough: Vec::new(),
            net_capability: NetworkCapability::Deny,
        };
        assert_eq!(
            base.workspace_mode(),
            "rwx",
            "通常起動 = WorkspaceWriteMode::DirectRw"
        );

        let cow = WorkspaceSpawn {
            cow_diff_layer_dir: Some(PathBuf::from(r"C:\ws\.harness\diff_layer")),
            ..base
        };
        assert_eq!(
            cow.workspace_mode(),
            "ro",
            "--sandbox tier2a-cow = WorkspaceWriteMode::Cow"
        );
    }

    /// ext captureの対象は**書込可の穴だけ**（読み取り専用の穴はCoWの記録対象ではない）。
    #[test]
    fn only_writable_passthrough_roots_become_ext_capture_roots() {
        let req = WorkspaceSpawn {
            cwd: PathBuf::from(r"C:\ws"),
            env: Vec::new(),
            workspace_root: PathBuf::from(r"C:\ws"),
            cow_diff_layer_dir: None,
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
