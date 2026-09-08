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
    ensure_profile, grant_job, resolve_shell, spawn_with_workspace,
    spawn_with_workspace_via_daemon, AppContainerChild, AppContainerError, CowInject,
    DomainIdentity, NetworkCapability, RedirectorInject, SpawnRequestAccess,
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
    /// `preflight`が**実際にACEを付けられた**passthroughルート。
    /// `--sandbox tier2a-cow`時、このうち書込可のものがRedirector DLLのext capture対象になる（設計書§19.8）。
    /// 境界＝ACLはfs-allowが既に張っているので、ここは変更の可視化のためのcaptureである。
    ///
    /// [§22.3] 各要素は**その穴のACEを実際に書いた宛先SID**を持つ。子のトークンへ積むのはそれで、
    /// ここで導出し直さない（導出し直すと、CoWでアクセス級が降格したときに別のSIDを作る）。
    pub granted_passthrough: Vec<harness_core::GrantedPassthrough>,
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

/// [§22.3] `--fs-allow`で開いた穴の分として、子のトークンへ積むcapability SIDを決める。
///
/// 穴のACEはもうこのセッションのpackage SID宛ではなく、**宣言ごとのcapability SID宛**である
/// ——積まなければ、`preflight`が正しく付与していても子からは1バイトも読めない
/// （`ACCESS_DENIED`）。
///
/// # 宣言と1対1である（2026-09-01、分流N1）
///
/// 積むのは**`preflight`がその穴のACEを実際に書いた宛先SIDそのもの**で、ここで導出も推測も
/// しない。宛先SIDは`(秘密, 畳み込み済みパス, access級)`から決まるので、**級を取り違えると
/// 別のSIDになり、症状は「ACEは正しいのに子から一切読めない」という最も分かりにくい形**に
/// なる（`--sandbox tier2a-cow`は`read_write`を`read`へ降格するため、ユーザーが要求した級から
/// 導出すると実際に外れる）。運ばれてきた値を使えば外れようがない。
///
/// 対象は**実際にACEが付いた穴**だけである（`granted_passthrough`がそう定義されている）。
/// 付けられなかったパスのcapability SIDまで積むと、宣言していないものをトークンへ載せる形になる。
///
/// **かつてはここで台帳をパスで引いていた**（`fs_allow_capability_sids`）。台帳は
/// 「このworkspaceがこのパスへ発行したcapability SID」を**全部**返すので、過去に別のaccess級で
/// 発行したものも一緒に載り、**宣言より広かった**。その広さがこの関数で消える。
///
/// # 関数として切り出してある理由
///
/// 「何を積むか」を**起こす副作用を持たずに測れる**ようにするため。この決定が
/// `spawn_shell_in_workspace`の中に埋まっていると、確かめる手段が実プロセスの起動しか無くなる。
fn declaration_caps(
    granted: &[harness_core::GrantedPassthrough],
) -> Vec<crate::win_common::OwnedSid> {
    let mut caps = Vec::with_capacity(granted.len());
    for entry in granted {
        match crate::win_common::sid_from_string(&entry.subject_sid) {
            Ok(sid) => caps.push(sid),
            // **黙って落とさない**（`B-09`/`B-10`）。ここで落ちた穴は、ACEは付いているのに
            // 子がその宛先SIDを持たないので`ACCESS_DENIED`になる——fail-closedだが、
            // 原因はACL側ではなくトークン側にあるので、言わないと追えない。
            Err(e) => eprintln!(
                "warning: could not use the capability SID recorded for {} ({}): {e}; \
                 the sandboxed child will not be able to reach this path",
                entry.path.display(),
                entry.subject_sid
            ),
        }
    }
    caps
}

/// Tier2aでシェルを**harness自身が直接**起こす。戻り値は`(子プロセス, シェルのラベル)`。
///
/// # **製品はここを通らない**（2026-09-07、段階④以降）
///
/// トップレベル生成はSpawn Daemon経由だけになった（`plans/DESIGN-MAC-PROTOCOL.md` §12）。
/// この関数の製品呼び出し元は**0件**で、残っているのはレーンの受入テストと待ち時間の測定だけ
/// である（`the_direct_route_has_no_product_callers`が数えて固定している）。
///
/// **新しい呼び出しをここへ足さないこと。** 足すとその経路だけがDaemonを通らず、
/// 「Daemonが居なくても動く」＝設計が禁じた直接生成への降格がそこから入る。
/// 製品から呼ぶなら[`spawn_shell_in_workspace_via_daemon`]である。
///
/// **ではなぜ残してあるのか。** レーンの測定が「Daemon経由と直接生成の差」を測る対の片側で、
/// これを消すと比較の基準が無くなる。**消せないものは、消せない理由ごと固定する。**
///
/// **ブロッキング**（モジュールdocの「呼び出しはブロッキングである」参照）。
pub fn spawn_shell_in_workspace(
    req: WorkspaceSpawn,
) -> Result<(AppContainerChild, &'static str), AppContainerError> {
    spawn_shell_in_workspace_on(req, SpawnRoute::Direct)
}

/// 製品のトップレベル経路。Daemon未注入を表せない入口にして、直接spawnへの降格を防ぐ。
pub fn spawn_shell_in_workspace_via_daemon(
    daemon: &crate::tier2a::spawnd::SharedSpawnDaemon,
    req: WorkspaceSpawn,
) -> Result<(AppContainerChild, &'static str), AppContainerError> {
    spawn_shell_in_workspace_on(req, SpawnRoute::Daemon(daemon))
}

#[derive(Clone, Copy)]
enum SpawnRoute<'a> {
    Direct,
    Daemon(&'a crate::tier2a::spawnd::SharedSpawnDaemon),
}

fn spawn_shell_in_workspace_on(
    req: WorkspaceSpawn,
    route: SpawnRoute<'_>,
) -> Result<(AppContainerChild, &'static str), AppContainerError> {
    let _ = std::fs::create_dir_all(&req.cwd);

    // D-37: 子プロセスはこの**セッションのプロファイル**で起動する。`preflight`がACEを付けたのも
    // 同じSIDなので、固定名（＝別のプロファイル）で導出すると workspace へ書けなくなる。
    let profile_name = crate::tier2a::session_profile::current_profile_name();
    let sid = ensure_profile(&profile_name)?;

    // preflightのsmoke testと同一のシェル解決を使う（pwshのストアアプリ実行エイリアスは
    // AppContainerで起動不可＝`resolve_shell`が実在のpowershell.exeへフォールバックする）。
    let (bin, shell_label) = resolve_shell();
    let args = ["-NoProfile", "-NonInteractive", "-Command", "-"];

    let ext_capture_roots: Vec<PathBuf> = req
        .granted_passthrough
        .iter()
        .filter(|g| g.writable)
        .map(|g| g.path.clone())
        .collect();
    let cow = req
        .cow_diff_layer_dir
        .as_ref()
        .map(|diff_layer_dir| CowInject {
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

    // [§22.3] `--fs-allow`で開いた穴のcapability SIDも積む（`declaration_caps`のdoc参照）。
    let fs_allow_caps = declaration_caps(&req.granted_passthrough);
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
        let domain = DomainIdentity::Capability(workspace_cap.as_psid());
        match route {
            SpawnRoute::Direct => spawn_with_workspace(
                &bin,
                &args,
                &req.cwd,
                &req.env,
                true,
                sid.as_psid(),
                req.net_capability,
                inject,
                &domain_caps,
                domain,
            ),
            SpawnRoute::Daemon(daemon) => spawn_with_workspace_via_daemon(
                daemon,
                &profile_name,
                &bin,
                &args,
                &req.cwd,
                &req.env,
                true,
                sid.as_psid(),
                req.net_capability,
                inject,
                &domain_caps,
                domain,
                // このシェルは要求受付パイプへ届いてよい（`plans/DESIGN-MAC-PROTOCOL.md` §12）。
                // 段階⑤で生成能力を取り上げたあと、CLIツールが子を起こす唯一の口がここになる
                // ——積まないと、そのときシェルは孫プロセスを1つも作れなくなる。
                SpawnRequestAccess::Grant,
            ),
        }
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

    // [段階5b（`plans/DESIGN-MAC-ENFORCEMENT.md` §8.1）] **ここも注入する。**
    //
    // かつてここは`cow.into()`で、CoWでなければ`RedirectorInject`が空になり
    // **DLLが1度も載らなかった**。lazyレーンの受付パイプは下準備の背景走査が
    // 走っている間しか存在しないので、走査が終わった後・準備済みのワークスペース・
    // レーンを切った構成はすべてこの経路へ落ちる——つまり**定常状態では注入が
    // 起きていなかった**（設計書§8.1が「現状との差」を`lane()`だけで書いていたのは
    // 実態より狭い。2026-09-08に実測して直した）。
    //
    // 段階⑤で生成を禁じる前に埋めるべきはここである。誘導も受付も無いので、
    // DLLはファイル系フックを1本も置かず、プロセス生成フックだけを設置する。
    let child = spawn(RedirectorInject::for_tier2a(
        Some(&canonical_workspace),
        cow,
        None,
    ))?;
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

    /// **直接生成の入口に製品の呼び出し元が1つも無いこと**を固定する（§12）。
    ///
    /// トップレベル生成はSpawn Daemon経由だけになったが、[`spawn_shell_in_workspace`]は
    /// `pub`のまま残っている（レーンの測定が対の片側として使う）。**印が無いと、次に足された
    /// 呼び出しは黙って非Daemon経路になる**——設計が禁じた「直接spawnへの降格」がそこから入り、
    /// しかも動いてしまうので誰も気付かない（`B-10`）。
    ///
    /// **`grep`で数えるので、限界は§10.1.1の数え上げと同じである**——別名で束ねてから呼ばれると
    /// 出ない。ここが緑でも「降格経路が無い」ではなく「**この綴りの**降格経路が無い」である。
    #[test]
    fn the_direct_route_has_no_product_callers() {
        // **探す綴りは実行時に組み立てる。** そのまま書くと**この関数自身が数え上げに
        // 引っ掛かる**——§10.1.1が「docに解放の綴りをそのまま書かないのは、doc自身が
        // 数え上げに掛かるため」と書いている罠の、検出器側の版である。1回実際に踏んだ。
        let needle = format!("spawn_shell_in_workspace{}", '(');
        let definition = format!("fn {needle}");
        let (product_callers, test_callers) =
            super::super::test_support::product_callers_of(&needle, &definition);

        assert!(
            product_callers.is_empty(),
            "直接生成の入口に製品の呼び出し元がある。この経路はSpawn Daemonを通らないので、\
             Daemonが居なくても動いてしまう（§12が禁じた降格）。\
             製品から呼ぶなら spawn_shell_in_workspace_via_daemon を使うこと:\n  {}",
            product_callers.join("\n  ")
        );
        assert!(
            test_callers > 0,
            "テストからの呼び出しも0件になった。この関数を残している理由\
             （Daemon経由と直接生成を比べる測定の片側）が消えているなら、関数ごと消すこと"
        );
    }

    /// **注入しない選択が製品コードに1つも無いこと**を固定する（段階5b、
    /// `plans/DESIGN-MAC-ENFORCEMENT.md` §8.1）。
    ///
    /// 製品のTier2a生成は例外なく[`RedirectorInject::for_tier2a`]を通り、
    /// **プロセス生成フックを必ず要求する**。段階⑤で`CHILD_PROCESS_RESTRICTED`
    /// （OSが子プロセス生成そのものを拒否する緩和策）を積んだあと、
    /// フックの入っていないプロセスは**子を作ることも頼むこともできなくなる**ので、
    /// 「1経路だけ注入しない」が残っていると、その経路だけが静かに死ぬ。
    ///
    /// **実際にその状態だった**——MCP stdioは2026-09-08まで注入しない側を固定で渡しており、
    /// それを赤くするテストは1本も無かった。ここがその印である。
    ///
    /// 限界は`product_callers_of`のdocが持つ（**緑は「この綴りの呼び出し元が無い」しか
    /// 意味しない**）。
    #[test]
    fn no_product_code_opts_out_of_redirector_injection() {
        let needle = format!("RedirectorInject::default{}", '(');
        let definition = String::from("impl Default for RedirectorInject");
        let (product_callers, test_callers) =
            super::super::test_support::product_callers_of(&needle, &definition);

        assert!(
            product_callers.is_empty(),
            "製品コードが「Redirector DLLを注入しない」を選んでいる。段階⑤で\
             CHILD_PROCESS_RESTRICTEDを積むと、この経路の子は子プロセスを作ることも\
             Spawn Daemonへ頼むこともできなくなる（§8.1）。\
             製品から起こすなら RedirectorInject::for_tier2a を使うこと:\n  {}",
            product_callers.join("\n  ")
        );
        assert!(
            test_callers > 0,
            "テストからの呼び出しも0件になった。綴りを間違えて1行も見ていない可能性がある\
             （0件マッチで黙って緑になる形＝BUG-056）"
        );
    }

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
                harness_core::GrantedPassthrough {
                    path: PathBuf::from(r"C:\ro"),
                    writable: false,
                    subject_sid: "S-1-15-3-1024-1".to_string(),
                    used_restore_privilege: false,
                },
                harness_core::GrantedPassthrough {
                    path: PathBuf::from(r"C:\rw"),
                    writable: true,
                    subject_sid: "S-1-15-3-1024-2".to_string(),
                    used_restore_privilege: false,
                },
            ],
            net_capability: NetworkCapability::Deny,
        };

        let roots: Vec<PathBuf> = req
            .granted_passthrough
            .iter()
            .filter(|g| g.writable)
            .map(|g| g.path.clone())
            .collect();

        assert_eq!(roots, vec![PathBuf::from(r"C:\rw")]);
    }

    /// [分流N1] **積むcapability SIDは、運ばれてきたものと1対1である。**
    ///
    /// 壊れた状態は「宣言していない級のcapability SIDまで積む」こと。かつてここは台帳を
    /// パスで引いており、同じパスへ過去に別の級で発行した分も一緒に載っていた。
    /// **この関数が台帳を一切見ないこと**が、その広さが戻らない根拠である。
    ///
    /// 台帳を見ないことをどう測るか——`granted`に載っていないパスの分は、たとえ実マシンの
    /// 台帳に在っても出てこない。ここでは実在しないパス2件を渡し、**出てくるのがその2件分
    /// ちょうど**であることを見る（台帳を引いていれば0件になるか、無関係な分が混ざる）。
    #[test]
    fn declaration_caps_carries_exactly_what_preflight_handed_over() {
        // 実在するcapability SIDの綴り。値そのものに意味は無く、**互いに違うこと**だけが要る。
        let a = "S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-\
                 3232135806-4053264122-3456934681";
        let b = "S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-\
                 543910227-1950414635-4190290187";
        let granted = vec![
            harness_core::GrantedPassthrough {
                path: PathBuf::from(r"C:\does-not-exist-a"),
                writable: false,
                subject_sid: a.to_string(),
                used_restore_privilege: false,
            },
            harness_core::GrantedPassthrough {
                path: PathBuf::from(r"C:\does-not-exist-b"),
                writable: true,
                subject_sid: b.to_string(),
                used_restore_privilege: false,
            },
        ];

        let caps = declaration_caps(&granted);
        let rendered: Vec<String> = caps
            .iter()
            .map(|c| {
                crate::win_common::sid_to_string(c.as_psid()).expect("render the capability SID")
            })
            .collect();
        assert_eq!(
            rendered,
            vec![a.to_string(), b.to_string()],
            "the caps piled onto the child must be exactly the ones preflight handed over, in order"
        );
    }

    /// 綴りが壊れていても**落ちない**——その穴だけが積まれず、他は積まれる。
    ///
    /// 倒れる向きはfail-closed（積まれない子はそのパスへ届かない）。**黙らせないこと**は
    /// `declaration_caps`のdocが述べているとおりで、ここでは「1件壊れても残りが生きる」ことだけを見る。
    #[test]
    fn a_malformed_subject_sid_drops_only_its_own_entry() {
        let good = "S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-\
                    3232135806-4053264122-3456934681";
        let granted = vec![
            harness_core::GrantedPassthrough {
                path: PathBuf::from(r"C:\broken"),
                writable: false,
                subject_sid: "not-a-sid".to_string(),
                used_restore_privilege: false,
            },
            harness_core::GrantedPassthrough {
                path: PathBuf::from(r"C:\fine"),
                writable: false,
                subject_sid: good.to_string(),
                used_restore_privilege: false,
            },
        ];

        let caps = declaration_caps(&granted);
        assert_eq!(caps.len(), 1, "only the malformed entry may be dropped");
        assert_eq!(
            crate::win_common::sid_to_string(caps[0].as_psid()).expect("render"),
            good,
            "the surviving cap must be the well-formed one"
        );
    }
}
