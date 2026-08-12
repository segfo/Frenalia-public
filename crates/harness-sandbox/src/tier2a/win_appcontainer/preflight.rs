//! Tier2a起動前の実機プローブ（`preflight`）。
//!
//! ワークスペース・fs passthrough・`.harness/**`制御面のそれぞれについて、実際に
//! AppContainer子を起動してFS I/Oを試し、Tier2aを選んでよいかを判定する。判定材料の
//! 収集が責務であり、ACLの付与/撤収そのものは`acl_grant`/`revoke`に委ねる。

use super::*;

/// `preflight`の戻り値。`warnings`はD8の到達不能診断（従来どおり）、`granted_passthrough`は
/// **実際にACEが付与された（既存で十分だった場合・部分的にしか適用できなかった場合を含む）**
/// passthroughルートの一覧（`(path, writable)`）。呼び出し側（`harness-cli`の台帳記録）は
/// この一覧だけを台帳へ書くことで、「幻の台帳エントリ」（実際には`ACCESS_DENIED`で失敗した
/// のに記録だけ残る）を防ぐ。逆に、rootへのACE付与自体は成功したが子孫の一部
/// （TrustedInstaller所有等）で失敗した「部分適用」ケースは、`sid_ace_mask`でrootを権威的に
/// プローブして`Ok`/`Err`によらず記録する（BUG-017: 記録漏れが「撤収経路の無い孤立ACE」を
/// 生むため、幻の台帳エントリより孤立ACEの方を重く見て記録側に倒す）。
#[derive(Debug)]
pub struct PreflightOutcome {
    pub warnings: Vec<String>,
    pub denied_passthrough: Vec<(std::path::PathBuf, String, String)>,
    pub granted_passthrough: Vec<(std::path::PathBuf, bool)>,
    /// `preflight`が特権分離ヘルパーへ`GrantFsAllow`を委譲する経路を実際に通り、その際
    /// `wfp_chain_pipe`が`Some`だったため「処理完了後に`harness-netfilterd`を連鎖起動してほしい」
    /// という指示を実際に添えたかどうか（`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`付録D
    /// シナリオ(A)）。
    ///
    /// **「依頼した」ではなく「実際に起きた」を意味する**（BUG-093で意味を変えた）。かつては
    /// 依頼した時点で`true`にし、成否は追跡せず「呼び出し元はタイムアウトすれば使えなかったと
    /// 扱えばよい」としていたが、その「タイムアウト」は30秒の空待ちであり、しかも
    /// `record_net`の呼び出し元はそれを`NoWfp`＝パス2の中止として扱っていた
    /// （実機で発生。`privhelper.log`に記録が残っている）。いまは`privhelper`が結末を応答に
    /// 載せて返すので、ここには**起動が成立したときだけ**`true`が入る。
    ///
    /// `false`の場合（依頼しなかった／本体が既に管理者で直接付与した／連鎖起動に失敗した）は、
    /// 呼び出し元はシナリオ(B)（`NetfilterHandle::start`＝`runas`直接起動）へ**待たずに**
    /// フォールバックする。失敗した場合の理由は`warnings`に積まれる。
    pub netfilterd_chain_attempted: bool,
}

/// `preflight`のfs-allow昇格結果（`granted`パス一覧、`(path, reason)`失敗一覧）。
type FsAllowElevationOutcome = (Vec<std::path::PathBuf>, Vec<(std::path::PathBuf, String)>);

/// [BUG-101] **付与したACEが台帳に載っているか**を、`preflight`をどう抜けても必ず測るガード。
///
/// `Drop`にしてあるのは`passthrough_progress::begin`と同じ理由——この関数は`?`で抜ける経路を
/// 複数持ち、**そのうち3つ（traverse付与の失敗、`:566`/`:627`/`:639`）は付与ループの後・
/// 台帳への記録（`record_granted_paths`）の前にある**。つまり早期returnした実行では、
/// 既にマシンへ書いたACEが1件も記録されていない。手で閉じる形にすると、脱出経路が
/// 1つ増えるたびに書き忘れる（B-06）。
///
/// 正常に抜けるときは[`Self::finish`]で`warnings`へも積む——stderrの1行はTUIでは
/// 進行ログに流れて消えるが、`warnings`は「⚠ 対応が要ります」欄とマニフェストに残る
/// （BUG-096: 「表示した」は「記録した」ではない）。
struct SessionGrantAudit {
    profile_name: String,
    done: bool,
}

impl SessionGrantAudit {
    fn arm(profile_name: &str) -> Self {
        Self {
            profile_name: profile_name.to_string(),
            done: false,
        }
    }

    fn run(&mut self) -> Option<crate::tier2a::grant_audit::GrantAudit> {
        if self.done {
            return None;
        }
        self.done = true;
        let recorded = crate::tier2a::session_profile::granted_paths_for_current_session();
        let audit = crate::tier2a::grant_audit::audit_profile(
            crate::tier2a::grant_audit::Stage::Preflight,
            &self.profile_name,
            &recorded,
        )?;
        crate::tier2a::grant_audit::report(&audit);
        Some(audit)
    }

    /// 正常経路。測った結果を`warnings`へも残して閉じる。
    fn finish(mut self, warnings: &mut Vec<String>) {
        if let Some(summary) = self.run().and_then(|audit| audit.summary()) {
            warnings.push(summary);
        }
    }
}

impl Drop for SessionGrantAudit {
    fn drop(&mut self) {
        // 早期returnで抜けた経路。`warnings`はもう存在しないのでstderrだけに出す。
        let _ = self.run();
    }
}

/// BUG-059の回収: redirector DLLに残った、**生存していないセッション**宛のACEを剥がす。
///
/// 付与側（下記CoW分岐）に保険を入れて新規発生は止めたが、記録漏れの間に積み上がったACEは
/// 台帳に無いため`gc_dead_sessions`の撤収対象に入らない（実機に4件残留していた）。DLLは
/// harness自身の実行ファイルの隣という**既知の固定パス**なので、そこだけを直接掃く。
///
/// 失敗しても起動は止めない——これは後始末であって境界ではなく、ここで`Err`を返すと
/// 「掃除できないマシンではTier2aが起動できない」という筋の悪い依存を作る。
fn sweep_stale_redirector_dll_aces() {
    let live = crate::tier2a::session_profile::live_profile_names();
    for dll in redirector_dll_paths() {
        match revoke_stale_appcontainer_aces(&dll, &live) {
            Ok(removed) if !removed.is_empty() => {
                eprintln!(
                    "harness: removed {} stale AppContainer ACE(s) left on {} by sessions that are \
                     no longer running (see docs/bugs/BUG-059.md)",
                    removed.len(),
                    dll.display()
                );
            }
            Ok(_) => {}
            Err(e) => eprintln!(
                "harness: could not sweep stale AppContainer ACEs on {}: {e}",
                dll.display()
            ),
        }
    }
}

/// プロセスのカレントディレクトリにできるパスの実測上限（文字数）。
///
/// **`CreateProcessW`が新しいプロセスへ与えるカレントディレクトリは`MAX_PATH`から逃げられません。**
/// 末尾の区切りとNUL終端の分を含めて260に収まる必要がある＝ディレクトリ自体は258文字まで。
///
/// この開発機での実測（`LongPathsEnabled=1`、2026-08-06。[BUG-068](../../../../docs/bugs/BUG-068.md)）:
///
/// | 操作 | `longPathAware`マニフェスト無し | 有り |
/// |---|---|---|
/// | `SetCurrentDirectoryW`（自プロセス、295文字） | `ERROR_FILENAME_EXCED_RANGE`(206) | **成功** |
/// | `CreateProcessW`＋`lpCurrentDirectory`（295文字） | `ERROR_DIRECTORY`(267) | `ERROR_DIRECTORY`(267) |
/// | `CreateProcessW`＋継承（親のcwdが295文字） | （前提不成立） | `ERROR_INVALID_PARAMETER`(87) |
///
/// つまり**マニフェストのオプトインは自プロセスのcwdしか解放しません**（Microsoftの
/// 「最大ファイルパスの制限」ページが挙げる対象一覧にも`SetCurrentDirectoryW`はあるが
/// `CreateProcessW`は無い）。明示的に渡しても親から継承させても、子プロセスへ260超のcwdは
/// 与えられないので、harness側にマニフェストを足しても**この制限は変わりません**（実測済み。
/// 再検討する前にこの表を見ること）。境界は258文字で、259文字から失敗します。
///
/// `\\?\`前置も解決になりません。285文字のverbatim形も同じ267で失敗し、短いパスですら
/// verbatim形のcwdは`cmd.exe`が「UNCパスはサポートされません」としてWindowsディレクトリへ
/// 黙って切り替えます（＝verbatimをcwdに使ってはいけない）。
const MAX_CHILD_CWD_LEN: usize = 258;

/// workspaceを子プロセスのカレントディレクトリにできるか（[BUG-068](../../../../docs/bugs/BUG-068.md)の
/// 追加検証で判明した、harnessではなくWindows側の限界）。
///
/// 超えている場合、`smoke_test_spawn`が`CreateProcessW: ディレクトリ名が無効です (0x8007010B)`で
/// 落ちます——**存在する正しいディレクトリなのに「無効」と言われる**ので、原因に辿り着くのが
/// 難しい。ACEを付ける前にここで止め、理由と回避策を名指しします。
fn check_workspace_usable_as_child_cwd(workspace_root: &Path) -> Result<(), AppContainerError> {
    let len = workspace_root.to_string_lossy().encode_utf16().count();
    if len <= MAX_CHILD_CWD_LEN {
        return Ok(());
    }
    Err(AppContainerError::Preflight(format!(
        "the workspace path is {len} characters long; Windows cannot use a directory longer than \
         {MAX_CHILD_CWD_LEN} characters as a process working directory (the limit is MAX_PATH \
         including a trailing separator and the NUL terminator, and it is lifted by neither \
         LongPathsEnabled nor a \\\\?\\ prefix). Every shell isolation tier hits this at spawn \
         time, so `--tier1`/`--tier0` will not help either. Move the workspace somewhere shorter, \
         or map it to a drive letter (`subst X: \"<workspace>\"`). Read-only commands \
         (`harness changes`/`apply`) are unaffected: {}",
        workspace_root.display()
    )))
}

/// harness起動時に1回だけ呼ぶ。プロファイル作成→ACL付与→起動smokeテストの一連を行い、
/// いずれか失敗したら理由文字列を返す（`shell_tier::best_effort_tier`がTier1への降格理由
/// としてそのまま使う）。判断は実行前に完結させ、`run_shell`個々の呼び出し中には降格ロジックを
/// 一切持たせない（非冪等コマンドの二重実行を避けるための意図的判断）。
///
/// `passthrough`（D-13、fs passthrough allowlist）は各ルートへACEを付与したうえで到達性を
/// プローブする（D8）。到達不能な穴は`preflight`全体を失敗させず、戻り値の警告一覧に
/// 診断メッセージ（D9）を積むだけに留める（壊れた穴があってもworkspaceと他の穴は動き続ける）。
///
/// 実際に子を起こしてFS I/Oを試すプローブ群は[`super::preflight_probe`]が持つ。この関数の
/// 責務は**どのプローブをどの順で打つか**と、その結果からTier2aを選んでよいかを決めることに
/// 絞ってある。
pub fn preflight(
    workspace_root: &Path,
    passthrough: &[FsPassthrough],
    wfp_chain_pipe: Option<String>,
    write_mode: &WorkspaceWriteMode,
) -> Result<PreflightOutcome, AppContainerError> {
    // 常駐daemonからの連鎖起動を使わない既定形（`runas`＝UACが1回）。
    preflight_with_privhelper_launcher(
        workspace_root,
        passthrough,
        wfp_chain_pipe,
        write_mode,
        None,
    )
}

/// [`preflight`]の、**`privhelper`の起こし方を差し替えられる**版（D-60）。
///
/// `privhelper_launcher`が`Some`なら、常駐している昇格プロセス（`harness-netfilterd`）へ
/// 連鎖起動を依頼する——**UACが出ない**。起こせなければ`runas`へ落ちる（理由は`warnings`へ）。
///
/// **「後から必要になった昇格」をUAC 0回で通すための唯一の入口**である。harness本体は起動時に
/// 1回しかpreflightを通らないので`None`（＝[`preflight`]）でよく、これを使うのは
/// 「記録→承認→パス2」を繰り返す`harness-policy-editor`である。
#[allow(clippy::too_many_arguments)]
pub fn preflight_with_privhelper_launcher(
    workspace_root: &Path,
    passthrough: &[FsPassthrough],
    wfp_chain_pipe: Option<String>,
    write_mode: &WorkspaceWriteMode,
    privhelper_launcher: Option<crate::tier2a::privhelper::ChainLauncher<'_>>,
) -> Result<PreflightOutcome, AppContainerError> {
    let mut timing = PhaseTiming::start();
    // ACEを1本も付ける前に、そもそもこのworkspaceで子プロセスを起動できるかを確かめる。
    check_workspace_usable_as_child_cwd(workspace_root)?;
    timing.mark("check_workspace_usable_as_child_cwd");
    // D-37: プロファイルはセッション単位。共有package SIDをやめ、workspace・CoW upper_dir・
    // fs-allowの穴はこのセッションのSIDにだけ紐付ける（別セッション・別workspaceから到達
    // できないようにする）。祖先のtraverseだけはharness共通のcapability SIDが持つ（下記）。
    //
    // 起動のたびに、死んだセッションが残した資源をここで回収する（台帳＋生存マーカー、
    // 台帳が失われていても接頭辞付きプロファイルの列挙で回収できる）。
    //
    // **回収の内訳は必ず出す**（B-11）。特に「付与内容を台帳から復元できないので削除を見送った」
    // 件数は、放っておくと積もる一方なのに無言だと誰も気付けない——見送り自体は
    // 孤児ACEを作らないための正しい判断だが、増え続けるなら「台帳エントリが失われる経路」が
    // 別にあるという診断になる（BUG-101）。
    //
    // stderrへ出すのは、stdoutが`--output-format json`/`jsonl`の機械可読出力に予約されているため
    // （B-24、BUG-064が同じ経路で`jq`を壊した）。
    let reclaim = crate::tier2a::session_profile::gc_dead_sessions_reporting(&revoke_session_grant);
    if let Some(summary) = reclaim.summary() {
        eprintln!("note: {summary}");
    }
    timing.mark("gc_dead_sessions");
    let profile_name =
        crate::tier2a::session_profile::begin_session().map_err(AppContainerError::Preflight)?;
    // [BUG-101] **この行より後で付けたACEは、必ず台帳と突き合わせてから抜ける。**
    // 武装をここに置くのは、この直後の`ensure_profile`以降が「このセッションのSID宛に
    // ACEを付け得る全区間」だからである（`SessionGrantAudit`のdoc）。
    let audit_guard = SessionGrantAudit::arm(&profile_name);
    let sid = ensure_profile(&profile_name)?;
    // [BUG-101/B-05] 台帳へ「どのSID宛に付与したか」を書くのは**呼び出し元**（`run_agent`と
    // ポリシーエディタのパス2）で、あちらは`current_session_grant_sid()`から値を取る。
    // ここで実際に使う主体とずれると、撤収側は「台帳に記録が無いACE」を見ることになり、
    // 名前を失った時点で剥がせなくなる。**ずれを無言にしない**ため、その場で検算する。
    if let (Ok(actual), Some(recorded)) = (
        crate::win_common::sid_to_string(sid.as_psid()),
        current_session_grant_sid(),
    ) {
        if actual != recorded {
            eprintln!(
                "warning: the SID this session grants with ({actual}) differs from the one the \
                 ledger will record ({recorded}); revoking these ACEs by record will not work \
                 (see docs/bugs/BUG-101.md)"
            );
        }
    }
    timing.mark("begin_session + ensure_profile");
    sweep_stale_redirector_dll_aces();
    timing.mark("sweep_stale_redirector_dll_aces");
    // 祖先traverseの付与先（D-37）。package SIDと違いセッションを跨いで永続する。
    let traverse_sid = traverse_capability_sid()?;

    // workspaceのアクセスモード（通常起動=RWX / `--cow`=RO、将来`--cow_exec`=RXを追加予定）は
    // 同じworkspaceに対して混在させてはいけない——ACEはファイルに1つしか付けられないため、
    // モードが違うセッションが同時に動くと片方の前提を裏切る（例: ROのはずが後から来た
    // RWXセッションのせいで書けてしまう）。ACE付与の前に、名前付きmutexで他モードが
    // 使用中でないか確認し、自モードの生存マーカーを確保する
    // （`crate::tier2a::workspace_ledger::begin_workspace_mode`のdoc参照、モード衝突チェックと
    // マーカー作成は内部で`with_named_lock`により直列化されるため、2プロセスがほぼ同時に
    // 別モードで起動しても早い者勝ちの事故にはならない）。
    let workspace_mode = match write_mode {
        WorkspaceWriteMode::DirectRw => "rwx",
        WorkspaceWriteMode::Cow { .. } => "ro",
    };
    let canonical_workspace_root = workspace_root.canonicalize().map_err(|e| {
        AppContainerError::Preflight(format!(
            "failed to canonicalize workspace root {}: {e}",
            workspace_root.display()
        ))
    })?;
    crate::tier2a::workspace_ledger::begin_workspace_mode(
        &canonical_workspace_root,
        workspace_mode,
    )
    .map_err(AppContainerError::Preflight)?;
    crate::tier2a::workspace_ledger::record_workspace_grant(
        &canonical_workspace_root,
        workspace_mode,
    );

    // D-54: workspaceツリーへ付けるACEの主体。**セッションのpackage SIDではなく、この
    // workspace＋モードに固有のcapability SID**へ付ける。付与の形（どのツリーへ何を許すか）は
    // workspaceとモードで決まるものであって、セッションの属性ではない——主体をその形に
    // 合わせることで、26万ノードへの継承ACEの伝播を**ワークスペースにつき一度きり**にする
    // （毎起動で払っていた実測60秒が消える、BUG-081）。名前はワークスペースごとのランダム
    // 秘密から導出され、サンドボックスから読めない台帳にだけ存在する
    // （`crate::tier2a::workspace_capability`のdoc）。
    let workspace_cap = workspace_capability_sid(&canonical_workspace_root, workspace_mode)?;
    let workspace_cap_psid = Some(workspace_cap.as_psid());

    // D-30: `write_mode`がACL付与方針を唯一決める。`match`を全分岐（`..`無し）にすることで、
    // `WorkspaceWriteMode`へバリアントを追加した際にACL決定漏れをコンパイルエラーにする。
    //
    // **workspace本体は`record_granted_path`しない**（D-54）。あれは「このセッションが撤収
    // 責任を負う」という表明で、記録すると`end_session`/`gc_dead_sessions`がツリー全体の
    // `revoke_ace_recursive`（実測30.8秒）を回してしまう。capability宛のACEはセッションより
    // 長生きするのが仕様であり、撤収は`harness fs revoke-workspace`が明示的に行う。
    let workspace_mask = match write_mode {
        WorkspaceWriteMode::DirectRw => {
            // 既定（D-29）。[BUG-082 Part B] rootへ継承ACEを1件、**伝播なし**で付けるだけ
            // （`grant_workspace_root_rw_fast`のdoc）——既存子孫への伝播は`grant_job`の
            // 背景フェーズへ委ねる。2回目以降の起動は冪等スキップでWin32書込0回。
            grant_workspace_root_rw_fast(workspace_root, workspace_cap.as_psid())?;
            timing.mark("grant_workspace_root_rw_fast(workspace_root)");
            workspace_rwx_mask()
        }
        WorkspaceWriteMode::Cow { upper_dir } => {
            // `--cow`（D-30）。workspaceはRead/Execute/Traverseのみ（D-13と同じ関数）。
            // Redirector DLLが無効・回避されても、この時点でACLがROである限り
            // workspace本体への書込は`ACCESS_DENIED`でfail-closeする。
            grant_workspace_root_ro_fast(workspace_root, workspace_cap.as_psid())?;
            // upper_dirは**セッション専有**（他セッションと共有しない）なので、主体は
            // 従来どおりセッションのpackage SIDのままにする。D-54が置き換えるのは
            // 「ワークスペースにつき一度きりで済むはずの付与」だけで、こちらは該当しない。
            std::fs::create_dir_all(upper_dir)
                .map_err(|e| AppContainerError::Preflight(e.to_string()))?;
            grant_ace_inheritable_rw(upper_dir, sid.as_psid())?;
            crate::tier2a::session_profile::record_granted_path(upper_dir);
            // `harness cow status`/`apply`/`list`がworkspace_rootを引けるよう、upper_dir自身に
            // 由来を記録する（`workspace_ledger::write_cow_session_meta`のdoc参照）。
            crate::tier2a::workspace_ledger::write_cow_session_meta(
                upper_dir,
                &canonical_workspace_root,
                upper_dir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown-session"),
            );
            // CoWのupper_dirはセッション専有（他セッションと共有しない）なので、他モードとの
            // 衝突チェックは不要。セッションID（upper_dirの最終パス要素、
            // `cow_upper_dir_for_session`参照）で名前を付けた生存マーカーだけを確保し、
            // `harness cow discard`等が「まだこのセッションが動いているか」を判定できるように
            // する（`plans/AppContainerベース Copy-on-Write ワークスペース設計書.md`Phase 6の
            // 前段）。
            let session_id = upper_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown-session");
            crate::tier2a::workspace_ledger::hold_cow_session_marker(session_id).map_err(|e| {
                AppContainerError::Preflight(format!(
                    "failed to create CoW session marker for {session_id}: {e}"
                ))
            })?;
            fs_access_mask(FsAccess::ReadExec)
        }
    };
    // D-05/D-09の層3。剥がす主体は**capability SID（今の継承元）とpackage SID（D-37時代の
    // 残骸）の両方**——片方だけだと剥がし残した側から制御面が書ける（`revoke.rs`のdoc参照）。
    let protected_nodes = protect_harness_control_dir_from_appcontainer(
        workspace_root,
        &[workspace_cap.as_psid(), sid.as_psid()],
    )?;
    // [BUG-084] 件数を出す。層3のhard-denyは「1件も掛かっていない」が症状として現れない
    // （BUG-083はそれが恒常的に起きていた）ので、`HARNESS_PREFLIGHT_TIMING=1`で事後確認
    // できる形にしておく。
    timing.mark(&format!(
        "protect_harness_control_dir_from_appcontainer ({protected_nodes} nodes)"
    ));

    // 保護DACL（BUG-020の残存損害等）で継承が届かなかった既存子孫の救済が要るか。
    // **ワークスペースにつき一度きり**で、実行は`preflight`の最後（他のACL作業を全て終えた後）に
    // 背景スレッドへ委ねる（`grant_job`のdoc「DACL書込の競合を避けるための約束」）。
    let needs_descendant_fix = !crate::tier2a::workspace_capability::tree_is_verified(
        &canonical_workspace_root,
        workspace_mode,
    );

    // workspace_root（Cow時はupper_dirも）の祖先traverseチェーンが不足していないか事前に判定する
    // （読み取り専用、UAC無し）。不足分は下のfs-allow昇格要求と合流させ、1回のprivhelper呼び出し
    // （起動あたりUAC最大1回）で解消する。以前はtraverse不足を`smoke_test_spawn`（下記）が
    // リアクティブに検知してTier1bへ静かに降格するだけだったが、privhelper経由で自動付与できる
    // 経路（`GrantWorkspaceAccess`）が整ったため、ここで先回りして解消する
    // （`plans/DESIGN-SANDBOX-PRIVSEP.md` D-16「特権昇格デーモンを使う際の注意点」参照）。
    // D-37: 見るのは**祖先だけ**。workspace_root/upper_dir自身への到達権はセッション固有の
    // package SID宛の継承ACE（すぐ上で付与済み）が与えるので、共通capability SIDのACEを
    // そこへ要求してはいけない。ここでleafまで含めると、セッションのたびに新しいworkspaceで
    // 「capability SIDのACEが無い」と判定され、毎回昇格を要求してしまう。
    let mut traverse_targets: Vec<std::path::PathBuf> = workspace_root
        .parent()
        .map(|p| p.to_path_buf())
        .into_iter()
        .collect();
    if let WorkspaceWriteMode::Cow { upper_dir } = write_mode {
        if let Some(parent) = upper_dir.parent() {
            traverse_targets.push(parent.to_path_buf());
        }
    }
    // D-45（W1の実測から確定、`plans/etw-spike/RESULTS.md` §19）: `--fs-allow`で許可した
    // パスの**親**もここへ入れる。対象自身への継承ACEだけでは、削除（`Remove-Item`）と
    // 移動（`Move-Item`）が失敗する——この2つは祖先ディレクトリを「通過」ではなく
    // **オープン**するため、対象へ到達する前に祖先で拒否される（拒否は対象ファイルではなく
    // 祖先に出るので、対象パスだけを見ていると「失敗しているのに拒否0件」に見える）。
    // 読取・書込・実行・`cmd /c type`はフルパスのファイルopenなので祖先未付与でも通る。
    //
    // マスクは現行の`FILE_TRAVERSE|FILE_READ_ATTRIBUTES`のままでよい（§19.2で7操作すべてが
    // これで通ることを実測した）。`SYNCHRONIZE`・`FILE_LIST_DIRECTORY`まで広げると
    // `C:\`・`C:\Users`が列挙可能になり機密性の実害が出るので広げない。
    //
    // **親を入れる（leafは入れない）**。leafへの到達権はこのセッション固有のpackage SIDが
    // 継承ACEで与える（上のfs-allowループ）。ここでcapability SIDのACEをleafへ要求すると、
    // 新しいパスを指定するたびに「capability SIDのACEが無い」と判定され毎回昇格を求めてしまう。
    //
    // 存在しないパスは入れない——後段のループが`path does not exist, skipped`として弾く
    // ものへ、先回りしてマシンのACLを書き換える理由が無い。
    for requested in passthrough {
        if !requested.path.exists() {
            continue;
        }
        let Some(parent) = requested.path.parent() else {
            continue;
        };
        let parent = parent.to_path_buf();
        if !traverse_targets.contains(&parent) {
            traverse_targets.push(parent);
        }
    }
    let missing_traverse: Vec<std::path::PathBuf> = traverse_targets
        .into_iter()
        .filter(|target| !traverse_chain_sufficient(target, traverse_sid.as_psid()))
        .collect();

    let mut warnings = Vec::new();

    // D-37: Redirector DLL（`--cow`の透過性）はworkspaceの外＝harness.exeの隣にあるため、
    // workspaceへの継承ACEでは覆えない。共有package SIDだった頃はリポジトリrootへの継承ACEが
    // たまたま`target/debug/*.dll`まで届いていたが、セッションごとにSIDが変わる今は明示的に
    // 読取+実行を与える必要がある（無ければ注入が失敗し、境界＝ACLは効いたまま透過性だけが失われる）。
    if matches!(write_mode, WorkspaceWriteMode::Cow { .. }) {
        for dll in redirector_dll_paths() {
            match grant_ace_inheritable_access(&dll, sid.as_psid(), FsAccess::ReadExec) {
                Ok(()) => crate::tier2a::session_profile::record_granted_path(&dll),
                // BUG-059 / BUG-017と同じ保険: `Err`は「何も起きなかった」を意味しない。
                // 副作用を伴う関数が途中で失敗したとき、ACEが既に載っているかは呼び出し側からは
                // 分からない。載っているのに記録しないと**撤収経路の無い孤立ACE**になる
                // （実機に4件残留していた）。rootを権威的にプローブして実在すれば記録する。
                // `grant_ace_inheritable_access`側のファイル分岐（層1）を直した後も、この保険は
                // 残す——記録漏れの代償（孤立ACE）は、幻の台帳エントリより重い。
                Err(e) => {
                    if matches!(sid_ace_mask(&dll, sid.as_psid()), Ok(Some(_))) {
                        crate::tier2a::session_profile::record_granted_path(&dll);
                        warnings.push(format!(
                            "cow: granting the redirector DLL to this session reported an error \
                             ({}): {e} -- but the ACE is present on the file, so it was recorded \
                             in the session ledger and will be revoked at session end",
                            dll.display()
                        ));
                    } else {
                        warnings.push(format!(
                            "cow: failed to grant the redirector DLL to this session ({}): {e}",
                            dll.display()
                        ));
                    }
                }
            }
        }
    }
    let mut denied_passthrough: Vec<(std::path::PathBuf, String, String)> = Vec::new();
    let mut granted_passthrough: Vec<(std::path::PathBuf, bool)> = Vec::new();
    // 本体プロセス内（非管理者）でACCESS_DENIEDになったエントリ（システム保護パス等）だけを
    // ここへ集め、後段で1回の特権分離ヘルパー要求へまとめる（起動あたりUAC最大1回、
    // `TIER1A-PRIVHELPER-HANG.md`「引き継ぎTODO」の決定）。
    let mut needs_elevation: Vec<crate::tier2a::privhelper::FsAllowGrant> = Vec::new();
    let mut netfilterd_chain_attempted = false;
    // 到達性プローブ（D8）の対象。**ここでは測らず、全ての付与が終わってから1プロセスで
    // まとめて測る**（`probe_passthrough_batch`）。理由は2つ:
    //
    // 1. **速度**: 以前は1件につきAppContainer内でPowerShellを1プロセス起こしていた。
    //    起動だけで実測182ms/回なので、workspace外の穴が数百件あるドメイン（ポリシー
    //    エディタの`cargo`ドメインで668件）では数分の無反応になっていた。しかも
    //    `already_sufficient`でも走るので、付与をスキップする2回目以降も同じ時間を払っていた。
    // 2. **正しさ**: 下の昇格経路で祖先のtraverseが直ることがある。付与の途中で測ると
    //    「直る前の状態」を到達不能として報告してしまう。
    let mut probe_targets: Vec<FsPassthrough> = Vec::new();
    // session ledgerへ記録するパス。**1件ずつ`update`を呼ばない**——1回の`update`は
    // 全文読取＋`.bak`への全文コピー＋全文書込であり、この台帳は実測66KBある。
    // 668件のドメインでは約130MBのI/Oになり、しかも`already_sufficient`（ACEを1件も
    // 書かない2回目以降）でも同じだけ払う（`record_granted_paths`のdoc）。
    let mut ledger_paths: Vec<std::path::PathBuf> = Vec::new();

    // 付与フェーズの進捗をUIへ見せる（`passthrough_progress`のdoc参照）。この区間は
    // 数百件になり得るので、**何件目かが見えないと「固まった」と読まれる**。
    // ガードなので、この下のどの`?`で抜けてもフェーズは閉じる。
    let grant_phase = passthrough_progress::begin(passthrough.len());

    for requested in passthrough {
        passthrough_progress::advance();
        if !requested.path.exists() {
            let reason = "path does not exist, skipped".to_string();
            warnings.push(format!("fs-allow {} : {reason}", requested.path.display()));
            denied_passthrough.push((
                requested.path.clone(),
                requested.access.label().to_string(),
                reason,
            ));
            continue;
        }

        // D-30（`--cow`）: fs-allowの`:rw`要求は、実際にOSへ付与するACLではRead止まりにする
        // （実行権限は与えない、`FsAccess::Read`。`FsAccess::ReadExec`ではない点に注意）。
        // `--cow`が存在する理由は「変更のあったファイルだけを単位としてレビュー・ロールバック
        // できること」（CoW＝ファイル単位の巻き戻し可能性が本質、スナップショット全体コピー
        // 方式ではない）であり、明示的にRO/ReadExecなfs-allowエントリはそもそも書込の余地が
        // 無いので対象外——ここで動的にRWをRO化しているのは、あくまで「元々RWだったものへ
        // 強制的にRedirector DLLのフックを通す書込経路」を作るための道具であって、頼まれても
        // いない実行権限まで付与する理由は無い（ユーザー指摘により`ReadExec`から`Read`へ訂正、
        // 2026-08-02）。workspace本体が`--cow`下で`grant_ace_inheritable_ro`
        // （`FsAccess::ReadExec`）を使うのは、workspace内のツール・スクリプトを実行できる
        // 必要があるというworkspace固有の事情であり、任意の外部fs-allowパスには適用されない。
        // 書込境界はACLであり、Redirector DLLの`_ext` captureはあくまで透過性のための利便性
        // （D-01「フックは境界にしない」）。ここで実RWを付与してしまうと、DLL注入失敗・バグ・
        // 迂回時にfail-closeせず実ファイルへ直接書けてしまい、workspace本体との一貫性が崩れる
        // （BUG-043発見時の実機検証を経てユーザー指摘により追加、2026-08-02）。`requested`
        // （ユーザーが本来要求したアクセス）は`granted_passthrough`の記録に使い、
        // `ext_capture_roots`（`crates/harness-tools/src/shell.rs`）の判定材料として残す。
        //
        // **和（`ReadWriteExec`）が来たときは実行権だけ残す。** ここで落としているのは
        // 「書込をRedirector DLLのフックへ強制的に通す」ためであって、ユーザーが明示的に
        // `fs.read_exec`で要求した実行権を取り上げる理由は無い（上の「頼まれてもいない実行権限まで
        // 付与する理由は無い」の裏返し——頼まれた実行権を消す理由も無い）。
        let downgrade_to_ro = matches!(write_mode, WorkspaceWriteMode::Cow { .. })
            && requested.access.is_read_write();
        let effective_access = if downgrade_to_ro {
            if requested.access.is_exec() {
                FsAccess::ReadExec
            } else {
                FsAccess::Read
            }
        } else {
            requested.access
        };
        let fp = FsPassthrough {
            path: requested.path.clone(),
            access: effective_access,
            forced: requested.forced,
            // [D-63] スコープは`--cow`でも変えない。上でRO化しているのは**アクセス種別**であって
            // 範囲ではない（範囲を狭めると、宣言した配下がRedirector DLL経由でも読めなくなる）。
            scope: requested.scope,
        };
        let fp = &fp;
        let requested_rw = requested.access.is_read_write();

        // 事前チェック（決定1）: 既にsid宛のACEが要求を満たしていれば、本体内のwalkも
        // privhelperのUACも一切スキップする（ユーザ所有パスの再実行はUAC無し）。
        //
        // [D-63] **満たしているかの判定にマスクと継承フラグの両方を使う**
        // （`ExplicitAce::satisfies`）。マスクだけを見ていると、同じパスへ素の宣言（非継承）と
        // `**`宣言（継承）が来たとき、先に付いた非継承ACEで足りていると判定して**再帰要求が
        // 黙って非継承のまま通る**（B-10）。1プロセスが複数ドメインを回すポリシーエディタの
        // パス2では、これは実際に起こり得る組み合わせである。
        let required = required_passthrough_mask(fp.access);
        let required_inherit = required_inherit_flags(fp.scope);
        let existing_ace = sid_explicit_ace(&fp.path, sid.as_psid()).ok().flatten();
        let already_sufficient =
            matches!(existing_ace, Some(ace) if ace.satisfies(required, required_inherit));
        // [D-63] 宣言はオブジェクト単体なのに、実DACLには継承ACEが載っている
        // （前のセッションが`**`で開いた・ユーザーが手で付けた）。**狭めはしない**——
        // 継承元を書き換えても既に配下へ降りたコピーは消えず、片手落ちの変更になる。
        // ただし「宣言より広い状態が現に在る」ことは黙らせない（B-09）。
        if already_sufficient && !fp.scope.is_recursive() {
            if let Some(ace) = existing_ace {
                if ace.is_inheritable() {
                    warnings.push(format!(
                        "fs-allow {} : declared as a single object, but an inheritable ACE for this \
                         session's SID is already on it, so the whole subtree stays open. harness \
                         does not narrow it here (removing the inheritable ACE would not remove the \
                         copies already propagated to descendants). Run `harness fs revoke {}` if \
                         you want it closed.",
                        fp.path.display(),
                        fp.path.display()
                    ));
                }
            }
        }
        if already_sufficient {
            // **Win32を1回も呼んでいない**ことを数える。ここが2回目以降で総数に一致する
            // ことが「差分適用になっている」の証拠になる（`passthrough_progress`のdoc）。
            passthrough_progress::record_already_sufficient();
            granted_passthrough.push((fp.path.clone(), requested_rw));
            // BUG-057: 付与を**スキップした**場合もsession ledgerへ記録する。ACEを実際に
            // 書いたのが前のセッションだったとしても、載っているのは**このセッションのSID宛**
            // であり（D-37でSIDはセッション固有）、撤収責任はこのセッションにある。
            // 記録しないと`end_session`の撤収対象から漏れ、「fs passthroughはセッション終了で
            // 失効する」（D-37の仕様）が破れる。
            ledger_paths.push(fp.path.clone());
            probe_targets.push(fp.clone());
            continue;
        }

        // [D-63] **宣言された範囲でだけ開く。** 素のパスはそのオブジェクト1つ、`<path>/**`は
        // 継承ACE。ここを`grant_ace_inheritable_access`固定にしていたのが、D-62で候補を畳むのを
        // やめた後も「観測された2件を承認したらサブツリー全体が開く」状態が残っていた理由である。
        let grant_result = grant_ace_scoped(&fp.path, sid.as_psid(), fp.access, fp.scope);
        match grant_result {
            Ok(()) => {
                // 実際にACEを書いた1件。
                passthrough_progress::record_granted();
                granted_passthrough.push((fp.path.clone(), requested_rw));
                ledger_paths.push(fp.path.clone());
                probe_targets.push(fp.clone());
            }
            Err(_) => {
                // forced（--force-system-acl, D-19）は host パスの絶対拒否ゲートを**UACの前に**
                // 通す（禁止パスなら昇格させずここで警告に落とす。無駄なUACを出さない二重化）。
                if fp.forced {
                    if let Some(reason) = is_force_grant_forbidden(&fp.path) {
                        denied_passthrough.push((
                            fp.path.clone(),
                            fp.access.label().to_string(),
                            format!("forced system-ACL grant refused: {reason}"),
                        ));
                        warnings.push(format!(
                            "fs-allow {} : forced system-ACL grant refused: {reason}",
                            fp.path.display()
                        ));
                        continue;
                    }
                }
                // 本体（非管理者）内では書けなかった。システム保護パス（所有者がSYSTEM/
                // TrustedInstaller等）の可能性があるため、即座に警告へ落とさず後段の
                // 特権分離ヘルパー経路へ回す。
                needs_elevation.push(crate::tier2a::privhelper::FsAllowGrant {
                    path: fp.path.clone(),
                    access: fp.access,
                    forced: fp.forced,
                    // [D-63] 昇格へ回しても宣言の範囲は変わらない。
                    scope: fp.scope,
                });
            }
        }
    }

    if !missing_traverse.is_empty() || !needs_elevation.is_empty() {
        let elevated: Result<FsAllowElevationOutcome, String> =
            if crate::tier2a::privhelper::is_elevated() {
                // 本体が既に管理者（§5.3、grant-traverseの`*_direct`と同じ考え方）:
                // ヘルパーを経由せずその場で直接付与する。traverseが不足していれば先に解消する
                // （workspace_root/upper_dirへ到達できなければfs-allow付与自体が無意味なため）。
                for target in &missing_traverse {
                    let (granted_nodes, result) =
                        grant_traverse_chain(target, traverse_sid.as_psid());
                    for node in &granted_nodes {
                        crate::tier2a::traverse_ledger::record_traverse_grant(node);
                    }
                    if let Err(e) = result {
                        return Err(AppContainerError::Preflight(format!(
                            "failed to grant traverse ACE (admin, direct) for {}: {e}",
                            target.display()
                        )));
                    }
                }
                let mut granted = Vec::new();
                let mut failures = Vec::new();
                for entry in &needs_elevation {
                    // forcedは書込前に絶対拒否ゲートを通し、通過分のみ`SeRestorePrivilege`下で付与する
                    // （dispatch側と同じ防壁。本体が既に管理者の経路でも同一の不変条件を保つ）。
                    if entry.forced {
                        if let Some(reason) = is_force_grant_forbidden(&entry.path) {
                            failures.push((entry.path.clone(), reason));
                            continue;
                        }
                    }
                    // [D-63] 本体が既に管理者の直接付与も**同じスコープ分岐を通る**
                    // （3つの入口のうち1つだけ従わない形を作らない、B-02）。
                    let do_grant =
                        || grant_ace_scoped(&entry.path, sid.as_psid(), entry.access, entry.scope);
                    let result = if entry.forced {
                        with_restore_privilege(do_grant)
                    } else {
                        do_grant()
                    };
                    match result {
                        Ok(()) => granted.push(entry.path.clone()),
                        Err(e) => failures.push((entry.path.clone(), e.to_string())),
                    }
                }
                Ok((granted, failures))
            } else {
                // [BUG-101] **委譲した付与は、このプロセスのDACL書込の絞り口を通らない**
                // （書くのは昇格側のプロセス）。ここで「依頼した」ことだけを残し、実際に
                // 載ったかは自己検証のDACL実測が決める——依頼と結果を同じ値にしない（B-09）。
                for entry in &needs_elevation {
                    crate::tier2a::grant_audit::note_delegated_grant(&entry.path, sid.as_psid());
                }
                match crate::tier2a::privhelper::run_privileged_workspace_access(
                    missing_traverse.clone(),
                    needs_elevation.clone(),
                    wfp_chain_pipe.clone(),
                    privhelper_launcher,
                ) {
                    Ok((traverse_granted, traverse_error, granted, failures, netfilterd_chain)) => {
                        // **「依頼した」ではなく「実際に起きた」を返す**（BUG-093）。
                        // 以前はここで`wfp_chain_pipe.is_some()`を立てていたため、privhelperの
                        // 連鎖起動が黙って失敗しても呼び出し元はシナリオAを選び、
                        // `ConnectNamedPipe`が30秒タイムアウトしてから`NoWfp`で落ちていた。
                        netfilterd_chain_attempted = match netfilterd_chain {
                            Some(Ok(())) => true,
                            Some(Err(reason)) => {
                                warnings.push(format!(
                                "WFPデーモンをprivhelperから連鎖起動できませんでした（{reason}）。\
                                 代わりに直接起動します——UACがもう1回出ます。"
                            ));
                                false
                            }
                            // 依頼していない、または連鎖起動の結末を名乗れない旧ヘルパー。
                            // どちらも「自前で起こす」（シナリオB）で正しい。
                            None => false,
                        };
                        for node in &traverse_granted {
                            crate::tier2a::traverse_ledger::record_traverse_grant(node);
                        }
                        if let Some(reason) = traverse_error {
                            if !missing_traverse.is_empty() {
                                return Err(AppContainerError::Preflight(format!(
                                "failed to grant traverse ACE via privilege-separation helper: \
                                 {reason}"
                            )));
                            }
                        }
                        Ok((granted, failures))
                    }
                    Err(e) => {
                        // traverseが不足していて、それがprivhelper経由でも解消できなかった場合は
                        // Tier2a自体が成立しない（fail-close、workspace FS I/Oが動かない）ため即座に
                        // 打ち切る。UAC拒否（`ElevationDeclined`）もここに含まれる。
                        if !missing_traverse.is_empty() {
                            return Err(AppContainerError::Preflight(format!(
                                "traverse ACE grant via privilege-separation helper failed (UAC \
                             declined or helper error?): {e}"
                            )));
                        }
                        Err(e.to_string())
                    }
                }
            };

        match elevated {
            Ok((granted, failures)) => {
                for path in &granted {
                    let writable = needs_elevation
                        .iter()
                        .find(|e| &e.path == path)
                        .map(|e| e.access.is_read_write())
                        .unwrap_or(false);
                    granted_passthrough.push((path.clone(), writable));
                    // BUG-057: 昇格経由（privhelper / 本体が既に管理者の直接付与、どちらも
                    // この`granted`へ合流する）の付与もsession ledgerへ記録する。ここが
                    // 抜けていたため、`fs-passthrough-ledger.json`（`harness fs revoke`が見る）
                    // には載るのに`end_session`の自動撤収からは漏れていた。
                    // 昇格経由（privhelper／本体が既に管理者）の付与も「書いた1件」に数える
                    // ——どの経路で書いたかではなく、**マシンのACLを変えたか**が知りたい事実。
                    passthrough_progress::record_granted();
                    ledger_paths.push(path.clone());
                    if let Some(fp) = passthrough.iter().find(|fp| &fp.path == path) {
                        probe_targets.push(fp.clone());
                    }
                }
                for (path, reason) in &failures {
                    let access = needs_elevation
                        .iter()
                        .find(|e| &e.path == path)
                        .map(|e| e.access)
                        .unwrap_or(FsAccess::ReadExec);
                    let writable = access.is_read_write();
                    // BUG-017: grant_ace_recursive/grant_ace_inheritable_roはroot(先頭ノード)から
                    // 順に付与するため、途中の子孫(TrustedInstaller所有等)で失敗しても、rootには
                    // 既にACEが載っている場合がある。「失敗」扱いで台帳へ記録しないと、実FS上には
                    // ACEが残るのに撤収経路が無い孤立ACEになる。rootを権威的にプローブし、ACEが
                    // 実在すれば台帳へ記録して`fs revoke`で後から掃除できるようにする。
                    if matches!(sid_ace_mask(path, sid.as_psid()), Ok(Some(_))) {
                        granted_passthrough.push((path.clone(), writable));
                        // BUG-057: 部分適用でACEが実在するなら、`end_session`の撤収対象にも入れる
                        // （`fs revoke`だけでなく自動撤収からも漏らさない）。
                        ledger_paths.push(path.clone());
                        warnings.push(format!(
                            "fs-allow {} : partially applied via privilege-separation helper \
                             (D-16) -- some descendant failed ({reason}), but the root itself now \
                             carries the sandbox ACE; recorded in the ledger so `harness fs revoke \
                             {}` can clean it up",
                            path.display(),
                            path.display()
                        ));
                    } else {
                        denied_passthrough.push((
                            path.clone(),
                            access.label().to_string(),
                            format!("ACE grant failed (via privilege-separation helper, D-16): {reason}"),
                        ));
                        warnings.push(format!(
                            "fs-allow {} : ACE grant failed (via privilege-separation helper, \
                             D-16): {reason}",
                            path.display()
                        ));
                    }
                }
            }
            Err(reason) => {
                for entry in &needs_elevation {
                    if matches!(sid_ace_mask(&entry.path, sid.as_psid()), Ok(Some(_))) {
                        granted_passthrough
                            .push((entry.path.clone(), entry.access.is_read_write()));
                        // BUG-057: 上と同じ（ヘルパーが完走できなかった場合の部分適用）。
                        ledger_paths.push(entry.path.clone());
                        warnings.push(format!(
                            "fs-allow {} : partially applied -- the privilege-separation helper \
                             (D-16) could not fully complete ({reason}), but the root itself now \
                             carries the sandbox ACE; recorded in the ledger so `harness fs revoke \
                             {}` can clean it up",
                            entry.path.display(),
                            entry.path.display()
                        ));
                    } else {
                        denied_passthrough.push((
                            entry.path.clone(),
                            entry.access.label().to_string(),
                            format!(
                                "ACE grant failed: access denied in-process, and the privilege-separation helper (D-16) could not complete either: {reason}"
                            ),
                        ));
                        warnings.push(format!(
                            "fs-allow {} : ACE grant failed: access denied in-process, and the \
                             privilege-separation helper (D-16) could not complete either: {reason}",
                            entry.path.display()
                        ));
                    }
                }
            }
        }
    }

    // **撤収責任の記録は、付与が全部終わった直後にここで1回だけ書く**（BUG-057の要件は
    // 「記録が漏れないこと」であって「1件ずつ書くこと」ではない）。付与とこの書込の間に
    // プロセスが落ちるとACEが台帳に載らないが、その窓は本体・昇格ヘルパーとも
    // 付与を終えた直後のミリ秒であり、**子プロセスはまだ1つも起きていない**。
    // 1件ずつ書くと668件で約130MBのI/Oになり、毎回数秒を確実に失う（`record_granted_paths`）。
    crate::tier2a::session_profile::record_granted_paths(&ledger_paths);

    // 付与フェーズはここで終わり（以降は到達性プローブとスモークテスト）。明示的に落として、
    // UIが「ACE付与 N/N」を出し続けないようにする。
    drop(grant_phase);

    // [BUG-101] **付与直後に、実マシンのDACLと台帳を突き合わせる。**
    // 記録するつもりだった集合（`ledger_paths`）と台帳を比べても、付与側の思い込みが
    // 両辺に乗るだけで差は出ない。見るのは実測したACEである（`grant_audit`のdoc）。
    audit_guard.finish(&mut warnings);
    timing.mark("grant audit (BUG-101)");

    // D8: 到達性プローブは**ここで1回だけ**行う（付与も昇格も全部終わった後）。
    // 対象が0件なら子プロセスは1つも起こさない。
    match probe_passthrough_batch(
        sid.as_psid(),
        traverse_sid.as_psid(),
        workspace_cap_psid,
        workspace_root,
        &probe_targets,
    ) {
        BatchProbeOutcome::Measured(results) => {
            for (fp, diagnosis) in probe_targets.iter().zip(results) {
                if let Some(diagnosis) = diagnosis {
                    denied_passthrough.push((
                        fp.path.clone(),
                        fp.access.label().to_string(),
                        diagnosis.clone(),
                    ));
                    warnings.push(diagnosis);
                }
            }
        }
        // **1つの事実は1回だけ言う。** 全件へ同じ文言を配ると数百件の同一警告になる（B-09）。
        // 「測れなかった」を「到達可」と混ぜないために、警告としては必ず出す（B-10）。
        BatchProbeOutcome::NotRun(reason) => warnings.push(format!(
            "fs-allow: could not verify reachability for {} passthrough root(s) from inside the \
             sandbox ({reason}). The ACE grants themselves were applied; only the D8 reachability \
             check was skipped",
            probe_targets.len()
        )),
    }
    timing.mark("fs-allow reachability probe");

    // D-30: `FS_IO_PROBE_COMMAND`はprobe_dirへの書込を試みる。Cowモードではworkspace自体が
    // 意図的にROなので、probe_dirをworkspace配下に置くと「workspaceが書けない」という
    // Cowモードの正しい挙動を誤ってtraverse ACE不足として誤診断してしまう。probe_dirは
    // 書込可能であるべき場所（DirectRw時はworkspace、Cow時はupper_dir）に置く。上のtraverse
    // 自動付与を経た後の保険として、未知の原因によるFS I/O拒否をここで最終確認する。
    let probe_base = match write_mode {
        WorkspaceWriteMode::DirectRw => workspace_root,
        WorkspaceWriteMode::Cow { upper_dir } => upper_dir.as_path(),
    };
    let tmp_dir = probe_base.join(format!(".harness-tier2a-probe-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir).map_err(|e| AppContainerError::Preflight(e.to_string()))?;
    timing.mark("traverse/fs-allow/elevation");
    let smoke_result =
        smoke_test_spawn(sid.as_psid(), workspace_cap_psid, workspace_root, &tmp_dir);
    let _ = std::fs::remove_dir_all(&tmp_dir);
    smoke_result?;
    smoke_test_harness_control_write_denied(sid.as_psid(), workspace_cap_psid, workspace_root)?;
    timing.mark("smoke tests");

    // D-54: 救済walkはここで初めて起動する——**`preflight`のACL作業を全て終えた後**である
    // ことが、DACL書込の競合を避ける条件になっている（`grant_job`のdoc）。rootへの継承付与は
    // 既に同期で終わっているので、workspaceの大半はこの時点で到達可能であり、残りは
    // 保護DACL配下だけである。子プロセスを起動する経路は`grant_job::wait_until_done`で
    // 完了を待つ（待たずに走らせると、モデルには「そのファイルは無い」と見える）。
    if needs_descendant_fix {
        // [BUG-082 Part B] 背景フェーズが行う伝播はrootへの継承ACE伝播である。BUG-083の修正で
        // `.harness/`の保護が実際に効くようになり、この伝播はOS側で`.harness/`の手前で止まるが、
        // 保護が止められるのは**継承経由の伝播だけ**なので、保護前から物理コピーとして乗っていた
        // ACEやD-37時代のpackage SID残骸に備えて背景側でも剥がし直す（第2の防御）。ここで渡す
        // `.harness/`再保護用のSIDは、上の
        // 同期`protect_harness_control_dir_from_appcontainer`呼び出しと**同じ集合**
        // （workspace capability＋セッションSID）にする——片方だけだと剥がし残した側から
        // 制御面が書けるのは同期区間と同じ理屈（`revoke.rs`のdoc参照）。`workspace_cap`は
        // このすぐ後で`grant_job::start`へ移動するため、先にコピーを取っておく。
        let session_sid_copy = unsafe { crate::win_common::OwnedSid::copy_from(sid.as_psid()) }
            .map_err(|e| {
                AppContainerError::Preflight(format!(
                    "failed to copy the session SID for background .harness re-protection: {e}"
                ))
            })?;
        let harness_protect_sids = vec![workspace_cap.clone(), session_sid_copy];

        // 戻り値の`false`は「このプロセスでは既に別のジョブが走っている」＝`preflight`が2回
        // 呼ばれた場合だけで、製品では起こらない（実機テストが同居するときだけ）。
        let started = grant_job::start(
            workspace_root,
            workspace_cap,
            workspace_mask,
            harness_protect_sids,
            vec![workspace_root.join(".harness")],
            &canonical_workspace_root,
            workspace_mode,
        );
        timing.mark(&format!(
            "grant_job::start (background propagate + descendant fix-up, started={started})"
        ));
    }

    Ok(PreflightOutcome {
        warnings,
        denied_passthrough,
        granted_passthrough,
        netfilterd_chain_attempted,
    })
}
