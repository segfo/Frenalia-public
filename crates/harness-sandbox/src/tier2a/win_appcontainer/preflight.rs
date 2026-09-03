//! Tier2a起動前の実機プローブ（`preflight`）。
//!
//! ワークスペース・fs passthrough・`.harness/**`制御面のそれぞれについて、実際に
//! AppContainer子を起動してFS I/Oを試し、Tier2aを選んでよいかを判定する。判定材料の
//! 収集が責務であり、ACLの付与/撤収そのものは`acl_grant`/`revoke`に委ねる。

use super::*;

use crate::tier2a::workspace_ledger::WorkspaceMode;

/// `preflight`の戻り値。`warnings`はD8の到達不能診断（従来どおり）、`granted_passthrough`は
/// **実際にACEが付与された（既存で十分だった場合・部分的にしか適用できなかった場合を含む）**
/// passthroughルートの一覧。呼び出し側（`harness-cli`の台帳記録）は
/// この一覧だけを台帳へ書くことで、「幻の台帳エントリ」（実際には`ACCESS_DENIED`で失敗した
/// のに記録だけ残る）を防ぐ。逆に、rootへのACE付与自体は成功したが子孫の一部
/// （TrustedInstaller所有等）で失敗した「部分適用」ケースは、`sid_ace_mask`でrootを権威的に
/// プローブして`Ok`/`Err`によらず記録する（BUG-017: 記録漏れが「撤収経路の無い孤立ACE」を
/// 生むため、幻の台帳エントリより孤立ACEの方を重く見て記録側に倒す）。
#[derive(Debug)]
pub struct PreflightOutcome {
    pub warnings: Vec<String>,
    pub denied_passthrough: Vec<(std::path::PathBuf, String, String)>,
    /// [§22.3] 開いた穴の一覧。各要素は**その穴のACEを実際に書いた宛先SID**を持つ
    /// （[`harness_core::GrantedPassthrough`]）。
    ///
    /// かつてここは`Vec<(PathBuf, bool)>`と、別立ての`granted_subjects: Vec<(PathBuf, SID文字列)>`の
    /// **2本のリスト**だった。1本に畳んだのは、**2本が1対1ではなかった**からである——
    /// 昇格ヘルパー経由の付与では、パス側は無条件に、宛先SID側は導出できたときだけ積まれていた。
    /// 畳んだことで「宛先SIDの無い行」が型の上で表現できなくなり、起動側に逃げ道が要らなくなった。
    pub granted_passthrough: Vec<harness_core::GrantedPassthrough>,
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

/// [§22.3] 昇格ヘルパーへ回す宣言1件と、**その宣言の宛先SID**を1つの値で持つ。
///
/// # なぜ電文（[`crate::tier2a::privhelper::FsAllowGrant`]）に足さないのか
///
/// 電文へ載せるのは**秘密**であって宛先SIDではない（§22.3.1の却下表）——昇格側は自分で
/// 畳み込んだパスから導出するので、SIDを渡してもその宛先SIDを呼び出し元が正当に持つかは
/// 判定できない。ここで持つのは**こちら側が既に導出した値**であり、電文の形は変えない。
///
/// # なぜ持ち回すのか
///
/// 宛先SIDはこのエントリを昇格へ回す**前に**導出済みで、導出に失敗した宣言はそもそも
/// ここへ到達しない（穴を開けずに`continue`する）。かつては昇格から戻った後に
/// `fs_allow_capability_sid`をもう一度呼んで引き直しており、**同じ値を作る場所が
/// 2箇所**あった。引き直しが失敗した行だけ宛先SIDを持たないまま「開いた穴」に数えられ、
/// その行のパスは子から一切読めなくなる（トークンにその宛先SIDが載らないため）。
struct PendingElevation {
    /// 昇格ヘルパーへ送る電文そのもの。
    grant: crate::tier2a::privhelper::FsAllowGrant,
    /// この宣言の宛先SID。子のトークンへ積むのも、台帳へ記録するのもこれ。
    subject: crate::win_common::OwnedSid,
    /// [`Self::subject`]の文字列表現。`sid_to_string`は失敗し得るので、
    /// **穴を開ける前に**1回だけ作って持ち回す。
    subject_sid: String,
}

/// [BUG-101] **付与したACEが台帳に載っているか**を、`preflight`をどう抜けても必ず測るガード。
///
/// `Drop`にしてあるのは`passthrough_progress::begin`と同じ理由——この関数は`?`で抜ける経路を
/// 複数持ち、そのいくつかは**セッション台帳へ記録する経路（CoW Redirector DLLの
/// `record_granted_path`）より後**にある。つまり早期returnした実行でも、既にマシンへ書いた
/// ACEを測る機会が要る。手で閉じる形にすると、脱出経路が1つ増えるたびに書き忘れる（B-06）。
///
/// **測る対象はセッションのpackage SIDだけである**（`grant_audit`のモジュールdocの既定方針）。
/// [§22.3] `--fs-allow`の穴は宣言ごとのcapability SID宛へ移り、**セッション台帳へは
/// 記録しなくなった**（同じセッションでは開かれっぱなしで、撤収は
/// `workspace-capability-ledger.json`を索引に名前の付いた扉が行う）。したがって
/// ここで除外リストを持つ必要はもう無い——除外は「記録しているのに宛先SIDが違う」ときに
/// 要ったもので、記録そのものをやめた時点で対象に入らない。
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
        let recorded: Vec<String> =
            crate::tier2a::session_profile::granted_paths_for_current_session();
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
         time, so `--sandbox tier1` will not help either (and there is no --sandbox value that \
         skips process creation). Move the workspace somewhere shorter, \
         or map it to a drive letter (`subst X: \"<workspace>\"`). Read-only commands \
         (`harness changes`/`apply`) are unaffected: {}",
        workspace_root.display()
    )))
}

/// **祖先traverseを要求する対象を決める純粋関数**（実マシンを一切読まない）。
///
/// # なぜ切り出してあるのか
///
/// ここが返す集合は「**このマシンに恒久的なACEを付けに行く先**」であり、しかも不足していれば
/// **昇格（UAC）を要求する**。つまり1件増えると、実マシンに残る変更が1つ増える。にもかかわらず、
/// 元は1,400行の関数の途中のローカル変数だったので、**何を要求するのかを測る手段が
/// 「実際に走らせて実マシンの記録の増減を見る」しか無かった**——そして一度付けてしまうと
/// 冪等スキップで二度と差が出ないので、後から「これは誰のせいで増えたのか」を測れない
/// （§22.3.2の移行でまさにこれを踏み、traverse台帳が7→10件に増えた理由を事後に決着できなかった）。
///
/// 純粋関数にすると、**まだACEが付いていない架空のパス**を渡して要求内容だけを測れる。
/// 実マシンの状態にも昇格にも依存しないので、何度でも同じ答えが出る。
///
/// # 何を入れて、何を入れないか
///
/// **入れるのは親（祖先）だけで、leaf自身は入れない。** leafへの到達権はそのツリーへ付けた
/// 継承ACEが与える。ここでleafまで要求すると、**新しいパスを指定するたびに「ACEが無い」と
/// 判定されて毎回昇格を求める**ことになる（D-37）。この規則は3種類すべてに掛かる——
/// workspace・CoWの差分層・`--fs-allow`の宣言。
///
/// D-45（`plans/etw-spike/RESULTS.md` §19の実測）で`--fs-allow`の**親**が入った。対象自身への
/// 継承ACEだけでは削除（`Remove-Item`）と移動（`Move-Item`）が失敗する——この2つは祖先を
/// 「通過」ではなく**オープン**するため、対象へ到達する前に祖先で拒否される（拒否は対象ではなく
/// 祖先に出るので、対象パスだけを見ていると「失敗しているのに拒否0件」に見える）。読取・書込・
/// 実行・`cmd /c type`はフルパスのファイルopenなので祖先未付与でも通る。
///
/// マスクを広げないこと（`FILE_TRAVERSE|FILE_READ_ATTRIBUTES`のまま）。§19.2で7操作すべてが
/// これで通ることを実測しており、`SYNCHRONIZE`・`FILE_LIST_DIRECTORY`まで広げると
/// `C:\`・`C:\Users`が列挙可能になり機密性の実害が出る。
///
/// **存在しないパスは入れない**——後段が`path does not exist, skipped`として弾くものへ、
/// 先回りしてマシンのACLを書き換える理由が無い。これだけは実FSを見る（`Path::exists`）ので、
/// テストは実在するディレクトリを渡すこと。
fn traverse_targets_for(
    workspace_root: &Path,
    write_mode: &WorkspaceWriteMode,
    passthrough: &[FsPassthrough],
) -> Vec<std::path::PathBuf> {
    let mut targets: Vec<std::path::PathBuf> = workspace_root
        .parent()
        .map(|p| p.to_path_buf())
        .into_iter()
        .collect();
    if let WorkspaceWriteMode::Cow { diff_layer_dir } = write_mode {
        if let Some(parent) = diff_layer_dir.parent() {
            targets.push(parent.to_path_buf());
        }
    }
    for requested in passthrough {
        if !requested.path.exists() {
            continue;
        }
        let Some(parent) = requested.path.parent() else {
            continue;
        };
        let parent = parent.to_path_buf();
        if !targets.contains(&parent) {
            targets.push(parent);
        }
    }
    targets
}

/// harness起動時に1回だけ呼ぶ。プロファイル作成→ACL付与→起動smokeテストの一連を行い、
/// いずれか失敗したら理由文字列を返す（`shell_tier::best_effort_tier`が**起動を拒否する理由**
/// としてそのまま使う——D-75以降、Tier2aが取れなくても弱いTierへは落とさない）。判断は実行前に
/// 完結させ、`run_shell`個々の呼び出し中にはTier選択のロジックを一切持たせない（非冪等コマンドの
/// 二重実行を避けるための意図的判断）。
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
    // D-37: プロファイルはセッション単位。共有package SIDをやめ、workspace・CoW diff_layer_dir・
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
    // **D-82のCoW差分層の掃除をここへ置かないこと。** 一度置いて実害が出た——
    // `preflight`は`harness-sandbox`の実機テストが直接呼ぶ関数であり、それらのテストは
    // workspaceだけをtempdirにして`%LOCALAPPDATA%`は実物を使う。結果、`cargo test`が
    // 開発機の差分層を70件消した（中身のあるものは残ったが、それは規則が正しかっただけで、
    // テストが実マシンのユーザーデータを消してよい理由にはならない）。
    // 掃除は`harness-cli`の起動経路（`startup::sandbox`）が持つ——TUIもheadlessもそこを通り、
    // テストは通らない。

    // [T-B] CoWのときだけ、注入され得るRedirector DLL 2本（x64・WOW64用x86）の版がそろって
    // いるかを検算する。**そろっていなければセッションを起こさない**（D-75: 隔離が取れないとき
    // 自動降格せず拒否する。弱い器が要るなら`--sandbox`の値で明示選択する）。
    //
    // **位置がこの行である理由**は2つある。
    //
    // - `gc_dead_sessions`の**後**: 落ちる機でも死んだセッションの後片付けは進むべきで、
    //   検算の失敗が回収を止める理由にはならない。
    // - `begin_session()`の**前**: ここから先はプロファイル作成とACE付与が始まる区間で、
    //   途中で落ちると撤収経路の無い孤立ACEを残す（BUG-101/B-05と同型）。**副作用を1つも
    //   起こしていない地点で落とす。**
    //
    // CoW以外（`DirectRw`）では検算しない——x86 DLLは32bit孫への透過注入にしか使わないので、
    // CoWでないセッションの起動条件にすると、無関係な理由でTier2aが使えなくなる。
    if matches!(write_mode, WorkspaceWriteMode::Cow { .. }) {
        let x64 = super::redirector_dll_path()?;
        let x86 = x64.with_file_name(crate::tier2a::redirector_identity::X86_DLL_FILENAME);
        crate::tier2a::redirector_identity::verify_redirector_set(&x64, &x86)
            .map_err(|e| AppContainerError::Preflight(e.to_string()))?;
    }
    timing.mark("verify_redirector_set");

    let profile_name =
        crate::tier2a::session_profile::begin_session().map_err(AppContainerError::Preflight)?;
    // [BUG-101] **この行より後で付けたACEは、必ず台帳と突き合わせてから抜ける。**
    // 武装をここに置くのは、この直後の`ensure_profile`以降が「このセッションのSID宛に
    // ACEを付け得る全区間」だからである（`SessionGrantAudit`のdoc）。
    let audit_guard = SessionGrantAudit::arm(&profile_name);
    let sid = ensure_profile(&profile_name)?;
    // [§22.3・BUG-101] **ここにあった検算は2026-09-01に削除した。**
    //
    // かつては「台帳へ書く宛先SID（呼び出し元が`current_session_grant_sid()`から取る値）」と
    // 「この起動が実際に使う宛先SID」の一致を確かめていた。**その前提が消えた**——
    // `--fs-allow`の穴の宛先SIDは宣言ごとのcapability SIDへ移り、呼び出し元は
    // セッションのpackage SIDを台帳へ書かなくなったので、**比べる相手が居ない**。
    // 残しても常に一致し、何も検出しないまま「検算があるから守られている」と読ませる。
    //
    // **移行の本当の不変条件はこの関数の末尾が測っている**（`§22.3.0 migration invariant`）——
    // 開いた穴に**セッションpackage SID宛のACEが1本も残っていない**ことを、台帳ではなく
    // 実DACLを読んで確かめる。網はそちらに在る。
    timing.mark("begin_session + ensure_profile");
    sweep_stale_redirector_dll_aces();
    timing.mark("sweep_stale_redirector_dll_aces");
    // 同じ「起動のたびに前回の残骸を畳む」枠。前回がACEを書いた直後に落ちていれば確定へ、
    // 書く前に落ちていれば予定を落とす（BUG-112・D-89）。**付与の経路に置くだけでは足りない**
    // ——祖先traverseが既に足りている起動は下の付与へ進まないので、そこに置いた畳み直しは
    // 一度も走らない。`pending`が0件なら台帳を1回読んで戻るだけである。
    crate::tier2a::traverse_ledger::settle_pending_traverse_grants();
    timing.mark("settle_pending_traverse_grants");
    // 祖先traverseの付与先（D-37）。package SIDと違いセッションを跨いで永続する。
    let traverse_sid = traverse_capability_sid()?;

    // workspaceのアクセスモード（通常起動=RWX / `--sandbox tier2a-cow`=RO、将来`--cow_exec`=RXを
    // 追加予定）は、同じworkspaceに対して混在させてはいけない——CoWセッションは「本体は動かない」
    // を前提に差分層を積むので、並走するRWXセッションが本体を書き換えると差分が**動く土台の上に
    // 積まれた**ものになる（根拠の全文は`workspace_ledger`のモジュールdoc。**「ACEはファイルに
    // 1つしか付けられない」という旧・根拠は事実ではない**——D-84はまさに2本同時に載せている）。
    // ACE付与の前に、名前付きmutexで他モードが使用中でないか確認し、自モードの生存マーカーを
    // 確保する（`begin_workspace_mode`のdoc参照。モード衝突チェックとマーカー作成は内部で
    // `with_named_lock`により直列化されるため、2プロセスがほぼ同時に別モードで起動しても
    // 早い者勝ちの事故にはならない）。
    let workspace_mode = match write_mode {
        WorkspaceWriteMode::DirectRw => WorkspaceMode::Rwx,
        WorkspaceWriteMode::Cow { .. } => WorkspaceMode::Ro,
    };
    let canonical_workspace_root = workspace_root.canonicalize().map_err(|e| {
        AppContainerError::Preflight(format!(
            "failed to canonicalize workspace root {}: {e}",
            workspace_root.display()
        ))
    })?;
    crate::tier2a::workspace_ledger::begin_workspace_mode(
        &canonical_workspace_root,
        workspace_mode.as_str(),
    )
    .map_err(AppContainerError::Preflight)?;
    crate::tier2a::workspace_ledger::record_workspace_grant(
        &canonical_workspace_root,
        workspace_mode.as_str(),
    );

    // D-54: workspaceツリーへ付けるACEの宛先SID。**セッションのpackage SIDではなく、この
    // workspace＋モードに固有のcapability SID**へ付ける。付与の形（どのツリーへ何を許すか）は
    // workspaceとモードで決まるものであって、セッションの属性ではない——宛先SIDをその形に
    // 合わせることで、26万ノードへの継承ACEの伝播を**ワークスペースにつき一度きり**にする
    // （毎起動で払っていた実測60秒が消える、BUG-081）。名前はワークスペースごとのランダム
    // 秘密から導出され、サンドボックスから読めない台帳にだけ存在する
    // （`crate::tier2a::workspace_capability`のdoc）。
    //
    // [D-84] **導出するのは自分のモードのcapability SID 1本ではなく、全モードのcapability SIDである。**
    // capability SIDは(パス, モード)から決まるので、モードを切り替えると宛先SIDごと変わり、既に配った
    // 26万件のACEが一斉に無効になって全額を払い直していた（一巡61.4秒、§S12）。両方を
    // **1回の書込で**置けばその払い直しが消える——費用はゼロ（§S15-1）、安全性も実測済み
    // （`ro`のcapability SIDしか持たない子は、隣に`rwx`宛のACEが載っていても作成・追記・削除が
    // すべて`ERROR_ACCESS_DENIED`。`plans/handoff/fs-boundary-cost/T-1.md`）。
    //
    // **ここで台帳エントリも両モードぶん作られる**（`ensure_capability_name`）。撤収
    // （`harness fs revoke-workspace`）は台帳を索引にして剥がすので、**配った本数と
    // 引ける本数が同じ**になっていなければならない（`B-01`／BUG-101: 記録の無いACEは
    // どのコマンドでも剥がせない）。
    let workspace_cap_sids: Vec<(WorkspaceMode, crate::win_common::OwnedSid)> = WorkspaceMode::ALL
        .iter()
        .map(|mode| {
            workspace_capability_sid(&canonical_workspace_root, mode.as_str())
                .map(|sid| (*mode, sid))
        })
        .collect::<Result<_, _>>()?;
    let ace_grants: Vec<AceGrant> = workspace_cap_sids
        .iter()
        .map(|(mode, sid)| AceGrant {
            sid: sid.as_psid(),
            mask: workspace_mode_mask(*mode),
        })
        .collect();
    // このセッションが子のトークンへ積むcapability SIDは**自分のモードのぶんだけ**（ここが
    // D-84の安全性の全て——ACEを2本配っても、子が名乗れるのは1本である）。
    let workspace_cap = workspace_cap_sids
        .iter()
        .find(|(mode, _)| *mode == workspace_mode)
        .map(|(_, sid)| sid.clone())
        .ok_or_else(|| {
            AppContainerError::Preflight(format!(
                "internal: no capability SID was derived for workspace mode '{}' \
                 (WorkspaceMode::ALL and the running mode disagree)",
                workspace_mode.as_str()
            ))
        })?;
    let workspace_cap_psid = Some(workspace_cap.as_psid());

    // D-30: `write_mode`がACL付与方針を唯一決める。**`match`は全分岐（`..`無し）に保つ**
    // ——`WorkspaceWriteMode`へバリアントを追加した際にACL決定漏れをコンパイルエラーに
    // するためで、D-84で付与そのものがモード非依存になった後もこのゲートは外さない。
    // matchが2つに割れているのは、**付与の前に置く段**（ボリュームの検算）と**後に置く段**
    // （差分層の用意）で順序の要求が逆だからである。
    //
    // **ACLを保持できないボリュームでは、そもそも境界を張れない**（D-81）。下の`grant_*`は
    // 失敗しないまま何も強制しないことがあり得るので、**付ける前に**検算して拒否する。
    // ワークスペース側（読取専用ACEが乗る）と差分層側（書込ACEが乗る）の**両方**を見る
    // ——D-81で両者は別ボリュームになり得る。
    match write_mode {
        WorkspaceWriteMode::DirectRw => {}
        WorkspaceWriteMode::Cow { diff_layer_dir } => {
            require_persistent_acl_volume("workspace", workspace_root)?;
            require_persistent_acl_volume("copy-on-write diff area", diff_layer_dir)?;
        }
    }

    // [D-84/BUG-082 Part B] rootへ継承ACEを**全モードぶん1回の書込で**、**伝播なし**で置く
    // （`grant_workspace_root_aces_fast`のdoc）——既存子孫への伝播は`grant_job`の背景
    // フェーズへ委ねる。2回目以降の起動は冪等スキップでWin32書込0回。
    //
    // マスクはACEの宛先のモードが決める（`workspace_mode_mask`）。`--sandbox tier2a-cow`で
    // 走っていても`rwx`のcapability SID宛ACEはRWXのままで、**それでもこのセッションの子は
    // 書けない**——子のトークンに`rwx`のcapability SIDが入っていないためである。Redirector DLLが無効・回避
    // されてもworkspace本体への書込が`ACCESS_DENIED`でfail-closeする、というD-30の性質は
    // 変わらない（D-01「フックは境界にしない」）。
    //
    // **workspace本体は`record_granted_path`しない**（D-54）。あれは「このセッションが撤収
    // 責任を負う」という表明で、記録すると`end_session`/`gc_dead_sessions`がツリー全体の
    // `revoke_ace_recursive`（実測30.8秒）を回してしまう。capability宛のACEはセッションより
    // 長生きするのが仕様であり、撤収は`harness fs revoke-workspace`が明示的に行う。
    grant_workspace_root_aces_fast(workspace_root, &ace_grants)?;
    timing.mark(&format!(
        "grant_workspace_root_aces_fast(workspace_root, {} ACEs)",
        ace_grants.len()
    ));

    // [§22.3.2] 差分層の宛先SIDは、付与した後も**プローブと子の起動まで**運ぶ必要がある
    // （`probe_capabilities`のdoc: CoWのプローブは`probe_dir`を差分層の中に作る）。
    // CoWでなければ`None`のまま。
    let mut cow_diff_layer_cap: Option<crate::win_common::OwnedSid> = None;
    match write_mode {
        WorkspaceWriteMode::DirectRw => {}
        WorkspaceWriteMode::Cow { diff_layer_dir } => {
            // [§22.3.2] **宛先SIDはセッションのpackage SIDではなく、差分層ごとのcapability SIDである。**
            //
            // ここには以前「diff_layer_dirはセッション専有なので宛先SIDは従来どおりpackage SIDの
            // ままにする」と書いてあった。**その理由は§22.3の移行で失効している**——
            // 「宛先が共有であること」と「対象がセッション専有であること」は別の話で、
            // ドメインを分けると前者が穴になる。package SIDはAppContainer全体で共有されるので、
            // そこへ付けたACEは同一セッションの**全ドメイン**へ効き続ける（§22.3.0:
            // DACLは「このpackage SIDかつこのcapability SID」を表現できず、並べたALLOWは
            // どれか1つ満たせば通る）。
            //
            // 宛先SIDがセッション固有になることは自動的に成立する——導出鍵に入る差分層のパスが
            // セッションIDを含むためで、「セッション限定capability」という別種のSIDは足さない。
            //
            // [D-82] **生存マーカーを、差分層の実体より先に握る。**
            //
            // 逆順（実体→マーカー）だと「ディレクトリは在るが生存マーカーはまだ無い」区間が
            // でき、並行して走る別の`harness.exe`のGCから見ると**空の殻**と区別が付かない。
            // かつてはその区間をGCのロックで囲み、さらに「作りたては回収しない」猶予を
            // 二重の網として置いていたが、**順序を入れ替えれば守るべき区間そのものが存在しない**
            // ので、どちらも撤去した（`workspace_ledger::cow_session_is_live`のdoc）。
            //
            // **作る側は2経路ある**（ここと`session_scope::prepare_scope`）。片方だけ直しても
            // もう片方の窓が残るので、順序を変えるときは必ず両方を見ること。
            //
            // CoWのdiff_layer_dirはセッション専有（他セッションと共有しない）なので、他モードとの
            // 衝突チェックは不要。セッションID（diff_layer_dirの最終パス要素、
            // `session_scope::cow_diff_layer_dir_in`参照）で名前を付けた生存マーカーだけを確保し、
            // `harness cow discard`等が「まだこのセッションが動いているか」を判定できるようにする
            // （`plans/AppContainerベース Copy-on-Write ワークスペース設計書.md` Phase 6の前段）。
            //
            // **セッションIDが読めなければ失敗させる**（fail-closed）。既定値で代用すると
            // 別々のセッションが**同じ名前のマーカーを共有**し、一方が生きているあいだ他方の
            // 差分層まで「使用中」に見える（逆向きには、取り違えたまま回収されうる）。
            let session_id = diff_layer_dir
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| {
                    AppContainerError::Preflight(format!(
                        "cannot derive the CoW session id from {}: the diff layer directory has \
                         no usable final path component, so its liveness marker cannot be named",
                        diff_layer_dir.display()
                    ))
                })?;
            crate::tier2a::workspace_ledger::claim_cow_diff_layer(session_id, diff_layer_dir)
                .map_err(AppContainerError::Preflight)?;
            // 順序は既存のまま**実体 → ACE → 記録**（`claim_cow_diff_layer`がディレクトリを
            // 作った直後にrootへ継承ACEを1本置く）。§22.3.2が「中身を作る前にrootへ付ける」と
            // 要求しているのはこの形で、あとから巨大ツリーへ配る形（BUG-081）を作り直さない。
            let diff_layer_cap =
                cow_diff_layer_capability_sid(&canonical_workspace_root, diff_layer_dir)?;
            grant_ace_inheritable_rw(diff_layer_dir, diff_layer_cap.as_psid())?;
            // [§22.3.2/B-01] **記録するのは「導出済みの名前」であって秘密ではない。**
            // 撤収時に秘密から導出し直す形にすると、差分層が使う秘密（ワークスペース側のもの）を
            // `fs revoke-workspace`／`fs prune`が**他人の都合で**消した後に名前を作れなくなり、
            // そのACEはどのコマンドでも剥がせなくなる（BUG-101と同型）。
            //
            // **`granted_paths`とは別の欄へ入れる。** 同じ欄に入れると、package SID宛の
            // 自己検証がこのパスを「台帳にあるのにACEが無い」＝幻の台帳エントリとして
            // 毎回のCoW起動で警告に出す（`grant_audit::classify`は`Stage::Preflight`で
            // `recorded_absent`を報告する）。
            let diff_layer_cap_name =
                crate::tier2a::workspace_capability::lookup_declaration_capability_name(
                    &canonical_workspace_root,
                    diff_layer_dir,
                    COW_DIFF_LAYER_ACCESS.label(),
                );
            match &diff_layer_cap_name {
                Some(name) => {
                    crate::tier2a::session_profile::record_granted_capability(diff_layer_dir, name)
                }
                // 直前に発行したものが引けないのは起こり得ないが、**起きたら黙らない**（B-10）。
                // 記録できないことは付与の失敗ではないので止めはしないが、このACEは自動撤収の
                // 対象から外れる。
                None => eprintln!(
                    "warning: could not look up the capability name just issued for {}; this \
                     ACE will not be revoked automatically (see docs/bugs/BUG-101.md)",
                    diff_layer_dir.display()
                ),
            }
            // [§22.3.2] **自己検証の射程が黙って狭まらないようにする。** `grant_audit`は
            // capability SIDを既定で対象外にしているが、その理由はワークスペースツリーで
            // 全件が偽陽性になることであって、差分層について検討した結果ではない。宛先SIDを
            // 移した以上、ここで明示的に測らないと差分層が静かに自己検証から外れる。
            //
            // **渡すのは「この宛先SIDのぶんの記録」だけである**（`granted_capability_paths_for`）。
            // 全capabilityの和を渡すと、別のcapability SIDのパスが候補に入り、そのSIDのACEが
            // 無いのは当然なのに「幻の台帳エントリ」として報告される。1セッションが差分層を
            // 2枚記録する回はfork（[BUG-147]で`preflight`より前に記録するようになった）で生まれる。
            //
            // **名前が引けなかったときは空を渡して、測ること自体はやめない。** 記録できて
            // いないのだから、この宛先SIDのACEは全部`present_unrecorded`として出るのが正しい
            // ——そこは自己検証がいちばん役に立つ場面であり、黙って飛ばす場所ではない（B-10）。
            let recorded_for_subject = diff_layer_cap_name
                .as_deref()
                .map(crate::tier2a::session_profile::granted_capability_paths_for)
                .unwrap_or_default();
            if let Some(audit) = crate::tier2a::grant_audit::audit_subject(
                crate::tier2a::grant_audit::Stage::Preflight,
                diff_layer_cap.as_psid(),
                &recorded_for_subject,
            ) {
                crate::tier2a::grant_audit::report(&audit);
            }
            cow_diff_layer_cap = Some(diff_layer_cap);
            // `harness cow status`/`apply`/`list`がworkspace_rootを引けるよう、
            // diff_layer_dir自身に由来を記録する
            // （`workspace_ledger::write_cow_session_meta`のdoc参照）。
            crate::tier2a::workspace_ledger::write_cow_session_meta(
                diff_layer_dir,
                &canonical_workspace_root,
                session_id,
            );
        }
    }
    // D-05/D-09の層3。剥がす宛先SIDは**全モードのcapability SID（今の継承元）とpackage SID
    // （D-37時代の残骸）**——片方だけだと剥がし残した側から制御面が書ける（`revoke.rs`のdoc参照）。
    //
    // [D-84] **「今の継承元」が2本になった。** ここが自モードのcapability SID宛ACEだけを
    // 剥がしていると、`.harness/`配下に**もう一方のモードのcapability SID宛ACEだけが残る**——
    // 次にそのモードで起動したセッションから制御面が書けてしまい、D-05/D-09が片方のモードでだけ
    // 成立するという無言の穴になる（`B-01`の非対称そのもの）。
    let mut control_dir_subjects: Vec<PSID> = workspace_cap_sids
        .iter()
        .map(|(_, s)| s.as_psid())
        .collect();
    control_dir_subjects.push(sid.as_psid());
    let protected_nodes =
        protect_harness_control_dir_from_appcontainer(workspace_root, &control_dir_subjects)?;
    // [BUG-084] 件数を出す。層3のhard-denyは「1件も掛かっていない」が症状として現れない
    // （BUG-083はそれが恒常的に起きていた）ので、`HARNESS_PREFLIGHT_TIMING=1`で事後確認
    // できる形にしておく。
    // [BUG-145] **書いた件数も出す。** 「保護済み」だけを出していたので、冪等スキップで
    // 書込が1回も走っていない状態と、実際に保護を確立した状態が同じ数に見えていた。
    timing.mark(&format!(
        "protect_harness_control_dir_from_appcontainer ({} nodes, {} written)",
        protected_nodes.protected, protected_nodes.written
    ));

    // 既存子孫への継承ACE伝播（フェーズ0）と、保護DACL（BUG-020の残存損害等）で継承が
    // 届かなかったノードの救済（フェーズ1）が要るか。**ワークスペースにつき一度きり**で、
    // 実行は`preflight`の最後（他のACL作業を全て終えた後）に背景スレッドへ委ねる
    // （`grant_job`のdoc「DACL書込の競合を避けるための約束」）。
    //
    // [BUG-110] 判定は**2つの向きから**行う。台帳（記録）だけを見ていたために、
    // workspaceを削除して同じパスへ作り直したツリーが「検証済み」と判定され、伝播が
    // 丸ごと省略されていた——起動**前**から在ったファイルがサンドボックスから一切見えない
    // workspaceが出来上がる。
    //
    // 1. 記録の側: `tree_is_verified`（完走時刻＋**そのとき検証したrootの識別子**）
    // 2. 実体の側: root直下に、**どれかのcapability SID**からアクセスが届いていないノードが無いか
    //
    // 2はO(root直下の件数)の読取だけで、実測でも数msである。1が通っても2で見つかったら
    // 回す（`B-14`: 台帳の存在で実体の存在を代替しない）。
    //
    // [D-84] **2が「全capability SID」を見るのは、既存ワークスペースの移行がここに掛かって
    // いるからである。** D-84より前に配ったツリーには`rwx`側のACEしか載っていないが、台帳の
    // 検証済みは立っている。1だけを見ると`ro`宛のACEは1件も配られないままになり、
    // 次に`--sandbox tier2a-cow`で起動したセッションからworkspaceが一切見えなくなる
    // （BUG-110とまったく同じ症状——拒否ではなく「無い」に見えるので気付けない）。
    //
    // `.harness/`を外す集合は、下の`grant_job::start`へ渡す`skip`と**同じ値**でなければ
    // ならない——ジョブが意図的にACEを付けない場所を検算側が数えると、毎起動でジョブが
    // 回り続ける（`B-05`）。だから両者は同じ変数を読む。
    let job_skip = vec![workspace_root.join(".harness")];
    let cap_sid_psids: Vec<PSID> = ace_grants.iter().map(|g| g.sid).collect();
    let unreachable_child = top_level_child_missing_aces(workspace_root, &cap_sid_psids, &job_skip);
    let needs_descendant_fix = !crate::tier2a::workspace_capability::tree_is_verified(
        &canonical_workspace_root,
        workspace_mode.as_str(),
    ) || unreachable_child.is_some();
    // 記録は「検証済み」なのに実体が届いていない、は**説明の要る状態**である（B-10:
    // 無言で直さない）。ジョブを回して直すが、直したこと自体は残す。
    if let Some(child) = &unreachable_child {
        timing.mark(&format!(
            "workspace ACL re-check: {} is not reachable by the workspace capability",
            child.display()
        ));
    }

    // workspace_root（Cow時はdiff_layer_dirも）の祖先traverseチェーンが不足していないか事前に判定する
    // （読み取り専用、UAC無し）。不足分は下のfs-allow昇格要求と合流させ、1回のprivhelper呼び出し
    // （起動あたりUAC最大1回）で解消する。以前はtraverse不足を`smoke_test_spawn`（下記）が
    // リアクティブに検知してTier1bへ静かに降格するだけだったが、privhelper経由で自動付与できる
    // 経路（`GrantWorkspaceAccess`）が整ったため、ここで先回りして解消する
    // （`plans/DESIGN-SANDBOX-PRIVSEP.md` D-16「特権昇格デーモンを使う際の注意点」参照）。
    // D-37: 見るのは**祖先だけ**。workspace_root/diff_layer_dir自身への到達権はセッション固有の
    // package SID宛の継承ACE（すぐ上で付与済み）が与えるので、共通capability SIDのACEを
    // そこへ要求してはいけない。ここでleafまで含めると、セッションのたびに新しいworkspaceで
    // 「capability SIDのACEが無い」と判定され、毎回昇格を要求してしまう。
    let traverse_targets = traverse_targets_for(workspace_root, write_mode, passthrough);
    let missing_traverse: Vec<std::path::PathBuf> = traverse_targets
        .into_iter()
        .filter(|target| !traverse_chain_sufficient(target, traverse_sid.as_psid()))
        .collect();
    let mut warnings = Vec::new();

    // D-37: Redirector DLL（`--sandbox tier2a-cow`の透過性）はworkspaceの外＝harness.exeの隣にあるため、
    // workspaceへの継承ACEでは覆えない。共有package SIDだった頃はリポジトリrootへの継承ACEが
    // たまたま`target/debug/*.dll`まで届いていたが、セッションごとにSIDが変わる今は明示的に
    // 読取+実行を与える必要がある（無ければ注入が失敗し、境界＝ACLは効いたまま透過性だけが失われる）。
    //
    // [D-88（`DESIGN-SANDBOX-APPPOLICY.md`）] **条件は「CoWか」ではなく「DLLを注入するか」である。**
    // lazyレーンはDirectRwの子にも同じDLLを注入するので、ここがCoW限定のままだと
    // `LoadLibraryW`が対象プロセスでNULLを返し、**注入が必ず失敗する**——受入E2Eが実際に
    // これで落ちた（`B-06`: 前提を変えたら、それを実現している経路を全部数える）。
    let injects_redirector = matches!(write_mode, WorkspaceWriteMode::Cow { .. })
        || matches!(super::lazy_grant::lane(), grant_job::PreparationLane::Lazy);
    if injects_redirector {
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
    let mut granted_passthrough: Vec<harness_core::GrantedPassthrough> = Vec::new();
    // 本体プロセス内（非管理者）でACCESS_DENIEDになったエントリ（システム保護パス等）だけを
    // ここへ集め、後段で1回の特権分離ヘルパー要求へまとめる（起動あたりUAC最大1回、
    // `TIER1A-PRIVHELPER-HANG.md`「引き継ぎTODO」の決定）。
    let mut needs_elevation: Vec<PendingElevation> = Vec::new();
    // [残課題#37] 昇格へ回すと決まった宣言の`(確定した宣言, 宛先SID, そのSIDの文字列)`。
    // **秘密はまだ持たない**——付与のループを抜けてから1回の台帳読み直しでまとめて引き、
    // そこで[`PendingElevation`]を組む（1件ずつ引くと、システム保護されたパスが多いドメインで
    // 台帳の全文往復が件数ぶん戻ってくる）。
    let mut pending_elevation: Vec<(FsPassthrough, crate::win_common::OwnedSid, String)> =
        Vec::new();
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
    // [§22.3] **この実行で実際に開いた穴**（既に足りていた・いま書いた・昇格側が書いた・
    // 部分適用で残った、のすべてを含む）。
    //
    // **セッション台帳へは記録しない。** 宣言はworkspaceの性質であってセッションの性質では
    // なく、その宛先SID（宣言ごとのcapability SID）は§22.2.1により**永続**である。記録すると
    // `end_session`がそのエントリを「回収済み」として落とすので、ACEは実マシンに残るのに
    // **それを覚えている記録だけが消える**（撤収に使える索引は
    // `workspace-capability-ledger.json`の宣言エントリで、付与時に必ず作られている）。
    //
    // ここで集めるのは§22.3.0の不変条件の検算（この関数の末尾）に使うためである。
    let mut fs_allow_opened_paths: Vec<std::path::PathBuf> = Vec::new();
    // [§22.3] **この穴の宛先SID**（宣言ごとのcapability SID）。2つの用途で持ち回る。
    //
    // 1. **子のトークンへ積む**——ACEを付けても、子がそのcapabilityを持っていなければ
    //    1バイトも読めない。`--fs-allow`がpackage SID宛だった頃はセッションのSIDが
    //    自動的に宛先SIDだったので、この持ち回り自体が要らなかった。
    // 2. **撤収側へ渡す**——どのSID宛に付けたかを台帳へ記録する（BUG-101）。宛先SIDは
    //    セッションに1つではなく**パスごとに違う**ので、呼び出し元が
    //    `current_session_grant_sid()`から1つ取る形はもう成立しない。
    let mut fs_allow_caps: Vec<crate::win_common::OwnedSid> = Vec::new();

    // 付与フェーズの進捗をUIへ見せる（`passthrough_progress`のdoc参照）。この区間は
    // 数百件になり得るので、**何件目かが見えないと「固まった」と読まれる**。
    // ガードなので、この下のどの`?`で抜けてもフェーズは閉じる。
    //
    // **共有セルを名指しするのはここを含めて製品の3箇所だけ**（BUG-138。他は
    // `grant_audit::probe_all`とポリシーエディタの`RunState::new`）。この関数の中の
    // 進捗はすべてこの束縛を通す——各所で`global()`と書くと、数える対象が増える。
    let progress = passthrough_progress::global();
    let grant_phase = progress.begin(passthrough.len());

    // [残課題#37] **付与は「絞り込み → 宛先SIDの一括確保 → 付与」の3段に割ってある。**
    //
    // 宛先SIDの確保は台帳のread-modify-writeなので、宣言1件ごとに呼ぶと全文の読み書きを
    // 宣言の本数だけ払う。台帳が育つほど1件あたりが高くなり、実測で宣言668件のとき**13.46秒**
    // ——**ACEを1本も書く前に**乗る（`plans/mac-spike/RESULTS.md` §S42-5）。しかもこの費用は
    // 下の`already_sufficient`（冪等スキップ）より手前にあるので、2回目以降の起動でも全額払う。
    //
    // **絞り込みを先に済ませてから確保する。** 確保した時点で台帳に撤収の索引が載るので、
    // 存在しないパスまで混ぜると**剥がす相手のいない記録**が残る（`B-01`/`B-14`）。
    //
    // 進捗は**この段では進めない**（存在しないパスを落とすぶんだけ進める）。ここで全件進めると
    // ゲージが一瞬で満ちてから、実際のACE書込の間だけ止まって見える。
    let mut resolved: Vec<(FsPassthrough, bool)> = Vec::with_capacity(passthrough.len());
    for requested in passthrough {
        if !requested.path.exists() {
            progress.advance();
            let reason = "path does not exist, skipped".to_string();
            warnings.push(format!("fs-allow {} : {reason}", requested.path.display()));
            denied_passthrough.push((
                requested.path.clone(),
                requested.access.label().to_string(),
                reason,
            ));
            continue;
        }

        // D-30（`--sandbox tier2a-cow`）: fs-allowの`:rw`要求は、実際にOSへ付与するACLではRead止まりにする
        // （実行権限は与えない、`FsAccess::Read`。`FsAccess::ReadExec`ではない点に注意）。
        // `--sandbox tier2a-cow`が存在する理由は「変更のあったファイルだけを単位としてレビュー・ロールバック
        // できること」（CoW＝ファイル単位の巻き戻し可能性が本質、スナップショット全体コピー
        // 方式ではない）であり、明示的にRO/ReadExecなfs-allowエントリはそもそも書込の余地が
        // 無いので対象外——ここで動的にRWをRO化しているのは、あくまで「元々RWだったものへ
        // 強制的にRedirector DLLのフックを通す書込経路」を作るための道具であって、頼まれても
        // いない実行権限まで付与する理由は無い（ユーザー指摘により`ReadExec`から`Read`へ訂正、
        // 2026-08-02）。workspace本体が`--sandbox tier2a-cow`下で`grant_ace_inheritable_ro`
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
        resolved.push((
            FsPassthrough {
                path: requested.path.clone(),
                access: effective_access,
                forced: requested.forced,
                // [D-63] スコープは`--sandbox tier2a-cow`でも変えない。上でRO化しているのは**アクセス種別**であって
                // 範囲ではない（範囲を狭めると、宣言した配下がRedirector DLL経由でも読めなくなる）。
                scope: requested.scope,
            },
            requested.access.is_read_write(),
        ));
    }

    // [§22.3 / 残課題#37] **この宣言たちの宛先SID**を、1回の台帳更新でまとめて確保する。
    // 以前はセッションのpackage SID（＝サンドボックス全体で共有されるSID）だったので、
    // `cargo`のために開けた穴が`pwsh`にも同じだけ開いていた。宛先SIDを宣言ごとに分けて初めて、
    // ドメインごとのFS制御が成立する。
    //
    // **導出には確定した級（`fp.access`）を使う。** ユーザーが要求した級ではない——CoWでRO降格
    // した場合、導出に使った級と実際に書いたマスクがずれると、撤収側は別の宛先SIDを探しに行って
    // 1件も剥がせない。だから級を決める分岐は上の1箇所だけにして、その結果をここへ渡す。
    let subject_requests: Vec<(&Path, FsAccess)> = resolved
        .iter()
        .map(|(fp, _)| (fp.path.as_path(), fp.access))
        .collect();
    let subjects =
        fs_allow_capability_sids_for_declarations(&canonical_workspace_root, &subject_requests);
    timing.mark(&format!(
        "fs-allow subjects minted ({} declarations, one ledger update)",
        subject_requests.len()
    ));

    for ((fp, requested_rw), subject) in resolved.iter().zip(subjects) {
        progress.advance();
        let requested_rw = *requested_rw;
        // 宛先SIDを作れなければ**この穴は開けない**（fail-closed）。乱数が取れないときに
        // 弱い秘密へ退避しないのは`workspace_capability`のdocのとおりで、ここで
        // package SIDへ退避するのは「移行したつもりで全ドメインに開く」という
        // 最悪の退避になる。**失敗は要素ごと**なので、他の宣言はそのまま続く。
        let entry_cap = match subject {
            Ok(cap) => cap,
            Err(e) => {
                let reason = format!("could not derive the capability for this declaration: {e}");
                warnings.push(format!("fs-allow {} : {reason}", fp.path.display()));
                denied_passthrough.push((fp.path.clone(), fp.access.label().to_string(), reason));
                continue;
            }
        };

        // [§22.3.0] **移行は付与と撤去で1つ。** capability宛を足しただけでは1ミリも成立しない
        // ——DACLは「この宛先SID**かつ**あの宛先SID」を表現できず、並べたALLOWはどれか1つで通るので、
        // 残ったpackage SID宛ACEが引き続き全ドメインへ許可を出し続ける。しかも**その状態は
        // 成功に見える**（新しいACEは正しく付き、アクセスも通る）。
        //
        // [§22.3.0.1] **順序は「消す→付ける」。** 逆にすると、その一瞬だけ
        // 「package SID **または** capability SID」で通る＝権限が広がる側へ倒れる。
        // ここは子プロセスを1つも起こす前の区間なので、削除を先に置くだけで満たせる
        // （1ノード1書込へまとめる部品は残課題#32の担当で、ここでは作らない）。
        //
        // **rootに明示ACEが無ければ何もしない。** 読取1回で判定でき、移行が済んだ2回目以降は
        // ここが常に空振りする——毎起動でツリー全walk（実測30.8秒）を回さないためのゲートである。
        // rootには無いが子孫に残っている（部分適用の残り）場合はここでは拾えないので、
        // その掃除は名前の付いた扉（`harness fs revoke <path>`）に委ねる。
        if matches!(sid_explicit_ace(&fp.path, sid.as_psid()), Ok(Some(_))) {
            match revoke_passthrough(&fp.path, sid.as_psid()) {
                RevokeOutcome::FullyRevoked => {}
                outcome => warnings.push(format!(
                    "fs-allow {} : could not fully remove the session package-SID ACE left by the \
                     pre-migration layout ({outcome:?}); until it is gone this path stays open to \
                     every domain in the session (plans/DESIGN-MAC-DOMAIN.md §22.3.0). Run \
                     `harness fs revoke {}` to clean it up",
                    fp.path.display(),
                    fp.path.display()
                )),
            }
        }

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
        let existing_ace = sid_explicit_ace(&fp.path, entry_cap.as_psid())
            .ok()
            .flatten();
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
                         declaration's capability SID is already on it, so the whole subtree stays \
                         open. harness does not narrow it here (removing the inheritable ACE would \
                         not remove the copies already propagated to descendants). Run \
                         `harness fs revoke {}` if you want it closed.",
                        fp.path.display(),
                        fp.path.display()
                    ));
                }
            }
        }
        // [§22.3] **宛先SIDはこの穴を開けるどの経路でも同じものを使う。** 既に足りていた／
        // いま書いた／昇格へ回した、のどれを通っても子のトークンへ積む集合と台帳へ記録する
        // 宛先SIDは変わらない——3つの入口のうち1つだけ違う宛先SIDになる形を作らない（B-02）。
        //
        // **宛先SIDの文字列は先に1回だけ作る。** ここで失敗するなら穴を開けない——
        // 開いてしまうと「ACEは書いたが、それがどのSID宛かを誰も知らない」＝撤収経路の
        // 無いACEになる（BUG-101と同じ形）。かつては文字列化の失敗を`if let Ok`で
        // 黙って読み飛ばしており、その行だけ宛先SIDを持たないまま「開いた穴」に数えられていた。
        let entry_cap_text = match crate::win_common::sid_to_string(entry_cap.as_psid()) {
            Ok(text) => text,
            Err(e) => {
                let reason =
                    format!("could not render the capability SID for this declaration: {e}");
                warnings.push(format!("fs-allow {} : {reason}", fp.path.display()));
                denied_passthrough.push((fp.path.clone(), fp.access.label().to_string(), reason));
                continue;
            }
        };
        let remember_subject = |caps: &mut Vec<crate::win_common::OwnedSid>| {
            if let Ok(copy) = unsafe { crate::win_common::OwnedSid::copy_from(entry_cap.as_psid()) }
            {
                caps.push(copy);
            }
        };
        let granted_entry = |writable: bool| harness_core::GrantedPassthrough {
            path: fp.path.clone(),
            writable,
            subject_sid: entry_cap_text.clone(),
        };

        if already_sufficient {
            // **Win32を1回も呼んでいない**ことを数える。ここが2回目以降で総数に一致する
            // ことが「差分適用になっている」の証拠になる（`passthrough_progress`のdoc）。
            progress.record_already_sufficient();
            granted_passthrough.push(granted_entry(requested_rw));
            // [§22.3] 付与を**スキップした**場合も「開いた穴」として数える——ACEを実際に
            // 書いたのが前のセッションでも、いまこの穴は開いている（BUG-057が
            // session ledgerについて言っていたのと同じ理由で、検算の対象から外さない）。
            // どのSID宛に付いているかは`granted_passthrough`の各要素が運ぶ。
            fs_allow_opened_paths.push(fp.path.clone());
            remember_subject(&mut fs_allow_caps);
            probe_targets.push(fp.clone());
            continue;
        }

        // [D-63] **宣言された範囲でだけ開く。** 素のパスはそのオブジェクト1つ、`<path>/**`は
        // 継承ACE。ここを`grant_ace_inheritable_access`固定にしていたのが、D-62で候補を畳むのを
        // やめた後も「観測された2件を承認したらサブツリー全体が開く」状態が残っていた理由である。
        let grant_result = grant_ace_scoped(&fp.path, entry_cap.as_psid(), fp.access, fp.scope);
        match grant_result {
            Ok(()) => {
                // 実際にACEを書いた1件。
                progress.record_granted();
                granted_passthrough.push(granted_entry(requested_rw));
                fs_allow_opened_paths.push(fp.path.clone());
                remember_subject(&mut fs_allow_caps);
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
                //
                // [§22.3] **導出済みの宛先SIDを一緒に持たせる。** 昇格から戻った後に
                // 引き直さないための唯一の手段で、引き直しをやめたことで
                // 「宛先SIDの無い開いた穴」が構造的に作れなくなる。
                let subject = match unsafe {
                    crate::win_common::OwnedSid::copy_from(entry_cap.as_psid())
                } {
                    Ok(copy) => copy,
                    Err(e) => {
                        let reason =
                            format!("could not copy the capability SID for this declaration: {e}");
                        warnings.push(format!("fs-allow {} : {reason}", fp.path.display()));
                        denied_passthrough.push((
                            fp.path.clone(),
                            fp.access.label().to_string(),
                            reason,
                        ));
                        continue;
                    }
                };
                // [残課題#37] 秘密はここでは引かない（このループを抜けてから1回でまとめて引く）。
                pending_elevation.push((fp.clone(), subject, entry_cap_text.clone()));
            }
        }
    }

    // [§22.3.1] **昇格側へはSIDでも名前でもなく秘密を渡す**（受信側が書込先のパスを自分で
    // 畳み込んで導出する）。秘密を引くのは**この1箇所だけ**にしてある——共通経路で持ち回ると、
    // ログやエラー文へ載る面が増える。台帳エントリは上の一括確保が既に作っているので、
    // ここは冪等な読み直しであり、**件数によらず1回の`update`で済む**（残課題#37）。
    if !pending_elevation.is_empty() {
        let secret_requests: Vec<(&Path, &str)> = pending_elevation
            .iter()
            .map(|(fp, _, _)| (fp.path.as_path(), fp.access.label()))
            .collect();
        let issued = crate::tier2a::workspace_capability::ensure_declaration_capabilities(
            &canonical_workspace_root,
            &secret_requests,
        );
        for ((fp, subject, subject_sid), capability) in pending_elevation.into_iter().zip(issued) {
            match capability {
                Ok(capability) => needs_elevation.push(PendingElevation {
                    grant: crate::tier2a::privhelper::FsAllowGrant {
                        path: fp.path.clone(),
                        access: fp.access,
                        forced: fp.forced,
                        // [D-63] 昇格へ回しても宣言の範囲は変わらない。
                        scope: fp.scope,
                        secret_hex: capability.secret_hex,
                    },
                    subject,
                    subject_sid,
                }),
                // **黙って落とさない**（B-10）。ここで落ちた宣言は昇格へ回らないので、
                // その穴は開かないまま終わる。
                Err(e) => {
                    let reason = format!(
                        "could not read back the capability secret for this declaration: {e}"
                    );
                    warnings.push(format!("fs-allow {} : {reason}", fp.path.display()));
                    denied_passthrough.push((
                        fp.path.clone(),
                        fp.access.label().to_string(),
                        reason,
                    ));
                }
            }
        }
    }

    if !missing_traverse.is_empty() || !needs_elevation.is_empty() {
        let elevated: Result<FsAllowElevationOutcome, String> =
            if crate::tier2a::privhelper::is_elevated() {
                // 本体が既に管理者（§5.3、grant-traverseの`*_direct`と同じ考え方）:
                // ヘルパーを経由せずその場で直接付与する。traverseが不足していれば先に解消する
                // （workspace_root/diff_layer_dirへ到達できなければfs-allow付与自体が無意味なため）。
                let (_, direct_traverse) =
                    crate::tier2a::traverse_ledger::with_recorded_traverse_grants(
                        &missing_traverse,
                        || {
                            let mut granted = Vec::new();
                            for target in &missing_traverse {
                                let (nodes, result) =
                                    grant_traverse_chain(target, traverse_sid.as_psid());
                                granted.extend(nodes);
                                if let Err(e) = result {
                                    return (
                                        granted,
                                        Err(AppContainerError::Preflight(format!(
                                        "failed to grant traverse ACE (admin, direct) for {}: {e}",
                                        target.display()
                                    ))),
                                    );
                                }
                            }
                            (granted, Ok(()))
                        },
                    );
                direct_traverse?;
                let mut granted = Vec::new();
                let mut failures = Vec::new();
                for entry in &needs_elevation {
                    let grant = &entry.grant;
                    // forcedは書込前に絶対拒否ゲートを通し、通過分のみ`SeRestorePrivilege`下で付与する
                    // （dispatch側と同じ防壁。本体が既に管理者の経路でも同一の不変条件を保つ）。
                    if grant.forced {
                        if let Some(reason) = is_force_grant_forbidden(&grant.path) {
                            failures.push((grant.path.clone(), reason));
                            continue;
                        }
                    }
                    // [§22.3] 宛先SIDは**本体内の付与が導出したものそのもの**である。
                    // ここで導出し直していたのを2026-09-01にやめた——同じ値を作る場所が2箇所
                    // あると、同じ宣言なのに「システム保護パスに在るかどうか」で開く相手が
                    // 変わり得る形が残る。
                    // [D-63] 本体が既に管理者の直接付与も**同じスコープ分岐を通る**
                    // （3つの入口のうち1つだけ従わない形を作らない、B-02）。
                    let do_grant = || {
                        grant_ace_scoped(
                            &grant.path,
                            entry.subject.as_psid(),
                            grant.access,
                            grant.scope,
                        )
                    };
                    let result = if grant.forced {
                        with_restore_privilege(do_grant)
                    } else {
                        do_grant()
                    };
                    match result {
                        Ok(()) => granted.push(grant.path.clone()),
                        Err(e) => failures.push((grant.path.clone(), e.to_string())),
                    }
                }
                Ok((granted, failures))
            } else {
                // [BUG-101] **委譲した付与は、このプロセスのDACL書込の絞り口を通らない**
                // （書くのは昇格側のプロセス）。ここで「依頼した」ことだけを残し、実際に
                // 載ったかは自己検証のDACL実測が決める——依頼と結果を同じ値にしない（B-09）。
                //
                // [§22.3] 記録する宛先SIDは**この宣言のcapability**である。セッションの
                // package SIDのまま記録すると、自己検証は「付けたはずのACEが無い」と
                // 全件について言い続ける（測る相手が違うだけなのに）。
                for entry in &needs_elevation {
                    crate::tier2a::grant_audit::note_delegated_grant(
                        &entry.grant.path,
                        entry.subject.as_psid(),
                    );
                }
                let (_, elevated_outcome) =
                    crate::tier2a::traverse_ledger::with_recorded_traverse_grants(
                        &missing_traverse,
                        || match crate::tier2a::privhelper::run_privileged_workspace_access(
                            missing_traverse.clone(),
                            needs_elevation.iter().map(|e| e.grant.clone()).collect(),
                            wfp_chain_pipe.clone(),
                            privhelper_launcher,
                        ) {
                            Ok(outcome) => (outcome.0.clone(), Ok(outcome)),
                            Err(e) => (Vec::new(), Err(e)),
                        },
                    );
                match elevated_outcome {
                    Ok((
                        _traverse_granted,
                        traverse_error,
                        granted,
                        failures,
                        netfilterd_chain,
                    )) => {
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

        // [§22.3] 昇格経路の後始末は3つに分かれる（完走・部分適用・ヘルパー不通）が、
        // **どれも同じ宛先SIDを見なければならない**。それを保証しているのは、
        // 3つとも`needs_elevation`の要素（[`PendingElevation`]）から宛先SIDを読むことである。
        //
        // **2026-09-01に`elevated_subject`（ここで導出し直すクロージャ）を廃した。**
        // 宛先SIDは昇格へ回す前に導出済みで、失敗した宣言はここへ到達しない。
        // 引き直しは同じ値をもう一度作るだけで、失敗した行が「宛先SIDの無い開いた穴」として
        // 残る余地を作っていた。
        //
        // **`granted`/`failures`ではなく`needs_elevation`を回す。** 昇格側が返すのはパスだけで、
        // こちら側の宣言と突き合わせないと級も宛先SIDも分からない。**送った集合を主にして
        // 結果を引く**ほうが、返ってきたパスを主にして`unwrap_or`で埋めるより取りこぼさない。
        match elevated {
            Ok((granted, failures)) => {
                for entry in &needs_elevation {
                    let grant = &entry.grant;
                    let path = &grant.path;
                    if granted.iter().any(|p| p == path) {
                        // [§22.3] 昇格側が書いたACEの宛先SIDも、子のトークンと台帳へ運ぶ
                        // ——ここが抜けると、**穴は開いているのに子がその宛先SIDを持っていない**
                        // （＝到達不能）か、**撤収経路の無い孤立ACE**のどちらかになる。
                        fs_allow_caps.push(entry.subject.clone());
                        granted_passthrough.push(harness_core::GrantedPassthrough {
                            path: path.clone(),
                            writable: grant.access.is_read_write(),
                            subject_sid: entry.subject_sid.clone(),
                        });
                        // 昇格経由（privhelper／本体が既に管理者）の付与も「書いた1件」に数える
                        // ——どの経路で書いたかではなく、**マシンのACLを変えたか**が知りたい事実。
                        // 開いた穴の集合にも同じ理由で入れる（BUG-057が「昇格経由だけが記録から
                        // 漏れる」形を踏んでいるので、経路ごとに数え方を変えない）。
                        progress.record_granted();
                        fs_allow_opened_paths.push(path.clone());
                        if let Some(fp) = passthrough.iter().find(|fp| &fp.path == path) {
                            probe_targets.push(fp.clone());
                        }
                        continue;
                    }
                    let Some((_, reason)) = failures.iter().find(|(p, _)| p == path) else {
                        // 送ったのに`granted`にも`failures`にも居ない。**黙って落とさない**
                        // （B-09/B-10: 「対象が無かった」と「見失った」は別の事実）。
                        warnings.push(format!(
                            "fs-allow {} : the privilege-separation helper (D-16) reported neither \
                             success nor failure for this declaration; treating it as not granted",
                            path.display()
                        ));
                        continue;
                    };
                    // BUG-017: grant_ace_recursive/grant_ace_inheritable_roはroot(先頭ノード)から
                    // 順に付与するため、途中の子孫(TrustedInstaller所有等)で失敗しても、rootには
                    // 既にACEが載っている場合がある。「失敗」扱いにして`granted_passthrough`から
                    // 落とすと、実FS上にはACEが残るのに呼び出し元（`fs-passthrough-ledger`への
                    // 記録）から漏れ、撤収経路の無い孤立ACEになる。rootを権威的にプローブし、
                    // ACEが実在すれば記録して`fs revoke`で後から掃除できるようにする。
                    if matches!(sid_ace_mask(path, entry.subject.as_psid()), Ok(Some(_))) {
                        granted_passthrough.push(harness_core::GrantedPassthrough {
                            path: path.clone(),
                            writable: grant.access.is_read_write(),
                            subject_sid: entry.subject_sid.clone(),
                        });
                        // 部分適用でACEが実在するなら、それは「開いた穴」である
                        // （§22.3.0の検算からも外さない）。
                        fs_allow_opened_paths.push(path.clone());
                        fs_allow_caps.push(entry.subject.clone());
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
                            grant.access.label().to_string(),
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
                    let grant = &entry.grant;
                    if matches!(
                        sid_ace_mask(&grant.path, entry.subject.as_psid()),
                        Ok(Some(_))
                    ) {
                        granted_passthrough.push(harness_core::GrantedPassthrough {
                            path: grant.path.clone(),
                            writable: grant.access.is_read_write(),
                            subject_sid: entry.subject_sid.clone(),
                        });
                        // 上と同じ（ヘルパーが完走できなかった場合の部分適用）。
                        fs_allow_opened_paths.push(grant.path.clone());
                        fs_allow_caps.push(entry.subject.clone());
                        warnings.push(format!(
                            "fs-allow {} : partially applied -- the privilege-separation helper \
                             (D-16) could not fully complete ({reason}), but the root itself now \
                             carries the sandbox ACE; recorded in the ledger so `harness fs revoke \
                             {}` can clean it up",
                            grant.path.display(),
                            grant.path.display()
                        ));
                    } else {
                        denied_passthrough.push((
                            grant.path.clone(),
                            grant.access.label().to_string(),
                            format!(
                                "ACE grant failed: access denied in-process, and the privilege-separation helper (D-16) could not complete either: {reason}"
                            ),
                        ));
                        warnings.push(format!(
                            "fs-allow {} : ACE grant failed: access denied in-process, and the \
                             privilege-separation helper (D-16) could not complete either: {reason}",
                            grant.path.display()
                        ));
                    }
                }
            }
        }
    }

    // [§22.3] **`--fs-allow`の穴はセッション台帳へ記録しない。** かつてはここで
    // `record_granted_paths`を呼び、`end_session`が同じパスからセッションのpackage SID宛ACEを
    // 剥がしていた（BUG-057）。宛先SIDが宣言ごとのcapability SIDへ移った後は、その撤収は
    // **何も剥がさないのに台帳エントリだけを「回収済み」として落とす**——ACEは実マシンに
    // 残るのに、それを覚えている記録が消える形になる。
    //
    // 撤収の索引は`workspace-capability-ledger.json`の宣言エントリで、付与時に
    // `fs_allow_capability_sid`が必ず作っている（§22.2.1「撤収すべきSIDは宣言から一意に
    // 計算できる」）。剥がすのは名前の付いた扉と、宣言が消えたときの起動時の差分である。
    //
    // **CoW Redirector DLL（このセッションのpackage SID宛）は従来どおり記録する**——
    // あちらは宛先SIDもセッションと同じ寿命なので、`end_session`が正しく剥がせる。

    // 付与フェーズはここで終わり（以降は到達性プローブとスモークテスト）。明示的に落として、
    // UIが「ACE付与 N/N」を出し続けないようにする。
    drop(grant_phase);

    // [§22.3.0] **移行の不変条件をここで検算する。**
    //
    // > 移行対象のパスに、セッション package SID 宛のACEが0本であること。
    //
    // 残っていると、その1本が同一セッションの**全ドメイン**へ許可を出し続ける——DACLは
    // 「この宛先SIDかつあの宛先SID」を表現できないので、capability宛を足しただけの状態は
    // **成功に見えるのに1ミリも制御が効いていない**。だから「付けたか」ではなく
    // 「**旧い宛先SIDが消えたか**」を測る。
    //
    // **新しい検算機構は作らない**（§22.3.0）。既にある宛先SIDの突き合わせ（この直後の
    // `audit_guard`＝BUG-101の自己検証）と同じ場所・同じ`warnings`へ寄せる。ここを
    // 別の仕組みにすると、移行後に「常時警告」か「沈黙」のどちらかへ倒れる。
    //
    // 測るのは`fs_allow_opened_paths`（＝実際に開いた穴）だけで、rootへの明示ACEを1件読む
    // だけである。
    let unmigrated: Vec<&std::path::PathBuf> = fs_allow_opened_paths
        .iter()
        .filter(|path| matches!(sid_explicit_ace(path, sid.as_psid()), Ok(Some(_))))
        .collect();
    if !unmigrated.is_empty() {
        const SHOWN: usize = 5;
        let head: Vec<String> = unmigrated
            .iter()
            .take(SHOWN)
            .map(|p| p.display().to_string())
            .collect();
        warnings.push(format!(
            "**{} 件のfs-allowパスに、このセッションのpackage SID宛ACEが残っています。** \
             package SIDはサンドボックス全体で共有されるSIDなので、その1本が残っている間は \
             宣言していないドメインからもこのパスへ届きます（capability宛を足しても\
             打ち消せません。plans/DESIGN-MAC-DOMAIN.md §22.3.0）: {}{}",
            unmigrated.len(),
            head.join(" / "),
            if unmigrated.len() > SHOWN {
                format!(" ほか{}件", unmigrated.len() - SHOWN)
            } else {
                String::new()
            }
        ));
    }
    timing.mark("§22.3.0 migration invariant (no session package-SID ACE left)");

    // [BUG-101] **付与直後に、実マシンのDACLと台帳を突き合わせる。**
    // 記録するつもりだった集合と台帳を比べても、付与側の思い込みが両辺に乗るだけで
    // 差は出ない。見るのは実測したACEである（`grant_audit`のdoc）。
    audit_guard.finish(&mut warnings);
    timing.mark("grant audit (BUG-101)");

    // **この機で使うシェルを、ここで実際に起こして決める**（`select_shell_by_probe`のdoc）。
    // 以降のプローブ（`probe_passthrough_batch`・2つのsmoke test）と`run_shell`本体は
    // すべて`resolve_shell()`を読むので、選択はそれらより前で終えていなければならない。
    warnings.extend(select_shell_by_probe(
        sid.as_psid(),
        workspace_cap_psid,
        workspace_root,
    ));
    timing.mark("shell selection");

    // [§22.3] プローブと本番の子が積むcapability。**穴の宛先SIDを積まないと、付与が正しくても
    // 到達性プローブは全件「到達不能」になる**（`probe_capabilities`のdoc）。
    //
    // [§22.3.2] **差分層のcapability SIDもここに入る。** CoWのsmoke testは`probe_dir`を差分層の中に
    // 作って書込を試すので、積まないと「workspace FS I/Oが拒否された」と誤診断して
    // `preflight`が起動そのものを拒否する（移行の最中に実際に踏んだ）。
    let mut fs_allow_cap_psids: Vec<windows::Win32::Security::PSID> =
        fs_allow_caps.iter().map(|cap| cap.as_psid()).collect();
    fs_allow_cap_psids.extend(cow_diff_layer_cap.iter().map(|cap| cap.as_psid()));

    // D8: 到達性プローブは**ここで1回だけ**行う（付与も昇格も全部終わった後）。
    // 対象が0件なら子プロセスは1つも起こさない。
    match probe_passthrough_batch(
        sid.as_psid(),
        traverse_sid.as_psid(),
        workspace_cap_psid,
        &fs_allow_cap_psids,
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
    // 書込可能であるべき場所（DirectRw時はworkspace、Cow時はdiff_layer_dir）に置く。上のtraverse
    // 自動付与を経た後の保険として、未知の原因によるFS I/O拒否をここで最終確認する。
    let probe_base = match write_mode {
        WorkspaceWriteMode::DirectRw => workspace_root,
        WorkspaceWriteMode::Cow { diff_layer_dir } => diff_layer_dir.as_path(),
    };
    let tmp_dir = probe_base.join(format!(".harness-tier2a-probe-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir).map_err(|e| AppContainerError::Preflight(e.to_string()))?;
    timing.mark("traverse/fs-allow/elevation");
    let smoke_result = smoke_test_spawn(
        sid.as_psid(),
        workspace_cap_psid,
        &fs_allow_cap_psids,
        workspace_root,
        &tmp_dir,
    );
    let _ = std::fs::remove_dir_all(&tmp_dir);
    smoke_result?;
    smoke_test_harness_control_write_denied(
        sid.as_psid(),
        workspace_cap_psid,
        &fs_allow_cap_psids,
        workspace_root,
    )?;
    timing.mark("smoke tests");

    // D-54: 救済walkはここで初めて起動する——**`preflight`のACL作業を全て終えた後**である
    // ことが、DACL書込の競合を避ける条件になっている（`grant_job`のdoc）。rootへの継承付与は
    // 既に同期で終わっているので、workspaceの大半はこの時点で到達可能であり、残りは
    // 保護DACL配下だけである。子プロセスを起動する経路は`grant_job::wait_until_done`で
    // 完了を待つ（待たずに走らせると、モデルには「そのファイルは無い」と見える）。
    if needs_descendant_fix {
        // [BUG-082 Part B] 背景フェーズが行う伝播はrootへの継承ACE伝播である。
        // [BUG-145] **`.harness/`の保護が実際に効くようになったのは2026-08-30以降である**
        // （かつてここは「BUG-083の修正で」と書いていたが、あの修正はこの機で一度も効いて
        // いなかった——保護の書込が冪等スキップで丸ごと省かれていた）。いまはこの伝播が
        // OS側で`.harness/`の手前で止まるが、
        // 保護が止められるのは**継承経由の伝播だけ**なので、保護前から物理コピーとして乗っていた
        // ACEやD-37時代のpackage SID残骸に備えて背景側でも剥がし直す（第2の防御）。ここで渡す
        // `.harness/`再保護用のSIDは、上の
        // 同期`protect_harness_control_dir_from_appcontainer`呼び出しと**同じ集合**
        // （**全モードのcapability SID**＋セッションSID）にする——片方だけだと剥がし残した側から
        // 制御面が書けるのは同期区間と同じ理屈（`revoke.rs`のdoc参照）。
        let session_sid_copy = unsafe { crate::win_common::OwnedSid::copy_from(sid.as_psid()) }
            .map_err(|e| {
                AppContainerError::Preflight(format!(
                    "failed to copy the session SID for background .harness re-protection: {e}"
                ))
            })?;
        let mut harness_protect_sids: Vec<crate::win_common::OwnedSid> = workspace_cap_sids
            .iter()
            .map(|(_, sid)| sid.clone())
            .collect();
        harness_protect_sids.push(session_sid_copy);

        // [D-84] 背景ジョブへも**全モードのcapability SID**を渡す。同期区間はrootへ2本置いたのに
        // 背景の伝播が1本だけだと、既存の子孫には片方しか届かない——次にモードを切り替えた
        // セッションが26万件を払い直す状態へ戻る（`B-01`: 同じ決定を全経路へ届ける）。
        let owned_ace_grants: Vec<OwnedAceGrant> = workspace_cap_sids
            .into_iter()
            .map(|(mode, sid)| OwnedAceGrant {
                sid,
                mask: workspace_mode_mask(mode),
            })
            .collect();

        // [D-85] ジョブの同一性は (workspace, mode, capabilityの世代) で決まる。世代を落とすと、
        // 秘密が入れ替わって**宛先SIDが別のSIDになった**あとも「同じジョブが走っている」と誤判定し、
        // 新しい世代の準備が始まらない。
        let capability_generation = crate::tier2a::workspace_capability::ensure_capability_name(
            &canonical_workspace_root,
            workspace_mode.as_str(),
        )
        .map_err(AppContainerError::Preflight)?;

        // 戻り値の`false`は「このプロセスでは既に別のジョブが走っている」＝`preflight`が2回
        // 呼ばれた場合だけで、製品では起こらない（実機テストが同居するときだけ）。
        let started = grant_job::start(grant_job::GrantJobRequest {
            root: workspace_root,
            ace_grants: owned_ace_grants,
            protect_sids: harness_protect_sids,
            // 上の`top_level_child_missing_aces`と**同じ集合**（`B-05`。ここがずれると、
            // ジョブが意図的に外した場所を検算側が数えて毎起動でジョブが回る）。
            skip: job_skip,
            workspace: &canonical_workspace_root,
            mode: workspace_mode.as_str(),
            capability_generation: &capability_generation,
            // [D-88（`DESIGN-SANDBOX-APPPOLICY.md`）] レーンの選択は実験的probeが決める
            // （既定は今日と同じ`FullWalk`）。**選ぶ場所はここ1つ**——`start`の時点で
            // 決まらないと、走査器とfault受付を用意する側が間に合わない。
            // 起動側（`launch`）は「受付が開いているか」だけを見て、決め直さない。
            lane: super::lazy_grant::lane(),
        });
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

/// `path`が載っているボリュームがACLを保持できることを確かめ、できなければ起動を拒否する（D-81）。
///
/// 規則そのもの（判定・文言・判定不能時に倒す向き）は
/// [`crate::session_scope::persistent_acl_gate`]が持つ純関数で、ここはボリュームの採取と
/// エラー型への変換だけを行う。**採取と判定を分ける**のは、判定側を`cargo test`で
/// 検算できるようにするためである。
pub(crate) fn require_persistent_acl_volume(
    what: &str,
    path: &Path,
) -> Result<(), AppContainerError> {
    let mount = crate::win_common::volume_mount_point_of(path);
    let probe = mount
        .as_deref()
        .and_then(crate::win_common::volume_capability);
    // 申告（上）だけでなく、**このボリュームが実際にDACLを受け付けるか**も測る。書き戻しは
    // 恒等なので副作用は無い。
    //
    // **測る先は`path`そのものではなく、同じボリューム上で実在する最も近い祖先である。**
    // 差分層は「点検してから作る」順序なので点検の時点では必ず存在せず、`path`を直接測ると
    // 毎回「測れなかった」になってCoWの起動そのものが塞がる（[BUG-130]）。見たいのは
    // ボリュームの性質なので、同じボリューム上の実在する祖先で足りる。
    //
    // **関数で渡すのは、安い判定で拒否が決まった相手に触らないため。** 実測は書込操作なので、
    // ネットワーク共有のように見に行くこと自体に費用が掛かる相手へ、拒否する直前に撃つ
    // 理由が無い（`cow_volume_gate`のdoc）。
    let dacl_writable = || {
        crate::session_scope::nearest_existing_ancestor(path, mount.as_deref(), &|p| p.exists())
            .map(|target| crate::win_common::can_write_dacl(&target))
    };
    crate::session_scope::cow_volume_gate(what, path, probe, &dacl_writable)
        .map_err(AppContainerError::Preflight)
}

#[cfg(test)]
mod acl_volume_gate_tests {
    use super::*;

    /// **[BUG-130](../../../../../docs/bugs/BUG-130.md)の回帰テスト。**
    ///
    /// 差分層は「点検してから作る」順序なので、点検の時点では**必ず**存在しない。
    /// 存在しないパスを直接測ると毎回「測れなかった」になり、判定不能を閉じる規則が
    /// CoWの起動そのものを塞ぐ（実際に`--sandbox tier2a-cow`が1つも起動できなくなった）。
    ///
    /// **判定側の単体テストではこれを捕まえられない。** `cow_volume_gate`へは
    /// `Some(true)`/`Some(false)`/`None`を直接渡しており、「**呼び出し側が`None`を
    /// 渡してしまう**」経路を再現していないからである。だから値を作るこちら側で測る。
    ///
    /// 拒否側は判定側（`session_scope`の`cow_volume_gate`まわり4件）が持つ。
    #[test]
    fn a_diff_layer_that_does_not_exist_yet_still_passes_the_acl_volume_gate() {
        let tmp = tempfile::tempdir().expect("一時ディレクトリを作れること");
        let not_yet = tmp.path().join("cow").join("session-does-not-exist-yet");
        assert!(
            !not_yet.exists(),
            "前提が崩れている: このパスは存在しないはず"
        );

        require_persistent_acl_volume("copy-on-write diff area", &not_yet)
            .expect("まだ作られていない差分層でも、同じボリューム上の実在する祖先で性質を測れる");
    }
}

/// **祖先traverseを要求する対象**（[`traverse_targets_for`]）のテスト。実マシンを読まない。
#[cfg(test)]
mod traverse_target_tests {
    use super::*;

    //
    // **ここが増えると、実マシンに恒久的なACEが増え、昇格（UAC）が要求される。**
    // だから「何を要求するか」は、実際に走らせて記録の増減を見るのではなく、
    // ここで直接測る——**まだACEが付いていない架空のパス**を渡せば、実マシンの状態にも
    // 昇格にも依存せず、何度でも同じ答えが出る。
    //
    // 走らせて測る形の限界は実際に踏んだ: §22.3.2の移行でtraverse台帳が7→10件へ増えたとき、
    // ACEは既に付いてしまっており、**変更前のコードで撃ち直しても冪等スキップで差が出ない**
    // ため、増えた理由を事後に決着できなかった。

    /// 通常起動（CoWでない）で要求するのは**workspaceの親だけ**。
    #[test]
    fn a_plain_session_only_asks_for_the_workspace_parent() {
        let targets = traverse_targets_for(
            Path::new(r"C:\work\repo"),
            &WorkspaceWriteMode::DirectRw,
            &[],
        );
        assert_eq!(targets, vec![std::path::PathBuf::from(r"C:\work")]);
    }

    /// CoWでは**差分層の親が1つ増えるだけ**。
    ///
    /// これが、移行の前後で変わっていないことを固定する当のものである——`traverse_targets_for`は
    /// **パスと書込モードだけ**から決まり、ACEの宛先（package SIDかcapability SIDか）を
    /// 一切見ない。したがって§22.3.2の宛先SIDの移行は、要求する祖先を1つも増やさない。
    #[test]
    fn a_cow_session_asks_for_the_diff_layer_parent_and_nothing_else() {
        let targets = traverse_targets_for(
            Path::new(r"C:\work\repo"),
            &WorkspaceWriteMode::Cow {
                diff_layer_dir: std::path::PathBuf::from(r"C:\layers\cow\session-42"),
            },
            &[],
        );
        assert_eq!(
            targets,
            vec![
                std::path::PathBuf::from(r"C:\work"),
                std::path::PathBuf::from(r"C:\layers\cow"),
            ]
        );
    }

    /// **leafは要求しない**（D-37）。要求すると、新しいパスを指定するたびに「ACEが無い」と
    /// 判定されて**毎回昇格を求める**——症状は「起動のたびにUACが出る」で、原因がここだと
    /// 分かりにくい。workspace・差分層の**どちらについても**入っていないことを見る。
    #[test]
    fn the_leaves_themselves_are_never_asked_for() {
        let workspace = Path::new(r"C:\work\repo");
        let diff_layer = std::path::PathBuf::from(r"C:\layers\cow\session-42");
        let targets = traverse_targets_for(
            workspace,
            &WorkspaceWriteMode::Cow {
                diff_layer_dir: diff_layer.clone(),
            },
            &[],
        );
        assert!(
            !targets.contains(&workspace.to_path_buf()),
            "workspace自身を要求している: {targets:?}"
        );
        assert!(
            !targets.contains(&diff_layer),
            "差分層自身を要求している: {targets:?}"
        );
    }

    /// `--fs-allow`は**親だけ**が入り、leafは入らない（D-45）。
    /// 実在するパスでなければ入らないので、一時ディレクトリを使う。
    #[test]
    fn a_declared_path_contributes_its_parent_but_not_itself() {
        let tmp = tempfile::tempdir().expect("一時ディレクトリ");
        let declared = tmp.path().join("tool");
        std::fs::create_dir_all(&declared).expect("宣言先を作る");

        let targets = traverse_targets_for(
            Path::new(r"C:\work\repo"),
            &WorkspaceWriteMode::DirectRw,
            &[FsPassthrough {
                path: declared.clone(),
                access: FsAccess::Read,
                forced: false,
                scope: GrantScope::Recursive,
            }],
        );

        assert!(
            targets.contains(&tmp.path().to_path_buf()),
            "宣言先の親が入っていない: {targets:?}"
        );
        assert!(
            !targets.contains(&declared),
            "宣言先自身を要求している（毎回昇格を求める形）: {targets:?}"
        );
    }

    /// **存在しない宣言先は、祖先のACLを書き換える理由にならない。**
    /// 後段が`path does not exist, skipped`として弾くものへ先回りしない。
    #[test]
    fn a_declared_path_that_does_not_exist_asks_for_nothing() {
        let targets = traverse_targets_for(
            Path::new(r"C:\work\repo"),
            &WorkspaceWriteMode::DirectRw,
            &[FsPassthrough {
                path: std::path::PathBuf::from(r"C:\definitely\not\here\at\all"),
                access: FsAccess::Read,
                forced: false,
                scope: GrantScope::Recursive,
            }],
        );
        assert_eq!(targets, vec![std::path::PathBuf::from(r"C:\work")]);
    }
}
