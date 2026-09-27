//! `win_appcontainer`配下の実機テストが共有する後始末ユーティリティ（テスト専用）。
//!
//! ここに集めているのはいずれも「**パニックしても実マシンに何も残さない**」ための道具である。
//! テスト末尾の`let _ = std::fs::remove_dir_all(...)`は正常終了時にしか走らず、assertが落ちた
//! 瞬間に残留物が生まれる——実際に`C:\harness-Tier2a-verify-*`が16件残っていたのが
//! [BUG-046](../../../../docs/bugs/BUG-046.md)の修正4である。RAIIなら`panic!`でも巻き戻る。
//!
//! `docs/CODE-STRUCTURE-RULES.md`規則5により、同じ`ScopeGuard`を各テストファイルへ複製せず
//! ここ1箇所に置く（元は`cow_containment_tests.rs`のprivate定義だった）。

use crate::tier2a::workspace_ledger::WorkspaceMode;

/// **本番の`run_shell`と同じ形で**AppContainer子を起こす（D-54）。
///
/// `preflight`はworkspaceツリーのACEを、セッションのpackage SIDではなく
/// **workspace＋モード単位のcapability SID**へ付ける。そのcapabilityを子のトークンへ積まないと
/// workspaceが一切見えず、PowerShellはcwdの設定に失敗して`C:\Windows\System32\...`へ
/// フォールバックする（実測: `preflight`を呼ぶ実機テスト12件がこれで落ちた）。
///
/// `cwd`が**workspace rootそのもの**であることを前提にしている（`preflight`へ渡したのと同じ
/// パス）。台帳に無ければ`None`を積む（＝素の[`super::spawn`]と同じ）。
///
/// # モードの決め方（**[D-84]で台帳引きをやめた**）
///
/// かつてここは「台帳に載っているモードを探して、見つかった方」を使っていた。当時は
/// `preflight`が登録するモードがちょうど1つだったので曖昧さが無かった——**その前提が
/// D-84で崩れた**。両モードのcapability SID宛ACEを常に配るようになったため、台帳には必ず2件載る。
/// 探索順で先に来る`rwx`が常に選ばれ、**CoWのテストの子が`rwx`のcapability SIDを積んで起動する**
/// ——workspace本体へ直接書けてしまい、封じ込めを測っているはずのテストが
/// 「封じ込めが無い世界」を測ることになる。
///
/// そこで本番の`launch.rs`とまったく同じ決め方にする: **`cow`が`Some`なら`ro`、
/// そうでなければ`rwx`**。「本番と同じ形」を名乗るヘルパーが本番と違うcapability SIDを積んでいたら、
/// 測っているものが違う（`B-08`）。
///
/// **`spawn`のシグネチャをそのまま写している**ので、テストの呼び出し側は関数名を差し替える
/// だけでよい。引数を1本足す形にしなかったのは、19箇所の呼び出しを機械的に置換できる方が
/// 取りこぼしが無いためである。
///
/// [BUG-082] `run_shell`（`crates/harness-tools/src/shell.rs`）と同じく、spawnの**前**に
/// `grant_job::wait_until_done()`を通す。D-54の背景ジョブがrootへの伝播（フェーズ0）まで
/// 引き受けるようになったため、`preflight`直後に子を起こすテストは、既存の（新規作成でない）
/// ファイルが**まだ見えていない**状態を踏みやすくなった——旧実装はrootへの伝播が`preflight`の
/// 同期区間で完了していたため、この待ち合わせが無くても大半のテストは無症状だった
/// （保護DACL配下だけを救う救済walkのみが背景だった頃の話）。「本番の`run_shell`と同じ形」を
/// 名乗る以上、このゲートも含めて同じ形にする。
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_in_workspace(
    exe: &str,
    args: &[&str],
    cwd: &std::path::Path,
    env: &[(String, String)],
    want_stdin: bool,
    container_sid: windows::Win32::Security::PSID,
    net: super::NetworkCapability,
    cow: Option<super::CowInject<'_>>,
) -> Result<super::AppContainerChild, super::AppContainerError> {
    // 本番の`launch.rs::workspace_mode`とまったく同じ導出（`cow`が`Some`なら`ro`）。
    // **この1行が「本番と同じ形」の中身である。**
    let mode = if cow.is_some() {
        WorkspaceMode::Ro
    } else {
        WorkspaceMode::Rwx
    };
    spawn_in_workspace_as(
        exe,
        args,
        cwd,
        env,
        want_stdin,
        container_sid,
        net,
        cow,
        mode,
        &[],
    )
}

/// [`spawn_in_workspace`]の**ドメインの積み方を外から渡せる版**。あちらはこれを、本番と同じ導出を
/// 適用して呼ぶ薄い包みである（同じ組み立てを2つ持たない、`docs/CODE-STRUCTURE-RULES.md`規則5）。
///
/// 引数は2つある。
///
/// - `mode` — workspace本体のどちらのモードのcapability SIDを積むか。
/// - `declaration_caps` — `--fs-allow`で開けた穴の**宣言capability SID**（[§22.3]）。
///   [`spawn_in_workspace`]は**1本も積まない**ので、あちら経由の子は宣言した穴へ届かない。
///   穴の到達性を測るテストは、`preflight`が返した`granted_passthrough[].subject_sid`を
///   ここへ渡す（**本番の`launch.rs`と同じ入手経路**。導出し直すとCoWの級降格で別のSIDになる）。
///
/// # **本番にこれらの引数は無い。使ってよいのは反実仮想の測定だけである**
///
/// 本番では「Redirector DLLを注入するか」と「どちらのモードのcapability SIDを積むか」が
/// 同じ1つの値（`cow_diff_layer_dir`が`Some`か）から決まるので、**片方だけを変えた配置は
/// 起こらない**。それでもこの入口が要るのは、D-01（「フックは境界にしない」）が主張する
/// 「**フックが無くてもACLだけで拒否される**」を測るには、**フックの有無だけを変えて
/// capabilityは本番のまま**にする必要があるからである。
///
/// **2つを同時に変えると測定が壊れる。** 実際に壊れていた——
/// `workspace_write_fails_closed_without_redirector_injection`は`cow: None`で子を起こしており、
/// それは「注入しない」と同時に「`rwx`のcapability SIDを積む」を意味していた。
/// D-84でworkspaceには`rwx`宛のACEも常に載っているので、**子は普通に書けて当然**であり、
/// テストは境界ではなく自分が壊した前提を測っていた（`cow-diagnostics` 17/19の片方）。
///
/// 本番で起こり得ない配置を作る入口なので、**新しい呼び出しを足す前に「本番の`launch.rs`が
/// この組み合わせを作るか」を確かめること**。作るなら[`spawn_in_workspace`]を使う。
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_in_workspace_as(
    exe: &str,
    args: &[&str],
    cwd: &std::path::Path,
    env: &[(String, String)],
    want_stdin: bool,
    container_sid: windows::Win32::Security::PSID,
    net: super::NetworkCapability,
    cow: Option<super::CowInject<'_>>,
    mode: WorkspaceMode,
    declaration_caps: &[windows::Win32::Security::PSID],
) -> Result<super::AppContainerChild, super::AppContainerError> {
    crate::tier2a::win_appcontainer::grant_job::wait_until_done()
        .map_err(super::AppContainerError::Preflight)?;
    let canonical = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
    // [D-84] **走っているモードのcapability SIDだけ**を積む（本番の`launch.rs`と同じ）。
    // `lookup_`（発行しない側）を通すのは、`preflight`を経ていないworkspaceで
    // 台帳エントリを作らないため——テストが`%APPDATA%`へ記録を積み増さない。
    let cap =
        crate::tier2a::workspace_capability::lookup_capability_name(&canonical, mode.as_str())
            .and_then(|_| super::workspace_capability_sid(&canonical, mode.as_str()).ok());
    // §22.1.1: workspace capabilityが引けたならそれがドメイン、引けなければプロファイル自身が
    // ドメイン（package SID宛ACEを自前で付けるテストがこちら）。**本番の`launch.rs`と同じ選び方**に
    // しておかないと、「本番と同じ形」を名乗るこのヘルパーだけ別の分離状態を測ることになる。
    let domain = match cap.as_ref() {
        Some(sid) => super::DomainIdentity::Capability(sid.as_psid()),
        None => super::DomainIdentity::OwnPackage,
    };
    // [§22.3.2] CoWのときは**差分層のcapability SIDも積む**（本番の`launch.rs`と同じ）。差分層のACEは
    // package SID宛から差分層ごとのcapability SID宛へ移ったので、これを積まない子は
    // Redirector DLLの退避先へ書けず、CoWのテストが「透過が壊れている」ように見える。
    // ここが本番と食い違うと、「本番と同じ形」を名乗るこのヘルパーだけ別の世界を測ることになる
    // （モジュールdocのD-84のときとまったく同じ理由）。
    let cow_cap = cow.as_ref().and_then(|inject| {
        let ws = inject
            .workspace_root
            .canonicalize()
            .unwrap_or_else(|_| inject.workspace_root.to_path_buf());
        super::lookup_cow_diff_layer_capability_sid(&ws, inject.diff_layer_dir)
    });
    // [§22.3] ここが渡すのはworkspace本体・CoWの差分層・**呼び出し側が明示した宣言capability**。
    // [`spawn_in_workspace`]は3つめを空で呼ぶので、**あちら経由の子は`--fs-allow`で開けた穴へ
    // 届かない**——1件ずつの到達性なら`probe_passthrough`（宛先SIDを直接渡せる）でも測れるが、
    // 子の中で複数の操作を回す測定はここへ宣言capabilityを渡すこと。
    // 渡さないまま穴の到達性を測ると、**全操作が失敗する**（実際にそうなっていた: BUG-153）。
    //
    // **[BUG-169] 4つめ（Redirector DLLの宛先）は`DomainCapabilities`が自分で引く。**
    // かつてここは3種類を自分で並べており、DLLの宛先がcapability SIDへ移った回
    // （2026-09-19）に製品側だけが4つめを足したため、**このヘルパー経由の子は
    // `LoadLibraryW`でNULLを受け取り、実機の封じ込めテスト18本が7日間赤のまま**だった。
    // 同じ形はD-84のときにも起きている（モジュールdoc）——だから並べ方を共有した。
    let owned: Vec<windows::Win32::Security::PSID> = cap
        .iter()
        .map(|s| s.as_psid())
        .chain(cow_cap.iter().map(|s| s.as_psid()))
        .chain(declaration_caps.iter().copied())
        .collect();
    let capabilities = super::DomainCapabilities::collect(owned);
    let domain_caps = capabilities.psids();

    super::spawn_with_workspace(
        exe,
        args,
        cwd,
        env,
        want_stdin,
        container_sid,
        net,
        cow,
        &domain_caps,
        domain,
    )
}

/// `path`のDACLに`PROTECTED_DACL_SECURITY_INFORMATION`を立て、祖先からの継承ACEが
/// このノード配下へ伝播するのを遮断する。**このとき`path`が現在実効的に持つ全ACE
/// （継承由来含む）をそのまま保持する**ため、Administrators/自分自身等の既存アクセスは
/// 失われない（0 ACEにはしない）。
///
/// 当初の実装は`GetExplicitEntriesFromAclW`で現在のACEを吸い出してから`SetEntriesInAclW`で
/// 組み直す方式だったが、`GetExplicitEntriesFromAclW`は**継承フラグ（`INHERITED_ACE`）が
/// 立ったACEを一切拾わない**（名前どおり「明示」ACEのみが対象）ため、対象ディレクトリの
/// ACEが全て継承由来（新規作成した子ディレクトリの典型）の場合は`count=0`になり、
/// `SetEntriesInAclW(&[], None, ...)`が`new_dacl=NULL`を返してしまう。`SetNamedSecurityInfoW`
/// に`pDacl=NULL`を渡すと「DACLそのものが無い＝誰でもフルコントロール」という最も危険な
/// 状態になり、`grant_ace_ro(root)`自体は成功するのに対象ディレクトリのアクセス制御が
/// 消え去るという事故を招いた（実機の`icacls`出力`"アクセスが設定されていません。すべての
/// ユーザーがフル コントロールを保持しています。"`で発覚）。
///
/// 修正: ACEを個別に吸い出して再構築する必要は無い。`GetNamedSecurityInfoW`が返す
/// `existing_dacl`は、継承由来かどうかを問わず**今この瞬間に有効な全ACEが物理的に
/// 格納された実体**（NTFSは継承ACEを都度計算せず子オブジェクトへ都度複製して保持する）
/// なので、そのポインタをそのまま`PROTECTED_DACL_SECURITY_INFORMATION`付きで書き戻すだけで
/// 「今の実効アクセスを凍結しつつ、以後の祖先からの継承だけを遮断する」が実現できる
/// （`.NET`の`SetAccessRuleProtection(true, true)`が内部で行うのと同じ操作）。
///
/// **`ace_grant_revoke_tests`と`dacl_protection_probe_tests`の2箇所から使う**ので、
/// `docs/CODE-STRUCTURE-RULES.md`規則5に従い元の定義（`ace_grant_revoke_tests.rs`）から
/// ここへ移した。前者は「保護DACL配下へ救済walkが届くか」の土台として、後者は
/// [BUG-083](../../../../docs/bugs/BUG-083.md)の候補Bの書込経路そのものとして使う。
pub(super) fn protect_dacl_preserve_inherited(path: &std::path::Path) -> windows::core::Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };
    unsafe {
        let path_w = crate::win_common::wide(&path.to_string_lossy());
        let mut existing_dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing_dacl),
            None,
            &mut sd,
        )
        .ok()?;

        let result = SetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(existing_dacl as *const _),
            None,
        )
        .ok();

        let _ = LocalFree(HLOCAL(sd.0));
        result
    }
}

/// パニック時にも確実にクロージャを実行する簡易scopeguard（`scopeguard`クレート依存を
/// 避けるための最小実装。テストコード専用）。
pub(super) struct ScopeGuard<F: FnMut()>(F);

impl<F: FnMut()> Drop for ScopeGuard<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}

pub(super) fn scopeguard<F: FnMut()>(f: F) -> ScopeGuard<F> {
    ScopeGuard(f)
}

/// `C:\harness-Tier2a-verify-<label>-<pid>`を作り、Dropで再帰削除するガード。
///
/// **削除は「必ず成功する」ものではない**——後始末の限界は
/// [`remove_test_dir_with_retry`]に書いてある。
///
/// **なぜ`tempfile::tempdir()`ではなく`C:\`直下なのか**: `%TEMP%`は実際には
/// `C:\Users\<user>\AppData\Local\Temp\…`という本物のユーザープロファイルの奥にあり、
/// `grant_traverse_chain`が`Path::ancestors()`で祖先を辿ると`C:\Users`・`C:\Users\<user>`まで
/// DACL変更が及ぶ（実行中プロファイルルートへの`SetNamedSecurityInfoW`が数分止まった
/// [BUG-011](../../../../docs/bugs/BUG-011.md)の直接の原因）。ドライブルート直下なら祖先は
/// `C:\`だけで済む。
pub(super) struct TestDirGuard {
    path: std::path::PathBuf,
}

impl TestDirGuard {
    /// 作成に失敗したらpanicする（テストの前提が崩れているので続行しても意味が無い）。
    pub(super) fn create(label: &str) -> Self {
        Self::create_in(std::path::Path::new("C:\\"), label)
    }

    /// [`Self::create`]の置き場を選べる版。**`create`はこれを`C:\`で呼ぶ薄い包みである**
    /// （同じ組み立てを2箇所に書かない、`docs/CODE-STRUCTURE-RULES.md`規則5）。
    ///
    /// # **`C:\`以外を渡してよいのは、祖先を触らない測定だけである**
    ///
    /// 上のdocのとおり、`%TEMP%`は本物のユーザープロファイルの奥にある。
    /// `grant_traverse_chain`のように`Path::ancestors()`で祖先まで辿る口を通す測定へ
    /// ここを渡すと、**実行中プロファイルルートのDACLを書きに行く**（BUG-011）。
    ///
    /// 渡してよいのは、対象とその配下しか触らない口だけである——
    /// `grant_aces_propagating`・`grant_aces_single_object`・`fix_descendants_missing_ace`・
    /// `revoke_workspace_sids_recursive`はいずれもそれに当たる。
    ///
    /// **置き場を軸にする測定のために足した入口である**（`acl_dacl_write`のモジュールdocが
    /// 「同じ書込列でもツリーの置き場所で伝播の挙動が反転した」実測を持っており、
    /// `C:\`直下だけで測ると実ワークスペース側の数字が取れない）。
    pub(super) fn create_in(base: &std::path::Path, label: &str) -> Self {
        let path = base.join(format!(
            "harness-Tier2a-verify-{label}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path)
            .unwrap_or_else(|e| panic!("create test dir {}: {e}", path.display()));
        Self { path }
    }

    pub(super) fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TestDirGuard {
    fn drop(&mut self) {
        remove_test_dir_with_retry(&self.path);
    }
}

/// テストディレクトリを消す。**消えるまで少し待ち、それでも消えなければ黙らない。**
///
/// **この関数の主目的は再試行ではなく、失敗を見えるようにすることである。** 旧実装は
/// `let _ = remove_dir_all(...)`で失敗を捨てており、`C:\`直下に空ディレクトリが積もっている
/// ことに誰も気付けなかった（[BUG-157](../../../../docs/bugs/BUG-157.md)。8件残っていた）。
///
/// **残った8件の引き金は未確定である。** 有力な候補は「`TerminateJobObject`は非同期なので、
/// Jobを明示終了しても配下のプロセスが消え切る前に`remove_dir_all`が走り、まだ
/// このツリーをカレントディレクトリにしている子が居て`os error 32`（使用中）になる」だが、
/// **修正後に緑で回した回では再試行が1度も発火していない**（発火すれば上の`eprintln!`が出る）。
/// つまりこの再試行は**引き金を再現できていない保険**であり、
/// 残骸が消えた理由をこの再試行に帰属させてはいけない。もう1つの候補は
/// 「テスト自身が失敗した回に、生きたままの子孫がツリーを掴んでいた」で、
/// 残っていた8件の作成時刻は製品修正前の測定（6緑2赤）の時間帯と一致する。
///
/// `Drop`から呼ばれるのでpanicしない——テスト本体が失敗して巻き戻している最中に
/// panicするとプロセスごとabortし、**本来の失敗理由が消える**。代わりにstderrへ残す
/// （昇格ランナーの`cancel-descendants`は`--nocapture`で回すので、そのまま目に入る）。
fn remove_test_dir_with_retry(path: &std::path::Path) {
    const DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);
    const POLL: std::time::Duration = std::time::Duration::from_millis(50);

    let started = std::time::Instant::now();
    let mut retries = 0usize;
    loop {
        let error = match std::fs::remove_dir_all(path) {
            Ok(()) => {
                // **再試行が効いたのか、そもそも1回で消えたのかを区別できるようにしておく。**
                // 区別が付かないと「残骸が出なくなった」理由をこの再試行だと言えない
                // （`measurement-review`の「計器を疑う」）。
                if retries > 0 {
                    eprintln!(
                        "cleanup: removed {} after {retries} retries ({:?})",
                        path.display(),
                        started.elapsed(),
                    );
                }
                return;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => e,
        };
        if started.elapsed() >= DEADLINE {
            eprintln!(
                "cleanup: FAILED to remove the test directory {} after {DEADLINE:?}: {error}. \
                 It is left on the real machine — remove it by hand and find out what still holds it.",
                path.display(),
            );
            return;
        }
        retries += 1;
        std::thread::sleep(POLL);
    }
}

/// `count`個のファイルを`root`直下の`fanout`個のサブディレクトリへ均等に撒く。
/// 実ノード数（ディレクトリ＋ファイル＋root）を返す。
///
/// **ACLのコスト測定が共有する土台である。** `d79_exec_split_tests`（D-79の2本割りのコスト、
/// `plans/mac-spike/RESULTS.md` §S9）と`acl_baseline_cost_tests`（現状の宛先SID 1本の基準線、§S10）が
/// 使う。**同じ形でなければ2つの測定の数字を並べられない**ので、ここに1つだけ置く
/// （`docs/CODE-STRUCTURE-RULES.md`規則5）。**片方のスパイクを消しても残る場所**に
/// 置いてあるのはそのためで、元は`d79_exec_split_tests`のprivate関数だった。
///
/// **形は「浅く広い」**——深さは2段（root → `dNNN/` → ファイル）で固定である。継承ACEの
/// 伝播コストが深さに依存するかは**この関数では測れない**。§S9も§S10もこの形の数字なので、
/// 深さの効果を知りたくなったら[`build_forest_tree`]（本関数を含む一般形）を使うこと。
///
/// **本体は[`build_forest_tree`]の`depth = 1`である。** 同じ組み立てを2つ持たない
/// （`docs/CODE-STRUCTURE-RULES.md`規則5）。等価であることは実際に両方を作って
/// 突き合わせてある（`acl_baseline_cost_tests::forest_tree_with_depth_one_is_the_wide_tree`）
/// ——ここが1バイトでもずれると、§S9・§S10・§S15の過去の数字と並べられなくなる。
pub(super) fn build_wide_tree(root: &std::path::Path, count: usize, fanout: usize) -> usize {
    build_forest_tree(root, count, fanout, 1)
}

/// `count`個のファイルを、`root`直下の`k`本の枝それぞれを`depth`段に重ねた**森**へ均等に撒く。
/// 実ノード数（ディレクトリ＋ファイル＋root）を返す。
///
/// **[`build_wide_tree`]と[`build_chain_tree`]の両方を含む一般形である。** 前者は`depth = 1`
/// （k本の枝が1段に並ぶ）、後者は`k = 1`（1本の枝がdepth段に重なる）に当たる。
/// **両方の軸を同時に動かしたい測定のために足した**——BUG-145の案A（配布をroot直下の子ごとに
/// 分割する）の費用は「直下の子の数」と「深さ」の両方に依存し得るのに、
/// 既存の2つはどちらか片方しか振れない。
///
/// 枝の1段目だけ`d{j:03}`で名前を分け、2段目以降は`d`で重ねる。ファイルは
/// **`k * depth`個のディレクトリ全部へ順に**撒くので、最深段にも必ずファイルが載る
/// （浅いところだけ届いて深いところが落ちる形を拾えるようにするため）。
///
/// # [`build_chain_tree`]は委譲していない（**意図的**）
///
/// あちらは全段の名前が1文字で、**深さとパス長の関係そのものが測定の前提**である
/// （深さ`N`でパス長が`2N`しか伸びない＝N=64まではMAX_PATHの内側、という腕の組み方）。
/// この関数へ委譲すると1段目が`d000`になってその関係が崩れるので、別のまま残す。
pub(super) fn build_forest_tree(
    root: &std::path::Path,
    count: usize,
    k: usize,
    depth: usize,
) -> usize {
    assert!(k >= 1, "a forest needs at least one branch");
    assert!(depth >= 1, "a branch needs at least one directory level");
    std::fs::create_dir_all(root).expect("create tree root");
    let mut dirs = Vec::with_capacity(k * depth);
    for j in 0..k {
        let mut cursor = root.join(format!("d{j:03}"));
        std::fs::create_dir_all(&cursor).expect("create forest branch");
        dirs.push(cursor.clone());
        for _ in 1..depth {
            cursor = cursor.join("d");
            std::fs::create_dir_all(&cursor).expect("create forest level");
            dirs.push(cursor.clone());
        }
    }
    for i in 0..count {
        let path = dirs[i % dirs.len()].join(format!("f{i:06}.txt"));
        std::fs::write(&path, b"x").expect("write tree file");
    }
    1 + k * depth + count
}

/// `count`個のファイルを、`root`から**一列にネストした**`depth`段のディレクトリへ均等に撒く。
/// 実ノード数（ディレクトリ＋ファイル＋root）を返す。
///
/// **[`build_wide_tree`]と対になる形である。** あちらは`fanout`個のディレクトリを**1段に並べ**、
/// こちらは同じ個数を**一列に重ねる**。`build_chain_tree(root, F, N)`と
/// `build_wide_tree(root, F, N)`は**ノード数・ディレクトリ数・ファイル数が完全に一致**し、
/// 違うのは深さだけになる——**そうしておかないと、伝播コストの差を「深さのせい」と言えない**
/// （ノード数が違えば、それだけで時間は動く）。
///
/// **段の名前を1文字固定にしてあるのは、深さと一緒にパス文字列長が動かないようにするため。**
/// 深さ`N`のパス長は`2N`文字ぶんしか伸びないので、`C:\harness-Tier2a-verify-*`を起点にすると
/// **N=64まではWindowsの伝統的なパス長上限（MAX_PATH=260）の内側**に収まる。
/// N=128はその外側へ出る——**そこでは深さとパス長という2つの変数が同時に動く**ので、
/// 差が出てもどちらのせいかは言えない（結果を書くときに限定詞を落とさないこと）。
///
/// ACL側は[`crate::win_common::long_path_wide`]が`\\?\`を付けるので上限の外でも書けるが、
/// **救済walkが使うディレクトリ走査（`collect_dirs_and_files`）と撤収が同じように通るかは
/// 別の事実**である。深い腕を測るときは、時間だけでなく「届いたか」「剥がせたか」も見ること。
pub(super) fn build_chain_tree(root: &std::path::Path, count: usize, depth: usize) -> usize {
    assert!(depth >= 1, "a chain needs at least one directory level");
    std::fs::create_dir_all(root).expect("create tree root");
    let mut levels = Vec::with_capacity(depth);
    let mut cursor = root.to_path_buf();
    for _ in 0..depth {
        cursor = cursor.join("d");
        std::fs::create_dir_all(&cursor).expect("create chain level");
        levels.push(cursor.clone());
    }
    for i in 0..count {
        let path = levels[i % depth].join(format!("f{i:06}.txt"));
        std::fs::write(&path, b"x").expect("write tree file");
    }
    1 + depth + count
}

/// `dacl`（自前バッファ上のコピー）の全ACEから継承由来のフラグ（`INHERITED_ACE`）を落とす。
///
/// 保護DACL（継承を受け付けない状態）に継承由来フラグの立ったACEが残るのは自己不整合であり、
/// `.NET`の`SetAccessRuleProtection(true, preserveInheritance: true)`やエクスプローラの
/// 「継承された権限をこのオブジェクトの明示的な権限に変換する」はこの変換を行う。
///
/// `docs/CODE-STRUCTURE-RULES.md`規則5により、**2箇所目の利用者が出たのでここへ移した**
/// （元は`dacl_protection_probe_tests`のprivate定義）。利用者は
/// [BUG-083](../../../../docs/bugs/BUG-083.md)のプローブ（保護がどの書込口で立つか）と、
/// [BUG-145](../../../../docs/bugs/BUG-145.md)のプローブ（保護が親の配布で落ちるのはなぜか）。
/// **同じ変換を2つの実装で持つと、片方だけ直ったときに2つのプローブの結果が比べられなくなる。**
///
/// # 安全性
///
/// `dacl`は呼び出し側が持つ有効なACLを指していること（自前バッファ上のコピーであること）。
pub(super) unsafe fn strip_inherited_ace_flags(
    dacl: *mut windows::Win32::Security::ACL,
) -> windows::core::Result<()> {
    use std::ffi::c_void;
    use windows::Win32::Security::{GetAce, ACE_HEADER, INHERITED_ACE};
    unsafe {
        let count = (*dacl).AceCount as u32;
        for index in 0..count {
            let mut ace_ptr: *mut c_void = std::ptr::null_mut();
            GetAce(dacl, index, &mut ace_ptr)?;
            let header = ace_ptr as *mut ACE_HEADER;
            (*header).AceFlags &= !(INHERITED_ACE.0 as u8);
        }
        Ok(())
    }
}

/// `path`のDACLのACEを1件ずつ「種別;フラグ;マスク;SID」の文字列にして返す。
///
/// **件数だけでなくtrusteeとマスクまで**比較できる形にしてある——件数が同じでも中身が
/// 入れ替わっていれば「元の許可を失っていない」とは言えないため。
///
/// `docs/CODE-STRUCTURE-RULES.md`規則5により、`dacl_protection_probe_tests`（保護DACLの
/// 耐久確認）と`acl_dacl_size_limit_tests`（DACLの上限で無言の切り捨てが起きるか）の
/// 2箇所から使うのでここ1箇所に置く。元は前者のprivate定義だった。
pub(super) fn describe_dacl_aces(path: &std::path::Path) -> windows::core::Result<Vec<String>> {
    use std::ffi::c_void;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        GetAce, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID,
    };
    unsafe {
        let path_w = crate::win_common::long_path_wide(path);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        )
        .ok()?;

        let mut out = Vec::new();
        if !dacl.is_null() {
            for index in 0..(*dacl).AceCount as u32 {
                let mut ace_ptr: *mut c_void = std::ptr::null_mut();
                if GetAce(dacl, index, &mut ace_ptr).is_err() || ace_ptr.is_null() {
                    continue;
                }
                let header = &*(ace_ptr as *const ACE_HEADER);
                let ace = &*(ace_ptr as *const ACCESS_ALLOWED_ACE);
                let ace_sid = PSID(&ace.SidStart as *const u32 as *mut c_void);
                let sid_string = crate::win_common::sid_to_string(ace_sid)
                    .unwrap_or_else(|_| "<unreadable>".to_string());
                out.push(format!(
                    "type={:#04x};flags={:#04x};mask={:#010x};{sid_string}",
                    header.AceType, header.AceFlags, ace.Mask
                ));
            }
        }
        let _ = LocalFree(HLOCAL(sd.0));
        Ok(out)
    }
}

/// `path`のDACLの**ヘッダの実測値**（[`dacl_size_info`]が返すもの）。
///
/// **ACEの一覧が同じでも、ここが違えば「同じ状態」ではない。** BUG-145の調査は
/// 「落ちるケースと無傷のケースでACE一覧が完全に同一」までしか見ておらず、
/// **ACLの確保容量とリビジョンを一度も読んでいなかった**。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DaclSizeInfo {
    /// 実際に使っているバイト数。
    pub(super) bytes_in_use: u32,
    /// 確保済みだが空いているバイト数。**書込側が確保した容量がそのまま保存されるか**を見る値。
    pub(super) bytes_free: u32,
    pub(super) ace_count: u32,
    /// ACLのリビジョン（`ACL_REVISION`＝2、`ACL_REVISION_DS`＝4）。
    pub(super) revision: u8,
}

/// `path`のDACLのヘッダを読む（使用バイト数・空きバイト数・ACE本数・リビジョン）。
///
/// ACLのサイズ欄は16ビットなので構造上65,535バイトが上限になる——**が、それは「どこで
/// 何が起きるか」を言っていない**。実際に何本入るか、上限に当たったときエラーになるのか
/// 黙って切り捨てられるのかは測らないと分からないので、その測定のためにここに置く。
/// **既存にACLの実バイト数を返す部品は無い**（`revoke.rs`の`copy_dacl_excluding_sids`は
/// 内部でバッファ容量を決めるために読んでいるだけで、値を外へ出さない）。
///
/// **空きバイト数とリビジョンは[BUG-145](../../../../docs/bugs/BUG-145.md)の調査で足した。**
/// 剥がす側は元のACLと同じ容量で確保するので**空きが残り**、組み直す口は詰めて確保する
/// ——その差が保存後にも現れるのかを見るには、使用バイト数だけでは足りない。
pub(super) fn dacl_size_info(path: &std::path::Path) -> windows::core::Result<DaclSizeInfo> {
    use std::ffi::c_void;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        AclSizeInformation, GetAclInformation, ACL, ACL_SIZE_INFORMATION,
        DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };
    unsafe {
        let path_w = crate::win_common::long_path_wide(path);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        )
        .ok()?;

        let result = if dacl.is_null() {
            Ok(DaclSizeInfo {
                bytes_in_use: 0,
                bytes_free: 0,
                ace_count: 0,
                revision: 0,
            })
        } else {
            let mut size_info = ACL_SIZE_INFORMATION::default();
            GetAclInformation(
                dacl as *const ACL,
                &mut size_info as *mut _ as *mut c_void,
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
            .map(|()| DaclSizeInfo {
                bytes_in_use: size_info.AclBytesInUse,
                bytes_free: size_info.AclBytesFree,
                ace_count: size_info.AceCount,
                revision: (*dacl).AclRevision,
            })
        };
        let _ = LocalFree(HLOCAL(sd.0));
        result
    }
}

/// `subst`で作る**テストが所有する仮想ドライブ**。Dropで`subst /D`と実体の削除まで行う。
///
/// traverse機構の検証に要るのは「まだ誰もACEを付けていないドライブルート」である。`C:\`実体で
/// 剥奪→再付与を試すと、その間にテストが落ちたときマシン全体のTier2a FS I/Oが壊れる
/// （[BUG-046](../../../../docs/bugs/BUG-046.md)そのもの、[BUG-012](../../../../docs/bugs/BUG-012.md)と同型）。
/// `subst`のルートは実体がテスト所有のディレクトリなので、**所有者権限だけで`WRITE_DAC`が
/// 通り管理者権限が要らない**という利点もある。
pub(super) struct SubstDrive {
    letter: char,
    backing: std::path::PathBuf,
}

impl SubstDrive {
    /// 空きドライブレターを`Z`から降順に探して割り当てる。空きが無ければ`None`
    /// （呼び出し側はskipする）。
    pub(super) fn create() -> Option<Self> {
        let backing =
            std::env::temp_dir().join(format!("harness-subst-root-{}", std::process::id()));
        std::fs::create_dir_all(&backing).ok()?;

        for letter in ('D'..='Z').rev() {
            if std::path::Path::new(&format!("{letter}:\\")).exists() {
                continue;
            }
            let status = std::process::Command::new("subst")
                .arg(format!("{letter}:"))
                .arg(&backing)
                .status();
            if matches!(status, Ok(s) if s.success()) {
                return Some(Self { letter, backing });
            }
        }
        let _ = std::fs::remove_dir_all(&backing);
        None
    }

    /// 仮想ドライブのルート（`X:\`）。`Path::ancestors()`の終端になる。
    pub(super) fn root(&self) -> std::path::PathBuf {
        std::path::PathBuf::from(format!("{}:\\", self.letter))
    }
}

impl Drop for SubstDrive {
    fn drop(&mut self) {
        let _ = std::process::Command::new("subst")
            .arg(format!("{}:", self.letter))
            .arg("/D")
            .status();
        let _ = std::fs::remove_dir_all(&self.backing);
    }
}

/// このworkspaceへ配る**全モードぶん**のACE（D-84。本番の`preflight`と同じ集合）。
///
/// `docs/CODE-STRUCTURE-RULES.md`規則5によりここ1箇所に置く。元は
/// `lazy_fault_in_acceptance_tests`と`lazy_descendant_reach_tests`に**同じものが2つ**あり、
/// 3つ目（UX測定）を作る前にここへ畳んだ。
pub(super) fn workspace_grants(canonical_ws: &std::path::Path) -> Vec<super::OwnedAceGrant> {
    WorkspaceMode::ALL
        .iter()
        .map(|mode| super::OwnedAceGrant {
            sid: super::workspace_capability_sid(canonical_ws, mode.as_str())
                .expect("the workspace capability must exist after preflight (D-54)"),
            mask: super::workspace_mode_mask(*mode),
        })
        .collect()
}

/// テストバイナリの隣（`target/debug/deps/`）から2つ上がった`target/debug/harness.exe`。
///
/// **「もう1つのharness」を起こす測定が共有する**（`docs/CODE-STRUCTURE-RULES.md`規則5）。
/// 元は`tier2a::deelevation_spike_tests`のprivate定義で、そちらは判定が出たら消える
/// スパイクなので、**消えても残る場所**へ移した。
///
/// 存在確認はしない——呼び出し側が「無ければビルド手順を添えて落とす」を自分の文面で
/// 書けるようにするためである（`mac_spike_tests::probe_exe`は逆に確認まで持っている）。
pub(crate) fn harness_exe() -> std::path::PathBuf {
    let mut p = std::env::current_exe().expect("current_exe");
    p.pop(); // deps/
    p.pop(); // debug/
    p.push("harness.exe");
    p
}

/// ツリーの全ノードについて「これらの宛先SIDへ届いているか」を集めた一覧を返す。
/// **rootからの相対パス（小文字）**で持つので、別々のディレクトリの結果でも比較できる。
///
/// **「届いているか」なので継承ACEを数える**（`sid_effective_ace_masks`）。明示ACEだけを
/// 見る口（`sid_ace_mask`）と取り違えると、継承で届いているノードを「届いていない」と読む
/// （[BUG-081](../../../../docs/bugs/BUG-081.md)がその形）。
///
/// 元は`grant_job_lane_tests`のprivate定義。3つ目の利用者（受入4「競合」の取りこぼし検算）が
/// 要るので写さずここへ移した（規則5）。
pub(super) fn reachability(
    root: &std::path::Path,
    grants: &[super::OwnedAceGrant],
) -> Vec<(String, bool)> {
    let sids: Vec<_> = grants.iter().map(|g| g.sid.as_psid()).collect();
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    super::acl_grant::collect_dirs_and_files(root, &mut dirs, &mut files, super::OnVanished::Abort)
        .expect("enumerate the tree");
    let mut out: Vec<(String, bool)> = dirs
        .into_iter()
        .chain(files)
        .map(|node| {
            let rel = node
                .strip_prefix(root)
                .map(|p| p.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            let reached = super::revoke::sid_effective_ace_masks(&node, &sids)
                .map(|masks| masks.iter().all(Option::is_some))
                .unwrap_or(false);
            (rel, reached)
        })
        .collect();
    out.sort();
    out
}

/// `path`を**どのcapability SIDからも届かない状態**にする。
///
/// 走査器がまだそのノードへ到達していない状態を、**決定的に**作るための細工である
/// （本物の「まだ到達していない」はツリーの列挙順に依存し、テストで固定できない）。
///
/// 継承ACEはそのままでは剥がせないので、**先にDACLを保護して継承を切り**（そのとき現在の
/// 実効ACEは明示ACEとして凍結される）、そのうえで対象SIDのACEを落とす。
///
/// 元はD-88の実機テスト3本に**同じものが3つ**あった（規則5でここへ畳んだ）。
pub(super) fn make_unreachable(path: &std::path::Path, grants: &[super::OwnedAceGrant]) {
    use windows::Win32::Security::PSID;
    protect_dacl_preserve_inherited(path).expect("protect the node's dacl");
    let sids: Vec<PSID> = grants.iter().map(|g| g.sid.as_psid()).collect();
    super::revoke::revoke_sids_from_node(path, &sids)
        .expect("strip the capability aces from the node");
    assert!(
        super::revoke::sid_effective_ace_masks(path, &sids)
            .expect("read back the dacl")
            .iter()
            .all(Option::is_none),
        "the setup must actually make {} unreachable, otherwise the measurement means nothing",
        path.display()
    );
}

/// 実マシンに残るものを戻す。**ACEを剥がしてから台帳を落とす**——逆にすると宛先SIDを引けなくなり、
/// 撤収経路の無いACEが残る（`workspace_capability::forget_capability`のdocが定める不変条件）。
///
/// # 台帳は2つある（`B-01`）
///
/// capability台帳（`forget_capability`）だけ落として**workspace台帳を残すと**、実体の無い
/// エントリが`harness fs list`に積み上がる——実際に26件積んだ。付けた先の数だけ剥がす。
///
/// ツリー本体は呼び出し側（`TestDirGuard`など）が消す。ここが消すのは
/// **ACEと台帳エントリだけ**である。
pub(super) fn cleanup_workspace(canonical_ws: &std::path::Path) {
    let sids: Vec<crate::win_common::OwnedSid> = WorkspaceMode::ALL
        .iter()
        .filter_map(|mode| super::workspace_capability_sid(canonical_ws, mode.as_str()).ok())
        .collect();
    if canonical_ws.exists() {
        let psids: Vec<windows::Win32::Security::PSID> = sids.iter().map(|s| s.as_psid()).collect();
        match super::revoke::revoke_workspace_sids_recursive(canonical_ws, &psids, &|_, _| {}) {
            Ok(report) => eprintln!("cleanup: workspace aces revoked: {report:?}"),
            Err(e) => eprintln!("cleanup: workspace revoke failed: {e}"),
        }
    }
    let forgotten = crate::tier2a::workspace_capability::forget_capability(canonical_ws, "");
    crate::tier2a::workspace_ledger::remove_workspace_entry(canonical_ws);
    eprintln!("cleanup: ledger entries dropped: {forgotten:?}");
}

/// 昇順に並べたときの`percentile`番目の値（0〜100）。**標本数が少ないとp95は最悪値そのもの**
/// になる（n=20なら20回中の最悪値）——結果を書くときはその解釈を添えること。
///
/// 元は`acl_payment_model_tests`のprivate定義。UX測定（`lazy_ux_latency_tests`）が
/// 同じものを要るので、写さずここへ移した（規則5）。
pub(super) fn percentile(mut values: Vec<u128>, percentile: usize) -> u128 {
    values.sort_unstable();
    let index = ((values.len() - 1) * percentile).div_ceil(100);
    values[index]
}

/// xorshiftで`items`をその場でシャッフルする（**腕の実行順をランダムにする**ため）。
///
/// 順序を固定すると、キャッシュの温まりやディスクの状態といった**時間とともに動くもの**が
/// 特定の腕へ偏って乗る。乱数源を`state`として外へ出してあるので、呼び出し側は種を
/// 結果へ記録でき、同じ順序を再現できる。
pub(super) fn shuffle_in_place<T>(items: &mut [T], state: &mut u64) {
    for i in (1..items.len()).rev() {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        items.swap(i, (*state as usize) % (i + 1));
    }
}

/// `crates/`配下の`.rs`を舐めて、ある綴りを**製品コードから**呼んでいる行を集める。
///
/// # 何のために在るのか
///
/// 「この経路は製品からは呼ばれていない」を印として固定するためである。印が無いと、
/// 次に足された呼び出しが黙って旧い経路へ落ち、**しかも動いてしまうので誰も気付かない**
/// （移行の中間状態で1経路だけ取り残される形。実際に段階5bのMCP経路がその状態だった）。
///
/// 戻り値は`(製品側の "path:line" 一覧, テスト側の件数)`。**テスト側も返す**のは、
/// 0件マッチで黙って緑になるのを防ぐため——「呼び出し元が無い」と
/// 「綴りを間違えて1行も見ていない」は外形上そっくりである（BUG-056と同型）。
///
/// # この数え方が持つ限界（**限界のほうが本体である**）
///
/// - **綴りに依存する。** 別名で束ねてから呼ばれると出ない。緑は
///   「呼び出し元が無い」ではなく「**この綴りの**呼び出し元が無い」しか意味しない。
/// - **テストかどうかをファイル名と`#[cfg(test)]`の位置で判定する。** 判定は
///   (1) ファイル名が`_tests.rs`で終わる (2) `tests`ディレクトリの下
///   (3) **そのファイルで最初に`#[cfg(test)]`が現れた行より後**、の3つ。
///   (3)は`wfp.rs`のように製品ファイルの末尾へテストを畳んでいる形のためで、
///   **逆に、インラインのテストモジュールより後ろへ製品コードを書くと見落とす。**
/// - **(2)が見るのは`tests`という名前のディレクトリだけである。** `spawnd_e2e_tests/`の
///   ように`_tests`で終わるディレクトリの下は見ない——そこへ置いたテストファイルは、
///   **ファイル名が`_tests.rs`で終わっていないと製品コードとして数えられる**。
///   2026-09-11に段階⑤のテストを`spawnd_e2e_tests/child_process_restricted.rs`として
///   足したとき実際に踏み、ファイル名の側を規約へ合わせて直した
///   （判定を広げなかったのは、`_tests.rs`という命名規約自体がこの機構だからである）。
/// - コメント行と、定義そのものの行は除く。
pub(super) fn product_callers_of(needle: &str, definition: &str) -> (Vec<String>, usize) {
    let crates_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate dir has a parent")
        .to_path_buf();
    let mut product = Vec::new();
    let mut tests = 0usize;
    walk_for_callers(&crates_dir, needle, definition, &mut product, &mut tests);
    (product, tests)
}

fn walk_for_callers(
    dir: &std::path::Path,
    needle: &str,
    definition: &str,
    product: &mut Vec<String>,
    tests: &mut usize,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            walk_for_callers(&path, needle, definition, product, tests);
            continue;
        }
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let test_file =
            name.ends_with("_tests.rs") || path.components().any(|c| c.as_os_str() == "tests");
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        // このファイルでインラインのテストが始まる行（限界の(3)）。
        let inline_tests_start = text
            .lines()
            .position(|line| line.trim_start().starts_with("#[cfg(test)"))
            .or_else(|| {
                text.lines().position(|line| {
                    line.trim_start().starts_with("#[cfg(all(") && line.contains("test")
                })
            })
            .unwrap_or(usize::MAX);
        for (index, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            if !line.contains(needle) || line.contains(definition) {
                continue;
            }
            if test_file || index > inline_tests_start {
                *tests += 1;
            } else {
                product.push(format!("{}:{}", path.display(), index + 1));
            }
        }
    }
}
