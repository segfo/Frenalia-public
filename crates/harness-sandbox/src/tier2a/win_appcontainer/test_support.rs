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
/// D-84で崩れた**。両モードのバッジを常に配るようになったため、台帳には必ず2件載る。
/// 探索順で先に来る`rwx`が常に選ばれ、**CoWのテストの子が`rwx`のバッジを積んで起動する**
/// ——workspace本体へ直接書けてしまい、封じ込めを測っているはずのテストが
/// 「封じ込めが無い世界」を測ることになる。
///
/// そこで本番の`launch.rs`とまったく同じ決め方にする: **`cow`が`Some`なら`ro`、
/// そうでなければ`rwx`**。「本番と同じ形」を名乗るヘルパーが本番と違う主体を積んでいたら、
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
    crate::tier2a::win_appcontainer::grant_job::wait_until_done()
        .map_err(super::AppContainerError::Preflight)?;
    let canonical = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
    // [D-84] **走っているモードのバッジだけ**を積む（本番の`launch.rs`と同じ）。
    // `lookup_`（発行しない側）を通すのは、`preflight`を経ていないworkspaceで
    // 台帳エントリを作らないため——テストが`%APPDATA%`へ記録を積み増さない。
    let mode = if cow.is_some() {
        WorkspaceMode::Ro
    } else {
        WorkspaceMode::Rwx
    };
    let cap = crate::tier2a::workspace_capability::lookup_capability_name(&canonical, mode.as_str())
        .and_then(|_| super::workspace_capability_sid(&canonical, mode.as_str()).ok());
    // §22.1.1: workspace capabilityが引けたならそれがドメイン、引けなければプロファイル自身が
    // ドメイン（package SID宛ACEを自前で付けるテストがこちら）。**本番の`launch.rs`と同じ選び方**に
    // しておかないと、「本番と同じ形」を名乗るこのヘルパーだけ別の分離状態を測ることになる。
    let domain = match cap.as_ref() {
        Some(sid) => super::DomainIdentity::Capability(sid.as_psid()),
        None => super::DomainIdentity::OwnPackage,
    };
    super::spawn_with_workspace(
        exe,
        args,
        cwd,
        env,
        want_stdin,
        container_sid,
        net,
        cow,
        // [§22.3] このヘルパーはworkspace本体だけを見て起こす。`--fs-allow`の宣言capabilityを
        // 積まないので、**このヘルパー経由の子は宣言した穴へ届かない**——穴の到達性を測る
        // テストは`probe_passthrough`（主体を明示的に渡せる）を使うこと。
        cap.as_ref()
            .map(|s| vec![s.as_psid()])
            .unwrap_or_default()
            .as_slice(),
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

/// `C:\harness-Tier2a-verify-<label>-<pid>`を作り、Dropで必ず再帰削除するガード。
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
        let path = std::path::PathBuf::from(format!(
            "C:\\harness-Tier2a-verify-{label}-{}",
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
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// `count`個のファイルを`root`直下の`fanout`個のサブディレクトリへ均等に撒く。
/// 実ノード数（ディレクトリ＋ファイル＋root）を返す。
///
/// **ACLのコスト測定が共有する土台である。** `d79_exec_split_tests`（D-79の2本割りのコスト、
/// `plans/mac-spike/RESULTS.md` §S9）と`acl_baseline_cost_tests`（現状1主体の基準線、§S10）が
/// 使う。**同じ形でなければ2つの測定の数字を並べられない**ので、ここに1つだけ置く
/// （`docs/CODE-STRUCTURE-RULES.md`規則5）。**片方のスパイクを消しても残る場所**に
/// 置いてあるのはそのためで、元は`d79_exec_split_tests`のprivate関数だった。
///
/// **形は「浅く広い」**——深さは2段（root → `dNNN/` → ファイル）で固定である。継承ACEの
/// 伝播コストが深さに依存するかは**この関数では測れない**。§S9も§S10もこの形の数字なので、
/// 深さの効果を知りたくなったら別の形を足すこと（**外挿しない**）。
pub(super) fn build_wide_tree(root: &std::path::Path, count: usize, fanout: usize) -> usize {
    std::fs::create_dir_all(root).expect("create tree root");
    for d in 0..fanout {
        std::fs::create_dir_all(root.join(format!("d{d:03}"))).expect("create tree subdir");
    }
    for i in 0..count {
        let path = root
            .join(format!("d{:03}", i % fanout))
            .join(format!("f{i:06}.txt"));
        std::fs::write(&path, b"x").expect("write tree file");
    }
    1 + fanout + count
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

/// `path`のDACLが**実際に使っているバイト数**とACE本数を返す。
///
/// ACLのサイズ欄は16ビットなので構造上65,535バイトが上限になる——**が、それは「どこで
/// 何が起きるか」を言っていない**。実際に何本入るか、上限に当たったときエラーになるのか
/// 黙って切り捨てられるのかは測らないと分からないので、その測定のためにここに置く。
/// **既存にACLの実バイト数を返す部品は無い**（`revoke.rs`の`copy_dacl_excluding_sids`は
/// 内部でバッファ容量を決めるために読んでいるだけで、値を外へ出さない）。
pub(super) fn dacl_size_info(path: &std::path::Path) -> windows::core::Result<(u32, u32)> {
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
            Ok((0, 0))
        } else {
            let mut size_info = ACL_SIZE_INFORMATION::default();
            GetAclInformation(
                dacl as *const ACL,
                &mut size_info as *mut _ as *mut c_void,
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
            .map(|()| (size_info.AclBytesInUse, size_info.AceCount))
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
