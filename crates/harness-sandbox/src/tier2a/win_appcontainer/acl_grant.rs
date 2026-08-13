//! AppContainer SIDへのACE付与と、その土台になるDACL低レベル操作。
//!
//! 「境界はACL」（D-01）の実装本体のうち**許可を付ける側**。撤収側は`revoke`、
//! 祖先チェーンへのtraverse付与は`traverse`が持つ。

use super::*;

/// walk中に対象ノードが消えていた（TOCTOU）ときの扱い。[`collect_dirs_and_files`]の呼び出し
/// 側が**必ず選ぶ**——既定を置かないのは、この選択が経路ごとに正反対だからである。
///
/// [BUG-084](../../../../docs/bugs/BUG-084.md): 元は[`Self::Abort`]相当の挙動しか無く、
/// `.harness/`の制御面保護（[`super::protect_harness_control_dir_from_appcontainer`]）が
/// **ツリーの深い位置でファイルが1つ消えただけで1ノードも保護せずに`Ok`を返して**いた。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnVanished {
    /// walk全体を`Err`で中断する。**列挙が完全であること自体を根拠に使う**経路向け
    /// （撤収完全性の検証`assert_no_sid_ace_recursive`のように、「見えた範囲にACEが無い」を
    /// 「ACEが無い」と読み替える経路では、黙って範囲が縮むと結論が嘘になる）。
    Abort,
    /// 消えたノードだけを飛ばして続行する。**残っているノードへ副作用を適用することが目的**の
    /// 経路向け（消えたノードにACEを付ける/剥がす必要は無く、そこで打ち切ると**残り全部**が
    /// 未処理のまま「成功」になる）。
    Skip,
}

impl OnVanished {
    /// このエラーを「ノードが消えていた」として飛ばしてよいか。
    fn tolerates(self, e: &std::io::Error) -> bool {
        self == Self::Skip && e.kind() == std::io::ErrorKind::NotFound
    }
}

/// `path`が指すディレクトリ配下を、シンボリックリンク/リパースポイントを辿らずに再帰列挙する。
/// 悪意あるsymlinkを辿ってworkspace外へpackage SIDの書込許可を誤って付与するスコープ逸脱を
/// 防ぐため、`WorkspaceJail::walk_dir`の`is_symlink()`スキップと同じガードを独立に実装する
/// （cap-stdの型保証が及ばない素の`std::fs`再帰のため、明示チェックが必須）。
///
/// **既知の診断精度の限界（安全性には影響しない）**: この関数が返す`io::Result`はどのノードで
/// 失敗したかを含まない（`?`で素通しするだけ）。呼び出し側（`grant_ace_recursive`・
/// `grant_ace_recursive_ro`・`grant_ace_inheritable_ro`）はこのエラーを`root`のパスに紐付けて
/// `AppContainerError::AclGrant`へ包むため、`preflight`の`.exists()`チェック後から実際の
/// walk開始までの間に対象配下のサブディレクトリが削除される（TOCTOU、Time-Of-Check to
/// Time-Of-Use、確認と使用の間に対象が変化する競合）ようなごく稀なケースでは、ユーザーに
/// 表示されるエラーメッセージが「どのノードで`read_dir`が失敗したか」ではなく`root`止まりに
/// なる。スコープが意図せず広がる・誤ったパスへ書き込む等の安全性の問題は無く、純粋に
/// エラーメッセージの特定精度の話に留まる。直す場合は本関数の戻り値を
/// `Result<(), (std::path::PathBuf, std::io::Error)>`のように失敗ノードを含む形へ変更する。
///
/// **そのTOCTOUを`Err`にするか飛ばすかは`on_vanished`で呼び出し側が選ぶ**（[`OnVanished`]、
/// BUG-084）。飛ばす側を選んだ経路は、列挙が縮み得ることを前提に**処理できた件数を戻り値へ
/// 載せる**こと——「打ち切ったのか全部やったのか」を呼び出し側が区別できなくなるため。
pub(crate) fn collect_dirs_and_files(
    root: &Path,
    dirs: &mut Vec<std::path::PathBuf>,
    files: &mut Vec<std::path::PathBuf>,
    on_vanished: OnVanished,
) -> std::io::Result<()> {
    dirs.push(root.to_path_buf());
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        // 消えたディレクトリは「配下に対象が1件も無い」のと同じ。自分自身を`dirs`から
        // 取り消して（`push`の直後なので`pop`で正確に戻る）、walk全体は続ける。
        Err(e) if on_vanished.tolerates(&e) => {
            dirs.pop();
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) if on_vanished.tolerates(&e) => continue,
            Err(e) => return Err(e),
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(e) if on_vanished.tolerates(&e) => continue,
            Err(e) => return Err(e),
        };
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if file_type.is_dir() {
            collect_dirs_and_files(&path, dirs, files, on_vanished)?;
        } else if file_type.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

/// `path`のDACLへ、既存ACEを保持したまま`sid`へ`access`の許可ACEを`inheritance`付きで
/// マージする。`SetEntriesInAclW`は同一trusteeの既存ACEを置換する仕様のため冪等
/// （再実行しても重複ACEが増えない、`win_restricted::set_low_integrity_label`の冪等性と
/// 同じ性質をDACL版でも担保する）。
/// `new_dacl`を`path`（ファイル/ディレクトリいずれも可）へ、**そのオブジェクト単体にのみ**設定する。
/// `SetNamedSecurityInfoW`（aclapi）は、コンテナのDACLを設定すると子孫全体へauto-inherit再伝播を
/// 走らせる（procmon実測で`SetSecurityFile`が子孫の数だけ発生、実行中プロファイルルート近傍では
/// 365,903件・93秒経っても未完 = 事実上ハング。`plans/TIER1A-PRIVHELPER-HANG.md`参照）。
/// `CreateFileW`でハンドルを取り`SetKernelObjectSecurity`（`NtSetSecurityObject`の薄いラッパ）を
/// 使うと、aclapiのツリー走査・パッケージSID解決RPCを一切経由せず、このオブジェクトのDACLだけを
/// 直接差し替えられる。`grant_ace_recursive_ro`等の**意図的にツリー全体へ伝播/全走査したい既存
/// 経路はこの関数を使わない**（そちらは`SetNamedSecurityInfoW`のままでよい、伝播が目的のため）。
/// `HARNESS_PREFLIGHT_TIMING=1`のとき、起動時のACL作業の各段の所要時間をstderrへ出す
/// （既定では何も出さない）。
///
/// preflightは「なぜか起動が遅い」の犯人になりやすい。実測で60秒かかっていた
/// [BUG-081](../../../../docs/bugs/BUG-081.md)では、段ごとの内訳が出せないために
/// 「どこが遅いか」の推測を何度も外した。次に遅くなったときに同じことを繰り返さないよう、
/// 計測フック自体を残す。
pub(crate) struct PhaseTiming {
    enabled: bool,
    started: std::time::Instant,
    last: std::time::Instant,
}

impl PhaseTiming {
    pub(crate) fn start() -> Self {
        let now = std::time::Instant::now();
        Self {
            enabled: std::env::var_os("HARNESS_PREFLIGHT_TIMING")
                .is_some_and(|v| !v.is_empty() && v != "0"),
            started: now,
            last: now,
        }
    }

    pub(crate) fn mark(&mut self, label: &str) {
        if !self.enabled {
            return;
        }
        let now = std::time::Instant::now();
        eprintln!(
            "preflight timing: {label} +{:.2}s (total {:.2}s)",
            now.duration_since(self.last).as_secs_f32(),
            now.duration_since(self.started).as_secs_f32()
        );
        self.last = now;
    }

    /// 件数だけでは追えない事象（「どのノードが継承から漏れたのか」等）のサンプルを出す。
    /// 時計は進めない——観測の出力であって段の区切りではないため。
    pub(crate) fn mark_lines(&self, label: &str, lines: &[String]) {
        if !self.enabled {
            return;
        }
        eprintln!("preflight timing: {label} (showing {}):", lines.len());
        for line in lines {
            eprintln!("preflight timing:     {line}");
        }
    }
}

/// DACLをどう書くか。**この選択がツリー全体の挙動を決める**ので、呼び出し側に明示させる
/// （[BUG-081](../../../../docs/bugs/BUG-081.md): 既定が`SingleObject`だと知らないまま
/// `grant_ace_inheritable_*`が伝播を失い、フォールバックが全ノードで発火していた）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DaclWrite {
    /// このオブジェクトのDACLだけを差し替える（[`set_dacl_single_object`]）。
    /// 子孫は一切触らない＝**継承ACEを足しても既存の子孫へは届かない**。
    SingleObject,
    /// 子孫へのauto-inherit再伝播を伴う（[`set_dacl_propagating`]）。
    /// 継承ありACEを既存ツリー全体へ行き渡らせたいときだけ使う。
    Propagate,
}

/// 冪等スキップ（「既にsid宛の明示ACEが要求マスクの上位集合を持っていれば書込を省く」）を
/// 行うかどうか。[BUG-082](../../../../docs/bugs/BUG-082.md) Part Bで新設——既定
/// （`SkipIfSufficient`）は変えないが、rootへ**伝播だけを目的に**無条件で書きたい呼び出し
/// （[`propagate_workspace_root_grant`]）が現れたため、`DaclWrite`を導入したときと同じ作法
/// （呼び出し側に明示させる）で分離する。
///
/// **`Always`が要る理由**: `preflight`の同期区間で先に`DaclWrite::SingleObject`のrootのみ
/// 書込（B1の高速パス）を行うと、rootは以後「充足済み」に見える。その後background jobが
/// 同じ内容を`DaclWrite::Propagate`で書こうとしても、既定の冪等スキップに引っかかって
/// **伝播そのものが黙って起きない**——BUG-081層1（伝播を使う高速経路が、伝播しない書込APIへ
/// 差し替えられていたのに機能は壊れず気付かれなかった）と同型の罠。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdempotentCheck {
    /// 既存ACEが要求マスクを満たしていれば書込を省く（既定の挙動、全既存呼び出しはこちら）。
    SkipIfSufficient,
    /// 既存の状態を見ずに常に書き込む。rootへの伝播を無条件に発生させたいときだけ使う。
    Always,
}

/// `new_dacl`を`path`へ設定し、**OSに子孫への再伝播をさせる**（`SetNamedSecurityInfoW`）。
///
/// `set_dacl_single_object`とは正反対の性質を持つ。伝播は子孫の数に比例したコストを持ち、
/// プロファイルルート近傍では事実上ハングする（BUG-011/013、`plans/TIER1A-PRIVHELPER-HANG.md`）
/// ため、**ツリー全体へ継承ACEを行き渡らせたい`grant_ace_inheritable_*`のroot付与だけ**が使う。
/// traverse chain（祖先への非継承ACE付与）は伝播の必要が無く、かつ対象がプロファイルルート
/// 近傍になりうるので、必ず`SingleObject`のままにすること。
unsafe fn set_dacl_propagating(path: &Path, new_dacl: *mut ACL) -> windows::core::Result<()> {
    let path_w = long_path_wide(path);
    SetNamedSecurityInfoW(
        PCWSTR(path_w.as_ptr()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        None,
        None,
        Some(new_dacl as *const _),
        None,
    )
    .ok()
}

unsafe fn set_dacl_single_object(path: &Path, new_dacl: *mut ACL) -> windows::core::Result<()> {
    let path_w = long_path_wide(path);
    let handle = CreateFileW(
        PCWSTR(path_w.as_ptr()),
        (WRITE_DAC | READ_CONTROL).0,
        FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )?;

    let mut sd = SECURITY_DESCRIPTOR::default();
    let sd_ptr = PSECURITY_DESCRIPTOR(&mut sd as *mut _ as *mut _);
    let result = (|| -> windows::core::Result<()> {
        InitializeSecurityDescriptor(sd_ptr, SECURITY_DESCRIPTOR_REVISION)?;
        SetSecurityDescriptorDacl(sd_ptr, true, Some(new_dacl as *const _), false)?;
        SetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION, sd_ptr)
    })();

    let _ = CloseHandle(handle);
    result
}

/// 指定トークンの1特権を有効/無効化する（`AdjustTokenPrivileges`）。`AdjustTokenPrivileges`は
/// 特権がトークンに割り当てられていなくても関数自体は成功（`S_OK`）を返し、
/// `GetLastError`で`ERROR_NOT_ALL_ASSIGNED`を返す仕様のため、有効化時はそれを失敗として扱う。
unsafe fn set_privilege(token: HANDLE, name: PCWSTR, enable: bool) -> windows::core::Result<()> {
    let mut luid = LUID::default();
    LookupPrivilegeValueW(PCWSTR::null(), name, &mut luid)?;
    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: if enable {
                SE_PRIVILEGE_ENABLED
            } else {
                TOKEN_PRIVILEGES_ATTRIBUTES(0)
            },
        }],
    };
    AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None)?;
    if enable && GetLastError() == ERROR_NOT_ALL_ASSIGNED {
        // トークンが`SeRestorePrivilege`を保持していない（非管理者等）。
        return Err(windows::core::Error::from_win32());
    }
    Ok(())
}

/// `SeRestorePrivilege`を有効化した状態で`f`を実行し、終了後に必ず元へ戻すRAIIガード
/// （D-19、`--force-system-acl`のオプトイン強制付与）。`SeRestorePrivilege`はバックアップ/リストア
/// 用特権で、DACLに関係なく`WRITE_DAC`/`WRITE_OWNER`でオブジェクトを開けるため、
/// `NT SERVICE\TrustedInstaller`所有ノード（Administratorでも`WRITE_DAC`不可）へも
/// **所有権を変えずに**（非破壊で）ACEを書ける。
///
/// **セキュリティ注意（D-19）**: 有効化中はこのプロセスがシステム上の任意オブジェクトの
/// セキュリティ記述子を書き換えられる。呼び出しは特権分離ヘルパー（昇格済み）内の、かつ
/// `--force-system-acl`が明示され`is_force_grant_forbidden`ゲートを通過したforced操作に限る。
/// 特権が有効化できない場合（非管理者等）は`f`をそのまま特権無しで実行する（呼び出し側の
/// grant/revokeが通常どおり`ACCESS_DENIED`で失敗するだけ。ここではpanicも早期returnもしない）。
pub fn with_restore_privilege<T>(f: impl FnOnce() -> T) -> T {
    struct PrivGuard {
        token: HANDLE,
        enabled: bool,
    }
    impl Drop for PrivGuard {
        fn drop(&mut self) {
            unsafe {
                if self.enabled {
                    let _ = set_privilege(self.token, SE_RESTORE_NAME, false);
                }
                if !self.token.is_invalid() {
                    let _ = CloseHandle(self.token);
                }
            }
        }
    }

    let _guard = unsafe {
        let mut token = HANDLE::default();
        let opened = OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ACCESS_MASK(TOKEN_ADJUST_PRIVILEGES.0 | TOKEN_QUERY.0),
            &mut token,
        )
        .is_ok();
        if !opened {
            PrivGuard {
                token: HANDLE::default(),
                enabled: false,
            }
        } else {
            let enabled = set_privilege(token, SE_RESTORE_NAME, true).is_ok();
            PrivGuard { token, enabled }
        }
    };
    f()
    // `_guard`のDropでSeRestorePrivilegeを無効化しトークンを閉じる（fがpanicしても戻る）。
}

/// `a`（対象パス）が`base`配下（`base`自身を含む）かを大文字小文字無視で判定する。
/// 双方canonicalize済みを前提とし、パス成分単位で比較する（文字列の`starts_with`だと
/// `C:\Windows`が`C:\WindowsApps`に誤マッチするため成分比較にする）。
fn path_is_within(a: &Path, base: &Path) -> bool {
    let comps = |p: &Path| -> Vec<String> {
        p.components()
            .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
            .collect()
    };
    let a = comps(a);
    let b = comps(base);
    b.len() <= a.len() && b.iter().zip(a.iter()).all(|(x, y)| x == y)
}

/// `--force-system-acl`（D-19、`SeRestorePrivilege`による強制付与）で触れてはいけない
/// host パスを保守的に拒否する。`SeRestorePrivilege`は全DACLをバイパスするため、既存の
/// jail相対 hard-deny（`overlay`/`permission`/`git`）ではカバーできない host パスに対する
/// **書込前の唯一の防壁**になる（`Some(reason)`なら禁止、`None`なら許可）。
///
/// 保守的な拒否対象:
/// - ドライブルート自体（例 `C:\`）——継承ACEを撒くと影響範囲が全ドライブに及ぶ。
/// - `%SystemRoot%`（通常`C:\Windows`）配下全体——`System32\config`のレジストリハイブ
///   （SAM/SYSTEM/SECURITY/SOFTWARE）等、OSの中核が含まれる。
///
/// 動機となった`...\Start Menu`（`%ProgramData%`配下）や`Program Files`配下の
/// TrustedInstaller所有フォルダはいずれも上記の外なので許可される。
/// canonicalizeに失敗するパスは安全側に倒して拒否する。
pub fn is_force_grant_forbidden(path: &Path) -> Option<String> {
    let canon = match std::fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) => {
            return Some(format!(
                "cannot canonicalize {} ({e}); refusing forced system-ACL grant",
                path.display()
            ));
        }
    };

    // ドライブルート（Prefix + RootDirのみで、通常成分が無い）を拒否する。
    let has_normal = canon
        .components()
        .any(|c| matches!(c, std::path::Component::Normal(_)));
    if !has_normal {
        return Some(format!(
            "{} is a drive root; refusing forced system-ACL grant (blast radius too large)",
            canon.display()
        ));
    }

    // `%SystemRoot%`（Windowsディレクトリ）配下全体を拒否する。
    if let Some(windir) = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("windir"))
        .map(std::path::PathBuf::from)
    {
        // windir自体をcanonicalizeして比較する（8.3名やcase差を吸収）。
        let windir_canon = std::fs::canonicalize(&windir).unwrap_or(windir);
        if path_is_within(&canon, &windir_canon) {
            return Some(format!(
                "{} is inside the Windows system directory ({}); refusing forced system-ACL grant \
                 (contains registry hives and OS-critical objects)",
                canon.display(),
                windir_canon.display()
            ));
        }
    }

    None
}

#[track_caller]
pub(crate) fn grant_ace_mask(
    path: &Path,
    sid: PSID,
    access: u32,
    inheritance: windows::Win32::Security::ACE_FLAGS,
) -> Result<(), AppContainerError> {
    grant_ace_mask_with(path, sid, access, inheritance, DaclWrite::SingleObject)
}

/// [`grant_ace_mask`]の書込モード指定版。既定（`SingleObject`）以外を使うのは
/// `grant_ace_inheritable_*`のroot付与だけ（[`DaclWrite`]のdoc参照）。冪等スキップは常に
/// 行う（[`IdempotentCheck::SkipIfSufficient`]）——それ以外が要る呼び出しは
/// [`grant_ace_mask_with_checked`]を直接使う。
#[track_caller]
pub(crate) fn grant_ace_mask_with(
    path: &Path,
    sid: PSID,
    access: u32,
    inheritance: windows::Win32::Security::ACE_FLAGS,
    write: DaclWrite,
) -> Result<(), AppContainerError> {
    grant_ace_mask_with_checked(
        path,
        sid,
        access,
        inheritance,
        write,
        IdempotentCheck::SkipIfSufficient,
    )
}

/// [`grant_ace_mask_with`]の実体。冪等スキップの有無まで呼び出し側に明示させる版
/// （[`IdempotentCheck`]のdoc参照）。`SkipIfSufficient`以外を渡すのは
/// [`propagate_workspace_root_grant`]（`grant_job`の背景フェーズ）だけ。
#[track_caller]
pub(crate) fn grant_ace_mask_with_checked(
    path: &Path,
    sid: PSID,
    access: u32,
    inheritance: windows::Win32::Security::ACE_FLAGS,
    write: DaclWrite,
    idempotent: IdempotentCheck,
) -> Result<(), AppContainerError> {
    // [BUG-101] 自己検証のために「この主体へこのパスの付与を要求した」ことを残す。
    // **root付与の内側なら何もしない**——`fix_descendants_missing_ace`が子孫の数だけ
    // ここを通るため（`grant_audit`のモジュールdoc）。ガードを張らずに直接ここへ来た
    // 書込（`grant_ace_mask`を直に呼ぶ経路）は記録する: 入口が1つ増えたときに
    // 黙って計装の対象外にならないようにするため（B-06）。
    crate::tier2a::grant_audit::note_low_level_grant(path, sid);
    // 冪等スキップ: 既にsid宛の明示ACEが要求（マスク**と継承フラグ**）を満たしていれば
    // `SetNamedSecurityInfoW`（プロファイルルート近傍で病的に遅くなりうる、BUG-011）を
    // 呼ばずに済ませる。
    //
    // [D-63] **継承フラグまで見る。** かつては「同一pathへ複数の異なる継承指定で呼ばれることが
    // 無い」という前提でマスクだけを比べていたが、D-63でその前提が崩れた——同じパスへ
    // 素の宣言（非継承）と`<path>/**`（継承）が来得る。マスクだけを見ていると、先に付いた
    // 非継承ACEで足りていると判定して**再帰要求が黙って非継承のまま通る**（B-10: 成功と
    // 報告しながら要求どおりになっていない）。回帰は
    // `a_recursive_request_is_not_skipped_by_an_existing_object_scoped_ace`が押さえる。
    //
    // 逆向き（非継承の要求に対して既存が継承あり）は**満たしているものとしてスキップする**
    // ——ここは付与の口であって、既にある継承ACEを狭める場所ではない（狭めるには配下へ
    // 降りたコピーを剥がす必要があり、それは撤収の仕事である）。`preflight`はその状態を
    // 警告として名指しする。
    if matches!(idempotent, IdempotentCheck::SkipIfSufficient) {
        if let Ok(Some(existing)) = sid_explicit_ace(path, sid) {
            if existing.satisfies(access, inheritance.0 as u8) {
                return Ok(());
            }
        }
    }
    let to_err = |e: windows::core::Error| AppContainerError::AclGrant {
        path: path.to_path_buf(),
        reason: e.to_string(),
    };
    unsafe {
        let path_w = long_path_wide(path);
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
        .ok()
        .map_err(to_err)?;

        let mut trustee = TRUSTEE_W::default();
        BuildTrusteeWithSidW(&mut trustee, sid);
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: access,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: inheritance,
            Trustee: trustee,
        };
        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        let entries_result =
            SetEntriesInAclW(Some(&[ea]), Some(existing_dacl as *const _), &mut new_dacl).ok();
        if let Err(e) = entries_result {
            let _ = LocalFree(HLOCAL(sd.0));
            return Err(to_err(e));
        }

        let set_result = match write {
            DaclWrite::SingleObject => set_dacl_single_object(path, new_dacl),
            DaclWrite::Propagate => set_dacl_propagating(path, new_dacl),
        };

        let _ = LocalFree(HLOCAL(new_dacl as *mut _));
        let _ = LocalFree(HLOCAL(sd.0));
        set_result.map_err(to_err)?;
    }
    Ok(())
}

/// `mask`を`path`へ付与する（ディレクトリは継承付き、ファイルは非継承）。
/// [`grant_ace`]（workspaceのRWX）と[`grant_ace_access`]（`FsAccess`）の共通の底で、
/// [`fix_descendants_missing_ace`]が**マスクの出どころを問わず**同じ形のACEを書けるようにする。
#[track_caller]
fn grant_ace_raw(path: &Path, sid: PSID, mask: u32, is_dir: bool) -> Result<(), AppContainerError> {
    let inheritance = if is_dir {
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
    } else {
        NO_INHERITANCE
    };
    grant_ace_mask(path, sid, mask, inheritance)
}

/// workspace配下のノードへ read/write/execute/delete を付与する（ディレクトリは継承付き、
/// ファイルは非継承）。`WRITE_DAC`/`WRITE_OWNER`は含めない（sandboxed子が自分でACLを緩める
/// ことを防ぐ多層防御）。
#[track_caller]
fn grant_ace(path: &Path, sid: PSID, is_dir: bool) -> Result<(), AppContainerError> {
    grant_ace_raw(path, sid, workspace_rwx_mask(), is_dir)
}

/// workspace配下へ与えるアクセス（read/write/execute/delete）。`WRITE_DAC`/`WRITE_OWNER`は
/// 含めない（sandboxed子が自分でACLを緩めることを防ぐ多層防御）。`grant_ace`と
/// [`grant_ace_propagating`]が同じ値を使うために切り出してある——ここがずれると、rootへ伝播
/// させたACEと、フォールバックが個別に書くACEの権限が食い違う。
pub(crate) fn workspace_rwx_mask() -> u32 {
    FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | FILE_GENERIC_EXECUTE.0 | DELETE.0
}

/// [`grant_ace`]のroot専用版（継承あり＋既存子孫への伝播）。理由は
/// [`grant_ace_access_propagating`]と同じ。
#[track_caller]
fn grant_ace_propagating(root: &Path, sid: PSID) -> Result<(), AppContainerError> {
    grant_ace_mask_with(
        root,
        sid,
        workspace_rwx_mask(),
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
        DaclWrite::Propagate,
    )
}

/// `root`配下（`root`自身含む）へ再帰的にpackage SIDの許可ACEを付与する。継承フラグ
/// （`CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE`）を使うため、`root`自身へのACE付与だけで
/// 新規作成される子孫にも自動継承されるが、**既存の子孫ファイル/ディレクトリ**には遡って
/// 効かないため、`root`付与時点で存在する全ノードへも明示的に付与する（`.git`を除外しない、
/// Tier1の`cwd`全体ラベル付与と整合させる設計判断。理由は`docs/phases/foundation/`参照）。
#[track_caller]
pub fn grant_ace_recursive(root: &Path, sid: PSID) -> Result<(), AppContainerError> {
    // [BUG-101] 全ノードへ個別に書くので、記録するのはrootだけ（`grant_audit`のdoc）。
    let _audit = crate::tier2a::grant_audit::note_root_grant(root, sid);
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    collect_dirs_and_files(root, &mut dirs, &mut files, OnVanished::Abort).map_err(|e| {
        AppContainerError::AclGrant {
            path: root.to_path_buf(),
            reason: e.to_string(),
        }
    })?;
    for dir in &dirs {
        grant_ace(dir, sid, true)?;
    }
    for file in &files {
        grant_ace(file, sid, false)?;
    }
    Ok(())
}

pub(crate) fn fs_access_mask(access: FsAccess) -> u32 {
    match access {
        FsAccess::Read => FILE_GENERIC_READ.0,
        FsAccess::ReadWrite => FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | DELETE.0,
        FsAccess::ReadExec => FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0,
        // 同じパスへの`fs.read_write`と`fs.read_exec`の宣言を1本のACEへ畳んだ形
        // （[`FsAccess::wider`]）。**workspace本体へ与えるマスクと同じ集合**なので、
        // 片方だけ直る事故を避けるために[`workspace_rwx_mask`]をそのまま呼ぶ。
        FsAccess::ReadWriteExec => workspace_rwx_mask(),
    }
}

#[track_caller]
fn grant_ace_access(
    path: &Path,
    sid: PSID,
    is_dir: bool,
    access: FsAccess,
) -> Result<(), AppContainerError> {
    grant_ace_raw(path, sid, fs_access_mask(access), is_dir)
}

/// `grant_ace_access`のroot専用版: 継承ありACEを付けたうえで**OSに既存子孫へ伝播させる**。
///
/// これが`grant_ace_inheritable_*`の高速経路の本体である（M12追記14）。ここを
/// `DaclWrite::SingleObject`で書くと伝播が起きず、後段のフォールバックが全ノードで発火して
/// 付与がO(ファイル数)になる（[BUG-081](../../../../docs/bugs/BUG-081.md)）。
#[track_caller]
fn grant_ace_access_propagating(
    root: &Path,
    sid: PSID,
    access: FsAccess,
) -> Result<(), AppContainerError> {
    grant_ace_mask_with(
        root,
        sid,
        fs_access_mask(access),
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
        DaclWrite::Propagate,
    )
}

/// workspace配下のノードへ read/execute のみを付与する（`grant_ace`のread-only版、D-13）。
/// `FILE_GENERIC_WRITE`・`DELETE`を含めないため、package SIDはこのルート配下を読取・実行
/// できるが書込・削除はできない（D-13「read-onlyを既定とする」）。
#[track_caller]
fn grant_ace_ro(path: &Path, sid: PSID, is_dir: bool) -> Result<(), AppContainerError> {
    grant_ace_access(path, sid, is_dir, FsAccess::ReadExec)
}

/// `grant_ace_recursive`のread-only版（D-13、fs passthroughの既定）。
#[track_caller]
pub fn grant_ace_recursive_ro(root: &Path, sid: PSID) -> Result<(), AppContainerError> {
    // [BUG-101] `grant_ace_recursive`と同じ（記録するのはrootだけ）。
    let _audit = crate::tier2a::grant_audit::note_root_grant(root, sid);
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    collect_dirs_and_files(root, &mut dirs, &mut files, OnVanished::Abort).map_err(|e| {
        AppContainerError::AclGrant {
            path: root.to_path_buf(),
            reason: e.to_string(),
        }
    })?;
    for dir in &dirs {
        grant_ace_ro(dir, sid, true)?;
    }
    for file in &files {
        grant_ace_ro(file, sid, false)?;
    }
    Ok(())
}

/// `grant_ace_recursive_ro`の高速化版（Phase B-2、`TIER1A-OPEN-ISSUES.md`項目6・制約2）。
/// Experiment L（`docs/phases/foundation/M12-shell-isolation-tiers.md`）の実機検証で、`root`へ継承あり
/// read-only ACEを1件付与するだけで、**付与時点で既に存在する**子孫にもOS側（NTFS）が
/// DACL変更時に伝播させることを確認した（`grant_ace_recursive_ro`直前の旧コメント「既存子孫
/// には遡及しない」という主張は誤りだった）。
///
/// ただし継承をブロックする保護DACL（`PROTECTED_DACL_SECURITY_INFORMATION`が立った子。
/// エクスプローラの「継承を無効にする」操作等で作られうる）が混在するツリーでは、その配下に
/// 伝播が届かない。そのため付与後に全ノードを再walkし、`sid`のACEが実際に届いているか
/// （[`sid_effective_ace_mask`]で検出、**継承経由・明示ACE経由を問わない**）を確認し、
/// **届いていないノードだけ**`grant_ace_ro`で個別に明示付与するフォールバックを行う。
///
/// **この2点はどちらも欠けると意味を失う**（[BUG-081](../../../../docs/bugs/BUG-081.md)）:
///
/// 1. rootへの付与は[`DaclWrite::Propagate`]でなければならない。`SingleObject`（BUG-011/013の
///    ハング対策で導入した単一オブジェクト書込）だと**伝播そのものが起きない**。
/// 2. 到達確認は継承ACEを数える`sid_effective_ace_mask`でなければならない。
///    `sid_ace_mask`（`GetExplicitEntriesFromAclW`）は継承ACEを拾わないので、伝播していても
///    「届いていない」と判定してしまう。
///
/// どちらかが欠けるとフォールバックが全ノードで発火し、この関数は`grant_ace_recursive_ro`と
/// 同じO(n)の明示付与へ退化する（実測: 254,000ファイルのworkspaceで起動が60秒、かつ
/// セッションのACEがツリー全体へ残留した）。
#[track_caller]
pub fn grant_ace_inheritable_ro(root: &Path, sid: PSID) -> Result<(), AppContainerError> {
    grant_ace_inheritable_access(root, sid, FsAccess::ReadExec)
}

/// `root`がファイルのときは、継承ACE＋ツリーwalkではなく**単一オブジェクトへの付与1件**で終える。
///
/// BUG-059: この分岐が無かった頃、`root`がファイル（`--cow`のredirector DLL・ファイル1件を指す
/// `--fs-allow`）だと`grant_ace_access`でACEを付けた**後**に`collect_dirs_and_files`の`read_dir`が
/// `ERROR_DIRECTORY`(267)で落ち、**ACEは載っているのに`Err`が返っていた**。呼び出し側は`Err`を
/// 「何も起きなかった」と解釈して台帳へ記録しないため、撤収経路の無い孤立ACEが残っていた。
///
/// ファイルに`CONTAINER_INHERIT_ACE|OBJECT_INHERIT_ACE`を立ててもWindowsは受け付けるが
/// （継承先が無いので実害は無い）、意味が無いので`is_dir: false`で付ける。
#[track_caller]
fn grant_ace_access_if_file(
    root: &Path,
    sid: PSID,
    access: FsAccess,
) -> Option<Result<(), AppContainerError>> {
    if root.is_dir() {
        return None;
    }
    Some(grant_ace_access(root, sid, false, access))
}

/// [D-63] **宣言されたスコープで付与する、fs passthroughの唯一の入口。**
///
/// 宣言値が`C:/x`なら`C:/x`というオブジェクト1つだけ、`C:/x/**`なら配下すべて。どちらを
/// 選ぶかは呼び出し側が推測せず、宣言から決まった[`GrantScope`]をそのまま渡す
/// （`harness_policy::normalize::declared_scope`が唯一の判定）。
///
/// # なぜ分岐をここに置くのか
///
/// 付与の入口は3つある——本体（非管理者）・本体が既に管理者のときの直接付与・昇格ヘルパー。
/// 3箇所が別々に「継承ありで付けるか」を決めると、**片方だけがD-63に従う**形になる（B-02:
/// 対の片方だけ実装する、が最頻の再発パターン）。だから分岐は1つにし、3入口はこれを呼ぶ。
///
/// ファイルはどちらのスコープでも単一オブジェクトへの付与1件で終わる
/// （[`grant_ace_access_if_file`]、BUG-059）——ファイルに子孫は無いので、`Recursive`と
/// `Object`の区別が意味を持つのはディレクトリだけである。
#[track_caller]
pub fn grant_ace_scoped(
    root: &Path,
    sid: PSID,
    access: FsAccess,
    scope: GrantScope,
) -> Result<(), AppContainerError> {
    match scope {
        GrantScope::Recursive => grant_ace_inheritable_access(root, sid, access),
        GrantScope::Object => grant_ace_object_access(root, sid, access),
    }
}

/// [D-63] `root`**そのものだけ**へ非継承ACEを1本書く（配下へは一切広げない）。
///
/// [`grant_ace_inheritable_access`]との違いは2つで、どちらも「観測されていない範囲を開かない」
/// という同じ理由から来ている:
///
/// 1. 継承フラグを立てない（`NO_INHERITANCE`）。立てると**今後そこに作られるファイル**まで
///    開く——D-62が畳み込みを廃した理由そのもの（ETWは1回の実行で通った経路しか見ていない）。
/// 2. 子孫救済walk（[`fix_descendants_missing_ace`]）を回さない。継承させないのだから
///    「継承が届かなかった子孫」は定義上存在せず、走らせれば**ACEを配りに行くだけ**になる。
///
/// 副作用として速い（DACL書込1回・walk無し）が、それは目的ではなく結果である。
#[track_caller]
fn grant_ace_object_access(
    root: &Path,
    sid: PSID,
    access: FsAccess,
) -> Result<(), AppContainerError> {
    // [BUG-101] 継承版と同じく「付与を要求した」ことを記録する。**両分岐に張る**——
    // 片方だけだと、オブジェクト単体の付与が計装の対象外になり、台帳との突き合わせ
    // （`grant_audit`）が「記録漏れ」を検出できなくなる（B-06）。
    let _audit = crate::tier2a::grant_audit::note_root_grant(root, sid);
    if let Some(result) = grant_ace_access_if_file(root, sid, access) {
        return result;
    }
    grant_ace_mask(root, sid, fs_access_mask(access), NO_INHERITANCE)
}

#[track_caller]
pub fn grant_ace_inheritable_access(
    root: &Path,
    sid: PSID,
    access: FsAccess,
) -> Result<(), AppContainerError> {
    // [BUG-101] root付与の入口。要求を記録し、この下の子孫救済（`fix_descendants_missing_ace`）が
    // 個別に書くACEは記録しない（撤収はrootからの再帰で行うので、台帳に載るのはrootだけ）。
    let _audit = crate::tier2a::grant_audit::note_root_grant(root, sid);
    if let Some(result) = grant_ace_access_if_file(root, sid, access) {
        return result;
    }
    grant_ace_access_propagating(root, sid, access)?;
    fix_descendants_missing_ace(root, sid, fs_access_mask(access), &[], &|_, _| {})?;
    Ok(())
}

/// 保護DACL等で継承が届かなかった既存子孫を洗い出し、そこだけへ明示ACEを書く（[`
/// grant_ace_inheritable_ro`]のdocの「2点目」の実体）。
///
/// **rootへの伝播付与とこのwalkは分けてある**。伝播は書込1回で済むのに対し、walkは
/// O(ファイル数)の読取確認で、この開発機のリポジトリ（26万ノード）では実測16秒かかる。
/// 分けておくと、呼び出し側が「rootの付与だけ同期で済ませ、walkは背景へ回す」という選択を
/// できる（D-54、`preflight`がそうする）。
///
/// - `skip`: この配下を丸ごと対象から外す。`preflight`は`.harness/`を渡す——直後に
///   [`super::protect_harness_control_dir_from_appcontainer`]が剥がす場所なので、ここで
///   付けるのは無駄なうえ、**walkを背景化すると剥がした後に付け直す競合**になる（D-05/D-09の
///   制御面保護が無言で外れる）。
/// - `progress`: `(処理済み, 全体)`で呼ばれる。表示のためだけのもので、判定には関与しない。
#[track_caller]
pub fn fix_descendants_missing_ace(
    root: &Path,
    sid: PSID,
    mask: u32,
    skip: &[std::path::PathBuf],
    progress: &dyn Fn(usize, usize),
) -> Result<DescendantFixReport, AppContainerError> {
    // [BUG-101] ここが書くのは**子孫**のACEで、台帳に載るのはrootである。ガードを張って
    // 子孫ぶんを記録から外す（26万ノードのworkspaceでは全件が偽の「記録漏れ」になる）。
    // `grant_ace_inheritable_*`から呼ばれた場合は既に外側のガードが立っているので、
    // ここは`grant_job`の背景フェーズが直接呼ぶ経路のためのものである。
    let _audit = crate::tier2a::grant_audit::note_root_grant(root, sid);
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    collect_dirs_and_files(root, &mut dirs, &mut files, OnVanished::Abort).map_err(|e| {
        AppContainerError::AclGrant {
            path: root.to_path_buf(),
            reason: e.to_string(),
        }
    })?;

    let is_skipped = |node: &Path| skip.iter().any(|s| path_is_within(node, s));
    let total = dirs.len() + files.len();
    let mut report = DescendantFixReport {
        checked: total,
        ..Default::default()
    };
    let mut processed = 0usize;
    for (node, is_dir) in dirs
        .iter()
        .map(|d| (d, true))
        .chain(files.iter().map(|f| (f, false)))
    {
        processed += 1;
        // 進捗は1000件ごと（1件ごとに通知すると、通知そのものがwalkより重くなる）。
        if processed.is_multiple_of(1000) || processed == total {
            progress(processed, total);
        }
        if is_skipped(node) {
            report.skipped += 1;
            continue;
        }
        match sid_effective_ace_mask(node, sid) {
            Ok(Some(_)) => continue,
            Ok(None) => {}
            Err(_) => report.probe_errors += 1,
        }
        if report.samples.len() < 8 {
            report.samples.push(node.display().to_string());
        }
        grant_ace_raw(node, sid, mask, is_dir)?;
        report.granted += 1;
    }
    Ok(report)
}

/// `root`の**直下**（深さ1）のうち、`sid`へアクセスが届いていないものを1件だけ返す
/// （届いていなければ`Some(そのパス)`、全部届いていれば`None`）。
///
/// **[BUG-110] 台帳の「検証済み」を実体側から裏取りするための検算である。**
/// 台帳が答えられるのは「以前このrootを検証し、rootが入れ替わっていない」までで、
/// 「いま実際にACEが載っているか」は別の事実である（`B-14`: 台帳の存在で実体の存在を
/// 代替しない）。ここが1件でも見つければ`preflight`は背景ジョブを回し直す。
///
/// **判定は救済walkと同じ述語**（[`sid_effective_ace_mask`]）を使う。別の述語で書くと
/// 「検算は欠けていると言うのに、修正側は足りていると言う」状態になり、**毎起動で
/// O(ファイル数)のジョブが回り続ける**（`B-05`: コンパイラが守らない複製）。
///
/// 深さ1だけを見るのは費用の判断である——rootの継承ACEが届いていない事態は、たいてい
/// 「ツリーごと入れ替わった」「継承が張られる前に置かれた」のどちらかで、どちらも直下に
/// 現れる。全走査はジョブ本体（フェーズ1）の仕事で、ここはその起動判定に過ぎない。
///
/// `skip`配下は対象外（`preflight`は`.harness/`を渡す——**意図的にACEを剥がしている場所**
/// なので、ここで数えると毎回ジョブが回る）。DACLを読めなかったノードは
/// **届いていない側**へ倒す（読めない理由がACL不足のこともある）。
pub(crate) fn top_level_child_missing_ace(
    root: &Path,
    sid: PSID,
    skip: &[std::path::PathBuf],
) -> Option<std::path::PathBuf> {
    let entries = std::fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if skip.iter().any(|s| path_is_within(&path, s)) {
            continue;
        }
        // symlink/リパースポイントは辿らない（`collect_dirs_and_files`と同じガード）。
        // 付与側が触らないものを、検算側だけが数えてはいけない。
        if entry.file_type().map(|t| t.is_symlink()).unwrap_or(true) {
            continue;
        }
        match sid_effective_ace_mask(&path, sid) {
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => return Some(path),
        }
    }
    None
}

/// [`fix_descendants_missing_ace`]の結果。件数だけでは追えない事象（「どのノードが継承から
/// 漏れたのか」）のために`samples`も持つ——BUG-081の調査では、この数件のパスが原因特定の
/// 決め手だった。
#[derive(Debug, Default)]
pub struct DescendantFixReport {
    /// walkが見たノード数（`skip`配下を含む）。
    pub checked: usize,
    /// `skip`配下として対象外にした数。
    pub skipped: usize,
    /// 継承が届いておらず、明示ACEを書いた数。**0であることが健全な状態**。
    pub granted: usize,
    /// ACEを読めなかった数（判定できないので付与側に倒す）。
    pub probe_errors: usize,
    /// 明示付与したノードの先頭数件。
    pub samples: Vec<String>,
}

/// `grant_ace_inheritable_ro`のRW版（Tier2aが既定でプローブされるようになったことに伴う
/// `preflight`の高速化）。`grant_ace_recursive`は
/// workspace_root配下の全ノードへ毎回個別に`SetNamedSecurityInfoW`書込を試みる（`grant_ace_mask`
/// 内部の冪等スキップにより実際のWin32書込呼び出し自体は2回目以降省略されるが、読取確認は
/// 変わらず全ノード分発生する）。root へ継承ACEを1件付与するだけで、付与時点で既に存在する
/// 子孫にもNTFSがDACL変更時に伝播させることを`grant_ace_inheritable_ro`側で実機確認済み
/// （このコメント参照）であるため、RW版でも同じ「root 1件書込 + 全ノード読取確認（大半は
/// 継承経由で既に充足）」パターンが使える。書込系Win32呼び出しの回数を大幅に削減できる
/// （BUG-011「プロファイルルート近傍の書込みは病的に遅くなりうる」を踏まえると効果が大きい）。
///
/// **残るコスト**: 全体walk自体（`collect_dirs_and_files`のreaddir + 各ノードの
/// [`sid_effective_ace_mask`]読取確認）はO(n)のまま。**書込**が伝播1回で済むようになった分だけ
/// 速くなるのであって、読取確認は依然として全ノードに対して走る（BUG-081の修正後に再測定し、
/// 必要ならこのwalkを背景スレッドへ回す——判断は`docs/STATUS.md`のTier2a節）。
#[track_caller]
pub fn grant_ace_inheritable_rw(root: &Path, sid: PSID) -> Result<(), AppContainerError> {
    // [BUG-101] `grant_ace_inheritable_access`と同じ理由でroot付与の入口（下の
    // `fix_descendants_missing_ace`が子孫ぶんの書込を行う）。
    let _audit = crate::tier2a::grant_audit::note_root_grant(root, sid);
    grant_workspace_root_rw(root, sid)?;
    let mut timing = PhaseTiming::start();
    let report = fix_descendants_missing_ace(root, sid, workspace_rwx_mask(), &[], &|_, _| {})?;
    timing.mark(&format!(
        "  rw: reach check + fallback ({} checked, {} explicit grants, {} probe errors)",
        report.checked, report.granted, report.probe_errors
    ));
    if !report.samples.is_empty() {
        timing.mark_lines("  rw: not reached by inheritance", &report.samples);
    }
    Ok(())
}

/// workspace rootへのRWX継承ACE付与だけを行う（子孫の確認walkは伴わない、D-54）。
///
/// これ1件で、**付与時点で存在する子孫26万件へOSが継承ACEを物理コピーする**（実測20.7秒。
/// NTFSのアクセス判定は対象自身のDACLしか見ないので、このコピーは要求そのものの費用であって
/// 実装の無駄ではない、[BUG-081](../../../../docs/bugs/BUG-081.md)）。2回目以降は
/// [`grant_ace_mask_with`]の冪等スキップが効き、Win32書込は1回も起きない。
///
/// 確認walk（保護DACLで継承が届かなかったノードの救済）は
/// [`fix_descendants_missing_ace`]が別に持つ。
#[track_caller]
pub fn grant_workspace_root_rw(root: &Path, sid: PSID) -> Result<(), AppContainerError> {
    // BUG-059と同じ分岐（`grant_ace_access_if_file`のdoc参照）。現在の呼び出し元は
    // ディレクトリしか渡さないが、**同じクラスの保険は同じクラスの関数すべてに入れる**
    // ——BUG-059は「1箇所だけ直して、後から足された経路が同じ穴を開けた」形だった。
    if !root.is_dir() {
        return grant_ace(root, sid, false);
    }
    let mut timing = PhaseTiming::start();
    grant_ace_propagating(root, sid)?;
    timing.mark("  rw: propagating root grant");
    Ok(())
}

/// [`grant_workspace_root_rw`]のread-only版（`--cow`のworkspace本体、D-30）。
#[track_caller]
pub fn grant_workspace_root_ro(root: &Path, sid: PSID) -> Result<(), AppContainerError> {
    if let Some(result) = grant_ace_access_if_file(root, sid, FsAccess::ReadExec) {
        return result;
    }
    let mut timing = PhaseTiming::start();
    grant_ace_access_propagating(root, sid, FsAccess::ReadExec)?;
    timing.mark("  ro: propagating root grant");
    Ok(())
}

/// [BUG-082 Part B] [`grant_workspace_root_rw`]の**伝播なし**版。`preflight`の同期区間は
/// これを使う。
///
/// tier判定（`smoke_test_spawn`）に必要なのはrootのDACL自体にcapability SIDのACEが
/// 載っていることだけで、**既存の子孫への伝播は不要**——`smoke_test_spawn`が使う`probe_dir`は
/// preflightがその場で新規作成するディレクトリであり、Windowsは新規オブジェクト作成時に
/// 親の**現在の**DACLから継承ACLを都度計算するため、既存子孫への伝播が未完でも正しく
/// ACEを継承する。既存子孫への伝播（コストの本体、実測20秒超）は`grant_job`の背景フェーズ
/// （[`propagate_workspace_root_grant`]）へ委ねる——この関数は常にミリ秒オーダーになる
/// （`DaclWrite::SingleObject`、[`grant_ace`]と同じ土台）。
#[track_caller]
pub fn grant_workspace_root_rw_fast(root: &Path, sid: PSID) -> Result<(), AppContainerError> {
    if !root.is_dir() {
        return grant_ace(root, sid, false);
    }
    let mut timing = PhaseTiming::start();
    grant_ace(root, sid, true)?;
    timing.mark("  rw: fast (single-object) root grant");
    Ok(())
}

/// [`grant_workspace_root_rw_fast`]のread-only版（`--cow`のworkspace本体、D-30）。
#[track_caller]
pub fn grant_workspace_root_ro_fast(root: &Path, sid: PSID) -> Result<(), AppContainerError> {
    if let Some(result) = grant_ace_access_if_file(root, sid, FsAccess::ReadExec) {
        return result;
    }
    let mut timing = PhaseTiming::start();
    grant_ace_ro(root, sid, true)?;
    timing.mark("  ro: fast (single-object) root grant");
    Ok(())
}

/// [BUG-082 Part B] rootへの継承ACE伝播を**冪等チェック無しで無条件に**行う。`grant_job`の
/// 背景フェーズだけが使う。
///
/// **`IdempotentCheck::Always`が必須の理由**: `preflight`の同期区間で先に
/// `grant_workspace_root_rw_fast`/`_ro_fast`（`DaclWrite::SingleObject`）を通しているため、
/// この時点でrootは既に「sid宛のACEが要求マスクを満たしている」ように見える。通常の
/// `grant_ace_mask_with`（`IdempotentCheck::SkipIfSufficient`）を使うと、この冪等スキップが
/// 効いて**伝播そのものが呼ばれない**——[BUG-081](../../../../docs/bugs/BUG-081.md)層1
/// （伝播を使う高速経路が、伝播しない書込APIへ差し替えられ、機能は壊れないまま無症状に
/// 退化していた）とまったく同じ形の罠なので、ここは意図を明示する専用関数にする。
///
/// `mask`は呼び出し側（`preflight`）が`workspace_mask`としてRWX/ROいずれかを渡す
/// （`grant_job::start`の他の引数と同じ`mask`をそのまま使う）。
#[track_caller]
pub(crate) fn propagate_workspace_root_grant(
    root: &Path,
    sid: PSID,
    mask: u32,
) -> Result<(), AppContainerError> {
    let mut timing = PhaseTiming::start();
    grant_ace_mask_with_checked(
        root,
        sid,
        mask,
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
        DaclWrite::Propagate,
        IdempotentCheck::Always,
    )?;
    timing.mark("  background: propagating root grant (unconditional)");
    Ok(())
}

#[cfg(test)]
mod fs_access_mask_tests {
    use super::*;

    /// **和のマスクは、書きと実行の両方を実際に含む。**
    ///
    /// ビットで確かめるのは、`FsAccess::ReadWriteExec`という名前が付いていることと、
    /// そのACEで実際に`CreateProcess`できることが別の事実だからである（B-25:
    /// 「設定した」ではなく実効で見る。ここは実効の手前——マスクそのもの——を固定する）。
    #[test]
    fn the_combined_mask_contains_read_write_execute_and_delete() {
        let mask = fs_access_mask(FsAccess::ReadWriteExec);

        for (bit, name) in [
            (FILE_GENERIC_READ.0, "read"),
            (FILE_GENERIC_WRITE.0, "write"),
            (FILE_GENERIC_EXECUTE.0, "execute"),
            (DELETE.0, "delete"),
        ] {
            assert_eq!(mask & bit, bit, "the combined mask is missing {name}");
        }
    }

    /// 和は、畳む前の2つのマスクの**どちらの上位集合でもある**。
    /// これが崩れると「和を取ったのに片方の権限が減る」という、直したはずの症状に戻る。
    #[test]
    fn the_combined_mask_is_a_superset_of_both_sources() {
        let combined = fs_access_mask(FsAccess::ReadWriteExec);

        for source in [FsAccess::Read, FsAccess::ReadWrite, FsAccess::ReadExec] {
            let mask = fs_access_mask(source);
            assert_eq!(
                combined & mask,
                mask,
                "combining must not drop bits from {:?}",
                source
            );
        }
    }

    /// 単独の`ReadWrite`には実行権が**入っていない**——これがそもそもの発端である
    /// （`fs.read_write`だけ承認しても`cargo.exe`は起動できない）。
    /// 対で固定しておかないと、和の側だけ見て「実行権はどこかで付いている」と誤読する（B-35）。
    #[test]
    fn read_write_alone_still_carries_no_execute_right() {
        let mask = fs_access_mask(FsAccess::ReadWrite);

        assert_ne!(
            mask & FILE_GENERIC_EXECUTE.0,
            FILE_GENERIC_EXECUTE.0,
            "if read_write ever includes execute, the whole read_exec distinction is moot"
        );
    }
}
