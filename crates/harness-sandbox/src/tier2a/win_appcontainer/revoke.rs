//! AppContainer SIDのACE撤収と、撤収済みであることの検証。
//!
//! 付与側（`acl_grant`）と対になる。DACLからSIDのACEだけを取り除く操作は、継承ACEを
//! 壊さずに明示ACEのみを消す必要があるため`copy_dacl_excluding_sid`を経由する。

use super::*;

/// [BUG-083](../../../../docs/bugs/BUG-083.md) の実測プローブ。
///
/// **他のテストモジュールと違い`win_appcontainer.rs`ではなくここで宣言する。** 測定対象が
/// このモジュールのprivate関数（[`set_dacl_single_object_with_protection`]・
/// [`copy_dacl_excluding_sids`]・[`remove_sid_aces_and_protect`]）そのものであり、
/// 兄弟モジュールからは触れないためである。ファイルを分けているのは
/// `docs/CODE-STRUCTURE-RULES.md`規則2（`#[path]`での分割は明示的に許容）に従う。
#[cfg(all(windows, test))]
#[path = "dacl_protection_probe_tests.rs"]
mod dacl_protection_probe_tests;

/// `ACCESS_ALLOWED_ACE_TYPE`（WinNT.h）。`windows`クレートはこの値を定数として公開して
/// いないため、既知の固定値としてここに置く。
pub(crate) const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
/// `ACCESS_DENIED_ACE_TYPE`（WinNT.h）。Deny ACEもこのクレートが書くので、revoke時は
/// Allow ACEと同じSID照合で取り除く。
pub(crate) const ACCESS_DENIED_ACE_TYPE: u8 = 1;
/// 条件付きACE（`ACCESS_ALLOWED_CALLBACK_ACE_TYPE`/`ACCESS_DENIED_CALLBACK_ACE_TYPE`、WinNT.h）。
///
/// **harnessは書かないが、実マシンに実在する。** この開発機の
/// `%LOCALAPPDATA%\PowerToys`には
/// `(XA;OICI;0x1200a9;;;BU;(WIN://SYSAPPID Contains "Microsoft.PowerToys.SparseApp_..."))`が
/// 載っており、MSIXのSparseパッケージが自分の実行時にだけ効くACEとして置いていく。
/// 先頭は`ACCESS_ALLOWED_ACE`と同じ`Mask`/`SidStart`配置で、SIDの後ろに条件式が続く。
pub(crate) const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;
pub(crate) const ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 10;

/// `path`のDACLに載っている**明示**ACE（継承ACEを除く）を1本ずつ渡す。
///
/// # なぜ`GetExplicitEntriesFromAclW`をやめたのか
///
/// あちらは**DACLに条件付きACEが1本でも載っていると`ERROR_INVALID_PARAMETER`(0x80070057)で
/// 全体が失敗する**。実マシンで`harness fs revoke-all`が
/// `%LOCALAPPDATA%\PowerToys`だけ撤収できず、台帳エントリが永久に残った
/// （2026-08-12の実測。そのパスにharnessのACEは1本も無く、**走査そのものが落ちていた**）。
/// 「読めなかった」が「撤収できない」に化ける形なので、読み取りを`GetAce`の直接列挙へ寄せる。
///
/// 扱うのは`Mask`/`SidStart`の配置が共通な4種別（allow/deny/条件付きallow/条件付きdeny）だけで、
/// object ACE（ディレクトリサービス用。ファイルオブジェクトには現れない）は**主体を特定できない
/// ので飛ばす**——[`copy_dacl_excluding_sids`]が未知種別を保持するのと同じ判断である。
///
/// `visit`には`(SID, ACE種別, ACEフラグ, マスク)`を渡す。継承ACEを渡さないのは
/// [`sid_ace_mask`]の従来の意味（`GetExplicitEntriesFromAclW`の仕様）を保つためで、
/// 撤収側にとってはこれが正しい——継承ACEはそのノードからは剥がせない。
pub(crate) unsafe fn visit_explicit_aces(
    path: &Path,
    visit: &mut dyn FnMut(PSID, u8, u8, u32),
) -> windows::core::Result<()> {
    unsafe {
        let path_w = long_path_wide(path);
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

        // NULL DACL（＝誰でもフルアクセス）には明示ACEが1本も無い。`sd`は解放する。
        if !dacl.is_null() {
            let count = (*dacl).AceCount as u32;
            for index in 0..count {
                let mut ace_ptr: *mut c_void = std::ptr::null_mut();
                if GetAce(dacl, index, &mut ace_ptr).is_err() || ace_ptr.is_null() {
                    continue;
                }
                let header = &*(ace_ptr as *const ACE_HEADER);
                // 継承ACEは「このノードの明示ACE」ではない。
                if header.AceFlags & (INHERITED_ACE.0 as u8) != 0 {
                    continue;
                }
                if !matches!(
                    header.AceType,
                    ACCESS_ALLOWED_ACE_TYPE
                        | ACCESS_DENIED_ACE_TYPE
                        | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                        | ACCESS_DENIED_CALLBACK_ACE_TYPE
                ) {
                    continue;
                }
                let ace = &*(ace_ptr as *const ACCESS_ALLOWED_ACE);
                let entry_sid = PSID(&ace.SidStart as *const u32 as *mut c_void);
                visit(entry_sid, header.AceType, header.AceFlags, ace.Mask);
            }
        }
        let _ = LocalFree(HLOCAL(sd.0));
        Ok(())
    }
}

/// あるSIDについて、そのノードの明示ACEを畳んだもの（[`sid_explicit_ace`]の戻り値）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExplicitAce {
    /// 明示ACE全種別のマスクの論理和。[`sid_ace_mask`]が返すのはこの値である。
    pub mask: u32,
    /// **素のallow ACE**だけのマスクの論理和。撤収側の指紋照合（規則4）はこちらを使う
    /// ——条件付きACEやdeny ACEは「harnessが書いた形」ではない。
    pub allow_mask: u32,
    /// 継承フラグ（`OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE`）の論理和。
    /// [D-63] **付与範囲の実測値**である——台帳の`scope`ではなくこれが根拠になる。
    pub inherit: u8,
    /// harnessが書かない形のACE（deny・条件付き）が1本でも混じっているか。
    pub foreign_shape: bool,
}

impl ExplicitAce {
    /// [D-63] このACEが配下へ継承されるか（＝再帰付与の実測）。
    pub fn is_inheritable(&self) -> bool {
        self.inherit & ((OBJECT_INHERIT_ACE.0 | CONTAINER_INHERIT_ACE.0) as u8) != 0
    }

    /// 要求（マスクと継承）を既に満たしているか。**冪等スキップの唯一の判定**（D-63）。
    ///
    /// マスクだけを見ていた頃は、同じパスへ素の宣言（非継承）と`**`宣言（継承）が来たとき、
    /// 先に付いた非継承ACEでマスクが足りていると**再帰要求が黙って非継承のまま通っていた**
    /// （B-10: 成功と報告しながら要求どおりになっていない）。
    pub fn satisfies(&self, required_mask: u32, required_inherit: u8) -> bool {
        self.mask & required_mask == required_mask
            && self.inherit & required_inherit == required_inherit
    }
}

/// `path`の`sid`宛の明示ACEを畳んで返す。無ければ`None`。
///
/// [`sid_ace_mask`]はこの薄い皮である（**同じDACLの読み方を2つ持たない**、B-05）。
pub(crate) fn sid_explicit_ace(
    path: &Path,
    sid: PSID,
) -> Result<Option<ExplicitAce>, AppContainerError> {
    let to_err = |e: windows::core::Error| AppContainerError::AclGrant {
        path: path.to_path_buf(),
        reason: e.to_string(),
    };
    let mut found: Option<ExplicitAce> = None;
    unsafe {
        visit_explicit_aces(path, &mut |entry_sid, ace_type, flags, mask| {
            if EqualSid(entry_sid, sid).is_err() {
                return;
            }
            let plain_allow = ace_type == ACCESS_ALLOWED_ACE_TYPE;
            let acc = found.get_or_insert(ExplicitAce {
                mask: 0,
                allow_mask: 0,
                inherit: 0,
                foreign_shape: false,
            });
            acc.mask |= mask;
            if plain_allow {
                acc.allow_mask |= mask;
            } else {
                acc.foreign_shape = true;
            }
            acc.inherit |= flags & ((OBJECT_INHERIT_ACE.0 | CONTAINER_INHERIT_ACE.0) as u8);
        })
        .map_err(to_err)?;
    }
    Ok(found)
}

/// [BUG-020の修正] `dacl`から`sids`のいずれかに一致するAllow/Deny ACEを取り除いた新しいDACLを、
/// 対象外のACEは`GetAce`で読んだ生バイト列のまま`AddAce`でコピーして構築する（trustee・
/// access mask・`AceFlags`——`INHERITED_ACE`を含め——を一切変更しない）。
///
/// **なぜ`SetEntriesInAclW`の`REVOKE_ACCESS`を使わないか**: `REVOKE_ACCESS`は`INHERITED_ACE`
/// フラグ付きのACEを取り除かない（Win32の仕様——継承ACEは継承元でしか正しく取り消せないという
/// 設計）。旧実装はこれを回避するため、`PROTECTED_DACL_SECURITY_INFORMATION`でノード全体を
/// 「凍結」（全ACEを明示化し継承を遮断）してから`REVOKE_ACCESS`をかけていた。しかしこの凍結は
/// 対象`sid`と無関係な他trusteeのACEも含めてノードを継承から永久に切り離す副作用があり、
/// `revoke_ace_recursive`が対象ツリー全体の継承を破壊するバグ（BUG-020、docs/bugs/BUG-020.md）
/// を引き起こした。ここではACEを1件ずつ生のまま読み対象`sids`以外はそのままコピーするため、
/// `INHERITED_ACE`フラグの有無に関わらず対象だけを正確に取り除ける。DACLの保護状態
/// （`SE_DACL_PROTECTED`）はこの関数の外で呼び出し側が読み取り・維持する（`revoke_ace`参照）。
///
/// Allow/Deny以外のACE種別（このコードベースが自ら書き込むことはない）は
/// trusteeを解釈せず常に保持する（未知の種別を誤って消さない安全側の判断）。
///
/// 戻り値の`usize`は実際に取り除いたACE件数。**呼び出し側はこれが0なら書込そのものを
/// 省略できる**（[BUG-082](../../../../docs/bugs/BUG-082.md)）——`revoke_ace_unguarded`は
/// 対象SIDが1本も無いノードで高価な`CreateFileW(WRITE_DAC)`＋`SetKernelObjectSecurity`を
/// 省くためにこれを使う。ただし`remove_sid_aces_and_protect`のように書込の目的がACE除去では
/// なく`SE_DACL_PROTECTED`の設定にある場合は、0件でも書込を省略してはならない
/// （呼び出し側ごとに判断する。この関数自体は判断を持たない）。
unsafe fn copy_dacl_excluding_sids(
    dacl: *const ACL,
    sids: &[PSID],
    buf: &mut Vec<u8>,
) -> windows::core::Result<(*mut ACL, usize)> {
    unsafe {
        let mut size_info = ACL_SIZE_INFORMATION::default();
        GetAclInformation(
            dacl,
            &mut size_info as *mut _ as *mut c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )?;

        // 除外は縮む方向にしか働かないため、既存ACLと同じ容量を確保すれば必ず収まる。
        let buf_size = (size_info.AclBytesInUse + size_info.AclBytesFree)
            .max(std::mem::size_of::<ACL>() as u32 + 64);
        buf.resize(buf_size as usize, 0u8);
        let new_dacl = buf.as_mut_ptr() as *mut ACL;
        InitializeAcl(new_dacl, buf_size, ACL_REVISION)?;

        let mut removed = 0usize;
        for i in 0..size_info.AceCount {
            let mut ace_ptr: *mut c_void = std::ptr::null_mut();
            GetAce(dacl, i, &mut ace_ptr)?;
            let header = &*(ace_ptr as *const ACE_HEADER);

            let is_target = if header.AceType == ACCESS_ALLOWED_ACE_TYPE
                || header.AceType == ACCESS_DENIED_ACE_TYPE
            {
                // ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE share the Mask/SidStart layout.
                let allowed = &*(ace_ptr as *const ACCESS_ALLOWED_ACE);
                let entry_sid = PSID((&allowed.SidStart) as *const u32 as *mut c_void);
                sids.iter().any(|&sid| EqualSid(entry_sid, sid).is_ok())
            } else {
                false
            };

            if is_target {
                removed += 1;
            } else {
                AddAce(
                    new_dacl,
                    ACL_REVISION,
                    u32::MAX, // MAXDWORD相当: 末尾へ追加し既存の並び順を保つ。
                    ace_ptr as *const c_void,
                    header.AceSize as u32,
                )?;
            }
        }

        Ok((new_dacl, removed))
    }
}

/// `set_dacl_single_object`の亜種。DACLの内容に加え、`SE_DACL_PROTECTED`（継承を受け付ける
/// かどうか）も明示的に指定する。`grant_ace_mask`用の`set_dacl_single_object`は意図的に
/// この状態へ触れない（呼び出し元が継承の有無を問わないため）が、`revoke_ace`は「対象sidを
/// 取り除いた後、ノードの継承状態を呼び出し前と同じに保つ」ために必要とする。
///
/// **[BUG-083の修正] 保護状態はセキュリティ記述子自身の制御ビットで宣言する。**
/// `SetKernelObjectSecurity`（＝`NtSetSecurityObject`）は`SECURITY_INFORMATION`引数の
/// `PROTECTED_DACL_SECURITY_INFORMATION`／`UNPROTECTED_DACL_SECURITY_INFORMATION`修飾子を
/// **無視する**——同じ情報を渡す口が2つあり、どちらが効くかは呼ぶ関数で違う。aclapi
/// （`SetNamedSecurityInfoW`）は修飾子を解釈するが、カーネル経路は解釈せずSDのControlだけを見る。
/// 修飾子だけを渡していた旧実装では`SE_DACL_PROTECTED`が一度も立たず、D-05/D-09が意図する
/// `.harness/**`の継承遮断が実機で機能していなかった
/// （[BUG-083](../../../../docs/bugs/BUG-083.md)、6経路の比較実測は
/// `dacl_protection_probe_tests.rs`）。
///
/// 書込APIは`SetKernelObjectSecurity`のままにしてある。aclapiでも保護は立つが、それは
/// BUG-011/013のハング（ツリー走査と継承の自動再計算）を招く経路であり、**保護のために
/// aclapiへ戻す必要は無い**ことが同じ実測で分かっている。
unsafe fn set_dacl_single_object_with_protection(
    path: &Path,
    new_dacl: *mut ACL,
    protected: bool,
) -> windows::core::Result<()> {
    unsafe {
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
            // [BUG-083] 実際に効くのはこちら。両方向を明示するのは、`protected=false`の
            // 「保護を外す／外れたままにする」も`revoke_sids_from_node`が依存する契約だからである
            // （`InitializeSecurityDescriptor`直後はたまたま0だが、それに寄りかからない）。
            SetSecurityDescriptorControl(
                sd_ptr,
                SE_DACL_PROTECTED,
                if protected {
                    SE_DACL_PROTECTED
                } else {
                    SECURITY_DESCRIPTOR_CONTROL(0)
                },
            )?;
            // 修飾子は無視されるが、意図の表明として残す（読み手に「保護を書いている」と伝わる）。
            let protection_flag = if protected {
                PROTECTED_DACL_SECURITY_INFORMATION
            } else {
                UNPROTECTED_DACL_SECURITY_INFORMATION
            };
            SetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION | protection_flag, sd_ptr)
        })();

        let _ = CloseHandle(handle);
        result
    }
}

/// `path`のDACL制御ビット（`SECURITY_DESCRIPTOR_CONTROL`）を読む。
///
/// [`dacl_is_protected`]・[`unprotect_harness_control_dir`]・BUG-083のプローブが共有する。
/// `revoke_sids_from_node`だけは既に`GetNamedSecurityInfoW`のSDを手元に持っているので、
/// 読取を二重にしないため`GetSecurityDescriptorControl`を直接呼んでいる。
pub(crate) fn dacl_control(path: &Path) -> windows::core::Result<u16> {
    unsafe {
        let path_w = long_path_wide(path);
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

        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        let result = GetSecurityDescriptorControl(sd, &mut control, &mut revision);
        let _ = LocalFree(HLOCAL(sd.0));
        result?;
        Ok(control)
    }
}

/// `path`のDACLが`SE_DACL_PROTECTED`（祖先からの継承を受け付けない状態）かどうか。
///
/// [BUG-083](../../../../docs/bugs/BUG-083.md)の修正以降、`.harness/**`はこれが`true`である
/// ことが期待される不変条件になった。**「サンドボックスから書けない」の根拠そのものではない**
/// （それはACEが物理的に無いこと）が、以後の再伝播を止める第1の防御である。
/// [BUG-084] 本番経路はノードの消失を許容する必要があるので[`dacl_protection_state`]を使う。
/// **こちらはテスト用**——「保護が立っているか」を二値で断言したいテストのための薄いラッパで、
/// 消えていたら（測定が成立していないので）`Err`にする。
#[cfg(test)]
pub(crate) fn dacl_is_protected(path: &Path) -> Result<bool, AppContainerError> {
    dacl_protection_state(path)?.ok_or_else(|| AppContainerError::AclRevoke {
        path: path.to_path_buf(),
        reason: "the node vanished while reading its DACL protection state".to_string(),
    })
}

/// [`dacl_is_protected`]の、**ノードが消えていることを許容する**版（BUG-084）。
/// `None`は「walkで見つけてから読むまでの間に消えた」ことだけを意味する（[`is_vanished`]）。
fn dacl_protection_state(path: &Path) -> Result<Option<bool>, AppContainerError> {
    match dacl_control(path) {
        Ok(control) => Ok(Some(control & SE_DACL_PROTECTED.0 != 0)),
        Err(e) if is_vanished(&e) => Ok(None),
        Err(e) => Err(AppContainerError::AclRevoke {
            path: path.to_path_buf(),
            reason: e.to_string(),
        }),
    }
}

/// Win32のエラーが「対象がもう存在しない」ものか（[BUG-084](../../../../docs/bugs/BUG-084.md)）。
///
/// `.harness/`の保護はwalkで集めたノードへ後から適用するので、集めてから触るまでの間に
/// 消えることがある（harness自身が`.harness/`へ書いている最中に背景スレッドから走る）。
/// 消えたノードは**保護する対象が無い**のであって失敗ではない。
fn is_vanished(e: &windows::core::Error) -> bool {
    e.code() == ERROR_FILE_NOT_FOUND.to_hresult() || e.code() == ERROR_PATH_NOT_FOUND.to_hresult()
}

/// `path`から`sid`宛のACEを剥がし、DACLの継承を切る。
///
/// 戻り値は**このノードが保護された状態になったか**。`false`は「walkで見つけてから触るまでの
/// 間に消えた」ことだけを意味する（[`is_vanished`]）。エラーは`Err`のままで、握り潰さない。
fn remove_sid_aces_and_protect(path: &Path, sid: PSID) -> Result<bool, AppContainerError> {
    let to_err = |e: windows::core::Error| AppContainerError::AclGrant {
        path: path.to_path_buf(),
        reason: e.to_string(),
    };
    unsafe {
        let path_w = long_path_wide(path);
        let mut existing_dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        if let Err(e) = GetNamedSecurityInfoW(
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
        {
            return if is_vanished(&e) {
                Ok(false)
            } else {
                Err(to_err(e))
            };
        }

        let mut new_buf: Vec<u8> = Vec::new();
        let (new_dacl, removed) =
            match copy_dacl_excluding_sids(existing_dacl as *const _, &[sid], &mut new_buf) {
                Ok(result) => result,
                Err(e) => {
                    let _ = LocalFree(HLOCAL(sd.0));
                    return Err(to_err(e));
                }
            };
        // 保護済みかは、既に手元にあるSDから読む（`dacl_is_protected`を呼ぶと同じノードを
        // もう一度`GetNamedSecurityInfoW`することになる）。
        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        let control_result = GetSecurityDescriptorControl(sd, &mut control, &mut revision);
        let _ = LocalFree(HLOCAL(sd.0));
        control_result.map_err(to_err)?;

        // [BUG-082と同型の冪等スキップ、BUG-083の修正で初めて成立] 剥がすACEが1本も無く、かつ
        // 既に保護済みなら、このノードに対してこの関数がすることは何も無い。書込を省いて
        // 高価な`CreateFileW(WRITE_DAC)`＋`SetKernelObjectSecurity`を避ける。
        // **保護が立たなかった頃はこの判定が常に偽で、毎起動・全ノードを書き直していた。**
        // 保護は`preflight`の同期区間と`grant_job`のフェーズ0.5の2回掛かるので効きは大きい。
        if removed == 0 && control & SE_DACL_PROTECTED.0 != 0 {
            return Ok(true);
        }

        // `new_dacl`は`new_buf`（このスコープで生きている自前バッファ）の中を指す。上の
        // `LocalFree`が解放したのは読取用SD（コピー元）なので、書き戻しにはそのまま使える。
        match set_dacl_single_object_with_protection(path, new_dacl, true) {
            Ok(()) => Ok(true),
            Err(e) if is_vanished(&e) => Ok(false),
            Err(e) => Err(to_err(e)),
        }
    }
}

/// `.harness/**`（制御面）をサンドボックスから隔離する（D-05/D-09の層3）。各ノードから
/// `sids`宛のACEを全て取り除いたうえで、DACLの継承を切る（`PROTECTED_DACL_SECURITY_INFORMATION`）。
/// 継承を切るのは、workspace rootに載せた継承ACEがここへ降りてくるのを止めるためである。
///
/// **`sids`が複数なのはD-54の帰結**である。workspaceツリーのACEはworkspace＋モード単位の
/// capability SID宛になったので、`.harness/`へ降りてくる主体もそれになる。一方、過去の
/// セッションがpackage SID宛に付けたACEも実マシンには残り得る（D-37時代の残骸）。**どちらか
/// 一方だけを剥がすと、剥がし残した側から制御面が書ける**ので、両方を渡して剥がす。
/// **戻り値は実際に保護した状態にできたノード数**（[BUG-084](../../../../docs/bugs/BUG-084.md)）。
/// 姉妹関数[`unprotect_harness_control_dir`]が解除件数を返すのと対称にしてある——D-05/D-09の
/// 層3は「掛けたつもりで1件も掛かっていない」が症状として出ない機構なので（[BUG-083]は
/// まさにそれがこの実機で恒常的に起きていた）、掛けた側にも件数の裏取り手段が要る。
pub(crate) fn protect_harness_control_dir_from_appcontainer(
    workspace_root: &Path,
    sids: &[PSID],
) -> Result<usize, AppContainerError> {
    let harness_dir = workspace_root.join(".harness");
    // 剥がす主体が空なら保護は1件も掛からない。「全ノード保護済み」と数えないための番兵
    // （呼び出し側は常に1つ以上渡すが、件数を返す関数が嘘をつく余地は残さない）。
    if sids.is_empty() || !harness_dir.exists() {
        return Ok(0);
    }

    let mut dirs = Vec::new();
    let mut files = Vec::new();
    // [BUG-084] `OnVanished::Skip`。ツリーの一部が消えているのは実運用で普通に起こる
    // ——`grant_job`の背景フェーズ0.5からここが呼ばれる間、harness自身が`.harness/`へ
    // 書いている（セッションJSONL・ログ・cognition scratch）し、ユーザーがharness実行中に
    // リポジトリを消すこともあれば、`preflight`を呼ぶ実機テストが一時ディレクトリを畳むことも
    // ある。**打ち切ってはいけない**——消えた1ノードのために残り全部が未保護のまま
    // 「保護済み」として返っていたのがBUG-084である。**`Err`にするのも駄目**で、
    // `wait_until_done`はプロセス内の全ジョブを待つ設計なので、消えたworkspace1つの
    // エラーが無関係なworkspaceの待ち手まで巻き添えで失敗させる。
    collect_dirs_and_files(&harness_dir, &mut dirs, &mut files, OnVanished::Skip).map_err(|e| {
        AppContainerError::AclGrant {
            path: harness_dir.clone(),
            reason: e.to_string(),
        }
    })?;

    // 走査順（files → `dirs.rev()`、＝葉から根へ）は保護をかける側の既定の向きで、
    // 解除側（[`unprotect_harness_control_dir`]、根から葉へ）と逆。ノードを外側・SIDを内側に
    // したのは件数を1ノード1回で数えるためで、`remove_sid_aces_and_protect`は毎回DACLを
    // 読み直すので、SIDを外側に回していた旧実装と最終状態は同じである。
    let mut protected = 0usize;
    for node in files.iter().chain(dirs.iter().rev()) {
        let mut node_protected = true;
        for sid in sids {
            node_protected =
                remove_sid_aces_and_protect(node, *sid).map_err(explain_control_plane_failure)?;
            // 消えたノードは以降のSIDでも同じなので、残りは試さない。
            if !node_protected {
                break;
            }
        }
        if node_protected {
            protected += 1;
        }
    }
    Ok(protected)
}

/// 制御面の保護に失敗したノードへ、**分かっている原因と回復手段**を添える
/// （[BUG-109](../../../../docs/bugs/BUG-109.md)）。
///
/// この失敗の既知の原因は1つだけである——**そのノードを昇格した収集器
/// （`harness-policy-learnd.exe`）が作った**場合、所有者が`BUILTIN\Administrators`になり、
/// 非昇格のharnessは`WRITE_DAC`を持たない（継承ACEが与えるのはModifyまで）。
/// `.harness/**`は1ノードでも保護できなければ制御面がAppContainerから隔離できず、
/// Tier2aはfail-closedで中止する。
///
/// **原因をエラー文字列の綴りから当てない**（B-33: 他人が出した文言はロケールで変わる）。
/// ここは「どのノードで失敗したか」という自分の知っている事実だけを足し、
/// 「UACを断ったのだろう」という**測っていない推測はしない**（B-32）。
fn explain_control_plane_failure(e: AppContainerError) -> AppContainerError {
    let AppContainerError::AclGrant { path, reason } = e else {
        return e;
    };
    AppContainerError::AclGrant {
        path: path.clone(),
        reason: format!(
            "{reason} -- this is a control-plane node under .harness/ and it could not be \
             re-secured. If it was created by the elevated collector it is owned by \
             Administrators, and this (non-elevated) process cannot write its DACL; delete it \
             or take ownership of it, then retry (see docs/bugs/BUG-109.md)"
        ),
    }
}

/// [BUG-083] [`protect_harness_control_dir_from_appcontainer`]が立てた継承遮断
/// （`SE_DACL_PROTECTED`）を`.harness/**`から落とし、ユーザーのリポジトリを
/// harnessが触る前の状態へ戻す。戻り値は実際に解除したノード数。
///
/// **なぜ専用の巻き戻し経路が要るのか**: 保護はACEと違って「このワークスペースを二度と
/// harnessで使わない」と決めても自動では消えない。`.harness/**`が継承から切り離されたままだと、
/// ユーザーが後からリポジトリのルートへ権限を足しても制御面だけ反映されない、という
/// **消せない恒久変更**を実マシンに残すことになる。`harness fs revoke-workspace`が
/// ACEを撤収した後にこれを呼ぶ（`crates/harness-cli/src/fs_grants/workspace.rs`）。
///
/// **解除はaclapi（`SetNamedSecurityInfoW`）で行う。** ここは`set_dacl_single_object_with_protection`
/// （制御ビットを落とすだけ）ではなく、**Windowsに継承を計算し直させたい**場面である
/// ——保護を外すだけでは祖先の継承ACEは戻ってこず、次に誰かが親へ伝播書込をするまで
/// 中途半端な状態が続く。BUG-011/013の伝播コストが問題にならないのは対象が`.harness/`配下
/// だけだからで（実機で24ノード、aclapi 1回あたり実測0.3ms程度）、**他のツリーへこの形を
/// 広げてはいけない**。
///
/// **順序は上から下**（`collect_dirs_and_files`が返す`dirs`は前順なのでそのまま、`files`は最後）。
/// 親の継承ACEが復元されてから子を解除しないと、子が受け取るべき継承ACEがまだ親に無い。
/// 保護をかける側（files→`dirs.rev()`）とは逆向きである。
pub fn unprotect_harness_control_dir(workspace_root: &Path) -> Result<usize, AppContainerError> {
    let harness_dir = workspace_root.join(".harness");
    if !harness_dir.exists() {
        return Ok(0);
    }

    let mut dirs = Vec::new();
    let mut files = Vec::new();
    collect_dirs_and_files(&harness_dir, &mut dirs, &mut files, OnVanished::Skip).map_err(|e| {
        AppContainerError::AclRevoke {
            path: harness_dir.clone(),
            reason: e.to_string(),
        }
    })?;

    let mut unprotected = 0usize;
    for node in dirs.iter().chain(files.iter()) {
        // 保護されていないノードは触らない——ユーザーが自分で保護したノードを巻き込んで
        // 継承を復活させないため、ではなく（それは区別できない）、無駄なaclapi呼び出しを
        // 避けるため。`.harness/`配下という限定されたツリーなので、ここに居る保護は
        // 実質このコードが立てたものである。
        //
        // [BUG-084] 消えたノードは飛ばす。walkが`OnVanished::Skip`で消失を許容する以上、
        // **集めてから触るまでの間に消えた**場合もここで許容しないと、掛ける側とだけ
        // 対称性が崩れる（掛ける側は`remove_sid_aces_and_protect`が`Ok(false)`を返す）。
        match dacl_protection_state(node)? {
            None | Some(false) => continue,
            Some(true) => {}
        }
        if unprotect_dacl_restoring_inheritance(node)? {
            unprotected += 1;
        }
    }
    Ok(unprotected)
}

/// `path`の`SE_DACL_PROTECTED`を落とし、祖先からの継承ACEをOSに計算し直させる
/// （[`unprotect_harness_control_dir`]の1ノード分）。
///
/// 戻り値は**解除できたか**。`false`は「触る前に消えていた」ことだけを意味する
/// （BUG-084、[`is_vanished`]）。
fn unprotect_dacl_restoring_inheritance(path: &Path) -> Result<bool, AppContainerError> {
    let to_err = |e: windows::core::Error| AppContainerError::AclRevoke {
        path: path.to_path_buf(),
        reason: e.to_string(),
    };
    unsafe {
        let path_w = long_path_wide(path);
        let mut existing_dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        if let Err(e) = GetNamedSecurityInfoW(
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
        {
            return if is_vanished(&e) {
                Ok(false)
            } else {
                Err(to_err(e))
            };
        }

        // 現在のDACLをそのまま渡し、`UNPROTECTED_…`で「継承を受け付ける状態へ戻せ」とだけ言う。
        // aclapiは保護中に凍結されていたACEと、祖先から降りてくるべきACEを突き合わせて
        // 正規化する（`pDacl=NULL`は「DACL無し＝誰でもフルコントロール」になるので**渡さない**
        // ——`test_support::protect_dacl_preserve_inherited`のdocに記録した事故と同じ罠）。
        let result = SetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(existing_dacl as *const _),
            None,
        )
        .ok();

        let _ = LocalFree(HLOCAL(sd.0));
        match result {
            Ok(()) => Ok(true),
            Err(e) if is_vanished(&e) => Ok(false),
            Err(e) => Err(to_err(e)),
        }
    }
}

/// `path`のDACLから、`sid`（trustee）に対する既存ACEを全て取り除く。元は
/// `TIER1A-OPEN-ISSUES.md`課題1のプロファイルtraverse実験（Experiment B）専用の後始末
/// ヘルパだったが、D-13のfs passthrough撤収機構（`fs revoke`）向けに本番昇格した
/// （`revoke_ace_recursive`から使う）。`grant_ace_mask`と対になる。単一ノードのみを対象とする
/// 非再帰の操作であり、`grant_traverse_drive_root`（同じく非再帰・単一ACE）の巻き戻し
/// （`harness fs revoke-traverse`）にもそのまま使う。
///
/// [BUG-020修正] `copy_dacl_excluding_sid`でACEを生のまま読み対象sidだけを除去するため、
/// 継承由来（`INHERITED_ACE`）かどうかを問わず正確に取り除ける。ノードの継承状態
/// （`SE_DACL_PROTECTED`）は呼び出し前後で変更しない（このノードが元々継承を受けていなければ
/// 書き戻し後も受けない、元々継承を受けていれば書き戻し後も受け続ける——ユーザーが独自に
/// 設定した保護状態を巻き込んで変更しない）。
/// D-37: セッションが付けたACEを1件撤収する（`session_profile`の回収経路が注入する処理）。
///
/// プロファイル名からSIDを導出して剥がし、ついでにworkspace一覧台帳からも消す。
/// `session_profile`側はACL APIを知らない（規則3の分割線）ので、その具体をここが持つ。
/// preflightの起動時GCと、CLIのセッション終了時撤収の**両方がこの1本を使う**。
///
/// [BUG-103] **剥がせなかったノードを返す**（`session_profile::RevokeLeftovers`）。かつては
/// `let _ = revoke_ace_recursive(...)`で捨てており、`%TEMP%`のような共有ツリーで1件も
/// 剥がせなくても呼び出し側には成功と同じに見えていた。ここはセッション終了時の
/// **唯一の撤収経路**なので、捨てた瞬間に孤立ACEの発生が観測不能になる（B-09）。
///
/// SIDを導出できないとき（プロファイルが既に消えている等）も**空ではなく理由を返す**——
/// 「剥がすものが無かった」と「剥がしに行けなかった」を同じ値にしない（B-10）。
pub fn revoke_session_grant(
    path: &Path,
    profile_name: &str,
) -> crate::tier2a::session_profile::RevokeLeftovers {
    // [BUG-101] 撤収は`ensure_profile`（＝存在しなければ`CreateAppContainerProfile`で作る）を
    // 呼ばない。剥がしに来た関数がOSの資源を作るのは筋が通らないし、削除済みプロファイルを
    // 復活させる。SIDの導出は名前のハッシュから決まるので、登録の有無に依らず同じ値になる。
    let sid = match derive_profile_sid(profile_name) {
        Ok(sid) => sid,
        Err(e) => {
            return vec![(
                path.to_path_buf(),
                format!("cannot derive the SID of {profile_name}: {e}"),
            )]
        }
    };
    let leftovers = match revoke_ace_recursive(path, sid.as_psid()) {
        Ok(report) => report.blocked,
        // rootにすら触れなかった＝このツリーからは1件も剥がせていない。
        Err(e) => vec![(path.to_path_buf(), e.to_string())],
    };
    crate::tier2a::workspace_ledger::remove_workspace_entry(path);
    leftovers
}

// `appcontainer_sid_aces`（パスのDACLに載っているパッケージSIDの列挙）と
// `revoke_stale_appcontainer_aces`（残す側を名指しして他を剥がす）は`revoke_subjects`へ移した。
// 「どのSIDを剥がすか」を決める責務であって「どう剥がすか」ではないため（規則3の分割線）。

/// 祖先traverseの主体（`traverse_capability_sid`）のバイト列を1回だけ導出してキャッシュする。
///
/// `revoke_ace`はツリー全ノードで通る経路なので、ここで`DeriveCapabilitySidsFromName`を
/// 毎回叩くわけにはいかない。導出に失敗した場合（あり得ないが）は`None`を持ち、ガードを
/// 素通りさせる——**判定材料が無いときに撤収を止めると、正当な`fs revoke`まで巻き添えで
/// 失敗する**ので、ここは開ける側へ倒す（境界そのものではなく事故防止のガードであるため）。
fn cached_traverse_capability_sid() -> Option<&'static crate::win_common::OwnedSid> {
    static SID: std::sync::OnceLock<Option<crate::win_common::OwnedSid>> =
        std::sync::OnceLock::new();
    SID.get_or_init(|| traverse_capability_sid().ok()).as_ref()
}

fn is_traverse_capability_sid(sid: PSID) -> bool {
    match cached_traverse_capability_sid() {
        Some(cap) => unsafe { EqualSid(cap.as_psid(), sid).is_ok() },
        None => false,
    }
}

/// [D-48] `path`のtraverse ACEが「traverse台帳に載った永続的な修復」かどうか。
///
/// [BUG-046](../../../../docs/bugs/BUG-046.md): 付与側`grant_ace_mask`には冪等スキップが
/// あり、要求マスクが既存ACEの部分集合なら**何も書かない**。一方この撤収側は所有権の概念を
/// 持たず、誰が付けたACEでも同じように消せる。この非対称のせいで「grantがno-op・revokeだけ
/// 有効」となり、テストが`C:\`の永続ACEを純減させてマシン全体のTier2a FS I/Oを壊した。
fn is_protected_traverse_grant(path: &Path, sid: PSID) -> bool {
    is_traverse_capability_sid(sid)
        && crate::tier2a::traverse_ledger::is_recorded_traverse_node(path)
}

/// `path`のDACLから`sid`宛の明示ACEを取り除く（D-48のガード付き、通常はこちらを使う）。
///
/// traverse台帳に載ったノードの**capability SID宛ACE**だけは剥がさず`Err`を返す。巻き戻したい
/// ときは名前の付いた扉[`revoke_traverse_grant`]（＝`harness fs revoke-traverse <path>`）を通ること。
/// 「汎用APIでは触れない／名指しの関数でだけ触れる」という非対称が目的で、悪意ある呼び出しを
/// 止めるためのものではない——**更新漏れの巻き添えを止める**ためのものである。
pub fn revoke_ace(path: &Path, sid: PSID) -> Result<(), AppContainerError> {
    revoke_ace_reporting(path, sid).map(|_rewrote| ())
}

/// [`revoke_ace`]の実体。**剥がして書き戻したか**を返す（[`RevokeReport`]の`rewritten`が
/// 「触った数」ではなく「実際に変わった数」であるために要る）。判定と文面は1箇所に保つ。
fn revoke_ace_reporting(path: &Path, sid: PSID) -> Result<bool, AppContainerError> {
    if is_protected_traverse_grant(path, sid) {
        return Err(AppContainerError::AclRevoke {
            path: path.to_path_buf(),
            reason: format!(
                "refusing to strip the persistent traverse ACE on {} (D-48): this node is \
                 recorded in the traverse ledger, so its capability-SID ACE is a permanent \
                 repair that Tier2a FS I/O depends on machine-wide. Use `harness fs \
                 revoke-traverse <path>` (win_appcontainer::revoke_traverse_grant) if you really \
                 mean to roll it back. See docs/bugs/BUG-046.md",
                path.display()
            ),
        });
    }
    revoke_sids_from_node(path, &[sid])
}

/// [`revoke_ace`]の実体（D-48のガードを通らない）。**このモジュールと
/// [`revoke_traverse_grant`]以外から呼ばないこと。**
///
/// D-48ガードを一切かけない生のプリミティブである。ガードは[`revoke_ace`]（このモジュール内の
/// 通常経路）と[`revoke_workspace_sids_recursive`]（workspace一括撤収）がそれぞれ**自分の
/// 呼び出し方に合わせて**外側でかける——`revoke_traverse_grant`がここを直接呼ぶのは
/// 「台帳に載った永続traverse ACEを意図的に剥がす唯一の正規の扉」だからで、ここへガードを
/// 埋め込むとその扉自体が機能しなくなる。
pub(crate) fn revoke_ace_unguarded(path: &Path, sid: PSID) -> Result<(), AppContainerError> {
    revoke_sids_from_node(path, &[sid]).map(|_rewrote| ())
}

/// [BUG-082] 1ノードから`sids`の全てを**DACL読取1回・（変更があれば）書込1回**で剥がす。
/// D-48ガードは持たない生のプリミティブ（呼び出し側がガードするかを決める、
/// [`revoke_ace_unguarded`]のdoc参照）。
///
/// [残課題#32] **付与側（[`super::acl_dacl_write::propagate_merged_dacl`]）もここを使う。**
/// 伝播する書込は「その主体のACEが既にそのノードに在る」と既存の子孫へ届かないので、
/// 書く直前に同じ主体を外す必要がある。撤収のための関数を付与側が呼ぶのは一見ちぐはぐだが、
/// **同じ「1ノードから指定主体のACEを外す」操作を2つ実装しない**ためである
/// （`docs/CODE-STRUCTURE-RULES.md`規則5）。
///
/// 戻り値は実際に書込を行ったか（＝1本以上のACEを剥がしたか）。0件なら`false`を返し、
/// 高価な`CreateFileW(WRITE_DAC)`＋`SetKernelObjectSecurity`を呼ばない
/// （`copy_dacl_excluding_sids`のdoc参照）。
///
/// [BUG-103] **触る前に消えていたノードは`Ok(false)`**（剥がす先が無いので失敗ではない）。
/// [`remove_sid_aces_and_protect`]が既に同じ判定を持っており、そちらと同じ[`is_vanished`]を
/// 通す。ここを`Err`にすると、`%TEMP%`のように揺れ動くツリーの撤収で
/// [`RevokeReport::blocked`]が「消えただけのノード」で埋まり、**本当に剥がせなかったものが
/// 埋もれる**（B-09: 数える対象を混ぜない）。
pub(crate) fn revoke_sids_from_node(
    path: &Path,
    sids: &[PSID],
) -> Result<bool, AppContainerError> {
    let to_err = |e: windows::core::Error| AppContainerError::AclRevoke {
        path: path.to_path_buf(),
        reason: e.to_string(),
    };
    unsafe {
        let path_w = long_path_wide(path);
        let mut existing_dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        if let Err(e) = GetNamedSecurityInfoW(
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
        {
            return if is_vanished(&e) {
                Ok(false)
            } else {
                Err(to_err(e))
            };
        }

        let mut new_buf: Vec<u8> = Vec::new();
        let (new_dacl, removed) =
            match copy_dacl_excluding_sids(existing_dacl as *const _, sids, &mut new_buf) {
                Ok(result) => result,
                Err(e) => {
                    let _ = LocalFree(HLOCAL(sd.0));
                    return Err(to_err(e));
                }
            };

        if removed == 0 {
            // [BUG-082] 対象sidのACEが1本も無いノード。読取だけで済ませ、書込を省略する。
            let _ = LocalFree(HLOCAL(sd.0));
            return Ok(false);
        }

        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        let control_result = GetSecurityDescriptorControl(sd, &mut control, &mut revision);
        let _ = LocalFree(HLOCAL(sd.0));
        control_result.map_err(to_err)?;
        let was_protected = control & SE_DACL_PROTECTED.0 != 0;

        set_dacl_single_object_with_protection(path, new_dacl, was_protected).map_err(to_err)?;
    }
    Ok(true)
}

/// [BUG-103] 撤収1回分の結果。**件数と「剥がせなかったノード」を返す**。
///
/// 姉妹の[`RevokeWorkspaceReport`]は最初から件数を返していたのに、[`revoke_ace_recursive`]だけが
/// `Result<(), _>`だった。この非対称のせいで「1件も剥がせなかった」が呼び出し側から見えず
/// （本体の呼び出し3箇所は全部`let _ =`だった）、実マシンに`(OI)(CI)(R,W,D)`が残り続けた（B-09）。
#[derive(Debug, Default)]
#[must_use]
pub struct RevokeReport {
    /// 撤収を試みたノード数（rootを含む）。
    pub checked: usize,
    /// 実際にACEを1本以上剥がして書き戻したノード数。
    pub rewritten: usize,
    /// **剥がせなかったノードと理由。** `WRITE_DAC`が無い（他アカウント所有・保護DACL）、
    /// D-48で保護されている等。空でなければ、そのノードにはACEが残っている。
    pub blocked: Vec<(std::path::PathBuf, String)>,
}

impl RevokeReport {
    /// 1件でも剥がし残したか。
    pub fn has_blocked(&self) -> bool {
        !self.blocked.is_empty()
    }

    /// 残件の要約（先頭数件を名指しする）。**名前を出さないと`icacls`で追えない**（B-09）。
    pub fn blocked_summary(&self, limit: usize) -> Option<String> {
        if self.blocked.is_empty() {
            return None;
        }
        let mut out = format!("{} node(s) still carry the ACE: ", self.blocked.len());
        let shown: Vec<String> = self
            .blocked
            .iter()
            .take(limit)
            .map(|(path, reason)| format!("{} ({reason})", path.display()))
            .collect();
        out.push_str(&shown.join("; "));
        if self.blocked.len() > limit {
            out.push_str(&format!(" ... and {} more", self.blocked.len() - limit));
        }
        Some(out)
    }
}

/// `root`配下（`root`自身含む）から`sid`のACEを再帰的に取り除く（`grant_ace_recursive`の逆）。
/// D-13のfs passthrough撤収（`harness fs revoke`）本体。`grant_ace_recursive`と同じ
/// `collect_dirs_and_files`（symlinkスキップ済み）を使い再walkするため、付与後に増えた
/// ファイルも含めて現在のツリー全体から取り除く（決定D3: 台帳はルートのみ記録、撤収は再walk）。
///
/// **`root`がファイルのときは単一オブジェクトの撤収1件で終える**（BUG-059の撤収側）。
/// この分岐が無かった頃、`collect_dirs_and_files`の`read_dir`が`ERROR_DIRECTORY`(267)で落ちて
/// **1件も剥がさずに`Err`を返していた**。`end_session`はこの関数を通して撤収するので、
/// ファイルへ付けたACE（`--sandbox tier2a-cow`のredirector DLL・ファイル1件を指す`--fs-allow`）は
/// **台帳に正しく載っていても剥がれない**。付与側だけを直しても孤立ACEは止まらなかった、
/// というのが実機E2Eで判明した順序である（付与側=`grant_ace_inheritable_access`、
/// 記録側=`preflight`、撤収側=ここ、の3つが揃って初めて閉じる）。
///
/// # [BUG-103] 途中で止まらない・rootを先に剥がす・件数を返す
///
/// かつてこの関数は(1)walkを`OnVanished::Abort`で回し、(2)ノードごとの失敗を`?`で伝播し、
/// (3)`files`ループの後に`dirs`（rootはその先頭）を処理していた。この3つが重なると、
/// **共有ディレクトリでは1件も剥がれない**——`%TEMP%`は中身が絶えず消えるので(1)で落ち、
/// 落ちなくても実測で直下6,169件中95件が非昇格ユーザーに`WRITE_DAC`が無いので(2)で落ち、
/// どちらの場合も(3)のrootへ到達しない。実マシンに`(OI)(CI)(R,W,D)`が残った機序がこれである。
///
/// 現在は:
/// - **rootを最初に剥がす**。継承元を先に断てば、以後に作られるファイルへコピーが増えない。
///   ただし**それだけでは足りない**——既にコピーを受け取った子孫からは自動では消えないことを
///   `removing_only_the_root_ace_leaves_inherited_copies_on_descendants`が実測で固定している。
///   だからwalkは残す。
/// - walkは`OnVanished::Skip`（[`OnVanished`]自身のdocどおり、**残っているノードへ副作用を
///   適用することが目的**の経路はこちら。`Abort`は「見えた範囲が完全であること」を結論の
///   根拠に使う[`assert_no_sid_ace_recursive`]のためのものだった）。
/// - ノードごとの失敗は`?`せず[`RevokeReport::blocked`]へ集めて**続行する**。
///   `Err`を返すのは**rootにすら触れなかった**ときだけ。
pub fn revoke_ace_recursive(root: &Path, sid: PSID) -> Result<RevokeReport, AppContainerError> {
    let walk = descendants_need_walk(root, std::slice::from_ref(&sid));
    revoke_tree(root, walk, &|_, _| {}, &|path| {
        revoke_ace_reporting(path, sid)
    })
}

/// [D-63] `root`から剥がすとき、**配下まで歩く必要があるか**を実DACLから決める。
///
/// # なぜ台帳の`scope`を根拠にしないのか
///
/// 台帳は[BUG-103](../../../../docs/bugs/BUG-103.md)(d)で**サンドボックスから書ける**ことが
/// 実測されている。`scope: Object`を鵜呑みにすると、「台帳を書き換えて再帰ACEを撤収の対象外に
/// する」経路になる。D-61（撤収の主体は対象パスのDACLに実在するSIDから決める）とまったく
/// 同じ原則を、**範囲の軸にも適用する**のがこの関数である。
///
/// # 判定
///
/// 対象SIDのいずれかがrootに**継承フラグ付きの明示ACE**を持つなら歩く。継承ACEを置いた
/// 以上、配下にはコピーが降りている（rootのACEを剥がしただけでは消えないことを
/// `removing_only_the_root_ace_leaves_inherited_copies_on_descendants`が実測で固定している）。
///
/// **迷ったら歩く。** DACLを読めなかった・対象SIDの明示ACEが1本も無い（継承で降りてきた
/// コピーだけがある等）ときは`true`を返す。撤収は「狭めない」側へ倒す——歩いて何も無ければ
/// 費用を払うだけだが、歩かずに残せば**撤収経路の無いACEが残る**（B-01）。
fn descendants_need_walk(root: &Path, sids: &[PSID]) -> bool {
    for &sid in sids {
        match sid_explicit_ace(root, sid) {
            Ok(Some(ace)) if ace.is_inheritable() => return true,
            Ok(Some(_)) => {}
            // 明示ACEが無い／読めない。**歩く側へ倒す**（上のdoc参照）。
            Ok(None) | Err(_) => return true,
        }
    }
    false
}

/// [`revoke_ace_recursive`]の複数SID版。**1回のツリー走査で`sids`の全部を剥がす。**
///
/// [BUG-101] `harness fs revoke`は「撤収し得るプロファイル」をSIDへ導出して**1つずつ**
/// [`revoke_ace_recursive`]を回していた（この開発機では最大24回のツリー全walk）。実際に
/// 剥がすべき主体は「そのパスのDACLに載っているSID」なので、まとめて1回で済む——
/// ノードごとのDACL読取も1回になる（[`revoke_sids_from_node`]、BUG-082と同じ考え方）。
///
/// D-48ガードは[`revoke_sids_from_node_guarded`]がノードごとに`sids`側から除いて掛ける。
/// 単一SID版が`Err`で全体を止めるのと違い、こちらは**保護対象のSIDだけを対象から外して
/// 残りは撤収する**（バッチ全体を1件の保護で失敗させない）。
///
/// `progress`は`(処理済み, 全体)`で1000件ごとに呼ばれる（表示専用、
/// [`revoke_workspace_sids_recursive`]と同じ間隔）。
pub fn revoke_sids_recursive(
    root: &Path,
    sids: &[PSID],
    progress: &dyn Fn(usize, usize),
) -> Result<RevokeReport, AppContainerError> {
    if sids.is_empty() {
        // 対象0件。**walkもしない**——「剥がすものが無かった」ことは呼び出し側が
        // `RevokeReport::checked == 0`で見分けられる（0件と成功を同じ値にしない、B-09）。
        return Ok(RevokeReport::default());
    }
    // [D-63] 歩くかどうかは**実DACLの継承フラグ**が決める（[`descendants_need_walk`]）。
    let walk = descendants_need_walk(root, sids);
    revoke_tree(root, walk, progress, &|path| {
        revoke_sids_from_node_guarded(path, sids)
    })
}

/// [`revoke_ace_recursive`]と[`revoke_sids_recursive`]が共有するwalk本体。
/// **違うのは「1ノードで何を剥がすか」だけ**なので、そこだけを`revoke_node`で受ける
/// （`CODE-STRUCTURE-RULES` §5.0: 単一SID版と複数SID版でwalkのコピーを作らない。
/// コピーを作ると、BUG-103で直した3点——root先頭・`OnVanished::Skip`・非中断——が
/// 片方にだけ入っている状態が再び生まれる）。
///
/// `revoke_node`は「実際に剥がして書き戻したか」を返す。
///
/// [D-63] `walk_descendants`が偽なら**rootの1件だけ**を処理して返す（判定は
/// [`descendants_need_walk`]が持つ）。オブジェクト単体で付与したノードには継承ACEが無く、
/// 配下にコピーが降りている理由が存在しないためである。**この引数は呼び出し側が必ず渡す**
/// ——既定値を置くと、片方の入口だけが実DACLを見ない形が生まれる。
fn revoke_tree(
    root: &Path,
    walk_descendants: bool,
    progress: &dyn Fn(usize, usize),
    revoke_node: &dyn Fn(&Path) -> Result<bool, AppContainerError>,
) -> Result<RevokeReport, AppContainerError> {
    let mut report = RevokeReport::default();
    if root.is_file() {
        fold_node(root, revoke_node, &mut report);
        progress(1, 1);
        return Ok(report);
    }

    // **rootが先**（継承元を断つ）。ここで失敗したら撤収は成立していないので`Err`にする
    // ——呼び出し側の「rootのACEが消えたか」という権威的判定と同じ基準である。
    report.checked += 1;
    if revoke_node(root)? {
        report.rewritten += 1;
    }

    // [D-63] 継承していないACEを剥がしたのなら、配下に降りたコピーは存在しない。
    if !walk_descendants {
        progress(1, 1);
        return Ok(report);
    }

    let mut dirs = Vec::new();
    let mut files = Vec::new();
    collect_dirs_and_files(root, &mut dirs, &mut files, OnVanished::Skip).map_err(|e| {
        AppContainerError::AclRevoke {
            path: root.to_path_buf(),
            reason: e.to_string(),
        }
    })?;
    // totalが定まった時点で1回通知する（呼び出し側がスピナーから数値表示へ切り替えられる、
    // `revoke_workspace_sids_recursive`と同じ理由）。
    let total = dirs.len() + files.len();
    progress(0, total);
    let mut processed = 0usize;
    for node in files.iter().chain(dirs.iter()) {
        processed += 1;
        if processed.is_multiple_of(1000) || processed == total {
            progress(processed, total);
        }
        // rootは上で処理済み（`collect_dirs_and_files`は`dirs[0]`にrootを入れる）。
        // **`processed`からは外さない**——進捗の分母は走査したノード数である。
        if node == root {
            continue;
        }
        fold_node(node, revoke_node, &mut report);
    }
    Ok(report)
}

/// 1ノードの撤収結果を[`RevokeReport`]へ畳む。**失敗しても止めない**（呼び出し側のループが
/// 続行できるように、成否をここで分類する）。
///
/// 「walkで見つけてから触るまでの間に消えた」ノードは失敗ではない（剥がす先が無い）。
/// その判定は[`revoke_sids_from_node`]が[`is_vanished`]で型のまま行い、`Ok`で返す
/// ——エラー文面の一致で見分けるとロケールで壊れる（B-33）。
fn fold_node(
    path: &Path,
    revoke_node: &dyn Fn(&Path) -> Result<bool, AppContainerError>,
    report: &mut RevokeReport,
) {
    report.checked += 1;
    match revoke_node(path) {
        Ok(true) => report.rewritten += 1,
        // `false`は「このノードには剥がすACEが無かった」か「触る前に消えていた」。
        // どちらも失敗ではないので数えるのは`checked`だけ。
        Ok(false) => {}
        Err(e) => report.blocked.push((path.to_path_buf(), e.to_string())),
    }
}

/// [BUG-082] `fix_descendants_missing_ace`と対称の、workspace撤収専用の1walk一括撤収
/// （`harness fs revoke-workspace`本体）。
///
/// [`revoke_ace_recursive`]はSIDごとに1回ツリー全体を舐め直す。`fs revoke-workspace`は
/// workspace capability（最大2＝rwx/ro）＋撤収可能なharnessプロファイル（複数）を同じツリーから
/// 一括で剥がすため、SIDの数だけ再walkするのは無駄である。**ここではノードごとにDACLを
/// 1回だけ読み、対象の全SIDを1回の走査で除去し、変更があった場合だけ1回書き戻す。**
///
/// D-48ガード（[`is_protected_traverse_grant`]）はノードごとに`sids`側から事前に除いてから
/// [`revoke_sids_from_node`]（生のプリミティブ、ガード無し）へ渡す。実運用では
/// `fs_revoke_workspace`がtraverse capability SIDをここへ渡すことは無いが、コストは
/// `EqualSid`比較（`is_traverse_capability_sid`）が数回増えるだけで無視できるため、将来の
/// 呼び出し元が誤って含めても保護対象が守られるよう常にかけておく。
///
/// `progress`は`(処理済み, 全体)`で1000件ごとに呼ばれる（表示専用、`fix_descendants_missing_ace`
/// と同じ間隔）。
pub fn revoke_workspace_sids_recursive(
    root: &Path,
    sids: &[PSID],
    progress: &dyn Fn(usize, usize),
) -> Result<RevokeWorkspaceReport, AppContainerError> {
    if sids.is_empty() {
        return Ok(RevokeWorkspaceReport::default());
    }
    if root.is_file() {
        let rewritten = revoke_sids_from_node_guarded(root, sids)?;
        return Ok(RevokeWorkspaceReport {
            checked: 1,
            rewritten: usize::from(rewritten),
        });
    }
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    collect_dirs_and_files(root, &mut dirs, &mut files, OnVanished::Abort).map_err(|e| {
        AppContainerError::AclRevoke {
            path: root.to_path_buf(),
            reason: e.to_string(),
        }
    })?;

    let total = dirs.len() + files.len();
    let mut report = RevokeWorkspaceReport {
        checked: total,
        ..Default::default()
    };
    // `collect_dirs_and_files`（このwalk）自体はtotalが定まるまで進捗を出せない
    // （呼び出し側はここまで「不定長の作業中」としか示せない）。totalが分かった時点で
    // すぐ1回`(0, total)`を通知する——1000件未満の小さいツリーだと以後
    // `processed == total`の最後の1回しか呼ばれず、呼び出し側が「合計が分かった」ことを
    // 知る機会が完走時まで無くなるため（`harness fs revoke-workspace`のCLI進捗表示が、
    // 走査完了までスピナーから数値表示へ切り替えられない）。
    progress(0, total);
    let mut processed = 0usize;
    for node in dirs.iter().chain(files.iter()) {
        processed += 1;
        // 進捗は1000件ごと（`fix_descendants_missing_ace`と同じ間隔。1件ごとだと通知自体が
        // walkより重くなる）。
        if processed.is_multiple_of(1000) || processed == total {
            progress(processed, total);
        }
        if revoke_sids_from_node_guarded(node, sids)? {
            report.rewritten += 1;
        }
    }
    Ok(report)
}

/// [`revoke_sids_from_node`]にD-48ガードをかけた版。このノードで「保護された永続traverse付与」
/// に該当するSIDだけを除去対象から外し、残りは正しく撤収する（バッチ全体を失敗させない、
/// かつ保護対象は必ず守る——単一SID版の`revoke_ace`のように`Err`で丸ごと止めない設計）。
fn revoke_sids_from_node_guarded(path: &Path, sids: &[PSID]) -> Result<bool, AppContainerError> {
    let effective: Vec<PSID> = sids
        .iter()
        .copied()
        .filter(|&sid| !is_protected_traverse_grant(path, sid))
        .collect();
    if effective.is_empty() {
        return Ok(false);
    }
    revoke_sids_from_node(path, &effective)
}

/// [`revoke_workspace_sids_recursive`]の結果。件数だけでは「本当に走査したのか」が分からない
/// ため、`checked`（読取だけ含む全ノード数）と`rewritten`（実際にDACLを書き換えた数）を分ける
/// （`fix_descendants_missing_ace`の`DescendantFixReport`と対称）。
#[derive(Debug, Default)]
pub struct RevokeWorkspaceReport {
    /// walkが見たノード数。
    pub checked: usize,
    /// 実際にACEを1本以上剥がして書き戻した数。
    pub rewritten: usize,
}

/// `path`のDACLに`sid`（trustee）への**明示**ACEが残っていれば、その許可アクセスマスクの
/// 論理和を返す（複数エントリがあり得るため合算）。無ければ`None`。
/// `GetExplicitEntriesFromAclW`は`BuildTrusteeWithSidW`で組み立てるのと同じ`TRUSTEE_W`を
/// 返すため、`grant_ace_mask`/`revoke_ace`が使うAPIと対称な形で読み取れる
/// （`GetAce`によるACEヘッダ直接パースより低リスク）。
///
/// **継承ACEは含まない**（`GetExplicitEntriesFromAclW`の仕様）。これは撤収側にとっては
/// 正しい意味である——継承ACEはそのノードからは剥がせず、継承元でしか取り消せないため、
/// 「このノードから剥がせるものがあるか」を問う`revoke_ace`系はここを見るのが正しい。
///
/// **アクセスが届いているかを問う用途にはこれを使ってはならない**。そちらは継承経由でも
/// 届いていれば足りるので[`sid_effective_ace_mask`]を使う（[BUG-081](../../../../docs/bugs/BUG-081.md):
/// 付与側のフォールバック判定がこちらを使っていたため、継承ACEが見えず全ノードへ明示ACEを
/// 書いていた）。
pub(crate) fn sid_ace_mask(path: &Path, sid: PSID) -> Result<Option<u32>, AppContainerError> {
    Ok(sid_explicit_ace(path, sid)?.map(|ace| ace.mask))
}

/// `path`で`sid`に**実効的に**届いている許可アクセスマスク（明示ACE＋継承ACEの論理和）。
/// 届いていなければ`None`。
///
/// [`sid_ace_mask`]との違いは継承ACEを数えるかどうかだけで、この1点が
/// [BUG-081](../../../../docs/bugs/BUG-081.md)の中身である。付与側（`grant_ace_inheritable_*`の
/// 「継承が届かなかったノードだけ明示付与する」フォールバック）が`sid_ace_mask`を使っていたため、
/// rootの継承ACEが子孫へ伝播していても常に`None`と判定され、**全ノードへ明示ACEを書いていた**
/// （254,000ファイルのworkspaceで起動が60秒、かつセッションのACEがツリー全体へ残留した）。
///
/// 実装は`GetExplicitEntriesFromAclW`ではなく`GetAce`でDACLを直接列挙する
/// （[`crate::elevated_launch`]の`read_allow_aces`と同じ理由・同じ形）。**Allow ACEだけを数える**
/// ——Deny ACEは「届いている」の根拠にならない。
pub(crate) fn sid_effective_ace_mask(
    path: &Path,
    sid: PSID,
) -> Result<Option<u32>, AppContainerError> {
    let to_err = |e: windows::core::Error| AppContainerError::AclGrant {
        path: path.to_path_buf(),
        reason: e.to_string(),
    };
    unsafe {
        let path_w = long_path_wide(path);
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
        .ok()
        .map_err(to_err)?;

        // NULL DACL＝誰でもフルアクセス。付与の要否判定としては「既に届いている」で正しい
        // （ここでACEを書き足しても実効アクセスは変わらない）。
        if dacl.is_null() {
            let _ = LocalFree(HLOCAL(sd.0));
            return Ok(Some(u32::MAX));
        }

        let mut mask: Option<u32> = None;
        let count = (*dacl).AceCount as u32;
        for index in 0..count {
            let mut ace_ptr: *mut c_void = std::ptr::null_mut();
            if GetAce(dacl, index, &mut ace_ptr).is_err() || ace_ptr.is_null() {
                continue;
            }
            let header = ace_ptr as *const ACE_HEADER;
            if (*header).AceType != ACCESS_ALLOWED_ACE_TYPE {
                continue;
            }
            let ace = ace_ptr as *const ACCESS_ALLOWED_ACE;
            let ace_sid = PSID(&(*ace).SidStart as *const u32 as *mut c_void);
            if EqualSid(ace_sid, sid).is_ok() {
                mask = Some(mask.unwrap_or(0) | (*ace).Mask);
            }
        }
        let _ = LocalFree(HLOCAL(sd.0));
        Ok(mask)
    }
}

/// D4（revoke完全性の検証パス）: `root`配下を再walkし、`sid`のACEがまだ残っている全ノードを
/// 列挙する。空なら完全に撤収できたことの機械的な証拠になる（`fs revoke`が呼ぶ）。
/// ツリー外へ移動されたオブジェクトは検出できない（T-16残余、`TIER1A-OPEN-ISSUES.md`参照）。
pub fn assert_no_sid_ace_recursive(root: &Path, sid: PSID) -> Result<(), Vec<std::path::PathBuf>> {
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    // [BUG-084] 消えたノードは飛ばす（`OnVanished::Skip`）——rootごと消えていれば`dirs`も
    // `files`も空になり、下のループが何も見つけずに`Ok`＝「残存無し」になる。これは正しい
    // （ACEを載せる先が無い）。
    //
    // **それ以外のwalk失敗を`Ok`にしてはいけない。** この関数の`Ok`は「完全に撤収できた」の
    // 機械的な証拠として`revoke_passthrough`（→`fs revoke`の台帳掃除）が使うので、
    // 「確かめられなかった」を「きれいだった」と読み替えると、撤収し損ねたACEを台帳から
    // 消してしまい**二度と撤収対象に上がらなくなる**。確かめられなかったrootは残存側へ倒す。
    if collect_dirs_and_files(root, &mut dirs, &mut files, OnVanished::Skip).is_err() {
        return Err(vec![root.to_path_buf()]);
    }
    let mut remaining = Vec::new();
    for node in dirs.iter().chain(files.iter()) {
        match sid_ace_mask(node, sid) {
            Ok(Some(_)) => remaining.push(node.clone()),
            Ok(None) => {}
            Err(_) => remaining.push(node.clone()),
        }
    }
    if remaining.is_empty() {
        Ok(())
    } else {
        Err(remaining)
    }
}

/// `revoke_passthrough`の3値結果（BUG-016で記録した「revoke側の台帳残留」非対称の解消、
/// BUG-017のroot再プローブの鏡像）。台帳除去の判定を「ツリー全体成功」ではなく「rootのACEが
/// 消えたか」基準にするために導入する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// `root`配下から完全に`sid`のACEを撤収できた。
    FullyRevoked,
    /// `root`自身のACEは撤収できたが、一部の子孫（`NT SERVICE\TrustedInstaller`所有等で
    /// `WRITE_DAC`不可）にACEが残る。台帳からは除去する（残しても同じ場所で失敗し続けるため）。
    ///
    /// # [BUG-103] かつてここに書いていた正当化は**継承ACEには当たらない**
    ///
    /// 以前の文面は「grantとrevokeは同じ`WRITE_DAC`を要するため、rootが消えたのにACEが残る
    /// 子孫は元々付与もできていないノードであり、除去残しにはならない」だった。
    /// **これは明示ACEにしか成り立たない。** 付与は`(OI)(CI)`の継承ACEをrootへ1本書くだけで
    /// 済み、子孫のコピーは**Windowsが作成時に自動で載せる**——子孫の`WRITE_DAC`は要らない。
    /// つまり「こちらが書けないノード」にも実効的なACEは載り得る。
    /// `removing_only_the_root_ace_leaves_inherited_copies_on_descendants`が実測で固定した。
    ///
    /// したがってこの値は「**残っているが、このプロセスの権限では剥がせない**」を意味する。
    /// 残ったノードは[`revoke_passthrough_reporting`]が名前で返すので、呼び出し側はそれを
    /// 見せること（昇格経由の`RevokeFsAllow`なら剥がせる場合がある）。
    RootClearedDescendantsBlocked,
    /// `root`自身のACEがまだ残っている（真の失敗、または一過性で再試行の余地あり）。
    /// 台帳には残す。
    Failed,
}

/// `root`配下から`sid`のfs passthrough ACEを撤収し、**rootのACEが消えたか**を権威的に
/// 再プローブして3値で返す（BUG-016で記録した「部分適用エントリのrevoke時、rootのACEは
/// 実際に消えるのに子孫の`Err`で台帳エントリが残る」非対称の解消）。`revoke_ace_recursive`が
/// 途中の子孫で`Err`を返しても、それを最終判定に使わず`sid_ace_mask(root)`で判定する点が要。
/// forced撤収（`SeRestorePrivilege`下）で呼ぶ場合は呼び出し側が`with_restore_privilege`で囲う。
pub fn revoke_passthrough(root: &Path, sid: PSID) -> RevokeOutcome {
    revoke_passthrough_reporting(root, sid).0
}

/// [`revoke_passthrough`]に**剥がせなかったノードの名前**を添えて返す（`gc_dead_sessions`と
/// `gc_dead_sessions_reporting`の関係と同じ形）。
///
/// [BUG-103] 判定基準は変えていない——**rootの権威的な再プローブがそのまま最終判定**である。
/// 変えたのは「途中で何が起きたかを呼び出し側が見られるようにした」点だけで、
/// かつては`let _ =`で捨てていた（B-09）。`Err`は「rootにすら触れなかった」ときだけ来るので、
/// その理由も残件として返す。
pub fn revoke_passthrough_reporting(root: &Path, sid: PSID) -> (RevokeOutcome, RevokeReport) {
    // rootが既に存在しない（revoke後にユーザが削除した等）場合は、実FS上にACEを載せる
    // オブジェクトが無いので完全撤収扱いとし、台帳エントリを掃除できるようにする。
    if !root.exists() {
        return (RevokeOutcome::FullyRevoked, RevokeReport::default());
    }
    // 途中の子孫（TrustedInstaller所有等）で失敗しても、後段のroot再プローブで最終判定する。
    let report = match revoke_ace_recursive(root, sid) {
        Ok(report) => report,
        Err(e) => RevokeReport {
            checked: 1,
            blocked: vec![(root.to_path_buf(), e.to_string())],
            ..RevokeReport::default()
        },
    };
    let outcome = match sid_ace_mask(root, sid) {
        Ok(None) => match assert_no_sid_ace_recursive(root, sid) {
            Ok(()) => RevokeOutcome::FullyRevoked,
            Err(_) => RevokeOutcome::RootClearedDescendantsBlocked,
        },
        // ACEが残っている、またはrootをプローブできない（存在しない等）→台帳に残す。
        _ => RevokeOutcome::Failed,
    };
    (outcome, report)
}

/// `assert_no_sid_ace_recursive`の非再帰版。単一ノード（`path`自身）のみを検証する。
/// `grant_traverse_drive_root`のような非再帰・単一ACEの付与（`revoke_ace`で撤収する対象）は
/// ツリー全体を再walkする必要が無く、むしろ`path`がドライブルートの場合に不要な全走査を
/// 招くため、`assert_no_sid_ace_recursive`を流用せずこちらを使う（`harness fs revoke-traverse`）。
pub fn assert_no_sid_ace(path: &Path, sid: PSID) -> Result<(), AppContainerError> {
    match sid_ace_mask(path, sid)? {
        None => Ok(()),
        Some(_) => Err(AppContainerError::AclRevoke {
            path: path.to_path_buf(),
            reason: "sandbox SID ACE still present after revoke".to_string(),
        }),
    }
}
