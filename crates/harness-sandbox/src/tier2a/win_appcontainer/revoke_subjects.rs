//! 撤収の**主体**を決める層——「どのSIDのACEを剥がすか」。剥がし方（`revoke`）とは責務が別。
//!
//! # なぜこの層が要るのか（[BUG-101](../../../../docs/bugs/BUG-101.md)欠陥②）
//!
//! `harness fs revoke <path>`は、剥がす相手を**プロファイル名から導出したSID**で決めていた。
//! 最終判定に使っていたのは旧共有プロファイル（`CONTAINER_NAME`）のSID1つだけで、実際に
//! パスへ載っているのがセッション固有SIDだと**探す相手が違う**。`revoke_passthrough`は
//! 「探したSIDのACEが無かった」ときも`FullyRevoked`を返すので、**ACEを1件も剥がしていないのに
//! `revoked:`＋exit 0**になり、しかも台帳エントリだけは消えていた（実マシンの6箇所で再現）。
//!
//! ここでは向きを逆にする——**対象パスのDACLに実在するSIDを列挙し、そのうちharness由来の
//! ものを剥がす**。名前からの導出は一方向（`DeriveAppContainerSidFromAppContainerName`）なので、
//! プロファイルが削除済みのSIDは名前側からは永久に届かない。
//!
//! # harness由来かどうかの判定（順序が意味を持つ）
//!
//! | 順 | 条件 | 結果 |
//! |---|---|---|
//! | -1 | **well-knownのパッケージSID**（`ALL APPLICATION PACKAGES`等） | **絶対に触らない** |
//! | 0 | レジストリに登録があり`Moniker`がharnessでない | **絶対に触らない** |
//! | 1 | 登録があり`Moniker`がharnessで、生きている | 触らない（BUG-053） |
//! | 2 | 登録があり`Moniker`がharnessで、生きていない | 撤収する |
//! | 3 | このパスの台帳エントリの`granted_sids`に載っている | 撤収する |
//! | 4 | 登録が無く、マスクがharnessの値に**完全一致** | 撤収する |
//! | 5 | それ以外 | 名指しで報告するだけ |
//!
//! **規則0が規則3より先にあるのが要**（`docs/SECURITY-PRINCIPLES.md` P-01）。台帳ファイルは
//! [BUG-103](../../../../docs/bugs/BUG-103.md)(d)で**サンドボックスから書ける状態だった**ことが
//! 実測されている。台帳の記録を無条件に信じて破壊的操作を行うと、「サンドボックス内から
//! 他アプリのACEを剥がさせる」経路になる。境界の内側から書けるファイルは外側で検証する。
//!
//! **登録が無いことは「harnessが付けた」の証明ではない**（アンインストールされた他アプリの
//! ものでもあり得る）。確実に言えるのは「名前へ逆引きする手段がこのマシンに存在しない」まで。
//! だから規則4はマスクの**完全一致**を要求する。加えて未登録は永続でもない——同じ名前で
//! プロファイルを作り直せば同じSIDが復活し、残っていたACEは再び有効になる。
//!
//! **規則-1が全ての先にあるのも同じ理由である**（[`WELL_KNOWN_PACKAGE_SIDS`]）。マスクの
//! 完全一致は「他に手掛かりが無いときの最後の指紋」であって、**その指紋を持つのがharnessだけ
//! である保証はどこにも無い**。実際、`ALL APPLICATION PACKAGES`(`S-1-15-2-1`)へ
//! `icacls /grant "*S-1-15-2-1:(OI)(CI)(RX)"`で付けたACEのマスクは`0x1200A9`で、
//! `fs_access_mask(FsAccess::ReadExec)`と**1ビット違わず同じ**である。この形のACEは
//! Edge/Chrome/VS Codeのインストールツリーが標準で持ち、剥がすとそれらのサンドボックスが
//! 起動できなくなる（`docs/DEV-ENVIRONMENT.md`のVS Code GPUサンドボックスの節）。

use std::collections::BTreeMap;

use super::*;

use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, KEY_READ,
    RRF_RT_REG_SZ,
};

/// AppContainer SIDの文字列接頭辞（`S-1-15-2-<hash…>`）。`SECURITY_APP_PACKAGE_BASE_RID`(2)で
/// 始まるものがAppContainerの**パッケージ**SIDで、capability SID（`S-1-15-3-`）は含まない。
///
/// capability SIDを混ぜないのは意図である——祖先traverse（D-37）とworkspace（D-54）の主体は
/// capability SIDで、それぞれ`fs revoke-traverse`・`fs revoke-workspace`という名前の付いた
/// 扉が担当する。ここで巻き込むと[BUG-046](../../../../docs/bugs/BUG-046.md)（`C:\`のtraverse ACEを
/// 純減させてマシン全体のFS I/Oを壊した）を再現する。
const APPCONTAINER_SID_PREFIX: &str = "S-1-15-2-";

/// **harnessが主体にすることが決して無い、well-knownのパッケージSID。**
///
/// [`APPCONTAINER_SID_PREFIX`]は`S-1-15-2-<ハッシュ>`という形のプロファイル固有SIDを拾う
/// つもりの接頭辞だが、well-knownのグループSIDもこの下にいる（RIDが1つだけの短い形）。
/// harnessのプロファイルSIDは`DeriveAppContainerSidFromAppContainerName`のハッシュなので
/// **これらと一致することはない**。
///
/// 剥がしてはいけない理由は、これがマシン共有の主体だからである。`ALL APPLICATION PACKAGES`は
/// 「AppContainerで動く全アプリ」を指し、Edge/Chrome/VS Codeのインストールツリーは自分の
/// GPU・レンダラサンドボックスを動かすためにこのSID宛のACEを持つ。純減させると、harnessと
/// 無関係なアプリが起動できなくなる（[BUG-046](../../../../docs/bugs/BUG-046.md)で`C:\`の
/// traverse ACEを純減させたのと同じ形の事故）。
const WELL_KNOWN_PACKAGE_SIDS: &[(&str, &str)] = &[
    ("S-1-15-2-1", "ALL APPLICATION PACKAGES"),
    ("S-1-15-2-2", "ALL RESTRICTED APPLICATION PACKAGES"),
];

/// well-knownのパッケージSIDなら、その表示名を返す。
fn well_known_package_name(sid: &str) -> Option<&'static str> {
    WELL_KNOWN_PACKAGE_SIDS
        .iter()
        .find(|(known, _)| known.eq_ignore_ascii_case(sid))
        .map(|(_, name)| *name)
}

/// `HKCU`配下のAppContainerプロファイル登録簿。サブキー名がSID、値`Moniker`がプロファイル名。
///
/// この機での実測: 218件登録されており、harness由来24件、残りはStoreアプリだった。
/// `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppContainer\Mappings`は**存在しない**。
const APPCONTAINER_MAPPINGS_KEY: &str = r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings";

/// `path`のDACLに明示ACEを持つAppContainerパッケージSID1件ぶん。
#[derive(Debug)]
pub struct PathAceSubject {
    /// SIDの文字列表現（`S-1-15-2-…`）。**プロファイルが削除済みでもこれは読める**——
    /// 名前を失ったACEに到達できる唯一の識別子である。
    pub sid: String,
    /// このSID宛の**許可**ACEのアクセスマスクの論理和（同一SIDに複数ACEがあり得るため）。
    pub allow_mask: u32,
    /// このSID宛に拒否ACEが1本でもあるか。マスクの指紋（規則4）はこれが真なら使わない
    /// ——harnessのfs passthrough付与は許可ACEしか書かないので、形が違う。
    pub has_deny: bool,
    sid_bytes: crate::win_common::OwnedSid,
}

impl PathAceSubject {
    fn psid(&self) -> PSID {
        self.sid_bytes.as_psid()
    }
}

/// 1つの主体をどう扱うか。**「撤収する」と「触らない」を1つの値で表し、理由を必ず持たせる**
/// ——理由を落とすと「0件だったのか、触らなかったのか」が呼び出し側から見えない（B-09/B-10）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectKind {
    /// 規則-1: well-knownのパッケージSID（[`WELL_KNOWN_PACKAGE_SIDS`]）。マシン共有の主体で、
    /// harnessが付与先にすることは無い。**登録簿と台帳のどちらが何と言おうと触らない。**
    WellKnownPackage { name: &'static str },
    /// 規則0: 登録済みで、harnessのものではない。
    ForeignRegistered { moniker: String },
    /// 規則1: 生きているharnessセッション。
    LiveHarness { profile: String },
    /// 規則2: 生きていないharnessプロファイル。
    DeadHarness { profile: String },
    /// 規則3: 台帳がこのパスへの付与先として記録している。
    LedgerRecorded,
    /// 規則4: 登録が無く、マスクがharnessの値に完全一致。
    UnregisteredHarnessMask,
    /// 規則5: 判別できない。`classified`が偽なら、そもそも登録簿を読めなかった。
    Unidentified { classified: bool },
}

impl SubjectKind {
    /// 撤収対象か。
    pub fn is_revocable(&self) -> bool {
        matches!(
            self,
            SubjectKind::DeadHarness { .. }
                | SubjectKind::LedgerRecorded
                | SubjectKind::UnregisteredHarnessMask
        )
    }

    /// 撤収対象ではない理由（表示用）。対象のものには`None`。
    pub fn left_alone_reason(&self) -> Option<String> {
        match self {
            SubjectKind::WellKnownPackage { name } => Some(format!(
                "{name} is a well-known machine-wide package SID that harness never grants to; \
                 other applications (Edge/Chrome/VS Code sandboxes) depend on it, so it is left \
                 untouched no matter what the ledger says"
            )),
            SubjectKind::ForeignRegistered { moniker } => {
                Some(format!("registered to {moniker}; not ours, left untouched"))
            }
            SubjectKind::LiveHarness { profile } => Some(format!(
                "{profile} is still running; refusing to take access from a live session"
            )),
            SubjectKind::Unidentified { classified: true } => Some(
                "no AppContainer profile on this machine maps to this SID and its mask does not \
                 match anything harness grants, so harness cannot claim it"
                    .to_string(),
            ),
            SubjectKind::Unidentified { classified: false } => Some(
                "the AppContainer profile registry could not be read, so no SID could be \
                 classified (nothing was revoked)"
                    .to_string(),
            ),
            _ => None,
        }
    }
}

/// 分類の材料。**Win32に触らない**ので、判定そのものは真理値表で全数テストできる
/// （`revoke_subjects_tests.rs`）。
pub struct SubjectClassifier<'a> {
    /// SID文字列 → `Moniker`。`None`は**登録簿を読めなかった**——「登録が無い」と
    /// 同一視しないこと（読めなかったのを孤児と読み替えると破壊側へ倒れる、B-10）。
    pub registered: Option<&'a BTreeMap<String, String>>,
    /// 生きているharnessプロファイル名（`session_profile::live_profile_names`）。
    pub live_profiles: &'a [String],
    /// この撤収対象パスの台帳エントリが記録している付与先SID。
    pub ledger_sids: &'a [String],
    /// harnessがパッケージSID宛に書き得る許可マスクの全体（[`harness_package_sid_masks`]）。
    pub harness_masks: &'a [u32],
}

impl SubjectClassifier<'_> {
    pub fn classify(&self, sid: &str, allow_mask: u32, has_deny: bool) -> SubjectKind {
        // 規則-1: **他のどの材料よりも先**（[`WELL_KNOWN_PACKAGE_SIDS`]）。登録簿が読めたか、
        // 台帳が何と言っているか、マスクが指紋に一致するか——どれとも無関係に決まる。
        // 台帳より先に置くのは規則0と同じ理由で、台帳はサンドボックスから書ける（BUG-103(d)）。
        // ここが後ろにあると、「台帳へ`S-1-15-2-1`を書き足す」だけで
        // **他アプリからALL APPLICATION PACKAGESのACEを剥がさせられる**。
        if let Some(name) = well_known_package_name(sid) {
            return SubjectKind::WellKnownPackage { name };
        }
        let Some(registered) = self.registered else {
            return SubjectKind::Unidentified { classified: false };
        };
        if let Some(moniker) = registered.get(sid) {
            // 規則0: 登録簿がharness以外の持ち主を名指ししている。**ここで打ち切る**
            // ——台帳（規則3）はサンドボックスから書かれ得るので、登録簿より弱い証拠である。
            if !is_harness_moniker(moniker) {
                return SubjectKind::ForeignRegistered {
                    moniker: moniker.clone(),
                };
            }
            return if self.live_profiles.iter().any(|p| p == moniker) {
                SubjectKind::LiveHarness {
                    profile: moniker.clone(),
                }
            } else {
                SubjectKind::DeadHarness {
                    profile: moniker.clone(),
                }
            };
        }
        // ここから先は「登録簿に無い」＝名前へ逆引きできないSID。
        if self.ledger_sids.iter().any(|s| s.eq_ignore_ascii_case(sid)) {
            return SubjectKind::LedgerRecorded;
        }
        // 規則4: マスクの**完全一致**でしか名乗らない。部分集合（AND）判定にすると、
        // `SYNCHRONIZE`や`READ_CONTROL`を持つだけの無関係なACEまで拾う（B-25）。
        if !has_deny && self.harness_masks.contains(&allow_mask) {
            return SubjectKind::UnregisteredHarnessMask;
        }
        SubjectKind::Unidentified { classified: true }
    }
}

/// `Moniker`がharness由来のプロファイル名か。
///
/// **`mcp_profile::is_harness_profile_name`だけでは足りない**——あれは接尾辞のある名前しか
/// 通さないので、旧共有プロファイル`harness.shell.sandbox`（接尾辞なし）を弾く
/// （`session_profile::LEGACY_SHARED_PROFILE`のdoc参照）。撤収は旧共有ぶんも対象なので、
/// ここで明示的に足す。
fn is_harness_moniker(moniker: &str) -> bool {
    moniker == crate::tier2a::session_profile::LEGACY_SHARED_PROFILE
        || crate::tier2a::mcp_profile::is_harness_profile_name(moniker)
}

/// harnessがパッケージSID宛に書き得る許可マスクの全体。
///
/// **手書きのリストを作らない**（B-05）。`FsAccess`のvariantを足すと`FsAccess::ALL`と
/// `index_in_all`の2段でビルドが落ちるので、ここは自動的に追随する。追随に失敗した形の
/// 無言失敗は「剥がせるはずのACEを剥がし損ねる」——つまりBUG-101そのものの再発になる。
///
/// **traverseマスク（`FILE_TRAVERSE|FILE_READ_ATTRIBUTES`）は入れない。** D-37以前は祖先
/// traverseも旧共有package SID宛だったので該当ACEは実在し得るが、祖先は`C:\`のような
/// マシン全体で共有されるノードで、純減させるとBUG-046を再現する。規則5（報告のみ）へ落とす。
pub fn harness_package_sid_masks() -> Vec<u32> {
    FsAccess::ALL.iter().copied().map(fs_access_mask).collect()
}

/// `path`のDACLに明示ACEを持つAppContainerパッケージSIDを列挙する（SIDごとに1件へ畳む）。
///
/// 読み取りは[`super::visit_explicit_aces`]（`GetAce`直接列挙）を通す。**`GetExplicitEntriesFromAclW`は
/// 使わない**——DACLに条件付きACEが1本でもあると`ERROR_INVALID_PARAMETER`で全体が落ち、
/// そのパスが永久に撤収不能になる（実マシンで`%LOCALAPPDATA%\PowerToys`が該当した。同関数のdoc）。
/// SIDはWin32が確保したバッファの中を指すため、解放前に[`crate::win_common::OwnedSid`]へ
/// コピーして所有権を単純化する。
///
/// **継承ACEは含まない。** 撤収側にとってはこれが正しい意味である——継承ACEはそのノードからは
/// 剥がせず、継承元でしか取り消せない。
///
/// `has_deny`は「harnessが書かない形のACEが混じっているか」を意味し、**deny ACEだけでなく
/// 条件付きACEも立てる**（規則4の指紋は「harnessが書いた形」でしか名乗らない、B-25）。
pub fn appcontainer_sid_aces(path: &Path) -> Result<Vec<PathAceSubject>, AppContainerError> {
    let mut found: Vec<PathAceSubject> = Vec::new();
    unsafe {
        super::visit_explicit_aces(path, &mut |entry_sid, ace_type, _flags, mask| {
            let Ok(sid_string) = crate::win_common::sid_to_string(entry_sid) else {
                return;
            };
            if !sid_string.starts_with(APPCONTAINER_SID_PREFIX) {
                return;
            }
            let harness_shape = ace_type == super::ACCESS_ALLOWED_ACE_TYPE;
            // 同一SIDに複数のACEがあれば1件へ畳む（許可はOR、それ以外は有無だけ）。
            if let Some(existing) = found.iter_mut().find(|s| s.sid == sid_string) {
                if harness_shape {
                    existing.allow_mask |= mask;
                } else {
                    existing.has_deny = true;
                }
                return;
            }
            if let Ok(owned) = crate::win_common::OwnedSid::copy_from(entry_sid) {
                found.push(PathAceSubject {
                    sid: sid_string,
                    allow_mask: if harness_shape { mask } else { 0 },
                    has_deny: !harness_shape,
                    sid_bytes: owned,
                });
            }
        })
        .map_err(|e| AppContainerError::AclRevoke {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
    }
    Ok(found)
}

/// `path`に載っているAppContainerパッケージSID宛の明示ACEのうち、`keep_profiles`のどの
/// プロファイルのSIDとも一致しないものを剥がし、剥がしたSID文字列を返す。
///
/// **なぜ「残す側」を名指しするのか**: プロファイルが削除済みのSIDは名前へ逆引きできない
/// （`DeriveAppContainerSidFromAppContainerName`は名前→SIDの一方向）ため、「死んだセッションの
/// SIDを列挙して剥がす」方式は既に残ってしまったACEには効かない。生存しているセッション
/// （`session_profile::live_profile_names`）のSIDだけを残し、それ以外を剥がす向きにする。
///
/// 対象は**呼び出し側が明示した既知パス**に限る（現状はredirector DLL）。マシン全体を
/// 走査する掃除機にはしない——それはこのプロセスが所有していない変更まで巻き込む。
///
/// BUG-059で実マシンに4件残留していた孤立ACEの回収経路。付与側（`preflight`）に保険を
/// 入れて新規発生は止めたが、**既に残っているものは台帳に無いので`fs revoke`では届かない**。
pub fn revoke_stale_appcontainer_aces(
    path: &Path,
    keep_profiles: &[String],
) -> Result<Vec<String>, AppContainerError> {
    let keep: Vec<String> = keep_profiles
        .iter()
        // [BUG-101] 撤収経路は`ensure_profile`（＝存在しなければ作る）を呼ばない。
        .filter_map(|name| derive_profile_sid(name).ok())
        .filter_map(|sid| crate::win_common::sid_to_string(sid.as_psid()).ok())
        .collect();

    let mut removed = Vec::new();
    for subject in appcontainer_sid_aces(path)? {
        if keep.contains(&subject.sid) {
            continue;
        }
        revoke_ace(path, subject.psid())?;
        removed.push(subject.sid);
    }
    Ok(removed)
}

/// 1主体の結末。
#[derive(Debug)]
pub struct SubjectOutcome {
    pub sid: String,
    pub kind: SubjectKind,
    /// 撤収対象だったのに、walkのあともrootにACEが残っているか。
    /// **対象でなかったものは常に`false`**（数える対象を混ぜない、B-09）。
    pub still_on_root: bool,
}

/// [`revoke_harness_subjects`]の結果。**ACE側と台帳側を別々に数えるための型**である。
///
/// [BUG-101] 旧実装は「台帳から何件落ちたか」だけを見て`revoked:`と報告していた。
/// ACE側の件数を持たないので、**1件も剥がしていないこと**が呼び出し側からは原理的に
/// 見えなかった。
#[derive(Debug)]
pub struct HarnessRevokeReport {
    /// DACLに載っていたパッケージSIDの全件（撤収対象かどうかを問わない）。
    pub subjects: Vec<SubjectOutcome>,
    /// walkの件数（`checked`/`rewritten`/`blocked`）。既存型をそのまま内包して二重に数えない。
    pub walk: RevokeReport,
    /// rootがそもそも存在しなかった。ACEを載せる先が無いので台帳は掃除してよい。
    pub root_missing: bool,
    /// 登録簿を読めなかった理由（読めた場合は`None`）。
    pub classification_error: Option<String>,
    /// **この報告を作るより前に、別の経路（昇格ヘルパー）が剥がした主体の数。**
    ///
    /// 昇格へエスカレーションした後の検算（[`classify_subjects_on_root`]）は、剥がし終えた
    /// 後のDACLを見るので`subjects`が空になる。そこだけを見ると「対象が0件だった」と
    /// 区別が付かず、**実際には剥がしたのに「何も一致しなかった」と報告してしまう**
    /// （0件と成功を同じ値にしない、B-09）。呼び出し側がここへ「エスカレーション前に
    /// 対象だった数」を入れる。
    pub cleared_elsewhere: usize,
}

impl HarnessRevokeReport {
    /// 撤収対象と判定した主体の数。**0は「対象が無かった」であって「成功」ではない。**
    pub fn targeted(&self) -> usize {
        self.subjects
            .iter()
            .filter(|s| s.kind.is_revocable())
            .count()
    }

    /// 実際にACEを剥がして書き戻したノード数。
    pub fn rewritten(&self) -> usize {
        self.walk.rewritten
    }

    /// 撤収対象なのにrootへ残ってしまったSID。空でなければ**撤収は成立していない**。
    pub fn unfinished(&self) -> Vec<&str> {
        self.subjects
            .iter()
            .filter(|s| s.still_on_root)
            .map(|s| s.sid.as_str())
            .collect()
    }

    /// 台帳エントリを落としてよいか。
    ///
    /// **落としてはいけないのは2つ**: (1) 撤収対象が残っている（次回再試行できるように記録を
    /// 残す）、(2) 生きているセッションがまだACEを持っている（そのACEは実在するので、
    /// 記録を消すとharnessが把握しない穴になる）。他アプリのSIDや判別できないSIDは
    /// harnessの記録の対象ではないので、これらを理由に台帳を残すことはしない。
    pub fn may_remove_ledger_entry(&self) -> bool {
        self.unfinished().is_empty()
            && !self
                .subjects
                .iter()
                .any(|s| matches!(s.kind, SubjectKind::LiveHarness { .. }))
    }

    /// 触らなかった主体を`(SID, 理由)`で返す（**名前を出さないと`icacls`で追えない**、B-09）。
    pub fn left_alone(&self) -> Vec<(&str, String)> {
        self.subjects
            .iter()
            .filter_map(|s| {
                s.kind
                    .left_alone_reason()
                    .map(|reason| (s.sid.as_str(), reason))
            })
            .collect()
    }
}

/// `root`配下から、**そのパスのDACLに実在するharness由来のパッケージSID**のACEを撤収する。
///
/// `ledger_sids`はこのパスの台帳エントリが記録している付与先SID（規則3）。無ければ空を渡す。
/// `progress`は`(処理済み, 全体)`で1000件ごとに呼ばれる。
///
/// **最終判定はrootの再プローブ**（`sid_ace_mask`）で、これは`revoke_passthrough`から
/// 変えていない基準である（B-08）。変えたのは**誰を探すか**だけ。
pub fn revoke_harness_subjects(
    root: &Path,
    ledger_sids: &[String],
    progress: &dyn Fn(usize, usize),
) -> Result<HarnessRevokeReport, AppContainerError> {
    let mut report = HarnessRevokeReport {
        subjects: Vec::new(),
        walk: RevokeReport::default(),
        root_missing: false,
        cleared_elsewhere: 0,
        classification_error: None,
    };
    // rootが既に存在しない（revoke後にユーザが削除した等）場合は、実FS上にACEを載せる
    // オブジェクトが無いので完全撤収扱いとし、台帳エントリを掃除できるようにする。
    if !root.exists() {
        report.root_missing = true;
        return Ok(report);
    }

    let (subjects, kinds, error) = classify_root(root, ledger_sids)?;
    report.classification_error = error;
    let targets: Vec<PSID> = subjects
        .iter()
        .zip(&kinds)
        .filter(|(_, kind)| kind.is_revocable())
        .map(|(s, _)| s.psid())
        .collect();

    // `Err`は「rootにすら触れなかった」ときだけ来る。**そこで打ち切らない**——後段のroot
    // 再プローブが最終判定なので、理由を残件へ畳んで判定へ進む（`revoke_passthrough_reporting`
    // と同じ形）。
    report.walk = match revoke_sids_recursive(root, &targets, progress) {
        Ok(walk) => walk,
        Err(e) => RevokeReport {
            checked: 1,
            blocked: vec![(root.to_path_buf(), e.to_string())],
            ..RevokeReport::default()
        },
    };

    for (subject, kind) in subjects.iter().zip(kinds) {
        let still_on_root =
            kind.is_revocable() && !matches!(sid_ace_mask(root, subject.psid()), Ok(None));
        report.subjects.push(SubjectOutcome {
            sid: subject.sid.clone(),
            kind,
            still_on_root,
        });
    }
    Ok(report)
}

/// `root`のDACLに載っている主体を列挙して分類する（**walkはしない**）。
///
/// 戻り値の3つ目は登録簿を読めなかった理由。`None`なら分類は材料が揃っている。
type ClassifiedRoot = (Vec<PathAceSubject>, Vec<SubjectKind>, Option<String>);

fn classify_root(root: &Path, ledger_sids: &[String]) -> Result<ClassifiedRoot, AppContainerError> {
    let subjects = appcontainer_sid_aces(root)?;
    let (registered, error) = match registered_appcontainer_monikers() {
        Ok(map) => (Some(map), None),
        Err(e) => (None, Some(e)),
    };
    let live = crate::tier2a::session_profile::live_profile_names();
    let masks = harness_package_sid_masks();
    let classifier = SubjectClassifier {
        registered: registered.as_ref(),
        live_profiles: &live,
        ledger_sids,
        harness_masks: &masks,
    };
    let kinds = subjects
        .iter()
        .map(|s| classifier.classify(&s.sid, s.allow_mask, s.has_deny))
        .collect();
    Ok((subjects, kinds, error))
}

/// `root`に**いま載っている**harness由来の主体を報告する（撤収はしない）。
///
/// 撤収を昇格ヘルパーへ委譲したあとの検算に使う——ヘルパーの応答だけを根拠に「剥がせた」と
/// 名乗ると、[BUG-101]と同じ「他人の成功報告を自分の結論にする」形になる。ここは単一ノードの
/// DACL読取1回で済むので、全walkをもう一度回さずに確かめられる。
pub fn classify_subjects_on_root(
    root: &Path,
    ledger_sids: &[String],
) -> Result<HarnessRevokeReport, AppContainerError> {
    let mut report = HarnessRevokeReport {
        subjects: Vec::new(),
        walk: RevokeReport::default(),
        root_missing: !root.exists(),
        cleared_elsewhere: 0,
        classification_error: None,
    };
    if report.root_missing {
        return Ok(report);
    }
    let (subjects, kinds, error) = classify_root(root, ledger_sids)?;
    report.classification_error = error;
    for (subject, kind) in subjects.into_iter().zip(kinds) {
        // rootのDACLから読んだ主体なので、撤収対象と判定されたものは**定義上まだ載っている**。
        let still_on_root = kind.is_revocable();
        report.subjects.push(SubjectOutcome {
            sid: subject.sid,
            kind,
            still_on_root,
        });
    }
    Ok(report)
}

/// `HKCU`のAppContainer登録簿を読む（SID文字列 → `Moniker`）。
///
/// **`Err`を空のマップへ潰さないこと。** 「登録が無い」と「読めなかった」を同一視すると、
/// 読めなかっただけのSIDが孤児と判定されて破壊側へ倒れる（B-10）。呼び出し側は`Err`を
/// 受けたら全主体を「判別不能」として扱う。
pub fn registered_appcontainer_monikers() -> Result<BTreeMap<String, String>, String> {
    unsafe {
        let key_w = crate::win_common::wide(APPCONTAINER_MAPPINGS_KEY);
        let mut hkey = HKEY::default();
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(key_w.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        )
        .ok()
        .map_err(|e| format!("RegOpenKeyExW({APPCONTAINER_MAPPINGS_KEY}): {e}"))?;

        let mut map = BTreeMap::new();
        // SIDの文字列表現は`S-1-15-2-`＋8個の32bit値で最長でも100文字程度。レジストリの
        // キー名上限（255）で取っておけば切り詰めは起きない。
        let mut name = vec![0u16; 256];
        let mut index = 0u32;
        let result = loop {
            let mut name_len = name.len() as u32;
            let status = RegEnumKeyExW(
                hkey,
                index,
                windows::core::PWSTR(name.as_mut_ptr()),
                &mut name_len,
                None,
                windows::core::PWSTR::null(),
                None,
                None,
            );
            if status == windows::Win32::Foundation::ERROR_NO_MORE_ITEMS {
                break Ok(map);
            }
            if let Err(e) = status.ok() {
                break Err(format!("RegEnumKeyExW(index={index}): {e}"));
            }
            index += 1;
            let sid = String::from_utf16_lossy(&name[..name_len as usize]);
            // `Moniker`が無いサブキーは飛ばす（分類材料にならないだけで、失敗ではない）。
            if let Some(moniker) = read_string_value(hkey, &sid, "Moniker") {
                map.insert(sid, moniker);
            }
        };
        let _ = RegCloseKey(hkey);
        result
    }
}

/// `hkey\subkey`の文字列値を1つ読む。無い・型が違う場合は`None`。
unsafe fn read_string_value(hkey: HKEY, subkey: &str, value: &str) -> Option<String> {
    let subkey_w = crate::win_common::wide(subkey);
    let value_w = crate::win_common::wide(value);
    let mut buf = vec![0u16; 512];
    let mut len = (buf.len() * 2) as u32;
    let status = RegGetValueW(
        hkey,
        PCWSTR(subkey_w.as_ptr()),
        PCWSTR(value_w.as_ptr()),
        RRF_RT_REG_SZ,
        None,
        Some(buf.as_mut_ptr() as *mut c_void),
        Some(&mut len),
    );
    if status.is_err() {
        return None;
    }
    // `len`はバイト数。終端NULを含むので落とす。
    let chars = (len as usize / 2).saturating_sub(1).min(buf.len());
    Some(String::from_utf16_lossy(&buf[..chars]))
}

#[cfg(test)]
#[path = "revoke_subjects_tests.rs"]
mod revoke_subjects_tests;
