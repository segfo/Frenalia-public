//! 撤収の**宛先SID**を決める層のうち、**宣言（`--fs-allow`）から導出できるもの**を担う
//! （[`super::revoke_subjects`]の姉妹。あちらはpackage SID、こちらはcapability SID）。
//!
//! # なぜ分類器と別の層なのか（§22.2.1）
//!
//! `revoke_subjects`は**対象パスのDACLに実在するSIDを列挙して、harness由来かを分類する**。
//! 名前から導出したSIDでは、プロファイル削除済みの宛先SIDに届かないからである（BUG-101）。
//!
//! 宣言capabilityでは、その推定がそもそも要らない——宛先SIDは
//! `(秘密, 畳み込み済み宣言パス, access級)`から**一意に計算できる**ので、台帳の索引を引けば
//! 「誰宛に開けたか」が分かる。逆に分類器へcapability SID（`S-1-15-3-`）を混ぜてはならない
//! ——同ファイルの接頭辞フィルタは意図的なもので、混ぜると
//! [BUG-046](../../../../docs/bugs/BUG-046.md)（`C:\`のtraverse ACEを純減させてマシン全体の
//! FS I/Oを壊した）を再現する。
//!
//! **剥がし方（DACLの書き換え・walk）は持たない。** それは[`super::revoke`]の責務で、
//! ここは「どのSIDを渡すか」を決めて呼ぶだけである。

use super::*;

/// [§22.2.1] 宣言capability（`--fs-allow`の宛先SID）を1つのパスから剥がした結果。
///
/// **package SIDの分類器（`revoke_subjects.rs`）とは別に数える。** 同じ`HarnessRevokeReport`へ
/// 混ぜないのは、あちらが「DACLに実在する宛先SIDを分類して剥がす」のに対し、こちらは
/// 「宣言から導出したSIDを名指しで剥がす」——**そもそも探し方が違う**からである
/// （混ぜると「0件だった」の意味が2つになる、B-09）。
#[derive(Debug, Default)]
pub struct DeclarationRevokeReport {
    /// 剥がす対象として名指しした宛先SID（SID文字列）。**0件は「対象が無かった」であって
    /// 「成功」ではない**（`HarnessRevokeReport::targeted`と同じ意味）。
    pub targeted: Vec<String>,
    /// walkが見たノード数。
    pub checked: usize,
    /// 実際にACEを剥がして書き戻したノード数。
    pub rewritten: usize,
    /// **walkのあともrootに残っている宛先SID。** 空でなければ撤収は成立していない。
    /// ヘルパーや戻り値ではなく実DACLを読み直して決める（B-25）。
    pub still_on_root: Vec<String>,
    /// rootがそもそも存在しなかった。剥がす先が無いので「残っていない」と同じ扱いでよいが、
    /// **0件と区別できるように別の事実として持つ**（B-10）。
    pub root_missing: bool,
    /// **この報告を作るより前に、別の経路（昇格ヘルパー）が剥がした宛先SIDの数。**
    /// `HarnessRevokeReport::cleared_elsewhere`と同じ役割で、同じ理由で要る——昇格後の検算は
    /// 剥がし終えたDACLを見るので、そこだけを見ると「対象が0件だった」と区別が付かない（B-09）。
    pub cleared_elsewhere: usize,
    /// **意図的に触らなかった宛先SIDと、その理由**（`(capability名, 理由)`）。
    ///
    /// `HarnessRevokeReport::left_alone`と同じ役割。**「剥がせなかった」と「剥がさないと
    /// 決めた」を同じ値にしない**（B-09/B-10）——前者は失敗だが、後者は正しい動作である。
    /// 現在ここに入るのは「その宛先SIDを発行したworkspaceでharnessが走っている」1種類だけで、
    /// これは分類器側の規則1（生きているセッションからは奪わない）と同じ判断である。
    pub left_alone: Vec<(String, String)>,
}

impl DeclarationRevokeReport {
    /// 剥がすつもりだったものが残っていないか（＝**昇格へ回す必要が無いか**）。
    ///
    /// **意図的に触らなかった宛先SID（[`Self::left_alone`]）はここに数えない。** あれは
    /// 失敗ではないので、昇格して再試行しても何も変わらない。
    pub fn is_clean(&self) -> bool {
        self.still_on_root.is_empty()
    }

    /// 台帳の記録を捨ててよいか（`HarnessRevokeReport::may_remove_ledger_entry`と同じ判断）。
    ///
    /// **触らなかった宛先SIDが1つでもあるなら捨ててはいけない。** そのACEは実在するので、
    /// 記録を消すとharnessが把握しない穴になる（`B-01`: 到達手段を捨てるのは最後）。
    pub fn may_forget(&self) -> bool {
        self.still_on_root.is_empty() && self.left_alone.is_empty()
    }
}

/// `subjects`（宣言から導出済みのcapability SID）のACEを`path`配下から剥がす。
///
/// **走査は新しく書かない。** [`revoke_workspace_sids_recursive`]（1ノード1読取・N本の宛先SIDを
/// 1walkで除去・D-48ガード込み）をそのまま使う。SIDの数だけツリーを舐め直す形にしないのは
/// あちらのdocが述べているとおりで、宣言capabilityも1つのパスに対して最大でaccess級の数
/// （§22.3.3）ぶん載るので同じ理由がそのまま効く。
///
/// **剥がした後にrootを読み直す**——「呼んだ」と「消えた」は別の事実である（B-09/B-25）。
/// 残っていれば`still_on_root`に載り、呼び出し元は台帳の記録を捨てずに昇格経路へ回す。
///
/// walkはノード1件の失敗で`Err`になる（`revoke_workspace_sids_recursive`の既存挙動）。
/// システム保護パスではこれが起きるので、**呼び出し元は`Err`を「失敗」ではなく
/// 「昇格が要る」として扱うこと**（`fs_revoke_one`の分岐と同じ形）。
pub fn revoke_capability_subjects(
    path: &Path,
    subjects: &[crate::win_common::OwnedSid],
    progress: &dyn Fn(usize, usize),
) -> Result<DeclarationRevokeReport, AppContainerError> {
    let mut report = DeclarationRevokeReport {
        targeted: subjects
            .iter()
            .map(|sid| {
                crate::win_common::sid_to_string(sid.as_psid())
                    .unwrap_or_else(|_| "<unprintable capability SID>".to_string())
            })
            .collect(),
        ..Default::default()
    };
    if subjects.is_empty() {
        return Ok(report);
    }
    if !path.exists() {
        report.root_missing = true;
        return Ok(report);
    }

    let psids: Vec<PSID> = subjects.iter().map(|sid| sid.as_psid()).collect();
    let walk = revoke_workspace_sids_recursive(path, &psids, progress)?;
    report.checked = walk.checked;
    report.rewritten = walk.rewritten;

    // rootの明示ACEを宛先SIDごとに1件ずつ読み直す（walkの戻り値を根拠にしない）。
    for (sid, text) in subjects.iter().zip(report.targeted.iter()) {
        if matches!(sid_explicit_ace(path, sid.as_psid()), Ok(Some(_))) {
            report.still_on_root.push(text.clone());
        }
    }
    Ok(report)
}

/// `path`のrootに**いま残っている**宣言capabilityの宛先SID（SID文字列）を読み取るだけの関数。
///
/// 撤収を昇格側へ委譲したあとの検算に使う（`classify_subjects_on_root`が package SIDについて
/// 果たしている役割の、宣言capability版）。**ヘルパーの応答を根拠に成功を名乗らない**ための
/// 経路なので、ここは剥がさず読むだけである（B-25）。読むのはrootの明示ACE1件ずつで、
/// ツリーの再walkはしない。
pub fn declaration_capabilities_on_root(path: &Path, workspace: Option<&Path>) -> Vec<String> {
    super::fs_allow_capability_sids(path, workspace)
        .into_iter()
        .filter(|sid| matches!(sid_explicit_ace(path, sid.as_psid()), Ok(Some(_))))
        .map(|sid| {
            crate::win_common::sid_to_string(sid.as_psid())
                .unwrap_or_else(|_| "<unprintable capability SID>".to_string())
        })
        .collect()
}

/// 撤収を試したパスについて、**実体がもう無い**宣言の宛先SIDの台帳エントリを落とす。
/// 戻り値は落としたエントリのラベル（呼び出し側がそのまま表示できる）。
///
/// # 「撤収を呼んだ」を根拠に落としてはならない
///
/// 撤収は**走っているworkspaceの宛先SIDを意図的に残す**（[`revocable_declaration_issuers`]）ので、
/// 「撤収を呼んだパス」の中には**まだACEが載っている宛先SID**が混じる。それを台帳から落とすと
/// 宛先SIDを二度と導出できなくなり、撤収経路の無い孤児ACEになる（`B-01`/`B-14`）。
/// だから捨てる前に**実体を見る**（[`declaration_capabilities_gone_from_root`]）。
///
/// # なぜここに置くのか
///
/// [BUG-142](../../../../docs/bugs/BUG-142.md)の修正で**呼ぶ側が2つになった**
/// （`harness fs revoke`系と、ポリシーエディタのパス2開始時の差分撤収）。別クレートなので、
/// どちらかに置くとコピーが1つ増える——同じ判定が2箇所にあると片方だけ古くなる（`B-05`）。
/// 判定が要るのは台帳と実DACLの両方で、どちらもこのクレートが持っている。
pub fn forget_revoked_declarations(revoked: &[std::path::PathBuf]) -> Vec<String> {
    if revoked.is_empty() {
        return Vec::new();
    }
    // `(宣言パスの畳み込み鍵, もう載っていないcapability名)`の対応表を先に作る。
    // [残課題#37] **台帳の写しは1回だけ取る。** パスごとに引き直すと、全文の読取と構文解析が
    // 取り消すパスの本数ぶん走る（付与側と同じ形の費用）。
    let index = crate::tier2a::workspace_capability::DeclarationIndex::load();
    let gone: Vec<(String, Vec<String>)> = revoked
        .iter()
        .map(|p| {
            (
                crate::tier2a::workspace_capability::declaration_key(p),
                declaration_capabilities_gone_from_root_indexed(&index, p),
            )
        })
        .collect();
    crate::tier2a::workspace_capability::prune_capability_entries(|entry| {
        let Some(declared) = entry.declaration.as_deref() else {
            // workspace本体の宛先SIDはここでは扱わない（撤収の扉は`fs revoke-workspace`）。
            return false;
        };
        gone.iter()
            .any(|(key, names)| key == declared && names.iter().any(|n| n == &entry.capability_name))
    })
}

/// `path`について、**実DACLにもう載っていない**宣言の宛先SIDのcapability名。
///
/// 記録を捨ててよいかを決めるために要る。**「剥がすつもりだった」ではなく「消えている」を
/// 見る**——撤収が生きているworkspaceの宛先SIDを意図的に残す（[`revocable_declaration_issuers`]）
/// ので、「撤収を呼んだ」だけを根拠に台帳から落とすと、実在するACEの記録が消えて
/// 撤収経路の無い孤児になる（`B-01`/`B-14`）。
pub fn declaration_capabilities_gone_from_root(path: &Path) -> Vec<String> {
    declaration_capabilities_gone_from_root_indexed(
        &crate::tier2a::workspace_capability::DeclarationIndex::load(),
        path,
    )
}

/// [残課題#37] [`declaration_capabilities_gone_from_root`]の、**台帳の写しを渡す版で、
/// こちらが実体**である。**「消えている」の判定は実DACLを読んで行う**ので、写しが古くても
/// 記録を誤って捨てることはない（写しに無いエントリは、そもそも捨てる候補に上がらない）。
pub fn declaration_capabilities_gone_from_root_indexed(
    index: &crate::tier2a::workspace_capability::DeclarationIndex,
    path: &Path,
) -> Vec<String> {
    index
        .issuers(path)
        .into_iter()
        .filter(|(_workspace, name)| match super::capability_sid_from_name(name) {
            // 導出できない名前は「消えた」と言えない（見に行けていないだけ）ので残す。
            Err(_) => false,
            Ok(sid) => matches!(sid_explicit_ace(path, sid.as_psid()), Ok(None)),
        })
        .map(|(_workspace, name)| name)
        .collect()
}

/// [§22.2.1] `path`に対して発行済みの**宣言capability**を台帳から引き、名指しで剥がす。
///
/// これが「分類器を使わず、宣言から導出したSIDを名指しで剥がす」の入口である。
/// ACLを列挙して「このSIDは何者か」を推定する必要はそもそも無い——撤収すべき宛先SIDは
/// 宣言から一意に決まる（`revoke_subjects.rs`の分類器は`S-1-15-2-`しか列挙しないので、
/// capability SIDは構造的にあちらへ入らない。混ぜると[BUG-046](../../../../docs/bugs/BUG-046.md)の再現になる）。
///
/// # `workspace`が決めるのは「誰の宛先SIDを対象にするか」である
///
/// | 値 | 対象 | 使う経路 | 生きているworkspaceの扱い |
/// |---|---|---|---|
/// | `Some(ws)` | **そのworkspaceが発行した宛先SIDだけ** | 呼び出し元自身がそのworkspaceで走っている経路（ポリシーエディタの整合） | **触る**（自分の穴を自分で閉じるので、走っていることは理由にならない） |
/// | `None` | そのパスへ発行された**全workspaceの宛先SID** | パスを名指しした明示操作（`harness fs revoke`）と、**もう誰も宣言していないことが確定した**自動整合（D-27） | **触らない**（下記） |
///
/// **`None`のとき、いま走っているworkspaceが発行した宛先SIDは剥がさない。** 宛先SIDはworkspace単位で
/// 共有されるので、走っている相手から取り上げると**その場でアクセスが落ちる**——分類器側の
/// 規則1（生きているセッションからは奪わない）とまったく同じ判断であり、
/// [BUG-046](../../../../docs/bugs/BUG-046.md)（他人が使っているACEを純減させた事故）の形でもある。
/// 生存判定は新しく作らず、既存のゲート（`workspace_ledger::live_modes`＝そのworkspaceのモード別
/// mutexが生きているか）をそのまま使う。触らなかったものは`left_alone`に理由つきで載る。
///
/// # なぜ自動整合が`Some`ではなく`None`なのか（**実機で1度間違えた**）
///
/// D-27の自動整合は当初`Some(自分のworkspace)`で呼んでいたが、それでは
/// **2つのworkspaceが同じパスを宣言して両方とも宣言を外した**とき、最後に起動した側の宛先SIDしか
/// 剥がれない（もう一方の宣言が消えた時点では、まだ他が宣言していたので撤収対象ではなかった）。
/// 実機E2Eで「台帳エントリは消えたのにACEが1本残る」として現れた。撤収の条件は
/// **そのパスをもう誰も宣言していないこと**であって、いま起動した誰かの都合ではない。
pub fn revoke_declaration_capabilities(
    path: &Path,
    workspace: Option<&Path>,
    progress: &dyn Fn(usize, usize),
) -> Result<DeclarationRevokeReport, AppContainerError> {
    revoke_declaration_capabilities_indexed(
        &crate::tier2a::workspace_capability::DeclarationIndex::load(),
        path,
        workspace,
        progress,
    )
}

/// [残課題#37] [`revoke_declaration_capabilities`]の、**台帳の写しを渡す版で、こちらが実体**である。
///
/// 宣言を数百件まとめて取り消す経路（ポリシーエディタのパス2開始時の差分撤収）は、
/// パス1件ごとに台帳を全文読んで構文解析していた。付与側（残課題#37）と**同じ形の費用**で、
/// 「配る側だけ速くして剥がす側を取り残す」を避けるためにこちらも写しを1回にする。
///
/// 写しの限界は[`crate::tier2a::workspace_capability::DeclarationIndex`]のdocが持つ
/// （見落としは「剥がし残す」側へ倒れ、他人のACEを剥がす向きには倒れない）。
pub fn revoke_declaration_capabilities_indexed(
    index: &crate::tier2a::workspace_capability::DeclarationIndex,
    path: &Path,
    workspace: Option<&Path>,
    progress: &dyn Fn(usize, usize),
) -> Result<DeclarationRevokeReport, AppContainerError> {
    let Some(workspace) = workspace else {
        return revoke_all_declaration_capabilities(index, path, progress);
    };
    let subjects = super::fs_allow_capability_sids_indexed(index, path, workspace.into());
    revoke_capability_subjects(path, &subjects, progress)
}

/// そのパスへ宣言の宛先SIDを発行した中で、**いま剥がしてよい発行元**（`(workspace, capability名)`）と、
/// 外したもの（`(capability名, 理由)`）。
///
/// **生存の判定はここ1箇所だけが持つ。** 非昇格側は「剥がす」経路と「昇格側へ秘密を渡す」経路の
/// 2つを持つので、同じ規則を両方に書くと片方だけ更新されて静かにずれる（`B-05`）——
/// どちらもこの関数を通す。
pub fn revocable_declaration_issuers(path: &Path) -> DeclarationIssuers {
    revocable_declaration_issuers_indexed(
        &crate::tier2a::workspace_capability::DeclarationIndex::load(),
        path,
    )
}

/// [残課題#37] [`revocable_declaration_issuers`]の、**台帳の写しを渡す版で、こちらが実体**である。
/// 生存の判定（`live_modes`）は別の台帳なので、ここでは写しに載らない。
pub fn revocable_declaration_issuers_indexed(
    index: &crate::tier2a::workspace_capability::DeclarationIndex,
    path: &Path,
) -> DeclarationIssuers {
    let mut issuers = DeclarationIssuers::default();
    for (workspace, name) in index.issuers(path) {
        let live = crate::tier2a::workspace_ledger::live_modes(Path::new(&workspace));
        if live.is_empty() {
            issuers.eligible.push((workspace, name));
        } else {
            issuers.left_alone.push((
                name,
                format!(
                    "{workspace} is still in use by another harness session (mode(s): {}); \
                     refusing to take access from a live workspace",
                    live.join(", ")
                ),
            ));
        }
    }
    issuers
}

/// [`revocable_declaration_issuers`]の結果。**「剥がしてよい」と「触らないと決めた」を
/// 別の欄で返す**——1つのリストに畳むと、呼び出し側が後者を「対象が無かった」と読む（`B-09`）。
#[derive(Debug, Default)]
pub struct DeclarationIssuers {
    /// 剥がしてよい発行元（`(workspaceのパス, capability名)`）。
    pub eligible: Vec<(String, String)>,
    /// 触らないと決めたもの（`(capability名, 理由)`）。
    pub left_alone: Vec<(String, String)>,
}

/// [`revoke_declaration_capabilities`]の`None`（全workspace）側。生きているworkspaceが発行した
/// 宛先SIDだけを外し、残りを剥がす。
fn revoke_all_declaration_capabilities(
    index: &crate::tier2a::workspace_capability::DeclarationIndex,
    path: &Path,
    progress: &dyn Fn(usize, usize),
) -> Result<DeclarationRevokeReport, AppContainerError> {
    let issuers = revocable_declaration_issuers_indexed(index, path);
    let mut left_alone = issuers.left_alone;
    let mut subjects = Vec::new();
    for (_workspace, name) in issuers.eligible {
        match super::capability_sid_from_name(&name) {
            Ok(sid) => subjects.push(sid),
            // 導出できない名前は**黙って落とさない**——剥がせないことが記録から見えなくなる。
            Err(e) => left_alone.push((name, format!("could not derive its SID: {e}"))),
        }
    }
    let mut report = revoke_capability_subjects(path, &subjects, progress)?;
    report.left_alone = left_alone;
    Ok(report)
}
