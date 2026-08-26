//! 撤収の**主体**を決める層のうち、**宣言（`--fs-allow`）から導出できるもの**を担う
//! （[`super::revoke_subjects`]の姉妹。あちらはpackage SID、こちらはcapability SID）。
//!
//! # なぜ分類器と別の層なのか（§22.2.1）
//!
//! `revoke_subjects`は**対象パスのDACLに実在するSIDを列挙して、harness由来かを分類する**。
//! 名前から導出したSIDでは、プロファイル削除済みの主体に届かないからである（BUG-101）。
//!
//! 宣言capabilityでは、その推定がそもそも要らない——主体は
//! `(秘密, 畳み込み済み宣言パス, access級)`から**一意に計算できる**ので、台帳の索引を引けば
//! 「誰宛に開けたか」が分かる。逆に分類器へcapability SID（`S-1-15-3-`）を混ぜてはならない
//! ——同ファイルの接頭辞フィルタは意図的なもので、混ぜると
//! [BUG-046](../../../../docs/bugs/BUG-046.md)（`C:\`のtraverse ACEを純減させてマシン全体の
//! FS I/Oを壊した）を再現する。
//!
//! **剥がし方（DACLの書き換え・walk）は持たない。** それは[`super::revoke`]の責務で、
//! ここは「どのSIDを渡すか」を決めて呼ぶだけである。

use super::*;

/// [§22.2.1] 宣言capability（`--fs-allow`の主体）を1つのパスから剥がした結果。
///
/// **package SIDの分類器（`revoke_subjects.rs`）とは別に数える。** 同じ`HarnessRevokeReport`へ
/// 混ぜないのは、あちらが「DACLに実在する主体を分類して剥がす」のに対し、こちらは
/// 「宣言から導出したSIDを名指しで剥がす」——**そもそも探し方が違う**からである
/// （混ぜると「0件だった」の意味が2つになる、B-09）。
#[derive(Debug, Default)]
pub struct DeclarationRevokeReport {
    /// 剥がす対象として名指しした主体（SID文字列）。**0件は「対象が無かった」であって
    /// 「成功」ではない**（`HarnessRevokeReport::targeted`と同じ意味）。
    pub targeted: Vec<String>,
    /// walkが見たノード数。
    pub checked: usize,
    /// 実際にACEを剥がして書き戻したノード数。
    pub rewritten: usize,
    /// **walkのあともrootに残っている主体。** 空でなければ撤収は成立していない。
    /// ヘルパーや戻り値ではなく実DACLを読み直して決める（B-25）。
    pub still_on_root: Vec<String>,
    /// rootがそもそも存在しなかった。剥がす先が無いので「残っていない」と同じ扱いでよいが、
    /// **0件と区別できるように別の事実として持つ**（B-10）。
    pub root_missing: bool,
    /// **この報告を作るより前に、別の経路（昇格ヘルパー）が剥がした主体の数。**
    /// `HarnessRevokeReport::cleared_elsewhere`と同じ役割で、同じ理由で要る——昇格後の検算は
    /// 剥がし終えたDACLを見るので、そこだけを見ると「対象が0件だった」と区別が付かない（B-09）。
    pub cleared_elsewhere: usize,
}

impl DeclarationRevokeReport {
    /// 剥がし残しが無いか（＝台帳の記録を捨ててよいか）。
    pub fn is_clean(&self) -> bool {
        self.still_on_root.is_empty()
    }
}

/// `subjects`（宣言から導出済みのcapability SID）のACEを`path`配下から剥がす。
///
/// **走査は新しく書かない。** [`revoke_workspace_sids_recursive`]（1ノード1読取・N主体を
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

    // rootの明示ACEを主体ごとに1件ずつ読み直す（walkの戻り値を根拠にしない）。
    for (sid, text) in subjects.iter().zip(report.targeted.iter()) {
        if matches!(sid_explicit_ace(path, sid.as_psid()), Ok(Some(_))) {
            report.still_on_root.push(text.clone());
        }
    }
    Ok(report)
}

/// `path`のrootに**いま残っている**宣言capabilityの主体（SID文字列）を読み取るだけの関数。
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

/// [§22.2.1] `path`に対して発行済みの**宣言capability**を台帳から引き、名指しで剥がす。
///
/// これが「分類器を使わず、宣言から導出したSIDを名指しで剥がす」の入口である。
/// ACLを列挙して「この主体は何者か」を推定する必要はそもそも無い——撤収すべき主体は
/// 宣言から一意に決まる（`revoke_subjects.rs`の分類器は`S-1-15-2-`しか列挙しないので、
/// capability SIDは構造的にあちらへ入らない。混ぜると[BUG-046](../../../../docs/bugs/BUG-046.md)の再現になる）。
///
/// **`workspace`が`None`＝そのパスへ発行された全workspaceの主体**を対象にする。これを
/// 使ってよいのは`harness fs revoke <path>`のように**そのパスを名指しした明示操作**だけで、
/// 暗黙の経路（起動時の自動整合・ポリシーエディタの整合）は必ず`Some`で絞ること
/// （[`super::fs_allow_capability_sids`]のdocと同じ制約）。
pub fn revoke_declaration_capabilities(
    path: &Path,
    workspace: Option<&Path>,
    progress: &dyn Fn(usize, usize),
) -> Result<DeclarationRevokeReport, AppContainerError> {
    let subjects = super::fs_allow_capability_sids(path, workspace);
    revoke_capability_subjects(path, &subjects, progress)
}
