//! 祖先ディレクトリチェーンへのtraverse ACE付与（D10）。
//!
//! `docs/phases/foundation/M12-shell-isolation-tiers.md`追記8で判明した根本原因
//! （ドライブルートのtraverse ACE欠如によりAppContainer子のFS I/Oが全滅する）の修復。
//! 付与そのものは`acl_grant::grant_ace_mask`を使い、本モジュールは「どのノードへ何を
//! 付けるか」の選定と、書込前の読み取り専用プレビューを持つ。

use super::*;

/// ドライブルート（例`C:\`）へ、`sid`の`FILE_TRAVERSE | FILE_READ_ATTRIBUTES`を単一・非継承で
/// 付与する（D10、`harness fs grant-traverse`本体）。`docs/phases/foundation/
/// M12-shell-isolation-tiers.md`追記8で判明した根本原因（ドライブルートのtraverse ACE欠如、
/// `FILE_TRAVERSE`単独では`Read Attributes`アクセス拒否が残り不十分）の修復そのもの。
/// ドライブルートのDACL変更には`WRITE_DAC`が要るため、非管理者では
/// `AppContainerError::AclGrant`（access denied）を返す（呼び出し側が「管理者で再実行」を促す）。
pub fn grant_traverse_drive_root(drive: &Path, sid: PSID) -> Result<(), AppContainerError> {
    grant_ace_mask(
        drive,
        sid,
        FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0,
        NO_INHERITANCE,
    )
}

/// `target`とその全祖先（ドライブルートまで）へ、`sid`の`FILE_TRAVERSE | FILE_READ_ATTRIBUTES`を
/// 単一・非継承で付与する（D10連鎖化、`TIER1A-OPEN-ISSUES.md`項目6「多階層祖先traverse ACE不足」の
/// 解消）。`C:\Users\<user>\.cargo`のようにドライブルート直下でないパスをpassthroughする場合、
/// `grant_traverse_drive_root`によるドライブルート単体への付与だけでは足りず、`C:\Users`・
/// `C:\Users\<user>`という中間の祖先にも個別にtraverse ACEが要ることが実機検証で判明した
/// （`docs/phases/foundation/M12-shell-isolation-tiers.md`追記10）。
///
/// `Path::ancestors()`はtarget自身→直近の親→…→ドライブルートの順で返すため、ここでは
/// ドライブルートから`target`へ向かう順（浅い方から深い方）に反転してから1ノードずつ付与する。
/// 祖先を先に開通させてから深いノードへ進む順序にしておけば、途中で失敗しても「到達不能な
/// 深いノードだけ付与済みで、そこへ辿り着くための浅い祖先が未付与」という手戻りしにくい
/// 半端な状態を避けられる。
///
/// 途中のノードで付与に失敗した場合は、そこで打ち切って`Err`を返す。**ただし戻り値の`Vec`には
/// 失敗した時点までに実際に付与が成功したノードを常に含める**（`Result`の成否に関わらず、
/// 呼び出し側は返ってきた`Vec`の全ノードをtraverse台帳へ記録しなければならない。台帳に載らない
/// まま実FS上にACEだけが残る「孤立ACE」を防ぐため。`CLAUDE.md`の台帳誤削除防止の思想と同根）。
pub fn grant_traverse_chain(
    target: &Path,
    sid: PSID,
) -> (Vec<std::path::PathBuf>, Result<(), AppContainerError>) {
    grant_traverse_chain_with_progress(target, sid, |_node, _result, _elapsed| {})
}

/// `grant_traverse_chain`と同じ処理を行うが、各ノードへの付与試行が完了するたびに
/// `on_node(node, result, elapsed)`を呼ぶ。特権分離ヘルパー（D-16、`privhelper.rs`）が
/// ノード別の所要時間をログへ残せるようにするためのフック（BUG-011の遅いプロファイル
/// ルート近傍書込みを、無言のブラックボックスにせず観測可能にする）。既存の
/// `grant_traverse_chain`はこの関数を空クロージャで包んだだけの薄いラッパであり、
/// 呼び出し側（CLI直接実行等）の挙動・シグネチャは変わらない。
pub fn grant_traverse_chain_with_progress(
    target: &Path,
    sid: PSID,
    mut on_node: impl FnMut(&Path, &Result<(), AppContainerError>, std::time::Duration),
) -> (Vec<std::path::PathBuf>, Result<(), AppContainerError>) {
    let mut chain: Vec<std::path::PathBuf> = target.ancestors().map(|p| p.to_path_buf()).collect();
    chain.reverse();

    let mut granted = Vec::with_capacity(chain.len());
    for node in &chain {
        let started = std::time::Instant::now();
        let result = grant_ace_mask(
            node,
            sid,
            FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0,
            NO_INHERITANCE,
        );
        on_node(node, &result, started.elapsed());
        if let Err(e) = result {
            return (granted, Err(e));
        }
        granted.push(node.clone());
    }
    (granted, Ok(()))
}

/// `grant_traverse_chain`の付与予定チェーンを、一切書込まずに読み取り専用で列挙する
/// （`harness fs grant-traverse --dry-run`、ユーザーが実書込前に対象ノードと既存ACE有無を
/// 確認できるようにする要件）。各ノードについて、現在`sid`宛の明示ACEがどのマスクを
/// 持っているか（`None`なら無し）を`sid_ace_mask`で読み取るだけで、`SetNamedSecurityInfoW`は
/// 一切呼ばない。`already_sufficient`が`true`のノードは、実行時に`grant_ace_mask`の
/// 冪等スキップ（本ファイル`grant_ace_mask`参照）によって書込みがスキップされる見込み。
pub struct TraversePreviewNode {
    pub path: std::path::PathBuf,
    pub existing_mask: Option<u32>,
    pub already_sufficient: bool,
}

pub fn preview_traverse_chain(target: &Path, sid: PSID) -> Vec<TraversePreviewNode> {
    const REQUIRED: u32 = FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0;
    let mut chain: Vec<std::path::PathBuf> = target.ancestors().map(|p| p.to_path_buf()).collect();
    chain.reverse();

    chain
        .into_iter()
        .map(|node| {
            let existing_mask = sid_ace_mask(&node, sid).unwrap_or(None);
            let already_sufficient = existing_mask
                .map(|m| m & REQUIRED == REQUIRED)
                .unwrap_or(false);
            TraversePreviewNode {
                path: node,
                existing_mask,
                already_sufficient,
            }
        })
        .collect()
}

/// `preflight`用: `target`の祖先チェーン（ドライブルートまで）が全ノードで既に
/// `FILE_TRAVERSE|FILE_READ_ATTRIBUTES`を持つか（＝privhelper経由の自動付与が不要か）を、
/// 一切書込まず判定する（`preview_traverse_chain`の読み取り専用ロジックをそのまま再利用、
/// `--dry-run`用の表示整形は行わない）。
pub fn traverse_chain_sufficient(target: &Path, sid: PSID) -> bool {
    preview_traverse_chain(target, sid)
        .iter()
        .all(|node| node.already_sufficient)
}
