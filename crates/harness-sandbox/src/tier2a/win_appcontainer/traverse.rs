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

/// [D-48] traverse ACEを1ノード撤収する**唯一の正規の扉**（`harness fs revoke-traverse <path>`本体）。
///
/// 宛先SID（capability SID）を引数で受けずここで自ら導出するため、呼び出し側がSIDを取り違えようが
/// ない（[BUG-061](../../../../docs/bugs/BUG-061.md)で実際に起きた事故の構造的な封じ込め）。
/// 汎用の[`revoke_ace`]は台帳に載ったノードのcapability SID宛ACEを剥がすことを拒否するので
/// （[BUG-046](../../../../docs/bugs/BUG-046.md)）、巻き戻したい経路は必ずここを通る。
///
/// **台帳エントリの除去はここでは行わない。** 昇格ヘルパー（`privhelper`）と本体では
/// `%APPDATA%`が同じとは限らないため、台帳の書き込みは非昇格側の呼び出し元に寄せる既存の
/// 分担をそのまま維持する。
///
/// # 走行中の他セッションがあるなら剥がさない（2026-08-21）
///
/// 祖先traverse ACEの宛先SIDは**セッションを跨ぐcapability SID**（D-37）なので、剥がした瞬間に
/// 走行中の全Tier2aセッションがサンドボックス内のFS I/Oを失う。対になる
/// `harness fs revoke-workspace`には同じ守りが既にある（`workspace_ledger::live_modes`。
/// 「実行中の他セッションから権限を奪わない」＝BUG-053と同じ原則）。
///
/// **ガードをここへ置くのは、呼び出し元3経路すべてがここを通るからである**
/// （既に昇格した本体からの直接・昇格ヘルパーの中・測定用テストからの直接）。
/// 昇格ヘルパーの中からでも生存判定が成立することは実測で確かめてある
/// （`plans/e2e/RESULTS.md`。台帳・名前付きmutexの2段とも昇格側から見える）。
///
/// **判定できないときは通す。** 生存判定に失敗したときに撤収を止めると、正当な
/// `harness fs revoke-traverse`が理由の分からない失敗をする。これは信頼境界ではないので
/// fail-closedにしない（D-48不変条件3と同じ向き）。
pub fn revoke_traverse_grant(path: &Path) -> Result<(), AppContainerError> {
    traverse_revoke_guard(path)?;
    let sid = traverse_capability_sid()?;
    revoke_ace_unguarded(path, sid.as_psid())?;
    assert_no_sid_ace(path, sid.as_psid())
}

/// [D-48] [`revoke_traverse_grant`]が撤収を拒む条件——**走行中の他セッションが1つでもあるか**。
///
/// **この判定を持つのはこの関数だけである。** 非昇格のCLI（`harness fs revoke-traverse`）は
/// privhelperへ委譲する**前**にここを見て早期に断る。UACを1回払わせてから拒否するのは
/// 払わせた意味が無く、`revoke-traverse-all`では台帳に載った件数だけUACが出るためである。
/// **ただし昇格側は非昇格側の判断を信用しない**——[`revoke_traverse_grant`]は昇格側でも
/// もう一度ここを通る（D-16「昇格側は渡された値を自分で検証する」）。判定を2箇所へ書き写すと
/// 片方だけ変わったときに答えがずれるので、関数は1つに保つ（B-13）。
pub fn traverse_revoke_guard(path: &Path) -> Result<(), AppContainerError> {
    let sessions = crate::tier2a::session_profile::other_live_profile_names();
    if sessions.is_empty() {
        return Ok(());
    }
    Err(AppContainerError::TraverseRevokeWhileSessionsLive {
        path: path.to_path_buf(),
        sessions,
    })
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

/// [残課題#68] 通行許可を書く**祖先の並び**を、浅い方から深い方の順で作る。
///
/// # 標的を実体へ解決してから並べる（2026-10-01、`plans/mac-spike/RESULTS.md` §S82で測った）
///
/// 許可を書くのは`SetNamedSecurityInfoW`で、**これはパスを辿る**——途中にジャンクションが
/// あると、許可はリンク自身ではなく**リンクの先の実体**に書かれる（実測）。綴りのまま並べると、
/// 次の2つがずれる。
///
/// - **台帳に載るパスと、実際に許可が書かれた場所がずれる。** 台帳は撤収の唯一の索引なので、
///   後からリンクが張り替えられると剥がす先が変わり、**実体に許可が残る**（`B-01`の非対称）
/// - **リンクの先の祖先に許可が付かない。** 綴りの祖先には付くが実体の祖先には付かないので、
///   その経路を通過できないまま終わることがある
///
/// 解決すれば、許可を書く先・台帳へ載る綴り・通過できる経路の3つが一致する。
///
/// **`\\?\`前置は落とす**——台帳の他の記録と綴りを揃えるため（`B-19`。揃えないと同じノードが
/// 2つの綴りで載る）。**解決できないときは綴りのまま進む**——ここで止めると、リンクを1つも
/// 含まない普通の経路まで付与できなくなる。
///
/// # 予告（[`preview_traverse_chain`]）と本番（[`grant_traverse_chain_with_progress`]）が
/// **同じ関数を通る**
///
/// 別々に並べると、予告が「ここへ付きます」と出した場所と実際に付く場所がずれる（`B-05`）。
fn traverse_chain_nodes(target: &Path) -> Vec<std::path::PathBuf> {
    let resolved = std::fs::canonicalize(target)
        .ok()
        .map(|p| {
            std::path::PathBuf::from(harness_change_ledger::path_rules::normalize_root_spelling(
                &p.to_string_lossy(),
            ))
        })
        .unwrap_or_else(|| target.to_path_buf());
    let mut chain: Vec<std::path::PathBuf> = resolved.ancestors().map(|p| p.to_path_buf()).collect();
    chain.reverse();
    chain
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
    let chain = traverse_chain_nodes(target);

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
    let chain = traverse_chain_nodes(target);

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

#[cfg(test)]
mod tests {
    use super::*;

    /// D-48の拒否は**無言にしない**。文言そのものを読む（B-32）——「拒否した」だけでは、
    /// 受け取った側が次に何をすればよいか分からず、逃がし弁を欲しがることになる。
    /// 逃がし弁を置かないと決めた（2026-08-21）ぶん、**この文面が出口の案内を担う**。
    #[test]
    fn the_refusal_names_the_live_sessions_and_the_way_out() {
        let message = AppContainerError::TraverseRevokeWhileSessionsLive {
            path: std::path::PathBuf::from(r"C:\harness-e2e\probe"),
            sessions: vec!["harness.shell.sandbox.999-1".to_string()],
        }
        .to_string();

        // 何を拒んだか（対象パス）。
        assert!(message.contains(r"C:\harness-e2e\probe"), "{message}");
        // 誰が生きているか。名前が出ないと閉じる相手を特定できない。
        assert!(message.contains("harness.shell.sandbox.999-1"), "{message}");
        assert!(message.contains("1 harness session(s)"), "{message}");
        // 出口の案内と、逃がし弁が「無い」ではなく「意図的に置いていない」ことの明示。
        assert!(message.contains("Close them"), "{message}");
        assert!(message.contains("no --force"), "{message}");
    }

    /// 複数生きているときは全部名指しする（1件だけ出して残りを隠さない）。
    #[test]
    fn every_live_session_is_listed() {
        let message = AppContainerError::TraverseRevokeWhileSessionsLive {
            path: std::path::PathBuf::from(r"C:\x"),
            sessions: vec!["a".to_string(), "b".to_string()],
        }
        .to_string();
        assert!(message.contains("2 harness session(s)"), "{message}");
        assert!(message.contains("a, b"), "{message}");
    }
}

/// **「昇格を要求するかどうか」の判定を、実マシンに対して測る**（読み取り専用・非昇格）。
///
/// # なぜこれが要るのか（測り方の失敗から来ている）
///
/// §22.3.2の移行の実機E2Eで、通過許可の台帳が7→10件へ増えた。その理由を
/// 「実際に走らせて記録の増減を見る」形で調べようとしたが、**一度ACEが付くと冪等スキップで
/// 二度と差が出ない**ので、事後には決着させられなかった——**測ると答えが消える測り方**だった。
///
/// 抜け道は単純で、**測るたびに新しいディレクトリを切ればよい**。まだ誰も許可を付けていない
/// 場所なら、判定は何度でも同じ答えを返す。ここが書込を一切しない
/// （[`preview_traverse_chain`]は`sid_ace_mask`で読むだけ）ので、測っても状態は変わらない。
///
/// # 何が言えて、何が言えないか
///
/// 言えるのは「**新しい場所は不足と判定され、付与済みの場所は充足と判定される**」までである。
/// 「どのパスについてこれを聞くか」は別の関数（`preflight`の`traverse_targets_for`）が決めており、
/// そちらは実マシンを読まない純粋関数として別に固定してある。**2つ揃って初めて
/// 「何が要求されるか」が言える**ので、片方だけを根拠にしないこと。
#[cfg(all(windows, test))]
mod machine_probe_tests {
    use super::*;

    /// **対で測る**（`B-35`）——「新しい場所は不足」だけだと、判定が**常に不足**へ壊れても緑になる。
    /// そして常に不足へ壊れると、**起動のたびにUACが出る**（D-37がleafを対象外にした理由そのもの）。
    /// だから「付与済みの場所は充足」を同じテストで測る。
    ///
    /// 実行:
    /// `cargo test -p harness-sandbox --lib -- --ignored --nocapture a_never_granted_directory`
    #[test]
    #[ignore = "real machine: reads DACLs under C:\\ (read-only, no elevation)"]
    fn a_never_granted_directory_is_judged_insufficient_and_a_granted_one_is_not() {
        let sid = match crate::tier2a::win_appcontainer::traverse_capability_sid() {
            Ok(sid) => sid,
            Err(e) => panic!("traverse capability SID must be derivable: {e}"),
        };

        // 禁止側: いま切ったばかりの場所。**測るたびに新しい名前**にするので、
        // 前の実行の結果を引き継がない。
        let fresh = std::path::PathBuf::from(format!(
            r"C:\harness-traverse-probe-{}-{}",
            std::process::id(),
            harness_grant_ledger::now_unix_secs()
        ));
        std::fs::create_dir_all(&fresh).expect("probe dir");
        // 書込は一切しないが、パニックしても残さない（`B-27`）。
        let _guard = super::super::test_support::scopeguard(|| {
            let _ = std::fs::remove_dir_all(&fresh);
        });

        let chain = preview_traverse_chain(&fresh, sid.as_psid());
        for node in &chain {
            println!(
                "  {:<60} mask={:?} sufficient={}",
                node.path.display(),
                node.existing_mask,
                node.already_sufficient
            );
        }
        assert!(
            !traverse_chain_sufficient(&fresh, sid.as_psid()),
            "a directory created seconds ago must be reported as needing a traverse grant; \
             if this is already 'sufficient', the judgment cannot distinguish granted from \
             ungranted and nothing would ever be requested"
        );
        // **その不足が「この新しいノードだけ」であることまで見る。** ここを見ないと、
        // ドライブルートごと不足に壊れていても同じく緑になる。
        let insufficient: Vec<&std::path::PathBuf> = chain
            .iter()
            .filter(|n| !n.already_sufficient)
            .map(|n| &n.path)
            .collect();
        assert_eq!(
            insufficient,
            vec![&fresh],
            "only the brand-new node should be missing the grant"
        );

        // 許可側: 既に付与済みのドライブルート。**これが充足でなければ、上の「不足」は
        // 移行の話ではなく単に何も付いていないマシンを見ているだけになる。**
        assert!(
            traverse_chain_sufficient(std::path::Path::new(r"C:\"), sid.as_psid()),
            "C:\\ has been granted on this machine (traverse ledger), so it must read as \
             sufficient; if not, the measurement above says nothing about the migration"
        );
    }

    /// [残課題#68] **リンク越しの綴りで頼まれても、許可を書く先と台帳へ載る綴りが一致する。**
    ///
    /// # 壊れた状態を一文で
    ///
    /// 台帳には`…\link\deep`と載るのに、許可は`…\real\deep`に書かれている。
    /// 後でリンクが張り替えられると、撤収は別の場所を剥がしに行き、**元の実体に許可が残る**。
    #[test]
    #[cfg(windows)]
    fn the_traverse_chain_is_resolved_so_the_ledger_matches_where_the_ace_lands() {
        let root = tempfile::tempdir().expect("tempdir");
        let real = root.path().join("real");
        std::fs::create_dir_all(real.join("deep")).expect("real dirs");
        let link = root.path().join("link");
        let status = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .stdout(std::process::Stdio::null())
            .status()
            .expect("run mklink");
        assert!(status.success(), "mklink /J failed; the arm cannot be measured");

        let chain = traverse_chain_nodes(&link.join("deep"));

        // 実体の経路が並ぶ——**リンクの綴りは1つも出ない**。
        assert!(
            chain.iter().all(|p| !p.to_string_lossy().contains("link")),
            "the chain still carries the link spelling, so the ledger would not match where the ACE \
             lands: {chain:?}"
        );
        // 実体の末端と、その親の両方が並ぶ（親が抜けるとその経路を通過できない）。
        let real_canonical = std::path::PathBuf::from(
            harness_change_ledger::path_rules::normalize_root_spelling(
                &std::fs::canonicalize(&real)
                    .expect("canonicalize the real dir")
                    .to_string_lossy(),
            ),
        );
        assert!(
            chain.contains(&real_canonical),
            "the resolved parent is missing, so the child could not traverse into it: {chain:?}"
        );
        assert!(
            chain.contains(&real_canonical.join("deep")),
            "the resolved leaf is missing: {chain:?}"
        );
        // 浅い方から深い方の順（途中で失敗しても、到達できない深い段だけが残る形にしない）。
        assert_eq!(
            chain.last(),
            Some(&real_canonical.join("deep")),
            "the chain must end at the deepest node: {chain:?}"
        );
    }

    /// **対（許可側）**: リンクを1つも含まない普通の綴りでは、並びは今までどおりである。
    ///
    /// これが無いと、「標的が何であれ空の並びを返す」実装でも上の試験が緑になる（`B-35`）。
    #[test]
    #[cfg(windows)]
    fn a_plain_path_without_links_keeps_the_same_traverse_chain() {
        let root = tempfile::tempdir().expect("tempdir");
        let deep = root.path().join("a").join("b");
        std::fs::create_dir_all(&deep).expect("dirs");

        let chain = traverse_chain_nodes(&deep);

        let expected = std::path::PathBuf::from(
            harness_change_ledger::path_rules::normalize_root_spelling(
                &std::fs::canonicalize(&deep)
                    .expect("canonicalize")
                    .to_string_lossy(),
            ),
        );
        assert_eq!(chain.last(), Some(&expected), "chain={chain:?}");
        assert!(
            chain.len() > 2,
            "the ancestors must still be there: {chain:?}"
        );
        // ドライブルートから始まる（浅い方が先）。
        assert_eq!(
            chain.first().map(|p| p.to_string_lossy().len()),
            chain.iter().map(|p| p.to_string_lossy().len()).min(),
            "the chain must start at the shallowest node: {chain:?}"
        );
    }

    /// **解決できない標的（まだ無いパス）でも、並びは空にならない。**
    ///
    /// 空を返すと、付与が1件も走らないまま成功に見える（成功に見える失敗、`B-09`）。
    #[test]
    #[cfg(windows)]
    fn a_target_that_cannot_be_resolved_still_yields_its_spelled_chain() {
        let root = tempfile::tempdir().expect("tempdir");
        let missing = root.path().join("not-yet").join("deep");

        let chain = traverse_chain_nodes(&missing);

        assert!(
            chain.contains(&missing),
            "the spelled target must remain when it cannot be resolved: {chain:?}"
        );
        assert!(chain.len() > 2, "chain={chain:?}");
    }

}
