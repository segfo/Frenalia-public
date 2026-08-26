//! [D-84] **workspaceツリーへ配る「バッジの集合」**と、それを1回の書込で置く口。
//!
//! # 何が困っていたのか
//!
//! Tier2aのファイルシステム境界は「許可したい各ノードのアクセス制御表（DACL）へ、
//! サンドボックスの主体宛の1行（ACE）を事前に書く」方式で張られている。その主体——以後
//! **バッジ**（capability SID）——は **(ワークスペースのパス, 書込モード)** から決まる（D-54）。
//!
//! **困りごとは費用そのものではなく、費用の取り消され方だった。** モードは2つあり
//! （[`WorkspaceMode`]）、**モードを切り替えるとバッジが変わって、既に配った26万件のACEが
//! 一斉に無効になる**。払い直しは一巡61.4秒（`plans/mac-spike/RESULTS.md` §S12）。
//! 「一度きり」の費用が、切り替えのたびに戻ってきていた。
//!
//! # 何をしているのか
//!
//! **全モードのバッジ宛ACEを、最初の1回で同時に置く。** そうすればモードを切り替えても
//! 配り直すものが無い。成立の根拠は実測が2つある。
//!
//! - **費用はゼロ**: 同一ノードのACEを3本まで増やしても、**1回の書込にまとめれば**時間は
//!   動かない（20,033／100,033ノードで1.0倍±3%。§S15-1）。**まとめなければ約2.9倍**払う——
//!   だからこのモジュールの関数はどれも「M本」を受け、呼び出し側でループを回させない。
//! - **安全性は保たれる**: 両モードのバッジ宛ACEが同じDACLに並んでいても、`ro`のバッジしか
//!   持たない子は作成・追記・削除がすべて`ERROR_ACCESS_DENIED`になる（陽性対照＝`rwx`の子は
//!   通る／陰性対照＝バッジ無しは読めもしない、の両方つきで実測。
//!   `plans/handoff/fs-boundary-cost/T-1.md`）。Windowsのアクセス判定は、トークンに入って
//!   いない主体宛のACEを読み飛ばすためである。
//!
//! # ここで守っていないもの（限界）
//!
//! - **「配れば見える」ではない。** 保護DACL（`SE_DACL_PROTECTED`）配下へは伝播が届かず、
//!   救済walk（[`super::fix_descendants_missing_aces`]）が別に要る。
//! - **子が名乗れるバッジは1本のままである。** 2本配ることと、子のトークンへ2本積むことは
//!   まったく別の話で、後者は**しない**（すればCoWの境界が消える）。積むのは
//!   `preflight`／`launch`が選ぶ「そのセッションのモードのバッジ」だけ。
//! - **モードの相互排他は撤廃していない。** 排他の根拠がACLではなくCoWの一貫性であることを
//!   `workspace_ledger`のモジュールdocで書き直しただけで、規則の存廃は本流の判断である
//!   （`plans/handoff/fs-boundary-cost/U-2.md`）。
//!
//! # `EnvironmentFacts`を更新しない理由（[D-84]）
//!
//! モデルへ送るシステムプロンプトの宣言点（`harness-core`の`EnvironmentFacts`）は、
//! **モデルから見て何が許され何が拒まれるか**が変わったときに追随させる規約になっている。
//! **D-84はそれを1ビットも変えていない。** 変えたのは「ツリーへ何本のACEを置くか」であって、
//! **子のトークンへ積むバッジは従来どおりそのセッションのモードのぶん1本だけ**だからである
//! （上の限界の2つ目）。`rwx`セッションの実効権限も、`--sandbox tier2a-cow`セッションが
//! workspace本体を書けないことも、D-84の前後で同一である——変わったのは
//! 「モードを切り替えたときに26万件を配り直すかどうか」という、モデルには見えない費用だけ。
//! 実際、`ro`のバッジしか持たない子は隣に`rwx`のACEが載っていても書込がすべて拒否される
//! （T-1が実子プロセスで実測）。

use super::*;

use crate::tier2a::workspace_ledger::WorkspaceMode;

/// そのモードのバッジがworkspaceツリーに対して持つアクセスマスク（[D-84]）。
///
/// **マスクを決めるのはバッジのモードであって、いま走っているセッションのモードではない。**
/// [D-84]以降、`ro`セッションの最中にも`rwx`バッジ宛のACEがツリーに載っている——そのACEに
/// `ro`のマスクを書いてしまうと、次に`rwx`で起動したセッションが書けなくなる（逆向きに
/// 間違えれば、`ro`のバッジで書けてしまいCoWの境界が消える）。**ここが唯一の対応表**である。
///
/// `match`は全分岐（`..`無し）で書く。[`WorkspaceMode`]へバリアントを足すと**ここが
/// コンパイルエラーになる**——それがこの関数を型で受けている理由である（`B-06`）。
pub(crate) fn workspace_mode_mask(mode: WorkspaceMode) -> u32 {
    match mode {
        // 通常起動。`WRITE_DAC`/`WRITE_OWNER`は含めない（`workspace_rwx_mask`のdoc）。
        WorkspaceMode::Rwx => workspace_rwx_mask(),
        // `--sandbox tier2a-cow`。D-13と同じ読取＋実行だけ（書込・削除のビットが入らないことが
        // CoWの境界そのもの）。
        WorkspaceMode::Ro => fs_access_mask(FsAccess::ReadExec),
    }
}

/// workspaceツリーへ配る**バッジ1本ぶん**の許可（主体とマスクの対）。
///
/// [D-84]で「両モードのバッジ宛ACEを1回の書込で同時に置く」ことにしたため、付与側の関数は
/// どれも「1本」ではなく「M本」を受ける形になった。**`PSID`は借用したポインタ**なので、
/// スレッドへ渡す（`grant_job`）ときは[`OwnedBadgeGrant`]を使う。
#[derive(Debug, Clone, Copy)]
pub struct BadgeGrant {
    pub sid: PSID,
    pub mask: u32,
}

/// [`BadgeGrant`]の所有版。背景ジョブ（`grant_job`）へ`move`するために要る。
#[derive(Debug, Clone)]
pub struct OwnedBadgeGrant {
    pub sid: crate::win_common::OwnedSid,
    pub mask: u32,
}

impl OwnedBadgeGrant {
    pub fn as_badge(&self) -> BadgeGrant {
        BadgeGrant {
            sid: self.sid.as_psid(),
            mask: self.mask,
        }
    }

    /// スライスまるごとを借用版へ落とす（呼び出し側で毎回同じ`map`を書かないため）。
    pub fn borrow_all(grants: &[OwnedBadgeGrant]) -> Vec<BadgeGrant> {
        grants.iter().map(OwnedBadgeGrant::as_badge).collect()
    }
}

/// [`BadgeGrant`]の並びを、ノードの種別に応じた継承フラグ付きの書込エントリへ写す。
///
/// ディレクトリは継承あり（`CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE`）、ファイルは
/// 継承なし——`acl_grant`の`grant_ace_raw`が単数でやっているのと**同じ規則**である
/// （2箇所で別々に決めると、片方だけ継承フラグが変わっても誰も気付かない、`B-05`）。
pub(crate) fn inheritable_grants(
    badges: &[BadgeGrant],
    is_dir: bool,
) -> Vec<super::acl_dacl_write::InheritableGrant> {
    let inheritance = if is_dir {
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
    } else {
        NO_INHERITANCE
    };
    badges
        .iter()
        .map(|badge| super::acl_dacl_write::InheritableGrant {
            sid: badge.sid,
            mask: badge.mask,
            inheritance,
        })
        .collect()
}

/// [D-84] **workspace rootへ、全モードのバッジ宛ACEを1回の書込でまとめて置く**（伝播なし）。
///
/// [`super::grant_workspace_root_rw_fast`]／[`super::grant_workspace_root_ro_fast`]は、これへ
/// バッジを1本だけ渡す薄い包みである（**実装は1つ**、`docs/CODE-STRUCTURE-RULES.md` §5.0）。
/// 製品の`preflight`はこの多本版を直接呼ぶ。
///
/// # なぜ1回にまとめるのか
///
/// バッジ1本ずつ書いてもrootは1ノードなので同期区間の費用は変わらないが、**同じ形を
/// 伝播側（[`propagate_workspace_root_grants`]）と救済walk側でも使う**——そちらは26万ノードに
/// 効き、主体ごとに書くと約2.9倍になる（`plans/mac-spike/RESULTS.md` §S15-1）。
/// 3箇所で書き方が割れないよう、口をここへ揃えてある。
#[track_caller]
pub fn grant_workspace_root_badges_fast(
    root: &Path,
    badges: &[BadgeGrant],
) -> Result<(), AppContainerError> {
    // BUG-059と同じ分岐（`grant_ace_access_if_file`のdoc）。ファイルに継承フラグを立てても
    // 害は無いが意味も無いので、`inheritable_grants`が`NO_INHERITANCE`を選ぶ。
    let is_dir = root.is_dir();
    let mut timing = PhaseTiming::start();
    super::acl_dacl_write::grant_aces_single_object(
        root,
        &inheritable_grants(badges, is_dir),
        IdempotentCheck::SkipIfSufficient,
    )?;
    timing.mark(&format!(
        "  fast (single-object) root grant, {} badge(s)",
        badges.len()
    ));
    Ok(())
}

/// [BUG-082 Part B] rootへの継承ACE伝播を**冪等チェック無しで無条件に**行う（[D-84]で
/// 全モードのバッジをまとめて配る形になった）。`grant_job`の背景フェーズだけが使う。
///
/// **`IdempotentCheck::Always`が必須の理由**: `preflight`の同期区間で先に
/// [`grant_workspace_root_badges_fast`]（`DaclWrite::SingleObject`）を通しているため、
/// この時点でrootは既に「要求マスクを満たしている」ように見える。通常の冪等スキップを
/// 使うと**伝播そのものが呼ばれない**——[BUG-081](../../../../docs/bugs/BUG-081.md)層1
/// （伝播を使う高速経路が、伝播しない書込APIへ差し替えられ、機能は壊れないまま無症状に
/// 退化していた）とまったく同じ形の罠なので、ここは意図を明示する専用関数にする。
///
/// [残課題#32] **配るのは[`super::acl_dacl_write::grant_aces_propagating`]（M本を1つのDACLへ
/// 畳んで1回だけ書く部品）である。** `IdempotentCheck::Always`は「冪等スキップで伝播が
/// *呼ばれない*」を防ぐもので、**必要だが十分ではなかった**——呼ばれても届いていなかった。
/// 十分にする側は部品が持つ（同モジュールのdocに実測表がある）。**両方要るので、どちらも外さない。**
///
/// バッジを1本増やしても費用は動かない（§S15-1で20,033／100,033ノードとも1.0倍±3%）。
/// **ただしそれは「1回の書込にまとめれば」の話**で、主体ごとに呼び直すと約2.9倍になる。
/// **呼び出し側でループを回さないこと。**
#[track_caller]
pub(crate) fn propagate_workspace_root_grants(
    root: &Path,
    badges: &[BadgeGrant],
) -> Result<(), AppContainerError> {
    let mut timing = PhaseTiming::start();
    super::acl_dacl_write::grant_aces_propagating(
        root,
        // rootは常にディレクトリ（ファイルのworkspaceは無い）。仮にファイルでも
        // `inheritable_grants`が継承フラグを落とすので、意味の無いフラグは立たない。
        &inheritable_grants(badges, root.is_dir()),
        IdempotentCheck::Always,
    )?;
    timing.mark(&format!(
        "  background: propagating root grant (unconditional, {} badge(s))",
        badges.len()
    ));
    Ok(())
}

/// [`propagate_workspace_root_grants`]の単数版。
///
/// **[D-84] 製品はもうここを通らない**（背景ジョブは全モードのバッジを1回で配る）。
/// 1主体で測る回帰テスト・コスト測定のために残してある薄い包みで、**判定も書込も多本版と
/// 同一**である（同じ関数を1本で呼ぶだけ）。
#[cfg(test)]
#[track_caller]
pub(crate) fn propagate_workspace_root_grant(
    root: &Path,
    sid: PSID,
    mask: u32,
) -> Result<(), AppContainerError> {
    propagate_workspace_root_grants(root, &[BadgeGrant { sid, mask }])
}

#[cfg(test)]
mod workspace_mode_mask_tests {
    use super::*;

    /// **`rwx`のバッジは書けて、`ro`のバッジは書けない。** ここが[D-84]の安全性の土台で、
    /// マスクを取り違えると「両方置いた」瞬間にCoWの境界が消える。
    ///
    /// 対で見る（`B-35`）——`ro`に書込ビットが無いことだけを測ると、**両方のマスクが
    /// 読取専用になった実装**でも緑になる（そのときworkspaceは誰からも書けなくなる）。
    ///
    /// # **複合マスクで測らない**（[BUG-048]と同じ罠）
    ///
    /// この検査を`ro & FILE_GENERIC_WRITE.0 == 0`と書くと**実装が正しくても落ちる**。
    /// `FILE_GENERIC_WRITE`と`FILE_GENERIC_READ`は`READ_CONTROL`(`0x0002_0000`)と
    /// `SYNCHRONIZE`(`0x0010_0000`)を**共有している**ので、読取専用のマスクと
    /// ANDを取っても`0x0012_0000`が残る。「読めるだけのACEを書込扱いする」この誤判定は
    /// [BUG-048]で実際に踏んでおり、`elevated_launch`の`DANGEROUS_WRITE_BITS`が
    /// 同じ理由で個別ビットを明示列挙している。**だからここも原子ビットで測る。**
    ///
    /// [BUG-048]: ../../../../docs/bugs/BUG-048.md
    #[test]
    fn only_the_rwx_badge_carries_the_write_and_delete_bits() {
        let rwx = workspace_mode_mask(WorkspaceMode::Rwx);
        let ro = workspace_mode_mask(WorkspaceMode::Ro);

        // `elevated_launch::DANGEROUS_WRITE_BITS`と同じ列挙（あちらは「非管理者が差し替え
        // られるか」を測る別の問いなので、定数は共有せず綴りだけ揃える）。
        for (bit, name) in [
            (0x0000_0002u32, "FILE_WRITE_DATA"),
            (0x0000_0004, "FILE_APPEND_DATA"),
            (0x0000_0010, "FILE_WRITE_EA"),
            (0x0000_0100, "FILE_WRITE_ATTRIBUTES"),
            (DELETE.0, "DELETE"),
        ] {
            assert_eq!(rwx & bit, bit, "the rwx badge must carry {name}");
            assert_eq!(ro & bit, 0, "the ro badge must not carry {name}");
        }
    }

    /// 上のテストが**複合マスクで書かれていたら落ちる**ことを、その場で示す。
    ///
    /// これは実装ではなく**測り方**を固定するテストである（[BUG-048]の再発防止）。
    /// 「読取専用マスクと`FILE_GENERIC_WRITE`のANDは0ではない」を明示的に記録しておくと、
    /// 次に誰かが「素直に複合マスクで測ればいいのでは」と書き直したときに、ここが
    /// **なぜそうしないのか**を答える。
    #[test]
    fn a_read_only_mask_still_shares_bits_with_the_composite_write_mask() {
        let ro = workspace_mode_mask(WorkspaceMode::Ro);
        // READ_CONTROL | SYNCHRONIZE。これが「roは書ける」の誤読を生む。
        assert_eq!(ro & FILE_GENERIC_WRITE.0, 0x0012_0000);
    }

    /// 読める・実行できるのは**両方**。`ro`のバッジで読めなくなると、CoWセッションから
    /// workspaceが一切見えない（拒否ではなく「無い」に見えるので気付きにくい、BUG-110）。
    #[test]
    fn both_badges_can_read_and_execute() {
        for mode in WorkspaceMode::ALL {
            let mask = workspace_mode_mask(mode);
            for (bit, name) in [
                (FILE_GENERIC_READ.0, "read"),
                (FILE_GENERIC_EXECUTE.0, "execute"),
            ] {
                assert_eq!(
                    mask & bit,
                    bit,
                    "the {} badge must carry {name}",
                    mode.as_str()
                );
            }
        }
    }

    /// **バッジどうしのSIDは違う**という前提の裏返し: マスクも同じであってはならない。
    /// 同じなら、モードを分けている意味がその時点で消えている。
    #[test]
    fn the_two_modes_do_not_end_up_with_the_same_mask() {
        assert_ne!(
            workspace_mode_mask(WorkspaceMode::Rwx),
            workspace_mode_mask(WorkspaceMode::Ro)
        );
    }

    /// どちらのバッジも`WRITE_DAC`/`WRITE_OWNER`を持たない——持つと、子が自分でACEを
    /// 足せてしまい**バッジを分けたこと自体が無意味になる**（T-1が実機で
    /// `Set-Acl`の拒否を両腕で確認している）。
    #[test]
    fn no_badge_can_rewrite_the_dacl() {
        // `WRITE_OWNER`は`windows`クレートのこの版が`Win32::Foundation`へ出していないので
        // 数値で書く（`elevated_launch.rs`が同じ理由で同じ値を持っている）。
        const WRITE_OWNER: u32 = 0x0008_0000;
        for mode in WorkspaceMode::ALL {
            let mask = workspace_mode_mask(mode);
            assert_eq!(
                mask & (WRITE_DAC.0 | WRITE_OWNER),
                0,
                "the {} badge must not be able to rewrite the DACL",
                mode.as_str()
            );
        }
    }
}
