//! [BUG-145](../../../../docs/bugs/BUG-145.md) の実測プローブ。
//! **保護したノード「自身」が、親の伝播で保護を失うのか**を測る。
//!
//! # 既存の2本が測っていない場所
//!
//! 同じ対象を測るプローブは既に2本ある。**どちらも保護したノード自身は見ていない。**
//!
//! - [`super::dacl_protection_probe_tests`]（BUG-083）は「どの書込口なら保護が立つか」と、
//!   **保護したノードの「下」のファイル**へ伝播が届くかを測る（`child = sub/f.txt`）。
//!   保護ノード自身のACE一覧は伝播後も記録しているが、**判定に使っているのは「失われた」ACEだけ**で、
//!   「増えた」ACEも保護ビットの行方も見ていない。
//! - 残課題#32の機序のプローブ（2026-09-30に消した。記録は`plans/mac-spike/RESULTS.md` §S11）は
//!   伝播が既存の子孫へ届くかを測っていた。保護そのものは扱っていなかった。
//!
//! BUG-145で観測されたのは**保護ノード自身**が保護を失い、継承由来の許可ACEを載せる現象なので、
//! どちらの計器にも写らない。
//!
//! # 3つの軸で振る
//!
//! **軸1（手順）**は15ケース。**軸3（深さ）は配布の対象が保護ノードの親か祖父か**で、
//! 後者は`--fs-allow <祖先>/**`が実際に使う形である（ケース9・10）。**軸2（置き場）は6水準で、
//! これを外すと再現しない可能性がある**——[`super::super::acl_dacl_write`]のモジュールdocは
//! 「同じ書込列でもツリーの置き場所で伝播の挙動が反転した」実測を持っており、BUG-145の実測は
//! `C:\`直下（`C:\harness-Tier2a-verify-*`）だった。**`%TEMP%`だけで測ると取り逃す。**
//!
//! # 原因は特定済みである（**このプローブが何を確定させたか**）
//!
//! **保護の書込が冪等スキップで丸ごと省かれていた。** [`super::remove_sid_aces_and_protect`]は
//! 「剥がすACEが1本も無く、かつ既に保護済みなら書かずに戻る」——そして`C:\`から降りるツリーでは
//! **新しく作ったディレクトリが最初から`SE_DACL_PROTECTED`付きで生まれる**ので、この条件が
//! 成立して**一度も書かない**。親からの配布はその「書いていない保護」を消す。
//!
//! 確定させたのは**ケース14**である——製品と同じ剥がし方・同じ書込で、
//! **中身を1バイトも変えずにスキップだけ外す**と、落ちていた4水準すべてで無傷になる。
//! ケース11・12も無傷だが、あちらは書くDACLの中身も変えているので原因を1点に絞れない。
//!
//! # 判定に使わない値を1つ必ず読む（**対照**）
//!
//! `open/f.txt`（保護していない兄弟の配下）へ伝播が届いたかを毎回読む。**ここが届いて
//! いなければ、そのケースは「伝播が不発だった」のであって「保護が効いた」ではない。**
//! これが無いと、何も起きなかった状態を合格と読む。
//!
//! # 前提と安全性
//!
//! - **管理者権限は不要**。祖先のDACLには一切触れない（伝播はケースrootとその配下にしか及ばない）。
//! - **台帳を触らない**。宛先SIDは[`super::super::capability_sid_from_name`]の純粋導出のみを使う
//!   （`workspace_capability_sid`は`%APPDATA%`へ実体を作るので使わない）。
//! - **合否を判定しない観測用テスト**である（BUG-083のプローブと同じ思想）。アサートするのは
//!   実験の前提が崩れていないかだけで、`panic!`させるとどのケースがどう出たかが出力に残らない。
//! - 実験ツリーは**消さない**（PowerShellの`Get-Acl`で独立に確かめられるようにするため）。
//!   毎回先頭で作り直す。**置き場を6水準へ広げたので後始末も6箇所ある**
//!   （`subst`の仮想ドライブだけはDropで自動的に消える）:
//!
//! ```powershell
//! Remove-Item -Recurse -Force -ErrorAction SilentlyContinue `
//!   C:\harness-bug145-probe, C:\harness-bug145-deep, `
//!   "$env:USERPROFILE\harness-bug145-probe", `
//!   "$env:TEMP\harness-bug145-probe", `
//!   (Join-Path (Split-Path -Parent $PWD) 'harness-bug145-probe')
//! ```
//!
//!   最後の1つは**このリポジトリの親ディレクトリ**（実ワークスペースの隣）で、
//!   リポジトリの中には入らないので`git status`には出ない。
//!
//! - **費用の測定も同じファイルにある**（[`control_dir_protect_skip_cost_probe`]）。
//!   原因が「スキップ」に確定したので、**その直し方の費用**がここで要るためである。
//!   あちらのツリーは`TestDirGuard`がDropで消す。
//!
//! # 寿命: 消さない（流用する測定として残す）
//!
//! BUG-145そのものは閉じたが、**保護したノード自身の保護ビットと許可ACEを、置き場6水準で
//! 撃ち分けられる計器はここにしか無い**。BUG-145の案A（伝播の書込を分ける）の採否と、
//! 保護の書き方を変えたときの再確認に使う（`docs/CODE-STRUCTURE-RULES.md`規則2の例外）。
//! 残してある測定の一覧は`.claude/skills/measurement-review/SKILL.md`「残してある測定」。

use super::*;

use windows::Win32::Security::Authorization::DENY_ACCESS;

// DACLのACEを1件ずつ「種別;フラグ;マスク;SID」の文字列にする部品。BUG-083のプローブと
// **同じものを使う**——同じDACLを2つの実装で読むと、どちらが正しいかを別途決めることになる。
use super::test_support::describe_dacl_aces;

/// 実験用ツリーの置き場。
///
/// # 「置き場」という1語に**3つの変数**が畳まれていた
///
/// 最初の版は2水準（`C:\`直下と`%TEMP%`配下）で、片方だけ落ちた。**しかしこの2つは
/// 3つの点で違う**——ドライブ直下からの段数・ユーザープロファイル配下かどうか・
/// 構文上ドライブ直下かどうか。**どれが効いているのかを1差分で分けるために6水準へ広げた。**
///
/// | 水準 | 段数 | プロファイル配下 | 構文上ドライブ直下 |
/// |---|---:|---|---|
/// | `drive-root` | 1 | ✗ | ✓ |
/// | `drive-root-deep` | 6 | ✗ | ✗ |
/// | `user-profile-root` | 3 | ✓ | ✗ |
/// | `real-workspace-parent` | 実ワークスペースと同じ | ✓ | ✗ |
/// | `user-temp` | 6 | ✓ | ✗ |
/// | `subst-drive-root` | 1 | ✓（実体） | ✓ |
///
/// `drive-root-deep`と`user-temp`は**段数を揃えてある**ので、この2つの差は
/// 「プロファイル配下かどうか」だけになる。`subst-drive-root`は実体が`%TEMP%`配下なので、
/// `user-temp`との差は「構文上ドライブ直下かどうか」だけになる。
///
/// # なぜ`real-workspace-parent`が要るのか（**この水準が本命**）
///
/// **実ワークスペースはユーザープロファイル配下にある**（このリポジトリ自身がそう）のに、
/// この欠陥を実証したテストはワークスペースを**ドライブ直下**に作っている
/// （[`super::grant_job_contention_tests`]が`TestDirGuard::create`を使う）。
/// **実運用の場所で再現するのかを一度も測っていない。**
struct Placement {
    label: &'static str,
    root: PathBuf,
    /// この置き場を成立させている資源。**Dropで撤収する**ので測定が終わるまで生かす。
    _drive: Option<super::test_support::SubstDrive>,
}

/// 6水準を組み立てる。**パスを直書きしない**——実ワークスペースの親はテストバイナリの
/// 位置から導出する（[`super::test_support::harness_exe`]と同じやり方）ので、
/// このリポジトリを別の場所へ置いても水準の意味が変わらない。
///
/// `subst`の仮想ドライブが取れなければ、その水準だけ落として続ける（**黙って落とさず**、
/// 呼び出し側が水準の数を印字する）。
fn placements() -> Vec<Placement> {
    const LEAF: &str = "harness-bug145-probe";
    let mut out = vec![
        Placement {
            label: "drive-root",
            root: PathBuf::from("C:\\").join(LEAF),
            _drive: None,
        },
        Placement {
            // `%TEMP%`と**段数を揃えてある**（どちらもドライブ直下から6段目）。
            label: "drive-root-deep",
            root: PathBuf::from("C:\\harness-bug145-deep")
                .join("a")
                .join("b")
                .join("c")
                .join("d")
                .join(LEAF),
            _drive: None,
        },
        Placement {
            label: "user-profile-root",
            root: user_profile_root().join(LEAF),
            _drive: None,
        },
        Placement {
            label: "real-workspace-parent",
            root: real_workspace_parent().join(LEAF),
            _drive: None,
        },
        Placement {
            label: "user-temp",
            root: std::env::temp_dir().join(LEAF),
            _drive: None,
        },
    ];
    if let Some(drive) = super::test_support::SubstDrive::create() {
        out.push(Placement {
            label: "subst-drive-root",
            root: drive.root().join(LEAF),
            _drive: Some(drive),
        });
    }
    out
}

/// ユーザープロファイルのルート。`%TEMP%`から`AppData\Local\Temp`の3段を戻して求める
/// ——`%USERPROFILE%`が設定されていない実行環境でも同じ場所を指すようにするため。
fn user_profile_root() -> PathBuf {
    let mut p = std::env::temp_dir();
    for _ in 0..3 {
        p.pop();
    }
    p
}

/// このリポジトリの**親ディレクトリ**＝実ワークスペースが置かれている場所。
///
/// テストバイナリは`<repo>/target/debug/deps/`配下にあるので、[`repo_root`]から1つ戻る。
fn real_workspace_parent() -> PathBuf {
    let mut p = repo_root();
    p.pop();
    p
}

/// このリポジトリのルート。テストバイナリの位置から導出する（パスを直書きしない）。
fn repo_root() -> PathBuf {
    let mut p = std::env::current_exe().expect("current_exe");
    p.pop(); // 実行ファイル名
    p.pop(); // deps/
    p.pop(); // debug/
    p.pop(); // target/
    p
}

/// 伝播書込をどこへ撃つか。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PropagateTo {
    /// 撃たない（対照）。
    Nowhere,
    /// ケースroot（＝製品と同じ。保護ノードの親）。
    CaseRoot,
    /// 保護していない兄弟だけ（案①の前提）。
    SiblingOnly,
}

/// 試す手順。**ケース2を基準に、1つずつ差分を作ってある。**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Case {
    /// 高速付与 → 保護 → **伝播しない**。対照。伝播以外の理由で保護が落ちていないこと。
    NoPropagate,
    /// 高速付与 → 保護 → ケースrootへ伝播。**製品と同じ形。**
    Production,
    /// 保護 → ケースrootへ伝播（**高速付与を抜く**）。直前のカーネル口の書込が引き金か。
    NoPriorRootWrite,
    /// 高速付与 → 保護 → **兄弟だけ**へ伝播。**案①の前提**（配布経路から外せば無傷か）。
    SiblingOnly,
    /// 高速付与 → 保護＋明示の拒否ACE → ケースrootへ伝播。**案②の前提**（明示ACEは生き延びるか）。
    ExplicitDeny,
    /// 高速付与 → 保護 → **同じDACLを保護つきでもう一度書く**（拒否ACEは足さない）→ ケースrootへ伝播。
    ///
    /// **ケース5の交絡を外すためだけに在る。** ケース5はケース2に対して2つ違う——
    /// 「拒否ACEが載っている」ことと「保護の書込がもう1回走った」こと。**どちらが効いたのかは、
    /// 拒否ACEを外した書込をもう1本並べないと分からない**（`B-29`: 1差分×1ケース）。
    ReprotectNoDeny,
    /// 高速付与 → **剥がす＋拒否ACE＋保護を1回の書込で** → ケースrootへ伝播。
    ///
    /// **案②を本当に測れるのはここだけである。** ケース5は書込が2回になった副作用で保護が
    /// 守られてしまい、**拒否ACEが「保護が落ちた状態でも残るか」を一度も試していない**。
    /// 書込を1回に戻せば保護は落ちるはずなので、そこで拒否ACEが生き延びるかを見る。
    DenyInOneWrite,
    /// **ケース2をそのまま繰り返すだけ。** 実行順そのものが結果を作っていないことを見る対照で、
    /// ケース2と同じ手順を行列の最後に置く。**ここが2と食い違ったら、読んでいるのは手順ではなく
    /// 実行順である**（`B-28`: 1回のテストは反復を保証しない）。
    ProductionRepeat,
    /// `ws/guarded`を保護 → **祖先**へ配布。**中間`ws`には何も書かない。**
    ///
    /// `--fs-allow` が祖先を指したときの形で、深さ1のケース1〜8は「親から配る」までしか
    /// 見ていない。**まず「深さ2へ配布が届くのか」から確かめる**——届かなければ、
    /// 保護が落ちるかどうか以前に測定が成立しない。
    AncestorCleanHolder,
    /// ケース9に**中間`ws`への高速付与**（別の宛先SID、カーネル口）を足してから祖先へ配布する。
    ///
    /// 製品ではここがworkspace rootに当たり、preflightのカーネル口の書込を受けている。
    /// **9との差はその1点だけ**で、深さ1でケース2と3を分けた変数と同じものである。
    AncestorWrittenHolder,
    /// 製品と同じ剥がし方 → **書く直前に継承由来フラグを落とす** → 1回で書く → 親へ配布。
    ///
    /// **仮説H1（自己不整合）だけを動かす。** 製品の保護は、継承由来のフラグが立ったままの
    /// ACEを「継承を受け付けない」DACLとして書いている。この矛盾した状態が親からの配布に
    /// 耐えないのではないか、を測る。
    StripInheritedProtect,
    /// 製品と同じ剥がし方 → **`SetEntriesInAclW`へ通す（ACEは足さない）** → 1回で書く → 親へ配布。
    ///
    /// **仮説H2（組み直し）だけを動かす。** 無傷だったケース5・6・7はいずれも、最後の書込の
    /// DACLが`SetEntriesInAclW`（正規順へ組み直す口）を通っているか、保護済みノードから
    /// 読み直したものだった。製品の`copy_dacl_excluding_sids`は**ACEをそのまま写す**。
    ///
    /// **ケース2と6の保護直後のACEは完全に同一だった**（実測）ので、差はDACLの「中身」ではなく
    /// 「どう組んで書いたか」の側にある——それがこのケースの狙いである。
    CanonicalizeProtect,
    /// 組み直したうえで、**わざと全ACEへ継承由来フラグを立て直してから**書く → 親へ配布。
    ///
    /// **仮説H1をひっくり返して確かめる逆向きの対照である。** 11・12が無傷になったので
    /// 「書くDACLのACEが継承由来を名乗っていなければ耐える」が残る仮説だが、それが本当なら
    /// **名乗らせれば壊れるはず**である。壊れなければH1は外れで、共通項は別にある。
    ///
    /// **無傷の形を並べるだけでは原因を特定できない**——狙って壊せて初めて確定する。
    ForceInheritedProtect,
    /// 製品とまったく同じ剥がし方・同じ書込で、**冪等スキップだけを外す**。
    ///
    /// # これが原因を1点に絞る唯一のケースである
    ///
    /// 製品の[`remove_sid_aces_and_protect`]は「剥がすACEが1本も無く、かつ既に保護済みなら
    /// 書かずに戻る」という冪等スキップを持つ（`revoke.rs`）。**`C:\`から降りるツリーでは、
    /// 新しく作ったディレクトリが最初から`SE_DACL_PROTECTED`付きで生まれる**ので、
    /// この条件が成立して**保護の書込が1回も走らない**。
    ///
    /// ケース11・12も無傷だが、あちらは**書くDACLの中身も変えている**（フラグを落とす／
    /// 組み直す）ので、「書いたこと」と「中身を変えたこと」のどちらが効いたのか分からない。
    /// **このケースは中身を1バイトも変えずに書くだけ**なので、無傷になれば
    /// **原因はスキップそのもの**に確定する。
    ForcedWriteProtect,
    /// 剥がしたうえで**拒否ACEを足し、保護は立てずに**1回で書く → 親へ配布。
    ///
    /// # 「拒否ACEは保護が落ちても残るのか」を測れる唯一の形
    ///
    /// 記録が「拒否ACEを置いた2ケース（5・7）はどちらも保護が落ちなかったので、
    /// 拒否が最後の砦として働く場面が一度も発生していない」と書いたまま残っていた。
    /// **原因が分かったいま、その理由も分かる**——どちらも「書いた」ので保護が確立し、
    /// 落ちようがなかった。
    ///
    /// **書けば保護が立ってしまうなら、最初から保護を立てずに書けばよい。** そうすれば
    /// 「保護が無い状態で親から配布を受けた拒否ACE」が観測できる。
    /// これは製品に入れる形ではなく、**問いに答えるためだけの形**である。
    DenyWithoutProtection,
    /// 製品と同じ剥がし方 → **印つき**（保護＋自動継承）で1回書く → 親へ配布。
    ///
    /// # 「自分が書いた印」が作れるかを測る
    ///
    /// この欠陥の核心は「**保護されている**」と「**自分が保護した**」が区別できないことだった。
    /// OSが自力で作る状態は保護のみ（`0x9004`）か自動継承のみ（`0x8404`）のどちらかなので、
    /// **両方立てれば印になる**——という仮説を測る。
    ///
    /// ここで答えるのは3つ: (a) その組合せが**保存されるか**（Windowsが正規化しないか）、
    /// (b) 保存されても**継承を遮断したままか**、(c) 親からの配布に**耐えるか**。
    MarkedProtect,
    /// ケース16のあと、**2回目は印を見て飛ばす**（＝何も書かない）→ 親へ配布。
    ///
    /// **仕組みの本体はここである。** 印が作れても「印があるノードを飛ばしてよい」が
    /// 成り立たなければ、結局毎回書くことになって費用は減らない。
    MarkedProtectThenSkip,
    /// aclapi（.NETの`SetAccessRuleProtection`と同じ口）で保護 → 親へ配布。
    ///
    /// # 印が**一意か**を測る負の対照
    ///
    /// 他人の道具が立てた保護が同じ組合せになるなら、**自分が書いていないノードを
    /// 「書いた」と誤認する**——いまと同じ欠陥がそのまま戻る。
    /// エクスプローラや.NETが通る口で保護して、制御ビットがどうなるかを見る。
    AclapiProtect,
    /// 製品と同じ剥がし方 → **aclapiの口で保護を書く** → 親へ配布。
    ///
    /// # これが「印つきで直す」ときの製品の形である
    ///
    /// ケース16で分かったのは、**カーネルの口では`SE_DACL_AUTO_INHERITED`が保存されない**
    /// （立てて渡しても`0x9004`になる）こと。ケース18で分かったのは、**aclapiの口なら
    /// `0x9404`が保存され、配布にも耐える**こと。
    ///
    /// ケース18は**宛先SIDのACEを剥がしていない**ので製品の形ではない。ここは剥がしと
    /// aclapiの保護を組み合わせて、**剥がせること・印が付くこと・配布に耐えること**を
    /// 同時に確かめる。
    AclapiStripAndProtect,
    /// **修正前の製品の形**——「剥がすACEが無く、かつ保護済みなら書かない」を再現する。
    ///
    /// # 直したあとも壊れる形を表に残すために在る
    ///
    /// 製品を直すとケース2（製品の形）は無傷になり、**この行列は欠陥を再現できなくなる**。
    /// 壊れる形が1本も無い表は、計器が生きているかどうかを言えない
    /// （`B-35`: 禁止側だけ／許可側だけの検証は片方が死んでも緑になる）。
    ///
    /// **ここが落ちなくなったら、それは環境が変わったということである**——
    /// 表の読み方そのものを見直すこと。
    LegacySkipProtect,
}

const CASES: &[Case] = &[
    Case::NoPropagate,
    Case::Production,
    Case::NoPriorRootWrite,
    Case::SiblingOnly,
    Case::ExplicitDeny,
    Case::ReprotectNoDeny,
    Case::DenyInOneWrite,
    Case::ProductionRepeat,
    Case::AncestorCleanHolder,
    Case::AncestorWrittenHolder,
    Case::StripInheritedProtect,
    Case::CanonicalizeProtect,
    Case::ForceInheritedProtect,
    Case::ForcedWriteProtect,
    Case::DenyWithoutProtection,
    Case::MarkedProtect,
    Case::MarkedProtectThenSkip,
    Case::AclapiProtect,
    Case::AclapiStripAndProtect,
    Case::LegacySkipProtect,
];

impl Case {
    fn label(self) -> &'static str {
        match self {
            Self::NoPropagate => "1-no-propagate",
            Self::Production => "2-production",
            Self::NoPriorRootWrite => "3-no-prior-root-write",
            Self::SiblingOnly => "4-sibling-only",
            Self::ExplicitDeny => "5-explicit-deny",
            Self::ReprotectNoDeny => "6-reprotect-no-deny",
            Self::DenyInOneWrite => "7-deny-in-one-write",
            Self::ProductionRepeat => "8-production-repeat",
            Self::AncestorCleanHolder => "9-ancestor-clean-holder",
            Self::AncestorWrittenHolder => "10-ancestor-written-holder",
            Self::StripInheritedProtect => "11-strip-inherited-protect",
            Self::CanonicalizeProtect => "12-canonicalize-protect",
            Self::ForceInheritedProtect => "13-force-inherited-protect",
            Self::ForcedWriteProtect => "14-forced-write-protect",
            Self::DenyWithoutProtection => "15-deny-without-protection",
            Self::MarkedProtect => "16-marked-protect",
            Self::MarkedProtectThenSkip => "17-marked-protect-then-skip",
            Self::AclapiProtect => "18-aclapi-protect",
            Self::AclapiStripAndProtect => "19-aclapi-strip-and-protect",
            Self::LegacySkipProtect => "20-legacy-skip-protect",
        }
    }

    /// 保護の前に`holder`（保護ノードの親）へ高速付与（伝播しない口）を通すか。
    ///
    /// **深さ2ではここが唯一の差分である**（ケース9は掛けない・10は掛ける）。
    fn fast_grants_holder(self) -> bool {
        !matches!(self, Self::NoPriorRootWrite | Self::AncestorCleanHolder)
    }

    /// 配布の対象（ケースroot）が保護ノードの**祖父以上**か。真ならツリーが1段深くなる。
    fn propagates_from_ancestor(self) -> bool {
        matches!(
            self,
            Self::AncestorCleanHolder | Self::AncestorWrittenHolder
        )
    }

    /// 祖先（＝配布の対象）にも先行の高速付与を掛けるか。
    ///
    /// **いまは常に偽である。** 深さ2で先に確かめるべきは「配布が届くのか」で、
    /// 祖先への先行書込は**それが届くと分かってから**振る変数である（振る軸を増やすと、
    /// 対照が落ちたときにどれのせいか分からなくなる）。
    fn fast_grants_ancestor(self) -> bool {
        false
    }

    fn propagate_to(self) -> PropagateTo {
        match self {
            Self::NoPropagate => PropagateTo::Nowhere,
            Self::SiblingOnly => PropagateTo::SiblingOnly,
            Self::Production
            | Self::NoPriorRootWrite
            | Self::ExplicitDeny
            | Self::ReprotectNoDeny
            | Self::DenyInOneWrite
            | Self::ProductionRepeat
            | Self::AncestorCleanHolder
            | Self::AncestorWrittenHolder
            | Self::StripInheritedProtect
            | Self::CanonicalizeProtect
            | Self::ForceInheritedProtect
            | Self::ForcedWriteProtect
            | Self::DenyWithoutProtection
            | Self::MarkedProtect
            | Self::MarkedProtectThenSkip
            | Self::AclapiProtect
            | Self::AclapiStripAndProtect
            | Self::LegacySkipProtect => PropagateTo::CaseRoot,
        }
    }

    /// 製品の保護（[`remove_sid_aces_and_protect`]）を通すか。
    ///
    /// 通さないのは、**保護の書き方そのものを差し替えて測るケース**だけである
    /// （7は拒否ACEを1回で、11は継承由来フラグを落として、12は組み直して、13は立て直して、
    /// **14は中身を変えずに書くだけ**）。
    fn uses_production_protect(self) -> bool {
        !matches!(
            self,
            Self::DenyInOneWrite
                | Self::StripInheritedProtect
                | Self::CanonicalizeProtect
                | Self::ForceInheritedProtect
                | Self::ForcedWriteProtect
                | Self::DenyWithoutProtection
                | Self::MarkedProtect
                | Self::MarkedProtectThenSkip
                | Self::AclapiProtect
                | Self::AclapiStripAndProtect
                | Self::LegacySkipProtect
        )
    }

    fn writes_deny(self) -> bool {
        matches!(self, Self::ExplicitDeny)
    }

    /// 保護のあとに、同じDACLを保護つきでもう一度書くか（ケース5の交絡を外す対照）。
    fn rewrites_protection(self) -> bool {
        matches!(self, Self::ReprotectNoDeny)
    }
}

/// 1ケースの観測結果。**保護直後と伝播直後を対で持つ**——片方だけでは
/// 「落ちた」と「そもそも立っていなかった」が区別できない。
struct CaseResult {
    placement: &'static str,
    case: &'static str,
    /// **親（ケースroot）**の制御ビット。ツリーを作った直後。
    root_control_initial: u16,
    /// 高速付与のあと（＝伝播書込の直前）。**高速付与が親の制御ビットに何をするか**が見える。
    root_control_before_propagate: u16,
    /// 伝播書込のあと。
    root_control_after_propagate: u16,
    /// 中間ディレクトリ（深さ2のケースだけ）の制御ビット。深さ1では`None`。
    holder_control_before_propagate: Option<u16>,
    /// 保護直後のDACL制御ビット。**ここで`SE_DACL_PROTECTED`が立っていなければ測定は不成立。**
    control_after_protect: u16,
    /// 伝播直後の同じ値。伝播しないケースでは同じ時点をもう一度読む。
    control_after_propagate: u16,
    /// 保護ノード自身へこの宛先SIDの**許可**が届いているか（`sid_effective_ace_mask`は
    /// allow ACEだけを数えるので、拒否ACEはここに現れない）。
    guarded_allow_after_protect: Option<u32>,
    guarded_allow_after_propagate: Option<u32>,
    /// 保護ノードの**子**。BUG-145の実測では一度も露出しなかった。
    inner_allow_after: Option<u32>,
    /// **対照**。保護していない兄弟の配下。ここが`None`なら伝播が走っていない。
    open_allow_after: Option<u32>,
    /// このSID宛の**拒否**ACEの本数（ケース5の生存確認）。
    deny_aces_after_protect: usize,
    deny_aces_after_propagate: usize,
    /// **保護直後のACE一覧そのもの。** 差分を作るためだけに集めて捨てていたが、
    /// 落ちるケースと無傷のケースでフラグ構成が違うのかを見るには**現物が要る**
    /// （`B-10`: 集めたのに出していない値は、無いのと同じ）。
    aces_after_protect: Vec<String>,
    /// **保護をかける「直前」のACE一覧と制御ビット。**
    ///
    /// ここが空白だったせいで前回の調査は行き止まりになった。**保護の書込が何を入力に
    /// 受け取ったのかを見ずに、出力だけを比べていた**——出力が同じでも入力が違えば、
    /// 「同じ状態から違う結果が出る」という読みは成り立たない（`B-29`: 前提を1つ測る）。
    aces_before_protect: Vec<String>,
    control_before_protect: u16,
    /// 2回目の保護が**実際に書いたか**（ケース17だけ`Some`）。`Some(false)`が
    /// 「印を見て飛ばした」で、狭めたスキップが働いた証拠になる。
    second_protect_wrote: Option<bool>,
    size_before_protect: super::test_support::DaclSizeInfo,
    /// 保護直後のACLの**ヘッダ**（使用バイト数・空き・ACE数・リビジョン）。
    ///
    /// **ACE一覧が同じでも、ここが違えば「同じ状態」ではない。** 前回の調査は
    /// 「落ちるケース2と無傷のケース11・12でACE一覧が完全に同一」で行き止まりになったが、
    /// **確保容量とリビジョンを一度も読んでいなかった**——剥がす側は元のACLと同じ容量で
    /// 確保するので**空きが残り**、組み直す口は詰めて確保する。その差が保存後にも
    /// 現れるなら、行き止まりではない。
    size_after_protect: super::test_support::DaclSizeInfo,
    size_after_propagate: super::test_support::DaclSizeInfo,
    /// 保護直後には無く、伝播後に増えたACE。**BUG-145の現象そのもの。**
    added_aces: Vec<String>,
    /// 保護直後にはあったのに、伝播後に消えたACE。
    lost_aces: Vec<String>,
    errors: Vec<String>,
}

impl CaseResult {
    fn protected_after_protect(&self) -> bool {
        self.control_after_protect & SE_DACL_PROTECTED.0 != 0
    }

    fn protected_after_propagate(&self) -> bool {
        self.control_after_propagate & SE_DACL_PROTECTED.0 != 0
    }

    /// 保護ノード自身が、伝播によって**新たに許可を得たか**。これが真ならBUG-145の再現である。
    fn guarded_became_reachable(&self) -> bool {
        self.guarded_allow_after_protect.is_none() && self.guarded_allow_after_propagate.is_some()
    }
}

/// `path`のDACLに載っている`sid_text`宛の拒否ACE（`type=0x01`）の本数。
///
/// [`super::test_support::describe_dacl_aces`]が出す `type=0x..;flags=0x..;mask=0x..;S-1-...`
/// の綴りをそのまま数える。**新しい読み取り器を作らない**——同じDACLを2つの実装で読むと、
/// どちらが正しいかを別途決めなければならなくなる（`B-05`）。
fn count_deny_aces(aces: &[String], sid_text: &str) -> usize {
    aces.iter()
        .filter(|ace| ace.starts_with("type=0x01;") && ace.ends_with(sid_text))
        .count()
}

/// `path`から`sid`宛のACEを剥がし、拒否ACEを足し、保護を立てる——**すべて1回の書込で**
/// （ケース7専用）。
///
/// 製品の[`remove_sid_aces_and_protect`]と**書込の回数と口を揃えてある**のが要点で、
/// ケース5との差はそこだけである。剥がす部分は製品と同じ[`copy_dacl_excluding_sids`]を通す。
///
/// # 安全性
///
/// `sid`は有効なSIDを指していること。
unsafe fn protect_with_deny_in_one_write(
    path: &Path,
    sid: PSID,
    mask: u32,
) -> windows::core::Result<()> {
    unsafe {
        let path_w = long_path_wide(path);
        let mut existing: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing),
            None,
            &mut sd,
        )
        .ok()?;

        let mut stripped_buf: Vec<u8> = Vec::new();
        let stripped = copy_dacl_excluding_sids(existing as *const _, &[sid], &mut stripped_buf);
        let mut trustee = TRUSTEE_W::default();
        BuildTrusteeWithSidW(&mut trustee, sid);
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: mask,
            grfAccessMode: DENY_ACCESS,
            grfInheritance: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
            Trustee: trustee,
        };
        let mut merged: *mut ACL = std::ptr::null_mut();
        let merge_result = match stripped {
            Ok((dacl, _removed)) => {
                SetEntriesInAclW(Some(&[entry]), Some(dacl as *const _), &mut merged).ok()
            }
            Err(e) => Err(e),
        };
        let _ = LocalFree(HLOCAL(sd.0));
        merge_result?;

        let result =
            set_dacl_single_object_with_protection(path, merged, DaclProtection::Protected);
        let _ = LocalFree(HLOCAL(merged as *mut _));
        result
    }
}

/// 製品と同じ剥がし方をしてから、**書く直前に継承由来フラグを落として**1回で書く（ケース11専用）。
///
/// 製品の[`remove_sid_aces_and_protect`]との差は**その1点だけ**である。落とす部品は
/// [`super::test_support::strip_inherited_ace_flags`]（BUG-083のプローブと共有）。
///
/// # 安全性
///
/// `sid`は有効なSIDを指していること。
unsafe fn protect_stripping_inherited_flags(path: &Path, sid: PSID) -> windows::core::Result<()> {
    unsafe {
        let path_w = long_path_wide(path);
        let mut existing: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing),
            None,
            &mut sd,
        )
        .ok()?;

        let mut buf: Vec<u8> = Vec::new();
        let copied = copy_dacl_excluding_sids(existing as *const _, &[sid], &mut buf);
        let _ = LocalFree(HLOCAL(sd.0));
        let (dacl, _removed) = copied?;
        super::test_support::strip_inherited_ace_flags(dacl)?;
        set_dacl_single_object_with_protection(path, dacl, DaclProtection::Protected)
    }
}

/// 剥がして拒否ACEを足し、**保護を立てずに**1回で書く（ケース15専用）。
///
/// [`protect_with_deny_in_one_write`]との差は最後の引数（`protected`）だけである。
/// **拒否ACEが「保護の無い状態で親からの配布を受けても残るか」を測れる唯一の形**で、
/// 製品に入れる形ではない。
///
/// # 安全性
///
/// `sid`は有効なSIDを指していること。
unsafe fn deny_without_protection(path: &Path, sid: PSID, mask: u32) -> windows::core::Result<()> {
    unsafe {
        let path_w = long_path_wide(path);
        let mut existing: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing),
            None,
            &mut sd,
        )
        .ok()?;

        let mut stripped_buf: Vec<u8> = Vec::new();
        let stripped = copy_dacl_excluding_sids(existing as *const _, &[sid], &mut stripped_buf);
        let mut trustee = TRUSTEE_W::default();
        BuildTrusteeWithSidW(&mut trustee, sid);
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: mask,
            grfAccessMode: DENY_ACCESS,
            grfInheritance: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
            Trustee: trustee,
        };
        let mut merged: *mut ACL = std::ptr::null_mut();
        let merge_result = match stripped {
            Ok((dacl, _removed)) => {
                SetEntriesInAclW(Some(&[entry]), Some(dacl as *const _), &mut merged).ok()
            }
            Err(e) => Err(e),
        };
        let _ = LocalFree(HLOCAL(sd.0));
        merge_result?;

        // **ここだけが`protect_with_deny_in_one_write`と違う**——保護を立てない。
        let result =
            set_dacl_single_object_with_protection(path, merged, DaclProtection::Unprotected);
        let _ = LocalFree(HLOCAL(merged as *mut _));
        result
    }
}

/// 製品とまったく同じ剥がし方・同じ書込を、**冪等スキップだけ外して**行う
/// （ケース14・16・17が共有）。
///
/// [`remove_sid_aces_and_protect`]から**スキップの3行を抜いただけ**である。剥がすACEが1本も無く
/// 既に保護済みなら製品は書かずに戻るが、ここは必ず書く。**書くDACLは1バイトも変えない。**
///
/// `protection`で立てる制御ビットを選ぶ——ケース14は製品と同じ保護のみ、
/// ケース16・17は**印つき**（保護＋自動継承）。**同じ書込を2つ書かない**ためにここで受ける。
///
/// # 安全性
///
/// `sid`は有効なSIDを指していること。
unsafe fn protect_forcing_the_write(
    path: &Path,
    sid: PSID,
    protection: DaclProtection,
) -> windows::core::Result<()> {
    unsafe {
        let path_w = long_path_wide(path);
        let mut existing: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing),
            None,
            &mut sd,
        )
        .ok()?;

        let mut buf: Vec<u8> = Vec::new();
        let copied = copy_dacl_excluding_sids(existing as *const _, &[sid], &mut buf);
        let _ = LocalFree(HLOCAL(sd.0));
        let (dacl, _removed) = copied?;
        set_dacl_single_object_with_protection(path, dacl, protection)
    }
}

/// **修正前の`remove_sid_aces_and_protect`をそのまま再現する**（ケース20専用）。
///
/// 「剥がすACEが1本も無く、かつ`SE_DACL_PROTECTED`が立っているなら書かずに戻る」
/// ——これが[BUG-145](../../../../docs/bugs/BUG-145.md)の原因だった判定である。
/// 製品はこの判定を「保護済み**かつ自動継承あり**」へ狭めたので、
/// **壊れる形を将来も表に並べるにはここで再現するしかない。**
///
/// # 安全性
///
/// `sid`は有効なSIDを指していること。
unsafe fn protect_with_the_legacy_skip(path: &Path, sid: PSID) -> windows::core::Result<()> {
    unsafe {
        let path_w = long_path_wide(path);
        let mut existing: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing),
            None,
            &mut sd,
        )
        .ok()?;
        let mut buf: Vec<u8> = Vec::new();
        let copied = copy_dacl_excluding_sids(existing as *const _, &[sid], &mut buf);
        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        let control_result = GetSecurityDescriptorControl(sd, &mut control, &mut revision);
        let _ = LocalFree(HLOCAL(sd.0));
        let (dacl, removed) = copied?;
        control_result?;

        // **これが旧条件。** `C:\`から降りるツリーでは新しく作ったディレクトリが最初から
        // 保護済みで生まれるので、ここで必ず戻る＝1回も書かない。
        if removed == 0 && control & SE_DACL_PROTECTED.0 != 0 {
            return Ok(());
        }
        set_dacl_single_object_with_protection(path, dacl, DaclProtection::Protected)
    }
}

/// 製品と同じ剥がし方をしてから、**カーネルの口で`SE_DACL_AUTO_INHERITED`も立てて**書く
/// （ケース16専用）。
///
/// # 保存されないことを測るためだけに在る
///
/// 製品の[`DaclProtection`]からはこの形を落とした——**カーネルの口はこのビットを保存しない**
/// と実測で分かったからである（`plans/mac-spike/RESULTS.md` §S36）。
/// **腕を残しておかないと、その事実を将来もう一度測り直すことになる。**
///
/// # 安全性
///
/// `sid`は有効なSIDを指していること。
unsafe fn protect_kernel_write_asking_for_the_mark(
    path: &Path,
    sid: PSID,
) -> windows::core::Result<()> {
    // Win32の名前は`use super::*`（＝`revoke`が取り込んでいるもの）でそのまま届く。
    unsafe {
        let path_w = long_path_wide(path);
        let mut existing: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing),
            None,
            &mut sd,
        )
        .ok()?;
        let mut buf: Vec<u8> = Vec::new();
        let copied = copy_dacl_excluding_sids(existing as *const _, &[sid], &mut buf);
        let _ = LocalFree(HLOCAL(sd.0));
        let (dacl, _removed) = copied?;

        let handle: HANDLE = CreateFileW(
            PCWSTR(path_w.as_ptr()),
            (WRITE_DAC | READ_CONTROL).0,
            FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )?;
        let mut new_sd = SECURITY_DESCRIPTOR::default();
        let sd_ptr = PSECURITY_DESCRIPTOR(&mut new_sd as *mut _ as *mut _);
        let result = (|| -> windows::core::Result<()> {
            InitializeSecurityDescriptor(sd_ptr, SECURITY_DESCRIPTOR_REVISION)?;
            SetSecurityDescriptorDacl(sd_ptr, true, Some(dacl as *const _), false)?;
            SetSecurityDescriptorControl(
                sd_ptr,
                SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED,
                SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED,
            )?;
            SetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION, sd_ptr)
        })();
        let _ = CloseHandle(handle);
        result
    }
}

/// 製品と同じ剥がし方をしてから、**aclapiの口で**保護を書く（ケース19専用）。
///
/// **印つきで直すなら製品はこの形になる。** カーネルの口は`SE_DACL_AUTO_INHERITED`を
/// 保存しない（ケース16の実測）ので、印を残せるのはこちらだけである。
///
/// 剥がしは製品と同じ[`copy_dacl_excluding_sids`]を通し、書込だけ
/// `SetNamedSecurityInfoW`＋`PROTECTED_DACL_SECURITY_INFORMATION`へ差し替える。
///
/// # 安全性
///
/// `sid`は有効なSIDを指していること。
unsafe fn aclapi_strip_and_protect(path: &Path, sid: PSID) -> windows::core::Result<()> {
    use windows::Win32::Security::Authorization::SetNamedSecurityInfoW;
    use windows::Win32::Security::PROTECTED_DACL_SECURITY_INFORMATION;
    unsafe {
        let path_w = long_path_wide(path);
        let mut existing: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing),
            None,
            &mut sd,
        )
        .ok()?;

        let mut buf: Vec<u8> = Vec::new();
        let copied = copy_dacl_excluding_sids(existing as *const _, &[sid], &mut buf);
        let result = match copied {
            Ok((dacl, _removed)) => SetNamedSecurityInfoW(
                PCWSTR(path_w.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(dacl as *const _),
                None,
            )
            .ok(),
            Err(e) => Err(e),
        };
        let _ = LocalFree(HLOCAL(sd.0));
        result
    }
}

/// **提案する狭めたスキップ**——印があれば書かず、無ければ印つきで書く（ケース17の2回目）。
///
/// 戻り値は**書いたか**。`false`が「印を見て飛ばした」で、そこが測る当のものである。
///
/// **製品の条件との差**: 本物の狭めたスキップは「剥がすACEが1本も無く**かつ**印がある」で
/// 判定する。このプローブの宛先SIDは`guarded`にACEを1本も持たないので前半は常に真になり、
/// **ここでは印の有無だけが効く**。両者は等価だが、製品へ入れるときは前半も落とさないこと。
///
/// # 安全性
///
/// `sid`は有効なSIDを指していること。
unsafe fn protect_skipping_when_marked(path: &Path, sid: PSID) -> windows::core::Result<bool> {
    unsafe {
        if dacl_is_protected_and_auto_inherited(dacl_control(path)?) {
            return Ok(false);
        }
        // **書くならaclapiの口である。** カーネルの口は`SE_DACL_AUTO_INHERITED`を保存しない
        // （ケース16の実測）ので、そちらで書くと印が付かず、次回も飛ばせない。
        aclapi_strip_and_protect(path, sid)?;
        Ok(true)
    }
}

/// 製品と同じ剥がし方をしてから、**`SetEntriesInAclW`へ通して組み直し**1回で書く（ケース12専用）。
///
/// 新しいACEは1本も渡さない——**組み直すこと自体が測る当のもの**だからである。
/// `SetEntriesInAclW`へ空の一覧を渡す形が受け付けられなければ、この関数が`Err`を返し、
/// 呼び出し側が`errors`へ積んで**そのケースは測定不成立として出力に残る**
/// （黙って別の形へ落として「測れた」ことにしない）。
///
/// # 安全性
///
/// `sid`は有効なSIDを指していること。
unsafe fn protect_canonicalizing_dacl(path: &Path, sid: PSID) -> windows::core::Result<()> {
    unsafe {
        let path_w = long_path_wide(path);
        let mut existing: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing),
            None,
            &mut sd,
        )
        .ok()?;

        let mut buf: Vec<u8> = Vec::new();
        let copied = copy_dacl_excluding_sids(existing as *const _, &[sid], &mut buf);
        let _ = LocalFree(HLOCAL(sd.0));
        let (stripped, _removed) = copied?;

        let mut merged: *mut ACL = std::ptr::null_mut();
        SetEntriesInAclW(None, Some(stripped as *const _), &mut merged).ok()?;
        let result =
            set_dacl_single_object_with_protection(path, merged, DaclProtection::Protected);
        let _ = LocalFree(HLOCAL(merged as *mut _));
        result
    }
}

/// 組み直したDACLの全ACEへ**継承由来フラグを立て直してから**保護つきで書く（ケース13専用）。
///
/// [`super::test_support::strip_inherited_ace_flags`]の逆向きで、**狙って壊すためだけに在る**。
/// 共有部品にしないのは利用者がここ1つで、かつ**製品が決してしてはいけない操作**だからである。
///
/// # 安全性
///
/// `sid`は有効なSIDを指していること。
unsafe fn protect_forcing_inherited_flags(path: &Path, sid: PSID) -> windows::core::Result<()> {
    use std::ffi::c_void;
    use windows::Win32::Security::{GetAce, ACE_HEADER, INHERITED_ACE};
    unsafe {
        let path_w = long_path_wide(path);
        let mut existing: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing),
            None,
            &mut sd,
        )
        .ok()?;

        let mut buf: Vec<u8> = Vec::new();
        let copied = copy_dacl_excluding_sids(existing as *const _, &[sid], &mut buf);
        let _ = LocalFree(HLOCAL(sd.0));
        let (stripped, _removed) = copied?;

        // ケース12と同じ組み直しを通してから、フラグだけを立て直す。
        // **12との差を「継承由来を名乗るか」の1点にするため**である。
        let mut merged: *mut ACL = std::ptr::null_mut();
        SetEntriesInAclW(None, Some(stripped as *const _), &mut merged).ok()?;
        let count = (*merged).AceCount as u32;
        for index in 0..count {
            let mut ace_ptr: *mut c_void = std::ptr::null_mut();
            if GetAce(merged, index, &mut ace_ptr).is_ok() && !ace_ptr.is_null() {
                let header = ace_ptr as *mut ACE_HEADER;
                (*header).AceFlags |= INHERITED_ACE.0 as u8;
            }
        }
        let result =
            set_dacl_single_object_with_protection(path, merged, DaclProtection::Protected);
        let _ = LocalFree(HLOCAL(merged as *mut _));
        result
    }
}

/// `path`のDACLを**一切変えずに**、保護つきでもう一度書き戻す（ケース6専用）。
///
/// ケース5との違いは拒否ACEを足さないことだけで、**書込の回数と口は同じ**にしてある。
///
/// # 安全性
///
/// 呼び出し側は`path`が存在することを保証すること。
unsafe fn rewrite_with_protection(path: &Path) -> windows::core::Result<()> {
    unsafe {
        let path_w = long_path_wide(path);
        let mut existing: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing),
            None,
            &mut sd,
        )
        .ok()?;
        let result =
            set_dacl_single_object_with_protection(path, existing, DaclProtection::Protected);
        let _ = LocalFree(HLOCAL(sd.0));
        result
    }
}

/// `path`へ`sid`宛の**明示の拒否ACE**を1本足し、保護を立てたまま書き戻す（ケース5専用）。
///
/// **製品コードは変えない。** 案②を採るかはまだ決まっていないので、ここでローカルに書く。
/// 継承フラグを立てるのは、実際に採るならその形になるからである（配下のファイルにも効かせる）。
///
/// # 安全性
///
/// `sid`は有効なSIDを指していること。
unsafe fn add_explicit_deny(path: &Path, sid: PSID, mask: u32) -> windows::core::Result<()> {
    unsafe {
        let path_w = long_path_wide(path);
        let mut existing: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing),
            None,
            &mut sd,
        )
        .ok()?;

        let mut trustee = TRUSTEE_W::default();
        BuildTrusteeWithSidW(&mut trustee, sid);
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: mask,
            grfAccessMode: DENY_ACCESS,
            grfInheritance: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
            Trustee: trustee,
        };
        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        // `SetEntriesInAclW`が正規順（拒否を許可より前）へ並べ替える。
        let merged =
            SetEntriesInAclW(Some(&[entry]), Some(existing as *const _), &mut new_dacl).ok();
        let _ = LocalFree(HLOCAL(sd.0));
        merged?;

        let result =
            set_dacl_single_object_with_protection(path, new_dacl, DaclProtection::Protected);
        let _ = LocalFree(HLOCAL(new_dacl as *mut _));
        result
    }
}

/// 1ケースを走らせる。ツリーの形は**深さの軸**（[`Case::propagates_from_ancestor`]）で2通り。
///
/// ```text
/// 深さ1（ケース1〜8）              深さ2（ケース9・10。`--fs-allow <祖先>/**`の形）
/// <case_root>/  ← 配布の対象        <case_root>/  ← 配布の対象（祖先）
///   ├─ guarded/ ← 保護                └─ ws/      ← 中間。高速付与で書込済み
///   │    └─ inner.txt                      ├─ guarded/ ← 保護
///   └─ open/    ← 対照                     │    └─ inner.txt
///        └─ f.txt                          └─ open/    ← 対照
///                                               └─ f.txt
/// ```
///
/// `holder`は「保護ノードと対照を直接ぶら下げているディレクトリ」で、深さ1では`case_root`
/// そのもの、深さ2では中間の`ws`である。**高速付与は常に`holder`へ掛ける**——製品で
/// カーネル口の書込を受けているのはworkspace rootであり、深さ2ではそれが中間に当たるためである。
fn run_case(placement: &Placement, case: Case, index: usize) -> CaseResult {
    let mut errors = Vec::new();
    let case_root = placement.root.join(case.label());
    let holder = if case.propagates_from_ancestor() {
        case_root.join("ws")
    } else {
        case_root.clone()
    };
    let guarded = holder.join("guarded");
    let inner = guarded.join("inner.txt");
    let open = holder.join("open");
    let open_file = open.join("f.txt");
    std::fs::create_dir_all(&guarded).expect("create the guarded dir");
    std::fs::create_dir_all(&open).expect("create the open dir");
    std::fs::write(&inner, b"bug-145 probe\n").expect("seed the inner file");
    std::fs::write(&open_file, b"bug-145 probe\n").expect("seed the open file");

    // ケースごとに別のSIDにして、ケース間の干渉を断つ（台帳は経由しない純粋導出）。
    //
    // **深さ2のケースは宛先SIDを2つ使う。** 製品では、中間（workspace root）へカーネル口で
    // 書かれているのは**workspaceのcapability SID**で、祖先から配るのは
    // **`--fs-allow`のcapability SID**という**別の宛先SID**である。1つのSIDで両方をやると、
    // 「同じ宛先SIDのACEが既に在ると配布が既存の子孫へ届かない」という既知の性質
    // （[`super::super::acl_dacl_write`]のモジュールdocの実測表）を自分で踏みに行くことになり、
    // 測りたいものと違うものを測る。**最初にそう書いて対照が落ちた。**
    let sid = capability_sid_from_name(&format!("harnessBug145Probe{index}"))
        .expect("derive a probe capability SID");
    // 中間へ先に書かれている宛先SID（深さ2のケースだけ）。深さ1では`sid`がその役も兼ねる。
    let holder_sid = case.propagates_from_ancestor().then(|| {
        capability_sid_from_name(&format!("harnessBug145Holder{index}"))
            .expect("derive the holder capability SID")
    });
    // 保護と高速付与の相手。深さ2では中間側の宛先SID、深さ1では`sid`。
    let holder_subject = holder_sid.as_ref().unwrap_or(&sid);
    let sid_text =
        crate::win_common::sid_to_string(sid.as_psid()).expect("render the probe SID as a string");
    let mask = workspace_rwx_mask();
    let grants = [AceGrant {
        sid: sid.as_psid(),
        mask,
    }];

    // **配布の対象（ケースroot）の制御ビットも読む。** 置き場で結果が割れたとき、
    // 対象の側に何の差があるのかを見ないと原因の名前を付けられない。
    let root_control_initial = dacl_control(&case_root).expect("read the case root control bits");

    // 深さ2のケースだけ、**祖先にも**先行の高速付与を掛ける（ケース10）。
    // ケース2と3の差（配布の対象への先行書込の有無）を、深さが増えても再現するかを見る。
    if case.fast_grants_ancestor() {
        if let Err(e) = grant_workspace_root_aces_fast(&case_root, &grants) {
            errors.push(format!("fast ancestor grant: {e}"));
        }
    }
    if case.fast_grants_holder() {
        let holder_grants = [AceGrant {
            sid: holder_subject.as_psid(),
            mask,
        }];
        if let Err(e) = grant_workspace_root_aces_fast(&holder, &holder_grants) {
            errors.push(format!("fast root grant: {e}"));
        }
    }
    let root_control_before_propagate =
        dacl_control(&case_root).expect("read the case root control bits before propagate");
    // 中間ディレクトリの制御ビット。深さ1では`case_root`と同じものなので出さない。
    let holder_control_before_propagate = case
        .propagates_from_ancestor()
        .then(|| dacl_control(&holder).expect("read the holder control bits before propagate"));

    // **保護の書込が受け取る入力**。出力（保護直後）だけを比べていたのが前回の行き止まりだった。
    let control_before_protect =
        dacl_control(&guarded).expect("read the control bits before protect");
    let aces_before_protect = describe_dacl_aces(&guarded).expect("list the ACEs before protect");
    let size_before_protect =
        super::test_support::dacl_size_info(&guarded).expect("read the ACL header before protect");

    if case.uses_production_protect() {
        // **保護の相手は中間側の宛先SIDである。** 製品でも`.harness`が守られているのは
        // workspaceのcapability SIDに対してであって、`--fs-allow`の宛先SIDに対してではない。
        match remove_sid_aces_and_protect(&guarded, holder_subject.as_psid()) {
            Ok(super::ProtectOutcome::Wrote) => {}
            // [BUG-145] **飛ばした**。製品はこれを`.harness/`の2回目以降で通る。
            // ここは毎回まっさらなツリーなので、起きたら印の読み方がおかしい。
            Ok(super::ProtectOutcome::SkippedAlreadyDurable) => errors.push(
                "protect: skipped on a freshly created tree; the mark must not be there yet".into(),
            ),
            // [BUG-084] 「触る前に消えていた」。自分で作ったツリーなので起こり得ないが、
            // 起きたなら測定が成立しない。
            Ok(super::ProtectOutcome::Vanished) => {
                errors.push("protect: the guarded dir vanished before it was protected".into())
            }
            Err(e) => errors.push(format!("protect: {e}")),
        }
    } else {
        // **保護の書き方そのものを差し替える3ケース。** どれも書込は1回で、製品との差は
        // 「最後に書くDACLをどう組んだか」だけである。
        let replaced = match case {
            Case::DenyInOneWrite => unsafe {
                protect_with_deny_in_one_write(&guarded, holder_subject.as_psid(), mask)
            },
            Case::StripInheritedProtect => unsafe {
                protect_stripping_inherited_flags(&guarded, holder_subject.as_psid())
            },
            Case::CanonicalizeProtect => unsafe {
                protect_canonicalizing_dacl(&guarded, holder_subject.as_psid())
            },
            Case::ForceInheritedProtect => unsafe {
                protect_forcing_inherited_flags(&guarded, holder_subject.as_psid())
            },
            Case::ForcedWriteProtect => unsafe {
                protect_forcing_the_write(
                    &guarded,
                    holder_subject.as_psid(),
                    DaclProtection::Protected,
                )
            },
            Case::DenyWithoutProtection => unsafe {
                deny_without_protection(&guarded, sid.as_psid(), mask)
            },
            // **カーネルの口で印を立てようとする腕。** 実測の答えは「保存されない」で、
            // `DaclProtection`から`Marked`を落とした根拠がこれである。**腕は残す**——
            // 落とすと「カーネルの口では作れない」を将来もう一度測り直すことになる。
            Case::MarkedProtect => unsafe {
                protect_kernel_write_asking_for_the_mark(&guarded, holder_subject.as_psid())
            },
            // **1回目はaclapiの口で書く**（印が残る唯一の口）。そのうえで2回目に
            // 印を見て飛ばし、**飛ばした状態のまま配布に耐えるか**を見る。
            Case::MarkedProtectThenSkip => unsafe {
                aclapi_strip_and_protect(&guarded, holder_subject.as_psid())
            },
            // **宛先SIDを渡さない口である。** このプローブの宛先SIDは`guarded`にACEを持たないので
            // 剥がすものが無く、製品の形との差は「どの口で保護を書いたか」だけになる。
            Case::AclapiProtect => super::test_support::protect_dacl_preserve_inherited(&guarded),
            Case::AclapiStripAndProtect => unsafe {
                aclapi_strip_and_protect(&guarded, holder_subject.as_psid())
            },
            Case::LegacySkipProtect => unsafe {
                protect_with_the_legacy_skip(&guarded, holder_subject.as_psid())
            },
            other => unreachable!("{other:?} は製品の保護を通すはずのケースである"),
        };
        if let Err(e) = replaced {
            errors.push(format!("replaced protect write: {e}"));
        }
    }
    if case.writes_deny() {
        if let Err(e) = unsafe { add_explicit_deny(&guarded, sid.as_psid(), mask) } {
            errors.push(format!("explicit deny: {e}"));
        }
    }
    if case.rewrites_protection() {
        if let Err(e) = unsafe { rewrite_with_protection(&guarded) } {
            errors.push(format!("reprotect: {e}"));
        }
    }
    // ケース17の2回目——**印を見て飛ばせるか**。`false`が「飛ばした」で、そこが測る当のもの。
    let second_protect_wrote = if case == Case::MarkedProtectThenSkip {
        match unsafe { protect_skipping_when_marked(&guarded, holder_subject.as_psid()) } {
            Ok(wrote) => Some(wrote),
            Err(e) => {
                errors.push(format!("second protect: {e}"));
                None
            }
        }
    } else {
        None
    };

    let control_after_protect =
        dacl_control(&guarded).expect("read the control bits after protect");
    let aces_after_protect = describe_dacl_aces(&guarded).expect("list the ACEs after protect");
    let size_after_protect =
        super::test_support::dacl_size_info(&guarded).expect("read the ACL header after protect");
    let guarded_allow_after_protect = match sid_effective_ace_mask(&guarded, sid.as_psid()) {
        Ok(m) => m,
        Err(e) => {
            errors.push(format!("read guarded after protect: {e}"));
            None
        }
    };

    match case.propagate_to() {
        PropagateTo::Nowhere => {}
        PropagateTo::CaseRoot => {
            if let Err(e) = propagate_workspace_root_grant(&case_root, sid.as_psid(), mask) {
                errors.push(format!("propagate (case root): {e}"));
            }
        }
        PropagateTo::SiblingOnly => {
            if let Err(e) = propagate_workspace_root_grant(&open, sid.as_psid(), mask) {
                errors.push(format!("propagate (sibling): {e}"));
            }
        }
    }

    let control_after_propagate =
        dacl_control(&guarded).expect("read the control bits after propagate");
    let aces_after_propagate = describe_dacl_aces(&guarded).expect("list the ACEs after propagate");
    let size_after_propagate =
        super::test_support::dacl_size_info(&guarded).expect("read the ACL header after propagate");
    let read_mask = |path: &Path, what: &str, errors: &mut Vec<String>| -> Option<u32> {
        match sid_effective_ace_mask(path, sid.as_psid()) {
            Ok(m) => m,
            Err(e) => {
                errors.push(format!("read {what}: {e}"));
                None
            }
        }
    };
    let guarded_allow_after_propagate = read_mask(&guarded, "guarded after propagate", &mut errors);
    let inner_allow_after = read_mask(&inner, "inner after propagate", &mut errors);
    let open_allow_after = read_mask(&open_file, "open/f.txt after propagate", &mut errors);

    let added_aces: Vec<String> = aces_after_propagate
        .iter()
        .filter(|ace| !aces_after_protect.contains(ace))
        .cloned()
        .collect();
    let lost_aces: Vec<String> = aces_after_protect
        .iter()
        .filter(|ace| !aces_after_propagate.contains(ace))
        .cloned()
        .collect();

    let root_control_after_propagate =
        dacl_control(&case_root).expect("read the case root control bits after propagate");

    CaseResult {
        placement: placement.label,
        case: case.label(),
        root_control_initial,
        root_control_before_propagate,
        root_control_after_propagate,
        holder_control_before_propagate,
        control_after_protect,
        control_after_propagate,
        guarded_allow_after_protect,
        guarded_allow_after_propagate,
        inner_allow_after,
        open_allow_after,
        deny_aces_after_protect: count_deny_aces(&aces_after_protect, &sid_text),
        aces_before_protect,
        control_before_protect,
        second_protect_wrote,
        size_before_protect,
        aces_after_protect,
        size_after_protect,
        size_after_propagate,
        deny_aces_after_propagate: count_deny_aces(&aces_after_propagate, &sid_text),
        added_aces,
        lost_aces,
        errors,
    }
}

/// controlビットのうち、この実験で意味を持つものを人が読める形にする。
/// **BUG-083のプローブと同じ綴り**にしてある（2つの出力を並べて読むため）。
fn describe_control(control: u16) -> String {
    let mut flags = Vec::new();
    for (bit, name) in [
        (0x0004u16, "DACL_PRESENT"),
        (0x0100, "DACL_AUTO_INHERIT_REQ"),
        (0x0400, "DACL_AUTO_INHERITED"),
        (0x1000, "DACL_PROTECTED"),
        (0x8000, "SELF_RELATIVE"),
    ] {
        if control & bit != 0 {
            flags.push(name);
        }
    }
    format!("0x{control:04x} [{}]", flags.join("|"))
}

fn describe_mask(mask: Option<u32>) -> String {
    match mask {
        Some(m) => format!("0x{m:08x}"),
        None => "-".to_string(),
    }
}

/// [BUG-145] **保護したノード自身が、親の伝播で保護を失うのか。**
///
/// 判定表（何が出たらどう読むか）は`docs/bugs/BUG-145.md`の「原因」節へ転記する。
#[test]
#[ignore = "実FSのDACLを書き換える観測用プローブ（C:\\harness-bug145-probe と %TEMP% のみ、管理者権限不要）。結果はdocs/bugs/BUG-145.mdへ転記する"]
fn control_dir_propagation_matrix_probe() {
    let placements = placements();
    println!("=== placements ({}) ===", placements.len());
    for p in &placements {
        println!("  {:<22}: {}", p.label, p.root.display());
    }

    let mut results = Vec::new();
    let mut index = 0usize;
    for placement in &placements {
        // 前回の残骸が結果を汚さないよう毎回作り直す（残すのは実行「後」だけ）。
        let _ = std::fs::remove_dir_all(&placement.root);
        std::fs::create_dir_all(&placement.root).expect("create the probe root");
        for case in CASES {
            index += 1;
            results.push(run_case(placement, *case, index));
        }
    }

    for r in &results {
        println!("--- [{}] {} ---", r.placement, r.case);
        println!(
            "  ROOT control            : {} -> {} -> {}   (作成直後 -> 高速付与後 -> 伝播後)",
            describe_control(r.root_control_initial),
            describe_control(r.root_control_before_propagate),
            describe_control(r.root_control_after_propagate)
        );
        if let Some(holder) = r.holder_control_before_propagate {
            println!(
                "  HOLDER control (中間)   : {}   (高速付与後、配布の直前)",
                describe_control(holder)
            );
        }
        println!(
            "  control before protect  : {}   <- 保護の書込が受け取る入力",
            describe_control(r.control_before_protect)
        );
        println!(
            "  control after protect   : {}{}",
            describe_control(r.control_after_protect),
            if dacl_is_protected_and_auto_inherited(r.control_after_protect) {
                "   <- 印あり（保護＋自動継承）"
            } else {
                ""
            }
        );
        if let Some(wrote) = r.second_protect_wrote {
            println!(
                "  2nd protect             : {}",
                if wrote {
                    "書いた（印が無かった）"
                } else {
                    "飛ばした（印を見た）"
                }
            );
        }
        println!(
            "  control after propagate : {}",
            describe_control(r.control_after_propagate)
        );
        println!(
            "  guarded allow           : {} -> {}   (protect -> propagate)",
            describe_mask(r.guarded_allow_after_protect),
            describe_mask(r.guarded_allow_after_propagate)
        );
        println!(
            "  guarded deny ACEs       : {} -> {}",
            r.deny_aces_after_protect, r.deny_aces_after_propagate
        );
        println!(
            "  guarded/inner.txt allow : {}",
            describe_mask(r.inner_allow_after)
        );
        println!(
            "  open/f.txt allow        : {}   <- 対照（伝播が走ったか）",
            describe_mask(r.open_allow_after)
        );
        // **ACLのヘッダ。** ACE一覧が同じでもここが違えば「同じ状態」ではない。
        // 空き容量は、剥がす側が元のACLと同じ容量で確保する（＝空きが残る）のに対し、
        // 組み直す口は詰めて確保する——その差が保存後にも残るのかを見る。
        println!(
            "  ACL header before       : in_use={} free={} aces={} rev={}",
            r.size_before_protect.bytes_in_use,
            r.size_before_protect.bytes_free,
            r.size_before_protect.ace_count,
            r.size_before_protect.revision,
        );
        for ace in &r.aces_before_protect {
            println!("  * ACE before protect    : {ace}");
        }
        println!(
            "  ACL header              : in_use={} free={} aces={} rev={}  ->  in_use={} free={} aces={} rev={}   (protect -> propagate)",
            r.size_after_protect.bytes_in_use,
            r.size_after_protect.bytes_free,
            r.size_after_protect.ace_count,
            r.size_after_protect.revision,
            r.size_after_propagate.bytes_in_use,
            r.size_after_propagate.bytes_free,
            r.size_after_propagate.ace_count,
            r.size_after_propagate.revision,
        );
        for ace in &r.aces_after_protect {
            println!("  = ACE after protect     : {ace}");
        }
        for ace in &r.added_aces {
            println!("  + gained ACE            : {ace}");
        }
        for ace in &r.lost_aces {
            println!("  - lost ACE              : {ace}");
        }
        for e in &r.errors {
            println!("  !! error                : {e}");
        }
    }

    println!("=== verdict ===");
    for placement in &placements {
        let label = placement.label;
        let mine: Vec<&CaseResult> = results.iter().filter(|r| r.placement == label).collect();
        let lost_protection: Vec<&str> = mine
            .iter()
            .filter(|r| r.protected_after_protect() && !r.protected_after_propagate())
            .map(|r| r.case)
            .collect();
        let became_reachable: Vec<&str> = mine
            .iter()
            .filter(|r| r.guarded_became_reachable())
            .map(|r| r.case)
            .collect();
        let deny_survived: Vec<&str> = mine
            .iter()
            .filter(|r| r.deny_aces_after_protect > 0 && r.deny_aces_after_propagate > 0)
            .map(|r| r.case)
            .collect();
        println!("  [{label}] lost SE_DACL_PROTECTED : {lost_protection:?}");
        println!("  [{label}] guarded became reachable: {became_reachable:?}");
        println!("  [{label}] explicit deny survived  : {deny_survived:?}");
        // 深さ2で配布が届かなかったケース。**「保護が無傷だった」とは読めない**——
        // 配布がそこまで到達していないので、保護の話をする前提が無い。
        let ancestor_unreached: Vec<&str> = mine
            .iter()
            .filter(|r| {
                (r.case == Case::AncestorCleanHolder.label()
                    || r.case == Case::AncestorWrittenHolder.label())
                    && r.open_allow_after.is_none()
            })
            .map(|r| r.case)
            .collect();
        println!("  [{label}] 深さ2で配布が届かず測定不成立: {ancestor_unreached:?}");
    }

    // 拒否ACEが**保護の無い状態で**配布を生き延びたか（ケース15。`deny_survived`は
    // 保護のあるケースと混ざるので別に出す）。
    let deny_no_protect: Vec<(&str, bool, bool)> = results
        .iter()
        .filter(|r| r.case == Case::DenyWithoutProtection.label())
        .map(|r| {
            (
                r.placement,
                r.deny_aces_after_protect > 0,
                r.deny_aces_after_propagate > 0,
            )
        })
        .collect();
    println!(
        "  [15-deny-without-protection] (置き場, 書けたか, 配布後も残ったか): {deny_no_protect:?}"
    );

    // --- ここから下は「実験の前提が崩れていないか」だけを見る（合否は判定しない） ---
    //
    // **ケース15は除く。** あちらは保護を立てないことが手順そのものなので、
    // 「保護が立った」を要求すると測定の意図と衝突する（`B-35`: 禁止側と許可側で
    // 見るべき前提が違う）。代わりに「拒否ACEが実際に書けたか」を下で見る。
    for r in results
        .iter()
        .filter(|r| r.case != Case::DenyWithoutProtection.label())
    {
        assert!(
            r.protected_after_protect(),
            "[{}] {}: 保護が立たなかったので、以降の観測は別のものを測っている（control={}）",
            r.placement,
            r.case,
            describe_control(r.control_after_protect)
        );
    }
    // **深さ1のケースだけ**。届いていなければ実験の組み方が壊れている。
    //
    // **深さ2はassertしない**——届くかどうかがそこでは観測対象そのものだからである。
    // 届かなかったケースは「保護が無傷だった」と主張できない（配布がそこまで来ていない）ので、
    // 上のverdictで**測定不成立として名指しする**。黙って無傷の側へ数えない（`B-10`）。
    for r in results.iter().filter(|r| {
        r.case != Case::NoPropagate.label()
            && r.case != Case::AncestorCleanHolder.label()
            && r.case != Case::AncestorWrittenHolder.label()
    }) {
        assert!(
            r.open_allow_after.is_some(),
            "[{}] {}: 対照の open/f.txt へ伝播が届いていない。このケースは『保護が効いた』ではなく \
             『伝播が走っていない』を測っている",
            r.placement,
            r.case
        );
    }
    // ケース17の前提——**2回目が実際に飛んだこと**。飛んでいなければ、この腕は
    // 「印を見て飛ばしても耐えるか」ではなく「2回書いたら耐えるか」を測っている（`B-10`）。
    for r in results
        .iter()
        .filter(|r| r.case == Case::MarkedProtectThenSkip.label())
    {
        assert_eq!(
            r.second_protect_wrote,
            Some(false),
            "[{}] {}: 2回目が飛ばずに書いている。印が残っていないので、測っているものが違う",
            r.placement,
            r.case
        );
    }

    // ケース15の前提——**拒否ACEが実際に書けていること**。書けていなければ
    // 「配布後も残った／消えた」のどちらを読んでも意味が無い（`B-10`）。
    for r in results
        .iter()
        .filter(|r| r.case == Case::DenyWithoutProtection.label())
    {
        assert!(
            r.deny_aces_after_protect > 0,
            "[{}] {}: 拒否ACEが1本も書けていない。このケースは何も測っていない",
            r.placement,
            r.case
        );
        // **保護が「立っていないこと」はassertできない。** `C:\`から降りるツリーでは
        // 新しく作ったディレクトリが最初から`SE_DACL_PROTECTED`付きで生まれ、
        // `protected=false`で書いてもその既存の保護は消えない（実測）。
        // **その置き場では代わりに「配布で保護が落ちた状態」が手に入る**——
        // つまり測りたかった状況そのものなので、どちらに転んでも問いには答えられる。
        // 立っていたか／落ちたかは上の一覧に出す（`B-10`: 分岐を黙って畳まない）。
        assert!(
            !(r.protected_after_protect() && r.protected_after_propagate()),
            "[{}] {}: 保護が最後まで立ったままなので、拒否ACEは一度も『最後の砦』に \
             なっていない。この腕は問いに答えていない",
            r.placement,
            r.case
        );
    }

    // 対照の対（`B-35`）——伝播しないケースでは兄弟にも届かないこと。届いていたら、
    // 高速付与が伝播していることになり、このプローブの前提そのものが崩れる。
    for r in results
        .iter()
        .filter(|r| r.case == Case::NoPropagate.label())
    {
        assert!(
            r.open_allow_after.is_none(),
            "[{}] {}: 伝播していないのに兄弟へ届いている。高速付与が伝播しない口である \
             という前提が崩れている",
            r.placement,
            r.case
        );
    }
}

/// **[BUG-145] 冪等スキップを外すと、いくら高くつくのか。**
///
/// 上のプローブが原因を「保護の書込が冪等スキップで丸ごと省かれること」に確定させた
/// （ケース14＝**中身を1バイトも変えずに書くだけ**で無傷になる）。**その直し方の費用が
///ここで要る**——スキップは`revoke.rs`が「高価な`CreateFileW(WRITE_DAC)`＋
/// `SetKernelObjectSecurity`を避ける」ために置いたもので、**効きは大きいと書いてあるが
/// 測った値は無い**。
///
/// # 2つの軸
///
/// **軸1は置き場。** スキップが発火するのは「作った直後から保護済みで生まれる」ツリー
/// ——つまり`C:\`から降りる側だけで、`%TEMP%`配下では初回から書いている。
/// **だから製品側の費用は置き場で変わる**（そこが測る当のもの）。
///
/// **軸2は規模。** このリポジトリの`.harness/`は344ノードなので、その値とその約7倍を測る。
///
/// # 2回呼ぶ理由
///
/// 保護は`preflight`の同期区間と`grant_job`のフェーズ0.5の**2回**掛かる（スキップのdoc）。
/// 1回だけ測ると、スキップが効くはずの2回目を測り落とす。
#[test]
#[ignore = "実FSのDACLを書き換える費用測定（管理者権限不要）。結果はplans/mac-spike/RESULTS.mdへ転記する"]
fn control_dir_protect_skip_cost_probe() {
    use std::time::Instant;

    // このリポジトリの`.harness/`は245ファイル・99ディレクトリの344ノード。
    // `build_forest_tree(dir, 245, 14, 7)` が 1 + 98 + 245 = 344 で一致する。
    const SIZES: [(usize, usize, usize); 2] = [(245, 14, 7), (1715, 14, 7)];

    let bases: [(&str, PathBuf); 2] = [
        ("drive-root", PathBuf::from("C:\\")),
        ("user-temp", std::env::temp_dir()),
    ];

    let mut arms = Vec::new();
    for (place_label, base) in &bases {
        for (index, (files, k, depth)) in SIZES.iter().enumerate() {
            // 宛先SIDは純粋導出。**腕ごとに別のSIDにして干渉を断つ。**
            let sid = capability_sid_from_name(&format!(
                "harnessBug145SkipCost{place_label}{index}{}",
                std::process::id()
            ))
            .expect("derive a probe capability SID");

            // --- 腕A: 製品の保護関数を2回 ---
            let dir_a = super::test_support::TestDirGuard::create_in(
                base,
                &format!("bug145skip-prod-{place_label}-{index}"),
            );
            let harness_a = dir_a.path().join(".harness");
            let nodes = super::test_support::build_forest_tree(&harness_a, *files, *k, *depth);
            let t = Instant::now();
            let first_a = super::protect_harness_control_dir_from_appcontainer(
                dir_a.path(),
                &[sid.as_psid()],
            )
            .expect("product protect, first pass");
            let first_a_ms = t.elapsed().as_millis();
            let t = Instant::now();
            let second_a = super::protect_harness_control_dir_from_appcontainer(
                dir_a.path(),
                &[sid.as_psid()],
            )
            .expect("product protect, second pass");
            let second_a_ms = t.elapsed().as_millis();

            // --- 腕B: スキップ無しで、同じノードへ同じ書込を2回 ---
            let dir_b = super::test_support::TestDirGuard::create_in(
                base,
                &format!("bug145skip-forced-{place_label}-{index}"),
            );
            let harness_b = dir_b.path().join(".harness");
            let nodes_b = super::test_support::build_forest_tree(&harness_b, *files, *k, *depth);
            let forced_pass = |root: &Path| -> u128 {
                let mut dirs = Vec::new();
                let mut files = Vec::new();
                super::acl_grant::collect_dirs_and_files(
                    root,
                    &mut dirs,
                    &mut files,
                    OnVanished::Skip,
                )
                .expect("enumerate the control dir");
                let t = Instant::now();
                for node in files.iter().chain(dirs.iter().rev()) {
                    // **費用の比較なので製品と同じビットで書く**（印つきにすると、
                    // 測っているものが「スキップを外す費用」から変わってしまう）。
                    unsafe {
                        protect_forcing_the_write(node, sid.as_psid(), DaclProtection::Protected)
                    }
                    .expect("forced protect write");
                }
                t.elapsed().as_millis()
            };
            let first_b_ms = forced_pass(&harness_b);
            let second_b_ms = forced_pass(&harness_b);

            // --- 腕C: aclapiの口（**印が残る唯一の口**）で、剥がして保護を2回 ---
            //
            // ここが要るのは、印つきで直すなら製品はこの口になるからである。
            // `unprotect_harness_control_dir`のdocが「aclapiは1回あたり実測0.3ms程度」と
            // 書いているが、**それは24ノードでの値**で、344ノードでどうなるかは別の事実である。
            let dir_c = super::test_support::TestDirGuard::create_in(
                base,
                &format!("bug145skip-aclapi-{place_label}-{index}"),
            );
            let harness_c = dir_c.path().join(".harness");
            let nodes_c = super::test_support::build_forest_tree(&harness_c, *files, *k, *depth);
            let aclapi_pass = |root: &Path| -> u128 {
                let mut dirs = Vec::new();
                let mut files = Vec::new();
                super::acl_grant::collect_dirs_and_files(
                    root,
                    &mut dirs,
                    &mut files,
                    OnVanished::Skip,
                )
                .expect("enumerate the control dir");
                let t = Instant::now();
                for node in files.iter().chain(dirs.iter().rev()) {
                    unsafe { aclapi_strip_and_protect(node, sid.as_psid()) }
                        .expect("aclapi strip-and-protect");
                }
                t.elapsed().as_millis()
            };
            let first_c_ms = aclapi_pass(&harness_c);
            // **2回目は印を見て飛ばす**——狭めたスキップが入った後の姿である。
            let t = Instant::now();
            let mut skipped = 0usize;
            let mut rewritten = 0usize;
            {
                let mut dirs = Vec::new();
                let mut files = Vec::new();
                super::acl_grant::collect_dirs_and_files(
                    &harness_c,
                    &mut dirs,
                    &mut files,
                    OnVanished::Skip,
                )
                .expect("enumerate the control dir");
                for node in files.iter().chain(dirs.iter().rev()) {
                    if dacl_is_protected_and_auto_inherited(
                        dacl_control(node).expect("read control"),
                    ) {
                        skipped += 1;
                    } else {
                        unsafe { aclapi_strip_and_protect(node, sid.as_psid()) }
                            .expect("aclapi strip-and-protect");
                        rewritten += 1;
                    }
                }
            }
            let second_c_ms = t.elapsed().as_millis();

            assert_eq!(nodes, nodes_b, "2つの腕は同じ形のツリーでなければならない");
            assert_eq!(nodes, nodes_c, "3つの腕は同じ形のツリーでなければならない");
            arms.push(serde_json::json!({
                "placement": place_label,
                "nodes": nodes,
                "product_protected_first": first_a.protected,
                "product_protected_second": second_a.protected,
                "product_first_ms": first_a_ms,
                "product_second_ms": second_a_ms,
                "forced_first_ms": first_b_ms,
                "forced_second_ms": second_b_ms,
                "extra_ms_for_two_passes":
                    (first_b_ms + second_b_ms) as i128 - (first_a_ms + second_a_ms) as i128,
                // 印つき（aclapi）の腕。**2回目は印を見て飛ばした件数まで出す**
                // ——「速かったのは何もしていないから」を、そのまま数で言えるようにする。
                "aclapi_marked_first_ms": first_c_ms,
                "aclapi_marked_second_ms": second_c_ms,
                "aclapi_second_skipped": skipped,
                "aclapi_second_rewritten": rewritten,
                "aclapi_second_vs_product_second_ms": second_c_ms as i128 - second_a_ms as i128,
            }));
        }
    }

    println!(
        "{}",
        serde_json::json!({
            "measurement": "S34 cost of dropping the idempotent skip in remove_sid_aces_and_protect (BUG-145)",
            "arms": arms,
        })
    );

    // **合否は判定しない**（時間が測る当のもの）。実験の前提だけを見る——製品の保護関数が
    // 全ノードを「保護済み」と数えていること。ここが欠けると、比べているのが別の仕事になる。
    for arm in &arms {
        assert_eq!(
            arm["product_protected_first"], arm["nodes"],
            "製品の保護関数が全ノードを数えていない。腕Bと同じ仕事を測っていない: {arm}"
        );
        // **2回目が速い理由を数で言えるようにする**（`B-35`の対）。印つきの腕は
        // 「全ノードを飛ばした」から速いのであって、歩かなかったからではない。
        assert_eq!(
            arm["aclapi_second_skipped"], arm["nodes"],
            "印つきの2回目が全ノードを飛ばしていない。狭めたスキップが働いていない: {arm}"
        );
        assert_eq!(
            arm["aclapi_second_rewritten"],
            serde_json::json!(0),
            "印つきの2回目が書き直している。印が残っていない: {arm}"
        );
    }
}

/// **[BUG-145] 印（保護＋自動継承）は、実マシンの既存のノードと衝突しないか。**
///
/// 印つきで直すなら、スキップの条件は「印がある」になる。**自分が書いていないノードにも
/// 印が付いているなら、それを「自分が書いた」と誤認して飛ばす**——いまと同じ欠陥が戻る。
///
/// # 誤認しても安全か、は別に測ってある
///
/// 行列のケース18が「aclapiの口で保護されたノード（＝印つき）は配布に耐える」を
/// 6つの置き場すべてで出している。**だから印つきを飛ばすこと自体は安全**だが、
/// **どれだけ在るのかは知っておく価値がある**（多ければ「印＝自分が書いた」という
/// 読み方そのものを文書から外す必要がある）。
///
/// **読取だけである。** 1バイトも書かない。
#[test]
#[ignore = "実マシンのDACLを読むだけの調査（書込なし・管理者権限不要）。結果はplans/mac-spike/RESULTS.mdへ転記する"]
fn control_dir_mark_collision_probe() {
    let repo = repo_root();
    let mut samples: Vec<(String, PathBuf, bool)> = Vec::new();

    // 1. このリポジトリの実`.harness/`（再帰）——**印つきで直したときに触る当のツリー**。
    let harness_dir = repo.join(".harness");
    if harness_dir.is_dir() {
        let mut dirs = Vec::new();
        let mut files = Vec::new();
        super::acl_grant::collect_dirs_and_files(
            &harness_dir,
            &mut dirs,
            &mut files,
            OnVanished::Skip,
        )
        .expect("enumerate the real control dir");
        for node in dirs.into_iter().chain(files) {
            let marked = dacl_control(&node)
                .map(dacl_is_protected_and_auto_inherited)
                .unwrap_or(false);
            samples.push(("repo/.harness (recursive)".into(), node, marked));
        }
    }

    // 2. 代表的な場所の**直下だけ**（再帰しない——`%TEMP%`は数万件になり得る）。
    for (label, base) in [
        ("C:\\ (direct children)", PathBuf::from("C:\\")),
        ("%USERPROFILE% (direct children)", user_profile_root()),
        ("%TEMP% (direct children)", std::env::temp_dir()),
    ] {
        let Ok(entries) = std::fs::read_dir(&base) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let marked = dacl_control(&path)
                .map(dacl_is_protected_and_auto_inherited)
                .unwrap_or(false);
            samples.push((label.to_string(), path, marked));
        }
    }

    let mut per_group: std::collections::BTreeMap<&str, (usize, usize)> =
        std::collections::BTreeMap::new();
    for (label, _, marked) in &samples {
        let e = per_group.entry(label.as_str()).or_insert((0, 0));
        e.0 += 1;
        if *marked {
            e.1 += 1;
        }
    }

    println!("=== 印（保護＋自動継承）を持つノードの数 ===");
    for (label, (total, marked)) in &per_group {
        println!("  {label:<34}: {marked} / {total}");
    }
    println!("  --- 印つきの実例（先頭10件） ---");
    for (_, path, _) in samples.iter().filter(|(_, _, m)| *m).take(10) {
        println!("    {}", path.display());
    }

    // **数えたことを確かめる**（`B-35`）。0件という結果は「1件も無い」でも
    // 「1件も見ていない」でも成り立つので、標本が空なら測定は不成立である。
    assert!(
        !samples.is_empty(),
        "1ノードも読めていない。この測定は何も言っていない"
    );
}
