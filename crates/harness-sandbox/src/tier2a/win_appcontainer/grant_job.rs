//! workspaceの伝播＋救済walkを背景で回すジョブ（D-54、[BUG-082](../../../../docs/bugs/BUG-082.md) Part Bで拡張）。
//!
//! `preflight`の同期区間はrootへ継承ACEを、**伝播なし**（`DaclWrite::SingleObject`、
//! [`super::grant_workspace_root_aces_fast`]）で付けるだけにしてある——tier判定
//! （`smoke_test_spawn`）にはrootのDACL自体で足り、既存子孫への伝播は不要だからである。
//! このジョブはその**残り**を2フェーズで背景に引き受ける。
//!
//! [D-84] **配る主体は1つではなく全モードのcapability SIDである。** 2フェーズとも「M本を1回の書込に
//! まとめる」形で書かれていて、これは費用の要求から来ている——同一ノードのACEを増やしても
//! 1回の書込にまとめる限り時間は動かないが（`plans/mac-spike/RESULTS.md` §S15-1）、
//! 主体ごとに書くと約2.9倍、主体ごとにwalkを1周すると読取が本数倍になる。
//!
//! - **フェーズ0（伝播）**: [`super::propagate_workspace_root_grant`]がrootへの継承ACE伝播を
//!   冪等チェック無しで無条件に行う。OSが既存子孫へ物理コピーする、単一のブロッキングOS
//!   呼び出し（実測20秒超）。直後に`.harness/`を**第2の防御として**再保護する
//!   （[BUG-083](../../../../docs/bugs/BUG-083.md)）。
//!
//!   このフェーズ0.5は元々、`SE_DACL_PROTECTED`が立っておらず伝播が`.harness/`の子孫まで
//!   届いてしまうことへの**回避策**として入れたものである。
//!
//!   **[BUG-145、2026-08-30] このdocは長らく2つの誤りを書いていた。** 根拠に使わないこと。
//!
//!   1. 「BUG-083の修正で保護が実際に立つようになった」——**立っていなかった。**
//!      `C:\`から降りるツリーでは新しく作ったディレクトリが最初から`SE_DACL_PROTECTED`付きで
//!      生まれるので、`remove_sid_aces_and_protect`の冪等スキップが成立し、**保護の書込が
//!      1回も走っていなかった**。立っていたのはOSが作った保護で、伝播がそれを消していた。
//!   2. 「置き場で割れ、規則は未確定である」——**割れていたのは置き場ではない。**
//!      割れ目は「**自分がその保護を書いたか**」で、`%TEMP%`配下だけ安全に見えたのは
//!      そこでは保護済みで生まれずスキップが発火しなかったからである（`plans/mac-spike/RESULTS.md`
//!      §S34。置き場は6水準へ分解して測った）。
//!
//!   **いまはフェーズ0の伝播が`.harness/`の手前でOSに止められる**（§S37で実プロセスを起こして
//!   実測。標本器2腕とも露出0、修正を戻すと2.2秒露出する）。**成立させているのはBUG-145の修正**
//!   ——スキップの条件を「保護済み**かつ**自動継承あり」へ狭め、書込をaclapiの口へ変えたことである。
//!
//!   再保護そのものは元の理由でも要る——保護が止められるのは**継承経由の伝播だけ**で、
//!   (a) 保護をかける前から`.harness/`配下に物理コピーとして乗っていたACE、
//!   (b) D-37時代にpackage SID宛で付けられた残骸、は継承とは無関係に残るためである。
//!   `remove_sid_aces_and_protect`は「剥がすACEが無く、**かつ配布に耐える形で保護済み**」
//!   なら書込を省くので、2回目以降はノードごとのDACL読取だけで終わる（実測: 344ノードで
//!   9〜10ミリ秒。§S36-3）。
//! - **フェーズ1（救済walk）**: 保護DACL（`PROTECTED_DACL_SECURITY_INFORMATION`が立ったノード。
//!   [BUG-020](../../../../docs/bugs/BUG-020.md)の残存損害等）の配下だけは、フェーズ0の伝播が
//!   届かない。その救済（[`super::fix_descendants_missing_ace`]）はO(ファイル数)の読取確認で、
//!   この開発機のリポジトリでは28万ノード・実測18.5秒かかる。
//!
//!   [残課題#32] **「保護DACL配下だけ」は長らく事実ではなかった。** フェーズ0の伝播が
//!   既存の子孫へ1件も届いておらず、このwalkが**全ノードへ明示ACEを書いて**いた
//!   （2026-08-25にツリーによって最大 260,032/260,033 で確定）。2026-08-25の修正で
//!   doc本来の姿へ戻したが、**戻ったことは`granted`を見ないと分からない**——
//!   walkが全部救うので機能は壊れず、遅いだけで無症状である。だから
//!   [`WorkspaceGrantProgress::rescue_granted`]で値を出している。
//!
//! これはワークスペースにつき一度きりだが、その一度はrun_shellの初回呼び出しを
//! （フェーズ0＋1合計で）数十秒止める。preflight自体は同期区間が軽くなったぶん即座に戻り、
//! TUIを先に出せる（[`WorkspaceGrantProgress`]の`phase`で今どちらのフェーズかを表示できる）。
//!
//! ## 待ち合わせが要る理由（fail-closed）
//!
//! フェーズ0・1のいずれかが終わるまで、対応する範囲は**サンドボックスから見えない**。その
//! 状態で`run_shell`を走らせると、モデルには「そのファイルは存在しない/読めない」と見え、
//! 原因不明の失敗として現れる。だから子プロセスを起動する経路は[`wait_until_done`]で完了を
//! 待つ——待って失敗するなら、その理由を添えて断る方が、黙って部分的に壊れた世界を見せるより
//! 良い。
//!
//! ## DACL書込の競合を避けるための約束
//!
//! このジョブが走っている間、**同じツリーへ別のDACL書込を並行させてはいけない**。
//! `grant_ace_mask`は「読む→ACEを足す→書き戻す」なので、2つのスレッドが同じノードで
//! 交差すると片方のACEが消える。守り方は4つ:
//!
//! 1. `preflight`はACL作業を全て終えてから[`start`]する（fs-allow付与・`.harness/`保護の後）。
//! 2. `.harness/`は[`start`]に渡す`skip`で（フェーズ1の）対象外にする。フェーズ0.5で
//!    再保護した場所を、フェーズ1が付け直すと制御面の保護（D-05/D-09）が無言で外れる。
//! 3. フェーズ0とフェーズ0.5は必ずこの順で、かつフェーズ1より前に完走させる
//!    （伝播が`.harness/`へ届けたACEを、フェーズ1が救済walkとして誤って「継承漏れ」と
//!    判定し明示付与し直す前に、フェーズ0.5が剥がしておく必要がある）。
//! 4. セッション中に**workspaceツリーのどこかへDACLを書きうる経路**は、先に
//!    [`wait_until_done`]を通す。[BUG-085](../../../../docs/bugs/BUG-085.md): ここを
//!    「workspaceへACEを足す経路」と書いていたため、MCP preflight（D-38 §3.2）が
//!    `req.workspace`が`Some`のときだけ待つ実装になっていた。実際にはその手前で
//!    サーバの実行ファイル・スクリプトの親ディレクトリにもACEを付けており、それが
//!    workspace配下のこともある（プロジェクト同梱のMCPサーバ）。**条件は「その意図で
//!    書かれたコード」ではなく「その状態を作り得る全経路」で書くこと。**

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::win_common::OwnedSid;

/// 待ち合わせの上限。walkが何らかの理由で進まなくなったとき、`run_shell`を永久に止めない
/// ための保険。この開発機の実測（28万ノードで18.5秒）に対して十分な余裕がある。
const WAIT_TIMEOUT: Duration = Duration::from_secs(300);

/// [BUG-082 Part B] このジョブが今どの段にいるか（表示専用）。
///
/// `Propagating`は単一のブロッキングOS呼び出し（rootへの継承ACE伝播＋直後の`.harness/`
/// 再保護）なので中間進捗が取れず、`done`/`total`は0のまま——TUIステータスバーは既に
/// `total==0`を「準備中」と表示する分岐を持つため、フェーズ名だけをここへ足す。
/// `Walking`は既存の`fix_descendants_missing_ace`の進捗（`done`/`total`）をそのまま使う。
///
/// [D-88（`DESIGN-SANDBOX-APPPOLICY.md`）] `Scanning`はlazyレーンの走査器
/// （[`super::lazy_grant`]）。**母数を先に数えないので`total`は0のまま**進む
/// ——streaming列挙が「全部数え終わってから配り始める」のをやめた段そのものなので、
/// ここで母数を出すには走査を2周することになる。`total==0`の表示分岐は既にある。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobPhase {
    Propagating,
    Walking,
    Scanning,
}

/// この背景ジョブがどちらの形でツリーを準備するか。
///
/// **既定は[`Self::FullWalk`]（今日と同じ挙動）。** lazyレーンは実験的probeの内側にあり、
/// 不成立なら自動でこちらへ戻る（設計書§5.1.3「検証と昇格条件」）。
///
/// # なぜ2つ在るのか（どちらかに寄せない理由）
///
/// [`Self::FullWalk`]は**1回のOS呼び出しで既存の子孫へ配る**ので総処理量が小さい。
/// [`Self::Lazy`]はノードごとに明示ACEを書くので**総処理量は増える**が、
/// **途中に割り込みを入れられる**（単一のOS伝播は中断も優先度変更もできない）。
/// 設計はこの交換を承知のうえで「総完了時間は悪化を許容し、記録だけ残す」と決めている
/// ——利用者が待つのは自分が要求したものが開くまでの時間だけになるからである。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreparationLane {
    /// 伝播（フェーズ0）→ `.harness/`再保護（0.5）→ 救済walk（1）。**既定。**
    FullWalk,
    /// `.harness/`再保護 → 走査器＋単一writer（[`super::lazy_grant`]）。
    Lazy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceGrantProgress {
    pub phase: JobPhase,
    pub done: usize,
    pub total: usize,
    /// [BUG-084] フェーズ0.5（`.harness/**`の再保護、D-05/D-09の層3）が実際に保護できた
    /// ノード数。表示用ではなく**事後確認用**——`0`のまま`finished`になったら、制御面の
    /// 保護が1件も掛かっていない（BUG-083がこの実機で恒常的にそうなっていた）。
    pub protected_nodes: usize,
    /// [BUG-145] そのうち**実際にDACLを書いた**ノード数。
    ///
    /// `protected_nodes`だけでは、冪等スキップで**書込が1回も走っていない**状態と
    /// 実際に保護を確立した状態が同じ数に見える——それがBUG-145の本体だった。
    /// **初回は`protected_nodes`と同じになり、2回目以降は0になる**のが健全な形である。
    pub protection_writes: usize,
    /// [残課題#32] フェーズ1（救済walk）が**明示ACEを書いたノード数**。`protected_nodes`と
    /// 同じく表示用ではなく**事後確認用**である。
    ///
    /// **`0`が健全な状態**（[`super::DescendantFixReport::granted`]のdoc）。0でなければ
    /// フェーズ0の伝播が既存の子孫へ届いていない——つまり「書込1回で済むはずの段」が
    /// 何もしておらず、O(ノード数)の明示書込を毎回払っている。
    ///
    /// **この値がどこにも出ていなかったこと自体が残課題#32の見つけにくさの本体である**
    /// （フェーズ1が全部救うので機能は壊れず、遅いだけで無症状。`B-10`: 無言失敗を作らない）。
    /// 直った後も残す——ここが再び0でなくなったら、それは伝播の退化の再発である。
    pub rescue_granted: usize,
    /// フェーズ1が見たノード数（`skip`配下を含む）。`rescue_granted`だけでは
    /// 「届いたから0」と「1件も歩かなかったから0」を区別できないので対で持つ（`B-35`）。
    pub rescue_checked: usize,
    /// フェーズ1がDACLを読めなかったノード数（判定不能なので付与側へ倒した数）。
    pub rescue_probe_errors: usize,
    /// [D-88] lazyレーンのfault受付が**何件の割り込みを通したか**。
    ///
    /// **3つの状態を1つの値で区別する**（`B-35`: 対で見ないと読み違える）。
    ///
    /// - `None` — 受付が開いていない。既定レーンで走っているか、lazyレーンだが受付を
    ///   開けなかった（その場合は準備は進むが、子は割り込めない）。
    /// - `Some(0)` — 受付は開いたが、**割り込みは1件も来なかった**。
    /// - `Some(n)` — n件の割り込みが成立した。
    ///
    /// **`Some(0)`と`None`を混ぜてはいけない。** 前者は「効く用意はできていた」、後者は
    /// 「そもそも用意が無かった」で、受入（設計書§5.1.3の検証6「割り込みが成立したことを
    /// 直接測る」）はこの区別の上に立っている。
    pub broker_faults_served: Option<usize>,
    pub finished: bool,
    /// 完了していて、かつ失敗していた場合の理由。
    pub error: Option<String>,
}

impl WorkspaceGrantProgress {
    /// 0〜100の百分率（`total`が未確定のうちは0）。表示専用。
    pub fn percent(&self) -> u16 {
        if self.total == 0 {
            return 0;
        }
        ((self.done.min(self.total) * 100) / self.total) as u16
    }
}

/// [BUG-082フォローアップ] このジョブを`harness_core::tool::WaitReason`として公開する。
///
/// `run_shell`等が`wait_until_done()`で無反応に見えている間、**ユーザー**へ理由を見せる
/// ための実装（開発者はD-54の背景ジョブを知っているが、一般利用者にとって初回起動が
/// 数十秒沈黙するのは起動失敗と区別が付かない、`docs/bugs/BUG-082.md`のユーザー報告）。
/// `harness_tools::wait_reasons`が集約する既知の待機理由源の1つとして登録される。
pub struct WorkspaceAclWaitReason;

impl harness_core::tool::WaitReason for WorkspaceAclWaitReason {
    /// **表示に使う事実はここが唯一の出所**（`refactor-perspectives` R-01）。以前はツールカードが
    /// この`describe`を、TUIステータスバーが`progress()`を直接読んでおり、「終わっていたら
    /// 出さない」という同じ判定が2箇所にあった（片方だけ直すと表示が食い違う、B-02）。
    ///
    /// 失敗して終わった場合も`None`を返す——**失敗の扱いはここではなく`run_shell`が持つ**
    /// （`wait_until_done`がfail-closedで断り、理由をツール結果として見せる）。表示のための
    /// 関数に判定を持たせると、同じ事実が2箇所で解釈されることになる。
    fn active(&self) -> Option<harness_core::tool::WaitState> {
        let p: WorkspaceGrantProgress = progress()?;
        if p.finished {
            return None;
        }
        // `total == 0`（母数が未確定・伝播段のように中間進捗が無い）で件数を出さない判定は
        // **この1箇所だけ**が持つ。表示面ごとに`> 0`のガードを書かせない（B-02）。
        let (description, label) = match p.phase {
            // [D-88] lazyレーンの走査は**背景**である。ここが`Blocking`と同じ文面で出ると、
            // 「待たされている」と読める——待っていないことがレーンの目的なので、文面を分ける。
            JobPhase::Scanning => (
                "ワークスペースへSandbox用ACLを背景で適用中（コマンドは待っていません）"
                    .to_string(),
                format!("workspace ACL 準備中 (背景 {} ノード)", p.done),
            ),
            JobPhase::Propagating => (
                "実行ブロック中: 初回起動時中のため、ワークスペースへSandbox用ACLの適用中"
                    .to_string(),
                "workspace ACL 準備中 (継承を伝播中)".to_string(),
            ),
            JobPhase::Walking if p.total > 0 => (
                format!(
                    "実行ブロック中: 保護されたノードを検証中 {}% ({}/{})",
                    p.percent(),
                    p.done,
                    p.total
                ),
                format!(
                    "workspace ACL {}% (保護ノード検証 {}/{})",
                    p.percent(),
                    p.done,
                    p.total
                ),
            ),
            JobPhase::Walking => (
                "実行ブロック中: 保護されたノードを検証中".to_string(),
                "workspace ACL 準備中".to_string(),
            ),
        };
        Some(harness_core::tool::WaitState { description, label })
    }
}

#[derive(Default)]
struct JobState {
    /// `JobPhase`を`u8`で持つ（既定値0＝`Propagating`。`Default`導出がそのまま初期フェーズに
    /// なるよう、`PHASE_WALKING`だけを明示の定数にしてある）。
    phase: AtomicU8,
    done: AtomicUsize,
    total: AtomicUsize,
    /// フェーズ0.5が`.harness/**`へ保護を掛けられたノード数（BUG-084）。
    protected_nodes: AtomicUsize,
    /// [BUG-145] そのうち**実際にDACLを書いた**ノード数。
    protection_writes: AtomicUsize,
    /// フェーズ1の[`super::DescendantFixReport`]（残課題#32の事後確認用）。
    rescue_granted: AtomicUsize,
    rescue_checked: AtomicUsize,
    rescue_probe_errors: AtomicUsize,
    finished: AtomicBool,
    error: Mutex<Option<String>>,
    /// [D-88] lazyレーンのfault受付パイプの名前。子へ渡すために起動側が引く
    /// （[`lazy_broker_pipe_for`]）。**既定レーンでは`None`のまま**で、それが
    /// 「このworkspaceはlazyで準備していない」の判定そのものになる。
    ///
    /// **名前は秘密ではない**（子から`\\.\pipe\`の一覧は取れる）。守るのはパイプのDACLだけ。
    broker_pipe: Mutex<Option<String>>,
    /// [D-88] 受付が開いたか、開いたなら何件通したか
    /// （[`WorkspaceGrantProgress::broker_faults_served`]の実体）。
    broker_faults_served: Mutex<Option<usize>>,
}

const PHASE_WALKING: u8 = 1;
/// [D-88] lazyレーンの走査段。
const PHASE_SCANNING: u8 = 2;

/// [`JOBS`]の1エントリ（ジョブの鍵と状態）。
type JobEntry = (String, Arc<JobState>);

/// このプロセスで動いている/動いたジョブの一覧。**workspace＋モード＋capability generation
/// ごとに1本**（キーは [`job_key`]）。明示 revoke 後に同じプロセスで再準備した場合は主体が
/// 変わるため、新しいジョブとして扱う。
///
/// [BUG-082] 当初は「1プロセス＝1workspace＝1モードなので1本で足りる」という前提の
/// `OnceLock<Arc<JobState>>`（プロセス全体で1本きり）だった。製品の`harness.exe`はこの前提が
/// 成り立つ（1プロセスにつき1回だけ`preflight`を呼ぶ）が、**同じプロセスで複数の
/// workspaceを`preflight`する実機テスト**（`cow_containment_tests.rs`等）では、2つ目以降の
/// workspaceの`start`が常に`false`（＝伝播もwalkも一切走らない）になり、Part Bで伝播が
/// このジョブへ移ったことで**その workspace の既存ファイルが子から永久に見えなくなる**
/// 退化を引き起こした（BUG-082のPart B検証で発覚）。workspace＋モードごとにジョブを分けれ
/// ば、製品での挙動（実質1本）はそのままに、複数workspaceが同居するテストプロセスでも
/// それぞれが自分のジョブを持てる。
static JOBS: OnceLock<Mutex<Vec<JobEntry>>> = OnceLock::new();

fn jobs() -> &'static Mutex<Vec<JobEntry>> {
    JOBS.get_or_init(|| Mutex::new(Vec::new()))
}

/// [`JOBS`]の鍵。`workspace_capability::workspace_key`と同じ正規化（大文字小文字・区切り・
/// `\\?\`前置の揺れを吸収）にモードを連結する——揺れで別キーになると、同じworkspaceへ
/// 2本のジョブが並行して同じツリーへDACL書込を行いかねない（モジュールdocの「約束」）。
fn job_key_prefix(workspace: &Path, mode: &str) -> String {
    format!(
        "{}\u{0}{mode}",
        crate::tier2a::workspace_capability::workspace_key(workspace)
    )
}

fn job_key(workspace: &Path, mode: &str, capability_generation: &str) -> String {
    format!(
        "{}\u{0}{capability_generation}",
        job_key_prefix(workspace, mode)
    )
}

/// 救済walkを背景スレッドで開始する。**モジュールdocの「約束」を満たしてから呼ぶこと。**
///
/// workspace＋モードごとに1本（[`job_key`]）。**同じworkspace＋モードで既に開始済みなら
/// `false`を返して何もしない。** 製品では`preflight`がプロセスにつき1回・1 workspaceしか
/// 呼ばないので常に`true`だが、同じ(workspace, mode)へ`preflight`を2回呼ぶような呼び出し方
/// （通常は起こらない）をした場合だけ`false`になる——戻り値を捨てると「起動したつもりで
/// 何も走っていない」呼び出しが黙って緑になるので、呼び出し側に見せる。
///
/// 完走したら[`crate::tier2a::workspace_capability::mark_tree_verified`]を立てるので、
/// 次回起動はwalk自体をしない。
///
/// [BUG-082 Part B] `preflight`の同期区間はroot付与を[`super::grant_workspace_root_aces_fast`]
/// （`DaclWrite::SingleObject`、伝播なし）にしたため、既存子孫への伝播そのものをこのジョブの
/// **最初のフェーズ**として引き受ける（[`super::propagate_workspace_root_grants`]、冪等チェックを
/// バイパスして無条件に呼ぶ——理由は同関数のdoc参照）。
///
/// **`protect_sids`が必要な理由（[BUG-083](../../../../docs/bugs/BUG-083.md)）**:
/// `.harness/`の保護（`protect_harness_control_dir_from_appcontainer`）は`preflight`の同期区間で
/// 既に一度行われており、**[BUG-145](../../../../docs/bugs/BUG-145.md)の修正以降**その保護は
/// 実際に効く（フェーズ0の伝播は`.harness/`の手前でOSに止められる）。
/// **かつてここは「BUG-083の修正以降」と書いていたが誤りである**——BUG-083の修正はこの機で
/// 一度も効いておらず、保護の書込が冪等スキップで丸ごと省かれていた（モジュールdoc冒頭を参照）。
/// それでも伝播の直後にもう一度保護し直すのは、**保護が止められるのは
/// 継承経由の伝播だけ**だからである——保護をかける前から`.harness/`配下に物理コピーとして
/// 乗っていたACEや、D-37時代にpackage SID宛で付けられた残骸は、継承とは無関係にそこに在る。
/// D-05/D-09の不変条件（サンドボックスから制御面が書けない）を背景フェーズでも維持するための
/// 第2の防御である。`protect_sids`は`preflight`が渡すのと同じ集合
/// （workspace capability＋セッションのSID）。
/// **`ace_grants`は全モードのcapability SID宛ACE**（[D-84]）。ここが1本だと、そのモードの
/// セッションからしかworkspaceが見えないツリーが出来上がり、モードを切り替えた瞬間に26万件を
/// 払い直す——それを消すのがD-84である。フェーズ0（伝播）もフェーズ1（救済walk）も、**多本を1回の
/// 書込にまとめる形**でここから下へ降りる（`plans/mac-spike/RESULTS.md` §S15-1）。
///
/// **`capability_generation`は合流の鍵である**（D-85）。同じworkspace＋モードでも、capabilityの
/// 世代が変われば主体そのものが別のSIDになるので、**前の世代のジョブが走っていることを理由に
/// 新しい世代の準備を飛ばしてはならない**。[`job_key`]がこの3つ組で1本を決める。
///
/// **`lane`は既定で[`PreparationLane::FullWalk`]**（今日と同じ挙動）。[`PreparationLane::Lazy`]は
/// [D-88（`DESIGN-SANDBOX-APPPOLICY.md`）]のレーンで、走査の途中に割り込みを入れられる形
/// である代わりに総処理量が増える。
pub(crate) struct GrantJobRequest<'a> {
    pub(crate) root: &'a Path,
    pub(crate) ace_grants: Vec<super::OwnedAceGrant>,
    pub(crate) protect_sids: Vec<OwnedSid>,
    pub(crate) skip: Vec<PathBuf>,
    pub(crate) workspace: &'a Path,
    pub(crate) mode: &'a str,
    pub(crate) capability_generation: &'a str,
    pub(crate) lane: PreparationLane,
}

#[must_use = "false means the job was not started (another one already claimed this process)"]
pub(crate) fn start(request: GrantJobRequest<'_>) -> bool {
    let GrantJobRequest {
        root,
        ace_grants,
        protect_sids,
        skip,
        workspace,
        mode,
        capability_generation,
        lane,
    } = request;
    let key = job_key(workspace, mode, capability_generation);
    let state = Arc::new(JobState::default());
    {
        let mut list = jobs().lock().unwrap();
        if list.iter().any(|(k, _)| k == &key) {
            return false;
        }
        list.push((key, Arc::clone(&state)));
    }
    crate::tier2a::workspace_capability::mark_tree_preparing(workspace, mode);

    let root = root.to_path_buf();
    let workspace = workspace.to_path_buf();
    let mode = mode.to_string();
    let lock_name = prepare_lock_name(&workspace, &mode);

    // [D-88] **このworkspaceを準備してよいのは、いつでも1プロセスだけである。**
    //
    // DACLの付与は「読む→足す→書き戻す」なので、別の`harness.exe`と交差すると片方の
    // 書込が消える（lost update）。消えるのは**こちらが足そうとした許可**なので普段は
    // 拒否側＝安全側へ倒れるが、`.harness/`の再保護だけは「読む→**外す**→書き戻す」で、
    // 交差すると**外したはずの許可が戻る**——そちらは安全側ではない。
    //
    // だから名前付きミューテックスを1つだけ置き、**取れたプロセスだけが書く**。取れなければ
    // 相手に任せて待つ（`follow_the_leader`）。設計書§5.1.3の writer-leader mutex がこれである。
    //
    // [BUG-146] **取得はこのスレッドではなく背景スレッドで行う。** Windowsの名前付き
    // ミューテックスは所有権が取得したスレッドに紐づくので、ここで取って背景スレッドで
    // 解放すると`ReleaseMutex`が失敗する。失敗しても`CloseHandle`は成功するため、
    // 待っている別の`harness.exe`は**leaderのプロセスが終了するまで**動き出せなくなる
    // （対話セッションは終了しないので、そのworkspaceが実質使えなくなる）。
    //
    // ただし`start`は、次の2つが済むまでは返れない（下の`ready_rx.recv()`）。
    //
    // 1. leaderかどうかが決まること。
    // 2. [D-88] **lazyレーンの受付の名前が公開されていること。** `preflight`（＝`start`の
    //    呼び出し元）が返った直後に`run_shell`が来たとき、`lazy_broker_pipe_for`がまだ
    //    `None`を返す窓ができると、そのコマンドは**レーンがあるのに従来どおり待つ**
    //    ——受入E2Eが実際にこれで落ちた（`B-18`: 確認と作成を不可分にする）。
    //
    // 待ち時間は移す前と同じである（取得は待たない`try_`で、受付の開設はもともと`start`が
    // 同期的に払っていた）。
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let leader = crate::try_acquire_named_lock(&lock_name);

        // **ミューテックスを取れなかったプロセスは受付を開かない。** 開くと、書く権利が
        // 無いのに割り込みでDACLを書くことになり、排他の意味が無くなる。
        let lazy = match (lane, &leader) {
            (PreparationLane::Lazy, Some(_)) => {
                Some(LazyLanePrep::open(&root, &ace_grants, &skip, &mode, &state))
            }
            _ => None,
        };
        // ここまでで上の1と2は済んでいる。`start`を返してよい。
        let _ = ready_tx.send(());

        let result = match (leader, lazy) {
            // 取れている＝自分が書く。持ったまま最後まで走る。
            (Some(guard), Some(lazy)) => {
                let r = run_lazy_lane(&root, lazy, &protect_sids, &skip, &state);
                drop(guard);
                r
            }
            (Some(guard), None) => {
                let r = run_full_walk_lane(&root, &ace_grants, &protect_sids, &skip, &state);
                drop(guard);
                r
            }
            // 取れていない＝別のプロセスが準備中。**1バイトも書かずに待つ。**
            (None, _) => follow_the_leader(
                &lock_name,
                &root,
                &ace_grants,
                &protect_sids,
                &skip,
                &state,
            ),
        };
        // **成否の記録はここ1箇所**（`B-02`: 2つのレーンで書き方が割れると、片方だけ
        // 台帳へ残らない形になる）。**失敗を台帳へ残す**理由はD-85——残さないと次回の起動は
        // 「準備中のまま終わった」と「そもそも始めていない」を区別できない。
        match result {
            Ok(()) => crate::tier2a::workspace_capability::mark_tree_verified(&workspace, &mode),
            Err(error) => {
                crate::tier2a::workspace_capability::mark_tree_preparation_failed(
                    &workspace, &mode, &error,
                );
                *state.error.lock().unwrap() = Some(error);
            }
        }
        // `finished`は最後に立てる。先に立てると、待ち手が`error`を読む前に「成功で終わった」と
        // 判断してしまう（`Ordering::Release`と対の`Acquire`で読む）。
        state.finished.store(true, Ordering::Release);
    });
    // [BUG-146] 背景スレッドがleaderを決め、（lazyレーンなら）受付を開くまで待つ。
    // **送り手が落ちた場合も`Err`で戻る**ので、スレッドがpanicしてもここで固まらない。
    let _ = ready_rx.recv();
    true
}

/// [D-88] このworkspace＋modeを準備する権利を表すミューテックスの名前（writer-leader mutex）。
///
/// **`Local\`接頭辞を付ける**——このセッション（ログオンセッション）の中だけで一意なら
/// 十分で、`Global\`にすると別ユーザーのharnessまで巻き込む。鍵の正規化はジョブ鍵と
/// 同じものを使う（綴りの揺れで別のミューテックスになると、ミューテックスが2つあるのと同じになる）。
fn prepare_lock_name(workspace: &Path, mode: &str) -> String {
    // **末尾の区切りを先に落とす。** `workspace_key`は綴りの揺れを畳むが、末尾の`\`は
    // 残す——残ったまま名前にすると`C:\ws`と`C:\ws\`が**別のミューテックス**になり、2つのプロセスが
    // それぞれ別のミューテックスを取って「両方が leader」になる。排他が黙って消える形なので、
    // 自分のテストで見つかるまで気付けなかった（`B-10`）。
    let folded = crate::tier2a::workspace_capability::workspace_key(workspace);
    let folded = folded.trim_end_matches(['\\', '/']);
    format!(
        "Local\\harness-ws-prepare-{}-{mode}",
        // カーネルオブジェクト名に使えない文字を潰す。**潰し方が違うと別のミューテックスになる**ので、
        // ここ1箇所だけが決める。
        folded.replace(['\\', ':', '/'], "_")
    )
}

/// [D-88] **別のプロセスが準備している間、1バイトも書かずに待つ。**
///
/// ミューテックスが空くまで待ち、空いたら**本当に終わっているかを実体で確かめる**。終わっていれば
/// 何もしない（相手が全部やってくれた）。終わっていなければ自分で全walkをやる——
/// 相手が途中で落ちた場合（ミューテックスが放棄状態になった場合）がこれに当たる。
///
/// **台帳の「検証済み」だけを根拠にしない**（`B-14`: 記録の存在で実体の存在を代替しない）。
/// 実DACLを浅く見て、届いていなければやり直す。
fn follow_the_leader(
    lock_name: &str,
    root: &Path,
    ace_grants: &[super::OwnedAceGrant],
    protect_sids: &[OwnedSid],
    skip: &[PathBuf],
    state: &Arc<JobState>,
) -> Result<(), String> {
    crate::with_named_lock(lock_name, || {
        let sids: Vec<windows::Win32::Security::PSID> =
            ace_grants.iter().map(|g| g.sid.as_psid()).collect();
        if super::top_level_child_missing_aces(root, &sids, skip).is_none() {
            // 相手が配り終えていた。**こちらは何も書かない。**
            let mut timing = super::PhaseTiming::start();
            timing.mark("  background: another process prepared this workspace; nothing to do");
            return Ok(());
        }
        // 相手が途中で終わった（落ちた等）。自分が引き継ぐ。
        run_full_walk_lane(root, ace_grants, protect_sids, skip, state)
    })
}

/// フェーズ0.5（[BUG-083](../../../../docs/bugs/BUG-083.md)対策）: `.harness/`を再保護する。
///
/// **両レーンが通る**。`.harness/`が存在しなければ
/// `protect_harness_control_dir_from_appcontainer`は無害な早期returnになる。
fn protect_control_dir(
    root: &Path,
    protect_sids: &[OwnedSid],
    state: &JobState,
) -> Result<(), String> {
    let protect_psids: Vec<windows::Win32::Security::PSID> =
        protect_sids.iter().map(|s| s.as_psid()).collect();
    // [BUG-084] 件数を残す。この背景フェーズはユーザーに何も見せずに終わるので、
    // 記録しないと「D-05/D-09の層3が1件も掛からなかった」ことを事後に知る手段が無い。
    let nodes = super::protect_harness_control_dir_from_appcontainer(root, &protect_psids)
        .map_err(|e| e.to_string())?;
    // [BUG-145] **書いた件数も残す。** 「保護済み」だけでは、書込が省かれていても
    // 同じ数になる——それが見えなかったことがこの欠陥の本体だった。
    state.protected_nodes.store(nodes.protected, Ordering::Relaxed);
    state.protection_writes.store(nodes.written, Ordering::Relaxed);
    Ok(())
}

/// 既定のレーン: 伝播（0）→ `.harness/`再保護（0.5）→ 救済walk（1）。
fn run_full_walk_lane(
    root: &Path,
    ace_grants: &[super::OwnedAceGrant],
    protect_sids: &[OwnedSid],
    skip: &[PathBuf],
    state: &Arc<JobState>,
) -> Result<(), String> {
    // 借用版へ落とすのは**この1箇所**（フェーズ0とフェーズ1が同じ値を見ることを、
    // 変数1つで保証する。別々に作ると片方だけACEが欠けても気付けない）。
    let ace_grant_refs = super::OwnedAceGrant::borrow_all(ace_grants);
    // フェーズ0: rootへの継承ACE伝播（冪等チェック無し、必ず呼ぶ）。全ACEを1回で。
    super::propagate_workspace_root_grants(root, &ace_grant_refs).map_err(|e| e.to_string())?;

    // フェーズ0.5: 伝播が`.harness/`の子孫へも物理コピーを届けた可能性があるため、直後に
    // もう一度剥がし直す（**この順序が要るのは伝播があるレーンだけ**、`run_lazy_lane`参照）。
    protect_control_dir(root, protect_sids, state)?;

    // フェーズ1: 保護DACL配下の救済walk（既存）。
    state.phase.store(PHASE_WALKING, Ordering::Relaxed);
    let progress_state = Arc::clone(state);
    let report = super::fix_descendants_missing_aces(root, &ace_grant_refs, skip, &move |
        done,
        total,
    | {
        progress_state.done.store(done, Ordering::Relaxed);
        progress_state.total.store(total, Ordering::Relaxed);
    })
    .map_err(|e| e.to_string())?;

    // [残課題#32] **報告を捨てない。** ここが`Ok(_)`で握り潰されていたために、
    // 「フェーズ0が17秒かけて何も配っておらず、実際に配っているのはこのwalkだけ」
    // という状態が実運用で一度も可視化されなかった（`B-10`）。
    state.rescue_granted.store(report.granted, Ordering::Relaxed);
    state.rescue_checked.store(report.checked, Ordering::Relaxed);
    state
        .rescue_probe_errors
        .store(report.probe_errors, Ordering::Relaxed);
    // 文面は`grant_ace_inheritable_rw`が出しているものに揃える（同じ事実を2つの綴りで
    // 出さない）。既定では何も出ない＝`HARNESS_PREFLIGHT_TIMING=1`のときだけ。
    let mut timing = super::PhaseTiming::start();
    timing.mark(&format!(
        "  background: rescue walk ({} checked, {} explicit grants, {} probe errors)",
        report.checked, report.granted, report.probe_errors
    ));
    if !report.samples.is_empty() {
        timing.mark_lines("  background: not reached by inheritance", &report.samples);
    }
    Ok(())
}

/// [D-88（`DESIGN-SANDBOX-APPPOLICY.md`）] lazyレーン: `.harness/`再保護 → 走査器＋単一writer。
///
/// # **伝播（フェーズ0）を使わない。速さの話ではなく、安全性の話である**
///
/// 伝播する書込は、**書込の直前にその主体のACEをrootから外す**
/// （[`super::acl_dacl_write`]のモジュールdoc「だからこの部品は何をするか」）。
/// あちらは「一瞬だけ、rootにその主体のACEが無い状態が生まれる」ことを認めたうえで、
/// **その窓が踏まれない根拠を「子プロセスは`wait_until_done`で完了を待つから」に置いている。**
///
/// **lazyレーンはその待ちを外すレーンである。** つまり根拠が成立しない——走っている子が
/// その瞬間にworkspaceを開くと、**ツリー全体が一瞬見えなくなる**。だからこのレーンは
/// 伝播する口を一度も呼ばず、[`super::lazy_grant::writer`]の単一オブジェクト書込
/// （剥がさない口）だけでツリーを埋める。**fallbackでも呼ばない**（下記）。
///
/// # `.harness/`の再保護を**先**に置く理由
///
/// 既定レーンで再保護が伝播の**後**に居るのは、伝播が`.harness/`配下へ物理コピーを
/// 届け得るからである。このレーンには伝播が無く、走査器は`skip`（`.harness/`）へ
/// 降りない。**したがって後ろに置く理由が無く、前に置くと制御面の保護が最初に立つ**
/// ——`preflight`の同期区間が終わってから保護が掛かるまでの時間が、既定レーンの
/// 「伝播1回ぶん」から「ゼロ」になる。
///
/// # このレーンでの`rescue_granted`の読み方が変わる（**既存の読み方を持ち込まない**）
///
/// 既定レーンでは`rescue_granted != 0`が「伝播が届いていない」＝退化の兆候だった。
/// **このレーンでは伝播が無いので、走査器が全ノードへ明示ACEを書くのが正常**である。
/// 同じ数字を同じ意味で読むと、健全な状態を退化と読み違える。
fn run_lazy_lane(
    root: &Path,
    lazy: LazyLanePrep,
    protect_sids: &[OwnedSid],
    skip: &[PathBuf],
    state: &Arc<JobState>,
) -> Result<(), String> {
    let LazyLanePrep { mut writer, broker } = lazy;
    protect_control_dir(root, protect_sids, state)?;

    state.phase.store(PHASE_SCANNING, Ordering::Relaxed);

    let control = ScanProgress {
        state: Arc::clone(state),
    };
    let scan = super::lazy_grant::scanner::scan(root, skip, &writer.handle(), &control);

    // **受付を先に閉じる。** writerを先に畳むと、その後に来たfaultが`Unavailable`になり、
    // 子は「もう準備は終わっているのに barrier で待つ」という無駄な待ちへ入る。
    // 閉じたら名前も消す——残すと、起動側が既に無い受付へ子を向ける（`B-14`:
    // 記録の存在で実体の存在を代替しない）。
    //
    // **閉じる前に、待っている子を起こす。** フックを入れられずに一時停止したまま
    // 待っている子が居るので、走査の成否を伝えてから畳む（伝えずに畳むと、その子は
    // 「配り切れなかった」扱いで動き出す——安全側だが、完走したのに損をする）。
    let scan_covered_everything = matches!(&scan, Ok(report) if !report.stopped_early);
    if let Some(broker) = &broker {
        broker.release_waiters(scan_covered_everything);
    }
    let broker_stats = broker.map(|mut broker| broker.stop());
    *state.broker_pipe.lock().unwrap() = None;
    if let Some(stats) = broker_stats {
        // **受付が閉じても件数は残す。** 消すと「割り込みが成立したか」を事後に測れない
        // （設計書§5.1.3の検証6が要求している唯一の数字）。
        *state.broker_faults_served.lock().unwrap() = Some(stats.served);
    }

    // **走査の成否に関わらずwriterは畳む**（安全点で1件を完了させてから止まる）。
    // ここを早期returnで飛ばすと、スレッドとACL書込の主体が残る（`B-01`）。
    let stats = writer.stop_at_safe_point();

    // [残課題#32と対をなす記録] このレーンでは**書いた数が正常に0でない**（上のdoc）。
    // 走査が1件も歩かなかった場合と区別できるよう、見た数と対で残す（`B-35`）。
    state.rescue_granted.store(stats.granted, Ordering::Relaxed);
    state.rescue_checked.store(stats.processed, Ordering::Relaxed);
    state
        .rescue_probe_errors
        .store(stats.probe_errors, Ordering::Relaxed);

    let report = scan.map_err(|_| {
        "the lazy ACL writer stopped before the scan finished; \
         part of the workspace may still be unreachable from the sandbox (D-88)"
            .to_string()
    })?;
    if report.stopped_early {
        return Err(
            "the lazy workspace scan was stopped before it finished; \
             part of the workspace may still be unreachable from the sandbox (D-88)"
                .to_string(),
        );
    }
    let mut timing = super::PhaseTiming::start();
    timing.mark(&format!(
        "  background: lazy scan ({} submitted, {} explicit grants, {} skipped, \
         {} probe errors, {} vanished, {} faults served)",
        report.submitted,
        stats.granted,
        report.skipped,
        stats.probe_errors,
        stats.vanished,
        stats.faults_served
    ));
    // **受付の内訳も残す。** `served`だけでは「割り込みが効いた」と「そもそも1件も
    // 来なかった」を区別できず、`denied`と`unavailable`を分けないと
    // 「境界が働いた」と「こちらが不調だった」が混ざる（`B-35`・`B-10`）。
    if let Some(broker) = broker_stats {
        timing.mark(&format!(
            "  background: lazy broker ({} served, {} denied, {} unavailable, \
             {} non-appcontainer clients refused)",
            broker.served, broker.denied, broker.unavailable, broker.rejected_clients
        ));
    }
    Ok(())
}

/// [D-88] lazyレーンの道具立て。**`start`が同期的に組んで、背景スレッドへ渡す。**
///
/// スレッドの中で組むと、受付の名前が公開されるまでの窓ができる（[`start`]のコメント）。
struct LazyLanePrep {
    writer: super::lazy_grant::writer::AclWriter,
    /// 受付。**開けなくてもレーンは続ける**——受付が無ければ子は割り込めないが、走査は
    /// 進むので準備は完了する（遅いだけで壊れない）。ここを`Err`で止めると、
    /// 受付を作れないという可用性の問題が**ツリー全体の準備失敗**に化ける。
    broker: Option<super::lazy_grant::broker::Broker>,
}

impl LazyLanePrep {
    fn open(
        root: &Path,
        ace_grants: &[super::OwnedAceGrant],
        skip: &[PathBuf],
        mode: &str,
        state: &Arc<JobState>,
    ) -> Self {
        let writer =
            super::lazy_grant::writer::AclWriter::start(root.to_path_buf(), ace_grants.to_vec());
        let broker = match open_broker(root, ace_grants, skip, mode, writer.handle()) {
            Ok(broker) => {
                *state.broker_pipe.lock().unwrap() = Some(broker.pipe_name().to_string());
                // **開いた時点で`Some(0)`にする。** 完了時にまとめて入れると、走査中はずっと
                // `None`＝「受付が無い」に見え、`None`と`Some(0)`の区別（`B-35`）が
                // 肝心の走査中だけ効かない。
                *state.broker_faults_served.lock().unwrap() = Some(0);
                Some(broker)
            }
            Err(_) => None,
        };
        Self { writer, broker }
    }
}

/// lazyレーンのfault受付を開く。**受け付ける範囲は走査と同じ集合から作る**
/// （`skip`をそのまま渡す。ここがずれると、走査が意図的に外した場所をbrokerが付け直す、`B-05`）。
fn open_broker(
    root: &Path,
    ace_grants: &[super::OwnedAceGrant],
    skip: &[PathBuf],
    mode: &str,
    writer: super::lazy_grant::writer::WriterHandle,
) -> Result<super::lazy_grant::broker::Broker, String> {
    // [D-84] **全モードのcapability SIDをパイプへ載せる。** 片方だけだと、もう片方の
    // モードのセッションでは子がパイプを開けず、fault-inが**静かに**一度も効かなくなる。
    let capabilities: Vec<String> = ace_grants
        .iter()
        .filter_map(|grant| crate::win_common::sid_to_string(grant.sid.as_psid()).ok())
        .collect();
    if capabilities.is_empty() {
        return Err("no capability sid could be rendered for the broker pipe".to_string());
    }
    let canonical_workspace = root
        .canonicalize()
        .map_err(|e| format!("failed to canonicalize the workspace root: {e}"))?;
    super::lazy_grant::broker::Broker::start(
        super::lazy_grant::broker::FaultPolicy {
            canonical_workspace,
            skip: skip.to_vec(),
            mode: mode.to_string(),
        },
        writer,
        &capabilities,
    )
}

/// [D-88] 指定した`(workspace, mode)`がlazyレーンで準備中なら、fault受付パイプの名前を返す。
///
/// **`None`は「lazyで準備していない」**——既定レーンで走っている、まだ始まっていない、
/// あるいは既に終わった、のいずれかである。起動側はこの3つを区別する必要が無い
/// （どれも「今日と同じく待つ」に落ちる）。
pub fn lazy_broker_pipe_for(workspace: &Path, mode: &str) -> Option<String> {
    let prefix = format!("{}\u{0}", job_key_prefix(workspace, mode));
    // 状態を`Arc`で取り出してからジョブ一覧のロックを手放す（一覧のロックを握ったまま
    // 状態のロックを取ると、2つのロックの順序が経路ごとに変わり得る）。
    let state = {
        let list = jobs().lock().unwrap();
        list.iter()
            .rev()
            .find(|(key, _)| key.starts_with(&prefix))
            .map(|(_, state)| Arc::clone(state))
    }?;
    let pipe = state.broker_pipe.lock().unwrap().clone();
    pipe
}

/// 走査の進捗を[`JobState`]へ流す。**止める口はまだ繋がっていない**——
/// fallback controllerとツールのキャンセルは段2以降で繋ぐ。
struct ScanProgress {
    state: Arc<JobState>,
}

impl super::lazy_grant::scanner::ScanControl for ScanProgress {
    fn should_stop(&self) -> bool {
        false
    }

    fn progress(&self, submitted: usize) {
        // `total`は据え置き（0＝母数未確定）。streaming列挙は母数を先に数えない
        // ——数えるには走査を2周することになる（[`JobPhase::Scanning`]のdoc）。
        self.state.done.store(submitted, Ordering::Relaxed);
    }
}

fn snapshot_progress(state: &JobState) -> WorkspaceGrantProgress {
    let finished = state.finished.load(Ordering::Acquire);
    let phase = match state.phase.load(Ordering::Relaxed) {
        PHASE_WALKING => JobPhase::Walking,
        PHASE_SCANNING => JobPhase::Scanning,
        _ => JobPhase::Propagating,
    };
    WorkspaceGrantProgress {
        phase,
        done: state.done.load(Ordering::Relaxed),
        total: state.total.load(Ordering::Relaxed),
        protected_nodes: state.protected_nodes.load(Ordering::Relaxed),
        protection_writes: state.protection_writes.load(Ordering::Relaxed),
        rescue_granted: state.rescue_granted.load(Ordering::Relaxed),
        rescue_checked: state.rescue_checked.load(Ordering::Relaxed),
        rescue_probe_errors: state.rescue_probe_errors.load(Ordering::Relaxed),
        broker_faults_served: *state.broker_faults_served.lock().unwrap(),
        finished,
        error: if finished {
            state.error.lock().unwrap().clone()
        } else {
            None
        },
    }
}

/// 進行中/完了済みのジョブの状態。`None`は「このプロセスでは一度も`start`が要らなかった」
/// （＝台帳が完走済みを記録している）ことを意味する。
///
/// 複数workspaceが同居するプロセス（実機テスト）では**最後に`start`したジョブ**を返す
/// ——製品（`harness.exe`）は常にちょうど1本なのでこの選び方に意味は無い（TUIの表示用途は
/// 製品でしか使わない）。
pub fn progress() -> Option<WorkspaceGrantProgress> {
    let list = jobs().lock().unwrap();
    let (_, state) = list.last()?;
    Some(snapshot_progress(state))
}

/// 指定した `(workspace, mode)` の最新generationの状態。
///
/// 通常製品は1 workspaceだけだが、`harness fs prepare-workspace`と実機テストは対象を明示して
/// 進捗を待つため、プロセス全体の「最後の1本」ではなくこの入口を使う。
pub fn progress_for(workspace: &Path, mode: &str) -> Option<WorkspaceGrantProgress> {
    let prefix = format!("{}\u{0}", job_key_prefix(workspace, mode));
    let list = jobs().lock().unwrap();
    let (_, state) = list
        .iter()
        .rev()
        .find(|(key, _)| key.starts_with(&prefix))?;
    Some(snapshot_progress(state))
}

/// このプロセスで開始された**全ての**ジョブの完了を待つ。1本も無ければ即座に`Ok`。
///
/// [BUG-082] 呼び出し側（`run_shell`等）は「自分がこれから触るworkspaceのジョブ」だけを
/// 待ちたいはずだが、`start`はワークスペース＋モードごとに独立したジョブを作るため、この
/// プロセスの中で**自分のジョブがどれか**を呼び出し側から見分ける手段が無い（`run_shell`は
/// 単に「preflightが仕込んだジョブが終わっているか」だけを知りたい）。**製品では
/// workspaceが1つしか無いのでこの区別は不要**——複数ジョブが並ぶのは同一プロセスで複数
/// workspaceを`preflight`する実機テストだけであり、そこでは「自分のジョブを含む全ジョブを
/// 待つ」ことが安全側（余分に待つだけで、待ち漏れは起きない）。
///
/// いずれかのジョブが失敗していた場合は`Err`を返す（fail-closed、モジュールdoc参照）。
/// 個々のジョブの上限（[`WAIT_TIMEOUT`]）を超えた場合も`Err`で、そのときは待ちきれなかった
/// ことを理由に添える。
pub fn wait_until_done() -> Result<(), String> {
    let snapshot: Vec<Arc<JobState>> = jobs()
        .lock()
        .unwrap()
        .iter()
        .map(|(_, state)| Arc::clone(state))
        .collect();
    for state in &snapshot {
        wait_for_job(state)?;
    }
    Ok(())
}

/// 指定した `(workspace, mode)` の最新generationだけを待つ。ジョブが無ければ即座に成功する。
pub fn wait_for_workspace(workspace: &Path, mode: &str) -> Result<(), String> {
    wait_for_workspace_reporting(workspace, mode, |_| {})
}

/// [`wait_for_workspace`] と同じ待機を行い、待機中のスナップショットを表示層へ渡す。
/// タイムアウト値と成否判定はこのモジュールだけが持ち、CLI側には複製しない。
pub fn wait_for_workspace_reporting(
    workspace: &Path,
    mode: &str,
    mut report: impl FnMut(&WorkspaceGrantProgress),
) -> Result<(), String> {
    let prefix = format!("{}\u{0}", job_key_prefix(workspace, mode));
    let state = {
        let list = jobs().lock().unwrap();
        list.iter()
            .rev()
            .find(|(key, _)| key.starts_with(&prefix))
            .map(|(_, state)| Arc::clone(state))
    };
    match state {
        Some(state) => wait_for_job_reporting(&state, &mut report),
        None => Ok(()),
    }
}

fn wait_for_job(state: &JobState) -> Result<(), String> {
    wait_for_job_reporting(state, &mut |_| {})
}

fn wait_for_job_reporting(
    state: &JobState,
    report: &mut dyn FnMut(&WorkspaceGrantProgress),
) -> Result<(), String> {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    while !state.finished.load(Ordering::Acquire) {
        report(&snapshot_progress(state));
        if Instant::now() >= deadline {
            let done = state.done.load(Ordering::Relaxed);
            let total = state.total.load(Ordering::Relaxed);
            return Err(format!(
                "the workspace ACL repair pass is still running after {}s ({done}/{total} nodes); \
                 refusing to run a sandboxed command while part of the workspace may still be \
                 unreachable (D-54)",
                WAIT_TIMEOUT.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    report(&snapshot_progress(state));
    match state.error.lock().unwrap().clone() {
        Some(e) => Err(format!(
            "the workspace ACL repair pass failed ({e}); part of the workspace may be unreachable \
             from the sandbox (D-54)"
        )),
        None => Ok(()),
    }
}

/// 2つのレーンが同じ到達状態を作ることの回帰。**`grant_job`の子モジュールとして置く**
/// ——レーン関数を`pub(super)`へ広げずにテストするため（可視性はテストの都合で広げない）。
#[cfg(all(windows, test))]
#[path = "grant_job_lane_tests.rs"]
mod grant_job_lane_tests;

/// [D-88] 受入4「競合」——**別プロセスとの交差**。ここも`grant_job`の子モジュールに置く
/// （[`prepare_lock_name`]が要り、**可視性をテストの都合で広げない**ため。上と同じ理由）。
#[cfg(all(windows, test))]
#[path = "grant_job_contention_tests.rs"]
mod grant_job_contention_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// ジョブを開始していないプロセスでは、待ちは即座に通り、進捗も無い
    /// （2回目以降の起動＝台帳が完走済みを記録しているケース）。
    #[test]
    fn without_a_job_waiting_succeeds_immediately_and_there_is_no_progress() {
        assert_eq!(wait_until_done(), Ok(()));
        assert_eq!(progress(), None);
    }

    #[test]
    fn percent_is_clamped_and_safe_before_the_total_is_known() {
        let p = |done, total| WorkspaceGrantProgress {
            phase: JobPhase::Walking,
            done,
            total,
            protected_nodes: 0,
            protection_writes: 0,
            rescue_granted: 0,
            rescue_checked: 0,
            rescue_probe_errors: 0,
            broker_faults_served: None,
            finished: false,
            error: None,
        };
        assert_eq!(p(0, 0).percent(), 0);
        assert_eq!(p(10, 0).percent(), 0);
        assert_eq!(p(1, 4).percent(), 25);
        assert_eq!(p(9, 4).percent(), 100);
    }
}
