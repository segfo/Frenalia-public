//! workspaceの伝播＋救済walkを背景で回すジョブ（D-54、[BUG-082](../../../../docs/bugs/BUG-082.md) Part Bで拡張）。
//!
//! `preflight`の同期区間はrootへ継承ACEを1件、**伝播なし**（`DaclWrite::SingleObject`、
//! `grant_workspace_root_rw_fast`/`_ro_fast`）で付けるだけにしてある——tier判定
//! （`smoke_test_spawn`）にはrootのDACL自体で足り、既存子孫への伝播は不要だからである。
//! このジョブはその**残り**を2フェーズで背景に引き受ける。
//!
//! - **フェーズ0（伝播）**: [`super::propagate_workspace_root_grant`]がrootへの継承ACE伝播を
//!   冪等チェック無しで無条件に行う。OSが既存子孫へ物理コピーする、単一のブロッキングOS
//!   呼び出し（実測20秒超）。直後に`.harness/`を**第2の防御として**再保護する
//!   （[BUG-083](../../../../docs/bugs/BUG-083.md)）。
//!
//!   このフェーズ0.5は元々、`SE_DACL_PROTECTED`が立っておらず伝播が`.harness/`の子孫まで
//!   届いてしまうことへの**回避策**として入れたものである。BUG-083の修正で保護が実際に効くように
//!   なり、フェーズ0の伝播はOS側で`.harness/`の手前で止まるようになったが、この再保護は残す
//!   ——保護が止められるのは**継承経由の伝播だけ**で、(a) 保護をかける前から`.harness/`配下に
//!   物理コピーとして乗っていたACE、(b) D-37時代にpackage SID宛で付けられた残骸、は継承とは
//!   無関係に残るためである。`remove_sid_aces_and_protect`は「剥がすACEが無く、かつ既に保護済み」
//!   なら書込を省くので、正常系ではノードごとのDACL読取だけで終わる。
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobPhase {
    Propagating,
    Walking,
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
    /// フェーズ1の[`super::DescendantFixReport`]（残課題#32の事後確認用）。
    rescue_granted: AtomicUsize,
    rescue_checked: AtomicUsize,
    rescue_probe_errors: AtomicUsize,
    finished: AtomicBool,
    error: Mutex<Option<String>>,
}

const PHASE_WALKING: u8 = 1;

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
/// [BUG-082 Part B] `preflight`の同期区間はroot付与を`grant_workspace_root_rw_fast`/`_ro_fast`
/// （`DaclWrite::SingleObject`、伝播なし）にしたため、既存子孫への伝播そのものをこのジョブの
/// **最初のフェーズ**として引き受ける（[`super::propagate_workspace_root_grant`]、冪等チェックを
/// バイパスして無条件に呼ぶ——理由は同関数のdoc参照）。
///
/// **`protect_sids`が必要な理由（[BUG-083](../../../../docs/bugs/BUG-083.md)）**:
/// `.harness/`の保護（`protect_harness_control_dir_from_appcontainer`）は`preflight`の同期区間で
/// 既に一度行われており、BUG-083の修正以降その保護は実際に効く（フェーズ0の伝播は`.harness/`の
/// 手前でOSに止められる）。それでも伝播の直後にもう一度保護し直すのは、**保護が止められるのは
/// 継承経由の伝播だけ**だからである——保護をかける前から`.harness/`配下に物理コピーとして
/// 乗っていたACEや、D-37時代にpackage SID宛で付けられた残骸は、継承とは無関係にそこに在る。
/// D-05/D-09の不変条件（サンドボックスから制御面が書けない）を背景フェーズでも維持するための
/// 第2の防御である。`protect_sids`は`preflight`が渡すのと同じ集合
/// （workspace capability＋セッションのSID）。
#[must_use = "false means the job was not started (another one already claimed this process)"]
pub fn start(
    root: &Path,
    sid: OwnedSid,
    mask: u32,
    protect_sids: Vec<OwnedSid>,
    skip: Vec<PathBuf>,
    workspace: &Path,
    mode: &str,
    capability_generation: &str,
) -> bool {
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
    std::thread::spawn(move || {
        // フェーズ0: rootへの継承ACE伝播（冪等チェック無し、必ず呼ぶ）。
        if let Err(e) = super::propagate_workspace_root_grant(&root, sid.as_psid(), mask) {
            let error = e.to_string();
            crate::tier2a::workspace_capability::mark_tree_preparation_failed(
                &workspace, &mode, &error,
            );
            *state.error.lock().unwrap() = Some(error);
            state.finished.store(true, Ordering::Release);
            return;
        }

        // フェーズ0.5（BUG-083対策）: 伝播が`.harness/`の子孫へも物理コピーを届けた可能性が
        // あるため、直後にもう一度剥がし直す。`.harness/`が存在しなければ
        // `protect_harness_control_dir_from_appcontainer`は無害な早期returnになる。
        let protect_psids: Vec<windows::Win32::Security::PSID> =
            protect_sids.iter().map(|s| s.as_psid()).collect();
        match super::protect_harness_control_dir_from_appcontainer(&root, &protect_psids) {
            // [BUG-084] 件数を残す。この背景フェーズはユーザーに何も見せずに終わるので、
            // 記録しないと「D-05/D-09の層3が1件も掛からなかった」ことを事後に知る手段が無い。
            Ok(nodes) => state.protected_nodes.store(nodes, Ordering::Relaxed),
            Err(e) => {
                let error = e.to_string();
                crate::tier2a::workspace_capability::mark_tree_preparation_failed(
                    &workspace, &mode, &error,
                );
                *state.error.lock().unwrap() = Some(error);
                state.finished.store(true, Ordering::Release);
                return;
            }
        }

        // フェーズ1: 保護DACL配下の救済walk（既存）。
        state.phase.store(PHASE_WALKING, Ordering::Relaxed);
        let progress_state = Arc::clone(&state);
        let result = super::fix_descendants_missing_ace(
            &root,
            sid.as_psid(),
            mask,
            &skip,
            &move |done, total| {
                progress_state.done.store(done, Ordering::Relaxed);
                progress_state.total.store(total, Ordering::Relaxed);
            },
        );
        match result {
            Ok(report) => {
                // [残課題#32] **報告を捨てない。** ここが`Ok(_)`で握り潰されていたために、
                // 「フェーズ0が17秒かけて何も配っておらず、実際に配っているのはこのwalkだけ」
                // という状態が実運用で一度も可視化されなかった（`B-10`）。
                state
                    .rescue_granted
                    .store(report.granted, Ordering::Relaxed);
                state
                    .rescue_checked
                    .store(report.checked, Ordering::Relaxed);
                state
                    .rescue_probe_errors
                    .store(report.probe_errors, Ordering::Relaxed);
                // 文面は`grant_ace_inheritable_rw`が出しているものに揃える（同じ事実を
                // 2つの綴りで出さない）。既定では何も出ない＝`HARNESS_PREFLIGHT_TIMING=1`のときだけ。
                let mut timing = super::PhaseTiming::start();
                timing.mark(&format!(
                    "  background: rescue walk ({} checked, {} explicit grants, {} probe errors)",
                    report.checked, report.granted, report.probe_errors
                ));
                if !report.samples.is_empty() {
                    timing.mark_lines("  background: not reached by inheritance", &report.samples);
                }
                crate::tier2a::workspace_capability::mark_tree_verified(&workspace, &mode);
            }
            Err(e) => {
                let error = e.to_string();
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
    true
}

fn snapshot_progress(state: &JobState) -> WorkspaceGrantProgress {
    let finished = state.finished.load(Ordering::Acquire);
    let phase = if state.phase.load(Ordering::Relaxed) == PHASE_WALKING {
        JobPhase::Walking
    } else {
        JobPhase::Propagating
    };
    WorkspaceGrantProgress {
        phase,
        done: state.done.load(Ordering::Relaxed),
        total: state.total.load(Ordering::Relaxed),
        protected_nodes: state.protected_nodes.load(Ordering::Relaxed),
        rescue_granted: state.rescue_granted.load(Ordering::Relaxed),
        rescue_checked: state.rescue_checked.load(Ordering::Relaxed),
        rescue_probe_errors: state.rescue_probe_errors.load(Ordering::Relaxed),
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
            rescue_granted: 0,
            rescue_checked: 0,
            rescue_probe_errors: 0,
            finished: false,
            error: None,
        };
        assert_eq!(p(0, 0).percent(), 0);
        assert_eq!(p(10, 0).percent(), 0);
        assert_eq!(p(1, 4).percent(), 25);
        assert_eq!(p(9, 4).percent(), 100);
    }
}
