//! CoW差分層に残った**引退した身分**宛のACEを剥がす巡回。
//!
//! # なぜ「巡回」が別に要るのか——足りなかったのは判定ではなく経路である
//!
//! 撤収の宛先判定（[`super::revoke_subjects`]）は、引退した身分——D-37以前の共有
//! AppContainerプロファイル`harness.shell.sandbox`（接尾辞なし）——を**明示的に対象へ
//! 含めている**（`is_harness_moniker`が`LEGACY_SHARED_PROFILE`を足す）。つまり
//! **「過去の自分を見分ける」機構は最初から在った。**
//!
//! 足りなかったのは、その判定器を**差分層のディレクトリへ向ける経路**である。
//! `harness cow gc`は「何も残っていない」差分層だけを回収し（中身があるものは対象外）、
//! `harness fs revoke-workspace`は差分層に一切触れない。結果、実機で48件中10件に
//! `Modify`のACEが2026-08-02から1か月残り、手作業で剥がすことになった
//! （`docs/STATUS.md`残課題#35、`plans/e2e/RESULTS.md` 2026-09-03）。
//!
//! # ここが安全である理由（BUG-046を再現しない）
//!
//! 剥がす相手は[`super::revoke_harness_subjects`]が決めるので、**判定を書き写していない**。
//! したがって次の2つは構造的に守られる。
//!
//! - `ALL APPLICATION PACKAGES`等のwell-knownと、登録簿が他アプリを名指しするSIDには触らない
//!   （規則-1・規則0）
//! - **capability SID（`S-1-15-3-`）はそもそも視野に入らない**——`APPCONTAINER_SID_PREFIX`が
//!   パッケージSIDだけを拾う。[BUG-046](../../../../docs/bugs/BUG-046.md)は`C:\`のtraverse ACEを
//!   純減させてマシン全体のFS I/Oを壊した事故で、その宛先はcapability SIDだった
//!
//! # 走っているセッションの差分層は歩かない
//!
//! 生きている身分は判定側でも守られる（規則1）が、**そもそも対象にしない**。走行中の差分層は
//! 中身が動いており、DACLを書き換えながら歩く理由が無い。
//!
//! # この巡回が拾えないもの（**空にしない**）
//!
//! - **台帳による裏取り（規則3）は効かない。** 差分層のパスに紐づく`granted_sids`の台帳が
//!   無いので`ledger_sids`は空で呼ぶ。登録が消えた身分は規則4（マスクの完全一致）でしか
//!   名乗れず、そこは「証拠ではない」と判定側のdocが明記している
//! - **継承元が差分層の外にあるACEは剥がせない。** 継承ACEはそのノードからは取り消せない
//!   （`B-25`）。差分層は`%LOCALAPPDATA%\harness\data\cow\<id>`直下に作られるので、
//!   実際に載るのはこのディレクトリを継承元とする明示ACEである
//! - **判定不能（規則5）は報告するだけ**で剥がさない

use std::path::PathBuf;

use super::*;

/// 巡回の対象1件。
///
/// **列挙は呼び出し側が渡す。** これは好みではなく事故の記録から来ている——差分層を触る掃除を
/// `preflight`の中へ置いたとき、`preflight`を直接呼ぶ実機テスト群がworkspaceだけを一時
/// ディレクトリにしていたため、`cargo test --workspace`が**開発機の差分層を70件消した**
/// （`harness-cli`の`sweep_empty_cow_diff_areas`のdoc）。列挙を引数にしておけば、
/// テストは自分が作ったディレクトリだけを渡せる。
#[derive(Debug, Clone)]
pub struct DiffLayerSweepTarget {
    pub session_id: String,
    pub diff_layer_dir: PathBuf,
    /// 生存マーカー（名前付きmutex）が在る＝そのセッションのharnessがまだ動いている。
    pub is_live: bool,
}

/// 巡回1回の結果。**黙って剥がさない・黙って見送らない**（`B-11`）。
#[derive(Debug, Default)]
pub struct DiffLayerAceSweep {
    /// DACLを実際に読んだ差分層の数（走行中と実体の無いものを除く）。
    pub examined: usize,
    /// 走行中なので対象にしなかった数。
    pub skipped_live: usize,
    /// 剥がせた `(session_id, SID)`。
    pub revoked: Vec<(String, String)>,
    /// 載っていたが**剥がさなかった** `(session_id, SID, 理由)`。
    pub left_alone: Vec<(String, String, String)>,
    /// 撤収対象と判定したのに**まだ載っている** `(session_id, SID)`。
    pub still_present: Vec<(String, String)>,
    /// DACLを読めなかった・撤収が失敗した `(session_id, 理由)`。
    pub failures: Vec<(String, String)>,
}

impl DiffLayerAceSweep {
    /// 人へ出す1行。**何も起きなかったときは`None`**——毎起動「0件」と言わせない。
    ///
    /// 見送り（`left_alone`）は載せない。他アプリのSIDが差分層に載っていることは通常あり得ず、
    /// あったとしてもこの巡回が触らないのは設計どおりなので、起動のたびに報告する情報ではない。
    /// **剥がし損ね（`still_present`）と失敗は必ず載せる**——積もる理由はそこにしか出ない。
    pub fn summary(&self) -> Option<String> {
        if self.revoked.is_empty() && self.still_present.is_empty() && self.failures.is_empty() {
            return None;
        }
        let mut parts = Vec::new();
        if !self.revoked.is_empty() {
            parts.push(format!(
                "revoked {} stale AppContainer ACE(s) left on {} copy-on-write diff area(s) by \
                 identities that are no longer in use",
                self.revoked.len(),
                self.revoked
                    .iter()
                    .map(|(id, _)| id.as_str())
                    .collect::<std::collections::BTreeSet<_>>()
                    .len(),
            ));
        }
        if !self.still_present.is_empty() {
            parts.push(format!(
                "{} ACE(s) were meant to be revoked but are still on the diff area",
                self.still_present.len()
            ));
        }
        if !self.failures.is_empty() {
            parts.push(format!(
                "{} diff area(s) could not be examined: {}",
                self.failures.len(),
                self.failures
                    .iter()
                    .map(|(id, e)| format!("{id} ({e})"))
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
        Some(parts.join("; "))
    }
}

/// 渡された差分層だけを巡回する（実マシンの列挙はしない）。
///
/// # 安い判定を先に置く
///
/// 差分層1件につき、まず**DACLを1回読むだけ**で`AppContainer`のパッケージSIDが載っているかを
/// 見る（[`appcontainer_sid_aces`]）。ほとんどの差分層は1本も持たないので、そこで抜ける。
/// 分類は登録簿（この機で218件）の読取を伴うので、**載っていないものに対しては読まない**。
pub fn sweep_diff_layer_aces_in(targets: &[DiffLayerSweepTarget]) -> DiffLayerAceSweep {
    let mut out = DiffLayerAceSweep::default();
    for target in targets {
        if target.is_live {
            out.skipped_live += 1;
            continue;
        }
        if !target.diff_layer_dir.exists() {
            continue;
        }
        out.examined += 1;
        match appcontainer_sid_aces(&target.diff_layer_dir) {
            Ok(subjects) if subjects.is_empty() => continue,
            Ok(_) => {}
            Err(e) => {
                out.failures
                    .push((target.session_id.clone(), e.to_string()));
                continue;
            }
        }
        // 差分層のパスに紐づく`granted_sids`の台帳は無いので、規則3は使えない（モジュールdoc）。
        let report = match revoke_harness_subjects(&target.diff_layer_dir, &[], &|_, _| {}) {
            Ok(report) => report,
            Err(e) => {
                out.failures
                    .push((target.session_id.clone(), e.to_string()));
                continue;
            }
        };
        for subject in report.subjects {
            match subject.kind.left_alone_reason() {
                Some(reason) => {
                    out.left_alone
                        .push((target.session_id.clone(), subject.sid, reason));
                }
                None if subject.still_on_root => {
                    out.still_present
                        .push((target.session_id.clone(), subject.sid));
                }
                None => out.revoked.push((target.session_id.clone(), subject.sid)),
            }
        }
    }
    out
}

/// このマシンの全ボリュームの差分層を巡回する。
///
/// # 列挙は`cow list`／`cow gc`と同じ根から取る
///
/// [`list_cow_sessions`]は`collect_cow_session_facts`（`cow list`と`cow gc`が使う方）が
/// **その内側で呼んでいる**列挙そのものである。一覧に出るものと巡回するものが分かれると、
/// 「一覧に無いところに残る」が生まれるので、根は共有する。
///
/// # ただし`collect_cow_session_facts`は使わない
///
/// あちらは列挙に加えて、差分層ごとにメタの読取・操作台帳の再生・内容ファイルの数え上げを行う。
/// **削除してよいかを決めるにはそれが要るが、DACLを読むだけのこの巡回には1つも要らない。**
/// しかも起動経路では`sweep_empty_cow_diff_areas`が**既にそれを払っている**ので、ここで
/// もう一度呼ぶと同じ費用を2回払う。実測（この機の48件）では
/// **`collect_cow_session_facts`が11.2ミリ秒に対し、巡回本体は1.5ミリ秒**だった
/// （`cow_layer_sweep_tests::measure_the_diff_layer_sweep_cost`）——つまり素直に書くと
/// 増分の9割が二重払いになる。
///
/// [`list_cow_sessions`]: crate::tier2a::workspace_ledger::list_cow_sessions
pub fn sweep_diff_layer_aces() -> DiffLayerAceSweep {
    use crate::tier2a::workspace_ledger as wl;
    let (dirs, _unreachable) = wl::list_cow_sessions();
    let targets: Vec<DiffLayerSweepTarget> = dirs
        .into_iter()
        .map(|d| DiffLayerSweepTarget {
            is_live: wl::cow_session_is_live(&d.session_id),
            session_id: d.session_id,
            diff_layer_dir: d.diff_layer_dir,
        })
        .collect();
    sweep_diff_layer_aces_in(&targets)
}
