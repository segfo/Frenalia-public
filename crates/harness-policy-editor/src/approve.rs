//! 中間ステップ——記録した候補のうちどれを許すかをユーザーが**明示的に**選び、
//! [`crate::policy_file`]（`policy.json`）へ書く（D-42: 反映は常にユーザーの明示操作）。
//!
//! # ここではACEを付けない
//!
//! 付与経路は`win_appcontainer::preflight`ただ1つに保つ。承認が独自にACEを付けると
//! **付与経路が2つになり**、片方だけが台帳へ記録する／片方だけが撤収できる、という形の
//! 事故になる（BUG-017の孤立ACEと同型）。承認は「次のパス2でこの穴を開ける」という宣言で、
//! 実際の付与と台帳への記録は[`crate::record_net`]がpreflight経由で行う。
//!
//! # 部分適用しない
//!
//! 未知のidが1件でもある、`--require-sandbox`と矛盾する提案が1件でもある、広すぎる値が
//! 1件でもある——いずれの場合も**何も書かずに失敗する**。設定は「後から効いてくる」対象で、
//! 「一部だけ通った」状態はユーザーが受け入れたつもりの構成と実際の構成をずらす
//! （`harness policy apply`と同じ判断）。
//!
//! # 判定は既存の純粋関数をそのまま使う
//!
//! - [`harness_policy::gate::check_proposal`]（D-42、`--require-sandbox`との矛盾）
//! - [`harness_policy::breadth::check`]（D-47、`C:/`のような広すぎる値）
//!
//! 承認の経路を別に作るからといって判定を書き直さない——書き直すと片方だけが緩む。
//!
//! # 「決める」と「書く」を分ける
//!
//! [`plan`]は何も書かずに結果（受理した提案・書き込む予定の内容・差分・パスの分類）を返し、
//! [`commit`]がそれを書く。CLIは間で差分を見せて確認を取り、TUIは同じ2段を別のUIで使う。

use std::path::Path;

use harness_core::RequireSandbox;
use harness_policy::{breadth, gate, generalize::SettingsKey, GateVerdict, RuleProposal};

use crate::policy_file::{self, ApprovalContext, MergeReport, PolicyDomain, PolicyFile};

/// 承認の要求。
pub struct ApproveRequest<'a> {
    pub workspace_root: &'a Path,
    /// `show`が出したのと**同じ**提案一覧（同じ`--generalize`で作ったもの）。
    pub proposals: &'a [RuleProposal],
    /// `--accept`で指定されたid（カンマ区切りは呼び出し側で展開済み）。
    pub accept_ids: &'a [String],
    pub require_sandbox: RequireSandbox,
    pub domain: &'a str,
    pub command: Option<&'a str>,
    pub cwd: Option<&'a Path>,
    pub record_session: Option<&'a str>,
    pub now_unix_ms: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ApproveError {
    #[error(
        "承認するidを1つ以上指定してください（--accept <id>[,<id>...]）。idは `show` の出力に\
         あります。**全件受理のショートハンドは意図的に用意していません**（D-42）"
    )]
    NoIds,
    #[error(
        "知らない提案id: {0}。idは `show` の出力から取り、`--generalize` の値によって変わります\
         ——`show` と `approve` に同じ値を渡してください"
    )]
    UnknownIds(String),
    #[error("承認できません（何も書いていません）:\n{0}")]
    Refused(String),
    #[error(transparent)]
    PolicyFile(#[from] policy_file::PolicyFileError),
}

/// 受理した提案のうち、その値がworkspaceのどちら側にあるか。
///
/// **承認の実質的な判断材料**である。Tier2aはworkspaceツリーへは既にACEを付けているので、
/// workspace内のパスに新しく穴を開ける必要は無い。実際にマシンのACLを変えるのは
/// workspace**外**の分だけである。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathClass {
    /// workspace配下。Tier2aのworkspace grantが既に覆う（ACEの追加は不要）。
    InsideWorkspace,
    /// workspace外。パス2でこのルートへ実際にACEを付ける（マシンに残る変更）。
    OutsideWorkspace,
    /// パスではない（`net.allow_domains`）。
    NotFilesystem,
}

/// 書く前に決まったこと一式。
#[derive(Debug)]
pub struct ApprovePlan<'a> {
    pub accepted: Vec<&'a RuleProposal>,
    /// 書き込む予定の内容（[`commit`]がそのまま保存する）。
    pub file: PolicyFile,
    pub report: MergeReport,
    /// 受理した提案ごとの分類（`accepted`と同じ並び）。
    pub classes: Vec<PathClass>,
    /// 拒否ではないが読んでおくべきこと（`gate`の警告）。
    pub warnings: Vec<String>,
}

impl ApprovePlan<'_> {
    /// マシンのACLを実際に変えることになる提案の件数（workspace外）。
    pub fn outside_workspace_count(&self) -> usize {
        self.classes
            .iter()
            .filter(|c| **c == PathClass::OutsideWorkspace)
            .count()
    }
}

/// 受理するidを解決し、検査を通し、`policy.json`へのマージ結果まで作る。**何も書かない。**
pub fn plan<'a>(req: &ApproveRequest<'a>) -> Result<ApprovePlan<'a>, ApproveError> {
    if req.accept_ids.is_empty() {
        return Err(ApproveError::NoIds);
    }

    let mut accepted: Vec<&RuleProposal> = Vec::new();
    let mut unknown: Vec<&str> = Vec::new();
    for id in req.accept_ids {
        match req.proposals.iter().find(|p| &p.id == id) {
            Some(proposal) => {
                if !accepted.iter().any(|p| p.id == proposal.id) {
                    accepted.push(proposal);
                }
            }
            None => unknown.push(id.as_str()),
        }
    }
    if !unknown.is_empty() {
        return Err(ApproveError::UnknownIds(unknown.join(", ")));
    }

    // 2軸の拒否を1箇所へ集める。どちらも**部分適用しない**（1件でも該当なら何も書かない）。
    // 軸を分けたまま両方を通すのは、拒否された理由がユーザーから見て別物だからである
    // （前者は自分の宣言との矛盾、後者は値そのものの広さ）。
    let mut refused = Vec::new();
    let mut warnings = Vec::new();
    for proposal in &accepted {
        match gate::check_proposal(proposal, req.require_sandbox) {
            GateVerdict::Rejected(message) => refused.push(format!("{}: {message}", proposal.id)),
            GateVerdict::AllowedWithWarning(message) => {
                warnings.push(format!("{}: {message}", proposal.id))
            }
            GateVerdict::Allowed => {}
        }
        if let Some(message) = breadth::check(proposal).message() {
            refused.push(format!("{}: {message}", proposal.id));
        }
    }
    if !refused.is_empty() {
        return Err(ApproveError::Refused(
            refused
                .iter()
                .map(|line| format!("  {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
        ));
    }

    let classes = accepted
        .iter()
        .map(|p| classify(p, req.workspace_root))
        .collect();

    let mut file = policy_file::load(req.workspace_root)?;
    let report = file.merge_approved(
        &accepted,
        &ApprovalContext {
            domain: req.domain,
            command: req.command,
            cwd: req.cwd,
            record_session: req.record_session,
            now_unix_ms: req.now_unix_ms,
        },
    );

    // **承認の結果が次のパス2の待ち時間になる、ということをこの瞬間に見せる。**
    // `preflight`はworkspace外のルートを1件ずつ処理するので、準備時間はこの件数にほぼ比例する。
    // 件数はマージ**後**のドメイン全体で数える（この承認で足した分だけでなく、次のパス2が
    // 実際に処理する数そのもの）。一般化して畳めば減らせる、という行動もここで伝える
    // ——数だけ出して「どうすればいいか」を書かないのは、警告として半分しか役に立たない（B-32）。
    let grant_roots = file
        .domain(req.domain)
        .map(|domain| grant_roots(domain, req.workspace_root).len())
        .unwrap_or(0);
    if grant_roots >= MANY_GRANT_ROOTS {
        warnings.push(format!(
            "このドメインのworkspace外のルートは{grant_roots}件になります。パス2はこれを1件ずつ\
             処理するので、準備に時間がかかります（承認前に一般化の度合いを上げて畳むと減ります）"
        ));
    }

    Ok(ApprovePlan {
        accepted,
        file,
        report,
        classes,
        warnings,
    })
}

/// 「workspace外のルートが多い」と警告し始める件数。
///
/// 根拠は`preflight`の実測——1件あたりのACL読取・付与・台帳更新は数ms程度だが、件数に比例して
/// 積み上がる。数十件までは体感できないので、**数百件のオーダーに入るところ**で線を引く。
/// 正確な閾値そのものに意味は無く、「気付かないうちに桁が変わっていた」ことを知らせるのが目的。
const MANY_GRANT_ROOTS: usize = 100;

/// [`plan`]の結果を実際に書き込む。
pub fn commit(workspace_root: &Path, plan: &ApprovePlan<'_>) -> Result<(), ApproveError> {
    policy_file::save(workspace_root, &plan.file)?;
    Ok(())
}

/// `value`が`root`自身か、その配下か。**配下判定の規則はこの1関数だけが持つ**（B-05・B-19）。
///
/// 値はワイルドカードを含み得る（`C:/Users/x/.cargo/**`）ので、**最初の`*`より前**の
/// 確定部分だけで比較する。綴りの正規化は`harness_policy::normalize::normalize_path`を通す
/// ——提案の値はその関数で揃えられているので、比較する側が別の規則を持つと一致しない（B-19）。
/// 大小は無視する（Windowsのパスは大小を区別しない）。
///
/// [`classify`]（承認時の「ACEを付けに行くのはworkspace外だけ」の判定）と、
/// [`crate::exclusion::ExclusionRules`]（候補にしない範囲の判定）が**同じ関数を通る**。
/// 別々に書くと、候補には出さないのに承認側は別の線を引く、という食い違いを作る。
pub fn is_under(value: &str, root: &Path) -> bool {
    let value = harness_policy::normalize::normalize_path(value);
    let literal = value.split('*').next().unwrap_or("");
    let root = harness_policy::normalize::normalize_path(&root.to_string_lossy());
    let root = root.trim_end_matches('/');
    if root.is_empty() {
        return false;
    }
    let literal_lower = literal.trim_end_matches('/').to_ascii_lowercase();
    let root_lower = root.to_ascii_lowercase();
    // 「root自身」または「root配下」。`C:/ws2`が`C:/ws`の配下と誤判定されないよう、
    // 直後が区切りであることまで見る。
    literal_lower == root_lower || literal_lower.starts_with(&format!("{root_lower}/"))
}

/// 提案の値がworkspaceのどちら側にあるかを判定する。判定の実体は[`is_under`]。
fn classify(proposal: &RuleProposal, workspace_root: &Path) -> PathClass {
    if proposal.key == SettingsKey::NetAllowDomains {
        return PathClass::NotFilesystem;
    }
    if is_under(&proposal.value, workspace_root) {
        PathClass::InsideWorkspace
    } else {
        PathClass::OutsideWorkspace
    }
}

/// 承認済みの値を、**実際にACEを付けるルート**（ワイルドカードを含まないディレクトリ）へ
/// 落とす。workspace配下なら`None`——Tier2aのworkspace grantが既に覆っているので、
/// 同じツリーへ別主体のACEを重ねる意味が無い。
///
/// 判定は[`classify`]と同じ規則を通す（片方だけ直る事故を避ける）。`C:/Users/x/.cargo/**`
/// なら`C:/Users/x/.cargo`が返る。末尾の要素にワイルドカードが混じっている場合
/// （`C:/Users/x/.rustup/toolchains/*/bin`のような`generalize`の出力）は、
/// **`*`を含む要素の1つ手前まで**を採る。
pub fn grant_root(value: &str, workspace_root: &Path) -> Option<std::path::PathBuf> {
    let proposal = RuleProposal {
        id: String::new(),
        key: SettingsKey::FsRead,
        value: value.to_string(),
        evidence: Vec::new(),
        warnings: Vec::new(),
    };
    if classify(&proposal, workspace_root) != PathClass::OutsideWorkspace {
        return None;
    }
    let normalized = harness_policy::normalize::normalize_path(value);
    // [D-63] 切る位置は`normalize::literal_prefix`が1つだけ持つ。**幅の判定（`breadth`）と
    // 同じ関数を通す**——別々に切ると、承認してよいと判定した値と、実際にACEを付ける値が
    // 食い違う（B-05）。
    let literal = harness_policy::normalize::literal_prefix(&normalized);
    let kept: Vec<&str> = literal.split('/').collect();
    // ドライブ文字だけ（`C:` / `C:/`）しか残らないなら、それは事実上ドライブ全体への付与に
    // なる。`breadth::check`が承認時に止めているはずだが、**変換側でも受け取らない**
    // （空要素も数えないこと——`C:/`は`["C:", ""]`に割れるので、要素数だけ見ると通ってしまう）。
    if kept.iter().filter(|s| !s.is_empty()).count() < 2 {
        return None;
    }
    // UNC（`//host/share/...`）の先頭2つの空要素は落とさない（`join`で復元される）。
    let root = kept.join("/");
    let root = root.trim_end_matches('/');
    if root.is_empty() {
        return None;
    }
    Some(std::path::PathBuf::from(root))
}

/// ドメインのFSルールを、`preflight`が**1件ずつ処理するworkspace外のルート**へ畳む。
///
/// **この関数が「件数」の唯一の定義である。** パス2の準備時間はこの件数にほぼ比例するので、
/// 承認時の警告（[`ApprovePlan::grant_root_count`]）と実際に処理される集合
/// （`record_net::passthrough_for_domain`）が別々に数えていると、警告した数と待たされる数が
/// 食い違う（B-05: 型で守られない同じ規則を2箇所に持たない）。
///
/// workspace配下は含めない——Tier2aのworkspace grantが既に覆っているので、同じツリーへ
/// 別主体のACEを重ねる意味が無い。
///
/// # 同じルートに複数のaccessが宣言されていたら「和」を取る
///
/// 1つのオブジェクトのDACLへ同じSID宛のACEを2本張ることはできないので、`fs.read_write`と
/// `fs.read_exec`が同じルートに立ったら**両方を含む1本**（`ReadWriteExec`）にする。
/// かつては「`ReadWrite`なら昇格する」という規則だけがあり、`ReadExec`が来たときの規則が
/// 無かった——先に入った方が残り、**もう片方の権限が黙って消えていた**。`ReadWrite`に
/// `FILE_GENERIC_EXECUTE`は入っていないので、消えた側は実行時の`Access is denied`として
/// 現れるのに、`policy.json`には許可が書いてあるように見える。
/// 合成の規則そのものは`harness_sandbox::FsAccess::wider`が唯一の定義を持つ。
///
/// # [D-63] 範囲も一緒に返す
///
/// 同じルートに素の宣言と`<path>/**`が同居したら**再帰を採る**。accessを和で畳むのと同じ理由で、
/// 1つのオブジェクトのDACLへ同じSID宛のACEを2本置くことはできないためである。
/// 逆向き（再帰宣言があるのにオブジェクト単体へ寄せる）にすると、ユーザーが`R`で明示的に
/// 広げた宣言が**別の行のせいで黙って効かなくなる**。
pub fn grant_roots(
    domain: &PolicyDomain,
    workspace_root: &Path,
) -> Vec<(
    std::path::PathBuf,
    harness_sandbox::FsAccess,
    harness_policy::GrantScope,
)> {
    let mut out: Vec<(
        std::path::PathBuf,
        harness_sandbox::FsAccess,
        harness_policy::GrantScope,
    )> = Vec::new();
    for (value, access) in domain.fs.entries() {
        let Some(root) = grant_root(value, workspace_root) else {
            continue;
        };
        let access = harness_sandbox::FsAccess::from_settings(access);
        let scope = harness_policy::normalize::declared_scope(value);
        match out.iter_mut().find(|(path, _, _)| path == &root) {
            Some(existing) => {
                existing.1 = existing.1.wider(access);
                if scope.is_recursive() {
                    existing.2 = scope;
                }
            }
            None => out.push((root, access, scope)),
        }
    }
    out
}

#[cfg(test)]
#[path = "approve_tests.rs"]
mod approve_tests;

#[cfg(test)]
#[path = "approve_grant_roots_tests.rs"]
mod approve_grant_roots_tests;
