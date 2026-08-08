//! 観測した監査イベントを、人が判断できる形（許可ルールの候補）へ畳み込む。
//!
//! # record-allは「拒否」ではなく「触った全部」が入ってくる
//!
//! `harness policy suggest`が使う`harness_policy::normalize_fs_audit`は、`allowed: true`の
//! 行を**捨てる**（deny-onlyの収集器を前提にしているため）。記録モードの出力はほぼ全部が
//! `allowed: true`なので、そのまま通すと候補が0件になる。ここでは
//! [`harness_policy::FsFolder`]で許可・拒否の両方を畳み込む。
//!
//! # `.harness`配下は候補にしない
//!
//! 2つの理由があり、どちらも実害がある。
//!
//! 1. `.harness`はサンドボックスから開けてはいけない制御ディレクトリである（P-08）。
//!    ここへの許可を提案すると、承認台帳や設定をサンドボックス内から書き換える経路を
//!    提案していることになる。`harness_policy::gate::check_proposal`は
//!    `--require-sandbox`との矛盾しか見ないので、この種の提案を止めてくれない。
//! 2. **記録の産物が自分の入力へ戻る**——収集器が書く`fs-audit.jsonl`は
//!    `<workspace>/.harness/sandbox/policy-editor-<id>/`にあるため、workspaceを走査する
//!    コマンド（`cargo build`・`rg`等）を記録すると、前回の記録結果が今回の候補に
//!    混ざり込む。放置すると記録のたびに候補が増える自己参照ループになる。
//!
//! **除外した件数は必ず表示する。** 黙って捨てると「観測できなかった」と区別できない（B-09）。

use std::collections::BTreeMap;

use harness_policy::{
    event::{FsAuditEvent, FsAuditKind},
    normalize::Source,
    DeniedCandidate, FsFolder, Generalization, RuleProposal,
};

/// 記録1回分の集計結果。
#[derive(Debug, Default)]
pub struct Aggregate {
    folder: FsFolder,
    /// 観測した監査イベント（制御レコードを含む）の総数。
    pub events_seen: u64,
    /// うち許可されていたもの。
    pub allowed: u64,
    /// うち拒否されていたもの。**Tier1の拒否はTier2aの拒否と意味が違う**
    /// （[`Self::render`]の注記を参照）。
    pub denied: u64,
    /// `.harness`配下だったため候補にしなかった件数（モジュールdoc参照）。
    pub excluded_control_dir: u64,
    /// パス・access種別を持たないイベント（候補にできない）。
    pub without_path: u64,
    /// 収集器自身が書いた制御レコードの内容。**候補ではないが必ず見せる**（D-43）。
    pub collector_notes: Vec<String>,
    /// JSONLとして解釈できなかった行数。
    pub unparsable_lines: u64,
    /// PID → プロセスの素性（ツリー表示用）。
    processes: BTreeMap<u32, ProcessNode>,
}

/// 記録中に観測した1プロセス。
#[derive(Debug, Clone, Default)]
pub struct ProcessNode {
    pub parent_pid: Option<u32>,
    pub image: Option<String>,
    pub accesses: u64,
}

impl Aggregate {
    pub fn new() -> Self {
        Self::default()
    }

    /// 監査イベント1件を取り込む。
    pub fn add_event(&mut self, event: &FsAuditEvent) {
        self.events_seen = self.events_seen.saturating_add(1);

        if event.kind == FsAuditKind::Control {
            self.collector_notes.push(event.reason.clone());
            return;
        }

        if let Some(pid) = event.process_id {
            let node = self.processes.entry(pid).or_default();
            node.accesses = node.accesses.saturating_add(1);
            // 素性は**最初に分かった値を保つ**（後から`None`で上書きしない）。
            if node.parent_pid.is_none() {
                node.parent_pid = event.parent_process_id;
            }
            if node.image.is_none() {
                node.image = event.image_path.clone();
            }
        }

        if event.allowed {
            self.allowed = self.allowed.saturating_add(1);
        } else {
            self.denied = self.denied.saturating_add(1);
        }

        let (Some(path), Some(access)) = (event.path.as_deref(), event.access) else {
            self.without_path = self.without_path.saturating_add(1);
            return;
        };
        if is_harness_control_path(path) {
            self.excluded_control_dir = self.excluded_control_dir.saturating_add(1);
            return;
        }
        self.folder
            .add(Source::Etw, path, access, &event.reason, event.timestamp_unix_ms);
    }

    /// JSONLとして解釈できなかった行を数える（`AuditTail::poll_fs_events`の戻り値）。
    pub fn add_unparsable(&mut self, count: usize) {
        self.unparsable_lines = self.unparsable_lines.saturating_add(count as u64);
    }

    /// 畳み込み後の候補（異なる`(パス, access)`ごとに1件）。
    pub fn candidates(&self) -> &[DeniedCandidate] {
        self.folder.candidates()
    }

    /// 許可ルールの提案。**適用はしない**（D-42: 反映は常にユーザーの明示操作）。
    pub fn proposals(&self, mode: Generalization) -> Vec<RuleProposal> {
        harness_policy::generalize::generalize(self.folder.candidates(), mode)
    }

    /// 観測したプロセスをツリー順（親→子）で並べる。
    ///
    /// 親が観測範囲の外（記録対象ツリーの外側にいる`harness-policy-editor`自身など）の
    /// プロセスは根として扱う。**親が分からないものを勝手に別の親へ繋がない**——
    /// 嘘の親子関係を描くくらいなら、根が複数ある方が正直である。
    ///
    /// PID再利用で親子関係が閉路になっても**1件も落とさない**: 閉路の中のプロセスは
    /// どこからも辿れなくなるので、走査の最後に根として拾い直す（表示から黙って
    /// 消えるより、親が変に見える方がまだ調べようがある、B-09）。
    pub fn process_tree(&self) -> Vec<(usize, u32, ProcessNode)> {
        let mut children: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        let mut roots: Vec<u32> = Vec::new();
        for (pid, node) in &self.processes {
            match node.parent_pid {
                Some(parent) if self.processes.contains_key(&parent) && parent != *pid => {
                    children.entry(parent).or_default().push(*pid);
                }
                _ => roots.push(*pid),
            }
        }

        let mut out = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let walk = |start: u32,
                        out: &mut Vec<(usize, u32, ProcessNode)>,
                        visited: &mut std::collections::HashSet<u32>| {
            let mut stack = vec![(0usize, start)];
            while let Some((depth, pid)) = stack.pop() {
                // 循環（PID再利用で親子が閉路になる）を踏んでも止まらないようにする。
                if !visited.insert(pid) {
                    continue;
                }
                if let Some(node) = self.processes.get(&pid) {
                    out.push((depth, pid, node.clone()));
                }
                if let Some(kids) = children.get(&pid) {
                    for kid in kids.iter().rev() {
                        stack.push((depth + 1, *kid));
                    }
                }
            }
        };

        for root in roots {
            walk(root, &mut out, &mut visited);
        }
        // 閉路の中に居て根から辿れなかったプロセスを拾い直す（1件も落とさない）。
        for pid in self.processes.keys() {
            if !visited.contains(pid) {
                walk(*pid, &mut out, &mut visited);
            }
        }
        out
    }

    pub fn process_count(&self) -> usize {
        self.processes.len()
    }
}

/// 記録済みの監査ログ（JSONL）を読み直して集計する。
///
/// **保存済みの集計値は使わない。** 観測の正本は`fs-audit.jsonl`だけで、マニフェストは
/// 文脈しか持たない（同じ事実の正本を2つ持たない、B-13）。`--generalize`を変えて
/// 何度でも見直せるのはこの性質から来ている。
pub fn from_log(path: &std::path::Path) -> Aggregate {
    let mut tail = crate::audit_tail::AuditTail::new(path);
    let mut aggregate = Aggregate::new();
    let (events, skipped) = tail.poll_fs_events();
    for event in &events {
        aggregate.add_event(event);
    }
    aggregate.add_unparsable(skipped);
    aggregate
}

/// `.harness`（harnessの制御ディレクトリ）配下のパスか。
///
/// パス**要素**として`.harness`を持つかで判定する。前方一致で
/// `<このworkspace>/.harness`だけを見ると、記録対象が別のリポジトリを走査したときに
/// そちらの`.harness`を拾ってしまう——どのworkspaceのものであれ、harnessの制御
/// ディレクトリへの許可を提案してよい理由は無い。
pub fn is_harness_control_path(path: &str) -> bool {
    path.split(['/', '\\'])
        .any(|component| component.eq_ignore_ascii_case(".harness"))
}

/// 記録結果を人が読む形へ整形する。
///
/// `limit`は提案の表示件数の上限。**打ち切ったら必ずその事実と残件数を出す**（B-09）。
pub fn render(aggregate: &Aggregate, mode: Generalization, limit: usize) -> String {
    let mut out = String::new();
    let proposals = aggregate.proposals(mode);

    out.push_str(&format!(
        "観測: {}件（許可 {} / 拒否 {}）、異なるパス×access {}件、プロセス {}件\n",
        aggregate.events_seen,
        aggregate.allowed,
        aggregate.denied,
        aggregate.candidates().len(),
        aggregate.process_count(),
    ));

    if aggregate.events_seen == 0 {
        out.push_str(
            "\n監査イベントが1件も観測できませんでした。収集器が起動していないか、ETWセッションが\n\
             張れていない可能性があります（上の警告と、記録セッションの制御レコードを確認してください）。\n",
        );
    }

    if aggregate.excluded_control_dir > 0 {
        out.push_str(&format!(
            "除外: .harness（harnessの制御ディレクトリ）配下 {}件。ここへの許可は提案しません（P-08）\n",
            aggregate.excluded_control_dir
        ));
    }
    if aggregate.without_path > 0 {
        out.push_str(&format!(
            "除外: パスまたはaccess種別を持たないイベント {}件\n",
            aggregate.without_path
        ));
    }
    if aggregate.unparsable_lines > 0 {
        out.push_str(&format!(
            "警告: 監査ログのうち解釈できなかった行 {}件\n",
            aggregate.unparsable_lines
        ));
    }
    for note in &aggregate.collector_notes {
        out.push_str(&format!("収集器からの報告: {note}\n"));
    }

    if aggregate.denied > 0 {
        out.push_str(
            "\n注意: **Tier1での拒否は、Tier2aで必要になる許可とは限りません。** Tier1は低IL\n\
             ラベルをcwd直下にしか付けない（継承させるとBUG-018が再発する）ため、記録対象が\n\
             cwd配下に作ったサブディレクトリの中への書込は、Tier1の実装都合で拒否されます。\n",
        );
    }

    out.push_str(&format!(
        "\n許可ルールの候補（--generalize {}）:\n",
        generalization_label(mode)
    ));
    if proposals.is_empty() {
        out.push_str("  （候補なし）\n");
    }
    for proposal in proposals.iter().take(limit) {
        out.push_str(&format!(
            "  {:<8} {} = {}  （観測 {}回）\n",
            proposal.id,
            proposal.key.dotted(),
            proposal.value,
            proposal.observed_count(),
        ));
        for warning in &proposal.warnings {
            out.push_str(&format!("           ! {warning}\n"));
        }
    }
    if proposals.len() > limit {
        out.push_str(&format!(
            "  ... 他 {}件（全件は `harness-policy-editor show --limit 0` で表示）\n",
            proposals.len() - limit
        ));
    }

    out
}

fn generalization_label(mode: Generalization) -> &'static str {
    match mode {
        Generalization::None => "none",
        Generalization::Directory => "dir",
        Generalization::Auto => "auto",
    }
}

/// 観測したプロセスツリーを整形する（記録対象が何を起動したかの俯瞰）。
pub fn render_process_tree(aggregate: &Aggregate) -> String {
    let mut out = String::from("観測したプロセス:\n");
    let tree = aggregate.process_tree();
    if tree.is_empty() {
        out.push_str("  （なし）\n");
    }
    for (depth, pid, node) in tree {
        out.push_str(&format!(
            "  {}{} pid={} ({}件)\n",
            "  ".repeat(depth),
            node.image.as_deref().unwrap_or("(不明)"),
            pid,
            node.accesses,
        ));
    }
    out
}

#[cfg(test)]
#[path = "aggregate_tests.rs"]
mod aggregate_tests;
