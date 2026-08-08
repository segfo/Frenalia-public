//! パス2で観測したネットワークイベントを、人が判断できる形（許可ドメインの候補）へ畳み込む。
//!
//! # record-allで走らせるので「拒否」ではなく「触った全部」が入ってくる
//!
//! パス2は[`harness_core::DomainPolicy::record_all`]で走らせるため、`net-audit.jsonl`の行は
//! ほぼ全部が`allowed: true, reason: "record_all"`になる。`harness_policy::normalize_net_audit`は
//! 拒否行以外を捨てる（`normalize.rs`）ので、そのまま通すと候補が**0件**になる。
//! [`harness_policy::NetIntake::All`]で取り込む——FS側の`on_operation_end_any`と同じ形の分岐である。
//!
//! # 正本はJSONLであってここではない
//!
//! [`NetAggregate`]は記録中のライブ表示のために行を溜めるが、候補の計算は毎回
//! `harness_policy`の正規化と一般化を通し直す（B-13: 同じ事実の正本を2つ持たない）。
//! `show --net`が`--generalize`を変えて何度でも見直せるのはこの性質から来ている。

use std::collections::BTreeMap;

use harness_policy::{DeniedCandidate, Generalization, NetIntake, RuleProposal};

/// パス2の記録1回分の集計。
#[derive(Debug, Default)]
pub struct NetAggregate {
    /// 観測した行（そのまま。候補の計算は`harness_policy`へ通し直す）。
    lines: Vec<String>,
    pub events_seen: u64,
    /// うち許可されたもの（record-allなのでほぼ全部）。
    pub allowed: u64,
    /// うち拒否されたもの。**record-allでの拒否はIPリテラル宛が主**（`evaluate_host`は
    /// record-allでもIPリテラルを拒否する）。
    pub denied: u64,
    /// ホスト名を持たなかったイベント（IP直打ち・WFPのdrop）。**盲点の指標**。
    pub without_host: u64,
    /// JSONとして解釈できなかった行数。
    pub unparsable_lines: u64,
    /// ホスト → 観測回数（ライブ表示用の速報。候補の正本ではない）。
    hosts: BTreeMap<String, u64>,
}

impl NetAggregate {
    pub fn new() -> Self {
        Self::default()
    }

    /// 監査イベント1件を取り込む。
    pub fn add_event(&mut self, event: &serde_json::Value) {
        self.events_seen = self.events_seen.saturating_add(1);
        if let Ok(line) = serde_json::to_string(event) {
            self.lines.push(line);
        }

        match event.get("allowed").and_then(|v| v.as_bool()) {
            Some(false) => self.denied = self.denied.saturating_add(1),
            _ => self.allowed = self.allowed.saturating_add(1),
        }

        let host = event
            .get("host")
            .and_then(|v| v.as_str())
            .or_else(|| event.get("remote_host").and_then(|v| v.as_str()))
            .map(str::trim)
            .filter(|h| !h.is_empty());
        match host {
            Some(host) => {
                let key = host.trim_end_matches('.').to_ascii_lowercase();
                *self.hosts.entry(key).or_insert(0) += 1;
            }
            None => self.without_host = self.without_host.saturating_add(1),
        }
    }

    pub fn add_unparsable(&mut self, count: usize) {
        self.unparsable_lines = self.unparsable_lines.saturating_add(count as u64);
    }

    /// 観測したホスト（多い順、同数なら名前順）。
    pub fn hosts(&self) -> Vec<(&str, u64)> {
        let mut out: Vec<(&str, u64)> = self.hosts.iter().map(|(h, c)| (h.as_str(), *c)).collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        out
    }

    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }

    /// 畳み込み後の候補（異なるドメインごとに1件）。
    pub fn candidates(&self) -> Vec<DeniedCandidate> {
        harness_policy::normalize::normalize_net_audit_with_mode(&self.lines.join("\n"), NetIntake::All)
            .candidates
    }

    /// 許可ルールの提案。**適用はしない**（D-42: 反映は常にユーザーの明示操作）。
    pub fn proposals(&self, mode: Generalization) -> Vec<RuleProposal> {
        harness_policy::generalize::generalize(&self.candidates(), mode)
    }

    /// 正規化が付けた注記（ホスト名を持たなかった件数の説明など）。
    pub fn notes(&self) -> Vec<String> {
        harness_policy::normalize::normalize_net_audit_with_mode(&self.lines.join("\n"), NetIntake::All)
            .notes
    }
}

/// 記録済みの`net-audit.jsonl`を読み直して集計する。
///
/// **保存済みの集計値は使わない**（B-13）。`--generalize`を変えて何度でも見直せる。
pub fn from_log(path: &std::path::Path) -> NetAggregate {
    let mut tail = crate::audit_tail::AuditTail::new(path);
    let mut aggregate = NetAggregate::new();
    let (events, skipped) = tail.poll_json_values();
    for event in &events {
        aggregate.add_event(event);
    }
    aggregate.add_unparsable(skipped);
    aggregate
}

/// 記録結果を人が読む形へ整形する。
pub fn render(aggregate: &NetAggregate, mode: Generalization, limit: usize) -> String {
    let mut out = String::new();
    let proposals = aggregate.proposals(mode);

    out.push_str(&format!(
        "観測: {}件（許可 {} / 拒否 {}）、異なるホスト {}件\n",
        aggregate.events_seen,
        aggregate.allowed,
        aggregate.denied,
        aggregate.host_count(),
    ));

    if aggregate.events_seen == 0 {
        out.push_str(
            "\nネットワークイベントが1件も観測できませんでした。対象コマンドが本当に通信して\n\
             いないか、環境変数を読まず生ソケットで直接接続している可能性があります\n\
             （後者はWFPのdefault-denyで**繋がらない**ため、コマンド側がエラーになっているはずです）。\n",
        );
    }
    if aggregate.without_host > 0 {
        out.push_str(&format!(
            "ホスト名を持たないイベント {}件（IP直打ち・WFPのdrop）。net.allow_domainsでは\n\
             表現できないため候補にしません\n",
            aggregate.without_host
        ));
    }
    if aggregate.unparsable_lines > 0 {
        out.push_str(&format!(
            "警告: 監査ログのうち解釈できなかった行 {}件\n",
            aggregate.unparsable_lines
        ));
    }
    for note in aggregate.notes() {
        out.push_str(&format!("注記: {note}\n"));
    }

    out.push_str(
        "\n注意: **ドメイン名を復元できない通信があります。** OSのリゾルバを経由しない自前DNS\n\
         実装（Go製CLIの一部等）や、プロキシ環境変数を読まないツールはこの記録に現れません。\n\
         パス2はWFPのdefault-denyで走っているので、それらは「見えない」のではなく\n\
         **「繋がらない」**——コマンドが失敗していないかを終了コードで確かめてください。\n",
    );

    out.push_str(&format!(
        "\n許可ドメインの候補（--generalize {}）:\n",
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
            "  ... 他 {}件（全件は `harness-policy-editor show --net --limit 0` で表示）\n",
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

#[cfg(test)]
#[path = "net_aggregate_tests.rs"]
mod net_aggregate_tests;
