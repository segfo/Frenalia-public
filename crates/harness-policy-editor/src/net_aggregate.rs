//! パス2で観測したネットワークイベントを、人が判断できる形（許可ドメインの候補）へ畳み込む。
//!
//! # 候補にする行は、走らせたモードで決まる（決定64、[`NetMode`]）
//!
//! **記録**（既定）は[`harness_core::DomainPolicy::record_all`]で走らせるため、`net-audit.jsonl`の
//! 行はほぼ全部が`allowed: true, reason: "record_all"`になる。`harness_policy::normalize_net_audit`は
//! 拒否行以外を捨てる（`normalize.rs`）ので、そのまま通すと候補が**0件**になる。
//! [`harness_policy::NetIntake::All`]で取り込む——FS側の`on_operation_end_any`と同じ形の分岐である。
//!
//! **強制**は宣言した通信先だけを許して走らせるので、許された行は宣言済みの宛先である。
//! 候補にするのは**断られた行だけ**（[`harness_policy::NetIntake::DeniedOnly`]、通常運用の
//! `harness policy suggest`と同じ取り込み口）。全部を取り込むと、宣言済みの宛先が
//! 「新しい候補」として並び、何が足りなかったのかが埋もれる。
//!
//! # 正本はJSONLであってここではない
//!
//! [`NetAggregate`]は記録中のライブ表示のために行を溜めるが、候補の計算は毎回
//! `harness_policy`の正規化と一般化を通し直す（B-13: 同じ事実の正本を2つ持たない）。
//! `show --net`が何度でも見直せるのはこの性質から来ている。

use std::collections::BTreeMap;

use harness_policy::{DeniedCandidate, RuleProposal};

use crate::session_dir::NetMode;

/// パス2の記録1回分の集計。
#[derive(Debug, Default)]
pub struct NetAggregate {
    /// 観測した行（そのまま。候補の計算は`harness_policy`へ通し直す）。
    lines: Vec<String>,
    /// [決定69 の前例の(7)] **行の持ち主のドメインごと**に分けた行（`domain`の印。印の無い行は入口）。
    /// 候補をドメインごとに出すのに使う（`proposals_by_domain`）。`lines`と二重に持つのは、
    /// 全体の件数・注記（入口と遷移先をまとめた見出し）がこれまでと同じ計算で要るためである。
    lines_by_domain: BTreeMap<String, Vec<String>>,
    pub events_seen: u64,
    /// うち許可されたもの（記録モードではほぼ全部）。
    pub allowed: u64,
    /// うち拒否されたもの。**記録モードでの拒否はIPリテラル宛が主**（`evaluate_host`は
    /// record-allでもIPリテラルを拒否する）。強制モードでは宣言の外の宛先がここへ入る。
    pub denied: u64,
    /// ホスト名を持たなかったイベント（IP直打ち・WFPのdrop）。**盲点の指標**。
    pub without_host: u64,
    /// JSONとして解釈できなかった行数。
    pub unparsable_lines: u64,
    /// ホスト → 観測回数（ライブ表示用の速報。候補の正本ではない）。
    hosts: BTreeMap<String, u64>,
    /// 昇格側が書いた**制御レコード**の理由（`protocol="control"`）。通信の記録ではないので
    /// 上のカウンタにも候補にも入れない——入れると「ホスト名を持たない拒否」として数えられ、
    /// 嘘の注記が出る（BUG-093のセッションで実際に出ていた）。
    ///
    /// **黙って捨てもしない。** ここに溜めたものを呼び出し側が警告として見せる
    /// ——昇格側の失敗は`SW_HIDE`のコンソールへ消えるので、これが唯一の伝達路である。
    control_reasons: Vec<String>,
    /// どのモードで走らせた記録か。候補の取り込み口（[`NetMode::intake`]）と注記を決める。
    mode: NetMode,
}

impl NetAggregate {
    /// 記録モード（既定）の集計。
    pub fn new() -> Self {
        Self::default()
    }

    /// `mode`で走らせた記録の集計。
    pub fn for_mode(mode: NetMode) -> Self {
        Self {
            mode,
            ..Self::default()
        }
    }

    pub fn mode(&self) -> NetMode {
        self.mode
    }

    /// 監査イベント1件を取り込む。
    ///
    /// **制御レコードはネットワークイベントとして数えない**（[`harness_policy::is_net_control_record`]）。
    /// 判定は`harness_policy`側の1箇所を通す——`normalize`とここで別々に書くと、片方だけ
    /// 変わったときに集計と候補がずれる。
    pub fn add_event(&mut self, event: &serde_json::Value) {
        if harness_policy::is_net_control_record(event) {
            if let Some(reason) = event.get("reason").and_then(|v| v.as_str()) {
                self.control_reasons.push(reason.to_string());
            }
            return;
        }
        self.events_seen = self.events_seen.saturating_add(1);
        if let Ok(line) = serde_json::to_string(event) {
            // [決定69 の前例の(7)] 行の持ち主のドメイン（印が無ければ入口＝セッションの中継プロキシ）。
            let domain = event
                .get("domain")
                .and_then(|v| v.as_str())
                .unwrap_or(crate::policy_file::ENTRY_DOMAIN)
                .to_string();
            self.lines_by_domain.entry(domain).or_default().push(line.clone());
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

    /// 昇格側が残した制御レコードの理由（観測順）。呼び出し側はこれを警告として見せる。
    pub fn control_reasons(&self) -> &[String] {
        &self.control_reasons
    }

    /// 畳み込み後の候補（異なるドメインごとに1件）。
    pub fn candidates(&self) -> Vec<DeniedCandidate> {
        harness_policy::normalize::normalize_net_audit_with_mode(
            &self.lines.join("\n"),
            self.mode.intake(),
        )
        .candidates
    }

    /// 許可ルールの提案。**適用はしない**（D-42: 反映は常にユーザーの明示操作）。
    pub fn proposals(&self) -> Vec<RuleProposal> {
        harness_policy::generalize::generalize(&self.candidates())
    }

    /// [決定69 の前例の(7)] **ドメインごとの**候補（`(ドメイン, 提案)`。並びは入口が先、残りは名前の順）。
    ///
    /// 行の印で振り分ける——1つの`net-audit.jsonl`へ入口とドメインのプロキシが追記するので、
    /// ファイル単位では分けられない。印の無い行は入口のドメインとして数える（古い記録もそうなる）。
    /// **番号は呼び出し側が振り直す**（ファイルの候補と1列に並べるため。`position_candidates::renumber`と同じ理由）。
    pub fn proposals_by_domain(&self) -> Vec<(String, RuleProposal)> {
        let entry = crate::policy_file::ENTRY_DOMAIN.to_string();
        let order: Vec<&String> = std::iter::once(&entry)
            .chain(self.lines_by_domain.keys().filter(|name| **name != entry))
            .collect();
        let mut out = Vec::new();
        for domain in order {
            let Some(lines) = self.lines_by_domain.get(domain) else {
                continue;
            };
            let report = harness_policy::normalize::normalize_net_audit_with_mode(
                &lines.join("
"),
                self.mode.intake(),
            );
            for proposal in harness_policy::generalize::generalize(&report.candidates) {
                out.push((domain.clone(), proposal));
            }
        }
        out
    }

    /// 印を持つ行が1つでもあるか（＝ドメインごとに分けられる記録か）。
    pub fn has_domain_tags(&self) -> bool {
        self.lines_by_domain
            .keys()
            .any(|domain| domain != crate::policy_file::ENTRY_DOMAIN)
    }

    /// 正規化が付けた注記（ホスト名を持たなかった件数の説明など）。
    pub fn notes(&self) -> Vec<String> {
        harness_policy::normalize::normalize_net_audit_with_mode(
            &self.lines.join("\n"),
            self.mode.intake(),
        )
        .notes
    }
}

/// 記録済みの`net-audit.jsonl`を読み直して集計する。
///
/// **保存済みの集計値は使わない**（B-13）。何度でも見直せる。`mode`はその記録の
/// マニフェストから渡す（[`crate::session_dir::RecordManifest::net_mode`]）。
pub fn from_log(path: &std::path::Path, mode: NetMode) -> NetAggregate {
    let mut tail = crate::audit_tail::AuditTail::new(path);
    let mut aggregate = NetAggregate::for_mode(mode);
    let (events, skipped) = tail.poll_json_values();
    for event in &events {
        aggregate.add_event(event);
    }
    aggregate.add_unparsable(skipped);
    aggregate
}

/// 候補一覧の**手前**に出す注記（観測件数・ホスト名を持たないイベント・盲点の説明）。
///
/// [`render`]（CLI）とTUIの両方が使う。理由は[`crate::aggregate::render_notes`]と同じ。
pub fn render_notes(aggregate: &NetAggregate) -> String {
    let mut out = String::new();

    out.push_str(&format!("通信の扱い: {}\n", aggregate.mode().label()));
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
    // 昇格側（netfilterd）が残した制御レコード。FS側の`aggregate::render_notes`が
    // `collector_notes`を出すのと同じ役割で、**`show`で後から見返す経路**にも要る
    // ——ライブの警告はその場限りだが、こちらは記録を開き直すたびに出る。
    for reason in aggregate.control_reasons() {
        out.push_str(&format!("昇格側からの報告: {reason}\n"));
    }

    out.push_str(
        "\n注意: **ドメイン名を復元できない通信があります。** OSのリゾルバを経由しない自前DNS\n\
         実装（Go製CLIの一部等）や、プロキシ環境変数を読まないツールはこの記録に現れません。\n\
         パス2はWFPのdefault-denyで走っているので、それらは「見えない」のではなく\n\
         **「繋がらない」**——コマンドが失敗していないかを終了コードで確かめてください。\n",
    );

    out
}

/// 記録結果を人が読む形へ整形する（注記＋候補一覧）。
pub fn render(aggregate: &NetAggregate, limit: usize) -> String {
    let mut out = render_notes(aggregate);
    let proposals = aggregate.proposals();

    out.push_str(match aggregate.mode() {
        NetMode::RecordAll => "\n許可ドメインの候補（観測された値そのまま）:\n",
        NetMode::Declared => "\n許可ドメインの候補（宣言の外で断られた宛先）:\n",
    });
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

#[cfg(test)]
#[path = "net_aggregate_tests.rs"]
mod net_aggregate_tests;
