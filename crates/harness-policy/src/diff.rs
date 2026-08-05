//! 提案を`.harness/settings.json`への**差分**として表す（`plans/DESIGN-SANDBOX-APPPOLICY.md` §11.3
//! 「提案は設定ファイルへの差分として見せる」）。
//!
//! ここは値を返すだけで、**ファイルへは書かない**（D-42）。書くのは`harness policy apply`が
//! ユーザーの明示操作を受けた後で、その入力になるJSONも[`apply_to_settings`]が純粋に組み立てる。
//! 差分の計算と書込を分けておくと、「表示された差分」と「実際に書かれる内容」が同じ関数から
//! 出ていることをテストで固定できる。

use serde_json::{Map, Value};

use crate::generalize::{RuleProposal, SettingsKey};

/// 1つの設定キーに対して追加される値。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsDiffEntry {
    pub key: SettingsKey,
    /// 既存の設定に**まだ無い**値だけが入る（冪等: 既に書かれているものは差分にならない）。
    pub added: Vec<String>,
}

/// `.harness/settings.json`への差分一式。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettingsDiff {
    pub entries: Vec<SettingsDiffEntry>,
}

impl SettingsDiff {
    pub fn is_empty(&self) -> bool {
        self.entries.iter().all(|e| e.added.is_empty())
    }

    /// `+ fs.read: "C:/x"`形式のテキスト表現。
    pub fn render_text(&self) -> String {
        if self.is_empty() {
            return "(no changes)\n".to_string();
        }
        let mut out = String::new();
        for entry in &self.entries {
            for value in &entry.added {
                out.push_str(&format!("+ {}: {:?}\n", entry.key.dotted(), value));
            }
        }
        out
    }
}

/// 既存の設定JSONと受理する提案から差分を計算する。
///
/// `existing`は`.harness/settings.json`をパースした`Value`（無ければ`Value::Null`でよい）。
/// 既に同じ値が書かれているキーは差分に出さない——`apply`を2回実行しても同じ行が2つ並ばない
/// （設定の重複は害が無いが、差分表示が毎回同じものを提案し続けると「効いていない」と誤解される）。
pub fn compute_diff(existing: &Value, accepted: &[&RuleProposal]) -> SettingsDiff {
    let mut entries: Vec<SettingsDiffEntry> = Vec::new();

    for proposal in accepted {
        let current = existing_values(existing, proposal.key);
        let already_present = current
            .iter()
            .any(|v| v.eq_ignore_ascii_case(&proposal.value));
        let slot = match entries.iter_mut().find(|e| e.key == proposal.key) {
            Some(slot) => slot,
            None => {
                entries.push(SettingsDiffEntry {
                    key: proposal.key,
                    added: Vec::new(),
                });
                entries.last_mut().expect("just pushed")
            }
        };
        if already_present || slot.added.iter().any(|v| v.eq_ignore_ascii_case(&proposal.value)) {
            continue;
        }
        slot.added.push(proposal.value.clone());
    }

    entries.sort_by_key(|e| e.key);
    SettingsDiff { entries }
}

/// 差分を適用した**新しい**設定JSONを返す（元の`existing`は変更しない）。
///
/// 既存の他のキー・書式は保持し、対象の配列へ追記するだけにする。harness自身のconfigへの
/// 書込は「runtime再読込禁止・変更は再起動時のみ発効」（`DESIGN.md`§ツールシステム）なので、
/// ここで組み立てたJSONを書いた後は次回起動まで効かない。
pub fn apply_to_settings(existing: &Value, diff: &SettingsDiff) -> Value {
    let mut root = match existing {
        Value::Object(map) => Value::Object(map.clone()),
        _ => Value::Object(Map::new()),
    };

    for entry in &diff.entries {
        if entry.added.is_empty() {
            continue;
        }
        let (top, array_key) = entry.key.json_path();
        let root_map = root.as_object_mut().expect("root is an object");
        let section = root_map
            .entry(top.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if !section.is_object() {
            *section = Value::Object(Map::new());
        }
        let section_map = section.as_object_mut().expect("section is an object");
        let array = section_map
            .entry(array_key.to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        if !array.is_array() {
            *array = Value::Array(Vec::new());
        }
        let items = array.as_array_mut().expect("array");
        for value in &entry.added {
            let duplicate = items
                .iter()
                .any(|v| v.as_str().is_some_and(|s| s.eq_ignore_ascii_case(value)));
            if !duplicate {
                items.push(Value::String(value.clone()));
            }
        }
    }

    root
}

fn existing_values(existing: &Value, key: SettingsKey) -> Vec<String> {
    let (top, array_key) = key.json_path();
    existing
        .get(top)
        .and_then(|section| section.get(array_key))
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::generalize::{generalize, Generalization};
    use crate::normalize::{DeniedCandidate, Source};
    use harness_config::FsAccess;

    fn proposals() -> Vec<RuleProposal> {
        generalize(
            &[
                DeniedCandidate::fs(Source::Etw, "C:/tools/bin", FsAccess::ReadExec, "d", 1, 0),
                DeniedCandidate::net(Source::Network, "api.example.com", "d", 1, 0),
            ],
            Generalization::None,
        )
    }

    #[test]
    fn diff_lists_only_values_missing_from_the_existing_settings() {
        let existing = serde_json::json!({ "fs": { "read_exec": ["C:/tools/bin"] } });
        let all = proposals();
        let accepted: Vec<&RuleProposal> = all.iter().collect();

        let diff = compute_diff(&existing, &accepted);

        let fs_entry = diff
            .entries
            .iter()
            .find(|e| e.key == SettingsKey::FsReadExec)
            .expect("fs entry present");
        assert!(fs_entry.added.is_empty(), "already present, nothing to add");
        let net_entry = diff
            .entries
            .iter()
            .find(|e| e.key == SettingsKey::NetAllowDomains)
            .expect("net entry present");
        assert_eq!(net_entry.added, vec!["api.example.com".to_string()]);
    }

    /// 適用は対象の配列への追記だけで、既存の他キーは触らない。
    #[test]
    fn apply_appends_without_disturbing_unrelated_settings() {
        let existing = serde_json::json!({
            "model": "keep-me",
            "fs": { "read": ["C:/already"] }
        });
        let all = proposals();
        let accepted: Vec<&RuleProposal> = all.iter().collect();
        let diff = compute_diff(&existing, &accepted);

        let updated = apply_to_settings(&existing, &diff);

        assert_eq!(updated["model"], "keep-me");
        assert_eq!(updated["fs"]["read"], serde_json::json!(["C:/already"]));
        assert_eq!(updated["fs"]["read_exec"], serde_json::json!(["C:/tools/bin"]));
        assert_eq!(
            updated["net"]["allow_domains"],
            serde_json::json!(["api.example.com"])
        );
    }

    /// 2回適用しても同じ値が2つ並ばない（冪等）。
    #[test]
    fn applying_twice_is_idempotent() {
        let all = proposals();
        let accepted: Vec<&RuleProposal> = all.iter().collect();

        let once = apply_to_settings(
            &Value::Null,
            &compute_diff(&Value::Null, &accepted),
        );
        let twice = apply_to_settings(&once, &compute_diff(&once, &accepted));

        assert_eq!(once, twice);
        assert_eq!(twice["fs"]["read_exec"].as_array().unwrap().len(), 1);
    }

    /// 受理しなかった提案は差分にも適用結果にも現れない（`apply --accept`が選択的であること）。
    #[test]
    fn unaccepted_proposals_never_reach_the_settings() {
        let all = proposals();
        let only_net: Vec<&RuleProposal> = all
            .iter()
            .filter(|p| p.key == SettingsKey::NetAllowDomains)
            .collect();

        let updated = apply_to_settings(&Value::Null, &compute_diff(&Value::Null, &only_net));

        assert!(updated.get("fs").is_none(), "fs proposal was not accepted");
        assert_eq!(
            updated["net"]["allow_domains"],
            serde_json::json!(["api.example.com"])
        );
    }

    #[test]
    fn text_rendering_shows_one_line_per_added_value() {
        let all = proposals();
        let accepted: Vec<&RuleProposal> = all.iter().collect();
        let diff = compute_diff(&Value::Null, &accepted);

        let text = diff.render_text();

        assert!(text.contains(r#"+ fs.read_exec: "C:/tools/bin""#), "{text}");
        assert!(text.contains(r#"+ net.allow_domains: "api.example.com""#), "{text}");
    }
}
