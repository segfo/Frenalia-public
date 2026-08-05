//! 提案の**幅**のガード（拘束的決定 D-47、`plans/PLAN-M15.7-FOLLOWUP.md` W5）。
//!
//! # なぜ要るのか
//!
//! `cmd`系のツールは祖先ディレクトリを「通過」(`FILE_TRAVERSE`)ではなく**オープン**する。
//! capability SIDへの祖先付与は`FILE_TRAVERSE|FILE_READ_ATTRIBUTES`だけなので、目的の
//! ファイルへ到達する前に祖先で落ちる。その結果、収集器が観測する拒否は対象ファイルではなく
//! **祖先チェーンそのもの**になる（`plans/etw-spike/RESULTS.md` §17.6の実測）:
//!
//! ```text
//! C:/  C:/Users/  C:/Users/segfo/  C:/Users/segfo/AppData/  .../Local/  .../Local/Temp/
//! ```
//!
//! [`crate::generalize::parent_dir`]はドライブルートへ**畳み上げない**だけなので、`C:/`の拒否は
//! `fs.read: ["C:/"]`という提案としてそのまま出てくる。D-42により自動適用はされないが、
//! **受理1回でマシン全体が読めるようになる提案が候補一覧に平然と並ぶ**。しかもこの形の拒否は
//! 実使用で日常的に出るので、机上の懸念ではない。
//!
//! # なぜ[`crate::gate`]に入れないのか
//!
//! `gate::check_proposal`の契約は`--require-sandbox`という**1つの軸**だけである。そこへ
//! 「値の幅」という別軸を混ぜると真理値表が2次元になり、どちらの理由で拒否されたのかが
//! 呼び出し側から見えなくなる。同じ形（[`check`]/[`check_all`]）の独立した関数として置き、
//! `harness-cli`が両方を呼ぶ。
//!
//! # どこで効かせるか（D-43との整合）
//!
//! | 経路 | 扱い |
//! |---|---|
//! | `harness policy audit` | **無傷**。生の候補一覧は隠さない（D-43「失敗を隠さない」） |
//! | `harness policy suggest` | 一覧に出す。`[too-broad]`と理由を付ける |
//! | `harness policy apply` | **1件でも該当したら何も書かずに失敗**する |
//!
//! [`crate::normalize`]の入口で落とすのは**採らない**——`audit`からも消えてしまい、
//! 「収集器が観測していない」と「広すぎるので提案しない」が区別できなくなる。
//!
//! 回避したいユーザーは`.harness/settings.json`を手で編集する。CLIに抜け道を作らないのは
//! 「触れば通る経路を1つも作らない」（D-42）と同じ思想である。
//!
//! # 判定は既知の浅いパスの名指しで始める
//!
//! 統計的な閾値は要らない（W1が測ったのは`--fs-allow`の到達性で、この観測とは別物である）。
//! 深さで機械的に切ると`C:/Users/<誰か>/AppData/Local/Temp`のような**正当な許可先**まで
//! 巻き込むので、止める位置は名指しで決める。

use crate::generalize::{RuleProposal, SettingsKey};

/// [`check`]の判定結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreadthVerdict {
    /// 幅の観点では問題ない。
    Acceptable,
    /// 広すぎる。`harness policy apply`はこれを書かない。
    TooBroad(String),
}

impl BreadthVerdict {
    pub fn is_too_broad(&self) -> bool {
        matches!(self, BreadthVerdict::TooBroad(_))
    }

    pub fn message(&self) -> Option<&str> {
        match self {
            BreadthVerdict::Acceptable => None,
            BreadthVerdict::TooBroad(m) => Some(m),
        }
    }
}

/// 1件の提案の幅を見る。ドメイン（`net.allow_domains`）は対象外——ここで見ているのは
/// FSパスが覆う範囲であって、宛先allowlistの広さではない。
pub fn check(proposal: &RuleProposal) -> BreadthVerdict {
    match proposal.key {
        SettingsKey::NetAllowDomains => BreadthVerdict::Acceptable,
        SettingsKey::FsRead | SettingsKey::FsReadWrite | SettingsKey::FsReadExec => {
            match classify(&proposal.value) {
                Some(reason) => BreadthVerdict::TooBroad(format!(
                    "{} is too broad to accept as a sandbox exception: {reason}. Accepting it \
                     would undo most of what the sandbox is for, and denials on paths like this \
                     usually mean an ancestor directory could not be opened -- not that the whole \
                     tree needs to be readable. If you really intend this, edit \
                     .harness/settings.json by hand.",
                    proposal.value
                )),
                None => BreadthVerdict::Acceptable,
            }
        }
    }
}

/// 複数の提案をまとめて判定し、`(提案id, 判定)`を返す（[`crate::gate::check_all`]と同じ形）。
pub fn check_all<'a>(
    proposals: impl IntoIterator<Item = &'a RuleProposal>,
) -> Vec<(String, BreadthVerdict)> {
    proposals
        .into_iter()
        .map(|p| (p.id.clone(), check(p)))
        .collect()
}

/// 広すぎるなら理由を返す。判定は正規化済みの`/`区切りパス前提（[`crate::normalize`]が済ませている）。
fn classify(value: &str) -> Option<&'static str> {
    let trimmed = value.trim_end_matches('/');

    // UNC（`//host` / `//host/share`）。共有ルートはドライブルートと同じ意味を持つ。
    if let Some(rest) = trimmed.strip_prefix("//") {
        let depth = rest.split('/').filter(|s| !s.is_empty()).count();
        return match depth {
            0 | 1 => Some("it is a UNC host with no share"),
            2 => Some("it is the root of a network share"),
            _ => None,
        };
    }

    let segments: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
    let Some(first) = segments.first() else {
        return Some("it is empty or the filesystem root");
    };
    // ドライブ指定（`C:`）でなければ深さの意味が違うので、判定しない。
    if !is_drive(first) {
        return None;
    }

    match segments.len() {
        // `C:` / `C:/`
        1 => Some("it is a drive root"),
        // `C:/Users` / `C:/Windows` / 任意の深さ1
        2 => Some("it is a top-level directory of the drive"),
        // `C:/Users/<誰か>` はユーザープロファイル全体。それ以外の深さ2は通す。
        3 if segments[1].eq_ignore_ascii_case("Users") => Some("it is an entire user profile"),
        // `C:/Users/<誰か>/AppData`
        4 if segments[1].eq_ignore_ascii_case("Users")
            && segments[3].eq_ignore_ascii_case("AppData") =>
        {
            Some("it is an entire AppData tree")
        }
        // `C:/Users/<誰か>/AppData/{Local,Roaming,LocalLow}` ——
        // この直下の`Temp`等は**通す**。祖先チェーンのうち正当な許可先になりうる最初の位置だから。
        5 if segments[1].eq_ignore_ascii_case("Users")
            && segments[3].eq_ignore_ascii_case("AppData")
            && is_appdata_container(segments[4]) =>
        {
            Some("it is an entire AppData container")
        }
        _ => {
            // `Generalization::Auto`が作りうる浅い位置のワイルドカード（`C:/*`・`C:/Users/*`）。
            // 実質的に上と同じ範囲を開くので同じ扱いにする。
            if segments
                .iter()
                .take(3)
                .any(|segment| segment.contains('*'))
            {
                return Some("a wildcard this close to the drive root matches almost everything");
            }
            None
        }
    }
}

fn is_drive(segment: &str) -> bool {
    segment.len() == 2
        && segment.as_bytes()[0].is_ascii_alphabetic()
        && segment.as_bytes()[1] == b':'
}

fn is_appdata_container(segment: &str) -> bool {
    ["Local", "Roaming", "LocalLow"]
        .iter()
        .any(|name| segment.eq_ignore_ascii_case(name))
}

#[cfg(test)]
#[path = "breadth_tests.rs"]
mod breadth_tests;
