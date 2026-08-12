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
//! # 判定は既知の浅いパスの名指しで行う
//!
//! 統計的な閾値は要らない（W1が測ったのは`--fs-allow`の到達性で、この観測とは別物である）。
//! 深さで機械的に切ると`C:/Users/<誰か>/AppData/Local/Temp`のような**正当な許可先**まで
//! 巻き込むので、止める位置は名指しで決める。
//!
//! **効いている軸は深さではなく「そのパスが何を束ねているか」である**（2026-08-08に見直し）。
//! かつてはドライブ直下（`C:/<任意>`）を一律に拒否していたが、それは`C:/.cargo`・`C:/tools`の
//! ような「束ねているのは自分自身のものだけ」のディレクトリまで巻き込む——ポリシーエディタで
//! 実際に記録したところ、この一律ルールのせいで承認できる候補が消えた。いまは2種類を名指しする。
//!
//! | 種別 | 例 | 扱い |
//! |---|---|---|
//! | 多者を束ねるルート（[`MULTI_PRINCIPAL_ROOTS`]） | `C:/Users`・`C:/ProgramData`・`C:/$Recycle.Bin` | **access種別によらず拒否**（他ユーザーの秘密が入る） |
//! | マシン全体のインストール先（[`MACHINE_WIDE_INSTALL_ROOTS`]） | `C:/Windows`・`C:/Program Files` | **`fs.read_write`だけ拒否**。読み取り・実行はAppContainerに既定で与えられている範囲なので、拒んでも機密性は増えない。一方そこへ書ければ、全ユーザーが実行するプログラムを差し替えられる |
//! | それ以外のドライブ直下 | `C:/.cargo`・`C:/tools`・`D:/data` | 通す |
//!
//! ドライブルート・ユーザープロファイル・`AppData`ルート・UNC共有ルート・浅いワイルドカードは
//! 従来どおり拒否する（祖先チェーンとして実際に観測される形、§17.6）。

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
    check_value(proposal.key, &proposal.value)
}

/// 提案になる**前の値**を同じ規則で見る。
///
/// [`crate::generalize`]の畳み込みが「ここで拒否される値」を作らないために要る——
/// 判定を書き直さずに同じ関数を通す（規則5・B-20: 判定は1箇所）。
pub fn check_value(key: SettingsKey, value: &str) -> BreadthVerdict {
    match key {
        SettingsKey::NetAllowDomains => BreadthVerdict::Acceptable,
        SettingsKey::FsRead | SettingsKey::FsReadWrite | SettingsKey::FsReadExec => {
            // [D-63] **ワイルドカードは確定部分で判定する。** ACEが付くのはそこだからである
            // （`C:/x/**`への付与は`C:/x`のACE）。値の見た目の深さで測っていた頃は、
            // `C:/Users/<誰か>`を「ユーザープロファイル全体」として拒否しながら、
            // **より広い**`C:/Users/<誰か>/**`を通していた。境目の定義は
            // `normalize::literal_prefix`が1つだけ持つ（付与ルートの算出と同じ関数）。
            let value = crate::normalize::literal_prefix(value);
            match classify(key, value) {
                Some(reason) => BreadthVerdict::TooBroad(format!(
                    "{value} is too broad to accept as a sandbox exception: {reason}. Accepting it \
                     would undo most of what the sandbox is for, and denials on paths like this \
                     usually mean an ancestor directory could not be opened -- not that the whole \
                     tree needs to be readable. If you really intend this, edit \
                     .harness/settings.json by hand."
                )),
                None => BreadthVerdict::Acceptable,
            }
        }
    }
}

// `is_too_broad_for_any_access`（最も厳しいaccessで見て通るか）はここに在ったが、D-62で削除した。
// 唯一の呼び出し元が`generalize`のディレクトリ畳み込み——「推論で`C:/Program Files`全体へ
// 広げない」ためのガード——で、畳み込みごと無くなったため。**残しておくと、在るはずのない
// 「推論で広げる経路」がまだ在るように読める。**

/// 複数の提案をまとめて判定し、`(提案id, 判定)`を返す（[`crate::gate::check_all`]と同じ形）。
pub fn check_all<'a>(
    proposals: impl IntoIterator<Item = &'a RuleProposal>,
) -> Vec<(String, BreadthVerdict)> {
    proposals
        .into_iter()
        .map(|p| (p.id.clone(), check(p)))
        .collect()
}

/// ドライブ直下のうち、**多者（他ユーザー・OS本体）を束ねている**ルート。
///
/// 深さではなく「そこに何が入っているか」で決める。`C:/.cargo`や`C:/tools`はドライブ直下でも
/// 束ねているのは自分自身のものだけなので、ここには入らない。
const MULTI_PRINCIPAL_ROOTS: &[(&str, &str)] = &[
    ("Users", "it is every user profile on this machine"),
    (
        "Documents and Settings",
        "it is the legacy junction to every user profile",
    ),
    (
        "ProgramData",
        "it is the shared application data of every installed program",
    ),
    ("$Recycle.Bin", "it is every user's deleted files"),
    (
        "System Volume Information",
        "it is the volume's shadow copies and restore points",
    ),
];

/// ドライブ直下のうち、**読むぶんには機密が無いが、書けると全ユーザーへ影響する**ルート。
///
/// どちらもAppContainerには既定で読み取り/実行が与えられている場所なので、`fs.read`/`fs.read_exec`を
/// 拒んでも機密性は増えない。一方`fs.read_write`は、そこへ置かれた実行ファイルを差し替えられる
/// ＝**このマシンの全ユーザーに対するコード実行**になるので拒否する。
const MACHINE_WIDE_INSTALL_ROOTS: &[&str] = &["Windows", "Program Files", "Program Files (x86)"];

/// **AppContainerに既定で読み取り・実行が与えられている場所か**（[`MACHINE_WIDE_INSTALL_ROOTS`]配下）。
///
/// # なぜ[`check_value`]と別の関数なのか
///
/// 見ている集合は同じでも、**問いが違う**。[`check_value`]が答えるのは「この値を承認して
/// よいか」で、[`MACHINE_WIDE_INSTALL_ROOTS`]については`fs.read_write`だけを拒否する。
/// こちらが答えるのは「**そもそも提案する必要があるか**」で、答えは実行・読み取りについて
/// 「不要」である——既定で与えられているものを承認させても、増えるのは
/// `preflight`がACEを付けに行く先だけになる。
///
/// 承認されると実害がある: `C:/Windows/System32`への再帰付与はTrustedInstaller所有ノードで
/// 失敗し（D-19の限界、BUG-015）、UACを増やし、最悪パス2が丸ごと落ちる。
///
/// **定数は共有し、判定は分ける**（B-05: 同じ集合を2箇所に持たない／B-20: 別の問いに同じ関数を
/// 使い回さない）。判定は正規化済みの`/`区切りパス前提。
pub fn is_default_exec_root_path(value: &str) -> bool {
    let trimmed = value.trim_end_matches('/');
    let segments: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
    let (Some(first), Some(second)) = (segments.first(), segments.get(1)) else {
        return false;
    };
    if !is_drive(first) {
        return false;
    }
    MACHINE_WIDE_INSTALL_ROOTS
        .iter()
        .any(|root| root.eq_ignore_ascii_case(second))
}

/// 広すぎるなら理由を返す。判定は正規化済みの`/`区切りパス前提（[`crate::normalize`]が済ませている）。
///
/// **`key`を見るのは[`MACHINE_WIDE_INSTALL_ROOTS`]だけ**である（他は読めるだけで実害が出る）。
fn classify(key: SettingsKey, value: &str) -> Option<String> {
    let trimmed = value.trim_end_matches('/');

    // UNC（`//host` / `//host/share`）。共有ルートはドライブルートと同じ意味を持つ。
    if let Some(rest) = trimmed.strip_prefix("//") {
        let depth = rest.split('/').filter(|s| !s.is_empty()).count();
        return match depth {
            0 | 1 => Some("it is a UNC host with no share".to_string()),
            2 => Some("it is the root of a network share".to_string()),
            _ => None,
        };
    }

    let segments: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
    let Some(first) = segments.first() else {
        return Some("it is empty or the filesystem root".to_string());
    };
    // ドライブ指定（`C:`）でなければ深さの意味が違うので、判定しない。
    if !is_drive(first) {
        return None;
    }

    match segments.len() {
        // `C:` / `C:/`
        1 => Some("it is a drive root".to_string()),
        // ドライブ直下は**名前で**決める。深さで一律に切ると`C:/.cargo`や`C:/tools`のような、
        // 束ねているのが自分自身のものだけのディレクトリまで巻き込む（本モジュールdoc）。
        2 => top_level_reason(key, segments[1]),
        // `C:/Users/<誰か>` はユーザープロファイル全体。それ以外の深さ2は通す。
        3 if segments[1].eq_ignore_ascii_case("Users") => {
            Some("it is an entire user profile".to_string())
        }
        // `C:/Users/<誰か>/AppData`
        4 if segments[1].eq_ignore_ascii_case("Users")
            && segments[3].eq_ignore_ascii_case("AppData") =>
        {
            Some("it is an entire AppData tree".to_string())
        }
        // `C:/Users/<誰か>/AppData/{Local,Roaming,LocalLow}` ——
        // この直下の`Temp`等は**通す**。祖先チェーンのうち正当な許可先になりうる最初の位置だから。
        5 if segments[1].eq_ignore_ascii_case("Users")
            && segments[3].eq_ignore_ascii_case("AppData")
            && is_appdata_container(segments[4]) =>
        {
            Some("it is an entire AppData container".to_string())
        }
        _ => {
            // `Generalization::Auto`が作りうる浅い位置のワイルドカード（`C:/*`・`C:/Users/*`）。
            // 実質的に上と同じ範囲を開くので同じ扱いにする。
            if segments.iter().take(3).any(|segment| segment.contains('*')) {
                return Some(
                    "a wildcard this close to the drive root matches almost everything".to_string(),
                );
            }
            None
        }
    }
}

/// ドライブ直下1階層（`C:/<name>`）の判定。
fn top_level_reason(key: SettingsKey, name: &str) -> Option<String> {
    // ワイルドカードで名指しを迂回されない（`C:/Us*`は名前の判定を素通りしてしまう）。
    if name.contains('*') {
        return Some(
            "a wildcard this close to the drive root matches almost everything".to_string(),
        );
    }
    if let Some((_, reason)) = MULTI_PRINCIPAL_ROOTS
        .iter()
        .find(|(root, _)| root.eq_ignore_ascii_case(name))
    {
        return Some((*reason).to_string());
    }
    if MACHINE_WIDE_INSTALL_ROOTS
        .iter()
        .any(|root| root.eq_ignore_ascii_case(name))
    {
        return match key {
            // 読み取り・実行はAppContainerに既定で与えられている範囲なので、拒んでも機密性は増えない。
            SettingsKey::FsRead | SettingsKey::FsReadExec | SettingsKey::NetAllowDomains => None,
            SettingsKey::FsReadWrite => Some(
                "it is a machine-wide install root: being able to write there means replacing \
                 programs that every user on this machine runs (fs.read and fs.read_exec on the \
                 same path are accepted -- it is the write that is the problem)"
                    .to_string(),
            ),
        };
    }
    // それ以外のドライブ直下（`C:/.cargo`・`C:/tools`・`D:/data`）は、束ねているのが
    // 自分自身のものだけなので通す。
    None
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
