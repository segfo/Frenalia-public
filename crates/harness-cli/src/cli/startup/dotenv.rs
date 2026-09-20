//! `.env`の読み込み。**リポジトリに同梱された`.env`は読まない**（[BUG-115]）。
//!
//! # なぜリポジトリ側を読まないのか
//!
//! `.env`はプロセスの環境変数を書き換える。そして**harnessが環境変数から読む名前は、
//! 数えるとほぼ全部がセキュリティに効く**——昇格ヘルパーの配置検査を外す逃がし弁
//! （`HARNESS_ALLOW_USER_WRITABLE_ELEVATED_HELPERS`、D-44）、**APIの宛先**
//! （`ANTHROPIC_BASE_URL`・`OPENAI_BASE_URL`。`--base-url`が無ければこれが使われ、
//! **APIキーごとその宛先へ渡る**——`crate::cli::setup::build_provider`）、
//! 起動するエディタ（`EDITOR`・`VISUAL`）。
//!
//! したがって「危ない名前だけ弾く」という形は成立しない。弾く一覧は「全部」に縮退する。
//!
//! # `.harness/`へ置けば守られる、ではない
//!
//! `<workspace>/.harness`は層3 hard-denyの対象だが、**あれは「書込」への防御**である。
//! `git clone`で同梱されてきたファイルは書込を一度も起こさないので、一度も発火しない。
//!
//! これはMCPサーバ宣言について既に一度解いた問題で、`plans/DESIGN-MCP.md` D-39が
//! 同じ理由を明記している——「この承認が必要なのは、`.harness/settings.json`に対する
//! 既存の多層防御がすべて『書込』への防御であり、**リポジトリに同梱された宣言には
//! 一度も発火しないため**である」。
//!
//! # この機構の限界
//!
//! - **OSのユーザー環境変数・システム環境変数・親シェルからの継承は塞がない。**
//!   そこへ書ける相手は既にユーザーと同じ権限でコードを実行できるので、harnessが
//!   環境変数を読まないようにしても何も守れない（同じ相手は`harness.exe`自体を差し替えられる）。
//! - **リポジトリ側の`.env`を消しはしない。** 読まないだけで、ファイルはそこに残る。
//!   他のツール（`docker compose`等）がそれを読むかどうかはharnessの関知するところではない。
//! - **ユーザー層の`.env`の中身は検査しない。** そこはユーザー自身の領域である。
//!
//! [BUG-115]: ../../../../../docs/bugs/BUG-115.md

use std::path::{Path, PathBuf};

/// 探すファイル名。リポジトリ側・ユーザー層の両方で同じ。
const ENV_FILE: &str = ".env";

/// `.env`をどう扱うかの判断。**環境変数に一切触らない**ので単体で検査できる。
///
/// 判断（ここ）と実行（[`apply`]）を分けているのは、読み込みが
/// `std::env::set_var`というプロセス全体の状態変更だからである——
/// テストから並行に呼べば互いの環境を壊す。
#[derive(Debug, PartialEq, Eq)]
pub(super) struct DotenvPlan {
    /// 読むファイル（ユーザー層）。存在しなければ`None`。
    pub load: Option<PathBuf>,
    /// **読まずに無視した**ファイル（リポジトリ側）。存在しなければ`None`。
    pub ignored: Option<PathBuf>,
}

/// `start`から上へ辿って最初に見つかる`.env`を返す。
///
/// **上へ辿るのは、以前の`dotenvy::dotenv()`がそうしていたためである**
/// （`dotenvy-0.15.7`の`find::find`は再帰的に親を見る）。無視したことを告げる相手は
/// 「以前なら読まれていたファイル」でなければ意味がないので、探索範囲を狭めない。
fn find_upwards(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        let candidate = d.join(ENV_FILE);
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = d.parent();
    }
    None
}

/// 読むもの・無視するものを決める。**存在確認以外のI/Oをしない。**
///
/// `user_config_dir`は`harness_grant_ledger::config_dir()`が返す
/// `%APPDATA%\harness\config`（mac/LinuxはXDG準拠）。取れない環境では`None`を渡す。
pub(super) fn plan(user_config_dir: Option<&Path>, start: &Path) -> DotenvPlan {
    let user_env = user_config_dir
        .map(|d| d.join(ENV_FILE))
        .filter(|p| p.is_file());
    let found = find_upwards(start);
    // ユーザー層の`.env`自身を「無視した」と報告しない——cwdが設定ディレクトリそのもの
    // だったときに、読んだファイルを同時に無視したと言うことになる。
    let ignored = found.filter(|p| Some(p) != user_env.as_ref());
    DotenvPlan {
        load: user_env,
        ignored,
    }
}

/// 無視したことを告げる文面。**置き場と移動の仕方まで書く。**
///
/// 「読みませんでした」だけでは、APIキーを`.env`に置いていた利用者は
/// **鍵が未設定になった理由に辿り着けない**。
pub(super) fn ignored_notice(ignored: &Path, user_config_dir: Option<&Path>) -> String {
    let destination = match user_config_dir {
        Some(dir) => dir.join(ENV_FILE).display().to_string(),
        None => format!("(the user config directory could not be resolved) {ENV_FILE}"),
    };
    format!(
        "warning: {} is NOT loaded.\n  \
         A .env that ships with a repository can redirect the provider base URL (your API key \
         goes to that host), disable the elevation-target check, and choose the editor harness \
         launches. Cloning the repository is enough -- nothing has to write the file, which is \
         why the hard-deny list does not cover this (BUG-115, same reason as D-39).\n  \
         Put your own values here instead:\n    {destination}",
        ignored.display()
    )
}

/// 判断を実行する。**戻り値は警告の文面**（無ければ`None`）で、出力は呼び出し側が行う。
pub(super) fn apply(plan: &DotenvPlan) -> Option<String> {
    if let Some(path) = &plan.load {
        // `from_path`は既存の環境変数を上書きしない（旧`dotenv()`と同じ規則）。
        if let Err(e) = dotenvy::from_path(path) {
            if !e.not_found() {
                eprintln!("warning: failed to read {}: {e}", path.display());
            }
        }
    }
    plan.ignored
        .as_ref()
        .map(|ignored| ignored_notice(ignored, harness_grant_ledger::config_dir().as_deref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "KEY=value\n").unwrap();
    }

    /// 許可側——ユーザー層に置いた`.env`は読む対象になる。
    #[test]
    fn a_dotenv_in_the_user_config_directory_is_the_one_we_load() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        let workspace = tmp.path().join("ws");
        std::fs::create_dir_all(&workspace).unwrap();
        touch(&config.join(ENV_FILE));

        let plan = plan(Some(&config), &workspace);
        assert_eq!(plan.load, Some(config.join(ENV_FILE)));
        assert_eq!(plan.ignored, None);
    }

    /// 禁止側——ワークスペースの`.env`は読まない。**これが本件の中身である。**
    #[test]
    fn a_dotenv_that_ships_with_the_repository_is_never_loaded() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        let workspace = tmp.path().join("ws");
        std::fs::create_dir_all(&config).unwrap();
        touch(&workspace.join(ENV_FILE));

        let plan = plan(Some(&config), &workspace);
        assert_eq!(plan.load, None, "リポジトリ側を読む対象にしてはならない");
        assert_eq!(plan.ignored, Some(workspace.join(ENV_FILE)));
    }

    /// 親ディレクトリの`.env`も「以前なら読まれていた」ので、無視したと告げる。
    ///
    /// 旧`dotenvy::dotenv()`は上へ辿って探していた。告げる範囲を狭めると、
    /// **黙って挙動が変わったように見える**利用者が出る。
    #[test]
    fn a_dotenv_in_an_ancestor_directory_is_reported_as_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        let nested = tmp.path().join("ws").join("crates").join("inner");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&nested).unwrap();
        touch(&tmp.path().join("ws").join(ENV_FILE));

        let plan = plan(Some(&config), &nested);
        assert_eq!(plan.ignored, Some(tmp.path().join("ws").join(ENV_FILE)));
    }

    /// cwdが設定ディレクトリそのものだったとき、**読んだファイルを同時に無視したと言わない**。
    #[test]
    fn the_user_level_file_is_not_also_reported_as_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        touch(&config.join(ENV_FILE));

        let plan = plan(Some(&config), &config);
        assert_eq!(plan.load, Some(config.join(ENV_FILE)));
        assert_eq!(plan.ignored, None);
    }

    /// `.env`がどこにも無ければ、読むものも告げることも無い（無言で正しい）。
    #[test]
    fn nothing_to_say_when_no_dotenv_exists_anywhere() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        let workspace = tmp.path().join("ws");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();

        let plan = plan(Some(&config), &workspace);
        assert_eq!(plan.load, None);
        assert_eq!(plan.ignored, None);
    }

    /// 文面は**移動先まで**書く。「読まなかった」だけでは鍵が消えた理由に辿り着けない。
    #[test]
    fn the_notice_names_where_to_put_the_file_instead() {
        let ignored = Path::new("C:/ws/.env");
        let config = Path::new("C:/Users/me/AppData/Roaming/harness/config");
        let text = ignored_notice(ignored, Some(config));
        assert!(
            text.contains("C:/ws/.env"),
            "無視したファイルが出ていない: {text}"
        );
        assert!(
            text.contains("C:/Users/me/AppData/Roaming/harness/config"),
            "置き場が出ていない: {text}"
        );
        assert!(
            text.contains("base URL"),
            "なぜ読まないのかが出ていない: {text}"
        );
    }
}
