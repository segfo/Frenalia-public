//! ユーザー単位の恒久設定（`%APPDATA%\harness\config\cli-defaults.toml`）。
//!
//! # 何のためにあるのか
//!
//! **コマンドラインのフラグで指定するような設定を、毎回打ち直さずに済ませるため**である。
//! ハーネスの隔離の強さを変える設定は、これまでコマンドラインのフラグでしか指定できなかった
//! （`plans/DESIGN-CLI-OPTIONS.md` §3.2）。恒久的に変えたいものを起動のたびに打つのは現実的でない。
//!
//! 優先順位は**既定値 → このファイル → コマンドラインのフラグ**で、フラグが最優先である
//! （フラグは「その起動だけ変える最終手段」として残る）。
//!
//! # なぜユーザー層だけなのか
//!
//! §3.2は「隔離を強める・弱める向きの設定はコマンドライン限定」と決めているが、その理由は
//! **プロジェクト層（`<workspace>/.harness/settings.json`）がリポジトリに同梱されて配られ得る**
//! ことである——クローンしたリポジトリに入っていた設定が、隔離を勝手に下げる経路になる。
//! **ユーザー層は同梱されない**ので、この理由が当たらない。
//!
//! 同じ形の前例がある——`harness_config::user_cow_gc_settings`は「プロジェクト層に現れる余地が
//! 無ければ、守り忘れる経路も無い」という理由でユーザー層にしか置いていない。
//!
//! **したがって、このクレートはプロジェクト層を読む関数を1つも持たない。** 置き場を増やすときは、
//! 上の理由が当たらないことを先に確かめること。
//!
//! # 壊れていたら起動を止める（`settings.json`とはここだけ振る舞いが違う）
//!
//! `harness-config`は、設定ファイルが壊れていても警告を出して既定値で続行する。
//! **こちらは止める**（ユーザー判断、2026-10-01）——隔離の強さを決める値が「書いたのに効いていない」
//! 状態で走り出すより、どこが壊れているかを出して直してもらうほうがよい。
//!
//! **壊れたファイルは1バイトも書き換えない。** 流用元（`github.com/segfo/libtoolbox`の
//! `config_loader.rs`）は既定値で上書きするが、それだとユーザーが書いた設定が黙って消える
//! （`B-09`: 成功に見える失敗を作らない）。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// 設定ファイルの名前。
///
/// **`config.toml`にしない。** 置き場が`…\harness\config\`なので`config\config.toml`となり、
/// 同じ語が2回出て何の設定か読み取れない。名前で役割（コマンドラインの既定値）を示す。
pub const CONFIG_FILE_NAME: &str = "cli-defaults.toml";

/// ファイルが無いときに書き出す中身。
///
/// # なぜ構造体のシリアライズそのままではないのか
///
/// `toml`のシリアライズは**コメントを書けない**。設定ファイルは人が読んで書き換えるものなので、
/// 各項目が何をするかがその場に無いと、ユーザーは別の文書を探すことになる。
/// **既定値の構造体と同じ内容であることは、往復のテストが固定している**（`a_generated_file_round_trips`）。
const DEFAULT_FILE_TEMPLATE: &str = r#"# harness のユーザー単位の設定。
#
# ここに書いた値は、コマンドラインのフラグが指定されていないときに使われる。
# 優先順位は「既定値 → このファイル → コマンドラインのフラグ」で、フラグが最優先。
#
# このファイルが無ければ、起動時にこの内容で作り直される。
# 中身が壊れているとハーネスは起動しない（どこが壊れているかを表示する）。

[security]
# 管理者権限で動く補助プロセス（netfilterd・policy-learnd・vmsandboxd）が、
# 管理者でないユーザーが作ったリンク（ジャンクション・シンボリックリンク）を辿らないようにする。
#
# false にすると、リンクを辿る経路の守りが1枚減る。書き込む前にパスを実体へ解決して
# 確かめる処理は残るが、新しい書込経路でその確認を呼び忘れたときに守るものが無くなる。
# 切った起動では、その事実が privhelper.log に1行記録される。
refuse_untrusted_links = true
"#;

/// ユーザー単位の設定。
///
/// **フィールドを足すときは`DEFAULT_FILE_TEMPLATE`にも項目とコメントを足すこと。**
/// 片方だけだと、生成されたファイルに書かれていない設定ができる（往復のテストが落ちる）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    #[serde(default)]
    pub security: SecurityConfig,
}

/// 隔離の強さに関わる設定。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// 管理者権限で動く補助プロセスが、管理者でないユーザーが作ったリンクを辿らないようにするか。
    ///
    /// **既定は`true`（辿らない）。** 切るのはユーザーの明示操作である——
    /// 既定を緩い側に置くと、設定ファイルを消しただけで守りが外れる。
    ///
    /// 何を守るかと、何を守らないか（ハードリンクには効かない等）は
    /// `harness_sandbox::process_hardening`のモジュールdocが持つ。**ここへ写さない。**
    pub refuse_untrusted_links: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            refuse_untrusted_links: true,
        }
    }
}

/// 設定を読めなかった理由。
///
/// **「無かった」はここに無い**——無いときは既定値を書き出して既定値を返すので、失敗ではない。
#[derive(Debug)]
pub enum UserConfigError {
    /// 置き場を決められなかった（ホームディレクトリが取れない等）。
    NoConfigDir,
    /// ファイルは在るが読めない（権限・入出力の失敗）。
    Read { path: PathBuf, source: std::io::Error },
    /// TOMLとして壊れている、または型が合わない。**どこが壊れているかを文面が持つ。**
    Parse { path: PathBuf, message: String },
}

impl std::fmt::Display for UserConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserConfigError::NoConfigDir => {
                write!(f, "could not determine the per-user configuration directory")
            }
            UserConfigError::Read { path, source } => {
                write!(f, "could not read {}: {source}", path.display())
            }
            UserConfigError::Parse { path, message } => {
                write!(f, "{} is malformed:\n{message}", path.display())
            }
        }
    }
}

impl std::error::Error for UserConfigError {}

/// 設定ファイルの置き場（`<ユーザーの設定ディレクトリ>/cli-defaults.toml`）。
///
/// 出どころは`harness_config`のユーザー層（`settings.json`）と**同じ**——
/// 2つの設定が別のディレクトリに散ると、どちらを直せばよいか分からなくなる。
pub fn path() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "harness")
        .map(|d| d.config_dir().join(CONFIG_FILE_NAME))
}

/// 既定の置き場から読む。無ければ既定値のファイルを書き出してから既定値を返す。
pub fn load() -> Result<UserConfig, UserConfigError> {
    let path = path().ok_or(UserConfigError::NoConfigDir)?;
    load_from(&path)
}

/// 置き場を指定して読む（テストが使う。製品の経路は[`load`]）。
///
/// # 書き出しに失敗しても読み取りは失敗にしない
///
/// 目的は**設定を読むこと**で、既定値を書き出すのは次回から人が編集できるようにする親切である。
/// 書けない（読取専用のディレクトリ等）ことを理由に起動を止めると、親切のために目的を落とす。
/// **黙らせはしない**——警告を標準エラーへ出す。
pub fn load_from(path: &Path) -> Result<UserConfig, UserConfigError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            write_default_file(path);
            return Ok(UserConfig::default());
        }
        Err(e) => {
            return Err(UserConfigError::Read {
                path: path.to_path_buf(),
                source: e,
            })
        }
    };
    // **壊れていても書き換えない。** 流用元はここで既定値を書き戻すが、それだとユーザーが
    // 書いた設定が黙って消える。読み手は`Err`を受けて起動を止める。
    toml::from_str(&text).map_err(|e| UserConfigError::Parse {
        path: path.to_path_buf(),
        // `toml`のエラーは行・列と期待した型を持つ。**そのまま運ぶ**——要約すると、
        // どこを直せばよいかが消える。
        message: e.to_string(),
    })
}

/// 既定値のファイルを書き出す（失敗しても警告だけ）。
fn write_default_file(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!(
                "warning: could not create the configuration directory {}: {e}",
                parent.display()
            );
            return;
        }
    }
    if let Err(e) = std::fs::write(path, DEFAULT_FILE_TEMPLATE) {
        eprintln!(
            "warning: could not write the default configuration to {}: {e}",
            path.display()
        );
    }
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod lib_tests;
