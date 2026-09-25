//! 判定の材料（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` §6.1・D-101）。
//!
//! 各ツールは自分の入力を`call`と同じ型付き構造体で解釈し、**何を照合させるか**をこの型で返す。
//! 判定器（`harness-engine`の`PermissionArbiter`）は**ツールの入力を見ず、これだけを見る**。
//!
//! # なぜ型で決めるのか
//!
//! 以前は判定に渡す文字列を「入力に`command`があればそれ、無ければ`path`」と**入力の形で**選んでいた。
//! 入力を作るのはモデルなので、`write_file`に使いもしない`command`を1つ足すだけで、設定注入パスの拒否が
//! 別の文字列で判定されて当たらなくなった（[BUG-164](../../../docs/bugs/BUG-164.md)）。
//! **材料はツールの種類で決まり、入力の形では決まらない**——ツールが自分の型で解釈すれば、
//! 判定器が「どのキーを見るか」を選ぶ余地そのものが無くなる。

use serde::{Deserialize, Serialize};

/// 判定の材料。変種ごとに掛かる判定が違う（§6.1 の表）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PermissionSubject {
    /// `run_shell`の行。T-09（綴りの検出）と、記録との完全一致が掛かる。
    Command(CommandSubject),
    /// `run_program`の呼び出し。インタプリタの扱いと、引数の配列での照合が掛かる。
    Program(ProgramSubject),
    /// `write_file`・`edit_file`の書込先。設定注入パスの拒否が掛かる。
    ///
    /// 相対パスは**書込口と同じ関数で正規化したもの**（区切りは`/`）、絶対パスは渡されたまま
    /// （書込口は差分層があるとき、ワークスペース外の絶対パスを`_ext`として記録する）。
    WritePath(String),
    /// それ以外のツール。ツールが選んだ代表の文字列（read系はパス、`web_fetch`はURL、
    /// `recall`は`action`、MCPは転送するJSON全体）。
    Text(String),
}

/// 承認に縛ったワークスペース内のファイル1つ（D-102・D-104）。承認の記録にもそのまま入る。
///
/// **中身そのものは持たない**——照合はハッシュだけで行い、表示用の中身は[`FilePreview`]が別に運ぶ。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BoundFile {
    /// ワークスペースルートからの相対パス（区切りは`/`）。
    pub rel_path: String,
    /// 中身の SHA-256（小文字16進）。
    pub sha256: String,
    /// 同じフォルダの名前一覧の SHA-256。スクリプトとして縛ったときだけ（D-104。隣に`json.py`を
    /// 置いて標準ライブラリを乗っ取る手口に、名前の増減で気づくため）。
    pub dir_listing_sha256: Option<String>,
}

/// 承認画面で見せる中身（**照合には使わない**）。ハッシュを取ったのと同じバイト列から作るので、
/// 見せたものと縛ったものは食い違わない。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilePreview {
    pub rel_path: String,
    /// 中身（UTF-8 として読めない部分は置き換える）。上限で切ったら`truncated`。
    pub text: String,
    pub truncated: bool,
}

/// `run_shell`の材料。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandSubject {
    /// モデルが書いた行そのもの。
    pub line: String,
    /// 行に字面で現れたワークスペース内のファイル（`rel_path`昇順・重複なし）。
    #[serde(default)]
    pub files: Vec<BoundFile>,
    /// 行に、存在するのに中身を確かめられないファイルが現れた。記録との照合では当たらない。
    #[serde(default)]
    pub unverifiable: bool,
    /// 表示用（照合に使わない）。
    #[serde(default)]
    pub previews: Vec<FilePreview>,
}

impl CommandSubject {
    /// ファイルを縛らない材料（テストや、中身で縛る必要の無い経路）。
    pub fn line_only(line: impl Into<String>) -> Self {
        Self {
            line: line.into(),
            files: Vec::new(),
            unverifiable: false,
            previews: Vec::new(),
        }
    }
}

/// `run_program`の材料。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramSubject {
    /// 解決前の綴り（モデルが書いたもの）。
    pub program: String,
    /// 引数の配列。
    pub args: Vec<String>,
    /// 解決した絶対パス（解決できなければ`None`。起動も失敗する）。
    #[serde(default)]
    pub resolved: Option<String>,
    /// **コードを走らせる**呼び出しか——インタプリタ（名前で判定）か、解決先がワークスペース内
    /// （モデルが作れるコード）。穴を持てず、記録との完全一致以外は`accept-all`でも聞く（D-99・D-103）。
    #[serde(default)]
    pub runs_code: bool,
    /// 縛ったファイル（`rel_path`昇順・重複なし）。`runs_code`のときだけ計算する。
    #[serde(default)]
    pub files: Vec<BoundFile>,
    /// 恒久承認できない——確かめられない引数（実在しない名前・ディレクトリ・ワークスペース外・
    /// その場のコード・パスの連結されたオプション）がある（D-104）。記録との照合では当たらない。
    #[serde(default)]
    pub one_shot_only: bool,
    /// 表示用（照合に使わない）。
    #[serde(default)]
    pub previews: Vec<FilePreview>,
    /// `-EncodedCommand`をハーネスが機械的に解読した文字列（表示用、照合に使わない）。
    #[serde(default)]
    pub decoded_inline: Option<String>,
}

impl ProgramSubject {
    /// ファイルを縛らない材料（テスト用。`runs_code`はインタプリタの名前だけで決める）。
    pub fn plain(program: impl Into<String>, args: Vec<String>) -> Self {
        let program = program.into();
        let runs_code = crate::is_interpreter_program(&program);
        Self {
            program,
            args,
            resolved: None,
            runs_code,
            files: Vec::new(),
            one_shot_only: runs_code,
            previews: Vec::new(),
            decoded_inline: None,
        }
    }
}

impl PermissionSubject {
    /// 汎用の規則（`tool:pattern`）と照合する文字列。
    ///
    /// `Program`と`Command`は`None`——`run_program`は引数の配列で、`run_shell`は行と縛ったファイルで
    /// 照合する（§3.3・§5）ので、1本の文字列で照合する経路を作らない。
    pub fn rule_text(&self) -> Option<&str> {
        match self {
            PermissionSubject::WritePath(p) => Some(p),
            PermissionSubject::Text(t) => Some(t),
            PermissionSubject::Command(_) | PermissionSubject::Program(_) => None,
        }
    }

    /// ファイルの中身や名前の解決先に依存する材料か（承認の直後に計算し直して比べる相手、D-106）。
    pub fn depends_on_files(&self) -> bool {
        matches!(
            self,
            PermissionSubject::Command(_) | PermissionSubject::Program(_)
        )
    }

    /// 照合に効く部分が同じか（**表示用の中身は比べない**）。承認画面で待っている間に書き換えられた
    /// 中身を、承認済みとして走らせないために、承認の直後に計算し直した材料と比べる（D-106）。
    pub fn same_for_approval(&self, other: &Self) -> bool {
        match (self, other) {
            (PermissionSubject::Command(a), PermissionSubject::Command(b)) => {
                a.line == b.line && a.files == b.files && a.unverifiable == b.unverifiable
            }
            (PermissionSubject::Program(a), PermissionSubject::Program(b)) => {
                a.program == b.program
                    && a.args == b.args
                    && a.resolved == b.resolved
                    && a.runs_code == b.runs_code
                    && a.files == b.files
                    && a.one_shot_only == b.one_shot_only
            }
            (a, b) => a == b,
        }
    }
}
