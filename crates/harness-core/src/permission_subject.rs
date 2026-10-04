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

/// ハーネスが機械的に解読した、符号化された中身の1段（`plans/DESIGN-RUNSHELL-ALLOWLIST.md` §4.4）。
///
/// **表示と要約のためだけで、照合に使わない**（[`FilePreview`]と同じ立場）。解読するのは
/// `harness-tools`の`encoded_command`で、ここは器だけを持つ。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedLayer {
    /// 何段目か（1から）。2段目は、1段目を解読した中身の中に見つかったもの。
    pub depth: u32,
    /// どの書き方から取り出したか。
    pub source: EncodedSource,
    pub outcome: DecodeOutcome,
}

/// 符号化された中身を、どの書き方から取り出したか。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncodedSource {
    /// PowerShell の`-EncodedCommand`（とその省略形）の値。
    EncodedCommand,
    /// PowerShell の`-EncodedArguments`（とその省略形）の値。
    EncodedArguments,
    /// `[Convert]::FromBase64String('…')`の文字列リテラル。
    FromBase64String,
    /// **行の中にそのまま置かれた base64 の塊**（場所を問わずハーネスが見つけた）。
    ///
    /// `-EncodedCommand`の値や`FromBase64String('…')`の引数のように決まった置き場所に無くても、
    /// `echo <base64> | ForEach-Object { … FromBase64String($_) }`のように**変数を経由して渡す形**があるので、
    /// 字面に出ている塊は置き場所に関わらず読む。読めたときだけ1段として残す（読めなければ何も出さない——
    /// 符号化だと名乗っていないものを「解読できなかった」と並べても、見る人の手がかりにならない）。
    BareBase64,
    /// 機械の解読が何も取れなかった行で、**LLM が「ここが符号化された中身」と場所を示した**文字列
    /// （`harness_engine::encoded_span`）。**解読はハーネスがする**——LLM には解読した文字列を書かせない
    /// （[BUG-224]: LLM に解かせると中身を取り違えた）。示された文字列が行の中にそのまま在るものだけを解読する。
    LocatedByModel(PayloadEncoding),
}

/// LLM が示した符号化の種類（[`EncodedSource::LocatedByModel`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayloadEncoding {
    Base64,
    /// RFC 4648 の base32（`A`〜`Z`と`2`〜`7`、詰め物は`=`）。
    Base32,
    /// 16進（`4765742D…`・`0x47 0x65`・`\x47\x65`）。
    Hex,
    /// 10進の文字コードの並び（`115,121,115`・`[char]105+[char]101`）。
    CharCodes,
    /// gzip で圧縮して base64 にしたもの。
    GzipBase64,
    /// deflate（ヘッダ無し）で圧縮して base64 にしたもの。
    DeflateBase64,
}

impl PayloadEncoding {
    /// LLM に答えさせる綴り（`encoded_span`の固定の指示と同じ表）。知らない綴りは`None`。
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name.trim().to_ascii_lowercase().as_str() {
            "base64" => PayloadEncoding::Base64,
            "base32" => PayloadEncoding::Base32,
            "hex" => PayloadEncoding::Hex,
            "char_codes" => PayloadEncoding::CharCodes,
            "gzip_base64" => PayloadEncoding::GzipBase64,
            "deflate_base64" => PayloadEncoding::DeflateBase64,
            _ => return None,
        })
    }

    /// 画面と要約に出す名前。
    pub fn name(self) -> &'static str {
        match self {
            PayloadEncoding::Base64 => "base64",
            PayloadEncoding::Base32 => "base32",
            PayloadEncoding::Hex => "hex",
            PayloadEncoding::CharCodes => "char codes",
            PayloadEncoding::GzipBase64 => "gzip+base64",
            PayloadEncoding::DeflateBase64 => "deflate+base64",
        }
    }
}

/// LLM が示した、行の中の符号化された文字列とその種類。**表示と要約・危険度の判定のためだけで、照合に使わない。**
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocatedSpan {
    pub text: String,
    pub encoding: PayloadEncoding,
}

impl EncodedSource {
    /// 画面と要約に出す綴り（PowerShell の正式な書き方）。
    pub fn spelling(self) -> &'static str {
        match self {
            EncodedSource::EncodedCommand => "-EncodedCommand",
            EncodedSource::EncodedArguments => "-EncodedArguments",
            EncodedSource::FromBase64String => "[Convert]::FromBase64String",
            EncodedSource::BareBase64 => "base64",
            EncodedSource::LocatedByModel(_) => "(located by the model)",
        }
    }
}

/// 1段を解読した結果。**解読できなかったこと・上限で止めたことも1段として残す**——黙って落とすと、
/// 見る人には「符号化された中身は無かった」と区別がつかない。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecodeOutcome {
    /// 文字として読めた。
    Text {
        encoding: TextEncoding,
        text: String,
    },
    /// 綴りの後ろに値が無い。
    MissingValue,
    /// 値が base64 として読めない（PowerShell も受け付けない形。変数や式なら実行時に決まる）。
    NotBase64,
    /// base64 は読めたが、UTF-8 でも UTF-16LE でも文字として成り立たない。
    ///
    /// 圧縮・暗号化・実行ファイルのほか、**長さが半端**（UTF-16LE なのに奇数バイト）もここに入る
    /// ——綴りの後ろにたまたま base64 として読める短い語が続いただけ、という形がこれである。
    NotText,
    /// `FromBase64String`の引数が文字列リテラルではない（実行時に決まる）。
    NotLiteral,
    /// 深さの上限で止めた（ここから先は解読していない）。
    DepthLimit { max_depth: u32 },
    /// 解読した中身の合計の大きさの上限で止めた。
    SizeLimit { max_bytes: usize },
    /// 段の数の上限で止めた（これ以降は探していない）。
    CountLimit { max_layers: usize },
    /// LLM が示した符号化として読めなかった（[`EncodedSource::LocatedByModel`]だけに出る）。
    Unreadable,
}

/// 文字として読んだときの符号化。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TextEncoding {
    Utf16Le,
    Utf8,
    /// 文字コードの並びを、そのまま文字にした（[`PayloadEncoding::CharCodes`]）。
    CharCodes,
}

impl TextEncoding {
    pub fn name(self) -> &'static str {
        match self {
            TextEncoding::Utf16Le => "UTF-16LE",
            TextEncoding::Utf8 => "UTF-8",
            TextEncoding::CharCodes => "char codes",
        }
    }
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
    /// 行に符号化された中身（PowerShell の`-EncodedCommand`など）があれば、ハーネスが機械的に
    /// 解読したもの（表示と要約のため、照合に使わない）。
    #[serde(default)]
    pub decoded: Vec<DecodedLayer>,
}

impl PermissionSubject {
    /// 人が読むコマンドの1行。`run_shell`は行そのもの、`run_program`は[`ProgramSubject::describe`]。
    /// コマンドでない材料（書込先・その他）は`None`。承認画面の危険度の判定と、流れの記録（[`crate::CommandHistory`]）が
    /// 同じこれを使う。
    pub fn command_line(&self) -> Option<String> {
        match self {
            PermissionSubject::Command(c) => Some(c.line.clone()),
            PermissionSubject::Program(p) => Some(p.describe()),
            PermissionSubject::WritePath(_) | PermissionSubject::Text(_) => None,
        }
    }
}

impl CommandSubject {
    /// ファイルを縛らない材料（テストや、中身で縛る必要の無い経路）。
    pub fn line_only(line: impl Into<String>) -> Self {
        Self {
            line: line.into(),
            files: Vec::new(),
            unverifiable: false,
            previews: Vec::new(),
            decoded: Vec::new(),
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
    /// 引数に符号化された中身（PowerShell の`-EncodedCommand`など）があれば、ハーネスが機械的に
    /// 解読したもの（表示と要約のため、照合に使わない）。
    #[serde(default)]
    pub decoded: Vec<DecodedLayer>,
}

impl ProgramSubject {
    /// 人が読む1行（認知層の出典・一覧・画面）。
    ///
    /// **空白や引用符を含む引数は引用符で囲む。** 境界が消えると `rm -rf /` と `rm "-rf /"` が
    /// 同じ文字列になり、出典として何を見たのか分からなくなる。見えない文字は綴りへ置き換える
    /// （[`crate::escape_for_display`] と同じ表を使う）。
    ///
    /// **これはシェルへ渡せる文字列ではない**——`run_program` はシェルを通さないので、
    /// 引用の規則をどのシェルにも合わせていない。読むためだけのものである。
    pub fn describe(&self) -> String {
        let mut out = crate::escape_for_display(&self.program);
        for arg in &self.args {
            out.push(' ');
            let shown = crate::escape_for_display(arg);
            if shown.is_empty() || shown.chars().any(|c| c.is_whitespace() || c == '"') {
                out.push_str(&format!("{shown:?}"));
            } else {
                out.push_str(&shown);
            }
        }
        out
    }

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
            decoded: Vec::new(),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 出典と画面に出す1行。**引数の境界を消さない**——消すと `rm -rf /` と `rm "-rf /"` が
    /// 同じ文字列になり、何を見たのか分からなくなる。見えない文字は綴りへ置き換える。
    #[test]
    fn describe_keeps_argument_boundaries_and_shows_invisible_characters() {
        let p = |args: &[&str]| {
            ProgramSubject::plain("git", args.iter().map(|a| a.to_string()).collect())
        };
        assert_eq!(p(&["status"]).describe(), "git status");
        assert_eq!(p(&[]).describe(), "git");
        assert_eq!(
            p(&["commit", "-m", "a b"]).describe(),
            r#"git commit -m "a b""#
        );
        assert_eq!(p(&[""]).describe(), r#"git """#);
        assert_eq!(p(&["a\u{202E}b"]).describe(), r"git a\u{202E}b");
        // 境界が消えていないこと（この2つが同じ文字列にならない）。
        assert_ne!(p(&["-rf", "/"]).describe(), p(&["-rf /"]).describe());
    }
}
