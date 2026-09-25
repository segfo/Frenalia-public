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

/// `run_shell`の材料。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandSubject {
    /// モデルが書いた行そのもの。
    pub line: String,
}

/// `run_program`の材料。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramSubject {
    /// 解決前の綴り（モデルが書いたもの）。
    pub program: String,
    /// 引数の配列。
    pub args: Vec<String>,
}

impl PermissionSubject {
    /// 汎用の規則（`tool:pattern`）と照合する文字列。
    ///
    /// `Program`は`None`——`run_program`の規則は引数の配列で照合する（§3.3）ので、
    /// 1本の文字列へ潰して照合する経路を作らない。
    pub fn rule_text(&self) -> Option<&str> {
        match self {
            PermissionSubject::Command(c) => Some(&c.line),
            PermissionSubject::WritePath(p) => Some(p),
            PermissionSubject::Text(t) => Some(t),
            PermissionSubject::Program(_) => None,
        }
    }
}
