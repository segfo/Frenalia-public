//! このセッションで実際に走ったコマンドの流れ（承認画面の「これまでの流れと合わせた危険度」。D-100 の追記）。
//!
//! # 何のためにあるのか
//!
//! 1つずつ見ると無害でも、並びで見ると危険なものがある——「スクリプトを取ってくる → 走らせる」
//! 「前のコマンドで変数にシステムの場所を入れる → その変数を消す」。判定モデルにこの並びを渡すために、
//! **実際に走ったもの**（承認が通って起動したもの。エンジンの`AgentEvent::ToolStarted`）を古い順に覚える。
//!
//! # 覚えるもの・覚えないもの
//!
//! - `run_shell`の行・`run_program`のプログラムと引数（[`crate::PermissionSubject::command_line`]）
//! - `write_file`・`edit_file`の書いた先のパス（`write_file setup.ps1`の形。**中身は入れない**）
//! - 読むだけのツール（`read_file`・`grep`等）は覚えない
//!
//! # 限界
//!
//! - **メモリにだけ持つ**——ハーネスを閉じると消え、`--resume`で再開した直後は空から始まる
//! - ハーネスの外でユーザーが打ったコマンドは入らない
//! - 新しい方から[`MAX_HISTORY_ENTRIES`]件・合計[`MAX_HISTORY_CHARS`]字まで（古いものから落とす）。
//!   判定モデルの側でも長い入力は切り詰められる

use std::collections::VecDeque;

use crate::PermissionSubject;

/// 覚える件数の上限。
pub const MAX_HISTORY_ENTRIES: usize = 20;
/// 覚える文字数の合計の上限。
pub const MAX_HISTORY_CHARS: usize = 4_000;
/// 1件の文字数の上限（長い1行で他を全部押し出さないため）。
pub const MAX_ENTRY_CHARS: usize = 500;

/// 実際に走ったコマンドの流れ（古い順）。
#[derive(Debug, Clone, Default)]
pub struct CommandHistory {
    entries: VecDeque<String>,
}

impl CommandHistory {
    /// 走った呼び出しを1件覚える。`tool`はツールの名前、`subject`は判定に使った材料。覚えないものは何もしない。
    pub fn record(&mut self, tool: &str, subject: &PermissionSubject) {
        let Some(entry) = entry(tool, subject) else {
            return;
        };
        let entry: String = entry.chars().take(MAX_ENTRY_CHARS).collect();
        self.entries.push_back(entry);
        while self.entries.len() > MAX_HISTORY_ENTRIES || self.chars() > MAX_HISTORY_CHARS {
            self.entries.pop_front();
        }
    }

    /// 覚えている流れ（古い順）。
    pub fn entries(&self) -> Vec<String> {
        self.entries.iter().cloned().collect()
    }

    fn chars(&self) -> usize {
        self.entries.iter().map(|e| e.chars().count()).sum()
    }
}

/// 1件の書き方。
fn entry(tool: &str, subject: &PermissionSubject) -> Option<String> {
    match subject {
        PermissionSubject::Command(_) | PermissionSubject::Program(_) => subject.command_line(),
        PermissionSubject::WritePath(path) => Some(format!("{tool} {path}")),
        PermissionSubject::Text(_) => None,
    }
}

#[cfg(test)]
#[path = "command_history_tests.rs"]
mod tests;
