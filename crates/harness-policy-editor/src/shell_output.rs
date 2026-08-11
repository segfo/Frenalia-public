//! シェルの起動時ノイズとコマンドの出力を、境界印で切り分ける（ストリーミング版）。
//!
//! [`harness_tools::RUN_SHELL_OUTPUT_SENTINEL`]は`run_shell`と共有する（B-05）。
//! `run_shell`側は全文が揃ってから切る（`split_shell_startup_noise`）が、記録モードは
//! 行が届くたびに流すので、**印が来るまで溜めて**から判断する。
//!
//! パス1（Tier0のFS記録）とパス2（Tier2aのドメイン記録）が同じものを使う——切り方を
//! 経路ごとに書くと、BUG-086（成功したコマンドが失敗に見える）の作法が片方だけになる。

use serde::Serialize;

/// 子プロセスから届いた1行を、**誰が言ったことか**で分けたもの。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ShellLine {
    /// シェルがコマンドを走らせる**前に**吐いた出力（境界印より前）。
    /// コマンドの出力と混ぜない（BUG-086）。
    StartupNoise(String),
    Stdout(String),
    Stderr(String),
}

/// 印は必ず出力の先頭付近に来る（ブートストラップの最初の文）ので、溜める時間は実質ゼロ。
/// **印が一度も来なかった場合は、溜めた行を全部コマンドの出力として流す**
/// ——隠さない側へ倒す（`run_shell`側と同じ判断）。
pub struct StartupNoiseFilter {
    pending: Vec<String>,
    seen_sentinel: bool,
}

impl Default for StartupNoiseFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl StartupNoiseFilter {
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            seen_sentinel: false,
        }
    }

    pub fn feed(&mut self, line: String, stderr: bool) -> Vec<ShellLine> {
        if self.seen_sentinel {
            return vec![Self::content(line, stderr)];
        }
        if line.contains(harness_tools::RUN_SHELL_OUTPUT_SENTINEL) {
            self.seen_sentinel = true;
            return std::mem::take(&mut self.pending)
                .into_iter()
                .map(ShellLine::StartupNoise)
                .collect();
        }
        self.pending.push(line);
        Vec::new()
    }

    /// EOF時に呼ぶ。印が来ないまま終わったなら、溜めた行は**コマンドの出力**として出す。
    pub fn flush(&mut self, stderr: bool) -> Vec<ShellLine> {
        if self.seen_sentinel {
            return Vec::new();
        }
        std::mem::take(&mut self.pending)
            .into_iter()
            .map(|line| Self::content(line, stderr))
            .collect()
    }

    fn content(line: String, stderr: bool) -> ShellLine {
        if stderr {
            ShellLine::Stderr(line)
        } else {
            ShellLine::Stdout(line)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(lines: Vec<ShellLine>) -> Vec<String> {
        lines
            .into_iter()
            .map(|line| match line {
                ShellLine::Stdout(l) => format!("out:{l}"),
                ShellLine::Stderr(l) => format!("err:{l}"),
                ShellLine::StartupNoise(l) => format!("noise:{l}"),
            })
            .collect()
    }

    /// 印より前の行はノイズ、後の行はコマンドの出力（BUG-086と同じ切り方）。
    #[test]
    fn lines_before_the_sentinel_are_startup_noise_and_lines_after_are_output() {
        let mut filter = StartupNoiseFilter::new();

        assert!(filter
            .feed("PowerShellの警告\n".to_string(), false)
            .is_empty());
        assert_eq!(
            labels(filter.feed(
                format!("{}\n", harness_tools::RUN_SHELL_OUTPUT_SENTINEL),
                false
            )),
            vec!["noise:PowerShellの警告\n"]
        );
        assert_eq!(
            labels(filter.feed("本当の出力\n".to_string(), false)),
            vec!["out:本当の出力\n"]
        );
    }

    /// **印が来ないまま終わったら、溜めた行は隠さずコマンドの出力として出す。**
    /// （シェルが印に到達する前に死んだ場合。安全側＝隠さない側へ倒す）
    #[test]
    fn output_is_not_swallowed_when_the_sentinel_never_arrives() {
        let mut filter = StartupNoiseFilter::new();
        filter.feed("何かの出力\n".to_string(), true);

        assert_eq!(labels(filter.flush(true)), vec!["err:何かの出力\n"]);
    }

    /// コマンド自身が印と同じ文字列を出力しても、分割位置は動かない
    /// （**最初の1つ**で切るため、コマンド側から分割位置を操作できない）。
    #[test]
    fn the_command_cannot_move_the_split_by_printing_the_sentinel_itself() {
        let mut filter = StartupNoiseFilter::new();
        filter.feed(
            format!("{}\n", harness_tools::RUN_SHELL_OUTPUT_SENTINEL),
            false,
        );

        assert_eq!(
            labels(filter.feed(
                format!("{}\n", harness_tools::RUN_SHELL_OUTPUT_SENTINEL),
                false
            )),
            vec![format!(
                "out:{}\n",
                harness_tools::RUN_SHELL_OUTPUT_SENTINEL
            )],
            "2度目の印は本文として扱う（分割は最初の1回だけ）"
        );
    }
}
