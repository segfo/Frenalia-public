//! 追記されていくテキストファイルの**追記追従読み**（前回どこまで読んだかをバイトオフセットで覚える）。
//!
//! 使うのは2か所ある——ポリシーエディタの監査JSONLの読み手（`harness-policy-editor`の`AuditTail`）と、
//! 画面を握っている間に預かった標準エラーの読み手（[`crate::stderr_capture`]）。どちらも
//! 「別の書き手が追記しているファイルを、画面を描きながら少しずつ読む」ので、同じ罠（下の2つ）を持つ。
//! **片方だけ直ると、もう片方だけが途中の行を食う**ので、1つの実装を共有する
//! （`docs/CODE-STRUCTURE-RULES.md`§5.0）。ここに置くのは、両方が依存しているクレートがここだからである。
//!
//! # 途中まで書かれた行を食わない
//!
//! 書き手と読み手は別のスレッド・別のプロセスなので、**改行までしか書かれていない瞬間**を読み得る。
//! [`LineTail::poll`]は**最後の改行までしか消費しない**——末尾の未完結な断片は
//! オフセットを進めずに残し、次回のpollで完結してから読む。
//!
//! # ファイルがまだ無い・途中で消える
//!
//! 見張りはファイルが作られる前から始まることがある。存在しないことは異常ではないので、
//! `poll`は空を返すだけにする。ただし**サイズが前回より縮んでいたら**（ファイルが作り直された）
//! オフセットを0へ巻き戻す——縮んだファイルへ古いオフセットで`seek`すると、以後永久に何も読めなくなる。

use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// 1本のファイルを追記追従で読む。
#[derive(Debug)]
pub struct LineTail {
    path: PathBuf,
    /// 次に読み始めるバイトオフセット（＝最後に読み切った改行の直後）。
    offset: u64,
}

impl LineTail {
    /// まだ存在しないパスを渡してよい（見張り始めた時点ではファイルが無いのが普通）。
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            offset: 0,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 前回の`poll`以降に追記された**完結した行**を返す。
    ///
    /// 返すのは生の行文字列（解釈は呼び出し側の責務）。空行は捨てる。ファイルが無い場合は空を返す。
    pub fn poll(&mut self) -> Vec<String> {
        self.read(false)
    }

    /// [`Self::poll`]と同じだが、**改行で終わっていない最後の断片も1行として返す**。
    ///
    /// 書き手がもう書かないと分かっているとき（預かりを終える直前）にだけ使う。
    /// 書き手が生きている間に使うと、書きかけの行を2つに割って返すことになる。
    pub fn drain(&mut self) -> Vec<String> {
        self.read(true)
    }

    fn read(&mut self, take_unterminated: bool) -> Vec<String> {
        let Ok(file) = std::fs::File::open(&self.path) else {
            return Vec::new();
        };
        let Ok(metadata) = file.metadata() else {
            return Vec::new();
        };
        let len = metadata.len();

        // ファイルが作り直されて縮んだ場合、古いオフセットのままだと`seek`が
        // EOFの先を指し続けて二度と読めなくなる。先頭から読み直す。
        if len < self.offset {
            self.offset = 0;
        }
        if len == self.offset {
            return Vec::new();
        }

        let mut reader = BufReader::new(file);
        if reader.seek(SeekFrom::Start(self.offset)).is_err() {
            return Vec::new();
        }

        let mut lines = Vec::new();
        let mut consumed = 0u64;
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    // **改行で終わっていない＝まだ書き終わっていない行**。
                    // オフセットを進めず、次回のpollで最初から読み直す。
                    if !buf.ends_with(b"\n") && !take_unterminated {
                        break;
                    }
                    consumed += n as u64;
                    let line = String::from_utf8_lossy(&buf);
                    let line = line.trim_end_matches(['\n', '\r']);
                    if !line.is_empty() {
                        lines.push(line.to_string());
                    }
                }
                Err(_) => break,
            }
        }
        self.offset += consumed;
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn append(path: &Path, text: &str) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        f.write_all(text.as_bytes()).unwrap();
        f.flush().unwrap();
    }

    /// 存在しないファイルは異常ではない（見張り始めた時点ではまだ作られていない）。
    #[test]
    fn a_missing_file_yields_nothing_instead_of_failing() {
        let dir = tempfile::tempdir().unwrap();
        let mut tail = LineTail::new(dir.path().join("not-created-yet.jsonl"));

        assert!(tail.poll().is_empty());
    }

    /// 追記した分だけが返り、同じ行を2度返さない。
    #[test]
    fn only_newly_appended_lines_are_returned_each_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut tail = LineTail::new(&path);

        append(&path, "first\n");
        assert_eq!(tail.poll(), vec!["first".to_string()]);

        // 追記が無ければ空。
        assert!(tail.poll().is_empty());

        append(&path, "second\nthird\n");
        assert_eq!(tail.poll(), vec!["second".to_string(), "third".to_string()]);
        assert!(tail.poll().is_empty());
    }

    /// **途中まで書かれた行は消費しない。** 別プロセスの書き手が改行を書く前に
    /// 読んでしまっても、壊れたJSONを掴まず次回まで待つ。
    #[test]
    fn a_partially_written_line_is_not_consumed_until_it_is_complete() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut tail = LineTail::new(&path);

        append(&path, "complete\n");
        append(&path, "partial-wi");
        assert_eq!(
            tail.poll(),
            vec!["complete".to_string()],
            "the unterminated tail must not be returned"
        );

        // 書き手が残りを書き終えたら、行全体が1回だけ返る。
        append(&path, "thout-newline-yet\n");
        assert_eq!(tail.poll(), vec!["partial-without-newline-yet".to_string()]);
    }

    /// **書き手が居なくなった後は、改行の無い最後の断片も捨てない**（預かりを終えるときの読み方）。
    /// `poll`のままだと、`eprint!`のように改行で終わらない最後の書込が黙って消える（B-10）。
    #[test]
    fn draining_also_returns_the_unterminated_last_fragment_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stderr.log");
        let mut tail = LineTail::new(&path);

        append(&path, "complete\nno-newline-at-the-end");
        assert_eq!(tail.poll(), vec!["complete".to_string()]);
        assert_eq!(tail.drain(), vec!["no-newline-at-the-end".to_string()]);
        assert!(tail.drain().is_empty(), "同じ断片を2度返さない");
    }

    /// ファイルが作り直されて縮んだら先頭から読み直す（古いオフセットのまま
    /// `seek`し続けると永久に何も読めなくなる）。
    #[test]
    fn a_truncated_file_is_re_read_from_the_beginning() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut tail = LineTail::new(&path);

        append(&path, "old-line-1\nold-line-2\n");
        assert_eq!(tail.poll().len(), 2);

        std::fs::write(&path, "fresh\n").unwrap();
        assert_eq!(tail.poll(), vec!["fresh".to_string()]);
    }

    #[test]
    fn blank_lines_are_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut tail = LineTail::new(&path);

        append(&path, "a\n\n\nb\n");
        assert_eq!(tail.poll(), vec!["a".to_string(), "b".to_string()]);
    }
}
