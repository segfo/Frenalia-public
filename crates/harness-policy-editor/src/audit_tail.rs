//! 監査JSONL（`fs-audit.jsonl` / `net-audit.jsonl`）の**追記追従読み**。
//!
//! # なぜ一括読みでは足りないのか
//!
//! 既存の`harness policy learn`は収集が終わってから`read_to_string`で全文を一度に読む
//! （`crates/harness-cli/src/cli/policy_cmd.rs`）。収集器を起こして`sleep`するだけの
//! コマンドではそれで足りるが、記録モードは**ユーザーがコマンドを打っている最中に**
//! 隣のペインへアクセスログを積んでいく必要があるため、追記に追従して読めないといけない。
//!
//! 両ファイルともイベント単位の追記（`OpenOptions::append`）なので、
//! 「前回どこまで読んだか」をバイトオフセットで覚えておけば追従できる。
//!
//! # 途中まで書かれた行を食わない
//!
//! 追記は`write_all`1回だが、書き手（昇格した収集器）と読み手（このプロセス）は
//! 別プロセスなので、**改行までしか書かれていない瞬間**を読み得る。
//! [`AuditTail::poll`]は**最後の改行までしか消費しない**——末尾の未完結な断片は
//! オフセットを進めずに残し、次回のpollで完結してから読む。
//!
//! # ファイルがまだ無い・途中で消える
//!
//! 記録モードはファイルが作られる前から見張り始める（収集器がまだ最初のイベントを
//! 書いていない）。存在しないことは異常ではないので、`poll`は空を返すだけにする。
//! ただし**サイズが前回より縮んでいたら**（ファイルが作り直された）オフセットを0へ
//! 巻き戻す——縮んだファイルへ古いオフセットで`seek`すると、以後永久に何も読めなくなる。

use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// 1本のJSONLを追記追従で読む。
#[derive(Debug)]
pub struct AuditTail {
    path: PathBuf,
    /// 次に読み始めるバイトオフセット（＝最後に読み切った改行の直後）。
    offset: u64,
}

impl AuditTail {
    /// まだ存在しないパスを渡してよい（記録開始時点ではファイルが無いのが普通）。
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
    /// 返すのは生の行文字列（JSONとして解釈するのは呼び出し側の責務）。
    /// 空行は捨てる。ファイルが無い場合は空を返す。
    pub fn poll(&mut self) -> Vec<String> {
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
                    if !buf.ends_with(b"\n") {
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

    /// 完結した行のうち、`FsAuditEvent`として解釈できたものだけを返す。
    ///
    /// 解釈できない行（別スキーマのレコード——`net-audit.jsonl`は`kind=proxy`等の
    /// 別形式も同じファイルへ混在する）は黙って捨てる。**捨てた件数は返す**
    /// ——「1件も解釈できていない」と「本当に何も無かった」を呼び出し側が
    /// 区別できないと、無言失敗になるため（B-09）。
    pub fn poll_fs_events(&mut self) -> (Vec<harness_policy::FsAuditEvent>, usize) {
        let mut events = Vec::new();
        let mut skipped = 0usize;
        for line in self.poll() {
            match serde_json::from_str::<harness_policy::FsAuditEvent>(&line) {
                Ok(event) => events.push(event),
                Err(_) => skipped += 1,
            }
        }
        (events, skipped)
    }

    /// 完結した行のうちJSONとして読めたものを、**型を決めずに**返す（パス2の`net-audit.jsonl`用）。
    ///
    /// `net-audit.jsonl`にはProxy・Fake DNS・WFPの3種のレコードが混在し、キーの構成が違う
    /// （`host`と`remote_host`等）。ここで1つの型へ押し込むと、その差を吸収する規則が
    /// `harness_policy::normalize_net_audit`とこことの2箇所に生まれる——判定の正本は
    /// あちらに置き、こちらは行を運ぶだけにする。**読めなかった件数は返す**（B-09）。
    pub fn poll_json_values(&mut self) -> (Vec<serde_json::Value>, usize) {
        let mut events = Vec::new();
        let mut skipped = 0usize;
        for line in self.poll() {
            match serde_json::from_str::<serde_json::Value>(&line) {
                Ok(value) => events.push(value),
                Err(_) => skipped += 1,
            }
        }
        (events, skipped)
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

    /// 存在しないファイルは異常ではない（記録開始時点ではまだ作られていない）。
    #[test]
    fn a_missing_file_yields_nothing_instead_of_failing() {
        let dir = tempfile::tempdir().unwrap();
        let mut tail = AuditTail::new(dir.path().join("not-created-yet.jsonl"));

        assert!(tail.poll().is_empty());
    }

    /// 追記した分だけが返り、同じ行を2度返さない。
    #[test]
    fn only_newly_appended_lines_are_returned_each_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut tail = AuditTail::new(&path);

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
        let mut tail = AuditTail::new(&path);

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

    /// ファイルが作り直されて縮んだら先頭から読み直す（古いオフセットのまま
    /// `seek`し続けると永久に何も読めなくなる）。
    #[test]
    fn a_truncated_file_is_re_read_from_the_beginning() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut tail = AuditTail::new(&path);

        append(&path, "old-line-1\nold-line-2\n");
        assert_eq!(tail.poll().len(), 2);

        std::fs::write(&path, "fresh\n").unwrap();
        assert_eq!(tail.poll(), vec!["fresh".to_string()]);
    }

    #[test]
    fn blank_lines_are_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut tail = AuditTail::new(&path);

        append(&path, "a\n\n\nb\n");
        assert_eq!(tail.poll(), vec!["a".to_string(), "b".to_string()]);
    }

    /// `FsAuditEvent`として読めた行だけを返し、読めなかった件数も返す
    /// （`net-audit.jsonl`には別スキーマのレコードが混在する）。
    #[test]
    fn fs_events_are_parsed_and_foreign_records_are_counted_not_hidden() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut tail = AuditTail::new(&path);

        let event = harness_policy::FsAuditEvent::observed(
            harness_policy::FsAuditKind::Etw,
            "C:/work/Cargo.toml",
            harness_config::FsAccess::Read,
            true,
            "observed",
            1,
        );
        append(&path, &format!("{}\n", event.to_jsonl_line().unwrap()));
        append(&path, "{\"kind\":\"proxy\",\"host\":\"crates.io\"}\n");

        let (events, skipped) = tail.poll_fs_events();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].path.as_deref(), Some("C:/work/Cargo.toml"));
        assert!(events[0].allowed);
        assert_eq!(
            skipped, 1,
            "foreign records must be counted, not silently lost"
        );
    }
}
