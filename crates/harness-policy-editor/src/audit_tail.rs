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
//! # 行を追う部分は`harness_term::line_tail`が持つ
//!
//! 途中まで書かれた行を食わない・ファイルがまだ無い／作り直されて縮んだ、の2つの罠への対処は
//! [`harness_term::line_tail::LineTail`]にある（書き手の収集器は昇格した別プロセスなので、
//! **改行までしか書かれていない瞬間**を読み得る）。TUIが預かる標準エラーの読み手も同じ罠を
//! 持つので、1つの実装を共有している（`docs/CODE-STRUCTURE-RULES.md`§5.0）。
//! ここが持つのは、行を監査レコードとして読む部分だけである。

use std::path::{Path, PathBuf};

use harness_term::line_tail::LineTail;

/// 1本のJSONLを追記追従で読む。
#[derive(Debug)]
pub struct AuditTail {
    lines: LineTail,
}

impl AuditTail {
    /// まだ存在しないパスを渡してよい（記録開始時点ではファイルが無いのが普通）。
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            lines: LineTail::new(path),
        }
    }

    pub fn path(&self) -> &Path {
        self.lines.path()
    }

    /// 前回の`poll`以降に追記された**完結した行**を返す。
    ///
    /// 返すのは生の行文字列（JSONとして解釈するのは呼び出し側の責務）。
    /// 空行は捨てる。ファイルが無い場合は空を返す。
    pub fn poll(&mut self) -> Vec<String> {
        self.lines.poll()
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

/// 行を追う部分の試験（途中の行・無いファイル・縮んだファイル・空行）は`harness_term::line_tail`が持つ。
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
