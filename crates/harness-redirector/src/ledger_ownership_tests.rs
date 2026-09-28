//! 削除済みの集合と台帳への書込を、**`ledger.rs`の外から変える行が無いか**を数える。
//!
//! # なぜソースを走査するのか
//!
//! [BUG-171]・[BUG-172]は、フックが本当の操作の結果を見る前に台帳へ書き、削除済みの集合から
//! 印を外していた形だった。直した今、この2つを変えてよいのは`ledger.rs`の中の口だけである——
//! 本当の操作の結果を受けて書く口（`PendingRecord::settle`）と、台帳の項目を読み込む口
//! （起動時の再生・兄弟プロセスの追記の取り込み）。**集合を台帳の項目以外から変える口は無い。**
//!
//! その約束は可視性（`ledger.rs`の非公開）で守っている。**可視性は、誰かが`pub(crate)`へ戻せば
//! 黙って崩れる**ので、外から触る行が0本であることをここで数える。
//!
//! # この機構が守らないもの
//!
//! 読むのは`src`配下の`.rs`の本文だけで、下の名前を含む行を数えている。**別の名前で同じ集合を
//! 作り直す経路**（プロセス内に2つめの削除済みの集合を持つ等）は止められない。止められるのは
//! 「この集合・この書込に、`ledger.rs`の外から手を伸ばす行が増えたこと」までである。
//!
//! [BUG-171]: ../../../docs/bugs/BUG-171.md
//! [BUG-172]: ../../../docs/bugs/BUG-172.md

/// `ledger.rs`だけが使ってよい名前。
const OWNED_BY_LEDGER: &[&str] = &[
    "deleted_paths_state",
    "ledger_read_offset",
    "append_ledger_entry",
    "store::append_entry",
];

/// `src`配下の製品コード（テスト専用ファイルとコメント行を除く）から、`needle`を含む行を集める。
fn code_lines_containing(needle: &str) -> Vec<(String, usize, String)> {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&src)
        .expect("read src/")
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        if !name.ends_with(".rs") || name.ends_with("_tests.rs") || name == "test_support.rs" {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read a source file");
        for (i, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") || !line.contains(needle) {
                continue;
            }
            out.push((name.clone(), i + 1, line.trim().to_string()));
        }
    }
    out.sort();
    out
}

/// 削除済みの集合と台帳への書込に触る行は、`ledger.rs`の中にしか無い。
#[test]
fn only_the_ledger_module_changes_the_deleted_set_or_writes_the_ledger() {
    for needle in OWNED_BY_LEDGER {
        let outside: Vec<_> = code_lines_containing(needle)
            .into_iter()
            .filter(|(file, _, _)| file != "ledger.rs")
            .collect();
        assert!(
            outside.is_empty(),
            "`{needle}` must stay inside ledger.rs (the deleted set changes only from ledger \
             entries, and the ledger is written only after the real operation): {outside:#?}"
        );
    }
}

/// 歯: 数えている名前が`ledger.rs`に実在する（名前を変えたのに一覧を直さないと、上の試験は
/// 何も数えずに緑になる）。
#[test]
fn the_names_the_ownership_test_counts_exist_in_the_ledger_module() {
    for needle in ["deleted_paths_state", "store::append_entry"] {
        assert!(
            code_lines_containing(needle)
                .iter()
                .any(|(file, _, _)| file == "ledger.rs"),
            "`{needle}` is not in ledger.rs any more; update OWNED_BY_LEDGER"
        );
    }
}
