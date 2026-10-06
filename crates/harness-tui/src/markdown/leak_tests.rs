//! codewandler（Markdownの解析器・描画部品。急場しのぎの依存）の名前が、決めた場所の外に出ていないかを数える試験。
//!
//! # 何のためにあるのか
//!
//! codewandlerはユーザーが「急場しのぎ」と位置づけた依存で、いずれ別の実装へ差し替える（計画書§1.2・§1.6）。
//! 使用側（`crate::ui`・`crate::app`）がcodewandlerの型や関数を1つでも名指しすると、差し替えのときに使用側まで
//! 直すことになり、`markdown/codewandler/`を消しただけでは済まなくなる。だから名前の出てよい場所を決めて、
//! その外に出たら落とす（`ui::border_tests::every_overlay_and_wrapped_text_goes_through_harness_term`と同じ、
//! ソースを読んで数える形）。
//!
//! | 名前 | 出てよい場所 |
//! |---|---|
//! | `markdown_stream`・`markdown_ratatui`（クレートの名前） | `src/markdown/codewandler/`の中だけ |
//! | `codewandler`（大文字小文字を問わない。Adapterのモジュール名・型名・文中の言及） | 上に加えて`src/markdown/mod.rs`（実装を選ぶ唯一の場所で、Adapterのモジュールを宣言して選ぶため） |
//!
//! 試験のファイルも数える（試験が名指ししていても、ディレクトリを消すと壊れる）。数えないのはこのファイルだけ
//! ——名前を探す文字列そのものを持つため。
//!
//! # 限界
//!
//! - 文字列を数えるだけなので、別名（`use … as …`）を`markdown/mod.rs`で付けて外へ出す形は止められない。
//!   使用側へ出す名前は[`super::MarkdownView`]と[`super::Rendered`]（とその中の[`super::LinkSpan`]）だけ、という形を
//!   レビューで保つ。

use std::path::{Path, PathBuf};

/// クレートの名前（`src/markdown/codewandler/`の外には書かない）。
const CRATE_NAMES: [&str; 2] = ["markdown_stream", "markdown_ratatui"];
/// Adapterの名前（`src/markdown/codewandler/`と`src/markdown/mod.rs`の外には書かない）。小文字で比べる。
const ADAPTER_NAME: &str = "codewandler";

/// `src`の下の`.rs`を全部集める。
fn rust_files(src: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![src.to_path_buf()];
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            pending.extend(
                std::fs::read_dir(&path)
                    .expect("read_dir")
                    .map(|entry| entry.expect("entry").path()),
            );
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
    found
}

#[test]
fn codewandler_names_stay_inside_the_adapter_and_the_facade() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let adapter_dir = src.join("markdown").join("codewandler");
    let facade = src.join("markdown").join("mod.rs");
    let this_file = src.join("markdown").join("leak_tests.rs");
    assert!(
        facade.is_file() && this_file.is_file(),
        "数える場所の前提が崩れた（{}）",
        src.display()
    );

    let files = rust_files(&src);
    let mut offenders = Vec::new();
    let mut counted = 0;
    for path in &files {
        if path.starts_with(&adapter_dir) || *path == this_file {
            continue;
        }
        counted += 1;
        let source = std::fs::read_to_string(path)
            .expect("read")
            .to_ascii_lowercase();
        let mut names: Vec<&str> = CRATE_NAMES.to_vec();
        if *path != facade {
            names.push(ADAPTER_NAME);
        }
        for name in names {
            let count = source.matches(name).count();
            if count > 0 {
                offenders.push(format!("{}: {name} ×{count}", path.display()));
            }
        }
    }
    // 1つも読めていないのに緑になる形を止める（`harness-tui`の`src`には数十のファイルがある）。
    assert!(
        counted >= 30,
        "数えたファイルが{counted}件しか無い（集め方が壊れている）"
    );
    assert!(
        offenders.is_empty(),
        "codewandlerの名前が、Adapter（src/markdown/codewandler/）と実装を選ぶ場所（src/markdown/mod.rs）の外にある:\n{}",
        offenders.join("\n")
    );
}
