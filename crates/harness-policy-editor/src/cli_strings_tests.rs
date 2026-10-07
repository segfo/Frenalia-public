//! **ユーザーへ案内する綴りが、実在するフラグであること**の検算
//! （[BUG-122](../../../docs/bugs/BUG-122.md) 案C）。
//!
//! # 何を守るテストか
//!
//! フラグを1本廃止したとき、消す場所は**3層ある**——clapの定義・実行時に出す案内文・
//! docコメント。定義だけ消すと、**製品が自分で出した案内どおりに打つと clap がエラーにする**
//! という状態になる。拒否を見た直後の「では何を許せばよいか」で次の手が止まるので、
//! 案内文が効かないのは表示の問題ではなく機能の問題である
//! （`B-32`＝ユーザーへ出す文言そのものを実装の一部として読む）。
//!
//! 実際に`--generalize`（D-62で廃止）が3箇所に取り残されていた。
//!
//! # 何を見ているか
//!
//! `src/`配下の**コメント行以外**に現れる`--xxx`を全部拾い、
//! エディタの[`Cli`]（ルート・サブコマンド・入れ子すべて）に実在するかを確かめる。
//!
//! **コメント行は対象外。** 廃止した綴りを経緯として書き残すのは正当で、
//! そこまで禁じると「なぜ消したか」を書けなくなる。
//!
//! # 限界（**同じ場所で言う**）
//!
//! - **静的な文字列しか拾えない。** `format!("--{name}")`のように動的に組み立てた綴りは
//!   取りこぼす。
//! - **他プログラムのフラグを案内し始めたら誤検知する。** 現状このクレートの文字列に出るのは
//!   自分のフラグだけなので許容リストを置いていない。必要になったら**理由付きで**足すこと。

use std::collections::BTreeSet;

use clap::CommandFactory;

use super::Cli;

/// エディタのCLIに実在するlong名（ルート・サブコマンド・入れ子を全部集める）。
fn all_known_longs() -> BTreeSet<String> {
    fn walk(cmd: &clap::Command, out: &mut BTreeSet<String>) {
        for a in cmd.get_arguments() {
            if let Some(l) = a.get_long() {
                out.insert(l.to_string());
            }
            for l in a.get_all_aliases().unwrap_or_default() {
                out.insert(l.to_string());
            }
        }
        for sub in cmd.get_subcommands() {
            walk(sub, out);
        }
    }
    let mut out = BTreeSet::new();
    walk(&Cli::command(), &mut out);
    out
}

/// `src/`配下の**コメント以外**の行から`--xxx`を拾う。戻り値は`(綴り, file:line)`。
fn spelled_flags_in_sources() -> Vec<(String, String)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            // テストの中の綴りは対象外——**廃止したフラグが正しく消えたことを測るテスト**が
            // その綴りを書けなくなる（自分で自分を縛る形になる）。
            if !name.ends_with(".rs") || name.ends_with("_tests.rs") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            for (i, line) in text.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                for spelled in extract_flags(line) {
                    out.push((spelled, format!("{}:{}", path.display(), i + 1)));
                }
            }
        }
    }
    out
}

/// 1行から`--xxx`形式の綴りを拾う（`---`のような区切りは拾わない）。
fn extract_flags(line: &str) -> Vec<String> {
    let bytes: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == '-' && bytes[i + 1] == '-' && bytes[i + 2].is_ascii_lowercase() {
            let start = i + 2;
            let mut end = start;
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == '-') {
                end += 1;
            }
            // 末尾のハイフンは綴りの一部ではない（`--foo-`のような行末の折り返し）。
            let name: String = bytes[start..end].iter().collect();
            let name = name.trim_end_matches('-').to_string();
            if !name.is_empty() {
                out.push(name);
            }
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

/// **[BUG-122] 案C。** 案内文に出る綴りは、実在するフラグであること。
#[test]
fn every_flag_spelling_we_print_actually_exists() {
    let known = all_known_longs();
    let missing: Vec<(String, String)> = spelled_flags_in_sources()
        .into_iter()
        .filter(|(name, _)| !known.contains(name))
        .collect();

    assert!(
        missing.is_empty(),
        "実在しないフラグを案内している（打つと clap がエラーにする）。\n\
         フラグを廃止したら **clap定義・実行時の案内文・docコメント の3層**を数えること（BUG-122）。\n\
         実在するのは: {known:?}\n\
         見つかったもの: {missing:#?}"
    );
}

/// 走査そのものが空振りしていないことの検算。
///
/// **0件マッチのまま緑になるのが、この種のテストで最も起きる壊れ方である**——
/// ディレクトリの綴りを間違えても、抽出の正規表現を壊しても、`missing`は空になり緑になる。
#[test]
fn the_scan_actually_finds_flag_spellings() {
    let spelled = spelled_flags_in_sources();
    assert!(
        spelled.len() >= 10,
        "案内文の走査が空振りしている（見つかったのは{}件）",
        spelled.len()
    );
    assert!(
        !all_known_longs().is_empty(),
        "clap定義の走査が空振りしている"
    );
}

#[test]
fn extract_flags_ignores_separators_and_takes_the_whole_name() {
    assert_eq!(extract_flags("---"), Vec::<String>::new());
    assert_eq!(
        extract_flags("see --require-sandbox now"),
        vec!["require-sandbox"]
    );
    assert_eq!(extract_flags("--a --b2"), vec!["a", "b2"]);
}

/// [決定68(2)] **`record-net`は`--domain`を受け付けない**（パス2は常に入口のドメインから始める）。旧い綴りで打つと
/// clap がエラーにする（禁止側）。`--domain`を外した形は通る（許可側——サブコマンドそのものが壊れていない対）。
#[test]
fn record_net_has_no_domain_flag() {
    use clap::Parser;

    let with_domain = Cli::try_parse_from([
        "harness-policy-editor",
        "record-net",
        "--domain",
        "cargo",
        "--",
        "cargo build",
    ]);
    let error = with_domain.expect_err("record-net が --domain を受け付けた");
    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::UnknownArgument,
        "{error}"
    );

    let without = Cli::try_parse_from(["harness-policy-editor", "record-net", "--", "cargo build"])
        .expect("--domain を外した record-net が通らない");
    assert!(
        matches!(without.command, Some(super::Command::RecordNet { .. })),
        "{:?}",
        without.command
    );
}
