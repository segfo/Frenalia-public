//! CLIの**形**そのものに掛ける検算（[BUG-120](../../../../docs/bugs/BUG-120.md) 案E）。
//!
//! # 何を守るテストか
//!
//! **ルート引数とサブコマンド引数に同じ綴りがあると、置く位置を間違えても clap は落ちない。**
//! サブコマンドの前にルート引数を置くのは clap の正しい構文なので、綴りとしては妥当であり、
//! **綴りが違えば出る終了コード2が、位置が違うだけのときは出ない。**
//!
//! `--dangerously-allow` は実際にその形をしていた——ルート側は「`--permission-mode accept-all`と
//! ワイルドカード`--allow`の解禁」、`apply`側は「ワークスペース外への実FS適用の解禁」で、
//! **意味が別なのに綴りが同じ**。`harness --dangerously-allow apply` は受理されるが、
//! `apply`側の値は`false`のままである。
//!
//! # このテストの立場
//!
//! **衝突そのものを禁止しない。** 禁止すると`--workspace`のように「同じ意味で両階層にある」
//! 正当な形まで巻き添えになる。代わりに**宣言を強制する**——衝突を作るなら
//! [`DECLARED_COLLISIONS`]へ理由付きで載せること。載っていない衝突が生まれたら落ちる。
//!
//! **`--dangerously-allow`が下の表に載っていることは「解決済み」を意味しない。**
//! 位置を間違えたときに無言で無効になる問題は
//! `startup::parse_args`の fail-fast が受け持っている（同じくBUG-120）。
//! ここが守るのは「**新しい衝突が黙って増えないこと**」だけである。

use std::collections::BTreeSet;

use clap::{CommandFactory, Parser};

use super::Cli;

/// 意図的に許している衝突。**足すときは必ず理由を書くこと。**
///
/// `(サブコマンドのパス, long名, なぜ許すか)`。
const DECLARED_COLLISIONS: &[(&str, &str, &str)] = &[
    (
        "apply",
        "dangerously-allow",
        "ルート側（承認モードの解禁）と apply 側（ワークスペース外への実FS適用の解禁）は\
         意味が別。改名するとルート側の綴りが `plans/DESIGN.md` §非対話モード・E2E・\
         複数の解説文書から名指しされているため正本の改訂とセットになる（BUG-120 案D）。\
         位置違いの無言無効は `startup::parse_args` の fail-fast が受け持つ。",
    ),
    // `--output-format` は**両階層で意味が同じ**（出力形式）。`--dangerously-allow` と違って
    // 「意味の違う2つのゲートが1つの値になる」形ではないので、**倒れる向きが危険側へ反転しない**。
    //
    // ただし位置違いが無害というわけではない——`harness --output-format json changes` は
    // サブコマンド側の既定（text）で出る。**機構で直すなら「ルート側を global にして
    // サブコマンド側の定義を消す」だが、9つのハンドラに触る別作業**なので、
    // ここでは宣言に留める（BUG-120 の「横展開で見つけたもの」節）。
    (
        "changes",
        "output-format",
        "両階層で同じ意味（出力形式）。下記の9件は同一の理由",
    ),
    ("apply", "output-format", "同上"),
    ("cow audit", "output-format", "同上"),
    ("net audit", "output-format", "同上"),
    ("memory list", "output-format", "同上"),
    ("policy suggest", "output-format", "同上"),
    ("policy audit", "output-format", "同上"),
    ("policy learn", "output-format", "同上"),
    ("mcp list", "output-format", "同上"),
];

/// clapが全コマンドへ自動で足すもの。衝突として数えない。
const CLAP_BUILTINS: &[&str] = &["help", "version"];

fn long_names(cmd: &clap::Command) -> BTreeSet<String> {
    cmd.get_arguments()
        .filter_map(|a| a.get_long())
        .filter(|l| !CLAP_BUILTINS.contains(l))
        .map(str::to_string)
        .collect()
}

/// サブコマンドを再帰的に辿り、`(パス, 引数のlong名)`を全部集める。
///
/// **入れ子まで降りる。** `harness fs grant-traverse` のように2段のものがあり、
/// 1段目だけ見ると取りこぼす。
fn all_subcommand_args(cmd: &clap::Command, prefix: &str, out: &mut Vec<(String, String)>) {
    for sub in cmd.get_subcommands() {
        let name = sub.get_name();
        if CLAP_BUILTINS.contains(&name) {
            continue;
        }
        let path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix} {name}")
        };
        for long in long_names(sub) {
            out.push((path.clone(), long));
        }
        all_subcommand_args(sub, &path, out);
    }
}

/// **[BUG-120] 案E。** ルート引数とサブコマンド引数のlong名が交差していたら、
/// [`DECLARED_COLLISIONS`]に載っていること。
#[test]
fn root_and_subcommand_flag_spellings_do_not_collide_undeclared() {
    let cmd = Cli::command();
    let root = long_names(&cmd);

    let mut subs = Vec::new();
    all_subcommand_args(&cmd, "", &mut subs);

    let declared: BTreeSet<(&str, &str)> = DECLARED_COLLISIONS
        .iter()
        .map(|(path, long, _)| (*path, *long))
        .collect();

    let undeclared: Vec<(String, String)> = subs
        .into_iter()
        .filter(|(_, long)| root.contains(long))
        .filter(|(path, long)| !declared.contains(&(path.as_str(), long.as_str())))
        .collect();

    assert!(
        undeclared.is_empty(),
        "ルート引数と同じ綴りのサブコマンド引数が宣言なしで増えている。\n\
         位置を間違えても clap は落ちないので、意味が別なら無言で無効になる（BUG-120）。\n\
         意図的なら crates/harness-cli/src/cli/cli_structure_tests.rs の \
         DECLARED_COLLISIONS へ理由付きで足すこと。\n\
         見つかったもの: {undeclared:?}"
    );
}

/// **[BUG-120] 案A・禁止側。** ルート位置に置いた`--dangerously-allow`をサブコマンドと
/// 併せて打ったら、無言で無視せずに理由を出して落ちること。
///
/// 直す前は clap も harness も何も言わず、`apply`側の値は`false`のままだった。
/// ユーザーから見えるのは「`--dangerously-allow`を付けたのに拒否された」だけで、
/// **付けた場所が違うという情報がどこにも出なかった。**
#[test]
fn a_root_dangerously_allow_placed_before_a_subcommand_is_refused() {
    let cli = Cli::try_parse_from(["harness", "--dangerously-allow", "apply"])
        .expect("clap は受理する（綴りとしては妥当なので、落とすのは harness の仕事）");
    let reason = super::misplaced_root_dangerously_allow(&cli)
        .expect("サブコマンド経路にルート側フラグが立っていたら理由を返す");
    assert!(
        reason.contains("--dangerously-allow"),
        "どのフラグの話か分かること: {reason}"
    );
}

/// **[BUG-120] 案A・許可側（対）。** 正しい位置なら何も言わないこと。
///
/// **この対が無いと「常に落ちる」実装でも禁止側が通る**（`B-35`）。
#[test]
fn a_correctly_placed_dangerously_allow_is_not_refused() {
    // (a) サブコマンド側に置いた形。これが `apply` の正しい打ち方。
    let cli = Cli::try_parse_from(["harness", "apply", "--dangerously-allow"]).expect("parse");
    assert!(super::misplaced_root_dangerously_allow(&cli).is_none());

    // (b) サブコマンド無し（エージェント実行）。ルート側フラグ本来の使い道。
    let cli = Cli::try_parse_from(["harness", "--dangerously-allow", "-p", "hi"]).expect("parse");
    assert!(super::misplaced_root_dangerously_allow(&cli).is_none());

    // (c) どちらも付けていない普通のサブコマンド実行。
    let cli = Cli::try_parse_from(["harness", "apply"]).expect("parse");
    assert!(super::misplaced_root_dangerously_allow(&cli).is_none());
}

/// **宣言表そのものが腐らないこと。** 衝突を解消したのに表から消し忘れると、
/// 「まだ衝突している」と読める死んだ記述が残る（`B-13`＝同じ事実の正本を2つ持たない）。
#[test]
fn every_declared_collision_still_exists() {
    let cmd = Cli::command();
    let root = long_names(&cmd);
    let mut subs = Vec::new();
    all_subcommand_args(&cmd, "", &mut subs);
    let actual: BTreeSet<(String, String)> = subs.into_iter().collect();

    for (path, long, _) in DECLARED_COLLISIONS {
        assert!(
            root.contains(*long),
            "DECLARED_COLLISIONS の {long:?} はルート引数に存在しない（解消済みなら表から消すこと）"
        );
        assert!(
            actual.contains(&(path.to_string(), long.to_string())),
            "DECLARED_COLLISIONS の ({path:?}, {long:?}) は実在しない（解消済みなら表から消すこと）"
        );
    }
}
