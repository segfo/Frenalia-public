//! **環境変数の名前だけで「テスト専用か、本番で効くか」が分かること**を、機構で固定する。
//!
//! # 何を守るテストか
//!
//! `HARNESS_TEST_DUAL_ACE_NODES` はテストが撒くファイル数を変えるだけの目盛りで、
//! `HARNESS_ALLOW_USER_WRITABLE_ELEVATED_HELPERS` は昇格ヘルパーの検証を丸ごと外す
//! セキュリティの逃がし弁である。**かつてはどちらも `HARNESS_` で始まるだけ**だったので、
//! コードや文書の中で出会ったとき、読み手はどちらなのかを名前から判定できなかった。
//!
//! 規約は [`plans/DESIGN-CLI-OPTIONS.md`](../../../plans/DESIGN-CLI-OPTIONS.md) §9 の
//! **D-86** が持つ——「テストからしか読まれない環境変数は `HARNESS_TEST_` で始める。
//! 本番の製品コードが読む環境変数は `HARNESS_TEST_` で始めてはならない」。
//! 本テストはその規約の**実行時の検問**であり、[`PRODUCTION_ENV_VARS`] が
//! **「どれが本番か」の正本**である（設計書には規則だけを書き、一覧を複製しない）。
//!
//! # なぜこのテストがここにあるのか
//!
//! `harness-cli` は誰にも依存されない終端クレートで、`tests/` には
//! [`stdout_contract.rs`](stdout_contract.rs)・[`mcp_namespace_drift.rs`](mcp_namespace_drift.rs)
//! という**リポジトリ全体の契約を固定するテスト**の前例がある。本テストも同じ性質で、
//! **管理者権限も実機も要らず、`#[ignore]` も1件も付いていない**——素の
//! `cargo test --workspace` で走ることが成果物である。
//!
//! # 走査の対象（`env::var("...")` だけを探すのでは足りない）
//!
//! 環境変数の読み手は3つの形を取る。1つだけ見ると取りこぼす。
//!
//! | 形 | 実例 |
//! |---|---|
//! | 文字列リテラル全体が名前 | `env::var("HARNESS_TEST_DUAL_ACE_NODES")` |
//! | 定数を経由する | `pub const ALLOW_USER_WRITABLE_HELPERS_ENV: &str = "HARNESS_ALLOW_..."`（呼び出し側にリテラルが無い） |
//! | 埋め込みスクリプト中の参照 | `$env:HARNESS_PROBE_DIR`・`${env:HARNESS_TEST_MCP_HTTP_TOKEN}`・`Remove-Item Env:HARNESS_RUN_SHELL_COMMAND` |
//!
//! # ここで守れない4つ（黙って落とすと網羅に見えるので、理由を書き残す）
//!
//! | 守れないもの | 理由 |
//! |---|---|
//! | **本番一覧へ足してしまえば、テストからしか読まれない変数も通る** | 名前から用途を機械で判定することはできない。だから一覧への追加は人の判断であり、**その判断は一覧の1行コメントに残す**という形で担保する |
//! | **`#[cfg(test)]` の内側かどうかは見ていない** | ファイルのパスと名前だけで判定する。テキストで `cfg` を追うと、`wfp.rs` のような「1関数だけ `#[cfg(test)]` で、その後ろに本番コードが続く」形を誤判定する |
//! | **接頭辞が1文字も無い名前は検査A・Bに映らない** | 名前で群を見分ける規約は、名前が群を名乗っていることが前提である。ここは検査C（`env::var` の呼び出し口を全数見る）が受けるが、埋め込みスクリプト中の `$env:FOO` は受けない——テスト用の擬似スクリプトに `$env:NOPE` の類が多数あり、選り分けが人の判断になるため |
//! | **`plans/` 配下は走査しない** | ワークスペースのビルド対象外。スパイク用の `N3_PIPE`・`T4_FILES` はこの検問に掛からない |
//! | **この検問自身のソースは走査から外している** | 検出したい形を例として書いているファイルなので、含めると自分のフィクスチャと doc コメントを違反として数える（[`THIS_FILE`]）。代わりに拾い方の正しさを末尾の検算テスト3本が固定する |

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// **本番の製品コードが読む環境変数の一覧（この規約の正本）。**
///
/// ここへ足すことは「これはテスト専用ではない」と宣言することなので、**用途を1行書く**。
/// 書けないなら、それはテスト専用であって `HARNESS_TEST_` を付けるべきものである。
const PRODUCTION_ENV_VARS: &[(&str, &str)] = &[
    (
        "HARNESS_ALLOW_USER_WRITABLE_ELEVATED_HELPERS",
        "昇格ヘルパーの置き場所の検証（T-21 / D-44）を警告付きで素通しする逃がし弁",
    ),
    (
        "HARNESS_GRANT_AUDIT",
        "ACE付与の自己検証の強さ（off / report / strict）",
    ),
    (
        "HARNESS_TIER3_CIFS_WORKSPACE",
        "Tier3のworkspace共有方式を旧方式へ戻す逃がし弁",
    ),
    (
        "HARNESS_COW_WORKSPACE",
        "起動側 → Redirector DLL: 捕捉するワークスペースの位置",
    ),
    (
        "HARNESS_COW_DIFF_LAYER",
        "起動側 → Redirector DLL: 書込を落とす差分層の位置",
    ),
    (
        "HARNESS_COW_EXT_ROOTS",
        "起動側 → Redirector DLL: ワークスペース外で捕捉する根の一覧",
    ),
    (
        "HARNESS_COW_READY_HANDLE",
        "起動側 → Redirector DLL: 準備完了を知らせるイベントのハンドル",
    ),
    (
        "HARNESS_LAZY_BROKER_PIPE",
        "起動側 → Redirector DLL: 拒否されたopenを問い合わせるfault受付パイプの名前（D-88）",
    ),
    (
        "HARNESS_TIER2A_LAZY_ACE",
        "Lazy ACE fault-inレーンを**切る**逃がし弁（D-88。既定は有効。注入と相性の悪い場面で従来の全walk待機へ戻す）",
    ),
    (
        "HARNESS_REDIRECTOR_NO_INJECT",
        "Redirector DLLを注入しないプロセス名の一覧（`;`区切り。相性の悪いツールの緊急回避と、フォールバックの検証に使う）",
    ),
    (
        "HARNESS_PROBE_DIR",
        "preflight → プローブ子プロセス: 実FS I/Oを試す作業ディレクトリ",
    ),
    (
        "HARNESS_CONTROL_DIR",
        "preflight → プローブ子プロセス: 書込が拒否されるべき対照ディレクトリ",
    ),
    (
        "HARNESS_RUN_SHELL_COMMAND",
        "harness → 子シェル: 実行するコマンド本文（argvに乗せない）",
    ),
    (
        "HARNESS_FAKE_DNS_ADDR",
        "harness → 子プロセス: 協調用の擬似DNSの待受アドレス",
    ),
    (
        "HARNESS_WIRE_LOG",
        "観測: プロバイダ送受信の全文をJSONLで指定パスへ落とす",
    ),
    (
        "HARNESS_PREFLIGHT_TIMING",
        "観測: preflightのACL付与の計時を出す（挙動は変えない）",
    ),
    (
        "HARNESS_KEY_DEBUG",
        "観測: TUIが受け取ったキー入力を出す（挙動は変えない）",
    ),
    (
        "HARNESS_REDIRECTOR_BUILD_ID",
        "ビルド時のみ。build.rsが `cargo:rustc-env` で設定し `env!()` が読む（実行時のenvではない）",
    ),
];

/// harness が定めたものではない、外から与えられる環境変数。
///
/// 検査Cで「接頭辞の無い名前を新しく作っていないか」を見るときの除外集合であり、
/// **harness の規約が及ばないもの**だけを載せる。
const EXTERNAL_ENV_VARS: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_BASE_URL",
    "APPDATA",
    "CARGO_MANIFEST_DIR",
    "COMPUTERNAME",
    "EDITOR",
    "GIT_AUTHOR_EMAIL",
    "GIT_AUTHOR_NAME",
    "HOME",
    "LM_API_TOKEN",
    "LOCALAPPDATA",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "ProgramData",
    "ProgramFiles",
    "SystemRoot",
    "TERM_PROGRAM",
    "USERNAME",
    "USERPROFILE",
    "VISUAL",
    "windir",
];

const TEST_PREFIX: &str = "HARNESS_TEST_";

/// **この検問自身のソース。** 走査から外す。
///
/// このファイルは検出したい形（リテラル全体・`$env:`・`env::var("...")`）を**例として
/// 書いている**ので、走査に含めると自分のフィクスチャと doc コメントを違反として数える。
/// 外す代わりに、拾い方の正しさは末尾の検算テスト3本が固定する。
const THIS_FILE: &str = "crates/harness-cli/tests/env_var_naming.rs";

// ---------------------------------------------------------------------------
// 走査
// ---------------------------------------------------------------------------

/// `CARGO_MANIFEST_DIR` から上へ辿り、`[workspace]` を持つ `Cargo.toml` のあるディレクトリを返す。
///
/// 親を固定段数で辿らないのは、このテストがどの深さに居ても効くようにするため
/// （`harness-build-id` の `workspace_root` と同じ方法。あちらは private かつビルド依存
/// クレートなので、`pub` にして引くより3行書く方が安い）。
fn workspace_root() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        if let Ok(text) = std::fs::read_to_string(dir.join("Cargo.toml")) {
            if text.contains("[workspace]") {
                return dir;
            }
        }
        assert!(
            dir.pop(),
            "walked up to the filesystem root without finding a Cargo.toml containing [workspace]"
        );
    }
}

/// `crates/` 配下の `.rs` を (ワークスペースからの相対パス, 中身) で集める。
fn rust_sources() -> Vec<(String, String)> {
    let root = workspace_root();
    let mut out = Vec::new();
    collect(&root.join("crates"), &root, &mut out);
    assert!(
        out.len() > 100,
        "expected to find the whole crates/ tree, found only {} files",
        out.len()
    );
    let before = out.len();
    out.retain(|(rel, _)| rel != THIS_FILE);
    assert_eq!(
        out.len(),
        before - 1,
        "THIS_FILE の綴りが実際のパスと合っていない（走査から外れていない）: {THIS_FILE}"
    );
    out
}

fn collect(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // ビルド生成物は走査しない（同じリテラルの写しが大量に出る）。
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            collect(&path, root, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            if let Ok(text) = std::fs::read_to_string(&path) {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, text));
            }
        }
    }
}

/// **テスト側のファイルか。** パスと名前だけで判定する（`#[cfg(test)]` は追わない。
/// 理由はモジュールdocの「ここで守れない4つ」）。
///
/// `*_tests.rs` という命名は [`docs/CODE-STRUCTURE-RULES.md`](../../../docs/CODE-STRUCTURE-RULES.md)
/// 規則1が既に定めている。
fn is_test_side(rel: &str) -> bool {
    rel.split('/')
        .any(|c| c == "tests" || c == "examples" || c == "benches")
        || rel.rsplit('/').next().is_some_and(|f| f.ends_with("_tests.rs"))
}

/// テキストから **環境変数として使われている** `HARNESS_*` を拾う。
///
/// 拾うのは次の2形だけ——(a) 文字列リテラル**全体**が名前、(b) 直前が `env:`
/// （`$env:NAME`・`${env:NAME}`・`Remove-Item Env:NAME` がすべてこれに当たる）。
/// doc コメント中の `` `HARNESS_FOO` `` のような散文や、`\\.\pipe\harness-` のような
/// 部分一致は拾わない。
///
/// **末尾が `_` のものは名前ではなく接頭辞**として捨てる（`"HARNESS_COW_"` は
/// 「この接頭辞を持つ環境変数を子へ転送する」判定に使うリテラルであって、変数ではない）。
fn harness_env_names(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while let Some(pos) = text[i..].find("HARNESS_") {
        let start = i + pos;
        let mut end = start;
        while end < bytes.len()
            && (bytes[end].is_ascii_uppercase() || bytes[end].is_ascii_digit() || bytes[end] == b'_')
        {
            end += 1;
        }
        let quoted = start > 0 && bytes[start - 1] == b'"' && bytes.get(end) == Some(&b'"');
        let after_env_ref = start >= 4 && bytes[start - 4..start].eq_ignore_ascii_case(b"env:");
        let is_prefix_literal = bytes[end - 1] == b'_';
        if (quoted || after_env_ref) && !is_prefix_literal {
            out.insert(text[start..end].to_string());
        }
        i = end.max(start + 1);
    }
    out
}

/// `env::var("NAME")` / `env::var_os("NAME")` の `NAME` を拾う（接頭辞を問わない）。
///
/// 環境変数として成立しない綴り（書式指定子の `{...}` や省略記号）は捨てる——
/// doc コメントの例やフォーマット文字列を変数名として数えないため。
fn env_var_call_names(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for pat in ["env::var(\"", "env::var_os(\""] {
        let mut i = 0usize;
        while let Some(pos) = text[i..].find(pat) {
            let start = i + pos + pat.len();
            match text[start..].find('"') {
                Some(len) => {
                    let name = &text[start..start + len];
                    if is_env_var_name(name) {
                        out.insert(name.to_string());
                    }
                    i = start + len;
                }
                None => break,
            }
        }
    }
    out
}

fn is_env_var_name(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with(|c: char| c.is_ascii_digit())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// ---------------------------------------------------------------------------
// 検査
// ---------------------------------------------------------------------------

/// **検査A**: `HARNESS_` で始まる環境変数は、本番一覧に載っているか `HARNESS_TEST_` で
/// 始まるかの**どちらか一方**である。
#[test]
fn every_harness_env_var_is_either_listed_as_production_or_marked_with_the_test_prefix() {
    let listed: BTreeSet<&str> = PRODUCTION_ENV_VARS.iter().map(|(n, _)| *n).collect();
    let mut unmarked: Vec<String> = Vec::new();
    let mut both: Vec<String> = Vec::new();

    for (rel, text) in rust_sources() {
        for name in harness_env_names(&text) {
            let in_list = listed.contains(name.as_str());
            let prefixed = name.starts_with(TEST_PREFIX);
            if in_list && prefixed {
                both.push(format!("{rel}: {name}"));
            } else if !in_list && !prefixed {
                unmarked.push(format!("{rel}: {name}"));
            }
        }
    }
    unmarked.sort();
    unmarked.dedup();
    both.sort();
    both.dedup();

    assert!(
        unmarked.is_empty(),
        "テスト専用の環境変数は `{TEST_PREFIX}` で始めること（D-86）。\n\
         本番で効くものなら PRODUCTION_ENV_VARS へ用途1行を添えて足すこと。\n\
         印の無い名前 {} 件:\n  {}",
        unmarked.len(),
        unmarked.join("\n  ")
    );
    assert!(
        both.is_empty(),
        "本番一覧の名前を `{TEST_PREFIX}` で始めてはならない（D-86）。{} 件:\n  {}",
        both.len(),
        both.join("\n  ")
    );
}

/// **検査B**: 本番一覧の各名前は、テスト側でないファイルに1件以上出現する。
///
/// 消えた変数が一覧に残り続けると、一覧が「かつて在ったもの」の墓場になり、
/// **検査Aの逃がし口として静かに効き続ける**。
#[test]
fn every_name_in_the_production_list_is_still_read_by_non_test_code() {
    let sources = rust_sources();
    let mut orphaned: Vec<&str> = Vec::new();

    for (name, _) in PRODUCTION_ENV_VARS {
        let alive = sources.iter().any(|(rel, text)| {
            !is_test_side(rel) && harness_env_names(text).contains(*name)
        });
        if !alive {
            orphaned.push(name);
        }
    }

    assert!(
        orphaned.is_empty(),
        "PRODUCTION_ENV_VARS に載っているが、テスト側でないファイルから読まれていない {} 件。\n\
         読み手ごと消えたなら一覧からも消すこと:\n  {}",
        orphaned.len(),
        orphaned.join("\n  ")
    );
}

/// **検査C**: `env::var` / `env::var_os` が読む名前は、`HARNESS_` で始まるか、
/// harness が定めたものではない外部の名前かのどちらかである。
///
/// 検査Aは名前が `HARNESS_` を名乗っていることを前提にするので、**接頭辞ごと無い名前**を
/// 素通しする。ここがその穴を塞ぐ——接頭辞の無い名前は、どの群かを名乗る余地が無いうえ、
/// 他人の環境に同じ名前があれば黙って値を拾う。
#[test]
fn every_environment_variable_read_is_either_ours_by_name_or_a_known_external_one() {
    let external: BTreeSet<&str> = EXTERNAL_ENV_VARS.iter().copied().collect();
    let mut foreign: Vec<String> = Vec::new();

    for (rel, text) in rust_sources() {
        for name in env_var_call_names(&text) {
            if !name.starts_with("HARNESS_") && !external.contains(name.as_str()) {
                foreign.push(format!("{rel}: {name}"));
            }
        }
    }
    foreign.sort();
    foreign.dedup();

    assert!(
        foreign.is_empty(),
        "harness が読む環境変数は `HARNESS_` で始めること（D-86）。\n\
         外から与えられる名前なら EXTERNAL_ENV_VARS へ足すこと。\n\
         どちらでもない {} 件:\n  {}",
        foreign.len(),
        foreign.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 検問そのものの検算——「拾えていない」と「違反が無い」は緑の見た目が同じ
// ---------------------------------------------------------------------------

/// 3つの形（リテラル全体・`$env:`・`Env:`）を拾い、散文と部分一致は拾わないこと。
///
/// **違反側の名前はここで組み立てる**——ソースに完全な綴りで書くと、この検問自身が
/// 自分のフィクスチャを違反として数えてしまう。
#[test]
fn the_scanner_picks_up_all_three_forms_and_nothing_else() {
    let listed = PRODUCTION_ENV_VARS[0].0;
    let text = format!(
        r#"
        env::var("{listed}");
        let s = "$env:HARNESS_TEST_ALPHA is read here";
        let t = "Bearer ${{env:HARNESS_TEST_BRAVO}}";
        let u = "Remove-Item Env:HARNESS_TEST_CHARLIE -Force";
        /// 散文の `HARNESS_TEST_NOT_A_READ` は拾わない。
        let p = r"\\.\pipe\harness-";
        let q = "pass paths via HARNESS_TEST_NOT_A_READ_EITHER";
        let prefix = "HARNESS_TEST_DELTA_";
        "#
    );
    let found = harness_env_names(&text);

    assert!(found.contains(listed), "リテラル全体の形を拾えていない");
    for name in [
        "HARNESS_TEST_ALPHA",
        "HARNESS_TEST_BRAVO",
        "HARNESS_TEST_CHARLIE",
    ] {
        assert!(found.contains(name), "`env:` 参照の形を拾えていない: {name}");
    }
    assert!(
        !found.contains("HARNESS_TEST_NOT_A_READ"),
        "doc コメントの散文まで拾っている"
    );
    assert!(
        !found.contains("HARNESS_TEST_NOT_A_READ_EITHER"),
        "リテラルの一部でしかない綴りまで拾っている"
    );
    assert!(
        !found.contains("HARNESS_TEST_DELTA_"),
        "末尾が `_` の接頭辞リテラルを名前として拾っている"
    );
    assert_eq!(found.len(), 4, "拾った集合: {found:?}");
}

/// 検査Cの拾い方——`env::var` の呼び出し口だけを見て、他の文字列は見ないこと。
#[test]
fn the_call_site_scanner_only_looks_at_env_var_arguments() {
    let foreign = format!("{}_{}", "MCP", "MOCK_EXAMPLE");
    let text = format!(
        r#"
        std::env::var("{foreign}");
        std::env::var_os("APPDATA");
        let unrelated = "APPDATA_LOOKALIKE";
        "#
    );
    let found = env_var_call_names(&text);
    assert_eq!(
        found,
        BTreeSet::from([foreign.clone(), "APPDATA".to_string()]),
        "拾った集合: {found:?}"
    );
}

/// テスト側ファイルの判定。
#[test]
fn test_side_files_are_recognised_by_path_and_by_name() {
    for rel in [
        "crates/harness-cli/tests/env_var_naming.rs",
        "crates/harness-sandbox/examples/bug102-langmode-matrix.rs",
        "crates/harness-sandbox/src/tier2a/win_appcontainer/dual_ace_mode_switch_tests.rs",
    ] {
        assert!(is_test_side(rel), "テスト側と判定できていない: {rel}");
    }
    for rel in [
        "crates/harness-sandbox/src/elevated_launch.rs",
        "crates/harness-core/src/wire_log.rs",
        "crates/harness-redirector/src/init.rs",
    ] {
        assert!(!is_test_side(rel), "本番側と判定できていない: {rel}");
    }
}
