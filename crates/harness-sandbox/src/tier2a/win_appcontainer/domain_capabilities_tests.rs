//! 子のトークンへ積む許可の宛先を、**組み立てる場所が増えていないか**を数える。
//!
//! # なぜソースを走査するのか
//!
//! [BUG-169] の形は、**同じ一覧を2箇所で組み立てていて、片方に1種類足りない**ことだった。
//! テストで検出できなかったのは、落ちるのが実機の `#[ignore]` テストだけで、
//! 明示的に撃つまで緑にも赤にもならなかったからである（7日間赤のまま気付かれなかった）。
//!
//! **同型の欠陥を、昇格も実機も要らない形で止める。** `DomainCapabilities` が
//! Redirector DLL の宛先を自分で引くようにしたので、そこを通れば忘れられない——
//! 残る危険は「**通らない3つめの組み立て点**が増えること」だけである。それを数える。
//!
//! # この機構が守らないもの
//!
//! **このテストが読むのは `src` 配下の `.rs` ファイルの本文だけ**で、
//! `redirector_dll_capability_sids()` という文字列を含む行を数えている。
//! **実際にトークンを組んだかどうかは一切見ていない。** したがって
//! `DomainCapabilities` を使わずに、まったく別の方法で `SECURITY_CAPABILITIES` を
//! 組む経路は止められない。止められるのは「宛先を自分で引き直す行が増えたこと」までである。

/// `redirector_dll_capability_sids` を**呼んで**いる製品コードの行を数える。
///
/// 定義そのもの（`pub fn …`）と、テスト専用ファイル（`*_tests.rs`・`test_support.rs`）は
/// 数えない。doc コメントの言及はバッククォート付きで `()` を伴わないので当たらない。
fn product_call_sites() -> Vec<(String, usize, String)> {
    fn walk(dir: &std::path::Path, out: &mut Vec<(String, usize, String)>) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("read_dir({}): {e}", dir.display()));
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
                continue;
            }
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.ends_with(".rs") || name.ends_with("_tests.rs") || name == "test_support.rs" {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            for (i, line) in text.lines().enumerate() {
                if !line.contains("redirector_dll_capability_sids()") {
                    continue;
                }
                // 定義行は呼び出しではない。
                if line.contains("pub fn ") {
                    continue;
                }
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                out.push((
                    name.to_string(),
                    i + 1,
                    trimmed.to_string(),
                ));
            }
        }
    }

    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    walk(&src, &mut out);
    out.sort();
    out
}

/// **宛先を自分で引く製品コードは2箇所ちょうどである。**
///
/// - `win_appcontainer.rs`: `DomainCapabilities::collect`。トークンを組む全経路がここを通る。
/// - `domain_provision.rs`: daemon がドメインを用意する経路。宛先を**文字列の一覧として
///   IPC で送る別表現**なので `DomainCapabilities` を通らず、自分で引いている。
///
/// 3つめが増えたら、それは「トークンを組む場所がもう1つできた」という意味である。
/// **増やしてよいが、そのときはこのテストを直しながら
/// [`super::DomainCapabilities`] を使えないか考えること**——使えるなら使う方が安い。
#[test]
fn only_two_places_look_up_the_redirector_dll_capability() {
    let sites = product_call_sites();
    let files: Vec<&str> = sites.iter().map(|(f, _, _)| f.as_str()).collect();
    assert_eq!(
        files,
        vec!["domain_provision.rs", "win_appcontainer.rs"],
        "子のトークンへ積む宛先を引く場所が変わった（BUG-169と同型の穴が開く）。実測:\n{}",
        sites
            .iter()
            .map(|(f, l, t)| format!("  {f}:{l}  {t}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// 製品の組み立て点（`launch.rs`）が、**自分で引き直していない**こと。
///
/// ここが引き直す形へ戻ると、テスト専用ヘルパーとの間に再び差が開く余地が生まれる
/// ——BUG-169 はまさにその状態だった（製品だけが4つめを積んでいた）。
#[test]
fn the_product_assembly_point_does_not_look_the_capability_up_itself() {
    let sites = product_call_sites();
    assert!(
        !sites.iter().any(|(f, _, _)| f == "launch.rs"),
        "launch.rsが宛先を自分で引いている。DomainCapabilities::collectへ寄せること"
    );
}
