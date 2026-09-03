//! Redirector DLL の**版の刻印**（build id）を、ソースから決まる 64 桁の 16 進として計算する。
//!
//! # 何のためにあるか
//!
//! `--sandbox tier2a-cow`（ワークスペースを読み取り専用にし、書込を差分層へ横流しする方式）では、
//! 透過役の DLL が 64bit の子と 32bit（WOW64）の孫の**両方**へ注入される。x64 の DLL は
//! `cargo build --workspace` が必ず作り直すが、x86 の DLL は別ターゲットの手動ビルドでしか
//! 生まれない（ワークスペースに `build.rs` も `.cargo/config.toml` も無く、通常ビルドの経路に
//! 乗っていない）。つまり **x86 だけが古いまま残り得る**。
//!
//! 古い方が「無い」なら注入が失敗し、読み取り専用 ACL が書込を拒んで安全側に倒れる。
//! 厄介なのは「**古いが在る**」で、この場合は注入に成功してしまう。しかも親から子へ渡す設定
//! （`harness-redirector` の `serialize_config_blob`）は位置依存のテキストで版タグを持たないため、
//! 将来その形が変わると古い DLL は知らない行を**黙って捨てて**動き続ける。エラーにならない。
//!
//! そこで「2 本が同じソースから作られたか」を機械が判定できるようにする。この刻印は
//! **アーキテクチャに依存しない**——同じソースなら x64 でも x86 でも同じ値になる。
//!
//! # なぜ実装が 1 本なのか
//!
//! 刻む側（`harness-redirector`）と照合する側（`harness-sandbox`）の 2 つの build script が
//! 同じ値を出す必要がある。ハッシュ対象のリストを両方へ書き写すと、**片方だけ更新されて
//! 必ずずれる**（このリポジトリで最頻の再発パターン）。リストはこのクレートだけが持ち、
//! build script 側はこの関数を呼ぶだけにする。

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// 刻印に含めるディレクトリ（配下の `.rs` を再帰的に拾う）。ワークスペースルートからの相対。
///
/// `harness-change-ledger` を含めるのは、**DLL と apply 側が共有する台帳の書式**だからである。
/// ここが変わって x86 だけ古いと、32bit の孫が旧書式で台帳へ書き、その食い違いは実行時まで
/// 表に出ない。「redirector のソース」だけを見ていると取りこぼす。
const HASHED_DIRS: &[&str] = &[
    "crates/harness-redirector/src",
    "crates/harness-change-ledger/src",
];

/// 刻印に含める単独ファイル。依存クレートのバージョンが変われば DLL の中身も変わり得るので
/// `Cargo.toml` も対象にする。
const HASHED_FILES: &[&str] = &["crates/harness-redirector/Cargo.toml"];

/// 刻印を DLL のバイト列から探すためのマーカー。この後に 64 桁の 16 進と NUL が続く。
pub const BUILD_ID_MARKER: &str = "HRBUILDID:";

/// 刻印（16 進）の桁数。SHA-256 なので 64。
pub const BUILD_ID_HEX_LEN: usize = 64;

/// build script から呼ぶ入口。刻印を返し、あわせて `cargo:rerun-if-changed` を出す。
///
/// **再ビルド指示を出すのはここだけ**である。出し漏らすと、ソースを直したのに古い刻印が
/// バイナリへ焼き付いたままになり、「版が一致している」という判定そのものが嘘になる。
///
/// 失敗したら panic する。build script が黙って既定値へ倒れると、**照合が常に通る刻印**が
/// 焼かれることになり、ゲートが形だけ残って中身が死ぬ。
pub fn emit_and_compute() -> String {
    let root = workspace_root();
    let files = collect_files(&root);
    assert!(
        !files.is_empty(),
        "harness-build-id: no source files were found under {} — the hashed path list is wrong, \
         and continuing would bake a build id that cannot detect anything",
        root.display()
    );

    // ディレクトリ自体も監視する。ファイルを**新しく足した**ときに再計算させるため
    // （既存ファイルの列挙だけでは、追加は検出できない）。
    for dir in HASHED_DIRS {
        println!("cargo:rerun-if-changed={}", root.join(dir).display());
    }
    for (_, abs, _) in &files {
        println!("cargo:rerun-if-changed={}", abs.display());
    }

    let pairs: Vec<(String, Vec<u8>)> = files
        .into_iter()
        .map(|(rel, _, bytes)| (rel, bytes))
        .collect();
    hash_sources(&pairs)
}

/// 刻印の計算そのもの。**ファイルシステムを触らない**ので単体テストで固定できる。
///
/// 入力は「ワークスペースルートからの相対パス（区切りは `/` に正規化済み）」と中身の対。
/// 呼び出し側が順序を保証しなくても同じ値になるよう、ここで並べ替える。
pub fn hash_sources(files: &[(String, Vec<u8>)]) -> String {
    let mut sorted: Vec<&(String, Vec<u8>)> = files.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = Sha256::new();
    for (rel, bytes) in sorted {
        // パスと中身の両方を、**長さを前置して**混ぜる。前置しないと
        // ("ab", "c") と ("a", "bc") が同じ入力列になり、別物が同じ刻印になる。
        hasher.update((rel.len() as u64).to_le_bytes());
        hasher.update(rel.as_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    format!("{:x}", hasher.finalize())
}

/// `CARGO_MANIFEST_DIR` から上へ辿り、`[workspace]` を持つ `Cargo.toml` のあるディレクトリを返す。
///
/// 親を固定段数で辿らないのは、呼び出し元のクレートがどの深さに居ても正しく効くようにするため。
fn workspace_root() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect(
        "harness-build-id: CARGO_MANIFEST_DIR is only set by cargo; call this from build.rs",
    );
    let mut dir = PathBuf::from(manifest);
    loop {
        let candidate = dir.join("Cargo.toml");
        if let Ok(text) = std::fs::read_to_string(&candidate) {
            if text.contains("[workspace]") {
                return dir;
            }
        }
        if !dir.pop() {
            panic!(
                "harness-build-id: walked up to the filesystem root without finding a Cargo.toml \
                 containing [workspace]"
            );
        }
    }
}

/// 刻印の対象ファイルを (相対パス, 絶対パス, 中身) で集める。相対パスの区切りは `/` に揃える
/// ——刻印が OS の区切り文字に依存すると、同じソースでも機によって値が変わってしまう。
fn collect_files(root: &Path) -> Vec<(String, PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    for dir in HASHED_DIRS {
        collect_rs_recursive(root, &root.join(dir), &mut out);
    }
    for file in HASHED_FILES {
        let abs = root.join(file);
        let bytes = std::fs::read(&abs).unwrap_or_else(|e| {
            panic!(
                "harness-build-id: failed to read {} which the build id depends on: {e}",
                abs.display()
            )
        });
        out.push(((*file).to_string(), abs, bytes));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn collect_rs_recursive(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf, Vec<u8>)>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| {
        panic!(
            "harness-build-id: failed to list {} which the build id depends on: {e}",
            dir.display()
        )
    });
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect::<Vec<_>>();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            collect_rs_recursive(root, &path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let bytes = std::fs::read(&path).unwrap_or_else(|e| {
                panic!(
                    "harness-build-id: failed to read {} which the build id depends on: {e}",
                    path.display()
                )
            });
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, path, bytes));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(path: &str, body: &str) -> (String, Vec<u8>) {
        (path.to_string(), body.as_bytes().to_vec())
    }

    /// 同じ中身なら**並び順に関わらず**同じ刻印になる。ディレクトリ列挙の順序は
    /// ファイルシステム任せなので、ここが揺れると同じソースが機ごとに別の刻印になる。
    #[test]
    fn the_id_does_not_depend_on_input_order() {
        let a = vec![f("a.rs", "one"), f("b.rs", "two")];
        let b = vec![f("b.rs", "two"), f("a.rs", "one")];
        assert_eq!(hash_sources(&a), hash_sources(&b));
    }

    /// 中身が 1 バイト変わったら刻印が変わる（＝古い DLL を見分けられる）。
    /// これが成り立たないとゲートが何も検出できない。
    #[test]
    fn the_id_changes_when_any_content_changes() {
        let base = vec![f("a.rs", "one"), f("b.rs", "two")];
        let edited = vec![f("a.rs", "one"), f("b.rs", "twO")];
        assert_ne!(hash_sources(&base), hash_sources(&edited));
    }

    /// **ファイル名だけ**が変わっても刻印が変わる。中身しか混ぜていないと、
    /// リネームやファイルの移動が刻印に出ない。
    #[test]
    fn the_id_changes_when_a_file_is_renamed() {
        let base = vec![f("a.rs", "one")];
        let renamed = vec![f("z.rs", "one")];
        assert_ne!(hash_sources(&base), hash_sources(&renamed));
    }

    /// 長さを前置している効果。前置が無いと ("ab","c") と ("a","bc") が同じバイト列に潰れ、
    /// **別のソースが同じ刻印を持つ**（＝古い DLL が新しいものに化ける）。
    #[test]
    fn concatenation_ambiguity_does_not_collapse_two_different_trees() {
        let one = vec![f("x.rs", "ab"), f("y.rs", "c")];
        let two = vec![f("x.rs", "a"), f("y.rs", "bc")];
        assert_ne!(hash_sources(&one), hash_sources(&two));
    }

    /// 刻印は常に 64 桁の 16 進。走査側（`harness-sandbox`）はこの長さを前提に切り出すので、
    /// ここが変わると照合が黙って外れる。
    #[test]
    fn the_id_is_always_64_lowercase_hex_digits() {
        let id = hash_sources(&[f("a.rs", "one")]);
        assert_eq!(id.len(), BUILD_ID_HEX_LEN);
        assert!(id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }
}
