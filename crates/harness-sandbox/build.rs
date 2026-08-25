//! harness 本体側へ、Redirector DLL に**期待する版の刻印**を焼き込む。
//!
//! `harness-redirector` の build script と**同じ関数**（`harness-build-id`）を呼ぶので、
//! 同じソースからビルドされた組では必ず同じ値になる。CoW セッションの開始時に、
//! 実際に注入され得る 2 本の DLL から読んだ刻印をこの期待値と突き合わせる。
//!
//! **期待値を持つのが本体側である**ことに意味がある。x64 と x86 の 2 本だけを比べると
//! 「両方とも古い」組を通してしまう。本体を基準に入れると、`cargo build --workspace` が
//! 本体と x64 を必ず一緒に作り直す性質がそのまま歯になる。

fn main() {
    let id = harness_build_id::emit_and_compute();
    println!("cargo:rustc-env=HARNESS_REDIRECTOR_BUILD_ID={id}");
}
