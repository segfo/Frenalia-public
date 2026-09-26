//! harness 本体側へ、Redirector DLL に**期待する版の刻印**を焼き込み、あわせて
//! **32bit（i686）版の成果物を作って配置する**。
//!
//! `harness-redirector` の build script と**同じ関数**（`harness-build-id`）を呼ぶので、
//! 同じソースからビルドされた組では必ず同じ値になる。Tier2a セッションの開始時に、
//! 実際に注入され得る 2 本の DLL から読んだ刻印をこの期待値と突き合わせる。
//!
//! **期待値を持つのが本体側である**ことに意味がある。x64 と x86 の 2 本だけを比べると
//! 「両方とも古い」組を通してしまう。本体を基準に入れると、`cargo build --workspace` が
//! 本体と x64 を必ず一緒に作り直す性質がそのまま歯になる。
//!
//! **32bit 版をここで作る理由**は、成果物が要る場所が 2 つ（harness.exe の隣と、
//! harness-sandbox のテストバイナリの隣）で、その両方を覆う build script がここだけだから
//! である。詳しくは `harness_build_id::x86_deploy` のモジュール doc を読むこと。

fn main() {
    let id = harness_build_id::emit_and_compute();
    println!("cargo:rustc-env=HARNESS_REDIRECTOR_BUILD_ID={id}");
    // 焼いた期待値をそのまま渡す。**置いたものがこの値を持つことを、置いた直後に検算する。**
    harness_build_id::x86_deploy::build_and_deploy_x86(&id);
}
