//! Redirector DLL へ**版の刻印**を焼き込む。
//!
//! 刻印は「このワークスペースの redirector 系ソースの内容」から決まる 64 桁の 16 進で、
//! 同じソースなら x64 でも x86（WOW64 用）でも同じ値になる。`harness-sandbox` 側の
//! build script も**同じ関数**で同じ値を出し、起動時にそれを期待値として照合する。
//!
//! ハッシュ対象のリストと再ビルド指示は `harness-build-id` が唯一持つ。ここへ写さない
//! ——写すと片方だけ更新されてずれ、「版が一致している」という判定そのものが嘘になる。

fn main() {
    let id = harness_build_id::emit_and_compute();
    println!("cargo:rustc-env=HARNESS_REDIRECTOR_BUILD_ID={id}");
}
