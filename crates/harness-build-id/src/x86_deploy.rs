//! 32bit（i686）版の成果物を**通常のビルドで作って配置する**。
//!
//! # 何のためにあるか
//!
//! Tier2a（Windows の AppContainer 隔離）では、32bit（WOW64）の孫プロセスにも透過役の DLL を
//! 注入する。cargo は 1 回の呼び出しで別アーキテクチャをビルドしないので、この 1 本だけが
//! 通常のビルド経路に乗らない。放っておくと **x86 だけが古いまま残る**——そして「古いが在る」は
//! 注入に成功してしまうので、エラーにならずに黙って壊れる。
//!
//! そこで `harness-sandbox` の build script からここを呼び、入れ子の
//! `cargo build --target i686-pc-windows-msvc` を起こして成果物を harness.exe の隣へ置く。
//! **外す環境変数もフラグも用意しない**（D-90「必ず作る」）——外せるなら、外したことを
//! 忘れた機で古い DLL が注入される。
//!
//! # 配置先が 2 つある理由
//!
//! 探す側の規約は「`current_exe()` の親を見る」ひとつだけである。実運用の `current_exe()` は
//! `<profile>/harness.exe` だが、実機テストの `current_exe()` は `<profile>/deps/<test>.exe`
//! なので、**同じ固定名で 2 箇所に要る**。
//!
//! # ここで検算できないこと
//!
//! x64 の DLL と harness.exe の刻印との突き合わせは**ここではできない**。`harness-sandbox` と
//! `harness-redirector` の間に依存関係が無く、cargo がどちらを先に作るか決まっていないためである
//! （x64 DLL がまだ無い時点でこの build script が走り得る）。3 者一致の判定は従来どおり
//! 実行時のゲート（`harness-sandbox` の `tier2a::redirector_identity`）と、テストバイナリの隣を
//! 見る単体テストが持つ。ここが受け持つのは「**いま置いた x86 が、いま焼く期待値と同じか**」だけ。

use std::path::{Path, PathBuf};

/// 32bit 版を作るときのターゲット三つ組。
pub const I686_TRIPLE: &str = "i686-pc-windows-msvc";

/// i686 のツールチェーンが入っていないときに案内するコマンド。**エラー文にそのまま出す**。
pub const RUSTUP_HINT: &str = "rustup target add i686-pc-windows-msvc";

/// 通常ビルドで一緒に作る 32bit 成果物。
struct X86Artifact {
    /// 入れ子ビルドに渡すパッケージ名。
    package: &'static str,
    /// cargo が出すファイル名（パッケージ側が決める）。
    built: &'static str,
    /// 配置するときの固定名。x64 と衝突しないよう `_x86` を付ける。
    deployed: &'static str,
    /// 配置後に刻印を検算するか。プローブ実行ファイルは刻印を持たないので検算しない。
    verify_build_id: bool,
    /// 変更を検出するために `rerun-if-changed` を出すソースの置き場（ワークスペース相対）。
    watched: &'static [&'static str],
}

/// **どちらも「手で打たないと揃わない」ものだった。** 前者はセッションの起動条件そのもので、
/// 後者は封じ込め E2E が使うプローブで、手引きのコピペ 4 行としてしか存在しなかった。
const X86_ARTIFACTS: &[X86Artifact] = &[
    X86Artifact {
        package: "harness-redirector",
        built: "harness_redirector.dll",
        deployed: "harness_redirector_x86.dll",
        verify_build_id: true,
        // 刻印の対象（`HASHED_DIRS`/`HASHED_FILES`）と同じ集合なので、`emit_and_compute` が
        // 既に `rerun-if-changed` を出している。ここで重ねて出さない。
        watched: &[],
    },
    X86Artifact {
        package: "tier2a-proc-probe",
        built: "tier2a_proc_probe.exe",
        deployed: "tier2a_proc_probe_x86.exe",
        verify_build_id: false,
        watched: &["crates/tier2a-proc-probe/src", "crates/tier2a-proc-probe/Cargo.toml"],
    },
];

/// 入れ子ビルドへ**渡してはいけない**環境変数（完全一致）。
///
/// 外側のビルドの設定がそのまま効くと、別アーキテクチャ向けに使えないフラグ
/// （`RUSTFLAGS` の `-C target-cpu` 等）や、外側の成果物置き場（`CARGO_TARGET_DIR`）が
/// 引き継がれる。**引き継がれても多くの場合エラーにならず、黙って別物ができる。**
const SCRUBBED_EXACT: &[&str] = &[
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "RUSTDOCFLAGS",
    "CARGO_ENCODED_RUSTDOCFLAGS",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTDOC",
    "CARGO_TARGET_DIR",
    "OUT_DIR",
    "TARGET",
    "HOST",
    "NUM_JOBS",
    "PROFILE",
    "DEBUG",
    "OPT_LEVEL",
];

/// 入れ子ビルドへ**渡してはいけない**環境変数（接頭辞一致）。cargo の設定は環境変数でも
/// 与えられるので、`CARGO_BUILD_TARGET` のような 1 つで行き先が変わるものを全部落とす。
const SCRUBBED_PREFIXES: &[&str] = &[
    "CARGO_BUILD_",
    "CARGO_TARGET_",
    "CARGO_PROFILE_",
    "CARGO_UNSTABLE_",
];

/// 接頭辞を広げたときに**巻き込んではいけない**もの。
///
/// - `CARGO_MAKEFLAGS`: cargo が build script へ渡す jobserver の取っ手。入れ子の cargo へ
///   渡すと**ジョブ数を共有する**（落とすと外側と内側が独立に並列度を決め、コア数の 2 倍走る）。
/// - `CARGO_HOME`: 置き場を変えている機で落とすと、入れ子の cargo が既定の場所を見て
///   **依存を取り直しに行く**。
///
/// ここは実行時には使わない——[`SCRUBBED_PREFIXES`] がこれらに当たらないことを、
/// 下の単体テストが固定している（`CARGO_` まで広げた瞬間に赤くなる）。
#[cfg(test)]
const MUST_SURVIVE_SCRUBBING: &[&str] = &["CARGO_MAKEFLAGS", "CARGO_HOME"];

/// build script から呼ぶ入口。
///
/// `expected_build_id` は [`crate::emit_and_compute`] が返した値。配置した DLL から読んだ刻印が
/// これと違えば panic する——**外部コマンドの見た目の成功を信用しない**。cargo が「Finished」と
/// 言っても、fingerprint が分岐して成果物が更新されていないことが実際にある
/// （`docs/DEV-ENVIRONMENT.md` の x86 節）。
pub fn build_and_deploy_x86(expected_build_id: &str) {
    let Some(reason) = skip_reason() else {
        run(expected_build_id);
        return;
    };
    // build script の出力は `-vv` を付けないと見えないので、ここは案内に留める。
    println!("cargo:warning=skipping the i686 redirector/probe build: {reason}");
}

/// 32bit 版を作らない条件。作る場合は `None`。
fn skip_reason() -> Option<String> {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    match classify(&target_os, &target_arch, cfg!(windows)) {
        Deploy::Yes => None,
        Deploy::No(reason) => Some(reason.to_string()),
    }
}

/// 作るか作らないかの判定。**ファイルシステムも環境変数も触らない**ので単体テストで固定できる。
#[derive(Debug, PartialEq, Eq)]
enum Deploy {
    Yes,
    No(&'static str),
}

fn classify(target_os: &str, target_arch: &str, host_is_windows: bool) -> Deploy {
    if target_os != "windows" {
        // この build script は Linux 向けビルドでも走る（`harness-sandbox` は tier2b を持つ）。
        return Deploy::No("the build target is not Windows");
    }
    if target_arch == "x86" {
        // 32bit の harness に WOW64 用の助けは要らない。**入れ子ビルドの再帰もここで止まる**
        // ——万一 `harness-redirector` が `harness-sandbox` に依存する日が来ても、
        // 内側のビルドは i686 なのでこの腕に落ちる。
        return Deploy::No("the build target is already 32bit, so no WOW64 helper is needed");
    }
    if !host_is_windows {
        // i686 の MSVC リンカはホストが Windows でないと引けない。
        return Deploy::No("the build host is not Windows, so the i686 MSVC linker is unavailable");
    }
    Deploy::Yes
}

fn run(expected_build_id: &str) {
    let out_dir = PathBuf::from(
        std::env::var("OUT_DIR").expect("x86_deploy: OUT_DIR is only set by cargo; call from build.rs"),
    );
    let profile_dir = profile_dir_from_out_dir(&out_dir).unwrap_or_else(|| {
        panic!(
            "x86_deploy: could not derive the deployment directory from OUT_DIR ({}). \
             It is expected to look like <target>/<profile>/build/<pkg>-<hash>/out",
            out_dir.display()
        )
    });
    let nested_target_dir = profile_dir.join("redirector-x86");
    let release = std::env::var("PROFILE").as_deref() == Ok("release");
    let workspace = crate::workspace_root();

    for artifact in X86_ARTIFACTS {
        for watched in artifact.watched {
            emit_rerun_recursive(&workspace.join(watched));
        }
        cargo_build_i686(artifact.package, &nested_target_dir, release);
        let src = nested_artifact_path(&nested_target_dir, release, artifact.built);
        let mut placed = Vec::new();
        for dst in deployment_paths(&profile_dir, artifact.deployed) {
            copy_artifact(&src, &dst);
            // 消されたら作り直す。**存在しないパスを `rerun-if-changed` に出すと
            // cargo は「変わった」と見なして build script を再実行する**ので、
            // 手で削除した成果物が黙って欠けたままにならない。
            println!("cargo:rerun-if-changed={}", dst.display());
            placed.push(dst);
        }
        if artifact.verify_build_id {
            for dst in &placed {
                verify_placed_build_id(dst, expected_build_id);
            }
        }
    }
}

/// `OUT_DIR`（`<target>/<profile>/build/<pkg>-<hash>/out`）から `<target>/<profile>` を導く。
///
/// **固定段数で辿る。** cargo が `OUT_DIR` をこの形で作ることは文書化された振る舞いで、
/// `--target` を付けたビルドでも `<target>/<triple>/<profile>/build/...` になるので、
/// 3 つ上が「実行ファイルが置かれるディレクトリ」であることは変わらない。
fn profile_dir_from_out_dir(out_dir: &Path) -> Option<PathBuf> {
    let build_dir = out_dir.parent()?.parent()?; // <profile>/build
    if build_dir.file_name()? != "build" {
        return None;
    }
    Some(build_dir.parent()?.to_path_buf())
}

/// 入れ子ビルドが成果物を置く場所。
fn nested_artifact_path(nested_target_dir: &Path, release: bool, built: &str) -> PathBuf {
    nested_target_dir
        .join(I686_TRIPLE)
        .join(if release { "release" } else { "debug" })
        .join(built)
}

/// 同じ固定名で 2 箇所へ置く（実運用は harness.exe の隣、実機テストはテストバイナリの隣）。
fn deployment_paths(profile_dir: &Path, deployed: &str) -> Vec<PathBuf> {
    vec![
        profile_dir.join(deployed),
        profile_dir.join("deps").join(deployed),
    ]
}

fn cargo_build_i686(package: &str, nested_target_dir: &Path, release: bool) {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut command = std::process::Command::new(cargo);
    command
        .arg("build")
        .arg("-p")
        .arg(package)
        .arg("--target")
        .arg(I686_TRIPLE)
        .arg("--target-dir")
        .arg(nested_target_dir);
    if release {
        command.arg("--release");
    }
    // 端末制御を混ぜない。進捗バーを出させると、build script の捕捉された出力の中で
    // 入れ子の cargo が止まって見えることがある（`spawnd/spawn_rate_tests.rs` と同じ扱い）。
    command
        .env("CARGO_TERM_COLOR", "never")
        .env("CARGO_TERM_PROGRESS_WHEN", "never");
    for key in scrubbed_keys() {
        command.env_remove(key);
    }

    let output = command.output().unwrap_or_else(|e| {
        panic!("x86_deploy: failed to launch the nested cargo build for {package}: {e}")
    });
    if !output.status.success() {
        panic!(
            "x86_deploy: the nested `cargo build -p {package} --target {I686_TRIPLE}` failed \
             (exit {:?}).\n\
             If the toolchain for that target is missing, install it with: {RUSTUP_HINT}\n\
             --- nested cargo stderr ---\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// 落とす環境変数の一覧を、いまのプロセスの環境から組む。
///
/// 接頭辞に当たるものは名前を列挙しないと消せないので、ここで実際の環境を見る。
fn scrubbed_keys() -> Vec<String> {
    let mut keys: Vec<String> = SCRUBBED_EXACT.iter().map(|k| (*k).to_string()).collect();
    for (key, _) in std::env::vars() {
        if SCRUBBED_PREFIXES.iter().any(|p| key.starts_with(p)) {
            keys.push(key);
        }
    }
    keys
}

fn copy_artifact(src: &Path, dst: &Path) {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            panic!("x86_deploy: failed to create {}: {e}", parent.display())
        });
    }
    std::fs::copy(src, dst).unwrap_or_else(|e| {
        panic!(
            "x86_deploy: the nested build reported success but copying {} to {} failed: {e}",
            src.display(),
            dst.display()
        )
    });
}

/// 置いた成果物から刻印を読み、期待値と一致することを確かめる。
///
/// **一致しないのは「cargo は成功したが成果物が更新されていない」場合である。** 実際に
/// 起きる（fingerprint の分岐）ので、成功の見た目ではなく中身を見る。
fn verify_placed_build_id(path: &Path, expected: &str) {
    let bytes = std::fs::read(path)
        .unwrap_or_else(|e| panic!("x86_deploy: failed to read back {}: {e}", path.display()));
    match crate::extract_build_id(&bytes) {
        Ok(found) if found == expected => {}
        Ok(found) => panic!(
            "x86_deploy: {} carries build id {found} but this build expects {expected}. \
             The nested cargo build reported success without refreshing the artifact.",
            path.display()
        ),
        Err(e) => panic!(
            "x86_deploy: could not read a build id back from {} ({e}). \
             The artifact was built without the build-id stamp.",
            path.display()
        ),
    }
}

/// `dir` 配下の全ファイルについて `rerun-if-changed` を出す。
///
/// **ディレクトリだけを出すのでは足りない。** cargo はディレクトリの更新時刻を見るので、
/// 中のファイルを編集しただけでは変化として拾われない（追加・削除しか拾えない）。
/// 逆にディレクトリも出すのは、**追加**を拾うためである。
///
/// 刻印を計算する側（`collect_files`）と walk を共有していないのは、あちらが
/// **中身を読んでハッシュする**のに対し、ここは名前を並べるだけで十分だからである
/// （共有すると、プローブのソースを刻印に含めないのに全部読むことになる）。
fn emit_rerun_recursive(dir: &Path) {
    println!("cargo:rerun-if-changed={}", dir.display());
    let Ok(entries) = std::fs::read_dir(dir) else {
        // ファイルを直接指された場合はここへ来る（上の 1 行で用は足りている）。
        return;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            emit_rerun_recursive(&path);
        } else {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- 作る／作らないの判定（許可側と拒否側の対） ----

    /// 64bit の Windows を Windows 上でビルドするとき**だけ**作る。
    #[test]
    fn a_windows_x64_build_on_a_windows_host_deploys() {
        assert_eq!(classify("windows", "x86_64", true), Deploy::Yes);
        assert_eq!(classify("windows", "aarch64", true), Deploy::Yes);
    }

    /// Windows 以外向けのビルドでは何もしない（この build script は Linux でも走る）。
    #[test]
    fn a_non_windows_target_does_not_deploy() {
        assert!(matches!(classify("linux", "x86_64", true), Deploy::No(_)));
        assert!(matches!(classify("macos", "aarch64", false), Deploy::No(_)));
    }

    /// 32bit 向けのビルドでは何もしない。**入れ子ビルドの再帰もここで止まる。**
    #[test]
    fn a_32bit_target_does_not_deploy_and_that_is_what_stops_recursion() {
        assert!(matches!(classify("windows", "x86", true), Deploy::No(_)));
    }

    /// ホストが Windows でなければ i686 の MSVC リンカを引けない。
    #[test]
    fn cross_compiling_to_windows_from_elsewhere_does_not_deploy() {
        assert!(matches!(classify("windows", "x86_64", false), Deploy::No(_)));
    }

    // ---- パスの組み立て ----

    #[test]
    fn the_deployment_dir_is_three_levels_above_out_dir() {
        let out = PathBuf::from("C:/repo/target/debug/build/harness-sandbox-abc123/out");
        assert_eq!(
            profile_dir_from_out_dir(&out),
            Some(PathBuf::from("C:/repo/target/debug"))
        );
    }

    /// `--target` を付けたビルドでも、3 つ上が「実行ファイルの置かれる場所」である。
    #[test]
    fn a_cross_target_out_dir_still_resolves_to_the_exe_directory() {
        let out =
            PathBuf::from("C:/repo/target/x86_64-pc-windows-msvc/release/build/harness-sandbox-1/out");
        assert_eq!(
            profile_dir_from_out_dir(&out),
            Some(PathBuf::from("C:/repo/target/x86_64-pc-windows-msvc/release"))
        );
    }

    /// 形が違うものを黙って受け入れない——受け入れると、成果物を**別の場所へ**置いて
    /// 「配置した」と報告することになる。
    #[test]
    fn an_out_dir_that_is_not_shaped_like_cargos_is_rejected() {
        assert_eq!(
            profile_dir_from_out_dir(&PathBuf::from("C:/somewhere/else/out")),
            None
        );
        assert_eq!(profile_dir_from_out_dir(&PathBuf::from("out")), None);
    }

    #[test]
    fn the_nested_artifact_path_follows_the_profile() {
        let nested = PathBuf::from("C:/repo/target/debug/redirector-x86");
        assert_eq!(
            nested_artifact_path(&nested, false, "harness_redirector.dll"),
            PathBuf::from(
                "C:/repo/target/debug/redirector-x86/i686-pc-windows-msvc/debug/harness_redirector.dll"
            )
        );
        assert_eq!(
            nested_artifact_path(&nested, true, "harness_redirector.dll"),
            PathBuf::from(
                "C:/repo/target/debug/redirector-x86/i686-pc-windows-msvc/release/harness_redirector.dll"
            )
        );
    }

    /// 配置先は 2 箇所。**片方だけだと、実運用と実機テストのどちらかが探し当てられない。**
    #[test]
    fn every_artifact_is_placed_next_to_both_the_exe_and_the_test_binaries() {
        let profile = PathBuf::from("C:/repo/target/debug");
        assert_eq!(
            deployment_paths(&profile, "harness_redirector_x86.dll"),
            vec![
                PathBuf::from("C:/repo/target/debug/harness_redirector_x86.dll"),
                PathBuf::from("C:/repo/target/debug/deps/harness_redirector_x86.dll"),
            ]
        );
    }

    // ---- 成果物の一覧 ----

    /// 「手で打たないと揃わない」ものは 2 つあり、**2 つとも**この一覧に載っていること。
    #[test]
    fn both_manually_built_artifacts_are_covered() {
        let packages: Vec<&str> = X86_ARTIFACTS.iter().map(|a| a.package).collect();
        assert_eq!(packages, vec!["harness-redirector", "tier2a-proc-probe"]);
    }

    /// 配置名は x64 と衝突しないこと（同じディレクトリに両方置くので、名前が同じだと上書きになる）。
    #[test]
    fn the_deployed_names_never_collide_with_the_x64_artifacts() {
        for artifact in X86_ARTIFACTS {
            assert_ne!(artifact.deployed, artifact.built, "{}", artifact.package);
            assert!(
                artifact.deployed.contains("_x86."),
                "{} deploys as {}",
                artifact.package,
                artifact.deployed
            );
        }
    }

    /// 刻印を持つのは DLL だけ。プローブに検算を掛けると、**刻印が無いという理由で
    /// 常にビルドが落ちる**。
    #[test]
    fn only_the_stamped_artifact_is_verified_by_build_id() {
        let verified: Vec<&str> = X86_ARTIFACTS
            .iter()
            .filter(|a| a.verify_build_id)
            .map(|a| a.package)
            .collect();
        assert_eq!(verified, vec!["harness-redirector"]);
    }

    /// **どの成果物も、ソースが変わったときに作り直される道を 1 つは持っていること。**
    ///
    /// 道は 2 通りある——刻印の対象なら `emit_and_compute` が `rerun-if-changed` を出している
    /// （＝`verify_build_id` が真のものはそれに乗っている）。対象外なら自分で `watched` を
    /// 持たなければならない。**どちらも無いと、ソースを直したのに古い成果物が置かれ続ける。**
    #[test]
    fn every_artifact_has_a_way_to_be_rebuilt_when_its_sources_change() {
        for artifact in X86_ARTIFACTS {
            assert!(
                artifact.verify_build_id || !artifact.watched.is_empty(),
                "{} is neither in the build-id hash set nor watching its own sources",
                artifact.package
            );
        }
    }

    // ---- 環境の落とし方 ----

    /// 別アーキテクチャへ持ち込めないフラグと、行き先を変える設定が落ちること。
    #[test]
    fn the_scrubbed_set_covers_flags_and_destinations() {
        for key in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_TARGET_DIR"] {
            assert!(SCRUBBED_EXACT.contains(&key), "{key}");
        }
        assert!(SCRUBBED_PREFIXES.contains(&"CARGO_BUILD_"));
    }

    /// **落としてはいけないものが、落とす側の条件に当たっていないこと。**
    ///
    /// これが本当のゲートである——接頭辞を `CARGO_` まで広げた瞬間に赤くなる。
    /// 「残す一覧」を実行時に持つ形にすると、一覧に載せ忘れたものが黙って落ちる。
    #[test]
    fn the_things_that_must_survive_are_not_matched_by_any_scrubbing_rule() {
        for key in MUST_SURVIVE_SCRUBBING {
            assert!(!SCRUBBED_EXACT.contains(key), "{key} is scrubbed by name");
            assert!(
                !SCRUBBED_PREFIXES.iter().any(|p| key.starts_with(p)),
                "{key} is scrubbed by prefix"
            );
        }
    }
}
