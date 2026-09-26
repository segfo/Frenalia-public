//! Tier2a セッションを起こしてよいかを、**Redirector DLL 2 本の版がそろっているか**で判定する。
//!
//! # 何を守っているか
//!
//! Tier2a（Windows の AppContainer 隔離）では、透過役の DLL が 2 つの姿で使われる。64bit の子には
//! `harness_redirector.dll` が、32bit（WOW64）の孫には `harness_redirector_x86.dll` が注入される。
//!
//! この 2 本は**別々の cargo 呼び出しで作られる**——cargo は 1 回の呼び出しで別アーキテクチャを
//! ビルドしないためである。`harness-sandbox` の build script が入れ子のビルドを起こして
//! 置くようにしてあるが（`harness_build_id::x86_deploy`）、**それでも古いまま残る経路は残る**
//! ——別のブランチで作った成果物が `target` に居る、頒布物の組み立てが半端だった、など。
//!
//! 「無い」と「古い」では**古い方が悪い**。
//!
//! - **無い**: 注入が失敗し、透過性が失われる。
//! - **古い**: 注入に**成功してしまう**。しかも親から子へ渡す設定
//!   （`harness-redirector` の `serialize_config_blob`）は位置依存のテキストで版タグを持たないため、
//!   将来その形が変わると古い DLL は知らない行を黙って捨てて動き続ける。エラーにならない。
//!
//! そこで、副作用を一切起こしていない段階で 2 本の版を検算し、そろわなければ**セッションごと
//! 起こさない**。自動的に弱いモードへ降格はしない（D-75。弱い器が要るなら `--sandbox` の値で
//! 明示的に選ぶ）。
//!
//! # 判定の範囲は全 Tier2a である（CoW 限定ではない）
//!
//! 当初この検算は Copy-on-Write（ワークスペースを読み取り専用にして書込を差分層へ横流しする
//! 方式）のときだけ走っていた。**注入そのものが全 Tier2a で起きるようになった**ので条件を外した
//! ——同じ問題の ACE 付与側は先に条件が外れており（`win_appcontainer::preflight` の
//! 「条件そのものが消えた」の注）、**検算側だけが取り残されていた**。
//!
//! # このゲートが守らないもの
//!
//! **同じ権限を持つローカル攻撃者**は防げない。x86 DLL を差し替えられる相手は、期待値を持つ
//! harness 本体も差し替えられるからである。これは D-44（昇格ヘルパーの整合性を署名ではなく
//! 配置の DACL で見ると決めた拘束的決定、`crate::elevated_launch`）で既に結論が出ている話で、
//! ここはその結論を変えない。**このゲートが相手にしているのは攻撃者ではなく取り違え**
//! ——人がビルドし忘れた、頒布物の組み立てが半端だった、という事故である。事故は harness 本体を
//! 辻褄合わせに書き換えてくれないので、版の刻印は事故に対しては壊れない。

use std::path::{Path, PathBuf};

// 刻印の綴りと、バイト列からの取り出しは `harness-build-id` が唯一持つ。**build script も
// 同じ関数を呼ぶ**——配置直後の検算と実行時のゲートで判定が分かれると、片方だけが通る。
pub use harness_build_id::{extract_build_id, IdError, BUILD_ID_HEX_LEN, BUILD_ID_MARKER};

/// この harness 本体が期待する刻印。build script が `harness-build-id` に計算させた値で、
/// 同じソースからビルドされた DLL には同じ値が入っている。
pub const EXPECTED_BUILD_ID: &str = env!("HARNESS_REDIRECTOR_BUILD_ID");

/// x86（WOW64 用）Redirector DLL の固定ファイル名。x64 の隣に置く規約
/// （`harness-redirector` 側の `x86_sibling_dll_path` と同じ綴り）。
pub const X86_DLL_FILENAME: &str = "harness_redirector_x86.dll";

/// 作り直すためのコマンド。**エラー文にそのまま出す**——「そろっていない」とだけ言われても
/// 次に何を打てばよいかが分からないと、利用者はゲートを外す方へ動く。
///
/// **手で 32bit 版を作る手順はもう案内しない。** `harness-sandbox` の build script が
/// 入れ子のビルドで作って置くので、打つのは普通のビルドである
/// （i686 のツールチェーンが無ければ、そのビルドが `rustup target add` を案内して落ちる）。
pub const REBUILD_HINT: &str = "cargo build --workspace \
    (the harness-sandbox build script builds and places the 32bit i686-pc-windows-msvc \
    redirector; if that toolchain is missing it will tell you to run \
    `rustup target add i686-pc-windows-msvc`)";

/// Tier2a セッションを起こしてよいかの判定に失敗した理由。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectorSetError {
    /// DLL がそこに無い。
    Missing { path: PathBuf },
    /// DLL は在るが読めない。
    Unreadable { path: PathBuf, reason: String },
    /// DLL は読めたが刻印が取り出せない（古すぎて刻印が無い版、または壊れている）。
    IdUnreadable { path: PathBuf, reason: IdError },
    /// 刻印は取れたが、期待値と一致しないものがある。
    Mismatch {
        expected: String,
        found: Vec<(PathBuf, String)>,
    },
}

impl std::fmt::Display for RedirectorSetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RedirectorSetError::Missing { path } => write!(
                f,
                "the redirector DLL {} is missing, so 32bit (WOW64) descendants would run \
                 without transparent redirection. Refusing to start the session. Build it with: \
                 {REBUILD_HINT}",
                path.display()
            ),
            RedirectorSetError::Unreadable { path, reason } => write!(
                f,
                "the redirector DLL {} could not be read ({reason}), so its version cannot be \
                 checked. Refusing to start the session.",
                path.display()
            ),
            RedirectorSetError::IdUnreadable { path, reason } => write!(
                f,
                "the redirector DLL {} carries no usable build id ({reason}). It was probably \
                 built before build ids existed, which means it is older than this harness. \
                 Rebuild it with: {REBUILD_HINT}",
                path.display()
            ),
            RedirectorSetError::Mismatch { expected, found } => {
                write!(
                    f,
                    "the redirector DLLs were not all built from this source tree. This \
                     harness expects build id {expected}, but found: "
                )?;
                for (i, (path, id)) in found.iter().enumerate() {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{} = {id}", path.display())?;
                }
                write!(
                    f,
                    ". A stale 32bit DLL is worse than a missing one because it still injects \
                     successfully. Refusing to start the session. Rebuild with: {REBUILD_HINT}"
                )
            }
        }
    }
}

impl std::error::Error for RedirectorSetError {}

/// 取り出し済みの刻印一覧を期待値と突き合わせる。**ファイルシステムを触らない**ので、
/// 判定そのものを単体テストで固定できる。
pub fn verify_ids(expected: &str, found: &[(PathBuf, String)]) -> Result<(), RedirectorSetError> {
    if found.iter().all(|(_, id)| id == expected) {
        return Ok(());
    }
    Err(RedirectorSetError::Mismatch {
        expected: expected.to_string(),
        found: found.to_vec(),
    })
}

/// 1 本の DLL から刻印を読む。存在・読み取り・刻印の 3 段をそれぞれ別の理由として返す
/// ——「そろっていない」とだけ言われても、作り忘れなのか壊れているのかで次の手が違う。
pub fn read_build_id(path: &Path) -> Result<String, RedirectorSetError> {
    if !path.exists() {
        return Err(RedirectorSetError::Missing {
            path: path.to_path_buf(),
        });
    }
    let bytes = std::fs::read(path).map_err(|e| RedirectorSetError::Unreadable {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    extract_build_id(&bytes).map_err(|reason| RedirectorSetError::IdUnreadable {
        path: path.to_path_buf(),
        reason,
    })
}

/// Tier2a セッションを起こす前のゲート。x64 と x86 の**両方**が在り、互いに、そしてこの harness
/// 本体が期待する刻印と一致することを確かめる。
///
/// **3 者一致にしている理由**: x64 と x86 の 2 者だけを比べると「両方とも古い」組を通してしまう。
/// 本体を基準に入れると、`cargo build --workspace` が本体と x64 を必ず一緒に作り直す性質が
/// そのまま歯になる。
pub fn verify_redirector_set(x64: &Path, x86: &Path) -> Result<(), RedirectorSetError> {
    verify_redirector_set_against(x64, x86, EXPECTED_BUILD_ID)
}

/// [`verify_redirector_set`] の、**期待値を差し替えられる**版（テスト用）。
pub fn verify_redirector_set_against(
    x64: &Path,
    x86: &Path,
    expected: &str,
) -> Result<(), RedirectorSetError> {
    let found = vec![
        (x64.to_path_buf(), read_build_id(x64)?),
        (x86.to_path_buf(), read_build_id(x86)?),
    ];
    verify_ids(expected, &found)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ID_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    // ---- 許可側 ----

    /// **A4**: 2 本とも期待値と一致すれば通る。
    #[test]
    fn a_matching_pair_passes() {
        let found = vec![
            (PathBuf::from("x64.dll"), ID_A.to_string()),
            (PathBuf::from("x86.dll"), ID_A.to_string()),
        ];
        assert_eq!(verify_ids(ID_A, &found), Ok(()));
    }

    // ---- 拒否側 ----

    /// **D4**: 2 本の刻印が食い違う。エラー文に**両方のパスと両方の刻印**が出ること
    /// ——どちらが古いのかを人が判断できないと、直しようがない。
    #[test]
    fn a_mismatched_pair_is_reported_with_both_paths_and_both_ids() {
        let found = vec![
            (PathBuf::from("x64.dll"), ID_A.to_string()),
            (PathBuf::from("x86.dll"), ID_B.to_string()),
        ];
        let err = verify_ids(ID_A, &found).expect_err("a mismatched pair must not pass");
        let msg = err.to_string();
        assert!(msg.contains("x64.dll") && msg.contains("x86.dll"), "{msg}");
        assert!(msg.contains(ID_A) && msg.contains(ID_B), "{msg}");
        // **次に何を打てばよいかが出ること。** 以前はここで `i686-pc-windows-msvc` という
        // 綴りを測っていた——32bit 版を手で作る手順を案内していた頃の文面である。
        // 通常ビルドが作るようになったので綴りは変わったが、**測りたい性質は変わっていない**
        // ので、文面に assert を合わせるのではなく「打つコマンドが入っていること」を測る。
        assert!(msg.contains(REBUILD_HINT), "{msg}");
        assert!(REBUILD_HINT.contains("cargo build"), "{REBUILD_HINT}");
    }

    /// **両方とも古い**組は、2 者比較では通ってしまう。本体の期待値を基準にすると落ちる
    /// ——これが 3 者一致にしている理由そのもの。
    #[test]
    fn a_pair_that_agrees_with_each_other_but_not_with_harness_is_rejected() {
        let found = vec![
            (PathBuf::from("x64.dll"), ID_B.to_string()),
            (PathBuf::from("x86.dll"), ID_B.to_string()),
        ];
        assert!(verify_ids(ID_A, &found).is_err());
    }

    /// 実ファイルが無い場合は、読み取り失敗ではなく**不在**として区別して返る
    /// （作り忘れと破損で次の手が違う）。
    #[test]
    fn a_missing_file_is_reported_as_missing_not_unreadable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(X86_DLL_FILENAME);
        match read_build_id(&path) {
            Err(RedirectorSetError::Missing { path: p }) => assert_eq!(p, path),
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    /// **実際に配置されている DLL**を、このテストバイナリが期待する刻印と突き合わせる。
    ///
    /// 開発中に効かせたい歯はここである——x64 だけ作り直して x86 を忘れると、この 1 本が
    /// 赤くなる（実機テストを回さなくても、昇格しなくても分かる）。
    ///
    /// **不在も食い違いも落とす。** かつてここは「不在ならスキップ」していた——x86 を手で
    /// ビルドする時代には、まだ一度も作っていない機（新しいクローン）で赤くしても
    /// 意味が無かったからである。**その前提が消えた**: `harness-sandbox` の build script が
    /// 必ず作って置くようになったので、不在は「新しいクローン」ではなく
    /// **「置く仕掛けが働かなかった」**を意味する。スキップで通すと、それを隠すだけになる。
    ///
    /// Windows 以外では配置そのものを行わないので、このテストは Windows だけで動く。
    #[cfg(windows)]
    #[test]
    fn the_redirector_dlls_deployed_next_to_this_test_binary_are_not_stale() {
        let exe = std::env::current_exe().expect("current_exe");
        let dir = exe.parent().expect("current_exe has a parent");
        let x64 = dir.join("harness_redirector.dll");
        let x86 = dir.join(X86_DLL_FILENAME);
        assert!(
            x64.exists() && x86.exists(),
            "the redirector DLLs are not deployed next to {} (x64 present: {}, x86 present: {}). \
             The harness-sandbox build script is supposed to place the 32bit one; the 64bit one \
             comes from the ordinary build of harness-redirector. Build with: {REBUILD_HINT}",
            dir.display(),
            x64.exists(),
            x86.exists()
        );
        if let Err(e) = verify_redirector_set(&x64, &x86) {
            panic!("the deployed redirector DLLs do not match this build: {e}");
        }
    }

    /// この harness 本体に焼かれた期待値が、走査側が要求する形（64 桁の小文字 16 進）に
    /// なっていること。ここがずれると、**どんな DLL も一致しなくなる**。
    #[test]
    fn the_expected_build_id_baked_into_this_binary_is_well_formed() {
        assert_eq!(EXPECTED_BUILD_ID.len(), BUILD_ID_HEX_LEN);
        assert!(EXPECTED_BUILD_ID
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    }
}
