//! CoW セッションを起こしてよいかを、**Redirector DLL 2 本の版がそろっているか**で判定する。
//!
//! # 何を守っているか
//!
//! `--sandbox tier2a-cow`（ワークスペースを読み取り専用にして、書込を差分層へ横流しする方式）
//! では、透過役の DLL が 2 つの姿で使われる。64bit の子には `harness_redirector.dll` が、
//! 32bit（WOW64）の孫には `harness_redirector_x86.dll` が注入される。
//!
//! この 2 本は**別々に作られる**。x64 は `cargo build --workspace` が必ず作り直すが、x86 は
//! 別ターゲットの手動ビルドでしか生まれない（ワークスペースに `build.rs` は在るが、cargo に
//! 別アーキテクチャを同時にビルドさせる仕組みは無い）。したがって **x86 だけが古いまま残り得る**。
//!
//! 「無い」と「古い」では**古い方が悪い**。
//!
//! - **無い**: 注入が失敗し、読み取り専用 ACL が書込を拒む。透過性は失われるが安全側に倒れる。
//! - **古い**: 注入に**成功してしまう**。しかも親から子へ渡す設定
//!   （`harness-redirector` の `serialize_config_blob`）は位置依存のテキストで版タグを持たないため、
//!   将来その形が変わると古い DLL は知らない行を黙って捨てて動き続ける。エラーにならない。
//!
//! そこで、副作用を一切起こしていない段階で 2 本の版を検算し、そろわなければ**セッションごと
//! 起こさない**。自動的に弱いモードへ降格はしない（D-75。弱い器が要るなら `--sandbox` の値で
//! 明示的に選ぶ）。
//!
//! # この関所が守らないもの
//!
//! **同じ権限を持つローカル攻撃者**は防げない。x86 DLL を差し替えられる相手は、期待値を持つ
//! harness 本体も差し替えられるからである。これは D-44（昇格ヘルパーの整合性を署名ではなく
//! 配置の DACL で見ると決めた拘束的決定、`crate::elevated_launch`）で既に結論が出ている話で、
//! ここはその結論を変えない。**この関所が相手にしているのは攻撃者ではなく取り違え**
//! ——人がビルドし忘れた、頒布物の組み立てが半端だった、という事故である。事故は harness 本体を
//! 辻褄合わせに書き換えてくれないので、版の刻印は事故に対しては壊れない。

use std::path::{Path, PathBuf};

pub use harness_build_id::{BUILD_ID_HEX_LEN, BUILD_ID_MARKER};

/// この harness 本体が期待する刻印。build script が `harness-build-id` に計算させた値で、
/// 同じソースからビルドされた DLL には同じ値が入っている。
pub const EXPECTED_BUILD_ID: &str = env!("HARNESS_REDIRECTOR_BUILD_ID");

/// x86（WOW64 用）Redirector DLL の固定ファイル名。x64 の隣に置く規約
/// （`harness-redirector` 側の `x86_sibling_dll_path` と同じ綴り）。
pub const X86_DLL_FILENAME: &str = "harness_redirector_x86.dll";

/// 作り直すためのコマンド。**エラー文にそのまま出す**——「そろっていない」とだけ言われても
/// 次に何を打てばよいかが分からないと、利用者は関所を外す方へ動く。
pub const REBUILD_HINT: &str = "tools/build-redirector-x86.ps1 \
    (or: cargo build -p harness-redirector --target i686-pc-windows-msvc, then copy \
    target/i686-pc-windows-msvc/debug/harness_redirector.dll next to harness.exe as \
    harness_redirector_x86.dll)";

/// バイト列から刻印を取り出すときの失敗。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdError {
    /// 目印が無い、または目印はあっても後続が正しい形（64 桁の 16 進 + NUL）ではない。
    /// **形が壊れているものから刻印をでっち上げない**——でっち上げると、壊れた DLL が
    /// たまたま期待値と一致して素通りし得る。
    Missing,
    /// **相異なる**刻印が複数入っていた。どれが本物か決められないので通さない。
    /// 「先に見つかった方が勝ち」にすると、選び方次第で判定が変わる。
    Ambiguous(Vec<String>),
}

impl std::fmt::Display for IdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdError::Missing => write!(
                f,
                "no well-formed \"{BUILD_ID_MARKER}<{BUILD_ID_HEX_LEN} hex digits>\\0\" build-id \
                 marker was found"
            ),
            IdError::Ambiguous(ids) => write!(
                f,
                "found {} different build-id markers ({}); cannot decide which one identifies \
                 this file",
                ids.len(),
                ids.join(", ")
            ),
        }
    }
}

/// CoW セッションを起こしてよいかの判定に失敗した理由。
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
                "the CoW redirector DLL {} is missing, so 32bit (WOW64) descendants would run \
                 without transparent redirection. Refusing to start the session. Build it with: \
                 {REBUILD_HINT}",
                path.display()
            ),
            RedirectorSetError::Unreadable { path, reason } => write!(
                f,
                "the CoW redirector DLL {} could not be read ({reason}), so its version cannot be \
                 checked. Refusing to start the session.",
                path.display()
            ),
            RedirectorSetError::IdUnreadable { path, reason } => write!(
                f,
                "the CoW redirector DLL {} carries no usable build id ({reason}). It was probably \
                 built before build ids existed, which means it is older than this harness. \
                 Rebuild it with: {REBUILD_HINT}",
                path.display()
            ),
            RedirectorSetError::Mismatch { expected, found } => {
                write!(
                    f,
                    "the CoW redirector DLLs were not all built from this source tree. This \
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

/// バイト列を走査して刻印を取り出す。**PE を解析しない**ので、x64 と x86 の両方を同じコードで
/// 扱える（エクスポートテーブルの構造は 32bit と 64bit で違う）。
///
/// 目印の後ろが「64 桁の小文字 16 進」＋「NUL」になっているものだけを正当とみなす。
/// 目印の綴りだけが偶然含まれていても刻印としては拾わない。
pub fn extract_build_id(bytes: &[u8]) -> Result<String, IdError> {
    let marker = BUILD_ID_MARKER.as_bytes();
    let payload = BUILD_ID_HEX_LEN;
    let mut found: Vec<String> = Vec::new();

    let mut i = 0usize;
    // 終端の NUL を読むので、その添字（`i + marker.len() + payload`）が範囲内であることを要求する。
    while i + marker.len() + payload < bytes.len() {
        if &bytes[i..i + marker.len()] != marker {
            i += 1;
            continue;
        }
        let start = i + marker.len();
        let hex = &bytes[start..start + payload];
        let terminator = bytes[start + payload];
        let well_formed = terminator == 0
            && hex
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b));
        if well_formed {
            // 走査中に UTF-8 検証を挟まないよう、16 進であることを確かめた後で文字列化する。
            let id = String::from_utf8_lossy(hex).into_owned();
            if !found.contains(&id) {
                found.push(id);
            }
            // 同じ目印の内側から重ねて探さない。
            i = start + payload + 1;
        } else {
            i += 1;
        }
    }

    match found.len() {
        0 => Err(IdError::Missing),
        1 => Ok(found.remove(0)),
        _ => Err(IdError::Ambiguous(found)),
    }
}

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

/// CoW セッションを起こす前の関所。x64 と x86 の**両方**が在り、互いに、そしてこの harness
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

    /// 目印 + 刻印 + NUL を、前後に無関係なバイトを挟んで埋め込んだ「DLL もどき」を作る。
    fn blob_with(ids: &[&str]) -> Vec<u8> {
        let mut out: Vec<u8> = b"\x7fELF junk before".to_vec();
        for id in ids {
            out.extend_from_slice(BUILD_ID_MARKER.as_bytes());
            out.extend_from_slice(id.as_bytes());
            out.push(0);
            out.extend_from_slice(b"...unrelated section bytes...");
        }
        out.extend_from_slice(b"junk after");
        out
    }

    // ---- 許可側 ----

    /// **A1**: 正しい刻印が 1 個あれば取り出せる。
    #[test]
    fn a_single_well_formed_marker_is_extracted() {
        assert_eq!(extract_build_id(&blob_with(&[ID_A])), Ok(ID_A.to_string()));
    }

    /// **A2**: 同じ刻印が 2 回現れても曖昧ではない。コード生成の都合で文字列が重複することは
    /// あり、そこで落とすと**正しくビルドした DLL が弾かれる**。
    #[test]
    fn the_same_id_appearing_twice_is_not_ambiguous() {
        assert_eq!(
            extract_build_id(&blob_with(&[ID_A, ID_A])),
            Ok(ID_A.to_string())
        );
    }

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

    /// **D1**: 刻印がまったく無いバイト列。
    #[test]
    fn a_blob_without_any_marker_is_missing() {
        assert_eq!(
            extract_build_id(b"no marker here at all"),
            Err(IdError::Missing)
        );
    }

    /// **D2a**: 16 進が 63 桁しかない（＝目印の後ろの形が違う）。
    #[test]
    fn a_marker_with_too_few_hex_digits_is_rejected() {
        let mut blob = BUILD_ID_MARKER.as_bytes().to_vec();
        blob.extend_from_slice(&ID_A.as_bytes()[..63]);
        blob.push(0);
        blob.extend_from_slice(b"trailing bytes to keep the buffer long enough");
        assert_eq!(extract_build_id(&blob), Err(IdError::Missing));
    }

    /// **D2b**: 64 桁あるが NUL で終わっていない。
    #[test]
    fn a_marker_without_the_nul_terminator_is_rejected() {
        let mut blob = BUILD_ID_MARKER.as_bytes().to_vec();
        blob.extend_from_slice(ID_A.as_bytes());
        blob.extend_from_slice(b"XXXX not a terminator");
        assert_eq!(extract_build_id(&blob), Err(IdError::Missing));
    }

    /// **D2c**: 16 進でない文字が混ざる（大文字は不可＝綴りを 1 つに固定する）。
    #[test]
    fn a_marker_with_non_lowercase_hex_is_rejected() {
        let upper = ID_A.to_uppercase();
        assert_eq!(extract_build_id(&blob_with(&[&upper])), Err(IdError::Missing));
    }

    /// **D3**: 相異なる刻印が 2 つ。どちらが本物か決められないので通さない。
    #[test]
    fn two_different_ids_in_one_file_are_ambiguous() {
        match extract_build_id(&blob_with(&[ID_A, ID_B])) {
            Err(IdError::Ambiguous(ids)) => {
                assert_eq!(ids.len(), 2);
                assert!(ids.contains(&ID_A.to_string()) && ids.contains(&ID_B.to_string()));
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    /// **A3（誤検知側）**: 目印の綴りだけが在って中身が無い。**刻印をでっち上げない**こと。
    /// でっち上げると、壊れた DLL が偶然期待値と一致して素通りし得る。
    #[test]
    fn the_marker_spelling_alone_does_not_fabricate_an_id() {
        let mut blob = b"some bytes ".to_vec();
        blob.extend_from_slice(BUILD_ID_MARKER.as_bytes());
        blob.extend_from_slice(b" and then completely unrelated text that is not hex at all");
        assert_eq!(extract_build_id(&blob), Err(IdError::Missing));
    }

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
        // 次に何を打てばよいかが出ること。
        assert!(msg.contains("i686-pc-windows-msvc"), "{msg}");
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
    /// **「無い」と「食い違う」を区別する。** まだ一度も x86 をビルドしていない機（新しい
    /// クローン）で赤くしても意味が無いので、不在なら理由を出して抜ける。**食い違いは落とす**
    /// ——それが T-B が相手にしている事故そのものだからである。
    #[test]
    fn the_redirector_dlls_deployed_next_to_this_test_binary_are_not_stale() {
        let Ok(exe) = std::env::current_exe() else {
            eprintln!("skipping: current_exe() is unavailable");
            return;
        };
        let Some(dir) = exe.parent() else {
            eprintln!("skipping: current_exe() has no parent");
            return;
        };
        let x64 = dir.join("harness_redirector.dll");
        let x86 = dir.join(X86_DLL_FILENAME);
        if !x64.exists() || !x86.exists() {
            eprintln!(
                "skipping: the redirector DLLs are not deployed next to {} yet (x64 present: {}, \
                 x86 present: {}). Build them with: {REBUILD_HINT}",
                dir.display(),
                x64.exists(),
                x86.exists()
            );
            return;
        }
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
