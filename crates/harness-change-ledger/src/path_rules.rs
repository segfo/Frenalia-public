//! 「workspace相対パスとして受け付けてよい形か」の判定（純粋関数。FSもOSも触らない）。
//!
//! **なぜこのクレートに置くのか**: 同じ判定が2箇所で要る。
//!
//! 1. `harness_sandbox::check_relative_path`（cap-stdジェイルの早期リジェクト）
//! 2. `SandboxFs::apply`（CoW操作台帳のエントリを実FSへ反映する直前）
//!
//! そして2の入力である`.harness-cow-ops.jsonl`は**upper_dir配下にあり、サンドボックス子へ
//! 書込可能として渡されている**（`preflight`の`grant_ace_inheritable_rw(upper_dir, sid)`）。
//! [P-01](../../../docs/SECURITY-PRINCIPLES.md)の下では、台帳の内容はharnessが信用してよい
//! 入力ではない——子はRedirector DLLのフックを経由せず、直接好きなJSON行を追記できる。
//! したがって信頼側の`apply`は、jailと**同じ判定**を通さなければならない
//! （[BUG-062](../../../docs/bugs/BUG-062.md)）。
//!
//! 判定の実体をここへ置いて`harness-sandbox`側を薄い層にするのは、依存の向きの都合である
//! ——このクレートはRedirector DLL（`harness-redirector`）も参照するので`harness-sandbox`へは
//! 依存できない。逆向きに同じ判定を書くと片方だけ更新されて食い違う
//! （`docs/CODE-STRUCTURE-RULES.md`規則5。[BUG-042](../../../docs/bugs/BUG-042.md)が
//! まさに「同じ計算を2箇所で独立に育てた」事故だった）。
//!
//! **この判定は安全性の根拠そのものではない**。主ゲートはcap-stdの`Dir`からの相対open
//! （openat相当）であり、ここが担うのは早期リジェクトである（`harness-sandbox`の
//! モジュールdoc「主ゲートはcap-std」と同じ位置付け）。ただし`apply`のように
//! **実FSへ触る前に文字列で弾けるものは弾いておく**ことで、`is_config_injection_path`の
//! ような後段の判定が「正規化済みの相対パスしか来ない」という前提を持てるようになる。

use std::path::{Component, Path, PathBuf};

/// 相対パスとして受け付けられなかった理由。
///
/// `harness-sandbox`側が`JailError`（`thiserror`）へ写すため、ここでは依存を増やさず
/// 素の列挙で持つ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathRejection {
    /// jail/workspaceの外へ出る形（絶対パス・`..`）。
    Escape,
    /// 形として受け付けない（UNC前置・ADS構文・Windows予約デバイス名）。理由の文言を持つ。
    Unsafe(String),
}

/// workspace相対パスとしての形だけを検査する。
///
/// 拒否するもの:
///
/// - 絶対パス（`C:\...`・`/etc/...`）
/// - UNC前置（`\\server\share`・`//server/share`）
/// - `..`成分（**正規化して畳むのではなく拒否する**。`x/../.git/config`のように、
///   畳むと別物になる値を後段へ渡さないため——これがBUG-062のD-09迂回の実体だった）
/// - 代替データストリーム構文（成分に`:`を含む）
/// - Windows予約デバイス名（`NUL.txt`のように拡張子付きも対象）
pub fn validate_relative_path(path: &str) -> Result<PathBuf, PathRejection> {
    let rel = Path::new(path);
    // UNCは`is_absolute()`より**先**に見る。Windowsでは`\\server\share`もUNC prefix付きの
    // 絶対パスとして`is_absolute() == true`になるので、後ろに置くと素通りして（＝この分岐が
    // 死んで）「UNCを名指しで拒否している」という見た目だけが残る。拒否されること自体は
    // どちらでも同じだが、**理由の文言が変わる**のでUNCと分かる側を優先する。
    if path.starts_with("\\\\") || path.starts_with("//") {
        return Err(PathRejection::Unsafe(format!(
            "UNC path is not allowed: {path}"
        )));
    }
    if rel.is_absolute() {
        return Err(PathRejection::Escape);
    }
    for c in rel.components() {
        match c {
            Component::ParentDir => return Err(PathRejection::Escape),
            Component::Normal(part) => {
                let s = part.to_string_lossy();
                if s.contains(':') {
                    return Err(PathRejection::Unsafe(format!(
                        "alternate data stream syntax is not allowed: {s}"
                    )));
                }
                if is_reserved_windows_name(&s) {
                    return Err(PathRejection::Unsafe(format!(
                        "reserved device name is not allowed: {s}"
                    )));
                }
            }
            // **`is_absolute()`だけでは足りない**（Windows）。`Path::is_absolute`は
            // 「prefix（`C:`）とroot（`\`）の両方がある」ことを要求するので、次の2つは
            // どちらも`false`を返しながら、`join`すると相対パスとして扱われない:
            //
            // - `/Windows/System32/x`（root付き・prefix無し）
            //   → `PathBuf::push`は「rootはあるがprefixが無いパス」に対し、
            //     **prefixだけ残して後を全部置き換える**。`C:\ws`.join("/Windows/x")は
            //     `C:\Windows\x`＝**ドライブルートからの脱出**になる。
            // - `C:foo`（prefix付き・root無し＝ドライブ相対）
            //   → `push`はprefixごと置き換える。
            //
            // どちらもworkspace相対パスではないので拒否する。
            Component::Prefix(_) | Component::RootDir => return Err(PathRejection::Escape),
            Component::CurDir => {}
        }
    }
    Ok(rel.to_path_buf())
}

/// Windowsの予約デバイス名（大小・拡張子を無視、`NUL.txt`も対象）。
fn is_reserved_windows_name(name: &str) -> bool {
    let base = name.split('.').next().unwrap_or(name);
    matches!(
        base.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_relative_paths() {
        for p in ["a.txt", "sub/dir/a.txt", "./a.txt", "a-b_c.1.txt"] {
            assert!(validate_relative_path(p).is_ok(), "expected ok for {p}");
        }
    }

    #[test]
    fn rejects_absolute_and_unc() {
        assert_eq!(
            validate_relative_path("/etc/passwd"),
            Err(PathRejection::Escape)
        );
        assert!(matches!(
            validate_relative_path(r"\\server\share\f"),
            Err(PathRejection::Unsafe(_))
        ));
        assert!(matches!(
            validate_relative_path("//server/share/f"),
            Err(PathRejection::Unsafe(_))
        ));
    }

    /// **BUG-062の核心**: `..`は畳まずに拒否する。畳んでしまうと
    /// `is_config_injection_path`のような前置詞一致の判定が別物を見ることになる。
    #[test]
    fn rejects_any_parent_dir_segment_including_ones_that_stay_inside() {
        for p in [
            "../escape.txt",
            "../../escape.txt",
            "x/../.git/config",
            "a/b/../../../out.txt",
            // 畳むとworkspace内へ戻る形も拒否する（畳んだ結果に依存しない判定にするため）。
            "a/../b.txt",
        ] {
            assert_eq!(
                validate_relative_path(p),
                Err(PathRejection::Escape),
                "expected escape for {p}"
            );
        }
    }

    #[test]
    fn rejects_alternate_data_streams_and_reserved_names() {
        assert!(matches!(
            validate_relative_path("a.txt:hidden"),
            Err(PathRejection::Unsafe(_))
        ));
        assert!(matches!(
            validate_relative_path("NUL.txt"),
            Err(PathRejection::Unsafe(_))
        ));
        assert!(matches!(
            validate_relative_path("sub/con"),
            Err(PathRejection::Unsafe(_))
        ));
    }

    /// Windowsで`Path::is_absolute()`が`false`を返すのに、`join`すると相対扱いされない
    /// 2つの形。**この2つを`is_absolute()`だけに任せると`join`でworkspace外へ出る**
    /// （`C:\ws`.join("/Windows/x") == `C:\Windows\x`）。
    #[cfg(windows)]
    #[test]
    fn rejects_rooted_and_drive_relative_paths_that_is_absolute_calls_relative() {
        for p in ["/Windows/System32/x", r"\Windows\System32\x", "C:foo"] {
            assert!(
                !Path::new(p).is_absolute(),
                "{p} is expected to fool is_absolute() -- that is why this test exists"
            );
            assert_eq!(
                validate_relative_path(p),
                Err(PathRejection::Escape),
                "{p} must not be treated as workspace-relative"
            );
        }
        // 実際に join がどう振る舞うかを固定しておく（上の主張の根拠）。
        // clippyのlintは「区切り文字始まりのjoinは置換になる」と警告するが、
        // **その置換が起きること自体がここで証明したい事実**なので意図的に抑止する。
        #[allow(clippy::join_absolute_paths)]
        let joined = Path::new(r"C:\ws").join("/Windows/x");
        assert_eq!(joined, Path::new(r"C:\Windows\x"));
    }
}
