//! 「workspace相対パスとして受け付けてよい形か」の判定（純粋関数。FSもOSも触らない）。
//!
//! **なぜこのクレートに置くのか**: 同じ判定が2箇所で要る。
//!
//! 1. `harness_sandbox::check_relative_path`（cap-stdジェイルの早期リジェクト）
//! 2. `SandboxFs::apply`（CoW操作台帳のエントリを実FSへ反映する直前）
//!
//! そして2の入力である`.harness-cow-ops.jsonl`は**diff_layer_dir配下にあり、サンドボックス子へ
//! 書込可能として渡されている**（`preflight`の`grant_ace_inheritable_rw(diff_layer_dir, diff_layer_cap)`。
//! 宛先は差分層ごとのcapability SIDだが、**子から書けるという事実はどちらでも変わらない**）。
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

/// workspace相対パスとしての形を検査し、**正規形**を返す。
///
/// 拒否するもの:
///
/// - 絶対パス（`C:\...`・`/etc/...`）
/// - UNC前置（`\\server\share`・`//server/share`）
/// - `..`成分（**正規化して畳むのではなく拒否する**。`x/../.git/config`のように、
///   畳むと別物になる値を後段へ渡さないため——これがBUG-062のD-09迂回の実体だった）
/// - 代替データストリーム構文（成分に`:`を含む）
/// - Windows予約デバイス名（`NUL.txt`のように拡張子付きも対象）
/// - **成分末尾のドット・スペース**（`.git.`・`.git `）。Win32のパス正規化はこれらを
///   落とすので、文字列としては別物なのに実FS上は同じ場所を指す。層ごとに落とす/落とさないが
///   食い違うと迂回の余地になるため、**曖昧な表記そのものを拒否する**（実測では
///   「書込側は落とすが読取側は落とさない」という不一致で偶然fail-closeしていた。
///   偶然に頼らない）
///
/// **返すのは正規形**（`.`成分を取り除いたもの）である点が重要。`././.git/config`のような
/// 値を素通ししていたため、`is_config_injection_path`（`./`を1回しか剥がさない）が
/// D-09のhard-denyを取りこぼしていた。呼び出し側は**戻り値の方**を後段の判定とFS操作の
/// 両方に使うこと——元の文字列を判定に使うと同じ穴が再生産される。
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
    let mut canonical = PathBuf::new();
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
                if s.ends_with('.') || s.ends_with(' ') {
                    return Err(PathRejection::Unsafe(format!(
                        "a path component may not end with a dot or a space (Win32 strips them, \
                         so the spelling is ambiguous): {s}"
                    )));
                }
                canonical.push(part);
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
            // `.`は正規形から取り除く（後段の前置詞一致を`././`で欺けないようにする）。
            Component::CurDir => {}
        }
    }
    if canonical.as_os_str().is_empty() {
        return Err(PathRejection::Unsafe(format!(
            "path has no usable component: {path}"
        )));
    }
    Ok(canonical)
}

/// NTパス／Win32拡張長パスの前置（`\??\`・`\\?\`）を剥がす。
///
/// Redirector DLL（`ntpath::strip_nt_prefix`）とhost側の照合が**同じ規則**で前置を落とすために
/// ここへ置く（[BUG-066](../../../docs/bugs/BUG-066.md)。`std::fs::canonicalize`が返す
/// verbatim形と、アプリが渡す素のDOS形が混ざる経路が複数ある）。
pub fn strip_verbatim_prefix(path: &str) -> &str {
    path.strip_prefix(r"\??\")
        .or_else(|| path.strip_prefix(r"\\?\"))
        .unwrap_or(path)
}

/// CoWのルート（workspace_root・diff_layer_dir）の綴りを揃える: `\??\`/`\\?\`前置を落とし、
/// 末尾の余分な区切りを落とす（`C:\`のようなドライブルートは保つ）。
///
/// [`relative_under_root`]は照合時にこれらの揺れを吸収するが、**綴りは揃えておかないと
/// 別の場所で壊れる**——例えば`\\?\`付きのdiff_layer_dirを`nt_path_wide`が組み立てると
/// `\??\\\?\C:\...`という不正なNTパスになる。設定を渡す側（`spawn`のenv/blob）と受け取る側
/// （Redirector DLLの`resolve_config`）が同じ関数で揃える（[BUG-066](../../../docs/bugs/BUG-066.md)）。
pub fn normalize_root_spelling(root: &str) -> String {
    let mut s = strip_verbatim_prefix(root).to_string();
    while s.len() > 1
        && (s.ends_with('\\') || s.ends_with('/'))
        && !s.ends_with(":\\")
        && !s.ends_with(":/")
    {
        s.pop();
    }
    s
}

/// パス文字列を比較用に畳み込む: `\??\`/`\\?\`前置を落とし、`/`を`\`へ統一し、ASCII小文字化する。
///
/// **`to_lowercase`（Unicode版）は使わない**——小文字化でバイト長が変わる文字があり
/// （例: `İ`は2バイトの`i̇`になる）、[`relative_under_root`]が「正規化後のバイト位置＝元の
/// 文字列のバイト位置」として相対部分を切り出す前提が壊れる。`to_ascii_lowercase`はASCII以外を
/// 素通しするので長さが保存される（日本語を含むパスでも安全）。ASCII以外の大小差を吸収しない点は
/// 既存の`workspace_relative`と同じ挙動である。
///
/// `harness-cognition`のRecall機構（`plans/PLAN-RECALL-MEMORY.md`）がworkspace-key（記憶ディレクトリ
/// 名の元になる綴りの畳み込み）にもこの関数を再利用する——独自実装すると、ここで踏んだ
/// `to_lowercase`の罠を再び踏みかねない（`bug-pattern-rules` B-05: 参照できるものを複製しない）。
pub fn fold_for_comparison(s: &str) -> String {
    strip_verbatim_prefix(s)
        .replace('/', "\\")
        .to_ascii_lowercase()
}

/// [`fold_for_comparison`]の**対**。違いは区切りを寄せる向きだけで、`/`へ統一する。
///
/// # なぜ向きの違う2つが要るのか
///
/// **正規表現のパターンと突き合わせる軸があるためである。** `\`は正規表現のescape文字なので、
/// パターン文字列の中では「区切りの`\`」と「escapeの`\`」を文字列上で区別できない。
/// そこで遷移MACのパターン言語は**区切りを`/`に固定**し、パターン側は一切正規化せず、
/// **入力側だけをこの関数で畳む**と決めている（正本は
/// `plans/DESIGN-MAC-TRANSITION-POLICY.md` §19.3.9と`plans/DESIGN-MAC-BROKER.md` §22.5）。
///
/// [`fold_for_comparison`]の向き（`\`）はRedirector DLLとの綴り合わせが文脈なので、
/// **どちらかへ寄せて1本にはできない**。**だから対にして同じ場所へ置く**——
/// 離して置くと、片方だけが`to_lowercase`の罠へ戻る（`bug-pattern-rules` B-05）。
///
/// `to_ascii_lowercase`を使う理由は[`fold_for_comparison`]と同一である（長さが保存される）。
/// **ただしこちらは相対部分の切り出しに使われないので、長さ保存に依存しているのは
/// あちらだけである**——同じ関数を選んでいるのは、2つの畳み込みの結果が
/// **区切り以外で食い違わないようにする**ためである。
pub fn fold_for_pattern_comparison(s: &str) -> String {
    strip_verbatim_prefix(s)
        .replace('\\', "/")
        .to_ascii_lowercase()
}

/// `path`が`root`配下（または`root`自身）なら、`root`からの相対部分を`/`区切りで返す
/// （`root`自身なら空文字列）。配下でなければ`None`。
///
/// **「配下かどうかの判定」と「相対部分の算出」を必ず1つの規則で行う**のがこの関数の要点で、
/// [BUG-066](../../../docs/bugs/BUG-066.md)の実体はここが分かれていたことだった——旧
/// `harness-redirector`の`workspace_relative`は、配下判定を小文字化した文字列の前置詞一致で
/// 行いながら、相対部分を`Path::strip_prefix`（**成分単位・case-sensitive**）で求めていた。
/// 大小が1文字違うだけで「配下と判定したのに相対パスを作れない」状態になり、呼び出し側からは
/// **workspace外と区別が付かない**（＝CoWのリダイレクトが黙って止まり、ACL拒否だけが残る）。
///
/// 吸収する表記ゆれ:
///
/// - 大文字小文字（Windowsのパスは大小を区別しない）
/// - `/`と`\`の混在（Win32層はどちらも区切りとして受ける）
/// - `root`末尾の余分な区切り（`C:\ws\`と`C:\ws`を同じものとして扱う）
/// - `\??\`・`\\?\`前置（`strip_verbatim_prefix`）
///
/// 吸収**しない**もの: `..`・`.`成分（畳むと別物になり得るのでここでは解決しない。相対部分を
/// 台帳キーとして使う側は[`validate_relative_path`]を別途通すこと）、8.3短縮名、
/// シンボリックリンク／ジャンクション（実FSを触らないと解決できない。ここは純粋関数）。
pub fn relative_under_root(path: &str, root: &str) -> Option<String> {
    let normalize = fold_for_comparison;
    let path_n = normalize(path);
    let root_n = {
        let mut r = normalize(root);
        while r.len() > 1 && r.ends_with('\\') {
            r.pop();
        }
        r
    };
    if root_n.is_empty() {
        return None;
    }
    if path_n == root_n {
        return Some(String::new());
    }
    // 区切り境界の確認（`C:\ws`が`C:\ws2\x`へ前置詞一致してしまうのを防ぐ）。上で末尾の
    // 区切りを落としてあるので通常は境界1文字分ずらす。`root`が区切り1文字だけ（`\`）の
    // 場合だけは落としていないのでずらさない。
    let boundary = if root_n.ends_with('\\') { 0 } else { 1 };
    if !path_n.starts_with(&root_n) {
        return None;
    }
    if boundary == 1 && path_n.as_bytes().get(root_n.len()) != Some(&b'\\') {
        return None;
    }
    // 相対部分は**元の綴りから**切り出す（台帳キーの大小を勝手に潰さないため）。正規化は
    // 区切り文字を`\`へ1:1で置換しているだけなので、バイト位置は元の文字列と一致する
    // （`strip_verbatim_prefix`で落とした分だけずらす）。
    let stripped_len = path.len() - strip_verbatim_prefix(path).len();
    let start = stripped_len + root_n.len() + boundary;
    let rel = path.get(start..)?.replace('\\', "/");
    let rel = rel.trim_start_matches('/').to_string();
    Some(rel)
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

    /// 2つの畳み込みは**区切りの向き以外では食い違わない**。
    ///
    /// 片方だけが`to_lowercase`（Unicode版）へ差し替えられる等の分岐が起きると、同じ入力が
    /// 軸をまたいだ瞬間に別物になる。**その差を1本で固定しておく**——区切りを揃え直せば
    /// 完全に一致することを見る（`bug-pattern-rules` B-05: 複製した綴りが静かにずれないか）。
    #[test]
    fn the_two_folds_differ_only_in_separator_direction() {
        for input in [
            r"\\?\C:\Users\Me\Proj\A.PY",
            r"\??\C:/Users/Me/Proj/a.py",
            "C:/Proj/日本語/Script.PY",
            r"C:\Proj\mixed/Sep\x.EXE",
        ] {
            let back = fold_for_comparison(input);
            let fwd = fold_for_pattern_comparison(input);
            assert_eq!(
                back.replace('\\', "/"),
                fwd,
                "the two folds disagree beyond the separator for {input:?}"
            );
            assert!(!fwd.contains('\\'), "pattern fold left a backslash: {fwd}");
            assert!(!back.contains('/'), "comparison fold left a slash: {back}");
        }
    }

    /// verbatim接頭辞の落とし方も共有していること（片方だけが残すと、パターン側の
    /// `c:/…`が`\\?\c:/…`に当たらなくなる）。
    #[test]
    fn the_pattern_fold_strips_the_verbatim_prefix_like_its_pair() {
        assert_eq!(fold_for_pattern_comparison(r"\\?\C:\X"), "c:/x");
        assert_eq!(fold_for_pattern_comparison(r"\??\C:\X"), "c:/x");
    }

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

    /// **`.`成分は正規形から落とす。** 落とさずに素通しすると、後段の
    /// `is_config_injection_path`（`./`を1回しか剥がさない）が`././.git/config`を
    /// 取りこぼす（実測で確認したD-09迂回）。
    #[test]
    fn current_dir_components_are_removed_from_the_canonical_form() {
        assert_eq!(
            validate_relative_path("././.git/config").unwrap(),
            PathBuf::from(".git").join("config")
        );
        assert_eq!(
            validate_relative_path("./a.txt").unwrap(),
            PathBuf::from("a.txt")
        );
        assert_eq!(
            validate_relative_path("a/./b/./c.txt").unwrap(),
            PathBuf::from("a").join("b").join("c.txt")
        );
    }

    /// 成分が`.`だけになる値は「使える成分が無い」として拒否する
    /// （空パスをFS操作へ渡さない）。
    #[test]
    fn a_path_made_only_of_current_dir_components_is_rejected() {
        assert!(matches!(
            validate_relative_path("."),
            Err(PathRejection::Unsafe(_))
        ));
        assert!(matches!(
            validate_relative_path("./././"),
            Err(PathRejection::Unsafe(_))
        ));
    }

    /// **末尾のドット・スペースは拒否する。** Win32のパス正規化はこれらを落とすので、
    /// 文字列としては別物なのに実FS上は同じ場所を指す。実測では「書込側は落とすが
    /// cap-stdの読取側は落とさない」という層間の不一致で偶然fail-closeしていたが、
    /// 偶然に頼らず表記そのものを拒否する。
    #[test]
    fn components_ending_with_a_dot_or_space_are_rejected_as_ambiguous() {
        for p in [".git./config", ".git /config", "a/b./c", "trailing "] {
            assert!(
                matches!(validate_relative_path(p), Err(PathRejection::Unsafe(_))),
                "expected {p} to be rejected as an ambiguous spelling"
            );
        }
        // 途中のドットは普通のファイル名なので通す。
        assert!(validate_relative_path("a.b/c.txt").is_ok());
        assert!(validate_relative_path(".gitignore").is_ok());
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

    #[test]
    fn strip_verbatim_prefix_removes_nt_and_win32_long_path_prefixes() {
        assert_eq!(strip_verbatim_prefix(r"\??\C:\ws\a.txt"), r"C:\ws\a.txt");
        assert_eq!(strip_verbatim_prefix(r"\\?\C:\ws\a.txt"), r"C:\ws\a.txt");
        assert_eq!(strip_verbatim_prefix(r"C:\ws\a.txt"), r"C:\ws\a.txt");
    }

    #[test]
    fn normalize_root_spelling_drops_verbatim_prefix_and_trailing_separators() {
        assert_eq!(normalize_root_spelling(r"\\?\C:\ws\"), r"C:\ws");
        assert_eq!(normalize_root_spelling(r"\??\C:\ws"), r"C:\ws");
        assert_eq!(normalize_root_spelling(r"C:\ws\\"), r"C:\ws");
        assert_eq!(normalize_root_spelling("C:/ws/"), "C:/ws");
        // ドライブルートは区切りを保つ（`C:`はドライブ相対パスという別物になるため）。
        assert_eq!(normalize_root_spelling(r"C:\"), r"C:\");
        assert_eq!(normalize_root_spelling(r"\\?\C:\"), r"C:\");
    }

    /// **BUG-066の回帰テスト（核心）**: 「配下と判定できる形」は全て相対パスまで返り切ること。
    /// 旧実装は配下判定を小文字化した文字列で、相対部分の算出を`Path::strip_prefix`
    /// （成分単位・case-sensitive）で行っていたため、この表のうち大小差の行で
    /// **配下なのに`None`**を返し、呼び出し側がworkspace外と誤認していた。
    #[test]
    fn relative_under_root_absorbs_case_separator_trailing_and_verbatim_spellings() {
        let cases = [
            (r"C:\ws\a.txt", r"C:\ws", "a.txt"),
            // 大文字小文字違い（両方向）。
            (r"C:\WS\A.txt", r"C:\ws", "A.txt"),
            (r"c:\ws\a.txt", r"C:\WS", "a.txt"),
            // root末尾の余分な区切り。
            (r"C:\ws\a.txt", r"C:\ws\", "a.txt"),
            // 区切り文字の混在。
            ("C:/ws/sub/a.txt", r"C:\ws", "sub/a.txt"),
            (r"C:\ws\sub\a.txt", "C:/ws", "sub/a.txt"),
            // verbatim前置（どちら側に付いていても）。
            (r"\??\C:\ws\a.txt", r"C:\ws", "a.txt"),
            (r"C:\ws\a.txt", r"\\?\C:\ws", "a.txt"),
            (r"\\?\C:\ws\a.txt", r"\??\C:\ws", "a.txt"),
            // ドライブルート直下（rootの末尾が既に区切り）。
            (r"C:\a.txt", r"C:\", "a.txt"),
        ];
        for (path, root, expected) in cases {
            assert_eq!(
                relative_under_root(path, root).as_deref(),
                Some(expected),
                "path={path:?} root={root:?}"
            );
        }
    }

    #[test]
    fn relative_under_root_returns_empty_for_the_root_itself() {
        assert_eq!(relative_under_root(r"C:\ws", r"C:\ws").as_deref(), Some(""));
        assert_eq!(
            relative_under_root(r"C:\ws\", r"C:\ws").as_deref(),
            Some("")
        );
    }

    /// 前置詞一致だけでは配下と誤認する形（区切り境界の確認）と、そもそも配下でない形。
    #[test]
    fn relative_under_root_rejects_paths_outside_the_root() {
        assert_eq!(relative_under_root(r"C:\ws2\a.txt", r"C:\ws"), None);
        assert_eq!(relative_under_root(r"C:\wsx", r"C:\ws"), None);
        assert_eq!(relative_under_root(r"D:\ws\a.txt", r"C:\ws"), None);
        assert_eq!(relative_under_root(r"C:\other\a.txt", r"C:\ws"), None);
        // 相対パスのroot（`--cwd .`相当）は照合の基準にならない＝配下と言い切れない。
        assert_eq!(relative_under_root(r"C:\ws\a.txt", "."), None);
        assert_eq!(relative_under_root(r"C:\ws\a.txt", ""), None);
    }

    /// ASCII以外を含むパスでも、相対部分がバイト位置ずれで壊れないこと
    /// （`to_lowercase`ではなく`to_ascii_lowercase`を使っている理由の固定）。
    #[test]
    fn relative_under_root_handles_non_ascii_paths_without_corrupting_the_tail() {
        assert_eq!(
            relative_under_root(r"C:\ユーザー\ws\メモ.txt", r"C:\ユーザー\ws").as_deref(),
            Some("メモ.txt")
        );
    }

    /// [BUG-066](../../../docs/bugs/BUG-066.md)で壊れていた**旧規則**の再現（characterization）。
    ///
    /// 配下判定は小文字化した文字列の前置詞一致、相対部分の算出は`Path::strip_prefix`
    /// （成分単位・**case-sensitive**）という、規則が2つに割れた実装。当時の
    /// `harness-redirector`の`workspace_relative`そのもの。
    fn legacy_workspace_relative(root: &str, path: &str) -> Option<String> {
        let path_lc = path.to_ascii_lowercase();
        let root_lc = root.to_ascii_lowercase();
        let is_under = path_lc == root_lc
            || (path_lc.starts_with(&root_lc)
                && path_lc.as_bytes().get(root_lc.len()) == Some(&b'\\'));
        if !is_under {
            return None;
        }
        Path::new(path)
            .strip_prefix(Path::new(root))
            .ok()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
    }

    /// **BUG-066の追加検証（2026-08-06）**: 候補だった4つの綴りについて、旧規則が何を返し、
    /// 新規則が何を返すかを表として固定する。
    ///
    /// 2026-08-05のセッションで`HARNESS_COW_WORKSPACE`がどの綴りだったかは残存証跡からは
    /// **特定できない**（4形とも同じ症状＝workspace内の絶対パス書込が全滅、を作れる）。
    /// このテストの目的は犯人特定ではなく、**4形すべてが旧規則で壊れていたこと**と
    /// **新規則では壊れないこと**を実行可能な形で残すことにある。
    ///
    /// 相対パス（`--cwd .`）だけは**新規則でも`None`**である点が他の3つと違う——絶対パスと
    /// 相対パスは照合しようがないので、ここは判定規則ではなく上流の正規化
    /// （`spawn::normalize_cow_root`の`canonicalize`）と、DLL側の警告
    /// （`config_workspace_not_absolute`）が守る領域である。
    #[test]
    fn bug066_spelling_matrix_legacy_rule_breaks_on_all_four_new_rule_does_not() {
        const PATH: &str = r"C:\ws\merge-demo.txt";
        // (綴りの説明, workspace_rootの綴り, 新規則の期待)
        let cases: [(&str, &str, Option<&str>); 4] = [
            ("case difference", r"C:\WS", Some("merge-demo.txt")),
            ("trailing separator", r"C:\ws\", Some("merge-demo.txt")),
            ("verbatim prefix", r"\\?\C:\ws", Some("merge-demo.txt")),
            // 相対パスは新規則でも照合できない（＝上流の正規化と警告で守る領域）。
            ("relative root", ".", None),
        ];
        for (label, root, expected_new) in cases {
            assert_eq!(
                legacy_workspace_relative(root, PATH),
                None,
                "{label}: 旧規則はここで`None`を返していた（＝workspace外と同じ扱いになり、\
                 素通し→read-only ACLで拒否。CoWの透過性が黙って消える）"
            );
            assert_eq!(
                relative_under_root(PATH, root).as_deref(),
                expected_new,
                "{label}: 新規則の期待値"
            );
        }
        // 制御群: 綴りが完全に一致していれば旧規則でも通っていた（＝壊れていたのは表記ゆれの
        // ときだけであり、CoW全体が常に壊れていたわけではないことの確認）。
        assert_eq!(
            legacy_workspace_relative(r"C:\ws", PATH).as_deref(),
            Some("merge-demo.txt")
        );
    }

    /// 相対部分は**元の綴りのまま**返す（台帳キーの大小を勝手に潰さない）。
    #[test]
    fn relative_under_root_preserves_the_original_spelling_of_the_tail() {
        assert_eq!(
            relative_under_root(r"C:\WS\Sub\MixedCase.TXT", r"c:\ws").as_deref(),
            Some("Sub/MixedCase.TXT")
        );
    }
}
