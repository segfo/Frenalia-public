//! D-05（`plans/DESIGN-SANDBOX.md` §7）: 設定注入系hard-deny対象パス。
//! Tier1/Tier2b内でも解除しない。`harness-engine::permission::classify()`と
//! `harness-sandbox::overlay::apply()`の両方から参照する単一の情報源
//! （二重防御の両ゲートが同じ判定基準を持つことを保証するため、ここに集約する）。

/// hard-deny対象のパスprefix一覧。ディレクトリ系（末尾整理は`is_config_injection_path`側で行う）も
/// ファイル系も同じ配列に入れ、完全一致 or `"{prefix}/"`前方一致で判定する。
/// CI設定（`.github/workflows/`・`.gitlab-ci.yml`・`.circleci/`）はDESIGN-SANDBOX.md D-05が
/// 「CI設定」とのみ書いており逐語規定ではない。GitHub Actions・GitLab CI・CircleCIの主要3系統を
/// 対象とする解釈（ユーザー確認済み、BUG-008修正時点）。
const CONFIG_INJECTION_PREFIXES: &[&str] = &[
    ".git/config",
    ".git/hooks",
    ".git/info/exclude",
    ".gitattributes",
    ".harness",
    ".github/workflows",
    ".gitlab-ci.yml",
    ".circleci",
    ".vscode",
    ".devcontainer",
];

/// `path`が設定注入系hard-deny対象かどうかを判定する。
///
/// **`path`は相対でも絶対でもよい。** 絶対なら`workspace_root`からの相対へ畳んでから照合し、
/// 畳めない（＝ワークスペース外を指す）ものは対象外として`false`を返す——外への書込は
/// `--dangerously-allow`（`ApplyOptions::allow_ext`）という**別目的のゲート**が受け持つ。
///
/// **絶対パスを受けるようになったのは[BUG-126](../../../docs/bugs/BUG-126.md)である。**
/// 以前はworkspace相対しか想定しておらず、`c:/ws/.git/hooks/pre-commit`と綴るだけで
/// **二重防御の2枚が同時に抜けた**——層1（`harness-engine::permission::classify()`）と
/// 層3（`harness-sandbox::overlay::apply()`）が**同じ判定器を共有している**ため、
/// 判定器そのものに開いた穴は冗長性として働かない。
///
/// `\`を`/`に正規化した上で、各対象prefixについて完全一致または`"{prefix}/"`前方一致を見る
/// （単純な`starts_with(prefix)`だと`.vscode-instructions.md`のような別ファイルを誤検知するため）。
///
/// **大小を区別しない。** NTFS・APFSは既定で大小を区別しないので、区別する判定にすると
/// `.GIT/config`が素通りして実FS上は`.git/config`へ着地する（実測で確認した迂回。
/// `docs/bugs/BUG-062.md`と同じ「文字列としては別物だが同じ場所へ着地する」クラス）。
/// Linuxでは`.GIT`は本当に別のディレクトリなので、この判定は**過剰に拒否する**側へ倒れる
/// ——deny listでは安全な向きであり（P-05）、`.GIT`という名前を実際に使うリポジトリは
/// 事実上存在しない。
///
/// **正規化はこの関数の中で完結させる。** 呼び出し側が正規形を渡してくれる前提にしない
/// ——`harness-engine::permission::classify()`は**モデルが書いた文字列そのもの**を渡すので、
/// そこに正規化の責務を置くことができない（`SandboxFs`の検証はもっと後段にある）。
/// 実測で`././.git/config`が主ゲートを素通りしていた（[BUG-063](../../../docs/bugs/BUG-063.md)）。
///
/// `..`を含むパスは**着地点を静的に決められないので拒否側へ倒す**（P-05 fail-closed）。
/// 正当な`..`付き書込は`check_relative_path`が別途どのみち弾くため、実害のある過剰拒否は無い。
pub fn is_config_injection_path(path: &str, workspace_root: &std::path::Path) -> bool {
    let relative = if std::path::Path::new(path).is_absolute() {
        // `..`を含む絶対パスは畳んだ先が静的に決まらないので、rootとの照合をせずに拒否側へ倒す
        // （P-05 fail-closed）。相対パス側の`..`は下の`fold_components`が同じ向きで拾う。
        if contains_parent_component(path) {
            return true;
        }
        // **配下判定と相対部分の算出を1つの規則で行う**——別々にすると
        // 「配下と判定したのに相対パスを作れない」状態が生まれ、呼び出し側からは
        // workspace外と区別が付かない（[BUG-066](../../../docs/bugs/BUG-066.md)）。
        // 大小・区切りの混在・末尾区切り・`\\?\`前置はこの関数が吸収する。
        match harness_change_ledger::path_rules::relative_under_root(
            path,
            &workspace_root.to_string_lossy(),
        ) {
            Some(rel) if !rel.is_empty() => rel,
            // workspace外（またはroot自身）。**外への書込はこのゲートの担当ではない**
            // ——`--dangerously-allow`（`ApplyOptions::allow_ext`）が受け持つ。
            // ここで拒否すると`--fs-allow`で外部リポジトリを扱う運用を壊す（過剰拒否）。
            _ => return false,
        }
    } else {
        path.to_string()
    };
    let Some(normalized) = fold_components(&relative) else {
        return true;
    };
    CONFIG_INJECTION_PREFIXES.iter().any(|prefix| {
        let prefix = prefix.to_ascii_lowercase();
        normalized == prefix || normalized.starts_with(&format!("{prefix}/"))
    })
}

/// `..`成分を含むか。区切りの混在だけ吸収する（畳みはしない）。
fn contains_parent_component(path: &str) -> bool {
    path.replace('\\', "/").split('/').any(|p| p == "..")
}

/// 照合用の正規形へ畳む。`..`を含むなら`None`（＝着地点が静的に決まらないので拒否側へ）。
fn fold_components(path: &str) -> Option<String> {
    let lowered = path.replace('\\', "/").to_ascii_lowercase();
    let mut components: Vec<&str> = Vec::new();
    for part in lowered.split('/') {
        match part {
            // 空成分（`a//b`）と`.`は落とす。`./`を1回だけ剥がす実装だと`././`で欺ける。
            "" | "." => {}
            // 着地点が分からない以上、拒否側へ倒す。
            ".." => return None,
            // 末尾のドット・スペースはWin32が落とすので、落とした形で照合する
            // （`.git./config`が`.git/config`へ着地するため）。
            other => components.push(other.trim_end_matches(['.', ' '])),
        }
    }
    Some(components.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_all_d05_paths() {
        for p in [
            ".git/config",
            ".git/hooks/pre-commit",
            ".git/info/exclude",
            ".gitattributes",
            ".harness/settings.json",
            ".github/workflows/ci.yml",
            ".gitlab-ci.yml",
            ".circleci/config.yml",
            ".vscode/settings.json",
            ".devcontainer/devcontainer.json",
        ] {
            assert!(
                is_config_injection_path(p, std::path::Path::new("/workspace")),
                "expected match for {p}"
            );
        }
    }

    /// NTFS・APFSは大小を区別しないので、区別する判定だと`.GIT/config`が素通りして
    /// 実FS上は`.git/config`へ着地する（実測で確認した迂回、`docs/bugs/BUG-062.md`）。
    #[test]
    fn matching_is_case_insensitive_because_the_filesystem_is() {
        for p in [
            ".GIT/config",
            ".Git/Config",
            ".HARNESS/settings.json",
            ".GitAttributes",
            ".VSCode/settings.json",
        ] {
            assert!(
                is_config_injection_path(p, std::path::Path::new("/workspace")),
                "expected {p} to be hard-denied (the filesystem does not distinguish case)"
            );
        }
    }

    /// 正規化はこの関数の中で完結する（呼び出し側が正規形をくれる前提にしない）。
    /// `permission::classify()`はモデルが書いた文字列をそのまま渡すため。
    #[test]
    fn normalization_happens_here_not_in_the_caller() {
        // `./`は何回でも剥がす（1回だけの実装は`././`で欺ける＝BUG-063）。
        assert!(is_config_injection_path(
            "././.git/config",
            std::path::Path::new("/workspace")
        ));
        assert!(is_config_injection_path(
            "./././.harness/settings.json",
            std::path::Path::new("/workspace")
        ));
        // 空成分も落とす。
        assert!(is_config_injection_path(
            ".git//config",
            std::path::Path::new("/workspace")
        ));
        // 末尾のドット・スペースはWin32が落とすので、落とした形で照合する。
        assert!(is_config_injection_path(
            ".git./config",
            std::path::Path::new("/workspace")
        ));
        assert!(is_config_injection_path(
            ".git /config",
            std::path::Path::new("/workspace")
        ));
        // `..`は着地点が静的に決まらないので拒否側へ倒す（P-05）。
        assert!(is_config_injection_path(
            "x/../.git/config",
            std::path::Path::new("/workspace")
        ));
        assert!(is_config_injection_path(
            "../anything",
            std::path::Path::new("/workspace")
        ));
    }

    #[test]
    fn matches_bare_directory_and_file_entries() {
        assert!(is_config_injection_path(
            ".git/hooks",
            std::path::Path::new("/workspace")
        ));
        assert!(is_config_injection_path(
            ".harness",
            std::path::Path::new("/workspace")
        ));
        assert!(is_config_injection_path(
            ".vscode",
            std::path::Path::new("/workspace")
        ));
        assert!(is_config_injection_path(
            ".devcontainer",
            std::path::Path::new("/workspace")
        ));
        assert!(is_config_injection_path(
            ".circleci",
            std::path::Path::new("/workspace")
        ));
        assert!(is_config_injection_path(
            ".gitattributes",
            std::path::Path::new("/workspace")
        ));
    }

    #[test]
    fn does_not_false_positive_on_similarly_named_paths() {
        for p in [
            ".gitattributes-backup.txt",
            ".vscode-icons/x",
            "src/.harness-like/x",
            ".github/workflows-notes.md",
            ".circleci-notes/x",
        ] {
            assert!(
                !is_config_injection_path(p, std::path::Path::new("/workspace")),
                "unexpected match for {p}"
            );
        }
    }

    #[test]
    fn normal_workspace_paths_unaffected() {
        for p in ["src/main.rs", "Cargo.toml", "README.md", "docs/INDEX.md"] {
            assert!(
                !is_config_injection_path(p, std::path::Path::new("/workspace")),
                "unexpected match for {p}"
            );
        }
    }

    /// **[BUG-126]** 絶対パスはworkspace rootからの相対へ畳んでから照合する。
    /// 畳む前は「ドライブレターとワークスペースの分だけ先頭がずれて」一致しなかった。
    #[cfg(windows)]
    #[test]
    fn absolute_paths_inside_the_workspace_are_folded_before_matching() {
        let root = std::path::Path::new(r"C:\ws");
        for p in [
            "C:/ws/.git/hooks/pre-commit",
            r"C:\ws\.git\config",
            "c:/WS/.harness/settings.json",
            "C:/ws/./.vscode/settings.json",
            // `\\?\`前置も`relative_under_root`が吸収する
            r"\\?\C:\ws\.git\config",
            // rootの末尾区切りの有無で結果が変わらないこと
            "C:/ws/.gitattributes",
        ] {
            assert!(is_config_injection_path(p, root), "expected match for {p}");
        }
        assert!(is_config_injection_path(
            "C:/ws/.git/config",
            std::path::Path::new(r"C:\ws\")
        ));
    }

    /// **[BUG-126] 対（過剰拒否側）。** workspace外はこの判定器の担当ではない。
    /// **これが無いと「絶対パスなら全部true」でも上のテストが通る。**
    #[cfg(windows)]
    #[test]
    fn absolute_paths_outside_the_workspace_are_not_this_gates_business() {
        let root = std::path::Path::new(r"C:\ws");
        for p in [
            "D:/other-repo/.git/config",
            "C:/elsewhere/.harness/settings.json",
            // 文字列としては`C:\ws`で始まるが、区切り境界が違うので配下ではない
            "C:/ws2/.git/config",
            // root自身は書込対象のファイルではない
            "C:/ws",
        ] {
            assert!(
                !is_config_injection_path(p, root),
                "unexpected match for {p}"
            );
        }
    }

    /// **`..`を含む絶対パスは、rootとの照合をせずに拒否側へ倒す**（P-05）。
    /// 畳み込みを足したときにここが素通りへ倒れると、`d:/x/../y`のような綴りで
    /// **従来より弱くなる**（畳み込み導入前は`..`だけで拒否していた）。
    #[cfg(windows)]
    #[test]
    fn absolute_paths_with_parent_components_stay_fail_closed() {
        let root = std::path::Path::new(r"C:\ws");
        assert!(is_config_injection_path("D:/other/../x", root));
        assert!(is_config_injection_path("C:/ws/x/../.git/config", root));
    }

    /// Unix側でも同じ規則が効くこと（絶対パスの綴りだけが違う）。
    #[cfg(unix)]
    #[test]
    fn absolute_paths_are_folded_on_unix_too() {
        let root = std::path::Path::new("/ws");
        assert!(is_config_injection_path("/ws/.git/hooks/pre-commit", root));
        assert!(!is_config_injection_path("/other/.git/config", root));
        assert!(is_config_injection_path("/other/../x", root));
    }

    #[test]
    fn normalizes_backslash_and_dot_slash_prefix() {
        assert!(is_config_injection_path(
            ".git\\config",
            std::path::Path::new("/workspace")
        ));
        assert!(is_config_injection_path(
            "./.harness/settings.json",
            std::path::Path::new("/workspace")
        ));
    }
}
