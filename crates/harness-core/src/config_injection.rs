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

/// `path`（workspace相対）が設定注入系hard-deny対象かどうかを判定する。
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
pub fn is_config_injection_path(path: &str) -> bool {
    let lowered = path.replace('\\', "/").to_ascii_lowercase();
    let mut components: Vec<&str> = Vec::new();
    for part in lowered.split('/') {
        match part {
            // 空成分（`a//b`）と`.`は落とす。`./`を1回だけ剥がす実装だと`././`で欺ける。
            "" | "." => {}
            // 着地点が分からない以上、拒否側へ倒す。
            ".." => return true,
            // 末尾のドット・スペースはWin32が落とすので、落とした形で照合する
            // （`.git./config`が`.git/config`へ着地するため）。
            other => components.push(other.trim_end_matches(['.', ' '])),
        }
    }
    let normalized = components.join("/");
    CONFIG_INJECTION_PREFIXES.iter().any(|prefix| {
        let prefix = prefix.to_ascii_lowercase();
        normalized == prefix || normalized.starts_with(&format!("{prefix}/"))
    })
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
            assert!(is_config_injection_path(p), "expected match for {p}");
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
                is_config_injection_path(p),
                "expected {p} to be hard-denied (the filesystem does not distinguish case)"
            );
        }
    }

    /// 正規化はこの関数の中で完結する（呼び出し側が正規形をくれる前提にしない）。
    /// `permission::classify()`はモデルが書いた文字列をそのまま渡すため。
    #[test]
    fn normalization_happens_here_not_in_the_caller() {
        // `./`は何回でも剥がす（1回だけの実装は`././`で欺ける＝BUG-063）。
        assert!(is_config_injection_path("././.git/config"));
        assert!(is_config_injection_path("./././.harness/settings.json"));
        // 空成分も落とす。
        assert!(is_config_injection_path(".git//config"));
        // 末尾のドット・スペースはWin32が落とすので、落とした形で照合する。
        assert!(is_config_injection_path(".git./config"));
        assert!(is_config_injection_path(".git /config"));
        // `..`は着地点が静的に決まらないので拒否側へ倒す（P-05）。
        assert!(is_config_injection_path("x/../.git/config"));
        assert!(is_config_injection_path("../anything"));
    }

    #[test]
    fn matches_bare_directory_and_file_entries() {
        assert!(is_config_injection_path(".git/hooks"));
        assert!(is_config_injection_path(".harness"));
        assert!(is_config_injection_path(".vscode"));
        assert!(is_config_injection_path(".devcontainer"));
        assert!(is_config_injection_path(".circleci"));
        assert!(is_config_injection_path(".gitattributes"));
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
            assert!(!is_config_injection_path(p), "unexpected match for {p}");
        }
    }

    #[test]
    fn normal_workspace_paths_unaffected() {
        for p in ["src/main.rs", "Cargo.toml", "README.md", "docs/INDEX.md"] {
            assert!(!is_config_injection_path(p), "unexpected match for {p}");
        }
    }

    #[test]
    fn normalizes_backslash_and_dot_slash_prefix() {
        assert!(is_config_injection_path(".git\\config"));
        assert!(is_config_injection_path("./.harness/settings.json"));
    }
}
