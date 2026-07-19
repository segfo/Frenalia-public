//! D-05（`plans/DESIGN-SANDBOX.md` §7）: 設定注入系hard-deny対象パス。
//! Tier1/Tier2内でも解除しない。`harness-engine::permission::classify()`と
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
pub fn is_config_injection_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let normalized = normalized.strip_prefix("./").unwrap_or(&normalized);
    CONFIG_INJECTION_PREFIXES.iter().any(|prefix| {
        normalized == *prefix || normalized.starts_with(&format!("{prefix}/"))
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
