//! secret env allowlist（D-07）。`plans/DESIGN-SANDBOX.md` §7 D-07参照。
//!
//! 子の環境はallowlist方式で構築する: 通す既定はPATH/HOME等toolchain安全集合のみ。
//! さらにallowlist内であっても変数名が秘密っぽいパターン
//! （`KEY`/`SECRET`/`TOKEN`/`PASSWORD`/`CREDENTIAL`）を含む場合は二重ガードとして除外する。
//! 全spawn（`run_shell`の子・`git.rs`の内部git）に適用する（Tier0限定機能ではない）。

/// 素通しを許す変数名（大小無視で比較）。
const ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "USERPROFILE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "LANG",
    "APPDATA",
    "LOCALAPPDATA",
    "COMSPEC",
    "CARGO_HOME",
    "RUSTUP_HOME",
    // `PATHEXT`が無いとWindows PowerShell/pwshは外部ネイティブexeの起動に**サイレントに
    // 失敗する**（出力無し・終了コード未設定・エラーも出ない）。既存テストがPowerShell
    // 組み込みコマンドレット（Write-Output等）のみを使っていたため長らく露呈しなかった
    // （協調プロキシE2Eテストでcurl.exeを初めて外部起動して発覚、bug-catalog参照）。
    "PATHEXT",
];

/// allowlistに載っていても除去する秘密っぽい名前パターン（大小無視の部分一致）。
const SECRET_PATTERNS: &[&str] = &["KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL"];

fn looks_secret(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    SECRET_PATTERNS.iter().any(|p| upper.contains(p))
}

fn is_allowlisted(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    ALLOWLIST.iter().any(|a| *a == upper)
}

/// 子プロセスへ渡すクリーンなenvを、現在プロセスの環境から構築する。
pub fn build_child_env() -> Vec<(String, String)> {
    build_child_env_from(std::env::vars())
}

/// テスト用: 任意の環境イテレータからクリーンなenvを構築する。
pub fn build_child_env_from(
    vars: impl IntoIterator<Item = (String, String)>,
) -> Vec<(String, String)> {
    vars.into_iter()
        .filter(|(name, _)| is_allowlisted(name) && !looks_secret(name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_non_allowlisted_and_secret_looking_vars() {
        let env = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("ANTHROPIC_API_KEY".to_string(), "sk-secret".to_string()),
            ("OPENAI_API_KEY".to_string(), "sk-secret2".to_string()),
            ("HOME".to_string(), "/home/u".to_string()),
            ("SOME_RANDOM_VAR".to_string(), "x".to_string()),
        ];
        let cleaned = build_child_env_from(env);
        let names: Vec<&str> = cleaned.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"PATH"));
        assert!(names.contains(&"HOME"));
        assert!(!names.contains(&"ANTHROPIC_API_KEY"));
        assert!(!names.contains(&"OPENAI_API_KEY"));
        assert!(!names.contains(&"SOME_RANDOM_VAR"));
    }

    #[test]
    fn allowlisted_name_that_looks_secret_is_still_dropped() {
        // 現実には無いが、二重ガードの意図（allowlist内でも秘密パターンなら除外）を確認。
        let env = vec![("CARGO_HOME".to_string(), "/home/u/.cargo".to_string())];
        let cleaned = build_child_env_from(env);
        assert_eq!(cleaned.len(), 1);

        let env2 = vec![("HOME_API_KEY".to_string(), "x".to_string())];
        assert!(build_child_env_from(env2).is_empty());
    }
}
