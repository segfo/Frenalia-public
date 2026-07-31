//! secret env allowlist（D-07）。`plans/DESIGN-SANDBOX.md` §7 D-07参照。
//!
//! 子の環境はallowlist方式で構築する: 通す既定はPATH/HOME等toolchain安全集合のみ。
//! さらにallowlist内であっても変数名が秘密っぽいパターン
//! （`KEY`/`SECRET`/`TOKEN`/`PASSWORD`/`CREDENTIAL`）を含む場合は二重ガードとして除外する。
//! 全spawn（`run_shell`の子・`resolve.rs`の内部git）に適用する（Tier0限定機能ではない）。

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

/// harnessが起動する全`git`（`run_shell`経由のモデル実行・`resolve.rs`の内部`git merge-file`の
/// 双方）へ適用する、自動発火経路だけを潰すenv（D-06/D-14b、`plans/DESIGN-SANDBOX-APPPOLICY.md`
/// §5.2）。`GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n`（git 2.31+）は`-c`と同じ
/// 最高優先度の設定として扱われ、攻撃者が書き換える`.git/config`では上書きできない。
///
/// global config（`user.name`・credential helper・`safe.directory`）は意図的に生かす——
/// `GIT_CONFIG_GLOBAL`/`SYSTEM`を空へ向ける旧`hardened_git_command`方式は、モデル実行`git commit`が
/// `Author identity unknown`で即死する副作用を持つため採用しない。system config
/// （`GIT_CONFIG_NOSYSTEM=1`）のみ無効化する。`core.hooksPath`は存在しないパスでよい
/// （gitは不在のhookを黙ってスキップする）。
pub fn git_hardening_env() -> Vec<(String, String)> {
    vec![
        ("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string()),
        ("GIT_CONFIG_COUNT".to_string(), "2".to_string()),
        ("GIT_CONFIG_KEY_0".to_string(), "core.hooksPath".to_string()),
        (
            "GIT_CONFIG_VALUE_0".to_string(),
            "harness-empty-git-hooks-dir-does-not-exist".to_string(),
        ),
        ("GIT_CONFIG_KEY_1".to_string(), "core.fsmonitor".to_string()),
        ("GIT_CONFIG_VALUE_1".to_string(), "false".to_string()),
        ("GIT_PAGER".to_string(), "cat".to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_hardening_env_disables_hooks_fsmonitor_and_pager() {
        let env = git_hardening_env();
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("GIT_CONFIG_NOSYSTEM"), Some("1"));
        assert_eq!(get("GIT_CONFIG_COUNT"), Some("2"));
        assert_eq!(get("GIT_CONFIG_KEY_0"), Some("core.hooksPath"));
        assert_eq!(get("GIT_CONFIG_KEY_1"), Some("core.fsmonitor"));
        assert_eq!(get("GIT_CONFIG_VALUE_1"), Some("false"));
        assert_eq!(get("GIT_PAGER"), Some("cat"));
    }

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
