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
    // **`PROGRAMDATA`が無いとMSVCリンカが見つからず、rustcが別物の`link`を掴む。**
    // rustcはVisual Studioの位置をVS Setup Configuration API経由で解決し、その実体は
    // `%ProgramData%\Microsoft\VisualStudio\Packages\_Instances`のインスタンスストアを読む。
    // この変数が無いと列挙が0件になり、rustcはPATHへフォールバックする——そこにGit for
    // Windows（MSYS）が同梱する**GNU coreutilsの`link`**があると、それを起動して
    // `link: extra operand ...` で失敗する。エラー文面がMSVCの話をしないので、
    // 「ビルドツールが入っていない」という誤った結論へ誘導される。
    //
    // 実測（2026-08-10、1差分×1ケース）: allowlistのみの環境で`cargo build --release`が失敗し、
    // `PROGRAMDATA`を1つ足すと成功する。`ProgramFiles`・`ProgramFiles(x86)`・`ProgramW6432`・
    // `windir`を足しても直らない（＝この変数が原因であって「環境が薄いから」ではない）。
    // 公開のシステムパスであり秘密を含まないのでallowlistの趣旨（D-07）と矛盾しない。
    //
    // AppContainer（Tier2a）で同じ症状が出たのが[BUG-014]で、あちらの原因は同じ検出機構への
    // **ACL拒否**だった。原因は違うが壊れ方は同一である。
    "PROGRAMDATA",
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

/// `harness_core::git::hardening_env`の再エクスポート。定義自体はそちらへ移した
/// （`harness-cognition`のRecall機構が`harness-sandbox`へ依存せずに同じハードニングを使うため。
/// `harness_core::git`のモジュールdoc参照）。既存呼び出し元（`shell.rs`・`resolve.rs`）は
/// この再エクスポートにより無改造のまま動く。
pub use harness_core::git::hardening_env as git_hardening_env;

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

    /// **MSVCツールチェーンの検出に要る変数が落ちていないこと。**
    ///
    /// `PROGRAMDATA`が無いとrustcはVisual Studioを見つけられず、PATH上のGNU `link`
    /// （Git for Windows同梱）を掴んで`link: extra operand ...`で失敗する。
    /// エラーがMSVCの話をしないため「ビルドツールが未インストール」と誤診されやすい
    /// （実測とBUG-014との関係はALLOWLIST側のコメント参照）。
    ///
    /// **綴りは実際の環境変数名と一致していなければ意味が無い**ので、
    /// 判定関数`is_allowlisted`を通す（定数配列を直接見ない。大小の扱いまで含めて検証する）。
    #[test]
    fn the_msvc_toolchain_lookup_variables_survive_the_allowlist() {
        for name in ["ProgramData", "PROGRAMDATA", "programdata"] {
            assert!(
                is_allowlisted(name),
                "{name} must pass the allowlist, otherwise rustc cannot locate the MSVC linker \
                 and silently falls back to an unrelated `link` on PATH"
            );
        }
        // 実際に構築しても残ることを確認する（`looks_secret`に巻き込まれていないこと）。
        let cleaned = build_child_env_from(vec![(
            "ProgramData".to_string(),
            r"C:\ProgramData".to_string(),
        )]);
        assert_eq!(
            cleaned.len(),
            1,
            "ProgramData must survive build_child_env_from"
        );
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
