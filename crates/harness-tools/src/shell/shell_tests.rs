//! `run_shell`のテスト。`shell.rs`の分割（規則1、2026-08-08）以前は`shell::tests`だった——
//! `docs/bugs/BUG-003.md`・`BUG-004.md`・`BUG-054.md`が旧パスで参照しているのはこれである
//! （Journalは過去形の記録なので書き換えない。対応表は`docs/refactor/`）。
//!
//! テスト対象が4モジュールへ散ったため、`mod tests`の`use super::*`だけでは届かないものを
//! ここで名前指定して取り込む。**globではなく名前で書く**——どのテストがどのモジュールを
//! 触っているかがファイル先頭で分かるようにするため。

use super::env::{path_entries_equal, path_separator};
use super::net_decision::should_grant_tier2a_network_capability;
#[cfg(windows)]
use super::platform::{CONSTRAINED_LANGUAGE_NOTICE, RUN_SHELL_BOOTSTRAP_SCRIPT};
use super::*;

mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn ctx(root: PathBuf) -> ToolCtx {
        let mut ctx = ToolCtx::new(root.clone());
        // `ToolCtx::new`はテスト既定でTier0（プレースホルダ）を積む。実行時は
        // `harness-cli`が起動時に`select_tier`で解決した値を積むため、ここでも
        // 実際のOS隔離Tier選択を再現する（さもないとTier1経路が単体テストで一切通らない）。
        // WindowsではTier2aが既定（`SandboxChoice::OsDefault`）で常時プローブされるため、
        // `--sandbox tier1`相当の`SandboxChoice::Tier1`を指定してTier1へ直接降ろし、
        // 決定論的にする（実Win32 preflightを単体テストで走らせない、既存Tier1テストの
        // 挙動を変えないため）。
        let probes = harness_sandbox::shell_tier::Probes {
            tier2a_preflight_override: Some(Err("test fixture: force Tier1".to_string())),
            ..Default::default()
        };
        ctx.shell_tier = harness_sandbox::shell_tier::select_tier_with_probes(
            harness_core::RequireSandbox::None,
            &root,
            harness_core::SandboxChoice::Tier1,
            &[],
            None,
            &harness_sandbox::shell_tier::WorkspaceWriteMode::DirectRw,
            None,
            &probes,
        )
        .expect("tier selection without --require-sandbox never fails");
        ctx
    }

    #[test]
    fn classify_net_app_denies_when_allowlist_empty() {
        assert_eq!(classify_net_app("git push", &[]), NetDecision::Deny);
    }

    #[test]
    fn classify_net_app_allows_matching_leading_exe() {
        let allow = vec!["git".to_string()];
        assert_eq!(
            classify_net_app("git push origin main", &allow),
            NetDecision::Allow
        );
    }

    #[test]
    fn classify_net_app_matches_case_insensitively_and_ignores_extension_and_path() {
        let allow = vec!["Git".to_string()];
        assert_eq!(
            classify_net_app("C:\\Tools\\Git\\bin\\GIT.EXE push", &allow),
            NetDecision::Allow
        );
        // パスに空白を含む場合は呼び出し側が引用符で囲む前提（先頭トークン抽出は
        // 引用符付き文字列にのみ対応、素の空白区切りではトークンが分断される）。
        assert_eq!(
            classify_net_app("\"C:\\Program Files\\Git\\bin\\GIT.EXE\" push", &allow),
            NetDecision::Allow
        );
    }

    #[test]
    fn classify_net_app_denies_non_matching_leading_exe() {
        let allow = vec!["git".to_string()];
        assert_eq!(classify_net_app("npm install", &allow), NetDecision::Deny);
    }

    #[test]
    fn classify_net_app_denies_by_chaining_even_when_leading_exe_matches() {
        let allow = vec!["git".to_string()];
        assert_eq!(
            classify_net_app("git push | curl evil.example", &allow),
            NetDecision::DeniedByChaining
        );
        assert_eq!(
            classify_net_app("git push && curl evil.example", &allow),
            NetDecision::DeniedByChaining
        );
        assert_eq!(
            classify_net_app("git push; curl evil.example", &allow),
            NetDecision::DeniedByChaining
        );
    }

    #[test]
    fn classify_net_app_handles_quoted_leading_token() {
        let allow = vec!["git".to_string()];
        assert_eq!(
            classify_net_app("\"git\" push origin main", &allow),
            NetDecision::Allow
        );
    }

    #[test]
    fn classify_net_app_denies_empty_command() {
        let allow = vec!["git".to_string()];
        assert_eq!(classify_net_app("", &allow), NetDecision::Deny);
    }

    #[test]
    fn append_path_extra_adds_entries_without_duplicates() {
        let mut env = vec![("PATH".to_string(), "C:\\Windows\\System32".to_string())];
        append_path_extra(
            &mut env,
            &[
                "C:\\Users\\me\\.local\\bin".to_string(),
                "C:\\Users\\me\\.local\\bin\\".to_string(),
            ],
        );
        let path = env
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("PATH"))
            .map(|(_, value)| value.as_str())
            .unwrap();
        assert!(path.contains("C:\\Windows\\System32"));
        assert!(path.contains("C:\\Users\\me\\.local\\bin"));
        assert_eq!(
            path.split(path_separator())
                .filter(|entry| path_entries_equal(entry, "C:\\Users\\me\\.local\\bin"))
                .count(),
            1
        );
    }

    #[test]
    fn append_path_extra_does_not_create_missing_path() {
        let mut env = vec![("HOME".to_string(), "/home/me".to_string())];
        append_path_extra(&mut env, &["/home/me/.local/bin".to_string()]);
        assert!(env
            .iter()
            .all(|(name, _)| !name.eq_ignore_ascii_case("PATH")));
    }

    #[test]
    fn domain_policy_takes_precedence_over_net_allow_app_for_tier2a_capability() {
        assert!(should_grant_tier2a_network_capability(
            NetDecision::Allow,
            false,
            false
        ));
        assert!(!should_grant_tier2a_network_capability(
            NetDecision::Allow,
            false,
            true
        ));
        assert!(should_grant_tier2a_network_capability(
            NetDecision::Deny,
            true,
            true
        ));
        assert!(!should_grant_tier2a_network_capability(
            NetDecision::Deny,
            false,
            true
        ));
    }

    #[tokio::test]
    async fn run_shell_captures_stdout_and_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let tool = RunShellTool::default();
        let command = "echo hello";

        let out = tool
            .call(
                json!({ "command": command }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();

        assert!(!out.is_error);
        assert!(out.content.contains("hello"));
        assert!(out.content.contains("[exit code: 0]"));
        assert!(out.content.contains("[tier:"));
    }

    #[test]
    fn run_shell_tool_spec_mentions_sh_c_for_tier3() {
        let dir = tempfile::tempdir().unwrap();
        let mut context = ToolCtx::new(dir.path().to_path_buf());
        context.shell_tier = harness_core::ShellTierSelection::direct(ShellTier::Tier3);

        let spec = RunShellTool::default().spec_for_ctx(&context);

        assert!(spec.description.contains("`sh -c`"), "{}", spec.description);
        assert!(
            spec.description.contains("POSIX sh互換"),
            "{}",
            spec.description
        );
        assert!(
            !spec.description.contains("PowerShell"),
            "{}",
            spec.description
        );
        let command_description = spec
            .input_schema
            .pointer("/properties/command/description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(
            command_description.contains("`sh -c`"),
            "{}",
            command_description
        );
        let cwd_description = spec
            .input_schema
            .pointer("/properties/cwd/description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(
            cwd_description.contains("/workspace"),
            "{}",
            cwd_description
        );
        assert!(
            cwd_description.contains("相対作業ディレクトリ"),
            "{}",
            cwd_description
        );
        assert!(!cwd_description.contains("ホスト"), "{}", cwd_description);
    }

    #[test]
    fn run_shell_tool_spec_keeps_default_description_for_non_tier3() {
        let dir = tempfile::tempdir().unwrap();
        let mut context = ToolCtx::new(dir.path().to_path_buf());
        context.shell_tier = harness_core::ShellTierSelection::direct(ShellTier::Tier1);

        let spec = RunShellTool::default().spec_for_ctx(&context);

        assert!(spec.description.contains("--net-allow-app"));
        assert!(!spec.description.contains("Incusコンテナ"));
        let command_description = spec
            .input_schema
            .pointer("/properties/command/description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(command_description, "実行するシェルコマンド");
        let cwd_description = spec
            .input_schema
            .pointer("/properties/cwd/description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(
            cwd_description,
            "ワークスペースルートからの相対作業ディレクトリ"
        );
    }

    #[tokio::test]
    async fn run_shell_warns_about_staged_writes_when_child_may_be_stale() {
        let dir = tempfile::tempdir().unwrap();
        let mut context = ctx(dir.path().to_path_buf());
        context.staging.mode = StagingMode::Staged;
        context.shell_sees_staged_writes = false;

        let out = RunShellTool::default()
            .call(json!({ "command": "echo hello" }), &context)
            .await
            .unwrap();

        assert!(
            out.content.contains("D-08 simplification"),
            "stale child views should keep the D-08 warning: {}",
            out.content
        );
    }

    #[derive(Debug)]
    struct MockVmShellExecutor;

    impl harness_core::VmShellExecutor for MockVmShellExecutor {
        fn exec(
            &self,
            _cmd: &str,
            _cwd: &std::path::Path,
            _env: &[(String, String)],
            _timeout: std::time::Duration,
        ) -> Result<(String, String, Option<i32>), String> {
            Ok(("hello from tier3".to_string(), String::new(), Some(0)))
        }
    }

    #[tokio::test]
    async fn run_shell_suppresses_staged_warning_when_tier3_cifs_sees_staged_writes() {
        let dir = tempfile::tempdir().unwrap();
        let mut context = ToolCtx::new(dir.path().to_path_buf());
        context.staging.mode = StagingMode::WorkspaceCommit;
        context.shell_tier = harness_core::ShellTierSelection::direct(ShellTier::Tier3);
        context.shell_sees_staged_writes = true;
        context.vm_sandbox = Some(Arc::new(MockVmShellExecutor));

        let out = RunShellTool::default()
            .call(json!({ "command": "echo hello" }), &context)
            .await
            .unwrap();

        assert!(out.content.contains("hello from tier3"));
        assert!(out.content.contains("[tier: tier3]"));
        assert!(
            !out.content.contains("D-08 simplification"),
            "Tier3+CIFS live-sharing should not emit the stale-write warning: {}",
            out.content
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_records_launched_windows_shell() {
        let dir = tempfile::tempdir().unwrap();
        let tool = RunShellTool::default();
        let out = tool
            .call(
                json!({ "command": "Write-Output hello" }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();
        assert!(!out.is_error);
        assert!(out.content.contains("hello"));
        assert!(
            out.content.contains("[shell: pwsh(tier1)]")
                || out.content.contains("[shell: powershell5.1(tier1)]")
        );
        assert!(out.content.contains("[tier: tier1]"));
    }

    /// Phase5-H回帰テスト: `cmd /c exit 7`単体（ネイティブコマンドの終了コード）が、
    /// PowerShellプロセス自身の終了コードへ正しく伝播すること。修正前は`0`でも`7`でもなく
    /// 常に`1`へブール化されていた（実機確認済み、モジュールdoc「Phase5-H実測」参照）。
    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_propagates_native_exit_code_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let tool = RunShellTool::default();
        let out = tool
            .call(
                json!({ "command": "cmd /c exit 7" }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();
        assert!(out.is_error);
        assert!(out.content.contains("[exit code: 7]"), "{}", out.content);
    }

    /// Phase5-H回帰テスト: 成功時（exit 0）が壊れないこと。
    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_native_success_exit_code_stays_zero() {
        let dir = tempfile::tempdir().unwrap();
        let tool = RunShellTool::default();
        let out = tool
            .call(
                json!({ "command": "cmd /c exit 0" }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();
        assert!(!out.is_error);
        assert!(out.content.contains("[exit code: 0]"), "{}", out.content);
    }

    /// [BUG-095](../../../../docs/bugs/BUG-095.md)回帰テスト:
    /// **走らせることすらできなかったコマンドが、終了コード0（成功）で報告されない**こと。
    ///
    /// 修正前は3つの形が全て`0`だった——判定（`$LASTEXITCODE`/`$?`）を
    /// `Invoke-Expression`の**外**で行っており、外側の`$?`は「評価が成功したか」しか
    /// 答えないためである。**情報は失われておらず、読む場所が外側だった。**
    ///
    /// **嘘だった側だけをテストしない**（`test-logic-rules`）——正しく動いていた側は
    /// 直下の`..._does_not_break_success_shapes`が対で固定する。片方だけだと、
    /// 「常に非0を返す」実装でも合格してしまう。
    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_reports_nonzero_when_the_command_could_not_run() {
        let dir = tempfile::tempdir().unwrap();
        // 起動できないEXE（PEではないファイル）。ACLで拒否されるEXEと同じ`NativeCommandFailed`。
        let fake_exe = dir.path().join("not-a-real.exe");
        std::fs::write(&fake_exe, b"not a real PE").unwrap();

        for (command, why) in [
            (
                "harness-definitely-not-a-command-xyz".to_string(),
                "存在しないコマンド（CommandNotFoundException）",
            ),
            (
                format!("& '{}'", fake_exe.display()),
                "見つかったが起動できないEXE（NativeCommandFailed）",
            ),
            (
                "Get-Item C:\\harness-definitely-missing-file-xyz.txt".to_string(),
                "失敗したcmdlet",
            ),
        ] {
            let tool = RunShellTool::default();
            let out = tool
                .call(
                    json!({ "command": command }),
                    &ctx(dir.path().to_path_buf()),
                )
                .await
                .unwrap();
            assert!(
                !out.content.contains("[exit code: 0]"),
                "{why}: 走らせられなかったコマンドが成功として報告された（BUG-095）: {}",
                out.content
            );
            assert!(
                out.is_error,
                "{why}: 終了コードが非0ならツール結果もエラーでなければならない: {}",
                out.content
            );
        }
    }

    /// [BUG-095](../../../../docs/bugs/BUG-095.md)回帰テストの**対**:
    /// 正しく動いていた2つの形が、上の修正で壊れていないこと。
    ///
    /// これを置かないと「常に非0を返す」実装が上のテストを通ってしまう。**成功が失敗に
    /// 見える**のはBUG-086で実際に起きた事故で、モデルがリトライループへ入った。
    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_exit_code_fix_does_not_break_success_shapes() {
        let dir = tempfile::tempdir().unwrap();
        for (command, expected, why) in [
            (
                "cmd /c exit 3",
                "[exit code: 3]",
                "ネイティブの終了コードはそのまま伝わる",
            ),
            ("Write-Output ok", "[exit code: 0]", "正常終了は0のまま"),
            (
                "Write-Output ok # trailing comment",
                "[exit code: 0]",
                "末尾コメント付きでも判定が飲まれない（区切りが改行である根拠）",
            ),
        ] {
            let tool = RunShellTool::default();
            let out = tool
                .call(
                    json!({ "command": command }),
                    &ctx(dir.path().to_path_buf()),
                )
                .await
                .unwrap();
            assert!(
                out.content.contains(expected),
                "{why}: {command} は {expected} を返すべき: {}",
                out.content
            );
        }
    }

    /// Phase5-G回帰テスト: 日本語（非ASCII）を含む既存ファイルの内容を読み出す出力が文字化け
    /// （U+FFFD等）せずそのまま返ること。修正前はコンソール既定コードページ（CP932想定）と
    /// われわれの`from_utf8_lossy`読取りが食い違い、非ASCII出力が破壊されていた。
    ///
    /// これは**出力側**の回帰テスト。コマンド文字列自体に非ASCIIを埋め込む**入力側**は
    /// [BUG-049](../../docs/bugs/BUG-049.md)で別途修正済み（下の
    /// `run_shell_executes_command_containing_non_ascii_literal`が回帰テスト）。
    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_returns_japanese_file_content_without_mojibake() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("japanese.txt");
        std::fs::write(&file_path, "こんにちは日本語テスト").unwrap();
        let tool = RunShellTool::default();
        let out = tool
            .call(
                json!({ "command": format!("Get-Content -Raw '{}'", file_path.display()) }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();
        assert!(!out.is_error);
        assert!(
            out.content.contains("こんにちは日本語テスト"),
            "{}",
            out.content
        );
        assert!(!out.content.contains('\u{FFFD}'), "{}", out.content);
    }

    /// BUG-049回帰テスト: モデルが非ASCIIリテラルを`command`文字列**自体**へ書いたとき、
    /// それがPowerShellへ壊れずに届くこと。修正前は`-Command -`のstdinペイロードをUTF-8で
    /// 書いていたが、PowerShell 5.1はstdinをコンソール入力コードページ（日本語Windowsでは
    /// CP932）で復号するため、`Remove-Item 'テスト - コピー.txt'`が
    /// `繝・せ繝・- 繧ｳ繝斐・.txt`を探しに行き「存在しない」で失敗していた。
    ///
    /// ファイル**名**の一致で検証する（`Write-Output`の出力比較ではなく実際のFS解決を通す）ため、
    /// 非ASCII名のファイルを作って`Test-Path`させる。旧「調査メモ」が指摘していた
    /// 「`cargo test`経由だと必ず文字化けする」現象は、まさにこの欠陥そのものだった
    /// （`cargo test`はコンソールを持たない起動コンテキストで`GetConsoleCP()`が異なるため、
    /// 直接起動時よりも再現しやすかった）。
    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_executes_command_containing_non_ascii_literal() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("テスト - コピー.txt");
        std::fs::write(&file_path, "x").unwrap();
        let tool = RunShellTool::default();
        // 既存の`run_shell_returns_japanese_file_content_without_mojibake`と同じく絶対パスで
        // 指定する（相対パス解決はTierごとのcwd事情が混ざるため、ここでは符号化だけを見る）。
        let out = tool
            .call(
                json!({ "command": format!(
                    "if (Test-Path '{}') {{ Write-Output 'FOUND' }} else {{ Write-Output 'MISSING' }}",
                    file_path.display()
                ) }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();
        assert!(!out.is_error, "{}", out.content);
        assert!(
            out.content.contains("FOUND"),
            "non-ASCII literal in the command must reach PowerShell intact: {}",
            out.content
        );
    }

    /// コマンド文字列中のリテラルが、PowerShellのパーサへ**コードポイント単位で無改変に**
    /// 届いたことを、出力側の符号化に一切依存せずに確かめる。
    ///
    /// 各文字のUTF-16単位を10進数（純ASCII）で出させて突き合わせる。stdoutの符号化が
    /// ANSIコードページ固定になる環境（[BUG-102](../../docs/bugs/BUG-102.md)の
    /// ConstrainedLanguage）でも、この経路は`?`へ潰れないので**両モードで同じ歯**を持つ。
    /// 期待値はRust側のリテラルから計算する（数値の羅列を手で書くとリテラルを変えたときに
    /// 静かにずれる）。
    #[cfg(windows)]
    async fn assert_literal_reaches_powershell_intact(literal: &str) -> String {
        let dir = tempfile::tempdir().unwrap();
        let tool = RunShellTool::default();
        let out = tool
            .call(
                json!({ "command": format!(
                    "Write-Output ('CP=' + (([int[]][char[]]'{literal}') -join ','))"
                ) }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();
        assert!(!out.is_error, "{}", out.content);
        let expected: Vec<String> = literal.encode_utf16().map(|u| u.to_string()).collect();
        assert!(
            out.content.contains(&format!("CP={}", expected.join(","))),
            "the literal must reach PowerShell without any code-point substitution: {}",
            out.content
        );
        out.content
    }

    /// BUG-050回帰テスト: 絵文字・非BMP文字（`𠮷`）・結合文字（`が`）を含むコマンドが実行できる
    /// こと。BUG-049修正のコードページ変換方式ではCP932で表現できないこれらの文字は`?`へ
    /// 潰れていた（ANSIコードページ変換自体を廃止したBUG-050修正で解消）。
    ///
    /// BUG-102以降、**入力側（コマンドがPowerShellへ届くこと）と出力側（実行結果が
    /// 文字化けせず戻ること）を分けて**検証する。前者はBUG-050が守った性質そのもので、
    /// ConstrainedLanguageでも成立する。後者は`[Console]::OutputEncoding`を設定できないと
    /// 成立しない（非BMPは`?`になる）ため、劣化を宣言している実行では要求しない。
    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_executes_command_containing_emoji_and_non_bmp_literal() {
        const LITERAL: &str = "🚀 𠮷野家 が";
        // 入力側: どのモードでも無改変で届くこと。
        let probe = assert_literal_reaches_powershell_intact(LITERAL).await;

        let dir = tempfile::tempdir().unwrap();
        let tool = RunShellTool::default();
        let out = tool
            .call(
                json!({ "command": format!("Write-Output '{LITERAL}'") }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();
        assert!(!out.is_error, "{}", out.content);
        if probe.contains(CONSTRAINED_LANGUAGE_NOTICE) {
            // BUG-102: この機のTier1ではstdoutがANSIコードページ固定で、非BMPは`?`へ潰れる。
            // 出力の一致は要求できないが、上でコマンド自体が無改変で届いたことは確認済み。
            return;
        }
        assert!(out.content.contains(LITERAL), "{}", out.content);
    }

    /// BUG-050回帰テスト（セキュリティ）: `WideCharToMultiByte`の既定のベストフィット変換は
    /// CP932下で`¦`(U+00A6)を`|`へ、`¥`(U+00A5)を`\`へ合成する。危険構文検査
    /// （`contains_chaining_metachar`・`looks_like_allowlist_bypass`）はモデルの元コマンドに
    /// 対して行われるため、変換後だけメタ文字が現れると検査が素通りになる（BUG-050）。
    /// コードページ変換自体を廃止したことで、送ったバイト表現がそのままPowerShellへ届き、
    /// `¦`が`|`に化けないことを確認する。
    ///
    /// **検証点はPowerShellが受け取った文字**である（BUG-102で分離）。危険なのは
    /// 「検査した文字列と実行される文字列の乖離」（B-21）であって、表示の乖離ではない。
    /// コードポイントで見ることで、stdoutの符号化がANSIコードページ固定になる環境
    /// （ConstrainedLanguage。実測でそこでは**出力側**が`¦`→`|`のベストフィット変換をする）でも
    /// 本来の検証点が保たれていることを確かめられる。
    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_does_not_best_fit_convert_broken_bar_into_pipe() {
        // 166 = U+00A6 BROKEN BAR。124（`|`）へ化けていればここで落ちる。
        let probe = assert_literal_reaches_powershell_intact("a¦b").await;
        assert!(probe.contains("CP=97,166,98"), "{probe}");

        let dir = tempfile::tempdir().unwrap();
        let tool = RunShellTool::default();
        let out = tool
            .call(
                json!({ "command": "Write-Output 'a¦b'" }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();
        assert!(!out.is_error, "{}", out.content);
        if out.content.contains(CONSTRAINED_LANGUAGE_NOTICE) {
            // BUG-102: 表示だけがANSIコードページのベストフィットで`a|b`になる。実行された
            // コマンドは`¦`のままであることを上で確認済みなので、検査回避（BUG-050）は生じない。
            return;
        }
        assert!(
            out.content.contains("a¦b"),
            "U+00A6 must not be best-fit-converted into a pipe character: {}",
            out.content
        );
    }

    /// BUG-050回帰テスト: コマンド本体を運ぶ`HARNESS_RUN_SHELL_COMMAND`が、
    /// ブートストラップスクリプト内の`Remove-Item Env:`で読み取り直後に消え、
    /// 孫プロセスへ継承されないこと。
    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_does_not_leak_command_env_var_to_grandchild() {
        let dir = tempfile::tempdir().unwrap();
        let tool = RunShellTool::default();
        let out = tool
            .call(
                json!({ "command": "cmd /c echo [%HARNESS_RUN_SHELL_COMMAND%]" }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();
        assert!(!out.is_error, "{}", out.content);
        assert!(
            out.content.contains("[%HARNESS_RUN_SHELL_COMMAND%]"),
            "env var must be gone by the time a grandchild reads it (cmd.exe leaves an unexpanded \
             literal when the variable is undefined): {}",
            out.content
        );
    }

    /// ブートストラップの中身が宣言済みのenv変数名を実際に参照していること（定数の食い違いを
    /// コンパイル時ではなくテストで固定する。`concat!`は任意のconst文字列を受け付けないため）。
    #[cfg(windows)]
    #[test]
    fn bootstrap_script_references_the_declared_env_var_name() {
        assert!(RUN_SHELL_BOOTSTRAP_SCRIPT.contains(RUN_SHELL_COMMAND_ENV_VAR));
    }

    /// BUG-102: 劣化の宣言文とその識別用定数の対応を固定する（上の env 名と同じ理由）。
    /// これがずれると、劣化しているのに劣化していないものとして扱われる。
    #[cfg(windows)]
    #[test]
    fn bootstrap_script_announces_constrained_language() {
        assert!(RUN_SHELL_BOOTSTRAP_SCRIPT.contains(CONSTRAINED_LANGUAGE_NOTICE));
        // 宣言は境界印より前＝`[shell-startup-noise]`枠に入る位置でなければ、
        // コマンドの出力に混ざる（B-33）。
        let notice_at = RUN_SHELL_BOOTSTRAP_SCRIPT
            .find(CONSTRAINED_LANGUAGE_NOTICE)
            .unwrap();
        let sentinel_at = RUN_SHELL_BOOTSTRAP_SCRIPT
            .find(RUN_SHELL_OUTPUT_SENTINEL)
            .unwrap();
        assert!(notice_at < sentinel_at);
    }

    /// 境界印はブートストラップが実際に出す文字列と一致していなければならない（定数の
    /// 食い違いをテストで固定する。上の`RUN_SHELL_COMMAND_ENV_VAR`と同じ理由）。
    #[cfg(windows)]
    #[test]
    fn bootstrap_script_emits_the_declared_sentinel_on_both_streams() {
        assert_eq!(
            RUN_SHELL_BOOTSTRAP_SCRIPT
                .matches(RUN_SHELL_OUTPUT_SENTINEL)
                .count(),
            2,
            "stdoutとstderrの両方へ出す必要がある（どちらへ出るかはホスト依存）"
        );
        // 印はコマンドを実行する行より**前**になければ意味が無い。
        let sentinel_at = RUN_SHELL_BOOTSTRAP_SCRIPT
            .find(RUN_SHELL_OUTPUT_SENTINEL)
            .unwrap();
        let exec_at = RUN_SHELL_BOOTSTRAP_SCRIPT
            .find("Invoke-Expression")
            .unwrap();
        assert!(sentinel_at < exec_at);
    }

    /// BUG-102回帰テスト: ブートストラップがConstrainedLanguageでも走ること。
    ///
    /// WDACのCIポリシーが配備された機では低ILのPowerShell（＝Tier1）がConstrainedLanguageに
    /// なり、.NET型のメソッド呼び出し・プロパティ設定が禁止される。旧実装は
    /// `. ([scriptblock]::Create($__harness_cmd))`で**コマンドを実行する当の行**が落ちていた。
    ///
    /// 実機がWDAC無効でも壊れたことを検出できるよう、**定数の形**で固定する
    /// （実行時の検証は下の`run_shell_*`群がTier1経由で行うが、それはCLになる機でしか
    /// 赤くならない）。
    #[cfg(windows)]
    #[test]
    fn bootstrap_script_is_constrained_language_safe() {
        assert!(
            !RUN_SHELL_BOOTSTRAP_SCRIPT.contains("scriptblock]::Create"),
            "コマンド実行に.NETの静的メソッドを使うとConstrainedLanguageで1行も走らない"
        );
        assert!(
            RUN_SHELL_BOOTSTRAP_SCRIPT.contains("Invoke-Expression ($__harness_cmd +"),
            "コマンドは`Invoke-Expression`で実行し、終了コードの判定はその評価文字列の内側へ\
             足す（BUG-095。外側の`$?`は評価自体の成否しか答えない）"
        );
        // BUG-095: 判定を足す区切りは改行でなければならない。`;`だと、末尾にコメントの付いた
        // コマンドで判定がコメントに飲まれて消える（実測）。
        assert!(
            RUN_SHELL_BOOTSTRAP_SCRIPT.contains("+ \"`n\" +"),
            "判定の区切りが改行でなくなっている（`;`では末尾コメント付きコマンドで消える）"
        );

        // `[Console]::`に触る文は全てFullLanguageガードの内側にあること。ガードの外に1つでも
        // あると、その`InvalidOperation`がコマンドの出力に見える（BUG-086と同型）。
        for (at, _) in RUN_SHELL_BOOTSTRAP_SCRIPT.match_indices("[Console]::") {
            let statement = RUN_SHELL_BOOTSTRAP_SCRIPT[..at]
                .rsplit(';')
                .next()
                .unwrap_or_default();
            assert!(
                statement.contains("$__harness_full"),
                "unguarded [Console]:: at byte {at} in the bootstrap script"
            );
        }
    }

    /// 起動時ノイズは切り離すが**捨てない**（`bug-pattern-rules` B-10）。
    #[cfg(windows)]
    #[test]
    fn startup_noise_is_separated_from_the_command_output() {
        let raw = format!(
            "'FileSystem' プロバイダーで InitializeDefaultDrives 操作に失敗しました。\n{}\nhello\n",
            RUN_SHELL_OUTPUT_SENTINEL
        );
        let (noise, output) = split_shell_startup_noise(&raw);
        assert!(noise.contains("InitializeDefaultDrives"));
        assert_eq!(output, "hello\n");
    }

    /// 印が無ければ**全部をコマンドの出力**として扱う（安全側＝隠さない側）。
    /// Unix・Tier3・シェルが印に到達する前に死んだ場合がこれに当たる。
    #[cfg(windows)]
    #[test]
    fn without_the_sentinel_nothing_is_treated_as_noise() {
        let (noise, output) = split_shell_startup_noise("boom\n");
        assert_eq!(noise, "");
        assert_eq!(output, "boom\n");
    }

    /// コマンドが同じ文字列を出力しても分割位置は動かない（**最初の1つ**で切るため、
    /// コマンド側から「ここまでをノイズ扱いにする」操作ができない）。
    #[cfg(windows)]
    #[test]
    fn a_command_echoing_the_sentinel_cannot_move_the_split() {
        let raw = format!(
            "noise\n{s}\nreal-1\n{s}\nreal-2\n",
            s = RUN_SHELL_OUTPUT_SENTINEL
        );
        let (noise, output) = split_shell_startup_noise(&raw);
        assert_eq!(noise, "noise");
        assert!(output.starts_with("real-1"));
        assert!(output.contains("real-2"));
    }

    /// 同じ文言がstdoutとstderrの両方に出ても、見せるのは1回だけ
    /// （2回出すと起きたことが2つあるように読める。B-32）。
    #[test]
    fn identical_noise_on_both_streams_is_shown_once() {
        assert_eq!(merge_startup_noise("warn", "warn").as_deref(), Some("warn"));
        assert_eq!(merge_startup_noise("", "").as_deref(), None);
        assert_eq!(merge_startup_noise("a", "b").as_deref(), Some("a\nb"));
    }

    #[tokio::test]
    async fn run_shell_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let tool = RunShellTool::default();
        #[cfg(windows)]
        let command = "Start-Sleep -Seconds 5";
        #[cfg(not(windows))]
        let command = "sleep 5";

        let err = tool
            .call(
                json!({ "command": command, "timeout_ms": 200 }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, ToolError::ExecutionFailed(_)));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_tier1_rejects_write_outside_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let outside = std::env::temp_dir().join("harness-m12-outside-test.txt");
        let _ = std::fs::remove_file(&outside);
        let tool = RunShellTool::default();
        let command = format!(
            "Set-Content -Path '{}' -Value 'blocked' -ErrorAction Stop",
            outside.display()
        );
        let out = tool
            .call(
                json!({ "command": command }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();
        assert!(
            out.is_error,
            "write outside the low-IL cwd should fail: {}",
            out.content
        );
        assert!(!outside.exists());
    }

    /// **`run_shell_tier1_rejects_write_outside_cwd`の対**（B-01/B-27）。
    ///
    /// 「cwd外への書込は拒否される」だけを検証していると、`set_low_integrity_label`が
    /// 完全に効いていなくてもテストは緑のままになる——低ILの子はcwd**内**へも書けなくなるが、
    /// 拒否側のテストしか無ければ誰も気付けない。実際、BUG-018の案Aが入れた不正なSDDL
    /// （`NI`は正規のACEフラグトークンではない）のせいでラベルは一度も付いておらず、
    /// この欠落したテストが理由で長期間検知されなかった（`win_restricted.rs`の
    /// `SDDL_LOW_LABEL`のコメント参照）。**許可側もテストする。**
    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_tier1_allows_write_inside_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let inside = dir.path().join("tier1-inside-cwd.txt");
        let tool = RunShellTool::default();
        let command = format!(
            "Set-Content -Path '{}' -Value 'allowed' -ErrorAction Stop",
            inside.display()
        );

        let out = tool
            .call(
                json!({ "command": command }),
                &ctx(dir.path().to_path_buf()),
            )
            .await
            .unwrap();

        assert!(
            !out.is_error,
            "write inside the low-IL cwd must succeed (is the mandatory label actually applied?): {}",
            out.content
        );
        assert!(
            inside.exists(),
            "the file must actually exist on disk after a successful write: {}",
            out.content
        );
    }

    /// 実preflightを走らせるテスト用の使い捨てワークスペース。**製品の実台帳へ残る記録を
    /// 持ち帰る。**
    ///
    /// preflightは成功のたびにworkspace台帳へ1件、capability台帳へモード数ぶんの記録を残す。
    /// 使い捨てディレクトリで走らせると、それは**指す先が消えた記録**として積もり続ける
    /// （`workspace_ledger`のdocが「実測で1,043件・155KB」と書いているのがこの形である）。
    /// 実測でも、素の`cargo test -p harness-tools --lib`1回につきworkspace台帳へ2件・
    /// capability台帳へ4件が増えていた。
    ///
    /// # 撤収の順序を型で固定する
    ///
    /// `Drop`は**先にツリーを消し、そのあとで台帳から名前を落とす**。逆にすると、ACEが載った
    /// ままの木に対して撤収経路の名前だけが先に消える——`forget_capability`のdocが名指しで
    /// 禁じている順序であり、BUG-017/BUG-059が繰り返し踏んだ孤立ACEの形そのものである。
    /// `Drop`に置いたのは、テストが途中でpanicしても撤収が走るようにするため。
    #[cfg(windows)]
    struct Tier2aScratchWorkspace {
        dir: Option<tempfile::TempDir>,
        /// preflightが台帳へ書いたのと同じ綴り（`\\?\`付き）。`remove_workspace_entry`が
        /// 使う`same_ledger_path`はverbatim前置を畳まないので、素のパスでは一致しない。
        canonical: PathBuf,
    }

    #[cfg(windows)]
    impl Tier2aScratchWorkspace {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let canonical = dir.path().canonicalize().unwrap();
            Self {
                dir: Some(dir),
                canonical,
            }
        }

        fn path(&self) -> &std::path::Path {
            self.dir.as_ref().expect("still alive").path()
        }
    }

    #[cfg(windows)]
    impl Drop for Tier2aScratchWorkspace {
        fn drop(&mut self) {
            drop(self.dir.take());
            harness_sandbox::tier2a::workspace_ledger::remove_workspace_entry(&self.canonical);
            let _ = harness_sandbox::tier2a::workspace_capability::forget_capability(
                &self.canonical,
                "",
            );
        }
    }

    /// Tier2a（AppContainer）の隔離セマンティクスを決定論的に検証する（LLM非依存、絶対パスを
    /// 使いモデルのCWD混乱を排除する）。実際にpreflight（プロファイル作成＋再帰ACL付与＋
    /// smoke-test起動）を走らせ、Tier2aが選択できなかった環境（AppContainer不可）ではskipする。
    ///
    /// **昇格は要らない**（2026-09-03に非昇格で実行を確認）。実台帳へ残す記録は
    /// [`Tier2aScratchWorkspace`]が持ち帰る。
    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_tier2a_contains_writes_and_reads() {
        use harness_core::{RequireSandbox, ShellTier};

        let dir = Tier2aScratchWorkspace::new();
        // 実Tier2a preflightを走らせる（`opt_in_Tier2a=true`）。AppContainer不可の環境では
        // Tier1へ降格するので、その場合はテストをskipする（CIやAppContainer無効環境向け）。
        // **Tier2aが取れない環境ではskipする。** D-75以後、取れないことは`Err`として返る
        // （かつては`Auto`が黙ってTier0/Tier1へ降格し、`selection.tier`を見て判定していた）。
        let selection = match harness_sandbox::select_tier(
            RequireSandbox::None,
            dir.path(),
            harness_core::SandboxChoice::Tier2a,
            &[],
            None,
            &harness_sandbox::shell_tier::WorkspaceWriteMode::DirectRw,
            None,
        ) {
            Ok(selection) => selection,
            Err(e) => {
                eprintln!("skipping Tier2a test: Tier2a is unavailable here ({e})");
                return;
            }
        };
        assert_eq!(
            selection.tier,
            ShellTier::Tier2a,
            "requesting Tier2a must land on Tier2a or fail"
        );

        let mut ctx = ToolCtx::new(dir.path().to_path_buf());
        ctx.shell_tier = selection;
        let daemon = harness_sandbox::tier2a::spawnd::SharedSpawnDaemon::start(
            harness_sandbox::tier2a::spawnd::ChildProcessPolicy::Unrestricted,
        )
            .expect("Tier2a product path requires a Spawn Daemon");
        let tool = RunShellTool::with_spawn_daemon(daemon);

        // (a) ワークスペース内への書込（絶対パス）→ 成功する（再帰ACL付与でパッケージSIDが
        //     workspace配下に書込可になっている証拠）。
        let inside = dir.path().join("inside.txt");
        let out = tool
            .call(
                json!({
                    "command": format!(
                        "Set-Content -Path '{}' -Value hi -ErrorAction Stop",
                        inside.display()
                    )
                }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(
            !out.is_error,
            "in-workspace write should succeed under Tier2a: {}",
            out.content
        );
        assert!(
            inside.exists(),
            "in-workspace file was not created: {}",
            out.content
        );
        assert!(out.content.contains("[tier: tier2a]"), "{}", out.content);

        // (b) ワークスペース外への書込 → 拒否され、ファイルは作られない（範囲外書込の物理拒否）。
        let outside = std::env::temp_dir().join("harness-Tier2a-outside.txt");
        let _ = std::fs::remove_file(&outside);
        let out = tool
            .call(
                json!({
                    "command": format!(
                        "Set-Content -Path '{}' -Value blocked -ErrorAction Stop",
                        outside.display()
                    )
                }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(
            out.is_error,
            "out-of-workspace write should fail under Tier2a: {}",
            out.content
        );
        assert!(!outside.exists());

        // (c) T-04: ワークスペース外の機密ファイルのread → 拒否される（Tier1なら読めてしまう
        //     既知の欠陥がTier2aでは直る、という差分。実`~/.ssh`は使わずダミーで同じ性質を再現）。
        let secret = std::env::temp_dir().join("harness-Tier2a-secret.txt");
        std::fs::write(&secret, "topsecret").unwrap();
        let out = tool
            .call(
                json!({
                    "command": format!(
                        "Get-Content -Path '{}' -ErrorAction Stop",
                        secret.display()
                    )
                }),
                &ctx,
            )
            .await
            .unwrap();
        let _ = std::fs::remove_file(&secret);
        assert!(
            !out.content.contains("topsecret"),
            "Tier2a must not read outside-workspace secrets (T-04): {}",
            out.content
        );

        // (e) **製品経路から要求受付パイプへ1往復する**（`plans/DESIGN-MAC-PROTOCOL.md` §12）。
        //
        // 断られること自体は`spawnd_e2e_tests`のP1が測っているが、あちらは**電文の
        // `DomainSpec`をテストが手で組む**ので、`run_shell`のアダプタが本当に
        // spawn要求用capabilityを積んでいるかは測れない。ここが製品側の対である。
        //
        // 見るのは**断る理由**である。`policy_not_implemented`なら
        // 「あなたが誰かは分かった（Process Tableに載っている）が、遷移を許すかを
        // 判定する仕組みがまだ無い」で、`not_registered`なら登録が効いていない（BUG-116の形）。
        // **同じ値へ丸めると、常に拒否する実装でも通る**（`B-35`）。
        //
        // **同じ綴りが`crates/harness-policy-editor/tests/record_net_e2e.rs`の
        // `SPAWN_REQUEST_ROUNDTRIP`にもある**（あちらはパス2の、こちらは`run_shell`の
        // 同じ測定である）。1箇所へ畳めない理由と、写しを許した判断の経緯はあちらのdocが持つ。
        // **直すときは必ず両方を直すこと**——片方だけ直っても誰も落ちない。
        let roundtrip = r#"
$raw = $env:HARNESS_SPAWN_REQUEST_PIPE
if (-not $raw) { Write-Output 'NO_PIPE_ENV'; exit 0 }
$name = $raw -replace '^\\\\\.\\pipe\\', ''
$c = New-Object System.IO.Pipes.NamedPipeClientStream('.', $name, 'InOut')
try { $c.Connect(5000) } catch { Write-Output ('CONNECT_FAILED:' + $_.Exception.Message); exit 0 }
$body = [Text.Encoding]::UTF8.GetBytes('{"kind":"spawn","exe":"git.exe","args":["status"],"cwd":"C:/"}')
$c.Write([BitConverter]::GetBytes([int]$body.Length), 0, 4)
$c.Write($body, 0, $body.Length)
$c.Flush()
$hdr = New-Object byte[] 4
if ($c.Read($hdr, 0, 4) -ne 4) { Write-Output 'NO_REPLY_HEADER'; exit 0 }
$n = [BitConverter]::ToInt32($hdr, 0)
$buf = New-Object byte[] $n
$got = 0
while ($got -lt $n) { $r = $c.Read($buf, $got, $n - $got); if ($r -le 0) { break }; $got += $r }
Write-Output ('REPLY:' + [Text.Encoding]::UTF8.GetString($buf, 0, $got))
"#;
        let out = tool
            .call(json!({ "command": roundtrip }), &ctx)
            .await
            .unwrap();
        assert!(
            !out.content.contains("NO_PIPE_ENV"),
            "run_shellの子に要求受付パイプの名前が届いていない。\
             Daemon経由になっていないか、環境変数の受け渡しが落ちている: {}",
            out.content
        );
        assert!(
            out.content.contains("policy_not_implemented"),
            "run_shellの子が要求受付パイプで `policy_not_implemented` を受け取れていない。\
             `not_registered` なら Process Table への登録が Resume より前に効いていない（BUG-116の形）、\
             接続自体が失敗しているなら spawn要求用capability を積んでいない: {}",
            out.content
        );
        assert!(
            !out.content.contains("not_registered"),
            "Daemonが起こした子なのに「台帳に無い」で断られている（§12・BUG-116）: {}",
            out.content
        );
    }

    /// アプリ単位network制御（軸1、D-10/D-11）の実機E2E。Tier2a配下で、許可リストに一致する
    /// 単一コマンドは`internetClient`が付与されて外向き接続に成功し、それ以外
    /// （不一致・連鎖）はcapability空のまま`WSAEACCES`相当で失敗することを確認する
    /// （`plans/DESIGN-SANDBOX-APPPOLICY.md` §10 検証計画1/2/3）。
    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_tier2a_net_allow_app_grants_and_denies_network() {
        use harness_core::{NetAppPolicy, RequireSandbox, ShellTier};

        let dir = Tier2aScratchWorkspace::new();
        // Tier2aが取れない環境ではskipする（上のE2Eと同じ理由・同じ形）。
        let selection = match harness_sandbox::select_tier(
            RequireSandbox::None,
            dir.path(),
            harness_core::SandboxChoice::Tier2a,
            &[],
            None,
            &harness_sandbox::shell_tier::WorkspaceWriteMode::DirectRw,
            None,
        ) {
            Ok(selection) => selection,
            Err(e) => {
                eprintln!("skipping Tier2a net-allow-app test: Tier2a is unavailable here ({e})");
                return;
            }
        };
        assert_eq!(
            selection.tier,
            ShellTier::Tier2a,
            "requesting Tier2a must land on Tier2a or fail"
        );

        let mut ctx = ToolCtx::new(dir.path().to_path_buf());
        ctx.shell_tier = selection;
        // This E2E is specifically for --net-allow-app / internetClient capability.
        // Domain policy has precedence and intentionally suppresses app-level grants.
        ctx.net_proxy.domain_policy_enabled = false;
        ctx.net_app = NetAppPolicy {
            allow_apps: vec!["powershell".to_string(), "pwsh".to_string()],
        };
        let daemon = harness_sandbox::tier2a::spawnd::SharedSpawnDaemon::start(
            harness_sandbox::tier2a::spawnd::ChildProcessPolicy::Unrestricted,
        )
            .expect("Tier2a product path requires a Spawn Daemon");
        let tool = RunShellTool::with_spawn_daemon(daemon);
        // TCPソケットを直接開くprobe（HTTP_PROXYに依存しない、capability機構そのものを見る）。
        let connect_probe = "try { \
            $c = New-Object Net.Sockets.TcpClient; \
            $c.Connect('8.8.8.8', 53); \
            Write-Output 'CONNECT OK'; \
            $c.Close() \
        } catch { Write-Output \"CONNECT FAIL: $_\" }";

        // (a) 許可リスト一致・単一コマンド → internetClient付与 → 接続成功。
        let out = tool
            .call(json!({ "command": connect_probe }), &ctx)
            .await
            .unwrap();
        assert!(
            out.content.contains("[net: internetClient]"),
            "allowed single command should be granted internetClient: {}",
            out.content
        );
        assert!(
            out.content.contains("CONNECT OK"),
            "allowed command should be able to open an outbound socket: {}",
            out.content
        );

        // (b) 連鎖コマンド → 先頭execは一致するがdeny側へ倒れる → 接続失敗。
        let chained = format!("{connect_probe}; Write-Output 'chained'");
        let out = tool
            .call(json!({ "command": chained }), &ctx)
            .await
            .unwrap();
        assert!(
            out.content.contains("[net: denied (chained command"),
            "chained command must not be granted network even if leading exe matches: {}",
            out.content
        );
        assert!(
            out.content.contains("CONNECT FAIL"),
            "chained command should still be network-denied (capability empty): {}",
            out.content
        );
    }

    /// 協調プロキシ（M12補遺、D-15）の実機E2E。単体テスト（`net_proxy::tests`）はプロキシ
    /// 単体をTCPクライアントから直接叩いて検証したが、これは「`run_shell`が実際に子プロセスへ
    /// `HTTP_PROXY`を注入し、外部ツール（`curl.exe`）がそれを自発的に読んで従う」という
    /// 統合経路まで通しで確認する（`plans/DESIGN-SANDBOX-PRIVSEP.md` §8フェーズ1検証計画:
    /// 「許可ドメインへの通信が成功し監査ログに残ること、未許可ドメインへのCONNECTが
    /// プロキシに拒否されること」）。`curl`がPATHに無い環境ではskipする。
    #[cfg(windows)]
    #[tokio::test]
    async fn run_shell_cooperative_proxy_allows_and_denies_real_curl_requests() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        if which::which("curl").is_err() {
            eprintln!("skipping cooperative proxy test: curl not found on PATH");
            return;
        }

        // ダミーの許可済み宛先サーバ（ループバック）。1リクエストだけ受けて200を返す。
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = target_listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                    .await;
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let mut context = ctx(dir.path().to_path_buf());
        context.net_proxy = harness_core::NetProxyConfig {
            allow_domains: vec!["localhost".to_string()],
            ..Default::default()
        };
        let tool = RunShellTool::default();

        let command = format!(
            "curl.exe -s -w 'ALLOWED_STATUS=%{{http_code}}' http://localhost:{target_port}/; \
             curl.exe -s -o NUL -w ' DENIED_STATUS=%{{http_code}}' http://notallowed.invalid.example/"
        );
        let out = tool
            .call(json!({ "command": command }), &context)
            .await
            .unwrap();

        assert!(
            out.content.contains("ALLOWED_STATUS=200"),
            "curl through the cooperative proxy to an allowed domain should succeed: {}",
            out.content
        );
        assert!(
            out.content.contains("DENIED_STATUS=403"),
            "curl through the cooperative proxy to a disallowed domain should get 403 from the \
             proxy itself (not a connection failure to notallowed.invalid.example, which does \
             not need to resolve): {}",
            out.content
        );
        assert!(
            out.content.contains("[net-proxy: ALLOW localhost]"),
            "audit log should record the allowed request: {}",
            out.content
        );
        assert!(
            out.content
                .contains("[net-proxy: DENY notallowed.invalid.example]"),
            "audit log should record the denied request: {}",
            out.content
        );
        assert!(
            out.content.contains("hello"),
            "curl should receive the allowed response body: {}",
            out.content
        );
    }

    #[tokio::test]
    async fn run_shell_net_proxy_starts_fake_dns_diagnostic_agent() {
        let dir = tempfile::tempdir().unwrap();
        let mut context = ctx(dir.path().to_path_buf());
        context.net_proxy = harness_core::NetProxyConfig {
            allow_domains: vec!["example.com".to_string()],
            ..Default::default()
        };
        let tool = RunShellTool::default();

        let out = tool
            .call(
                json!({ "command": "Write-Output $env:HARNESS_FAKE_DNS_ADDR" }),
                &context,
            )
            .await
            .unwrap();

        assert!(
            out.content.contains("127.0.0.1:"),
            "fake DNS diagnostic address should be injected into child env: {}",
            out.content
        );
        assert!(
            out.content
                .contains("[net-fakedns: diagnostic-only addr=127.0.0.1:"),
            "run_shell footer should describe the fake DNS diagnostic agent: {}",
            out.content
        );
    }

    #[tokio::test]
    async fn run_shell_uses_session_scoped_proxy_and_fake_dns_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let mut context = ctx(dir.path().to_path_buf());
        context.net_proxy = harness_core::NetProxyConfig {
            allow_domains: vec!["example.com".to_string()],
            proxy_addr: Some("127.0.0.1:18080".parse().unwrap()),
            fake_dns_addr: Some("127.0.0.1:18053".parse().unwrap()),
            audit_log_path: Some(dir.path().join("net-audit.jsonl")),
            ..Default::default()
        };
        let tool = RunShellTool::default();

        let out = tool
            .call(
                json!({
                    "command": "Write-Output $env:ALL_PROXY; Write-Output $env:HARNESS_FAKE_DNS_ADDR"
                }),
                &context,
            )
            .await
            .unwrap();

        assert!(
            out.content.contains("socks5h://127.0.0.1:18080"),
            "session proxy address should be injected: {}",
            out.content
        );
        assert!(
            out.content.contains("127.0.0.1:18053"),
            "session Fake DNS address should be injected: {}",
            out.content
        );
        assert!(
            out.content.contains("[net-proxy-audit:"),
            "session proxy footer should still point at the JSONL audit log: {}",
            out.content
        );
        assert!(
            out.content
                .contains("[net-fakedns: diagnostic-only addr=127.0.0.1:18053]"),
            "session Fake DNS footer should describe the diagnostic agent: {}",
            out.content
        );
    }
}
