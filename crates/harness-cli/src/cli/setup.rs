//! 起動時の各種解決（ステージングモード・sandbox_dir・プロバイダ構築・セッション解決）と
//! セッション一覧の表示。`startup`の各段が使う「引数から実際の値を決める」処理を集める。

use super::*;

/// `--require-sandbox[=confidential]`の文字列表現を`RequireSandbox`へ変換する
/// （M12、`plans/DESIGN-SANDBOX.md` §7 D-03）。未知の値は`write-containment`扱いにする
/// （clapの`default_missing_value`と揃える安全側フォールバック）。
pub(crate) fn parse_require_sandbox(value: Option<&str>) -> RequireSandbox {
    match value {
        None => RequireSandbox::None,
        Some("confidential") => RequireSandbox::Confidential,
        Some(_) => RequireSandbox::WriteContainment,
    }
}

// `session_id` → オーバーレイの置き場、の写像は`harness_sandbox::session_scope`が正本
// （起動時のここと、セッション切替時の`harness-tui`の両方から引かれるため。以前は本ファイルと
// `tier2a::workspace_ledger`に同じ`ProjectDirs::…join("cow")`が複製されていた）。
pub(crate) use harness_sandbox::session_scope::sandbox_dir_for_session;

/// `--sandbox`の値がこのOSで通るか。**通らないものは黙って無視せず起動を拒否する。**
///
/// Tier1（Restricted Token + 低IL + Job Object）もTier2a（AppContainer）もWindows専用の機構で、
/// 他のOSには対応物が無い。指定を無視して別のTierで走ると、「隔離を指定したのに違う形で
/// 動いている」ことに気付けない。
///
/// **`harness prompt`と起動パイプラインの両方がここを通る**（同じ判定を2箇所に書くと、
/// 片方だけ直った状態が無言で残る。B-05/B-06）。
///
/// `tier3`をここで弾かないのは、従来の`--vm-sandbox`が非Windowsで単に無視されていた挙動を
/// そのまま残すためである（Tierの選択自体は`best_effort_tier`のOSごとの実装が決める）。
pub(crate) fn check_sandbox_choice_supported(choice: SandboxChoice) -> Result<(), String> {
    sandbox_choice_supported_on(choice, cfg!(windows))
}

/// [`check_sandbox_choice_supported`]の判定本体。**OSを引数で受ける純粋関数にしてある。**
///
/// `cfg!(windows)`を関数の中で読むと、テストを回せる唯一の機械（Windows）では
/// 早期returnより下が**丸ごとデッドコード**になり、拒否側を1度も測れない。
/// 壊しても永久に緑のままになるので、禁止側と許可側を対で測れる形にする
/// （`test-logic-rules`「禁止側と許可側を対にする」）。
pub(crate) fn sandbox_choice_supported_on(
    choice: SandboxChoice,
    is_windows: bool,
) -> Result<(), String> {
    if is_windows {
        return Ok(());
    }
    match choice {
        SandboxChoice::Auto | SandboxChoice::Tier3 => Ok(()),
        SandboxChoice::Tier1 | SandboxChoice::Tier2a | SandboxChoice::Tier2aCow => Err(format!(
            "--sandbox {} is only supported on Windows (Tier1 = Restricted Token + low IL, \
             Tier2a = AppContainer; neither exists on this OS). Leave --sandbox at its default \
             (auto) here.",
            choice.value_label()
        )),
    }
}

/// `--sandbox`と`--live`/`--staged`/`--workspace-commit`から、**書込捕捉の形を1度に決める**。
///
/// # なぜ1本の関数なのか
///
/// 「どのオーバーレイ機構で書込を捕まえるか」は、この2系統のフラグが**合わさって**決まる。
/// マニフェスト方式（`--staged`/`--workspace-commit`）とCoW方式（`--sandbox tier2a-cow`）は
/// 別々の捕捉機構で、同時に立てない——ところがclapの`conflicts_with`は
/// 「`--sandbox`が`tier2a-cow`のときだけ`--staged`と排他」という**値依存の排他**を宣言できない。
/// そこで拒否を実行時へ移した。
///
/// 移した先をここにしたのは、**本番の入口が2つある**からである
/// （`startup::sandbox::stage_prepare_sandbox`と`workspace_cmd::run_prompt_subcommand`）。
/// 片方（起動パイプライン）のガード位置に置くと`harness prompt`が素通りする
/// ——「同じ状態を作り得る経路が2つあるのに判定は1つにしかない」型の穴で、
/// `bug-pattern-rules` B-06そのものである。**両方がこの関数を通る。**
///
/// # 決め方
///
/// - `StagingMode`: 明示指定が無ければ常に`Live`（オプトイン。書込/読取の防御はシェル隔離Tierに
///   委ねる、D-29）。`live`分岐は他の2フラグが立っていなければ既定でも同じ結果になるため
///   論理的には冗長だが、`cli.live`を読む唯一の箇所なのでdead-code警告を避けるために明示する。
/// - `WorkspaceWriteMode`: `--sandbox tier2a-cow`のときだけ`Cow`。`session_id`はCoW 差分層の
///   採番に使う（`sandbox_dir_for_session`と同じ採番元）。`ProjectDirs`が解決できない
///   （HOME未設定等の異常環境）場合は起動を拒否する（安全側: 差分層が無いままRW付与へ
///   フォールバックしない）。**置き場はワークスペースのボリュームで決まる**（D-81）ので
///   `workspace_root`を受ける。
///
/// 3つ目の返り値は「置き場を`%LOCALAPPDATA%`へ降格した理由」で、`Some`なら
/// **呼び出し側が必ず表示する**（`bug-pattern-rules` B-09: 黙って弱い形に落ちない）。
pub(crate) fn resolve_staging_and_write_mode(
    choice: SandboxChoice,
    live: bool,
    staged: bool,
    workspace_commit: bool,
    session_id: &str,
    workspace_root: &std::path::Path,
) -> Result<(StagingMode, WorkspaceWriteMode, Option<String>), String> {
    let staging_mode = resolve_staging_mode_checked(choice, live, staged, workspace_commit)?;

    if !choice.wants_cow() {
        return Ok((staging_mode, WorkspaceWriteMode::DirectRw, None));
    }

    let chosen = harness_sandbox::session_scope::cow_diff_layer_root_for_workspace(workspace_root)?;
    let diff_layer_dir = harness_sandbox::session_scope::cow_diff_layer_dir_in(&chosen.root, session_id);
    Ok((
        staging_mode,
        WorkspaceWriteMode::Cow { diff_layer_dir },
        chosen.fell_back,
    ))
}

/// 書込捕捉の**組合せの妥当性だけ**を判定して`StagingMode`を返す（資源を1つも解決しない）。
///
/// [`resolve_staging_and_write_mode`]から切り出してあるのは、`harness prompt`のためである。
/// あちらは診断用の読み取り専用コマンドで`WorkspaceWriteMode`を捨てるのに、畳んだ関数を
/// そのまま呼ぶと**使わないCoW 差分層の解決失敗で落ちる**（`%LOCALAPPDATA%`が引けない環境）。
/// 排他判定は両方の入口が通す必要がある（B-06）が、資源の解決は起動側だけの都合なので分ける。
pub(crate) fn resolve_staging_mode_checked(
    choice: SandboxChoice,
    live: bool,
    staged: bool,
    workspace_commit: bool,
) -> Result<StagingMode, String> {
    let staging_mode = if live {
        StagingMode::Live
    } else if staged {
        StagingMode::Staged
    } else if workspace_commit {
        StagingMode::WorkspaceCommit
    } else {
        StagingMode::Live
    };

    if !choice.wants_cow() {
        return Ok(staging_mode);
    }

    // 値依存の排他。**黙って片方を無視しない**——どちらの機構で変更を拾うつもりだったかは
    // 打った本人にしか分からないので、勝手に決めずに止める。
    if staged || workspace_commit {
        let other = if staged {
            "--staged"
        } else {
            "--workspace-commit"
        };
        return Err(format!(
            "--sandbox tier2a-cow cannot be combined with {other}: they are two different write \
             capture mechanisms (a staging manifest vs. a Copy-on-Write diff_layer layer) and only one \
             can be in effect. Pick the one you want to review changes through."
        ));
    }

    Ok(staging_mode)
}

/// `--session <id>`指定が無い場合に`.harness/sandbox/`直下で最も更新日時の新しいものを選ぶ
/// （`apply`/`changes`/`discard`の既定対象）。
pub(crate) fn resolve_sandbox_dir(workspace_root: &Path, session: Option<&str>) -> Option<PathBuf> {
    if let Some(id) = session {
        let stem = id.strip_prefix("session-").unwrap_or(id);
        return Some(sandbox_dir_for_session(&format!("session-{stem}")));
    }
    let base = workspace_root.join(".harness").join("sandbox");
    let mut newest: Option<(String, std::time::SystemTime)> = None;
    let entries = std::fs::read_dir(&base).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if newest.as_ref().is_none_or(|(_, t)| modified > *t) {
            newest = Some((name.to_string(), modified));
        }
    }
    newest.map(|(name, _)| sandbox_dir_for_session(&name))
}

#[cfg(feature = "e2e-mock")]
pub(crate) fn build_mock_provider(
    mock_turns: Option<&Path>,
    mock_record_requests: Option<&Path>,
) -> Result<Box<dyn LlmProvider>, String> {
    let turns_path =
        mock_turns.ok_or_else(|| "--provider mock requires --mock-turns <path>".to_string())?;
    let mut provider = harness_providers::MockProvider::from_turns_file(turns_path)
        .map_err(|e| format!("failed to read --mock-turns {}: {e}", turns_path.display()))?;
    if let Some(record_path) = mock_record_requests {
        provider = provider.with_request_record_path(record_path.to_path_buf());
    }
    Ok(Box::new(provider))
}

pub(crate) fn build_provider(
    kind: ProviderKind,
    base_url_override: Option<String>,
    #[cfg(feature = "e2e-mock")] mock_turns: Option<&Path>,
    #[cfg(feature = "e2e-mock")] mock_record_requests: Option<&Path>,
) -> Result<Box<dyn LlmProvider>, String> {
    // §設定とシークレット: CLIフラグ > env優先、プロジェクト設定に永続化しない・ログに出さない・
    // 起動時fail-fast。
    match kind {
        #[cfg(feature = "e2e-mock")]
        ProviderKind::Mock => build_mock_provider(mock_turns, mock_record_requests),
        ProviderKind::Anthropic => {
            let api_key = std::env::var("ANTHROPIC_API_KEY")
                .map_err(|_| "ANTHROPIC_API_KEY is not set".to_string())?;
            match base_url_override.or_else(|| std::env::var("ANTHROPIC_BASE_URL").ok()) {
                Some(base_url) => Ok(Box::new(AnthropicProvider::with_base_url(
                    api_key, base_url,
                ))),
                None => Ok(Box::new(AnthropicProvider::new(api_key))),
            }
        }
        ProviderKind::Openai => {
            // LMStudioは空キー可（§プロバイダ抽象「LMStudioは空キー可」）なので、
            // 実OpenAIと異なり未設定でもfail-fastしない。
            let api_key = std::env::var("OPENAI_API_KEY").unwrap_or_default();
            match base_url_override.or_else(|| std::env::var("OPENAI_BASE_URL").ok()) {
                Some(base_url) => Ok(Box::new(OpenAiProvider::with_base_url(api_key, base_url))),
                None => Ok(Box::new(OpenAiProvider::new(api_key))),
            }
        }
        // §設定「LMStudio は単に base_url=http://localhost:1234/v1 の openai-family
        // プロファイル」。`--base-url`/`OPENAI_API_KEY`/`OPENAI_BASE_URL`での上書きも許す。
        ProviderKind::Lmstudio => {
            // 管理REST API（`/api/v1/`）のトークン。縮退ガードの (d) 段が使う
            // （`plans/DESIGN-COGNITION.md` §11.5）。この開発機のLM Studioでは認証不要のため
            // 通常は未設定で、その場合はトークンを付けずに叩く。
            let mgmt_token = std::env::var("LM_API_TOKEN").ok();
            match base_url_override.or_else(|| std::env::var("OPENAI_BASE_URL").ok()) {
                // **`with_base_url`ではなく`lmstudio_with_base_url`を使う**。前者は系統を
                // `OpenAiFamily::OpenAi`にしてしまい、`--provider lmstudio --base-url ...`が
                // `schema_with_tools:true`・`local:false`・`recycle`無効という、実体と食い違う
                // 能力表明で走っていた（縮約のローカル既定値も (d) 段も効かない）。
                Some(base_url) => Ok(Box::new(
                    OpenAiProvider::lmstudio_with_base_url(base_url).with_mgmt_token(mgmt_token),
                )),
                None => Ok(Box::new(
                    OpenAiProvider::lmstudio().with_mgmt_token(mgmt_token),
                )),
            }
        }
    }
}

/// `--resume <id>`/`--continue`/新規のいずれかで`SessionStore`を用意する
/// （M9、§非対話モード「JSONL 追記型セッション永続化」）。`resume`は値省略（空文字列、
/// ピッカー要求）を渡さない前提（呼び出し側で分岐済み）。
pub(crate) fn resolve_session(
    sessions_dir: &std::path::Path,
    resume: Option<&str>,
    continue_session: bool,
) -> Result<harness_engine::SessionStore, String> {
    if let Some(id) = resume {
        let path = harness_engine::SessionStore::resolve_path(sessions_dir, id);
        if !path.exists() {
            return Err(format!(
                "no session found for --resume {id} ({})",
                path.display()
            ));
        }
        return Ok(harness_engine::SessionStore::open(path));
    }
    if continue_session {
        return harness_engine::SessionStore::resume_latest(sessions_dir)
            .map_err(|e| format!("failed to find latest session: {e}"))?
            .ok_or_else(|| "no existing session to --continue".to_string());
    }
    harness_engine::SessionStore::create_new(sessions_dir)
        .map_err(|e| format!("failed to create session file: {e}"))
}

/// `--list-sessions`の出力レコード（`SessionSummary`はシリアライズ非対応のため、
/// `--output-format json/jsonl`用にここでJSON化可能な形へ写す）。
#[derive(serde::Serialize)]
pub(crate) struct SessionListEntry {
    id: String,
    modified_unix_millis: u128,
    message_count: usize,
    first_prompt: String,
}

impl From<&harness_engine::SessionSummary> for SessionListEntry {
    fn from(s: &harness_engine::SessionSummary) -> Self {
        Self {
            id: s.id.clone(),
            modified_unix_millis: s
                .modified
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            message_count: s.message_count,
            first_prompt: s.first_prompt.clone(),
        }
    }
}

pub(crate) fn print_session_list(
    summaries: &[harness_engine::SessionSummary],
    format: OutputFormat,
) {
    let entries: Vec<SessionListEntry> = summaries.iter().map(SessionListEntry::from).collect();
    match format {
        OutputFormat::Json => {
            if let Ok(s) = serde_json::to_string(&entries) {
                println!("{s}");
            }
        }
        OutputFormat::Jsonl => {
            for entry in &entries {
                if let Ok(s) = serde_json::to_string(entry) {
                    println!("{s}");
                }
            }
        }
        OutputFormat::Text => {
            if entries.is_empty() {
                println!("(no saved sessions)");
            }
            for entry in &entries {
                println!(
                    "{:<16} {:>4} msgs  {}",
                    entry.id, entry.message_count, entry.first_prompt
                );
            }
        }
    }
}
#[cfg(test)]
mod staging_mode_tests {
    use super::{resolve_staging_and_write_mode, sandbox_choice_supported_on};
    use harness_core::{SandboxChoice, StagingMode};
    use harness_sandbox::WorkspaceWriteMode;

    const SESSION: &str = "session-test";

    /// OS依存の受理判定を**両側**測る。`cfg!(windows)`を関数の中で読んでいた頃は、
    /// テストを回せる唯一の機械（Windows）で拒否側が一度も実行されず、
    /// 壊しても緑のままだった（`test-logic-rules`「禁止側と許可側を対にする」）。
    #[test]
    fn windows_accepts_every_sandbox_choice() {
        for choice in SandboxChoice::ALL {
            assert!(
                sandbox_choice_supported_on(choice, true).is_ok(),
                "{choice:?} should be accepted on Windows"
            );
        }
    }

    #[test]
    fn non_windows_rejects_only_the_windows_only_tiers() {
        for choice in SandboxChoice::ALL {
            let verdict = sandbox_choice_supported_on(choice, false);
            match choice {
                // 許可側: 従来の`--vm-sandbox`が非Windowsで無視されていた挙動を保つ。
                SandboxChoice::Auto | SandboxChoice::Tier3 => {
                    assert!(verdict.is_ok(), "{choice:?} should be accepted off Windows");
                }
                // 禁止側: Tier1もTier2aもWindows専用の機構で、他OSに対応物が無い。
                SandboxChoice::Tier1 | SandboxChoice::Tier2a | SandboxChoice::Tier2aCow => {
                    let message = verdict.expect_err("{choice:?} should be rejected off Windows");
                    assert!(
                        message.contains(choice.value_label()),
                        "拒否理由は打った綴りを名指しすること: {message}"
                    );
                }
            }
        }
    }

    /// 差分層の置き場の規則（D-81）はここでの主題ではないので、**プロファイルと必ず同じ
    /// ボリュームになるパス**を使う。別ボリュームのパスを渡すとそちらのルートへ
    /// `.harness-cow`を作りに行き、単体テストが実マシンに副作用を残す。
    fn test_workspace() -> std::path::PathBuf {
        harness_sandbox::session_scope::cow_profile_diff_layer_root()
            .expect("%LOCALAPPDATA% must resolve for these tests")
            .join("test-workspace")
    }

    /// staging側だけを見るヘルパ（`--sandbox`は既定`auto`）。
    fn staging(live: bool, staged: bool, workspace_commit: bool) -> StagingMode {
        resolve_staging_and_write_mode(
            SandboxChoice::Auto,
            live,
            staged,
            workspace_commit,
            SESSION,
            &test_workspace(),
        )
        .expect("auto never conflicts with the staging flags")
        .0
    }

    /// D-29: フラグ無指定時は常にLive（オプトイン、既定の安全策ではない）。
    #[test]
    fn no_flags_defaults_to_live() {
        assert_eq!(staging(false, false, false), StagingMode::Live);
    }

    #[test]
    fn staged_flag_selects_staged() {
        assert_eq!(staging(false, true, false), StagingMode::Staged);
    }

    #[test]
    fn workspace_commit_flag_selects_workspace_commit() {
        assert_eq!(staging(false, false, true), StagingMode::WorkspaceCommit);
    }

    #[test]
    fn live_flag_selects_live() {
        assert_eq!(staging(true, false, false), StagingMode::Live);
    }

    /// **`SandboxChoice`から`WorkspaceWriteMode`への写像を値ごとに固定する。**
    ///
    /// `tier2a-cow`だけがCoW、他は全部`DirectRw`。ここが崩れると、CoWを要求していないのに
    /// workspaceがROになる（逆にCoWを要求したのにRWのまま走る＝BUG-113）。
    /// **`SandboxChoice::ALL`を回す**ので、variantが増えたらこの表に無い値として落ちる（B-06）。
    #[test]
    fn every_sandbox_choice_maps_to_the_expected_write_mode() {
        for choice in SandboxChoice::ALL {
            let (staging, write_mode, _fell_back) =
                resolve_staging_and_write_mode(choice, false, false, false, SESSION, &test_workspace())
                    .expect("no staging flag is set, so nothing can conflict");
            assert_eq!(
                staging,
                StagingMode::Live,
                "{}: --sandbox must not change the staging mode by itself",
                choice.value_label()
            );
            match choice {
                SandboxChoice::Tier2aCow => assert!(
                    matches!(write_mode, WorkspaceWriteMode::Cow { .. }),
                    "tier2a-cow must produce a CoW diff layer, got {write_mode:?}"
                ),
                SandboxChoice::Auto
                | SandboxChoice::Tier1
                | SandboxChoice::Tier2a
                | SandboxChoice::Tier3 => assert!(
                    matches!(write_mode, WorkspaceWriteMode::DirectRw),
                    "{} must stay on the direct-RW workspace, got {write_mode:?}",
                    choice.value_label()
                ),
            }
        }
    }

    /// **禁止側**: マニフェスト方式とCoW方式は同時に立てられない。clapの`conflicts_with`では
    /// 表せない値依存の排他なので、ここが唯一の拒否点である。
    #[test]
    fn cow_is_rejected_together_with_the_manifest_based_staging_modes() {
        for (staged, workspace_commit, expected_flag) in [
            (true, false, "--staged"),
            (false, true, "--workspace-commit"),
        ] {
            let err = resolve_staging_and_write_mode(
                SandboxChoice::Tier2aCow,
                false,
                staged,
                workspace_commit,
                SESSION,
                &test_workspace(),
            )
            .expect_err("two write capture mechanisms must not both be armed");
            assert!(
                err.contains(expected_flag) && err.contains("tier2a-cow"),
                "the rejection must name both flags so the user knows what to drop: {err}"
            );
        }
    }

    /// **許可側**（禁止側と対で測る、`test-logic-rules`）。`--sandbox tier2a-cow`単体は通り、
    /// `--live`との併用も通る（`--live`はCoWと意味的に矛盾しないので排他にしていない）。
    /// 禁止側だけを固定すると「全部拒否する」実装でもテストが緑になる。
    #[test]
    fn cow_alone_and_cow_with_live_are_accepted() {
        for live in [false, true] {
            let (staging, write_mode, _fell_back) = resolve_staging_and_write_mode(
                SandboxChoice::Tier2aCow,
                live,
                false,
                false,
                SESSION,
                &test_workspace(),
            )
            .expect("--sandbox tier2a-cow on its own must start");
            assert_eq!(staging, StagingMode::Live);
            let diff_layer = write_mode
                .diff_layer_dir()
                .expect("tier2a-cow must carry a CoW diff layer directory");
            assert!(
                diff_layer.ends_with(SESSION),
                "the diff layer directory must be numbered by session id: {}",
                diff_layer.display()
            );
        }
    }
}
