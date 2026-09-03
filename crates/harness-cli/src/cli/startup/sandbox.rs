//! 起動パイプライン Stage4: サンドボックス関連の確定。
//!
//! staging mode・`sandbox_dir`・`read_scope`・net proxy/app・`require_sandbox`・
//! fs passthrough・privhelper昇格・WFP連鎖パイプ・`write_mode`・`select_tier`。

use super::session::SessionOpened;
use super::*;

/// [`stage_prepare_sandbox`]の出力。Stage5（`stage_run_agent`）が必要とする値を運ぶ。
pub(super) struct SandboxPrepared {
    pub(super) cli: Cli,
    pub(super) workspace_root: PathBuf,
    pub(super) resume_wants_picker: bool,
    pub(super) provider: Box<dyn LlmProvider>,
    pub(super) model: String,
    pub(super) max_turns: usize,
    pub(super) compaction: harness_engine::compaction::CompactionPolicy,
    pub(super) degeneracy: Option<harness_engine::degeneracy::DegeneracyDetector>,
    pub(super) enter_submits: bool,
    pub(super) tools: ToolRegistry,
    pub(super) arbiter: PermissionArbiter,
    pub(super) cognition: CognitiveOrchestrator,
    pub(super) sessions_dir: PathBuf,
    pub(super) session: harness_engine::SessionStore,
    pub(super) session_messages: Vec<harness_core::Message>,
    pub(super) staging_mode: StagingMode,
    pub(super) sandbox_dir: Option<PathBuf>,
    pub(super) read_scope: harness_core::ReadScopeConfig,
    pub(super) net_proxy: NetProxyConfig,
    pub(super) net_app: harness_core::NetAppPolicy,
    pub(super) run_shell_path_extra: Vec<String>,
    pub(super) fs_passthrough: Vec<harness_sandbox::FsPassthrough>,
    pub(super) settings_fs_paths: std::collections::HashSet<String>,
    /// M15.7: セッション中のOS監査収集を有効にするか（`--policy-learn`→`settings.policy.learn`→false）。
    /// **`ToolCtx`には載せない**——収集器は受動的で`run_shell`の挙動を変えないため。
    pub(super) policy_learn: bool,
    #[cfg(windows)]
    pub(super) wfp_prelude: Option<harness_sandbox::tier2a::netfilterd::PreparedPipe>,
    #[cfg(not(windows))]
    pub(super) wfp_prelude: Option<String>,
    pub(super) write_mode: harness_sandbox::WorkspaceWriteMode,
    pub(super) shell_tier: harness_core::ShellTierSelection,
    /// MCPサーバ宣言（M15.5）。承認照合・起動はStage5（`stage_run_agent`）が、Tier確定と
    /// WFP適用の間で行う（順序が本質、`startup::mcp`のモジュールdoc参照）。
    pub(super) mcp_decls: Vec<harness_mcp::McpServerDecl>,
    /// Streamable HTTPのセッションゲート（M15.6、D-49）。**ユーザ層設定とCLIからしか来ない**
    /// ——プロジェクト層の分は`harness_config::clamp_project_mcp_http_gates`が剥がしている。
    pub(super) mcp_gates: harness_mcp::McpGates,
}

/// staging mode・`sandbox_dir`・`read_scope`・net proxy/app・`require_sandbox`・
/// fs passthrough・privhelper昇格・WFP連鎖パイプ・`write_mode`・`select_tier`。
pub(super) fn stage_prepare_sandbox(
    session_opened: SessionOpened,
) -> Result<SandboxPrepared, ExitCode> {
    let SessionOpened {
        cli,
        workspace_root,
        resume_wants_picker,
        settings,
        provider,
        model,
        max_turns,
        compaction,
        degeneracy,
        enter_submits,
        tools,
        arbiter,
        cognition,
        sessions_dir,
        session,
        session_messages,
        forked_from_session_id,
    } = session_opened;

    // `/workspace`の再起動で起こされた子は、ここから先（`select_tier`→`preflight`）へ入る前に
    // 親の終了を待つ。名前付きmutex（workspaceのモードマーカー・CoWのセッションマーカー）は
    // プロセス寿命に紐付いているので、親が生きているうちにpreflightへ入ると「使用中」と
    // 誤判定され得る（`startup::relaunch`のモジュールdoc）。
    if let Some(pid) = cli.wait_for_pid {
        super::relaunch::wait_for_parent_exit(pid);
    }

    // 書込ステージング設定（M10・D-29）。`sandbox_dir`は`session.id()`確定後でなければ組めない
    // ため、ここで`ToolCtx`を構築する。既定（フラグ無指定）を含め`Live`実効時はオーバーレイ
    // 自体を使わない（`sandbox_dir: None`、M9までの直接実FSアクセスとバイト等価・監査ログも
    // 作らない）。書込/読取の実防御はシェル隔離Tier（既定Tier2a=AppContainer）に委ねる。
    //
    // **`--sandbox`と`--live`/`--staged`/`--workspace-commit`は1本の関数で一緒に解く**
    // （`setup::resolve_staging_and_write_mode`）。`tier2a-cow`×`--staged`の排他は値依存で
    // clapが表せないため、拒否はその関数が持つ——`harness prompt`も同じ関数を通るので、
    // 片方の入口だけ守られる形にはならない（B-06）。
    let sandbox_choice: SandboxChoice = sandbox_choice_of(cli.sandbox);
    if let Err(e) = check_sandbox_choice_supported(sandbox_choice) {
        eprintln!("error: {e}");
        return Err(ExitCode::FAILURE);
    }
    let (staging_mode, write_mode, diff_layer_root_fell_back) = match resolve_staging_and_write_mode(
        sandbox_choice,
        cli.live,
        cli.staged,
        cli.workspace_commit,
        &session.id(),
        &workspace_root,
    ) {
        Ok(triple) => triple,
        Err(e) => {
            eprintln!("error: {e}");
            return Err(ExitCode::FAILURE);
        }
    };
    // D-81: 差分層をワークスペースと同じボリュームへ置けなかった。隔離は同じように張れるので
    // 続行するが、**「媒体と一緒に消える」性質が失われたことは黙らせない**——これを黙ると、
    // ボリュームを外した後に回収できない差分層が残る理由が誰にも分からなくなる。
    if let Some(reason) = diff_layer_root_fell_back {
        eprintln!("warning: {reason}");
    }
    let sandbox_dir = if staging_mode == StagingMode::Live {
        None
    } else {
        Some(sandbox_dir_for_session(&session.id()))
    };
    // **ここで実際に作る。** このディレクトリは`net-audit.jsonl`/`fs-audit.jsonl`の置き場として
    // 昇格ヘルパー（`harness-netfilterd`・`harness-policy-learnd`）へ渡され、受け取った側は
    // D-44の検証で`canonicalize`する——存在しないパスは正規化できないので**起動が失敗する**。
    // 監査ログの書き手はどちらも「最初の1件を書くときに親を`create_dir_all`する」遅延作成
    // （`net_proxy.rs`の`push`）なので、新規ワークスペースでは検証の時点でまだ存在しない。
    // その結果`--net-allow-domain`はWFPを起動できずfail-closed（通信が一切できない）になり、
    // `--policy-learn`は収集器を起動できずに黙って無効化されていた。
    // 遅延作成に頼れるのは書き手が1人のときだけで、**パスを他プロセスへ渡す瞬間から
    // 「存在すること」が契約になる**。
    if let Some(dir) = &sandbox_dir {
        let path = workspace_root.join(dir);
        if let Err(e) = std::fs::create_dir_all(&path) {
            eprintln!(
                "warning: could not create the sandbox session directory {} ({e}); \
                 network/FS audit sinks that depend on it will be unavailable this session",
                path.display()
            );
        }
    }

    // `--fork-session`: 元セッションの未適用変更も分岐先へ持っていく。TUIの`/fork`と同じ
    // `session_scope::fork_overlay`を通す——**同じ状態（forkされたセッション）を作り得る経路が
    // 2つある**ので、片方だけ実装すると「CLIでforkしたときだけ変更が見えない」形の穴になる
    // （`bug-pattern-rules` B-06）。
    //
    // **`--sandbox tier2a-cow`でもここを通る**（2026-09-01に読み直して訂正。以前は
    // 「CoWのACE付与は`preflight`が後で行うため、ここでは`--staged`系だけが対象になる」と
    // 書いてあったが、事実ではない）。`ScopeTemplate::new`は`write_mode`が`Cow`なら
    // `ScopeTemplate::Cow`を返し、`scope_for`は`cow_diff_layer_dir: Some(..)`を返すので、
    // `fork_overlay`→`prepare_scope`は**差分層のACEをここで書く**——`--fork-session`と
    // `--sandbox tier2a-cow`の併用を拒む判定はどこにも無い。
    //
    // **この関数は`select_tier`（内部で`preflight`）より前にある。** つまりここへ来た時点では
    // まだ`preflight`が`session_profile::begin_session`を呼んでいない。
    // **[BUG-147] だから`prepare_cow_diff_layer`が自分で開く**——ACEを書く前に
    // `begin_session`を通すので、この経路で付けた差分層のACEもその場で台帳に載る。
    //
    // かつてここには「記録できないが、後続の`preflight`が同じ差分層へ付け直して記録するので
    // 警告だけが偽である」と書いてあった。**その一文は`preflight`が成功した回しか含んでいない**
    // ——下の`select_tier`が`Err`を返すと`ExitCode::FAILURE`で起動ごと打ち切るので、付け直しは起きず、
    // ACEだけが撤収の索引を持たないまま実マシンに残っていた（実測は
    // `plans/mac-spike/RESULTS.md` §S43）。順序を直したので、打ち切られた回でも
    // `end_session`と次回起動のGCが引ける。
    if let Some(source_id) = &forked_from_session_id {
        let template =
            harness_sandbox::session_scope::ScopeTemplate::new(&write_mode, staging_mode);
        let (from, to) = (
            template.scope_for(source_id),
            template.scope_for(&session.id()),
        );
        match harness_sandbox::session_scope::fork_overlay(&workspace_root, &from, &to) {
            Ok(0) => {}
            Ok(copied) => eprintln!(
                "note: carried {copied} overlay file(s) from {source_id} into the forked session \
                 (unapplied changes stay reviewable in both)"
            ),
            // 会話のforkは既に済んでいる。ここで起動を止めると「forkはできたが起動できない」に
            // なるので、変更が分岐先へ来ていないことだけを名指しして続ける（元セッション側に
            // 残っているので失われてはいない）。
            Err(e) => eprintln!(
                "warning: could not carry {source_id}'s unapplied changes into the forked session \
                 ({e}); they remain reviewable with `harness changes --session {source_id}`"
            ),
        }
    }

    let read_scope = settings
        .read
        .clone()
        .unwrap_or_default()
        .to_read_scope_config();

    // 協調プロキシ設定（M12補遺、D-15）。CLI `--net-allow-domain`（繰り返し）と
    // `.harness/settings.json`の`net.allow_domains`を和集合でマージする（重複除去）。
    let mut net_proxy = settings
        .net
        .clone()
        .unwrap_or_default()
        .to_net_proxy_config();
    if let Err(e) = validate_and_merge_net_allow_domains(&mut net_proxy, &cli.net_allow_domain) {
        eprintln!("error: invalid network domain policy: {e}");
        return Err(ExitCode::FAILURE);
    }
    if net_proxy.audit_log_path.is_none() {
        if let Some(dir) = &sandbox_dir {
            net_proxy.audit_log_path = Some(workspace_root.join(dir).join("net-audit.jsonl"));
        }
    }

    // アプリ単位network制御（軸1、D-10/D-11）。CLI `--net-allow-app`（繰り返し）と
    // `.harness/settings.json`の`net.allow_apps`を和集合でマージする（重複除去、net_proxyと同形）。
    let mut net_app = settings.net.clone().unwrap_or_default().to_net_app_policy();
    for app in &cli.net_allow_app {
        if !net_app.allow_apps.contains(app) {
            net_app.allow_apps.push(app.clone());
        }
    }
    // M15.7: `--policy-learn`が最優先、無指定なら`settings.json`の`policy.learn`、既定false
    // （オプトイン。有効化するとUACが1回出るため、黙って有効にはしない）。
    let policy_learn = cli
        .policy_learn
        .unwrap_or_else(|| settings.policy.clone().unwrap_or_default().learn_enabled());

    let run_shell_path_extra = settings.run_shell.clone().unwrap_or_default().path_extra();

    // MCPサーバ宣言（M15.5）。**ここでは解釈だけ**で、承認照合も起動も行わない
    // （`startup::mcp`のモジュールdoc参照）。綴り間違いは黙って無視せず起動を止める——
    // 「設定したのに効かない」に気付けないと、裏取りしたつもりで裏取りしていない結論を
    // 受け取ることになる。
    let mcp_decls = match harness_mcp::parse_mcp_settings(settings.mcp.as_ref()) {
        Ok(decls) => decls,
        Err(e) => {
            eprintln!("error: {e}");
            return Err(ExitCode::FAILURE);
        }
    };

    // M15.6（D-49）: Streamable HTTPのゲート。`settings.mcp`はここへ来る時点で
    // プロジェクト層の分が剥がされている（`harness_config::clamp_project_mcp_http_gates`）ので、
    // 残っているのはユーザ層の値だけ。そこへCLIフラグを重ねる。
    let mcp_gates = match build_mcp_gates(&cli, settings.mcp.as_ref()) {
        Ok(gates) => gates,
        Err(e) => {
            eprintln!("error: {e}");
            return Err(ExitCode::FAILURE);
        }
    };

    // シェル隔離Tier選択（M12、`plans/DESIGN-SANDBOX.md` §6/§7 D-03）。`--require-sandbox`指定時は
    // 自動降格せず起動を拒否する（既存の`--dangerously-allow`と同じfail-fastパターン）。
    let require_sandbox = parse_require_sandbox(cli.require_sandbox);

    // confidential（外部持出し経路を作らない明示拒否モード＝通信許可リストを無効化する上位モード）
    // と net-allow-domain/net-allow-app（通信を開く）は意味的に矛盾するため、黙って無視/弱めず起動を拒否する
    // （`--require-sandbox`のsatisfiesと同じfail-fast思想、`plans/DESIGN-SANDBOX-APPPOLICY.md` §7）。
    if require_sandbox == RequireSandbox::Confidential
        && (!net_proxy.allow_domains.is_empty() || !net_app.allow_apps.is_empty())
    {
        eprintln!(
            "error: network allow rules (--net-allow-domain / --net-allow-app / settings net.*) \
             conflict with --require-sandbox=confidential (confidential \
             mode denies all outbound network unconditionally; refusing to start rather than \
             silently ignoring network allow rules or weakening the confidentiality guarantee)"
        );
        return Err(ExitCode::FAILURE);
    }

    // fs passthrough allowlist（軸2・D-13）。CLI `--fs-allow`（繰り返し）と
    // `.harness/settings.json`の`fs.allow`を和集合でマージする（重複除去、net_appと同形）。
    // 各要素は`<path>[:rw]`（末尾`:rw`が無ければread-only既定、D-13）。パスは`workspace_root`
    // 基準で絶対化する（既に絶対パスなら`Path::join`はそのまま採用する）。
    let settings_fs_entries: Vec<(String, harness_config::FsAccess)> =
        settings.fs.clone().unwrap_or_default().to_fs_passthrough();
    // このワークスペースが現在`.harness/settings.json`経由で宣言しているfs passthroughパスの
    // 絶対パス集合（D-27）。`--fs-allow`由来のパスは含めない（対象は設定ファイル経由の宣言のみ）。
    //
    // [D-63] **台帳に載るのと同じ「付与ルート」で集める。** 台帳が記録するのはACEを実際に付けた
    // オブジェクト（`C:/x/**`なら`C:/x`）なので、宣言文字列のまま集めると`**`付きの宣言が
    // 台帳のどのエントリとも一致しない。一致しないと、D-27の自動整合が「もう誰も宣言していない」と
    // 判定して**毎起動で自動撤収**し、次の起動で付け直す往復になる。
    //
    // 受け付けない綴り（下の`retain`が弾く中間ワイルドカード）は**ここでも数えない**——
    // 付与しないパスを「このワークスペースが宣言している」と数えると、他の経路が付けた
    // 同名の台帳エントリを自動撤収から守ってしまう（参照カウントは付与と対でなければ嘘になる）。
    let settings_fs_paths: std::collections::HashSet<String> = settings_fs_entries
        .iter()
        .filter(|(path, _)| !harness_policy::normalize::has_unsupported_wildcard(path))
        .map(|(path, _)| {
            grant_root_of(&workspace_root, path)
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    let mut fs_allow_raw: Vec<(String, harness_config::FsAccess)> = settings_fs_entries;
    for entry in &cli.fs_allow {
        let (path, access) = match entry.strip_suffix(":rw") {
            Some(p) => (p.to_string(), harness_config::FsAccess::ReadWrite),
            None => (entry.clone(), harness_config::FsAccess::ReadExec),
        };
        // **同じパスが既にあっても捨てない。** 捨てると、設定に`fs.read`で書いてあるパスへ
        // `--fs-allow <path>:rw`を足したときに書込要求が黙って消える（先に入った方が残る）。
        // access種別まで同じものだけを重複と見なし、種別が違うものは下の畳み込みで**和を取る**。
        if !fs_allow_raw.iter().any(|(p, a)| p == &path && *a == access) {
            fs_allow_raw.push((path, access));
        }
    }
    // --force-system-acl（D-19）はread-only専用（システムディレクトリへの書込強制は危険すぎる）。
    // `:rw`エントリが1つでもあれば起動を拒否する（fail-fast、--require-sandboxのD7と同じ思想）。
    if cli.force_system_acl
        && fs_allow_raw
            .iter()
            .any(|(_, access)| *access == harness_config::FsAccess::ReadWrite)
    {
        eprintln!(
            "error: --force-system-acl requires read-only --fs-allow entries (a :rw entry is \
             present); forcing writable ACEs into system-protected paths is refused. Drop :rw or \
             drop --force-system-acl."
        );
        return Err(ExitCode::FAILURE);
    }
    // [D-63] **`<path>/**`以外のワイルドカードは受け付けない。** 確定部分が`C:/x`まで戻るため、
    // 再帰にすれば宣言よりはるかに広く、オブジェクト単体にすれば何も開かない——どちらも宣言と
    // 一致しない（D-62で`--generalize=auto`を廃した理由そのもの）。**黙って落とさず名指しで
    // 出す**（B-10）: 設定に書いたものが効いていないことに気付けないと、拒否の原因を別の場所に
    // 探し続けることになる。起動自体は止めない（既存の「存在しないパスはスキップ」と同じ扱い）。
    fs_allow_raw.retain(|(path, _)| {
        if !harness_policy::normalize::has_unsupported_wildcard(path) {
            return true;
        }
        eprintln!(
            "warning: fs allow entry {path:?} is ignored: only a trailing `/**` is supported as a \
             wildcard. Write `{}/**` to open the whole subtree, or name the paths you actually \
             need. (A wildcard in the middle would grant ACEs on `{}` -- everything under it.)",
            harness_policy::normalize::literal_prefix(path),
            harness_policy::normalize::literal_prefix(path)
        );
        false
    });
    // **同じパスへの宣言は1本のACEへ畳む（和を取る）。** 1つのオブジェクトのDACLへ同じSID宛の
    // ACEを2本持つことはできないので、ここで畳まないと後段のどちらかの付与が上書きになる。
    // 合成の規則は`harness_sandbox::FsAccess::wider`が唯一の定義を持つ（B-05）。
    let mut fs_passthrough: Vec<harness_sandbox::FsPassthrough> = Vec::new();
    for (path, access) in fs_allow_raw {
        // [D-63] 宣言値から**付与ルートと範囲の両方**を決める。判定は
        // `harness_policy::normalize`が唯一持つ（`literal_prefix`と`declared_scope`の対）。
        let scope = harness_policy::normalize::declared_scope(&path);
        let root = grant_root_of(&workspace_root, &path);
        let access = harness_sandbox::FsAccess::from_settings(access);
        match fs_passthrough.iter_mut().find(|fp| fp.path == root) {
            Some(existing) => {
                existing.access = existing.access.wider(access);
                // **同じルートに素の宣言と`**`宣言が同居したら再帰を採る。** 1つのオブジェクトの
                // DACLへ同じSID宛のACEを2本置けないので、accessを和で畳むのと同じ理屈になる。
                if scope.is_recursive() {
                    existing.scope = scope;
                }
            }
            None => fs_passthrough.push(harness_sandbox::FsPassthrough {
                path: root,
                access,
                forced: cli.force_system_acl,
                scope,
            }),
        }
    }
    if !fs_passthrough.is_empty() && !cfg!(windows) {
        eprintln!(
            "warning: --fs-allow / fs.allow is only supported on Windows (Tier2a); ignored on \
             this OS"
        );
    }

    // fs passthrough ACEのライフサイクル自動整合（D-27）。`.harness/settings.json`から
    // 消えたエントリのうち、どのワークスペースからも参照されなくなったものだけACEを撤収する
    // （複数ワークスペースが同じパスを共有宣言している場合は、他が参照している限り残す）。
    // Tier2aが実際に選択されるかどうかとは独立に、起動のたびに毎回行う（設定変更の反映は
    // Tierの降格有無と無関係のため）。`select_tier`（preflight）より前に行う。
    #[cfg(windows)]
    crate::fs_grants::reconcile_fs_ledger_for_workspace(&workspace_root, &settings_fs_paths);

    // D7: --require-sandboxとの矛盾チェック。write-containmentは範囲外書込を禁じるため:rwのみ
    // 拒否（:roは書込に無関係で許可）。confidentialは範囲外を読めない保証のため:ro/:rwいずれも
    // 拒否する（外部読取穴がconfidentialの機密性保証と正面から矛盾するため、
    // `--net-allow-app`×confidentialと同じfail-fast思想）。
    let fs_has_write = fs_passthrough.iter().any(|fp| fp.access.is_read_write());
    match require_sandbox {
        RequireSandbox::WriteContainment if fs_has_write => {
            eprintln!(
                "error: --fs-allow with :rw conflicts with --require-sandbox (write-containment \
                 forbids writes outside the workspace; use read-only --fs-allow entries instead, \
                 or drop --require-sandbox)"
            );
            return Err(ExitCode::FAILURE);
        }
        RequireSandbox::Confidential if !fs_passthrough.is_empty() => {
            eprintln!(
                "error: --fs-allow conflicts with --require-sandbox=confidential (confidential \
                 mode denies reading outside the workspace unconditionally; even read-only \
                 --fs-allow breaks this guarantee; refusing to start rather than silently \
                 weakening it)"
            );
            return Err(ExitCode::FAILURE);
        }
        _ => {}
    }

    // WFP 出口強制（Layer2、`~/Downloads/appcontainer-wfp-sandbox-spec-v1.md`付録D）の
    // named pipeを、`select_tier`（内部で`preflight`を呼ぶ）より前に用意しておく。
    // Tier2aはフラグ無しで既定プローブされるため、ドメインポリシー監査が有効な場合は常に投機的に用意しておく
    // （そうでなければWFPは不要＝シナリオ(C)、パイプすら作らずUACゼロを保つ）。ここで作った
    // パイプ名は、`preflight`経由で特権分離ヘルパーへ「処理完了後この名前でnetfilterdを
    // 連鎖起動してほしい」という指示として渡す（シナリオ(A)）。実際にTier2aへ降格せずに
    // 終わる、またはprivhelperへの委譲が発生しなかった場合（シナリオ(B)/(C)）は、この
    // パイプは未使用のまま閉じるか、`NetfilterHandle::start`の直接起動へ切り替える
    // （下記`net_wfp`解決を参照）。
    #[cfg(windows)]
    let wfp_prelude: Option<harness_sandbox::tier2a::netfilterd::PreparedPipe> =
        if net_proxy.domain_policy_enabled {
            match harness_sandbox::tier2a::netfilterd::prepare_pipe() {
                Ok(prepared) => Some(prepared),
                Err(e) => {
                    // ここでの失敗はシナリオ(A)（privhelperによる連鎖起動）の断念であって、
                    // Layer2の断念ではない——`wfp_chain_pipe`が`None`になると
                    // `netfilterd_chain_attempted`が立たず、`run_agent.rs`の`net_wfp`解決は
                    // シナリオ(B)（`NetfilterHandle::start`が自前でパイプを作り昇格起動する）へ
                    // 倒れる。そのため「協調プロキシのみへ縮退」と断定しない。拒否が確定するのは
                    // シナリオ(B)も失敗したときで、その文言（`TIER2A_NET_DENIED`）はそちらが出す。
                    eprintln!(
                        "warning: failed to prepare the WFP netfilterd chain-launch pipe; \
                         netfilterd will not be chain-launched by the privilege-separation \
                         helper this session and harness will try to start it directly instead \
                         (Layer2 enforcement is not given up here; if that direct start also \
                         fails, the warning it prints states the resulting fail-closed \
                         behavior): {e}"
                    );
                    None
                }
            }
        } else {
            None
        };
    #[cfg(not(windows))]
    let wfp_prelude: Option<String> = None;
    #[cfg(windows)]
    let wfp_chain_pipe = wfp_prelude.as_ref().map(|p| p.name().to_string());
    #[cfg(not(windows))]
    let wfp_chain_pipe: Option<String> = None;

    let shell_tier = match select_tier(
        require_sandbox,
        &workspace_root,
        sandbox_choice,
        &fs_passthrough,
        wfp_chain_pipe,
        &write_mode,
        // D-60: harness本体は起動シーケンスで**1回しか**ここを通らないので、連鎖元になる
        // 常駐daemonはまだ居ない（netfilterdはこの`select_tier`より後で立つ）。`None`＝自前で
        // `runas`する。「最大UAC1回」は、この1回で3ヘルパー全部を賄う既存の連鎖
        // （privhelper → netfilterd → 収集器）で成立している。
        None,
    ) {
        Ok(selection) => selection,
        Err(e) => {
            eprintln!("{e}");
            return Err(ExitCode::FAILURE);
        }
    };

    sweep_empty_cow_diff_areas();
    sweep_stale_aces_on_cow_diff_areas();

    Ok(SandboxPrepared {
        cli,
        workspace_root,
        resume_wants_picker,
        provider,
        model,
        max_turns,
        compaction,
        degeneracy,
        enter_submits,
        tools,
        arbiter,
        cognition,
        sessions_dir,
        session,
        session_messages,
        staging_mode,
        sandbox_dir,
        read_scope,
        net_proxy,
        net_app,
        run_shell_path_extra,
        fs_passthrough,
        settings_fs_paths,
        policy_learn,
        wfp_prelude,
        write_mode,
        shell_tier,
        mcp_decls,
        mcp_gates,
    })
}

/// [D-63] 宣言値から**ACEを実際に付けるオブジェクト**を求め、workspace基準で絶対化する。
///
/// 切る位置は`harness_policy::normalize::literal_prefix`が唯一の定義を持つ（ポリシーエディタの
/// `approve::grant_root`・幅の判定`breadth::check`と同じ関数）。ここで別に切ると、**判定した値と
/// 付与する値が食い違う**（B-05）。
///
/// 既に絶対パスなら`Path::join`はそれをそのまま採る（従来どおり）。
fn grant_root_of(workspace_root: &Path, declared: &str) -> PathBuf {
    workspace_root.join(harness_policy::normalize::literal_prefix(declared))
}

/// Streamable HTTPのセッションゲート（D-49）を、ユーザ層設定とCLIフラグから組み立てる。
///
/// - 宛先allowlist: 両者の**和集合**。CLIで足せるが、設定から取り除くことはできない
/// - 有効化: **宛先が1つでもあれば有効**。設定の`allow_streamable_http`も引き続き読むが、
///   宛先が空なら結局1つも起動しない（closed-by-default）ので、有効化の口を分けても
///   「有効なのに何も起きない」と「宛先はあるのに無効」という空振りが増えるだけだった
///   （`plans/DESIGN-CLI-OPTIONS.md` §5.6 B1-3）
/// - 平文: **CLIだけ**、しかも**書いたドメインに限って**許す。設定ファイルにも宣言にも
///   同等のスイッチを置かない
fn build_mcp_gates(
    cli: &Cli,
    mcp_settings: Option<&serde_json::Value>,
) -> Result<harness_mcp::McpGates, String> {
    let settings = harness_mcp::parse_mcp_http_gates(mcp_settings)?;

    // 設定側の宛先は常にhttpsのみ（平文はCLIでしか開けられない）。
    let mut domains = Vec::new();
    for domain in settings.http_allow_domains {
        let domain = normalize_domain_pattern(&domain)?;
        if !domains.contains(&domain) {
            domains.push(domain);
        }
    }

    let mut plaintext_domains = Vec::new();
    for value in &cli.mcp_http_allow {
        let (domain, plaintext) = harness_mcp::parse_http_allow_value(value)?;
        if !domains.contains(&domain) {
            domains.push(domain.clone());
        }
        if plaintext && !plaintext_domains.contains(&domain) {
            plaintext_domains.push(domain);
        }
    }

    // **宛先が空でも設定が有効化していれば「有効」と答える。** 起動できる宣言は結局0件だが、
    // `harness mcp list`が「HTTPは無効」ではなく「有効・宛先0件」と出せる方が、
    // 何が足りないかを言い当てられる（B-11: 効かなかった理由を黙らせない）。
    let enabled = settings.allow_streamable_http || !domains.is_empty();

    Ok(harness_mcp::McpGates {
        streamable_http_enabled: enabled,
        http_endpoints: harness_mcp::EndpointGates {
            allow_domains: harness_core::DomainPolicy::new(domains),
            plaintext_domains: harness_core::DomainPolicy::new(plaintext_domains),
        },
        http_ca_bundle: settings.http_ca_bundle.map(PathBuf::from),
    })
}

/// 何も残っていないCoW差分層を回収する（D-82の回収点2）。
///
/// # なぜ`preflight`ではなくここなのか
///
/// 最初は`preflight`の`gc_dead_sessions`の隣へ置いた。**それは実害を出した**——`preflight`は
/// `harness-sandbox`の実機テストが直接呼ぶ関数で、それらはworkspaceだけをtempdirにし、
/// 差分層の置き場（`%LOCALAPPDATA%`）は実物を使う。結果、`cargo test --workspace`が
/// 開発機の差分層を70件消した。規則自体は正しく動いて中身のあるものは残ったが、
/// **テストが実マシンのユーザーデータを消してよい理由にはならない**。
///
/// `harness-cli`の起動経路に置けば、TUIもheadlessも通り（B-06: 入口を片方だけ掃除しない）、
/// テストは通らない。
///
/// # ここで消さないもの
///
/// 消すのは「操作台帳を再生しても変更が無く、実体ファイルも無い」ものだけ。**実ワークスペース
/// とは突き合わせない**——起動のたびに全セッション×実ワークスペースを読むと、いま開いてすら
/// いない他のワークスペースまで触ることになる。`apply`を通さずに終わった差分層や、適用済みで
/// 実体だけが残ったものは「変更を抱えている」と判定されて残るので、`harness cow gc`が受け持つ。
#[cfg(windows)]
fn sweep_empty_cow_diff_areas() {
    use harness_sandbox::tier2a::workspace_ledger as wl;

    let outcome = wl::run_cow_gc(false, cow_gc_policy(), &|_, _| false);
    if !outcome.collected.is_empty() {
        eprintln!(
            "note: collected {} empty copy-on-write diff area(s) left by finished sessions \
             (`harness cow list` shows what is left)",
            outcome.collected.len()
        );
    }
    // 失敗は黙らせない。消せない差分層が積もる理由は、ここでしか分からない。
    for (session_id, e) in &outcome.failures {
        eprintln!("warning: could not remove the CoW diff area for {session_id}: {e}");
    }
}

#[cfg(not(windows))]
fn sweep_empty_cow_diff_areas() {}

/// 差分層に残った**引退した身分**宛のACEを剥がす（残課題#35）。
///
/// # なぜ`preflight`ではなくここなのか
///
/// [`sweep_empty_cow_diff_areas`]とまったく同じ理由である——`preflight`は`harness-sandbox`の
/// 実機テストが直接呼ぶ関数で、それらは差分層の置き場（`%LOCALAPPDATA%`）に実物を使う。
/// 差分層を触る掃除をあちらへ置くと、`cargo test --workspace`が開発機のユーザーデータへ
/// 手を入れる（前例では70件消えた）。**削除ではなくACEの撤収でも、実マシンを変えることに
/// 変わりはない。**
///
/// # なぜ`cow gc`（削除）と分けるのか
///
/// 削除の対象は「何も残っていない」差分層だけで、**中身があるものは残す**のが正しい。
/// 一方ACEは、中身が残っているかどうかと関係なく引退した身分のものを剥がしてよい。
/// 実際、実機に1か月残った10件は**全て中身があった**ので、削除の掃除には永久に拾われなかった。
#[cfg(windows)]
fn sweep_stale_aces_on_cow_diff_areas() {
    let outcome = harness_sandbox::tier2a::win_appcontainer::sweep_diff_layer_aces();
    // **何も起きなければ黙る**（起動のたびに「0件」を出さない）。起きたことは必ず出す。
    if let Some(summary) = outcome.summary() {
        eprintln!("note: {summary}");
    }
}

#[cfg(not(windows))]
fn sweep_stale_aces_on_cow_diff_areas() {}

/// 回収の方針を**ユーザ層の設定だけ**から作る（D-82）。
///
/// プロジェクト層（`.harness/settings.json`）を見ないのは、これが「何を削除してよいか」の
/// 設定だからである——リポジトリ同梱の設定が「消してよい」と言えると、リポジトリが
/// 他のセッションの未適用の作業を消させられる（`harness_config::CowGcSettings`のdoc）。
#[cfg(windows)]
fn cow_gc_policy() -> harness_sandbox::tier2a::workspace_ledger::CowGcPolicy {
    let settings = harness_config::user_cow_gc_settings();
    harness_sandbox::tier2a::workspace_ledger::CowGcPolicy {
        protect_network_volumes: settings.protect_network_volumes(),
    }
}
