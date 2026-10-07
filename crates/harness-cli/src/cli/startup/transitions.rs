//! 起動パイプラインの遷移MACの部分（[#55]・段階6e）——遷移先ドメインの実体を用意し、Spawn Daemonを起こし、
//! `run_shell`／`run_program`／`can_run_program`を登録する。
//!
//! 2026-10-07に`run_agent.rs`（本体が1,000行を超えている）から**そのまま移した**
//! （`plans/position-domains/P7.md`の Task P7.1）。移した理由は、P7（決定69）でこの塊の途中へ
//! **ドメインごとの中継プロキシとWFPの適用**が入るからである。
//!
//! # この配線は順序が本質である
//!
//! ```text
//! 1. provision()     遷移先ドメインの実体を用意し、モデルへ見せる事実を作る（**プロセスはまだ起こさない**）
//! 2. （呼び出し側）   ドメインごとの中継プロキシ → WFPの適用 → 出口（internetClient・プロキシの宛先）を表へ付ける
//! 3. start_daemon()  Spawn Daemonを起こし、ツールを登録する
//! ```
//!
//! 2を3の後へ置くと、**出口の強制が効くまでの間に子が走れる窓**ができる（`startup::mcp`のモジュールdocが
//! 言うのと同じ理由）。**P7.1の時点では2はまだ無く**、呼び出し側（`run_agent`）が1と3を続けて呼ぶ
//! ——振る舞いは移す前と1ビットも変わらない。

use super::*;

/// [`provision`]の結果。呼び出し側が2（プロキシとWFP）を挟んでから[`start_daemon`]へ渡す。
pub(super) struct ProvisionedTransitions {
    /// 起動時に1回だけ読んだ`policy.json`（`stage_prepare_sandbox`が読んだもの）。
    policy: harness_policy::policy_file::PolicyFile,
    workspace_root: String,
    writable_outside_policy: Vec<String>,
    /// Daemonへ渡す表（用意できたものだけ）。
    pub(super) domains: Vec<harness_sandbox::tier2a::spawnd::DomainSpec>,
    /// モデルへ見せる事実。**積むかどうかは[`start_daemon`]が決める**（強制が3条件とも揃ったときだけ）。
    pub(super) facts: std::sync::Arc<harness_core::TransitionFacts>,
}

/// 1. 遷移先ドメインの実体を用意し、モデルへ見せる事実を作る。**Daemonはまだ起こさない。**
///
/// `Err`は起動を止める合図である（理由は印字済み・preflightが付けたACEとプロファイルも撤収済み）。
pub(super) fn provision(
    policy: Option<harness_policy::policy_file::PolicyFile>,
    workspace_root: &Path,
    write_mode: &harness_sandbox::WorkspaceWriteMode,
    domain_fs_grants: &harness_sandbox::tier2a::policy_fs::DomainFsGrants,
    writable_outside_policy: Vec<String>,
    approved_fs_values: &std::collections::BTreeSet<(String, &'static str)>,
) -> Result<ProvisionedTransitions, ExitCode> {
    // [段階⑤] **製品の既定は「生成禁止を積まない」。** 積むと、遷移ポリシーの評価
    // （段階E）が無い今はDaemonの答えが常に「未実装なので断る」になり、
    // サンドボックスの中で外部プログラムが1つも起動できなくなる。
    // 常時適用へ切り替えるのは段階Eが着地してからで、そのときはこの引数ごと消す。
    // [段階6b・#30] **遷移の宣言はharnessが読んでDaemonへ渡す**
    // （`plans/DESIGN-MAC-PROTOCOL.md` §12.1）。`policy.json`を読むのは`stage_prepare_sandbox`の
    // 1回だけで、ここはその値を使う——ファイル宣言から許可を付ける付与処理（#30）より前に読む必要が
    // あるためで、読み直すと付与に使った宣言とDaemonへ渡す宣言が別物になり得る（`B-13`）。
    //
    // **読めなければTier2aセッションを始めない**——その判断は`stage_prepare_sandbox`が既にしており、
    // Tier2aでここへ来たなら読めている。`None`はその不変条件の破れなので、起動しない側へ倒す。
    //
    // [残課題 サンドボックス周辺 #65] **`policy.json`の外で書込を許した場所も検査へ渡す。**
    // 一覧は`stage_prepare_sandbox`で1回だけ作り、harnessの検査・モデルへ見せる一覧・
    // Daemonの検査の3つへ同じ値を渡す——別々に作ると、どれか1つだけ入力が違う状態が
    // 黙って成立する（`B-13`）。
    let Some(policy) = policy else {
        eprintln!(
            "error: the transition policy (.harness/policy.json) was not read before the \
             Tier2a session started; refusing to start a Spawn Daemon without it"
        );
        end_session_after_failure();
        return Err(ExitCode::FAILURE);
    };
    // [#55] **遷移先ドメインの実体をここで用意する**（`plans/DESIGN-MAC-BROKER.md` §22.9）。
    //
    // 判定器は「Dへ移してよい」までしか答えない。Dで実際に起こすには
    // Dのpackage SIDとcapabilityの組が要り、それは`policy.json`には書かれていない。
    // **Daemonを起こす前に作って、宣言と同じ電文で渡す**——表を持たないDaemonが
    // 要求を捌く瞬間を作らないためである（`Hello`に載せた理由そのもの）。
    //
    // [#30] **宣言の宛先は、このセッションの付与処理が付けたものを渡す**（台帳を引き直さない、
    // BUG-185）。付与は`stage_prepare_sandbox`が入口の宣言と一緒に1回で済ませている。
    let canonical_workspace = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    let provisioned =
        harness_sandbox::tier2a::win_appcontainer::domain_provision::provision_target_domains(
            &policy,
            &canonical_workspace,
            // **`preflight`が付与したのと同じ語彙**でなければ別の宛先SIDを導出し、
            // 用意したドメインからワークスペースが一切見えなくなる。
            write_mode.capability_mode(),
            domain_fs_grants,
        );
    // **用意できなかったものを黙って落とさない**（`B-10`）。落とすと、
    // 宣言したのに断られる理由が画面のどこにも出ない。
    for (domain, reason) in &provisioned.skipped {
        eprintln!("warning: transitions into the domain {domain:?} will be refused: {reason}");
    }
    // [段階6e] **モデルへ見せる一覧は、Daemonへ渡すのと同じ宣言と同じ表から作る**
    // （§19.3.8）。ここで読み直すと判定に使うグラフとずれ、「起こせる」と
    // 答えたものをDaemonが拒否する形になる（正本を2つ持たない、`B-13`）。
    // [#30] 権限欄にはこのマシンで承認済みの宣言だけを載せる（付いていない許可を伝えない）。
    // [2026-10-01] 「いま起こせるか」は**用意できた表**（Daemonへ渡す`provisioned.domains`）で決める
    // ——そのため一覧は用意の**後**に作る（§10.1.2の撤去一覧5点目を外した）。
    let provisioned_domains: std::collections::BTreeSet<String> = provisioned
        .domains
        .iter()
        .map(|domain| domain.policy_domain.clone())
        .collect();
    let facts = std::sync::Arc::new(super::transition_tool::facts_from_policy(
        &policy,
        &workspace_root.to_string_lossy(),
        &writable_outside_policy,
        approved_fs_values,
        &provisioned_domains,
    ));
    Ok(ProvisionedTransitions {
        policy,
        workspace_root: workspace_root.to_string_lossy().into_owned(),
        writable_outside_policy,
        domains: provisioned.domains,
        facts,
    })
}

/// 3. Spawn Daemonを起こし、ツールを登録する。**呼び出し側がWFPの適用を終えてから呼ぶ**（モジュールdoc）。
///
/// `facts`は呼び出し側が持つモデルへ見せる事実の置き場で、**強制が3条件とも揃わなければここで`None`へ戻す**
/// （`Some`が「強制が効いている」の意味を持つ、`TransitionFacts`のdoc）。
///
/// `Err`は起動を止める合図である（[`provision`]と同じ）。
pub(super) fn start_daemon(
    provisioned: ProvisionedTransitions,
    tools: &mut ToolRegistry,
    shell_tier: harness_core::ShellTier,
    facts: &mut Option<std::sync::Arc<harness_core::TransitionFacts>>,
) -> Result<harness_sandbox::tier2a::spawnd::SharedSpawnDaemon, ExitCode> {
    let ProvisionedTransitions {
        policy,
        workspace_root,
        writable_outside_policy,
        domains,
        facts: _,
    } = provisioned;
    let transition_policy = harness_sandbox::tier2a::spawnd::TransitionPolicy {
        policy,
        workspace_root,
        writable_outside_policy,
        domains,
        // [決定68 の前例の(4)] **`harness.exe`は許可した生成の記録を頼まない**（暫定）。セッションは長く
        // `cargo build`1回で数千行になるのに、量の上限と回転を決めていない。決めた日にここで置き場の名前を渡す。
        spawn_audit_record: None,
    };
    // **この値が段階6eの露出条件の3つ目である。** `Unrestricted`である限り、
    // 子は要求受付パイプへ頼まずに自分で生成できるので、モデルへ
    // 「宣言された組み合わせだけ起こせる」と言ってはならない（§19.3.8）。
    // [残課題#50] **姿勢の綴りをここに書かない。** 読む場所が3つに増えた
    // （ここ・ポリシーエディタ・Tier2aのシェルの選び方）ので、
    // 既定を持つのは`PRODUCT_DEFAULT`1箇所だけにしてある。
    // [⑤'] **このセッションで選ばれた姿勢を読む。** 旗（`--enforce-transitions`）を
    // 姿勢へ変えるのは`stage_prepare_sandbox`1箇所で、シェルの選び方も同じものを読む
    // ——ここで旗をもう一度読むと、いつか片方だけ真になる（`B-06`）。
    let child_process_policy =
        harness_sandbox::tier2a::spawnd::child_process_policy_for_this_process();
    match harness_sandbox::tier2a::spawnd::SharedSpawnDaemon::start(
        transition_policy,
        child_process_policy,
    ) {
        Ok(daemon) => {
            // [段階6e] 強制が効いているときだけ、モデルへ見せる（§19.3.8）。
            // **判定は`should_expose`ただ1つが持つ**——ここへ条件を書くと、
            // 今日は通らない分岐なので配線したこと自体をテストできない。
            // **姿勢を読むのに綴りを書かない**（`ChildProcessPolicy::is_restricted`のdoc）。
            // 生成禁止の綴りが製品コードに0件であることを数え上げテストが固定しており、
            // 比較のために書いた行まで「選んだ」と数えられてしまう。
            //
            // [段階6f-3] **この1つの値を、ツール登録と`run_shell`の両方へ配る。**
            // 拒否の注記は「`can_run_program`を引け」と書くので、
            // **ツールを登録しない構成でその注記を出すと、存在しないツールを指す**。
            // 判定を2箇所に置くと、いつか片方だけ真になる（`B-06`）。
            let expose_transitions = super::transition_tool::should_expose(
                shell_tier,
                true,
                child_process_policy.is_restricted(),
            );
            tools.register(Arc::new(harness_tools::RunShellTool::with_spawn_daemon(
                daemon.clone(),
                expose_transitions,
            )));
            // `run_program`も同じ接続と同じ注記の判定で差し替える。**片方だけ差し替えると、
            // もう片方は接続なしの既定値のままTier2aで内部エラーになる**（`B-06`）。
            tools.register(Arc::new(harness_tools::RunProgramTool::with_spawn_daemon(
                daemon.clone(),
                expose_transitions,
            )));
            if expose_transitions {
                tools.register(Arc::new(harness_tools::CanRunProgramTool));
            } else {
                // 出さないなら**事実も積まない**。積んだままにすると、
                // `EnvironmentFacts`が1行を出してしまう（`Some`が「強制が効いている」の
                // 意味を持つ、`TransitionFacts`のdoc）。
                *facts = None;
            }
            Ok(daemon)
        }
        Err(error) => {
            eprintln!("error: could not start the Tier2a Spawn Daemon: {error}");
            // **Daemonが起こせないならTier2aセッションを始めない**（直接生成へ降格しない、
            // `plans/DESIGN-MAC-PROTOCOL.md` §12）。preflightが既に付けたACEと
            // プロファイルはここで撤収する。
            end_session_after_failure();
            Err(ExitCode::FAILURE)
        }
    }
}

/// 起動を止めるときに、preflightが既に付けたACEとプロファイルを撤収する。
///
/// [BUG-103] **剥がせなかったノードは名前で出す。** 正常終了の末尾と同じ扱いに
/// する——失敗パスだけ黙ると、撤収が1件も成功しなくても何も出ない状態が
/// 早期returnの側にだけ残る（`B-09`）。
fn end_session_after_failure() {
    let outcome = harness_sandbox::tier2a::session_profile::end_session(
        &harness_sandbox::tier2a::win_appcontainer::revoke_session_grant,
    );
    if let Some(summary) = outcome.summary() {
        eprintln!("note: {summary}");
    }
}
