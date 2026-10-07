//! パス2の本体（付与→Tier2a→Proxy/Fake DNS→WFP→収集器→子の起動→出力と監査の取り込み。`record_net.rs`からそのまま移した。P6.1）。
//! 撤収の順序と全体の流れはモジュールの親（[`super`]）のdocが持つ。

use super::*;
use super::session_grants::{file_declared_roots, reconcile_undeclared_roots};

pub(super) struct Pass2Inner {
    pub(super) exit_code: Option<i32>,
    pub(super) aborted: Option<AbortReason>,
    pub(super) granted_passthrough: Vec<harness_core::GrantedPassthrough>,
    pub(super) denied_passthrough: Vec<(PathBuf, String, String)>,
    pub(super) aggregate: NetAggregate,
    /// **強制が効いている状態で実際に拒否されたFSアクセス。** ネットワークの候補とは
    /// 別枠にする——スキーマも意味も違う（あちらは全許可の記録、こちらは強制下の拒否）。
    pub(super) fs_aggregate: crate::aggregate::Aggregate,
}

/// **途中で失敗しても残さなければならない事実。**
///
/// [`Pass2Inner`]は成功したときにしか返らないので、そこへ置いた事実は失敗経路から消える。
/// 収集器が起きたかどうかは「拒否を1件も観測しなかった」と「観測していない」の区別
/// （D-43）そのものなので、**失敗した記録でも正しくなければならない**。
/// `warnings: &mut Vec<String>`と同じ形で外から渡し、**出所を1つにする**（B-13）。
#[derive(Default)]
pub(super) struct Pass2Facts {
    pub(super) collector_started: bool,
    pub(super) etw_available: bool,
    /// 実行前診断が「このままでは起動できない」と名指しした実行ファイル
    /// （[`crate::exec_reach::ExecReach::unreachable_exec_value`]）。
    ///
    /// **失敗した記録にも残さなければならない。** 起動できないと分かっているコマンドは
    /// その先で落ちやすく、そのときこそ「何を許可すれば動くのか」が要る。
    pub(super) unreachable_exec: Option<String>,
    /// 記録対象が実際に着地したTier（[`crate::session_dir::RecordManifest::shell_tier`]）。
    /// **Tierが確定した後にだけ入れる**——「Tier2aを狙った」と「Tier2aへ着地した」は
    /// 別の事実で、混ぜると失敗した記録が成功した記録と同じタグを持ってしまう（B-15）。
    pub(super) shell_tier: Option<String>,
}

pub(super) fn run_pass2<'a>(
    request: &RecordNetRequest<'a>,
    net_plan: &NetPolicyPlan,
    dir: &RecordSessionDir,
    warnings: &mut Vec<String>,
    facts: &mut Pass2Facts,
    state: &mut TeardownState<'a>,
    on_event: &mut dyn FnMut(NetRecordEvent),
) -> Result<Pass2Inner, RecordNetError> {
    let passthrough = passthrough_for_domain(request.domain, request.workspace_root, warnings, on_event);
    // **付与より先に、もう宣言されていない穴を閉じる。** 宣言を取り消しただけでは
    // このプロセスが既に開けたACEは残っており、同じプロセスで次のパス2を走らせると
    // 「取り消したのにまだ通る」ことになる（付与は`preflight`が宣言から毎回計算するので
    // 付け直しはされないが、剥がす側の経路が無かった）。
    //
    // [BUG-184] 残す集合は**このワークスペースのファイル宣言の全部**（記録中のドメインだけではない）。
    // 宣言を読めなければ取り消し自体を飛ばす——空として扱うと全部を取り消す。
    if let Some(wanted) = file_declared_roots(request.workspace_root, warnings, on_event) {
        reconcile_undeclared_roots(&wanted, request.workspace_root, warnings, on_event);
    }
    on_event(NetRecordEvent::ElevationExpected {
        // **出ない見込みのUACを予告しない**——出なかったことが「何か起きなかった」に見える。
        max_prompts: if request.wfp.is_live() {
            // 常駐daemonが居るなら全部まかなえる: netfilterdは`ApplyRules`の再送（D-56）、
            // privhelperと収集器は`ChainLaunchHelper`（D-60）。どれも昇格を起こさない。
            // 連鎖起動が失敗したときは、その時点で理由とUACが増える旨を警告に出す。
            0
        } else {
            // netfilterdをこれから起こす（1回）。workspace外の穴があるとprivhelperが先に
            // `runas`され、netfilterdはそこから連鎖起動されるので**実際は1回で収まる**
            // 見込みだが、連鎖が失敗すると2回になるので上限として数える。
            1 + u8::from(!passthrough.is_empty())
        },
    });
    on_event(NetRecordEvent::GrantingPassthrough {
        outside_count: passthrough.len(),
    });

    // WFPパイプは`select_tier`（＝preflight）**より前**に用意する。preflightがprivhelperへ
    // 委譲したとき、「処理完了後にこの名前でnetfilterdを連鎖起動してほしい」と添えられる
    // （シナリオA＝UACを1回に抑えられる経路）。
    //
    // **daemonが既に立っているなら、パイプも連鎖起動の依頼も作らない**（B-23(c) 二重起動ガード）。
    // 依頼を残すと、2回目の実行でworkspace外の新しい穴が要る場合——つまりprivhelperが起動する
    // 場合——に**2つ目のnetfilterdが連鎖起動される**。「2回目は`already_sufficient`が効くから
    // privhelperは起動しないはず」という当てには乗らない（ドメインを変えれば起動しうる）。
    let wfp_prelude = if request.wfp.is_live() {
        None
    } else {
        match harness_sandbox::tier2a::netfilterd::prepare_pipe() {
            Ok(prepared) => Some(prepared),
            Err(e) => {
                // ここで失敗しても`NetfilterHandle::start`（シナリオB、UACがもう1回）で立て直せる。
                warn(
                    format!(
                        "WFPの連鎖起動用パイプを用意できませんでした（{e}）。UACがもう1回出ます。"
                    ),
                    warnings,
                    on_event,
                );
                None
            }
        }
    };
    let wfp_chain_pipe = wfp_prelude.as_ref().map(|p| p.name().to_string());

    // 収集器の連鎖起動用パイプ。**収集器が既に生きているときだけ**用意しない（B-23(c)）。
    //
    // 起こし方は3通りあり、**どれもUACは0回**である。
    //
    // | netfilterdの状態 | 収集器の起こし方 |
    // |---|---|
    // | これから起こす | `ApplyRules`へ相乗り（`chain_launch_policy_learnd`） |
    // | 既に生きている | `ChainLaunchHelper`（D-60、`chain_launch_collector`） |
    // | 起こせなかった | `runas`（**ここだけUACが1回**） |
    //
    // 相乗りが「これから起こす場合だけ」なのは、昇格側が1接続につき1回しか受け付けない
    // ためである（2回目以降は拒否を印字して無視するので、依頼を残すと待ち時間だけが増える）。
    // **起動時前倒しでdaemonが常駐すると毎回「既に生きている」側になる**ので、
    // 2列目が無いと消したはずのUACが収集器で復活する。
    let learn_prelude = if request.collector.is_live() {
        None
    } else {
        match harness_sandbox::tier2a::policy_learnd::client::prepare_pipe() {
            Ok(prepared) => Some(prepared),
            Err(e) => {
                warn(
                    format!(
                        "収集器の連鎖起動用パイプを用意できませんでした（{e}）。UACがもう1回出ます。"
                    ),
                    warnings,
                    on_event,
                );
                None
            }
        }
    };
    let learn_chain_pipe = learn_prelude.as_ref().map(|p| p.name().to_string());
    // 相乗りを依頼するのは「netfilterdをこれから起こす」場合だけ（上の表）。
    let ride_learn_on_apply = !request.wfp.is_live();

    // preflightはここで`begin_session`を呼ぶ（セッションのプロファイルを作る）。**撤収は実行1回ごとではなく
    // プロセスの終わりに`SessionGrants`が`end_session`で行う**（`teardown`の末尾のコメント。落ちた場合は次の起動の
    // `gc_dead_sessions`が回収する）。
    // D-60: **2回目以降の記録では、privhelperを常駐netfilterdから起こす**（UACは出ない）。
    // 1回目はdaemonがまだ居ないので`chain_launch_privhelper`が`Err`を返し、`preflight`が
    // `runas`へ落ちる（UAC 1回）——これが「セッション全体でUAC 1回」の内訳である。
    let privhelper_launcher = |pipe_name: &str| request.wfp.chain_launch_privhelper(pipe_name);
    // **`Auto`ではなく`Tier2a`を渡す。** この経路はモジュールdocの表のとおり
    // 「着地したTierがTier2aでなければ中止」であり、Tier2aは選好ではなく**要件**である
    // ——Tier1にWFPは効かず素通しなので、そこで記録しても「何も拒否されなかった」以上のことは
    // 言えない。`Auto`のままだと、昇格できないアカウントでTier0へ降格し、
    // すぐ下の`selection.tier != ShellTier::Tier2a`で結局中止する（同じ結末を2段階で出す）。
    // 要求を引数で言えば、拒否の理由が`select_tier`の側で「tier2aを要求したが届かなかった」
    // として1つに定まる。下の分岐は残す——`Tier2a`指定なら`Ok`はTier2aだけのはずだという
    // 不変条件の検算として安い（B-06: 前提が変わったときに黙って通らない）。
    let selection = harness_sandbox::select_tier(
        RequireSandbox::None,
        request.workspace_root,
        SandboxChoice::Tier2a,
        &passthrough,
        wfp_chain_pipe,
        &WorkspaceWriteMode::DirectRw,
        Some(&privhelper_launcher),
    )
    .map_err(|e| RecordNetError::NotTier2a {
        tier: "(選択できず)".to_string(),
        reason: e.to_string(),
    })?;

    if selection.tier != ShellTier::Tier2a {
        // **到達しないはずの分岐**（`Tier2a`を要求しているので`Ok`ならTier2aである）。
        // 残してあるのは不変条件の検算のためで、D-75後は「降格した理由」という概念が無い
        // ので、理由の欄には**何が起きたか**をそのまま書く。
        return Err(RecordNetError::NotTier2a {
            tier: selection.tier.label().to_string(),
            reason: "select_tier(Tier2a)がTier2a以外を返しました（要求したTierに着地しない\
                     経路は存在しないはずです）"
                .to_string(),
        });
    }
    // ここへ来た＝**実際にTier2aへ着地した**（直前の分岐が他のTierを弾いている）。
    facts.shell_tier = Some(selection.tier.label().to_string());
    on_event(NetRecordEvent::Tier2aReady);
    // パス1では起こさない。Tier2a preflightが成功したこの地点が、最初のパス2だけの起動点。
    //
    // [段階6b] **遷移の宣言はここで読んでDaemonへ渡す**（`plans/DESIGN-MAC-PROTOCOL.md` §12.1）。
    // 読めなければパス2を失敗させる——宣言を持たないDaemonを起こすと、
    // 宣言してある遷移まで拒否される（`SharedSpawnDaemon::start`のdoc）。
    let transition_policy = harness_sandbox::tier2a::spawnd::TransitionPolicy {
        policy: crate::policy_file::load(request.workspace_root)
            .map_err(|e| RecordNetError::SpawnDaemon(e.to_string()))?,
        workspace_root: request.workspace_root.to_string_lossy().into_owned(),
        // [残課題 サンドボックス周辺 #65] **パス2は`policy.json`の外で書込を許さない**
        // ——`--fs-allow`も`settings.json`も読まず、付けるのは記録中のドメインの宣言だけで、
        // それは宣言として既に検査の視野に入っている。したがって空が正しい。
        writable_outside_policy: Vec::new(),
        // [#55] **パス2は遷移先ドメインを用意しない。**
        //
        // ここが記録しているのは「このコマンドが何へ触るか」であって、
        // **遷移の強制ではない**——パス2のドメインは`--domain`で指定された記録中のもの1つで、
        // `policy.json`の遷移先とは由来が違う（`plans/DESIGN-MAC-PROTOCOL.md` §12.1の表）。
        // 用意すると、記録のために起こした入れ物が記録の対象へ混ざる。
        //
        // **空は「用意できなかった」と同じ扱い**で、別ドメインへの遷移は断られる（fail-closed）。
        domains: Vec::new(),
    };
    let spawn_daemon = request
        .spawn_daemon
        .ensure_started(transition_policy)
        .map_err(RecordNetError::SpawnDaemon)?;
    for warning in &selection.passthrough_warnings {
        warn(warning.clone(), warnings, on_event);
    }

    // **実際にACEが付いた穴だけ**を台帳へ記録する（幻の台帳エントリを作らない、BUG-017）。
    // 記録しないと撤収経路の無い孤立ACEになるので、ここは飛ばせない。
    //
    // **台帳の更新は1回にまとめる。** `record_fs_passthrough_grant`を1件ずつ呼ぶと、
    // 1回ごとに全文読取＋`.bak`への全文コピー＋全文書込が走る。この台帳は実測185KBあるので
    // 1件あたり約550KB、668件では**約370MB**のI/Oになり数秒かかる
    // （`record_fs_passthrough_grants`のdoc）。**イベントの発火は1件ずつのまま**——
    // 見せ方と台帳の書き方は別の話である。
    // [BUG-101/§22.3] `granted_sid`には**何も入れない**（2026-09-01）。この欄が意味するのは
    // 「このパスへ**どのpackage SID宛に**ACEを付けたか」で、撤収側（`revoke_subjects`）は
    // `S-1-15-2-`で始まるSIDしか列挙しないため、そこに載る資格があるのはpackage SIDだけである。
    // 主体移行が済んだいま、`--fs-allow`の穴にpackage SID宛のACEは**1本も無い**ので、
    // `None`＝「package SID宛には付与していない」が事実そのものになる。
    //
    // capability SIDをここへ書かないのは、書いても撤収側が一度も見ないうえに、
    // package SID専用の欄へ別種を混ぜる形になるからである（`revoke_subjects`は
    // capability SIDを混ぜないことが意図——BUG-046の再発防止）。宣言capabilityの撤収は
    // `workspace-capability-ledger.json`の`declaration`欄を索引にした名前の付いた扉が担う。
    //
    // **移行前の記録は消えない**——この欄は上書きではなく積み増しである。
    let grants: Vec<_> = selection
        .granted_passthrough
        .iter()
        .map(|granted| {
            let path = &granted.path;
            harness_sandbox::tier2a::fs_passthrough_ledger::FsPassthroughGrantRecord {
                path: path.clone(),
                writable: granted.writable,
                forced: passthrough
                    .iter()
                    .find(|fp| &fp.path == path)
                    .map(|fp| fp.forced)
                    .unwrap_or(false),
                // [D-63] 宣言された範囲を記録する（`forced`と同じ引き方）。
                scope: passthrough
                    .iter()
                    .find(|fp| &fp.path == path)
                    .map(|fp| fp.scope)
                    .unwrap_or(harness_policy::GrantScope::Recursive),
                // policy.json由来はsettings.jsonの参照カウントに載せない。
                settings_workspace: None,
                granted_sid: None,
            }
        })
        .collect();
    harness_sandbox::tier2a::fs_passthrough_ledger::record_fs_passthrough_grants(&grants);
    // [BUG-142] **ここでプロセス内へ覚え直さない。** 「どのパスへ宛先SIDを発行したか」は
    // `preflight`が既にcapability台帳へ書いており（`declaration`欄）、撤収側は
    // `declared_paths_for_workspace`でそこから引く。2つ目の索引を作ると、
    // 片方だけ更新される形（＝この欠陥そのもの）へ戻る。
    for granted in &selection.granted_passthrough {
        on_event(NetRecordEvent::PassthroughGranted {
            path: granted.path.clone(),
            writable: granted.writable,
        });
    }
    // **付けられなかった穴は必ず見せる。** パス2が途中で落ちる原因はほぼこれである。
    harness_sandbox::tier2a::fs_passthrough_ledger::record_fs_passthrough_denials(
        &selection.denied_passthrough,
    );
    for (path, access, reason) in &selection.denied_passthrough {
        on_event(NetRecordEvent::PassthroughDenied {
            path: path.clone(),
            access: access.clone(),
            reason: reason.clone(),
        });
    }

    // --- 実行ファイルへ届くかを、**子を起こす前に**測る ---------------------------
    // 起こしてから`Access is denied`という文言を解釈する形にはしない（ロケール依存の
    // 文字列判定はBUG-086が「やってはいけない」と結論した形そのもの）。
    // **警告だけで止めない**（`exec_reach`のモジュールdoc参照）。
    //
    // envはここで組み立てて下の起動でも使い回す——`PATH`を測るときと渡すときで別々に
    // 読むと、片方だけ変わったときに判定が静かにずれる（B-05）。
    let mut env = harness_sandbox::secret_env::build_child_env();
    let reach = diagnose_command_exe(request, &selection.denied_passthrough, &env);
    // **表示はイベント側だけが行う。** ここで`warn`も呼ぶと、同じ文言が2回出る
    // （`Warning`と`ExecReachability`の両方を表示側が描くため。実機E2Eで実際に二重に出た）。
    // マニフェストへは残したいので、`warnings`へは直接積む。
    if let Some(message) = reach.message() {
        warnings.push(message);
    }
    // **名指しできた実行ファイルは候補の材料になる**（D-57の追記）。起動を拒否されたexeは
    // `ProcessStart`を出さないので、収集器の観測からは永久に候補が作れない——ここで拾わないと
    // 「詰まった当のexeだけが候補一覧に無い」状態が続く。文言ではなく**値**を残すこと
    // （表示のために積んだ`warnings`から後で文字列を切り出す形にはしない、B-05）。
    facts.unreachable_exec = reach.unreachable_exec_value();
    on_event(NetRecordEvent::ExecReachability(Box::new(reach)));

    // --- Proxy / Fake DNS（どちらも同じ`net_plan`。記録ならrecord_all、強制なら宣言だけ）---
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .map_err(|e| RecordNetError::Runtime(e.to_string()))?;

    let net_audit_path = dir.net_audit_log_path();
    let proxy_config = NetProxyConfig {
        allow_domains: net_plan.allow_domains.clone(),
        domain_policy_enabled: true,
        // 下でnetfilterdを立てるまでは未確定。この値はProxy自身の判定には使われない。
        enforced_by_wfp: false,
        audit_log_path: Some(net_audit_path.clone()),
        proxy_addr: None,
        fake_dns_addr: None,
        tls_inspection: harness_core::TlsInspection::Sni,
    };
    let proxy = runtime
        .block_on(harness_tools::net_proxy::spawn_local_proxy_with_policy(
            &proxy_config,
            net_plan.policy.clone(),
        ))
        .map_err(|e| RecordNetError::NoProxy(e.to_string()))?
        .ok_or_else(|| {
            RecordNetError::NoProxy("domain_policy_enabled=false（内部エラー）".to_string())
        })?;
    let proxy_addr = proxy.addr;
    state.proxy = Some(proxy);
    on_event(NetRecordEvent::ProxyStarted {
        addr: proxy_addr,
        mode: request.net_mode,
        allowed: net_plan.allow_domains.len(),
    });

    // **Proxyと同じポリシー**を渡す（食い違うと、名前は引けたのに繋がらない／その逆になる）。
    let fake_dns = runtime.block_on(harness_tools::fake_dns::spawn_fake_dns_with_policy(
        &harness_tools::fake_dns::FakeDnsConfig {
            allow_domains: net_plan.allow_domains.clone(),
            policy_required: true,
            audit_log_path: Some(net_audit_path.clone()),
            preferred_port: Some(53),
        },
        net_plan.policy.clone(),
    ));
    let fake_dns_addr = match fake_dns {
        Ok(agent) => {
            let addr = agent.addr;
            state.fake_dns = Some(agent);
            on_event(NetRecordEvent::FakeDnsStarted(addr));
            Some(addr)
        }
        Err(e) => {
            // Fake DNSはSOCKS5のremote DNS経路が主なので、無くても記録は成立する。
            warn(
                format!(
                    "Fake DNSを起動できませんでした（{e}）。SOCKS5のremote DNS経路は使えますが、\
                     OSリゾルバ経由の名前解決は記録されません。"
                ),
                warnings,
                on_event,
            );
            None
        }
    };
    state.runtime = Some(runtime);

    // --- WFPの出口強制 -----------------------------------------------------------
    let loopback =
        harness_tools::net_proxy::net_loopback_ports_for_agents(Some(proxy_addr), fake_dns_addr);
    let policy = harness_sandbox::tier2a::netfilterd::NetfilterPolicy {
        // D-37: WFPフィルタはこのセッションのpackage SIDだけを条件にする。
        session_profile: harness_sandbox::tier2a::session_profile::current_profile_name(),
        allow_loopback_tcp_ports: loopback.tcp.clone(),
        allow_loopback_udp_ports: loopback.udp.clone(),
        audit_log_path: Some(net_audit_path.clone()),
        mcp_profiles: Vec::new(),
        // M15.7/D-44: 昇格側が`audit_log_path`を検証するための基準。渡さないと監査ログが
        // 無効化される（fail-safe側）。
        workspace_root: Some(request.workspace_root.to_path_buf()),
        chain_launch_policy_learnd: if ride_learn_on_apply {
            learn_chain_pipe.clone()
        } else {
            None
        },
    };
    // D-56: 生きているdaemonがあれば`ApplyRules`を再送するだけ（UACは出ない）。無ければ
    // シナリオA/Bで起こす。**この行より後の全経路が`teardown`（＝`ClearRules`）を通る。**
    let applied = request
        .wfp
        .apply(wfp_prelude, selection.netfilterd_chain_attempted, policy)
        .map_err(|e| RecordNetError::NoWfp(e.to_string()))?;
    state.wfp_applied = Some(request.wfp);
    on_event(NetRecordEvent::WfpEnforced {
        reused: applied.reused,
    });

    // --- deny-only収集器（パス2で実際に起きたFS拒否を観測する）---------------------
    // **WFPを張ってから起こす**（順序に依存は無いが、出口強制の確立を遅らせない）。
    // fail-open（D-43）: 起こせなくてもパス2は続ける。ただし観測できていない事実は必ず出す。
    let learn_policy = harness_sandbox::tier2a::policy_learnd::LearnPolicy {
        session_profile: harness_sandbox::tier2a::session_profile::current_profile_name(),
        workspace_root: request.workspace_root.to_path_buf(),
        fs_audit_log_path: dir.audit_log_path(),
        harness_pid: Some(std::process::id()),
        spawn_daemon_pid: Some(spawn_daemon.daemon_pid()),
        // **パス2はdeny-only。** 全アクセスを採ると、強制が効いている状態の「触れた記録」に
        // なってしまい、パス1（隔離しないTier0での記録）と意味が混ざる。
        record_all: false,
        // **パス2ではargvを観測しない**（段階6d、§10.3の入口の表）。ここは隔離が効いた
        // 状態なので、宣言していない生成は起きる前に断られる——観測できるのは
        // 「断られた事実」であり、それは`.harness/transitions/pending.jsonl`が既に持つ。
        // 同じものを2つの機構で集めない（枠も1本余計に取らない）。
        capture_argv: false,
    };
    // **依頼したことと起きたことは別**（BUG-093）。昇格側は結末を`Applied`の応答で返すので、
    // 起きていないと分かっているものは待たない——待つと`ConnectNamedPipe`が60秒
    // タイムアウトしてから同じフォールバックへ着くだけで、その60秒が丸ごと無駄になる。
    if let Some(harness_sandbox::tier2a::netfilterd::ChainLaunchReport::Failed { reason }) =
        applied.chain_launch.as_ref()
    {
        // **黙ってフォールバックしない。** UACが1回増える理由をここで言い切る（B-32）。
        warn(
            format!(
                "収集器をnetfilterdから連鎖起動できませんでした（{reason}）。\
                 代わりに直接起動します——UACがもう1回出ます。"
            ),
            warnings,
            on_event,
        );
    }
    let learn_chain_attempted = if ride_learn_on_apply {
        learn_chain_pipe.is_some() && applied.collector_chain_launched()
    } else if let Some(pipe) = learn_chain_pipe.as_deref() {
        // daemonは既に生きている＝相乗りは使えない。D-60の`ChainLaunchHelper`で起こす
        // （これが無いと、ここが`runas`＝UAC1回になる）。
        match request.wfp.chain_launch_collector(pipe) {
            Ok(()) => true,
            Err(reason) => {
                warn(
                    format!(
                        "収集器を常駐daemonから連鎖起動できませんでした（{reason}）。\
                         代わりに直接起動します——UACがもう1回出ます。"
                    ),
                    warnings,
                    on_event,
                );
                false
            }
        }
    } else {
        // 収集器が既に生きている（`StartCollect`の再送だけで済む）。
        false
    };
    let collecting = match request.collector.start(
        learn_prelude,
        learn_chain_attempted,
        learn_policy,
        // [BUG-098] daemonが黙って死んでいたときに、その場で連鎖起動を依頼できるようにする。
        Some(request.wfp),
    ) {
        Ok(collecting) => {
            // **起きた事実はここで確定させる**（この後に失敗しても消えない、`Pass2Facts`のdoc）。
            facts.collector_started = true;
            facts.etw_available = collecting.etw_available;
            on_event(NetRecordEvent::CollectorStarted {
                etw_available: collecting.etw_available,
                reused: collecting.reused,
            });
            if !collecting.etw_available {
                warn(
                    "収集器は起動しましたがETWセッションを張れませんでした。この実行では\
                     FSの拒否を1件も観測できません（理由はfs-audit.jsonlの制御レコードに残ります）。"
                        .to_string(),
                    warnings,
                    on_event,
                );
            }
            state.collector = Some(request.collector);
            Some(collecting)
        }
        Err(e) => {
            // **どちらの経路で試したかを必ず残す**（BUG-093）。「60秒待って接続が来なかった」
            // だけでは、netfilterdからの連鎖起動（UACなし）が黙って失敗したのか、`runas`の
            // UACが放置されたのかを後から区別できない。パイプ名は昇格側の制御レコードにも
            // 入るので、親とdaemonが同じ要求について話していることの突き合わせに使う。
            let route = if learn_chain_attempted {
                format!(
                    "netfilterdからの連鎖起動（追加UACなし）。依頼したパイプ: {}",
                    learn_chain_pipe.as_deref().unwrap_or("(不明)")
                )
            } else {
                "runasでの直接起動（UACが1回出るはずの経路）".to_string()
            };
            warn(
                format!(
                    "収集器を起動できませんでした（{e}）。試した経路: {route}／\
                     WFPのdaemonは{}。コマンドは実行しますが、FSの拒否は1件も記録されません。",
                    if applied.reused {
                        "既存を再利用した"
                    } else {
                        "この実行で起こした"
                    }
                ),
                warnings,
                on_event,
            );
            None
        }
    };
    // ETWの配送が始まるまで待つ。**対象コマンドの起動前**でなければ意味が無い。
    // **daemonを再利用してもこの待ちは消えない**（消えるのはUACだけ、B-32）。
    if collecting.is_some() {
        on_event(NetRecordEvent::WarmingUp(crate::record::WARMUP));
        std::thread::sleep(crate::record::WARMUP);
    }

    // --- Tier2aで対象コマンドを起動 ----------------------------------------------
    // `should_grant_tier2a_network_capability`は`run_shell`と**同じ関数**を通す
    // （判定を書き直すと片方だけ緩む）。ここまで来ていればWFPは立っているので
    // `InternetClient`になるが、規則そのものは共有側が持つ。
    let net_capability = if harness_tools::should_grant_tier2a_network_capability(
        harness_tools::NetDecision::Deny,
        /* net_proxy_enforced */ true,
        /* net_domain_policy_requested */ true,
    ) {
        NetworkCapability::InternetClient
    } else {
        NetworkCapability::Deny
    };

    // `env`は上の到達性診断で組み立てたものをそのまま使う（同じ`PATH`で測って渡す）。
    // Proxy/Fake DNSのアドレスは`run_shell`と**同じ純粋関数**で組み立てる（規則5）。
    env.extend(harness_tools::net_proxy::proxy_env_vars(
        Some(proxy_addr),
        fake_dns_addr,
    ));
    // BUG-050: コマンド本体はstdinスクリプトへ埋め込まず、env経由で渡す。
    env.push((
        harness_tools::RUN_SHELL_COMMAND_ENV_VAR.to_string(),
        request.command.to_string(),
    ));

    let (child, _shell_label) =
        harness_sandbox::tier2a::win_appcontainer::spawn_shell_in_workspace_via_daemon(
            &spawn_daemon,
            WorkspaceSpawn {
                // 記録モードは**シェル**でコマンドを走らせる（`run_shell`と同じ経路）。
                image: WorkspaceImage::Shell,
                cwd: request.cwd.to_path_buf(),
                env,
                workspace_root: request.workspace_root.to_path_buf(),
                cow_diff_layer_dir: None,
                granted_passthrough: selection.granted_passthrough.clone(),
                net_capability,
                // [段階6b] **パス2の遷移元は「いま記録しているドメイン」である**
                // （`plans/DESIGN-MAC-PROTOCOL.md` §12.1の表）。`run_shell`と入口の関数を
                // 共有しているが、遷移元の名前だけは共有しない——あちらは入口ドメインの固定名で、
                // こちらは`--domain`で指定された名前である。
                policy_domain: request.domain.name.clone(),
            },
        )
        .map_err(|e| RecordNetError::Spawn(e.to_string()))?;
    let kill_token = child
        .kill_token()
        .map_err(|e| RecordNetError::Spawn(e.to_string()))?;
    let mut rx = child.spawn_streaming(Some(&harness_tools::run_shell_bootstrap_stdin()));
    on_event(NetRecordEvent::ChildStarted);

    // --- 出力と監査を同時に吸う ---------------------------------------------------
    let mut aggregate = NetAggregate::for_mode(request.net_mode);
    let mut tail = crate::audit_tail::AuditTail::new(net_audit_path.clone());
    // 候補にしないパスの規則は**このセッションのworkspace**から作る（BUG-103）。
    // `from_session`（撤収後に読み直す方）と同じ規則になる——マニフェストの
    // `workspace_root`は`request.workspace_root`そのものなので、綴りも一致する。
    let mut fs_aggregate = crate::aggregate::Aggregate::new(
        crate::exclusion::ExclusionRules::for_session(request.workspace_root),
    );
    let mut fs_tail = crate::audit_tail::AuditTail::new(dir.audit_log_path());
    let outcome = {
        let mut sink = Pass2Sink {
            on_event,
            tail: &mut tail,
            aggregate: &mut aggregate,
            fs_tail: &mut fs_tail,
            fs_aggregate: &mut fs_aggregate,
        };
        pump_child(
            &mut rx,
            &|| kill_token.kill(),
            request.timeout,
            request.cancel,
            &mut sink,
        )
    };

    if let Some(code) = outcome.exit_code {
        on_event(NetRecordEvent::Exited(code));
    }

    // 監査は同期的に書かれるが、最後のリクエストが書き切られる直前で抜けないよう少し待つ。
    //
    // **収集器が居るときは長い方（ETWの配送遅延ぶん）で待つ。** net側だけの500msで抜けると、
    // 最後に起きたFS拒否——つまり「なぜ落ちたか」の答えそのもの——を取りこぼす。
    let drain = if collecting.is_some() {
        crate::record::DRAIN
    } else {
        NET_DRAIN
    };
    on_event(NetRecordEvent::Draining(drain));
    let until = Instant::now() + drain;
    while Instant::now() < until {
        drain_net_audit(&mut tail, &mut aggregate, on_event);
        drain_fs_audit(&mut fs_tail, &mut fs_aggregate, on_event);
        std::thread::sleep(POLL_INTERVAL);
    }
    drain_net_audit(&mut tail, &mut aggregate, on_event);
    drain_fs_audit(&mut fs_tail, &mut fs_aggregate, on_event);

    // 昇格側の制御レコードを**マニフェストにも残す**（画面は`drain_net_audit`が既に出している。
    // ここで`warn()`を使うと同じ文言が2回描かれる）。進行ログは末尾しか見せない窓なので、
    // 残さないと実行が終わった時点で理由が消える——それがBUG-093の見え方そのものだった。
    for reason in aggregate.control_reasons() {
        warnings.push(format!("昇格側（harness-netfilterd）からの報告: {reason}"));
    }

    Ok(Pass2Inner {
        exit_code: outcome.exit_code,
        aborted: outcome.aborted,
        granted_passthrough: selection.granted_passthrough.clone(),
        denied_passthrough: selection.denied_passthrough.clone(),
        aggregate,
        fs_aggregate,
    })
}

/// パス2が[`pump_child`]へ渡す出力先。パス1との違いは`on_tick`（何の監査ログを読むか）だけ。
struct Pass2Sink<'a> {
    on_event: &'a mut dyn FnMut(NetRecordEvent),
    tail: &'a mut crate::audit_tail::AuditTail,
    aggregate: &'a mut NetAggregate,
    /// FS監査（deny-only収集器が書く）。net側とは別のファイル・別の集計。
    fs_tail: &'a mut crate::audit_tail::AuditTail,
    fs_aggregate: &'a mut crate::aggregate::Aggregate,
}

impl ChildRunSink for Pass2Sink<'_> {
    fn on_line(&mut self, line: ShellLine) {
        (self.on_event)(NetRecordEvent::from_line(line));
    }

    fn on_tick(&mut self) {
        drain_net_audit(self.tail, self.aggregate, self.on_event);
        drain_fs_audit(self.fs_tail, self.fs_aggregate, self.on_event);
    }

    fn on_abort(&mut self, reason: AbortReason) {
        (self.on_event)(NetRecordEvent::Aborted(reason));
    }
}

/// FS監査ログ（収集器が書く`fs-audit.jsonl`）を読み進める。
///
/// net側と**別の関数**にしているのはスキーマが違うため（あちらは生のJSON値、こちらは
/// 型付きの[`harness_policy::FsAuditEvent`]）。集計も別で、`.harness`除外や実行像の
/// 候補化といった判断は`Aggregate`が既に持っているものをそのまま通す。
fn drain_fs_audit(
    tail: &mut crate::audit_tail::AuditTail,
    aggregate: &mut crate::aggregate::Aggregate,
    on_event: &mut dyn FnMut(NetRecordEvent),
) {
    let (events, skipped) = tail.poll_fs_events();
    for event in events {
        aggregate.add_event(&event);
        on_event(NetRecordEvent::FsAccess(Box::new(event)));
    }
    aggregate.add_unparsable(skipped);
}

fn drain_net_audit(
    tail: &mut crate::audit_tail::AuditTail,
    aggregate: &mut NetAggregate,
    on_event: &mut dyn FnMut(NetRecordEvent),
) {
    let (events, skipped) = tail.poll_json_values();
    for event in events {
        // **昇格側の制御レコードは通信の記録ではない**（BUG-093）。件数へ足して黙って
        // 流すと、`net-audit.jsonl`を手で開いた人にしか届かない——昇格側の`eprintln!`は
        // `SW_HIDE`のコンソールへ消えるので、これが「なぜ収集器が居ないのか」を伝える
        // 唯一の経路である。**その場で警告として出す。**
        if harness_policy::is_net_control_record(&event) {
            aggregate.add_event(&event);
            if let Some(reason) = event.get("reason").and_then(|v| v.as_str()) {
                // ここでは`warn()`を使わない——`warn()`はイベント発火と`warnings`への
                // 蓄積を両方やるが、`warnings`はこの関数から触れない。マニフェストへは
                // 呼び出し側が`aggregate.control_reasons()`から1回だけ積む
                // （**出す側1回・残す側1回**。両方でやると同じ文言が2回出る）。
                on_event(NetRecordEvent::Warning(format!(
                    "昇格側（harness-netfilterd）からの報告: {reason}"
                )));
            }
            continue;
        }
        aggregate.add_event(&event);
        on_event(NetRecordEvent::NetAccess(Box::new(event)));
    }
    aggregate.add_unparsable(skipped);
}

/// ドメインのFSルールから`FsPassthrough`を作る。
///
/// 変換は`harness_sandbox::tier2a::policy_grants`が唯一の定義を持つ——**`harness.exe`が
/// 起動時に付ける一覧も同じ関数で作る**ので、ここで確かめた挙動がそのまま再現される（#30）。
/// workspace配下のパスは含めない（Tier2aのworkspace grantが既に覆っている）。
///
/// **宣言にあるのに付けない値は、理由ごと見せる**（B-10）。黙って落とすと、
/// 「承認したのに読めない」の原因が画面のどこにも出ない。
fn passthrough_for_domain(
    domain: &PolicyDomain,
    workspace_root: &Path,
    warnings: &mut Vec<String>,
    on_event: &mut dyn FnMut(NetRecordEvent),
) -> Vec<FsPassthrough> {
    // [D-112] このマシンで承認した宣言だけに付ける。`harness.exe`も同じ台帳・同じ関数で決める。
    let approvals = crate::approval_store::approval_store().load();
    let workspace_key =
        harness_sandbox::tier2a::policy_approval::approval_workspace_key(workspace_root);
    let grants = harness_sandbox::tier2a::policy_grants::GrantContext::for_workspace(workspace_root)
        .domain_grants(domain, &|d| approvals.is_approved_for_key(&workspace_key, d));
    for skipped in &grants.skipped {
        warn(
            format!(
                "fs宣言 {} ({}) には許可を付けません: {}",
                skipped.value,
                skipped.access.settings_key(),
                skipped.reason.describe()
            ),
            warnings,
            on_event,
        );
    }
    grants.passthrough
}

/// このドメインの宣言と付与結果から、コマンドの実行ファイルへ届くかを測る。
///
/// 判定そのものは[`crate::exec_reach`]の純粋関数が持つ（実機なしで全数テストできる）。
/// ここがやるのは**入力の組み立てだけ**——`PATH`は子へ渡す`env`から取る（プロセスのenvを
/// 別途読むと、渡す値と測る値が将来ずれる）。
fn diagnose_command_exe(
    request: &RecordNetRequest<'_>,
    denied_passthrough: &[(PathBuf, String, String)],
    env: &[(String, String)],
) -> crate::exec_reach::ExecReach {
    let path_env = env
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("PATH"))
        .map(|(_, value)| value.as_str())
        .unwrap_or("");
    let Some(exe) = crate::exec_reach::resolve_command_exe(request.command, path_env, request.cwd)
    else {
        return crate::exec_reach::ExecReach::Unresolved {
            token: request
                .command
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string(),
        };
    };
    let entries = request.domain.fs.entries();
    crate::exec_reach::diagnose(&exe, &entries, request.workspace_root, denied_passthrough)
}
