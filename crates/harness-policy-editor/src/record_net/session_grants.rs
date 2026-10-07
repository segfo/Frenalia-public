//! パス2が開けた穴（workspace外へのACE）とAppContainerプロファイルを**プロセスの寿命**で持つガードと、
//! もう宣言されていない穴を次のパス2の開始時に剥がす取り消し（`record_net.rs`からそのまま移した。P6.1）。

use super::*;

/// このプロセスがパス2で開けた穴（workspace外へのACE）とAppContainerプロファイルの寿命を、
/// **プロセスの寿命**に合わせるガード。
///
/// # なぜ実行1回ごとに撤収しないのか
///
/// D-37の「セッション」＝プロセスであり、`session_token`はプロセス内で一度だけ確定する。
/// 同じプロセスで2回目のパス2を走らせるとSIDは同じなので、穴を残しておけば`preflight`の
/// `already_sufficient`が効いて**付与も昇格（UAC）も丸ごとスキップされる**。実行のたびに
/// 撤収すると、そのたびに巨大ツリーへの再帰付与をやり直すことになる。
///
/// # 落ちたときにどうなるか
///
/// `Drop`は`std::process::exit`やクラッシュでは走らない。その場合でも**次回起動時の
/// `preflight`が`gc_dead_sessions`で回収する**——生存マーカー（名前付きmutex）が消えている
/// セッションを、台帳とプロファイル名の列挙の**両方**から拾って剥がす（台帳が失われていても
/// 効く二重化）。つまりこのガードは「速く片付けるための最適化」であって、正しさの要件は
/// GC側が持つ。この構造は`session_profile::end_session`のdocが元々宣言しているものである。
pub struct SessionGrants;

impl SessionGrants {
    /// プロセスの入口で1つだけ作る（CLIの`record-net`とTUIの`run`）。
    pub fn hold() -> Self {
        Self
    }

    /// 撤収を**いま**行い、1件ごとに進捗を返す。
    ///
    /// # なぜ`Drop`任せにしないのか（画面を出せる場所で撤収する）
    ///
    /// `Drop`が走るのはイベントループを抜けた後で、そこではもうフレームを描けない。
    /// 結果として撤収は「素のstderrへ686行流れる」しかなくなり、**付与にはゲージがあるのに
    /// 撤収は画面が滝になる**という非対称になった（`docs/CODE-STRUCTURE-RULES.md`§5.1違反）。
    /// TUIはループの中でこれを呼び、付与と同じゲージ（`PhaseWork`）で見せる。
    ///
    /// **`Drop`は保険として残る。** `end_session`は台帳のエントリを消してから戻るので、
    /// ここで撤収済みなら`Drop`側は対象0件で何もしない（冪等）。クラッシュや
    /// `std::process::exit`で`Drop`ごと飛んだ場合も、正しさは次回起動時の
    /// `gc_dead_sessions`が担保する（型のdocを参照）。
    pub fn release(&self, on_progress: &mut dyn FnMut(usize, usize, &Path)) -> usize {
        // [§22.3.2] **capability SID宛の付与も数える。** `granted_paths`だけを見ると、
        // 差分層しか付けていないセッションで撤収が丸ごと飛ぶ（`end_session`を呼ばずに戻る）。
        // 足し算は`session_profile`側の唯一の場所が持つ（`B-05`: 2箇所で別々に足さない）。
        let total = harness_sandbox::tier2a::session_profile::pending_revocation_count();
        // [P6.3・決定68 の前例の(14)] **付与が0件でも`end_session`を呼ぶ。** 件数は付与だけを数え、入れ物（セッション・
        // 遷移先のドメイン・MCP）を数えない。パス2が遷移先を用意すると「付与0件・入れ物あり」が普通に起き、ここで
        // 戻ると入れ物が次の起動の`gc_dead_sessions`まで残る。撤収済みなら台帳のエントリが無く、対象0件で戻る（冪等）。
        // `end_session`が受けるのは`&dyn Fn`（＝不変借用）なので、進捗コールバックは
        // `RefCell`越しに借りる。**単一スレッドで、同時に2回借りる経路は無い**
        // （`end_session`はこのクロージャを直列に呼ぶだけ）。
        let done = std::cell::Cell::new(0usize);
        let sink = std::cell::RefCell::new(on_progress);
        let outcome = harness_sandbox::tier2a::session_profile::end_session(&|path, profile| {
            let leftovers =
                harness_sandbox::tier2a::win_appcontainer::revoke_session_grant(path, profile);
            done.set(done.get() + 1);
            (sink.borrow_mut())(done.get(), total, path);
            leftovers
        });
        // [BUG-103] **剥がせなかったノードは黙って捨てない。** ここはパス2の撤収の正面で、
        // 残ったACEは実マシンに残り続ける（プロファイル削除後はSIDを導出できず、
        // どのコマンドでも剥がせなくなる）。件数ではなく名前を出す（B-09）。
        if let Some(summary) = outcome.summary() {
            eprintln!("note: {summary}");
        }
        done.get()
    }
}

impl Drop for SessionGrants {
    fn drop(&mut self) {
        // **撤収したことは必ず見せる。** これは実マシンのACLとAppContainerプロファイルを
        // 実際に変える操作なので、「付けた」だけが見えて「剥がした」が見えない状態にしない
        // （B-01: 対の片方だけを可視にしない）。実行1回ごとの`teardown`から
        // プロセス終了時のここへ移した際に、この1行が一緒に消えていた——
        // `record_net_e2e`の「撤収まで通っている」というassertはその文言を見ており、
        // 移動と同時に赤くなっていた（`safe-refactoring`段階1-1の実例）。
        //
        // # ここでは1件ごとの行を出さない（TUIのゲージが正面）
        //
        // 撤収は速くない（`.cargo`規模のツリーは付与に実測142.6s掛かり、剥がす側も同じ
        // 再帰walkをする）ので進捗は要るが、**それを出す場所はここではない**——`Drop`が走るのは
        // イベントループを抜けた後で、1件ごとに`eprintln!`すると端末へ686行流れる（実際に
        // そうなった）。進捗は[`SessionGrants::release`]をループの中から呼び、**付与と同じ
        // ゲージ**で見せる（`docs/CODE-STRUCTURE-RULES.md`§5.1）。
        //
        // ここは**保険**として、まだ残っていたぶんだけを黙って畳み、結果を1行で報告する。
        // 撤収済み（`release`を通った）なら対象は0件なので、何も出さない——
        // 「撤収しました」が2回出ると、2回撤収したように読める。
        // [§22.3.2] **capability SID宛の付与も数える。** `granted_paths`だけを見ると、
        // 差分層しか付けていないセッションで撤収が丸ごと飛ぶ（`end_session`を呼ばずに戻る）。
        // 足し算は`session_profile`側の唯一の場所が持つ（`B-05`: 2箇所で別々に足さない）。
        let total = harness_sandbox::tier2a::session_profile::pending_revocation_count();
        // [P6.3] `release`と同じく、付与が0件でも`end_session`を呼ぶ（入れ物だけのセッションを残さない）。
        let done = std::cell::Cell::new(0usize);
        let outcome = harness_sandbox::tier2a::session_profile::end_session(&|path, profile| {
            let leftovers =
                harness_sandbox::tier2a::win_appcontainer::revoke_session_grant(path, profile);
            done.set(done.get() + 1);
            leftovers
        });
        // [BUG-103] 保険経路でも残件は出す（`release`と同じ理由・同じ文言、規則5）。
        if let Some(summary) = outcome.summary() {
            eprintln!("note: {summary}");
        }
        // **撤収したことは1行で必ず言う**（B-01: 付けたのが見えて剥がしたのが見えない状態にしない）。
        // 何も撤収しなかったら黙る（文面と件数のずれの警告は`drop_report`が持つ）。
        for line in drop_report(done.get(), total, outcome.deleted_profiles) {
            eprintln!("{line}");
        }
    }
}

/// [P6.3・決定68 の前例の(14)] 保険の`Drop`が出す行。**撤収したもの（剥がした付与・消した入れ物）が何も無ければ空**
/// ——`release`の後の`Drop`で「撤収しました」が2回出ると、2回撤収したように読める。
///
/// 剥がした件数が台帳の件数とずれたら黙らない——台帳に無いパス（＝`record_granted_path`の記録漏れ）があると
/// 件数がずれる（B-09。BUG-057・BUG-059はどちらも「付与したのに記録しなかった」欠陥で、記録漏れは撤収漏れに直結する）。
fn drop_report(done: usize, total: usize, deleted_profiles: usize) -> Vec<String> {
    if done == 0 && total == 0 && deleted_profiles == 0 {
        return Vec::new();
    }
    let mut lines = vec![format!(
        "撤収: AppContainerプロファイル {deleted_profiles}個とACE（{done}/{total}件）"
    )];
    if done != total {
        lines.push(format!(
            "警告: 撤収した件数 {done} が台帳の {total} 件と一致しません\
             （台帳に記録されていない付与があった可能性があります）"
        ));
    }
    lines
}

/// 「このworkspaceが宛先SIDを発行済みのルート」のうち、**今回の宣言がもう要求していない**ものを返す。
///
/// 剥がす対象を決める判定そのもの。OSに触らない純粋関数にしてあるのは、**取りすぎ・取り足りず
/// のどちらも実害が出る**判定であり、実機や管理者権限なしで全数を固定したいためである
/// （条件を反転させたら「まだ要る穴を剥がす」になり、コマンドが動かなくなる）。
///
/// # 突き合わせは畳み込み鍵で行う（`eq_ignore_ascii_case`では足りない）
///
/// `held`の出どころは**capability台帳**で、綴りは`declaration_key`が畳んだ形
/// （小文字・区切りは`\`）である。一方`wanted`は`policy.json`由来なので区切りが`/`のことが多い。
/// 大文字小文字だけを無視する比較では**同じルートが別物に見え、まだ要る穴を全部剥がす**。
/// FS軸の畳み込みは1つでなければならない（`B-20`）ので、ここでも同じ関数を通す。
///
/// [BUG-184] `wanted`は**このワークスペースがファイルで宣言している付与ルートの全部**
/// （[`file_declared_roots`]）であって、記録中のドメインの分だけではない。`held`は台帳の
/// ワークスペース全体なので、`wanted`も同じ範囲で数えないと、差が他ドメインの宣言の分だけ広がる。
fn stale_roots(held: &[PathBuf], wanted: &[String]) -> Vec<PathBuf> {
    use harness_sandbox::tier2a::workspace_capability::declaration_key;
    let wanted_keys: Vec<String> = wanted
        .iter()
        .map(|root| declaration_key(Path::new(root)))
        .collect();
    held.iter()
        .filter(|granted| {
            let key = declaration_key(granted);
            !wanted_keys.iter().any(|w| w == &key)
        })
        .cloned()
        .collect()
}

/// [BUG-184] 開始時の取り消しで**残す**付与ルート——`policy.json`の**全ドメイン**のこのマシンで
/// 承認済みの宣言と、`settings.json`の`fs.*`。数え方は`harness.exe`の自動撤収（D-27）と同じ関数
/// （`GrantContext::declared_roots`・`policy_grants::settings_declared_roots`）を通す。
///
/// **読めなければ`None`**（取り消しを飛ばす）。空として扱うと、宣言されている穴まで全部取り消す。
pub(super) fn file_declared_roots(
    workspace_root: &Path,
    warnings: &mut Vec<String>,
    on_event: &mut dyn FnMut(NetRecordEvent),
) -> Option<Vec<String>> {
    let policy = match crate::policy_file::load(workspace_root) {
        Ok(policy) => policy,
        Err(e) => {
            warn(
                format!(
                    "policy.jsonを読めないので、もう宣言されていない許可の取り消しを飛ばしました: {e}"
                ),
                warnings,
                on_event,
            );
            return None;
        }
    };
    let settings_entries = harness_config::Settings::load(workspace_root)
        .fs
        .unwrap_or_default()
        .to_fs_passthrough();
    Some(declared_roots_from(
        &policy,
        &settings_entries,
        workspace_root,
        &crate::approval_store::approval_store().load(),
    ))
}

/// [`file_declared_roots`]の純粋な部分（試験はここを測る）。
fn declared_roots_from(
    policy: &crate::PolicyFile,
    settings_entries: &[(String, harness_config::FsAccess)],
    workspace_root: &Path,
    approvals: &harness_sandbox::tier2a::policy_approval::PolicyApprovalLedger,
) -> Vec<String> {
    let workspace_key =
        harness_sandbox::tier2a::policy_approval::approval_workspace_key(workspace_root);
    let mut roots =
        harness_sandbox::tier2a::policy_grants::GrantContext::for_workspace(workspace_root)
            .declared_roots(policy, &|d| approvals.is_approved_for_key(&workspace_key, d));
    roots.extend(harness_sandbox::tier2a::policy_grants::settings_declared_roots(
        workspace_root,
        settings_entries,
    ));
    roots
}

/// 宣言が縮んだぶんのACEを剥がす（パス2開始時のreconcile、D-27と同型）。
///
/// # なぜここでやるのか（付与と同じライフサイクル点）
///
/// ACEが付くのは**パス2の開始時**（`preflight`）である。したがって「もう宣言されていない」に
/// なったACEを落とすのも同じ点でやるのが対になる。宣言を取り消した瞬間に剥がす設計にすると、
/// 付与は遅延するのに撤収は即時という非対称になり、しかもUACを要求しうる操作が
/// 「宣言を1行消すだけ」のつもりの操作へ紛れ込む。
///
/// # 縮んでいなければ何もしない
///
/// 差分が空なら追加コストは0である。`teardown`が実行1回ごとの撤収を**しない**理由
/// （同一プロセスの2回目で付け直す無駄を避ける）はここでも守られる——剥がすのは
/// 「今回の宣言に含まれないもの」だけなので、次の実行で付け直す対象にはならない。
///
/// # [BUG-184] 残す集合はワークスペースのファイル宣言の全部、走っているワークスペースは触らない
///
/// 以前は残す集合が**記録中の1ドメイン**だけで、他ドメインの宣言と、同じワークスペースで
/// `harness.exe`が`settings.json`・`--fs-allow`で付けた許可・CoWの差分層の許可まで取り消していた
/// （取り消しは発行元を名指しする経路なので、生存判定が掛からない）。いまは
/// - 残す集合を[`file_declared_roots`]（`policy.json`の全ドメインの承認済み宣言＋`settings.json`）にし、
/// - 発行元のワークスペースが**実行中なら取り消さずに件数を出す**（`workspace_ledger::live_modes`。
///   `revocable_declaration_issuers`と同じ判定）。
///
/// **この限界は残る**: 画面版のエディタは1つのプロセスで試験実行を繰り返し、作業ディレクトリのモードの印を
/// プロセスが終わるまで持つので、**2回目以降は自分の印で「実行中」と判定して見送る**。見送ったACEの
/// 宛先SIDはどのトークンにも載らないので効き目は無く、次にエディタか`harness.exe`を起動したときに消える。
/// `--fs-allow`の許可は残す集合に入らない（エディタは発行元を区別できる台帳を持たない）ので、
/// 走っていないセッションの分はこの後も取り消される（次の起動で付け直し）。
pub(super) fn reconcile_undeclared_roots(
    wanted: &[String],
    workspace_root: &Path,
    warnings: &mut Vec<String>,
    on_event: &mut dyn FnMut(NetRecordEvent),
) {
    // [§22.2.1] 宣言capabilityの索引は**canonicalize済みのworkspace**で引く。付与側
    // （`preflight`）が台帳へ書くときに使うのがその形なので、生のパスで絞ると
    // **1件も一致せず、黙って何も剥がさない**（この経路の失敗は無症状になる）。
    let canonical_ws = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    // [BUG-142] 索引は**台帳**から引く。かつてはプロセス内の`static`に「この実行が開けた穴」を
    // 覚えていたが、CLIの流れ（付与→`unapprove`→再実行）は3つとも別プロセスなので
    // **常に空集合との差分**になり、撤収が無言で0件になっていた。
    let held: Vec<PathBuf> =
        harness_sandbox::tier2a::workspace_capability::declared_paths_for_workspace(&canonical_ws)
            .into_iter()
            .map(PathBuf::from)
            .collect();
    let stale = stale_roots(&held, wanted);
    if stale.is_empty() {
        return;
    }
    // [BUG-184] **走っているワークスペースからは取り上げない。** 同じワークスペースで`harness.exe`
    // （やこのエディタの前の試験実行）が動いている間に取り消すと、その子が走行中に許可を失う。
    // 判定は`revocable_declaration_issuers`と同じ（作業ディレクトリのモードの印が生きているか）。
    let live = harness_sandbox::tier2a::workspace_ledger::live_modes(&canonical_ws);
    if !live.is_empty() {
        warn(
            format!(
                "もう宣言されていない許可が{}件ありますが、このワークスペースは使用中なので\
                 取り消しを見送りました（モード: {}）。その許可の宛先はこの試験実行の子には渡らないので\
                 効き目はありません。次にエディタか harness.exe を起動したときに取り消されます",
                stale.len(),
                live.join(", ")
            ),
            warnings,
            on_event,
        );
        return;
    }

    // **黙って数十秒使わない**（B-23a）。剥がす側も付与と同じ再帰walkをするので、
    // 大きなツリーでは時間がかかる（`.cargo`への付与は実測142.6s）。
    on_event(NetRecordEvent::RevokingUndeclared { total: stale.len() });
    let profile = harness_sandbox::tier2a::session_profile::current_profile_name();
    // [残課題#37] **撤収の索引は1回だけ読む。** 単発版はパス1件ごとに台帳を全文読んで
    // 構文解析するので、宣言を数百件まとめて取り消すこの経路では、その読取が件数ぶん走る
    // （付与側と同じ形の費用。「配る側だけ速くして剥がす側を取り残さない」）。
    // 写しの限界は`workspace_capability::DeclarationIndex`のdocが持つ。
    let declaration_index = harness_sandbox::tier2a::workspace_capability::DeclarationIndex::load();
    for (index, path) in stale.iter().enumerate() {
        // [§22.2.1] **`--fs-allow`の宛先SIDは宣言ごとのcapability SIDへ移った。**
        // package SIDの撤収（下）だけでは、宣言を取り消しても穴が閉じない。
        // 絞り込みは自分のworkspaceに限る——このプロセスが開けた穴だけが対象で、
        // 同じパスを宣言している他のworkspaceの宛先SIDには触らない（BUG-046と同型）。
        match harness_sandbox::tier2a::win_appcontainer::revoke_declaration_capabilities_indexed(
            &declaration_index,
            path,
            Some(&canonical_ws),
            &|_, _| {},
        ) {
            Ok(report) if report.is_clean() => {}
            // **黙って飛ばさない**（B-10）。剥がせなかった穴は開いたままなので、
            // 「宣言を取り消したのにまだ通る」が起きる。昇格が要る場合もここへ来る。
            Ok(report) => warnings.push(format!(
                "fs-allow {} : the declaration capability ACE is still on the path after the \
                 revoke ({}); run `harness fs revoke {}` to close it",
                path.display(),
                report.still_on_root.join(", "),
                path.display()
            )),
            Err(e) => warnings.push(format!(
                "fs-allow {} : could not revoke the declaration capability ACE ({e}); run \
                 `harness fs revoke {}` to close it",
                path.display(),
                path.display()
            )),
        }
        // D-37時代の残骸（package SID宛）も同じ機会に剥がす。撤収は`end_session`が使うのと
        // **同じ関数**を通す（撤収経路を2つ持たない、B-05）。
        harness_sandbox::tier2a::win_appcontainer::revoke_session_grant(path, &profile);
        on_event(NetRecordEvent::UndeclaredRevoked {
            path: path.clone(),
            done: index + 1,
            total: stale.len(),
        });
    }
    // **セッション台帳（`granted_paths`）からは消さない。** 消すと「撤収の責任を負っている
    // パス」の記録が減り、剥がし残しがあったときに`end_session`/`gc_dead_sessions`が
    // 拾えなくなる。責任を多めに持つのは安全側で、少なく持つのがBUG-057・BUG-059の形である。
    //
    // [BUG-142] **capability台帳のほうは落とす。** ここが索引そのものなので、落とさないと
    // 次の実行でも同じパスをstaleとして拾い、剥がすものが無いまま再walkを繰り返す。
    // ただし判定は「撤収を呼んだ」ではなく**実DACLからもう消えている**で行う——
    // 生きているworkspaceの宛先SIDは意図的に残るので、呼んだだけを根拠に記録を捨てると
    // 宛先SIDを導出できない孤児ACEになる（`B-01`/`B-14`）。判定の実体は`harness-sandbox`側にある
    // （`harness fs revoke`系と共有。同じ判定を2箇所に書かない、`B-05`）。
    //
    // **ここで別の行は出さない。** 剥がしたことは`UndeclaredRevoked`が1件ずつ見せており
    // （付与と同じ粒度、`B-01`）、これはその後始末である。剥がせなかった場合は上の`warnings`が
    // 既に名指ししている——「無言で飛ばした」にはならない。
    let _forgotten = harness_sandbox::tier2a::win_appcontainer::forget_revoked_declarations(&stale);
}

#[cfg(test)]
#[path = "session_grants_tests.rs"]
mod stale_roots_tests;
