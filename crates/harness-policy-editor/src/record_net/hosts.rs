//! パス2が**プロセスの寿命で**持つ常駐のもの——WFPの出口強制daemonとSpawn Daemon（`record_net.rs`からそのまま移した。P6.1）。

/// WFPの出口強制daemonを**プロセスの寿命で**持つ（D-56）。
///
/// [`SessionGrants`]と同じ理由でここに置く——実行1回ごとに起こし直すとそのたびUACが出る。
/// 記録は同時に1本しか走らない（`session_lock`）が、TUIは記録を専用スレッドで回すので、
/// 所有権をUIスレッドに置いたままworkerへ貸せるよう`Arc<Mutex<..>>`で包む。
///
/// # 宣言順（重要）
///
/// **[`SessionGrants`]より後に宣言すること。** Rustは宣言の逆順にdropするので、これで
/// netfilterdの`Teardown`がAppContainerプロファイルの削除（`end_session`）より**先**に走る。
/// 逆にすると、フィルタが条件にしているpackage SIDのプロファイルを先に消すことになる
/// （現行`record_net`の撤収順「WFP → Proxy/Fake DNS → プロファイル」と同じ関係）。
///
/// # 落ちたときにどうなるか
///
/// `Drop`が走らない終わり方でも、プロセス消滅でパイプが閉じ、daemonは`ERROR_BROKEN_PIPE`を
/// 見て自発的に撤収する。残ったフィルタはDYNAMICセッションなのでBFEが消す
/// （`NetfilterSession`のdoc）。
#[derive(Clone, Default)]
pub struct SharedNetfilter {
    inner: std::sync::Arc<std::sync::Mutex<harness_sandbox::tier2a::netfilterd::NetfilterSession>>,
}

/// policy editorのパス2が使うSpawn Daemonの持ち主（TUI・CLI・プロセス内のE2Eが同じ1つを持つ）。
///
/// [決定68 の前例の(3)] **パス2のたびに起こし直す**（[`Self::restart`]）。宣言と遷移先の表を Hello の後で差し替える口は
/// 無いので、使い回すと承認した辺がそのパス2に効かない（決定68の困りごと2）。
#[derive(Clone, Default)]
pub struct SharedSpawnDaemon {
    inner: std::sync::Arc<
        std::sync::Mutex<Option<harness_sandbox::tier2a::spawnd::SharedSpawnDaemon>>,
    >,
}

impl SharedSpawnDaemon {
    pub fn hold() -> Self {
        Self::default()
    }

    /// このプロセスが選んだ生成の姿勢。**エディタで姿勢を読む場所はここ1つ**——Daemon へ渡す値（[`Self::restart`]）と、
    /// パス2が宣言の直後に確かめる値（`run::run_pass2`の`NotRestricted`）が同じこれを通る（読み口を2つにすると、いつか
    /// 片方だけ違う値になる、`B-06`。`launch.rs`の数え上げ試験が読む場所の合計を固定している）。
    pub(super) fn chosen_child_process_policy() -> harness_sandbox::tier2a::spawnd::ChildProcessPolicy {
        harness_sandbox::tier2a::spawnd::child_process_policy_for_this_process()
    }

    /// [決定68 の前例の(3)] **前の Daemon を畳んでから、その回の宣言で起こし直す。** `policy`は呼び出し側が必ず渡す
    /// （`SharedSpawnDaemon::start`のdoc）。表と宣言が変わっていなくても起こし直す——比べて使い回す経路を作ると、
    /// 通らない経路が1本増える（`B-08`）。Daemon は昇格しないので UAC は増えない。畳むのに最長5秒待つ
    /// （`SpawnDaemonHandle::shutdown`）。
    ///
    /// 姿勢は**このプロセスが選んだもの**（[`Self::chosen_child_process_policy`]。パス2は`select_tier`より前で生成禁止を
    /// 宣言する、決定68 の前例の(15)）。**製品の既定の姿勢を直接渡さない**——渡すと、宣言したのに生成禁止の
    /// 無い Daemon が起きる。
    pub(super) fn restart(
        &self,
        policy: harness_sandbox::tier2a::spawnd::TransitionPolicy,
    ) -> Result<harness_sandbox::tier2a::spawnd::SharedSpawnDaemon, String> {
        let mut slot = self
            .inner
            .lock()
            .map_err(|_| "Spawn Daemon holder mutex was poisoned".to_string())?;
        if let Some(previous) = slot.take() {
            previous.shutdown();
        }
        let daemon = harness_sandbox::tier2a::spawnd::SharedSpawnDaemon::start(
            policy,
            Self::chosen_child_process_policy(),
        )
        .map_err(|error| error.to_string())?;
        *slot = Some(daemon.clone());
        Ok(daemon)
    }
}

impl SharedNetfilter {
    pub fn hold() -> Self {
        Self::default()
    }

    /// 生きているdaemonを持っているか。**呼び出し側はこれを見て、投機的パイプの用意と
    /// privhelperへの連鎖起動依頼を省く**（B-23(c) 二重起動ガード）。
    pub fn is_live(&self) -> bool {
        self.lock().is_live()
    }

    /// **生きているdaemonから`privhelper`を起こす**（D-60、UACは出ない）。
    ///
    /// ポリシーエディタは「記録→承認→パス2」の対話ループなので、承認で増えたルートの
    /// 祖先traverse付与が**後から**必要になる。そのときnetfilterdは既に生きているので、
    /// `privhelper`はここから起こせる——起こさないと`runas`になり、**確定のたびにUACが
    /// 1回増える**（D-60の経緯そのもの）。
    ///
    /// 起こせなかった理由は`Err`で返す。呼び出し側（`preflight`）は`runas`へ落ちる。
    pub fn chain_launch_privhelper(&self, pipe_name: &str) -> Result<(), String> {
        self.chain_launch(
            harness_sandbox::tier2a::netfilterd::SiblingHelper::Privhelper,
            pipe_name,
        )
    }

    /// **生きているdaemonから収集器を起こす**（D-60の適用範囲を収集器へ広げたもの）。
    ///
    /// `ApplyRules`相乗りの経路（`chain_launch_policy_learnd`）は「netfilterdをこれから
    /// 起こす」ときにしか使えない——昇格側は1接続につき1回しか相乗りを受け付けないためで、
    /// **起動時前倒しでdaemonが常駐すると毎回そちらの条件になる**。塞がないと、
    /// netfilterdから消したUACが収集器で復活する（昇格するプロセスが入れ替わるだけになる）。
    pub fn chain_launch_collector(&self, pipe_name: &str) -> Result<(), String> {
        self.chain_launch(
            harness_sandbox::tier2a::netfilterd::SiblingHelper::PolicyLearnd,
            pipe_name,
        )
    }

    fn chain_launch(
        &self,
        helper: harness_sandbox::tier2a::netfilterd::SiblingHelper,
        pipe_name: &str,
    ) -> Result<(), String> {
        use harness_sandbox::tier2a::netfilterd::ChainLaunchReport;
        match self.lock().chain_launch_helper(helper, pipe_name) {
            None => Err("no resident WFP daemon to chain-launch from".to_string()),
            Some(Err(e)) => Err(e.to_string()),
            Some(Ok(ChainLaunchReport::Launched { .. })) => Ok(()),
            Some(Ok(ChainLaunchReport::Failed { reason })) => Err(reason),
        }
    }

    /// **daemonを先に起こしておく**（起動時前倒し）。`Ok(true)`は「この呼び出しで起こした
    /// ＝UACが1回出た」、`Ok(false)`は「既に居た」。
    ///
    /// 失敗しても記録は使える（必要になった時点で`apply`が起こす）ので、呼び出し側は
    /// 続行してよい——ただし**理由は必ず見せる**（黙って諦めると、後で出るUACの説明が付かない）。
    pub fn standby(&self) -> Result<bool, String> {
        self.lock().standby().map_err(|e| e.to_string())
    }

    fn lock(
        &self,
    ) -> std::sync::MutexGuard<'_, harness_sandbox::tier2a::netfilterd::NetfilterSession> {
        // 毒されたロックでも中身は使える——daemonのハンドルは`NetfilterSession`が持っており、
        // 最後の砦（プロセス終了でパイプが閉じる）はpanicの有無に依存しない。
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(super) fn apply(
        &self,
        prelude: Option<harness_sandbox::tier2a::netfilterd::PreparedPipe>,
        chain_attempted: bool,
        policy: harness_sandbox::tier2a::netfilterd::NetfilterPolicy,
    ) -> Result<
        harness_sandbox::tier2a::netfilterd::Applied,
        harness_sandbox::tier2a::netfilterd::NetfilterError,
    > {
        self.lock().apply(prelude, chain_attempted, policy)
    }

    pub(super) fn clear(&self) -> Result<(), harness_sandbox::tier2a::netfilterd::NetfilterError> {
        self.lock().clear()
    }
}
