//! Process Table — 「そのPIDはどのドメインで、どの系統に属するか」の台帳（§12）。
//!
//! # なぜ台帳が要るのか
//!
//! Daemonは要求してきた相手のドメインを知る必要があるが、**相手に名乗らせてはいけない**
//! （名乗れるなら`{"domain":"trusted"}`と言うだけで境界が消える）。名乗らせない代わりに、
//! **Daemon自身が起こしたときに書き留めておいて、後で引く**。それがこの台帳である。
//!
//! # Win32を直接呼ばない
//!
//! 生存確認とハンドルのcloseは**呼び出し側から注入する**（[`ProcessTable::resolve`]の
//! `is_alive`、[`Reap`]が返す値）。同じ形を`policy_learnd::etw::scope::ScopeTracker`が
//! 採っており、判定ロジック全体が管理者権限なしに単体テストできる
//! （`docs/CODE-STRUCTURE-RULES.md`規則3）。
//!
//! # ここが持たない事実
//!
//! - **遷移を許すかどうか**は持たない。台帳が答えるのは「誰か」までで、
//!   「その誰かがそれを起こしてよいか」はポリシー側の問いである（段階E）
//! - **Daemonが落ちたら中身は失われ、再構築できない**（§10.1）。生存中のプロセスの
//!   ドメインは生成時にDaemonが決めたものであり、後から観測して復元する手段が無い。
//!   だから復旧はセッションの再起動だけで、**空の台帳で立て直さない**

use std::collections::{HashMap, HashSet};

use super::{DenyReason, DomainSpec};

/// 系統（1回のトップレベル生成から伸びるプロセスの一族）の識別子。
///
/// **Windowsのプロセスツリーとは別物である**（§13: Parent PIDをMACの根拠にしない）。
/// 系統はDaemonが生成時に振るもので、`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`で
/// 付け替えられるツリーとは独立している。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LineageId(u64);

impl LineageId {
    /// 記録・診断用。判定には使わない。
    pub fn get(self) -> u64 {
        self.0
    }
}

/// 台帳の1エントリ。
#[derive(Debug, Clone)]
struct Entry {
    lineage: LineageId,
    domain: DomainSpec,
    /// Daemonが**所有する**プロセスハンドルの生の値。
    ///
    /// 開いたまま持ち続けることが、`resolve`の前提そのものである——ハンドルを持っている
    /// 間はそのPIDがOSに再利用されないので、生存が取れた時点でPIDとドメインの対応が
    /// 一意に定まる（§12「PID再利用への対処」）。
    process: u64,
}

/// 1つの系統が共有するもの。
#[derive(Debug, Clone)]
struct Lineage {
    /// 系統Jobの**複製**（§10.1.1）。harnessが作り、Daemonへ渡されたもの。
    job: u64,
    /// [段階6b] この系統のトップレベルを起こしたときの環境変数一式（**base env**）。
    ///
    /// # なぜ系統が持つのか
    ///
    /// nestedのspawnで子へ渡す環境が要る。要求電文（[`super::SpawnRequest`]）には
    /// envの欄が無く、**あってもならない**——サンドボックスの中の呼び出し元が申告した
    /// 環境をそのまま使うと、`PATH`や`HARNESS_SPAWN_REQUEST_PIPE`を差し替えられる。
    /// harnessが組んだトップレベルの環境が、この系統で唯一信頼できる出発点である。
    ///
    /// 辺が`env`の差分を宣言していれば、これへ当てたものを渡す
    /// （`harness_policy::transition::EnvPolicy::Fixed`）。
    base_env: Vec<(String, String)>,
    /// [段階6f-1] この系統のトップレベルへ注入したRedirector DLLの設定。
    ///
    /// # なぜ系統が持つのか（[`Lineage::base_env`]と同じ理由）
    ///
    /// nestedの子にも**同じ誘導の下で**動いてもらう必要があるが、何を注入するかを
    /// 呼び出し元に申告させてはいけない——差分層の置き場や受付パイプの名前を
    /// 自分で決められることになる。**harnessがトップレベルを起こしたときの値が、
    /// この系統で唯一信頼できる出発点である。**
    ///
    /// `None`は「この系統には注入しない」。段階6bまではnestedへ**常に**注入していなかった
    /// ので、ここが`Some`でも子は素のままだった（`server::spawn_nested`の限界）。
    redirector: Option<super::RedirectorSpec>,
    members: HashSet<u32>,
}

/// [`ProcessTable::resolve`]が返す、要求元について確定した事実。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub pid: u32,
    /// [段階6f-1] Daemonが持っている、**要求元プロセスのハンドル**（[`Entry::process`]の写し）。
    ///
    /// # 何に使うのか
    ///
    /// 要求元のstdioハンドルを**引き抜く**のと、起こした子のハンドルを**渡す**のに要る
    /// （`DuplicateHandle`の相手側）。サンドボックスの中のプロセスはDaemonのプロセスを
    /// 開けないので、複製はどちらの向きもDaemon側から行うしかない。
    ///
    /// **この値は閉じてはいけない。** 所有しているのは台帳で、閉じるのは`reap`のときである。
    pub process: u64,
    pub lineage: LineageId,
    pub domain: DomainSpec,
    /// この系統のJobハンドル（複製）。nestedの子はここへ入れる（§10.1.1）。
    pub lineage_job: u64,
    /// [段階6b] この系統のbase env（[`Lineage::base_env`]の写し）。
    ///
    /// **要求元が申告した環境ではない**——段階6f-1からは要求元の申告も使うが、
    /// **harnessが所有する名前だけはこちらの値で強制する**
    /// （`win_appcontainer::spawn::harness_owned_env_names`）。
    pub base_env: Vec<(String, String)>,
    /// [段階6f-1] この系統のRedirector設定（[`Lineage::redirector`]の写し）。
    pub redirector: Option<super::RedirectorSpec>,
}

/// [`ProcessTable::reap`]・[`ProcessTable::drain`]が返す「閉じるべきハンドル」。
///
/// **台帳自身は`CloseHandle`を呼ばない**（Win32を持ち込まないため）。呼び出し側が
/// 必ず閉じること——閉じ忘れると、系統Jobの複製が残って
/// kill-on-closeの保険が二度と働かなくなる（§10.1.1）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "返されたハンドルを閉じないと、系統Jobの複製が残り kill-on-close が働かなくなる"]
pub struct Reap {
    /// そのプロセスのハンドル。
    ///
    /// **`Option`なのは、[`ProcessTable::drain`]がメンバーの残っている系統のJobだけを
    /// 単独で返すことがあるため。** 番兵として`0`を入れると、呼び出し側が
    /// `CloseHandle(0)`を撃つ形になる（無効ハンドルのcloseは静かに失敗するので、
    /// **間違いに気づけない**）。
    pub process: Option<u64>,
    /// **系統の最後の1人だったときだけ`Some`。** 系統Jobの複製を閉じる。
    pub lineage_job: Option<u64>,
}

/// 登録に失敗した理由。
///
/// **失敗したら子を`TerminateProcess`して生成自体を失敗させる**のが§12の決定である
/// （再開前なので子はユーザーのコードを1行も実行しておらず、作り直しても副作用が
/// 二重にならない。BUG-116）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterError {
    /// そのPIDが既に台帳に居る。
    ///
    /// **上書きしない。** 上書きすると古いエントリが持つプロセスハンドルと系統Jobの複製が
    /// 誰からも閉じられなくなる（`B-01`: 付与と撤収の対を片方だけにしない）。
    /// これが起きるのは回収が漏れているときなので、**症状を握り潰さずに生成を失敗させる。**
    PidAlreadyRegistered { pid: u32 },
    /// 指定された系統が存在しない。
    UnknownLineage,
}

impl std::fmt::Display for RegisterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegisterError::PidAlreadyRegistered { pid } => {
                write!(f, "pid {pid} is already in the process table")
            }
            RegisterError::UnknownLineage => write!(f, "unknown lineage"),
        }
    }
}

impl std::error::Error for RegisterError {}

/// PIDからドメインと系統を引く台帳。
#[derive(Debug, Default)]
pub struct ProcessTable {
    entries: HashMap<u32, Entry>,
    lineages: HashMap<LineageId, Lineage>,
    next_lineage: u64,
}

impl ProcessTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// トップレベルの生成を登録し、新しい系統を1つ作る。
    ///
    /// `job`はharnessが作った系統Jobの**複製**（§10.1.1）で、以後この台帳が所有する
    /// ——系統の最後のエントリが消えるときに[`Reap::lineage_job`]として返るので、
    /// 呼び出し側はそれを閉じる。
    pub fn register_top_level(
        &mut self,
        pid: u32,
        process: u64,
        job: u64,
        domain: DomainSpec,
        base_env: Vec<(String, String)>,
        redirector: Option<super::RedirectorSpec>,
    ) -> Result<LineageId, RegisterError> {
        if self.entries.contains_key(&pid) {
            return Err(RegisterError::PidAlreadyRegistered { pid });
        }
        let lineage = LineageId(self.next_lineage);
        self.next_lineage += 1;
        self.lineages.insert(
            lineage,
            Lineage {
                job,
                base_env,
                redirector,
                members: HashSet::from([pid]),
            },
        );
        self.entries.insert(
            pid,
            Entry {
                lineage,
                domain,
                process,
            },
        );
        Ok(lineage)
    }

    /// 既存の系統へ、Daemonが起こした子を足す（nestedのspawn用、§10.1.1）。
    ///
    /// **系統Jobは新しく作らない。** 呼び出し元と同じ系統へ入れるのがこの機構の要点で、
    /// 別のJobを作ると「1コマンドの子孫ツリーだけを殺す」粒度が失われる。
    pub fn register_in_lineage(
        &mut self,
        pid: u32,
        process: u64,
        lineage: LineageId,
        domain: DomainSpec,
    ) -> Result<(), RegisterError> {
        if self.entries.contains_key(&pid) {
            return Err(RegisterError::PidAlreadyRegistered { pid });
        }
        let Some(entry) = self.lineages.get_mut(&lineage) else {
            return Err(RegisterError::UnknownLineage);
        };
        entry.members.insert(pid);
        self.entries.insert(
            pid,
            Entry {
                lineage,
                domain,
                process,
            },
        );
        Ok(())
    }

    /// 要求元PIDから、そのドメインと系統を引く。
    ///
    /// `is_alive`は「このプロセスハンドルが指すプロセスはまだ生きているか」を答える。
    /// **PIDでも実行ファイル名でも「一覧に居るか」でも代用しない**（`B-17`・`B-29`）。
    ///
    /// # 倒れる向き
    ///
    /// 台帳に無い／死んでいるのどちらも**拒否**である（fail-closed）。
    /// ただし**理由は分ける**——同じ値にすると、「常に拒否する」実装でも受け入れテストが
    /// 通ってしまう（`B-35`）。
    pub fn resolve(&self, pid: u32, is_alive: impl Fn(u64) -> bool) -> Result<Caller, DenyReason> {
        let Some(entry) = self.entries.get(&pid) else {
            return Err(DenyReason::NotRegistered);
        };
        if !is_alive(entry.process) {
            // ハンドルはまだ持っているのに終了済み＝このPIDは既に別のプロセスのものか、
            // これから別のプロセスへ振り替わる。どちらにせよ対応を信用してはいけない。
            return Err(DenyReason::PidReused);
        }
        let lineage = self
            .lineages
            .get(&entry.lineage)
            .ok_or(DenyReason::NotRegistered)?;
        Ok(Caller {
            pid,
            process: entry.process,
            lineage: entry.lineage,
            domain: entry.domain.clone(),
            lineage_job: lineage.job,
            base_env: lineage.base_env.clone(),
            redirector: lineage.redirector.clone(),
        })
    }

    /// プロセスが終了したので、そのエントリを落とす。
    ///
    /// **系統の最後の1人だったら、系統Jobの複製も返す**（§10.1.1「系統の最後のプロセスが
    /// 終わったらDaemonが複製を閉じる」）。閉じないとJobが生き続け、kill-on-closeの保険が
    /// 働かない。
    ///
    /// 知らないPIDなら`None`（二重に呼ばれても壊れない）。
    pub fn reap(&mut self, pid: u32) -> Option<Reap> {
        let entry = self.entries.remove(&pid)?;
        let mut lineage_job = None;
        if let Some(lineage) = self.lineages.get_mut(&entry.lineage) {
            lineage.members.remove(&pid);
            if lineage.members.is_empty() {
                lineage_job = Some(lineage.job);
                self.lineages.remove(&entry.lineage);
            }
        }
        Some(Reap {
            process: Some(entry.process),
            lineage_job,
        })
    }

    /// 台帳を空にし、保持している全ハンドルを返す（Daemonの終了時）。
    ///
    /// **系統Jobは、まだメンバーが残っている系統のぶんも返す。** 終了時は「最後の1人」を
    /// 待たないので、[`reap`](Self::reap)の条件をそのまま使うと閉じ漏れる
    /// （`B-01`: 対の片方だけになる）。
    pub fn drain(&mut self) -> Vec<Reap> {
        let mut out: Vec<Reap> = Vec::new();
        let mut entries: Vec<(u32, Entry)> = self.entries.drain().collect();
        entries.sort_by_key(|(pid, _)| *pid);
        for (_, entry) in entries {
            out.push(Reap {
                process: Some(entry.process),
                lineage_job: None,
            });
        }
        let mut lineages: Vec<(LineageId, Lineage)> = self.lineages.drain().collect();
        lineages.sort_by_key(|(id, _)| *id);
        for (_, lineage) in lineages {
            out.push(Reap {
                process: None,
                lineage_job: Some(lineage.job),
            });
        }
        out
    }

    /// 登録済みのプロセス数（診断用）。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
#[path = "table_tests.rs"]
mod table_tests;
