//! Process Table（§12）の単体テスト。**昇格も実プロセスも要らない**——生存確認を
//! 注入で外してあるため（`table.rs`のモジュールdoc）。
//!
//! # 何が壊れたときに、ここが赤くなるのか
//!
//! 台帳が壊れる形は3つあり、それぞれ別の被害になる。
//!
//! | 壊れ方 | 被害 |
//! |---|---|
//! | 台帳に無いPIDが通る | ドメインを名乗らせないという§12の前提が消える |
//! | 台帳に在るPIDが拒否される | サンドボックスの中で何も起動できなくなる（可用性） |
//! | 系統Jobの複製を閉じ忘れる | kill-on-closeの保険が**二度と**働かない（§10.1.1） |
//!
//! **拒否側だけを測らない**（`B-35`）。全部拒否する実装は、禁止側のassertだけなら
//! すべて緑になる。
//!
//! ハンドル値はここでは**ただの整数**である（生存確認もcloseも注入されるので、
//! 本物のカーネルオブジェクトを指す必要が無い）。区別できれば何でもよいので、
//! 見分けやすい値を置いてある。

use super::*;

const JOB_A: u64 = 0x1000;
const JOB_B: u64 = 0x2000;
const PROC_1: u64 = 0x11;
const PROC_2: u64 = 0x22;
const PROC_3: u64 = 0x33;

fn domain(name: &str) -> DomainSpec {
    DomainSpec {
        name: name.to_string(),
        container_sid: "S-1-15-2-1111111111-2222222222".to_string(),
        capability_sids: vec!["S-1-15-3-1024-1".to_string()],
    }
}

/// すべて生きているとみなす生存確認（正常系用）。
fn all_alive(_handle: u64) -> bool {
    true
}

/// **対の測定その1**（`B-35`）: 台帳に無いPIDは拒否され、**在るPIDは通る**。
///
/// 片方だけだと、`resolve`が常に`Err`を返す実装でも合格する。
#[test]
fn an_unregistered_pid_is_denied_while_a_registered_one_resolves() {
    let mut table = ProcessTable::new();
    table
        .register_top_level(4200, PROC_1, JOB_A, domain("pwsh-workspace"))
        .expect("register the top-level process");

    assert_eq!(
        table.resolve(9999, all_alive),
        Err(DenyReason::NotRegistered),
        "台帳に無いPIDが拒否されていない。§12の既定拒否が成立しない"
    );

    let allowed = table
        .resolve(4200, all_alive)
        .expect("registered pid resolves");
    assert_eq!(allowed.pid, 4200);
    assert_eq!(
        allowed.domain,
        domain("pwsh-workspace"),
        "登録したドメインがそのまま引けていない"
    );
    assert_eq!(
        allowed.lineage_job, JOB_A,
        "系統Jobが引けていない。nestedの子を同じ系統へ入れられなくなる（§10.1.1）"
    );
}

/// **PID再利用は「台帳に無い」とは別の理由で断る**（§12「PID再利用への対処」）。
///
/// 同じ`DenyReason`へ丸めると、受け入れテストが**2つの別々の欠陥を区別できなくなる**
/// ——台帳が空でも、生存確認が常に偽でも、同じ症状に見える。
#[test]
fn a_dead_process_handle_is_denied_as_pid_reuse_not_as_unregistered() {
    let mut table = ProcessTable::new();
    table
        .register_top_level(4200, PROC_1, JOB_A, domain("pwsh-workspace"))
        .expect("register");

    let denied = table.resolve(4200, |_| false);
    assert_eq!(
        denied,
        Err(DenyReason::PidReused),
        "終了済みのプロセスハンドルが「台帳に無い」として扱われている。\
         この2つは原因が別なので、同じ理由へ丸めない"
    );
    assert_ne!(
        denied,
        Err(DenyReason::NotRegistered),
        "2つの拒否理由が同じ値になっている（対で測る意味が消える）"
    );
}

/// **系統Jobの複製は、系統の最後の1人が消えたときにだけ返る**（§10.1.1）。
///
/// これが早すぎると、まだ生きている子孫を封じ込めているJobが閉じられる。
/// 遅すぎる（＝返らない）と、複製が残ってkill-on-closeが二度と働かない。
#[test]
fn the_lineage_job_comes_back_only_when_the_last_member_is_reaped() {
    let mut table = ProcessTable::new();
    let lineage = table
        .register_top_level(4200, PROC_1, JOB_A, domain("pwsh-workspace"))
        .expect("register the top level");
    table
        .register_in_lineage(4201, PROC_2, lineage, domain("git-workspace"))
        .expect("register a nested child in the same lineage");

    let first = table.reap(4200).expect("reap the first member");
    assert_eq!(first.process, Some(PROC_1));
    assert_eq!(
        first.lineage_job, None,
        "まだ子孫が残っているのに系統Jobを閉じようとしている。\
         生きている子孫の封じ込めが外れる"
    );

    let last = table.reap(4201).expect("reap the last member");
    assert_eq!(last.process, Some(PROC_2));
    assert_eq!(
        last.lineage_job,
        Some(JOB_A),
        "系統の最後の1人が消えたのに複製が返ってこない。\
         閉じられないままJobが生き続け、kill-on-closeの保険が働かなくなる（§10.1.1）"
    );

    assert!(table.is_empty(), "回収後も台帳にエントリが残っている");
}

/// **誤検知の対**（問4）: ある系統を畳んでも、**別の系統には触らない**。
///
/// ここが混ざると、片方のコマンドをキャンセルしたつもりで別のコマンドの
/// 封じ込めまで外れる。
#[test]
fn reaping_one_lineage_leaves_another_lineage_untouched() {
    let mut table = ProcessTable::new();
    table
        .register_top_level(4200, PROC_1, JOB_A, domain("pwsh-workspace"))
        .expect("register lineage A");
    table
        .register_top_level(5300, PROC_2, JOB_B, domain("pwsh-workspace"))
        .expect("register lineage B");

    let reaped = table.reap(4200).expect("reap lineage A");
    assert_eq!(reaped.lineage_job, Some(JOB_A));

    let survivor = table
        .resolve(5300, all_alive)
        .expect("the other lineage still resolves");
    assert_eq!(
        survivor.lineage_job, JOB_B,
        "別の系統のJobが巻き添えで消えている"
    );
}

/// 同じPIDを2度登録したら**失敗する**（上書きしない）。
///
/// 上書きすると、古いエントリが持っていたプロセスハンドルと系統Jobの複製を
/// 誰も閉じられなくなる（`B-01`）。**握り潰さずに生成を失敗させる**のが§12の決定なので、
/// ここは`Err`でなければならない。
#[test]
fn registering_the_same_pid_twice_fails_instead_of_overwriting() {
    let mut table = ProcessTable::new();
    table
        .register_top_level(4200, PROC_1, JOB_A, domain("pwsh-workspace"))
        .expect("first registration");

    let second = table.register_top_level(4200, PROC_3, JOB_B, domain("other"));
    assert_eq!(
        second,
        Err(RegisterError::PidAlreadyRegistered { pid: 4200 }),
        "同じPIDの再登録が通っている。古いハンドルが行方不明になる"
    );

    // 上書きされていないことを、引ける値の側からも確かめる。
    let still = table.resolve(4200, all_alive).expect("resolve");
    assert_eq!(still.lineage_job, JOB_A, "元のエントリが壊れている");
}

/// 知らないPIDの回収は**何もしない**（二重に呼ばれても壊れない）。
///
/// プロセス終了の待ちは複数の経路（待機スレッド・終了処理）から来るので、
/// 冪等でないとハンドルを二重に閉じる。
#[test]
fn reaping_an_unknown_pid_is_a_no_op() {
    let mut table = ProcessTable::new();
    table
        .register_top_level(4200, PROC_1, JOB_A, domain("pwsh-workspace"))
        .expect("register");

    assert!(table.reap(9999).is_none(), "知らないPIDで何かを返している");
    assert!(table.reap(4200).is_some(), "登録済みのPIDが回収できない");
    assert!(
        table.reap(4200).is_none(),
        "同じPIDの2度目の回収が値を返している。呼び出し側が同じハンドルを2度閉じる"
    );
}

/// 終了時の`drain`は、**プロセスハンドルも系統Jobも1つ残らず返す**（`B-01`）。
///
/// `reap`と同じ条件（最後の1人だけ返す）を使うと、メンバーが残っている系統のJobが
/// 閉じ漏れる——Daemonの終了時は「最後の1人」を待たないためである。
#[test]
fn drain_returns_every_process_handle_and_every_lineage_job() {
    let mut table = ProcessTable::new();
    let lineage = table
        .register_top_level(4200, PROC_1, JOB_A, domain("pwsh-workspace"))
        .expect("register the top level");
    table
        .register_in_lineage(4201, PROC_2, lineage, domain("git-workspace"))
        .expect("register a nested child");
    table
        .register_top_level(5300, PROC_3, JOB_B, domain("pwsh-workspace"))
        .expect("register another lineage");

    let reaped = table.drain();

    let mut processes: Vec<u64> = reaped.iter().filter_map(|r| r.process).collect();
    processes.sort_unstable();
    assert_eq!(
        processes,
        vec![PROC_1, PROC_2, PROC_3],
        "プロセスハンドルが1つ以上返っていない"
    );

    let mut jobs: Vec<u64> = reaped.iter().filter_map(|r| r.lineage_job).collect();
    jobs.sort_unstable();
    assert_eq!(
        jobs,
        vec![JOB_A, JOB_B],
        "メンバーが残っている系統のJobが返っていない。\
         Daemonの終了時に複製が閉じ漏れる"
    );

    assert!(table.is_empty(), "drain後も台帳が空になっていない");
    assert!(
        table.drain().is_empty(),
        "2度目のdrainが値を返している。同じハンドルを2度閉じる"
    );
}

/// 存在しない系統への追加は失敗する。
///
/// 通してしまうと、そのプロセスは**どのJobにも属さないまま台帳に載る**ことになり、
/// キャンセルで殺せない子が生まれる（[BUG-156](../../../../docs/bugs/BUG-156.md)と同じ形）。
#[test]
fn registering_into_an_unknown_lineage_fails() {
    let mut table = ProcessTable::new();
    let lineage = table
        .register_top_level(4200, PROC_1, JOB_A, domain("pwsh-workspace"))
        .expect("register");
    // ここで返る系統Jobは、このテストでは閉じる相手が居ない（ただの整数）。
    // `#[must_use]`は「呼び出し側が閉じ忘れる」ことへの警告なので、
    // **閉じる相手が無いことを明示して**受け取る。
    let _reaped = table.reap(4200).expect("reap so the lineage disappears");

    assert_eq!(
        table.register_in_lineage(4201, PROC_2, lineage, domain("git-workspace")),
        Err(RegisterError::UnknownLineage),
        "消えた系統へ子を足せてしまう。どのJobにも入らない子が台帳に載る"
    );
}
