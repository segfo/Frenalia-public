//! **ドメインをN個用意して片付ける費用の測定**（残課題#55の本体に着手する前）。
//! 結果の正本は `plans/mac-spike/RESULTS.md` **§S72**。
//!
//! # なぜ測るのか
//!
//! 遷移先ごとにドメインを分けると、ドメインは自分専用の入れ物（AppContainerプロファイル
//! ＝package SID）を持つ（`plans/DESIGN-MAC-BROKER.md` §22.9）。問題は**いつ作るか**で、
//! 選べる形は2つしかない。
//!
//! | 形 | 起動 | 許可を配る操作 |
//! |---|---|---|
//! | A: 起動時にまとめて用意する | Nに比例して重くなる | **1回で済む** |
//! | B: 遷移が起きた瞬間に作る | 速い | **任意の時点で起きる**（昇格が要る場面ではそこでUACが出る） |
//!
//! **Bは実質採れない**——起動あたりのUACを1回に抑える設計と正面から衝突する。
//! だから**Aが払えるかどうか**が分岐点である。
//!
//! §22.9の費用表はプロファイル生成を「7〜11ミリ秒/個」と持っているが、それは
//! **生成の呼び出し単体**の値で、**台帳への記録・終了時の回収を含む一周**は数えていない。
//!
//! # 測る前に決めてある分岐（数字を見てから基準を作らない）
//!
//! | 結果 | どう進めるか |
//! |---|---|
//! | N=11で**1秒未満**、かつ線形 | Aで進む（起動時にまとめて用意する素直な実装） |
//! | 数秒、または**Nより速く増える** | 形を変える。測定結果を持って設計へ戻る |
//!
//! # 測っているのは**部品**であって、実装後の前口上ではない
//!
//! #55の実装がまだ無いので、製品の前口上そのものは測れない。ここが積むのは
//! 「入れ物を作る」「台帳へ記録する」「回収する」という**部品の値**である。
//! **「実装したらこの値になる」とは書かないこと。**
//!
//! # ドメイン用の名前はまだ無いので、MCPサーバの形を代役にする
//!
//! ドメインのプロファイル名（`harness.domain.…`）は#55の実装で決まる。ここで先に作ると、
//! **実装が決める前に綴りが1つ増える**。MCPサーバのプロファイルは
//! `<接頭辞>.<セッションの印>.<id>` という**同じ形**で、しかも既に回収経路を持っている
//! （`plan_reclaim`・`end_session`）ので、機構としては同一である。**代役であることは
//! 結果にも書く**——ドメイン固有の費用（宣言からcapabilityを組む等）は含まれていない。
//!
//! # 昇格は要らない／ただし直列で回す
//!
//! 入れ物の作成も台帳の書込も非昇格で通る。ただし**入れ物はマシン全体の資源**なので、
//! 並列に回すと他のテストのプロファイルと混ざる。`#[ignore]`にしてあり、明示的に回す。
//!
//! ```text
//! cargo test -p harness-sandbox --lib domain_profile_cost -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! # このモジュールを消す条件（**日付ではなく出来事**）
//!
//! 残課題#55が着地し、§22.9の費用表がこの測定の値で更新されたら、**モジュールごと消す**。
//! 「着地」は**`docs/STATUS.md`サンドボックス周辺 #55 の行が閉じること**を指す（骨格の着地ではない。
//! 2026-09-30のユーザー判断）。費用表の側は§S72の値で更新済みなので、残っている条件は#55だけである。
//! 隣の`acl_baseline_cost_tests`が同じ形の先例を持つ（規則2の例外の扱いもそちら）。

use std::time::Instant;

use super::*;
use crate::tier2a::session_profile;

/// 振るNの値。
///
/// **11はこのリポジトリの実測値である**——サンドボックスの中で`cargo build`を通すのに要る
/// プログラムが11本で（`plans/mac-spike/RESULTS.md` §S71）、設計は「exeが違えば各段は
/// 自動的に別ドメインになる」と定めている（§19.3.2）。0と1は下駄の分離、32は**形
/// （線形かそれより悪いか）を見るため**であって「32ドメインを使う」という主張ではない。
const AXIS: &[usize] = &[0, 1, 4, 11, 32];

/// 測定で作るプロファイルのidの接頭辞。**実際のMCPサーバのidと衝突しない綴り**にする
/// （回収は同じ経路を通るので、混ざると他人のものを消す形になる）。
const COST_ID_PREFIX: &str = "domaincost";

/// 1回ぶんの測定値（ミリ秒）。
#[derive(Debug, Clone, Copy)]
struct Arm {
    n: usize,
    create_ms: u128,
    record_ms: u128,
    reclaim_ms: u128,
}

impl Arm {
    fn total_ms(&self) -> u128 {
        self.create_ms + self.record_ms + self.reclaim_ms
    }
}

/// 測定で作ったプロファイルが1つも残っていないことを確かめる。
///
/// # 台帳ではなく**マシン**に聞く
///
/// `DeleteAppContainerProfile`は**S_OKを返しながら何も消さないことがある**
/// （`session_profile`の`delete_profile`のdocが実測を書いている）。そのとき落ちるのは
/// 台帳エントリだけなので、**台帳を見ても「消えた」は分からない**——実機に66件
/// たまっていたのはこの形である。「呼んだ」と「消えた」は別の事実なので、
/// OSに直接聞く口（`existing_profiles_for_test`）を通す（`B-33`）。
///
/// 残っていたら次の測定の下駄になるので、**その回の数字は使えない**。
fn assert_no_cost_profiles_left(stage: &str) {
    let leftovers: Vec<String> = session_profile::existing_profiles_for_test()
        .into_iter()
        .filter(|name| name.contains(COST_ID_PREFIX))
        .collect();
    assert!(
        leftovers.is_empty(),
        "[{stage}] 測定が作った入れ物がマシンに残っている。残すと次の測定の下駄になり、\
         この回の数字は使えない: {leftovers:?}"
    );
}

/// N個ぶんを「作る→記録する→回収する」まで回して、区間ごとの所要を返す。
///
/// **製品の経路をそのまま通す**——`ensure_profile`（作る）・`record_mcp_profile`（台帳へ）・
/// `end_session`（回収）。形を書き写した再現で測ると、製品が変わったときに計器だけが
/// 古いまま緑になる。
fn measure_arm(n: usize) -> Arm {
    // このセッションの台帳エントリを開く（冪等）。回収のたびに消えるので毎回呼ぶ。
    session_profile::begin_session().expect("begin the measurement session");

    // 区間2: 台帳へN件記録する。**記録が先**（`record_mcp_profile`のdocの順序）。
    let t = Instant::now();
    let mut names = Vec::with_capacity(n);
    for k in 0..n {
        names.push(session_profile::record_mcp_profile(&format!(
            "{COST_ID_PREFIX}{k}"
        )));
    }
    let record_ms = t.elapsed().as_millis();

    // 区間1: 入れ物をN個作る。
    let t = Instant::now();
    for name in &names {
        let _sid = ensure_profile(name).expect("create the measurement profile");
    }
    let create_ms = t.elapsed().as_millis();

    // 検算: 作ったものが**マシンに実在する**こと。台帳ではなくOSに聞く——
    // 台帳は「記録した」しか答えず、それは`ensure_profile`が実際に作ったことの根拠にならない
    // （上の`assert_no_cost_profiles_left`と同じ理由）。
    // **0件の腕では何も作っていない**ので、その場合だけ飛ばす
    // （「作っていない」と「作れなかった」を混ぜない）。
    if n > 0 {
        let existing = session_profile::existing_profiles_for_test();
        let found = names.iter().filter(|name| existing.contains(name)).count();
        assert_eq!(
            found, n,
            "作ったはずの入れ物がマシンに無い。以後の数字は「作る費用」を測っていない"
        );
    }

    // 区間4: 回収する（入れ物の削除＋台帳の掃除）。製品の終了経路そのもの。
    let t = Instant::now();
    let outcome = session_profile::end_session(&revoke_session_grant);
    let reclaim_ms = t.elapsed().as_millis();
    // 回収の報告そのものは信じない（上記docの理由）。残っていないことを別に見る。
    let _ = outcome;
    assert_no_cost_profiles_left(&format!("N={n} の回収後"));

    Arm {
        n,
        create_ms,
        record_ms,
        reclaim_ms,
    }
}

/// **§S72の本体**: ドメインをN個用意して片付けるまでの費用と、その増え方。
///
/// # 壊れた状態を一文で
///
/// **起動時にまとめて用意する形（A）が、実際には払えない重さだった**。
/// そのときは実装へ進まず、設計へ戻る（モジュールdocの分岐表）。
///
/// # 読み方の限界
///
/// 測っているのは**部品**である（モジュールdoc）。実装後の前口上には、ここに含まれない
/// 費用（宣言からcapabilityを組む・`.harness/`の保護・WFP）が乗る。
#[test]
#[ignore = "実機の資源（AppContainerプロファイル）を作るため、明示的に直列で回す"]
fn domain_profile_cost_of_preparing_and_reclaiming_n_domains() {
    // 始める前に、前の回の残骸が無いことを確かめる（在ると下駄になる）。
    assert_no_cost_profiles_left("開始前");

    let mut arms = Vec::new();
    for n in AXIS {
        let arm = measure_arm(*n);
        eprintln!(
            "  N={:>2}: create {:>5} ms / record {:>5} ms / reclaim {:>5} ms / total {:>5} ms",
            arm.n,
            arm.create_ms,
            arm.record_ms,
            arm.reclaim_ms,
            arm.total_ms()
        );
        arms.push(arm);
    }

    println!("\n=== §S72: ドメインをN個用意して片付ける費用 ===");
    println!("N\tcreate(ms)\trecord(ms)\treclaim(ms)\ttotal(ms)\tper-domain(ms)");
    for arm in &arms {
        let per = if arm.n == 0 {
            0
        } else {
            arm.total_ms() / arm.n as u128
        };
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            arm.n,
            arm.create_ms,
            arm.record_ms,
            arm.reclaim_ms,
            arm.total_ms(),
            per
        );
    }

    // **計器の歯**: Nを増やしたのに総額が動かないなら、この計器は費用を測れていない。
    let smallest = arms.first().expect("at least one arm").total_ms();
    let largest = arms.last().expect("at least one arm").total_ms();
    assert!(
        largest > smallest,
        "Nを0から{}まで増やしても総額が増えていない（{smallest} ms → {largest} ms）。\
         この計器は費用を測れていないので、出た数字は使えない",
        AXIS.last().copied().unwrap_or(0)
    );

    assert_no_cost_profiles_left("全腕の終了後");
}

/// **対照（`B-35`）**: 台帳への記録は、件数に対してどう増えるか。
///
/// # なぜ別の腕にするのか
///
/// 残課題#37は「1件ずつ台帳を更新すると、台帳が育つほど1件が高くなる」を実測している
/// （宣言668件で13.46秒）。**いまの`record_mcp_profile`は1件ずつの形**なので、
/// 同じ性質がここにも出るはずである。出ないなら、どちらかの測定が間違っている。
///
/// 上の本体テストは3区間の合計を見るので、**記録だけの増え方がその中に埋もれる**。
/// ここはそれだけを取り出す。
#[test]
#[ignore = "実機の台帳を触るため、明示的に直列で回す"]
fn domain_profile_cost_of_recording_grows_with_the_count() {
    assert_no_cost_profiles_left("開始前");
    session_profile::begin_session().expect("begin the measurement session");

    let mut rows = Vec::new();
    for n in AXIS {
        let t = Instant::now();
        for k in 0..*n {
            let _ = session_profile::record_mcp_profile(&format!("{COST_ID_PREFIX}r{k}"));
        }
        let ms = t.elapsed().as_millis();
        rows.push((*n, ms));
        // 次の腕のために畳む（**記録は冪等**なので、同じidを積み直しても増えない。
        // それでは「N件を新しく書く費用」にならないので、毎回回収してから次へ行く）。
        let _ = session_profile::end_session(&revoke_session_grant);
        assert_no_cost_profiles_left(&format!("N={n} の記録測定後"));
        session_profile::begin_session().expect("re-open the measurement session");
    }

    println!("\n=== §S72-2: 台帳へN件記録する費用（1件ずつ書く今日の形） ===");
    println!("N\trecord(ms)\tper-entry(ms)");
    for (n, ms) in &rows {
        let per = if *n == 0 { 0 } else { ms / *n as u128 };
        println!("{n}\t{ms}\t{per}");
    }

    let _ = session_profile::end_session(&revoke_session_grant);
    assert_no_cost_profiles_left("記録測定の終了後");
}

/// **区間3**: 制御面（`.harness/`）の保護は、宛先SIDの本数で重くなるか。
///
/// # なぜ別に測るのか
///
/// ドメインを増やすと、`.harness/`から締め出す宛先SIDも増える（§22.9の配線点）。
/// **ノード数は変わらない**ので「1ノードにN本のACEを書くだけ」で済むはずだが、
/// それは読み取りからの推定である。宛先ごとにwalkを回す形になっていれば**N倍**になる。
///
/// 同じ形の取り違えは既に踏んでいる——`plans/mac-spike/RESULTS.md` §S15が
/// 「部品を使えば0倍、宛先SIDごとに伝播を呼ぶと約2.9倍」を出している。
///
/// # 対照（`B-35`）
///
/// 宛先1本と宛先N+1本の両方を測る。**増えない**と主張するには、増える側の値が要る。
#[test]
#[ignore = "実機のDACLを書くため、明示的に直列で回す"]
fn domain_profile_cost_of_protecting_the_control_dir_by_subject_count() {
    /// 腕1本ぶんの制御面を作る。**実物に近い形にする**（`.harness/`は数十ノード程度）。
    fn fresh_control_dir() -> tempfile::TempDir {
        let workspace = tempfile::tempdir().expect("temp workspace");
        let harness_dir = workspace.path().join(".harness");
        for sub in ["sandbox", "sessions", "logs", "transitions"] {
            std::fs::create_dir_all(harness_dir.join(sub)).expect("create the control dir");
            for k in 0..8 {
                std::fs::write(harness_dir.join(sub).join(format!("f{k}.json")), b"{}")
                    .expect("write a control file");
            }
        }
        workspace
    }

    // 宛先SIDは**実在の導出**で作る（偽のSIDだとDACLの書込が別経路へ落ちる）。
    // capability SIDとpackage SIDは所有型が別なので、`PSID`の列へ揃えてから渡す。
    let traverse = traverse_capability_sid().expect("traverse capability");
    let mut packages = Vec::new();
    for k in 0..*AXIS.last().expect("axis") {
        let name = crate::tier2a::mcp_profile::mcp_profile_name_for(
            session_profile::session_token(),
            &format!("{COST_ID_PREFIX}p{k}"),
        );
        packages.push(derive_profile_sid(&name).expect("derive a package SID from a profile name"));
    }
    let sids: Vec<_> = std::iter::once(traverse.as_psid())
        .chain(packages.iter().map(|s| s.as_psid()))
        .collect();

    println!("\n=== §S72-3: 制御面の保護（宛先SIDの本数を振る） ===");
    println!("subjects\tprotect(ms)\tprotected\twritten");
    for count in [1usize, 4, 12, 33] {
        // **腕ごとに新しい制御面を作る。** 保護は冪等で、2回目以降は「もう保護済み」として
        // **1ノードも書かない**——最初の測り方はこれで壊れていた（`written`が1回目だけ37で
        // 以降0になり、腕が比較になっていなかった）。書く費用を測るには毎回書かせる。
        let workspace = fresh_control_dir();
        let subset: Vec<_> = sids.iter().take(count).copied().collect();
        let t = Instant::now();
        let report = protect_harness_control_dir_from_appcontainer(workspace.path(), &subset)
            .expect("protect the control dir");
        let ms = t.elapsed().as_millis();
        println!("{count}\t{ms}\t{}\t{}", report.protected, report.written);
        // **計器の歯**: 1ノードも「書いた」になっていない腕は、冪等スキップの経路を
        // 測っているので、その数字は使えない。
        assert!(
            report.written > 0,
            "宛先{count}本の腕が1ノードも書いていない。冪等スキップの経路を測っている"
        );
        assert!(
            report.protected > 0,
            "1ノードも保護できていない。この数字は保護の費用を測っていない"
        );
    }
}
