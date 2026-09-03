//! CoW差分層の巡回（[`super::cow_layer_sweep`]）が、**剥がすべきものだけを剥がす**ことの回帰。
//!
//! # なぜ許可側を対にするのか
//!
//! 「引退した身分のACEが消えた」だけを見るテストは、**全部剥がす実装でも緑になる**。
//! そして全部剥がす実装は、他アプリのサンドボックス（`ALL APPLICATION PACKAGES`宛のACEに
//! 依存するEdge/Chrome/VS Code）を壊すか、走行中のセッションから権限を奪う——
//! どちらもこのリポジトリで実際に起きた形である（BUG-046・BUG-053）。`B-35`。
//!
//! | # | 測るもの | テスト |
//! |---|---|---|
//! | 1 | 引退した身分のACEは**剥がれる**／well-knownのSIDは**残る** | `the_sweep_takes_a_retired_identitys_ace_off_a_diff_layer_and_leaves_a_well_known_one` |
//! | 2 | 走行中の差分層は**DACLを読みにすら行かない** | `a_running_sessions_diff_layer_is_not_even_examined` |
//! | 3 | AppContainerのACEが1本も無い差分層は**1行も報告しない** | `a_diff_layer_with_no_appcontainer_ace_reports_nothing` |
//! | 4 | 剥がした件数は**報告に出る**（黙って剥がさない、`B-11`） | `the_summary_names_what_was_revoked_and_stays_quiet_when_nothing_happened` |
//!
//! # 実マシンの差分層は触らない
//!
//! すべて`sweep_diff_layer_aces_in`（列挙を引数で受ける方）に対して撃ち、対象は自分が作った
//! 一時ディレクトリだけである。実列挙を使う`sweep_diff_layer_aces`はここでは呼ばない——
//! 差分層を触る掃除を`preflight`へ置いたときに`cargo test --workspace`が開発機の差分層を
//! 70件消した前例がある（`harness-cli`の`sweep_empty_cow_diff_areas`のdoc）。

use super::test_support::scopeguard;
use super::*;

/// 実在しないプロファイル名からSIDを導く。**プロファイルは作らない**
/// （`derive_profile_sid`は名前→SIDの一方向の導出で、OSの資源を1つも作らない）。
fn fabricate_subject(name: &str) -> (OwnedContainerSid, String) {
    let sid = derive_profile_sid(name).expect("derive a package SID from a profile name");
    let text = crate::win_common::sid_to_string(sid.as_psid()).expect("SID to string");
    (sid, text)
}

fn package_sids_on(path: &std::path::Path) -> Vec<String> {
    appcontainer_sid_aces(path)
        .expect("read the DACL")
        .into_iter()
        .map(|s| s.sid)
        .collect()
}

fn target(id: &str, dir: &std::path::Path, is_live: bool) -> DiffLayerSweepTarget {
    DiffLayerSweepTarget {
        session_id: id.to_string(),
        diff_layer_dir: dir.to_path_buf(),
        is_live,
    }
}

/// **測定1**: 引退した身分のACEは剥がれ、well-knownのSIDは残る。
///
/// # 壊れた状態を一文で
///
/// 剥がれない側に壊れると、身分の付け方を変えるたびに撤収経路の無いACEが積もる
/// （残課題#35で実際に10件・1か月）。剥がしすぎる側に壊れると、`ALL APPLICATION PACKAGES`に
/// 依存している他アプリのサンドボックスが起動できなくなる（BUG-046と同じ形）。
#[test]
fn the_sweep_takes_a_retired_identitys_ace_off_a_diff_layer_and_leaves_a_well_known_one() {
    let dir = tempfile::tempdir().expect("temp dir");
    let layer = dir.path().join("session-1785675833861");
    std::fs::create_dir(&layer).expect("create the diff layer");

    // 登録の無い身分。マスクが完全一致するので規則4で「harness由来」と名乗れる。
    let (retired_sid, retired_text) = fabricate_subject("harness.shell.sandbox.9002-22222222");
    let well_known = crate::win_common::sid_from_string("S-1-15-2-1").expect("well-known SID");

    grant_ace_inheritable_access(&layer, retired_sid.as_psid(), FsAccess::ReadWrite)
        .expect("grant the retired identity's ACE");
    grant_ace_inheritable_access(&layer, well_known.as_psid(), FsAccess::ReadExec)
        .expect("grant the well-known SID's ACE");
    let _cleanup = scopeguard(|| {
        let _ = revoke_ace(&layer, retired_sid.as_psid());
        let _ = revoke_ace(&layer, well_known.as_psid());
    });

    // **子は付与のあとで作る。** `grant_ace_inheritable_access`は単一オブジェクト書込なので、
    // 既に在る子孫へは届かない（`DaclWrite::SingleObject`のdoc）。実機の差分層も
    // 「セッション開始時にディレクトリへ付き、そのあと中身が作られて継承する」順序なので、
    // ここを逆にすると実機と違う形を測ることになる。
    std::fs::write(layer.join(".harness-cow-session.json"), b"{}").expect("write a child file");

    // **計器を先に確かめる。** ここが崩れていると、後の「0本」は「剥がれた」ではなく
    // 「最初から見えていなかった」を意味する。
    let before = package_sids_on(&layer);
    assert!(
        before.contains(&retired_text) && before.contains(&"S-1-15-2-1".to_string()),
        "the reader must see both subjects before the sweep runs; saw {before:?}"
    );
    // 子は**継承ACEまで数える読み口**で見る。このリポジトリには読み口が3つあり、
    // 継承を数えるのは`sid_effective_ace_mask`だけである——`appcontainer_sid_aces`
    // （＝`package_sids_on`）と`sid_ace_mask`はどちらも**明示ACEしか返さない**
    // （撤収側は継承元でしか剥がせないので、そちらではそれが正しい意味である）。
    // ここで明示側を使うと、「継承していない」と「その読み口には見えない」を取り違える。
    let child = layer.join(".harness-cow-session.json");
    assert!(
        sid_effective_ace_mask(&child, retired_sid.as_psid())
            .expect("readable")
            .is_some(),
        "the grant must reach the child through inheritance, otherwise this test never exercises \
         the recursive part of the revoke"
    );

    let outcome = sweep_diff_layer_aces_in(&[target("session-1785675833861", &layer, false)]);

    assert_eq!(outcome.examined, 1);
    assert_eq!(
        outcome
            .revoked
            .iter()
            .map(|(_, sid)| sid.clone())
            .collect::<Vec<_>>(),
        vec![retired_text.clone()],
        "exactly the retired identity must be reported as revoked"
    );
    assert!(
        outcome.still_present.is_empty() && outcome.failures.is_empty(),
        "nothing may be left half-revoked: {outcome:?}"
    );
    assert_eq!(
        outcome.left_alone.len(),
        1,
        "the well-known SID must be reported as deliberately left alone, not silently ignored"
    );
    assert_eq!(outcome.left_alone[0].1, "S-1-15-2-1");

    // 別の読み口で検算する（同じ列挙関数だけを信じない）。
    assert_eq!(
        sid_ace_mask(&layer, retired_sid.as_psid()).expect("readable"),
        None,
        "a second reader must also agree that the retired identity's ACE is gone"
    );
    assert!(
        sid_ace_mask(&layer, well_known.as_psid())
            .expect("readable")
            .is_some(),
        "the well-known SID's ACE must survive: other applications depend on it"
    );
    assert_eq!(
        sid_effective_ace_mask(&child, retired_sid.as_psid()).expect("readable"),
        None,
        "the inherited copy on the child must be gone too; leaving it there is exactly the state \
         that had to be cleaned up by hand on the real machine"
    );
}

/// **測定2**: 走行中の差分層は対象にしない。
///
/// 生きている身分は宛先判定の規則1でも守られるが、ここで測るのは**そこへ辿り着かない**ことである
/// ——走行中の差分層は中身が動いており、DACLを書き換えながら歩く理由が無い。
#[test]
fn a_running_sessions_diff_layer_is_not_even_examined() {
    let dir = tempfile::tempdir().expect("temp dir");
    let layer = dir.path().join("session-live");
    std::fs::create_dir(&layer).expect("create the diff layer");

    let (retired_sid, retired_text) = fabricate_subject("harness.shell.sandbox.9003-33333333");
    grant_ace_inheritable_access(&layer, retired_sid.as_psid(), FsAccess::ReadWrite)
        .expect("grant an ACE that would otherwise be revoked");
    let _cleanup = scopeguard(|| {
        let _ = revoke_ace(&layer, retired_sid.as_psid());
    });

    let outcome = sweep_diff_layer_aces_in(&[target("session-live", &layer, true)]);

    assert_eq!(outcome.skipped_live, 1);
    assert_eq!(
        outcome.examined, 0,
        "a live session's diff layer must not even have its DACL read"
    );
    assert!(outcome.revoked.is_empty());
    assert!(
        package_sids_on(&layer).contains(&retired_text),
        "the ACE must still be there: the same SID is revoked when the session is not live, so \
         this asserts the live check and not the classifier"
    );
}

/// **測定3**: AppContainerのACEが1本も無い差分層は、何も報告せずに終わる。
///
/// **このテストが測っていないもの**: 実装はここで「登録簿を読まずに抜ける」安い経路を通るが、
/// **その事実はここからは観測できない**（分類を1回余計に走らせても結果は同じ緑になる）。
/// 費用の性質はコードを読んで言っているだけで、測定ではない。ここで固定しているのは
/// **「何も無い差分層は起動のたびに1行も出さない」**という、報告の側の性質である。
#[test]
fn a_diff_layer_with_no_appcontainer_ace_reports_nothing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let layer = dir.path().join("session-plain");
    std::fs::create_dir(&layer).expect("create the diff layer");

    assert!(
        package_sids_on(&layer).is_empty(),
        "the fixture must start with no AppContainer ACE, otherwise this measures nothing"
    );

    let outcome = sweep_diff_layer_aces_in(&[target("session-plain", &layer, false)]);

    assert_eq!(outcome.examined, 1);
    assert!(outcome.revoked.is_empty());
    assert!(outcome.left_alone.is_empty());
    assert!(outcome.failures.is_empty());
    assert_eq!(
        outcome.summary(),
        None,
        "a sweep that found nothing must stay quiet; otherwise every startup prints a line that \
         means nothing and the one startup that matters is lost in it"
    );
}

/// **測定4**: 実体の無い差分層は数えず、報告は起きたことだけを言う。
#[test]
fn the_summary_names_what_was_revoked_and_stays_quiet_when_nothing_happened() {
    let dir = tempfile::tempdir().expect("temp dir");
    let missing = dir.path().join("session-gone");

    let outcome = sweep_diff_layer_aces_in(&[target("session-gone", &missing, false)]);
    assert_eq!(
        outcome.examined, 0,
        "a diff layer that is gone is not examined"
    );
    assert_eq!(outcome.summary(), None);

    let spoke = DiffLayerAceSweep {
        revoked: vec![("session-a".into(), "S-1-15-2-9".into())],
        ..DiffLayerAceSweep::default()
    };
    let line = spoke.summary().expect("a revoke must be reported");
    assert!(
        line.contains("revoked 1"),
        "the count has to be in the line: {line}"
    );
}

/// **この巡回を起動のたびに走らせる追加費用**を、この機の実際の差分層で測る。
///
/// # なぜプロセスの外から測らないのか
///
/// `harness tier2a gc`をシェルから3回撃って比べたところ、`harness --version`（何もしない）
/// より速い値が出た——**プロセス起動のばらつきが測りたい量より大きい**。桁が違うものを
/// 引き算しても差は出ない。だから同一プロセス内で`Instant`で測る。
///
/// # 何が分かれば十分か
///
/// 起動のたびに払うものは2つある。**(a) 差分層の列挙**（`collect_cow_session_facts`。
/// メタの読取と内容ファイルの数え上げ）と、**(b) 各差分層のDACLを1回読む**巡回本体である。
/// (a)は`sweep_empty_cow_diff_areas`が**既に**払っているので、この変更で増えるのは
/// 「(a)をもう1回」＋(b)になる。**その2つを分けて出す**——分けないと、増えた分が
/// もともと在った分に紛れる。
///
/// # 実マシンを読む（書かない）
///
/// この測定は`sweep_diff_layer_aces`（実列挙を使う方）を呼ぶので、**この機の実際の差分層の
/// DACLを読む**。書込は起きない——引退した身分のACEは2026-09-03に手で剥がしてあり、
/// 剥がすものが無ければ`revoke_sids_recursive`は対象0件で即座に戻る。それでも読み取りは
/// 実マシンに対して行うので`#[ignore]`にしてある。
///
/// ```text
/// cargo test -p harness-sandbox --lib measure_the_diff_layer_sweep_cost -- --ignored --nocapture
/// ```
#[test]
#[ignore = "timing measurement against the real machine's diff layers; run explicitly"]
fn measure_the_diff_layer_sweep_cost() {
    const REPS: usize = 5;
    let mut enumerate = Vec::new();
    let mut sweep = Vec::new();
    let mut layers = 0usize;

    let mut cheap = Vec::new();
    for _ in 0..=REPS {
        // (a-1) `cow list`／`cow gc`が使う重い方（削除の可否を決めるための材料まで採る）。
        // **この巡回はこれを使わない**が、起動経路では別の掃除が既に払っているので、
        // 「素直に書いたら増えていたはずの額」としてここで測る。
        let started = std::time::Instant::now();
        let (facts, _) = crate::tier2a::workspace_ledger::collect_cow_session_facts();
        let enumerated = started.elapsed().as_secs_f64() * 1000.0;
        layers = facts.len();
        drop(facts);

        // (a-2) この巡回が実際に使う軽い方（ディレクトリ列挙＋生存判定だけ）。
        let started = std::time::Instant::now();
        let (dirs, _) = crate::tier2a::workspace_ledger::list_cow_sessions();
        let targets: Vec<DiffLayerSweepTarget> = dirs
            .into_iter()
            .map(|d| DiffLayerSweepTarget {
                is_live: crate::tier2a::workspace_ledger::cow_session_is_live(&d.session_id),
                session_id: d.session_id,
                diff_layer_dir: d.diff_layer_dir,
            })
            .collect();
        cheap.push(started.elapsed().as_secs_f64() * 1000.0);

        let started = std::time::Instant::now();
        let outcome = sweep_diff_layer_aces_in(&targets);
        let swept = started.elapsed().as_secs_f64() * 1000.0;

        // **検算**: 速いのが「見に行かなかったから」でないこと。走行中でない差分層は
        // 全部DACLを読んでいるはずである。
        assert_eq!(
            outcome.examined + outcome.skipped_live,
            targets.iter().filter(|t| t.diff_layer_dir.exists()).count(),
            "every diff layer that exists must be either examined or skipped as live; if some \
             were silently dropped, the time below measures less work than it claims"
        );
        enumerate.push(enumerated);
        sweep.push(swept);
    }
    // 先頭の1周は捨てる（冷えた状態が全体に混ざる）。
    for v in [&mut enumerate, &mut cheap, &mut sweep] {
        v.remove(0);
        v.sort_by(f64::total_cmp);
    }
    let med = |v: &Vec<f64>| v[v.len() / 2];

    eprintln!(
        "diff layer sweep cost: layers={layers} (n={REPS}, medians)\n  \
         collect_cow_session_facts (NOT used here; the startup path already pays it): {:.1}ms\n  \
         list_cow_sessions + liveness (what this sweep uses)                        : {:.1}ms\n  \
         the sweep itself (one DACL read per layer)                                 : {:.1}ms\n  \
         => added per startup: {:.1}ms",
        med(&enumerate),
        med(&cheap),
        med(&sweep),
        med(&cheap) + med(&sweep),
    );

    // **検算**: 軽い列挙が重い列挙より安いこと。逆転していたら、置き換えた理由が成立しない。
    assert!(
        med(&cheap) < med(&enumerate),
        "the cheap enumeration ({:.1}ms) must beat the one that also reads metadata and counts \
         content files ({:.1}ms); if it does not, this sweep should just reuse the facts the \
         startup path already collected",
        med(&cheap),
        med(&enumerate),
    );
}
