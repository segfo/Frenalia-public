//! **Redirector DLLに残った孤立ACEを、既存の掃除処理が本当に回収するかの測定**
//! （残課題#23の測定M1、仮説H1。記録は`plans/e2e/RESULTS.md`の2026-09-03と[BUG-112](../../../../docs/bugs/BUG-112.md)）。
//!
//! # 何を測っているのか
//!
//! ACEを実マシンへ書いてから台帳へ記録するまでの間に強制終了されると、そのACEは
//! 「誰のものか」が分からなくなり、撤収（`end_session`・`gc_dead_sessions`）の対象から外れる。
//! これが残課題#23の窓である。Redirector DLLについては`preflight`が毎起動
//! `sweep_stale_redirector_dll_aces`を呼んでおり（BUG-059の修正）、**それで既に閉じている
//! のではないか**というのが仮説H1だった。**読み取りからそう見えるだけで、測っていなかった。**
//!
//! | # | 測るもの | テスト |
//! |---|---|---|
//! | 1 | 死んだセッションのpackage SID宛ACEが**剥がれる**／生きているセッションのものは**残る** | `the_sweep_takes_a_dead_sessions_ace_off_the_dll_and_leaves_the_live_one` |
//! | 2 | capability SID宛ACEは**掃除の視野に入らない**（意図された限界） | `the_sweep_is_blind_to_capability_sids_so_workspace_and_traverse_grants_survive` |
//! | 3 | 掃除が使う「残す側の名簿」が、**走行中の自分を含み・死んだセッションを含まない** | `the_live_list_keeps_this_session_and_excludes_one_that_is_no_longer_running` |
//! | 4 | 掃除が見に行く先は**走っている実行ファイルの隣だけ**である | `the_sweep_only_ever_looks_next_to_the_running_executable` |
//! | 5 | 走行中のセッションの**遷移先ドメイン**も残す側に載り、そのACEが**残る**（死んだものは剥がれる） | `the_sweep_leaves_a_running_sessions_transition_domain_alone` |
//!
//! # なぜ許可側（残る側）を必ず対にするのか
//!
//! 1と3は**禁止側だけでは緑にできてしまう**。「全部剥がす」実装でも、「名簿を常に空で返す」
//! 実装でも、剥がれることだけを見るテストは通る。そして全部剥がす実装は、
//! **走行中の他セッションから権限を奪う**（BUG-053で実際に起きた形）。`B-35`。
//!
//! # 計器を先に確かめる
//!
//! 1と2は「剥がれた」を**ACEが0本になったこと**で判定する。0本は
//! 「剥がれた」と「そもそも計器が見えていない」の2つを同じ値で表すので、
//! **剥がす前に計器が両方のACEを見えていること**を先にassertしてある。
//!
//! # このファイルが測っていないもの（**空にしない**）
//!
//! - **強制終了そのものを再現していない。** `TerminateProcess`は撃たない。窓が開く瞬間ではなく
//!   「開いた後に掃除が届くか」を測っている。窓の存在自体は依然として順序の読取から言っている
//! - **`preflight`を通していない。** 掃除の本体（`revoke_stale_appcontainer_aces`）と名簿
//!   （`live_profile_names`）を別々に測り、`sweep_stale_redirector_dll_aces`がその2つを
//!   繋いでいることは**読取で確かめてある**（`preflight.rs`の同関数）。通しで撃つと実物の
//!   DLLのDACLを書き換えることになる
//! - **別のビルドディレクトリに残った孤立ACE**。4がその境界を固定するだけで、
//!   「そこに実際に残っているか」は数えていない（`tools/probe-redirector-aces.ps1`で読める）
//!
//! # 実行（**昇格しないこと**）
//!
//! 1・2・4は一時ディレクトリしか触らないので、通常の`cargo test`で回る。
//!
//! **3と5だけは実台帳**（`%APPDATA%\harness\config\appcontainer-session-ledger.json`）へ
//! このプロセスのセッションエントリを開き、最後に自分で落とす。並列実行中の隣のテストから
//! 記録を奪い得るので`#[ignore]`にしてあり、専用ターゲットから**直列で**回す
//! （理由の全文は同テストのdoc）。
//!
//! ```text
//! dev-elevated-run.exe redirector-dll-sweep
//! ```

use super::test_support::scopeguard;
use super::*;

/// 実在しないプロファイル名からSIDを導いて、その文字列表現も返す。
///
/// **プロファイルは作らない。** `derive_profile_sid`は名前→SIDの一方向の導出で、
/// OSの資源を1つも作らない（同関数のdoc。撤収が副作用を持たないための性質）。
fn fabricate_subject(name: &str) -> (OwnedContainerSid, String) {
    let sid = derive_profile_sid(name).expect("derive a package SID from a profile name");
    let text = crate::win_common::sid_to_string(sid.as_psid()).expect("SID to string");
    (sid, text)
}

/// `path`のDACLに明示ACEを持つAppContainerパッケージSIDの文字列一覧（順不同）。
fn package_sids_on(path: &std::path::Path) -> Vec<String> {
    appcontainer_sid_aces(path)
        .expect("read the DACL")
        .into_iter()
        .map(|s| s.sid)
        .collect()
}

/// **測定1**: 死んだセッションのACEは剥がれ、生きているセッションのACEは残る。
///
/// # 壊れた状態を一文で
///
/// **記録の無いACEが、掃除を通しても剥がれずに残る**（＝残課題#23の窓が開いたままである）。
/// 逆向きに壊れた状態は「走行中のセッションのACEまで剥がれる」で、そちらは
/// サンドボックスの子がRedirector DLLを読めなくなる（BUG-053と同じ形）。
#[test]
fn the_sweep_takes_a_dead_sessions_ace_off_the_dll_and_leaves_the_live_one() {
    let dir = tempfile::tempdir().expect("temp dir");
    let dll = dir.path().join("harness_redirector.dll");
    std::fs::write(&dll, b"not really a dll").expect("write the probe file");

    // 実在しない2つのセッション。名前は`is_session_profile_name`が通す形にしておく
    // （掃除は名前を見ないが、製品が作る名前と別の形で測ると測定の前提がずれる）。
    let live_name = "harness.shell.sandbox.9001-11111111";
    let dead_name = "harness.shell.sandbox.9002-22222222";
    let (live_sid, live_text) = fabricate_subject(live_name);
    let (dead_sid, dead_text) = fabricate_subject(dead_name);

    // 付与は製品の付与ループと同じ関数・同じアクセスで行う（`preflight.rs`のCoW分岐）。
    grant_ace_inheritable_access(&dll, live_sid.as_psid(), FsAccess::ReadExec)
        .expect("grant the live session's ACE");
    grant_ace_inheritable_access(&dll, dead_sid.as_psid(), FsAccess::ReadExec)
        .expect("grant the dead session's ACE");
    let _cleanup = scopeguard(|| {
        let _ = revoke_ace(&dll, live_sid.as_psid());
        let _ = revoke_ace(&dll, dead_sid.as_psid());
    });

    // 計器の確認を先に置く。ここが崩れていると、この後の「0本になった」は
    // 「剥がれた」ではなく「最初から見えていなかった」を意味する。
    let before = package_sids_on(&dll);
    assert!(
        before.contains(&live_text) && before.contains(&dead_text),
        "the ACE reader must see both subjects before the sweep runs, otherwise a later count of \
         zero cannot be read as 'the sweep removed it'; saw {before:?}"
    );

    // `sweep_stale_redirector_dll_aces`の本体。名簿には生きている側だけを載せる。
    let removed = revoke_stale_appcontainer_aces(&dll, &[live_name.to_string()])
        .expect("sweep the stale ACEs");

    assert_eq!(
        removed,
        vec![dead_text.clone()],
        "the sweep must report exactly the dead session's SID as removed"
    );

    let after = package_sids_on(&dll);
    assert_eq!(
        after,
        vec![live_text.clone()],
        "the dead session's ACE must be gone and the live session's ACE must survive"
    );

    // 別の読み口で検算する（同じ列挙関数だけを信じない）。
    assert_eq!(
        sid_ace_mask(&dll, dead_sid.as_psid()).expect("readable"),
        None,
        "a second reader must also agree that the dead session's ACE is gone"
    );
    assert!(
        sid_ace_mask(&dll, live_sid.as_psid())
            .expect("readable")
            .is_some(),
        "a second reader must also agree that the live session's ACE is still there"
    );
}

/// **測定2**: capability SID宛のACEは**この掃除の**視野に入らない（`APPCONTAINER_SID_PREFIX`の意図）。
///
/// これは欠陥ではなく**限界**である。祖先traverse（D-37）とworkspace（D-54）の宛先SIDは
/// capability SIDで、`fs revoke-traverse`／`fs revoke-workspace`という名前の付いた扉が
/// 担当する。ここで巻き込むと`C:\`のtraverse ACEを純減させる（BUG-046）。
///
/// # 「この掃除が見ない」であって「誰も掃除しない」ではない（2026-09-25以降）
///
/// 名前を失ったcapability SID宛のACEには、上の3つの扉のどれも届かない——どれも台帳の名前を
/// 起点にSIDを導くからである。そこだけを担当する口を
/// [`revoke_unrecorded_capability_aces`]として別に置いた（[BUG-165](../../../../docs/bugs/BUG-165.md)。
/// このファイルの末尾に対のテストがある）。**この関数の射程は変えていない**——
/// 混ぜると上のとおりBUG-046を再現するので、2つの口が互いの担当へ手を出さないことを
/// 両向きで固定してある（`the_capability_sweep_does_not_touch_package_sid_aces`）。
///
/// **測る意味**: 「Redirector DLLの窓は閉じている」と言えるのは**package SID宛だけ**である、
/// という射程をここで固定する。同じDLLに載るcapability SID宛ACEはこの掃除では回収されない。
///
/// # 2026-09-19以降、これはDLL自身の許可を守るテストでもある（§22.9の前提）
///
/// DLLの読取+実行ACEは**宣言宛のcapability SID**へ移った（`preflight`の該当ブロック）。
/// つまりこの掃除がcapability SIDまで剥がすようになると、**毎起動でDLLが読めなくなり、
/// 注入の失敗＝生成ごと落ちる**（BUG-116）。当初は「他の扉の担当ぶんを巻き込まない」ための
/// テストだったが、いまは**この機構自身が依存している**。
#[test]
fn the_sweep_is_blind_to_capability_sids_so_workspace_and_traverse_grants_survive() {
    let dir = tempfile::tempdir().expect("temp dir");
    let dll = dir.path().join("harness_redirector.dll");
    std::fs::write(&dll, b"not really a dll").expect("write the probe file");

    let (dead_sid, dead_text) = fabricate_subject("harness.shell.sandbox.9003-33333333");
    let cap = traverse_capability_sid().expect("derive the traverse capability SID");

    grant_ace_inheritable_access(&dll, dead_sid.as_psid(), FsAccess::ReadExec)
        .expect("grant the package SID ACE");
    grant_ace_inheritable_access(&dll, cap.as_psid(), FsAccess::ReadExec)
        .expect("grant the capability SID ACE");
    let _cleanup = scopeguard(|| {
        let _ = revoke_ace(&dll, dead_sid.as_psid());
        let _ = revoke_ace(&dll, cap.as_psid());
    });

    // 計器: package SID側は見える。capability SID側は**この列挙関数からは最初から見えない**
    // ——だから「剥がれなかった」を`sid_ace_mask`で別途確かめる必要がある。
    assert!(
        package_sids_on(&dll).contains(&dead_text),
        "the reader must see the package SID before the sweep"
    );
    assert!(
        sid_ace_mask(&dll, cap.as_psid())
            .expect("readable")
            .is_some(),
        "the capability ACE must be present before the sweep"
    );

    // 名簿は空＝「残してよいセッションは1つも無い」。それでもcapabilityは剥がれない。
    let removed = revoke_stale_appcontainer_aces(&dll, &[]).expect("sweep");

    assert_eq!(
        removed,
        vec![dead_text],
        "the sweep must remove the package SID ACE even with an empty keep list"
    );
    assert!(
        sid_ace_mask(&dll, cap.as_psid())
            .expect("readable")
            .is_some(),
        "the capability SID ACE must survive: this sweep is deliberately scoped to S-1-15-2- \
         subjects, and pulling capability ACEs off shared ancestors is what broke the machine in \
         BUG-046"
    );
}

/// **測定3**: 掃除が「残す側」として使う名簿の両側。
///
/// # 壊れた状態を一文で
///
/// **走行中のセッションが名簿から落ちる**（＝そのセッションのACEが掃除で剥がされる）か、
/// **死んだセッションが名簿に残る**（＝孤立ACEが永久に剥がれない）。
/// 前者はfail-openではなく機能停止、後者がまさに残課題#23の窓である。
///
/// # なぜ`#[ignore]`なのか——**この測定だけが実台帳を触る**
///
/// 1・2・4は一時ディレクトリしか触らないが、この測定は実物の
/// `appcontainer-session-ledger.json`へ自分のセッションを開き、最後に**自分のエントリを消す**。
/// 既定の`cargo test`は同じlibターゲットのテストを並列に走らせるので、隣のテストがACEを付けて
/// 記録した直後にこの削除が入ると、**そのACEが回収名を失う**——測定が残課題#23そのものの状態を
/// 作ることになる（方式索引の方式6「テストが製品の台帳を書き換える」、`B-27`・`B-13`）。
///
/// 昇格は要らない。`dev-elevated-run.exe redirector-dll-sweep`から直列で回す。
#[test]
#[ignore = "writes to the real session ledger; run via dev-elevated-run redirector-dll-sweep"]
fn the_live_list_keeps_this_session_and_excludes_one_that_is_no_longer_running() {
    use crate::tier2a::session_profile;

    let dir = tempfile::tempdir().expect("temp dir");

    // 許可側: 自分は走っている。`begin_session`は生存マーカーを握り台帳へ登録する（冪等）。
    let own = session_session_name(&session_profile::begin_session());
    // **後始末はassertより先に武装する。** 落ちた回にも台帳を戻すため——歯の確認（意図的に
    // 壊して赤くする回）が実台帳へエントリを積むのでは、安全網の確認そのものが残骸を作る。
    let _forget_own = scopeguard(|| {
        session_profile::forget_session_entry_for_test(session_profile::session_token())
    });
    let live = session_profile::live_profile_names();
    assert!(
        live.contains(&own),
        "the running session must be on the keep list, otherwise the sweep tears the redirector \
         DLL ACE off a sandbox that is still using it (BUG-053); live={live:?} own={own}"
    );

    // 禁止側: 生存マーカーを握っていないトークンのエントリを1件足す。
    let dead_token = format!("{}-dead-for-test", session_profile::session_token());
    let dead_profile = session_profile::profile_name_for(&dead_token);
    session_profile::add_dead_session_with_capability_for_test(
        &dir.path().join("diff-layer-that-does-not-exist"),
        "harness.test.capability.that.was.never.granted",
    );
    // **足したものは自分で落とす。** GCに任せると落ちない——剥がす相手が実在しない
    // capabilityなので`revoke_capability_grant`が`Err`を返し、GCは（正しく）名前を残す。
    // 1回目の測定ではこれで実台帳にエントリが1件残った。
    let _forget = scopeguard(|| session_profile::forget_session_entry_for_test(&dead_token));

    let live_after = session_profile::live_profile_names();
    assert!(
        !live_after.contains(&dead_profile),
        "a session that is no longer running must NOT be on the keep list, otherwise its orphaned \
         ACE is never swept; live={live_after:?} dead={dead_profile}"
    );
    assert!(
        live_after.contains(&own),
        "adding a dead session must not knock the running session off the keep list"
    );

    // 後始末が**効いたことを読み返す**（「戻した」ではなく「戻っている」を測る）。
    drop(_forget);
    let tokens = session_profile::ledger_session_tokens_for_test();
    assert!(
        !tokens.contains(&dead_token),
        "the measurement must take its own dead entry back out of the real ledger; tokens={tokens:?}"
    );

    // このプロセス自身のエントリも戻す。プロファイルは作っていない（`begin_session`は
    // 台帳と生存マーカーだけ）ので、落としても回収不能なものは生まれない。
    drop(_forget_own);
    let tokens = session_profile::ledger_session_tokens_for_test();
    assert!(
        !tokens.contains(&session_profile::session_token().to_string()),
        "the measurement must not leave its own session entry behind either; tokens={tokens:?}"
    );
}

/// **測定5**（`docs/STATUS.md`「サンドボックス周辺 #63」）: 走行中のセッションの
/// **遷移先ドメイン**の入れ物宛のACEも、掃除で剥がれない。死んだセッションのものは剥がれる。
///
/// # 壊れた状態を一文で
///
/// **別のセッションの起動が、走行中の遷移先ドメインから権限を剥がす**（BUG-053と同じ形）。
/// 残す側の名簿（`live_profile_names`）は台帳の`domains`を拾わず、実在の列挙から拾う側も
/// 持ち主の判定（`token_of_profile`）がこの族を解釈しなかったので、遷移先ドメインは
/// 生きていても名簿に載らなかった。掃除（`revoke_stale_appcontainer_aces`）は名簿に無い
/// package SIDを**持ち主を確かめずに全部**剥がす。
///
/// # 今は実害が無い——それでも部品の単位で固定する理由
///
/// 2026-09-30時点で、遷移先ドメインの**package SID宛**のACEは1本も付けていない（土台は全部
/// capability SID宛で、`domain_provision_tests`がそれを固定している）。付ける回が来た瞬間に
/// 症状になり、しかも壊れるのは剥がされた側（別のプロセスの子が`ACCESS_DENIED`で落ちる）
/// なので、剥がした側のログをいくら読んでも原因に辿り着けない。
///
/// # なぜ`#[ignore]`なのか
///
/// 測定3と同じ——実台帳へ自分のセッションとドメインのエントリを開く。**プロファイルは作らない**
/// （`record_domain_profile`は台帳だけを書き、SIDは`fabricate_subject`で名前から導くだけ）。
#[test]
#[ignore = "writes to the real session ledger; run via dev-elevated-run redirector-dll-sweep"]
fn the_sweep_leaves_a_running_sessions_transition_domain_alone() {
    use crate::tier2a::{domain_profile, session_profile};

    let dir = tempfile::tempdir().expect("temp dir");
    let dll = dir.path().join("harness_redirector.dll");
    std::fs::write(&dll, b"not really a dll").expect("write the probe file");

    // 許可側: 自分は走っていて、遷移先ドメインを1つ用意した（台帳だけ）。
    // **後始末はassertより先に武装する**（測定3と同じ理由）。
    let _ = session_session_name(&session_profile::begin_session());
    let _forget_own = scopeguard(|| {
        session_profile::forget_session_entry_for_test(session_profile::session_token())
    });
    let live_domain = session_profile::record_domain_profile("s63keep");
    // 禁止側: 走っていないセッションの遷移先ドメイン。台帳にも載せない（孤児の形）。
    let dead_domain = domain_profile::domain_profile_name_for("999999-1", "s63keep");

    let (live_sid, live_text) = fabricate_subject(&live_domain);
    let (dead_sid, dead_text) = fabricate_subject(&dead_domain);
    grant_ace_inheritable_access(&dll, live_sid.as_psid(), FsAccess::ReadExec)
        .expect("grant the running domain's ACE");
    grant_ace_inheritable_access(&dll, dead_sid.as_psid(), FsAccess::ReadExec)
        .expect("grant the dead domain's ACE");
    let _cleanup = scopeguard(|| {
        let _ = revoke_ace(&dll, live_sid.as_psid());
        let _ = revoke_ace(&dll, dead_sid.as_psid());
    });

    let before = package_sids_on(&dll);
    assert!(
        before.contains(&live_text) && before.contains(&dead_text),
        "the ACE reader must see both subjects before the sweep runs; saw {before:?}"
    );

    // `sweep_stale_redirector_dll_aces`と同じ2つを、同じ順で繋ぐ。
    let live = session_profile::live_profile_names();
    let removed =
        revoke_stale_appcontainer_aces(&dll, &live).expect("sweep the stale ACEs");

    let after = package_sids_on(&dll);
    assert!(
        after.contains(&live_text),
        "a running session's transition domain must keep its ACE, otherwise another session's \
         startup takes the permission away from a child that is still running (BUG-053); \
         live list={live:?} domain={live_domain} removed={removed:?}"
    );
    assert!(
        !after.contains(&dead_text),
        "a dead session's transition domain must still be swept; after={after:?}"
    );
}

/// `begin_session`の戻り値からプロファイル名を取り出す（失敗は測定の前提の崩壊なのでpanic）。
fn session_session_name(result: &Result<String, String>) -> String {
    match result {
        Ok(name) => name.clone(),
        Err(e) => panic!("could not open a session ledger entry for this process: {e}"),
    }
}

/// **測定4**: 掃除が見に行くのは、走っている実行ファイルの隣にあるDLLだけである。
///
/// # なぜこれを固定するのか
///
/// `redirector_dll_paths`は`current_exe`の隣を見て`exists()`で絞る。つまり
/// **別のビルドディレクトリ・別の配布先にあるコピーへ付いた孤立ACEは、この掃除では
/// 一度も訪れられない**。このリポジトリには実際にDLLのコピーが4つある
/// （`bin\`・`target\debug\`（x64/x86）・`target\i686-pc-windows-msvc\debug\`）。
///
/// 「掃除が届く範囲」を測定として固定しておかないと、測定1の結果が
/// 「Redirector DLLの窓は閉じている」と**射程を超えて**読まれる。
#[test]
fn the_sweep_only_ever_looks_next_to_the_running_executable() {
    let exe = std::env::current_exe().expect("current exe");
    let exe_dir = exe.parent().expect("exe has a parent").to_path_buf();

    let paths = redirector_dll_paths();
    for p in &paths {
        assert_eq!(
            p.parent(),
            Some(exe_dir.as_path()),
            "the sweep must only ever visit files next to the running executable; got {}",
            p.display()
        );
    }

    // 両側で書く: 隣に在れば列挙され、無ければ0件になる。
    // 0件になること自体が「別ディレクトリのコピーは掃かれない」の測定である。
    let sibling = exe_dir.join("harness_redirector.dll");
    assert_eq!(
        !paths.is_empty(),
        sibling.exists(),
        "redirector_dll_paths must be non-empty exactly when a redirector DLL sits next to the \
         running executable ({}); any copy in another directory is never swept",
        exe_dir.display()
    );
}

// ---------------------------------------------------------------------------
// [§22.9の前提] 宛先が宣言のcapabilityへ移ったこと
// ---------------------------------------------------------------------------

/// Redirector DLLの宛先を**このテストの中で発行し**、引き終わるまで記録が捨てられない
/// 区間の中で`f`を走らせる。`f`が受け取るのは発行の結果（DLLが隣に無い構成では空）。
///
/// # なぜ自分で発行するのか（[BUG-187](../../../../docs/bugs/BUG-187.md)）
///
/// 発行は実台帳への書込で、**DLL 1本ごとに別の更新**である（`issue_redirector_dll_capabilities`）。
/// 発行を同じバイナリの別のテスト（や別のワークツリーで同時に走る同じテスト）に任せて
/// 引くだけにすると、**x64だけ発行済みでx86がまだ**という途中の状態を読み得る。
/// その状態は、DLLの置き場が新しい（新しいビルド出力先・`harness fs prune`の後）ときに毎回訪れる。
///
/// # なぜ`SHARED_CAPABILITY_LOCK`の中で行うのか
///
/// 台帳から記録を**落とす**側もある。セッションの撤収（`end_session`・`gc_dead_sessions`）は、
/// 剥がし終えたDLLの宛先の名前を台帳から捨てる。発行してから引くまでの間にそれが走ると、
/// 引けない・次の発行で別の名前になる。製品の`preflight`は同じ理由で
/// 「引く・付ける・記録する」をこの錠の中で行っており（BUG-165）、撤収側もこの錠を握ってから
/// 捨てるので、ここで握っていれば区間の途中で捨てられない。
///
/// **守らないもの**: この錠を握らずに記録を落とす経路（`harness fs prune`・宣言の撤収）は止めない。
/// どちらも手で撃つ操作で、DLLの記録を落とすのはDLLそのものが消えたときなどに限られる。
fn with_redirector_dll_capabilities_issued<R>(
    f: impl FnOnce(&[(std::path::PathBuf, Result<String, String>)]) -> R,
) -> R {
    harness_grant_ledger::with_named_lock(
        crate::tier2a::session_profile::SHARED_CAPABILITY_LOCK,
        || f(&issue_redirector_dll_capabilities()),
    )
}

/// **発行してから引ける。** 引けないと、子のトークンへ積むものが無くなり注入が失敗する。
///
/// ここが測っているのは`preflight`（発行する側）と`launch`（引く側）が**同じ鍵**を使って
/// いることである。鍵は`(発行元, DLLのパス, access級)`の3つで、どれか1つでも綴りが
/// ずれると引けない——症状は`LoadLibraryW`のNULL＝**生成ごと失敗**で、
/// 「積み忘れ」と区別が付かない。**実機で踏んだ**（2026-09-19、`spawn-daemon`が5本落ちた）。
#[test]
fn the_dll_capability_can_be_looked_up_with_the_same_key_it_was_issued_with() {
    with_redirector_dll_capabilities_issued(|issued| {
        if issued.is_empty() {
            // DLLが隣に無いビルド構成では測れない（`redirector_dll_paths`は`exists()`で絞る）。
            return;
        }
        let looked_up = redirector_dll_capability_sids();
        assert_eq!(
            looked_up.len(),
            issued.iter().filter(|(_, r)| r.is_ok()).count(),
            "発行した鍵で引けない。子のトークンへ積むものが無くなり、注入が必ず失敗する"
        );
    });
}

/// **発行元はワークスペースではない**——同じDLLなら、どのワークスペースから呼んでも同じ宛先。
///
/// # 壊れた状態を一文で
///
/// **同じDLLにACEが際限なく積み上がる。** 鍵にワークスペースを入れると、ワークスペースごとに
/// 別の宛先が発行され、しかもワークスペースが使い捨て（テストの一時ディレクトリ）だと
/// **台帳の記録が消えた後もACEだけが残る**。掃除（`sweep_stale_redirector_dll_aces`）は
/// capability SIDを意図的に見ないので、誰も剥がさない。
///
/// **実際に踏んだ**（2026-09-19）。最初の実装はワークスペースを鍵に入れており、実機のE2Eを
/// 1周しただけで`harness_redirector.dll`に36本、x86側に4本の孤立ACEが積み上がった。
///
/// # 引く前に自分で発行する（[BUG-187](../../../../docs/bugs/BUG-187.md)）
///
/// 以前は発行を隣のテストに任せて引くだけだったので、DLLの置き場が新しいと
/// (1) 隣より先に引けば空で`return`し、**何も測らずに緑**になり、
/// (2) 隣の発行の途中（x64だけ発行済み）を引けば**1本対2本で落ちた**。
/// 理由と錠の範囲は[`with_redirector_dll_capabilities_issued`]のdoc。
#[test]
fn the_dll_capability_does_not_depend_on_which_workspace_asks_for_it() {
    with_redirector_dll_capabilities_issued(|issued| {
        if issued.is_empty() {
            // DLLが隣に無いビルド構成では測れない（`redirector_dll_paths`は`exists()`で絞る）。
            return;
        }
        // 前提: 発行そのものが通っている。ここで落ちるなら、測りたい性質の判定まで進んでいない。
        for (dll, result) in issued {
            if let Err(e) = result {
                panic!(
                    "前提が崩れている: {} の宛先を発行できなかった: {e}",
                    dll.display()
                );
            }
        }
        // 2回引いても同じ宛先が返る（発行元がプロセスやワークスペースで変わらないことの検算）。
        let first = redirector_dll_capability_sids();
        let second = redirector_dll_capability_sids();
        let text = |sids: &[crate::win_common::OwnedSid]| -> Vec<String> {
            sids.iter()
                .map(|s| crate::win_common::sid_to_string(s.as_psid()).expect("sid to string"))
                .collect()
        };
        assert_eq!(
            text(&first),
            text(&second),
            "同じDLLに対して違う宛先が返っている。ACEが際限なく積み上がる形である"
        );
        assert_eq!(
            first.len(),
            redirector_dll_paths().len(),
            "DLL 1本につき宛先は1つに収束していなければならない"
        );
    });
}

// ---------------------------------------------------------------------------
// [BUG-165] capability SID宛の孤立ACEを落とす口（`revoke_unrecorded_capability_aces`）。
//
// 上の測定2が固定しているのは「package SID側の掃除はcapability SIDを見ない」という
// **射程**であって、「capability SIDは誰も掃除しない」ではない。名前を失ったACEには
// どの撤収経路も届かないので、**残す側を名指しする**別の口をここで測る。
//
// 剥がす側だけを測ってはいけない（`B-35`）——「全部剥がす」実装でも緑になり、それは
// 毎起動でRedirector DLLが読めなくなる（＝子が1つも起きない）ことを意味する。
// だから残す側を3通り（台帳に名前がある／祖先traverse／harnessが書かない形）測る。
// ---------------------------------------------------------------------------

/// テスト用のcapability SIDを名前から作り、SID文字列も返す（`fabricate_subject`のcapability版）。
fn fabricate_capability(name: &str) -> (crate::win_common::OwnedSid, String) {
    let sid = capability_sid_from_name(name).expect("derive a capability SID from a name");
    let text = crate::win_common::sid_to_string(sid.as_psid()).expect("SID to string");
    (sid, text)
}

/// **禁止側**: 台帳のどの名前にも対応しないcapability SID宛のACEは落ちる。
///
/// これが[BUG-165](../../../../docs/bugs/BUG-165.md)が残した状態そのもので、
/// この口が無い間は`fs prune`も`fs revoke-workspace`も**定義から到達できなかった**
/// （どちらも台帳の名前を起点にSIDを導くため）。
#[test]
fn an_orphaned_capability_ace_is_taken_off_the_dll_when_no_ledger_name_claims_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let dll = dir.path().join("harness_redirector.dll");
    std::fs::write(&dll, b"not really a dll").expect("write the probe file");

    let (orphan, orphan_text) = fabricate_capability("harnessDecl00000000000000000000000000000165");
    grant_ace_inheritable_access(&dll, orphan.as_psid(), FsAccess::ReadExec)
        .expect("grant the orphaned capability ACE");
    let _cleanup = scopeguard(|| {
        let _ = revoke_ace(&dll, orphan.as_psid());
    });

    // 計器: 剥がす前に見えていること。0本は「剥がれた」と「最初から見えない」を同じ値で表す。
    assert!(
        capability_sid_aces(&dll)
            .expect("read the DACL")
            .iter()
            .any(|s| s.sid == orphan_text),
        "the reader must see the capability ACE before the sweep"
    );

    // 名簿は空にしない——空は「台帳を読めなかった」と区別が付かないので剥がさない側へ倒して
    // ある（下の`an_empty_keep_list_removes_nothing_...`）。実運用でも空にはならない：
    // 掃除は自分の名前を発行した**後**に走るので、必ず1件は載っている。
    let keep = vec!["harnessDecl0000000000000000000000000000f00d".to_string()];
    let removed = revoke_unrecorded_capability_aces(&dll, &keep).expect("sweep");

    assert_eq!(
        removed,
        vec![orphan_text],
        "名前を失ったACEが落ちていない。これが落ちないと、以後どの経路からも剥がせない"
    );
    assert!(
        sid_ace_mask(&dll, orphan.as_psid())
            .expect("readable")
            .is_none(),
        "戻り値ではなく実DACLで消えたことを確かめる（B-25）"
    );
}

/// **許可側**: 台帳に名前が残っている宛先は落ちない。
///
/// これが落ちると、**走っている他のセッションの足元を剥がす**（BUG-046の形）。
/// Redirector DLLの場合は「毎起動でDLLが読めない＝子が1つも起きない」になる。
#[test]
fn a_capability_ace_whose_name_is_still_in_the_ledger_survives_the_sweep() {
    let dir = tempfile::tempdir().expect("temp dir");
    let dll = dir.path().join("harness_redirector.dll");
    std::fs::write(&dll, b"not really a dll").expect("write the probe file");

    let live_name = "harnessDecl0000000000000000000000000000beef";
    let (live, live_text) = fabricate_capability(live_name);
    let (orphan, orphan_text) = fabricate_capability("harnessDecl0000000000000000000000000000dead");
    grant_ace_inheritable_access(&dll, live.as_psid(), FsAccess::ReadExec).expect("grant live");
    grant_ace_inheritable_access(&dll, orphan.as_psid(), FsAccess::ReadExec).expect("grant orphan");
    let _cleanup = scopeguard(|| {
        let _ = revoke_ace(&dll, live.as_psid());
        let _ = revoke_ace(&dll, orphan.as_psid());
    });

    let removed = revoke_unrecorded_capability_aces(&dll, &[live_name.to_string()]).expect("sweep");

    assert_eq!(
        removed,
        vec![orphan_text],
        "名簿に載っている宛先まで剥がしている（走行中のセッションから権限を奪う形）"
    );
    assert!(
        sid_ace_mask(&dll, live.as_psid())
            .expect("readable")
            .is_some(),
        "{live_text} は名簿に載っているのに実DACLから消えている"
    );
}

/// **許可側**: 祖先traverseの宛先は、名簿が空でも落ちない。
///
/// これは台帳の`entries`に載らない**well-knownの固定名**なので、名簿を台帳だけから
/// 作ると抜ける。抜けたまま剥がすと`C:\`のtraverse ACEと同じ宛先を落とすことになり、
/// [BUG-046](../../../../docs/bugs/BUG-046.md)をそのまま再現する。
#[test]
fn the_traverse_capability_survives_even_when_the_keep_list_is_empty() {
    let dir = tempfile::tempdir().expect("temp dir");
    let dll = dir.path().join("harness_redirector.dll");
    std::fs::write(&dll, b"not really a dll").expect("write the probe file");

    let cap = traverse_capability_sid().expect("derive the traverse capability SID");
    grant_ace_inheritable_access(&dll, cap.as_psid(), FsAccess::ReadExec)
        .expect("grant the traverse capability ACE");
    let _cleanup = scopeguard(|| {
        let _ = revoke_ace(&dll, cap.as_psid());
    });

    // 名簿は空にしない（空だと無条件で剥がさないので、traverseが残る理由が2つになる）。
    let keep = vec!["harnessDecl0000000000000000000000000000f00d".to_string()];
    let removed = revoke_unrecorded_capability_aces(&dll, &keep).expect("sweep");

    assert!(
        removed.is_empty(),
        "祖先traverseの宛先を剥がそうとしている: {removed:?}"
    );
    assert!(
        sid_ace_mask(&dll, cap.as_psid())
            .expect("readable")
            .is_some(),
        "traverse capabilityのACEが実DACLから消えている"
    );
}

/// **許可側**: harnessが書かない形のACEには手を出さない（マスクの**完全一致**、`B-25`）。
///
/// 部分集合（AND）判定にすると`SYNCHRONIZE`を持つだけの無関係なACEまで拾う。
/// このパスにはharness以外が書いたACEが載り得るし、載っていてよい。
#[test]
fn a_capability_ace_that_harness_would_never_write_is_left_alone() {
    let dir = tempfile::tempdir().expect("temp dir");
    let dll = dir.path().join("harness_redirector.dll");
    std::fs::write(&dll, b"not really a dll").expect("write the probe file");

    let (foreign, foreign_text) = fabricate_capability("someOtherAppsCapability165");
    // harnessが書くどのFsAccessとも違うマスク（`WRITE_DAC`単体）。
    grant_ace_mask(
        &dll,
        foreign.as_psid(),
        0x0004_0000, // WRITE_DAC 単体。harnessはどのFsAccessでもこの形を書かない。
        windows::Win32::Security::ACE_FLAGS(0),
    )
    .expect("grant a mask harness never writes");
    let _cleanup = scopeguard(|| {
        let _ = revoke_ace(&dll, foreign.as_psid());
    });

    // 名簿は空にしない（空だと無条件で剥がさないので、残る理由が2つになる）。
    let keep = vec!["harnessDecl0000000000000000000000000000f00d".to_string()];
    let removed = revoke_unrecorded_capability_aces(&dll, &keep).expect("sweep");

    assert!(
        removed.is_empty(),
        "harnessが書かない形のACEを剥がしている（{foreign_text}）: {removed:?}"
    );
}

/// **fail-closed**: 名簿が空なら1本も剥がさない。
///
/// # なぜ「導出に失敗したら止める」ではなくここを測るのか
///
/// 当初は「名簿の名前をSIDへ導出できなければ止める」を測ろうとしたが、
/// **`DeriveCapabilitySidsFromName`は入力を1つも拒まない**——実測で空文字列・空白入り・
/// 日本語・`\0`入り・300文字・`*`のすべてが`Ok`を返した（名前をハッシュするだけの関数である）。
/// つまりその分岐は入力からは到達できず、テストで歯を確かめられない。
///
/// **危険は別の場所にあった。** 台帳の読み取りが失敗すると`Ledger::load`は
/// 空の台帳へ倒れる（`.json.bak`も読めなかった場合）。すると名簿が空になり、
/// **載っているACEが全部「名前を失った」ように見える**——生きている宛先を全部剥がす。
/// 空は「残すものが無い」と「台帳を読めなかった」を同じ値で表すので、
/// ここは開ける側へ倒せない（`B-09`/`B-10`）。
#[test]
fn an_empty_keep_list_removes_nothing_because_it_cannot_be_told_from_an_unreadable_ledger() {
    let dir = tempfile::tempdir().expect("temp dir");
    let dll = dir.path().join("harness_redirector.dll");
    std::fs::write(&dll, b"not really a dll").expect("write the probe file");

    let (orphan, _) = fabricate_capability("harnessDecl00000000000000000000000000000abc");
    grant_ace_inheritable_access(&dll, orphan.as_psid(), FsAccess::ReadExec).expect("grant orphan");
    let _cleanup = scopeguard(|| {
        let _ = revoke_ace(&dll, orphan.as_psid());
    });

    let removed = revoke_unrecorded_capability_aces(&dll, &[]).expect("sweep");

    assert!(
        removed.is_empty(),
        "名簿が空の状態で剥がしている（台帳が読めなかっただけかもしれない）: {removed:?}"
    );
    assert!(
        sid_ace_mask(&dll, orphan.as_psid())
            .expect("readable")
            .is_some(),
        "名簿が空の状態でACEを剥がしている"
    );
}

/// **対の相手**: capability側の掃除はpackage SID宛のACEを見ない
/// （測定2「package側はcapability SIDを見ない」の裏返し）。
///
/// 2つの口が互いの担当へ手を出さないことを両向きで固定しておかないと、
/// 片方を直した人がもう片方の射程を広げてしまう。
#[test]
fn the_capability_sweep_does_not_touch_package_sid_aces() {
    let dir = tempfile::tempdir().expect("temp dir");
    let dll = dir.path().join("harness_redirector.dll");
    std::fs::write(&dll, b"not really a dll").expect("write the probe file");

    let (dead_sid, dead_text) = fabricate_subject("harness.shell.sandbox.9004-44444444");
    grant_ace_inheritable_access(&dll, dead_sid.as_psid(), FsAccess::ReadExec)
        .expect("grant the package SID ACE");
    let _cleanup = scopeguard(|| {
        let _ = revoke_ace(&dll, dead_sid.as_psid());
    });

    // 計器: package側の読み手には見えている。
    assert!(package_sids_on(&dll).contains(&dead_text));

    let keep = vec!["harnessDecl0000000000000000000000000000f00d".to_string()];
    let removed = revoke_unrecorded_capability_aces(&dll, &keep).expect("sweep");

    assert!(
        removed.is_empty(),
        "capability側の掃除がpackage SIDを剥がしている: {removed:?}"
    );
    assert!(
        sid_ace_mask(&dll, dead_sid.as_psid())
            .expect("readable")
            .is_some(),
        "package SID宛のACEが消えている。担当は`revoke_stale_appcontainer_aces`である"
    );
}
