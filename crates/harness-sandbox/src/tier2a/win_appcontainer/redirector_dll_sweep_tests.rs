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
//! **3だけは実台帳**（`%APPDATA%\harness\config\appcontainer-session-ledger.json`）へ
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

/// **測定2**: capability SID宛のACEは掃除の視野に入らない（`APPCONTAINER_SID_PREFIX`の意図）。
///
/// これは欠陥ではなく**限界**である。祖先traverse（D-37）とworkspace（D-54）の宛先SIDは
/// capability SIDで、`fs revoke-traverse`／`fs revoke-workspace`という名前の付いた扉が
/// 担当する。ここで巻き込むと`C:\`のtraverse ACEを純減させる（BUG-046）。
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

/// **発行してから引ける。** 引けないと、子のトークンへ積むものが無くなり注入が失敗する。
///
/// ここが測っているのは`preflight`（発行する側）と`launch`（引く側）が**同じ鍵**を使って
/// いることである。鍵は`(発行元, DLLのパス, access級)`の3つで、どれか1つでも綴りが
/// ずれると引けない——症状は`LoadLibraryW`のNULL＝**生成ごと失敗**で、
/// 「積み忘れ」と区別が付かない。**実機で踏んだ**（2026-09-19、`spawn-daemon`が5本落ちた）。
#[test]
fn the_dll_capability_can_be_looked_up_with_the_same_key_it_was_issued_with() {
    let issued = issue_redirector_dll_capabilities();
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
#[test]
fn the_dll_capability_does_not_depend_on_which_workspace_asks_for_it() {
    let first = redirector_dll_capability_sids();
    if first.is_empty() {
        return;
    }
    // 2回引いても同じ宛先が返る（発行元がプロセスやワークスペースで変わらないことの検算）。
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
}
