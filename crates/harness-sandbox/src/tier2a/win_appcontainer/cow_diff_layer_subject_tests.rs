//! **CoW差分層の宛先SID移行（§22.3.2、`docs/STATUS.md`残課題#20）の受け入れ測定。**
//!
//! 差分層（`--sandbox tier2a-cow`が書込を退避するセッション専有フォルダ）へ付けるACEの宛先は、
//! セッションのpackage SIDから**差分層ごとのcapability SID**へ移った。移行が成立したと
//! 言える条件は4つある。
//!
//! | # | 条件 | このファイルのテスト |
//! |---|---|---|
//! | 1 | 差分層のrootに**package SID宛ACEが0本**、capability宛が1本 | `the_diff_layer_is_owned_by_a_capability_and_not_by_the_session_package_sid` |
//! | 2 | セッション終了で**0本へ戻る**（付与と撤収が対） | `ending_the_session_takes_the_capability_ace_back_off_the_diff_layer` |
//! | 3 | GC（死んだセッションの回収）でも**0本へ戻る** | `the_gc_path_also_takes_the_capability_ace_off_the_diff_layer` |
//! | 4 | **セッションを切り替えても、前のセッションの宛先SIDが子へ持ち越されない**（測定4） | `switching_sessions_does_not_carry_the_previous_diff_layer_capability` |
//!
//! # なぜ台帳ではなく実DACLを読むのか
//!
//! 台帳は「付けたつもり」を記録しているだけで、**付与側の思い込みがそのまま両辺に乗る**
//! （`grant_audit`のモジュールdocが「台帳 vs 台帳では差が出ない」と書いているのと同じ理由）。
//! §22.3.0が定めた移行後の不変条件は「対象パスにセッションpackage SID宛ACEが0本であること」で、
//! これは実物を読まないと言えない。**しかもpackage SID宛が1本残っている状態は成功に見える**
//! ——新しいACEは正しく付いており、アクセスも通るからである。
//!
//! # 1〜3が測っていないもの（`fs_allow_domain_acceptance_tests`との違い）
//!
//! **1〜3は子プロセスから見た実I/Oを測っていない。** 見るのはDACLだけである。
//! 「capabilityを積んだ子だけが差分層へ書ける」は実機E2E（`tier2a_cow_commit_matrix`）と
//! `cow_containment_tests`が測る層で、そちらは子を起こす。**両方要る**——ACEが正しくても
//! トークンへ積み忘れれば書けず、逆にpackage SID宛が1本でも残っていれば積まなくても書ける。
//!
//! **4だけは子を起こす。** 切替の境界は**ACEではなくトークン**だからである——古い差分層の
//! ACEは意図的に残す（切り戻す可能性のあるものを回収可能に見せない）ので、DACLを何本読んでも
//! 「持ち越したか」は判定できない。
//!
//! # 実行（**昇格しないこと**）
//!
//! ```text
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture cow_diff_layer_subject
//! ```
//!
//! 昇格すると子のトークンが実運用とずれる（`B-08`）。対象を`C:\`直下に置いてあるのは、
//! 祖先が`C:\`だけで済み、**既にtraverse台帳にあるACEで足りる＝新しい昇格が要らない**ため
//! （`%TEMP%`を使うと`preflight`がプロファイル全階層へ恒久的なtraverse ACEを付ける）。

use super::test_support::{scopeguard, TestDirGuard};
use super::*;

/// 測定用のworkspaceと差分層を**どちらも`C:\`直下**に作る（昇格を避けるため）。
///
/// **`TestDirGuard`で戻す**——assertが落ちた瞬間に残留物が生まれる形にしない（`B-27`）。
///
/// # 差分層を入れ子にしないこと（**一度踏んだ**）
///
/// 最初は`C:\…-diff\<セッションID>`という2段にしていた。**それは昇格を誘発する**——
/// `preflight`は差分層の**祖先**のtraverseチェーンを解決しようとし、間に挟まった
/// `C:\…-diff`はtraverse台帳に無い新しいディレクトリなので、privhelper（昇格）を起こしに行く。
/// `C:\`直下に置けば祖先は`C:\`だけで、それは既に台帳にある。
///
/// 差分層のディレクトリ名がそのままセッションIDになる（`preflight`が`file_name()`から
/// 生存マーカーの名前を作る。読めないと起動を拒否する）ので、**pidを含む一意な名前**である
/// `TestDirGuard`の綴りがそのまま使える。
fn make_roots(tag: &str) -> (TestDirGuard, TestDirGuard) {
    let ws = TestDirGuard::create(&format!("cow-subject-{tag}-ws"));
    let diff = TestDirGuard::create(&format!("cow-subject-{tag}-diff"));
    (ws, diff)
}

/// `preflight`をCoWで通し、`(セッションpackage SID, 差分層のcapability SID)`を返す。
///
/// **失敗したら`panic!`する。** 「環境が整っていないので飛ばす」にすると、受け入れ条件を
/// 1度も測らないまま緑になる（`B-12`）。
fn preflight_cow(
    workspace: &std::path::Path,
    diff_layer: &std::path::Path,
) -> (OwnedContainerSid, crate::win_common::OwnedSid) {
    let outcome = preflight(
        workspace,
        &[],
        None,
        &WorkspaceWriteMode::Cow {
            diff_layer_dir: diff_layer.to_path_buf(),
        },
    )
    .unwrap_or_else(|e| {
        panic!(
            "preflight must succeed before this measurement means anything ({e:?}); \
             if the ancestor traverse is missing, run `harness fs grant-traverse C:\\` \
             as administrator once and re-run"
        )
    });
    for warning in &outcome.warnings {
        eprintln!("preflight warning: {warning}");
    }
    let canonical_ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.to_path_buf());
    // **引く側**（発行しない）で取る——本番の`launch.rs`と同じ引き方にしておかないと、
    // 「preflightが実際に発行したもの」ではなく「このテストが今作ったもの」を測ることになる。
    let cap = lookup_cow_diff_layer_capability_sid(&canonical_ws, diff_layer).unwrap_or_else(|| {
        panic!(
            "preflight must have issued a capability for the diff layer {}; \
             without it there is nothing to measure",
            diff_layer.display()
        )
    });
    (session_sid(), cap)
}

/// 条件1: 差分層のrootの宛先SIDは**capability SIDであり、package SIDではない**。
///
/// **対で測る**（`B-35`）。「package SID宛が0本」だけを見ると、**付与そのものが失敗していても
/// 緑になる**——ACEが1本も無い差分層は、確かにpackage SID宛を0本しか持たない。
/// だから「capability宛が実在すること」を同じテストで確かめる。
#[test]
#[ignore = "real machine: creates directories under C:\\ and writes DACLs"]
fn the_diff_layer_is_owned_by_a_capability_and_not_by_the_session_package_sid() {
    let (ws, diff_guard) = make_roots("owner");
    let diff = diff_guard.path().to_path_buf();
    let (session, cap) = preflight_cow(ws.path(), &diff);
    let _cleanup = scopeguard(|| {
        let _ = revoke_ace_recursive(&diff, cap.as_psid());
    });

    // 許可側: 移行先の宛先SIDのACEが実在する。
    let cap_mask = sid_ace_mask(&diff, cap.as_psid())
        .expect("the diff layer DACL must be readable");
    assert!(
        cap_mask.is_some(),
        "the diff layer must carry an ACE for its capability SID; \
         without it the CoW child cannot write anywhere (nothing was migrated)"
    );

    // 禁止側（§22.3.0の不変条件そのもの）: 共有されるSIDのACEは1本も無い。
    let package_mask = sid_ace_mask(&diff, session.as_psid())
        .expect("the diff layer DACL must be readable");
    assert_eq!(
        package_mask, None,
        "the session package SID must have no ACE on the diff layer: it is shared by every \
         process in this AppContainer, so one such ACE re-opens the diff layer to every domain \
         (DACL cannot express 'package SID AND capability SID' — parallel ALLOW entries are OR). \
         Note this state looks successful: the new ACE is correct and access works."
    );
}

/// 条件2: **セッション終了で0本へ戻る**（付与と撤収で1つ、`B-01`）。
///
/// `end_session`は`granted_capabilities`に記録された**導出済みの名前**からSIDを作り直して剥がす。
/// ここが落ちるということは、記録か撤収のどちらかが欠けているということで、差分層には
/// **どのコマンドでも剥がせないACE**が残る（BUG-101と同型）。
#[test]
#[ignore = "real machine: creates directories under C:\\ and writes DACLs"]
fn ending_the_session_takes_the_capability_ace_back_off_the_diff_layer() {
    let (ws, diff_guard) = make_roots("end");
    let diff = diff_guard.path().to_path_buf();
    let (_session, cap) = preflight_cow(ws.path(), &diff);
    let _cleanup = scopeguard(|| {
        let _ = revoke_ace_recursive(&diff, cap.as_psid());
    });

    // **まず付いていることを確かめる。** 付いていなければ、この後の「無い」は撤収が効いた
    // 証拠ではなく、ただの未付与である（`B-33`と同じ形の取り違え）。
    assert!(
        sid_ace_mask(&diff, cap.as_psid())
            .expect("readable")
            .is_some(),
        "the ACE must exist before we can claim that revoking it worked"
    );

    let outcome = crate::tier2a::session_profile::end_session(&revoke_session_grant);
    eprintln!("end_session: {:?}", outcome.summary());

    assert_eq!(
        sid_ace_mask(&diff, cap.as_psid()).expect("readable"),
        None,
        "ending the session must take the capability ACE off the diff layer; \
         leftovers: {:?}",
        outcome.blocked_paths
    );
}

/// 条件3: **GC（死んだセッションの回収）でも0本へ戻る。**
///
/// 強制終了（Ctrl+C・kill・電源断）では`end_session`が走らないので、実際に撤収するのは
/// **次の起動のGC**である。つまりこちらが本番の経路で、`end_session`は速く片付けるための
/// 最適化にすぎない（`run_agent.rs`のコメントが同じことを言っている）。
///
/// 死んだセッションを装うために、台帳へ**生存マーカーを持たないトークン**のエントリを直接置く。
#[test]
#[ignore = "real machine: creates directories under C:\\ and writes DACLs"]
fn the_gc_path_also_takes_the_capability_ace_off_the_diff_layer() {
    let (ws, diff_guard) = make_roots("gc");
    let diff = diff_guard.path().to_path_buf();
    let (_session, cap) = preflight_cow(ws.path(), &diff);
    let _cleanup = scopeguard(|| {
        let _ = revoke_ace_recursive(&diff, cap.as_psid());
    });
    assert!(
        sid_ace_mask(&diff, cap.as_psid())
            .expect("readable")
            .is_some(),
        "the ACE must exist before we can claim that the GC removed it"
    );

    // このプロセスのセッションは**生きている**（マーカーを握っている）ので、GCの対象には
    // ならない。だから「この差分層を付けた死んだセッション」を1件足して測る。現行セッションの
    // エントリには触らないので、実マシンに回収不能なプロファイルは残らない（テスト用の口のdoc）。
    let cap_name = crate::tier2a::workspace_capability::lookup_declaration_capability_name(
        &ws.path()
            .canonicalize()
            .unwrap_or_else(|_| ws.path().to_path_buf()),
        &diff,
        COW_DIFF_LAYER_ACCESS.label(),
    )
    .expect("preflight must have recorded the capability name");
    crate::tier2a::session_profile::add_dead_session_with_capability_for_test(&diff, &cap_name);

    let outcome =
        crate::tier2a::session_profile::gc_dead_sessions_reporting(&revoke_session_grant);
    eprintln!("gc: {:?}", outcome.summary());

    assert_eq!(
        sid_ace_mask(&diff, cap.as_psid()).expect("readable"),
        None,
        "the GC path must take the capability ACE off the diff layer too — this is the path \
         that actually runs after a forced termination; leftovers: {:?}",
        outcome.blocked_paths
    );
}

/// 子が「起動して、コマンドを解釈するところまでは進んだ」ことの印（`B-33`）。
const SWITCH_ALIVE_MARKER: &str = "HARNESS-SWITCH-CHILD-ALIVE";

/// **受け入れ条件4（測定4、`plans/HANDOFF-ISSUE-20-SUBJECT-MIGRATION.md`）**:
/// セッションを切り替えても、**前のセッションの差分層のcapability SIDは子へ持ち越されない**。
///
/// # 壊れた状態を一文で
///
/// **切替後の子のトークンに、切替前の差分層のcapability SIDが載ったままになっている。**
/// そうなると新しいセッションの子が**古いセッションの差分層を書き換えられる**。
///
/// # なぜDACLでは判定できないのか（このテストだけが子を起こす理由）
///
/// 古い差分層のACEは**意図的に残す**——切り戻す可能性のあるオーバーレイを回収可能に
/// 見せない方が安全側だからで、生存マーカーもプロセス終了まで保持される
/// （`session_scope::prepare_cow_diff_layer`の末尾）。つまり**古い差分層は「ACEが在るのに
/// 届いてはいけない」状態**であり、境界を張っているのはトークンだけである。
/// DACLを何本読んでもこの境界は見えない。
///
/// # 何を根拠に「持ち越していない」と言うか（**対で測る**、`B-35`）
///
/// - **許可側**: 切替後の子は**新しい**差分層へ書ける（書けなければCoWが丸ごと死んでいる）
/// - **禁止側**: 同じ子が**古い**差分層へ書けない（これが本題）
/// - **歯の対照**: 禁止側を測った時点で、古い差分層には**まだcapability宛ACEが在る**
///
/// **3つ目が要である。** 撤収が効きすぎて古い差分層のACEごと消えた世界でも禁止側は緑になり、
/// 「持ち越さない」という結論が**別の理由で**成り立ってしまう。
///
/// # 本番と同じ形で測る
///
/// - 切替は`session_scope::prepare_scope`を通す。**切替の副作用点は製品でもこの1関数**で、
///   入口6つ（`/sessions`・`/fork`・起動時ピッカー2種・`--fork-session`・セッションパネル）が
///   すべてここへ落ちる。自前で差分層を用意すると、測るものが製品と別になる
/// - 子は`test_support::spawn_in_workspace`で起こす。差分層のcapabilityを
///   **`diff_layer_dir`から引き直して積む**のは本番の`launch.rs`と同じ形で、
///   切替後の`ToolCtx`から組まれるトークンがこれである
///
/// # 差分層の根を`C:\`にしている理由
///
/// `ScopeTemplate::Cow`の根を`C:\`にすると`cow_diff_layer_dir_in`が`C:\<セッションID>`を返し、
/// **差分層の親が`C:\`**になる——traverse台帳に既にあるので**新しい昇格が要らない**。
/// 本番の`%LOCALAPPDATA%\harness\data\cow`は開発機の実データが入っている場所なので使わない。
#[test]
#[ignore = "real machine: creates directories under C:\\, writes DACLs, and spawns an AppContainer child; run NON-elevated with --test-threads=1"]
fn switching_sessions_does_not_carry_the_previous_diff_layer_capability() {
    use crate::session_scope::{prepare_scope, ScopeTemplate};

    let (ws_guard, old_guard) = make_roots("switch");
    // 切替先の差分層。**ディレクトリ名がそのままセッションIDになる**ので、`scope_for`へ渡す
    // 文字列と`file_name()`を一致させる（`preflight`は`file_name()`からIDを導出する）。
    let new_guard = TestDirGuard::create("cow-subject-switch-new");
    let workspace = ws_guard.path().to_path_buf();
    let old = old_guard.path().to_path_buf();
    let new = new_guard.path().to_path_buf();
    let new_id = new
        .file_name()
        .and_then(|n| n.to_str())
        .expect("the new diff layer directory name is the session id")
        .to_string();

    let (_session, old_cap) = preflight_cow(&workspace, &old);
    let canonical_ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.clone());

    // --- 開始状態が本物であることを先に測る ---
    //
    // 古い差分層にACEが無ければ、この後の「古い方へ届かない」は持ち越していない証拠ではなく、
    // ただの未付与である。
    assert!(
        sid_ace_mask(&old, old_cap.as_psid())
            .expect("the old diff layer DACL must be readable")
            .is_some(),
        "the previous session's diff layer must carry its capability ACE before we can ask \
         whether that capability is carried over"
    );

    // --- 切替（製品と同じ副作用点を通す） ---
    let template = ScopeTemplate::Cow {
        diff_layer_root: std::path::PathBuf::from("C:\\"),
    };
    let next = template.scope_for(&new_id);
    // **前提の確認**: 根を`C:\`にした狙い（差分層の親が`C:\`）が実際に成立しているか。
    // ここがずれると祖先traverseが増え、測定の途中で昇格を要求される。
    assert_eq!(
        next.cow_diff_layer_dir.as_deref(),
        Some(new.as_path()),
        "the scope template must map this session id onto the directory we prepared"
    );
    prepare_scope(&workspace, &next).expect("the session switch must prepare the new diff layer");

    let new_cap = lookup_cow_diff_layer_capability_sid(&canonical_ws, &new)
        .expect("the switch must issue a capability for the new diff layer");
    // **順序はACEを剥がしてから台帳を落とす。** 逆にすると宛先SIDを引けなくなり、撤収経路の
    // 無いACEが残る（`workspace_capability::forget_capability`のdocが定める不変条件）。
    //
    // 台帳まで落とすのは、**測定の前後で台帳の件数が戻ることを検証条件にしている**ためである
    // （`harness fs prune`頼みにすると、使い捨てワークスペースの記録が溜まり続ける）。
    // このファイルの他の3本はACEしか剥がしておらず、実行のたびに記録が残る——
    // それはこの測定が持ち込んだものではないので、ここでは直さずに記録へ書く。
    let _cleanup = scopeguard(|| {
        let _ = revoke_ace_recursive(&new, new_cap.as_psid());
        let _ = revoke_ace_recursive(&old, old_cap.as_psid());
        let dropped = crate::tier2a::workspace_capability::forget_capability(&canonical_ws, "");
        eprintln!("cleanup: dropped {} capability ledger entries", dropped.len());
        crate::tier2a::workspace_ledger::remove_workspace_entry(&canonical_ws);
    });

    let old_sid = crate::win_common::sid_to_string(old_cap.as_psid()).expect("render the old SID");
    let new_sid = crate::win_common::sid_to_string(new_cap.as_psid()).expect("render the new SID");
    assert_ne!(
        old_sid, new_sid,
        "the two sessions must derive different capability SIDs, otherwise this test cannot tell \
         them apart (the derivation would not include the session)"
    );
    assert!(
        sid_ace_mask(&new, new_cap.as_psid())
            .expect("the new diff layer DACL must be readable")
            .is_some(),
        "the switch must put a capability ACE on the new diff layer; without it the child has \
         nowhere to write and CoW is dead after every switch"
    );
    // **付与と撤収は対**（`B-01`）。切替で付けたACEが台帳へ記録されていなければ、
    // `end_session`/GCはこれを引けず、切替のたびに撤収経路の無いACEが1件ずつ残る。
    assert!(
        crate::tier2a::session_profile::granted_capability_paths_for_current_session()
            .iter()
            .any(|p| p == &new),
        "the ACE the switch just wrote must be recorded for this session, or nothing will ever \
         revoke it (BUG-101と同型)"
    );

    // --- 切替後の子を1つ起こす（本番の`launch.rs`と同じトークンの組み方） ---
    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    let ext_roots: Vec<std::path::PathBuf> = Vec::new();
    let command = format!(
        "$ErrorActionPreference = 'Stop'; \
         Write-Output '{SWITCH_ALIVE_MARKER}'; \
         try {{ New-Item -ItemType File -Path '{}' -Force | Out-Null; Write-Output 'NEW-OK' }} \
         catch {{ Write-Output ('NEW-ERR: ' + $_.Exception.Message) }}; \
         try {{ New-Item -ItemType File -Path '{}' -Force | Out-Null; Write-Output 'OLD-OK' }} \
         catch {{ Write-Output ('OLD-ERR: ' + $_.Exception.Message) }}",
        new.join("switch-probe.txt").display(),
        old.join("switch-probe.txt").display()
    );
    let child = super::test_support::spawn_in_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", &command],
        &workspace,
        &env,
        false,
        session_sid().as_psid(),
        NetworkCapability::Deny,
        Some(CowInject {
            workspace_root: &workspace,
            // **切替後の差分層**。本番はここへ`ctx.cow_diff_layer_dir`（`apply_scope`が
            // 書き換えた値）が入る。
            diff_layer_dir: &new,
            ext_capture_roots: &ext_roots,
        }),
    )
    .expect("spawn the post-switch child through the production path");
    let (stdout, stderr, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("read the child output");
    eprintln!("[post-switch child] exit={code}\nstdout={stdout}\nstderr={stderr}");

    // 「書けなかった」が「そもそも走らなかった」ではないことを確かめる（`B-33`）。
    assert!(
        stdout.contains(SWITCH_ALIVE_MARKER),
        "the post-switch child never started, so nothing below says anything about the access \
         check: {stdout}"
    );
    // 許可側。
    assert!(
        stdout.contains("NEW-OK"),
        "the child must be able to write into the diff layer of the session it switched to; \
         if this fails, CoW is dead after a switch: {stdout}"
    );
    // 禁止側（本題）。
    assert!(
        !stdout.contains("OLD-OK"),
        "the child wrote into the PREVIOUS session's diff layer -- the old capability was carried \
         over into the token, so switching sessions does not actually change what the child can \
         reach: {stdout}"
    );
    assert!(
        stdout.contains("OLD-ERR"),
        "the write into the previous diff layer must fail loudly (caught exception), not silently \
         produce nothing: {stdout}"
    );

    // --- 歯の対照: 禁止側が通ったのは「ACEが消えたから」ではない ---
    assert!(
        sid_ace_mask(&old, old_cap.as_psid())
            .expect("the old diff layer DACL must still be readable")
            .is_some(),
        "the previous session's capability ACE must STILL be on its diff layer at this point. \
         If it is gone, the child was denied because the ACE vanished (revocation ran too early), \
         not because the capability is absent from its token -- and this measurement proves nothing"
    );
}
