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
//! # 5〜6は受け入れ条件ではなく、**§22.3.1の未測定を埋める測定**である
//!
//! `plans/DESIGN-MAC-DOMAIN.md`の§22.3.1は「差分層で移行したのはin-process側だけ。
//! **昇格側を通らない見込みでそうしたが、通らないことは確かめていない**」と書いている。
//! 1〜4はどれもその問いに触れていない——DACLに正しいACEが載っていることは、
//! **それを誰が書いたか**を何も言わないからである（昇格側が書いても同じDACLになる）。
//!
//! | # | 測るもの | このファイルのテスト |
//! |---|---|---|
//! | 5 | 付与そのものが昇格側へ委譲されていない | `granting_the_cow_diff_layer_never_reaches_the_elevated_path` |
//! | 6 | 祖先traverseが昇格を要求するかは**置き場が決める**（本番の置き場は今どちら側か） | `where_the_diff_layer_sits_decides_whether_the_ancestor_traverse_demands_elevation` |
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

// =============================================================================
// 測定3（§22.3.1の未測定）: **差分層への付与は、本当に昇格側を通らないのか**
// =============================================================================
//
// 昇格が起こり得る経路は2つあり、**別々の計器で見ないと片方が黙って通る**。
//
// | # | 経路 | 引き金 | 見る計器 |
// |---|---|---|---|
// | 1 | 付与そのものを昇格側（privhelper）へ委譲する | 本体（非管理者）で`ACCESS_DENIED`になった対象 | `grant_audit`の付与要求レジストリ（`origin.delegated`） |
// | 2 | 祖先traverseが足りず、その解消を昇格側へ回す | 差分層の**親**のチェーンにtraverse ACEが欠けている | `traverse-grant-ledger.json`の前後差 |
//
// **経路1に差分層が入らないことは実装から読める**（`needs_elevation`へ積むのは`--fs-allow`の
// ループの中だけで、差分層は`grant_ace_inheritable_rw`のin-process呼び出しである）。
// **だが読んだだけでは測定ではない**（`plans/etw-spike/RESULTS.md`§21.4）ので、絞り口の記録で
// 実際に確かめる。経路2は置き場で決まるので、下の`where_the_diff_layer_sits_...`が担当する。

/// traverse台帳の中身を、**件数ではなく`(パス, 付与時刻)`の組**で控える。
///
/// **件数だけを見ると、既に載っているノードへの再付与を見逃す**——`record_traverse_grant`は
/// 同じパスなら時刻だけを上書きするので、件数は動かない。§S38-5・§S39-7は件数で見ており、
/// そこは「新しいノードが増えなかった」までしか言えていない。ここが1バイトも動かないことを
/// 言えて初めて「経路2は1度も走っていない」と書ける。
fn traverse_ledger_snapshot() -> Vec<(String, u64)> {
    let mut rows: Vec<(String, u64)> = crate::tier2a::traverse_ledger::load_traverse_ledger()
        .entries
        .into_iter()
        .map(|e| (e.path, e.granted_at_unix_secs))
        .collect();
    rows.sort();
    rows
}

/// 祖先traverseチェーン1本を、**実DACLとtraverse台帳の2つ**で読んだ結果。
///
/// この2つは互いに独立な源から来る——片方はOSが持つ実物、もう片方は`%APPDATA%`のJSONである。
/// **「足りている」だけでは、それが一度昇格して払った結果なのかそもそも要らなかったのかを
/// 書き分けられない**ので、台帳を重ねて初めて判定になる。
///
/// **3つ目の値（その根が実際に使われた実績＝配下の差分層の件数）はここには入らない。**
/// 呼び出し側が別に読んで印字する——チェーンの性質ではないうえ、`preview_traverse_chain`が
/// 持っていない値をこの型へ混ぜると、読み手が「同じ計器の出力」と受け取るためである。
#[derive(Debug)]
struct ChainVerdict {
    /// 全ノードが`FILE_TRAVERSE|FILE_READ_ATTRIBUTES`を持つ（＝`preflight`は昇格を要求しない）。
    sufficient: bool,
    /// ACEが在り、**かつ台帳が「harnessが付与した」と記録している**ノード。
    recorded: Vec<std::path::PathBuf>,
    /// ACEは在るが台帳に無いノード（＝harness以外の由来。ここは「そもそも要らなかった」側）。
    unrecorded: Vec<std::path::PathBuf>,
    /// ACEが無いノード（＝ここへ差分層を置くと`preflight`が昇格を要求する）。
    missing: Vec<std::path::PathBuf>,
    /// **台帳は記録しているのにACEが無い**ノード。台帳は撤収の索引なので、ここが空でないと
    /// 「誰が払ったか」の判定そのものが台帳を信用できなくなる。
    recorded_but_gone: Vec<std::path::PathBuf>,
}

/// [`ChainVerdict`]を作りながら、1行1ノードで印字する。
///
/// **印字を伴うのは意図である**——本流はこの出力をそのまま測定記録へ写す。
/// マスクを生で出すのは、`already_sufficient`の真偽値だけだと「何が足りないのか」が
/// 記録に残らないためである（`preview_traverse_chain`が既に持っているものを読むだけで、
/// 判定は新設しない）。
fn classify_chain(label: &str, target: &std::path::Path, sid: PSID) -> ChainVerdict {
    let ledger = crate::tier2a::traverse_ledger::load_traverse_ledger();
    let mut verdict = ChainVerdict {
        sufficient: true,
        recorded: Vec::new(),
        unrecorded: Vec::new(),
        missing: Vec::new(),
        recorded_but_gone: Vec::new(),
    };
    eprintln!("--- traverse chain [{label}]: {} ---", target.display());
    for node in preview_traverse_chain(target, sid) {
        let recorded = crate::tier2a::traverse_ledger::is_recorded(&node.path, &ledger);
        eprintln!(
            "  {:<4} {:<7} mask={:>10} {}",
            if node.already_sufficient {
                "ACE"
            } else {
                "MISS"
            },
            if recorded { "ledger" } else { "-" },
            node.existing_mask
                .map(|m| format!("{m:#010x}"))
                .unwrap_or_else(|| "(none)".to_string()),
            node.path.display()
        );
        match (node.already_sufficient, recorded) {
            (true, true) => verdict.recorded.push(node.path),
            (true, false) => verdict.unrecorded.push(node.path),
            (false, true) => {
                verdict.sufficient = false;
                verdict.recorded_but_gone.push(node.path.clone());
                verdict.missing.push(node.path);
            }
            (false, false) => {
                verdict.sufficient = false;
                verdict.missing.push(node.path);
            }
        }
    }
    verdict
}

/// **測定3-a**: 差分層のACEを書いたのは**このプロセス自身**であって、昇格側ではない。
///
/// # 壊れた状態を一文で
///
/// **差分層への付与が privhelper（昇格）へ委譲されており、`--sandbox tier2a-cow`を使うたびに
/// UACが出る／出ないがマシンの状態次第で変わる。** §22.3.1はそうなっていない「見込み」で
/// 実装したと自ら書いているので、ここはその見込みを測る。
///
/// # 突き合わせる2つは、どこまで遡ると同じ値になるか
///
/// - **実物（DACL）**と**絞り口の記録（`grant_audit`）**は、どちらも
///   `preflight`の`grant_ace_inheritable_rw(diff_layer_dir, cap)`という**1つの呼び出し**から出る。
///   だから「その呼び出しが丸ごと消えた」は両方が捕まえるが、
///   **「同じACEを昇格側に書かせるようになった」はDACLでは区別が付かない**——
///   出来上がるDACLが同じだからである。捕まえるのは`origin.delegated`だけ。
/// - したがって**源より上流**（経路2＝祖先traverse）を捕まえる第3の値として、
///   **別ファイル・別コードパスが書く`traverse-grant-ledger.json`**を混ぜる。
///
/// # 対照（同じ回に両側を入れる）
///
/// - **成功するはずの腕**: 差分層にcapability宛ACEが実在する（付与そのものは起きている）
/// - **失敗するはずの腕**: 計器の較正——`grant_audit`へ「委譲した」を1件わざと積み、
///   レジストリがその値を**表現できる**ことを同じ回で見る。これが無いと、
///   計装が`HARNESS_GRANT_AUDIT=off`で死んでいる回でも「委譲は0件」が緑になる
/// - **ゲートの位置**: `preflight`が経路2を通らないのは「祖先が既に足りているから」である。
///   その前提（`C:\`のチェーンが足りている）を**測る前に**読んで固定する
/// - **台帳の「載っている」側**: `load_traverse_ledger`は**fail-open**で、`%APPDATA%`を
///   解決できない・ファイルが読めない・JSONが壊れているのどれでも空の台帳を黙って返す
///   （`harness-grant-ledger`の`load_unlocked`が`T::default()`）。空の台帳では
///   「載っていない」側の判定が全部自明に通るので、**同じ回に「載っている」側を1つ立てる**
///
/// # この仕込みで**実際に偽になり得るのはどれか**（結論を測った量へ合わせる）
///
/// 置き場を`C:\`直下に固定し、走らせる前に`C:\`の充足を確かめ、`preflight_cow`が
/// `passthrough`へ`&[]`を渡している以上、`missing_traverse`も`needs_elevation`も空で確定し、
/// **昇格の分岐（`preflight.rs:1081`）の入口にそもそも入らない**。だから:
///
/// | assert | 種別 |
/// |---|---|
/// | `grant_audit`が「委譲した」を表現できる | **較正**（自分で積んだ1件を読み返している） |
/// | traverse台帳が非空・`C:\`が「載っている」側に出る | **較正**（台帳の読みが生きている） |
/// | `C:\`のチェーンが足りている | **前提の固定**（足りていなければ走らせてはいけない） |
/// | 差分層にcapability宛ACEが実在する | **前提**（無ければ以下は「未付与」の別名） |
/// | 差分層のrootへの付与要求が**絞り口に載っている** | **これが載荷している1本** |
/// | 委譲が0件 | **見張り**。この仕込みでは偽になれない |
/// | traverse台帳が前後で完全一致 | **見張り**。同上 |
///
/// **見張りは将来の実装変更に対する番犬であって、今回の根拠ではない**——
/// `grant_ace_inheritable_rw`が昇格側へ回るよう変わった日に落ちる、という値である。
///
/// # だからこのテストが緑でも言えないこと
///
/// 「差分層の付与は昇格側を通らない」とは書けない。言えるのは
/// **「`C:\`直下の置き場では昇格の分岐の入口に入らず、差分層のACE要求は自プロセスの
/// 絞り口に載った」**までである。本番の置き場について言えることは
/// [`where_the_diff_layer_sits_decides_whether_the_ancestor_traverse_demands_elevation`]の
/// **読取**だけが根拠になる。
#[test]
#[ignore = "real machine: creates directories under C:\\ and writes DACLs; run NON-elevated with --test-threads=1"]
fn granting_the_cow_diff_layer_never_reaches_the_elevated_path() {
    use crate::tier2a::grant_audit;

    // --- 計器の較正（失敗するはずの腕） ---
    //
    // レジストリが死んでいると、下の「委譲は0件」は対象について何も言わない。
    assert_ne!(
        grant_audit::mode(),
        grant_audit::Mode::Off,
        "HARNESS_GRANT_AUDIT=off で走っている。付与要求レジストリが1件も積まれないので、\
         このテストの『昇格側へ委譲していない』は対象の性質ではなく計器の沈黙になる"
    );
    let traverse_sid = traverse_capability_sid().expect("derive the traverse capability SID");
    let traverse_sid_text =
        crate::win_common::sid_to_string(traverse_sid.as_psid()).expect("render the traverse SID");
    // **実在しないパスを使う。** `note_delegated_grant`はプロセス内レジストリへ1行積むだけで
    // ファイルにもDACLにも触らないので、較正が実マシンに何も残さない。
    let calibration = std::path::PathBuf::from(format!(
        "C:\\harness-Tier2a-verify-elevation-calibration-{}",
        std::process::id()
    ));
    grant_audit::note_delegated_grant(&calibration, traverse_sid.as_psid());
    assert!(
        grant_audit::attempts_for(&traverse_sid_text)
            .iter()
            .any(|a| a.path == calibration && a.origin.delegated),
        "計器が『昇格側へ委譲した』という値を表現できていない。表現できない計器で\
         『委譲は0件だった』と読むと、いつでも緑になる"
    );

    // --- 台帳の計器が生きていること（**「載っている」側の対照**） ---
    //
    // `load_traverse_ledger`はfail-openで、空の台帳を黙って返し得る。空だと
    // (a) `classify_chain`の全ノードが`unrecorded`へ落ち、(b) 「台帳に無い」系の判定が
    // 自明に通り、(c) 前後差が`[] == []`で通る。**計器が死んだ回といちばん強い結論の回が
    // 見分けられなくなる**ので、対象を判定する前にここで固定する。
    let ledger_before = traverse_ledger_snapshot();
    assert!(
        !ledger_before.is_empty(),
        "traverse台帳が空で読めた。`load_traverse_ledger`は『ファイルが無い』『JSONが壊れている』\
         『%APPDATA%が引けない』のどれでも空を返す（fail-open）ので、空のまま先へ進むと\
         このテストの『台帳が前後で動かなかった』は対象の性質ではなく計器の沈黙になる"
    );

    // --- ゲートの位置を、測る前に読む ---
    let (ws, diff_guard) = make_roots("elev");
    let diff = diff_guard.path().to_path_buf();
    // 軸（置き場）が注文どおりであることの検算。ここがずれると祖先が1段増え、
    // 経路2が発火して測定の途中でUACが出る。
    assert_eq!(
        diff.parent(),
        Some(std::path::Path::new("C:\\")),
        "この測定は差分層の親が`C:\\`であることに依存している（既にtraverse台帳にある）。\
         親が別のディレクトリになっていると preflight は昇格を要求する"
    );
    let gate = classify_chain(
        "測定用の置き場（差分層の親）",
        std::path::Path::new("C:\\"),
        traverse_sid.as_psid(),
    );
    assert!(
        gate.sufficient,
        "祖先traverseが足りていない状態で走らせると、この測定は preflight ごと昇格を要求する\
         （UACが出る）。足りていない: {:?}",
        gate.missing
    );
    // **台帳を突き合わせる側の較正**。`C:\`はharnessが過去にtraverse ACEを付けたノードなので、
    // 台帳の読みが生きていれば必ず`recorded`側に出る。`unrecorded`側へ回っていたら、
    // 台帳が空か、照合の正規化（`is_recorded`）が壊れているかのどちらかである。
    assert!(
        gate.recorded
            .iter()
            .any(|p| p == std::path::Path::new("C:\\")),
        "`C:\\`が台帳の『載っている』側に出なかった。この台帳の読みでは NEVER-NEEDED\
         （＝昇格を1度も要していない）と『台帳が読めていない』が同じ形になるので、\
         ここが立たない回の判定は使えない。recorded={:?} / unrecorded={:?}",
        gate.recorded,
        gate.unrecorded
    );

    // --- 測定本体 ---
    let (_session, cap) = preflight_cow(ws.path(), &diff);
    let cap_text = crate::win_common::sid_to_string(cap.as_psid()).expect("render the diff SID");
    let canonical_ws = ws
        .path()
        .canonicalize()
        .unwrap_or_else(|_| ws.path().to_path_buf());
    // **ACEを剥がしてから台帳を落とす**（`workspace_capability::forget_capability`のdocが定める
    // 不変条件。逆順にすると宛先SIDを引けなくなり、撤収経路の無いACEが残る）。
    // 台帳まで落とすのは、この測定を**前後で中立**にするためである（§S39-6）。
    let _cleanup = scopeguard(|| {
        let _ = revoke_ace_recursive(&diff, cap.as_psid());
        let dropped = crate::tier2a::workspace_capability::forget_capability(&canonical_ws, "");
        eprintln!("cleanup: dropped {} capability ledger entries", dropped.len());
        crate::tier2a::workspace_ledger::remove_workspace_entry(&canonical_ws);
    });

    // 許可側（実物）: 付与そのものは起きている。これが無いと以下は全部「未付与」の別名になる。
    assert!(
        sid_ace_mask(&diff, cap.as_psid())
            .expect("the diff layer DACL must be readable")
            .is_some(),
        "the diff layer must carry an ACE for its capability SID before we can ask who wrote it"
    );

    // 経路1（委譲）: この宛先SIDへの付与要求は、**全部このプロセスの絞り口を通っている**。
    //
    // **この下の2本のうち載荷しているのは前者だけである**（doc の表）。差分層の要求が
    // 絞り口に載るかは実装次第で偽になり得るが、`delegated`が0件であることは
    // この仕込み（`C:\`直下・`passthrough`が空）では偽になれない——`note_delegated_grant`は
    // `preflight.rs:1146`＝昇格の分岐の中でしか呼ばれず、その分岐へは入らないからである。
    let attempts = grant_audit::attempts_for(&cap_text);
    for attempt in &attempts {
        eprintln!(
            "grant attempt: delegated={} origin={} path={}",
            attempt.origin.delegated,
            attempt.origin,
            attempt.path.display()
        );
    }
    assert!(
        attempts.iter().any(|a| a.path == diff),
        "差分層のrootへの付与が、このプロセスの付与要求レジストリに1件も無い。\
         『委譲していない』の根拠にしているのはこのレジストリなので、対象が載っていない回の\
         結果は読めない。記録された要求: {attempts:?}"
    );
    let delegated: Vec<&grant_audit::GrantAttempt> =
        attempts.iter().filter(|a| a.origin.delegated).collect();
    assert!(
        delegated.is_empty(),
        "差分層のACEは昇格側（privhelper）へ委譲されている。§22.3.1が『昇格側を通らない見込み』\
         としていた前提が偽で、CoW起動のたびにUACが出る条件が存在することになる: {delegated:?}"
    );

    // 経路2（祖先traverse）: 別ファイル・別コードパスが書く台帳が1バイトも動いていない。
    //
    // **これも見張りである**——上でゲート（`C:\`の充足）を固定したので`missing_traverse`は
    // 空で確定しており、この仕込みでは偽になれない。緑になったことを
    // 「経路2は走らない」と読まないこと。言えるのは**この置き場では入口に入らない**まで。
    let ledger_after = traverse_ledger_snapshot();
    assert_eq!(
        ledger_after, ledger_before,
        "traverse台帳が動いた＝`preflight`が祖先traverseの解消を昇格側へ回した（または\
         本体が管理者で直接付与した）。どちらでも『差分層の用意は昇格を通らない』は言えない"
    );
}

/// 差分層が置かれ得る場所1つぶん。**まだ根が作られていない候補も含む。**
#[derive(Debug)]
struct CowRootProbe {
    root: std::path::PathBuf,
    /// 製品の棚卸し（`cow_diff_layer_roots`）が返した＝**もう実在する**根。
    in_use: bool,
    /// D-81の規則（`plan_cow_diff_layer_root`）が、このボリューム上のワークスペースに対して
    /// 実際に選ぶ根か。`false`なら製品はここへ差分層を作らない（＝WOULD-ELEVATEが出ても
    /// 「いつか誰かが踏む」ではない）。
    chosen_by_d81: bool,
}

/// 差分層が置かれ得る場所を、**根が実在するかを問わず**全部並べる。
///
/// # なぜ`cow_diff_layer_roots()`だけでは足りないのか
///
/// あの列挙は別ボリュームの根を **`<vol>\.harness-cow`が実在するときだけ**足す
/// （`session_scope.rs:274`〜。`NotFound`は`unreachable`にも数えない）。つまり
/// **まだ根が作られていないボリューム＝D-81で次に使われる置き場**が1腕も立たず、
/// 「証拠が0件」が「そこでは起きない」に見える。**測りたい失敗（昇格を要求する置き場）が
/// 器の視野の外で起きる形**なので、論理ドライブ全部について候補を立てる。
///
/// # 綴りも規則も自前で持たない（`B-05`）
///
/// - 根の名前は`PER_VOLUME_COW_DIRNAME`——`cow_diff_layer_roots`が同じ結合で組む定数そのもの
/// - D-81がそこを選ぶかは`plan_cow_diff_layer_root`に聞く。**製品の規則そのもの**であり、
///   純関数なので**実在しないパスにも撃てる**（Win32もFSも触らない）
/// - 「リモートかどうか採れなかったらリモート扱い」も、製品
///   （`cow_diff_layer_root_for_workspace`の`unwrap_or(true)`）と同じ倒し方に揃える
///
/// 返り値の2つ目は`cow_diff_layer_roots`が数えた到達できないボリュームの件数
/// （呼び出し側が0であることを確かめる。0でなければ、下の「ACEが無い」は
/// **本当に無い**のか**読めなかっただけ**なのかが混ざる）。
fn cow_root_probes() -> (Vec<CowRootProbe>, usize) {
    use crate::session_scope::{
        cow_diff_layer_roots, cow_profile_diff_layer_root, plan_cow_diff_layer_root,
        CowDiffLayerRootPlan, PER_VOLUME_COW_DIRNAME,
    };

    /// 同じ根を2度並べない。既に在れば`chosen_by_d81`だけを強い側（true）へ寄せる
    /// ——同じ根に複数の由来があるとき、「D-81が選ぶ」を後から`false`で消さないため。
    fn push(
        probes: &mut Vec<CowRootProbe>,
        already_created: &[std::path::PathBuf],
        root: std::path::PathBuf,
        chosen_by_d81: bool,
    ) {
        if let Some(existing) = probes.iter_mut().find(|p| p.root == root) {
            existing.chosen_by_d81 |= chosen_by_d81;
            return;
        }
        let in_use = already_created.iter().any(|r| r == &root);
        probes.push(CowRootProbe {
            root,
            in_use,
            chosen_by_d81,
        });
    }

    let (in_use, unreachable) = cow_diff_layer_roots();
    let profile_root = cow_profile_diff_layer_root()
        .expect("%LOCALAPPDATA% must resolve; every CoW root is derived from it");
    let profile_volume = crate::win_common::volume_mount_point_of(&profile_root)
        .expect("the volume that holds %LOCALAPPDATA% must be readable");
    let mut probes: Vec<CowRootProbe> = Vec::new();

    // ① プロファイル配下の根。ワークスペースがプロファイルと同じボリュームにあるとき
    //    D-81が選ぶ側で、`cow_diff_layer_roots`も無条件に返す。
    push(&mut probes, &in_use, profile_root, true);

    // ② 各論理ドライブの`<vol>\.harness-cow`。**実在を問わない。**
    #[cfg(windows)]
    for drive in crate::win_common::logical_drive_roots() {
        let capability = crate::win_common::volume_capability(&drive);
        let is_remote = capability.as_ref().map(|c| c.is_remote).unwrap_or(true);
        let synthetic_workspace = drive.join("harness-elevation-probe-workspace");
        let plan =
            plan_cow_diff_layer_root(&synthetic_workspace, &drive, &profile_volume, is_remote);
        let chosen = matches!(plan, Ok(CowDiffLayerRootPlan::PerVolume(_)));
        eprintln!(
            "volume {} : fs={} remote={is_remote} chosen_by_D81={chosen} -- {}",
            drive.display(),
            capability
                .as_ref()
                .map(|c| c.filesystem.as_str())
                .unwrap_or("(unreadable)"),
            match &plan {
                Ok(CowDiffLayerRootPlan::PerVolume(root)) => format!("root {}", root.display()),
                Ok(CowDiffLayerRootPlan::Profile) =>
                    "same volume as %LOCALAPPDATA%; D-81 keeps the diff area in the profile root"
                        .to_string(),
                Ok(CowDiffLayerRootPlan::ProfileFallback(reason)) =>
                    format!("falls back to the profile root: {reason}"),
                Err(e) => format!("D-81 refuses this volume: {e}"),
            }
        );
        // **選ばれない側も腕にする。** 「選ばれないから読まなくてよい」にすると、
        // D-81の規則が変わった日に黙って射程から外れる。
        push(
            &mut probes,
            &in_use,
            drive.join(PER_VOLUME_COW_DIRNAME),
            chosen,
        );
    }

    // ③ 製品の棚卸しが返したのに①②で拾えていない根（根の種類が増えたときの取りこぼし防止）。
    for root in &in_use {
        push(&mut probes, &in_use, root.clone(), false);
    }

    (probes, unreachable)
}

/// **測定3-b**: 昇格を要求するかどうかを決めているのは**差分層の置き場**であって差分層ではない。
/// そのうえで、本番の置き場が**いまどちら側にいるか**を、実DACL・台帳・実在の3つで読む。
///
/// # 何のために要るか（3-aだけでは足りない理由）
///
/// 3-aは差分層を`C:\`直下に置いて測る。`C:\`のtraverseは既に払ってあるので、
/// **その回で「昇格が起きなかった」ことを本番へ外挿すると、置き場という軸を振らずに
/// 結論だけ広げたことになる**（§S38-5が「これは測定3ではない」と明記しているのと同じ線）。
///
/// # 「一度昇格して払った」と「そもそも要らない」の書き分け
///
/// | チェーンの読み | 何と言えるか |
/// |---|---|
/// | 全ノードにACEがあり、**台帳が記録している** | **PAID-ONCE**。harnessが過去に一度昇格して付与した。台帳を消した環境では崩れる |
/// | 全ノードにACEがあり、**台帳に無い** | **NEVER-NEEDED**。その到達権はharness以外の由来（既定のACL等）で、昇格を1度も要していない |
/// | ACEの無いノードがある | **WOULD-ELEVATE**。§22.3.1の見込みはこの置き場では成り立たない |
///
/// # 対照（両側を同じ回に入れる）
///
/// - **成功するはずの腕**: `C:\`直下（測定用の置き場）→ `sufficient`
/// - **失敗するはずの腕**: 1段入れ子にした親（このファイルの`make_roots`のdocが「一度踏んだ」と
///   書いている形）→ `sufficient`でないこと。**この腕が緑になったら、計器は「足りない」を
///   表現できておらず、上の判定は全部意味を失う**
/// - **台帳の「載っている」側**: `C:\`が台帳側に出ること。`load_traverse_ledger`はfail-openで
///   空を返し得るので、これが無いと**空の台帳＝全部NEVER-NEEDED**が最も強い結論の顔をする
///
/// # 掃く置き場（**まだ作られていない根も腕にする**）
///
/// [`cow_root_probes`]が並べる。`cow_diff_layer_roots()`だけを掃くと、別ボリュームの根は
/// **実在するときだけ**足されるので、**D-81で次に使われる置き場（まだ根が無いボリューム）が
/// 0腕**になり、証拠が0件であることが「そこでは起きない」に見える。
///
/// - **既に使われている置き場**（`in_use`）が`WOULD-ELEVATE`なら**赤にする**——
///   いま動いているCoWがUACを出す条件が在るということで、それが§22.3.1への答えになる
/// - **まだ根の無い置き場**が`WOULD-ELEVATE`なのは**読みであって失敗ではない**。
///   赤にせず、`VERDICT`行と最後の要約に残す
///
/// # 突き合わせ（源より上流を捕まえる第3の値）
///
/// 実DACLと台帳は独立に作られる（片方はOS、片方は`%APPDATA%`のJSON）。さらに
/// **その根の下に実際にいくつ差分層があるか**を数える——「使われた実績があるのに台帳に
/// 記録が無い」なら、その到達権はharnessが払ったものではない、と言い切れる。
///
/// # 実行しないもの（**ここが要点**）
///
/// **本番の置き場で`preflight`を走らせない。** 走らせれば白黒は付くが、足りていなければ
/// その場でUACが出る。承認ダイアログは人が押すものであり、測定から出してはならない
/// （`CLAUDE.md`）。だから**読取だけ**で、走らせたら何が起きるかを判定する。
#[test]
#[ignore = "real machine: reads the DACLs of the production CoW roots and creates two directories under C:\\"]
fn where_the_diff_layer_sits_decides_whether_the_ancestor_traverse_demands_elevation() {
    let traverse_sid = traverse_capability_sid().expect("derive the traverse capability SID");
    let ledger_before = traverse_ledger_snapshot();
    // **台帳の計器が生きていること。** `load_traverse_ledger`はfail-openで空を返し得るので、
    // 空のまま進むと下の`unrecorded`側が全部埋まり、**NEVER-NEEDED（昇格を1度も要していない、
    // という一番強い主張）が計器の沈黙と同じ形になる**。
    assert!(
        !ledger_before.is_empty(),
        "traverse台帳が空で読めた。空の台帳では全ノードが「台帳に無い」側へ落ちるので、\
         PAID-ONCE と NEVER-NEEDED の区別が付かない（どちらの読みも使えない）"
    );

    // --- 成功するはずの腕: 測定用の置き場 ---
    let flat = TestDirGuard::create("cow-elev-flat-diff");
    let flat_parent = flat
        .path()
        .parent()
        .expect("a directory under C:\\ has a parent")
        .to_path_buf();
    let flat_verdict = classify_chain(
        "成功対照: C:\\直下へ置いた差分層の親",
        &flat_parent,
        traverse_sid.as_psid(),
    );
    assert!(
        flat_verdict.sufficient,
        "成功対照が失敗した。`C:\\`のtraverseが無い機では、このファイルの他のテストも\
         走らせた瞬間に昇格を要求する: {:?}",
        flat_verdict.missing
    );
    // 台帳側の**「載っている」対照**。`C:\`はharnessが過去に付与したノードなので、
    // 台帳の読みが生きていればここに出る。出なければ下の PAID-ONCE / NEVER-NEEDED は読めない。
    assert!(
        flat_verdict
            .recorded
            .iter()
            .any(|p| p == std::path::Path::new("C:\\")),
        "`C:\\`が台帳の『載っている』側に出なかった。台帳が読めていないか、照合の正規化\
         （`is_recorded`）が壊れている。recorded={:?} / unrecorded={:?}",
        flat_verdict.recorded,
        flat_verdict.unrecorded
    );

    // --- 失敗するはずの腕: 1段入れ子（差分層の親が新しいディレクトリになる形） ---
    let nested_parent = TestDirGuard::create("cow-elev-nested-diff");
    let nested_verdict = classify_chain(
        "失敗対照: 入れ子にした差分層の親",
        nested_parent.path(),
        traverse_sid.as_psid(),
    );
    assert!(
        !nested_verdict.sufficient,
        "失敗対照が『足りている』になった。`C:\\`へのtraverse ACEは非継承で付けてあるので、\
         直下に作ったばかりのディレクトリが足りていることは無い。ここが緑になる計器では\
         『足りない』を1度も表現できず、本番の置き場の判定も信用できない"
    );
    // 台帳側も同じ向きを言うこと。**2つの計器が食い違ったら、どちらの読みも使えない。**
    assert!(
        !crate::tier2a::traverse_ledger::is_recorded_traverse_node(nested_parent.path()),
        "いま作ったばかりのディレクトリを traverse台帳が「付与済み」と記録している。\
         台帳とDACLが食い違っており、本番の置き場について下す判定も信用できない"
    );
    assert!(
        nested_verdict.missing.contains(&nested_parent.path().to_path_buf()),
        "足りていないと出たノードが、いま作ったディレクトリ自身ではない: {:?}",
        nested_verdict.missing
    );

    // --- 本番の置き場（**読むだけ**） ---
    //
    // D-81でCoWの根は1つではない（プロファイル配下と、別ボリュームのルート直下）。
    // 列挙は`cow_root_probes`——**まだ根が作られていないボリュームも腕にする**
    // （`cow_diff_layer_roots`だけを掃くと、そこが0腕のまま「全部見た」に見える）。
    const PROBE_SESSION_ID: &str = "harness-elevation-probe-session";
    let (probes, unreachable) = cow_root_probes();
    eprintln!(
        "CoW diff layer placements: {} arms ({} already in use), {unreachable} unreachable volumes",
        probes.len(),
        probes.iter().filter(|p| p.in_use).count()
    );
    assert!(
        !probes.is_empty(),
        "置き場が1つも取れなかった。判定する対象が無い回の結果は『昇格は要らない』ではなく\
         『測っていない』である"
    );
    // **到達できないボリュームが0であることは、下の読みの前提である。** 0でなければ、
    // ある置き場の「ACEが無い」が**本当に無い**のか**読めなかっただけ**なのかが混ざる。
    assert_eq!(
        unreachable, 0,
        "到達できないボリュームがある。そこに差分層があっても読めないので、\
         『全部の置き場を見た』とは言えない"
    );
    // **視野の検算**（軸を1本足したら、その軸が実際に振れたことを見る）。論理ドライブが
    // 1つでも腕になっていなければ、そのボリュームの置き場は測っていない。
    #[cfg(windows)]
    for drive in crate::win_common::logical_drive_roots() {
        let expected = drive.join(crate::session_scope::PER_VOLUME_COW_DIRNAME);
        assert!(
            probes.iter().any(|p| p.root == expected),
            "ボリューム {} の置き場（{}）が腕になっていない。根が実在しないボリュームを\
             落としているなら、それは『昇格を要求する置き場』を器の外へ出したということである",
            drive.display(),
            expected.display()
        );
    }

    let mut verdicts: Vec<(std::path::PathBuf, &'static str)> = Vec::new();
    let mut in_use_would_elevate: Vec<std::path::PathBuf> = Vec::new();
    let mut not_yet_created_would_elevate: Vec<std::path::PathBuf> = Vec::new();
    for probe in &probes {
        let root = &probe.root;
        // **製品と同じ結合で当のパスを組む**（`B-05`）。`preflight`が祖先traverseを要求するのは
        // 差分層そのものではなく**その親**なので、組んでから親を取り出す。
        let diff = crate::session_scope::cow_diff_layer_dir_in(root, PROBE_SESSION_ID);
        let target = diff
            .parent()
            .expect("a diff layer under a root has a parent")
            .to_path_buf();
        assert_eq!(
            &target,
            root,
            "軸の確認: `preflight`がtraverseを要求する相手は根そのもののはずである。\
             ここがずれると、下で読んでいるチェーンは製品が見るチェーンではない"
        );

        // 第3の値: この根が**実際に使われた実績**。台帳に記録が無いのに実績があるなら、
        // その到達権はharnessが昇格して払ったものではない。
        let used = std::fs::read_dir(root)
            .map(|entries| entries.filter_map(Result::ok).count())
            .unwrap_or(0);
        eprintln!(
            "root {} : exists={} in_use={} chosen_by_D81={} existing diff layers={used}",
            root.display(),
            root.exists(),
            probe.in_use,
            probe.chosen_by_d81
        );

        // `preview_traverse_chain`は`ancestors()`を字面で辿り、`sid_ace_mask`の失敗を`None`へ
        // 落とすので、**実在しない根にも撃てる**（作らない・書かないので昇格は起きない）。
        let verdict = classify_chain(
            &format!("本番の置き場: {}", root.display()),
            &target,
            traverse_sid.as_psid(),
        );
        assert!(
            verdict.recorded_but_gone.is_empty(),
            "traverse台帳が「付与済み」と記録しているノードに、実際のACEが無い: {:?}。\
             台帳は撤収の索引であり、下の『誰が払ったか』の判定はこの台帳を信用している。\
             ここが崩れていると、PAID-ONCE と NEVER-NEEDED の区別そのものが成り立たない",
            verdict.recorded_but_gone
        );
        let label = if !verdict.sufficient {
            "WOULD-ELEVATE"
        } else if verdict.recorded.is_empty() {
            "NEVER-NEEDED"
        } else {
            "PAID-ONCE"
        };
        eprintln!(
            "VERDICT {label} {} (in_use={} chosen_by_D81={} / ledger-backed: {:?} / \
             not in ledger: {:?} / missing: {:?})",
            root.display(),
            probe.in_use,
            probe.chosen_by_d81,
            verdict.recorded,
            verdict.unrecorded,
            verdict.missing
        );
        verdicts.push((root.clone(), label));
        if label == "WOULD-ELEVATE" {
            if probe.in_use {
                in_use_would_elevate.push(root.clone());
            } else {
                not_yet_created_would_elevate.push(root.clone());
            }
        }
    }
    eprintln!("VERDICT SUMMARY: {verdicts:?}");
    // **まだ根の無い置き場のWOULD-ELEVATEは読みであって失敗ではない**ので、赤にせず数える。
    // ここが空でないなら、§22.3.1の「昇格側を通らない見込み」は
    // **そのボリュームで初めてCoWを起動する回**については偽である、と書ける。
    eprintln!(
        "WOULD-ELEVATE (root not created yet, {}): {:?} -- reading, not a failure: no diff layer \
         lives there today, so the elevation would happen the first time a workspace on that \
         volume starts CoW",
        not_yet_created_would_elevate.len(),
        not_yet_created_would_elevate
    );

    // **既に使われている置き場が足りていないのは失敗である**——いま動いているCoWが
    // UACを出す条件が在るということで、§22.3.1の見込みがその置き場で偽になる。
    assert!(
        in_use_would_elevate.is_empty(),
        "既に差分層が置かれている置き場で祖先traverseが足りていない: {in_use_would_elevate:?}。\
         この置き場へ差分層を作ると`preflight`は解消を昇格側へ回す（UACが出る）。\
         §22.3.1の『昇格側を通らない見込み』は、この置き場では偽である"
    );

    // --- 後始末の確認: 読取だけのはずが、何も書いていないこと ---
    assert_eq!(
        traverse_ledger_snapshot(),
        ledger_before,
        "この測定は読取だけのはずである。台帳が動いたなら、どこかで付与が走っている"
    );
}
