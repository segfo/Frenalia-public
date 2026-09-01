//! **CoW差分層の宛先SID移行（§22.3.2、`docs/STATUS.md`残課題#20）の受け入れ測定。**
//!
//! 差分層（`--sandbox tier2a-cow`が書込を退避するセッション専有フォルダ）へ付けるACEの宛先は、
//! セッションのpackage SIDから**差分層ごとのcapability SID**へ移った。移行が成立したと
//! 言える条件は3つあり、**そのすべてが「実マシンのDACL」で測られる**——台帳ではない。
//!
//! | # | 条件 | このファイルのテスト |
//! |---|---|---|
//! | 1 | 差分層のrootに**package SID宛ACEが0本**、capability宛が1本 | `the_diff_layer_is_owned_by_a_capability_and_not_by_the_session_package_sid` |
//! | 2 | セッション終了で**0本へ戻る**（付与と撤収が対） | `ending_the_session_takes_the_capability_ace_back_off_the_diff_layer` |
//! | 3 | GC（死んだセッションの回収）でも**0本へ戻る** | `the_gc_path_also_takes_the_capability_ace_off_the_diff_layer` |
//!
//! # なぜ台帳ではなく実DACLを読むのか
//!
//! 台帳は「付けたつもり」を記録しているだけで、**付与側の思い込みがそのまま両辺に乗る**
//! （`grant_audit`のモジュールdocが「台帳 vs 台帳では差が出ない」と書いているのと同じ理由）。
//! §22.3.0が定めた移行後の不変条件は「対象パスにセッションpackage SID宛ACEが0本であること」で、
//! これは実物を読まないと言えない。**しかもpackage SID宛が1本残っている状態は成功に見える**
//! ——新しいACEは正しく付いており、アクセスも通るからである。
//!
//! # ここで測っていないもの（`fs_allow_domain_acceptance_tests`との違い）
//!
//! **子プロセスから見た実I/Oは測っていない。** ここが見るのはDACLだけである。
//! 「capabilityを積んだ子だけが差分層へ書ける」は実機E2E（`tier2a_cow_commit_matrix`）と
//! `cow_containment_tests`が測る層で、そちらは子を起こす。**両方要る**——ACEが正しくても
//! トークンへ積み忘れれば書けず、逆にpackage SID宛が1本でも残っていれば積まなくても書ける。
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
