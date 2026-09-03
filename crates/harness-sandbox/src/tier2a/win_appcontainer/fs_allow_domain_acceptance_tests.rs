//! **§22.3.0.2（残課題#20の受け入れ条件）の実機測定**。
//!
//! `--fs-allow`で開けた穴の宛先SIDは、セッションのpackage SIDから**宣言ごとのcapability SID**へ
//! 移った。移行が成立したと言える条件は「拒否ACEを書いたか」ではなく
//! **許可を持たないドメインが存在するか**である（capability SID宛に`FILE_EXECUTE`のDENYを
//! 置いても素通りすることが実測されている。`plans/mac-spike/RESULTS.md` §S8）。
//!
//! ここで測るのは、**同じセッション（同じpackage SID）の中で、宣言capabilityを積んだ子と
//! 積まない子で到達可否が割れる**ことと、**子へ運ばれる宛先SIDが宣言と1対1である**ことである。
//!
//! | # | 条件 | このファイルのテスト |
//! |---|---|---|
//! | 1 | インタプリタ経由の実行が止まる | `only_the_declaring_domain_can_run_the_declared_script_through_an_interpreter` |
//! | 2 | 宣言したドメインだけがパスを見る | `only_the_declaring_domain_reaches_the_declared_path` |
//! | 3 | 運ばれる宛先SIDは**いま宣言した級**の1件だけ（分流N1） | `only_the_declared_access_class_is_carried_to_the_child` |
//! | 4 | **CoWのRO降格を通しても**、運ばれるのは実際に書いた級（測定1） | `the_cow_read_only_downgrade_carries_the_class_that_was_actually_written` |
//! | 5 | **宣言を2件持つ子**で、級が**割れている**とき（測定2・級の軸） | `each_declaration_carries_only_its_own_class_when_a_child_holds_two` |
//! | 6 | **宣言を2件持つ子**で、級が**同じ**とき（測定2・パスの軸。`--fs-allow A --fs-allow B`の既定形） | `two_same_class_declarations_keep_a_separate_subject_per_path` |
//!
//! 3・4・5・6は同じ「宣言と1対1」を**別の作られ方**で測る（`test-logic-rules`型C）。3は同じパスへ
//! 2つの級を発行した状態から、4は`--sandbox tier2a-cow`が級を降格した状態から、
//! 5と6は**別のパス2件を1回の`preflight`へまとめて渡した**状態から始める。
//! **5と6だけが軸として「宣言の件数」を振っている**（3と4はどちらも宣言1件で、振っているのは級である）。
//!
//! # なぜ5と6の**両方**が要るのか（片方だけでは宛先SIDの導出鍵の半分しか測れない）
//!
//! 宛先SIDの導出鍵は`(秘密, 畳み込み済みパス, access級)`である。5は級を`read`と`read_exec`へ
//! 割っているので、**鍵からパスが落ちても級が残っていれば2つの宣言は別のSIDのまま**になる
//! ——クロスパスの否定（「相手のパスに自分の宛先SID宛ACEが無い」）が、その世界でも緑で通る。
//! つまり5が緑でも「宣言と1対1」と言えるのは**級の軸についてだけ**である。
//!
//! 6は同じ級（`read_exec`）で別パス2件を渡す。`--fs-allow`が受ける接尾辞は`:rw`だけで、
//! 付けなければ`read_exec`になる（`harness-cli/src/cli/startup/sandbox.rs`）ので、
//! **`--fs-allow A --fs-allow B`という実運用でいちばん多い形はこちら**である。この形では
//! 2つの宣言を分けているものが**パスしか無い**ので、クロスパスの否定が初めてfalsifiableになる。
//!
//! 器（[`measure_two_declarations_in_one_preflight`]）は1つで、5と6は級の組を変えて呼ぶだけである。
//!
//! # 何を測っているか（測る対象を一文で書く）
//!
//! **壊れた状態＝「宣言していないドメインの子が、宣言されたパスへ届く」**である。
//! したがって見るのはACEの有無（台帳でも実DACLでもない）ではなく、
//! **子プロセスから見た実I/Oの成否**——付与が正しくてもトークンへcapabilityを積み忘れれば
//! 届かず、逆にpackage SID宛ACEが1本でも残っていれば積まなくても届く。ACLだけを見る
//! 単体テスト（`ace_grant_revoke_tests`）ではその両方が見えない。
//!
//! # 対で測る（`B-35`）
//!
//! 禁止側（宣言していないドメインが届かない）だけを見るテストは、**機構が効きすぎて
//! 全部拒否になっているときも緑になる**。だから許可側（宣言したドメインは届く）を必ず
//! 同じテストの中で測る。2つの子は**capabilityの集合だけが違い、他は同じ**にしてある。
//!
//! 加えて、禁止側では**子が起動したこと自体を印で確かめる**（`B-33`）。「印が出ない」は
//! 「拒否された」ではなく「そもそも走らなかった」でも起きるので、両者を区別できないと
//! 拒否側は常に緑になる。
//!
//! # 実行（**昇格しないこと**）
//!
//! ```text
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture fs_allow_domain_acceptance
//! ```
//!
//! 昇格すると子のトークンが実運用とずれる（`B-08`）。対象を`C:\`直下に置いてあるのは、
//! 祖先が`C:\`だけで済み、**既にtraverse台帳にあるACEで足りる＝新しい昇格が要らない**ため
//! （`%TEMP%`を使うと`preflight`がプロファイル全階層へ恒久的にtraverse ACEを付ける。
//! `docs/DEV-ENVIRONMENT.md`）。

use super::test_support::{scopeguard, TestDirGuard};
use super::*;
use crate::tier2a::workspace_ledger::WorkspaceMode;

/// 子が「起動して、コマンドを解釈するところまでは進んだ」ことの印（`B-33`: 他人の出力を
/// 印にしない。自分で出したこの文字列だけを根拠にする）。
const CHILD_ALIVE_MARKER: &str = "HARNESS-ACCEPT-CHILD-ALIVE";
/// 宣言したパスにあるスクリプトが**実際に走った**ことの印。
const PAYLOAD_RAN_MARKER: &str = "HARNESS-ACCEPT-PAYLOAD-RAN";
/// インタプリタがスクリプトへ到達できず、例外を捕まえたことの印。
const DENIED_MARKER: &str = "HARNESS-ACCEPT-DENIED";

/// このテスト群が使う宣言の**唯一の組み立て場所**（`--fs-allow <path>[:<級>]`と同じ形）。
///
/// 級だけを変えた宣言を作る口が2つ（[`read_declaration`]・[`read_write_declaration`]）あるが、
/// **`FsPassthrough`を組むのはここ1箇所**である（`docs/CODE-STRUCTURE-RULES.md`規則5。
/// `forced`や`scope`の既定を後から変えるとき、片方だけ直して「同じ形のつもりの別物」を
/// 2つ持つのを防ぐ）。
///
/// 級を**値で受ける**入口でもある——器を1つのまま級の組み合わせを振るには、
/// 級が呼び出し側から渡せなければならない。
///
/// # CLIのどの形がどの級になるか（測定がどれを選ぶかの根拠）
///
/// `--fs-allow`が受ける接尾辞は`:rw`だけで、**付けなかったときの既定は`read_exec`**である
/// （`harness-cli/src/cli/startup/sandbox.rs`の`strip_suffix(":rw")`分岐）。したがって
/// 実運用でいちばん多く作られる宣言は`read_exec`で、`--fs-allow A --fs-allow B`と2件並べると
/// **両方とも`read_exec`**になる。しかも`read_exec`と`read`は
/// **マスクが実行ビット1つ分しか違わない**（`acl_grant::fs_access_mask`）——
/// **見分けにくい対を選ぶのは意図的である**（差が小さいほど、級を取り違えたときに
/// マスクの検算をすり抜ける余地が大きい）。
fn declaration_of(path: &std::path::Path, access: FsAccess) -> FsPassthrough {
    FsPassthrough {
        path: path.to_path_buf(),
        access,
        forced: false,
        scope: GrantScope::Recursive,
    }
}

/// このテスト群が使う宣言（`--fs-allow <path>:read`と同じ形）。
fn read_declaration(path: &std::path::Path) -> FsPassthrough {
    declaration_of(path, FsAccess::Read)
}

/// 級から宛先SIDを引き直して文字列にする（**運ばれた値の突き合わせ相手**）。
///
/// **この値は運ばれた宛先SIDと同じ源**（`fs_allow_capability_sid`＝
/// `(秘密, 畳み込み済みパス, access級)`の導出）**から出る**ので、導出そのものが壊れると
/// 両方が同じだけずれて差が出ない（`plans/mac-spike/RESULTS.md` §S38-4で実測済み）。
/// だからこの対だけを根拠にせず、台帳・実DACL・実I/Oを併せて見ること。
///
/// **既に発行済みの級にだけ使うこと。** `fs_allow_capability_sid`は無ければその場で発行する
/// ので、「発行されていないはずの級」をこれで引くと**測る前に答えを書き換える**
/// （そちらは`lookup_declaration_capability_name`で読む）。
fn declared_subject_text(
    canonical_workspace: &std::path::Path,
    declared: &std::path::Path,
    access: FsAccess,
) -> String {
    let cap = fs_allow_capability_sid(canonical_workspace, declared, access)
        .expect("the capability for this access class must be derivable");
    crate::win_common::sid_to_string(cap.as_psid()).expect("render the capability SID")
}

/// `--fs-allow <path>:rw`と同じ形。**`--sandbox tier2a-cow`ではこれが`read`へ降格して書かれる**
/// （`preflight`のD-30分岐）。降格を通った後の姿を測るテストが使う。
fn read_write_declaration(path: &std::path::Path) -> FsPassthrough {
    declaration_of(path, FsAccess::ReadWrite)
}

/// `preflight`が**宣言1件について運んできたもの**。
///
/// **`GrantedPassthrough`をそのまま持つ**のは、宛先SID以外の欄（`writable`）も測る対象だから
/// である——1つの構造体の中で`writable`は**要求した級**、`subject_sid`は**実際に書いた級**を
/// 表しており、CoWの降格はその2つを意図的に食い違わせる。片方だけ持つと、その食い違いが
/// 意図どおりかを確かめる手段がテストから消える。
struct CarriedDeclaration {
    /// `preflight`が運んだエントリそのもの（本番の`launch.rs`が読むのと同じ値）。
    granted: harness_core::GrantedPassthrough,
    /// [`Self::granted`]の`subject_sid`をSIDへ戻したもの。実DACLの読取と到達性プローブが使う。
    subject: crate::win_common::OwnedSid,
}

/// `preflight`を1回通した結果のうち、このファイルの測定が使うもの。
struct GrantedDomain {
    session: OwnedContainerSid,
    ws_cap: crate::win_common::OwnedSid,
    /// **入力の宣言と同じ順・同じ件数**。1つの宣言に複数運ばれていても、ここには先頭だけが入る。
    carried: Vec<CarriedDeclaration>,
    /// `preflight`の戻り値そのもの。
    ///
    /// **「1つのパスへ何件運ばれたか」はここから数える。** 器の側で1件へ畳んでしまうと、
    /// 測定の核心（**載っているのが宣言した級の1件だけか**）が器の中で消える。
    outcome: PreflightOutcome,
}

impl GrantedDomain {
    /// 宣言を1件しか渡していない測定用の入口。
    ///
    /// **これは件数の判定ではない**（判定は各測定が`outcome`から行う。同じ事実を2箇所で
    /// 判定しない、`B-05`）。ここは「1件しか渡していないのだから1件のはず」という
    /// **呼び出し側の前提**を明示するだけである。
    fn only(&self) -> &CarriedDeclaration {
        assert_eq!(
            self.carried.len(),
            1,
            "only() is for measurements that pass a single declaration"
        );
        &self.carried[0]
    }

    /// そのパスへ`preflight`が運んだエントリを**全部**返す（畳まない）。
    fn carried_for(&self, path: &std::path::Path) -> Vec<&harness_core::GrantedPassthrough> {
        self.outcome
            .granted_passthrough
            .iter()
            .filter(|g| g.path == path)
            .collect()
    }
}

/// `preflight`を通して宣言capabilityを発行・付与し、[`GrantedDomain`]を返す。
///
/// # 宣言を**スライス**で受け、書込モードを引数で受ける理由
///
/// どちらも「同じ器へ別の作られ方を流す」ためである（`test-logic-rules`型C）。
///
/// - **`&[FsPassthrough]`**: 1つの子が宣言を2つ以上持つとき、**各パスへ運ばれるのが
///   宣言した級の1件だけか**を測るには、1回の`preflight`へ複数の宣言を渡せなければならない。
/// - **`write_mode`**: `--sandbox tier2a-cow`は`:rw`の宣言を`read`へ降格して書くので、
///   **降格を通った後に何が運ばれるか**を測るには同じ器へCoWを流せなければならない。
///
/// 器を2つ書くと、片方だけが仕様変更に追随しない（`docs/CODE-STRUCTURE-RULES.md`規則5）。
///
/// **失敗したら`panic!`する。** ここを「環境が整っていないので飛ばす」にすると、
/// 受け入れ条件を1度も測らないまま緑になる（`B-12`と同じ形の穴で、実際に
/// CoW封じ込めE2E 17件が0件マッチのまま緑だった前例がある）。
fn grant_and_collect_subjects(
    workspace: &std::path::Path,
    declarations: &[FsPassthrough],
    write_mode: &WorkspaceWriteMode,
) -> GrantedDomain {
    assert!(
        !declarations.is_empty(),
        "a run that declares nothing would go green without measuring anything (B-12)"
    );
    let outcome = preflight(workspace, declarations, None, write_mode).unwrap_or_else(|e| {
        panic!(
            "preflight must succeed before this measurement means anything ({e:?}); \
             if the ancestor traverse is missing, run `harness fs grant-traverse C:\\` \
             as administrator once (D10) and re-run"
        )
    });
    grant_job::wait_until_done().expect("the background grant job must finish before we spawn");

    for warning in &outcome.warnings {
        eprintln!("preflight warning: {warning}");
    }
    // **まず「測れる状態になったか」を確かめる。** 付与できていなければ、この後の
    // 「届かない」は移行が効いた証拠ではなく、ただの未付与である。
    let carried: Vec<CarriedDeclaration> = declarations
        .iter()
        .map(|declaration| {
            let granted = outcome
                .granted_passthrough
                .iter()
                .find(|g| g.path == declaration.path)
                .unwrap_or_else(|| {
                    panic!(
                        "every declared path must be reported as granted before we measure \
                         reachability; {} is missing from {:?}",
                        declaration.path.display(),
                        outcome.granted_passthrough
                    )
                })
                .clone();
            // [分流N1] 宣言の宛先SIDは**`preflight`が運んできた値**を使う（本番の`launch.rs`と
            // 同じ入手経路）。かつてここは台帳の索引（`fs_allow_capability_sids`）を引いていたが、
            // **本番がそれをやめた**ので、引き続き台帳を引くと「本番が積むもの」ではなく
            // 「台帳に在るもの」を測ることになる。台帳の索引が宣言より広いこと自体は
            // `only_the_declared_access_class_is_carried_to_the_child`が別に測る。
            let subject = crate::win_common::sid_from_string(&granted.subject_sid)
                .expect("preflight must hand back a usable capability SID for the declaration");
            CarriedDeclaration { granted, subject }
        })
        .collect();

    let canonical_ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.to_path_buf());
    // workspace本体の宛先SIDのモードは**書込モードが決める**。この対応は`preflight`の
    // 同じ`match`（`WorkspaceWriteMode` → `WorkspaceMode`）と一致していなければならず、
    // ずれるとCoWで`rwx`のcapabilityを積んで「テストだけが書ける」形になる。
    // **`match`は`..`無しの全分岐に保つ**（バリアントを足したらここで落とす）。
    let ws_mode = match write_mode {
        WorkspaceWriteMode::DirectRw => WorkspaceMode::Rwx,
        WorkspaceWriteMode::Cow { .. } => WorkspaceMode::Ro,
    };
    let ws_cap = workspace_capability_sid(&canonical_ws, ws_mode.as_str())
        .expect("the workspace capability must exist after preflight (D-54)");

    GrantedDomain {
        session: session_sid(),
        ws_cap,
        carried,
        outcome,
    }
}

/// 実マシンに残るもの（宣言capability宛のACEと台帳エントリ）を、**assertが落ちても**戻す
/// （`型F`。`TestDirGuard`はディレクトリしか戻さない）。
///
/// 順序は**ACEを剥がしてから台帳を落とす**。逆にすると宛先SIDを引けなくなり、撤収経路の無い
/// ACEが残る（`workspace_capability::forget_capability`のdocが定める不変条件）。
///
/// **宣言パスをスライスで受ける。** 1回の`preflight`で複数のパスを開く測定があるので、
/// パス1件ぶんの器を各測定が自前で回すと、**戻し忘れが測定ごとに別々に生まれる**。
fn cleanup_declarations(
    workspace: std::path::PathBuf,
    declared: Vec<std::path::PathBuf>,
) -> impl Drop {
    scopeguard(move || {
        let canonical_ws = workspace
            .canonicalize()
            .unwrap_or_else(|_| workspace.clone());
        for declared in &declared {
            if !declared.exists() {
                continue;
            }
            match revoke_declaration_capabilities(declared, Some(&canonical_ws), &|_, _| {}) {
                Ok(report) => eprintln!(
                    "cleanup: declaration ACEs revoked for {}: {report:?}",
                    declared.display()
                ),
                Err(e) => eprintln!(
                    "cleanup: could not revoke the declaration ACEs for {}: {e}",
                    declared.display()
                ),
            }
        }
        let dropped = crate::tier2a::workspace_capability::forget_capability(&canonical_ws, "");
        eprintln!(
            "cleanup: dropped {} capability ledger entries",
            dropped.len()
        );
        // `preflight`成功のたびに`workspace-grant-ledger.json`へ1行積まれる。使い捨ての
        // ワークスペースなので、消さないと**実在しないパスの記録**が溜まり続ける
        // （実測で1,043件まで育った前例があり、掃除は`harness fs prune`頼みになっていた）。
        crate::tier2a::workspace_ledger::remove_workspace_entry(&canonical_ws);
    })
}

/// 同じpackage SIDのまま、`domain_caps`だけを変えて子を起こし、標準出力を返す。
///
/// **2つのドメインの違いをこの引数1つに閉じ込める**のがこのヘルパーの目的である。
/// 起動の仕方が少しでも違うと、割れた結果を「capabilityのせい」と言えなくなる。
fn run_in_domain(
    session: &OwnedContainerSid,
    workspace: &std::path::Path,
    domain_caps: &[windows::Win32::Security::PSID],
    command: &str,
) -> String {
    let (shell, _) = resolve_shell();
    let env = crate::secret_env::build_child_env();
    let identity = domain_caps
        .first()
        .copied()
        .map(DomainIdentity::Capability)
        .unwrap_or(DomainIdentity::OwnPackage);
    let child = spawn_with_workspace(
        &shell,
        &["-NoProfile", "-NonInteractive", "-Command", command],
        workspace,
        &env,
        false,
        session.as_psid(),
        NetworkCapability::Deny,
        None,
        domain_caps,
        identity,
    )
    .expect("spawn the domain child through the production path");
    let (stdout, stderr, code) = child
        .write_stdin_read_output_and_wait(None)
        .expect("read the child output");
    eprintln!("[domain child] exit={code}\nstdout={stdout}\nstderr={stderr}");
    stdout
}

/// **受け入れ条件2**: 宣言したドメインだけがパスを見る。
///
/// 到達性は本番のプローブ（`probe_passthrough`）で測る。宛先SIDを明示的に渡せるので、
/// 「この宛先SIDでは届く／この宛先SIDでは届かない」を**同じ器で**1件ずつ測れる
/// （`test_support::spawn_in_workspace`は宣言capabilityを積まないので、この測定には使えない
/// ——同ヘルパーのdocがそう名指ししている）。
#[test]
#[ignore = "spawns real AppContainer children and changes real ACLs; run NON-elevated with --test-threads=1"]
fn only_the_declaring_domain_reaches_the_declared_path() {
    let workspace_guard = TestDirGuard::create("fsallow-accept-ws");
    let declared_guard = TestDirGuard::create("fsallow-accept-declared");
    let workspace = workspace_guard.path().to_path_buf();
    let declared = declared_guard.path().to_path_buf();
    std::fs::write(declared.join("secret.txt"), b"declared-content")
        .expect("seed the declared dir");

    let _cleanup = cleanup_declarations(workspace.clone(), vec![declared.clone()]);
    let declaration = read_declaration(&declared);
    let domain = grant_and_collect_subjects(
        &workspace,
        std::slice::from_ref(&declaration),
        &WorkspaceWriteMode::DirectRw,
    );
    let (session, ws_cap) = (&domain.session, &domain.ws_cap);
    let decl_cap = &domain.only().subject;
    let traverse = traverse_capability_sid().expect("traverse capability SID");

    // --- 許可側: 宣言capabilityを積んだドメインは届く ---
    //
    // **この対が無いと、機構が丸ごと死んでいても禁止側だけは緑になる。**
    let reachable = probe_passthrough(
        session.as_psid(),
        traverse.as_psid(),
        Some(ws_cap.as_psid()),
        &[decl_cap.as_psid()],
        &workspace,
        &declaration,
    );
    assert!(
        reachable.is_none(),
        "the declaring domain must reach its own declaration: {reachable:?}"
    );

    // --- 禁止側: 同じセッション・同じpackage SIDでも、積まないドメインは届かない ---
    let denied = probe_passthrough(
        session.as_psid(),
        traverse.as_psid(),
        Some(ws_cap.as_psid()),
        &[],
        &workspace,
        &declaration,
    )
    .expect(
        "a domain that did not declare the path must not reach it -- if this is None, the hole \
         is still open to every domain in the session (a package-SID ACE may have survived)",
    );
    // 「届かなかった」が**別の理由**（プローブを起こせなかった）でないことを確かめる
    // ——許可側が通っている以上プローブ自体は動くが、ここを見ないと将来の回帰で
    // 「起動失敗＝拒否」と読み替わる（問4）。
    assert!(
        !denied.contains("probe failed"),
        "the denial must come from the access check, not from a failure to start the probe: {denied}"
    );
    eprintln!("the non-declaring domain was denied as expected: {denied}");
}

/// **受け入れ条件1**: インタプリタ経由の実行が止まる。
///
/// 宣言したパスにスクリプトを置き、**同じコマンド**を2つのドメインで走らせる。
/// 宣言capabilityを積んだ側だけがスクリプトを読めて実行でき、積まない側は
/// インタプリタがファイルへ到達できずに例外になる。
///
/// これが閉じるのは、`D-79`（パスベースの実行制御）が**不採用で決着した後に残っていた
/// 唯一の道**である——`--sandbox tier2a`はワークスペース内の実行を止めないが、
/// 宛先SIDを宣言ごとに割れば「読めないから走らせられない」が成立する。
///
/// **実行ポリシーは測定から外す。** 子の中で`Set-ExecutionPolicy -Scope Process Bypass`を
/// 先に撃つのは、測りたいのがACLであってPowerShellの署名ポリシーではないためである
/// （ポリシーが理由で落ちると、拒否側が「capabilityが無いから」に見えてしまう）。
#[test]
#[ignore = "spawns real AppContainer children and changes real ACLs; run NON-elevated with --test-threads=1"]
fn only_the_declaring_domain_can_run_the_declared_script_through_an_interpreter() {
    let workspace_guard = TestDirGuard::create("fsallow-accept-exec-ws");
    let declared_guard = TestDirGuard::create("fsallow-accept-exec-declared");
    let workspace = workspace_guard.path().to_path_buf();
    let declared = declared_guard.path().to_path_buf();
    let payload = declared.join("payload.ps1");
    std::fs::write(&payload, format!("Write-Output '{PAYLOAD_RAN_MARKER}'\n"))
        .expect("seed the payload script");

    let _cleanup = cleanup_declarations(workspace.clone(), vec![declared.clone()]);
    let domain = grant_and_collect_subjects(
        &workspace,
        &[read_declaration(&declared)],
        &WorkspaceWriteMode::DirectRw,
    );
    let (session, ws_cap) = (&domain.session, &domain.ws_cap);
    let decl_cap = &domain.only().subject;

    // 2つのドメインへ**同じ文字列**を渡す（違いはcapabilityの集合だけにする）。
    let command = format!(
        "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; \
         Write-Output '{CHILD_ALIVE_MARKER}'; \
         try {{ & '{}' }} catch {{ Write-Output ('{DENIED_MARKER}: ' + $_.Exception.Message) }}",
        payload.display()
    );

    // --- 許可側 ---
    let declaring = run_in_domain(
        session,
        &workspace,
        &[ws_cap.as_psid(), decl_cap.as_psid()],
        &command,
    );
    assert!(
        declaring.contains(CHILD_ALIVE_MARKER),
        "the declaring domain's child did not even start: {declaring}"
    );
    assert!(
        declaring.contains(PAYLOAD_RAN_MARKER),
        "the declaring domain must be able to run the script it declared: {declaring}"
    );

    // --- 禁止側 ---
    let non_declaring = run_in_domain(session, &workspace, &[ws_cap.as_psid()], &command);
    assert!(
        non_declaring.contains(CHILD_ALIVE_MARKER),
        "the non-declaring domain's child never ran -- 'the payload did not run' would then say \
         nothing about the access check: {non_declaring}"
    );
    assert!(
        !non_declaring.contains(PAYLOAD_RAN_MARKER),
        "a domain that did not declare the path ran the script anyway -- the hole is still open \
         to the whole session: {non_declaring}"
    );
    assert!(
        non_declaring.contains(DENIED_MARKER),
        "the interpreter must fail on the script (and be caught), not silently produce nothing: \
         {non_declaring}"
    );
}

/// **受け入れ条件（分流N1）**: 子へ運ばれるcapability SIDは、**いま宣言した級のものだけ**である。
///
/// # 壊れた状態を一文で
///
/// **同じパスへ過去に別のアクセス級で発行したcapability SIDまで、子のトークンへ載る。**
/// 宛先SIDは`(秘密, 畳み込み済みパス, access級)`から決まるので、同じパスでも級が違えば
/// 別のSIDになり、それぞれ別のACEが載る。`read`だけを宣言した子に`read_write`用の
/// capability SIDまで積むと、その子は**宣言していない書込の許可へ手が届く**。
///
/// # なぜ2回`preflight`を通すのか
///
/// 「同じパスに複数の級のcapability SIDが在る」状態を作るためである。実運用では
/// `--fs-allow C:\x:rw`で1回起動し、次に`:read`で起動すれば自然にこうなる
/// （`--sandbox tier2a-cow`でも起きる——RW宣言が`read`へ降格するので、同じ宣言のまま
/// モードを変えるだけで2つ目の級が発行される）。
///
/// # 何を根拠に「1対1になった」と言うか（**対で測る**、`B-35`）
///
/// - **広い側が実在すること**を先に測る——台帳の索引（`fs_allow_capability_sids`）が
///   このパスに対して**2件**返すこと。ここが1件なら、この後の「1件だった」は
///   絞り込みが効いた証拠ではなく、**そもそも2件目が作られていない**だけである。
/// - そのうえで、`preflight`が運ぶ宛先SIDが**ちょうど1件**で、しかも
///   **いま宣言した級のもの**であること。本番の`launch.rs`はこの値をそのまま積むので、
///   これが子のトークンに載る集合そのものである。
#[test]
#[ignore = "changes real ACLs and the real capability ledger; run NON-elevated with --test-threads=1"]
fn only_the_declared_access_class_is_carried_to_the_child() {
    let workspace_guard = TestDirGuard::create("fsallow-n1-ws");
    let declared_guard = TestDirGuard::create("fsallow-n1-declared");
    let workspace = workspace_guard.path().to_path_buf();
    let declared = declared_guard.path().to_path_buf();
    std::fs::write(declared.join("seed.txt"), b"seed").expect("seed the declared dir");

    let _cleanup = cleanup_declarations(workspace.clone(), vec![declared.clone()]);
    let canonical_ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.clone());

    // --- 1回目: `read_write`で宣言する（2つ目の級を先に作っておく） ---
    let rw_declaration = FsPassthrough {
        path: declared.clone(),
        access: FsAccess::ReadWrite,
        forced: false,
        scope: GrantScope::Recursive,
    };
    preflight(
        &workspace,
        std::slice::from_ref(&rw_declaration),
        None,
        &WorkspaceWriteMode::DirectRw,
    )
    .expect("the read_write declaration must be granted first");
    grant_job::wait_until_done().expect("the background grant job must finish");

    // --- 2回目: 同じパスを`read`で宣言する（本番の測定対象） ---
    let read_decl = read_declaration(&declared);
    let outcome = preflight(
        &workspace,
        std::slice::from_ref(&read_decl),
        None,
        &WorkspaceWriteMode::DirectRw,
    )
    .expect("the read declaration must be granted");
    grant_job::wait_until_done().expect("the background grant job must finish");

    // --- 広い側が実在することを先に測る（歯の確認） ---
    let ledger_subjects = fs_allow_capability_sids(&declared, Some(&canonical_ws));
    assert_eq!(
        ledger_subjects.len(),
        2,
        "this measurement is only meaningful if the ledger really holds two access classes for \
         the path; found {} (if this is 1, the second class was never issued and 'exactly one \
         was carried' proves nothing)",
        ledger_subjects.len()
    );

    // --- 狭い側: 運ばれるのはちょうど1件 ---
    let carried: Vec<&harness_core::GrantedPassthrough> = outcome
        .granted_passthrough
        .iter()
        .filter(|g| g.path == declared)
        .collect();
    assert_eq!(
        carried.len(),
        1,
        "exactly one subject must be carried for the declared path, got {:?}",
        carried
    );

    // --- しかも「いま宣言した級」のものであること ---
    //
    // 級から宛先SIDを引き直して突き合わせる。**ここで`read`側と一致し、`read_write`側と
    // 一致しないこと**が、「宣言と1対1」の中身である。
    let read_cap = fs_allow_capability_sid(&canonical_ws, &declared, FsAccess::Read)
        .expect("the read capability must exist after the second preflight");
    let rw_cap = fs_allow_capability_sid(&canonical_ws, &declared, FsAccess::ReadWrite)
        .expect("the read_write capability must exist from the first preflight");
    let read_sid = crate::win_common::sid_to_string(read_cap.as_psid()).expect("render read SID");
    let rw_sid = crate::win_common::sid_to_string(rw_cap.as_psid()).expect("render read_write SID");
    assert_ne!(
        read_sid, rw_sid,
        "the two access classes must derive different SIDs, otherwise this test cannot tell them \
         apart (the derivation would not include the access class)"
    );
    assert_eq!(
        carried[0].subject_sid, read_sid,
        "the carried subject must be the one for the access class declared in this run"
    );
    assert_ne!(
        carried[0].subject_sid, rw_sid,
        "the read_write subject from the earlier run must not be carried into this child"
    );
}

/// **受け入れ条件（測定1、`plans/HANDOFF-ISSUE-20-SUBJECT-MIGRATION.md`）**:
/// `--sandbox tier2a-cow`のRO降格を通しても、運ばれる宛先SIDは**実際にACEを書いた級**のものである。
///
/// # 壊れた状態を一文で
///
/// **CoWで`:rw`を宣言したとき、ACEは`read`級のcapability SID宛に書かれるのに、子のトークンへ
/// 運ばれるのは`read_write`級のcapability SIDになっている。**
///
/// `--sandbox tier2a-cow`はworkspace本体を読取専用にして書込を差分層へ逃がすモードで、
/// `--fs-allow <path>:rw`の要求もOSへ書くときは`read`へ降格する（D-30。書込はRedirector DLLの
/// フックを通す経路だけに絞るため）。宛先SIDは`(秘密, 畳み込み済みパス, access級)`から決まるので、
/// **級が1つ違えばまったく別のSID**になる。したがって「ユーザーが要求した級」から導出すると、
/// ACEを書いた先と積む先がずれる。
///
/// **この壊れ方は成功に見える**——ACEは正しく付き、台帳にも記録が残る。壊れるのは
/// 子のトークンへ積む先（`launch.rs`はこの値をそのまま積む）と、撤収側が探しに行く先である。
///
/// # 何を根拠に「実際に書いた級」と言うか（**対で測る**、`B-35`）
///
/// - **台帳側**: このパスへ発行された宣言capabilityが**`read`の1件だけ**であること
///   （`read_write`は1度も発行されていない）。ここが2件なら降格前の級でも発行している
/// - **DACL側**: 運ばれた宛先SID宛のACEが**実在し**、そのマスクが`read`級であること。
///   台帳ではなく実物を読む——台帳は「付けたつもり」を記録しているだけである
/// - **到達側**: 運ばれた宛先SIDを積んだ子は届き、積まない子は届かない
///
/// # このテストの歯がどこにあるか（`B-27`。**2つの壊れ方を別々に測って確かめた**）
///
/// **壊れ方が2つあり、捕まえる assert が違う。** 片方だけ試すと「歯がある」と誤解する。
///
/// | 壊れ方 | 作り方（実測） | 赤くなる assert | 緑のままの assert |
/// |---|---|---|---|
/// | `preflight`が**要求した級**から導出する | `preflight`の導出を`fp.access`→`requested.access`へ | **台帳側だけ**（`read`が未発行・`read_write`が発行済み） | DACL側・`writable`・package SID・**到達側の許可/禁止とも** |
/// | 運ぶ側が級を**導出し直す** | 運ばれた宛先SIDを`read_write`級のSIDへ差し替え | **DACL側**（その宛先SIDのACEが無い） | 台帳側 |
///
/// **到達側には、1つ目の壊れ方に対する歯が無い**（実測）。導出が要求した級に変わっても、
/// ACEも運ぶ値も同じ`entry_cap`から出るので**両方まとめてずれ、子は普通に読める**——
/// 級が違うだけで整合してしまう。だから台帳側の assert を落とせない。
/// 到達側が担当しているのは「機構が丸ごと死んでいる／全ドメインへ開いている」の側である。
///
/// 2つ目の壊れ方では**DACL側が先に落ちる**ので、到達側がそれも捕まえるかどうかは
/// このテストからは言えない（**測っていない**）。
///
/// # 実行（**昇格しないこと**）
///
/// workspace・差分層・宣言先を**3つとも`C:\`直下**に置く。差分層を入れ子にすると`preflight`が
/// 中間ディレクトリのtraverseを求めて昇格を起こす（`cow_diff_layer_subject_tests`が一度踏んだ）。
#[test]
#[ignore = "real machine: creates directories under C:\\, writes DACLs, and spawns AppContainer children; run NON-elevated with --test-threads=1"]
fn the_cow_read_only_downgrade_carries_the_class_that_was_actually_written() {
    let workspace_guard = TestDirGuard::create("fsallow-cow-ws");
    let diff_guard = TestDirGuard::create("fsallow-cow-diff");
    let declared_guard = TestDirGuard::create("fsallow-cow-declared");
    let workspace = workspace_guard.path().to_path_buf();
    let diff_layer = diff_guard.path().to_path_buf();
    let declared = declared_guard.path().to_path_buf();
    std::fs::write(declared.join("seed.txt"), b"declared-content").expect("seed the declared dir");

    let canonical_ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.clone());
    let _cleanup = cleanup_declarations(workspace.clone(), vec![declared.clone()]);

    // **要求は`:rw`。** 降格させるのがこの測定の全てなので、ここを`read`にすると何も測らない。
    let requested = read_write_declaration(&declared);
    let domain = grant_and_collect_subjects(
        &workspace,
        std::slice::from_ref(&requested),
        &WorkspaceWriteMode::Cow {
            diff_layer_dir: diff_layer.clone(),
        },
    );
    let (session, ws_cap) = (&domain.session, &domain.ws_cap);
    let decl_cap = &domain.only().subject;
    let granted = &domain.only().granted;

    // 差分層のACEは、台帳から名前を引ける**うちに**剥がす。`cleanup_declaration`の
    // `forget_capability`が台帳を落とすと宛先SIDを引けなくなり、撤収経路の無いACEが残る。
    // **この束縛は`_cleanup`より後**なので、Dropは先に走る（宣言の順と逆順に落ちる）。
    let diff_cap = lookup_cow_diff_layer_capability_sid(&canonical_ws, &diff_layer);
    let _diff_cleanup = scopeguard({
        let diff_layer = diff_layer.clone();
        move || {
            if let Some(cap) = &diff_cap {
                let _ = revoke_ace_recursive(&diff_layer, cap.as_psid());
            }
        }
    });

    // --- 台帳側: 発行されたのは`read`の1件だけ ---
    //
    // **広い側が作られていないことを直接見る。** ここで`read_write`が`Some`なら、降格前の級で
    // 発行しているということで、たとえ運ぶ値が正しくても撤収側は2つの索引を持つことになる。
    let read_name = crate::tier2a::workspace_capability::lookup_declaration_capability_name(
        &canonical_ws,
        &declared,
        FsAccess::Read.label(),
    )
    .expect(
        "the CoW downgrade must issue the capability for the class it actually writes (read); \
         if this is None, the subject was derived from the class the user requested",
    );
    assert_eq!(
        crate::tier2a::workspace_capability::lookup_declaration_capability_name(
            &canonical_ws,
            &declared,
            FsAccess::ReadWrite.label(),
        ),
        None,
        "the read_write class must never be issued under --sandbox tier2a-cow: the ACE that is \
         actually written is a read-class ACE, so a read_write capability would be a subject with \
         no ACE behind it (and a second index for revocation to disagree about)"
    );
    let ledger_subjects = fs_allow_capability_sids(&declared, Some(&canonical_ws));
    assert_eq!(
        ledger_subjects.len(),
        1,
        "exactly one declaration capability must exist for this path after a CoW run, found {}",
        ledger_subjects.len()
    );

    // --- 運ばれた値: ちょうど1件で、`read`級のSIDである ---
    let read_sid_from_ledger = crate::win_common::sid_to_string(
        capability_sid_from_name(&read_name)
            .expect("the recorded read capability name must render to a SID")
            .as_psid(),
    )
    .expect("render the read-class SID");
    assert_eq!(
        granted.subject_sid, read_sid_from_ledger,
        "the carried subject must be the capability of the class that was actually written (read)"
    );

    // **`writable`は要求した級のまま残る。** ここが`false`へ落ちると、CoWのRedirector DLLが
    // どのルートの書込を横取りすべきか（`ext_capture_roots`）を見失う——降格するのは
    // **ACLの級**であって、ユーザーが何を要求したかの記録ではない。
    assert!(
        granted.writable,
        "the CoW downgrade must not erase the fact that the user asked for :rw; \
         ext_capture_roots reads this field to decide which roots the redirector captures"
    );

    // --- DACL側: 運ばれたSID宛のACEが実在し、そのマスクが`read`級である ---
    //
    // **台帳ではなく実物を読む。** 台帳は「付けたつもり」を記録しているだけで、付与側の
    // 思い込みがそのまま両辺に乗る。
    let carried_mask = sid_ace_mask(&declared, decl_cap.as_psid())
        .expect("the declared path DACL must be readable")
        .expect(
            "the carried subject must be the SID that actually holds an ACE on the declared path; \
             if this is None, the ACE was written for a different class than the one being carried \
             (symptom: the ACL looks correct but the child cannot read a single byte)",
        );
    let read_mask = required_passthrough_mask(FsAccess::Read);
    assert_eq!(
        carried_mask & read_mask,
        read_mask,
        "the ACE behind the carried subject must satisfy the read-class mask \
         (got {carried_mask:#x}, need {read_mask:#x})"
    );
    let rw_mask = required_passthrough_mask(FsAccess::ReadWrite);
    assert_ne!(
        carried_mask & rw_mask,
        rw_mask,
        "the ACE must NOT satisfy the read_write mask: the whole point of --sandbox tier2a-cow is \
         that writes go through the redirector into the diff layer, not straight to the real path \
         (got {carried_mask:#x})"
    );

    // --- 移行後の不変条件（§22.3.0）: セッションpackage SID宛のACEは0本 ---
    assert_eq!(
        sid_ace_mask(&declared, session.as_psid())
            .expect("the declared path DACL must be readable"),
        None,
        "the session package SID must have no ACE on the declared path: it is shared by every \
         process in this AppContainer, so one such ACE re-opens the path to every domain \
         (DACL cannot express 'package SID AND capability SID' -- parallel ALLOW entries are OR)"
    );

    // --- 到達側 ---
    //
    // **降格後の級でプローブを撃つ。** 要求した`:rw`の形で撃つと書込を試して落ち、
    // 「宛先SIDが間違っている」と区別の付かない**偽の到達不能**になる
    // （本番の`preflight`も降格後の宣言でプローブしている）。
    let effective = read_declaration(&declared);
    let traverse = traverse_capability_sid().expect("traverse capability SID");

    // 許可側: 運ばれた宛先SIDを積んだ子は届く。**この対が無いと、機構が丸ごと死んでいても
    // 禁止側だけは緑になる。**
    let reachable = probe_passthrough(
        session.as_psid(),
        traverse.as_psid(),
        Some(ws_cap.as_psid()),
        &[decl_cap.as_psid()],
        &workspace,
        &effective,
    );
    assert!(
        reachable.is_none(),
        "a child carrying the subject that preflight handed back must reach the declaration \
         even after the CoW read-only downgrade: {reachable:?}"
    );

    // 禁止側: 同じセッション・同じpackage SIDでも、積まない子は届かない。
    let denied = probe_passthrough(
        session.as_psid(),
        traverse.as_psid(),
        Some(ws_cap.as_psid()),
        &[],
        &workspace,
        &effective,
    )
    .expect(
        "a domain that did not declare the path must not reach it -- if this is None, the hole is \
         still open to every domain in the session (a package-SID ACE may have survived)",
    );
    assert!(
        !denied.contains("probe failed"),
        "the denial must come from the access check, not from a failure to start the probe: {denied}"
    );
    eprintln!("the non-declaring domain was denied as expected: {denied}");
}

/// **受け入れ条件（残課題#20の測定2、分流A）の器**: 1つの子が宣言を2件持つとき、
/// **各パスへ運ばれるのは、そのパスについて宣言した級のcapability SID 1件だけ**である。
///
/// # 壊れた状態を一文で
///
/// **宣言を2件まとめて`preflight`へ渡すと、あるパスについて宣言していない宛先SID
/// （過去に別の級で発行したもの／もう一方の宣言のもの）まで子のトークンへ載る。**
///
/// 宛先SIDは`(秘密, 畳み込み済みパス, access級)`から決まるので、**パスか級のどちらかが違えば
/// まったく別のSID**になる。`read`だけを宣言したパスへ`read_write`用のSIDまで積むと、
/// その子は**宣言していない書込の許可へ手が届く**。
///
/// # 測るのは「2件載ること」ではない
///
/// **「各パスについて、載っているのが宣言した級の1件だけ」**である。2件載っていること自体は
/// 宣言が2件あるのだから当たり前で、それを数えても何も判定していない。
///
/// # なぜ級を引数で受けるのか（**器を2つ書かない**、`docs/CODE-STRUCTURE-RULES.md`規則5）
///
/// 導出鍵の軸は**パスと級の2本**である。級を割った組（`read`と`read_exec`）だけを流すと、
/// **鍵からパスが落ちた世界でも級が2つの宣言を分け続ける**ので、下のクロスパスの否定は
/// その世界でも緑で通る——つまりその回で言えるのは級の軸についてだけになる。同じ級の組
/// （`read_exec`を2件）を同じ器へ流すと、2つの宣言を分けているものがパスだけになり、
/// クロスパスの否定が初めてfalsifiableになる。呼び出し側はモジュールdocの表5・6。
///
/// # 既存の`only_the_declared_access_class_is_carried_to_the_child`との違い
///
/// あちらは**同じパスに2つの級**がある状態を`preflight`を**2回**通して作り、宣言は常に1件である。
/// こちらは**別のパス2件を1回の`preflight`へまとめて渡す**——`--fs-allow`は繰り返し指定でき、
/// 実運用ではこちらが常態である。**振っている軸が違う**（あちらは級、こちらは宣言の件数）。
///
/// # 突き合わせる2つは、どこまで遡ると同じ値になるか（`measurement-review`検問10）
///
/// 「運ばれた宛先SID」と「級から引き直したSID」は、どちらも`fs_allow_capability_sid`から出る。
/// **導出そのものが壊れれば両方が同じだけずれる**ので、この対では捕まらない
/// （`plans/mac-spike/RESULTS.md` §S38-4で実測済み）。だから**源とは独立に作られた値を4つ混ぜる**。
///
/// | 第3の値 | なぜ源より上流を捕まえられるか | 何を捕まえるか |
/// |---|---|---|
/// | 台帳の宣言エントリ（`lookup_declaration_capability_name`） | **引くキーが宣言のパスとラベル**（テストが書いた値）であり、導出の出力ではない | 宣言していない級を発行した |
/// | **2つのパスの台帳名の比較** | 引くキーはテストが書いた2つのパスで、比べるのは台帳が記録した名前どうし | 2つのパスが**同じ名前**を指した（導出鍵からパスが落ちた）。**ACLを1バイトも読まない経路** |
/// | **もう一方のパス**の実DACL | 値の出どころ（このパスへの付与）とは**別のオブジェクト**を読む | 2つの宣言が宛先SIDを共有した（同上を実物から見る） |
/// | 子の実I/O（`probe_passthrough_batch`） | ACLとトークンをOSのアクセス検査に掛ける | 機構が丸ごと死んでいる／セッションの全ドメインへ開いている |
///
/// **実I/Oには上流の壊れ方に対する歯が無い**（§S38-4）。導出が級やパスを取り違えても、
/// ACEを書く先と運ぶ値がまとめてずれるので子は普通に読める。**台帳側とDACL側のassertを
/// 落とさないこと。**
///
/// # assertの順序（**独立な第3の値を、同源の対より先に置く**）
///
/// 同源の対（運ばれた値 対 テストが引き直した値）を先に置くと、**下流の壊れ方では必ずそこが
/// 先に落ち、第3の値に歯があるかを1度も見られない**。仕込みを通しても「台帳側・DACL側が
/// 赤くなった」と書けないままになるので、この器は同源の対を各腕の**最後**に置く。
///
/// 同じ理由で[`declared_subject_text`]の呼び出しも台帳の読取より**後**に置く——あれは
/// 無ければ**その場で発行する**ので、先に呼ぶと「宣言した級が1度も発行されていない」という
/// 壊れ方をテスト自身が埋めてしまう（読むだけのつもりの呼び出しが作用を持つ、`B-01`）。
///
/// # 対照（`B-35`。成功するはずの腕と失敗するはずの腕を同じ回に混ぜる）
///
/// | 腕 | 期待 | これが無いと |
/// |---|---|---|
/// | 台帳に**広い側**（`read_write`）が実在する | 各パス2件 | 「運ばれたのは1件」が、絞り込みではなく**2件目が作られていないだけ**になる |
/// | 狭い側のACEが**広い側の級のマスクを満たさない** | 満たさない | 両方へ広い方を書いた世界でも「自分の級を満たす」は通る。**級が同じ組では原理的に空**（相手が広くない）なので、その回は下の3行が対照を担う |
/// | クロスパスの否定（台帳名・実DACLの両方向） | 別々／どちらも`None` | 2つの宣言が宛先SIDを共有しても気づけない。**級が同じ組ではここだけがパスの軸を見ている** |
/// | 両方のcapabilityを積んだ子 | 両方へ届く | 機構が効きすぎて全拒否でも禁止側は緑になる |
/// | 1件目だけ積んだ子 | 2件目へ届かない | 2つの宣言が別々の扉である証拠が無い |
///
/// # 歯（**このテストを書いたセッションでは確かめていない**）
///
/// 分流は準備だけを担当し、実行は本流が行う（`plans/handoff/issue20-measure/INDEX.md`）。
/// したがって**「赤くなることを見た」とは言えない**（`B-27`）。仕込むべき壊れ方と、
/// どのassertが赤くなるはずかは`plans/handoff/issue20-measure/A.md`の「実行手順」が持つ。
///
/// # 実行（**昇格しないこと**）
///
/// workspaceと宣言先2つを**3つとも`C:\`直下**に置く。祖先が`C:\`だけで済み、既にtraverse台帳に
/// あるACEで足りる＝新しい昇格が要らない（§S38-5で実測）。`tag`はディレクトリ名に入る
/// ——**呼び出しごとに違う値を渡すこと**（同じ名前だと2本のテストが同じ実ディレクトリを掴む）。
fn measure_two_declarations_in_one_preflight(
    tag: &str,
    first_access: FsAccess,
    second_access: FsAccess,
) {
    // 準備（広い側）は`read_write`級を発行する。そこを宣言に使うと「広い側が実在する」対照が
    // **宣言そのものと同じ級**になり、対照が空になる。
    assert!(
        first_access != FsAccess::ReadWrite && second_access != FsAccess::ReadWrite,
        "the widening preparation issues the read_write class, so declaring it here would make \
         the control vacuous"
    );
    let workspace_guard = TestDirGuard::create(&format!("fsallow-multi-{tag}-ws"));
    let first_guard = TestDirGuard::create(&format!("fsallow-multi-{tag}-a"));
    let second_guard = TestDirGuard::create(&format!("fsallow-multi-{tag}-b"));
    let workspace = workspace_guard.path().to_path_buf();
    let first_path = first_guard.path().to_path_buf();
    let second_path = second_guard.path().to_path_buf();
    std::fs::write(first_path.join("seed.txt"), b"first-side").expect("seed the first declaration");
    std::fs::write(second_path.join("seed.txt"), b"second-side")
        .expect("seed the second declaration");

    let _cleanup = cleanup_declarations(
        workspace.clone(),
        vec![first_path.clone(), second_path.clone()],
    );
    let canonical_ws = workspace
        .canonicalize()
        .unwrap_or_else(|_| workspace.clone());

    // --- 準備: 両方のパスへ`read_write`級を先に発行しておく（歯の対照＝広い側） ---
    //
    // これが無いと、この後の「運ばれたのは1件だけ」は**絞り込みが効いた証拠ではなく、
    // そもそも2件目が作られていないだけ**になる。実運用では`--fs-allow <path>:rw`で
    // 一度起動した後に級を変えれば自然にこの状態になる。
    let widening = [
        read_write_declaration(&first_path),
        read_write_declaration(&second_path),
    ];
    grant_and_collect_subjects(&workspace, &widening, &WorkspaceWriteMode::DirectRw);

    // --- 測定本体: **別のパス2件を1回の`preflight`で**宣言する ---
    let declarations = [
        declaration_of(&first_path, first_access),
        declaration_of(&second_path, second_access),
    ];
    let domain =
        grant_and_collect_subjects(&workspace, &declarations, &WorkspaceWriteMode::DirectRw);

    // --- 軸が振れたことの検算（`measurement-review`検問3） ---
    //
    // 足した軸は**宣言の件数**（1→2）である。ここを見ないと、「宣言2件の測定」のつもりで
    // 実際には1件ぶんしか処理されていなくても以下のassertが全部通る——軸を振ったつもりで
    // 振れておらず、既存の検算3本を全部通り抜けた前例がこのリポジトリにある。
    assert_ne!(
        first_path, second_path,
        "the two declarations must be different paths, otherwise this measures the same door twice"
    );
    let touched: std::collections::BTreeSet<&std::path::Path> = domain
        .outcome
        .granted_passthrough
        .iter()
        .map(|g| g.path.as_path())
        .collect();
    assert!(
        touched.contains(first_path.as_path()) && touched.contains(second_path.as_path()),
        "one preflight call must have processed BOTH declarations; it reported {touched:?}"
    );

    let first_carried = &domain.carried[0];
    let second_carried = &domain.carried[1];

    // 各腕: (宣言パス, この回に宣言した級, **もう一方の宣言の級**, 運ばれたもの)。
    //
    // 3つ目は**級が割れているときだけ`Some`**である。同じ級の組では「もう一方の宣言の級」が
    // この宣言の級そのものなので、「このパスへ発行されていないこと」を求めると**正しい世界を
    // 赤にする**assertになる。その回でパスの軸を見るのは、ループの後のクロスパス2本
    // （台帳の名前・実DACL）である。
    let other_of =
        |mine: FsAccess, other: FsAccess| -> Option<FsAccess> { (mine != other).then_some(other) };
    let arms: [(
        &std::path::Path,
        FsAccess,
        Option<FsAccess>,
        &CarriedDeclaration,
    ); 2] = [
        (
            &first_path,
            first_access,
            other_of(first_access, second_access),
            first_carried,
        ),
        (
            &second_path,
            second_access,
            other_of(second_access, first_access),
            second_carried,
        ),
    ];
    // 実DACLから読んだマスクと、台帳が記録していたcapability名（どちらも腕の順）。
    // **両側の対照とクロスパスの否定はループの外**で見る。
    let mut masks: Vec<u32> = Vec::new();
    let mut recorded_names: Vec<String> = Vec::new();

    for (path, declared_access, other_access, carried) in arms {
        // --- 広い側が実在する（歯の対照） ---
        let ledger_subjects = fs_allow_capability_sids(path, Some(&canonical_ws));
        assert_eq!(
            ledger_subjects.len(),
            2,
            "{}: this measurement is only meaningful if the ledger really holds a second access \
             class for the path; found {} (if this is 1, 'exactly one was carried' proves nothing)",
            path.display(),
            ledger_subjects.len()
        );

        // --- 狭い側: このパスへ運ばれたのはちょうど1件 ---
        let carried_here = domain.carried_for(path);
        assert_eq!(
            carried_here.len(),
            1,
            "{}: exactly one subject must be carried for this declaration, got {carried_here:?}",
            path.display()
        );

        // --- 第3の値1: 台帳の宣言エントリ（引くキーは**宣言のパスとラベル**） ---
        //
        // §S38-4で唯一歯があった値である。`lookup_...`は**発行しない**ので、
        // 「そのパスについて発行された級」を状態を変えずにそのまま読める。
        //
        // **同源の対（この腕の末尾）より前に置く。** 後ろに置くと、運ぶ側だけが級やパスを
        // 作り直す壊れ方では同源の対が先に落ち、ここに歯があるかを1度も見られない。
        let recorded = crate::tier2a::workspace_capability::lookup_declaration_capability_name(
            &canonical_ws,
            path,
            declared_access.label(),
        )
        .unwrap_or_else(|| {
            panic!(
                "{}: the declared class ({}) must have been issued; if this is None, the subject \
                 was derived from some other class than the one declared",
                path.display(),
                declared_access.label()
            )
        });
        let recorded_sid = crate::win_common::sid_to_string(
            capability_sid_from_name(&recorded)
                .expect("the recorded capability name must render to a SID")
                .as_psid(),
        )
        .expect("render the recorded SID");
        assert_eq!(
            carried.granted.subject_sid,
            recorded_sid,
            "{}: the carried subject must be the one the ledger recorded for the declared class",
            path.display()
        );
        recorded_names.push(recorded);

        // --- 第3の値1': もう一方の**宣言の級**は、このパスへは発行されていない ---
        //
        // 宣言がパスをまたいで漏れていれば、ここに現れる。**級が割れている回だけ測れる**
        // ——同じ級の回では「もう一方の宣言の級」がこの宣言の級そのものなので、正しい世界でも
        // `Some`になる。その回にパスの軸を見るのは、ループの後のクロスパス2本である。
        if let Some(other_access) = other_access {
            assert_eq!(
                crate::tier2a::workspace_capability::lookup_declaration_capability_name(
                    &canonical_ws,
                    path,
                    other_access.label(),
                ),
                None,
                "{}: the class declared for the OTHER path ({}) must never be issued for this \
                 one; a capability here would be a subject that no declaration on this path \
                 asked for",
                path.display(),
                other_access.label()
            );
        }

        // --- 第3の値2a: このパスの実DACL（運ばれたSID宛のACEが実在する） ---
        //
        // **台帳ではなく実物を読む。** 台帳は「付けたつもり」を記録しているだけである。
        let mask = sid_ace_mask(path, carried.subject.as_psid())
            .expect("the declared path DACL must be readable")
            .unwrap_or_else(|| {
                panic!(
                    "{}: the carried subject must be the SID that actually holds an ACE on this \
                     path; if this is None, the ACE was written for a different subject than the \
                     one being carried (symptom: the ACL looks correct but the child cannot read \
                     a single byte)",
                    path.display()
                )
            });
        let required = required_passthrough_mask(declared_access);
        assert_eq!(
            mask & required,
            required,
            "{}: the ACE behind the carried subject must satisfy the declared class's mask \
             (got {mask:#x}, need {required:#x})",
            path.display()
        );
        masks.push(mask);

        // --- 移行後の不変条件（§22.3.0）: セッションpackage SID宛のACEは0本 ---
        assert_eq!(
            sid_ace_mask(path, domain.session.as_psid())
                .expect("the declared path DACL must be readable"),
            None,
            "{}: the session package SID must have no ACE here: it is shared by every process in \
             this AppContainer, so one such ACE re-opens the path to every domain (DACL cannot \
             express 'package SID AND capability SID' -- parallel ALLOW entries are OR)",
            path.display()
        );

        // --- 同源の対（**この腕でいちばん弱いので最後に置く**） ---
        //
        // 上の3本と違い、突き合わせる2つは`fs_allow_capability_sid`という**同じ源**から出る
        // ——導出そのものが壊れれば両方が同じだけずれて差が出ない（§S38-4の実測）。
        // それでも置くのは、(1)級が導出鍵に入っていること自体を1行で見るため、
        // (2)運ぶ側だけが級を作り直した場合の読み分けが付くため、の2つである。
        //
        // **`declared_subject_text`は無ければその場で発行する**ので、台帳の読取より後に置く
        // （前に置くと「宣言した級が1度も発行されていない」壊れ方をテスト自身が埋める）。
        let declared_sid = declared_subject_text(&canonical_ws, path, declared_access);
        let wider_sid = declared_subject_text(&canonical_ws, path, FsAccess::ReadWrite);
        assert_ne!(
            declared_sid,
            wider_sid,
            "{}: two access classes must derive different SIDs, otherwise this test cannot tell \
             them apart (the derivation would not include the access class)",
            path.display()
        );
        assert_eq!(
            carried.granted.subject_sid,
            declared_sid,
            "{}: the carried subject must be the capability of the class declared in this run",
            path.display()
        );
        assert_ne!(
            carried.granted.subject_sid,
            wider_sid,
            "{}: the read_write subject issued by the earlier run must not be carried into this \
             child -- it would hand the child a write permission it never declared",
            path.display()
        );
    }

    // --- 両側の対照（マスクの側） ---
    //
    // 上のループは各腕が「自分の級のマスクを満たす」ことしか見ておらず、それは
    // **両方へ広い方を書いた世界**でも通る。だから、相手の級が自分の級に無いビットを持つ腕
    // （＝相手のほうが広い腕）について「相手の級は満たさない」を置く。
    //
    // **級が同じ組では、ここは原理的に空になる**（相手が広くないので条件が立たない）。
    // その回の対照はクロスパスの否定2本と、到達側の禁止の腕が担う。
    let required_of = [
        required_passthrough_mask(first_access),
        required_passthrough_mask(second_access),
    ];
    for (i, path) in [&first_path, &second_path].into_iter().enumerate() {
        let mine = required_of[i];
        let other = required_of[1 - i];
        // 相手の級に、自分の級が要求しないビットが1つでもあるときだけ意味を持つ。
        if other & !mine == 0 {
            continue;
        }
        assert_ne!(
            masks[i] & other,
            other,
            "{}: the narrower declaration must NOT have received the wider class's bits \
             (needs {other:#x} to satisfy the other class): if it did, the two declarations would \
             open the same door and the access-class axis would be fiction (mask {:#x})",
            path.display(),
            masks[i]
        );
    }

    // --- 第3の値2b: **もう一方のパス**の実DACL（クロスパスの否定、両方向） ---
    //
    // 値の出どころ（このパスへの付与）とは別のオブジェクトを読む。2つの宣言が宛先SIDを
    // 共有していれば（導出鍵からパスが落ちた形）、その宛先SIDは相手のパスにもACEを持つので
    // ここが`Some`になる。
    //
    // **級が割れている回では、鍵からパスが落ちても級が2つの宣言を分け続けるのでここは緑のまま
    // 通る。** 級が同じ回（[`two_same_class_declarations_keep_a_separate_subject_per_path`]）が
    // 並んでいるのはそのためで、この2本がfalsifiableになるのはそちらの回である。
    assert_eq!(
        sid_ace_mask(&second_path, first_carried.subject.as_psid())
            .expect("the other declaration's DACL must be readable"),
        None,
        "the subject carried for {} must hold no ACE on {}: the derivation key includes the \
         folded path, so a hit here means the two declarations ended up sharing one subject",
        first_path.display(),
        second_path.display()
    );
    assert_eq!(
        sid_ace_mask(&first_path, second_carried.subject.as_psid())
            .expect("the other declaration's DACL must be readable"),
        None,
        "the subject carried for {} must hold no ACE on {} (symmetric to the assertion above; \
         checking one direction only would miss a swap in the other)",
        second_path.display(),
        first_path.display()
    );

    // --- 第3の値1'': 2つのパスの台帳エントリが**同じ名前を指していない** ---
    //
    // 引くキーはテストが書いた2つのパスで、比べるのは台帳が記録した名前である。導出鍵から
    // パスが落ちると、2件目の宣言は1件目のエントリに当たって**同じ秘密＝同じ名前**を返すので
    // ここが一致する。上のクロスパスと同じ壊れ方を、**ACLを1バイトも読まずに**捕まえる経路で、
    // 級が同じ回でも級が割れた回でも同じだけ効く。
    assert_ne!(
        recorded_names[0],
        recorded_names[1],
        "the ledger must have issued different capability names for {} and {}; one name for two \
         paths means the derivation key stopped including the path",
        first_path.display(),
        second_path.display()
    );

    // --- 到達側: 1つの子が2つの宣言を持つ形で、両側の対照を同じ回に混ぜる ---
    //
    // **`probe_passthrough_batch`を使う**（1件版の`probe_passthrough`はこれへ委譲している）。
    // 2件を1プロセスで測るので、許可側と禁止側の差が「子の起こし方の違い」になり得ない。
    let traverse = traverse_capability_sid().expect("traverse capability SID");
    let probe_with = |caps: &[windows::Win32::Security::PSID]| -> Vec<Option<String>> {
        match probe_passthrough_batch(
            domain.session.as_psid(),
            traverse.as_psid(),
            Some(domain.ws_cap.as_psid()),
            caps,
            &workspace,
            &declarations,
        ) {
            BatchProbeOutcome::Measured(results) => {
                assert_eq!(
                    results.len(),
                    declarations.len(),
                    "the probe must report one verdict per declaration, in input order"
                );
                results
            }
            BatchProbeOutcome::NotRun(reason) => panic!(
                "the reachability probe never ran ({reason}); 'unreachable' would then say \
                 nothing about the access check (B-33)"
            ),
        }
    };

    // 許可側: 宣言した2つのcapabilityを積んだ子は、両方へ届く。
    // **この腕が無いと、機構が丸ごと死んでいても禁止側だけは緑になる。**
    let both = probe_with(&[
        first_carried.subject.as_psid(),
        second_carried.subject.as_psid(),
    ]);
    assert!(
        both.iter().all(|verdict| verdict.is_none()),
        "a child carrying both declared subjects must reach both declarations: {both:?}"
    );

    // 禁止側: 1件目のcapabilityだけを積んだ子は、2件目へ届かない。
    let first_only = probe_with(&[first_carried.subject.as_psid()]);
    assert!(
        first_only[0].is_none(),
        "the declaration whose subject IS carried must stay reachable in the same run, otherwise \
         the denial below says nothing about which door was closed: {first_only:?}"
    );
    let denied = first_only[1].as_ref().unwrap_or_else(|| {
        panic!(
            "a child that carries only the subject of {} must not reach {} -- if this is None, \
             the two declarations are not separate doors (a shared subject or a surviving \
             package-SID ACE would do it)",
            first_path.display(),
            second_path.display()
        )
    });
    assert!(
        !denied.contains("probe failed"),
        "the denial must come from the access check, not from a failure to start the probe: \
         {denied}"
    );
    eprintln!("the declaration that was not carried stayed out of reach: {denied}");

    // --- 最後に置く同源の対: 2つの宣言が**別々の宛先SID**になっている ---
    //
    // 突き合わせる2つはどちらも`preflight`が運んだ値なので、これは**独立な第3の値ではない**。
    // ここを早い位置に置くと、宛先SIDを共有する壊れ方でまずここが落ち、上の独立な3本
    // （台帳の名前・クロスパスの実DACL・到達側の禁止）に歯があるかを1度も見られなくなる。
    // だから読み分けを1行で締めるためだけに、いちばん後ろへ置く。
    assert_ne!(
        first_carried.granted.subject_sid, second_carried.granted.subject_sid,
        "the two declarations must not share one subject SID: a child that declares only one of \
         them would carry the other declaration's permission as well"
    );
}

/// **測定2・級の軸**: 宣言2件の級が**割れている**とき（`read`と`read_exec`）、各パスへ運ばれるのは
/// そのパスについて宣言した級の1件だけである。
///
/// 級の対を`read`と`read_exec`にしてあるのは意図的で、**マスクが実行ビット1つ分しか違わない**
/// （`acl_grant::fs_access_mask`）。差が小さいほど、級を取り違えたときにマスクの検算を
/// すり抜ける余地が大きい。
///
/// **この回だけでは「宣言と1対1」を級の軸についてしか言えない**——導出鍵からパスが落ちても
/// 級が2つの宣言を分け続けるので、クロスパスの否定が緑のまま通る。パスの軸は
/// [`two_same_class_declarations_keep_a_separate_subject_per_path`]が測る。
#[test]
#[ignore = "real machine: creates directories under C:\\, writes DACLs, and spawns AppContainer children; run NON-elevated with --test-threads=1"]
fn each_declaration_carries_only_its_own_class_when_a_child_holds_two() {
    measure_two_declarations_in_one_preflight("cls", FsAccess::Read, FsAccess::ReadExec);
}

/// **測定2・パスの軸**: 宣言2件の級が**同じ**とき（`read_exec`を2件）でも、各パスへ運ばれる
/// 宛先SIDは**パスごとに別**である。
///
/// # なぜこの形が要るのか（**実運用でいちばん多いのがこれである**）
///
/// `--fs-allow`が受ける接尾辞は`:rw`だけで、付けなければ`read_exec`になる
/// （`harness-cli/src/cli/startup/sandbox.rs`）。したがって`--fs-allow A --fs-allow B`という
/// もっとも普通の使い方は、**級が同じでパスだけが違う宣言2件**を1回の`preflight`へ渡す形になる。
///
/// # この回だけがfalsifiableにする問い
///
/// 宛先SIDの導出鍵は`(秘密, 畳み込み済みパス, access級)`である。**鍵からパスが落ちる**壊れ方は、
/// 級が割れている回では級が2つの宣言を分け続けるので**クロスパスの否定に引っ掛からない**。
/// 級を揃えると2つの宣言を分けるものがパスしか無くなり、そこで初めて
/// 「相手のパスに自分の宛先SID宛ACEが無い」「2つの台帳エントリが別の名前を指す」が
/// 赤くなり得る主張になる。
///
/// **級が同じぶん、マスクの両側対照（狭い側が広い級を満たさない）はこの回では空になる**
/// ——器がその腕を自動で飛ばす。代わりに対照を担うのはクロスパスの否定2本と、
/// 到達側の「1件目だけ積んだ子が2件目へ届かない」腕である。
#[test]
#[ignore = "real machine: creates directories under C:\\, writes DACLs, and spawns AppContainer children; run NON-elevated with --test-threads=1"]
fn two_same_class_declarations_keep_a_separate_subject_per_path() {
    measure_two_declarations_in_one_preflight("path", FsAccess::ReadExec, FsAccess::ReadExec);
}
