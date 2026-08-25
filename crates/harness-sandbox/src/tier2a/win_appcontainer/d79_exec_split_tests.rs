//! **D-79の受け入れ測定（M2）**: ワークスペース内の実行を宣言制にする実装を入れたら
//! **本当に止まるのか**、そして**その実装はいくら掛かるのか**。
//!
//! 計画は[`plans/HANDOFF-ACL-DOMAIN-SPLIT-COST.md`](../../../../../plans/HANDOFF-ACL-DOMAIN-SPLIT-COST.md)のM2、
//! 決定は`DESIGN-SANDBOX-APPPOLICY.md`のD-79、結果の正本は
//! [`plans/mac-spike/RESULTS.md`](../../../../../plans/mac-spike/RESULTS.md)。
//!
//! ## なぜ「2本に割る」形を測るのか
//!
//! Windowsでは`FILE_EXECUTE`と`FILE_TRAVERSE`が**同じビット**（0x20）で、意味はオブジェクトの
//! 型が決める。したがって`CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE`を載せた**1本**のACEでは
//! 「ディレクトリは辿れるがファイルは実行できない」を表現できない。D-79はこれを
//!
//! - `CONTAINER_INHERIT_ACE`のみ（traverse込み）
//! - `OBJECT_INHERIT_ACE`のみ（execute抜き）
//!
//! の**2本**に割ることで表現する、と決めている。**その形が本当に成立するかは未測定だった。**
//!
//! ## 先行測定との違い（ここを取り違えないこと）
//!
//! `crates/harness-cli/tests/tier2a_e2e.rs`の`tier2a_workspace_exec_ace_matrix`（RESULTS.md §S8）は
//! **ファイル単位の手術**で「実行可否はEXECUTE権で決まるか」を測った。本モジュールが測るのは
//! **継承ACEの形そのもの**——D-79が採る2本割りで、(a) ディレクトリを辿れるまま
//! (b) 無宣言のファイルが実行できなくなり (c) 宣言したファイルだけが実行できる、が同時に成立するか。
//!
//! ## 実行（**昇格しないこと**）
//!
//! ```text
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture d79_exec_split_tests
//! ```
//!
//! `mac_spike_tests`と同じ理由で昇格しない——昇格したテストからAppContainer子を起こすと
//! 親トークンが管理者のものになり、測っている世界が実運用とずれる（B-08、BUG-109と同型）。
//! ACEを書くのは**テスト自身が作ったツリー**だけなので、所有者権限で足りる。

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::mac_spike_tests::{SpikeConsole, SpikeSpawn};
use super::*;

/// `FILE_EXECUTE`（ファイル）＝`FILE_TRAVERSE`（ディレクトリ）。**同じビットである**ことが
/// D-79が2本に割らざるを得ない理由そのものなので、定数を1つだけ置いて両方をこれで呼ぶ。
const EXECUTE_OR_TRAVERSE: u32 = 0x0000_0020;

/// 測定用のcapability SIDを**名前から導出**する。`workspace_capability_sid`は使わない——
/// あちらはworkspace＋mode単位の秘密を`%APPDATA%`の台帳へ永続化するので、測定が実マシンへ
/// 記録を残す（HANDOFFの「やってはいけないこと」2番）。
fn measure_capability(label: &str) -> crate::win_common::OwnedSid {
    let name = format!("harness-d79-{}-{label}", std::process::id());
    super::capability_sid_from_name(&name).expect("derive capability sid")
}

/// AppContainer子（PowerShell）に`command`を実行させ、stdout＋stderrを返す。
/// `mac_spike_capability_tests::read_from_sandbox`と同じ形だが、任意のコマンドを撃てる。
fn run_in_sandbox(container_sid: PSID, capabilities: &[PSID], command: &str) -> String {
    let (shell, _) = resolve_shell();
    // cwdは全パッケージが読める場所にする（測定対象のツリーをcwdにすると、
    // 「cwdへ入れないから何もできなかった」と「実行だけができない」が混ざる）。
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let cwd = PathBuf::from(format!("{system_root}\\System32"));
    let mut child = SpikeSpawn {
        exe: &shell,
        args: &["-NoProfile", "-NonInteractive", "-Command", command],
        cwd: &cwd,
        container_sid,
        capabilities,
        child_process_restricted: false,
        stdout_override: None,
        extra_inherit: &[],
        process_sddl: None,
        thread_sddl: None,
        token_default_dacl_sddl: None,
        no_appcontainer: false,
        console: SpikeConsole::NoWindow,
    }
    .spawn()
    .expect("spawn the probe child");
    let (out, err, _code) = child.wait_and_read();
    format!("{out}{err}")
}

/// 測定対象のツリーを1つ作る。
///
/// ```text
/// <root>/note.txt          読取の対象
/// <root>/payload.exe       **宣言していない**実行ファイル（cmd.exeの複製）
/// <root>/declared.exe      **宣言した**実行ファイル（同上）
/// <root>/sub/inner.txt     ディレクトリを辿れないと読めない場所
/// ```
fn build_probe_tree(root: &Path) {
    std::fs::create_dir_all(root.join("sub")).expect("create sub dir");
    std::fs::write(root.join("note.txt"), "NOTEBODY").expect("write note.txt");
    std::fs::write(root.join("sub").join("inner.txt"), "INNERBODY").expect("write inner.txt");
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let cmd_exe = PathBuf::from(format!("{system_root}\\System32\\cmd.exe"));
    for name in ["payload.exe", "declared.exe"] {
        std::fs::copy(&cmd_exe, root.join(name))
            .unwrap_or_else(|e| panic!("copy cmd.exe -> {name}: {e}"));
    }
}

/// プローブの各項目。`token`が出力に現れたら「できた」。
/// トークンは**互いに部分文字列にならない**ようにしてある（`EXECDECL`が`EXECUNDECL`に
/// 含まれると、片方しか成立していなくても両方できたことになる）。
const PROBE_ITEMS: &[(&str, &str)] = &[
    ("traverse-into-subdir", "TRAVOK"),
    ("read-a-file", "READOK"),
    ("write-a-new-file", "WRITEOK"),
    ("exec-undeclared-exe", "RANPAYLOAD"),
    ("exec-declared-exe", "RANDECLARED"),
    ("exec-a-copy-of-the-declared-exe", "RANTHECOPY"),
];

/// プローブ本体。形（1本 / 2本割り）を変えても**同じ文字列**を撃つ。
fn probe_script(root: &Path) -> String {
    let r = root.display().to_string();
    format!(
        "$ErrorActionPreference='SilentlyContinue'; \
         Remove-Item -LiteralPath '{r}\\copy.exe' -Force -ErrorAction SilentlyContinue; \
         Remove-Item -LiteralPath '{r}\\sub\\new.txt' -Force -ErrorAction SilentlyContinue; \
         try {{ if ((Get-Content -LiteralPath '{r}\\sub\\inner.txt' -Raw) -match 'INNERBODY') \
           {{ Write-Output 'TRAVOK' }} }} catch {{ }}; \
         try {{ if ((Get-Content -LiteralPath '{r}\\note.txt' -Raw) -match 'NOTEBODY') \
           {{ Write-Output 'READOK' }} }} catch {{ }}; \
         try {{ Set-Content -LiteralPath '{r}\\sub\\new.txt' -Value 'x' -ErrorAction Stop; \
           Write-Output 'WRITEOK' }} catch {{ }}; \
         try {{ & '{r}\\payload.exe' /c echo RANPAYLOAD }} catch {{ }}; \
         try {{ & '{r}\\declared.exe' /c echo RANDECLARED }} catch {{ }}; \
         try {{ Copy-Item -LiteralPath '{r}\\declared.exe' -Destination '{r}\\copy.exe' \
           -Force -ErrorAction Stop; & '{r}\\copy.exe' /c echo RANTHECOPY }} catch {{ }}; \
         Write-Output 'PROBEFINISHED'"
    )
}

/// プローブを1回撃って、成立した項目の名前を返す。
///
/// `PROBEFINISHED`が無ければ**判定しない**（途中で死んでいれば以降は全部「できなかった」に
/// 見え、それをACEの手柄と読んでしまう。B-12と同型）。
fn probe(container_sid: PSID, capabilities: &[PSID], root: &Path, label: &str) -> Vec<String> {
    let out = run_in_sandbox(container_sid, capabilities, &probe_script(root));
    eprintln!("[d79] --- probe {label} raw ---\n{out}\n[d79] --- end ---");
    assert!(
        out.contains("PROBEFINISHED"),
        "[{label}] プローブが最後まで走っていない。以降の判定は読めない: {out}"
    );
    PROBE_ITEMS
        .iter()
        .filter(|(_, token)| out.contains(token))
        .map(|(name, _)| (*name).to_string())
        .collect()
}

/// **現行の形**: `CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE`を1本、実行権つきで。
///
/// `DaclWrite::Propagate`でなければならない。既定の`SingleObject`は「継承ACEを足しても
/// **既存の**子孫へは届かない」（[`DaclWrite`]のdoc）ので、先に作ったツリーには何も効かず、
/// 全項目が「できなかった」になる——**最初の測定で実際にこれを踏んだ**。製品のroot付与も
/// `grant_ace_propagating`＝Propagateである。
fn grant_current_single_ace(root: &Path, sid: PSID) {
    grant_ace_mask_with(
        root,
        sid,
        workspace_rwx_mask(),
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
        DaclWrite::Propagate,
    )
    .expect("grant the current single inheritable ACE");
}

/// **D-79の形**: 2本に割る。ディレクトリ側は traverse 込み、ファイル側は execute 抜き。
/// 伝播が要る理由は[`grant_current_single_ace`]と同じ。
fn grant_d79_split_aces(root: &Path, sid: PSID) {
    grant_ace_mask_with(
        root,
        sid,
        workspace_rwx_mask(),
        CONTAINER_INHERIT_ACE,
        DaclWrite::Propagate,
    )
    .expect("grant the container-inherit ACE (traverse included)");
    grant_ace_mask_with(
        root,
        sid,
        workspace_rwx_mask() & !EXECUTE_OR_TRAVERSE,
        OBJECT_INHERIT_ACE,
        DaclWrite::Propagate,
    )
    .expect("grant the object-inherit ACE (execute removed)");
}

/// D-79が言う「宣言された実行ファイルには個別に execute の ACE を足す」（非継承のobject ACE、
/// D-63の`GrantScope::Object`と同じ形）。
fn declare_executable(file: &Path, sid: PSID) {
    grant_ace_mask(file, sid, workspace_rwx_mask(), NO_INHERITANCE)
        .expect("grant the per-object exec ACE for a declared executable");
}

// ============================================================================
// M2-0（真偽）: 2本割りは「ディレクトリは辿れる／ファイルは実行できない」を表現できるか
// ============================================================================

/// **これが「実装したら止まるのか」への答えである。**
///
/// 許可側と禁止側を対で測る（`test-logic-rules`問2）——現行の1本構成で**全部できる**ことを
/// 先に確かめないと、2本構成の「できない」が「ACEの形のおかげ」なのか「そもそも到達できて
/// いない」のか区別できない。
#[test]
#[ignore = "spawns real AppContainer children and writes real DACLs; run NON-elevated with --test-threads=1"]
fn d79_split_stops_undeclared_executables_but_keeps_dirs_traversable() {
    let traverse = traverse_capability_sid().expect("traverse capability");
    let container = session_sid();

    // --- 対照（現行の1本構成）。ここが全項目成立しないと、以降は読めない ---
    let baseline_dir = test_support::TestDirGuard::create("d79-baseline");
    let baseline = baseline_dir.path();
    build_probe_tree(baseline);
    let cap_a = measure_capability("baseline");
    grant_current_single_ace(baseline, cap_a.as_psid());
    let caps_a = [traverse.as_psid(), cap_a.as_psid()];
    let ran_a = probe(container.as_psid(), &caps_a, baseline, "current-single-ace");

    // --- 本題（D-79の2本構成） ---
    let split_dir = test_support::TestDirGuard::create("d79-split");
    let split = split_dir.path();
    build_probe_tree(split);
    let cap_b = measure_capability("split");
    grant_d79_split_aces(split, cap_b.as_psid());
    declare_executable(&split.join("declared.exe"), cap_b.as_psid());
    let caps_b = [traverse.as_psid(), cap_b.as_psid()];
    let ran_b = probe(container.as_psid(), &caps_b, split, "d79-two-aces");

    // --- 期待値 ---
    // 2本構成で止まってほしいのは「宣言していない実行ファイル」と「宣言済みexeの複製」だけ。
    // 残りは全部通らなければならない（過剰拒否＝作業場として使えない、を検出する）。
    let expected_b: &[(&str, bool)] = &[
        ("traverse-into-subdir", true),
        ("read-a-file", true),
        ("write-a-new-file", true),
        ("exec-undeclared-exe", false),
        ("exec-declared-exe", true),
        ("exec-a-copy-of-the-declared-exe", false),
    ];

    let mut failures: Vec<String> = Vec::new();
    for (name, _) in PROBE_ITEMS {
        let a = ran_a.iter().any(|n| n == name);
        let b = ran_b.iter().any(|n| n == name);
        let want_b = expected_b
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, w)| *w)
            .expect("every probe item has an expectation for the split shape");
        println!(
            "{}",
            serde_json::json!({
                "probe": name,
                "current_single_ace": a,
                "d79_two_aces": b,
                "d79_expected": want_b,
            })
        );
        if !a {
            failures.push(format!(
                "{name}: 現行の1本構成でも成立しなかった。計器が壊れているので2本構成の結果は読めない"
            ));
            continue;
        }
        if b != want_b {
            failures.push(format!(
                "{name}: 2本構成の期待は{}だが実際は{}",
                if want_b { "できる" } else { "できない" },
                if b { "できた" } else { "できなかった" }
            ));
        }
    }
    assert!(failures.is_empty(), "D-79 split shape:\n{}", failures.join("\n"));
}

// ============================================================================
// M2-a（真偽）: 2本構成で冪等スキップは効くか
// ============================================================================

/// HANDOFFのM2-aは「`sid_explicit_ace`はSIDあたり1本しか返さないので、2本あると片方しか
/// 見つからず`satisfies`が偽になり、**毎起動で再書き込みが走る**のではないか」と疑っていた。
///
/// **実装を読むとそうではない**——`sid_explicit_ace`は同じSIDのACEを**畳んで**返す
/// （`acc.mask |= mask` / `acc.inherit |= flags`、`revoke.rs`）。したがって2本構成でも
/// マスクと継承フラグの**和**が返り、`satisfies`は真になる。**再書き込みは起きない。**
///
/// **ただしこれは良い知らせだけではない。** 畳んだ結果は
/// 「`CONTAINER_INHERIT|OBJECT_INHERIT`かつ実行権あり」に見えるので、
/// **この検査は2本割り（ファイルに実行権が無い）と1本（実行権がある）を区別できない。**
/// D-79を入れたあと、誰かが1本へ戻してもこの検査は何も言わない。ここを実測で固定しておく。
#[test]
#[ignore = "writes real DACLs; run NON-elevated"]
fn d79_split_is_folded_into_one_ace_by_the_idempotent_check() {
    let dir = test_support::TestDirGuard::create("d79-idem");
    let root = dir.path();
    build_probe_tree(root);
    let cap = measure_capability("idem");
    grant_d79_split_aces(root, cap.as_psid());

    let folded = sid_explicit_ace(root, cap.as_psid())
        .expect("read the explicit ACEs")
        .expect("the capability has explicit ACEs on the root");

    let both_flags = (CONTAINER_INHERIT_ACE.0 | OBJECT_INHERIT_ACE.0) as u8;
    println!(
        "{}",
        serde_json::json!({
            "folded_mask": format!("0x{:x}", folded.mask),
            "folded_inherit": folded.inherit,
            "requested_mask": format!("0x{:x}", workspace_rwx_mask()),
            "satisfies_the_single_ace_requirement":
                folded.satisfies(workspace_rwx_mask(), both_flags),
        })
    );

    // (1) 畳まれて「1本ぶんの十分なACE」に見えること＝冪等スキップは効く（再書込は起きない）。
    assert!(
        folded.satisfies(workspace_rwx_mask(), both_flags),
        "2本構成が`satisfies`を満たさない＝毎起動で再書き込みが走る。\
         HANDOFFのM2-aが疑っていたとおりの結果なので、`sid_explicit_ace`を広げる作業が要る。\
         folded={folded:?}"
    );
    // (2) そして**それゆえに**、この検査は2本割りと1本を区別できない。
    //     区別できてしまうならこのassertが落ちるので、そのときは(1)の結論も変わる。
    assert_eq!(
        folded.mask & EXECUTE_OR_TRAVERSE,
        EXECUTE_OR_TRAVERSE,
        "畳んだマスクに実行権が乗っていない。この場合`satisfies`は偽になるはずで、(1)と矛盾する"
    );
}

// ============================================================================
// M2-b / M2-c（時間）: 実装の実行時コスト
// ============================================================================

/// **切り分け（M2-bの前提）**: 「rootへ`SingleObject`で置いてから、`Propagate`＋`Always`で
/// 押し込む」は、既存の子孫へ本当に届くのか。
///
/// M2-bの最初の測定で、この形の2腕だけが**葉に何も降ろしていなかった**（`0x0`）。
/// 速さの比較の前にここを確定させないと、「速い」と「何もしていない」を取り違える。
///
/// **これは製品の高速経路と同じ形である**——`preflight`はrootへ`SingleObject`で先に書き
/// （`grant_workspace_root_rw_fast`）、既存子孫への伝播は背景ジョブの
/// `propagate_workspace_root_grant`（`Always`＋`Propagate`）へ委ねている。したがって
/// ここで届かないなら、それは測定の都合ではなく**製品の経路の性質**である。
#[test]
#[ignore = "writes real DACLs; run NON-elevated"]
fn place_then_force_propagate_versus_a_single_propagating_write() {
    let mut rows = Vec::new();
    for (label, place_first) in [("propagate-only", false), ("place-then-propagate", true)] {
        let dir = test_support::TestDirGuard::create(&format!("d79-prop-{label}"));
        let root = dir.path();
        build_wide_tree(root, 200, 4);
        let cap = measure_capability(&format!("prop-{label}"));
        if place_first {
            grant_ace_mask(
                root,
                cap.as_psid(),
                workspace_rwx_mask(),
                CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
            )
            .expect("place on the root first (SingleObject)");
        }
        grant_ace_mask_with_checked(
            root,
            cap.as_psid(),
            workspace_rwx_mask(),
            CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
            DaclWrite::Propagate,
            IdempotentCheck::Always,
        )
        .expect("propagating write");
        let leaf = root.join("d000").join("f000000.txt");
        let leaf_mask = sid_effective_ace_mask(&leaf, cap.as_psid())
            .expect("read leaf")
            .unwrap_or(0);
        let root_mask = sid_effective_ace_mask(root, cap.as_psid())
            .expect("read root")
            .unwrap_or(0);
        rows.push((label, root_mask, leaf_mask));
        println!(
            "{}",
            serde_json::json!({
                "measurement": "M2-b-precondition",
                "shape": label,
                "root_effective_mask": format!("0x{root_mask:x}"),
                "leaf_effective_mask": format!("0x{leaf_mask:x}"),
                "reached_existing_descendants": leaf_mask != 0,
            })
        );
    }
    // 陽性対照: 素の`Propagate`1回は必ず届く（`d79_split_stops_...`で実効まで確認済みの形）。
    assert_ne!(
        rows[0].2, 0,
        "`Propagate`1回でも既存の子孫へ届いていない。この環境では伝播そのものが測れない"
    );
}

// `build_wide_tree`は`test_support`が持つ（§S10の基準線測定と**同じ形のツリー**でなければ
// 2つの測定の数字を並べられないため、共有の置き場へ移した）。
use super::test_support::build_wide_tree;

fn ms(d: Duration) -> u128 {
    d.as_millis()
}

/// **M2-b**: 継承ACEを1本→2本に割ると、既存ツリーへの伝播コストは何倍になるか。
///
/// 測るのは`DaclWrite::Propagate`（`SetNamedSecurityInfoW`）——**製品がroot付与で使っている
/// のと同じ道具**である（`grant_ace_propagating`）。ここを`SingleObject`で測ると
/// 「伝播していないもの」を測ることになる（BUG-081と同型の取り違え）。
///
/// 仮説A（支配項はツリー歩き）が正しければ 1.0 倍近い。仮説B（支配項はノードごとの書込）
/// なら 2.0 倍に近づく。
///
/// **3つの腕で測る。** HANDOFFが警告しているとおり、「2本目のACEをもう一度伝播させる」形は
/// **仮説Bになる実装を測っているだけ**なので、それだけでは結論にできない。
///
/// | 腕 | 形 | 何を表すか |
/// |---|---|---|
/// | `single` | 1本を1回伝播 | 現行の基準線 |
/// | `naive_split` | 2本を**別々に**2回伝播 | D-79の**素朴な**実装 |
/// | `one_write_split` | rootへ2本載せてから**1回だけ**伝播 | D-79の**あるべき**実装 |
///
/// `one_write_split`の timed 区間は`IdempotentCheck::Always`で回す——2本は既にrootへ
/// 載っているので、既定の冪等スキップだと**伝播そのものが黙って起きない**（BUG-081層1と同型）。
/// 比較のため`single`も同じ`Always`で測る（計器を揃える）。
#[test]
#[ignore = "creates tens of thousands of files and propagates DACLs; run NON-elevated, takes minutes"]
fn d79_cost_of_splitting_the_inherited_ace() {
    for count in [5_000usize, 20_000usize] {
        let dirs: Vec<_> = ["single", "naive", "onewrite"]
            .iter()
            .map(|arm| test_support::TestDirGuard::create(&format!("d79-cost-{arm}-{count}")))
            .collect();
        let mut nodes = 0usize;
        for d in &dirs {
            let n = build_wide_tree(d.path(), count, 32);
            assert!(nodes == 0 || nodes == n, "測定ツリーのノード数が揃っていない");
            nodes = n;
        }
        let caps: Vec<_> = ["single", "naive", "onewrite"]
            .iter()
            .map(|arm| measure_capability(&format!("cost-{arm}-{count}")))
            .collect();

        // --- 腕1: 現行（1本、CI|OI、実行権つき）を`Propagate`で1回 ---
        //
        // **「rootへ`SingleObject`で置いてから`Always`＋`Propagate`で押し込む」形は使えない**
        // ——`place_then_force_propagate_versus_a_single_propagating_write`の実測どおり、
        // 既存の子孫へ届かない（葉が`0x0`）。最初の版はこれで測ってしまい、
        // 「何もしていない」を「速い」と読みかけた。
        let root = dirs[0].path();
        let sid = caps[0].as_psid();
        let t = Instant::now();
        grant_ace_mask_with(
            root,
            sid,
            workspace_rwx_mask(),
            CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
            DaclWrite::Propagate,
        )
        .expect("propagate the single ACE once");
        let single = t.elapsed();

        // --- 腕2: 素朴な2本割り（別々に2回伝播） ---
        let root = dirs[1].path();
        let sid = caps[1].as_psid();
        let t = Instant::now();
        grant_ace_mask_with(
            root,
            sid,
            workspace_rwx_mask(),
            CONTAINER_INHERIT_ACE,
            DaclWrite::Propagate,
        )
        .expect("propagate the container-inherit ACE");
        let naive_first = t.elapsed();
        let t = Instant::now();
        grant_ace_mask_with(
            root,
            sid,
            workspace_rwx_mask() & !EXECUTE_OR_TRAVERSE,
            OBJECT_INHERIT_ACE,
            DaclWrite::Propagate,
        )
        .expect("propagate the object-inherit ACE");
        let naive_total = naive_first + t.elapsed();

        // --- 腕3: あるべき2本割り（**伝播を1回で済ませる**） ---
        //
        // 先にOI側（execute抜き）を`SingleObject`でrootへ**置くだけ**にする（伝播しない＝安い）。
        // 続くCI側の書込は**DACLが変わる**ので伝播が起き、そのとき運ばれるDACLには
        // 2本とも載っている。**伝播1回で2本を配れるか**を、これで測る。
        // 「置いてから同じものをもう一度書く」形が届かないのは、DACLが変わらないためである
        // （上記の切り分けテスト）。ここは変わるので届くはず——**降りたかを葉で確かめる。**
        let root = dirs[2].path();
        let sid = caps[2].as_psid();
        grant_ace_mask(
            root,
            sid,
            workspace_rwx_mask() & !EXECUTE_OR_TRAVERSE,
            OBJECT_INHERIT_ACE,
        )
        .expect("place the object-inherit ACE on the root (no propagation yet)");
        let t = Instant::now();
        grant_ace_mask_with(
            root,
            sid,
            workspace_rwx_mask(),
            CONTAINER_INHERIT_ACE,
            DaclWrite::Propagate,
        )
        .expect("one propagating write that carries both ACEs");
        let one_write = t.elapsed();

        // **3腕すべての葉を読み返す**（B-25: 書いたことと効いたことは別）。
        // 1腕だけ見ると、「速い」のか「伝播していない」のかを取り違える——最初の測定で
        // 実際に腕3の葉が`0x0`になり、それに気づかず1.0倍と読みかけた。
        // 素朴な2本割り（腕2）は`d79_split_stops_...`で実効まで確認済みなので、**これが陽性対照**である。
        let leaf_of = |i: usize| -> u32 {
            let leaf = dirs[i].path().join("d000").join("f000000.txt");
            sid_effective_ace_mask(&leaf, caps[i].as_psid())
                .expect("read the leaf ACE")
                .unwrap_or(0)
        };
        let (single_leaf, naive_leaf, one_write_leaf) = (leaf_of(0), leaf_of(1), leaf_of(2));
        let folded = sid_explicit_ace(dirs[2].path(), caps[2].as_psid())
            .expect("read back the root ACEs")
            .expect("the root carries explicit ACEs");
        let leaf_mask = one_write_leaf;

        let ratio = |d: Duration| (d.as_secs_f64() / single.as_secs_f64() * 100.0).round() / 100.0;
        println!(
            "{}",
            serde_json::json!({
                "measurement": "M2-b",
                "files": count,
                "nodes": nodes,
                "single_ms": ms(single),
                "naive_split_ms": ms(naive_total),
                "one_write_split_ms": ms(one_write),
                "ratio_naive_over_single": ratio(naive_total),
                "ratio_one_write_over_single": ratio(one_write),
                "single_us_per_node": (single.as_micros() as f64 / nodes as f64).round(),
                "one_write_us_per_node": (one_write.as_micros() as f64 / nodes as f64).round(),
                "one_write_root_folded_mask": format!("0x{:x}", folded.mask),
                "leaf_effective_mask": {
                    "single": format!("0x{single_leaf:x}"),
                    "naive_split": format!("0x{naive_leaf:x}"),
                    "one_write_split": format!("0x{one_write_leaf:x}"),
                },
            })
        );

        // 陽性対照: 素朴な2本割り（実効まで確認済みの形）は葉へ届いていなければならない。
        assert_ne!(
            naive_leaf, 0,
            "陽性対照が落ちた。伝播そのものがこの測定環境で起きていないので、\
             他の腕の時間は「速い」ではなく「何もしていない」かもしれない"
        );
        // 現行の1本は葉へ実行権つきで届く。
        assert_eq!(
            single_leaf & EXECUTE_OR_TRAVERSE,
            EXECUTE_OR_TRAVERSE,
            "現行の1本構成なのに葉に実行権が無い（0x{single_leaf:x}）"
        );
        // 2本割りは葉に実行権を降ろさない。
        assert_eq!(
            naive_leaf & EXECUTE_OR_TRAVERSE,
            0,
            "素朴な2本割りの葉に実行権がある（0x{naive_leaf:x}）"
        );
        // 腕3は**成立しない**。これは実測で確定した性質なので、そのまま固定する。
        //
        // 「OI側を`SingleObject`でrootへ置いてから、CI側の書込で伝播させる」——DACLは
        // 確かに変わるのに、既存の子孫へは何も降りない（葉が`0x0`）。
        // `place_then_force_propagate_versus_a_single_propagating_write`と合わせると、
        // **rootへ一度でも`SingleObject`で書くと、以後の`Propagate`が子孫へ届かなくなる**
        // という形に見える（機序は未測定・推定）。
        //
        // したがって「1回の伝播で2本を配る」形は**現状の部品では作れない**。作るには
        // 「2本のACEを含むDACLを1つ組んで`SetNamedSecurityInfoW`を1回」という新しい部品が要る。
        // **腕3の時間は比較に使ってはいけない**（伝播していないので速いだけである）。
        assert_eq!(
            leaf_mask, 0,
            "腕3が既存の子孫へ届いた（0x{leaf_mask:x}）。**この測定の結論が変わる**——\
             1回の伝播で2本を配れることになるので、D-79のコストは約1.0倍になる。\
             上のコメントと`plans/mac-spike/RESULTS.md`の§S9を書き直すこと"
        );
    }
}

/// **M2-c**: 宣言された実行ファイルへの非継承object ACEを N 件足すコスト（N = 1/10/100）。
#[test]
#[ignore = "writes real DACLs; run NON-elevated"]
fn d79_cost_of_per_object_exec_aces() {
    let dir = test_support::TestDirGuard::create("d79-cost-object");
    let root = dir.path();
    let nodes = build_wide_tree(root, 100, 4);
    let cap = measure_capability("cost-object");
    grant_d79_split_aces(root, cap.as_psid());

    let files: Vec<PathBuf> = (0..100)
        .map(|i| root.join(format!("d{:03}", i % 4)).join(format!("f{i:06}.txt")))
        .collect();

    let mut done = 0usize;
    for target in [1usize, 10usize, 100usize] {
        let t = Instant::now();
        for file in &files[done..target] {
            declare_executable(file, cap.as_psid());
        }
        let elapsed = t.elapsed();
        done = target;
        println!(
            "{}",
            serde_json::json!({
                "measurement": "M2-c",
                "declared_up_to": target,
                "this_batch": target - (if target == 1 { 0 } else if target == 10 { 1 } else { 10 }),
                "batch_ms": ms(elapsed),
                "tree_nodes": nodes,
            })
        );
    }
}
