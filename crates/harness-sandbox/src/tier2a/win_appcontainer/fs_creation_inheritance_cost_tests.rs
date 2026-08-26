//! **「作る前に札を置く」は本当に無料か、既存ツリーを運ぶといくらか**
//! （[`plans/HANDOFF-FS-BOUNDARY-STATIC-ACE.md`](../../../../../plans/HANDOFF-FS-BOUNDARY-STATIC-ACE.md)
//! の「Bの内訳 — 名前空間を変える」）。結果は `plans/handoff/fs-boundary-cost/T-3.md`。
//!
//! # なぜ測るのか
//!
//! いまのFS境界は、許可したいツリーの**全ノードのDACLへ**サンドボックス主体宛のACEを配る。
//! 26万ノードで初回22.5秒・撤収18.7秒・一巡61.4秒である（`plans/mac-spike/RESULTS.md` §S12）。
//!
//! Microsoftが薦める形はこれではない——**空のルートへ継承する札（inheritable ACE）を1本置いて
//! から中身を作る**。子は作成の瞬間に親のDACLから継承ACLを計算して持つので、
//! **中身が何件でも配布の費用がゼロになる**はずである（[Automatic Propagation of Inheritable
//! ACEs](https://learn.microsoft.com/en-us/windows/win32/secauthz/automatic-propagation-of-inheritable-aces)。
//! 逆に**既存**ツリーへの後付けは、カーネルに一括経路が無くuser-modeのライブラリが1件ずつ
//! 書くので必ずO(N)になる）。
//!
//! **効くのはこれから作るツリーだけである。** 既存の26万ノードには効かない。だから測るのは2つ:
//!
//! | # | 問い | 腕 |
//! |---|---|---|
//! | 1 | 作成時継承の**限界費用**は本当にゼロか | 継承ACE**有り**の空ルートと**無し**の空ルートへ同じN件を作り、**その差**を見る |
//! | 2 | 既存ツリーを**運ぶ**といくらか | 同一NTFSボリューム内の**コピー**・**移動**と、その場でACEを配る**対照**を同じ実行で並べる |
//!
//! # この測定が言わないこと（**外挿しないこと**）
//!
//! - **ファイルは1バイトである**（[`super::test_support::build_wide_tree`]が`b"x"`を書く）。
//!   したがって腕2のコピーは**メタデータの床**であって、実ワークスペースのバイト複製の費用を
//!   含まない。**実物はこれより必ず高い。**
//! - **ReFSのブロッククローン（メタデータだけの複製）は測っていない。**
//!   この開発機にReFSボリュームが無いためで、**推定で埋めない**
//!   （実測した素性は `docs/DEV-ENVIRONMENT.md`「この開発機のドライブの素性」）。
//! - **ツリーは深さ2段固定**（§S9・§S10・§S12と同じ形）。深さの効果は§S15が別に測っている。
//! - **`preflight`を通していない。** 基本操作を直接呼んでいる（§S10と同じ限界）。
//!
//! # 実行
//!
//! **昇格しない。** ACEを書くのはテスト自身が作ったツリーだけで、主体は
//! `capability_sid_from_name`（純粋導出）＝**台帳にもプロファイルにも何も残さない**。
//!
//! ```text
//! HARNESS_T3_COST_NODES=2000,20000 cargo test -p harness-sandbox --lib -- \
//!     --ignored --test-threads=1 --nocapture fs_cost_t3
//! ```
//!
//! **判定が出たら本ファイルは削除する**（`docs/CODE-STRUCTURE-RULES.md`規則2）。

use std::path::{Path, PathBuf};
use std::time::Instant;

use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{CopyFileW, MoveFileW};

use super::test_support::{build_wide_tree, TestDirGuard};
use super::*;

/// §S9・§S10・§S12・§S13と同じfanout。**形が違うと数字を並べられない。**
const FANOUT: usize = 32;

/// 既定のファイル数（2点）。小さい側は「差がノイズに埋もれていないか」を見るため、
/// 大きい側は§S10-1の突き合わせ点（20,033ノード）に合わせるため。
const DEFAULT_FILE_COUNTS: [usize; 2] = [2_000, 20_000];

/// 腕あたりの繰り返し回数。**1回では機械の温まり方と腕の差を区別できない。**
///
/// **偶数にしてある。** 腕の実行順を回ごとに入れ替えるので（下記）、奇数だと片方の順序が
/// 1回多くなって偏りが残る。
///
/// **順序を入れ替える理由は実測で分かった。** 最初は毎回「札なし → 札あり」の固定順で
/// 回したところ、差が**負**（札ありのほうが速い）に出た——2万件のツリーを消した直後に
/// 次の計測が始まるので、**先に走る腕がその後片付けを吸う**。順序を入れ替えると、
/// この偏りが両方の腕へ等しく掛かる。
const REPEATS: usize = 4;

/// **事前配布の1ノードあたり費用**（`plans/mac-spike/RESULTS.md` §S12-1の実測、
/// 26万ノードで22,484 ms ÷ 260,033ノード）。移行費用の相手側として使う。
///
/// **この定数は測定値の転記である。** §S12を測り直したらここも直すこと。
const EAGER_US_PER_NODE: f64 = 86.5;

fn file_counts() -> Vec<usize> {
    match std::env::var("HARNESS_T3_COST_NODES") {
        Ok(v) => {
            let parsed: Vec<usize> = v
                .split(',')
                .filter_map(|p| p.trim().parse::<usize>().ok())
                .collect();
            if parsed.is_empty() {
                DEFAULT_FILE_COUNTS.to_vec()
            } else {
                parsed
            }
        }
        Err(_) => DEFAULT_FILE_COUNTS.to_vec(),
    }
}

/// 測定用のcapability SIDを**名前から導出**する。`workspace_capability_sid`は使わない
/// ——あちらはworkspace＋mode単位の秘密を`%APPDATA%`の台帳へ永続化するので、測定が実マシンへ
/// 記録を残す（HANDOFFの「やってはいけないこと」2番）。
fn measure_capability(label: &str) -> crate::win_common::OwnedSid {
    let name = format!("harness-fs-cost-t3-{}-{label}", std::process::id());
    super::capability_sid_from_name(&name).expect("derive capability sid")
}

/// 撤収し、**残っていないことを実測してから**ツリーを消す（B-25・BUG-101）。
/// 付与と撤収は対にする（B-01）——ツリーごと消えるとしても、剥がせることを毎回確かめる。
fn revoke_and_verify(root: &Path, sid: PSID) -> u128 {
    let started = Instant::now();
    let report = revoke_ace_recursive(root, sid).expect("revoke the measurement ACEs");
    let elapsed = started.elapsed().as_millis();
    if let Err(leftovers) = assert_no_sid_ace_recursive(root, sid) {
        panic!(
            "the measurement SID still has ACEs on {} node(s) after revoke (report={report:?}); \
             first few: {:?}",
            leftovers.len(),
            leftovers.iter().take(5).collect::<Vec<_>>()
        );
    }
    elapsed
}

/// **全ノードを読み返して、札が本当に載っているかを数える。**
///
/// 「継承させた」と「載っている」は別の事実である。末端1件だけを見ると、浅いところに
/// 載って深いところに載っていない形を拾えない——`granted`（継承が届かず明示ACEを書いた数）が
/// 0であることが、**全N件に載っている**の直接の証拠になる。
///
/// 副作用として足りないノードには書き込むが、その場合は`granted > 0`で失敗するので
/// 「黙って直して緑になる」ことはない。
fn assert_every_node_carries(root: &Path, sid: PSID, mask: u32, nodes: usize, label: &str) {
    let report = fix_descendants_missing_ace(root, sid, mask, &[], &|_, _| {})
        .unwrap_or_else(|e| panic!("{label}: read back every node: {e}"));
    assert_eq!(
        report.checked, nodes,
        "{label}: the walk must visit every node before its `granted` can be read"
    );
    assert_eq!(
        report.probe_errors, 0,
        "{label}: a node whose DACL could not be read is counted as granted, which would make \
         the check meaningless"
    );
    assert_eq!(
        report.granted, 0,
        "{label}: {} of {} nodes did NOT carry the inheritable ACE — creation-time inheritance \
         did not actually reach them, so any timing above is measuring the wrong thing",
        report.granted, report.checked
    );
}

/// 平らなツリー（[`build_wide_tree`]、深さ2段）の末端。
fn wide_tree_leaves(root: &Path) -> (PathBuf, PathBuf) {
    let dir = root.join("d000");
    let file = dir.join("f000000.txt");
    (dir, file)
}

fn median(mut xs: Vec<u128>) -> u128 {
    xs.sort_unstable();
    xs[xs.len() / 2]
}

/// **最小値も出す理由**: この測定のノイズは片側にしか出ない（他のプロセス・遅延書き戻し・
/// 直前のツリー削除は所要時間を**伸ばす**方向にしか働かない）。中央値は外れ値には強いが
/// 片側ノイズの下駄をそのまま履くので、**「じゃまが入らなかった1回」を代表値として
/// 並べたほうが、腕の差だけを見られる**。両方を出して食い違わないことを見る。
fn minimum(xs: &[u128]) -> u128 {
    *xs.iter().min().expect("at least one repetition")
}

// ===========================================================================
// 1. 作成時継承の限界費用
// ===========================================================================

/// 1腕: 空のルートを作り、`with_ace`なら継承ACEを1本置いてから、N件を**作る時間**を測る。
///
/// **測る区間は[`build_wide_tree`]だけ**である。札を置く操作そのもの（1オブジェクトへの
/// DACL書込1回）は区間の外に置いてある——§S10-1が「どのサイズでも1 ms以下」と測っており、
/// **これから作る中身の件数に依存しない**ので、限界費用の問いには入らない。
fn measure_creation(
    label: &str,
    count: usize,
    sid: PSID,
    with_ace: bool,
    mask: u32,
) -> (u128, usize, u128) {
    let dir = TestDirGuard::create(label);
    let root = dir.path();

    // 札を置く操作そのものの値段（1オブジェクトへのDACL書込1回）。**中身の件数に
    // 依存しないので限界費用の問いには入らない**が、「置く側もタダか」は別の問いなので出す。
    let mut label_ms = 0;
    if with_ace {
        // 空のルートへ`OBJECT_INHERIT | CONTAINER_INHERIT`のACEを1本。**伝播は要らない**
        // ——配る相手がまだ1件も無い。これが`grant_workspace_root_rw_fast`
        // （`DaclWrite::SingleObject`）そのものである。
        let started = Instant::now();
        grant_workspace_root_rw_fast(root, sid).expect("inheritable ACE on the empty root");
        label_ms = started.elapsed().as_millis();
    }

    // --- 測る区間はここだけ ---
    let started = Instant::now();
    let nodes = build_wide_tree(root, count, FANOUT);
    let elapsed = started.elapsed().as_millis();

    // --- 検算: 末端（ファイルとディレクトリの両方）に載ったか／載っていないか ---
    let (leaf_dir, leaf_file) = wide_tree_leaves(root);
    for leaf in [&leaf_dir, &leaf_file] {
        let effective = sid_effective_ace_mask(leaf, sid).unwrap_or_else(|e| {
            panic!(
                "{label}: read the effective mask of {}: {e}",
                leaf.display()
            )
        });
        if with_ace {
            assert_eq!(
                effective,
                Some(mask),
                "{label}: {} must carry exactly the mask the root declared",
                leaf.display()
            );
        } else {
            assert_eq!(
                effective,
                None,
                "{label}: the control arm placed no ACE, so {} must carry none — if it does, the \
                 two arms are not measuring different things",
                leaf.display()
            );
        }
    }

    if with_ace {
        assert_every_node_carries(root, sid, mask, nodes, label);
        revoke_and_verify(root, sid);
    }

    (elapsed, nodes, label_ms)
}

/// **1: 作成時継承の限界費用はゼロか。**
///
/// # 何が分かれば答えになるのか
///
/// 「札を置いてから作る」形が採れるかどうかは、**札があることで中身の作成が遅くならないか**で
/// 決まる。遅くなるとしても、それは1件あたりの定数——だから
/// **(継承ACE有りでN件作る時間) − (無しで同じN件を作る時間) ÷ N** を見る。
///
/// 事前配布の1ノードあたり（[`EAGER_US_PER_NODE`] = 86.5 µs）と比べて桁違いに小さければ
/// 「実質ゼロ」と言ってよい。
///
/// # 対照を必ず取る（B-35）
///
/// 継承ACE無しの腕が要る。無いと「1件あたり数µs」が**継承のせいなのか、この機械の
/// ファイル作成がそもそもそのくらいなのか**を言えない。腕は交互に回す
/// （片方をまとめて回すと、ディスクキャッシュの温まり方がそのまま腕の差に化ける）。
#[test]
#[ignore = "creates tens of thousands of files and writes DACLs; run NON-elevated"]
fn fs_cost_t3_creation_time_inheritance_marginal_cost() {
    let mask = workspace_rwx_mask();
    let mut per_size = Vec::new();

    for &count in &file_counts() {
        let sid = measure_capability(&format!("create{count}"));
        let mut without = Vec::new();
        let mut with = Vec::new();
        let mut label_costs = Vec::new();
        let mut nodes_seen = 0usize;

        for rep in 0..REPEATS {
            // **回ごとに順序を入れ替える**（偏りの理由は[`REPEATS`]のdoc）。
            let ace_first = rep % 2 == 1;
            let run = |with_ace: bool| {
                let kind = if with_ace { "ace" } else { "plain" };
                measure_creation(
                    &format!("t3c-{kind}-{count}-{rep}"),
                    count,
                    sid.as_psid(),
                    with_ace,
                    mask,
                )
            };
            let ((plain_ms, nodes_a, _), (ace_ms, nodes_b, label_ms)) = if ace_first {
                let b = run(true);
                let a = run(false);
                (a, b)
            } else {
                let a = run(false);
                let b = run(true);
                (a, b)
            };
            assert_eq!(
                nodes_a, nodes_b,
                "the two arms must build identical trees, otherwise their timings differ for a \
                 reason other than the inheritable ACE"
            );
            nodes_seen = nodes_a;
            without.push(plain_ms);
            with.push(ace_ms);
            label_costs.push(label_ms);
            eprintln!(
                "  [{count}/rep{rep}] order={} no-ace={plain_ms} ms, with-ace={ace_ms} ms \
                 (placing the label took {label_ms} ms)",
                if ace_first {
                    "ace-first"
                } else {
                    "plain-first"
                }
            );
        }

        let med_without = median(without.clone());
        let med_with = median(with.clone());
        let delta_med = med_with as i128 - med_without as i128;
        let delta_min = minimum(&with) as i128 - minimum(&without) as i128;
        let per_file_us = |delta: i128| (delta as f64) * 1000.0 / (count as f64);

        per_size.push(serde_json::json!({
            "file_count": count,
            "nodes": nodes_seen,
            "no_ace_ms": without,
            "with_ace_ms": with,
            "place_the_label_ms": label_costs,
            "median_no_ace_ms": med_without,
            "median_with_ace_ms": med_with,
            "min_no_ace_ms": minimum(&without),
            "min_with_ace_ms": minimum(&with),
            "delta_median_ms": delta_med,
            "delta_min_ms": delta_min,
            "marginal_us_per_file_from_median": per_file_us(delta_med),
            "marginal_us_per_file_from_min": per_file_us(delta_min),
            "eager_us_per_node_for_comparison": EAGER_US_PER_NODE,
            "marginal_over_eager_from_min": per_file_us(delta_min) / EAGER_US_PER_NODE,
        }));
    }

    println!(
        "{}",
        serde_json::json!({
            "measurement": "T-3 (1) marginal cost of creating N nodes under an inheritable ACE",
            "fanout": FANOUT,
            "repeats": REPEATS,
            "arms": per_size,
        })
    );
}

// ===========================================================================
// 2. 既存ツリーを運ぶ費用
// ===========================================================================

/// `src`のツリーを`dst`へ**1件ずつ`CopyFileW`で**複製する。ディレクトリは先に作る。
///
/// **`CopyFileW`はソースのセキュリティ記述子を運ばない**（運ぶのは`CopyFileEx`の
/// `COPY_FILE_*`でもなく、`SetNamedSecurityInfo`を別に呼ぶ側の仕事である）。
/// したがって複製先のDACLは**複製先の親から作成時継承で決まる**——それがこの腕で
/// 確かめたいことそのものである。
fn copy_tree(src: &Path, dst: &Path, dirs: &[PathBuf], files: &[PathBuf]) {
    for dir in dirs {
        let rel = dir.strip_prefix(src).expect("a collected dir is under src");
        if rel.as_os_str().is_empty() {
            continue; // rootは呼び出し側が先に作ってある（札を置くため）
        }
        std::fs::create_dir_all(dst.join(rel)).expect("create the destination directory");
    }
    for file in files {
        let rel = file
            .strip_prefix(src)
            .expect("a collected file is under src");
        let target = dst.join(rel);
        let from = crate::win_common::long_path_wide(file);
        let to = crate::win_common::long_path_wide(&target);
        unsafe {
            CopyFileW(PCWSTR(from.as_ptr()), PCWSTR(to.as_ptr()), true).unwrap_or_else(|e| {
                panic!("CopyFileW {} -> {}: {e}", file.display(), target.display())
            });
        }
    }
}

/// **2: 既存ツリーを、札が既に載ったルートへ運ぶといくらか。**
///
/// # 3つを同じ実行で並べる（B-35）
///
/// | 腕 | 何をするか | 何が分かるか |
/// |---|---|---|
/// | `inplace_grant` | その場で全ノードへACEを配る（**対照**） | いま払っている値段。§S12-1と並べて計器を検算する |
/// | `copy` | 札の載ったルートへ`CopyFileW`で1件ずつ複製 | 運ぶ値段（**1バイトファイルなのでメタデータの床**） |
/// | `move` | 札の載ったルートへ`MoveFileW`で丸ごと1回 | 最も安い「運ぶ」——**ただし札が載るかは別の事実** |
///
/// **`move`の腕は時間ではなく真偽を測るためにある。** 同一ボリューム内の`MoveFileW`は
/// リネームなのでO(1)だが、NTFSは移動したオブジェクトのDACLを**そのまま持ち越す**——
/// 新しい親の継承ACEは適用されない。ここが`None`なら「移動では運べない＝コピーしかない」が
/// 実測で固まる。
#[test]
#[ignore = "creates tens of thousands of files, copies them, and writes DACLs; run NON-elevated"]
fn fs_cost_t3_carrying_an_existing_tree_into_an_ace_bearing_root() {
    let mask = workspace_rwx_mask();
    let mut per_size = Vec::new();

    for &count in &file_counts() {
        // --- 対照: その場で配る ---
        let inplace = {
            let dir = TestDirGuard::create(&format!("t3m-inplace-{count}"));
            let root = dir.path();
            let nodes = build_wide_tree(root, count, FANOUT);
            let sid = measure_capability(&format!("inplace{count}"));

            let started = Instant::now();
            grant_ace_inheritable_rw(root, sid.as_psid()).expect("in-place grant over the tree");
            let ms = started.elapsed().as_millis();

            assert_every_node_carries(root, sid.as_psid(), mask, nodes, "inplace");
            let revoke_ms = revoke_and_verify(root, sid.as_psid());
            eprintln!("  [{count}] inplace_grant={ms} ms (revoke {revoke_ms} ms)");
            serde_json::json!({
                "arm": "inplace_grant",
                "nodes": nodes,
                "ms": ms,
                "us_per_node": (ms as f64) * 1000.0 / (nodes as f64),
                "revoke_ms": revoke_ms,
            })
        };

        // --- 腕1: コピー ---
        let copy = {
            let src_guard = TestDirGuard::create(&format!("t3m-copysrc-{count}"));
            let src = src_guard.path();
            let nodes = build_wide_tree(src, count, FANOUT);

            let dst_guard = TestDirGuard::create(&format!("t3m-copydst-{count}"));
            let dst = dst_guard.path();
            let sid = measure_capability(&format!("copy{count}"));
            grant_workspace_root_rw_fast(dst, sid.as_psid())
                .expect("inheritable ACE on the empty destination root");

            // 列挙は測る区間の外（運ぶ費用の話をしているので、走査は別勘定）。
            let mut dirs = Vec::new();
            let mut files = Vec::new();
            super::acl_grant::collect_dirs_and_files(src, &mut dirs, &mut files, OnVanished::Abort)
                .expect("enumerate the source tree");
            let bytes: u64 = files
                .iter()
                .filter_map(|f| std::fs::metadata(f).ok().map(|m| m.len()))
                .sum();

            // --- 測る区間はここだけ ---
            let started = Instant::now();
            copy_tree(src, dst, &dirs, &files);
            let ms = started.elapsed().as_millis();

            let (leaf_dir, leaf_file) = wide_tree_leaves(dst);
            for leaf in [&leaf_dir, &leaf_file] {
                let effective = sid_effective_ace_mask(leaf, sid.as_psid())
                    .unwrap_or_else(|e| panic!("copy: read {}: {e}", leaf.display()));
                assert_eq!(
                    effective,
                    Some(mask),
                    "copy: the copied {} must inherit the destination root's ACE at creation time",
                    leaf.display()
                );
            }
            assert_every_node_carries(dst, sid.as_psid(), mask, nodes, "copy");
            let revoke_ms = revoke_and_verify(dst, sid.as_psid());
            eprintln!("  [{count}] copy={ms} ms ({bytes} bytes)");
            serde_json::json!({
                "arm": "copy",
                "nodes": nodes,
                "ms": ms,
                "us_per_node": (ms as f64) * 1000.0 / (nodes as f64),
                "source_bytes": bytes,
                "revoke_ms": revoke_ms,
            })
        };

        // --- 腕2: 移動 ---
        let moved = {
            let src_guard = TestDirGuard::create(&format!("t3m-movesrc-{count}"));
            let src = src_guard.path();
            let nodes = build_wide_tree(src, count, FANOUT);

            let parent_guard = TestDirGuard::create(&format!("t3m-movedst-{count}"));
            let parent = parent_guard.path();
            let sid = measure_capability(&format!("move{count}"));
            grant_workspace_root_rw_fast(parent, sid.as_psid())
                .expect("inheritable ACE on the empty destination parent");

            let target = parent.join("carried");
            let from = crate::win_common::long_path_wide(src);
            let to = crate::win_common::long_path_wide(&target);

            // --- 測る区間はここだけ ---
            let started = Instant::now();
            unsafe {
                MoveFileW(PCWSTR(from.as_ptr()), PCWSTR(to.as_ptr()))
                    .expect("MoveFileW within the same volume");
            }
            let ms = started.elapsed().as_millis();

            // **札が載ったか。** 時間ではなくここが本題。
            let (leaf_dir, leaf_file) = wide_tree_leaves(&target);
            let leaf_dir_mask = sid_effective_ace_mask(&leaf_dir, sid.as_psid())
                .expect("read the moved leaf directory");
            let leaf_file_mask = sid_effective_ace_mask(&leaf_file, sid.as_psid())
                .expect("read the moved leaf file");
            let root_mask =
                sid_effective_ace_mask(&target, sid.as_psid()).expect("read the moved root");
            eprintln!(
                "  [{count}] move={ms} ms, moved-root={root_mask:?}, \
                 leaf-dir={leaf_dir_mask:?}, leaf-file={leaf_file_mask:?}"
            );

            // **先に「運べたこと」を確かめる。** 中身が消えていたら、下の`None`は
            // 「札が載らなかった」ではなく「見る相手が居なかった」になる（B-35）。
            assert!(
                leaf_file.is_file(),
                "move: the tree must still be there after the rename ({})",
                leaf_file.display()
            );
            // **実測で固定する事実**: 同一ボリューム内の`MoveFileW`はリネームなので、
            // 移動したオブジェクトはDACLを持ち越し、**新しい親の継承ACEは1件も適用されない**。
            // だから「安い運び方」は札を運ばない——運ぶにはコピーが要る。
            // ここが`Some(..)`に変わったらT-3の結論が覆るので、先に結果文書を読み直すこと。
            for (what, observed) in [
                ("root", root_mask),
                ("leaf directory", leaf_dir_mask),
                ("leaf file", leaf_file_mask),
            ] {
                assert_eq!(
                    observed, None,
                    "move: the moved {what} must NOT have picked up the destination parent's \
                     inheritable ACE — a same-volume rename carries the old DACL over. If this \
                     is now Some(..), the T-3 conclusion (moving cannot carry the label) is wrong."
                );
            }

            // 親には札が残っているので、移動先ごと剥がしてから消す（付与と撤収は対）。
            let revoke_ms = revoke_and_verify(parent, sid.as_psid());
            serde_json::json!({
                "arm": "move",
                "nodes": nodes,
                "ms": ms,
                "moved_root_mask": root_mask,
                "moved_leaf_dir_mask": leaf_dir_mask,
                "moved_leaf_file_mask": leaf_file_mask,
                "revoke_ms": revoke_ms,
            })
        };

        per_size.push(serde_json::json!({
            "file_count": count,
            "inplace_grant": inplace,
            "copy": copy,
            "move": moved,
        }));
    }

    println!(
        "{}",
        serde_json::json!({
            "measurement": "T-3 (2) cost of carrying an existing tree into an ACE-bearing root",
            "fanout": FANOUT,
            "note": "files are 1 byte each; the copy arm is a metadata floor, not a real workspace",
            "arms": per_size,
        })
    );
}

/// **この開発機にReFSボリュームがあるか**を、本番の判定部品で数え上げる。
///
/// # なぜテストの形にするのか
///
/// 「無いので測れない」と書く前に、**無いことを実測しておく**ため。ReFSの
/// ブロッククローン（同一ボリューム内の複製をメタデータだけで済ませる仕組み、
/// Win11 24H2以降は`CopyFileW`が自動で使う）は、もしReFSがあれば腕1の値段を
/// 大きく変え得る——**だから「測っていない」ではなく「測れる相手が居ない」**である
/// ことを、判定部品（[`crate::win_common::volume_capability`]）の出力で残す。
///
/// **ボリュームを新しく作る／マウントするのは昇格が要るので、既存のものだけを見る。**
#[test]
#[ignore = "enumerates this machine's volumes; run NON-elevated"]
fn fs_cost_t3_inventory_of_volumes_for_block_cloning() {
    let mut rows = Vec::new();
    let mut refs_roots = Vec::new();
    for root in crate::win_common::logical_drive_roots() {
        let cap = crate::win_common::volume_capability(&root);
        let filesystem = cap.as_ref().map(|c| c.filesystem.clone());
        if filesystem
            .as_deref()
            .is_some_and(|f| f.eq_ignore_ascii_case("ReFS"))
        {
            refs_roots.push(root.display().to_string());
        }
        rows.push(serde_json::json!({
            "root": root.display().to_string(),
            "filesystem": filesystem,
            "persistent_acls": cap.as_ref().map(|c| c.persistent_acls),
            "is_remote": cap.as_ref().map(|c| c.is_remote),
        }));
    }

    println!(
        "{}",
        serde_json::json!({
            "measurement": "T-3 (2b) is there a ReFS volume on this machine",
            "volumes": rows,
            "refs_roots": refs_roots,
        })
    );
}
