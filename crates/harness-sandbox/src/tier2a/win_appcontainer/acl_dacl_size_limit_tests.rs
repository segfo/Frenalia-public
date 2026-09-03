//! **DACLに載るACEの本数には上限がある。どこで当たり、当たったときどう失敗するのか。**
//! （`plans/HANDOFF-ACL-DOMAIN-SPLIT-COST.md` のM3-b、結果の正本は `plans/mac-spike/RESULTS.md` §S15）
//!
//! # なぜ測るのか
//!
//! 残課題#20 の費用の変数は「同一ノードに載るACE本数 M」で、**設計上の上限は3**である
//! （1つの宣言パスにつき`ro`/`rw`/`rx`）。3なら上限には遠い。**それでもこの問いは消えない**
//! ——宣言パスが多い実ポリシーでは、深いノードに**祖先由来の継承ACEが重なる**ためである。
//! 祖先が10段あって各段が3本宣言していれば、葉には30本載る。
//!
//! # 測るのは2つで、大事なのは2つ目である
//!
//! | # | 問い |
//! |---|---|
//! | 1 | **どこで当たるか**（1ノードに何本まで入るか） |
//! | 2 | **当たったときどう失敗するか**——エラーが返るのか、**黙って切り捨てられるのか** |
//!
//! **無言で切り捨てられるなら、それ自体が欠陥の種である。** 「許可を配ったつもりで配れて
//! いない」は、このリポジトリが繰り返し踏んでいる形（成功に見える失敗）そのもので、
//! しかもDACLの場合は**権限が減る方向**にも**残る方向**にも転びうる。
//!
//! # 前提として書いていないこと
//!
//! HANDOFFは「ACLには64KBの上限がある」と書いているが、**本モジュールはそれを前提にしない。**
//! ACLのサイズ欄が16ビットである以上65,535バイトが構造上の限界だ、というのは仕様の話であって、
//! **「何本入るか」でも「どう失敗するか」でもない。** だから最初の一歩は
//! **capability ACE 1本が何バイトかの実測**である（計算しない）。
//!
//! # 実行
//!
//! **非昇格。** ACEを書くのはテスト自身が作ったツリーだけで、宛先SIDは
//! [`super::capability_sid_from_name`]の純粋導出（台帳にもプロファイルにも何も残さない）。
//!
//! ```text
//! cargo test -p harness-sandbox --lib -- \
//!     --ignored --test-threads=1 --nocapture acl_dacl_size_limit
//! ```
//!
//! # 測って分かったこと（詳細は §S15-3）
//!
//! **上限は1,168本／65,524バイトで、超えるとエラーで止まる。無言の切り捨ては
//! 16段測って1度も観測されなかった。** 設計上の上限3に対して約390倍の余裕がある。
//! 祖先由来の継承が4段重なる形でも同じで、上限を超える段の書込だけがエラーになり、
//! それ以前の段のACEは正しく葉まで届く。
//!
//! **ただし「無言でない」は、呼び出し側が戻り値を見た場合の話である。**
//! `grant_aces_propagating`は`Result`を返し、製品の呼び出し元は`?`で伝播させているので
//! 現状は問題ない。**戻り値を捨てる呼び出しを足すと、ここで無言に変わる。**
//!
//! # このファイルの寿命
//!
//! **残課題#20の実装が終わったら消す**（`docs/CODE-STRUCTURE-RULES.md`規則2）。
//! 問い自体は§S15-3で閉じているが、#20の実装は「同一ノードに何本載せるか」を決める作業
//! なので、その間だけ手元に置いておく。
//!
//! **無言の切り捨てが観測されていたら常設の回帰へ昇格させる予定だったが、
//! 観測されなかったので昇格しない。** もし将来ここが無言に変わるなら、それは
//! 「戻り値を捨てる呼び出しが足された」ときであり、**それを止めるのはこのテストではなく
//! 呼び出し側のレビューである**（`B-05`）。

use std::collections::HashSet;
use std::path::Path;

use super::test_support::{dacl_size_info, describe_dacl_aces, TestDirGuard};
use super::*;

/// 階段の段。**倍々で上げてから二分探索で詰める**——1本ずつ上げると数千回の書込になる。
const LADDER: &[usize] = &[1, 64, 256, 512, 1024, 2048, 4096];

/// 階段の打ち切り。**無限に上げない**——上限に当たらないまま伸び続けると
/// 「エラーも出ず終わらない」という最悪の沈黙になる（`LADDER`の最大値と揃える）。
const LADDER_CAP: usize = 4096;

/// 測定用のcapability SIDを名前から導出する。`workspace_capability_sid`は使わない
/// ——あちらは`%APPDATA%`の台帳へ書く（HANDOFFの「やってはいけないこと」2番）。
fn subject(index: usize) -> crate::win_common::OwnedSid {
    let name = format!("harness-dacl-limit-{}-{index}", std::process::id());
    super::capability_sid_from_name(&name).expect("derive capability sid")
}

/// `n`本ぶんの宛先SIDを作る。**呼び出し側が生かしておくこと**——
/// [`InheritableGrant`]が持つのは生の`PSID`（借用）なので、ここで作った`OwnedSid`を
/// 落とすとぶら下がりポインタになる。
fn subjects(n: usize) -> Vec<crate::win_common::OwnedSid> {
    (0..n).map(subject).collect()
}

/// SIDの文字列表現の集合。[`describe_dacl_aces`]の各行の末尾と突き合わせるために使う。
fn sid_strings(subjects: &[crate::win_common::OwnedSid]) -> HashSet<String> {
    subjects
        .iter()
        .map(|s| {
            crate::win_common::sid_to_string(s.as_psid()).expect("stringify the measurement SID")
        })
        .collect()
}

/// `path`のDACLに載っている**自分の宛先SID**の本数を数える。
///
/// **全ACE数ではなく自分のぶんだけ数えるのが要点**——ノードには元から
/// Administrators・SYSTEM・所有者のACEが載っており、それを混ぜると
/// 「N本書いてN本載った」の判定が数本ぶんずれる（B-09: 数える対象を混ぜない）。
fn count_own_aces(path: &Path, wanted: &HashSet<String>) -> usize {
    describe_dacl_aces(path)
        .expect("list the ACEs")
        .iter()
        .filter(|line| {
            line.rsplit(';')
                .next()
                .is_some_and(|sid| wanted.contains(sid))
        })
        .count()
}

/// 1回の階段の結果。
#[derive(Debug)]
struct Step {
    requested: usize,
    write_error: Option<String>,
    /// 書込後に**実際に載っていた**自分の宛先SIDの本数。
    present: usize,
    acl_bytes: u32,
    total_aces: u32,
}

impl Step {
    /// **書込が成功したのに、要求した本数が載っていない** ＝ 無言の切り捨て。
    fn silently_truncated(&self) -> bool {
        self.write_error.is_none() && self.present < self.requested
    }

    fn succeeded_fully(&self) -> bool {
        self.write_error.is_none() && self.present == self.requested
    }
}

/// `parent`の下に使い捨てのディレクトリを作り、そこへ`n`本の継承ACEを**1回の書込で**載せて、
/// 何が起きたかを返す。
///
/// **段ごとに新しいディレクトリを使う**のは、前の段のACEが積み残ると
/// 「N本目で失敗した」の N がずれるためである。
fn try_n_aces(parent: &Path, tag: &str, n: usize, pool: &[crate::win_common::OwnedSid]) -> Step {
    use super::acl_dacl_write::{grant_aces_propagating, InheritableGrant};

    let node = parent.join(format!("n{tag}"));
    std::fs::create_dir_all(&node).expect("create the ladder node");

    let both = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
    let mask = workspace_rwx_mask();
    let grants: Vec<InheritableGrant> = pool[..n]
        .iter()
        .map(|sid| InheritableGrant {
            sid: sid.as_psid(),
            mask,
            inheritance: both,
        })
        .collect();

    let write_error = grant_aces_propagating(&node, &grants, IdempotentCheck::Always)
        .err()
        .map(|e| e.to_string());

    let wanted = sid_strings(&pool[..n]);
    let present = count_own_aces(&node, &wanted);
    let size = dacl_size_info(&node).expect("read the DACL size");
    let (acl_bytes, total_aces) = (size.bytes_in_use, size.ace_count);

    // **剥がしてから戻る**（B-01）。ツリーごと消えるとはいえ、撤収が通ることを
    // 段ごとに確かめておかないと「付けられたが剥がせない」を見逃す。
    let psids: Vec<PSID> = pool[..n].iter().map(|s| s.as_psid()).collect();
    if !psids.is_empty() {
        revoke_sids_from_node(&node, &psids).expect("revoke the ladder ACEs");
    }
    let left = count_own_aces(&node, &wanted);
    assert_eq!(
        left, 0,
        "the ladder step for {n} ACEs left {left} of them behind after the revoke"
    );

    Step {
        requested: n,
        write_error,
        present,
        acl_bytes,
        total_aces,
    }
}

/// 1ノードに入る本数の上限を、階段＋二分探索で確定させる。
struct Ceiling {
    /// **完全に成功した**最大の本数（要求＝実際に載った本数）。
    max_ok: usize,
    /// 最初に完全成功しなくなった本数（打ち切りまで成功し続けたら`None`）。
    first_bad: Option<usize>,
    steps: Vec<serde_json::Value>,
    /// 一度でも「成功したのに本数が足りない」が観測されたか。
    saw_silent_truncation: bool,
}

fn step_json(step: &Step) -> serde_json::Value {
    serde_json::json!({
        "requested": step.requested,
        "present": step.present,
        "acl_bytes": step.acl_bytes,
        "total_aces_including_others": step.total_aces,
        "write_error": step.write_error,
        "silently_truncated": step.silently_truncated(),
    })
}

fn find_ceiling(parent: &Path, pool: &[crate::win_common::OwnedSid]) -> Ceiling {
    let mut steps = Vec::new();
    let mut saw_silent_truncation = false;
    let mut max_ok = 0usize;
    let mut first_bad = None;

    for &n in LADDER {
        let step = try_n_aces(parent, &format!("ladder{n}"), n, pool);
        saw_silent_truncation |= step.silently_truncated();
        let ok = step.succeeded_fully();
        steps.push(step_json(&step));
        eprintln!("  [ladder] {}", steps.last().expect("just pushed"));
        if ok {
            max_ok = n;
        } else {
            first_bad = Some(n);
            break;
        }
    }

    // 二分探索で `max_ok` と `first_bad` の間を詰める。**上限が無いときは詰めない。**
    if let Some(bad) = first_bad {
        let (mut lo, mut hi) = (max_ok, bad);
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            let step = try_n_aces(parent, &format!("bisect{mid}"), mid, pool);
            saw_silent_truncation |= step.silently_truncated();
            let ok = step.succeeded_fully();
            steps.push(step_json(&step));
            eprintln!("  [bisect] {}", steps.last().expect("just pushed"));
            if ok {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        max_ok = lo;
        first_bad = Some(hi);
    }

    Ceiling {
        max_ok,
        first_bad,
        steps,
        saw_silent_truncation,
    }
}

/// **M3-b テスト1: 1ノードに何本入るか。当たったとき、エラーか無言か。**
///
/// # 測る順序
///
/// 1. **1本あたりのバイト数を実測する**（0本と1本のDACLサイズの差）。計算しない
/// 2. 階段で上限に当たるところまで上げ、二分探索で詰める
/// 3. 各段で**書き戻して読み直し**、要求した本数が実際に載っているかを数える
///
/// # 何をassertするか
///
/// **「何本入るか」はassertしない**——それが測る当のものであり、OSやファイルシステムの
/// 版で動きうる。固定するのは**測定そのものが成立していること**だけ:
///
/// - 少ない本数（設計上の上限3を含む）では**完全に成功する**（B-35の許可側。これが無いと、
///   全部失敗している状態を「上限に当たった」と読んでしまう）
/// - 打ち切り（4096本）までに**何らかの上限に当たる**か、当たらないならそう記録される
///
/// **無言の切り捨てが観測されたら赤くする。** これは「まだ起きていないことの確認」ではなく
/// 「起きたら気付く」ための歯である——起きているなら、それは記録すべき欠陥だからである。
#[test]
#[ignore = "writes DACLs with thousands of ACEs; run NON-elevated"]
fn acl_dacl_size_limit_where_it_breaks_and_how_it_fails() {
    let dir = TestDirGuard::create("dacllimit-one");
    let root = dir.path();
    let pool = subjects(LADDER_CAP);

    // --- 1. 1本あたりのバイト数を実測する ---
    let empty = root.join("bytes-0");
    std::fs::create_dir_all(&empty).expect("create the byte-probe node");
    let baseline = dacl_size_info(&empty).expect("read the baseline DACL size");
    let (bytes_0, aces_0) = (baseline.bytes_in_use, baseline.ace_count);
    let one = try_n_aces(root, "bytes1", 1, &pool);
    let bytes_per_ace = one.acl_bytes as i64 - bytes_0 as i64;

    // --- 2/3. 階段と二分探索 ---
    let ceiling = find_ceiling(root, &pool);

    // 設計上の上限（M=3）が普通に通ることを対で押さえる（B-35の許可側）。
    let at_design_limit = try_n_aces(root, "design3", 3, &pool);

    println!(
        "{}",
        serde_json::json!({
            "measurement": "S15 M3-b how many capability ACEs fit on one node, and how it fails",
            "baseline_without_our_aces": { "acl_bytes": bytes_0, "ace_count": aces_0 },
            "bytes_per_capability_ace": bytes_per_ace,
            "design_limit_m3": step_json(&at_design_limit),
            "max_fully_successful": ceiling.max_ok,
            "first_failing": ceiling.first_bad,
            "saw_silent_truncation": ceiling.saw_silent_truncation,
            "ladder_cap": LADDER_CAP,
            "steps": ceiling.steps,
        })
    );

    assert!(
        at_design_limit.succeeded_fully(),
        "the design limit of M=3 must fit comfortably; if this fails the whole ladder below is \
         measuring something other than the ACL size limit ({at_design_limit:?})"
    );
    assert!(
        bytes_per_ace > 0,
        "one capability ACE must make the DACL bigger; a non-positive delta ({bytes_per_ace}) \
         means the write did not land and every number above is meaningless"
    );
    assert!(
        ceiling.max_ok >= 3,
        "fewer than 3 ACEs fit on a node, which contradicts the design limit — read the ladder"
    );
    assert!(
        !ceiling.saw_silent_truncation,
        "SILENT TRUNCATION: a write reported success but fewer ACEs than requested were actually \
         on the node. That is a defect worth filing — permissions were 'granted' and are not \
         there. Steps: {:?}",
        ceiling.steps
    );
}

/// **M3-b テスト2: 祖先由来の継承ACEが重なったとき、葉は何本受け取るのか。**
///
/// # これがHANDOFFの本当の心配である
///
/// 1ノードに直接3本しか載らなくても、**祖先が何段も宣言していれば葉には積み上がる**。
/// ここでは`root/d/d/d`の4段（root含む）へ**段ごとに別の宛先SID**を`per_level`本ずつ置き、
/// 最深部の葉が`4 × per_level`本を受け取るかを数える。
///
/// # 2つの腕（B-35: 禁止側だけを見ない）
///
/// | 腕 | `per_level` | 何を言うためのものか |
/// |---|---|---|
/// | 収まる | 少数 | **積み上がりが正常に効く**こと。これが無いと、上限側の「届かない」を「上限のせい」と読めない |
/// | 溢れる | 上限を超える本数 | 上限に当たったとき、エラーか無言か |
///
/// 溢れる側の本数は**テスト1が実測した上限から決める**（定数で決め打ちしない——
/// 上限は環境で動きうるので、決め打ちすると「溢れていないのに溢れた腕と呼ぶ」ことになる）。
///
/// # 新規作成したファイルも別に見る
///
/// 既存の子孫への伝播と、**新規オブジェクトが作成時に継承を計算される経路**はOSの中で別物である。
/// 上限付近では片方だけ壊れうるので、両方数える。
#[test]
#[ignore = "writes DACLs with thousands of inherited ACEs; run NON-elevated"]
fn acl_dacl_size_limit_when_ancestors_stack_inherited_aces() {
    use super::acl_dacl_write::{grant_aces_propagating, InheritableGrant};

    const LEVELS: usize = 3; // root + 3段 = 4段が宣言する

    // 溢れる側の本数を決めるために、まず1ノードの上限を測る。
    let probe_dir = TestDirGuard::create("dacllimit-probe");
    let pool = subjects(LADDER_CAP);
    let ceiling = find_ceiling(probe_dir.path(), &pool);
    // 4段で確実に超える本数。上限が見つからなかった（打ち切りまで通った）ときは
    // 打ち切り値から決める。
    let over = (ceiling.max_ok / (LEVELS + 1)) + 8;
    let arms: [(&str, usize); 2] = [("fits", 8), ("overflows", over)];

    let mut results = Vec::new();
    for (label, per_level) in arms {
        let dir = TestDirGuard::create(&format!("dacllimit-{label}"));
        let root = dir.path();

        // 段を掘り、各段にファイルを1つ置く（葉の実効を見るため）。
        let mut levels = vec![root.to_path_buf()];
        let mut cursor = root.to_path_buf();
        for _ in 0..LEVELS {
            cursor = cursor.join("d");
            std::fs::create_dir_all(&cursor).expect("create a level");
            levels.push(cursor.clone());
        }
        let leaf_file = cursor.join("leaf.txt");
        std::fs::write(&leaf_file, b"x").expect("write the leaf file");

        // 段ごとに**別の宛先SID**を割り当てる。同じ宛先SIDを使うと畳まれて本数が数えられない。
        let mut per_level_subjects = Vec::new();
        let mut base = 0usize;
        for _ in 0..levels.len() {
            per_level_subjects.push(pool[base..base + per_level].to_vec());
            base += per_level;
        }

        // **上から順に**書く。下から書くと、上の段の書込が下を上書きしうる。
        let both = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
        let mask = workspace_rwx_mask();
        let mut write_errors = Vec::new();
        for (level_index, (node, subs)) in levels.iter().zip(per_level_subjects.iter()).enumerate()
        {
            let grants: Vec<InheritableGrant> = subs
                .iter()
                .map(|sid| InheritableGrant {
                    sid: sid.as_psid(),
                    mask,
                    inheritance: both,
                })
                .collect();
            if let Err(e) = grant_aces_propagating(node, &grants, IdempotentCheck::Always) {
                write_errors
                    .push(serde_json::json!({ "level": level_index, "error": e.to_string() }));
            }
        }

        // 期待は「全段ぶんが葉に載る」。
        let expected: Vec<crate::win_common::OwnedSid> =
            per_level_subjects.iter().flatten().cloned().collect();
        let wanted = sid_strings(&expected);
        let present_on_leaf = count_own_aces(&leaf_file, &wanted);
        let leaf_size = dacl_size_info(&leaf_file).expect("read the leaf DACL size");
        let (leaf_bytes, leaf_total) = (leaf_size.bytes_in_use, leaf_size.ace_count);

        // **新規作成したファイルが継承する数**は別経路なので別に数える。
        let fresh = cursor.join("fresh.txt");
        std::fs::write(&fresh, b"x").expect("write a fresh file at the deepest level");
        let present_on_fresh = count_own_aces(&fresh, &wanted);

        results.push(serde_json::json!({
            "arm": label,
            "per_level": per_level,
            "levels_declaring": levels.len(),
            "expected_on_leaf": expected.len(),
            "present_on_preexisting_leaf": present_on_leaf,
            "present_on_freshly_created_file": present_on_fresh,
            "leaf_acl_bytes": leaf_bytes,
            "leaf_total_aces_including_others": leaf_total,
            "write_errors": write_errors,
            "silently_short_on_leaf": write_errors.is_empty() && present_on_leaf < expected.len(),
        }));
        eprintln!("  [{label}] {}", results.last().expect("just pushed"));

        // 撤収（B-01）。段ごとに剥がして、残っていないことを読み直しで確かめる。
        let psids: Vec<PSID> = expected.iter().map(|s| s.as_psid()).collect();
        let report = revoke_workspace_sids_recursive(root, &psids, &|_, _| {})
            .expect("revoke every subject");
        // 撤収walkは1ノードの失敗で全体を止めず、剥がせなかったノードを`blocked`へ集めて
        // 続行する形になった。**集めた側を見ないと、剥がし残しが黙って測定結果に混じる**（B-09）。
        assert!(
            report.blocked.is_empty(),
            "{label}: could not strip the measurement ACEs from {} node(s): {:?}",
            report.blocked.len(),
            report.blocked
        );
        for node in [&leaf_file, &fresh, root] {
            let left = count_own_aces(node, &wanted);
            assert_eq!(
                left,
                0,
                "{label}: {} still carries {left} of the measurement ACEs after the revoke",
                node.display()
            );
        }
    }

    println!(
        "{}",
        serde_json::json!({
            "measurement": "S15 M3-b what a deep node inherits when every ancestor declares",
            "single_node_ceiling": ceiling.max_ok,
            "arms": results,
        })
    );

    // 収まる側は**必ず全部届く**。ここが赤いなら、溢れる側の「届かない」を上限のせいと読めない。
    let fits = &results[0];
    assert_eq!(
        fits["present_on_preexisting_leaf"], fits["expected_on_leaf"],
        "the small arm must deliver every ancestor's ACEs to the leaf; without this control the \
         overflowing arm says nothing about the size limit"
    );
    assert_eq!(
        fits["present_on_freshly_created_file"], fits["expected_on_leaf"],
        "a freshly created file must inherit every ancestor's ACEs in the small arm"
    );

    // 溢れる側で「成功したのに足りない」なら、それは無言の切り捨てである。
    let overflowing = &results[1];
    assert_eq!(
        overflowing["silently_short_on_leaf"],
        serde_json::json!(false),
        "SILENT TRUNCATION on inheritance: every ancestor's write reported success, but the leaf \
         carries fewer ACEs than were declared. A deep workspace would lose permissions with no \
         error anywhere. Arm: {overflowing}"
    );
}
