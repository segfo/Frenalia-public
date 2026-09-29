//! **copy-up の写しを「一時名で作ってから置く」ようにした費用**を測る
//! （`plans/mac-spike/RESULTS.md` の §S76、`docs/bugs/BUG-178.md` の追記）。
//!
//! # なぜ要るか
//!
//! CoW の Redirector は、既存ファイルを初めて書込で開くとき、元の中身を差分層へ写してから開かせる。
//! 写しを本来のパスへ直接書いていた頃は、作りかけの写しが他のプロセスから見えた。写しを一時の置き場へ
//! 作ってから「移動先が在れば失敗」の名前の変更で置くと、**初めて書くファイルごとに名前の変更が1回増える**。
//! その1回がいくらかを、写しそのものの費用と並べて測る。
//!
//! # 測り方
//!
//! §S25 の計器（`tier2a-proc-probe --open-bench`）をそのまま使う。同じプロセスで DLL を読み込む前と後を
//! 撮り、差を上乗せとして読む。腕は2本足した。
//!
//! | 腕 | 何を測るか |
//! |---|---|
//! | `first_touch_write` | 別々の既存ファイル N 個を1回ずつ書込で開く（DLL を読み込んだ区間では毎回 copy-up が走る） |
//! | `rewrite_write` | 1つのファイルを2万回書込で開く（copy-up は最初の1回だけ。対照） |
//!
//! **変更前と変更後の DLL を `HARNESS_TEST_REDIRECTOR_DLL` で差し替えて、交互に撃って比べる。**
//! この試験は1回ぶんを撃って JSON を1行ずつ出すだけで、比べるのは撃つ側である。
//!
//! # この測定が言わないこと
//!
//! - AppContainer の中では回していない（§S25 と同じ）。
//! - 1セッションの総額は、ここで得る単価に「初めて書くファイル数」を掛けた計算値でしか言えない。
//! - **判定が出たら削除する**（`docs/CODE-STRUCTURE-RULES.md` 規則2）。

use std::process::Command;

use serde_json::Value;

use super::mac_spike_tests::{last_json_line, probe_exe};
use super::test_support::TestDirGuard;

/// 大きさ（バイト）と、区間ごとに初めて書くファイルの数。
///
/// 16KB はこのリポジトリの追跡ファイル1,295件の大きさの中央値（15,908バイト、2026-09-29 実測）。
/// 1MiB は追跡ファイルの最大（558,599バイト）を超える大きさで、ビルドの生成物のように大きいファイルを
/// 初めて書き直す場合の代わり。数は、1腕あたり1秒前後に収まるように選んだ。
const CASES: [(usize, usize); 2] = [(15_908, 2_000), (1 << 20, 200)];

/// 写し済みのファイルを書込で開く回数（§S25 の腕と同じ）。
const REWRITE_ITERS: usize = 20_000;

/// 変更後の DLL だけが持つ文字列（一時の置き場の名前）。撃つ前にどちらの DLL かを機械で確かめるため。
const PUBLISH_MARKER: &[u8] = b".harness-cow-tmp";

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
#[ignore = "loads the Redirector DLL into a probe and times first-touch write opens; run NON-elevated"]
fn copy_up_cost_per_first_write() {
    let dll = match std::env::var("HARNESS_TEST_REDIRECTOR_DLL") {
        Ok(p) if !p.trim().is_empty() => std::path::PathBuf::from(p),
        _ => super::spawn::redirector_dll_path().expect("resolve the redirector DLL path"),
    };
    let dll_bytes = std::fs::read(&dll).unwrap_or_else(|e| panic!("read {}: {e}", dll.display()));
    let has_marker = contains(&dll_bytes, PUBLISH_MARKER);

    for (size, files) in CASES {
        let guard = TestDirGuard::create("copy-up-cost");
        let workspace = guard.path().join("workspace");
        let diff_layer = guard.path().join("diff-layer");
        let first_touch = workspace.join("first-touch");
        for phase in ["before", "after"] {
            let dir = first_touch.join(phase);
            std::fs::create_dir_all(&dir).expect("create the first-touch directory");
            let body = vec![b'x'; size];
            for i in 0..files {
                std::fs::write(dir.join(format!("f{i:05}.bin")), &body).expect("write a file");
            }
        }
        std::fs::create_dir_all(&diff_layer).expect("create the diff layer");
        let inside = workspace.join("inside.txt");
        std::fs::write(&inside, b"copy-up cost measurement").expect("write inside file");
        let rewrite = workspace.join("rewrite.bin");
        std::fs::write(&rewrite, vec![b'y'; size]).expect("write the rewrite file");

        let out = Command::new(probe_exe())
            .arg("--open-bench")
            .arg(&inside)
            .arg("--open-bench-iters")
            .arg(REWRITE_ITERS.to_string())
            .arg("--open-bench-first-touch")
            .arg(&first_touch)
            .arg("--open-bench-rewrite")
            .arg(&rewrite)
            .arg("--open-bench-dll")
            .arg(&dll)
            .env("HARNESS_COW_WORKSPACE", &workspace)
            .env("HARNESS_COW_DIFF_LAYER", &diff_layer)
            .output()
            .expect("run the open-bench probe");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let report: Value = last_json_line(&stdout).unwrap_or_else(|| {
            panic!(
                "the probe printed no JSON line.\nstdout:\n{stdout}\nstderr:\n{}",
                String::from_utf8_lossy(&out.stderr)
            )
        });

        // ---- 数字を読む前の検算（崩れていたら、その回の数字は使えない） ----
        let load = &report["redirector"];
        assert_eq!(load["load_ok"].as_bool(), Some(true), "the DLL must load");
        assert_eq!(
            load["init_rc"].as_u64(),
            Some(1),
            "harness_cow_init must return 1"
        );
        for phase in ["before", "after"] {
            assert_eq!(
                report[phase]["first_touch_write"]["ok"].as_u64(),
                Some(files as u64),
                "every first-touch write open in {phase} must succeed"
            );
            assert_eq!(
                report[phase]["rewrite_write"]["ok"].as_u64(),
                Some(REWRITE_ITERS as u64),
                "every rewrite open in {phase} must succeed"
            );
        }
        // 初めて書いた回ごとに copy-up が走ったこと（写しが N 個・台帳の`Modify`が N 行）。
        let copies = std::fs::read_dir(diff_layer.join("first-touch").join("after"))
            .map(|rd| rd.count())
            .unwrap_or(0);
        assert_eq!(
            copies, files,
            "each first-touch write must leave one copy in the diff layer"
        );
        let ledger = std::fs::read_to_string(
            diff_layer.join(harness_change_ledger::COW_OPS_LEDGER_FILENAME),
        )
        .unwrap_or_default();
        let modifies = harness_change_ledger::parse_ledger(&ledger)
            .into_iter()
            .filter(|e| {
                e.op == harness_change_ledger::ChangeOp::Modify
                    && e.path.starts_with("first-touch/after/")
            })
            .count();
        assert_eq!(modifies, files, "each first touch must be recorded once");
        // 一時の置き場に何も残っていないこと（変更前の DLL では置き場そのものが無い）。
        let staged = std::fs::read_dir(diff_layer.join(".harness-cow-tmp"))
            .map(|rd| rd.count())
            .unwrap_or(0);
        assert_eq!(staged, 0, "nothing may be left in the staging directory");

        println!(
            "{}",
            serde_json::json!({
                "measurement": "copy-up cost per first write open (publish via a staging name vs direct copy)",
                "dll": dll.to_string_lossy(),
                "dll_has_publish_marker": has_marker,
                "file_bytes": size,
                "first_touch_files_per_phase": files,
                "rewrite_iters": REWRITE_ITERS,
                "first_touch_write": report["delta"]["first_touch_write"],
                "rewrite_write": report["delta"]["rewrite_write"],
                "open_inside": report["delta"]["open_inside"],
            })
        );
    }
}
