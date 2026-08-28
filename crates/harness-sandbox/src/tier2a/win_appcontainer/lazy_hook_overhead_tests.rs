//! **Redirector DLLのフックが、成功するopen 1回へ上乗せする時間**（D-88＝Lazy ACE fault-inの着手条件）。
//!
//! # なぜ測るのか——払う相手が「faultした回数」ではないから
//!
//! Lazy ACE fault-inは、いまフックの無いTier2a（DirectRw）へRedirector DLLを新設で注入する。
//! **fault（拒否されたopen）は数百件しかないが、フックは成功する全openの上を通る。**
//! §S21が実ワークロードを実測している。
//!
//! | 実測（§S21） | S1 ビルド系 | S2 テスト系 |
//! |---|---:|---:|
//! | 触った既存ノード（＝faultし得る上限） | 503 | 461 |
//! | **オープン総回数** | **144,967** | **218,841** |
//!
//! したがって費用は次の2本に割れる。
//!
//! - **fault側**: 503件 × 約153 µs（§S13の単価123.5 µs＋§S20の跨ぎ往復29.2 µs）＝ **約0.08秒**
//! - **フック側**: 145,000〜219,000回 × **1オープンあたりの上乗せ**（＝本測定）
//!
//! 上乗せが1 µsなら0.15秒で誤差、20 µsなら2.9秒である。**しかもフック側は初回だけでなく
//! 毎回払う**——lazyが消すのは初回の待ち（§S12-1の26万ノードで22.5秒）だけなので、
//! 「一度きりの22.5秒を消すために、毎回2.9秒を払う」形になっていないかがここで決まる。
//!
//! # 測り方
//!
//! 測定は`tier2a-proc-probe --open-bench`（`open_bench`モジュールdoc）が行う。**同一プロセスの
//! 中で「DLLを載せる前」と「載せた後」を撮り、その差**を上乗せとして読む。別プロセス同士を
//! 比べるとキャッシュやスケジューリングの差が混ざるためである。
//!
//! **腕は対で置く**（B-35）。
//!
//! | 腕 | 何を確かめるか |
//! |---|---|
//! | `control`（DLLを渡さない） | 2区間目が勝手に速く／遅くなる量＝**ドリフト**。これを超えない差は上乗せと言えない |
//! | `hooked`（DLLを渡す） | フックを載せた後の上乗せ |
//!
//! # この測定が言わないこと（**外挿しないこと**）
//!
//! - **CoWの分類ロジック込みの値である。** fault-in専用のフックは差分層への書き換えを
//!   行わないぶん軽いはずなので、得られる値は**上限**である。
//! - 実ビルドの壁時計ではない。§S21が測った回数を掛けて見積もるための**単価**である。
//! - AppContainerの中では回していない（フックの費用はトークンに依らない）。
//! - **fault経路（拒否→要求→再open）は測っていない。** 上記のとおり総額0.08秒で、
//!   判断を動かさないためである。
//!
//! # 実行
//!
//! **昇格しない。ACEを1本も書かない。台帳にも触れない。**
//!
//! ```text
//! cargo build -p tier2a-proc-probe
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture lazy_hook_overhead
//! ```
//!
//! **判定が出たら本ファイルは削除する**（`docs/CODE-STRUCTURE-RULES.md`規則2）。

use std::path::Path;
use std::process::Command;

use serde_json::Value;

use super::mac_spike_tests::{last_json_line, probe_exe};
use super::test_support::TestDirGuard;

/// 1腕あたりの反復回数。§S13が「件数を5倍にしても1件あたりが1%も動かない」を確認しているので、
/// ここも平坦なはずである。2万回はµs単位の差を読むのに十分で、1腕あたり1秒未満に収まる。
const ITERS: usize = 20_000;

/// §S21-1の実測。**転記である**——§S21を測り直したらここも直すこと。
const OPENS_PER_SESSION_BUILD: f64 = 144_967.0;
const OPENS_PER_SESSION_TEST: f64 = 218_841.0;

/// §S12-1の実測（26万ノードの初回実体化）。lazyが消す側の待ち時間。
const EAGER_FIRST_RUN_SECS: f64 = 22.5;

fn run_probe(
    label: &str,
    workspace: &Path,
    inside: &Path,
    outside: &Path,
    dll: Option<&Path>,
) -> Value {
    let probe = probe_exe();
    let diff_layer = workspace.parent().unwrap().join("diff-layer");
    std::fs::create_dir_all(&diff_layer).expect("create the diff layer directory");

    let mut cmd = Command::new(&probe);
    cmd.arg("--open-bench")
        .arg(inside)
        .arg("--open-bench-outside")
        .arg(outside)
        .arg("--open-bench-iters")
        .arg(ITERS.to_string());
    if let Some(dll) = dll {
        cmd.arg("--open-bench-dll").arg(dll);
        // `harness_cow_init(NULL)`はenvから設定を読む（`init::resolve_config`）。
        cmd.env("HARNESS_COW_WORKSPACE", workspace)
            .env("HARNESS_COW_DIFF_LAYER", &diff_layer);
    }

    let out = cmd.output().expect("run the open-bench probe");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    last_json_line(&stdout).unwrap_or_else(|| {
        panic!("{label}: the probe printed no JSON line.\nstdout:\n{stdout}\nstderr:\n{stderr}")
    })
}

fn delta_us(report: &Value, arm: &str) -> f64 {
    report["delta"][arm]["delta_us"]
        .as_f64()
        .unwrap_or_else(|| panic!("missing delta for {arm} in {report}"))
}

fn ok_count(report: &Value, phase: &str, arm: &str) -> u64 {
    report[phase][arm]["ok"]
        .as_u64()
        .unwrap_or_else(|| panic!("missing ok count for {phase}/{arm} in {report}"))
}

/// **フックの上乗せを、ドリフトと対で測る。**
///
/// assertするのは揺れない構造の側だけ（全openが成功したか、DLLが実際に載って初期化が
/// 成功したか）。**時間は判定に使わず値として出す**——マシンの状態で揺れるので、
/// 読むのは人間の仕事である。
#[test]
#[ignore = "spawns a probe that loads the Redirector DLL and times 20,000 opens per arm; run NON-elevated"]
fn lazy_hook_overhead_per_open() {
    // 既定はテストバイナリの隣（＝`cargo build`が置いたdebugビルド）。**releaseのDLLで測り直す
    // ために差し替え口を開けてある**——フックの上乗せは最適化で変わるので、debugだけで
    // 判断すると製品の値を過大に見積もる。テスト専用の環境変数は`HARNESS_TEST_`を名乗る規約。
    let dll = match std::env::var("HARNESS_TEST_REDIRECTOR_DLL") {
        Ok(p) if !p.trim().is_empty() => std::path::PathBuf::from(p),
        _ => super::spawn::redirector_dll_path().expect("resolve the redirector DLL path"),
    };
    assert!(
        dll.exists(),
        "harness_redirector.dll not found at {} (build it with `cargo build -p harness-redirector`)",
        dll.display()
    );

    let guard = TestDirGuard::create("lazy-hook-overhead");
    let workspace = guard.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("create the measurement workspace");
    let inside = workspace.join("inside.txt");
    std::fs::write(&inside, b"lazy fault-in hook overhead measurement").expect("write inside file");
    let outside = guard.path().join("outside.txt");
    std::fs::write(&outside, b"outside the workspace").expect("write outside file");

    // 対照を先に撮る（DLL無し）。**2区間の差がここで既に大きいなら、下の差は読めない。**
    let control = run_probe("control", &workspace, &inside, &outside, None);
    let hooked = run_probe("hooked", &workspace, &inside, &outside, Some(&dll));

    let load = &hooked["redirector"];
    let drift_inside = delta_us(&control, "open_inside");
    let drift_outside = delta_us(&control, "open_outside");
    let drift_attrs = delta_us(&control, "attrs_inside");
    let hook_inside = delta_us(&hooked, "open_inside");
    let hook_outside = delta_us(&hooked, "open_outside");
    let hook_attrs = delta_us(&hooked, "attrs_inside");

    // ドリフトを差し引いた上乗せ。**負なら「測れていない」と読む**（下のprintで見る）。
    let net_inside = hook_inside - drift_inside;
    let net_outside = hook_outside - drift_outside;

    // 上乗せをセッション総額へ換算する。**どちらの腕で換算したかを併記する**——
    // workspace内と外では分類の経路が違い、実ワークロードは両方を混ぜて開く。
    let session = |us: f64, opens: f64| us * opens / 1e6;

    println!(
        "{}",
        serde_json::json!({
            "measurement": "Redirector hook overhead per successful open (upper bound for D-88)",
            "iters_per_arm": ITERS,
            "redirector_dll": dll.to_string_lossy(),
            "load_report": load,
            "control_drift_us": {
                "open_inside": drift_inside,
                "open_outside": drift_outside,
                "attrs_inside": drift_attrs,
            },
            "hooked_delta_us": {
                "open_inside": hook_inside,
                "open_outside": hook_outside,
                "attrs_inside": hook_attrs,
            },
            "net_overhead_us": {
                "open_inside": net_inside,
                "open_outside": net_outside,
                "attrs_inside": hook_attrs - drift_attrs,
            },
            "session_estimate_secs": {
                "build_inside": session(net_inside, OPENS_PER_SESSION_BUILD),
                "build_outside": session(net_outside, OPENS_PER_SESSION_BUILD),
                "test_inside": session(net_inside, OPENS_PER_SESSION_TEST),
                "test_outside": session(net_outside, OPENS_PER_SESSION_TEST),
            },
            "eager_first_run_secs_saved_once": EAGER_FIRST_RUN_SECS,
            "raw": { "control": control, "hooked": hooked },
        })
    );

    // ---- 構造の検算（B-25: 「呼んだ」ではなく「効いた」を見る） ----
    assert_eq!(
        load["load_ok"].as_bool(),
        Some(true),
        "the probe must actually load the Redirector DLL; otherwise the 'hooked' arm is a second control run"
    );
    assert_eq!(
        load["init_rc"].as_u64(),
        Some(1),
        "harness_cow_init must return 1 (config resolved and hooks installed); a 0 here means the \
         hooks were never placed and the measured delta is noise"
    );
    for (phase, arm) in [
        ("before", "open_inside"),
        ("after", "open_inside"),
        ("before", "open_outside"),
        ("after", "open_outside"),
    ] {
        assert_eq!(
            ok_count(&hooked, phase, arm),
            ITERS as u64,
            "every open in {phase}/{arm} must succeed; a partial count means we timed failures"
        );
    }
}
