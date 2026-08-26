//! **T4: サンドボックスの子は privhelper の要求受付パイプへ届くのか**（測定）。
//! 結果の正本は`plans/handoff-issue-20/T4.md`、問いの出所は
//! `plans/handoff-issue-20/INDEX.md`のT4行である。
//!
//! ## 何を測るのか
//!
//! harness本体は、管理者権限が要る操作を別プログラム（`harness-privhelper.exe`）へ渡す。
//! 両者をつなぐ名前付きパイプは「**このユーザー本人だけが取れる**」という許可設定
//! （`win_pipe_ipc::user_only_security_attributes`＝`D:(A;;GA;;;<ユーザーSID>)`）ひとつで
//! 守られている。残課題#20はこのパイプに**秘密の値**を載せる予定で、その前提が
//! 「サンドボックスの中のプログラムはこのパイプに触れない」である。
//!
//! **この前提は今まで推論であって測っていない**（`plans/HANDOFF-ISSUE-20-SUBJECT-MIGRATION.md`）。
//! ここで測る。
//!
//! ## 塞ぎに行かない
//!
//! 本モジュールは**測定だけ**を行う。塞いでから測ると、元から塞がっていたのか塞いだから
//! 止まったのかが区別できない。届いた場合の対処は本流が決める。
//!
//! ## 既存の測定（§S2）との違い
//!
//! `plans/mac-spike/RESULTS.md` §S2 が「本人のみ許可のパイプへサンドボックスから到達できるか
//! → できない」を既に記録している。ただし**的が違う**——§S2 が撃ったのはテストがその場で
//! 作った同型のパイプで、ここで撃つのは**本番コードが実際に開いた生きたパイプ**である。
//! 「同型だから同じはず」は推論なので、§S2 は根拠ではなく**比較対象**として引く。
//!
//! ## 生きたパイプを、昇格せずに測る仕掛け
//!
//! 本番の特権要求関数[`crate::tier2a::privhelper::run_privileged_workspace_access`]は、
//! 「このパイプ名でヘルパーを起こしてくれ」という関数（`ChainLauncher`、D-60）を外から受け取る。
//! **その関数はパイプを作った直後に、生きたパイプ名を引数として呼ばれる**
//! （`privhelper/client.rs`の`run_privileged_raw`）。テストはそこへ自分の関数を差し込むだけで、
//! 生きた本番のパイプへプローブを撃てる。**本番コードは1行も変えない。**
//!
//! 差し込んだ関数は**ヘルパーを起こさない**（起こすと管理者昇格が起きる）。代わりに`Ok(())`を
//! 返し、本番側には「起こした」と伝える。その結果、本番の要求は応答を得られずエラーで終わる——
//! これは**意図した終わり方**であり、要求の中身を空（付与対象0件・穴0件）にしてあるので
//! 実マシンには何も起こらない（空要求はサーバ側で別分岐、`privhelper/server.rs`）。
//!
//! ## 昇格して回さないこと
//!
//! `dev-elevated-run.exe`から回してはいけない。昇格したテストからAppContainerの子を起こすと
//! 親トークンが管理者のものになり、**測っている世界が実運用（非昇格のharness）と変わる**
//! （`mac_spike_tests`のモジュールdocと同じ理由、`bug-pattern-rules` B-08）。本モジュールは
//! 昇格を一切必要としない設計にしてある。
//!
//! ```text
//! cargo build -p tier2a-proc-probe   # プローブをテストバイナリの隣へ置くこと
//! cargo test -p harness-sandbox --lib -- --ignored --test-threads=1 --nocapture t4_privhelper_pipe_reach
//! ```
//!
//! ## 判定が出たらこのファイルは消す
//!
//! `docs/CODE-STRUCTURE-RULES.md`規則2（一回性の調査実験をテストとして残さない）に従う。

use std::cell::RefCell;

use serde_json::{json, Value};

use super::mac_spike_tests::{
    last_json_line, probe_exe, workspace_capability_for, SpikeChild, SpikeConsole, SpikeSpawn,
};
use super::*;

/// 1つのプローブ実行の結果（stdoutの最後のJSON行）。
struct ProbeRun {
    label: &'static str,
    report: Value,
    stderr: String,
}

/// `attempts`配列から`kind`が一致する最初の的を引く。無ければ`None`——
/// **「拒否された」と「そもそも撃っていない」を混ぜない**ため、呼び出し側は
/// `None`を失敗として扱う（B-10: 無言の欠測を成功に見せない）。
fn attempt_of<'a>(report: &'a Value, kind: &str) -> Option<&'a Value> {
    report
        .get("attempts")?
        .as_array()?
        .iter()
        .find(|a| a.get("kind").and_then(|k| k.as_str()) == Some(kind))
}

fn ok_of(report: &Value, kind: &str) -> Option<bool> {
    attempt_of(report, kind)?.get("ok")?.as_bool()
}

fn err_of(report: &Value, kind: &str) -> Option<u64> {
    attempt_of(report, kind)?.get("last_error")?.as_u64()
}

/// **サンドボックスの子は、本番が今まさに開いている privhelper のパイプを開けるか。**
///
/// 対で測る（B-35）——拒否側だけを見ると、機構が効いているのか的が居なかっただけなのかを
/// 区別できない。素のユーザーのプロセスが同じ的へ接続できることまで確かめる。
///
/// | 主体 | 何を撃つか | 期待 |
/// |---|---|---|
/// | A: 本番と同じcapabilityを積んだAppContainerの子 | 開く・相乗り作成・列挙・名前の先取り | 開けない |
/// | B: workspace capabilityを持たない狭い子 | 開く | 開けない |
/// | C1: 素のユーザー（対照） | 相乗り作成・列挙・名前の先取り | 主体Aとの差が出る |
/// | C2: 素のユーザー（対照） | 開いて1往復 | 開けて、**本番の要求電文が読める** |
///
/// **撃つ順序に意味がある。** このパイプは同時1本（`nMaxInstances=1`）なので、開いて閉じた
/// 時点でそれ以降の接続は成立しない。だから「開かない測定」を先に済ませ、**開く対照は最後**に置く。
#[test]
#[ignore = "実機測定（AppContainerプロファイルと実マシンの権限を触る）。**昇格せずに**回すこと"]
fn t4_privhelper_pipe_reach_from_a_sandboxed_child() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    let sid = session_sid();
    preflight(workspace.path(), &[], None, &WorkspaceWriteMode::DirectRw).expect("preflight");
    // 使い捨てworkspaceの台帳エントリを落とす（既存スパイクと同じ撤収）。
    // **作りっぱなしにしない**——1回の測定ごとに1件積もる（B-02: 対の片方だけ実装しない）。
    let _capability_cleanup = super::test_support::scopeguard(|| {
        super::mac_spike_tests::forget_workspace_capability(workspace.path())
    });
    grant_job::wait_until_done().expect("background grant job");

    let traverse = traverse_capability_sid().expect("traverse capability");
    let workspace_cap = workspace_capability_for(workspace.path());
    // 主体A: 本番の`spawn_with_workspace`が積むのと同じ組（traverse＋workspace）。
    let mut production_caps: Vec<PSID> = vec![traverse.as_psid()];
    if let Some(cap) = &workspace_cap {
        production_caps.push(cap.as_psid());
    }
    // 主体B: workspace capabilityを持たない狭いドメイン相当。
    let narrow_caps: Vec<PSID> = vec![traverse.as_psid()];

    let probe = probe_exe();
    let probe_str = probe
        .to_str()
        .expect("probe path is valid utf-8")
        .to_string();

    // 差し込んだ関数の中で測った結果を持ち帰る器。`ChainLauncher`は`&dyn Fn`なので
    // 内側で書き換えるには内部可変性が要る。
    let observed: RefCell<Vec<ProbeRun>> = RefCell::new(Vec::new());
    let observed_pipe_name: RefCell<Option<String>> = RefCell::new(None);
    // 対照C2だけは完了を待たずに預ける（理由は起動箇所のコメント）。
    let control_open_child: RefCell<Option<SpikeChild>> = RefCell::new(None);

    {
        let run_probe = |label: &'static str,
                         args: &[&str],
                         capabilities: &[PSID],
                         no_appcontainer: bool| {
            let mut child = SpikeSpawn {
                exe: &probe_str,
                args,
                cwd: workspace.path(),
                container_sid: sid.as_psid(),
                capabilities,
                child_process_restricted: false,
                stdout_override: None,
                extra_inherit: &[],
                process_sddl: None,
                thread_sddl: None,
                token_default_dacl_sddl: None,
                no_appcontainer,
                console: SpikeConsole::NoWindow,
            }
            .spawn()
            .unwrap_or_else(|e| panic!("{label}のプローブを起動できなかった: {e}"));
            let (stdout, stderr, _code) = child.wait_and_read();
            let report = last_json_line(&stdout)
                .unwrap_or_else(|| panic!("{label}のプローブがJSONを出さなかった: {stdout}"));
            // **その場で出す。** 後段のassertで落ちたときに、ここまでに測れた分が
            // 道連れで消えるのを防ぐ（測定は再実行のたびに的が変わる）。
            eprintln!("[T4] {label}: {report}");
            observed.borrow_mut().push(ProbeRun {
                label,
                report,
                stderr,
            });
        };

        // **ヘルパーは起こさない**（モジュールdoc「生きたパイプを、昇格せずに測る仕掛け」）。
        let launcher = |pipe_name: &str| -> Result<(), String> {
            *observed_pipe_name.borrow_mut() = Some(pipe_name.to_string());

            // 名前の先取り用の的。**まだ存在しない**harness形の名前を2つ作る（主体Aと対照で
            // 別の名前を使う——同じ名前だと、先に取った側のせいで後の測定が変わる）。
            let squat_sandboxed = format!("{pipe_name}-t4-squat-sandboxed");
            let squat_control = format!("{pipe_name}-t4-squat-control");
            // harnessと無関係な名前も1つ撃つ。**「この名前だから作れない」と「そもそも
            // パイプを1本も作れない」は別の事実**で、これが分かれないと先取りの可否を
            // 誤読する（前者なら名前の形が守っていることになるが、そんな機構は無い）。
            let neutral_sandboxed = format!(r"\\.\pipe\t4-neutral-sandboxed-{}", std::process::id());
            let neutral_control = format!(r"\\.\pipe\t4-neutral-control-{}", std::process::id());

            // --- 主体A: 本番と同じcapabilityのAppContainer子（開く・相乗り・列挙・先取り） ---
            run_probe(
                "主体A（本番形のAppContainer子）",
                &[
                    "--reach-pipe",
                    pipe_name,
                    "--reach-create-pipe-instance",
                    pipe_name,
                    "--reach-pipe-enumerate",
                    "--reach-create-pipe-new",
                    &squat_sandboxed,
                    "--reach-create-pipe-new",
                    &neutral_sandboxed,
                    "--timeout-secs",
                    "60",
                ],
                &production_caps,
                false,
            );

            // --- 主体B: workspace capabilityを持たない狭い子（開くだけ） ---
            run_probe(
                "主体B（workspace capability無しのAppContainer子）",
                &["--reach-pipe", pipe_name, "--timeout-secs", "60"],
                &narrow_caps,
                false,
            );

            // --- 対照C1: 素のユーザー。**開かない**測定だけ（開くと1本しかない口を消費する） ---
            run_probe(
                "対照C1（素のユーザー・開かない測定）",
                &[
                    "--reach-create-pipe-instance",
                    pipe_name,
                    "--reach-pipe-enumerate",
                    "--reach-create-pipe-new",
                    &squat_control,
                    "--reach-create-pipe-new",
                    &neutral_control,
                    "--timeout-secs",
                    "60",
                ],
                &[],
                true,
            );

            // --- 対照C2: 素のユーザーが実際に開いて1往復する（最後に撃つ） ---
            //
            // **待たずに起動する。** 本番が電文を書くのは、この関数が戻ってIPCの交換が
            // 始まってからである。ここで完了を待つと、応答を待つプローブと電文を書く前の
            // 本番とで**互いに待ち合う**（最初の実行で実際に61秒固まって取りこぼした）。
            // 回収は本番の要求が終わったあとで行う。
            let child = SpikeSpawn {
                exe: &probe_str,
                args: &["--pipe-client", pipe_name, "--timeout-secs", "60"],
                cwd: workspace.path(),
                container_sid: sid.as_psid(),
                capabilities: &[],
                child_process_restricted: false,
                stdout_override: None,
                extra_inherit: &[],
                process_sddl: None,
                thread_sddl: None,
                token_default_dacl_sddl: None,
                no_appcontainer: true,
                console: SpikeConsole::NoWindow,
            }
            .spawn()
            .map_err(|e| format!("対照C2のプローブを起動できなかった: {e}"))?;
            // 起動しただけでは接続していない。本番の`ConnectNamedPipe`より先でも後でも
            // 成立するので順序は問わないが、**起動が済んだこと**だけは確かめてから戻る。
            child.pid();
            *control_open_child.borrow_mut() = Some(child);

            Ok(())
        };

        // 空の要求（付与対象0件・穴0件）。パイプだけが本物になり、実マシンには何も起こらない。
        let outcome = crate::tier2a::privhelper::run_privileged_workspace_access(
            Vec::new(),
            Vec::new(),
            None,
            Some(&launcher),
        );
        eprintln!(
            "[T4] 本番要求の終わり方（ヘルパーを起こしていないのでエラーが正常）: {outcome:?}"
        );

        // 対照C2をここで回収する（本番が電文を書き終えた後でないと1往復が閉じない）。
        let mut child = control_open_child
            .borrow_mut()
            .take()
            .expect("対照C2が起動していない");
        let (stdout, stderr, _code) = child.wait_and_read();
        let report = last_json_line(&stdout)
            .unwrap_or_else(|| panic!("対照C2のプローブがJSONを出さなかった: {stdout}"));
        eprintln!("[T4] 対照C2（素のユーザー・開いて1往復）: {report}");
        observed.borrow_mut().push(ProbeRun {
            label: "対照C2（素のユーザー・開いて1往復）",
            report,
            stderr,
        });
    }

    // --- ここから判定 ---
    let pipe_name = observed_pipe_name
        .borrow()
        .clone()
        .expect("ChainLauncherが呼ばれていない（本番がパイプを作る前に落ちた可能性）");
    assert!(
        pipe_name.starts_with(r"\\.\pipe\harness-privhelper-"),
        "測った的が本番のprivhelperパイプではない: {pipe_name}"
    );

    let runs = observed.borrow();
    assert_eq!(runs.len(), 4, "4本すべてのプローブが走っていない");
    for run in runs.iter() {
        eprintln!(
            "[T4] {}: {}\n      stderr={}",
            run.label, run.report, run.stderr
        );
    }
    let sandboxed = &runs[0].report;
    let narrow = &runs[1].report;
    let control_closed = &runs[2].report;
    let control_open = &runs[3].report;

    // --- 許可側（対照）が成立していること。ここが崩れると拒否側の測定は無意味 ---
    assert_eq!(
        control_open.get("connected").and_then(|c| c.as_bool()),
        Some(true),
        "素のユーザーからも生きたパイプへ接続できていない。的が居なかっただけの可能性があり、\
         拒否側の測定を結論に使えない: {control_open}"
    );

    // --- 拒否側 ---
    assert_eq!(
        ok_of(sandboxed, "pipe-open"),
        Some(false),
        "**本番形のAppContainerの子が、生きたprivhelperのパイプを開けた**。#20の前提が崩れる: {sandboxed}"
    );
    assert_eq!(
        ok_of(narrow, "pipe-open"),
        Some(false),
        "workspace capabilityを持たない子が生きたprivhelperのパイプを開けた: {narrow}"
    );

    // --- 隣接する3つの原始は、真偽を固定せず**撃ったことだけ**を強制する ---
    // どちらへ転ぶかが未知なので、期待値をここへ書かない（書くと測定ではなく確認になる）。
    // ただし「モードごと落ちていて何も撃っていない」は成功に見えてはいけない（B-10）。
    for (label, report, kinds) in [
        (
            "主体A",
            sandboxed,
            &["pipe-create-instance", "pipe-enumerate", "pipe-create-new"][..],
        ),
        (
            "対照C1",
            control_closed,
            &["pipe-create-instance", "pipe-enumerate", "pipe-create-new"][..],
        ),
    ] {
        for kind in kinds {
            assert!(
                attempt_of(report, kind).is_some(),
                "{label}が`{kind}`を撃っていない（プローブのモードが届いていない）: {report}"
            );
        }
    }

    // --- 転記用のレポートを1ファイルへ落とす（stdoutの拾い漏れを防ぐ） ---
    // **摘み食いをせず、撃った的をそのまま残す。** 同じ`kind`を複数撃つ的（名前の先取りは
    // harness形と無関係な名前の2本）があるので、要約すると片方が消える。
    let summary = json!({
        "measurement": "T4",
        "live_pipe": pipe_name,
        "production_request_outcome": "Err(Ipc: failed to parse helper response) ＝ヘルパーを起こしていないので想定どおり",
        "subjects": {
            "A_production_appcontainer_child": sandboxed,
            "B_narrow_appcontainer_child": narrow,
            "C1_plain_user_without_opening": control_closed,
            "C2_plain_user_round_trip": control_open,
        },
        "key_readings": {
            "A_pipe_open_ok": ok_of(sandboxed, "pipe-open"),
            "A_pipe_open_last_error": err_of(sandboxed, "pipe-open"),
            "B_pipe_open_ok": ok_of(narrow, "pipe-open"),
            "B_pipe_open_last_error": err_of(narrow, "pipe-open"),
            "C2_connected": control_open.get("connected"),
        },
    });
    let report_path = std::path::Path::new(r"C:\harness-e2e\_scratch").join(format!(
        "t4-pipe-reach-{}.json",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    ));
    if let Some(dir) = report_path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    match std::fs::write(&report_path, serde_json::to_vec_pretty(&summary).unwrap()) {
        Ok(()) => eprintln!("[T4] レポート: {}", report_path.display()),
        Err(e) => eprintln!("[T4] レポートを書けなかった（測定自体は上のログにある）: {e}"),
    }
}
