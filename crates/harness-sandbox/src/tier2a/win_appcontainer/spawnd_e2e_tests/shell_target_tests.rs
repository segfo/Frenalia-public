//! [残課題#50] **既定のシェルを「呼び出し元の中から起こす遷移先」にできるか**——
//! 綴りを1つだけ変えて3本撃つ測定。記録は`plans/mac-spike/RESULTS.md` §S62（§S59の続き）。
//!
//! # 何が分からなかったのか
//!
//! この機のpwsh 7は**ストアの実行エイリアス**（`WindowsApps\pwsh.exe`。中身0バイトの飛び先で、
//! OSがアプリの仕組みを通して本体を起こす）である。そうして起きたプロセスは
//! **OSが自分のJob**（プロセスの群れをまとめて始末する入れ物）**へ先に入れる**ので、
//! こちらの系統Jobに誰か1人でも居ると入れられない（§S59）。系統Jobには必ず呼び出し元が居る。
//!
//! **一方、実体のパスなら通るのかは一度も測っていない。** 近い測定（§S1b、2026-08-13）は
//! **逆のこと**を言っている——「MSIXの実体パスはAppContainerの中で`ERROR_INVALID_PARAMETER`、
//! 通るのはエイリアスの方」。ただしあれは**トップレベル**の測定で、ここで問うているのは
//! **nested**（呼び出し元の中から起こす側）である。**だから測り直す。**
//!
//! # 変える軸は「遷移先の綴り」1つだけ
//!
//! | 腕 | 遷移先 | 役割 | 2026-09-18の結果 |
//! |---|---|---|---|
//! | A | ストアの実行エイリアス | **負の対照**（§S59の再現） | ❌ `AssignProcessToJobObject`がアクセス拒否 |
//! | B | MSIXの実体 | **測りたかった1点** | ❌ `CreateProcessW`が`ERROR_INVALID_PARAMETER` |
//! | C | Windows PowerShell 5.1（System32の本物） | **正の対照**＝計器が生きている証拠 | ✅ 起きて走った |
//!
//! **結論**: ストア版のPowerShell 7は、どちらの綴りでも遷移先にできない。だから
//! **生成禁止を積む構成では、アプリの仕組みを通る綴りをシェルの候補から外す**
//! （`spawn.rs`の`shell_candidates_from`）。この測定が、その判断の唯一の根拠である
//! ——だからA・Bが**通ってしまった日には赤くして知らせる**。
//!
//! ほかは全部同じである（AppContainerの中・生成禁止あり・要求受付パイプ経由・
//! コンソール要と申告・同じ印・同じ判定・**同じDaemon1本**）。
//!
//! # 判定を終了コードに預けない
//!
//! PowerShellは**コンソールが無いと何も実行せず終了コード0**で終わる（§7.1の無言失敗）。
//! だから実行印を標準出力へ出させ、**印と応答の両方**を見る（§S1b・T5と同じ判定）。
//!
//! # ここで測っていないもの（**limitation**）
//!
//! - **トップレベルの起動**。段階⑤の受け入れ2本が`resolve_shell()`（この機ではエイリアス）を
//!   生成禁止つきで撃って緑なので、既に測ってある（`child_process_restricted_tests`）
//! - **エイリアス以外にも同じ形があるか**（自分のJobへ入るOSの経路は他にもあり得る）
//! - **製品経路**。製品は生成禁止を積んでいないので、nestedの遷移そのものが起きない

use super::transition_acceptance_tests::{
    ask_daemon_as_a_hook, policy_with_edges, windows_powershell_51,
};
use super::*;

/// 1本の腕。`exe`が`None`は「**この機にその綴りが無い**」であって「起こせない」ではない。
struct Arm {
    label: &'static str,
    exe: Option<String>,
}

/// 測定の1行（表へ出すためだけの入れ物）。
struct Row {
    label: &'static str,
    exe: String,
    reply: String,
    reason: String,
    ran: bool,
}

impl Row {
    /// 「起こせて、しかも実際に走った」——この2つが揃って初めて遷移先にできたと言える。
    fn started_and_ran(&self) -> bool {
        self.reply == "spawned" && self.ran
    }
}

/// 腕A・腕Bが**通ってしまった**ときに出す文面。
///
/// **これは失敗ではなく朗報の可能性である。** 経緯を知らない人が1回だけ読む前提で書く
/// （残課題#52の見張りと同じ書き方。`page_heap_fault_tests`）。
fn os_constraint_may_be_lifted_message(row: &Row) -> String {
    // **1行ずつの配列で持つ。** 文字列の行継続（`\`）は次の行の行頭の空白を食う。
    let lines = [
        "",
        "========================================================================",
        " これはテストの失敗ではなく、**朗報の可能性**です。",
        " **OS側の制約が外れたようなので、迂回の撤収を検討してください。**",
        "========================================================================",
        "",
        "【何が起きていたか】",
        "  Microsoft Store版のPowerShell 7は、**サンドボックスの中のプログラムから",
        "  起こすことができません**。入口が2つあり、どちらも別々の理由で塞がっています",
        "  （2026-09-18に測定。plans/mac-spike/RESULTS.md §S62）。",
        "",
        "    ・実行エイリアス（`pwsh.exe`という名前の0バイトの飛び先）",
        "        → これで起きたプロセスは、OSが自分のJob（プロセスの群れをまとめて",
        "          終わらせるための入れ物）へ先に入れてしまいます。こちらは",
        "          「1つのコマンドの子孫だけをまとめて殺せる」ようにするため、",
        "          呼び出し元と同じJobへ子を入れる決まりなので、入れ物が二重になって",
        "          OSに拒否されます（AssignProcessToJobObject がアクセス拒否）。",
        "",
        "    ・パッケージの実体（`Program Files\\WindowsApps\\...\\pwsh.exe`）",
        "        → そもそも起動できません（CreateProcessW がパラメーター違い）。",
        "",
        "  そのため、テストや宣言では**アプリの仕組みを通らない本物のexe**",
        "  （System32のWindows PowerShell 5.1など）を使う迂回をしていました。",
        "",
        "【いま何が変わったか】",
        "  そのどちらかで起こす遷移が**通りました**。つまりOS側の制約が外れたか、",
        "  この機のPowerShellの入り方が変わった（例: ストア版ではなくMSI版が入った）",
        "  かのどちらかです。",
        "",
        "【次にすること】",
        "  1. もう一度この的を撃ってください:",
        "       target\\debug\\dev-elevated-run.exe spawn-daemon",
        "     1回では断定しません（§S59の観測は2腕×1回です）。",
        "",
        "  2. 下の `exe=` が本当にストアの実行エイリアスか確かめてください。",
        "     `C:\\Program Files\\PowerShell\\7\\pwsh.exe` のような実体のパスなら、",
        "     **OSは何も変わっておらず、この機の入れ方が変わっただけ**です。",
        "",
        "  3. 本当に制約が外れていたら、迂回を撤去します:",
        "       - crates/harness-sandbox/.../win_appcontainer/spawn.rs",
        "           starts_through_the_app_model と、それを使う shell_candidates_from の分岐",
        "           （生成禁止を積むときにpwsh 7を候補から外している箇所）",
        "       - crates/harness-sandbox/.../spawnd_e2e_tests/transition_acceptance_tests.rs",
        "           windows_powershell_51 と、それを使っているT5・T6のコメント",
        "       - crates/harness-sandbox/.../spawnd_e2e_tests/transparent_hook_tests.rs",
        "           モジュールdocの「ストアの実行エイリアスへの遷移」の行",
        "       - docs/STATUS.md の残課題#50",
        "       - plans/DESIGN-MAC-ENFORCEMENT.md §10.1.2 の",
        "           「実行エイリアスは、いまは遷移先にできない」小節",
        "       - このファイル（測定そのものが要らなくなります）",
        "",
        "  4. 経緯の全文は plans/mac-spike/RESULTS.md の §S59 と §S62 にあります。",
        "",
        "【この回の結果】",
    ];
    format!(
        "{}\n  {} reply={} reason={} 実行印={} exe={}\n",
        lines.join("\n"),
        row.label,
        row.reply,
        if row.reason.is_empty() {
            "-"
        } else {
            &row.reason
        },
        if row.ran { "出た" } else { "出ない" },
        row.exe
    )
}

/// **§S62**: 遷移先の綴りを3通り変えて、どれがnestedで起こせるかを1回の起動で測る。
#[test]
#[ignore = "starts a real spawn daemon and AppContainer children; run through spawn-daemon"]
fn which_spelling_of_the_shell_can_be_a_nested_transition_target() {
    const MARKER: &str = "HARNESS-50-SHELL-RAN";

    let arms = [
        Arm {
            label: "A ストアの実行エイリアス",
            exe: super::super::mac_spike_followup_tests::store_alias_pwsh_path(),
        },
        Arm {
            label: "B MSIXの実体",
            exe: super::super::mac_spike_followup_tests::msix_pwsh_path(),
        },
        Arm {
            label: "C Windows PowerShell 5.1",
            exe: Some(windows_powershell_51()),
        },
    ];

    // **測れなかったものを空欄にしない**（`B-10`）。とくにBは、この回で測りたい1点そのもの
    // ——見つからないまま緑になると「測って決めた」と読まれる記録だけが残る。
    assert!(
        arms[1].exe.is_some(),
        "MSIX版pwsh 7の実体パスが特定できないので、**この測定の目的が果たせない**。\
         `Get-AppxPackage Microsoft.PowerShell`が空なら、この機にストア版は入っていない\
         ——そのときは残課題#50の前提（既定のシェルが実行エイリアス）自体が成り立たないので、\
         先に`resolve_shell()`が何を返すかを確かめること"
    );

    let declared: Vec<&str> = arms.iter().filter_map(|arm| arm.exe.as_deref()).collect();
    let (case, profile, caps) = setup_with_policy_and_transitions(
        "spawnd-50-shell-target",
        // **生成禁止を積む。** 積まないとフックが自分で起こせてしまい、
        // 「Daemonが遷移先として起こせるか」を測っていないことになる。
        ChildProcessPolicy::Restricted,
        |_workspace| policy_with_edges(E2E_POLICY_DOMAIN, &declared),
    );
    let workspace = case
        .dir
        .as_ref()
        .expect("case owns the dir")
        .path()
        .to_path_buf();

    let mut rows: Vec<Row> = Vec::new();
    for (index, arm) in arms.iter().enumerate() {
        let Some(exe) = arm.exe.as_deref() else {
            rows.push(Row {
                label: arm.label,
                exe: "（この機に無い）".to_string(),
                reply: "測れなかった".to_string(),
                reason: String::new(),
                ran: false,
            });
            continue;
        };
        let captured = workspace.join(format!("shell-target-{index}.txt"));
        let out = ask_daemon_as_a_hook(
            &case,
            &profile,
            &caps,
            exe,
            &format!("\"{exe}\" -NoProfile -NonInteractive -Command \"Write-Output '{MARKER}'\""),
            &captured,
            "required",
        );
        let text = std::fs::read_to_string(&captured).unwrap_or_default();
        rows.push(Row {
            label: arm.label,
            exe: exe.to_string(),
            reply: reply_kind(&out).unwrap_or_else(|| "（応答なし）".to_string()),
            reason: deny_reason(&out).unwrap_or_default(),
            ran: text.contains(MARKER),
        });
    }

    eprintln!("\n[§S62] 遷移先の綴りを1つだけ変えて撃った結果（生成禁止あり・コンソール要と申告）");
    for row in &rows {
        eprintln!(
            "  {:<26} reply={:<14} reason={:<20} 実行印={:<6} exe={}",
            row.label,
            row.reply,
            if row.reason.is_empty() {
                "-"
            } else {
                &row.reason
            },
            if row.ran { "出た" } else { "出ない" },
            row.exe
        );
    }

    // **正の対照。** これが落ちたら測れていない（計器の側が壊れている）ので、
    // 他の腕の結果を読んではいけない。
    let ps51 = &rows[2];
    assert!(
        ps51.started_and_ran(),
        "実体のパス（Windows PowerShell 5.1）すら遷移先にできていない。\
         **この回の測定は計器が壊れている**——生成禁止・コンソールの貸し出し・宣言の\
         いずれかが効いていないので、他の腕の結果は読まないこと: \
         reply={} reason={} 実行印={}",
        ps51.reply,
        ps51.reason,
        ps51.ran
    );

    // **負の対照 兼 見張り（2本）。** 2026-09-18の測定では、ストア版PowerShell 7は
    // **どちらの綴りでも**遷移先にできなかった（腕A＝Jobへ入れられない、
    // 腕B＝`CreateProcessW`がパラメーター違い）。**通ってしまった日は「失敗」ではなく
    // 朗報の可能性である**——`shell_candidates_from`が生成禁止のときpwsh 7を候補から
    // 外しているのは、この2本が塞がっていることだけが根拠だからである。
    for row in rows.iter().take(2) {
        if row.reply == "測れなかった" {
            eprintln!(
                "[§S62] {} はこの機に無いので測っていない。**「起こせない」と読まないこと。**",
                row.label
            );
            continue;
        }
        assert!(
            !row.started_and_ran(),
            "{}",
            os_constraint_may_be_lifted_message(row)
        );
    }

    drop(case);
}
