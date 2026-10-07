//! M16: 妥当性（Validity）の経路を**本物のMCPサーバ**で通す
//!
//! `docs/STATUS.md`認知レイヤー残課題#4は「M16はスタブMCPツールで全経路を単体・統合テスト
//! 済みだが、M15.5が実装した本物のMCPサーバ経由での裏取りは通していない」だった。ここが
//! 埋めるのは**配線**である——実MCPクライアント（AppContainer隔離下のstdioサーバ）→
//! `ToolRegistry`への`mcp__<server>__<tool>`登録 → SourceBrokerのカタログ →
//! `Corroborated`昇格 → 最終回答の表示、が実起動経路で繋がっているか。
//!
//! **モデルのツール選択能力は測らない。** 2026-08-04のLMStudio実機E2Eが表示経路へ到達
//! しなかった原因はそちら（`docs/STATUS.md`認知レイヤー残課題#10＝ローカルモデルが
//! `read_file`を呼べない）で、M16の配線とは別の変数である。混ぜると「配線が壊れている」と
//! 「モデルが道具を選べない」を切り分けられないので、`--provider mock --mock-turns`で
//! フェーズ出力を台本化して固定する。
//!
//! 成功対照（宣言あり＝`corroborated`）と失敗対照（宣言なし＝`single_source`＋「MCP裏取り
//! 不可」）を必ず**組**で回す。片方だけでは、見えた表示が本当にMCP由来かを言えない。
//!
//! `dev-elevated-run.exe e2e-mcp-corroboration`（フィルタ`tier2a_mcp_corroboration`）。
//!
//! # 成功対照はWFPが立ったことも確かめる（[BUG-239]）
//!
//! この台本のサーバは通信を要求しない（いちばん普通の形）。かつては、そういうサーバにも許可ポートが
//! 空のWFPの項目が積まれ、`netfilterd`が全体を失敗させて**セッションのWFPが立たなかった**。
//! それでもこの試験は緑だった——通信を要求しないサーバはWFPが無くても起動対象に残るので、
//! 裏取りの経路は通るからである。だから成功対照では、WFPが立たなかったときに必ず出る句
//! （`wfp_outcome::TIER2A_NET_DENIED`）が標準エラーに**無い**ことも確かめる。
//!
//! 2026-10-07に`tier2a_e2e.rs`から子モジュールへ移した（あちらは1万行を超えている。
//! `docs/CODE-STRUCTURE-RULES.md`規則1）。試験の名前は変えていないので、キーのフィルタは同じものに当たる。

use super::*;

/// 検証用MCPサーバ（`crates/harness-mcp/src/bin/mcp-mock-server.rs`）。
///
/// `cargo test -p harness-cli`はこのbinをビルドしない（`CARGO_BIN_EXE_*`が渡るのは
/// 同じパッケージのbinだけ）ので、`net_probe_exe`と同じく**事前ビルドを前提条件**にする。
/// 無ければ手順を添えて落とす——黙って飛ばすと「0件で緑」になる（BUG-056と同じ形）。
fn mcp_mock_server_exe() -> Result<PathBuf, String> {
    let exe = harness_exe()
        .parent()
        .expect("harness exe has a parent dir")
        .join("mcp-mock-server.exe");
    if !exe.exists() {
        return Err(format!(
            "{} not found. build it first: cargo build -p harness-mcp --bin mcp-mock-server",
            exe.display()
        ));
    }
    Ok(exe)
}

/// M16の台本が使うMCPサーバid（`mcp__docs__search`へ名前空間化される）。
const MCP_SERVER_ID: &str = "docs";
const MCP_SEARCH_TOOL: &str = "mcp__docs__search";

/// ワークスペースを作る。`declare_server`が偽なら**MCPの宣言だけを落とす**——他は
/// 完全に同一にして、2つの実行の差が「サーバが居るかどうか」だけになるようにする。
fn mcp_case_workspace(name: &str, declare_server: bool) -> Result<PathBuf, String> {
    let ws = case_dir(name);
    // ローカル一次証拠（§4.2の接地優先順位1）。台本のラウンド1がこれを読む。
    std::fs::write(
        ws.join("shell.rs"),
        "let mut cmd = Command::new(\"powershell.exe\");",
    )
    .map_err(|e| e.to_string())?;

    let harness_dir = ws.join(".harness");
    std::fs::create_dir_all(&harness_dir).map_err(|e| e.to_string())?;

    // `cognition.sources`はどちらの構成でも書く。宣言だけあってツールが登録されていなければ
    // `SourceCatalog::available`から落ちる＝MCP未接続として扱われる、という設計
    // （`harness-cognition`の`source.rs`）そのものを実起動経路で確認するため。
    let mut settings = serde_json::json!({
        "cognition": {
            "sources": [
                { "id": "mcp/docs", "kind": "mcp", "use_for": ["社内仕様"], "trust": "high" }
            ]
        }
    });
    if declare_server {
        let exe = mcp_mock_server_exe()?;
        settings["mcp"] = serde_json::json!({
            "servers": [{
                "id": MCP_SERVER_ID,
                "transport": "stdio",
                "command": exe.display().to_string(),
                // D-40: 宣言したツールだけがread扱いになる。`search`をread-onlyにするのは
                // Investigate（ToolGateがReadOnlyしか候補に入れない）で呼ばせるため。
                // workspace要求もnetwork要求も**書かない**（既定＝ACE無し・全拒否）。
                // 裏取りに要るのはサーバ自身の応答だけで、workspaceを読ませる理由が無い。
                "tools": { "search": "read_only" }
            }]
        });
    }
    std::fs::write(
        harness_dir.join("settings.json"),
        serde_json::to_string_pretty(&settings).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    Ok(ws)
}

/// `harness mcp approve <id> --yes` / `revoke <id>`（D-39の承認台帳）。
/// 台帳はユーザグローバル（`%APPDATA%\harness\config\mcp-approval-ledger.json`）なので、
/// ケースの最後で必ず`revoke`して元へ戻す。
fn mcp_approval(ws: &Path, action: &str) -> Result<String, String> {
    let mut cmd = Command::new(harness_exe());
    cmd.args(["--cwd", ws.to_str().unwrap(), "mcp", action, MCP_SERVER_ID]);
    if action == "approve" {
        cmd.arg("--yes");
    }
    let out = cmd
        .output()
        .map_err(|e| format!("failed to run `harness mcp {action}`: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() {
        return Err(format!(
            "`harness mcp {action} {MCP_SERVER_ID}` failed: {stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(stdout)
}

fn phase_text_turn(value: serde_json::Value) -> Vec<StreamEvent> {
    end_turn(&value.to_string())
}

/// Investigateのターン。**計画のJSONとツール呼び出しを同じメッセージで返す**
/// （mockの`schema_with_tools:true`により`CallKind::Fused`になる）。
///
/// `recall_e2e.rs`の同名の関数とは計画の形が違う（こちらはJSONの計画で呼び出しIDを変える）
/// ので共有していない（`support`のdoc）。
fn plan_and_tool_turn(id: &str, tool: &str, input: serde_json::Value) -> Vec<StreamEvent> {
    vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::Text,
        },
        StreamEvent::TextDelta {
            index: 0,
            text: serde_json::json!({
                "plan": [{ "source": tool, "query": "run_shell", "expects": "起動するシェル名" }]
            })
            .to_string(),
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::BlockStart {
            index: 1,
            kind: BlockKind::ToolUse {
                id: id.to_string(),
                name: tool.to_string(),
            },
        },
        StreamEvent::ToolInputDelta {
            index: 1,
            json_fragment: input.to_string(),
        },
        StreamEvent::BlockStop { index: 1 },
        StreamEvent::Done {
            stop_reason: StopReason::ToolUse,
            usage: Usage::default(),
        },
    ]
}

/// 「ローカルで見つけた主張を、次のラウンドでMCPが裏取りする」2ラウンドの台本。
/// `crates/harness-cognition/tests/m16_validity_transcript.rs`の`corroboration_script`と
/// 同じ形で、**MCPツールだけが本物**（あちらはスタブツール）。
fn mcp_corroboration_turns() -> Vec<Vec<StreamEvent>> {
    let distill = |claim: &str| {
        phase_text_turn(serde_json::json!({
            "evidence": [{
                "claim": claim,
                "relation": "supports",
                "source": "（自己申告の出典は台帳に入らない）",
                "contradicts": []
            }]
        }))
    };
    vec![
        phase_text_turn(serde_json::json!({
            "hypotheses": [{
                "statement": "run_shellはPowerShellを起動している",
                "predicts": ["shell.rsにpowershellの記述が無ければ偽"],
                "confidence": 0.7
            }]
        })),
        // ラウンド1: ワークスペースの実ファイル（接地優先順位1）。
        plan_and_tool_turn(
            "call_1",
            "read_file",
            serde_json::json!({ "path": "shell.rs" }),
        ),
        distill("shell.rsがpowershell.exeを起動している"),
        // まだ裏取りできていないので決着させない。
        phase_text_turn(serde_json::json!({
            "verdict": "inconclusive", "missing": ["別系統の裏取り"], "note": "ローカル観測のみ"
        })),
        // ラウンド2: 実MCPサーバで裏取り（接地優先順位2）。
        plan_and_tool_turn(
            "call_2",
            MCP_SEARCH_TOOL,
            serde_json::json!({ "query": "run_shell" }),
        ),
        distill("社内仕様もPowerShellを既定としている"),
        phase_text_turn(serde_json::json!({
            "verdict": "confirms", "missing": [], "note": "2系統で一致した"
        })),
        phase_text_turn(serde_json::json!({
            "action": "PowerShellを前提に手順を書く",
            "then_verify": "run_shellでecho $PSVersionTableを実行する"
        })),
    ]
}

fn run_cognition_harness(ws: &Path, case_name: &str) -> HarnessRun {
    // **前の回が残した記憶を消してから撃つ。** `--cognition always`はゴール完了時に記憶を書き、
    // 消すのは成功した回の`cleanup_on_success`だけである。失敗した回の記憶が残っていると、次の回で
    // 「過去の記憶の候補」を載せた呼び出しが先に台本を食べてずれ、裏取りの経路に届かない
    // （2026-10-07に実際に起きた。BUG-239の検証の2回目）。ワークスペースは`case_dir`が作り直している。
    let _ = std::fs::remove_dir_all(recall_data_root(&scratch_dir(), case_name));
    run_harness(
        ws,
        &mcp_corroboration_turns(),
        &["--cognition", "always"],
        case_name,
    )
}

/// モックへ実際に送られたリクエストの中に、そのツール名のspecが載っていたか。
/// 「MCPサーバが起動して`tools/list`が返り、`ToolRegistry`へ登録された」ことの直接の証拠。
fn recorded_requests_offer_tool(run: &HarnessRun, tool: &str) -> Result<bool, String> {
    let data = std::fs::read_to_string(&run.record_path)
        .map_err(|e| format!("failed to read {}: {e}", run.record_path.display()))?;
    for line in data.lines() {
        let req: CompletionRequest = serde_json::from_str(line)
            .map_err(|e| format!("recorded request is not valid JSON: {e}"))?;
        if req.tools.iter().any(|t| t.name == tool) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// 成功対照: 宣言・承認済みの実MCPサーバがあると、ローカル観測がMCPで裏取りされて
/// `corroborated`まで上がり、「MCP裏取り不可」の注記は出ない。
fn mcp_case_real_server_corroborates_a_local_observation() -> Result<(), String> {
    let ws = mcp_case_workspace("mcp-corroborated", true)?;
    mcp_approval(&ws, "approve")?;
    let run = run_cognition_harness(&ws, "mcp-corroborated");
    // 承認台帳はユーザグローバルなので、判定より先に必ず戻す。
    let revoked = mcp_approval(&ws, "revoke");

    let json = parse_json_stdout(&run)?;
    // 探す語はどちらも**最終応答文**に着地する（`corroborated`は`Grade::Corroborated`のラベル、
    // 「MCP裏取り不可」は`hiv/answer.rs`が本文へ書く注記）。JSON全体を見ると、無関係な
    // ツール入力にも当たり得る（BUG-137）。
    let text = json.answer();
    revoked?;

    if !recorded_requests_offer_tool(&run, MCP_SEARCH_TOOL)? {
        return Err(format!(
            "{MCP_SEARCH_TOOL} was never offered to the model -- the mcp server did not start or \
             its tools were not registered. stderr={}",
            run.stderr
        ));
    }
    if !text.contains("corroborated") {
        return Err(format!(
            "the answer does not report a corroborated grade (real-mcp cross-source did not \
             land): {text}\nstderr={}",
            run.stderr
        ));
    }
    if text.contains("MCP裏取り不可") {
        return Err(format!(
            "the answer claims MCP corroboration was unavailable even though the server ran: {text}"
        ));
    }
    // [BUG-239] 通信を要求しないサーバが居ても、セッションのWFPは立つ（モジュールdoc）。
    session_wfp_came_up(&run, "a server that requests no network was declared")?;

    cleanup_on_success(&ws, &[], "mcp-corroborated");
    Ok(())
}

/// 失敗対照: **同じ台本**でMCPの宣言だけを外すと、裏取りは成立せず`single_source`のまま
/// 結論し、「MCP裏取り不可」を明記する（§4.2「隠さない」）。上のケースで見えた
/// `corroborated`が本当にMCP由来だったことは、この対照が付いて初めて言える。
fn mcp_case_without_the_declaration_it_stays_single_source() -> Result<(), String> {
    let ws = mcp_case_workspace("mcp-single-source", false)?;
    let run = run_cognition_harness(&ws, "mcp-single-source");

    let json = parse_json_stdout(&run)?;
    // 上のケースと対称に、最終応答文だけを見る（BUG-137）。
    let text = json.answer();

    if recorded_requests_offer_tool(&run, MCP_SEARCH_TOOL)? {
        return Err(format!(
            "{MCP_SEARCH_TOOL} was offered even though no server is declared -- the two runs are \
             not differing only in the declaration. stderr={}",
            run.stderr
        ));
    }
    if !text.contains("single_source") {
        return Err(format!("the answer does not report single_source: {text}"));
    }
    if !text.contains("MCP裏取り不可") {
        return Err(format!(
            "a single-source conclusion must say that MCP corroboration was unavailable: {text}"
        ));
    }
    // [BUG-239] の対照: 宣言が無い回もWFPは立つ。上のケースでだけWFPが落ちたなら、
    // 原因は環境（`harness-netfilterd.exe`の不在等）ではなく宣言の側だと言える。
    session_wfp_came_up(&run, "no mcp server was declared")?;

    cleanup_on_success(&ws, &[], "mcp-single-source");
    Ok(())
}

/// セッションのWFPが立ったか。立たなかった回は、どの経路でも`wfp_outcome::TIER2A_NET_DENIED`を
/// 標準エラーへ出す（BUG-111でその句へ集約してある）。ここが見るのはその接頭辞で、
/// `tier2a_smb445_layer2`の不在チェックと同じ綴りである。
fn session_wfp_came_up(run: &HarnessRun, condition: &str) -> Result<(), String> {
    if run
        .stderr
        .contains("Tier2a run_shell network capability will remain denied")
    {
        return Err(format!(
            "the session's WFP did not come up while {condition} (an entry with no allowed port \
             makes netfilterd fail the whole ApplyRules). stderr={}",
            run.stderr
        ));
    }
    Ok(())
}

#[test]
#[ignore]
fn tier2a_mcp_corroboration() {
    let cases: Vec<(&str, CaseFn)> = vec![
        (
            "real-server-corroborates",
            mcp_case_real_server_corroborates_a_local_observation,
        ),
        (
            "no-declaration-stays-single-source",
            mcp_case_without_the_declaration_it_stays_single_source,
        ),
    ];
    let mut passed = 0;
    let total = cases.len();
    for (name, f) in cases {
        if run_named_case(name, f) {
            passed += 1;
        }
    }
    assert_eq!(
        passed, total,
        "{passed}/{total} mcp corroboration cases passed (see per-case JSON above)"
    );
}
