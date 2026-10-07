//! **[段階6f-1] フックの役を演じるモード**——サンドボックスの中から、呼び出し元の持ち物
//! （標準出力のハンドル）を載せてSpawn Daemonへ生成を頼み、**返ってきたハンドルで待つ**。
//!
//! # 何のためにあるのか
//!
//! 段階6f-1はDaemon側だけを仕上げる回で、Redirector DLLのフックは1行も変えていない。
//! だが「呼び出し元のstdioが子へ渡るか」「返ったプロセスハンドルで待てるか」は、
//! **頼む側が居なければ測れない**。そこでプローブがその役を演じる
//! （`--pipe-client`が窓口への到達だけを測るのと同じ位置付けで、こちらは1往復の**中身**を測る）。
//!
//! # 既存の`--pipe-client`と何が違うのか
//!
//! 接続と1往復そのものは[`crate::pipe_client`]をそのまま使う（**写さない**）。
//! ここが足すのは前後の2つだけである。
//!
//! 1. **前**: 子の標準出力にするファイルを継承可で開き、そのハンドル値を電文へ載せる
//! 2. **後**: 応答の`process`ハンドルで`WaitForSingleObject`し、終了コードを読む
//!
//! # 測れないことを測れたことにしない
//!
//! 待てなかった・終了コードが読めなかったときは、**その旨を欄に残す**（`B-10`）。
//! 「子が走らなかった」と「待てなかった」は別の事実で、混ぜるとDaemon側の不具合が
//! プローブ側の不具合に見える。

use serde_json::{json, Value};

/// 1回の「頼んで、待って、終了コードを読む」の設定。
#[cfg_attr(not(windows), allow(dead_code))]
pub struct Spec<'a> {
    /// 要求受付パイプの名前。
    pub pipe_name: &'a str,
    /// 起こす実行ファイルの**絶対パス**（電文の`image`）。
    pub image: &'a str,
    /// `lpCommandLine`へ逐語で渡る文字列（電文の`command_line`）。
    pub command_line: &'a str,
    pub cwd: &'a str,
    /// 子の標準出力を落とす先。**ここを開いたハンドルを電文へ載せる。**
    pub stdout_file: Option<&'a str>,
    /// [P5.4b] 子の標準入力にするファイル（読み取りで開いたハンドルを電文の`stdin`へ載せる）。`None`なら載せない。
    pub stdin_file: Option<&'a str>,
    /// 電文の`console`欄。**`"required"`か`"not_needed"`の綴りをそのまま運ぶ**
    /// ——ここで真偽値へ畳むと、取り違えたときにどちらを送ったのか報告から読めなくなる。
    pub console: &'a str,
    /// 応答のJSONの置き場（テスト側が読む）。
    pub report_file: Option<&'a str>,
    /// [#49] `CREATE_SUSPENDED`で頼むか。
    ///
    /// **返ってきたハンドルの権限を測るときは`true`にすること**——子が終わった後では
    /// `VirtualAllocEx`も失敗するので、「絞れたから失敗した」と「死んでいたから失敗した」が
    /// 区別できなくなる（[`crate::spawn_report::record_handle_rights`]）。
    /// 動かすのは測り終えた後で、`ResumeThread`はその測定の最後の1本そのものである。
    pub suspended: bool,
}

#[cfg(windows)]
pub fn run(spec: &Spec) -> Value {
    // **受け皿と待ち方はフック経由の腕と共有する**（[`crate::spawn_report`]）。
    // 欄がずれると2つの腕を比べられない。
    let mut stdout = crate::spawn_report::open_inheritable(spec.stdout_file);
    let mut stdin = crate::spawn_report::open_inheritable_for_read(spec.stdin_file);

    let payload = json!({
        "kind": "spawn",
        "image": spec.image,
        "command_line": spec.command_line,
        "cwd": spec.cwd,
        // **`null`は「申告していない」。** `[]`（空だと申告した）を送ると、子は
        // `SystemRoot`の無い環境ブロックで起こされ、`CreateProcessW`が
        // `ERROR_ENVVAR_NOT_FOUND`で落ちる（電文側のdocに経緯がある）。
        // フックの本番（6f-2）はここで呼び出し元の環境を`Some`で載せる。
        "env": Value::Null,
        "handles": {
            "stdin": stdin.value(),
            "stdout": stdout.value(),
            "stderr": Value::Null,
        },
        "console": spec.console,
        "suspended": spec.suspended,
    })
    .to_string();

    let round_trip = crate::pipe_client::run_spec(&crate::pipe_client::Spec {
        pipe_name: spec.pipe_name,
        payload_override: Some(&payload),
        // **往復の報告はここでは書き出さない**（下で自分の報告に畳んでから書く）。
        report_file: None,
        repeat: 1,
        start_at_epoch_ms: None,
    });

    // 子側の端はもう要らない。**閉じないと、子が終わってもファイルが掴まれたままになる。**
    let stdout_opened = stdout.handle.is_some();
    stdout.close();
    let stdin_opened = stdin.handle.is_some();
    stdin.close();

    let reply: Option<Value> = round_trip
        .get("reply")
        .and_then(Value::as_str)
        .and_then(|s| serde_json::from_str(s).ok());

    let mut report = json!({
        "mode": "spawn-via-daemon",
        "connected": round_trip.get("connected").cloned().unwrap_or(Value::Null),
        "last_error": round_trip.get("last_error").cloned().unwrap_or(Value::Null),
        "sent": payload,
        "reply": round_trip.get("reply").cloned().unwrap_or(Value::Null),
        "reply_kind": reply.as_ref().and_then(|r| r.get("kind")).cloned(),
        "stdout_handle_opened": stdout_opened,
        "stdout_open_error": stdout.open_error.clone(),
        "stdin_handle_opened": stdin_opened,
        "stdin_open_error": stdin.open_error.clone(),
    });

    if let Some(reply) = reply.as_ref() {
        if reply.get("kind").and_then(Value::as_str) == Some("spawned") {
            report["child_pid"] = reply.get("pid").cloned().unwrap_or(Value::Null);
            let process = reply.get("process").and_then(Value::as_u64);
            let thread = reply.get("thread").and_then(Value::as_u64);
            // [#49] **待つ前に測る。** `wait_and_record`はハンドルを閉じるうえ、
            // 子が終わった後では注入の可否が測れない（同関数のdoc）。
            // 最後の`ResumeThread`がここで撃たれるので、一時停止で頼んだ子はここから動き出す。
            crate::spawn_report::record_handle_rights(&mut report, process, thread);
            crate::spawn_report::wait_and_record(&mut report, process, thread);
        } else {
            report["deny_reason"] = reply.get("reason").cloned().unwrap_or(Value::Null);
        }
    }

    if let Some(path) = spec.report_file {
        let _ = std::fs::write(path, report.to_string());
    }
    report
}

#[cfg(not(windows))]
pub fn run(_spec: &Spec) -> Value {
    json!({ "mode": "spawn-via-daemon", "error": "windows only" })
}
