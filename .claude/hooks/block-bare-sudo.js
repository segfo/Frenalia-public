// PreToolUse(Bash) フック: 素の `sudo` を止めて `dev-elevated-runner` へ誘導する。
//
// なぜ機構で止めるのか
// --------------------
// CLAUDE.mdは「実行中に昇格が起きるものは`dev-elevated-runner`経由で実行する」と定めているが、
// 文面の条件が「テスト」に紐づいているため、**単発のセットアップコマンド**（`CheckNetIsolation`等）が
// 条件の外に読めてしまい、実際に`sudo`が撃たれた（2026-08-16）。
// 「これはテストか」「昇格が起きるか」をモデルが判断する構造である限り、判断は外れうる。
// このフックは**判断を介在させずに**入口で止めるためのものである。
//
// 判定を`deny`ではなく`ask`にしてある理由
// --------------------------------------
// `deny`だと、ユーザーが「今回は`sudo`でよい」と判断しても設定を書き換えるまで実行できず、
// 運用が詰まる。`ask`なら**モデルの独断では通らない**という目的を満たしつつ、
// 人間が理由を見て判断できる。止めたいのは「モデルが自分で決めて撃つ」ことである。
//
// 誤検知を避ける
// --------------
// `grep sudo file` のように引数へ文字列として現れる`sudo`は止めない。
// コマンドの先頭、または `;` `&&` `||` `|` `(` の直後に来るものだけを見る。

let buf = "";
process.stdin.on("data", (d) => (buf += d));
process.stdin.on("end", () => {
  let cmd = "";
  try {
    cmd = (JSON.parse(buf).tool_input || {}).command || "";
  } catch {
    // 入力を解釈できないときは通す。フック自身の不調で作業が止まる方が害が大きい。
    process.exit(0);
  }
  if (!/(^|[;&|(]|&&|\|\|)\s*sudo(\s|$)/.test(cmd)) process.exit(0);

  const reason = [
    "CLAUDE.md: 昇格が要る操作は単発の `sudo` ではなく dev-elevated-runner 経由で実行する。",
    "",
    "手順:",
    "(1) crates/dev-elevated-runner/src/lib.rs の KNOWN_TARGETS を grep し、該当ターゲットがあれば",
    "    `target/debug/dev-elevated-run.exe <target>` で実行する。",
    "(2) 無ければ、昇格が要る操作の側をテストにして KNOWN_TARGETS へ足す。",
    "    このrunnerは validate_target が固定リストとの完全一致を要求するため、",
    "    任意コマンドの昇格実行はできない（無検証の昇格経路を作らないための設計）。",
    "(3) それでも単発 sudo が要るなら、理由を添えてユーザーに承認を求めてから実行する。",
    "    この判断を自分で下さないこと。",
  ].join("\n");

  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "ask",
        permissionDecisionReason: reason,
      },
    })
  );
});
