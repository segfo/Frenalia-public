//! MCPツールの名前空間が、**作る側と読む側で一致していること**を固定する。
//!
//! 作る側は`harness_mcp::decl::namespaced_tool_name`（M15.5）、読む側は
//! `harness_cognition::source::split_mcp_tool_name`（M16、`SourceRef::Mcp`の判定）である。
//!
//! # なぜ写しがあるのか
//!
//! `harness-cognition`は`harness-mcp`へ依存できない——`harness-mcp`はWindowsで
//! `harness-sandbox`（AppContainer隔離、D-38）を引き込み、認知レイヤーがサンドボックス層へ
//! 依存するとレイヤリングが崩れる（`docs/INDEX.md`が「M16の依存は`harness-core`/
//! `harness-engine`/`harness-tools`だけ」と定めている）。そのため接頭辞・区切りは
//! `harness-cognition`側に写しを持つ。
//!
//! # なぜこのテストがここにあるのか
//!
//! `harness-cli`は**両方へ依存する唯一のクレート**なので、写しが腐ったことを検出できるのは
//! ここだけである。片方だけ変えると、認知レイヤーがMCPの観測を`SourceRef::File`と誤分類し、
//! §4.2の接地優先順位（ローカル一次証拠 → MCPで裏取り）が静かに壊れる——**エラーにならず、
//! 妥当性グレードが少しずれるだけ**なので、テストが無ければ気付けない種類の破綻である。

use harness_cognition::source::split_mcp_tool_name;
use harness_mcp::decl::namespaced_tool_name;

/// 作った名前を、そのまま読み戻せること。
#[test]
fn the_cognition_layer_can_split_names_built_by_the_mcp_layer() {
    for (server, tool) in [
        ("company-docs", "search_docs"),
        ("jira", "get_issue"),
        // ツール名側は`_`を含んでよい（サーバidは`[a-z0-9-]`のみ）。
        ("a", "get__issue__v2"),
        ("x-y-z", "t"),
    ] {
        let name = namespaced_tool_name(server, tool);
        assert_eq!(
            split_mcp_tool_name(&name),
            Some((server, tool)),
            "namespace drift: {name:?} did not round-trip"
        );
    }
}

/// MCPでない名前をMCP扱いしないこと（誤検知側）。
#[test]
fn builtin_tool_names_are_not_mistaken_for_mcp_tools() {
    for name in [
        "read_file",
        "run_shell",
        "web_fetch",
        // 接頭辞に似ているだけの名前。
        "mcp_helper",
        "mcpx__a__b",
    ] {
        assert_eq!(split_mcp_tool_name(name), None, "{name}");
    }
}
