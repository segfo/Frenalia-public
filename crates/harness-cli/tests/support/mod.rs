//! `tier2a_e2e.rs`と`recall_e2e.rs`が共有する部品。2つのテストバイナリの両方から`mod support;`で取り込む。
//!
//! # なぜここにあるのか
//!
//! 2本は、実`harness.exe`を`--provider mock`で起動する統合テストで、同じ部品を別々に持っていた
//! （2026-09-30に発覚、`docs/STATUS.md`「コード構造 #7」）。同じことを2か所に書くと、以後の修正を
//! 毎回2か所へ届けなければならず、そのうち片方が忘れられる（`docs/CODE-STRUCTURE-RULES.md`§5.0）。
//! ここへ移したのは、**本文が同じ**ものと、**置き場の根だけが違う**ものである。根は引数で受ける。
//!
//! # 共有しなかったもの（同じ名前だが、中身が違う）
//!
//! 共通化しない判断の理由を残す（§5.1）。どれも各ファイルの側にも短く書いてある。
//!
//! - **置き場の根（`CASE_ROOT`）。** 2本は意図して別の根を使う（`C:\harness-e2e`と
//!   `C:\harness-e2e\recall`）。記憶のE2Eは全ケース緑のときに**根ごと消す**ので、1つの定数に
//!   まとめると、Tier2aの根に置いてある恒久ACE・台帳の1エントリ・手で置く設定ファイル
//!   （`docs/DEV-ENVIRONMENT.md`が「消してはいけない」と書くもの）ごと消す。
//! - **模擬応答の組み立て（`tool_use_turn`など）。** 本文の形は同じだが、報告する使用量の慣習が
//!   2本で違う（Tier2a側は全部0、記憶側は全部「入力100・出力20」）。そろえるとテストの入力が変わる。
//! - **計画付きのツール呼び出し（`plan_and_tool_turn`）。** 計画の形が違う（Tier2a側はJSONの計画で
//!   呼び出しIDを変える、記憶側は文の計画）。写した元も別で、`harness-cognition`の
//!   `m16_validity_transcript.rs`と`hiv_light_transcript.rs`である。
//! - **harnessの起動（`run_harness`）。** 起動の約束が違う（権限モード・出力形式・プロンプト・環境変数）。
//!   記憶側はゴール文が検索に掛かるのでプロンプトが結果を左右し、Tier2a側は模擬プロバイダが無視する。
//!
//! # 置き場の注意
//!
//! Cargoは`tests/`直下のファイルだけをテストバイナリにするので、`tests/support/mod.rs`は
//! バイナリにならない。**`tests/support.rs`にすると、それ自体が1本のテストバイナリになる。**
//! テストバイナリごとに使う項目が違うので、未使用の警告は抑える
//! （前例: `crates/harness-mcp/tests/support/mod.rs`）。

#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// 行列の1ケース。
pub type CaseFn = fn() -> Result<(), String>;

pub fn harness_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_harness"))
}

/// `root`直下の作業用ディレクトリ（台本とリクエスト記録の置き場）。
pub fn scratch_dir(root: &Path) -> PathBuf {
    let dir = root.join("_scratch");
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// `root`直下のケース専用ワークスペース。既存があれば作り直す（前回失敗の残骸を引き継がない）。
pub fn case_dir(root: &Path, name: &str) -> PathBuf {
    let dir = root.join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create case workspace");
    dir
}

/// 実`harness.exe`を1回起動した結果。
pub struct HarnessRun {
    pub status: std::process::ExitStatus,
    pub stdout: String,
    pub stderr: String,
    pub record_path: PathBuf,
    /// 起動の期限を過ぎて、こちらから止めたか（Tier2a側の`Driver::Lmstudio`の`deadline`）。
    /// **止めた回の`status`は失敗だが、製品が失敗したのではない**——読む側が取り違えないよう
    /// 別の欄にしてある。模擬プロバイダの起動は期限を持たないので常に`false`。
    pub timed_out: bool,
}

/// ケースを1つ走らせ、結果を1行のJSONで標準出力へ出す。合否を返す。
pub fn run_named_case<F: FnOnce() -> Result<(), String>>(name: &str, f: F) -> bool {
    let result = f();
    let passed = result.is_ok();
    let record = serde_json::json!({
        "case": name,
        "passed": passed,
        "error": result.err(),
    });
    println!("{record}");
    passed
}
