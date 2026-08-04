//! `HARNESS_WIRE_LOG=<path>`が設定されているときだけ、観測レコードをJSONL追記する共通経路。
//!
//! **未設定時はゼロコスト**（`std::env::var_os`1回のみ）。1行1JSONオブジェクトで、`kind`フィールドが
//! レコード種別を区別する。`run_shell`不安定性調査（BUG-030）のPhase 2観測基盤として導入され、
//! 現在は次の3箇所が使う。
//!
//! | `kind` | 発行元 | 何を残すか |
//! |---|---|---|
//! | `request` / SSEチャンク | `harness-providers::openai` | 送信ボディと受信チャンクそのもの |
//! | `tool_input_assembled` | `harness-engine::turn` | `tool_use`引数の連結結果とパース成否 |
//! | `turn_discarded` | `harness-engine::degeneracy` | 縮退で捨てたターンの全文と発火理由（§11.6「捨てた本文の保全」） |
//!
//! 3箇所それぞれが同じ「envを見る→追記で開く→1行書く」を持っていたため、`harness-core`へ
//! 1本化した（`docs/CODE-STRUCTURE-RULES.md` 規則5）。**新しい保存経路を作らない**方針でもあり、
//! これを使う限りクリーンアップ対象のファイルは増えない。

use std::path::PathBuf;

/// 出力先。未設定なら`None`（＝この機構全体が無効）。
pub fn path() -> Option<PathBuf> {
    std::env::var_os("HARNESS_WIRE_LOG").map(PathBuf::from)
}

/// 1レコードを追記する。**失敗は握り潰す**——観測はデバッグ補助であって、
/// 本来の処理を止める理由にはならない（保護境界ではない）。
pub fn append(path: &std::path::Path, value: &serde_json::Value) {
    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{value}");
    }
}

/// [`path`]が設定されているときだけ`build`を呼んで追記する。
///
/// `build`をクロージャで受けるのは、**未設定時にJSON値の組み立て自体を走らせない**ため
/// （捨てたターンの全文のような大きな値をログ無効時に作るのは無駄）。
pub fn record(build: impl FnOnce() -> serde_json::Value) {
    let Some(p) = path() else {
        return;
    };
    append(&p, &build());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appending_twice_produces_two_lines() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("wire.jsonl");
        append(&p, &serde_json::json!({ "kind": "a" }));
        append(&p, &serde_json::json!({ "kind": "b" }));
        let body = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<_> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"a\""));
        assert!(lines[1].contains("\"b\""));
    }

    /// 環境変数が未設定なら`build`すら呼ばれない（ゼロコストであることの固定）。
    #[test]
    fn a_record_is_not_built_when_the_log_is_disabled() {
        // このテストはプロセス全体で共有される環境変数を読むため、`HARNESS_WIRE_LOG`が
        // 設定された環境では意味を持たない。設定されているならスキップする。
        if path().is_some() {
            return;
        }
        let mut built = false;
        record(|| {
            built = true;
            serde_json::json!({})
        });
        assert!(!built);
    }
}
