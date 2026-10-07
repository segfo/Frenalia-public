//! 段5の測定（[`super::tier2a_cow_change_census_mock`]・実プロバイダの腕）が`run_program`の git に与える
//! **完全一致の規則**（`--allow run_program:[…]`）。
//!
//! # なぜ規則が要るのか（D-123、2026-10-04）
//!
//! `run_program`の引数に**ワークスペース内の実在ファイル**が名指しされていると、その呼び出しは
//! ファイルの中身で縛られ、**accept-all でも記録（規則）と一致しなければ聞く**——ヘッドレスでは拒否になる
//! （`plans/DESIGN-RUNSHELL-ALLOWLIST.md` D-123 の4。ファイルを名指ししない`git log`は従来どおり通る）。
//! この測定は D-123 より前に書かれ、`git rm -q notes.txt`がそのまま通る前提だった。2026-10-07 に
//! 撃ち直して、その段が拒否され、続く段も崩れて「判定不能」になった。
//!
//! 規則は harness が**起動した時点の中身**で縛る（D-104）。だから規則で通せるのは、名指しした
//! ファイルを**その段より前に変えていない**段だけである（`git rm -q notes.txt`は通る）。
//! 同じセッションで書き換えたファイルを名指しする段（`git add`）は規則でも通らないので、手順の側で
//! ディレクトリを名指しする形にしてある（[`super::CENSUS_STEPS`]の4段目。ディレクトリは縛られない）。
//!
//! **規則は手順そのものから作る**（[`super::census_step_call`]）。綴りを2か所に書くと片方だけ直されて
//! 一致しなくなる（`B-05`）。`write_file`の段は規則を作らない（`run_program`ではない）。
//!
//! 2026-10-07 に足した。`tier2a_e2e.rs`は1万行を超えているので、足す分は子モジュールへ置く
//! （`docs/CODE-STRUCTURE-RULES.md`規則1）。

/// 手順の git の段ごとに`--allow`と規則の2語を返す（`run_harness_driven`の`extra_args`へそのまま足す）。
pub(super) fn program_rule_args() -> Vec<String> {
    let mut out = Vec::new();
    for step in super::CENSUS_STEPS {
        let (tool, input) = super::census_step_call(step);
        if tool != "run_program" {
            continue;
        }
        let mut argv = vec![input["program"].clone()];
        argv.extend(input["args"].as_array().into_iter().flatten().cloned());
        out.push("--allow".to_string());
        out.push(format!("{tool}:{}", serde_json::Value::Array(argv)));
    }
    out
}
