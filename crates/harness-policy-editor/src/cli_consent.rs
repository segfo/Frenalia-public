//! CLI の書込の同意——`--auto-approve`（`--yes`は同じ意味の古い綴り）と`--force-approve`（決定66(8)。
//! `plans/position-domains/P5.md`の P5.6）。
//!
//! # なぜ2つに分けたのか
//!
//! 決定66で、権限が広がる子への遷移（広げる遷移）を入力を固定せずに書けるようにした。代わりに、書くと
//! **呼び出し元が子を通して子のドメインの権限を使える**ようになり、ポリシーの書き方次第では「あるドメインが書ける
//! 場所を、外部と通信できる別のドメインが読む」組み合わせも生まれる（Limit 1）。画面の確認ではそれを明細に出して
//! 人が判断する。CLI の一括承認（`--yes`）だけが**明細を読まずに通る口**として残ると、スクリプトから広がりを
//! 黙って書けてしまう。そこで確認済みの同意を2段に分けた:
//!
//! | フラグ | 広がる遷移・新しい組み合わせが1件でもある | 無い |
//! |---|---|---|
//! | 無し | 端末なら y/N を聞く。端末でなければ書かない | 同じ |
//! | `--auto-approve`（`--yes`） | **書かない**（理由と`--force-approve`を出す） | 書く |
//! | `--force-approve` | 書く（明細を読んで受け入れた人の明示の同意） | 書く |
//!
//! 判定の材料は確定の明細と同じ`exposure_view::Widening`（`hands_over_rights`）で、ここは並べた結果に従うだけ
//! （判定を2つ持たない、`B-13`）。
//!
//! # 限界
//!
//! - `--auto-approve`が見るのは**`policy.json`の中身から数えた広がり**だけで、`policy.json`の外で書込を許した場所
//!   （`--fs-allow`）はエディタが知らないので数えない（`exposure_view`の限界と同じ）
//! - `approve-declared`は`policy.json`を変えない（このマシンの承認台帳だけ）ので、広がりは常に空として扱う

use clap::Args;
use harness_policy_editor::exposure_view::Widening;

/// 書込のあるサブコマンドに埋める同意のフラグ（`#[command(flatten)]`）。
#[derive(Debug, Clone, Copy, Default, Args)]
pub(super) struct ConsentArgs {
    /// 差分を確認済みとして書き込む（非対話では必須）。ただし広がる遷移（書くと呼び出し元が子を通して新しく
    /// 使えるようになる権限）か新しい組み合わせが1件でもあれば書かない（決定66(8)）。--yes は同じ意味の古い綴り
    #[arg(long = "auto-approve", visible_alias = "yes")]
    auto_approve: bool,
    /// 広がる遷移・新しい組み合わせも含めて確認済みとして書き込む（明細を読んで受け入れたときだけ使う）
    #[arg(long = "force-approve", conflicts_with = "auto_approve")]
    force_approve: bool,
}

/// 書込の同意（[`ConsentArgs`]から決まる）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Consent {
    /// どちらのフラグも無い（端末なら聞く）。
    Ask,
    /// `--auto-approve`／`--yes`。
    AutoApprove,
    /// `--force-approve`。
    ForceApprove,
}

impl ConsentArgs {
    pub(super) fn consent(self) -> Consent {
        // 2つは clap が同時に受け付けない（`conflicts_with`）。
        if self.force_approve {
            Consent::ForceApprove
        } else if self.auto_approve {
            Consent::AutoApprove
        } else {
            Consent::Ask
        }
    }
}

/// `--auto-approve`で書かない理由（書いてよければ`None`）。**書く・書かないの判定はここだけ**（純粋な関数）。
pub(super) fn auto_refusal(consent: Consent, widening: &Widening) -> Option<String> {
    if consent != Consent::AutoApprove || !widening.hands_over_rights() {
        return None;
    }
    let mut what = Vec::new();
    if !widening.edges.is_empty() {
        what.push(format!("広がる遷移 {}本", widening.edges.len()));
    }
    if !widening.pairs.is_empty() {
        what.push(format!("組み合わせ {}組", widening.pairs.len()));
    }
    if widening.uncounted.is_some() {
        what.push("数えられなかった広がり".to_string());
    }
    Some(format!(
        "--auto-approve では書きません: この変更は呼び出し元へ新しく権限を渡し得ます（{}）。上の明細を読んで\
         受け入れるなら --force-approve を付けて実行してください（決定66(8)）。何も書いていません",
        what.join("・")
    ))
}

/// 書込前の確認。非対話（パイプ・リダイレクト）ではフラグを必須にする——ヘッドレスは対話プロンプトを一切出さない
/// 原則に従い、「答えが返ってこないまま既定で進む」形を作らない（`harness policy apply`と同じ作法）。
/// `widening`は確定の明細と同じもの（呼び出し元は先に明細を表示している）。
pub(super) fn confirm_write(consent: Consent, widening: &Widening) -> bool {
    use std::io::IsTerminal;

    match consent {
        Consent::ForceApprove => return true,
        Consent::AutoApprove => {
            return match auto_refusal(consent, widening) {
                Some(reason) => {
                    eprintln!("{reason}");
                    false
                }
                None => true,
            }
        }
        Consent::Ask => {}
    }
    if !std::io::stdin().is_terminal() {
        eprintln!(
            "確認なしには書きません: 標準入力が端末ではないためプロンプトを出せません。\
             上の差分を確認したうえで --auto-approve（広がる遷移や組み合わせも書くなら --force-approve）を\
             付けて実行してください。"
        );
        return false;
    }
    eprint!("この内容を .harness/policy.json へ書きますか？ [y/N] ");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim(), "y" | "Y" | "yes" | "YES")
}

#[cfg(test)]
#[path = "cli_consent_tests.rs"]
mod cli_consent_tests;
