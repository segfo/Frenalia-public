//! [段階6f-3] 拒否された遷移を、**モデルが読める1行**にする
//! （`plans/DESIGN-MAC-TRANSITION-POLICY.md` §19.3.8）。
//!
//! # 何のためにあるのか
//!
//! Spawn Daemonが遷移を拒否すると、呼び出し元のシェルに返るのは
//! `ERROR_ACCESS_DENIED`（アクセスが拒否されました）という**生のWin32エラーだけ**である。
//! そこから「何を宣言すれば通るのか」は読めない。
//!
//! 段階6eで`can_run_program`（いま何を起こせるかを引く読み取り専用ツール）を足したが、
//! **pull方式なので、存在を教えられないと永久に呼ばれない**。ここがその誘導である。
//!
//! # なぜ`harness-sandbox`側ではなくここに在るのか
//!
//! **ツールの名前を持っている側だから**である。注記は「このツールを引け」と書くので、
//! 名前がずれると**存在しないツールを指す案内**になる。同じクレートの
//! [`crate::can_run_program::CAN_RUN_PROGRAM_TOOL`]から取る。
//!
//! 待ち行列の**形**（何が書いてあるか・どう読むか）は`harness-sandbox`側が持ち、
//! ここはその読み終えた結果を文にするだけである。
//!
//! # 「何をすれば直るか」の分類は写さない
//!
//! [`Remedy`]は拒否の理由から計算される（`harness-sandbox`の`transitions::remedy`）。
//! **ここでは`_ =>`を書かない**——分類が1つ増えた日に、新しい分類が黙って
//! 「宣言を直せ」の文言へ混ざるのを止める。
//!
//! # 実行ファイル名には上限がある
//!
//! §19.3.8は「到達可能なexeの集合をプロンプトへ載せない」と決めている。理由は
//! **宣言の増加がそのままプロンプトの肥大になる**ことで、その問題は出力側でも同じ形で起きる
//! ——`cargo build`1回で数百種類が断られ得る。だから[`MAX_NAMED_EXES`]までで打ち切る。

use std::collections::BTreeSet;

use harness_sandbox::tier2a::spawnd::transitions::{remedy, Denial, PendingRecord, Remedy};

use crate::can_run_program::CAN_RUN_PROGRAM_TOOL;

/// 注記に名前を挙げる実行ファイルの上限。超えた分は`+N more`にする。
const MAX_NAMED_EXES: usize = 3;

/// 読み終えた待ち行列の続きを、`run_shell`の出力へ足す注記にする。
///
/// **`None`は「足すものが無い」。** 拒否が1件も無い回では1文字も足さない。
pub(super) fn note(records: &[PendingRecord]) -> Option<String> {
    let mut fixable: BTreeSet<String> = BTreeSet::new();
    let mut blocked: BTreeSet<String> = BTreeSet::new();
    let mut unrelated: BTreeSet<String> = BTreeSet::new();
    let mut environment: BTreeSet<String> = BTreeSet::new();
    let mut dropped = 0u64;

    for record in records {
        let denial: &Denial = match record {
            // **どちらが拒否したかで文言を変えない。** モデルにとって必要なのは
            // 「何をすれば通るか」であって、拒否した主体はポリシー側の語彙である。
            PendingRecord::DeniedByDaemon(denial) | PendingRecord::DeniedByKernel(denial) => denial,
            PendingRecord::Overflowed { dropped: n, .. } => {
                dropped += n;
                continue;
            }
        };
        let bucket = match remedy(&denial.reason) {
            Remedy::FixTheDeclaration => &mut fixable,
            Remedy::BlockedUntilHarnessImplementsIt => &mut blocked,
            Remedy::NotAboutPolicy => &mut unrelated,
            Remedy::FixTheEnvironment => &mut environment,
        };
        bucket.insert(file_name_of(&denial.exe));
    }

    let mut lines: Vec<String> = Vec::new();
    if !fixable.is_empty() {
        lines.push(format!(
            "[transition: denied starting {}; declare the transition in policy.json to allow it \
             — call {CAN_RUN_PROGRAM_TOOL} to see what can be started now]",
            named(&fixable)
        ));
    }
    if !blocked.is_empty() {
        lines.push(format!(
            "[transition: denied starting {}; harness does not support this transition target \
             yet, so declaring it will not help]",
            named(&blocked)
        ));
    }
    if !environment.is_empty() {
        // 宣言は通っている。**宣言を直せとも、ツールを引けとも言わない**——どちらも効かない。
        // 直せるのはユーザーだけなので、モデルにはそう伝える。
        lines.push(format!(
            "[transition: denied starting {}; the declared transition fixes a program or argument \
             file that this sandbox can modify, so it is refused — ask the user to move that file \
             somewhere this sandbox cannot write, or to remove the write permission]",
            named(&environment)
        ));
    }
    if !unrelated.is_empty() {
        lines.push(format!(
            "[transition: denied starting {} for a reason unrelated to policy]",
            named(&unrelated)
        ));
    }
    if dropped > 0 {
        lines.push(format!(
            "[transition: {dropped} further denials were not recorded (too many distinct kinds)]"
        ));
    }

    (!lines.is_empty()).then(|| lines.join("\n"))
}

/// 実行ファイルの**末尾の名前だけ**を出す。
///
/// フルパスを並べると1行が長くなるうえ、モデルが知りたいのは「どのプログラムか」である。
fn file_name_of(exe: &str) -> String {
    exe.rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(exe)
        .to_string()
}

/// 名前を最大[`MAX_NAMED_EXES`]個まで並べ、残りは`+N more`にする。
fn named(exes: &BTreeSet<String>) -> String {
    let shown: Vec<&str> = exes.iter().take(MAX_NAMED_EXES).map(String::as_str).collect();
    let rest = exes.len().saturating_sub(shown.len());
    if rest == 0 {
        shown.join(", ")
    } else {
        format!("{}, +{rest} more", shown.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harness_policy::transition::TransitionDenial;
    use harness_sandbox::tier2a::spawnd::DenyReason;

    fn denial(exe: &str, reason: DenyReason) -> PendingRecord {
        PendingRecord::DeniedByDaemon(Denial {
            from_domain: Some("entry".to_string()),
            exe: exe.to_string(),
            argv: format!("\"{exe}\""),
            cwd: Some("C:/ws".to_string()),
            reason,
            count: 1,
            first_ts: 1,
            last_ts: 1,
            argv_truncation: false,
        })
    }

    fn fixable(exe: &str) -> PendingRecord {
        denial(
            exe,
            DenyReason::Transition {
                denial: TransitionDenial::NoMatchingEdge,
            },
        )
    }

    /// **拒否が無ければ1文字も足さない。** ここが`Some("")`を返すと、
    /// 出力末尾に空の注記が毎回付く。
    #[test]
    fn nothing_denied_means_nothing_to_say() {
        assert_eq!(note(&[]), None);
    }

    /// **宣言で直るものは、直し方と引く先の両方を出す。**
    ///
    /// ツール名を出さないと、モデルは`can_run_program`の存在を知らないまま
    /// 手探りを続ける（pullは教えないと呼ばれない、というのがこの回の前提）。
    #[test]
    fn a_fixable_denial_names_the_file_and_points_at_the_tool() {
        let text = note(&[fixable("C:/Program Files/Git/cmd/git.exe")]).expect("a note");
        assert!(text.contains("git.exe"), "{text}");
        assert!(!text.contains("Program Files"), "フルパスは出さない: {text}");
        assert!(text.contains("policy.json"), "{text}");
        assert!(text.contains(CAN_RUN_PROGRAM_TOOL), "{text}");
    }

    /// **宣言では直らないものに「宣言を直せ」と言わない**（対の片割れ）。
    ///
    /// これが無いと、全部を同じ文言にする実装が上のテストだけで緑になり、
    /// **直しようのない拒否に「宣言を直せ」の顔をさせる**ことになる。
    #[test]
    fn a_denial_that_no_declaration_can_fix_does_not_ask_for_a_declaration() {
        let text = note(&[denial("C:/bin/foo.exe", DenyReason::NotRegistered)]).expect("a note");
        assert!(text.contains("foo.exe"), "{text}");
        assert!(
            !text.contains("policy.json") && !text.contains(CAN_RUN_PROGRAM_TOOL),
            "宣言では直らないのに宣言を促している: {text}"
        );
        assert!(text.contains("unrelated to policy"), "{text}");
    }

    /// harness側が未実装で断られたものは、**「宣言しても無駄」と言う**。
    #[test]
    fn a_denial_waiting_on_harness_says_declaring_will_not_help() {
        let text = note(&[denial(
            "C:/bin/bar.exe",
            DenyReason::TargetDomainNotProvisioned {
                to: "build".to_string(),
            },
        )])
        .expect("a note");
        assert!(text.contains("will not help"), "{text}");
        assert!(!text.contains(CAN_RUN_PROGRAM_TOOL), "{text}");
    }

    /// 固定辺の前提が崩れて断られたものは、**宣言でもツールでもなく、ユーザーに頼め**と言う。
    ///
    /// 宣言は通っているので「宣言を直せ」は効かず、`can_run_program`は「起こせる」と答える
    /// ——どちらを促しても、モデルは同じ要求を繰り返すだけになる。
    #[test]
    fn a_fixed_input_the_sandbox_can_modify_asks_the_user_instead_of_a_declaration() {
        let text =
            note(&[denial("C:/tools/gen.exe", DenyReason::FixedInputWritable)]).expect("a note");
        assert!(text.contains("gen.exe"), "{text}");
        assert!(text.contains("ask the user"), "{text}");
        assert!(
            !text.contains("declare the transition") && !text.contains(CAN_RUN_PROGRAM_TOOL),
            "宣言では直らないのに宣言やツールを促している: {text}"
        );
    }

    /// 分類が混ざったら**分類ごとに1行ずつ出す**。1つに畳むと、直せるものと直せないものが混ざる。
    #[test]
    fn each_kind_is_reported_separately() {
        let text = note(&[
            fixable("C:/bin/a.exe"),
            denial("C:/bin/b.exe", DenyReason::NotRegistered),
            denial(
                "C:/bin/c.exe",
                DenyReason::TargetDomainNotProvisioned {
                    to: "d".to_string(),
                },
            ),
            denial("C:/bin/e.exe", DenyReason::FixedInputWritable),
        ])
        .expect("a note");
        assert_eq!(text.lines().count(), 4, "{text}");
    }

    /// **名前は上限で打ち切る。** 打ち切らないと、断られた種類の数だけ1行が伸びる
    /// ——§19.3.8がプロンプト側で避けた肥大を、出力側で再現することになる。
    #[test]
    fn the_named_files_are_capped() {
        let records: Vec<PendingRecord> = (0..10)
            .map(|i| fixable(&format!("C:/bin/p{i}.exe")))
            .collect();
        let text = note(&records).expect("a note");
        assert!(text.contains("+7 more"), "{text}");
        assert!(!text.contains("p9.exe"), "上限を超えて名前が出ている: {text}");
    }

    /// 同じ実行ファイルが何度断られても、**名前は1つだけ**出す。
    #[test]
    fn the_same_program_is_named_once() {
        let text = note(&[fixable("C:/bin/git.exe"), fixable("C:/bin/git.exe")]).expect("a note");
        assert_eq!(text.matches("git.exe").count(), 1, "{text}");
    }

    /// **覚えきれずに捨てた分を黙らせない**（`B-10`）。
    #[test]
    fn dropped_denials_are_reported() {
        let text = note(&[PendingRecord::Overflowed {
            dropped: 12,
            last_ts: 1,
        }])
        .expect("a note");
        assert!(text.contains("12 further denials"), "{text}");
    }
}
