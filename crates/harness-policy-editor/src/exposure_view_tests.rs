//! 確定の明細の「広がる遷移」（[`widening`]・[`lines`]）の単体試験（`plans/position-domains/P5.md` の P5.3）。
//!
//! **出す側と出さない側を対で測る**（`bug-pattern-rules` B-35）——「広がる遷移が出る」だけを測ると、
//! 何でも出す実装でも緑になる。

use harness_policy::policy_file::{PolicyDomain, PolicyFile, ENTRY_DOMAIN};
use harness_policy::transition::{editor_edge, AnyMarker, ArgvMatcher, ChildOutput};
use harness_policy::transition_listing::Rights;

use super::*;

const PEEK: &str = "C:/Users/x/tools/peek.exe";

fn file(domains: Vec<PolicyDomain>) -> PolicyFile {
    PolicyFile {
        domains,
        ..PolicyFile::default()
    }
}

fn reading(name: &str, value: &str) -> PolicyDomain {
    let mut domain = PolicyDomain::new(name);
    domain.fs.read.push(value.to_string());
    domain
}

fn with_edge(mut domain: PolicyDomain, exe: &str, to: &str) -> PolicyDomain {
    domain
        .process
        .transitions
        .push(editor_edge(exe, ArgvMatcher::Any(AnyMarker), to));
    domain
}

fn ws() -> std::path::PathBuf {
    std::path::PathBuf::from("C:/ws")
}

/// 新しく書く広げる辺は、遷移元・実行ファイル・遷移先と、呼び出し元が子を通して使えるようになる権限を全部出す。
/// 明細の行には本数・遷移元から遷移先・権限の綴りが出る。
#[test]
fn a_new_widening_edge_is_listed_with_what_it_hands_over() {
    let before = file(vec![
        PolicyDomain::new(ENTRY_DOMAIN),
        reading("secret", "C:/Users/x/secret/**"),
    ]);
    let after = file(vec![
        with_edge(PolicyDomain::new(ENTRY_DOMAIN), PEEK, "secret"),
        reading("secret", "C:/Users/x/secret/**"),
    ]);

    let widening = widening(&before, &after, &ws());

    assert_eq!(
        widening.edges,
        vec![WidenedEdge {
            from: ENTRY_DOMAIN.to_string(),
            exe: PEEK.to_string(),
            to: "secret".to_string(),
            newly_usable: Rights {
                fs: vec![("C:/Users/x/secret/**".to_string(), "read")],
                net: Vec::new(),
            },
            output: ChildOutput::Return,
        }]
    );
    assert_eq!(widening.uncounted, None);
    let text = lines(&widening).join("\n");
    assert!(text.contains("広がる遷移 1本"), "{text}");
    assert!(text.contains("呼び出し元は子を通して"), "{text}");
    assert!(text.contains(&format!("{ENTRY_DOMAIN} → secret")), "{text}");
    assert!(text.contains(PEEK), "{text}");
    assert!(text.contains("fs.read") && text.contains("C:/Users/x/secret/**"), "{text}");
    // [P5.4b] 出力を返す（既定）辺は、いちばん太い持ち出しの経路を言う（決定66(4)。P5.3 は Daemon が出力を
    // 返していなかったので出さなかった）。
    assert!(
        text.contains("出力を返すので、子が読めるものは呼び出し元へ渡ります"),
        "{text}"
    );
}

/// [P5.4b] 対: 出力を捨てる辺は「返すので渡る」とは言わず、捨てる設定であることを出す——ただし捨てても子が書いた
/// ファイルは残るので、「渡らない」とは言わない（言い過ぎない、`B-32`）。
#[test]
fn a_widening_edge_that_discards_its_output_does_not_claim_it_returns_it() {
    let before = file(vec![
        PolicyDomain::new(ENTRY_DOMAIN),
        reading("secret", "C:/Users/x/secret/**"),
    ]);
    let mut entry = with_edge(PolicyDomain::new(ENTRY_DOMAIN), PEEK, "secret");
    entry.process.transitions[0].output = ChildOutput::Discard;
    let after = file(vec![entry, reading("secret", "C:/Users/x/secret/**")]);

    let widening = widening(&before, &after, &ws());

    assert_eq!(widening.edges.len(), 1, "{widening:?}");
    assert_eq!(widening.edges[0].output, ChildOutput::Discard);
    let text = lines(&widening).join("\n");
    assert!(!text.contains("出力を返すので"), "{text}");
    assert!(text.contains("子の出力は捨てる設定です"), "{text}");
}

/// 対: 遷移元が自分で持っている権限しか渡さない辺（狭める辺）と、変更の前から同じだけ渡していた辺は出さず、
/// 明細に1行も足さない。
#[test]
fn a_change_that_hands_over_nothing_new_adds_no_line() {
    let narrowing = file(vec![
        with_edge(
            reading(ENTRY_DOMAIN, "C:/Users/x/secret/**"),
            PEEK,
            "secret",
        ),
        reading("secret", "C:/Users/x/secret/a.txt"),
    ]);
    let empty_before = file(vec![reading(ENTRY_DOMAIN, "C:/Users/x/secret/**")]);
    let none = widening(&empty_before, &narrowing, &ws());
    assert!(none.is_empty(), "{none:?}");
    assert!(lines(&none).is_empty());

    let widened = file(vec![
        with_edge(PolicyDomain::new(ENTRY_DOMAIN), PEEK, "secret"),
        reading("secret", "C:/Users/x/secret/**"),
    ]);
    assert!(widening(&widened, &widened, &ws()).is_empty());
}

/// 数えられないとき（同じ名前のドメインが2つある）は**黙って「広がらない」にしない**（`B-10`）。
#[test]
fn a_policy_that_cannot_be_counted_says_so_instead_of_showing_nothing() {
    let broken = file(vec![
        PolicyDomain::new(ENTRY_DOMAIN),
        PolicyDomain::new(ENTRY_DOMAIN),
    ]);
    let widening = widening(&PolicyFile::default(), &broken, &ws());
    assert!(widening.uncounted.is_some());
    assert!(!widening.is_empty());
    let text = lines(&widening).join("\n");
    assert!(text.contains("数えられません"), "{text}");
}

/// [P5.5] **出力を捨てる辺か Strict の印を初めて書く確定は、`policy.json`のスキーマ版が3へ上がることを言う**——
/// 版2までしか読めない古い`harness.exe`は読込で断る（黙って印を無視して読むことはない）ので、書く前に知らせる。
///
/// 対（`B-35`）: 既に版3のファイルへ足すとき・版が上がらない変更（普通の辺を足すだけ）では言わない。
#[test]
fn writing_the_first_discarding_edge_or_strict_mark_says_the_schema_version_rises_to_3() {
    let plain = file(vec![with_edge(PolicyDomain::new(ENTRY_DOMAIN), PEEK, "secret")]);
    let mut discarding = plain.clone();
    discarding.domains[0].process.transitions[0].output = ChildOutput::Discard;
    let raised = widening(&plain, &discarding, &ws());
    assert_eq!(raised.schema_raised, Some((2, 3)));
    assert!(!raised.is_empty());
    let text = lines(&raised).join("\n");
    assert!(
        text.contains("スキーマ版") && text.contains("2→3") && text.contains("harness.exe"),
        "{text}"
    );

    let mut strict = plain.clone();
    strict.domains.push(PolicyDomain::new("secret"));
    strict.domains[1].strict = true;
    assert_eq!(widening(&plain, &strict, &ws()).schema_raised, Some((2, 3)));

    // 対: 既に版3（捨てる辺がある）のファイルへ印を足しても言わない。普通の辺を足すだけでも言わない。
    let mut both = discarding.clone();
    both.domains.push(PolicyDomain::new("secret"));
    both.domains[1].strict = true;
    assert_eq!(widening(&discarding, &both, &ws()).schema_raised, None);
    let first_edge = widening(&file(vec![PolicyDomain::new(ENTRY_DOMAIN)]), &plain, &ws());
    assert_eq!(first_edge.schema_raised, None, "版1→2は言わない（P5 より前からの振る舞い）");
    assert!(!lines(&first_edge).join("\n").contains("スキーマ版"));
}

/// [P5.5] 辺の綴りに添える出力の設定は、捨てる辺にだけ付く（既定の「返す」は何も添えない）。
#[test]
fn only_a_discarding_edge_gets_an_output_suffix() {
    assert_eq!(output_suffix(ChildOutput::Return), "");
    assert!(output_suffix(ChildOutput::Discard).contains("子の出力を捨てる"));
}

/// [P5.6] **変更で生まれた組み合わせの対を、断らずに明細へ並べる**（決定66(9)・Limit 1）——あるドメインが書ける場所を、
/// 外部と通信できる別のドメインが読む／実行する組。外部と通信できるかの見立ては暫定（P7 で差し替え）と添える。
///
/// 対（`B-35`）: 前からあった対は出さない（何度確定しても同じ対を言い続けない）。
#[test]
fn a_new_combination_pair_is_listed_without_refusing() {
    let mut builder = PolicyDomain::new("builder");
    builder.fs.read_write.push("C:/share/**".to_string());
    let before = file(vec![PolicyDomain::new(ENTRY_DOMAIN), builder.clone()]);
    let after = file(vec![reading(ENTRY_DOMAIN, "C:/share/out.txt"), builder]);

    let found = widening(&before, &after, &ws());
    assert_eq!(found.pairs.len(), 1, "{:?}", found.pairs);
    assert!(!found.is_empty());
    assert!(found.hands_over_rights(), "組み合わせだけでも --auto-approve は断る（決定66(8)）");
    let text = lines(&found).join("\n");
    assert!(text.contains("組み合わせ 1組"), "{text}");
    assert!(
        text.contains("builder が書ける C:/share/**") && text.contains(&format!("{ENTRY_DOMAIN} が読める")),
        "{text}"
    );
    assert!(text.contains("暫定"), "通信できるかの見立てが暫定だと言っていない: {text}");

    assert!(widening(&after, &after, &ws()).pairs.is_empty(), "前からあった対を言った");
}

/// [P5.6] **明細は辺のモードを示す**——広がる辺は「普通」、新しく Strict になった辺は「入力を固定するので呼び出し元は
/// 子を操れない（広がる遷移に数えない）」と1行で言う（決定66の追記）。
#[test]
fn the_details_say_whether_each_edge_is_ordinary_or_strict() {
    let widened = file(vec![
        with_edge(PolicyDomain::new(ENTRY_DOMAIN), PEEK, "secret"),
        reading("secret", "C:/Users/x/secret/**"),
    ]);
    let ordinary = lines(&widening(
        &file(vec![PolicyDomain::new(ENTRY_DOMAIN), reading("secret", "C:/Users/x/secret/**")]),
        &widened,
        &ws(),
    ))
    .join("\n");
    assert!(ordinary.contains("［普通］"), "{ordinary}");
    assert!(!ordinary.contains("［Strict］"), "{ordinary}");

    let mut fixed = widened.clone();
    let edge = &mut fixed.domains[0].process.transitions[0];
    edge.argv = ArgvMatcher::Literal(format!("\"{PEEK}\" --report"));
    edge.cwd = Some("C:/work".to_string());
    let mut marked = fixed.clone();
    marked.domains[1].strict = true;
    let strict = widening(&fixed, &marked, &ws());
    assert_eq!(strict.strict_edges.len(), 1, "{strict:?}");
    assert!(strict.edges.is_empty(), "Strict の辺は何も渡さない: {strict:?}");
    let text = lines(&strict).join("\n");
    assert!(
        text.contains("［Strict］") && text.contains("入力を固定するので") && text.contains("secret"),
        "{text}"
    );
}
