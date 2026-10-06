//! 確定の明細の「広がる遷移」（[`widening`]・[`lines`]）の単体試験（`plans/position-domains/P5.md` の P5.3）。
//!
//! **出す側と出さない側を対で測る**（`bug-pattern-rules` B-35）——「広がる遷移が出る」だけを測ると、
//! 何でも出す実装でも緑になる。

use harness_policy::policy_file::{PolicyDomain, PolicyFile, ENTRY_DOMAIN};
use harness_policy::transition::{editor_edge, AnyMarker, ArgvMatcher};
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
        }]
    );
    assert_eq!(widening.uncounted, None);
    let text = lines(&widening).join("\n");
    assert!(text.contains("広がる遷移 1本"), "{text}");
    assert!(text.contains("呼び出し元は子を通して"), "{text}");
    assert!(text.contains(&format!("{ENTRY_DOMAIN} → secret")), "{text}");
    assert!(text.contains(PEEK), "{text}");
    assert!(text.contains("fs.read") && text.contains("C:/Users/x/secret/**"), "{text}");
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
