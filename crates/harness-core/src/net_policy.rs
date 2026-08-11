//! Network domain policy shared by proxy, DNS diagnostics, and audit code.
//!
//! This module intentionally contains only stable, transport-independent decisions:
//! domain allowlist matching, IP-literal rejection, and audit reason strings.

use std::net::IpAddr;

const MAX_DOMAIN_PATTERN_LEN: usize = 253;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainPolicy {
    allow_domains: Vec<String>,
    mode: DomainPolicyMode,
}

/// [`DomainPolicy`]の評価モード。
///
/// `RecordAll`はポリシーエディタの記録モード（Tier2aでのネットワーク学習パス）専用——
/// 許可リストに関わらず、IPリテラル以外の宛先を全て許可として通す。これにより1回の完走で
/// 到達したドメインを取りこぼさず記録できる。マジックパターン（`*`のような`allow_domains`への
/// 特殊値）にしないのは、`validate_domain_pattern`の通常経路（CLI引数・設定ファイル）から
/// 誤って到達できてしまうと「全許可」がユーザーの意図しない形で発動しかねないため——
/// モードを型で分けることで、記録モードの起動経路だけが到達できるようにする。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DomainPolicyMode {
    /// 通常運用: `allow_domains`に一致したドメインだけ許可する。
    Allowlist,
    /// 記録モード専用: IPリテラル拒否以外は全許可し、宛先の学習に使う。
    RecordAll,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainPolicyDecision {
    pub allowed: bool,
    pub reason: &'static str,
    pub matched_pattern: Option<String>,
}

impl DomainPolicy {
    pub fn new(allow_domains: Vec<String>) -> Self {
        let mut normalized = Vec::new();
        for pattern in allow_domains {
            let Ok(pattern) = normalize_domain_pattern(&pattern) else {
                continue;
            };
            if !normalized.contains(&pattern) {
                normalized.push(pattern);
            }
        }
        Self {
            allow_domains: normalized,
            mode: DomainPolicyMode::Allowlist,
        }
    }

    /// ポリシーエディタの記録モード（Tier2aでのネットワーク学習パス）専用の全許可ポリシー。
    /// `allow_domains`は空のまま持つ——このモードでは評価に使わないが、
    /// [`Self::allow_domains`]が空リストを一貫して返すようにするため。
    pub fn record_all() -> Self {
        Self {
            allow_domains: Vec::new(),
            mode: DomainPolicyMode::RecordAll,
        }
    }

    pub fn is_record_all(&self) -> bool {
        self.mode == DomainPolicyMode::RecordAll
    }

    pub fn allow_domains(&self) -> &[String] {
        &self.allow_domains
    }

    pub fn is_empty(&self) -> bool {
        self.allow_domains.is_empty()
    }

    pub fn evaluate_host(&self, host: &str) -> DomainPolicyDecision {
        if is_ip_literal(host) {
            return DomainPolicyDecision {
                allowed: false,
                reason: "ip_literal_denied",
                matched_pattern: None,
            };
        }
        if self.mode == DomainPolicyMode::RecordAll {
            return DomainPolicyDecision {
                allowed: true,
                reason: "record_all",
                matched_pattern: None,
            };
        }
        let matched_pattern = domain_match(host, &self.allow_domains);
        DomainPolicyDecision {
            allowed: matched_pattern.is_some(),
            reason: if matched_pattern.is_some() {
                "domain_allowed"
            } else {
                "domain_denied"
            },
            matched_pattern,
        }
    }
}

pub fn normalize_domain_pattern(pattern: &str) -> Result<String, String> {
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    validate_domain_pattern(&pattern)?;
    Ok(pattern)
}

pub fn validate_domain_pattern(pattern: &str) -> Result<(), String> {
    let pattern = pattern.trim().trim_end_matches('.');
    if pattern.is_empty() || pattern.len() > MAX_DOMAIN_PATTERN_LEN {
        return Err(format!(
            "invalid domain pattern (empty or too long, max {MAX_DOMAIN_PATTERN_LEN}): {pattern:?}"
        ));
    }
    if is_ip_literal(pattern) {
        return Err(format!(
            "invalid domain pattern (IP literals are not accepted for domain policy): {pattern:?}"
        ));
    }
    let domain = pattern.strip_prefix("*.").unwrap_or(pattern);
    if domain.is_empty() {
        return Err(format!(
            "invalid domain pattern (empty wildcard suffix): {pattern:?}"
        ));
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return Err(format!(
            "invalid domain pattern (malformed labels): {pattern:?}"
        ));
    }
    for label in domain.split('.') {
        if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
            return Err(format!(
                "invalid domain pattern (malformed label): {pattern:?}"
            ));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!(
                "invalid domain pattern (only [a-zA-Z0-9.-] and optional leading *. allowed): {pattern:?}"
            ));
        }
    }
    Ok(())
}

pub fn domain_match(host: &str, allow_domains: &[String]) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    allow_domains.iter().find_map(|pattern| {
        let pattern = pattern.trim().to_ascii_lowercase();
        let matched = match pattern.strip_prefix("*.") {
            Some(suffix) => host == suffix || host.ends_with(&format!(".{suffix}")),
            None => host == pattern,
        };
        matched.then_some(pattern)
    })
}

pub fn is_ip_literal(host: &str) -> bool {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    host.parse::<IpAddr>().is_ok() || is_legacy_ipv4_numeric_literal(host)
}

fn is_legacy_ipv4_numeric_literal(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 || parts.iter().any(|part| part.is_empty()) {
        return false;
    }
    let Some(numbers) = parts
        .iter()
        .map(|part| parse_legacy_ipv4_number(part))
        .collect::<Option<Vec<u64>>>()
    else {
        return false;
    };
    match numbers.as_slice() {
        [a] => *a <= 0xffff_ffff,
        [a, b] => *a <= 0xff && *b <= 0x00ff_ffff,
        [a, b, c] => *a <= 0xff && *b <= 0xff && *c <= 0xffff,
        [a, b, c, d] => *a <= 0xff && *b <= 0xff && *c <= 0xff && *d <= 0xff,
        _ => false,
    }
}

fn parse_legacy_ipv4_number(part: &str) -> Option<u64> {
    if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        if hex.is_empty() {
            return None;
        }
        return u64::from_str_radix(hex, 16).ok();
    }
    if part.len() > 1 && part.starts_with('0') {
        return u64::from_str_radix(part, 8).ok();
    }
    part.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_policy_matches_exact_and_wildcard() {
        let policy =
            DomainPolicy::new(vec!["example.com".to_string(), "*.trusted.org".to_string()]);
        assert!(policy.evaluate_host("example.com").allowed);
        assert!(policy.evaluate_host("Example.COM").allowed);
        assert!(!policy.evaluate_host("evil.example.com").allowed);
        assert!(policy.evaluate_host("api.trusted.org").allowed);
        assert!(policy.evaluate_host("trusted.org").allowed);
        assert!(!policy.evaluate_host("trusted.org.evil.com").allowed);
        assert!(!policy.evaluate_host("nope.com").allowed);
    }

    #[test]
    fn domain_policy_rejects_ip_literals_even_if_listed() {
        let policy = DomainPolicy::new(vec![
            "127.0.0.1".to_string(),
            "::1".to_string(),
            "198.18.0.1".to_string(),
            "2130706433".to_string(),
            "0x7f000001".to_string(),
        ]);
        for host in [
            "127.0.0.1",
            "[::1]",
            "198.18.0.1",
            "2130706433",
            "0x7f000001",
            "017700000001",
            "127.1",
            "127.0.1",
            "0x7f.0.0.1",
        ] {
            let decision = policy.evaluate_host(host);
            assert!(!decision.allowed);
            assert_eq!(decision.reason, "ip_literal_denied");
            assert_eq!(decision.matched_pattern, None);
        }
    }

    #[test]
    fn validate_domain_pattern_accepts_exact_and_wildcard_domains() {
        assert!(validate_domain_pattern("example.com").is_ok());
        assert!(validate_domain_pattern("api.example-1.co.jp").is_ok());
        assert!(validate_domain_pattern("*.example.com").is_ok());
    }

    #[test]
    fn normalize_domain_pattern_trims_lowercases_and_strips_trailing_dot() {
        assert_eq!(
            normalize_domain_pattern(" Example.COM. ").unwrap(),
            "example.com"
        );
        assert_eq!(
            normalize_domain_pattern(" *.Trusted.Example. ").unwrap(),
            "*.trusted.example"
        );
    }

    #[test]
    fn domain_policy_normalizes_and_deduplicates_patterns() {
        let policy = DomainPolicy::new(vec![
            "Example.COM.".to_string(),
            " example.com ".to_string(),
            "*.Trusted.Example.".to_string(),
        ]);

        assert_eq!(
            policy.allow_domains(),
            &["example.com".to_string(), "*.trusted.example".to_string()]
        );
        assert_eq!(
            policy.evaluate_host("API.TRUSTED.EXAMPLE").matched_pattern,
            Some("*.trusted.example".to_string())
        );
    }

    /// record-allモード: 通常のドメインはallow_domainsに関わらず全部許可される。
    #[test]
    fn record_all_mode_allows_any_non_ip_host_regardless_of_allow_domains() {
        let policy = DomainPolicy::record_all();
        assert!(policy.is_record_all());
        assert!(policy.allow_domains().is_empty());

        for host in [
            "example.com",
            "crates.io",
            "sub.anything.example",
            "a.b.c.d.example",
        ] {
            let decision = policy.evaluate_host(host);
            assert!(
                decision.allowed,
                "{host} should be allowed in record-all mode"
            );
            assert_eq!(decision.reason, "record_all");
            assert_eq!(decision.matched_pattern, None);
        }
    }

    /// record-allモードでもIPリテラルは引き続き拒否する——全許可はドメイン名の学習が
    /// 目的であり、IP直打ちは既存の非目標（アーキテクチャ設計書§9.2）のまま。
    #[test]
    fn record_all_mode_still_rejects_ip_literals() {
        let policy = DomainPolicy::record_all();
        for host in ["127.0.0.1", "[::1]", "198.18.0.1", "2130706433"] {
            let decision = policy.evaluate_host(host);
            assert!(!decision.allowed);
            assert_eq!(decision.reason, "ip_literal_denied");
        }
    }

    /// 通常の`DomainPolicy::new`はrecord-allモードにならない（既定はAllowlist）。
    #[test]
    fn new_constructs_an_allowlist_policy_not_record_all() {
        let policy = DomainPolicy::new(vec!["example.com".to_string()]);
        assert!(!policy.is_record_all());
        assert!(!policy.evaluate_host("nope.com").allowed);
    }

    #[test]
    fn validate_domain_pattern_rejects_ip_literals_and_injection() {
        for pattern in [
            "127.0.0.1",
            "[::1]",
            "2130706433",
            "0x7f000001",
            "017700000001",
            "127.1",
            "0x7f.0.0.1",
            "example.com\";}\nserver{{",
            "",
            "*. ",
            ".example.com",
            "example..com",
            "-example.com",
            "example-.com",
        ] {
            assert!(
                validate_domain_pattern(pattern).is_err(),
                "pattern should be rejected: {pattern:?}"
            );
        }
        assert!(validate_domain_pattern(&"a".repeat(300)).is_err());
    }
}
