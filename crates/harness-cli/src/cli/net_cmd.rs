//! `harness net`サブコマンド（ネットワーク監査ログの表示）と、協調プロキシ/Fake DNSへ
//! 渡すloopback許可ポートの算出。

use super::*;

pub(crate) fn net_audit_path(
    workspace_root: &Path,
    session: Option<&str>,
    explicit_path: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(path) = explicit_path {
        return Some(path.to_path_buf());
    }
    resolve_sandbox_dir(workspace_root, session)
        .map(|dir| workspace_root.join(dir).join("net-audit.jsonl"))
}

pub(crate) fn validate_and_merge_net_allow_domains(
    net_proxy: &mut NetProxyConfig,
    cli_domains: &[String],
) -> Result<(), String> {
    let mut normalized = Vec::new();
    for domain in &net_proxy.allow_domains {
        let domain = normalize_domain_pattern(domain)?;
        if !normalized.contains(&domain) {
            normalized.push(domain);
        }
    }
    for domain in cli_domains {
        let domain = normalize_domain_pattern(domain)?;
        if !normalized.contains(&domain) {
            normalized.push(domain);
        }
    }
    net_proxy.allow_domains = normalized;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetLoopbackPorts {
    pub(crate) tcp: Vec<u16>,
    pub(crate) udp: Vec<u16>,
}

pub(crate) fn sorted_unique_ports(mut ports: Vec<u16>) -> Vec<u16> {
    ports.sort_unstable();
    ports.dedup();
    ports
}

pub(crate) fn net_loopback_ports_for_agents(
    proxy_addr: Option<SocketAddr>,
    fake_dns_addr: Option<SocketAddr>,
) -> NetLoopbackPorts {
    let mut tcp = Vec::new();
    let mut udp = Vec::new();
    if let Some(addr) = proxy_addr {
        tcp.push(addr.port());
    }
    if let Some(addr) = fake_dns_addr {
        tcp.push(addr.port());
        udp.push(addr.port());
    }
    NetLoopbackPorts {
        tcp: sorted_unique_ports(tcp),
        udp: sorted_unique_ports(udp),
    }
}

fn event_string<'a>(event: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    event.get(key).and_then(|v| v.as_str())
}

pub(crate) fn event_bool(event: &serde_json::Value, key: &str) -> Option<bool> {
    event.get(key).and_then(|v| v.as_bool())
}

pub(crate) fn event_u64(event: &serde_json::Value, key: &str) -> Option<u64> {
    event.get(key).and_then(|v| v.as_u64())
}

pub(crate) fn filter_net_audit_events(
    events: Vec<serde_json::Value>,
    kind: Option<&str>,
    deny_only: bool,
) -> Vec<serde_json::Value> {
    events
        .into_iter()
        .filter(|event| {
            if let Some(kind) = kind {
                if event_string(event, "kind") != Some(kind) {
                    return false;
                }
            }
            if deny_only && event_bool(event, "allowed") != Some(false) {
                return false;
            }
            true
        })
        .collect()
}

pub(crate) fn format_net_audit_text(events: &[serde_json::Value]) -> String {
    if events.is_empty() {
        return "(no matching net audit events)\n".to_string();
    }
    let mut output = String::new();
    for event in events {
        let kind = event_string(event, "kind").unwrap_or("unknown");
        let protocol = event_string(event, "protocol").unwrap_or("-");
        let allowed = event_bool(event, "allowed")
            .map(|v| if v { "ALLOW" } else { "DENY" })
            .unwrap_or("-");
        let reason = event_string(event, "reason").unwrap_or("-");
        let host = event_string(event, "host")
            .or_else(|| event_string(event, "remote_host"))
            .unwrap_or("-");
        let port = event_u64(event, "port")
            .or_else(|| event_u64(event, "remote_port"))
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".to_string());
        let remote = event_string(event, "remote_addr").unwrap_or("-");
        output.push_str(&format!(
            "{kind:<8} {protocol:<8} {allowed:<5} {host:<40} {port:<5} {remote:<39} {reason}"
        ));
        if let Some(connect_host) = event_string(event, "connect_host") {
            output.push_str(&format!(" via={connect_host}"));
        }
        output.push('\n');
    }
    output
}

pub(crate) fn format_net_audit_output(events: &[serde_json::Value], output_format: OutputFormat) -> String {
    match output_format {
        OutputFormat::Json => serde_json::to_string(events).unwrap_or_else(|_| "[]".to_string()),
        OutputFormat::Jsonl => {
            let mut output = String::new();
            for event in events {
                if let Ok(s) = serde_json::to_string(event) {
                    output.push_str(&s);
                    output.push('\n');
                }
            }
            output
        }
        OutputFormat::Text => format_net_audit_text(events),
    }
}

pub(crate) fn run_net_subcommand(action: NetAction, workspace_root: &Path) -> ExitCode {
    match action {
        NetAction::Audit {
            session,
            path,
            kind,
            deny_only,
            output_format,
        } => {
            let Some(path) = net_audit_path(workspace_root, session.as_deref(), path.as_deref())
            else {
                eprintln!("no sandbox session found under .harness/sandbox/ (no net audit log)");
                return ExitCode::FAILURE;
            };
            let text = match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(e) => {
                    eprintln!("failed to read net audit log {}: {e}", path.display());
                    return ExitCode::FAILURE;
                }
            };
            let mut events = Vec::new();
            for (idx, line) in text.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let event = match serde_json::from_str::<serde_json::Value>(line) {
                    Ok(event) => event,
                    Err(e) => {
                        eprintln!(
                            "failed to parse net audit log {} line {}: {e}",
                            path.display(),
                            idx + 1
                        );
                        return ExitCode::FAILURE;
                    }
                };
                events.push(event);
            }
            let events = filter_net_audit_events(events, kind.as_deref(), deny_only);

            print!("{}", format_net_audit_output(&events, output_format));
            ExitCode::SUCCESS
        }
    }
}
#[cfg(test)]
mod net_audit_tests {
    use super::{
        filter_net_audit_events, format_net_audit_output, net_audit_path,
        net_loopback_ports_for_agents, validate_and_merge_net_allow_domains, NetLoopbackPorts,
        OutputFormat,
    };
    use harness_core::NetProxyConfig;
    use serde_json::json;
    use std::path::Path;

    #[test]
    fn explicit_net_audit_path_takes_precedence() {
        let workspace = Path::new(r"C:\workspace");
        let explicit = Path::new(r"C:\logs\net-audit.jsonl");

        assert_eq!(
            net_audit_path(workspace, Some("ignored"), Some(explicit)),
            Some(explicit.to_path_buf())
        );
    }

    #[test]
    fn session_net_audit_path_resolves_under_sandbox_dir() {
        let workspace = Path::new(r"C:\workspace");

        assert_eq!(
            net_audit_path(workspace, Some("abc123"), None),
            Some(
                workspace
                    .join(".harness")
                    .join("sandbox")
                    .join("session-abc123")
                    .join("net-audit.jsonl")
            )
        );
        assert_eq!(
            net_audit_path(workspace, Some("session-abc123"), None),
            Some(
                workspace
                    .join(".harness")
                    .join("sandbox")
                    .join("session-abc123")
                    .join("net-audit.jsonl")
            )
        );
    }

    #[test]
    fn loopback_ports_are_protocol_scoped_for_proxy_and_fake_dns() {
        let ports = net_loopback_ports_for_agents(
            Some("127.0.0.1:18080".parse().unwrap()),
            Some("127.0.0.1:18053".parse().unwrap()),
        );

        assert_eq!(
            ports,
            NetLoopbackPorts {
                tcp: vec![18053, 18080],
                udp: vec![18053],
            }
        );
    }

    #[test]
    fn loopback_ports_are_deduplicated_without_widening_protocols() {
        let ports = net_loopback_ports_for_agents(
            Some("127.0.0.1:18053".parse().unwrap()),
            Some("127.0.0.1:18053".parse().unwrap()),
        );

        assert_eq!(ports.tcp, vec![18053]);
        assert_eq!(ports.udp, vec![18053]);
    }

    #[test]
    fn net_allow_domains_are_validated_and_deduplicated() {
        let mut config = NetProxyConfig {
            allow_domains: vec!["Example.COM.".to_string()],
            ..Default::default()
        };

        validate_and_merge_net_allow_domains(
            &mut config,
            &["example.com".to_string(), "*.Trusted.Example.".to_string()],
        )
        .unwrap();

        assert_eq!(
            config.allow_domains,
            vec!["example.com".to_string(), "*.trusted.example".to_string()]
        );
    }

    #[test]
    fn net_allow_domains_reject_ip_literals_at_cli_merge_boundary() {
        let mut config = NetProxyConfig::default();

        let err = validate_and_merge_net_allow_domains(&mut config, &["127.0.0.1".to_string()])
            .unwrap_err();

        assert!(err.contains("IP literals"));
    }

    #[test]
    fn net_audit_filter_selects_kind_and_deny_only() {
        let events = vec![
            json!({
                "kind": "proxy",
                "protocol": "socks5",
                "host": "example.com",
                "allowed": true,
                "reason": "domain_allowed"
            }),
            json!({
                "kind": "fake_dns",
                "protocol": "dns_udp",
                "host": "blocked.example",
                "allowed": false,
                "reason": "domain_denied"
            }),
            json!({
                "kind": "wfp",
                "protocol": "tcp",
                "remote_addr": "198.18.0.1",
                "remote_host": "blocked.example",
                "allowed": false,
                "reason": "classify_drop"
            }),
        ];

        let filtered = filter_net_audit_events(events, Some("wfp"), true);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0]["kind"], "wfp");
        assert_eq!(filtered[0]["allowed"], false);
        assert_eq!(filtered[0]["remote_host"], "blocked.example");
    }

    #[test]
    fn net_audit_output_formats_json_jsonl_and_text() {
        let events = vec![json!({
            "kind": "wfp",
            "protocol": "tcp",
            "allowed": false,
            "remote_addr": "198.18.0.1",
            "remote_port": 443,
            "remote_host": "blocked.example",
            "reason": "classify_drop"
        })];

        let json_output = format_net_audit_output(&events, OutputFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();
        assert_eq!(parsed[0]["kind"], "wfp");

        let jsonl_output = format_net_audit_output(&events, OutputFormat::Jsonl);
        assert_eq!(jsonl_output.lines().count(), 1);
        let parsed_line: serde_json::Value = serde_json::from_str(jsonl_output.trim()).unwrap();
        assert_eq!(parsed_line["remote_host"], "blocked.example");

        let text_output = format_net_audit_output(&events, OutputFormat::Text);
        assert!(text_output.contains("wfp"));
        assert!(text_output.contains("DENY"));
        assert!(text_output.contains("blocked.example"));
        assert!(text_output.contains("classify_drop"));
    }
}
