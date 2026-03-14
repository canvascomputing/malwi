//! Network policy evaluation — URL, domain, endpoint, and protocol checks.

use super::active::{
    decision_to_disposition, pick_stricter, pick_stricter_opt, ActivePolicy, EventDisposition,
};
use crate::policy::PolicyDecision;
use malwi_intercept::{NetworkInfo, TraceEvent};

/// Evaluate a policy decision and merge into the running strictest disposition.
fn merge_decision(strictest: &mut Option<EventDisposition>, decision: PolicyDecision) {
    let disp = decision_to_disposition(decision);
    if disp.should_display() {
        *strictest = Some(pick_stricter_opt(strictest.take(), disp));
    }
}

impl ActivePolicy {
    /// Evaluate networking policy (URL, domain, endpoint, protocol) against a trace event.
    /// Takes the function-level disposition and returns the strictest combined result.
    pub(super) fn evaluate_network_phase(
        &self,
        event: &TraceEvent,
        mut disp: EventDisposition,
    ) -> EventDisposition {
        // Prefer structured NetworkInfo when available (populated agent-side).
        // Falls back to text-based extraction for events without it.
        if let Some(ref net) = event.network_info {
            if let Some(net_disp) = self.evaluate_network_info(net) {
                disp = pick_stricter(disp, net_disp);
            }
        } else {
            // Fallback: text-based extraction from argument display strings
            let args: Vec<&str> = event
                .arguments
                .iter()
                .filter_map(|a| a.display.as_deref())
                .collect();
            if let Some(http_disp) = self.evaluate_http_from_args(&args) {
                disp = pick_stricter(disp, http_disp);
                if disp.is_blocked() {
                    return disp;
                }
            }
            if let Some(net_disp) = self.evaluate_networking_from_args(&args) {
                disp = pick_stricter(disp, net_disp);
            }
        }

        disp
    }

    /// Evaluate structured networking metadata against all networking policy sections.
    ///
    /// Evaluation order (broadest → most specific), short-circuits on Block:
    /// 1. Protocol — broadest constraint ("HTTPS only")
    /// 2. URL match — full URL pattern
    /// 3. Domain-only bridge — synthetic URL for socket events (no URL but domain known)
    /// 4. Domain — hostname pattern
    /// 5. Endpoint — domain:port or ip:port, most specific
    fn evaluate_network_info(&self, info: &NetworkInfo) -> Option<EventDisposition> {
        let mut s: Option<EventDisposition> = None;

        // 1. Protocol — broadest constraint
        if let Some(ref protocol) = info.protocol {
            merge_decision(&mut s, self.engine.evaluate_protocol(protocol.as_str()));
            if s.as_ref().is_some_and(|d| d.is_blocked()) {
                return s;
            }
        }

        // 2. HTTP URL rules (network section, URL patterns)
        if let Some(ref url) = info.url {
            if url.contains("://") {
                if let Some(parsed) = ParsedUrl::parse(url) {
                    merge_decision(
                        &mut s,
                        self.engine
                            .evaluate_http_url(&parsed.full_url(), &parsed.url_without_scheme()),
                    );
                    if s.as_ref().is_some_and(|d| d.is_blocked()) {
                        return s;
                    }
                }
            }
        }

        // 3. Domain-only bridge: synthetic URL for socket events without a URL.
        // Only uses domain (never constructs URLs from raw IPs — meaningless for
        // hostname-based patterns like "pypi.org/**").
        if info.url.is_none() {
            if let Some(ref domain) = info.domain {
                let synthetic = format!("{}/", domain);
                merge_decision(
                    &mut s,
                    self.engine.evaluate_http_url(&synthetic, &synthetic),
                );
                if s.as_ref().is_some_and(|d| d.is_blocked()) {
                    return s;
                }
            }
        }

        // 4. Domain — hostname pattern
        if let Some(ref domain) = info.domain {
            merge_decision(&mut s, self.engine.evaluate_domain(domain));
        }
        if s.as_ref().is_some_and(|d| d.is_blocked()) {
            return s;
        }

        // 5. Endpoint — domain:port or ip:port, most specific
        let endpoint_host = info.domain.as_deref().or(info.ip.as_deref());
        if let (Some(host), Some(port)) = (endpoint_host, info.port) {
            merge_decision(&mut s, self.engine.evaluate_endpoint(host, port));
        }

        s
    }

    /// Extract URL from arguments and evaluate against network URL rules.
    pub(super) fn evaluate_http_from_args(&self, args: &[&str]) -> Option<EventDisposition> {
        for arg in args {
            if let Some(url) = extract_url_from_arg(arg) {
                if let Some(parsed) = ParsedUrl::parse(&url) {
                    let full_url = parsed.full_url();
                    let no_scheme_url = parsed.url_without_scheme();
                    let decision = self.engine.evaluate_http_url(&full_url, &no_scheme_url);
                    let disp = decision_to_disposition(decision);
                    if disp.should_display() {
                        return Some(disp);
                    }
                }
            }
        }
        None
    }

    /// Extract HTTP metadata (URL, domain, protocol) from argument strings
    /// and evaluate against networking policy sections.
    ///
    /// Evaluation order: Protocol → Domain → Endpoint (short-circuit on Block).
    fn evaluate_networking_from_args(&self, args: &[&str]) -> Option<EventDisposition> {
        let mut strictest: Option<EventDisposition> = None;

        for arg in args {
            if let Some(url) = extract_url_from_arg(arg) {
                if let Some(parsed) = ParsedUrl::parse(&url) {
                    // 1. Protocol
                    let proto_decision = self.engine.evaluate_protocol(&parsed.scheme);
                    let proto_disp = decision_to_disposition(proto_decision);
                    strictest = Some(pick_stricter_opt(strictest, proto_disp));
                    if strictest.as_ref().is_some_and(|d| d.is_blocked()) {
                        return strictest.filter(|d| d.should_display());
                    }

                    // 2. Domain
                    let domain_decision = self.engine.evaluate_domain(&parsed.host);
                    let domain_disp = decision_to_disposition(domain_decision);
                    strictest = Some(pick_stricter_opt(strictest, domain_disp));
                    if strictest.as_ref().is_some_and(|d| d.is_blocked()) {
                        return strictest.filter(|d| d.should_display());
                    }

                    // 3. Endpoint (host:port)
                    if let Some(port) = parsed.port {
                        let ep_decision = self.engine.evaluate_endpoint(&parsed.host, port);
                        let ep_disp = decision_to_disposition(ep_decision);
                        strictest = Some(pick_stricter_opt(strictest, ep_disp));
                    }
                }
            }
        }

        // Only return if we found a non-Suppress result
        strictest.filter(|d| d.should_display())
    }
}

/// Parsed URL components for policy evaluation.
struct ParsedUrl {
    scheme: String,
    host: String,
    port: Option<u16>,
    /// Path component of the URL (everything after the authority, including leading /).
    /// Empty string if no path is present.
    path: String,
}

impl ParsedUrl {
    /// Parse a URL string into components.
    /// Handles http://, https://, ws://, wss:// schemes.
    fn parse(url: &str) -> Option<Self> {
        let (scheme, rest) = url.split_once("://")?;
        let scheme = scheme.to_lowercase();
        if !matches!(scheme.as_str(), "http" | "https" | "ws" | "wss") {
            return None;
        }

        // Split authority from path at first /
        let (authority, path) = if let Some(slash_pos) = rest.find('/') {
            (&rest[..slash_pos], &rest[slash_pos..])
        } else {
            (rest, "")
        };

        // Strip userinfo@ if present
        let authority = authority
            .rsplit_once('@')
            .map(|(_, h)| h)
            .unwrap_or(authority);

        let (host, explicit_port) = if authority.starts_with('[') {
            // IPv6: [::1]:port
            let bracket_end = authority.find(']')?;
            let host = &authority[1..bracket_end];
            let port = authority[bracket_end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse().ok());
            (host.to_string(), port)
        } else if let Some((h, p)) = authority.rsplit_once(':') {
            // host:port (only if p is numeric — avoids splitting IPv6 without brackets)
            if let Ok(port) = p.parse::<u16>() {
                (h.to_string(), Some(port))
            } else {
                (authority.to_string(), None)
            }
        } else {
            (authority.to_string(), None)
        };

        if host.is_empty() {
            return None;
        }

        // Default port based on scheme
        let port = explicit_port.or(match scheme.as_str() {
            "http" | "ws" => Some(80),
            "https" | "wss" => Some(443),
            _ => None,
        });

        Some(ParsedUrl {
            scheme,
            host,
            port,
            path: path.to_string(),
        })
    }

    /// Reconstruct the full URL for pattern matching.
    fn full_url(&self) -> String {
        let default_port = match self.scheme.as_str() {
            "http" | "ws" => Some(80),
            "https" | "wss" => Some(443),
            _ => None,
        };
        let port_suffix = match self.port {
            Some(p) if Some(p) != default_port => format!(":{}", p),
            _ => String::new(),
        };
        format!(
            "{}://{}{}{}",
            self.scheme, self.host, port_suffix, self.path
        )
    }

    /// Return the URL without scheme for matching patterns that omit the scheme.
    fn url_without_scheme(&self) -> String {
        let default_port = match self.scheme.as_str() {
            "http" | "ws" => Some(80),
            "https" | "wss" => Some(443),
            _ => None,
        };
        let port_suffix = match self.port {
            Some(p) if Some(p) != default_port => format!(":{}", p),
            _ => String::new(),
        };
        format!("{}{}{}", self.host, port_suffix, self.path)
    }
}

/// Extract a URL from a formatted argument display string.
fn extract_url_from_arg(arg: &str) -> Option<String> {
    let value = if let Some(rest) = arg
        .strip_prefix("url=")
        .or_else(|| arg.strip_prefix("uri="))
    {
        rest
    } else {
        arg
    };

    let value = value.strip_suffix("...").unwrap_or(value);
    let value = value.trim_matches('\'').trim_matches('"');

    if value.contains("://") {
        Some(value.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::super::active::test_helpers::*;
    use super::*;
    use crate::policy::PolicyEngine;
    use malwi_intercept::{HookType, Protocol};

    #[test]
    fn test_extract_url_from_formatted_arg() {
        assert_eq!(
            extract_url_from_arg("url='https://example.com/path'"),
            Some("https://example.com/path".to_string())
        );

        assert_eq!(
            extract_url_from_arg("url=https://example.com/path"),
            Some("https://example.com/path".to_string())
        );

        assert_eq!(
            extract_url_from_arg("'https://example.com'"),
            Some("https://example.com".to_string())
        );

        assert_eq!(
            extract_url_from_arg("uri='wss://ws.example.com'"),
            Some("wss://ws.example.com".to_string())
        );

        assert_eq!(
            extract_url_from_arg("url='https://example.com/very/long/path'..."),
            Some("https://example.com/very/long/path".to_string())
        );

        assert_eq!(extract_url_from_arg("method=GET"), None);
        assert_eq!(extract_url_from_arg("42"), None);
    }

    #[test]
    fn test_parsed_url_basic() {
        let url = ParsedUrl::parse("https://example.com/path").unwrap();
        assert_eq!(url.scheme, "https");
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, Some(443));
        assert_eq!(url.path, "/path");

        let url = ParsedUrl::parse("http://api.example.com:8080/data").unwrap();
        assert_eq!(url.scheme, "http");
        assert_eq!(url.host, "api.example.com");
        assert_eq!(url.port, Some(8080));
        assert_eq!(url.path, "/data");
    }

    #[test]
    fn test_parsed_url_websocket() {
        let url = ParsedUrl::parse("ws://localhost:3000").unwrap();
        assert_eq!(url.scheme, "ws");
        assert_eq!(url.host, "localhost");
        assert_eq!(url.port, Some(3000));
        assert_eq!(url.path, "");

        let url = ParsedUrl::parse("wss://ws.example.com").unwrap();
        assert_eq!(url.scheme, "wss");
        assert_eq!(url.host, "ws.example.com");
        assert_eq!(url.port, Some(443));
    }

    #[test]
    fn test_parsed_url_path_preserved() {
        let url = ParsedUrl::parse("https://api.example.com/v1/users/123").unwrap();
        assert_eq!(url.path, "/v1/users/123");

        let url = ParsedUrl::parse("https://example.com").unwrap();
        assert_eq!(url.path, "");

        let url = ParsedUrl::parse("https://example.com/").unwrap();
        assert_eq!(url.path, "/");
    }

    #[test]
    fn test_parsed_url_full_url() {
        let url = ParsedUrl::parse("https://example.com/path").unwrap();
        assert_eq!(url.full_url(), "https://example.com/path");

        let url = ParsedUrl::parse("http://api.example.com:8080/data").unwrap();
        assert_eq!(url.full_url(), "http://api.example.com:8080/data");

        let url = ParsedUrl::parse("https://example.com:443/test").unwrap();
        assert_eq!(url.full_url(), "https://example.com/test");

        let url = ParsedUrl::parse("http://example.com:80/test").unwrap();
        assert_eq!(url.full_url(), "http://example.com/test");
    }

    #[test]
    fn test_parsed_url_without_scheme() {
        let url = ParsedUrl::parse("https://example.com/path").unwrap();
        assert_eq!(url.url_without_scheme(), "example.com/path");

        let url = ParsedUrl::parse("http://api.example.com:8080/data").unwrap();
        assert_eq!(url.url_without_scheme(), "api.example.com:8080/data");
    }

    #[test]
    fn test_parsed_url_no_scheme() {
        assert!(ParsedUrl::parse("example.com").is_none());
        assert!(ParsedUrl::parse("ftp://example.com").is_none());
    }

    #[test]
    fn test_domain_policy_denies_via_url_arg() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  deny:\n    - \"*.evil.com\"\n")
                .unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://malware.evil.com/payload'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display(), "evil.com domain should be flagged");

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://api.example.com/data'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "example.com should be allowed");
    }

    #[test]
    fn test_protocol_policy_denies_http() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  protocols: [https]\n").unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='http://example.com/insecure'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "http should be denied when only https allowed"
        );

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://example.com/secure'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "https should be allowed");
    }

    #[test]
    fn test_endpoint_policy_denies_port() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\nnetwork:\n  deny:\n    - \"*:22\"\n    - \"*:25\"\n",
        )
        .unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(
            HookType::Nodejs,
            "http.request",
            &["url='http://example.com:22/ssh-tunnel'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display(), "port 22 should be denied");

        let event = make_trace_event(
            HookType::Nodejs,
            "http.request",
            &["url='https://example.com/safe'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "port 443 should be allowed");
    }

    #[test]
    fn test_function_deny_and_domain_deny_both_trigger() {
        let engine = PolicyEngine::from_yaml("version: 1\npython:\n  deny:\n    - \"requests.get\"\nnetwork:\n  deny:\n    - \"*.evil.com\"\n").unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://malware.evil.com'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(disp.is_blocked(), "function deny should win (blocked)");
    }

    #[test]
    fn test_function_allowed_but_domain_denied() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  deny:\n    - \"*.evil.com\"\n")
                .unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://malware.evil.com'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display(), "domain deny should still trigger");
    }

    #[test]
    fn test_no_url_in_args_skips_networking() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  deny:\n    - \"*.evil.com\"\n")
                .unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(HookType::Python, "json.loads", &["'{\"key\": \"value\"}'"]);
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "no URL = no networking check");
    }

    #[test]
    fn test_nodejs_bare_url_extraction() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  deny:\n    - \"*.evil.com\"\n")
                .unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(
            HookType::Nodejs,
            "https.request",
            &["'https://download.evil.com/malware'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display(), "bare URL should be extracted");
    }

    #[test]
    fn test_http_url_policy_denies_evil_domain() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  deny:\n    - \"*.evil.com/**\"\n")
                .unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://malware.evil.com/payload'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display());
    }

    #[test]
    fn test_http_url_policy_allows_safe_url() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  deny:\n    - \"*.evil.com/**\"\n")
                .unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://api.example.com/data'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "safe URL should be allowed");
    }

    #[test]
    fn test_http_url_policy_path_deny() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  deny:\n    - \"**/admin/**\"\n")
                .unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://example.com/admin/users'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display(), "/admin/ path should be denied");

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://example.com/api/data'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "/api/ path should be allowed");
    }

    #[test]
    fn test_http_url_policy_deny_http_scheme() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  deny:\n    - \"http://**\"\n")
                .unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='http://example.com/insecure'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display(), "http:// should be denied");

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://example.com/secure'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "https:// should be allowed");
    }

    #[test]
    fn test_http_url_policy_allow_with_implicit_deny() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  allow:\n    - \"pypi.org/**\"\n")
                .unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://pypi.org/simple/requests/'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "pypi.org should be allowed");

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://evil.com/malware'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display(), "non-pypi URL should be denied");

        let event = make_trace_event(
            HookType::Nodejs,
            "http.request",
            &["url='https://evil.com/malware'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "global network section affects all runtimes"
        );
    }

    #[test]
    fn test_network_url_and_domain_patterns_both_evaluated() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\nnetwork:\n  deny:\n    - \"*.evil.com/**\"\n    - \"*.bad.com\"\n",
        )
        .unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://x.evil.com/path'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "evil.com should be denied by URL pattern"
        );

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://x.bad.com/path'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "bad.com should be denied by domain pattern"
        );
    }

    #[test]
    fn test_network_info_domain_deny() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  deny:\n    - \"*.evil.com\"\n")
                .unwrap();
        let policy = ActivePolicy::new(engine);

        let net = NetworkInfo {
            url: Some("https://malware.evil.com/payload".to_string()),
            domain: Some("malware.evil.com".to_string()),
            port: Some(443),
            protocol: Some(Protocol::Https),
            ..Default::default()
        };
        let event = make_trace_event_with_net(
            HookType::Python,
            "requests.get",
            &["url='https://malware.evil.com/payload'"],
            net,
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "evil.com domain via NetworkInfo should be flagged"
        );
    }

    #[test]
    fn test_network_info_endpoint_deny() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  deny:\n    - \"*:22\"\n").unwrap();
        let policy = ActivePolicy::new(engine);

        let net = NetworkInfo {
            ip: Some("10.0.0.1".to_string()),
            port: Some(22),
            protocol: Some(Protocol::Tcp),
            ..Default::default()
        };
        let event = make_trace_event_with_net(
            HookType::Python,
            "socket.connect",
            &["address=('10.0.0.1', 22)"],
            net,
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "port 22 via socket.connect should be denied"
        );

        let net = NetworkInfo {
            domain: Some("example.com".to_string()),
            port: Some(80),
            protocol: Some(Protocol::Tcp),
            ..Default::default()
        };
        let event = make_trace_event_with_net(
            HookType::Python,
            "socket.connect",
            &["address=('example.com', 80)"],
            net,
        );
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "port 80 should be allowed");
    }

    #[test]
    fn test_network_info_protocol_deny() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  protocols: [https]\n").unwrap();
        let policy = ActivePolicy::new(engine);

        let net = NetworkInfo {
            url: Some("http://example.com/insecure".to_string()),
            domain: Some("example.com".to_string()),
            port: Some(80),
            protocol: Some(Protocol::Http),
            ..Default::default()
        };
        let event = make_trace_event_with_net(
            HookType::Python,
            "requests.get",
            &["url='http://example.com/insecure'"],
            net,
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "http protocol should be denied when only https allowed"
        );
    }

    #[test]
    fn test_network_info_http_url_deny() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  deny:\n    - \"*.evil.com/**\"\n")
                .unwrap();
        let policy = ActivePolicy::new(engine);

        let net = NetworkInfo {
            url: Some("https://x.evil.com/payload".to_string()),
            domain: Some("x.evil.com".to_string()),
            port: Some(443),
            protocol: Some(Protocol::Https),
            ..Default::default()
        };
        let event = make_trace_event_with_net(HookType::Python, "requests.get", &[], net);
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display());
    }

    #[test]
    fn test_network_info_socket_no_url_still_evaluates_endpoint() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  deny:\n    - \"*:6379\"\n").unwrap();
        let policy = ActivePolicy::new(engine);

        let net = NetworkInfo {
            domain: Some("redis.internal".to_string()),
            port: Some(6379),
            protocol: Some(Protocol::Tcp),
            ..Default::default()
        };
        let event = make_trace_event_with_net(
            HookType::Python,
            "socket.connect",
            &["address=('redis.internal', 6379)"],
            net,
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "port 6379 via socket.connect should be denied"
        );
    }

    #[test]
    fn test_network_allow_blocks_python_http_to_unknown_host() {
        // network: allow: ["huggingface.co/**"] — requests.get to evil.com should be blocked
        let engine = PolicyEngine::from_yaml(
            "version: 1\nnetwork:\n  allow:\n    - \"huggingface.co/**\"\n",
        )
        .unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://evil.com/exfil'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(disp.is_blocked(), "non-allowed host should be blocked");
    }

    #[test]
    fn test_network_allow_permits_python_http_to_allowed_host() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\nnetwork:\n  allow:\n    - \"huggingface.co/**\"\n",
        )
        .unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://huggingface.co/model'"],
        );
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.is_blocked(), "allowed host should pass through");
    }

    #[test]
    fn test_network_allow_auto_generates_network_hooks() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\nnetwork:\n  allow:\n    - \"huggingface.co/**\"\n",
        )
        .unwrap();
        let policy = ActivePolicy::new(engine);

        let configs = policy.derive_hook_configs(false);
        let has_requests_get = configs
            .iter()
            .any(|c| c.hook_type == HookType::Python && c.symbol == "requests.get");
        assert!(
            has_requests_get,
            "network: allow should auto-add requests.get hook"
        );
        let has_socket_connect = configs
            .iter()
            .any(|c| c.hook_type == HookType::Python && c.symbol == "socket.connect");
        assert!(
            has_socket_connect,
            "network: allow should auto-add socket.connect hook"
        );
    }

    #[test]
    fn test_network_allow_auto_generates_socket_hooks() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  allow:\n    - \"pypi.org/**\"\n")
                .unwrap();
        let policy = ActivePolicy::new(engine);

        let configs = policy.derive_hook_configs(false);
        let has_socket_connect = configs
            .iter()
            .any(|c| c.hook_type == HookType::Python && c.symbol == "socket.connect");
        assert!(
            has_socket_connect,
            "network: allow should auto-add socket.connect for Python"
        );
        let has_socket_sendto = configs
            .iter()
            .any(|c| c.hook_type == HookType::Python && c.symbol == "socket.sendto");
        assert!(
            has_socket_sendto,
            "network: allow should auto-add socket.sendto for Python"
        );
    }

    #[test]
    fn test_network_allow_auto_generates_nodejs_net_hooks() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\nnetwork:\n  allow:\n    - \"registry.npmjs.org/**\"\n",
        )
        .unwrap();
        let policy = ActivePolicy::new(engine);

        let configs = policy.derive_hook_configs(false);
        let has_net_connect = configs
            .iter()
            .any(|c| c.hook_type == HookType::Nodejs && c.symbol == "net.connect");
        assert!(
            has_net_connect,
            "network: allow should auto-add net.connect for Node.js"
        );
        let has_net_create = configs
            .iter()
            .any(|c| c.hook_type == HookType::Nodejs && c.symbol == "net.createConnection");
        assert!(
            has_net_create,
            "network: allow should auto-add net.createConnection for Node.js"
        );
    }

    #[test]
    fn test_network_allow_blocks_python_socket_to_unknown_host() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\nnetwork:\n  allow:\n    - \"huggingface.co/**\"\n",
        )
        .unwrap();
        let policy = ActivePolicy::new(engine);

        let net = NetworkInfo {
            domain: Some("evil.com".to_string()),
            port: Some(443),
            ..Default::default()
        };
        let event = make_trace_event_with_net(
            HookType::Python,
            "socket.connect",
            &["address=('evil.com', 443)"],
            net,
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "socket.connect to evil.com should be blocked when only huggingface.co is allowed"
        );
    }

    #[test]
    fn test_network_allow_permits_python_socket_to_allowed_host() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\nnetwork:\n  allow:\n    - \"huggingface.co/**\"\n",
        )
        .unwrap();
        let policy = ActivePolicy::new(engine);

        let net = NetworkInfo {
            domain: Some("huggingface.co".to_string()),
            port: Some(443),
            ..Default::default()
        };
        let event = make_trace_event_with_net(
            HookType::Python,
            "socket.connect",
            &["address=('huggingface.co', 443)"],
            net,
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            !disp.is_blocked(),
            "socket.connect to huggingface.co should be allowed"
        );
    }

    #[test]
    fn test_native_connect_ip_not_blocked_when_network_allow_exists() {
        let engine = PolicyEngine::from_yaml(
            "version: 1\nnetwork:\n  allow:\n    - \"huggingface.co/**\"\n",
        )
        .unwrap();
        let policy = ActivePolicy::new(engine);

        let net = NetworkInfo {
            ip: Some("93.184.216.34".to_string()),
            port: Some(443),
            ..Default::default()
        };
        let event = make_trace_event_with_net(HookType::Native, "connect", &[], net);
        let disp = policy.evaluate_trace(&event);
        assert!(
            !disp.is_blocked(),
            "IP-only connect should not be blocked by hostname allow rules"
        );
    }

    #[test]
    fn test_fallback_to_text_extraction_when_no_network_info() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  deny:\n    - \"*.evil.com\"\n")
                .unwrap();
        let policy = ActivePolicy::new(engine);

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://malware.evil.com/payload'"],
        );
        assert!(event.network_info.is_none());
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display(), "text fallback should still work");
    }

    #[test]
    fn test_network_phase_evaluates_on_cache_hit() {
        // Verify that network phase runs on 2nd+ calls (cache hit path).
        // The function-level cache only stores the function disposition;
        // network evaluation must still run for each event's NetworkInfo.
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  deny:\n    - \"*.evil.com\"\n")
                .unwrap();
        let policy = ActivePolicy::new(engine);

        // 1st call: safe URL — Suppress (no function deny, no network deny)
        let safe_net = malwi_intercept::NetworkInfo {
            domain: Some("safe.example.com".to_string()),
            url: Some("https://safe.example.com/api".to_string()),
            ..Default::default()
        };
        let event = make_trace_event_with_net(
            HookType::Python,
            "requests.get",
            &["url='https://safe.example.com/api'"],
            safe_net,
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            !disp.should_display(),
            "1st requests.get (safe URL) should be suppressed"
        );

        // 2nd call: evil URL — cache hit for function-level, but network must still evaluate
        let evil_net = malwi_intercept::NetworkInfo {
            domain: Some("malware.evil.com".to_string()),
            url: Some("https://malware.evil.com/payload".to_string()),
            ..Default::default()
        };
        let event = make_trace_event_with_net(
            HookType::Python,
            "requests.get",
            &["url='https://malware.evil.com/payload'"],
            evil_net,
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.should_display(),
            "2nd requests.get (evil URL) must be caught even on cache hit"
        );
    }

    #[test]
    fn test_protocol_deny_short_circuits_before_domain() {
        // Protocol deny (http not in protocols list) should short-circuit —
        // subsequent domain/endpoint checks should not override the block.
        let engine = PolicyEngine::from_yaml(
            "version: 1\nnetwork:\n  protocols: [https]\n  allow:\n    - \"example.com/**\"\n",
        )
        .unwrap();
        let policy = ActivePolicy::new(engine);

        let net = NetworkInfo {
            url: Some("http://example.com/data".to_string()),
            domain: Some("example.com".to_string()),
            port: Some(80),
            protocol: Some(Protocol::Http),
            ..Default::default()
        };
        let event = make_trace_event_with_net(
            HookType::Python,
            "requests.get",
            &["url='http://example.com/data'"],
            net,
        );
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "http protocol should be blocked even though example.com is allowed"
        );
    }

    #[test]
    fn test_resolved_domain_enables_domain_matching() {
        // network: allow: ["pypi.org/**"] — domain field provides hostname context
        // so the network phase can match allow rules against the original domain.
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  allow:\n    - \"pypi.org/**\"\n")
                .unwrap();
        let policy = ActivePolicy::new(engine);

        // IP-only connect without domain — Display (no hostname context,
        // hostname check in network phase prevents escalation)
        let net = NetworkInfo::ip_connect("151.101.0.223".to_string(), 443);
        let event = make_trace_event_with_net(HookType::Native, "connect", &[], net);
        let disp = policy.evaluate_trace(&event);
        assert!(
            !disp.is_blocked(),
            "IP-only connect without domain should not be blocked"
        );

        // Same IP but with domain=pypi.org — should match allow rule
        let net =
            NetworkInfo::resolved_connect("151.101.0.223".to_string(), 443, "pypi.org".to_string());
        let event = make_trace_event_with_net(HookType::Native, "connect", &[], net);
        let disp = policy.evaluate_trace(&event);
        assert!(
            !disp.is_blocked(),
            "connect with domain=pypi.org should match allow rule"
        );
    }

    #[test]
    fn test_resolved_domain_blocks_unlisted_domain() {
        // connect() to IP with domain not in allow list should be blocked
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  allow:\n    - \"pypi.org/**\"\n")
                .unwrap();
        let policy = ActivePolicy::new(engine);

        let net =
            NetworkInfo::resolved_connect("93.184.216.34".to_string(), 443, "evil.com".to_string());
        let event = make_trace_event_with_net(HookType::Native, "connect", &[], net);
        let disp = policy.evaluate_trace(&event);
        assert!(
            disp.is_blocked(),
            "connect with domain=evil.com should be blocked when only pypi.org is allowed"
        );
    }
}
