//! Network policy evaluation — URL, domain, endpoint, and protocol checks.

use super::active::{
    decision_to_disposition, pick_stricter, pick_stricter_opt, ActivePolicy, EventDisposition,
};
use malwi_protocol::{NetworkInfo, TraceEvent};

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
    fn evaluate_network_info(&self, info: &NetworkInfo) -> Option<EventDisposition> {
        let mut strictest: Option<EventDisposition> = None;

        // HTTP URL rules (network section, URL patterns)
        if let Some(ref url) = info.url {
            if url.contains("://") {
                if let Some(parsed) = ParsedUrl::parse(url) {
                    let full_url = parsed.full_url();
                    let no_scheme_url = parsed.url_without_scheme();
                    let decision = self.engine.evaluate_http_url(&full_url, &no_scheme_url);
                    let disp = decision_to_disposition(decision);
                    if disp.should_display() {
                        strictest = Some(pick_stricter_opt(strictest, disp));
                    }
                }
            }
        }

        // network domains
        if let Some(ref host) = info.host {
            let decision = self.engine.evaluate_domain(host);
            let disp = decision_to_disposition(decision);
            if disp.should_display() {
                strictest = Some(pick_stricter_opt(strictest, disp));
            }
        }

        // network endpoints
        if let (Some(ref host), Some(port)) = (&info.host, info.port) {
            let decision = self.engine.evaluate_endpoint(host, port);
            let disp = decision_to_disposition(decision);
            if disp.should_display() {
                strictest = Some(pick_stricter_opt(strictest, disp));
            }
        }

        // network protocols
        if let Some(ref protocol) = info.protocol {
            let decision = self.engine.evaluate_protocol(protocol.as_str());
            let disp = decision_to_disposition(decision);
            if disp.should_display() {
                strictest = Some(pick_stricter_opt(strictest, disp));
            }
        }

        strictest
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
    fn evaluate_networking_from_args(&self, args: &[&str]) -> Option<EventDisposition> {
        let mut strictest: Option<EventDisposition> = None;

        for arg in args {
            if let Some(url) = extract_url_from_arg(arg) {
                if let Some(parsed) = ParsedUrl::parse(&url) {
                    // Evaluate domain
                    let domain_decision = self.engine.evaluate_domain(&parsed.host);
                    let domain_disp = decision_to_disposition(domain_decision);
                    strictest = Some(pick_stricter_opt(strictest, domain_disp));

                    // Evaluate protocol
                    let proto_decision = self.engine.evaluate_protocol(&parsed.scheme);
                    let proto_disp = decision_to_disposition(proto_decision);
                    strictest = Some(pick_stricter_opt(strictest, proto_disp));

                    // Evaluate endpoint (host:port)
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
    use malwi_policy::PolicyEngine;
    use malwi_protocol::{HookType, Protocol};

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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let event = make_trace_event(HookType::Python, "json.loads", &["'{\"key\": \"value\"}'"]);
        let disp = policy.evaluate_trace(&event);
        assert!(!disp.should_display(), "no URL = no networking check");
    }

    #[test]
    fn test_nodejs_bare_url_extraction() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  deny:\n    - \"*.evil.com\"\n")
                .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let net = NetworkInfo {
            url: Some("https://malware.evil.com/payload".to_string()),
            host: Some("malware.evil.com".to_string()),
            port: Some(443),
            protocol: Some(Protocol::Https),
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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let net = NetworkInfo {
            host: Some("10.0.0.1".to_string()),
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
            host: Some("example.com".to_string()),
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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let net = NetworkInfo {
            url: Some("http://example.com/insecure".to_string()),
            host: Some("example.com".to_string()),
            port: Some(80),
            protocol: Some(Protocol::Http),
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
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let net = NetworkInfo {
            url: Some("https://x.evil.com/payload".to_string()),
            host: Some("x.evil.com".to_string()),
            port: Some(443),
            protocol: Some(Protocol::Https),
        };
        let event = make_trace_event_with_net(HookType::Python, "requests.get", &[], net);
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display());
    }

    #[test]
    fn test_network_info_socket_no_url_still_evaluates_endpoint() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  deny:\n    - \"*:6379\"\n").unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let net = NetworkInfo {
            host: Some("redis.internal".to_string()),
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
    fn test_fallback_to_text_extraction_when_no_network_info() {
        let engine =
            PolicyEngine::from_yaml("version: 1\nnetwork:\n  deny:\n    - \"*.evil.com\"\n")
                .unwrap();
        let policy = ActivePolicy {
            engine,
            fn_cache: Default::default(),
        };

        let event = make_trace_event(
            HookType::Python,
            "requests.get",
            &["url='https://malware.evil.com/payload'"],
        );
        assert!(event.network_info.is_none());
        let disp = policy.evaluate_trace(&event);
        assert!(disp.should_display(), "text fallback should still work");
    }
}
