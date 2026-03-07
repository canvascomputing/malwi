//! Node.js function argument formatting.
//!
//! Extracts structured `NetworkInfo` from pre-formatted Node.js arguments.
//! Unlike Python/native formatters which set display strings, Node.js args
//! arrive pre-formatted from the C++ addon — this module only parses them
//! for NetworkInfo population.

use crate::{Argument, NetworkInfo, Protocol};

/// Extract `NetworkInfo` from Node.js function arguments.
///
/// Recognizes HTTP, socket, and DNS functions by name and parses their
/// pre-formatted argument display strings for host/port/URL/protocol.
///
/// Returns `Some(NetworkInfo)` for networking functions with extractable
/// metadata, `None` for non-networking functions.
pub fn format_nodejs_arguments(function_name: &str, arguments: &[Argument]) -> Option<NetworkInfo> {
    match function_name {
        // http/https module
        "http.request" | "http.get" => extract_http_network_info(arguments, Protocol::Http),
        "https.request" | "https.get" => extract_http_network_info(arguments, Protocol::Https),

        // net module
        "net.connect" | "net.createConnection" => extract_net_connect_info(arguments),

        // dns module
        "dns.resolve" | "dns.resolve4" | "dns.resolve6" | "dns.lookup" | "dns.resolveMx"
        | "dns.resolveTxt" | "dns.resolveSrv" | "dns.resolveNs" | "dns.resolveCname" => {
            extract_dns_info(arguments)
        }

        // fetch (global)
        "fetch" => extract_fetch_info(arguments),

        _ => None,
    }
}

/// Extract NetworkInfo from http.request/https.request arguments.
///
/// First arg is either:
/// - A URL string: `'http://example.com/path'`
/// - An options object: `{hostname: 'example.com', port: 80, path: '/api'}`
fn extract_http_network_info(args: &[Argument], default_proto: Protocol) -> Option<NetworkInfo> {
    let first = args.first()?.display.as_deref()?;

    // URL string argument: 'http://example.com/path'
    if first.starts_with('\'') || first.starts_with('"') {
        let url = first.trim_matches('\'').trim_matches('"');
        if url.contains("://") {
            return Some(network_info_from_url(url));
        }
    }

    // Options object: {hostname: 'example.com', port: 80, ...}
    if first.starts_with('{') {
        let mut ni = NetworkInfo {
            protocol: Some(default_proto),
            ..Default::default()
        };
        ni.host = extract_object_string_field(first, "hostname")
            .or_else(|| extract_object_string_field(first, "host"));
        ni.port = extract_object_number_field(first, "port");

        // Reconstruct URL if we have host
        if let Some(ref host) = ni.host {
            let path = extract_object_string_field(first, "path").unwrap_or_default();
            let port_suffix = ni.port.map(|p| format!(":{}", p)).unwrap_or_default();
            let scheme = ni.protocol.as_ref().map(|p| p.as_str()).unwrap_or("http");
            ni.url = Some(format!("{}://{}{}{}", scheme, host, port_suffix, path));
        }

        if !ni.is_empty() {
            return Some(ni);
        }
    }

    None
}

/// Extract NetworkInfo from net.connect/net.createConnection arguments.
///
/// First arg is either:
/// - Options object: `{port: 80, host: '127.0.0.1'}`
/// - Port number: `80`
fn extract_net_connect_info(args: &[Argument]) -> Option<NetworkInfo> {
    let first = args.first()?.display.as_deref()?;

    if first.starts_with('{') {
        let mut ni = NetworkInfo {
            protocol: Some(Protocol::Tcp),
            ..Default::default()
        };
        ni.host = extract_object_string_field(first, "host");
        ni.port = extract_object_number_field(first, "port");
        if !ni.is_empty() {
            return Some(ni);
        }
    }

    // Port number as first arg, host as second
    if let Ok(port) = first.parse::<u16>() {
        let host = args
            .get(1)
            .and_then(|a| a.display.as_deref())
            .map(|s| s.trim_matches('\'').trim_matches('"').to_string());
        return Some(NetworkInfo {
            host,
            port: Some(port),
            protocol: Some(Protocol::Tcp),
            ..Default::default()
        });
    }

    None
}

/// Extract NetworkInfo from dns.resolve/dns.lookup arguments.
///
/// First arg is hostname string: `'example.com'`
fn extract_dns_info(args: &[Argument]) -> Option<NetworkInfo> {
    let first = args.first()?.display.as_deref()?;
    let hostname = first.trim_matches('\'').trim_matches('"');
    if !hostname.is_empty() && !hostname.starts_with('{') {
        return Some(NetworkInfo::host_only(hostname.to_string()));
    }
    None
}

/// Extract NetworkInfo from fetch() arguments.
///
/// First arg is URL string: `'https://example.com/api'`
fn extract_fetch_info(args: &[Argument]) -> Option<NetworkInfo> {
    let first = args.first()?.display.as_deref()?;
    let url = first.trim_matches('\'').trim_matches('"');
    if url.contains("://") {
        return Some(network_info_from_url(url));
    }
    None
}

// =============================================================================
// HELPERS
// =============================================================================

/// Parse a URL string into NetworkInfo.
fn network_info_from_url(url: &str) -> NetworkInfo {
    let mut ni = NetworkInfo {
        url: Some(url.to_string()),
        ..Default::default()
    };

    let Some((scheme, rest)) = url.split_once("://") else {
        return ni;
    };
    ni.protocol = Some(Protocol::from(scheme.to_lowercase().as_str()));

    // Split authority from path
    let authority = if let Some(pos) = rest.find('/') {
        &rest[..pos]
    } else {
        rest
    };

    // Strip userinfo@
    let authority = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);

    if let Some(colon) = authority.rfind(':') {
        let host = &authority[..colon];
        if let Ok(port) = authority[colon + 1..].parse::<u16>() {
            ni.host = Some(host.to_string());
            ni.port = Some(port);
        } else {
            ni.host = Some(authority.to_string());
        }
    } else {
        ni.host = Some(authority.to_string());
    }

    ni
}

/// Extract a string value from a display-formatted JS object.
///
/// Parses `{key: 'value', ...}` format produced by the C++ addon's
/// `get_value_info()`. Handles single-quoted string values.
fn extract_object_string_field(obj_display: &str, key: &str) -> Option<String> {
    // Look for "key: 'value'" or "key: \"value\""
    let needle = format!("{}: ", key);
    let start = obj_display.find(&needle)? + needle.len();
    let rest = &obj_display[start..];

    // String value starts with quote
    let (quote, rest) = if rest.starts_with('\'') {
        ('\'', &rest[1..])
    } else if rest.starts_with('"') {
        ('"', &rest[1..])
    } else {
        return None;
    };

    // Find closing quote
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

/// Extract a numeric value from a display-formatted JS object.
///
/// Parses `{key: 1234, ...}` format.
fn extract_object_number_field(obj_display: &str, key: &str) -> Option<u16> {
    let needle = format!("{}: ", key);
    let start = obj_display.find(&needle)? + needle.len();
    let rest = &obj_display[start..];

    // Collect digits
    let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    num_str.parse().ok()
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Argument;

    fn arg(display: &str) -> Argument {
        Argument {
            raw_value: 0,
            display: Some(display.to_string()),
        }
    }

    #[test]
    fn test_format_nodejs_http_request_with_url_string() {
        let args = vec![arg("'http://example.com/api'")];
        let ni = format_nodejs_arguments("http.request", &args).unwrap();
        assert_eq!(ni.url.as_deref(), Some("http://example.com/api"));
        assert_eq!(ni.host.as_deref(), Some("example.com"));
        assert_eq!(ni.protocol, Some(Protocol::Http));
    }

    #[test]
    fn test_format_nodejs_https_request_with_options() {
        let args = vec![arg(
            "{hostname: 'api.example.com', port: 443, path: '/v1/users'}",
        )];
        let ni = format_nodejs_arguments("https.request", &args).unwrap();
        assert_eq!(ni.host.as_deref(), Some("api.example.com"));
        assert_eq!(ni.port, Some(443));
        assert_eq!(ni.protocol, Some(Protocol::Https));
        assert_eq!(
            ni.url.as_deref(),
            Some("https://api.example.com:443/v1/users")
        );
    }

    #[test]
    fn test_format_nodejs_http_get_with_host_field() {
        let args = vec![arg("{host: 'localhost', port: 3000}")];
        let ni = format_nodejs_arguments("http.get", &args).unwrap();
        assert_eq!(ni.host.as_deref(), Some("localhost"));
        assert_eq!(ni.port, Some(3000));
    }

    #[test]
    fn test_format_nodejs_net_connect_with_options() {
        let args = vec![arg("{port: 6379, host: '127.0.0.1'}")];
        let ni = format_nodejs_arguments("net.connect", &args).unwrap();
        assert_eq!(ni.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(ni.port, Some(6379));
        assert_eq!(ni.protocol, Some(Protocol::Tcp));
    }

    #[test]
    fn test_format_nodejs_net_connect_with_port_and_host_args() {
        let args = vec![arg("6379"), arg("'127.0.0.1'")];
        let ni = format_nodejs_arguments("net.connect", &args).unwrap();
        assert_eq!(ni.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(ni.port, Some(6379));
    }

    #[test]
    fn test_format_nodejs_dns_resolve() {
        let args = vec![arg("'evil.example.com'")];
        let ni = format_nodejs_arguments("dns.resolve", &args).unwrap();
        assert_eq!(ni.host.as_deref(), Some("evil.example.com"));
    }

    #[test]
    fn test_format_nodejs_dns_lookup() {
        let args = vec![arg("'example.com'")];
        let ni = format_nodejs_arguments("dns.lookup", &args).unwrap();
        assert_eq!(ni.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_format_nodejs_fetch_with_url() {
        let args = vec![arg("'https://api.example.com/data'")];
        let ni = format_nodejs_arguments("fetch", &args).unwrap();
        assert_eq!(ni.url.as_deref(), Some("https://api.example.com/data"));
        assert_eq!(ni.host.as_deref(), Some("api.example.com"));
        assert_eq!(ni.protocol, Some(Protocol::Https));
    }

    #[test]
    fn test_format_nodejs_non_networking_returns_none() {
        let args = vec![arg("'/etc/passwd'")];
        assert!(format_nodejs_arguments("fs.readFileSync", &args).is_none());
    }

    #[test]
    fn test_format_nodejs_empty_args_returns_none() {
        assert!(format_nodejs_arguments("http.request", &[]).is_none());
    }

    #[test]
    fn test_extract_object_string_field() {
        let obj = "{hostname: 'example.com', port: 80}";
        assert_eq!(
            extract_object_string_field(obj, "hostname"),
            Some("example.com".to_string())
        );
        assert_eq!(extract_object_string_field(obj, "port"), None);
    }

    #[test]
    fn test_extract_object_number_field() {
        let obj = "{hostname: 'example.com', port: 80, timeout: 5000}";
        assert_eq!(extract_object_number_field(obj, "port"), Some(80));
        assert_eq!(extract_object_number_field(obj, "timeout"), Some(5000));
        assert_eq!(extract_object_number_field(obj, "hostname"), None);
    }

    #[test]
    fn test_format_nodejs_http_request_with_url_and_port() {
        let args = vec![arg("'http://127.0.0.1:4444/path'")];
        let ni = format_nodejs_arguments("http.request", &args).unwrap();
        assert_eq!(ni.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(ni.port, Some(4444));
        assert_eq!(ni.protocol, Some(Protocol::Http));
    }
}
