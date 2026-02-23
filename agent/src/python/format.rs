//! Python function argument formatting.
//!
//! Provides human-readable display values for arguments to known Python
//! networking functions. Enhances the generic repr() output with context-specific
//! labels and constant names.

use malwi_protocol::{Argument, NetworkInfo, Protocol};

const MAX_URL_LEN: usize = 80;
const MAX_DATA_PREVIEW: usize = 64;

/// Format arguments for known Python networking functions.
///
/// Enhances the generic repr() display with:
/// - Named parameter labels (e.g., "url=", "timeout=")
/// - Symbolic constant names (e.g., AF_INET, SOCK_STREAM)
/// - Truncated previews of long data
///
/// Returns `Some(NetworkInfo)` for networking functions with structured
/// metadata for direct policy evaluation.
///
/// # Arguments
/// * `qualified_name` - Full qualified function name (e.g., "socket.socket", "requests.get")
/// * `arguments` - Mutable slice of arguments to format
pub fn format_python_arguments(
    qualified_name: &str,
    arguments: &mut [Argument],
) -> Option<NetworkInfo> {
    // Extract module and function from qualified name
    // e.g., "socket.socket" -> ("socket", "socket")
    // e.g., "requests.api.get" -> ("requests.api", "get")
    // e.g., "urllib.request.urlopen" -> ("urllib.request", "urlopen")
    let (module, function) = match qualified_name.rsplit_once('.') {
        Some((m, f)) => (m, f),
        None => ("", qualified_name),
    };

    match (module, function) {
        // =====================================================================
        // socket module (standard library)
        // =====================================================================
        ("socket" | "_socket", "socket") => {
            let ni = format_socket_socket(arguments);
            return non_empty_network_info(ni);
        }
        ("socket" | "_socket", "connect") => {
            let ni = format_socket_connect(arguments);
            return non_empty_network_info(ni);
        }
        ("socket" | "_socket", "bind") => {
            format_socket_address(arguments, "address");
        }
        ("socket" | "_socket", "listen") => format_socket_listen(arguments),
        ("socket" | "_socket", "send") => format_socket_send(arguments),
        ("socket" | "_socket", "sendall") => format_socket_send(arguments),
        ("socket" | "_socket", "recv") => format_socket_recv(arguments),
        ("socket" | "_socket", "sendto") => {
            let ni = format_socket_sendto(arguments);
            return non_empty_network_info(ni);
        }
        ("socket" | "_socket", "recvfrom") => format_socket_recvfrom(arguments),
        ("socket" | "_socket", "setsockopt") => format_socket_setsockopt(arguments),
        ("socket" | "_socket", "getsockopt") => format_socket_getsockopt(arguments),
        ("socket" | "_socket", "shutdown") => format_socket_shutdown(arguments),
        ("socket" | "_socket", "getaddrinfo") => {
            let ni = format_socket_getaddrinfo(arguments);
            return non_empty_network_info(ni);
        }
        ("socket" | "_socket", "gethostbyname") => {
            let ni = format_socket_gethostbyname(arguments);
            return non_empty_network_info(ni);
        }
        ("socket" | "_socket", "create_connection") => {
            let ni = format_socket_create_connection(arguments);
            return non_empty_network_info(ni);
        }

        // =====================================================================
        // ssl module (standard library)
        // =====================================================================
        ("ssl", "wrap_socket") => {
            let ni = format_ssl_wrap_socket(arguments);
            return non_empty_network_info(ni);
        }
        ("ssl", "create_default_context") => format_ssl_create_default_context(arguments),
        ("ssl.SSLContext", "wrap_socket") => {
            let ni = format_ssl_context_wrap_socket(arguments);
            return non_empty_network_info(ni);
        }
        ("ssl.SSLContext", "load_cert_chain") => format_ssl_load_cert_chain(arguments),
        ("ssl.SSLContext", "load_verify_locations") => format_ssl_load_verify_locations(arguments),

        // =====================================================================
        // http.client module (standard library)
        // =====================================================================
        ("http.client.HTTPConnection" | "http.client", "__init__") => {
            let ni = format_http_connection_init_net(arguments, "http");
            return non_empty_network_info(ni);
        }
        ("http.client.HTTPSConnection", "__init__") => {
            let ni = format_http_connection_init_net(arguments, "https");
            return non_empty_network_info(ni);
        }
        ("http.client.HTTPConnection" | "http.client.HTTPSConnection", "request") => {
            let ni = format_http_request_net(arguments, module);
            return non_empty_network_info(ni);
        }
        ("http.client.HTTPResponse", "read") => format_http_response_read(arguments),

        // =====================================================================
        // urllib.request module (standard library)
        // =====================================================================
        ("urllib.request", "urlopen") => {
            let ni = format_urlopen_net(arguments);
            return non_empty_network_info(ni);
        }
        ("urllib.request.Request", "__init__") => {
            let ni = format_urllib_request_init_net(arguments);
            return non_empty_network_info(ni);
        }
        ("urllib.request.OpenerDirector", "open") => {
            let ni = format_opener_open_net(arguments);
            return non_empty_network_info(ni);
        }

        // =====================================================================
        // requests library (third-party)
        // =====================================================================
        ("requests" | "requests.api", "get") => {
            return format_requests_get_net(arguments, Some("GET"));
        }
        ("requests" | "requests.api", "post") => {
            return format_requests_post_net(arguments, Some("POST"));
        }
        ("requests" | "requests.api", "put") => {
            return format_requests_method_net(arguments, Some("PUT"));
        }
        ("requests" | "requests.api", "delete") => {
            return format_requests_method_net(arguments, Some("DELETE"));
        }
        ("requests" | "requests.api", "patch") => {
            return format_requests_method_net(arguments, Some("PATCH"));
        }
        ("requests" | "requests.api", "head") => {
            return format_requests_method_net(arguments, Some("HEAD"));
        }
        ("requests" | "requests.api", "options") => {
            return format_requests_method_net(arguments, Some("OPTIONS"));
        }
        ("requests" | "requests.api", "request") => {
            return format_requests_request_net(arguments);
        }
        ("requests.sessions.Session" | "requests.Session", "request") => {
            return format_requests_request_net(arguments);
        }
        ("requests.sessions.Session" | "requests.Session", "get") => {
            return format_requests_get_net(arguments, Some("GET"));
        }
        ("requests.sessions.Session" | "requests.Session", "post") => {
            return format_requests_post_net(arguments, Some("POST"));
        }
        ("requests.sessions.Session" | "requests.Session", "put") => {
            return format_requests_method_net(arguments, Some("PUT"));
        }
        ("requests.sessions.Session" | "requests.Session", "delete") => {
            return format_requests_method_net(arguments, Some("DELETE"));
        }
        ("requests.sessions.Session" | "requests.Session", "patch") => {
            return format_requests_method_net(arguments, Some("PATCH"));
        }
        ("requests.sessions.Session" | "requests.Session", "head") => {
            return format_requests_method_net(arguments, Some("HEAD"));
        }
        ("requests.sessions.Session" | "requests.Session", "options") => {
            return format_requests_method_net(arguments, Some("OPTIONS"));
        }
        ("requests.models.Response", "iter_content") => format_response_iter_content(arguments),

        // =====================================================================
        // urllib3 library (third-party, used by requests)
        // =====================================================================
        ("urllib3.poolmanager.PoolManager" | "urllib3.PoolManager", "request") => {
            return format_urllib3_request_net(arguments);
        }
        ("urllib3.connectionpool.HTTPConnectionPool", "__init__") => {
            format_urllib3_pool_init(arguments)
        }
        ("urllib3.connectionpool.HTTPSConnectionPool", "__init__") => {
            format_urllib3_pool_init(arguments)
        }
        ("urllib3.connectionpool.HTTPConnectionPool", "urlopen")
        | ("urllib3.connectionpool.HTTPSConnectionPool", "urlopen") => {
            return format_urllib3_urlopen_net(arguments);
        }

        // =====================================================================
        // httpx library (third-party, modern async-first)
        // =====================================================================
        ("httpx" | "httpx._api", "get") => {
            return format_httpx_get_net(arguments, Some("GET"));
        }
        ("httpx" | "httpx._api", "post") => {
            return format_httpx_post_net(arguments, Some("POST"));
        }
        ("httpx" | "httpx._api", "request") => {
            return format_httpx_request_net(arguments);
        }
        ("httpx" | "httpx._api", "put") => {
            return format_httpx_method_net(arguments, Some("PUT"));
        }
        ("httpx" | "httpx._api", "delete") => {
            return format_httpx_method_net(arguments, Some("DELETE"));
        }
        ("httpx" | "httpx._api", "patch") => {
            return format_httpx_method_net(arguments, Some("PATCH"));
        }
        ("httpx" | "httpx._api", "head") => {
            return format_httpx_method_net(arguments, Some("HEAD"));
        }
        ("httpx" | "httpx._api", "options") => {
            return format_httpx_method_net(arguments, Some("OPTIONS"));
        }
        ("httpx.Client" | "httpx._client.Client", "get")
        | ("httpx.AsyncClient" | "httpx._client.AsyncClient", "get") => {
            return format_httpx_get_net(arguments, Some("GET"));
        }
        ("httpx.Client" | "httpx._client.Client", "post")
        | ("httpx.AsyncClient" | "httpx._client.AsyncClient", "post") => {
            return format_httpx_post_net(arguments, Some("POST"));
        }
        ("httpx.Client" | "httpx._client.Client", "request")
        | ("httpx.AsyncClient" | "httpx._client.AsyncClient", "request") => {
            return format_httpx_request_net(arguments);
        }

        // =====================================================================
        // aiohttp library (third-party, async)
        // =====================================================================
        ("aiohttp.client.ClientSession" | "aiohttp.ClientSession", "get")
        | ("aiohttp.client.ClientSession" | "aiohttp.ClientSession", "_request") => {
            return format_aiohttp_request_net(arguments, Some("GET"));
        }
        ("aiohttp.client.ClientSession" | "aiohttp.ClientSession", "post") => {
            return format_aiohttp_post_net(arguments, Some("POST"));
        }
        ("aiohttp.client.ClientSession" | "aiohttp.ClientSession", "request") => {
            return format_aiohttp_request_method_net(arguments);
        }
        ("aiohttp.client.ClientSession" | "aiohttp.ClientSession", "ws_connect") => {
            return format_aiohttp_ws_connect_net(arguments);
        }
        ("aiohttp.connector.TCPConnector", "__init__") => format_aiohttp_connector_init(arguments),

        // =====================================================================
        // dns.resolver (dnspython library)
        // =====================================================================
        ("dns.resolver", "resolve") | ("dns.resolver", "query") => {
            let ni = format_dns_resolver_resolve_net(arguments);
            return non_empty_network_info(ni);
        }
        ("dns.resolver.Resolver", "resolve") | ("dns.resolver.Resolver", "query") => {
            let ni = format_dns_resolver_resolve_net(arguments);
            return non_empty_network_info(ni);
        }

        // =====================================================================
        // websockets / websocket-client libraries
        // =====================================================================
        ("websockets" | "websockets.client" | "websockets.legacy.client", "connect") => {
            return format_websocket_connect_net(arguments);
        }
        ("websockets" | "websockets.server" | "websockets.legacy.server", "serve") => {
            format_websocket_serve(arguments);
        }
        ("websocket" | "websocket._core.WebSocket", "connect") => {
            return format_websocket_client_connect_net(arguments);
        }
        ("websocket._core.WebSocket", "send") => format_websocket_send(arguments),

        // =====================================================================
        // subprocess module (standard library)
        // =====================================================================
        ("subprocess", "run")
        | ("subprocess", "call")
        | ("subprocess", "check_call")
        | ("subprocess", "check_output") => format_subprocess_args(arguments),
        ("subprocess", "Popen") => format_subprocess_args(arguments),

        // =====================================================================
        // os module - process execution functions
        // =====================================================================
        ("os", "system") => format_os_system(arguments),
        ("os", "execv") | ("os", "execve") | ("os", "execvp") | ("os", "execvpe") => {
            format_os_exec(arguments)
        }
        ("os", "spawnv")
        | ("os", "spawnve")
        | ("os", "spawnl")
        | ("os", "spawnle")
        | ("os", "spawnvp")
        | ("os", "spawnvpe")
        | ("os", "spawnlp")
        | ("os", "spawnlpe") => format_os_spawn(arguments),
        ("os", "popen") => format_os_popen(arguments),

        _ => {} // Unknown function - leave as repr()
    }

    None
}

// =============================================================================
// NETWORK INFO HELPERS
// =============================================================================

/// Return Some only if NetworkInfo has at least one field populated.
fn non_empty_network_info(ni: NetworkInfo) -> Option<NetworkInfo> {
    if ni.url.is_some() || ni.host.is_some() || ni.port.is_some() || ni.protocol.is_some() {
        Some(ni)
    } else {
        None
    }
}

/// Parse a simple URL into NetworkInfo components.
/// Handles http://, https://, ws://, wss:// schemes.
fn network_info_from_url(raw: &str) -> NetworkInfo {
    let url = raw.trim_matches('\'').trim_matches('"');
    let mut ni = NetworkInfo {
        url: Some(url.to_string()),
        ..Default::default()
    };

    let Some((scheme, rest)) = url.split_once("://") else {
        return ni;
    };
    let scheme_lower = scheme.to_lowercase();
    ni.protocol = Some(Protocol::from(scheme_lower.as_str()));

    // Split authority from path at first /
    let authority = if let Some(slash_pos) = rest.find('/') {
        &rest[..slash_pos]
    } else {
        rest
    };

    // Strip userinfo@
    let authority = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);

    if authority.starts_with('[') {
        // IPv6
        if let Some(bracket_end) = authority.find(']') {
            ni.host = Some(authority[1..bracket_end].to_string());
            ni.port = authority[bracket_end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse().ok());
        }
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            ni.host = Some(h.to_string());
            ni.port = Some(port);
        } else {
            ni.host = Some(authority.to_string());
        }
    } else {
        ni.host = Some(authority.to_string());
    }

    // Default port from scheme
    if ni.port.is_none() {
        ni.port = match scheme_lower.as_str() {
            "http" | "ws" => Some(80),
            "https" | "wss" => Some(443),
            _ => None,
        };
    }

    ni
}

/// Parse a Python socket address tuple repr like "('127.0.0.1', 80)" into (host, port).
fn parse_socket_address(repr: &str) -> Option<(String, u16)> {
    let inner = repr.trim().strip_prefix('(')?.strip_suffix(')')?;
    let (host_part, port_part) = inner.rsplit_once(',')?;
    let host = host_part.trim().trim_matches('\'').trim_matches('"');
    let port: u16 = port_part.trim().parse().ok()?;
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

/// Extract a clean URL string from a display argument value.
/// Strips surrounding quotes and truncation markers.
fn clean_url_from_display(display: &str) -> &str {
    let v = display.strip_suffix("...").unwrap_or(display);
    v.trim_matches('\'').trim_matches('"')
}

// =============================================================================
// SOCKET MODULE FORMATTERS
// =============================================================================

/// Format socket.socket(family, type, proto) arguments.
/// Returns NetworkInfo with protocol (tcp/udp) based on socket type.
fn format_socket_socket(args: &mut [Argument]) -> NetworkInfo {
    let mut ni = NetworkInfo::default();
    // arg0: family (int)
    if !args.is_empty() {
        if let Some(family) = parse_int_from_repr(&args[0].display) {
            args[0].display = Some(format_address_family(family));
        }
    }
    // arg1: type (int)
    if args.len() > 1 {
        if let Some(sock_type) = parse_int_from_repr(&args[1].display) {
            let base = sock_type & 0xf;
            ni.protocol = match base {
                1 => Some(Protocol::Tcp),
                2 => Some(Protocol::Udp),
                _ => None,
            };
            args[1].display = Some(format_socket_type(sock_type));
        }
    }
    // arg2: proto (int)
    if args.len() > 2 {
        if let Some(proto) = parse_int_from_repr(&args[2].display) {
            args[2].display = Some(format!("proto={}", proto));
        }
    }
    ni
}

/// Format socket.connect arguments with NetworkInfo.
fn format_socket_connect(args: &mut [Argument]) -> NetworkInfo {
    let mut ni = NetworkInfo {
        protocol: Some(Protocol::Tcp),
        ..Default::default()
    };
    let addr_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > addr_idx {
        if let Some(ref display) = args[addr_idx].display {
            if let Some((host, port)) = parse_socket_address(display) {
                ni.host = Some(host);
                ni.port = Some(port);
            }
            args[addr_idx].display = Some(format!("address={}", display));
        }
    }
    ni
}

/// Format socket address argument (bind, etc.) — display only, no NetworkInfo.
fn format_socket_address(args: &mut [Argument], label: &str) {
    // Skip 'self' argument if present
    let addr_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > addr_idx {
        if let Some(ref display) = args[addr_idx].display {
            args[addr_idx].display = Some(format!("{}={}", label, display));
        }
    }
}

/// Format socket.listen(backlog) arguments.
fn format_socket_listen(args: &mut [Argument]) {
    // Skip 'self', get backlog
    let idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > idx {
        if let Some(ref display) = args[idx].display {
            args[idx].display = Some(format!("backlog={}", display));
        }
    }
}

/// Format socket.send(data, flags) / socket.sendall(data, flags) arguments.
fn format_socket_send(args: &mut [Argument]) {
    // Skip 'self'
    let data_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > data_idx {
        if let Some(ref display) = args[data_idx].display {
            let preview = truncate_data_preview(display);
            let len = estimate_bytes_length(display);
            args[data_idx].display = Some(format!("{}, len={}", preview, len));
        }
    }
    // flags
    let flags_idx = data_idx + 1;
    if args.len() > flags_idx {
        if let Some(ref display) = args[flags_idx].display {
            args[flags_idx].display = Some(format!("flags={}", display));
        }
    }
}

/// Format socket.recv(bufsize, flags) arguments.
fn format_socket_recv(args: &mut [Argument]) {
    // Skip 'self'
    let bufsize_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > bufsize_idx {
        if let Some(ref display) = args[bufsize_idx].display {
            args[bufsize_idx].display = Some(format!("bufsize={}", display));
        }
    }
    // flags
    let flags_idx = bufsize_idx + 1;
    if args.len() > flags_idx {
        if let Some(ref display) = args[flags_idx].display {
            args[flags_idx].display = Some(format!("flags={}", display));
        }
    }
}

/// Format socket.sendto(data, address) arguments.
fn format_socket_sendto(args: &mut [Argument]) -> NetworkInfo {
    let mut ni = NetworkInfo {
        protocol: Some(Protocol::Udp),
        ..Default::default()
    };
    // Skip 'self'
    let data_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > data_idx {
        if let Some(ref display) = args[data_idx].display {
            let preview = truncate_data_preview(display);
            args[data_idx].display = Some(preview);
        }
    }
    // address
    let addr_idx = data_idx + 1;
    if args.len() > addr_idx {
        if let Some(ref display) = args[addr_idx].display {
            if let Some((host, port)) = parse_socket_address(display) {
                ni.host = Some(host);
                ni.port = Some(port);
            }
            args[addr_idx].display = Some(format!("address={}", display));
        }
    }
    ni
}

/// Format socket.recvfrom(bufsize) arguments.
fn format_socket_recvfrom(args: &mut [Argument]) {
    // Skip 'self'
    let bufsize_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > bufsize_idx {
        if let Some(ref display) = args[bufsize_idx].display {
            args[bufsize_idx].display = Some(format!("bufsize={}", display));
        }
    }
}

/// Format socket.setsockopt(level, optname, value) arguments.
fn format_socket_setsockopt(args: &mut [Argument]) {
    // Skip 'self'
    let level_idx = if args.len() > 1 { 1 } else { 0 };

    // level
    if args.len() > level_idx {
        if let Some(level) = parse_int_from_repr(&args[level_idx].display) {
            args[level_idx].display = Some(format_socket_level(level));
        }
    }
    // optname
    let opt_idx = level_idx + 1;
    if args.len() > opt_idx {
        let level = args
            .get(level_idx)
            .and_then(|a| parse_int_from_repr(&a.display))
            .unwrap_or(0);
        if let Some(optname) = parse_int_from_repr(&args[opt_idx].display) {
            args[opt_idx].display = Some(format_socket_option(level, optname));
        }
    }
    // value stays as-is
}

/// Format socket.getsockopt(level, optname) arguments.
fn format_socket_getsockopt(args: &mut [Argument]) {
    format_socket_setsockopt(args); // Same format for first two args
}

/// Format socket.shutdown(how) arguments.
fn format_socket_shutdown(args: &mut [Argument]) {
    // Skip 'self'
    let how_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > how_idx {
        if let Some(how) = parse_int_from_repr(&args[how_idx].display) {
            args[how_idx].display = Some(format_shutdown_how(how));
        }
    }
}

/// Format socket.getaddrinfo(host, port, family, type) arguments.
fn format_socket_getaddrinfo(args: &mut [Argument]) -> NetworkInfo {
    let mut ni = NetworkInfo::default();
    // arg0: host
    if !args.is_empty() {
        if let Some(ref display) = args[0].display {
            let host = display.trim_matches('\'').trim_matches('"');
            if !host.is_empty() && host != "None" {
                ni.host = Some(host.to_string());
            }
            args[0].display = Some(format!("host={}", display));
        }
    }
    // arg1: port
    if args.len() > 1 {
        if let Some(ref display) = args[1].display {
            if let Ok(port) = display.trim().parse::<u16>() {
                ni.port = Some(port);
            }
            args[1].display = Some(format!("port={}", display));
        }
    }
    // arg2: family
    if args.len() > 2 {
        if let Some(family) = parse_int_from_repr(&args[2].display) {
            args[2].display = Some(format_address_family(family));
        }
    }
    // arg3: type
    if args.len() > 3 {
        if let Some(sock_type) = parse_int_from_repr(&args[3].display) {
            args[3].display = Some(format_socket_type(sock_type));
        }
    }
    ni
}

/// Format socket.gethostbyname(hostname) arguments.
fn format_socket_gethostbyname(args: &mut [Argument]) -> NetworkInfo {
    let mut ni = NetworkInfo::default();
    if !args.is_empty() {
        if let Some(ref display) = args[0].display {
            let host = display.trim_matches('\'').trim_matches('"');
            if !host.is_empty() {
                ni.host = Some(host.to_string());
            }
            args[0].display = Some(format!("hostname={}", display));
        }
    }
    ni
}

/// Format socket.create_connection(address, timeout) arguments.
fn format_socket_create_connection(args: &mut [Argument]) -> NetworkInfo {
    let mut ni = NetworkInfo {
        protocol: Some(Protocol::Tcp),
        ..Default::default()
    };
    // arg0: address (tuple)
    if !args.is_empty() {
        if let Some(ref display) = args[0].display {
            if let Some((host, port)) = parse_socket_address(display) {
                ni.host = Some(host);
                ni.port = Some(port);
            }
            args[0].display = Some(format!("address={}", display));
        }
    }
    // arg1: timeout
    if args.len() > 1 {
        if let Some(ref display) = args[1].display {
            args[1].display = Some(format!("timeout={}", display));
        }
    }
    ni
}

// =============================================================================
// SSL MODULE FORMATTERS
// =============================================================================

/// Format ssl.wrap_socket arguments.
fn format_ssl_wrap_socket(args: &mut [Argument]) -> NetworkInfo {
    let mut ni = NetworkInfo::default();
    // Look for server_hostname in kwargs or positional args
    for (i, arg) in args.iter_mut().enumerate() {
        if i == 0 {
            continue;
        }
        if let Some(ref display) = arg.display {
            if display.contains("server_hostname") || is_hostname_like(display) {
                let host = display.trim_matches('\'').trim_matches('"');
                ni.host = Some(host.to_string());
                arg.display = Some(format!("server_hostname={}", display));
                break;
            }
        }
    }
    ni
}

/// Format ssl.create_default_context arguments.
fn format_ssl_create_default_context(args: &mut [Argument]) {
    if !args.is_empty() {
        if let Some(ref display) = args[0].display {
            // Purpose enum value
            if display.contains("Purpose") || display.contains("SERVER_AUTH") {
                args[0].display = Some(format!("purpose={}", display));
            }
        }
    }
}

/// Format SSLContext.wrap_socket arguments.
fn format_ssl_context_wrap_socket(args: &mut [Argument]) -> NetworkInfo {
    let mut ni = NetworkInfo::default();
    let sock_idx = if args.len() > 1 { 1 } else { 0 };

    for (i, arg) in args.iter_mut().enumerate() {
        if i <= sock_idx {
            continue;
        }
        if let Some(ref display) = arg.display {
            if is_hostname_like(display) {
                let host = display.trim_matches('\'').trim_matches('"');
                ni.host = Some(host.to_string());
                arg.display = Some(format!("server_hostname={}", display));
                break;
            }
        }
    }
    ni
}

/// Format SSLContext.load_cert_chain arguments.
fn format_ssl_load_cert_chain(args: &mut [Argument]) {
    // Skip 'self'
    let cert_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > cert_idx {
        if let Some(ref display) = args[cert_idx].display {
            args[cert_idx].display = Some(format!("certfile={}", display));
        }
    }
    let key_idx = cert_idx + 1;
    if args.len() > key_idx {
        if let Some(ref display) = args[key_idx].display {
            args[key_idx].display = Some(format!("keyfile={}", display));
        }
    }
}

/// Format SSLContext.load_verify_locations arguments.
fn format_ssl_load_verify_locations(args: &mut [Argument]) {
    // Skip 'self'
    let ca_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > ca_idx {
        if let Some(ref display) = args[ca_idx].display {
            args[ca_idx].display = Some(format!("cafile={}", display));
        }
    }
}

// =============================================================================
// HTTP.CLIENT MODULE FORMATTERS
// =============================================================================

/// Format HTTPConnection/HTTPSConnection.__init__ arguments.
fn format_http_connection_init(args: &mut [Argument]) {
    // Skip 'self'
    let host_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > host_idx {
        if let Some(ref display) = args[host_idx].display {
            args[host_idx].display = Some(format!("host={}", display));
        }
    }
    let port_idx = host_idx + 1;
    if args.len() > port_idx {
        if let Some(ref display) = args[port_idx].display {
            args[port_idx].display = Some(format!("port={}", display));
        }
    }
    let timeout_idx = port_idx + 1;
    if args.len() > timeout_idx {
        if let Some(ref display) = args[timeout_idx].display {
            args[timeout_idx].display = Some(format!("timeout={}", display));
        }
    }
}

/// Format HTTPConnection.request arguments.
fn format_http_request(args: &mut [Argument]) {
    // Skip 'self'
    let method_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > method_idx {
        if let Some(ref display) = args[method_idx].display {
            args[method_idx].display = Some(format!("method={}", display.to_uppercase()));
        }
    }
    let url_idx = method_idx + 1;
    if args.len() > url_idx {
        if let Some(ref display) = args[url_idx].display {
            args[url_idx].display = Some(format!("url={}", truncate_url(display)));
        }
    }
    let body_idx = url_idx + 1;
    if args.len() > body_idx {
        if let Some(ref display) = args[body_idx].display {
            if display != "None" {
                let len = estimate_bytes_length(display);
                args[body_idx].display = Some(format!("body=<{} bytes>", len));
            }
        }
    }
}

/// Format HTTPResponse.read arguments.
fn format_http_response_read(args: &mut [Argument]) {
    // Skip 'self'
    let amt_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > amt_idx {
        if let Some(ref display) = args[amt_idx].display {
            if display == "None" {
                args[amt_idx].display = Some("amt=None (read all)".to_string());
            } else {
                args[amt_idx].display = Some(format!("amt={}", display));
            }
        }
    }
}

// =============================================================================
// URLLIB.REQUEST MODULE FORMATTERS
// =============================================================================

/// Format urllib.request.urlopen arguments.
fn format_urlopen(args: &mut [Argument]) {
    // arg0: url
    if !args.is_empty() {
        if let Some(ref display) = args[0].display {
            args[0].display = Some(format!("url={}", truncate_url(display)));
        }
    }
    // arg1: data
    if args.len() > 1 {
        if let Some(ref display) = args[1].display {
            if display != "None" {
                let len = estimate_bytes_length(display);
                args[1].display = Some(format!("data=<{} bytes>", len));
            }
        }
    }
    // arg2: timeout
    if args.len() > 2 {
        if let Some(ref display) = args[2].display {
            if display != "None" {
                args[2].display = Some(format!("timeout={}", display));
            }
        }
    }
}

/// Format urllib.request.Request.__init__ arguments.
fn format_urllib_request_init(args: &mut [Argument]) {
    // Skip 'self'
    let url_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > url_idx {
        if let Some(ref display) = args[url_idx].display {
            args[url_idx].display = Some(format!("url={}", truncate_url(display)));
        }
    }
    // data
    let data_idx = url_idx + 1;
    if args.len() > data_idx {
        if let Some(ref display) = args[data_idx].display {
            if display != "None" {
                let len = estimate_bytes_length(display);
                args[data_idx].display = Some(format!("data=<{} bytes>", len));
            }
        }
    }
}

/// Format OpenerDirector.open arguments.
fn format_opener_open(args: &mut [Argument]) {
    // Skip 'self'
    let url_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > url_idx {
        if let Some(ref display) = args[url_idx].display {
            args[url_idx].display = Some(format!("url={}", truncate_url(display)));
        }
    }
}

// =============================================================================
// REQUESTS LIBRARY FORMATTERS
// =============================================================================

/// Format requests.get(url, params, ...) arguments.
fn format_requests_get(args: &mut [Argument]) {
    // arg0: url (or self, url)
    let url_idx = find_url_arg_index(args);
    if let Some(idx) = url_idx {
        if let Some(ref display) = args[idx].display {
            args[idx].display = Some(format!("url={}", truncate_url(display)));
        }
    }
    // Look for params, timeout, headers
    format_requests_common_kwargs(args, url_idx.unwrap_or(0) + 1);
}

/// Format requests.post(url, data, json, ...) arguments.
fn format_requests_post(args: &mut [Argument]) {
    let url_idx = find_url_arg_index(args);
    if let Some(idx) = url_idx {
        if let Some(ref display) = args[idx].display {
            args[idx].display = Some(format!("url={}", truncate_url(display)));
        }
    }
    let start_idx = url_idx.unwrap_or(0) + 1;
    // data or json arg
    if args.len() > start_idx {
        if let Some(ref display) = args[start_idx].display {
            if display.starts_with('{') || display.starts_with('[') {
                args[start_idx].display = Some(format!("json={}", truncate_json(display)));
            } else if display != "None" {
                args[start_idx].display = Some(format!("data={}", truncate_data_preview(display)));
            }
        }
    }
    format_requests_common_kwargs(args, start_idx + 1);
}

/// Format generic requests method (put, delete, etc.).
fn format_requests_method(args: &mut [Argument]) {
    let url_idx = find_url_arg_index(args);
    if let Some(idx) = url_idx {
        if let Some(ref display) = args[idx].display {
            args[idx].display = Some(format!("url={}", truncate_url(display)));
        }
    }
    format_requests_common_kwargs(args, url_idx.unwrap_or(0) + 1);
}

/// Format requests.request(method, url, ...) arguments.
fn format_requests_request(args: &mut [Argument]) {
    // Skip 'self' if present
    let method_idx = if args
        .first()
        .and_then(|a| a.display.as_ref())
        .map(|d| d.starts_with('<'))
        .unwrap_or(false)
    {
        1
    } else {
        0
    };

    if args.len() > method_idx {
        if let Some(ref display) = args[method_idx].display {
            args[method_idx].display = Some(format!("method={}", display.to_uppercase()));
        }
    }
    let url_idx = method_idx + 1;
    if args.len() > url_idx {
        if let Some(ref display) = args[url_idx].display {
            args[url_idx].display = Some(format!("url={}", truncate_url(display)));
        }
    }
    format_requests_common_kwargs(args, url_idx + 1);
}

/// Format common kwargs for requests methods.
fn format_requests_common_kwargs(args: &mut [Argument], start_idx: usize) {
    for arg in args.iter_mut().skip(start_idx) {
        if let Some(ref display) = arg.display {
            // Try to identify parameter type from value
            if display.starts_with('{') && display.contains(':') {
                // Could be params, headers, or json
                if display.len() < 50 && !display.contains("'Content-Type'") {
                    arg.display = Some(format!("params={}", display));
                }
            } else if display.parse::<f64>().is_ok() || display.ends_with(')') {
                // Likely timeout
                arg.display = Some(format!("timeout={}", display));
            }
        }
    }
}

/// Format Response.iter_content arguments.
fn format_response_iter_content(args: &mut [Argument]) {
    // Skip 'self'
    let chunk_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > chunk_idx {
        if let Some(ref display) = args[chunk_idx].display {
            args[chunk_idx].display = Some(format!("chunk_size={}", display));
        }
    }
}

// =============================================================================
// URLLIB3 LIBRARY FORMATTERS
// =============================================================================

/// Format PoolManager.request arguments.
fn format_urllib3_request(args: &mut [Argument]) {
    // Skip 'self'
    let method_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > method_idx {
        if let Some(ref display) = args[method_idx].display {
            args[method_idx].display = Some(format!("method={}", display.to_uppercase()));
        }
    }
    let url_idx = method_idx + 1;
    if args.len() > url_idx {
        if let Some(ref display) = args[url_idx].display {
            args[url_idx].display = Some(format!("url={}", truncate_url(display)));
        }
    }
}

/// Format HTTPConnectionPool.__init__ arguments.
fn format_urllib3_pool_init(args: &mut [Argument]) {
    // Skip 'self'
    let host_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > host_idx {
        if let Some(ref display) = args[host_idx].display {
            args[host_idx].display = Some(format!("host={}", display));
        }
    }
    let port_idx = host_idx + 1;
    if args.len() > port_idx {
        if let Some(ref display) = args[port_idx].display {
            args[port_idx].display = Some(format!("port={}", display));
        }
    }
}

/// Format HTTPConnectionPool.urlopen arguments.
fn format_urllib3_urlopen(args: &mut [Argument]) {
    // Skip 'self'
    let method_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > method_idx {
        if let Some(ref display) = args[method_idx].display {
            args[method_idx].display = Some(format!("method={}", display.to_uppercase()));
        }
    }
    let url_idx = method_idx + 1;
    if args.len() > url_idx {
        if let Some(ref display) = args[url_idx].display {
            args[url_idx].display = Some(format!("url={}", truncate_url(display)));
        }
    }
}

// =============================================================================
// HTTPX LIBRARY FORMATTERS
// =============================================================================

/// Format httpx.get arguments.
fn format_httpx_get(args: &mut [Argument]) {
    let url_idx = find_url_arg_index(args);
    if let Some(idx) = url_idx {
        if let Some(ref display) = args[idx].display {
            args[idx].display = Some(format!("url={}", truncate_url(display)));
        }
    }
    format_httpx_common_kwargs(args, url_idx.unwrap_or(0) + 1);
}

/// Format httpx.post arguments.
fn format_httpx_post(args: &mut [Argument]) {
    let url_idx = find_url_arg_index(args);
    if let Some(idx) = url_idx {
        if let Some(ref display) = args[idx].display {
            args[idx].display = Some(format!("url={}", truncate_url(display)));
        }
    }
    let start_idx = url_idx.unwrap_or(0) + 1;
    if args.len() > start_idx {
        if let Some(ref display) = args[start_idx].display {
            if display.starts_with('{') || display.starts_with('[') {
                args[start_idx].display = Some(format!("json={}", truncate_json(display)));
            } else if display != "None" {
                args[start_idx].display = Some(format!("data={}", truncate_data_preview(display)));
            }
        }
    }
    format_httpx_common_kwargs(args, start_idx + 1);
}

/// Format httpx.request arguments.
fn format_httpx_request(args: &mut [Argument]) {
    let method_idx = if args
        .first()
        .and_then(|a| a.display.as_ref())
        .map(|d| d.starts_with('<'))
        .unwrap_or(false)
    {
        1
    } else {
        0
    };

    if args.len() > method_idx {
        if let Some(ref display) = args[method_idx].display {
            args[method_idx].display = Some(format!("method={}", display.to_uppercase()));
        }
    }
    let url_idx = method_idx + 1;
    if args.len() > url_idx {
        if let Some(ref display) = args[url_idx].display {
            args[url_idx].display = Some(format!("url={}", truncate_url(display)));
        }
    }
    format_httpx_common_kwargs(args, url_idx + 1);
}

/// Format generic httpx method.
fn format_httpx_method(args: &mut [Argument]) {
    format_httpx_get(args);
}

/// Format common httpx kwargs.
fn format_httpx_common_kwargs(args: &mut [Argument], start_idx: usize) {
    for arg in args.iter_mut().skip(start_idx) {
        if let Some(ref display) = arg.display {
            if display.parse::<f64>().is_ok() {
                arg.display = Some(format!("timeout={}", display));
            }
        }
    }
}

// =============================================================================
// AIOHTTP LIBRARY FORMATTERS
// =============================================================================

/// Format aiohttp ClientSession request.
fn format_aiohttp_request(args: &mut [Argument]) {
    let url_idx = find_url_arg_index(args);
    if let Some(idx) = url_idx {
        if let Some(ref display) = args[idx].display {
            args[idx].display = Some(format!("url={}", truncate_url(display)));
        }
    }
}

/// Format aiohttp ClientSession.post.
fn format_aiohttp_post(args: &mut [Argument]) {
    let url_idx = find_url_arg_index(args);
    if let Some(idx) = url_idx {
        if let Some(ref display) = args[idx].display {
            args[idx].display = Some(format!("url={}", truncate_url(display)));
        }
    }
    let start_idx = url_idx.unwrap_or(0) + 1;
    if args.len() > start_idx {
        if let Some(ref display) = args[start_idx].display {
            if display.starts_with('{') || display.starts_with('[') {
                args[start_idx].display = Some(format!("json={}", truncate_json(display)));
            } else if display != "None" {
                args[start_idx].display = Some(format!("data={}", truncate_data_preview(display)));
            }
        }
    }
}

/// Format aiohttp ClientSession.request(method, url).
fn format_aiohttp_request_method(args: &mut [Argument]) {
    // Skip 'self'
    let method_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > method_idx {
        if let Some(ref display) = args[method_idx].display {
            args[method_idx].display = Some(format!("method={}", display.to_uppercase()));
        }
    }
    let url_idx = method_idx + 1;
    if args.len() > url_idx {
        if let Some(ref display) = args[url_idx].display {
            args[url_idx].display = Some(format!("url={}", truncate_url(display)));
        }
    }
}

/// Format aiohttp ws_connect.
fn format_aiohttp_ws_connect(args: &mut [Argument]) {
    // Skip 'self'
    let url_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > url_idx {
        if let Some(ref display) = args[url_idx].display {
            args[url_idx].display = Some(format!("url={}", truncate_url(display)));
        }
    }
}

/// Format aiohttp TCPConnector.__init__.
fn format_aiohttp_connector_init(args: &mut [Argument]) {
    for arg in args.iter_mut().skip(1) {
        // Skip 'self'
        if let Some(ref display) = arg.display {
            if display.parse::<i32>().is_ok() {
                arg.display = Some(format!("limit={}", display));
                break;
            }
        }
    }
}

// =============================================================================
// DNS.RESOLVER FORMATTERS
// =============================================================================

/// Format dns.resolver.resolve/query arguments.
fn format_dns_resolver_resolve(args: &mut [Argument]) {
    // Could have 'self' or not
    let qname_idx = if args
        .first()
        .and_then(|a| a.display.as_ref())
        .map(|d| d.starts_with('<'))
        .unwrap_or(false)
    {
        1
    } else {
        0
    };

    if args.len() > qname_idx {
        if let Some(ref display) = args[qname_idx].display {
            args[qname_idx].display = Some(format!("qname={}", display));
        }
    }
    let rdtype_idx = qname_idx + 1;
    if args.len() > rdtype_idx {
        if let Some(ref display) = args[rdtype_idx].display {
            args[rdtype_idx].display = Some(format!("rdtype={}", display));
        }
    }
}

// =============================================================================
// WEBSOCKET FORMATTERS
// =============================================================================

/// Format websockets.connect arguments.
fn format_websocket_connect(args: &mut [Argument]) {
    if !args.is_empty() {
        if let Some(ref display) = args[0].display {
            args[0].display = Some(format!("uri={}", truncate_url(display)));
        }
    }
}

/// Format websockets.serve arguments.
fn format_websocket_serve(args: &mut [Argument]) {
    // handler, host, port
    if args.len() > 1 {
        if let Some(ref display) = args[1].display {
            args[1].display = Some(format!("host={}", display));
        }
    }
    if args.len() > 2 {
        if let Some(ref display) = args[2].display {
            args[2].display = Some(format!("port={}", display));
        }
    }
}

/// Format websocket-client connect.
fn format_websocket_client_connect(args: &mut [Argument]) {
    // Skip 'self'
    let url_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > url_idx {
        if let Some(ref display) = args[url_idx].display {
            args[url_idx].display = Some(format!("url={}", truncate_url(display)));
        }
    }
}

/// Format WebSocket.send arguments.
fn format_websocket_send(args: &mut [Argument]) {
    // Skip 'self'
    let data_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > data_idx {
        if let Some(ref display) = args[data_idx].display {
            let preview = truncate_data_preview(display);
            args[data_idx].display = Some(format!("data={}", preview));
        }
    }
}

// =============================================================================
// NETWORK-INFO-RETURNING FORMATTER WRAPPERS
// =============================================================================
// These functions call the display-only formatters AND build NetworkInfo.

/// Format HTTPConnection.__init__ with NetworkInfo.
fn format_http_connection_init_net(args: &mut [Argument], scheme: &str) -> NetworkInfo {
    format_http_connection_init(args);
    let mut ni = NetworkInfo {
        protocol: Some(Protocol::from(scheme)),
        ..Default::default()
    };
    let host_idx = if args.len() > 1 { 1 } else { 0 };
    if args.len() > host_idx {
        if let Some(ref display) = args[host_idx].display {
            // display is "host='example.com'" — extract the value
            let val = display.strip_prefix("host=").unwrap_or(display);
            let host = val.trim_matches('\'').trim_matches('"');
            if !host.is_empty() {
                ni.host = Some(host.to_string());
            }
        }
    }
    let port_idx = host_idx + 1;
    if args.len() > port_idx {
        if let Some(ref display) = args[port_idx].display {
            let val = display.strip_prefix("port=").unwrap_or(display);
            if let Ok(port) = val.trim().parse::<u16>() {
                ni.port = Some(port);
            }
        }
    }
    if ni.port.is_none() {
        ni.port = match scheme {
            "http" => Some(80),
            "https" => Some(443),
            _ => None,
        };
    }
    ni
}

/// Format HTTPConnection.request with NetworkInfo.
fn format_http_request_net(args: &mut [Argument], module: &str) -> NetworkInfo {
    format_http_request(args);
    let mut ni = NetworkInfo::default();
    // Skip method arg, extract url/path
    let method_idx = if args.len() > 1 { 1 } else { 0 };
    // Extract url/path
    let url_idx = method_idx + 1;
    if args.len() > url_idx {
        if let Some(ref display) = args[url_idx].display {
            let val = display.strip_prefix("url=").unwrap_or(display);
            let path = clean_url_from_display(val);
            // The path is relative — the host comes from the connection object.
            // We can still store the path as partial URL info.
            if !path.is_empty() {
                ni.url = Some(path.to_string());
            }
        }
    }
    // Infer protocol from class name
    ni.protocol = if module.contains("HTTPS") {
        Some(Protocol::Https)
    } else {
        Some(Protocol::Http)
    };
    ni
}

/// Format urllib.request.urlopen with NetworkInfo.
fn format_urlopen_net(args: &mut [Argument]) -> NetworkInfo {
    // Extract URL before formatting (formatting modifies display)
    let url_raw = args.first().and_then(|a| a.display.clone());
    format_urlopen(args);
    if let Some(raw) = url_raw {
        let url = clean_url_from_display(&raw);
        if url.contains("://") {
            let mut ni = network_info_from_url(url);
            ni.url = Some(url.to_string());
            return ni;
        }
    }
    NetworkInfo::default()
}

/// Format urllib.request.Request.__init__ with NetworkInfo.
fn format_urllib_request_init_net(args: &mut [Argument]) -> NetworkInfo {
    let url_idx = if args.len() > 1 { 1 } else { 0 };
    let url_raw = args.get(url_idx).and_then(|a| a.display.clone());
    format_urllib_request_init(args);
    if let Some(raw) = url_raw {
        let url = clean_url_from_display(&raw);
        if url.contains("://") {
            return network_info_from_url(url);
        }
    }
    NetworkInfo::default()
}

/// Format OpenerDirector.open with NetworkInfo.
fn format_opener_open_net(args: &mut [Argument]) -> NetworkInfo {
    let url_idx = if args.len() > 1 { 1 } else { 0 };
    let url_raw = args.get(url_idx).and_then(|a| a.display.clone());
    format_opener_open(args);
    if let Some(raw) = url_raw {
        let url = clean_url_from_display(&raw);
        if url.contains("://") {
            return network_info_from_url(url);
        }
    }
    NetworkInfo::default()
}

/// Extract URL from args, build NetworkInfo with method, then call display formatter.
fn url_network_info_from_args(args: &[Argument], _method: Option<&str>) -> Option<NetworkInfo> {
    let url_idx = find_url_arg_index(args)?;
    let raw = args[url_idx].display.as_ref()?;
    let url = clean_url_from_display(raw);
    if !url.contains("://") {
        return None;
    }
    let ni = network_info_from_url(url);
    Some(ni)
}

/// Format requests.get with NetworkInfo.
fn format_requests_get_net(args: &mut [Argument], method: Option<&str>) -> Option<NetworkInfo> {
    let ni = url_network_info_from_args(args, method);
    format_requests_get(args);
    ni
}

/// Format requests.post with NetworkInfo.
fn format_requests_post_net(args: &mut [Argument], method: Option<&str>) -> Option<NetworkInfo> {
    let ni = url_network_info_from_args(args, method);
    format_requests_post(args);
    ni
}

/// Format requests generic method with NetworkInfo.
fn format_requests_method_net(args: &mut [Argument], method: Option<&str>) -> Option<NetworkInfo> {
    let ni = url_network_info_from_args(args, method);
    format_requests_method(args);
    ni
}

/// Format requests.request with NetworkInfo.
fn format_requests_request_net(args: &mut [Argument]) -> Option<NetworkInfo> {
    // Extract method before formatting
    let method_idx = if args
        .first()
        .and_then(|a| a.display.as_ref())
        .map(|d| d.starts_with('<'))
        .unwrap_or(false)
    {
        1
    } else {
        0
    };
    let url_idx = method_idx + 1;
    let url_raw = args.get(url_idx).and_then(|a| a.display.clone());
    format_requests_request(args);

    if let Some(raw) = url_raw {
        let url = clean_url_from_display(&raw);
        if url.contains("://") {
            let ni = network_info_from_url(url);
            return Some(ni);
        }
    }
    None
}

/// Format urllib3 PoolManager.request with NetworkInfo.
fn format_urllib3_request_net(args: &mut [Argument]) -> Option<NetworkInfo> {
    // method at idx 1 (skip self), url at idx 2
    let method_idx = if args.len() > 1 { 1 } else { 0 };
    let _method = args.get(method_idx).and_then(|a| a.display.clone());
    let url_idx = method_idx + 1;
    let url_raw = args.get(url_idx).and_then(|a| a.display.clone());
    format_urllib3_request(args);

    if let Some(raw) = url_raw {
        let url = clean_url_from_display(&raw);
        if url.contains("://") {
            let ni = network_info_from_url(url);
            return Some(ni);
        }
    }
    None
}

/// Format urllib3 HTTPConnectionPool.urlopen with NetworkInfo.
fn format_urllib3_urlopen_net(args: &mut [Argument]) -> Option<NetworkInfo> {
    let method_idx = if args.len() > 1 { 1 } else { 0 };
    let _method = args.get(method_idx).and_then(|a| a.display.clone());
    let url_idx = method_idx + 1;
    let url_raw = args.get(url_idx).and_then(|a| a.display.clone());
    format_urllib3_urlopen(args);

    let mut ni = NetworkInfo::default();
    if let Some(raw) = url_raw {
        let url = clean_url_from_display(&raw);
        if url.contains("://") {
            ni = network_info_from_url(url);
            return non_empty_network_info(ni);
        }
        // Relative URL path — just store it
        ni.url = Some(url.to_string());
    }
    non_empty_network_info(ni)
}

/// Format httpx.get with NetworkInfo.
fn format_httpx_get_net(args: &mut [Argument], method: Option<&str>) -> Option<NetworkInfo> {
    let ni = url_network_info_from_args(args, method);
    format_httpx_get(args);
    ni
}

/// Format httpx.post with NetworkInfo.
fn format_httpx_post_net(args: &mut [Argument], method: Option<&str>) -> Option<NetworkInfo> {
    let ni = url_network_info_from_args(args, method);
    format_httpx_post(args);
    ni
}

/// Format httpx generic method with NetworkInfo.
fn format_httpx_method_net(args: &mut [Argument], method: Option<&str>) -> Option<NetworkInfo> {
    let ni = url_network_info_from_args(args, method);
    format_httpx_method(args);
    ni
}

/// Format httpx.request with NetworkInfo.
fn format_httpx_request_net(args: &mut [Argument]) -> Option<NetworkInfo> {
    let method_idx = if args
        .first()
        .and_then(|a| a.display.as_ref())
        .map(|d| d.starts_with('<'))
        .unwrap_or(false)
    {
        1
    } else {
        0
    };
    let _method = args.get(method_idx).and_then(|a| a.display.clone());
    let url_idx = method_idx + 1;
    let url_raw = args.get(url_idx).and_then(|a| a.display.clone());
    format_httpx_request(args);

    if let Some(raw) = url_raw {
        let url = clean_url_from_display(&raw);
        if url.contains("://") {
            let ni = network_info_from_url(url);
            return Some(ni);
        }
    }
    None
}

/// Format aiohttp request with NetworkInfo.
fn format_aiohttp_request_net(args: &mut [Argument], method: Option<&str>) -> Option<NetworkInfo> {
    let ni = url_network_info_from_args(args, method);
    format_aiohttp_request(args);
    ni
}

/// Format aiohttp post with NetworkInfo.
fn format_aiohttp_post_net(args: &mut [Argument], method: Option<&str>) -> Option<NetworkInfo> {
    let ni = url_network_info_from_args(args, method);
    format_aiohttp_post(args);
    ni
}

/// Format aiohttp request_method with NetworkInfo.
fn format_aiohttp_request_method_net(args: &mut [Argument]) -> Option<NetworkInfo> {
    let method_idx = if args.len() > 1 { 1 } else { 0 };
    let _method = args.get(method_idx).and_then(|a| a.display.clone());
    let url_idx = method_idx + 1;
    let url_raw = args.get(url_idx).and_then(|a| a.display.clone());
    format_aiohttp_request_method(args);

    if let Some(raw) = url_raw {
        let url = clean_url_from_display(&raw);
        if url.contains("://") {
            let ni = network_info_from_url(url);
            return Some(ni);
        }
    }
    None
}

/// Format aiohttp ws_connect with NetworkInfo.
fn format_aiohttp_ws_connect_net(args: &mut [Argument]) -> Option<NetworkInfo> {
    let url_idx = if args.len() > 1 { 1 } else { 0 };
    let url_raw = args.get(url_idx).and_then(|a| a.display.clone());
    format_aiohttp_ws_connect(args);

    if let Some(raw) = url_raw {
        let url = clean_url_from_display(&raw);
        if url.contains("://") {
            return Some(network_info_from_url(url));
        }
    }
    None
}

/// Format dns.resolver.resolve with NetworkInfo.
fn format_dns_resolver_resolve_net(args: &mut [Argument]) -> NetworkInfo {
    let mut ni = NetworkInfo::default();
    // Extract qname before formatting
    let qname_idx = if args
        .first()
        .and_then(|a| a.display.as_ref())
        .map(|d| d.starts_with('<'))
        .unwrap_or(false)
    {
        1
    } else {
        0
    };
    if let Some(display) = args.get(qname_idx).and_then(|a| a.display.as_ref()) {
        let host = display.trim_matches('\'').trim_matches('"');
        if !host.is_empty() {
            ni.host = Some(host.to_string());
        }
    }
    format_dns_resolver_resolve(args);
    ni
}

/// Format websockets.connect with NetworkInfo.
fn format_websocket_connect_net(args: &mut [Argument]) -> Option<NetworkInfo> {
    let url_raw = args.first().and_then(|a| a.display.clone());
    format_websocket_connect(args);
    if let Some(raw) = url_raw {
        let url = clean_url_from_display(&raw);
        if url.contains("://") {
            return Some(network_info_from_url(url));
        }
    }
    None
}

/// Format websocket-client connect with NetworkInfo.
fn format_websocket_client_connect_net(args: &mut [Argument]) -> Option<NetworkInfo> {
    let url_idx = if args.len() > 1 { 1 } else { 0 };
    let url_raw = args.get(url_idx).and_then(|a| a.display.clone());
    format_websocket_client_connect(args);
    if let Some(raw) = url_raw {
        let url = clean_url_from_display(&raw);
        if url.contains("://") {
            return Some(network_info_from_url(url));
        }
    }
    None
}

// =============================================================================
// SUBPROCESS / OS MODULE FORMATTERS
// =============================================================================

/// Format subprocess.run/call/check_call/check_output/Popen arguments.
/// These functions take `args` as the first positional argument, which can be
/// a list like ['curl', '-X', 'POST'] or a string command.
fn format_subprocess_args(args: &mut [Argument]) {
    if args.is_empty() {
        return;
    }

    if let Some(ref display) = args[0].display {
        // Check if it's a list repr like ['curl', '-X', 'POST']
        if display.starts_with('[') && display.ends_with(']') {
            if let Some(cmd) = parse_python_list_to_shell_command(display) {
                args[0].display = Some(format!("cmd={}", cmd));
                return;
            }
        }
        // If it's a string command, just label it
        args[0].display = Some(format!("cmd={}", truncate_data_preview(display)));
    }
}

/// Format os.system(command) arguments.
fn format_os_system(args: &mut [Argument]) {
    if !args.is_empty() {
        if let Some(ref display) = args[0].display {
            args[0].display = Some(format!("cmd={}", truncate_data_preview(display)));
        }
    }
}

/// Format os.execv/execve/execvp/execvpe(path, args) arguments.
fn format_os_exec(args: &mut [Argument]) {
    // arg0: path
    if !args.is_empty() {
        if let Some(ref display) = args[0].display {
            args[0].display = Some(format!("path={}", display));
        }
    }
    // arg1: args list
    if args.len() > 1 {
        if let Some(ref display) = args[1].display {
            if display.starts_with('[') && display.ends_with(']') {
                if let Some(cmd) = parse_python_list_to_shell_command(display) {
                    args[1].display = Some(format!("cmd={}", cmd));
                    return;
                }
            }
            args[1].display = Some(format!("args={}", truncate_data_preview(display)));
        }
    }
}

/// Format os.spawnv/spawnve/spawnl/etc arguments.
fn format_os_spawn(args: &mut [Argument]) {
    // arg0: mode
    if !args.is_empty() {
        if let Some(mode) = parse_int_from_repr(&args[0].display) {
            args[0].display = Some(format_spawn_mode(mode));
        }
    }
    // arg1: path
    if args.len() > 1 {
        if let Some(ref display) = args[1].display {
            args[1].display = Some(format!("path={}", display));
        }
    }
    // arg2: args list
    if args.len() > 2 {
        if let Some(ref display) = args[2].display {
            if display.starts_with('[') && display.ends_with(']') {
                if let Some(cmd) = parse_python_list_to_shell_command(display) {
                    args[2].display = Some(format!("cmd={}", cmd));
                    return;
                }
            }
            args[2].display = Some(format!("args={}", truncate_data_preview(display)));
        }
    }
}

/// Format os.popen(cmd) arguments.
fn format_os_popen(args: &mut [Argument]) {
    if !args.is_empty() {
        if let Some(ref display) = args[0].display {
            args[0].display = Some(format!("cmd={}", truncate_data_preview(display)));
        }
    }
    // Optional mode argument
    if args.len() > 1 {
        if let Some(ref display) = args[1].display {
            args[1].display = Some(format!("mode={}", display));
        }
    }
}

/// Format spawn mode constant.
fn format_spawn_mode(mode: i32) -> String {
    match mode {
        0 => "P_WAIT".to_string(),
        1 => "P_NOWAIT".to_string(),
        2 => "P_NOWAITO".to_string(),
        4 => "P_DETACH".to_string(),
        _ => format!("mode={}", mode),
    }
}

/// Parse a Python list repr like ['curl', '-X', 'POST'] into a shell command.
/// Returns None if parsing fails.
fn parse_python_list_to_shell_command(list_repr: &str) -> Option<String> {
    // Strip the outer brackets
    let inner = list_repr.strip_prefix('[')?.strip_suffix(']')?;

    if inner.is_empty() {
        return Some(String::new());
    }

    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut string_char = '"';
    let mut escape_next = false;

    for c in inner.chars() {
        if escape_next {
            current.push(c);
            escape_next = false;
            continue;
        }

        match c {
            '\\' if in_string => {
                escape_next = true;
            }
            '"' | '\'' if !in_string => {
                in_string = true;
                string_char = c;
            }
            c if in_string && c == string_char => {
                in_string = false;
                // Don't add the quote itself - we're extracting the content
            }
            ',' if !in_string => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    parts.push(trimmed);
                }
                current.clear();
            }
            _ if in_string => {
                current.push(c);
            }
            _ => {
                // Skip whitespace outside of strings
                if !c.is_whitespace() {
                    current.push(c);
                }
            }
        }
    }

    // Don't forget the last element
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        parts.push(trimmed);
    }

    if parts.is_empty() {
        return Some(String::new());
    }

    // Convert to shell command with proper quoting
    Some(format_args_as_shell_command(&parts))
}

/// Characters that require quoting in shell arguments.
const SHELL_SPECIAL_CHARS: &[char] = &[
    ' ', '\t', '\n', '"', '\'', '\\', '$', '`', '!', '*', '?', '[', ']', '#', '~', '=', '%', '|',
    '&', ';', '<', '>', '(', ')', '{', '}', '^',
];

/// Format arguments as a shell command with proper quoting.
fn format_args_as_shell_command(args: &[String]) -> String {
    args.iter()
        .map(|arg| quote_shell_arg(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Quote a shell argument if needed.
fn quote_shell_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }

    let needs_quoting = arg.chars().any(|c| SHELL_SPECIAL_CHARS.contains(&c));

    if !needs_quoting {
        return arg.to_string();
    }

    // Prefer single quotes if the argument doesn't contain them
    if !arg.contains('\'') {
        return format!("'{}'", arg);
    }

    // Use double quotes with escaping
    let escaped: String = arg
        .chars()
        .map(|c| match c {
            '"' | '\\' | '$' | '`' => format!("\\{}", c),
            _ => c.to_string(),
        })
        .collect();

    format!("\"{}\"", escaped)
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Parse an integer from a Python repr string.
/// Handles formats like "2", "<AddressFamily.AF_INET: 2>", etc.
fn parse_int_from_repr(display: &Option<String>) -> Option<i32> {
    let s = display.as_ref()?;

    // Try direct parse first
    if let Ok(n) = s.trim().parse::<i32>() {
        return Some(n);
    }

    // Try to extract from enum repr like "<AddressFamily.AF_INET: 2>"
    if let Some(colon_idx) = s.rfind(':') {
        let after_colon = s[colon_idx + 1..].trim().trim_end_matches('>');
        if let Ok(n) = after_colon.parse::<i32>() {
            return Some(n);
        }
    }

    None
}

/// Format socket address family constant.
fn format_address_family(family: i32) -> String {
    match family {
        0 => "AF_UNSPEC".to_string(),
        1 => "AF_UNIX".to_string(),
        2 => "AF_INET".to_string(),
        10 => "AF_INET6".to_string(),  // Linux
        30 => "AF_INET6".to_string(),  // macOS
        17 => "AF_PACKET".to_string(), // Linux raw
        _ => format!("family={}", family),
    }
}

/// Format socket type constant.
fn format_socket_type(sock_type: i32) -> String {
    let base_type = sock_type & 0xf;
    let type_str = match base_type {
        1 => "SOCK_STREAM",
        2 => "SOCK_DGRAM",
        3 => "SOCK_RAW",
        5 => "SOCK_SEQPACKET",
        _ => return format!("type={}", sock_type),
    };

    // Check for flags
    let mut parts = vec![type_str];
    if sock_type & 0x80000 != 0 {
        parts.push("SOCK_CLOEXEC");
    }
    if sock_type & 0x800 != 0 {
        parts.push("SOCK_NONBLOCK");
    }

    parts.join("|")
}

/// Format socket level constant.
fn format_socket_level(level: i32) -> String {
    match level {
        0 => "IPPROTO_IP".to_string(),
        1 => "SOL_SOCKET".to_string(), // Linux
        6 => "IPPROTO_TCP".to_string(),
        17 => "IPPROTO_UDP".to_string(),
        0xffff => "SOL_SOCKET".to_string(), // macOS
        _ => format!("level={}", level),
    }
}

/// Format socket option constant.
fn format_socket_option(level: i32, optname: i32) -> String {
    // SOL_SOCKET options (values differ between Linux and macOS)
    if level == 1 || level == 0xffff {
        #[cfg(target_os = "linux")]
        {
            return match optname {
                2 => "SO_REUSEADDR".to_string(),
                9 => "SO_KEEPALIVE".to_string(),
                15 => "SO_REUSEPORT".to_string(),
                7 => "SO_SNDBUF".to_string(),
                8 => "SO_RCVBUF".to_string(),
                _ => format!("optname={}", optname),
            };
        }
        #[cfg(target_os = "macos")]
        {
            return match optname {
                0x0004 => "SO_REUSEADDR".to_string(),
                0x0008 => "SO_KEEPALIVE".to_string(),
                0x0200 => "SO_REUSEPORT".to_string(),
                0x1001 => "SO_SNDBUF".to_string(),
                0x1002 => "SO_RCVBUF".to_string(),
                _ => format!("optname={}", optname),
            };
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            return format!("optname={}", optname);
        }
    }

    // IPPROTO_TCP options
    if level == 6 {
        return match optname {
            1 => "TCP_NODELAY".to_string(),
            _ => format!("optname={}", optname),
        };
    }

    format!("optname={}", optname)
}

/// Format shutdown how constant.
fn format_shutdown_how(how: i32) -> String {
    match how {
        0 => "SHUT_RD".to_string(),
        1 => "SHUT_WR".to_string(),
        2 => "SHUT_RDWR".to_string(),
        _ => format!("how={}", how),
    }
}

/// Truncate URL for display.
fn truncate_url(url: &str) -> String {
    let clean = url.trim_matches('\'').trim_matches('"');
    if clean.len() > MAX_URL_LEN {
        format!("'{}'...", &clean[..MAX_URL_LEN - 3])
    } else {
        url.to_string()
    }
}

/// Truncate data/bytes preview.
fn truncate_data_preview(data: &str) -> String {
    if data.len() > MAX_DATA_PREVIEW {
        format!("{}...", &data[..MAX_DATA_PREVIEW])
    } else {
        data.to_string()
    }
}

/// Truncate JSON for display.
fn truncate_json(json: &str) -> String {
    truncate_data_preview(json)
}

/// Estimate byte length from repr string.
fn estimate_bytes_length(repr: &str) -> usize {
    // For b'...' or bytes, count characters (rough estimate)
    if repr.starts_with("b'") || repr.starts_with("b\"") {
        repr.len().saturating_sub(3) // Remove b' and trailing '
    } else {
        repr.len()
    }
}

/// Check if string looks like a hostname.
fn is_hostname_like(s: &str) -> bool {
    let clean = s.trim_matches('\'').trim_matches('"');
    clean.contains('.') && !clean.starts_with('{') && !clean.starts_with('[')
}

/// Find index of URL argument (skip 'self' if present).
fn find_url_arg_index(args: &[Argument]) -> Option<usize> {
    if args.is_empty() {
        return None;
    }

    // Check if first arg looks like 'self' (object repr starts with '<')
    if let Some(ref display) = args[0].display {
        if display.starts_with('<') && display.contains(" object at ") {
            return if args.len() > 1 { Some(1) } else { None };
        }
    }

    // First arg that looks like a URL
    for (i, arg) in args.iter().enumerate() {
        if let Some(ref display) = arg.display {
            let clean = display.trim_matches('\'').trim_matches('"');
            if clean.starts_with("http://")
                || clean.starts_with("https://")
                || clean.starts_with("wss://")
                || clean.starts_with("ws://")
            {
                return Some(i);
            }
        }
    }

    // Default to first non-self arg
    if args.len() > 1
        && args[0]
            .display
            .as_ref()
            .map(|d| d.starts_with('<'))
            .unwrap_or(false)
    {
        Some(1)
    } else {
        Some(0)
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_args(displays: &[&str]) -> Vec<Argument> {
        displays
            .iter()
            .map(|&d| Argument {
                raw_value: 0,
                display: Some(d.to_string()),
            })
            .collect()
    }

    #[test]
    fn test_parse_int_from_repr() {
        assert_eq!(parse_int_from_repr(&Some("2".to_string())), Some(2));
        assert_eq!(
            parse_int_from_repr(&Some("<AddressFamily.AF_INET: 2>".to_string())),
            Some(2)
        );
        assert_eq!(
            parse_int_from_repr(&Some("<SocketKind.SOCK_STREAM: 1>".to_string())),
            Some(1)
        );
        assert_eq!(parse_int_from_repr(&Some("hello".to_string())), None);
        assert_eq!(parse_int_from_repr(&None), None);
    }

    #[test]
    fn test_format_address_family() {
        assert_eq!(format_address_family(2), "AF_INET");
        assert_eq!(format_address_family(1), "AF_UNIX");
        assert_eq!(format_address_family(10), "AF_INET6");
        assert_eq!(format_address_family(30), "AF_INET6");
        assert_eq!(format_address_family(99), "family=99");
    }

    #[test]
    fn test_format_socket_type() {
        assert_eq!(format_socket_type(1), "SOCK_STREAM");
        assert_eq!(format_socket_type(2), "SOCK_DGRAM");
        assert_eq!(format_socket_type(3), "SOCK_RAW");
    }

    #[test]
    fn test_format_socket_socket() {
        let mut args = make_args(&["2", "1", "0"]);
        format_socket_socket(&mut args);

        assert_eq!(args[0].display, Some("AF_INET".to_string()));
        assert_eq!(args[1].display, Some("SOCK_STREAM".to_string()));
        assert_eq!(args[2].display, Some("proto=0".to_string()));
    }

    #[test]
    fn test_format_socket_socket_enum_repr() {
        let mut args = make_args(&[
            "<AddressFamily.AF_INET: 2>",
            "<SocketKind.SOCK_STREAM: 1>",
            "0",
        ]);
        format_socket_socket(&mut args);

        assert_eq!(args[0].display, Some("AF_INET".to_string()));
        assert_eq!(args[1].display, Some("SOCK_STREAM".to_string()));
        assert_eq!(args[2].display, Some("proto=0".to_string()));
    }

    #[test]
    fn test_format_shutdown_how() {
        assert_eq!(format_shutdown_how(0), "SHUT_RD");
        assert_eq!(format_shutdown_how(1), "SHUT_WR");
        assert_eq!(format_shutdown_how(2), "SHUT_RDWR");
        assert_eq!(format_shutdown_how(99), "how=99");
    }

    #[test]
    fn test_truncate_url() {
        let short = "'https://example.com'";
        assert_eq!(truncate_url(short), short);

        let long = format!("'https://example.com/{}'", "x".repeat(100));
        let truncated = truncate_url(&long);
        assert!(truncated.len() <= MAX_URL_LEN + 10); // Account for quotes and ...
        assert!(truncated.ends_with("..."));
    }

    #[test]
    fn test_format_requests_get() {
        let mut args = make_args(&["'https://api.example.com/data'"]);
        format_requests_get(&mut args);

        assert_eq!(
            args[0].display,
            Some("url='https://api.example.com/data'".to_string())
        );
    }

    #[test]
    fn test_format_requests_get_with_self() {
        let mut args = make_args(&[
            "<requests.sessions.Session object at 0x...>",
            "'https://api.example.com/data'",
        ]);
        format_requests_get(&mut args);

        assert_eq!(
            args[1].display,
            Some("url='https://api.example.com/data'".to_string())
        );
    }

    #[test]
    fn test_format_python_arguments_socket() {
        let mut args = make_args(&["2", "1", "0"]);
        format_python_arguments("socket.socket", &mut args);

        assert_eq!(args[0].display, Some("AF_INET".to_string()));
        assert_eq!(args[1].display, Some("SOCK_STREAM".to_string()));
    }

    #[test]
    fn test_format_python_arguments_requests_get() {
        let mut args = make_args(&["'https://httpbin.org/get'"]);
        format_python_arguments("requests.get", &mut args);

        assert_eq!(
            args[0].display,
            Some("url='https://httpbin.org/get'".to_string())
        );
    }

    #[test]
    fn test_format_python_arguments_unknown() {
        let mut args = make_args(&["arg1", "arg2"]);
        let original = args.clone();
        format_python_arguments("some.unknown.function", &mut args);

        // Unknown functions should not modify arguments
        assert_eq!(args[0].display, original[0].display);
        assert_eq!(args[1].display, original[1].display);
    }

    #[test]
    fn test_format_socket_level() {
        assert_eq!(format_socket_level(1), "SOL_SOCKET");
        assert_eq!(format_socket_level(0xffff), "SOL_SOCKET");
        assert_eq!(format_socket_level(6), "IPPROTO_TCP");
        assert_eq!(format_socket_level(17), "IPPROTO_UDP");
    }

    #[test]
    fn test_format_socket_option() {
        // SOL_SOCKET options - values differ by platform
        #[cfg(target_os = "linux")]
        {
            assert_eq!(format_socket_option(1, 2), "SO_REUSEADDR");
            assert_eq!(format_socket_option(1, 9), "SO_KEEPALIVE");
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(format_socket_option(0xffff, 0x0004), "SO_REUSEADDR");
            assert_eq!(format_socket_option(0xffff, 0x0008), "SO_KEEPALIVE");
        }
        // TCP_NODELAY is the same on both platforms
        assert_eq!(format_socket_option(6, 1), "TCP_NODELAY");
    }

    #[test]
    fn test_find_url_arg_index() {
        let args = make_args(&["'https://example.com'"]);
        assert_eq!(find_url_arg_index(&args), Some(0));

        let args_with_self = make_args(&["<Session object at 0x123>", "'https://example.com'"]);
        assert_eq!(find_url_arg_index(&args_with_self), Some(1));
    }

    #[test]
    fn test_estimate_bytes_length() {
        assert_eq!(estimate_bytes_length("b'hello'"), 5);
        assert_eq!(estimate_bytes_length("hello"), 5);
    }

    #[test]
    fn test_format_dns_resolver() {
        let mut args = make_args(&["'example.com'", "'A'"]);
        format_python_arguments("dns.resolver.resolve", &mut args);

        assert_eq!(args[0].display, Some("qname='example.com'".to_string()));
        assert_eq!(args[1].display, Some("rdtype='A'".to_string()));
    }

    #[test]
    fn test_parse_python_list_to_shell_command() {
        // Simple command
        let result = parse_python_list_to_shell_command("['curl', '--version']");
        assert_eq!(result, Some("curl --version".to_string()));

        // Command with spaces in argument
        let result = parse_python_list_to_shell_command("['echo', 'hello world']");
        assert_eq!(result, Some("echo 'hello world'".to_string()));

        // Command with double-quoted strings in Python repr
        let result = parse_python_list_to_shell_command(r#"["curl", "-X", "POST"]"#);
        assert_eq!(result, Some("curl -X POST".to_string()));

        // Empty list
        let result = parse_python_list_to_shell_command("[]");
        assert_eq!(result, Some("".to_string()));
    }

    #[test]
    fn test_format_subprocess_run() {
        let mut args = make_args(&["['curl', '-X', 'POST', 'https://example.com']"]);
        format_python_arguments("subprocess.run", &mut args);

        assert_eq!(
            args[0].display,
            Some("cmd=curl -X POST https://example.com".to_string())
        );
    }

    #[test]
    fn test_format_subprocess_popen() {
        let mut args = make_args(&["['ls', '-la']"]);
        format_python_arguments("subprocess.Popen", &mut args);

        assert_eq!(args[0].display, Some("cmd=ls -la".to_string()));
    }

    #[test]
    fn test_format_os_system() {
        let mut args = make_args(&["'curl https://example.com'"]);
        format_python_arguments("os.system", &mut args);

        assert_eq!(
            args[0].display,
            Some("cmd='curl https://example.com'".to_string())
        );
    }

    #[test]
    fn test_format_os_execv() {
        let mut args = make_args(&["'/usr/bin/curl'", "['curl', '--version']"]);
        format_python_arguments("os.execv", &mut args);

        assert_eq!(args[0].display, Some("path='/usr/bin/curl'".to_string()));
        assert_eq!(args[1].display, Some("cmd=curl --version".to_string()));
    }

    #[test]
    fn test_format_spawn_mode() {
        assert_eq!(format_spawn_mode(0), "P_WAIT");
        assert_eq!(format_spawn_mode(1), "P_NOWAIT");
        assert_eq!(format_spawn_mode(99), "mode=99");
    }

    // =====================================================================
    // NetworkInfo tests
    // =====================================================================

    #[test]
    fn test_network_info_from_url() {
        let ni = network_info_from_url("https://example.com/path");
        assert_eq!(ni.url.as_deref(), Some("https://example.com/path"));
        assert_eq!(ni.host.as_deref(), Some("example.com"));
        assert_eq!(ni.port, Some(443));
        assert_eq!(ni.protocol.as_ref().map(|p| p.as_str()), Some("https"));

        let ni = network_info_from_url("http://api.example.com:8080/data");
        assert_eq!(ni.host.as_deref(), Some("api.example.com"));
        assert_eq!(ni.port, Some(8080));
        assert_eq!(ni.protocol.as_ref().map(|p| p.as_str()), Some("http"));
    }

    #[test]
    fn test_network_info_from_url_websocket() {
        let ni = network_info_from_url("wss://ws.example.com/chat");
        assert_eq!(ni.host.as_deref(), Some("ws.example.com"));
        assert_eq!(ni.port, Some(443));
        assert_eq!(ni.protocol.as_ref().map(|p| p.as_str()), Some("wss"));
    }

    #[test]
    fn test_network_info_from_url_quoted() {
        let ni = network_info_from_url("'https://example.com'");
        assert_eq!(ni.url.as_deref(), Some("https://example.com"));
        assert_eq!(ni.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_parse_socket_address() {
        assert_eq!(
            parse_socket_address("('127.0.0.1', 80)"),
            Some(("127.0.0.1".to_string(), 80))
        );
        assert_eq!(
            parse_socket_address("('example.com', 443)"),
            Some(("example.com".to_string(), 443))
        );
        assert_eq!(parse_socket_address("invalid"), None);
        assert_eq!(parse_socket_address("('', 80)"), None);
    }

    #[test]
    fn test_format_python_arguments_socket_returns_network_info() {
        let mut args = make_args(&["2", "1", "0"]);
        let ni = format_python_arguments("socket.socket", &mut args);
        let ni = ni.unwrap();
        assert_eq!(ni.protocol.as_ref().map(|p| p.as_str()), Some("tcp"));
    }

    #[test]
    fn test_format_python_arguments_socket_connect_returns_network_info() {
        let mut args = make_args(&["<socket>", "('10.0.0.1', 8080)"]);
        let ni = format_python_arguments("socket.connect", &mut args);
        let ni = ni.unwrap();
        assert_eq!(ni.host.as_deref(), Some("10.0.0.1"));
        assert_eq!(ni.port, Some(8080));
        assert_eq!(ni.protocol.as_ref().map(|p| p.as_str()), Some("tcp"));
    }

    #[test]
    fn test_format_python_arguments_requests_get_returns_network_info() {
        let mut args = make_args(&["'https://httpbin.org/get'"]);
        let ni = format_python_arguments("requests.get", &mut args);
        let ni = ni.unwrap();
        assert_eq!(ni.url.as_deref(), Some("https://httpbin.org/get"));
        assert_eq!(ni.host.as_deref(), Some("httpbin.org"));
        assert_eq!(ni.protocol.as_ref().map(|p| p.as_str()), Some("https"));
    }

    #[test]
    fn test_format_python_arguments_requests_post_returns_network_info() {
        let mut args = make_args(&["'https://api.example.com/data'", "'{\"key\": 1}'"]);
        let ni = format_python_arguments("requests.post", &mut args);
        let ni = ni.unwrap();
        assert_eq!(ni.host.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn test_format_python_arguments_urlopen_returns_network_info() {
        let mut args = make_args(&["'https://example.com/page'"]);
        let ni = format_python_arguments("urllib.request.urlopen", &mut args);
        let ni = ni.unwrap();
        assert_eq!(ni.url.as_deref(), Some("https://example.com/page"));
        assert_eq!(ni.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_format_python_arguments_dns_returns_network_info() {
        let mut args = make_args(&["'example.com'", "'A'"]);
        let ni = format_python_arguments("dns.resolver.resolve", &mut args);
        let ni = ni.unwrap();
        assert_eq!(ni.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_format_python_arguments_websocket_returns_network_info() {
        let mut args = make_args(&["'wss://ws.example.com/chat'"]);
        let ni = format_python_arguments("websockets.connect", &mut args);
        let ni = ni.unwrap();
        assert_eq!(ni.url.as_deref(), Some("wss://ws.example.com/chat"));
        assert_eq!(ni.protocol.as_ref().map(|p| p.as_str()), Some("wss"));
    }

    #[test]
    fn test_format_python_arguments_unknown_returns_none() {
        let mut args = make_args(&["arg1", "arg2"]);
        let ni = format_python_arguments("some.unknown.function", &mut args);
        assert!(ni.is_none());
    }

    #[test]
    fn test_format_python_arguments_getaddrinfo_returns_network_info() {
        let mut args = make_args(&["'example.com'", "443", "2", "1"]);
        let ni = format_python_arguments("socket.getaddrinfo", &mut args);
        let ni = ni.unwrap();
        assert_eq!(ni.host.as_deref(), Some("example.com"));
        assert_eq!(ni.port, Some(443));
    }

    #[test]
    fn test_format_python_arguments_sendto_returns_network_info() {
        let mut args = make_args(&["<socket>", "b'hello'", "('8.8.8.8', 53)"]);
        let ni = format_python_arguments("socket.sendto", &mut args);
        let ni = ni.unwrap();
        assert_eq!(ni.host.as_deref(), Some("8.8.8.8"));
        assert_eq!(ni.port, Some(53));
        assert_eq!(ni.protocol.as_ref().map(|p| p.as_str()), Some("udp"));
    }

    #[test]
    fn test_format_python_arguments_http_connection_init_returns_network_info() {
        let mut args = make_args(&["<self>", "'example.com'", "8080"]);
        let ni = format_python_arguments("http.client.HTTPSConnection.__init__", &mut args);
        let ni = ni.unwrap();
        assert_eq!(ni.host.as_deref(), Some("example.com"));
        assert_eq!(ni.port, Some(8080));
        assert_eq!(ni.protocol.as_ref().map(|p| p.as_str()), Some("https"));
    }
}
