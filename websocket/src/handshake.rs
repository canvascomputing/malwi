use std::collections::HashMap;

use crate::{Error, Result};

const WS_VERSION: &str = "13";
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#[derive(Debug, Clone, Copy)]
pub struct HandshakeParseConfig {
    pub max_bytes: usize,
    pub max_headers: usize,
    pub max_line_len: usize,
}

impl Default for HandshakeParseConfig {
    fn default() -> Self {
        Self {
            max_bytes: 16 * 1024,
            max_headers: 64,
            max_line_len: 4096,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeHeaders {
    inner: HashMap<String, String>,
}

impl HandshakeHeaders {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.inner
            .insert(name.into().to_ascii_lowercase(), value.into());
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.inner
            .get(&name.to_ascii_lowercase())
            .map(std::string::String::as_str)
    }

    pub fn get_required(&self, name: &'static str) -> Result<&str> {
        self.get(name)
            .ok_or(Error::InvalidHandshake("required header missing"))
    }

    pub fn tokens_contains(&self, name: &'static str, token: &'static str) -> bool {
        self.get(name)
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .any(|candidate| candidate.eq_ignore_ascii_case(token))
            })
            .unwrap_or(false)
    }
}

impl Default for HandshakeHeaders {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeRequest {
    pub method: String,
    pub path: String,
    pub version: u8,
    pub headers: HandshakeHeaders,
}

impl HandshakeRequest {
    pub fn validate_client_request(&self) -> Result<()> {
        if !self.method.eq_ignore_ascii_case("GET") {
            return Err(Error::InvalidHandshake(
                "handshake request method must be GET",
            ));
        }

        if self.version < 1 {
            return Err(Error::InvalidHandshake("HTTP/1.1 or higher required"));
        }

        if !self.headers.tokens_contains("connection", "Upgrade") {
            return Err(Error::InvalidHandshake(
                "Connection header must contain Upgrade token",
            ));
        }

        let upgrade = self.headers.get_required("upgrade")?;
        if !upgrade.eq_ignore_ascii_case("websocket") {
            return Err(Error::InvalidHandshake("Upgrade header must be websocket"));
        }

        let version = self.headers.get_required("sec-websocket-version")?;
        if version.trim() != WS_VERSION {
            return Err(Error::InvalidHandshake("Sec-WebSocket-Version must be 13"));
        }

        let key = self.headers.get_required("sec-websocket-key")?;
        validate_websocket_key(key)?;

        Ok(())
    }

    pub fn websocket_key(&self) -> Result<&str> {
        self.headers.get_required("sec-websocket-key")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHandshakeRequest {
    pub host: String,
    pub path: String,
    pub key: String,
    pub origin: Option<String>,
    pub protocols: Vec<String>,
    pub extensions: Vec<String>,
}

impl ClientHandshakeRequest {
    pub fn validate(&self) -> Result<()> {
        if self.host.trim().is_empty() {
            return Err(Error::InvalidHandshake("Host must be set"));
        }

        if self.path.trim().is_empty() {
            return Err(Error::InvalidHandshake("path must be set"));
        }

        validate_websocket_key(&self.key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHandshakeResponse {
    pub status: u16,
    pub reason: String,
    pub headers: HandshakeHeaders,
}

impl ClientHandshakeResponse {
    pub fn validate_server_response(&self, expected_key: &str) -> Result<()> {
        if self.status != 101 {
            return Err(Error::InvalidHandshake("status code must be 101"));
        }

        if !self.headers.tokens_contains("connection", "Upgrade") {
            return Err(Error::InvalidHandshake(
                "Connection header must contain Upgrade token",
            ));
        }

        let upgrade = self.headers.get_required("upgrade")?;
        if !upgrade.eq_ignore_ascii_case("websocket") {
            return Err(Error::InvalidHandshake("Upgrade header must be websocket"));
        }

        let accept = self.headers.get_required("sec-websocket-accept")?;
        let expected = websocket_accept_key(expected_key);
        if accept.trim() != expected {
            return Err(Error::InvalidHandshake(
                "Sec-WebSocket-Accept mismatch in handshake response",
            ));
        }

        Ok(())
    }
}

pub fn websocket_accept_key(client_key: &str) -> String {
    let mut input = Vec::with_capacity(client_key.len() + WS_GUID.len());
    input.extend_from_slice(client_key.as_bytes());
    input.extend_from_slice(WS_GUID.as_bytes());
    base64_encode(&sha1_digest(&input))
}

pub fn build_client_handshake_request(req: &ClientHandshakeRequest) -> Result<Vec<u8>> {
    req.validate()?;

    let mut out = Vec::new();
    out.extend_from_slice(format!("GET {} HTTP/1.1\r\n", req.path).as_bytes());
    out.extend_from_slice(format!("Host: {}\r\n", req.host).as_bytes());
    out.extend_from_slice(b"Upgrade: websocket\r\n");
    out.extend_from_slice(b"Connection: Upgrade\r\n");
    out.extend_from_slice(format!("Sec-WebSocket-Key: {}\r\n", req.key).as_bytes());
    out.extend_from_slice(format!("Sec-WebSocket-Version: {}\r\n", WS_VERSION).as_bytes());

    if let Some(origin) = &req.origin {
        out.extend_from_slice(format!("Origin: {}\r\n", origin).as_bytes());
    }

    if !req.protocols.is_empty() {
        out.extend_from_slice(
            format!("Sec-WebSocket-Protocol: {}\r\n", req.protocols.join(", ")).as_bytes(),
        );
    }

    if !req.extensions.is_empty() {
        out.extend_from_slice(
            format!(
                "Sec-WebSocket-Extensions: {}\r\n",
                req.extensions.join(", ")
            )
            .as_bytes(),
        );
    }

    out.extend_from_slice(b"\r\n");
    Ok(out)
}

pub fn parse_client_handshake(data: &[u8]) -> Result<HandshakeRequest> {
    parse_client_handshake_with_len(data, HandshakeParseConfig::default()).map(|(req, _)| req)
}

pub fn parse_client_handshake_with_len(
    data: &[u8],
    config: HandshakeParseConfig,
) -> Result<(HandshakeRequest, usize)> {
    let (text, consumed) = parse_http_text(data, config)?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or(Error::InvalidHttp("missing request line"))?;
    if request_line.len() > config.max_line_len {
        return Err(Error::SizeLimitExceeded {
            category: "handshake request line",
            configured_max: config.max_line_len,
            actual: request_line.len(),
        });
    }

    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or(Error::InvalidHttp("missing method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or(Error::InvalidHttp("missing request path"))?
        .to_string();
    let version_str = parts
        .next()
        .ok_or(Error::InvalidHttp("missing HTTP version"))?;
    if parts.next().is_some() {
        return Err(Error::InvalidHttp("malformed request line"));
    }

    let version = parse_http_version(version_str)?;
    let headers = parse_headers(lines, config)?;

    let parsed = HandshakeRequest {
        method,
        path,
        version,
        headers,
    };
    parsed.validate_client_request()?;

    Ok((parsed, consumed))
}

pub fn parse_server_handshake_response(data: &[u8]) -> Result<ClientHandshakeResponse> {
    parse_server_handshake_response_with_len(data, HandshakeParseConfig::default())
        .map(|(res, _)| res)
}

pub fn parse_server_handshake_response_with_len(
    data: &[u8],
    config: HandshakeParseConfig,
) -> Result<(ClientHandshakeResponse, usize)> {
    let (text, consumed) = parse_http_text(data, config)?;
    let mut lines = text.split("\r\n");

    let status_line = lines
        .next()
        .ok_or(Error::InvalidHttp("missing status line"))?;
    if status_line.len() > config.max_line_len {
        return Err(Error::SizeLimitExceeded {
            category: "handshake status line",
            configured_max: config.max_line_len,
            actual: status_line.len(),
        });
    }

    let mut status_parts = status_line.split_whitespace();
    let version = status_parts
        .next()
        .ok_or(Error::InvalidHttp("missing HTTP version"))?;
    let _ = parse_http_version(version)?;

    let status = status_parts
        .next()
        .ok_or(Error::InvalidHttp("missing status code"))?
        .parse::<u16>()
        .map_err(|_| Error::InvalidHttp("invalid status code"))?;

    let reason = status_parts.collect::<Vec<&str>>().join(" ");
    let headers = parse_headers(lines, config)?;

    Ok((
        ClientHandshakeResponse {
            status,
            reason,
            headers,
        },
        consumed,
    ))
}

pub fn build_server_handshake_response(
    req: &HandshakeRequest,
    selected_protocol: Option<&str>,
    extra_headers: &[(&str, &str)],
) -> Result<Vec<u8>> {
    req.validate_client_request()?;

    let key = req.websocket_key()?;
    let accept = websocket_accept_key(key);

    let mut out = Vec::new();
    out.extend_from_slice(b"HTTP/1.1 101 Switching Protocols\r\n");
    out.extend_from_slice(b"Upgrade: websocket\r\n");
    out.extend_from_slice(b"Connection: Upgrade\r\n");
    out.extend_from_slice(format!("Sec-WebSocket-Accept: {}\r\n", accept).as_bytes());

    if let Some(protocol) = selected_protocol {
        out.extend_from_slice(format!("Sec-WebSocket-Protocol: {}\r\n", protocol).as_bytes());
    }

    for (name, value) in extra_headers {
        if name.contains(':') || name.contains('\r') || name.contains('\n') {
            return Err(Error::InvalidHeaderValue("invalid header name"));
        }

        if value.contains('\r') || value.contains('\n') {
            return Err(Error::InvalidHeaderValue("invalid header value"));
        }

        out.extend_from_slice(format!("{}: {}\r\n", name.trim(), value.trim()).as_bytes());
    }

    out.extend_from_slice(b"\r\n");
    Ok(out)
}

fn parse_http_text(data: &[u8], config: HandshakeParseConfig) -> Result<(&str, usize)> {
    let mut boundary = None;
    for i in 0..data.len().saturating_sub(3) {
        if &data[i..i + 4] == b"\r\n\r\n" {
            boundary = Some(i + 4);
            break;
        }
    }

    let consumed = boundary.ok_or(Error::Incomplete)?;
    if consumed > config.max_bytes {
        return Err(Error::SizeLimitExceeded {
            category: "handshake bytes",
            configured_max: config.max_bytes,
            actual: consumed,
        });
    }

    let text = std::str::from_utf8(&data[..consumed])?;
    Ok((text, consumed))
}

fn parse_http_version(input: &str) -> Result<u8> {
    if !input.starts_with("HTTP/1.") {
        return Err(Error::InvalidHttp("unsupported HTTP version"));
    }

    let minor = input
        .strip_prefix("HTTP/1.")
        .ok_or(Error::InvalidHttp("unsupported HTTP version"))?
        .parse::<u8>()
        .map_err(|_| Error::InvalidHttp("invalid HTTP version"))?;
    Ok(minor)
}

fn parse_headers<'a>(
    lines: impl Iterator<Item = &'a str>,
    config: HandshakeParseConfig,
) -> Result<HandshakeHeaders> {
    let mut headers = HandshakeHeaders::new();
    let mut count = 0usize;

    for line in lines {
        if line.is_empty() {
            break;
        }

        if line.len() > config.max_line_len {
            return Err(Error::SizeLimitExceeded {
                category: "handshake header line",
                configured_max: config.max_line_len,
                actual: line.len(),
            });
        }

        count += 1;
        if count > config.max_headers {
            return Err(Error::SizeLimitExceeded {
                category: "handshake headers",
                configured_max: config.max_headers,
                actual: count,
            });
        }

        let (name, value) = line
            .split_once(':')
            .ok_or(Error::InvalidHttp("malformed header"))?;
        headers.insert(name.trim(), value.trim());
    }

    Ok(headers)
}

fn validate_websocket_key(value: &str) -> Result<()> {
    let decoded = base64_decode(value.trim())
        .map_err(|_| Error::InvalidHandshake("invalid Sec-WebSocket-Key encoding"))?;

    if decoded.len() != 16 {
        return Err(Error::InvalidHandshake(
            "Sec-WebSocket-Key must decode to 16 bytes",
        ));
    }

    Ok(())
}

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);

    let mut idx = 0;
    while idx + 3 <= data.len() {
        let block = u32::from_be_bytes([0, data[idx], data[idx + 1], data[idx + 2]]);
        out.push(TABLE[((block >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((block >> 12) & 0x3F) as usize] as char);
        out.push(TABLE[((block >> 6) & 0x3F) as usize] as char);
        out.push(TABLE[(block & 0x3F) as usize] as char);
        idx += 3;
    }

    let rem = data.len() - idx;
    if rem == 1 {
        let block = (data[idx] as u32) << 16;
        out.push(TABLE[((block >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((block >> 12) & 0x3F) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let block = ((data[idx] as u32) << 16) | ((data[idx + 1] as u32) << 8);
        out.push(TABLE[((block >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((block >> 12) & 0x3F) as usize] as char);
        out.push(TABLE[((block >> 6) & 0x3F) as usize] as char);
        out.push('=');
    }

    out
}

fn base64_decode(input: &str) -> std::result::Result<Vec<u8>, ()> {
    if !input.len().is_multiple_of(4) {
        return Err(());
    }

    let mut out = Vec::with_capacity((input.len() / 4) * 3);
    for chunk in input.as_bytes().chunks(4) {
        let c0 = decode_char(chunk[0])? as u32;
        let c1 = decode_char(chunk[1])? as u32;

        let c2 = if chunk[2] == b'=' {
            64
        } else {
            decode_char(chunk[2])? as u32
        };

        let c3 = if chunk[3] == b'=' {
            64
        } else {
            decode_char(chunk[3])? as u32
        };

        let block = (c0 << 18)
            | (c1 << 12)
            | ((if c2 == 64 { 0 } else { c2 }) << 6)
            | (if c3 == 64 { 0 } else { c3 });

        out.push(((block >> 16) & 0xFF) as u8);
        if c2 != 64 {
            out.push(((block >> 8) & 0xFF) as u8);
        }
        if c3 != 64 {
            out.push((block & 0xFF) as u8);
        }
    }

    Ok(out)
}

fn decode_char(c: u8) -> std::result::Result<u8, ()> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(()),
    }
}

fn sha1_digest(input: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let mut msg = input.to_vec();
    let bit_len = (msg.len() as u64) * 8;
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            let base = i * 4;
            w[i] = u32::from_be_bytes([
                chunk[base],
                chunk[base + 1],
                chunk[base + 2],
                chunk[base + 3],
            ]);
        }

        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for (i, wi) in w.iter().enumerate().take(80) {
            let (f, k) = match i {
                0..=19 => (((b & c) | ((!b) & d)), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => (((b & c) | (b & d) | (c & d)), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

    #[test]
    fn accept_key_matches_rfc_example() {
        let accept = websocket_accept_key(SAMPLE_KEY);
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn parse_and_build_server_response_roundtrip() {
        let req = format!(
            "GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\r\n",
            SAMPLE_KEY
        );

        let (parsed, used) =
            parse_client_handshake_with_len(req.as_bytes(), HandshakeParseConfig::default())
                .expect("parse client request");
        assert_eq!(used, req.len());

        let response = build_server_handshake_response(&parsed, Some("chat"), &[])
            .expect("build server response");
        let parsed_response =
            parse_server_handshake_response(&response).expect("parse server response");

        parsed_response
            .validate_server_response(SAMPLE_KEY)
            .expect("response validation");
    }

    #[test]
    fn invalid_key_is_rejected() {
        let req = "GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: invalid\r\nSec-WebSocket-Version: 13\r\n\r\n";
        let err = parse_client_handshake(req.as_bytes()).expect_err("must fail");
        assert!(matches!(err, Error::InvalidHandshake(_)));
    }

    #[test]
    fn handshake_size_limit_enforced() {
        let req = format!(
            "GET /x HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\r\n",
            SAMPLE_KEY
        );

        let err = parse_client_handshake_with_len(
            req.as_bytes(),
            HandshakeParseConfig {
                max_bytes: 20,
                ..HandshakeParseConfig::default()
            },
        )
        .expect_err("must fail");
        assert!(matches!(err, Error::SizeLimitExceeded { .. }));
    }

    #[test]
    fn sha1_known_vector() {
        let digest = sha1_digest(b"abc");
        assert_eq!(base64_encode(&digest), "qZk+NkcGgWq6PiVxeFDCbJzQ2J0=");
    }

    #[test]
    fn base64_roundtrip() {
        let src = b"hello world";
        let enc = base64_encode(src);
        let dec = base64_decode(&enc).expect("decode");
        assert_eq!(dec, src);
    }
}
