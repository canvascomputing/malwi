//! Binary wire protocol for agent↔CLI communication.
//!
//! Three layers:
//! 1. **Framing** — length-prefixed TCP: `[4-byte BE length][payload]`
//! 2. **Codec trait** — abstraction for encoding/decoding messages
//! 3. **BinaryCodec** — default binary implementation (no JSON, no serde)
//!
//! The browser-facing WebSocket server (`ws_server.rs`) keeps JSON+WebSocket.
//! This module is used only for the agent↔CLI path.

use std::io::{self, Read, Write};

use crate::event::{
    Argument, ChildOperation, EventType, HookConfig, HookType, HostChildInfo, NetworkInfo,
    NodejsFrame, PythonFrame, RuntimeStack, TraceEvent,
};
use crate::message::{AgentMessage, CliMessage};
use crate::protocol::{
    ChildReconnectRequest, ConfigureRequest, ConfigureResponse, ModuleInfo, ReadyRequest,
    ReviewDecision, RuntimeInfoRequest, ShutdownRequest,
};

// =============================================================================
// Layer 1: Framing
// =============================================================================

/// Maximum message size: 64 MiB.
const MAX_FRAME_LEN: u32 = 64 * 1024 * 1024;

/// Write a length-prefixed frame: `[4-byte BE length][payload]`.
pub fn write_frame(stream: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let len = payload.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(payload)?;
    Ok(())
}

/// Read a length-prefixed frame: `[4-byte BE length][payload]`.
///
/// Returns the payload. Enforces `MAX_FRAME_LEN` to prevent OOM.
pub fn read_frame(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {} bytes", len),
        ));
    }
    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

// =============================================================================
// Layer 2: Codec Trait
// =============================================================================

/// Abstraction for message encoding/decoding.
///
/// Allows swapping the encoding format (binary, protobuf, msgpack, etc.)
/// without changing the transport layer.
pub trait Codec {
    fn encode_agent_msg(&self, msg: &AgentMessage, buf: &mut Vec<u8>);
    fn decode_agent_msg(&self, data: &[u8]) -> io::Result<AgentMessage>;
    fn encode_cli_msg(&self, msg: &CliMessage, buf: &mut Vec<u8>);
    fn decode_cli_msg(&self, data: &[u8]) -> io::Result<CliMessage>;
}

// =============================================================================
// Layer 3: BinaryCodec
// =============================================================================

/// Binary codec: zero-size, stateless.
pub struct BinaryCodec;

// -- Message type tags --
const TAG_CONFIGURE: u8 = 0x01;
const TAG_READY: u8 = 0x02;
const TAG_RUNTIME: u8 = 0x03;
const TAG_EVENT: u8 = 0x04;
const TAG_EVENTS: u8 = 0x05;
const TAG_CHILD: u8 = 0x06;
const TAG_RECONNECT: u8 = 0x07;
const TAG_REVIEW: u8 = 0x08;
const TAG_SHUTDOWN: u8 = 0x09;

const TAG_CONFIGURE_RESPONSE: u8 = 0x81;
const TAG_REVIEW_RESPONSE: u8 = 0x82;

impl Codec for BinaryCodec {
    fn encode_agent_msg(&self, msg: &AgentMessage, buf: &mut Vec<u8>) {
        let mut w = WireWriter(buf);
        match msg {
            AgentMessage::Configure(req) => {
                w.put_u8(TAG_CONFIGURE);
                w.put_u32(req.pid);
                w.put_opt_u32(req.nodejs_version);
            }
            AgentMessage::Ready(req) => {
                w.put_u8(TAG_READY);
                w.put_u32(req.pid);
                w.put_vec(&req.hooks_installed, |w, s| w.put_str(s));
                w.put_opt_u32(req.nodejs_version);
                w.put_opt_str(req.python_version.as_deref());
                w.put_opt_str(req.bash_version.as_deref());
                w.put_vec(&req.modules, |w, m| {
                    w.put_str(&m.name);
                    w.put_str(&m.path);
                    w.put_u64(m.base_address);
                    w.put_u64(m.size);
                });
            }
            AgentMessage::Runtime(req) => {
                w.put_u8(TAG_RUNTIME);
                w.put_u32(req.pid);
                w.put_str(&req.runtime);
                w.put_str(&req.version);
            }
            AgentMessage::Event(event) => {
                w.put_u8(TAG_EVENT);
                encode_trace_event(&mut w, event);
            }
            AgentMessage::Events(events) => {
                w.put_u8(TAG_EVENTS);
                w.put_u32(events.len() as u32);
                for event in events {
                    encode_trace_event(&mut w, event);
                }
            }
            AgentMessage::Child(info) => {
                w.put_u8(TAG_CHILD);
                encode_child_info(&mut w, info);
            }
            AgentMessage::Reconnect(req) => {
                w.put_u8(TAG_RECONNECT);
                w.put_u32(req.parent_pid);
                w.put_u32(req.child_pid);
            }
            AgentMessage::Review { request_id, event } => {
                w.put_u8(TAG_REVIEW);
                w.put_u32(*request_id);
                encode_trace_event(&mut w, event);
            }
            AgentMessage::Shutdown(req) => {
                w.put_u8(TAG_SHUTDOWN);
                w.put_u32(req.pid);
            }
        }
    }

    fn decode_agent_msg(&self, data: &[u8]) -> io::Result<AgentMessage> {
        let mut r = WireReader::new(data);
        let tag = r.get_u8()?;
        match tag {
            TAG_CONFIGURE => {
                let pid = r.get_u32()?;
                let nodejs_version = r.get_opt_u32()?;
                Ok(AgentMessage::Configure(ConfigureRequest {
                    pid,
                    nodejs_version,
                }))
            }
            TAG_READY => {
                let pid = r.get_u32()?;
                let hooks_installed = r.get_vec(|r| r.get_string())?;
                let nodejs_version = r.get_opt_u32()?;
                let python_version = r.get_opt_string()?;
                let bash_version = r.get_opt_string()?;
                let modules = r.get_vec(|r| {
                    let name = r.get_string()?;
                    let path = r.get_string()?;
                    let base_address = r.get_u64()?;
                    let size = r.get_u64()?;
                    Ok(ModuleInfo {
                        name,
                        path,
                        base_address,
                        size,
                    })
                })?;
                Ok(AgentMessage::Ready(ReadyRequest {
                    pid,
                    hooks_installed,
                    nodejs_version,
                    python_version,
                    bash_version,
                    modules,
                }))
            }
            TAG_RUNTIME => {
                let pid = r.get_u32()?;
                let runtime = r.get_string()?;
                let version = r.get_string()?;
                Ok(AgentMessage::Runtime(RuntimeInfoRequest {
                    pid,
                    runtime,
                    version,
                }))
            }
            TAG_EVENT => {
                let event = decode_trace_event(&mut r)?;
                Ok(AgentMessage::Event(event))
            }
            TAG_EVENTS => {
                let count = r.get_u32()?;
                let mut events = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    events.push(decode_trace_event(&mut r)?);
                }
                Ok(AgentMessage::Events(events))
            }
            TAG_CHILD => {
                let info = decode_child_info(&mut r)?;
                Ok(AgentMessage::Child(info))
            }
            TAG_RECONNECT => {
                let parent_pid = r.get_u32()?;
                let child_pid = r.get_u32()?;
                Ok(AgentMessage::Reconnect(ChildReconnectRequest {
                    parent_pid,
                    child_pid,
                }))
            }
            TAG_REVIEW => {
                let request_id = r.get_u32()?;
                let event = decode_trace_event(&mut r)?;
                Ok(AgentMessage::Review { request_id, event })
            }
            TAG_SHUTDOWN => {
                let pid = r.get_u32()?;
                Ok(AgentMessage::Shutdown(ShutdownRequest { pid }))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown agent message tag: 0x{:02x}", tag),
            )),
        }
    }

    fn encode_cli_msg(&self, msg: &CliMessage, buf: &mut Vec<u8>) {
        let mut w = WireWriter(buf);
        match msg {
            CliMessage::ConfigureResponse(resp) => {
                w.put_u8(TAG_CONFIGURE_RESPONSE);
                w.put_vec(&resp.hooks, |w, h| {
                    encode_hook_type(w, &h.hook_type);
                    w.put_str(&h.symbol);
                    w.put_opt_u64(h.arg_count.map(|n| n as u64));
                    w.put_bool(h.capture_return);
                    w.put_bool(h.capture_stack);
                });
                w.put_bool(resp.review_mode);
                w.put_vec(&resp.envvar_allow_patterns, |w, p| {
                    w.put_str(p);
                });
            }
            CliMessage::ReviewResponse {
                request_id,
                decision,
            } => {
                w.put_u8(TAG_REVIEW_RESPONSE);
                w.put_u32(*request_id);
                encode_review_decision(&mut w, decision);
            }
        }
    }

    fn decode_cli_msg(&self, data: &[u8]) -> io::Result<CliMessage> {
        let mut r = WireReader::new(data);
        let tag = r.get_u8()?;
        match tag {
            TAG_CONFIGURE_RESPONSE => {
                let hooks = r.get_vec(|r| {
                    let hook_type = decode_hook_type(r)?;
                    let symbol = r.get_string()?;
                    let arg_count = r.get_opt_u64()?.map(|n| n as usize);
                    let capture_return = r.get_bool()?;
                    let capture_stack = r.get_bool()?;
                    Ok(HookConfig {
                        hook_type,
                        symbol,
                        arg_count,
                        capture_return,
                        capture_stack,
                    })
                })?;
                let review_mode = r.get_bool()?;
                let envvar_allow_patterns = r.get_vec(|r| r.get_string())?;
                Ok(CliMessage::ConfigureResponse(ConfigureResponse {
                    hooks,
                    review_mode,
                    envvar_allow_patterns,
                }))
            }
            TAG_REVIEW_RESPONSE => {
                let request_id = r.get_u32()?;
                let decision = decode_review_decision(&mut r)?;
                Ok(CliMessage::ReviewResponse {
                    request_id,
                    decision,
                })
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown CLI message tag: 0x{:02x}", tag),
            )),
        }
    }
}

// =============================================================================
// TraceEvent encoding/decoding
// =============================================================================

fn encode_trace_event(w: &mut WireWriter, event: &TraceEvent) {
    encode_hook_type(w, &event.hook_type);
    encode_event_type(w, &event.event_type);
    w.put_str(&event.function);
    w.put_vec(&event.arguments, |w, arg| {
        w.put_u64(arg.raw_value as u64);
        w.put_opt_str(arg.display.as_deref());
    });
    // native_stack: Vec<usize> as Vec<u64>
    w.put_u32(event.native_stack.len() as u32);
    for &addr in &event.native_stack {
        w.put_u64(addr as u64);
    }
    encode_opt_runtime_stack(w, &event.runtime_stack);
    encode_opt_network_info(w, &event.network_info);
    w.put_opt_str(event.source_file.as_deref());
    w.put_opt_u32(event.source_line);
    w.put_opt_u32(event.source_column);
    w.put_u64(event.timestamp_ns);
    // seq, source, category, disposition are CLI-only — not sent on wire
}

fn decode_trace_event(r: &mut WireReader) -> io::Result<TraceEvent> {
    let hook_type = decode_hook_type(r)?;
    let event_type = decode_event_type(r)?;
    let function = r.get_string()?;
    let arguments = r.get_vec(|r| {
        let raw_value = r.get_u64()? as usize;
        let display = r.get_opt_string()?;
        Ok(Argument { raw_value, display })
    })?;
    let stack_count = r.get_u32()? as usize;
    let mut native_stack = Vec::with_capacity(stack_count);
    for _ in 0..stack_count {
        native_stack.push(r.get_u64()? as usize);
    }
    let runtime_stack = decode_opt_runtime_stack(r)?;
    let network_info = decode_opt_network_info(r)?;
    let source_file = r.get_opt_string()?;
    let source_line = r.get_opt_u32()?;
    let source_column = r.get_opt_u32()?;
    let timestamp_ns = r.get_u64()?;
    Ok(TraceEvent {
        hook_type,
        event_type,
        function,
        arguments,
        native_stack,
        runtime_stack,
        network_info,
        source_file,
        source_line,
        source_column,
        timestamp_ns,
        // CLI-only fields default to zero/None
        seq: 0,
        source: None,
        category: None,
        disposition: None,
    })
}

// =============================================================================
// HostChildInfo encoding/decoding
// =============================================================================

fn encode_child_info(w: &mut WireWriter, info: &HostChildInfo) {
    w.put_u32(info.parent_pid);
    w.put_u32(info.child_pid);
    encode_child_operation(w, info.operation);
    w.put_opt_str(info.path.as_deref());
    // argv: Option<Vec<String>>
    match &info.argv {
        None => w.put_u8(0),
        Some(argv) => {
            w.put_u8(1);
            w.put_vec(argv, |w, s| w.put_str(s));
        }
    }
    // native_stack
    w.put_u32(info.native_stack.len() as u32);
    for &addr in &info.native_stack {
        w.put_u64(addr as u64);
    }
    w.put_opt_str(info.source_file.as_deref());
    w.put_opt_u32(info.source_line);
    w.put_opt_u32(info.source_column);
    encode_opt_runtime_stack(w, &info.runtime_stack);
    // hook_type: Option<HookType> — 0 = None, 1+ = Some(type+1)
    match &info.hook_type {
        None => w.put_u8(0),
        Some(ht) => {
            w.put_u8(1);
            encode_hook_type(w, ht);
        }
    }
}

fn decode_child_info(r: &mut WireReader) -> io::Result<HostChildInfo> {
    let parent_pid = r.get_u32()?;
    let child_pid = r.get_u32()?;
    let operation = decode_child_operation(r)?;
    let path = r.get_opt_string()?;
    let argv = match r.get_u8()? {
        0 => None,
        1 => Some(r.get_vec(|r| r.get_string())?),
        t => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid argv tag: {}", t),
            ))
        }
    };
    let stack_count = r.get_u32()? as usize;
    let mut native_stack = Vec::with_capacity(stack_count);
    for _ in 0..stack_count {
        native_stack.push(r.get_u64()? as usize);
    }
    let source_file = r.get_opt_string()?;
    let source_line = r.get_opt_u32()?;
    let source_column = r.get_opt_u32()?;
    let runtime_stack = decode_opt_runtime_stack(r)?;
    let hook_type = match r.get_u8()? {
        0 => None,
        1 => Some(decode_hook_type(r)?),
        t => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid hook_type tag: {}", t),
            ))
        }
    };
    Ok(HostChildInfo {
        parent_pid,
        child_pid,
        operation,
        path,
        argv,
        native_stack,
        source_file,
        source_line,
        source_column,
        runtime_stack,
        hook_type,
    })
}

// =============================================================================
// Enum encoding helpers
// =============================================================================

fn encode_hook_type(w: &mut WireWriter, ht: &HookType) {
    w.put_u8(match ht {
        HookType::Native => 0,
        HookType::Python => 1,
        HookType::Nodejs => 2,
        HookType::Exec => 3,
        HookType::EnvVar => 4,
        HookType::Bash => 5,
    });
}

fn decode_hook_type(r: &mut WireReader) -> io::Result<HookType> {
    match r.get_u8()? {
        0 => Ok(HookType::Native),
        1 => Ok(HookType::Python),
        2 => Ok(HookType::Nodejs),
        3 => Ok(HookType::Exec),
        4 => Ok(HookType::EnvVar),
        5 => Ok(HookType::Bash),
        t => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid HookType tag: {}", t),
        )),
    }
}

fn encode_event_type(w: &mut WireWriter, et: &EventType) {
    match et {
        EventType::Enter => w.put_u8(0),
        EventType::Leave { return_value } => {
            w.put_u8(1);
            w.put_opt_str(return_value.as_deref());
        }
    }
}

fn decode_event_type(r: &mut WireReader) -> io::Result<EventType> {
    match r.get_u8()? {
        0 => Ok(EventType::Enter),
        1 => {
            let return_value = r.get_opt_string()?;
            Ok(EventType::Leave { return_value })
        }
        t => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid EventType tag: {}", t),
        )),
    }
}

fn encode_child_operation(w: &mut WireWriter, op: ChildOperation) {
    w.put_u8(match op {
        ChildOperation::Fork => 0,
        ChildOperation::Exec => 1,
        ChildOperation::Spawn => 2,
    });
}

fn decode_child_operation(r: &mut WireReader) -> io::Result<ChildOperation> {
    match r.get_u8()? {
        0 => Ok(ChildOperation::Fork),
        1 => Ok(ChildOperation::Exec),
        2 => Ok(ChildOperation::Spawn),
        t => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid ChildOperation tag: {}", t),
        )),
    }
}

fn encode_review_decision(w: &mut WireWriter, d: &ReviewDecision) {
    w.put_u8(match d {
        ReviewDecision::Allow => 0,
        ReviewDecision::Block => 1,
        ReviewDecision::Warn => 2,
        ReviewDecision::Suppress => 3,
    });
}

fn decode_review_decision(r: &mut WireReader) -> io::Result<ReviewDecision> {
    match r.get_u8()? {
        0 => Ok(ReviewDecision::Allow),
        1 => Ok(ReviewDecision::Block),
        2 => Ok(ReviewDecision::Warn),
        3 => Ok(ReviewDecision::Suppress),
        t => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid ReviewDecision tag: {}", t),
        )),
    }
}

// =============================================================================
// RuntimeStack encoding/decoding
// =============================================================================

fn encode_opt_runtime_stack(w: &mut WireWriter, stack: &Option<RuntimeStack>) {
    match stack {
        None => w.put_u8(0),
        Some(RuntimeStack::Python(frames)) => {
            w.put_u8(1);
            w.put_vec(frames, |w, f| {
                w.put_str(&f.function);
                w.put_str(&f.filename);
                w.put_u32(f.line);
                // locals: Option<Vec<(String, String)>>
                match &f.locals {
                    None => w.put_u8(0),
                    Some(locals) => {
                        w.put_u8(1);
                        w.put_vec(locals, |w, (k, v)| {
                            w.put_str(k);
                            w.put_str(v);
                        });
                    }
                }
            });
        }
        Some(RuntimeStack::Nodejs(frames)) => {
            w.put_u8(2);
            w.put_vec(frames, |w, f| {
                w.put_str(&f.function);
                w.put_str(&f.script);
                w.put_u32(f.line);
                w.put_u32(f.column);
                w.put_bool(f.is_user_javascript);
            });
        }
    }
}

fn decode_opt_runtime_stack(r: &mut WireReader) -> io::Result<Option<RuntimeStack>> {
    match r.get_u8()? {
        0 => Ok(None),
        1 => {
            let frames = r.get_vec(|r| {
                let function = r.get_string()?;
                let filename = r.get_string()?;
                let line = r.get_u32()?;
                let locals = match r.get_u8()? {
                    0 => None,
                    1 => Some(r.get_vec(|r| {
                        let k = r.get_string()?;
                        let v = r.get_string()?;
                        Ok((k, v))
                    })?),
                    t => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid locals tag: {}", t),
                        ))
                    }
                };
                Ok(PythonFrame {
                    function,
                    filename,
                    line,
                    locals,
                })
            })?;
            Ok(Some(RuntimeStack::Python(frames)))
        }
        2 => {
            let frames = r.get_vec(|r| {
                let function = r.get_string()?;
                let script = r.get_string()?;
                let line = r.get_u32()?;
                let column = r.get_u32()?;
                let is_user_javascript = r.get_bool()?;
                Ok(NodejsFrame {
                    function,
                    script,
                    line,
                    column,
                    is_user_javascript,
                })
            })?;
            Ok(Some(RuntimeStack::Nodejs(frames)))
        }
        t => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid RuntimeStack tag: {}", t),
        )),
    }
}

// =============================================================================
// NetworkInfo encoding/decoding
// =============================================================================

fn encode_opt_network_info(w: &mut WireWriter, info: &Option<NetworkInfo>) {
    match info {
        None => w.put_u8(0),
        Some(ni) => {
            w.put_u8(1);
            w.put_opt_str(ni.url.as_deref());
            w.put_opt_str(ni.domain.as_deref());
            w.put_opt_str(ni.ip.as_deref());
            w.put_opt_u16(ni.port);
            // protocol: Option<Protocol>
            match &ni.protocol {
                None => w.put_u8(0),
                Some(p) => {
                    w.put_u8(1);
                    w.put_str(p.as_str());
                }
            }
        }
    }
}

fn decode_opt_network_info(r: &mut WireReader) -> io::Result<Option<NetworkInfo>> {
    match r.get_u8()? {
        0 => Ok(None),
        1 => {
            let url = r.get_opt_string()?;
            let domain = r.get_opt_string()?;
            let ip = r.get_opt_string()?;
            let port = r.get_opt_u16()?;
            let protocol = match r.get_u8()? {
                0 => None,
                1 => {
                    let s = r.get_string()?;
                    Some(crate::event::Protocol::from(s.as_str()))
                }
                t => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid Protocol tag: {}", t),
                    ))
                }
            };
            Ok(Some(NetworkInfo {
                url,
                domain,
                ip,
                port,
                protocol,
            }))
        }
        t => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid NetworkInfo tag: {}", t),
        )),
    }
}

// =============================================================================
// WireWriter
// =============================================================================

struct WireWriter<'a>(&'a mut Vec<u8>);

impl WireWriter<'_> {
    fn put_u8(&mut self, v: u8) {
        self.0.push(v);
    }

    fn put_bool(&mut self, v: bool) {
        self.0.push(v as u8);
    }

    fn put_u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    fn put_u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    fn put_u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    fn put_str(&mut self, s: &str) {
        self.put_u32(s.len() as u32);
        self.0.extend_from_slice(s.as_bytes());
    }

    fn put_opt_str(&mut self, s: Option<&str>) {
        match s {
            None => self.put_u8(0),
            Some(s) => {
                self.put_u8(1);
                self.put_str(s);
            }
        }
    }

    fn put_opt_u16(&mut self, v: Option<u16>) {
        match v {
            None => self.put_u8(0),
            Some(v) => {
                self.put_u8(1);
                self.put_u16(v);
            }
        }
    }

    fn put_opt_u32(&mut self, v: Option<u32>) {
        match v {
            None => self.put_u8(0),
            Some(v) => {
                self.put_u8(1);
                self.put_u32(v);
            }
        }
    }

    fn put_opt_u64(&mut self, v: Option<u64>) {
        match v {
            None => self.put_u8(0),
            Some(v) => {
                self.put_u8(1);
                self.put_u64(v);
            }
        }
    }

    fn put_vec<T>(&mut self, items: &[T], mut encode_item: impl FnMut(&mut WireWriter, &T)) {
        self.put_u32(items.len() as u32);
        for item in items {
            encode_item(self, item);
        }
    }
}

// =============================================================================
// WireReader
// =============================================================================

struct WireReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn need(&self, n: usize) -> io::Result<()> {
        if self.remaining() < n {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("need {} bytes, have {}", n, self.remaining()),
            ))
        } else {
            Ok(())
        }
    }

    fn get_u8(&mut self) -> io::Result<u8> {
        self.need(1)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn get_bool(&mut self) -> io::Result<bool> {
        Ok(self.get_u8()? != 0)
    }

    fn get_u16(&mut self) -> io::Result<u16> {
        self.need(2)?;
        let v = u16::from_be_bytes(self.data[self.pos..self.pos + 2].try_into().unwrap());
        self.pos += 2;
        Ok(v)
    }

    fn get_u32(&mut self) -> io::Result<u32> {
        self.need(4)?;
        let v = u32::from_be_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn get_u64(&mut self) -> io::Result<u64> {
        self.need(8)?;
        let v = u64::from_be_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    fn get_string(&mut self) -> io::Result<String> {
        let len = self.get_u32()? as usize;
        self.need(len)?;
        let s = std::str::from_utf8(&self.data[self.pos..self.pos + len])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.pos += len;
        Ok(s.to_string())
    }

    fn get_opt_string(&mut self) -> io::Result<Option<String>> {
        match self.get_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.get_string()?)),
            t => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid Option tag: {}", t),
            )),
        }
    }

    fn get_opt_u16(&mut self) -> io::Result<Option<u16>> {
        match self.get_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.get_u16()?)),
            t => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid Option tag: {}", t),
            )),
        }
    }

    fn get_opt_u32(&mut self) -> io::Result<Option<u32>> {
        match self.get_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.get_u32()?)),
            t => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid Option tag: {}", t),
            )),
        }
    }

    fn get_opt_u64(&mut self) -> io::Result<Option<u64>> {
        match self.get_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.get_u64()?)),
            t => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid Option tag: {}", t),
            )),
        }
    }

    fn get_vec<T>(
        &mut self,
        mut decode_item: impl FnMut(&mut WireReader) -> io::Result<T>,
    ) -> io::Result<Vec<T>> {
        let count = self.get_u32()? as usize;
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(decode_item(self)?);
        }
        Ok(items)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Protocol;

    fn roundtrip_agent(msg: &AgentMessage) -> AgentMessage {
        let codec = BinaryCodec;
        let mut buf = Vec::new();
        codec.encode_agent_msg(msg, &mut buf);
        codec.decode_agent_msg(&buf).expect("decode_agent_msg")
    }

    fn roundtrip_cli(msg: &CliMessage) -> CliMessage {
        let codec = BinaryCodec;
        let mut buf = Vec::new();
        codec.encode_cli_msg(msg, &mut buf);
        codec.decode_cli_msg(&buf).expect("decode_cli_msg")
    }

    #[test]
    fn test_framing_roundtrip() {
        let payload = b"hello wire protocol";
        let mut buf = Vec::new();
        write_frame(&mut buf, payload).unwrap();
        let decoded = read_frame(&mut &buf[..]).unwrap();
        assert_eq!(&decoded, payload);
    }

    #[test]
    fn test_framing_empty() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &[]).unwrap();
        let decoded = read_frame(&mut &buf[..]).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_framing_max_len_reject() {
        // Manually craft a frame with length > MAX_FRAME_LEN
        let len = (MAX_FRAME_LEN + 1).to_be_bytes();
        let buf = len.to_vec();
        let result = read_frame(&mut &buf[..]);
        assert!(result.is_err());
    }

    #[test]
    fn test_configure_roundtrip() {
        let msg = AgentMessage::Configure(ConfigureRequest {
            pid: 42,
            nodejs_version: Some(22),
        });
        let decoded = roundtrip_agent(&msg);
        match decoded {
            AgentMessage::Configure(req) => {
                assert_eq!(req.pid, 42);
                assert_eq!(req.nodejs_version, Some(22));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_configure_no_nodejs() {
        let msg = AgentMessage::Configure(ConfigureRequest {
            pid: 1,
            nodejs_version: None,
        });
        let decoded = roundtrip_agent(&msg);
        match decoded {
            AgentMessage::Configure(req) => {
                assert_eq!(req.pid, 1);
                assert_eq!(req.nodejs_version, None);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_ready_roundtrip() {
        let msg = AgentMessage::Ready(ReadyRequest {
            pid: 100,
            hooks_installed: vec!["malloc".to_string(), "free".to_string()],
            nodejs_version: Some(22),
            python_version: Some("3.12.0".to_string()),
            bash_version: None,
            modules: vec![ModuleInfo {
                name: "libSystem.B.dylib".to_string(),
                path: "/usr/lib/libSystem.B.dylib".to_string(),
                base_address: 0x7fff00000000,
                size: 0x100000,
            }],
        });
        let decoded = roundtrip_agent(&msg);
        match decoded {
            AgentMessage::Ready(req) => {
                assert_eq!(req.pid, 100);
                assert_eq!(req.hooks_installed, vec!["malloc", "free"]);
                assert_eq!(req.nodejs_version, Some(22));
                assert_eq!(req.python_version, Some("3.12.0".to_string()));
                assert_eq!(req.bash_version, None);
                assert_eq!(req.modules.len(), 1);
                assert_eq!(req.modules[0].base_address, 0x7fff00000000);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_runtime_roundtrip() {
        let msg = AgentMessage::Runtime(RuntimeInfoRequest {
            pid: 5,
            runtime: "nodejs".to_string(),
            version: "22.3.0".to_string(),
        });
        let decoded = roundtrip_agent(&msg);
        match decoded {
            AgentMessage::Runtime(req) => {
                assert_eq!(req.pid, 5);
                assert_eq!(req.runtime, "nodejs");
                assert_eq!(req.version, "22.3.0");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_event_roundtrip() {
        let event = TraceEvent {
            hook_type: HookType::Nodejs,
            event_type: EventType::Enter,
            function: "js:fs.readFileSync".to_string(),
            arguments: vec![
                Argument {
                    raw_value: 0x1000,
                    display: Some("/etc/passwd".to_string()),
                },
                Argument {
                    raw_value: 0,
                    display: None,
                },
            ],
            native_stack: vec![0x7fff00001000, 0x7fff00002000],
            runtime_stack: Some(RuntimeStack::Nodejs(vec![NodejsFrame {
                function: "readFileSync".to_string(),
                script: "internal/fs.js".to_string(),
                line: 42,
                column: 10,
                is_user_javascript: false,
            }])),
            network_info: None,
            source_file: Some("app.js".to_string()),
            source_line: Some(7),
            source_column: Some(15),
            timestamp_ns: 123456789,
            ..Default::default()
        };
        let msg = AgentMessage::Event(event);
        let decoded = roundtrip_agent(&msg);
        match decoded {
            AgentMessage::Event(e) => {
                assert!(matches!(e.hook_type, HookType::Nodejs));
                assert!(matches!(e.event_type, EventType::Enter));
                assert_eq!(e.function, "js:fs.readFileSync");
                assert_eq!(e.arguments.len(), 2);
                assert_eq!(e.arguments[0].display, Some("/etc/passwd".to_string()));
                assert_eq!(e.arguments[1].display, None);
                assert_eq!(e.native_stack, vec![0x7fff00001000, 0x7fff00002000]);
                assert!(matches!(e.runtime_stack, Some(RuntimeStack::Nodejs(_))));
                assert_eq!(e.source_file, Some("app.js".to_string()));
                assert_eq!(e.source_line, Some(7));
                assert_eq!(e.source_column, Some(15));
                assert_eq!(e.timestamp_ns, 123456789);
                // CLI-only fields should be default
                assert_eq!(e.seq, 0);
                assert!(e.source.is_none());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_event_leave_roundtrip() {
        let event = TraceEvent {
            hook_type: HookType::Python,
            event_type: EventType::Leave {
                return_value: Some("42".to_string()),
            },
            function: "py:open".to_string(),
            ..Default::default()
        };
        let msg = AgentMessage::Event(event);
        let decoded = roundtrip_agent(&msg);
        match decoded {
            AgentMessage::Event(e) => match &e.event_type {
                EventType::Leave { return_value } => {
                    assert_eq!(return_value.as_deref(), Some("42"));
                }
                _ => panic!("expected Leave"),
            },
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_events_batch_roundtrip() {
        let events = vec![
            TraceEvent {
                function: "malloc".to_string(),
                ..Default::default()
            },
            TraceEvent {
                function: "free".to_string(),
                ..Default::default()
            },
        ];
        let msg = AgentMessage::Events(events);
        let decoded = roundtrip_agent(&msg);
        match decoded {
            AgentMessage::Events(evts) => {
                assert_eq!(evts.len(), 2);
                assert_eq!(evts[0].function, "malloc");
                assert_eq!(evts[1].function, "free");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_child_roundtrip() {
        let info = HostChildInfo {
            parent_pid: 1,
            child_pid: 2,
            operation: ChildOperation::Spawn,
            path: Some("/usr/bin/curl".to_string()),
            argv: Some(vec!["curl".to_string(), "--version".to_string()]),
            native_stack: vec![0x1000],
            source_file: Some("/app/index.js".to_string()),
            source_line: Some(42),
            source_column: Some(8),
            runtime_stack: None,
            hook_type: None,
        };
        let msg = AgentMessage::Child(info);
        let decoded = roundtrip_agent(&msg);
        match decoded {
            AgentMessage::Child(i) => {
                assert_eq!(i.parent_pid, 1);
                assert_eq!(i.child_pid, 2);
                assert_eq!(i.operation, ChildOperation::Spawn);
                assert_eq!(i.path, Some("/usr/bin/curl".to_string()));
                assert_eq!(
                    i.argv,
                    Some(vec!["curl".to_string(), "--version".to_string()])
                );
                assert_eq!(i.source_file, Some("/app/index.js".to_string()));
                assert_eq!(i.source_line, Some(42));
                assert_eq!(i.source_column, Some(8));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_reconnect_roundtrip() {
        let msg = AgentMessage::Reconnect(ChildReconnectRequest {
            parent_pid: 10,
            child_pid: 20,
        });
        let decoded = roundtrip_agent(&msg);
        match decoded {
            AgentMessage::Reconnect(req) => {
                assert_eq!(req.parent_pid, 10);
                assert_eq!(req.child_pid, 20);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_review_roundtrip() {
        let msg = AgentMessage::Review {
            request_id: 42,
            event: TraceEvent {
                function: "dangerous_call".to_string(),
                ..Default::default()
            },
        };
        let decoded = roundtrip_agent(&msg);
        match decoded {
            AgentMessage::Review { request_id, event } => {
                assert_eq!(request_id, 42);
                assert_eq!(event.function, "dangerous_call");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_shutdown_roundtrip() {
        let msg = AgentMessage::Shutdown(ShutdownRequest { pid: 99 });
        let decoded = roundtrip_agent(&msg);
        match decoded {
            AgentMessage::Shutdown(req) => assert_eq!(req.pid, 99),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_configure_response_roundtrip() {
        let msg = CliMessage::ConfigureResponse(ConfigureResponse {
            hooks: vec![
                HookConfig {
                    hook_type: HookType::Native,
                    symbol: "malloc".to_string(),
                    arg_count: Some(1),
                    capture_return: true,
                    capture_stack: false,
                },
                HookConfig {
                    hook_type: HookType::Python,
                    symbol: "open".to_string(),
                    arg_count: None,
                    capture_return: false,
                    capture_stack: true,
                },
            ],
            review_mode: true,
            envvar_allow_patterns: vec!["HF_HUB_*".to_string(), "HF_TOKEN_PATH".to_string()],
        });
        let decoded = roundtrip_cli(&msg);
        match decoded {
            CliMessage::ConfigureResponse(resp) => {
                assert_eq!(resp.hooks.len(), 2);
                assert!(matches!(resp.hooks[0].hook_type, HookType::Native));
                assert_eq!(resp.hooks[0].symbol, "malloc");
                assert_eq!(resp.hooks[0].arg_count, Some(1));
                assert!(resp.hooks[0].capture_return);
                assert!(!resp.hooks[0].capture_stack);
                assert!(matches!(resp.hooks[1].hook_type, HookType::Python));
                assert_eq!(resp.hooks[1].arg_count, None);
                assert!(resp.review_mode);
                assert_eq!(resp.envvar_allow_patterns.len(), 2);
                assert_eq!(resp.envvar_allow_patterns[0], "HF_HUB_*");
                assert_eq!(resp.envvar_allow_patterns[1], "HF_TOKEN_PATH");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_review_response_roundtrip() {
        for decision in [
            ReviewDecision::Allow,
            ReviewDecision::Block,
            ReviewDecision::Warn,
            ReviewDecision::Suppress,
        ] {
            let msg = CliMessage::ReviewResponse {
                request_id: 7,
                decision: decision.clone(),
            };
            let decoded = roundtrip_cli(&msg);
            match decoded {
                CliMessage::ReviewResponse {
                    request_id,
                    decision: d,
                } => {
                    assert_eq!(request_id, 7);
                    assert_eq!(
                        std::mem::discriminant(&d),
                        std::mem::discriminant(&decision)
                    );
                }
                _ => panic!("wrong variant"),
            }
        }
    }

    #[test]
    fn test_network_info_roundtrip() {
        let event = TraceEvent {
            hook_type: HookType::Nodejs,
            function: "js:http.request".to_string(),
            network_info: Some(NetworkInfo {
                url: Some("https://example.com/api/v1/users".to_string()),
                domain: Some("example.com".to_string()),
                port: Some(443),
                protocol: Some(Protocol::Https),
                ..Default::default()
            }),
            ..Default::default()
        };
        let msg = AgentMessage::Event(event);
        let decoded = roundtrip_agent(&msg);
        match decoded {
            AgentMessage::Event(e) => {
                let ni = e.network_info.unwrap();
                assert_eq!(ni.url, Some("https://example.com/api/v1/users".to_string()));
                assert_eq!(ni.domain, Some("example.com".to_string()));
                assert_eq!(ni.port, Some(443));
                assert!(matches!(ni.protocol, Some(Protocol::Https)));
                assert_eq!(ni.ip, None);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_network_info_resolved_connect_roundtrip() {
        let event = TraceEvent {
            hook_type: HookType::Native,
            function: "connect".to_string(),
            network_info: Some(NetworkInfo::resolved_connect(
                "93.184.216.34".into(),
                443,
                "example.com".into(),
            )),
            ..Default::default()
        };
        let msg = AgentMessage::Event(event);
        let decoded = roundtrip_agent(&msg);
        match decoded {
            AgentMessage::Event(e) => {
                let ni = e.network_info.unwrap();
                assert_eq!(ni.ip, Some("93.184.216.34".to_string()));
                assert_eq!(ni.port, Some(443));
                assert_eq!(ni.domain, Some("example.com".to_string()));
                assert_eq!(ni.url, None);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_python_stack_roundtrip() {
        let event = TraceEvent {
            hook_type: HookType::Python,
            function: "py:open".to_string(),
            runtime_stack: Some(RuntimeStack::Python(vec![PythonFrame {
                function: "main".to_string(),
                filename: "app.py".to_string(),
                line: 10,
                locals: Some(vec![
                    ("x".to_string(), "42".to_string()),
                    ("name".to_string(), "test".to_string()),
                ]),
            }])),
            ..Default::default()
        };
        let msg = AgentMessage::Event(event);
        let decoded = roundtrip_agent(&msg);
        match decoded {
            AgentMessage::Event(e) => match &e.runtime_stack {
                Some(RuntimeStack::Python(frames)) => {
                    assert_eq!(frames.len(), 1);
                    assert_eq!(frames[0].function, "main");
                    assert_eq!(frames[0].line, 10);
                    let locals = frames[0].locals.as_ref().unwrap();
                    assert_eq!(locals.len(), 2);
                    assert_eq!(locals[0], ("x".to_string(), "42".to_string()));
                }
                _ => panic!("expected Python stack"),
            },
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_child_with_runtime_stack() {
        let info = HostChildInfo {
            parent_pid: 1,
            child_pid: 2,
            operation: ChildOperation::Exec,
            path: None,
            argv: None,
            native_stack: vec![],
            source_file: Some("script.py".to_string()),
            source_line: Some(42),
            source_column: None,
            runtime_stack: Some(RuntimeStack::Python(vec![PythonFrame {
                function: "run".to_string(),
                filename: "script.py".to_string(),
                line: 42,
                locals: None,
            }])),
            hook_type: None,
        };
        let msg = AgentMessage::Child(info);
        let decoded = roundtrip_agent(&msg);
        match decoded {
            AgentMessage::Child(i) => {
                assert!(i.path.is_none());
                assert!(i.argv.is_none());
                assert_eq!(i.source_file, Some("script.py".to_string()));
                assert!(matches!(i.runtime_stack, Some(RuntimeStack::Python(_))));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_unknown_agent_tag_error() {
        let codec = BinaryCodec;
        let data = [0xFF];
        let result = codec.decode_agent_msg(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_cli_tag_error() {
        let codec = BinaryCodec;
        let data = [0xFF];
        let result = codec.decode_cli_msg(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_data_error() {
        let codec = BinaryCodec;
        // Just a tag byte with no payload for Configure (needs pid)
        let data = [TAG_CONFIGURE];
        let result = codec.decode_agent_msg(&data);
        assert!(result.is_err());
    }
}
