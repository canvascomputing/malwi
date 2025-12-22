//! Trace event types representing function calls and stack traces.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Type of hook target.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HookType {
    /// Native function hook via malwi-hook Interceptor
    #[default]
    Native,
    /// Python function hook via profile API
    Python,
    /// Node.js function hook (via N-API addon)
    Nodejs,
    /// Exec filter for child process commands
    Exec,
    /// Direct syscall detected by syscall tracing
    DirectSyscall,
    /// Environment variable access (bash find_variable with att_exported)
    EnvVar,
}

/// Network protocol type.
///
/// Serializes as a lowercase string for wire compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Http,
    Https,
    Wss,
    Ws,
    Other(String),
}

impl Protocol {
    pub fn as_str(&self) -> &str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Http => "http",
            Protocol::Https => "https",
            Protocol::Wss => "wss",
            Protocol::Ws => "ws",
            Protocol::Other(s) => s,
        }
    }
}

impl From<&str> for Protocol {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            "http" => Protocol::Http,
            "https" => Protocol::Https,
            "wss" => Protocol::Wss,
            "ws" => Protocol::Ws,
            _ => Protocol::Other(s.to_string()),
        }
    }
}

impl Serialize for Protocol {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Protocol {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Protocol::from(s.as_str()))
    }
}

/// Structured networking metadata populated at hook time.
///
/// Provides structured fields for policy evaluation without
/// requiring text parsing of argument display strings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// Full URL if available (e.g., "https://example.com/v1/users")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Target host/domain (e.g., "example.com")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Target port (e.g., 443)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Network protocol
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
}

/// A trace event representing a function invocation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceEvent {
    /// Type of hook that generated this event
    #[serde(default)]
    pub hook_type: HookType,
    /// Type of event (enter or leave)
    #[serde(default)]
    pub event_type: EventType,
    /// Function name
    #[serde(default)]
    pub function: String,
    /// Function arguments (on enter)
    #[serde(default)]
    pub arguments: Vec<Argument>,
    /// Native stack trace (raw addresses, resolved CLI-side)
    #[serde(default)]
    pub native_stack: Vec<usize>,
    /// Runtime-specific stack (Python, V8, etc.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_stack: Option<RuntimeStack>,
    /// Structured networking metadata (populated by agent for networking calls)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_info: Option<NetworkInfo>,
    /// Source file where the call originated (caller's file)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
    /// Source line where the call originated (caller's line)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_line: Option<u32>,
}

/// Type of trace event.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum EventType {
    /// Function entry
    #[default]
    Enter,
    /// Function exit with optional return value
    Leave { return_value: Option<String> },
}

/// A function argument.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Argument {
    /// Raw pointer value
    #[serde(default)]
    pub raw_value: usize,
    /// String representation if available
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

/// A native stack frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeFrame {
    /// Instruction pointer
    pub address: usize,
    /// Symbol name if resolved
    pub symbol: Option<String>,
    /// Module name
    pub module: Option<String>,
    /// Offset from symbol start
    pub offset: Option<usize>,
}

/// Runtime-specific stack trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuntimeStack {
    Python(Vec<PythonFrame>),
    Nodejs(Vec<NodejsFrame>),
}

/// A Python stack frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PythonFrame {
    /// Function name
    pub function: String,
    /// Source file path
    pub filename: String,
    /// Line number
    pub line: u32,
    /// Local variables (if captured)
    pub locals: Option<Vec<(String, String)>>,
}

/// A Node.js/JavaScript stack frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodejsFrame {
    /// Function name
    pub function: String,
    /// Script name/path
    pub script: String,
    /// Line number (1-based)
    pub line: u32,
    /// Column number (1-based)
    pub column: u32,
    /// Whether this is user JavaScript (not Node.js internals)
    pub is_user_javascript: bool,
}

/// Hook configuration for a single function.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HookConfig {
    /// Type of hook (native or Python)
    #[serde(default)]
    pub hook_type: HookType,
    /// Symbol name to hook (for native) or function name (for Python)
    #[serde(default)]
    pub symbol: String,
    /// Number of arguments to capture
    #[serde(default)]
    pub arg_count: Option<usize>,
    /// Whether to capture return value
    #[serde(default)]
    pub capture_return: bool,
    /// Whether to capture stack trace
    #[serde(default)]
    pub capture_stack: bool,
}

/// How a child process was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChildOperation {
    /// Created via fork() or vfork()
    Fork,
    /// Created via execve() or similar
    Exec,
    /// Created via posix_spawn() or CreateProcess()
    Spawn,
}

/// Information about a child process creation event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostChildInfo {
    /// Parent process ID
    pub parent_pid: u32,
    /// Child process ID
    pub child_pid: u32,
    /// How the child was created
    pub operation: ChildOperation,
    /// Executable path (if known)
    pub path: Option<String>,
    /// Command line arguments (if known)
    pub argv: Option<Vec<String>>,
    /// Native stack trace (raw addresses, resolved CLI-side)
    #[serde(default)]
    pub native_stack: Vec<usize>,
    /// Source file where the call originated (caller's file)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
    /// Source line where the call originated (caller's line)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_line: Option<u32>,
}
