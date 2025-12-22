//! HTTP protocol types between CLI and agent.

use serde::{Deserialize, Serialize};

use crate::event::{HookConfig, TraceEvent};

// =============================================================================
// HTTP REQUEST/RESPONSE TYPES
// =============================================================================

/// Agent → CLI: Initial configuration request (POST /configure).
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigureRequest {
    pub pid: u32,
    pub nodejs_version: Option<u32>,
}

/// CLI → Agent: Configuration response with hooks and settings.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ConfigureResponse {
    #[serde(default)]
    pub hooks: Vec<HookConfig>,
    #[serde(default)]
    pub review_mode: bool,
}

/// Information about a loaded module in the target process.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub path: String,
    pub base_address: u64,
    pub size: u64,
}

/// Agent → CLI: Agent ready notification (POST /ready).
#[derive(Debug, Serialize, Deserialize)]
pub struct ReadyRequest {
    pub pid: u32,
    pub hooks_installed: Vec<String>,
    pub nodejs_version: Option<u32>,
    #[serde(default)]
    pub python_version: Option<String>,
    #[serde(default)]
    pub bash_version: Option<String>,
    #[serde(default)]
    pub modules: Vec<ModuleInfo>,
}

/// Agent → CLI: Review decision request (POST /review).
#[derive(Debug, Serialize, Deserialize)]
pub struct ReviewRequest {
    pub event: TraceEvent,
}

/// Review mode decision — carries disposition context from CLI to agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReviewDecision {
    /// Proceed normally (was: Continue).
    Allow,
    /// Denied by policy or user (was: Abort).
    Block,
    /// Allowed but flagged — warning displayed CLI-side.
    Warn,
    /// Auto-allowed, nothing to show.
    Suppress,
}

impl ReviewDecision {
    /// Returns true if the call should be allowed to proceed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow | Self::Warn | Self::Suppress)
    }
}

/// CLI → Agent: Review decision response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReviewResponse {
    pub decision: ReviewDecision,
}

/// CLI → Agent: Pending command for agent polling (GET /command).
#[derive(Debug, Serialize, Deserialize)]
pub struct CommandResponse {
    pub command: Option<String>,
}

/// Agent → CLI: Child process reconnection after fork (POST /child/reconnect).
#[derive(Debug, Serialize, Deserialize)]
pub struct ChildReconnectRequest {
    pub parent_pid: u32,
    pub child_pid: u32,
}

/// Agent → CLI: Late runtime info notification (POST /runtime).
/// Sent when runtime details become available after ReadyRequest
/// (e.g., Node.js version detected after main() runs).
#[derive(Debug, Serialize, Deserialize)]
pub struct RuntimeInfoRequest {
    pub pid: u32,
    pub runtime: String,
    pub version: String,
}

/// Agent → CLI: Agent shutdown notification (POST /shutdown).
#[derive(Debug, Serialize, Deserialize)]
pub struct ShutdownRequest {
    pub pid: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ready_request_with_modules_serde_roundtrip() {
        let req = ReadyRequest {
            pid: 42,
            hooks_installed: vec!["malloc".to_string(), "free".to_string()],
            nodejs_version: Some(22),
            python_version: None,
            bash_version: None,
            modules: vec![
                ModuleInfo {
                    name: "libSystem.B.dylib".to_string(),
                    path: "/usr/lib/libSystem.B.dylib".to_string(),
                    base_address: 0x7fff00000000,
                    size: 0x100000,
                },
                ModuleInfo {
                    name: "test_binary".to_string(),
                    path: "/tmp/test_binary".to_string(),
                    base_address: 0x100000000,
                    size: 0x50000,
                },
            ],
        };

        let json = serde_json::to_string(&req).expect("serialize");
        let decoded: ReadyRequest = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded.pid, 42);
        assert_eq!(decoded.hooks_installed.len(), 2);
        assert_eq!(decoded.nodejs_version, Some(22));
        assert_eq!(decoded.modules.len(), 2);
        assert_eq!(decoded.modules[0], req.modules[0]);
        assert_eq!(decoded.modules[1], req.modules[1]);
    }

    #[test]
    fn test_ready_request_without_modules_deserializes() {
        // Ensure backward compatibility: old agents without modules field
        let json = r#"{"pid":1,"hooks_installed":[],"nodejs_version":null}"#;
        let decoded: ReadyRequest = serde_json::from_str(json).expect("deserialize");
        assert_eq!(decoded.pid, 1);
        assert!(decoded.modules.is_empty());
    }
}
