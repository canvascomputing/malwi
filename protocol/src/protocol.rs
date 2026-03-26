//! Protocol types for agent → CLI communication.

use serde::{Deserialize, Serialize};

// =============================================================================
// PROTOCOL TYPES
// =============================================================================

/// Information about a loaded module in the target process.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub path: String,
    pub base_address: u64,
    pub size: u64,
}

/// Agent → CLI: Agent ready notification.
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

/// Agent → CLI: Late runtime info notification.
/// Sent when runtime details become available after ReadyRequest
/// (e.g., Node.js version detected after main() runs).
#[derive(Debug, Serialize, Deserialize)]
pub struct RuntimeInfoRequest {
    pub pid: u32,
    pub runtime: String,
    pub version: String,
}

/// Agent → CLI: Agent shutdown notification.
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
