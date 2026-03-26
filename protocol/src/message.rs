//! Message types for agent → CLI communication.
//!
//! Contains tagged message enums for the binary wire protocol.
//! Communication is unidirectional: agent → CLI only.

use serde::{Deserialize, Serialize};

use crate::{HostChildInfo, ReadyRequest, RuntimeInfoRequest, ShutdownRequest, TraceEvent};

/// Messages sent from agent → CLI.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum AgentMessage {
    /// Hooks installed, agent ready
    #[serde(rename = "ready")]
    Ready(ReadyRequest),
    /// Late runtime version info
    #[serde(rename = "runtime")]
    Runtime(RuntimeInfoRequest),
    /// Single trace event (raw, no disposition)
    #[serde(rename = "event")]
    Event(TraceEvent),
    /// Batch of trace events (raw, no disposition)
    #[serde(rename = "events")]
    Events(Vec<TraceEvent>),
    /// Child process creation
    #[serde(rename = "child")]
    Child(HostChildInfo),
    /// Agent shutdown notification
    #[serde(rename = "shutdown")]
    Shutdown(ShutdownRequest),
    /// Batch of display events with agent-computed disposition.
    /// When the agent has a local policy, it evaluates events and sends them
    /// with disposition already attached — no CLI-side evaluation needed.
    #[serde(rename = "display_events")]
    DisplayEvents(Vec<DisplayEvent>),
}

// =============================================================================
// Display Event Types (agent-side policy evaluation)
// =============================================================================

/// A trace event with agent-computed disposition.
///
/// When the agent has a local policy (loaded from config file), it evaluates
/// events before sending them. The CLI receives pre-evaluated events and
/// only needs to render them — no policy evaluation on the CLI side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayEvent {
    /// The underlying trace event.
    pub trace: TraceEvent,
    /// Agent's policy evaluation result.
    pub disposition: Disposition,
}

/// Agent-side policy disposition for a trace event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Disposition {
    /// Normal display — no policy match or matched a log-mode deny rule.
    Traced,
    /// Agent blocked the call (returned -1/EACCES from hook).
    Blocked { rule: String, section: String },
    /// Agent allowed but flagged (warning displayed).
    Warning { rule: String, section: String },
}
