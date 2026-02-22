//! WebSocket message types for agent↔CLI communication.
//!
//! Replaces HTTP endpoints with tagged message enums transported over WebSocket.

use serde::{Deserialize, Serialize};

use crate::{
    ChildReconnectRequest, ConfigureRequest, ConfigureResponse, HostChildInfo, ReadyRequest,
    ReviewDecision, RuntimeInfoRequest, ShutdownRequest, TraceEvent,
};

/// Messages sent from agent → CLI over WebSocket.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum AgentMessage {
    /// Request hook configuration (replaces POST /configure)
    #[serde(rename = "configure")]
    Configure(ConfigureRequest),
    /// Hooks installed, agent ready (replaces POST /ready)
    #[serde(rename = "ready")]
    Ready(ReadyRequest),
    /// Late runtime version info (replaces POST /runtime)
    #[serde(rename = "runtime")]
    Runtime(RuntimeInfoRequest),
    /// Single trace event (replaces POST /event)
    #[serde(rename = "event")]
    Event(TraceEvent),
    /// Batch of trace events (replaces POST /events)
    #[serde(rename = "events")]
    Events(Vec<TraceEvent>),
    /// Child process creation (replaces POST /child)
    #[serde(rename = "child")]
    Child(HostChildInfo),
    /// Child reconnect after fork+exec (replaces POST /child/reconnect)
    #[serde(rename = "reconnect")]
    Reconnect(ChildReconnectRequest),
    /// Review request — agent blocks for response (replaces POST /review)
    #[serde(rename = "review")]
    Review { request_id: u32, event: TraceEvent },
    /// Agent shutdown notification (replaces POST /shutdown)
    #[serde(rename = "shutdown")]
    Shutdown(ShutdownRequest),
}

/// Messages sent from CLI → agent over WebSocket.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum CliMessage {
    /// Hook configuration response (replaces ConfigureResponse)
    #[serde(rename = "configure_response")]
    ConfigureResponse(ConfigureResponse),
    /// Review decision (replaces ReviewResponse)
    #[serde(rename = "review_response")]
    ReviewResponse {
        request_id: u32,
        decision: ReviewDecision,
    },
}
